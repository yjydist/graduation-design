//go:build fabriclive

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/agent"
	"grad/platform/gateway"
	"grad/platform/policy"
	"grad/platform/registrysvc"
	"grad/platform/state"
	"grad/platform/state/fabric"
	"grad/protocol"
	"grad/protocol/registry"
)

func TestFabricLiveFullStackAcceptance(t *testing.T) {
	dir := os.Getenv("FABRIC_INSTANCE")
	if dir == "" {
		t.Skip("set FABRIC_INSTANCE to a running Fabric instance directory")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	inst, err := fabric.OpenInstance(dir)
	require.NoError(t, err)

	// 1. Deploy, seed, verify outbox deliveries, and scan registry for zero private key leakage.
	dep, err := inst.Deploy(ctx, false)
	require.NoError(t, err)
	db, err := inst.Database(ctx)
	require.NoError(t, err)
	defer db.Close()

	report, err := Seed(ctx, inst, db, dep)
	require.NoError(t, err)
	require.NotNil(t, report.Fixtures())
	require.NoError(t, SyncSeedDeliveries(ctx, inst, db, dep, report))

	scanned, err := ScanDirForPrivateKeys(inst.RegistryPath("."))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(scanned), 25)

	f := report.Fixtures()

	// 2. Start full Fabric-backed Stack (state/fabric + policy + registrysvc + gateway + wallet).
	stack, err := StartFabricGatewayStack(ctx, inst, db, dep, f,
		WithProbeRole("probe1"),
		WithProbeGrant(f.RPG2.ID),
	)
	require.NoError(t, err)
	defer stack.Close()

	// Seed trusted contexts for RP and BM tasks.
	now := time.Now().UTC()
	seedContext := func(taskID string) {
		body, mErr := json.Marshal(gateway.ContextUpdateRequest{
			ExpectedContextVersion: 0,
			SourceID:               "live-risk-engine",
			ObservedAt:             now.Add(-10 * time.Second).Unix(),
			RiskLevel:              policy.RiskNormal,
			AccessDeadline:         now.Add(2 * time.Hour).Unix(),
		})
		require.NoError(t, mErr)
		req := httptest.NewRequest(http.MethodPost, "/v1/contexts/"+taskID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		stack.Gateway.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK && rec.Code != http.StatusConflict {
			t.Fatalf("unexpected context status %d: %s", rec.Code, rec.Body.String())
		}
	}
	seedContext(f.RPTask.ID)
	seedContext(f.BMTask.ID)

	// Verify /v1/health/ready reports Fabric state source and probe block.
	readyRec := httptest.NewRecorder()
	stack.Gateway.Handler().ServeHTTP(readyRec, httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil))
	require.Equal(t, http.StatusOK, readyRec.Code, readyRec.Body.String())
	var ready map[string]any
	require.NoError(t, json.Unmarshal(readyRec.Body.Bytes(), &ready))
	assert.Equal(t, state.SourceFabric, ready["stateSource"])

	// 3. Execute RP quote + order, plus BM quote + order on live Fabric state.
	runSuffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	rpQuote, err := stack.Wallet.RequestQuote(ctx, agent.RequestQuoteInput{
		Actor:             "B1",
		TaskID:            f.RPTask.ID,
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		ProductID:         gateway.DefaultProductID,
		Quantity:          1,
		IdempotencyKey:    "live-rp-q-" + runSuffix,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", rpQuote.Decision, "code=%s msg=%s", rpQuote.ErrorCode, rpQuote.ErrorMessage)

	rpOrderKey := "live-rp-o-" + runSuffix
	rpOrder, err := stack.Wallet.CreateOrder(ctx, agent.CreateOrderInput{
		Actor:             "B1",
		TaskID:            f.RPTask.ID,
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		QuoteID:           rpQuote.QuoteID,
		AmountMinor:       rpQuote.TotalAmountMinor,
		IdempotencyKey:    rpOrderKey,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", rpOrder.Decision, "code=%s msg=%s", rpOrder.ErrorCode, rpOrder.ErrorMessage)
	require.NotEmpty(t, rpOrder.OrderID)

	bmQuote, err := stack.Wallet.RequestQuote(ctx, agent.RequestQuoteInput{
		Actor:             "B1",
		TaskID:            f.BMTask.ID,
		AuthorizationMode: protocol.ModeBuyerMandate,
		ProductID:         gateway.DefaultProductID,
		Quantity:          1,
		IdempotencyKey:    "live-bm-q-" + runSuffix,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", bmQuote.Decision, "code=%s msg=%s", bmQuote.ErrorCode, bmQuote.ErrorMessage)

	bmOrder, err := stack.Wallet.CreateOrder(ctx, agent.CreateOrderInput{
		Actor:             "B1",
		TaskID:            f.BMTask.ID,
		AuthorizationMode: protocol.ModeBuyerMandate,
		QuoteID:           bmQuote.QuoteID,
		AmountMinor:       bmQuote.TotalAmountMinor,
		IdempotencyKey:    "live-bm-o-" + runSuffix,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", bmOrder.Decision, "code=%s msg=%s", bmOrder.ErrorCode, bmOrder.ErrorMessage)

	// 4. Delegate a fresh child grant via wallet (using fabric.Journal + DeliveryService), execute an order,
	//    revoke it at block r, confirm subsequent access is DENIED, and verify historical h < r audit is MATCHED!
	childID := registry.Digest([]byte("live-child-" + runSuffix))
	delOut, err := stack.Wallet.DelegateGrant(ctx, agent.DelegateGrantInput{
		IssuerActor:       "A1",
		SubjectActor:      "B2",
		ParentGrantID:     f.RPG1.ID,
		GrantID:           childID,
		TaskID:            f.RPTask.ID,
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		MaxAmountMinor:    90000,
		RemainingDepth:    0,
	})
	require.NoError(t, err)
	require.True(t, delOut.Anchored)

	// Wait until C's Fabric view has applied the new child grant.
	require.NoError(t, fabric.Poll(ctx, 15*time.Second, func() (bool, error) {
		_, sErr := stack.FabricSP.AssembleSnapshot(ctx, childID, time.Now().UTC())
		return sErr == nil, nil
	}))

	b2Quote, err := stack.Wallet.RequestQuote(ctx, agent.RequestQuoteInput{
		Actor:             "B2",
		GrantID:           childID,
		TaskID:            f.RPTask.ID,
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		ProductID:         gateway.DefaultProductID,
		Quantity:          1,
		IdempotencyKey:    "live-b2-q-" + runSuffix,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", b2Quote.Decision, "code=%s msg=%s", b2Quote.ErrorCode, b2Quote.ErrorMessage)

	b2OrderKey := "live-b2-o-" + runSuffix
	b2Order, err := stack.Wallet.CreateOrder(ctx, agent.CreateOrderInput{
		Actor:             "B2",
		GrantID:           childID,
		TaskID:            f.RPTask.ID,
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		QuoteID:           b2Quote.QuoteID,
		AmountMinor:       b2Quote.TotalAmountMinor,
		IdempotencyKey:    b2OrderKey,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", b2Order.Decision, "code=%s msg=%s", b2Order.ErrorCode, b2Order.ErrorMessage)

	// Revoke childID on Fabric and await view replay past block r.
	_, a1Mgmt, _, err := inst.Role("A1")
	require.NoError(t, err)
	mgmtClient := NewLocalMTLSClientWithFingerprint(stack.Management.Handler(), f.Identities["A1"].ID, "MANAGEMENT", a1Mgmt.MSPID, a1Mgmt.CertificateSHA256)
	child, err := stack.FabricSP.AssembleSnapshot(ctx, childID, time.Now().UTC())
	require.NoError(t, err)
	mutation, err := json.Marshal(registry.Mutation{
		Bound: registry.Bound{DeploymentID: dep.DeploymentID}, ID: childID,
		ExpectedRevision: 1, ExpectedDigest: child.Snapshot.Grants[childID].Digest, Reason: "post-order revocation audit test",
	})
	require.NoError(t, err)
	key := "live-revoke-" + runSuffix
	requestRevoke, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://a.local/v1/management/RevokeGrant", bytes.NewReader(mutation))
	require.NoError(t, err)
	requestRevoke.Header.Set("Idempotency-Key", key)
	requestRevoke.Header.Set("Content-Type", "application/json")
	accepted, err := mgmtClient.Do(requestRevoke)
	require.NoError(t, err)
	defer accepted.Body.Close()
	require.Equal(t, http.StatusAccepted, accepted.StatusCode)
	var queued registrysvc.OperationView
	require.NoError(t, json.NewDecoder(accepted.Body).Decode(&queued))

	var committed registrysvc.OperationView
	require.NoError(t, fabric.Poll(ctx, 15*time.Second, func() (bool, error) {
		response, err := mgmtClient.Get("https://a.local/v1/operations/" + queued.OperationID)
		if err != nil {
			return false, err
		}
		defer response.Body.Close()
		if err := json.NewDecoder(response.Body).Decode(&committed); err != nil {
			return false, err
		}
		return committed.Status != "PENDING", nil
	}))
	require.Equal(t, "CONFIRMED", committed.Status)
	require.Nil(t, committed.FailureCode)
	journal := fabric.NewJournal(inst, db, dep.DeploymentID)
	original, err := journal.Load(ctx, queued.OperationID, db)
	require.NoError(t, err)
	require.NotNil(t, original)
	require.NotNil(t, original.Commit)
	require.Equal(t, original.TxID, committed.TxID)
	require.Equal(t, &original.Commit.Index, committed.TransactionIndex)
	require.Equal(t, "peer-c", original.Commit.ObservedPeer)
	require.Equal(t, &original.Commit.ObservedPeer, committed.ObservedPeer)
	v := fabric.View{DB: db, Deployment: dep}
	require.NoError(t, fabric.Poll(ctx, 15*time.Second, func() (bool, error) {
		head, hErr := v.Head(ctx, db, false)
		return head != nil && head.Number >= original.Commit.Number, hErr
	}))

	// Post-revocation request by B2 must be rejected.
	postRevQuote, err := stack.Wallet.RequestQuote(ctx, agent.RequestQuoteInput{
		Actor:             "B2",
		GrantID:           childID,
		TaskID:            f.RPTask.ID,
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		ProductID:         gateway.DefaultProductID,
		Quantity:          1,
		IdempotencyKey:    "live-b2-postrev-" + runSuffix,
	})
	require.NoError(t, err)
	assert.Equal(t, "DENY", postRevQuote.Decision)

	// Historical h < r audit for b2Order must return CREATED + MATCHED with h < r!
	b2Act, err := stack.Wallet.GetClientActionByKey(ctx, f.Identities["B2"].ID, f.RPTask.ID, protocol.ActionOrderCreate, b2OrderKey)
	require.NoError(t, err)
	audClient := NewLocalMTLSClient(stack.Gateway.Handler(), defaultAuditorDID, "C_AUDITOR", "CMsp")
	auditPayload, err := json.Marshal(gateway.AuditOrderOutcomeRequest{
		DeploymentID:   dep.DeploymentID,
		Actor:          f.Identities["B2"].ID,
		TaskID:         f.RPTask.ID,
		IdempotencyKey: b2OrderKey,
		RequestHash:    b2Act.RequestHash,
		ChallengeIDs:   b2Act.ChallengeIDs,
	})
	require.NoError(t, err)
	auditResp, err := audClient.Post("https://c.local/v1/audit/order-outcomes", "application/json", bytes.NewReader(auditPayload))
	require.NoError(t, err)
	defer auditResp.Body.Close()
	require.Equal(t, http.StatusOK, auditResp.StatusCode)
	var auditBody gateway.AuditOrderOutcomeResponse
	require.NoError(t, json.NewDecoder(auditResp.Body).Decode(&auditBody))
	assert.Equal(t, "CREATED", auditBody.Outcome)
	assert.Equal(t, "MATCHED", auditBody.HistoricalStatus, "reason=%s", auditBody.HistoricalReason)
	require.NotNil(t, auditBody.DecisionBlock)
	require.NotNil(t, auditBody.RevocationBlock)
	assert.Less(t, *auditBody.DecisionBlock, *auditBody.RevocationBlock)

	// 5. Verify registrysvc.Service HTTP management operation endpoint with mTLS fingerprint.
	mgmtReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://a.local/v1/management/RevokeGrant", bytes.NewReader([]byte(fmt.Sprintf(`{"deploymentId":%q,"id":%q,"expectedRevision":1,"expectedDigest":%q}`, dep.DeploymentID, childID, delOut.Grant.GrantID))))
	require.NoError(t, err)
	mgmtReq.Header.Set("Content-Type", "application/json")
	mgmtReq.Header.Set("Idempotency-Key", "live-mgmt-check-"+runSuffix)
	mgmtResp, err := mgmtClient.Do(mgmtReq)
	require.NoError(t, err)
	_ = mgmtResp.Body.Close()
	// Already revoked at revision 2, so pre-acceptance revision check must return 409 STATE_CHANGED.
	assert.Equal(t, http.StatusConflict, mgmtResp.StatusCode)

	// Also confirm GET /v1/operations/{unknown} returns 404 OPERATION_UNKNOWN.
	getOpResp, err := mgmtClient.Get("https://a.local/v1/operations/nonexistent-op")
	require.NoError(t, err)
	defer getOpResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, getOpResp.StatusCode)
	var opErr map[string]any
	require.NoError(t, json.NewDecoder(getOpResp.Body).Decode(&opErr))
	assert.Equal(t, registry.ErrCodeOperationUnknown, opErr["code"])

	// 6. Build and invoke ledgerctl binary for check, inspect, and mcp stdio handshake on live instance.
	binPath := filepath.Join(t.TempDir(), "ledgerctl")
	buildCmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, "../cmd/ledgerctl")
	out, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "build ledgerctl: %s", out)

	checkOut, err := exec.CommandContext(ctx, binPath, "check", "--dir", dir, "--grant", f.G1.ID).CombinedOutput()
	require.NoError(t, err, "ledgerctl check: %s", checkOut)
	var checkJSON map[string]any
	require.NoError(t, json.Unmarshal(checkOut, &checkJSON))
	assert.Equal(t, dep.DeploymentID, checkJSON["deploymentId"])

	head, err := v.Head(ctx, db, false)
	require.NoError(t, err)
	require.NotNil(t, head)
	inspectOut, err := exec.CommandContext(ctx, binPath, "inspect", "--dir", dir, "--grant", f.G1.ID, "--block", strconv.FormatUint(head.Number, 10)).CombinedOutput()
	require.NoError(t, err, "ledgerctl inspect: %s", inspectOut)
	var inspectJSON map[string]any
	require.NoError(t, json.Unmarshal(inspectOut, &inspectJSON))
	assert.Equal(t, "historical", inspectJSON["mode"])

	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "live-verify", Version: "v1.0.0"}, nil)
	session, err := mcpClient.Connect(ctx, &mcp.CommandTransport{
		Command: exec.CommandContext(ctx, binPath, "mcp", "--dir", dir),
	}, nil)
	require.NoError(t, err)
	toolsResp, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	require.NoError(t, err)
	assert.Len(t, toolsResp.Tools, 6)
	require.NoError(t, session.Close())
}
