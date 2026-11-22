//go:build db

package agent_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/agent"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/platform/internal/testutil"
	"grad/protocol"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

func TestDBCreateOrderPreSendIntentLockAndResponseLossReconciliation(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()

	fx := newUnitFixture(t, func(cfg *agent.WalletConfig) {
		cfg.DB = pool
	})

	g2ID := protocol.DigestBytes([]byte("db-g2-b1"))
	_, err := fx.wallet.DelegateGrant(ctx, agent.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID, GrantID: g2ID,
		TaskID: fx.taskID, AuthorizationMode: protocol.ModeBuyerMandate,
		MaxAmountMinor: 100000, RemainingDepth: 0,
	})
	require.NoError(t, err)

	q, err := fx.wallet.RequestQuote(ctx, agent.RequestQuoteInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, ProductID: "urn:grad:product:P1", Quantity: 1,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", q.Decision)

	// 1. Verify pre-send OUTCOME_UNKNOWN intent lock is persisted in PostgreSQL BEFORE gateway receives the challenge request.
	lostKey := "db-pre-send-lost-1"
	var sawPreSendRow atomic.Bool
	fx.gw.onChallenge = func(req agent.ChallengeRequest) {
		if req.TaskID != fx.taskID || req.Actor != fx.didB1 {
			return
		}
		rec, gErr := fx.wallet.GetClientActionByKey(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, lostKey)
		if gErr == nil && rec != nil &&
			rec.Status == agent.ActionStatusOutcomeUnknown &&
			rec.SendRevision == 1 &&
			rec.RequestHash == req.RequestHash &&
			rec.IdempotencyKey == lostKey {
			sawPreSendRow.Store(true)
		}
	}
	fx.gw.mu.Lock()
	fx.gw.failExecuteOnce[lostKey] = true
	fx.gw.mu.Unlock()

	ordResp, err := fx.wallet.CreateOrder(ctx, agent.CreateOrderInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: q.QuoteID,
		AmountMinor: 80000, IdempotencyKey: lostKey,
	})
	require.NoError(t, err)
	assert.True(t, sawPreSendRow.Load(), "client_actions row MUST exist with OUTCOME_UNKNOWN and sendRevision=1 before contacting gateway")
	assert.Equal(t, "UNKNOWN", ordResp.Decision)
	assert.Equal(t, agent.ActionStatusOutcomeUnknown, ordResp.ActionStatus)
	assert.Equal(t, int64(1), ordResp.SendRevision)

	// Verify BeginClientAction rejects conflicting requestHash for the same idempotencyKey.
	_, conflictErr := fx.wallet.BeginClientAction(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, lostKey, protocol.DigestBytes([]byte("different-request")), "{}")
	require.Error(t, conflictErr)
	assert.True(t, protocol.HasCode(conflictErr, protocol.ErrCodeIdempotencyConflict))

	// 2. Reconcile order: stops delayed worker via sendRevision++, registers case, audits C, applies CREATED receipt via ReceiptHandler().
	recOut, err := fx.wallet.ReconcileOrder(ctx, agent.ReconcileOrderInput{
		Actor: "B1", TaskID: fx.taskID, IdempotencyKey: lostKey,
	})
	require.NoError(t, err)
	assert.Equal(t, "CREATED", recOut.Outcome)
	assert.Equal(t, "MATCHED", recOut.HistoricalStatus)
	assert.Equal(t, int64(2), recOut.SendRevision)
	assert.Equal(t, agent.ActionStatusReconciled, recOut.ActionStatus)
	assert.NotEmpty(t, recOut.OrderID)
	assert.NotEmpty(t, recOut.CreationDecisionID)

	// 3. Delayed worker holding stale sendRevision=1 MUST be blocked by both RecordClientActionChallenge and DispatchClientAction.
	_, staleChalErr := fx.wallet.RecordClientActionChallenge(ctx, ordResp.ActionID, 1, "urn:grad:chal:stale", "{}")
	require.Error(t, staleChalErr)
	assert.True(t, protocol.HasCode(staleChalErr, protocol.ErrCodeStateChanged))

	dispatched := false
	staleDispErr := fx.wallet.DispatchClientAction(ctx, ordResp.ActionID, 1, func() error {
		dispatched = true
		return nil
	})
	require.Error(t, staleDispErr)
	assert.True(t, protocol.HasCode(staleDispErr, protocol.ErrCodeStateChanged))
	assert.False(t, dispatched, "stale worker callback must never execute")

	// 4. Verify persisted PostgreSQL row in client_actions & order_outcome_receipts.
	dbAction, err := fx.wallet.GetClientActionByKey(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, lostKey)
	require.NoError(t, err)
	assert.Equal(t, agent.ActionStatusReconciled, dbAction.Status)
	assert.Equal(t, "CREATED", dbAction.Outcome)
	assert.Equal(t, recOut.OrderID, dbAction.OrderID)
	assert.Equal(t, recOut.CreationDecisionID, dbAction.DecisionID)
	assert.Equal(t, recOut.CaseID, dbAction.CaseID)
	assert.Equal(t, int64(2), dbAction.SendRevision)

	var receiptCount int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM order_outcome_receipts WHERE deployment_id=$1 AND case_id=$2`, fx.depID, recOut.CaseID).Scan(&receiptCount))
	assert.Equal(t, 1, receiptCount)

	// 5. ListClientActions returns the persisted row.
	listed, err := fx.wallet.ListClientActions(ctx, fx.didB1, fx.taskID)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, dbAction.ActionID, listed[0].ActionID)
}

func TestDBReceiptSemanticsIdempotencyConflictStaleRevisionAndNoReopen(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()

	fx := newUnitFixture(t, func(cfg *agent.WalletConfig) {
		cfg.DB = pool
	})

	// Seed an OUTCOME_UNKNOWN intent and stop send (sendRevision -> 2, case_id assigned).
	reqHash := protocol.DigestBytes([]byte("db-receipt-semantics-req"))
	act, err := fx.wallet.BeginClientAction(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-sem-key-1", reqHash, `{"idempotencyKey":"db-sem-key-1"}`)
	require.NoError(t, err)
	assert.Equal(t, agent.ActionStatusOutcomeUnknown, act.Status)
	assert.Equal(t, int64(1), act.SendRevision)

	caseID := "urn:grad:case:db-semantics-1"
	stopped, err := fx.wallet.StopClientActionSend(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-sem-key-1", caseID, "")
	require.NoError(t, err)
	assert.Equal(t, int64(2), stopped.SendRevision)
	assert.Equal(t, caseID, stopped.CaseID)

	// 1. Stale sendRevision (1 != 2) MUST be flagged STALE_SEND_REVISION and MUST NOT mutate client_actions.
	staleOrderID := "urn:grad:order:stale"
	staleResp, err := fx.wallet.ApplyOrderOutcomeReceipt(ctx, agent.OrderOutcomeReceipt{
		CaseID: caseID, CheckNo: 1, SendRevision: 1, DeploymentID: fx.depID,
		Actor: fx.didB1, TaskID: fx.taskID, RequestHash: reqHash,
		Outcome: "CREATED", OrderID: &staleOrderID, HistoricalStatus: "MATCHED", AuditAt: fx.now.Unix(),
	})
	require.NoError(t, err)
	assert.Equal(t, "STALE_SEND_REVISION", staleResp.Status)
	assert.Equal(t, agent.ActionStatusOutcomeUnknown, staleResp.ClientActionStatus)

	cur, err := fx.wallet.GetClientActionByKey(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-sem-key-1")
	require.NoError(t, err)
	assert.Equal(t, agent.ActionStatusOutcomeUnknown, cur.Status)
	assert.Empty(t, cur.OrderID)

	// 2. UNKNOWN receipt (check_no=1, send_revision=2) records outcome='UNKNOWN' and keeps status=OUTCOME_UNKNOWN.
	unkReceipt := agent.OrderOutcomeReceipt{
		CaseID: caseID, CheckNo: 1, SendRevision: 2, DeploymentID: fx.depID,
		Actor: fx.didB1, TaskID: fx.taskID, RequestHash: reqHash,
		Outcome: "UNKNOWN", HistoricalStatus: "NO_DECISION", AuditAt: fx.now.Unix(),
	}
	unkResp, err := fx.wallet.ApplyOrderOutcomeReceipt(ctx, unkReceipt)
	require.NoError(t, err)
	assert.Equal(t, "UNKNOWN", unkResp.Status)
	assert.Equal(t, agent.ActionStatusOutcomeUnknown, unkResp.ClientActionStatus)

	// 3. Exact duplicate receipt replay returns IDEMPOTENT_REPLAY.
	replayResp, err := fx.wallet.ApplyOrderOutcomeReceipt(ctx, unkReceipt)
	require.NoError(t, err)
	assert.Equal(t, "IDEMPOTENT_REPLAY", replayResp.Status)
	assert.Equal(t, agent.ActionStatusOutcomeUnknown, replayResp.ClientActionStatus)

	// 4. Same (case_id, send_revision, check_no) with conflicting content returns IDEMPOTENCY_CONFLICT.
	conflictOrderID := "urn:grad:order:conflict"
	_, err = fx.wallet.ApplyOrderOutcomeReceipt(ctx, agent.OrderOutcomeReceipt{
		CaseID: caseID, CheckNo: 1, SendRevision: 2, DeploymentID: fx.depID,
		Actor: fx.didB1, TaskID: fx.taskID, RequestHash: reqHash,
		Outcome: "CREATED", OrderID: &conflictOrderID, HistoricalStatus: "MATCHED", AuditAt: fx.now.Unix(),
	})
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeIdempotencyConflict))

	// 5. NOT_CREATED receipt (check_no=2, send_revision=2) transitions client_actions to RECONCILED.
	notCreatedResp, err := fx.wallet.ApplyOrderOutcomeReceipt(ctx, agent.OrderOutcomeReceipt{
		CaseID: caseID, CheckNo: 2, SendRevision: 2, DeploymentID: fx.depID,
		Actor: fx.didB1, TaskID: fx.taskID, RequestHash: reqHash,
		Outcome: "NOT_CREATED", HistoricalStatus: "NO_DECISION", AuditAt: fx.now.Unix() + 10,
	})
	require.NoError(t, err)
	assert.Equal(t, "RECONCILED", notCreatedResp.Status)
	assert.Equal(t, agent.ActionStatusReconciled, notCreatedResp.ClientActionStatus)

	cur, err = fx.wallet.GetClientActionByKey(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-sem-key-1")
	require.NoError(t, err)
	assert.Equal(t, agent.ActionStatusReconciled, cur.Status)
	assert.Equal(t, "NOT_CREATED", cur.Outcome)
	assert.Empty(t, cur.OrderID)

	// 6. Late UNKNOWN receipt (check_no=3, send_revision=2) MUST NOT reopen already-finalized RECONCILED intent!
	lateUnkResp, err := fx.wallet.ApplyOrderOutcomeReceipt(ctx, agent.OrderOutcomeReceipt{
		CaseID: caseID, CheckNo: 3, SendRevision: 2, DeploymentID: fx.depID,
		Actor: fx.didB1, TaskID: fx.taskID, RequestHash: reqHash,
		Outcome: "UNKNOWN", HistoricalStatus: "NO_DECISION", AuditAt: fx.now.Unix() + 20,
	})
	require.NoError(t, err)
	assert.Equal(t, "ALREADY_FINALIZED", lateUnkResp.Status)
	assert.Equal(t, agent.ActionStatusReconciled, lateUnkResp.ClientActionStatus)

	afterLate, err := fx.wallet.GetClientActionByKey(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-sem-key-1")
	require.NoError(t, err)
	assert.Equal(t, agent.ActionStatusReconciled, afterLate.Status)
	assert.Equal(t, "NOT_CREATED", afterLate.Outcome, "late UNKNOWN receipt must never overwrite finalized outcome")
}

func TestDBReceiptHandlerMTLSAuthorization(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()

	fx := newUnitFixture(t, func(cfg *agent.WalletConfig) {
		cfg.DB = pool
	})

	reqHash := protocol.DigestBytes([]byte("db-mtls-auth-req"))
	_, err := fx.wallet.BeginClientAction(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-mtls-key-1", reqHash, `{}`)
	require.NoError(t, err)
	caseID := "urn:grad:case:db-mtls-1"
	_, err = fx.wallet.StopClientActionSend(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-mtls-key-1", caseID, "")
	require.NoError(t, err)

	ordID := "urn:grad:order:db-mtls-1"
	decID := "urn:grad:decision:db-mtls-1"
	receipt := agent.OrderOutcomeReceipt{
		CaseID: caseID, CheckNo: 1, SendRevision: 2, DeploymentID: fx.depID,
		Actor: fx.didB1, TaskID: fx.taskID, RequestHash: reqHash,
		Outcome: "CREATED", OrderID: &ordID, CreationDecisionID: &decID,
		HistoricalStatus: "MATCHED", AuditAt: fx.now.Unix(),
	}
	payload, err := json.Marshal(receipt)
	require.NoError(t, err)

	handler := fx.wallet.ReceiptHandler()

	sendReceipt := func(id *mtls.Identity, extraHeaders map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/internal/order-outcome-receipts", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range extraHeaders {
			req.Header.Set(k, v)
		}
		if id != nil {
			req = req.WithContext(mtls.WithIdentity(req.Context(), *id))
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// 1. Missing mTLS identity (even with spoofed headers) -> 403 AUDIT_FORBIDDEN.
	recNoAuth := sendReceipt(nil, map[string]string{
		"X-Caller-Role": "C_AUDIT_SERVICE",
		"X-Caller-DID":  "did:web:c.local:services:audit",
	})
	assert.Equal(t, http.StatusForbidden, recNoAuth.Code)
	var env httpx.ErrorEnvelope
	require.NoError(t, json.Unmarshal(recNoAuth.Body.Bytes(), &env))
	assert.Equal(t, protocol.ErrCodeAuditForbidden, env.Code)

	// 2. Non-c.local domain -> 403 AUDIT_FORBIDDEN.
	recWrongDomain := sendReceipt(&mtls.Identity{Role: "C_AUDIT_SERVICE", DID: "did:web:a.local:services:audit"}, nil)
	assert.Equal(t, http.StatusForbidden, recWrongDomain.Code)
	env = httpx.ErrorEnvelope{}
	require.NoError(t, json.Unmarshal(recWrongDomain.Body.Bytes(), &env))
	assert.Equal(t, protocol.ErrCodeAuditForbidden, env.Code)

	// 3. Wrong role from c.local -> 403 AUDIT_FORBIDDEN.
	recWrongRole := sendReceipt(&mtls.Identity{Role: "B_RECOVERY", DID: "did:web:c.local:services:recovery"}, nil)
	assert.Equal(t, http.StatusForbidden, recWrongRole.Code)
	env = httpx.ErrorEnvelope{}
	require.NoError(t, json.Unmarshal(recWrongRole.Body.Bytes(), &env))
	assert.Equal(t, protocol.ErrCodeAuditForbidden, env.Code)

	// 4. Valid C_AUDIT_SERVICE from c.local -> 200 OK & transitions client_actions to RECONCILED.
	recOK := sendReceipt(&mtls.Identity{Role: "C_AUDIT_SERVICE", DID: "did:web:c.local:services:audit"}, nil)
	assert.Equal(t, http.StatusOK, recOK.Code)
	var resp agent.OrderOutcomeReceiptResponse
	require.NoError(t, json.Unmarshal(recOK.Body.Bytes(), &resp))
	assert.Equal(t, "RECONCILED", resp.Status)
	assert.Equal(t, agent.ActionStatusReconciled, resp.ClientActionStatus)

	// 5. Valid C_AUDITOR from c.local replaying same receipt -> 200 OK IDEMPOTENT_REPLAY.
	recAuditor := sendReceipt(&mtls.Identity{Role: "C_AUDITOR", DID: "did:web:c.local:auditors:c1"}, nil)
	assert.Equal(t, http.StatusOK, recAuditor.Code)
	resp = agent.OrderOutcomeReceiptResponse{}
	require.NoError(t, json.Unmarshal(recAuditor.Body.Bytes(), &resp))
	assert.Equal(t, "IDEMPOTENT_REPLAY", resp.Status)

	// 6. Conflicting payload on same key via ReceiptHandler -> 409 IDEMPOTENCY_CONFLICT.
	badOrder := "urn:grad:order:different"
	conflictReceipt := receipt
	conflictReceipt.OrderID = &badOrder
	conflictPayload, err := json.Marshal(conflictReceipt)
	require.NoError(t, err)
	conflictReq := httptest.NewRequest(http.MethodPost, "/v1/internal/order-outcome-receipts", bytes.NewReader(conflictPayload))
	conflictReq.Header.Set("Content-Type", "application/json")
	conflictReq = conflictReq.WithContext(mtls.WithIdentity(conflictReq.Context(), mtls.Identity{
		Role: "C-AUDITOR", DID: "did:web:c.local:auditors:c2",
	}))
	conflictRec := httptest.NewRecorder()
	handler.ServeHTTP(conflictRec, conflictReq)
	assert.Equal(t, http.StatusConflict, conflictRec.Code)
	env = httpx.ErrorEnvelope{}
	require.NoError(t, json.Unmarshal(conflictRec.Body.Bytes(), &env))
	assert.Equal(t, protocol.ErrCodeIdempotencyConflict, env.Code)
}
