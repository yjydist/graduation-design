package gateway_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"graduation-design/internal/fabric"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"
	"graduation-design/internal/serviceauth"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedHistoricalBlocksFromCurrent(t *testing.T, h *procurementGatewayHarness, tag string) {
	t.Helper()
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `DELETE FROM fabric_version WHERE deployment=$1`, h.depID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM fabric_block WHERE deployment=$1`, h.depID); err != nil {
		t.Fatal(err)
	}
	b0Hash := api.Digest([]byte("blk0:" + tag))
	b1Hash := api.Digest([]byte("blk1:" + tag))
	if _, err := h.pool.Exec(ctx, `INSERT INTO fabric_block(deployment, block_no, hash, parent, data)
		VALUES($1, 0, $2, '', ''::bytea), ($1, 1, $3, $2, ''::bytea)`,
		h.depID, b0Hash, b1Hash,
	); err != nil {
		t.Fatal(err)
	}
	rows, err := h.pool.Query(ctx, `SELECT key, value FROM fabric_current WHERE deployment=$1 ORDER BY key ASC`, h.depID)
	if err != nil {
		t.Fatal(err)
	}
	type kv struct {
		k string
		v []byte
	}
	var kvs []kv
	for rows.Next() {
		var item kv
		if err := rows.Scan(&item.k, &item.v); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		kvs = append(kvs, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for idx, item := range kvs {
		if _, err := h.pool.Exec(ctx, `INSERT INTO fabric_version(deployment, key, block_no, tx_index, tx_id, value)
			VALUES($1, $2, 1, $3, $4, $5)`,
			h.depID, item.k, idx, "tx-init-"+tag, item.v,
		); err != nil {
			t.Fatal(err)
		}
	}
}

func registerAuditCleanup(t *testing.T, pool *pgxpool.Pool, depID string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM decision_evidence WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM order_outcome_outbox WHERE deployment_id=$1`, depID)
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM order_outcome_receipts WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM order_outcome_audits WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM order_outcome_cases WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM fabric_version WHERE deployment=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM fabric_block WHERE deployment=$1`, depID)
	})
}

func callJSONEndpoint(t *testing.T, h http.Handler, method, path string, headers map[string]string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Test fixtures install the authenticated channel independently of the HTTP headers.
	req = req.WithContext(serviceauth.WithIdentity(req.Context(), serviceauth.Identity{Role: headers["X-Caller-Role"], DID: headers["X-Caller-DID"]}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestClientActionStopSendAndCaseTransitions(t *testing.T) {
	h := newProcurementGatewayHarness(t)
	registerAuditCleanup(t, h.pool, h.depID)
	ctx := t.Context()

	currentSec := h.fixedNow.Unix()
	srv, err := gateway.NewServer(gateway.Config{
		DB: h.pool, State: h.state.GatewayAdapter(), Delivery: h.delivery, DIDs: h.dids, Policy: h.bundle,
		DeploymentID: h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID,
		AuditorDIDs:      []string{"did:web:c.local:auditors:c1"},
		VerifierID:       "c-gw-1",
		ClockErrorMargin: api.ClockError, NowFn: func() time.Time { return time.Unix(currentSec, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()

	qID := "urn:grad:quote:order-recovery-stop-1"
	orderReq := protocol.AccessRequest{
		SchemaVersion:     protocol.SchemaVersion,
		DeploymentID:      h.depID,
		Actor:             h.didB1,
		PrincipalDomain:   "A",
		AuthorizationMode: h.rp.mode,
		TaskID:            h.rp.taskID,
		Audience:          h.audience,
		Resource:          "urn:grad:resource:C:orders",
		Action:            "order.create",
		SupplierID:        h.supplierID,
		ProductID:         gateway.DefaultProductID,
		Quantity:          1,
		Currency:          "CNY",
		QuoteID:           &qID,
		AmountMinor:       80000,
		IdempotencyKey:    "order-recovery-stop-key-1",
	}
	reqHash, err := orderReq.Hash(false)
	if err != nil {
		t.Fatal(err)
	}
	reqRaw, _ := json.Marshal(orderReq)

	// 1. BeginClientAction starts in PENDING at send_revision=1.
	act, err := gateway.BeginClientAction(ctx, h.pool, h.depID, h.didB1, h.rp.taskID, "order.create", orderReq.IdempotencyKey, reqHash, currentSec)
	if err != nil {
		t.Fatal(err)
	}
	if act.Status != "PENDING" || act.SendRevision != 1 {
		t.Fatalf("unexpected initial client action: %+v", act)
	}

	// Registering a case before stopping send MUST be rejected (409 STATE_CHANGED).
	caseReqPre := gateway.OrderOutcomeCaseRequest{
		CaseID:       "urn:grad:case:pre-stop",
		SendRevision: act.SendRevision,
		DeploymentID: h.depID,
		Request:      orderReq,
		RequestHash:  reqHash,
		ChallengeIDs: []string{"urn:grad:challenge:ch1"},
	}
	preRec := callJSONEndpoint(t, handler, http.MethodPost, "/v1/internal/order-outcome-cases",
		map[string]string{"X-Caller-Role": "B_RECOVERY", "X-Caller-DID": "did:web:b.local:services:recovery"},
		caseReqPre,
	)
	if preRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 before OUTCOME_UNKNOWN stop-send, got %d %s", preRec.Code, preRec.Body.String())
	}

	// 2. Worker records challenge ch1 under send_revision=1 -> OUTCOME_UNKNOWN.
	act, err = gateway.RecordClientActionChallenge(ctx, h.pool, h.depID, act.ActionID, 1, "urn:grad:challenge:ch1", string(reqRaw), currentSec)
	if err != nil {
		t.Fatal(err)
	}
	if act.Status != "OUTCOME_UNKNOWN" || !slices.Equal(act.ChallengeIDs, []string{"urn:grad:challenge:ch1"}) {
		t.Fatalf("unexpected action after recording ch1: %+v", act)
	}

	// 3. Recovery service invokes StopClientActionSend -> increments send_revision to 2.
	stopped, err := gateway.StopClientActionSend(ctx, h.pool, h.depID, h.didB1, h.rp.taskID, "order.create", orderReq.IdempotencyKey, "urn:grad:case:case-1", string(reqRaw), currentSec)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.SendRevision != 2 || stopped.Status != "OUTCOME_UNKNOWN" || stopped.CaseID != "urn:grad:case:case-1" {
		t.Fatalf("unexpected stopped client action: %+v", stopped)
	}

	// Delayed worker with stale send_revision=1 MUST be rejected with STATE_CHANGED.
	if _, err := gateway.RecordClientActionChallenge(ctx, h.pool, h.depID, act.ActionID, 1, "urn:grad:challenge:late", string(reqRaw), currentSec); !protocol.HasCode(err, protocol.ErrCodeStateChanged) {
		t.Fatalf("expected STATE_CHANGED for stale worker send_revision=1, got %v", err)
	}

	// Verify unauthorized role cannot register outcome case (403 AUDIT_FORBIDDEN).
	badRoleRec := callJSONEndpoint(t, handler, http.MethodPost, "/v1/internal/order-outcome-cases",
		map[string]string{"X-Caller-Role": "A_ADMIN", "X-Caller-DID": "did:web:a.local:admins:a"},
		gateway.OrderOutcomeCaseRequest{
			CaseID:       "urn:grad:case:case-1",
			SendRevision: 2,
			DeploymentID: h.depID,
			Request:      orderReq,
			RequestHash:  reqHash,
			ChallengeIDs: []string{"urn:grad:challenge:ch1"},
		},
	)
	if badRoleRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-recovery caller, got %d %s", badRoleRec.Code, badRoleRec.Body.String())
	}

	// Register case at matching sendRevision=2 -> 202 Accepted, idempotent on retry, immutable against change.
	caseReq := gateway.OrderOutcomeCaseRequest{
		CaseID:       "urn:grad:case:case-1",
		SendRevision: 2,
		DeploymentID: h.depID,
		Request:      orderReq,
		RequestHash:  reqHash,
		ChallengeIDs: []string{"urn:grad:challenge:ch1"},
	}
	bHeaders := map[string]string{"X-Caller-Role": "B_RECOVERY", "X-Caller-DID": "did:web:b.local:services:recovery"}
	okRec := callJSONEndpoint(t, handler, http.MethodPost, "/v1/internal/order-outcome-cases", bHeaders, caseReq)
	if okRec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted, got %d %s", okRec.Code, okRec.Body.String())
	}
	idemRec := callJSONEndpoint(t, handler, http.MethodPost, "/v1/internal/order-outcome-cases", bHeaders, caseReq)
	if idemRec.Code != http.StatusAccepted {
		t.Fatalf("expected idempotent 202 Accepted, got %d %s", idemRec.Code, idemRec.Body.String())
	}

	// Tampered challenge list under same caseId -> 409 IDEMPOTENCY_CONFLICT.
	mutated := caseReq
	mutated.ChallengeIDs = []string{"urn:grad:challenge:ch1", "urn:grad:challenge:ch2"}
	conflictRec := callJSONEndpoint(t, handler, http.MethodPost, "/v1/internal/order-outcome-cases", bHeaders, mutated)
	if conflictRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 IDEMPOTENCY_CONFLICT on same caseId mutation, got %d %s", conflictRec.Code, conflictRec.Body.String())
	}

	// Different caseId for same key -> 409 STATE_CHANGED.
	otherCase := caseReq
	otherCase.CaseID = "urn:grad:case:case-other"
	otherRec := callJSONEndpoint(t, handler, http.MethodPost, "/v1/internal/order-outcome-cases", bHeaders, otherCase)
	if otherRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 STATE_CHANGED on second caseId for same key, got %d %s", otherRec.Code, otherRec.Body.String())
	}
}

func TestDualGatewayOrderOutcomeAuditAndHistoricalHvsR(t *testing.T) {
	h := newProcurementGatewayHarness(t)
	registerAuditCleanup(t, h.pool, h.depID)
	ctx := t.Context()

	seedHistoricalBlocksFromCurrent(t, h, strings.TrimPrefix(h.depID, h.depID[:0]))
	// Domain A was suspended before h=1 and resumed at h=1. That past suspension
	// must not invalidate an order created after the domain became active again.
	var domainJSON []byte
	if err := h.pool.QueryRow(ctx, `SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2`, h.depID, api.Key("domain", "A")).Scan(&domainJSON); err != nil {
		t.Fatal(err)
	}
	var priorDomain api.Domain
	if err := json.Unmarshal(domainJSON, &priorDomain); err != nil {
		t.Fatal(err)
	}
	priorDomain.Status = api.Suspended
	priorJSON, _ := json.Marshal(priorDomain)
	if _, err := h.pool.Exec(ctx, `INSERT INTO fabric_version(deployment,key,block_no,tx_index,tx_id,value) VALUES($1,$2,0,0,'prior-suspension',$3)`, h.depID, api.Key("domain", "A"), priorJSON); err != nil {
		t.Fatal(err)
	}
	// Fix block hashes to match exact seeded fabric_head block 1 hash.
	var headHash string
	if err := h.pool.QueryRow(ctx, `SELECT hash FROM fabric_head WHERE deployment=$1`, h.depID).Scan(&headHash); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE fabric_block SET hash=$1 WHERE deployment=$2 AND block_no=1`, headHash, h.depID); err != nil {
		t.Fatal(err)
	}

	var currentSec atomic.Int64
	currentSec.Store(h.fixedNow.Unix())
	nowFn := func() time.Time { return time.Unix(currentSec.Load(), 0) }
	// Keep monotonic probe fresh as simulated wall clock advances within test.
	h.state.SetMonoClock(nowFn)
	h.state.SetStaticProbe(&fabric.ProbeSnapshot{
		TxID: "probe-m3", ProbeBlock: 1, SentAt: h.fixedNow, Deadline: h.fixedNow.Add(600 * time.Second),
		SentMonoNs: h.fixedNow.UnixNano(), DeadlineMonoNs: h.fixedNow.Add(600 * time.Second).UnixNano(),
		AdoptedAt: h.fixedNow, AdoptedMonoNs: h.fixedNow.UnixNano(),
	})

	auditor1 := "did:web:c.local:auditors:c1"
	auditor2 := "did:web:c.local:auditors:c2"
	gw1, err := gateway.NewServer(gateway.Config{
		DB: h.pool, State: h.state.GatewayAdapter(), Delivery: h.delivery, DIDs: h.dids, Policy: h.bundle,
		DeploymentID: h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID,
		AuditorDIDs: []string{auditor1, auditor2}, VerifierID: "c-gw-1",
		ClockErrorMargin: api.ClockError, NowFn: nowFn,
	})
	if err != nil {
		t.Fatal(err)
	}
	gw2, err := gateway.NewServer(gateway.Config{
		DB: h.pool, State: h.state.GatewayAdapter(), Delivery: h.delivery, DIDs: h.dids, Policy: h.bundle,
		DeploymentID: h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID,
		AuditorDIDs: []string{auditor1, auditor2}, VerifierID: "c-gw-2",
		ClockErrorMargin: api.ClockError, NowFn: nowFn,
	})
	if err != nil {
		t.Fatal(err)
	}
	h1 := gw1.Handler()
	h2 := gw2.Handler()

	h.postContext(t, h1, h.rp.taskID, 0, "NORMAL", h.policyDeadline)

	// 1. Acquire quote Q800 via gw1.
	qRec := h.execReq(t, h1, h.rp, currentSec.Load(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, protocol.AccessRequest{
		SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1,
		PrincipalDomain: "A", AuthorizationMode: h.rp.mode, TaskID: h.rp.taskID,
		Audience: h.audience, Resource: "urn:grad:resource:C:quotes", Action: "quote.read",
		SupplierID: h.supplierID, ProductID: gateway.DefaultProductID, Quantity: 1,
		Currency: "CNY", AmountMinor: 0, IdempotencyKey: "order-recovery-q-1",
	})
	if qRec.Code != http.StatusOK {
		t.Fatalf("quote.read failed: %d %s", qRec.Code, qRec.Body.String())
	}
	var qResp gateway.ExecuteResponse
	_ = json.Unmarshal(qRec.Body.Bytes(), &qResp)
	quoteID := qResp.Quote.QuoteID

	// 2. B1 persists local intent & challenge ch1, submits order.create to gw1 -> response "lost" before updating B1 state.
	orderReq := protocol.AccessRequest{
		SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1,
		PrincipalDomain: "A", AuthorizationMode: h.rp.mode, TaskID: h.rp.taskID,
		Audience: h.audience, Resource: "urn:grad:resource:C:orders", Action: "order.create",
		SupplierID: h.supplierID, ProductID: gateway.DefaultProductID, Quantity: 1,
		Currency: "CNY", QuoteID: &quoteID, AmountMinor: 80000, IdempotencyKey: "order-recovery-ord-lost-1",
	}
	orderHash, _ := orderReq.Hash(false)
	orderRaw, _ := json.Marshal(orderReq)

	act, err := gateway.BeginClientAction(ctx, h.pool, h.depID, h.didB1, h.rp.taskID, "order.create", orderReq.IdempotencyKey, orderHash, currentSec.Load())
	if err != nil {
		t.Fatal(err)
	}
	ch1Rec := callJSONEndpoint(t, h1, http.MethodPost, "/v1/auth/challenges", nil, gateway.ChallengeRequest{
		Actor: h.didB1, TaskID: h.rp.taskID, RequestHash: orderHash,
	})
	if ch1Rec.Code != http.StatusCreated {
		t.Fatal(ch1Rec.Body.String())
	}
	var ch1 gateway.ChallengeResponse
	_ = json.Unmarshal(ch1Rec.Body.Bytes(), &ch1)

	act, err = gateway.RecordClientActionChallenge(ctx, h.pool, h.depID, act.ActionID, 1, ch1.ChallengeID, string(orderRaw), currentSec.Load())
	if err != nil {
		t.Fatal(err)
	}

	// Actually execute on gw1 at h=1, then simulate truncated response on B1's side.
	oRec := execReqWithChallenge(t, h1, h, h.rp, currentSec.Load(), h.b1PresPrefix, h.b1KeyID, h.privB1, orderReq, ch1)
	if oRec.Code != http.StatusOK {
		t.Fatalf("order.create failed: %d %s", oRec.Code, oRec.Body.String())
	}
	var oResp gateway.ExecuteResponse
	_ = json.Unmarshal(oRec.Body.Bytes(), &oResp)
	origOrderID := oResp.Order.OrderID
	origDecID := oResp.DecisionID

	// 3. Revoke G1 at block r = 2!
	g1Rev := h.rp.g1
	g1Rev.Version = api.Version{Status: api.Revoked, Revision: 2}
	rawG1Rev, _ := json.Marshal(g1Rev)
	b2Hash := api.Digest([]byte("blk2-rev-" + h.depID))
	if _, err := h.pool.Exec(ctx, `INSERT INTO fabric_block(deployment, block_no, hash, parent, data) VALUES($1, 2, $2, $3, ''::bytea)`,
		h.depID, b2Hash, headHash); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO fabric_version(deployment, key, block_no, tx_index, tx_id, value) VALUES($1,$2,2,0,'tx-rev-g1',$3)`,
		h.depID, api.Key("grant", g1Rev.ID), rawG1Rev); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE fabric_current SET value=$1 WHERE deployment=$2 AND key=$3`,
		rawG1Rev, h.depID, api.Key("grant", g1Rev.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE fabric_head SET block_no=2, hash=$1 WHERE deployment=$2`, b2Hash, h.depID); err != nil {
		t.Fatal(err)
	}

	// 4. B1 retry hits 403 ANCESTOR_INACTIVE on gw2.
	retryRec := h.execReq(t, h2, h.rp, currentSec.Load(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, orderReq)
	if retryRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 ANCESTOR_INACTIVE after G1 revocation at r=2, got %d %s", retryRec.Code, retryRec.Body.String())
	}

	// B1 stops send and registers case on gw2.
	stopped, err := gateway.StopClientActionSend(ctx, h.pool, h.depID, h.didB1, h.rp.taskID, "order.create", orderReq.IdempotencyKey, "urn:grad:case:lost-1", string(orderRaw), currentSec.Load())
	if err != nil {
		t.Fatal(err)
	}
	caseRegRec := callJSONEndpoint(t, h2, http.MethodPost, "/v1/internal/order-outcome-cases",
		map[string]string{"X-Caller-Role": "B_RECOVERY", "X-Caller-DID": "did:web:b.local:services:recovery"},
		gateway.OrderOutcomeCaseRequest{
			CaseID:       stopped.CaseID,
			SendRevision: stopped.SendRevision,
			DeploymentID: h.depID,
			Request:      orderReq,
			RequestHash:  orderHash,
			ChallengeIDs: stopped.ChallengeIDs,
		},
	)
	if caseRegRec.Code != http.StatusAccepted {
		t.Fatalf("case registration failed: %d %s", caseRegRec.Code, caseRegRec.Body.String())
	}

	// 5. S67: Non-auditor roles (B1, A admin, missing role) MUST get 403 AUDIT_FORBIDDEN and reveal nothing about order existence.
	for _, bad := range []struct{ name, role, did string }{
		{"B1", "BUYER_AGENT", h.didB1},
		{"A_ADMIN", "DOMAIN_ADMIN", "did:web:a.local:admins:admin1"},
		{"C_WRONG_DID", "C_AUDITOR", "did:web:a.local:auditors:evil"},
		{"UNAUTH", "", ""},
	} {
		forbRec := callJSONEndpoint(t, h2, http.MethodPost, "/v1/audit/order-outcomes",
			map[string]string{"X-Caller-Role": bad.role, "X-Caller-DID": bad.did},
			gateway.AuditOrderOutcomeRequest{CaseID: stopped.CaseID, ChallengeIDs: stopped.ChallengeIDs},
		)
		if forbRec.Code != http.StatusForbidden {
			t.Fatalf("%s expected 403 AUDIT_FORBIDDEN, got %d %s", bad.name, forbRec.Code, forbRec.Body.String())
		}
		var eb gateway.ErrorBody
		_ = json.Unmarshal(forbRec.Body.Bytes(), &eb)
		if eb.Code != protocol.ErrCodeAuditForbidden {
			t.Fatalf("%s expected code AUDIT_FORBIDDEN, got %+v", bad.name, eb)
		}
		if strings.Contains(forbRec.Body.String(), origOrderID) || strings.Contains(forbRec.Body.String(), "CREATED") {
			t.Fatalf("%s leaked order existence: %s", bad.name, forbRec.Body.String())
		}
	}

	// Snapshot business counts before C audit so we assert zero mutations to quotes/orders/business_keys/challenges.
	var ordCountBefore, quoteCountBefore, bkCountBefore, chalCountBefore int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM orders WHERE deployment_id=$1`, h.depID).Scan(&ordCountBefore)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM quotes WHERE deployment_id=$1`, h.depID).Scan(&quoteCountBefore)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM business_keys WHERE deployment_id=$1`, h.depID).Scan(&bkCountBefore)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM challenges WHERE deployment_id=$1`, h.depID).Scan(&chalCountBefore)

	// 6. C auditor audits via gw2 -> CREATED + original orderId + historical MATCHED (h=1 < r=2)!
	auditRec := callJSONEndpoint(t, h2, http.MethodPost, "/v1/audit/order-outcomes",
		map[string]string{"X-Caller-Role": "C_AUDITOR", "X-Caller-DID": auditor2},
		gateway.AuditOrderOutcomeRequest{CaseID: stopped.CaseID, ChallengeIDs: stopped.ChallengeIDs},
	)
	if auditRec.Code != http.StatusOK {
		t.Fatalf("C audit failed: %d %s", auditRec.Code, auditRec.Body.String())
	}
	var auditResp gateway.AuditOrderOutcomeResponse
	if err := json.Unmarshal(auditRec.Body.Bytes(), &auditResp); err != nil {
		t.Fatal(err)
	}
	if auditResp.Outcome != "CREATED" || auditResp.OrderID == nil || *auditResp.OrderID != origOrderID ||
		auditResp.CreationDecisionID == nil || *auditResp.CreationDecisionID != origDecID ||
		auditResp.HistoricalStatus != "MATCHED" || auditResp.DecisionBlock == nil || *auditResp.DecisionBlock != 1 ||
		auditResp.RevocationBlock == nil || *auditResp.RevocationBlock != 2 || auditResp.VerifierID != "c-gw-2" {
		t.Fatalf("unexpected C audit response: %+v", auditResp)
	}

	var ordCountAfter, quoteCountAfter, bkCountAfter, chalCountAfter int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM orders WHERE deployment_id=$1`, h.depID).Scan(&ordCountAfter)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM quotes WHERE deployment_id=$1`, h.depID).Scan(&quoteCountAfter)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM business_keys WHERE deployment_id=$1`, h.depID).Scan(&bkCountAfter)
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM challenges WHERE deployment_id=$1`, h.depID).Scan(&chalCountAfter)
	if ordCountBefore != ordCountAfter || quoteCountBefore != quoteCountAfter || bkCountBefore != bkCountAfter || chalCountBefore != chalCountAfter {
		t.Fatalf("audit mutated business tables!")
	}

	t.Run("RejectHeaderOnlyAuditorAndForgedReceipt", func(t *testing.T) {
		for _, path := range []string{"/v1/audit/order-outcomes", "/v1/internal/order-outcome-receipts"} {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Caller-Role", "C_AUDITOR")
			req.Header.Set("X-Caller-DID", auditor2)
			rec := httptest.NewRecorder()
			h2.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("header-only request got %d", rec.Code)
			}
			req = req.WithContext(serviceauth.WithIdentity(ctx, serviceauth.Identity{Role: "B_RECOVERY", DID: "did:web:b.local:services:recovery"}))
			rec = httptest.NewRecorder()
			h2.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatal("B caller overrode identity with C headers")
			}
		}
	})
	t.Run("HistoricalRevokedCredentialAndMissingEvidence", func(t *testing.T) {
		key := api.Key("credential", h.rp.g1.IssuerCredential)
		var raw []byte
		if err := h.pool.QueryRow(ctx, `SELECT value FROM fabric_version WHERE deployment=$1 AND key=$2 AND block_no=1`, h.depID, key).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var c api.Credential
		_ = json.Unmarshal(raw, &c)
		c.Status = api.Revoked
		changed, _ := json.Marshal(c)
		if _, err := h.pool.Exec(ctx, `UPDATE fabric_version SET value=$1 WHERE deployment=$2 AND key=$3 AND block_no=1`, changed, h.depID, key); err != nil {
			t.Fatal(err)
		}
		headers := map[string]string{"X-Caller-Role": "C_AUDITOR", "X-Caller-DID": auditor2}
		rec := callJSONEndpoint(t, h2, http.MethodPost, "/v1/audit/order-outcomes", headers, gateway.AuditOrderOutcomeRequest{CaseID: stopped.CaseID})
		var got gateway.AuditOrderOutcomeResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if got.HistoricalStatus != "MISMATCH" {
			t.Fatalf("revoked historical credential returned %+v", got)
		}
		if _, err := h.pool.Exec(ctx, `UPDATE fabric_version SET value=$1 WHERE deployment=$2 AND key=$3 AND block_no=1`, raw, h.depID, key); err != nil {
			t.Fatal(err)
		}
		var pkgRaw []byte
		if err := h.pool.QueryRow(ctx, `SELECT package_json FROM decision_evidence WHERE deployment_id=$1 AND decision_id=$2`, h.depID, origDecID).Scan(&pkgRaw); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = h.pool.Exec(ctx, `UPDATE decision_evidence SET package_json=$1 WHERE deployment_id=$2 AND decision_id=$3`, pkgRaw, h.depID, origDecID)
		}()
		var pkg protocol.AccessEvidencePackage
		_ = json.Unmarshal(pkgRaw, &pkg)
		pkg.TrustPaths = []protocol.TrustPathEntry{}
		missing, _ := json.Marshal(pkg)
		if _, err := h.pool.Exec(ctx, `UPDATE decision_evidence SET package_json=$1 WHERE deployment_id=$2 AND decision_id=$3`, missing, h.depID, origDecID); err != nil {
			t.Fatal(err)
		}
		rec = callJSONEndpoint(t, h2, http.MethodPost, "/v1/audit/order-outcomes", headers, gateway.AuditOrderOutcomeRequest{CaseID: stopped.CaseID})
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if got.HistoricalStatus != "INCOMPLETE" {
			t.Fatalf("missing historical certification body returned %+v", got)
		}
	})
	t.Run("StoppedIntentRejectsCurrentRevision", func(t *testing.T) {
		if _, err := gateway.RecordClientActionChallenge(ctx, h.pool, h.depID, stopped.ActionID, stopped.SendRevision, ch1.ChallengeID, string(orderRaw), currentSec.Load()); !protocol.HasCode(err, protocol.ErrCodeStateChanged) {
			t.Fatalf("stopped intent accepted new worker: %v", err)
		}
	})
	t.Run("DurableOutboxSurvivesRestartAndLostAcknowledgement", func(t *testing.T) {
		var count int
		if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM order_outcome_outbox WHERE deployment_id=$1 AND case_id=$2 AND delivered_at IS NULL`, h.depID, stopped.CaseID).Scan(&count); err != nil || count == 0 {
			t.Fatalf("missing durable outbox: %d %v", count, err)
		}
		client := serviceauth.NewLocalClient(h1, serviceauth.Identity{Role: "C_AUDIT_SERVICE", DID: auditor2})
		lostClient := &http.Client{Transport: receiptAckLossTransport{base: client.Transport}}
		if _, err := gw2.DeliverReceipt(ctx, lostClient, "https://c.local/v1/internal/order-outcome-receipts", auditResp.Receipt); err == nil {
			t.Fatal("lost receipt acknowledgement unexpectedly succeeded")
		}
		var stillPending bool
		if err := h.pool.QueryRow(ctx, `SELECT delivered_at IS NULL FROM order_outcome_outbox WHERE deployment_id=$1 AND case_id=$2 AND send_revision=$3 AND check_no=$4`, h.depID, auditResp.CaseID, auditResp.SendRevision, auditResp.CheckNo).Scan(&stillPending); err != nil || !stillPending {
			t.Fatalf("lost acknowledgement removed durable work: %v %v", stillPending, err)
		}
		restarted, err := gateway.NewServer(gateway.Config{DB: h.pool, State: h.state.GatewayAdapter(), Delivery: h.delivery, DIDs: h.dids, Policy: h.bundle, DeploymentID: h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID, AuditorDIDs: []string{auditor1, auditor2}, NowFn: nowFn})
		if err != nil {
			t.Fatal(err)
		}
		// A new server instance reads the durable queue, without issuing another audit.
		delivered, err := restarted.DeliverPendingReceipts(ctx, client, "https://c.local/v1/internal/order-outcome-receipts")
		if err != nil || delivered == 0 {
			t.Fatalf("restart delivery: %d %v", delivered, err)
		}
		before := auditResp.CheckNo
		replay, err := gw2.DeliverReceipt(ctx, client, "https://c.local/v1/internal/order-outcome-receipts", auditResp.Receipt)
		if err != nil || replay.Status != "IDEMPOTENT_REPLAY" || replay.Receipt.CheckNo != before {
			t.Fatalf("lost acknowledgement replay: %+v %v", replay, err)
		}
	})

	// 7. Deliver receipt to B -> RECONCILED, idempotent replay, conflict rejection, late UNKNOWN ignored.
	cHeaders := map[string]string{"X-Caller-Role": "C_AUDIT_SERVICE", "X-Caller-DID": auditor2}
	deliv1 := callJSONEndpoint(t, h1, http.MethodPost, "/v1/internal/order-outcome-receipts", cHeaders, auditResp.Receipt)
	if deliv1.Code != http.StatusOK {
		t.Fatalf("deliver receipt failed: %d %s", deliv1.Code, deliv1.Body.String())
	}
	delivDup := callJSONEndpoint(t, h1, http.MethodPost, "/v1/internal/order-outcome-receipts", cHeaders, auditResp.Receipt)
	if delivDup.Code != http.StatusOK {
		t.Fatalf("duplicate receipt failed: %d %s", delivDup.Code, delivDup.Body.String())
	}
	tamperedReceipt := auditResp.Receipt
	tamperedReceipt.Outcome = "UNKNOWN"
	tamperedReceipt.OrderID = nil
	delivConflict := callJSONEndpoint(t, h1, http.MethodPost, "/v1/internal/order-outcome-receipts", cHeaders, tamperedReceipt)
	if delivConflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 on conflicting receipt for same (caseId,sendRevision,checkNo), got %d %s", delivConflict.Code, delivConflict.Body.String())
	}
	lateUnknown := auditResp.Receipt
	lateUnknown.CheckNo = 99
	lateUnknown.Outcome = "UNKNOWN"
	lateUnknown.OrderID = nil
	delivLate := callJSONEndpoint(t, h1, http.MethodPost, "/v1/internal/order-outcome-receipts", cHeaders, lateUnknown)
	if delivLate.Code != http.StatusOK {
		t.Fatalf("late UNKNOWN failed: %d %s", delivLate.Code, delivLate.Body.String())
	}
	finalAct, err := gateway.GetClientActionByKey(ctx, h.pool, h.depID, h.didB1, h.rp.taskID, "order.create", orderReq.IdempotencyKey)
	if err != nil || finalAct.Status != "RECONCILED" || finalAct.Outcome != "CREATED" || finalAct.OrderID != origOrderID {
		t.Fatalf("late UNKNOWN must not reopen finalized client action, got %+v err=%v", finalAct, err)
	}

	// 8. UNKNOWN -> NOT_CREATED transition on uncreated order once all challenges expire.
	unkReq := orderReq
	unkReq.IdempotencyKey = "order-recovery-ord-unk-2"
	unkHash, _ := unkReq.Hash(false)
	unkRaw, _ := json.Marshal(unkReq)
	unkAct, err := gateway.BeginClientAction(ctx, h.pool, h.depID, h.didB1, h.rp.taskID, "order.create", unkReq.IdempotencyKey, unkHash, currentSec.Load())
	if err != nil {
		t.Fatal(err)
	}
	chUnkRec := callJSONEndpoint(t, h1, http.MethodPost, "/v1/auth/challenges", nil, gateway.ChallengeRequest{
		Actor: h.didB1, TaskID: h.rp.taskID, RequestHash: unkHash,
	})
	var chUnk gateway.ChallengeResponse
	_ = json.Unmarshal(chUnkRec.Body.Bytes(), &chUnk)
	unkAct, err = gateway.RecordClientActionChallenge(ctx, h.pool, h.depID, unkAct.ActionID, 1, chUnk.ChallengeID, string(unkRaw), currentSec.Load())
	if err != nil {
		t.Fatal(err)
	}
	unkStop, err := gateway.StopClientActionSend(ctx, h.pool, h.depID, h.didB1, h.rp.taskID, "order.create", unkReq.IdempotencyKey, "urn:grad:case:unk-2", string(unkRaw), currentSec.Load())
	if err != nil {
		t.Fatal(err)
	}
	_ = callJSONEndpoint(t, h1, http.MethodPost, "/v1/internal/order-outcome-cases",
		map[string]string{"X-Caller-Role": "B_RECOVERY", "X-Caller-DID": "did:web:b.local:services:recovery"},
		gateway.OrderOutcomeCaseRequest{
			CaseID: unkStop.CaseID, SendRevision: unkStop.SendRevision, DeploymentID: h.depID,
			Request: unkReq, RequestHash: unkHash, ChallengeIDs: unkStop.ChallengeIDs,
		},
	)
	aHeaders := map[string]string{"X-Caller-Role": "C_AUDITOR", "X-Caller-DID": auditor1}
	unkAudit1Rec := callJSONEndpoint(t, h1, http.MethodPost, "/v1/audit/order-outcomes", aHeaders, gateway.AuditOrderOutcomeRequest{CaseID: unkStop.CaseID})
	var unkAudit1 gateway.AuditOrderOutcomeResponse
	_ = json.Unmarshal(unkAudit1Rec.Body.Bytes(), &unkAudit1)
	if unkAudit1.Outcome != "UNKNOWN" || unkAudit1.HistoricalStatus != "NO_DECISION" {
		t.Fatalf("expected UNKNOWN before challenge expires, got %+v", unkAudit1)
	}

	// Advance clock past chUnk.ExpiresAt -> re-audit now returns NOT_CREATED!
	currentSec.Store(chUnk.ExpiresAt)
	unkAudit2Rec := callJSONEndpoint(t, h1, http.MethodPost, "/v1/audit/order-outcomes", aHeaders, gateway.AuditOrderOutcomeRequest{CaseID: unkStop.CaseID})
	var unkAudit2 gateway.AuditOrderOutcomeResponse
	_ = json.Unmarshal(unkAudit2Rec.Body.Bytes(), &unkAudit2)
	if unkAudit2.Outcome != "NOT_CREATED" || unkAudit2.HistoricalStatus != "NO_DECISION" || unkAudit2.CheckNo != 2 {
		t.Fatalf("expected NOT_CREATED after all challenges expired, got %+v", unkAudit2)
	}

	// 9. Historical negative cases: MISMATCH (h >= r, probeDeadline, certDigest) and INCOMPLETE (missing h or d1).
	// MISMATCH (h >= r): shift decision block_number to 2 (equals revocation block r=2) & block_hash to b2Hash.
	if _, err := h.pool.Exec(ctx, `UPDATE decisions SET block_number=2, block_hash=$1 WHERE deployment_id=$2 AND decision_id=$3`, b2Hash, h.depID, origDecID); err != nil {
		t.Fatal(err)
	}
	misHGErRec := callJSONEndpoint(t, h2, http.MethodPost, "/v1/audit/order-outcomes", aHeaders, gateway.AuditOrderOutcomeRequest{CaseID: stopped.CaseID})
	var misHGEr gateway.AuditOrderOutcomeResponse
	_ = json.Unmarshal(misHGErRec.Body.Bytes(), &misHGEr)
	if misHGEr.Outcome != "CREATED" || misHGEr.HistoricalStatus != "MISMATCH" {
		t.Fatalf("expected HistoricalStatus MISMATCH for h >= r, got %+v", misHGEr)
	}

	// Restore block 1 & test decisionAt >= probeDeadline -> MISMATCH.
	if _, err := h.pool.Exec(ctx, `UPDATE decisions SET block_number=1, block_hash=$1, probe_deadline=decision_at WHERE deployment_id=$2 AND decision_id=$3`, headHash, h.depID, origDecID); err != nil {
		t.Fatal(err)
	}
	misProbeRec := callJSONEndpoint(t, h2, http.MethodPost, "/v1/audit/order-outcomes", aHeaders, gateway.AuditOrderOutcomeRequest{CaseID: stopped.CaseID})
	var misProbe gateway.AuditOrderOutcomeResponse
	_ = json.Unmarshal(misProbeRec.Body.Bytes(), &misProbe)
	if misProbe.Outcome != "CREATED" || misProbe.HistoricalStatus != "MISMATCH" {
		t.Fatalf("expected HistoricalStatus MISMATCH for decisionAt >= probeDeadline, got %+v", misProbe)
	}

	// Restore probe_deadline, test missing block -> INCOMPLETE.
	if _, err := h.pool.Exec(ctx, `UPDATE decisions SET probe_deadline=decision_at+600 WHERE deployment_id=$1 AND decision_id=$2`, h.depID, origDecID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM fabric_version WHERE deployment=$1 AND block_no=1`, h.depID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM fabric_block WHERE deployment=$1 AND block_no=1`, h.depID); err != nil {
		t.Fatal(err)
	}
	incBlkRec := callJSONEndpoint(t, h2, http.MethodPost, "/v1/audit/order-outcomes", aHeaders, gateway.AuditOrderOutcomeRequest{CaseID: stopped.CaseID})
	var incBlk gateway.AuditOrderOutcomeResponse
	_ = json.Unmarshal(incBlkRec.Body.Bytes(), &incBlk)
	if incBlk.Outcome != "CREATED" || incBlk.HistoricalStatus != "INCOMPLETE" {
		t.Fatalf("expected HistoricalStatus INCOMPLETE when block h missing, got %+v", incBlk)
	}

	// Missing creation decision d1 while order exists -> INCOMPLETE.
	if _, err := h.pool.Exec(ctx, `DELETE FROM decisions WHERE deployment_id=$1 AND decision_id=$2`, h.depID, origDecID); err != nil {
		t.Fatal(err)
	}
	incDecRec := callJSONEndpoint(t, h2, http.MethodPost, "/v1/audit/order-outcomes", aHeaders, gateway.AuditOrderOutcomeRequest{CaseID: stopped.CaseID})
	var incDec gateway.AuditOrderOutcomeResponse
	_ = json.Unmarshal(incDecRec.Body.Bytes(), &incDec)
	if incDec.Outcome != "CREATED" || incDec.HistoricalStatus != "INCOMPLETE" {
		t.Fatalf("expected HistoricalStatus INCOMPLETE when d1 missing, got %+v", incDec)
	}

	// 10. 503 STATE_UNAVAILABLE on DB outage during audit.
	badPoolCfg := h.pool.Config().Copy()
	closedPool, err := pgxpool.NewWithConfig(ctx, badPoolCfg)
	if err != nil {
		t.Fatal(err)
	}
	gwDown, err := gateway.NewServer(gateway.Config{
		DB: closedPool, State: h.state.GatewayAdapter(), Delivery: h.delivery, DIDs: h.dids, Policy: h.bundle,
		DeploymentID: h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID,
		AuditorDIDs: []string{auditor1}, NowFn: nowFn,
	})
	if err != nil {
		t.Fatal(err)
	}
	closedPool.Close()
	downRec := callJSONEndpoint(t, gwDown.Handler(), http.MethodPost, "/v1/audit/order-outcomes", aHeaders, gateway.AuditOrderOutcomeRequest{CaseID: stopped.CaseID})
	if downRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 STATE_UNAVAILABLE on closed DB pool, got %d %s", downRec.Code, downRec.Body.String())
	}
}

func execReqWithChallenge(
	t *testing.T,
	srv http.Handler,
	h *procurementGatewayHarness,
	chain procurementChainFixture,
	nowUnix int64,
	leafPres, keyID string,
	leafPriv *ecdsa.PrivateKey,
	req protocol.AccessRequest,
	chal gateway.ChallengeResponse,
) *httptest.ResponseRecorder {
	t.Helper()
	pkg := protocol.AccessEvidencePackage{
		Request: req, TaskSpec: h.spec, AncestorCredentials: chain.ancCreds, Grants: chain.grants, TrustPaths: chain.tp,
	}
	if _, _, err := protocol.AssembleAccessEvidencePackage(&pkg, leafPres, keyID, leafPriv, protocol.ChallengeContext{
		ChallengeID: chal.ChallengeID, Nonce: chal.Nonce, Audience: chal.Audience, IssuedAt: chal.IssuedAt, ExpiresAt: chal.ExpiresAt,
	}, nowUnix, false); err != nil {
		t.Fatal(err)
	}
	rawPkg, _ := json.Marshal(pkg)
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(rawPkg))
	httpReq.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, httpReq)
	return rec
}

func TestConcurrentChallengeExpiryBarrier(t *testing.T) {
	h := newProcurementGatewayHarness(t)
	registerAuditCleanup(t, h.pool, h.depID)
	ctx := t.Context()

	t0 := h.fixedNow.Unix()
	var currentSec atomic.Int64
	currentSec.Store(t0)
	nowFn := func() time.Time { return time.Unix(currentSec.Load(), 0) }
	h.state.SetMonoClock(nowFn)
	h.state.SetStaticProbe(&fabric.ProbeSnapshot{
		TxID: "probe-s66", ProbeBlock: 1, SentAt: h.fixedNow, Deadline: h.fixedNow.Add(600 * time.Second),
		SentMonoNs: h.fixedNow.UnixNano(), DeadlineMonoNs: h.fixedNow.Add(600 * time.Second).UnixNano(),
		AdoptedAt: h.fixedNow, AdoptedMonoNs: h.fixedNow.UnixNano(),
	})

	bEnteredHead := make(chan struct{})
	releaseB := make(chan struct{})
	var bOnce sync.Once

	srvB, err := gateway.NewServer(gateway.Config{
		DB: h.pool, State: h.state.GatewayAdapter(), Delivery: h.delivery, DIDs: h.dids, Policy: h.bundle,
		DeploymentID: h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID,
		ClockErrorMargin: api.ClockError, NowFn: nowFn,
		BeforeLockHead: func(attempt int) {
			bOnce.Do(func() {
				close(bEnteredHead)
				<-releaseB
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srvA, err := gateway.NewServer(gateway.Config{
		DB: h.pool, State: h.state.GatewayAdapter(), Delivery: h.delivery, DIDs: h.dids, Policy: h.bundle,
		DeploymentID: h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID,
		ClockErrorMargin: api.ClockError, NowFn: nowFn,
	})
	if err != nil {
		t.Fatal(err)
	}
	hA := srvA.Handler()
	hB := srvB.Handler()

	h.postContext(t, hA, h.rp.taskID, 0, "NORMAL", h.policyDeadline)

	qRec := h.execReq(t, hA, h.rp, currentSec.Load(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, protocol.AccessRequest{
		SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1,
		PrincipalDomain: "A", AuthorizationMode: h.rp.mode, TaskID: h.rp.taskID,
		Audience: h.audience, Resource: "urn:grad:resource:C:quotes", Action: "quote.read",
		SupplierID: h.supplierID, ProductID: gateway.DefaultProductID, Quantity: 1,
		Currency: "CNY", AmountMinor: 0, IdempotencyKey: "s66-q",
	})
	if qRec.Code != http.StatusOK {
		t.Fatal(qRec.Body.String())
	}
	var qResp gateway.ExecuteResponse
	_ = json.Unmarshal(qRec.Body.Bytes(), &qResp)
	quoteID := qResp.Quote.QuoteID

	orderReq := protocol.AccessRequest{
		SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1,
		PrincipalDomain: "A", AuthorizationMode: h.rp.mode, TaskID: h.rp.taskID,
		Audience: h.audience, Resource: "urn:grad:resource:C:orders", Action: "order.create",
		SupplierID: h.supplierID, ProductID: gateway.DefaultProductID, Quantity: 1,
		Currency: "CNY", QuoteID: &quoteID, AmountMinor: 80000, IdempotencyKey: "s66-same-order-key",
	}
	reqHash, _ := orderReq.Hash(false)

	// Challenge A issued at t0 (expiresAt = t0 + 30).
	currentSec.Store(t0)
	cARec := callJSONEndpoint(t, hA, http.MethodPost, "/v1/auth/challenges", nil, gateway.ChallengeRequest{
		Actor: h.didB1, TaskID: h.rp.taskID, RequestHash: reqHash,
	})
	var chalA gateway.ChallengeResponse
	_ = json.Unmarshal(cARec.Body.Bytes(), &chalA)

	// Challenge B issued at t0 + 1 (expiresAt = t0 + 31).
	currentSec.Store(t0 + 1)
	cBRec := callJSONEndpoint(t, hB, http.MethodPost, "/v1/auth/challenges", nil, gateway.ChallengeRequest{
		Actor: h.didB1, TaskID: h.rp.taskID, RequestHash: reqHash,
	})
	var chalB gateway.ChallengeResponse
	_ = json.Unmarshal(cBRec.Body.Bytes(), &chalB)

	// Build signed AccessEvidencePackages at t0 + 29 while BOTH challenges are still valid.
	buildSignedBody := func(chal gateway.ChallengeResponse, signAt int64) []byte {
		pkg := protocol.AccessEvidencePackage{
			Request: orderReq, TaskSpec: h.spec, AncestorCredentials: h.rp.ancCreds, Grants: h.rp.grants, TrustPaths: h.rp.tp,
		}
		if _, _, err := protocol.AssembleAccessEvidencePackage(&pkg, h.b1PresPrefix, h.b1KeyID, h.privB1, protocol.ChallengeContext{
			ChallengeID: chal.ChallengeID, Nonce: chal.Nonce, Audience: chal.Audience, IssuedAt: chal.IssuedAt, ExpiresAt: chal.ExpiresAt,
		}, signAt, false); err != nil {
			t.Fatal(err)
		}
		rawPkg, _ := json.Marshal(pkg)
		return rawPkg
	}

	currentSec.Store(t0 + 29)
	bodyA := buildSignedBody(chalA, t0+29)
	bodyB := buildSignedBody(chalB, t0+29)

	var resA, resB *httptest.ResponseRecorder
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(bodyB))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		hB.ServeHTTP(rec, req)
		resB = rec
	}()

	<-bEnteredHead

	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(bodyA))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		hA.ServeHTTP(rec, req)
		resA = rec
	}()

	// Wait briefly until goroutine A has locked chalA and blocked waiting for business_keys lock in Postgres.
	deadlineWait := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadlineWait) {
		var waiting int
		err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'`).Scan(&waiting)
		if err == nil && waiting > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Advance clock to chalA.ExpiresAt (t0 + 30): chalA is now expired when it acquires lock, while chalB (t0 + 31) is still valid!
	currentSec.Store(chalA.ExpiresAt)
	close(releaseB)
	wg.Wait()

	if resB == nil || resB.Code != http.StatusOK {
		t.Fatalf("expected concurrent valid chalB to succeed 200 OK, got %+v", resB)
	}
	if resA == nil || resA.Code != http.StatusUnauthorized {
		t.Fatalf("expected locked-waiting expired chalA to fail 401 CHALLENGE_EXPIRED, got %+v body=%s", resA, func() string {
			if resA != nil {
				return resA.Body.String()
			}
			return ""
		}())
	}
	var errBodyA gateway.ErrorBody
	_ = json.Unmarshal(resA.Body.Bytes(), &errBodyA)
	if errBodyA.Code != protocol.ErrCodeChallengeExpired {
		t.Fatalf("expected code CHALLENGE_EXPIRED, got %+v", errBodyA)
	}

	// Verify chalA was NOT consumed and no decision was written for chalA.
	var consumedAt *int64
	var decID *string
	if err := h.pool.QueryRow(ctx, `SELECT consumed_at, decision_id FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`,
		h.depID, chalA.ChallengeID).Scan(&consumedAt, &decID); err != nil {
		t.Fatal(err)
	}
	if consumedAt != nil || decID != nil {
		t.Fatalf("expired challenge must NOT be consumed on post-lock timeout, got consumedAt=%v decID=%v", consumedAt, decID)
	}

	var orderCount, allowDecCount int
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM orders WHERE deployment_id=$1`, h.depID).Scan(&orderCount); err != nil {
		t.Fatal(err)
	}
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM decisions WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND action='order.create' AND outcome='ALLOW'`,
		h.depID, h.didB1, h.rp.taskID).Scan(&allowDecCount); err != nil {
		t.Fatal(err)
	}
	if orderCount != 1 || allowDecCount != 1 {
		t.Fatalf("expected exactly 1 unique order and 1 ALLOW decision, got orders=%d decisions=%d", orderCount, allowDecCount)
	}
}

func TestStoppedIntentSerializesFinalDispatch(t *testing.T) {
	h := newProcurementGatewayHarness(t)
	registerAuditCleanup(t, h.pool, h.depID)
	ctx := t.Context()
	act, err := gateway.BeginClientAction(ctx, h.pool, h.depID, h.didB1, h.rp.taskID, "order.create", "dispatch-stop", strings.Repeat("a", 64), h.fixedNow.Unix())
	if err != nil {
		t.Fatal(err)
	}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		finished <- gateway.DispatchClientAction(ctx, h.pool, h.depID, act.ActionID, 1, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	stopCtx, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	_, err = gateway.StopClientActionSend(stopCtx, h.pool, h.depID, h.didB1, h.rp.taskID, "order.create", "dispatch-stop", "case-dispatch", "{}", h.fixedNow.Unix())
	cancel()
	if err == nil {
		close(release)
		t.Fatal("stop completed while final send still owned intent lock")
	}
	close(release)
	if err = <-finished; err != nil {
		t.Fatal(err)
	}
	stopped, err := gateway.StopClientActionSend(ctx, h.pool, h.depID, h.didB1, h.rp.taskID, "order.create", "dispatch-stop", "case-dispatch", "{}", h.fixedNow.Unix())
	if err != nil {
		t.Fatal(err)
	}
	sent := false
	err = gateway.DispatchClientAction(ctx, h.pool, h.depID, act.ActionID, stopped.SendRevision, func() error { sent = true; return nil })
	if !protocol.HasCode(err, protocol.ErrCodeStateChanged) || sent {
		t.Fatalf("stopped send was dispatched: %v %v", sent, err)
	}
}

type receiptAckLossTransport struct{ base http.RoundTripper }

func (t receiptAckLossTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return nil, errors.New("injected receipt acknowledgement loss after receiver commit")
}
