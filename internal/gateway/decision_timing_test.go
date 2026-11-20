package gateway_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"
)

func TestPostLockDecisionSubSecondTimingAndDelayedResponse(t *testing.T) {
	h := newGatewayTestHarness(t)

	var (
		mu      sync.Mutex
		timings = map[string]gateway.DecisionTiming{}
	)
	const responseDelay = 60 * time.Millisecond

	// Keep live wall clock so post-lock decision, commit, and delayed HTTP response
	// are captured as distinct sub-second events on the same host timebase.
	h.state.SetMonoClock(time.Now)
	srv, err := gateway.NewServer(gateway.Config{
		DB:           h.pool,
		State:        h.state.GatewayAdapter(),
		Delivery:     h.delivery,
		DIDs:         h.dids,
		Policy:       h.bundle,
		DeploymentID: h.deploymentID,
		ServiceDID:   h.serviceDID,
		Audience:     h.audience,
		SupplierID:   h.supplierID,
		OnDecisionCommitted: func(dt gateway.DecisionTiming) {
			mu.Lock()
			timings[dt.DecisionID] = dt
			mu.Unlock()
		},
		BeforeWriteResponse: func(_ string) {
			time.Sleep(responseDelay)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	h.updateContext(t, handler, 0, "NORMAL", h.fixedNow.Unix()+3600)

	// 1. Delayed-response ALLOW request
	req := h.buildQuoteRequest("timing-allow-1", 1)
	reqHash, err := req.Hash(false)
	if err != nil {
		t.Fatal(err)
	}
	chal := h.requestChallenge(t, handler, reqHash)
	pkg := h.assemblePackage(t, req, chal, h.uPriv)
	rawBody, _ := json.Marshal(pkg)

	submittedAt := time.Now().UTC()
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(rawBody))
	httpReq.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, httpReq)
	respondedAt := time.Now().UTC()

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 ALLOW, got %d: %s", rec.Code, rec.Body.String())
	}
	var execResp gateway.ExecuteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &execResp); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	dt, ok := timings[execResp.DecisionID]
	mu.Unlock()
	if !ok {
		t.Fatalf("OnDecisionCommitted was not invoked for decisionId %s", execResp.DecisionID)
	}
	if dt.Outcome != "ALLOW" || dt.Code != "ALLOW" || dt.ChallengeID != chal.ChallengeID {
		t.Fatalf("unexpected DecisionTiming metadata: %+v", dt)
	}
	if dt.DecisionAt.Before(submittedAt) {
		t.Fatalf("decisionAt %v preceded submittedAt %v", dt.DecisionAt, submittedAt)
	}
	if dt.CommittedAt.Before(dt.DecisionAt) {
		t.Fatalf("committedAt %v preceded decisionAt %v", dt.CommittedAt, dt.DecisionAt)
	}
	if respondedAt.Sub(dt.CommittedAt) < responseDelay-10*time.Millisecond {
		t.Fatalf("expected response delay >= %v after commit, got %v (decisionAt=%v committedAt=%v respondedAt=%v)",
			responseDelay-10*time.Millisecond, respondedAt.Sub(dt.CommittedAt), dt.DecisionAt, dt.CommittedAt, respondedAt)
	}

	// Verify persisted sub-second decision_at_ns and probe timestamps via GET /v1/decisions/{id}.
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/v1/decisions/"+execResp.DecisionID, nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/decisions failed: %d %s", getRec.Code, getRec.Body.String())
	}
	var stored gateway.DecisionRecord
	if err := json.Unmarshal(getRec.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.DecisionAtNs == nil || *stored.DecisionAtNs != dt.DecisionAt.UnixNano() {
		t.Fatalf("stored decisionAtNs %v != observed %d", stored.DecisionAtNs, dt.DecisionAt.UnixNano())
	}
	if stored.ProbeSentAtNs == nil || stored.ProbeDeadlineNs == nil || *stored.ProbeDeadlineNs <= *stored.ProbeSentAtNs {
		t.Fatalf("expected sub-second probe timestamps, got sent=%v deadline=%v", stored.ProbeSentAtNs, stored.ProbeDeadlineNs)
	}

	// 2. Delayed-response DENY request (policy denied via BLOCKED context)
	h.updateContext(t, handler, 1, "BLOCKED", h.fixedNow.Unix()+3600)
	denyReq := h.buildQuoteRequest("timing-deny-1", 1)
	denyHash, _ := denyReq.Hash(false)
	denyChal := h.requestChallenge(t, handler, denyHash)
	denyPkg := h.assemblePackage(t, denyReq, denyChal, h.uPriv)
	denyBody, _ := json.Marshal(denyPkg)

	denyRec := httptest.NewRecorder()
	denyHTTP := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(denyBody))
	denyHTTP.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(denyRec, denyHTTP)
	denyRespondedAt := time.Now().UTC()
	if denyRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 DENY, got %d: %s", denyRec.Code, denyRec.Body.String())
	}
	var errBody gateway.ErrorBody
	if err := json.Unmarshal(denyRec.Body.Bytes(), &errBody); err != nil {
		t.Fatal(err)
	}
	if errBody.DecisionID == nil || *errBody.DecisionID == "" {
		t.Fatalf("expected decisionId on policy DENY")
	}
	mu.Lock()
	denyDT, ok := timings[*errBody.DecisionID]
	mu.Unlock()
	if !ok || denyDT.Outcome != "DENY" || denyRespondedAt.Sub(denyDT.CommittedAt) < responseDelay-10*time.Millisecond {
		t.Fatalf("unexpected DENY timing: ok=%v dt=%+v delta=%v", ok, denyDT, denyRespondedAt.Sub(denyDT.CommittedAt))
	}
}

func TestSecondLevelDeadlineBoundaryPreservedWithSubSecondCapture(t *testing.T) {
	h := newGatewayTestHarness(t)
	deadline := h.fixedNow.Unix() + 10
	current := time.Unix(deadline-1, 850_000_000).UTC()
	probeTime := h.fixedNow
	h.state.SetMonoClock(func() time.Time { return probeTime })

	srv := h.newServer(func() time.Time { return current })
	handler := srv.Handler()
	h.updateContext(t, handler, 0, "NORMAL", deadline)
	h.fixedNow = current.Truncate(time.Second)

	// 1. At deadline - 1s + 850ms: still within integer-second deadline -> ALLOW
	req1 := h.buildQuoteRequest("sec-boundary-allow", 1)
	hash1, _ := req1.Hash(false)
	chal1 := h.requestChallenge(t, handler, hash1)
	pkg1 := h.assemblePackage(t, req1, chal1, h.uPriv)
	body1, _ := json.Marshal(pkg1)
	rec1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(body1))
	r1.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec1, r1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 at deadline-1s+850ms, got %d: %s", rec1.Code, rec1.Body.String())
	}
	var out1 gateway.ExecuteResponse
	_ = json.Unmarshal(rec1.Body.Bytes(), &out1)
	get1 := httptest.NewRecorder()
	handler.ServeHTTP(get1, httptest.NewRequest(http.MethodGet, "/v1/decisions/"+out1.DecisionID, nil))
	var d1 gateway.DecisionRecord
	_ = json.Unmarshal(get1.Body.Bytes(), &d1)
	if d1.DecisionAt != deadline-1 || d1.DecisionAtNs == nil || *d1.DecisionAtNs != current.UnixNano() {
		t.Fatalf("expected decisionAt=%d ns=%d, got sec=%d ns=%v", deadline-1, current.UnixNano(), d1.DecisionAt, d1.DecisionAtNs)
	}

	// 2. At exact deadline second (+100ms): reaches context deadline -> 503 CONTEXT_STALE (original second-level rule)
	req2 := h.buildQuoteRequest("sec-boundary-expire", 1)
	hash2, _ := req2.Hash(false)
	chal2 := h.requestChallenge(t, handler, hash2)
	pkg2 := h.assemblePackage(t, req2, chal2, h.uPriv)
	current = time.Unix(deadline, 100_000_000).UTC()
	body2, _ := json.Marshal(pkg2)
	rec2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(body2))
	r2.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 CONTEXT_STALE at exact deadline second, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var err2 gateway.ErrorBody
	_ = json.Unmarshal(rec2.Body.Bytes(), &err2)
	if err2.Code != protocol.ErrCodeContextStale {
		t.Fatalf("expected %s, got %s", protocol.ErrCodeContextStale, err2.Code)
	}
}
