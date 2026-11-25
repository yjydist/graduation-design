package interdomain

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"grad/platform/core/domain/evidence"
	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/domain/procurement"
	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	apigw "grad/platform/service/api/gateway"
	"grad/protocol"
	"grad/protocol/registry"
)

func testDigest(label string) string {
	return registry.Digest([]byte(label))
}

func samplePeers() map[string]PeerBinding {
	return map[string]PeerBinding{
		"A": {URL: "https://a.local:8443", Fingerprint: testDigest("cert-a")},
		"B": {URL: "https://b.local:8443", Fingerprint: testDigest("cert-b")},
		"C": {URL: "https://c.local:8443", Fingerprint: testDigest("cert-c")},
	}
}

func decodeEnvelope(t *testing.T, body *bytes.Buffer) httpx.ErrorEnvelope {
	t.Helper()
	var env httpx.ErrorEnvelope
	if err := json.Unmarshal(body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope %q: %v", body.String(), err)
	}
	return env
}

func TestFromDomainBindingEnforcement(t *testing.T) {
	t.Parallel()

	peers := samplePeers()
	didA := "did:web:a.local:users:u1"
	docA := []byte(`{"id":"did:web:a.local:users:u1"}`)

	srv, err := NewServer(ServerConfig{
		DomainID: "A",
		Peers:    peers,
		DIDDocs: map[string][]byte{
			didA:                       docA,
			"did:web:b.local:users:b1": []byte(`{"id":"did:web:b.local:users:b1"}`),
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	roleC, didC := TransportRole("C")
	tests := []struct {
		name       string
		id         *mtls.Identity
		wantStatus int
		wantCode   string
	}{
		{
			name:       "unauthenticated caller rejected",
			id:         nil,
			wantStatus: http.StatusForbidden,
			wantCode:   registry.ErrCodeBindingMismatch,
		},
		{
			name: "wrong fingerprint rejected",
			id: &mtls.Identity{
				DID:         didC,
				Role:        roleC,
				Fingerprint: testDigest("wrong-cert"),
			},
			wantStatus: http.StatusForbidden,
			wantCode:   registry.ErrCodeBindingMismatch,
		},
		{
			name: "wrong role rejected",
			id: &mtls.Identity{
				DID:         didC,
				Role:        "B_RECOVERY",
				Fingerprint: peers["C"].Fingerprint,
			},
			wantStatus: http.StatusForbidden,
			wantCode:   registry.ErrCodeBindingMismatch,
		},
		{
			name: "wrong DID rejected",
			id: &mtls.Identity{
				DID:         "did:web:c.local:services:other",
				Role:        roleC,
				Fingerprint: peers["C"].Fingerprint,
			},
			wantStatus: http.StatusForbidden,
			wantCode:   registry.ErrCodeBindingMismatch,
		},
		{
			name: "exact domain C binding accepted",
			id: &mtls.Identity{
				DID:         didC,
				Role:        roleC,
				Fingerprint: peers["C"].Fingerprint,
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "https://a.local/users/u1/did.json", nil)
			if tc.id != nil {
				req = req.WithContext(mtls.WithIdentity(req.Context(), *tc.id))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus == http.StatusOK {
				if ct := rec.Header().Get("Content-Type"); ct != "application/did+json" {
					t.Fatalf("content-type=%q want application/did+json", ct)
				}
				if !bytes.Equal(rec.Body.Bytes(), docA) {
					t.Fatalf("body=%q want=%q", rec.Body.String(), string(docA))
				}
				if rec.Header().Get(httpx.HeaderRequestID) == "" {
					t.Fatalf("expected X-Request-Id response header")
				}
			} else {
				env := decodeEnvelope(t, rec.Body)
				if env.Code != tc.wantCode {
					t.Fatalf("code=%q want=%q", env.Code, tc.wantCode)
				}
			}
		})
	}

	// DID documents belonging to another domain host must not be mounted on Domain A.
	req := httptest.NewRequest(http.MethodGet, "https://b.local/users/b1/did.json", nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{
		DID: didC, Role: roleC, Fingerprint: peers["C"].Fingerprint,
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("foreign DID route status=%d want=404", rec.Code)
	}
}

func TestWalletReceiptHandler(t *testing.T) {
	t.Parallel()

	depID := "dep-test-receipt"
	taskID := testDigest("task-receipt")
	reqHash := testDigest("req-receipt")
	actorDID := "did:web:b.local:agents:b1"
	orderID := "ord-1001"
	decID := "dec-1001"

	wctx, err := wallet.NewWalletContext(wallet.WalletConfig{
		DeploymentID: depID,
		Now:          func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatalf("NewWalletContext: %v", err)
	}
	if _, err := wctx.BeginClientAction(t.Context(), actorDID, taskID, protocol.ActionOrderCreate, "idem-1", reqHash, `{}`); err != nil {
		t.Fatalf("BeginClientAction: %v", err)
	}
	stopped, err := wctx.StopClientActionSend(t.Context(), actorDID, taskID, protocol.ActionOrderCreate, "idem-1", "case-1", `{}`)
	if err != nil {
		t.Fatalf("StopClientActionSend: %v", err)
	}

	handler := NewWalletReceiptHandler(wctx)
	validReceipt := wallet.OrderOutcomeReceipt{
		CaseID:             "case-1",
		CheckNo:            1,
		SendRevision:       stopped.SendRevision,
		DeploymentID:       depID,
		Actor:              actorDID,
		TaskID:             taskID,
		RequestHash:        reqHash,
		Outcome:            "CREATED",
		OrderID:            &orderID,
		CreationDecisionID: &decID,
		HistoricalStatus:   "MATCHED",
		AuditAt:            1_700_000_005,
	}
	validRaw, err := json.Marshal(validReceipt)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}

	t.Run("missing mTLS caller forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, PathOrderOutcomeReceipts, bytes.NewReader(validRaw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=403 body=%s", rec.Code, rec.Body.String())
		}
		if env := decodeEnvelope(t, rec.Body); env.Code != protocol.ErrCodeAuditForbidden {
			t.Fatalf("code=%q want=%q", env.Code, protocol.ErrCodeAuditForbidden)
		}
	})

	t.Run("wrong domain or role forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, PathOrderOutcomeReceipts, bytes.NewReader(validRaw))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{
			DID:  "did:web:b.local:services:recovery",
			Role: "B_RECOVERY",
		}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=403 body=%s", rec.Code, rec.Body.String())
		}
		if env := decodeEnvelope(t, rec.Body); env.Code != protocol.ErrCodeAuditForbidden {
			t.Fatalf("code=%q want=%q", env.Code, protocol.ErrCodeAuditForbidden)
		}
	})

	t.Run("invalid JSON schema returns 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, PathOrderOutcomeReceipts, strings.NewReader(`{"unknownField":true}`))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{
			DID:  DIDAuditServiceC,
			Role: RoleAuditServiceC,
		}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=400 body=%s", rec.Code, rec.Body.String())
		}
		if env := decodeEnvelope(t, rec.Body); env.Code != protocol.ErrCodeInvalidSchema {
			t.Fatalf("code=%q want=%q", env.Code, protocol.ErrCodeInvalidSchema)
		}
	})

	t.Run("authorized C audit service applies receipt 200 OK", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, PathOrderOutcomeReceipts, bytes.NewReader(validRaw))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{
			DID:  DIDAuditServiceC,
			Role: RoleAuditServiceC,
		}))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d want=200 body=%s", rec.Code, rec.Body.String())
		}
		var out wallet.OrderOutcomeReceiptResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode receipt response: %v", err)
		}
		if out.Receipt.CaseID != "case-1" || out.Receipt.Outcome != "CREATED" {
			t.Fatalf("unexpected receipt ack: %+v", out)
		}
		if out.ClientActionStatus != wallet.ActionStatusReconciled {
			t.Fatalf("expected reconciled client action status, got %+v", out)
		}
	})
}

func TestPeerClientRoundTrips(t *testing.T) {
	t.Parallel()

	runID := testDigest("run-1")
	taskID := testDigest("task-1")
	grantID := testDigest("grant-g0")
	digest := testDigest("delivery-digest")
	probeKey := testDigest("probe-key")

	muxB := http.NewServeMux()
	muxB.HandleFunc("POST "+PathDispatch, func(w http.ResponseWriter, r *http.Request) {
		var in procurement.DispatchRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode SubmitDispatch: %v", err)
		}
		if in.Run.RunID != runID || in.Delivery.Digest != digest {
			t.Errorf("unexpected SubmitDispatch payload: %+v", in)
		}
		httpx.WriteJSON(w, http.StatusAccepted, procurement.DispatchStatusView{
			Receipt: digest,
			Status:  procurement.RunPending,
		})
	})
	muxB.HandleFunc("GET "+PathDispatch+"/{runId}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("runId") != runID {
			httpx.WriteError(w, http.StatusNotFound, "req-1", "NOT_FOUND", nil, "not found")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, procurement.DispatchStatusView{
			Receipt: digest,
			Status:  procurement.RunDecided,
			Traces:  []procurement.ToolTrace{{ToolName: "create_order", Step: 1}},
		})
	})
	muxB.HandleFunc("POST "+PathProbe, func(w http.ResponseWriter, r *http.Request) {
		var in procurement.ProbeRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode RequestDispatchProbe: %v", err)
		}
		if in.RunID != runID || in.Key != probeKey || !in.Order {
			t.Errorf("unexpected ProbeRequest: %+v", in)
		}
		httpx.WriteJSON(w, http.StatusOK, procurement.ProbeResponse{
			Quote: wallet.RequestQuoteOutput{Decision: "ALLOW", QuoteID: "q-1", TotalAmountMinor: 80000},
			Order: &wallet.CreateOrderOutput{Decision: "DENY", ErrorCode: protocol.ErrCodeAmountLimitExceeded},
		})
	})
	srvB := httptest.NewServer(muxB)
	defer srvB.Close()

	muxC := http.NewServeMux()
	muxC.HandleFunc("POST "+PathRoot, func(w http.ResponseWriter, r *http.Request) {
		var in procurement.RootGrantRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode RequestRoot: %v", err)
		}
		if in.GrantID != grantID || in.TaskID != taskID {
			t.Errorf("unexpected RootGrantRequest: %+v", in)
		}
		httpx.WriteJSON(w, http.StatusOK, procurement.RootGrantResponse{
			Operation: &domreg.OperationView{OperationID: "op-root", Status: "CONFIRMED"},
			Delivery:  &procurement.GrantDelivery{Digest: digest},
		})
	})
	muxC.HandleFunc("POST "+PathRootReceipt, func(w http.ResponseWriter, r *http.Request) {
		var in procurement.RootGrantReceipt
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode AckRootReceipt: %v", err)
		}
		if in.GrantID != grantID || in.Digest != digest {
			t.Errorf("unexpected RootGrantReceipt: %+v", in)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	muxC.HandleFunc("POST "+PathContext, func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode EnsureContext: %v", err)
		}
		if in["taskId"] != taskID {
			t.Errorf("unexpected EnsureContext payload: %+v", in)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	muxC.HandleFunc("GET "+PathEvidencePrefix+"{taskId}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("taskId") != taskID {
			httpx.WriteError(w, http.StatusNotFound, "req-2", "NOT_FOUND", nil, "not found")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, domgw.TaskEvidence{
			Quotes: []domgw.QuotePayload{{QuoteID: "q-1", TotalAmountMinor: 80000}},
		})
	})
	muxC.HandleFunc("GET "+PathRootAmountPrefix+"{taskId}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("taskId") != taskID {
			httpx.WriteError(w, http.StatusNotFound, "req-3", "NOT_FOUND", nil, "not found")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, evidence.RootGrantAmount{
			Digest:         digest,
			MaxAmountMinor: 100000,
		})
	})
	srvC := httptest.NewServer(muxC)
	defer srvC.Close()

	pc := NewPeerClient(
		map[string]PeerBinding{
			"B": {URL: srvB.URL, Fingerprint: testDigest("cert-b")},
			"C": {URL: srvC.URL, Fingerprint: testDigest("cert-c")},
		},
		map[string]*http.Client{
			"B": srvB.Client(),
			"C": srvC.Client(),
		},
	)

	// Verify procurement.PeerClient contract.
	var procClient procurement.PeerClient = pc
	rootResp, err := procClient.RequestRoot(t.Context(), procurement.RootGrantRequest{
		GrantID: grantID, TaskID: taskID, MaxAmountMinor: 100000, Depth: 2,
	})
	if err != nil || rootResp.Delivery == nil || rootResp.Delivery.Digest != digest {
		t.Fatalf("RequestRoot=(%+v, %v)", rootResp, err)
	}
	if err := procClient.AckRootReceipt(t.Context(), grantID, digest); err != nil {
		t.Fatalf("AckRootReceipt: %v", err)
	}
	if err := procClient.EnsureContext(t.Context(), taskID); err != nil {
		t.Fatalf("EnsureContext: %v", err)
	}
	dispResp, err := procClient.SubmitDispatch(t.Context(), procurement.DispatchRequest{
		Run:      procurement.DispatchRun{RunID: runID, TaskID: taskID},
		Delivery: procurement.GrantDelivery{Digest: digest},
	})
	if err != nil || dispResp.Status != procurement.RunPending || dispResp.Receipt != digest {
		t.Fatalf("SubmitDispatch=(%+v, %v)", dispResp, err)
	}
	statusResp, err := procClient.GetDispatch(t.Context(), runID)
	if err != nil || statusResp.Status != procurement.RunDecided || len(statusResp.Traces) != 1 {
		t.Fatalf("GetDispatch=(%+v, %v)", statusResp, err)
	}
	probeResp, err := procClient.RequestDispatchProbe(t.Context(), procurement.ProbeRequest{
		RunID: runID, Key: probeKey, Order: true,
	})
	if err != nil || probeResp.Quote.QuoteID != "q-1" || probeResp.Order == nil || probeResp.Order.ErrorCode != protocol.ErrCodeAmountLimitExceeded {
		t.Fatalf("RequestDispatchProbe=(%+v, %v)", probeResp, err)
	}
	// Error envelope code propagation on 404.
	if _, err := procClient.GetDispatch(t.Context(), testDigest("missing-run")); !protocol.HasCode(err, "NOT_FOUND") {
		t.Fatalf("expected NOT_FOUND error code, got %v", err)
	}

	// Verify evidence.PeerEvidenceClient contract.
	var evClient evidence.PeerEvidenceClient = pc
	evResp, err := evClient.FetchTaskEvidence(t.Context(), taskID)
	if err != nil || len(evResp.Quotes) != 1 || evResp.Quotes[0].QuoteID != "q-1" {
		t.Fatalf("FetchTaskEvidence=(%+v, %v)", evResp, err)
	}
	amtResp, err := evClient.FetchRootAmount(t.Context(), taskID)
	if err != nil || amtResp.Digest != digest || amtResp.MaxAmountMinor != 100000 {
		t.Fatalf("FetchRootAmount=(%+v, %v)", amtResp, err)
	}
}

func TestReconcileFromB(t *testing.T) {
	t.Parallel()

	peers := samplePeers()
	depID := "dep-reconcile"
	actorB1 := "did:web:b.local:agents:b1"
	taskID := testDigest("task-rec")
	reqHash := testDigest("req-rec")
	roleB, didB := TransportRole("B")

	// Wrap an unbacked L2 gateway.Service in L3 apigw.Server to prove
	// HasOrderOutcomeCase is invoked through Gateway.Service() with zero raw SQL.
	gwSrv, err := apigw.NewServer(&domgw.Service{})
	if err != nil {
		t.Fatalf("apigw.NewServer: %v", err)
	}

	srv, err := NewServer(ServerConfig{
		DeploymentID: depID,
		DomainID:     "C",
		ActorB1DID:   actorB1,
		Peers:        peers,
		Gateway:      gwSrv,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.cfg.AuditorDID != DefaultAuditorDID {
		t.Fatalf("default AuditorDID=%q want=%q", srv.cfg.AuditorDID, DefaultAuditorDID)
	}
	h, err := srv.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	asDomainB := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/audit/order-outcomes", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{
			DID:         didB,
			Role:        roleB,
			Fingerprint: peers["B"].Fingerprint,
		}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	t.Run("missing request or wrong actor rejected with 403 BINDING_MISMATCH", func(t *testing.T) {
		badPayloads := []domgw.AuditOrderOutcomeRequest{
			{DeploymentID: depID, CaseID: "case-1"}, // nil Request
			{
				DeploymentID: depID,
				CaseID:       "case-1",
				Request:      &protocol.AccessRequest{DeploymentID: depID, Actor: "did:web:b.local:agents:other", TaskID: taskID},
				RequestHash:  reqHash,
			},
			{
				DeploymentID: "wrong-dep",
				CaseID:       "case-1",
				Request:      &protocol.AccessRequest{DeploymentID: depID, Actor: actorB1, TaskID: taskID},
				RequestHash:  reqHash,
			},
			{
				DeploymentID: depID,
				CaseID:       "",
				Request:      &protocol.AccessRequest{DeploymentID: depID, Actor: actorB1, TaskID: taskID},
				RequestHash:  reqHash,
			},
		}
		for i, payload := range badPayloads {
			raw, _ := json.Marshal(payload)
			rec := asDomainB(raw)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("case %d: status=%d want=403 body=%s", i, rec.Code, rec.Body.String())
			}
			if env := decodeEnvelope(t, rec.Body); env.Code != registry.ErrCodeBindingMismatch {
				t.Fatalf("case %d: code=%q want=%q", i, env.Code, registry.ErrCodeBindingMismatch)
			}
		}
	})

	t.Run("missing order_outcome_case rejected with 403 BINDING_MISMATCH", func(t *testing.T) {
		payload := domgw.AuditOrderOutcomeRequest{
			DeploymentID: depID,
			CaseID:       "case-missing",
			Request:      &protocol.AccessRequest{DeploymentID: depID, Actor: actorB1, TaskID: taskID},
			RequestHash:  reqHash,
		}
		raw, _ := json.Marshal(payload)
		rec := asDomainB(raw)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=403 body=%s", rec.Code, rec.Body.String())
		}
		if env := decodeEnvelope(t, rec.Body); env.Code != registry.ErrCodeBindingMismatch {
			t.Fatalf("code=%q want=%q", env.Code, registry.ErrCodeBindingMismatch)
		}
	})

	t.Run("verified case injects C_AUDITOR identity and delegates to gateway", func(t *testing.T) {
		var capturedIdentity mtls.Identity
		var capturedOK bool
		var capturedReq domgw.AuditOrderOutcomeRequest
		var lookupCalled bool

		customAuditor := "did:web:c.local:auditors:c1"
		delegatedSrv, err := NewServer(ServerConfig{
			DeploymentID: depID,
			DomainID:     "C",
			ActorB1DID:   actorB1,
			AuditorDID:   customAuditor,
			Peers:        peers,
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		delegatedSrv.hasOrderOutcomeCase = func(_ context.Context, caseID, actor, gotTaskID, gotHash string) (bool, error) {
			lookupCalled = true
			return caseID == "case-ok" && actor == actorB1 && gotTaskID == taskID && gotHash == reqHash, nil
		}
		delegatedSrv.gatewayHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedIdentity, capturedOK = mtls.Caller(r)
			_ = json.NewDecoder(r.Body).Decode(&capturedReq)
			httpx.WriteJSON(w, http.StatusOK, map[string]string{"outcome": "CREATED"})
		})
		dh, err := delegatedSrv.Handler()
		if err != nil {
			t.Fatalf("Handler: %v", err)
		}

		payload := domgw.AuditOrderOutcomeRequest{
			DeploymentID: depID,
			CaseID:       "case-ok",
			Request:      &protocol.AccessRequest{DeploymentID: depID, Actor: actorB1, TaskID: taskID},
			RequestHash:  reqHash,
		}
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/v1/audit/order-outcomes", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{
			DID:         didB,
			Role:        roleB,
			Fingerprint: peers["B"].Fingerprint,
		}))
		rec := httptest.NewRecorder()
		dh.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d want=200 body=%s", rec.Code, rec.Body.String())
		}
		if !lookupCalled {
			t.Fatalf("expected case lookup to be called")
		}
		if !capturedOK || capturedIdentity.Role != "C_AUDITOR" || capturedIdentity.DID != customAuditor || capturedIdentity.MSPID != "CMsp" {
			t.Fatalf("unexpected injected identity: ok=%v id=%+v", capturedOK, capturedIdentity)
		}
		if capturedReq.CaseID != "case-ok" || capturedReq.RequestHash != reqHash {
			t.Fatalf("unexpected forwarded request: %+v", capturedReq)
		}
	})
}

func TestBuildSecureTransport(t *testing.T) {
	t.Parallel()

	ca, err := protocol.GenerateTestCA(time.Now())
	if err != nil {
		t.Fatalf("GenerateTestCA: %v", err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "internal-ca.crt")
	if err := os.WriteFile(caPath, ca.CertPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	writeDomainCert := func(domain string) (certPath, keyPath, fp string) {
		t.Helper()
		role, did := TransportRole(domain)
		didURL, err := url.Parse(did)
		if err != nil {
			t.Fatalf("parse DID: %v", err)
		}
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("gen key: %v", err)
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "workbench-" + strings.ToLower(domain), OrganizationalUnit: []string{role}},
			DNSNames:     []string{strings.ToLower(domain) + ".local", "localhost"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
			URIs:         []*url.URL{didURL},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &priv.PublicKey, ca.Key)
		if err != nil {
			t.Fatalf("create cert: %v", err)
		}
		keyBytes, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			t.Fatalf("marshal key: %v", err)
		}
		certPath = filepath.Join(dir, domain+".crt")
		keyPath = filepath.Join(dir, domain+".key")
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatalf("write cert: %v", err)
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
			t.Fatalf("write key: %v", err)
		}
		return certPath, keyPath, registry.Digest(der)
	}

	certA, keyA, fpA := writeDomainCert("A")
	_, _, fpB := writeDomainCert("B")
	_, _, fpC := writeDomainCert("C")

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	rootDID := "did:web:t.local"
	rootKeyID := rootDID + "#key-1"
	rootDoc, err := protocol.NewDIDDocument(rootDID, rootKeyID, &rootKey.PublicKey, protocol.KeyPurposeAssertionMethod)
	if err != nil {
		t.Fatalf("NewDIDDocument: %v", err)
	}
	rootRaw, err := json.Marshal(rootDoc)
	if err != nil {
		t.Fatalf("marshal root doc: %v", err)
	}
	_, rootDigest, err := protocol.ParseDIDDocument(rootRaw)
	if err != nil {
		t.Fatalf("ParseDIDDocument: %v", err)
	}
	rootPubHex, err := protocol.FormatAppPublicKey(&rootKey.PublicKey)
	if err != nil {
		t.Fatalf("FormatAppPublicKey: %v", err)
	}

	cfg := TransportConfig{
		DomainID: "A",
		CertPath: certA,
		KeyPath:  keyA,
		CAPath:   caPath,
		Peers: map[string]PeerBinding{
			"A": {URL: "https://127.0.0.1:9441", Fingerprint: fpA},
			"B": {URL: "https://127.0.0.1:9442", Fingerprint: fpB},
			"C": {URL: "https://127.0.0.1:9443", Fingerprint: fpC},
		},
		RootPreseed: protocol.RootPreseed{
			DID:               rootDID,
			KeyID:             rootKeyID,
			KeyVersion:        1,
			PublicKeyHex:      rootPubHex,
			DIDDocumentDigest: rootDigest,
			RawDocument:       rootRaw,
		},
	}

	serverTLS, clients, resolver, err := BuildSecureTransport(cfg)
	if err != nil {
		t.Fatalf("BuildSecureTransport: %v", err)
	}
	if serverTLS == nil || serverTLS.MinVersion != 0x0304 {
		t.Fatalf("expected TLS 1.3 server config, got %+v", serverTLS)
	}
	if len(clients) != 3 || clients["A"] == nil || clients["B"] == nil || clients["C"] == nil {
		t.Fatalf("expected A/B/C mTLS clients, got %+v", clients)
	}
	if resolver == nil {
		t.Fatalf("expected non-nil DIDWebResolver")
	}
	if _, _, err := resolver.ResolvePreseededKey(rootDID, rootKeyID, 1, protocol.KeyPurposeAssertionMethod, rootPubHex); err != nil {
		t.Fatalf("ResolvePreseededKey: %v", err)
	}

	// Mismatched local fingerprint must be rejected.
	badCfg := cfg
	badCfg.Peers = map[string]PeerBinding{
		"A": {URL: "https://127.0.0.1:9441", Fingerprint: testDigest("wrong-local")},
		"B": cfg.Peers["B"],
		"C": cfg.Peers["C"],
	}
	if _, _, _, err := BuildSecureTransport(badCfg); err == nil {
		t.Fatalf("expected BuildSecureTransport to reject mismatched local fingerprint")
	}
}
