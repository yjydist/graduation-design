package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domgw "grad/platform/core/domain/gateway"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/protocol"
)

type stubDomainService struct {
	createChallengeFn          func(ctx context.Context, req domgw.ChallengeRequest) (*domgw.ChallengeResponse, error)
	updateContextFn            func(ctx context.Context, taskID string, req domgw.ContextUpdateRequest) (*domgw.ContextResponse, error)
	executeAccessFn            func(ctx context.Context, requestID string, rawBody []byte) (*domgw.ExecuteResponse, error)
	getDecisionFn              func(ctx context.Context, id string) (*domgw.DecisionRecord, error)
	checkReadyFn               func(ctx context.Context) (*domgw.ReadyStatus, error)
	registerOrderOutcomeCaseFn func(ctx context.Context, caller domgw.CallerIdentity, req domgw.OrderOutcomeCaseRequest) (*domgw.OrderOutcomeCaseResponse, error)
	auditOrderOutcomeFn        func(ctx context.Context, caller domgw.CallerIdentity, req domgw.AuditOrderOutcomeRequest) (*domgw.AuditOrderOutcomeResponse, error)
	deliverReceiptFn           func(ctx context.Context, entry domgw.OutboxEntry, send domgw.ReceiptSender) error
	deliverPendingReceiptsFn   func(ctx context.Context, send domgw.ReceiptSender) (int, error)
}

func (s *stubDomainService) CreateChallenge(ctx context.Context, req domgw.ChallengeRequest) (*domgw.ChallengeResponse, error) {
	return s.createChallengeFn(ctx, req)
}

func (s *stubDomainService) UpdateContext(ctx context.Context, taskID string, req domgw.ContextUpdateRequest) (*domgw.ContextResponse, error) {
	return s.updateContextFn(ctx, taskID, req)
}

func (s *stubDomainService) ExecuteAccess(ctx context.Context, requestID string, rawBody []byte) (*domgw.ExecuteResponse, error) {
	return s.executeAccessFn(ctx, requestID, rawBody)
}

func (s *stubDomainService) GetDecision(ctx context.Context, id string) (*domgw.DecisionRecord, error) {
	return s.getDecisionFn(ctx, id)
}

func (s *stubDomainService) CheckReady(ctx context.Context) (*domgw.ReadyStatus, error) {
	return s.checkReadyFn(ctx)
}

func (s *stubDomainService) RegisterOrderOutcomeCase(ctx context.Context, caller domgw.CallerIdentity, req domgw.OrderOutcomeCaseRequest) (*domgw.OrderOutcomeCaseResponse, error) {
	return s.registerOrderOutcomeCaseFn(ctx, caller, req)
}

func (s *stubDomainService) AuditOrderOutcome(ctx context.Context, caller domgw.CallerIdentity, req domgw.AuditOrderOutcomeRequest) (*domgw.AuditOrderOutcomeResponse, error) {
	return s.auditOrderOutcomeFn(ctx, caller, req)
}

func (s *stubDomainService) DeliverReceipt(ctx context.Context, entry domgw.OutboxEntry, send domgw.ReceiptSender) error {
	return s.deliverReceiptFn(ctx, entry, send)
}

func (s *stubDomainService) DeliverPendingReceipts(ctx context.Context, send domgw.ReceiptSender) (int, error) {
	return s.deliverPendingReceiptsFn(ctx, send)
}

func doRequest(
	t *testing.T,
	h http.Handler,
	method string,
	target string,
	body any,
	headers map[string]string,
	identity *mtls.Identity,
) *httptest.ResponseRecorder {
	t.Helper()
	var buf []byte
	if body != nil {
		switch v := body.(type) {
		case []byte:
			buf = v
		case string:
			buf = []byte(v)
		default:
			var err error
			buf, err = json.Marshal(v)
			require.NoError(t, err)
		}
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(buf))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	if identity != nil {
		req = req.WithContext(mtls.WithIdentity(req.Context(), *identity))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNewServerValidation(t *testing.T) {
	t.Parallel()

	_, err := NewServer(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "domain service")

	svc := &domgw.Service{}
	srv, err := NewServer(svc)
	require.NoError(t, err)
	assert.Same(t, svc, srv.Service())
	assert.NotNil(t, srv.Handler())
}

func TestAllSevenRoutesSuccessAndRequestIDPropagation(t *testing.T) {
	t.Parallel()

	var (
		gotChallengeReq domgw.ChallengeRequest
		gotCtxTaskID    string
		gotCtxReq       domgw.ContextUpdateRequest
		gotExecReqID    string
		gotExecBody     []byte
		gotDecisionID   string
		gotCaseCaller   domgw.CallerIdentity
		gotCaseReq      domgw.OrderOutcomeCaseRequest
		gotAuditCaller  domgw.CallerIdentity
		gotAuditReq     domgw.AuditOrderOutcomeRequest
	)

	probeBlock := uint64(12)
	orderID := "urn:grad:order:ord-1"
	decID := "urn:grad:decision:dec-1"

	ops := &stubDomainService{
		createChallengeFn: func(_ context.Context, req domgw.ChallengeRequest) (*domgw.ChallengeResponse, error) {
			gotChallengeReq = req
			return &domgw.ChallengeResponse{
				ChallengeID: "urn:grad:challenge:ch-1",
				Nonce:       "nonce-1",
				Audience:    "https://c.local",
				IssuedAt:    1000,
				ExpiresAt:   1030,
			}, nil
		},
		updateContextFn: func(_ context.Context, taskID string, req domgw.ContextUpdateRequest) (*domgw.ContextResponse, error) {
			gotCtxTaskID = taskID
			gotCtxReq = req
			return &domgw.ContextResponse{
				DeploymentID:   "dep-1",
				TaskID:         taskID,
				ContextVersion: req.ExpectedContextVersion + 1,
				SourceID:       req.SourceID,
				ObservedAt:     req.ObservedAt,
				RiskLevel:      req.RiskLevel,
				AccessDeadline: req.AccessDeadline,
			}, nil
		},
		executeAccessFn: func(_ context.Context, requestID string, rawBody []byte) (*domgw.ExecuteResponse, error) {
			gotExecReqID = requestID
			gotExecBody = append([]byte(nil), rawBody...)
			return &domgw.ExecuteResponse{
				DecisionID: decID,
				Code:       "ALLOW",
				Quote: &domgw.QuotePayload{
					QuoteID:          "urn:grad:quote:q-1",
					TaskID:           "task-1",
					Actor:            "did:web:b.local:b1",
					SupplierID:       domgw.DefaultSupplierID,
					ProductID:        domgw.DefaultProductID,
					Quantity:         1,
					Currency:         domgw.DefaultCurrency,
					UnitPriceMinor:   domgw.DefaultProductPriceMinor,
					TotalAmountMinor: domgw.DefaultProductPriceMinor,
					IssuedAt:         1000,
					ValidUntil:       1300,
				},
			}, nil
		},
		getDecisionFn: func(_ context.Context, id string) (*domgw.DecisionRecord, error) {
			gotDecisionID = id
			return &domgw.DecisionRecord{
				StateSource:  "fabric",
				DeploymentID: "dep-1",
				DecisionID:   id,
				Outcome:      "ALLOW",
				Code:         "ALLOW",
				BlockNumber:  12,
				BlockHash:    "abcd",
			}, nil
		},
		checkReadyFn: func(_ context.Context) (*domgw.ReadyStatus, error) {
			return &domgw.ReadyStatus{
				Status:       "READY",
				DeploymentID: "dep-1",
				ServiceDID:   "did:web:c.local:supplier",
				PolicyDigest: "sha256:pol",
				StateSource:  "fabric",
				ProbeBlock:   &probeBlock,
			}, nil
		},
		registerOrderOutcomeCaseFn: func(_ context.Context, caller domgw.CallerIdentity, req domgw.OrderOutcomeCaseRequest) (*domgw.OrderOutcomeCaseResponse, error) {
			gotCaseCaller = caller
			gotCaseReq = req
			return &domgw.OrderOutcomeCaseResponse{
				CaseID:         req.CaseID,
				SendRevision:   req.SendRevision,
				DeploymentID:   req.DeploymentID,
				Actor:          req.Request.Actor,
				TaskID:         req.Request.TaskID,
				IdempotencyKey: req.Request.IdempotencyKey,
				RequestHash:    req.RequestHash,
				ChallengeIDs:   req.ChallengeIDs,
				Status:         "REGISTERED",
			}, nil
		},
		auditOrderOutcomeFn: func(_ context.Context, caller domgw.CallerIdentity, req domgw.AuditOrderOutcomeRequest) (*domgw.AuditOrderOutcomeResponse, error) {
			gotAuditCaller = caller
			gotAuditReq = req
			return &domgw.AuditOrderOutcomeResponse{
				CaseID:             req.CaseID,
				CheckNo:            1,
				SendRevision:       2,
				DeploymentID:       "dep-1",
				Outcome:            "CREATED",
				OrderID:            &orderID,
				CreationDecisionID: &decID,
				HistoricalStatus:   "MATCHED",
			}, nil
		},
	}

	srv := newServerWithOps(&domgw.Service{}, ops)
	h := srv.Handler()

	// 1. POST /v1/auth/challenges -> 201 Created + generated X-Request-Id.
	reqHash := strings.Repeat("a", 64)
	chalRec := doRequest(t, h, http.MethodPost, "/v1/auth/challenges", domgw.ChallengeRequest{
		Actor:       "did:web:b.local:b1",
		TaskID:      "task-1",
		RequestHash: reqHash,
	}, nil, nil)
	require.Equal(t, http.StatusCreated, chalRec.Code, chalRec.Body.String())
	assert.True(t, strings.HasPrefix(chalRec.Header().Get(httpx.HeaderRequestID), "urn:grad:req:"))
	assert.Equal(t, "did:web:b.local:b1", gotChallengeReq.Actor)
	var chalResp domgw.ChallengeResponse
	require.NoError(t, json.Unmarshal(chalRec.Body.Bytes(), &chalResp))
	assert.Equal(t, "urn:grad:challenge:ch-1", chalResp.ChallengeID)

	// 2. POST /v1/contexts/{taskId} -> 200 OK + propagated X-Request-Id.
	ctxRec := doRequest(t, h, http.MethodPost, "/v1/contexts/task-42", domgw.ContextUpdateRequest{
		ExpectedContextVersion: 0,
		SourceID:               "risk-engine",
		ObservedAt:             1000,
		RiskLevel:              "NORMAL",
		AccessDeadline:         2000,
	}, map[string]string{httpx.HeaderRequestID: "urn:grad:req:custom-ctx"}, nil)
	require.Equal(t, http.StatusOK, ctxRec.Code, ctxRec.Body.String())
	assert.Equal(t, "urn:grad:req:custom-ctx", ctxRec.Header().Get(httpx.HeaderRequestID))
	assert.Equal(t, "task-42", gotCtxTaskID)
	assert.Equal(t, "risk-engine", gotCtxReq.SourceID)
	var ctxResp domgw.ContextResponse
	require.NoError(t, json.Unmarshal(ctxRec.Body.Bytes(), &ctxResp))
	assert.Equal(t, int64(1), ctxResp.ContextVersion)

	// 3. POST /v1/access/execute -> 200 OK + forwards requestID and exact raw JSON body.
	rawExec := `{"challengeId":"urn:grad:challenge:ch-1"}`
	execRec := doRequest(t, h, http.MethodPost, "/v1/access/execute", rawExec, map[string]string{
		httpx.HeaderRequestID: "urn:grad:req:custom-exec",
	}, nil)
	require.Equal(t, http.StatusOK, execRec.Code, execRec.Body.String())
	assert.Equal(t, "urn:grad:req:custom-exec", execRec.Header().Get(httpx.HeaderRequestID))
	assert.Equal(t, "urn:grad:req:custom-exec", gotExecReqID)
	assert.Equal(t, rawExec, string(gotExecBody))
	var execResp domgw.ExecuteResponse
	require.NoError(t, json.Unmarshal(execRec.Body.Bytes(), &execResp))
	assert.Equal(t, decID, execResp.DecisionID)
	require.NotNil(t, execResp.Quote)
	assert.Equal(t, "urn:grad:quote:q-1", execResp.Quote.QuoteID)

	// 4. GET /v1/decisions/{id} -> 200 OK.
	decRec := doRequest(t, h, http.MethodGet, "/v1/decisions/"+decID, nil, nil, nil)
	require.Equal(t, http.StatusOK, decRec.Code, decRec.Body.String())
	assert.Equal(t, decID, gotDecisionID)
	var decBody domgw.DecisionRecord
	require.NoError(t, json.Unmarshal(decRec.Body.Bytes(), &decBody))
	assert.Equal(t, decID, decBody.DecisionID)
	assert.Equal(t, "ALLOW", decBody.Outcome)

	// 5. GET /v1/health/ready -> 200 OK.
	readyRec := doRequest(t, h, http.MethodGet, "/v1/health/ready", nil, nil, nil)
	require.Equal(t, http.StatusOK, readyRec.Code, readyRec.Body.String())
	var readyResp domgw.ReadyStatus
	require.NoError(t, json.Unmarshal(readyRec.Body.Bytes(), &readyResp))
	assert.Equal(t, "READY", readyResp.Status)
	require.NotNil(t, readyResp.ProbeBlock)
	assert.Equal(t, uint64(12), *readyResp.ProbeBlock)

	// 6. POST /v1/internal/order-outcome-cases -> 202 Accepted + mTLS B_RECOVERY identity.
	recoveryID := &mtls.Identity{Role: "B_RECOVERY", DID: "did:web:b.local:services:recovery"}
	caseRec := doRequest(t, h, http.MethodPost, "/v1/internal/order-outcome-cases", domgw.OrderOutcomeCaseRequest{
		CaseID:       "urn:grad:case:1",
		SendRevision: 2,
		DeploymentID: "dep-1",
		Request: protocol.AccessRequest{
			Actor:          "did:web:b.local:b1",
			TaskID:         "task-1",
			IdempotencyKey: "idem-1",
		},
		RequestHash:  reqHash,
		ChallengeIDs: []string{"urn:grad:challenge:ch-1"},
	}, nil, recoveryID)
	require.Equal(t, http.StatusAccepted, caseRec.Code, caseRec.Body.String())
	assert.Equal(t, domgw.CallerIdentity{Role: "B_RECOVERY", DID: "did:web:b.local:services:recovery"}, gotCaseCaller)
	assert.Equal(t, "urn:grad:case:1", gotCaseReq.CaseID)
	var caseResp domgw.OrderOutcomeCaseResponse
	require.NoError(t, json.Unmarshal(caseRec.Body.Bytes(), &caseResp))
	assert.Equal(t, "REGISTERED", caseResp.Status)

	// 7. POST /v1/audit/order-outcomes -> 200 OK + mTLS C_AUDITOR identity.
	auditorID := &mtls.Identity{Role: "C_AUDITOR", DID: "did:web:c.local:auditors:c1"}
	auditRec := doRequest(t, h, http.MethodPost, "/v1/audit/order-outcomes", domgw.AuditOrderOutcomeRequest{
		CaseID: "urn:grad:case:1",
	}, nil, auditorID)
	require.Equal(t, http.StatusOK, auditRec.Code, auditRec.Body.String())
	assert.Equal(t, domgw.CallerIdentity{Role: "C_AUDITOR", DID: "did:web:c.local:auditors:c1"}, gotAuditCaller)
	assert.Equal(t, "urn:grad:case:1", gotAuditReq.CaseID)
	var auditResp domgw.AuditOrderOutcomeResponse
	require.NoError(t, json.Unmarshal(auditRec.Body.Bytes(), &auditResp))
	assert.Equal(t, "CREATED", auditResp.Outcome)
	require.NotNil(t, auditResp.OrderID)
	assert.Equal(t, orderID, *auditResp.OrderID)
}

func TestErrorStatusCodesAndErrorBodyDecisionID(t *testing.T) {
	t.Parallel()

	t.Run("415 unsupported media type and 413 payload too large and 400 invalid JSON", func(t *testing.T) {
		t.Parallel()
		srv := newServerWithOps(&domgw.Service{}, &stubDomainService{})
		h := srv.Handler()

		// 415 missing/wrong Content-Type.
		rec415 := doRequest(t, h, http.MethodPost, "/v1/auth/challenges", `{}`, map[string]string{
			"Content-Type":        "text/plain",
			httpx.HeaderRequestID: "urn:grad:req:415",
		}, nil)
		require.Equal(t, http.StatusUnsupportedMediaType, rec415.Code)
		var eb415 ErrorBody
		require.NoError(t, json.Unmarshal(rec415.Body.Bytes(), &eb415))
		assert.Equal(t, "urn:grad:req:415", eb415.RequestID)
		assert.Equal(t, protocol.ErrCodeUnsupportedMediaType, eb415.Code)
		assert.Nil(t, eb415.DecisionID)
		var rawMap map[string]any
		require.NoError(t, json.Unmarshal(rec415.Body.Bytes(), &rawMap))
		_, hasDecKey := rawMap["decisionId"]
		assert.True(t, hasDecKey, "decisionId key must be emitted even when null")

		// 413 oversized payload (> 256 KiB).
		bigBody := bytes.Repeat([]byte("a"), domgw.MaxExecuteBodyBytes+1)
		rec413 := doRequest(t, h, http.MethodPost, "/v1/access/execute", bigBody, nil, nil)
		require.Equal(t, http.StatusRequestEntityTooLarge, rec413.Code)
		var eb413 ErrorBody
		require.NoError(t, json.Unmarshal(rec413.Body.Bytes(), &eb413))
		assert.Equal(t, protocol.ErrCodePayloadTooLarge, eb413.Code)
		assert.Nil(t, eb413.DecisionID)

		// 400 unknown field rejected by strict JSON decoding.
		rec400 := doRequest(t, h, http.MethodPost, "/v1/auth/challenges", `{"actor":"a","unknownField":1}`, nil, nil)
		require.Equal(t, http.StatusBadRequest, rec400.Code)
		var eb400 ErrorBody
		require.NoError(t, json.Unmarshal(rec400.Body.Bytes(), &eb400))
		assert.Equal(t, protocol.ErrCodeInvalidSchema, eb400.Code)
		assert.Nil(t, eb400.DecisionID)

		// 400 whitespace path parameter rejected before calling L2.
		recBlankTask := doRequest(t, h, http.MethodPost, "/v1/contexts/%20%20", `{}`, nil, nil)
		require.Equal(t, http.StatusBadRequest, recBlankTask.Code)
		recBlankDec := doRequest(t, h, http.MethodGet, "/v1/decisions/%20", nil, nil, nil)
		require.Equal(t, http.StatusBadRequest, recBlankDec.Code)
	})

	t.Run("403 DENY includes decisionId in ErrorBody and 409 conflict and 404 not found and 503 unavailable", func(t *testing.T) {
		t.Parallel()

		ops := &stubDomainService{
			executeAccessFn: func(_ context.Context, _ string, rawBody []byte) (*domgw.ExecuteResponse, error) {
				if strings.Contains(string(rawBody), "conflict") {
					return nil, &domgw.DecisionError{
						DecisionID: "urn:grad:decision:deny-conflict",
						Err:        protocol.NewError(protocol.ErrCodeAmountMismatch, "amount mismatch"),
					}
				}
				return nil, &domgw.DecisionError{
					DecisionID: "urn:grad:decision:deny-policy",
					Err:        protocol.NewError(protocol.ErrCodePolicyDenied, "blocked by risk policy"),
				}
			},
			getDecisionFn: func(_ context.Context, _ string) (*domgw.DecisionRecord, error) {
				return nil, protocol.WrapError(protocol.ErrCodeInvalidSchema, "decision not found", domgw.ErrDecisionNotFound)
			},
			updateContextFn: func(_ context.Context, _ string, _ domgw.ContextUpdateRequest) (*domgw.ContextResponse, error) {
				return nil, protocol.NewError(protocol.ErrCodeStateChanged, "expectedContextVersion mismatch")
			},
			checkReadyFn: func(_ context.Context) (*domgw.ReadyStatus, error) {
				return nil, protocol.NewError(protocol.ErrCodeStateStale, "fabric probe lease expired")
			},
			auditOrderOutcomeFn: func(_ context.Context, _ domgw.CallerIdentity, _ domgw.AuditOrderOutcomeRequest) (*domgw.AuditOrderOutcomeResponse, error) {
				return nil, protocol.NewError(protocol.ErrCodeAuditForbidden, "caller lacks C_AUDITOR role")
			},
		}

		srv := newServerWithOps(&domgw.Service{}, ops)
		h := srv.Handler()

		// 403 DENY with persisted decisionId.
		recDeny := doRequest(t, h, http.MethodPost, "/v1/access/execute", `{"mode":"deny"}`, map[string]string{
			httpx.HeaderRequestID: "urn:grad:req:deny-1",
		}, nil)
		require.Equal(t, http.StatusForbidden, recDeny.Code)
		var ebDeny ErrorBody
		require.NoError(t, json.Unmarshal(recDeny.Body.Bytes(), &ebDeny))
		assert.Equal(t, "urn:grad:req:deny-1", ebDeny.RequestID)
		assert.Equal(t, protocol.ErrCodePolicyDenied, ebDeny.Code)
		require.NotNil(t, ebDeny.DecisionID)
		assert.Equal(t, "urn:grad:decision:deny-policy", *ebDeny.DecisionID)

		// 409 DENY with persisted decisionId.
		recConflictExec := doRequest(t, h, http.MethodPost, "/v1/access/execute", `{"mode":"conflict"}`, nil, nil)
		require.Equal(t, http.StatusConflict, recConflictExec.Code)
		var ebConflictExec ErrorBody
		require.NoError(t, json.Unmarshal(recConflictExec.Body.Bytes(), &ebConflictExec))
		assert.Equal(t, protocol.ErrCodeAmountMismatch, ebConflictExec.Code)
		require.NotNil(t, ebConflictExec.DecisionID)
		assert.Equal(t, "urn:grad:decision:deny-conflict", *ebConflictExec.DecisionID)

		// 409 conflict on context version mismatch.
		recCtx409 := doRequest(t, h, http.MethodPost, "/v1/contexts/task-1", domgw.ContextUpdateRequest{
			ExpectedContextVersion: 1,
			SourceID:               "risk-engine",
			ObservedAt:             1000,
			RiskLevel:              "NORMAL",
			AccessDeadline:         2000,
		}, nil, nil)
		require.Equal(t, http.StatusConflict, recCtx409.Code)
		var ebCtx409 ErrorBody
		require.NoError(t, json.Unmarshal(recCtx409.Body.Bytes(), &ebCtx409))
		assert.Equal(t, protocol.ErrCodeStateChanged, ebCtx409.Code)
		assert.Nil(t, ebCtx409.DecisionID)

		// 404 decision not found.
		rec404 := doRequest(t, h, http.MethodGet, "/v1/decisions/urn:grad:decision:missing", nil, nil, nil)
		require.Equal(t, http.StatusNotFound, rec404.Code)
		var eb404 ErrorBody
		require.NoError(t, json.Unmarshal(rec404.Body.Bytes(), &eb404))
		assert.Equal(t, protocol.ErrCodeInvalidSchema, eb404.Code)
		assert.Nil(t, eb404.DecisionID)

		// 403 audit forbidden.
		rec403 := doRequest(t, h, http.MethodPost, "/v1/audit/order-outcomes", domgw.AuditOrderOutcomeRequest{CaseID: "c1"}, nil, nil)
		require.Equal(t, http.StatusForbidden, rec403.Code)
		var eb403 ErrorBody
		require.NoError(t, json.Unmarshal(rec403.Body.Bytes(), &eb403))
		assert.Equal(t, protocol.ErrCodeAuditForbidden, eb403.Code)

		// 503 readiness unavailable.
		rec503 := doRequest(t, h, http.MethodGet, "/v1/health/ready", nil, nil, nil)
		require.Equal(t, http.StatusServiceUnavailable, rec503.Code)
		var eb503 ErrorBody
		require.NoError(t, json.Unmarshal(rec503.Body.Bytes(), &eb503))
		assert.Equal(t, protocol.ErrCodeStateStale, eb503.Code)
	})
}

func TestHTTPStatusForCodeMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		code string
		want int
	}{
		{protocol.ErrCodePayloadTooLarge, http.StatusRequestEntityTooLarge},
		{protocol.ErrCodeUnsupportedMediaType, http.StatusUnsupportedMediaType},
		{protocol.ErrCodeInvalidSchema, http.StatusBadRequest},
		{protocol.ErrCodeInvalidDisclosure, http.StatusBadRequest},
		{protocol.ErrCodeRecoveryProofInvalid, http.StatusBadRequest},
		{protocol.ErrCodeSignatureInvalid, http.StatusUnauthorized},
		{protocol.ErrCodeBindingMismatch, http.StatusUnauthorized},
		{protocol.ErrCodeChallengeExpired, http.StatusUnauthorized},
		{protocol.ErrCodeChallengeReplay, http.StatusConflict},
		{protocol.ErrCodeIdempotencyConflict, http.StatusConflict},
		{protocol.ErrCodeStateChanged, http.StatusConflict},
		{protocol.ErrCodeQuoteExpired, http.StatusConflict},
		{protocol.ErrCodeAmountMismatch, http.StatusConflict},
		{protocol.ErrCodePolicyDenied, http.StatusForbidden},
		{protocol.ErrCodeAmountLimitExceeded, http.StatusForbidden},
		{protocol.ErrCodeAuditForbidden, http.StatusForbidden},
		{protocol.ErrCodeDomainInactive, http.StatusForbidden},
		{protocol.ErrCodeStateUnavailable, http.StatusServiceUnavailable},
		{protocol.ErrCodeStateStale, http.StatusServiceUnavailable},
		{protocol.ErrCodeMaterialNotSynced, http.StatusServiceUnavailable},
		{protocol.ErrCodeContextStale, http.StatusServiceUnavailable},
		{protocol.ErrCodePriceUnavailable, http.StatusServiceUnavailable},
		{"CUSTOM_INVALID_INPUT", http.StatusBadRequest},
		{"UNEXPECTED_FAILURE", http.StatusInternalServerError},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.want, httpStatusForCode(tc.code), "code=%s", tc.code)
	}
}

func TestExtractCallerIdentityMTLSBoundaries(t *testing.T) {
	t.Parallel()

	// Self-asserted headers MUST be ignored without mTLS identity.
	reqHeaderOnly := httptest.NewRequest(http.MethodPost, "/v1/audit/order-outcomes", nil)
	reqHeaderOnly.Header.Set("X-Caller-Role", "C_AUDITOR")
	reqHeaderOnly.Header.Set("X-Caller-DID", "did:web:c.local:auditors:c1")
	assert.Equal(t, domgw.CallerIdentity{}, extractCallerIdentity(reqHeaderOnly))

	// In-process context identity extracted cleanly.
	reqCtx := httptest.NewRequest(http.MethodPost, "/v1/audit/order-outcomes", nil)
	reqCtx = reqCtx.WithContext(mtls.WithIdentity(reqCtx.Context(), mtls.Identity{
		Role: "B_RECOVERY",
		DID:  "did:web:b.local:services:recovery",
	}))
	assert.Equal(t, domgw.CallerIdentity{
		Role: "B_RECOVERY",
		DID:  "did:web:b.local:services:recovery",
	}, extractCallerIdentity(reqCtx))

	// Verified TLS client certificate extracted from r.TLS.VerifiedChains.
	uriSAN, err := url.Parse("did:web:c.local:auditors:c1")
	require.NoError(t, err)
	leaf := &x509.Certificate{
		Raw:     []byte("synthetic-leaf-cert"),
		URIs:    []*url.URL{uriSAN},
		Subject: pkix.Name{OrganizationalUnit: []string{"c_auditor"}},
	}
	reqTLS := httptest.NewRequest(http.MethodPost, "/v1/audit/order-outcomes", nil)
	reqTLS.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{leaf}},
	}
	assert.Equal(t, domgw.CallerIdentity{
		Role: "C_AUDITOR",
		DID:  "did:web:c.local:auditors:c1",
	}, extractCallerIdentity(reqTLS))
}

func TestNewHTTPReceiptSenderAndServerDelivery(t *testing.T) {
	t.Parallel()

	orderID := "urn:grad:order:ord-1"
	decID := "urn:grad:decision:dec-1"
	sampleReceipt := domgw.OrderOutcomeReceipt{
		CaseID:             "urn:grad:case:1",
		CheckNo:            1,
		SendRevision:       2,
		DeploymentID:       "dep-1",
		Actor:              "did:web:b.local:b1",
		TaskID:             "task-1",
		RequestHash:        strings.Repeat("b", 64),
		Outcome:            "CREATED",
		OrderID:            &orderID,
		CreationDecisionID: &decID,
		HistoricalStatus:   "MATCHED",
		AuditAt:            1700000000,
	}

	t.Run("success validates request headers and echoed receipt", func(t *testing.T) {
		t.Parallel()
		var (
			gotMethod      string
			gotContentType string
			gotReqID       string
			gotReceipt     domgw.OrderOutcomeReceipt
		)
		receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			gotContentType = r.Header.Get("Content-Type")
			gotReqID = r.Header.Get(httpx.HeaderRequestID)
			require.NoError(t, json.NewDecoder(r.Body).Decode(&gotReceipt))
			httpx.WriteJSON(w, http.StatusOK, domgw.OrderOutcomeReceiptResponse{
				Status:             "RECEIVED",
				ClientActionStatus: "RECONCILED",
				Receipt:            gotReceipt,
			})
		}))
		defer receiver.Close()

		ack, err := SendHTTPReceipt(t.Context(), receiver.Client(), receiver.URL, sampleReceipt)
		require.NoError(t, err)
		require.NotNil(t, ack)
		assert.Equal(t, "RECEIVED", ack.Status)
		assert.Equal(t, "RECONCILED", ack.ClientActionStatus)
		assert.Equal(t, sampleReceipt, ack.Receipt)

		sender := NewHTTPReceiptSender(receiver.Client(), receiver.URL)
		require.NoError(t, sender(t.Context(), sampleReceipt))
		assert.Equal(t, http.MethodPost, gotMethod)
		assert.Equal(t, "application/json", gotContentType)
		assert.True(t, strings.HasPrefix(gotReqID, "urn:grad:req:"))
		assert.Equal(t, sampleReceipt, gotReceipt)
	})

	t.Run("echo mismatch is rejected", func(t *testing.T) {
		t.Parallel()
		receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var rcpt domgw.OrderOutcomeReceipt
			require.NoError(t, json.NewDecoder(r.Body).Decode(&rcpt))
			rcpt.Outcome = "NOT_CREATED"
			httpx.WriteJSON(w, http.StatusOK, domgw.OrderOutcomeReceiptResponse{
				Status:  "RECEIVED",
				Receipt: rcpt,
			})
		}))
		defer receiver.Close()

		sender := NewHTTPReceiptSender(receiver.Client(), receiver.URL)
		err := sender(t.Context(), sampleReceipt)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "receipt acknowledgement binding mismatch")
	})

	t.Run("non-200 status and malformed or oversized ack are rejected", func(t *testing.T) {
		t.Parallel()
		srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv500.Close()
		err := NewHTTPReceiptSender(srv500.Client(), srv500.URL)(t.Context(), sampleReceipt)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "receipt delivery HTTP 500")

		srvBadJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-json"))
		}))
		defer srvBadJSON.Close()
		err = NewHTTPReceiptSender(srvBadJSON.Client(), srvBadJSON.URL)(t.Context(), sampleReceipt)
		require.Error(t, err)

		srvHuge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.Repeat([]byte(" "), domgw.MaxExecuteBodyBytes+10))
		}))
		defer srvHuge.Close()
		err = NewHTTPReceiptSender(srvHuge.Client(), srvHuge.URL)(t.Context(), sampleReceipt)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds")
	})

	t.Run("validation and Server delivery wrappers", func(t *testing.T) {
		t.Parallel()
		err := NewHTTPReceiptSender(nil, "https://b.local/receipts")(t.Context(), sampleReceipt)
		require.Error(t, err)
		err = NewHTTPReceiptSender(http.DefaultClient, "   ")(t.Context(), sampleReceipt)
		require.Error(t, err)

		receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var rcpt domgw.OrderOutcomeReceipt
			require.NoError(t, json.NewDecoder(r.Body).Decode(&rcpt))
			httpx.WriteJSON(w, http.StatusOK, domgw.OrderOutcomeReceiptResponse{
				Status:  "RECEIVED",
				Receipt: rcpt,
			})
		}))
		defer receiver.Close()

		var deliveredEntries []domgw.OutboxEntry
		ops := &stubDomainService{
			deliverReceiptFn: func(ctx context.Context, entry domgw.OutboxEntry, send domgw.ReceiptSender) error {
				deliveredEntries = append(deliveredEntries, entry)
				return send(ctx, sampleReceipt)
			},
			deliverPendingReceiptsFn: func(ctx context.Context, send domgw.ReceiptSender) (int, error) {
				if err := send(ctx, sampleReceipt); err != nil {
					return 0, err
				}
				return 1, nil
			},
		}
		srv := newServerWithOps(&domgw.Service{}, ops)

		entry := domgw.OutboxEntry{
			DeploymentID: "dep-1",
			CaseID:       sampleReceipt.CaseID,
			SendRevision: sampleReceipt.SendRevision,
			CheckNo:      sampleReceipt.CheckNo,
		}
		require.Error(t, srv.DeliverReceipt(t.Context(), nil, receiver.URL, entry))
		require.Error(t, srv.DeliverReceipt(t.Context(), receiver.Client(), "", entry))
		require.NoError(t, srv.DeliverReceipt(t.Context(), receiver.Client(), receiver.URL, entry))
		require.Len(t, deliveredEntries, 1)
		assert.Equal(t, entry.CaseID, deliveredEntries[0].CaseID)

		_, err = srv.DeliverPendingReceipts(t.Context(), nil, receiver.URL)
		require.Error(t, err)
		_, err = srv.DeliverPendingReceipts(t.Context(), receiver.Client(), "")
		require.Error(t, err)
		n, err := srv.DeliverPendingReceipts(t.Context(), receiver.Client(), receiver.URL)
		require.NoError(t, err)
		assert.Equal(t, 1, n)
	})
}
