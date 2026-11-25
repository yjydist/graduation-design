package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domreg "grad/platform/core/domain/registry"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/protocol"
	preg "grad/protocol/registry"
)

func assertUnifiedErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCode string) httpx.ErrorEnvelope {
	t.Helper()
	require.Equal(t, wantStatus, rec.Code, "body=%s", rec.Body.String())
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
	reqIDHeader := rec.Header().Get(httpx.HeaderRequestID)
	assert.NotEmpty(t, reqIDHeader)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	_, hasLegacy := raw["errorCode"]
	assert.False(t, hasLegacy, "legacy errorCode key must not appear in unified error envelope: %s", rec.Body.String())
	val, hasDecisionID := raw["decisionId"]
	assert.True(t, hasDecisionID, "decisionId must always be present in error envelope")
	assert.Nil(t, val, "decisionId must be null for registry API errors")

	var env httpx.ErrorEnvelope
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	assert.Equal(t, reqIDHeader, env.RequestID)
	assert.Equal(t, wantCode, env.Code)
	assert.Nil(t, env.DecisionID)
	assert.NotEmpty(t, env.Message)
	return env
}

type noopBackend struct{}

func (*noopBackend) CurrentRevision(context.Context, string, string) (uint64, bool, error) {
	return 0, false, nil
}

func (*noopBackend) SubmitAsync(
	context.Context,
	string, string,
	preg.Management,
	string,
	json.RawMessage,
	domreg.OutcomeHandler,
) {
}

type resolvingNoopBackend struct {
	noopBackend
	bound map[string]preg.Management
}

func (b *resolvingNoopBackend) ManagementForFingerprint(fp string) (preg.Management, bool) {
	m, ok := b.bound[fp]
	return m, ok
}

func TestHandlerUnifiedErrorEnvelopeWithoutDB(t *testing.T) {
	caller := mtls.Identity{Role: "MANAGEMENT", MSPID: "AMsp", Fingerprint: strings.Repeat("a", 64)}

	// Nil service returns 403 for unauthenticated callers and 503 for authenticated callers.
	hNil := NewServer(nil).Handler()
	req := httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	hNil.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden)

	req = httptest.NewRequest(http.MethodGet, "/v1/operations/op-1", nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	hNil.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable)

	// Service with nil backend -> 503 STATE_UNAVAILABLE on POST.
	svcNoBackend := domreg.NewService(nil, strings.Repeat("1", 64), preg.Management{}, nil)
	hNoBackend := NewServer(svcNoBackend).Handler()

	// Unauthenticated POST -> 403 IDENTITY_MANAGEMENT_FORBIDDEN (self-asserted headers ignored).
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Caller-MSPID", caller.MSPID)
	req.Header.Set("X-Caller-Fingerprint", caller.Fingerprint)
	rec = httptest.NewRecorder()
	hNoBackend.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden)

	// Unauthenticated GET -> 403 IDENTITY_MANAGEMENT_FORBIDDEN.
	req = httptest.NewRequest(http.MethodGet, "/v1/operations/some-id", nil)
	rec = httptest.NewRecorder()
	hNoBackend.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden)

	// Invalid mTLS caller (missing fingerprint) -> 403 IDENTITY_MANAGEMENT_FORBIDDEN.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: "AMsp"}))
	rec = httptest.NewRecorder()
	hNoBackend.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden)

	// Authenticated GET with empty operationId -> 400 INVALID_SCHEMA.
	req = httptest.NewRequest(http.MethodGet, "/v1/operations/", nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	hNoBackend.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusBadRequest, preg.ErrCodeInvalidSchema)

	// Authenticated POST with nil backend -> 503 STATE_UNAVAILABLE.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	hNoBackend.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable)

	// Service with backend and nil DB to verify HTTP body validation errors.
	svcWithBackend := domreg.NewService(nil, strings.Repeat("1", 64), preg.Management{}, &noopBackend{})
	h := NewServer(svcWithBackend).Handler()

	// Unsupported Content-Type -> 415 UNSUPPORTED_MEDIA_TYPE.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusUnsupportedMediaType, preg.ErrCodeUnsupportedMediaType)

	// Missing Content-Type -> 415 UNSUPPORTED_MEDIA_TYPE.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{}`))
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusUnsupportedMediaType, preg.ErrCodeUnsupportedMediaType)

	// Oversized payload -> 413 PAYLOAD_TOO_LARGE.
	bigBody := bytes.Repeat([]byte("a"), protocol.MaxJSONBytes+1)
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", bytes.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusRequestEntityTooLarge, preg.ErrCodePayloadTooLarge)

	// Empty JSON body -> 400 INVALID_SCHEMA.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader("   "))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusBadRequest, preg.ErrCodeInvalidSchema)

	// Malformed JSON -> 400 INVALID_SCHEMA with custom X-Request-Id echoed.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{"broken":`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httpx.HeaderRequestID, "urn:grad:req:custom-1")
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	env := assertUnifiedErrorEnvelope(t, rec, http.StatusBadRequest, preg.ErrCodeInvalidSchema)
	assert.Equal(t, "urn:grad:req:custom-1", env.RequestID)
}

func TestHandlerResolverBackedCallerAndAuditor(t *testing.T) {
	fpA := strings.Repeat("a", 64)
	fpAuditor := strings.Repeat("b", 64)
	fpUnknown := strings.Repeat("f", 64)
	mgmtA := preg.Management{MSPID: "AMsp", CertificateSHA256: fpA}
	auditorB := preg.Management{MSPID: "BMsp", CertificateSHA256: fpAuditor}

	svc := domreg.NewService(nil, strings.Repeat("1", 64), preg.Management{}, &resolvingNoopBackend{
		bound: map[string]preg.Management{fpA: mgmtA},
	})
	svc.SetOperationAuditors([]preg.Management{auditorB})
	h := NewServer(svc).Handler()

	// Unbound mTLS fingerprint -> 403 IDENTITY_MANAGEMENT_FORBIDDEN.
	req := httptest.NewRequest(http.MethodGet, "/v1/operations/op-1", nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: "AMsp", Fingerprint: fpUnknown}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden)

	// Bound management caller passes auth and reaches service (nil DB -> 503 STATE_UNAVAILABLE).
	req = httptest.NewRequest(http.MethodGet, "/v1/operations/op-1", nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: "", Fingerprint: fpA}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable)

	// Registered auditor passes auth and reaches service (nil DB -> 503 STATE_UNAVAILABLE).
	req = httptest.NewRequest(http.MethodGet, "/v1/operations/op-1", nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "AUDITOR", MSPID: "BMsp", Fingerprint: fpAuditor}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable)
}

type fakeOpRecord struct {
	owner       preg.Management
	payloadHash string
	view        domreg.OperationView
}

type fakeOpService struct {
	mu           sync.Mutex
	deploymentID string
	rootMgmt     preg.Management
	hasBackend   bool
	currentRev   uint64
	auditors     map[preg.Management]bool
	byKey        map[string]*fakeOpRecord
	byID         map[string]*fakeOpRecord
}

func newFakeOpService(depID string, rootMgmt preg.Management, currentRev uint64) *fakeOpService {
	return &fakeOpService{
		deploymentID: depID,
		rootMgmt:     rootMgmt,
		hasBackend:   true,
		currentRev:   currentRev,
		auditors:     make(map[preg.Management]bool),
		byKey:        make(map[string]*fakeOpRecord),
		byID:         make(map[string]*fakeOpRecord),
	}
}

func (f *fakeOpService) HasBackend() bool { return f.hasBackend }

func (f *fakeOpService) ResolveManagementCaller(fp, mspID string) (preg.Management, bool) {
	c := preg.Management{MSPID: mspID, CertificateSHA256: fp}
	return c, c.Valid()
}

func (f *fakeOpService) IsOperationAuditor(fp, mspID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auditors[preg.Management{MSPID: mspID, CertificateSHA256: fp}]
}

func (f *fakeOpService) Accept(
	_ context.Context,
	opKey string,
	caller preg.Management,
	method string,
	input json.RawMessage,
	_ bool,
) (*domreg.OperationView, error) {
	if opKey == "" || method == "" {
		return nil, protocol.NewError(preg.ErrCodeInvalidSchema, "operationKey and method required")
	}
	if (method == "CertifyDomain" || method == "RevokeCertification" || method == "SetDomainStatus" || method == "UpdateAuthorityIdentity") &&
		f.rootMgmt.Valid() && caller != f.rootMgmt {
		return nil, protocol.NewError(preg.ErrCodeTrustManagementForbidden, fmt.Sprintf("caller %s not permitted for %s", caller, method))
	}
	canon, err := protocol.CanonicalizeJSON(input)
	if err != nil {
		return nil, protocol.WrapError(preg.ErrCodeInvalidSchema, "canonicalize request", err)
	}
	payloadHash := preg.Digest(canon)
	opID := domreg.ManagementOperationID(f.deploymentID, caller, method, opKey)

	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.byKey[opID]; ok {
		if existing.payloadHash != payloadHash {
			return nil, protocol.NewError(preg.ErrCodeIdempotencyConflict, fmt.Sprintf("operationKey %q reused with different payload", opKey))
		}
		v := existing.view
		return &v, nil
	}

	var revCheck struct {
		ExpectedRevision *uint64 `json:"expectedRevision"`
	}
	if err := json.Unmarshal(canon, &revCheck); err != nil {
		return nil, protocol.WrapError(preg.ErrCodeInvalidSchema, "invalid revision target", err)
	}
	if revCheck.ExpectedRevision != nil && *revCheck.ExpectedRevision != f.currentRev {
		return nil, protocol.NewError(preg.ErrCodeStateChanged, fmt.Sprintf("expected %d, current %d", *revCheck.ExpectedRevision, f.currentRev))
	}

	rec := &fakeOpRecord{
		owner:       caller,
		payloadHash: payloadHash,
		view: domreg.OperationView{
			OperationID:  opID,
			OperationKey: opKey,
			Method:       method,
			TxID:         "pending:" + preg.Digest([]byte(opID))[:24],
			Stage:        "ACCEPT",
			Status:       "PENDING",
		},
	}
	f.byKey[opID] = rec
	f.byID[opID] = rec
	v := rec.view
	return &v, nil
}

func (f *fakeOpService) Operation(_ context.Context, caller preg.Management, opID string) (*domreg.OperationView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.byID[opID]
	if !ok {
		return nil, protocol.NewError(preg.ErrCodeOperationUnknown, fmt.Sprintf("unknown operationId %q", opID))
	}
	if caller != rec.owner && !(f.auditors[caller] && caller.MSPID == rec.owner.MSPID) {
		return nil, protocol.NewError(preg.ErrCodeIdentityManagementForbidden, "operation query forbidden")
	}
	v := rec.view
	return &v, nil
}

func TestHandlerManagementAcceptReplayConflictAndOperationQueries(t *testing.T) {
	depID := strings.Repeat("d", 64)
	rootMgmt := preg.Management{MSPID: "TMsp", CertificateSHA256: strings.Repeat("f", 64)}
	owner := preg.Management{MSPID: "BMsp", CertificateSHA256: strings.Repeat("a", 64)}
	sameDomainAuditor := preg.Management{MSPID: "BMsp", CertificateSHA256: strings.Repeat("b", 64)}
	otherDomainAuditor := preg.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("c", 64)}
	otherManager := preg.Management{MSPID: "BMsp", CertificateSHA256: strings.Repeat("e", 64)}

	fake := newFakeOpService(depID, rootMgmt, 2)
	fake.auditors[sameDomainAuditor] = true
	fake.auditors[otherDomainAuditor] = true
	h := newServerWithOps(fake).Handler()

	// 1. Missing Idempotency-Key -> 400 INVALID_SCHEMA.
	req := httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{"id":"u1","expectedRevision":2}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusBadRequest, preg.ErrCodeInvalidSchema)

	// 2. Stale expectedRevision -> 409 STATE_CHANGED.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{"id":"u1","expectedRevision":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "op-stale")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusConflict, preg.ErrCodeStateChanged)

	// 3. Non-root caller on trust management method -> 403 TRUST_MANAGEMENT_FORBIDDEN.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/SetDomainStatus", strings.NewReader(`{"domainId":"A","expectedRevision":2,"status":"SUSPENDED"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "op-trust")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, preg.ErrCodeTrustManagementForbidden)

	// 4. Valid POST -> 202 Accepted via verified mTLS local client.
	client := mtls.NewLocalClient(h, mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256})
	inA := []byte(`{"id":"did:web:b.local:u","expectedRevision":2,"keyId":"k2"}`)
	httpReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://c.local/v1/management/RotateIdentity", bytes.NewReader(inA))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Idempotency-Key", "run1/op-1")
	resp, err := client.Do(httpReq)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get(httpx.HeaderRequestID))
	var created domreg.OperationView
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	assert.NotEmpty(t, created.OperationID)
	assert.Equal(t, "run1/op-1", created.OperationKey)
	assert.Equal(t, "RotateIdentity", created.Method)
	assert.Equal(t, "PENDING", created.Status)

	// 5. Idempotency replay with canonically equivalent payload -> 202 with same operationId.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{"keyId":"k2", "expectedRevision":2, "id":"did:web:b.local:u"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "run1/op-1")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)
	var replayed domreg.OperationView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &replayed))
	assert.Equal(t, created.OperationID, replayed.OperationID)

	// 6. Idempotency conflict (different payload, same key) -> 409 IDEMPOTENCY_CONFLICT.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{"id":"did:web:b.local:u","expectedRevision":2,"keyId":"k3"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "run1/op-1")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusConflict, preg.ErrCodeIdempotencyConflict)

	// 7. GET /v1/operations/{id} as owner -> 200 OK.
	req = httptest.NewRequest(http.MethodGet, "/v1/operations/"+created.OperationID, nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var fetched domreg.OperationView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &fetched))
	assert.Equal(t, created.OperationID, fetched.OperationID)

	// 8. GET /v1/operations/{id} as same-domain auditor -> 200 OK.
	req = httptest.NewRequest(http.MethodGet, "/v1/operations/"+created.OperationID, nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "AUDITOR", MSPID: sameDomainAuditor.MSPID, Fingerprint: sameDomainAuditor.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// 9. GET /v1/operations/{id} as unauthorized callers -> 403 without leaking operationId/operationKey.
	for _, tc := range []struct {
		name string
		id   mtls.Identity
	}{
		{"other-same-domain-manager", mtls.Identity{Role: "MANAGEMENT", MSPID: otherManager.MSPID, Fingerprint: otherManager.CertificateSHA256}},
		{"cross-domain-auditor", mtls.Identity{Role: "AUDITOR", MSPID: otherDomainAuditor.MSPID, Fingerprint: otherDomainAuditor.CertificateSHA256}},
		{"unapproved-auditor", mtls.Identity{Role: "AUDITOR", MSPID: "BMsp", Fingerprint: strings.Repeat("9", 64)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/operations/"+created.OperationID, nil)
			req.Header.Set("X-Caller-MSPID", owner.MSPID)
			req.Header.Set("X-Caller-Fingerprint", owner.CertificateSHA256)
			req = req.WithContext(mtls.WithIdentity(req.Context(), tc.id))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden)
			assert.NotContains(t, rec.Body.String(), created.OperationID)
			assert.NotContains(t, rec.Body.String(), "operationKey")
		})
	}

	// 10. GET /v1/operations/{unknown} -> 404 OPERATION_UNKNOWN.
	req = httptest.NewRequest(http.MethodGet, "/v1/operations/"+depID+"/does-not-exist", nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusNotFound, preg.ErrCodeOperationUnknown)

	// 11. Backend unavailable -> 503 STATE_UNAVAILABLE.
	fake.hasBackend = false
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", bytes.NewReader(inA))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "op-no-backend")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable)
}

func TestStatusForErrorMapping(t *testing.T) {
	cases := []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		{protocol.NewError(preg.ErrCodeInvalidSchema, "bad"), http.StatusBadRequest, preg.ErrCodeInvalidSchema},
		{protocol.NewError(preg.ErrCodeInvalidStructure, "bad"), http.StatusBadRequest, preg.ErrCodeInvalidStructure},
		{protocol.NewError(preg.ErrCodeIdentityManagementForbidden, "forbid"), http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden},
		{protocol.NewError(preg.ErrCodeTrustManagementForbidden, "forbid"), http.StatusForbidden, preg.ErrCodeTrustManagementForbidden},
		{protocol.NewError(preg.ErrCodeRecoveryProofInvalid, "bad proof"), http.StatusForbidden, preg.ErrCodeRecoveryProofInvalid},
		{protocol.NewError(preg.ErrCodeSignatureInvalid, "bad sig"), http.StatusForbidden, preg.ErrCodeSignatureInvalid},
		{protocol.NewError(preg.ErrCodeChallengeUnknown, "unknown"), http.StatusForbidden, preg.ErrCodeChallengeUnknown},
		{protocol.NewError(preg.ErrCodeChallengeReplay, "replay"), http.StatusForbidden, preg.ErrCodeChallengeReplay},
		{protocol.NewError(preg.ErrCodeChallengeMismatch, "mismatch"), http.StatusForbidden, preg.ErrCodeChallengeMismatch},
		{protocol.NewError(preg.ErrCodeChallengeExpired, "expired"), http.StatusForbidden, preg.ErrCodeChallengeExpired},
		{protocol.NewError(preg.ErrCodeOperationUnknown, "missing"), http.StatusNotFound, preg.ErrCodeOperationUnknown},
		{protocol.NewError(preg.ErrCodeIdempotencyConflict, "conflict"), http.StatusConflict, preg.ErrCodeIdempotencyConflict},
		{protocol.NewError(preg.ErrCodeStateChanged, "changed"), http.StatusConflict, preg.ErrCodeStateChanged},
		{protocol.NewError(preg.ErrCodePayloadTooLarge, "too large"), http.StatusRequestEntityTooLarge, preg.ErrCodePayloadTooLarge},
		{protocol.NewError(preg.ErrCodeUnsupportedMediaType, "bad media"), http.StatusUnsupportedMediaType, preg.ErrCodeUnsupportedMediaType},
		{protocol.NewError(preg.ErrCodeStateUnavailable, "down"), http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable},
		{errors.New("untyped transport failure"), http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable},
	}

	for _, tc := range cases {
		status, code := statusForError(tc.err)
		assert.Equal(t, tc.wantStatus, status, "err=%v", tc.err)
		assert.Equal(t, tc.wantCode, code, "err=%v", tc.err)
	}
}
