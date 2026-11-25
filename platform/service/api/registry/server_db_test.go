//go:build db

package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/ledger"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/platform/internal/testutil"
	preg "grad/protocol/registry"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

type stubDBBackend struct {
	revision    uint64
	exists      bool
	submitCalls int
	calls       chan string
}

func (b *stubDBBackend) CurrentRevision(context.Context, string, string) (uint64, bool, error) {
	return b.revision, b.exists, nil
}

func (b *stubDBBackend) SubmitAsync(
	_ context.Context,
	key, _ string,
	_ preg.Management,
	_ string,
	_ json.RawMessage,
	update domreg.OutcomeHandler,
) {
	b.submitCalls++
	if b.calls != nil {
		commit := &ledger.Outcome{
			Point:        ledger.Point{Number: 1, Hash: strings.Repeat("f", 64)},
			Index:        0,
			Code:         "VALID",
			ObservedPeer: "peer-c",
		}
		if err := update("COMMIT", "CONFIRMED", "unit-original-tx", commit, nil, false); err == nil {
			b.calls <- key
		}
	}
}

func TestServerDBBackedManagementAndOperationAPI(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()
	depID := strings.Repeat("d", 63) + "2"

	backend := &stubDBBackend{revision: 2, exists: true, calls: make(chan string, 4)}
	rootMgmt := preg.Management{MSPID: "TMsp", CertificateSHA256: strings.Repeat("f", 64)}
	owner := preg.Management{MSPID: "BMsp", CertificateSHA256: strings.Repeat("a", 64)}
	sameDomainAuditor := preg.Management{MSPID: "BMsp", CertificateSHA256: strings.Repeat("b", 64)}
	otherDomainAuditor := preg.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("c", 64)}

	svc := domreg.NewService(pool, depID, rootMgmt, backend)
	svc.SetOperationAuditors([]preg.Management{sameDomainAuditor, otherDomainAuditor})
	h := NewServer(svc).Handler()

	// 1. Stale expectedRevision -> 409 STATE_CHANGED.
	req := httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{"id":"did:web:b.local:u","expectedRevision":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "stale-1")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusConflict, preg.ErrCodeStateChanged)

	// 2. Non-root trust management -> 403 TRUST_MANAGEMENT_FORBIDDEN.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/SetDomainStatus", strings.NewReader(`{"domainId":"A","expectedRevision":2,"status":"SUSPENDED"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "trust-forbid")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, preg.ErrCodeTrustManagementForbidden)

	// 3. Valid POST -> 202 Accepted and async dispatch.
	inA := []byte(`{"id":"did:web:b.local:u","expectedRevision":2,"keyId":"k2","publicKey":"04` + strings.Repeat("1", 128) + `"}`)
	client := mtls.NewLocalClient(h, mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://c.local/v1/management/RotateIdentity", bytes.NewReader(inA))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Idempotency-Key", "run1/op-db-1")
	resp, err := client.Do(httpReq)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get(httpx.HeaderRequestID))
	var accepted domreg.OperationView
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&accepted))

	select {
	case key := <-backend.calls:
		assert.Equal(t, "run1/op-db-1", key)
	case <-time.After(2 * time.Second):
		t.Fatal("accepted HTTP operation was never dispatched")
	}

	// 4. Exact idempotency replay -> 202 original operationId; different payload -> 409 IDEMPOTENCY_CONFLICT.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", bytes.NewReader(inA))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "run1/op-db-1")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)
	var replay domreg.OperationView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &replay))
	assert.Equal(t, accepted.OperationID, replay.OperationID)

	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{"id":"did:web:b.local:u","expectedRevision":2,"keyId":"k3"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "run1/op-db-1")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusConflict, preg.ErrCodeIdempotencyConflict)

	// 5. GET /v1/operations/{id} for owner & same-MSP auditor -> 200 OK; unauthorized -> 403; unknown -> 404.
	req = httptest.NewRequest(http.MethodGet, "/v1/operations/"+accepted.OperationID, nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "AUDITOR", MSPID: sameDomainAuditor.MSPID, Fingerprint: sameDomainAuditor.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var view domreg.OperationView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	assert.Equal(t, "CONFIRMED", view.Status)
	assert.Equal(t, "unit-original-tx", view.TxID)

	req = httptest.NewRequest(http.MethodGet, "/v1/operations/"+accepted.OperationID, nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "AUDITOR", MSPID: otherDomainAuditor.MSPID, Fingerprint: otherDomainAuditor.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden)
	assert.NotContains(t, rec.Body.String(), accepted.OperationID)

	req = httptest.NewRequest(http.MethodGet, "/v1/operations/"+depID+":missing", nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusNotFound, preg.ErrCodeOperationUnknown)
}
