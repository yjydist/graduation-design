//go:build db

package registrysvc

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

	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/platform/internal/testutil"
	"grad/platform/state/fabric"
	"grad/protocol/registry"
)

func testCommit(number uint64, hash, code string) *fabric.Outcome {
	return &fabric.Outcome{Point: fabric.Point{Number: number, Hash: hash}, Index: 0, Code: code, ObservedPeer: "peer-c"}
}

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

type stubOpBackend struct {
	kind, id    string
	revision    uint64
	exists      bool
	revErr      error
	submitCalls int
}

func (b *stubOpBackend) CurrentRevision(_ context.Context, kind, id string) (uint64, bool, error) {
	b.kind, b.id = kind, id
	return b.revision, b.exists, b.revErr
}

func (b *stubOpBackend) SubmitAsync(
	context.Context,
	string, string,
	registry.Management,
	string,
	json.RawMessage,
	OutcomeHandler,
) {
	b.submitCalls++
}

type observedManagementBackend struct {
	calls    chan string
	blockKey string
	entered  chan struct{}
	release  chan struct{}
}

func (b *observedManagementBackend) CurrentRevision(context.Context, string, string) (uint64, bool, error) {
	return 2, true, nil
}

func (b *observedManagementBackend) SubmitAsync(
	ctx context.Context,
	key, _ string,
	_ registry.Management,
	_ string,
	_ json.RawMessage,
	update OutcomeHandler,
) {
	if key == b.blockKey {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			return
		}
	}
	code := "VALID"
	if err := update("COMMIT", "CONFIRMED", "unit-original-tx", testCommit(1, strings.Repeat("f", 64), code), nil, false); err == nil {
		b.calls <- key
	}
}

func TestEnsureSchema(t *testing.T) {
	pool := testutil.OpenTestPool(t)
	require.NoError(t, EnsureSchema(t.Context(), pool))
	// Idempotent second invocation.
	require.NoError(t, EnsureSchema(t.Context(), pool))
}

func TestOperationsAsyncStateMachineAndUnifiedErrors(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()
	depID := strings.Repeat("d", 63) + "1"

	backend := &stubOpBackend{revision: 2, exists: true}
	rootMgmt := registry.Management{MSPID: "TMsp", CertificateSHA256: strings.Repeat("f", 64)}
	caller := registry.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("a", 64)}
	svc := NewService(pool, depID, rootMgmt, backend)
	h := svc.Handler()

	// 1. Pre-acceptance stale expectedRevision -> 409 STATE_CHANGED with ZERO rows in operations.
	staleInput := json.RawMessage(`{"id":"did:web:a.local:u","expectedRevision":1}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", bytes.NewReader(staleInput))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "op-stale-1")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: caller.MSPID, Fingerprint: caller.CertificateSHA256}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusConflict, registry.ErrCodeStateChanged)
	assert.Equal(t, 0, backend.submitCalls)

	var opCount int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM operations WHERE deployment_id=$1`, depID).Scan(&opCount))
	assert.Equal(t, 0, opCount)

	// 2. Non-root caller on trust management method -> 403 TRUST_MANAGEMENT_FORBIDDEN.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/SetDomainStatus", strings.NewReader(`{"domainId":"A","expectedRevision":2,"status":"SUSPENDED"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "op-trust-forbid")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: caller.MSPID, Fingerprint: caller.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, registry.ErrCodeTrustManagementForbidden)

	// 3. Two distinct operationKeys both pass expectedRevision=2 -> both 202.
	inA := json.RawMessage(`{"id":"did:web:a.local:u","expectedRevision":2,"keyId":"k2","publicKey":"04` + strings.Repeat("1", 128) + `"}`)
	inB := json.RawMessage(`{"id":"did:web:a.local:u","expectedRevision":2,"keyId":"k3","publicKey":"04` + strings.Repeat("2", 128) + `"}`)
	c1, v1, err := svc.Accept(ctx, "run1/op-conc-1", caller, "RotateIdentity", inA, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, c1)
	require.NotEmpty(t, v1.OperationID)

	c2, v2, err := svc.Accept(ctx, "op-conc-2", caller, "RotateIdentity", inB, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, c2)

	c3, v3, err := svc.Accept(ctx, "op-conc-3", caller, "RotateIdentity", inB, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, c3)

	// 4. Exact idempotent retry -> 202 original operationId; mutated payload -> 409 IDEMPOTENCY_CONFLICT.
	c1Retry, v1Retry, err := svc.Accept(ctx, "run1/op-conc-1", caller, "RotateIdentity", inA, false)
	require.NoError(t, err)
	assert.Equal(t, http.StatusAccepted, c1Retry)
	assert.Equal(t, v1.OperationID, v1Retry.OperationID)

	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", bytes.NewReader(inB))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "run1/op-conc-1")
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: caller.MSPID, Fingerprint: caller.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusConflict, registry.ErrCodeIdempotencyConflict)

	// 5. Visibility suppression -> GET /v1/operations/{id} returns PENDING/null until restored.
	svc.SetVisibilitySuppressed(v1.OperationID, true)
	valCode := "VALID"
	blkHash := strings.Repeat("9", 64)
	require.NoError(t, svc.RecordOutcome(ctx, v1.OperationID, "COMMIT", "CONFIRMED", "tx-win-1", testCommit(10, blkHash, valCode), nil, true))

	// MVCC_READ_CONFLICT with nil failCode normalizes to STATE_CHANGED and never opens delivery.
	mvccCode := "MVCC_READ_CONFLICT"
	require.NoError(t, svc.RecordOutcome(ctx, v2.OperationID, "COMMIT", "FAILED", "tx-lose-2", testCommit(11, blkHash, mvccCode), nil, true))

	// Generic non-VALID commit normalizes to COMMIT_INVALID and never opens delivery.
	phantomCode := "PHANTOM_READ_CONFLICT"
	require.NoError(t, svc.RecordOutcome(ctx, v3.OperationID, "COMMIT", "FAILED", "tx-lose-3", testCommit(12, blkHash, phantomCode), nil, true))

	req = httptest.NewRequest(http.MethodGet, "/v1/operations/"+v1.OperationID, nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: caller.MSPID, Fingerprint: caller.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var pending map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pending))
	for _, key := range []string{"failureCode", "transactionIndex", "observedPeer"} {
		require.Contains(t, pending, key)
		assert.Nil(t, pending[key])
	}
	assert.NotContains(t, pending, "errorCode")
	var suppressedView OperationView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &suppressedView))
	assert.Equal(t, "PENDING", suppressedView.Status)
	assert.Nil(t, suppressedView.FailureCode)
	assert.Nil(t, suppressedView.ValidationCode)
	assert.Equal(t, int64(0), suppressedView.BlockNumber)
	assert.False(t, suppressedView.Delivered)

	// 6. Restore visibility and verify DUPLICATE_TXID never overwrites CONFIRMED or FAILED outcomes.
	svc.SetVisibilitySuppressed(v1.OperationID, false)
	dupVal := "DUPLICATE_TXID"
	dupFail := registry.ErrCodeCommitInvalid
	require.NoError(t, svc.RecordOutcome(ctx, v1.OperationID, "COMMIT", "FAILED", "tx-win-dup", testCommit(99, blkHash, dupVal), &dupFail, false))
	require.NoError(t, svc.RecordOutcome(ctx, v2.OperationID, "COMMIT", "FAILED", "tx-lose-dup", testCommit(99, blkHash, dupVal), &dupFail, false))
	require.NoError(t, svc.RecordOutcome(ctx, v2.OperationID, "COMMIT", "CONFIRMED", "tx-lose-override", testCommit(99, blkHash, valCode), nil, true))

	got1, err := svc.GetOperation(ctx, v1.OperationID)
	require.NoError(t, err)
	assert.Equal(t, "CONFIRMED", got1.Status)
	assert.Nil(t, got1.FailureCode)
	require.NotNil(t, got1.ValidationCode)
	assert.Equal(t, "VALID", *got1.ValidationCode)
	assert.Equal(t, "tx-win-1", got1.TxID)
	assert.Equal(t, int64(10), got1.BlockNumber)
	assert.True(t, got1.Delivered)

	got2, err := svc.GetOperation(ctx, v2.OperationID)
	require.NoError(t, err)
	assert.Equal(t, "FAILED", got2.Status)
	require.NotNil(t, got2.FailureCode)
	assert.Equal(t, registry.ErrCodeStateChanged, *got2.FailureCode)
	require.NotNil(t, got2.ValidationCode)
	assert.Equal(t, "MVCC_READ_CONFLICT", *got2.ValidationCode)
	assert.False(t, got2.Delivered)

	got3, err := svc.GetOperation(ctx, v3.OperationID)
	require.NoError(t, err)
	assert.Equal(t, "FAILED", got3.Status)
	require.NotNil(t, got3.FailureCode)
	assert.Equal(t, registry.ErrCodeCommitInvalid, *got3.FailureCode)
	assert.False(t, got3.Delivered)

	for _, view := range []*OperationView{got1, got2} {
		req := httptest.NewRequest(http.MethodGet, "/v1/operations/"+view.OperationID, nil)
		req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: caller.MSPID, Fingerprint: caller.CertificateSHA256}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		require.Contains(t, body, "failureCode")
		if view.Status == "FAILED" {
			assert.Equal(t, registry.ErrCodeStateChanged, body["failureCode"])
		} else {
			assert.Nil(t, body["failureCode"])
		}
		assert.Equal(t, float64(0), body["transactionIndex"])
		assert.Equal(t, "peer-c", body["observedPeer"])
		assert.NotContains(t, body, "errorCode")
	}

	// 7. Unknown operationId -> 404 OPERATION_UNKNOWN with unified error envelope.
	req = httptest.NewRequest(http.MethodGet, "/v1/operations/"+depID+":does-not-exist", nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: caller.MSPID, Fingerprint: caller.CertificateSHA256}))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusNotFound, registry.ErrCodeOperationUnknown)
}

func TestManagementOperationScopeCanonicalRetryAndReplacement(t *testing.T) {
	ctx := t.Context()
	db := testutil.OpenMigratedPool(t)
	backend := &stubOpBackend{revision: 2, exists: true}
	svc := NewService(db, strings.Repeat("d", 64), registry.Management{}, backend)
	a := registry.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("a", 64)}
	b := registry.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("b", 64)}
	const key = "procurement/1"
	input := json.RawMessage(`{"id":"g","expectedRevision":2}`)
	accept := func(caller registry.Management, method string, input json.RawMessage) string {
		t.Helper()
		status, view, err := svc.Accept(ctx, key, caller, method, input, false)
		require.NoError(t, err)
		require.Equal(t, http.StatusAccepted, status)
		return view.OperationID
	}
	id := accept(a, "SuspendGrant", input)
	require.Equal(t, id, accept(a, "SuspendGrant", json.RawMessage(`{"expectedRevision":2, "id":"g"}`)))
	otherMethod := accept(a, "ResumeGrant", input)
	otherCaller := accept(b, "SuspendGrant", input)
	require.NotEqual(t, id, otherMethod)
	require.NotEqual(t, id, otherCaller)
	require.NotEqual(t, otherMethod, otherCaller)

	target := func(revision uint64) json.RawMessage {
		input, err := json.Marshal(registry.Replacement{Old: registry.Mutation{ID: "original-grant", ExpectedRevision: revision}})
		require.NoError(t, err)
		return input
	}
	status, _, err := svc.Accept(ctx, key, a, "ReplaceGrant", target(1), true)
	require.True(t, registry.HasCode(err, registry.ErrCodeStateChanged))
	require.Equal(t, http.StatusConflict, status)
	assert.Zero(t, backend.submitCalls)
	assert.Equal(t, "grant", backend.kind)
	assert.Equal(t, "original-grant", backend.id)
	var count int
	require.NoError(t, db.QueryRow(ctx, "SELECT count(*) FROM operations WHERE method='ReplaceGrant'").Scan(&count))
	require.Zero(t, count)
	accept(a, "ReplaceGrant", target(2))
}

func TestOperationsMTLSAndAuditorScoping(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	dep := registry.Digest([]byte(t.Name()))
	svc := NewService(pool, dep, registry.Management{}, &stubOpBackend{revision: 1, exists: true})

	owner := registry.Management{MSPID: "BMsp", CertificateSHA256: strings.Repeat("a", 64)}
	sameDomainAuditor := registry.Management{MSPID: "BMsp", CertificateSHA256: strings.Repeat("b", 64)}
	otherDomainAuditor := registry.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("c", 64)}
	svc.SetOperationAuditors([]registry.Management{sameDomainAuditor, otherDomainAuditor})

	_, view, err := svc.Accept(t.Context(), "private", owner, "RotateIdentity", json.RawMessage(`{"id":"b1","expectedRevision":1}`), false)
	require.NoError(t, err)

	cases := []struct {
		name     string
		identity mtls.Identity
		code     int
	}{
		{"owner", mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}, http.StatusOK},
		{"approved-auditor", mtls.Identity{Role: "AUDITOR", MSPID: sameDomainAuditor.MSPID, Fingerprint: sameDomainAuditor.CertificateSHA256}, http.StatusOK},
		{"unauthenticated", mtls.Identity{}, http.StatusForbidden},
		{"other-same-domain-manager", mtls.Identity{Role: "MANAGEMENT", MSPID: "BMsp", Fingerprint: strings.Repeat("d", 64)}, http.StatusForbidden},
		{"other-domain-manager", mtls.Identity{Role: "MANAGEMENT", MSPID: "AMsp", Fingerprint: strings.Repeat("e", 64)}, http.StatusForbidden},
		{"cross-domain-auditor", mtls.Identity{Role: "AUDITOR", MSPID: otherDomainAuditor.MSPID, Fingerprint: otherDomainAuditor.CertificateSHA256}, http.StatusForbidden},
		{"unapproved-auditor", mtls.Identity{Role: "AUDITOR", MSPID: "BMsp", Fingerprint: strings.Repeat("f", 64)}, http.StatusForbidden},
	}

	h := svc.Handler()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/operations/"+view.OperationID, nil)
			// Self-asserted headers must always be ignored.
			req.Header.Set("X-Caller-MSPID", owner.MSPID)
			req.Header.Set("X-Caller-Fingerprint", owner.CertificateSHA256)
			req.Header.Set("X-Caller-Role", "AUDITOR")
			if tc.identity.Role != "" {
				req = req.WithContext(mtls.WithIdentity(req.Context(), tc.identity))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if tc.code == http.StatusForbidden {
				assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, registry.ErrCodeIdentityManagementForbidden)
				assert.NotContains(t, rec.Body.String(), "operationKey")
				assert.NotContains(t, rec.Body.String(), view.OperationID)
			} else {
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			}
		})
	}

	for _, state := range []string{"PENDING", "CONFIRMED", "FAILED"} {
		_, err := pool.Exec(t.Context(), `UPDATE operations SET status=$2 WHERE deployment_id=$1`, dep, state)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, "/v1/operations/"+view.OperationID, nil)
		req = req.WithContext(mtls.WithIdentity(req.Context(), mtls.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.CertificateSHA256}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var got OperationView
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		assert.Equal(t, state, got.Status)
	}
}

func TestOperationsHTTPDispatchCrashResumeAndNonBlocking(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()
	depID := strings.Repeat("8", 64)

	b := &observedManagementBackend{calls: make(chan string, 4)}
	caller := registry.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("a", 64)}
	svc := NewService(pool, depID, registry.Management{}, b)
	raw := []byte(`{"id":"did:web:a.local:u","expectedRevision":2}`)

	// Self-asserted management headers rejected with 403 unified envelope.
	req := httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "http-submit")
	req.Header.Set("X-Caller-MSPID", caller.MSPID)
	req.Header.Set("X-Caller-Fingerprint", caller.CertificateSHA256)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, registry.ErrCodeIdentityManagementForbidden)

	// Verified in-process mTLS local client dispatches asynchronously.
	client := mtls.NewLocalClient(svc.Handler(), mtls.Identity{Role: "MANAGEMENT", MSPID: caller.MSPID, Fingerprint: caller.CertificateSHA256})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://c.local/v1/management/RotateIdentity", bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "http-submit")
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get(httpx.HeaderRequestID))

	select {
	case key := <-b.calls:
		assert.Equal(t, "http-submit", key)
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP never dispatched accepted request")
	}

	// Simulate crash before dispatch, then recover via restarted Service.ResumePending.
	code, v, err := svc.Accept(ctx, "restart-queued", caller, "RotateIdentity", raw, false)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, code)

	restarted := NewService(pool, depID, registry.Management{}, b)
	require.NoError(t, restarted.ResumePending(ctx))

	got, err := restarted.GetOperation(ctx, v.OperationID)
	require.NoError(t, err)
	assert.Equal(t, "CONFIRMED", got.Status)
	assert.Equal(t, "unit-original-tx", got.TxID)

	code, retry, err := restarted.Accept(ctx, "restart-queued", caller, "RotateIdentity", raw, true)
	require.NoError(t, err)
	assert.Equal(t, http.StatusAccepted, code)
	assert.Equal(t, got.TxID, retry.TxID)

	// Blocked pending operation must not block unrelated pending recovery.
	depID2 := strings.Repeat("7", 64)
	blockBackend := &observedManagementBackend{
		calls:    make(chan string, 2),
		blockKey: "a-invisible",
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	svc2 := NewService(pool, depID2, registry.Management{}, blockBackend)
	for _, key := range []string{"a-invisible", "b-independent"} {
		c, _, err := svc2.Accept(ctx, key, caller, "RotateIdentity", json.RawMessage(`{"id":"u","expectedRevision":2}`), false)
		require.NoError(t, err)
		require.Equal(t, http.StatusAccepted, c)
	}
	done := make(chan error, 1)
	go func() { done <- svc2.ResumePending(ctx) }()
	<-blockBackend.entered
	select {
	case key := <-blockBackend.calls:
		assert.Equal(t, "b-independent", key)
	case <-time.After(2 * time.Second):
		close(blockBackend.release)
		t.Fatal("unavailable original transaction blocked unrelated recovery")
	}
	close(blockBackend.release)
	require.NoError(t, <-done)

	// RunRecovery runs continuously and exits cleanly on cancellation.
	runCtx, cancel := context.WithCancel(ctx)
	runDone := make(chan error, 1)
	go func() { runDone <- restarted.RunRecovery(runCtx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	assert.ErrorIs(t, <-runDone, context.Canceled)
}
