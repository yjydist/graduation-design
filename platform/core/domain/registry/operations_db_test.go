//go:build db

package registry

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/ledger"
	"grad/platform/internal/testutil"
	"grad/protocol"
	preg "grad/protocol/registry"
)

func testCommit(number uint64, hash, code string) *ledger.Outcome {
	return &ledger.Outcome{Point: ledger.Point{Number: number, Hash: hash}, Index: 0, Code: code, ObservedPeer: "peer-c"}
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
	preg.Management,
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
	_ preg.Management,
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

func TestOperationsAsyncStateMachineAndTypedErrors(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()
	depID := strings.Repeat("d", 63) + "1"

	backend := &stubOpBackend{revision: 2, exists: true}
	rootMgmt := preg.Management{MSPID: "TMsp", CertificateSHA256: strings.Repeat("f", 64)}
	caller := preg.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("a", 64)}
	svc := NewService(pool, depID, rootMgmt, backend)

	// 0. Missing opKey or method -> INVALID_SCHEMA; malformed JSON -> INVALID_SCHEMA.
	_, err := svc.Accept(ctx, "", caller, "RotateIdentity", json.RawMessage(`{}`), false)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeInvalidSchema))
	_, err = svc.Accept(ctx, "op-bad-json", caller, "RotateIdentity", json.RawMessage(`{"broken":`), false)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeInvalidSchema))

	// 1. Pre-acceptance stale expectedRevision -> STATE_CHANGED with ZERO rows in operations.
	staleInput := json.RawMessage(`{"id":"did:web:a.local:u","expectedRevision":1}`)
	_, err = svc.Accept(ctx, "op-stale-1", caller, "RotateIdentity", staleInput, true)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeStateChanged))
	assert.Equal(t, 0, backend.submitCalls)

	var opCount int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM operations WHERE deployment_id=$1`, depID).Scan(&opCount))
	assert.Equal(t, 0, opCount)

	// 2. Non-root caller on trust management method -> TRUST_MANAGEMENT_FORBIDDEN.
	_, err = svc.Accept(ctx, "op-trust-forbid", caller, "SetDomainStatus",
		json.RawMessage(`{"domainId":"A","expectedRevision":2,"status":"SUSPENDED"}`), true)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeTrustManagementForbidden))

	// 3. Distinct operationKeys passing expectedRevision=2 -> all accepted.
	inA := json.RawMessage(`{"id":"did:web:a.local:u","expectedRevision":2,"keyId":"k2","publicKey":"04` + strings.Repeat("1", 128) + `"}`)
	inB := json.RawMessage(`{"id":"did:web:a.local:u","expectedRevision":2,"keyId":"k3","publicKey":"04` + strings.Repeat("2", 128) + `"}`)
	v1, err := svc.Accept(ctx, "run1/op-conc-1", caller, "RotateIdentity", inA, false)
	require.NoError(t, err)
	require.NotEmpty(t, v1.OperationID)

	v2, err := svc.Accept(ctx, "op-conc-2", caller, "RotateIdentity", inB, false)
	require.NoError(t, err)

	v3, err := svc.Accept(ctx, "op-conc-3", caller, "RotateIdentity", inB, false)
	require.NoError(t, err)

	// 4. Exact idempotent retry -> original operationId; mutated payload -> IDEMPOTENCY_CONFLICT.
	v1Retry, err := svc.Accept(ctx, "run1/op-conc-1", caller, "RotateIdentity", inA, false)
	require.NoError(t, err)
	assert.Equal(t, v1.OperationID, v1Retry.OperationID)

	_, err = svc.Accept(ctx, "run1/op-conc-1", caller, "RotateIdentity", inB, false)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeIdempotencyConflict))

	// 5. Visibility suppression -> Operation/GetOperation returns PENDING/null until restored.
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

	suppressedView, err := svc.Operation(ctx, caller, v1.OperationID)
	require.NoError(t, err)
	assert.Equal(t, "PENDING", suppressedView.Status)
	assert.Nil(t, suppressedView.FailureCode)
	assert.Nil(t, suppressedView.ValidationCode)
	assert.Nil(t, suppressedView.TransactionIndex)
	assert.Nil(t, suppressedView.ObservedPeer)
	assert.Equal(t, int64(0), suppressedView.BlockNumber)
	assert.False(t, suppressedView.Delivered)

	// 6. Restore visibility and verify DUPLICATE_TXID never overwrites CONFIRMED or FAILED outcomes.
	svc.SetVisibilitySuppressed(v1.OperationID, false)
	dupVal := "DUPLICATE_TXID"
	dupFail := preg.ErrCodeCommitInvalid
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
	require.NotNil(t, got1.TransactionIndex)
	assert.Equal(t, 0, *got1.TransactionIndex)
	require.NotNil(t, got1.ObservedPeer)
	assert.Equal(t, "peer-c", *got1.ObservedPeer)
	assert.True(t, got1.Delivered)

	got2, err := svc.GetOperation(ctx, v2.OperationID)
	require.NoError(t, err)
	assert.Equal(t, "FAILED", got2.Status)
	require.NotNil(t, got2.FailureCode)
	assert.Equal(t, preg.ErrCodeStateChanged, *got2.FailureCode)
	require.NotNil(t, got2.ValidationCode)
	assert.Equal(t, "MVCC_READ_CONFLICT", *got2.ValidationCode)
	assert.False(t, got2.Delivered)

	got3, err := svc.GetOperation(ctx, v3.OperationID)
	require.NoError(t, err)
	assert.Equal(t, "FAILED", got3.Status)
	require.NotNil(t, got3.FailureCode)
	assert.Equal(t, preg.ErrCodeCommitInvalid, *got3.FailureCode)
	assert.False(t, got3.Delivered)

	// 7. Unknown operationId -> OPERATION_UNKNOWN.
	_, err = svc.Operation(ctx, caller, depID+":does-not-exist")
	assert.True(t, protocol.HasCode(err, preg.ErrCodeOperationUnknown))
}

func TestManagementOperationScopeCanonicalRetryAndReplacement(t *testing.T) {
	ctx := t.Context()
	db := testutil.OpenMigratedPool(t)
	backend := &stubOpBackend{revision: 2, exists: true}
	svc := NewService(db, strings.Repeat("d", 64), preg.Management{}, backend)
	a := preg.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("a", 64)}
	b := preg.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("b", 64)}
	const key = "procurement/1"
	input := json.RawMessage(`{"id":"g","expectedRevision":2}`)
	accept := func(caller preg.Management, method string, input json.RawMessage) string {
		t.Helper()
		view, err := svc.Accept(ctx, key, caller, method, input, false)
		require.NoError(t, err)
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
		input, err := json.Marshal(preg.Replacement{Old: preg.Mutation{ID: "original-grant", ExpectedRevision: revision}})
		require.NoError(t, err)
		return input
	}
	_, err := svc.Accept(ctx, key, a, "ReplaceGrant", target(1), true)
	require.True(t, preg.HasCode(err, preg.ErrCodeStateChanged))
	assert.Zero(t, backend.submitCalls)
	assert.Equal(t, "grant", backend.kind)
	assert.Equal(t, "original-grant", backend.id)
	var count int
	require.NoError(t, db.QueryRow(ctx, "SELECT count(*) FROM operations WHERE method='ReplaceGrant'").Scan(&count))
	require.Zero(t, count)
	accept(a, "ReplaceGrant", target(2))
}

func TestOperationsCallerAndAuditorScoping(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	dep := preg.Digest([]byte(t.Name()))
	svc := NewService(pool, dep, preg.Management{}, &stubOpBackend{revision: 1, exists: true})

	owner := preg.Management{MSPID: "BMsp", CertificateSHA256: strings.Repeat("a", 64)}
	sameDomainAuditor := preg.Management{MSPID: "BMsp", CertificateSHA256: strings.Repeat("b", 64)}
	otherDomainAuditor := preg.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("c", 64)}
	svc.SetOperationAuditors([]preg.Management{sameDomainAuditor, otherDomainAuditor})

	assert.True(t, svc.IsOperationAuditor(sameDomainAuditor.CertificateSHA256, sameDomainAuditor.MSPID))
	assert.True(t, svc.IsOperationAuditor(otherDomainAuditor.CertificateSHA256, otherDomainAuditor.MSPID))
	assert.False(t, svc.IsOperationAuditor(owner.CertificateSHA256, owner.MSPID))

	view, err := svc.Accept(t.Context(), "private", owner, "RotateIdentity", json.RawMessage(`{"id":"b1","expectedRevision":1}`), false)
	require.NoError(t, err)

	cases := []struct {
		name      string
		caller    preg.Management
		forbidden bool
	}{
		{"owner", owner, false},
		{"approved-auditor", sameDomainAuditor, false},
		{"invalid-empty", preg.Management{}, true},
		{"other-same-domain-manager", preg.Management{MSPID: "BMsp", CertificateSHA256: strings.Repeat("d", 64)}, true},
		{"other-domain-manager", preg.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("e", 64)}, true},
		{"cross-domain-auditor", otherDomainAuditor, true},
		{"unapproved-auditor", preg.Management{MSPID: "BMsp", CertificateSHA256: strings.Repeat("f", 64)}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.Operation(t.Context(), tc.caller, view.OperationID)
			if tc.forbidden {
				assert.True(t, protocol.HasCode(err, preg.ErrCodeIdentityManagementForbidden))
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, view.OperationID, got.OperationID)
			}
		})
	}

	for _, state := range []string{"PENDING", "CONFIRMED", "FAILED"} {
		_, err := pool.Exec(t.Context(), `UPDATE operations SET status=$2 WHERE deployment_id=$1`, dep, state)
		require.NoError(t, err)
		got, err := svc.Operation(t.Context(), owner, view.OperationID)
		require.NoError(t, err)
		assert.Equal(t, state, got.Status)
	}
}

func TestOperationsAsyncDispatchCrashResumeAndNonBlocking(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()
	depID := strings.Repeat("8", 64)

	b := &observedManagementBackend{calls: make(chan string, 4)}
	caller := preg.Management{MSPID: "AMsp", CertificateSHA256: strings.Repeat("a", 64)}
	svc := NewService(pool, depID, preg.Management{}, b)
	raw := []byte(`{"id":"did:web:a.local:u","expectedRevision":2}`)

	// Invalid caller rejected on Submit.
	_, err := svc.Submit(ctx, preg.Management{}, "RotateIdentity", "bad-caller", json.RawMessage(raw))
	assert.True(t, protocol.HasCode(err, preg.ErrCodeIdentityManagementForbidden))

	// Accepted request with triggerBackend=true dispatches asynchronously.
	submitted, err := svc.Accept(ctx, "async-submit", caller, "RotateIdentity", raw, true)
	require.NoError(t, err)
	assert.Equal(t, "PENDING", submitted.Status)

	select {
	case key := <-b.calls:
		assert.Equal(t, "async-submit", key)
	case <-time.After(2 * time.Second):
		t.Fatal("accepted request was never dispatched asynchronously")
	}

	// Simulate crash before dispatch, then recover via restarted Service.ResumePending.
	v, err := svc.Accept(ctx, "restart-queued", caller, "RotateIdentity", raw, false)
	require.NoError(t, err)

	restarted := NewService(pool, depID, preg.Management{}, b)
	require.NoError(t, restarted.ResumePending(ctx))

	got, err := restarted.GetOperation(ctx, v.OperationID)
	require.NoError(t, err)
	assert.Equal(t, "CONFIRMED", got.Status)
	assert.Equal(t, "unit-original-tx", got.TxID)

	retry, err := restarted.Accept(ctx, "restart-queued", caller, "RotateIdentity", raw, true)
	require.NoError(t, err)
	assert.Equal(t, got.TxID, retry.TxID)

	// Blocked pending operation must not block unrelated pending recovery.
	depID2 := strings.Repeat("7", 64)
	blockBackend := &observedManagementBackend{
		calls:    make(chan string, 2),
		blockKey: "a-invisible",
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	svc2 := NewService(pool, depID2, preg.Management{}, blockBackend)
	for _, key := range []string{"a-invisible", "b-independent"} {
		_, err := svc2.Accept(ctx, key, caller, "RotateIdentity", json.RawMessage(`{"id":"u","expectedRevision":2}`), false)
		require.NoError(t, err)
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
