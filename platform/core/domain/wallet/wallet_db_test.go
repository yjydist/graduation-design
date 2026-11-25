//go:build db

package wallet_test

import (
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/domain/wallet"
	"grad/platform/internal/testutil"
	"grad/protocol"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

func TestDBCreateOrderPreSendIntentLockAndResponseLossReconciliation(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()

	fx := newUnitFixture(t, func(cfg *wallet.WalletConfig) {
		cfg.DB = pool
	})

	g2ID := protocol.DigestBytes([]byte("db-g2-b1"))
	_, err := fx.wallet.DelegateGrant(ctx, wallet.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID, GrantID: g2ID,
		TaskID: fx.taskID, AuthorizationMode: protocol.ModeBuyerMandate,
		MaxAmountMinor: 100000, RemainingDepth: 0,
	})
	require.NoError(t, err)

	q, err := fx.wallet.RequestQuote(ctx, wallet.RequestQuoteInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, ProductID: "urn:grad:product:P1", Quantity: 1,
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", q.Decision)

	// 1. Verify pre-send OUTCOME_UNKNOWN intent lock is persisted in PostgreSQL BEFORE gateway receives the challenge request.
	lostKey := "db-pre-send-lost-1"
	var sawPreSendRow atomic.Bool
	fx.gw.onChallenge = func(req wallet.ChallengeRequest) {
		if req.TaskID != fx.taskID || req.Actor != fx.didB1 {
			return
		}
		rec, gErr := fx.wallet.GetClientActionByKey(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, lostKey)
		if gErr == nil && rec != nil &&
			rec.Status == wallet.ActionStatusOutcomeUnknown &&
			rec.SendRevision == 1 &&
			rec.RequestHash == req.RequestHash &&
			rec.IdempotencyKey == lostKey {
			sawPreSendRow.Store(true)
		}
	}
	fx.gw.mu.Lock()
	fx.gw.failExecuteOnce[lostKey] = true
	fx.gw.mu.Unlock()

	ordResp, err := fx.wallet.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor: "B1", GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: protocol.ModeBuyerMandate, QuoteID: q.QuoteID,
		AmountMinor: 80000, IdempotencyKey: lostKey,
	})
	require.NoError(t, err)
	assert.True(t, sawPreSendRow.Load(), "client_actions row MUST exist with OUTCOME_UNKNOWN and sendRevision=1 before contacting gateway")
	assert.Equal(t, "UNKNOWN", ordResp.Decision)
	assert.Equal(t, wallet.ActionStatusOutcomeUnknown, ordResp.ActionStatus)
	assert.Equal(t, int64(1), ordResp.SendRevision)

	// Verify BeginClientAction rejects conflicting requestHash for the same idempotencyKey.
	_, conflictErr := fx.wallet.BeginClientAction(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, lostKey, protocol.DigestBytes([]byte("different-request")), "{}")
	require.Error(t, conflictErr)
	assert.True(t, protocol.HasCode(conflictErr, protocol.ErrCodeIdempotencyConflict))

	// 2. Reconcile order: stops delayed worker via sendRevision++, registers case, audits C, applies CREATED receipt.
	recOut, err := fx.wallet.ReconcileOrder(ctx, wallet.ReconcileOrderInput{
		Actor: "B1", TaskID: fx.taskID, IdempotencyKey: lostKey,
	})
	require.NoError(t, err)
	assert.Equal(t, "CREATED", recOut.Outcome)
	assert.Equal(t, "MATCHED", recOut.HistoricalStatus)
	assert.Equal(t, int64(2), recOut.SendRevision)
	assert.Equal(t, wallet.ActionStatusReconciled, recOut.ActionStatus)
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
	assert.Equal(t, wallet.ActionStatusReconciled, dbAction.Status)
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

	fx := newUnitFixture(t, func(cfg *wallet.WalletConfig) {
		cfg.DB = pool
	})

	// Seed an OUTCOME_UNKNOWN intent and stop send (sendRevision -> 2, case_id assigned).
	reqHash := protocol.DigestBytes([]byte("db-receipt-semantics-req"))
	act, err := fx.wallet.BeginClientAction(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-sem-key-1", reqHash, `{"idempotencyKey":"db-sem-key-1"}`)
	require.NoError(t, err)
	assert.Equal(t, wallet.ActionStatusOutcomeUnknown, act.Status)
	assert.Equal(t, int64(1), act.SendRevision)

	caseID := "urn:grad:case:db-semantics-1"
	stopped, err := fx.wallet.StopClientActionSend(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-sem-key-1", caseID, "")
	require.NoError(t, err)
	assert.Equal(t, int64(2), stopped.SendRevision)
	assert.Equal(t, caseID, stopped.CaseID)

	// 1. Stale sendRevision (1 != 2) MUST be flagged STALE_SEND_REVISION and MUST NOT mutate client_actions.
	staleOrderID := "urn:grad:order:stale"
	staleResp, err := fx.wallet.ApplyOrderOutcomeReceipt(ctx, wallet.OrderOutcomeReceipt{
		CaseID: caseID, CheckNo: 1, SendRevision: 1, DeploymentID: fx.depID,
		Actor: fx.didB1, TaskID: fx.taskID, RequestHash: reqHash,
		Outcome: "CREATED", OrderID: &staleOrderID, HistoricalStatus: "MATCHED", AuditAt: fx.now.Unix(),
	})
	require.NoError(t, err)
	assert.Equal(t, "STALE_SEND_REVISION", staleResp.Status)
	assert.Equal(t, wallet.ActionStatusOutcomeUnknown, staleResp.ClientActionStatus)

	cur, err := fx.wallet.GetClientActionByKey(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-sem-key-1")
	require.NoError(t, err)
	assert.Equal(t, wallet.ActionStatusOutcomeUnknown, cur.Status)
	assert.Empty(t, cur.OrderID)

	// 2. UNKNOWN receipt (check_no=1, send_revision=2) records outcome='UNKNOWN' and keeps status=OUTCOME_UNKNOWN.
	unkReceipt := wallet.OrderOutcomeReceipt{
		CaseID: caseID, CheckNo: 1, SendRevision: 2, DeploymentID: fx.depID,
		Actor: fx.didB1, TaskID: fx.taskID, RequestHash: reqHash,
		Outcome: "UNKNOWN", HistoricalStatus: "NO_DECISION", AuditAt: fx.now.Unix(),
	}
	unkResp, err := fx.wallet.ApplyOrderOutcomeReceipt(ctx, unkReceipt)
	require.NoError(t, err)
	assert.Equal(t, "UNKNOWN", unkResp.Status)
	assert.Equal(t, wallet.ActionStatusOutcomeUnknown, unkResp.ClientActionStatus)

	// 3. Exact duplicate receipt replay returns IDEMPOTENT_REPLAY.
	replayResp, err := fx.wallet.ApplyOrderOutcomeReceipt(ctx, unkReceipt)
	require.NoError(t, err)
	assert.Equal(t, "IDEMPOTENT_REPLAY", replayResp.Status)
	assert.Equal(t, wallet.ActionStatusOutcomeUnknown, replayResp.ClientActionStatus)

	// 4. Same (case_id, send_revision, check_no) with conflicting content returns IDEMPOTENCY_CONFLICT.
	conflictOrderID := "urn:grad:order:conflict"
	_, err = fx.wallet.ApplyOrderOutcomeReceipt(ctx, wallet.OrderOutcomeReceipt{
		CaseID: caseID, CheckNo: 1, SendRevision: 2, DeploymentID: fx.depID,
		Actor: fx.didB1, TaskID: fx.taskID, RequestHash: reqHash,
		Outcome: "CREATED", OrderID: &conflictOrderID, HistoricalStatus: "MATCHED", AuditAt: fx.now.Unix(),
	})
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeIdempotencyConflict))

	// 5. NOT_CREATED receipt (check_no=2, send_revision=2) transitions client_actions to RECONCILED.
	notCreatedResp, err := fx.wallet.ApplyOrderOutcomeReceipt(ctx, wallet.OrderOutcomeReceipt{
		CaseID: caseID, CheckNo: 2, SendRevision: 2, DeploymentID: fx.depID,
		Actor: fx.didB1, TaskID: fx.taskID, RequestHash: reqHash,
		Outcome: "NOT_CREATED", HistoricalStatus: "NO_DECISION", AuditAt: fx.now.Unix() + 10,
	})
	require.NoError(t, err)
	assert.Equal(t, "RECONCILED", notCreatedResp.Status)
	assert.Equal(t, wallet.ActionStatusReconciled, notCreatedResp.ClientActionStatus)

	cur, err = fx.wallet.GetClientActionByKey(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-sem-key-1")
	require.NoError(t, err)
	assert.Equal(t, wallet.ActionStatusReconciled, cur.Status)
	assert.Equal(t, "NOT_CREATED", cur.Outcome)
	assert.Empty(t, cur.OrderID)

	// 6. Late UNKNOWN receipt (check_no=3, send_revision=2) MUST NOT reopen already-finalized RECONCILED intent!
	lateUnkResp, err := fx.wallet.ApplyOrderOutcomeReceipt(ctx, wallet.OrderOutcomeReceipt{
		CaseID: caseID, CheckNo: 3, SendRevision: 2, DeploymentID: fx.depID,
		Actor: fx.didB1, TaskID: fx.taskID, RequestHash: reqHash,
		Outcome: "UNKNOWN", HistoricalStatus: "NO_DECISION", AuditAt: fx.now.Unix() + 20,
	})
	require.NoError(t, err)
	assert.Equal(t, "ALREADY_FINALIZED", lateUnkResp.Status)
	assert.Equal(t, wallet.ActionStatusReconciled, lateUnkResp.ClientActionStatus)

	afterLate, err := fx.wallet.GetClientActionByKey(ctx, fx.didB1, fx.taskID, protocol.ActionOrderCreate, "db-sem-key-1")
	require.NoError(t, err)
	assert.Equal(t, wallet.ActionStatusReconciled, afterLate.Status)
	assert.Equal(t, "NOT_CREATED", afterLate.Outcome, "late UNKNOWN receipt must never overwrite finalized outcome")
}

func TestDBBoundQuotePersistenceViaDAO(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()

	fx := newUnitFixture(t, func(cfg *wallet.WalletConfig) {
		cfg.DB = pool
	})

	g2ID := protocol.DigestBytes([]byte("db-bound-g2"))
	_, err := fx.wallet.DelegateGrant(ctx, wallet.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID, GrantID: g2ID,
		TaskID: fx.taskID, AuthorizationMode: protocol.ModeBuyerMandate,
		MaxAmountMinor: 100000, RemainingDepth: 0,
	})
	require.NoError(t, err)

	scope := wallet.ExecutionBinding{
		DeploymentID: fx.depID, DomainID: "A", Actor: "B1", DID: fx.didB1, TaskID: fx.taskID,
		Mode: protocol.ModeBuyerMandate, GrantID: g2ID, Stage: wallet.StageExecute, RunID: "db-run-1",
		ProductID: "urn:grad:product:P1", Quantity: 1,
	}
	ops, err := wallet.NewBoundOperations(fx.wallet, scope)
	require.NoError(t, err)

	q, err := ops.RequestQuote(ctx, wallet.RequestQuoteInput{})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", q.Decision)

	// Verify wallet_bound_quotes persisted via DAO and rejects mismatched quote ID.
	_, err = ops.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor: "B1", TaskID: fx.taskID, QuoteID: "urn:grad:quote:other",
		AuthorizationMode: protocol.ModeBuyerMandate, AmountMinor: q.TotalAmountMinor,
		IdempotencyKey: ops.OrderKey(),
	})
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeBindingMismatch))

	// Valid bound quote succeeds and creates order.
	ord, err := ops.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor: "B1", TaskID: fx.taskID, QuoteID: q.QuoteID,
		AuthorizationMode: protocol.ModeBuyerMandate, AmountMinor: q.TotalAmountMinor,
		IdempotencyKey: ops.OrderKey(),
	})
	require.NoError(t, err)
	assert.Equal(t, "ALLOW", ord.Decision)
	assert.Equal(t, q.TotalAmountMinor, ord.TotalAmountMinor)
}
