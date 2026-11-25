//go:build db

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/domain/policy"
	"grad/platform/core/domain/wallet"
	"grad/platform/core/ledger"
	"grad/platform/internal/testutil"
	"grad/protocol"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

func postTrustedContext(t *testing.T, h http.Handler, taskID string, now time.Time) {
	t.Helper()
	body, err := json.Marshal(domgw.ContextUpdateRequest{
		ExpectedContextVersion: 0,
		SourceID:               "risk-engine-1",
		ObservedAt:             now.Add(-10 * time.Second).Unix(),
		RiskLevel:              policy.RiskNormal,
		AccessDeadline:         now.Add(2 * time.Hour).Unix(),
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/v1/contexts/"+taskID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "seed context %s: %s", taskID, rec.Body.String())
}

func TestCentralStackEndToEndQuoteOrderResponseLossAndReconcile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db := testutil.OpenMigratedPool(t)
	inst, dep := newOfflineInstanceAndDeployment(t)

	f, err := PrepareFixtures(inst, dep, nil)
	require.NoError(t, err)

	// 1. Sync domain certifications and grant delivery packages into PostgreSQL outbox/receipt tables.
	report := &SeedReport{fixtureBody: f, Scope: "db-test"}
	require.NoError(t, SyncSeedDeliveries(ctx, inst, db, dep, report))

	var receiptCount int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM wallet_receipts WHERE deployment_id=$1`, dep.DeploymentID).Scan(&receiptCount))
	assert.GreaterOrEqual(t, receiptCount, 7)

	// 2. Start the full centralized Stack (core/dao/central + core/domain/{policy,registry,gateway,wallet} + service/api/gateway).
	stack, err := StartCentralGatewayStack(ctx, inst, db, dep, f)
	require.NoError(t, err)
	defer stack.Close()

	now := time.Now().UTC()
	postTrustedContext(t, stack.Gateway.Handler(), f.RPTask.ID, now)
	postTrustedContext(t, stack.Gateway.Handler(), f.BMTask.ID, now)

	// 3. Verify gateway readiness endpoint.
	readyReq := httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil)
	readyRec := httptest.NewRecorder()
	stack.Gateway.Handler().ServeHTTP(readyRec, readyReq)
	require.Equal(t, http.StatusOK, readyRec.Code, readyRec.Body.String())
	var readyBody map[string]any
	require.NoError(t, json.Unmarshal(readyRec.Body.Bytes(), &readyBody))
	assert.Equal(t, "READY", readyBody["status"])
	assert.Equal(t, ledger.SourceCentralized, readyBody["stateSource"])

	// 4. RP mode normal flow: B1 requests quote -> creates order -> COMPLETED.
	rpQuote, err := stack.Wallet.RequestQuote(ctx, wallet.RequestQuoteInput{
		Actor:             "B1",
		TaskID:            f.RPTask.ID,
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		ProductID:         domgw.DefaultProductID,
		Quantity:          1,
		IdempotencyKey:    "rp-quote-normal-01",
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", rpQuote.Decision, "error=%s %s", rpQuote.ErrorCode, rpQuote.ErrorMessage)
	require.NotEmpty(t, rpQuote.QuoteID)
	assert.Equal(t, domgw.DefaultProductPriceMinor, rpQuote.TotalAmountMinor)

	rpOrder, err := stack.Wallet.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor:             "B1",
		TaskID:            f.RPTask.ID,
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		QuoteID:           rpQuote.QuoteID,
		AmountMinor:       rpQuote.TotalAmountMinor,
		IdempotencyKey:    "rp-order-normal-01",
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", rpOrder.Decision, "error=%s %s", rpOrder.ErrorCode, rpOrder.ErrorMessage)
	assert.Equal(t, wallet.ActionStatusCompleted, rpOrder.ActionStatus)
	assert.NotEmpty(t, rpOrder.OrderID)

	// 5. Response-loss simulation on order.create followed by full C audit + outbox delivery + receipt reconciliation.
	var dropNextOrderExecute atomic.Bool
	dropHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/access/execute" && dropNextOrderExecute.CompareAndSwap(true, false) {
			// Let the real gateway commit the order transaction, then drop the HTTP response (502).
			sink := httptest.NewRecorder()
			stack.Gateway.Handler().ServeHTTP(sink, r)
			require.Equal(t, http.StatusOK, sink.Code, "underlying order commit must succeed before response loss")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"code":"GATEWAY_RESPONSE_LOST","message":"simulated response drop after commit"}`))
			return
		}
		stack.Gateway.Handler().ServeHTTP(w, r)
	})

	lossWallet, err := BuildWallet(ctx, inst, dep, f, db, dropHandler)
	require.NoError(t, err)

	lossQuote, err := lossWallet.RequestQuote(ctx, wallet.RequestQuoteInput{
		Actor:             "B1",
		TaskID:            f.RPTask.ID,
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		ProductID:         domgw.DefaultProductID,
		Quantity:          1,
		IdempotencyKey:    "rp-quote-loss-01",
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", lossQuote.Decision)

	dropNextOrderExecute.Store(true)
	lostOrder, err := lossWallet.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor:             "B1",
		TaskID:            f.RPTask.ID,
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		QuoteID:           lossQuote.QuoteID,
		AmountMinor:       lossQuote.TotalAmountMinor,
		IdempotencyKey:    "rp-order-loss-01",
	})
	require.NoError(t, err)
	assert.Equal(t, "UNKNOWN", lostOrder.Decision)
	assert.Equal(t, wallet.ActionStatusOutcomeUnknown, lostOrder.ActionStatus)
	assert.Empty(t, lostOrder.OrderID)

	// Reconcile the lost order: stop send (sendRevision=2) -> register case (B_RECOVERY) ->
	// C audit (C_AUDITOR) -> outbox delivery (domgw.DeliverReceiptWithDB -> interdomain.NewWalletReceiptHandler via C_AUDIT_SERVICE).
	reconciled, err := lossWallet.ReconcileOrder(ctx, wallet.ReconcileOrderInput{
		Actor:          "B1",
		TaskID:         f.RPTask.ID,
		IdempotencyKey: "rp-order-loss-01",
	})
	require.NoError(t, err)
	assert.Equal(t, "CREATED", reconciled.Outcome, "error=%s %s", reconciled.ErrorCode, reconciled.ErrorMessage)
	assert.Equal(t, wallet.ActionStatusReconciled, reconciled.ActionStatus)
	assert.Equal(t, int64(2), reconciled.SendRevision)
	assert.NotEmpty(t, reconciled.OrderID)
	assert.NotEmpty(t, reconciled.CreationDecisionID)

	// Verify durable PostgreSQL tables across both gateway (outbox) and wallet (client_actions + receipts).
	var deliveredAt *int64
	var attempts int64
	require.NoError(t, db.QueryRow(ctx, `SELECT delivered_at, attempts FROM order_outcome_outbox
		WHERE deployment_id=$1 AND case_id=$2 AND send_revision=$3 AND check_no=$4`,
		dep.DeploymentID, reconciled.CaseID, reconciled.SendRevision, reconciled.CheckNo,
	).Scan(&deliveredAt, &attempts))
	assert.NotNil(t, deliveredAt, "order_outcome_outbox must be marked delivered via domgw.DeliverReceiptWithDB")
	assert.Equal(t, int64(1), attempts)

	var receiptOutcome string
	require.NoError(t, db.QueryRow(ctx, `SELECT outcome FROM order_outcome_receipts
		WHERE deployment_id=$1 AND case_id=$2 AND send_revision=$3 AND check_no=$4`,
		dep.DeploymentID, reconciled.CaseID, reconciled.SendRevision, reconciled.CheckNo,
	).Scan(&receiptOutcome))
	assert.Equal(t, "CREATED", receiptOutcome)

	act, err := lossWallet.GetClientActionByKey(ctx, f.Identities["B1"].ID, f.RPTask.ID, protocol.ActionOrderCreate, "rp-order-loss-01")
	require.NoError(t, err)
	assert.Equal(t, wallet.ActionStatusReconciled, act.Status)
	assert.Equal(t, "CREATED", act.Outcome)
	assert.Equal(t, reconciled.OrderID, act.OrderID)

	// 6. BM mode (PA -> U -> A1 -> B1) end-to-end quote + order through the same real gateway stack.
	bmQuote, err := stack.Wallet.RequestQuote(ctx, wallet.RequestQuoteInput{
		Actor:             "B1",
		TaskID:            f.BMTask.ID,
		AuthorizationMode: protocol.ModeBuyerMandate,
		ProductID:         domgw.DefaultProductID,
		Quantity:          1,
		IdempotencyKey:    "bm-quote-normal-01",
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", bmQuote.Decision, "error=%s %s", bmQuote.ErrorCode, bmQuote.ErrorMessage)

	bmOrder, err := stack.Wallet.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor:             "B1",
		TaskID:            f.BMTask.ID,
		AuthorizationMode: protocol.ModeBuyerMandate,
		QuoteID:           bmQuote.QuoteID,
		AmountMinor:       bmQuote.TotalAmountMinor,
		IdempotencyKey:    "bm-order-normal-01",
	})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", bmOrder.Decision, "error=%s %s", bmOrder.ErrorCode, bmOrder.ErrorMessage)
	assert.Equal(t, wallet.ActionStatusCompleted, bmOrder.ActionStatus)
	assert.NotEmpty(t, bmOrder.OrderID)
}
