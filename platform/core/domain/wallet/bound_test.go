package wallet_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/domain/wallet"
	"grad/protocol"
)

func TestBoundOperationsEnforceScopeAndOrderEffects(t *testing.T) {
	fx := newUnitFixture(t, nil)
	ctx := t.Context()
	const productID = "urn:grad:product:P1"
	const mode = protocol.ModeBuyerMandate
	g2ID := protocol.DigestBytes([]byte("bound-g2"))
	scope := wallet.ExecutionBinding{
		DeploymentID: fx.depID, DomainID: "A", Actor: "A1", DID: fx.didA1, TaskID: fx.taskID,
		Mode: mode, GrantID: fx.g1ID, Stage: wallet.StageDelegate, RunID: "run",
		SubjectDID: fx.didB1, SubjectActor: "B1", ChildGrantID: g2ID,
	}
	delegate, err := wallet.NewBoundOperations(fx.wallet, scope)
	require.NoError(t, err)
	assert.Equal(t, wallet.StageDelegate, delegate.Scope().Stage)
	assert.Equal(t, fx.g1ID, delegate.Scope().GrantID)

	good := wallet.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID, GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: mode, MaxAmountMinor: 100000,
	}
	for label, mutate := range map[string]func(*wallet.DelegateGrantInput){
		"signer":    func(in *wallet.DelegateGrantInput) { in.IssuerActor = "B1" },
		"task":      func(in *wallet.DelegateGrantInput) { in.TaskID = "other" },
		"mode":      func(in *wallet.DelegateGrantInput) { in.AuthorizationMode = protocol.ModeResourcePreauthorized },
		"grant":     func(in *wallet.DelegateGrantInput) { in.ParentGrantID = "other" },
		"recipient": func(in *wallet.DelegateGrantInput) { in.SubjectDID = fx.didB2 },
	} {
		t.Run(label, func(t *testing.T) {
			bad := good
			mutate(&bad)
			_, err := delegate.DelegateGrant(ctx, bad)
			require.True(t, protocol.HasCode(err, protocol.ErrCodeBindingMismatch), "%v", err)
		})
	}

	_, err = wallet.NewBoundOperations(fx.wallet, wallet.ExecutionBinding{
		DeploymentID: fx.depID, DomainID: "A", Actor: "B1", DID: fx.didB1, TaskID: fx.taskID,
		Mode: mode, GrantID: g2ID, Stage: wallet.StageExecute, RunID: "run", ProductID: productID, Quantity: 1,
	})
	require.True(t, protocol.HasCode(err, protocol.ErrCodeBindingMismatch), "invalid delegated calls must not add a grant")

	issued, err := delegate.DelegateGrant(ctx, good)
	require.NoError(t, err)
	require.True(t, issued.Anchored)

	scope = wallet.ExecutionBinding{
		DeploymentID: fx.depID, DomainID: "A", Actor: "B1", DID: fx.didB1, TaskID: fx.taskID,
		Mode: mode, GrantID: g2ID, Stage: wallet.StageExecute, RunID: "run", ProductID: productID, Quantity: 1,
	}
	ops, err := wallet.NewBoundOperations(fx.wallet, scope)
	require.NoError(t, err)
	assert.Equal(t, wallet.StageExecute, ops.Scope().Stage)

	quote, err := ops.RequestQuote(ctx, wallet.RequestQuoteInput{})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", quote.Decision)

	// Mismatched amount or quote must be rejected before touching gateway.
	_, err = ops.CreateOrder(ctx, wallet.CreateOrderInput{
		Actor: "B1", TaskID: fx.taskID, QuoteID: quote.QuoteID, AuthorizationMode: mode,
		AmountMinor: quote.TotalAmountMinor + 1, IdempotencyKey: ops.OrderKey(),
	})
	require.True(t, protocol.HasCode(err, protocol.ErrCodeBindingMismatch))

	in := wallet.CreateOrderInput{
		Actor: "B1", TaskID: fx.taskID, QuoteID: quote.QuoteID, AuthorizationMode: mode,
		AmountMinor: quote.TotalAmountMinor, IdempotencyKey: ops.OrderKey(),
	}
	direct, err := ops.CreateOrder(ctx, in)
	require.NoError(t, err)
	require.Equal(t, "ALLOW", direct.Decision)

	replay, err := ops.CreateOrder(ctx, in)
	require.NoError(t, err)
	require.Equal(t, direct, replay)

	fx.gw.mu.Lock()
	defer fx.gw.mu.Unlock()
	require.Len(t, fx.gw.ordersByKey, 1)
	require.Len(t, fx.gw.verifiedRequests, 2)
	assert.Equal(t, fx.didB1, fx.gw.verifiedRequests[1].Actor)
	assert.Equal(t, ops.OrderKey(), fx.gw.verifiedRequests[1].IdempotencyKey)
}
