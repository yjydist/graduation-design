package dao_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/dao"
	"grad/protocol"
	"grad/protocol/registry"
)

func TestActionStoreInMemoryIntentLockAndReceipt(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	depID := registry.Digest([]byte("dao-mem-dep"))
	now := time.Unix(1770000000, 0).UTC()
	store := dao.NewActionStore(nil, depID, func() time.Time { return now })

	reqHash := registry.Digest([]byte("order-request-1"))
	act, err := store.BeginClientAction(ctx, "did:web:b.local:b1", "task-1", protocol.ActionOrderCreate, "idem-1", reqHash, `{"ok":true}`)
	require.NoError(t, err)
	assert.Equal(t, dao.ActionStatusOutcomeUnknown, act.Status)
	assert.Equal(t, int64(1), act.SendRevision)

	// Idempotent replay with same hash returns same action.
	act2, err := store.BeginClientAction(ctx, "did:web:b.local:b1", "task-1", protocol.ActionOrderCreate, "idem-1", reqHash, `{"ok":true}`)
	require.NoError(t, err)
	assert.Equal(t, act.ActionID, act2.ActionID)

	// Conflicting hash returns IDEMPOTENCY_CONFLICT.
	_, err = store.BeginClientAction(ctx, "did:web:b.local:b1", "task-1", protocol.ActionOrderCreate, "idem-1", registry.Digest([]byte("other")), `{}`)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeIdempotencyConflict))

	// Stop send increments sendRevision and blocks stale dispatch.
	stopped, err := store.StopClientActionSend(ctx, "did:web:b.local:b1", "task-1", protocol.ActionOrderCreate, "idem-1", "case-1", "")
	require.NoError(t, err)
	assert.Equal(t, int64(2), stopped.SendRevision)
	assert.Equal(t, "case-1", stopped.CaseID)

	err = store.DispatchClientAction(ctx, act.ActionID, 1, func() error { return nil })
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateChanged))

	// Apply CREATED receipt transitions action to RECONCILED.
	orderID := "ord-123"
	resp, err := store.ApplyOrderOutcomeReceipt(ctx, dao.OrderOutcomeReceipt{
		CaseID:       "case-1",
		CheckNo:      1,
		SendRevision: 2,
		DeploymentID: depID,
		Actor:        "did:web:b.local:b1",
		TaskID:       "task-1",
		RequestHash:  reqHash,
		Outcome:      "CREATED",
		OrderID:      &orderID,
		AuditAt:      now.Unix(),
	})
	require.NoError(t, err)
	assert.Equal(t, "RECONCILED", resp.Status)
	assert.Equal(t, dao.ActionStatusReconciled, resp.ClientActionStatus)
}
