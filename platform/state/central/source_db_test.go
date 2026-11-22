//go:build db

package central

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/internal/testutil"
	"grad/platform/state"
	"grad/protocol"
	"grad/protocol/registry"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

func TestCentralSourceLifecycleAndLocking(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()

	initial := sampleCentralSnapshot()
	src, err := Initialize(ctx, pool, initial)
	require.NoError(t, err)

	// 1. AssembleSnapshot under concurrent Update keeps REPEATABLE READ revision 1.
	updated := false
	src.AfterRead = func() {
		err := src.Update(ctx, 1, func(v *protocol.SnapshotView) error {
			g := v.Grants["g1"]
			g.Status = registry.Revoked
			g.Revision = 2
			v.Grants["g1"] = g
			return nil
		})
		require.NoError(t, err)
		updated = true
	}

	snap1, err := src.AssembleSnapshot(ctx, "g1", time.Now().UTC())
	src.AfterRead = nil
	require.NoError(t, err)
	require.True(t, updated)
	assert.Equal(t, state.SourceCentralized, snap1.StateSource)
	assert.Equal(t, int64(1), snap1.Revision)
	assert.Equal(t, registry.Active, snap1.Snapshot.Grants["g1"].Status)

	// 2. Stale expected revision on Update returns STATE_CHANGED.
	err = src.Update(ctx, 1, func(v *protocol.SnapshotView) error { return nil })
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateChanged))

	// 3. LockCheckpoint returns false for stale snap1 and true for fresh snap2.
	tx1, err := pool.Begin(ctx)
	require.NoError(t, err)
	same, err := src.LockCheckpoint(ctx, tx1, snap1)
	require.NoError(t, err)
	assert.False(t, same)
	require.NoError(t, tx1.Rollback(context.Background()))

	snap2, err := src.AssembleSnapshot(ctx, "g1", time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, int64(2), snap2.Revision)
	assert.Equal(t, registry.Revoked, snap2.Snapshot.Grants["g1"].Status)

	tx2, err := pool.Begin(ctx)
	require.NoError(t, err)
	same, err = src.LockCheckpoint(ctx, tx2, snap2)
	require.NoError(t, err)
	assert.True(t, same)
	require.NoError(t, tx2.Commit(ctx))

	// 4. Readiness snapshot (empty leafGrantID) succeeds and CheckFresh validates metadata.
	readySnap, err := src.AssembleSnapshot(ctx, "", time.Now().UTC())
	require.NoError(t, err)
	assert.Contains(t, readySnap.Snapshot.Domains, "A")
	assert.Contains(t, readySnap.Snapshot.Domains, "C")
	lease, err := src.CheckFresh(ctx, readySnap)
	require.NoError(t, err)
	assert.Equal(t, state.ProbeLease{}, lease)
}
