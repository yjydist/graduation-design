//go:build db

package dao_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/dao"
	"grad/platform/internal/testutil"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

func TestMigrationsUpIdempotentAndAllTablesPresent(t *testing.T) {
	ctx := context.Background()
	pool := testutil.OpenTestPool(t)

	// First apply must succeed.
	require.NoError(t, dao.Up(ctx, pool))
	// Second apply must be an idempotent no-op.
	require.NoError(t, dao.Up(ctx, pool))

	expectedTables := []string{
		// 001_fabric.sql (5)
		"fabric_head",
		"fabric_block",
		"fabric_version",
		"fabric_current",
		"fabric_operation",
		// 002_central.sql (1)
		"centralized_registry",
		// 003_registrysvc.sql (7)
		"operations",
		"registration_challenges",
		"recovery_challenges",
		"certification_outbox",
		"certification_receipts",
		"grant_outbox",
		"wallet_receipts",
		// 004_gateway.sql (11)
		"challenges",
		"trusted_contexts",
		"business_keys",
		"catalog_prices",
		"quotes",
		"orders",
		"decisions",
		"decision_evidence",
		"order_outcome_cases",
		"order_outcome_audits",
		"order_outcome_outbox",
		// 005_agent.sql (2)
		"client_actions",
		"order_outcome_receipts",
		// 006_web_sessions.sql (2)
		"workbench_accounts",
		"workbench_sessions",
		// 007_workbench_runs.sql (6)
		"workbench_drafts",
		"workbench_runs",
		"workbench_grant_controls",
		"workbench_store_binding",
		"workbench_dispatch",
		"workbench_tool_trace",
		// 008_workbench_grants.sql (1)
		"workbench_grant_issue",
		// 009_workbench_proof.sql (1)
		"workbench_decision_proof",
		// 010_workbench_rejections.sql (1)
		"workbench_gateway_rejections",
		// 012_bound_quotes.sql (1)
		"wallet_bound_quotes",
	}
	require.Len(t, expectedTables, 38)

	rows, err := pool.Query(ctx, `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
	`)
	require.NoError(t, err)
	defer rows.Close()

	actualTables := map[string]bool{}
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		actualTables[name] = true
	}
	require.NoError(t, rows.Err())

	for _, tbl := range expectedTables {
		assert.True(t, actualTables[tbl], "expected table %q to exist after dao.Up", tbl)
	}

	// Verify fabric_version_tx index exists.
	var indexExists bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			WHERE schemaname = 'public' AND tablename = 'fabric_version' AND indexname = 'fabric_version_tx'
		)
	`).Scan(&indexExists))
	assert.True(t, indexExists, "expected index fabric_version_tx to exist")

	// Verify decisions has all 46 columns and nullable Fabric-only fields.
	var decisionsColCount int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'decisions'
	`).Scan(&decisionsColCount))
	assert.Equal(t, 46, decisionsColCount)

	for _, col := range []string{
		"block_number", "block_hash", "revocation_epoch",
		"probe_tx_id", "probe_block", "probe_sent_at",
		"probe_deadline", "probe_sent_mono_ns", "probe_deadline_mono_ns",
	} {
		var nullable string
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT is_nullable
			FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'decisions' AND column_name = $1
		`, col).Scan(&nullable))
		assert.Equal(t, "YES", nullable, "decisions.%s must be nullable", col)
	}
}

func TestWorkbenchScheduleMigrationPreservesPendingRows(t *testing.T) {
	ctx := t.Context()
	pool := testutil.OpenTestPool(t)
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	provider, err := goose.NewProvider(database.DialectPostgres, db, dao.FS, goose.WithLogger(goose.NopLogger()))
	require.NoError(t, err)
	_, err = provider.UpTo(ctx, 10)
	require.NoError(t, err)
	created := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	_, err = pool.Exec(ctx, `INSERT INTO workbench_runs
		(deployment_id,domain_id,owner_id,run_id,task_id,status,body,created_at)
		VALUES ('dep','A','buyer','run','task','OUTCOME_UNKNOWN','{}',$1)`, created)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO workbench_dispatch
		(deployment_id,run_id,task_id,status,body,result)
		VALUES ('dep','run','task','PENDING','{}','{"receipt":"accepted"}')`)
	require.NoError(t, err)

	require.NoError(t, dao.Up(ctx, pool))
	var nextAttempt time.Time
	var status, receipt string
	require.NoError(t, pool.QueryRow(ctx, `SELECT status,next_attempt_at FROM workbench_runs WHERE run_id='run'`).Scan(&status, &nextAttempt))
	require.Equal(t, "OUTCOME_UNKNOWN", status)
	require.True(t, nextAttempt.Equal(created))
	require.NoError(t, pool.QueryRow(ctx, `SELECT status,result->>'receipt',next_attempt_at
		FROM workbench_dispatch WHERE run_id='run'`).Scan(&status, &receipt, &nextAttempt))
	require.Equal(t, "PENDING", status)
	require.Equal(t, "accepted", receipt)
	require.False(t, nextAttempt.Before(created))
}

func TestTxHelpersAndAdvisoryLock(t *testing.T) {
	ctx := t.Context()
	pool := testutil.OpenMigratedPool(t)
	store := dao.NewStore(pool)

	var epoch int64
	require.NoError(t, store.RunInTx(ctx, func(tx dao.Tx) error {
		if err := tx.AdvisoryXactLock(ctx, "test-lock-key"); err != nil {
			return err
		}
		var err error
		epoch, err = tx.ClockEpochSeconds(ctx)
		return err
	}))
	assert.Greater(t, epoch, int64(1700000000))

	var ts time.Time
	require.NoError(t, store.RunRepeatableReadTx(ctx, func(tx dao.Tx) error {
		var err error
		ts, err = tx.ClockTimestamp(ctx)
		return err
	}))
	assert.False(t, ts.IsZero())
}
