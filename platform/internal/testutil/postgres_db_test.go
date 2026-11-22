//go:build db

package testutil_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/internal/testutil"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

func TestOpenTestPoolIsolatesDatabases(t *testing.T) {
	ctx := context.Background()
	poolA, dsnA := testutil.OpenTestDB(t)
	poolB, dsnB := testutil.OpenTestDB(t)

	assert.NotEqual(t, dsnA, dsnB)

	var dbA, dbB string
	require.NoError(t, poolA.QueryRow(ctx, "SELECT current_database()").Scan(&dbA))
	require.NoError(t, poolB.QueryRow(ctx, "SELECT current_database()").Scan(&dbB))
	assert.NotEqual(t, dbA, dbB)

	_, err := poolA.Exec(ctx, "CREATE TABLE isolation_probe (id INT PRIMARY KEY)")
	require.NoError(t, err)

	var existsInB bool
	require.NoError(t, poolB.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'isolation_probe')",
	).Scan(&existsInB))
	assert.False(t, existsInB, "table created in poolA must not exist in poolB")
}
