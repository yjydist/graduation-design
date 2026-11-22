package testutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIsolatedDBName(t *testing.T) {
	a := newIsolatedDBName()
	b := newIsolatedDBName()
	assert.Regexp(t, `^test_[0-9a-f]{16}$`, a)
	assert.Regexp(t, `^test_[0-9a-f]{16}$`, b)
	assert.NotEqual(t, a, b)
}

func TestReplaceDSNDatabase(t *testing.T) {
	t.Run("postgres URL preserves credentials and query params", func(t *testing.T) {
		got, err := replaceDSNDatabase("postgres://user:pass@127.0.0.1:5432/postgres?sslmode=disable", "test_abc123")
		require.NoError(t, err)
		assert.Equal(t, "postgres://user:pass@127.0.0.1:5432/test_abc123?sslmode=disable", got)
	})

	t.Run("postgresql URL without initial path", func(t *testing.T) {
		got, err := replaceDSNDatabase("postgresql://postgres@localhost:5432?sslmode=disable", "test_abc123")
		require.NoError(t, err)
		assert.Equal(t, "postgresql://postgres@localhost:5432/test_abc123?sslmode=disable", got)
	})

	t.Run("keyword value DSN replaces existing dbname", func(t *testing.T) {
		got, err := replaceDSNDatabase("host=127.0.0.1 port=5432 user=postgres dbname=postgres sslmode=disable", "test_abc123")
		require.NoError(t, err)
		assert.Contains(t, got, "dbname=test_abc123")
		assert.NotContains(t, got, "dbname=postgres")
	})

	t.Run("keyword value DSN appends dbname when missing", func(t *testing.T) {
		got, err := replaceDSNDatabase("host=127.0.0.1 port=5432 user=postgres sslmode=disable", "test_abc123")
		require.NoError(t, err)
		assert.Contains(t, got, "dbname=test_abc123")
	})

	t.Run("rejects unsafe database name", func(t *testing.T) {
		_, err := replaceDSNDatabase("postgres://postgres@localhost:5432/postgres", "bad;DROP TABLE x")
		require.Error(t, err)
	})
}
