// Package testutil provides isolated PostgreSQL databases for platform integration tests.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"grad/platform/core/dao"
)

const (
	// EnvTestPostgresDSN overrides testcontainers with an externally managed PostgreSQL instance.
	EnvTestPostgresDSN = "TEST_POSTGRES_DSN"
	postgresImage      = "postgres:17-alpine"
)

var (
	pgMu        sync.Mutex
	pgOnce      sync.Once
	pgAdminDSN  string
	pgContainer *tcpostgres.PostgresContainer
	pgInitErr   error

	dbNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
)

func ensurePostgres() (string, error) {
	pgOnce.Do(func() {
		if dsn := strings.TrimSpace(os.Getenv(EnvTestPostgresDSN)); dsn != "" {
			pgAdminDSN = dsn
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		ctr, err := tcpostgres.Run(
			ctx,
			postgresImage,
			tcpostgres.WithDatabase("postgres"),
			tcpostgres.WithUsername("postgres"),
			tcpostgres.WithPassword("postgres"),
			tcpostgres.BasicWaitStrategies(),
		)
		if err != nil {
			pgInitErr = fmt.Errorf("testutil: start %s container: %w", postgresImage, err)
			return
		}
		dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			_ = ctr.Terminate(context.Background())
			pgInitErr = fmt.Errorf("testutil: postgres connection string: %w", err)
			return
		}
		pgMu.Lock()
		pgContainer = ctr
		pgMu.Unlock()
		pgAdminDSN = dsn
	})
	return pgAdminDSN, pgInitErr
}

// CleanupPostgres terminates the package-shared testcontainers PostgreSQL instance if started.
func CleanupPostgres() {
	pgMu.Lock()
	ctr := pgContainer
	pgContainer = nil
	pgMu.Unlock()
	if ctr != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = ctr.Terminate(ctx)
	}
}

// RunWithPostgres runs m and ensures the shared PostgreSQL test container is terminated on exit.
func RunWithPostgres(m *testing.M) int {
	code := m.Run()
	CleanupPostgres()
	return code
}

// OpenTestPool creates a fresh isolated PostgreSQL database for t without running migrations.
// The pool is closed and the database is dropped automatically during t.Cleanup.
func OpenTestPool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	pool, _ := OpenTestDB(t)
	return pool
}

// OpenTestDB creates a fresh isolated PostgreSQL database for t and returns both its pool and DSN.
func OpenTestDB(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	adminDSN, err := ensurePostgres()
	if err != nil {
		t.Fatalf("testutil: initialize postgres: %v", err)
	}
	dbName := newIsolatedDBName()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := execAdmin(ctx, adminDSN, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatalf("testutil: create isolated database %s: %v", dbName, err)
	}

	dsn, err := replaceDSNDatabase(adminDSN, dbName)
	if err != nil {
		_ = execAdmin(context.Background(), adminDSN, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
		t.Fatalf("testutil: build database DSN: %v", err)
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		_ = execAdmin(context.Background(), adminDSN, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
		t.Fatalf("testutil: parse database config: %v", err)
	}
	cfg.ConnConfig.Database = dbName

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		_ = execAdmin(context.Background(), adminDSN, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
		t.Fatalf("testutil: open pool for %s: %v", dbName, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		_ = execAdmin(context.Background(), adminDSN, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
		t.Fatalf("testutil: ping %s: %v", dbName, err)
	}

	t.Cleanup(func() {
		pool.Close()
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer dropCancel()
		_ = execAdmin(dropCtx, adminDSN, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)")
	})

	return pool, dsn
}

// OpenMigratedPool creates an isolated PostgreSQL database for t and applies all embedded migrations.
func OpenMigratedPool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	pool, _ := OpenMigratedDB(t)
	return pool
}

// OpenMigratedDB creates an isolated PostgreSQL database for t, applies all embedded migrations,
// and returns both the pool and the database DSN.
func OpenMigratedDB(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	pool, dsn := OpenTestDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := dao.Up(ctx, pool); err != nil {
		t.Fatalf("testutil: apply migrations: %v", err)
	}
	return pool, dsn
}

func execAdmin(ctx context.Context, adminDSN, sqlStmt string) error {
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	_, err = conn.Exec(ctx, sqlStmt)
	return err
}

func newIsolatedDBName() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("test_%d", time.Now().UnixNano())
	}
	return "test_" + hex.EncodeToString(b[:])
}

func replaceDSNDatabase(adminDSN, dbName string) (string, error) {
	if !dbNameRe.MatchString(dbName) {
		return "", fmt.Errorf("invalid database name %q", dbName)
	}
	trimmed := strings.TrimSpace(adminDSN)
	if trimmed == "" {
		return "", fmt.Errorf("empty admin DSN")
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		u, err := url.Parse(trimmed)
		if err != nil {
			return "", fmt.Errorf("parse postgres URL: %w", err)
		}
		u.Path = "/" + dbName
		return u.String(), nil
	}
	// Keyword/value DSN format.
	parts := strings.Fields(trimmed)
	replaced := false
	for i, part := range parts {
		if strings.HasPrefix(part, "dbname=") {
			parts[i] = "dbname=" + dbName
			replaced = true
		}
	}
	if !replaced {
		parts = append(parts, "dbname="+dbName)
	}
	out := strings.Join(parts, " ")
	cfg, err := pgxpool.ParseConfig(out)
	if err != nil {
		return "", fmt.Errorf("validate keyword DSN: %w", err)
	}
	if cfg.ConnConfig.Database != dbName {
		return "", fmt.Errorf("unexpected parsed database %q, want %q", cfg.ConnConfig.Database, dbName)
	}
	return out, nil
}
