// Package migrations embeds and applies PostgreSQL schema migrations for grad/platform.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
	"github.com/pressly/goose/v3/lock"
)

//go:embed *.sql
var FS embed.FS

// advisoryLockID serializes concurrent migration runs targeting the same database.
const advisoryLockID int64 = 376602444033251

// Up applies all embedded PostgreSQL migrations using pool.
func Up(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return fmt.Errorf("migrations: database pool is required")
	}
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	return UpDB(ctx, db)
}

// UpDB applies all embedded PostgreSQL migrations using an existing *sql.DB.
// It uses a goose.Provider with a PostgreSQL session advisory lock so concurrent
// callers targeting either the same database or isolated databases execute safely.
func UpDB(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("migrations: sql.DB is required")
	}
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(advisoryLockID))
	if err != nil {
		return fmt.Errorf("migrations: create postgres session locker: %w", err)
	}
	provider, err := goose.NewProvider(
		database.DialectPostgres,
		db,
		FS,
		goose.WithSessionLocker(locker),
		goose.WithLogger(goose.NopLogger()),
	)
	if err != nil {
		return fmt.Errorf("migrations: create goose provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("migrations: apply up migrations: %w", err)
	}
	return nil
}
