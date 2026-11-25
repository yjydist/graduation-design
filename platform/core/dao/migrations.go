// Package dao owns PostgreSQL schema migrations, explicit transaction management,
// and data-access helpers for grad/platform.
package dao

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
		return fmt.Errorf("dao: database pool is required")
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
		return fmt.Errorf("dao: sql.DB is required")
	}
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(advisoryLockID))
	if err != nil {
		return fmt.Errorf("dao: create postgres session locker: %w", err)
	}
	provider, err := goose.NewProvider(
		database.DialectPostgres,
		db,
		FS,
		goose.WithSessionLocker(locker),
		goose.WithLogger(goose.NopLogger()),
	)
	if err != nil {
		return fmt.Errorf("dao: create goose provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("dao: apply up migrations: %w", err)
	}
	return nil
}
