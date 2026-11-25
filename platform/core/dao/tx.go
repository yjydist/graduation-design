package dao

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier abstracts *pgxpool.Pool and pgx.Tx for shared SQL queries.
type Querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Tx wraps pgx.Tx to expose explicit transaction control and row-lock helpers
// while preserving PostgreSQL lock ordering across domain operations.
type Tx struct {
	pgx.Tx
}

// Unwrap returns the underlying pgx.Tx for state-source checkpoint locks.
func (t Tx) Unwrap() pgx.Tx {
	return t.Tx
}

// AdvisoryXactLock acquires a transaction-scoped advisory lock keyed by a
// deterministic string hash.
func (t Tx) AdvisoryXactLock(ctx context.Context, key string) error {
	_, err := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)
	return err
}

// ClockEpochSeconds reads PostgreSQL clock_timestamp() as Unix seconds inside tx.
func (t Tx) ClockEpochSeconds(ctx context.Context) (int64, error) {
	var ts int64
	if err := t.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM clock_timestamp())::bigint`).Scan(&ts); err != nil {
		return 0, err
	}
	return ts, nil
}

// ClockTimestamp reads PostgreSQL clock_timestamp() in UTC inside tx.
func (t Tx) ClockTimestamp(ctx context.Context) (time.Time, error) {
	var ts time.Time
	if err := t.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&ts); err != nil {
		return time.Time{}, err
	}
	return ts.UTC(), nil
}

// Store wraps a *pgxpool.Pool with explicit transaction helpers.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore wraps pool in a Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Pool returns the underlying *pgxpool.Pool.
func (s *Store) Pool() *pgxpool.Pool {
	if s == nil {
		return nil
	}
	return s.pool
}

// RunInTx executes fn within a ReadCommitted read-write transaction and commits
// when fn returns nil.
func (s *Store) RunInTx(ctx context.Context, fn func(Tx) error) error {
	return RunInTx(ctx, s.Pool(), fn)
}

// RunRepeatableReadTx executes fn within a RepeatableRead read-only transaction.
func (s *Store) RunRepeatableReadTx(ctx context.Context, fn func(Tx) error) error {
	return RunRepeatableReadTx(ctx, s.Pool(), fn)
}

// RunInTx executes fn inside a ReadCommitted transaction on pool.
func RunInTx(ctx context.Context, pool *pgxpool.Pool, fn func(Tx) error) error {
	return RunTx(ctx, pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, fn)
}

// RunRepeatableReadTx executes fn inside a RepeatableRead read-only transaction on pool.
func RunRepeatableReadTx(ctx context.Context, pool *pgxpool.Pool, fn func(Tx) error) error {
	return RunTx(ctx, pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, fn)
}

// RunTx executes fn inside a transaction with opts and commits when fn returns nil.
func RunTx(ctx context.Context, pool *pgxpool.Pool, opts pgx.TxOptions, fn func(Tx) error) error {
	if pool == nil {
		return fmt.Errorf("dao: database pool is required")
	}
	raw, err := pool.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer raw.Rollback(context.Background())
	if err := fn(Tx{Tx: raw}); err != nil {
		return err
	}
	return raw.Commit(ctx)
}

// WithSessionAdvisoryLock acquires a session-scoped advisory lock on a dedicated
// pool connection for the duration of fn.
func WithSessionAdvisoryLock(ctx context.Context, pool *pgxpool.Pool, key string, fn func(context.Context, *pgxpool.Conn) error) error {
	if pool == nil {
		return fmt.Errorf("dao: database pool is required")
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, key); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key)
	}()
	return fn(ctx, conn)
}

// TryWithSessionAdvisoryLock attempts to acquire a session-scoped advisory lock
// without blocking. Returns acquired=false without calling fn if already locked.
func TryWithSessionAdvisoryLock(ctx context.Context, pool *pgxpool.Pool, key string, fn func(context.Context, *pgxpool.Conn) error) (bool, error) {
	if pool == nil {
		return false, fmt.Errorf("dao: database pool is required")
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, key).Scan(&acquired); err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key)
	}()
	return true, fn(ctx, conn)
}
