package gateway

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

const gatewaySchemaSQL = `
CREATE TABLE IF NOT EXISTS challenges (
	deployment_id TEXT NOT NULL,
	challenge_id TEXT NOT NULL,
	nonce TEXT NOT NULL,
	actor TEXT NOT NULL,
	task_id TEXT NOT NULL,
	request_hash TEXT NOT NULL,
	audience TEXT NOT NULL,
	issued_at BIGINT NOT NULL,
	expires_at BIGINT NOT NULL,
	consumed_at BIGINT,
	decision_id TEXT,
	PRIMARY KEY (deployment_id, challenge_id),
	UNIQUE (deployment_id, nonce)
);

CREATE TABLE IF NOT EXISTS trusted_contexts (
	deployment_id TEXT NOT NULL,
	task_id TEXT NOT NULL,
	context_version BIGINT NOT NULL,
	source_id TEXT NOT NULL,
	observed_at BIGINT NOT NULL,
	risk_level TEXT NOT NULL CHECK (risk_level IN ('NORMAL', 'ELEVATED', 'BLOCKED')),
	access_deadline BIGINT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (deployment_id, task_id)
);

CREATE TABLE IF NOT EXISTS business_keys (
	deployment_id TEXT NOT NULL,
	actor TEXT NOT NULL,
	task_id TEXT NOT NULL,
	action TEXT NOT NULL,
	idempotency_key TEXT NOT NULL,
	request_hash TEXT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('IN_PROGRESS', 'COMPLETED')),
	resource_id TEXT,
	decision_id TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (deployment_id, actor, task_id, action, idempotency_key)
);

CREATE TABLE IF NOT EXISTS quotes (
	deployment_id TEXT NOT NULL,
	quote_id TEXT NOT NULL,
	task_id TEXT NOT NULL,
	actor TEXT NOT NULL,
	supplier_id TEXT NOT NULL,
	product_id TEXT NOT NULL,
	quantity BIGINT NOT NULL CHECK (quantity > 0),
	currency TEXT NOT NULL,
	unit_price_minor BIGINT NOT NULL CHECK (unit_price_minor > 0),
	total_amount_minor BIGINT NOT NULL CHECK (total_amount_minor > 0),
	issued_at BIGINT NOT NULL,
	valid_until BIGINT NOT NULL,
	decision_id TEXT NOT NULL,
	PRIMARY KEY (deployment_id, quote_id)
);

CREATE TABLE IF NOT EXISTS decisions (
	deployment_id TEXT NOT NULL,
	decision_id TEXT NOT NULL,
	request_id TEXT NOT NULL,
	challenge_id TEXT NOT NULL,
	actor TEXT NOT NULL,
	task_id TEXT NOT NULL,
	action TEXT NOT NULL,
	idempotency_key TEXT NOT NULL,
	outcome TEXT NOT NULL CHECK (outcome IN ('ALLOW', 'DENY')),
	code TEXT NOT NULL,
	reason TEXT,
	quote_id TEXT,
	order_id TEXT,
	block_number BIGINT NOT NULL,
	block_hash TEXT NOT NULL,
	revocation_epoch BIGINT NOT NULL,
	probe_tx_id TEXT NOT NULL,
	probe_block BIGINT NOT NULL,
	probe_sent_at BIGINT NOT NULL,
	probe_deadline BIGINT NOT NULL,
	probe_sent_mono_ns BIGINT NOT NULL,
	probe_deadline_mono_ns BIGINT NOT NULL,
	decision_at BIGINT NOT NULL,
	root_did TEXT NOT NULL,
	root_key_version BIGINT NOT NULL,
	domain_id TEXT,
	certification_id TEXT,
	certification_digest TEXT,
	domain_revision BIGINT NOT NULL,
	identity_issuer TEXT,
	policy_digest TEXT NOT NULL,
	context_version BIGINT NOT NULL,
	context_risk_level TEXT NOT NULL,
	context_observed_at BIGINT NOT NULL,
	context_access_deadline BIGINT NOT NULL,
	effective_deadline BIGINT NOT NULL,
	grant_path TEXT[] NOT NULL,
	failed_object_id TEXT,
	PRIMARY KEY (deployment_id, decision_id),
	UNIQUE (deployment_id, challenge_id)
);

CREATE TABLE IF NOT EXISTS catalog_prices (
	deployment_id TEXT NOT NULL,
	product_id TEXT NOT NULL,
	supplier_id TEXT NOT NULL,
	currency TEXT NOT NULL,
	unit_price_minor BIGINT NOT NULL CHECK (unit_price_minor > 0),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (deployment_id, product_id)
);

CREATE TABLE IF NOT EXISTS orders (
	deployment_id TEXT NOT NULL,
	order_id TEXT NOT NULL,
	quote_id TEXT NOT NULL,
	task_id TEXT NOT NULL,
	actor TEXT NOT NULL,
	supplier_id TEXT NOT NULL,
	product_id TEXT NOT NULL,
	quantity BIGINT NOT NULL CHECK (quantity > 0),
	currency TEXT NOT NULL,
	total_amount_minor BIGINT NOT NULL CHECK (total_amount_minor > 0),
	idempotency_key TEXT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('CREATED')),
	created_at BIGINT NOT NULL,
	decision_id TEXT NOT NULL,
	PRIMARY KEY (deployment_id, order_id),
	UNIQUE (deployment_id, actor, task_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS client_actions (
	deployment_id TEXT NOT NULL,
	action_id TEXT NOT NULL,
	actor TEXT NOT NULL,
	task_id TEXT NOT NULL,
	action TEXT NOT NULL,
	idempotency_key TEXT NOT NULL,
	request_hash TEXT NOT NULL,
	challenge_id TEXT,
	quote_id TEXT,
	order_id TEXT,
	decision_id TEXT,
	status TEXT NOT NULL CHECK (status IN ('PENDING', 'SUBMITTED', 'COMPLETED', 'FAILED')),
	created_at BIGINT NOT NULL,
	updated_at BIGINT NOT NULL,
	PRIMARY KEY (deployment_id, action_id),
	UNIQUE (deployment_id, actor, task_id, action, idempotency_key)
);

ALTER TABLE decisions ADD COLUMN IF NOT EXISTS order_id TEXT;
`

const (
	// DefaultProductID is the seeded P1 procurement catalog identifier.
	DefaultProductID = "urn:grad:product:P1"
	// DefaultProductPriceMinor is the seeded P1 unit price in CNY minor units (80000 fen).
	DefaultProductPriceMinor = int64(80000)
	// SecondaryProductID is the seeded M2 P2 catalog identifier (exceeds G2 100000 fen limit).
	SecondaryProductID = "urn:grad:product:P2"
	// SecondaryProductPriceMinor is the seeded P2 unit price in CNY minor units (120000 fen).
	SecondaryProductPriceMinor = int64(120000)
	// DefaultCurrency is the seeded CNY currency code.
	DefaultCurrency = "CNY"
)

// EnsureSchema creates all C business gateway PostgreSQL tables and seeds P1/P2 catalog pricing for deploymentID.
func EnsureSchema(ctx context.Context, db *pgxpool.Pool, deploymentID, supplierID string) error {
	if db == nil {
		return fmt.Errorf("gateway database pool is required")
	}
	if _, err := db.Exec(ctx, gatewaySchemaSQL); err != nil {
		return fmt.Errorf("create gateway schema: %w", err)
	}
	if deploymentID == "" {
		return nil
	}
	if supplierID == "" {
		supplierID = "urn:grad:supplier:C"
	}
	for _, item := range []struct {
		productID string
		price     int64
	}{
		{DefaultProductID, DefaultProductPriceMinor},
		{SecondaryProductID, SecondaryProductPriceMinor},
	} {
		_, err := db.Exec(ctx, `INSERT INTO catalog_prices(
			deployment_id, product_id, supplier_id, currency, unit_price_minor
		) VALUES($1, $2, $3, $4, $5)
		ON CONFLICT(deployment_id, product_id) DO NOTHING`,
			deploymentID, item.productID, supplierID, DefaultCurrency, item.price,
		)
		if err != nil {
			return fmt.Errorf("seed catalog price %s: %w", item.productID, err)
		}
	}
	return nil
}
