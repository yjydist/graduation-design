-- +goose Up
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

CREATE TABLE IF NOT EXISTS catalog_prices (
    deployment_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    supplier_id TEXT NOT NULL,
    currency TEXT NOT NULL,
    unit_price_minor BIGINT NOT NULL CHECK (unit_price_minor > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (deployment_id, product_id)
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
    block_number BIGINT,
    block_hash TEXT,
    revocation_epoch BIGINT,
    probe_tx_id TEXT,
    probe_block BIGINT,
    probe_sent_at BIGINT,
    probe_deadline BIGINT,
    probe_sent_mono_ns BIGINT,
    probe_deadline_mono_ns BIGINT,
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
    state_source TEXT NOT NULL DEFAULT 'fabric',
    revision BIGINT,
    state_read_at TIMESTAMPTZ,
    state_rechecks INTEGER NOT NULL DEFAULT 0,
    probe_checked_mono_ns BIGINT,
    decision_at_ns BIGINT,
    probe_sent_at_ns BIGINT,
    probe_deadline_ns BIGINT,
    PRIMARY KEY (deployment_id, decision_id),
    UNIQUE (deployment_id, challenge_id)
);

CREATE TABLE IF NOT EXISTS decision_evidence (
    deployment_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    package_json JSONB NOT NULL,
    did_documents JSONB NOT NULL,
    checked_mono_ns BIGINT,
    PRIMARY KEY (deployment_id, decision_id)
);

CREATE TABLE IF NOT EXISTS order_outcome_cases (
    deployment_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    task_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    send_revision BIGINT NOT NULL,
    request_json TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    challenge_ids TEXT[] NOT NULL DEFAULT '{}',
    created_at BIGINT NOT NULL,
    PRIMARY KEY (deployment_id, case_id),
    UNIQUE (deployment_id, actor, task_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS order_outcome_audits (
    deployment_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    check_no BIGINT NOT NULL,
    send_revision BIGINT NOT NULL,
    actor TEXT NOT NULL,
    task_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('CREATED', 'NOT_CREATED', 'UNKNOWN')),
    order_id TEXT,
    creation_decision_id TEXT,
    historical_status TEXT NOT NULL CHECK (historical_status IN ('MATCHED', 'INCOMPLETE', 'MISMATCH', 'NO_DECISION')),
    historical_reason TEXT,
    verifier_id TEXT NOT NULL DEFAULT '',
    audit_at BIGINT NOT NULL,
    PRIMARY KEY (deployment_id, case_id, check_no)
);

CREATE TABLE IF NOT EXISTS order_outcome_outbox (
    deployment_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    send_revision BIGINT NOT NULL,
    check_no BIGINT NOT NULL,
    receipt_json JSONB NOT NULL,
    delivered_at BIGINT,
    attempts BIGINT NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (deployment_id, case_id, send_revision, check_no)
);

-- +goose Down
DROP TABLE IF EXISTS order_outcome_outbox;
DROP TABLE IF EXISTS order_outcome_audits;
DROP TABLE IF EXISTS order_outcome_cases;
DROP TABLE IF EXISTS decision_evidence;
DROP TABLE IF EXISTS decisions;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS quotes;
DROP TABLE IF EXISTS catalog_prices;
DROP TABLE IF EXISTS business_keys;
DROP TABLE IF EXISTS trusted_contexts;
DROP TABLE IF EXISTS challenges;
