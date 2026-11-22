-- +goose Up
CREATE TABLE IF NOT EXISTS operations (
    deployment_id TEXT NOT NULL,
    operation_key TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    caller_msp_id TEXT NOT NULL,
    caller_fingerprint TEXT NOT NULL,
    method TEXT NOT NULL,
    tx_id TEXT NOT NULL,
    block_no BIGINT NOT NULL DEFAULT 0,
    block_hash TEXT NOT NULL DEFAULT '',
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    validation_code TEXT,
    failure_code TEXT,
    payload_hash TEXT NOT NULL,
    request_json BYTEA,
    delivered BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (deployment_id, operation_key)
);

CREATE TABLE IF NOT EXISTS registration_challenges (
    challenge_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    challenge_sha256 TEXT NOT NULL,
    msp_id TEXT NOT NULL,
    certificate_sha256 TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    app_key_id TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    challenge_json JSONB NOT NULL,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_by_operation_id TEXT,
    consumed_at BIGINT
);

CREATE TABLE IF NOT EXISTS recovery_challenges (
    challenge_id TEXT PRIMARY KEY,
    deployment_id TEXT NOT NULL,
    challenge_sha256 TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    account_commitment TEXT NOT NULL,
    old_msp_id TEXT NOT NULL,
    old_certificate_sha256 TEXT NOT NULL,
    new_msp_id TEXT NOT NULL,
    new_certificate_sha256 TEXT NOT NULL,
    expected_revision BIGINT NOT NULL,
    expected_key_version BIGINT NOT NULL,
    new_app_key_id TEXT NOT NULL,
    new_app_key_version BIGINT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    challenge_json JSONB NOT NULL,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    consumed_by_operation_id TEXT,
    consumed_at BIGINT
);

CREATE TABLE IF NOT EXISTS certification_outbox (
    deployment_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    certification_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    cert_jws TEXT NOT NULL,
    cert_digest TEXT NOT NULL,
    root_key_version BIGINT NOT NULL,
    tx_id TEXT NOT NULL,
    block_no BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (deployment_id, domain_id, certification_id, recipient)
);

CREATE TABLE IF NOT EXISTS certification_receipts (
    deployment_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    certification_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    cert_jws TEXT NOT NULL,
    cert_digest TEXT NOT NULL,
    received_at BIGINT NOT NULL,
    PRIMARY KEY (deployment_id, domain_id, certification_id, recipient)
);

CREATE TABLE IF NOT EXISTS grant_outbox (
    deployment_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    package_json JSONB NOT NULL,
    package_digest TEXT NOT NULL,
    tx_id TEXT NOT NULL,
    block_no BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (deployment_id, recipient, grant_id)
);

CREATE TABLE IF NOT EXISTS wallet_receipts (
    deployment_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    package_json JSONB NOT NULL,
    package_digest TEXT NOT NULL,
    received_at BIGINT NOT NULL,
    PRIMARY KEY (deployment_id, recipient, grant_id)
);

-- +goose Down
DROP TABLE IF EXISTS wallet_receipts;
DROP TABLE IF EXISTS grant_outbox;
DROP TABLE IF EXISTS certification_receipts;
DROP TABLE IF EXISTS certification_outbox;
DROP TABLE IF EXISTS recovery_challenges;
DROP TABLE IF EXISTS registration_challenges;
DROP TABLE IF EXISTS operations;
