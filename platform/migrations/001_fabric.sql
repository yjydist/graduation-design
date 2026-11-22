-- +goose Up
CREATE TABLE IF NOT EXISTS fabric_head (
    deployment TEXT PRIMARY KEY,
    block_no BIGINT NOT NULL,
    hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fabric_block (
    deployment TEXT NOT NULL,
    block_no BIGINT NOT NULL,
    hash TEXT NOT NULL,
    parent TEXT NOT NULL,
    data BYTEA NOT NULL,
    PRIMARY KEY (deployment, block_no)
);

CREATE TABLE IF NOT EXISTS fabric_version (
    deployment TEXT NOT NULL,
    key TEXT NOT NULL,
    block_no BIGINT NOT NULL,
    tx_index INTEGER NOT NULL,
    tx_id TEXT NOT NULL,
    value BYTEA,
    PRIMARY KEY (deployment, key, block_no, tx_index),
    FOREIGN KEY (deployment, block_no) REFERENCES fabric_block (deployment, block_no)
);

CREATE INDEX IF NOT EXISTS fabric_version_tx ON fabric_version (deployment, key, tx_id);

CREATE TABLE IF NOT EXISTS fabric_current (
    deployment TEXT NOT NULL,
    key TEXT NOT NULL,
    value BYTEA NOT NULL,
    PRIMARY KEY (deployment, key)
);

CREATE TABLE IF NOT EXISTS fabric_operation (
    deployment TEXT NOT NULL,
    operation_key TEXT NOT NULL,
    data JSONB NOT NULL,
    PRIMARY KEY (deployment, operation_key)
);

-- +goose Down
DROP TABLE IF EXISTS fabric_operation;
DROP TABLE IF EXISTS fabric_current;
DROP INDEX IF EXISTS fabric_version_tx;
DROP TABLE IF EXISTS fabric_version;
DROP TABLE IF EXISTS fabric_block;
DROP TABLE IF EXISTS fabric_head;
