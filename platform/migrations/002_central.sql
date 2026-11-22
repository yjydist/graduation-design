-- +goose Up
CREATE TABLE IF NOT EXISTS centralized_registry (
    deployment_id TEXT PRIMARY KEY,
    revision BIGINT NOT NULL CHECK (revision > 0),
    snapshot JSONB NOT NULL
);

-- +goose Down
DROP TABLE IF EXISTS centralized_registry;
