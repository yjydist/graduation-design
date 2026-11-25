-- +goose Up
CREATE TABLE IF NOT EXISTS client_actions (
    deployment_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    task_id TEXT NOT NULL,
    action TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    request_json TEXT NOT NULL DEFAULT '',
    send_revision BIGINT NOT NULL DEFAULT 1,
    challenge_id TEXT,
    challenge_ids TEXT[] NOT NULL DEFAULT '{}',
    quote_id TEXT,
    order_id TEXT,
    decision_id TEXT,
    case_id TEXT,
    outcome TEXT,
    status TEXT NOT NULL CONSTRAINT client_actions_status_check CHECK (status IN ('PENDING', 'OUTCOME_UNKNOWN', 'SUBMITTED', 'COMPLETED', 'RECONCILED', 'FAILED')),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (deployment_id, action_id),
    UNIQUE (deployment_id, actor, task_id, action, idempotency_key)
);

CREATE TABLE IF NOT EXISTS order_outcome_receipts (
    deployment_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    check_no BIGINT NOT NULL,
    send_revision BIGINT NOT NULL,
    actor TEXT NOT NULL,
    task_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('CREATED', 'NOT_CREATED', 'UNKNOWN')),
    order_id TEXT,
    creation_decision_id TEXT,
    historical_status TEXT NOT NULL CHECK (historical_status IN ('MATCHED', 'INCOMPLETE', 'MISMATCH', 'NO_DECISION')),
    audit_at BIGINT NOT NULL DEFAULT 0,
    received_at BIGINT NOT NULL,
    PRIMARY KEY (deployment_id, case_id, send_revision, check_no)
);

-- +goose Down
DROP TABLE IF EXISTS order_outcome_receipts;
DROP TABLE IF EXISTS client_actions;
