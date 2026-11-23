-- +goose Up
CREATE TABLE workbench_accounts (
    deployment_id TEXT NOT NULL,
    domain_id TEXT NOT NULL CHECK (domain_id IN ('A', 'B', 'C')),
    username TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('ADMIN', 'BUYER', 'AUDITOR')),
    management_msp_id TEXT NOT NULL,
    management_fingerprint TEXT NOT NULL,
    password_hash BYTEA NOT NULL,
    PRIMARY KEY (deployment_id, domain_id, username)
);

CREATE TABLE workbench_sessions (
    deployment_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    username TEXT NOT NULL,
    session_digest BYTEA NOT NULL CHECK (octet_length(session_digest) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (deployment_id, domain_id, session_digest),
    FOREIGN KEY (deployment_id, domain_id, username)
        REFERENCES workbench_accounts (deployment_id, domain_id, username) ON DELETE CASCADE
);

CREATE INDEX workbench_sessions_account ON workbench_sessions (deployment_id, domain_id, username);

-- +goose Down
DROP TABLE workbench_sessions;
DROP TABLE workbench_accounts;
