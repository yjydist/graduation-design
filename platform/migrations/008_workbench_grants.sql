-- +goose Up
CREATE TABLE workbench_grant_issue (
    deployment_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    issuer_did TEXT NOT NULL,
    operation_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    grant_jws TEXT NOT NULL,
    PRIMARY KEY (deployment_id, domain_id, grant_id),
    UNIQUE (deployment_id, domain_id, issuer_did, operation_key)
);

-- +goose Down
DROP TABLE workbench_grant_issue;
