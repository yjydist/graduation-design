-- +goose Up
CREATE TABLE workbench_decision_proof (
    deployment_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    body JSONB NOT NULL,
    PRIMARY KEY (deployment_id, decision_id),
    FOREIGN KEY (deployment_id, decision_id) REFERENCES decisions (deployment_id, decision_id)
);

-- +goose Down
DROP TABLE workbench_decision_proof;
