-- +goose Up
CREATE TABLE workbench_gateway_rejections (
    deployment_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    task_id TEXT NOT NULL,
    observed_at BIGINT NOT NULL,
    body JSONB NOT NULL,
    PRIMARY KEY (deployment_id, request_id)
);
CREATE INDEX workbench_gateway_rejections_task ON workbench_gateway_rejections (deployment_id, actor, task_id, observed_at);

-- +goose Down
DROP TABLE workbench_gateway_rejections;
