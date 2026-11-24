-- +goose Up
CREATE TABLE wallet_bound_quotes (
    deployment_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    task_id TEXT NOT NULL,
    quote_key TEXT NOT NULL,
    quote_id TEXT NOT NULL CHECK (quote_id <> ''),
    currency TEXT NOT NULL CHECK (currency <> ''),
    total_amount_minor BIGINT NOT NULL CHECK (total_amount_minor > 0),
    PRIMARY KEY (deployment_id, actor, task_id, quote_key)
);

-- +goose Down
DROP TABLE wallet_bound_quotes;
