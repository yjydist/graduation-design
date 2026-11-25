-- +goose Up
ALTER TABLE workbench_runs ADD COLUMN next_attempt_at TIMESTAMPTZ;
UPDATE workbench_runs SET next_attempt_at = created_at;
ALTER TABLE workbench_runs
    ALTER COLUMN next_attempt_at SET DEFAULT clock_timestamp(),
    ALTER COLUMN next_attempt_at SET NOT NULL;

ALTER TABLE workbench_dispatch ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp();

DROP INDEX workbench_runs_pending;
CREATE INDEX workbench_runs_pending ON workbench_runs (deployment_id, domain_id, next_attempt_at, run_id)
    WHERE status IN ('PENDING', 'OUTCOME_UNKNOWN');
CREATE INDEX workbench_dispatch_pending ON workbench_dispatch (deployment_id, next_attempt_at, run_id)
    WHERE status IN ('PENDING', 'OUTCOME_UNKNOWN');

-- +goose Down
DROP INDEX workbench_dispatch_pending;
DROP INDEX workbench_runs_pending;
ALTER TABLE workbench_dispatch DROP COLUMN next_attempt_at;
ALTER TABLE workbench_runs DROP COLUMN next_attempt_at;
CREATE INDEX workbench_runs_pending ON workbench_runs (deployment_id, domain_id, created_at) WHERE status = 'PENDING';
