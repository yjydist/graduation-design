package dao

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BindWorkbenchStore binds a PostgreSQL database exclusively to a single
// (deploymentID, domainID) pair using workbench_store_binding (007_workbench_runs.sql).
func BindWorkbenchStore(ctx context.Context, db *pgxpool.Pool, deploymentID, domainID string) error {
	if db == nil {
		return fmt.Errorf("dao: database pool is required")
	}
	return RunInTx(ctx, db, func(tx Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO workbench_store_binding(singleton, deployment_id, domain_id)
			VALUES (TRUE, $1, $2) ON CONFLICT (singleton) DO NOTHING`, deploymentID, domainID); err != nil {
			return err
		}
		var boundDep, boundDomain string
		if err := tx.QueryRow(ctx, `SELECT deployment_id, domain_id FROM workbench_store_binding WHERE singleton = TRUE FOR SHARE`).
			Scan(&boundDep, &boundDomain); err != nil {
			return err
		}
		if boundDep != deploymentID || boundDomain != domainID {
			return fmt.Errorf("workbench database is bound to deployment %s domain %s, not %s domain %s",
				boundDep, boundDomain, deploymentID, domainID)
		}
		return nil
	})
}
