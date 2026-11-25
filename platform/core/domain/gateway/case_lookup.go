package gateway

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/core/dao"
	"grad/protocol"
)

// HasOrderOutcomeCase reports whether a registered order_outcome_cases row matches
// the exact (deployment_id, case_id, actor, task_id, request_hash) binding.
func (s *Service) HasOrderOutcomeCase(ctx context.Context, caseID, actor, taskID, requestHash string) (bool, error) {
	if s == nil || s.cfg.DB == nil {
		return false, protocol.NewError(protocol.ErrCodeStateUnavailable, "gateway database unavailable")
	}
	var exists bool
	err := s.cfg.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM order_outcome_cases
		WHERE deployment_id=$1 AND case_id=$2 AND actor=$3 AND task_id=$4 AND request_hash=$5)`,
		s.cfg.DeploymentID, caseID, actor, taskID, requestHash).Scan(&exists)
	if err != nil {
		return false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "query order_outcome_cases", err)
	}
	return exists, nil
}

// DeliverReceiptWithDB locks one committed outbox entry FOR UPDATE using db directly
// (without requiring a full gateway.Service instance), invokes send with the immutable
// persisted receipt, and atomically records attempt/delivery metadata.
func DeliverReceiptWithDB(
	ctx context.Context,
	db *pgxpool.Pool,
	deploymentID, caseID string,
	sendRevision, checkNo int64,
	send ReceiptSender,
) error {
	if db == nil {
		return fmt.Errorf("gateway database pool is required")
	}
	if send == nil {
		return fmt.Errorf("receipt sender is required")
	}
	var sendErr error
	txErr := dao.RunInTx(ctx, db, func(tx dao.Tx) error {
		rows, err := tx.Query(ctx, `SELECT
			deployment_id, case_id, send_revision, check_no, receipt_json, delivered_at, attempts, last_error
			FROM order_outcome_outbox
			WHERE deployment_id=$1 AND case_id=$2 AND send_revision=$3 AND check_no=$4
			FOR UPDATE`,
			deploymentID, caseID, sendRevision, checkNo,
		)
		if err != nil {
			return err
		}
		locked, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[OutboxEntry])
		if err != nil {
			return err
		}
		var persisted OrderOutcomeReceipt
		if err := json.Unmarshal(locked.ReceiptJSON, &persisted); err != nil {
			return err
		}
		sendErr = send(ctx, persisted)
		lastError := ""
		if sendErr != nil {
			lastError = sendErr.Error()
		}
		_, err = tx.Exec(ctx, `UPDATE order_outcome_outbox
			SET attempts = attempts + 1,
			    last_error = $5,
			    delivered_at = CASE WHEN $5 = '' THEN EXTRACT(EPOCH FROM clock_timestamp())::bigint ELSE delivered_at END
			WHERE deployment_id=$1 AND case_id=$2 AND send_revision=$3 AND check_no=$4`,
			deploymentID, caseID, sendRevision, checkNo, lastError,
		)
		return err
	})
	if txErr != nil {
		return txErr
	}
	return sendErr
}
