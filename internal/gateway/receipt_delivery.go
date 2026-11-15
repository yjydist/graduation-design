package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DeliverStoredReceipt is the C host's delivery callback for an embedded tool runtime.
func DeliverStoredReceipt(ctx context.Context, db *pgxpool.Pool, deploymentID string, client *http.Client, target string, receipt OrderOutcomeReceipt) (*OrderOutcomeReceiptResponse, error) {
	s := &Server{cfg: Config{DB: db, DeploymentID: deploymentID}}
	return s.DeliverReceipt(ctx, client, target, receipt)
}

// DeliverReceipt sends only the immutable receipt committed by C's audit transaction.
// The host provides an authenticated C service client, separate from buyer clients.
func (s *Server) DeliverReceipt(ctx context.Context, client *http.Client, target string, receipt OrderOutcomeReceipt) (*OrderOutcomeReceiptResponse, error) {
	if client == nil {
		return nil, fmt.Errorf("authenticated receipt client required")
	}
	tx, err := s.cfg.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT receipt_json FROM order_outcome_outbox WHERE deployment_id=$1 AND case_id=$2 AND send_revision=$3 AND check_no=$4 FOR UPDATE`, s.cfg.DeploymentID, receipt.CaseID, receipt.SendRevision, receipt.CheckNo).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var persisted OrderOutcomeReceipt
	if err = json.Unmarshal(raw, &persisted); err != nil {
		return nil, err
	}
	a, _ := json.Marshal(receipt)
	b, _ := json.Marshal(persisted)
	if !bytes.Equal(a, b) {
		return nil, fmt.Errorf("receipt differs from durable outbox")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, sendErr := client.Do(req)
	var result OrderOutcomeReceiptResponse
	if sendErr == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			sendErr = fmt.Errorf("receipt delivery HTTP %d", resp.StatusCode)
		} else {
			raw, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxExecuteBodyBytes+1))
			if readErr != nil {
				sendErr = readErr
			} else {
				sendErr = json.Unmarshal(raw, &result)
			}
		}
	}
	if sendErr == nil {
		echo, _ := json.Marshal(result.Receipt)
		if !bytes.Equal(echo, b) {
			sendErr = fmt.Errorf("receipt acknowledgement binding mismatch")
		}
	}
	lastError := ""
	if sendErr != nil {
		lastError = sendErr.Error()
	}
	if _, err = tx.Exec(ctx, `UPDATE order_outcome_outbox SET attempts=attempts+1,last_error=$5,delivered_at=CASE WHEN $5='' THEN EXTRACT(EPOCH FROM clock_timestamp())::bigint ELSE delivered_at END WHERE deployment_id=$1 AND case_id=$2 AND send_revision=$3 AND check_no=$4`, s.cfg.DeploymentID, receipt.CaseID, receipt.SendRevision, receipt.CheckNo, lastError); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	if sendErr != nil {
		return nil, sendErr
	}
	return &result, nil
}

// DeliverPendingReceipts resumes delivery after restart without rerunning audits or
// allocating another checkNo. Receiver deduplication handles lost acknowledgements.
func (s *Server) DeliverPendingReceipts(ctx context.Context, client *http.Client, target string) (int, error) {
	rows, err := s.cfg.DB.Query(ctx, `SELECT receipt_json FROM order_outcome_outbox WHERE deployment_id=$1 AND delivered_at IS NULL ORDER BY case_id,send_revision,check_no`, s.cfg.DeploymentID)
	if err != nil {
		return 0, err
	}
	var pending []OrderOutcomeReceipt
	for rows.Next() {
		var raw []byte
		var r OrderOutcomeReceipt
		if err = rows.Scan(&raw); err != nil {
			break
		}
		if err = json.Unmarshal(raw, &r); err != nil {
			break
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err != nil {
		return 0, err
	}
	if err = rows.Err(); err != nil {
		return 0, err
	}
	count := 0
	for _, r := range pending {
		if _, err = s.DeliverReceipt(ctx, client, target, r); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
