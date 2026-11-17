package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"graduation-design/internal/experiment"
)

func (r *baselineRun) decision(ctx context.Context, db *pgxpool.Pool, row experiment.Row) error {
	if row["decision_id"] == nil {
		return fmt.Errorf("no decision returned")
	}
	var raw []byte
	if err := db.QueryRow(ctx, `SELECT to_jsonb(d) FROM decisions d WHERE deployment_id=$1 AND decision_id=$2`, r.d.DeploymentID, row["decision_id"]).Scan(&raw); err != nil {
		return err
	}
	var d map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&d); err != nil {
		return err
	}
	for _, key := range []string{"state_source", "revision", "state_read_at", "block_number", "block_hash", "probe_tx_id", "probe_block", "probe_sent_mono_ns", "probe_deadline_mono_ns", "context_version", "state_rechecks", "probe_checked_mono_ns"} {
		row[key] = d[key]
	}
	for _, key := range []string{"probe_sent_at", "probe_deadline", "context_observed_at", "context_access_deadline", "decision_at", "effective_deadline"} {
		if value, ok := d[key].(json.Number); ok {
			sec, err := value.Int64()
			if err != nil {
				return err
			}
			row[key] = time.Unix(sec, 0).UTC()
		} else {
			row[key] = nil
		}
	}
	if row["request_id"] != d["request_id"] || row["challenge_id"] != d["challenge_id"] || row["task_id"] != d["task_id"] || row["actor"] != d["actor"] || row["idempotency_key"] != d["idempotency_key"] || row["code"] != d["code"] {
		return fmt.Errorf("HTTP decision association mismatch")
	}
	if row["disposition"] == "allowed" && d["outcome"] != "ALLOW" || row["disposition"] == "denied" && d["outcome"] != "DENY" {
		return fmt.Errorf("HTTP disposition differs from stored decision")
	}
	if row["disposition"] == "allowed" && (row["quote_id"] != d["quote_id"] || row["order_id"] != d["order_id"]) {
		return fmt.Errorf("HTTP resource IDs differ from stored decision")
	}
	var consumed *int64
	var challengeDecision *string
	var requestHash string
	if err := db.QueryRow(ctx, `SELECT consumed_at,decision_id,request_hash FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`, r.d.DeploymentID, row["challenge_id"]).Scan(&consumed, &challengeDecision, &requestHash); err != nil {
		return err
	}
	if consumed == nil || challengeDecision == nil || *challengeDecision != row["decision_id"] || requestHash != row["request_hash"] {
		return fmt.Errorf("challenge and decision association mismatch")
	}
	return nil
}

func (r *baselineRun) orderCheck(ctx context.Context, db *pgxpool.Pool, c experiment.Case, row, check experiment.Row, before int64, quoteID string) error {
	check["quote_id"] = quoteID
	check["challenge_id"] = row["challenge_id"]
	check["decision_id"] = row["decision_id"]
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	var after, keys, quoteAmount int64
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM orders WHERE deployment_id=$1 AND task_id=$2`, r.d.DeploymentID, row["task_id"]).Scan(&after); err != nil {
		return err
	}
	check["order_rows_after"] = after
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM business_keys WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND action='order.create' AND idempotency_key=$4`, r.d.DeploymentID, row["actor"], row["task_id"], row["idempotency_key"]).Scan(&keys); err != nil {
		return err
	}
	check["order_key_rows"] = keys
	var qActor, qTask string
	if err = tx.QueryRow(ctx, `SELECT total_amount_minor,actor,task_id FROM quotes WHERE deployment_id=$1 AND quote_id=$2`, r.d.DeploymentID, quoteID).Scan(&quoteAmount, &qActor, &qTask); err != nil {
		return err
	}
	check["quote_amount_minor"] = quoteAmount
	var consumed *int64
	var challengeDecision *string
	var requestHash string
	if err = tx.QueryRow(ctx, `SELECT consumed_at,decision_id,request_hash FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`, r.d.DeploymentID, row["challenge_id"]).Scan(&consumed, &challengeDecision, &requestHash); err != nil {
		return err
	}
	check["challenge_consumed"] = consumed != nil
	var outcome, code string
	if err = tx.QueryRow(ctx, `SELECT outcome,code FROM decisions WHERE deployment_id=$1 AND decision_id=$2`, r.d.DeploymentID, row["decision_id"]).Scan(&outcome, &code); err != nil {
		return err
	}
	check["decision_outcome"] = outcome
	check["decision_code"] = code
	var ownOrders int64
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM orders WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND idempotency_key=$4`, r.d.DeploymentID, row["actor"], row["task_id"], row["idempotency_key"]).Scan(&ownOrders); err != nil {
		return err
	}
	httpOK := row["http_status"] == c.ExpectedStatus && row["code"] == c.ExpectedCode && row["failure_stage"] == nil
	primaryOK := quoteAmount == c.AmountMinor && qActor == row["actor"] && qTask == row["task_id"] &&
		consumed != nil && challengeDecision != nil && *challengeDecision == row["decision_id"] && requestHash == row["request_hash"]
	if c.AmountMinor == 80000 {
		var id, status, decision, qid string
		var amount int64
		if ownOrders == 1 {
			if err = tx.QueryRow(ctx, `SELECT order_id,status,decision_id,quote_id,total_amount_minor FROM orders WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND idempotency_key=$4`, r.d.DeploymentID, row["actor"], row["task_id"], row["idempotency_key"]).Scan(&id, &status, &decision, &qid, &amount); err != nil {
				return err
			}
			check["order_id"] = id
			check["order_status"] = status
			check["creation_decision_id"] = decision
		}
		var keyStatus, keyResource, keyDecision string
		if keys == 1 {
			if err = tx.QueryRow(ctx, `SELECT status,resource_id,decision_id FROM business_keys WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND action='order.create' AND idempotency_key=$4`, r.d.DeploymentID, row["actor"], row["task_id"], row["idempotency_key"]).Scan(&keyStatus, &keyResource, &keyDecision); err != nil {
				return err
			}
			check["order_key_status"] = keyStatus
		}
		httpOK = httpOK && id != "" && row["order_id"] == id && row["quote_id"] == quoteID &&
			row["order_status"] == "CREATED" && row["order_amount_minor"] == c.AmountMinor
		primaryOK = primaryOK && after == before+1 && keys == 1 && ownOrders == 1 && outcome == "ALLOW" && code == "ALLOW" &&
			status == "CREATED" && decision == row["decision_id"] && qid == quoteID && amount == c.AmountMinor &&
			keyStatus == "COMPLETED" && keyResource == id && keyDecision == decision
	} else {
		httpOK = httpOK && row["order_id"] == nil
		primaryOK = primaryOK && after == before && ownOrders == 0 && keys == 0 && outcome == "DENY" && code == "AMOUNT_LIMIT_EXCEEDED"
	}
	if httpOK && primaryOK {
		check["verdict"] = "PASS"
		check["failure_reason"] = nil
	} else {
		check["verdict"] = "FAIL"
		check["failure_reason"] = "HTTP and primary database facts did not meet the paired case expectation"
	}
	return tx.Commit(ctx)
}

func (r *baselineRun) compare() bool {
	caseResults := []any{}
	pairResults := []any{}
	by := map[string]map[string]int{}
	passed := len(r.evidence.Summary["failures"].([]any)) == 0
	seenChallenges := map[string]bool{}
	for n, c := range r.inputs.Cases {
		q, o, check := r.evidence.Requests[2*n], r.evidence.Requests[2*n+1], r.evidence.Orders[n]
		profile, _ := experiment.BaselineConfiguration(c.Configuration)
		ok := check["verdict"] == "PASS" && q["http_status"] == 200 && q["code"] == "ALLOW" && q["failure_stage"] == nil
		for _, row := range []experiment.Row{q, o} {
			challenge, _ := row["challenge_id"].(string)
			if challenge == "" || seenChallenges[challenge] {
				ok = false
			}
			seenChallenges[challenge] = true
			if row["state_source"] != profile.StateSource {
				ok = false
			}
			if c.Configuration == "C0" {
				if row["revision"] == nil || row["state_read_at"] == nil || row["block_number"] != nil || row["probe_tx_id"] != nil {
					ok = false
				}
			} else {
				if row["revision"] != nil || row["state_read_at"] != nil || row["block_number"] == nil || row["probe_tx_id"] == nil {
					ok = false
				}
			}
			if c.Configuration != "B1" && row["signature_cache_hits"] != int64(0) {
				ok = false
			}
		}
		if !ok {
			passed = false
		}
		key := c.Configuration + "/" + c.Mode
		if by[key] == nil {
			by[key] = map[string]int{"cases": 0, "passed": 0, "failed": 0}
		}
		by[key]["cases"]++
		if ok {
			by[key]["passed"]++
		} else {
			by[key]["failed"]++
		}
		caseResults = append(caseResults, map[string]any{"configuration": c.Configuration, "case_id": c.CaseID, "mode": c.Mode, "amount_minor": c.AmountMinor, "expected_status": c.ExpectedStatus, "actual_status": o["http_status"], "expected_code": c.ExpectedCode, "actual_code": o["code"], "order_delta": delta(check), "order_key_rows": check["order_key_rows"], "passed": ok})
	}
	for n := 0; n < 4; n++ {
		ok := true
		for _, offset := range []int{4, 8} {
			a, b := r.evidence.Requests[2*n+1], r.evidence.Requests[2*(n+offset)+1]
			x, y := r.evidence.Orders[n], r.evidence.Orders[n+offset]
			if a["http_status"] != b["http_status"] || a["code"] != b["code"] || x["verdict"] != "PASS" || y["verdict"] != "PASS" || delta(x) != delta(y) || x["order_key_rows"] != y["order_key_rows"] {
				ok = false
			}
		}
		if !ok {
			passed = false
		}
		pairResults = append(pairResults, map[string]any{"seed": r.inputs.Seed, "case_id": r.inputs.Cases[n].CaseID, "mode": r.inputs.Cases[n].Mode, "amount_minor": r.inputs.Cases[n].AmountMinor, "passed": ok})
	}
	var hits int64
	for _, row := range r.evidence.Requests {
		if row["configuration"] == "B1" {
			n, _ := row["signature_cache_hits"].(int64)
			hits += n
		}
	}
	if hits == 0 {
		passed = false
	}
	r.evidence.Summary["b1_signature_cache_hits"] = hits
	r.evidence.Summary["by_configuration_and_mode"] = by
	r.evidence.Summary["case_results"] = caseResults
	r.evidence.Summary["pair_results"] = pairResults
	return passed
}

func delta(row experiment.Row) any {
	a, okA := row["order_rows_after"].(int64)
	b, okB := row["order_rows_before"].(int64)
	if !okA || !okB {
		return nil
	}
	return a - b
}
