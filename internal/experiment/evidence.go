package experiment

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const RequestColumns = "run_id,configuration,case_id,mode,action,actor,task_id,amount_minor,idempotency_key,planned_at,started_at,finished_at,challenge_ns,execute_ns,request_id,request_hash,challenge_id,decision_id,quote_id,order_id,http_status,code,disposition,failure_stage,state_source,revision,state_read_at,block_number,block_hash,probe_tx_id,probe_block,probe_sent_at,probe_deadline,probe_sent_mono_ns,probe_deadline_mono_ns,probe_checked_mono_ns,context_version,context_observed_at,context_access_deadline,decision_at,effective_deadline,state_rechecks,signature_cache_hits,signature_cache_misses"
const OrderColumns = "run_id,configuration,case_id,task_id,quote_id,idempotency_key,challenge_id,challenge_consumed,decision_id,decision_outcome,decision_code,quote_amount_minor,order_rows_before,order_rows_after,order_key_rows,order_key_status,order_id,creation_decision_id,order_status,verdict,failure_reason"

// Row uses a fixed public column whitelist; unknown or sensitive fields are never exported.
type Row map[string]any

type Evidence struct {
	Directory string
	Manifest  map[string]any
	Requests  []Row
	Orders    []Row
	Summary   map[string]any
}

func NewEvidence(dir, runID string, in *Inputs) (*Evidence, error) {
	if err := os.Mkdir(dir, 0755); err != nil {
		return nil, err
	}
	started := time.Now().UTC()
	e := &Evidence{Directory: dir, Manifest: map[string]any{}, Summary: map[string]any{"run_id": runID, "seed": in.Seed, "passed": false, "failures": []any{}}}
	for _, key := range strings.Split("run_id,seed,started_at,source_commit,go_version,host,clock,topology,artifact_locks,deployment_id,channel_id,genesis_hash,chaincode,root,fixture_digest,material_digest,registry_input_digest,registry_readback,policy_source_digest,policy_digest,configurations,driver,planned_cases", ",") {
		e.Manifest[key] = nil
	}
	digest, err := in.Digest()
	if err != nil {
		return nil, err
	}
	e.Manifest["run_id"] = runID
	e.Manifest["seed"] = in.Seed
	e.Manifest["started_at"] = started
	e.Manifest["fixture_digest"] = digest
	e.Manifest["policy_source_digest"] = in.PolicySourceDigest
	e.Manifest["planned_cases"] = in.Cases
	e.Manifest["driver"] = "deterministic wallet tools"
	for _, c := range in.Cases {
		for _, action := range in.Fixture.Actions {
			amount := c.AmountMinor
			if action == "quote.read" {
				amount = 0
			}
			e.Requests = append(e.Requests, Row{"run_id": runID, "configuration": c.Configuration, "case_id": c.CaseID, "mode": c.Mode, "action": action, "amount_minor": amount, "planned_at": started, "disposition": "dropped", "failure_stage": "preparation"})
		}
		e.Orders = append(e.Orders, Row{"run_id": runID, "configuration": c.Configuration, "case_id": c.CaseID, "verdict": "FAIL", "failure_reason": "not executed"})
	}
	results := []any{}
	pairs := []any{}
	for n, c := range in.Cases {
		results = append(results, map[string]any{"configuration": c.Configuration, "case_id": c.CaseID, "mode": c.Mode, "amount_minor": c.AmountMinor, "expected_status": c.ExpectedStatus, "expected_code": c.ExpectedCode, "actual_status": nil, "actual_code": nil, "order_delta": nil, "order_key_rows": nil, "passed": false, "failure_reason": "not executed"})
		if n < 4 {
			pairs = append(pairs, map[string]any{"seed": in.Seed, "case_id": c.CaseID, "mode": c.Mode, "amount_minor": c.AmountMinor, "passed": false, "failure_reason": "not executed"})
		}
	}
	e.Summary["case_results"] = results
	e.Summary["pair_results"] = pairs
	e.Summary["by_configuration_and_mode"] = nil
	e.Summary["request_accounting"] = e.Account()
	return e, nil
}

func (e *Evidence) Save() error {
	e.Summary["request_accounting"] = e.Account()
	if err := saveJSON(filepath.Join(e.Directory, "manifest.json"), e.Manifest); err != nil {
		return err
	}
	if err := saveCSV(filepath.Join(e.Directory, "requests.csv"), RequestColumns, e.Requests); err != nil {
		return err
	}
	if err := saveCSV(filepath.Join(e.Directory, "order_checks.csv"), OrderColumns, e.Orders); err != nil {
		return err
	}
	return saveJSON(filepath.Join(e.Directory, "summary.json"), e.Summary)
}

func saveJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0644)
}
func cell(value any) string {
	if value == nil {
		return "null"
	}
	switch v := value.(type) {
	case time.Time:
		if v.IsZero() {
			return "null"
		}
		return v.UTC().Format(time.RFC3339Nano)
	case *time.Time:
		if v == nil || v.IsZero() {
			return "null"
		}
		return v.UTC().Format(time.RFC3339Nano)
	case *int64:
		if v == nil {
			return "null"
		}
		return strconv.FormatInt(*v, 10)
	case *string:
		if v == nil {
			return "null"
		}
		return *v
	default:
		return fmt.Sprint(value)
	}
}
func saveCSV(path, columns string, rows []Row) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	keys := strings.Split(columns, ",")
	if err = w.Write(keys); err != nil {
		f.Close()
		return err
	}
	for _, row := range rows {
		values := make([]string, len(keys))
		for n, key := range keys {
			values[n] = cell(row[key])
		}
		if err = w.Write(values); err != nil {
			f.Close()
			return err
		}
	}
	w.Flush()
	if err = w.Error(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Account is also used on failure so every planned action remains explainable.
func (e *Evidence) Account() map[string]int {
	c := map[string]int{"planned": len(e.Requests), "started": 0, "dropped": 0, "completed": 0, "timeout": 0, "allowed": 0, "denied": 0, "error": 0}
	for _, row := range e.Requests {
		d, _ := row["disposition"].(string)
		c[d]++
		if d != "dropped" {
			c["started"]++
		}
		if d == "allowed" || d == "denied" || d == "error" {
			c["completed"]++
		}
	}
	return c
}
