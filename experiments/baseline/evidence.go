package baseline

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"grad/experiments/harness"
	"grad/protocol"
)

const (
	// RequestColumns defines the exact public whitelist header for requests.csv.
	RequestColumns = "run_id,configuration,case_id,mode,action,actor,task_id,amount_minor,idempotency_key,planned_at,started_at,finished_at,challenge_ns,execute_ns,request_id,request_hash,challenge_id,decision_id,quote_id,order_id,http_status,code,disposition,failure_stage,state_source,revision,state_read_at,block_number,block_hash,probe_tx_id,probe_block,probe_sent_at,probe_deadline,probe_sent_mono_ns,probe_deadline_mono_ns,probe_checked_mono_ns,context_version,context_observed_at,context_access_deadline,decision_at,effective_deadline,state_rechecks,signature_cache_hits,signature_cache_misses"
	// OrderColumns defines the exact public whitelist header for order_checks.csv.
	OrderColumns = "run_id,configuration,case_id,task_id,quote_id,idempotency_key,challenge_id,challenge_consumed,decision_id,decision_outcome,decision_code,quote_amount_minor,order_rows_before,order_rows_after,order_key_rows,order_key_status,order_id,creation_decision_id,order_status,verdict,failure_reason"
)

type nullString struct {
	Value string
	Valid bool
}

func someString(v string) nullString { return nullString{Value: v, Valid: true} }

func (n nullString) MarshalCSV() ([]byte, error) {
	if !n.Valid {
		return []byte("null"), nil
	}
	return []byte(n.Value), nil
}

func (n nullString) ptr() *string {
	if !n.Valid {
		return nil
	}
	v := n.Value
	return &v
}

type nullInt64 struct {
	Value int64
	Valid bool
}

func someInt64(v int64) nullInt64 { return nullInt64{Value: v, Valid: true} }

func (n nullInt64) MarshalCSV() ([]byte, error) {
	if !n.Valid {
		return []byte("null"), nil
	}
	return strconv.AppendInt(nil, n.Value, 10), nil
}

func (n nullInt64) ptr() *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Value
	return &v
}

func (n nullInt64) intPtr() *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Value)
	return &v
}

type nullBool struct {
	Value bool
	Valid bool
}

func someBool(v bool) nullBool { return nullBool{Value: v, Valid: true} }

func (n nullBool) MarshalCSV() ([]byte, error) {
	if !n.Valid {
		return []byte("null"), nil
	}
	return strconv.AppendBool(nil, n.Value), nil
}

type nullTime struct {
	Value time.Time
	Valid bool
}

func someTime(v time.Time) nullTime {
	if v.IsZero() {
		return nullTime{}
	}
	return nullTime{Value: v.UTC(), Valid: true}
}

func (n nullTime) MarshalCSV() ([]byte, error) {
	if !n.Valid || n.Value.IsZero() {
		return []byte("null"), nil
	}
	return []byte(n.Value.UTC().Format(time.RFC3339Nano)), nil
}

// RequestRow encodes one whitelisted public row in requests.csv.
// Only explicit CSV-tagged public fields are exported; private credentials and disclosures never exist on this type.
type RequestRow struct {
	RunID                 string     `csv:"run_id"`
	Configuration         string     `csv:"configuration"`
	CaseID                string     `csv:"case_id"`
	Mode                  string     `csv:"mode"`
	Action                string     `csv:"action"`
	Actor                 nullString `csv:"actor"`
	TaskID                nullString `csv:"task_id"`
	AmountMinor           int64      `csv:"amount_minor"`
	IdempotencyKey        nullString `csv:"idempotency_key"`
	PlannedAt             nullTime   `csv:"planned_at"`
	StartedAt             nullTime   `csv:"started_at"`
	FinishedAt            nullTime   `csv:"finished_at"`
	ChallengeNs           nullInt64  `csv:"challenge_ns"`
	ExecuteNs             nullInt64  `csv:"execute_ns"`
	RequestID             nullString `csv:"request_id"`
	RequestHash           nullString `csv:"request_hash"`
	ChallengeID           nullString `csv:"challenge_id"`
	DecisionID            nullString `csv:"decision_id"`
	QuoteID               nullString `csv:"quote_id"`
	OrderID               nullString `csv:"order_id"`
	HTTPStatus            nullInt64  `csv:"http_status"`
	Code                  nullString `csv:"code"`
	Disposition           string     `csv:"disposition"`
	FailureStage          nullString `csv:"failure_stage"`
	StateSource           nullString `csv:"state_source"`
	Revision              nullInt64  `csv:"revision"`
	StateReadAt           nullTime   `csv:"state_read_at"`
	BlockNumber           nullInt64  `csv:"block_number"`
	BlockHash             nullString `csv:"block_hash"`
	ProbeTxID             nullString `csv:"probe_tx_id"`
	ProbeBlock            nullInt64  `csv:"probe_block"`
	ProbeSentAt           nullTime   `csv:"probe_sent_at"`
	ProbeDeadline         nullTime   `csv:"probe_deadline"`
	ProbeSentMonoNs       nullInt64  `csv:"probe_sent_mono_ns"`
	ProbeDeadlineMonoNs   nullInt64  `csv:"probe_deadline_mono_ns"`
	ProbeCheckedMonoNs    nullInt64  `csv:"probe_checked_mono_ns"`
	ContextVersion        nullInt64  `csv:"context_version"`
	ContextObservedAt     nullTime   `csv:"context_observed_at"`
	ContextAccessDeadline nullTime   `csv:"context_access_deadline"`
	DecisionAt            nullTime   `csv:"decision_at"`
	EffectiveDeadline     nullTime   `csv:"effective_deadline"`
	StateRechecks         nullInt64  `csv:"state_rechecks"`
	SignatureCacheHits    nullInt64  `csv:"signature_cache_hits"`
	SignatureCacheMisses  nullInt64  `csv:"signature_cache_misses"`

	// Internal HTTP order response observations used for primary-DB consistency verification; never written to CSV.
	httpOrderStatus      nullString `csv:"-"`
	httpOrderAmountMinor nullInt64  `csv:"-"`
}

// OrderCheckRow encodes one whitelisted public row in order_checks.csv.
type OrderCheckRow struct {
	RunID              string     `csv:"run_id"`
	Configuration      string     `csv:"configuration"`
	CaseID             string     `csv:"case_id"`
	TaskID             nullString `csv:"task_id"`
	QuoteID            nullString `csv:"quote_id"`
	IdempotencyKey     nullString `csv:"idempotency_key"`
	ChallengeID        nullString `csv:"challenge_id"`
	ChallengeConsumed  nullBool   `csv:"challenge_consumed"`
	DecisionID         nullString `csv:"decision_id"`
	DecisionOutcome    nullString `csv:"decision_outcome"`
	DecisionCode       nullString `csv:"decision_code"`
	QuoteAmountMinor   nullInt64  `csv:"quote_amount_minor"`
	OrderRowsBefore    nullInt64  `csv:"order_rows_before"`
	OrderRowsAfter     nullInt64  `csv:"order_rows_after"`
	OrderKeyRows       nullInt64  `csv:"order_key_rows"`
	OrderKeyStatus     nullString `csv:"order_key_status"`
	OrderID            nullString `csv:"order_id"`
	CreationDecisionID nullString `csv:"creation_decision_id"`
	OrderStatus        nullString `csv:"order_status"`
	Verdict            string     `csv:"verdict"`
	FailureReason      nullString `csv:"failure_reason"`
}

// FailureRecord records a sanitized failure diagnostic in summary.json.
type FailureRecord struct {
	Scope         string  `json:"scope"`
	FailureStage  string  `json:"failure_stage"`
	Reason        string  `json:"reason"`
	Configuration string  `json:"configuration,omitempty"`
	CaseID        string  `json:"case_id,omitempty"`
	Action        string  `json:"action,omitempty"`
	HTTPStatus    *int    `json:"http_status,omitempty"`
	Code          *string `json:"code,omitempty"`
	RequestID     *string `json:"request_id,omitempty"`
	ChallengeID   *string `json:"challenge_id,omitempty"`
	DecisionID    *string `json:"decision_id"`
}

// GroupSummary aggregates case verdicts for one (configuration, mode) pair.
type GroupSummary struct {
	Cases  int `json:"cases"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
}

// CaseResult summarizes one planned baseline order case.
type CaseResult struct {
	Configuration  string  `json:"configuration"`
	CaseID         string  `json:"case_id"`
	Mode           string  `json:"mode"`
	AmountMinor    int64   `json:"amount_minor"`
	ExpectedStatus int     `json:"expected_status"`
	ExpectedCode   string  `json:"expected_code"`
	ActualStatus   *int    `json:"actual_status"`
	ActualCode     *string `json:"actual_code"`
	OrderDelta     *int64  `json:"order_delta"`
	OrderKeyRows   *int64  `json:"order_key_rows"`
	Passed         bool    `json:"passed"`
	FailureReason  string  `json:"failure_reason,omitempty"`
}

// PairResult summarizes cross-configuration (C0 vs B0 vs B1) agreement for one paired case.
type PairResult struct {
	Seed          int    `json:"seed"`
	CaseID        string `json:"case_id"`
	Mode          string `json:"mode"`
	AmountMinor   int64  `json:"amount_minor"`
	Passed        bool   `json:"passed"`
	FailureReason string `json:"failure_reason,omitempty"`
}

// RequestAccountingSummary balances planned, started, completed, dropped, and outcome request counts.
type RequestAccountingSummary struct {
	Planned   int `json:"planned"`
	Started   int `json:"started"`
	Dropped   int `json:"dropped"`
	Completed int `json:"completed"`
	Timeout   int `json:"timeout"`
	Allowed   int `json:"allowed"`
	Denied    int `json:"denied"`
	Error     int `json:"error"`
}

// SecretScanSummary reports the post-export sensitive-data scan outcome.
type SecretScanSummary struct {
	Passed   bool `json:"passed"`
	Files    int  `json:"files"`
	Findings int  `json:"findings"`
}

// Summary is the structured summary exported to summary.json and returned by Run.
type Summary struct {
	RunID                  string                   `json:"run_id"`
	Seed                   int                      `json:"seed"`
	Passed                 bool                     `json:"passed"`
	Failures               []FailureRecord          `json:"failures"`
	B1SignatureCacheHits   int64                    `json:"b1_signature_cache_hits"`
	ByConfigurationAndMode map[string]GroupSummary  `json:"by_configuration_and_mode"`
	CaseResults            []CaseResult             `json:"case_results"`
	PairResults            []PairResult             `json:"pair_results"`
	RequestAccounting      RequestAccountingSummary `json:"request_accounting"`
	SecretScan             *SecretScanSummary       `json:"secret_scan,omitempty"`
}

// Evidence manages the four exported public artifacts of one baseline attempt.
type Evidence struct {
	Directory string
	Manifest  map[string]any
	Requests  []RequestRow
	Orders    []OrderCheckRow
	Summary   Summary
}

// NewEvidence creates a brand-new evidence directory (failing if dir already exists) and
// initializes the complete 24-request and 12-order plan.
func NewEvidence(dir, runID string, in *Inputs) (*Evidence, error) {
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil, err
	}
	started := time.Now().UTC()
	e := &Evidence{
		Directory: dir,
		Manifest:  map[string]any{},
		Summary: Summary{
			RunID:    runID,
			Seed:     in.Seed,
			Passed:   false,
			Failures: []FailureRecord{},
		},
	}
	for _, key := range strings.Split("run_id,seed,started_at,source_commit,go_version,host,clock,clock_resolution_ns,topology,artifact_locks,deployment_id,channel_id,genesis_hash,chaincode,root,fixture_digest,material_digest,registry_input_digest,registry_readback,policy_source_digest,policy_digest,configurations,driver,planned_cases", ",") {
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

	e.Requests = make([]RequestRow, 0, len(in.Cases)*len(in.Fixture.Actions))
	e.Orders = make([]OrderCheckRow, 0, len(in.Cases))
	for _, c := range in.Cases {
		for _, action := range in.Fixture.Actions {
			amount := c.AmountMinor
			if action == protocol.ActionQuoteRead {
				amount = 0
			}
			e.Requests = append(e.Requests, RequestRow{
				RunID:         runID,
				Configuration: c.Configuration,
				CaseID:        c.CaseID,
				Mode:          c.Mode,
				Action:        action,
				AmountMinor:   amount,
				PlannedAt:     someTime(started),
				Disposition:   "dropped",
				FailureStage:  someString("preparation"),
			})
		}
		e.Orders = append(e.Orders, OrderCheckRow{
			RunID:         runID,
			Configuration: c.Configuration,
			CaseID:        c.CaseID,
			Verdict:       "FAIL",
			FailureReason: someString("not executed"),
		})
	}

	results := make([]CaseResult, 0, len(in.Cases))
	pairs := make([]PairResult, 0, 4)
	for n, c := range in.Cases {
		results = append(results, CaseResult{
			Configuration:  c.Configuration,
			CaseID:         c.CaseID,
			Mode:           c.Mode,
			AmountMinor:    c.AmountMinor,
			ExpectedStatus: c.ExpectedStatus,
			ExpectedCode:   c.ExpectedCode,
			Passed:         false,
			FailureReason:  "not executed",
		})
		if n < 4 {
			pairs = append(pairs, PairResult{
				Seed:          in.Seed,
				CaseID:        c.CaseID,
				Mode:          c.Mode,
				AmountMinor:   c.AmountMinor,
				Passed:        false,
				FailureReason: "not executed",
			})
		}
	}
	e.Summary.CaseResults = results
	e.Summary.PairResults = pairs
	e.Summary.RequestAccounting = e.Account()
	return e, nil
}

// Save atomically writes manifest.json, requests.csv, order_checks.csv, and summary.json.
func (e *Evidence) Save() error {
	e.Summary.RequestAccounting = e.Account()
	if err := harness.WriteJSON(filepath.Join(e.Directory, "manifest.json"), e.Manifest); err != nil {
		return err
	}
	if err := harness.WriteCSV(filepath.Join(e.Directory, "requests.csv"), e.Requests); err != nil {
		return err
	}
	if err := harness.WriteCSV(filepath.Join(e.Directory, "order_checks.csv"), e.Orders); err != nil {
		return err
	}
	return harness.WriteJSON(filepath.Join(e.Directory, "summary.json"), e.Summary)
}

// Account tallies planned, started, dropped, completed, timeout, and outcome counts
// so every planned action remains explainable even on failure.
func (e *Evidence) Account() RequestAccountingSummary {
	a := RequestAccountingSummary{Planned: len(e.Requests)}
	for _, row := range e.Requests {
		switch row.Disposition {
		case "dropped":
			a.Dropped++
		case "timeout":
			a.Started++
			a.Timeout++
		case "allowed":
			a.Started++
			a.Completed++
			a.Allowed++
		case "denied":
			a.Started++
			a.Completed++
			a.Denied++
		case "error":
			a.Started++
			a.Completed++
			a.Error++
		default:
			a.Started++
			a.Completed++
			a.Error++
		}
	}
	return a
}
