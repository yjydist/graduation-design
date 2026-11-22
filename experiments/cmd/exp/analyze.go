package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"grad/experiments/harness"
)

const (
	E1AnalysisVersion = "e1-analyzer/v1"
	E6AnalysisVersion = "e6-analyzer/v1"
)

type e1RequestCSVRow struct {
	Case        string `csv:"case"`
	Mode        string `csv:"authorization_mode"`
	Method      string `csv:"method"`
	Path        string `csv:"path"`
	TaskID      string `csv:"task_id"`
	Action      string `csv:"action"`
	Key         string `csv:"idempotency_key"`
	StartedAt   string `csv:"started_at"`
	FinishedAt  string `csv:"finished_at"`
	DurationNs  string `csv:"duration_ns"`
	HTTPStatus  string `csv:"http_status"`
	RequestID   string `csv:"request_id"`
	ChallengeID string `csv:"challenge_id"`
	DecisionID  string `csv:"decision_id"`
	RequestHash string `csv:"request_hash"`
	QuoteID     string `csv:"quote_id"`
	OrderID     string `csv:"order_id"`
	Code        string `csv:"code"`
	AmountMinor string `csv:"amount_minor"`
}

type E1CaseAnalysis struct {
	Name          string `json:"name"`
	Pass          bool   `json:"pass"`
	Category      string `json:"category"` // pass, fail, upstream_blocked, not_executed
	MissingReason string `json:"missingReason,omitempty"`
	Error         string `json:"error,omitempty"`
}

type E1ModeReconciliation struct {
	Mode                   string            `json:"mode"`
	LLMTraceCases          []string          `json:"llmTraceCases"`
	LLMTraceModelMatch     bool              `json:"llmTraceModelMatch"`
	F05DelegationAnchored  bool              `json:"f05DelegationAnchored"`
	F15DelegationAnchored  bool              `json:"f15DelegationAnchored"`
	F06HTTPRoundTrips      int               `json:"f06HttpRoundTrips"`
	F06QuoteID             string            `json:"f06QuoteId,omitempty"`
	F06OrderID             string            `json:"f06OrderId,omitempty"`
	F06CreationDecisionID  string            `json:"f06CreationDecisionId,omitempty"`
	F06ChallengeIDs        []string          `json:"f06ChallengeIds,omitempty"`
	F06QuoteAmountMinor    int64             `json:"f06QuoteAmountMinor"`
	F06OrderAmountMinor    int64             `json:"f06OrderAmountMinor"`
	F06PrimaryDBMatched    bool              `json:"f06PrimaryDbMatched"`
	F07QuoteAmountMinor    int64             `json:"f07QuoteAmountMinor"`
	F07Denials             map[string]string `json:"f07Denials,omitempty"`
	F07ZeroOrderSideEffect bool              `json:"f07ZeroOrderSideEffect"`
	F08OrderID             string            `json:"f08OrderId,omitempty"`
	F08RetryReusedOrder    bool              `json:"f08RetryReusedOrder"`
	F14ExpiredDenied       bool              `json:"f14ExpiredDenied"`
	F15ReissuedAllowed     bool              `json:"f15ReissuedAllowed"`
	F16EvidenceHash        string            `json:"f16EvidenceHash,omitempty"`
	F16BindingsVerified    bool              `json:"f16BindingsVerified"`
	ProbeAndBlockChecked   int               `json:"probeAndBlockChecked"`
	Anomalies              []string          `json:"anomalies,omitempty"`
}

type E1BlockInterval struct {
	FirstExclusive    int64 `json:"firstExclusive"`
	LastInclusive     int64 `json:"lastInclusive"`
	NonProbeWriteKeys int   `json:"nonProbeWriteKeys"`
}

type E1RecomputedReport struct {
	AnalysisVersion             string                           `json:"analysisVersion"`
	Experiment                  string                           `json:"experiment"`
	SourceRunID                 string                           `json:"sourceRunId"`
	SourceRunDir                string                           `json:"sourceRunDir"`
	RunStatus                   string                           `json:"runStatus"`
	RunStage                    string                           `json:"runStage,omitempty"`
	RunError                    string                           `json:"runError,omitempty"`
	SourceCommit                string                           `json:"sourceCommit,omitempty"`
	DeploymentID                string                           `json:"deploymentId,omitempty"`
	ModelProvider               string                           `json:"modelProvider,omitempty"`
	ModelName                   string                           `json:"modelName,omitempty"`
	InputFilesSHA256            map[string]string                `json:"inputFilesSha256"`
	MissingInputFiles           []string                         `json:"missingInputFiles,omitempty"`
	SummaryVerdicts             int                              `json:"summaryVerdicts"`
	PassedCases                 int                              `json:"passedCases"`
	FailedCases                 int                              `json:"failedCases"`
	UpstreamBlockedCases        int                              `json:"upstreamBlockedCases"`
	NotExecutedCases            int                              `json:"notExecutedCases"`
	Cases                       []E1CaseAnalysis                 `json:"cases"`
	CapturedGatewayRequests     int                              `json:"capturedGatewayRequests"`
	LLMSessions                 int                              `json:"llmSessions"`
	LLMToolCalls                int                              `json:"llmToolCalls"`
	LLMErrorSessions            int                              `json:"llmErrorSessions"`
	Blocks                      int                              `json:"blocks"`
	BlocksContinuous            bool                             `json:"blocksContinuous"`
	StoredQuotes                int                              `json:"storedQuotes"`
	StoredOrders                int                              `json:"storedOrders"`
	StoredDecisions             int                              `json:"storedDecisions"`
	StoredChallenges            int                              `json:"storedChallenges"`
	StoredBusinessKeys          int                              `json:"storedBusinessKeys"`
	AuthorizationModes          map[string]*E1ModeReconciliation `json:"authorizationModes"`
	F06BlockInterval            *E1BlockInterval                 `json:"f06BlockIntervalAfterFirstDecision,omitempty"`
	PublishedAuditChecked       bool                             `json:"publishedAuditChecked"`
	PublishedAuditMatches       bool                             `json:"publishedAuditMatches"`
	PublishedAuditMismatches    []string                         `json:"publishedAuditMismatches,omitempty"`
	ReconciliationPassed        bool                             `json:"reconciliationPassed"`
	Anomalies                   []string                         `json:"anomalies,omitempty"`
	FailureAndMissingDiagnostic []string                         `json:"failureAndMissingDiagnostic,omitempty"`
}

func runAnalyzeE1(_ context.Context, runDir, outDir string, stdout io.Writer) error {
	report, err := AnalyzeE1Run(runDir, outDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s (%s): status=%s passed=%d/%d requests=%d llmSessions=%d llmToolCalls=%d reconciliationPassed=%v -> %s\n",
		report.SourceRunID, report.AnalysisVersion, report.RunStatus, report.PassedCases, report.SummaryVerdicts,
		report.CapturedGatewayRequests, report.LLMSessions, report.LLMToolCalls, report.ReconciliationPassed, outDir)
	return nil
}

func ensureSeparateOutDir(runDir, outDir string) (string, string, error) {
	absRun, err := filepath.Abs(runDir)
	if err != nil {
		return "", "", err
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return "", "", err
	}
	rel, err := filepath.Rel(absRun, absOut)
	if err == nil && (rel == "." || !strings.HasPrefix(rel, "..")) {
		return "", "", fmt.Errorf("derived output directory %q must be outside raw run directory %q", absOut, absRun)
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return "", "", err
	}
	return absRun, absOut, nil
}

func readTrackedBytes(absRun, name string, hashes map[string]string, missing *[]string) ([]byte, bool) {
	p := filepath.Join(absRun, name)
	raw, err := os.ReadFile(p)
	if err != nil {
		*missing = append(*missing, name)
		return nil, false
	}
	hashes[name] = harness.SHA256Bytes(raw)
	return raw, true
}

func trackCSVPath(absRun, name string, hashes map[string]string, missing *[]string) (string, bool) {
	p := filepath.Join(absRun, name)
	sum, err := harness.SHA256File(p)
	if err != nil {
		*missing = append(*missing, name)
		return "", false
	}
	hashes[name] = sum
	return p, true
}

func AnalyzeE1Run(runDir, outDir string) (*E1RecomputedReport, error) {
	absRun, absOut, err := ensureSeparateOutDir(runDir, outDir)
	if err != nil {
		return nil, err
	}
	rep := &E1RecomputedReport{
		AnalysisVersion:    E1AnalysisVersion,
		Experiment:         "E1",
		SourceRunID:        filepath.Base(absRun),
		SourceRunDir:       filepath.ToSlash(runDir),
		InputFilesSHA256:   map[string]string{},
		AuthorizationModes: map[string]*E1ModeReconciliation{},
	}

	readTracked := func(name string) ([]byte, bool) {
		return readTrackedBytes(absRun, name, rep.InputFilesSHA256, &rep.MissingInputFiles)
	}

	// 1. manifest.json
	if raw, ok := readTracked("manifest.json"); ok {
		var manifest map[string]any
		if err := json.Unmarshal(raw, &manifest); err != nil {
			rep.Anomalies = append(rep.Anomalies, fmt.Sprintf("manifest.json parse error: %v", err))
		} else {
			if v, ok := manifest["runId"].(string); ok && v != "" {
				rep.SourceRunID = v
			}
			if v, ok := manifest["sourceCommit"].(string); ok {
				rep.SourceCommit = v
			}
			if dep, ok := manifest["deployment"].(map[string]any); ok {
				if id, ok := dep["deploymentId"].(string); ok {
					rep.DeploymentID = id
				}
			}
			if llm, ok := manifest["llm"].(map[string]any); ok {
				rep.ModelProvider, _ = llm["provider"].(string)
				rep.ModelName, _ = llm["model"].(string)
			}
		}
	}

	// 2. summary.json
	var summary struct {
		RunID        string `json:"runId"`
		Status       string `json:"status"`
		Stage        string `json:"stage"`
		DeploymentID string `json:"deploymentId"`
		Error        string `json:"error"`
		Diagnostic   string `json:"diagnostic"`
		Cases        []struct {
			Name          string `json:"name"`
			Pass          bool   `json:"pass"`
			Status        string `json:"status"`
			MissingReason string `json:"missingReason"`
			Error         string `json:"error"`
		} `json:"cases"`
		MissingItems []MissingItem `json:"missingItems"`
	}
	if raw, ok := readTracked("summary.json"); ok {
		if err := json.Unmarshal(raw, &summary); err != nil {
			rep.Anomalies = append(rep.Anomalies, fmt.Sprintf("summary.json parse error: %v", err))
		} else {
			if summary.RunID != "" {
				rep.SourceRunID = summary.RunID
			}
			rep.RunStatus = summary.Status
			rep.RunStage = summary.Stage
			if summary.DeploymentID != "" && rep.DeploymentID == "" {
				rep.DeploymentID = summary.DeploymentID
			}
			if summary.Diagnostic != "" {
				rep.RunError = summary.Diagnostic
			} else {
				rep.RunError = summary.Error
			}
			seen := map[string]bool{}
			for _, c := range summary.Cases {
				seen[c.Name] = true
				ca := E1CaseAnalysis{Name: c.Name, Pass: c.Pass, Error: c.Error, MissingReason: c.MissingReason}
				if c.Pass {
					ca.Category = "pass"
					rep.PassedCases++
				} else if c.Status == "not_executed" {
					ca.Category = "not_executed"
					rep.NotExecutedCases++
				} else if isUpstreamCascadeError(c.Error) {
					ca.Category = "upstream_blocked"
					ca.MissingReason = summarizeCascadeReason(c.Error)
					rep.UpstreamBlockedCases++
					rep.FailedCases++
				} else {
					ca.Category = "fail"
					rep.FailedCases++
				}
				rep.Cases = append(rep.Cases, ca)
			}
			for i := 1; i <= 16; i++ {
				name := fmt.Sprintf("F%02d", i)
				if !seen[name] {
					reason := "case missing from summary.json"
					for _, mi := range summary.MissingItems {
						if mi.ID == name {
							reason = mi.Reason
							break
						}
					}
					rep.Cases = append(rep.Cases, E1CaseAnalysis{
						Name:          name,
						Pass:          false,
						Category:      "not_executed",
						MissingReason: reason,
					})
					rep.NotExecutedCases++
				}
			}
			rep.SummaryVerdicts = len(rep.Cases)
		}
	} else {
		rep.RunStatus = "MISSING_SUMMARY"
		rep.FailureAndMissingDiagnostic = append(rep.FailureAndMissingDiagnostic, "summary.json is absent")
	}

	// 3. requests.csv
	var reqRows []e1RequestCSVRow
	if p, ok := trackCSVPath(absRun, "requests.csv", rep.InputFilesSHA256, &rep.MissingInputFiles); ok {
		rows, err := harness.ReadCSV[e1RequestCSVRow](p)
		if err != nil {
			rep.Anomalies = append(rep.Anomalies, fmt.Sprintf("requests.csv parse error: %v", err))
		} else {
			reqRows = rows
		}
	}
	rep.CapturedGatewayRequests = len(reqRows)

	// 4. llm-traces.json
	type traceTool struct {
		ToolName string         `json:"toolName"`
		Output   map[string]any `json:"output"`
		IsError  bool           `json:"isError"`
	}
	type traceEntry struct {
		Case   string `json:"Case"`
		Mode   string `json:"Mode"`
		Error  string `json:"Error"`
		Result *struct {
			Provider       string      `json:"provider"`
			Model          string      `json:"model"`
			LLMLatencyMs   int64       `json:"llmLatencyMs"`
			ToolCallsCount int         `json:"toolCallsCount"`
			ToolTraces     []traceTool `json:"toolTraces"`
		} `json:"Result"`
	}
	var traces []traceEntry
	if raw, ok := readTracked("llm-traces.json"); ok {
		if err := json.Unmarshal(raw, &traces); err != nil {
			rep.Anomalies = append(rep.Anomalies, fmt.Sprintf("llm-traces.json parse error: %v", err))
		}
	}
	rep.LLMSessions = len(traces)
	for _, tr := range traces {
		if tr.Error != "" {
			rep.LLMErrorSessions++
		}
		if tr.Result != nil {
			rep.LLMToolCalls += tr.Result.ToolCallsCount
		}
	}

	// 5. Primary DB JSON exports
	challenges := map[string]map[string]any{}
	if raw, ok := readTracked("db-challenges.json"); ok {
		var list []map[string]any
		if json.Unmarshal(raw, &list) == nil {
			for _, item := range list {
				if id, _ := item["challenge_id"].(string); id != "" {
					challenges[id] = item
				}
			}
		}
	}
	rep.StoredChallenges = len(challenges)

	decisions := map[string]map[string]any{}
	if raw, ok := readTracked("db-decisions.json"); ok {
		var list []map[string]any
		if json.Unmarshal(raw, &list) == nil {
			for _, item := range list {
				if id, _ := item["decision_id"].(string); id != "" {
					decisions[id] = item
				}
			}
		}
	}
	rep.StoredDecisions = len(decisions)

	orders := map[string]map[string]any{}
	orderByKey := map[string]bool{}
	if raw, ok := readTracked("db-orders.json"); ok {
		var list []map[string]any
		if json.Unmarshal(raw, &list) == nil {
			for _, item := range list {
				if id, _ := item["order_id"].(string); id != "" {
					orders[id] = item
				}
				if k, _ := item["idempotency_key"].(string); k != "" {
					orderByKey[k] = true
				}
			}
		}
	}
	rep.StoredOrders = len(orders)

	quotes := map[string]map[string]any{}
	if raw, ok := readTracked("db-quotes.json"); ok {
		var list []map[string]any
		if json.Unmarshal(raw, &list) == nil {
			for _, item := range list {
				if id, _ := item["quote_id"].(string); id != "" {
					quotes[id] = item
				}
			}
		}
	}
	rep.StoredQuotes = len(quotes)

	keyRowsByKey := map[string]bool{}
	var keyRowsCount int
	if raw, ok := readTracked("db-business-keys.json"); ok {
		var list []map[string]any
		if json.Unmarshal(raw, &list) == nil {
			keyRowsCount = len(list)
			for _, item := range list {
				if k, _ := item["idempotency_key"].(string); k != "" {
					keyRowsByKey[k] = true
				}
			}
		}
	}
	rep.StoredBusinessKeys = keyRowsCount

	// 6. blocks.jsonl
	type blockTx struct {
		TxID           string   `json:"txId"`
		ValidationCode string   `json:"validationCode"`
		WriteKeys      []string `json:"writeKeys"`
	}
	type blockLine struct {
		Point struct {
			BlockNumber int64  `json:"blockNumber"`
			BlockHash   string `json:"blockHash"`
		} `json:"point"`
		Transactions []blockTx `json:"transactions"`
	}
	blocks := map[int64]blockLine{}
	txIndex := map[string]struct {
		height int64
		code   string
	}{}
	if raw, ok := readTracked("blocks.jsonl"); ok {
		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var bl blockLine
			if err := json.Unmarshal([]byte(line), &bl); err != nil {
				rep.Anomalies = append(rep.Anomalies, fmt.Sprintf("blocks.jsonl parse error: %v", err))
				continue
			}
			blocks[bl.Point.BlockNumber] = bl
			for _, tx := range bl.Transactions {
				txIndex[tx.TxID] = struct {
					height int64
					code   string
				}{height: bl.Point.BlockNumber, code: tx.ValidationCode}
			}
		}
	}
	rep.Blocks = len(blocks)
	if len(blocks) > 0 {
		continuous := true
		for h := int64(0); h < int64(len(blocks)); h++ {
			if _, exists := blocks[h]; !exists {
				continuous = false
				break
			}
		}
		rep.BlocksContinuous = continuous
	}

	// 7. Reconcile RP and BM modes
	for _, spec := range []struct {
		short, mode string
	}{{"rp", "RESOURCE_PREAUTHORIZED"}, {"bm", "BUYER_MANDATE"}} {
		mr := &E1ModeReconciliation{
			Mode:       spec.mode,
			F07Denials: map[string]string{},
		}
		rep.AuthorizationModes[spec.short] = mr

		modelMatch := true
		seenTraceCases := map[string]bool{}
		for _, tr := range traces {
			if tr.Mode != spec.mode {
				continue
			}
			seenTraceCases[tr.Case] = true
			if tr.Result == nil {
				modelMatch = false
				continue
			}
			if rep.ModelName != "" && tr.Result.Model != rep.ModelName {
				modelMatch = false
			}
			if rep.ModelProvider != "" && tr.Result.Provider != rep.ModelProvider {
				modelMatch = false
			}
			if tr.Result.LLMLatencyMs <= 0 {
				modelMatch = false
			}
			for _, tt := range tr.Result.ToolTraces {
				if tt.ToolName == "delegate_grant" && !tt.IsError {
					if anchored, _ := tt.Output["anchored"].(bool); anchored {
						if tr.Case == "F05" {
							mr.F05DelegationAnchored = true
						}
						if tr.Case == "F15" {
							mr.F15DelegationAnchored = true
						}
					}
				}
			}
		}
		for c := range seenTraceCases {
			mr.LLMTraceCases = append(mr.LLMTraceCases, c)
		}
		slices.Sort(mr.LLMTraceCases)
		mr.LLMTraceModelMatch = len(seenTraceCases) > 0 && modelMatch

		// F06 positive loop
		var f06Rows []e1RequestCSVRow
		for _, r := range reqRows {
			if r.Case == "F06" && r.Mode == spec.mode {
				f06Rows = append(f06Rows, r)
			}
		}
		mr.F06HTTPRoundTrips = len(f06Rows)
		var f06QuoteReq, f06OrderReq *e1RequestCSVRow
		if len(f06Rows) == 4 &&
			f06Rows[0].HTTPStatus == "201" && f06Rows[1].HTTPStatus == "200" &&
			f06Rows[2].HTTPStatus == "201" && f06Rows[3].HTTPStatus == "200" {
			f06QuoteReq, f06OrderReq = &f06Rows[1], &f06Rows[3]
			mr.F06QuoteID = f06QuoteReq.QuoteID
			mr.F06OrderID = f06OrderReq.OrderID
			mr.F06CreationDecisionID = f06OrderReq.DecisionID
			mr.F06ChallengeIDs = []string{f06QuoteReq.ChallengeID, f06OrderReq.ChallengeID}
			qRow := quotes[mr.F06QuoteID]
			oRow := orders[mr.F06OrderID]
			mr.F06QuoteAmountMinor = asInt64(qRow["total_amount_minor"])
			mr.F06OrderAmountMinor = asInt64(oRow["total_amount_minor"])
			mr.F06PrimaryDBMatched = f06QuoteReq.QuoteID != "" &&
				f06QuoteReq.QuoteID == f06OrderReq.QuoteID &&
				mr.F06QuoteAmountMinor == 80000 &&
				mr.F06OrderAmountMinor == 80000 &&
				asString(oRow["decision_id"]) == f06OrderReq.DecisionID &&
				asString(oRow["quote_id"]) == f06QuoteReq.QuoteID
			if !mr.F06PrimaryDBMatched {
				mr.Anomalies = append(mr.Anomalies, "F06 primary DB quote/order mismatch")
			}
		} else {
			mr.Anomalies = append(mr.Anomalies, fmt.Sprintf("F06 expected 4 round trips (201/200/201/200), observed %d", len(f06Rows)))
		}

		// F07 negative controls
		var f07Rows []e1RequestCSVRow
		for _, r := range reqRows {
			if r.Case == "F07" && r.Mode == spec.mode {
				f07Rows = append(f07Rows, r)
			}
		}
		var f07QuoteReq *e1RequestCSVRow
		var f07NegReqs []e1RequestCSVRow
		zeroSideEffect := true
		if len(f07Rows) >= 6 && f07Rows[1].HTTPStatus == "200" {
			f07QuoteReq = &f07Rows[1]
			mr.F07QuoteAmountMinor = asInt64(quotes[f07QuoteReq.QuoteID]["total_amount_minor"])
			for _, r := range f07Rows {
				if r.Action == "order.create" {
					f07NegReqs = append(f07NegReqs, r)
					if r.Code != "" {
						mr.F07Denials[r.Code] = r.DecisionID
					}
					if r.OrderID != "" || orderByKey[r.Key] || keyRowsByKey[r.Key] {
						zeroSideEffect = false
					}
				}
			}
			if mr.F07Denials["AMOUNT_MISMATCH"] == "" || mr.F07Denials["AMOUNT_LIMIT_EXCEEDED"] == "" || mr.F07QuoteAmountMinor != 120000 {
				mr.Anomalies = append(mr.Anomalies, "F07 missing Q1200 or required negative control denials")
			}
			mr.F07ZeroOrderSideEffect = zeroSideEffect && len(f07NegReqs) >= 2
		} else {
			mr.F07ZeroOrderSideEffect = false
			mr.Anomalies = append(mr.Anomalies, fmt.Sprintf("F07 incomplete: observed %d requests", len(f07Rows)))
		}

		// Cross-check decisions -> challenges -> blocks -> probes for F06/F07
		checkReqs := make([]e1RequestCSVRow, 0, 5)
		for _, r := range []*e1RequestCSVRow{f06QuoteReq, f06OrderReq, f07QuoteReq} {
			if r != nil {
				checkReqs = append(checkReqs, *r)
			}
		}
		checkReqs = append(checkReqs, f07NegReqs...)
		for _, r := range checkReqs {
			dec := decisions[r.DecisionID]
			chal := challenges[r.ChallengeID]
			if dec == nil || chal == nil {
				mr.Anomalies = append(mr.Anomalies, fmt.Sprintf("%s missing decision or challenge row for %s", r.Case, r.DecisionID))
				continue
			}
			blockNo := asInt64(dec["block_number"])
			probeBlock := asInt64(dec["probe_block"])
			probeTx := asString(dec["probe_tx_id"])
			sentMono := asInt64(dec["probe_sent_mono_ns"])
			checkedMono := asInt64(dec["probe_checked_mono_ns"])
			deadlineMono := asInt64(dec["probe_deadline_mono_ns"])
			bl, blOK := blocks[blockNo]
			txInfo, txOK := txIndex[probeTx]
			ok := asString(dec["challenge_id"]) == asString(chal["challenge_id"]) &&
				asString(chal["decision_id"]) == asString(dec["decision_id"]) &&
				chal["consumed_at"] != nil &&
				asString(dec["task_id"]) == asString(chal["task_id"]) &&
				asString(dec["task_id"]) == r.TaskID &&
				r.RequestHash == asString(chal["request_hash"]) &&
				blOK && bl.Point.BlockHash == asString(dec["block_hash"]) &&
				txOK && txInfo.height == probeBlock && txInfo.code == "VALID" &&
				sentMono <= checkedMono && checkedMono < deadlineMono
			if ok {
				mr.ProbeAndBlockChecked++
			} else {
				mr.Anomalies = append(mr.Anomalies, fmt.Sprintf("%s decision %s failed challenge/block/probe cross-check", r.Case, r.DecisionID))
			}
		}

		// F08 retry check
		if raw, ok := readTracked("F08-" + spec.short + ".json"); ok {
			var f08 struct {
				FirstChallenge  string `json:"firstChallenge"`
				RetryChallenge  string `json:"retryChallenge"`
				OrderRowsBefore int    `json:"orderRowsBefore"`
				OrderRowsAfter  int    `json:"orderRowsAfter"`
				FirstOrder      struct {
					OrderID string `json:"orderId"`
				} `json:"firstOrder"`
				RetryOrder struct {
					OrderID string `json:"orderId"`
				} `json:"retryOrder"`
			}
			if json.Unmarshal(raw, &f08) == nil {
				mr.F08OrderID = f08.FirstOrder.OrderID
				mr.F08RetryReusedOrder = f08.FirstChallenge != "" && f08.FirstChallenge != f08.RetryChallenge &&
					f08.FirstOrder.OrderID != "" && f08.FirstOrder.OrderID == f08.RetryOrder.OrderID &&
					f08.OrderRowsAfter-f08.OrderRowsBefore == 1
			}
		}

		// F14 expired check
		if raw, ok := readTracked("F14-expired-" + spec.short + ".json"); ok {
			var f14 struct {
				Code string `json:"code"`
			}
			if json.Unmarshal(raw, &f14) == nil {
				mr.F14ExpiredDenied = f14.Code == "DOMAIN_CERTIFICATION_INVALID"
			}
		}

		// F15 reissued check
		if raw, ok := readTracked("F15-reissued-" + spec.short + ".json"); ok {
			var f15 struct {
				Quote struct {
					Decision string `json:"decision"`
				} `json:"quote"`
			}
			if json.Unmarshal(raw, &f15) == nil {
				mr.F15ReissuedAllowed = f15.Quote.Decision == "ALLOW"
			}
		}

		// F16 bindings check
		if raw, ok := readTracked("F16-" + spec.short + ".json"); ok {
			var f16 struct {
				CanonicalEvidence       string `json:"canonicalEvidence"`
				KBEvidenceHash          string `json:"kbEvidenceHash"`
				VerifiedEvidenceHash    string `json:"verifiedEvidenceHash"`
				ChangedEvidenceHash     string `json:"changedEvidenceHash"`
				AbsentCredentialControl string `json:"absentCredentialControl"`
			}
			if json.Unmarshal(raw, &f16) == nil {
				digest := harness.SHA256Bytes([]byte(f16.CanonicalEvidence))
				mr.F16EvidenceHash = f16.KBEvidenceHash
				mr.F16BindingsVerified = f16.CanonicalEvidence != "" &&
					digest == f16.KBEvidenceHash &&
					digest == f16.VerifiedEvidenceHash &&
					f16.ChangedEvidenceHash != f16.KBEvidenceHash &&
					strings.Contains(f16.AbsentCredentialControl, "CREDENTIAL_STATUS_INVALID")
			}
		}
	}

	// 8. Check no business on-chain writes in F06 block interval
	var f06Blocks []int64
	for _, r := range reqRows {
		if r.Case == "F06" && r.DecisionID != "" {
			if dec := decisions[r.DecisionID]; dec != nil {
				f06Blocks = append(f06Blocks, asInt64(dec["block_number"]))
			}
		}
	}
	if len(f06Blocks) >= 2 {
		slices.Sort(f06Blocks)
		first, last := f06Blocks[0], f06Blocks[len(f06Blocks)-1]
		nonProbe := 0
		for h := first + 1; h <= last; h++ {
			for _, tx := range blocks[h].Transactions {
				if tx.ValidationCode != "VALID" {
					continue
				}
				for _, k := range tx.WriteKeys {
					if !strings.HasPrefix(k, "probe/") {
						nonProbe++
					}
				}
			}
		}
		rep.F06BlockInterval = &E1BlockInterval{
			FirstExclusive:    first,
			LastInclusive:     last,
			NonProbeWriteKeys: nonProbe,
		}
		if nonProbe != 0 {
			rep.Anomalies = append(rep.Anomalies, fmt.Sprintf("F06 interval (%d,%d] had %d non-probe on-chain writes", first, last, nonProbe))
		}
	}

	// 9. Cross-check against published audit.json if present
	if raw, ok := readTracked("audit.json"); ok {
		var pub struct {
			RunID                   string `json:"runId"`
			SummaryVerdicts         int    `json:"summaryVerdicts"`
			CapturedGatewayRequests int    `json:"capturedGatewayRequests"`
			LLMSessions             int    `json:"llmSessions"`
			LLMToolCalls            int    `json:"llmToolCalls"`
			Blocks                  int    `json:"blocks"`
			StoredQuotes            int    `json:"storedQuotes"`
			StoredOrders            int    `json:"storedOrders"`
			StoredDecisions         int    `json:"storedDecisions"`
			AuthorizationModes      map[string]struct {
				F06OrderID            string            `json:"F06OrderId"`
				F06CreationDecisionID string            `json:"F06CreationDecisionId"`
				F06QuoteID            string            `json:"F06QuoteId"`
				F07Denials            map[string]string `json:"F07Denials"`
				F08OrderID            string            `json:"F08OrderId"`
				F16EvidenceHash       string            `json:"F16EvidenceHash"`
			} `json:"authorizationModes"`
		}
		if err := json.Unmarshal(raw, &pub); err == nil {
			rep.PublishedAuditChecked = true
			var mismatches []string
			cmpInt := func(label string, got, want int) {
				if got != want {
					mismatches = append(mismatches, fmt.Sprintf("%s: got %d want %d", label, got, want))
				}
			}
			cmpInt("summaryVerdicts", rep.SummaryVerdicts, pub.SummaryVerdicts)
			cmpInt("capturedGatewayRequests", rep.CapturedGatewayRequests, pub.CapturedGatewayRequests)
			cmpInt("llmSessions", rep.LLMSessions, pub.LLMSessions)
			cmpInt("llmToolCalls", rep.LLMToolCalls, pub.LLMToolCalls)
			cmpInt("blocks", rep.Blocks, pub.Blocks)
			cmpInt("storedQuotes", rep.StoredQuotes, pub.StoredQuotes)
			cmpInt("storedOrders", rep.StoredOrders, pub.StoredOrders)
			cmpInt("storedDecisions", rep.StoredDecisions, pub.StoredDecisions)
			for short, wantMode := range pub.AuthorizationModes {
				gotMode := rep.AuthorizationModes[short]
				if gotMode == nil {
					mismatches = append(mismatches, short+": missing mode")
					continue
				}
				if gotMode.F06OrderID != wantMode.F06OrderID {
					mismatches = append(mismatches, short+".F06OrderId mismatch")
				}
				if gotMode.F06CreationDecisionID != wantMode.F06CreationDecisionID {
					mismatches = append(mismatches, short+".F06CreationDecisionId mismatch")
				}
				if gotMode.F06QuoteID != wantMode.F06QuoteID {
					mismatches = append(mismatches, short+".F06QuoteId mismatch")
				}
				if gotMode.F08OrderID != wantMode.F08OrderID {
					mismatches = append(mismatches, short+".F08OrderId mismatch")
				}
				if gotMode.F16EvidenceHash != wantMode.F16EvidenceHash {
					mismatches = append(mismatches, short+".F16EvidenceHash mismatch")
				}
				for k, v := range wantMode.F07Denials {
					if gotMode.F07Denials[k] != v {
						mismatches = append(mismatches, short+".F07Denials."+k+" mismatch")
					}
				}
			}
			slices.Sort(mismatches)
			rep.PublishedAuditMismatches = mismatches
			rep.PublishedAuditMatches = len(mismatches) == 0
		}
	}

	// 10. Summarize diagnostics and overall reconciliation verdict
	if rep.RunStatus != "PASS" {
		rep.FailureAndMissingDiagnostic = append(rep.FailureAndMissingDiagnostic,
			fmt.Sprintf("run status=%s stage=%s passed=%d/%d failed=%d upstreamBlocked=%d notExecuted=%d llmErrorSessions=%d",
				rep.RunStatus, rep.RunStage, rep.PassedCases, rep.SummaryVerdicts, rep.FailedCases, rep.UpstreamBlockedCases, rep.NotExecutedCases, rep.LLMErrorSessions))
		for _, c := range rep.Cases {
			if c.Category == "fail" {
				rep.FailureAndMissingDiagnostic = append(rep.FailureAndMissingDiagnostic, fmt.Sprintf("root failure %s: %s", c.Name, firstLine(c.Error)))
			}
		}
	}

	allModesOK := true
	for _, short := range []string{"rp", "bm"} {
		mr := rep.AuthorizationModes[short]
		if mr == nil || !mr.F06PrimaryDBMatched || !mr.F07ZeroOrderSideEffect || !mr.F08RetryReusedOrder ||
			!mr.F14ExpiredDenied || !mr.F15ReissuedAllowed || !mr.F16BindingsVerified ||
			!mr.F05DelegationAnchored || !mr.F15DelegationAnchored || !mr.LLMTraceModelMatch ||
			mr.ProbeAndBlockChecked != 5 || len(mr.Anomalies) > 0 {
			allModesOK = false
		}
	}
	rep.ReconciliationPassed = rep.RunStatus == "PASS" &&
		rep.PassedCases == 16 &&
		rep.FailedCases == 0 &&
		rep.NotExecutedCases == 0 &&
		rep.BlocksContinuous &&
		allModesOK &&
		rep.F06BlockInterval != nil && rep.F06BlockInterval.NonProbeWriteKeys == 0 &&
		len(rep.Anomalies) == 0 &&
		(!rep.PublishedAuditChecked || rep.PublishedAuditMatches)

	if err := harness.WriteJSON(filepath.Join(absOut, "recomputed.json"), rep); err != nil {
		return nil, err
	}
	md := renderE1RecomputedMarkdown(rep)
	if err := harness.WriteAtomic(filepath.Join(absOut, "recomputed-table.md"), []byte(md), 0o644); err != nil {
		return nil, err
	}
	return rep, nil
}

func renderE1RecomputedMarkdown(rep *E1RecomputedReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# E1 离线复算结果 (%s)\n\n", rep.SourceRunID)
	fmt.Fprintf(&b, "- 分析版本: `%s`\n", rep.AnalysisVersion)
	fmt.Fprintf(&b, "- 源运行 ID: `%s`\n", rep.SourceRunID)
	fmt.Fprintf(&b, "- 原始运行目录: `%s`\n", rep.SourceRunDir)
	fmt.Fprintf(&b, "- 运行状态: `%s` (对账通过: `%v`)\n", rep.RunStatus, rep.ReconciliationPassed)
	if rep.ModelProvider != "" || rep.ModelName != "" {
		fmt.Fprintf(&b, "- 实际模型: `%s / %s`\n", rep.ModelProvider, rep.ModelName)
	}
	b.WriteString("\n## 关键计数\n\n")
	b.WriteString("| 指标 | 离线复算值 |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| F01-F16 通过数 | %d/%d (失败 %d, 上游阻断 %d, 未执行 %d) |\n", rep.PassedCases, rep.SummaryVerdicts, rep.FailedCases, rep.UpstreamBlockedCases, rep.NotExecutedCases)
	fmt.Fprintf(&b, "| 模型会话 / 工具调用 / 异常会话 | %d / %d / %d |\n", rep.LLMSessions, rep.LLMToolCalls, rep.LLMErrorSessions)
	fmt.Fprintf(&b, "| 记录的网关请求 | %d |\n", rep.CapturedGatewayRequests)
	fmt.Fprintf(&b, "| 主库报价 / 订单 / 决定 / 挑战 / 业务键 | %d / %d / %d / %d / %d |\n", rep.StoredQuotes, rep.StoredOrders, rep.StoredDecisions, rep.StoredChallenges, rep.StoredBusinessKeys)
	fmt.Fprintf(&b, "| 导出区块数 (连续性) | %d (%v) |\n", rep.Blocks, rep.BlocksContinuous)
	if rep.F06BlockInterval != nil {
		fmt.Fprintf(&b, "| F06 决定区间非探针链上写入 | %d (区块 (%d, %d]) |\n", rep.F06BlockInterval.NonProbeWriteKeys, rep.F06BlockInterval.FirstExclusive, rep.F06BlockInterval.LastInclusive)
	}

	b.WriteString("\n## RP/BM 主库与轨迹对账\n\n")
	b.WriteString("| 检查项 | RP | BM |\n| --- | --- | --- |\n")
	rp, bm := rep.AuthorizationModes["rp"], rep.AuthorizationModes["bm"]
	fmt.Fprintf(&b, "| F05/F15 模型签发落链 | %v / %v | %v / %v |\n", rp.F05DelegationAnchored, rp.F15DelegationAnchored, bm.F05DelegationAnchored, bm.F15DelegationAnchored)
	fmt.Fprintf(&b, "| F06 往返数 / 主库对账 | %d / %v | %d / %v |\n", rp.F06HTTPRoundTrips, rp.F06PrimaryDBMatched, bm.F06HTTPRoundTrips, bm.F06PrimaryDBMatched)
	fmt.Fprintf(&b, "| F06 订单金额 / 订单 ID | %d / `%s` | %d / `%s` |\n", rp.F06OrderAmountMinor, rp.F06OrderID, bm.F06OrderAmountMinor, bm.F06OrderID)
	fmt.Fprintf(&b, "| F07 Q1200 零订单副作用 | %v | %v |\n", rp.F07ZeroOrderSideEffect, bm.F07ZeroOrderSideEffect)
	fmt.Fprintf(&b, "| F08 同键重试复用原订单 | %v (`%s`) | %v (`%s`) |\n", rp.F08RetryReusedOrder, rp.F08OrderID, bm.F08RetryReusedOrder, bm.F08OrderID)
	fmt.Fprintf(&b, "| F06/F07 探针与区块核对通过数 | %d/5 | %d/5 |\n", rp.ProbeAndBlockChecked, bm.ProbeAndBlockChecked)
	fmt.Fprintf(&b, "| F14 过期拒绝 / F15 重签放行 / F16 绑定复算 | %v / %v / %v | %v / %v / %v |\n", rp.F14ExpiredDenied, rp.F15ReissuedAllowed, rp.F16BindingsVerified, bm.F14ExpiredDenied, bm.F15ReissuedAllowed, bm.F16BindingsVerified)

	if len(rep.FailureAndMissingDiagnostic) > 0 {
		b.WriteString("\n## 失败与缺测诊断\n\n")
		for _, d := range rep.FailureAndMissingDiagnostic {
			fmt.Fprintf(&b, "- %s\n", d)
		}
	}

	b.WriteString("\n## 原始输入文件摘要 (SHA-256)\n\n")
	b.WriteString("| 原始文件 | SHA-256 |\n| --- | --- |\n")
	keys := make([]string, 0, len(rep.InputFilesSHA256))
	for k := range rep.InputFilesSHA256 {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", k, rep.InputFilesSHA256[k])
	}
	return b.String()
}

// --- E6 Offline Analysis ---

type e6RevocationCSVRow struct {
	RunID               string `csv:"run_id"`
	Mode                string `csv:"mode"`
	Configuration       string `csv:"configuration"`
	RevokedGrantID      string `csv:"revoked_grant_id"`
	RevocationTxID      string `csv:"revocation_tx_id"`
	RevocationBlockR    string `csv:"revocation_block_r"`
	RevocationBlockHash string `csv:"revocation_block_hash"`
	TxIndex             string `csv:"tx_index"`
	ValidationCode      string `csv:"validation_code"`
	TSubmitNs           string `csv:"t_submit_ns"`
	TValidNs            string `csv:"t_valid_ns"`
	TApplyNs            string `csv:"t_apply_ns"`
	InstanceID          string `csv:"instance_id"`
	ProbeRole           string `csv:"probe_role"`
	TAdoptNs            string `csv:"t_adopt_ns"`
	AdoptBlockH         string `csv:"adopt_block_h"`
	ProbeIntervalMs     string `csv:"probe_interval_ms"`
	ProbeLifetimeMs     string `csv:"probe_lifetime_ms"`
	DetectIntervalMs    string `csv:"detect_interval_ms"`
	ClockTimebase       string `csv:"clock_timebase"`
	ClockResolutionNs   string `csv:"clock_resolution_ns"`
	ClockErrorNs        string `csv:"clock_error_ns"`
	Status              string `csv:"status"`
	UnobservedReason    string `csv:"unobserved_reason"`
}

type e6RequestCSVRow struct {
	RunID              string `csv:"run_id"`
	Mode               string `csv:"mode"`
	Configuration      string `csv:"configuration"`
	Phase              string `csv:"phase"`
	InstanceID         string `csv:"instance_id"`
	ProbeRole          string `csv:"probe_role"`
	Seq                string `csv:"seq"`
	PlannedAtNs        string `csv:"planned_at_ns"`
	ActualIntervalNs   string `csv:"actual_interval_ns"`
	SubmittedAtNs      string `csv:"submitted_at_ns"`
	DecisionAtNs       string `csv:"decision_at_ns"`
	CommittedAtNs      string `csv:"committed_at_ns"`
	RespondedAtNs      string `csv:"responded_at_ns"`
	DecisionAtSec      string `csv:"decision_at_sec"`
	IdempotencyKey     string `csv:"idempotency_key"`
	RequestID          string `csv:"request_id"`
	ChallengeID        string `csv:"challenge_id"`
	DecisionID         string `csv:"decision_id"`
	OrderID            string `csv:"order_id"`
	HTTPStatus         string `csv:"http_status"`
	Code               string `csv:"code"`
	Outcome            string `csv:"outcome"`
	Disposition        string `csv:"disposition"`
	BlockNumber        string `csv:"block_number"`
	BlockHash          string `csv:"block_hash"`
	G1StatusAtBlock    string `csv:"g1_status_at_block"`
	ProbeTxID          string `csv:"probe_tx_id"`
	ProbeBlock         string `csv:"probe_block"`
	ProbeSentAtNs      string `csv:"probe_sent_at_ns"`
	ProbeDeadlineNs    string `csv:"probe_deadline_ns"`
	ProbeSentMonoNs    string `csv:"probe_sent_mono_ns"`
	ProbeCheckedMonoNs string `csv:"probe_checked_mono_ns"`
	ProbeDeadlineMono  string `csv:"probe_deadline_mono_ns"`
	ClockTimebase      string `csv:"clock_timebase"`
	ClockResolutionNs  string `csv:"clock_resolution_ns"`
	UnobservedReason   string `csv:"unobserved_reason"`
}

type E6Violation struct {
	Type              string `json:"type"` // allow_after_revocation_block, allow_past_probe_deadline
	InstanceID        string `json:"instanceId"`
	Seq               int64  `json:"seq"`
	DecisionID        string `json:"decisionId,omitempty"`
	BlockNumber       *int64 `json:"blockNumber,omitempty"`
	RevocationBlockR  int64  `json:"revocationBlockR"`
	DecisionAtNs      *int64 `json:"decisionAtNs,omitempty"`
	ProbeDeadlineNs   *int64 `json:"probeDeadlineNs,omitempty"`
	ProbeCheckedMono  *int64 `json:"probeCheckedMonoNs,omitempty"`
	ProbeDeadlineMono *int64 `json:"probeDeadlineMonoNs,omitempty"`
	Detail            string `json:"detail"`
}

type E6DelayedResponseSample struct {
	InstanceID          string   `json:"instanceId"`
	Seq                 int64    `json:"seq"`
	DecisionID          string   `json:"decisionId"`
	BlockNumber         int64    `json:"blockNumber"`
	RevocationBlockR    int64    `json:"revocationBlockR"`
	DecisionAtNs        int64    `json:"decisionAtNs"`
	CommittedAtNs       *int64   `json:"committedAtNs,omitempty"`
	RespondedAtNs       int64    `json:"respondedAtNs"`
	DecisionMinusValid  float64  `json:"decisionMinusValidMs"`
	ResponseMinusValid  float64  `json:"responseMinusValidMs"`
	ResponseMinusCommit *float64 `json:"responseMinusCommitMs,omitempty"`
}

type E6AmbiguousTimingSample struct {
	InstanceID      string `json:"instanceId"`
	Seq             int64  `json:"seq"`
	DecisionID      string `json:"decisionId,omitempty"`
	DecisionAtNs    int64  `json:"decisionAtNs"`
	TValidNs        int64  `json:"tValidNs"`
	DeltaNs         int64  `json:"deltaNs"`
	OrderMarginNs   int64  `json:"orderMarginNs"`
	ResolutionNs    int64  `json:"resolutionNs"`
	UsedSecondLevel bool   `json:"usedSecondLevelFallback"`
}

type E6SampleAccounting struct {
	Warmup           int                   `json:"warmup"`
	Planned          int                   `json:"planned"`
	Started          int                   `json:"started"`
	Completed        int                   `json:"completed"`
	Missed           int                   `json:"missed"`
	Timeout          int                   `json:"timeout"`
	Allowed          int                   `json:"allowed"`
	Denied           int                   `json:"denied"`
	Error            int                   `json:"error"`
	AvailabilityRate *float64              `json:"availabilityRate,omitempty"`
	MedianIntervalMs *float64              `json:"medianActualIntervalMs,omitempty"`
	MaxIntervalMs    *float64              `json:"maxActualIntervalMs,omitempty"`
	IntervalStats    *harness.LatencyStats `json:"intervalStats,omitempty"`
}

type E6InstanceAnalysis struct {
	InstanceID                   string                    `json:"instanceId"`
	ProbeRole                    string                    `json:"probeRole"`
	RevocationTxID               string                    `json:"revocationTxId"`
	RevocationBlockR             int64                     `json:"revocationBlockR"`
	RevocationStatus             string                    `json:"revocationStatus"`
	ProbeIntervalMs              int64                     `json:"probeIntervalMs"`
	ProbeLifetimeMs              int64                     `json:"probeLifetimeMs"`
	DetectIntervalMs             int64                     `json:"detectIntervalMs"`
	ClockTimebase                string                    `json:"clockTimebase"`
	ClockResolutionNs            int64                     `json:"clockResolutionNs"`
	ClockErrorNs                 int64                     `json:"clockErrorNs"`
	TSubmitNs                    *int64                    `json:"tSubmitNs,omitempty"`
	TValidNs                     *int64                    `json:"tValidNs,omitempty"`
	TApplyNs                     *int64                    `json:"tApplyNs,omitempty"`
	TAdoptNs                     *int64                    `json:"tAdoptNs,omitempty"`
	AdoptBlockH                  *int64                    `json:"adoptBlockH,omitempty"`
	ValidMinusSubmitMs           *float64                  `json:"validMinusSubmitMs,omitempty"`
	ApplyMinusValidMs            *float64                  `json:"applyMinusValidMs,omitempty"`
	AdoptMinusApplyMs            *float64                  `json:"adoptMinusApplyMs,omitempty"`
	LastAllowDecisionAtNs        *int64                    `json:"lastAllowDecisionAtNs,omitempty"`
	LastAllowDecisionID          string                    `json:"lastAllowDecisionId,omitempty"`
	LastAllowBlockH              *int64                    `json:"lastAllowBlockH,omitempty"`
	FirstDenyObservedAtNs        *int64                    `json:"firstDenyObservedAtNs,omitempty"`
	FirstDenySource              string                    `json:"firstDenySource,omitempty"`
	FirstDenyCode                string                    `json:"firstDenyCode,omitempty"`
	FirstDenyUnobservedReason    string                    `json:"firstDenyUnobservedReason,omitempty"`
	PostValidAllowCount          int                       `json:"postValidAllowCount"`
	PostValidWindowMs            *float64                  `json:"postValidWindowMs,omitempty"`
	PostSubmitWindowMs           *float64                  `json:"postSubmitWindowMs,omitempty"`
	WindowStatus                 string                    `json:"windowStatus"` // observed, post_valid_allow_unobserved, insufficient_time_resolution, revocation_unconfirmed, VIOLATION
	CensoringReasons             []string                  `json:"censoringReasons,omitempty"`
	Accounting                   E6SampleAccounting        `json:"accounting"`
	DelayedResponseAfterOldBlock []E6DelayedResponseSample `json:"delayedResponseAfterOldBlock,omitempty"`
	AmbiguousTimingSamples       []E6AmbiguousTimingSample `json:"ambiguousTimingSamples,omitempty"`
	Violations                   []E6Violation             `json:"violations,omitempty"`
	Passed                       bool                      `json:"passed"`
}

type E6RecomputedReport struct {
	AnalysisVersion     string                `json:"analysisVersion"`
	Experiment          string                `json:"experiment"`
	SourceRunID         string                `json:"sourceRunId"`
	SourceRunDir        string                `json:"sourceRunDir"`
	Mode                string                `json:"mode,omitempty"`
	Configuration       string                `json:"configuration,omitempty"`
	RevokedGrantID      string                `json:"revokedGrantId,omitempty"`
	RevocationTxID      string                `json:"revocationTxId,omitempty"`
	RevocationBlockR    int64                 `json:"revocationBlockR"`
	InputFilesSHA256    map[string]string     `json:"inputFilesSha256"`
	MissingInputFiles   []string              `json:"missingInputFiles,omitempty"`
	Instances           []*E6InstanceAnalysis `json:"instances"`
	TotalAccounting     E6SampleAccounting    `json:"totalAccounting"`
	TotalViolations     int                   `json:"totalViolations"`
	TotalDelayedSamples int                   `json:"totalDelayedSamples"`
	TotalAmbiguous      int                   `json:"totalAmbiguousTimingSamples"`
	Passed              bool                  `json:"passed"`
	Anomalies           []string              `json:"anomalies,omitempty"`
}

func runAnalyzeE6(_ context.Context, runDir, outDir string, stdout io.Writer) error {
	rep, err := AnalyzeE6Run(runDir, outDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s (%s): mode=%s instances=%d planned=%d completed=%d missed=%d violations=%d delayed=%d passed=%v -> %s\n",
		rep.SourceRunID, rep.AnalysisVersion, rep.Mode, len(rep.Instances),
		rep.TotalAccounting.Planned, rep.TotalAccounting.Completed, rep.TotalAccounting.Missed,
		rep.TotalViolations, rep.TotalDelayedSamples, rep.Passed, outDir)
	return nil
}

func AnalyzeE6Run(runDir, outDir string) (*E6RecomputedReport, error) {
	absRun, absOut, err := ensureSeparateOutDir(runDir, outDir)
	if err != nil {
		return nil, err
	}
	rep := &E6RecomputedReport{
		AnalysisVersion:  E6AnalysisVersion,
		Experiment:       "E6",
		SourceRunID:      filepath.Base(absRun),
		SourceRunDir:     filepath.ToSlash(runDir),
		InputFilesSHA256: map[string]string{},
		Passed:           true,
	}

	readTracked := func(name string) ([]byte, bool) {
		return readTrackedBytes(absRun, name, rep.InputFilesSHA256, &rep.MissingInputFiles)
	}

	if raw, ok := readTracked("manifest.json"); ok {
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			if id, ok := m["runId"].(string); ok && id != "" {
				rep.SourceRunID = id
			}
		}
	}
	_, _ = readTracked("summary.json")

	var revRows []e6RevocationCSVRow
	if p, ok := trackCSVPath(absRun, "revocations.csv", rep.InputFilesSHA256, &rep.MissingInputFiles); ok {
		rows, err := harness.ReadCSV[e6RevocationCSVRow](p)
		if err != nil {
			return nil, fmt.Errorf("parse revocations.csv: %w", err)
		}
		revRows = rows
	}

	var reqRows []e6RequestCSVRow
	if p, ok := trackCSVPath(absRun, "requests.csv", rep.InputFilesSHA256, &rep.MissingInputFiles); ok {
		rows, err := harness.ReadCSV[e6RequestCSVRow](p)
		if err != nil {
			return nil, fmt.Errorf("parse requests.csv: %w", err)
		}
		reqRows = rows
	}

	if len(revRows) == 0 {
		rep.Passed = false
		rep.Anomalies = append(rep.Anomalies, "revocations.csv missing or empty")
	}

	reqByInstance := map[string][]e6RequestCSVRow{}
	for _, r := range reqRows {
		reqByInstance[r.InstanceID] = append(reqByInstance[r.InstanceID], r)
	}

	var allIntervals []float64
	for _, rr := range revRows {
		ia, instIntervals := analyzeE6Instance(rr, reqByInstance[rr.InstanceID])
		if rep.Mode == "" {
			rep.Mode = rr.Mode
		}
		if rep.Configuration == "" {
			rep.Configuration = rr.Configuration
		}
		if rep.RevokedGrantID == "" {
			rep.RevokedGrantID = rr.RevokedGrantID
		}
		if rep.RevocationTxID == "" {
			rep.RevocationTxID = rr.RevocationTxID
		}
		if rep.RevocationBlockR == 0 {
			rep.RevocationBlockR = ia.RevocationBlockR
		}
		rep.Instances = append(rep.Instances, ia)
		rep.TotalViolations += len(ia.Violations)
		rep.TotalDelayedSamples += len(ia.DelayedResponseAfterOldBlock)
		rep.TotalAmbiguous += len(ia.AmbiguousTimingSamples)
		rep.TotalAccounting.Warmup += ia.Accounting.Warmup
		rep.TotalAccounting.Planned += ia.Accounting.Planned
		rep.TotalAccounting.Started += ia.Accounting.Started
		rep.TotalAccounting.Completed += ia.Accounting.Completed
		rep.TotalAccounting.Missed += ia.Accounting.Missed
		rep.TotalAccounting.Timeout += ia.Accounting.Timeout
		rep.TotalAccounting.Allowed += ia.Accounting.Allowed
		rep.TotalAccounting.Denied += ia.Accounting.Denied
		rep.TotalAccounting.Error += ia.Accounting.Error
		allIntervals = append(allIntervals, instIntervals...)
		if !ia.Passed {
			rep.Passed = false
		}
	}
	if rep.TotalAccounting.Planned > 0 {
		rate := float64(rep.TotalAccounting.Completed) / float64(rep.TotalAccounting.Planned)
		rep.TotalAccounting.AvailabilityRate = &rate
	}
	if len(allIntervals) > 0 {
		stats := harness.ComputeLatencyStats(allIntervals)
		med := stats.P50Ms
		mx := stats.MaxMs
		rep.TotalAccounting.MedianIntervalMs = &med
		rep.TotalAccounting.MaxIntervalMs = &mx
		rep.TotalAccounting.IntervalStats = &stats
	}

	if err := harness.WriteJSON(filepath.Join(absOut, "recomputed.json"), rep); err != nil {
		return nil, err
	}
	md := renderE6RecomputedMarkdown(rep)
	if err := harness.WriteAtomic(filepath.Join(absOut, "recomputed-table.md"), []byte(md), 0o644); err != nil {
		return nil, err
	}
	return rep, nil
}

func analyzeE6Instance(rev e6RevocationCSVRow, rows []e6RequestCSVRow) (*E6InstanceAnalysis, []float64) {
	ia := &E6InstanceAnalysis{
		InstanceID:       rev.InstanceID,
		ProbeRole:        rev.ProbeRole,
		RevocationTxID:   rev.RevocationTxID,
		RevocationStatus: rev.Status,
		ClockTimebase:    rev.ClockTimebase,
		Passed:           true,
	}
	if r, ok := parseOptInt64(rev.RevocationBlockR); ok {
		ia.RevocationBlockR = r
	}
	if v, ok := parseOptInt64(rev.ProbeIntervalMs); ok {
		ia.ProbeIntervalMs = v
	}
	if v, ok := parseOptInt64(rev.ProbeLifetimeMs); ok {
		ia.ProbeLifetimeMs = v
	}
	if v, ok := parseOptInt64(rev.DetectIntervalMs); ok {
		ia.DetectIntervalMs = v
	}
	if v, ok := parseOptInt64(rev.ClockResolutionNs); ok {
		ia.ClockResolutionNs = v
	}
	if v, ok := parseOptInt64(rev.ClockErrorNs); ok {
		ia.ClockErrorNs = v
	}
	if v, ok := parseOptInt64(rev.TSubmitNs); ok {
		ia.TSubmitNs = &v
	}
	if v, ok := parseOptInt64(rev.TValidNs); ok {
		ia.TValidNs = &v
	}
	if v, ok := parseOptInt64(rev.TApplyNs); ok {
		ia.TApplyNs = &v
	}
	if v, ok := parseOptInt64(rev.TAdoptNs); ok {
		ia.TAdoptNs = &v
	}
	if v, ok := parseOptInt64(rev.AdoptBlockH); ok {
		ia.AdoptBlockH = &v
	}

	if ia.TSubmitNs != nil && ia.TValidNs != nil {
		ms := nsToMs(*ia.TValidNs - *ia.TSubmitNs)
		ia.ValidMinusSubmitMs = &ms
	}
	if ia.TValidNs != nil && ia.TApplyNs != nil {
		ms := nsToMs(*ia.TApplyNs - *ia.TValidNs)
		ia.ApplyMinusValidMs = &ms
	}
	if ia.TApplyNs != nil && ia.TAdoptNs != nil {
		ms := nsToMs(*ia.TAdoptNs - *ia.TApplyNs)
		ia.AdoptMinusApplyMs = &ms
	}

	revConfirmed := ia.TValidNs != nil && ia.RevocationBlockR > 0 && (rev.ValidationCode == "" || rev.ValidationCode == "VALID")

	var actualIntervalsMs []float64
	var lastPostSubmitAllowNs *int64

	for _, r := range rows {
		if r.Phase == "warmup" {
			ia.Accounting.Warmup++
			continue
		}
		ia.Accounting.Planned++
		switch r.Disposition {
		case "missed":
			ia.Accounting.Missed++
			continue
		case "timeout":
			ia.Accounting.Started++
			ia.Accounting.Timeout++
			continue
		case "allowed":
			ia.Accounting.Started++
			ia.Accounting.Completed++
			ia.Accounting.Allowed++
		case "denied":
			ia.Accounting.Started++
			ia.Accounting.Completed++
			ia.Accounting.Denied++
		default:
			ia.Accounting.Started++
			ia.Accounting.Completed++
			ia.Accounting.Error++
		}

		if iv, ok := parseOptInt64(r.ActualIntervalNs); ok && iv > 0 {
			actualIntervalsMs = append(actualIntervalsMs, nsToMs(iv))
		}

		seq, _ := parseOptInt64(r.Seq)
		decID := r.DecisionID
		blockNo, hasBlock := parseOptInt64(r.BlockNumber)
		decNs, hasDecNs := parseOptInt64(r.DecisionAtNs)
		decSec, hasDecSec := parseOptInt64(r.DecisionAtSec)
		commitNs, hasCommitNs := parseOptInt64(r.CommittedAtNs)
		respNs, hasRespNs := parseOptInt64(r.RespondedAtNs)
		probeDeadlineNs, hasProbeDeadlineNs := parseOptInt64(r.ProbeDeadlineNs)
		probeCheckedMono, hasProbeCheckedMono := parseOptInt64(r.ProbeCheckedMonoNs)
		probeDeadlineMono, hasProbeDeadlineMono := parseOptInt64(r.ProbeDeadlineMono)
		rowClockRes, hasRowRes := parseOptInt64(r.ClockResolutionNs)

		// Track first deny after revocation submission.
		if r.Disposition == "denied" {
			var obsNs *int64
			src := ""
			if hasDecNs {
				v := decNs
				obsNs = &v
				src = "decision_at_ns"
			} else if hasRespNs {
				v := respNs
				obsNs = &v
				src = "responded_at_ns"
			}
			if obsNs != nil && (ia.TSubmitNs == nil || *obsNs >= *ia.TSubmitNs) {
				if ia.FirstDenyObservedAtNs == nil || *obsNs < *ia.FirstDenyObservedAtNs {
					v := *obsNs
					ia.FirstDenyObservedAtNs = &v
					ia.FirstDenySource = src
					ia.FirstDenyCode = r.Code
					ia.FirstDenyUnobservedReason = r.UnobservedReason
				}
			}
			continue
		}

		if r.Disposition != "allowed" {
			continue
		}

		// Determine effective decision timestamp and resolution.
		effectiveDecNs := decNs
		usedSecondFallback := false
		sampleResNs := ia.ClockResolutionNs
		if hasRowRes && rowClockRes > sampleResNs {
			sampleResNs = rowClockRes
		}
		if !hasDecNs && hasDecSec {
			effectiveDecNs = decSec * 1_000_000_000
			usedSecondFallback = true
			if sampleResNs < 1_000_000_000 {
				sampleResNs = 1_000_000_000
			}
		}
		hasAnyDecTime := hasDecNs || hasDecSec

		// Violation 1: ALLOW using block h >= r.
		if revConfirmed && hasBlock && blockNo >= ia.RevocationBlockR {
			bn := blockNo
			v := E6Violation{
				Type:             "allow_after_revocation_block",
				InstanceID:       ia.InstanceID,
				Seq:              seq,
				DecisionID:       decID,
				BlockNumber:      &bn,
				RevocationBlockR: ia.RevocationBlockR,
				Detail:           fmt.Sprintf("allowed old path at block h=%d >= r=%d", blockNo, ia.RevocationBlockR),
			}
			if hasAnyDecTime {
				dn := effectiveDecNs
				v.DecisionAtNs = &dn
			}
			ia.Violations = append(ia.Violations, v)
		}

		// Violation 2: ALLOW at or past original probe deadline (monotonic or wall clock).
		pastMono := hasProbeCheckedMono && hasProbeDeadlineMono && probeCheckedMono >= probeDeadlineMono
		pastWall := hasAnyDecTime && hasProbeDeadlineNs && effectiveDecNs >= probeDeadlineNs
		if pastMono || pastWall {
			v := E6Violation{
				Type:             "allow_past_probe_deadline",
				InstanceID:       ia.InstanceID,
				Seq:              seq,
				DecisionID:       decID,
				RevocationBlockR: ia.RevocationBlockR,
				Detail:           fmt.Sprintf("allowed at or after original probe deadline (pastMono=%v pastWall=%v)", pastMono, pastWall),
			}
			if hasBlock {
				bn := blockNo
				v.BlockNumber = &bn
			}
			if hasAnyDecTime {
				dn := effectiveDecNs
				v.DecisionAtNs = &dn
			}
			if hasProbeDeadlineNs {
				pd := probeDeadlineNs
				v.ProbeDeadlineNs = &pd
			}
			if hasProbeCheckedMono {
				cm := probeCheckedMono
				v.ProbeCheckedMono = &cm
			}
			if hasProbeDeadlineMono {
				dm := probeDeadlineMono
				v.ProbeDeadlineMono = &dm
			}
			ia.Violations = append(ia.Violations, v)
		}

		// Categorize delayed HTTP response after an old-block (h < r) decision.
		if revConfirmed && hasBlock && blockNo < ia.RevocationBlockR && hasDecNs && hasRespNs {
			respAfterValid := respNs >= *ia.TValidNs
			respAfterAdopt := ia.TAdoptNs != nil && respNs >= *ia.TAdoptNs
			decBeforeValid := decNs < *ia.TValidNs
			decBeforeAdopt := ia.TAdoptNs != nil && decNs < *ia.TAdoptNs
			if (respAfterValid && decBeforeValid) || (respAfterAdopt && decBeforeAdopt) {
				sample := E6DelayedResponseSample{
					InstanceID:         ia.InstanceID,
					Seq:                seq,
					DecisionID:         decID,
					BlockNumber:        blockNo,
					RevocationBlockR:   ia.RevocationBlockR,
					DecisionAtNs:       decNs,
					RespondedAtNs:      respNs,
					DecisionMinusValid: nsToMs(decNs - *ia.TValidNs),
					ResponseMinusValid: nsToMs(respNs - *ia.TValidNs),
				}
				if hasCommitNs {
					cn := commitNs
					sample.CommittedAtNs = &cn
					rmc := nsToMs(respNs - commitNs)
					sample.ResponseMinusCommit = &rmc
				}
				ia.DelayedResponseAfterOldBlock = append(ia.DelayedResponseAfterOldBlock, sample)
			}
		}

		if !hasAnyDecTime {
			continue
		}

		// Track last allow relative to t_submit (using decision time, never response time).
		if ia.TSubmitNs != nil && effectiveDecNs >= *ia.TSubmitNs {
			if lastPostSubmitAllowNs == nil || effectiveDecNs > *lastPostSubmitAllowNs {
				v := effectiveDecNs
				lastPostSubmitAllowNs = &v
			}
		}

		if !revConfirmed {
			continue
		}

		// Compare decision timestamp against t_valid considering clock resolution + error margin.
		orderMarginNs := sampleResNs + ia.ClockErrorNs
		deltaNs := effectiveDecNs - *ia.TValidNs
		if absInt64(deltaNs) <= orderMarginNs {
			ia.AmbiguousTimingSamples = append(ia.AmbiguousTimingSamples, E6AmbiguousTimingSample{
				InstanceID:      ia.InstanceID,
				Seq:             seq,
				DecisionID:      decID,
				DecisionAtNs:    effectiveDecNs,
				TValidNs:        *ia.TValidNs,
				DeltaNs:         deltaNs,
				OrderMarginNs:   orderMarginNs,
				ResolutionNs:    sampleResNs,
				UsedSecondLevel: usedSecondFallback,
			})
			continue
		}
		if deltaNs > orderMarginNs {
			ia.PostValidAllowCount++
			if ia.LastAllowDecisionAtNs == nil || effectiveDecNs > *ia.LastAllowDecisionAtNs {
				v := effectiveDecNs
				ia.LastAllowDecisionAtNs = &v
				ia.LastAllowDecisionID = decID
				if hasBlock {
					bn := blockNo
					ia.LastAllowBlockH = &bn
				}
			}
		}
	}

	if ia.Accounting.Planned > 0 {
		rate := float64(ia.Accounting.Completed) / float64(ia.Accounting.Planned)
		ia.Accounting.AvailabilityRate = &rate
	}
	if len(actualIntervalsMs) > 0 {
		stats := harness.ComputeLatencyStats(actualIntervalsMs)
		med := stats.P50Ms
		mx := stats.MaxMs
		ia.Accounting.MedianIntervalMs = &med
		ia.Accounting.MaxIntervalMs = &mx
		ia.Accounting.IntervalStats = &stats
	}

	if ia.TSubmitNs != nil && lastPostSubmitAllowNs != nil {
		ms := math.Max(0, nsToMs(*lastPostSubmitAllowNs-*ia.TSubmitNs))
		ia.PostSubmitWindowMs = &ms
	}

	// Final classification and censoring for instance.
	if !revConfirmed {
		ia.WindowStatus = "revocation_unconfirmed"
		ia.CensoringReasons = append(ia.CensoringReasons, "revocation_unconfirmed")
		ia.Passed = false
	} else if len(ia.Violations) > 0 {
		ia.WindowStatus = "VIOLATION"
		ia.Passed = false
	} else if ia.PostValidAllowCount > 0 && ia.LastAllowDecisionAtNs != nil {
		ms := math.Max(0, nsToMs(*ia.LastAllowDecisionAtNs-*ia.TValidNs))
		ia.PostValidWindowMs = &ms
		ia.WindowStatus = "observed"
		if ia.ProbeLifetimeMs > 0 && ms > float64(ia.ProbeLifetimeMs) {
			ia.CensoringReasons = append(ia.CensoringReasons, "window_exceeded_nominal_delta_state")
			ia.Passed = false
		}
	} else if len(ia.AmbiguousTimingSamples) > 0 {
		ia.WindowStatus = "insufficient_time_resolution"
		ia.CensoringReasons = append(ia.CensoringReasons, "insufficient_time_resolution")
	} else {
		ia.WindowStatus = "post_valid_allow_unobserved"
		ia.CensoringReasons = append(ia.CensoringReasons, "post_valid_allow_unobserved")
	}
	if ia.Accounting.Missed > 0 {
		ia.CensoringReasons = append(ia.CensoringReasons, fmt.Sprintf("missed_probes:%d", ia.Accounting.Missed))
	}
	if ia.Accounting.Timeout > 0 {
		ia.CensoringReasons = append(ia.CensoringReasons, fmt.Sprintf("timeouts:%d", ia.Accounting.Timeout))
	}
	if ia.TAdoptNs == nil && revConfirmed {
		ia.CensoringReasons = append(ia.CensoringReasons, "adopt_r_unobserved")
	}
	return ia, actualIntervalsMs
}

func renderE6RecomputedMarkdown(rep *E6RecomputedReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# E6 撤销窗口离线复算结果 (%s)\n\n", rep.SourceRunID)
	fmt.Fprintf(&b, "- 分析版本: `%s`\n", rep.AnalysisVersion)
	fmt.Fprintf(&b, "- 源运行 ID: `%s`\n", rep.SourceRunID)
	fmt.Fprintf(&b, "- 原始运行目录: `%s`\n", rep.SourceRunDir)
	fmt.Fprintf(&b, "- 根模式 / 验证配置: `%s` / `%s`\n", rep.Mode, rep.Configuration)
	fmt.Fprintf(&b, "- 撤销目标 G1: `%s`\n", rep.RevokedGrantID)
	fmt.Fprintf(&b, "- 撤销原交易 txID / 块 r: `%s` / `%d`\n", rep.RevocationTxID, rep.RevocationBlockR)
	fmt.Fprintf(&b, "- 复算判定: `passed=%v` (违规放行 %d, 旧块定案后延迟响应 %d, 时间精度不足 %d)\n",
		rep.Passed, rep.TotalViolations, rep.TotalDelayedSamples, rep.TotalAmbiguous)

	b.WriteString("\n## 实例阶段耗时与窗口汇总\n\n")
	b.WriteString("| 实例 | 探针角色 | `t_valid-t_submit` (ms) | `t_apply-t_valid` (ms) | `t_adopt-t_apply` (ms) | 确认后窗口 (ms) | 相对提交窗口 (ms) | 窗口状态 | 违规放行 | 计划/完成/漏探测/超时 | 时钟分辨率 (ns) |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, ia := range rep.Instances {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s | %s | %s | %s | `%s` | %d | %d/%d/%d/%d | %d |\n",
			ia.InstanceID, ia.ProbeRole,
			fmtOptMs(ia.ValidMinusSubmitMs), fmtOptMs(ia.ApplyMinusValidMs), fmtOptMs(ia.AdoptMinusApplyMs),
			fmtOptMs(ia.PostValidWindowMs), fmtOptMs(ia.PostSubmitWindowMs),
			ia.WindowStatus, len(ia.Violations),
			ia.Accounting.Planned, ia.Accounting.Completed, ia.Accounting.Missed, ia.Accounting.Timeout,
			ia.ClockResolutionNs)
	}

	b.WriteString("\n## 样本对账与删失说明\n\n")
	fmt.Fprintf(&b, "- 预热样本: %d, 计划探测: %d, 启动: %d, 完成: %d, 漏探测: %d, 超时: %d, 允许: %d, 拒绝: %d, 错误: %d\n",
		rep.TotalAccounting.Warmup, rep.TotalAccounting.Planned, rep.TotalAccounting.Started, rep.TotalAccounting.Completed,
		rep.TotalAccounting.Missed, rep.TotalAccounting.Timeout, rep.TotalAccounting.Allowed, rep.TotalAccounting.Denied, rep.TotalAccounting.Error)
	for _, ia := range rep.Instances {
		if len(ia.CensoringReasons) > 0 {
			fmt.Fprintf(&b, "- `%s` 删失/缺测备注: `%s`\n", ia.InstanceID, strings.Join(ia.CensoringReasons, ", "))
		}
		if ia.FirstDenyObservedAtNs != nil {
			fmt.Fprintf(&b, "- `%s` 首次拒绝观测: `code=%s`, `source=%s`, `unobserved_reason=%s`\n",
				ia.InstanceID, ia.FirstDenyCode, ia.FirstDenySource, ia.FirstDenyUnobservedReason)
		}
	}

	b.WriteString("\n## 原始输入文件摘要 (SHA-256)\n\n")
	b.WriteString("| 原始文件 | SHA-256 |\n| --- | --- |\n")
	keys := make([]string, 0, len(rep.InputFilesSHA256))
	for k := range rep.InputFilesSHA256 {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", k, rep.InputFilesSHA256[k])
	}
	return b.String()
}

func isUpstreamCascadeError(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "did not confirm the leaf grant") ||
		strings.Contains(lower, "package unavailable") ||
		strings.Contains(lower, "missing f06") ||
		strings.Contains(lower, "missing bm order package") ||
		strings.Contains(lower, "wallet was not prepared") ||
		strings.Contains(lower, "verified access package is unavailable")
}

func summarizeCascadeReason(msg string) string {
	return firstLine(msg)
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asInt64(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	default:
		return 0
	}
}

func parseOptInt64(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func nsToMs(ns int64) float64 {
	return float64(ns) / 1e6
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func fmtOptMs(v *float64) string {
	if v == nil {
		return "null"
	}
	return fmt.Sprintf("%.3f", *v)
}
