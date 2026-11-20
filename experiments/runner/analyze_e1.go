package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const E1AnalysisVersion = "e1-analyzer/v1"

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
	if err := os.MkdirAll(absOut, 0755); err != nil {
		return "", "", err
	}
	return absRun, absOut, nil
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
		p := filepath.Join(absRun, name)
		raw, err := os.ReadFile(p)
		if err != nil {
			rep.MissingInputFiles = append(rep.MissingInputFiles, name)
			return nil, false
		}
		sum := sha256.Sum256(raw)
		rep.InputFilesSHA256[name] = hex.EncodeToString(sum[:])
		return raw, true
	}

	// 1. manifest.json
	var manifest map[string]any
	if raw, ok := readTracked("manifest.json"); ok {
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
	var reqRows []map[string]string
	if raw, ok := readTracked("requests.csv"); ok {
		r := csv.NewReader(strings.NewReader(string(raw)))
		records, err := r.ReadAll()
		if err != nil {
			rep.Anomalies = append(rep.Anomalies, fmt.Sprintf("requests.csv parse error: %v", err))
		} else if len(records) >= 1 {
			headers := records[0]
			for _, rec := range records[1:] {
				row := make(map[string]string, len(headers))
				for idx, h := range headers {
					if idx < len(rec) {
						row[h] = rec[idx]
					}
				}
				reqRows = append(reqRows, row)
			}
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

		// Model traces for mode
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
		sort.Strings(mr.LLMTraceCases)
		mr.LLMTraceModelMatch = len(seenTraceCases) > 0 && modelMatch

		// F06 positive loop
		var f06Rows []map[string]string
		for _, r := range reqRows {
			if r["case"] == "F06" && r["authorization_mode"] == spec.mode {
				f06Rows = append(f06Rows, r)
			}
		}
		mr.F06HTTPRoundTrips = len(f06Rows)
		var f06QuoteReq, f06OrderReq map[string]string
		if len(f06Rows) == 4 &&
			f06Rows[0]["http_status"] == "201" && f06Rows[1]["http_status"] == "200" &&
			f06Rows[2]["http_status"] == "201" && f06Rows[3]["http_status"] == "200" {
			f06QuoteReq, f06OrderReq = f06Rows[1], f06Rows[3]
			mr.F06QuoteID = f06QuoteReq["quote_id"]
			mr.F06OrderID = f06OrderReq["order_id"]
			mr.F06CreationDecisionID = f06OrderReq["decision_id"]
			mr.F06ChallengeIDs = []string{f06QuoteReq["challenge_id"], f06OrderReq["challenge_id"]}
			qRow := quotes[mr.F06QuoteID]
			oRow := orders[mr.F06OrderID]
			mr.F06QuoteAmountMinor = asInt64(qRow["total_amount_minor"])
			mr.F06OrderAmountMinor = asInt64(oRow["total_amount_minor"])
			mr.F06PrimaryDBMatched = f06QuoteReq["quote_id"] != "" &&
				f06QuoteReq["quote_id"] == f06OrderReq["quote_id"] &&
				mr.F06QuoteAmountMinor == 80000 &&
				mr.F06OrderAmountMinor == 80000 &&
				asString(oRow["decision_id"]) == f06OrderReq["decision_id"] &&
				asString(oRow["quote_id"]) == f06QuoteReq["quote_id"]
			if !mr.F06PrimaryDBMatched {
				mr.Anomalies = append(mr.Anomalies, "F06 primary DB quote/order mismatch")
			}
		} else {
			mr.Anomalies = append(mr.Anomalies, fmt.Sprintf("F06 expected 4 round trips (201/200/201/200), observed %d", len(f06Rows)))
		}

		// F07 negative controls
		var f07Rows []map[string]string
		for _, r := range reqRows {
			if r["case"] == "F07" && r["authorization_mode"] == spec.mode {
				f07Rows = append(f07Rows, r)
			}
		}
		var f07QuoteReq map[string]string
		var f07NegReqs []map[string]string
		zeroSideEffect := true
		if len(f07Rows) >= 6 && f07Rows[1]["http_status"] == "200" {
			f07QuoteReq = f07Rows[1]
			mr.F07QuoteAmountMinor = asInt64(quotes[f07QuoteReq["quote_id"]]["total_amount_minor"])
			for _, r := range f07Rows {
				if r["action"] == "order.create" {
					f07NegReqs = append(f07NegReqs, r)
					if r["code"] != "" {
						mr.F07Denials[r["code"]] = r["decision_id"]
					}
					if r["order_id"] != "" || orderByKey[r["idempotency_key"]] || keyRowsByKey[r["idempotency_key"]] {
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
		checkReqs := make([]map[string]string, 0, 5)
		for _, r := range []*map[string]string{&f06QuoteReq, &f06OrderReq, &f07QuoteReq} {
			if *r != nil {
				checkReqs = append(checkReqs, *r)
			}
		}
		checkReqs = append(checkReqs, f07NegReqs...)
		for _, r := range checkReqs {
			dec := decisions[r["decision_id"]]
			chal := challenges[r["challenge_id"]]
			if dec == nil || chal == nil {
				mr.Anomalies = append(mr.Anomalies, fmt.Sprintf("%s missing decision or challenge row for %s", r["case"], r["decision_id"]))
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
				asString(dec["task_id"]) == r["task_id"] &&
				r["request_hash"] == asString(chal["request_hash"]) &&
				blOK && bl.Point.BlockHash == asString(dec["block_hash"]) &&
				txOK && txInfo.height == probeBlock && txInfo.code == "VALID" &&
				sentMono <= checkedMono && checkedMono < deadlineMono
			if ok {
				mr.ProbeAndBlockChecked++
			} else {
				mr.Anomalies = append(mr.Anomalies, fmt.Sprintf("%s decision %s failed challenge/block/probe cross-check", r["case"], r["decision_id"]))
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
				sum := sha256.Sum256([]byte(f16.CanonicalEvidence))
				digest := hex.EncodeToString(sum[:])
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
		if r["case"] == "F06" && r["decision_id"] != "" {
			if dec := decisions[r["decision_id"]]; dec != nil {
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
			rep.PublishedAuditMismatches = mismatches
			rep.PublishedAuditMatches = len(mismatches) == 0
		}
	}

	// 10. Summarize failure/missing diagnostics and overall reconciliation verdict
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

	if err := writeJSONFile(filepath.Join(absOut, "recomputed.json"), rep); err != nil {
		return nil, err
	}
	md := renderE1RecomputedMarkdown(rep)
	if err := os.WriteFile(filepath.Join(absOut, "recomputed-table.md"), []byte(md), 0644); err != nil {
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
	sort.Strings(keys)
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
