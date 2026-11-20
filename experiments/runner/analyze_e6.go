package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const E6AnalysisVersion = "e6-analyzer/v1"

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
	InstanceID          string  `json:"instanceId"`
	Seq                 int64   `json:"seq"`
	DecisionID          string  `json:"decisionId"`
	BlockNumber         int64   `json:"blockNumber"`
	RevocationBlockR    int64   `json:"revocationBlockR"`
	DecisionAtNs        int64   `json:"decisionAtNs"`
	CommittedAtNs       *int64  `json:"committedAtNs,omitempty"`
	RespondedAtNs       int64   `json:"respondedAtNs"`
	DecisionMinusValid  float64 `json:"decisionMinusValidMs"`
	ResponseMinusValid  float64 `json:"responseMinusValidMs"`
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
	Warmup              int      `json:"warmup"`
	Planned             int      `json:"planned"`
	Started             int      `json:"started"`
	Completed           int      `json:"completed"`
	Missed              int      `json:"missed"`
	Timeout             int      `json:"timeout"`
	Allowed             int      `json:"allowed"`
	Denied              int      `json:"denied"`
	Error               int      `json:"error"`
	AvailabilityRate    *float64 `json:"availabilityRate,omitempty"`
	MedianIntervalMs    *float64 `json:"medianActualIntervalMs,omitempty"`
	MaxIntervalMs       *float64 `json:"maxActualIntervalMs,omitempty"`
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

	// Optional metadata from manifest.json and summary.json
	if raw, ok := readTracked("manifest.json"); ok {
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			if id, ok := m["runId"].(string); ok && id != "" {
				rep.SourceRunID = id
			}
		}
	}
	_, _ = readTracked("summary.json")

	revRows, err := readCSVRows(readTracked, "revocations.csv")
	if err != nil {
		return nil, fmt.Errorf("parse revocations.csv: %w", err)
	}
	reqRows, err := readCSVRows(readTracked, "requests.csv")
	if err != nil {
		return nil, fmt.Errorf("parse requests.csv: %w", err)
	}
	if len(revRows) == 0 {
		rep.Passed = false
		rep.Anomalies = append(rep.Anomalies, "revocations.csv missing or empty")
	}

	reqByInstance := map[string][]map[string]string{}
	for _, r := range reqRows {
		inst := r["instance_id"]
		reqByInstance[inst] = append(reqByInstance[inst], r)
	}

	var allIntervals []float64
	for _, rr := range revRows {
		ia := analyzeE6Instance(rr, reqByInstance[rr["instance_id"]])
		if rep.Mode == "" {
			rep.Mode = rr["mode"]
		}
		if rep.Configuration == "" {
			rep.Configuration = rr["configuration"]
		}
		if rep.RevokedGrantID == "" {
			rep.RevokedGrantID = rr["revoked_grant_id"]
		}
		if rep.RevocationTxID == "" {
			rep.RevocationTxID = rr["revocation_tx_id"]
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
		if ia.Accounting.MedianIntervalMs != nil {
			allIntervals = append(allIntervals, *ia.Accounting.MedianIntervalMs)
		}
		if !ia.Passed {
			rep.Passed = false
		}
	}
	if rep.TotalAccounting.Planned > 0 {
		rate := float64(rep.TotalAccounting.Completed) / float64(rep.TotalAccounting.Planned)
		rep.TotalAccounting.AvailabilityRate = &rate
	}
	if len(allIntervals) > 0 {
		sort.Float64s(allIntervals)
		med := allIntervals[len(allIntervals)/2]
		mx := allIntervals[len(allIntervals)-1]
		rep.TotalAccounting.MedianIntervalMs = &med
		rep.TotalAccounting.MaxIntervalMs = &mx
	}

	if err := writeJSONFile(filepath.Join(absOut, "recomputed.json"), rep); err != nil {
		return nil, err
	}
	md := renderE6RecomputedMarkdown(rep)
	if err := os.WriteFile(filepath.Join(absOut, "recomputed-table.md"), []byte(md), 0644); err != nil {
		return nil, err
	}
	return rep, nil
}

func analyzeE6Instance(rev map[string]string, rows []map[string]string) *E6InstanceAnalysis {
	ia := &E6InstanceAnalysis{
		InstanceID:        rev["instance_id"],
		ProbeRole:         rev["probe_role"],
		RevocationTxID:    rev["revocation_tx_id"],
		RevocationStatus:  rev["status"],
		ClockTimebase:     rev["clock_timebase"],
		Passed:            true,
	}
	if r, ok := parseOptInt64(rev["revocation_block_r"]); ok {
		ia.RevocationBlockR = r
	}
	if v, ok := parseOptInt64(rev["probe_interval_ms"]); ok {
		ia.ProbeIntervalMs = v
	}
	if v, ok := parseOptInt64(rev["probe_lifetime_ms"]); ok {
		ia.ProbeLifetimeMs = v
	}
	if v, ok := parseOptInt64(rev["detect_interval_ms"]); ok {
		ia.DetectIntervalMs = v
	}
	if v, ok := parseOptInt64(rev["clock_resolution_ns"]); ok {
		ia.ClockResolutionNs = v
	}
	if v, ok := parseOptInt64(rev["clock_error_ns"]); ok {
		ia.ClockErrorNs = v
	}
	if v, ok := parseOptInt64(rev["t_submit_ns"]); ok {
		ia.TSubmitNs = &v
	}
	if v, ok := parseOptInt64(rev["t_valid_ns"]); ok {
		ia.TValidNs = &v
	}
	if v, ok := parseOptInt64(rev["t_apply_ns"]); ok {
		ia.TApplyNs = &v
	}
	if v, ok := parseOptInt64(rev["t_adopt_ns"]); ok {
		ia.TAdoptNs = &v
	}
	if v, ok := parseOptInt64(rev["adopt_block_h"]); ok {
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

	revConfirmed := ia.TValidNs != nil && ia.RevocationBlockR > 0 && (rev["validation_code"] == "" || rev["validation_code"] == "VALID")

	var actualIntervalsMs []float64
	var lastPostSubmitAllowNs *int64

	for _, r := range rows {
		if r["phase"] == "warmup" {
			ia.Accounting.Warmup++
			continue
		}
		ia.Accounting.Planned++
		disp := r["disposition"]
		switch disp {
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

		if iv, ok := parseOptInt64(r["actual_interval_ns"]); ok && iv > 0 {
			actualIntervalsMs = append(actualIntervalsMs, nsToMs(iv))
		}

		seq, _ := parseOptInt64(r["seq"])
		decID := r["decision_id"]
		blockNo, hasBlock := parseOptInt64(r["block_number"])
		decNs, hasDecNs := parseOptInt64(r["decision_at_ns"])
		decSec, hasDecSec := parseOptInt64(r["decision_at_sec"])
		commitNs, hasCommitNs := parseOptInt64(r["committed_at_ns"])
		respNs, hasRespNs := parseOptInt64(r["responded_at_ns"])
		probeDeadlineNs, hasProbeDeadlineNs := parseOptInt64(r["probe_deadline_ns"])
		probeCheckedMono, hasProbeCheckedMono := parseOptInt64(r["probe_checked_mono_ns"])
		probeDeadlineMono, hasProbeDeadlineMono := parseOptInt64(r["probe_deadline_mono_ns"])
		rowClockRes, hasRowRes := parseOptInt64(r["clock_resolution_ns"])

		// Track first deny after revocation submission.
		if disp == "denied" {
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
					ia.FirstDenyCode = r["code"]
					ia.FirstDenyUnobservedReason = r["unobserved_reason"]
				}
			}
			continue
		}

		if disp != "allowed" {
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

		// Violation 1: ALLOW using block h >= r (adopted revocation block or later).
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
		sort.Float64s(actualIntervalsMs)
		med := actualIntervalsMs[len(actualIntervalsMs)/2]
		mx := actualIntervalsMs[len(actualIntervalsMs)-1]
		ia.Accounting.MedianIntervalMs = &med
		ia.Accounting.MaxIntervalMs = &mx
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
	return ia
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
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", k, rep.InputFilesSHA256[k])
	}
	return b.String()
}

func readCSVRows(readFn func(string) ([]byte, bool), name string) ([]map[string]string, error) {
	raw, ok := readFn(name)
	if !ok {
		return nil, nil
	}
	r := csv.NewReader(strings.NewReader(string(raw)))
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, nil
	}
	headers := records[0]
	out := make([]map[string]string, 0, len(records)-1)
	for _, rec := range records[1:] {
		row := make(map[string]string, len(headers))
		for i, h := range headers {
			if i < len(rec) {
				row[h] = rec[i]
			}
		}
		out = append(out, row)
	}
	return out, nil
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
