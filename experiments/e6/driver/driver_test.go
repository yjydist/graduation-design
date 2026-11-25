package main

import (
	"encoding/csv"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/ledger"
	"grad/protocol/registry"
)

func TestRegisterAndValidateE6Flags(t *testing.T) {
	t.Parallel()

	var cfg e6Config
	fs := flag.NewFlagSet("e6-driver", flag.ContinueOnError)
	registerE6Flags(fs, &cfg)

	err := fs.Parse([]string{
		"-revision", "deadbeef",
		"-dir", "/tmp/inst",
		"-out", "/tmp/out",
		"-mode", "bm",
		"-configuration", "b1",
		"-probe-interval", "1s",
		"-probe-lifetime", "5s",
		"-detect-interval", "20ms",
		"-revoke-after", "500ms",
		"-duration", "6s",
		"-instances", "2",
		"-seed", "42",
	})
	require.NoError(t, err)

	modeShort, authMode, configName, err := validateE6Config(cfg)
	require.NoError(t, err)
	assert.Equal(t, "BM", modeShort)
	assert.Equal(t, registry.BM, authMode)
	assert.Equal(t, "B1", configName)
	assert.Equal(t, 42, cfg.seed)

	// Invalid mode
	bad := cfg
	bad.mode = "INVALID"
	_, _, _, err = validateE6Config(bad)
	require.Error(t, err)

	// Invalid configuration
	bad = cfg
	bad.configuration = "B9"
	_, _, _, err = validateE6Config(bad)
	require.Error(t, err)

	// Invalid instances count
	bad = cfg
	bad.instances = 3
	_, _, _, err = validateE6Config(bad)
	require.Error(t, err)

	// probeLifetime < probeInterval
	bad = cfg
	bad.probeInterval = 5 * time.Second
	bad.probeLifetime = 2 * time.Second
	_, _, _, err = validateE6Config(bad)
	require.Error(t, err)

	// Missing dir/out
	bad = cfg
	bad.out = ""
	_, _, _, err = validateE6Config(bad)
	require.Error(t, err)
}

func TestE6ProcurementSetupValidates(t *testing.T) {
	t.Parallel()

	setup := e6ProcurementSetup(strings.Repeat("a", 64), "run-test-e6", 1109)
	require.NoError(t, setup.Validate())
	assert.Contains(t, setup.Spec.Resources, registry.ResourceOrders)
	assert.Contains(t, setup.Spec.Resources, registry.ResourceQuotes)
	assert.Contains(t, setup.Spec.Actions, registry.ActionOrderCreate)
	assert.Contains(t, setup.Spec.Actions, registry.ActionQuoteRead)
}

func TestApplyProbeLeaseAndDecisionTiming(t *testing.T) {
	t.Parallel()

	sentAt := time.Date(2026, 11, 22, 10, 0, 0, 1000, time.UTC)
	deadline := sentAt.Add(5 * time.Second)
	decisionAt := sentAt.Add(200 * time.Millisecond)
	committedAt := decisionAt.Add(5 * time.Millisecond)

	var rec probeSlotRecord
	applyProbeLease(&rec, ledger.ProbeLease{
		TxID:           "probe-tx-1",
		ProbeBlock:     12,
		SentAt:         sentAt,
		Deadline:       deadline,
		SentMonoNs:     1000,
		DeadlineMonoNs: 5_000_001_000,
		CheckedMonoNs:  200_001_000,
	})
	assert.Equal(t, "probe-tx-1", rec.ProbeTxID)
	require.NotNil(t, rec.ProbeBlock)
	assert.Equal(t, int64(12), *rec.ProbeBlock)
	require.NotNil(t, rec.ProbeSentAtNs)
	assert.Equal(t, sentAt.UnixNano(), *rec.ProbeSentAtNs)
	require.NotNil(t, rec.ProbeDeadlineNs)
	assert.Equal(t, deadline.UnixNano(), *rec.ProbeDeadlineNs)
	require.NotNil(t, rec.ProbeCheckedMonoNs)
	assert.Equal(t, int64(200_001_000), *rec.ProbeCheckedMonoNs)

	applyDecisionTiming(&rec, domgw.DecisionTiming{
		DecisionID:          "dec-1",
		BlockNumber:         13,
		BlockHash:           strings.Repeat("f", 64),
		ProbeTxID:           "probe-tx-2",
		ProbeBlock:          13,
		ProbeSentAt:         sentAt,
		ProbeDeadline:       deadline,
		ProbeSentMonoNs:     2000,
		ProbeCheckedMonoNs:  3000,
		ProbeDeadlineMonoNs: 5_000_002_000,
		DecisionAtSec:       decisionAt.Unix(),
		DecisionAt:          decisionAt,
		CommittedAt:         committedAt,
	})
	require.NotNil(t, rec.DecisionAtNs)
	assert.Equal(t, decisionAt.UnixNano(), *rec.DecisionAtNs)
	require.NotNil(t, rec.CommittedAtNs)
	assert.Equal(t, committedAt.UnixNano(), *rec.CommittedAtNs)
	require.NotNil(t, rec.BlockNumber)
	assert.Equal(t, int64(13), *rec.BlockNumber)
	assert.Equal(t, "probe-tx-2", rec.ProbeTxID)
}

func TestWriteRevocationsAndRequestsCSVSchema(t *testing.T) {
	t.Parallel()

	outDir := t.TempDir()
	baseTime := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

	tApply := baseTime.Add(50 * time.Millisecond).UnixNano()
	rev := &ledger.RevocationEvent{
		GrantID:         strings.Repeat("1", 64),
		TxID:            "rev-tx-1",
		BlockNumber:     20,
		BlockHash:       strings.Repeat("2", 64),
		TxIndex:         0,
		ValidationCode:  "VALID",
		Status:          "CONFIRMED",
		SubmittedAt:     baseTime,
		ValidObservedAt: baseTime.Add(30 * time.Millisecond),
	}

	tr1 := &instanceTracker{id: "gw-1", probeRole: "probe1", timings: map[string]domgw.DecisionTiming{}}
	tr1.recordAdopt(ledger.AdoptEvent{BlockNumber: 20, AdoptedAt: baseTime.Add(90 * time.Millisecond)}, 20)
	tr2 := &instanceTracker{id: "gw-2", probeRole: "probe2", timings: map[string]domgw.DecisionTiming{}}

	cfg := e6Config{
		configuration:  "B0",
		probeInterval:  time.Second,
		probeLifetime:  5 * time.Second,
		detectInterval: 20 * time.Millisecond,
	}

	revPath := filepath.Join(outDir, "revocations.csv")
	require.NoError(t, writeRevocationsCSV(revPath, "run-e6-1", registry.RP, cfg, rev, &tApply, []*instanceTracker{tr1, tr2}, 1000))

	revRaw, err := os.ReadFile(revPath)
	require.NoError(t, err)
	revRows, err := csv.NewReader(strings.NewReader(string(revRaw))).ReadAll()
	require.NoError(t, err)
	require.Len(t, revRows, 3)

	wantRevHeader := []string{
		"run_id", "mode", "configuration", "revoked_grant_id", "revocation_tx_id",
		"revocation_block_r", "revocation_block_hash", "tx_index", "validation_code",
		"t_submit_ns", "t_valid_ns", "t_apply_ns",
		"instance_id", "probe_role", "t_adopt_ns", "adopt_block_h",
		"probe_interval_ms", "probe_lifetime_ms", "detect_interval_ms",
		"clock_timebase", "clock_resolution_ns", "clock_error_ns", "status", "unobserved_reason",
	}
	assert.Equal(t, wantRevHeader, revRows[0])
	assert.Equal(t, "gw-1", revRows[1][12])
	assert.Equal(t, "20", revRows[1][15])
	assert.Equal(t, "", revRows[1][23])
	assert.Equal(t, "gw-2", revRows[2][12])
	assert.Equal(t, "null", revRows[2][14])
	assert.Equal(t, "null", revRows[2][15])
	assert.Equal(t, "instance_did_not_adopt_r_during_window", revRows[2][23])

	statusOK := 200
	block19 := int64(19)
	decNs := baseTime.Add(10 * time.Millisecond).UnixNano()
	psNs := baseTime.Add(-1 * time.Second).UnixNano()
	pdNs := baseTime.Add(4 * time.Second).UnixNano()
	records := []probeSlotRecord{
		{
			Phase:           "probe",
			InstanceID:      "gw-1",
			ProbeRole:       "probe1",
			Seq:             1,
			PlannedAtNs:     baseTime.UnixNano(),
			DecisionAtNs:    &decNs,
			HTTPStatus:      &statusOK,
			Outcome:         "ALLOW",
			Disposition:     "allowed",
			BlockNumber:     &block19,
			G1StatusAtBlock: registry.Active,
			ProbeSentAtNs:   &psNs,
			ProbeDeadlineNs: &pdNs,
		},
		{
			Phase:            "probe",
			InstanceID:       "gw-1",
			ProbeRole:        "probe1",
			Seq:              2,
			PlannedAtNs:      baseTime.Add(20 * time.Millisecond).UnixNano(),
			Disposition:      "missed",
			UnobservedReason: "missed_probe_slot",
		},
	}

	reqPath := filepath.Join(outDir, "requests.csv")
	require.NoError(t, writeRequestsCSV(reqPath, "run-e6-1", registry.RP, "B0", 1000, records))

	reqRaw, err := os.ReadFile(reqPath)
	require.NoError(t, err)
	reqRows, err := csv.NewReader(strings.NewReader(string(reqRaw))).ReadAll()
	require.NoError(t, err)
	require.Len(t, reqRows, 3)

	wantReqHeader := []string{
		"run_id", "mode", "configuration", "phase", "instance_id", "probe_role", "seq",
		"planned_at_ns", "actual_interval_ns", "submitted_at_ns", "decision_at_ns", "committed_at_ns", "responded_at_ns", "decision_at_sec",
		"idempotency_key", "request_id", "challenge_id", "decision_id", "order_id",
		"http_status", "code", "outcome", "disposition",
		"block_number", "block_hash", "g1_status_at_block",
		"probe_tx_id", "probe_block", "probe_sent_at_ns", "probe_deadline_ns",
		"probe_sent_mono_ns", "probe_checked_mono_ns", "probe_deadline_mono_ns",
		"clock_timebase", "clock_resolution_ns", "unobserved_reason",
	}
	assert.Equal(t, wantReqHeader, reqRows[0])
	assert.Equal(t, "200", reqRows[1][19])
	assert.Equal(t, "null", reqRows[1][8])
	assert.Equal(t, "19", reqRows[1][23])
	assert.Equal(t, "missed", reqRows[2][22])
	assert.Equal(t, "null", reqRows[2][10])
	assert.Equal(t, "null", reqRows[2][19])
	assert.Equal(t, "missed_probe_slot", reqRows[2][35])

	acct := accountProbeRecords(records)
	assert.Equal(t, 2, acct["planned"])
	assert.Equal(t, 1, acct["started"])
	assert.Equal(t, 1, acct["completed"])
	assert.Equal(t, 1, acct["allowed"])
	assert.Equal(t, 1, acct["missed"])
}
