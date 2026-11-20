package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const e6RevHeader = "run_id,mode,configuration,revoked_grant_id,revocation_tx_id,revocation_block_r,revocation_block_hash,tx_index,validation_code,t_submit_ns,t_valid_ns,t_apply_ns,instance_id,probe_role,t_adopt_ns,adopt_block_h,probe_interval_ms,probe_lifetime_ms,detect_interval_ms,clock_timebase,clock_resolution_ns,clock_error_ns,status,unobserved_reason\n"
const e6ReqHeader = "run_id,mode,configuration,phase,instance_id,probe_role,seq,planned_at_ns,actual_interval_ns,submitted_at_ns,decision_at_ns,committed_at_ns,responded_at_ns,decision_at_sec,idempotency_key,request_id,challenge_id,decision_id,order_id,http_status,code,outcome,disposition,block_number,block_hash,g1_status_at_block,probe_tx_id,probe_block,probe_sent_at_ns,probe_deadline_ns,probe_sent_mono_ns,probe_checked_mono_ns,probe_deadline_mono_ns,clock_timebase,clock_resolution_ns,unobserved_reason\n"

func writeE6Fixture(t *testing.T, revRows, reqRows []string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run-e6-fixture")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"runId":"run-e6-fixture","experiment":"E6"}`+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "summary.json"), []byte(`{"runId":"run-e6-fixture","status":"PASS"}`+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "revocations.csv"), []byte(e6RevHeader+strings.Join(revRows, "\n")+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "requests.csv"), []byte(e6ReqHeader+strings.Join(reqRows, "\n")+"\n"), 0644)
	return dir
}

func TestAnalyzeE6DelayedResponseAfterOldBlockDecision(t *testing.T) {
	// Base time: 1700000000s in ns
	const base int64 = 1_700_000_000_000_000_000
	tSubmit := base + 100_000_000 // +100ms
	tValid := base + 200_000_000  // +200ms
	tApply := base + 220_000_000  // +220ms
	tAdopt := base + 260_000_000  // +260ms

	rev := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-1,probe1,%d,50,1000,5000,20,host-utc-unix-ns,1000,0,CONFIRMED,",
		tSubmit, tValid, tApply, tAdopt)

	// Sample 1: decided on old block 49 at +180ms (BEFORE t_valid), but HTTP response delayed to +350ms (AFTER t_adopt).
	// Sample 2: decided on old block 49 at +240ms (+40ms AFTER t_valid, BEFORE t_adopt), response delayed to +400ms (+200ms after t_valid).
	// Sample 3: denied on block 50 at +280ms (precheck deny without decision row).
	req1 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,1,%d,20000000,%d,%d,%d,%d,1700000000,k1,r1,c1,d1,o1,200,ALLOW,ALLOW,allowed,49,hash49,ACTIVE,ptx1,49,%d,%d,1000,180000000,5000001000,host-utc-unix-ns,1000,",
		base+170_000_000, base+170_000_000, base+180_000_000, base+185_000_000, base+350_000_000, base, base+5_000_000_000)
	req2 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,2,%d,20000000,%d,%d,%d,%d,1700000000,k2,r2,c2,d2,o2,200,ALLOW,ALLOW,allowed,49,hash49,ACTIVE,ptx1,49,%d,%d,1000,240000000,5000001000,host-utc-unix-ns,1000,",
		base+230_000_000, base+230_000_000, base+240_000_000, base+245_000_000, base+400_000_000, base, base+5_000_000_000)
	req3 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,3,%d,20000000,%d,null,null,%d,null,k3,r3,c3,,,403,ANCESTOR_INACTIVE,DENY,denied,50,hash50,REVOKED,ptx2,50,%d,%d,1000,null,5000001000,host-utc-unix-ns,1000,precheck_deny_no_decision_row",
		base+270_000_000, base+270_000_000, base+280_000_000, base+200_000_000, base+5_200_000_000)

	runDir := writeE6Fixture(t, []string{rev}, []string{req1, req2, req3})
	outDir := filepath.Join(t.TempDir(), "out")
	rep, err := AnalyzeE6Run(runDir, outDir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Passed || rep.TotalViolations != 0 {
		t.Fatalf("expected PASS with 0 violations, got passed=%v violations=%d", rep.Passed, rep.TotalViolations)
	}
	ia := rep.Instances[0]
	if ia.WindowStatus != "observed" || ia.PostValidWindowMs == nil || math.Abs(*ia.PostValidWindowMs-40.0) > 0.01 {
		t.Fatalf("expected postValidWindowMs=40.0 (from decision_at_ns, NOT responded_at_ns=200ms), got status=%s win=%v", ia.WindowStatus, ia.PostValidWindowMs)
	}
	if len(ia.DelayedResponseAfterOldBlock) != 2 {
		t.Fatalf("expected 2 delayed-response samples categorized, got %d", len(ia.DelayedResponseAfterOldBlock))
	}
	if ia.FirstDenySource != "responded_at_ns" || ia.FirstDenyUnobservedReason != "precheck_deny_no_decision_row" {
		t.Fatalf("unexpected first deny metadata: source=%s reason=%s", ia.FirstDenySource, ia.FirstDenyUnobservedReason)
	}
}

func TestAnalyzeE6ViolationAllowAfterRevocationBlock(t *testing.T) {
	const base int64 = 1_700_000_000_000_000_000
	rev := fmt.Sprintf("run-e6-fixture,BUYER_MANDATE,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-1,probe1,%d,50,1000,5000,20,host-utc-unix-ns,1000,0,CONFIRMED,",
		base+100_000_000, base+200_000_000, base+220_000_000, base+250_000_000)
	// Allowed at h=50 (== r) -> MUST FAIL.
	reqBad := fmt.Sprintf("run-e6-fixture,BUYER_MANDATE,B0,probe,gw-1,probe1,1,%d,20000000,%d,%d,%d,%d,1700000000,k1,r1,c1,d1,o1,200,ALLOW,ALLOW,allowed,50,hash50,REVOKED,ptx1,50,%d,%d,1000,260000000,5000001000,host-utc-unix-ns,1000,",
		base+255_000_000, base+255_000_000, base+260_000_000, base+262_000_000, base+265_000_000, base, base+5_000_000_000)

	rep, err := AnalyzeE6Run(writeE6Fixture(t, []string{rev}, []string{reqBad}), filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Passed || rep.TotalViolations != 1 || rep.Instances[0].WindowStatus != "VIOLATION" ||
		rep.Instances[0].Violations[0].Type != "allow_after_revocation_block" {
		t.Fatalf("expected allow_after_revocation_block violation, got %+v", rep.Instances[0])
	}
}

func TestAnalyzeE6ViolationAllowPastProbeDeadline(t *testing.T) {
	const base int64 = 1_700_000_000_000_000_000
	rev := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-1,probe1,%d,50,1000,5000,20,host-utc-unix-ns,1000,0,CONFIRMED,",
		base+100_000_000, base+200_000_000, base+220_000_000, base+6_000_000_000)
	// Old block 49, but decision at +5.1s >= probe deadline +5.0s -> MUST FAIL.
	reqExpired := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,1,%d,20000000,%d,%d,%d,%d,1700000005,k1,r1,c1,d1,o1,200,ALLOW,ALLOW,allowed,49,hash49,ACTIVE,ptx1,49,%d,%d,1000,5100001000,5000001000,host-utc-unix-ns,1000,",
		base+5_090_000_000, base+5_090_000_000, base+5_100_000_000, base+5_102_000_000, base+5_105_000_000, base, base+5_000_000_000)

	rep, err := AnalyzeE6Run(writeE6Fixture(t, []string{rev}, []string{reqExpired}), filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Passed || rep.TotalViolations != 1 || rep.Instances[0].Violations[0].Type != "allow_past_probe_deadline" {
		t.Fatalf("expected allow_past_probe_deadline violation, got %+v", rep.Instances[0])
	}
}

func TestAnalyzeE6MissedProbesAndPostValidUnobserved(t *testing.T) {
	const base int64 = 1_700_000_000_000_000_000
	rev := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-1,probe1,%d,50,1000,5000,20,host-utc-unix-ns,1000,0,CONFIRMED,",
		base+100_000_000, base+200_000_000, base+210_000_000, base+215_000_000)
	// Probe 1: allowed before t_valid; Probe 2: missed slot; Probe 3: timeout; Probe 4: denied after adopt.
	r1 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,1,%d,20000000,%d,%d,%d,%d,1700000000,k1,r1,c1,d1,o1,200,ALLOW,ALLOW,allowed,49,hash49,ACTIVE,ptx1,49,%d,%d,1000,150000000,5000001000,host-utc-unix-ns,1000,",
		base+140_000_000, base+140_000_000, base+150_000_000, base+152_000_000, base+155_000_000, base, base+5_000_000_000)
	r2 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,2,%d,null,null,null,null,null,null,k2,,,,,null,,,missed,null,,,,null,null,null,null,null,null,host-utc-unix-ns,1000,missed_probe_slot",
		base+205_000_000)
	r3 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,3,%d,20000000,%d,null,null,null,null,k3,r3,c3,,,null,,,timeout,null,,,,null,null,null,null,null,null,host-utc-unix-ns,1000,execute_timeout",
		base+210_000_000, base+210_000_000)
	r4 := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,4,%d,20000000,%d,null,null,%d,null,k4,r4,c4,,,403,ANCESTOR_INACTIVE,DENY,denied,50,hash50,REVOKED,ptx2,50,%d,%d,1000,null,5000001000,host-utc-unix-ns,1000,precheck_deny_no_decision_row",
		base+225_000_000, base+225_000_000, base+230_000_000, base+200_000_000, base+5_200_000_000)

	rep, err := AnalyzeE6Run(writeE6Fixture(t, []string{rev}, []string{r1, r2, r3, r4}), filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	ia := rep.Instances[0]
	if !rep.Passed || ia.WindowStatus != "post_valid_allow_unobserved" || ia.PostValidWindowMs != nil {
		t.Fatalf("expected post_valid_allow_unobserved, got status=%s win=%v passed=%v", ia.WindowStatus, ia.PostValidWindowMs, rep.Passed)
	}
	if ia.Accounting.Planned != 4 || ia.Accounting.Started != 3 || ia.Accounting.Completed != 2 || ia.Accounting.Missed != 1 || ia.Accounting.Timeout != 1 {
		t.Fatalf("unexpected sample accounting: %+v", ia.Accounting)
	}
}

func TestAnalyzeE6InsufficientTimeResolutionClassification(t *testing.T) {
	const base int64 = 1_700_000_000_000_000_000
	// Coarse 1-second resolution (missing decision_at_ns, only decision_at_sec=1700000000) overlapping t_valid at 1700000000.200s.
	rev := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,grant-g1,tx-rev,50,hash50,0,VALID,%d,%d,%d,gw-1,probe1,%d,50,1000,5000,20,host-utc-unix-sec,1000000000,0,CONFIRMED,",
		base+100_000_000, base+200_000_000, base+220_000_000, base+250_000_000)
	rCoarse := fmt.Sprintf("run-e6-fixture,RESOURCE_PREAUTHORIZED,B0,probe,gw-1,probe1,1,%d,20000000,%d,null,null,%d,1700000000,k1,r1,c1,d1,o1,200,ALLOW,ALLOW,allowed,49,hash49,ACTIVE,ptx1,49,%d,%d,1000,230000000,5000001000,host-utc-unix-sec,1000000000,",
		base+220_000_000, base+220_000_000, base+240_000_000, base, base+5_000_000_000)

	rep, err := AnalyzeE6Run(writeE6Fixture(t, []string{rev}, []string{rCoarse}), filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	ia := rep.Instances[0]
	if ia.WindowStatus != "insufficient_time_resolution" || len(ia.AmbiguousTimingSamples) != 1 || !ia.AmbiguousTimingSamples[0].UsedSecondLevel {
		t.Fatalf("expected insufficient_time_resolution classification, got status=%s ambiguous=%+v", ia.WindowStatus, ia.AmbiguousTimingSamples)
	}
}
