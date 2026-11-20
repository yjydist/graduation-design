package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func hashDirFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	hashes := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sum, err := sha256File(path)
		if err != nil {
			return err
		}
		hashes[filepath.ToSlash(rel)] = sum
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hashes
}

func TestAnalyzeE1OfflinePassRunMatchesPublishedAuditAndIsImmutable(t *testing.T) {
	repo := testRepoRoot(t)
	runDir := filepath.Join(repo, "experiments", "e1-procurement", "runs", "run-3f8a7a6db26d582c")
	beforeHashes := hashDirFiles(t, runDir)

	out1 := filepath.Join(t.TempDir(), "out1")
	out2 := filepath.Join(t.TempDir(), "out2")

	rep1, err := AnalyzeE1Run(runDir, out1)
	if err != nil {
		t.Fatalf("AnalyzeE1Run #1 failed: %v", err)
	}
	rep2, err := AnalyzeE1Run(runDir, out2)
	if err != nil {
		t.Fatalf("AnalyzeE1Run #2 failed: %v", err)
	}

	// Verify key counts match published fixed-build run-3f8a7a6db26d582c.
	if !rep1.ReconciliationPassed || !rep1.PublishedAuditChecked || !rep1.PublishedAuditMatches {
		t.Fatalf("expected full reconciliation and published audit match, got anomalies=%v mismatches=%v", rep1.Anomalies, rep1.PublishedAuditMismatches)
	}
	if rep1.PassedCases != 16 || rep1.SummaryVerdicts != 16 || rep1.CapturedGatewayRequests != 78 ||
		rep1.LLMSessions != 8 || rep1.LLMToolCalls != 19 || rep1.Blocks != 106 ||
		rep1.StoredQuotes != 11 || rep1.StoredOrders != 8 || rep1.StoredDecisions != 27 {
		t.Fatalf("unexpected recomputed counts: %+v", rep1)
	}
	if rep1.F06BlockInterval == nil || rep1.F06BlockInterval.NonProbeWriteKeys != 0 {
		t.Fatalf("expected 0 non-probe write keys in F06 interval, got %+v", rep1.F06BlockInterval)
	}

	// Verify repeatability: identical input + analysisVersion => identical bytes.
	b1, err := os.ReadFile(filepath.Join(out1, "recomputed.json"))
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(filepath.Join(out2, "recomputed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) || rep1.AnalysisVersion != rep2.AnalysisVersion {
		t.Fatalf("offline recomputation output is not deterministic")
	}

	// Verify raw run directory was NOT modified (SHA-256 unchanged for every file).
	afterHashes := hashDirFiles(t, runDir)
	if len(beforeHashes) != len(afterHashes) {
		t.Fatalf("raw run file count changed: %d -> %d", len(beforeHashes), len(afterHashes))
	}
	for k, before := range beforeHashes {
		if afterHashes[k] != before {
			t.Fatalf("raw run file %s modified during analysis", k)
		}
	}

	// Verify writing inside raw run directory is rejected.
	if _, err := AnalyzeE1Run(runDir, filepath.Join(runDir, "derived")); err == nil {
		t.Fatalf("expected error when --out is inside --run-dir")
	}
}

func TestAnalyzeE1OfflineFailedRunDetectsFailureAndMissing(t *testing.T) {
	repo := testRepoRoot(t)
	runDir := filepath.Join(repo, "experiments", "e1-procurement", "runs", "run-8e823c1f2d3bc13a")
	out := filepath.Join(t.TempDir(), "failed-out")

	rep, err := AnalyzeE1Run(runDir, out)
	if err != nil {
		t.Fatalf("AnalyzeE1Run on failed run errored: %v", err)
	}
	if rep.RunStatus != "FAIL" || rep.ReconciliationPassed {
		t.Fatalf("expected FAIL / reconciliationPassed=false, got status=%s passed=%v", rep.RunStatus, rep.ReconciliationPassed)
	}
	if rep.PassedCases != 4 || rep.FailedCases != 12 || rep.UpstreamBlockedCases < 10 {
		t.Fatalf("expected 4 passed / 12 failed / >=10 upstream blocked, got passed=%d failed=%d blocked=%d",
			rep.PassedCases, rep.FailedCases, rep.UpstreamBlockedCases)
	}
	if rep.LLMErrorSessions == 0 || len(rep.FailureAndMissingDiagnostic) == 0 || len(rep.MissingInputFiles) == 0 {
		t.Fatalf("expected LLM errors, diagnostics and missing files to be reported, got errors=%d diag=%v missing=%v",
			rep.LLMErrorSessions, rep.FailureAndMissingDiagnostic, rep.MissingInputFiles)
	}
}
