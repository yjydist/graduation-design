package fabric

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"graduation-design/internal/experiment"
	api "graduation-design/internal/fabricapi"
)

func newBaselineTestRun(t *testing.T) *baselineRun {
	t.Helper()
	in, err := experiment.Baseline(1109)
	if err != nil {
		t.Fatal(err)
	}
	e, err := experiment.NewEvidence(baselineTestEvidenceDir(t), "test", in)
	if err != nil {
		t.Fatal(err)
	}
	return &baselineRun{inputs: in, evidence: e, d: &deployment{DeploymentID: "test"}, options: baselineOptions{RequestTimeout: time.Nanosecond}}
}

func baselineTestEvidenceDir(t *testing.T) string {
	t.Helper()
	if root := os.Getenv("BASELINE_FAULT_EVIDENCE_DIR"); root != "" {
		return filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"))
	}
	return filepath.Join(t.TempDir(), "evidence")
}

func TestBaselineManagedFailuresRetainPlan(t *testing.T) {
	t.Run("preparation", func(t *testing.T) {
		opts := baselineOptions{Dir: filepath.Join(t.TempDir(), "missing"), Out: baselineTestEvidenceDir(t), C0Database: "baseline_missing", Seed: 1109, RequestTimeout: time.Second}
		e, err := runBaseline(t.Context(), opts)
		if err == nil {
			t.Fatal("preparation failure returned success")
		}
		if e.Account()["dropped"] != 24 || len(e.Orders) != 12 || len(e.Summary["case_results"].([]any)) != 12 || e.Summary["passed"] != false {
			t.Fatal("preparation failure lost plan")
		}
		assertBaselineFiles(t, e.Directory)
	})
	t.Run("timeout", func(t *testing.T) {
		r := newBaselineTestRun(t)
		row := r.evidence.Requests[0]
		r.action(t.Context(), row, nil, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
		if row["disposition"] != "timeout" || row["http_status"] != nil || row["decision_id"] != nil {
			t.Fatalf("timeout invented a response: %v", row)
		}
		r.evidence.Requests[1]["failure_stage"] = "quote-dependency"
		r.compare()
		if err := r.evidence.Save(); err != nil {
			t.Fatal(err)
		}
		assertBaselineFiles(t, r.evidence.Directory)
	})
	t.Run("primary-query", func(t *testing.T) {
		r := newBaselineTestRun(t)
		pool, err := pgxpool.New(t.Context(), "postgres://invalid.invalid/unused")
		if err != nil {
			t.Fatal(err)
		}
		pool.Close()
		row, check := r.evidence.Requests[1], r.evidence.Orders[0]
		r.checkOrder(t.Context(), pool, r.inputs.Cases[0], row, check, 0, "quote")
		if check["verdict"] != "FAIL" || check["order_rows_after"] != nil || check["order_key_rows"] != nil || len(r.evidence.Summary["failures"].([]any)) != 1 {
			t.Fatal("failed query inferred absence")
		}
		r.compare()
		if err = r.evidence.Save(); err != nil {
			t.Fatal(err)
		}
		assertBaselineFiles(t, r.evidence.Directory)
	})
}

func assertBaselineFiles(t *testing.T, dir string) {
	t.Helper()
	for _, file := range []string{"manifest.json", "requests.csv", "order_checks.csv", "summary.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(file, ".json") && !json.Valid(raw) {
			t.Fatal("invalid JSON evidence")
		}
		if strings.Contains(string(raw), "PRIVATE KEY") {
			t.Fatal("secret in evidence")
		}
	}
	for file, count := range map[string]int{"requests.csv": 25, "order_checks.csv": 13} {
		f, err := os.Open(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(f).ReadAll()
		f.Close()
		if err != nil || len(rows) != count {
			t.Fatalf("incomplete %s: %d %v", file, len(rows), err)
		}
	}
}

func TestBaselinePairedChecksRejectMissingOrInconsistentResults(t *testing.T) {
	r := newBaselineTestRun(t)
	for n, c := range r.inputs.Cases {
		for j := 0; j < 2; j++ {
			row := r.evidence.Requests[2*n+j]
			row["challenge_id"] = api.Digest([]byte(c.Configuration + c.CaseID + row["action"].(string)))
			row["failure_stage"] = nil
			row["http_status"] = 200
			row["code"] = "ALLOW"
			row["signature_cache_hits"] = int64(0)
			if c.Configuration == "C0" {
				row["state_source"] = "centralized"
				row["revision"] = int64(1)
				row["state_read_at"] = time.Now()
			} else {
				row["state_source"] = "fabric"
				row["block_number"] = int64(1)
				row["probe_tx_id"] = "probe"
			}
			if c.Configuration == "B1" {
				row["signature_cache_hits"] = int64(8)
			}
		}
		row, check := r.evidence.Requests[2*n+1], r.evidence.Orders[n]
		row["http_status"] = c.ExpectedStatus
		row["code"] = c.ExpectedCode
		check["verdict"] = "PASS"
		check["order_rows_before"] = int64(0)
		check["order_rows_after"] = int64(1)
		check["order_key_rows"] = int64(1)
		if c.AmountMinor == 120000 {
			check["order_rows_after"] = int64(0)
			check["order_key_rows"] = int64(0)
		}
	}
	if !r.compare() {
		t.Fatal("expected denial did not pass paired checks")
	}
	r.evidence.Orders[1]["order_key_rows"] = int64(1)
	if r.compare() {
		t.Fatal("cross-group comparison ignored denial side effect")
	}
	r.evidence.Orders[1]["order_key_rows"] = int64(0)
	r.evidence.Requests[1]["challenge_id"] = r.evidence.Requests[0]["challenge_id"]
	if r.compare() {
		t.Fatal("duplicate challenge passed")
	}
}

func TestBaselineErrorExportDoesNotIncludeSecrets(t *testing.T) {
	r := newBaselineTestRun(t)
	secret := "sensitive-token-must-stay-private"
	r.failure("test", "preparation", errors.New(secret))
	if err := r.evidence.Save(); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(r.evidence.Directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		raw, err := os.ReadFile(filepath.Join(r.evidence.Directory, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), secret) {
			t.Fatal("raw error exposed sensitive data")
		}
	}
	if err := scanBaselineEvidence(r.evidence.Directory, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.evidence.Directory, "requests.csv"), []byte("PRIVATE KEY"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := scanBaselineEvidence(r.evidence.Directory, nil); err == nil {
		t.Fatal("secret scan did not reject private key encoding")
	}
}
