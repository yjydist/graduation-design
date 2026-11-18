package fabric

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"graduation-design/internal/experiment"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
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

func TestBaselineRejectsDefaultInstanceAliases(t *testing.T) {
	const defaultDir = ".local/fabric-d0"
	for _, tc := range []struct {
		name, dir string
		link      string
		linkTo    string
	}{
		{name: "direct", dir: defaultDir},
		{name: "requested path is a symlink", dir: "alias", link: "alias", linkTo: defaultDir},
		{name: "default path is a symlink", dir: ".local/instance", link: defaultDir, linkTo: ".local/instance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			t.Chdir(root)
			target := defaultDir
			if tc.linkTo != "" {
				target = tc.linkTo
			}
			if err := os.MkdirAll(target, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, "network.env"), []byte("COMPOSE_PROJECT_NAME=baseline-test\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.link != "" {
				if err := os.Symlink(filepath.Join(root, target), tc.link); err != nil {
					t.Fatal(err)
				}
			}
			r := baselineRun{options: baselineOptions{Dir: tc.dir}, runID: "test"}
			err := r.claimInstance()
			if _, statErr := os.Lstat(filepath.Join(target, "baseline-run")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("default instance marker should be absent, stat error: %v", statErr)
			}
			if err == nil || !strings.Contains(err.Error(), "requires an explicitly isolated Fabric instance") {
				t.Fatalf("expected default instance rejection, got %v", err)
			}
		})
	}
}

func TestBaselineClaimsIsolatedInstanceThroughAlias(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if err := os.Mkdir("isolated", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("isolated/network.env", []byte("COMPOSE_PROJECT_NAME=baseline-test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("isolated", "alias"); err != nil {
		t.Fatal(err)
	}
	r := baselineRun{options: baselineOptions{Dir: "alias"}, runID: "first"}
	if err := r.claimInstance(); err != nil {
		t.Fatal(err)
	}
	second := baselineRun{options: baselineOptions{Dir: "isolated"}, runID: "second"}
	if err := second.claimInstance(); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected duplicate claim rejection, got %v", err)
	}
	marker, err := os.ReadFile("isolated/baseline-run")
	if err != nil {
		t.Fatal(err)
	}
	if string(marker) != "first\n" {
		t.Fatalf("unexpected claim marker: %q", marker)
	}
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

func TestBaselineQuoteExecuteFailureRetainsResponse(t *testing.T) {
	r := newBaselineTestRun(t)
	r.options.RequestTimeout = time.Second
	quote, order, check := r.evidence.Requests[0], r.evidence.Requests[1], r.evidence.Orders[0]
	handler := r.observe(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v1/auth/challenges":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"challengeId":"issued-challenge"}`))
		case "/v1/access/execute":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"requestId":"failed-execute","code":"STATE_UNAVAILABLE","message":"private response detail"}`))
		default:
			t.Fatalf("unexpected endpoint: %s", req.URL.Path)
		}
	}), func() experiment.Row { return quote })

	r.action(t.Context(), quote, nil, func(ctx context.Context) error {
		challenge := httptest.NewRecorder()
		handler.ServeHTTP(challenge, httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/auth/challenges", nil))
		if challenge.Code != http.StatusCreated {
			t.Fatalf("challenge status = %d", challenge.Code)
		}
		execute := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/access/execute", strings.NewReader(`{"challengeId":"issued-challenge"}`))
		handler.ServeHTTP(httptest.NewRecorder(), execute)
		return nil // RequestQuote returns an HTTP result without a Go error for a 503 response.
	})
	if id := r.checkQuote(t.Context(), nil, quote, order, check); id != "" ||
		order["disposition"] != "dropped" || order["failure_stage"] != "quote-dependency" {
		t.Fatalf("failed quote did not stop the dependent order: %v", order)
	}
	if account := r.evidence.Account(); account["error"] != 1 || account["completed"] != 1 || account["dropped"] != 23 || r.compare() {
		t.Fatalf("incorrect failure accounting: %v", account)
	}
	if err := r.evidence.Save(); err != nil {
		t.Fatal(err)
	}
	assertBaselineFiles(t, r.evidence.Directory)
	f, err := os.Open(filepath.Join(r.evidence.Directory, "requests.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"failure_stage": "execute", "disposition": "error", "http_status": "503", "code": "STATE_UNAVAILABLE",
		"request_id": "failed-execute", "challenge_id": "issued-challenge", "decision_id": "null"}
	wantOrder := map[string]string{"failure_stage": "quote-dependency", "disposition": "dropped", "http_status": "null"}
	for i, column := range rows[0] {
		if value, ok := want[column]; ok && rows[1][i] != value {
			t.Errorf("quote CSV %s = %q, want %q", column, rows[1][i], value)
		}
		if value, ok := wantOrder[column]; ok && rows[2][i] != value {
			t.Errorf("order CSV %s = %q, want %q", column, rows[2][i], value)
		}
	}
	raw, err := os.ReadFile(filepath.Join(r.evidence.Directory, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Passed   bool             `json:"passed"`
		Failures []map[string]any `json:"failures"`
	}
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Passed || len(summary.Failures) != 1 || strings.Contains(string(raw), "private response detail") {
		t.Fatalf("incorrect failure summary: %+v", summary)
	}
	failure := summary.Failures[0]
	if failure["failure_stage"] != "execute" || failure["http_status"] != float64(503) || failure["code"] != "STATE_UNAVAILABLE" || failure["reason"] != "STATE_UNAVAILABLE" ||
		failure["request_id"] != "failed-execute" || failure["challenge_id"] != "issued-challenge" || failure["decision_id"] != nil {
		t.Fatalf("incorrect execution failure: %v", failure)
	}
}

func TestBaselineExecuteDeadlineRetainsResponse(t *testing.T) {
	r := newBaselineTestRun(t)
	r.options.RequestTimeout = 10 * time.Millisecond
	row := r.evidence.Requests[1]
	handler := r.observe(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		<-req.Context().Done()
		w.Header().Set("X-Request-Id", "timed-out-order")
		w.WriteHeader(http.StatusServiceUnavailable)
	}), func() experiment.Row { return row })

	r.action(t.Context(), row, nil, func(ctx context.Context) error {
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/access/execute", strings.NewReader(`{"challengeId":"challenge"}`))
		handler.ServeHTTP(httptest.NewRecorder(), req)
		// The wallet can return a 503 result with no Go error.
		return nil
	})

	if row["disposition"] != "timeout" || row["failure_stage"] != "execute" ||
		row["http_status"] != http.StatusServiceUnavailable || row["request_id"] != "timed-out-order" ||
		row["challenge_id"] != "challenge" || row["decision_id"] != nil || row["execute_ns"] == nil {
		t.Fatalf("execution timeout lost observations or stage: %v", row)
	}
	account := r.evidence.Account()
	if account["started"] != 1 || account["completed"] != 0 || account["timeout"] != 1 || account["error"] != 0 {
		t.Fatalf("incorrect execution timeout accounting: %v", account)
	}
	failures := r.evidence.Summary["failures"].([]any)
	if len(failures) != 1 {
		t.Fatalf("expected one timeout failure, got %v", failures)
	}
	failure := failures[0].(map[string]any)
	if failure["failure_stage"] != "execute" || failure["reason"] != "deadline exceeded" || failure["request_id"] != row["request_id"] {
		t.Fatalf("incorrect execution timeout summary: %v", failure)
	}
}

func TestBaselineChallengeFailureRetainsResponse(t *testing.T) {
	for _, action := range []string{"quote.read", "order.create"} {
		t.Run(action, func(t *testing.T) {
			r := newBaselineTestRun(t)
			r.options.RequestTimeout = time.Second
			quote, order, check := r.evidence.Requests[0], r.evidence.Requests[1], r.evidence.Orders[0]
			row := quote
			if action == "order.create" {
				row = order
			}
			handler := r.observe(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("X-Request-Id", "challenge-failure")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"code":"STATE_UNAVAILABLE","message":"private response detail"}`))
			}), func() experiment.Row { return row })
			r.action(t.Context(), row, nil, func(ctx context.Context) error {
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/auth/challenges", nil)
				handler.ServeHTTP(httptest.NewRecorder(), req)
				// A non-201 challenge response can reach the wallet as an HTTP result without a Go error.
				return nil
			})
			if action == "quote.read" {
				if id := r.checkQuote(t.Context(), nil, quote, order, check); id != "" ||
					order["disposition"] != "dropped" || order["failure_stage"] != "quote-dependency" {
					t.Fatalf("failed quote challenge dispatched an order: %v", order)
				}
			} else {
				r.checkDecision(t.Context(), nil, order, "order-decision")
				r.checkOrder(t.Context(), nil, r.inputs.Cases[0], order, check, 0, "quote")
				if check["failure_reason"] != "order challenge failed" || check["order_rows_after"] != nil || check["order_key_rows"] != nil {
					t.Fatalf("order challenge failure invented primary database facts: %v", check)
				}
			}
			if r.compare() {
				t.Fatal("failed challenge passed paired checks")
			}
			if err := r.evidence.Save(); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(filepath.Join(r.evidence.Directory, "requests.csv"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			records, err := csv.NewReader(f).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			data := records[1]
			if action == "order.create" {
				data = records[2]
			}
			for i, name := range records[0] {
				switch name {
				case "http_status":
					if data[i] != "503" {
						t.Fatalf("lost HTTP status in CSV: %s", data[i])
					}
				case "code":
					if data[i] != "STATE_UNAVAILABLE" {
						t.Fatalf("lost error code in CSV: %s", data[i])
					}
				case "request_id":
					if data[i] != "challenge-failure" {
						t.Fatalf("lost request ID in CSV: %s", data[i])
					}
				case "challenge_id", "decision_id", "execute_ns":
					if data[i] != "null" {
						t.Fatalf("invented %s in CSV: %s", name, data[i])
					}
				}
			}
			failures := r.evidence.Summary["failures"].([]any)
			if len(failures) != 1 {
				t.Fatalf("expected one challenge failure, got %v", failures)
			}
			failure := failures[0].(map[string]any)
			if failure["failure_stage"] != "challenge" || failure["http_status"] != 503 ||
				failure["code"] != "STATE_UNAVAILABLE" || failure["request_id"] != "challenge-failure" ||
				row["disposition"] != "error" || row["challenge_ns"] == nil || r.evidence.Account()["error"] != 1 {
				t.Fatalf("incorrect challenge evidence: %v, %v", row, failure)
			}
			raw, err := os.ReadFile(filepath.Join(r.evidence.Directory, "summary.json"))
			if err != nil || strings.Contains(string(raw), "private response detail") {
				t.Fatalf("invalid summary or raw error message leaked: %v", err)
			}
		})
	}
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

func TestBaselineChecksHTTPOrderAndPrimaryIndependently(t *testing.T) {
	cfg := testPgPool(t).Config().Copy()
	cfg.MaxConns = 1 // Keep the test tables local to one database session.
	db, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(t.Context(), `
		CREATE TEMP TABLE decisions (deployment_id text, decision_id text, request_id text,
			challenge_id text, task_id text, actor text, idempotency_key text, outcome text, code text,
			quote_id text, order_id text);
		CREATE TEMP TABLE challenges (deployment_id text, challenge_id text,
			consumed_at bigint, decision_id text, request_hash text);
		CREATE TEMP TABLE orders (deployment_id text, task_id text, actor text, idempotency_key text,
			order_id text, status text, decision_id text, quote_id text, total_amount_minor bigint);
		CREATE TEMP TABLE business_keys (deployment_id text, actor text, task_id text, action text,
			idempotency_key text, status text, resource_id text, decision_id text);
		CREATE TEMP TABLE quotes (deployment_id text, quote_id text, total_amount_minor bigint, actor text, task_id text);
		INSERT INTO decisions VALUES ('test','decision','request','challenge','task','actor','key','ALLOW','ALLOW','quote','order');
		INSERT INTO challenges VALUES ('test','challenge',1,'decision','hash');
		INSERT INTO orders VALUES ('test','task','actor','key','order','CREATED','decision','quote',80000);
		INSERT INTO business_keys VALUES ('test','actor','task','order.create','key','COMPLETED','order','decision');
		INSERT INTO quotes VALUES ('test','quote',80000,'actor','task');`); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name          string
		order         *gateway.OrderDTO
		decisionError bool
		badPrimary    bool
		verdict       string
	}{
		{name: "matching", order: &gateway.OrderDTO{OrderID: "order", QuoteID: "quote", Status: "CREATED", TotalAmountMinor: 80000}, verdict: "PASS"},
		{name: "missing-order", decisionError: true, verdict: "FAIL"},
		{name: "wrong-order-id", order: &gateway.OrderDTO{OrderID: "wrong", QuoteID: "quote", Status: "CREATED", TotalAmountMinor: 80000}, decisionError: true, verdict: "FAIL"},
		{name: "wrong-quote-id", order: &gateway.OrderDTO{OrderID: "order", QuoteID: "wrong", Status: "CREATED", TotalAmountMinor: 80000}, decisionError: true, verdict: "FAIL"},
		{name: "wrong-status", order: &gateway.OrderDTO{OrderID: "order", QuoteID: "quote", Status: "WRONG", TotalAmountMinor: 80000}, verdict: "FAIL"},
		{name: "wrong-amount", order: &gateway.OrderDTO{OrderID: "order", QuoteID: "quote", Status: "CREATED", TotalAmountMinor: 120000}, verdict: "FAIL"},
		{name: "wrong-primary-key-status", order: &gateway.OrderDTO{OrderID: "order", QuoteID: "quote", Status: "CREATED", TotalAmountMinor: 80000}, badPrimary: true, verdict: "FAIL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyStatus := "COMPLETED"
			if tc.badPrimary {
				keyStatus = "IN_PROGRESS"
			}
			if _, err := db.Exec(t.Context(), `UPDATE business_keys SET status=$1`, keyStatus); err != nil {
				t.Fatal(err)
			}
			r := newBaselineTestRun(t)
			row, check := r.evidence.Requests[1], r.evidence.Orders[0]
			row["task_id"], row["actor"], row["idempotency_key"], row["quote_id"] = "task", "actor", "key", "quote"
			r.options.RequestTimeout = time.Second
			handler := r.observe(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-Request-Id", "request")
				err := json.NewEncoder(w).Encode(gateway.ExecuteResponse{DecisionID: "decision", Code: "ALLOW", Order: tc.order})
				if err != nil {
					t.Fatal(err)
				}
			}), func() experiment.Row { return row })
			r.action(t.Context(), row, nil, func(ctx context.Context) error {
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/access/execute", strings.NewReader(`{"challengeId":"challenge"}`))
				handler.ServeHTTP(httptest.NewRecorder(), req)
				return nil
			})
			row["request_hash"] = "hash"
			httpID, httpQuoteID := row["order_id"], row["quote_id"]
			if err := r.decision(t.Context(), db, row); (err != nil) != tc.decisionError {
				t.Fatalf("unexpected decision check result: %v", err)
			}
			if row["order_id"] != httpID || row["quote_id"] != httpQuoteID {
				t.Fatalf("database lookup overwrote HTTP evidence: %v", row)
			}
			r.checkOrder(t.Context(), db, r.inputs.Cases[0], row, check, 0, "quote")
			if check["verdict"] != tc.verdict || check["order_id"] != "order" || check["order_status"] != "CREATED" {
				t.Fatalf("unexpected order check: %v", check)
			}
		})
	}
	t.Run("execute-failure-without-decision", func(t *testing.T) {
		if _, err := db.Exec(t.Context(), `INSERT INTO challenges VALUES ('test','failed-challenge',NULL,NULL,'failed-hash')`); err != nil {
			t.Fatal(err)
		}
		r := newBaselineTestRun(t)
		row, check := r.evidence.Requests[1], r.evidence.Orders[0]
		row["task_id"], row["actor"], row["idempotency_key"] = "task", "actor", "failed-key"
		row["failure_stage"], row["challenge_id"] = "execute", "failed-challenge"
		r.checkDecision(t.Context(), db, row, "order-decision")
		r.checkOrder(t.Context(), db, r.inputs.Cases[0], row, check, 1, "quote")
		if check["verdict"] != "FAIL" || check["failure_reason"] != "order execution returned no decision" ||
			check["order_rows_after"] != int64(1) || check["order_key_rows"] != int64(0) || check["challenge_consumed"] != false ||
			check["decision_id"] != nil || len(r.evidence.Summary["failures"].([]any)) != 0 {
			t.Fatalf("incorrect observations for a failed order execution: %v, %v", check, r.evidence.Summary["failures"])
		}
	})
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
				row["block_number"] = json.Number("4")
				row["block_hash"] = api.Digest([]byte("block"))
				row["probe_tx_id"] = "probe"
				row["probe_block"] = json.Number("3")
				row["probe_sent_at"] = time.Unix(100, 0)
				row["probe_deadline"] = time.Unix(105, 0)
				row["probe_sent_mono_ns"] = json.Number("1")
				row["probe_deadline_mono_ns"] = json.Number("5000000001")
				row["probe_checked_mono_ns"] = json.Number("5000000000")
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
	for _, tc := range []struct {
		name, field string
		value       any
	}{
		{name: "missing-checkpoint-height", field: "block_number"},
		{name: "missing-block-hash", field: "block_hash"},
		{name: "invalid-block-hash", field: "block_hash", value: "invalid"},
		{name: "missing-probe-id", field: "probe_tx_id"},
		{name: "missing-probe-block", field: "probe_block"},
		{name: "probe-above-checkpoint", field: "probe_block", value: json.Number("5")},
		{name: "missing-sent-time", field: "probe_sent_at"},
		{name: "missing-wall-deadline", field: "probe_deadline"},
		{name: "missing-monotonic-send", field: "probe_sent_mono_ns"},
		{name: "missing-monotonic-deadline", field: "probe_deadline_mono_ns"},
		{name: "missing-monotonic-check", field: "probe_checked_mono_ns"},
		{name: "checked-before-send", field: "probe_checked_mono_ns", value: json.Number("0")},
		{name: "checked-at-deadline", field: "probe_checked_mono_ns", value: json.Number("5000000001")},
		{name: "checked-after-deadline", field: "probe_checked_mono_ns", value: json.Number("5000000002")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Cover the B0 quote and the B1 order paths.
			for _, i := range []int{8, 17} {
				row := r.evidence.Requests[i]
				original := row[tc.field]
				row[tc.field] = tc.value
				passed := r.compare()
				row[tc.field] = original
				if passed {
					t.Fatalf("invalid %s passed for %s %s", tc.field, row["configuration"], row["action"])
				}
			}
		})
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
