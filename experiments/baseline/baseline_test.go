package baseline

import (
	"context"
	"encoding/base64"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/experiments/harness"
	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/ledger"
	"grad/protocol"
	"grad/protocol/registry"
)

func newBaselineTestRun(t *testing.T) *baselineRun {
	t.Helper()
	in, err := Baseline(DefaultSeed)
	require.NoError(t, err)
	e, err := NewEvidence(baselineTestEvidenceDir(t), "test", in)
	require.NoError(t, err)
	return &baselineRun{
		inputs:   in,
		evidence: e,
		d:        &ledger.Deployment{DeploymentID: "test"},
		options:  Options{RequestTimeout: time.Nanosecond, Timeout: time.Minute},
	}
}

func baselineTestEvidenceDir(t *testing.T) string {
	t.Helper()
	if root := os.Getenv("BASELINE_FAULT_EVIDENCE_DIR"); root != "" {
		return filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"))
	}
	return filepath.Join(t.TempDir(), "evidence")
}

func TestBaselineReproduciblePlan(t *testing.T) {
	var previous string
	for _, seed := range []int{1109, 1110, 1111, 1112, 1113} {
		a, err := Baseline(seed)
		require.NoError(t, err)
		b, err := Baseline(seed)
		require.NoError(t, err)
		da, err := a.Digest()
		require.NoError(t, err)
		db, err := b.Digest()
		require.NoError(t, err)
		assert.Equal(t, da, db, "same seed changed logical inputs")
		assert.Equal(t, a.Cases, b.Cases)
		assert.NotEqual(t, previous, da, "different seed did not change fixture digest")
		previous = da

		require.Len(t, a.Cases, 12)
		for n, c := range a.Cases {
			assert.Equal(t, []string{"C0", "B0", "B1"}[n/4], c.Configuration)
			assert.Equal(t, []string{registry.RP, registry.BM}[(n%4)/2], c.Mode)
			assert.Equal(t, []int64{80000, 120000}[n%2], c.AmountMinor)
			assert.Equal(t, []int{200, 403}[n%2], c.ExpectedStatus)
			assert.Equal(t, a.Cases[n%4].CaseID, c.CaseID, "configurations are not paired")
		}
		assert.Equal(t, domgw.ChallengeTTLSeconds, a.Fixture.TimeRules.ChallengeTTL)
		assert.Equal(t, int64(registry.ProbeLifetime.Seconds()), a.Fixture.TimeRules.ProbeLifetime)
		assert.Equal(t, int64(registry.ProbeInterval.Seconds()), a.Fixture.TimeRules.ProbeInterval)
	}
	_, err := Baseline(42)
	require.Error(t, err, "accepted unplanned seed")
}

func TestBaselineHasNoRandomState(t *testing.T) {
	first, err := Baseline(DefaultSeed)
	require.NoError(t, err)
	digest, err := first.Digest()
	require.NoError(t, err)
	first.Fixture.Domains["A"] = "mutated"

	again, err := Baseline(DefaultSeed)
	require.NoError(t, err)
	after, err := again.Digest()
	require.NoError(t, err)
	assert.Equal(t, digest, after, "shared mutable fixture")

	// Planning neither consumes nor supplies entropy to the protocol nonce generator.
	n1, err := protocol.GenerateNonce()
	require.NoError(t, err)
	_, err = Baseline(DefaultSeed)
	require.NoError(t, err)
	n2, err := protocol.GenerateNonce()
	require.NoError(t, err)
	assert.NotEqual(t, n1, n2, "challenge randomness reused")
}

func TestBaselineConfigurations(t *testing.T) {
	for _, want := range []Configuration{
		{Name: "C0", StateSource: ledger.SourceCentralized},
		{Name: "B0", StateSource: ledger.SourceFabric},
		{Name: "B1", StateSource: ledger.SourceFabric, SignatureCache: true},
	} {
		got, err := BaselineConfiguration(want.Name)
		require.NoError(t, err)
		assert.Equal(t, want, got)
		assert.Equal(t, want.SignatureCache, got.NewSignatureCache() != nil)
	}
	_, err := BaselineConfiguration("UNKNOWN")
	require.Error(t, err)
}

func TestOptionsValidation(t *testing.T) {
	base := Options{
		Dir:            "/tmp/isolated",
		C0Database:     "baseline_valid_1",
		OutDir:         filepath.Join(t.TempDir(), "out"),
		Seed:           DefaultSeed,
		RequestTimeout: time.Second,
		Timeout:        time.Minute,
	}
	require.NoError(t, base.Validate())

	for _, tc := range []struct {
		name   string
		mutate func(*Options)
	}{
		{name: "missing-dir", mutate: func(o *Options) { o.Dir = "" }},
		{name: "missing-out", mutate: func(o *Options) { o.OutDir = "" }},
		{name: "missing-c0-db", mutate: func(o *Options) { o.C0Database = "" }},
		{name: "bad-c0-db-prefix", mutate: func(o *Options) { o.C0Database = "other_db" }},
		{name: "bad-c0-db-chars", mutate: func(o *Options) { o.C0Database = "baseline_BAD-NAME" }},
		{name: "zero-request-timeout", mutate: func(o *Options) { o.RequestTimeout = 0 }},
		{name: "zero-timeout", mutate: func(o *Options) { o.Timeout = 0 }},
		{name: "unplanned-seed", mutate: func(o *Options) { o.Seed = 9999 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			o.OutDir = filepath.Join(t.TempDir(), tc.name)
			tc.mutate(&o)
			res, err := Run(t.Context(), o)
			require.Error(t, err)
			assert.Nil(t, res)
		})
	}
}

func TestBaselineProcurementUsesCanonicalResources(t *testing.T) {
	in, err := Baseline(DefaultSeed)
	require.NoError(t, err)
	depID := registry.Digest([]byte("dep-test"))
	setup := baselineProcurement(depID, in)
	require.NoError(t, setup.Validate())
	assert.Equal(t, []string{protocol.ResourceOrders, protocol.ResourceQuotes}, setup.Spec.Resources)
	assert.Equal(t, []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead}, setup.Spec.Actions)
}

func TestEvidenceCSVPlanNullsAndWhitelist(t *testing.T) {
	in, err := Baseline(DefaultSeed)
	require.NoError(t, err)
	dir := filepath.Join(t.TempDir(), "attempt")
	e, err := NewEvidence(dir, "run-test", in)
	require.NoError(t, err)
	require.Len(t, e.Requests, 24)
	require.Len(t, e.Orders, 12)

	stamp := time.Date(2026, 11, 16, 4, 5, 6, 7, time.UTC)
	r := &e.Requests[0]
	r.StartedAt = someTime(stamp)
	r.ExecuteNs = someInt64(123456789)
	r.AmountMinor = 80000
	r.RequestID = someString("with,comma\nline")
	r.httpOrderStatus = someString("CREATED")
	r.httpOrderAmountMinor = someInt64(80000)

	require.NoError(t, e.Save())

	for file, columns := range map[string]string{
		"requests.csv":     RequestColumns,
		"order_checks.csv": OrderColumns,
	} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		require.NoError(t, err)
		rows, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
		require.NoError(t, err)
		assert.Equal(t, strings.Split(columns, ","), rows[0], "column order changed: %s", file)
		if file == "requests.csv" {
			m := map[string]string{}
			for n, k := range rows[0] {
				m[k] = rows[1][n]
			}
			assert.Equal(t, "null", m["revision"])
			assert.Equal(t, "123456789", m["execute_ns"])
			assert.Equal(t, stamp.Format(time.RFC3339Nano), m["started_at"])
			assert.Equal(t, "with,comma\nline", m["request_id"])
		}
	}
	for _, file := range []string{"manifest.json", "summary.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		require.NoError(t, err)
		assert.True(t, json.Valid(raw), "invalid JSON in %s", file)
	}
	_, err = NewEvidence(dir, "overwrite", in)
	require.Error(t, err, "attempt directory was reused")
}

func TestRequestAccountingIncludesDenialsAndMissingActions(t *testing.T) {
	in, err := Baseline(DefaultSeed)
	require.NoError(t, err)
	e, err := NewEvidence(filepath.Join(t.TempDir(), "attempt"), "run", in)
	require.NoError(t, err)
	for n, disposition := range []string{"allowed", "denied", "error", "timeout"} {
		e.Requests[n].Disposition = disposition
	}
	a := e.Account()
	assert.Equal(t, RequestAccountingSummary{
		Planned:   24,
		Started:   4,
		Dropped:   20,
		Completed: 3,
		Timeout:   1,
		Allowed:   1,
		Denied:    1,
		Error:     1,
	}, a)
	assert.Equal(t, a.Planned, a.Started+a.Dropped)
	assert.Equal(t, a.Started, a.Completed+a.Timeout)
	assert.Equal(t, a.Completed, a.Allowed+a.Denied+a.Error)
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
			require.NoError(t, os.MkdirAll(target, 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(target, "network.env"), []byte("COMPOSE_PROJECT_NAME=baseline-test\n"), 0o600))
			if tc.link != "" {
				require.NoError(t, os.Symlink(filepath.Join(root, target), tc.link))
			}
			r := baselineRun{repoRoot: root, options: Options{Dir: tc.dir}, runID: "test"}
			err := r.claimInstance()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "default Fabric instance")
			_, statErr := os.Lstat(filepath.Join(target, "baseline-run"))
			assert.ErrorIs(t, statErr, os.ErrNotExist)
		})
	}
}

func TestBaselineClaimsIsolatedInstanceThroughAlias(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	require.NoError(t, os.Mkdir("isolated", 0o700))
	require.NoError(t, os.WriteFile("isolated/network.env", []byte("COMPOSE_PROJECT_NAME=baseline-test\n"), 0o600))
	require.NoError(t, os.Symlink("isolated", "alias"))

	first := baselineRun{repoRoot: root, options: Options{Dir: "alias"}, runID: "first"}
	require.NoError(t, first.claimInstance())

	second := baselineRun{repoRoot: root, options: Options{Dir: "isolated"}, runID: "second"}
	err := second.claimInstance()
	require.ErrorIs(t, err, os.ErrExist)

	marker, err := os.ReadFile("isolated/baseline-run")
	require.NoError(t, err)
	assert.Equal(t, "first\n", string(marker))
}

func TestBaselineManagedFailuresRetainPlan(t *testing.T) {
	t.Run("preparation", func(t *testing.T) {
		opts := Options{
			Dir:            filepath.Join(t.TempDir(), "missing"),
			OutDir:         baselineTestEvidenceDir(t),
			C0Database:     "baseline_missing",
			Seed:           DefaultSeed,
			RequestTimeout: time.Second,
			Timeout:        time.Minute,
		}
		res, err := Run(t.Context(), opts)
		require.Error(t, err)
		require.NotNil(t, res)
		assert.Equal(t, 24, res.Summary.RequestAccounting.Dropped)
		assert.Len(t, res.Summary.CaseResults, 12)
		assert.False(t, res.Summary.Passed)
		assertBaselineFiles(t, res.EvidenceDirectory)
		var manifest struct {
			Locks map[string]string `json:"artifact_locks"`
		}
		require.NoError(t, harness.ReadJSON(filepath.Join(res.EvidenceDirectory, "manifest.json"), &manifest))
		root, err := harness.RepoRoot()
		require.NoError(t, err)
		for _, path := range []string{"mise.toml", "infra/fabric/network.sh", "infra/fabric/channel.sh"} {
			digest, err := harness.SHA256File(filepath.Join(root, path))
			require.NoError(t, err)
			assert.Equal(t, digest, manifest.Locks[path], path)
		}
		assert.NotContains(t, manifest.Locks, "experiments/mise.toml")
	})
	t.Run("timeout", func(t *testing.T) {
		r := newBaselineTestRun(t)
		row := &r.evidence.Requests[0]
		r.action(t.Context(), row, nil, func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
		assert.Equal(t, "timeout", row.Disposition)
		assert.False(t, row.HTTPStatus.Valid)
		assert.False(t, row.DecisionID.Valid)
		r.evidence.Requests[1].FailureStage = someString("quote-dependency")
		r.compare()
		require.NoError(t, r.evidence.Save())
		assertBaselineFiles(t, r.evidence.Directory)
	})
	t.Run("primary-query", func(t *testing.T) {
		r := newBaselineTestRun(t)
		pool, err := pgxpool.New(t.Context(), "postgres://invalid.invalid/unused")
		require.NoError(t, err)
		pool.Close()
		row, check := &r.evidence.Requests[1], &r.evidence.Orders[0]
		r.checkOrder(t.Context(), pool, r.inputs.Cases[0], row, check, 0, "quote")
		assert.Equal(t, "FAIL", check.Verdict)
		assert.False(t, check.OrderRowsAfter.Valid)
		assert.False(t, check.OrderKeyRows.Valid)
		assert.Len(t, r.evidence.Summary.Failures, 1)
		r.compare()
		require.NoError(t, r.evidence.Save())
		assertBaselineFiles(t, r.evidence.Directory)
	})
}

func TestBaselineQuoteExecuteFailureRetainsResponse(t *testing.T) {
	r := newBaselineTestRun(t)
	r.options.RequestTimeout = time.Second
	quote, order, check := &r.evidence.Requests[0], &r.evidence.Requests[1], &r.evidence.Orders[0]
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
	}), func() *RequestRow { return quote })

	r.action(t.Context(), quote, nil, func(ctx context.Context) error {
		challenge := httptest.NewRecorder()
		handler.ServeHTTP(challenge, httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/auth/challenges", nil))
		require.Equal(t, http.StatusCreated, challenge.Code)
		execute := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/access/execute", strings.NewReader(`{"challengeId":"issued-challenge"}`))
		handler.ServeHTTP(httptest.NewRecorder(), execute)
		return nil // RequestQuote returns an HTTP result without a Go error for a 503 response.
	})

	id := r.checkQuote(t.Context(), nil, quote, order, check)
	assert.Empty(t, id)
	assert.Equal(t, "dropped", order.Disposition)
	assert.Equal(t, someString("quote-dependency"), order.FailureStage)

	account := r.evidence.Account()
	assert.Equal(t, 1, account.Error)
	assert.Equal(t, 1, account.Completed)
	assert.Equal(t, 23, account.Dropped)
	assert.False(t, r.compare())
	require.NoError(t, r.evidence.Save())
	assertBaselineFiles(t, r.evidence.Directory)

	f, err := os.Open(filepath.Join(r.evidence.Directory, "requests.csv"))
	require.NoError(t, err)
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	require.NoError(t, err)

	want := map[string]string{
		"failure_stage": "execute",
		"disposition":   "error",
		"http_status":   "503",
		"code":          "STATE_UNAVAILABLE",
		"request_id":    "failed-execute",
		"challenge_id":  "issued-challenge",
		"decision_id":   "null",
	}
	wantOrder := map[string]string{
		"failure_stage": "quote-dependency",
		"disposition":   "dropped",
		"http_status":   "null",
	}
	for i, column := range rows[0] {
		if value, ok := want[column]; ok {
			assert.Equal(t, value, rows[1][i], "quote CSV %s", column)
		}
		if value, ok := wantOrder[column]; ok {
			assert.Equal(t, value, rows[2][i], "order CSV %s", column)
		}
	}

	raw, err := os.ReadFile(filepath.Join(r.evidence.Directory, "summary.json"))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "private response detail")

	var summary Summary
	require.NoError(t, json.Unmarshal(raw, &summary))
	assert.False(t, summary.Passed)
	require.Len(t, summary.Failures, 1)
	failure := summary.Failures[0]
	assert.Equal(t, "execute", failure.FailureStage)
	require.NotNil(t, failure.HTTPStatus)
	assert.Equal(t, 503, *failure.HTTPStatus)
	require.NotNil(t, failure.Code)
	assert.Equal(t, "STATE_UNAVAILABLE", *failure.Code)
	assert.Equal(t, "STATE_UNAVAILABLE", failure.Reason)
	require.NotNil(t, failure.RequestID)
	assert.Equal(t, "failed-execute", *failure.RequestID)
	require.NotNil(t, failure.ChallengeID)
	assert.Equal(t, "issued-challenge", *failure.ChallengeID)
	assert.Nil(t, failure.DecisionID)
}

func TestBaselineExecuteDeadlineRetainsResponse(t *testing.T) {
	r := newBaselineTestRun(t)
	r.options.RequestTimeout = 10 * time.Millisecond
	row := &r.evidence.Requests[1]
	handler := r.observe(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		<-req.Context().Done()
		w.Header().Set("X-Request-Id", "timed-out-order")
		w.WriteHeader(http.StatusServiceUnavailable)
	}), func() *RequestRow { return row })

	r.action(t.Context(), row, nil, func(ctx context.Context) error {
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/access/execute", strings.NewReader(`{"challengeId":"challenge"}`))
		handler.ServeHTTP(httptest.NewRecorder(), req)
		return nil
	})

	assert.Equal(t, "timeout", row.Disposition)
	assert.Equal(t, someString("execute"), row.FailureStage)
	assert.Equal(t, someInt64(http.StatusServiceUnavailable), row.HTTPStatus)
	assert.Equal(t, someString("timed-out-order"), row.RequestID)
	assert.Equal(t, someString("challenge"), row.ChallengeID)
	assert.False(t, row.DecisionID.Valid)
	assert.True(t, row.ExecuteNs.Valid)

	account := r.evidence.Account()
	assert.Equal(t, 1, account.Started)
	assert.Equal(t, 0, account.Completed)
	assert.Equal(t, 1, account.Timeout)
	assert.Equal(t, 0, account.Error)

	require.Len(t, r.evidence.Summary.Failures, 1)
	failure := r.evidence.Summary.Failures[0]
	assert.Equal(t, "execute", failure.FailureStage)
	assert.Equal(t, "deadline exceeded", failure.Reason)
	require.NotNil(t, failure.RequestID)
	assert.Equal(t, "timed-out-order", *failure.RequestID)
}

func TestBaselineChallengeFailureRetainsResponse(t *testing.T) {
	for _, action := range []string{protocol.ActionQuoteRead, protocol.ActionOrderCreate} {
		t.Run(action, func(t *testing.T) {
			r := newBaselineTestRun(t)
			r.options.RequestTimeout = time.Second
			quote, order, check := &r.evidence.Requests[0], &r.evidence.Requests[1], &r.evidence.Orders[0]
			row := quote
			if action == protocol.ActionOrderCreate {
				row = order
			}
			handler := r.observe(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("X-Request-Id", "challenge-failure")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"code":"STATE_UNAVAILABLE","message":"private response detail"}`))
			}), func() *RequestRow { return row })

			r.action(t.Context(), row, nil, func(ctx context.Context) error {
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/auth/challenges", nil)
				handler.ServeHTTP(httptest.NewRecorder(), req)
				return nil
			})

			if action == protocol.ActionQuoteRead {
				id := r.checkQuote(t.Context(), nil, quote, order, check)
				assert.Empty(t, id)
				assert.Equal(t, "dropped", order.Disposition)
				assert.Equal(t, someString("quote-dependency"), order.FailureStage)
			} else {
				r.checkDecision(t.Context(), nil, order, "order-decision")
				r.checkOrder(t.Context(), nil, r.inputs.Cases[0], order, check, 0, "quote")
				assert.Equal(t, someString("order challenge failed"), check.FailureReason)
				assert.False(t, check.OrderRowsAfter.Valid)
				assert.False(t, check.OrderKeyRows.Valid)
			}
			assert.False(t, r.compare())
			require.NoError(t, r.evidence.Save())

			f, err := os.Open(filepath.Join(r.evidence.Directory, "requests.csv"))
			require.NoError(t, err)
			defer f.Close()
			records, err := csv.NewReader(f).ReadAll()
			require.NoError(t, err)
			data := records[1]
			if action == protocol.ActionOrderCreate {
				data = records[2]
			}
			for i, name := range records[0] {
				switch name {
				case "http_status":
					assert.Equal(t, "503", data[i])
				case "code":
					assert.Equal(t, "STATE_UNAVAILABLE", data[i])
				case "request_id":
					assert.Equal(t, "challenge-failure", data[i])
				case "challenge_id", "decision_id", "execute_ns":
					assert.Equal(t, "null", data[i])
				}
			}

			require.Len(t, r.evidence.Summary.Failures, 1)
			failure := r.evidence.Summary.Failures[0]
			assert.Equal(t, "challenge", failure.FailureStage)
			require.NotNil(t, failure.HTTPStatus)
			assert.Equal(t, 503, *failure.HTTPStatus)
			require.NotNil(t, failure.Code)
			assert.Equal(t, "STATE_UNAVAILABLE", *failure.Code)
			require.NotNil(t, failure.RequestID)
			assert.Equal(t, "challenge-failure", *failure.RequestID)
			assert.Equal(t, "error", row.Disposition)
			assert.True(t, row.ChallengeNs.Valid)
			assert.Equal(t, 1, r.evidence.Account().Error)

			raw, err := os.ReadFile(filepath.Join(r.evidence.Directory, "summary.json"))
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "private response detail")
		})
	}
}

func TestBaselinePairedChecksRejectMissingOrInconsistentResults(t *testing.T) {
	r := newBaselineTestRun(t)
	for n, c := range r.inputs.Cases {
		for j := 0; j < 2; j++ {
			row := &r.evidence.Requests[2*n+j]
			row.ChallengeID = someString(registry.Digest([]byte(c.Configuration + c.CaseID + row.Action)))
			row.FailureStage = nullString{}
			row.HTTPStatus = someInt64(200)
			row.Code = someString("ALLOW")
			row.SignatureCacheHits = someInt64(0)
			if c.Configuration == "C0" {
				row.StateSource = someString(ledger.SourceCentralized)
				row.Revision = someInt64(1)
				row.StateReadAt = someTime(time.Now())
			} else {
				row.StateSource = someString(ledger.SourceFabric)
				row.BlockNumber = someInt64(4)
				row.BlockHash = someString(registry.Digest([]byte("block")))
				row.ProbeTxID = someString("probe")
				row.ProbeBlock = someInt64(3)
				row.ProbeSentAt = someTime(time.Unix(100, 0))
				row.ProbeDeadline = someTime(time.Unix(105, 0))
				row.ProbeSentMonoNs = someInt64(1)
				row.ProbeDeadlineMonoNs = someInt64(5000000001)
				row.ProbeCheckedMonoNs = someInt64(5000000000)
			}
			if c.Configuration == "B1" {
				row.SignatureCacheHits = someInt64(8)
			}
		}
		row, check := &r.evidence.Requests[2*n+1], &r.evidence.Orders[n]
		row.HTTPStatus = someInt64(int64(c.ExpectedStatus))
		row.Code = someString(c.ExpectedCode)
		check.Verdict = "PASS"
		check.OrderRowsBefore = someInt64(0)
		check.OrderRowsAfter = someInt64(1)
		check.OrderKeyRows = someInt64(1)
		if c.AmountMinor == 120000 {
			check.OrderRowsAfter = someInt64(0)
			check.OrderKeyRows = someInt64(0)
		}
	}
	require.True(t, r.compare(), "expected denial did not pass paired checks")

	for _, tc := range []struct {
		name   string
		mutate func(*RequestRow)
	}{
		{name: "missing-checkpoint-height", mutate: func(row *RequestRow) { row.BlockNumber = nullInt64{} }},
		{name: "missing-block-hash", mutate: func(row *RequestRow) { row.BlockHash = nullString{} }},
		{name: "invalid-block-hash", mutate: func(row *RequestRow) { row.BlockHash = someString("invalid") }},
		{name: "missing-probe-id", mutate: func(row *RequestRow) { row.ProbeTxID = nullString{} }},
		{name: "missing-probe-block", mutate: func(row *RequestRow) { row.ProbeBlock = nullInt64{} }},
		{name: "probe-above-checkpoint", mutate: func(row *RequestRow) { row.ProbeBlock = someInt64(5) }},
		{name: "missing-sent-time", mutate: func(row *RequestRow) { row.ProbeSentAt = nullTime{} }},
		{name: "missing-wall-deadline", mutate: func(row *RequestRow) { row.ProbeDeadline = nullTime{} }},
		{name: "missing-monotonic-send", mutate: func(row *RequestRow) { row.ProbeSentMonoNs = nullInt64{} }},
		{name: "missing-monotonic-deadline", mutate: func(row *RequestRow) { row.ProbeDeadlineMonoNs = nullInt64{} }},
		{name: "missing-monotonic-check", mutate: func(row *RequestRow) { row.ProbeCheckedMonoNs = nullInt64{} }},
		{name: "checked-before-send", mutate: func(row *RequestRow) { row.ProbeCheckedMonoNs = someInt64(0) }},
		{name: "checked-at-deadline", mutate: func(row *RequestRow) { row.ProbeCheckedMonoNs = someInt64(5000000001) }},
		{name: "checked-after-deadline", mutate: func(row *RequestRow) { row.ProbeCheckedMonoNs = someInt64(5000000002) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Cover both B0 quote (index 8) and B1 order (index 17) paths.
			for _, i := range []int{8, 17} {
				orig := r.evidence.Requests[i]
				tc.mutate(&r.evidence.Requests[i])
				passed := r.compare()
				r.evidence.Requests[i] = orig
				assert.False(t, passed, "invalid %s passed for %s %s", tc.name, orig.Configuration, orig.Action)
			}
		})
	}

	r.evidence.Orders[1].OrderKeyRows = someInt64(1)
	assert.False(t, r.compare(), "cross-group comparison ignored denial side effect")
	r.evidence.Orders[1].OrderKeyRows = someInt64(0)

	r.evidence.Requests[1].ChallengeID = r.evidence.Requests[0].ChallengeID
	assert.False(t, r.compare(), "duplicate challenge passed")
}

func TestBaselineErrorExportDoesNotIncludeSecrets(t *testing.T) {
	r := newBaselineTestRun(t)
	secret := "sensitive-token-must-stay-private"
	r.failure("test", "preparation", errors.New(secret))
	require.NoError(t, r.evidence.Save())

	files, err := os.ReadDir(r.evidence.Directory)
	require.NoError(t, err)
	for _, file := range files {
		raw, err := os.ReadFile(filepath.Join(r.evidence.Directory, file.Name()))
		require.NoError(t, err)
		assert.NotContains(t, string(raw), secret, "raw error exposed sensitive data")
	}

	findings, err := harness.ScanExports(r.evidence.Directory)
	require.NoError(t, err)
	assert.Empty(t, findings)

	// Verify PEM private key leak is caught.
	require.NoError(t, os.WriteFile(filepath.Join(r.evidence.Directory, "requests.csv"), []byte("-----BEGIN EC PRIVATE KEY-----\n"), 0o600))
	findings, err = harness.ScanExports(r.evidence.Directory)
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "secret scan did not reject private key encoding")

	// Verify runtime disclosure salt from instance directory is caught.
	instDir := t.TempDir()
	credsDir := filepath.Join(instDir, "registry", "credentials")
	require.NoError(t, os.MkdirAll(credsDir, 0o700))
	salt := "salt-secret-value-12345678"
	disclosure := base64.RawURLEncoding.EncodeToString([]byte(`["` + salt + `","role","broker-agent"]`))
	require.NoError(t, os.WriteFile(filepath.Join(credsDir, "B1.sdjwt"), []byte("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJCMCJ9.c2ln~"+disclosure+"~"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(r.evidence.Directory, "requests.csv"), []byte("clean,"+salt+"\n"), 0o600))

	findings, err = harness.ScanExports(r.evidence.Directory, harness.CollectInstanceSecrets(instDir)...)
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "secret scan did not reject runtime disclosure salt")
}

func assertBaselineFiles(t *testing.T, dir string) {
	t.Helper()
	for _, file := range []string{"manifest.json", "requests.csv", "order_checks.csv", "summary.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		require.NoError(t, err)
		if strings.HasSuffix(file, ".json") {
			assert.True(t, json.Valid(raw), "invalid JSON in %s", file)
		}
		assert.NotContains(t, string(raw), "PRIVATE KEY")
	}
	for file, count := range map[string]int{"requests.csv": 25, "order_checks.csv": 13} {
		f, err := os.Open(filepath.Join(dir, file))
		require.NoError(t, err)
		rows, err := csv.NewReader(f).ReadAll()
		_ = f.Close()
		require.NoError(t, err)
		assert.Len(t, rows, count, "incomplete %s", file)
	}
}
