package baseline

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/experiments/harness"
	"grad/platform/bootstrap"
	"grad/platform/core/dao/central"
	domgw "grad/platform/core/domain/gateway"
	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/platform/core/ledger"
	apigw "grad/platform/service/api/gateway"
	"grad/protocol"
	"grad/protocol/registry"
)

const (
	// DefaultSeed is the default paired fixture seed for the three-group baseline.
	DefaultSeed = 1109
	// DefaultRequestTimeout is the default timeout per deterministic wallet action.
	DefaultRequestTimeout = 15 * time.Second
	// DefaultTimeout is the default total preparation and execution timeout.
	DefaultTimeout = 10 * time.Minute
)

var c0DatabaseRe = regexp.MustCompile(`^baseline_[a-z0-9_]{1,48}$`)

// Options configures a three-group (C0/B0/B1) paired procurement baseline run.
type Options struct {
	Dir            string
	C0Database     string
	OutDir         string
	Seed           int
	RequestTimeout time.Duration
	Timeout        time.Duration
}

// RunResult returns the evidence directory and final summary for a baseline run.
type RunResult struct {
	EvidenceDirectory string  `json:"evidence_directory"`
	Summary           Summary `json:"summary"`
}

type baselineRun struct {
	options  Options
	repoRoot string
	inputs   *Inputs
	evidence *Evidence
	runID    string
	stage    string
	i        *ledger.Instance
	dir      string
	d        *ledger.Deployment
	f        *bootstrap.Fixtures
	db, c0db *pgxpool.Pool
	c0       *central.Source
	resolver *protocol.DIDWebResolver
	passed   bool
}

// Validate checks CLI-level baseline options before creating the output directory.
func (o Options) Validate() error {
	if strings.TrimSpace(o.Dir) == "" || strings.TrimSpace(o.C0Database) == "" || strings.TrimSpace(o.OutDir) == "" ||
		o.RequestTimeout <= 0 || o.Timeout <= 0 {
		return fmt.Errorf("explicit dir, c0-database, out and positive timeouts required")
	}
	if !c0DatabaseRe.MatchString(o.C0Database) {
		return fmt.Errorf("C0 database must be a new name matching baseline_[a-z0-9_]{1,48}")
	}
	return nil
}

// Run executes the C0/B0/B1 paired procurement baseline and exports manifest.json,
// requests.csv, order_checks.csv, and summary.json into opts.OutDir.
func Run(ctx context.Context, opts Options) (res *RunResult, err error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	in, err := Baseline(opts.Seed)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	runID := fmt.Sprintf("baseline-%x", id)
	e, err := NewEvidence(opts.OutDir, runID, in)
	if err != nil {
		return nil, err
	}
	r := &baselineRun{
		options:  opts,
		inputs:   in,
		evidence: e,
		runID:    runID,
		stage:    "preparation",
	}
	defer func() {
		if err != nil {
			r.failure("run", r.stage, err)
			for i := range e.Requests {
				row := &e.Requests[i]
				if row.Disposition == "dropped" && row.FailureStage.Valid && row.FailureStage.Value == "preparation" {
					row.FailureStage = someString(r.stage)
				}
			}
		}
		r.passed = r.compare()
		e.Summary.RequestAccounting = e.Account()
		e.Summary.Passed = err == nil && r.passed
		err = errors.Join(err, e.Save())

		findings, scanErr := harness.ScanExports(e.Directory, harness.CollectInstanceSecrets(r.dir)...)
		if scanErr == nil && len(findings) > 0 {
			scanErr = fmt.Errorf("sensitive data detected in baseline exports: %s", findings[0].String())
		}
		e.Summary.SecretScan = &SecretScanSummary{
			Passed:   scanErr == nil,
			Files:    4,
			Findings: len(findings),
		}
		if scanErr != nil {
			e.Summary.Passed = false
			r.failure("run", "secret-scan", scanErr)
		}
		err = errors.Join(err, scanErr, e.Save())
		res = &RunResult{EvidenceDirectory: e.Directory, Summary: e.Summary}
	}()

	if err = e.Save(); err != nil {
		return nil, err
	}
	if err = r.prepare(ctx); err != nil {
		return nil, err
	}
	defer r.db.Close()
	defer r.c0db.Close()

	didServer, resolver, err := r.i.StartRegistryDIDResolver(r.d)
	if err != nil {
		return nil, err
	}
	defer didServer.Close()
	r.resolver = resolver

	for _, name := range in.Fixture.Configurations {
		if err = r.configuration(ctx, name); err != nil {
			return nil, err
		}
	}
	r.stage = "comparison"
	r.passed = r.compare()
	if !r.passed {
		return nil, fmt.Errorf("baseline business or paired checks failed")
	}
	return nil, nil
}

func (r *baselineRun) prepare(ctx context.Context) error {
	e := r.evidence
	repoRoot, err := harness.RepoRoot()
	if err != nil {
		return err
	}
	r.repoRoot = repoRoot

	e.Manifest["go_version"] = goruntime.Version()
	e.Manifest["host"] = goruntime.GOOS + "/" + goruntime.GOARCH
	e.Manifest["clock"] = "UTC wall clock and per-process monotonic nanoseconds"
	e.Manifest["clock_resolution_ns"] = harness.MeasureClockResolutionNs(2000)

	commit, _, err := harness.GitHeadRevision(repoRoot)
	if err != nil {
		return err
	}
	e.Manifest["source_commit"] = commit

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	binaryDigest, err := harness.SHA256File(exe)
	if err != nil {
		return err
	}
	e.Manifest["binary_sha256"] = binaryDigest

	locks := map[string]string{}
	for _, rel := range []string{
		"go.work",
		"protocol/go.mod",
		"chaincode/go.mod",
		"platform/go.mod",
		"experiments/go.mod",
		"mise.toml",
		"infra/fabric/compose.yaml",
		"infra/fabric/channel.sh",
		"infra/fabric/network.sh",
		"protocol/contexts/vc-v2.json",
		"experiments/mise.toml",
		"experiments/baseline/baseline.json",
	} {
		digest, err := harness.SHA256File(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		locks[rel] = digest
	}
	// Pin the actual working source tree as well as HEAD.
	for _, tree := range []string{
		"protocol",
		"chaincode",
		"platform",
		"experiments/cmd",
		"experiments/harness",
		"experiments/baseline",
	} {
		absTree := filepath.Join(repoRoot, filepath.FromSlash(tree))
		if _, statErr := os.Stat(absTree); errors.Is(statErr, os.ErrNotExist) && tree == "experiments/cmd" {
			continue
		}
		if err := filepath.WalkDir(absTree, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".sql") {
				digest, err := harness.SHA256File(path)
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(repoRoot, path)
				if err != nil {
					return err
				}
				locks[filepath.ToSlash(rel)] = digest
			}
			return nil
		}); err != nil {
			return err
		}
	}
	e.Manifest["artifact_locks"] = locks

	if err := r.claimInstance(); err != nil {
		return err
	}
	i := r.i
	if _, err = os.Stat(filepath.Join(r.dir, "registry", "fixtures.json")); err == nil {
		return fmt.Errorf("baseline requires an instance with no existing seed fixtures")
	} else if !os.IsNotExist(err) {
		return err
	}

	d, err := i.Deploy(ctx, false)
	if err != nil {
		return err
	}
	r.d = d
	e.Manifest["deployment_id"] = d.DeploymentID
	e.Manifest["channel_id"] = d.ChannelID
	e.Manifest["genesis_hash"] = d.GenesisHash
	e.Manifest["chaincode"] = map[string]any{
		"name":          d.RegistryName,
		"version":       ledger.RegistryVersion,
		"sequence":      ledger.RegistrySequence,
		"source_digest": d.SourceDigest,
		"build_digest":  d.BuildDigest,
	}
	e.Manifest["root"] = d.Bootstrap.Root

	db, err := i.Database(ctx)
	if err != nil {
		return err
	}
	r.db = db
	// prepare closes pools on failure; successful execution closes them after the three groups.
	ready := false
	defer func() {
		if !ready {
			db.Close()
			if r.c0db != nil {
				r.c0db.Close()
			}
		}
	}()

	setup := baselineProcurement(d.DeploymentID, r.inputs)
	report, err := bootstrap.SeedProcurement(ctx, i, db, d, setup)
	if err != nil {
		return err
	}
	r.f = report.Fixtures()
	centralInput, err := prepareRegistration(r.dir, d, report, setup)
	if err != nil {
		return err
	}
	e.Manifest["material_digest"] = centralInput.MaterialDigest
	e.Manifest["registry_input_digest"] = centralInput.InputDigest

	// CREATE DATABASE is deliberate and never reuses or clears an existing database.
	if _, err = db.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{r.options.C0Database}.Sanitize()); err != nil {
		return err
	}
	cfg := db.Config().Copy()
	cfg.ConnConfig.Database = r.options.C0Database
	c0db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return err
	}
	r.c0db = c0db
	if err = c0db.Ping(ctx); err != nil {
		return err
	}
	e.Manifest["topology"] = map[string]any{
		"fabric_instance":      r.dir,
		"fabric_database":      db.Config().ConnConfig.Database,
		"centralized_database": r.options.C0Database,
		"peer_domains":         []string{"A", "B", "C"},
		"orderers":             4,
	}

	if r.c0, err = central.Initialize(ctx, c0db, centralInput.Snapshot); err != nil {
		return err
	}
	r.stage = "registry-readback"
	if err = i.ApplyCommittedRegistry(ctx, db, d); err != nil {
		return fmt.Errorf("apply Fabric registry: %w", err)
	}
	if err = r.checkRegistryReadback(ctx, centralInput.Snapshot); err != nil {
		return err
	}
	r.stage = "preparation"

	if err = domgw.EnsureSchema(ctx, c0db, d.DeploymentID, r.inputs.Fixture.Supplier); err != nil {
		return err
	}
	if err = domgw.EnsureSchema(ctx, db, d.DeploymentID, r.inputs.Fixture.Supplier); err != nil {
		return err
	}
	if err = bootstrap.SyncSeedDeliveries(ctx, i, c0db, d, report); err != nil {
		return err
	}
	e.Manifest["configurations"] = []any{}
	ready = true
	return e.Save()
}

func (r *baselineRun) claimInstance() error {
	repoRoot := r.repoRoot
	if repoRoot == "" {
		var err error
		repoRoot, err = harness.RepoRoot()
		if err != nil {
			wd, wdErr := os.Getwd()
			if wdErr != nil {
				return err
			}
			repoRoot = wd
		}
	}
	dir, err := harness.ValidateIsolatedInstance(repoRoot, r.options.Dir, false)
	if err != nil {
		return err
	}
	inst, err := ledger.OpenInstance(dir)
	if err != nil {
		return err
	}
	// Baseline claims an instance permanently (no release) so failed runs cannot reuse it.
	if _, err := harness.ClaimInstance(dir, "baseline-run", r.runID); err != nil {
		return fmt.Errorf("baseline instance is already claimed: %w", err)
	}
	r.i = inst
	r.dir = dir
	return nil
}

func (r *baselineRun) configuration(ctx context.Context, name string) error {
	r.stage = "configuration-" + name
	profile, err := BaselineConfiguration(name)
	if err != nil {
		return err
	}
	db := r.db
	var src ledger.StateSource
	if name == "C0" {
		db = r.c0db
		src = r.c0
	} else {
		role := "probe1"
		if name == "B1" {
			role = "probe2"
		}
		provider, stop, err := r.i.StartStateProvider(ctx, db, r.d, role, r.f.BMG2.ID)
		if err != nil {
			return err
		}
		defer stop()
		src = provider
	}

	bundle, err := r.inputs.Policy(r.d.DeploymentID, r.f.Identities["C"].ID, r.d.Bootstrap.Root, r.f.RPTask.EXP, r.f.BMTask.EXP)
	if err != nil {
		return err
	}
	if old := r.evidence.Manifest["policy_digest"]; old != nil && old != bundle.PolicyDigest {
		return fmt.Errorf("policy digest differs across groups")
	}
	r.evidence.Manifest["policy_digest"] = bundle.PolicyDigest

	cache := profile.NewSignatureCache()
	gwSvc, err := domgw.NewService(domgw.Config{
		DB:             db,
		State:          src,
		CertChecker:    domreg.NewDeliveryService(db, r.d.DeploymentID),
		DIDs:           r.resolver,
		Policy:         bundle,
		SignatureCache: cache,
		DeploymentID:   r.d.DeploymentID,
		ServiceDID:     r.f.Identities["C"].ID,
		Audience:       "https://c.local",
		SupplierID:     r.inputs.Fixture.Supplier,
		VerifierID:     r.runID + "-" + name,
	})
	if err != nil {
		return err
	}
	srv, err := apigw.NewServer(gwSvc)
	if err != nil {
		return err
	}

	meta := map[string]any{
		"configuration":          name,
		"state_source":           profile.StateSource,
		"database":               db.Config().ConnConfig.Database,
		"gateway_instance":       r.runID + "-" + name,
		"signature_cache":        profile.SignatureCache,
		"probe_interval_seconds": nil,
		"probe_lifetime_seconds": nil,
	}
	if name != "C0" {
		meta["probe_interval_seconds"] = int64(registry.ProbeInterval.Seconds())
		meta["probe_lifetime_seconds"] = int64(registry.ProbeLifetime.Seconds())
	}
	r.evidence.Manifest["configurations"] = append(r.evidence.Manifest["configurations"].([]any), meta)

	// A fresh wallet keeps intents and quotes isolated while sharing the exact signed chain.
	var active *RequestRow
	wrapped := r.observe(srv.Handler(), func() *RequestRow { return active })
	w, err := bootstrap.BuildWallet(ctx, r.i, r.d, r.f, db, wrapped)
	if err != nil {
		return err
	}

	for n, c := range r.inputs.Cases {
		if c.Configuration != name {
			continue
		}
		r.stage = "case-prepare"
		task, leaf := r.f.RPTask, r.f.RPG2
		if c.Mode == registry.BM {
			task, leaf = r.f.BMTask, r.f.BMG2
		}
		qrow := &r.evidence.Requests[2*n]
		orow := &r.evidence.Requests[2*n+1]
		check := &r.evidence.Orders[n]
		qkey := r.runID + "-" + name + "-" + c.CaseID + "-q"
		okey := r.runID + "-" + name + "-" + c.CaseID + "-o"

		qrow.TaskID = someString(task.ID)
		qrow.Actor = someString(r.f.Identities["B1"].ID)
		qrow.IdempotencyKey = someString(qkey)

		orow.TaskID = someString(task.ID)
		orow.Actor = someString(r.f.Identities["B1"].ID)
		orow.IdempotencyKey = someString(okey)
		orow.QuoteID = nullString{}

		check.TaskID = someString(task.ID)
		check.IdempotencyKey = someString(okey)

		if time.Now().Unix() >= min(task.EXP, r.f.Certifications["B"].Certification.EXP) {
			return fmt.Errorf("baseline materials expired")
		}
		if err := domgw.SetCatalogPrice(ctx, db, r.d.DeploymentID, r.inputs.Fixture.Product, c.AmountMinor); err != nil {
			return err
		}
		var price int64
		if err := db.QueryRow(ctx,
			`SELECT unit_price_minor FROM catalog_prices WHERE deployment_id=$1 AND product_id=$2`,
			r.d.DeploymentID, r.inputs.Fixture.Product,
		).Scan(&price); err != nil {
			return fmt.Errorf("read back catalog price: %w", err)
		}
		if price != c.AmountMinor {
			return fmt.Errorf("catalog price readback: got %d, want %d", price, c.AmountMinor)
		}
		var contextVersion int64
		err = db.QueryRow(ctx,
			`SELECT context_version FROM trusted_contexts WHERE deployment_id=$1 AND task_id=$2`,
			r.d.DeploymentID, task.ID,
		).Scan(&contextVersion)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err = setNormalContext(srv.Handler(), task.ID, contextVersion, min(r.f.RPTask.EXP, r.f.BMTask.EXP)); err != nil {
			return err
		}
		var before int64
		if err = db.QueryRow(ctx,
			`SELECT count(*) FROM orders WHERE deployment_id=$1 AND task_id=$2`,
			r.d.DeploymentID, task.ID,
		).Scan(&before); err != nil {
			return err
		}
		check.OrderRowsBefore = someInt64(before)

		active = qrow
		var quoted wallet.RequestQuoteOutput
		r.action(ctx, qrow, cache, func(call context.Context) error {
			var err error
			quoted, err = w.RequestQuote(call, wallet.RequestQuoteInput{
				Actor:             "B1",
				GrantID:           leaf.ID,
				TaskID:            task.ID,
				AuthorizationMode: c.Mode,
				ProductID:         r.inputs.Fixture.Product,
				Quantity:          1,
				IdempotencyKey:    qkey,
			})
			return err
		})
		quoteID := r.checkQuote(ctx, db, qrow, orow, check)
		if quoteID == "" {
			active = nil
			continue
		}

		active = orow
		orow.QuoteID = someString(quoteID)
		orow.AmountMinor = quoted.TotalAmountMinor
		r.action(ctx, orow, cache, func(call context.Context) error {
			_, err := w.CreateOrder(call, wallet.CreateOrderInput{
				Actor:             "B1",
				GrantID:           leaf.ID,
				TaskID:            task.ID,
				AuthorizationMode: c.Mode,
				QuoteID:           quoteID,
				ProductID:         r.inputs.Fixture.Product,
				Quantity:          1,
				AmountMinor:       quoted.TotalAmountMinor,
				Currency:          r.inputs.Fixture.Currency,
				IdempotencyKey:    okey,
			})
			return err
		})
		r.checkDecision(ctx, db, orow, "order-decision")
		r.checkOrder(ctx, db, c, orow, check, before, quoteID)
		active = nil
		if err = r.evidence.Save(); err != nil {
			return err
		}
	}
	return nil
}

func setNormalContext(handler http.Handler, taskID string, version, deadline int64) error {
	body, err := json.Marshal(domgw.ContextUpdateRequest{
		ExpectedContextVersion: version,
		SourceID:               "ctx-verifier-c",
		ObservedAt:             time.Now().UTC().Unix(),
		RiskLevel:              "NORMAL",
		AccessDeadline:         deadline,
	})
	if err != nil {
		return err
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/contexts/"+taskID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return fmt.Errorf("POST /v1/contexts HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var result domgw.ContextResponse
	return json.Unmarshal(rec.Body.Bytes(), &result)
}

func (r *baselineRun) action(ctx context.Context, row *RequestRow, cache *protocol.SignatureCache, run func(context.Context) error) {
	row.StartedAt = someTime(time.Now().UTC())
	row.Disposition = "error"
	row.FailureStage = someString("wallet")
	hits, misses := cache.Hits(), cache.Misses()
	call, cancel := context.WithTimeout(ctx, r.options.RequestTimeout)
	defer cancel()
	err := run(call)
	row.FinishedAt = someTime(time.Now().UTC())
	row.SignatureCacheHits = someInt64(cache.Hits() - hits)
	row.SignatureCacheMisses = someInt64(cache.Misses() - misses)

	if row.Disposition == "timeout" || errors.Is(call.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		if row.Disposition != "timeout" {
			row.FailureStage = someString("wallet")
		}
		row.Disposition = "timeout"
		err = context.DeadlineExceeded
	}
	stage := ""
	if row.FailureStage.Valid {
		stage = row.FailureStage.Value
	}
	if err != nil {
		if stage == "" {
			stage = "wallet"
			row.FailureStage = someString(stage)
		}
		r.failureRow(row, stage, err)
	} else if stage == "challenge" || stage == "execute" {
		code := ""
		if row.Code.Valid {
			code = row.Code.Value
		}
		r.failureRow(row, stage, protocol.NewError(code, "gateway request failed"))
	}
}

// observe retains only public identifiers and measurements, never raw evidence or disclosure bodies.
func (r *baselineRun) observe(next http.Handler, current func() *RequestRow) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		row := current()
		if row == nil {
			next.ServeHTTP(w, req)
			return
		}
		start := time.Now()
		rec := httptest.NewRecorder()
		if req.URL.Path == "/v1/access/execute" {
			raw, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "request read failed", http.StatusBadRequest)
				return
			}
			req.Body = io.NopCloser(bytes.NewReader(raw))
			var pkg struct {
				ChallengeID string                 `json:"challengeId"`
				Request     protocol.AccessRequest `json:"request"`
			}
			if json.Unmarshal(raw, &pkg) == nil {
				if pkg.ChallengeID != "" {
					row.ChallengeID = someString(pkg.ChallengeID)
				}
				if hash, err := pkg.Request.Hash(false); err == nil {
					row.RequestHash = someString(hash)
				}
				if pkg.Request.AmountMinor != 0 {
					row.AmountMinor = pkg.Request.AmountMinor
				}
			}
		}
		next.ServeHTTP(rec, req)
		var stage string
		switch req.URL.Path {
		case "/v1/auth/challenges":
			stage = "challenge"
			row.ChallengeNs = someInt64(time.Since(start).Nanoseconds())
			if rec.Code == http.StatusCreated {
				var c domgw.ChallengeResponse
				if json.Unmarshal(rec.Body.Bytes(), &c) == nil && c.ChallengeID != "" {
					row.ChallengeID = someString(c.ChallengeID)
				}
			} else {
				row.HTTPStatus = someInt64(int64(rec.Code))
				row.Disposition = "error"
				row.FailureStage = someString(stage)
				requestID := rec.Header().Get("X-Request-Id")
				var body apigw.ErrorBody
				if json.Unmarshal(rec.Body.Bytes(), &body) == nil {
					if body.RequestID != "" {
						requestID = body.RequestID
					}
					if body.Code != "" {
						row.Code = someString(body.Code)
					}
				}
				if requestID != "" {
					row.RequestID = someString(requestID)
				}
			}
		case "/v1/access/execute":
			stage = "execute"
			row.ExecuteNs = someInt64(time.Since(start).Nanoseconds())
			row.HTTPStatus = someInt64(int64(rec.Code))
			if reqID := rec.Header().Get("X-Request-Id"); reqID != "" {
				row.RequestID = someString(reqID)
			}
			var body struct {
				RequestID  string              `json:"requestId"`
				DecisionID *string             `json:"decisionId"`
				Code       string              `json:"code"`
				Quote      *domgw.QuotePayload `json:"quote"`
				Order      *domgw.OrderPayload `json:"order"`
			}
			if json.Unmarshal(rec.Body.Bytes(), &body) == nil {
				if body.RequestID != "" {
					row.RequestID = someString(body.RequestID)
				}
				if body.DecisionID != nil && *body.DecisionID != "" {
					row.DecisionID = someString(*body.DecisionID)
				}
				if body.Code != "" {
					row.Code = someString(body.Code)
				}
				if body.Quote != nil && body.Quote.QuoteID != "" {
					row.QuoteID = someString(body.Quote.QuoteID)
				}
				if body.Order != nil {
					if body.Order.QuoteID != "" {
						row.QuoteID = someString(body.Order.QuoteID)
					}
					if body.Order.OrderID != "" {
						row.OrderID = someString(body.Order.OrderID)
					}
					if body.Order.Status != "" {
						row.httpOrderStatus = someString(body.Order.Status)
					}
					row.httpOrderAmountMinor = someInt64(body.Order.TotalAmountMinor)
				}
			}
			row.FailureStage = someString(stage)
			switch rec.Code {
			case http.StatusOK:
				row.Disposition = "allowed"
				row.FailureStage = nullString{}
			case http.StatusForbidden:
				row.Disposition = "denied"
				if row.DecisionID.Valid {
					row.FailureStage = nullString{}
				}
			default:
				row.Disposition = "error"
			}
		}
		if stage != "" && errors.Is(req.Context().Err(), context.DeadlineExceeded) {
			row.Disposition = "timeout"
			row.FailureStage = someString(stage)
		}
		for key, values := range rec.Header() {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
}

func (r *baselineRun) failure(scope, stage string, err error) {
	code := "operation failed"
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.Code != "" {
		code = pe.Code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = "deadline exceeded"
	}
	r.evidence.Summary.Failures = append(r.evidence.Summary.Failures, FailureRecord{
		Scope:        scope,
		FailureStage: stage,
		Reason:       code,
	})
}

func (r *baselineRun) failureRow(row *RequestRow, stage string, err error) {
	r.failure(row.Configuration+"/"+row.CaseID+"/"+row.Action, stage, err)
	entry := &r.evidence.Summary.Failures[len(r.evidence.Summary.Failures)-1]
	entry.Configuration = row.Configuration
	entry.CaseID = row.CaseID
	entry.Action = row.Action
	entry.HTTPStatus = row.HTTPStatus.intPtr()
	entry.Code = row.Code.ptr()
	entry.RequestID = row.RequestID.ptr()
	entry.ChallengeID = row.ChallengeID.ptr()
	entry.DecisionID = row.DecisionID.ptr()
}

func (r *baselineRun) checkDecision(ctx context.Context, db *pgxpool.Pool, row *RequestRow, stage string) {
	if row.FailureStage.Valid && (row.FailureStage.Value == "challenge" || (row.FailureStage.Value == "execute" && !row.DecisionID.Valid)) {
		return
	}
	if err := r.decision(ctx, db, row); err != nil {
		r.failureRow(row, stage, err)
		if !row.FailureStage.Valid {
			row.FailureStage = someString(stage)
		}
	}
}

func (r *baselineRun) checkQuote(ctx context.Context, db *pgxpool.Pool, quote, order *RequestRow, check *OrderCheckRow) string {
	r.checkDecision(ctx, db, quote, "quote-check")
	if quote.Disposition == "allowed" && !quote.FailureStage.Valid && quote.QuoteID.Valid && quote.QuoteID.Value != "" {
		return quote.QuoteID.Value
	}
	order.FailureStage = someString("quote-dependency")
	check.FailureReason = someString("quote dependency failed")
	return ""
}

func (r *baselineRun) checkOrder(ctx context.Context, db *pgxpool.Pool, c Case, row *RequestRow, check *OrderCheckRow, before int64, quoteID string) {
	if row.FailureStage.Valid && row.FailureStage.Value == "challenge" {
		check.QuoteID = someString(quoteID)
		check.FailureReason = someString("order challenge failed")
		return
	}
	if err := r.orderCheck(ctx, db, c, row, check, before, quoteID); err != nil {
		r.failureRow(row, "primary-check", err)
		check.FailureReason = someString("primary database query failed")
		check.Verdict = "FAIL"
	}
}
