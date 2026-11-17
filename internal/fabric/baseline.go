package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"graduation-design/internal/agent"
	"graduation-design/internal/centralstate"
	"graduation-design/internal/experiment"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"
)

type baselineOptions struct {
	Dir, Out, C0Database string
	Seed                 int
	RequestTimeout       time.Duration
}
type baselineRun struct {
	options      baselineOptions
	inputs       *experiment.Inputs
	evidence     *experiment.Evidence
	runID, stage string
	i            *instance
	d            *deployment
	f            *fixtures
	db, c0db     *pgxpool.Pool
	registration *baselineRegistration
	c0           *centralstate.Source
	resolver     *protocol.DIDWebResolver
	passed       bool
}

func runBaseline(ctx context.Context, opts baselineOptions) (e *experiment.Evidence, err error) {
	in, err := experiment.Baseline(opts.Seed)
	if err != nil {
		return nil, err
	}
	runID := "baseline-" + randomID()[:16]
	e, err = experiment.NewEvidence(opts.Out, runID, in)
	if err != nil {
		return nil, err
	}
	r := &baselineRun{options: opts, inputs: in, evidence: e, runID: runID, stage: "preparation"}
	defer func() {
		if err != nil {
			r.failure("run", r.stage, err)
			for _, row := range e.Requests {
				if row["disposition"] == "dropped" && row["failure_stage"] == "preparation" {
					row["failure_stage"] = r.stage
				}
			}
		}
		r.passed = r.compare()
		e.Summary["request_accounting"] = e.Account()
		e.Summary["passed"] = err == nil && r.passed
		err = errors.Join(err, e.Save())
		scanErr := scanBaselineEvidence(e.Directory, r.i)
		e.Summary["secret_scan"] = map[string]any{"passed": scanErr == nil, "files": 4}
		if scanErr != nil {
			e.Summary["passed"] = false
			r.failure("run", "secret-scan", scanErr)
		}
		err = errors.Join(err, scanErr, e.Save())
	}()
	if err = e.Save(); err != nil {
		return e, err
	}
	if err = r.prepare(ctx); err != nil {
		return e, err
	}
	defer r.db.Close()
	defer r.c0db.Close()
	a := acceptance{instance: r.i, d: r.d, f: r.f}
	didServer, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return e, err
	}
	defer didServer.Close()
	r.resolver = resolver
	for _, name := range in.Fixture.Configurations {
		if err = r.configuration(ctx, name); err != nil {
			return e, err
		}
	}
	r.stage = "comparison"
	r.passed = r.compare()
	if !r.passed {
		return e, fmt.Errorf("baseline business or paired checks failed")
	}
	return e, nil
}

func (r *baselineRun) prepare(ctx context.Context) error {
	e := r.evidence
	e.Manifest["go_version"] = runtime.Version()
	e.Manifest["host"] = runtime.GOOS + "/" + runtime.GOARCH
	e.Manifest["clock"] = "UTC wall clock and per-process monotonic nanoseconds"
	commit, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	e.Manifest["source_commit"] = strings.TrimSpace(string(commit))
	locks := map[string]string{}
	for _, path := range []string{"go.mod", "go.sum", "mise.toml", "infra/fabric/compose.yaml", "infra/fabric/channel.sh", "internal/experiment/baseline.json"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		locks[path] = api.Digest(raw)
	}
	// Pin the actual working source as well as HEAD when implementing an uncommitted change.
	for _, root := range []string{"internal", "cmd", "chaincode"} {
		if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") {
				raw, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				locks[filepath.ToSlash(path)] = api.Digest(raw)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	e.Manifest["artifact_locks"] = locks
	if !regexp.MustCompile(`^baseline_[a-z0-9_]{1,48}$`).MatchString(r.options.C0Database) {
		return fmt.Errorf("C0 database must be a new name matching baseline_[a-z0-9_]{1,48}")
	}
	dir, err := filepath.Abs(r.options.Dir)
	if err != nil {
		return err
	}
	defaultDir, _ := filepath.Abs(".local/fabric-d0")
	if dir == defaultDir {
		return fmt.Errorf("baseline requires an explicitly isolated Fabric instance")
	}
	i, err := loadInstance(dir)
	if err != nil {
		return err
	}
	r.i = i
	i.baseline = r.inputs
	claim, err := os.OpenFile(filepath.Join(dir, "baseline-run"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("baseline instance is already claimed: %w", err)
	}
	_, err = claim.WriteString(r.runID + "\n")
	closeErr := claim.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return err
	}
	if _, err = os.Stat(i.registryPath("fixtures.json")); err == nil {
		return fmt.Errorf("baseline requires an instance with no existing seed fixtures")
	} else if !os.IsNotExist(err) {
		return err
	}
	d, err := i.deploy(ctx, false)
	if err != nil {
		return err
	}
	r.d = d
	e.Manifest["deployment_id"] = d.DeploymentID
	e.Manifest["channel_id"] = d.ChannelID
	e.Manifest["genesis_hash"] = d.GenesisHash
	e.Manifest["chaincode"] = map[string]any{"name": d.RegistryName, "version": version, "sequence": sequence, "source_digest": d.SourceDigest, "build_digest": d.BuildDigest}
	e.Manifest["root"] = d.Bootstrap.Root
	db, err := i.database(ctx)
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
	if err = initSchema(ctx, db, operationsSchema+viewSchema); err != nil {
		return err
	}
	report, err := i.seed(ctx, journal{instance: i, db: db, deploymentID: d.DeploymentID}, d)
	if err != nil {
		return err
	}
	r.f = report.fixtures
	fabricInput, centralInput, err := i.baselineRegistrations(d, r.f)
	if err != nil {
		return err
	}
	if fabricInput.MaterialDigest != centralInput.MaterialDigest || fabricInput.AnchorDigest != centralInput.AnchorDigest {
		return fmt.Errorf("paired registration material mismatch")
	}
	r.registration = centralInput
	e.Manifest["material_digest"] = centralInput.MaterialDigest
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
	if r.c0, err = centralstate.Initialize(ctx, c0db, centralInput.Snapshot); err != nil {
		return err
	}
	if err = initSchema(ctx, c0db, operationsSchema); err != nil {
		return err
	}
	if err = gateway.EnsureSchema(ctx, c0db, d.DeploymentID, r.inputs.Fixture.Supplier); err != nil {
		return err
	}
	if err = gateway.EnsureSchema(ctx, db, d.DeploymentID, r.inputs.Fixture.Supplier); err != nil {
		return err
	}
	if err = i.syncMaterialOutboxes(ctx, journal{instance: i, db: c0db, deploymentID: d.DeploymentID}, d, r.f, report); err != nil {
		return err
	}
	e.Manifest["topology"] = map[string]any{"fabric_instance": dir, "fabric_database": db.Config().ConnConfig.Database, "centralized_database": r.options.C0Database, "centralized_registry_digest": centralInput.AnchorDigest, "fabric_registry_digest": fabricInput.AnchorDigest, "peer_domains": []string{"A", "B", "C"}, "orderers": 4}
	e.Manifest["configurations"] = []any{}
	ready = true
	return e.Save()
}

func (r *baselineRun) configuration(ctx context.Context, name string) error {
	r.stage = "configuration-" + name
	profile, err := experiment.BaselineConfiguration(name)
	if err != nil {
		return err
	}
	db := r.db
	var state gateway.StateSource
	var stop func()
	if name == "C0" {
		db = r.c0db
		state = r.c0
	} else {
		rt := &online{view: view{db: db, d: r.d}, instance: r.i, role: "probe1", interval: api.ProbeInterval, timeLimit: api.ProbeLifetime}
		if name == "B1" {
			rt.role = "probe2"
		}
		stop, err = rt.start(ctx)
		if err != nil {
			return err
		}
		defer stop()
		wait, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, err = waitOnline(wait, rt, r.f.BMG2.ID)
		cancel()
		if err != nil {
			return err
		}
		state = NewStateProvider(db, r.d, rt).GatewayAdapter()
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
	srv, err := gateway.NewServer(gateway.Config{DB: db, State: state, Delivery: NewDeliveryService(db), DIDs: r.resolver, Policy: bundle, SignatureCache: cache, DeploymentID: r.d.DeploymentID, ServiceDID: r.f.Identities["C"].ID, Audience: "https://c.local", SupplierID: r.inputs.Fixture.Supplier, VerifierID: r.runID + "-" + name})
	if err != nil {
		return err
	}
	meta := map[string]any{"configuration": name, "state_source": profile.StateSource, "database": db.Config().ConnConfig.Database, "gateway_instance": r.runID + "-" + name, "signature_cache": profile.SignatureCache, "probe_interval_seconds": nil, "probe_lifetime_seconds": nil}
	if name != "C0" {
		meta["probe_interval_seconds"] = int64(api.ProbeInterval.Seconds())
		meta["probe_lifetime_seconds"] = int64(api.ProbeLifetime.Seconds())
	}
	r.evidence.Manifest["configurations"] = append(r.evidence.Manifest["configurations"].([]any), meta)
	// A fresh wallet keeps intents and quotes isolated while sharing the exact signed chain.
	var active experiment.Row
	wrapped := r.observe(srv.Handler(), func() experiment.Row { return active })
	wallet, err := buildM2WalletContext(ctx, r.i, *r.d, r.f, db, "", wrapped, time.Now)
	if err != nil {
		return err
	}
	for n, c := range r.inputs.Cases {
		if c.Configuration != name {
			continue
		}
		r.stage = "case-prepare"
		task, leaf := r.f.RPTask, r.f.RPG2
		if c.Mode == api.BM {
			task, leaf = r.f.BMTask, r.f.BMG2
		}
		qrow, orow, check := r.evidence.Requests[2*n], r.evidence.Requests[2*n+1], r.evidence.Orders[n]
		qkey := r.runID + "-" + name + "-" + c.CaseID + "-q"
		okey := r.runID + "-" + name + "-" + c.CaseID + "-o"
		for _, row := range []experiment.Row{qrow, orow, check} {
			row["task_id"] = task.ID
			row["actor"] = r.f.Identities["B1"].ID
		}
		qrow["idempotency_key"] = qkey
		orow["idempotency_key"] = okey
		check["idempotency_key"] = okey
		orow["quote_id"] = nil
		if time.Now().Unix() >= min(task.EXP, r.f.Certifications["B"].Certification.EXP) {
			return fmt.Errorf("baseline materials expired")
		}
		if _, err = db.Exec(ctx, `UPDATE catalog_prices SET unit_price_minor=$3 WHERE deployment_id=$1 AND product_id=$2`, r.d.DeploymentID, r.inputs.Fixture.Product, c.AmountMinor); err != nil {
			return err
		}
		var price int64
		if err = db.QueryRow(ctx, `SELECT unit_price_minor FROM catalog_prices WHERE deployment_id=$1 AND product_id=$2`, r.d.DeploymentID, r.inputs.Fixture.Product).Scan(&price); err != nil || price != c.AmountMinor {
			return fmt.Errorf("catalog price readback failed: %w", err)
		}
		var contextVersion int64
		err = db.QueryRow(ctx, `SELECT context_version FROM trusted_contexts WHERE deployment_id=$1 AND task_id=$2`, r.d.DeploymentID, task.ID).Scan(&contextVersion)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err = gatewaySetContext(srv.Handler(), task.ID, contextVersion, time.Now().UTC().Unix(), "NORMAL", min(r.f.RPTask.EXP, r.f.BMTask.EXP)); err != nil {
			return err
		}
		var before int64
		if err = db.QueryRow(ctx, `SELECT count(*) FROM orders WHERE deployment_id=$1 AND task_id=$2`, r.d.DeploymentID, task.ID).Scan(&before); err != nil {
			return err
		}
		check["order_rows_before"] = before
		active = qrow
		var quoted agent.RequestQuoteOutput
		r.action(ctx, qrow, cache, func(call context.Context) error {
			var err error
			quoted, err = wallet.RequestQuote(call, agent.RequestQuoteInput{Actor: "B1", GrantID: leaf.ID, TaskID: task.ID, AuthorizationMode: c.Mode, ProductID: r.inputs.Fixture.Product, Quantity: 1, IdempotencyKey: qkey})
			return err
		})
		if err = r.decision(ctx, db, qrow); err != nil {
			r.failureRow(qrow, "quote-check", err)
			if qrow["failure_stage"] == nil {
				qrow["failure_stage"] = "quote-check"
			}
		}
		quoteID, _ := qrow["quote_id"].(string)
		if qrow["disposition"] != "allowed" || qrow["failure_stage"] != nil || quoteID == "" {
			orow["failure_stage"] = "quote-dependency"
			check["failure_reason"] = "quote dependency failed"
			continue
		}
		active = orow
		orow["quote_id"] = quoteID
		orow["amount_minor"] = quoted.TotalAmountMinor
		r.action(ctx, orow, cache, func(call context.Context) error {
			_, err := wallet.CreateOrder(call, agent.CreateOrderInput{Actor: "B1", GrantID: leaf.ID, TaskID: task.ID, AuthorizationMode: c.Mode, QuoteID: quoteID, ProductID: r.inputs.Fixture.Product, Quantity: 1, AmountMinor: quoted.TotalAmountMinor, Currency: r.inputs.Fixture.Currency, IdempotencyKey: okey})
			return err
		})
		if err = r.decision(ctx, db, orow); err != nil {
			r.failureRow(orow, "order-decision", err)
			if orow["failure_stage"] == nil {
				orow["failure_stage"] = "order-decision"
			}
		}
		r.checkOrder(ctx, db, c, orow, check, before, quoteID)
		active = nil
		if err = r.evidence.Save(); err != nil {
			return err
		}
	}
	return nil
}

func (r *baselineRun) action(ctx context.Context, row experiment.Row, cache *protocol.SignatureCache, run func(context.Context) error) {
	row["started_at"] = time.Now().UTC()
	row["disposition"] = "error"
	row["failure_stage"] = "wallet"
	hits, misses := cache.Hits(), cache.Misses()
	call, cancel := context.WithTimeout(ctx, r.options.RequestTimeout)
	defer cancel()
	err := run(call)
	row["finished_at"] = time.Now().UTC()
	row["signature_cache_hits"] = cache.Hits() - hits
	row["signature_cache_misses"] = cache.Misses() - misses
	if row["disposition"] == "timeout" || errors.Is(call.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		if row["disposition"] != "timeout" {
			row["failure_stage"] = "wallet"
		}
		row["disposition"] = "timeout"
		err = context.DeadlineExceeded
	}
	if err != nil {
		stage, _ := row["failure_stage"].(string)
		if stage == "" {
			stage = "wallet"
			row["failure_stage"] = stage
		}
		r.failureRow(row, stage, err)
	}
}

// observe retains only public identifiers and measurements, never raw evidence or disclosure bodies.
func (r *baselineRun) observe(next http.Handler, current func() experiment.Row) http.Handler {
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
				http.Error(w, "request read failed", 400)
				return
			}
			req.Body = io.NopCloser(bytes.NewReader(raw))
			var pkg struct {
				ChallengeID string                 `json:"challengeId"`
				Request     protocol.AccessRequest `json:"request"`
			}
			if json.Unmarshal(raw, &pkg) == nil {
				row["challenge_id"] = pkg.ChallengeID
				hash, err := pkg.Request.Hash(false)
				if err == nil {
					row["request_hash"] = hash
				}
				row["amount_minor"] = pkg.Request.AmountMinor
			}
		}
		next.ServeHTTP(rec, req)
		var stage string
		switch req.URL.Path {
		case "/v1/auth/challenges":
			stage = "challenge"
			row["challenge_ns"] = time.Since(start).Nanoseconds()
			if rec.Code == 201 {
				var c gateway.ChallengeResponse
				if json.Unmarshal(rec.Body.Bytes(), &c) == nil {
					row["challenge_id"] = c.ChallengeID
				}
			}
		case "/v1/access/execute":
			stage = "execute"
			row["execute_ns"] = time.Since(start).Nanoseconds()
			row["http_status"] = rec.Code
			row["request_id"] = rec.Header().Get("X-Request-Id")
			var body struct {
				RequestID  string            `json:"requestId"`
				DecisionID *string           `json:"decisionId"`
				Code       string            `json:"code"`
				Quote      *gateway.QuoteDTO `json:"quote"`
				Order      *gateway.OrderDTO `json:"order"`
			}
			if json.Unmarshal(rec.Body.Bytes(), &body) == nil {
				if body.RequestID != "" {
					row["request_id"] = body.RequestID
				}
				if body.DecisionID != nil {
					row["decision_id"] = *body.DecisionID
				}
				row["code"] = body.Code
				if body.Quote != nil {
					row["quote_id"] = body.Quote.QuoteID
				}
				if body.Order != nil {
					row["quote_id"] = body.Order.QuoteID
					row["order_id"] = body.Order.OrderID
					row["order_status"] = body.Order.Status
					row["order_amount_minor"] = body.Order.TotalAmountMinor
				}
			}
			row["disposition"] = "error"
			if rec.Code == 200 {
				row["disposition"] = "allowed"
			}
			if rec.Code == 403 {
				row["disposition"] = "denied"
			}
			row["failure_stage"] = nil
		}
		if stage != "" && errors.Is(req.Context().Err(), context.DeadlineExceeded) {
			row["disposition"] = "timeout"
			row["failure_stage"] = stage
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
	if errors.As(err, &pe) {
		code = pe.Code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = "deadline exceeded"
	}
	f := map[string]any{"scope": scope, "failure_stage": stage, "reason": code}
	r.evidence.Summary["failures"] = append(r.evidence.Summary["failures"].([]any), f)
}

func (r *baselineRun) failureRow(row experiment.Row, stage string, err error) {
	r.failure(fmt.Sprint(row["configuration"], "/", row["case_id"], "/", row["action"]), stage, err)
	list := r.evidence.Summary["failures"].([]any)
	entry := list[len(list)-1].(map[string]any)
	for _, key := range []string{"configuration", "case_id", "action", "request_id", "challenge_id", "decision_id"} {
		entry[key] = row[key]
	}
}

func (r *baselineRun) checkOrder(ctx context.Context, db *pgxpool.Pool, c experiment.Case, row, check experiment.Row, before int64, quoteID string) {
	if err := r.orderCheck(ctx, db, c, row, check, before, quoteID); err != nil {
		r.failureRow(row, "primary-check", err)
		check["failure_reason"] = "primary database query failed"
		check["verdict"] = "FAIL"
	}
}
