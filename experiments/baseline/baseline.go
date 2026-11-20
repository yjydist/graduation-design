package main

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
	"graduation-design/internal/fabric"
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
	inputs       *Inputs
	evidence     *Evidence
	runID, stage string
	i            *fabric.Instance
	dir          string
	d            *fabric.Deployment
	f            *fabric.Fixtures
	db, c0db     *pgxpool.Pool
	c0           *centralstate.Source
	resolver     *protocol.DIDWebResolver
	passed       bool
}

func runBaseline(ctx context.Context, opts baselineOptions) (e *Evidence, err error) {
	in, err := Baseline(opts.Seed)
	if err != nil {
		return nil, err
	}
	var id [8]byte
	rand.Read(id[:])
	runID := fmt.Sprintf("baseline-%x", id)
	e, err = NewEvidence(opts.Out, runID, in)
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
		scanErr := scanBaselineEvidence(e.Directory, r.dir)
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
	didServer, resolver, err := r.i.StartRegistryDIDResolver(r.d)
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
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	e.Manifest["binary_sha256"] = api.Digest(binary)
	for _, path := range []string{
		"go.mod",
		"go.sum",
		"mise.toml",
		"infra/fabric/compose.yaml",
		"infra/fabric/channel.sh",
		"infra/fabric/network.sh",
		"internal/protocol/contexts/vc-v2.json",
		"experiments/mise.toml",
		"experiments/baseline/baseline.json",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		locks[path] = api.Digest(raw)
	}
	// Pin the actual working source as well as HEAD when implementing an uncommitted change.
	for _, root := range []string{"internal", "cmd", "chaincode", "experiments/baseline"} {
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
	if err := r.claimInstance(); err != nil {
		return err
	}
	i := r.i
	if _, err = os.Stat(filepath.Join(r.dir, "registry", "fixtures.json")); err == nil {
		return fmt.Errorf("baseline requires an instance with no existing seed fixtures")
	} else if !os.IsNotExist(err) {
		return err
	}
	d, err := i.Deploy(ctx)
	if err != nil {
		return err
	}
	r.d = d
	e.Manifest["deployment_id"] = d.DeploymentID
	e.Manifest["channel_id"] = d.ChannelID
	e.Manifest["genesis_hash"] = d.GenesisHash
	e.Manifest["chaincode"] = map[string]any{"name": d.RegistryName, "version": fabric.RegistryVersion, "sequence": fabric.RegistrySequence, "source_digest": d.SourceDigest, "build_digest": d.BuildDigest}
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
	report, err := i.SeedProcurement(ctx, db, d, setup)
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
	e.Manifest["topology"] = map[string]any{"fabric_instance": r.dir, "fabric_database": db.Config().ConnConfig.Database, "centralized_database": r.options.C0Database, "peer_domains": []string{"A", "B", "C"}, "orderers": 4}
	if r.c0, err = centralstate.Initialize(ctx, c0db, centralInput.Snapshot); err != nil {
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
	if err = fabric.EnsureOperationSchema(ctx, c0db); err != nil {
		return err
	}
	if err = gateway.EnsureSchema(ctx, c0db, d.DeploymentID, r.inputs.Fixture.Supplier); err != nil {
		return err
	}
	if err = gateway.EnsureSchema(ctx, db, d.DeploymentID, r.inputs.Fixture.Supplier); err != nil {
		return err
	}
	if err = i.SyncSeedDeliveries(ctx, c0db, d, report); err != nil {
		return err
	}
	e.Manifest["configurations"] = []any{}
	ready = true
	return e.Save()
}

func (r *baselineRun) claimInstance() error {
	dir, err := filepath.Abs(r.options.Dir)
	if err != nil {
		return err
	}
	defaultDir, err := filepath.Abs(".local/fabric-d0")
	if err != nil {
		return err
	}
	if dir == defaultDir {
		return fmt.Errorf("baseline requires an explicitly isolated Fabric instance")
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	target, err := root.Stat(".")
	if err != nil {
		return err
	}
	defaultInfo, err := os.Stat(defaultDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat default Fabric instance: %w", err)
	}
	if err == nil && os.SameFile(target, defaultInfo) {
		return fmt.Errorf("baseline requires an explicitly isolated Fabric instance")
	}
	i, err := fabric.OpenInstance(dir)
	if err != nil {
		return err
	}
	r.i = i
	r.dir = dir
	claim, err := root.OpenFile("baseline-run", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("baseline instance is already claimed: %w", err)
	}
	_, err = claim.WriteString(r.runID + "\n")
	return errors.Join(err, claim.Close())
}

func (r *baselineRun) configuration(ctx context.Context, name string) error {
	r.stage = "configuration-" + name
	profile, err := BaselineConfiguration(name)
	if err != nil {
		return err
	}
	db := r.db
	var state gateway.StateSource
	if name == "C0" {
		db = r.c0db
		state = r.c0
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
		state = provider.GatewayAdapter()
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
	srv, err := gateway.NewServer(gateway.Config{DB: db, State: state, Delivery: fabric.NewDeliveryService(db), DIDs: r.resolver, Policy: bundle, SignatureCache: cache, DeploymentID: r.d.DeploymentID, ServiceDID: r.f.Identities["C"].ID, Audience: "https://c.local", SupplierID: r.inputs.Fixture.Supplier, VerifierID: r.runID + "-" + name})
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
	var active Row
	wrapped := r.observe(srv.Handler(), func() Row { return active })
	wallet, err := r.i.BuildWallet(ctx, r.d, r.f, db, wrapped)
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
		for _, row := range []Row{qrow, orow, check} {
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
		if err = setNormalContext(srv.Handler(), task.ID, contextVersion, min(r.f.RPTask.EXP, r.f.BMTask.EXP)); err != nil {
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
		quoteID := r.checkQuote(ctx, db, qrow, orow, check)
		if quoteID == "" {
			continue
		}
		active = orow
		orow["quote_id"] = quoteID
		orow["amount_minor"] = quoted.TotalAmountMinor
		r.action(ctx, orow, cache, func(call context.Context) error {
			_, err := wallet.CreateOrder(call, agent.CreateOrderInput{Actor: "B1", GrantID: leaf.ID, TaskID: task.ID, AuthorizationMode: c.Mode, QuoteID: quoteID, ProductID: r.inputs.Fixture.Product, Quantity: 1, AmountMinor: quoted.TotalAmountMinor, Currency: r.inputs.Fixture.Currency, IdempotencyKey: okey})
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
	body, err := json.Marshal(gateway.ContextUpdateRequest{
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
	var result gateway.ContextResponse
	return json.Unmarshal(rec.Body.Bytes(), &result)
}

func (r *baselineRun) action(ctx context.Context, row Row, cache *protocol.SignatureCache, run func(context.Context) error) {
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
	stage, _ := row["failure_stage"].(string)
	if err != nil {
		if stage == "" {
			stage = "wallet"
			row["failure_stage"] = stage
		}
		r.failureRow(row, stage, err)
	} else if stage == "challenge" || stage == "execute" {
		code, _ := row["code"].(string)
		r.failureRow(row, stage, protocol.NewError(code, "gateway request failed"))
	}
}

// observe retains only public identifiers and measurements, never raw evidence or disclosure bodies.
func (r *baselineRun) observe(next http.Handler, current func() Row) http.Handler {
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
			if rec.Code == http.StatusCreated {
				var c gateway.ChallengeResponse
				if json.Unmarshal(rec.Body.Bytes(), &c) == nil {
					row["challenge_id"] = c.ChallengeID
				}
			} else {
				row["http_status"] = rec.Code
				row["disposition"] = "error"
				row["failure_stage"] = stage
				requestID := rec.Header().Get("X-Request-Id")
				var body gateway.ErrorBody
				if json.Unmarshal(rec.Body.Bytes(), &body) == nil {
					if body.RequestID != "" {
						requestID = body.RequestID
					}
					if body.Code != "" {
						row["code"] = body.Code
					}
				}
				if requestID != "" {
					row["request_id"] = requestID
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
				if body.DecisionID != nil && *body.DecisionID != "" {
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
			row["failure_stage"] = stage
			switch rec.Code {
			case http.StatusOK:
				row["disposition"] = "allowed"
				row["failure_stage"] = nil
			case http.StatusForbidden:
				row["disposition"] = "denied"
				if row["decision_id"] != nil {
					row["failure_stage"] = nil
				}
			default:
				row["disposition"] = "error"
			}
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
	if errors.As(err, &pe) && pe.Code != "" {
		code = pe.Code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = "deadline exceeded"
	}
	f := map[string]any{"scope": scope, "failure_stage": stage, "reason": code}
	r.evidence.Summary["failures"] = append(r.evidence.Summary["failures"].([]any), f)
}

func (r *baselineRun) failureRow(row Row, stage string, err error) {
	r.failure(fmt.Sprint(row["configuration"], "/", row["case_id"], "/", row["action"]), stage, err)
	list := r.evidence.Summary["failures"].([]any)
	entry := list[len(list)-1].(map[string]any)
	for _, key := range []string{"configuration", "case_id", "action", "http_status", "code", "request_id", "challenge_id", "decision_id"} {
		entry[key] = row[key]
	}
}

func (r *baselineRun) checkDecision(ctx context.Context, db *pgxpool.Pool, row Row, stage string) {
	if row["failure_stage"] == "challenge" || (row["failure_stage"] == "execute" && row["decision_id"] == nil) {
		return
	}
	if err := r.decision(ctx, db, row); err != nil {
		r.failureRow(row, stage, err)
		if row["failure_stage"] == nil {
			row["failure_stage"] = stage
		}
	}
}

func (r *baselineRun) checkQuote(ctx context.Context, db *pgxpool.Pool, quote, order, check Row) string {
	r.checkDecision(ctx, db, quote, "quote-check")
	quoteID, _ := quote["quote_id"].(string)
	if quote["disposition"] == "allowed" && quote["failure_stage"] == nil && quoteID != "" {
		return quoteID
	}
	order["failure_stage"] = "quote-dependency"
	check["failure_reason"] = "quote dependency failed"
	return ""
}

func (r *baselineRun) checkOrder(ctx context.Context, db *pgxpool.Pool, c Case, row, check Row, before int64, quoteID string) {
	if row["failure_stage"] == "challenge" {
		check["quote_id"] = quoteID
		check["failure_reason"] = "order challenge failed"
		return
	}
	if err := r.orderCheck(ctx, db, c, row, check, before, quoteID); err != nil {
		r.failureRow(row, "primary-check", err)
		check["failure_reason"] = "primary database query failed"
		check["verdict"] = "FAIL"
	}
}
