package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"graduation-design/internal/agent"
	"graduation-design/internal/fabric"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/policy"
	"graduation-design/internal/protocol"

	"github.com/jackc/pgx/v5/pgxpool"
)

type verdict struct {
	Name          string `json:"name"`
	Pass          bool   `json:"pass"`
	Status        string `json:"status,omitempty"`
	MissingReason string `json:"missingReason,omitempty"`
	Error         string `json:"error,omitempty"`
}

type report struct {
	Run        string    `json:"runId"`
	Status     string    `json:"status"`
	Stage      string    `json:"stage"`
	Deployment string    `json:"deploymentId,omitempty"`
	Started    time.Time `json:"startedAt"`
	Finished   time.Time `json:"finishedAt"`
	Cases      []verdict `json:"cases"`
	Error      string    `json:"error,omitempty"`
}

type e1Trial struct {
	ctx                          context.Context
	id, dir, ledgerctl, revision string
	instance                     instance
	cfg                          agent.RunnerConfig
	configuredURL                string
	d                            deployment
	db                           *pgxpool.Pool
	f                            fixture
	seed                         seedReport
	sp                           *fabric.StateProvider
	state                        gateway.StateSource
	did                          *protocol.DIDWebServer
	resolver                     *protocol.DIDWebResolver
	server                       *gateway.Server
	bundle                       *policy.VerifiedBundle
	modes                        []*e1Mode
	requests                     []e1HTTPRecord
	traces                       []e1Trace
	stage                        string
	eventFile                    *os.File
	eventErr                     error
}

type e1Mode struct {
	tag       string
	task      api.Task
	g0, g1    api.Grant
	leafID    string
	wallet    *agent.WalletContext
	delegated bool
	q800      string
	pkg       *protocol.AccessEvidencePackage
	chal      protocol.ChallengeContext
}

func main() {
	var e e1Trial
	flag.StringVar(&e.revision, "revision", "", "fixed project commit")
	flag.StringVar(&e.dir, "out", "", "new experiment output directory")
	flag.StringVar(&e.ledgerctl, "ledgerctl", "", "ledgerctl binary built from the fixed commit")
	flag.StringVar(&e.instance.dir, "dir", "", "isolated Fabric instance")
	flag.Parse()
	if err := e.run(); err != nil {
		fmt.Fprintln(os.Stderr, e.redact(err.Error()))
		os.Exit(1)
	}
}

func (e *e1Trial) run() (err error) {
	if e.dir == "" || e.ledgerctl == "" || e.revision == "" || e.instance.dir == "" {
		return fmt.Errorf("revision, out, ledgerctl and dir are required")
	}
	e.id = filepath.Base(e.dir)
	r := report{Run: e.id, Status: "FAIL", Stage: "preparation", Started: time.Now().UTC(), Cases: []verdict{}}
	defer func() {
		r.Finished = time.Now().UTC()
		if err != nil {
			r.Error = e.redact(err.Error())
		} else {
			r.Status = "PASS"
		}
		err = errors.Join(err, writePublicJSON(filepath.Join(e.dir, "summary.json"), r))
	}()
	e.cfg = agent.LoadRunnerConfigFromEnv()
	e.configuredURL = e.cfg.BaseURL
	base, err := url.Parse(e.cfg.BaseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") ||
		base.User != nil || base.RawQuery != "" || base.Fragment != "" || e.cfg.APIKey == "" || e.cfg.Model == "" {
		return fmt.Errorf("invalid LLM endpoint, model or API key configuration")
	}
	if e.cfg.Provider == agent.ProviderOpenAI && (base.Path == "" || base.Path == "/") {
		base.Path = "/v1"
		e.cfg.BaseURL = base.String()
	}
	e.cfg.MaxSteps = max(e.cfg.MaxSteps, 10)
	sigCtx, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSig()
	ctx, cancel := context.WithTimeout(sigCtx, 12*time.Minute)
	e.ctx = ctx
	defer cancel()
	e.eventFile, err = os.Create(filepath.Join(e.dir, "events.jsonl"))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, e.eventErr, e.eventFile.Close()) }()
	defer func() { err = errors.Join(err, e.finish()) }()
	if err := e.setup(); err != nil {
		return err
	}
	r.Deployment = e.d.DeploymentID
	r.Stage = "cases"
	for _, item := range []struct {
		name string
		run  func() error
	}{
		{"F01", e.bootstrap}, {"F02", e.link}, {"F03", e.credentials}, {"F04", e.trust},
		{"F05", func() error { return e.forModes(e.delegate) }},
		{"F06", func() error { return e.forModes(e.acceptOrder) }},
		{"F07", func() error { return e.forModes(e.overLimit) }},
		{"F08", func() error { return e.forModes(e.retryOrder) }},
		{"F09", e.decisions}, {"F10", e.buyerRoot},
		{"F11", func() error { return e.forModes(e.supplierPolicy) }},
		{"F12", e.didBinding},
		{"F13", func() error { return e.forModes(e.modeBinding) }},
		{"F14", e.offlineRoot}, {"F15", e.renewAuthority}, {"F16", e.evidenceBindings},
	} {
		e.stage = item.name
		if ctx.Err() != nil {
			reason := fmt.Sprintf("aborted before %s: %v", item.name, ctx.Err())
			entry := verdict{Name: item.name, Pass: false, Status: "not_executed", MissingReason: reason, Error: reason}
			r.Cases = append(r.Cases, entry)
			e.event("case_result", entry)
			err = errors.Join(err, ctx.Err())
			continue
		}
		e.event("case_start", e.stage)
		caseErr := item.run()
		entry := verdict{Name: item.name, Pass: caseErr == nil, Status: "passed"}
		if caseErr != nil {
			entry.Status = "failed"
			if ctx.Err() != nil {
				entry.Status = "aborted"
				entry.MissingReason = fmt.Sprintf("aborted during %s: %v", item.name, ctx.Err())
			}
			entry.Error = e.redact(caseErr.Error())
			err = errors.Join(err, fmt.Errorf("%s: %s", item.name, entry.Error))
		}
		r.Cases = append(r.Cases, entry)
		e.event("case_result", entry)
	}
	return err
}

func (e *e1Trial) setup() error {
	if err := e.command(e.ctx, &e.d, "deploy"); err != nil {
		return err
	}
	if err := e.saveManifest(); err != nil {
		return err
	}
	db, err := e.instance.database(e.ctx)
	if err != nil {
		return err
	}
	e.db = db
	if err := e.prepareRegistry(); err != nil {
		return err
	}

	provider := fabric.NewStateProviderFromBootstrap(db, e.d.DeploymentID, e.d.Bootstrap, nil)
	e.sp = provider
	e.state = &liveState{StateSource: provider.GatewayAdapter(), trial: e}
	if _, err := e.refresh(e.ctx, e.f.RPG2.ID); err != nil {
		return err
	}
	e.did, e.resolver, err = e.newControlledDIDResolver()
	if err != nil {
		return err
	}
	if err := gateway.EnsureSchema(e.ctx, db, e.d.DeploymentID, "urn:grad:supplier:C"); err != nil {
		return err
	}
	c := e.f.Identities["C"].ID
	files, digest, err := policy.BuildDefaultBundle(e.d.DeploymentID, c, policy.DefaultPolicyVersion, e.d.Bootstrap.Root, nil)
	if err != nil {
		return err
	}
	e.bundle, err = policy.VerifyAndLoadBundle(files, e.d.DeploymentID, c, e.d.Bootstrap.Root, digest)
	if err != nil {
		return err
	}
	e.server, err = e.newGateway(e.resolver, e.bundle, time.Now)
	if err != nil {
		return err
	}
	e.modes = []*e1Mode{
		{tag: "rp", task: e.f.RPTask, g0: e.f.RPG0, g1: e.f.RPG1},
		{tag: "bm", task: e.f.BMTask, g0: e.f.BMG0, g1: e.f.BMG1},
	}
	for _, mode := range e.modes {
		mode.leafID = api.Digest([]byte(e.id + "/E1/" + mode.tag + "/G2"))
	}
	return e.saveManifest()
}

func (e *e1Trial) saveManifest() error {
	driverPath, err := os.Executable()
	if err != nil {
		return err
	}
	binaries := map[string]string{}
	for name, path := range map[string]string{"ledgerctl": e.ledgerctl, "driver": driverPath} {
		value, err := sha256File(path)
		if err != nil {
			return err
		}
		binaries[name] = value
	}
	driverFiles, err := filepath.Glob("experiments/e1-procurement/driver/*.go")
	if err != nil || len(driverFiles) == 0 {
		return fmt.Errorf("driver source files were not included in the build environment")
	}
	inputs := map[string]string{}
	for _, name := range append(driverFiles, "go.mod", "go.sum", "infra/fabric/compose.yaml", "docs/experiments/实验计划.md", "docs/experiments/验证用例.md") {
		hash, err := sha256File(name)
		if err != nil {
			return err
		}
		inputs[name] = hash
	}
	manifest := map[string]any{}
	if existingRaw, readErr := os.ReadFile(filepath.Join(e.dir, "manifest.json")); readErr == nil {
		_ = json.Unmarshal(existingRaw, &manifest)
	}
	updates := map[string]any{
		"experiment": "E1", "runId": e.id, "sourceCommit": e.revision, "binarySHA256": binaries, "fileSHA256": inputs,
		"instance": e.instance.dir, "deployment": e.d.Raw, "host": runtime.GOOS + "/" + runtime.GOARCH, "go": runtime.Version(),
		"configuration":      "Fabric fixed-height, static signature cache disabled; real lease acquired using ledgerctl check and handed to the existing StateProvider",
		"authorizationModes": []string{api.RP, api.BM},
		"llm":                map[string]any{"provider": e.cfg.Provider, "model": e.cfg.Model, "configuredBaseURL": e.configuredURL, "baseURL": e.cfg.BaseURL, "maxSteps": e.cfg.MaxSteps},
	}
	for k, v := range updates {
		if k == "fileSHA256" {
			if prev, ok := manifest[k].(map[string]any); ok {
				for fk, fv := range inputs {
					prev[fk] = fv
				}
				continue
			}
		}
		manifest[k] = v
	}
	if e.bundle != nil {
		manifest["policyDigest"] = e.bundle.PolicyDigest
	}
	if fixtureSum, err := sha256File(e.instance.registrySubPath("fixtures.json")); err == nil {
		manifest["fixtureDigest"] = fixtureSum
	}
	return e.save("manifest", manifest)
}

func (e *e1Trial) event(name string, value any) {
	if e.eventErr == nil {
		e.eventErr = json.NewEncoder(e.eventFile).Encode(map[string]any{"at": time.Now().UTC(), "event": name, "details": value})
	}
}

func (e *e1Trial) save(name string, value any) error {
	return writePublicJSON(filepath.Join(e.dir, name+".json"), value)
}

func (e *e1Trial) redact(value string) string {
	if e.cfg.APIKey != "" {
		return strings.ReplaceAll(value, e.cfg.APIKey, "[REDACTED]")
	}
	return value
}

func (e *e1Trial) forModes(run func(*e1Mode) error) error {
	var combined error
	for _, m := range e.modes {
		err := run(m)
		e.event("mode_result", map[string]any{"case": e.stage, "mode": m.task.Mode, "passed": err == nil})
		if err != nil {
			combined = errors.Join(combined, fmt.Errorf("%s: %w", m.tag, err))
		}
	}
	return combined
}

func (e *e1Trial) newGateway(resolver *protocol.DIDWebResolver, bundle *policy.VerifiedBundle, now func() time.Time) (*gateway.Server, error) {
	return gateway.NewServer(gateway.Config{
		DB: e.db, State: e.state, Delivery: fabric.NewDeliveryService(e.db), DIDs: resolver,
		Policy: bundle, DeploymentID: e.d.DeploymentID, ServiceDID: e.f.Identities["C"].ID,
		Audience: "https://c.local", SupplierID: "urn:grad:supplier:C", NowFn: now,
	})
}

func (e *e1Trial) gatewayFor(resolver *protocol.DIDWebResolver, bundle *policy.VerifiedBundle, now func() time.Time) (http.Handler, error) {
	server, err := e.newGateway(resolver, bundle, now)
	if err != nil {
		return nil, err
	}
	return server.Handler(), nil
}
