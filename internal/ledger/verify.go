package ledger

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type VerifyOptions struct {
	Dir            string        `json:"instanceDirectory"`
	Manifest       string        `json:"manifest"`
	Endpoint       string        `json:"endpoint"`
	Output         string        `json:"outputRoot"`
	ProjectRoot    string        `json:"projectRoot"`
	ComposeFile    string        `json:"composeFile"`
	ComposeProject string        `json:"composeProject"`
	Timeout        time.Duration `json:"timeoutNanoseconds"`
	StartupTimeout time.Duration `json:"startupTimeoutNanoseconds"`
	ReceiptTimeout time.Duration `json:"receiptTimeoutNanoseconds"`
}

type VerificationCheck struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Evidence string `json:"evidence"`
	Error    string `json:"error,omitempty"`
}
type VerificationSummary struct {
	RunID        string              `json:"runId"`
	Directory    string              `json:"directory"`
	DeploymentID string              `json:"deploymentId,omitempty"`
	Passed       bool                `json:"passed"`
	Checks       []VerificationCheck `json:"checks"`
	Scope        string              `json:"scope"`
	Unexecuted   []string            `json:"unexecuted"`
}

type verificationRun struct {
	summary  *VerificationSummary
	events   *os.File
	options  VerifyOptions
	recorder *RPCRecorder
}

func (v *verificationRun) event(value any) error {
	if err := json.NewEncoder(v.events).Encode(value); err != nil {
		return err
	}
	return v.events.Sync()
}

func (v *verificationRun) check(name string, fn func() (any, error)) error {
	if err := v.event(map[string]any{"runId": v.summary.RunID, "deploymentId": v.summary.DeploymentID, "check": name, "phase": "started", "observedAt": time.Now().UTC()}); err != nil {
		return err
	}
	data, checkErr := fn()
	file := name + ".json"
	result := VerificationCheck{Name: name, Passed: checkErr == nil, Evidence: file}
	if checkErr != nil {
		result.Error = checkErr.Error()
	}
	if err := writeJSON(filepath.Join(v.summary.Directory, file), map[string]any{"runId": v.summary.RunID, "deploymentId": v.summary.DeploymentID, "result": result, "data": data}); err != nil {
		return err
	}
	v.summary.Checks = append(v.summary.Checks, result)
	if err := v.event(map[string]any{"runId": v.summary.RunID, "check": name, "phase": "finished", "result": result, "observedAt": time.Now().UTC()}); err != nil {
		return err
	}
	return checkErr
}

func normalizeVerifyOptions(o VerifyOptions) (VerifyOptions, error) {
	var err error
	if o.ProjectRoot == "" {
		o.ProjectRoot = "."
	}
	if o.Dir == "" {
		o.Dir = ".local/besu-qbft"
	}
	if o.Output == "" {
		o.Output = ".local/evidence"
	}
	if o.Endpoint == "" {
		o.Endpoint = "http://127.0.0.1:18547"
	}
	if o.ComposeProject == "" {
		o.ComposeProject = "grad-besu"
	}
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Minute
	}
	if o.StartupTimeout == 0 {
		o.StartupTimeout = 120 * time.Second
	}
	if o.ReceiptTimeout == 0 {
		o.ReceiptTimeout = 30 * time.Second
	}
	if o.ProjectRoot, err = filepath.Abs(o.ProjectRoot); err != nil {
		return o, err
	}
	for _, p := range []*string{&o.Dir, &o.Output} {
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(o.ProjectRoot, *p)
		}
	}
	if o.Manifest == "" {
		o.Manifest = filepath.Join(o.Dir, "deployment-registry.json")
	} else if !filepath.IsAbs(o.Manifest) {
		o.Manifest = filepath.Join(o.ProjectRoot, o.Manifest)
	}
	if o.ComposeFile == "" {
		o.ComposeFile = filepath.Join(o.ProjectRoot, "infra/besu/compose.yaml")
	} else if !filepath.IsAbs(o.ComposeFile) {
		o.ComposeFile = filepath.Join(o.ProjectRoot, o.ComposeFile)
	}
	if o.Timeout < 0 || o.StartupTimeout < 0 || o.ReceiptTimeout < 0 {
		return o, fmt.Errorf("verification timeouts must be positive")
	}
	return o, nil
}

func parseDeploymentABI(d *Deployment) (abi.ABI, error) {
	return abi.JSON(strings.NewReader(string(d.ABI)))
}

// Verify preserves every failed run in an independent directory and always writes a summary.
func Verify(ctx context.Context, options VerifyOptions) (summary *VerificationSummary, runErr error) {
	o, err := normalizeVerifyOptions(options)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	random := make([]byte, 8)
	if _, err = rand.Read(random); err != nil {
		return nil, err
	}
	runID := "run-" + hex.EncodeToString(random)
	runDir := filepath.Join(o.Output, runID)
	if err = os.MkdirAll(runDir, 0755); err != nil {
		return nil, err
	}
	events, err := os.OpenFile(filepath.Join(runDir, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	summary = &VerificationSummary{RunID: runID, Directory: runDir, Scope: "D0 minimal permissioned ledger and state availability", Unexecuted: []string{"order-level E6/E7", "D0 complete credential protocol", "M1/M2 business workflows"}}
	v := &verificationRun{summary: summary, events: events, options: o, recorder: &RPCRecorder{}}
	defer func() {
		if runErr != nil && (len(summary.Checks) == 0 || summary.Checks[len(summary.Checks)-1].Passed) {
			summary.Checks = append(summary.Checks, VerificationCheck{Name: "execution", Error: runErr.Error()})
		}
		summary.Passed = runErr == nil && len(summary.Checks) > 0
		if err := writeJSONL(filepath.Join(runDir, "rpc.jsonl"), v.recorder.Snapshot()); err != nil && runErr == nil {
			runErr = err
			summary.Passed = false
		}
		if err := writeJSON(filepath.Join(runDir, "summary.json"), summary); err != nil && runErr == nil {
			runErr = err
			summary.Passed = false
		}
		events.Close()
	}()
	if err = writeJSON(filepath.Join(runDir, "configuration.json"), map[string]any{"options": o, "goVersion": runtime.Version(), "architecture": runtime.GOARCH, "deltaStateSeconds": 5, "futureToleranceSeconds": 1, "emptyBlocks": 10, "oneNodeNewBlocks": 3, "settleSeconds": 5, "stableWindowSeconds": 15, "cleanupTimeoutSeconds": 30}); err != nil {
		return summary, err
	}
	var r *Registry
	runErr = v.check("preflight", func() (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, err := LoadInstance(o.Dir)
		if err != nil {
			return nil, err
		}
		b, err := os.ReadFile(o.Manifest)
		if err != nil {
			return nil, err
		}
		var d Deployment
		if err = json.Unmarshal(b, &d); err != nil {
			return nil, err
		}
		client, err := RecordedClient(ctx, o.Endpoint, v.recorder)
		if err != nil {
			return nil, err
		}
		if err = ValidateDeployment(ctx, client, &d); err != nil {
			client.Close()
			return nil, err
		}
		contractABI, err := parseDeploymentABI(&d)
		if err != nil {
			client.Close()
			return nil, err
		}
		r = &Registry{Client: client, Deployment: &d, ABI: contractABI, Dir: o.Dir}
		summary.DeploymentID = d.DeploymentID
		if err = writeJSON(filepath.Join(runDir, "deployment.json"), &d); err != nil {
			return nil, err
		}
		materials, err := v.materials(m)
		return map[string]any{"instance": m, "materials": materials}, err
	})
	if runErr != nil {
		return summary, runErr
	}
	defer r.Client.Close()
	runErr = v.check("seed", func() (any, error) {
		seed, err := Seed(ctx, r)
		if err != nil {
			return seed, err
		}
		return seed, nil
	})
	if runErr != nil {
		return summary, runErr
	}
	runErr = v.check("network-baseline", func() (any, error) { return v.networkBaseline(ctx, r) })
	if runErr != nil {
		return summary, runErr
	}
	runErr = v.check("unit-and-integration-tests", func() (any, error) { return v.testSuite(ctx) })
	if runErr != nil {
		return summary, runErr
	}
	runErr = v.check("unpermitted-node", func() (any, error) { return v.unpermittedNode(ctx, r) })
	if runErr != nil {
		return summary, runErr
	}
	f, err := LoadFixtures(ctx, r)
	if err != nil {
		return summary, err
	}
	runErr = v.check("historical-and-interleaved-revocation", func() (any, error) { return v.history(ctx, r, f) })
	if runErr != nil {
		return summary, runErr
	}
	runErr = v.check("node-fault-staleness-recovery", func() (any, error) { return v.nodeFaults(ctx, r, f) })
	if runErr != nil {
		return summary, runErr
	}
	return summary, nil
}

func writeJSONL(path string, values []RPCSample) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	e := json.NewEncoder(f)
	for _, value := range values {
		if err = e.Encode(value); err != nil {
			return err
		}
	}
	return nil
}

func (v *verificationRun) materials(m *Instance) (map[string]string, error) {
	files := map[string]string{"go.mod": filepath.Join(v.options.ProjectRoot, "go.mod"), "go.sum": filepath.Join(v.options.ProjectRoot, "go.sum"), "AuthRegistry.sol": filepath.Join(v.options.ProjectRoot, "contracts/AuthRegistry.sol"), "compiler-input.json": filepath.Join(v.options.ProjectRoot, "contracts/compiler-input.json"), "compiler-lock.json": filepath.Join(v.options.ProjectRoot, "contracts/compiler-lock.json"), "compose.yaml": v.options.ComposeFile, "node.toml": filepath.Join(v.options.ProjectRoot, "infra/besu/node.toml"), "genesis.json": filepath.Join(v.options.Dir, "genesis.json"), "permissions_config.toml": filepath.Join(v.options.Dir, "nodes/C/permissions_config.toml"), "static-nodes.json": filepath.Join(v.options.Dir, "static-nodes.json")}
	dir := filepath.Join(v.summary.Directory, "materials")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	hashes := map[string]string{}
	for name, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(b)
		hashes[name] = hex.EncodeToString(h[:])
		if err = os.WriteFile(filepath.Join(dir, name), b, 0644); err != nil {
			return nil, err
		}
	}
	if err := writeJSON(filepath.Join(dir, "instance-public.json"), m); err != nil {
		return nil, err
	}
	return hashes, nil
}

func (v *verificationRun) testSuite(ctx context.Context) (any, error) {
	dir := filepath.Join(v.summary.Directory, "test-cases")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	output, err := os.Create(filepath.Join(v.summary.Directory, "go-tests.jsonl"))
	if err != nil {
		return nil, err
	}
	defer output.Close()
	stderr, err := os.Create(filepath.Join(v.summary.Directory, "go-tests.stderr"))
	if err != nil {
		return nil, err
	}
	defer stderr.Close()
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-json", "./...")
	cmd.Dir = v.options.ProjectRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "LEDGER_INSTANCE="+v.options.Dir, "LEDGER_MANIFEST="+v.options.Manifest, "LEDGER_DEPLOYMENT="+v.options.Manifest, "LEDGER_EVIDENCE="+dir)
	cmd.Stdout, cmd.Stderr = output, stderr
	runErr := cmd.Run()
	output.Close()
	f, err := os.Open(filepath.Join(v.summary.Directory, "go-tests.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 16<<20)
	passed := map[string]bool{}
	for scanner.Scan() {
		var event struct{ Action, Test string }
		if json.Unmarshal(scanner.Bytes(), &event) == nil && event.Action == "pass" {
			passed[event.Test] = true
		}
	}
	if err = scanner.Err(); err != nil {
		return passed, err
	}
	required := []string{"TestDeploymentBindingIntegration", "TestRootMutationIntegration", "TestAccountPermissioningIntegration", "TestDomainRegistrationIntegration", "TestIdentityRegistrationIntegration", "TestRPRegistrationIntegration", "TestGrantStructureIntegration", "TestRevocationIntegration", "TestOriginalTransactionTraceIntegration", "TestTraceFailureRecoveryIntegration", "TestRevisionCompetitionIntegration", "TestBlockTraceFallbackFaultsIntegration", "TestStateAssemblyFailuresIntegration", "TestHighestHeadRecoveryIntegration", "TestPendingTransactionRecovery", "TestFreshnessWallBoundaries", "TestMonotonicBudgetNotRenewed", "TestClockRollbackAndRevalidation", "TestFutureBlockBudgetAndStaleRestart"}
	missing := []string{}
	for _, name := range required {
		if !passed[name] {
			missing = append(missing, name)
		}
	}
	data := map[string]any{"passedTests": passed, "required": required, "missingPasses": missing, "stdout": "go-tests.jsonl", "stderr": "go-tests.stderr", "cases": "test-cases/"}
	if runErr != nil {
		return data, fmt.Errorf("Go verification tests failed: %w", runErr)
	}
	if len(missing) > 0 {
		return data, fmt.Errorf("required tests missing passes: %s", strings.Join(missing, ", "))
	}
	return data, nil
}

func (v *verificationRun) compose(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"compose", "-p", v.options.ComposeProject, "-f", v.options.ComposeFile}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	cmd.Env = append(os.Environ(), "BESU_INSTANCE="+v.options.Dir, "BESU_UID="+strconv.Itoa(os.Getuid()), "BESU_GID="+strconv.Itoa(os.Getgid()))
	b, err := cmd.CombinedOutput()
	return string(b), err
}
