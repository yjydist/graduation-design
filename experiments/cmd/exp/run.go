package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"grad/experiments/harness"
)

const (
	DriverTypeRealLLMMCP         = "real-llm-mcp"
	DriverTypeDeterministicTools = "deterministic-wallet-tools"

	e1DriverDir = "experiments/e1/driver"
	e6DriverDir = "experiments/e6/driver"
)

type PlannedItem struct {
	ID   string `json:"id"`
	Mode string `json:"mode,omitempty"`
	Kind string `json:"kind,omitempty"`
}

type RunPlan struct {
	Experiment         string         `json:"experiment"`
	DriverType         string         `json:"driverType"`
	Configuration      string         `json:"configuration"`
	AuthorizationModes []string       `json:"authorizationModes"`
	Seed               *int           `json:"seed,omitempty"`
	Items              []PlannedItem  `json:"items"`
	Sampling           map[string]any `json:"sampling,omitempty"`
}

type SourceSnapshotInfo struct {
	WorkspaceCommit string   `json:"workspaceCommit"`
	WorkspaceDirty  bool     `json:"workspaceDirty"`
	ArchiveFile     string   `json:"archiveFile"`
	ArchiveSHA256   string   `json:"archiveSha256"`
	IncludedFiles   []string `json:"includedFiles"`
}

type MissingItem struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type SecretScanResult struct {
	Passed   bool     `json:"passed"`
	Files    int      `json:"files"`
	Findings []string `json:"findings,omitempty"`
}

type RunSummary struct {
	RunID             string            `json:"runId"`
	Experiment        string            `json:"experiment"`
	Status            string            `json:"status"`
	Stage             string            `json:"stage"`
	Aborted           bool              `json:"aborted,omitempty"`
	DeploymentID      string            `json:"deploymentId,omitempty"`
	StartedAt         time.Time         `json:"startedAt"`
	FinishedAt        *time.Time        `json:"finishedAt,omitempty"`
	ExitCode          int               `json:"exitCode"`
	Diagnostic        string            `json:"diagnostic,omitempty"`
	Error             string            `json:"error,omitempty"`
	PlannedCount      int               `json:"plannedCount"`
	ExecutedCount     int               `json:"executedCount"`
	MissingCount      int               `json:"missingCount"`
	MissingItems      []MissingItem     `json:"missingItems,omitempty"`
	SecretScan        *SecretScanResult `json:"secretScan,omitempty"`
	Cases             []any             `json:"cases,omitempty"`
	Revocation        any               `json:"revocation,omitempty"`
	Instances         any               `json:"instances,omitempty"`
	RequestAccounting any               `json:"requestAccounting,omitempty"`
	Mode              string            `json:"mode,omitempty"`
	ModeShort         string            `json:"modeShort,omitempty"`
	Configuration     string            `json:"configuration,omitempty"`
	ClockTimebase     string            `json:"clockTimebase,omitempty"`
	ClockResolutionNs *int64            `json:"clockResolutionNs,omitempty"`
}

type RunOptions struct {
	Experiment     string
	Revision       string
	InstanceDir    string
	BasePort       int
	OutRoot        string
	RunID          string
	Seed           int
	Mode           string
	Configuration  string
	ProbeInterval  time.Duration
	ProbeLifetime  time.Duration
	DetectInterval time.Duration
	Duration       time.Duration
	RevokeAfter    time.Duration
	Instances      int
	PlanOnly       bool
	WorkspaceSUT   bool
}

type RunResult struct {
	RunID   string
	RunDir  string
	Summary RunSummary
}

type CommandFunc func(ctx context.Context, dir string, env []string, logPath string, name string, args ...string) error

type RunnerDeps struct {
	RepoRoot       string
	RunCmd         CommandFunc
	GitResolve     func(ctx context.Context, repoRoot, rev string) (string, error)
	GitWorkspace   func(ctx context.Context, repoRoot string) (commit string, dirty bool, err error)
	ArchiveCommit  func(ctx context.Context, repoRoot, commit, destDir string) error
	ExecuteE1      func(ctx context.Context, rc *runContext) error
	ExecuteE6      func(ctx context.Context, rc *runContext) error
	TeardownFabric func(ctx context.Context, workDir, instanceDir, logPath string) error
	LookupEnv      func(string) (string, bool)
}

type runContext struct {
	opts            RunOptions
	deps            RunnerDeps
	repoRoot        string
	runID           string
	runDir          string
	workDir         string
	instanceDir     string
	sourceCommit    string
	workspaceCommit string
	workspaceDirty  bool
	plan            RunPlan
	startedAt       time.Time
	stage           string
	secrets         []string
	llmConfig       map[string]any
}

func defaultRunnerDeps() RunnerDeps {
	return RunnerDeps{
		RunCmd:         execCommandLogged,
		GitResolve:     gitResolveCommit,
		GitWorkspace:   gitWorkspaceState,
		ArchiveCommit:  harness.ExportGitWorktree,
		ExecuteE1:      executeE1Run,
		ExecuteE6:      executeE6Run,
		TeardownFabric: teardownFabricNetwork,
		LookupEnv:      os.LookupEnv,
	}
}

func ExecuteRun(ctx context.Context, opts RunOptions, deps RunnerDeps) (*RunResult, error) {
	if deps.RunCmd == nil {
		deps.RunCmd = execCommandLogged
	}
	if deps.GitResolve == nil {
		deps.GitResolve = gitResolveCommit
	}
	if deps.GitWorkspace == nil {
		deps.GitWorkspace = gitWorkspaceState
	}
	if deps.ArchiveCommit == nil {
		deps.ArchiveCommit = harness.ExportGitWorktree
	}
	if deps.ExecuteE1 == nil {
		deps.ExecuteE1 = executeE1Run
	}
	if deps.ExecuteE6 == nil {
		deps.ExecuteE6 = executeE6Run
	}
	if deps.TeardownFabric == nil {
		deps.TeardownFabric = teardownFabricNetwork
	}
	if deps.LookupEnv == nil {
		deps.LookupEnv = os.LookupEnv
	}

	exp := strings.ToUpper(strings.TrimSpace(opts.Experiment))
	if exp != "E1" && exp != "E6" {
		return nil, fmt.Errorf("experiment must be E1 or E6, got %q", opts.Experiment)
	}
	opts.Experiment = exp
	if opts.WorkspaceSUT && opts.Revision != "" && opts.Revision != "HEAD" {
		return nil, fmt.Errorf("--workspace-sut cannot be combined with explicit --revision %q", opts.Revision)
	}
	if opts.Revision == "" {
		opts.Revision = "HEAD"
	}

	repoRoot := deps.RepoRoot
	if repoRoot == "" {
		var err error
		repoRoot, err = harness.RepoRoot()
		if err != nil {
			return nil, fmt.Errorf("locate repository root: %w", err)
		}
	}
	if opts.BasePort < 1024 || opts.BasePort > 60000 {
		return nil, fmt.Errorf("base port must be between 1024 and 60000, got %d", opts.BasePort)
	}
	instanceDir, err := harness.ValidateIsolatedInstance(repoRoot, opts.InstanceDir, true)
	if err != nil {
		return nil, err
	}

	sourceCommit, err := deps.GitResolve(ctx, repoRoot, opts.Revision)
	if err != nil {
		return nil, fmt.Errorf("resolve revision %q: %w", opts.Revision, err)
	}
	wsCommit, wsDirty, err := deps.GitWorkspace(ctx, repoRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect workspace git state: %w", err)
	}

	rc := &runContext{
		opts:            opts,
		deps:            deps,
		repoRoot:        repoRoot,
		instanceDir:     instanceDir,
		sourceCommit:    sourceCommit,
		workspaceCommit: wsCommit,
		workspaceDirty:  wsDirty,
		startedAt:       time.Now().UTC(),
		stage:           "plan",
	}

	var snapshotPatterns []string
	var extraManifest map[string]any
	var defaultOutRoot string
	switch exp {
	case "E1":
		defaultOutRoot = filepath.Join(repoRoot, "experiments", "e1", "runs")
		plan, llmMeta, apiKey, patterns, err := prepareE1Plan(rc)
		if err != nil {
			return nil, err
		}
		rc.plan = plan
		rc.llmConfig = llmMeta
		if apiKey != "" {
			rc.secrets = append(rc.secrets, apiKey)
		}
		extraManifest = map[string]any{"llm": llmMeta}
		snapshotPatterns = patterns
	case "E6":
		defaultOutRoot = filepath.Join(repoRoot, "experiments", "e6", "runs")
		plan, patterns, err := prepareE6Plan(rc)
		if err != nil {
			return nil, err
		}
		rc.plan = plan
		snapshotPatterns = patterns
	}

	outRoot := opts.OutRoot
	if outRoot == "" {
		outRoot = defaultOutRoot
	} else if !filepath.IsAbs(outRoot) {
		outRoot = filepath.Join(repoRoot, outRoot)
	}

	runID := strings.TrimSpace(opts.RunID)
	if runID == "" {
		runID, err = harness.NewRunID()
		if err != nil {
			return nil, err
		}
	}
	runDir, err := harness.CreateRunDir(outRoot, runID)
	if err != nil {
		return nil, err
	}
	rc.runID = runID
	rc.runDir = runDir

	archivePath := filepath.Join(rc.runDir, "driver-source.tar.gz")
	archiveHash, err := harness.BuildSourceSnapshot(repoRoot, archivePath, snapshotPatterns)
	if err != nil {
		return nil, fmt.Errorf("create source snapshot: %w", err)
	}
	includedFiles, fileHashes, err := inspectTarGzHashes(archivePath)
	if err != nil {
		return nil, fmt.Errorf("inspect source snapshot: %w", err)
	}
	snapInfo := &SourceSnapshotInfo{
		WorkspaceCommit: wsCommit,
		WorkspaceDirty:  wsDirty,
		ArchiveFile:     filepath.Base(archivePath),
		ArchiveSHA256:   archiveHash,
		IncludedFiles:   includedFiles,
	}

	manifestPath := filepath.Join(rc.runDir, "manifest.json")
	initManifest := buildInitialManifest(runID, rc.startedAt, rc.plan, sourceCommit, snapInfo, fileHashes, instanceDir, opts.BasePort, extraManifest)
	if err := harness.WriteJSON(manifestPath, initManifest); err != nil {
		return nil, err
	}

	summaryPath := filepath.Join(rc.runDir, "summary.json")
	initMissing := missingItemsFromPlan(rc.plan, "run initialized; execution not started")
	summary := RunSummary{
		RunID:        runID,
		Experiment:   exp,
		Status:       "INCOMPLETE",
		Stage:        "plan",
		StartedAt:    rc.startedAt,
		PlannedCount: len(rc.plan.Items),
		MissingCount: len(initMissing),
		MissingItems: initMissing,
	}
	if err := harness.WriteJSON(summaryPath, summary); err != nil {
		return nil, err
	}

	if opts.PlanOnly {
		now := time.Now().UTC()
		summary.FinishedAt = &now
		summary.Status = "PLANNED"
		_ = harness.WriteJSON(summaryPath, summary)
		return &RunResult{RunID: runID, RunDir: rc.runDir, Summary: summary}, nil
	}

	if err := os.MkdirAll(filepath.Join(repoRoot, ".local"), 0o755); err != nil {
		return nil, err
	}
	workDir, err := os.MkdirTemp(filepath.Join(repoRoot, ".local"), strings.ToLower(exp)+"-build.")
	if err != nil {
		return nil, err
	}
	rc.workDir = workDir

	var runErr error
	defer func() {
		if _, statErr := os.Stat(filepath.Join(rc.instanceDir, "network.env")); statErr == nil {
			downCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			_ = deps.TeardownFabric(downCtx, rc.workDir, rc.instanceDir, filepath.Join(rc.runDir, "network-down.log"))
			cancel()
		}
	}()

	switch exp {
	case "E1":
		runErr = deps.ExecuteE1(ctx, rc)
	case "E6":
		runErr = deps.ExecuteE6(ctx, rc)
	}

	finalSummary, finalizeErr := rc.finalize(ctx, runErr)
	runErr = errors.Join(runErr, finalizeErr)
	return &RunResult{RunID: runID, RunDir: rc.runDir, Summary: finalSummary}, runErr
}

func prepareFixedBuild(ctx context.Context, rc *runContext, driverDir string) error {
	if err := rc.deps.ArchiveCommit(ctx, rc.repoRoot, rc.sourceCommit, rc.workDir); err != nil {
		return fmt.Errorf("export commit %s: %w", rc.sourceCommit, err)
	}

	// Replace any driver from the exported project with the exact driver recorded for this run.
	driverDst := filepath.Join(rc.workDir, filepath.FromSlash(driverDir))
	if err := os.RemoveAll(driverDst); err != nil {
		return err
	}
	if err := os.MkdirAll(driverDst, 0o755); err != nil {
		return err
	}
	snapshot, err := os.Open(filepath.Join(rc.runDir, "driver-source.tar.gz"))
	if err != nil {
		return err
	}
	defer snapshot.Close()
	gz, err := gzip.NewReader(snapshot)
	if err != nil {
		return err
	}
	defer gz.Close()
	entries := tar.NewReader(gz)
	count := 0
	for {
		entry, err := entries.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if entry.Typeflag != tar.TypeReg || path.Dir(entry.Name) != driverDir || path.Ext(entry.Name) != ".go" {
			continue
		}
		raw, err := io.ReadAll(entries)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(driverDst, path.Base(entry.Name)), raw, 0o644); err != nil {
			return err
		}
		count++
	}
	if count == 0 {
		return fmt.Errorf("driver source snapshot contains no Go files under %s", driverDir)
	}

	localTools := filepath.Join(rc.repoRoot, ".local", "fabric-tools")
	if info, err := os.Stat(localTools); err == nil && info.IsDir() {
		_ = os.MkdirAll(filepath.Join(rc.workDir, ".local"), 0o755)
		_ = os.Symlink(localTools, filepath.Join(rc.workDir, ".local", "fabric-tools"))
	}
	return nil
}

func prepareE1Plan(rc *runContext) (RunPlan, map[string]any, string, []string, error) {
	llmEnvPath := filepath.Join(rc.repoRoot, "experiments", "llm.env")
	fileEnv, err := harness.ParseEnvFile(llmEnvPath)
	if err != nil {
		return RunPlan{}, nil, "", nil, fmt.Errorf("load experiments/llm.env: %w", err)
	}
	resolve := func(key string) string {
		if v, ok := rc.deps.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return strings.TrimSpace(fileEnv[key])
	}
	provider := resolve("LLM_PROVIDER")
	baseURL := resolve("LLM_BASE_URL")
	model := resolve("LLM_MODEL")
	apiKey, _ := rc.deps.LookupEnv("LLM_API_KEY")
	apiKey = strings.TrimSpace(apiKey)

	if provider == "" || baseURL == "" || model == "" {
		return RunPlan{}, nil, "", nil, fmt.Errorf("LLM_PROVIDER, LLM_BASE_URL and LLM_MODEL must be set in experiments/llm.env")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return RunPlan{}, nil, "", nil, fmt.Errorf("LLM_BASE_URL must be an HTTP(S) endpoint without credentials, query parameters or fragment")
	}
	effectiveURL := baseURL
	if provider == "openai" && (parsed.Path == "" || parsed.Path == "/") {
		cp := *parsed
		cp.Path = "/v1"
		effectiveURL = cp.String()
	}
	if !rc.opts.PlanOnly && apiKey == "" {
		return RunPlan{}, nil, "", nil, fmt.Errorf("LLM_API_KEY must be exported in environment before running E1")
	}

	items := make([]PlannedItem, 0, 16)
	for i := 1; i <= 16; i++ {
		items = append(items, PlannedItem{ID: fmt.Sprintf("F%02d", i), Kind: "functional-case"})
	}
	plan := RunPlan{
		Experiment:         "E1",
		DriverType:         DriverTypeRealLLMMCP,
		Configuration:      "B0 (Fabric fixed-height, static signature cache disabled; real lease via ledgerctl check)",
		AuthorizationModes: []string{"RESOURCE_PREAUTHORIZED", "BUYER_MANDATE"},
		Items:              items,
		Sampling: map[string]any{
			"cases":              "F01-F16",
			"llmDriverCases":     []string{"F05", "F06", "F07", "F15"},
			"deterministicCases": []string{"F01", "F02", "F03", "F04", "F08", "F09", "F10", "F11", "F12", "F13", "F14", "F16"},
		},
	}
	if rc.opts.Seed != 0 {
		seed := rc.opts.Seed
		plan.Seed = &seed
	}
	llmMeta := map[string]any{
		"provider":          provider,
		"requestedModel":    model,
		"configuredBaseURL": baseURL,
		"baseURL":           effectiveURL,
		"apiKeySource":      "env:LLM_API_KEY",
	}
	patterns := []string{
		"go.work",
		"mise.toml",
		"infra/fabric/compose.yaml",
		"experiments/go.mod",
		"experiments/go.sum",
		"experiments/mise.toml",
		"experiments/e1/run.sh",
		"experiments/harness/*.go",
		"experiments/cmd/exp/*.go",
		e1DriverDir + "/*.go",
		"experiments/实验计划.md",
		"experiments/验证用例.md",
		"experiments/e1/method.md",
	}
	return plan, llmMeta, apiKey, patterns, nil
}

func executeE1Run(ctx context.Context, rc *runContext) error {
	manifestPath := filepath.Join(rc.runDir, "manifest.json")

	rc.stage = "build"
	buildDir := rc.workDir
	sutSource := "git-archive"
	if rc.opts.WorkspaceSUT {
		buildDir = rc.repoRoot
		sutSource = "workspace"
	} else if err := prepareFixedBuild(ctx, rc, e1DriverDir); err != nil {
		return err
	}

	buildStart := time.Now()
	buildLog := filepath.Join(rc.runDir, "build.log")
	ledgerctlBin := filepath.Join(rc.workDir, "ledgerctl")
	driverBin := filepath.Join(rc.workDir, "e1-driver")
	if err := rc.deps.RunCmd(ctx, filepath.Join(buildDir, "platform"), nil, buildLog, "go", "build", "-o", ledgerctlBin, "./cmd/ledgerctl"); err != nil {
		return fmt.Errorf("build ledgerctl: %w", err)
	}
	if err := rc.deps.RunCmd(ctx, filepath.Join(buildDir, "experiments"), nil, buildLog, "go", "build", "-o", driverBin, "./e1/driver"); err != nil {
		return fmt.Errorf("build e1-driver: %w", err)
	}

	binaries := map[string]string{}
	for name, binPath := range map[string]string{"ledgerctl": ledgerctlBin, "driver": driverBin} {
		sum, err := harness.SHA256File(binPath)
		if err != nil {
			return fmt.Errorf("hash binary %s: %w", name, err)
		}
		binaries[name] = sum
	}
	if err := harness.MergeJSON(manifestPath, map[string]any{
		"stage":           "build",
		"sutSource":       sutSource,
		"binarySHA256":    binaries,
		"buildDurationMs": time.Since(buildStart).Milliseconds(),
	}); err != nil {
		return err
	}

	rc.stage = "network"
	netLog := filepath.Join(rc.runDir, "network-up.log")
	if err := rc.deps.RunCmd(ctx, buildDir, nil, netLog, "sh", "infra/fabric/network.sh", "rebuild", rc.instanceDir, strconv.Itoa(rc.opts.BasePort)); err != nil {
		return fmt.Errorf("prepare isolated Fabric network: %w", err)
	}
	netMeta := readPublicNetworkEnv(filepath.Join(rc.instanceDir, "network.env"))
	if err := harness.MergeJSON(manifestPath, map[string]any{
		"stage":      "network",
		"networkEnv": netMeta,
	}); err != nil {
		return err
	}

	rc.stage = "execution"
	env := append(os.Environ(),
		"LLM_PROVIDER="+fmt.Sprint(rc.llmConfig["provider"]),
		"LLM_BASE_URL="+fmt.Sprint(rc.llmConfig["configuredBaseURL"]),
		"LLM_MODEL="+fmt.Sprint(rc.llmConfig["requestedModel"]),
	)
	if err := rc.deps.RunCmd(ctx, buildDir, env, filepath.Join(rc.runDir, "driver.log"), driverBin,
		"-revision", rc.sourceCommit,
		"-ledgerctl", ledgerctlBin,
		"-dir", rc.instanceDir,
		"-out", rc.runDir,
	); err != nil {
		return fmt.Errorf("execute E1 driver: %w", err)
	}
	return nil
}

func prepareE6Plan(rc *runContext) (RunPlan, []string, error) {
	mode := strings.ToUpper(strings.TrimSpace(rc.opts.Mode))
	if mode != "RP" && mode != "BM" {
		return RunPlan{}, nil, fmt.Errorf("E6 requires --mode RP or BM, got %q", rc.opts.Mode)
	}
	rc.opts.Mode = mode
	authMode := "RESOURCE_PREAUTHORIZED"
	if mode == "BM" {
		authMode = "BUYER_MANDATE"
	}
	if strings.TrimSpace(rc.opts.Configuration) == "" {
		rc.opts.Configuration = "B0"
	}
	if rc.opts.ProbeInterval <= 0 {
		rc.opts.ProbeInterval = time.Second
	}
	if rc.opts.ProbeLifetime <= 0 {
		rc.opts.ProbeLifetime = 5 * time.Second
	}
	if rc.opts.DetectInterval <= 0 {
		rc.opts.DetectInterval = 20 * time.Millisecond
	}
	if rc.opts.Duration <= 0 {
		rc.opts.Duration = 12 * time.Second
	}
	if rc.opts.RevokeAfter <= 0 {
		rc.opts.RevokeAfter = time.Second
	}
	if rc.opts.Instances <= 0 {
		rc.opts.Instances = 2
	}

	items := []PlannedItem{
		{ID: "warmup-order", Mode: authMode, Kind: "positive"},
		{ID: "revoke-G1", Mode: authMode, Kind: "revocation"},
		{ID: "post-revocation-window", Mode: authMode, Kind: "probing"},
	}
	plan := RunPlan{
		Experiment:         "E6",
		DriverType:         DriverTypeDeterministicTools,
		Configuration:      rc.opts.Configuration,
		AuthorizationModes: []string{authMode},
		Items:              items,
		Sampling: map[string]any{
			"modeShort":        mode,
			"revocationTarget": "G1",
			"gatewayInstances": rc.opts.Instances,
			"probeIntervalMs":  rc.opts.ProbeInterval.Milliseconds(),
			"probeLifetimeMs":  rc.opts.ProbeLifetime.Milliseconds(),
			"detectIntervalMs": rc.opts.DetectInterval.Milliseconds(),
			"revokeAfterMs":    rc.opts.RevokeAfter.Milliseconds(),
			"postRevokeDurMs":  rc.opts.Duration.Milliseconds(),
			"delegationDepth":  2,
			"descendantCount":  1,
			"clockTimebase":    "host-utc-unix-ns",
		},
	}
	if rc.opts.Seed != 0 {
		seed := rc.opts.Seed
		plan.Seed = &seed
	}
	patterns := []string{
		"go.work",
		"mise.toml",
		"infra/fabric/compose.yaml",
		"experiments/go.mod",
		"experiments/go.sum",
		"experiments/mise.toml",
		"experiments/harness/*.go",
		"experiments/cmd/exp/*.go",
		e6DriverDir + "/*.go",
		"experiments/实验计划.md",
		"experiments/e6/method.md",
	}
	return plan, patterns, nil
}

func executeE6Run(ctx context.Context, rc *runContext) error {
	manifestPath := filepath.Join(rc.runDir, "manifest.json")

	rc.stage = "build"
	buildDir := rc.workDir
	sutSource := "git-archive"
	if rc.opts.WorkspaceSUT {
		buildDir = rc.repoRoot
		sutSource = "workspace"
	} else if err := prepareFixedBuild(ctx, rc, e6DriverDir); err != nil {
		return err
	}

	buildStart := time.Now()
	buildLog := filepath.Join(rc.runDir, "build.log")
	driverBin := filepath.Join(rc.workDir, "e6-driver")
	if err := rc.deps.RunCmd(ctx, filepath.Join(buildDir, "experiments"), nil, buildLog, "go", "build", "-o", driverBin, "./e6/driver"); err != nil {
		return fmt.Errorf("build e6-driver: %w", err)
	}
	driverHash, err := harness.SHA256File(driverBin)
	if err != nil {
		return fmt.Errorf("hash e6-driver: %w", err)
	}
	if err := harness.MergeJSON(manifestPath, map[string]any{
		"stage":           "build",
		"sutSource":       sutSource,
		"binarySHA256":    map[string]string{"driver": driverHash},
		"buildDurationMs": time.Since(buildStart).Milliseconds(),
	}); err != nil {
		return err
	}

	rc.stage = "network"
	netLog := filepath.Join(rc.runDir, "network-up.log")
	if err := rc.deps.RunCmd(ctx, buildDir, nil, netLog, "sh", "infra/fabric/network.sh", "rebuild", rc.instanceDir, strconv.Itoa(rc.opts.BasePort)); err != nil {
		return fmt.Errorf("prepare isolated Fabric network: %w", err)
	}
	netMeta := readPublicNetworkEnv(filepath.Join(rc.instanceDir, "network.env"))
	if err := harness.MergeJSON(manifestPath, map[string]any{
		"stage":      "network",
		"networkEnv": netMeta,
	}); err != nil {
		return err
	}

	rc.stage = "execution"
	args := []string{
		"-revision", rc.sourceCommit,
		"-dir", rc.instanceDir,
		"-out", rc.runDir,
		"-mode", rc.opts.Mode,
		"-configuration", rc.opts.Configuration,
		"-probe-interval", rc.opts.ProbeInterval.String(),
		"-probe-lifetime", rc.opts.ProbeLifetime.String(),
		"-detect-interval", rc.opts.DetectInterval.String(),
		"-revoke-after", rc.opts.RevokeAfter.String(),
		"-duration", rc.opts.Duration.String(),
		"-instances", strconv.Itoa(rc.opts.Instances),
	}
	if rc.opts.Seed != 0 {
		args = append(args, "-seed", strconv.Itoa(rc.opts.Seed))
	}
	if err := rc.deps.RunCmd(ctx, buildDir, nil, filepath.Join(rc.runDir, "driver.log"), driverBin, args...); err != nil {
		return fmt.Errorf("execute E6 driver: %w", err)
	}
	return nil
}

func (rc *runContext) finalize(ctx context.Context, runErr error) (RunSummary, error) {
	now := time.Now().UTC()
	aborted := ctx.Err() != nil || errors.Is(runErr, context.Canceled)
	summaryPath := filepath.Join(rc.runDir, "summary.json")
	manifestPath := filepath.Join(rc.runDir, "manifest.json")

	var existing map[string]any
	_ = harness.ReadJSON(summaryPath, &existing)

	summary := RunSummary{
		RunID:        rc.runID,
		Experiment:   rc.opts.Experiment,
		Stage:        rc.stage,
		Aborted:      aborted,
		StartedAt:    rc.startedAt,
		FinishedAt:   &now,
		PlannedCount: len(rc.plan.Items),
	}

	if dep, ok := existing["deploymentId"].(string); ok && dep != "" {
		summary.DeploymentID = dep
	}
	if v, ok := existing["revocation"]; ok && v != nil {
		summary.Revocation = v
	}
	if v, ok := existing["instances"]; ok && v != nil {
		summary.Instances = v
	}
	if v, ok := existing["requestAccounting"]; ok && v != nil {
		summary.RequestAccounting = v
	}
	if v, ok := existing["mode"].(string); ok && v != "" {
		summary.Mode = v
	}
	if v, ok := existing["modeShort"].(string); ok && v != "" {
		summary.ModeShort = v
	}
	if v, ok := existing["configuration"].(string); ok && v != "" {
		summary.Configuration = v
	}
	if v, ok := existing["clockTimebase"].(string); ok && v != "" {
		summary.ClockTimebase = v
	}
	if v, ok := existing["clockResolutionNs"].(float64); ok && v > 0 {
		n := int64(v)
		summary.ClockResolutionNs = &n
	}
	if casesRaw, ok := existing["cases"].([]any); ok && len(casesRaw) > 0 {
		summary.Cases = casesRaw
		executed := 0
		seenIDs := map[string]bool{}
		for _, item := range casesRaw {
			if m, ok := item.(map[string]any); ok {
				name, _ := m["name"].(string)
				if name != "" {
					seenIDs[name] = true
				}
				statusStr, _ := m["status"].(string)
				if statusStr == "not_executed" {
					reason, _ := m["missingReason"].(string)
					if reason == "" {
						reason, _ = m["error"].(string)
					}
					if reason == "" {
						reason = fmt.Sprintf("not executed during %s", rc.stage)
					}
					summary.MissingItems = append(summary.MissingItems, MissingItem{
						ID:     name,
						Status: "not_executed",
						Reason: harness.RedactSecrets(reason, rc.secrets...),
					})
				} else {
					executed++
				}
			}
		}
		summary.ExecutedCount = executed
		if runErr != nil || aborted {
			reason := fmt.Sprintf("not executed due to %s failure", rc.stage)
			if aborted {
				reason = fmt.Sprintf("aborted during %s", rc.stage)
			}
			for _, p := range rc.plan.Items {
				if !seenIDs[p.ID] {
					summary.MissingItems = append(summary.MissingItems, MissingItem{
						ID:     p.ID,
						Status: "not_executed",
						Reason: reason,
					})
				}
			}
		}
	} else if runErr != nil || aborted {
		reason := fmt.Sprintf("not executed: failed during %s", rc.stage)
		if aborted {
			reason = fmt.Sprintf("not executed: aborted during %s", rc.stage)
		}
		summary.MissingItems = missingItemsFromPlan(rc.plan, reason)
	} else {
		summary.ExecutedCount = len(rc.plan.Items)
	}
	summary.MissingCount = len(summary.MissingItems)

	if runErr == nil && !aborted {
		summary.Status = "PASS"
		summary.ExitCode = 0
		summary.Stage = "finalize"
	} else if aborted {
		summary.Status = "ABORTED"
		summary.ExitCode = 130
		if runErr != nil {
			summary.Diagnostic = harness.RedactSecrets(runErr.Error(), rc.secrets...)
			summary.Error = summary.Diagnostic
		} else {
			summary.Diagnostic = fmt.Sprintf("run aborted during stage %s", rc.stage)
			summary.Error = summary.Diagnostic
		}
	} else {
		summary.Status = "FAIL"
		summary.ExitCode = 1
		summary.Diagnostic = harness.RedactSecrets(runErr.Error(), rc.secrets...)
		summary.Error = summary.Diagnostic
	}

	if err := harness.WriteJSON(summaryPath, summary); err != nil {
		return summary, err
	}
	if err := harness.MergeJSON(manifestPath, map[string]any{
		"status":     summary.Status,
		"stage":      summary.Stage,
		"finishedAt": now.Format(time.RFC3339Nano),
	}); err != nil {
		return summary, err
	}

	scan := scanRunExports(rc.runDir, rc.instanceDir, rc.secrets)
	summary.SecretScan = &scan
	var scanErr error
	if !scan.Passed {
		summary.Status = "FAIL"
		if summary.ExitCode == 0 {
			summary.ExitCode = 1
		}
		scanErr = fmt.Errorf("sensitive field check failed: %s", strings.Join(scan.Findings, "; "))
		if summary.Diagnostic == "" {
			summary.Diagnostic = scanErr.Error()
		} else {
			summary.Diagnostic = summary.Diagnostic + "; " + scanErr.Error()
		}
		summary.Error = summary.Diagnostic
	}
	if err := harness.WriteJSON(summaryPath, summary); err != nil {
		return summary, errors.Join(scanErr, err)
	}
	mErr := harness.MergeJSON(manifestPath, map[string]any{
		"status":     summary.Status,
		"secretScan": scan,
	})
	return summary, errors.Join(scanErr, mErr)
}

func scanRunExports(runDir, instanceDir string, extraSecrets []string) SecretScanResult {
	secrets := make([]string, 0, len(extraSecrets))
	secrets = append(secrets, extraSecrets...)
	secrets = append(secrets, harness.CollectInstanceSecrets(instanceDir)...)

	findings, err := harness.ScanExports(runDir, secrets...)
	files := countScannedFiles(runDir)
	res := SecretScanResult{
		Passed: err == nil && len(findings) == 0,
		Files:  files,
	}
	if err != nil {
		res.Findings = append(res.Findings, err.Error())
	}
	for _, f := range findings {
		res.Findings = append(res.Findings, f.String())
	}
	return res
}

func countScannedFiles(root string) int {
	count := 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(d.Name())) {
		case ".pb", ".gz", ".png", ".pdf", ".tar", ".zip":
			return nil
		default:
			count++
			return nil
		}
	})
	return count
}

func inspectTarGzHashes(archivePath string) ([]string, map[string]string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var files []string
	hashes := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, hdr.Name)
		hashes[hdr.Name] = harness.SHA256Bytes(raw)
	}
	slices.Sort(files)
	return files, hashes, nil
}

func buildInitialManifest(runID string, startedAt time.Time, plan RunPlan, sourceCommit string, snap *SourceSnapshotInfo, fileHashes map[string]string, instanceDir string, basePort int, extra map[string]any) map[string]any {
	m := map[string]any{
		"schemaVersion":      "grad-experiment-manifest-v1",
		"experiment":         plan.Experiment,
		"runId":              runID,
		"startedAt":          startedAt.UTC().Format(time.RFC3339Nano),
		"status":             "INITIALIZED",
		"stage":              "plan",
		"sourceCommit":       sourceCommit,
		"driverType":         plan.DriverType,
		"configuration":      plan.Configuration,
		"authorizationModes": plan.AuthorizationModes,
		"plan":               plan,
		"driverSnapshot":     snap,
		"fileSHA256":         fileHashes,
		"binarySHA256":       nil,
		"instance":           instanceDir,
		"basePort":           basePort,
		"deployment":         nil,
		"policyDigest":       nil,
		"fixtureDigest":      nil,
		"host":               runtime.GOOS + "/" + runtime.GOARCH,
		"go":                 runtime.Version(),
		"clock":              "host-utc-unix-ns and per-process monotonic ns",
	}
	if plan.Seed != nil {
		m["seed"] = *plan.Seed
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func missingItemsFromPlan(plan RunPlan, reason string) []MissingItem {
	items := make([]MissingItem, 0, len(plan.Items))
	for _, item := range plan.Items {
		id := item.ID
		if item.Mode != "" {
			id = item.ID + "/" + item.Mode
		}
		items = append(items, MissingItem{
			ID:     id,
			Status: "not_executed",
			Reason: reason,
		})
	}
	return items
}

func readPublicNetworkEnv(envPath string) map[string]string {
	raw, err := harness.ParseEnvFile(envPath)
	if err != nil {
		return nil
	}
	public := map[string]string{}
	for k, v := range raw {
		upper := strings.ToUpper(k)
		if strings.Contains(upper, "PASS") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "KEY") || strings.Contains(upper, "TOKEN") {
			continue
		}
		public[k] = v
	}
	return public
}

func gitResolveCommit(ctx context.Context, repoRoot, rev string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", "-C", repoRoot, "rev-parse", "--verify", rev+"^{commit}").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func gitWorkspaceState(_ context.Context, repoRoot string) (string, bool, error) {
	return harness.GitHeadRevision(repoRoot)
}

func execCommandLogged(ctx context.Context, dir string, env []string, logPath string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = env
	}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		cmd.Stdout = f
		cmd.Stderr = f
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s %s: %w (see %s)", name, strings.Join(args, " "), err, filepath.Base(logPath))
		}
		return nil
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

func teardownFabricNetwork(ctx context.Context, workDir, instanceDir, logPath string) error {
	scriptRoot := workDir
	if _, err := os.Stat(filepath.Join(workDir, "infra", "fabric", "network.sh")); err != nil {
		root, rootErr := harness.RepoRoot()
		if rootErr != nil {
			return rootErr
		}
		scriptRoot = root
	}
	return harness.FabricNetworkCmd(ctx, scriptRoot, "down", instanceDir, 0, logPath)
}
