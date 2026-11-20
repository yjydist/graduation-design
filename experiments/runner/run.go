package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

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
		ArchiveCommit:  gitArchiveToDir,
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
		deps.ArchiveCommit = gitArchiveToDir
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
	if opts.Revision == "" {
		opts.Revision = "HEAD"
	}

	repoRoot := deps.RepoRoot
	if repoRoot == "" {
		var err error
		repoRoot, err = gitRepoRoot(ctx)
		if err != nil {
			return nil, fmt.Errorf("locate repository root: %w", err)
		}
	}
	if opts.InstanceDir == "" {
		return nil, fmt.Errorf("instance directory is required")
	}
	if opts.BasePort < 1024 || opts.BasePort > 60000 {
		return nil, fmt.Errorf("base port must be between 1024 and 60000, got %d", opts.BasePort)
	}
	instanceDir := opts.InstanceDir
	if !filepath.IsAbs(instanceDir) {
		instanceDir = filepath.Join(repoRoot, instanceDir)
	}
	instanceDir = filepath.Clean(instanceDir)
	defaultFabricDir := filepath.Clean(filepath.Join(repoRoot, ".local", "fabric-d0"))
	if instanceDir == defaultFabricDir {
		return nil, fmt.Errorf("refusing to use default Fabric instance %s; specify an isolated directory", defaultFabricDir)
	}
	if _, err := os.Stat(instanceDir); err == nil {
		return nil, fmt.Errorf("isolated Fabric instance directory already exists: %s", instanceDir)
	} else if !os.IsNotExist(err) {
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
		defaultOutRoot = filepath.Join(repoRoot, "experiments", "e1-procurement", "runs")
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
		defaultOutRoot = filepath.Join(repoRoot, "experiments", "e6-revocation", "runs")
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
	if err := os.MkdirAll(outRoot, 0755); err != nil {
		return nil, fmt.Errorf("create runs root: %w", err)
	}

	runID := strings.TrimSpace(opts.RunID)
	if runID == "" {
		runID, err = generateRunID()
		if err != nil {
			return nil, err
		}
	}
	rc.runID = runID
	rc.runDir = filepath.Join(outRoot, runID)
	// Enforce anti-overwrite: os.Mkdir fails if run directory already exists.
	if err := os.Mkdir(rc.runDir, 0755); err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("run directory already exists (refusing to overwrite): %s", rc.runDir)
		}
		return nil, fmt.Errorf("create run directory: %w", err)
	}

	// Build reproducible source snapshot and write initial manifest/summary BEFORE build or network setup.
	relFiles, err := collectRelFiles(repoRoot, snapshotPatterns)
	if err != nil {
		return nil, fmt.Errorf("collect snapshot files: %w", err)
	}
	archivePath := filepath.Join(rc.runDir, "driver-source.tar.gz")
	snapInfo, fileHashes, err := buildSourceSnapshot(repoRoot, archivePath, relFiles)
	if err != nil {
		return nil, fmt.Errorf("create source snapshot: %w", err)
	}
	snapInfo.WorkspaceCommit = wsCommit
	snapInfo.WorkspaceDirty = wsDirty

	manifestPath := filepath.Join(rc.runDir, "manifest.json")
	initManifest := buildInitialManifest(runID, rc.startedAt, rc.plan, sourceCommit, snapInfo, fileHashes, instanceDir, opts.BasePort, extraManifest)
	if err := writeJSONFile(manifestPath, initManifest); err != nil {
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
	if err := writeJSONFile(summaryPath, summary); err != nil {
		return nil, err
	}

	if opts.PlanOnly {
		now := time.Now().UTC()
		summary.FinishedAt = &now
		summary.Status = "PLANNED"
		_ = writeJSONFile(summaryPath, summary)
		return &RunResult{RunID: runID, RunDir: rc.runDir, Summary: summary}, nil
	}

	if err := os.MkdirAll(filepath.Join(repoRoot, ".local"), 0755); err != nil {
		return nil, err
	}
	workDir, err := os.MkdirTemp(filepath.Join(repoRoot, ".local"), strings.ToLower(exp)+"-build.")
	if err != nil {
		return nil, err
	}
	rc.workDir = workDir

	var runErr error
	defer func() {
		// Always tear down Fabric containers if an instance was created.
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

func (rc *runContext) finalize(ctx context.Context, runErr error) (RunSummary, error) {
	now := time.Now().UTC()
	aborted := ctx.Err() != nil || errors.Is(runErr, context.Canceled)
	summaryPath := filepath.Join(rc.runDir, "summary.json")
	manifestPath := filepath.Join(rc.runDir, "manifest.json")

	// Preserve driver-written case results if present.
	var existing map[string]any
	if loaded, err := readJSONMap(summaryPath); err == nil {
		existing = loaded
	}

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
				if statusStr != "not_executed" {
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
			summary.Diagnostic = redactSecrets(runErr.Error(), rc.secrets)
			summary.Error = summary.Diagnostic
		} else {
			summary.Diagnostic = fmt.Sprintf("run aborted during stage %s", rc.stage)
			summary.Error = summary.Diagnostic
		}
	} else {
		summary.Status = "FAIL"
		summary.ExitCode = 1
		summary.Diagnostic = redactSecrets(runErr.Error(), rc.secrets)
		summary.Error = summary.Diagnostic
	}

	// Write summary before sensitive scan so summary itself is scanned, then record scan result.
	if err := writeJSONFile(summaryPath, summary); err != nil {
		return summary, err
	}
	if _, err := mergeManifest(manifestPath, map[string]any{
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
	if err := writeJSONFile(summaryPath, summary); err != nil {
		return summary, errors.Join(scanErr, err)
	}
	_, mErr := mergeManifest(manifestPath, map[string]any{
		"status":     summary.Status,
		"secretScan": scan,
	})
	return summary, errors.Join(scanErr, mErr)
}

func redactSecrets(text string, secrets []string) string {
	for _, s := range secrets {
		if s != "" {
			text = strings.ReplaceAll(text, s, "[REDACTED]")
		}
	}
	return text
}

func gitRepoRoot(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func gitResolveCommit(ctx context.Context, repoRoot, rev string) (string, error) {
	out, err := exec.CommandContext(ctx, "git", "-C", repoRoot, "rev-parse", "--verify", rev+"^{commit}").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func gitWorkspaceState(ctx context.Context, repoRoot string) (string, bool, error) {
	head, err := gitResolveCommit(ctx, repoRoot, "HEAD")
	if err != nil {
		return "", false, err
	}
	status, err := exec.CommandContext(ctx, "git", "-C", repoRoot, "status", "--porcelain").Output()
	if err != nil {
		return "", false, err
	}
	return head, len(bytes.TrimSpace(status)) > 0, nil
}

func gitArchiveToDir(ctx context.Context, repoRoot, commit, destDir string) error {
	archive := exec.CommandContext(ctx, "git", "-C", repoRoot, "archive", commit)
	extract := exec.CommandContext(ctx, "tar", "-xf", "-", "-C", destDir)
	pipe, err := archive.StdoutPipe()
	if err != nil {
		return err
	}
	extract.Stdin = pipe
	var aErr, eErr bytes.Buffer
	archive.Stderr = &aErr
	extract.Stderr = &eErr
	if err := archive.Start(); err != nil {
		return err
	}
	if err := extract.Start(); err != nil {
		_ = archive.Process.Kill()
		return err
	}
	errA := archive.Wait()
	errE := extract.Wait()
	if errA != nil {
		return fmt.Errorf("git archive %s: %w: %s", commit, errA, strings.TrimSpace(aErr.String()))
	}
	if errE != nil {
		return fmt.Errorf("tar extract: %w: %s", errE, strings.TrimSpace(eErr.String()))
	}
	return nil
}

func execCommandLogged(ctx context.Context, dir string, env []string, logPath string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = env
	}
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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
	script := filepath.Join(workDir, "infra", "fabric", "network.sh")
	if _, err := os.Stat(script); err != nil {
		script = "infra/fabric/network.sh"
	}
	env := append(os.Environ(), "FABRIC_INSTANCE="+instanceDir)
	return execCommandLogged(ctx, filepath.Dir(filepath.Dir(filepath.Dir(script))), env, logPath, "sh", script, "down")
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
	probeInterval := rc.opts.ProbeInterval
	if probeInterval <= 0 {
		probeInterval = time.Second
	}
	probeLifetime := rc.opts.ProbeLifetime
	if probeLifetime <= 0 {
		probeLifetime = 5 * time.Second
	}
	detectInterval := rc.opts.DetectInterval
	if detectInterval <= 0 {
		detectInterval = 20 * time.Millisecond
	}
	duration := rc.opts.Duration
	if duration <= 0 {
		duration = 12 * time.Second
	}
	revokeAfter := rc.opts.RevokeAfter
	if revokeAfter <= 0 {
		revokeAfter = time.Second
	}
	instances := rc.opts.Instances
	if instances <= 0 {
		instances = 2
	}
	rc.opts.ProbeInterval = probeInterval
	rc.opts.ProbeLifetime = probeLifetime
	rc.opts.DetectInterval = detectInterval
	rc.opts.Duration = duration
	rc.opts.RevokeAfter = revokeAfter
	rc.opts.Instances = instances

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
			"modeShort":         mode,
			"revocationTarget":  "G1",
			"gatewayInstances":  instances,
			"probeIntervalMs":   probeInterval.Milliseconds(),
			"probeLifetimeMs":   probeLifetime.Milliseconds(),
			"detectIntervalMs":  detectInterval.Milliseconds(),
			"revokeAfterMs":     revokeAfter.Milliseconds(),
			"postRevokeDurMs":   duration.Milliseconds(),
			"delegationDepth":   2,
			"descendantCount":   1,
			"clockTimebase":     "host-utc-unix-ns",
		},
	}
	if rc.opts.Seed != 0 {
		seed := rc.opts.Seed
		plan.Seed = &seed
	}
	patterns := []string{
		"mise.toml",
		"go.mod",
		"go.sum",
		"infra/fabric/compose.yaml",
		"docs/experiments/实验计划.md",
		"docs/experiments/E6-撤销窗口.md",
		"experiments/runner/*.go",
		"experiments/e6-revocation/driver/*.go",
	}
	return plan, patterns, nil
}
