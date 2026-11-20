package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func prepareE1Plan(rc *runContext) (RunPlan, map[string]any, string, []string, error) {
	llmEnvPath := filepath.Join(rc.repoRoot, "experiments", "llm.env")
	fileEnv, err := parseEnvFile(llmEnvPath)
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
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return RunPlan{}, nil, "", nil, fmt.Errorf("invalid LLM_BASE_URL %q", baseURL)
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
			"cases":             "F01-F16",
			"llmDriverCases":    []string{"F05", "F06", "F07", "F15"},
			"deterministicCases": []string{"F01", "F02", "F03", "F04", "F08", "F09", "F10", "F11", "F12", "F13", "F14", "F16"},
		},
	}
	if rc.opts.Seed != 0 {
		seed := rc.opts.Seed
		plan.Seed = &seed
	}
	llmMeta := map[string]any{
		"provider":          provider,
		"model":             model,
		"configuredBaseURL": baseURL,
		"baseURL":           effectiveURL,
		"apiKeySource":      "env:LLM_API_KEY",
	}
	patterns := []string{
		"mise.toml",
		"go.mod",
		"go.sum",
		"infra/fabric/compose.yaml",
		"experiments/llm.env",
		"experiments/e1-procurement/run.sh",
		"experiments/e1-procurement/driver/*.go",
		"experiments/runner/*.go",
		"docs/experiments/实验计划.md",
		"docs/experiments/验证用例.md",
		"docs/experiments/E1-采购功能闭环.md",
	}
	return plan, llmMeta, apiKey, patterns, nil
}

func executeE1Run(ctx context.Context, rc *runContext) error {
	manifestPath := filepath.Join(rc.runDir, "manifest.json")

	// Stage: build
	rc.stage = "build"
	if err := rc.deps.ArchiveCommit(ctx, rc.repoRoot, rc.sourceCommit, rc.workDir); err != nil {
		return fmt.Errorf("export commit %s: %w", rc.sourceCommit, err)
	}
	driverDst := filepath.Join(rc.workDir, "experiments", "e1-procurement", "driver")
	if err := os.MkdirAll(driverDst, 0755); err != nil {
		return err
	}
	driverSrcFiles, err := filepath.Glob(filepath.Join(rc.repoRoot, "experiments", "e1-procurement", "driver", "*.go"))
	if err != nil || len(driverSrcFiles) == 0 {
		return fmt.Errorf("E1 driver sources missing")
	}
	for _, src := range driverSrcFiles {
		raw, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(driverDst, filepath.Base(src)), raw, 0644); err != nil {
			return err
		}
	}
	localTools := filepath.Join(rc.repoRoot, ".local", "fabric-tools")
	if info, err := os.Stat(localTools); err == nil && info.IsDir() {
		_ = os.MkdirAll(filepath.Join(rc.workDir, ".local"), 0755)
		_ = os.Symlink(localTools, filepath.Join(rc.workDir, ".local", "fabric-tools"))
	}

	buildStart := time.Now()
	buildLog := filepath.Join(rc.runDir, "build.log")
	ledgerctlBin := filepath.Join(rc.workDir, "ledgerctl")
	driverBin := filepath.Join(rc.workDir, "e1-driver")
	if err := rc.deps.RunCmd(ctx, rc.workDir, nil, buildLog, "go", "build", "-o", ledgerctlBin, "./cmd/ledgerctl"); err != nil {
		return fmt.Errorf("build ledgerctl: %w", err)
	}
	if err := rc.deps.RunCmd(ctx, rc.workDir, nil, buildLog, "go", "build", "-o", driverBin, "./experiments/e1-procurement/driver"); err != nil {
		return fmt.Errorf("build e1-driver: %w", err)
	}

	binaries := map[string]string{}
	for name, binPath := range map[string]string{"ledgerctl": ledgerctlBin, "driver": driverBin} {
		sum, err := sha256File(binPath)
		if err != nil {
			return fmt.Errorf("hash binary %s: %w", name, err)
		}
		binaries[name] = sum
	}
	if _, err := mergeManifest(manifestPath, map[string]any{
		"stage":         "build",
		"binarySHA256":  binaries,
		"buildDurationMs": time.Since(buildStart).Milliseconds(),
	}); err != nil {
		return err
	}

	// Stage: network / preparation
	rc.stage = "network"
	netLog := filepath.Join(rc.runDir, "network-up.log")
	if err := rc.deps.RunCmd(ctx, rc.workDir, nil, netLog, "sh", "infra/fabric/network.sh", "rebuild", rc.instanceDir, strconv.Itoa(rc.opts.BasePort)); err != nil {
		return fmt.Errorf("prepare isolated Fabric network: %w", err)
	}
	netMeta := readPublicNetworkEnv(filepath.Join(rc.instanceDir, "network.env"))
	if _, err := mergeManifest(manifestPath, map[string]any{
		"stage":      "network",
		"networkEnv": netMeta,
	}); err != nil {
		return err
	}

	// Stage: execution
	rc.stage = "execution"
	env := append(os.Environ(),
		"LLM_PROVIDER="+fmt.Sprint(rc.llmConfig["provider"]),
		"LLM_BASE_URL="+fmt.Sprint(rc.llmConfig["configuredBaseURL"]),
		"LLM_MODEL="+fmt.Sprint(rc.llmConfig["model"]),
	)
	if err := rc.deps.RunCmd(ctx, rc.workDir, env, filepath.Join(rc.runDir, "driver.log"), driverBin,
		"-revision", rc.sourceCommit,
		"-ledgerctl", ledgerctlBin,
		"-dir", rc.instanceDir,
		"-out", rc.runDir,
	); err != nil {
		return fmt.Errorf("execute E1 driver: %w", err)
	}
	return nil
}

func readPublicNetworkEnv(path string) map[string]string {
	raw, err := parseEnvFile(path)
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
