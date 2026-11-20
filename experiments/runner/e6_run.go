package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"time"
)

const e6DriverDir = "experiments/e6/driver"

func executeE6Run(ctx context.Context, rc *runContext) error {
	manifestPath := filepath.Join(rc.runDir, "manifest.json")

	// Stage: build
	rc.stage = "build"
	buildDir := rc.workDir
	sutSource := "git-archive"
	if rc.opts.WorkspaceSUT {
		// Build directly from the current repository workspace when testing uncommitted SUT changes,
		// while still recording workspaceCommit, workspaceDirty, and binary/file SHA-256 digests.
		buildDir = rc.repoRoot
		sutSource = "workspace"
	} else if err := prepareFixedBuild(ctx, rc, e6DriverDir); err != nil {
		return err
	}

	buildStart := time.Now()
	buildLog := filepath.Join(rc.runDir, "build.log")
	driverBin := filepath.Join(rc.workDir, "e6-driver")
	if err := rc.deps.RunCmd(ctx, buildDir, nil, buildLog, "go", "build", "-o", driverBin, "./"+e6DriverDir); err != nil {
		return fmt.Errorf("build e6-driver: %w", err)
	}
	driverHash, err := sha256File(driverBin)
	if err != nil {
		return fmt.Errorf("hash e6-driver: %w", err)
	}
	if _, err := mergeManifest(manifestPath, map[string]any{
		"stage":           "build",
		"sutSource":       sutSource,
		"binarySHA256":    map[string]string{"driver": driverHash},
		"buildDurationMs": time.Since(buildStart).Milliseconds(),
	}); err != nil {
		return err
	}

	// Stage: network
	rc.stage = "network"
	netLog := filepath.Join(rc.runDir, "network-up.log")
	if err := rc.deps.RunCmd(ctx, buildDir, nil, netLog, "sh", "infra/fabric/network.sh", "rebuild", rc.instanceDir, strconv.Itoa(rc.opts.BasePort)); err != nil {
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
