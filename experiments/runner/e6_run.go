package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

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
	} else {
		if err := rc.deps.ArchiveCommit(ctx, rc.repoRoot, rc.sourceCommit, rc.workDir); err != nil {
			return fmt.Errorf("export commit %s: %w", rc.sourceCommit, err)
		}
		driverDst := filepath.Join(rc.workDir, "experiments", "e6-revocation", "driver")
		if err := os.MkdirAll(driverDst, 0755); err != nil {
			return err
		}
		driverSrcFiles, err := filepath.Glob(filepath.Join(rc.repoRoot, "experiments", "e6-revocation", "driver", "*.go"))
		if err != nil || len(driverSrcFiles) == 0 {
			return fmt.Errorf("E6 driver sources missing")
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
	}

	buildStart := time.Now()
	buildLog := filepath.Join(rc.runDir, "build.log")
	driverBin := filepath.Join(rc.workDir, "e6-driver")
	if err := rc.deps.RunCmd(ctx, buildDir, nil, buildLog, "go", "build", "-o", driverBin, "./experiments/e6-revocation/driver"); err != nil {
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
