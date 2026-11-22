package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"grad/experiments/baseline"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := newRootCmd()
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "exp",
		Short:         "Unified experiment CLI for baseline, E1/E6 orchestration, and offline analysis",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newBaselineCmd(),
		newRunCmd(),
		newAnalyzeCmd(),
	)
	return root
}

func newBaselineCmd() *cobra.Command {
	var opts baseline.Options
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Run the three-group (C0/B0/B1) paired procurement baseline",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := baseline.Run(cmd.Context(), opts)
			if res != nil {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				_ = enc.Encode(res)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&opts.Dir, "dir", "", "isolated Fabric instance directory")
	cmd.Flags().StringVar(&opts.C0Database, "c0-database", "", "new PostgreSQL database name for C0 (baseline_*)")
	cmd.Flags().StringVar(&opts.OutDir, "out", "", "new output directory for baseline evidence")
	cmd.Flags().IntVar(&opts.Seed, "seed", baseline.DefaultSeed, "paired fixture seed")
	cmd.Flags().DurationVar(&opts.RequestTimeout, "request-timeout", baseline.DefaultRequestTimeout, "timeout per wallet action")
	cmd.Flags().DurationVar(&opts.Timeout, "timeout", baseline.DefaultTimeout, "total preparation and execution timeout")
	return cmd
}

func newRunCmd() *cobra.Command {
	var opts RunOptions
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Execute an isolated E1 or E6 experiment run",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := ExecuteRun(cmd.Context(), opts, defaultRunnerDeps())
			if res != nil && res.RunDir != "" {
				fmt.Fprintln(cmd.OutOrStdout(), res.RunDir)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&opts.Experiment, "experiment", "", "experiment identifier (E1 or E6)")
	cmd.Flags().StringVar(&opts.Revision, "revision", "HEAD", "target git commit for system under test")
	cmd.Flags().StringVar(&opts.InstanceDir, "instance", "", "new isolated Fabric instance directory")
	cmd.Flags().IntVar(&opts.BasePort, "port", 0, "base TCP port for isolated Fabric network")
	cmd.Flags().StringVar(&opts.OutRoot, "out-root", "", "optional override for runs root directory")
	cmd.Flags().StringVar(&opts.RunID, "run-id", "", "optional explicit run ID (must not already exist)")
	cmd.Flags().IntVar(&opts.Seed, "seed", 0, "optional experiment seed")
	cmd.Flags().StringVar(&opts.Mode, "mode", "", "authorization mode for E6 (RP or BM)")
	cmd.Flags().StringVar(&opts.Configuration, "configuration", "B0", "verification configuration (B0 or B1)")
	cmd.Flags().DurationVar(&opts.ProbeInterval, "probe-interval", time.Second, "E6 state probe send interval")
	cmd.Flags().DurationVar(&opts.ProbeLifetime, "probe-lifetime", 5*time.Second, "E6 state probe lifetime deltaState")
	cmd.Flags().DurationVar(&opts.DetectInterval, "detect-interval", 20*time.Millisecond, "E6 planned order probe interval")
	cmd.Flags().DurationVar(&opts.RevokeAfter, "revoke-after", time.Second, "E6 pre-revocation baseline duration")
	cmd.Flags().DurationVar(&opts.Duration, "duration", 12*time.Second, "E6 post-revocation probing duration")
	cmd.Flags().IntVar(&opts.Instances, "instances", 2, "E6 number of gateway instances sharing C view")
	cmd.Flags().BoolVar(&opts.PlanOnly, "plan-only", false, "write initial manifest and source snapshot then stop before build")
	cmd.Flags().BoolVar(&opts.WorkspaceSUT, "workspace-sut", false, "build SUT from current workspace instead of git archive (records workspaceDirty)")
	return cmd
}

func newAnalyzeCmd() *cobra.Command {
	var exp, runDir, outDir string
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Recompute E1 or E6 metrics offline from a read-only run directory",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(exp) == "" || strings.TrimSpace(runDir) == "" || strings.TrimSpace(outDir) == "" {
				return fmt.Errorf("experiment, run-dir and out are required")
			}
			switch strings.ToUpper(strings.TrimSpace(exp)) {
			case "E1":
				return runAnalyzeE1(cmd.Context(), runDir, outDir, cmd.OutOrStdout())
			case "E6":
				return runAnalyzeE6(cmd.Context(), runDir, outDir, cmd.OutOrStdout())
			default:
				return fmt.Errorf("unsupported experiment %q for offline analysis", exp)
			}
		},
	}
	cmd.Flags().StringVar(&exp, "experiment", "", "experiment identifier (E1 or E6)")
	cmd.Flags().StringVar(&runDir, "run-dir", "", "raw run directory to analyze (read-only)")
	cmd.Flags().StringVar(&outDir, "out", "", "derived output directory (must be outside raw run-dir)")
	return cmd
}
