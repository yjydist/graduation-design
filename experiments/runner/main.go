package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runCLI(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCLI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: experiment-runner <run|analyze> [flags]")
	}
	switch args[0] {
	case "run":
		return runSubcommand(ctx, args[1:], stdout, stderr)
	case "analyze":
		return analyzeSubcommand(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown subcommand %q (expected run or analyze)", args[0])
	}
}

func runSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("experiment:run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts RunOptions
	fs.StringVar(&opts.Experiment, "experiment", "", "experiment identifier (E1 or E6)")
	fs.StringVar(&opts.Revision, "revision", "HEAD", "target git commit for system under test")
	fs.StringVar(&opts.InstanceDir, "instance", "", "new isolated Fabric instance directory")
	fs.IntVar(&opts.BasePort, "port", 0, "base TCP port for isolated Fabric network")
	fs.StringVar(&opts.OutRoot, "out-root", "", "optional override for runs root directory")
	fs.StringVar(&opts.RunID, "run-id", "", "optional explicit run ID (must not already exist)")
	fs.IntVar(&opts.Seed, "seed", 0, "optional experiment seed")
	fs.StringVar(&opts.Mode, "mode", "", "authorization mode for E6 (RP or BM)")
	fs.StringVar(&opts.Configuration, "configuration", "B0", "verification configuration (B0 or B1)")
	fs.DurationVar(&opts.ProbeInterval, "probe-interval", 0, "E6 state probe send interval (default 1s)")
	fs.DurationVar(&opts.ProbeLifetime, "probe-lifetime", 0, "E6 state probe lifetime deltaState (default 5s)")
	fs.DurationVar(&opts.DetectInterval, "detect-interval", 0, "E6 planned order probe interval (default 20ms)")
	fs.DurationVar(&opts.Duration, "duration", 0, "E6 post-revocation probing duration (default 12s)")
	fs.DurationVar(&opts.RevokeAfter, "revoke-after", 0, "E6 pre-revocation baseline duration (default 1s)")
	fs.IntVar(&opts.Instances, "instances", 2, "E6 number of gateway instances sharing C view")
	fs.BoolVar(&opts.PlanOnly, "plan-only", false, "write initial manifest and source snapshot then stop before build")
	fs.BoolVar(&opts.WorkspaceSUT, "workspace-sut", false, "build SUT from current workspace instead of git archive (records workspaceDirty)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	res, err := ExecuteRun(ctx, opts, defaultRunnerDeps())
	if res != nil && res.RunDir != "" {
		fmt.Fprintln(stdout, res.RunDir)
	}
	return err
}

func analyzeSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("experiment:analyze", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var exp, runDir, outDir string
	fs.StringVar(&exp, "experiment", "", "experiment identifier (E1 or E6)")
	fs.StringVar(&runDir, "run-dir", "", "raw run directory to analyze (read-only)")
	fs.StringVar(&outDir, "out", "", "derived output directory (must be outside raw run-dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || exp == "" || runDir == "" || outDir == "" {
		return fmt.Errorf("experiment, run-dir and out are required")
	}
	switch strings.ToUpper(strings.TrimSpace(exp)) {
	case "E1":
		return runAnalyzeE1(ctx, runDir, outDir, stdout)
	case "E6":
		return runAnalyzeE6(ctx, runDir, outDir, stdout)
	default:
		return fmt.Errorf("unsupported experiment %q for offline analysis", exp)
	}
}
