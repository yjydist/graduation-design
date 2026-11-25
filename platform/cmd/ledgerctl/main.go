package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"grad/platform/bootstrap"
	"grad/platform/core/ledger"
	"grad/protocol/registry"
)

type cliOptions struct {
	dir     string
	timeout time.Duration
}

func main() {
	cmd := newRootCmd(os.Stdin, os.Stdout, os.Stderr)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func defaultInstanceDir() string {
	if dir := strings.TrimSpace(os.Getenv("FABRIC_INSTANCE")); dir != "" {
		return dir
	}
	return filepath.Join(".local", "fabric-d0")
}

func newRootCmd(in io.Reader, out, errOut io.Writer) *cobra.Command {
	opts := &cliOptions{
		dir:     defaultInstanceDir(),
		timeout: 2 * time.Minute,
	}

	root := &cobra.Command{
		Use:           "ledgerctl",
		Short:         "Fabric registry deployment, seeding, audit inspection, and MCP wallet CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if opts.timeout <= 0 {
				return fmt.Errorf("invalid --timeout %s: must be positive", opts.timeout)
			}
			return nil
		},
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(errOut)
	root.PersistentFlags().StringVar(&opts.dir, "dir", opts.dir, "Fabric instance directory (defaults to $FABRIC_INSTANCE or .local/fabric-d0)")
	root.PersistentFlags().DurationVar(&opts.timeout, "timeout", opts.timeout, "Overall command timeout")

	root.AddCommand(
		newDeployCmd(opts),
		newSeedCmd(opts),
		newCheckCmd(opts),
		newInspectCmd(opts),
		newInvokeCmd(opts),
		newOperationCmd(opts),
		newMCPCmd(opts),
	)
	return root
}

func commandContext(cmd *cobra.Command, timeout time.Duration) (context.Context, context.CancelFunc) {
	base := cmd.Context()
	if base == nil {
		base = context.Background()
	}
	return context.WithTimeout(base, timeout)
}

func writeJSONOutput(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newDeployCmd(opts *cliOptions) *cobra.Command {
	var retryInit bool
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy, approve, commit, and initialize the Fabric registry chaincode",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, opts.timeout)
			defer cancel()
			inst, err := ledger.OpenInstance(opts.dir)
			if err != nil {
				return err
			}
			dep, err := inst.Deploy(ctx, retryInit)
			if err != nil {
				return err
			}
			return writeJSONOutput(cmd.OutOrStdout(), dep)
		},
	}
	cmd.Flags().BoolVar(&retryInit, "retry-initialization", false, "Allow a new operation after a rejected unsigned initialization")
	return cmd
}

func newSeedCmd(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "seed",
		Short: "Generate verifiable protocol materials, seed Fabric anchors, and sync delivery outboxes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, opts.timeout)
			defer cancel()
			inst, err := ledger.OpenInstance(opts.dir)
			if err != nil {
				return err
			}
			dep, err := inst.LoadDeployment()
			if err != nil {
				return err
			}
			db, err := inst.Database(ctx)
			if err != nil {
				return err
			}
			defer db.Close()
			p, err := inst.Peer("c", "read")
			if err != nil {
				return err
			}
			defer p.Close()
			if err := dep.ValidatePeer(ctx, p); err != nil {
				return err
			}
			report, err := bootstrap.Seed(ctx, inst, db, dep)
			if report != nil {
				err = errors.Join(err, writeJSONOutput(cmd.OutOrStdout(), report))
			}
			return err
		},
	}
}

func newCheckCmd(opts *cliOptions) *cobra.Command {
	var (
		grant         string
		probeRole     string
		probeInterval time.Duration
		probeLifetime time.Duration
	)
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Start an online Fabric state view, verify an original liveness probe, and read a grant snapshot",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := commandContext(cmd, opts.timeout)
			defer cancel()
			inst, err := ledger.OpenInstance(opts.dir)
			if err != nil {
				return err
			}
			snap, err := bootstrap.CheckRegistryAccess(ctx, inst, grant, probeRole, probeInterval, probeLifetime)
			if err != nil {
				return err
			}
			return writeJSONOutput(cmd.OutOrStdout(), snap)
		},
	}
	cmd.Flags().StringVar(&grant, "grant", "", "Target grant ID (defaults to seeded G1)")
	cmd.Flags().StringVar(&probeRole, "probe-role", "probe1", "Dedicated probe identity (probe1 or probe2)")
	cmd.Flags().DurationVar(&probeInterval, "probe-interval", registry.ProbeInterval, "Original liveness probe interval")
	cmd.Flags().DurationVar(&probeLifetime, "probe-lifetime", registry.ProbeLifetime, "Original liveness probe lifetime")
	return cmd
}

func newInspectCmd(opts *cliOptions) *cobra.Command {
	var (
		grant   string
		blockNo int64 = -1
	)
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Reconstruct a historical Fabric view snapshot for a grant at a committed block number",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !cmd.Flags().Changed("block") || blockNo < 0 {
				return fmt.Errorf("inspect requires --block with a non-negative integer")
			}
			ctx, cancel := commandContext(cmd, opts.timeout)
			defer cancel()
			inst, err := ledger.OpenInstance(opts.dir)
			if err != nil {
				return err
			}
			snap, err := bootstrap.InspectHistory(ctx, inst, grant, blockNo)
			if err != nil {
				return err
			}
			return writeJSONOutput(cmd.OutOrStdout(), snap)
		},
	}
	cmd.Flags().StringVar(&grant, "grant", "", "Target grant ID (defaults to seeded G1)")
	cmd.Flags().Int64Var(&blockNo, "block", -1, "Required non-negative Fabric block number")
	return cmd
}

func newInvokeCmd(opts *cliOptions) *cobra.Command {
	var key, role, method, inputPath string
	cmd := &cobra.Command{
		Use:   "invoke",
		Short: "Submit or idempotently resume a durable original-txID Fabric registry operation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(key) == "" || strings.TrimSpace(role) == "" || strings.TrimSpace(method) == "" || strings.TrimSpace(inputPath) == "" {
				return fmt.Errorf("invoke requires --key, --role, --method, and --input")
			}
			ctx, cancel := commandContext(cmd, opts.timeout)
			defer cancel()
			inst, err := ledger.OpenInstance(opts.dir)
			if err != nil {
				return err
			}
			raw, err := os.ReadFile(inputPath)
			if err != nil {
				return err
			}
			op, err := bootstrap.InvokeOperation(ctx, inst, key, role, method, raw)
			if op != nil {
				err = errors.Join(err, writeJSONOutput(cmd.OutOrStdout(), op))
			}
			return err
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Durable operation key")
	cmd.Flags().StringVar(&role, "role", "", "Management identity role")
	cmd.Flags().StringVar(&method, "method", "", "Registry chaincode method")
	cmd.Flags().StringVar(&inputPath, "input", "", "Path to JSON input payload file")
	return cmd
}

func newOperationCmd(opts *cliOptions) *cobra.Command {
	var key string
	cmd := &cobra.Command{
		Use:   "operation",
		Short: "Query or recover an existing durable original-txID operation by key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(key) == "" {
				return fmt.Errorf("operation requires --key")
			}
			ctx, cancel := commandContext(cmd, opts.timeout)
			defer cancel()
			inst, err := ledger.OpenInstance(opts.dir)
			if err != nil {
				return err
			}
			op, err := bootstrap.InspectOperation(ctx, inst, key)
			if op != nil {
				err = errors.Join(err, writeJSONOutput(cmd.OutOrStdout(), op))
			}
			return err
		},
	}
	cmd.Flags().StringVar(&key, "key", "", "Durable operation key")
	return cmd
}

func newMCPCmd(opts *cliOptions) *cobra.Command {
	var (
		gatewayURL string
		offline    bool
	)
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run the isolated agent wallet MCP server over stdio",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			var cancel context.CancelFunc
			if cmd.Flags().Changed("timeout") {
				ctx, cancel = context.WithTimeout(ctx, opts.timeout)
				defer cancel()
			}
			inst, err := ledger.OpenInstance(opts.dir)
			if err != nil {
				return err
			}
			return bootstrap.RunInstanceMCP(ctx, inst, offline, gatewayURL, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&gatewayURL, "gateway", os.Getenv("GATEWAY_URL"), "Gateway HTTP base URL (defaults to $GATEWAY_URL or http://127.0.0.1:8103)")
	cmd.Flags().BoolVar(&offline, "offline", false, "Run the MCP wallet over local instance fixtures without connecting to PostgreSQL")
	return cmd
}
