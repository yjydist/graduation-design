// Package ledger provides local ledger initialization and verification tools.
package ledger

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"
)

func Run(args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "verify" {
		return verifyCommand(args, out)
	}
	if len(args) > 0 && (args[0] == "inspect" || args[0] == "check") {
		return readStateCommand(args, out)
	}
	if len(args) > 0 && args[0] == "seed" {
		flags := flag.NewFlagSet("seed", flag.ContinueOnError)
		flags.SetOutput(out)
		dir := flags.String("dir", ".local/besu-qbft", "local instance directory")
		manifest := flags.String("manifest", "", "trusted deployment manifest, default <dir>/deployment-registry.json")
		endpoint := flags.String("rpc", "http://127.0.0.1:18547", "trusted C RPC")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected positional arguments")
		}
		if *manifest == "" {
			*manifest = filepath.Join(*dir, "deployment-registry.json")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		r, err := OpenRegistry(ctx, *dir, *manifest, *endpoint)
		if err != nil {
			return err
		}
		defer r.Client.Close()
		report, seedErr := Seed(ctx, r)
		if report != nil {
			if err = json.NewEncoder(out).Encode(report); err != nil {
				return err
			}
		}
		return seedErr
	}
	if len(args) > 0 && (args[0] == "compile" || args[0] == "deploy") {
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		flags.SetOutput(out)
		dir := flags.String("dir", ".local/besu-qbft", "local instance directory")
		contracts := flags.String("contracts", "contracts", "Solidity directory")
		endpoint := flags.String("rpc", "http://127.0.0.1:18547", "trusted C RPC")
		name := flags.String("name", "registry", "deployment name")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected positional arguments")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		if args[0] == "compile" {
			artifact, err := Compile(ctx, *contracts)
			if err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(map[string]any{"compiler": artifact.Compiler, "sourceSha256": artifact.SourceSHA256, "bytecodeBytes": len(artifact.EVM.Bytecode.Object) / 2})
		}
		d, err := Deploy(ctx, *dir, *contracts, *endpoint, *name)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(d)
	}
	if len(args) > 0 && args[0] == "init" {
		flags := flag.NewFlagSet("init", flag.ContinueOnError)
		flags.SetOutput(out)
		dir := flags.String("dir", ".local/besu-qbft", "local instance directory")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected positional arguments")
		}
		m, created, err := InitInstance(*dir)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"instanceId": m.InstanceID, "created": created, "synthetic": m.Synthetic, "directory": *dir})
	}
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help") {
		_, err := fmt.Fprintln(out, "Usage: ledgerctl <init|compile|deploy|seed|inspect|check|verify> [options]\ninit --dir .local/besu-qbft\ncompile --contracts contracts\ndeploy --dir .local/besu-qbft --name registry --rpc http://127.0.0.1:18547\nseed --dir .local/besu-qbft [--manifest path]\ninspect --block <height> [--grant URI] [--rpc-log path]\ncheck [--grant URI] [--rpc-log path]\nverify --out .local/evidence [--timeout 10m] [--startup-timeout 120s]")
		return err
	}
	return fmt.Errorf("expected a command; use ledgerctl --help")
}
