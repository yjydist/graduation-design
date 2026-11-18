package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func main() {
	if err := runCLI(os.Args[1:], os.Stdout); err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runCLI(args []string, output io.Writer) error {
	f := flag.NewFlagSet("experiment:baseline", flag.ContinueOnError)
	f.SetOutput(output)
	var opts baselineOptions
	f.StringVar(&opts.Dir, "dir", "", "explicit isolated Fabric instance")
	f.StringVar(&opts.Out, "out", "", "new evidence directory")
	f.StringVar(&opts.C0Database, "c0-database", "", "new independent PostgreSQL database named baseline_...")
	f.IntVar(&opts.Seed, "seed", 1109, "paired fixture seed")
	f.DurationVar(&opts.RequestTimeout, "request-timeout", 15*time.Second, "timeout per wallet action")
	timeout := f.Duration("timeout", 10*time.Minute, "total preparation and execution timeout")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || opts.Dir == "" || opts.Out == "" || opts.C0Database == "" || *timeout <= 0 || opts.RequestTimeout <= 0 {
		return fmt.Errorf("explicit dir, c0-database, out and positive timeouts required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	e, err := runBaseline(ctx, opts)
	if e != nil {
		err = errors.Join(err, json.NewEncoder(output).Encode(map[string]any{"evidence_directory": e.Directory, "summary": e.Summary}))
	}
	return err
}
