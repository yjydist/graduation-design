package fabric

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	api "graduation-design/internal/fabricapi"
)

// Run is the Fabric ledgerctl entry point.
func Run(args []string, output io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: ledgerctl {deploy|seed|check|inspect|invoke|operation|verify}")
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(output)
	dir := os.Getenv("FABRIC_INSTANCE")
	if dir == "" {
		dir = filepath.Join(".local", "fabric-d0")
	}
	flags.StringVar(&dir, "dir", dir, "Fabric instance directory")
	defaultTimeout := 2 * time.Minute
	if command == "verify" {
		defaultTimeout = 5 * time.Minute
	}
	timeout := flags.Duration("timeout", defaultTimeout, "overall command timeout")
	var grant, height, role, key, method, input, evidence string
	var interval, lifetime time.Duration
	var retryInitialization bool
	switch command {
	case "check", "inspect":
		flags.StringVar(&grant, "grant", "", "target grant ID, defaults to the synthetic G1")
		if command == "inspect" {
			flags.StringVar(&height, "block", "", "required Fabric block number")
		} else {
			flags.StringVar(&role, "probe-role", "probe1", "dedicated probe identity (probe1 or probe2)")
			flags.DurationVar(&interval, "probe-interval", api.ProbeInterval, "probe interval")
			flags.DurationVar(&lifetime, "probe-lifetime", api.ProbeLifetime, "original probe lifetime")
		}
	case "invoke", "operation":
		flags.StringVar(&key, "key", "", "durable operation key")
		if command == "invoke" {
			flags.StringVar(&role, "role", "", "management identity")
			flags.StringVar(&method, "method", "", "registry operation")
			flags.StringVar(&input, "input", "", "JSON input file")
		}
	case "verify":
		flags.StringVar(&evidence, "out", ".local/fabric-evidence", "parent directory for a unique evidence run")
	case "deploy":
		flags.BoolVar(&retryInitialization, "retry-initialization", false, "allow a new operation after a rejected unsigned initialization")
	case "seed":
	default:
		return fmt.Errorf("unknown Fabric command %q", command)
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *timeout <= 0 {
		return fmt.Errorf("unexpected argument or invalid timeout")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	enc := json.NewEncoder(output)
	enc.SetIndent("", "  ")
	if command == "verify" {
		report, err := verify(ctx, dir, evidence)
		if report != nil {
			err = errors.Join(err, enc.Encode(report))
		}
		return err
	}
	i, err := loadInstance(dir)
	if err != nil {
		return err
	}
	if command == "deploy" {
		d, err := i.deploy(ctx, retryInitialization)
		if err != nil {
			return err
		}
		return enc.Encode(d)
	}
	d, err := i.loadDeployment()
	if err != nil {
		return err
	}
	db, err := i.database(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	if command == "check" || command == "inspect" {
		if grant == "" {
			var f fixtures
			if err := readJSON(i.registryPath("fixtures.json"), &f); err != nil {
				return err
			}
			if f.DeploymentID != d.DeploymentID {
				return fmt.Errorf("DEPLOYMENT_MISMATCH: fixture")
			}
			grant = f.G1.ID
		}
		if err := initSchema(ctx, db, viewSchema); err != nil {
			return err
		}
		v := view{db: db, d: d}
		if command == "inspect" {
			n, err := strconv.ParseUint(height, 10, 63)
			if err != nil {
				return fmt.Errorf("inspect requires --block with a non-negative integer")
			}
			s, err := v.snapshot(ctx, grant, &n, nil, nil)
			if err != nil {
				return err
			}
			return enc.Encode(s)
		}
		if (role != "probe1" && role != "probe2") || interval < 100*time.Millisecond || lifetime < interval {
			return fmt.Errorf("invalid probe configuration")
		}
		rt := &online{view: v, instance: i, role: role, interval: interval, timeLimit: lifetime}
		stop, err := rt.start(ctx)
		if err != nil {
			return err
		}
		defer stop()
		s, err := waitOnline(ctx, rt, grant)
		if err != nil {
			return err
		}
		return enc.Encode(s)
	}
	if err := initSchema(ctx, db, operationsSchema); err != nil {
		return err
	}
	j := journal{instance: i, deploymentID: d.DeploymentID, db: db}
	var stored *operation
	var raw []byte
	if command == "invoke" || command == "operation" {
		// Resolve retries from the journal before contacting the Peer.
		stored, err = j.load(ctx, key, db)
		if err != nil {
			return err
		}
		if command == "invoke" {
			raw, err = os.ReadFile(input)
			if err != nil {
				return err
			}
			if stored != nil {
				if _, _, err := j.matchInput(stored, role, method, raw); err != nil {
					return err
				}
			}
		} else if stored == nil {
			return fmt.Errorf("unknown operation %q", key)
		}
		if stored != nil && stored.Status != "PENDING" {
			return enc.Encode(stored)
		}
	}
	p, err := i.peer("c", "read")
	if err != nil {
		return err
	}
	defer p.close()
	if err := d.validatePeer(ctx, p); err != nil {
		// A disconnected or mismatched Peer cannot change the journal.
		if stored != nil {
			return enc.Encode(stored)
		}
		return err
	}
	switch command {
	case "seed":
		seed, err := i.seed(ctx, j, d)
		if seed != nil {
			err = errors.Join(err, enc.Encode(seed))
		}
		return err
	case "invoke":
		op, err := j.write(ctx, key, role, method, raw)
		if op != nil {
			err = errors.Join(err, enc.Encode(op))
		}
		return err
	case "operation":
		op, err := j.recover(ctx, key, nil)
		if op != nil {
			err = errors.Join(err, enc.Encode(op))
		}
		return err
	}
	return nil
}

func waitOnline(ctx context.Context, v *online, grant string) (*snapshot, error) {
	var last error
	for ctx.Err() == nil {
		s, err := v.snapshot(ctx, grant, nil, v, nil)
		if err == nil {
			return s, nil
		}
		if !errors.Is(err, errStale) && !errors.Is(err, errUnavailable) {
			return nil, err
		}
		v.mu.Lock()
		hard := v.hardError
		v.mu.Unlock()
		if hard != nil && !errors.Is(hard, context.DeadlineExceeded) {
			return nil, errors.Join(errUnavailable, hard)
		}
		last = err
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, errors.Join(last, ctx.Err())
}
