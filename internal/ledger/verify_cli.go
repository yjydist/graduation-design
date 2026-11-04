package ledger

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"
)

func verifyCommand(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(out)
	var options VerifyOptions
	flags.StringVar(&options.Dir, "dir", ".local/besu-qbft", "selected instance directory")
	flags.StringVar(&options.Manifest, "manifest", "", "trusted deployment manifest")
	flags.StringVar(&options.Endpoint, "rpc", "http://127.0.0.1:18547", "trusted C RPC")
	flags.StringVar(&options.Output, "out", ".local/evidence", "root for independent evidence runs")
	flags.StringVar(&options.ProjectRoot, "project-root", ".", "project source root for tests and locked materials")
	flags.StringVar(&options.ComposeFile, "compose", "infra/besu/compose.yaml", "selected Compose configuration")
	flags.StringVar(&options.ComposeProject, "compose-project", "grad-besu", "selected Compose project")
	flags.DurationVar(&options.Timeout, "timeout", 10*time.Minute, "overall verification deadline")
	flags.DurationVar(&options.StartupTimeout, "startup-timeout", 120*time.Second, "node readiness/recovery deadline")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if options.Timeout <= 0 || options.StartupTimeout <= 0 {
		return fmt.Errorf("timeouts must be positive")
	}
	summary, err := Verify(context.Background(), options)
	if summary != nil {
		if encodeErr := json.NewEncoder(out).Encode(summary); encodeErr != nil {
			return encodeErr
		}
	}
	return err
}
