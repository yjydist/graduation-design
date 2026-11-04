package ledger

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func parseGrantID(value string) (common.Hash, error) {
	if value == "" {
		return common.Hash{}, fmt.Errorf("grant id required")
	}
	if strings.HasPrefix(value, "0x") {
		b, err := hex.DecodeString(value[2:])
		if err != nil || len(b) != 32 {
			return common.Hash{}, fmt.Errorf("invalid grant hash")
		}
		return common.BytesToHash(b), nil
	}
	return hashID(value), nil
}

func readStateCommand(args []string, out io.Writer) error {
	mode := args[0]
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	flags.SetOutput(out)
	dir := flags.String("dir", ".local/besu-qbft", "instance or checkpoint directory")
	manifest := flags.String("manifest", "", "trusted deployment manifest")
	endpoint := flags.String("rpc", "http://127.0.0.1:18547", "trusted C RPC")
	grant := flags.String("grant", ChildFixtureID, "grant URI or 0x SHA-256 index")
	logPath := flags.String("rpc-log", "", "optional public RPC transcript JSON")
	var block *string
	if mode == "inspect" {
		block = flags.String("block", "", "required historical height, decimal or 0x hex")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	id, err := parseGrantID(*grant)
	if err != nil {
		return err
	}
	var number *big.Int
	if block != nil {
		base := 10
		text := *block
		if strings.HasPrefix(text, "0x") {
			base = 16
			text = text[2:]
		}
		var ok bool
		number, ok = new(big.Int).SetString(text, base)
		if !ok || !number.IsUint64() {
			return fmt.Errorf("inspect requires an explicit nonnegative --block")
		}
	}
	if *manifest == "" {
		*manifest = filepath.Join(*dir, "deployment-registry.json")
	}
	b, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	var d Deployment
	if err = json.Unmarshal(b, &d); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	recorder := &RPCRecorder{}
	client, err := RecordedClient(ctx, *endpoint, recorder)
	if err != nil {
		return err
	}
	defer client.Close()
	reader := NewStateReader(client, &d, *dir, nil)
	var snapshot *Snapshot
	if mode == "inspect" {
		snapshot, err = reader.Inspect(ctx, id, number)
	} else {
		snapshot, err = reader.Check(ctx, id)
	}
	if *logPath != "" {
		if logErr := os.MkdirAll(filepath.Dir(*logPath), 0755); logErr != nil {
			return logErr
		}
		if logErr := writeJSON(*logPath, recorder.Snapshot()); logErr != nil {
			return logErr
		}
	}
	if err != nil {
		failure, ok := err.(*StateFailure)
		if !ok {
			failure = &StateFailure{Code: "STATE_QUERY_FAILED", Detail: err.Error(), CheckedAt: time.Now().UTC()}
		}
		if encodeErr := json.NewEncoder(out).Encode(map[string]any{"mode": mode, "deploymentId": d.DeploymentID, "grantId": id, "error": failure}); encodeErr != nil {
			return encodeErr
		}
		return err
	}
	return json.NewEncoder(out).Encode(snapshot)
}
