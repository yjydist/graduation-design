package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func callData(q RPCRequest) string {
	if q.Method != "eth_call" || len(q.Params) < 1 {
		return ""
	}
	var arg map[string]string
	_ = json.Unmarshal(q.Params[0], &arg)
	if arg["input"] != "" {
		return arg["input"]
	}
	return arg["data"]
}

func requireFixedCalls(t *testing.T, samples []RPCSample, block string) {
	t.Helper()
	for _, s := range samples {
		if s.Request.Method == "eth_call" {
			var tag string
			json.Unmarshal(s.Request.Params[1], &tag)
			if tag == "latest" || (block != "" && tag != block) {
				t.Fatalf("mixed-height call %s, expected %s", tag, block)
			}
		}
	}
}

func TestStateAssemblyFailuresIntegration(t *testing.T) {
	h := newRegistryHarness(t, "assembly-failures")
	for _, kind := range []string{"missing-height", "missing-record", "single-call-failure", "empty-record", "changed-block-hash"} {
		recorder := &RPCRecorder{}
		grantRead := false
		selected := ""
		recorder.Before = func(q RPCRequest) error {
			if kind == "single-call-failure" && strings.HasPrefix(callData(q), hexutil.Encode(h.r.ABI.Methods["getCredential"].ID)) {
				return fmt.Errorf("injected fixed-height credential query failure")
			}
			return nil
		}
		recorder.After = func(q RPCRequest, b []byte) ([]byte, error) {
			if strings.HasPrefix(callData(q), hexutil.Encode(h.r.ABI.Methods["getGrant"].ID)) {
				grantRead = true
			}
			var envelope map[string]any
			if err := json.Unmarshal(b, &envelope); err != nil {
				return nil, err
			}
			if kind == "empty-record" && strings.HasPrefix(callData(q), hexutil.Encode(h.r.ABI.Methods["getCredential"].ID)) {
				envelope["result"] = "0x"
				delete(envelope, "error")
				return json.Marshal(envelope)
			}
			if q.Method == "eth_getBlockByNumber" && len(q.Params) > 0 {
				var tag string
				json.Unmarshal(q.Params[0], &tag)
				if tag == "latest" {
					if result, ok := envelope["result"].(map[string]any); ok {
						selected = result["number"].(string)
					}
				}
				if kind == "changed-block-hash" && grantRead && tag == selected {
					envelope["result"].(map[string]any)["hash"] = common.Hash{9}.Hex()
					return json.Marshal(envelope)
				}
			}
			return b, nil
		}
		client, err := RecordedClient(h.ctx, "http://127.0.0.1:18547", recorder)
		if err != nil {
			t.Fatal(err)
		}
		reader := NewStateReader(client, h.r.Deployment, t.TempDir(), nil)
		var snapshot *Snapshot
		if kind == "missing-height" {
			snapshot, err = reader.Inspect(h.ctx, h.f.Grants["G1"].GrantId, big.NewInt(1<<40))
		} else if kind == "missing-record" {
			snapshot, err = reader.Check(h.ctx, hashID("missing-grant"))
		} else {
			snapshot, err = reader.Check(h.ctx, h.f.Grants["G1"].GrantId)
		}
		client.Close()
		if err == nil || snapshot != nil {
			t.Fatalf("accepted partial or invalid snapshot: %s", kind)
		}
		requireFixedCalls(t, recorder.Snapshot(), selected)
		h.cases = append(h.cases, map[string]any{"name": kind, "passed": true, "error": err.Error(), "snapshot": snapshot, "rpc": recorder.Snapshot()})
	}
}

func TestHighestHeadRecoveryIntegration(t *testing.T) {
	h := newRegistryHarness(t, "highest-head")
	header, err := ReadHeader(h.ctx, h.r.Client, nil)
	if err != nil {
		t.Fatal(err)
	}
	mode := "normal"
	recorder := &RPCRecorder{}
	recorder.After = func(q RPCRequest, b []byte) ([]byte, error) {
		if q.Method != "eth_getBlockByNumber" {
			return b, nil
		}
		var tag string
		json.Unmarshal(q.Params[0], &tag)
		var envelope map[string]any
		json.Unmarshal(b, &envelope)
		if tag == "latest" {
			if mode == "regression" {
				old, err := ReadHeader(h.ctx, h.r.Client, new(big.Int).SetUint64(uint64(header.Number)-1))
				if err != nil {
					return nil, err
				}
				raw, _ := json.Marshal(old)
				var v any
				json.Unmarshal(raw, &v)
				envelope["result"] = v
			} else {
				raw, _ := json.Marshal(header)
				var v any
				json.Unmarshal(raw, &v)
				envelope["result"] = v
			}
		}
		if mode == "conflict" && (tag == "latest" || tag == hexutil.EncodeUint64(uint64(header.Number))) {
			envelope["result"].(map[string]any)["hash"] = common.Hash{7}.Hex()
		}
		return json.Marshal(envelope)
	}
	client, err := RecordedClient(h.ctx, "http://127.0.0.1:18547", recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	dir := t.TempDir()
	reader := NewStateReader(client, h.r.Deployment, dir, nil)
	id := h.f.Grants["G1"].GrantId
	first, err := reader.Check(h.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"conflict", "regression"} {
		mode = kind
		snapshot, err := reader.Check(h.ctx, id)
		if err == nil || snapshot != nil {
			t.Fatalf("accepted %s", kind)
		}
		h.cases = append(h.cases, map[string]any{"name": kind, "passed": true, "error": err.Error()})
	}
	mode = "normal"
	restarted := NewStateReader(client, h.r.Deployment, dir, nil)
	if _, err = restarted.Check(h.ctx, id); err != nil {
		t.Fatalf("restart with retained checkpoint failed: %v", err)
	}
	checkpoint := filepath.Join(dir, "heads", h.r.Deployment.DeploymentID+".json")
	before, _ := os.ReadFile(checkpoint)
	if _, err = restarted.Inspect(h.ctx, id, h.r.Deployment.Operation.Receipt.BlockNumber); err == nil {
		t.Fatal("grant must not exist in deployment block")
	}
	after, _ := os.ReadFile(checkpoint)
	if string(before) != string(after) {
		t.Fatal("historical query changed online checkpoint")
	}
	changed := cloneValue(*h.r.Deployment)
	changed.InstanceID = strings.Repeat("0", 64)
	changed.DeploymentID = deploymentID(&changed)
	if snapshot, err := NewStateReader(client, &changed, t.TempDir(), nil).Check(h.ctx, id); err == nil || snapshot != nil {
		t.Fatal("accepted changed deployment")
	}
	// Restore a trusted fresh head and recheck the retained lower bound.
	header, err = ReadHeader(h.ctx, h.r.Client, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Check(h.ctx, id); err != nil {
		t.Fatalf("trusted fresh head recovery failed: %v", err)
	}
	h.cases = append(h.cases, map[string]any{"name": "restart-history-deployment-recovery", "passed": true, "first": first.Header, "recovered": header, "rpc": recorder.Snapshot()})
}

// Ensure the deterministic clock used below never relies on host wall-clock adjustments.
type manualClock struct {
	wall time.Time
	mono time.Duration
}

func (c *manualClock) Wall() time.Time     { return c.wall }
func (c *manualClock) Mono() time.Duration { return c.mono }

var _ Clock = (*manualClock)(nil)
var _ = context.Background
