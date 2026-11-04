package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
)

func (v *verificationRun) networkBaseline(ctx context.Context, r *Registry) (any, error) {
	data := map[string]any{}
	m, err := LoadInstance(r.Dir)
	if err != nil {
		return data, err
	}
	nodes := []any{}
	for _, node := range []struct{ name, url string }{{"A", "http://127.0.0.1:18545"}, {"B", "http://127.0.0.1:18546"}, {"C", v.options.Endpoint}, {"ops", "http://127.0.0.1:18548"}} {
		client, err := RecordedClient(ctx, node.url, v.recorder)
		if err != nil {
			return data, err
		}
		chain, err := client.ChainID(ctx)
		if err != nil {
			client.Close()
			return data, err
		}
		genesis, err := ReadHeader(ctx, client, big.NewInt(0))
		if err != nil {
			client.Close()
			return data, err
		}
		var validators []common.Address
		err = client.Client().CallContext(ctx, &validators, "qbft_getValidatorsByBlockNumber", "latest")
		if err != nil {
			client.Close()
			return data, err
		}
		var peers hexutil.Uint64
		err = client.Client().CallContext(ctx, &peers, "net_peerCount")
		client.Close()
		if err != nil {
			return data, err
		}
		if chain.String() != r.Deployment.ChainID || genesis.Hash != r.Deployment.GenesisHash || len(validators) != 4 || uint64(peers) != 3 {
			return data, fmt.Errorf("network identity/peers mismatch: %s", node.name)
		}
		wanted := map[common.Address]bool{}
		for _, validator := range m.Validators {
			wanted[common.HexToAddress(validator.Address)] = true
		}
		for _, validator := range validators {
			if !wanted[validator] {
				return data, fmt.Errorf("unexpected validator")
			}
			delete(wanted, validator)
		}
		if len(wanted) != 0 {
			return data, fmt.Errorf("missing validator")
		}
		nodes = append(nodes, map[string]any{"role": node.name, "chainId": chain.String(), "genesisHash": genesis.Hash, "validators": validators, "peers": peers})
	}
	data["nodes"] = nodes
	h, err := ReadHeader(ctx, r.Client, nil)
	if err != nil {
		return data, err
	}
	start := uint64(h.Number) + 1
	if _, err = waitHeight(ctx, r.Client, start+10, v.options.StartupTimeout); err != nil {
		return data, err
	}
	blocks := []json.RawMessage{}
	intervals := []uint64{}
	var previous *Header
	for number := start; number <= start+10; number++ {
		var raw json.RawMessage
		if err = r.Client.Client().CallContext(ctx, &raw, "eth_getBlockByNumber", hexutil.EncodeUint64(number), false); err != nil {
			return data, err
		}
		var block struct {
			Header
			Transactions []common.Hash `json:"transactions"`
		}
		if err = json.Unmarshal(raw, &block); err != nil {
			return data, err
		}
		if uint64(block.Number) != number || len(block.Transactions) != 0 {
			return data, fmt.Errorf("nonempty or missing observation block")
		}
		if previous != nil {
			if block.ParentHash != previous.Hash || block.Timestamp < previous.Timestamp {
				return data, fmt.Errorf("empty block sequence mismatch")
			}
			intervals = append(intervals, uint64(block.Timestamp-previous.Timestamp))
		}
		copyHeader := block.Header
		previous = &copyHeader
		blocks = append(blocks, raw)
	}
	data["emptyBlocks"], data["intervalSeconds"] = blocks, intervals
	return data, nil
}

func waitHeight(ctx context.Context, client *ethclient.Client, minimum uint64, timeout time.Duration) (*Header, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		h, err := ReadHeader(ctx, client, nil)
		if err == nil && uint64(h.Number) >= minimum {
			return h, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("head wait exceeded bound: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (v *verificationRun) history(ctx context.Context, r *Registry, f *Fixtures) (any, error) {
	data := map[string]any{}
	g := f.Grants["G1"]
	g.GrantId = hashID("urn:grad:grant:verify:" + v.summary.RunID)
	g = anchorSyntheticGrant(f, g)
	register, err := r.Write(ctx, v.summary.RunID+"-register", "U", "registerGrant", g)
	data["registerOperation"] = register
	data["grant"] = g
	data["syntheticMaterial"] = f.Materials[g.GrantId.Hex()]
	if err != nil {
		return data, err
	}
	if register.Status != "CONFIRMED" {
		return data, fmt.Errorf("verification grant registration failed")
	}
	var revoke *Operation
	triggered := false
	v.recorder.After = func(q RPCRequest, b []byte) ([]byte, error) {
		if !triggered && q.Method == "eth_call" {
			var arg map[string]string
			json.Unmarshal(q.Params[0], &arg)
			input := arg["input"]
			if input == "" {
				input = arg["data"]
			}
			if strings.HasPrefix(input, hexutil.Encode(r.ABI.Methods["getGrant"].ID)) && strings.Contains(input, strings.TrimPrefix(g.GrantId.Hex(), "0x")) {
				triggered = true
				var err error
				revoke, err = r.Write(ctx, v.summary.RunID+"-revoke", "U", "revokeGrant", g.GrantId, uint64(1), g.Digest)
				if err != nil {
					return nil, err
				}
				if revoke.Status != "CONFIRMED" {
					return nil, fmt.Errorf("interleaved revocation failed")
				}
			}
		}
		return b, nil
	}
	reader := NewStateReader(r.Client, r.Deployment, r.Dir, nil)
	snapshot, err := reader.Check(ctx, g.GrantId)
	v.recorder.After = nil
	data["interleavedSnapshot"], data["revokeOperation"] = snapshot, revoke
	if err != nil {
		return data, err
	}
	if !triggered || revoke == nil || snapshot.Grants[g.GrantId.Hex()].Status != StatusActive || snapshot.Header.Number >= hexutil.Uint64(revoke.Receipt.BlockNumber.Uint64()) {
		return data, fmt.Errorf("interleaved snapshot mixed heights or missed the revocation")
	}
	for _, q := range snapshot.Queries {
		if q.Block != hexutil.EncodeUint64(uint64(snapshot.Header.Number)) {
			return data, fmt.Errorf("mixed-height query in interleaved snapshot")
		}
	}
	historicH, err := reader.Inspect(ctx, g.GrantId, new(big.Int).SetUint64(uint64(snapshot.Header.Number)))
	data["historicalH"] = historicH
	if err != nil {
		return data, err
	}
	historicR, err := reader.Inspect(ctx, g.GrantId, revoke.Receipt.BlockNumber)
	data["historicalR"] = historicR
	if err != nil {
		return data, err
	}
	current, err := reader.Check(ctx, g.GrantId)
	data["onlineAfter"] = current
	if err != nil {
		return data, err
	}
	if historicH.Grants[g.GrantId.Hex()].Status != StatusActive || historicR.Grants[g.GrantId.Hex()].Status != StatusRevoked || current.Grants[g.GrantId.Hex()].Status != StatusRevoked || historicH.Fresh != nil || historicR.Fresh != nil {
		return data, fmt.Errorf("historical/online revocation contrast failed")
	}
	return data, nil
}

func (v *verificationRun) nodeFaults(ctx context.Context, r *Registry, f *Fixtures) (data map[string]any, runErr error) {
	data = map[string]any{}
	// Refuse to control containers belonging to another selected instance.
	inspect, err := exec.CommandContext(ctx, "docker", "inspect", v.options.ComposeProject+"-c-1").Output()
	if err != nil {
		return data, err
	}
	var containers []struct {
		Mounts []struct{ Source, Destination string }
	}
	if err = json.Unmarshal(inspect, &containers); err != nil {
		return data, err
	}
	matched := false
	for _, c := range containers {
		for _, mount := range c.Mounts {
			if mount.Destination == "/data" && filepath.Clean(mount.Source) == filepath.Join(v.options.Dir, "nodes", "C") {
				matched = true
			}
		}
	}
	if !matched {
		return data, fmt.Errorf("refusing fault control: C container instance mount mismatch")
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		output, err := v.compose(cleanupCtx, "up", "-d", "a", "b")
		data["cleanupOutput"] = output
		if err == nil {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				var peers hexutil.Uint64
				rpcErr := r.Client.Client().CallContext(cleanupCtx, &peers, "net_peerCount")
				if rpcErr == nil && uint64(peers) == 3 {
					data["restoredPeers"] = peers
					break
				}
				select {
				case <-cleanupCtx.Done():
					err = cleanupCtx.Err()
				case <-ticker.C:
				}
				if err != nil {
					break
				}
			}
		}
		if err != nil {
			data["cleanupError"] = err.Error()
			if runErr == nil {
				runErr = fmt.Errorf("network cleanup: %w", err)
			}
		}
	}()
	id := f.Grants["G1"].GrantId
	reader := NewStateReader(r.Client, r.Deployment, r.Dir, nil)
	before, err := reader.Check(ctx, id)
	data["before"] = before
	if err != nil {
		return data, err
	}
	output, err := v.compose(ctx, "stop", "a")
	data["stopA"] = output
	if err != nil {
		return data, err
	}
	postStop, err := ReadHeader(ctx, r.Client, nil)
	data["headAfterStopA"] = postStop
	if err != nil {
		return data, err
	}
	one, err := waitHeight(ctx, r.Client, uint64(postStop.Number)+3, v.options.StartupTimeout)
	data["afterOneStopped"] = one
	if err != nil {
		return data, err
	}
	output, err = v.compose(ctx, "stop", "b")
	data["stopB"] = output
	if err != nil {
		return data, err
	}
	settled := []any{}
	if err = observeDuration(ctx, r, 5*time.Second, func(h *Header) error {
		settled = append(settled, map[string]any{"observedAt": time.Now().UTC(), "header": h})
		return nil
	}); err != nil {
		return data, err
	}
	data["settlingHeads"] = settled
	stopped, err := ReadHeader(ctx, r.Client, nil)
	if err != nil {
		return data, err
	}
	stable := []any{}
	stableStart := time.Now()
	data["stableWindowStartedAt"] = stableStart.UTC()
	err = observeDuration(ctx, r, 15*time.Second, func(h *Header) error {
		stable = append(stable, map[string]any{"observedAt": time.Now().UTC(), "header": h})
		if h.Number != stopped.Number || h.Hash != stopped.Hash {
			return fmt.Errorf("chain grew during two-node stable window")
		}
		return nil
	})
	data["stableWindow"] = stable
	data["stableWindowEndedAt"], data["stableWindowDurationSeconds"] = time.Now().UTC(), time.Since(stableStart).Seconds()
	if err != nil {
		return data, err
	}
	stale := []any{}
	for i := 0; i < 3; i++ {
		snapshot, err := reader.Check(ctx, id)
		if err == nil || snapshot != nil || !strings.HasPrefix(err.Error(), "STATE_STALE") {
			return data, fmt.Errorf("stopped chain was not stale: %v", err)
		}
		stale = append(stale, map[string]any{"checkedAt": time.Now().UTC(), "error": err.Error()})
	}
	data["repeatedStaleChecks"] = stale
	restarted := NewStateReader(r.Client, r.Deployment, r.Dir, nil)
	snapshot, err := restarted.Check(ctx, id)
	if err == nil || snapshot != nil || !strings.HasPrefix(err.Error(), "STATE_STALE") {
		return data, fmt.Errorf("restart renewed stopped-chain age: %v", err)
	}
	data["staleRestart"] = err.Error()
	historical, err := restarted.Inspect(ctx, id, new(big.Int).SetUint64(uint64(stopped.Number)))
	data["historicalStoppedHead"] = historical
	if err != nil {
		return data, err
	}
	output, err = v.compose(ctx, "up", "-d", "a")
	data["restoreA"] = output
	if err != nil {
		return data, err
	}
	recoverCtx, cancel := context.WithTimeout(ctx, v.options.StartupTimeout)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		h, err := ReadHeader(recoverCtx, r.Client, nil)
		if err == nil && h.Number > stopped.Number {
			snapshot, err = restarted.Check(recoverCtx, id)
			if err == nil {
				data["freshRecovery"] = snapshot
				break
			}
		}
		select {
		case <-recoverCtx.Done():
			return data, fmt.Errorf("fresh recovery exceeded bound: %w", recoverCtx.Err())
		case <-ticker.C:
		}
	}
	if !reflect.DeepEqual(historical.Grants[id.Hex()].Grant, f.Grants["G1"]) {
		return data, fmt.Errorf("historical state changed during node faults")
	}
	return data, nil
}

func observeDuration(ctx context.Context, r *Registry, duration time.Duration, visit func(*Header) error) error {
	end := time.NewTimer(duration)
	defer end.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		h, err := ReadHeader(ctx, r.Client, nil)
		if err != nil {
			return err
		}
		if err = visit(h); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-end.C:
			final, err := ReadHeader(ctx, r.Client, nil)
			if err != nil {
				return err
			}
			return visit(final)
		case <-ticker.C:
		}
	}
}
