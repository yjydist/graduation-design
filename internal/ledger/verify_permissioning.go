package ledger

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

func (v *verificationRun) unpermittedNode(ctx context.Context, r *Registry) (data map[string]any, runErr error) {
	data = map[string]any{}
	name := v.options.ComposeProject + "-rogue-" + v.summary.RunID
	dir := filepath.Join(r.Dir, "probes", v.summary.RunID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return data, err
	}
	imageBytes, err := exec.CommandContext(ctx, "docker", "inspect", v.options.ComposeProject+"-c-1", "--format", "{{.Config.Image}}").Output()
	if err != nil {
		return data, err
	}
	image := strings.TrimSpace(string(imageBytes))
	if !strings.Contains(image, "@sha256:") {
		return data, fmt.Errorf("permission probe requires the selected pinned image")
	}
	args := []string{"run", "-d", "--name", name, "--network", v.options.ComposeProject + "_ledger", "--ip", "172.28.61.15", "--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()), "--memory", "1280m", "--cpus", "2", "-e", "JAVA_OPTS=-Xms256m -Xmx512m", "-p", "127.0.0.1::8545", "-v", dir + ":/data", "-v", filepath.Join(r.Dir, "genesis.json") + ":/config/genesis.json:ro", "-v", filepath.Join(r.Dir, "static-nodes.json") + ":/config/static-nodes.json:ro", image, "--data-path=/data", "--genesis-file=/config/genesis.json", "--network-id=20261104", "--data-storage-format=FOREST", "--sync-mode=FULL", "--sync-min-peers=1", "--discovery-enabled=false", "--static-nodes-file=/config/static-nodes.json", "--p2p-host=172.28.61.15", "--nat-method=NONE", "--rpc-http-enabled", "--rpc-http-host=0.0.0.0", "--rpc-http-api=ETH,NET,WEB3", "--logging=DEBUG"}
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	data["startOutput"] = string(output)
	if err != nil {
		return data, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		logs, _ := exec.CommandContext(cleanup, "docker", "logs", name).CombinedOutput()
		clean := regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAll(logs, nil)
		_ = os.WriteFile(filepath.Join(v.summary.Directory, "unpermitted-node.log"), clean, 0644)
		data["logs"] = "unpermitted-node.log"
		matches := regexp.MustCompile(`Loaded public key (0x[0-9a-fA-F]{128})`).FindSubmatch(clean)
		if len(matches) == 2 {
			data["unpermittedPublicKey"] = string(matches[1])
		}
		_, err := exec.CommandContext(cleanup, "docker", "rm", "-f", name).CombinedOutput()
		if err != nil {
			data["cleanupError"] = err.Error()
			if runErr == nil {
				runErr = err
			}
		}
	}()
	portBytes, err := exec.CommandContext(ctx, "docker", "port", name, "8545/tcp").Output()
	if err != nil {
		return data, err
	}
	address := strings.TrimSpace(string(portBytes))
	if !strings.HasPrefix(address, "127.0.0.1:") || strings.Contains(address, "\n") {
		return data, fmt.Errorf("unexpected rogue RPC binding")
	}
	client, err := RecordedClient(ctx, "http://"+address, v.recorder)
	if err != nil {
		return data, err
	}
	defer client.Close()
	ready, cancel := context.WithTimeout(ctx, v.options.StartupTimeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		_, err := client.ChainID(ready)
		if err == nil {
			break
		}
		select {
		case <-ready.Done():
			return data, fmt.Errorf("permission probe startup exceeded bound: %w", ready.Err())
		case <-ticker.C:
		}
	}
	genesis, err := ReadHeader(ctx, client, big.NewInt(0))
	if err != nil {
		return data, err
	}
	if genesis.Hash != r.Deployment.GenesisHash {
		return data, fmt.Errorf("rogue probe genesis mismatch")
	}
	logs, err := exec.CommandContext(ctx, "docker", "logs", name).CombinedOutput()
	if err != nil {
		return data, err
	}
	public := regexp.MustCompile(`public key (0x[0-9a-fA-F]{128})`).FindSubmatch(logs)
	if len(public) != 2 {
		return data, fmt.Errorf("rogue node public identity not observed")
	}
	m, err := LoadInstance(r.Dir)
	if err != nil {
		return data, err
	}
	for _, validator := range m.Validators {
		if strings.EqualFold(validator.PublicKey, strings.TrimPrefix(string(public[1]), "0x")) {
			return data, fmt.Errorf("permission probe identity was already allowlisted")
		}
	}
	data["unpermittedPublicKey"] = string(public[1])
	var head *Header
	head, err = ReadHeader(ctx, client, nil)
	if err != nil {
		return data, err
	}
	samples := []any{}
	for i := 0; i < 12; i++ {
		var trusted, rogue hexutil.Uint64
		if err = r.Client.Client().CallContext(ctx, &trusted, "net_peerCount"); err != nil {
			return data, err
		}
		if err = client.Client().CallContext(ctx, &rogue, "net_peerCount"); err != nil {
			return data, err
		}
		samples = append(samples, map[string]any{"observedAt": time.Now().UTC(), "trustedPeers": trusted, "unpermittedPeers": rogue})
		if uint64(trusted) != 3 || uint64(rogue) != 0 {
			return data, fmt.Errorf("unpermitted node established an effective connection")
		}
		select {
		case <-ctx.Done():
			return data, ctx.Err()
		case <-ticker.C:
		}
	}
	data["samples"], data["rogueGenesisHash"], data["rogueStartHead"], data["image"] = samples, genesis.Hash, head, image
	var final *Header
	final, err = ReadHeader(ctx, client, nil)
	if err != nil {
		return data, err
	}
	data["rogueEndHead"] = final
	if final.Number != 0 || final.Hash != genesis.Hash {
		return data, fmt.Errorf("unpermitted node synchronized trusted chain")
	}
	return data, nil
}
