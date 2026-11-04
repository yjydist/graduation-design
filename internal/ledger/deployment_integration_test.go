package ledger

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func TestDeploymentBindingIntegration(t *testing.T) {
	path := os.Getenv("LEDGER_DEPLOYMENT")
	if path == "" {
		t.Skip("set LEDGER_DEPLOYMENT to run against Besu")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var original Deployment
	if err = json.Unmarshal(b, &original); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	client, err := ethclient.DialContext(ctx, "http://127.0.0.1:18547")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = ValidateDeployment(ctx, client, &original); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Deployment){
		"chainId":            func(d *Deployment) { d.ChainID = "1" },
		"genesisHash":        func(d *Deployment) { d.GenesisHash[0] ^= 1 },
		"registryAddress":    func(d *Deployment) { d.RegistryAddress = common.Address{1} },
		"runtimeCodeHash":    func(d *Deployment) { d.RuntimeCodeHash[0] ^= 1 },
		"instanceId":         func(d *Deployment) { d.InstanceID = strings.Repeat("0", 64) },
		"schemaVersion":      func(d *Deployment) { d.SchemaVersion = "wrong" },
		"rootDid":            func(d *Deployment) { d.Root.RootDid += "-wrong" },
		"managementIdentity": func(d *Deployment) { d.Root.ManagementIdentity[0] ^= 1 },
		"didDocumentDigest":  func(d *Deployment) { d.Root.DidDocumentDigest[0] ^= 1 },
		"appKeyId":           func(d *Deployment) { d.Root.AppKeyId += "-wrong" },
		"appKeyVersion":      func(d *Deployment) { d.Root.AppKeyVersion++ },
		"appPublicKey":       func(d *Deployment) { d.Root.AppPublicKey[10] ^= 1 },
		"resourceId":         func(d *Deployment) { d.ResourceID[0] ^= 1 },
		"resourceOwner":      func(d *Deployment) { d.ResourceOwner[0] ^= 1 },
	}
	results := []map[string]any{}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var d Deployment
			if err := json.Unmarshal(b, &d); err != nil {
				t.Fatal(err)
			}
			mutate(&d)
			d.DeploymentID = deploymentID(&d)
			err := ValidateDeployment(ctx, client, &d)
			results = append(results, map[string]any{"field": name, "rejected": err != nil, "error": errString(err)})
			if err == nil {
				t.Fatal("accepted mismatched deployment")
			}
		})
	}
	var wrongID Deployment
	json.Unmarshal(b, &wrongID)
	wrongID.DeploymentID = strings.Repeat("0", 64)
	if err := ValidateDeployment(ctx, client, &wrongID); err == nil {
		t.Fatal("accepted wrong deploymentId")
	}
	if out := os.Getenv("LEDGER_EVIDENCE"); out != "" {
		if err := os.MkdirAll(out, 0755); err != nil {
			t.Fatal(err)
		}
		if err := writeJSON(filepath.Join(out, "deployment-binding.json"), map[string]any{"passed": !t.Failed(), "deploymentId": original.DeploymentID, "cases": results}); err != nil {
			t.Fatal(err)
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestRootMutationIntegration(t *testing.T) {
	path := os.Getenv("LEDGER_DEPLOYMENT")
	dir := os.Getenv("LEDGER_INSTANCE")
	if path == "" || dir == "" {
		t.Skip("set LEDGER_DEPLOYMENT and LEDGER_INSTANCE to run against Besu")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d Deployment
	if err = json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ethclient.DialContext(ctx, "http://127.0.0.1:18547")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	key, err := crypto.LoadECDSA(filepath.Join(dir, "keys", "T", "management.key"))
	if err != nil {
		t.Fatal(err)
	}
	data := append(crypto.Keccak256([]byte("setRoot(bytes32)"))[:4], make([]byte, 32)...)
	op, err := Submit(ctx, client, dir, d.DeploymentID[:8]+"-reject-root-mutation", key, &d.RegistryAddress, data, ChainID)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != "FAILED" || op.Receipt.Status != 0 {
		t.Fatal("root mutation must revert")
	}
	if err = ValidateDeployment(ctx, client, &d); err != nil {
		t.Fatalf("root changed: %v", err)
	}
	if out := os.Getenv("LEDGER_EVIDENCE"); out != "" {
		if err := os.MkdirAll(out, 0755); err != nil {
			t.Fatal(err)
		}
		if err = writeJSON(filepath.Join(out, "root-mutation.json"), map[string]any{"passed": true, "deploymentId": d.DeploymentID, "operation": op}); err != nil {
			t.Fatal(err)
		}
	}
}
