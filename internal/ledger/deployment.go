package ledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type RootRecord struct {
	RootDid            string         `json:"rootDid"`
	ManagementIdentity common.Address `json:"managementIdentity"`
	DidDocumentDigest  common.Hash    `json:"didDocumentDigest"`
	AppKeyId           string         `json:"appKeyId"`
	AppKeyVersion      uint64         `json:"appKeyVersion"`
	AppPublicKey       []byte         `json:"appPublicKey"`
}

func (r RootRecord) MarshalJSON() ([]byte, error) {
	type alias RootRecord
	return json.Marshal(struct {
		alias
		AppPublicKey hexutil.Bytes `json:"appPublicKey"`
	}{alias(r), hexutil.Bytes(r.AppPublicKey)})
}

func (r *RootRecord) UnmarshalJSON(b []byte) error {
	type alias RootRecord
	var v struct {
		alias
		AppPublicKey hexutil.Bytes `json:"appPublicKey"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*r = RootRecord(v.alias)
	r.AppPublicKey = []byte(v.AppPublicKey)
	return nil
}

type Deployment struct {
	ChainID         string          `json:"chainId"`
	GenesisHash     common.Hash     `json:"genesisHash"`
	RegistryAddress common.Address  `json:"registryAddress"`
	RuntimeCodeHash common.Hash     `json:"runtimeCodeHash"`
	InstanceID      string          `json:"instanceId"`
	SchemaVersion   string          `json:"schemaVersion"`
	DeploymentID    string          `json:"deploymentId"`
	Root            RootRecord      `json:"root"`
	ResourceID      common.Hash     `json:"resourceId"`
	ResourceOwner   common.Hash     `json:"resourceOwner"`
	TaskDomain      common.Hash     `json:"taskDomain"`
	TaskCreator     common.Hash     `json:"taskCreator"`
	Compiler        string          `json:"compiler"`
	SourceSHA256    string          `json:"sourceSha256"`
	InputSHA256     string          `json:"inputSha256"`
	ABI             json.RawMessage `json:"abi"`
	Operation       *Operation      `json:"operation"`
	Synthetic       bool            `json:"synthetic"`
}

func hashID(id string) common.Hash { return common.Hash(sha256.Sum256([]byte(id))) }

func deploymentID(d *Deployment) string {
	// The six fields contain only ASCII strings. Sorted map serialization is JCS.
	b, _ := json.Marshal(map[string]string{"chainId": d.ChainID, "genesisHash": d.GenesisHash.Hex(), "registryAddress": strings.ToLower(d.RegistryAddress.Hex()), "runtimeCodeHash": d.RuntimeCodeHash.Hex(), "instanceId": d.InstanceID, "schemaVersion": d.SchemaVersion})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func Deploy(ctx context.Context, dir, contractsDir, endpoint, name string) (*Deployment, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,50}$`).MatchString(name) {
		return nil, fmt.Errorf("invalid deployment name")
	}
	m, err := LoadInstance(dir)
	if err != nil {
		return nil, err
	}
	var artifact ContractArtifact
	b, err := os.ReadFile(filepath.Join(contractsDir, "build", "AuthRegistry.json"))
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &artifact); err != nil {
		return nil, err
	}
	for file, expected := range map[string]string{"AuthRegistry.sol": artifact.SourceSHA256, "compiler-input.json": artifact.InputSHA256} {
		b, err := os.ReadFile(filepath.Join(contractsDir, file))
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != expected {
			return nil, fmt.Errorf("artifact stale; compile first: %s", file)
		}
	}
	contractABI, err := abi.JSON(strings.NewReader(string(artifact.ABI)))
	if err != nil {
		return nil, err
	}
	var root RootRecord
	var owner common.Hash
	var creator common.Hash
	for _, a := range m.Accounts {
		if a.Role == "T" {
			pub, err := hexutil.Decode(a.AppPublic)
			if err != nil {
				return nil, err
			}
			root = RootRecord{a.SubjectID, common.HexToAddress(a.Address), common.HexToHash(a.DIDDigest), a.AppKeyID, a.AppVersion, pub}
		}
		if a.Role == "C" {
			owner = hashID(a.SubjectID)
		}
		if a.Role == "U" {
			creator = hashID(a.SubjectID)
		}
	}
	instance, err := hex.DecodeString(m.InstanceID)
	if err != nil {
		return nil, err
	}
	var instance32 [32]byte
	copy(instance32[:], instance)
	resource := hashID("urn:grad:resource:C:orders")
	client, err := ethclient.DialContext(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	genesis, err := ReadHeader(ctx, client, big.NewInt(0))
	if err != nil {
		return nil, err
	}
	taskDomain := hashID("urn:grad:domain:A")
	constructor, err := contractABI.Pack("", root, instance32, resource, owner, genesis.Hash, taskDomain, creator)
	if err != nil {
		return nil, err
	}
	bytecode, err := hex.DecodeString(artifact.EVM.Bytecode.Object)
	if err != nil {
		return nil, err
	}
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, err
	}
	if !chainID.IsUint64() || chainID.Uint64() != m.ChainID {
		return nil, fmt.Errorf("chain mismatch")
	}
	key, err := crypto.LoadECDSA(filepath.Join(dir, "keys", "deployer", "management.key"))
	if err != nil {
		return nil, err
	}
	txCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	op, err := Submit(txCtx, client, dir, "deploy-"+name, key, nil, append(bytecode, constructor...), m.ChainID)
	if err != nil {
		return nil, err
	}
	if op.Status != "CONFIRMED" {
		return nil, fmt.Errorf("deployment failed: %s", op.TxHash)
	}
	address := op.Receipt.ContractAddress
	code, err := client.CodeAt(ctx, address, op.Receipt.BlockNumber)
	if err != nil {
		return nil, err
	}
	if len(code) == 0 {
		return nil, fmt.Errorf("deployed code absent")
	}
	d := &Deployment{ChainID: chainID.String(), GenesisHash: genesis.Hash, RegistryAddress: address, RuntimeCodeHash: crypto.Keccak256Hash(code), InstanceID: m.InstanceID, SchemaVersion: "grad-auth-v1", Root: root, ResourceID: resource, ResourceOwner: owner, Compiler: artifact.Compiler, SourceSHA256: artifact.SourceSHA256, InputSHA256: artifact.InputSHA256, ABI: artifact.ABI, Operation: op, Synthetic: true}
	d.DeploymentID = deploymentID(d)
	d.TaskDomain, d.TaskCreator = taskDomain, creator
	if err = ValidateDeployment(ctx, client, d); err != nil {
		return nil, err
	}
	if err = durableJSON(filepath.Join(dir, "deployment-"+name+".json"), d); err != nil {
		return nil, err
	}
	return d, nil
}

func ReadView(ctx context.Context, client *ethclient.Client, d *Deployment, block *big.Int, method string, args ...any) ([]any, error) {
	if block == nil {
		return nil, fmt.Errorf("explicit block number required")
	}
	a, err := abi.JSON(strings.NewReader(string(d.ABI)))
	if err != nil {
		return nil, err
	}
	data, err := a.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	result, err := client.CallContract(ctx, ethereum.CallMsg{To: &d.RegistryAddress, Data: data}, block)
	if err != nil {
		return nil, err
	}
	return a.Unpack(method, result)
}

// ValidateDeployment binds every online session to the trusted manifest.
func ValidateDeployment(ctx context.Context, client *ethclient.Client, d *Deployment) error {
	head, err := ReadHeader(ctx, client, nil)
	if err != nil {
		return err
	}
	return ValidateDeploymentAt(ctx, client, d, head)
}

func ValidateDeploymentAt(ctx context.Context, client *ethclient.Client, d *Deployment, head *Header) error {
	if d.DeploymentID != deploymentID(d) {
		return fmt.Errorf("DEPLOYMENT_MISMATCH: deploymentId")
	}
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return err
	}
	if chainID.String() != d.ChainID {
		return fmt.Errorf("DEPLOYMENT_MISMATCH: chainId")
	}
	genesis, err := ReadHeader(ctx, client, big.NewInt(0))
	if err != nil {
		return err
	}
	if genesis.Hash != d.GenesisHash {
		return fmt.Errorf("DEPLOYMENT_MISMATCH: genesisHash")
	}
	block := new(big.Int).SetUint64(uint64(head.Number))
	code, err := client.CodeAt(ctx, d.RegistryAddress, block)
	if err != nil {
		return err
	}
	if len(code) == 0 || crypto.Keccak256Hash(code) != d.RuntimeCodeHash {
		return fmt.Errorf("DEPLOYMENT_MISMATCH: runtimeCodeHash")
	}
	values := map[string]any{"instanceId": common.HexToHash(d.InstanceID), "schemaVersion": d.SchemaVersion, "resourceId": d.ResourceID, "resourceOwner": d.ResourceOwner}
	if d.TaskDomain != (common.Hash{}) || d.TaskCreator != (common.Hash{}) {
		values["taskDomain"], values["taskCreator"], values["genesisHash"], values["deploymentId"] = d.TaskDomain, d.TaskCreator, d.GenesisHash, common.HexToHash(d.DeploymentID)
	}
	for method, want := range values {
		v, err := ReadView(ctx, client, d, block, method)
		if err != nil {
			return err
		}
		a, _ := json.Marshal(v[0])
		b, _ := json.Marshal(want)
		if string(a) != string(b) {
			// ABI bytes32 decodes as [32]byte; compare it as a hash.
			if h, ok := v[0].([32]byte); ok {
				if expected, ok := want.(common.Hash); ok && common.Hash(h) == expected {
					continue
				}
			}
			return fmt.Errorf("DEPLOYMENT_MISMATCH: %s", method)
		}
	}
	v, err := ReadView(ctx, client, d, block, "getRoot")
	if err != nil {
		return err
	}
	root := abi.ConvertType(v[0], new(RootRecord)).(*RootRecord)
	a, _ := json.Marshal(root)
	b, _ := json.Marshal(d.Root)
	if string(a) != string(b) {
		return fmt.Errorf("DEPLOYMENT_MISMATCH: RootRecord")
	}
	confirmed, err := ReadHeader(ctx, client, block)
	if err != nil {
		return err
	}
	if confirmed.Hash != head.Hash || confirmed.Timestamp != head.Timestamp {
		return fmt.Errorf("BLOCK_HASH_CHANGED: deployment verification")
	}
	return nil
}
