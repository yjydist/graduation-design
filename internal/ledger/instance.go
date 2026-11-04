package ledger

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

const ChainID = 20261104

type Validator struct {
	Role       string `json:"role"`
	Controller string `json:"controller"`
	Address    string `json:"address"`
	PublicKey  string `json:"publicKey"`
	IP         string `json:"ip"`
	Enode      string `json:"enode"`
}

type Account struct {
	Role       string            `json:"role"`
	Address    string            `json:"managementIdentity"`
	SubjectID  string            `json:"subjectId"`
	AppKeyID   string            `json:"appKeyId"`
	AppVersion uint64            `json:"appKeyVersion"`
	AppPublic  string            `json:"appPublicKey"`
	JWK        map[string]string `json:"publicKeyJwk"`
	DIDDigest  string            `json:"didDocumentDigest"`
}

// Instance contains public initialization material, never private keys.
type Instance struct {
	InstanceID string      `json:"instanceId"`
	ChainID    uint64      `json:"chainId"`
	Synthetic  bool        `json:"synthetic"`
	Validators []Validator `json:"validators"`
	Accounts   []Account   `json:"accounts"`
}

var accountRoles = []string{
	"T", "deployer", "domainA", "adminA", "registrarA", "IA",
	"domainB", "adminB", "registrarB", "IB", "domainC", "adminC", "registrarC", "IC",
	"U", "A1", "B1", "C", "unrelated", "unpermitted",
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}

// InitInstance creates a new directory atomically, or validates an existing one.
// A damaged or partially initialized directory is never repaired by regenerating keys.
func InitInstance(path string) (*Instance, bool, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, false, err
	}
	if _, err = os.Lstat(path); err == nil {
		m, err := LoadInstance(path)
		return m, false, err
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, false, err
	}
	staging, err := os.MkdirTemp(filepath.Dir(path), ".ledger-init-")
	if err != nil {
		return nil, false, err
	}
	defer os.RemoveAll(staging)
	m, err := generateInstance(staging)
	if err != nil {
		return nil, false, err
	}
	if err = os.Rename(staging, path); err != nil {
		return nil, false, err
	}
	return m, true, nil
}

func generateInstance(dir string) (*Instance, error) {
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	m := &Instance{InstanceID: hex.EncodeToString(id), ChainID: ChainID, Synthetic: true}
	for i, role := range []string{"A", "B", "C", "ops"} {
		nodeDir := filepath.Join(dir, "nodes", role)
		if err := os.MkdirAll(nodeDir, 0700); err != nil {
			return nil, err
		}
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, err
		}
		if err = crypto.SaveECDSA(filepath.Join(nodeDir, "key"), key); err != nil {
			return nil, err
		}
		pub := hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey)[1:])
		ip := fmt.Sprintf("172.28.61.%d", i+11)
		m.Validators = append(m.Validators, Validator{
			Role: role, Controller: role, Address: strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex()),
			PublicKey: pub, IP: ip, Enode: fmt.Sprintf("enode://%s@%s:30303", pub, ip),
		})
	}
	for _, role := range accountRoles {
		keyDir := filepath.Join(dir, "keys", role)
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return nil, err
		}
		management, err := crypto.GenerateKey()
		if err != nil {
			return nil, err
		}
		if err = crypto.SaveECDSA(filepath.Join(keyDir, "management.key"), management); err != nil {
			return nil, err
		}
		app, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(app)
		if err != nil {
			return nil, err
		}
		if err = os.WriteFile(filepath.Join(keyDir, "application.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
			return nil, err
		}
		a := publicAccount(role, management, app)
		if err = writeJSON(filepath.Join(keyDir, "did.json"), didDocument(a)); err != nil {
			return nil, err
		}
		m.Accounts = append(m.Accounts, a)
	}
	if err := writeNetworkFiles(dir, m); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(dir, "instance.json"), m); err != nil {
		return nil, err
	}
	return m, nil
}

func publicAccount(role string, management, app *ecdsa.PrivateKey) Account {
	subject := "did:web:grad.example.test:subjects:" + role
	a := Account{
		Role: role, Address: strings.ToLower(crypto.PubkeyToAddress(management.PublicKey).Hex()),
		SubjectID: subject, AppKeyID: subject + "#key-1", AppVersion: 1,
		AppPublic: "0x" + hex.EncodeToString(elliptic.Marshal(elliptic.P256(), app.X, app.Y)),
		JWK:       map[string]string{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(app.X.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(app.Y.FillBytes(make([]byte, 32)))},
	}
	// All generated values are ASCII strings. Sorted map keys and compact encoding
	// therefore coincide with JCS for this restricted document schema.
	b, _ := json.Marshal(didDocument(a))
	digest := sha256.Sum256(b)
	a.DIDDigest = hex.EncodeToString(digest[:])
	return a
}

func didDocument(a Account) map[string]any {
	return map[string]any{
		"id": a.SubjectID, "authentication": []string{a.AppKeyID}, "assertionMethod": []string{a.AppKeyID},
		"verificationMethod": []any{map[string]any{"id": a.AppKeyID, "type": "JsonWebKey", "controller": a.SubjectID, "publicKeyJwk": a.JWK}},
	}
}

func networkMaterial(m *Instance) (map[string]any, string, error) {
	validators := make([]common.Address, 0, 4)
	enodes := make([]string, 0, 4)
	for _, v := range m.Validators {
		validators = append(validators, common.HexToAddress(v.Address))
		enodes = append(enodes, fmt.Sprintf("%q", v.Enode))
	}
	extra, err := rlp.EncodeToBytes([]any{make([]byte, 32), validators, []any{}, uint64(0), []any{}})
	if err != nil {
		return nil, "", err
	}
	alloc := map[string]any{}
	accounts := []string{}
	for _, a := range m.Accounts {
		alloc[strings.TrimPrefix(a.Address, "0x")] = map[string]string{"balance": "1000000000000000000000"}
		if a.Role != "unpermitted" {
			accounts = append(accounts, fmt.Sprintf("%q", a.Address))
		}
	}
	genesis := map[string]any{
		"config": map[string]any{"chainId": m.ChainID, "berlinBlock": 0, "qbft": map[string]any{"blockperiodseconds": 1, "epochlength": 30000, "requesttimeoutseconds": 4}},
		"nonce":  "0x0", "timestamp": "0x0", "extraData": "0x" + hex.EncodeToString(extra),
		"gasLimit": "0x2faf080", "difficulty": "0x1", "mixHash": "0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365",
		"coinbase": "0x0000000000000000000000000000000000000000", "alloc": alloc,
	}
	permissions := "nodes-allowlist=[" + strings.Join(enodes, ",") + "]\naccounts-allowlist=[" + strings.Join(accounts, ",") + "]\n"
	return genesis, permissions, nil
}

func writeNetworkFiles(dir string, m *Instance) error {
	genesis, permissions, err := networkMaterial(m)
	if err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "genesis.json"), genesis); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "static-nodes.json"), staticNodes(m)); err != nil {
		return err
	}
	for _, v := range m.Validators {
		if err = os.WriteFile(filepath.Join(dir, "nodes", v.Role, "permissions_config.toml"), []byte(permissions), 0600); err != nil {
			return err
		}
	}
	return nil
}

func staticNodes(m *Instance) []string {
	result := make([]string, 0, len(m.Validators))
	for _, v := range m.Validators {
		result = append(result, v.Enode)
	}
	return result
}

// LoadInstance rederives all public identities and checks immutable network material.
func LoadInstance(dir string) (*Instance, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("instance must be an existing directory: %s", dir)
	}
	b, err := os.ReadFile(filepath.Join(dir, "instance.json"))
	if err != nil {
		return nil, fmt.Errorf("instance incomplete; choose a new directory: %w", err)
	}
	var m Instance
	if err = json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	id, err := hex.DecodeString(m.InstanceID)
	if err != nil || len(id) != 32 || hex.EncodeToString(id) != m.InstanceID || m.ChainID != ChainID || !m.Synthetic || len(m.Validators) != 4 || len(m.Accounts) != len(accountRoles) {
		return nil, fmt.Errorf("invalid instance metadata")
	}
	seen := map[string]bool{}
	for i, v := range m.Validators {
		role := []string{"A", "B", "C", "ops"}[i]
		key, err := crypto.LoadECDSA(filepath.Join(dir, "nodes", role, "key"))
		if err != nil {
			return nil, err
		}
		address := strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
		pub := hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey)[1:])
		ip := fmt.Sprintf("172.28.61.%d", i+11)
		if v.Role != role || v.Controller != role || v.Address != address || v.PublicKey != pub || v.IP != ip || v.Enode != fmt.Sprintf("enode://%s@%s:30303", pub, ip) || seen[address] {
			return nil, fmt.Errorf("validator material mismatch: %s", role)
		}
		seen[address] = true
	}
	for i, a := range m.Accounts {
		role := accountRoles[i]
		keyDir := filepath.Join(dir, "keys", role)
		management, err := crypto.LoadECDSA(filepath.Join(keyDir, "management.key"))
		if err != nil {
			return nil, err
		}
		pemBytes, err := os.ReadFile(filepath.Join(keyDir, "application.pem"))
		if err != nil {
			return nil, err
		}
		block, rest := pem.Decode(pemBytes)
		if block == nil || block.Type != "EC PRIVATE KEY" || len(rest) != 0 {
			return nil, fmt.Errorf("invalid application PEM: %s", role)
		}
		app, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil || app.Curve != elliptic.P256() {
			return nil, fmt.Errorf("invalid P-256 key: %s", role)
		}
		expected := publicAccount(role, management, app)
		if !reflect.DeepEqual(a, expected) || seen[a.Address] {
			return nil, fmt.Errorf("account material mismatch: %s", role)
		}
		seen[a.Address] = true
		if err = checkJSON(filepath.Join(keyDir, "did.json"), didDocument(a)); err != nil {
			return nil, err
		}
	}
	genesis, permissions, err := networkMaterial(&m)
	if err != nil {
		return nil, err
	}
	if err = checkJSON(filepath.Join(dir, "genesis.json"), genesis); err != nil {
		return nil, err
	}
	if err = checkJSON(filepath.Join(dir, "static-nodes.json"), staticNodes(&m)); err != nil {
		return nil, err
	}
	for _, v := range m.Validators {
		b, err = os.ReadFile(filepath.Join(dir, "nodes", v.Role, "permissions_config.toml"))
		if err != nil || strings.TrimSpace(string(b)) != strings.TrimSpace(permissions) {
			return nil, fmt.Errorf("permissions mismatch: %s", v.Role)
		}
	}
	return &m, nil
}

func checkJSON(path string, expected any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var actual any
	if err = json.Unmarshal(b, &actual); err != nil {
		return err
	}
	canonical, _ := json.Marshal(actual)
	want, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	if string(canonical) != string(want) {
		return fmt.Errorf("instance material mismatch: %s", path)
	}
	return nil
}
