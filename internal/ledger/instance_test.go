package ledger

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

func TestInstanceReopenAndRebuild(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "instance")
	m, created, err := InitInstance(dir)
	if err != nil || !created {
		t.Fatalf("create: %v", err)
	}
	before := map[string]string{}
	err = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		before[path] = string(b)
		if strings.HasSuffix(path, ".key") || strings.HasSuffix(path, ".pem") || entry.Name() == "key" {
			info, _ := entry.Info()
			if info.Mode().Perm() != 0600 {
				t.Errorf("private key permissions: %s", path)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	reopened, created, err := InitInstance(dir)
	if err != nil || created || reopened.InstanceID != m.InstanceID {
		t.Fatalf("reopen changed identity: %v", err)
	}
	for path, want := range before {
		b, err := os.ReadFile(path)
		if err != nil || string(b) != want {
			t.Errorf("reopen changed file %s", path)
		}
	}
	other, _, err := InitInstance(filepath.Join(t.TempDir(), "new-instance"))
	if err != nil || other.InstanceID == m.InstanceID || other.Validators[0].Address == m.Validators[0].Address || other.Accounts[0].Address == m.Accounts[0].Address {
		t.Fatalf("rebuild must use fresh identities: %v", err)
	}
}

func TestInstanceRejectsDamagedMaterial(t *testing.T) {
	for _, name := range []string{"instance.json", "genesis.json", "nodes/A/key", "nodes/C/permissions_config.toml", "keys/T/management.key", "keys/U/application.pem", "keys/IA/did.json"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "instance")
			if _, _, err := InitInstance(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("damaged"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := InitInstance(dir); err == nil {
				t.Fatal("accepted damaged material")
			}
			b, _ := os.ReadFile(path)
			if string(b) != "damaged" {
				t.Fatal("regenerated damaged material")
			}
		})
	}
}

func TestIncompleteInstanceIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := InitInstance(dir); err == nil {
		t.Fatal("accepted uninitialized directory")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("wrote into uninitialized directory")
	}
}

func TestPermissionsSeparateValidatorsAndAccounts(t *testing.T) {
	m, _, err := InitInstance(filepath.Join(t.TempDir(), "instance"))
	if err != nil {
		t.Fatal(err)
	}
	genesis, permissions, err := networkMaterial(m)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := hex.DecodeString(strings.TrimPrefix(genesis["extraData"].(string), "0x"))
	if err != nil {
		t.Fatal(err)
	}
	var extra struct {
		Vanity     []byte
		Validators []common.Address
		Vote       []rlp.RawValue
		Round      uint64
		Seals      []rlp.RawValue
	}
	if err := rlp.DecodeBytes(encoded, &extra); err != nil || len(extra.Validators) != 4 || len(extra.Vote) != 0 {
		t.Fatalf("invalid QBFT extra data: %v", err)
	}
	alloc := genesis["alloc"].(map[string]any)
	for _, a := range m.Accounts {
		if alloc[strings.TrimPrefix(a.Address, "0x")] == nil {
			t.Errorf("not prefunded: %s", a.Role)
		}
		if strings.Contains(permissions, a.Address) != (a.Role != "unpermitted") {
			t.Errorf("wrong account permission: %s", a.Role)
		}
	}
	for _, v := range m.Validators {
		if strings.Contains(permissions, `"`+v.Address+`"`) || !strings.Contains(permissions, v.Enode) {
			t.Errorf("validator/account role mixed: %s", v.Role)
		}
	}
}
