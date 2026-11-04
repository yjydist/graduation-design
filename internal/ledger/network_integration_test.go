package ledger

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// Run only against an explicitly selected local instance. This test broadcasts
// one signed transaction that must be rejected by account permissioning.
func TestAccountPermissioningIntegration(t *testing.T) {
	dir := os.Getenv("LEDGER_INSTANCE")
	if dir == "" {
		t.Skip("set LEDGER_INSTANCE and LEDGER_EVIDENCE to run against Besu")
	}
	out := os.Getenv("LEDGER_EVIDENCE")
	if out == "" {
		t.Fatal("LEDGER_EVIDENCE is required")
	}
	m, err := LoadInstance(dir)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://127.0.0.1:18547"
	samples := []any{}
	result := map[string]any{"passed": false, "instanceId": m.InstanceID, "synthetic": true, "endpoint": endpoint}
	defer func() {
		if err := os.MkdirAll(out, 0755); err != nil {
			t.Error(err)
			return
		}
		result["passed"] = !t.Failed()
		result["rpc"] = samples
		if err := writeJSON(filepath.Join(out, "account-permissioning.json"), result); err != nil {
			t.Error(err)
		}
	}()
	call := func(method string, params []any) map[string]json.RawMessage {
		t.Helper()
		request := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
		b, _ := json.Marshal(request)
		client := &http.Client{Timeout: 3 * time.Second}
		response, err := client.Post(endpoint, "application/json", bytes.NewReader(b))
		if err != nil {
			samples = append(samples, map[string]any{"request": request, "error": err.Error()})
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil || response.StatusCode != 200 {
			t.Fatalf("HTTP RPC failed: %v status=%d", err, response.StatusCode)
		}
		samples = append(samples, map[string]any{"observedAt": time.Now().UTC(), "request": request, "response": json.RawMessage(body)})
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	key, err := crypto.LoadECDSA(filepath.Join(dir, "keys", "unpermitted", "management.key"))
	if err != nil {
		t.Fatal(err)
	}
	address := crypto.PubkeyToAddress(key.PublicKey)
	balance := call("eth_getBalance", []any{address.Hex(), "latest"})
	if balance["error"] != nil || string(balance["result"]) == `"0x0"` {
		t.Fatal("negative account must be prefunded")
	}
	nonceResult := call("eth_getTransactionCount", []any{address.Hex(), "pending"})
	var nonceHex string
	if err := json.Unmarshal(nonceResult["result"], &nonceHex); err != nil {
		t.Fatal(err)
	}
	nonce, ok := new(big.Int).SetString(strings.TrimPrefix(nonceHex, "0x"), 16)
	if !ok {
		t.Fatal("invalid nonce")
	}
	// Legacy EIP-155 transfer with no state effect even if erroneously accepted.
	fields := []any{nonce, big.NewInt(1000), uint64(21000), common.Address(address), big.NewInt(0), []byte{}}
	preimage, err := rlp.EncodeToBytes(append(append([]any{}, fields...), m.ChainID, uint64(0), uint64(0)))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.Sign(crypto.Keccak256(preimage), key)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := rlp.EncodeToBytes(append(fields, m.ChainID*2+35+uint64(sig[64]), new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:64])))
	if err != nil {
		t.Fatal(err)
	}
	txHash := crypto.Keccak256Hash(signed).Hex()
	result["rawSignedTransaction"] = "0x" + hex.EncodeToString(signed)
	result["txHash"] = txHash
	response := call("eth_sendRawTransaction", []any{"0x" + hex.EncodeToString(signed)})
	var rejection struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(response["error"], &rejection) != nil || rejection.Code != -32007 || rejection.Message != "Sender account not authorized to send transactions" {
		t.Fatalf("expected account permission rejection: %s", response["error"])
	}
	for _, method := range []string{"eth_getTransactionByHash", "eth_getTransactionReceipt"} {
		r := call(method, []any{txHash})
		if r["error"] != nil || string(r["result"]) != "null" {
			t.Fatalf("rejected transaction must not be known: %s", method)
		}
	}
	after := call("eth_getBalance", []any{address.Hex(), "latest"})
	if !bytes.Equal(after["result"], balance["result"]) {
		t.Fatal("balance changed after rejected transaction")
	}
}
