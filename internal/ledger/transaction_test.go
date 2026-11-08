package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type transactionRPC struct {
	mu                       sync.Mutex
	hide                     bool
	accept                   bool
	loseResponse             bool
	wrongReceipt             bool
	txs                      map[common.Hash]*types.Transaction
	byNonce                  map[uint64]*types.Transaction
	broadcasts               [][]byte
	nonceQueries             int
	dir                      string
	opID                     string
	persistedBeforeBroadcast bool
}

func (m *transactionRPC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var q struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&q)
	response := map[string]any{"jsonrpc": "2.0", "id": q.ID}
	var result any
	switch q.Method {
	case "eth_getTransactionCount":
		m.nonceQueries++
		result = "0x0"
	case "eth_sendRawTransaction":
		var raw hexutil.Bytes
		_ = json.Unmarshal(q.Params[0], &raw)
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(raw); err != nil {
			panic(err)
		}
		m.broadcasts = append(m.broadcasts, append([]byte{}, raw...))
		b, err := os.ReadFile(filepath.Join(m.dir, "operations", m.opID+".json"))
		var saved Operation
		if err == nil && json.Unmarshal(b, &saved) == nil && saved.Status == "PENDING" && saved.TxHash == tx.Hash() && bytes.Equal(saved.Raw, raw) {
			m.persistedBeforeBroadcast = true
		}
		if m.accept {
			m.txs[tx.Hash()] = tx
			m.byNonce[tx.Nonce()] = tx
		}
		if m.loseResponse {
			response["error"] = map[string]any{"code": -32000, "message": "injected lost broadcast response"}
		} else {
			result = tx.Hash()
		}
	case "eth_getTransactionReceipt":
		var hash common.Hash
		_ = json.Unmarshal(q.Params[0], &hash)
		if tx := m.txs[hash]; tx != nil && !m.hide {
			if m.wrongReceipt {
				hash[0] ^= 1
			}
			result = &types.Receipt{Type: 0, Status: 1, CumulativeGasUsed: 21000, Logs: []*types.Log{}, TxHash: hash, GasUsed: 21000, BlockHash: common.Hash{1}, BlockNumber: big.NewInt(1), TransactionIndex: uint(tx.Nonce())}
		}
	case "eth_getBlockByNumber":
		result = map[string]any{"number": "0x1", "hash": common.Hash{1}, "timestamp": "0x1", "parentHash": common.Hash{}}
	case "eth_getTransactionByBlockHashAndIndex":
		var index string
		_ = json.Unmarshal(q.Params[1], &index)
		n, _ := strconv.ParseUint(index[2:], 16, 64)
		result = m.byNonce[n]
	default:
		response["error"] = map[string]any{"code": -32601, "message": "unexpected method " + q.Method}
	}
	if response["error"] == nil {
		response["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func newTransactionRPC(t *testing.T, dir, id string) (*transactionRPC, string) {
	t.Helper()
	m := &transactionRPC{accept: true, txs: map[common.Hash]*types.Transaction{}, byNonce: map[uint64]*types.Transaction{}, dir: dir, opID: id}
	s := httptest.NewServer(m)
	t.Cleanup(s.Close)
	return m, s.URL
}

func TestPendingTransactionRecovery(t *testing.T) {
	for _, name := range []string{"broadcast-response-lost", "receipt-hidden", "broadcast-not-delivered"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			m, url := newTransactionRPC(t, dir, "op")
			m.hide = true
			m.loseResponse = name != "receipt-hidden"
			m.accept = name != "broadcast-not-delivered"
			key, _ := crypto.GenerateKey()
			target := common.Address{2}
			client, err := ethclient.Dial(url)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
			op, err := Submit(ctx, client, dir, "op", key, &target, []byte{1, 2}, ChainID)
			cancel()
			client.Close()
			if err == nil || op == nil || op.Status != "PENDING" || op.Receipt != nil {
				t.Fatalf("must preserve pending operation: %v", err)
			}
			before := cloneValue(*op)
			m.mu.Lock()
			m.hide = false
			m.accept = true
			m.loseResponse = false
			m.mu.Unlock()
			client, err = ethclient.Dial(url)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			recovered, err := Submit(ctx, client, dir, "op", key, &target, []byte{1, 2}, ChainID)
			if err != nil || recovered.Status != "CONFIRMED" || recovered.TxHash != before.TxHash || recovered.Nonce != before.Nonce || !bytes.Equal(recovered.Raw, before.Raw) {
				t.Fatalf("recovery replaced operation: %v", err)
			}
			m.mu.Lock()
			defer m.mu.Unlock()
			if !m.persistedBeforeBroadcast || m.nonceQueries != 1 {
				t.Fatal("transaction not persisted before broadcast, or nonce reallocated")
			}
			want := 1
			if name == "broadcast-not-delivered" {
				want = 2
			}
			if len(m.broadcasts) != want {
				t.Fatalf("broadcast count %d", len(m.broadcasts))
			}
			for _, raw := range m.broadcasts {
				if !bytes.Equal(raw, before.Raw) {
					t.Fatal("replay changed signed bytes")
				}
			}
		})
	}
}

func TestOperatorLockAndNonceSequence(t *testing.T) {
	dir := t.TempDir()
	m, url := newTransactionRPC(t, dir, "first")
	client, _ := ethclient.Dial(url)
	defer client.Close()
	key, _ := crypto.GenerateKey()
	target := common.Address{2}
	lock, err := acquireLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(context.Background(), client, dir, "blocked", key, &target, nil, ChainID); err == nil {
		t.Fatal("parallel operator acquired lock")
	}
	releaseLock(lock)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	first, err := Submit(ctx, client, dir, "first", key, &target, nil, ChainID)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.opID = "second"
	m.mu.Unlock()
	second, err := Submit(ctx, client, dir, "second", key, &target, nil, ChainID)
	if err != nil {
		t.Fatal(err)
	}
	if first.Nonce != 0 || second.Nonce != 1 {
		t.Fatal("nonce journal did not serialize allocation")
	}
	if _, err := Submit(ctx, client, dir, "first", key, &target, []byte{9}, ChainID); err == nil {
		t.Fatal("accepted operation input conflict")
	}
}

func TestReceiptMismatchStaysPending(t *testing.T) {
	dir := t.TempDir()
	m, url := newTransactionRPC(t, dir, "op")
	m.wrongReceipt = true
	client, _ := ethclient.Dial(url)
	defer client.Close()
	key, _ := crypto.GenerateKey()
	target := common.Address{2}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	op, err := Submit(ctx, client, dir, "op", key, &target, nil, ChainID)
	if err == nil || op.Status != "PENDING" {
		t.Fatalf("accepted mismatched receipt: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "operations", "op.json"))
	var saved Operation
	json.Unmarshal(b, &saved)
	if saved.Status != "PENDING" || saved.Receipt != nil {
		t.Fatal("persisted false confirmation")
	}
}

func TestJournalTargetMismatch(t *testing.T) {
	dir := t.TempDir()
	m, url := newTransactionRPC(t, dir, "op")
	m.hide = true
	client, _ := ethclient.Dial(url)
	defer client.Close()
	key, _ := crypto.GenerateKey()
	target := common.Address{2}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	op, _ := Submit(ctx, client, dir, "op", key, &target, nil, ChainID)
	cancel()
	other := common.Address{3}
	tx, _ := types.SignTx(types.NewTx(&types.LegacyTx{Nonce: op.Nonce, To: &other, Gas: 8000000, GasPrice: big.NewInt(1000), Value: new(big.Int)}), types.NewEIP155Signer(big.NewInt(ChainID)), key)
	op.Raw, _ = tx.MarshalBinary()
	op.TxHash = tx.Hash()
	if err := durableJSON(filepath.Join(dir, "operations", "op.json"), op); err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(context.Background(), client, dir, "op", key, &target, nil, ChainID); err == nil {
		t.Fatal("accepted signed transaction to a different target")
	}
}
