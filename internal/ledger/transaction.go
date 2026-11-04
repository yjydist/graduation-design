package ledger

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Operation struct {
	ID                 string          `json:"operationId"`
	InputDigest        string          `json:"inputDigest"`
	Sender             common.Address  `json:"sender"`
	Target             *common.Address `json:"target"`
	Nonce              uint64          `json:"nonce"`
	Raw                hexutil.Bytes   `json:"rawSignedTransaction"`
	TxHash             common.Hash     `json:"txHash"`
	Status             string          `json:"status"`
	FailureCode        string          `json:"failureCode,omitempty"`
	Receipt            *types.Receipt  `json:"receipt,omitempty"`
	LastBroadcastError string          `json:"lastBroadcastError,omitempty"`
	TraceAttempts      []TraceEvidence `json:"traceAttempts,omitempty"`
}

func durableJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func acquireLock(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "operator.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another operator holds the instance lock: %w", err)
	}
	return f, nil
}

func releaseLock(f *os.File) { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }

// Submit retains the operation lock through confirmation. Recovery uses only
// the persisted signed bytes; ambiguous broadcast responses remain PENDING.
func Submit(ctx context.Context, client *ethclient.Client, dir, operationID string, key *ecdsa.PrivateKey, target *common.Address, data []byte, chainID uint64) (*Operation, error) {
	lock, err := acquireLock(dir)
	if err != nil {
		return nil, err
	}
	defer releaseLock(lock)
	op, tx, err := prepareOperation(ctx, client, dir, operationID, key, target, data, chainID)
	if err != nil {
		return nil, err
	}
	if op.Status != "PENDING" {
		return op, nil
	}
	return awaitOperation(ctx, client, dir, op, tx, false)
}

func prepareOperation(ctx context.Context, client *ethclient.Client, dir, operationID string, key *ecdsa.PrivateKey, target *common.Address, data []byte, chainID uint64) (*Operation, *types.Transaction, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,80}$`).MatchString(operationID) {
		return nil, nil, fmt.Errorf("invalid operation id")
	}

	opsDir := filepath.Join(dir, "operations")
	if err := os.MkdirAll(opsDir, 0700); err != nil {
		return nil, nil, err
	}
	sender := crypto.PubkeyToAddress(key.PublicKey)
	input, _ := json.Marshal(map[string]any{"sender": sender, "target": target, "data": hexutil.Bytes(data), "chainId": chainID})
	digest := sha256.Sum256(input)
	path := filepath.Join(opsDir, operationID+".json")
	op := &Operation{ID: operationID, InputDigest: hex.EncodeToString(digest[:]), Sender: sender, Target: target, Status: "PENDING"}
	b, err := os.ReadFile(path)
	var tx *types.Transaction
	if err == nil {
		var saved Operation
		if err = json.Unmarshal(b, &saved); err != nil {
			return nil, nil, err
		}
		if saved.InputDigest != op.InputDigest || saved.ID != operationID {
			return nil, nil, fmt.Errorf("operation input conflict: %s", operationID)
		}
		op = &saved
		tx = new(types.Transaction)
		if err = tx.UnmarshalBinary(op.Raw); err != nil {
			return nil, nil, err
		}
		from, err := types.Sender(types.NewEIP155Signer(new(big.Int).SetUint64(chainID)), tx)
		if err != nil || from != sender || op.Sender != sender || tx.Hash() != op.TxHash || tx.Nonce() != op.Nonce || !bytes.Equal(tx.Data(), data) ||
			!equalAddress(tx.To(), target) || !equalAddress(op.Target, target) || tx.Value().Sign() != 0 {
			return nil, nil, fmt.Errorf("persisted transaction mismatch")
		}
		if op.Status == "CONFIRMED" || op.Status == "FAILED" {
			return op, tx, nil
		}
		if op.Status != "PENDING" {
			return nil, nil, fmt.Errorf("invalid persisted operation state")
		}
	} else if os.IsNotExist(err) {
		nonce, err := client.PendingNonceAt(ctx, sender)
		if err != nil {
			return nil, nil, err
		}
		entries, err := os.ReadDir(opsDir)
		if err != nil {
			return nil, nil, err
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(opsDir, entry.Name()))
			if err != nil {
				return nil, nil, err
			}
			var prior Operation
			if err = json.Unmarshal(b, &prior); err != nil {
				return nil, nil, err
			}
			if prior.Sender == sender && prior.Nonce >= nonce {
				if prior.Nonce == ^uint64(0) {
					return nil, nil, fmt.Errorf("account nonce exhausted")
				}
				nonce = prior.Nonce + 1
			}
		}
		gas := uint64(8_000_000)
		if target == nil {
			gas = 25_000_000
		}
		tx, err = types.SignTx(types.NewTx(&types.LegacyTx{Nonce: nonce, To: target, Gas: gas, GasPrice: big.NewInt(1000), Value: new(big.Int), Data: data}), types.NewEIP155Signer(new(big.Int).SetUint64(chainID)), key)
		if err != nil {
			return nil, nil, err
		}
		op.Raw, err = tx.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		op.Nonce, op.TxHash = nonce, tx.Hash()
		if err = durableJSON(path, op); err != nil {
			return nil, nil, err
		}
	} else {
		return nil, nil, err
	}

	return op, tx, nil
}

type BatchAction struct {
	ID     string
	Key    *ecdsa.PrivateKey `json:"-"`
	Target *common.Address
	Data   []byte
}

// SubmitBatch durably prepares every signed operation before broadcasting any.
// Receipts are observed only after all pending operations have been broadcast.
func SubmitBatch(ctx context.Context, client *ethclient.Client, dir string, actions []BatchAction, chainID uint64) ([]*Operation, error) {
	lock, err := acquireLock(dir)
	if err != nil {
		return nil, err
	}
	defer releaseLock(lock)
	ops := make([]*Operation, 0, len(actions))
	txs := make([]*types.Transaction, 0, len(actions))
	for _, action := range actions {
		op, tx, err := prepareOperation(ctx, client, dir, action.ID, action.Key, action.Target, action.Data, chainID)
		if err != nil {
			return ops, err
		}
		ops = append(ops, op)
		txs = append(txs, tx)
	}
	for i, op := range ops {
		if op.Status != "PENDING" {
			continue
		}
		if err := client.SendTransaction(ctx, txs[i]); err != nil {
			op.LastBroadcastError = err.Error()
		}
		if err := durableJSON(filepath.Join(dir, "operations", op.ID+".json"), op); err != nil {
			return ops, err
		}
	}
	for i, op := range ops {
		if op.Status != "PENDING" {
			continue
		}
		ops[i], err = awaitOperation(ctx, client, dir, op, txs[i], true)
		if err != nil {
			return ops, err
		}
	}
	return ops, nil
}

func awaitOperation(ctx context.Context, client *ethclient.Client, dir string, op *Operation, tx *types.Transaction, broadcast bool) (*Operation, error) {

	path := filepath.Join(dir, "operations", op.ID+".json")
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		receipt, err := client.TransactionReceipt(ctx, op.TxHash)
		if err == nil {
			if err = validateReceipt(ctx, client, tx, receipt); err != nil {
				return op, err
			}
			op.Receipt = receipt
			if receipt.Status == types.ReceiptStatusSuccessful {
				op.Status = "CONFIRMED"
			} else {
				op.Status, op.FailureCode = "FAILED", "TRANSACTION_REVERTED"
			}
			if err = durableJSON(path, op); err != nil {
				return op, err
			}
			return op, nil
		}
		if ctx.Err() != nil {
			return op, fmt.Errorf("operation %s remains PENDING: %w", op.ID, ctx.Err())
		}
		if err != ethereum.NotFound {
			// Transient receipt errors are ambiguous and must not trigger a replacement.
			op.LastBroadcastError = "receipt: " + err.Error()
		}
		if !broadcast {
			if err = client.SendTransaction(ctx, tx); err != nil {
				op.LastBroadcastError = err.Error()
			}
			if err = durableJSON(path, op); err != nil {
				return op, err
			}
			broadcast = true
		}
		select {
		case <-ctx.Done():
			return op, fmt.Errorf("operation %s remains PENDING: %w", op.ID, ctx.Err())
		case <-ticker.C:
		}
	}
}

func equalAddress(a, b *common.Address) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func validateReceipt(ctx context.Context, client *ethclient.Client, tx *types.Transaction, receipt *types.Receipt) error {
	if receipt.TxHash != tx.Hash() || receipt.BlockNumber == nil || (receipt.Status != 0 && receipt.Status != 1) {
		return fmt.Errorf("receipt mismatch")
	}
	header, err := ReadHeader(ctx, client, receipt.BlockNumber)
	if err != nil {
		return err
	}
	if header.Hash != receipt.BlockHash {
		return fmt.Errorf("receipt block mismatch")
	}
	stored, err := client.TransactionInBlock(ctx, receipt.BlockHash, receipt.TransactionIndex)
	if err != nil {
		return err
	}
	if stored.Hash() != tx.Hash() {
		return fmt.Errorf("receipt transaction position mismatch")
	}
	if tx.To() == nil && receipt.Status == 1 {
		from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
		if err != nil {
			return err
		}
		if receipt.ContractAddress != crypto.CreateAddress(from, tx.Nonce()) {
			return fmt.Errorf("contract address mismatch")
		}
	}
	return nil
}
