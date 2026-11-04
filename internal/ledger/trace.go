package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type TraceEvidence struct {
	TxHash            common.Hash     `json:"txHash"`
	BlockHash         common.Hash     `json:"blockHash"`
	BlockNumber       string          `json:"blockNumber"`
	TransactionIndex  uint            `json:"transactionIndex"`
	Method            string          `json:"method"`
	Options           map[string]any  `json:"options"`
	Raw               json.RawMessage `json:"rawResult,omitempty"`
	RevertData        hexutil.Bytes   `json:"revertData,omitempty"`
	FailureCode       string          `json:"failureCode"`
	Error             string          `json:"error,omitempty"`
	BlockTransactions []common.Hash   `json:"blockTransactions,omitempty"`
}

var errTraceMismatch = errors.New("trace execution does not match original receipt")

func decodeCustomError(a abi.ABI, data []byte) (string, error) {
	if len(data) != 4 {
		return "", fmt.Errorf("custom error selector length mismatch")
	}
	for name, e := range a.Errors {
		if bytes.Equal(data, e.ID[:4]) && len(e.Inputs) == 0 {
			codes := map[string]string{"Unauthorized": "UNAUTHORIZED", "StateChanged": "STATE_CHANGED", "InvalidStructure": "INVALID_STRUCTURE", "InvalidState": "INVALID_STATE", "MissingDependency": "MISSING_DEPENDENCY", "IdAlreadyUsed": "ID_ALREADY_USED"}
			if code, ok := codes[name]; ok {
				return code, nil
			}
		}
	}
	return "", fmt.Errorf("unknown custom error selector")
}

// EnrichFailure supplements an immutable FAILED receipt with original execution evidence.
// Trace failures are recorded; they never replace FAILED with PENDING or CONFIRMED.
func EnrichFailure(ctx context.Context, client *ethclient.Client, dir string, op *Operation, a abi.ABI) (*Operation, error) {
	lock, err := acquireLock(dir)
	if err != nil {
		return op, err
	}
	defer releaseLock(lock)
	path := filepath.Join(dir, "operations", op.ID+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return op, err
	}
	var saved Operation
	if err = json.Unmarshal(b, &saved); err != nil {
		return op, err
	}
	if saved.TxHash != op.TxHash || !bytes.Equal(saved.Raw, op.Raw) || saved.Status != "FAILED" || saved.Receipt == nil || saved.Receipt.Status != 0 {
		return op, fmt.Errorf("failure enrichment operation mismatch")
	}
	op = &saved
	if op.FailureCode == "" {
		op.FailureCode = "TRANSACTION_REVERTED"
	}
	evidence := TraceEvidence{TxHash: op.TxHash, BlockHash: op.Receipt.BlockHash, BlockNumber: hexutil.EncodeBig(op.Receipt.BlockNumber), TransactionIndex: op.Receipt.TransactionIndex, Method: "debug_traceTransaction", Options: map[string]any{"tracer": "callTracer"}, FailureCode: "TRANSACTION_REVERTED"}
	tx := new(types.Transaction)
	if err = tx.UnmarshalBinary(op.Raw); err == nil {
		err = validateReceipt(ctx, client, tx, op.Receipt)
	}
	if err == nil {
		err = client.Client().CallContext(ctx, &evidence.Raw, "debug_traceTransaction", op.TxHash, evidence.Options)
	}
	if err == nil {
		var trace struct {
			From      common.Address `json:"from"`
			To        common.Address `json:"to"`
			Input     hexutil.Bytes  `json:"input"`
			Output    hexutil.Bytes  `json:"output"`
			GasUsed   hexutil.Uint64 `json:"gasUsed"`
			Error     string         `json:"error"`
			Type      string         `json:"type"`
			Truncated bool           `json:"truncated"`
		}
		err = json.Unmarshal(evidence.Raw, &trace)
		if err == nil && (trace.Truncated || bytes.Equal(bytes.TrimSpace(evidence.Raw), []byte("null"))) {
			err = fmt.Errorf("trace is incomplete")
		}
		if err == nil && (trace.Type != "CALL" || trace.Error == "" || op.Target == nil || trace.To != *op.Target || trace.From != op.Sender || !bytes.Equal(trace.Input, tx.Data()) || uint64(trace.GasUsed) != op.Receipt.GasUsed) {
			err = errTraceMismatch
		}
		if err == nil {
			evidence.RevertData = trace.Output
			evidence.FailureCode, err = decodeCustomError(a, trace.Output)
			if err == nil {
				op.FailureCode = evidence.FailureCode
			}
		}
	}
	useBlockTrace := errors.Is(err, errTraceMismatch)
	if err != nil {
		evidence.Error = err.Error()
		evidence.FailureCode = "TRANSACTION_REVERTED"
	}
	op.TraceAttempts = append(op.TraceAttempts, evidence)
	if useBlockTrace {
		blockEvidence, blockErr := originalBlockTrace(ctx, client, op, a)
		if blockErr != nil {
			blockEvidence.Error = blockErr.Error()
			blockEvidence.FailureCode = "TRANSACTION_REVERTED"
		} else {
			op.FailureCode = blockEvidence.FailureCode
		}
		op.TraceAttempts = append(op.TraceAttempts, blockEvidence)
	}
	if err = durableJSON(path, op); err != nil {
		return op, err
	}
	return op, nil
}

func originalBlockTrace(ctx context.Context, client *ethclient.Client, op *Operation, a abi.ABI) (TraceEvidence, error) {
	e := TraceEvidence{TxHash: op.TxHash, BlockHash: op.Receipt.BlockHash, BlockNumber: hexutil.EncodeBig(op.Receipt.BlockNumber), TransactionIndex: op.Receipt.TransactionIndex, Method: "debug_traceBlockByHash", Options: map[string]any{"disableMemory": true, "disableStack": true, "disableStorage": true, "opcodes": []string{"REVERT"}}, FailureCode: "TRANSACTION_REVERTED"}
	var block *struct {
		Hash         common.Hash   `json:"hash"`
		Number       hexutil.Big   `json:"number"`
		Transactions []common.Hash `json:"transactions"`
	}
	if err := client.Client().CallContext(ctx, &block, "eth_getBlockByHash", op.Receipt.BlockHash, false); err != nil {
		return e, err
	}
	if block == nil || block.Hash != op.Receipt.BlockHash || (*big.Int)(&block.Number).Cmp(op.Receipt.BlockNumber) != 0 || int(op.Receipt.TransactionIndex) >= len(block.Transactions) || block.Transactions[op.Receipt.TransactionIndex] != op.TxHash {
		return e, fmt.Errorf("original block transaction binding mismatch")
	}
	e.BlockTransactions = append([]common.Hash{}, block.Transactions...)
	if err := client.Client().CallContext(ctx, &e.Raw, "debug_traceBlockByHash", op.Receipt.BlockHash, e.Options); err != nil {
		return e, err
	}
	var entries []struct {
		TxHash common.Hash     `json:"txHash"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(e.Raw, &entries); err != nil {
		return e, err
	}
	if len(entries) != len(block.Transactions) {
		return e, fmt.Errorf("block trace transaction count mismatch")
	}
	for i, entry := range entries {
		if entry.TxHash != block.Transactions[i] {
			return e, fmt.Errorf("block trace transaction order mismatch")
		}
	}
	var result struct {
		Gas         uint64        `json:"gas"`
		Failed      bool          `json:"failed"`
		ReturnValue hexutil.Bytes `json:"returnValue"`
		Truncated   bool          `json:"truncated"`
		Logs        []struct {
			Op     string        `json:"op"`
			Depth  int           `json:"depth"`
			Reason hexutil.Bytes `json:"reason"`
		} `json:"structLogs"`
	}
	if err := json.Unmarshal(entries[op.Receipt.TransactionIndex].Result, &result); err != nil {
		return e, err
	}
	if !result.Failed || result.Gas != op.Receipt.GasUsed || result.Truncated {
		return e, fmt.Errorf("block trace failure or gas mismatch")
	}
	data := []byte(result.ReturnValue)
	for _, step := range result.Logs {
		if step.Op == "REVERT" && step.Depth == 1 {
			if len(data) > 0 && !bytes.Equal(data, step.Reason) {
				return e, fmt.Errorf("conflicting root revert evidence")
			}
			data = step.Reason
		}
	}
	code, err := decodeCustomError(a, data)
	if err != nil {
		return e, err
	}
	header, err := ReadHeader(ctx, client, op.Receipt.BlockNumber)
	if err != nil {
		return e, err
	}
	if header.Hash != op.Receipt.BlockHash {
		return e, fmt.Errorf("original block changed during tracing")
	}
	e.RevertData, e.FailureCode = data, code
	return e, nil
}
