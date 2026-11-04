package ledger

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Header struct {
	Number     hexutil.Uint64 `json:"number"`
	Hash       common.Hash    `json:"hash"`
	ParentHash common.Hash    `json:"parentHash"`
	Timestamp  hexutil.Uint64 `json:"timestamp"`
}

// ReadHeader preserves the trusted node's consensus-specific block hash.
// Ethereum Header.Hash() cannot be used to rehash a QBFT header with commit seals.
func ReadHeader(ctx context.Context, client *ethclient.Client, number *big.Int) (*Header, error) {
	tag := "latest"
	if number != nil {
		tag = hexutil.EncodeBig(number)
	}
	var h *Header
	if err := client.Client().CallContext(ctx, &h, "eth_getBlockByNumber", tag, false); err != nil {
		return nil, err
	}
	if h == nil || h.Hash == (common.Hash{}) {
		return nil, fmt.Errorf("BLOCK_UNAVAILABLE: %s", tag)
	}
	if number != nil && new(big.Int).SetUint64(uint64(h.Number)).Cmp(number) != 0 {
		return nil, fmt.Errorf("block number mismatch")
	}
	return h, nil
}
