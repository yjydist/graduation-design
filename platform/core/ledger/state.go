// Package ledger defines shared state-source contracts and the Hyperledger Fabric
// ledger client, Deliver block stream, fixed-height PostgreSQL view, original-tx
// journal, and liveness probe implementation.
package ledger

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"grad/protocol"
)

const (
	// SourceFabric identifies a Hyperledger Fabric backed PostgreSQL state view.
	SourceFabric = "fabric"
	// SourceCentralized identifies a primary-database centralized registry state source.
	SourceCentralized = "centralized"
)

// ProbeLease records the original liveness probe metadata and monotonic clock deadline
// associated with a consistent state snapshot.
type ProbeLease struct {
	TxID           string    `json:"txId,omitempty"`
	ProbeBlock     uint64    `json:"probeBlockNumber,omitempty"`
	SentAt         time.Time `json:"sentAt,omitempty"`
	Deadline       time.Time `json:"deadline,omitempty"`
	SentMonoNs     int64     `json:"sentMonoNs,omitempty"`
	DeadlineMonoNs int64     `json:"deadlineMonoNs,omitempty"`
	CheckedMonoNs  int64     `json:"checkedMonoNs,omitempty"`
}

// StateSnapshot holds a fixed-height or fixed-revision consistent registry snapshot
// assembled inside a single PostgreSQL REPEATABLE READ transaction.
type StateSnapshot struct {
	DeploymentID    string                 `json:"deploymentId"`
	StateSource     string                 `json:"stateSource"`
	Revision        int64                  `json:"revision,omitempty"`
	StateReadAt     time.Time              `json:"stateReadAt,omitempty"`
	BlockNumber     int64                  `json:"blockNumber,omitempty"`
	BlockHash       string                 `json:"blockHash,omitempty"`
	RevocationEpoch int64                  `json:"revocationEpoch,omitempty"`
	Probe           ProbeLease             `json:"probe,omitempty"`
	Snapshot        *protocol.SnapshotView `json:"snapshot,omitempty"`
	CertJWSByID     map[string]string      `json:"certJwsById,omitempty"`
	CertJWSByDom    map[string]string      `json:"certJwsByDom,omitempty"`
}

// StateSource provides consistent snapshot reads, lock-then-recheck checkpoint verification,
// and monotonic probe freshness checks.
type StateSource interface {
	AssembleSnapshot(ctx context.Context, leafGrantID string, now time.Time) (*StateSnapshot, error)
	LockCheckpoint(ctx context.Context, tx pgx.Tx, original *StateSnapshot) (bool, error)
	CheckFresh(ctx context.Context, original *StateSnapshot) (ProbeLease, error)
}

// HistoricalStateSource reconstructs historical snapshots at a specific committed block
// height and locates deactivation blocks for post-hoc audit (h < r).
type HistoricalStateSource interface {
	AssembleHistoricalSnapshot(ctx context.Context, leafGrantID string, blockNo int64, now time.Time) (*StateSnapshot, error)
	FindInactiveBlock(ctx context.Context, kind, id string, afterBlock int64) (blockNo int64, txID string, found bool, err error)
}
