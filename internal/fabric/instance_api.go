package fabric

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Instance = instance
type Deployment = deployment
type SeedReport = seedReport
type Fixtures = fixtures

const (
	RegistryVersion  = version
	RegistrySequence = sequence
)

func OpenInstance(dir string) (*Instance, error) {
	return loadInstance(dir)
}

func (i *instance) Deploy(ctx context.Context) (*Deployment, error) {
	return i.deploy(ctx, false)
}

func (i *instance) Database(ctx context.Context) (*pgxpool.Pool, error) {
	return i.database(ctx)
}

func EnsureOperationSchema(ctx context.Context, db *pgxpool.Pool) error {
	return initSchema(ctx, db, operationsSchema)
}

func (i *instance) SeedProcurement(ctx context.Context, db *pgxpool.Pool, d *Deployment, setup ProcurementSetup) (*SeedReport, error) {
	if err := initSchema(ctx, db, operationsSchema+viewSchema); err != nil {
		return nil, err
	}
	return i.seedProcurement(ctx, journal{instance: i, db: db, deploymentID: d.DeploymentID}, d, &setup)
}

func (r *seedReport) Fixtures() *Fixtures { return r.fixtures }

func (r *seedReport) RegistrationSnapshot(d *Deployment) *protocol.SnapshotView {
	return fixtureSnapshot(d, r.fixtures, time.Time{})
}

func (i *instance) SyncSeedDeliveries(ctx context.Context, db *pgxpool.Pool, d *Deployment, report *SeedReport) error {
	return i.syncMaterialOutboxes(ctx, journal{instance: i, db: db, deploymentID: d.DeploymentID}, d, report.fixtures, report)
}

func (i *instance) StartStateProvider(ctx context.Context, db *pgxpool.Pool, d *Deployment, probeRole, grant string) (*StateProvider, func(), error) {
	return i.StartObservedStateProvider(ctx, db, d, probeRole, grant, api.ProbeInterval, api.ProbeLifetime, nil)
}

// BlockAppliedEvent reports a validated Fabric block applied to C's PostgreSQL view.
type BlockAppliedEvent struct {
	BlockNumber uint64    `json:"blockNumber"`
	BlockHash   string    `json:"blockHash"`
	AppliedAt   time.Time `json:"appliedAt"`
}

// AdoptEvent reports a gateway instance adopting a consistent Fabric view height and probe lease.
type AdoptEvent struct {
	TxID           string    `json:"txId"`
	ProbeBlock     uint64    `json:"probeBlockNumber"`
	BlockNumber    uint64    `json:"blockNumber"`
	BlockHash      string    `json:"blockHash"`
	SentAt         time.Time `json:"sentAt"`
	Deadline       time.Time `json:"deadline"`
	AdoptedAt      time.Time `json:"adoptedAt"`
	SentMonoNs     int64     `json:"sentMonoNs"`
	DeadlineMonoNs int64     `json:"deadlineMonoNs"`
	AdoptedMonoNs  int64     `json:"adoptedMonoNs"`
}

// RevocationEvent captures original-tx revocation submission and trusted-peer VALID observation.
type RevocationEvent struct {
	OperationKey    string    `json:"operationKey"`
	TxID            string    `json:"txId"`
	Role            string    `json:"role"`
	GrantID         string    `json:"grantId"`
	BlockNumber     uint64    `json:"blockNumber"`
	BlockHash       string    `json:"blockHash"`
	TxIndex         int       `json:"transactionIndex"`
	ValidationCode  string    `json:"validationCode"`
	Status          string    `json:"status"`
	SubmittedAt     time.Time `json:"submittedAt"`
	ValidObservedAt time.Time `json:"validObservedAt"`
}

// StartObservedStateProvider starts a continuous StateProvider with custom probe cadence/lifetime
// and an optional host-timebase observer for block_applied, adopt, probe_sent, and probe_commit_observed events.
func (i *instance) StartObservedStateProvider(
	ctx context.Context,
	db *pgxpool.Pool,
	d *Deployment,
	probeRole, grant string,
	probeInterval, probeLifetime time.Duration,
	observe func(event string, at time.Time, details any),
) (*StateProvider, func(), error) {
	if probeInterval <= 0 {
		probeInterval = api.ProbeInterval
	}
	if probeLifetime <= 0 {
		probeLifetime = api.ProbeLifetime
	}
	var rawObserve streamObserver
	if observe != nil {
		rawObserve = func(kind string, fields any) {
			at := time.Now().UTC()
			switch v := fields.(type) {
			case point:
				observe(kind, at, BlockAppliedEvent{BlockNumber: v.Number, BlockHash: v.Hash, AppliedAt: at})
			case *probeEvidence:
				if v != nil {
					observe(kind, at, AdoptEvent{
						TxID:           v.TxID,
						ProbeBlock:     v.ProbeBlock,
						BlockNumber:    v.View.Number,
						BlockHash:      v.View.Hash,
						SentAt:         v.Sent.UTC(),
						Deadline:       v.Deadline.UTC(),
						AdoptedAt:      v.Adopted.UTC(),
						SentMonoNs:     v.SentMono,
						DeadlineMonoNs: v.DeadlineMono,
						AdoptedMonoNs:  v.AdoptedMono,
					})
				}
			default:
				observe(kind, at, fields)
			}
		}
	}
	runtime := &online{
		view:      view{db: db, d: d},
		instance:  i,
		role:      probeRole,
		interval:  probeInterval,
		timeLimit: probeLifetime,
		observe:   rawObserve,
	}
	stop, err := runtime.start(ctx)
	if err != nil {
		return nil, nil, err
	}
	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := waitOnline(wait, runtime, grant); err != nil {
		stop()
		return nil, nil, err
	}
	return NewStateProvider(db, d, runtime), stop, nil
}

// RevokeGrant submits an original-txID RevokeGrant management operation and returns its submit and VALID timings.
func (i *instance) RevokeGrant(ctx context.Context, db *pgxpool.Pool, d *Deployment, opKey, role, grantID, reason string) (*RevocationEvent, error) {
	var rawGrant []byte
	if err := db.QueryRow(ctx, `SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2`, d.DeploymentID, api.Key("grant", grantID)).Scan(&rawGrant); err != nil {
		return nil, fmt.Errorf("load current grant %s before revocation: %w", grantID, err)
	}
	var current api.Grant
	if err := json.Unmarshal(rawGrant, &current); err != nil {
		return nil, fmt.Errorf("decode current grant %s: %w", grantID, err)
	}
	mut := api.Mutation{
		Bound:            api.Bound{DeploymentID: d.DeploymentID},
		ID:               current.ID,
		ExpectedRevision: current.Revision,
		ExpectedDigest:   current.Digest,
		Reason:           reason,
	}
	payload, err := json.Marshal(mut)
	if err != nil {
		return nil, err
	}
	j := journal{instance: i, db: db, deploymentID: d.DeploymentID}
	op, err := j.write(ctx, opKey, role, "RevokeGrant", payload)
	if err != nil {
		return nil, err
	}
	if op == nil || op.Status != "CONFIRMED" || op.Commit == nil || op.Commit.Code != "VALID" {
		status := ""
		obs := ""
		if op != nil {
			status = op.Status
			obs = op.Observation
		}
		return nil, fmt.Errorf("RevokeGrant did not confirm VALID: status=%s observation=%s", status, obs)
	}
	ev := &RevocationEvent{
		OperationKey:   op.Key,
		TxID:           op.TxID,
		Role:           role,
		GrantID:        grantID,
		BlockNumber:    op.Commit.Number,
		BlockHash:      op.Commit.Hash,
		TxIndex:        op.Commit.Index,
		ValidationCode: op.Commit.Code,
		Status:         op.Status,
	}
	if op.BroadcastAt != nil {
		ev.SubmittedAt = op.BroadcastAt.UTC()
	}
	if op.ObservedAt != nil {
		ev.ValidObservedAt = op.ObservedAt.UTC()
	}
	return ev, nil
}

// ApplyCommittedRegistry applies the committed prefix reported by the trusted peer.
func (i *instance) ApplyCommittedRegistry(ctx context.Context, db *pgxpool.Pool, d *Deployment) error {
	peer, err := i.peer("c", "read")
	if err != nil {
		return err
	}
	defer peer.close()
	if err := d.validatePeer(ctx, peer); err != nil {
		return err
	}
	height, err := peer.height(ctx)
	if err != nil {
		return err
	}
	v := view{db: db, d: d}
	for n := uint64(0); n < height; n++ {
		block, err := peer.getBlock(ctx, n)
		if err != nil {
			return err
		}
		if err := v.apply(ctx, block, nil); err != nil {
			return err
		}
	}
	return nil
}

type RegistryReadback struct {
	Number  uint64
	Hash    string
	Root    api.RootRecord
	Records map[string]json.RawMessage
}

// ReadAppliedRegistry returns the requested records and their checkpoint in one read transaction.
func ReadAppliedRegistry(ctx context.Context, db *pgxpool.Pool, d *Deployment, keys []string) (*RegistryReadback, error) {
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	v := view{db: db, d: d}
	head, err := v.head(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	if head == nil {
		return nil, errUnavailable
	}
	snap := &snapshot{point: *head, Records: make(map[string]json.RawMessage)}
	r := reader{ctx: ctx, tx: tx, d: d, snapshot: snap}
	boot, err := record[api.Bootstrap](r, api.BootstrapKey)
	if err != nil {
		return nil, err
	}
	if boot != d.Bootstrap || api.Digest(snap.Records[api.BootstrapKey]) != d.BootstrapDigest {
		return nil, fmt.Errorf("DEPLOYMENT_MISMATCH: view bootstrap")
	}
	records := make(map[string]json.RawMessage, len(keys))
	for _, key := range keys {
		value, err := record[json.RawMessage](r, key)
		if err != nil {
			return nil, err
		}
		records[key] = value
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &RegistryReadback{Number: head.Number, Hash: head.Hash, Root: boot.Root, Records: records}, nil
}
