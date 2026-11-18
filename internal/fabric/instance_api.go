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
	runtime := &online{view: view{db: db, d: d}, instance: i, role: probeRole, interval: api.ProbeInterval, timeLimit: api.ProbeLifetime}
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
