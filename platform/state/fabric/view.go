package fabric

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"grad/platform/migrations"
	"grad/platform/state"
	"grad/protocol"
	"grad/protocol/registry"
)

var (
	// ErrStale indicates that no unexpired original liveness probe has been applied to the view.
	ErrStale = errors.New("STATE_STALE: no applied original probe within its deadline")
	// ErrUnavailable indicates that the PostgreSQL view has not been continuously replayed or is missing dependencies.
	ErrUnavailable = errors.New("STATE_UNAVAILABLE: view requires trusted continuous replay")

	_ state.StateSource           = (*StateProvider)(nil)
	_ state.HistoricalStateSource = (*StateProvider)(nil)
)

// RowReader abstracts *pgxpool.Pool, *pgxpool.Conn, and pgx.Tx for single-row queries.
type RowReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// View manages continuous full-block replay and fixed-height reads against PostgreSQL fabric_* tables.
type View struct {
	DB         *pgxpool.Pool
	Deployment *Deployment
}

// EnsureSchema applies embedded PostgreSQL migrations required by Fabric view and journal tables.
func EnsureSchema(ctx context.Context, db *pgxpool.Pool) error {
	return migrations.Up(ctx, db)
}

// OpenView ensures the schema is migrated and returns a View bound to db and d.
func OpenView(ctx context.Context, db *pgxpool.Pool, d *Deployment) (*View, error) {
	if err := EnsureSchema(ctx, db); err != nil {
		return nil, err
	}
	return &View{DB: db, Deployment: d}, nil
}

// Head returns the highest continuously applied block checkpoint for this deployment.
func (v View) Head(ctx context.Context, q RowReader, lock bool) (*Point, error) {
	stmt := "SELECT block_no, hash FROM fabric_head WHERE deployment=$1"
	if lock {
		stmt += " FOR UPDATE"
	}
	var h Point
	err := q.QueryRow(ctx, stmt, v.Deployment.DeploymentID).Scan(&h.Number, &h.Hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &h, err
}

// Apply atomically persists a validated block, its VALID KV versions, fabric_current state,
// and the advancing fabric_head checkpoint in one PostgreSQL transaction.
func (v View) Apply(ctx context.Context, b *Block, beforeCommit func() error) error {
	if b.Number > math.MaxInt64 {
		return fmt.Errorf("unsupported block number")
	}
	if b.Number == 0 && (b.Hash != v.Deployment.GenesisHash || b.ConfigDigest != v.Deployment.ConfigDigest) ||
		b.ConfigDigest != "" && b.ConfigDigest != v.Deployment.ConfigDigest {
		return fmt.Errorf("%w: channel configuration at %d", ErrDeploymentMismatch, b.Number)
	}
	for _, tx := range b.Transactions {
		if tx.DefinitionChange && (tx.ID != v.Deployment.DefinitionTxID || b.Point != v.Deployment.DefinitionBlock) {
			return fmt.Errorf("%w: registry definition at %d", ErrDeploymentMismatch, b.Number)
		}
	}
	if b.Number == v.Deployment.DefinitionBlock.Number && b.Point != v.Deployment.DefinitionBlock ||
		b.Number == v.Deployment.InitBlock.Number && b.Point != v.Deployment.InitBlock {
		return fmt.Errorf("%w: pinned definition or initialization block", ErrDeploymentMismatch)
	}
	raw, err := proto.Marshal(b.Raw)
	if err != nil {
		return err
	}
	tx, err := v.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	// Ensure one row can serialize concurrent consumers even before block zero.
	if _, err := tx.Exec(ctx, "INSERT INTO fabric_head VALUES($1,-1,'') ON CONFLICT DO NOTHING", v.Deployment.DeploymentID); err != nil {
		return err
	}
	var last int64
	var hash string
	if err := tx.QueryRow(ctx, "SELECT block_no, hash FROM fabric_head WHERE deployment=$1 FOR UPDATE", v.Deployment.DeploymentID).Scan(&last, &hash); err != nil {
		return err
	}
	if int64(b.Number) <= last {
		var stored []byte
		if err := tx.QueryRow(ctx, "SELECT data FROM fabric_block WHERE deployment=$1 AND block_no=$2", v.Deployment.DeploymentID, b.Number).Scan(&stored); err != nil {
			return fmt.Errorf("stored block %d missing: %w", b.Number, err)
		}
		if !compareCheckpoint(stored, b) {
			return fmt.Errorf("conflicting already applied block %d", b.Number)
		}
		return tx.Commit(ctx)
	}
	if int64(b.Number) != last+1 || b.Parent != hash {
		return fmt.Errorf("missing or divergent block after %d/%s", last, hash)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO fabric_block VALUES($1,$2,$3,$4,$5)", v.Deployment.DeploymentID, b.Number, b.Hash, b.Parent, raw); err != nil {
		return err
	}
	for _, source := range b.Transactions {
		if source.Code != pb.TxValidationCode_VALID {
			continue
		}
		for _, w := range source.Writes {
			var value []byte
			if !w.IsDelete {
				value = w.Value
			}
			if _, err := tx.Exec(ctx, "INSERT INTO fabric_version VALUES($1,$2,$3,$4,$5,$6)",
				v.Deployment.DeploymentID, w.Key, b.Number, source.Index, source.ID, value); err != nil {
				return err
			}
			if w.IsDelete {
				_, err = tx.Exec(ctx, "DELETE FROM fabric_current WHERE deployment=$1 AND key=$2", v.Deployment.DeploymentID, w.Key)
			} else {
				_, err = tx.Exec(ctx, `INSERT INTO fabric_current VALUES($1,$2,$3)
					ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, v.Deployment.DeploymentID, w.Key, w.Value)
			}
			if err != nil {
				return err
			}
		}
	}
	if beforeCommit != nil {
		if err := beforeCommit(); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, "UPDATE fabric_head SET block_no=$2, hash=$3 WHERE deployment=$1", v.Deployment.DeploymentID, b.Number, b.Hash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RawSnapshot represents the raw JSON records assembled at a fixed block height or online head.
type RawSnapshot struct {
	DeploymentID string `json:"deploymentId"`
	Mode         string `json:"mode"`
	Point
	GrantID string                     `json:"grantId"`
	Grants  []registry.Grant           `json:"grants"`
	Records map[string]json.RawMessage `json:"records"`
	Probe   *ProbeEvidence             `json:"probe,omitempty"`
}

type viewReader struct {
	ctx      context.Context
	tx       pgx.Tx
	d        *Deployment
	snapshot *RawSnapshot
}

func readViewRecord[T any](r viewReader, key string) (T, error) {
	var value T
	raw, exists := r.snapshot.Records[key]
	if !exists {
		var err error
		if r.snapshot.Mode == "historical" {
			err = r.tx.QueryRow(r.ctx, `SELECT value FROM fabric_version WHERE deployment=$1 AND key=$2 AND block_no<=$3
				ORDER BY block_no DESC, tx_index DESC LIMIT 1`, r.d.DeploymentID, key, r.snapshot.Number).Scan(&raw)
		} else {
			err = r.tx.QueryRow(r.ctx, "SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2", r.d.DeploymentID, key).Scan(&raw)
		}
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && raw == nil) {
			return value, fmt.Errorf("%s: %s at block %d", registry.ErrCodeMissingDependency, key, r.snapshot.Number)
		}
		if err != nil {
			return value, err
		}
		r.snapshot.Records[key] = raw
	}
	return value, json.Unmarshal(raw, &value)
}

// RawSnapshot assembles the raw ledger records for grant at the current online head or at historical block height.
func (v View) RawSnapshot(ctx context.Context, grant string, historical *uint64, runtime *Online, afterRoot func() error) (*RawSnapshot, error) {
	tx, err := v.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())

	h, err := v.Head(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	if h == nil {
		if historical != nil {
			return nil, fmt.Errorf("HISTORY_UNAVAILABLE: no replayed blocks")
		}
		return nil, ErrUnavailable
	}
	s := &RawSnapshot{
		DeploymentID: v.Deployment.DeploymentID,
		Mode:         "online",
		Point:        *h,
		GrantID:      grant,
		Records:      map[string]json.RawMessage{},
	}
	var epoch uint64
	if historical != nil {
		s.Mode, s.Number = "historical", *historical
		if err := v.HistoricalPoint(ctx, tx, &s.Point, *h); err != nil {
			return nil, err
		}
	} else {
		lease, generation, err := runtime.lease(ctx, tx, *h)
		if err != nil {
			return nil, err
		}
		s.Probe, epoch = lease, generation
	}
	r := viewReader{ctx: ctx, tx: tx, d: v.Deployment, snapshot: s}
	boot, err := readViewRecord[registry.Bootstrap](r, registry.BootstrapKey)
	if err != nil {
		return nil, err
	}
	if boot != v.Deployment.Bootstrap || registry.Digest(s.Records[registry.BootstrapKey]) != v.Deployment.BootstrapDigest {
		return nil, fmt.Errorf("%w: view bootstrap", ErrDeploymentMismatch)
	}
	if grant != "" {
		if err := r.assemble(grant, afterRoot); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if historical == nil {
		if err := runtime.checkLease(s.Probe, epoch, time.Now()); err != nil {
			return nil, err
		}
		runtime.emit("adopt", s.Probe)
	}
	return s, nil
}

// HistoricalPoint verifies uninterrupted replayed block history [0..h.Number] and fills h.Hash.
func (v View) HistoricalPoint(ctx context.Context, tx pgx.Tx, h *Point, last Point) error {
	if h.Number > last.Number {
		return fmt.Errorf("HISTORY_UNAVAILABLE: requested %d after applied %d", h.Number, last.Number)
	}
	var count uint64
	err := tx.QueryRow(ctx, "SELECT count(*) FROM fabric_block WHERE deployment=$1 AND block_no<=$2", v.Deployment.DeploymentID, h.Number).Scan(&count)
	if err != nil || count != h.Number+1 {
		return fmt.Errorf("HISTORY_UNAVAILABLE: gap before or at block %d: %v", h.Number, err)
	}
	return tx.QueryRow(ctx, "SELECT hash FROM fabric_block WHERE deployment=$1 AND block_no=$2", v.Deployment.DeploymentID, h.Number).Scan(&h.Hash)
}

func (r viewReader) assemble(id string, afterRoot func() error) error {
	leaf, err := readViewRecord[registry.Grant](r, registry.Key("grant", id))
	if err != nil {
		return err
	}
	root, err := readViewRecord[registry.Grant](r, registry.Key("grant", leaf.Root))
	if err != nil {
		return err
	}
	if afterRoot != nil {
		// Deterministic test hook runs after reading root and before re-reading leaf and dependencies.
		delete(r.snapshot.Records, registry.Key("grant", id))
		if err := afterRoot(); err != nil {
			return err
		}
		leaf, err = readViewRecord[registry.Grant](r, registry.Key("grant", id))
		if err != nil {
			return err
		}
	}
	if root.Parent != "" || root.ID != leaf.Root {
		return fmt.Errorf("%s: invalid root reference", registry.ErrCodeInvalidState)
	}
	if root.Mode == registry.BM {
		dom, err := readViewRecord[registry.Domain](r, registry.Key("domain", root.Domain))
		if err != nil {
			return err
		}
		if dom.Status != registry.Active || dom.PurchasingAuthority == "" || root.Issuer != dom.PurchasingAuthority {
			return fmt.Errorf("%s: %s: root issuer %s != domain %s PA %q", registry.ErrCodeInvalidState, registry.ErrCodePurchasingAuthorityInvalid, root.Issuer, dom.ID, dom.PurchasingAuthority)
		}
	} else if root.Mode != registry.RP {
		return fmt.Errorf("%s: unsupported authorizationMode %q", registry.ErrCodeInvalidState, root.Mode)
	}
	for g, count := leaf, 0; ; count++ {
		if count > 32 || g.Root != root.ID || g.Task != root.Task || g.DeploymentID != r.d.DeploymentID {
			return fmt.Errorf("%s: broken delegation path", registry.ErrCodeInvalidState)
		}
		r.snapshot.Grants = append(r.snapshot.Grants, g)
		if err := r.credential(g.IssuerCredential, g.Issuer); err != nil {
			return err
		}
		if err := r.credential(g.GranteeCredential, g.Grantee); err != nil {
			return err
		}
		if g.Parent == "" {
			if g.ID != root.ID {
				return fmt.Errorf("%s: delegation path did not reach its root", registry.ErrCodeInvalidState)
			}
			break
		}
		p, err := readViewRecord[registry.Grant](r, registry.Key("grant", g.Parent))
		if err != nil {
			return err
		}
		if p.Digest != g.ParentDigest {
			return fmt.Errorf("%s: parent digest mismatch", registry.ErrCodeInvalidState)
		}
		g = p
	}
	t, err := readViewRecord[registry.Task](r, registry.Key("task", root.Task))
	if err != nil {
		return err
	}
	return r.credential(t.CreatorCredential, t.Creator)
}

func (r viewReader) credential(id, holder string) error {
	c, err := readViewRecord[registry.Credential](r, registry.Key("credential", id))
	if err != nil {
		return err
	}
	if c.Subject != holder {
		return fmt.Errorf("%s: credential subject mismatch", registry.ErrCodeInvalidState)
	}
	for _, subject := range []string{holder, c.Issuer} {
		i, err := readViewRecord[registry.Identity](r, registry.Key("identity", subject))
		if err != nil {
			return err
		}
		d, err := readViewRecord[registry.Domain](r, registry.Key("domain", i.Domain))
		if err != nil {
			return err
		}
		if _, err := readViewRecord[registry.Identity](r, registry.Key("identity", d.DID)); err != nil {
			return err
		}
		if _, err := readViewRecord[registry.Certification](r, registry.Key("certification", d.Certification)); err != nil {
			return err
		}
	}
	return nil
}

// Online runs continuous full-block Deliver replay and periodic liveness probing against the pinned peer.
type Online struct {
	View
	Instance  *Instance
	Role      string
	Interval  time.Duration
	TimeLimit time.Duration
	Observe   func(string, any)

	started   time.Time
	mu        sync.Mutex
	ready     bool
	hardError error
	epoch     uint64
	attempts  map[string]time.Time
}

func (v *Online) emit(kind string, fields any) {
	if v.Observe != nil {
		v.Observe(kind, fields)
	}
}

func (v *Online) inhibit(err error) {
	v.mu.Lock()
	v.ready = false
	v.hardError = err
	v.epoch++
	clear(v.attempts)
	v.mu.Unlock()
	v.emit("view_rejected", err.Error())
}

func (v *Online) resume() {
	v.mu.Lock()
	v.ready = true
	v.hardError = nil
	v.mu.Unlock()
}

func (v *Online) follow(ctx context.Context, peer *PeerClient) {
	for ctx.Err() == nil {
		err := v.followOnce(ctx, peer)
		if err != nil && ctx.Err() == nil {
			v.emit("delivery_interrupted", err.Error())
		}
		select {
		case <-ctx.Done():
		case <-time.After(350 * time.Millisecond):
		}
	}
}

func (v *Online) followOnce(ctx context.Context, peer *PeerClient) error {
	// Capture the checkpoint before querying the Peer so another consumer's
	// concurrent progress cannot be compared against an older height response.
	last, err := v.Head(ctx, v.DB, false)
	if err != nil {
		v.inhibit(err)
		return err
	}
	height, err := peer.Height(ctx)
	if err != nil {
		return err
	}
	if err := checkSourceHeight(height, last); err != nil {
		v.inhibit(err)
		return err
	}
	if err := v.Deployment.ValidatePeer(ctx, peer); err != nil {
		// Retry unavailable queries. A mismatch in the retrieved evidence blocks reads.
		if errors.Is(err, ErrDeploymentMismatch) {
			v.inhibit(err)
		}
		return err
	}
	next := uint64(0)
	if last != nil {
		observed, err := peer.GetBlock(ctx, last.Number)
		if err != nil {
			switch status.Code(err) {
			case codes.Canceled, codes.DeadlineExceeded, codes.Unavailable:
				// A transport interruption leaves existing probes bound to their original deadlines.
			default:
				v.inhibit(err)
			}
			return err
		}
		if observed.Hash != last.Hash {
			err := fmt.Errorf("checkpoint %d conflicts with the pinned Peer", last.Number)
			v.inhibit(err)
			return err
		}
		if err := v.Apply(ctx, observed, nil); err != nil {
			v.inhibit(err)
			return err
		}
		next = last.Number + 1
	}
	v.resume()
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := peer.Deliver(c, next, math.MaxUint64)
	if err != nil {
		return err
	}
	for ctx.Err() == nil {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}
		if resp.GetBlock() == nil {
			err := fmt.Errorf("Peer Deliver status %s", resp.GetStatus())
			v.inhibit(err)
			return err
		}
		b, err := ParseBlock(resp.GetBlock())
		if err == nil {
			err = v.Apply(ctx, b, nil)
		}
		if err != nil {
			if ctx.Err() == nil {
				v.inhibit(err)
			}
			return err
		}
		v.emit("block_applied", b.Point)
	}
	return ctx.Err()
}

// WaitOnline waits until the online view has applied a fresh original probe and can assemble grant.
func (v *Online) WaitOnline(ctx context.Context, grant string) (*RawSnapshot, error) {
	var last error
	for ctx.Err() == nil {
		s, err := v.RawSnapshot(ctx, grant, nil, v, nil)
		if err == nil {
			return s, nil
		}
		if !errors.Is(err, ErrStale) && !errors.Is(err, ErrUnavailable) {
			return nil, err
		}
		v.mu.Lock()
		hard := v.hardError
		v.mu.Unlock()
		if hard != nil && !errors.Is(hard, context.DeadlineExceeded) {
			return nil, errors.Join(ErrUnavailable, hard)
		}
		last = err
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil, errors.Join(last, ctx.Err())
}

func compareCheckpoint(raw []byte, b *Block) bool {
	known, err := decodeProto(raw, b.Raw.ProtoReflect().New().Interface())
	return err == nil && proto.Equal(known, b.Raw)
}

func checkSourceHeight(height uint64, last *Point) error {
	if last != nil && height <= last.Number {
		return fmt.Errorf("Peer height %d is below applied checkpoint %d", height, last.Number)
	}
	return nil
}

// Checkpoint captures the Fabric block height, hash, and revocation epoch anchored in fabric_head.
type Checkpoint struct {
	Height          int64  `json:"blockNumber"`
	Hash            string `json:"blockHash"`
	RevocationEpoch int64  `json:"revocationEpoch"`
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

// RegistryReadback returns raw persisted registry values alongside their consistent block checkpoint.
type RegistryReadback struct {
	Number  uint64
	Hash    string
	Root    registry.RootRecord
	Records map[string]json.RawMessage
}

// ConsistentProtocolView holds all protocol records, synced domain certification JWS documents,
// checkpoint metadata, and original probe lease assembled inside a single REPEATABLE READ transaction.
type ConsistentProtocolView struct {
	DeploymentID string
	Checkpoint   Checkpoint
	Probe        ProbeEvidence
	Bootstrap    registry.Bootstrap
	Snapshot     *protocol.SnapshotView
	CertJWSByID  map[string]string
	CertJWSByDom map[string]string
}

// StateProvider assembles consistent protocol snapshots purely from PostgreSQL state views
// without ever falling back to querying Peer latest state. It directly implements
// state.StateSource and state.HistoricalStateSource.
type StateProvider struct {
	db           *pgxpool.Pool
	deploymentID string
	boot         registry.Bootstrap
	bootDigest   string
	runtime      *Online

	mu          sync.RWMutex
	staticProbe *state.ProbeLease
	lastProbe   *state.ProbeLease
	monoClock   func() time.Time
	afterRoot   func() error
}

// NewStateProvider constructs a StateProvider from a verified Deployment and optional Online runtime.
func NewStateProvider(db *pgxpool.Pool, d *Deployment, runtime *Online) *StateProvider {
	return &StateProvider{
		db:           db,
		deploymentID: d.DeploymentID,
		boot:         d.Bootstrap,
		bootDigest:   d.BootstrapDigest,
		runtime:      runtime,
		monoClock:    time.Now,
	}
}

// NewStateProviderFromBootstrap constructs a StateProvider with explicit deployment ID and Bootstrap anchor.
func NewStateProviderFromBootstrap(db *pgxpool.Pool, deploymentID string, boot registry.Bootstrap, runtime *Online) *StateProvider {
	raw, _ := json.Marshal(boot)
	return &StateProvider{
		db:           db,
		deploymentID: deploymentID,
		boot:         boot,
		bootDigest:   registry.Digest(raw),
		runtime:      runtime,
		monoClock:    time.Now,
	}
}

// SetAfterRootHook installs an optional deterministic test hook executed mid-REPEATABLE READ
// transaction after reading the root grant and before reading the leaf grant and dependencies.
func (sp *StateProvider) SetAfterRootHook(fn func() error) {
	sp.mu.Lock()
	sp.afterRoot = fn
	sp.mu.Unlock()
}

// StartStateProvider starts a continuous Fabric block follower and liveness probe loop with default cadence.
func (i *Instance) StartStateProvider(ctx context.Context, db *pgxpool.Pool, d *Deployment, probeRole, grant string) (*StateProvider, func(), error) {
	return i.StartObservedStateProvider(ctx, db, d, probeRole, grant, registry.ProbeInterval, registry.ProbeLifetime, nil)
}

// StartObservedStateProvider starts a continuous StateProvider with custom probe cadence/lifetime
// and an optional host-timebase observer for block_applied, adopt, probe_sent, and probe_commit_observed events.
func (i *Instance) StartObservedStateProvider(
	ctx context.Context,
	db *pgxpool.Pool,
	d *Deployment,
	probeRole, grant string,
	probeInterval, probeLifetime time.Duration,
	observe func(event string, at time.Time, details any),
) (*StateProvider, func(), error) {
	if probeInterval <= 0 {
		probeInterval = registry.ProbeInterval
	}
	if probeLifetime <= 0 {
		probeLifetime = registry.ProbeLifetime
	}
	var rawObserve func(string, any)
	if observe != nil {
		rawObserve = func(kind string, fields any) {
			at := time.Now().UTC()
			switch v := fields.(type) {
			case Point:
				observe(kind, at, BlockAppliedEvent{BlockNumber: v.Number, BlockHash: v.Hash, AppliedAt: at})
			case *ProbeEvidence:
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
	rt := &Online{
		View:      View{DB: db, Deployment: d},
		Instance:  i,
		Role:      probeRole,
		Interval:  probeInterval,
		TimeLimit: probeLifetime,
		Observe:   rawObserve,
	}
	stop, err := rt.Start(ctx)
	if err != nil {
		return nil, nil, err
	}
	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := rt.WaitOnline(wait, grant); err != nil {
		stop()
		return nil, nil, err
	}
	return NewStateProvider(db, d, rt), stop, nil
}

// ApplyCommittedRegistry pulls and applies the committed block prefix reported by the trusted peer C.
func (i *Instance) ApplyCommittedRegistry(ctx context.Context, db *pgxpool.Pool, d *Deployment) error {
	if err := EnsureSchema(ctx, db); err != nil {
		return err
	}
	return i.SyncCommittedRegistry(ctx, db, d)
}

// SyncCommittedRegistry advances an initialized database to the local peer's
// committed prefix after verifying both the deployment and the stored checkpoint.
func (i *Instance) SyncCommittedRegistry(ctx context.Context, db *pgxpool.Pool, d *Deployment) error {
	peer, err := i.ReadPeer()
	if err != nil {
		return err
	}
	defer peer.Close()
	if err := d.ValidatePeer(ctx, peer); err != nil {
		return err
	}
	v := View{DB: db, Deployment: d}
	head, err := v.Head(ctx, db, false)
	if err != nil {
		return err
	}
	height, err := peer.Height(ctx)
	if err != nil {
		return err
	}
	var start uint64
	if head != nil {
		if head.Number >= height {
			return fmt.Errorf("%w: local peer is behind applied registry", ErrUnavailable)
		}
		block, err := peer.GetBlock(ctx, head.Number)
		if err != nil {
			return err
		}
		if block.Point != *head {
			return fmt.Errorf("%w: committed checkpoint changed", ErrDeploymentMismatch)
		}
		start = head.Number + 1
	}
	for n := start; n < height; n++ {
		b, err := peer.GetBlock(ctx, n)
		if err != nil {
			return err
		}
		if err := v.Apply(ctx, b, nil); err != nil {
			return err
		}
	}
	return nil
}

// ReadAppliedRegistry returns the requested ledger records and their checkpoint in one REPEATABLE READ transaction.
func ReadAppliedRegistry(ctx context.Context, db *pgxpool.Pool, d *Deployment, keys []string) (*RegistryReadback, error) {
	tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())

	v := View{DB: db, Deployment: d}
	head, err := v.Head(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	if head == nil {
		return nil, ErrUnavailable
	}
	snap := &RawSnapshot{Point: *head, Records: make(map[string]json.RawMessage)}
	r := viewReader{ctx: ctx, tx: tx, d: d, snapshot: snap}
	boot, err := readViewRecord[registry.Bootstrap](r, registry.BootstrapKey)
	if err != nil {
		return nil, err
	}
	if boot != d.Bootstrap || registry.Digest(snap.Records[registry.BootstrapKey]) != d.BootstrapDigest {
		return nil, fmt.Errorf("%w: view bootstrap", ErrDeploymentMismatch)
	}
	records := make(map[string]json.RawMessage, len(keys))
	for _, key := range keys {
		value, err := readViewRecord[json.RawMessage](r, key)
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

// AssembleSnapshot implements state.StateSource directly against the PostgreSQL Fabric view.
func (sp *StateProvider) AssembleSnapshot(ctx context.Context, leafGrantID string, now time.Time) (*state.StateSnapshot, error) {
	view, err := sp.AssembleProtocolSnapshot(ctx, leafGrantID, now)
	if err != nil {
		return nil, err
	}
	return toStateSnapshot(view), nil
}

// LockCheckpoint implements state.StateSource by acquiring a FOR SHARE lock on fabric_head inside tx.
func (sp *StateProvider) LockCheckpoint(ctx context.Context, tx pgx.Tx, original *state.StateSnapshot) (bool, error) {
	var height int64
	var hash string
	err := tx.QueryRow(ctx, `SELECT block_no, hash FROM fabric_head WHERE deployment=$1 FOR SHARE`, sp.deploymentID).Scan(&height, &hash)
	if err != nil {
		return false, protocol.WrapError(protocol.ErrCodeStateUnavailable, "lock Fabric checkpoint", err)
	}
	return original != nil && original.StateSource == state.SourceFabric && height == original.BlockNumber && hash == original.BlockHash, nil
}

// CheckFresh implements state.StateSource by validating original's monotonic probe deadline.
func (sp *StateProvider) CheckFresh(ctx context.Context, original *state.StateSnapshot) (state.ProbeLease, error) {
	if original == nil {
		return sp.IsProbeFresh()
	}
	return sp.IsProbeFresh(original.Probe)
}

// AssembleHistoricalSnapshot implements state.HistoricalStateSource at an exact committed block height.
func (sp *StateProvider) AssembleHistoricalSnapshot(ctx context.Context, leafGrantID string, blockNo int64, now time.Time) (*state.StateSnapshot, error) {
	if blockNo <= 0 {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "HISTORY_UNAVAILABLE: blockNo must be >= 1")
	}
	view, err := sp.AssembleHistoricalProtocolSnapshot(ctx, leafGrantID, uint64(blockNo), now)
	if err != nil {
		return nil, err
	}
	return toStateSnapshot(view), nil
}

func toStateSnapshot(view *ConsistentProtocolView) *state.StateSnapshot {
	return &state.StateSnapshot{
		DeploymentID:    view.DeploymentID,
		StateSource:     state.SourceFabric,
		BlockNumber:     view.Checkpoint.Height,
		BlockHash:       view.Checkpoint.Hash,
		RevocationEpoch: view.Checkpoint.RevocationEpoch,
		Probe:           view.Probe.Lease(),
		Snapshot:        view.Snapshot,
		CertJWSByID:     view.CertJWSByID,
		CertJWSByDom:    view.CertJWSByDom,
	}
}

// AssembleProtocolSnapshot reads fabric_head and all grant-chain protocol dependencies in one
// PostgreSQL REPEATABLE READ read-only transaction, checking original probe freshness without
// falling back to querying Peer latest state.
func (sp *StateProvider) AssembleProtocolSnapshot(ctx context.Context, leafGrantID string, now time.Time) (*ConsistentProtocolView, error) {
	return sp.assembleAtHeight(ctx, leafGrantID, nil, now)
}

// AssembleHistoricalProtocolSnapshot reconstructs an immutable historical SnapshotView at blockNo
// inside a single REPEATABLE READ transaction after verifying continuous replayed block history up to blockNo.
func (sp *StateProvider) AssembleHistoricalProtocolSnapshot(ctx context.Context, leafGrantID string, blockNo uint64, now time.Time) (*ConsistentProtocolView, error) {
	if blockNo == 0 {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "HISTORY_UNAVAILABLE: blockNo must be >= 1")
	}
	return sp.assembleAtHeight(ctx, leafGrantID, &blockNo, now)
}

func (sp *StateProvider) assembleAtHeight(ctx context.Context, leafGrantID string, historicalBlock *uint64, now time.Time) (*ConsistentProtocolView, error) {
	if sp == nil || sp.db == nil {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "state provider database is nil")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	tx, err := sp.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "begin repeatable read transaction", err)
	}
	defer tx.Rollback(context.Background())

	var h Point
	err = tx.QueryRow(ctx, "SELECT block_no, hash FROM fabric_head WHERE deployment=$1", sp.deploymentID).Scan(&h.Number, &h.Hash)
	if errors.Is(err, pgx.ErrNoRows) || h.Hash == "" {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "fabric_head checkpoint missing")
	}
	if err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeStateUnavailable, "query fabric_head", err)
	}

	sp.mu.RLock()
	rt := sp.runtime
	staticP := sp.staticProbe
	clock := sp.monoClock
	hook := sp.afterRoot
	sp.mu.RUnlock()
	if clock == nil {
		clock = time.Now
	}

	d := &Deployment{DeploymentID: sp.deploymentID, Bootstrap: sp.boot, BootstrapDigest: sp.bootDigest}
	v := View{DB: sp.db, Deployment: d}

	mode := "online"
	snapPoint := h
	var probeEv ProbeEvidence
	if historicalBlock != nil {
		mode = "historical"
		snapPoint.Number = *historicalBlock
		if err := v.HistoricalPoint(ctx, tx, &snapPoint, h); err != nil {
			return nil, mapViewErr(err)
		}
		hook = nil
	} else if rt != nil {
		lease, epoch, lErr := rt.lease(ctx, tx, h)
		if lErr != nil {
			return nil, mapViewErr(lErr)
		}
		if cErr := rt.checkLease(lease, epoch, clock()); cErr != nil {
			return nil, mapViewErr(cErr)
		}
		probeEv = *lease
	} else if staticP != nil {
		nowMono := clock()
		if !nowMono.Before(staticP.Deadline) {
			return nil, protocol.NewError(protocol.ErrCodeStateStale, "original probe monotonic deadline reached")
		}
		probeEv = ProbeEvidence{
			TxID:         staticP.TxID,
			ProbeBlock:   staticP.ProbeBlock,
			View:         snapPoint,
			Sent:         staticP.SentAt,
			Deadline:     staticP.Deadline,
			Adopted:      nowMono,
			SentMono:     staticP.SentMonoNs,
			DeadlineMono: staticP.DeadlineMonoNs,
			AdoptedMono:  staticP.SentMonoNs + nowMono.Sub(staticP.SentAt).Nanoseconds(),
		}
	} else {
		return nil, protocol.NewError(protocol.ErrCodeStateStale, "STATE_STALE: no active original probe lease")
	}

	s := &RawSnapshot{
		DeploymentID: sp.deploymentID,
		Mode:         mode,
		Point:        snapPoint,
		GrantID:      leafGrantID,
		Records:      map[string]json.RawMessage{},
	}
	r := viewReader{ctx: ctx, tx: tx, d: d, snapshot: s}

	boot, err := readViewRecord[registry.Bootstrap](r, registry.BootstrapKey)
	if err != nil {
		return nil, mapViewErr(err)
	}
	if boot != sp.boot {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "DEPLOYMENT_MISMATCH: view bootstrap")
	}

	if leafGrantID != "" {
		if err := r.assemble(leafGrantID, hook); err != nil {
			return nil, mapViewErr(err)
		}
	} else {
		for _, id := range []string{"A", "C"} {
			dom, err := readViewRecord[registry.Domain](r, registry.Key("domain", id))
			if err != nil {
				return nil, mapViewErr(err)
			}
			if _, err := readViewRecord[registry.Certification](r, registry.Key("certification", dom.Certification)); err != nil {
				return nil, mapViewErr(err)
			}
		}
	}

	snapView := &protocol.SnapshotView{
		Height:              snapPoint.Number,
		Now:                 now.UTC(),
		ClockError:          registry.ClockError,
		ExactIntervalBounds: true,
		DeploymentID:        sp.deploymentID,
		Root:                boot.Root,
		Domains:             make(map[string]registry.Domain),
		Certifications:      make(map[string]registry.Certification),
		Identities:          make(map[string]registry.Identity),
		Credentials:         make(map[string]registry.Credential),
		Tasks:               make(map[string]registry.Task),
		Grants:              make(map[string]registry.Grant),
		Links:               make(map[string]registry.IdentityLink),
	}

	certJWSByID := make(map[string]string)
	certJWSByDom := make(map[string]string)

	for key, raw := range s.Records {
		kind, _, ok := strings.Cut(key, "/")
		if !ok {
			continue
		}
		switch kind {
		case "domain":
			var rec registry.Domain
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Domains[rec.ID] = rec
		case "certification":
			var rec registry.Certification
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Certifications[rec.ID] = rec
		case "identity":
			var rec registry.Identity
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Identities[rec.ID] = rec
		case "credential":
			var rec registry.Credential
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Credentials[rec.ID] = rec
		case "task":
			var rec registry.Task
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Tasks[rec.ID] = rec
		case "grant":
			var rec registry.Grant
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Grants[rec.ID] = rec
		case "link":
			var rec registry.IdentityLink
			if err := json.Unmarshal(raw, &rec); err != nil {
				return nil, err
			}
			snapView.Links[rec.ID] = rec
		}
	}

	// Load any identity links at the same REPEATABLE READ snapshot height so dual-domain link state is visible.
	var linkRows pgx.Rows
	if mode == "historical" {
		linkRows, err = tx.Query(ctx, `SELECT DISTINCT ON (key) value FROM fabric_version
			WHERE deployment=$1 AND key LIKE 'link/%' AND block_no <= $2
			ORDER BY key, block_no DESC, tx_index DESC`, sp.deploymentID, snapPoint.Number)
	} else {
		linkRows, err = tx.Query(ctx, "SELECT value FROM fabric_current WHERE deployment=$1 AND key LIKE 'link/%'", sp.deploymentID)
	}
	if err == nil {
		rawLinks, collectErr := pgx.CollectRows(linkRows, pgx.RowTo[[]byte])
		if collectErr == nil {
			var links []registry.IdentityLink
			for _, raw := range rawLinks {
				if len(raw) == 0 {
					continue
				}
				var l registry.IdentityLink
				if json.Unmarshal(raw, &l) == nil && l.ID != "" {
					snapView.Links[l.ID] = l
					links = append(links, l)
				}
			}
			for _, l := range links {
				for _, domID := range []string{l.SourceDomain, l.TargetDomain} {
					if _, exists := snapView.Domains[domID]; !exists && domID != "" {
						if dRaw, dErr := loadOptionalAt(ctx, tx, sp.deploymentID, registry.Key("domain", domID), historicalBlock); dErr == nil && len(dRaw) > 0 {
							var dom registry.Domain
							if json.Unmarshal(dRaw, &dom) == nil {
								snapView.Domains[dom.ID] = dom
							}
						}
					}
				}
				for _, subID := range []string{l.SourceSubject, l.TargetSubject} {
					if _, exists := snapView.Identities[subID]; !exists && subID != "" {
						if iRaw, iErr := loadOptionalAt(ctx, tx, sp.deploymentID, registry.Key("identity", subID), historicalBlock); iErr == nil && len(iRaw) > 0 {
							var id registry.Identity
							if json.Unmarshal(iRaw, &id) == nil {
								snapView.Identities[id.ID] = id
							}
						}
					}
				}
			}
		}
	}

	// Optional PA identity (not directly on RP grant path, needed when checking BM/authority presence).
	if paRaw, err := loadOptionalAt(ctx, tx, sp.deploymentID, registry.Key("identity", "did:web:a.local:pa"), historicalBlock); err == nil && len(paRaw) > 0 {
		var paID registry.Identity
		if json.Unmarshal(paRaw, &paID) == nil {
			snapView.Identities[paID.ID] = paID
		}
	}

	// Ensure every loaded domain also has its active certification record available for delivery/protocol checks.
	for _, dom := range snapView.Domains {
		if dom.Certification == "" {
			continue
		}
		if _, exists := snapView.Certifications[dom.Certification]; !exists {
			if cRaw, cErr := loadOptionalAt(ctx, tx, sp.deploymentID, registry.Key("certification", dom.Certification), historicalBlock); cErr == nil && len(cRaw) > 0 {
				var cert registry.Certification
				if json.Unmarshal(cRaw, &cert) == nil && cert.ID != "" {
					snapView.Certifications[cert.ID] = cert
				}
			}
		}
	}

	// Load synced certification JWS documents in the same REPEATABLE READ tx.
	for domID, dom := range snapView.Domains {
		if dom.Certification == "" {
			continue
		}
		var jws string
		err := tx.QueryRow(ctx, `SELECT cert_jws FROM certification_receipts
			WHERE deployment_id=$1 AND domain_id=$2 AND certification_id=$3 LIMIT 1`,
			sp.deploymentID, domID, dom.Certification).Scan(&jws)
		if errors.Is(err, pgx.ErrNoRows) {
			err = tx.QueryRow(ctx, `SELECT cert_jws FROM certification_outbox
				WHERE deployment_id=$1 AND domain_id=$2 AND certification_id=$3 LIMIT 1`,
				sp.deploymentID, domID, dom.Certification).Scan(&jws)
		}
		if err == nil && jws != "" {
			certJWSByID[dom.Certification] = jws
			certJWSByDom[domID] = jws
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	if historicalBlock == nil && rt != nil {
		lease := probeEv.Lease()
		sp.mu.Lock()
		sp.lastProbe = &lease
		sp.mu.Unlock()
		evCopy := probeEv
		evCopy.View = snapPoint
		rt.emit("adopt", &evCopy)
	}

	return &ConsistentProtocolView{
		DeploymentID: sp.deploymentID,
		Checkpoint: Checkpoint{
			Height:          int64(snapPoint.Number),
			Hash:            snapPoint.Hash,
			RevocationEpoch: 0,
		},
		Probe:        probeEv,
		Bootstrap:    boot,
		Snapshot:     snapView,
		CertJWSByID:  certJWSByID,
		CertJWSByDom: certJWSByDom,
	}, nil
}

func loadOptionalAt(ctx context.Context, tx pgx.Tx, depID, key string, historicalBlock *uint64) ([]byte, error) {
	var raw []byte
	var err error
	if historicalBlock != nil {
		err = tx.QueryRow(ctx, `SELECT value FROM fabric_version WHERE deployment=$1 AND key=$2 AND block_no <= $3
			ORDER BY block_no DESC, tx_index DESC LIMIT 1`, depID, key, *historicalBlock).Scan(&raw)
	} else {
		err = tx.QueryRow(ctx, "SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2", depID, key).Scan(&raw)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

type versionStatusRow struct {
	BlockNo int64  `db:"block_no"`
	TxID    string `db:"tx_id"`
	Value   []byte `db:"value"`
}

// FindInactiveBlock searches fabric_version for the earliest VALID block >= afterBlock
// where (kind, id) entered SUSPENDED, REVOKED, or CANCELLED.
func (sp *StateProvider) FindInactiveBlock(ctx context.Context, kind, id string, afterBlock int64) (int64, string, bool, error) {
	if sp == nil || sp.db == nil {
		return 0, "", false, protocol.NewError(protocol.ErrCodeStateUnavailable, "state provider database is nil")
	}
	if afterBlock < 1 {
		afterBlock = 1
	}
	key := registry.Key(kind, id)
	rows, err := sp.db.Query(ctx, `SELECT block_no, tx_id, value FROM fabric_version
		WHERE deployment=$1 AND key=$2 AND block_no >= $3
		ORDER BY block_no ASC, tx_index ASC`, sp.deploymentID, key, afterBlock)
	if err != nil {
		return 0, "", false, err
	}
	versions, err := pgx.CollectRows(rows, pgx.RowToStructByName[versionStatusRow])
	if err != nil {
		return 0, "", false, err
	}
	for _, row := range versions {
		var st struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(row.Value, &st) == nil && (st.Status == registry.Suspended || st.Status == registry.Revoked || st.Status == registry.Cancelled) {
			return row.BlockNo, row.TxID, true, nil
		}
	}
	return 0, "", false, nil
}

func mapViewErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrStale) || strings.Contains(err.Error(), registry.ErrCodeStateStale) {
		return protocol.NewError(protocol.ErrCodeStateStale, err.Error())
	}
	if errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), registry.ErrCodeMissingDependency) ||
		strings.Contains(err.Error(), "DEPLOYMENT_MISMATCH") || strings.Contains(err.Error(), "HISTORY_UNAVAILABLE") {
		return protocol.NewError(protocol.ErrCodeStateUnavailable, err.Error())
	}
	if strings.Contains(err.Error(), registry.ErrCodeInvalidState) {
		return protocol.NewError(protocol.ErrCodeGrantChainInvalid, err.Error())
	}
	return err
}
