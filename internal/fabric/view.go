package fabric

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	api "graduation-design/internal/fabricapi"

	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const viewSchema = `
CREATE TABLE IF NOT EXISTS fabric_head (
    deployment text PRIMARY KEY,
    block_no bigint NOT NULL,
    hash text NOT NULL
);
CREATE TABLE IF NOT EXISTS fabric_block (
    deployment text NOT NULL,
    block_no bigint NOT NULL,
    hash text NOT NULL,
    parent text NOT NULL,
    data bytea NOT NULL,
    PRIMARY KEY (deployment, block_no)
);
CREATE TABLE IF NOT EXISTS fabric_version (
    deployment text NOT NULL,
    key text NOT NULL,
    block_no bigint NOT NULL,
    tx_index integer NOT NULL,
    tx_id text NOT NULL,
    value bytea,
    PRIMARY KEY (deployment, key, block_no, tx_index),
    FOREIGN KEY (deployment, block_no) REFERENCES fabric_block (deployment, block_no)
);
CREATE INDEX IF NOT EXISTS fabric_version_tx ON fabric_version (deployment,key,tx_id);
CREATE TABLE IF NOT EXISTS fabric_current (
    deployment text NOT NULL,
    key text NOT NULL,
    value bytea NOT NULL,
    PRIMARY KEY (deployment,key)
);`

var (
	errStale       = errors.New("STATE_STALE: no applied original probe within its deadline")
	errUnavailable = errors.New("STATE_UNAVAILABLE: view requires trusted continuous replay")
)

type view struct {
	db *pgxpool.Pool
	d  *deployment
}

type rowReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (v view) head(ctx context.Context, q rowReader, lock bool) (*point, error) {
	stmt := "SELECT block_no,hash FROM fabric_head WHERE deployment=$1"
	if lock {
		stmt += " FOR UPDATE"
	}
	var h point
	err := q.QueryRow(ctx, stmt, v.d.DeploymentID).Scan(&h.Number, &h.Hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &h, err
}

func (v view) apply(ctx context.Context, b *block, beforeCommit func() error) error {
	if b.Number > math.MaxInt64 {
		return fmt.Errorf("unsupported block number")
	}
	if b.Number == 0 && (b.Hash != v.d.GenesisHash || b.ConfigDigest != v.d.ConfigDigest) ||
		b.ConfigDigest != "" && b.ConfigDigest != v.d.ConfigDigest {
		return fmt.Errorf("DEPLOYMENT_MISMATCH: channel configuration at %d", b.Number)
	}
	for _, tx := range b.Transactions {
		if tx.DefinitionChange && (tx.ID != v.d.DefinitionTxID || b.point != v.d.DefinitionBlock) {
			return fmt.Errorf("DEPLOYMENT_MISMATCH: registry definition at %d", b.Number)
		}
	}
	if b.Number == v.d.DefinitionBlock.Number && b.point != v.d.DefinitionBlock ||
		b.Number == v.d.InitBlock.Number && b.point != v.d.InitBlock {
		return fmt.Errorf("DEPLOYMENT_MISMATCH: pinned definition or initialization block")
	}
	raw, err := proto.Marshal(b.raw)
	if err != nil {
		return err
	}
	tx, err := v.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	// Ensure one row can serialize concurrent consumers even before block zero.
	if _, err := tx.Exec(ctx, "INSERT INTO fabric_head VALUES($1,-1,'') ON CONFLICT DO NOTHING", v.d.DeploymentID); err != nil {
		return err
	}
	var last int64
	var hash string
	if err := tx.QueryRow(ctx, "SELECT block_no,hash FROM fabric_head WHERE deployment=$1 FOR UPDATE", v.d.DeploymentID).Scan(&last, &hash); err != nil {
		return err
	}
	if int64(b.Number) <= last {
		var stored []byte
		if err := tx.QueryRow(ctx, "SELECT data FROM fabric_block WHERE deployment=$1 AND block_no=$2", v.d.DeploymentID, b.Number).Scan(&stored); err != nil {
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
	if _, err := tx.Exec(ctx, "INSERT INTO fabric_block VALUES($1,$2,$3,$4,$5)", v.d.DeploymentID, b.Number, b.Hash, b.Parent, raw); err != nil {
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
				v.d.DeploymentID, w.Key, b.Number, source.Index, source.ID, value); err != nil {
				return err
			}
			if w.IsDelete {
				_, err = tx.Exec(ctx, "DELETE FROM fabric_current WHERE deployment=$1 AND key=$2", v.d.DeploymentID, w.Key)
			} else {
				_, err = tx.Exec(ctx, `INSERT INTO fabric_current VALUES($1,$2,$3)
					ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, v.d.DeploymentID, w.Key, w.Value)
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
	if _, err := tx.Exec(ctx, "UPDATE fabric_head SET block_no=$2, hash=$3 WHERE deployment=$1", v.d.DeploymentID, b.Number, b.Hash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type snapshot struct {
	DeploymentID string `json:"deploymentId"`
	Mode         string `json:"mode"`
	point
	GrantID string                     `json:"grantId"`
	Grants  []api.Grant                `json:"grants"`
	Records map[string]json.RawMessage `json:"records"`
	Probe   *probeEvidence             `json:"probe,omitempty"`
}

type reader struct {
	ctx      context.Context
	tx       pgx.Tx
	d        *deployment
	snapshot *snapshot
}

func record[T any](r reader, key string) (T, error) {
	var value T
	raw, exists := r.snapshot.Records[key]
	if !exists {
		var err error
		if r.snapshot.Mode == "historical" {
			err = r.tx.QueryRow(r.ctx, `SELECT value FROM fabric_version WHERE deployment=$1 AND key=$2 AND block_no<=$3
				ORDER BY block_no DESC,tx_index DESC LIMIT 1`, r.d.DeploymentID, key, r.snapshot.Number).Scan(&raw)
		} else {
			err = r.tx.QueryRow(r.ctx, "SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2", r.d.DeploymentID, key).Scan(&raw)
		}
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && raw == nil) {
			return value, fmt.Errorf("MISSING_DEPENDENCY: %s at block %d", key, r.snapshot.Number)
		}
		if err != nil {
			return value, err
		}
		r.snapshot.Records[key] = raw
	}
	return value, json.Unmarshal(raw, &value)
}

func (v view) snapshot(ctx context.Context, grant string, historical *uint64, runtime *online, afterRoot func() error) (*snapshot, error) {
	tx, err := v.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	h, err := v.head(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	if h == nil {
		if historical != nil {
			return nil, fmt.Errorf("HISTORY_UNAVAILABLE: no replayed blocks")
		}
		return nil, errUnavailable
	}
	s := &snapshot{DeploymentID: v.d.DeploymentID, Mode: "online", point: *h, GrantID: grant, Records: map[string]json.RawMessage{}}
	var epoch uint64
	if historical != nil {
		s.Mode, s.Number = "historical", *historical
		if err := v.historicalPoint(ctx, tx, &s.point, *h); err != nil {
			return nil, err
		}
	} else {
		lease, generation, err := runtime.lease(ctx, tx, *h)
		if err != nil {
			return nil, err
		}
		s.Probe, epoch = lease, generation
	}
	r := reader{ctx: ctx, tx: tx, d: v.d, snapshot: s}
	boot, err := record[api.Bootstrap](r, api.BootstrapKey)
	if err != nil {
		return nil, err
	}
	if boot != v.d.Bootstrap || api.Digest(s.Records[api.BootstrapKey]) != v.d.BootstrapDigest {
		return nil, fmt.Errorf("DEPLOYMENT_MISMATCH: view bootstrap")
	}
	if err := r.assemble(grant, afterRoot); err != nil {
		return nil, err
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

func (v view) historicalPoint(ctx context.Context, tx pgx.Tx, h *point, last point) error {
	if h.Number > last.Number {
		return fmt.Errorf("HISTORY_UNAVAILABLE: requested %d after applied %d", h.Number, last.Number)
	}
	var count uint64
	err := tx.QueryRow(ctx, "SELECT count(*) FROM fabric_block WHERE deployment=$1 AND block_no<=$2", v.d.DeploymentID, h.Number).Scan(&count)
	if err != nil || count != h.Number+1 {
		return fmt.Errorf("HISTORY_UNAVAILABLE: gap before or at block %d: %v", h.Number, err)
	}
	return tx.QueryRow(ctx, "SELECT hash FROM fabric_block WHERE deployment=$1 AND block_no=$2", v.d.DeploymentID, h.Number).Scan(&h.Hash)
}

func (r reader) assemble(id string, afterRoot func() error) error {
	leaf, err := record[api.Grant](r, api.Key("grant", id))
	if err != nil {
		return err
	}
	root, err := record[api.Grant](r, api.Key("grant", leaf.Root))
	if err != nil {
		return err
	}
	if afterRoot != nil {
		// The test hook runs after the root read and before assembling the leaf and all other dependencies.
		delete(r.snapshot.Records, api.Key("grant", id))
		if err := afterRoot(); err != nil {
			return err
		}
		leaf, err = record[api.Grant](r, api.Key("grant", id))
		if err != nil {
			return err
		}
	}
	if root.Parent != "" || root.ID != leaf.Root {
		return fmt.Errorf("INVALID_STATE: invalid root reference")
	}
	for g, count := leaf, 0; ; count++ {
		if count > 32 || g.Root != root.ID || g.Task != root.Task || g.DeploymentID != r.d.DeploymentID {
			return fmt.Errorf("INVALID_STATE: broken delegation path")
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
				return fmt.Errorf("INVALID_STATE: delegation path did not reach its root")
			}
			break
		}
		p, err := record[api.Grant](r, api.Key("grant", g.Parent))
		if err != nil {
			return err
		}
		if p.Digest != g.ParentDigest {
			return fmt.Errorf("INVALID_STATE: parent digest mismatch")
		}
		g = p
	}
	t, err := record[api.Task](r, api.Key("task", root.Task))
	if err != nil {
		return err
	}
	return r.credential(t.CreatorCredential, t.Creator)
}

func (r reader) credential(id, holder string) error {
	c, err := record[api.Credential](r, api.Key("credential", id))
	if err != nil {
		return err
	}
	if c.Subject != holder {
		return fmt.Errorf("INVALID_STATE: credential subject mismatch")
	}
	for _, subject := range []string{holder, c.Issuer} {
		i, err := record[api.Identity](r, api.Key("identity", subject))
		if err != nil {
			return err
		}
		d, err := record[api.Domain](r, api.Key("domain", i.Domain))
		if err != nil {
			return err
		}
		if _, err := record[api.Identity](r, api.Key("identity", d.DID)); err != nil {
			return err
		}
		if _, err := record[api.Certification](r, api.Key("certification", d.Certification)); err != nil {
			return err
		}
	}
	return nil
}

type streamObserver func(string, any)

type online struct {
	view
	instance            *instance
	role                string
	interval, timeLimit time.Duration
	started             time.Time
	observe             streamObserver

	mu        sync.Mutex
	ready     bool
	hardError error
	epoch     uint64
	attempts  map[string]time.Time
}

func (v *online) emit(kind string, fields any) {
	if v.observe != nil {
		v.observe(kind, fields)
	}
}

func (v *online) inhibit(err error) {
	v.mu.Lock()
	v.ready = false
	v.hardError = err
	v.epoch++
	clear(v.attempts)
	v.mu.Unlock()
	v.emit("view_rejected", err.Error())
}

func (v *online) resume() {
	v.mu.Lock()
	v.ready = true
	v.hardError = nil
	v.mu.Unlock()
}

func (v *online) follow(ctx context.Context, peer *peerClient) {
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

func (v *online) followOnce(ctx context.Context, peer *peerClient) error {
	// Capture the checkpoint before querying the Peer so another consumer's
	// concurrent progress cannot be compared against an older height response.
	last, err := v.head(ctx, v.db, false)
	if err != nil {
		v.inhibit(err)
		return err
	}
	height, err := peer.height(ctx)
	if err != nil {
		return err
	}
	if err := checkSourceHeight(height, last); err != nil {
		v.inhibit(err)
		return err
	}
	if err := v.d.validatePeer(ctx, peer); err != nil {
		// Retry unavailable queries. A mismatch in the retrieved evidence blocks reads.
		if errors.Is(err, errDeploymentMismatch) {
			v.inhibit(err)
		}
		return err
	}
	next := uint64(0)
	if last != nil {
		observed, err := peer.getBlock(ctx, last.Number)
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
		if err := v.apply(ctx, observed, nil); err != nil {
			v.inhibit(err)
			return err
		}
		next = last.Number + 1
	}
	v.resume()
	c, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := peer.deliver(c, next, math.MaxUint64)
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
		b, err := parseBlock(resp.GetBlock())
		if err == nil {
			err = v.apply(ctx, b, nil)
		}
		if err != nil {
			if ctx.Err() == nil {
				v.inhibit(err)
			}
			return err
		}
		v.emit("block_applied", b.point)
	}
	return ctx.Err()
}

// compareCheckpoint checks the complete prior block including the trusted validation filter.
func compareCheckpoint(raw []byte, b *block) bool {
	known, err := decode(raw, b.raw.ProtoReflect().New().Interface())
	return err == nil && proto.Equal(known, b.raw)
}

func checkSourceHeight(height uint64, last *point) error {
	if last != nil && height <= last.Number {
		return fmt.Errorf("Peer height %d is below applied checkpoint %d", height, last.Number)
	}
	return nil
}
