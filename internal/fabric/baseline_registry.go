package fabric

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

type baselineAnchorEvidence struct {
	AnchorDigest    string            `json:"anchor_digest"`
	ObjectRevisions map[string]uint64 `json:"object_revisions"`
}

type baselineCentralReadback struct {
	baselineAnchorEvidence
	Revision    int64     `json:"revision"`
	StateReadAt time.Time `json:"state_read_at"`
}

type baselineFabricReadback struct {
	baselineAnchorEvidence
	BlockNumber uint64 `json:"block_number"`
	BlockHash   string `json:"block_hash"`
}

type baselineRegistryReadback struct {
	C0      *baselineCentralReadback `json:"c0"`
	Fabric  *baselineFabricReadback  `json:"fabric"`
	Matched *bool                    `json:"matched"`
}

func baselineRegistryRecords(snap *protocol.SnapshotView) map[string]any {
	records := make(map[string]any)
	addBaselineRecords(records, "domain", snap.Domains)
	addBaselineRecords(records, "certification", snap.Certifications)
	addBaselineRecords(records, "identity", snap.Identities)
	addBaselineRecords(records, "credential", snap.Credentials)
	addBaselineRecords(records, "task", snap.Tasks)
	addBaselineRecords(records, "grant", snap.Grants)
	return records
}

func addBaselineRecords[T any](records map[string]any, kind string, values map[string]T) {
	for id, record := range values {
		records[kind+"/"+id] = record
	}
}

// baselineAnchorFingerprint excludes only source-specific record revisions from the comparison.
func baselineAnchorFingerprint(root api.RootRecord, records map[string]any) (baselineAnchorEvidence, error) {
	var evidence baselineAnchorEvidence
	raw, err := json.Marshal(records)
	if err != nil {
		return evidence, err
	}
	var anchors map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &anchors); err != nil {
		return evidence, err
	}
	revisions := make(map[string]uint64, len(anchors))
	for key, fields := range anchors {
		var revision uint64
		if err := json.Unmarshal(fields["revision"], &revision); err != nil || revision == 0 {
			return evidence, fmt.Errorf("missing or invalid registry revision for %s", key)
		}
		revisions[key] = revision
		delete(fields, "revision")
	}
	canonical, err := protocol.MarshalJCS(struct {
		Root    api.RootRecord                        `json:"root"`
		Records map[string]map[string]json.RawMessage `json:"records"`
	}{Root: root, Records: anchors})
	if err != nil {
		return evidence, err
	}
	return baselineAnchorEvidence{AnchorDigest: api.Digest(canonical), ObjectRevisions: revisions}, nil
}

func (r *baselineRun) checkRegistryReadback(ctx context.Context, expected *protocol.SnapshotView) error {
	readback := &baselineRegistryReadback{}
	r.evidence.Manifest["registry_readback"] = readback
	central, err := r.c0.ReadRegistry(ctx)
	if err != nil {
		return fmt.Errorf("read C0 registry: %w", err)
	}
	anchors, err := baselineAnchorFingerprint(central.Snapshot.Root, baselineRegistryRecords(central.Snapshot))
	if err != nil {
		return fmt.Errorf("fingerprint C0 registry: %w", err)
	}
	readback.C0 = &baselineCentralReadback{baselineAnchorEvidence: anchors, Revision: central.Revision, StateReadAt: central.StateReadAt}

	fabricView := view{db: r.db, d: r.d}
	keys := slices.Sorted(maps.Keys(baselineRegistryRecords(expected)))
	readback.Fabric, err = fabricView.readBaselineRegistry(ctx, keys)
	if err != nil {
		return fmt.Errorf("read Fabric registry: %w", err)
	}
	matched := readback.C0.AnchorDigest == readback.Fabric.AnchorDigest
	readback.Matched = &matched
	if !matched {
		return fmt.Errorf("C0 and Fabric registry anchors differ")
	}
	return nil
}

func (r *baselineRun) applyBaselineRegistry(ctx context.Context) error {
	peer, err := r.i.peer("c", "read")
	if err != nil {
		return err
	}
	fabricView := view{db: r.db, d: r.d}
	defer peer.close()
	if err := r.d.validatePeer(ctx, peer); err != nil {
		return err
	}
	height, err := peer.height(ctx)
	if err != nil {
		return err
	}
	// Apply the committed seed blocks before the purchasing experiment starts.
	for n := uint64(0); n < height; n++ {
		block, err := peer.getBlock(ctx, n)
		if err != nil {
			return err
		}
		if err := fabricView.apply(ctx, block, nil); err != nil {
			return err
		}
	}
	return nil
}

func (v view) readBaselineRegistry(ctx context.Context, keys []string) (*baselineFabricReadback, error) {
	tx, err := v.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	head, err := v.head(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	if head == nil {
		return nil, errUnavailable
	}
	snap := &snapshot{point: *head, Records: make(map[string]json.RawMessage)}
	r := reader{ctx: ctx, tx: tx, d: v.d, snapshot: snap}
	boot, err := record[api.Bootstrap](r, api.BootstrapKey)
	if err != nil {
		return nil, err
	}
	if boot != v.d.Bootstrap || api.Digest(snap.Records[api.BootstrapKey]) != v.d.BootstrapDigest {
		return nil, fmt.Errorf("DEPLOYMENT_MISMATCH: view bootstrap")
	}
	records := make(map[string]any, len(keys))
	for _, key := range keys {
		kind, id, _ := strings.Cut(key, "/")
		value, err := record[json.RawMessage](r, api.Key(kind, id))
		if err != nil {
			return nil, err
		}
		records[key] = value
	}
	anchors, err := baselineAnchorFingerprint(boot.Root, records)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &baselineFabricReadback{baselineAnchorEvidence: anchors, BlockNumber: head.Number, BlockHash: head.Hash}, nil
}
