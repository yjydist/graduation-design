package main

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"graduation-design/internal/fabric"
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

	keys := slices.Sorted(maps.Keys(baselineRegistryRecords(expected)))
	ledgerKeys := make([]string, len(keys))
	for n, key := range keys {
		kind, id, _ := strings.Cut(key, "/")
		ledgerKeys[n] = api.Key(kind, id)
	}
	applied, err := fabric.ReadAppliedRegistry(ctx, r.db, r.d, ledgerKeys)
	if err != nil {
		return fmt.Errorf("read Fabric registry: %w", err)
	}
	records := make(map[string]any, len(keys))
	for n, key := range keys {
		records[key] = applied.Records[ledgerKeys[n]]
	}
	anchors, err = baselineAnchorFingerprint(applied.Root, records)
	if err != nil {
		return fmt.Errorf("fingerprint Fabric registry: %w", err)
	}
	readback.Fabric = &baselineFabricReadback{baselineAnchorEvidence: anchors, BlockNumber: applied.Number, BlockHash: applied.Hash}
	matched := readback.C0.AnchorDigest == readback.Fabric.AnchorDigest
	readback.Matched = &matched
	if !matched {
		return fmt.Errorf("C0 and Fabric registry anchors differ")
	}
	return nil
}
