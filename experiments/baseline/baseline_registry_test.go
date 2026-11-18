package main

import (
	"context"
	"encoding/json"
	"testing"

	"graduation-design/internal/centralstate"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

func TestBaselineRegistryReadbackUsesStoredAnchors(t *testing.T) {
	ctx := t.Context()
	db := testPgPool(t)
	r := newBaselineTestRun(t)
	r.db = db
	r.d.DeploymentID = api.Digest([]byte(t.TempDir()))
	boot := api.Bootstrap{Root: api.RootRecord{DID: "did:web:t.local", KeyVersion: 1}}
	bootJSON := marshalTestRecord(boot)
	r.d.Bootstrap = boot
	r.d.BootstrapDigest = api.Digest(bootJSON)
	active := api.Version{Status: api.Active, Revision: 1}
	domain := api.Domain{ID: "A", Version: active}
	grant := api.Grant{ID: "grant-1", Digest: api.Digest([]byte("signed grant")), Version: active}
	preload := &protocol.SnapshotView{
		DeploymentID: r.d.DeploymentID, Root: boot.Root,
		Domains: map[string]api.Domain{domain.ID: domain},
		Grants:  map[string]api.Grant{grant.ID: grant},
	}
	central, err := centralstate.Initialize(ctx, db, preload)
	if err != nil {
		t.Fatal(err)
	}
	r.c0 = central
	t.Cleanup(func() {
		for _, query := range []string{
			`DELETE FROM centralized_registry WHERE deployment_id=$1`,
			`DELETE FROM fabric_current WHERE deployment=$1`,
			`DELETE FROM fabric_head WHERE deployment=$1`,
		} {
			if _, err := db.Exec(context.Background(), query, r.d.DeploymentID); err != nil {
				t.Error(err)
			}
		}
	})
	blockHash := api.Digest([]byte(t.Name()))
	if _, err := db.Exec(ctx, `INSERT INTO fabric_head VALUES($1,50,$2)`, r.d.DeploymentID, blockHash); err != nil {
		t.Fatal(err)
	}
	domain.Revision = 3
	grantKey := api.Key("grant", grant.ID)
	for key, raw := range map[string][]byte{
		api.BootstrapKey: bootJSON, api.Key("domain", domain.ID): marshalTestRecord(domain), grantKey: marshalTestRecord(grant),
	} {
		if _, err := db.Exec(ctx, `INSERT INTO fabric_current VALUES($1,$2,$3)`, r.d.DeploymentID, key, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.checkRegistryReadback(ctx, preload); err != nil {
		t.Fatal(err)
	}
	getReadback := func() *baselineRegistryReadback {
		return r.evidence.Manifest["registry_readback"].(*baselineRegistryReadback)
	}
	matched := getReadback()
	if !*matched.Matched || matched.C0.Revision != 1 || matched.C0.StateReadAt.IsZero() ||
		matched.C0.ObjectRevisions["domain/A"] != 1 || matched.Fabric.ObjectRevisions["domain/A"] != 3 ||
		matched.Fabric.BlockNumber != 50 || matched.Fabric.BlockHash != blockHash {
		t.Fatalf("unexpected matching registry evidence: %+v", matched)
	}

	// Change a signed anchor after preload without touching the original input.
	changed := grant
	changed.Digest = api.Digest([]byte("other signed grant"))
	if _, err := db.Exec(ctx, `UPDATE fabric_current SET value=$3 WHERE deployment=$1 AND key=$2`,
		r.d.DeploymentID, grantKey, marshalTestRecord(changed)); err != nil {
		t.Fatal(err)
	}
	if err := r.checkRegistryReadback(ctx, preload); err == nil {
		t.Fatal("accepted a different registered grant digest")
	}
	mismatch := getReadback()
	if mismatch.Matched == nil || *mismatch.Matched ||
		mismatch.C0.AnchorDigest != matched.C0.AnchorDigest || mismatch.Fabric.AnchorDigest == matched.Fabric.AnchorDigest {
		t.Fatal("missing or incorrect mismatch evidence")
	}

	if _, err := db.Exec(ctx, `DELETE FROM fabric_current WHERE deployment=$1 AND key=$2`, r.d.DeploymentID, grantKey); err != nil {
		t.Fatal(err)
	}
	if err := r.checkRegistryReadback(ctx, preload); err == nil {
		t.Fatal("accepted a missing Fabric grant")
	}
	if partial := getReadback(); partial.C0 == nil || partial.Fabric != nil || partial.Matched != nil {
		t.Fatalf("unexpected partial registry evidence: %+v", partial)
	}
}

func marshalTestRecord(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}
