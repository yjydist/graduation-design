package fabric

import (
	"context"
	"os"
	"testing"
	"time"

	"graduation-design/internal/centralstate"
	"graduation-design/internal/experiment"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

func TestBaselineSharedRealMaterials(t *testing.T) {
	inputs, err := experiment.Baseline(1109)
	if err != nil {
		t.Fatal(err)
	}
	i := &instance{dir: t.TempDir(), env: map[string]string{}, baseline: inputs}
	writeTestRoleCerts(t, i)
	g := &block{}
	g.Hash = api.Digest([]byte(t.Name()))
	boot, raw, err := i.bootstrap(g)
	if err != nil {
		t.Fatal(err)
	}
	d := &deployment{DeploymentFields: boot.DeploymentFields, DeploymentID: api.Digest(raw), Bootstrap: boot}
	f, err := i.fixtures(d)
	if err != nil {
		t.Fatal(err)
	}
	input, err := i.baselineRegistration(d, f)
	if err != nil {
		t.Fatal(err)
	}
	if !api.IsDigest(input.MaterialDigest) || !api.IsDigest(input.InputDigest) || input.Snapshot.Root != boot.Root {
		t.Fatal("invalid registration input")
	}
	for n, mode := range []string{api.RP, api.BM} {
		prefix := []string{"rp", "bm"}[n]
		grants := []api.Grant{f.RPG0, f.RPG1, f.RPG2}
		if n == 1 {
			grants = []api.Grant{f.BMG0, f.BMG1, f.BMG2}
		}
		var parsed []*protocol.ParsedGrant
		for hop, anchored := range grants {
			file := i.registrySubPath("grants", prefix+"_"+[]string{"g0", "g1", "g2"}[hop]+".jws")
			jws, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			issuer := input.Snapshot.Identities[anchored.Issuer]
			pub, _, err := protocol.ParseAppPublicKey(issuer.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			p, err := protocol.ParseAndVerifyGrant(string(jws), pub, issuer.KeyID)
			if err != nil {
				t.Fatal(err)
			}
			if p.Claims.AuthorizationMode != mode || p.Claims.MaxAmountMinor != inputs.Fixture.Path[hop].AmountMinor || p.Claims.RemainingDepth != inputs.Fixture.Path[hop].RemainingDepth || anchored.Digest != api.Digest(jws) {
				t.Fatal("signed grant differs from baseline")
			}
			parsed = append(parsed, p)
		}
		if err := protocol.VerifyGrantChain(parsed); err != nil {
			t.Fatal(err)
		}
	}
	// Exercise the actual signature-checking delivery path on a real PostgreSQL store.
	db := testPgPool(t)
	report := &seedReport{fixtures: f}
	if err := i.syncMaterialOutboxes(t.Context(), journal{instance: i, db: db, deploymentID: d.DeploymentID}, d, f, report); err != nil {
		t.Fatal(err)
	}
	w, err := buildM2WalletContext(t.Context(), i, *d, f, db, "", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if w == nil {
		t.Fatal("wallet not prepared")
	}
	var receipts int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM wallet_receipts WHERE deployment_id=$1`, d.DeploymentID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts < 6 {
		t.Fatalf("expected all six baseline grant deliveries, got %d", receipts)
	}
}

func TestBaselineRegistryReadbackUsesStoredAnchors(t *testing.T) {
	ctx := t.Context()
	db := testPgPool(t)
	r := newBaselineTestRun(t)
	r.db = db
	r.d.DeploymentID = randomID()
	boot := api.Bootstrap{Root: api.RootRecord{DID: "did:web:t.local", KeyVersion: 1}}
	bootJSON := payload(boot)
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
		api.BootstrapKey: bootJSON, api.Key("domain", domain.ID): payload(domain), grantKey: payload(grant),
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
		r.d.DeploymentID, grantKey, payload(changed)); err != nil {
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
