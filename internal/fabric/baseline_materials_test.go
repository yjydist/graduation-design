package fabric

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

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
	a, b, err := i.baselineRegistrations(d, f)
	if err != nil {
		t.Fatal(err)
	}
	if a.MaterialDigest != b.MaterialDigest || a.AnchorDigest != b.AnchorDigest || !reflect.DeepEqual(a.Snapshot, b.Snapshot) || a.Snapshot.Root != boot.Root {
		t.Fatal("registration inputs diverged")
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
			issuer := a.Snapshot.Identities[anchored.Issuer]
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
