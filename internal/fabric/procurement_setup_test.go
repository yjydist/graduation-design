package fabric

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

func TestProcurementSetupMaterialSigningAndDelivery(t *testing.T) {
	i := &instance{dir: t.TempDir(), env: map[string]string{}}
	writeTestRoleCerts(t, i)
	g := &block{}
	g.Hash = api.Digest([]byte(t.Name()))
	boot, raw, err := i.bootstrap(g)
	if err != nil {
		t.Fatal(err)
	}
	d := &deployment{DeploymentFields: boot.DeploymentFields, DeploymentID: api.Digest(raw), Bootstrap: boot}
	ids := func(mode string) ProcurementPathIDs {
		return ProcurementPathIDs{
			Task: api.Digest([]byte(mode + "/task")), G0: api.Digest([]byte(mode + "/G0")),
			G1: api.Digest([]byte(mode + "/G1")), G2: api.Digest([]byte(mode + "/G2")),
		}
	}
	setup := ProcurementSetup{
		Spec: protocol.TaskSpec{
			SupplierID: "urn:grad:supplier:C", ProductID: "urn:grad:product:P1",
			MaxQuantity: 1, Currency: "CNY", Description: "Explicit procurement setup",
			Resources: []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
			Actions:   []string{"order.create", "quote.read"},
		},
		RP: ids(api.RP), BM: ids(api.BM),
	}
	f, err := i.procurementFixtures(d, &setup)
	if err != nil {
		t.Fatal(err)
	}
	specDigest, err := setup.Spec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if f.RPTask.ID != setup.RP.Task || f.BMTask.ID != setup.BM.Task ||
		f.RPTask.Digest != specDigest || f.BMTask.Digest != specDigest {
		t.Fatal("registered task inputs differ from requested setup")
	}
	persisted, err := os.ReadFile(i.registryPath("fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(persisted, []byte(`"m2TaskSpec"`)) {
		t.Fatal("persisted fixture changed its task specification key")
	}
	f, err = i.procurementFixtures(d, &setup)
	if err != nil {
		t.Fatal(err)
	}
	different := setup
	different.Spec.MaxQuantity++
	if _, err := i.procurementFixtures(d, &different); err == nil {
		t.Fatal("accepted a change to the persisted setup")
	}
	snapshot := fixtureSnapshot(d, f, time.Time{})
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
			issuer := snapshot.Identities[anchored.Issuer]
			pub, _, err := protocol.ParseAppPublicKey(issuer.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			p, err := protocol.ParseAndVerifyGrant(string(jws), pub, issuer.KeyID)
			if err != nil {
				t.Fatal(err)
			}
			if p.Claims.AuthorizationMode != mode || p.Claims.MaxAmountMinor != []int64{500000, 500000, 100000}[hop] || p.Claims.RemainingDepth != int64(2-hop) || anchored.Digest != api.Digest(jws) {
				t.Fatal("signed grant differs from registered path")
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
	w, err := buildWalletContext(t.Context(), i, *d, f, db, "", nil, time.Now)
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
		t.Fatalf("expected all six procurement grant deliveries, got %d", receipts)
	}
}
