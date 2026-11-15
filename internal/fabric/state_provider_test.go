package fabric

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

func seedSyntheticViewRows(t *testing.T, sp *StateProvider, dep *deployment, f *fixtures, certCJWS string, blockNo int64, blockHash string) {
	t.Helper()
	ctx := t.Context()
	tx, err := sp.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	putKV := func(k string, v any) {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1,$2,$3)
			ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, dep.DeploymentID, k, raw); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := tx.Exec(ctx, `INSERT INTO fabric_head(deployment, block_no, hash) VALUES($1,$2,$3)
		ON CONFLICT(deployment) DO UPDATE SET block_no=EXCLUDED.block_no, hash=EXCLUDED.hash`,
		dep.DeploymentID, blockNo, blockHash); err != nil {
		t.Fatal(err)
	}
	putKV(api.BootstrapKey, dep.Bootstrap)
	for domID, db := range f.Domains {
		d := db.Domain
		d.Issuers = []string{db.Issuers[0].ID}
		d.Certification = f.Certifications[domID].Certification.ID
		d.Version = api.Version{Status: api.Active, Revision: 1}
		putKV(api.Key("domain", domID), d)

		c := f.Certifications[domID].Certification
		c.Version = api.Version{Status: api.Active, Revision: 1}
		putKV(api.Key("certification", c.ID), c)

		di := db.Identity
		di.Version = api.Version{Status: api.Active, Revision: 1}
		putKV(api.Key("identity", di.ID), di)

		ii := db.Issuers[0]
		ii.Version = api.Version{Status: api.Active, Revision: 1}
		putKV(api.Key("identity", ii.ID), ii)
	}
	for role, id := range f.Identities {
		id.Version = api.Version{Status: api.Active, Revision: 1}
		putKV(api.Key("identity", id.ID), id)
		cred := f.Credentials[role]
		cred.Version = api.Version{Status: api.Active, Revision: 1}
		putKV(api.Key("credential", cred.ID), cred)
	}
	putKV(api.Key("task", f.Task.ID), activateTaskSnapshot(f.Task))
	putKV(api.Key("grant", f.G0.ID), activateGrantSnapshot(f.G0))
	putKV(api.Key("grant", f.G1.ID), activateGrantSnapshot(f.G1))

	if _, err := tx.Exec(ctx, `INSERT INTO certification_receipts(
		deployment_id, domain_id, certification_id, recipient, cert_jws, cert_digest, received_at
	) VALUES($1,'C',$2,$3,$4,$5,$6)
	ON CONFLICT(deployment_id, domain_id, certification_id, recipient) DO UPDATE SET cert_jws=EXCLUDED.cert_jws`,
		dep.DeploymentID, f.Certifications["C"].Certification.ID, f.Identities["U"].ID,
		certCJWS, f.Certifications["C"].Certification.Digest, time.Now().UTC().Unix()); err != nil {
		t.Fatal(err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStateProviderRepeatableReadAndFaults(t *testing.T) {
	pool := testPgPool(t)
	ctx := t.Context()

	dir := t.TempDir()
	inst := &instance{dir: dir, env: map[string]string{}}
	writeTestRoleCerts(t, inst)

	genesis := &block{}
	genesis.Hash = api.Digest([]byte("test-sp-genesis-" + time.Now().Format(time.RFC3339Nano)))
	boot, bootRaw, err := inst.bootstrap(genesis)
	if err != nil {
		t.Fatal(err)
	}
	dep := &deployment{
		DeploymentFields: boot.DeploymentFields,
		DeploymentID:     api.Digest(bootRaw),
		Bootstrap:        boot,
	}
	f, err := inst.fixtures(dep)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM fabric_current WHERE deployment=$1", dep.DeploymentID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM fabric_head WHERE deployment=$1", dep.DeploymentID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM certification_receipts WHERE deployment_id=$1", dep.DeploymentID)
	})

	certCJWS, err := os.ReadFile(inst.registrySubPath("certifications", "C.jws"))
	if err != nil {
		t.Fatal(err)
	}

	sp := NewStateProvider(pool, dep, nil)

	// 1. Empty fabric_head -> 503 STATE_UNAVAILABLE without falling back to Peer
	if _, err := sp.AssembleProtocolSnapshot(ctx, f.G0.ID, time.Now().UTC()); !protocol.HasCode(err, protocol.ErrCodeStateUnavailable) {
		t.Fatalf("expected STATE_UNAVAILABLE on empty fabric_head, got %v", err)
	}

	// Populate height 5
	h1Hash := api.Digest([]byte("block-5"))
	seedSyntheticViewRows(t, sp, dep, f, string(certCJWS), 5, h1Hash)

	// 2. Missing probe or expired monotonic deadline -> 503 STATE_STALE
	if _, err := sp.AssembleProtocolSnapshot(ctx, f.G0.ID, time.Now().UTC()); !protocol.HasCode(err, protocol.ErrCodeStateStale) {
		t.Fatalf("expected STATE_STALE when probe lease is absent, got %v", err)
	}
	baseMono := time.Now()
	sp.SetStaticProbe(&ProbeSnapshot{
		TxID:       api.Digest([]byte("probe-tx-1")),
		Identity:   api.Management{MSPID: "CMsp", Fingerprint: api.Digest([]byte("probe"))},
		ProbeBlock: 5,
		SentAt:     baseMono,
		Deadline:   baseMono.Add(5 * time.Second),
	})
	sp.SetMonoClock(func() time.Time { return baseMono.Add(5 * time.Second) })
	if _, err := sp.AssembleProtocolSnapshot(ctx, f.G0.ID, time.Now().UTC()); !protocol.HasCode(err, protocol.ErrCodeStateStale) {
		t.Fatalf("expected STATE_STALE at exact monotonic probe deadline, got %v", err)
	}

	// 3. Fresh monotonic deadline + concurrent mutation mid-REPEATABLE READ transaction -> snapshot stays pinned at height 5!
	sp.SetMonoClock(func() time.Time { return baseMono.Add(2 * time.Second) })
	sp.mu.Lock()
	sp.afterRoot = func() error {
		// Simulate another transaction advancing fabric_head to block 6 and revoking G0 in fabric_current
		g0Rev := activateGrantSnapshot(f.G0)
		g0Rev.Status = api.Revoked
		raw, _ := json.Marshal(g0Rev)
		if _, err := pool.Exec(ctx, "UPDATE fabric_current SET value=$3 WHERE deployment=$1 AND key=$2",
			dep.DeploymentID, api.Key("grant", f.G0.ID), raw); err != nil {
			return err
		}
		_, err := pool.Exec(ctx, "UPDATE fabric_head SET block_no=6, hash=$2 WHERE deployment=$1",
			dep.DeploymentID, api.Digest([]byte("block-6")))
		return err
	}
	sp.mu.Unlock()

	view, err := sp.AssembleProtocolSnapshot(ctx, f.G0.ID, time.Now().UTC())
	sp.mu.Lock()
	sp.afterRoot = nil
	sp.mu.Unlock()
	if err != nil {
		t.Fatalf("AssembleProtocolSnapshot failed: %v", err)
	}
	if view.Checkpoint.Height != 5 || view.Checkpoint.Hash != h1Hash {
		t.Fatalf("expected repeatable read checkpoint 5/%s, got %d/%s", h1Hash, view.Checkpoint.Height, view.Checkpoint.Hash)
	}
	if view.Snapshot.Grants[f.G0.ID].Status != api.Active {
		t.Fatalf("expected G0 ACTIVE inside REPEATABLE READ snapshot even after concurrent revoke commit, got %s", view.Snapshot.Grants[f.G0.ID].Status)
	}
	if view.CertJWSByDom["C"] != string(certCJWS) {
		t.Fatalf("expected domain C certification JWS loaded inside consistent view")
	}

	// 4. Deleting a required dependency returns 503 STATE_UNAVAILABLE
	if _, err := pool.Exec(ctx, "DELETE FROM fabric_current WHERE deployment=$1 AND key=$2",
		dep.DeploymentID, api.Key("credential", f.Credentials["C"].ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := sp.AssembleProtocolSnapshot(ctx, f.G0.ID, time.Now().UTC()); !protocol.HasCode(err, protocol.ErrCodeStateUnavailable) {
		t.Fatalf("expected STATE_UNAVAILABLE on missing dependency, got %v", err)
	}
}

func TestStateProviderBMRootAndIdentityLinkView(t *testing.T) {
	pool := testPgPool(t)
	ctx := t.Context()

	dir := t.TempDir()
	inst := &instance{dir: dir, env: map[string]string{}}
	writeTestRoleCerts(t, inst)

	genesis := &block{}
	genesis.Hash = api.Digest([]byte("test-bm-view-genesis-" + time.Now().Format(time.RFC3339Nano)))
	boot, bootRaw, err := inst.bootstrap(genesis)
	if err != nil {
		t.Fatal(err)
	}
	dep := &deployment{
		DeploymentFields: boot.DeploymentFields,
		DeploymentID:     api.Digest(bootRaw),
		Bootstrap:        boot,
	}
	f, err := inst.fixtures(dep)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM fabric_current WHERE deployment=$1", dep.DeploymentID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM fabric_head WHERE deployment=$1", dep.DeploymentID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM certification_receipts WHERE deployment_id=$1", dep.DeploymentID)
	})

	certCJWS, err := os.ReadFile(inst.registrySubPath("certifications", "C.jws"))
	if err != nil {
		t.Fatal(err)
	}
	sp := NewStateProvider(pool, dep, nil)
	baseMono := time.Now()
	sp.SetStaticProbe(&ProbeSnapshot{
		TxID:       api.Digest([]byte("probe-tx-bm")),
		Identity:   api.Management{MSPID: "CMsp", Fingerprint: api.Digest([]byte("probe"))},
		ProbeBlock: 10,
		SentAt:     baseMono,
		Deadline:   baseMono.Add(30 * time.Second),
	})
	sp.SetMonoClock(func() time.Time { return baseMono })

	seedSyntheticViewRows(t, sp, dep, f, string(certCJWS), 10, api.Digest([]byte("block-10")))

	// Insert BM task & PA-issued G0 without PA set in Domain["A"] -> must fail view assembly!
	bmTask := f.Task
	bmTask.ID = api.Digest([]byte("bm-task-view"))
	bmTask.Mode = api.BM
	bmG0 := f.G0
	bmG0.ID = api.Digest([]byte("bm-g0-view"))
	bmG0.Root = bmG0.ID
	bmG0.Task = bmTask.ID
	bmG0.Mode = api.BM
	bmG0.Issuer = f.Identities["PA"].ID
	bmG0.IssuerCredential = f.Credentials["PA"].ID

	putRec := func(k string, v any) {
		raw, _ := json.Marshal(v)
		if _, err := pool.Exec(ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1,$2,$3)
			ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, dep.DeploymentID, k, raw); err != nil {
			t.Fatal(err)
		}
	}
	putRec(api.Key("task", bmTask.ID), activateTaskSnapshot(bmTask))
	putRec(api.Key("grant", bmG0.ID), activateGrantSnapshot(bmG0))

	if _, err := sp.AssembleProtocolSnapshot(ctx, bmG0.ID, time.Now().UTC()); err == nil {
		t.Fatalf("expected BM view assembly to fail when Domain.PurchasingAuthority is unset")
	}

	// Set Domain A PurchasingAuthority = PA and insert an ACTIVE IdentityLink -> view assembly succeeds & link is effective.
	domA := f.Domains["A"].Domain
	domA.Issuers = []string{f.Domains["A"].Issuers[0].ID}
	domA.Certification = f.Certifications["A"].Certification.ID
	domA.PurchasingAuthority = f.Identities["PA"].ID
	domA.Version = api.Version{Status: api.Active, Revision: 2}
	putRec(api.Key("domain", "A"), domA)

	now := time.Now().UTC()
	link := api.IdentityLink{
		Bound:                   api.Bound{DeploymentID: dep.DeploymentID},
		ID:                      "urn:grad:link:view-test",
		SourceDomain:            "A",
		SourceSubject:           f.Identities["U"].ID,
		SourceKeyVersion:        1,
		SourceAccountCommitment: f.Identities["U"].AccountCommitment,
		TargetDomain:            "B",
		TargetSubject:           f.Identities["B1"].ID,
		TargetKeyVersion:        1,
		TargetAccountCommitment: f.Identities["B1"].AccountCommitment,
		ProposalDigest:          api.Digest([]byte("link-prop")),
		ProposedAt:              now.Add(-time.Minute).Unix(),
		ExpiresAt:               now.Add(time.Hour).Unix(),
		EffectiveActive:         true,
		Version:                 api.Version{Status: api.Active, Revision: 2},
	}
	putRec(api.Key("link", link.ID), link)

	view, err := sp.AssembleProtocolSnapshot(ctx, bmG0.ID, now)
	if err != nil {
		t.Fatalf("expected BM view assembly to succeed after SetPurchasingAuthority: %v", err)
	}
	if !view.Snapshot.IsIdentityLinkEffective(link.ID) {
		t.Fatalf("expected active identity link to be effective in snapshot")
	}
	// Revoking link disables EffectiveActive in snapshot.
	link.Status = api.Revoked
	link.EffectiveActive = false
	putRec(api.Key("link", link.ID), link)
	viewRev, err := sp.AssembleProtocolSnapshot(ctx, bmG0.ID, now)
	if err != nil {
		t.Fatalf("AssembleProtocolSnapshot after link revoke: %v", err)
	}
	if viewRev.Snapshot.IsIdentityLinkEffective(link.ID) {
		t.Fatalf("expected revoked identity link to report effectiveActive=false")
	}
}
