//go:build db

package fabric

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/internal/testutil"
	"grad/platform/state"
	"grad/protocol"
	"grad/protocol/registry"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

type testFixtureSet struct {
	dep     *Deployment
	domA    registry.Domain
	domB    registry.Domain
	domC    registry.Domain
	certA   registry.Certification
	certB   registry.Certification
	certC   registry.Certification
	ids     map[string]registry.Identity
	creds   map[string]registry.Credential
	task    registry.Task
	g0      registry.Grant
	g1      registry.Grant
	certJWS string
}

func makeTestFixtureSet(t *testing.T, label string) *testFixtureSet {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	iv := registry.Interval{NBF: now.Add(-time.Hour).Unix(), EXP: now.Add(time.Hour).Unix()}

	mkPub := func() string {
		k, err := protocol.GenerateP256Key()
		require.NoError(t, err)
		hexPub, err := protocol.FormatAppPublicKey(&k.PublicKey)
		require.NoError(t, err)
		return hexPub
	}
	mkMgmt := func(msp, tag string) registry.Management {
		return registry.Management{MSPID: msp, CertificateSHA256: registry.Digest([]byte(label + ":" + msp + ":" + tag))}
	}

	df := registry.DeploymentFields{
		ChannelID:     registry.Channel,
		GenesisHash:   registry.Digest([]byte("genesis-" + label)),
		InstanceID:    registry.Digest([]byte("instance-" + label)),
		RegistryName:  registry.Registry,
		SchemaVersion: registry.Schema,
	}
	depID := df.DeploymentID()
	bound := registry.Bound{DeploymentID: depID}
	boot := registry.Bootstrap{
		DeploymentFields: df,
		Root: registry.RootRecord{
			DID:            "did:web:t.local",
			Management:     mkMgmt("TMsp", "T"),
			DocumentDigest: registry.Digest([]byte("t-doc-" + label)),
			KeyID:          "did:web:t.local#key-1",
			KeyVersion:     1,
			PublicKey:      mkPub(),
		},
		Initializer:        mkMgmt("AMsp", "init"),
		TaskCreator:        registry.TaskAuthority{Domain: "A", Subject: SubjectU, Management: mkMgmt("AMsp", "U")},
		ResourceID:         registry.Digest([]byte("resource:" + SubjectC)),
		ResourceOwner:      SubjectC,
		ResourceManagement: mkMgmt("CMsp", "C"),
	}
	bootRaw, err := json.Marshal(boot)
	require.NoError(t, err)
	dep := &Deployment{
		DeploymentFields: df,
		DeploymentID:     depID,
		BootstrapDigest:  registry.Digest(bootRaw),
		Bootstrap:        boot,
	}

	mkID := func(did, dom, kind, msp, tag string) registry.Identity {
		return registry.Identity{
			Bound:             bound,
			ID:                did,
			Domain:            dom,
			Kind:              kind,
			Management:        mkMgmt(msp, tag),
			DocumentDigest:    registry.Digest([]byte("doc-" + did)),
			KeyID:             did + "#key-1",
			KeyVersion:        1,
			PublicKey:         mkPub(),
			AccountCommitment: registry.Digest([]byte("acct-" + did)),
			Version:           registry.Version{Status: registry.Active, Revision: 1},
		}
	}

	ids := map[string]registry.Identity{
		"domA": mkID("did:web:a.local", "A", "DOMAIN", "AMsp", "domA"),
		"domB": mkID("did:web:b.local", "B", "DOMAIN", "BMsp", "domB"),
		"domC": mkID("did:web:c.local", "C", "DOMAIN", "CMsp", "domC"),
		"IA":   mkID("did:web:a.local:ia", "A", "ISSUER", "AMsp", "IA"),
		"IB":   mkID("did:web:b.local:ib", "B", "ISSUER", "BMsp", "IB"),
		"IC":   mkID("did:web:c.local:ic", "C", "ISSUER", "CMsp", "IC"),
		"U":    mkID(SubjectU, "A", "USER", "AMsp", "U"),
		"A1":   mkID("did:web:a.local:a1", "A", "AGENT", "AMsp", "A1"),
		"PA":   mkID("did:web:a.local:pa", "A", "SERVICE", "AMsp", "PA"),
		"B1":   mkID("did:web:b.local:b1", "B", "AGENT", "BMsp", "B1"),
		"C":    mkID(SubjectC, "C", "SERVICE", "CMsp", "C"),
	}

	certA := registry.Certification{
		Bound: bound, ID: "cert-A-" + label, Domain: "A", RootKeyVersion: 1,
		Digest: registry.Digest([]byte("cert-A-" + label)), Interval: iv,
		Version: registry.Version{Status: registry.Active, Revision: 1},
	}
	certB := registry.Certification{
		Bound: bound, ID: "cert-B-" + label, Domain: "B", RootKeyVersion: 1,
		Digest: registry.Digest([]byte("cert-B-" + label)), Interval: iv,
		Version: registry.Version{Status: registry.Active, Revision: 1},
	}
	certC := registry.Certification{
		Bound: bound, ID: "cert-C-" + label, Domain: "C", RootKeyVersion: 1,
		Digest: registry.Digest([]byte("cert-C-" + label)), Interval: iv,
		Version: registry.Version{Status: registry.Active, Revision: 1},
	}

	domA := registry.Domain{
		Bound: bound, ID: "A", DID: "did:web:a.local", Admin: mkMgmt("AMsp", "adminA"),
		Registrar: mkMgmt("AMsp", "regA"), Issuers: []string{ids["IA"].ID},
		Certification: certA.ID, Version: registry.Version{Status: registry.Active, Revision: 1},
	}
	domB := registry.Domain{
		Bound: bound, ID: "B", DID: "did:web:b.local", Admin: mkMgmt("BMsp", "adminB"),
		Registrar: mkMgmt("BMsp", "regB"), Issuers: []string{ids["IB"].ID},
		Certification: certB.ID, Version: registry.Version{Status: registry.Active, Revision: 1},
	}
	domC := registry.Domain{
		Bound: bound, ID: "C", DID: "did:web:c.local", Admin: mkMgmt("CMsp", "adminC"),
		Registrar: mkMgmt("CMsp", "regC"), Issuers: []string{ids["IC"].ID},
		Certification: certC.ID, Version: registry.Version{Status: registry.Active, Revision: 1},
	}

	mkCred := func(id, iss, sub string) registry.Credential {
		return registry.Credential{
			Bound: bound, ID: id, Issuer: iss, Subject: sub,
			IssuerKeyVersion: 1, SubjectKeyVersion: 1, Type: "EnterpriseIdentityCredential",
			ClaimNames: []string{"domain", "role"}, Digest: registry.Digest([]byte("cred-" + id)),
			Interval: iv, Version: registry.Version{Status: registry.Active, Revision: 1},
		}
	}
	creds := map[string]registry.Credential{
		"U":  mkCred("cred-u-"+label, ids["IA"].ID, ids["U"].ID),
		"A1": mkCred("cred-a1-"+label, ids["IA"].ID, ids["A1"].ID),
		"PA": mkCred("cred-pa-"+label, ids["IA"].ID, ids["PA"].ID),
		"B1": mkCred("cred-b1-"+label, ids["IB"].ID, ids["B1"].ID),
		"C":  mkCred("cred-c-"+label, ids["IC"].ID, ids["C"].ID),
	}

	task := registry.Task{
		Bound: bound, ID: "task-" + label, Creator: ids["U"].ID,
		CreatorCredential: creds["U"].ID, CreatorKeyVersion: 1,
		Domain: "A", Mode: registry.RP, Resource: boot.ResourceID,
		Digest: registry.Digest([]byte("task-" + label)), Interval: iv,
		Version: registry.Version{Status: registry.Active, Revision: 1},
	}

	g0ID := "g0-" + label
	g0Digest := registry.Digest([]byte("g0-jws-" + label))
	g0 := registry.Grant{
		Bound: bound, ID: g0ID, Schema: registry.Schema, Root: g0ID, Task: task.ID,
		Mode: registry.RP, Domain: "A", Resource: boot.ResourceID,
		Issuer: ids["C"].ID, Grantee: ids["U"].ID, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredential: creds["C"].ID, GranteeCredential: creds["U"].ID,
		Depth: 2, Digest: g0Digest, Interval: iv,
		Version: registry.Version{Status: registry.Active, Revision: 1},
	}
	g1 := registry.Grant{
		Bound: bound, ID: "g1-" + label, Schema: registry.Schema, Parent: g0ID, ParentDigest: g0Digest,
		Root: g0ID, Task: task.ID, Mode: registry.RP, Domain: "A", Resource: boot.ResourceID,
		Issuer: ids["U"].ID, Grantee: ids["A1"].ID, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredential: creds["U"].ID, GranteeCredential: creds["A1"].ID,
		Depth: 1, Digest: registry.Digest([]byte("g1-jws-" + label)), Interval: iv,
		Version: registry.Version{Status: registry.Active, Revision: 1},
	}

	return &testFixtureSet{
		dep: dep, domA: domA, domB: domB, domC: domC,
		certA: certA, certB: certB, certC: certC,
		ids: ids, creds: creds, task: task, g0: g0, g1: g1,
		certJWS: "eyJhbGciOiJFUzI1NiJ9.eyJkb21haW4iOiJDIn0.sig",
	}
}

func seedViewState(t *testing.T, pool *pgxpool.Pool, f *testFixtureSet, blockNo int64, blockHash string) {
	t.Helper()
	ctx := t.Context()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())

	putKV := func(k string, v any) {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1,$2,$3)
			ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, f.dep.DeploymentID, k, raw)
		require.NoError(t, err)
	}

	_, err = tx.Exec(ctx, `INSERT INTO fabric_head(deployment, block_no, hash) VALUES($1,$2,$3)
		ON CONFLICT(deployment) DO UPDATE SET block_no=EXCLUDED.block_no, hash=EXCLUDED.hash`,
		f.dep.DeploymentID, blockNo, blockHash)
	require.NoError(t, err)

	putKV(registry.BootstrapKey, f.dep.Bootstrap)
	putKV(registry.Key("domain", "A"), f.domA)
	putKV(registry.Key("domain", "B"), f.domB)
	putKV(registry.Key("domain", "C"), f.domC)
	putKV(registry.Key("certification", f.certA.ID), f.certA)
	putKV(registry.Key("certification", f.certB.ID), f.certB)
	putKV(registry.Key("certification", f.certC.ID), f.certC)
	for _, id := range f.ids {
		putKV(registry.Key("identity", id.ID), id)
	}
	for _, cred := range f.creds {
		putKV(registry.Key("credential", cred.ID), cred)
	}
	putKV(registry.Key("task", f.task.ID), f.task)
	putKV(registry.Key("grant", f.g0.ID), f.g0)
	putKV(registry.Key("grant", f.g1.ID), f.g1)

	_, err = tx.Exec(ctx, `INSERT INTO certification_receipts(
		deployment_id, domain_id, certification_id, recipient, cert_jws, cert_digest, received_at
	) VALUES($1,'C',$2,$3,$4,$5,$6)
	ON CONFLICT(deployment_id, domain_id, certification_id, recipient) DO UPDATE SET cert_jws=EXCLUDED.cert_jws`,
		f.dep.DeploymentID, f.certC.ID, f.ids["U"].ID, f.certJWS, f.certC.Digest, time.Now().UTC().Unix())
	require.NoError(t, err)

	require.NoError(t, tx.Commit(ctx))
}

func TestStateProviderAssembleSnapshotAndLockCheckpoint(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()
	f := makeTestFixtureSet(t, "repeatable")

	sp := NewStateProvider(pool, f.dep, nil)

	// 1. Empty fabric_head -> STATE_UNAVAILABLE without falling back to Peer.
	_, err := sp.AssembleSnapshot(ctx, f.g1.ID, time.Now().UTC())
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateUnavailable))

	// Populate height 5.
	h5Hash := registry.Digest([]byte("block-5"))
	seedViewState(t, pool, f, 5, h5Hash)

	// 2. Missing probe or exact monotonic deadline -> STATE_STALE.
	_, err = sp.AssembleSnapshot(ctx, f.g1.ID, time.Now().UTC())
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateStale))

	baseMono := time.Now()
	sp.SetStaticProbe(&state.ProbeLease{
		TxID:           registry.Digest([]byte("probe-tx-1")),
		ProbeBlock:     5,
		SentAt:         baseMono,
		Deadline:       baseMono.Add(5 * time.Second),
		SentMonoNs:     1000,
		DeadlineMonoNs: 5_000_001_000,
	})
	sp.SetMonoClock(func() time.Time { return baseMono.Add(5 * time.Second) })
	_, err = sp.AssembleSnapshot(ctx, f.g1.ID, time.Now().UTC())
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateStale))

	// 3. Fresh monotonic deadline + concurrent revocation mid-REPEATABLE READ keeps snapshot pinned at block 5!
	sp.SetMonoClock(func() time.Time { return baseMono.Add(2 * time.Second) })
	h6Hash := registry.Digest([]byte("block-6"))
	sp.SetAfterRootHook(func() error {
		g1Rev := f.g1
		g1Rev.Status = registry.Revoked
		g1Rev.Revision = 2
		raw, err := json.Marshal(g1Rev)
		if err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, "UPDATE fabric_current SET value=$3 WHERE deployment=$1 AND key=$2",
			f.dep.DeploymentID, registry.Key("grant", f.g1.ID), raw); err != nil {
			return err
		}
		_, err = pool.Exec(ctx, "UPDATE fabric_head SET block_no=6, hash=$2 WHERE deployment=$1",
			f.dep.DeploymentID, h6Hash)
		return err
	})

	snap5, err := sp.AssembleSnapshot(ctx, f.g1.ID, time.Now().UTC())
	sp.SetAfterRootHook(nil)
	require.NoError(t, err)
	assert.Equal(t, state.SourceFabric, snap5.StateSource)
	assert.Equal(t, int64(5), snap5.BlockNumber)
	assert.Equal(t, h5Hash, snap5.BlockHash)
	assert.Equal(t, registry.Active, snap5.Snapshot.Grants[f.g1.ID].Status)
	assert.Equal(t, f.certJWS, snap5.CertJWSByDom["C"])
	assert.Equal(t, f.certJWS, snap5.CertJWSByID[f.certC.ID])

	// 4. LockCheckpoint detects that fabric_head moved to block 6.
	tx1, err := pool.Begin(ctx)
	require.NoError(t, err)
	same, err := sp.LockCheckpoint(ctx, tx1, snap5)
	require.NoError(t, err)
	assert.False(t, same)
	require.NoError(t, tx1.Rollback(context.Background()))

	snap6, err := sp.AssembleSnapshot(ctx, f.g1.ID, time.Now().UTC())
	require.NoError(t, err)
	assert.Equal(t, int64(6), snap6.BlockNumber)
	assert.Equal(t, registry.Revoked, snap6.Snapshot.Grants[f.g1.ID].Status)

	tx2, err := pool.Begin(ctx)
	require.NoError(t, err)
	same, err = sp.LockCheckpoint(ctx, tx2, snap6)
	require.NoError(t, err)
	assert.True(t, same)
	require.NoError(t, tx2.Commit(ctx))

	// CheckFresh succeeds before deadline and rejects at deadline.
	lease, err := sp.CheckFresh(ctx, snap6)
	require.NoError(t, err)
	assert.Equal(t, snap6.Probe.TxID, lease.TxID)

	sp.SetMonoClock(func() time.Time { return baseMono.Add(5 * time.Second) })
	_, err = sp.CheckFresh(ctx, snap6)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateStale))

	// 5. Deleting a required dependency returns STATE_UNAVAILABLE.
	sp.SetMonoClock(func() time.Time { return baseMono.Add(2 * time.Second) })
	_, err = pool.Exec(ctx, "DELETE FROM fabric_current WHERE deployment=$1 AND key=$2",
		f.dep.DeploymentID, registry.Key("credential", f.creds["C"].ID))
	require.NoError(t, err)
	_, err = sp.AssembleSnapshot(ctx, f.g1.ID, time.Now().UTC())
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateUnavailable))
}

func TestStateProviderBMRootAndIdentityLink(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()
	f := makeTestFixtureSet(t, "bm-link")

	sp := NewStateProvider(pool, f.dep, nil)
	baseMono := time.Now()
	sp.SetStaticProbe(&state.ProbeLease{
		TxID:       registry.Digest([]byte("probe-tx-bm")),
		ProbeBlock: 10,
		SentAt:     baseMono,
		Deadline:   baseMono.Add(30 * time.Second),
	})
	sp.SetMonoClock(func() time.Time { return baseMono })

	seedViewState(t, pool, f, 10, registry.Digest([]byte("block-10")))

	bmTask := f.task
	bmTask.ID = "bm-task"
	bmTask.Mode = registry.BM
	bmG0 := f.g0
	bmG0.ID = "bm-g0"
	bmG0.Root = bmG0.ID
	bmG0.Task = bmTask.ID
	bmG0.Mode = registry.BM
	bmG0.Issuer = f.ids["PA"].ID
	bmG0.IssuerCredential = f.creds["PA"].ID

	putRec := func(k string, v any) {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1,$2,$3)
			ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, f.dep.DeploymentID, k, raw)
		require.NoError(t, err)
	}
	putRec(registry.Key("task", bmTask.ID), bmTask)
	putRec(registry.Key("grant", bmG0.ID), bmG0)

	// Without PurchasingAuthority on Domain A, BM snapshot assembly must fail.
	_, err := sp.AssembleSnapshot(ctx, bmG0.ID, time.Now().UTC())
	require.Error(t, err)

	// Configure PurchasingAuthority = PA and insert ACTIVE IdentityLink.
	domA := f.domA
	domA.PurchasingAuthority = f.ids["PA"].ID
	domA.Revision = 2
	putRec(registry.Key("domain", "A"), domA)

	now := time.Now().UTC()
	link := registry.IdentityLink{
		Bound:                   registry.Bound{DeploymentID: f.dep.DeploymentID},
		ID:                      "urn:grad:link:view-test",
		SourceDomain:            "A",
		SourceSubject:           f.ids["U"].ID,
		SourceKeyVersion:        1,
		SourceAccountCommitment: f.ids["U"].AccountCommitment,
		TargetDomain:            "B",
		TargetSubject:           f.ids["B1"].ID,
		TargetKeyVersion:        1,
		TargetAccountCommitment: f.ids["B1"].AccountCommitment,
		ProposalDigest:          registry.Digest([]byte("link-prop")),
		ProposedAt:              now.Add(-time.Minute).Unix(),
		ExpiresAt:               now.Add(time.Hour).Unix(),
		EffectiveActive:         true,
		Version:                 registry.Version{Status: registry.Active, Revision: 2},
	}
	putRec(registry.Key("link", link.ID), link)

	snap, err := sp.AssembleSnapshot(ctx, bmG0.ID, now)
	require.NoError(t, err)
	assert.True(t, snap.Snapshot.IsIdentityLinkEffective(link.ID))

	// Revoking link disables EffectiveActive in subsequent snapshot.
	link.Status = registry.Revoked
	link.EffectiveActive = false
	putRec(registry.Key("link", link.ID), link)
	snapRev, err := sp.AssembleSnapshot(ctx, bmG0.ID, now)
	require.NoError(t, err)
	assert.False(t, snapRev.Snapshot.IsIdentityLinkEffective(link.ID))
}

func TestStateProviderHistoricalSnapshotAndFindInactiveBlock(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()
	f := makeTestFixtureSet(t, "hist")

	// Insert contiguous blocks [0..4] and head=4.
	var hashes [5]string
	for n := 0; n <= 4; n++ {
		hashes[n] = registry.Digest([]byte{byte('b'), byte(n)})
		parent := ""
		if n > 0 {
			parent = hashes[n-1]
		}
		_, err := pool.Exec(ctx, `INSERT INTO fabric_block(deployment, block_no, hash, parent, data) VALUES($1,$2,$3,$4,$5)`,
			f.dep.DeploymentID, n, hashes[n], parent, []byte("raw"))
		require.NoError(t, err)
	}
	_, err := pool.Exec(ctx, `INSERT INTO fabric_head(deployment, block_no, hash) VALUES($1, 4, $2)`, f.dep.DeploymentID, hashes[4])
	require.NoError(t, err)

	putVer := func(blk int64, txIdx int, txID, key string, v any) {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `INSERT INTO fabric_version(deployment, key, block_no, tx_index, tx_id, value)
			VALUES($1,$2,$3,$4,$5,$6)`, f.dep.DeploymentID, key, blk, txIdx, txID, raw)
		require.NoError(t, err)
	}

	// Block 1: bootstrap, domains, certs, identities, credentials, task.
	putVer(1, 0, "tx-boot", registry.BootstrapKey, f.dep.Bootstrap)
	putVer(1, 1, "tx-domA", registry.Key("domain", "A"), f.domA)
	putVer(1, 2, "tx-domC", registry.Key("domain", "C"), f.domC)
	putVer(1, 3, "tx-certA", registry.Key("certification", f.certA.ID), f.certA)
	putVer(1, 4, "tx-certC", registry.Key("certification", f.certC.ID), f.certC)
	idx := 5
	for _, id := range f.ids {
		putVer(1, idx, "tx-id", registry.Key("identity", id.ID), id)
		idx++
	}
	for _, cred := range f.creds {
		putVer(1, idx, "tx-cred", registry.Key("credential", cred.ID), cred)
		idx++
	}
	putVer(1, idx, "tx-task", registry.Key("task", f.task.ID), f.task)

	// Block 2: G0 and G1 ACTIVE.
	putVer(2, 0, "tx-g0", registry.Key("grant", f.g0.ID), f.g0)
	putVer(2, 1, "tx-g1-active", registry.Key("grant", f.g1.ID), f.g1)

	// Block 4: G1 REVOKED.
	g1Rev := f.g1
	g1Rev.Status = registry.Revoked
	g1Rev.Revision = 2
	revokeTxID := registry.Digest([]byte("tx-g1-revoke"))
	putVer(4, 0, revokeTxID, registry.Key("grant", f.g1.ID), g1Rev)

	sp := NewStateProvider(pool, f.dep, nil)
	now := time.Now().UTC()

	// Historical snapshot at block 2 sees G1 ACTIVE (no online probe required).
	hist2, err := sp.AssembleHistoricalSnapshot(ctx, f.g1.ID, 2, now)
	require.NoError(t, err)
	assert.Equal(t, int64(2), hist2.BlockNumber)
	assert.Equal(t, hashes[2], hist2.BlockHash)
	assert.Equal(t, registry.Active, hist2.Snapshot.Grants[f.g1.ID].Status)

	// Historical snapshot at block 4 sees G1 REVOKED.
	hist4, err := sp.AssembleHistoricalSnapshot(ctx, f.g1.ID, 4, now)
	require.NoError(t, err)
	assert.Equal(t, int64(4), hist4.BlockNumber)
	assert.Equal(t, registry.Revoked, hist4.Snapshot.Grants[f.g1.ID].Status)

	// Boundary checks: block 0 and block > head must fail with STATE_UNAVAILABLE.
	_, err = sp.AssembleHistoricalSnapshot(ctx, f.g1.ID, 0, now)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateUnavailable))
	_, err = sp.AssembleHistoricalSnapshot(ctx, f.g1.ID, 5, now)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateUnavailable))

	// FindInactiveBlock locates block 4 and revokeTxID for G1.
	blk, txID, found, err := sp.FindInactiveBlock(ctx, "grant", f.g1.ID, 1)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, int64(4), blk)
	assert.Equal(t, revokeTxID, txID)

	// Searching after block 4 finds nothing.
	_, _, found, err = sp.FindInactiveBlock(ctx, "grant", f.g1.ID, 5)
	require.NoError(t, err)
	assert.False(t, found)

	// Introducing a history gap at block 3 causes block 4 historical snapshot to fail.
	_, err = pool.Exec(ctx, "DELETE FROM fabric_block WHERE deployment=$1 AND block_no=3", f.dep.DeploymentID)
	require.NoError(t, err)
	_, err = sp.AssembleHistoricalSnapshot(ctx, f.g1.ID, 4, now)
	require.Error(t, err)
	assert.True(t, protocol.HasCode(err, protocol.ErrCodeStateUnavailable))
}
