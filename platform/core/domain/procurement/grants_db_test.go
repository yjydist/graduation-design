//go:build db

package procurement

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/platform/core/ledger"
	"grad/platform/internal/testutil"
	"grad/protocol"
	preg "grad/protocol/registry"
)

type grantTestFixture struct {
	dep    *ledger.Deployment
	now    time.Time
	task   preg.Task
	spec   protocol.TaskSpec
	run    Run
	certs  map[string]string
	actors map[string]GrantActor
	recs   map[string]GrantRecipient
	base   map[string]any
}

func newGrantTestFixture(t *testing.T, now time.Time) *grantTestFixture {
	t.Helper()
	interval := preg.Interval{NBF: now.Add(-time.Hour).Unix(), EXP: now.Add(time.Hour).Unix()}
	validFrom := time.Unix(interval.NBF, 0).UTC().Format(time.RFC3339)
	validUntil := time.Unix(interval.EXP, 0).UTC().Format(time.RFC3339)

	genesisHash := preg.Digest([]byte("proc-genesis"))
	depBinding := protocol.DeploymentBinding{
		ChannelID:     preg.Channel,
		GenesisHash:   genesisHash,
		InstanceID:    preg.Digest([]byte("proc-instance")),
		Purpose:       protocol.DeploymentPurpose,
		RegistryName:  preg.Registry,
		SchemaVersion: protocol.SchemaVersion,
	}
	depID, err := protocol.ComputeDeploymentID(depBinding)
	require.NoError(t, err)

	type keyBundle struct {
		did   string
		priv  *ecdsa.PrivateKey
		pub   string
		kid   string
		docDg string
		mgmt  preg.Management
	}
	genKey := func(did, msp, hashChar string) keyBundle {
		priv, err := protocol.GenerateP256Key()
		require.NoError(t, err)
		pubHex, err := protocol.FormatAppPublicKey(&priv.PublicKey)
		require.NoError(t, err)
		kid := did + "#key-1"
		doc, err := protocol.NewDIDDocument(did, kid, &priv.PublicKey)
		require.NoError(t, err)
		docDig, err := doc.Digest()
		require.NoError(t, err)
		return keyBundle{
			did:   did,
			priv:  priv,
			pub:   pubHex,
			kid:   kid,
			docDg: docDig,
			mgmt:  preg.Management{MSPID: msp, CertificateSHA256: strings.Repeat(hashChar, 64)},
		}
	}

	rootK := genKey("did:web:t.local", "TMsp", "1")
	domAK := genKey("did:web:a.local", "AMsp", "2")
	domBK := genKey("did:web:b.local", "BMsp", "3")
	domCK := genKey("did:web:c.local", "CMsp", "4")
	iaK := genKey("did:web:a.local:ia", "AMsp", "5")
	ibK := genKey("did:web:b.local:ib", "BMsp", "6")
	icK := genKey("did:web:c.local:ic", "CMsp", "7")
	uK := genKey("did:web:a.local:u", "AMsp", "8")
	paK := genKey("did:web:a.local:pa", "AMsp", "9")
	a1K := genKey("did:web:a.local:a1", "AMsp", "a")
	b1K := genKey("did:web:b.local:b1", "BMsp", "b")
	cK := genKey("did:web:c.local:supplier", "CMsp", "c")

	base := map[string]any{}
	addIdentity := func(k keyBundle, domain, kind string) {
		base[preg.Key("identity", k.did)] = preg.Identity{
			Bound:          preg.Bound{DeploymentID: depID},
			ID:             k.did,
			Domain:         domain,
			Kind:           kind,
			Management:     k.mgmt,
			KeyID:          k.kid,
			KeyVersion:     1,
			PublicKey:      k.pub,
			DocumentDigest: k.docDg,
			Version:        preg.Version{Status: preg.Active, Revision: 1},
		}
	}
	addIdentity(domAK, "A", "DOMAIN")
	addIdentity(domBK, "B", "DOMAIN")
	addIdentity(domCK, "C", "DOMAIN")
	addIdentity(iaK, "A", "ISSUER")
	addIdentity(ibK, "B", "ISSUER")
	addIdentity(icK, "C", "ISSUER")
	addIdentity(uK, "A", "USER")
	addIdentity(paK, "A", "SERVICE")
	addIdentity(a1K, "A", "AGENT")
	addIdentity(b1K, "B", "AGENT")
	addIdentity(cK, "C", "SERVICE")

	certs := map[string]string{}
	addDomainAndCert := func(domID string, domK, issK keyBundle, pa string) {
		certID := "urn:grad:cert:" + domID + ":v1"
		scopes := []preg.IssuerScope{{
			ID:              issK.did,
			AppKeyVersion:   1,
			CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity},
			ClaimNames:      []string{"domain", "role"},
		}}
		jws, dig, err := protocol.SignDomainAuthorityCredential(rootK.priv, rootK.kid, &protocol.DomainAuthorityCredential{
			Type:             []string{protocol.CredentialTypeVC, protocol.CredentialTypeDomainAuthority},
			ID:               certID,
			DeploymentID:     depID,
			Issuer:           rootK.did,
			Iss:              rootK.did,
			Sub:              domK.did,
			IssuerKeyVersion: 1,
			ValidFrom:        validFrom,
			ValidUntil:       validUntil,
			NBF:              interval.NBF,
			EXP:              interval.EXP,
			CredentialStatus: protocol.CredentialStatus{ID: certID, Type: protocol.StatusTypeDomainCertification},
			CredentialSubject: protocol.DomainAuthoritySubject{
				ID:              domK.did,
				DomainID:        domID,
				IdentityIssuers: scopes,
			},
		})
		require.NoError(t, err)
		certs[domID] = jws
		base[preg.Key("domain", domID)] = preg.Domain{
			Bound:               preg.Bound{DeploymentID: depID},
			ID:                  domID,
			DID:                 domK.did,
			Admin:               domK.mgmt,
			Registrar:           domK.mgmt,
			Certification:       certID,
			Issuers:             []string{issK.did},
			PurchasingAuthority: pa,
			Version:             preg.Version{Status: preg.Active, Revision: 1},
		}
		base[preg.Key("certification", certID)] = preg.Certification{
			Bound:          preg.Bound{DeploymentID: depID},
			ID:             certID,
			Domain:         domID,
			RootKeyVersion: 1,
			Digest:         dig,
			Scopes:         scopes,
			Interval:       interval,
			Version:        preg.Version{Status: preg.Active, Revision: 1},
		}
	}
	addDomainAndCert("A", domAK, iaK, paK.did)
	addDomainAndCert("B", domBK, ibK, "")
	addDomainAndCert("C", domCK, icK, "")

	actors := map[string]GrantActor{}
	recs := map[string]GrantRecipient{}
	addActor := func(name, domID, entityType, role string, k, issK keyBundle) {
		credID := "urn:grad:cred:" + name
		jwk, err := protocol.JWKFromPublicKey(&k.priv.PublicKey)
		require.NoError(t, err)
		sdjwt, err := protocol.IssueEnterpriseIdentityCredential(issK.priv, issK.kid, protocol.EnterpriseIdentityCredential{
			Type:              []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
			ID:                credID,
			DeploymentID:      depID,
			Issuer:            issK.did,
			Iss:               issK.did,
			Sub:               k.did,
			IssuerKeyVersion:  1,
			AppKeyVersion:     1,
			ValidFrom:         validFrom,
			ValidUntil:        validUntil,
			NBF:               interval.NBF,
			EXP:               interval.EXP,
			Cnf:               protocol.ConfirmationKey{JWK: jwk},
			CredentialStatus:  protocol.CredentialStatus{ID: credID, Type: protocol.StatusTypeCredential},
			CredentialSubject: protocol.SDJWTCredentialSubject{ID: k.did},
		}, domID, role, nil)
		require.NoError(t, err)
		pres := sdjwt.PresentationPrefix
		base[preg.Key("credential", credID)] = preg.Credential{
			Bound:             preg.Bound{DeploymentID: depID},
			ID:                credID,
			Subject:           k.did,
			Issuer:            issK.did,
			Type:              protocol.CredentialTypeEnterpriseIdentity,
			IssuerKeyVersion:  1,
			SubjectKeyVersion: 1,
			Digest:            sdjwt.AnchorDigest,
			ClaimNames:        []string{"domain", "role"},
			Interval:          interval,
			Version:           preg.Version{Status: preg.Active, Revision: 1},
		}
		actors[name] = GrantActor{
			Management: k.mgmt,
			Signer: wallet.Signer{
				Actor:             name,
				DID:               k.did,
				KeyID:             k.kid,
				CredentialID:      credID,
				KeyVersion:        1,
				DomainID:          domID,
				EntityType:        entityType,
				PrivateKey:        k.priv,
				SDJWTPresentation: pres,
			},
		}
		recs[name] = GrantRecipient{DID: k.did, CredentialID: credID}
	}
	addActor("U", "A", "USER", "procurement-owner", uK, iaK)
	addActor("PA", "A", "SERVICE", "purchasing-authority", paK, iaK)
	addActor("A1", "A", "AGENT", "procurement-agent", a1K, iaK)
	addActor("B1", "B", "AGENT", "broker-agent", b1K, ibK)
	addActor("C", "C", "SERVICE", "supplier-service", cK, icK)

	spec := protocol.TaskSpec{
		SupplierID:  DefaultSupplierID,
		ProductID:   "urn:grad:product:P1",
		MaxQuantity: 1,
		Currency:    DefaultCurrency,
		Description: "verifiable dynamically confirmed task",
		Resources:   []string{protocol.ResourceOrders, protocol.ResourceQuotes},
		Actions:     []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
	}
	specDigest, err := spec.Digest()
	require.NoError(t, err)

	runID := preg.Digest([]byte("original run"))
	taskID := preg.Digest([]byte(depID + "/workbench/" + runID))
	task := preg.Task{
		Bound:             preg.Bound{DeploymentID: depID},
		ID:                taskID,
		Creator:           uK.did,
		CreatorCredential: actors["U"].Signer.CredentialID,
		CreatorKeyVersion: 1,
		Domain:            "A",
		Mode:              preg.RP,
		Resource:          "urn:grad:resource:procurement",
		Digest:            specDigest,
		Interval:          preg.Interval{NBF: now.Add(-time.Minute).Unix(), EXP: now.Add(15 * time.Minute).Unix()},
		Version:           preg.Version{Status: preg.Active, Revision: 1},
	}
	base[preg.Key("task", task.ID)] = task

	boot := preg.Bootstrap{
		DeploymentFields: preg.DeploymentFields{
			ChannelID:     depBinding.ChannelID,
			GenesisHash:   depBinding.GenesisHash,
			InstanceID:    depBinding.InstanceID,
			Purpose:       depBinding.Purpose,
			RegistryName:  depBinding.RegistryName,
			SchemaVersion: depBinding.SchemaVersion,
		},
		ResourceID:         task.Resource,
		ResourceOwner:      cK.did,
		ResourceManagement: cK.mgmt,
		TaskCreator:        preg.TaskAuthority{Domain: "A", Subject: uK.did, Management: uK.mgmt},
		Root: preg.RootRecord{
			DID:        rootK.did,
			Management: rootK.mgmt,
			KeyID:      rootK.kid,
			KeyVersion: 1,
			PublicKey:  rootK.pub,
		},
	}
	bootRaw, err := json.Marshal(boot)
	require.NoError(t, err)
	base[preg.BootstrapKey] = boot

	dep := &ledger.Deployment{
		DeploymentID:    depID,
		GenesisHash:     genesisHash,
		ConfigDigest:    preg.Digest([]byte("cfg")),
		Bootstrap:       boot,
		BootstrapDigest: preg.Digest(bootRaw),
		DefinitionBlock: ledger.Point{Number: 1, Hash: preg.Digest([]byte("def-blk"))},
		InitBlock:       ledger.Point{Number: 2, Hash: preg.Digest([]byte("init-blk"))},
	}

	run := Run{
		RunID:  runID,
		TaskID: taskID,
		Stage:  StageDispatch,
		Status: RunPending,
		Task: Draft{
			ProductID:      spec.ProductID,
			Quantity:       spec.MaxQuantity,
			Mode:           task.Mode,
			MaxAmountMinor: 100000,
			ExpiresAt:      task.EXP,
			DelegateDID:    a1K.did,
			Description:    spec.Description,
		},
	}
	return &grantTestFixture{
		dep:    dep,
		now:    now,
		task:   task,
		spec:   spec,
		run:    run,
		certs:  certs,
		actors: actors,
		recs:   recs,
		base:   base,
	}
}

// applyTestBlock writes a validated block directly into fabric_block, fabric_version,
// fabric_current, and fabric_head without importing Fabric protobuf types into L2 tests.
func applyTestBlock(t *testing.T, ctx context.Context, db *pgxpool.Pool, depID string, blockNo uint64, hash, parent, txID string, records map[string]any) {
	t.Helper()
	_, err := db.Exec(ctx, `INSERT INTO fabric_block(deployment,block_no,hash,parent,data) VALUES($1,$2,$3,$4,$5)`,
		depID, blockNo, hash, parent, []byte{})
	require.NoError(t, err)
	for key, val := range records {
		raw, err := json.Marshal(val)
		require.NoError(t, err)
		_, err = db.Exec(ctx, `INSERT INTO fabric_version(deployment,key,block_no,tx_index,tx_id,value) VALUES($1,$2,$3,0,$4,$5)`,
			depID, key, blockNo, txID, raw)
		require.NoError(t, err)
		_, err = db.Exec(ctx, `INSERT INTO fabric_current(deployment,key,value) VALUES($1,$2,$3)
			ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, depID, key, raw)
		require.NoError(t, err)
	}
	_, err = db.Exec(ctx, `INSERT INTO fabric_head(deployment,block_no,hash) VALUES($1,$2,$3)
		ON CONFLICT(deployment) DO UPDATE SET block_no=EXCLUDED.block_no, hash=EXCLUDED.hash`, depID, blockNo, hash)
	require.NoError(t, err)
}

func seedBaseBlocks(t *testing.T, ctx context.Context, fx *grantTestFixture, dbs ...*pgxpool.Pool) {
	t.Helper()
	initTx := preg.Digest([]byte("confirmed task and identity state"))
	for _, db := range dbs {
		applyTestBlock(t, ctx, db, fx.dep.DeploymentID, 0, fx.dep.GenesisHash, "", "", nil)
		applyTestBlock(t, ctx, db, fx.dep.DeploymentID, 1, fx.dep.DefinitionBlock.Hash, fx.dep.GenesisHash, "", nil)
		applyTestBlock(t, ctx, db, fx.dep.DeploymentID, 2, fx.dep.InitBlock.Hash, fx.dep.DefinitionBlock.Hash, initTx, fx.base)
	}
}

func TestGrantOperationsIssueDeliverChildAnchorAndDispatchTransitions(t *testing.T) {
	ctx := t.Context()
	dbA, dbB, dbC := testutil.OpenMigratedPool(t), testutil.OpenMigratedPool(t), testutil.OpenMigratedPool(t)
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }

	fx := newGrantTestFixture(t, now)
	seedBaseBlocks(t, ctx, fx, dbA, dbB, dbC)

	// Verify SyncCertifications uses ledger.View.FirstVersionCommit cleanly.
	syncedA, err := SyncCertifications(ctx, dbA, fx.dep, "A", fx.certs, now)
	require.NoError(t, err)
	require.Len(t, syncedA, 3)

	mgmtC := domreg.NewService(dbC, fx.dep.DeploymentID, fx.dep.Bootstrap.Root.Management, nil)
	gC, err := NewGrantOperations(GrantOperationsConfig{
		Deployment:     fx.dep,
		DomainID:       "C",
		DB:             dbC,
		Management:     mgmtC,
		Certifications: fx.certs,
		Now:            clock,
		Actors:         map[string]GrantActor{"C": fx.actors["C"]},
	})
	require.NoError(t, err)

	mgmtA := domreg.NewService(dbA, fx.dep.DeploymentID, fx.dep.Bootstrap.Root.Management, nil)
	gA, err := NewGrantOperations(GrantOperationsConfig{
		Deployment:     fx.dep,
		DomainID:       "A",
		DB:             dbA,
		Management:     mgmtA,
		Certifications: fx.certs,
		Now:            clock,
		Actors:         map[string]GrantActor{"U": fx.actors["U"], "PA": fx.actors["PA"], "A1": fx.actors["A1"]},
	})
	require.NoError(t, err)

	// ResolveRecipient resolves active identity keyVersion and credentialId.
	resolved, err := gA.ResolveRecipient(ctx, fx.recs["B1"])
	require.NoError(t, err)
	require.Equal(t, fx.recs["B1"].DID, resolved.DID)
	require.Equal(t, uint64(1), resolved.KeyVersion)

	// RP root issuance: PA rejected, C accepted as PENDING.
	req := RootGrantRequest{
		GrantID:        fx.run.GrantID("G0"),
		TaskID:         fx.task.ID,
		Recipient:      fx.recs["U"],
		TaskSpec:       fx.spec,
		MaxAmountMinor: 100000,
		Depth:          2,
	}
	const key = "actual-g0"
	_, _, err = gA.IssueRoot(ctx, "PA", key, req)
	require.True(t, protocol.HasCode(err, preg.ErrCodeRootAuthorityInvalid), "%v", err)

	op, delivery, err := gC.IssueRoot(ctx, "C", key, req)
	require.NoError(t, err)
	require.Equal(t, "PENDING", op.Status)
	require.Nil(t, delivery)
	_, err = gA.Load(ctx, fx.recs["U"], req.GrantID)
	require.True(t, protocol.HasCode(err, preg.ErrCodeMaterialNotSynced), "%v", err)

	// Record confirmed commit on C, verify IssueRoot waits until applied block exists, then succeeds.
	var storedJWS string
	require.NoError(t, dbC.QueryRow(ctx, "SELECT grant_jws FROM workbench_grant_issue WHERE grant_id=$1", req.GrantID).Scan(&storedJWS))
	parsed, err := protocol.ParseAndVerifyGrant(storedJWS, &fx.actors["C"].Signer.PrivateKey.PublicKey, fx.actors["C"].Signer.KeyID)
	require.NoError(t, err)
	txID := preg.Digest([]byte("original valid root transaction"))
	point := ledger.Point{Number: 3, Hash: preg.Digest([]byte("original root block"))}
	commit := &ledger.Outcome{Point: point, Code: "VALID", ObservedPeer: "peer0.c.local", Index: 0}
	require.NoError(t, mgmtC.RecordOutcome(ctx, op.OperationID, "COMMIT", "CONFIRMED", txID, commit, nil, false))

	_, delivery, err = gC.IssueRoot(ctx, "C", key, req)
	require.True(t, protocol.HasCode(err, preg.ErrCodeMaterialNotSynced), "%v", err)
	require.Nil(t, delivery)

	g0Anchor := LedgerGrant(parsed)
	g0Anchor.Version = preg.Version{Status: preg.Active, Revision: 1}
	applyTestBlock(t, ctx, dbC, fx.dep.DeploymentID, point.Number, point.Hash, fx.dep.InitBlock.Hash, txID, map[string]any{preg.Key("grant", g0Anchor.ID): g0Anchor})
	applyTestBlock(t, ctx, dbB, fx.dep.DeploymentID, point.Number, point.Hash, fx.dep.InitBlock.Hash, txID, map[string]any{preg.Key("grant", g0Anchor.ID): g0Anchor})

	actual, delivery, err := gC.IssueRoot(ctx, "C", key, req)
	require.NoError(t, err)
	require.NotNil(t, delivery)
	require.Equal(t, op.OperationID, actual.OperationID)

	// AnchoredAmount works on issuer C and rejects mismatched digest.
	amt, err := gC.AnchoredAmount(ctx, g0Anchor)
	require.NoError(t, err)
	require.Equal(t, int64(100000), amt)
	badAnchor := g0Anchor
	badAnchor.Digest = preg.Digest([]byte("tampered"))
	_, err = gC.AnchoredAmount(ctx, badAnchor)
	require.True(t, protocol.HasCode(err, preg.ErrCodeBindingMismatch), "%v", err)

	// Domain A cannot receive before applying block 3; wrong recipient rejected; U succeeds.
	_, _, err = gA.Receive(ctx, fx.recs["U"], *delivery)
	require.True(t, protocol.HasCode(err, preg.ErrCodeMaterialNotSynced), "%v", err)
	applyTestBlock(t, ctx, dbA, fx.dep.DeploymentID, point.Number, point.Hash, fx.dep.InitBlock.Hash, txID, map[string]any{preg.Key("grant", g0Anchor.ID): g0Anchor})
	_, _, err = gA.Receive(ctx, fx.recs["A1"], *delivery)
	require.True(t, protocol.HasCode(err, preg.ErrCodeBindingMismatch), "%v", err)

	// Domain A AnchoredAmount returns 0 before receipt, then 100000 after receipt.
	amtBefore, err := gA.AnchoredAmount(ctx, g0Anchor)
	require.NoError(t, err)
	require.Zero(t, amtBefore)

	bundle, receipt, err := gA.Receive(ctx, fx.recs["U"], *delivery)
	require.NoError(t, err)
	require.Equal(t, delivery.Digest, receipt)
	require.NoError(t, gC.MarkReceived(ctx, *delivery, receipt))

	amtAfter, err := gA.AnchoredAmount(ctx, g0Anchor)
	require.NoError(t, err)
	require.Equal(t, int64(100000), amtAfter)

	replay, err := gC.Published(ctx, fx.recs["U"], req.GrantID)
	require.NoError(t, err)
	require.True(t, replay.Operation.Delivered)
	_, secondReceipt, err := gA.Receive(ctx, fx.recs["U"], *replay)
	require.NoError(t, err)
	require.Equal(t, receipt, secondReceipt)

	// Sign and publish G1 (U -> A1), then G2 (A1 -> B1).
	signChild := func(parent wallet.GrantBundle, issuer, recipient, id string, depth int, capMinor int64) wallet.AnchorChildGrantRequest {
		t.Helper()
		var signed wallet.AnchorChildGrantRequest
		w, err := wallet.NewWalletContext(wallet.WalletConfig{
			DeploymentID: fx.dep.DeploymentID,
			Now:          clock,
			AnchorChildFunc: func(_ context.Context, req wallet.AnchorChildGrantRequest) (*wallet.AnchorChildGrantResult, error) {
				signed = req
				return &wallet.AnchorChildGrantResult{}, nil
			},
		})
		require.NoError(t, err)
		require.NoError(t, w.RegisterActor(fx.actors[issuer].Signer))
		require.NoError(t, w.RegisterActor(fx.actors[recipient].Signer))
		require.NoError(t, w.AddGrantBundle(parent))
		_, err = w.DelegateGrant(ctx, wallet.DelegateGrantInput{
			IssuerActor:    issuer,
			SubjectActor:   recipient,
			ParentGrantID:  parent.Claims.ID,
			GrantID:        id,
			MaxAmountMinor: capMinor,
			RemainingDepth: depth,
		})
		require.NoError(t, err)
		return signed
	}

	g1ID := fx.run.GrantID("G1")
	signedG1 := signChild(bundle, "U", "A1", g1ID, 1, 95000)
	g1Op, g1Del, err := gA.PublishChild(ctx, signedG1)
	require.NoError(t, err)
	require.Equal(t, "PENDING", g1Op.Status)
	require.Nil(t, g1Del)

	g1Parsed, err := protocol.ParseAndVerifyGrant(signedG1.RawGrantJWS, &fx.actors["U"].Signer.PrivateKey.PublicKey, fx.actors["U"].Signer.KeyID)
	require.NoError(t, err)
	g1Anchor := LedgerGrant(g1Parsed)
	g1Anchor.Version = preg.Version{Status: preg.Active, Revision: 1}
	g1Tx := preg.Digest([]byte("g1-tx"))
	g1Point := ledger.Point{Number: 4, Hash: preg.Digest([]byte("g1-blk"))}
	require.NoError(t, mgmtA.RecordOutcome(ctx, g1Op.OperationID, "COMMIT", "CONFIRMED", g1Tx,
		&ledger.Outcome{Point: g1Point, Code: "VALID", ObservedPeer: "peer0.a.local", Index: 0}, nil, false))
	applyTestBlock(t, ctx, dbA, fx.dep.DeploymentID, g1Point.Number, g1Point.Hash, point.Hash, g1Tx, map[string]any{preg.Key("grant", g1ID): g1Anchor})
	applyTestBlock(t, ctx, dbB, fx.dep.DeploymentID, g1Point.Number, g1Point.Hash, point.Hash, g1Tx, map[string]any{preg.Key("grant", g1ID): g1Anchor})

	resumedG1, g1Del, err := gA.ResumeChild(ctx, "U", g1ID)
	require.NoError(t, err)
	require.Equal(t, g1Op.OperationID, resumedG1.OperationID)
	require.NotNil(t, g1Del)
	g1Bundle, g1Receipt, err := gA.Receive(ctx, fx.recs["A1"], *g1Del)
	require.NoError(t, err)
	require.NoError(t, gA.MarkReceived(ctx, *g1Del, g1Receipt))

	g2ID := fx.run.GrantID("G2")
	signedG2 := signChild(g1Bundle, "A1", "B1", g2ID, 0, 90000)
	g2Op, _, err := gA.PublishChild(ctx, signedG2)
	require.NoError(t, err)
	g2Parsed, err := protocol.ParseAndVerifyGrant(signedG2.RawGrantJWS, &fx.actors["A1"].Signer.PrivateKey.PublicKey, fx.actors["A1"].Signer.KeyID)
	require.NoError(t, err)
	g2Anchor := LedgerGrant(g2Parsed)
	g2Anchor.Version = preg.Version{Status: preg.Active, Revision: 1}
	g2Tx := preg.Digest([]byte("g2-tx"))
	g2Point := ledger.Point{Number: 5, Hash: preg.Digest([]byte("g2-blk"))}
	require.NoError(t, mgmtA.RecordOutcome(ctx, g2Op.OperationID, "COMMIT", "CONFIRMED", g2Tx,
		&ledger.Outcome{Point: g2Point, Code: "VALID", ObservedPeer: "peer0.a.local", Index: 0}, nil, false))
	applyTestBlock(t, ctx, dbA, fx.dep.DeploymentID, g2Point.Number, g2Point.Hash, g1Point.Hash, g2Tx, map[string]any{preg.Key("grant", g2ID): g2Anchor})
	applyTestBlock(t, ctx, dbB, fx.dep.DeploymentID, g2Point.Number, g2Point.Hash, g1Point.Hash, g2Tx, map[string]any{preg.Key("grant", g2ID): g2Anchor})

	_, g2Delivery, err := gA.ResumeChild(ctx, "A1", g2ID)
	require.NoError(t, err)
	require.NotNil(t, g2Delivery)

	// Domain B DispatchService accepts G2 delivery, replays idempotently, and rejects mismatched bindings.
	mgmtB := domreg.NewService(dbB, fx.dep.DeploymentID, fx.dep.Bootstrap.Root.Management, nil)
	gB, err := NewGrantOperations(GrantOperationsConfig{
		Deployment:     fx.dep,
		DomainID:       "B",
		DB:             dbB,
		Management:     mgmtB,
		Certifications: fx.certs,
		Now:            clock,
		Actors:         map[string]GrantActor{"B1": fx.actors["B1"]},
	})
	require.NoError(t, err)
	walletB, err := wallet.NewWalletContext(wallet.WalletConfig{
		DeploymentID: fx.dep.DeploymentID,
		DB:           dbB,
		Now:          clock,
		Audience:     DefaultAudience,
		SupplierID:   DefaultSupplierID,
		SupplierDID:  fx.dep.Bootstrap.ResourceOwner,
		Currency:     DefaultCurrency,
	})
	require.NoError(t, err)
	require.NoError(t, walletB.RegisterActor(fx.actors["B1"].Signer))

	dispatchSvc, err := NewDispatchService(DispatchConfig{
		DB:          dbB,
		Deployment:  fx.dep,
		DomainID:    "B",
		DelegateDID: fx.actors["A1"].Signer.DID,
		ActorB1:     fx.recs["B1"],
		Grants:      gB,
		Wallet:      walletB,
		Now:         clock,
	})
	require.NoError(t, err)

	dispatchReq := DispatchRequest{
		Run:      DispatchRun{RunID: fx.run.RunID, TaskID: fx.run.TaskID, Task: fx.run.Task},
		Delivery: *g2Delivery,
	}
	view, replayed, err := dispatchSvc.AcceptDispatch(ctx, dispatchReq)
	require.NoError(t, err)
	require.False(t, replayed)
	require.Equal(t, RunPending, view.Status)
	require.Equal(t, g2Delivery.Digest, view.Receipt)

	// Replay returns replayed=true with identical receipt.
	replayView, replayed, err := dispatchSvc.AcceptDispatch(ctx, dispatchReq)
	require.NoError(t, err)
	require.True(t, replayed)
	require.Equal(t, g2Delivery.Digest, replayView.Receipt)

	// Mismatched task binding on same runId fails with BINDING_MISMATCH.
	badReq := dispatchReq
	badReq.Run.Task.Quantity = 9
	_, _, err = dispatchSvc.AcceptDispatch(ctx, badReq)
	require.Equal(t, preg.ErrCodeBindingMismatch, protocol.CodeOf(err))

	// Suspending G1 causes Load to fail with ANCESTOR_INACTIVE while LoadRetained still succeeds.
	g1Anchor.Version = preg.Version{Status: preg.Suspended, Revision: 2}
	pausedPoint := ledger.Point{Number: 6, Hash: preg.Digest([]byte("paused-g1-blk"))}
	applyTestBlock(t, ctx, dbA, fx.dep.DeploymentID, pausedPoint.Number, pausedPoint.Hash, g2Point.Hash, preg.Digest([]byte("pause-tx")), map[string]any{preg.Key("grant", g1ID): g1Anchor})
	applyTestBlock(t, ctx, dbB, fx.dep.DeploymentID, pausedPoint.Number, pausedPoint.Hash, g2Point.Hash, preg.Digest([]byte("pause-tx")), map[string]any{preg.Key("grant", g1ID): g1Anchor})

	_, err = gA.Load(ctx, fx.recs["A1"], g1ID)
	require.True(t, protocol.HasCode(err, preg.ErrCodeAncestorInactive), "%v", err)
	retained, err := gA.LoadRetained(ctx, fx.recs["A1"], g1ID)
	require.NoError(t, err)
	require.Equal(t, g1Bundle.RawGrantJWS, retained.RawGrantJWS)

	// ProcessPending on B observes suspended ancestor and transitions dispatch to FAILED / ANCESTOR_INACTIVE.
	require.NoError(t, dispatchSvc.ProcessPending(ctx))
	statusView, err := dispatchSvc.GetDispatchStatus(ctx, fx.run.RunID)
	require.NoError(t, err)
	require.Equal(t, RunFailed, statusView.Status)
	require.Equal(t, preg.ErrCodeAncestorInactive, statusView.Code)
}

func TestDispatchPendingRunsRotateAcrossRestart(t *testing.T) {
	ctx := t.Context()
	db := testutil.OpenMigratedPool(t)
	const deployment = "dispatch-rotate-test"
	const batch = 50
	scheduled := time.Now().Truncate(time.Second).Add(-time.Minute)
	for i := 0; i <= batch; i++ {
		run := Run{RunID: fmt.Sprintf("%064x", i), TaskID: fmt.Sprintf("task-%d", i)}
		_, err := db.Exec(ctx, `INSERT INTO workbench_dispatch(deployment_id,run_id,task_id,status,body,result,next_attempt_at)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, deployment, run.RunID, run.TaskID, RunPending, run,
			DispatchStatusView{Status: RunPending}, scheduled)
		require.NoError(t, err)
	}
	newWorker := func() *DispatchService {
		svc, err := NewDispatchService(DispatchConfig{
			DB:         db,
			Deployment: &ledger.Deployment{DeploymentID: deployment},
			DomainID:   "B",
		})
		require.NoError(t, err)
		return svc
	}
	require.NoError(t, newWorker().ProcessPending(ctx))
	var attempted int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM workbench_dispatch WHERE next_attempt_at>$1`, scheduled).Scan(&attempted))
	require.Equal(t, batch, attempted)

	id := fmt.Sprintf("%064x", batch)
	pending, err := newWorker().GetDispatchStatus(ctx, id)
	require.NoError(t, err)
	require.Empty(t, pending.Code)

	restarted := newWorker()
	require.NoError(t, restarted.ProcessPending(ctx))
	pending, err = restarted.GetDispatchStatus(ctx, id)
	require.NoError(t, err)
	require.Equal(t, RunPending, pending.Status)
	require.Equal(t, preg.ErrCodeMaterialNotSynced, pending.Code, "the later dispatch received its first attempt")
}
