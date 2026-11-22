//go:build db

package registrysvc

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/internal/testutil"
	"grad/protocol"
	"grad/protocol/registry"
)

type deliveryFixture struct {
	depID     string
	now       int64
	snap      *protocol.SnapshotView
	rootKey   *ecdsa.PrivateKey
	iaKey     *ecdsa.PrivateKey
	icKey     *ecdsa.PrivateKey
	cKey      *ecdsa.PrivateKey
	paKey     *ecdsa.PrivateKey
	certAJWS  string
	certCJWS  string
	rpPkg     GrantDeliveryPackage
	bmPkg     GrantDeliveryPackage
	interval  registry.Interval
	recipient string
}

func newDeliveryFixture(t *testing.T) *deliveryFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second).Unix()
	interval := registry.Interval{NBF: now - 3600, EXP: now + 3600}
	validFrom := time.Unix(interval.NBF, 0).UTC().Format(time.RFC3339)
	validUntil := time.Unix(interval.EXP, 0).UTC().Format(time.RFC3339)

	dep := protocol.DeploymentBinding{
		ChannelID:     registry.Channel,
		GenesisHash:   registry.Digest([]byte("delivery-genesis")),
		InstanceID:    registry.Digest([]byte("delivery-instance")),
		Purpose:       protocol.DeploymentPurpose,
		RegistryName:  registry.Registry,
		SchemaVersion: protocol.SchemaVersion,
	}
	depID, err := protocol.ComputeDeploymentID(dep)
	require.NoError(t, err)

	genKey := func(did string) (*ecdsa.PrivateKey, string, string, string) {
		priv, err := protocol.GenerateP256Key()
		require.NoError(t, err)
		pubHex, err := protocol.FormatAppPublicKey(&priv.PublicKey)
		require.NoError(t, err)
		kid := did + "#key-1"
		doc, err := protocol.NewDIDDocument(did, kid, &priv.PublicKey)
		require.NoError(t, err)
		docDigest, err := doc.Digest()
		require.NoError(t, err)
		return priv, pubHex, kid, docDigest
	}

	rootDID := "did:web:t.local"
	rootKey, rootPubHex, rootKID, rootDocDig := genKey(rootDID)

	domADID := "did:web:a.local"
	_, domAPubHex, domAKID, domADocDig := genKey(domADID)
	domCDID := "did:web:c.local"
	_, domCPubHex, domCKID, domCDocDig := genKey(domCDID)

	iaDID := "did:web:a.local:ia"
	iaKey, iaPubHex, iaKID, iaDocDig := genKey(iaDID)
	icDID := "did:web:c.local:ic"
	icKey, icPubHex, icKID, icDocDig := genKey(icDID)

	uDID := "did:web:a.local:u"
	uKey, uPubHex, uKID, uDocDig := genKey(uDID)
	paDID := "did:web:a.local:pa"
	paKey, paPubHex, paKID, paDocDig := genKey(paDID)
	cDID := "did:web:c.local:supplier"
	cKey, cPubHex, cKID, cDocDig := genKey(cDID)

	scopeA := []registry.IssuerScope{{
		ID:              iaDID,
		AppKeyVersion:   1,
		CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity},
		ClaimNames:      []string{"domain", "role"},
	}}
	scopeC := []registry.IssuerScope{{
		ID:              icDID,
		AppKeyVersion:   1,
		CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity},
		ClaimNames:      []string{"domain", "role"},
	}}

	certAID := "urn:grad:cert:A:v1"
	certAJWS, certADig, err := protocol.SignDomainAuthorityCredential(rootKey, rootKID, &protocol.DomainAuthorityCredential{
		Type:             []string{protocol.CredentialTypeVC, protocol.CredentialTypeDomainAuthority},
		ID:               certAID,
		DeploymentID:     depID,
		Issuer:           rootDID,
		Iss:              rootDID,
		Sub:              domADID,
		IssuerKeyVersion: 1,
		ValidFrom:        validFrom,
		ValidUntil:       validUntil,
		NBF:              interval.NBF,
		EXP:              interval.EXP,
		CredentialStatus: protocol.CredentialStatus{ID: certAID, Type: protocol.StatusTypeDomainCertification},
		CredentialSubject: protocol.DomainAuthoritySubject{
			ID:              domADID,
			DomainID:        "A",
			IdentityIssuers: scopeA,
		},
	})
	require.NoError(t, err)

	certCID := "urn:grad:cert:C:v1"
	certCJWS, certCDig, err := protocol.SignDomainAuthorityCredential(rootKey, rootKID, &protocol.DomainAuthorityCredential{
		Type:             []string{protocol.CredentialTypeVC, protocol.CredentialTypeDomainAuthority},
		ID:               certCID,
		DeploymentID:     depID,
		Issuer:           rootDID,
		Iss:              rootDID,
		Sub:              domCDID,
		IssuerKeyVersion: 1,
		ValidFrom:        validFrom,
		ValidUntil:       validUntil,
		NBF:              interval.NBF,
		EXP:              interval.EXP,
		CredentialStatus: protocol.CredentialStatus{ID: certCID, Type: protocol.StatusTypeDomainCertification},
		CredentialSubject: protocol.DomainAuthoritySubject{
			ID:              domCDID,
			DomainID:        "C",
			IdentityIssuers: scopeC,
		},
	})
	require.NoError(t, err)

	issueSD := func(issKey *ecdsa.PrivateKey, issDID, issKID, credID, subDID, domain, role string, holderPub *ecdsa.PublicKey) (*protocol.SignedSDJWTCredential, registry.Credential) {
		jwk, err := protocol.JWKFromPublicKey(holderPub)
		require.NoError(t, err)
		sd, err := protocol.IssueEnterpriseIdentityCredential(issKey, issKID, protocol.EnterpriseIdentityCredential{
			Type:              []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
			ID:                credID,
			DeploymentID:      depID,
			Issuer:            issDID,
			Iss:               issDID,
			Sub:               subDID,
			IssuerKeyVersion:  1,
			AppKeyVersion:     1,
			ValidFrom:         validFrom,
			ValidUntil:        validUntil,
			NBF:               interval.NBF,
			EXP:               interval.EXP,
			CredentialStatus:  protocol.CredentialStatus{ID: credID, Type: protocol.StatusTypeCredential},
			Cnf:               protocol.ConfirmationKey{JWK: jwk},
			CredentialSubject: protocol.SDJWTCredentialSubject{ID: subDID},
		}, domain, role, nil)
		require.NoError(t, err)
		rec := registry.Credential{
			Bound:             registry.Bound{DeploymentID: depID},
			ID:                credID,
			Issuer:            issDID,
			Subject:           subDID,
			IssuerKeyVersion:  1,
			SubjectKeyVersion: 1,
			Type:              protocol.CredentialTypeEnterpriseIdentity,
			ClaimNames:        []string{"domain", "role"},
			Digest:            sd.AnchorDigest,
			Interval:          interval,
			Version:           registry.Version{Status: registry.Active, Revision: 1},
		}
		return sd, rec
	}

	_, credU := issueSD(iaKey, iaDID, iaKID, "urn:grad:cred:U:v1", uDID, "A", "procurement-owner", &uKey.PublicKey)
	sdPA, credPA := issueSD(iaKey, iaDID, iaKID, "urn:grad:cred:PA:v1", paDID, "A", "procurement-authority", &paKey.PublicKey)
	sdC, credC := issueSD(icKey, icDID, icKID, "urn:grad:cred:C:v1", cDID, "C", "supplier-service", &cKey.PublicKey)

	taskSpec := protocol.TaskSpec{
		SupplierID:  cDID,
		ProductID:   "urn:grad:product:P1",
		MaxQuantity: 10,
		Currency:    "CNY",
		Resources:   []string{protocol.ResourceOrders, protocol.ResourceQuotes},
		Actions:     []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
		Description: "delivery test task",
	}
	taskDig, err := taskSpec.Digest()
	require.NoError(t, err)

	taskRP := registry.Task{
		Bound:             registry.Bound{DeploymentID: depID},
		ID:                "urn:grad:task:rp-1",
		Creator:           uDID,
		CreatorCredential: credU.ID,
		CreatorKeyVersion: 1,
		Domain:            "A",
		Mode:              registry.RP,
		Resource:          protocol.ResourceOrders,
		Digest:            taskDig,
		Interval:          interval,
		Version:           registry.Version{Status: registry.Active, Revision: 1},
	}
	taskBM := taskRP
	taskBM.ID = "urn:grad:task:bm-1"
	taskBM.Mode = registry.BM

	rpGrantID := "urn:grad:grant:rp-root"
	rpGrantJWS, rpGrantDig, err := protocol.SignGrant(cKey, cKID, &protocol.GrantClaims{
		ID:                  rpGrantID,
		SchemaVersion:       protocol.SchemaVersion,
		DeploymentID:        depID,
		RootID:              rpGrantID,
		TaskID:              taskRP.ID,
		AuthorizationMode:   registry.RP,
		PrincipalDomain:     "A",
		ResourceID:          protocol.ResourceOrders,
		Issuer:              cDID,
		Grantee:             uDID,
		IssuerKeyVersion:    1,
		GranteeKeyVersion:   1,
		IssuerCredentialID:  credC.ID,
		GranteeCredentialID: credU.ID,
		Resources:           []string{protocol.ResourceOrders, protocol.ResourceQuotes},
		Actions:             []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
		Suppliers:           []string{cDID},
		Aud:                 cDID,
		Currency:            "CNY",
		MaxAmountMinor:      100000,
		NBF:                 interval.NBF,
		EXP:                 interval.EXP,
		RemainingDepth:      2,
	})
	require.NoError(t, err)

	bmGrantID := "urn:grad:grant:bm-root"
	bmGrantJWS, bmGrantDig, err := protocol.SignGrant(paKey, paKID, &protocol.GrantClaims{
		ID:                  bmGrantID,
		SchemaVersion:       protocol.SchemaVersion,
		DeploymentID:        depID,
		RootID:              bmGrantID,
		TaskID:              taskBM.ID,
		AuthorizationMode:   registry.BM,
		PrincipalDomain:     "A",
		ResourceID:          protocol.ResourceOrders,
		Issuer:              paDID,
		Grantee:             uDID,
		IssuerKeyVersion:    1,
		GranteeKeyVersion:   1,
		IssuerCredentialID:  credPA.ID,
		GranteeCredentialID: credU.ID,
		Resources:           []string{protocol.ResourceOrders, protocol.ResourceQuotes},
		Actions:             []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
		Suppliers:           []string{cDID},
		Aud:                 cDID,
		Currency:            "CNY",
		MaxAmountMinor:      100000,
		NBF:                 interval.NBF,
		EXP:                 interval.EXP,
		RemainingDepth:      2,
	})
	require.NoError(t, err)

	snap := &protocol.SnapshotView{
		Height:       5,
		Now:          time.Unix(now, 0).UTC(),
		DeploymentID: depID,
		Root: registry.RootRecord{
			DID:            rootDID,
			DocumentDigest: rootDocDig,
			KeyID:          rootKID,
			KeyVersion:     1,
			PublicKey:      rootPubHex,
		},
		Domains: map[string]registry.Domain{
			"A": {
				Bound:               registry.Bound{DeploymentID: depID},
				ID:                  "A",
				DID:                 domADID,
				Issuers:             []string{iaDID},
				PurchasingAuthority: paDID,
				Certification:       certAID,
				Version:             registry.Version{Status: registry.Active, Revision: 1},
			},
			"C": {
				Bound:         registry.Bound{DeploymentID: depID},
				ID:            "C",
				DID:           domCDID,
				Issuers:       []string{icDID},
				Certification: certCID,
				Version:       registry.Version{Status: registry.Active, Revision: 1},
			},
		},
		Certifications: map[string]registry.Certification{
			certAID: {
				Bound:          registry.Bound{DeploymentID: depID},
				ID:             certAID,
				Domain:         "A",
				RootKeyVersion: 1,
				Digest:         certADig,
				Scopes:         scopeA,
				Interval:       interval,
				Version:        registry.Version{Status: registry.Active, Revision: 1},
			},
			certCID: {
				Bound:          registry.Bound{DeploymentID: depID},
				ID:             certCID,
				Domain:         "C",
				RootKeyVersion: 1,
				Digest:         certCDig,
				Scopes:         scopeC,
				Interval:       interval,
				Version:        registry.Version{Status: registry.Active, Revision: 1},
			},
		},
		Identities: map[string]registry.Identity{
			domADID: {Bound: registry.Bound{DeploymentID: depID}, ID: domADID, Domain: "A", Kind: "DOMAIN", DocumentDigest: domADocDig, KeyID: domAKID, KeyVersion: 1, PublicKey: domAPubHex, Version: registry.Version{Status: registry.Active, Revision: 1}},
			domCDID: {Bound: registry.Bound{DeploymentID: depID}, ID: domCDID, Domain: "C", Kind: "DOMAIN", DocumentDigest: domCDocDig, KeyID: domCKID, KeyVersion: 1, PublicKey: domCPubHex, Version: registry.Version{Status: registry.Active, Revision: 1}},
			iaDID:   {Bound: registry.Bound{DeploymentID: depID}, ID: iaDID, Domain: "A", Kind: "ISSUER", DocumentDigest: iaDocDig, KeyID: iaKID, KeyVersion: 1, PublicKey: iaPubHex, Version: registry.Version{Status: registry.Active, Revision: 1}},
			icDID:   {Bound: registry.Bound{DeploymentID: depID}, ID: icDID, Domain: "C", Kind: "ISSUER", DocumentDigest: icDocDig, KeyID: icKID, KeyVersion: 1, PublicKey: icPubHex, Version: registry.Version{Status: registry.Active, Revision: 1}},
			uDID:    {Bound: registry.Bound{DeploymentID: depID}, ID: uDID, Domain: "A", Kind: "USER", DocumentDigest: uDocDig, KeyID: uKID, KeyVersion: 1, PublicKey: uPubHex, Version: registry.Version{Status: registry.Active, Revision: 1}},
			paDID:   {Bound: registry.Bound{DeploymentID: depID}, ID: paDID, Domain: "A", Kind: "SERVICE", DocumentDigest: paDocDig, KeyID: paKID, KeyVersion: 1, PublicKey: paPubHex, Version: registry.Version{Status: registry.Active, Revision: 1}},
			cDID:    {Bound: registry.Bound{DeploymentID: depID}, ID: cDID, Domain: "C", Kind: "SERVICE", DocumentDigest: cDocDig, KeyID: cKID, KeyVersion: 1, PublicKey: cPubHex, Version: registry.Version{Status: registry.Active, Revision: 1}},
		},
		Credentials: map[string]registry.Credential{
			credU.ID:  credU,
			credPA.ID: credPA,
			credC.ID:  credC,
		},
		Tasks: map[string]registry.Task{
			taskRP.ID: taskRP,
			taskBM.ID: taskBM,
		},
		Grants: map[string]registry.Grant{
			rpGrantID: {
				Bound:             registry.Bound{DeploymentID: depID},
				ID:                rpGrantID,
				Schema:            registry.Schema,
				Root:              rpGrantID,
				Task:              taskRP.ID,
				Mode:              registry.RP,
				Domain:            "A",
				Resource:          protocol.ResourceOrders,
				Issuer:            cDID,
				Grantee:           uDID,
				IssuerKeyVersion:  1,
				GranteeKeyVersion: 1,
				IssuerCredential:  credC.ID,
				GranteeCredential: credU.ID,
				Depth:             2,
				Digest:            rpGrantDig,
				Interval:          interval,
				Version:           registry.Version{Status: registry.Active, Revision: 1},
			},
			bmGrantID: {
				Bound:             registry.Bound{DeploymentID: depID},
				ID:                bmGrantID,
				Schema:            registry.Schema,
				Root:              bmGrantID,
				Task:              taskBM.ID,
				Mode:              registry.BM,
				Domain:            "A",
				Resource:          protocol.ResourceOrders,
				Issuer:            paDID,
				Grantee:           uDID,
				IssuerKeyVersion:  1,
				GranteeKeyVersion: 1,
				IssuerCredential:  credPA.ID,
				GranteeCredential: credU.ID,
				Depth:             2,
				Digest:            bmGrantDig,
				Interval:          interval,
				Version:           registry.Version{Status: registry.Active, Revision: 1},
			},
		},
	}

	return &deliveryFixture{
		depID:     depID,
		now:       now,
		snap:      snap,
		rootKey:   rootKey,
		iaKey:     iaKey,
		icKey:     icKey,
		cKey:      cKey,
		paKey:     paKey,
		certAJWS:  certAJWS,
		certCJWS:  certCJWS,
		interval:  interval,
		recipient: uDID,
		rpPkg: GrantDeliveryPackage{
			DeploymentID:           depID,
			Recipient:              uDID,
			GrantID:                rpGrantID,
			GrantJWS:               rpGrantJWS,
			TaskSpec:               taskSpec,
			ServicePresentation:    sdC.PresentationPrefix,
			DomainCertificationJWS: certCJWS,
		},
		bmPkg: GrantDeliveryPackage{
			DeploymentID:           depID,
			Recipient:              uDID,
			GrantID:                bmGrantID,
			GrantJWS:               bmGrantJWS,
			TaskSpec:               taskSpec,
			ServicePresentation:    sdPA.PresentationPrefix,
			DomainCertificationJWS: certAJWS,
		},
	}
}

func TestCertificationOutboxReceiptAndHasSyncedCertification(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()
	f := newDeliveryFixture(t)
	ds := NewDeliveryService(pool, f.depID)
	otherDepDS := NewDeliveryService(pool, registry.Digest([]byte("other-deployment")))

	// Unsynced before publish.
	synced, err := ds.HasSyncedCertification(ctx, "C")
	require.NoError(t, err)
	assert.False(t, synced)

	_, err = ds.SyncCertificationReceipt(ctx, f.snap, f.recipient, "C", &f.rootKey.PublicKey, f.now)
	assert.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced))

	// Invalid original tx or mismatched domain cert rejected.
	err = ds.PublishDomainCertification(ctx, f.snap, f.recipient, "C", f.certCJWS, &f.rootKey.PublicKey, "tx-bad", 3, false, f.now)
	assert.True(t, protocol.HasCode(err, registry.ErrCodeMaterialInvalid))

	err = ds.PublishDomainCertification(ctx, f.snap, f.recipient, "C", f.certAJWS, &f.rootKey.PublicKey, "tx-mismatch", 3, true, f.now)
	assert.True(t, protocol.HasCode(err, registry.ErrCodeDomainCertificationInvalid))

	// Publish & sync C certification.
	require.NoError(t, ds.PublishDomainCertification(ctx, f.snap, f.recipient, "C", f.certCJWS, &f.rootKey.PublicKey, "tx-cert-C", 3, true, f.now))

	gotCert, err := ds.SyncCertificationReceipt(ctx, f.snap, f.recipient, "C", &f.rootKey.PublicKey, f.now)
	require.NoError(t, err)
	assert.Equal(t, f.certCJWS, gotCert)

	// HasSyncedCertification returns true for domain C under matching deployment only.
	synced, err = ds.HasSyncedCertification(ctx, "C")
	require.NoError(t, err)
	assert.True(t, synced)

	synced, err = ds.HasSyncedCertification(ctx, "B")
	require.NoError(t, err)
	assert.False(t, synced)

	synced, err = otherDepDS.HasSyncedCertification(ctx, "C")
	require.NoError(t, err)
	assert.False(t, synced)

	// Exact digest lookup via SyncedCertificationJWS.
	certC := f.snap.Certifications["urn:grad:cert:C:v1"]
	jws, err := ds.SyncedCertificationJWS(ctx, f.depID, "C", certC.ID, certC.Digest)
	require.NoError(t, err)
	assert.Equal(t, f.certCJWS, jws)

	_, err = ds.SyncedCertificationJWS(ctx, f.depID, "C", certC.ID, registry.Digest([]byte("wrong-digest")))
	assert.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced))
}

func TestGrantOutboxAndWalletReceiptDedupConflictAndSyncGuard(t *testing.T) {
	pool := testutil.OpenMigratedPool(t)
	ctx := t.Context()
	f := newDeliveryFixture(t)
	ds := NewDeliveryService(pool, f.depID)

	// Guard 1: missing synced C domain certification -> MATERIAL_NOT_SYNCED, zero wallet_receipts written.
	_, err := ds.PublishGrantOutbox(ctx, f.snap, f.rpPkg, &f.rootKey.PublicKey, &f.icKey.PublicKey, &f.cKey.PublicKey, "tx-g0", 6, true, f.now)
	assert.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced))

	_, _, err = ds.DeliverGrantReceipt(ctx, f.snap, f.depID, f.recipient, f.rpPkg.GrantID, &f.rpPkg, &f.rootKey.PublicKey, &f.icKey.PublicKey, &f.cKey.PublicKey, f.now)
	assert.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced))

	var receiptCnt int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM wallet_receipts WHERE deployment_id=$1`, f.depID).Scan(&receiptCnt))
	assert.Equal(t, 0, receiptCnt)

	// Guard 2: non-VALID original grant tx -> MATERIAL_INVALID.
	_, err = ds.PublishGrantOutbox(ctx, f.snap, f.rpPkg, &f.rootKey.PublicKey, &f.icKey.PublicKey, &f.cKey.PublicKey, "tx-g0", 6, false, f.now)
	assert.True(t, protocol.HasCode(err, registry.ErrCodeMaterialInvalid))

	// Guard 3: DeliverGrantReceipt before grant_outbox exists -> MATERIAL_NOT_SYNCED.
	_, _, err = ds.DeliverGrantReceipt(ctx, f.snap, f.depID, f.recipient, f.rpPkg.GrantID, nil, &f.rootKey.PublicKey, &f.icKey.PublicKey, &f.cKey.PublicKey, f.now)
	assert.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced))

	// Publish & sync domain A and C certifications.
	require.NoError(t, ds.PublishDomainCertification(ctx, f.snap, f.recipient, "A", f.certAJWS, &f.rootKey.PublicKey, "tx-cert-A", 2, true, f.now))
	_, err = ds.SyncCertificationReceipt(ctx, f.snap, f.recipient, "A", &f.rootKey.PublicKey, f.now)
	require.NoError(t, err)
	require.NoError(t, ds.PublishDomainCertification(ctx, f.snap, f.recipient, "C", f.certCJWS, &f.rootKey.PublicKey, "tx-cert-C", 3, true, f.now))
	_, err = ds.SyncCertificationReceipt(ctx, f.snap, f.recipient, "C", &f.rootKey.PublicKey, f.now)
	require.NoError(t, err)

	// Positive RP root grant delivery + idempotent deduplication.
	dig1, err := ds.PublishGrantOutbox(ctx, f.snap, f.rpPkg, &f.rootKey.PublicKey, &f.icKey.PublicKey, &f.cKey.PublicKey, "tx-g0", 6, true, f.now)
	require.NoError(t, err)
	dig2, err := ds.PublishGrantOutbox(ctx, f.snap, f.rpPkg, &f.rootKey.PublicKey, &f.icKey.PublicKey, &f.cKey.PublicKey, "tx-g0", 6, true, f.now)
	require.NoError(t, err)
	assert.Equal(t, dig1, dig2)

	delPkg, delDig1, err := ds.DeliverGrantReceipt(ctx, f.snap, f.depID, f.recipient, f.rpPkg.GrantID, nil, &f.rootKey.PublicKey, &f.icKey.PublicKey, &f.cKey.PublicKey, f.now)
	require.NoError(t, err)
	assert.Equal(t, dig1, delDig1)
	assert.Equal(t, f.rpPkg.GrantID, delPkg.GrantID)

	_, delDig2, err := ds.DeliverGrantReceipt(ctx, f.snap, f.depID, f.recipient, f.rpPkg.GrantID, nil, &f.rootKey.PublicKey, &f.icKey.PublicKey, &f.cKey.PublicKey, f.now)
	require.NoError(t, err)
	assert.Equal(t, delDig1, delDig2)

	// Positive BM root grant delivery from PA in domain A.
	bmDig, err := ds.PublishGrantOutbox(ctx, f.snap, f.bmPkg, &f.rootKey.PublicKey, &f.iaKey.PublicKey, &f.paKey.PublicKey, "tx-bm", 7, true, f.now)
	require.NoError(t, err)
	_, bmDelDig, err := ds.DeliverGrantReceipt(ctx, f.snap, f.depID, f.recipient, f.bmPkg.GrantID, nil, &f.rootKey.PublicKey, &f.iaKey.PublicKey, &f.paKey.PublicKey, f.now)
	require.NoError(t, err)
	assert.Equal(t, bmDig, bmDelDig)

	// Conflicting package digest under same (deploymentId, recipient, grantId) -> DELIVERY_CONFLICT.
	holderJWKC, err := protocol.JWKFromPublicKey(&f.cKey.PublicKey)
	require.NoError(t, err)
	altSD, err := protocol.IssueEnterpriseIdentityCredential(
		f.icKey,
		"did:web:c.local:ic#key-1",
		protocol.EnterpriseIdentityCredential{
			Type:              []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
			ID:                "urn:grad:credential:C-alt-v1",
			DeploymentID:      f.depID,
			Issuer:            "did:web:c.local:ic",
			Iss:               "did:web:c.local:ic",
			Sub:               "did:web:c.local:supplier",
			IssuerKeyVersion:  1,
			AppKeyVersion:     1,
			ValidFrom:         time.Unix(f.interval.NBF, 0).UTC().Format(time.RFC3339),
			ValidUntil:        time.Unix(f.interval.EXP, 0).UTC().Format(time.RFC3339),
			NBF:               f.interval.NBF,
			EXP:               f.interval.EXP,
			CredentialStatus:  protocol.CredentialStatus{ID: "urn:grad:credential:C-alt-v1", Type: protocol.StatusTypeCredential},
			Cnf:               protocol.ConfirmationKey{JWK: holderJWKC},
			CredentialSubject: protocol.SDJWTCredentialSubject{ID: "did:web:c.local:supplier"},
		},
		"C",
		"supplier-service",
		nil,
	)
	require.NoError(t, err)
	f.snap.Credentials["urn:grad:credential:C-alt-v1"] = registry.Credential{
		Bound:             registry.Bound{DeploymentID: f.depID},
		ID:                "urn:grad:credential:C-alt-v1",
		Issuer:            "did:web:c.local:ic",
		Subject:           "did:web:c.local:supplier",
		IssuerKeyVersion:  1,
		SubjectKeyVersion: 1,
		Type:              protocol.CredentialTypeEnterpriseIdentity,
		ClaimNames:        []string{"domain", "role"},
		Digest:            altSD.AnchorDigest,
		Interval:          f.interval,
		Version:           registry.Version{Status: registry.Active, Revision: 1},
	}

	conflictPkg := f.rpPkg
	conflictPkg.ServicePresentation = altSD.PresentationPrefix
	_, err = ds.PublishGrantOutbox(ctx, f.snap, conflictPkg, &f.rootKey.PublicKey, &f.icKey.PublicKey, &f.cKey.PublicKey, "tx-g0-conflict", 8, true, f.now)
	assert.True(t, protocol.HasCode(err, registry.ErrCodeDeliveryConflict))

	_, _, err = ds.DeliverGrantReceipt(ctx, f.snap, f.depID, f.recipient, f.rpPkg.GrantID, &conflictPkg, &f.rootKey.PublicKey, &f.icKey.PublicKey, &f.cKey.PublicKey, f.now)
	assert.True(t, protocol.HasCode(err, registry.ErrCodeDeliveryConflict))
}
