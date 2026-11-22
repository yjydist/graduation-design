package protocol

import (
	"context"
	"crypto/ecdsa"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/protocol/registry"
)

func TestAccessEvidencePackageFullVerifyAndSingleFieldTampers(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := GenerateTestCA(now)
	require.NoError(t, err)
	caPool, err := ParseTestCAPublic(ca.CertPEM)
	require.NoError(t, err)
	certs := make(map[string]*HostTLSCert, len(ControlledTestDomains))
	for _, host := range ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		require.NoError(t, err)
		certs[host] = hc
	}

	privT, pubT := mustGenKeyPair(t)
	privIA, pubIA := mustGenKeyPair(t)
	privIB, pubIB := mustGenKeyPair(t)
	privIC, pubIC := mustGenKeyPair(t)
	privU, pubU := mustGenKeyPair(t)
	privB1, pubB1 := mustGenKeyPair(t)
	privC, pubC := mustGenKeyPair(t)

	didT := "did:web:t.local"
	didIA := "did:web:a.local:ia"
	didU := "did:web:a.local:u"
	didIB := "did:web:b.local:ib"
	didB1 := "did:web:b.local:b1"
	didIC := "did:web:c.local:ic"
	didC := "did:web:c.local:supplier"

	docs := map[string][]byte{}
	makeDoc := func(did, keyID string, pub *ecdsa.PublicKey, purposes ...string) string {
		d, err := NewDIDDocument(did, keyID, pub, purposes...)
		require.NoError(t, err)
		raw, err := MarshalJCS(d)
		require.NoError(t, err)
		dig, err := d.Digest()
		require.NoError(t, err)
		docs[did] = raw
		return dig
	}

	digT := makeDoc(didT, didT+"#key-1", &privT.PublicKey, KeyPurposeAssertionMethod)
	digIA := makeDoc(didIA, didIA+"#key-1", &privIA.PublicKey, KeyPurposeAssertionMethod)
	digU := makeDoc(didU, didU+"#key-1", &privU.PublicKey, KeyPurposeAuthentication, KeyPurposeAssertionMethod)
	digIB := makeDoc(didIB, didIB+"#key-1", &privIB.PublicKey, KeyPurposeAssertionMethod)
	digB1 := makeDoc(didB1, didB1+"#key-1", &privB1.PublicKey, KeyPurposeAuthentication, KeyPurposeAssertionMethod)
	digIC := makeDoc(didIC, didIC+"#key-1", &privIC.PublicKey, KeyPurposeAssertionMethod)
	digC := makeDoc(didC, didC+"#key-1", &privC.PublicKey, KeyPurposeAuthentication, KeyPurposeAssertionMethod)

	srv, err := NewDIDWebServer(certs, docs)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	dids, err := NewDIDWebResolver(caPool, srv.Routes())
	require.NoError(t, err)
	_, err = dids.RegisterPreseed(RootPreseed{
		DID:               didT,
		KeyID:             didT + "#key-1",
		KeyVersion:        1,
		PublicKeyHex:      pubT,
		DIDDocumentDigest: digT,
		RawDocument:       docs[didT],
	})
	require.NoError(t, err)

	depID := registry.Digest([]byte("test-deployment-id"))
	taskID := registry.Digest([]byte("test-task-id"))
	resID := registry.Digest([]byte("resource:" + didC))
	g0ID := registry.Digest([]byte("test-grant-g0"))
	g1ID := registry.Digest([]byte("test-grant-g1"))

	nbf := now.Add(-time.Hour).Unix()
	exp := now.Add(24 * time.Hour).Unix()
	vf := time.Unix(nbf, 0).UTC().Format(time.RFC3339)
	vu := time.Unix(exp, 0).UTC().Format(time.RFC3339)

	issueCert := func(domID, domDID, issuerDID string) (string, string, registry.Domain, registry.Certification) {
		certID := "urn:grad:domain-certification:" + domID + "-v1"
		scopes := []IssuerScope{{
			ID:              issuerDID,
			AppKeyVersion:   1,
			CredentialTypes: []string{CredentialTypeEnterpriseIdentity},
			ClaimNames:      []string{"domain", "role"},
		}}
		jws, dig, err := SignDomainAuthorityCredential(privT, didT+"#key-1", &DomainAuthorityCredential{
			Type:             []string{CredentialTypeVC, CredentialTypeDomainAuthority},
			ID:               certID,
			DeploymentID:     depID,
			Issuer:           didT,
			Iss:              didT,
			Sub:              domDID,
			IssuerKeyVersion: 1,
			ValidFrom:        vf,
			ValidUntil:       vu,
			NBF:              nbf,
			EXP:              exp,
			CredentialStatus: CredentialStatus{ID: certID, Type: StatusTypeDomainCertification},
			CredentialSubject: DomainAuthoritySubject{
				ID:              domDID,
				DomainID:        domID,
				IdentityIssuers: scopes,
			},
		})
		require.NoError(t, err)
		domRec := registry.Domain{
			Bound:         registry.Bound{DeploymentID: depID},
			ID:            domID,
			DID:           domDID,
			Issuers:       []string{issuerDID},
			Certification: certID,
			Version:       registry.Version{Status: registry.Active, Revision: 1},
		}
		certRec := registry.Certification{
			Bound:          registry.Bound{DeploymentID: depID},
			ID:             certID,
			Domain:         domID,
			RootKeyVersion: 1,
			Digest:         dig,
			Scopes:         scopes,
			Interval:       registry.Interval{NBF: nbf, EXP: exp},
			Version:        registry.Version{Status: registry.Active, Revision: 1},
		}
		return jws, dig, domRec, certRec
	}

	certAJWS, _, domA, certA := issueCert("A", "did:web:a.local", didIA)
	certBJWS, _, domB, certB := issueCert("B", "did:web:b.local", didIB)
	certCJWS, _, domC, certC := issueCert("C", "did:web:c.local", didIC)

	issueCred := func(credID, issuerDID, subjectDID, domVal, roleVal string, holderPub *ecdsa.PublicKey, privIssuer *ecdsa.PrivateKey) (*SignedSDJWTCredential, registry.Credential) {
		jwk, err := JWKFromPublicKey(holderPub)
		require.NoError(t, err)
		signed, err := IssueEnterpriseIdentityCredential(
			privIssuer,
			issuerDID+"#key-1",
			EnterpriseIdentityCredential{
				Type:             []string{CredentialTypeVC, CredentialTypeEnterpriseIdentity},
				ID:               credID,
				DeploymentID:     depID,
				Issuer:           issuerDID,
				Iss:              issuerDID,
				Sub:              subjectDID,
				IssuerKeyVersion: 1,
				AppKeyVersion:    1,
				ValidFrom:        vf,
				ValidUntil:       vu,
				NBF:              nbf,
				EXP:              exp,
				CredentialStatus: CredentialStatus{ID: credID, Type: StatusTypeCredential},
				Cnf:              ConfirmationKey{JWK: jwk},
				CredentialSubject: SDJWTCredentialSubject{
					ID: subjectDID,
				},
			},
			domVal,
			roleVal,
			nil,
		)
		require.NoError(t, err)
		rec := registry.Credential{
			Bound:             registry.Bound{DeploymentID: depID},
			ID:                credID,
			Issuer:            issuerDID,
			Subject:           subjectDID,
			IssuerKeyVersion:  1,
			SubjectKeyVersion: 1,
			Type:              CredentialTypeEnterpriseIdentity,
			ClaimNames:        []string{"domain", "role"},
			Digest:            signed.AnchorDigest,
			Interval:          registry.Interval{NBF: nbf, EXP: exp},
			Version:           registry.Version{Status: registry.Active, Revision: 1},
		}
		return signed, rec
	}

	sdU, credU := issueCred("urn:grad:credential:U-v1", didIA, didU, "A", "USER", &privU.PublicKey, privIA)
	sdB1, credB1 := issueCred("urn:grad:credential:B1-v1", didIB, didB1, "B", "AGENT", &privB1.PublicKey, privIB)
	sdC, credC := issueCred("urn:grad:credential:C-v1", didIC, didC, "C", "SERVICE", &privC.PublicKey, privIC)

	spec := TaskSpec{
		SupplierID:  "urn:grad:supplier:C",
		ProductID:   "urn:grad:product:P1",
		MaxQuantity: 1,
		Currency:    "CNY",
		Resources:   []string{ResourceOrders, ResourceQuotes},
		Actions:     []string{ActionOrderCreate, ActionQuoteRead},
		Description: "P1 x 1",
	}
	specDigest, err := spec.Digest()
	require.NoError(t, err)

	g0Claims := GrantClaims{
		ID:                  g0ID,
		SchemaVersion:       SchemaVersion,
		DeploymentID:        depID,
		RootID:              g0ID,
		TaskID:              taskID,
		AuthorizationMode:   ModeResourcePreauthorized,
		PrincipalDomain:     "A",
		ResourceID:          resID,
		Issuer:              didC,
		Grantee:             didU,
		IssuerKeyVersion:    1,
		GranteeKeyVersion:   1,
		IssuerCredentialID:  credC.ID,
		GranteeCredentialID: credU.ID,
		Resources:           []string{ResourceOrders, ResourceQuotes},
		Actions:             []string{ActionOrderCreate, ActionQuoteRead},
		Suppliers:           []string{"urn:grad:supplier:C"},
		Aud:                 "https://c.local",
		Currency:            "CNY",
		MaxAmountMinor:      100000,
		NBF:                 nbf + 5,
		EXP:                 exp - 5,
		RemainingDepth:      2,
	}
	g0JWS, g0Digest, err := SignGrant(privC, didC+"#key-1", &g0Claims)
	require.NoError(t, err)

	g1Claims := GrantClaims{
		ID:                  g1ID,
		SchemaVersion:       SchemaVersion,
		DeploymentID:        depID,
		ParentID:            &g0ID,
		ParentDigest:        &g0Digest,
		RootID:              g0ID,
		TaskID:              taskID,
		AuthorizationMode:   ModeResourcePreauthorized,
		PrincipalDomain:     "A",
		ResourceID:          resID,
		Issuer:              didU,
		Grantee:             didB1,
		IssuerKeyVersion:    1,
		GranteeKeyVersion:   1,
		IssuerCredentialID:  credU.ID,
		GranteeCredentialID: credB1.ID,
		Resources:           []string{ResourceOrders, ResourceQuotes},
		Actions:             []string{ActionOrderCreate, ActionQuoteRead},
		Suppliers:           []string{"urn:grad:supplier:C"},
		Aud:                 "https://c.local",
		Currency:            "CNY",
		MaxAmountMinor:      90000,
		NBF:                 nbf + 10,
		EXP:                 exp - 10,
		RemainingDepth:      1,
	}
	g1JWS, g1Digest, err := SignGrant(privU, didU+"#key-1", &g1Claims)
	require.NoError(t, err)

	snap := &SnapshotView{
		Height:       42,
		Now:          now,
		ClockError:   registry.ClockError,
		DeploymentID: depID,
		Root: registry.RootRecord{
			DID:            didT,
			DocumentDigest: digT,
			KeyID:          didT + "#key-1",
			KeyVersion:     1,
			PublicKey:      pubT,
		},
		Domains:        map[string]registry.Domain{"A": domA, "B": domB, "C": domC},
		Certifications: map[string]registry.Certification{certA.ID: certA, certB.ID: certB, certC.ID: certC},
		Identities: map[string]registry.Identity{
			didIA: {Bound: registry.Bound{DeploymentID: depID}, ID: didIA, Domain: "A", DocumentDigest: digIA, KeyID: didIA + "#key-1", KeyVersion: 1, PublicKey: pubIA, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didU:  {Bound: registry.Bound{DeploymentID: depID}, ID: didU, Domain: "A", DocumentDigest: digU, KeyID: didU + "#key-1", KeyVersion: 1, PublicKey: pubU, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didIB: {Bound: registry.Bound{DeploymentID: depID}, ID: didIB, Domain: "B", DocumentDigest: digIB, KeyID: didIB + "#key-1", KeyVersion: 1, PublicKey: pubIB, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didB1: {Bound: registry.Bound{DeploymentID: depID}, ID: didB1, Domain: "B", DocumentDigest: digB1, KeyID: didB1 + "#key-1", KeyVersion: 1, PublicKey: pubB1, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didIC: {Bound: registry.Bound{DeploymentID: depID}, ID: didIC, Domain: "C", DocumentDigest: digIC, KeyID: didIC + "#key-1", KeyVersion: 1, PublicKey: pubIC, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didC:  {Bound: registry.Bound{DeploymentID: depID}, ID: didC, Domain: "C", Kind: "SERVICE", DocumentDigest: digC, KeyID: didC + "#key-1", KeyVersion: 1, PublicKey: pubC, Version: registry.Version{Status: registry.Active, Revision: 1}},
		},
		Credentials: map[string]registry.Credential{
			credU.ID:  credU,
			credB1.ID: credB1,
			credC.ID:  credC,
		},
		Tasks: map[string]registry.Task{
			taskID: {
				Bound:             registry.Bound{DeploymentID: depID},
				ID:                taskID,
				Creator:           didU,
				CreatorCredential: credU.ID,
				CreatorKeyVersion: 1,
				Domain:            "A",
				Mode:              ModeResourcePreauthorized,
				Resource:          resID,
				Digest:            specDigest,
				Interval:          registry.Interval{NBF: nbf, EXP: exp},
				Version:           registry.Version{Status: registry.Active, Revision: 1},
			},
		},
		Grants: map[string]registry.Grant{
			g0ID: {
				Bound:             registry.Bound{DeploymentID: depID},
				ID:                g0ID,
				Schema:            SchemaVersion,
				Root:              g0ID,
				Task:              taskID,
				Mode:              ModeResourcePreauthorized,
				Domain:            "A",
				Resource:          resID,
				Issuer:            didC,
				Grantee:           didU,
				IssuerKeyVersion:  1,
				GranteeKeyVersion: 1,
				IssuerCredential:  credC.ID,
				GranteeCredential: credU.ID,
				Depth:             2,
				Digest:            g0Digest,
				Interval:          registry.Interval{NBF: g0Claims.NBF, EXP: g0Claims.EXP},
				Version:           registry.Version{Status: registry.Active, Revision: 1},
			},
			g1ID: {
				Bound:             registry.Bound{DeploymentID: depID},
				ID:                g1ID,
				Schema:            SchemaVersion,
				Parent:            g0ID,
				ParentDigest:      g0Digest,
				Root:              g0ID,
				Task:              taskID,
				Mode:              ModeResourcePreauthorized,
				Domain:            "A",
				Resource:          resID,
				Issuer:            didU,
				Grantee:           didB1,
				IssuerKeyVersion:  1,
				GranteeKeyVersion: 1,
				IssuerCredential:  credU.ID,
				GranteeCredential: credB1.ID,
				Depth:             1,
				Digest:            g1Digest,
				Interval:          registry.Interval{NBF: g1Claims.NBF, EXP: g1Claims.EXP},
				Version:           registry.Version{Status: registry.Active, Revision: 1},
			},
		},
	}

	nonce, err := GenerateNonce()
	require.NoError(t, err)
	challenge := ChallengeContext{
		ChallengeID: "ch-001",
		Nonce:       nonce,
		Audience:    "https://c.local",
		IssuedAt:    now.Add(-5 * time.Second).Unix(),
		ExpiresAt:   now.Add(60 * time.Second).Unix(),
	}
	quoteID := "urn:grad:quote:Q800"
	basePkg := AccessEvidencePackage{
		Request: AccessRequest{
			SchemaVersion:     SchemaVersion,
			DeploymentID:      depID,
			Actor:             didB1,
			PrincipalDomain:   "A",
			AuthorizationMode: ModeResourcePreauthorized,
			TaskID:            taskID,
			Audience:          "https://c.local",
			Resource:          ResourceOrders,
			Action:            ActionOrderCreate,
			SupplierID:        "urn:grad:supplier:C",
			QuoteID:           &quoteID,
			ProductID:         "urn:grad:product:P1",
			Quantity:          1,
			Currency:          "CNY",
			AmountMinor:       80000,
			IdempotencyKey:    "order-001",
		},
		TaskSpec: spec,
		AncestorCredentials: []AncestorCredential{
			{CredentialID: credC.ID, Presentation: sdC.PresentationPrefix},
			{CredentialID: credU.ID, Presentation: sdU.PresentationPrefix},
		},
		Grants: []string{g0JWS, g1JWS},
		TrustPaths: []TrustPathEntry{
			{Issuer: didIA, DomainCertification: certAJWS},
			{Issuer: didIB, DomainCertification: certBJWS},
			{Issuer: didIC, DomainCertification: certCJWS},
		},
	}

	bindings, kbJWT, err := AssembleAccessEvidencePackage(&basePkg, sdB1.PresentationPrefix, didB1+"#key-1", privB1, challenge, now.Unix(), false)
	require.NoError(t, err)
	assert.NotEmpty(t, kbJWT)
	assert.NotEmpty(t, bindings.RequestHash)
	assert.NotEmpty(t, bindings.ChainHash)
	assert.NotEmpty(t, bindings.EvidenceHash)
	assert.NotEmpty(t, bindings.SDHash)

	ctx := context.Background()
	res, err := VerifyAccessEvidencePackage(ctx, &basePkg, snap, dids, challenge)
	require.NoError(t, err)
	assert.Equal(t, specDigest, res.TaskSpecDigest)
	assert.Len(t, res.Grants, 2)
	assert.Len(t, res.TrustPathCerts, 3)

	// Round-trip through strict JSON parsing.
	rawPkgBytes, err := MarshalJCS(&basePkg)
	require.NoError(t, err)
	parsedPkg, err := ParseAccessEvidencePackage(rawPkgBytes)
	require.NoError(t, err)
	_, err = VerifyAccessEvidencePackage(ctx, parsedPkg, snap, dids, challenge)
	require.NoError(t, err)

	clonePkg := func() AccessEvidencePackage {
		p := basePkg
		p.AncestorCredentials = append([]AncestorCredential(nil), basePkg.AncestorCredentials...)
		p.Grants = append([]string(nil), basePkg.Grants...)
		p.TrustPaths = append([]TrustPathEntry(nil), basePkg.TrustPaths...)
		p.TaskSpec.Resources = append([]string(nil), basePkg.TaskSpec.Resources...)
		p.TaskSpec.Actions = append([]string(nil), basePkg.TaskSpec.Actions...)
		if basePkg.Request.QuoteID != nil {
			q := *basePkg.Request.QuoteID
			p.Request.QuoteID = &q
		}
		return p
	}

	// 1. Tamper request.
	tamperReq := clonePkg()
	tamperReq.Request.AmountMinor = 80001
	_, err = VerifyAccessEvidencePackage(ctx, &tamperReq, snap, dids, challenge)
	assert.Error(t, err)

	// 2. Tamper taskSpec.
	tamperSpec := clonePkg()
	tamperSpec.TaskSpec.Description = "tampered"
	_, err = VerifyAccessEvidencePackage(ctx, &tamperSpec, snap, dids, challenge)
	assert.Error(t, err)

	// 3. Tamper challengeId.
	tamperChalID := clonePkg()
	tamperChalID.ChallengeID = "ch-999"
	_, err = VerifyAccessEvidencePackage(ctx, &tamperChalID, snap, dids, challenge)
	assert.Error(t, err)

	// 4. Tamper nonce in challenge context.
	tamperNonceChal := challenge
	otherNonce, err := GenerateNonce()
	require.NoError(t, err)
	tamperNonceChal.Nonce = otherNonce
	_, err = VerifyAccessEvidencePackage(ctx, &basePkg, snap, dids, tamperNonceChal)
	assert.Error(t, err)

	// 5. Tamper leafPresentation.
	tamperLeaf := clonePkg()
	tamperLeaf.LeafPresentation = strings.Replace(tamperLeaf.LeafPresentation, sdB1.DisclosureByClaim["role"], sdB1.DisclosureByClaim["domain"], 1)
	_, err = VerifyAccessEvidencePackage(ctx, &tamperLeaf, snap, dids, challenge)
	assert.Error(t, err)

	// 6. Tamper ancestorCredentials.
	tamperAnc := clonePkg()
	tamperAnc.AncestorCredentials[0].Presentation = sdC.IssuerSignedJWT + "~" + sdC.DisclosureByClaim["domain"] + "~"
	_, err = VerifyAccessEvidencePackage(ctx, &tamperAnc, snap, dids, challenge)
	assert.Error(t, err)

	// 7. Tamper grants.
	tamperGrants := clonePkg()
	tamperGrants.Grants[1] = tamperGrants.Grants[1][:len(tamperGrants.Grants[1])-1] + toggleLastB64Char(tamperGrants.Grants[1])
	_, err = VerifyAccessEvidencePackage(ctx, &tamperGrants, snap, dids, challenge)
	assert.Error(t, err)

	// 8. Tamper trustPaths.
	tamperTP := clonePkg()
	tamperTP.TrustPaths[0].DomainCertification = tamperTP.TrustPaths[0].DomainCertification[:len(tamperTP.TrustPaths[0].DomainCertification)-1] + toggleLastB64Char(tamperTP.TrustPaths[0].DomainCertification)
	_, err = VerifyAccessEvidencePackage(ctx, &tamperTP, snap, dids, challenge)
	assert.Error(t, err)

	// 9. Suspended domain at fixed snapshot height rejected.
	tamperDom := *snap
	domCopy := domB
	domCopy.Status = registry.Suspended
	tamperDom.Domains = map[string]registry.Domain{"A": domA, "B": domCopy, "C": domC}
	_, err = VerifyAccessEvidencePackage(ctx, &basePkg, &tamperDom, dids, challenge)
	assert.Error(t, err)
}

func toggleLastB64Char(s string) string {
	if s[len(s)-1] == 'A' {
		return "B"
	}
	return "A"
}

func TestTwoHopEvidenceVerificationRPAndBM(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	nbf, exp := now.Add(-10*time.Minute).Unix(), now.Add(time.Hour).Unix()
	depID := strings.Repeat("cc", 32)
	resID := ResourceOrders

	ca, err := GenerateTestCA(now)
	require.NoError(t, err)
	caPool, err := ParseTestCAPublic(ca.CertPEM)
	require.NoError(t, err)
	certs := make(map[string]*HostTLSCert, len(ControlledTestDomains))
	for _, host := range ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		require.NoError(t, err)
		certs[host] = hc
	}

	privT, pubT := mustGenKeyPair(t)
	privIA, pubIA := mustGenKeyPair(t)
	privIB, pubIB := mustGenKeyPair(t)
	privIC, pubIC := mustGenKeyPair(t)
	privPA, pubPA := mustGenKeyPair(t)
	privU, pubU := mustGenKeyPair(t)
	privA1, pubA1 := mustGenKeyPair(t)
	privB1, pubB1 := mustGenKeyPair(t)
	privUinB, pubUinB := mustGenKeyPair(t)
	privC, pubC := mustGenKeyPair(t)

	didT := "did:web:t.local"
	didIA, didU, didPA, didA1 := "did:web:a.local:issuer", "did:web:a.local:u", "did:web:a.local:pa", "did:web:a.local:a1"
	didIB, didB1, didUinB := "did:web:b.local:issuer", "did:web:b.local:b1", "did:web:b.local:u-in-b"
	didIC, didC := "did:web:c.local:issuer", "did:web:c.local:supplier"

	docs := map[string][]byte{}
	makeDoc := func(did string, pub *ecdsa.PublicKey) string {
		d, err := NewDIDDocument(did, did+"#key-1", pub, KeyPurposeAuthentication, KeyPurposeAssertionMethod)
		require.NoError(t, err)
		raw, err := MarshalJCS(d)
		require.NoError(t, err)
		dig, err := d.Digest()
		require.NoError(t, err)
		docs[did] = raw
		return dig
	}
	digT := makeDoc(didT, &privT.PublicKey)
	digIA, digU, digPA, digA1 := makeDoc(didIA, &privIA.PublicKey), makeDoc(didU, &privU.PublicKey), makeDoc(didPA, &privPA.PublicKey), makeDoc(didA1, &privA1.PublicKey)
	digIB, digB1, digUinB := makeDoc(didIB, &privIB.PublicKey), makeDoc(didB1, &privB1.PublicKey), makeDoc(didUinB, &privUinB.PublicKey)
	digIC, digC := makeDoc(didIC, &privIC.PublicKey), makeDoc(didC, &privC.PublicKey)

	srv, err := NewDIDWebServer(certs, docs)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	dids, err := NewDIDWebResolver(caPool, srv.Routes())
	require.NoError(t, err)
	_, err = dids.RegisterPreseed(RootPreseed{
		DID: didT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKeyHex: pubT, DIDDocumentDigest: digT, RawDocument: docs[didT],
	})
	require.NoError(t, err)

	issueCert := func(id, domID, domDID, issDID string) (string, registry.Domain, registry.Certification) {
		scopes := []IssuerScope{{ID: issDID, AppKeyVersion: 1, CredentialTypes: []string{CredentialTypeEnterpriseIdentity}, ClaimNames: []string{"domain", "role"}}}
		jws, dig, err := SignDomainAuthorityCredential(privT, didT+"#key-1", &DomainAuthorityCredential{
			Type: []string{CredentialTypeVC, CredentialTypeDomainAuthority}, ID: id, DeploymentID: depID,
			Issuer: didT, Iss: didT, Sub: domDID, IssuerKeyVersion: 1,
			ValidFrom: time.Unix(nbf, 0).UTC().Format(time.RFC3339), ValidUntil: time.Unix(exp, 0).UTC().Format(time.RFC3339),
			NBF: nbf, EXP: exp, CredentialStatus: CredentialStatus{ID: id, Type: StatusTypeDomainCertification},
			CredentialSubject: DomainAuthoritySubject{ID: domDID, DomainID: domID, IdentityIssuers: scopes},
		})
		require.NoError(t, err)
		dom := registry.Domain{Bound: registry.Bound{DeploymentID: depID}, ID: domID, DID: domDID, Issuers: []string{issDID}, Certification: id, Version: registry.Version{Status: registry.Active, Revision: 2}}
		if domID == "A" {
			dom.PurchasingAuthority = didPA
		}
		cert := registry.Certification{Bound: registry.Bound{DeploymentID: depID}, ID: id, Domain: domID, RootKeyVersion: 1, Digest: dig, Scopes: scopes, Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1}}
		return jws, dom, cert
	}
	certAJWS, domA, certA := issueCert("urn:grad:cert:A-v1", "A", "did:web:a.local", didIA)
	certBJWS, domB, certB := issueCert("urn:grad:cert:B-v1", "B", "did:web:b.local", didIB)
	certCJWS, domC, certC := issueCert("urn:grad:cert:C-v1", "C", "did:web:c.local", didIC)

	issueCred := func(id, issDID, subDID, domID, role string, subPub *ecdsa.PublicKey, issPriv *ecdsa.PrivateKey) (*SignedSDJWTCredential, registry.Credential) {
		jwk, err := JWKFromPublicKey(subPub)
		require.NoError(t, err)
		s, err := IssueEnterpriseIdentityCredential(issPriv, issDID+"#key-1", EnterpriseIdentityCredential{
			Type: []string{CredentialTypeVC, CredentialTypeEnterpriseIdentity}, ID: id, DeploymentID: depID,
			Issuer: issDID, Iss: issDID, Sub: subDID, IssuerKeyVersion: 1, AppKeyVersion: 1,
			ValidFrom: time.Unix(nbf, 0).UTC().Format(time.RFC3339), ValidUntil: time.Unix(exp, 0).UTC().Format(time.RFC3339),
			NBF: nbf, EXP: exp, CredentialStatus: CredentialStatus{ID: id, Type: StatusTypeCredential},
			Cnf: ConfirmationKey{JWK: jwk}, CredentialSubject: SDJWTCredentialSubject{ID: subDID},
		}, domID, role, nil)
		require.NoError(t, err)
		return s, registry.Credential{
			Bound: registry.Bound{DeploymentID: depID}, ID: id, Issuer: issDID, Subject: subDID,
			IssuerKeyVersion: 1, SubjectKeyVersion: 1, Type: CredentialTypeEnterpriseIdentity,
			ClaimNames: []string{"domain", "role"}, Digest: s.AnchorDigest,
			Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1},
		}
	}
	sdPA, credPA := issueCred("urn:grad:credential:PA-v1", didIA, didPA, "A", "procurement-authority", &privPA.PublicKey, privIA)
	sdU, credU := issueCred("urn:grad:credential:U-v1", didIA, didU, "A", "USER", &privU.PublicKey, privIA)
	sdA1, credA1 := issueCred("urn:grad:credential:A1-v1", didIA, didA1, "A", "AGENT", &privA1.PublicKey, privIA)
	sdB1, credB1 := issueCred("urn:grad:credential:B1-v1", didIB, didB1, "B", "AGENT", &privB1.PublicKey, privIB)
	_, credUinB := issueCred("urn:grad:credential:UinB-v1", didIB, didUinB, "B", "USER", &privUinB.PublicKey, privIB)
	sdC, credC := issueCred("urn:grad:credential:C-v1", didIC, didC, "C", "supplier-service", &privC.PublicKey, privIC)

	spec := TaskSpec{
		SupplierID: "urn:grad:supplier:C", ProductID: "urn:grad:product:P1", MaxQuantity: 1, Currency: "CNY",
		Resources: []string{ResourceOrders, ResourceQuotes},
		Actions:   []string{ActionOrderCreate, ActionQuoteRead}, Description: "Dual-root verification",
	}
	specDig, err := spec.Digest()
	require.NoError(t, err)

	makeChain := func(mode, taskID, g0ID, g1ID, g2ID, rootDID, rootCredID string, rootPriv *ecdsa.PrivateKey) (registry.Task, map[string]registry.Grant, []string) {
		tRec := registry.Task{
			Bound: registry.Bound{DeploymentID: depID}, ID: taskID, Creator: didU, CreatorCredential: credU.ID, CreatorKeyVersion: 1,
			Domain: "A", Mode: mode, Resource: resID, Digest: specDig, Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1},
		}
		g0C := GrantClaims{
			ID: g0ID, SchemaVersion: SchemaVersion, DeploymentID: depID, RootID: g0ID, TaskID: taskID, AuthorizationMode: mode,
			PrincipalDomain: "A", ResourceID: resID, Issuer: rootDID, Grantee: didU, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
			IssuerCredentialID: rootCredID, GranteeCredentialID: credU.ID, Resources: spec.Resources, Actions: spec.Actions,
			Suppliers: []string{spec.SupplierID}, Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 2,
		}
		g0JWS, g0Dig, err := SignGrant(rootPriv, rootDID+"#key-1", &g0C)
		require.NoError(t, err)
		g1C := GrantClaims{
			ID: g1ID, SchemaVersion: SchemaVersion, DeploymentID: depID, ParentID: &g0ID, ParentDigest: &g0Dig, RootID: g0ID,
			TaskID: taskID, AuthorizationMode: mode, PrincipalDomain: "A", ResourceID: resID, Issuer: didU, Grantee: didA1,
			IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: credU.ID, GranteeCredentialID: credA1.ID,
			Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{spec.SupplierID}, Aud: "https://c.local",
			Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 1,
		}
		g1JWS, g1Dig, err := SignGrant(privU, didU+"#key-1", &g1C)
		require.NoError(t, err)
		g2C := GrantClaims{
			ID: g2ID, SchemaVersion: SchemaVersion, DeploymentID: depID, ParentID: &g1ID, ParentDigest: &g1Dig, RootID: g0ID,
			TaskID: taskID, AuthorizationMode: mode, PrincipalDomain: "A", ResourceID: resID, Issuer: didA1, Grantee: didB1,
			IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: credA1.ID, GranteeCredentialID: credB1.ID,
			Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{spec.SupplierID}, Aud: "https://c.local",
			Currency: "CNY", MaxAmountMinor: 100000, NBF: nbf, EXP: exp, RemainingDepth: 0,
		}
		g2JWS, g2Dig, err := SignGrant(privA1, didA1+"#key-1", &g2C)
		require.NoError(t, err)
		grants := map[string]registry.Grant{
			g0ID: {Bound: registry.Bound{DeploymentID: depID}, ID: g0ID, Schema: SchemaVersion, Root: g0ID, Task: taskID, Mode: mode, Domain: "A", Resource: resID, Issuer: rootDID, Grantee: didU, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: rootCredID, GranteeCredential: credU.ID, Depth: 2, Digest: g0Dig, Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1}},
			g1ID: {Bound: registry.Bound{DeploymentID: depID}, ID: g1ID, Schema: SchemaVersion, Parent: g0ID, ParentDigest: g0Dig, Root: g0ID, Task: taskID, Mode: mode, Domain: "A", Resource: resID, Issuer: didU, Grantee: didA1, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: credU.ID, GranteeCredential: credA1.ID, Depth: 1, Digest: g1Dig, Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1}},
			g2ID: {Bound: registry.Bound{DeploymentID: depID}, ID: g2ID, Schema: SchemaVersion, Parent: g1ID, ParentDigest: g1Dig, Root: g0ID, Task: taskID, Mode: mode, Domain: "A", Resource: resID, Issuer: didA1, Grantee: didB1, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: credA1.ID, GranteeCredential: credB1.ID, Depth: 0, Digest: g2Dig, Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1}},
		}
		return tRec, grants, []string{g0JWS, g1JWS, g2JWS}
	}

	rpTaskID, rpG0, rpG1, rpG2 := strings.Repeat("11", 32), strings.Repeat("21", 32), strings.Repeat("22", 32), strings.Repeat("23", 32)
	bmTaskID, bmG0, bmG1, bmG2 := strings.Repeat("31", 32), strings.Repeat("41", 32), strings.Repeat("42", 32), strings.Repeat("43", 32)
	rpTask, rpGrants, rpJWS := makeChain(ModeResourcePreauthorized, rpTaskID, rpG0, rpG1, rpG2, didC, credC.ID, privC)
	bmTask, bmGrants, bmJWS := makeChain(ModeBuyerMandate, bmTaskID, bmG0, bmG1, bmG2, didPA, credPA.ID, privPA)

	allGrants := map[string]registry.Grant{}
	for k, v := range rpGrants {
		allGrants[k] = v
	}
	for k, v := range bmGrants {
		allGrants[k] = v
	}
	snap := &SnapshotView{
		Height: 100, Now: now, ClockError: registry.ClockError, DeploymentID: depID,
		Root:           registry.RootRecord{DID: didT, DocumentDigest: digT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKey: pubT},
		Domains:        map[string]registry.Domain{"A": domA, "B": domB, "C": domC},
		Certifications: map[string]registry.Certification{certA.ID: certA, certB.ID: certB, certC.ID: certC},
		Identities: map[string]registry.Identity{
			didIA:   {Bound: registry.Bound{DeploymentID: depID}, ID: didIA, Domain: "A", Kind: "ISSUER", DocumentDigest: digIA, KeyID: didIA + "#key-1", KeyVersion: 1, PublicKey: pubIA, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didU:    {Bound: registry.Bound{DeploymentID: depID}, ID: didU, Domain: "A", Kind: "USER", DocumentDigest: digU, KeyID: didU + "#key-1", KeyVersion: 1, PublicKey: pubU, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didPA:   {Bound: registry.Bound{DeploymentID: depID}, ID: didPA, Domain: "A", Kind: "SERVICE", DocumentDigest: digPA, KeyID: didPA + "#key-1", KeyVersion: 1, PublicKey: pubPA, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didA1:   {Bound: registry.Bound{DeploymentID: depID}, ID: didA1, Domain: "A", Kind: "AGENT", DocumentDigest: digA1, KeyID: didA1 + "#key-1", KeyVersion: 1, PublicKey: pubA1, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didIB:   {Bound: registry.Bound{DeploymentID: depID}, ID: didIB, Domain: "B", Kind: "ISSUER", DocumentDigest: digIB, KeyID: didIB + "#key-1", KeyVersion: 1, PublicKey: pubIB, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didB1:   {Bound: registry.Bound{DeploymentID: depID}, ID: didB1, Domain: "B", Kind: "AGENT", DocumentDigest: digB1, KeyID: didB1 + "#key-1", KeyVersion: 1, PublicKey: pubB1, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didUinB: {Bound: registry.Bound{DeploymentID: depID}, ID: didUinB, Domain: "B", Kind: "USER", DocumentDigest: digUinB, KeyID: didUinB + "#key-1", KeyVersion: 1, PublicKey: pubUinB, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didIC:   {Bound: registry.Bound{DeploymentID: depID}, ID: didIC, Domain: "C", Kind: "ISSUER", DocumentDigest: digIC, KeyID: didIC + "#key-1", KeyVersion: 1, PublicKey: pubIC, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didC:    {Bound: registry.Bound{DeploymentID: depID}, ID: didC, Domain: "C", Kind: "SERVICE", DocumentDigest: digC, KeyID: didC + "#key-1", KeyVersion: 1, PublicKey: pubC, Version: registry.Version{Status: registry.Active, Revision: 1}},
		},
		Credentials: map[string]registry.Credential{
			credPA.ID: credPA, credU.ID: credU, credA1.ID: credA1, credB1.ID: credB1, credUinB.ID: credUinB, credC.ID: credC,
		},
		Tasks:  map[string]registry.Task{rpTaskID: rpTask, bmTaskID: bmTask},
		Grants: allGrants,
	}

	nonce, err := GenerateNonce()
	require.NoError(t, err)
	chal := ChallengeContext{ChallengeID: "dual-root-ch-1", Nonce: nonce, Audience: "https://c.local", IssuedAt: now.Unix(), ExpiresAt: exp}
	qID := "urn:grad:quote:Q800"

	// 1. RP 2-hop C -> U -> A1 -> B1 succeeds.
	rpPkg := AccessEvidencePackage{
		Request: AccessRequest{
			SchemaVersion: SchemaVersion, DeploymentID: depID, Actor: didB1, PrincipalDomain: "A",
			AuthorizationMode: ModeResourcePreauthorized, TaskID: rpTaskID, Audience: "https://c.local",
			Resource: resID, Action: ActionOrderCreate, SupplierID: spec.SupplierID, QuoteID: &qID,
			ProductID: spec.ProductID, Quantity: 1, Currency: "CNY", AmountMinor: 80000, IdempotencyKey: "dual-root-rp-001",
		},
		TaskSpec: spec,
		AncestorCredentials: []AncestorCredential{
			{CredentialID: credA1.ID, Presentation: sdA1.PresentationPrefix},
			{CredentialID: credC.ID, Presentation: sdC.PresentationPrefix},
			{CredentialID: credU.ID, Presentation: sdU.PresentationPrefix},
		},
		Grants: rpJWS,
		TrustPaths: []TrustPathEntry{
			{Issuer: didIA, DomainCertification: certAJWS},
			{Issuer: didIB, DomainCertification: certBJWS},
			{Issuer: didIC, DomainCertification: certCJWS},
		},
	}
	_, _, err = AssembleAccessEvidencePackage(&rpPkg, sdB1.PresentationPrefix, didB1+"#key-1", privB1, chal, now.Unix(), false)
	require.NoError(t, err)
	rpRes, err := VerifyAccessEvidencePackage(ctx, &rpPkg, snap, dids, chal)
	require.NoError(t, err)
	assert.Equal(t, int64(100000), rpRes.MinMaxAmountMinor)
	assert.Equal(t, "supplier-service", rpRes.RootAuthorityRole)

	// 2. BM 2-hop PA -> U -> A1 -> B1 succeeds with deduplicated TrustPaths (didIA, didIB only).
	bmPkg := AccessEvidencePackage{
		Request: AccessRequest{
			SchemaVersion: SchemaVersion, DeploymentID: depID, Actor: didB1, PrincipalDomain: "A",
			AuthorizationMode: ModeBuyerMandate, TaskID: bmTaskID, Audience: "https://c.local",
			Resource: resID, Action: ActionOrderCreate, SupplierID: spec.SupplierID, QuoteID: &qID,
			ProductID: spec.ProductID, Quantity: 1, Currency: "CNY", AmountMinor: 80000, IdempotencyKey: "dual-root-bm-001",
		},
		TaskSpec: spec,
		AncestorCredentials: []AncestorCredential{
			{CredentialID: credA1.ID, Presentation: sdA1.PresentationPrefix},
			{CredentialID: credPA.ID, Presentation: sdPA.PresentationPrefix},
			{CredentialID: credU.ID, Presentation: sdU.PresentationPrefix},
		},
		Grants: bmJWS,
		TrustPaths: []TrustPathEntry{
			{Issuer: didIA, DomainCertification: certAJWS},
			{Issuer: didIB, DomainCertification: certBJWS},
		},
	}
	_, _, err = AssembleAccessEvidencePackage(&bmPkg, sdB1.PresentationPrefix, didB1+"#key-1", privB1, chal, now.Unix(), false)
	require.NoError(t, err)
	bmRes, err := VerifyAccessEvidencePackage(ctx, &bmPkg, snap, dids, chal)
	require.NoError(t, err)
	assert.Equal(t, int64(100000), bmRes.MinMaxAmountMinor)
	assert.Equal(t, "procurement-authority", bmRes.RootAuthorityRole)

	// 3. Clearing Domain A PurchasingAuthority rejects BM with PURCHASING_AUTHORITY_INVALID.
	noPASnap := *snap
	domANoPA := domA
	domANoPA.PurchasingAuthority = ""
	noPASnap.Domains = map[string]registry.Domain{"A": domANoPA, "B": domB, "C": domC}
	_, err = VerifyAccessEvidencePackage(ctx, &bmPkg, &noPASnap, dids, chal)
	assert.True(t, HasCode(err, ErrCodePurchasingAuthorityInvalid), "got %v", err)

	// 4. Suspended ancestor grant G1 rejects with ANCESTOR_INACTIVE.
	suspSnap := *snap
	suspGrants := map[string]registry.Grant{}
	for k, v := range allGrants {
		suspGrants[k] = v
	}
	g1Susp := suspGrants[bmG1]
	g1Susp.Status = registry.Suspended
	suspGrants[bmG1] = g1Susp
	suspSnap.Grants = suspGrants
	_, err = VerifyAccessEvidencePackage(ctx, &bmPkg, &suspSnap, dids, chal)
	assert.True(t, HasCode(err, ErrCodeAncestorInactive), "got %v", err)

	// 5. order.create at 120000 (> G2 100000) defers amount check from VerifyAccessEvidencePackage to gateway executeInTx.
	overPkg := bmPkg
	overPkg.Request.AmountMinor = 120000
	_, _, err = AssembleAccessEvidencePackage(&overPkg, sdB1.PresentationPrefix, didB1+"#key-1", privB1, chal, now.Unix(), false)
	require.NoError(t, err)
	_, err = VerifyAccessEvidencePackage(ctx, &overPkg, snap, dids, chal)
	require.NoError(t, err)
}
