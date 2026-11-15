package protocol

import (
	"context"
	"crypto/ecdsa"
	"strings"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"
)

func TestAccessEvidencePackageFullVerifyAndSingleFieldTampers(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := GenerateTestCA(now)
	if err != nil {
		t.Fatal(err)
	}
	caPool, err := ParseTestCAPublic(ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	certs := make(map[string]*HostTLSCert, len(ControlledTestDomains))
	for _, host := range ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		if err != nil {
			t.Fatal(err)
		}
		certs[host] = hc
	}

	// Keys for T root, issuers IA/IB/IC, subjects U/B1/C
	privT, pubT, _ := GenerateP256KeyPair()
	privIA, pubIA, _ := GenerateP256KeyPair()
	privIB, pubIB, _ := GenerateP256KeyPair()
	privIC, pubIC, _ := GenerateP256KeyPair()
	privU, pubU, _ := GenerateP256KeyPair()
	privB1, pubB1, _ := GenerateP256KeyPair()
	privC, pubC, _ := GenerateP256KeyPair()

	didT := "did:web:t.local"
	didIA := "did:web:a.local:ia"
	didU := "did:web:a.local:u"
	didIB := "did:web:b.local:ib"
	didB1 := "did:web:b.local:b1"
	didIC := "did:web:c.local:ic"
	didC := "did:web:c.local:supplier"

	docs := map[string][]byte{}
	makeDoc := func(did, keyID, pub string, purposes ...string) string {
		d, err := NewDIDDocument(did, keyID, pub, purposes...)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := MarshalJCS(d)
		if err != nil {
			t.Fatal(err)
		}
		dig, err := d.Digest()
		if err != nil {
			t.Fatal(err)
		}
		docs[did] = raw
		return dig
	}

	digT := makeDoc(didT, didT+"#key-1", pubT, KeyPurposeAssertionMethod)
	digIA := makeDoc(didIA, didIA+"#key-1", pubIA, KeyPurposeAssertionMethod)
	digU := makeDoc(didU, didU+"#key-1", pubU, KeyPurposeAuthentication, KeyPurposeAssertionMethod)
	digIB := makeDoc(didIB, didIB+"#key-1", pubIB, KeyPurposeAssertionMethod)
	digB1 := makeDoc(didB1, didB1+"#key-1", pubB1, KeyPurposeAuthentication, KeyPurposeAssertionMethod)
	digIC := makeDoc(didIC, didIC+"#key-1", pubIC, KeyPurposeAssertionMethod)
	digC := makeDoc(didC, didC+"#key-1", pubC, KeyPurposeAuthentication, KeyPurposeAssertionMethod)

	srv, err := NewDIDWebServer(certs, docs)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	dids, err := NewDIDWebResolver(caPool, srv.Routes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dids.RegisterPreseed(RootPreseed{
		DID:               didT,
		KeyID:             didT + "#key-1",
		KeyVersion:        1,
		PublicKeyHex:      pubT,
		DIDDocumentDigest: digT,
		RawDocument:       docs[didT],
	}); err != nil {
		t.Fatal(err)
	}

	depID := api.Digest([]byte("test-deployment-id"))
	taskID := api.Digest([]byte("test-task-id"))
	resID := api.Digest([]byte("resource:" + didC))
	g0ID := api.Digest([]byte("test-grant-g0"))
	g1ID := api.Digest([]byte("test-grant-g1"))

	nbf := now.Add(-time.Hour).Unix()
	exp := now.Add(24 * time.Hour).Unix()
	vf := time.Unix(nbf, 0).UTC().Format(time.RFC3339)
	vu := time.Unix(exp, 0).UTC().Format(time.RFC3339)

	// Domain certifications A, B, C
	issueCert := func(domID, domDID, issuerDID string) (string, string, api.Domain, api.Certification) {
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
		if err != nil {
			t.Fatal(err)
		}
		domRec := api.Domain{
			Bound:         api.Bound{DeploymentID: depID},
			ID:            domID,
			DID:           domDID,
			Issuers:       []string{issuerDID},
			Certification: certID,
			Version:       api.Version{Status: api.Active, Revision: 1},
		}
		certRec := api.Certification{
			Bound:          api.Bound{DeploymentID: depID},
			ID:             certID,
			Domain:         domID,
			RootKeyVersion: 1,
			Digest:         dig,
			Scopes: []api.Scope{{
				ID:         issuerDID,
				KeyVersion: 1,
				Types:      []string{CredentialTypeEnterpriseIdentity},
				Claims:     []string{"domain", "role"},
			}},
			Interval: api.Interval{NBF: nbf, EXP: exp},
			Version:  api.Version{Status: api.Active, Revision: 1},
		}
		return jws, dig, domRec, certRec
	}

	certAJWS, _, domA, certA := issueCert("A", "did:web:a.local", didIA)
	certBJWS, _, domB, certB := issueCert("B", "did:web:b.local", didIB)
	certCJWS, _, domC, certC := issueCert("C", "did:web:c.local", didIC)

	// Identity credentials for U, B1, C
	issueCred := func(credID, issuerDID, subjectDID, domVal, roleVal, pubHex string, privIssuer *ecdsa.PrivateKey) (*SignedSDJWTCredential, api.Credential) {
		jwk, _ := AppPublicKeyToJWK(pubHex)
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
		if err != nil {
			t.Fatal(err)
		}
		rec := api.Credential{
			Bound:             api.Bound{DeploymentID: depID},
			ID:                credID,
			Issuer:            issuerDID,
			Subject:           subjectDID,
			IssuerKeyVersion:  1,
			SubjectKeyVersion: 1,
			Type:              CredentialTypeEnterpriseIdentity,
			ClaimNames:        []string{"domain", "role"},
			Digest:            signed.AnchorDigest,
			Interval:          api.Interval{NBF: nbf, EXP: exp},
			Version:           api.Version{Status: api.Active, Revision: 1},
		}
		return signed, rec
	}

	sdU, credU := issueCred("urn:grad:credential:U-v1", didIA, didU, "A", "USER", pubU, privIA)
	sdB1, credB1 := issueCred("urn:grad:credential:B1-v1", didIB, didB1, "B", "AGENT", pubB1, privIB)
	sdC, credC := issueCred("urn:grad:credential:C-v1", didIC, didC, "C", "SERVICE", pubC, privIC)

	spec := TaskSpec{
		SupplierID:  "urn:grad:supplier:C",
		ProductID:   "urn:grad:product:P1",
		MaxQuantity: 1,
		Currency:    "CNY",
		Resources:   []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:     []string{"order.create", "quote.read"},
		Description: "P1 x 1",
	}
	specDigest, err := spec.Digest()
	if err != nil {
		t.Fatal(err)
	}

	// Sign G0 (C -> U) and G1 (U -> B1)
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
		Resources:           []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:             []string{"order.create", "quote.read"},
		Suppliers:           []string{"urn:grad:supplier:C"},
		Aud:                 "https://c.local",
		Currency:            "CNY",
		MaxAmountMinor:      100000,
		NBF:                 nbf + 5,
		EXP:                 exp - 5,
		RemainingDepth:      2,
	}
	g0JWS, g0Digest, err := SignGrant(privC, didC+"#key-1", &g0Claims)
	if err != nil {
		t.Fatal(err)
	}

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
		Resources:           []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:             []string{"order.create", "quote.read"},
		Suppliers:           []string{"urn:grad:supplier:C"},
		Aud:                 "https://c.local",
		Currency:            "CNY",
		MaxAmountMinor:      90000,
		NBF:                 nbf + 10,
		EXP:                 exp - 10,
		RemainingDepth:      1,
	}
	g1JWS, g1Digest, err := SignGrant(privU, didU+"#key-1", &g1Claims)
	if err != nil {
		t.Fatal(err)
	}

	// Build fixed-height SnapshotView
	snap := &SnapshotView{
		Height:       42,
		Now:          now,
		ClockError:   api.ClockError,
		DeploymentID: depID,
		Root: api.RootRecord{
			DID:            didT,
			DocumentDigest: digT,
			KeyID:          didT + "#key-1",
			KeyVersion:     1,
			PublicKey:      pubT,
		},
		Domains:        map[string]api.Domain{"A": domA, "B": domB, "C": domC},
		Certifications: map[string]api.Certification{certA.ID: certA, certB.ID: certB, certC.ID: certC},
		Identities: map[string]api.Identity{
			didIA: {Bound: api.Bound{DeploymentID: depID}, ID: didIA, Domain: "A", DocumentDigest: digIA, KeyID: didIA + "#key-1", KeyVersion: 1, PublicKey: pubIA, Version: api.Version{Status: api.Active, Revision: 1}},
			didU:  {Bound: api.Bound{DeploymentID: depID}, ID: didU, Domain: "A", DocumentDigest: digU, KeyID: didU + "#key-1", KeyVersion: 1, PublicKey: pubU, Version: api.Version{Status: api.Active, Revision: 1}},
			didIB: {Bound: api.Bound{DeploymentID: depID}, ID: didIB, Domain: "B", DocumentDigest: digIB, KeyID: didIB + "#key-1", KeyVersion: 1, PublicKey: pubIB, Version: api.Version{Status: api.Active, Revision: 1}},
			didB1: {Bound: api.Bound{DeploymentID: depID}, ID: didB1, Domain: "B", DocumentDigest: digB1, KeyID: didB1 + "#key-1", KeyVersion: 1, PublicKey: pubB1, Version: api.Version{Status: api.Active, Revision: 1}},
			didIC: {Bound: api.Bound{DeploymentID: depID}, ID: didIC, Domain: "C", DocumentDigest: digIC, KeyID: didIC + "#key-1", KeyVersion: 1, PublicKey: pubIC, Version: api.Version{Status: api.Active, Revision: 1}},
			didC:  {Bound: api.Bound{DeploymentID: depID}, ID: didC, Domain: "C", Kind: "SERVICE", DocumentDigest: digC, KeyID: didC + "#key-1", KeyVersion: 1, PublicKey: pubC, Version: api.Version{Status: api.Active, Revision: 1}},
		},
		Credentials: map[string]api.Credential{
			credU.ID:  credU,
			credB1.ID: credB1,
			credC.ID:  credC,
		},
		Tasks: map[string]api.Task{
			taskID: {
				Bound:             api.Bound{DeploymentID: depID},
				ID:                taskID,
				Creator:           didU,
				CreatorCredential: credU.ID,
				CreatorKeyVersion: 1,
				Domain:            "A",
				Mode:              ModeResourcePreauthorized,
				Resource:          resID,
				Digest:            specDigest,
				Interval:          api.Interval{NBF: nbf, EXP: exp},
				Version:           api.Version{Status: api.Active, Revision: 1},
			},
		},
		Grants: map[string]api.Grant{
			g0ID: {
				Bound:             api.Bound{DeploymentID: depID},
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
				Interval:          api.Interval{NBF: g0Claims.NBF, EXP: g0Claims.EXP},
				Version:           api.Version{Status: api.Active, Revision: 1},
			},
			g1ID: {
				Bound:             api.Bound{DeploymentID: depID},
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
				Interval:          api.Interval{NBF: g1Claims.NBF, EXP: g1Claims.EXP},
				Version:           api.Version{Status: api.Active, Revision: 1},
			},
		},
	}

	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
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
			Resource:          "urn:grad:resource:C:orders",
			Action:            "order.create",
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
	if err != nil {
		t.Fatalf("AssembleAccessEvidencePackage: %v", err)
	}
	if kbJWT == "" || bindings.RequestHash == "" || bindings.ChainHash == "" || bindings.EvidenceHash == "" || bindings.SDHash == "" {
		t.Fatal("incomplete bindings returned")
	}

	ctx := context.Background()
	res, err := VerifyAccessEvidencePackage(ctx, &basePkg, snap, dids, challenge)
	if err != nil {
		t.Fatalf("VerifyAccessEvidencePackage positive case failed: %v", err)
	}
	if res.TaskSpecDigest != specDigest || len(res.Grants) != 2 || len(res.TrustPathCerts) != 3 {
		t.Fatalf("unexpected verified evidence summary")
	}

	// Verify KB-JWT recomputes identical sd_hash & binding digests and round-trips through strict JSON parsing
	rawPkgBytes, err := MarshalJCS(&basePkg)
	if err != nil {
		t.Fatal(err)
	}
	parsedPkg, err := ParseAccessEvidencePackage(rawPkgBytes)
	if err != nil {
		t.Fatalf("ParseAccessEvidencePackage: %v", err)
	}
	if _, err := VerifyAccessEvidencePackage(ctx, parsedPkg, snap, dids, challenge); err != nil {
		t.Fatalf("re-parsed package failed verification: %v", err)
	}

	// Single-field tamper tests across all 8 required dimensions
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

	// 1. Tamper request
	tamperReq := clonePkg()
	tamperReq.Request.AmountMinor = 80001
	if _, err := VerifyAccessEvidencePackage(ctx, &tamperReq, snap, dids, challenge); err == nil {
		t.Fatal("expected failure on tampered request")
	}

	// 2. Tamper taskSpec
	tamperSpec := clonePkg()
	tamperSpec.TaskSpec.Description = "tampered"
	if _, err := VerifyAccessEvidencePackage(ctx, &tamperSpec, snap, dids, challenge); err == nil {
		t.Fatal("expected failure on tampered taskSpec")
	}

	// 3. Tamper challengeId
	tamperChalID := clonePkg()
	tamperChalID.ChallengeID = "ch-999"
	if _, err := VerifyAccessEvidencePackage(ctx, &tamperChalID, snap, dids, challenge); err == nil {
		t.Fatal("expected failure on tampered challengeId")
	}

	// 4. Tamper nonce in challenge context
	tamperNonceChal := challenge
	otherNonce, _ := GenerateNonce()
	tamperNonceChal.Nonce = otherNonce
	if _, err := VerifyAccessEvidencePackage(ctx, &basePkg, snap, dids, tamperNonceChal); err == nil {
		t.Fatal("expected failure on tampered challenge nonce")
	}

	// 5. Tamper leafPresentation (flip signature/character or remove KB-JWT)
	tamperLeaf := clonePkg()
	tamperLeaf.LeafPresentation = strings.Replace(tamperLeaf.LeafPresentation, sdB1.DisclosureByClaim["role"], sdB1.DisclosureByClaim["domain"], 1)
	if _, err := VerifyAccessEvidencePackage(ctx, &tamperLeaf, snap, dids, challenge); err == nil {
		t.Fatal("expected failure on tampered leafPresentation")
	}

	// 6. Tamper ancestorCredentials (extra duplicate / missing / modified byte)
	tamperAnc := clonePkg()
	tamperAnc.AncestorCredentials[0].Presentation = sdC.IssuerSignedJWT + "~" + sdC.DisclosureByClaim["domain"] + "~"
	if _, err := VerifyAccessEvidencePackage(ctx, &tamperAnc, snap, dids, challenge); err == nil {
		t.Fatal("expected failure on tampered ancestorCredentials")
	}

	// 7. Tamper grants (flip single char in G1 signature or truncate to G0 only)
	tamperGrants := clonePkg()
	tamperGrants.Grants[1] = tamperGrants.Grants[1][:len(tamperGrants.Grants[1])-1] + toggleLastB64Char(tamperGrants.Grants[1])
	if _, err := VerifyAccessEvidencePackage(ctx, &tamperGrants, snap, dids, challenge); err == nil {
		t.Fatal("expected failure on tampered grants")
	}

	// 8. Tamper trustPaths (alter domainCertification byte)
	tamperTP := clonePkg()
	tamperTP.TrustPaths[0].DomainCertification = tamperTP.TrustPaths[0].DomainCertification[:len(tamperTP.TrustPaths[0].DomainCertification)-1] + toggleLastB64Char(tamperTP.TrustPaths[0].DomainCertification)
	if _, err := VerifyAccessEvidencePackage(ctx, &tamperTP, snap, dids, challenge); err == nil {
		t.Fatal("expected failure on tampered trustPaths")
	}

	// 9. Suspended domain at fixed snapshot height rejected
	tamperDom := *snap
	domCopy := domB
	domCopy.Status = api.Suspended
	tamperDom.Domains = map[string]api.Domain{"A": domA, "B": domCopy, "C": domC}
	if _, err := VerifyAccessEvidencePackage(ctx, &basePkg, &tamperDom, dids, challenge); err == nil {
		t.Fatal("expected failure when domain B is suspended in snapshot")
	}
}

func toggleLastB64Char(s string) string {
	last := s[len(s)-1]
	if last == 'A' {
		return "B"
	}
	return "A"
}

func TestM2TwoHopEvidenceVerificationRPAndBM(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	nbf, exp := now.Add(-10*time.Minute).Unix(), now.Add(time.Hour).Unix()
	depID := strings.Repeat("cc", 32)
	resID := "urn:grad:resource:C:orders"

	ca, err := GenerateTestCA(now)
	if err != nil {
		t.Fatal(err)
	}
	caPool, err := ParseTestCAPublic(ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	certs := make(map[string]*HostTLSCert, len(ControlledTestDomains))
	for _, host := range ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		if err != nil {
			t.Fatal(err)
		}
		certs[host] = hc
	}

	privT, pubT, _ := GenerateP256KeyPair()
	privIA, pubIA, _ := GenerateP256KeyPair()
	privIB, pubIB, _ := GenerateP256KeyPair()
	privIC, pubIC, _ := GenerateP256KeyPair()
	privPA, pubPA, _ := GenerateP256KeyPair()
	privU, pubU, _ := GenerateP256KeyPair()
	privA1, pubA1, _ := GenerateP256KeyPair()
	privB1, pubB1, _ := GenerateP256KeyPair()
	_, pubUinB, _ := GenerateP256KeyPair()
	privC, pubC, _ := GenerateP256KeyPair()

	didT := "did:web:t.local"
	didIA, didU, didPA, didA1 := "did:web:a.local:issuer", "did:web:a.local:u", "did:web:a.local:pa", "did:web:a.local:a1"
	didIB, didB1, didUinB := "did:web:b.local:issuer", "did:web:b.local:b1", "did:web:b.local:u-in-b"
	didIC, didC := "did:web:c.local:issuer", "did:web:c.local:supplier"

	docs := map[string][]byte{}
	makeDoc := func(did, pub string) string {
		d, err := NewDIDDocument(did, did+"#key-1", pub, KeyPurposeAuthentication, KeyPurposeAssertionMethod)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := MarshalJCS(d)
		if err != nil {
			t.Fatal(err)
		}
		dig, err := d.Digest()
		if err != nil {
			t.Fatal(err)
		}
		docs[did] = raw
		return dig
	}
	digT := makeDoc(didT, pubT)
	digIA, digU, digPA, digA1 := makeDoc(didIA, pubIA), makeDoc(didU, pubU), makeDoc(didPA, pubPA), makeDoc(didA1, pubA1)
	digIB, digB1, digUinB := makeDoc(didIB, pubIB), makeDoc(didB1, pubB1), makeDoc(didUinB, pubUinB)
	digIC, digC := makeDoc(didIC, pubIC), makeDoc(didC, pubC)

	srv, err := NewDIDWebServer(certs, docs)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	dids, err := NewDIDWebResolver(caPool, srv.Routes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dids.RegisterPreseed(RootPreseed{
		DID: didT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKeyHex: pubT, DIDDocumentDigest: digT, RawDocument: docs[didT],
	}); err != nil {
		t.Fatal(err)
	}

	issueCert := func(id, domID, domDID, issDID string) (string, api.Domain, api.Certification) {
		scopes := []IssuerScope{{ID: issDID, AppKeyVersion: 1, CredentialTypes: []string{CredentialTypeEnterpriseIdentity}, ClaimNames: []string{"domain", "role"}}}
		jws, dig, err := SignDomainAuthorityCredential(privT, didT+"#key-1", &DomainAuthorityCredential{
			Type: []string{CredentialTypeVC, CredentialTypeDomainAuthority}, ID: id, DeploymentID: depID,
			Issuer: didT, Iss: didT, Sub: domDID, IssuerKeyVersion: 1,
			ValidFrom: time.Unix(nbf, 0).UTC().Format(time.RFC3339), ValidUntil: time.Unix(exp, 0).UTC().Format(time.RFC3339),
			NBF: nbf, EXP: exp, CredentialStatus: CredentialStatus{ID: id, Type: StatusTypeDomainCertification},
			CredentialSubject: DomainAuthoritySubject{ID: domDID, DomainID: domID, IdentityIssuers: scopes},
		})
		if err != nil {
			t.Fatal(err)
		}
		dom := api.Domain{Bound: api.Bound{DeploymentID: depID}, ID: domID, DID: domDID, Issuers: []string{issDID}, Certification: id, Version: api.Version{Status: api.Active, Revision: 2}}
		if domID == "A" {
			dom.PurchasingAuthority = didPA
		}
		cert := api.Certification{Bound: api.Bound{DeploymentID: depID}, ID: id, Domain: domID, RootKeyVersion: 1, Digest: dig, Scopes: []api.Scope{{ID: issDID, KeyVersion: 1, Types: []string{CredentialTypeEnterpriseIdentity}, Claims: []string{"domain", "role"}}}, Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1}}
		return jws, dom, cert
	}
	certAJWS, domA, certA := issueCert("urn:grad:cert:A-v1", "A", "did:web:a.local", didIA)
	certBJWS, domB, certB := issueCert("urn:grad:cert:B-v1", "B", "did:web:b.local", didIB)
	certCJWS, domC, certC := issueCert("urn:grad:cert:C-v1", "C", "did:web:c.local", didIC)

	issueCred := func(id, issDID, subDID, domID, role, subPub string, issPriv *ecdsa.PrivateKey) (*SignedSDJWTCredential, api.Credential) {
		jwk, err := AppPublicKeyToJWK(subPub)
		if err != nil {
			t.Fatal(err)
		}
		s, err := IssueEnterpriseIdentityCredential(issPriv, issDID+"#key-1", EnterpriseIdentityCredential{
			Type: []string{CredentialTypeVC, CredentialTypeEnterpriseIdentity}, ID: id, DeploymentID: depID,
			Issuer: issDID, Iss: issDID, Sub: subDID, IssuerKeyVersion: 1, AppKeyVersion: 1,
			ValidFrom: time.Unix(nbf, 0).UTC().Format(time.RFC3339), ValidUntil: time.Unix(exp, 0).UTC().Format(time.RFC3339),
			NBF: nbf, EXP: exp, CredentialStatus: CredentialStatus{ID: id, Type: StatusTypeCredential},
			Cnf: ConfirmationKey{JWK: jwk}, CredentialSubject: SDJWTCredentialSubject{ID: subDID},
		}, domID, role, nil)
		if err != nil {
			t.Fatal(err)
		}
		return s, api.Credential{
			Bound: api.Bound{DeploymentID: depID}, ID: id, Issuer: issDID, Subject: subDID,
			IssuerKeyVersion: 1, SubjectKeyVersion: 1, Type: CredentialTypeEnterpriseIdentity,
			ClaimNames: []string{"domain", "role"}, Digest: s.AnchorDigest,
			Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
		}
	}
	sdPA, credPA := issueCred("urn:grad:credential:PA-v1", didIA, didPA, "A", "procurement-authority", pubPA, privIA)
	sdU, credU := issueCred("urn:grad:credential:U-v1", didIA, didU, "A", "USER", pubU, privIA)
	sdA1, credA1 := issueCred("urn:grad:credential:A1-v1", didIA, didA1, "A", "AGENT", pubA1, privIA)
	sdB1, credB1 := issueCred("urn:grad:credential:B1-v1", didIB, didB1, "B", "AGENT", pubB1, privIB)
	_, credUinB := issueCred("urn:grad:credential:UinB-v1", didIB, didUinB, "B", "USER", pubUinB, privIB)
	sdC, credC := issueCred("urn:grad:credential:C-v1", didIC, didC, "C", "supplier-service", pubC, privIC)

	spec := TaskSpec{
		SupplierID: "urn:grad:supplier:C", ProductID: "urn:grad:product:P1", MaxQuantity: 1, Currency: "CNY",
		Resources: []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions: []string{"order.create", "quote.read"}, Description: "M2 verification",
	}
	specDig, _ := spec.Digest()

	makeChain := func(mode, taskID, g0ID, g1ID, g2ID, rootDID, rootCredID string, rootPriv *ecdsa.PrivateKey) (api.Task, map[string]api.Grant, []string) {
		tRec := api.Task{
			Bound: api.Bound{DeploymentID: depID}, ID: taskID, Creator: didU, CreatorCredential: credU.ID, CreatorKeyVersion: 1,
			Domain: "A", Mode: mode, Resource: resID, Digest: specDig, Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
		}
		g0C := GrantClaims{
			ID: g0ID, SchemaVersion: SchemaVersion, DeploymentID: depID, RootID: g0ID, TaskID: taskID, AuthorizationMode: mode,
			PrincipalDomain: "A", ResourceID: resID, Issuer: rootDID, Grantee: didU, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
			IssuerCredentialID: rootCredID, GranteeCredentialID: credU.ID, Resources: spec.Resources, Actions: spec.Actions,
			Suppliers: []string{spec.SupplierID}, Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 2,
		}
		g0JWS, g0Dig, _ := SignGrant(rootPriv, rootDID+"#key-1", &g0C)
		g1C := GrantClaims{
			ID: g1ID, SchemaVersion: SchemaVersion, DeploymentID: depID, ParentID: &g0ID, ParentDigest: &g0Dig, RootID: g0ID,
			TaskID: taskID, AuthorizationMode: mode, PrincipalDomain: "A", ResourceID: resID, Issuer: didU, Grantee: didA1,
			IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: credU.ID, GranteeCredentialID: credA1.ID,
			Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{spec.SupplierID}, Aud: "https://c.local",
			Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 1,
		}
		g1JWS, g1Dig, _ := SignGrant(privU, didU+"#key-1", &g1C)
		g2C := GrantClaims{
			ID: g2ID, SchemaVersion: SchemaVersion, DeploymentID: depID, ParentID: &g1ID, ParentDigest: &g1Dig, RootID: g0ID,
			TaskID: taskID, AuthorizationMode: mode, PrincipalDomain: "A", ResourceID: resID, Issuer: didA1, Grantee: didB1,
			IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: credA1.ID, GranteeCredentialID: credB1.ID,
			Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{spec.SupplierID}, Aud: "https://c.local",
			Currency: "CNY", MaxAmountMinor: 100000, NBF: nbf, EXP: exp, RemainingDepth: 0,
		}
		g2JWS, g2Dig, _ := SignGrant(privA1, didA1+"#key-1", &g2C)
		grants := map[string]api.Grant{
			g0ID: {Bound: api.Bound{DeploymentID: depID}, ID: g0ID, Schema: SchemaVersion, Root: g0ID, Task: taskID, Mode: mode, Domain: "A", Resource: resID, Issuer: rootDID, Grantee: didU, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: rootCredID, GranteeCredential: credU.ID, Depth: 2, Digest: g0Dig, Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1}},
			g1ID: {Bound: api.Bound{DeploymentID: depID}, ID: g1ID, Schema: SchemaVersion, Parent: g0ID, ParentDigest: g0Dig, Root: g0ID, Task: taskID, Mode: mode, Domain: "A", Resource: resID, Issuer: didU, Grantee: didA1, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: credU.ID, GranteeCredential: credA1.ID, Depth: 1, Digest: g1Dig, Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1}},
			g2ID: {Bound: api.Bound{DeploymentID: depID}, ID: g2ID, Schema: SchemaVersion, Parent: g1ID, ParentDigest: g1Dig, Root: g0ID, Task: taskID, Mode: mode, Domain: "A", Resource: resID, Issuer: didA1, Grantee: didB1, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: credA1.ID, GranteeCredential: credB1.ID, Depth: 0, Digest: g2Dig, Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1}},
		}
		return tRec, grants, []string{g0JWS, g1JWS, g2JWS}
	}

	rpTaskID, rpG0, rpG1, rpG2 := strings.Repeat("11", 32), strings.Repeat("21", 32), strings.Repeat("22", 32), strings.Repeat("23", 32)
	bmTaskID, bmG0, bmG1, bmG2 := strings.Repeat("31", 32), strings.Repeat("41", 32), strings.Repeat("42", 32), strings.Repeat("43", 32)
	rpTask, rpGrants, rpJWS := makeChain(ModeResourcePreauthorized, rpTaskID, rpG0, rpG1, rpG2, didC, credC.ID, privC)
	bmTask, bmGrants, bmJWS := makeChain(ModeBuyerMandate, bmTaskID, bmG0, bmG1, bmG2, didPA, credPA.ID, privPA)

	allGrants := map[string]api.Grant{}
	for k, v := range rpGrants {
		allGrants[k] = v
	}
	for k, v := range bmGrants {
		allGrants[k] = v
	}
	snap := &SnapshotView{
		Height: 100, Now: now, ClockError: api.ClockError, DeploymentID: depID,
		Root:           api.RootRecord{DID: didT, DocumentDigest: digT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKey: pubT},
		Domains:        map[string]api.Domain{"A": domA, "B": domB, "C": domC},
		Certifications: map[string]api.Certification{certA.ID: certA, certB.ID: certB, certC.ID: certC},
		Identities: map[string]api.Identity{
			didIA: {Bound: api.Bound{DeploymentID: depID}, ID: didIA, Domain: "A", Kind: "ISSUER", DocumentDigest: digIA, KeyID: didIA + "#key-1", KeyVersion: 1, PublicKey: pubIA, Version: api.Version{Status: api.Active, Revision: 1}},
			didU:  {Bound: api.Bound{DeploymentID: depID}, ID: didU, Domain: "A", Kind: "USER", DocumentDigest: digU, KeyID: didU + "#key-1", KeyVersion: 1, PublicKey: pubU, Version: api.Version{Status: api.Active, Revision: 1}},
			didPA: {Bound: api.Bound{DeploymentID: depID}, ID: didPA, Domain: "A", Kind: "SERVICE", DocumentDigest: digPA, KeyID: didPA + "#key-1", KeyVersion: 1, PublicKey: pubPA, Version: api.Version{Status: api.Active, Revision: 1}},
			didA1: {Bound: api.Bound{DeploymentID: depID}, ID: didA1, Domain: "A", Kind: "AGENT", DocumentDigest: digA1, KeyID: didA1 + "#key-1", KeyVersion: 1, PublicKey: pubA1, Version: api.Version{Status: api.Active, Revision: 1}},
			didIB: {Bound: api.Bound{DeploymentID: depID}, ID: didIB, Domain: "B", Kind: "ISSUER", DocumentDigest: digIB, KeyID: didIB + "#key-1", KeyVersion: 1, PublicKey: pubIB, Version: api.Version{Status: api.Active, Revision: 1}},
			didB1: {Bound: api.Bound{DeploymentID: depID}, ID: didB1, Domain: "B", Kind: "AGENT", DocumentDigest: digB1, KeyID: didB1 + "#key-1", KeyVersion: 1, PublicKey: pubB1, Version: api.Version{Status: api.Active, Revision: 1}},
			didUinB: {Bound: api.Bound{DeploymentID: depID}, ID: didUinB, Domain: "B", Kind: "USER", DocumentDigest: digUinB, KeyID: didUinB + "#key-1", KeyVersion: 1, PublicKey: pubUinB, Version: api.Version{Status: api.Active, Revision: 1}},
			didIC: {Bound: api.Bound{DeploymentID: depID}, ID: didIC, Domain: "C", Kind: "ISSUER", DocumentDigest: digIC, KeyID: didIC + "#key-1", KeyVersion: 1, PublicKey: pubIC, Version: api.Version{Status: api.Active, Revision: 1}},
			didC:  {Bound: api.Bound{DeploymentID: depID}, ID: didC, Domain: "C", Kind: "SERVICE", DocumentDigest: digC, KeyID: didC + "#key-1", KeyVersion: 1, PublicKey: pubC, Version: api.Version{Status: api.Active, Revision: 1}},
		},
		Credentials: map[string]api.Credential{
			credPA.ID: credPA, credU.ID: credU, credA1.ID: credA1, credB1.ID: credB1, credUinB.ID: credUinB, credC.ID: credC,
		},
		Tasks:  map[string]api.Task{rpTaskID: rpTask, bmTaskID: bmTask},
		Grants: allGrants,
	}

	nonce, _ := GenerateNonce()
	chal := ChallengeContext{ChallengeID: "m2-ch-1", Nonce: nonce, Audience: "https://c.local", IssuedAt: now.Unix(), ExpiresAt: exp}
	qID := "urn:grad:quote:Q800"

	// 1. RP 2-hop C -> U -> A1 -> B1 succeeds.
	rpPkg := AccessEvidencePackage{
		Request: AccessRequest{
			SchemaVersion: SchemaVersion, DeploymentID: depID, Actor: didB1, PrincipalDomain: "A",
			AuthorizationMode: ModeResourcePreauthorized, TaskID: rpTaskID, Audience: "https://c.local",
			Resource: resID, Action: "order.create", SupplierID: spec.SupplierID, QuoteID: &qID,
			ProductID: spec.ProductID, Quantity: 1, Currency: "CNY", AmountMinor: 80000, IdempotencyKey: "m2-rp-001",
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
	if _, _, err := AssembleAccessEvidencePackage(&rpPkg, sdB1.PresentationPrefix, didB1+"#key-1", privB1, chal, now.Unix(), false); err != nil {
		t.Fatal(err)
	}
	rpRes, err := VerifyAccessEvidencePackage(ctx, &rpPkg, snap, dids, chal)
	if err != nil {
		t.Fatalf("RP 2-hop verify failed: %v", err)
	}
	if rpRes.MinMaxAmountMinor != 100000 || rpRes.RootAuthorityRole != "supplier-service" {
		t.Fatalf("unexpected RP result limits/role: %+v", rpRes)
	}

	// 2. BM 2-hop PA -> U -> A1 -> B1 succeeds with deduplicated TrustPaths (didIA, didIB only).
	bmPkg := AccessEvidencePackage{
		Request: AccessRequest{
			SchemaVersion: SchemaVersion, DeploymentID: depID, Actor: didB1, PrincipalDomain: "A",
			AuthorizationMode: ModeBuyerMandate, TaskID: bmTaskID, Audience: "https://c.local",
			Resource: resID, Action: "order.create", SupplierID: spec.SupplierID, QuoteID: &qID,
			ProductID: spec.ProductID, Quantity: 1, Currency: "CNY", AmountMinor: 80000, IdempotencyKey: "m2-bm-001",
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
	if _, _, err := AssembleAccessEvidencePackage(&bmPkg, sdB1.PresentationPrefix, didB1+"#key-1", privB1, chal, now.Unix(), false); err != nil {
		t.Fatal(err)
	}
	bmRes, err := VerifyAccessEvidencePackage(ctx, &bmPkg, snap, dids, chal)
	if err != nil {
		t.Fatalf("BM 2-hop verify failed: %v", err)
	}
	if bmRes.MinMaxAmountMinor != 100000 || bmRes.RootAuthorityRole != "procurement-authority" {
		t.Fatalf("unexpected BM result limits/role: %+v", bmRes)
	}

	// 3. Clearing Domain A PurchasingAuthority rejects BM with PURCHASING_AUTHORITY_INVALID.
	noPASnap := *snap
	domANoPA := domA
	domANoPA.PurchasingAuthority = ""
	noPASnap.Domains = map[string]api.Domain{"A": domANoPA, "B": domB, "C": domC}
	if _, err := VerifyAccessEvidencePackage(ctx, &bmPkg, &noPASnap, dids, chal); !HasCode(err, ErrCodePurchasingAuthorityInvalid) {
		t.Fatalf("expected PURCHASING_AUTHORITY_INVALID, got %v", err)
	}

	// 4. Suspended ancestor grant G1 rejects with ANCESTOR_INACTIVE.
	suspSnap := *snap
	suspGrants := map[string]api.Grant{}
	for k, v := range allGrants {
		suspGrants[k] = v
	}
	g1Susp := suspGrants[bmG1]
	g1Susp.Status = api.Suspended
	suspGrants[bmG1] = g1Susp
	suspSnap.Grants = suspGrants
	if _, err := VerifyAccessEvidencePackage(ctx, &bmPkg, &suspSnap, dids, chal); !HasCode(err, ErrCodeAncestorInactive) {
		t.Fatalf("expected ANCESTOR_INACTIVE, got %v", err)
	}

	// 5. order.create at 120000 (> G2 100000) defers amount check from VerifyAccessEvidencePackage to gateway executeInTx,
	// whereas quote.read > MaxAmountMinor rejects immediately with AMOUNT_LIMIT_EXCEEDED.
	overPkg := bmPkg
	overPkg.Request.AmountMinor = 120000
	if _, _, err := AssembleAccessEvidencePackage(&overPkg, sdB1.PresentationPrefix, didB1+"#key-1", privB1, chal, now.Unix(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccessEvidencePackage(ctx, &overPkg, snap, dids, chal); err != nil {
		t.Fatalf("expected order.create over-limit check to be deferred to gateway executeInTx, got %v", err)
	}
}
