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
			didC:  {Bound: api.Bound{DeploymentID: depID}, ID: didC, Domain: "C", DocumentDigest: digC, KeyID: didC + "#key-1", KeyVersion: 1, PublicKey: pubC, Version: api.Version{Status: api.Active, Revision: 1}},
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
