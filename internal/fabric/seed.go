package fabric

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

type fixtures struct {
	Synthetic     bool   `json:"synthetic"`
	SchemaVersion string `json:"schemaVersion"`
	api.Bound
	Domains        map[string]api.DomainBootstrap `json:"domains"`
	Certifications map[string]api.Certify         `json:"certifications"`
	Identities     map[string]api.Identity        `json:"identities"`
	Credentials    map[string]api.Credential      `json:"credentials"`
	Task           api.Task                       `json:"task"`
	G0             api.Grant                      `json:"g0"`
	G1             api.Grant                      `json:"g1"`
	TaskSpec       protocol.TaskSpec              `json:"taskSpec"`
	DIDDocuments         map[string]string              `json:"didDocuments"`
	PurchasingAuthority  api.PurchasingAuthorityUpdate  `json:"purchasingAuthority,omitempty"`
	IdentityLink         api.IdentityLink               `json:"identityLink,omitempty"`
	IdentityLinkApproval api.IdentityLinkApproval       `json:"identityLinkApproval,omitempty"`
	M2TaskSpec           protocol.TaskSpec              `json:"m2TaskSpec,omitempty"`
	RPTask               api.Task                       `json:"rpTask,omitempty"`
	RPG0                 api.Grant                      `json:"rpG0,omitempty"`
	RPG1                 api.Grant                      `json:"rpG1,omitempty"`
	RPG2                 api.Grant                      `json:"rpG2,omitempty"`
	BMTask               api.Task                       `json:"bmTask,omitempty"`
	BMG0                 api.Grant                      `json:"bmG0,omitempty"`
	BMG1                 api.Grant                      `json:"bmG1,omitempty"`
	BMG2                 api.Grant                      `json:"bmG2,omitempty"`
}

type seedReport struct {
	*fixtures
	Operations []*operation `json:"operations"`
	Scope      string       `json:"scope"`
}

func payload(v any) []byte {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // Only typed, JSON-representable protocol records are passed here.
	}
	return b
}

func (i *instance) fixtures(d *deployment) (*fixtures, error) {
	var f fixtures
	path := i.registryPath("fixtures.json")
	if err := readJSON(path, &f); err == nil {
		if f.DeploymentID != d.DeploymentID || f.Synthetic || f.SchemaVersion != protocol.SchemaVersion {
			return nil, fmt.Errorf("DEPLOYMENT_MISMATCH: fixtures incompatible with verifiable protocol")
		}
		if err := i.ensureProtocolFixtures(d, &f); err != nil {
			return nil, err
		}
		return &f, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	mat, err := i.ensureBootstrapProtocolMaterials(time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if d.Bootstrap.Root.PublicKey != mat.RootPubHex || d.Bootstrap.Root.DocumentDigest != mat.RootDIDDigest {
		return nil, fmt.Errorf("DEPLOYMENT_MISMATCH: bootstrap root materials do not match persisted DID/key")
	}
	privT, err := loadECPrivateKeyPEM(i.privatePath("app", "T.key.pem"))
	if err != nil {
		return nil, err
	}

	bound := api.Bound{DeploymentID: d.DeploymentID}
	now := time.Now().UTC().Truncate(time.Second)
	valid := api.Interval{NBF: now.Add(-time.Hour).Unix(), EXP: now.Add(24 * time.Hour).Unix()}
	vf := time.Unix(valid.NBF, 0).UTC().Format(time.RFC3339)
	vu := time.Unix(valid.EXP, 0).UTC().Format(time.RFC3339)

	f = fixtures{
		Synthetic:      false,
		SchemaVersion:  protocol.SchemaVersion,
		Bound:          bound,
		Domains:        map[string]api.DomainBootstrap{},
		Certifications: map[string]api.Certify{},
		Identities:     map[string]api.Identity{},
		Credentials:    map[string]api.Credential{},
		DIDDocuments:   map[string]string{"did:web:t.local": didRelPath("did:web:t.local")},
	}

	appPrivKeys := make(map[string]*ecdsa.PrivateKey)
	appDIDIndex := map[string]string{"did:web:t.local": didRelPath("did:web:t.local")}
	certJWSByDomain := make(map[string]string, 3)

	makeID := func(role, did, domain, kind string, purposes ...string) (api.Identity, *ecdsa.PrivateKey, error) {
		_, management, _, err := i.role(role)
		if err != nil {
			return api.Identity{}, nil, err
		}
		keyID := did + "#key-1"
		priv, pubHex, docDigest, _, err := i.ensureAppKey(role, did, keyID, purposes...)
		if err != nil {
			return api.Identity{}, nil, err
		}
		appPrivKeys[role] = priv
		appDIDIndex[did] = didRelPath(did)
		f.DIDDocuments[did] = didRelPath(did)
		return api.Identity{
			Bound:             bound,
			ID:                did,
			Domain:            domain,
			Kind:              kind,
			Management:        management,
			DocumentDigest:    docDigest,
			KeyID:             keyID,
			KeyVersion:        1,
			PublicKey:         pubHex,
			AccountCommitment: api.Digest([]byte("grad-auth-account:" + d.DeploymentID + ":" + did)),
		}, priv, nil
	}

	for _, domain := range []string{"A", "B", "C"} {
		domDID := "did:web:" + strings.ToLower(domain) + ".local"
		identity, _, err := makeID("domain"+domain, domDID, domain, "DOMAIN", protocol.KeyPurposeAssertionMethod)
		if err != nil {
			return nil, err
		}
		issuerDID := domDID + ":issuer"
		issuer, _, err := makeID("I"+domain, issuerDID, domain, "ISSUER", protocol.KeyPurposeAssertionMethod)
		if err != nil {
			return nil, err
		}
		_, registrar, _, err := i.role("registrar" + domain)
		if err != nil {
			return nil, err
		}
		certID := "urn:grad:domain-certification:" + domain + "-v1"
		scopes := []protocol.IssuerScope{{
			ID:              issuer.ID,
			AppKeyVersion:   1,
			CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity},
			ClaimNames:      []string{"domain", "role"},
		}}
		certJWS, certDigest, err := protocol.SignDomainAuthorityCredential(privT, d.Bootstrap.Root.KeyID, &protocol.DomainAuthorityCredential{
			Type:             []string{protocol.CredentialTypeVC, protocol.CredentialTypeDomainAuthority},
			ID:               certID,
			DeploymentID:     d.DeploymentID,
			Issuer:           d.Bootstrap.Root.DID,
			Iss:              d.Bootstrap.Root.DID,
			Sub:              identity.ID,
			IssuerKeyVersion: d.Bootstrap.Root.KeyVersion,
			ValidFrom:        vf,
			ValidUntil:       vu,
			NBF:              valid.NBF,
			EXP:              valid.EXP,
			CredentialStatus: protocol.CredentialStatus{ID: certID, Type: protocol.StatusTypeDomainCertification},
			CredentialSubject: protocol.DomainAuthoritySubject{
				ID:              identity.ID,
				DomainID:        domain,
				IdentityIssuers: scopes,
			},
		})
		if err != nil {
			return nil, err
		}
		certJWSByDomain[domain] = certJWS
		if err := writePublicFile(i.registrySubPath("certifications", domain+".jws"), []byte(certJWS)); err != nil {
			return nil, err
		}

		f.Domains[domain] = api.DomainBootstrap{
			Domain:   api.Domain{Bound: bound, ID: domain, DID: identity.ID, Admin: identity.Management, Registrar: registrar},
			Identity: identity,
			Issuers:  []api.Identity{issuer},
		}
		f.Certifications[domain] = api.Certify{
			ExpectedRevision: 1,
			Certification: api.Certification{
				Bound:          bound,
				ID:             certID,
				Domain:         domain,
				RootKeyVersion: d.Bootstrap.Root.KeyVersion,
				Digest:         certDigest,
				Scopes: []api.Scope{{
					ID:         issuer.ID,
					KeyVersion: 1,
					Types:      []string{protocol.CredentialTypeEnterpriseIdentity},
					Claims:     []string{"domain", "role"},
				}},
				Interval: valid,
			},
		}
	}

	sdCreds := make(map[string]*protocol.SignedSDJWTCredential, 6)
	for _, r := range []struct{ role, id, domain, kind, sdRole string }{
		{"U", subjectU, "A", "USER", "procurement-owner"},
		{"PA", "did:web:a.local:pa", "A", "SERVICE", "procurement-authority"},
		{"A1", "did:web:a.local:a1", "A", "AGENT", "procurement-agent"},
		{"alt", "did:web:a.local:other", "A", "USER", "procurement-owner"},
		{"B1", "did:web:b.local:b1", "B", "AGENT", "broker-agent"},
		{"C", subjectC, "C", "SERVICE", "supplier-service"},
	} {
		id, _, err := makeID(r.role, r.id, r.domain, r.kind, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
		if err != nil {
			return nil, err
		}
		f.Identities[r.role] = id

		issuerRec := f.Domains[r.domain].Issuers[0]
		issuerPriv := appPrivKeys["I"+r.domain]
		credID := "urn:grad:credential:" + r.role + "-v1"
		holderJWK, err := protocol.AppPublicKeyToJWK(id.PublicKey)
		if err != nil {
			return nil, err
		}
		signedSD, err := protocol.IssueEnterpriseIdentityCredential(
			issuerPriv,
			issuerRec.KeyID,
			protocol.EnterpriseIdentityCredential{
				Type:             []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
				ID:               credID,
				DeploymentID:     d.DeploymentID,
				Issuer:           issuerRec.ID,
				Iss:              issuerRec.ID,
				Sub:              id.ID,
				IssuerKeyVersion: issuerRec.KeyVersion,
				AppKeyVersion:    id.KeyVersion,
				ValidFrom:        vf,
				ValidUntil:       vu,
				NBF:              valid.NBF,
				EXP:              valid.EXP,
				CredentialStatus: protocol.CredentialStatus{ID: credID, Type: protocol.StatusTypeCredential},
				Cnf:              protocol.ConfirmationKey{JWK: holderJWK},
				CredentialSubject: protocol.SDJWTCredentialSubject{
					ID: id.ID,
				},
			},
			r.domain,
			r.sdRole,
			nil,
		)
		if err != nil {
			return nil, err
		}
		sdCreds[r.role] = signedSD
		if err := writePublicFile(i.registrySubPath("credentials", r.role+".sdjwt"), []byte(signedSD.PresentationPrefix)); err != nil {
			return nil, err
		}
		f.Credentials[r.role] = api.Credential{
			Bound:             bound,
			ID:                credID,
			Issuer:            issuerRec.ID,
			Subject:           id.ID,
			IssuerKeyVersion:  issuerRec.KeyVersion,
			SubjectKeyVersion: id.KeyVersion,
			Type:              protocol.CredentialTypeEnterpriseIdentity,
			ClaimNames:        []string{"domain", "role"},
			Digest:            signedSD.AnchorDigest,
			Interval:          valid,
		}
	}

	if err := i.updateDIDIndex(appDIDIndex); err != nil {
		return nil, err
	}

	taskSpec := protocol.TaskSpec{
		SupplierID:  "urn:grad:supplier:C",
		ProductID:   "urn:grad:product:P1",
		MaxQuantity: 1,
		Currency:    "CNY",
		Resources:   []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:     []string{"order.create", "quote.read"},
		Description: "P1 x 1",
	}
	taskSpecDigest, err := taskSpec.Digest()
	if err != nil {
		return nil, err
	}
	taskSpecJCS, err := protocol.MarshalJCS(taskSpec)
	if err != nil {
		return nil, err
	}
	if err := writePublicFile(i.registrySubPath("taskspec.json"), append(taskSpecJCS, '\n')); err != nil {
		return nil, err
	}
	f.TaskSpec = taskSpec

	f.Task = api.Task{
		Bound:             bound,
		ID:                api.Digest([]byte(d.DeploymentID + "/task")),
		Creator:           subjectU,
		CreatorCredential: f.Credentials["U"].ID,
		CreatorKeyVersion: f.Identities["U"].KeyVersion,
		Domain:            "A",
		Mode:              api.RP,
		Resource:          d.Bootstrap.ResourceID,
		Digest:            taskSpecDigest,
		Interval:          valid,
	}

	// Sign real ES256 Grant JWS for G0 (C -> U) and G1 (U -> A1).
	g0ID := api.Digest([]byte(d.DeploymentID + "/G0"))
	g0Claims := protocol.GrantClaims{
		ID:                  g0ID,
		SchemaVersion:       api.Schema,
		DeploymentID:        d.DeploymentID,
		RootID:              g0ID,
		TaskID:              f.Task.ID,
		AuthorizationMode:   api.RP,
		PrincipalDomain:     "A",
		ResourceID:          f.Task.Resource,
		Issuer:              f.Identities["C"].ID,
		Grantee:             f.Identities["U"].ID,
		IssuerKeyVersion:    f.Identities["C"].KeyVersion,
		GranteeKeyVersion:   f.Identities["U"].KeyVersion,
		IssuerCredentialID:  f.Credentials["C"].ID,
		GranteeCredentialID: f.Credentials["U"].ID,
		Resources:           []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:             []string{"order.create", "quote.read"},
		Suppliers:           []string{"urn:grad:supplier:C"},
		Aud:                 "https://c.local",
		Currency:            "CNY",
		MaxAmountMinor:      100000,
		NBF:                 valid.NBF,
		EXP:                 valid.EXP,
		RemainingDepth:      2,
	}
	g0JWS, g0Digest, err := protocol.SignGrant(appPrivKeys["C"], f.Identities["C"].KeyID, &g0Claims)
	if err != nil {
		return nil, err
	}
	if err := writePublicFile(i.registrySubPath("grants", "g0.jws"), []byte(g0JWS)); err != nil {
		return nil, err
	}
	f.G0 = api.Grant{
		Bound:             bound,
		ID:                g0ID,
		Schema:            api.Schema,
		Root:              g0ID,
		Task:              f.Task.ID,
		Mode:              api.RP,
		Domain:            "A",
		Resource:          f.Task.Resource,
		Issuer:            f.Identities["C"].ID,
		Grantee:           f.Identities["U"].ID,
		IssuerKeyVersion:  f.Identities["C"].KeyVersion,
		GranteeKeyVersion: f.Identities["U"].KeyVersion,
		IssuerCredential:  f.Credentials["C"].ID,
		GranteeCredential: f.Credentials["U"].ID,
		Depth:             2,
		Digest:            g0Digest,
		Interval:          valid,
	}

	g1ID := api.Digest([]byte(d.DeploymentID + "/G1"))
	g1Claims := protocol.GrantClaims{
		ID:                  g1ID,
		SchemaVersion:       api.Schema,
		DeploymentID:        d.DeploymentID,
		ParentID:            &g0ID,
		ParentDigest:        &g0Digest,
		RootID:              g0ID,
		TaskID:              f.Task.ID,
		AuthorizationMode:   api.RP,
		PrincipalDomain:     "A",
		ResourceID:          f.Task.Resource,
		Issuer:              f.Identities["U"].ID,
		Grantee:             f.Identities["A1"].ID,
		IssuerKeyVersion:    f.Identities["U"].KeyVersion,
		GranteeKeyVersion:   f.Identities["A1"].KeyVersion,
		IssuerCredentialID:  f.Credentials["U"].ID,
		GranteeCredentialID: f.Credentials["A1"].ID,
		Resources:           []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:             []string{"order.create", "quote.read"},
		Suppliers:           []string{"urn:grad:supplier:C"},
		Aud:                 "https://c.local",
		Currency:            "CNY",
		MaxAmountMinor:      90000,
		NBF:                 valid.NBF,
		EXP:                 valid.EXP,
		RemainingDepth:      1,
	}
	g1JWS, g1Digest, err := protocol.SignGrant(appPrivKeys["U"], f.Identities["U"].KeyID, &g1Claims)
	if err != nil {
		return nil, err
	}
	if err := writePublicFile(i.registrySubPath("grants", "g1.jws"), []byte(g1JWS)); err != nil {
		return nil, err
	}
	f.G1 = api.Grant{
		Bound:             bound,
		ID:                g1ID,
		Schema:            api.Schema,
		Parent:            g0ID,
		ParentDigest:      g0Digest,
		Root:              g0ID,
		Task:              f.Task.ID,
		Mode:              api.RP,
		Domain:            "A",
		Resource:          f.Task.Resource,
		Issuer:            f.Identities["U"].ID,
		Grantee:           f.Identities["A1"].ID,
		IssuerKeyVersion:  f.Identities["U"].KeyVersion,
		GranteeKeyVersion: f.Identities["A1"].KeyVersion,
		IssuerCredential:  f.Credentials["U"].ID,
		GranteeCredential: f.Credentials["A1"].ID,
		Depth:             1,
		Digest:            g1Digest,
		Interval:          valid,
	}

	// Build and persist sample AccessEvidencePackage + KB-JWT for A1 exercising G0 -> G1.
	nonce, err := protocol.GenerateNonce()
	if err != nil {
		return nil, err
	}
	chal := protocol.ChallengeContext{
		ChallengeID: "sample-" + api.Digest([]byte(d.DeploymentID + "/challenge"))[:16],
		Nonce:       nonce,
		Audience:    "https://c.local",
		IssuedAt:    now.Unix(),
		ExpiresAt:   valid.EXP,
	}
	quoteID := "urn:grad:quote:Q800"
	samplePkg := protocol.AccessEvidencePackage{
		Request: protocol.AccessRequest{
			SchemaVersion:     api.Schema,
			DeploymentID:      d.DeploymentID,
			Actor:             f.Identities["A1"].ID,
			PrincipalDomain:   "A",
			AuthorizationMode: api.RP,
			TaskID:            f.Task.ID,
			Audience:          "https://c.local",
			Resource:          "urn:grad:resource:C:orders",
			Action:            "order.create",
			SupplierID:        "urn:grad:supplier:C",
			QuoteID:           &quoteID,
			ProductID:         "urn:grad:product:P1",
			Quantity:          1,
			Currency:          "CNY",
			AmountMinor:       80000,
			IdempotencyKey:    "seed-sample-order-001",
		},
		TaskSpec: taskSpec,
		AncestorCredentials: []protocol.AncestorCredential{
			{CredentialID: f.Credentials["C"].ID, Presentation: sdCreds["C"].PresentationPrefix},
			{CredentialID: f.Credentials["U"].ID, Presentation: sdCreds["U"].PresentationPrefix},
		},
		Grants: []string{g0JWS, g1JWS},
		TrustPaths: []protocol.TrustPathEntry{
			{Issuer: f.Domains["A"].Issuers[0].ID, DomainCertification: certJWSByDomain["A"]},
			{Issuer: f.Domains["C"].Issuers[0].ID, DomainCertification: certJWSByDomain["C"]},
		},
	}
	bindings, _, err := protocol.AssembleAccessEvidencePackage(
		&samplePkg,
		sdCreds["A1"].PresentationPrefix,
		f.Identities["A1"].KeyID,
		appPrivKeys["A1"],
		chal,
		now.Unix(),
		false,
	)
	if err != nil {
		return nil, err
	}
	sampleFile := EvidenceSample{
		ChallengeID: chal.ChallengeID,
		Nonce:       chal.Nonce,
		Audience:    chal.Audience,
		IssuedAt:    chal.IssuedAt,
		ExpiresAt:   chal.ExpiresAt,
		Bindings:    *bindings,
		Package:     samplePkg,
	}
	if err := writePublicJSON(i.registrySubPath("evidence-sample.json"), sampleFile); err != nil {
		return nil, err
	}
	// Sanity-check that G0/G1 raw digests match anchored strings.
	g0Check := sha256.Sum256([]byte(g0JWS))
	if hex.EncodeToString(g0Check[:]) != f.G0.Digest {
		return nil, fmt.Errorf("internal G0 digest mismatch")
	}

	if err := i.writeUQuoteSample(d, &f, sdCreds["U"].PresentationPrefix, appPrivKeys["U"], certJWSByDomain["C"], g0JWS, now); err != nil {
		return nil, err
	}

	if _, err := i.ensureM2Fixtures(d, &f); err != nil {
		return nil, err
	}

	if err := writePublicJSON(path, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func (i *instance) seed(ctx context.Context, j journal, d *deployment) (*seedReport, error) {
	_, unlock, err := j.lock(ctx, "seed/fixture-generation")
	if err != nil {
		return nil, err
	}
	defer unlock()
	f, err := i.fixtures(d)
	if err != nil {
		return nil, err
	}
	report := &seedReport{fixtures: f, Scope: "D0 verifiable protocol anchors and real Fabric management transactions"}
	write := func(key, role, method string, arg any) error {
		op, err := j.write(ctx, "seed/"+key, role, method, payload(arg))
		if op != nil {
			report.Operations = append(report.Operations, op)
		}
		if err != nil {
			return err
		}
		if op.Status != "CONFIRMED" || op.Commit == nil {
			return fmt.Errorf("seed/%s: %s: %s", key, op.Status, op.Observation)
		}
		return i.awaitEndorsers(ctx, *op.Commit)
	}
	for _, domain := range []string{"A", "B", "C"} {
		if err := write("domain-"+domain, "T", "BootstrapDomain", f.Domains[domain]); err != nil {
			return report, err
		}
		if err := write("cert-"+domain, "T", "CertifyDomain", f.Certifications[domain]); err != nil {
			return report, err
		}
	}
	for _, role := range []string{"U", "PA", "U-in-B", "A1", "alt", "B1", "C"} {
		id, ok := f.Identities[role]
		if !ok {
			continue
		}
		if err := write("identity-"+role, "registrar"+id.Domain, "RegisterIdentity", id); err != nil {
			return report, err
		}
		if err := write("credential-"+role, "I"+id.Domain, "RegisterCredential", f.Credentials[role]); err != nil {
			return report, err
		}
	}
	if cSvc, ok := f.Credentials["C-service"]; ok {
		if err := write("credential-C-service", "IC", "RegisterCredential", cSvc); err != nil {
			return report, err
		}
	}
	if f.PurchasingAuthority.DomainID != "" {
		rp, err := i.peer("c", "read")
		if err != nil {
			return report, err
		}
		domA, err := ledgerRecord[api.Domain](ctx, rp, "domain", "A")
		rp.close()
		if err != nil {
			return report, err
		}
		if domA.PurchasingAuthority != f.PurchasingAuthority.PurchasingAuthority {
			paUpdate := f.PurchasingAuthority
			paUpdate.ExpectedRevision = domA.Revision
			opKey := "domain-A-pa"
			if domA.Revision != f.PurchasingAuthority.ExpectedRevision {
				opKey = fmt.Sprintf("domain-A-pa-rev%d", domA.Revision)
			}
			if err := write(opKey, "domainA", "SetPurchasingAuthority", paUpdate); err != nil {
				return report, err
			}
		}
	}
	if f.IdentityLink.ID != "" {
		if err := write("link-propose", "registrarA", "ProposeIdentityLink", f.IdentityLink); err != nil {
			return report, err
		}
		if err := write("link-approve", "registrarB", "ApproveIdentityLink", f.IdentityLinkApproval); err != nil {
			return report, err
		}
	}
	for _, r := range []struct {
		name, role, method string
		input              any
	}{
		{"task", "U", "RegisterTask", f.Task},
		{"G0", "C", "RegisterGrant", f.G0},
		{"G1", "U", "RegisterGrant", f.G1},
	} {
		if err := write(r.name, r.role, r.method, r.input); err != nil {
			return report, err
		}
	}
	if f.RPTask.ID != "" {
		for _, r := range []struct {
			name, role, method string
			input              any
		}{
			{"rp-task", "U", "RegisterTask", f.RPTask},
			{"rp-G0", "C", "RegisterGrant", f.RPG0},
			{"rp-G1", "U", "RegisterGrant", f.RPG1},
			{"rp-G2", "A1", "RegisterGrant", f.RPG2},
			{"bm-task", "U", "RegisterTask", f.BMTask},
			{"bm-G0", "PA", "RegisterGrant", f.BMG0},
			{"bm-G1", "U", "RegisterGrant", f.BMG1},
			{"bm-G2", "A1", "RegisterGrant", f.BMG2},
		} {
			if err := write(r.name, r.role, r.method, r.input); err != nil {
				return report, err
			}
		}
	}
	if err := i.syncMaterialOutboxes(ctx, j, d, f, report); err != nil {
		return report, err
	}
	return report, writePublicJSON(i.registryPath("seed.json"), report)
}

func (i *instance) ensureProtocolFixtures(d *deployment, f *fixtures) error {
	updated := false
	bound := api.Bound{DeploymentID: d.DeploymentID}

	if _, hasPA := f.Identities["PA"]; !hasPA {
		_, management, _, err := i.role("PA")
		if err != nil {
			return err
		}
		paDID := "did:web:a.local:pa"
		paKeyID := paDID + "#key-1"
		paPriv, pubHex, docDigest, _, err := i.ensureAppKey("PA", paDID, paKeyID, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
		_ = paPriv
		if err != nil {
			return err
		}
		if err := i.updateDIDIndex(map[string]string{paDID: didRelPath(paDID)}); err != nil {
			return err
		}
		f.DIDDocuments[paDID] = didRelPath(paDID)
		paID := api.Identity{
			Bound:             bound,
			ID:                paDID,
			Domain:            "A",
			Kind:              "SERVICE",
			Management:        management,
			DocumentDigest:    docDigest,
			KeyID:             paKeyID,
			KeyVersion:        1,
			PublicKey:         pubHex,
			AccountCommitment: api.Digest([]byte("grad-auth-account:" + d.DeploymentID + ":" + paDID)),
		}
		f.Identities["PA"] = paID

		iaPriv, err := loadECPrivateKeyPEM(i.privatePath("app", "IA.key.pem"))
		if err != nil {
			return err
		}
		iaRec := f.Domains["A"].Issuers[0]
		valid := f.Certifications["A"].Certification.Interval
		vf := time.Unix(valid.NBF, 0).UTC().Format(time.RFC3339)
		vu := time.Unix(valid.EXP, 0).UTC().Format(time.RFC3339)
		credID := "urn:grad:credential:PA-v1"
		holderJWK, err := protocol.AppPublicKeyToJWK(paID.PublicKey)
		if err != nil {
			return err
		}
		signedSD, err := protocol.IssueEnterpriseIdentityCredential(
			iaPriv,
			iaRec.KeyID,
			protocol.EnterpriseIdentityCredential{
				Type:              []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
				ID:                credID,
				DeploymentID:      d.DeploymentID,
				Issuer:            iaRec.ID,
				Iss:               iaRec.ID,
				Sub:               paID.ID,
				IssuerKeyVersion:  iaRec.KeyVersion,
				AppKeyVersion:     paID.KeyVersion,
				ValidFrom:         vf,
				ValidUntil:        vu,
				NBF:               valid.NBF,
				EXP:               valid.EXP,
				CredentialStatus:  protocol.CredentialStatus{ID: credID, Type: protocol.StatusTypeCredential},
				Cnf:               protocol.ConfirmationKey{JWK: holderJWK},
				CredentialSubject: protocol.SDJWTCredentialSubject{ID: paID.ID},
			},
			"A",
			"procurement-authority",
			nil,
		)
		if err != nil {
			return err
		}
		if err := writePublicFile(i.registrySubPath("credentials", "PA.sdjwt"), []byte(signedSD.PresentationPrefix)); err != nil {
			return err
		}
		f.Credentials["PA"] = api.Credential{
			Bound:             bound,
			ID:                credID,
			Issuer:            iaRec.ID,
			Subject:           paID.ID,
			IssuerKeyVersion:  iaRec.KeyVersion,
			SubjectKeyVersion: paID.KeyVersion,
			Type:              protocol.CredentialTypeEnterpriseIdentity,
			ClaimNames:        []string{"domain", "role"},
			Digest:            signedSD.AnchorDigest,
			Interval:          valid,
		}
		updated = true
	}

	if _, hasCSvc := f.Credentials["C-service"]; !hasCSvc {
		cSDBytes, err := os.ReadFile(i.registrySubPath("credentials", "C.sdjwt"))
		if err == nil && !strings.Contains(string(cSDBytes), "supplier-service") {
			cID := f.Identities["C"]
			icRec := f.Domains["C"].Issuers[0]
			icPriv, err := loadECPrivateKeyPEM(i.privatePath("app", "IC.key.pem"))
			if err != nil {
				return err
			}
			icPub, _, err := protocol.ParseAppPublicKey(icRec.PublicKey)
			if err != nil {
				return err
			}
			vc, err := protocol.VerifySDJWTCredential(string(cSDBytes), icPub, icRec.KeyID, cID.PublicKey, false)
			if err == nil && vc.Role != "supplier-service" {
				valid := f.Certifications["C"].Certification.Interval
				vf := time.Unix(valid.NBF, 0).UTC().Format(time.RFC3339)
				vu := time.Unix(valid.EXP, 0).UTC().Format(time.RFC3339)
				credID := "urn:grad:credential:C-service-v1"
				holderJWK, err := protocol.AppPublicKeyToJWK(cID.PublicKey)
				if err != nil {
					return err
				}
				signedSD, err := protocol.IssueEnterpriseIdentityCredential(
					icPriv,
					icRec.KeyID,
					protocol.EnterpriseIdentityCredential{
						Type:              []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
						ID:                credID,
						DeploymentID:      d.DeploymentID,
						Issuer:            icRec.ID,
						Iss:               icRec.ID,
						Sub:               cID.ID,
						IssuerKeyVersion:  icRec.KeyVersion,
						AppKeyVersion:     cID.KeyVersion,
						ValidFrom:         vf,
						ValidUntil:        vu,
						NBF:               valid.NBF,
						EXP:               valid.EXP,
						CredentialStatus:  protocol.CredentialStatus{ID: credID, Type: protocol.StatusTypeCredential},
						Cnf:               protocol.ConfirmationKey{JWK: holderJWK},
						CredentialSubject: protocol.SDJWTCredentialSubject{ID: cID.ID},
					},
					"C",
					"supplier-service",
					nil,
				)
				if err != nil {
					return err
				}
				if err := writePublicFile(i.registrySubPath("credentials", "C-service.sdjwt"), []byte(signedSD.PresentationPrefix)); err != nil {
					return err
				}
				f.Credentials["C-service"] = api.Credential{
					Bound:             bound,
					ID:                credID,
					Issuer:            icRec.ID,
					Subject:           cID.ID,
					IssuerKeyVersion:  icRec.KeyVersion,
					SubjectKeyVersion: cID.KeyVersion,
					Type:              protocol.CredentialTypeEnterpriseIdentity,
					ClaimNames:        []string{"domain", "role"},
					Digest:            signedSD.AnchorDigest,
					Interval:          valid,
				}
				updated = true
			}
		}
	}

	if _, err := os.Stat(i.registrySubPath("u-quote-sample.json")); os.IsNotExist(err) {
		uPriv, err := loadECPrivateKeyPEM(i.privatePath("app", "U.key.pem"))
		if err != nil {
			return err
		}
		uSD, err := os.ReadFile(i.registrySubPath("credentials", "U.sdjwt"))
		if err != nil {
			return err
		}
		cCert, err := os.ReadFile(i.registrySubPath("certifications", "C.jws"))
		if err != nil {
			return err
		}
		g0Raw, err := os.ReadFile(i.registrySubPath("grants", "g0.jws"))
		if err != nil {
			return err
		}
		if err := i.writeUQuoteSample(d, f, string(uSD), uPriv, string(cCert), string(g0Raw), time.Now().UTC().Truncate(time.Second)); err != nil {
			return err
		}
	}

	m2Updated, err := i.ensureM2Fixtures(d, f)
	if err != nil {
		return err
	}
	if updated || m2Updated {
		return writePublicJSON(i.registryPath("fixtures.json"), f)
	}
	return nil
}

func (i *instance) ensureM2Fixtures(d *deployment, f *fixtures) (bool, error) {
	updated := false
	bound := api.Bound{DeploymentID: d.DeploymentID}

	if _, ok := f.Identities["U-in-B"]; !ok {
		_, management, _, err := i.role("U-in-B")
		if err != nil {
			return false, err
		}
		uInBDID := "did:web:b.local:u-in-b"
		uInBKeyID := uInBDID + "#key-1"
		_, pubHex, docDigest, _, err := i.ensureAppKey("U-in-B", uInBDID, uInBKeyID, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
		if err != nil {
			return false, err
		}
		if err := i.updateDIDIndex(map[string]string{uInBDID: didRelPath(uInBDID)}); err != nil {
			return false, err
		}
		f.DIDDocuments[uInBDID] = didRelPath(uInBDID)
		uInBID := api.Identity{
			Bound:             bound,
			ID:                uInBDID,
			Domain:            "B",
			Kind:              "USER",
			Management:        management,
			DocumentDigest:    docDigest,
			KeyID:             uInBKeyID,
			KeyVersion:        1,
			PublicKey:         pubHex,
			AccountCommitment: api.Digest([]byte("grad-auth-account:" + d.DeploymentID + ":" + uInBDID)),
		}
		f.Identities["U-in-B"] = uInBID

		ibPriv, err := loadECPrivateKeyPEM(i.privatePath("app", "IB.key.pem"))
		if err != nil {
			return false, err
		}
		ibRec := f.Domains["B"].Issuers[0]
		valid := f.Certifications["B"].Certification.Interval
		vf := time.Unix(valid.NBF, 0).UTC().Format(time.RFC3339)
		vu := time.Unix(valid.EXP, 0).UTC().Format(time.RFC3339)
		credID := "urn:grad:credential:U-in-B-v1"
		holderJWK, err := protocol.AppPublicKeyToJWK(uInBID.PublicKey)
		if err != nil {
			return false, err
		}
		signedSD, err := protocol.IssueEnterpriseIdentityCredential(
			ibPriv,
			ibRec.KeyID,
			protocol.EnterpriseIdentityCredential{
				Type:              []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
				ID:                credID,
				DeploymentID:      d.DeploymentID,
				Issuer:            ibRec.ID,
				Iss:               ibRec.ID,
				Sub:               uInBID.ID,
				IssuerKeyVersion:  ibRec.KeyVersion,
				AppKeyVersion:     uInBID.KeyVersion,
				ValidFrom:         vf,
				ValidUntil:        vu,
				NBF:               valid.NBF,
				EXP:               valid.EXP,
				CredentialStatus:  protocol.CredentialStatus{ID: credID, Type: protocol.StatusTypeCredential},
				Cnf:               protocol.ConfirmationKey{JWK: holderJWK},
				CredentialSubject: protocol.SDJWTCredentialSubject{ID: uInBID.ID},
			},
			"B",
			"procurement-owner",
			nil,
		)
		if err != nil {
			return false, err
		}
		if err := writePublicFile(i.registrySubPath("credentials", "U-in-B.sdjwt"), []byte(signedSD.PresentationPrefix)); err != nil {
			return false, err
		}
		f.Credentials["U-in-B"] = api.Credential{
			Bound:             bound,
			ID:                credID,
			Issuer:            ibRec.ID,
			Subject:           uInBID.ID,
			IssuerKeyVersion:  ibRec.KeyVersion,
			SubjectKeyVersion: uInBID.KeyVersion,
			Type:              protocol.CredentialTypeEnterpriseIdentity,
			ClaimNames:        []string{"domain", "role"},
			Digest:            signedSD.AnchorDigest,
			Interval:          valid,
		}
		updated = true
	}

	if f.PurchasingAuthority.DomainID == "" {
		f.PurchasingAuthority = api.PurchasingAuthorityUpdate{
			Bound:               bound,
			DomainID:            "A",
			PurchasingAuthority: f.Identities["PA"].ID,
			ExpectedRevision:    2,
		}
		updated = true
	}

	if f.IdentityLink.ID == "" {
		uID := f.Identities["U"]
		uInBID := f.Identities["U-in-B"]
		valid := f.Certifications["A"].Certification.Interval
		uPriv, err := loadECPrivateKeyPEM(i.privatePath("app", "U.key.pem"))
		if err != nil {
			return false, err
		}
		uInBPriv, err := loadECPrivateKeyPEM(i.privatePath("app", "U-in-B.key.pem"))
		if err != nil {
			return false, err
		}
		linkID := "urn:grad:link:U-UinB"
		proposal := protocol.IdentityLinkProposal{
			DeploymentID:            d.DeploymentID,
			ExpiresAt:               valid.EXP,
			ID:                      linkID,
			ProposedAt:              valid.NBF,
			SourceAccountCommitment: uID.AccountCommitment,
			SourceDomain:            uID.Domain,
			SourceKeyID:             uID.KeyID,
			SourceKeyVersion:        uID.KeyVersion,
			SourceSubject:           uID.ID,
			TargetAccountCommitment: uInBID.AccountCommitment,
			TargetDomain:            uInBID.Domain,
			TargetKeyID:             uInBID.KeyID,
			TargetKeyVersion:        uInBID.KeyVersion,
			TargetSubject:           uInBID.ID,
		}
		bundle, err := protocol.SignIdentityLinkProofBundle(proposal, uPriv, uInBPriv)
		if err != nil {
			return false, err
		}
		propDigest := bundle.ProposalDigest
		f.IdentityLink = api.IdentityLink{
			Bound:                   bound,
			ID:                      linkID,
			SourceDomain:            uID.Domain,
			SourceSubject:           uID.ID,
			SourceKeyVersion:        uID.KeyVersion,
			SourceAccountCommitment: uID.AccountCommitment,
			TargetDomain:            uInBID.Domain,
			TargetSubject:           uInBID.ID,
			TargetKeyVersion:        uInBID.KeyVersion,
			TargetAccountCommitment: uInBID.AccountCommitment,
			ProposalDigest:          propDigest,
			ProposedAt:              valid.NBF,
			ExpiresAt:               valid.EXP,
		}
		f.IdentityLinkApproval = api.IdentityLinkApproval{
			Bound:            bound,
			ID:               linkID,
			ProposalDigest:   propDigest,
			ExpectedRevision: 1,
			ApprovedAt:       valid.NBF,
		}
		updated = true
	}

	if f.RPTask.ID == "" || f.BMTask.ID == "" {
		valid := f.Task.Interval
		spec := protocol.TaskSpec{
			SupplierID:  "urn:grad:supplier:C",
			ProductID:   "urn:grad:product:P1",
			MaxQuantity: 2,
			Currency:    "CNY",
			Resources:   []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
			Actions:     []string{"order.create", "quote.read"},
			Description: "M2 dual-root procurement",
		}
		specDigest, err := spec.Digest()
		if err != nil {
			return false, err
		}
		f.M2TaskSpec = spec

		uPriv, err := loadECPrivateKeyPEM(i.privatePath("app", "U.key.pem"))
		if err != nil {
			return false, err
		}
		a1Priv, err := loadECPrivateKeyPEM(i.privatePath("app", "A1.key.pem"))
		if err != nil {
			return false, err
		}
		cPriv, err := loadECPrivateKeyPEM(i.privatePath("app", "C.key.pem"))
		if err != nil {
			return false, err
		}
		paPriv, err := loadECPrivateKeyPEM(i.privatePath("app", "PA.key.pem"))
		if err != nil {
			return false, err
		}

		cCredID := f.Credentials["C"].ID
		if cSvc, ok := f.Credentials["C-service"]; ok && cSvc.ID != "" {
			cCredID = cSvc.ID
		}
		uID := f.Identities["U"]
		a1ID := f.Identities["A1"]
		b1ID := f.Identities["B1"]
		cID := f.Identities["C"]
		paID := f.Identities["PA"]

		build2Hop := func(prefix, mode string, rootIssuer api.Identity, rootCredID string, rootPriv *ecdsa.PrivateKey) (api.Task, api.Grant, api.Grant, api.Grant, error) {
			taskID := api.Digest([]byte(d.DeploymentID + "/m2/" + prefix + "/task"))
			task := api.Task{
				Bound:             bound,
				ID:                taskID,
				Creator:           uID.ID,
				CreatorCredential: f.Credentials["U"].ID,
				CreatorKeyVersion: uID.KeyVersion,
				Domain:            "A",
				Mode:              mode,
				Resource:          d.Bootstrap.ResourceID,
				Digest:            specDigest,
				Interval:          valid,
			}
			signOne := func(id string, parentID, parentDigest *string, rootID string, iss, gr api.Identity, issCred, grCred string, maxAmt, depth int64, priv *ecdsa.PrivateKey, file string) (api.Grant, string, error) {
				claims := protocol.GrantClaims{
					ID:                  id,
					SchemaVersion:       api.Schema,
					DeploymentID:        d.DeploymentID,
					ParentID:            parentID,
					ParentDigest:        parentDigest,
					RootID:              rootID,
					TaskID:              taskID,
					AuthorizationMode:   mode,
					PrincipalDomain:     "A",
					ResourceID:          d.Bootstrap.ResourceID,
					Issuer:              iss.ID,
					Grantee:             gr.ID,
					IssuerKeyVersion:    iss.KeyVersion,
					GranteeKeyVersion:   gr.KeyVersion,
					IssuerCredentialID:  issCred,
					GranteeCredentialID: grCred,
					Resources:           spec.Resources,
					Actions:             spec.Actions,
					Suppliers:           []string{spec.SupplierID},
					Aud:                 "https://c.local",
					Currency:            spec.Currency,
					MaxAmountMinor:      maxAmt,
					NBF:                 valid.NBF,
					EXP:                 valid.EXP,
					RemainingDepth:      depth,
				}
				jws, dig, err := protocol.SignGrant(priv, iss.KeyID, &claims)
				if err != nil {
					return api.Grant{}, "", err
				}
				if err := writePublicFile(i.registrySubPath("grants", file), []byte(jws)); err != nil {
					return api.Grant{}, "", err
				}
				parentVal, parentDigVal := "", ""
				if parentID != nil {
					parentVal = *parentID
				}
				if parentDigest != nil {
					parentDigVal = *parentDigest
				}
				return api.Grant{
					Bound:             bound,
					ID:                id,
					Schema:            api.Schema,
					Parent:            parentVal,
					ParentDigest:      parentDigVal,
					Root:              rootID,
					Task:              taskID,
					Mode:              mode,
					Domain:            "A",
					Resource:          d.Bootstrap.ResourceID,
					Issuer:            iss.ID,
					Grantee:           gr.ID,
					IssuerKeyVersion:  iss.KeyVersion,
					GranteeKeyVersion: gr.KeyVersion,
					IssuerCredential:  issCred,
					GranteeCredential: grCred,
					Depth:             uint8(depth),
					Digest:            dig,
					Interval:          valid,
				}, dig, nil
			}
			g0ID := api.Digest([]byte(d.DeploymentID + "/m2/" + prefix + "/G0"))
			g0, g0Dig, err := signOne(g0ID, nil, nil, g0ID, rootIssuer, uID, rootCredID, f.Credentials["U"].ID, 500000, 2, rootPriv, prefix+"_g0.jws")
			if err != nil {
				return api.Task{}, api.Grant{}, api.Grant{}, api.Grant{}, err
			}
			g1ID := api.Digest([]byte(d.DeploymentID + "/m2/" + prefix + "/G1"))
			g1, g1Dig, err := signOne(g1ID, &g0ID, &g0Dig, g0ID, uID, a1ID, f.Credentials["U"].ID, f.Credentials["A1"].ID, 500000, 1, uPriv, prefix+"_g1.jws")
			if err != nil {
				return api.Task{}, api.Grant{}, api.Grant{}, api.Grant{}, err
			}
			g2ID := api.Digest([]byte(d.DeploymentID + "/m2/" + prefix + "/G2"))
			g2, _, err := signOne(g2ID, &g1ID, &g1Dig, g0ID, a1ID, b1ID, f.Credentials["A1"].ID, f.Credentials["B1"].ID, 100000, 0, a1Priv, prefix+"_g2.jws")
			if err != nil {
				return api.Task{}, api.Grant{}, api.Grant{}, api.Grant{}, err
			}
			return task, g0, g1, g2, nil
		}

		rpTask, rpG0, rpG1, rpG2, err := build2Hop("rp", api.RP, cID, cCredID, cPriv)
		if err != nil {
			return false, err
		}
		bmTask, bmG0, bmG1, bmG2, err := build2Hop("bm", api.BM, paID, f.Credentials["PA"].ID, paPriv)
		if err != nil {
			return false, err
		}
		f.RPTask, f.RPG0, f.RPG1, f.RPG2 = rpTask, rpG0, rpG1, rpG2
		f.BMTask, f.BMG0, f.BMG1, f.BMG2 = bmTask, bmG0, bmG1, bmG2
		updated = true
	}
	return updated, nil
}

func (i *instance) writeUQuoteSample(
	d *deployment,
	f *fixtures,
	uPresentationPrefix string,
	uPriv *ecdsa.PrivateKey,
	certCJWS string,
	g0JWS string,
	now time.Time,
) error {
	nonce, err := protocol.GenerateNonce()
	if err != nil {
		return err
	}
	chal := protocol.ChallengeContext{
		ChallengeID: "u-quote-" + api.Digest([]byte(d.DeploymentID + "/u-quote-challenge"))[:16],
		Nonce:       nonce,
		Audience:    "https://c.local",
		IssuedAt:    now.Unix(),
		ExpiresAt:   f.G0.EXP,
	}
	cSDPath := i.registrySubPath("credentials", "C.sdjwt")
	cSDBytes, err := os.ReadFile(cSDPath)
	if err != nil {
		return err
	}
	pkg := protocol.AccessEvidencePackage{
		Request: protocol.AccessRequest{
			SchemaVersion:     api.Schema,
			DeploymentID:      d.DeploymentID,
			Actor:             f.Identities["U"].ID,
			PrincipalDomain:   "A",
			AuthorizationMode: api.RP,
			TaskID:            f.Task.ID,
			Audience:          "https://c.local",
			Resource:          "urn:grad:resource:C:quotes",
			Action:            "quote.read",
			SupplierID:        "urn:grad:supplier:C",
			QuoteID:           nil,
			ProductID:         "urn:grad:product:P1",
			Quantity:          1,
			Currency:          "CNY",
			AmountMinor:       0,
			IdempotencyKey:    "seed-sample-u-quote-001",
		},
		TaskSpec: f.TaskSpec,
		AncestorCredentials: []protocol.AncestorCredential{
			{CredentialID: f.Credentials["C"].ID, Presentation: string(cSDBytes)},
		},
		Grants: []string{g0JWS},
		TrustPaths: []protocol.TrustPathEntry{
			{Issuer: f.Domains["C"].Issuers[0].ID, DomainCertification: certCJWS},
		},
	}
	if certAJWS, err := os.ReadFile(i.registrySubPath("certifications", "A.jws")); err == nil {
		pkg.TrustPaths = append(pkg.TrustPaths, protocol.TrustPathEntry{
			Issuer:              f.Domains["A"].Issuers[0].ID,
			DomainCertification: string(certAJWS),
		})
	}
	bindings, _, err := protocol.AssembleAccessEvidencePackage(
		&pkg,
		uPresentationPrefix,
		f.Identities["U"].KeyID,
		uPriv,
		chal,
		now.Unix(),
		false,
	)
	if err != nil {
		return err
	}
	sampleFile := EvidenceSample{
		ChallengeID: chal.ChallengeID,
		Nonce:       chal.Nonce,
		Audience:    chal.Audience,
		IssuedAt:    chal.IssuedAt,
		ExpiresAt:   chal.ExpiresAt,
		Bindings:    *bindings,
		Package:     pkg,
	}
	return writePublicJSON(i.registrySubPath("u-quote-sample.json"), sampleFile)
}

func (i *instance) syncMaterialOutboxes(ctx context.Context, j journal, d *deployment, f *fixtures, report *seedReport) error {
	ds := NewDeliveryService(j.db)
	now := time.Now().UTC().Unix()
	snap := &protocol.SnapshotView{
		Height:         1,
		Now:            time.Unix(now, 0).UTC(),
		DeploymentID:   d.DeploymentID,
		Root:           d.Bootstrap.Root,
		Domains:        make(map[string]api.Domain),
		Certifications: make(map[string]api.Certification),
		Identities:     make(map[string]api.Identity),
		Credentials:    make(map[string]api.Credential),
		Tasks: map[string]api.Task{
			f.Task.ID: activateTaskSnapshot(f.Task),
		},
		Grants: map[string]api.Grant{
			f.G0.ID: activateGrantSnapshot(f.G0),
			f.G1.ID: activateGrantSnapshot(f.G1),
		},
		Links: map[string]api.IdentityLink{},
	}
	if f.RPTask.ID != "" {
		snap.Tasks[f.RPTask.ID] = activateTaskSnapshot(f.RPTask)
		snap.Grants[f.RPG0.ID] = activateGrantSnapshot(f.RPG0)
		snap.Grants[f.RPG1.ID] = activateGrantSnapshot(f.RPG1)
		snap.Grants[f.RPG2.ID] = activateGrantSnapshot(f.RPG2)
	}
	if f.BMTask.ID != "" {
		snap.Tasks[f.BMTask.ID] = activateTaskSnapshot(f.BMTask)
		snap.Grants[f.BMG0.ID] = activateGrantSnapshot(f.BMG0)
		snap.Grants[f.BMG1.ID] = activateGrantSnapshot(f.BMG1)
		snap.Grants[f.BMG2.ID] = activateGrantSnapshot(f.BMG2)
	}
	for domID, db := range f.Domains {
		dom := db.Domain
		dom.Issuers = []string{db.Issuers[0].ID}
		dom.Certification = f.Certifications[domID].Certification.ID
		if domID == "A" && f.PurchasingAuthority.DomainID == "A" {
			dom.PurchasingAuthority = f.PurchasingAuthority.PurchasingAuthority
		}
		dom.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Domains[domID] = dom

		cert := f.Certifications[domID].Certification
		cert.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Certifications[cert.ID] = cert

		di := db.Identity
		di.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Identities[di.ID] = di

		ii := db.Issuers[0]
		ii.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Identities[ii.ID] = ii
	}
	for role, id := range f.Identities {
		id.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Identities[id.ID] = id
		if cred, ok := f.Credentials[role]; ok {
			cred.Version = api.Version{Status: api.Active, Revision: 1}
			snap.Credentials[cred.ID] = cred
		}
	}
	if cSvc, ok := f.Credentials["C-service"]; ok {
		cSvc.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Credentials[cSvc.ID] = cSvc
	}

	rootPub, _, err := protocol.ParseAppPublicKey(d.Bootstrap.Root.PublicKey)
	if err != nil {
		return err
	}
	icPub, _, err := protocol.ParseAppPublicKey(f.Domains["C"].Issuers[0].PublicKey)
	if err != nil {
		return err
	}
	cPub, _, err := protocol.ParseAppPublicKey(f.Identities["C"].PublicKey)
	if err != nil {
		return err
	}

	opCoords := func(suffix string) (string, int64) {
		for _, op := range report.Operations {
			if op != nil && op.Key == "seed/"+suffix && op.Commit != nil {
				return op.TxID, int64(op.Commit.Number)
			}
		}
		return api.Digest([]byte("seed/" + suffix)), 1
	}

	for _, domID := range []string{"A", "B", "C"} {
		jwsBytes, err := os.ReadFile(i.registrySubPath("certifications", domID+".jws"))
		if err != nil {
			return err
		}
		txID, blockNo := opCoords("cert-" + domID)
		recipients := []string{
			f.Domains[domID].Issuers[0].ID,
			f.Identities["U"].ID,
			f.Identities["PA"].ID,
			f.Identities["A1"].ID,
			f.Identities["B1"].ID,
			f.Identities["C"].ID,
		}
		for _, rec := range recipients {
			if rec == "" {
				continue
			}
			if err := ds.PublishDomainCertification(ctx, snap, rec, domID, string(jwsBytes), rootPub, txID, blockNo, true, now); err != nil {
				return err
			}
			if _, err := ds.SyncCertificationReceipt(ctx, snap, rec, domID, rootPub, now); err != nil {
				return err
			}
		}
	}

	g0Bytes, err := os.ReadFile(i.registrySubPath("grants", "g0.jws"))
	if err != nil {
		return err
	}
	certCBytes, err := os.ReadFile(i.registrySubPath("certifications", "C.jws"))
	if err != nil {
		return err
	}
	cSvcBytes, err := os.ReadFile(i.registrySubPath("credentials", "C-service.sdjwt"))
	if err != nil {
		cSvcBytes, err = os.ReadFile(i.registrySubPath("credentials", "C.sdjwt"))
		if err != nil {
			return err
		}
	}
	g0TxID, g0BlockNo := opCoords("G0")
	pkg := GrantDeliveryPackage{
		DeploymentID:           d.DeploymentID,
		Recipient:              f.Identities["U"].ID,
		GrantID:                f.G0.ID,
		GrantJWS:               string(g0Bytes),
		TaskSpec:               f.TaskSpec,
		ServicePresentation:    string(cSvcBytes),
		DomainCertificationJWS: string(certCBytes),
	}
	if _, err := ds.PublishGrantOutbox(ctx, snap, pkg, rootPub, icPub, cPub, g0TxID, g0BlockNo, true, now); err != nil {
		return err
	}
	if _, _, err := ds.DeliverGrantReceipt(ctx, snap, d.DeploymentID, f.Identities["U"].ID, f.G0.ID, nil, rootPub, icPub, cPub, now); err != nil {
		return err
	}

	if f.RPTask.ID != "" {
		iaPub, _, err := protocol.ParseAppPublicKey(f.Domains["A"].Issuers[0].PublicKey)
		if err != nil {
			return err
		}
		paPub, _, err := protocol.ParseAppPublicKey(f.Identities["PA"].PublicKey)
		if err != nil {
			return err
		}
		uPub, _, err := protocol.ParseAppPublicKey(f.Identities["U"].PublicKey)
		if err != nil {
			return err
		}
		a1Pub, _, err := protocol.ParseAppPublicKey(f.Identities["A1"].PublicKey)
		if err != nil {
			return err
		}
		certABytes, err := os.ReadFile(i.registrySubPath("certifications", "A.jws"))
		if err != nil {
			return err
		}
		paSD, err := os.ReadFile(i.registrySubPath("credentials", "PA.sdjwt"))
		if err != nil {
			return err
		}
		uSD, err := os.ReadFile(i.registrySubPath("credentials", "U.sdjwt"))
		if err != nil {
			return err
		}
		a1SD, err := os.ReadFile(i.registrySubPath("credentials", "A1.sdjwt"))
		if err != nil {
			return err
		}
		deliverHop := func(opKey string, g api.Grant, jwsFile string, ancGrants []string, grantorSD []byte, grantorCert []byte, credIssPub, grantorPub *ecdsa.PublicKey) error {
			gBytes, err := os.ReadFile(i.registrySubPath("grants", jwsFile))
			if err != nil {
				return err
			}
			txID, blockNo := opCoords(opKey)
			hopPkg := GrantDeliveryPackage{
				DeploymentID:           d.DeploymentID,
				Recipient:              g.Grantee,
				GrantID:                g.ID,
				GrantJWS:               string(gBytes),
				TaskSpec:               f.M2TaskSpec,
				ServicePresentation:    string(grantorSD),
				DomainCertificationJWS: string(grantorCert),
				AncestorGrants:         ancGrants,
			}
			if _, err := ds.PublishGrantOutbox(ctx, snap, hopPkg, rootPub, credIssPub, grantorPub, txID, blockNo, true, now); err != nil {
				return err
			}
			if _, _, err := ds.DeliverGrantReceipt(ctx, snap, d.DeploymentID, g.Grantee, g.ID, nil, rootPub, credIssPub, grantorPub, now); err != nil {
				return err
			}
			return nil
		}
		rpG0Bytes, err := os.ReadFile(i.registrySubPath("grants", "rp_g0.jws"))
		if err != nil {
			return err
		}
		rpG1Bytes, err := os.ReadFile(i.registrySubPath("grants", "rp_g1.jws"))
		if err != nil {
			return err
		}
		if err := deliverHop("rp-G0", f.RPG0, "rp_g0.jws", nil, cSvcBytes, certCBytes, icPub, cPub); err != nil {
			return err
		}
		if err := deliverHop("rp-G1", f.RPG1, "rp_g1.jws", []string{string(rpG0Bytes)}, uSD, certABytes, iaPub, uPub); err != nil {
			return err
		}
		if err := deliverHop("rp-G2", f.RPG2, "rp_g2.jws", []string{string(rpG0Bytes), string(rpG1Bytes)}, a1SD, certABytes, iaPub, a1Pub); err != nil {
			return err
		}

		bmG0Bytes, err := os.ReadFile(i.registrySubPath("grants", "bm_g0.jws"))
		if err != nil {
			return err
		}
		bmG1Bytes, err := os.ReadFile(i.registrySubPath("grants", "bm_g1.jws"))
		if err != nil {
			return err
		}
		if err := deliverHop("bm-G0", f.BMG0, "bm_g0.jws", nil, paSD, certABytes, iaPub, paPub); err != nil {
			return err
		}
		if err := deliverHop("bm-G1", f.BMG1, "bm_g1.jws", []string{string(bmG0Bytes)}, uSD, certABytes, iaPub, uPub); err != nil {
			return err
		}
		if err := deliverHop("bm-G2", f.BMG2, "bm_g2.jws", []string{string(bmG0Bytes), string(bmG1Bytes)}, a1SD, certABytes, iaPub, a1Pub); err != nil {
			return err
		}
	}
	return nil
}

func activateTaskSnapshot(t api.Task) api.Task {
	t.Version = api.Version{Status: api.Active, Revision: 1}
	return t
}

func activateGrantSnapshot(g api.Grant) api.Grant {
	g.Version = api.Version{Status: api.Active, Revision: 1}
	return g
}
