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
	DIDDocuments   map[string]string              `json:"didDocuments"`
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

	sdCreds := make(map[string]*protocol.SignedSDJWTCredential, 5)
	for _, r := range []struct{ role, id, domain, kind string }{
		{"U", subjectU, "A", "USER"},
		{"A1", "did:web:a.local:a1", "A", "AGENT"},
		{"alt", "did:web:a.local:other", "A", "USER"},
		{"B1", "did:web:b.local:b1", "B", "AGENT"},
		{"C", subjectC, "C", "SERVICE"},
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
			r.kind,
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
	for _, role := range []string{"U", "A1", "alt", "B1", "C"} {
		id := f.Identities[role]
		if err := write("identity-"+role, "registrar"+id.Domain, "RegisterIdentity", id); err != nil {
			return report, err
		}
		if err := write("credential-"+role, "I"+id.Domain, "RegisterCredential", f.Credentials[role]); err != nil {
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
	return report, writePublicJSON(i.registryPath("seed.json"), report)
}
