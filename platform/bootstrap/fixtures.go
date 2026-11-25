// Package bootstrap assembles top-level protocol fixtures, Fabric seeding,
// controlled material delivery, gateway/wallet/MCP stacks, and the three-domain
// workbench dependency injection composition root.
package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/core/dao"
	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/ledger"
	"grad/protocol"
	"grad/protocol/registry"
)

// EvidenceSample bundles a seeded verifiable AccessEvidencePackage alongside the challenge
// context under which its KB-JWT was minted.
type EvidenceSample struct {
	ChallengeID string                         `json:"challengeId"`
	Nonce       string                         `json:"nonce"`
	Audience    string                         `json:"audience"`
	IssuedAt    int64                          `json:"issuedAt"`
	ExpiresAt   int64                          `json:"expiresAt"`
	Bindings    protocol.PackageBindings       `json:"bindings"`
	Package     protocol.AccessEvidencePackage `json:"package"`
}

// ProcurementPathIDs identifies a procurement task and its three registered grants (G0 -> G1 -> G2).
type ProcurementPathIDs struct {
	Task string `json:"task"`
	G0   string `json:"g0"`
	G1   string `json:"g1"`
	G2   string `json:"g2"`
}

// ProcurementSetup supplies a shared task specification and explicit IDs for both RP and BM root modes.
type ProcurementSetup struct {
	Spec protocol.TaskSpec
	RP   ProcurementPathIDs
	BM   ProcurementPathIDs
}

// Validate checks that Spec is valid and all eight RP/BM task and grant IDs are distinct 64-hex digests.
func (s ProcurementSetup) Validate() error {
	if err := s.Spec.Validate(); err != nil {
		return err
	}
	seen := make(map[string]bool, 8)
	for _, id := range []string{s.RP.Task, s.RP.G0, s.RP.G1, s.RP.G2, s.BM.Task, s.BM.G0, s.BM.G1, s.BM.G2} {
		if !registry.IsDigest(id) || seen[id] {
			return fmt.Errorf("procurement setup requires distinct 64-hex digest IDs")
		}
		seen[id] = true
	}
	return nil
}

// Fixtures captures the verifiable protocol anchors, domains, certifications, identities,
// credentials, tasks, and grant chains generated for a deployment.
type Fixtures struct {
	SchemaVersion string `json:"schemaVersion"`
	registry.Bound
	Domains              map[string]registry.DomainBootstrap `json:"domains"`
	Certifications       map[string]registry.Certify         `json:"certifications"`
	Identities           map[string]registry.Identity        `json:"identities"`
	Credentials          map[string]registry.Credential      `json:"credentials"`
	Task                 registry.Task                       `json:"task"`
	G0                   registry.Grant                      `json:"g0"`
	G1                   registry.Grant                      `json:"g1"`
	TaskSpec             protocol.TaskSpec                   `json:"taskSpec"`
	DIDDocuments         map[string]string                   `json:"didDocuments"`
	PurchasingAuthority  registry.PurchasingAuthorityUpdate  `json:"purchasingAuthority,omitempty"`
	IdentityLink         registry.IdentityLink               `json:"identityLink,omitempty"`
	IdentityLinkApproval registry.IdentityLinkApproval       `json:"identityLinkApproval,omitempty"`
	ProcurementTaskSpec  protocol.TaskSpec                   `json:"procurementTaskSpec"`
	RPTask               registry.Task                       `json:"rpTask,omitempty"`
	RPG0                 registry.Grant                      `json:"rpG0,omitempty"`
	RPG1                 registry.Grant                      `json:"rpG1,omitempty"`
	RPG2                 registry.Grant                      `json:"rpG2,omitempty"`
	BMTask               registry.Task                       `json:"bmTask,omitempty"`
	BMG0                 registry.Grant                      `json:"bmG0,omitempty"`
	BMG1                 registry.Grant                      `json:"bmG1,omitempty"`
	BMG2                 registry.Grant                      `json:"bmG2,omitempty"`
}

// fixtureBody aliases Fixtures under an unexported name so SeedReport embeds its fields
// cleanly in JSON while also exposing a Fixtures() method.
type fixtureBody = Fixtures

// SeedReport summarizes the seeded protocol fixtures and confirmed Fabric operations.
type SeedReport struct {
	*fixtureBody
	Operations []*ledger.Operation `json:"operations"`
	Scope      string              `json:"scope"`
}

// Fixtures returns the underlying Fixtures payload of r.
func (r *SeedReport) Fixtures() *Fixtures {
	if r == nil {
		return nil
	}
	return r.fixtureBody
}

// RegistrationSnapshot builds an active protocol.SnapshotView from r for delivery verification
// or centralized registry preloading.
func (r *SeedReport) RegistrationSnapshot(d *ledger.Deployment) *protocol.SnapshotView {
	if r == nil || r.fixtureBody == nil {
		return nil
	}
	return BuildFixtureSnapshot(d, r.fixtureBody, time.Time{})
}

// LoadFixtures reads and strictly validates <instance>/registry/fixtures.json.
func LoadFixtures(inst *ledger.Instance) (*Fixtures, error) {
	if inst == nil {
		return nil, fmt.Errorf("fabric instance is required")
	}
	raw, err := os.ReadFile(inst.RegistryPath("fixtures.json"))
	if err != nil {
		return nil, err
	}
	var f Fixtures
	if err := protocol.DecodeStrictJSON(raw, &f); err != nil {
		return nil, fmt.Errorf("decode fixtures.json: %w", err)
	}
	if f.SchemaVersion != protocol.SchemaVersion || !registry.IsDigest(f.DeploymentID) {
		return nil, fmt.Errorf("%w: incompatible fixtures schema or deploymentId", ledger.ErrDeploymentMismatch)
	}
	if dep, err := inst.LoadDeployment(); err == nil && dep.DeploymentID != f.DeploymentID {
		return nil, fmt.Errorf("%w: fixtures deploymentId %s != %s", ledger.ErrDeploymentMismatch, f.DeploymentID, dep.DeploymentID)
	}
	return &f, nil
}

// PrepareFixtures loads persisted verifiable fixtures or generates a fresh complete set
// (domains A/B/C, T-signed certifications, 8 actors + SD-JWTs, base RP task/grants,
// dual-root RP/BM 2-hop procurement chains, identity link, PA binding, and sample evidence).
func PrepareFixtures(inst *ledger.Instance, d *ledger.Deployment, setup *ProcurementSetup) (*Fixtures, error) {
	if inst == nil || d == nil {
		return nil, fmt.Errorf("fabric instance and deployment are required")
	}
	if setup != nil {
		if err := setup.Validate(); err != nil {
			return nil, err
		}
	}
	path := inst.RegistryPath("fixtures.json")
	if existing, err := LoadFixtures(inst); err == nil {
		if existing.DeploymentID != d.DeploymentID {
			return nil, fmt.Errorf("%w: fixtures deploymentId mismatch", ledger.ErrDeploymentMismatch)
		}
		if setup != nil {
			specDigest, err := setup.Spec.Digest()
			if err != nil {
				return nil, err
			}
			rp := ProcurementPathIDs{Task: existing.RPTask.ID, G0: existing.RPG0.ID, G1: existing.RPG1.ID, G2: existing.RPG2.ID}
			bm := ProcurementPathIDs{Task: existing.BMTask.ID, G0: existing.BMG0.ID, G1: existing.BMG1.ID, G2: existing.BMG2.ID}
			if rp != setup.RP || bm != setup.BM || existing.RPTask.Digest != specDigest || existing.BMTask.Digest != specDigest {
				return nil, fmt.Errorf("procurement setup differs from persisted fixtures")
			}
		}
		return existing, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	now := time.Now().UTC().Truncate(time.Second)
	mat, err := inst.EnsureBootstrapMaterials(now)
	if err != nil {
		return nil, err
	}
	if d.Bootstrap.Root.PublicKey != mat.RootPubHex || d.Bootstrap.Root.DocumentDigest != mat.RootDIDDigest {
		return nil, fmt.Errorf("%w: bootstrap root materials mismatch persisted DID/key", ledger.ErrDeploymentMismatch)
	}
	privT, err := ledger.LoadECPrivateKeyPEM(inst.PrivatePath("app", "T.key.pem"))
	if err != nil {
		return nil, err
	}

	bound := registry.Bound{DeploymentID: d.DeploymentID}
	valid := registry.Interval{NBF: now.Add(-time.Hour).Unix(), EXP: now.Add(24 * time.Hour).Unix()}
	vf := time.Unix(valid.NBF, 0).UTC().Format(time.RFC3339)
	vu := time.Unix(valid.EXP, 0).UTC().Format(time.RFC3339)

	f := Fixtures{
		SchemaVersion:  protocol.SchemaVersion,
		Bound:          bound,
		Domains:        make(map[string]registry.DomainBootstrap, 3),
		Certifications: make(map[string]registry.Certify, 3),
		Identities:     make(map[string]registry.Identity, 8),
		Credentials:    make(map[string]registry.Credential, 8),
		DIDDocuments:   map[string]string{"did:web:t.local": ledger.DIDRelPath("did:web:t.local")},
	}

	appPrivKeys := make(map[string]*ecdsa.PrivateKey, 16)
	appDIDIndex := map[string]string{"did:web:t.local": ledger.DIDRelPath("did:web:t.local")}
	certJWSByDomain := make(map[string]string, 3)

	makeIdentity := func(role, did, domain, kind string, purposes ...string) (registry.Identity, *ecdsa.PrivateKey, error) {
		_, mgmt, _, err := inst.Role(role)
		if err != nil {
			return registry.Identity{}, nil, err
		}
		keyID := did + "#key-1"
		priv, pubHex, docDigest, _, err := inst.EnsureAppKey(role, did, keyID, purposes...)
		if err != nil {
			return registry.Identity{}, nil, err
		}
		rel := ledger.DIDRelPath(did)
		appPrivKeys[role] = priv
		appDIDIndex[did] = rel
		f.DIDDocuments[did] = rel
		return registry.Identity{
			Bound:             bound,
			ID:                did,
			Domain:            domain,
			Kind:              kind,
			Management:        mgmt,
			DocumentDigest:    docDigest,
			KeyID:             keyID,
			KeyVersion:        1,
			PublicKey:         pubHex,
			AccountCommitment: registry.Digest([]byte("grad-auth-account:" + d.DeploymentID + ":" + did)),
		}, priv, nil
	}

	// 1. Domains A, B, C and T-signed DomainAuthorityCredentials.
	for _, dom := range []string{"A", "B", "C"} {
		domDID := "did:web:" + strings.ToLower(dom) + ".local"
		domID, _, err := makeIdentity("domain"+dom, domDID, dom, "DOMAIN", protocol.KeyPurposeAssertionMethod)
		if err != nil {
			return nil, err
		}
		issuerDID := domDID + ":issuer"
		issuerID, _, err := makeIdentity("I"+dom, issuerDID, dom, "ISSUER", protocol.KeyPurposeAssertionMethod)
		if err != nil {
			return nil, err
		}
		_, registrar, _, err := inst.Role("registrar" + dom)
		if err != nil {
			return nil, err
		}
		certID := "urn:grad:domain-certification:" + dom + "-v1"
		scopes := []registry.IssuerScope{{
			ID:              issuerID.ID,
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
			Sub:              domID.ID,
			IssuerKeyVersion: d.Bootstrap.Root.KeyVersion,
			ValidFrom:        vf,
			ValidUntil:       vu,
			NBF:              valid.NBF,
			EXP:              valid.EXP,
			CredentialStatus: protocol.CredentialStatus{ID: certID, Type: protocol.StatusTypeDomainCertification},
			CredentialSubject: protocol.DomainAuthoritySubject{
				ID:              domID.ID,
				DomainID:        dom,
				IdentityIssuers: scopes,
			},
		})
		if err != nil {
			return nil, err
		}
		certJWSByDomain[dom] = certJWS
		if err := ledger.WritePublicFile(inst.RegistryPath("certifications", dom+".jws"), []byte(certJWS)); err != nil {
			return nil, err
		}
		f.Domains[dom] = registry.DomainBootstrap{
			Domain:   registry.Domain{Bound: bound, ID: dom, DID: domID.ID, Admin: domID.Management, Registrar: registrar, Issuers: []string{issuerID.ID}},
			Identity: domID,
			Issuers:  []registry.Identity{issuerID},
		}
		f.Certifications[dom] = registry.Certify{
			ExpectedRevision: 1,
			Certification: registry.Certification{
				Bound:          bound,
				ID:             certID,
				Domain:         dom,
				RootKeyVersion: d.Bootstrap.Root.KeyVersion,
				Digest:         certDigest,
				Scopes:         scopes,
				Interval:       valid,
			},
		}
	}

	// 2. All ordinary identities and standardized SD-JWT credentials (C uses key "C" with role "supplier-service").
	sdCreds := make(map[string]*protocol.SignedSDJWTCredential, 8)
	actorSpecs := []struct{ role, did, domain, kind, sdRole string }{
		{"U", ledger.SubjectU, "A", "USER", "procurement-owner"},
		{"PA", "did:web:a.local:pa", "A", "SERVICE", "procurement-authority"},
		{"U-in-B", "did:web:b.local:u-in-b", "B", "USER", "procurement-owner"},
		{"A1", "did:web:a.local:a1", "A", "AGENT", "procurement-agent"},
		{"alt", "did:web:a.local:other", "A", "USER", "procurement-owner"},
		{"B1", "did:web:b.local:b1", "B", "AGENT", "broker-agent"},
		{"B2", "did:web:b.local:b2", "B", "AGENT", "broker-agent"},
		{"C", ledger.SubjectC, "C", "SERVICE", "supplier-service"},
	}
	for _, r := range actorSpecs {
		idRec, priv, err := makeIdentity(r.role, r.did, r.domain, r.kind, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
		if err != nil {
			return nil, err
		}
		f.Identities[r.role] = idRec

		issuerRec := f.Domains[r.domain].Issuers[0]
		issuerPriv := appPrivKeys["I"+r.domain]
		credID := "urn:grad:credential:" + r.role + "-v1"
		holderJWK, err := protocol.JWKFromPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		signedSD, err := protocol.IssueEnterpriseIdentityCredential(
			issuerPriv,
			issuerRec.KeyID,
			protocol.EnterpriseIdentityCredential{
				Type:              []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
				ID:                credID,
				DeploymentID:      d.DeploymentID,
				Issuer:            issuerRec.ID,
				Iss:               issuerRec.ID,
				Sub:               idRec.ID,
				IssuerKeyVersion:  issuerRec.KeyVersion,
				AppKeyVersion:     idRec.KeyVersion,
				ValidFrom:         vf,
				ValidUntil:        vu,
				NBF:               valid.NBF,
				EXP:               valid.EXP,
				CredentialStatus:  protocol.CredentialStatus{ID: credID, Type: protocol.StatusTypeCredential},
				Cnf:               protocol.ConfirmationKey{JWK: holderJWK},
				CredentialSubject: protocol.SDJWTCredentialSubject{ID: idRec.ID},
			},
			r.domain,
			r.sdRole,
			nil,
		)
		if err != nil {
			return nil, err
		}
		sdCreds[r.role] = signedSD
		if err := ledger.WritePublicFile(inst.RegistryPath("credentials", r.role+".sdjwt"), []byte(signedSD.PresentationPrefix)); err != nil {
			return nil, err
		}
		f.Credentials[r.role] = registry.Credential{
			Bound:             bound,
			ID:                credID,
			Issuer:            issuerRec.ID,
			Subject:           idRec.ID,
			IssuerKeyVersion:  issuerRec.KeyVersion,
			SubjectKeyVersion: idRec.KeyVersion,
			Type:              protocol.CredentialTypeEnterpriseIdentity,
			ClaimNames:        []string{"domain", "role"},
			Digest:            signedSD.AnchorDigest,
			Interval:          valid,
		}
	}

	if err := inst.UpdateDIDIndex(appDIDIndex); err != nil {
		return nil, err
	}

	// 3. Domain A PurchasingAuthority binding and cross-domain U <-> U-in-B IdentityLink.
	f.PurchasingAuthority = registry.PurchasingAuthorityUpdate{
		Bound:               bound,
		DomainID:            "A",
		PurchasingAuthority: f.Identities["PA"].ID,
		ExpectedRevision:    2,
	}
	if err := initIdentityLink(&f, d.DeploymentID, bound, valid, appPrivKeys["U"], appPrivKeys["U-in-B"]); err != nil {
		return nil, err
	}

	// 4. Base single-hop RP Task/G0/G1 and signed evidence samples.
	if err := initBaseRPSamples(inst, d, &f, bound, valid, now, appPrivKeys, sdCreds, certJWSByDomain); err != nil {
		return nil, err
	}

	// 5. Dual-root 2-hop procurement paths (RP: C -> U -> A1 -> B1, BM: PA -> U -> A1 -> B1).
	if err := initDualModeProcurement(inst, d, &f, bound, valid, setup, appPrivKeys); err != nil {
		return nil, err
	}

	if err := ledger.WritePublicJSON(path, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func initIdentityLink(
	f *Fixtures,
	depID string,
	bound registry.Bound,
	valid registry.Interval,
	uPriv, uInBPriv *ecdsa.PrivateKey,
) error {
	uID := f.Identities["U"]
	uInBID := f.Identities["U-in-B"]
	linkID := "urn:grad:link:U-UinB"
	proposal := protocol.IdentityLinkProposal{
		DeploymentID:            depID,
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
		return err
	}
	f.IdentityLink = registry.IdentityLink{
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
		ProposalDigest:          bundle.ProposalDigest,
		ProposedAt:              valid.NBF,
		ExpiresAt:               valid.EXP,
	}
	f.IdentityLinkApproval = registry.IdentityLinkApproval{
		Bound:            bound,
		ID:               linkID,
		ProposalDigest:   bundle.ProposalDigest,
		ExpectedRevision: 1,
		ApprovedAt:       valid.NBF,
	}
	return nil
}

func initBaseRPSamples(
	inst *ledger.Instance,
	d *ledger.Deployment,
	f *Fixtures,
	bound registry.Bound,
	valid registry.Interval,
	now time.Time,
	appPrivKeys map[string]*ecdsa.PrivateKey,
	sdCreds map[string]*protocol.SignedSDJWTCredential,
	certJWSByDomain map[string]string,
) error {
	taskSpec := protocol.TaskSpec{
		SupplierID:  "urn:grad:supplier:C",
		ProductID:   "urn:grad:product:P1",
		MaxQuantity: 1,
		Currency:    "CNY",
		Resources:   []string{protocol.ResourceOrders, protocol.ResourceQuotes},
		Actions:     []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
		Description: "P1 x 1",
	}
	taskSpecDigest, err := taskSpec.Digest()
	if err != nil {
		return err
	}
	taskSpecJCS, err := protocol.MarshalJCS(taskSpec)
	if err != nil {
		return err
	}
	if err := ledger.WritePublicFile(inst.RegistryPath("taskspec.json"), append(taskSpecJCS, '\n')); err != nil {
		return err
	}
	f.TaskSpec = taskSpec
	f.Task = registry.Task{
		Bound:             bound,
		ID:                registry.Digest([]byte(d.DeploymentID + "/task")),
		Creator:           ledger.SubjectU,
		CreatorCredential: f.Credentials["U"].ID,
		CreatorKeyVersion: f.Identities["U"].KeyVersion,
		Domain:            "A",
		Mode:              registry.RP,
		Resource:          d.Bootstrap.ResourceID,
		Digest:            taskSpecDigest,
		Interval:          valid,
	}

	g0ID := registry.Digest([]byte(d.DeploymentID + "/G0"))
	g0JWS, g0, err := signAnchoredGrant(inst, d, bound, valid, grantSignSpec{
		id:          g0ID,
		rootID:      g0ID,
		taskID:      f.Task.ID,
		mode:        registry.RP,
		issuer:      f.Identities["C"],
		grantee:     f.Identities["U"],
		issuerCred:  f.Credentials["C"].ID,
		granteeCred: f.Credentials["U"].ID,
		spec:        taskSpec,
		maxAmount:   100000,
		depth:       2,
		priv:        appPrivKeys["C"],
		filename:    "g0.jws",
	})
	if err != nil {
		return err
	}
	f.G0 = g0

	g1ID := registry.Digest([]byte(d.DeploymentID + "/G1"))
	g1JWS, g1, err := signAnchoredGrant(inst, d, bound, valid, grantSignSpec{
		id:           g1ID,
		parentID:     &g0ID,
		parentDigest: &g0.Digest,
		rootID:       g0ID,
		taskID:       f.Task.ID,
		mode:         registry.RP,
		issuer:       f.Identities["U"],
		grantee:      f.Identities["A1"],
		issuerCred:   f.Credentials["U"].ID,
		granteeCred:  f.Credentials["A1"].ID,
		spec:         taskSpec,
		maxAmount:    90000,
		depth:        1,
		priv:         appPrivKeys["U"],
		filename:     "g1.jws",
	})
	if err != nil {
		return err
	}
	f.G1 = g1

	sum := sha256.Sum256([]byte(g0JWS))
	if hex.EncodeToString(sum[:]) != f.G0.Digest {
		return fmt.Errorf("internal G0 digest mismatch")
	}

	// Sample AccessEvidencePackage for A1 order.create over G0 -> G1.
	nonce, err := protocol.GenerateNonce()
	if err != nil {
		return err
	}
	chal := protocol.ChallengeContext{
		ChallengeID: "sample-" + registry.Digest([]byte(d.DeploymentID + "/challenge"))[:16],
		Nonce:       nonce,
		Audience:    "https://c.local",
		IssuedAt:    now.Unix(),
		ExpiresAt:   valid.EXP,
	}
	quoteID := "urn:grad:quote:Q800"
	samplePkg := protocol.AccessEvidencePackage{
		Request: protocol.AccessRequest{
			SchemaVersion:     protocol.SchemaVersion,
			DeploymentID:      d.DeploymentID,
			Actor:             f.Identities["A1"].ID,
			PrincipalDomain:   "A",
			AuthorizationMode: registry.RP,
			TaskID:            f.Task.ID,
			Audience:          "https://c.local",
			Resource:          protocol.ResourceOrders,
			Action:            protocol.ActionOrderCreate,
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
		return err
	}
	if err := ledger.WritePublicJSON(inst.RegistryPath("evidence-sample.json"), EvidenceSample{
		ChallengeID: chal.ChallengeID,
		Nonce:       chal.Nonce,
		Audience:    chal.Audience,
		IssuedAt:    chal.IssuedAt,
		ExpiresAt:   chal.ExpiresAt,
		Bindings:    *bindings,
		Package:     samplePkg,
	}); err != nil {
		return err
	}

	// Sample AccessEvidencePackage for U quote.read over G0.
	uNonce, err := protocol.GenerateNonce()
	if err != nil {
		return err
	}
	uChal := protocol.ChallengeContext{
		ChallengeID: "u-quote-" + registry.Digest([]byte(d.DeploymentID + "/u-quote-challenge"))[:16],
		Nonce:       uNonce,
		Audience:    "https://c.local",
		IssuedAt:    now.Unix(),
		ExpiresAt:   f.G0.EXP,
	}
	uPkg := protocol.AccessEvidencePackage{
		Request: protocol.AccessRequest{
			SchemaVersion:     protocol.SchemaVersion,
			DeploymentID:      d.DeploymentID,
			Actor:             f.Identities["U"].ID,
			PrincipalDomain:   "A",
			AuthorizationMode: registry.RP,
			TaskID:            f.Task.ID,
			Audience:          "https://c.local",
			Resource:          protocol.ResourceQuotes,
			Action:            protocol.ActionQuoteRead,
			SupplierID:        "urn:grad:supplier:C",
			QuoteID:           nil,
			ProductID:         "urn:grad:product:P1",
			Quantity:          1,
			Currency:          "CNY",
			AmountMinor:       0,
			IdempotencyKey:    "seed-sample-u-quote-001",
		},
		TaskSpec: taskSpec,
		AncestorCredentials: []protocol.AncestorCredential{
			{CredentialID: f.Credentials["C"].ID, Presentation: sdCreds["C"].PresentationPrefix},
		},
		Grants: []string{g0JWS},
		TrustPaths: []protocol.TrustPathEntry{
			{Issuer: f.Domains["A"].Issuers[0].ID, DomainCertification: certJWSByDomain["A"]},
			{Issuer: f.Domains["C"].Issuers[0].ID, DomainCertification: certJWSByDomain["C"]},
		},
	}
	uBindings, _, err := protocol.AssembleAccessEvidencePackage(
		&uPkg,
		sdCreds["U"].PresentationPrefix,
		f.Identities["U"].KeyID,
		appPrivKeys["U"],
		uChal,
		now.Unix(),
		false,
	)
	if err != nil {
		return err
	}
	return ledger.WritePublicJSON(inst.RegistryPath("u-quote-sample.json"), EvidenceSample{
		ChallengeID: uChal.ChallengeID,
		Nonce:       uChal.Nonce,
		Audience:    uChal.Audience,
		IssuedAt:    uChal.IssuedAt,
		ExpiresAt:   uChal.ExpiresAt,
		Bindings:    *uBindings,
		Package:     uPkg,
	})
}

func initDualModeProcurement(
	inst *ledger.Instance,
	d *ledger.Deployment,
	f *Fixtures,
	bound registry.Bound,
	valid registry.Interval,
	setup *ProcurementSetup,
	appPrivKeys map[string]*ecdsa.PrivateKey,
) error {
	spec := protocol.TaskSpec{
		SupplierID:  "urn:grad:supplier:C",
		ProductID:   "urn:grad:product:P1",
		MaxQuantity: 2,
		Currency:    "CNY",
		Resources:   []string{protocol.ResourceOrders, protocol.ResourceQuotes},
		Actions:     []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
		Description: "Dual-root procurement",
	}
	deriveIDs := func(prefix string) ProcurementPathIDs {
		ns := d.DeploymentID + "/procurement/" + prefix + "/"
		return ProcurementPathIDs{
			Task: registry.Digest([]byte(ns + "task")),
			G0:   registry.Digest([]byte(ns + "G0")),
			G1:   registry.Digest([]byte(ns + "G1")),
			G2:   registry.Digest([]byte(ns + "G2")),
		}
	}
	rpIDs, bmIDs := deriveIDs("rp"), deriveIDs("bm")
	if setup != nil {
		spec, rpIDs, bmIDs = setup.Spec, setup.RP, setup.BM
	}
	specDigest, err := spec.Digest()
	if err != nil {
		return err
	}
	f.ProcurementTaskSpec = spec

	buildPath := func(prefix, mode string, ids ProcurementPathIDs, rootIssuer registry.Identity, rootCredID string, rootPriv *ecdsa.PrivateKey) (registry.Task, registry.Grant, registry.Grant, registry.Grant, error) {
		task := registry.Task{
			Bound:             bound,
			ID:                ids.Task,
			Creator:           f.Identities["U"].ID,
			CreatorCredential: f.Credentials["U"].ID,
			CreatorKeyVersion: f.Identities["U"].KeyVersion,
			Domain:            "A",
			Mode:              mode,
			Resource:          d.Bootstrap.ResourceID,
			Digest:            specDigest,
			Interval:          valid,
		}
		_, g0, err := signAnchoredGrant(inst, d, bound, valid, grantSignSpec{
			id:          ids.G0,
			rootID:      ids.G0,
			taskID:      ids.Task,
			mode:        mode,
			issuer:      rootIssuer,
			grantee:     f.Identities["U"],
			issuerCred:  rootCredID,
			granteeCred: f.Credentials["U"].ID,
			spec:        spec,
			maxAmount:   500000,
			depth:       2,
			priv:        rootPriv,
			filename:    prefix + "_g0.jws",
		})
		if err != nil {
			return registry.Task{}, registry.Grant{}, registry.Grant{}, registry.Grant{}, err
		}
		_, g1, err := signAnchoredGrant(inst, d, bound, valid, grantSignSpec{
			id:           ids.G1,
			parentID:     &g0.ID,
			parentDigest: &g0.Digest,
			rootID:       ids.G0,
			taskID:       ids.Task,
			mode:         mode,
			issuer:       f.Identities["U"],
			grantee:      f.Identities["A1"],
			issuerCred:   f.Credentials["U"].ID,
			granteeCred:  f.Credentials["A1"].ID,
			spec:         spec,
			maxAmount:    500000,
			depth:        1,
			priv:         appPrivKeys["U"],
			filename:     prefix + "_g1.jws",
		})
		if err != nil {
			return registry.Task{}, registry.Grant{}, registry.Grant{}, registry.Grant{}, err
		}
		_, g2, err := signAnchoredGrant(inst, d, bound, valid, grantSignSpec{
			id:           ids.G2,
			parentID:     &g1.ID,
			parentDigest: &g1.Digest,
			rootID:       ids.G0,
			taskID:       ids.Task,
			mode:         mode,
			issuer:       f.Identities["A1"],
			grantee:      f.Identities["B1"],
			issuerCred:   f.Credentials["A1"].ID,
			granteeCred:  f.Credentials["B1"].ID,
			spec:         spec,
			maxAmount:    100000,
			depth:        0,
			priv:         appPrivKeys["A1"],
			filename:     prefix + "_g2.jws",
		})
		if err != nil {
			return registry.Task{}, registry.Grant{}, registry.Grant{}, registry.Grant{}, err
		}
		return task, g0, g1, g2, nil
	}

	f.RPTask, f.RPG0, f.RPG1, f.RPG2, err = buildPath("rp", registry.RP, rpIDs, f.Identities["C"], f.Credentials["C"].ID, appPrivKeys["C"])
	if err != nil {
		return err
	}
	f.BMTask, f.BMG0, f.BMG1, f.BMG2, err = buildPath("bm", registry.BM, bmIDs, f.Identities["PA"], f.Credentials["PA"].ID, appPrivKeys["PA"])
	return err
}

type grantSignSpec struct {
	id           string
	parentID     *string
	parentDigest *string
	rootID       string
	taskID       string
	mode         string
	issuer       registry.Identity
	grantee      registry.Identity
	issuerCred   string
	granteeCred  string
	spec         protocol.TaskSpec
	maxAmount    int64
	depth        int64
	priv         *ecdsa.PrivateKey
	filename     string
}

func signAnchoredGrant(
	inst *ledger.Instance,
	d *ledger.Deployment,
	bound registry.Bound,
	valid registry.Interval,
	gs grantSignSpec,
) (string, registry.Grant, error) {
	claims := protocol.GrantClaims{
		ID:                  gs.id,
		SchemaVersion:       protocol.SchemaVersion,
		DeploymentID:        d.DeploymentID,
		ParentID:            gs.parentID,
		ParentDigest:        gs.parentDigest,
		RootID:              gs.rootID,
		TaskID:              gs.taskID,
		AuthorizationMode:   gs.mode,
		PrincipalDomain:     "A",
		ResourceID:          d.Bootstrap.ResourceID,
		Issuer:              gs.issuer.ID,
		Grantee:             gs.grantee.ID,
		IssuerKeyVersion:    gs.issuer.KeyVersion,
		GranteeKeyVersion:   gs.grantee.KeyVersion,
		IssuerCredentialID:  gs.issuerCred,
		GranteeCredentialID: gs.granteeCred,
		Resources:           slices.Clone(gs.spec.Resources),
		Actions:             slices.Clone(gs.spec.Actions),
		Suppliers:           []string{gs.spec.SupplierID},
		Aud:                 "https://c.local",
		Currency:            gs.spec.Currency,
		MaxAmountMinor:      gs.maxAmount,
		NBF:                 valid.NBF,
		EXP:                 valid.EXP,
		RemainingDepth:      gs.depth,
	}
	jws, digest, err := protocol.SignGrant(gs.priv, gs.issuer.KeyID, &claims)
	if err != nil {
		return "", registry.Grant{}, err
	}
	if err := ledger.WritePublicFile(inst.RegistryPath("grants", gs.filename), []byte(jws)); err != nil {
		return "", registry.Grant{}, err
	}
	var parentID, parentDigest string
	if gs.parentID != nil {
		parentID = *gs.parentID
	}
	if gs.parentDigest != nil {
		parentDigest = *gs.parentDigest
	}
	return jws, registry.Grant{
		Bound:             bound,
		ID:                gs.id,
		Schema:            registry.Schema,
		Parent:            parentID,
		ParentDigest:      parentDigest,
		Root:              gs.rootID,
		Task:              gs.taskID,
		Mode:              gs.mode,
		Domain:            "A",
		Resource:          d.Bootstrap.ResourceID,
		Issuer:            gs.issuer.ID,
		Grantee:           gs.grantee.ID,
		IssuerKeyVersion:  gs.issuer.KeyVersion,
		GranteeKeyVersion: gs.grantee.KeyVersion,
		IssuerCredential:  gs.issuerCred,
		GranteeCredential: gs.granteeCred,
		Depth:             uint8(gs.depth),
		Digest:            digest,
		Interval:          valid,
	}, nil
}

// Seed registers the default protocol fixtures on Fabric and syncs outbox/receipt deliveries.
func Seed(ctx context.Context, inst *ledger.Instance, db *pgxpool.Pool, d *ledger.Deployment) (*SeedReport, error) {
	return seedInternal(ctx, inst, db, d, nil)
}

// SeedProcurement registers protocol fixtures using an explicit ProcurementSetup and syncs deliveries.
func SeedProcurement(ctx context.Context, inst *ledger.Instance, db *pgxpool.Pool, d *ledger.Deployment, setup ProcurementSetup) (*SeedReport, error) {
	return seedInternal(ctx, inst, db, d, &setup)
}

func seedInternal(ctx context.Context, inst *ledger.Instance, db *pgxpool.Pool, d *ledger.Deployment, setup *ProcurementSetup) (*SeedReport, error) {
	if inst == nil || db == nil || d == nil {
		return nil, fmt.Errorf("instance, database pool, and deployment are required")
	}
	if err := dao.Up(ctx, db); err != nil {
		return nil, err
	}
	j := ledger.NewJournal(inst, db, d.DeploymentID)
	_, unlock, err := j.Lock(ctx, "seed/fixture-generation")
	if err != nil {
		return nil, err
	}
	defer unlock()

	f, err := PrepareFixtures(inst, d, setup)
	if err != nil {
		return nil, err
	}
	report := &SeedReport{
		fixtureBody: f,
		Scope:       "Verifiable protocol anchors and Fabric management transactions",
	}
	writeOp := func(key, role, method string, arg any) error {
		raw, err := json.Marshal(arg)
		if err != nil {
			return err
		}
		op, err := j.Write(ctx, "seed/"+key, role, method, raw)
		if op != nil {
			report.Operations = append(report.Operations, op)
		}
		if err != nil {
			return err
		}
		if op.Status != "CONFIRMED" || op.Commit == nil || op.Commit.Code != "VALID" {
			return fmt.Errorf("seed/%s: %s: %s", key, op.Status, op.Observation)
		}
		return inst.AwaitEndorsers(ctx, *op.Commit)
	}

	for _, dom := range []string{"A", "B", "C"} {
		if err := writeOp("domain-"+dom, "T", "BootstrapDomain", f.Domains[dom]); err != nil {
			return report, err
		}
		if err := writeOp("cert-"+dom, "T", "CertifyDomain", f.Certifications[dom]); err != nil {
			return report, err
		}
	}
	for _, role := range []string{"U", "PA", "U-in-B", "A1", "alt", "B1", "B2", "C"} {
		id, ok := f.Identities[role]
		if !ok {
			continue
		}
		if err := writeOp("identity-"+role, "registrar"+id.Domain, "RegisterIdentity", id); err != nil {
			return report, err
		}
		if err := writeOp("credential-"+role, "I"+id.Domain, "RegisterCredential", f.Credentials[role]); err != nil {
			return report, err
		}
	}
	if f.PurchasingAuthority.DomainID != "" {
		rp, err := inst.Peer("c", "read")
		if err != nil {
			return report, err
		}
		domA, err := ledger.ReadLedgerRecord[registry.Domain](ctx, rp, "domain", "A")
		rp.Close()
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
			if err := writeOp(opKey, "domainA", "SetPurchasingAuthority", paUpdate); err != nil {
				return report, err
			}
		}
	}
	if f.IdentityLink.ID != "" {
		if err := writeOp("link-propose", "registrarA", "ProposeIdentityLink", f.IdentityLink); err != nil {
			return report, err
		}
		if err := writeOp("link-approve", "registrarB", "ApproveIdentityLink", f.IdentityLinkApproval); err != nil {
			return report, err
		}
	}
	for _, step := range []struct {
		name, role, method string
		input              any
	}{
		{"task", "U", "RegisterTask", f.Task},
		{"G0", "C", "RegisterGrant", f.G0},
		{"G1", "U", "RegisterGrant", f.G1},
	} {
		if err := writeOp(step.name, step.role, step.method, step.input); err != nil {
			return report, err
		}
	}
	if f.RPTask.ID != "" {
		for _, step := range []struct {
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
			if err := writeOp(step.name, step.role, step.method, step.input); err != nil {
				return report, err
			}
		}
	}

	if err := SyncSeedDeliveries(ctx, inst, db, d, report); err != nil {
		return report, err
	}
	return report, ledger.WritePublicJSON(inst.RegistryPath("seed.json"), report)
}

// SyncSeedDeliveries verifies and persists seeded domain certifications and grant delivery
// packages into certification_outbox, certification_receipts, grant_outbox, and wallet_receipts.
func SyncSeedDeliveries(ctx context.Context, inst *ledger.Instance, db *pgxpool.Pool, d *ledger.Deployment, report *SeedReport) error {
	if inst == nil || db == nil || d == nil || report == nil || report.Fixtures() == nil {
		return fmt.Errorf("instance, db, deployment, and seed report with fixtures are required")
	}
	if err := dao.Up(ctx, db); err != nil {
		return err
	}
	f := report.Fixtures()
	ds := domreg.NewDeliveryService(db, d.DeploymentID)
	now := time.Now().UTC().Unix()
	snap := BuildFixtureSnapshot(d, f, time.Unix(now, 0).UTC())

	rootPub, err := protocol.ParseAppPublicKey(d.Bootstrap.Root.PublicKey)
	if err != nil {
		return err
	}
	icPub, err := protocol.ParseAppPublicKey(f.Domains["C"].Issuers[0].PublicKey)
	if err != nil {
		return err
	}
	cPub, err := protocol.ParseAppPublicKey(f.Identities["C"].PublicKey)
	if err != nil {
		return err
	}

	opCoords := func(suffix string) (string, int64) {
		for _, op := range report.Operations {
			if op != nil && op.Key == "seed/"+suffix && op.Commit != nil {
				return op.TxID, int64(op.Commit.Number)
			}
		}
		return registry.Digest([]byte("seed/" + suffix)), 1
	}

	for _, domID := range []string{"A", "B", "C"} {
		jwsBytes, err := os.ReadFile(inst.RegistryPath("certifications", domID+".jws"))
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
			f.Identities["B2"].ID,
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

	g0Bytes, err := os.ReadFile(inst.RegistryPath("grants", "g0.jws"))
	if err != nil {
		return err
	}
	certCBytes, err := os.ReadFile(inst.RegistryPath("certifications", "C.jws"))
	if err != nil {
		return err
	}
	cSDBytes, err := os.ReadFile(inst.RegistryPath("credentials", "C.sdjwt"))
	if err != nil {
		return err
	}
	g0TxID, g0BlockNo := opCoords("G0")
	basePkg := domreg.GrantDeliveryPackage{
		DeploymentID:           d.DeploymentID,
		Recipient:              f.Identities["U"].ID,
		GrantID:                f.G0.ID,
		GrantJWS:               string(g0Bytes),
		TaskSpec:               f.TaskSpec,
		ServicePresentation:    string(cSDBytes),
		DomainCertificationJWS: string(certCBytes),
	}
	if _, err := ds.PublishGrantOutbox(ctx, snap, basePkg, rootPub, icPub, cPub, g0TxID, g0BlockNo, true, now); err != nil {
		return err
	}
	if _, _, err := ds.DeliverGrantReceipt(ctx, snap, d.DeploymentID, f.Identities["U"].ID, f.G0.ID, nil, rootPub, icPub, cPub, now); err != nil {
		return err
	}

	if f.RPTask.ID == "" {
		return nil
	}

	iaPub, err := protocol.ParseAppPublicKey(f.Domains["A"].Issuers[0].PublicKey)
	if err != nil {
		return err
	}
	paPub, err := protocol.ParseAppPublicKey(f.Identities["PA"].PublicKey)
	if err != nil {
		return err
	}
	uPub, err := protocol.ParseAppPublicKey(f.Identities["U"].PublicKey)
	if err != nil {
		return err
	}
	a1Pub, err := protocol.ParseAppPublicKey(f.Identities["A1"].PublicKey)
	if err != nil {
		return err
	}
	certABytes, err := os.ReadFile(inst.RegistryPath("certifications", "A.jws"))
	if err != nil {
		return err
	}
	paSD, err := os.ReadFile(inst.RegistryPath("credentials", "PA.sdjwt"))
	if err != nil {
		return err
	}
	uSD, err := os.ReadFile(inst.RegistryPath("credentials", "U.sdjwt"))
	if err != nil {
		return err
	}
	a1SD, err := os.ReadFile(inst.RegistryPath("credentials", "A1.sdjwt"))
	if err != nil {
		return err
	}

	deliverHop := func(opKey string, g registry.Grant, jwsFile string, ancGrants []string, grantorSD, grantorCert []byte, credIssPub, grantorPub *ecdsa.PublicKey) error {
		gBytes, err := os.ReadFile(inst.RegistryPath("grants", jwsFile))
		if err != nil {
			return err
		}
		txID, blockNo := opCoords(opKey)
		hopPkg := domreg.GrantDeliveryPackage{
			DeploymentID:           d.DeploymentID,
			Recipient:              g.Grantee,
			GrantID:                g.ID,
			GrantJWS:               string(gBytes),
			TaskSpec:               f.ProcurementTaskSpec,
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

	rpG0Bytes, err := os.ReadFile(inst.RegistryPath("grants", "rp_g0.jws"))
	if err != nil {
		return err
	}
	rpG1Bytes, err := os.ReadFile(inst.RegistryPath("grants", "rp_g1.jws"))
	if err != nil {
		return err
	}
	if err := deliverHop("rp-G0", f.RPG0, "rp_g0.jws", nil, cSDBytes, certCBytes, icPub, cPub); err != nil {
		return err
	}
	if err := deliverHop("rp-G1", f.RPG1, "rp_g1.jws", []string{string(rpG0Bytes)}, uSD, certABytes, iaPub, uPub); err != nil {
		return err
	}
	if err := deliverHop("rp-G2", f.RPG2, "rp_g2.jws", []string{string(rpG0Bytes), string(rpG1Bytes)}, a1SD, certABytes, iaPub, a1Pub); err != nil {
		return err
	}

	bmG0Bytes, err := os.ReadFile(inst.RegistryPath("grants", "bm_g0.jws"))
	if err != nil {
		return err
	}
	bmG1Bytes, err := os.ReadFile(inst.RegistryPath("grants", "bm_g1.jws"))
	if err != nil {
		return err
	}
	if err := deliverHop("bm-G0", f.BMG0, "bm_g0.jws", nil, paSD, certABytes, iaPub, paPub); err != nil {
		return err
	}
	if err := deliverHop("bm-G1", f.BMG1, "bm_g1.jws", []string{string(bmG0Bytes)}, uSD, certABytes, iaPub, uPub); err != nil {
		return err
	}
	return deliverHop("bm-G2", f.BMG2, "bm_g2.jws", []string{string(bmG0Bytes), string(bmG1Bytes)}, a1SD, certABytes, iaPub, a1Pub)
}

// BuildFixtureSnapshot constructs the shared active protocol.SnapshotView for delivery
// verification and centralized registry initialization.
func BuildFixtureSnapshot(d *ledger.Deployment, f *Fixtures, at time.Time) *protocol.SnapshotView {
	activateTask := func(t registry.Task) registry.Task {
		t.Version = registry.Version{Status: registry.Active, Revision: 1}
		return t
	}
	activateGrant := func(g registry.Grant) registry.Grant {
		g.Version = registry.Version{Status: registry.Active, Revision: 1}
		return g
	}

	snap := &protocol.SnapshotView{
		Height:         0,
		Now:            at,
		ClockError:     registry.ClockError,
		DeploymentID:   d.DeploymentID,
		Root:           d.Bootstrap.Root,
		Domains:        make(map[string]registry.Domain, len(f.Domains)),
		Certifications: make(map[string]registry.Certification, len(f.Certifications)),
		Identities:     make(map[string]registry.Identity, len(f.Identities)+len(f.Domains)*2),
		Credentials:    make(map[string]registry.Credential, len(f.Credentials)),
		Tasks: map[string]registry.Task{
			f.Task.ID: activateTask(f.Task),
		},
		Grants: map[string]registry.Grant{
			f.G0.ID: activateGrant(f.G0),
			f.G1.ID: activateGrant(f.G1),
		},
		Links: map[string]registry.IdentityLink{},
	}
	if f.RPTask.ID != "" {
		snap.Tasks[f.RPTask.ID] = activateTask(f.RPTask)
		snap.Grants[f.RPG0.ID] = activateGrant(f.RPG0)
		snap.Grants[f.RPG1.ID] = activateGrant(f.RPG1)
		snap.Grants[f.RPG2.ID] = activateGrant(f.RPG2)
	}
	if f.BMTask.ID != "" {
		snap.Tasks[f.BMTask.ID] = activateTask(f.BMTask)
		snap.Grants[f.BMG0.ID] = activateGrant(f.BMG0)
		snap.Grants[f.BMG1.ID] = activateGrant(f.BMG1)
		snap.Grants[f.BMG2.ID] = activateGrant(f.BMG2)
	}
	for domID, db := range f.Domains {
		dom := db.Domain
		dom.Issuers = []string{db.Issuers[0].ID}
		dom.Certification = f.Certifications[domID].Certification.ID
		if domID == "A" && f.PurchasingAuthority.DomainID == "A" {
			dom.PurchasingAuthority = f.PurchasingAuthority.PurchasingAuthority
		}
		dom.Version = registry.Version{Status: registry.Active, Revision: 1}
		snap.Domains[domID] = dom

		cert := f.Certifications[domID].Certification
		cert.Version = registry.Version{Status: registry.Active, Revision: 1}
		snap.Certifications[cert.ID] = cert

		di := db.Identity
		di.Version = registry.Version{Status: registry.Active, Revision: 1}
		snap.Identities[di.ID] = di

		ii := db.Issuers[0]
		ii.Version = registry.Version{Status: registry.Active, Revision: 1}
		snap.Identities[ii.ID] = ii
	}
	for role, id := range f.Identities {
		id.Version = registry.Version{Status: registry.Active, Revision: 1}
		snap.Identities[id.ID] = id
		if cred, ok := f.Credentials[role]; ok {
			cred.Version = registry.Version{Status: registry.Active, Revision: 1}
			snap.Credentials[cred.ID] = cred
		}
	}
	if f.IdentityLink.ID != "" {
		link := f.IdentityLink
		link.Version = registry.Version{Status: registry.Active, Revision: 2}
		link.EffectiveActive = true
		snap.Links[link.ID] = link
	}
	return snap
}

// ScanDirForPrivateKeys walks dir and fails if any filename or file content contains private key material.
// Returns the sorted relative paths of all scanned non-directory files.
func ScanDirForPrivateKeys(dir string) ([]string, error) {
	var scanned []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		lower := strings.ToLower(filepath.ToSlash(rel))
		if strings.HasSuffix(lower, ".key") || strings.Contains(lower, ".key.") ||
			strings.Contains(lower, "keystore") || strings.Contains(lower, "private") {
			return fmt.Errorf("forbidden private key filename in public directory: %s", rel)
		}
		scanned = append(scanned, filepath.ToSlash(rel))
		if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".pb") || lower == "registry" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, []byte("EC PRIVATE KEY")) {
			return fmt.Errorf("forbidden PRIVATE KEY PEM content in public directory: %s", rel)
		}
		return nil
	})
	slices.Sort(scanned)
	return scanned, err
}

// CollectRegistryPublicFiles returns sorted relative paths of public registry artifacts under <instance>/registry.
// Any unexpected non-certificate file under registry/tls is rejected.
func CollectRegistryPublicFiles(inst *ledger.Instance) ([]string, error) {
	if inst == nil {
		return nil, fmt.Errorf("fabric instance is required")
	}
	regDir := inst.RegistryPath(".")
	var out []string
	for _, sub := range []string{"ca", "tls", "did", "certifications", "credentials", "grants"} {
		root := filepath.Join(regDir, sub)
		if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(regDir, p)
			if err != nil {
				return err
			}
			if sub == "tls" && !strings.HasSuffix(d.Name(), ".cert.pem") {
				return fmt.Errorf("unexpected non-cert file %q in registry/tls", rel)
			}
			out = append(out, filepath.ToSlash(rel))
			return nil
		}); err != nil {
			return nil, err
		}
	}
	for _, single := range []string{
		"vc-v2.context.json",
		"context-manifest.json",
		"taskspec.json",
		"evidence-sample.json",
		"u-quote-sample.json",
		"fixtures.json",
		"seed.json",
	} {
		if _, err := os.Stat(filepath.Join(regDir, single)); err == nil {
			out = append(out, single)
		}
	}
	slices.Sort(out)
	return out, nil
}

// CheckRegistryAccess starts an online Fabric view with the requested probe cadence,
// waits for a fresh original probe, and returns the assembled grant snapshot as a JSON-ready map.
func CheckRegistryAccess(
	ctx context.Context,
	inst *ledger.Instance,
	grantID, probeRole string,
	probeInterval, probeLifetime time.Duration,
) (map[string]any, error) {
	if inst == nil {
		return nil, fmt.Errorf("fabric instance is required")
	}
	if probeRole == "" {
		probeRole = "probe1"
	}
	if probeInterval <= 0 {
		probeInterval = registry.ProbeInterval
	}
	if probeLifetime <= 0 {
		probeLifetime = registry.ProbeLifetime
	}
	if (probeRole != "probe1" && probeRole != "probe2") || probeInterval < 100*time.Millisecond || probeLifetime < probeInterval {
		return nil, fmt.Errorf("invalid probe configuration (role=%q interval=%s lifetime=%s)", probeRole, probeInterval, probeLifetime)
	}
	d, err := inst.LoadDeployment()
	if err != nil {
		return nil, err
	}
	if grantID == "" {
		f, err := LoadFixtures(inst)
		if err != nil {
			return nil, err
		}
		grantID = f.G1.ID
	}
	db, err := inst.Database(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := ledger.EnsureSchema(ctx, db); err != nil {
		return nil, err
	}
	rt := &ledger.Online{
		View:      ledger.View{DB: db, Deployment: d},
		Instance:  inst,
		Role:      probeRole,
		Interval:  probeInterval,
		TimeLimit: probeLifetime,
	}
	stop, err := rt.Start(ctx)
	if err != nil {
		return nil, err
	}
	defer stop()

	snap, err := rt.WaitOnline(ctx, grantID)
	if err != nil {
		return nil, err
	}
	return rawSnapshotToMap(snap)
}

// InspectHistory reconstructs an immutable historical Fabric view snapshot for grantID at blockNo.
func InspectHistory(ctx context.Context, inst *ledger.Instance, grantID string, blockNo int64) (map[string]any, error) {
	if inst == nil {
		return nil, fmt.Errorf("fabric instance is required")
	}
	if blockNo < 0 {
		return nil, fmt.Errorf("inspect requires a non-negative block number")
	}
	d, err := inst.LoadDeployment()
	if err != nil {
		return nil, err
	}
	if grantID == "" {
		f, err := LoadFixtures(inst)
		if err != nil {
			return nil, err
		}
		grantID = f.G1.ID
	}
	db, err := inst.Database(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := ledger.EnsureSchema(ctx, db); err != nil {
		return nil, err
	}
	v := ledger.View{DB: db, Deployment: d}
	n := uint64(blockNo)
	snap, err := v.RawSnapshot(ctx, grantID, &n, nil, nil)
	if err != nil {
		return nil, err
	}
	return rawSnapshotToMap(snap)
}

func rawSnapshotToMap(snap *ledger.RawSnapshot) (map[string]any, error) {
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
