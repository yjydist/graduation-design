package ledger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type DomainFixture struct {
	Domain        DomainInput        `json:"domain"`
	Identity      IdentityInput      `json:"identity"`
	Issuers       []IdentityInput    `json:"issuers"`
	Certification CertificationInput `json:"certification"`
}

type Fixtures struct {
	Synthetic     bool                         `json:"synthetic"`
	DeploymentID  string                       `json:"deploymentId"`
	Nbf           uint64                       `json:"nbf"`
	Exp           uint64                       `json:"exp"`
	Domains       map[string]DomainFixture     `json:"domains"`
	Identities    map[string]IdentityInput     `json:"identities"`
	Credentials   map[string]CredentialInput   `json:"credentials"`
	Task          TaskInput                    `json:"task"`
	Grants        map[string]GrantInput        `json:"grants"`
	Materials     map[string]json.RawMessage   `json:"syntheticMaterials"`
	AccountProofs map[string]map[string]string `json:"syntheticAccountCommitments"`
}

// LoadFixtures persists random salts and synthetic material before any management transaction.
func LoadFixtures(ctx context.Context, r *Registry) (*Fixtures, error) {
	path := filepath.Join(r.Dir, "fixtures-"+r.Deployment.DeploymentID+".json")
	b, err := os.ReadFile(path)
	if err == nil {
		var f Fixtures
		if err = json.Unmarshal(b, &f); err != nil {
			return nil, err
		}
		if !f.Synthetic || f.DeploymentID != r.Deployment.DeploymentID {
			return nil, fmt.Errorf("fixture deployment mismatch")
		}
		if len(f.Credentials) == 0 {
			if err = addCredentialFixtures(&f); err != nil {
				return nil, err
			}
			if err = durableJSON(path, &f); err != nil {
				return nil, err
			}
		}
		if f.Task.TaskId == (common.Hash{}) {
			addRPFixtures(&f)
			if err = durableJSON(path, &f); err != nil {
				return nil, err
			}
		}
		return &f, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	m, err := LoadInstance(r.Dir)
	if err != nil {
		return nil, err
	}
	h, err := ReadHeader(ctx, r.Client, nil)
	if err != nil {
		return nil, err
	}
	nbf := uint64(h.Timestamp) - 60
	f := &Fixtures{Synthetic: true, DeploymentID: r.Deployment.DeploymentID, Nbf: nbf, Exp: nbf + 86400, Domains: map[string]DomainFixture{}, Identities: map[string]IdentityInput{}, Materials: map[string]json.RawMessage{}, AccountProofs: map[string]map[string]string{}}
	accounts := map[string]Account{}
	for _, a := range m.Accounts {
		accounts[a.Role] = a
	}
	identity := func(role, domain string, kind uint8) (IdentityInput, error) {
		a := accounts[role]
		pub, err := hexutil.Decode(a.AppPublic)
		if err != nil {
			return IdentityInput{}, err
		}
		salt := make([]byte, 16)
		if _, err = rand.Read(salt); err != nil {
			return IdentityInput{}, err
		}
		proof := map[string]string{"purpose": "grad-account-v1", "domainId": domain, "localAccountId": "synthetic-" + role, "salt": hex.EncodeToString(salt)}
		b, _ := json.Marshal(proof)
		f.AccountProofs[role] = proof
		return IdentityInput{a.SubjectID, domain, kind, common.HexToAddress(a.Address), common.HexToHash(a.DIDDigest), a.AppKeyID, a.AppVersion, pub, hashID(string(b))}, nil
	}
	for _, name := range []string{"A", "C", "B"} {
		domainId := "urn:grad:domain:" + name
		domainIdentity, err := identity("domain"+name, domainId, 1)
		if err != nil {
			return nil, err
		}
		issuer, err := identity("I"+name, domainId, 2)
		if err != nil {
			return nil, err
		}
		certID := "urn:grad:domain-certification:" + name + "-v1"
		scopes := []IssuerScope{{issuer.SubjectId, issuer.AppKeyVersion, []string{"EnterpriseIdentityCredential"}, []string{"domain", "role"}}}
		material, _ := json.Marshal(map[string]any{"synthetic": true, "id": certID, "deploymentId": f.DeploymentID, "domainId": domainId, "issuer": "T", "identityIssuers": scopes, "nbf": f.Nbf, "exp": f.Exp})
		f.Materials[certID] = material
		f.Domains[name] = DomainFixture{Domain: DomainInput{domainId, domainIdentity.SubjectId, common.HexToAddress(accounts["admin"+name].Address), common.HexToAddress(accounts["registrar"+name].Address)}, Identity: domainIdentity, Issuers: []IdentityInput{issuer}, Certification: CertificationInput{certID, domainId, 1, hashID(string(material)), f.Nbf, f.Exp, scopes}}
	}
	for role, settings := range map[string]struct {
		domain string
		kind   uint8
	}{"U": {"A", 3}, "A1": {"A", 4}, "C": {"C", 5}, "B1": {"A", 3}} {
		i, err := identity(role, "urn:grad:domain:"+settings.domain, settings.kind)
		if err != nil {
			return nil, err
		}
		f.Identities[role] = i
	}
	if err = addCredentialFixtures(f); err != nil {
		return nil, err
	}
	addRPFixtures(f)
	if err = durableJSON(path, f); err != nil {
		return nil, err
	}
	return f, nil
}

func addCredentialFixtures(f *Fixtures) error {
	f.Credentials = map[string]CredentialInput{}
	for _, role := range []string{"U", "A1", "C", "B1"} {
		i := f.Identities[role]
		domain := "A"
		if role == "C" {
			domain = "C"
		}
		issuer := f.Domains[domain].Issuers[0]
		id := "urn:grad:credential:" + role + "-v1"
		material, err := json.Marshal(map[string]any{"synthetic": true, "id": id, "deploymentId": f.DeploymentID, "issuer": issuer.SubjectId, "subject": i.SubjectId, "nbf": f.Nbf, "exp": f.Exp, "appKeyVersion": i.AppKeyVersion})
		if err != nil {
			return err
		}
		f.Materials[id] = material
		f.Credentials[role] = CredentialInput{id, issuer.SubjectId, i.SubjectId, issuer.AppKeyVersion, i.AppKeyVersion, "EnterpriseIdentityCredential", hashID(string(material)), f.Nbf, f.Exp}
	}
	return nil
}

const TaskFixtureID = "urn:grad:task:RP-001"
const RootFixtureID = "urn:grad:grant:RP-G0"
const ChildFixtureID = "urn:grad:grant:RP-G1"

func addRPFixtures(f *Fixtures) {
	u, a, c := f.Identities["U"], f.Identities["A1"], f.Identities["C"]
	f.Task = TaskInput{TaskId: hashID(TaskFixtureID), DeploymentId: common.HexToHash(f.DeploymentID), Creator: hashID(u.SubjectId), PrincipalDomain: u.DomainId, AuthorizationMode: "RESOURCE_PREAUTHORIZED", TaskSpecDigest: common.HexToHash("430541fe288ebcb3eaadbc6ba54765d45e4e56a1131148ff57a5e42c26e7c6ba"), ResourceId: hashID("urn:grad:resource:C:orders"), CreatorCredentialId: hashID(f.Credentials["U"].CredentialId), CreatorKeyVersion: u.AppKeyVersion, Nbf: f.Nbf, Exp: f.Exp}
	g0 := GrantInput{GrantId: hashID(RootFixtureID), SchemaVersion: "grad-auth-v1", DeploymentId: common.HexToHash(f.DeploymentID), RootId: hashID(RootFixtureID), TaskId: f.Task.TaskId, AuthorizationMode: f.Task.AuthorizationMode, PrincipalDomain: u.DomainId, Issuer: hashID(c.SubjectId), Grantee: hashID(u.SubjectId), IssuerKeyVersion: c.AppKeyVersion, GranteeKeyVersion: u.AppKeyVersion, IssuerCredentialId: hashID(f.Credentials["C"].CredentialId), GranteeCredentialId: hashID(f.Credentials["U"].CredentialId), ResourceId: f.Task.ResourceId, Nbf: f.Nbf, Exp: f.Exp, RemainingDepth: 2}
	g0 = anchorSyntheticGrant(f, g0)
	g1 := g0
	g1.GrantId = hashID(ChildFixtureID)
	g1.ParentId = g0.GrantId
	g1.ParentDigest = g0.Digest
	g1.Issuer = g0.Grantee
	g1.Grantee = hashID(a.SubjectId)
	g1.IssuerKeyVersion = u.AppKeyVersion
	g1.GranteeKeyVersion = a.AppKeyVersion
	g1.IssuerCredentialId = g0.GranteeCredentialId
	g1.GranteeCredentialId = hashID(f.Credentials["A1"].CredentialId)
	g1.RemainingDepth = 1
	g1 = anchorSyntheticGrant(f, g1)
	f.Grants = map[string]GrantInput{"G0": g0, "G1": g1}
}

func anchorSyntheticGrant(f *Fixtures, g GrantInput) GrantInput {
	b, _ := json.Marshal(g)
	var payload map[string]any
	_ = json.Unmarshal(b, &payload)
	delete(payload, "digest")
	b, _ = json.Marshal(map[string]any{"synthetic": true, "payload": payload, "boundary": "application signatures and full resource/amount containment are not verified"})
	f.Materials[g.GrantId.Hex()] = b
	g.Digest = hashID(string(b))
	return g
}
