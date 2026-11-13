package fabric

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"
)

type fixtures struct {
	Synthetic bool `json:"synthetic"`
	api.Bound
	Domains        map[string]api.DomainBootstrap `json:"domains"`
	Certifications map[string]api.Certify         `json:"certifications"`
	Identities     map[string]api.Identity        `json:"identities"`
	Credentials    map[string]api.Credential      `json:"credentials"`
	Task           api.Task                       `json:"task"`
	G0             api.Grant                      `json:"g0"`
	G1             api.Grant                      `json:"g1"`
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
		if f.DeploymentID != d.DeploymentID || !f.Synthetic {
			return nil, fmt.Errorf("DEPLOYMENT_MISMATCH: fixtures")
		}
		return &f, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	bound := api.Bound{DeploymentID: d.DeploymentID}
	now := time.Now()
	valid := api.Interval{NBF: now.Add(-time.Hour).Unix(), EXP: now.Add(24 * time.Hour).Unix()}
	f = fixtures{Synthetic: true, Bound: bound, Domains: map[string]api.DomainBootstrap{}, Certifications: map[string]api.Certify{},
		Identities: map[string]api.Identity{}, Credentials: map[string]api.Credential{}}
	makeID := func(role, id, domain, kind string) (api.Identity, error) {
		_, management, _, err := i.role(role)
		if err != nil {
			return api.Identity{}, err
		}
		key, err := publicKey()
		if err != nil {
			return api.Identity{}, err
		}
		return api.Identity{Bound: bound, ID: id, Domain: domain, Kind: kind, Management: management,
			DocumentDigest: api.Digest([]byte("synthetic DID document " + key)), KeyID: id + "#auth", KeyVersion: 1, PublicKey: key,
			AccountCommitment: api.Digest([]byte("synthetic account " + d.DeploymentID + id))}, nil
	}
	for _, domain := range []string{"A", "B", "C"} {
		host := "did:web:" + strings.ToLower(domain) + ".local"
		identity, err := makeID("domain"+domain, host, domain, "DOMAIN")
		if err != nil {
			return nil, err
		}
		issuer, err := makeID("I"+domain, host+":issuer", domain, "ISSUER")
		if err != nil {
			return nil, err
		}
		_, registrar, _, err := i.role("registrar" + domain)
		if err != nil {
			return nil, err
		}
		f.Domains[domain] = api.DomainBootstrap{
			Domain:   api.Domain{Bound: bound, ID: domain, DID: identity.ID, Admin: identity.Management, Registrar: registrar},
			Identity: identity, Issuers: []api.Identity{issuer},
		}
		id := "domain-cert-" + domain
		f.Certifications[domain] = api.Certify{ExpectedRevision: 1, Certification: api.Certification{
			Bound: bound, ID: id, Domain: domain, RootKeyVersion: 1, Digest: api.Digest([]byte(d.DeploymentID + id)), Interval: valid,
			Scopes: []api.Scope{{ID: issuer.ID, KeyVersion: 1, Types: []string{"EnterpriseIdentityCredential"}, Claims: []string{"domain", "role"}}},
		}}
	}
	for _, r := range []struct{ role, id, domain, kind string }{
		{"U", subjectU, "A", "USER"}, {"A1", "did:web:a.local:a1", "A", "AGENT"},
		{"alt", "did:web:a.local:other", "A", "USER"}, {"B1", "did:web:b.local:b1", "B", "AGENT"}, {"C", subjectC, "C", "SERVICE"},
	} {
		id, err := makeID(r.role, r.id, r.domain, r.kind)
		if err != nil {
			return nil, err
		}
		f.Identities[r.role] = id
		cred := "credential-" + r.role
		f.Credentials[r.role] = api.Credential{
			Bound: bound, ID: cred, Issuer: f.Domains[r.domain].Issuers[0].ID, Subject: id.ID, IssuerKeyVersion: 1,
			SubjectKeyVersion: 1, Type: "EnterpriseIdentityCredential", ClaimNames: []string{"domain", "role"},
			Digest: api.Digest([]byte(d.DeploymentID + cred)), Interval: valid,
		}
	}
	f.Task = api.Task{Bound: bound, ID: api.Digest([]byte(d.DeploymentID + "/task")), Creator: subjectU,
		CreatorCredential: f.Credentials["U"].ID, CreatorKeyVersion: 1, Domain: "A", Mode: api.RP, Resource: d.Bootstrap.ResourceID,
		Digest: api.Digest([]byte("synthetic P1/one unit procurement task")), Interval: valid}
	grant := func(label, issuer, holder string, depth uint8) api.Grant {
		return api.Grant{Bound: bound, ID: api.Digest([]byte(d.DeploymentID + "/" + label)), Schema: api.Schema,
			Task: f.Task.ID, Mode: api.RP, Domain: "A", Resource: f.Task.Resource, Issuer: f.Identities[issuer].ID,
			Grantee: f.Identities[holder].ID, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: f.Credentials[issuer].ID,
			GranteeCredential: f.Credentials[holder].ID, Depth: depth, Digest: api.Digest([]byte("synthetic " + d.DeploymentID + "/" + label)), Interval: valid}
	}
	f.G0 = grant("G0", "C", "U", 2)
	f.G0.Root = f.G0.ID
	f.G1 = grant("G1", "U", "A1", 1)
	f.G1.Root, f.G1.Parent, f.G1.ParentDigest = f.G0.ID, f.G0.ID, f.G0.Digest
	return &f, writeJSON(path, &f)
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
	report := &seedReport{fixtures: f, Scope: "D0 synthetic registration anchors and real Fabric management transactions"}
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
	return report, writeJSON(i.registryPath("seed.json"), report)
}
