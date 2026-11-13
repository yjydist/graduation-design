package main

import (
	"slices"
	"strings"

	api "graduation-design/internal/fabricapi"
)

type binding struct {
	Domain  string `json:"domainId"`
	Subject string `json:"subjectId"`
	Role    string `json:"role"`
}

func (tx transaction) bind(m api.Management, b binding) error {
	if m == tx.boot.Initializer || m == tx.boot.Root.Management || m.String() == probeOne || m.String() == probeTwo {
		return reject(denied)
	}
	key := api.Key("binding", m.String())
	if err := tx.vacant(key); err != nil {
		return err
	}
	return tx.put(key, b)
}

func (tx transaction) match(m api.Management, b binding) error {
	if tx.caller != m {
		return reject(denied)
	}
	actual, err := get[binding](tx.stub, api.Key("binding", m.String()))
	if err != nil {
		return err
	}
	if actual != b {
		return reject(denied)
	}
	return nil
}

func (tx transaction) bootstrapDomain(input api.DomainBootstrap) error {
	if tx.caller != tx.boot.Root.Management {
		return reject(denied)
	}
	d := input.Domain
	if !tx.bound(d.Bound) || !slices.Contains([]string{"A", "B", "C"}, d.ID) ||
		d.DID != input.Identity.ID || d.Admin != input.Identity.Management ||
		!d.Registrar.Valid() || d.Registrar.MSPID != d.ID+"Msp" || d.Certification != "" ||
		input.Identity.Kind != "DOMAIN" || input.Identity.Domain != d.ID ||
		len(input.Issuers) < 1 || len(input.Issuers) > 8 {
		return reject(badInput)
	}
	key := api.Key("domain", d.ID)
	if err := tx.vacant(key); err != nil {
		return err
	}
	d.Issuers = make([]string, len(input.Issuers))
	seen := map[api.Management]bool{d.Registrar: true, d.Admin: true}
	if d.Registrar == d.Admin {
		return reject(used)
	}
	for i, issuer := range input.Issuers {
		if issuer.Kind != "ISSUER" || issuer.Domain != d.ID ||
			issuer.ID == d.DID || (i > 0 && d.Issuers[i-1] >= issuer.ID) || issuer.KeyVersion != 1 {
			return reject(badInput)
		}
		if seen[issuer.Management] {
			return reject(used)
		}
		seen[issuer.Management] = true
		d.Issuers[i] = issuer.ID
	}
	if err := tx.bind(d.Registrar, binding{Domain: d.ID, Role: "REGISTRAR"}); err != nil {
		return err
	}
	if err := tx.storeIdentity(input.Identity); err != nil {
		return err
	}
	for _, issuer := range input.Issuers {
		if err := tx.storeIdentity(issuer); err != nil {
			return err
		}
	}
	d.Version = api.Version{Status: api.Pending, Revision: 1}
	return tx.put(key, d)
}

func (tx transaction) certify(input api.Certify) error {
	if tx.caller != tx.boot.Root.Management {
		return reject(denied)
	}
	c := input.Certification
	if !tx.bound(c.Bound) || c.ID == "" || !api.IsDigest(c.Digest) || c.RootKeyVersion != tx.boot.Root.KeyVersion {
		return reject(badInput)
	}
	if !tx.current(c.Interval) {
		return reject(invalid)
	}
	domainKey := api.Key("domain", c.Domain)
	d, err := get[api.Domain](tx.stub, domainKey)
	if err != nil {
		return err
	}
	if d.Revision != input.ExpectedRevision || d.Certification != input.ExpectedCertification {
		return reject(stale)
	}
	if d.Status != api.Pending || d.Certification != "" {
		return reject(invalid)
	}
	if len(c.Scopes) != len(d.Issuers) {
		return reject(badInput)
	}
	for i, s := range c.Scopes {
		issuer, err := get[api.Identity](tx.stub, api.Key("identity", s.ID))
		if err != nil {
			return err
		}
		if s.ID != d.Issuers[i] || issuer.Status != api.Active || issuer.Domain != c.Domain ||
			issuer.Kind != "ISSUER" || issuer.KeyVersion != s.KeyVersion || !validSet(s.Types) || !validSet(s.Claims) {
			return reject(badInput)
		}
	}
	key := api.Key("certification", c.ID)
	if err := tx.vacant(key); err != nil {
		return err
	}
	c.Version = api.Version{Status: api.Active, Revision: 1}
	d.Status, d.Certification = api.Active, c.ID
	d.Revision++
	if err := tx.put(key, c); err != nil {
		return err
	}
	return tx.put(domainKey, d)
}

func validSet(s []string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, v := range s {
		if v == "" || strings.Contains(v, "*") || (i > 0 && s[i-1] >= v) {
			return false
		}
	}
	return true
}

func (tx transaction) setDomainStatus(input api.DomainStatus) error {
	if tx.caller != tx.boot.Root.Management {
		return reject(denied)
	}
	if !tx.bound(input.Bound) {
		return reject(badInput)
	}
	key := api.Key("domain", input.ID)
	d, err := get[api.Domain](tx.stub, key)
	if err != nil {
		return err
	}
	if d.Revision != input.ExpectedRevision {
		return reject(stale)
	}
	switch {
	case d.Status == api.Active && (input.Status == api.Suspended || input.Status == api.Revoked):
	case d.Status == api.Suspended && input.Status == api.Revoked:
	case d.Status == api.Suspended && input.Status == api.Active:
		if _, err := tx.qualification(d); err != nil {
			return err
		}
	default:
		return reject(invalid)
	}
	d.Status = input.Status
	d.Revision++
	return tx.put(key, d)
}

func (tx transaction) registerIdentity(i api.Identity) error {
	if i.Kind != "USER" && i.Kind != "AGENT" && i.Kind != "SERVICE" {
		return reject(badInput)
	}
	d, _, err := tx.activeDomain(i.Domain)
	if err != nil {
		return err
	}
	if err := tx.match(d.Registrar, binding{Domain: d.ID, Role: "REGISTRAR"}); err != nil {
		return err
	}
	if i.KeyVersion != 1 || (i.ID == tx.boot.TaskCreator.Subject && i.Management != tx.boot.TaskCreator.Management) ||
		(i.ID == tx.boot.ResourceOwner && i.Management != tx.boot.ResourceManagement) {
		return reject(badInput)
	}
	return tx.storeIdentity(i)
}

func (tx transaction) storeIdentity(i api.Identity) error {
	if !tx.bound(i.Bound) || i.ID == tx.boot.Root.DID || i.Management.MSPID != i.Domain+"Msp" ||
		!i.Management.Valid() || !api.ValidAppKey(i.ID, i.KeyID, i.PublicKey, i.KeyVersion) ||
		!api.IsDigest(i.DocumentDigest) || !api.IsDigest(i.AccountCommitment) {
		return reject(badInput)
	}
	key := api.Key("identity", i.ID)
	if err := tx.vacant(key); err != nil {
		return err
	}
	if err := tx.bind(i.Management, binding{Domain: i.Domain, Subject: i.ID, Role: i.Kind}); err != nil {
		return err
	}
	i.Version = api.Version{Status: api.Active, Revision: 1}
	return tx.put(key, i)
}

func (tx transaction) qualification(d api.Domain) (api.Certification, error) {
	c, err := get[api.Certification](tx.stub, api.Key("certification", d.Certification))
	if err != nil {
		return c, err
	}
	identity, err := get[api.Identity](tx.stub, api.Key("identity", d.DID))
	if err != nil {
		return c, err
	}
	if c.Status != api.Active || c.Domain != d.ID || c.RootKeyVersion != tx.boot.Root.KeyVersion ||
		identity.Status != api.Active || identity.Kind != "DOMAIN" || identity.Domain != d.ID ||
		identity.Management != d.Admin || !tx.current(c.Interval) {
		return c, reject(invalid)
	}
	return c, nil
}

func (tx transaction) activeDomain(id string) (api.Domain, api.Certification, error) {
	d, err := get[api.Domain](tx.stub, api.Key("domain", id))
	if err != nil {
		return d, api.Certification{}, err
	}
	if d.Status != api.Active || d.Certification == "" {
		return d, api.Certification{}, reject(invalid)
	}
	c, err := tx.qualification(d)
	return d, c, err
}

func (tx transaction) credentialAuthority(c api.Credential, signing bool) error {
	subject, err := get[api.Identity](tx.stub, api.Key("identity", c.Subject))
	if err != nil {
		return err
	}
	issuer, err := get[api.Identity](tx.stub, api.Key("identity", c.Issuer))
	if err != nil {
		return err
	}
	if signing {
		if err := tx.match(issuer.Management, binding{Domain: issuer.Domain, Subject: issuer.ID, Role: "ISSUER"}); err != nil {
			return err
		}
	}
	if issuer.Domain != subject.Domain || issuer.Kind != "ISSUER" || (subject.Kind == "DOMAIN" || subject.Kind == "ISSUER") ||
		issuer.KeyVersion != c.IssuerKeyVersion || subject.KeyVersion != c.SubjectKeyVersion {
		return reject(badInput)
	}
	if subject.Status != api.Active || issuer.Status != api.Active || !tx.current(c.Interval) {
		return reject(invalid)
	}
	d, cert, err := tx.activeDomain(subject.Domain)
	if err != nil {
		return err
	}
	if signing && !c.Interval.Within(cert.Interval) {
		return reject(badInput)
	}
	if !slices.Contains(d.Issuers, issuer.ID) || !validSet(c.ClaimNames) {
		return reject(badInput)
	}
	for _, s := range cert.Scopes {
		if s.ID == c.Issuer && s.KeyVersion == c.IssuerKeyVersion && slices.Contains(s.Types, c.Type) {
			for _, claim := range c.ClaimNames {
				if !slices.Contains(s.Claims, claim) {
					return reject(badInput)
				}
			}
			return nil
		}
	}
	return reject(badInput)
}

func (tx transaction) registerCredential(c api.Credential) error {
	if !tx.bound(c.Bound) || c.ID == "" || !api.IsDigest(c.Digest) {
		return reject(badInput)
	}
	key := api.Key("credential", c.ID)
	if err := tx.vacant(key); err != nil {
		return err
	}
	if err := tx.credentialAuthority(c, true); err != nil {
		return err
	}
	c.Version = api.Version{Status: api.Active, Revision: 1}
	return tx.put(key, c)
}

func (tx transaction) validCredential(id, holder string, version uint64) (api.Credential, error) {
	c, err := get[api.Credential](tx.stub, api.Key("credential", id))
	if err != nil {
		return c, err
	}
	if c.Subject != holder || c.SubjectKeyVersion != version {
		return c, reject(badInput)
	}
	if c.Status != api.Active {
		return c, reject(invalid)
	}
	return c, tx.credentialAuthority(c, false)
}
