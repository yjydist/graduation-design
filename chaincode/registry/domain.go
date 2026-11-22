package main

import (
	"slices"

	api "grad/protocol/registry"
)

func (tx transaction) bootstrapDomain(input api.DomainBootstrap) error {
	if tx.caller != tx.boot.Root.Management {
		return api.Reject(api.ErrCodeUnauthorized)
	}
	d := input.Domain
	if !tx.bound(d.Bound) || !slices.Contains([]string{"A", "B", "C"}, d.ID) ||
		d.DID != input.Identity.ID || d.Admin != input.Identity.Management ||
		!d.Registrar.Valid() || d.Registrar.MSPID != d.ID+"Msp" || d.Certification != "" ||
		input.Identity.Kind != "DOMAIN" || input.Identity.Domain != d.ID ||
		len(input.Issuers) < 1 || len(input.Issuers) > api.MaxIdentityIssuers {
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	key := api.Key("domain", d.ID)
	if err := tx.vacant(key); err != nil {
		return err
	}
	d.Issuers = make([]string, len(input.Issuers))
	seen := map[api.Management]bool{d.Registrar: true, d.Admin: true}
	if d.Registrar == d.Admin {
		return api.Reject(api.ErrCodeIDAlreadyUsed)
	}
	for i, issuer := range input.Issuers {
		if issuer.Kind != "ISSUER" || issuer.Domain != d.ID ||
			issuer.ID == d.DID || (i > 0 && api.CompareUTF16(d.Issuers[i-1], issuer.ID) >= 0) || issuer.KeyVersion != 1 {
			return api.Reject(api.ErrCodeInvalidStructure)
		}
		if seen[issuer.Management] {
			return api.Reject(api.ErrCodeIDAlreadyUsed)
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

func (tx transaction) certifyDomain(input api.Certify) error {
	if tx.caller != tx.boot.Root.Management {
		return api.Reject(api.ErrCodeUnauthorized)
	}
	c := input.Certification
	if !tx.bound(c.Bound) || c.ID == "" || !api.IsDigest(c.Digest) || c.RootKeyVersion != tx.boot.Root.KeyVersion {
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	if !tx.current(c.Interval) {
		return api.Reject(api.ErrCodeInvalidState)
	}
	domainKey := api.Key("domain", c.Domain)
	d, err := get[api.Domain](tx.stub, domainKey)
	if err != nil {
		return err
	}
	if d.Revision != input.ExpectedRevision || d.Certification != input.ExpectedCertification {
		return api.Reject(api.ErrCodeStateChanged)
	}
	switch d.Status {
	case api.Pending:
		if d.Certification != "" {
			return api.Reject(api.ErrCodeInvalidState)
		}
		d.Status = api.Active
	case api.Active, api.Suspended:
		if d.Certification == "" {
			return api.Reject(api.ErrCodeInvalidState)
		}
	default:
		return api.Reject(api.ErrCodeInvalidState)
	}
	if len(c.Scopes) != len(d.Issuers) {
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	for i, s := range c.Scopes {
		issuer, err := get[api.Identity](tx.stub, api.Key("identity", s.ID))
		if err != nil {
			return err
		}
		if s.ID != d.Issuers[i] || issuer.Status != api.Active || issuer.Domain != c.Domain ||
			issuer.Kind != "ISSUER" || issuer.KeyVersion != s.AppKeyVersion ||
			!api.ValidStringSet(s.CredentialTypes) || !api.ValidStringSet(s.ClaimNames) {
			return api.Reject(api.ErrCodeInvalidStructure)
		}
	}
	key := api.Key("certification", c.ID)
	if err := tx.vacant(key); err != nil {
		return err
	}
	c.Version = api.Version{Status: api.Active, Revision: 1}
	d.Certification = c.ID
	d.Revision++
	if err := tx.put(key, c); err != nil {
		return err
	}
	return tx.put(domainKey, d)
}

func (tx transaction) revokeCertification(m api.Mutation) error {
	if tx.caller != tx.boot.Root.Management {
		return api.Reject(api.ErrCodeTrustManagementForbidden)
	}
	if !tx.bound(m.Bound) || m.ID == "" || m.ExpectedRevision == 0 {
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	key := api.Key("certification", m.ID)
	c, err := get[api.Certification](tx.stub, key)
	if err != nil {
		return err
	}
	if c.Status == api.Revoked {
		return api.Reject(api.ErrCodeAlreadyRevoked)
	}
	if c.Revision != m.ExpectedRevision || (m.ExpectedDigest != "" && c.Digest != m.ExpectedDigest) {
		return api.Reject(api.ErrCodeStateChanged)
	}
	c.Status = api.Revoked
	c.Revision++
	return tx.put(key, c)
}

func (tx transaction) setDomainStatus(input api.DomainStatus) error {
	if tx.caller != tx.boot.Root.Management {
		return api.Reject(api.ErrCodeUnauthorized)
	}
	if !tx.bound(input.Bound) {
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	key := api.Key("domain", input.ID)
	d, err := get[api.Domain](tx.stub, key)
	if err != nil {
		return err
	}
	if d.Revision != input.ExpectedRevision {
		return api.Reject(api.ErrCodeStateChanged)
	}
	switch {
	case d.Status == api.Active && (input.Status == api.Suspended || input.Status == api.Revoked):
	case d.Status == api.Suspended && input.Status == api.Revoked:
	case d.Status == api.Suspended && input.Status == api.Active:
		if _, err := tx.qualification(d); err != nil {
			return err
		}
	default:
		return api.Reject(api.ErrCodeInvalidState)
	}
	d.Status = input.Status
	d.Revision++
	return tx.put(key, d)
}

func (tx transaction) setPurchasingAuthority(input api.PurchasingAuthorityUpdate) error {
	if !tx.bound(input.Bound) || input.DomainID == "" || input.ExpectedRevision == 0 {
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	key := api.Key("domain", input.DomainID)
	d, err := get[api.Domain](tx.stub, key)
	if err != nil {
		return err
	}
	if err := tx.match(d.Admin, binding{Domain: d.ID, Subject: d.DID, Role: "DOMAIN"}); err != nil {
		return err
	}
	if d.Status != api.Active || d.Certification == "" {
		return api.Reject(api.ErrCodeInvalidState)
	}
	if _, err := tx.qualification(d); err != nil {
		return err
	}
	if d.Revision != input.ExpectedRevision {
		return api.Reject(api.ErrCodeStateChanged)
	}
	if input.PurchasingAuthority != "" {
		pa, err := get[api.Identity](tx.stub, api.Key("identity", input.PurchasingAuthority))
		if err != nil {
			return err
		}
		if pa.Status != api.Active {
			return api.Reject(api.ErrCodeInvalidState)
		}
		if pa.Domain != d.ID || pa.Kind != "SERVICE" {
			return api.Reject(api.ErrCodePurchasingAuthorityInvalid)
		}
	}
	d.PurchasingAuthority = input.PurchasingAuthority
	d.Revision++
	return tx.put(key, d)
}

func (tx transaction) updateAuthorityIdentity(in api.AuthorityIdentityUpdateInput) error {
	if tx.caller != tx.boot.Root.Management {
		return api.Reject(api.ErrCodeTrustManagementForbidden)
	}
	if !tx.bound(in.Bound) || in.ID == "" || in.ExpectedRevision == 0 || in.ExpectedKeyVersion == 0 {
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	key := api.Key("identity", in.ID)
	i, err := get[api.Identity](tx.stub, key)
	if err != nil {
		return err
	}
	if i.Kind != "DOMAIN" && i.Kind != "ISSUER" {
		return api.Reject(api.ErrCodeIdentityManagementForbidden)
	}
	if i.Status == api.Revoked {
		return api.Reject(api.ErrCodeIdentityStateConflict)
	}
	if i.Revision != in.ExpectedRevision || i.KeyVersion != in.ExpectedKeyVersion {
		return api.Reject(api.ErrCodeStateChanged)
	}
	if !in.Management.Valid() || in.Management.MSPID != i.Domain+"Msp" ||
		!api.IsDigest(in.DocumentDigest) || !api.ValidAppKey(i.ID, in.KeyID, in.PublicKey, i.KeyVersion+1) {
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	if in.Management != i.Management {
		if err := tx.bind(in.Management, binding{Domain: i.Domain, Subject: i.ID, Role: i.Kind}); err != nil {
			return err
		}
		if err := tx.stub.DelState(api.Key("binding", i.Management.String())); err != nil {
			return err
		}
		if i.Kind == "DOMAIN" {
			dKey := api.Key("domain", i.Domain)
			d, err := get[api.Domain](tx.stub, dKey)
			if err != nil {
				return err
			}
			d.Admin = in.Management
			d.Revision++
			if err := tx.put(dKey, d); err != nil {
				return err
			}
		}
	}
	i.Management = in.Management
	i.DocumentDigest = in.DocumentDigest
	i.KeyID = in.KeyID
	i.PublicKey = in.PublicKey
	i.KeyVersion++
	i.Revision++
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
		return c, api.Reject(api.ErrCodeInvalidState)
	}
	return c, nil
}

func (tx transaction) activeDomain(id string) (api.Domain, api.Certification, error) {
	d, err := get[api.Domain](tx.stub, api.Key("domain", id))
	if err != nil {
		return d, api.Certification{}, err
	}
	if d.Status != api.Active || d.Certification == "" {
		return d, api.Certification{}, api.Reject(api.ErrCodeInvalidState)
	}
	c, err := tx.qualification(d)
	return d, c, err
}
