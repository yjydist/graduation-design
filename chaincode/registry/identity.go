package main

import (
	"encoding/json"
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
	switch d.Status {
	case api.Pending:
		if d.Certification != "" {
			return reject(invalid)
		}
		d.Status = api.Active
	case api.Active, api.Suspended:
		if d.Certification == "" {
			return reject(invalid)
		}
	default:
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
	d.Certification = c.ID
	d.Revision++
	if err := tx.put(key, c); err != nil {
		return err
	}
	return tx.put(domainKey, d)
}

func (tx transaction) revokeCertification(m api.Mutation) error {
	if tx.caller != tx.boot.Root.Management {
		return reject(trustMgmtForbidden)
	}
	if !tx.bound(m.Bound) || m.ID == "" || m.ExpectedRevision == 0 {
		return reject(badInput)
	}
	key := api.Key("certification", m.ID)
	c, err := get[api.Certification](tx.stub, key)
	if err != nil {
		return err
	}
	if c.Status == api.Revoked {
		return reject(alreadyRevoked)
	}
	if c.Revision != m.ExpectedRevision || (m.ExpectedDigest != "" && c.Digest != m.ExpectedDigest) {
		return reject(stale)
	}
	c.Status = api.Revoked
	c.Revision++
	return tx.put(key, c)
}

func (tx transaction) updateAuthorityIdentity(in api.AuthorityIdentityUpdateInput) error {
	if tx.caller != tx.boot.Root.Management {
		return reject(trustMgmtForbidden)
	}
	if !tx.bound(in.Bound) || in.ID == "" || in.ExpectedRevision == 0 || in.ExpectedKeyVersion == 0 {
		return reject(badInput)
	}
	key := api.Key("identity", in.ID)
	i, err := get[api.Identity](tx.stub, key)
	if err != nil {
		return err
	}
	if i.Kind != "DOMAIN" && i.Kind != "ISSUER" {
		return reject(identityMgmtForbidden)
	}
	if i.Status == api.Revoked {
		return reject(identityStateConflict)
	}
	if i.Revision != in.ExpectedRevision || i.KeyVersion != in.ExpectedKeyVersion {
		return reject(stale)
	}
	if !in.Management.Valid() || in.Management.MSPID != i.Domain+"Msp" ||
		!api.IsDigest(in.DocumentDigest) || !api.ValidAppKey(i.ID, in.KeyID, in.PublicKey, i.KeyVersion+1) {
		return reject(badInput)
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

func (tx transaction) setPurchasingAuthority(input api.PurchasingAuthorityUpdate) error {
	if !tx.bound(input.Bound) || input.DomainID == "" || input.ExpectedRevision == 0 {
		return reject(badInput)
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
		return reject(invalid)
	}
	if _, err := tx.qualification(d); err != nil {
		return err
	}
	if d.Revision != input.ExpectedRevision {
		return reject(stale)
	}
	if input.PurchasingAuthority != "" {
		pa, err := get[api.Identity](tx.stub, api.Key("identity", input.PurchasingAuthority))
		if err != nil {
			return err
		}
		if pa.Status != api.Active {
			return reject(invalid)
		}
		if pa.Domain != d.ID || pa.Kind != "SERVICE" {
			return reject(paInvalid)
		}
	}
	d.PurchasingAuthority = input.PurchasingAuthority
	d.Revision++
	return tx.put(key, d)
}

func (tx transaction) proposeIdentityLink(l api.IdentityLink) error {
	if !tx.bound(l.Bound) || l.ID == "" || l.SourceDomain == "" || l.TargetDomain == "" ||
		l.SourceDomain == l.TargetDomain || l.SourceSubject == "" || l.TargetSubject == "" ||
		l.SourceSubject == l.TargetSubject || !api.IsDigest(l.ProposalDigest) ||
		l.ProposedAt <= 0 || l.ExpiresAt <= l.ProposedAt {
		return reject(linkProofInvalid)
	}
	srcDom, _, err := tx.activeDomain(l.SourceDomain)
	if err != nil {
		return err
	}
	if _, _, err := tx.activeDomain(l.TargetDomain); err != nil {
		return err
	}
	if err := tx.match(srcDom.Registrar, binding{Domain: srcDom.ID, Role: "REGISTRAR"}); err != nil {
		return err
	}
	key := api.Key("link", l.ID)
	if err := tx.vacant(key); err != nil {
		return err
	}
	srcID, err := get[api.Identity](tx.stub, api.Key("identity", l.SourceSubject))
	if err != nil {
		return err
	}
	dstID, err := get[api.Identity](tx.stub, api.Key("identity", l.TargetSubject))
	if err != nil {
		return err
	}
	if srcID.Status != api.Active || dstID.Status != api.Active {
		return reject(invalid)
	}
	if srcID.Domain != l.SourceDomain || srcID.Kind != "USER" || srcID.KeyVersion != l.SourceKeyVersion ||
		srcID.AccountCommitment == "" || srcID.AccountCommitment != l.SourceAccountCommitment ||
		dstID.Domain != l.TargetDomain || dstID.Kind != "USER" || dstID.KeyVersion != l.TargetKeyVersion ||
		dstID.AccountCommitment == "" || dstID.AccountCommitment != l.TargetAccountCommitment {
		return reject(linkProofInvalid)
	}
	l.EffectiveActive = false
	l.ApprovedBy = ""
	l.ApprovedAt = 0
	l.RevokedBy = ""
	l.RevokedAt = 0
	l.Reason = ""
	l.Version = api.Version{Status: api.Pending, Revision: 1}
	return tx.put(key, l)
}

func (tx transaction) approveIdentityLink(input api.IdentityLinkApproval) error {
	if !tx.bound(input.Bound) || input.ID == "" || !api.IsDigest(input.ProposalDigest) ||
		input.ExpectedRevision == 0 || input.ApprovedAt <= 0 {
		return reject(badInput)
	}
	key := api.Key("link", input.ID)
	l, err := get[api.IdentityLink](tx.stub, key)
	if err != nil {
		return err
	}
	dstDom, _, err := tx.activeDomain(l.TargetDomain)
	if err != nil {
		return err
	}
	if err := tx.match(dstDom.Registrar, binding{Domain: dstDom.ID, Role: "REGISTRAR"}); err != nil {
		return reject(linkApprovalForbidden)
	}
	if l.Status != api.Pending {
		return reject(linkStateConflict)
	}
	if l.Revision != input.ExpectedRevision {
		return reject(stale)
	}
	if l.ProposalDigest != input.ProposalDigest {
		return reject(linkProposalMismatch)
	}
	if input.ApprovedAt < l.ProposedAt || input.ApprovedAt >= l.ExpiresAt || tx.at.Unix() >= l.ExpiresAt+int64(api.ClockError.Seconds()) {
		return reject(linkStateConflict)
	}
	if _, _, err := tx.activeDomain(l.SourceDomain); err != nil {
		return reject(linkStateConflict)
	}
	srcID, err := get[api.Identity](tx.stub, api.Key("identity", l.SourceSubject))
	if err != nil || srcID.Status != api.Active || srcID.KeyVersion != l.SourceKeyVersion || srcID.AccountCommitment != l.SourceAccountCommitment {
		return reject(linkStateConflict)
	}
	dstID, err := get[api.Identity](tx.stub, api.Key("identity", l.TargetSubject))
	if err != nil || dstID.Status != api.Active || dstID.KeyVersion != l.TargetKeyVersion || dstID.AccountCommitment != l.TargetAccountCommitment {
		return reject(linkStateConflict)
	}
	l.Status = api.Active
	l.EffectiveActive = true
	l.ApprovedBy = dstDom.DID
	l.ApprovedAt = input.ApprovedAt
	l.Revision++
	return tx.put(key, l)
}

func (tx transaction) revokeIdentityLink(m api.Mutation) error {
	if !tx.bound(m.Bound) || m.ID == "" || m.ExpectedRevision == 0 {
		return reject(badInput)
	}
	key := api.Key("link", m.ID)
	l, err := get[api.IdentityLink](tx.stub, key)
	if err != nil {
		return err
	}
	srcDom, err := get[api.Domain](tx.stub, api.Key("domain", l.SourceDomain))
	if err != nil {
		return err
	}
	dstDom, err := get[api.Domain](tx.stub, api.Key("domain", l.TargetDomain))
	if err != nil {
		return err
	}
	srcID, err := get[api.Identity](tx.stub, api.Key("identity", l.SourceSubject))
	if err != nil {
		return err
	}
	dstID, err := get[api.Identity](tx.stub, api.Key("identity", l.TargetSubject))
	if err != nil {
		return err
	}
	authorized := tx.match(srcDom.Registrar, binding{Domain: srcDom.ID, Role: "REGISTRAR"}) == nil ||
		tx.match(dstDom.Registrar, binding{Domain: dstDom.ID, Role: "REGISTRAR"}) == nil ||
		tx.match(srcID.Management, binding{Domain: srcID.Domain, Subject: srcID.ID, Role: srcID.Kind}) == nil ||
		tx.match(dstID.Management, binding{Domain: dstID.Domain, Subject: dstID.ID, Role: dstID.Kind}) == nil
	if !authorized {
		return reject(denied)
	}
	if l.Status != api.Pending && l.Status != api.Active {
		return reject(linkStateConflict)
	}
	if l.Revision != m.ExpectedRevision {
		return reject(stale)
	}
	l.Status = api.Revoked
	l.EffectiveActive = false
	l.RevokedBy = tx.caller.String()
	l.RevokedAt = tx.at.Unix()
	l.Reason = m.Reason
	l.Revision++
	return tx.put(key, l)
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
	raw, err := tx.stub.GetState(key)
	if err != nil {
		return err
	}
	if raw != nil {
		var prev api.Identity
		if err := json.Unmarshal(raw, &prev); err == nil && prev.Status == api.Revoked {
			return reject(identityStateConflict)
		}
		return reject(used)
	}
	if err := tx.bind(i.Management, binding{Domain: i.Domain, Subject: i.ID, Role: i.Kind}); err != nil {
		return err
	}
	i.Version = api.Version{Status: api.Active, Revision: 1}
	return tx.put(key, i)
}

func (tx transaction) setIdentityStatus(in api.IdentityStatusInput) error {
	if !tx.bound(in.Bound) || in.ID == "" || in.ExpectedRevision == 0 ||
		(in.Status != api.Active && in.Status != api.Suspended && in.Status != api.Revoked) {
		return reject(badInput)
	}
	key := api.Key("identity", in.ID)
	i, err := get[api.Identity](tx.stub, key)
	if err != nil {
		return err
	}
	switch i.Kind {
	case "DOMAIN", "ISSUER":
		if tx.caller != tx.boot.Root.Management {
			return reject(identityMgmtForbidden)
		}
	case "USER", "AGENT", "SERVICE":
		if tx.caller == tx.boot.Root.Management {
			return reject(identityMgmtForbidden)
		}
		d, err := get[api.Domain](tx.stub, api.Key("domain", i.Domain))
		if err != nil {
			return err
		}
		isSelf := tx.match(i.Management, binding{Domain: i.Domain, Subject: i.ID, Role: i.Kind}) == nil
		isRegistrar := tx.match(d.Registrar, binding{Domain: d.ID, Role: "REGISTRAR"}) == nil
		if in.Status == api.Active {
			if !isRegistrar {
				return reject(identityMgmtForbidden)
			}
		} else {
			if !isSelf && !isRegistrar {
				return reject(identityMgmtForbidden)
			}
		}
	default:
		return reject(badInput)
	}
	if i.Status == api.Revoked || i.Status == in.Status {
		return reject(identityStateConflict)
	}
	if i.Revision != in.ExpectedRevision {
		return reject(stale)
	}
	if in.Status == api.Active && (i.Kind == "USER" || i.Kind == "AGENT" || i.Kind == "SERVICE") {
		if _, _, err := tx.activeDomain(i.Domain); err != nil {
			return err
		}
	}
	i.Status = in.Status
	i.Revision++
	return tx.put(key, i)
}

func (tx transaction) rotateIdentity(in api.RotateIdentityInput) error {
	if !tx.bound(in.Bound) || in.ID == "" || in.ExpectedRevision == 0 || in.ExpectedKeyVersion == 0 {
		return reject(badInput)
	}
	key := api.Key("identity", in.ID)
	i, err := get[api.Identity](tx.stub, key)
	if err != nil {
		return err
	}
	if i.Kind != "USER" && i.Kind != "AGENT" && i.Kind != "SERVICE" {
		return reject(identityMgmtForbidden)
	}
	if err := tx.match(i.Management, binding{Domain: i.Domain, Subject: i.ID, Role: i.Kind}); err != nil {
		return reject(identityMgmtForbidden)
	}
	if i.Status != api.Active {
		return reject(identityStateConflict)
	}
	if _, _, err := tx.activeDomain(i.Domain); err != nil {
		return err
	}
	if i.Revision != in.ExpectedRevision || i.KeyVersion != in.ExpectedKeyVersion {
		return reject(stale)
	}
	if !api.IsDigest(in.DocumentDigest) || !api.ValidAppKey(i.ID, in.KeyID, in.PublicKey, i.KeyVersion+1) {
		return reject(badInput)
	}
	i.DocumentDigest = in.DocumentDigest
	i.KeyID = in.KeyID
	i.PublicKey = in.PublicKey
	i.KeyVersion++
	i.Revision++
	return tx.put(key, i)
}

func (tx transaction) recoverIdentity(in api.RecoverIdentityInput) error {
	if !tx.bound(in.Bound) || in.ID == "" || in.ExpectedRevision == 0 || in.ExpectedKeyVersion == 0 {
		return reject(badInput)
	}
	key := api.Key("identity", in.ID)
	i, err := get[api.Identity](tx.stub, key)
	if err != nil {
		return err
	}
	if i.Kind != "USER" && i.Kind != "AGENT" && i.Kind != "SERVICE" {
		return reject(identityRecoveryForbidden)
	}
	d, err := get[api.Domain](tx.stub, api.Key("domain", i.Domain))
	if err != nil {
		return err
	}
	if err := tx.match(d.Registrar, binding{Domain: d.ID, Role: "REGISTRAR"}); err != nil {
		return reject(identityRecoveryForbidden)
	}
	if _, _, err := tx.activeDomain(i.Domain); err != nil {
		return err
	}
	if i.Status != api.Active && i.Status != api.Suspended {
		return reject(identityStateConflict)
	}
	if i.Revision != in.ExpectedRevision || i.KeyVersion != in.ExpectedKeyVersion {
		return reject(stale)
	}
	if in.AccountCommitment != i.AccountCommitment || in.OldManagement != i.Management ||
		!in.NewManagement.Valid() || in.NewManagement.MSPID != i.Domain+"Msp" ||
		in.NewManagement == in.OldManagement || !api.IsDigest(in.DocumentDigest) ||
		!api.ValidAppKey(i.ID, in.KeyID, in.PublicKey, i.KeyVersion+1) {
		return reject(recoveryProofInvalid)
	}
	if err := tx.bind(in.NewManagement, binding{Domain: i.Domain, Subject: i.ID, Role: i.Kind}); err != nil {
		return err
	}
	if err := tx.stub.DelState(api.Key("binding", i.Management.String())); err != nil {
		return err
	}
	i.Management = in.NewManagement
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

func (tx transaction) revokeCredential(m api.Mutation) error {
	if !tx.bound(m.Bound) || m.ID == "" || m.ExpectedRevision == 0 {
		return reject(badInput)
	}
	key := api.Key("credential", m.ID)
	c, err := get[api.Credential](tx.stub, key)
	if err != nil {
		return err
	}
	iss, err := get[api.Identity](tx.stub, api.Key("identity", c.Issuer))
	if err != nil {
		return err
	}
	if err := tx.match(iss.Management, binding{Domain: iss.Domain, Subject: iss.ID, Role: "ISSUER"}); err != nil {
		return err
	}
	if c.Status == api.Revoked {
		return reject(alreadyRevoked)
	}
	if c.Revision != m.ExpectedRevision || (m.ExpectedDigest != "" && c.Digest != m.ExpectedDigest) {
		return reject(stale)
	}
	c.Status = api.Revoked
	c.Revision++
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
