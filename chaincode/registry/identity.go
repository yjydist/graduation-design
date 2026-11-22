package main

import (
	"encoding/json"
	"slices"

	api "grad/protocol/registry"
)

func (tx transaction) registerIdentity(i api.Identity) error {
	if i.Kind != "USER" && i.Kind != "AGENT" && i.Kind != "SERVICE" {
		return api.Reject(api.ErrCodeInvalidStructure)
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
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	return tx.storeIdentity(i)
}

func (tx transaction) storeIdentity(i api.Identity) error {
	if !tx.bound(i.Bound) || i.ID == tx.boot.Root.DID || i.Management.MSPID != i.Domain+"Msp" ||
		!i.Management.Valid() || !api.ValidAppKey(i.ID, i.KeyID, i.PublicKey, i.KeyVersion) ||
		!api.IsDigest(i.DocumentDigest) || !api.IsDigest(i.AccountCommitment) {
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	key := api.Key("identity", i.ID)
	raw, err := tx.stub.GetState(key)
	if err != nil {
		return err
	}
	if raw != nil {
		var prev api.Identity
		if err := json.Unmarshal(raw, &prev); err == nil && prev.Status == api.Revoked {
			return api.Reject(api.ErrCodeIdentityStateConflict)
		}
		return api.Reject(api.ErrCodeIDAlreadyUsed)
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
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	key := api.Key("identity", in.ID)
	i, err := get[api.Identity](tx.stub, key)
	if err != nil {
		return err
	}
	switch i.Kind {
	case "DOMAIN", "ISSUER":
		if tx.caller != tx.boot.Root.Management {
			return api.Reject(api.ErrCodeIdentityManagementForbidden)
		}
	case "USER", "AGENT", "SERVICE":
		if tx.caller == tx.boot.Root.Management {
			return api.Reject(api.ErrCodeIdentityManagementForbidden)
		}
		d, err := get[api.Domain](tx.stub, api.Key("domain", i.Domain))
		if err != nil {
			return err
		}
		isSelf := tx.match(i.Management, binding{Domain: i.Domain, Subject: i.ID, Role: i.Kind}) == nil
		isRegistrar := tx.match(d.Registrar, binding{Domain: d.ID, Role: "REGISTRAR"}) == nil
		if in.Status == api.Active {
			if !isRegistrar {
				return api.Reject(api.ErrCodeIdentityManagementForbidden)
			}
		} else {
			if !isSelf && !isRegistrar {
				return api.Reject(api.ErrCodeIdentityManagementForbidden)
			}
		}
	default:
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	if i.Status == api.Revoked || i.Status == in.Status {
		return api.Reject(api.ErrCodeIdentityStateConflict)
	}
	if i.Revision != in.ExpectedRevision {
		return api.Reject(api.ErrCodeStateChanged)
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
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	key := api.Key("identity", in.ID)
	i, err := get[api.Identity](tx.stub, key)
	if err != nil {
		return err
	}
	if i.Kind != "USER" && i.Kind != "AGENT" && i.Kind != "SERVICE" {
		return api.Reject(api.ErrCodeIdentityManagementForbidden)
	}
	if err := tx.match(i.Management, binding{Domain: i.Domain, Subject: i.ID, Role: i.Kind}); err != nil {
		return api.Reject(api.ErrCodeIdentityManagementForbidden)
	}
	if i.Status != api.Active {
		return api.Reject(api.ErrCodeIdentityStateConflict)
	}
	if _, _, err := tx.activeDomain(i.Domain); err != nil {
		return err
	}
	if i.Revision != in.ExpectedRevision || i.KeyVersion != in.ExpectedKeyVersion {
		return api.Reject(api.ErrCodeStateChanged)
	}
	if !api.IsDigest(in.DocumentDigest) || !api.ValidAppKey(i.ID, in.KeyID, in.PublicKey, i.KeyVersion+1) {
		return api.Reject(api.ErrCodeInvalidStructure)
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
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	key := api.Key("identity", in.ID)
	i, err := get[api.Identity](tx.stub, key)
	if err != nil {
		return err
	}
	if i.Kind != "USER" && i.Kind != "AGENT" && i.Kind != "SERVICE" {
		return api.Reject(api.ErrCodeIdentityRecoveryForbidden)
	}
	d, err := get[api.Domain](tx.stub, api.Key("domain", i.Domain))
	if err != nil {
		return err
	}
	if err := tx.match(d.Registrar, binding{Domain: d.ID, Role: "REGISTRAR"}); err != nil {
		return api.Reject(api.ErrCodeIdentityRecoveryForbidden)
	}
	if _, _, err := tx.activeDomain(i.Domain); err != nil {
		return err
	}
	if i.Status != api.Active && i.Status != api.Suspended {
		return api.Reject(api.ErrCodeIdentityStateConflict)
	}
	if i.Revision != in.ExpectedRevision || i.KeyVersion != in.ExpectedKeyVersion {
		return api.Reject(api.ErrCodeStateChanged)
	}
	if in.AccountCommitment != i.AccountCommitment || in.OldManagement != i.Management ||
		!in.NewManagement.Valid() || in.NewManagement.MSPID != i.Domain+"Msp" ||
		in.NewManagement == in.OldManagement || !api.IsDigest(in.DocumentDigest) ||
		!api.ValidAppKey(i.ID, in.KeyID, in.PublicKey, i.KeyVersion+1) {
		return api.Reject(api.ErrCodeRecoveryProofInvalid)
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

func (tx transaction) proposeIdentityLink(l api.IdentityLink) error {
	if !tx.bound(l.Bound) || l.ID == "" || l.SourceDomain == "" || l.TargetDomain == "" ||
		l.SourceDomain == l.TargetDomain || l.SourceSubject == "" || l.TargetSubject == "" ||
		l.SourceSubject == l.TargetSubject || !api.IsDigest(l.ProposalDigest) ||
		l.ProposedAt <= 0 || l.ExpiresAt <= l.ProposedAt {
		return api.Reject(api.ErrCodeLinkProofInvalid)
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
		return api.Reject(api.ErrCodeInvalidState)
	}
	if srcID.Domain != l.SourceDomain || srcID.Kind != "USER" || srcID.KeyVersion != l.SourceKeyVersion ||
		srcID.AccountCommitment == "" || srcID.AccountCommitment != l.SourceAccountCommitment ||
		dstID.Domain != l.TargetDomain || dstID.Kind != "USER" || dstID.KeyVersion != l.TargetKeyVersion ||
		dstID.AccountCommitment == "" || dstID.AccountCommitment != l.TargetAccountCommitment {
		return api.Reject(api.ErrCodeLinkProofInvalid)
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
		return api.Reject(api.ErrCodeInvalidStructure)
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
		return api.Reject(api.ErrCodeLinkApprovalForbidden)
	}
	if l.Status != api.Pending {
		return api.Reject(api.ErrCodeLinkStateConflict)
	}
	if l.Revision != input.ExpectedRevision {
		return api.Reject(api.ErrCodeStateChanged)
	}
	if l.ProposalDigest != input.ProposalDigest {
		return api.Reject(api.ErrCodeLinkProposalMismatch)
	}
	if input.ApprovedAt < l.ProposedAt || input.ApprovedAt >= l.ExpiresAt || tx.at.Unix() >= l.ExpiresAt+int64(api.ClockError.Seconds()) {
		return api.Reject(api.ErrCodeLinkStateConflict)
	}
	if _, _, err := tx.activeDomain(l.SourceDomain); err != nil {
		return api.Reject(api.ErrCodeLinkStateConflict)
	}
	srcID, err := get[api.Identity](tx.stub, api.Key("identity", l.SourceSubject))
	if err != nil || srcID.Status != api.Active || srcID.KeyVersion != l.SourceKeyVersion || srcID.AccountCommitment != l.SourceAccountCommitment {
		return api.Reject(api.ErrCodeLinkStateConflict)
	}
	dstID, err := get[api.Identity](tx.stub, api.Key("identity", l.TargetSubject))
	if err != nil || dstID.Status != api.Active || dstID.KeyVersion != l.TargetKeyVersion || dstID.AccountCommitment != l.TargetAccountCommitment {
		return api.Reject(api.ErrCodeLinkStateConflict)
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
		return api.Reject(api.ErrCodeInvalidStructure)
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
		return api.Reject(api.ErrCodeUnauthorized)
	}
	if l.Status != api.Pending && l.Status != api.Active {
		return api.Reject(api.ErrCodeLinkStateConflict)
	}
	if l.Revision != m.ExpectedRevision {
		return api.Reject(api.ErrCodeStateChanged)
	}
	l.Status = api.Revoked
	l.EffectiveActive = false
	l.RevokedBy = tx.caller.String()
	l.RevokedAt = tx.at.Unix()
	l.Reason = m.Reason
	l.Revision++
	return tx.put(key, l)
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
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	if subject.Status != api.Active || issuer.Status != api.Active || !tx.current(c.Interval) {
		return api.Reject(api.ErrCodeInvalidState)
	}
	d, cert, err := tx.activeDomain(subject.Domain)
	if err != nil {
		return err
	}
	if signing && !c.Interval.Within(cert.Interval) {
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	if !slices.Contains(d.Issuers, issuer.ID) || !api.ValidStringSet(c.ClaimNames) {
		return api.Reject(api.ErrCodeInvalidStructure)
	}
	for _, s := range cert.Scopes {
		if s.ID == c.Issuer && s.AppKeyVersion == c.IssuerKeyVersion && slices.Contains(s.CredentialTypes, c.Type) {
			for _, claim := range c.ClaimNames {
				if !slices.Contains(s.ClaimNames, claim) {
					return api.Reject(api.ErrCodeInvalidStructure)
				}
			}
			return nil
		}
	}
	return api.Reject(api.ErrCodeInvalidStructure)
}

func (tx transaction) registerCredential(c api.Credential) error {
	if !tx.bound(c.Bound) || c.ID == "" || !api.IsDigest(c.Digest) {
		return api.Reject(api.ErrCodeInvalidStructure)
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
		return api.Reject(api.ErrCodeInvalidStructure)
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
		return api.Reject(api.ErrCodeAlreadyRevoked)
	}
	if c.Revision != m.ExpectedRevision || (m.ExpectedDigest != "" && c.Digest != m.ExpectedDigest) {
		return api.Reject(api.ErrCodeStateChanged)
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
		return c, api.Reject(api.ErrCodeInvalidStructure)
	}
	if c.Status != api.Active {
		return c, api.Reject(api.ErrCodeInvalidState)
	}
	return c, tx.credentialAuthority(c, false)
}
