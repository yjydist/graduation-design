package main

import (
	"slices"

	api "graduation-design/internal/fabricapi"
)

func (tx transaction) registerTask(t api.Task) error {
	authority := tx.boot.TaskCreator
	if t.Creator != authority.Subject || t.Domain != authority.Domain || tx.caller != authority.Management {
		return reject(denied)
	}
	if !tx.bound(t.Bound) || !api.IsDigest(t.ID) || !api.IsDigest(t.Digest) || t.Resource != tx.boot.ResourceID || t.Mode != api.RP {
		return reject(badInput)
	}
	key := api.Key("task", t.ID)
	if err := tx.vacant(key); err != nil {
		return err
	}
	i, err := get[api.Identity](tx.stub, api.Key("identity", t.Creator))
	if err != nil {
		return err
	}
	if i.Domain != t.Domain || i.Kind != "USER" {
		return reject(badInput)
	}
	if err := tx.match(i.Management, binding{Domain: i.Domain, Subject: i.ID, Role: i.Kind}); err != nil {
		return err
	}
	c, err := tx.validCredential(t.CreatorCredential, t.Creator, t.CreatorKeyVersion)
	if err != nil {
		return err
	}
	if !tx.current(t.Interval) || !t.Interval.Within(c.Interval) {
		return reject(badInput)
	}
	t.Version = api.Version{Status: api.Active, Revision: 1}
	return tx.put(key, t)
}

func (tx transaction) registerGrant(g api.Grant) error {
	if err := tx.checkGrant(g); err != nil {
		return err
	}
	g.Version = api.Version{Status: api.Active, Revision: 1}
	return tx.put(api.Key("grant", g.ID), g)
}

func (tx transaction) checkGrant(g api.Grant) error {
	if !tx.bound(g.Bound) || !api.IsDigest(g.ID) || !api.IsDigest(g.Digest) ||
		g.Schema != api.Schema || g.Issuer == g.Grantee || g.Depth > 32 {
		return reject(badInput)
	}
	if err := tx.vacant(api.Key("grant", g.ID)); err != nil {
		return err
	}
	t, err := get[api.Task](tx.stub, api.Key("task", g.Task))
	if err != nil {
		return err
	}
	if t.Status != api.Active || !tx.current(t.Interval) {
		return reject(invalid)
	}
	if _, err := tx.validCredential(t.CreatorCredential, t.Creator, t.CreatorKeyVersion); err != nil {
		return err
	}
	issuer, err := get[api.Identity](tx.stub, api.Key("identity", g.Issuer))
	if err != nil {
		return err
	}
	if err := tx.match(issuer.Management, binding{Domain: issuer.Domain, Subject: issuer.ID, Role: issuer.Kind}); err != nil {
		return err
	}
	if g.Mode != t.Mode || g.Resource != t.Resource || g.Domain != t.Domain || !tx.current(g.Interval) || !g.Interval.Within(t.Interval) {
		return reject(badInput)
	}
	if err := tx.grantCredentials(g); err != nil {
		return err
	}
	if g.Parent == "" {
		if g.ParentDigest != "" || g.Root != g.ID || g.Issuer != tx.boot.ResourceOwner ||
			issuer.Management != tx.boot.ResourceManagement || issuer.Domain != "C" || issuer.Kind != "SERVICE" || g.Grantee != t.Creator {
			return reject(badInput)
		}
		return nil
	}
	for child, depth := g, 0; depth <= 32; depth++ {
		p, err := get[api.Grant](tx.stub, api.Key("grant", child.Parent))
		if err != nil {
			return err
		}
		if p.Status != api.Active || !tx.current(p.Interval) {
			return reject(invalid)
		}
		if p.Grantee != child.Issuer || p.GranteeKeyVersion != child.IssuerKeyVersion || p.GranteeCredential != child.IssuerCredential {
			return reject(denied)
		}
		if p.Digest != child.ParentDigest || p.Root != child.Root || p.Task != child.Task ||
			p.Mode != child.Mode || p.Resource != child.Resource || p.Domain != child.Domain ||
			!child.Interval.Within(p.Interval) || child.Depth >= p.Depth {
			return reject(badInput)
		}
		if err := tx.grantCredentials(p); err != nil {
			return err
		}
		if p.Parent == "" {
			if p.ID != g.Root {
				return reject(badInput)
			}
			return nil
		}
		child = p
	}
	return reject(badInput)
}

func (tx transaction) grantCredentials(g api.Grant) error {
	issuer, err := tx.validCredential(g.IssuerCredential, g.Issuer, g.IssuerKeyVersion)
	if err != nil {
		return err
	}
	grantee, err := tx.validCredential(g.GranteeCredential, g.Grantee, g.GranteeKeyVersion)
	if err != nil {
		return err
	}
	if !g.Interval.Within(issuer.Interval) || !g.Interval.Within(grantee.Interval) {
		return reject(badInput)
	}
	return nil
}

func (tx transaction) revocable(m api.Mutation, issuerOnly bool) (api.Grant, error) {
	if !tx.bound(m.Bound) {
		return api.Grant{}, reject(badInput)
	}
	g, err := get[api.Grant](tx.stub, api.Key("grant", m.ID))
	if err != nil {
		return g, err
	}
	if tx.caller == tx.boot.Root.Management {
		return g, reject(denied)
	}
	caller, err := get[binding](tx.stub, api.Key("binding", tx.caller.String()))
	if err != nil {
		return g, reject(denied)
	}
	i, err := get[api.Identity](tx.stub, api.Key("identity", caller.Subject))
	if err != nil {
		return g, reject(denied)
	}
	if i.Management != tx.caller || i.Domain != caller.Domain || i.Kind != caller.Role {
		return g, reject(denied)
	}
	allowed := i.ID == g.Issuer
	if !issuerOnly && !allowed {
		root, err := get[api.Grant](tx.stub, api.Key("grant", g.Root))
		if err != nil {
			return g, err
		}
		allowed = slices.Contains([]string{g.Grantee, root.Issuer, tx.boot.ResourceOwner}, i.ID)
	}
	if !allowed {
		return g, reject(denied)
	}
	if g.Revision != m.ExpectedRevision || g.Digest != m.ExpectedDigest {
		return g, reject(stale)
	}
	if g.Status != api.Active {
		return g, reject(invalid)
	}
	g.Status = api.Revoked
	g.Revision++
	return g, nil
}

func (tx transaction) revoke(m api.Mutation) error {
	g, err := tx.revocable(m, false)
	if err != nil {
		return err
	}
	return tx.put(api.Key("grant", g.ID), g)
}

func (tx transaction) replace(r api.Replacement) error {
	old, err := tx.revocable(r.Old, true)
	if err != nil {
		return err
	}
	next := r.New
	if next.ID == old.ID || next.Issuer != old.Issuer || next.Parent != old.Parent ||
		next.Task != old.Task || next.Mode != old.Mode || (old.Parent != "" && next.Root != old.Root) {
		return reject(badInput)
	}
	if err := tx.checkGrant(next); err != nil {
		return err
	}
	if err := tx.put(api.Key("grant", old.ID), old); err != nil {
		return err
	}
	next.Version = api.Version{Status: api.Active, Revision: 1}
	return tx.put(api.Key("grant", next.ID), next)
}
