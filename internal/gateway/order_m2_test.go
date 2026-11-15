package gateway_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"graduation-design/internal/fabric"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/policy"
	"graduation-design/internal/protocol"

	"github.com/jackc/pgx/v5/pgxpool"
)

type m2ChainFixture struct {
	mode     string
	taskID   string
	grants   []string
	ancCreds []protocol.AncestorCredential
	tp       []protocol.TrustPathEntry
	g1ID     string
	g1       api.Grant
}

type m2GatewayHarness struct {
	pool           *pgxpool.Pool
	depID          string
	serviceDID     string
	audience       string
	supplierID     string
	didB1          string
	didUinB        string
	privB1         *ecdsa.PrivateKey
	privUinB       *ecdsa.PrivateKey
	b1KeyID        string
	uInBKeyID      string
	b1PresPrefix   string
	uInBPresPrefix string
	spec           protocol.TaskSpec
	rp             m2ChainFixture
	bm             m2ChainFixture
	boot           api.Bootstrap
	rootRec        api.RootRecord
	state          *fabric.StateProvider
	delivery       *fabric.DeliveryService
	dids           *protocol.DIDWebResolver
	bundle         *policy.VerifiedBundle
	policyDeadline int64
	fixedNow       time.Time
}

func newM2GatewayHarness(t *testing.T) *m2GatewayHarness {
	t.Helper()
	pool := openTestPool(t)
	ctx := t.Context()

	now := time.Now().UTC().Truncate(time.Second)
	ca, err := protocol.GenerateTestCA(now)
	if err != nil {
		t.Fatal(err)
	}
	caPool, err := protocol.ParseTestCAPublic(ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	certs := make(map[string]*protocol.HostTLSCert, len(protocol.ControlledTestDomains))
	for _, host := range protocol.ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		if err != nil {
			t.Fatal(err)
		}
		certs[host] = hc
	}

	privT, pubT, _ := protocol.GenerateP256KeyPair()
	privIA, pubIA, _ := protocol.GenerateP256KeyPair()
	privIB, pubIB, _ := protocol.GenerateP256KeyPair()
	privIC, pubIC, _ := protocol.GenerateP256KeyPair()
	_, pubDomA, _ := protocol.GenerateP256KeyPair()
	_, pubDomB, _ := protocol.GenerateP256KeyPair()
	_, pubDomC, _ := protocol.GenerateP256KeyPair()
	privPA, pubPA, _ := protocol.GenerateP256KeyPair()
	privU, pubU, _ := protocol.GenerateP256KeyPair()
	privA1, pubA1, _ := protocol.GenerateP256KeyPair()
	privB1, pubB1, _ := protocol.GenerateP256KeyPair()
	privUinB, pubUinB, _ := protocol.GenerateP256KeyPair()
	privC, pubC, _ := protocol.GenerateP256KeyPair()

	didT := "did:web:t.local"
	didA, didB, didC := "did:web:a.local", "did:web:b.local", "did:web:c.local"
	didIA, didIB, didIC := "did:web:a.local:ia", "did:web:b.local:ib", "did:web:c.local:ic"
	didPA, didU, didA1 := "did:web:a.local:pa", "did:web:a.local:u", "did:web:a.local:a1"
	didB1, didUinB, didCSvc := "did:web:b.local:b1", "did:web:b.local:u-in-b", "did:web:c.local:supplier"

	docs := map[string][]byte{}
	makeDoc := func(did, pub string) string {
		d, err := protocol.NewDIDDocument(did, did+"#key-1", pub, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := protocol.MarshalJCS(d)
		if err != nil {
			t.Fatal(err)
		}
		dig, err := d.Digest()
		if err != nil {
			t.Fatal(err)
		}
		docs[did] = raw
		return dig
	}
	digT := makeDoc(didT, pubT)
	digA, digB, digC := makeDoc(didA, pubDomA), makeDoc(didB, pubDomB), makeDoc(didC, pubDomC)
	digIA, digIB, digIC := makeDoc(didIA, pubIA), makeDoc(didIB, pubIB), makeDoc(didIC, pubIC)
	digPA, digU, digA1 := makeDoc(didPA, pubPA), makeDoc(didU, pubU), makeDoc(didA1, pubA1)
	digB1, digUinB, digCSvc := makeDoc(didB1, pubB1), makeDoc(didUinB, pubUinB), makeDoc(didCSvc, pubC)

	srv, err := protocol.NewDIDWebServer(certs, docs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	dids, err := protocol.NewDIDWebResolver(caPool, srv.Routes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dids.RegisterPreseed(protocol.RootPreseed{
		DID: didT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKeyHex: pubT, DIDDocumentDigest: digT, RawDocument: docs[didT],
	}); err != nil {
		t.Fatal(err)
	}

	tag := fmt.Sprintf("m2-gw-%d", time.Now().UnixNano())
	depID := api.Digest([]byte("dep:" + tag))
	resID := "urn:grad:resource:C:orders"
	nbf := now.Add(-time.Hour).Unix()
	exp := now.Add(time.Hour).Unix()
	policyDeadline := now.Add(2 * time.Hour).Unix()
	vf := time.Unix(nbf, 0).UTC().Format(time.RFC3339)
	vu := time.Unix(exp, 0).UTC().Format(time.RFC3339)

	boot := api.Bootstrap{
		DeploymentFields: api.DeploymentFields{
			ChannelID: api.Channel, GenesisHash: api.Digest([]byte("gen:" + tag)),
			InstanceID: api.Digest([]byte("inst:" + tag)), RegistryName: api.Registry, SchemaVersion: api.Schema,
		},
		Root: api.RootRecord{
			DID: didT, DocumentDigest: digT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKey: pubT,
			Management: api.Management{MSPID: "TMsp", Fingerprint: api.Digest([]byte("t-mgmt:" + tag))},
		},
	}

	issueCert := func(id, domID, domDID, issDID string) (string, api.Domain, api.Certification) {
		jws, dig, err := protocol.SignDomainAuthorityCredential(privT, didT+"#key-1", &protocol.DomainAuthorityCredential{
			Type: []string{protocol.CredentialTypeVC, protocol.CredentialTypeDomainAuthority}, ID: id, DeploymentID: depID,
			Issuer: didT, Iss: didT, Sub: domDID, IssuerKeyVersion: 1, ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
			CredentialStatus: protocol.CredentialStatus{ID: id, Type: protocol.StatusTypeDomainCertification},
			CredentialSubject: protocol.DomainAuthoritySubject{
				ID: domDID, DomainID: domID, IdentityIssuers: []protocol.IssuerScope{{ID: issDID, AppKeyVersion: 1, CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity}, ClaimNames: []string{"domain", "role"}}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		dom := api.Domain{Bound: api.Bound{DeploymentID: depID}, ID: domID, DID: domDID, Issuers: []string{issDID}, Certification: id, Version: api.Version{Status: api.Active, Revision: 2}}
		if domID == "A" {
			dom.PurchasingAuthority = didPA
		}
		cert := api.Certification{
			Bound: api.Bound{DeploymentID: depID}, ID: id, Domain: domID, RootKeyVersion: 1, Digest: dig,
			Scopes:   []api.Scope{{ID: issDID, KeyVersion: 1, Types: []string{protocol.CredentialTypeEnterpriseIdentity}, Claims: []string{"domain", "role"}}},
			Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
		}
		return jws, dom, cert
	}
	certAJWS, domA, certA := issueCert("urn:grad:cert:A:"+tag, "A", didA, didIA)
	certBJWS, domB, certB := issueCert("urn:grad:cert:B:"+tag, "B", didB, didIB)
	certCJWS, domC, certC := issueCert("urn:grad:cert:C:"+tag, "C", didC, didIC)

	makeID := func(id, dom, kind, dig, pub string) api.Identity {
		return api.Identity{
			Bound: api.Bound{DeploymentID: depID}, ID: id, Domain: dom, Kind: kind,
			Management:     api.Management{MSPID: dom + "Msp", Fingerprint: api.Digest([]byte("mgmt:" + id + ":" + tag))},
			DocumentDigest: dig, KeyID: id + "#key-1", KeyVersion: 1, PublicKey: pub,
			AccountCommitment: api.Digest([]byte("acct:" + depID + ":" + id)),
			Version:           api.Version{Status: api.Active, Revision: 1},
		}
	}
	idA := makeID(didA, "A", "DOMAIN", digA, pubDomA)
	idB := makeID(didB, "B", "DOMAIN", digB, pubDomB)
	idC_dom := makeID(didC, "C", "DOMAIN", digC, pubDomC)
	idIA := makeID(didIA, "A", "ISSUER", digIA, pubIA)
	idIB := makeID(didIB, "B", "ISSUER", digIB, pubIB)
	idIC := makeID(didIC, "C", "ISSUER", digIC, pubIC)
	idPA := makeID(didPA, "A", "SERVICE", digPA, pubPA)
	idU := makeID(didU, "A", "USER", digU, pubU)
	idA1 := makeID(didA1, "A", "AGENT", digA1, pubA1)
	idB1 := makeID(didB1, "B", "AGENT", digB1, pubB1)
	idUinB := makeID(didUinB, "B", "USER", digUinB, pubUinB)
	idC := makeID(didCSvc, "C", "SERVICE", digCSvc, pubC)

	issueCred := func(id, issDID, subDID, dom, role, pub string, priv *ecdsa.PrivateKey) (*protocol.SignedSDJWTCredential, api.Credential) {
		jwk, err := protocol.AppPublicKeyToJWK(pub)
		if err != nil {
			t.Fatal(err)
		}
		s, err := protocol.IssueEnterpriseIdentityCredential(priv, issDID+"#key-1", protocol.EnterpriseIdentityCredential{
			Type: []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity}, ID: id, DeploymentID: depID,
			Issuer: issDID, Iss: issDID, Sub: subDID, IssuerKeyVersion: 1, AppKeyVersion: 1,
			ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
			CredentialStatus: protocol.CredentialStatus{ID: id, Type: protocol.StatusTypeCredential},
			Cnf:              protocol.ConfirmationKey{JWK: jwk}, CredentialSubject: protocol.SDJWTCredentialSubject{ID: subDID},
		}, dom, role, nil)
		if err != nil {
			t.Fatal(err)
		}
		return s, api.Credential{
			Bound: api.Bound{DeploymentID: depID}, ID: id, Issuer: issDID, Subject: subDID,
			IssuerKeyVersion: 1, SubjectKeyVersion: 1, Type: protocol.CredentialTypeEnterpriseIdentity,
			ClaimNames: []string{"domain", "role"}, Digest: s.AnchorDigest,
			Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
		}
	}
	sdPA, credPA := issueCred("urn:grad:cred:PA:"+tag, didIA, didPA, "A", "procurement-authority", pubPA, privIA)
	sdU, credU := issueCred("urn:grad:cred:U:"+tag, didIA, didU, "A", "procurement-owner", pubU, privIA)
	sdA1, credA1 := issueCred("urn:grad:cred:A1:"+tag, didIA, didA1, "A", "procurement-agent", pubA1, privIA)
	sdB1, credB1 := issueCred("urn:grad:cred:B1:"+tag, didIB, didB1, "B", "broker-agent", pubB1, privIB)
	sdUinB, credUinB := issueCred("urn:grad:cred:UinB:"+tag, didIB, didUinB, "B", "procurement-owner", pubUinB, privIB)
	sdC, credC := issueCred("urn:grad:cred:C:"+tag, didIC, didCSvc, "C", "supplier-service", pubC, privIC)

	spec := protocol.TaskSpec{
		SupplierID:  "urn:grad:supplier:C",
		ProductID:   gateway.DefaultProductID,
		MaxQuantity: 1,
		Currency:    "CNY",
		Resources:   []string{"urn:grad:resource:C:orders", "urn:grad:resource:C:quotes"},
		Actions:     []string{"order.create", "quote.read"},
		Description: "M2 order acceptance",
	}
	specDig, _ := spec.Digest()

	makeChain := func(mode, prefix, rootDID, rootCredID string, rootPres string, rootPriv *ecdsa.PrivateKey, includeC bool) (api.Task, []api.Grant, m2ChainFixture) {
		tID := api.Digest([]byte(prefix + ":task:" + tag))
		g0ID := api.Digest([]byte(prefix + ":g0:" + tag))
		g1ID := api.Digest([]byte(prefix + ":g1:" + tag))
		g2ID := api.Digest([]byte(prefix + ":g2:" + tag))
		tRec := api.Task{
			Bound: api.Bound{DeploymentID: depID}, ID: tID, Creator: didU, CreatorCredential: credU.ID, CreatorKeyVersion: 1,
			Domain: "A", Mode: mode, Resource: resID, Digest: specDig, Interval: api.Interval{NBF: nbf, EXP: exp},
			Version: api.Version{Status: api.Active, Revision: 1},
		}
		g0C := protocol.GrantClaims{
			ID: g0ID, SchemaVersion: protocol.SchemaVersion, DeploymentID: depID, RootID: g0ID, TaskID: tID,
			AuthorizationMode: mode, PrincipalDomain: "A", ResourceID: resID, Issuer: rootDID, Grantee: didU,
			IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: rootCredID, GranteeCredentialID: credU.ID,
			Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{spec.SupplierID},
			Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 2,
		}
		g0JWS, g0Dig, _ := protocol.SignGrant(rootPriv, rootDID+"#key-1", &g0C)
		g1C := protocol.GrantClaims{
			ID: g1ID, SchemaVersion: protocol.SchemaVersion, DeploymentID: depID, ParentID: &g0ID, ParentDigest: &g0Dig,
			RootID: g0ID, TaskID: tID, AuthorizationMode: mode, PrincipalDomain: "A", ResourceID: resID,
			Issuer: didU, Grantee: didA1, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
			IssuerCredentialID: credU.ID, GranteeCredentialID: credA1.ID,
			Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{spec.SupplierID},
			Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 1,
		}
		g1JWS, g1Dig, _ := protocol.SignGrant(privU, didU+"#key-1", &g1C)
		g2C := protocol.GrantClaims{
			ID: g2ID, SchemaVersion: protocol.SchemaVersion, DeploymentID: depID, ParentID: &g1ID, ParentDigest: &g1Dig,
			RootID: g0ID, TaskID: tID, AuthorizationMode: mode, PrincipalDomain: "A", ResourceID: resID,
			Issuer: didA1, Grantee: didB1, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
			IssuerCredentialID: credA1.ID, GranteeCredentialID: credB1.ID,
			Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{spec.SupplierID},
			Aud: "https://c.local", Currency: "CNY", MaxAmountMinor: 100000, NBF: nbf, EXP: exp, RemainingDepth: 0,
		}
		g2JWS, g2Dig, _ := protocol.SignGrant(privA1, didA1+"#key-1", &g2C)
		g0Chain := api.Grant{Bound: api.Bound{DeploymentID: depID}, ID: g0ID, Schema: api.Schema, Root: g0ID, Task: tID, Mode: mode, Domain: "A", Resource: resID, Issuer: rootDID, Grantee: didU, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: rootCredID, GranteeCredential: credU.ID, Depth: 2, Digest: g0Dig, Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1}}
		g1Chain := api.Grant{Bound: api.Bound{DeploymentID: depID}, ID: g1ID, Schema: api.Schema, Parent: g0ID, ParentDigest: g0Dig, Root: g0ID, Task: tID, Mode: mode, Domain: "A", Resource: resID, Issuer: didU, Grantee: didA1, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: credU.ID, GranteeCredential: credA1.ID, Depth: 1, Digest: g1Dig, Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1}}
		g2Chain := api.Grant{Bound: api.Bound{DeploymentID: depID}, ID: g2ID, Schema: api.Schema, Parent: g1ID, ParentDigest: g1Dig, Root: g0ID, Task: tID, Mode: mode, Domain: "A", Resource: resID, Issuer: didA1, Grantee: didB1, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: credA1.ID, GranteeCredential: credB1.ID, Depth: 0, Digest: g2Dig, Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1}}

		tp := []protocol.TrustPathEntry{
			{Issuer: didIA, DomainCertification: certAJWS},
			{Issuer: didIB, DomainCertification: certBJWS},
		}
		if includeC {
			tp = append(tp, protocol.TrustPathEntry{Issuer: didIC, DomainCertification: certCJWS})
		}
		anc := []protocol.AncestorCredential{
			{CredentialID: credA1.ID, Presentation: sdA1.PresentationPrefix},
			{CredentialID: rootCredID, Presentation: rootPres},
			{CredentialID: credU.ID, Presentation: sdU.PresentationPrefix},
		}
		if rootCredID < credA1.ID {
			anc[0], anc[1] = anc[1], anc[0]
		}
		return tRec, []api.Grant{g0Chain, g1Chain, g2Chain}, m2ChainFixture{
			mode: mode, taskID: tID, grants: []string{g0JWS, g1JWS, g2JWS}, ancCreds: anc, tp: tp, g1ID: g1ID, g1: g1Chain,
		}
	}

	rpTask, rpGrants, rpFix := makeChain(api.RP, "rp", didCSvc, credC.ID, sdC.PresentationPrefix, privC, true)
	bmTask, bmGrants, bmFix := makeChain(api.BM, "bm", didPA, credPA.ID, sdPA.PresentationPrefix, privPA, false)

	if err := gateway.EnsureSchema(ctx, pool, depID, "urn:grad:supplier:C"); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	putKV := func(k string, v any) {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1,$2,$3)
			ON CONFLICT(deployment,key) DO UPDATE SET value=EXCLUDED.value`, depID, k, raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO fabric_head(deployment, block_no, hash) VALUES($1,1,$2)`, depID, api.Digest([]byte("blk1:"+tag))); err != nil {
		t.Fatal(err)
	}
	putKV(api.BootstrapKey, boot)
	putKV(api.Key("domain", "A"), domA)
	putKV(api.Key("domain", "B"), domB)
	putKV(api.Key("domain", "C"), domC)
	putKV(api.Key("certification", certA.ID), certA)
	putKV(api.Key("certification", certB.ID), certB)
	putKV(api.Key("certification", certC.ID), certC)
	for _, id := range []api.Identity{idA, idB, idC_dom, idIA, idIB, idIC, idPA, idU, idA1, idB1, idUinB, idC} {
		putKV(api.Key("identity", id.ID), id)
	}
	for _, c := range []api.Credential{credPA, credU, credA1, credB1, credUinB, credC} {
		putKV(api.Key("credential", c.ID), c)
	}
	putKV(api.Key("task", rpTask.ID), rpTask)
	putKV(api.Key("task", bmTask.ID), bmTask)
	for _, g := range append(rpGrants, bmGrants...) {
		putKV(api.Key("grant", g.ID), g)
	}
	for _, item := range []struct{ domID, certID, jws, dig string }{
		{"A", certA.ID, certAJWS, certA.Digest},
		{"B", certB.ID, certBJWS, certB.Digest},
		{"C", certC.ID, certCJWS, certC.Digest},
	} {
		if _, err := tx.Exec(ctx, `INSERT INTO certification_receipts(
			deployment_id, domain_id, certification_id, recipient, cert_jws, cert_digest, received_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)`, depID, item.domID, item.certID, didCSvc, item.jws, item.dig, now.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM decision_evidence WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM order_outcome_outbox WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM orders WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM client_actions WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM quotes WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM decisions WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM business_keys WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM challenges WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM trusted_contexts WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM catalog_prices WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM certification_receipts WHERE deployment_id=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM fabric_current WHERE deployment=$1`, depID)
		_, _ = pool.Exec(bg, `DELETE FROM fabric_head WHERE deployment=$1`, depID)
	})

	files, dig, err := policy.BuildDefaultBundle(depID, didCSvc, policy.DefaultPolicyVersion, boot.Root, &policyDeadline)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := policy.VerifyAndLoadBundle(files, depID, didCSvc, boot.Root, dig)
	if err != nil {
		t.Fatal(err)
	}

	sp := fabric.NewStateProviderFromBootstrap(pool, depID, boot, nil)
	monoNow := now
	sp.SetMonoClock(func() time.Time { return monoNow })
	sp.SetStaticProbe(&fabric.ProbeSnapshot{
		TxID: "probe-" + tag, ProbeBlock: 1, SentAt: now, Deadline: now.Add(5 * time.Second),
		SentMonoNs: monoNow.UnixNano(), DeadlineMonoNs: monoNow.Add(5 * time.Second).UnixNano(),
		AdoptedAt: now, AdoptedMonoNs: monoNow.UnixNano(),
	})

	return &m2GatewayHarness{
		pool: pool, depID: depID, serviceDID: didCSvc, audience: "https://c.local", supplierID: "urn:grad:supplier:C",
		didB1: didB1, didUinB: didUinB, privB1: privB1, privUinB: privUinB,
		b1KeyID: didB1 + "#key-1", uInBKeyID: didUinB + "#key-1",
		b1PresPrefix: sdB1.PresentationPrefix, uInBPresPrefix: sdUinB.PresentationPrefix,
		spec: spec, rp: rpFix, bm: bmFix, boot: boot, rootRec: boot.Root,
		state: sp, delivery: fabric.NewDeliveryService(pool), dids: dids, bundle: bundle,
		policyDeadline: policyDeadline, fixedNow: now,
	}
}

func (h *m2GatewayHarness) newServer(nowFn func() time.Time, bundle *policy.VerifiedBundle) *gateway.Server {
	if bundle == nil {
		bundle = h.bundle
	}
	srv, err := gateway.NewServer(gateway.Config{
		DB: h.pool, State: h.state.GatewayAdapter(), Delivery: h.delivery, DIDs: h.dids, Policy: bundle,
		DeploymentID: h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID,
		ClockErrorMargin: api.ClockError, NowFn: nowFn,
	})
	if err != nil {
		panic(err)
	}
	return srv
}

func (h *m2GatewayHarness) postContext(t *testing.T, srv http.Handler, taskID string, ver int64, risk string, deadline int64) {
	t.Helper()
	b, _ := json.Marshal(gateway.ContextUpdateRequest{
		ExpectedContextVersion: ver, SourceID: "ctx-c", ObservedAt: h.fixedNow.Unix(), RiskLevel: risk, AccessDeadline: deadline,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/contexts/"+taskID, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update context status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func (h *m2GatewayHarness) execReq(t *testing.T, srv http.Handler, chain m2ChainFixture, nowUnix int64, actor, leafPres, keyID string, leafPriv *ecdsa.PrivateKey, accessReq protocol.AccessRequest) *httptest.ResponseRecorder {
	t.Helper()
	nowTime := time.Unix(nowUnix, 0).UTC()
	h.state.SetMonoClock(func() time.Time { return nowTime })
	h.state.SetStaticProbe(&fabric.ProbeSnapshot{
		TxID: "probe-" + h.depID[:8], ProbeBlock: 1, SentAt: nowTime, Deadline: nowTime.Add(5 * time.Second),
		SentMonoNs: nowTime.UnixNano(), DeadlineMonoNs: nowTime.Add(5 * time.Second).UnixNano(),
		AdoptedAt: nowTime, AdoptedMonoNs: nowTime.UnixNano(),
	})
	reqHash, err := accessReq.Hash(false)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := json.Marshal(gateway.ChallengeRequest{Actor: accessReq.Actor, TaskID: accessReq.TaskID, RequestHash: reqHash})
	crec := httptest.NewRecorder()
	creq := httptest.NewRequest(http.MethodPost, "/v1/auth/challenges", bytes.NewReader(cb))
	creq.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(crec, creq)
	if crec.Code != http.StatusCreated {
		t.Fatalf("challenge status=%d body=%s", crec.Code, crec.Body.String())
	}
	var chal gateway.ChallengeResponse
	_ = json.Unmarshal(crec.Body.Bytes(), &chal)

	pkg := protocol.AccessEvidencePackage{
		Request: accessReq, TaskSpec: h.spec, AncestorCredentials: chain.ancCreds, Grants: chain.grants, TrustPaths: chain.tp,
	}
	if _, _, err := protocol.AssembleAccessEvidencePackage(&pkg, leafPres, keyID, leafPriv, protocol.ChallengeContext{
		ChallengeID: chal.ChallengeID, Nonce: chal.Nonce, Audience: chal.Audience, IssuedAt: chal.IssuedAt, ExpiresAt: chal.ExpiresAt,
	}, nowUnix, false); err != nil {
		t.Fatal(err)
	}
	rawPkg, _ := json.Marshal(pkg)
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/access/execute", bytes.NewReader(rawPkg))
	httpReq.Header.Set("Content-Type", "application/json")
	srv.ServeHTTP(rec, httpReq)
	return rec
}

func TestGatewayM2OrderCreateRPAndBMPositiveAndLimits(t *testing.T) {
	h := newM2GatewayHarness(t)
	ctx := t.Context()
	var currentTime atomic.Int64
	currentTime.Store(h.fixedNow.Unix())
	srv := h.newServer(func() time.Time { return time.Unix(currentTime.Load(), 0).UTC() }, nil)
	handler := srv.Handler()

	h.postContext(t, handler, h.rp.taskID, 0, "NORMAL", h.policyDeadline)
	h.postContext(t, handler, h.bm.taskID, 0, "NORMAL", h.policyDeadline)

	makeReq := func(chain m2ChainFixture, action, resource string, qID *string, amt int64, ik string) protocol.AccessRequest {
		return protocol.AccessRequest{
			SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1,
			PrincipalDomain: "A", AuthorizationMode: chain.mode, TaskID: chain.taskID,
			Audience: h.audience, Resource: resource, Action: action, SupplierID: h.supplierID,
			QuoteID: qID, ProductID: gateway.DefaultProductID, Quantity: 1, Currency: "CNY",
			AmountMinor: amt, IdempotencyKey: ik,
		}
	}

	// 1. RP and BM 2-hop quote.read (80000) -> order.create -> 200 OK + order persisted + decision link.
	var q800BM string
	for _, tc := range []struct {
		name  string
		chain m2ChainFixture
	}{
		{"RP", h.rp},
		{"BM", h.bm},
	} {
		qRec := h.execReq(t, handler, tc.chain, currentTime.Load(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq(tc.chain, "quote.read", "urn:grad:resource:C:quotes", nil, 0, "q800-"+tc.name))
		if qRec.Code != http.StatusOK {
			t.Fatalf("%s quote.read failed: status=%d body=%s", tc.name, qRec.Code, qRec.Body.String())
		}
		var qResp gateway.ExecuteResponse
		_ = json.Unmarshal(qRec.Body.Bytes(), &qResp)
		if qResp.Quote == nil || qResp.Quote.TotalAmountMinor != 80000 {
			t.Fatalf("%s unexpected quote: %+v", tc.name, qResp)
		}
		if tc.name == "BM" {
			q800BM = qResp.Quote.QuoteID
		}

		// Local client_actions intent tracking before order.create.
		orderReq := makeReq(tc.chain, "order.create", "urn:grad:resource:C:orders", &qResp.Quote.QuoteID, 80000, "ord800-"+tc.name)
		reqHash, _ := orderReq.Hash(false)
		actRec, err := gateway.BeginClientAction(ctx, h.pool, h.depID, h.didB1, tc.chain.taskID, "order.create", orderReq.IdempotencyKey, reqHash, currentTime.Load())
		if err != nil || actRec.Status != "PENDING" {
			t.Fatalf("BeginClientAction failed: rec=%+v err=%v", actRec, err)
		}

		oRec := h.execReq(t, handler, tc.chain, currentTime.Load(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, orderReq)
		if oRec.Code != http.StatusOK {
			t.Fatalf("%s order.create failed: status=%d body=%s", tc.name, oRec.Code, oRec.Body.String())
		}
		var oResp gateway.ExecuteResponse
		_ = json.Unmarshal(oRec.Body.Bytes(), &oResp)
		if oResp.Order == nil || oResp.Order.TotalAmountMinor != 80000 || oResp.Order.QuoteID != qResp.Quote.QuoteID {
			t.Fatalf("%s unexpected order response: %+v", tc.name, oResp)
		}
		if err := gateway.UpdateClientAction(ctx, h.pool, h.depID, actRec.ActionID, "COMPLETED", "", qResp.Quote.QuoteID, oResp.Order.OrderID, oResp.DecisionID, currentTime.Load()); err != nil {
			t.Fatal(err)
		}

		// Decision GET includes both quoteId and orderId.
		dRec := httptest.NewRecorder()
		handler.ServeHTTP(dRec, httptest.NewRequest(http.MethodGet, "/v1/decisions/"+oResp.DecisionID, nil))
		if dRec.Code != http.StatusOK {
			t.Fatalf("GET decision status=%d", dRec.Code)
		}
		var dOut gateway.DecisionRecord
		_ = json.Unmarshal(dRec.Body.Bytes(), &dOut)
		if dOut.OrderID == nil || *dOut.OrderID != oResp.Order.OrderID || dOut.QuoteID == nil || *dOut.QuoteID != qResp.Quote.QuoteID {
			t.Fatalf("unexpected decision links: %+v", dOut)
		}
	}

	// Verify conflicting client_actions idempotency key fails locally with IDEMPOTENCY_CONFLICT.
	if _, err := gateway.BeginClientAction(ctx, h.pool, h.depID, h.didB1, h.rp.taskID, "order.create", "ord800-RP", api.Digest([]byte("other")), currentTime.Load()); !protocol.HasCode(err, protocol.ErrCodeIdempotencyConflict) {
		t.Fatalf("expected client_actions IDEMPOTENCY_CONFLICT, got %v", err)
	}

	// 2. Preset P1 catalog price to 120000 -> quote.read -> Q1200 -> amount 80000 -> 409 AMOUNT_MISMATCH, amount 120000 -> 403 AMOUNT_LIMIT_EXCEEDED.
	if _, err := h.pool.Exec(ctx, `UPDATE catalog_prices SET unit_price_minor=120000 WHERE deployment_id=$1 AND product_id=$2`, h.depID, gateway.DefaultProductID); err != nil {
		t.Fatal(err)
	}
	q1200Rec := h.execReq(t, handler, h.rp, currentTime.Load(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq(h.rp, "quote.read", "urn:grad:resource:C:quotes", nil, 0, "q1200-rp"))
	if q1200Rec.Code != http.StatusOK {
		t.Fatalf("Q1200 quote.read failed: %d %s", q1200Rec.Code, q1200Rec.Body.String())
	}
	var q1200Resp gateway.ExecuteResponse
	_ = json.Unmarshal(q1200Rec.Body.Bytes(), &q1200Resp)
	if q1200Resp.Quote.TotalAmountMinor != 120000 {
		t.Fatalf("expected 120000 quote, got %d", q1200Resp.Quote.TotalAmountMinor)
	}

	tamperAmtRec := h.execReq(t, handler, h.rp, currentTime.Load(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq(h.rp, "order.create", "urn:grad:resource:C:orders", &q1200Resp.Quote.QuoteID, 80000, "ord-tamper-amt"))
	if tamperAmtRec.Code != http.StatusConflict || !bytes.Contains(tamperAmtRec.Body.Bytes(), []byte(protocol.ErrCodeAmountMismatch)) {
		t.Fatalf("expected 409 AMOUNT_MISMATCH, got status=%d body=%s", tamperAmtRec.Code, tamperAmtRec.Body.String())
	}
	overLimitRec := h.execReq(t, handler, h.rp, currentTime.Load(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq(h.rp, "order.create", "urn:grad:resource:C:orders", &q1200Resp.Quote.QuoteID, 120000, "ord-over-limit"))
	if overLimitRec.Code != http.StatusForbidden || !bytes.Contains(overLimitRec.Body.Bytes(), []byte(protocol.ErrCodeAmountLimitExceeded)) {
		t.Fatalf("expected 403 AMOUNT_LIMIT_EXCEEDED, got status=%d body=%s", overLimitRec.Code, overLimitRec.Body.String())
	}

	// 3. Cross-task quote -> 403 QUOTE_SCOPE_MISMATCH.
	scopeRec := h.execReq(t, handler, h.rp, currentTime.Load(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq(h.rp, "order.create", "urn:grad:resource:C:orders", &q800BM, 80000, "ord-scope-mismatch"))
	if scopeRec.Code != http.StatusForbidden || !bytes.Contains(scopeRec.Body.Bytes(), []byte(protocol.ErrCodeQuoteScopeMismatch)) {
		t.Fatalf("expected 403 QUOTE_SCOPE_MISMATCH, got status=%d body=%s", scopeRec.Code, scopeRec.Body.String())
	}

	// 4. Custom supplier bundle rejecting BM -> 403 SUPPLIER_POLICY_DENIED.
	rpOnlyFiles, rpOnlyDig, err := policy.BuildCustomBundle(h.depID, h.serviceDID, "1.0.1", h.rootRec, policy.RolesConfig{
		AcceptedAuthorizationModes: []string{api.RP}, AcceptedAuthorityRoles: []string{}, AcceptedBuyerDomains: []string{"A"}, AcceptedServiceRoles: []string{"supplier-service"},
	}, policy.ResourcesConfig{
		AllowedActions: []string{"quote.read", "order.create"}, AllowedProductIDs: []string{gateway.DefaultProductID}, MaxQuantity: 10, PolicyDeadline: &h.policyDeadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	rpOnlyBundle, err := policy.VerifyAndLoadBundle(rpOnlyFiles, h.depID, h.serviceDID, h.rootRec, rpOnlyDig)
	if err != nil {
		t.Fatal(err)
	}
	srvRPOnly := h.newServer(func() time.Time { return time.Unix(currentTime.Load(), 0).UTC() }, rpOnlyBundle)
	denyBMRec := h.execReq(t, srvRPOnly.Handler(), h.bm, currentTime.Load(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq(h.bm, "order.create", "urn:grad:resource:C:orders", &q800BM, 80000, "ord-bm-denied"))
	if denyBMRec.Code != http.StatusForbidden || !bytes.Contains(denyBMRec.Body.Bytes(), []byte(protocol.ErrCodeSupplierPolicyDenied)) {
		t.Fatalf("expected 403 SUPPLIER_POLICY_DENIED, got status=%d body=%s", denyBMRec.Code, denyBMRec.Body.String())
	}

	// 5. Quote expired -> 409 QUOTE_EXPIRED.
	currentTime.Store(h.fixedNow.Unix() + 300) // validUntil = issuedAt + 300 exact boundary
	expRec := h.execReq(t, handler, h.bm, currentTime.Load(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq(h.bm, "order.create", "urn:grad:resource:C:orders", &q800BM, 80000, "ord-expired"))
	if expRec.Code != http.StatusConflict || !bytes.Contains(expRec.Body.Bytes(), []byte(protocol.ErrCodeQuoteExpired)) {
		t.Fatalf("expected 409 QUOTE_EXPIRED, got status=%d body=%s", expRec.Code, expRec.Body.String())
	}

	var orderCount int
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM orders WHERE deployment_id=$1`, h.depID).Scan(&orderCount); err != nil {
		t.Fatal(err)
	}
	if orderCount != 2 {
		t.Fatalf("expected exactly 2 committed orders (RP + BM 80000), got %d", orderCount)
	}
}

func TestGatewayM2PostLockDynamicChecksAndIsolation(t *testing.T) {
	h := newM2GatewayHarness(t)
	ctx := t.Context()
	nowFn := func() time.Time { return h.fixedNow }
	srv := h.newServer(nowFn, nil)
	handler := srv.Handler()

	h.postContext(t, handler, h.bm.taskID, 0, "NORMAL", h.policyDeadline)

	qRec := h.execReq(t, handler, h.bm, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, protocol.AccessRequest{
		SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1, PrincipalDomain: "A",
		AuthorizationMode: h.bm.mode, TaskID: h.bm.taskID, Audience: h.audience, Resource: "urn:grad:resource:C:quotes",
		Action: "quote.read", SupplierID: h.supplierID, ProductID: gateway.DefaultProductID, Quantity: 1, Currency: "CNY",
		IdempotencyKey: "dyn-q800",
	})
	var qResp gateway.ExecuteResponse
	_ = json.Unmarshal(qRec.Body.Bytes(), &qResp)

	// 1. BeforeLockTx escalates trusted context to BLOCKED -> 403 POLICY_DENIED & no new order.
	srv.SetTestHooks(func(attempt int) {
		if attempt == 0 {
			h.postContext(t, handler, h.bm.taskID, 1, "BLOCKED", h.policyDeadline)
		}
	}, nil)
	blockedRec := h.execReq(t, handler, h.bm, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, protocol.AccessRequest{
		SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1, PrincipalDomain: "A",
		AuthorizationMode: h.bm.mode, TaskID: h.bm.taskID, Audience: h.audience, Resource: "urn:grad:resource:C:orders",
		Action: "order.create", SupplierID: h.supplierID, QuoteID: &qResp.Quote.QuoteID, ProductID: gateway.DefaultProductID,
		Quantity: 1, Currency: "CNY", AmountMinor: 80000, IdempotencyKey: "dyn-ord-blocked",
	})
	if blockedRec.Code != http.StatusForbidden || !bytes.Contains(blockedRec.Body.Bytes(), []byte(protocol.ErrCodePolicyDenied)) {
		t.Fatalf("expected 403 POLICY_DENIED after risk escalation, got status=%d body=%s", blockedRec.Code, blockedRec.Body.String())
	}

	// Reset hooks & context to NORMAL, then U-in-B isolation test -> 401 HOLDER_MISMATCH.
	srv.SetTestHooks(nil, nil)
	h.postContext(t, handler, h.bm.taskID, 2, "NORMAL", h.policyDeadline)
	uinBRec := h.execReq(t, handler, h.bm, h.fixedNow.Unix(), h.didUinB, h.uInBPresPrefix, h.uInBKeyID, h.privUinB, protocol.AccessRequest{
		SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didUinB, PrincipalDomain: "A",
		AuthorizationMode: h.bm.mode, TaskID: h.bm.taskID, Audience: h.audience, Resource: "urn:grad:resource:C:orders",
		Action: "order.create", SupplierID: h.supplierID, QuoteID: &qResp.Quote.QuoteID, ProductID: gateway.DefaultProductID,
		Quantity: 1, Currency: "CNY", AmountMinor: 80000, IdempotencyKey: "dyn-ord-uinb",
	})
	if uinBRec.Code != http.StatusUnauthorized || !bytes.Contains(uinBRec.Body.Bytes(), []byte(protocol.ErrCodeHolderMismatch)) {
		t.Fatalf("expected 401 HOLDER_MISMATCH for U-in-B on B1 path, got status=%d body=%s", uinBRec.Code, uinBRec.Body.String())
	}

	// 2. Suspend ancestor G1 on ledger snapshot -> 403 ANCESTOR_INACTIVE.
	suspG1 := h.bm.g1
	suspG1.Status = api.Suspended
	rawG1, _ := json.Marshal(suspG1)
	if _, err := h.pool.Exec(ctx, `UPDATE fabric_current SET value=$1 WHERE deployment=$2 AND key=$3`, rawG1, h.depID, api.Key("grant", h.bm.g1ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `UPDATE fabric_head SET block_no=2, hash=$1 WHERE deployment=$2`, api.Digest([]byte("blk2")), h.depID); err != nil {
		t.Fatal(err)
	}
	ancRec := h.execReq(t, handler, h.bm, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, protocol.AccessRequest{
		SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1, PrincipalDomain: "A",
		AuthorizationMode: h.bm.mode, TaskID: h.bm.taskID, Audience: h.audience, Resource: "urn:grad:resource:C:orders",
		Action: "order.create", SupplierID: h.supplierID, QuoteID: &qResp.Quote.QuoteID, ProductID: gateway.DefaultProductID,
		Quantity: 1, Currency: "CNY", AmountMinor: 80000, IdempotencyKey: "dyn-ord-anc",
	})
	if ancRec.Code != http.StatusForbidden || !bytes.Contains(ancRec.Body.Bytes(), []byte(protocol.ErrCodeAncestorInactive)) {
		t.Fatalf("expected 403 ANCESTOR_INACTIVE after G1 suspension, got status=%d body=%s", ancRec.Code, ancRec.Body.String())
	}

	var count int
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM orders WHERE deployment_id=$1`, h.depID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected 0 orders after dynamic rejections, got %d", count)
	}
}

func TestGatewayM2DualInstanceConcurrentOrderIdempotency(t *testing.T) {
	h := newM2GatewayHarness(t)
	ctx := t.Context()
	nowFn := func() time.Time { return h.fixedNow }
	srv8103 := h.newServer(nowFn, nil)
	srv8104 := h.newServer(nowFn, nil)
	h8103 := srv8103.Handler()
	h8104 := srv8104.Handler()

	h.postContext(t, h8103, h.bm.taskID, 0, "NORMAL", h.policyDeadline)

	qRec := h.execReq(t, h8103, h.bm, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, protocol.AccessRequest{
		SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1, PrincipalDomain: "A",
		AuthorizationMode: h.bm.mode, TaskID: h.bm.taskID, Audience: h.audience, Resource: "urn:grad:resource:C:quotes",
		Action: "quote.read", SupplierID: h.supplierID, ProductID: gateway.DefaultProductID, Quantity: 1, Currency: "CNY",
		IdempotencyKey: "dual-q800",
	})
	var qResp gateway.ExecuteResponse
	_ = json.Unmarshal(qRec.Body.Bytes(), &qResp)

	sameReq := protocol.AccessRequest{
		SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1, PrincipalDomain: "A",
		AuthorizationMode: h.bm.mode, TaskID: h.bm.taskID, Audience: h.audience, Resource: "urn:grad:resource:C:orders",
		Action: "order.create", SupplierID: h.supplierID, QuoteID: &qResp.Quote.QuoteID, ProductID: gateway.DefaultProductID,
		Quantity: 1, Currency: "CNY", AmountMinor: 80000, IdempotencyKey: "dual-ord-same",
	}

	// Issue two separate challenges for the two concurrent instances.
	var wg sync.WaitGroup
	wg.Add(2)
	results := make([]*httptest.ResponseRecorder, 2)
	handlers := []http.Handler{h8103, h8104}
	for idx := 0; idx < 2; idx++ {
		go func(i int) {
			defer wg.Done()
			results[i] = h.execReq(t, handlers[i], h.bm, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, sameReq)
		}(idx)
	}
	wg.Wait()

	var orderIDs [2]string
	for idx, rec := range results {
		if rec.Code != http.StatusOK {
			t.Fatalf("instance %d concurrent order.create failed: status=%d body=%s", idx, rec.Code, rec.Body.String())
		}
		var out gateway.ExecuteResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Order == nil || out.Order.OrderID == "" {
			t.Fatalf("instance %d missing order in response", idx)
		}
		orderIDs[idx] = out.Order.OrderID
	}
	if orderIDs[0] != orderIDs[1] {
		t.Fatalf("dual instances created different orders for same idempotencyKey: %q vs %q", orderIDs[0], orderIDs[1])
	}

	var count int
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM orders WHERE deployment_id=$1 AND idempotency_key='dual-ord-same'`, h.depID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 immutable order row across dual instances, got %d", count)
	}

	// Same idempotencyKey with altered payload -> 409 IDEMPOTENCY_CONFLICT.
	diffReq := sameReq
	diffReq.AmountMinor = 79999
	conflictRec := h.execReq(t, h8104, h.bm, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, diffReq)
	if conflictRec.Code != http.StatusConflict || !bytes.Contains(conflictRec.Body.Bytes(), []byte(protocol.ErrCodeIdempotencyConflict)) {
		t.Fatalf("expected 409 IDEMPOTENCY_CONFLICT on different payload same key, got status=%d body=%s", conflictRec.Code, conflictRec.Body.String())
	}
}
