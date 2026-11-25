//go:build db

package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/core/domain/gateway"
	"grad/platform/core/domain/policy"
	"grad/platform/core/ledger"
	"grad/platform/internal/testutil"
	"grad/protocol"
	"grad/protocol/registry"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

type staticCertChecker struct {
	mu     sync.RWMutex
	synced map[string]bool
}

func newStaticCertChecker(domains ...string) *staticCertChecker {
	m := make(map[string]bool, len(domains))
	for _, d := range domains {
		m[d] = true
	}
	return &staticCertChecker{synced: m}
}

func (c *staticCertChecker) HasSyncedCertification(_ context.Context, domainID string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.synced[domainID], nil
}

type chainFixture struct {
	mode     string
	taskID   string
	grants   []string
	ancCreds []protocol.AncestorCredential
	tp       []protocol.TrustPathEntry
	g0ID     string
	g1ID     string
	g2ID     string
	g1       registry.Grant
}

type gatewayFixture struct {
	pool           *pgxpool.Pool
	depID          string
	serviceDID     string
	audience       string
	supplierID     string
	didU           string
	didB1          string
	didUinB        string
	privU          *ecdsa.PrivateKey
	privB1         *ecdsa.PrivateKey
	privUinB       *ecdsa.PrivateKey
	privWrong      *ecdsa.PrivateKey
	uKeyID         string
	b1KeyID        string
	uInBKeyID      string
	uPresPrefix    string
	b1PresPrefix   string
	uInBPresPrefix string
	spec           protocol.TaskSpec
	directU        chainFixture
	rp             chainFixture
	bm             chainFixture
	boot           registry.Bootstrap
	rootRec        registry.RootRecord
	state          *ledger.StateProvider
	certs          *staticCertChecker
	dids           *protocol.DIDWebResolver
	bundle         *policy.VerifiedBundle
	policyDeadline int64
	fixedNow       time.Time
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	t.Helper()
	ctx := t.Context()
	pool := testutil.OpenMigratedPool(t)

	now := time.Now().UTC().Truncate(time.Second)
	ca, err := protocol.GenerateTestCA(now)
	require.NoError(t, err)
	caPool, err := protocol.ParseTestCAPublic(ca.CertPEM)
	require.NoError(t, err)

	hostCerts := make(map[string]*protocol.HostTLSCert, len(protocol.ControlledTestDomains))
	for _, host := range protocol.ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		require.NoError(t, err)
		hostCerts[host] = hc
	}

	genKey := func() (*ecdsa.PrivateKey, string) {
		priv, err := protocol.GenerateP256Key()
		require.NoError(t, err)
		pubHex, err := protocol.FormatAppPublicKey(&priv.PublicKey)
		require.NoError(t, err)
		return priv, pubHex
	}

	privT, pubT := genKey()
	privIA, pubIA := genKey()
	privIB, pubIB := genKey()
	privIC, pubIC := genKey()
	_, pubDomA := genKey()
	_, pubDomB := genKey()
	_, pubDomC := genKey()
	privPA, pubPA := genKey()
	privU, pubU := genKey()
	privA1, pubA1 := genKey()
	privB1, pubB1 := genKey()
	privUinB, pubUinB := genKey()
	privC, pubC := genKey()
	privWrong, _ := genKey()

	didT := "did:web:t.local"
	didA, didB, didC := "did:web:a.local", "did:web:b.local", "did:web:c.local"
	didIA, didIB, didIC := "did:web:a.local:ia", "did:web:b.local:ib", "did:web:c.local:ic"
	didPA, didU, didA1 := "did:web:a.local:pa", "did:web:a.local:u", "did:web:a.local:a1"
	didB1, didUinB, didCSvc := "did:web:b.local:b1", "did:web:b.local:u-in-b", "did:web:c.local:supplier"

	docs := map[string][]byte{}
	makeDoc := func(did, pubHex string) string {
		pub, err := protocol.ParseAppPublicKey(pubHex)
		require.NoError(t, err)
		d, err := protocol.NewDIDDocument(did, did+"#key-1", pub, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
		require.NoError(t, err)
		raw, err := protocol.MarshalJCS(d)
		require.NoError(t, err)
		dig, err := d.Digest()
		require.NoError(t, err)
		docs[did] = raw
		return dig
	}
	digT := makeDoc(didT, pubT)
	digA, digB, digC := makeDoc(didA, pubDomA), makeDoc(didB, pubDomB), makeDoc(didC, pubDomC)
	digIA, digIB, digIC := makeDoc(didIA, pubIA), makeDoc(didIB, pubIB), makeDoc(didIC, pubIC)
	digPA, digU, digA1 := makeDoc(didPA, pubPA), makeDoc(didU, pubU), makeDoc(didA1, pubA1)
	digB1, digUinB, digCSvc := makeDoc(didB1, pubB1), makeDoc(didUinB, pubUinB), makeDoc(didCSvc, pubC)

	didSrv, err := protocol.NewDIDWebServer(hostCerts, docs)
	require.NoError(t, err)
	t.Cleanup(func() { _ = didSrv.Close() })

	dids, err := protocol.NewDIDWebResolver(caPool, didSrv.Routes())
	require.NoError(t, err)
	_, err = dids.RegisterPreseed(protocol.RootPreseed{
		DID:               didT,
		KeyID:             didT + "#key-1",
		KeyVersion:        1,
		PublicKeyHex:      pubT,
		DIDDocumentDigest: digT,
		RawDocument:       docs[didT],
	})
	require.NoError(t, err)

	tag := fmt.Sprintf("gw-%d", time.Now().UnixNano())
	df := registry.DeploymentFields{
		ChannelID:     registry.Channel,
		GenesisHash:   registry.Digest([]byte("genesis:" + tag)),
		InstanceID:    registry.Digest([]byte("instance:" + tag)),
		RegistryName:  registry.Registry,
		SchemaVersion: registry.Schema,
	}
	depID := df.DeploymentID()
	nbf := now.Add(-time.Hour).Unix()
	exp := now.Add(time.Hour).Unix()
	policyDeadline := now.Add(2 * time.Hour).Unix()
	vf := time.Unix(nbf, 0).UTC().Format(time.RFC3339)
	vu := time.Unix(exp, 0).UTC().Format(time.RFC3339)

	mkMgmt := func(msp, label string) registry.Management {
		return registry.Management{MSPID: msp, CertificateSHA256: registry.Digest([]byte("mgmt:" + label + ":" + tag))}
	}

	rootRec := registry.RootRecord{
		DID:            didT,
		Management:     mkMgmt("TMsp", "root"),
		DocumentDigest: digT,
		KeyID:          didT + "#key-1",
		KeyVersion:     1,
		PublicKey:      pubT,
	}
	boot := registry.Bootstrap{
		DeploymentFields:   df,
		Root:               rootRec,
		Initializer:        rootRec.Management,
		TaskCreator:        registry.TaskAuthority{Domain: "A", Subject: didU, Management: mkMgmt("AMsp", "U")},
		ResourceID:         protocol.ResourceOrders,
		ResourceOwner:      didCSvc,
		ResourceManagement: mkMgmt("CMsp", "C"),
	}

	issueCert := func(domID, domDID, issDID string) (string, registry.Domain, registry.Certification) {
		certID := "urn:grad:cert:" + domID + ":" + tag
		jws, dig, err := protocol.SignDomainAuthorityCredential(privT, didT+"#key-1", &protocol.DomainAuthorityCredential{
			Type:             []string{protocol.CredentialTypeVC, protocol.CredentialTypeDomainAuthority},
			ID:               certID,
			DeploymentID:     depID,
			Issuer:           didT,
			Iss:              didT,
			Sub:              domDID,
			IssuerKeyVersion: 1,
			ValidFrom:        vf,
			ValidUntil:       vu,
			NBF:              nbf,
			EXP:              exp,
			CredentialStatus: protocol.CredentialStatus{ID: certID, Type: protocol.StatusTypeDomainCertification},
			CredentialSubject: protocol.DomainAuthoritySubject{
				ID:       domDID,
				DomainID: domID,
				IdentityIssuers: []protocol.IssuerScope{{
					ID:              issDID,
					AppKeyVersion:   1,
					CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity},
					ClaimNames:      []string{"domain", "role"},
				}},
			},
		})
		require.NoError(t, err)
		dom := registry.Domain{
			Bound:         registry.Bound{DeploymentID: depID},
			ID:            domID,
			DID:           domDID,
			Admin:         mkMgmt(domID+"Msp", "admin-"+domID),
			Registrar:     mkMgmt(domID+"Msp", "reg-"+domID),
			Issuers:       []string{issDID},
			Certification: certID,
			Version:       registry.Version{Status: registry.Active, Revision: 2},
		}
		if domID == "A" {
			dom.PurchasingAuthority = didPA
		}
		cert := registry.Certification{
			Bound:          registry.Bound{DeploymentID: depID},
			ID:             certID,
			Domain:         domID,
			RootKeyVersion: 1,
			Digest:         dig,
			Scopes:         []registry.IssuerScope{{ID: issDID, AppKeyVersion: 1, CredentialTypes: []string{protocol.CredentialTypeEnterpriseIdentity}, ClaimNames: []string{"domain", "role"}}},
			Interval:       registry.Interval{NBF: nbf, EXP: exp},
			Version:        registry.Version{Status: registry.Active, Revision: 1},
		}
		return jws, dom, cert
	}

	certAJWS, domA, certA := issueCert("A", didA, didIA)
	certBJWS, domB, certB := issueCert("B", didB, didIB)
	certCJWS, domC, certC := issueCert("C", didC, didIC)

	makeID := func(id, dom, kind, dig, pubHex string) registry.Identity {
		return registry.Identity{
			Bound:             registry.Bound{DeploymentID: depID},
			ID:                id,
			Domain:            dom,
			Kind:              kind,
			Management:        mkMgmt(dom+"Msp", id),
			DocumentDigest:    dig,
			KeyID:             id + "#key-1",
			KeyVersion:        1,
			PublicKey:         pubHex,
			AccountCommitment: registry.Digest([]byte("acct:" + depID + ":" + id)),
			Version:           registry.Version{Status: registry.Active, Revision: 1},
		}
	}
	identities := []registry.Identity{
		makeID(didA, "A", "DOMAIN", digA, pubDomA),
		makeID(didB, "B", "DOMAIN", digB, pubDomB),
		makeID(didC, "C", "DOMAIN", digC, pubDomC),
		makeID(didIA, "A", "ISSUER", digIA, pubIA),
		makeID(didIB, "B", "ISSUER", digIB, pubIB),
		makeID(didIC, "C", "ISSUER", digIC, pubIC),
		makeID(didPA, "A", "SERVICE", digPA, pubPA),
		makeID(didU, "A", "USER", digU, pubU),
		makeID(didA1, "A", "AGENT", digA1, pubA1),
		makeID(didB1, "B", "AGENT", digB1, pubB1),
		makeID(didUinB, "B", "USER", digUinB, pubUinB),
		makeID(didCSvc, "C", "SERVICE", digCSvc, pubC),
	}

	issueCred := func(id, issDID, subDID, dom, role, pubHex string, priv *ecdsa.PrivateKey) (*protocol.SignedSDJWTCredential, registry.Credential) {
		pub, err := protocol.ParseAppPublicKey(pubHex)
		require.NoError(t, err)
		jwk, err := protocol.JWKFromPublicKey(pub)
		require.NoError(t, err)
		s, err := protocol.IssueEnterpriseIdentityCredential(priv, issDID+"#key-1", protocol.EnterpriseIdentityCredential{
			Type:              []string{protocol.CredentialTypeVC, protocol.CredentialTypeEnterpriseIdentity},
			ID:                id,
			DeploymentID:      depID,
			Issuer:            issDID,
			Iss:               issDID,
			Sub:               subDID,
			IssuerKeyVersion:  1,
			AppKeyVersion:     1,
			ValidFrom:         vf,
			ValidUntil:        vu,
			NBF:               nbf,
			EXP:               exp,
			CredentialStatus:  protocol.CredentialStatus{ID: id, Type: protocol.StatusTypeCredential},
			Cnf:               protocol.ConfirmationKey{JWK: jwk},
			CredentialSubject: protocol.SDJWTCredentialSubject{ID: subDID},
		}, dom, role, nil)
		require.NoError(t, err)
		return s, registry.Credential{
			Bound:             registry.Bound{DeploymentID: depID},
			ID:                id,
			Issuer:            issDID,
			Subject:           subDID,
			IssuerKeyVersion:  1,
			SubjectKeyVersion: 1,
			Type:              protocol.CredentialTypeEnterpriseIdentity,
			ClaimNames:        []string{"domain", "role"},
			Digest:            s.AnchorDigest,
			Interval:          registry.Interval{NBF: nbf, EXP: exp},
			Version:           registry.Version{Status: registry.Active, Revision: 1},
		}
	}

	sdPA, credPA := issueCred("urn:grad:cred:PA:"+tag, didIA, didPA, "A", "procurement-authority", pubPA, privIA)
	sdU, credU := issueCred("urn:grad:cred:U:"+tag, didIA, didU, "A", "procurement-owner", pubU, privIA)
	sdA1, credA1 := issueCred("urn:grad:cred:A1:"+tag, didIA, didA1, "A", "procurement-agent", pubA1, privIA)
	sdB1, credB1 := issueCred("urn:grad:cred:B1:"+tag, didIB, didB1, "B", "broker-agent", pubB1, privIB)
	sdUinB, credUinB := issueCred("urn:grad:cred:UinB:"+tag, didIB, didUinB, "B", "procurement-owner", pubUinB, privIB)
	sdC, credC := issueCred("urn:grad:cred:C:"+tag, didIC, didCSvc, "C", "supplier-service", pubC, privIC)

	spec := protocol.TaskSpec{
		SupplierID:  gateway.DefaultSupplierID,
		ProductID:   gateway.DefaultProductID,
		MaxQuantity: 2,
		Currency:    gateway.DefaultCurrency,
		Resources:   []string{protocol.ResourceOrders, protocol.ResourceQuotes},
		Actions:     []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
		Description: "Procurement acceptance test",
	}
	specDig, err := spec.Digest()
	require.NoError(t, err)

	// Direct U RP G0 chain (C -> U).
	uTaskID := registry.Digest([]byte("u-direct:task:" + tag))
	uG0ID := registry.Digest([]byte("u-direct:g0:" + tag))
	uTaskRec := registry.Task{
		Bound: registry.Bound{DeploymentID: depID}, ID: uTaskID, Creator: didU, CreatorCredential: credU.ID, CreatorKeyVersion: 1,
		Domain: "A", Mode: protocol.ModeResourcePreauthorized, Resource: protocol.ResourceQuotes, Digest: specDig,
		Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1},
	}
	uG0Claims := protocol.GrantClaims{
		ID: uG0ID, SchemaVersion: protocol.SchemaVersion, DeploymentID: depID, RootID: uG0ID, TaskID: uTaskID,
		AuthorizationMode: protocol.ModeResourcePreauthorized, PrincipalDomain: "A", ResourceID: protocol.ResourceQuotes,
		Issuer: didCSvc, Grantee: didU, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredentialID: credC.ID, GranteeCredentialID: credU.ID,
		Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{spec.SupplierID},
		Aud: "https://c.local", Currency: gateway.DefaultCurrency, MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 0,
	}
	uG0JWS, uG0Dig, err := protocol.SignGrant(privC, didCSvc+"#key-1", &uG0Claims)
	require.NoError(t, err)
	uG0Rec := registry.Grant{
		Bound: registry.Bound{DeploymentID: depID}, ID: uG0ID, Schema: registry.Schema, Root: uG0ID, Task: uTaskID,
		Mode: protocol.ModeResourcePreauthorized, Domain: "A", Resource: protocol.ResourceQuotes,
		Issuer: didCSvc, Grantee: didU, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredential: credC.ID, GranteeCredential: credU.ID, Depth: 0, Digest: uG0Dig,
		Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1},
	}
	directU := chainFixture{
		mode:     protocol.ModeResourcePreauthorized,
		taskID:   uTaskID,
		grants:   []string{uG0JWS},
		ancCreds: []protocol.AncestorCredential{{CredentialID: credC.ID, Presentation: sdC.PresentationPrefix}},
		tp: []protocol.TrustPathEntry{
			{Issuer: didIA, DomainCertification: certAJWS},
			{Issuer: didIC, DomainCertification: certCJWS},
		},
		g0ID: uG0ID,
	}

	make3HopChain := func(mode, prefix, rootDID, rootCredID, rootPres string, rootPriv *ecdsa.PrivateKey, includeC bool) (registry.Task, []registry.Grant, chainFixture) {
		tID := registry.Digest([]byte(prefix + ":task:" + tag))
		g0ID := registry.Digest([]byte(prefix + ":g0:" + tag))
		g1ID := registry.Digest([]byte(prefix + ":g1:" + tag))
		g2ID := registry.Digest([]byte(prefix + ":g2:" + tag))
		tRec := registry.Task{
			Bound: registry.Bound{DeploymentID: depID}, ID: tID, Creator: didU, CreatorCredential: credU.ID, CreatorKeyVersion: 1,
			Domain: "A", Mode: mode, Resource: protocol.ResourceOrders, Digest: specDig,
			Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1},
		}
		g0C := protocol.GrantClaims{
			ID: g0ID, SchemaVersion: protocol.SchemaVersion, DeploymentID: depID, RootID: g0ID, TaskID: tID,
			AuthorizationMode: mode, PrincipalDomain: "A", ResourceID: protocol.ResourceOrders, Issuer: rootDID, Grantee: didU,
			IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: rootCredID, GranteeCredentialID: credU.ID,
			Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{spec.SupplierID},
			Aud: "https://c.local", Currency: gateway.DefaultCurrency, MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 2,
		}
		g0JWS, g0Dig, err := protocol.SignGrant(rootPriv, rootDID+"#key-1", &g0C)
		require.NoError(t, err)
		g1C := protocol.GrantClaims{
			ID: g1ID, SchemaVersion: protocol.SchemaVersion, DeploymentID: depID, ParentID: &g0ID, ParentDigest: &g0Dig,
			RootID: g0ID, TaskID: tID, AuthorizationMode: mode, PrincipalDomain: "A", ResourceID: protocol.ResourceOrders,
			Issuer: didU, Grantee: didA1, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
			IssuerCredentialID: credU.ID, GranteeCredentialID: credA1.ID,
			Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{spec.SupplierID},
			Aud: "https://c.local", Currency: gateway.DefaultCurrency, MaxAmountMinor: 500000, NBF: nbf, EXP: exp, RemainingDepth: 1,
		}
		g1JWS, g1Dig, err := protocol.SignGrant(privU, didU+"#key-1", &g1C)
		require.NoError(t, err)
		g2C := protocol.GrantClaims{
			ID: g2ID, SchemaVersion: protocol.SchemaVersion, DeploymentID: depID, ParentID: &g1ID, ParentDigest: &g1Dig,
			RootID: g0ID, TaskID: tID, AuthorizationMode: mode, PrincipalDomain: "A", ResourceID: protocol.ResourceOrders,
			Issuer: didA1, Grantee: didB1, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
			IssuerCredentialID: credA1.ID, GranteeCredentialID: credB1.ID,
			Resources: spec.Resources, Actions: spec.Actions, Suppliers: []string{spec.SupplierID},
			Aud: "https://c.local", Currency: gateway.DefaultCurrency, MaxAmountMinor: 100000, NBF: nbf, EXP: exp, RemainingDepth: 0,
		}
		g2JWS, g2Dig, err := protocol.SignGrant(privA1, didA1+"#key-1", &g2C)
		require.NoError(t, err)
		g0Rec := registry.Grant{Bound: registry.Bound{DeploymentID: depID}, ID: g0ID, Schema: registry.Schema, Root: g0ID, Task: tID, Mode: mode, Domain: "A", Resource: protocol.ResourceOrders, Issuer: rootDID, Grantee: didU, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: rootCredID, GranteeCredential: credU.ID, Depth: 2, Digest: g0Dig, Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1}}
		g1Rec := registry.Grant{Bound: registry.Bound{DeploymentID: depID}, ID: g1ID, Schema: registry.Schema, Parent: g0ID, ParentDigest: g0Dig, Root: g0ID, Task: tID, Mode: mode, Domain: "A", Resource: protocol.ResourceOrders, Issuer: didU, Grantee: didA1, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: credU.ID, GranteeCredential: credA1.ID, Depth: 1, Digest: g1Dig, Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1}}
		g2Rec := registry.Grant{Bound: registry.Bound{DeploymentID: depID}, ID: g2ID, Schema: registry.Schema, Parent: g1ID, ParentDigest: g1Dig, Root: g0ID, Task: tID, Mode: mode, Domain: "A", Resource: protocol.ResourceOrders, Issuer: didA1, Grantee: didB1, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: credA1.ID, GranteeCredential: credB1.ID, Depth: 0, Digest: g2Dig, Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1}}

		tp := []protocol.TrustPathEntry{
			{Issuer: didIA, DomainCertification: certAJWS},
			{Issuer: didIB, DomainCertification: certBJWS},
		}
		if includeC {
			tp = append(tp, protocol.TrustPathEntry{Issuer: didIC, DomainCertification: certCJWS})
		}
		anc := []protocol.AncestorCredential{
			{CredentialID: rootCredID, Presentation: rootPres},
			{CredentialID: credU.ID, Presentation: sdU.PresentationPrefix},
			{CredentialID: credA1.ID, Presentation: sdA1.PresentationPrefix},
		}
		return tRec, []registry.Grant{g0Rec, g1Rec, g2Rec}, chainFixture{
			mode: mode, taskID: tID, grants: []string{g0JWS, g1JWS, g2JWS}, ancCreds: anc, tp: tp,
			g0ID: g0ID, g1ID: g1ID, g2ID: g2ID, g1: g1Rec,
		}
	}

	rpTask, rpGrants, rpChain := make3HopChain(protocol.ModeResourcePreauthorized, "rp", didCSvc, credC.ID, sdC.PresentationPrefix, privC, true)
	bmTask, bmGrants, bmChain := make3HopChain(protocol.ModeBuyerMandate, "bm", didPA, credPA.ID, sdPA.PresentationPrefix, privPA, false)

	// Build and verify default OPA policy bundle allowing P1 and P2.
	files, digest, err := policy.BuildDefaultBundle(depID, didCSvc, policy.DefaultPolicyVersion, rootRec, &policyDeadline)
	require.NoError(t, err)
	bundle, err := policy.VerifyAndLoadBundle(files, depID, didCSvc, rootRec, digest)
	require.NoError(t, err)

	// Seed gateway schema + default P1 (80000) / P2 (120000) catalog prices.
	require.NoError(t, gateway.EnsureSchema(ctx, pool, depID, gateway.DefaultSupplierID))

	// Seed Fabric view tables (block 0 genesis + block 1 active registry state).
	b0Hash := registry.Digest([]byte("blk0:" + tag))
	b1Hash := registry.Digest([]byte("blk1:" + tag))
	_, err = pool.Exec(ctx, `INSERT INTO fabric_head(deployment, block_no, hash) VALUES($1, 1, $2)`, depID, b1Hash)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO fabric_block(deployment, block_no, hash, parent, data)
		VALUES($1, 0, $2, '', ''::bytea), ($1, 1, $3, $2, ''::bytea)`, depID, b0Hash, b1Hash)
	require.NoError(t, err)

	txIdx := 0
	putKV := func(k string, v any) {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `INSERT INTO fabric_current(deployment, key, value) VALUES($1, $2, $3)`, depID, k, raw)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `INSERT INTO fabric_version(deployment, key, block_no, tx_index, tx_id, value)
			VALUES($1, $2, 1, $3, $4, $5)`, depID, k, txIdx, "tx-init-"+tag, raw)
		require.NoError(t, err)
		txIdx++
	}
	putKV(registry.BootstrapKey, boot)
	putKV(registry.Key("domain", "A"), domA)
	putKV(registry.Key("domain", "B"), domB)
	putKV(registry.Key("domain", "C"), domC)
	putKV(registry.Key("certification", certA.ID), certA)
	putKV(registry.Key("certification", certB.ID), certB)
	putKV(registry.Key("certification", certC.ID), certC)
	for _, id := range identities {
		putKV(registry.Key("identity", id.ID), id)
	}
	for _, c := range []registry.Credential{credPA, credU, credA1, credB1, credUinB, credC} {
		putKV(registry.Key("credential", c.ID), c)
	}
	putKV(registry.Key("task", uTaskRec.ID), uTaskRec)
	putKV(registry.Key("grant", uG0Rec.ID), uG0Rec)
	putKV(registry.Key("task", rpTask.ID), rpTask)
	for _, g := range rpGrants {
		putKV(registry.Key("grant", g.ID), g)
	}
	putKV(registry.Key("task", bmTask.ID), bmTask)
	for _, g := range bmGrants {
		putKV(registry.Key("grant", g.ID), g)
	}

	sp := ledger.NewStateProviderFromBootstrap(pool, depID, boot, nil)
	sp.SetMonoClock(func() time.Time { return now })
	sp.SetStaticProbe(&ledger.ProbeLease{
		TxID:           "probe-init-" + tag,
		ProbeBlock:     1,
		SentAt:         now,
		Deadline:       now.Add(600 * time.Second),
		SentMonoNs:     now.UnixNano(),
		DeadlineMonoNs: now.Add(600 * time.Second).UnixNano(),
		CheckedMonoNs:  now.UnixNano(),
	})

	return &gatewayFixture{
		pool:           pool,
		depID:          depID,
		serviceDID:     didCSvc,
		audience:       "https://c.local",
		supplierID:     gateway.DefaultSupplierID,
		didU:           didU,
		didB1:          didB1,
		didUinB:        didUinB,
		privU:          privU,
		privB1:         privB1,
		privUinB:       privUinB,
		privWrong:      privWrong,
		uKeyID:         didU + "#key-1",
		b1KeyID:        didB1 + "#key-1",
		uInBKeyID:      didUinB + "#key-1",
		uPresPrefix:    sdU.PresentationPrefix,
		b1PresPrefix:   sdB1.PresentationPrefix,
		uInBPresPrefix: sdUinB.PresentationPrefix,
		spec:           spec,
		directU:        directU,
		rp:             rpChain,
		bm:             bmChain,
		boot:           boot,
		rootRec:        rootRec,
		state:          sp,
		certs:          newStaticCertChecker("A", "B", "C"),
		dids:           dids,
		bundle:         bundle,
		policyDeadline: policyDeadline,
		fixedNow:       now,
	}
}

func (f *gatewayFixture) newService(t *testing.T, customize func(*gateway.Config)) *gateway.Service {
	t.Helper()
	cfg := gateway.Config{
		DB:               f.pool,
		State:            f.state,
		CertChecker:      f.certs,
		DIDs:             f.dids,
		Policy:           f.bundle,
		AuditorDIDs:      []string{"did:web:c.local:auditors:c1"},
		VerifierID:       "c-gw-1",
		DeploymentID:     f.depID,
		ServiceDID:       f.serviceDID,
		Audience:         f.audience,
		SupplierID:       f.supplierID,
		ClockErrorMargin: registry.ClockError,
		NowFn:            func() time.Time { return f.fixedNow },
	}
	if customize != nil {
		customize(&cfg)
	}
	svc, err := gateway.NewService(cfg)
	require.NoError(t, err)
	return svc
}

func (f *gatewayFixture) updateContext(t *testing.T, svc *gateway.Service, taskID string, expectedVer int64, risk string, deadline int64) {
	t.Helper()
	_, err := svc.UpdateContext(t.Context(), taskID, gateway.ContextUpdateRequest{
		ExpectedContextVersion: expectedVer,
		SourceID:               "urn:grad:context-source:c-monitor",
		ObservedAt:             f.fixedNow.Unix() - 5,
		RiskLevel:              risk,
		AccessDeadline:         deadline,
	})
	require.NoError(t, err)
}

func (f *gatewayFixture) requestChallenge(t *testing.T, svc *gateway.Service, actor, taskID, reqHash string) gateway.ChallengeResponse {
	t.Helper()
	out, err := svc.CreateChallenge(t.Context(), gateway.ChallengeRequest{
		Actor:       actor,
		TaskID:      taskID,
		RequestHash: reqHash,
	})
	require.NoError(t, err)
	return *out
}

func (f *gatewayFixture) executePkg(t *testing.T, svc *gateway.Service, pkg *protocol.AccessEvidencePackage) (*gateway.ExecuteResponse, error) {
	t.Helper()
	raw, err := json.Marshal(pkg)
	require.NoError(t, err)
	return svc.ExecuteAccess(t.Context(), "urn:grad:req:test", raw)
}

func (f *gatewayFixture) buildRequest(actor string, chain chainFixture, action, resource, productID string, qty int64, quoteID *string, amount int64, idemKey string) protocol.AccessRequest {
	return protocol.AccessRequest{
		SchemaVersion:     protocol.SchemaVersion,
		DeploymentID:      f.depID,
		Actor:             actor,
		PrincipalDomain:   "A",
		AuthorizationMode: chain.mode,
		TaskID:            chain.taskID,
		Audience:          f.audience,
		Resource:          resource,
		Action:            action,
		SupplierID:        f.supplierID,
		ProductID:         productID,
		Quantity:          qty,
		Currency:          gateway.DefaultCurrency,
		QuoteID:           quoteID,
		AmountMinor:       amount,
		IdempotencyKey:    idemKey,
	}
}

func (f *gatewayFixture) assemblePackage(t *testing.T, req protocol.AccessRequest, chain chainFixture, chal gateway.ChallengeResponse, leafPrefix, keyID string, priv *ecdsa.PrivateKey, iat int64) *protocol.AccessEvidencePackage {
	t.Helper()
	pkg := &protocol.AccessEvidencePackage{
		ChallengeID:         chal.ChallengeID,
		Request:             req,
		TaskSpec:            f.spec,
		Grants:              append([]string(nil), chain.grants...),
		AncestorCredentials: append([]protocol.AncestorCredential(nil), chain.ancCreds...),
		TrustPaths:          append([]protocol.TrustPathEntry(nil), chain.tp...),
	}
	_, _, err := protocol.AssembleAccessEvidencePackage(pkg, leafPrefix, keyID, priv, protocol.ChallengeContext{
		ChallengeID: chal.ChallengeID,
		Nonce:       chal.Nonce,
		Audience:    chal.Audience,
		IssuedAt:    chal.IssuedAt,
		ExpiresAt:   chal.ExpiresAt,
	}, iat, false)
	require.NoError(t, err)
	return pkg
}

func (f *gatewayFixture) assertChallengeUnconsumed(t *testing.T, challengeID string) {
	t.Helper()
	var consumedAt *int64
	err := f.pool.QueryRow(t.Context(), `SELECT consumed_at FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`, f.depID, challengeID).Scan(&consumedAt)
	require.NoError(t, err)
	assert.Nil(t, consumedAt, "challenge %s should remain unconsumed", challengeID)
}

func (f *gatewayFixture) assertChallengeConsumed(t *testing.T, challengeID string) {
	t.Helper()
	var consumedAt *int64
	err := f.pool.QueryRow(t.Context(), `SELECT consumed_at FROM challenges WHERE deployment_id=$1 AND challenge_id=$2`, f.depID, challengeID).Scan(&consumedAt)
	require.NoError(t, err)
	assert.NotNil(t, consumedAt, "challenge %s should be consumed", challengeID)
}

func TestDirectQuoteIdempotencyConflictWrongKeyAndLegacyResourceRejection(t *testing.T) {
	f := newGatewayFixture(t)
	svc := f.newService(t, nil)
	ctx := t.Context()

	// Readiness check succeeds when DB + Fabric view + certs are ready.
	ready, err := svc.CheckReady(ctx)
	require.NoError(t, err)
	assert.Equal(t, "READY", ready.Status)
	assert.Equal(t, ledger.SourceFabric, ready.StateSource)
	require.NotNil(t, ready.ProbeBlock)
	assert.Equal(t, uint64(1), *ready.ProbeBlock)

	f.updateContext(t, svc, f.directU.taskID, 0, policy.RiskNormal, f.fixedNow.Unix()+3600)

	// 1. Direct U RP G0 quote with canonical urn:grad:resource:C:quotes -> ALLOW.
	req := f.buildRequest(f.didU, f.directU, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "u-direct-quote-1")
	reqHash, err := req.Hash(false)
	require.NoError(t, err)
	chal1 := f.requestChallenge(t, svc, f.didU, f.directU.taskID, reqHash)
	pkg1 := f.assemblePackage(t, req, f.directU, chal1, f.uPresPrefix, f.uKeyID, f.privU, f.fixedNow.Unix())

	resp1, err := f.executePkg(t, svc, pkg1)
	require.NoError(t, err)
	require.NotNil(t, resp1.Quote)
	assert.Equal(t, "ALLOW", resp1.Code)
	assert.Equal(t, int64(80000), resp1.Quote.TotalAmountMinor)
	assert.NotEmpty(t, resp1.DecisionID)
	f.assertChallengeConsumed(t, chal1.ChallengeID)

	// GetDecision returns persisted record with Fabric checkpoint fields.
	storedDec, err := svc.GetDecision(ctx, resp1.DecisionID)
	require.NoError(t, err)
	assert.Equal(t, ledger.SourceFabric, storedDec.StateSource)
	assert.Equal(t, int64(1), storedDec.BlockNumber)
	assert.Equal(t, resp1.Quote.QuoteID, *storedDec.QuoteID)

	_, err = svc.GetDecision(ctx, "urn:grad:decision:missing")
	require.ErrorIs(t, err, gateway.ErrDecisionNotFound)

	// Oversized payload is rejected with PAYLOAD_TOO_LARGE before parsing.
	_, err = svc.ExecuteAccess(ctx, "urn:grad:req:big", make([]byte, gateway.MaxExecuteBodyBytes+1))
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodePayloadTooLarge, protocol.CodeOf(err))

	// 2. Idempotent retry with same key + same requestHash + fresh challenge -> same quoteId, distinct decisionId.
	chal2 := f.requestChallenge(t, svc, f.didU, f.directU.taskID, reqHash)
	pkg2 := f.assemblePackage(t, req, f.directU, chal2, f.uPresPrefix, f.uKeyID, f.privU, f.fixedNow.Unix())
	resp2, err := f.executePkg(t, svc, pkg2)
	require.NoError(t, err)
	require.NotNil(t, resp2.Quote)
	assert.Equal(t, resp1.Quote.QuoteID, resp2.Quote.QuoteID)
	assert.NotEqual(t, resp1.DecisionID, resp2.DecisionID)

	// 3. Same key + different requestHash (quantity=2) -> IDEMPOTENCY_CONFLICT, decisionId=nil, challenge unconsumed.
	reqConflict := f.buildRequest(f.didU, f.directU, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 2, nil, 0, "u-direct-quote-1")
	conflictHash, err := reqConflict.Hash(false)
	require.NoError(t, err)
	chalConflict := f.requestChallenge(t, svc, f.didU, f.directU.taskID, conflictHash)
	pkgConflict := f.assemblePackage(t, reqConflict, f.directU, chalConflict, f.uPresPrefix, f.uKeyID, f.privU, f.fixedNow.Unix())
	_, err = f.executePkg(t, svc, pkgConflict)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeIdempotencyConflict, protocol.CodeOf(err))
	assert.Nil(t, gateway.DecisionIDOf(err))
	f.assertChallengeUnconsumed(t, chalConflict.ChallengeID)

	// 4. Wrong leaf key -> SIGNATURE_INVALID, decisionId=nil, challenge unconsumed, no quote/business key written.
	reqWrong := f.buildRequest(f.didU, f.directU, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "u-wrong-key-1")
	wrongHash, err := reqWrong.Hash(false)
	require.NoError(t, err)
	chalWrong := f.requestChallenge(t, svc, f.didU, f.directU.taskID, wrongHash)
	pkgWrong := f.assemblePackage(t, reqWrong, f.directU, chalWrong, f.uPresPrefix, f.uKeyID, f.privWrong, f.fixedNow.Unix())
	_, err = f.executePkg(t, svc, pkgWrong)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeSignatureInvalid, protocol.CodeOf(err))
	assert.Nil(t, gateway.DecisionIDOf(err))
	f.assertChallengeUnconsumed(t, chalWrong.ChallengeID)

	var bkCount int
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM business_keys WHERE deployment_id=$1 AND idempotency_key='u-wrong-key-1'`, f.depID).Scan(&bkCount))
	assert.Equal(t, 0, bkCount)

	// 5. Legacy resource aliases -> INVALID_SCHEMA, decisionId=nil, unconsumed challenge, no business key.
	qID := resp1.Quote.QuoteID
	legacyCases := []struct {
		name     string
		action   string
		resource string
		quoteID  *string
		amount   int64
		key      string
	}{
		{"short_quotes", protocol.ActionQuoteRead, "quotes", nil, 0, "legacy-1"},
		{"urn_quotes", protocol.ActionQuoteRead, "urn:grad:resource:quotes", nil, 0, "legacy-2"},
		{"short_orders", protocol.ActionOrderCreate, "orders", &qID, 80000, "legacy-3"},
		{"urn_orders", protocol.ActionOrderCreate, "urn:grad:resource:orders", &qID, 80000, "legacy-4"},
	}
	for _, tc := range legacyCases {
		t.Run(tc.name, func(t *testing.T) {
			chalLegacy := f.requestChallenge(t, svc, f.didU, f.directU.taskID, reqHash)
			legacyReq := f.buildRequest(f.didU, f.directU, tc.action, tc.resource, gateway.DefaultProductID, 1, tc.quoteID, tc.amount, tc.key)
			pkgLegacy := &protocol.AccessEvidencePackage{
				ChallengeID:         chalLegacy.ChallengeID,
				Request:             legacyReq,
				TaskSpec:            f.spec,
				Grants:              f.directU.grants,
				AncestorCredentials: f.directU.ancCreds,
				TrustPaths:          f.directU.tp,
				LeafPresentation:    f.uPresPrefix + "dummy",
			}
			_, err := f.executePkg(t, svc, pkgLegacy)
			require.Error(t, err)
			assert.Equal(t, protocol.ErrCodeInvalidSchema, protocol.CodeOf(err))
			assert.Nil(t, gateway.DecisionIDOf(err))
			f.assertChallengeUnconsumed(t, chalLegacy.ChallengeID)
			var cnt int
			require.NoError(t, f.pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM business_keys WHERE deployment_id=$1 AND idempotency_key=$2`, f.depID, tc.key).Scan(&cnt))
			assert.Equal(t, 0, cnt)
		})
	}
}

func TestProcurementRPAndBMOrderLifecycleAndRejections(t *testing.T) {
	f := newGatewayFixture(t)
	var currentSec atomic.Int64
	currentSec.Store(f.fixedNow.Unix())
	nowFn := func() time.Time { return time.Unix(currentSec.Load(), 0).UTC() }
	f.state.SetMonoClock(nowFn)

	svc := f.newService(t, func(cfg *gateway.Config) {
		cfg.NowFn = nowFn
	})

	f.updateContext(t, svc, f.rp.taskID, 0, policy.RiskNormal, f.fixedNow.Unix()+3600)
	f.updateContext(t, svc, f.bm.taskID, 0, policy.RiskNormal, f.fixedNow.Unix()+3600)

	exec := func(req protocol.AccessRequest, chain chainFixture) (*gateway.ExecuteResponse, error) {
		reqHash, err := req.Hash(false)
		require.NoError(t, err)
		chal := f.requestChallenge(t, svc, req.Actor, req.TaskID, reqHash)
		pkg := f.assemblePackage(t, req, chain, chal, f.b1PresPrefix, f.b1KeyID, f.privB1, currentSec.Load())
		return f.executePkg(t, svc, pkg)
	}

	// 1. RP 800-yuan (P1=80000) quote + order -> ALLOW.
	qRPReq := f.buildRequest(f.didB1, f.rp, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "rp-q-800")
	qRPResp, err := exec(qRPReq, f.rp)
	require.NoError(t, err)
	require.NotNil(t, qRPResp.Quote)
	assert.Equal(t, int64(80000), qRPResp.Quote.TotalAmountMinor)

	oRPReq := f.buildRequest(f.didB1, f.rp, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qRPResp.Quote.QuoteID, 80000, "rp-o-800")
	oRPResp, err := exec(oRPReq, f.rp)
	require.NoError(t, err)
	require.NotNil(t, oRPResp.Order)
	assert.Equal(t, "CREATED", oRPResp.Order.Status)
	assert.Equal(t, int64(80000), oRPResp.Order.TotalAmountMinor)

	// 2. BM 800-yuan (P1=80000) quote + order -> ALLOW.
	qBMReq := f.buildRequest(f.didB1, f.bm, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "bm-q-800")
	qBMResp, err := exec(qBMReq, f.bm)
	require.NoError(t, err)
	require.NotNil(t, qBMResp.Quote)

	oBMReq := f.buildRequest(f.didB1, f.bm, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qBMResp.Quote.QuoteID, 80000, "bm-o-800")
	oBMResp, err := exec(oBMReq, f.bm)
	require.NoError(t, err)
	require.NotNil(t, oBMResp.Order)
	assert.Equal(t, "CREATED", oBMResp.Order.Status)

	// 3. Change the catalog price for future quotes. The earlier Q800 remains immutable.
	require.Error(t, gateway.SetCatalogPrice(t.Context(), f.pool, f.depID, "missing-product", 120000))
	require.Error(t, gateway.SetCatalogPrice(t.Context(), f.pool, f.depID, gateway.DefaultProductID, 0))
	require.NoError(t, gateway.SetCatalogPrice(t.Context(), f.pool, f.depID, gateway.DefaultProductID, 120000))
	q1200Req := f.buildRequest(f.didB1, f.rp, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "rp-q-1200")
	q1200Resp, err := exec(q1200Req, f.rp)
	require.NoError(t, err)
	require.Equal(t, int64(120000), q1200Resp.Quote.TotalAmountMinor)

	o1200Req := f.buildRequest(f.didB1, f.rp, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &q1200Resp.Quote.QuoteID, 120000, "rp-o-1200")
	_, err = exec(o1200Req, f.rp)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeAmountLimitExceeded, protocol.CodeOf(err))
	assert.NotNil(t, gateway.DecisionIDOf(err))

	// 4. Tampered amount (79999 vs immutable Q800=80000) -> AMOUNT_MISMATCH.
	oTamperReq := f.buildRequest(f.didB1, f.rp, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qRPResp.Quote.QuoteID, 79999, "rp-o-tamper")
	_, err = exec(oTamperReq, f.rp)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeAmountMismatch, protocol.CodeOf(err))
	assert.NotNil(t, gateway.DecisionIDOf(err))

	// 5. Cross-task quote reuse and cross-actor quote reuse -> QUOTE_SCOPE_MISMATCH.
	oCrossTaskReq := f.buildRequest(f.didB1, f.bm, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qRPResp.Quote.QuoteID, 80000, "bm-o-cross-task")
	_, err = exec(oCrossTaskReq, f.bm)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeQuoteScopeMismatch, protocol.CodeOf(err))
	assert.NotNil(t, gateway.DecisionIDOf(err))

	f.updateContext(t, svc, f.directU.taskID, 0, policy.RiskNormal, f.fixedNow.Unix()+3600)
	oCrossActorReq := f.buildRequest(f.didU, f.directU, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qRPResp.Quote.QuoteID, 80000, "u-o-cross-actor")
	oCrossActorHash, err := oCrossActorReq.Hash(false)
	require.NoError(t, err)
	oCrossActorChal := f.requestChallenge(t, svc, f.didU, f.directU.taskID, oCrossActorHash)
	oCrossActorPkg := f.assemblePackage(t, oCrossActorReq, f.directU, oCrossActorChal, f.uPresPrefix, f.uKeyID, f.privU, currentSec.Load())
	_, err = f.executePkg(t, svc, oCrossActorPkg)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeQuoteScopeMismatch, protocol.CodeOf(err))
	assert.NotNil(t, gateway.DecisionIDOf(err))

	// 6. Expired quote (advance clock past validUntil = issuedAt + 300) -> QUOTE_EXPIRED.
	currentSec.Store(qRPResp.Quote.ValidUntil)
	oExpReq := f.buildRequest(f.didB1, f.rp, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qRPResp.Quote.QuoteID, 80000, "rp-o-expired-q")
	_, err = exec(oExpReq, f.rp)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeQuoteExpired, protocol.CodeOf(err))
	assert.NotNil(t, gateway.DecisionIDOf(err))
}

func TestPostLockRiskEscalationAndRevocationAdoption(t *testing.T) {
	f := newGatewayFixture(t)
	svc := f.newService(t, nil)

	f.updateContext(t, svc, f.rp.taskID, 0, policy.RiskNormal, f.fixedNow.Unix()+3600)

	// Obtain a valid 800-yuan quote first.
	qReq := f.buildRequest(f.didB1, f.rp, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "risk-q-1")
	qHash, _ := qReq.Hash(false)
	qChal := f.requestChallenge(t, svc, f.didB1, f.rp.taskID, qHash)
	qPkg := f.assemblePackage(t, qReq, f.rp, qChal, f.b1PresPrefix, f.b1KeyID, f.privB1, f.fixedNow.Unix())
	qResp, err := f.executePkg(t, svc, qPkg)
	require.NoError(t, err)

	// 1. Post-lock risk escalation: between precheck and tx lock, context escalates NORMAL -> ELEVATED.
	// Final locked OPA evaluation MUST deny order.create with POLICY_DENIED.
	escalated := false
	svc.SetTestHooks(func(attempt int) {
		if !escalated {
			escalated = true
			f.updateContext(t, svc, f.rp.taskID, 1, policy.RiskElevated, f.fixedNow.Unix()+3600)
		}
	}, nil, nil)

	oReq := f.buildRequest(f.didB1, f.rp, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qResp.Quote.QuoteID, 80000, "risk-o-elevated")
	oHash, _ := oReq.Hash(false)
	oChal := f.requestChallenge(t, svc, f.didB1, f.rp.taskID, oHash)
	oPkg := f.assemblePackage(t, oReq, f.rp, oChal, f.b1PresPrefix, f.b1KeyID, f.privB1, f.fixedNow.Unix())
	_, err = f.executePkg(t, svc, oPkg)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodePolicyDenied, protocol.CodeOf(err))
	decID := gateway.DecisionIDOf(err)
	require.NotNil(t, decID)

	// Verify decision persisted context_version=2 and ELEVATED.
	dec, err := svc.GetDecision(t.Context(), *decID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), dec.ContextVersion)
	assert.Equal(t, policy.RiskElevated, dec.ContextRiskLevel)

	// Also verify BLOCKED rejects even quote.read after lock.
	blocked := false
	svc.SetTestHooks(func(attempt int) {
		if !blocked {
			blocked = true
			f.updateContext(t, svc, f.rp.taskID, 2, policy.RiskBlocked, f.fixedNow.Unix()+3600)
		}
	}, nil, nil)
	qBlockedReq := f.buildRequest(f.didB1, f.rp, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "risk-q-blocked")
	qBHash, _ := qBlockedReq.Hash(false)
	qBChal := f.requestChallenge(t, svc, f.didB1, f.rp.taskID, qBHash)
	qBPkg := f.assemblePackage(t, qBlockedReq, f.rp, qBChal, f.b1PresPrefix, f.b1KeyID, f.privB1, f.fixedNow.Unix())
	_, err = f.executePkg(t, svc, qBPkg)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodePolicyDenied, protocol.CodeOf(err))

	// Restore NORMAL context for revocation adoption test.
	svc.SetTestHooks(nil, nil, nil)
	f.updateContext(t, svc, f.rp.taskID, 3, policy.RiskNormal, f.fixedNow.Unix()+3600)

	// 2. Post-lock revocation adoption: right before LockCheckpoint, G1 is revoked in block 2.
	// Gateway detects head mismatch, retries precheck at block 2, and rejects with ANCESTOR_INACTIVE.
	revoked := false
	svc.SetTestHooks(nil, nil, func(attempt int) {
		if attempt == 0 && !revoked {
			revoked = true
			g1Rev := f.rp.g1
			g1Rev.Status = registry.Revoked
			g1Rev.Revision = 2
			rawG1, err := json.Marshal(g1Rev)
			require.NoError(t, err)
			b2Hash := registry.Digest([]byte("blk2:revoke-g1:" + f.depID))
			var b1Hash string
			require.NoError(t, f.pool.QueryRow(t.Context(), `SELECT hash FROM fabric_head WHERE deployment=$1`, f.depID).Scan(&b1Hash))
			_, err = f.pool.Exec(t.Context(), `INSERT INTO fabric_block(deployment, block_no, hash, parent, data) VALUES($1, 2, $2, $3, ''::bytea)`, f.depID, b2Hash, b1Hash)
			require.NoError(t, err)
			_, err = f.pool.Exec(t.Context(), `INSERT INTO fabric_version(deployment, key, block_no, tx_index, tx_id, value) VALUES($1, $2, 2, 0, 'tx-revoke-g1', $3)`, f.depID, registry.Key("grant", f.rp.g1ID), rawG1)
			require.NoError(t, err)
			_, err = f.pool.Exec(t.Context(), `UPDATE fabric_current SET value=$3 WHERE deployment=$1 AND key=$2`, f.depID, registry.Key("grant", f.rp.g1ID), rawG1)
			require.NoError(t, err)
			_, err = f.pool.Exec(t.Context(), `UPDATE fabric_head SET block_no=2, hash=$2 WHERE deployment=$1`, f.depID, b2Hash)
			require.NoError(t, err)
		}
	})

	oRevReq := f.buildRequest(f.didB1, f.rp, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qResp.Quote.QuoteID, 80000, "rev-o-1")
	oRevHash, _ := oRevReq.Hash(false)
	oRevChal := f.requestChallenge(t, svc, f.didB1, f.rp.taskID, oRevHash)
	oRevPkg := f.assemblePackage(t, oRevReq, f.rp, oRevChal, f.b1PresPrefix, f.b1KeyID, f.privB1, f.fixedNow.Unix())
	_, err = f.executePkg(t, svc, oRevPkg)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeAncestorInactive, protocol.CodeOf(err))

	var orderCount int
	require.NoError(t, f.pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM orders WHERE deployment_id=$1 AND idempotency_key='rev-o-1'`, f.depID).Scan(&orderCount))
	assert.Equal(t, 0, orderCount)
}

func TestDualGatewayConcurrentUniqueOrderAndChallengeExpiryBarrier(t *testing.T) {
	f := newGatewayFixture(t)
	var currentSec atomic.Int64
	currentSec.Store(f.fixedNow.Unix())
	nowFn := func() time.Time { return time.Unix(currentSec.Load(), 0).UTC() }
	f.state.SetMonoClock(nowFn)

	gw1 := f.newService(t, func(cfg *gateway.Config) {
		cfg.VerifierID = "c-gw-1"
		cfg.NowFn = nowFn
	})
	gw2 := f.newService(t, func(cfg *gateway.Config) {
		cfg.VerifierID = "c-gw-2"
		cfg.NowFn = nowFn
	})

	f.updateContext(t, gw1, f.rp.taskID, 0, policy.RiskNormal, f.fixedNow.Unix()+3600)

	// Issue quote on gw1.
	qReq := f.buildRequest(f.didB1, f.rp, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "dual-q-1")
	qHash, _ := qReq.Hash(false)
	qChal := f.requestChallenge(t, gw1, f.didB1, f.rp.taskID, qHash)
	qPkg := f.assemblePackage(t, qReq, f.rp, qChal, f.b1PresPrefix, f.b1KeyID, f.privB1, currentSec.Load())
	qResp, err := f.executePkg(t, gw1, qPkg)
	require.NoError(t, err)

	// 1. Dual-instance concurrent same-key order creation -> exactly 1 order, same orderId, distinct decisionIds.
	oReq := f.buildRequest(f.didB1, f.rp, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qResp.Quote.QuoteID, 80000, "dual-order-key")
	oHash, _ := oReq.Hash(false)
	chal1 := f.requestChallenge(t, gw1, f.didB1, f.rp.taskID, oHash)
	chal2 := f.requestChallenge(t, gw2, f.didB1, f.rp.taskID, oHash)
	pkg1 := f.assemblePackage(t, oReq, f.rp, chal1, f.b1PresPrefix, f.b1KeyID, f.privB1, currentSec.Load())
	pkg2 := f.assemblePackage(t, oReq, f.rp, chal2, f.b1PresPrefix, f.b1KeyID, f.privB1, currentSec.Load())

	var ready sync.WaitGroup
	ready.Add(2)
	release := make(chan struct{})
	hookFn := func(attempt int) {
		if attempt == 0 {
			ready.Done()
			<-release
		}
	}
	gw1.SetTestHooks(hookFn, nil, nil)
	gw2.SetTestHooks(hookFn, nil, nil)

	var out1, out2 *gateway.ExecuteResponse
	var err1, err2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		out1, err1 = f.executePkg(t, gw1, pkg1)
	}()
	go func() {
		defer wg.Done()
		out2, err2 = f.executePkg(t, gw2, pkg2)
	}()
	ready.Wait()
	close(release)
	wg.Wait()

	require.NoError(t, err1)
	require.NoError(t, err2)
	require.NotNil(t, out1.Order)
	require.NotNil(t, out2.Order)
	assert.Equal(t, out1.Order.OrderID, out2.Order.OrderID)
	assert.NotEqual(t, out1.DecisionID, out2.DecisionID)

	var orderCnt int
	require.NoError(t, f.pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM orders WHERE deployment_id=$1 AND idempotency_key='dual-order-key'`, f.depID).Scan(&orderCnt))
	assert.Equal(t, 1, orderCnt)

	// Subsequent same-key different-hash request -> IDEMPOTENCY_CONFLICT.
	gw1.SetTestHooks(nil, nil, nil)
	gw2.SetTestHooks(nil, nil, nil)
	diffReq := f.buildRequest(f.didB1, f.rp, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qResp.Quote.QuoteID, 79999, "dual-order-key")
	diffHash, _ := diffReq.Hash(false)
	diffChal := f.requestChallenge(t, gw2, f.didB1, f.rp.taskID, diffHash)
	diffPkg := f.assemblePackage(t, diffReq, f.rp, diffChal, f.b1PresPrefix, f.b1KeyID, f.privB1, currentSec.Load())
	_, err = f.executePkg(t, gw2, diffPkg)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeIdempotencyConflict, protocol.CodeOf(err))

	// 2. Concurrent two-challenge barrier test:
	// Earlier challenge c1 expires while waiting for business_keys lock held by later valid challenge c2.
	// c2 creates the unique order; c1 fails post-lock with CHALLENGE_EXPIRED and remains unconsumed.
	t0 := f.fixedNow.Unix()
	currentSec.Store(t0)
	barReq := f.buildRequest(f.didB1, f.rp, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qResp.Quote.QuoteID, 80000, "barrier-exp-order")
	barHash, _ := barReq.Hash(false)

	// c1 issued at t0 (expires at t0 + 30).
	c1 := f.requestChallenge(t, gw1, f.didB1, f.rp.taskID, barHash)
	p1 := f.assemblePackage(t, barReq, f.rp, c1, f.b1PresPrefix, f.b1KeyID, f.privB1, t0)

	// c2 issued at t0 + 15 (expires at t0 + 45).
	currentSec.Store(t0 + 15)
	c2 := f.requestChallenge(t, gw2, f.didB1, f.rp.taskID, barHash)
	p2 := f.assemblePackage(t, barReq, f.rp, c2, f.b1PresPrefix, f.b1KeyID, f.privB1, t0+15)

	gw2Locked := make(chan struct{})
	gw1Prechecked := make(chan struct{})
	releaseGW2 := make(chan struct{})

	gw2.SetTestHooks(nil, nil, func(attempt int) {
		if attempt == 0 {
			close(gw2Locked)
			<-releaseGW2
		}
	})
	gw1.SetTestHooks(func(attempt int) {
		if attempt == 0 {
			close(gw1Prechecked)
		}
	}, nil, nil)

	var barOut2 *gateway.ExecuteResponse
	var barErr1, barErr2 error
	var barWG sync.WaitGroup
	barWG.Add(2)
	go func() {
		defer barWG.Done()
		barOut2, barErr2 = f.executePkg(t, gw2, p2)
	}()
	<-gw2Locked

	go func() {
		defer barWG.Done()
		_, barErr1 = f.executePkg(t, gw1, p1)
	}()
	<-gw1Prechecked
	// Give gw1 a brief moment to enter the transaction and wait on business_keys FOR UPDATE.
	time.Sleep(40 * time.Millisecond)

	// Advance clock past c1 expiry (t0+31 >= t0+30) while c2 is still valid (t0+31 < t0+45).
	currentSec.Store(t0 + 31)
	close(releaseGW2)
	barWG.Wait()

	require.NoError(t, barErr2)
	require.NotNil(t, barOut2.Order)

	require.Error(t, barErr1)
	assert.Equal(t, protocol.ErrCodeChallengeExpired, protocol.CodeOf(barErr1))
	assert.Nil(t, gateway.DecisionIDOf(barErr1))
	f.assertChallengeUnconsumed(t, c1.ChallengeID)
	f.assertChallengeConsumed(t, c2.ChallengeID)

	var barOrderCnt int
	require.NoError(t, f.pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM orders WHERE deployment_id=$1 AND idempotency_key='barrier-exp-order'`, f.depID).Scan(&barOrderCnt))
	assert.Equal(t, 1, barOrderCnt)
}

func TestOrderOutcomeReconciliationHistoricalAuditAndOutboxDelivery(t *testing.T) {
	f := newGatewayFixture(t)
	ctx := t.Context()

	// Seed a prior suspension of Domain A at block 0 (resumed at block 1) to verify
	// FindInactiveBlock(afterBlock=h=1) does NOT falsely invalidate block 1.
	var domAJSON []byte
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2`, f.depID, registry.Key("domain", "A")).Scan(&domAJSON))
	var priorDomA registry.Domain
	require.NoError(t, json.Unmarshal(domAJSON, &priorDomA))
	priorDomA.Status = registry.Suspended
	priorRaw, err := json.Marshal(priorDomA)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `INSERT INTO fabric_version(deployment, key, block_no, tx_index, tx_id, value) VALUES($1, $2, 0, 0, 'tx-prior-susp', $3)`,
		f.depID, registry.Key("domain", "A"), priorRaw)
	require.NoError(t, err)

	var currentSec atomic.Int64
	currentSec.Store(f.fixedNow.Unix())
	nowFn := func() time.Time { return time.Unix(currentSec.Load(), 0).UTC() }
	f.state.SetMonoClock(nowFn)

	svc := f.newService(t, func(cfg *gateway.Config) {
		cfg.NowFn = nowFn
	})

	f.updateContext(t, svc, f.rp.taskID, 0, policy.RiskNormal, f.fixedNow.Unix()+3600)

	// 1. Create an 800-yuan order at block h=1.
	qReq := f.buildRequest(f.didB1, f.rp, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "audit-q-1")
	qHash, _ := qReq.Hash(false)
	qChal := f.requestChallenge(t, svc, f.didB1, f.rp.taskID, qHash)
	qPkg := f.assemblePackage(t, qReq, f.rp, qChal, f.b1PresPrefix, f.b1KeyID, f.privB1, currentSec.Load())
	qResp, err := f.executePkg(t, svc, qPkg)
	require.NoError(t, err)

	oReq := f.buildRequest(f.didB1, f.rp, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qResp.Quote.QuoteID, 80000, "audit-order-1")
	oHash, _ := oReq.Hash(false)
	oChal := f.requestChallenge(t, svc, f.didB1, f.rp.taskID, oHash)
	oPkg := f.assemblePackage(t, oReq, f.rp, oChal, f.b1PresPrefix, f.b1KeyID, f.privB1, currentSec.Load())
	oResp, err := f.executePkg(t, svc, oPkg)
	require.NoError(t, err)
	require.NotNil(t, oResp.Order)

	// 2. Revoke G1 at block r=2 (after creation at h=1).
	g1Rev := f.rp.g1
	g1Rev.Status = registry.Revoked
	g1Rev.Revision = 2
	rawG1, err := json.Marshal(g1Rev)
	require.NoError(t, err)
	var b1Hash string
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT hash FROM fabric_head WHERE deployment=$1`, f.depID).Scan(&b1Hash))
	b2Hash := registry.Digest([]byte("blk2:audit-revoke:" + f.depID))
	_, err = f.pool.Exec(ctx, `INSERT INTO fabric_block(deployment, block_no, hash, parent, data) VALUES($1, 2, $2, $3, ''::bytea)`, f.depID, b2Hash, b1Hash)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `INSERT INTO fabric_version(deployment, key, block_no, tx_index, tx_id, value) VALUES($1, $2, 2, 0, 'tx-g1-rev-r2', $3)`,
		f.depID, registry.Key("grant", f.rp.g1ID), rawG1)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE fabric_current SET value=$3 WHERE deployment=$1 AND key=$2`, f.depID, registry.Key("grant", f.rp.g1ID), rawG1)
	require.NoError(t, err)
	_, err = f.pool.Exec(ctx, `UPDATE fabric_head SET block_no=2, hash=$2 WHERE deployment=$1`, f.depID, b2Hash)
	require.NoError(t, err)

	// 3. Register order outcome case as B_RECOVERY (sendRevision=1 rejected, sendRevision=2 accepted & idempotent).
	bRecoveryID := gateway.CallerIdentity{Role: "B_RECOVERY", DID: "did:web:b.local:services:recovery"}
	cAuditorID := gateway.CallerIdentity{Role: "C_AUDITOR", DID: "did:web:c.local:auditors:c1"}

	casePre := gateway.OrderOutcomeCaseRequest{
		CaseID:       "urn:grad:case:created-1",
		SendRevision: 1,
		DeploymentID: f.depID,
		Request:      oReq,
		RequestHash:  oHash,
		ChallengeIDs: []string{oChal.ChallengeID},
	}
	_, err = svc.RegisterOrderOutcomeCase(ctx, bRecoveryID, casePre)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeStateChanged, protocol.CodeOf(err))

	caseReq := casePre
	caseReq.SendRevision = 2
	regResp, err := svc.RegisterOrderOutcomeCase(ctx, bRecoveryID, caseReq)
	require.NoError(t, err)
	assert.Equal(t, "REGISTERED", regResp.Status)
	// Idempotent retry succeeds.
	regRetry, err := svc.RegisterOrderOutcomeCase(ctx, bRecoveryID, caseReq)
	require.NoError(t, err)
	assert.Equal(t, regResp.CaseID, regRetry.CaseID)

	// 4. Non-C-auditor rejected with AUDIT_FORBIDDEN without leaking existence.
	for _, badID := range []gateway.CallerIdentity{
		{},
		bRecoveryID,
		{Role: "A_ADMIN", DID: "did:web:a.local:admins:a1"},
		{Role: "C_AUDITOR", DID: "did:web:c.local:auditors:unlisted"},
	} {
		_, err := svc.AuditOrderOutcome(ctx, badID, gateway.AuditOrderOutcomeRequest{CaseID: caseReq.CaseID})
		require.Error(t, err)
		assert.Equal(t, protocol.ErrCodeAuditForbidden, protocol.CodeOf(err))
		assert.NotContains(t, err.Error(), oResp.Order.OrderID)
	}

	// 5. Authorized C_AUDITOR executes reconciliation -> CREATED + MATCHED with h=1 < r=2.
	auditResp, err := svc.AuditOrderOutcome(ctx, cAuditorID, gateway.AuditOrderOutcomeRequest{CaseID: caseReq.CaseID})
	require.NoError(t, err)
	assert.Equal(t, "CREATED", auditResp.Outcome)
	require.NotNil(t, auditResp.OrderID)
	assert.Equal(t, oResp.Order.OrderID, *auditResp.OrderID)
	require.NotNil(t, auditResp.CreationDecisionID)
	assert.Equal(t, oResp.DecisionID, *auditResp.CreationDecisionID)
	assert.Equal(t, "MATCHED", auditResp.HistoricalStatus)
	require.NotNil(t, auditResp.DecisionBlock)
	assert.Equal(t, int64(1), *auditResp.DecisionBlock)
	require.NotNil(t, auditResp.RevocationBlock)
	assert.Equal(t, int64(2), *auditResp.RevocationBlock)
	assert.Equal(t, int64(1), auditResp.CheckNo)

	// 6. Outbox delivery failure persists attempts/last_error without setting delivered_at;
	// subsequent retry via DeliverPendingReceipts succeeds and marks delivered_at.
	nFail, err := svc.DeliverPendingReceipts(ctx, func(_ context.Context, _ gateway.OrderOutcomeReceipt) error {
		return errors.New("temporary transport failure")
	})
	require.Error(t, err)
	assert.Equal(t, 0, nFail)

	var attempts int64
	var lastErr string
	var deliveredAt *int64
	require.NoError(t, f.pool.QueryRow(ctx, `SELECT attempts, last_error, delivered_at FROM order_outcome_outbox WHERE deployment_id=$1 AND case_id=$2 AND check_no=1`, f.depID, caseReq.CaseID).Scan(&attempts, &lastErr, &deliveredAt))
	assert.Equal(t, int64(1), attempts)
	assert.Contains(t, lastErr, "temporary transport failure")
	assert.Nil(t, deliveredAt)

	var received []gateway.OrderOutcomeReceipt
	sender := func(_ context.Context, rcpt gateway.OrderOutcomeReceipt) error {
		if err := gateway.VerifyReceiptEcho(rcpt, rcpt); err != nil {
			return err
		}
		received = append(received, rcpt)
		return nil
	}
	n, err := svc.DeliverPendingReceipts(ctx, sender)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	require.Len(t, received, 1)
	assert.Equal(t, "CREATED", received[0].Outcome)
	assert.Equal(t, oResp.Order.OrderID, *received[0].OrderID)

	require.NoError(t, f.pool.QueryRow(ctx, `SELECT attempts, last_error, delivered_at FROM order_outcome_outbox WHERE deployment_id=$1 AND case_id=$2 AND check_no=1`, f.depID, caseReq.CaseID).Scan(&attempts, &lastErr, &deliveredAt))
	assert.Equal(t, int64(2), attempts)
	assert.Empty(t, lastErr)
	assert.NotNil(t, deliveredAt)

	// Second run finds 0 pending receipts.
	n2, err := svc.DeliverPendingReceipts(ctx, sender)
	require.NoError(t, err)
	assert.Equal(t, 0, n2)

	// 7. UNKNOWN -> NOT_CREATED lifecycle: unconsumed active challenge yields UNKNOWN, then NOT_CREATED after expiry.
	oNotReq := f.buildRequest(f.didB1, f.rp, protocol.ActionOrderCreate, protocol.ResourceOrders, gateway.DefaultProductID, 1, &qResp.Quote.QuoteID, 80000, "audit-not-created-1")
	oNotHash, _ := oNotReq.Hash(false)
	oNotChal := f.requestChallenge(t, svc, f.didB1, f.rp.taskID, oNotHash)

	notCaseReq := gateway.OrderOutcomeCaseRequest{
		CaseID:       "urn:grad:case:not-created-1",
		SendRevision: 2,
		DeploymentID: f.depID,
		Request:      oNotReq,
		RequestHash:  oNotHash,
		ChallengeIDs: []string{oNotChal.ChallengeID},
	}
	_, err = svc.RegisterOrderOutcomeCase(ctx, bRecoveryID, notCaseReq)
	require.NoError(t, err)

	// While challenge is still unexpired -> UNKNOWN.
	unkResp, err := svc.AuditOrderOutcome(ctx, cAuditorID, gateway.AuditOrderOutcomeRequest{CaseID: notCaseReq.CaseID})
	require.NoError(t, err)
	assert.Equal(t, "UNKNOWN", unkResp.Outcome)
	assert.Equal(t, "NO_DECISION", unkResp.HistoricalStatus)
	assert.Equal(t, int64(1), unkResp.CheckNo)

	// Advance clock past challenge expiry -> NOT_CREATED with checkNo=2.
	currentSec.Store(oNotChal.ExpiresAt)
	ncResp, err := svc.AuditOrderOutcome(ctx, cAuditorID, gateway.AuditOrderOutcomeRequest{CaseID: notCaseReq.CaseID})
	require.NoError(t, err)
	assert.Equal(t, "NOT_CREATED", ncResp.Outcome)
	assert.Equal(t, "NO_DECISION", ncResp.HistoricalStatus)
	assert.Equal(t, int64(2), ncResp.CheckNo)
}

func TestWorkbenchDecisionAndTaskEvidenceScope(t *testing.T) {
	f := newGatewayFixture(t)
	svc := f.newService(t, func(cfg *gateway.Config) { cfg.RecordWorkbenchEvidence = true })
	ctx := t.Context()

	f.updateContext(t, svc, f.directU.taskID, 0, policy.RiskNormal, f.fixedNow.Unix()+3600)
	req := f.buildRequest(f.didU, f.directU, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "workbench-decision-scope")
	reqHash, err := req.Hash(false)
	require.NoError(t, err)
	chal := f.requestChallenge(t, svc, f.didU, f.directU.taskID, reqHash)
	pkg := f.assemblePackage(t, req, f.directU, chal, f.uPresPrefix, f.uKeyID, f.privU, f.fixedNow.Unix())
	out, err := f.executePkg(t, svc, pkg)
	require.NoError(t, err)

	actorDecision, err := svc.ReadDecision(ctx, out.DecisionID, f.didU, false)
	require.NoError(t, err)
	require.Equal(t, f.didU, actorDecision.Actor)
	require.Equal(t, f.directU.taskID, actorDecision.TaskID)
	_, err = svc.ReadDecision(ctx, out.DecisionID, f.didB1, false)
	require.ErrorIs(t, err, gateway.ErrDecisionNotFound)
	auditorDecision, err := svc.ReadDecision(ctx, out.DecisionID, "did:web:c.local:auditor", true)
	require.NoError(t, err)
	require.Equal(t, actorDecision, auditorDecision)
	_, err = svc.ReadDecision(ctx, "unknown-decision", f.didU, true)
	require.ErrorIs(t, err, gateway.ErrDecisionNotFound)

	owned, err := svc.ReadTaskEvidence(ctx, f.didU, f.directU.taskID)
	require.NoError(t, err)
	require.Len(t, owned.Decisions, 1)
	require.Equal(t, out.DecisionID, owned.Decisions[0].DecisionID)
	require.Len(t, owned.Quotes, 1)
	require.Equal(t, out.Quote.QuoteID, owned.Quotes[0].QuoteID)
	require.NotEmpty(t, owned.Identity)
	require.NotEmpty(t, owned.Disclosures)
	for _, disclosure := range owned.Disclosures {
		for key := range disclosure.Disclosed {
			require.Contains(t, []string{"domain", "role"}, key)
		}
	}
	for _, scope := range [][2]string{{f.didB1, f.directU.taskID}, {f.didU, f.rp.taskID}} {
		outside, err := svc.ReadTaskEvidence(ctx, scope[0], scope[1])
		require.NoError(t, err)
		require.Empty(t, outside.Decisions)
		require.Empty(t, outside.Quotes)
		require.Empty(t, outside.Identity)
		require.Empty(t, outside.Disclosures)
	}
}

func TestOnDecisionCommittedSubSecondTimingHook(t *testing.T) {
	f := newGatewayFixture(t)
	const responseDelay = 50 * time.Millisecond

	var (
		mu      sync.Mutex
		timings = map[string]gateway.DecisionTiming{}
	)
	liveNow := time.Now().UTC()
	f.state.SetMonoClock(time.Now)
	f.state.SetStaticProbe(&ledger.ProbeLease{
		TxID:           "probe-timing-1",
		ProbeBlock:     1,
		SentAt:         liveNow,
		Deadline:       liveNow.Add(600 * time.Second),
		SentMonoNs:     liveNow.UnixNano(),
		DeadlineMonoNs: liveNow.Add(600 * time.Second).UnixNano(),
		CheckedMonoNs:  liveNow.UnixNano(),
	})

	svc := f.newService(t, func(cfg *gateway.Config) {
		cfg.NowFn = nil // live host clock for sub-second timing
		cfg.OnDecisionCommitted = func(dt gateway.DecisionTiming) {
			mu.Lock()
			timings[dt.DecisionID] = dt
			mu.Unlock()
		}
		cfg.BeforeWriteResponse = func(_ string) {
			time.Sleep(responseDelay)
		}
	})
	f.updateContext(t, svc, f.directU.taskID, 0, policy.RiskNormal, liveNow.Unix()+3600)

	// 1. Delayed-response ALLOW request.
	req := f.buildRequest(f.didU, f.directU, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "timing-allow-1")
	reqHash, _ := req.Hash(false)
	chal := f.requestChallenge(t, svc, f.didU, f.directU.taskID, reqHash)
	pkg := f.assemblePackage(t, req, f.directU, chal, f.uPresPrefix, f.uKeyID, f.privU, time.Now().Unix())

	submittedAt := time.Now().UTC()
	out, err := f.executePkg(t, svc, pkg)
	respondedAt := time.Now().UTC()
	require.NoError(t, err)

	mu.Lock()
	dt, ok := timings[out.DecisionID]
	mu.Unlock()
	require.True(t, ok, "OnDecisionCommitted must be invoked for ALLOW decision")
	assert.Equal(t, "ALLOW", dt.Outcome)
	assert.Equal(t, chal.ChallengeID, dt.ChallengeID)
	assert.False(t, dt.DecisionAt.Before(submittedAt))
	assert.False(t, dt.CommittedAt.Before(dt.DecisionAt))
	assert.GreaterOrEqual(t, respondedAt.Sub(dt.CommittedAt), responseDelay-10*time.Millisecond)

	// Verify persisted nanosecond timestamps via GetDecision.
	stored, err := svc.GetDecision(t.Context(), out.DecisionID)
	require.NoError(t, err)
	require.NotNil(t, stored.DecisionAtNs)
	assert.Equal(t, dt.DecisionAt.UnixNano(), *stored.DecisionAtNs)
	require.NotNil(t, stored.ProbeSentAtNs)
	require.NotNil(t, stored.ProbeDeadlineNs)
	assert.Greater(t, *stored.ProbeDeadlineNs, *stored.ProbeSentAtNs)

	// 2. Delayed-response DENY request (BLOCKED context).
	f.updateContext(t, svc, f.directU.taskID, 1, policy.RiskBlocked, liveNow.Unix()+3600)
	denyReq := f.buildRequest(f.didU, f.directU, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "timing-deny-1")
	denyHash, _ := denyReq.Hash(false)
	denyChal := f.requestChallenge(t, svc, f.didU, f.directU.taskID, denyHash)
	denyPkg := f.assemblePackage(t, denyReq, f.directU, denyChal, f.uPresPrefix, f.uKeyID, f.privU, time.Now().Unix())

	_, denyErr := f.executePkg(t, svc, denyPkg)
	denyRespondedAt := time.Now().UTC()
	require.Error(t, denyErr)
	assert.Equal(t, protocol.ErrCodePolicyDenied, protocol.CodeOf(denyErr))
	denyDecID := gateway.DecisionIDOf(denyErr)
	require.NotNil(t, denyDecID)

	mu.Lock()
	denyDT, ok := timings[*denyDecID]
	mu.Unlock()
	require.True(t, ok, "OnDecisionCommitted must be invoked for DENY decision")
	assert.Equal(t, "DENY", denyDT.Outcome)
	assert.GreaterOrEqual(t, denyRespondedAt.Sub(denyDT.CommittedAt), responseDelay-10*time.Millisecond)

	// 3. Second-level deadline boundary preserved alongside sub-second decisionAtNs capture.
	deadline := f.fixedNow.Unix() + 10
	curTime := time.Unix(deadline-1, 850_000_000).UTC()
	f.state.SetMonoClock(func() time.Time { return f.fixedNow })
	f.state.SetStaticProbe(&ledger.ProbeLease{
		TxID:           "probe-boundary-1",
		ProbeBlock:     1,
		SentAt:         f.fixedNow,
		Deadline:       f.fixedNow.Add(600 * time.Second),
		SentMonoNs:     f.fixedNow.UnixNano(),
		DeadlineMonoNs: f.fixedNow.Add(600 * time.Second).UnixNano(),
		CheckedMonoNs:  f.fixedNow.UnixNano(),
	})
	boundSvc := f.newService(t, func(cfg *gateway.Config) {
		cfg.NowFn = func() time.Time { return curTime }
	})
	f.updateContext(t, boundSvc, f.directU.taskID, 2, policy.RiskNormal, deadline)

	bReq1 := f.buildRequest(f.didU, f.directU, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "sec-boundary-allow")
	bHash1, _ := bReq1.Hash(false)
	bChal1 := f.requestChallenge(t, boundSvc, f.didU, f.directU.taskID, bHash1)
	bPkg1 := f.assemblePackage(t, bReq1, f.directU, bChal1, f.uPresPrefix, f.uKeyID, f.privU, curTime.Unix())
	_, err = f.executePkg(t, boundSvc, bPkg1)
	require.NoError(t, err)

	// At exact deadline second (+100ms) -> CONTEXT_STALE (unconsumed).
	bReq2 := f.buildRequest(f.didU, f.directU, protocol.ActionQuoteRead, protocol.ResourceQuotes, gateway.DefaultProductID, 1, nil, 0, "sec-boundary-stale")
	bHash2, _ := bReq2.Hash(false)
	bChal2 := f.requestChallenge(t, boundSvc, f.didU, f.directU.taskID, bHash2)
	bPkg2 := f.assemblePackage(t, bReq2, f.directU, bChal2, f.uPresPrefix, f.uKeyID, f.privU, curTime.Unix())
	curTime = time.Unix(deadline, 100_000_000).UTC()
	_, err = f.executePkg(t, boundSvc, bPkg2)
	require.Error(t, err)
	assert.Equal(t, protocol.ErrCodeContextStale, protocol.CodeOf(err))
	assert.Nil(t, gateway.DecisionIDOf(err))
	f.assertChallengeUnconsumed(t, bChal2.ChallengeID)
}
