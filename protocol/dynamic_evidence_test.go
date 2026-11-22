package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/protocol/registry"
)

type dynamicProtocolFixture struct {
	ctx       context.Context
	now       time.Time
	nbf, exp  int64
	vf, vu    string
	depID     string
	ca        *TestCA
	dids      *DIDWebResolver
	tCalls    *atomic.Int64
	tServer   *httptest.Server
	docs      map[string][]byte
	privT     *ecdsa.PrivateKey
	pubT      string
	privIA    *ecdsa.PrivateKey
	pubIA     string
	privIB    *ecdsa.PrivateKey
	pubIB     string
	privIB2   *ecdsa.PrivateKey
	pubIB2    string
	privU     *ecdsa.PrivateKey
	pubU      string
	privB1    *ecdsa.PrivateKey
	pubB1     string
	privB1Rot *ecdsa.PrivateKey
	pubB1Rot  string
	privIC    *ecdsa.PrivateKey
	pubIC     string
	privC     *ecdsa.PrivateKey
	pubC      string
	snap      *SnapshotView
	pkg       AccessEvidencePackage
	sdB1Dept  *SignedSDJWTCredential
	certBJWS  string
	certBDig  string
	grantID   string
}

func strPtr(s string) *string { return &s }

func newDynamicProtocolFixture(t *testing.T, withDepartmentClaim bool) *dynamicProtocolFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	nbf := now.Add(-time.Minute).Unix()
	exp := now.Add(time.Hour).Unix()
	vf := time.Unix(nbf, 0).UTC().Format(time.RFC3339)
	vu := time.Unix(exp, 0).UTC().Format(time.RFC3339)

	ca, err := GenerateTestCA(now)
	require.NoError(t, err)
	caPool, err := ParseTestCAPublic(ca.CertPEM)
	require.NoError(t, err)
	certs := make(map[string]*HostTLSCert, len(ControlledTestDomains))
	for _, host := range ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		require.NoError(t, err)
		certs[host] = hc
	}

	privT, pubT := mustGenKeyPair(t)
	privIA, pubIA := mustGenKeyPair(t)
	privIB, pubIB := mustGenKeyPair(t)
	privIB2, pubIB2 := mustGenKeyPair(t)
	privIC, pubIC := mustGenKeyPair(t)
	privU, pubU := mustGenKeyPair(t)
	privB1, pubB1 := mustGenKeyPair(t)
	privB1Rot, pubB1Rot := mustGenKeyPair(t)
	privC, pubC := mustGenKeyPair(t)

	didT := "did:web:t.local"
	didIA := "did:web:a.local:ia"
	didU := "did:web:a.local:u"
	didIB := "did:web:b.local:ib"
	didB1 := "did:web:b.local:b1"
	didIC := "did:web:c.local:ic"
	didC := "did:web:c.local:supplier"

	docs := map[string][]byte{}
	makeDoc := func(did, keyID string, pub *ecdsa.PublicKey, purposes ...string) string {
		d, err := NewDIDDocument(did, keyID, pub, purposes...)
		require.NoError(t, err)
		raw, err := MarshalJCS(d)
		require.NoError(t, err)
		dig, err := d.Digest()
		require.NoError(t, err)
		docs[did] = raw
		return dig
	}
	digT := makeDoc(didT, didT+"#key-1", &privT.PublicKey, KeyPurposeAssertionMethod)
	digIA := makeDoc(didIA, didIA+"#key-1", &privIA.PublicKey, KeyPurposeAssertionMethod)
	digU := makeDoc(didU, didU+"#key-1", &privU.PublicKey, KeyPurposeAssertionMethod, KeyPurposeAuthentication)
	digIB := makeDoc(didIB, didIB+"#key-1", &privIB.PublicKey, KeyPurposeAssertionMethod)
	digB1 := makeDoc(didB1, didB1+"#key-1", &privB1.PublicKey, KeyPurposeAssertionMethod, KeyPurposeAuthentication)
	digIC := makeDoc(didIC, didIC+"#key-1", &privIC.PublicKey, KeyPurposeAssertionMethod)
	digC := makeDoc(didC, didC+"#key-1", &privC.PublicKey, KeyPurposeAssertionMethod, KeyPurposeAuthentication)

	var tCalls atomic.Int64
	tSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tCalls.Add(1)
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write(docs[didT])
	}))
	tSrv.TLS = &tls.Config{Certificates: []tls.Certificate{certs["t.local"].TLSCert}, MinVersion: tls.VersionTLS13}
	tSrv.StartTLS()
	t.Cleanup(tSrv.Close)

	startDIDServer := func(host string, pathMap map[string]string) *httptest.Server {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			did, ok := pathMap[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/did+json")
			_, _ = w.Write(docs[did])
		}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{certs[host].TLSCert}, MinVersion: tls.VersionTLS13}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv
	}
	aSrv := startDIDServer("a.local", map[string]string{"/ia/did.json": didIA, "/u/did.json": didU})
	bSrv := startDIDServer("b.local", map[string]string{"/ib/did.json": didIB, "/b1/did.json": didB1})
	cSrv := startDIDServer("c.local", map[string]string{"/ic/did.json": didIC, "/supplier/did.json": didC})

	dids, err := NewDIDWebResolver(caPool, map[string]string{
		"t.local:443": strings.TrimPrefix(tSrv.URL, "https://"),
		"a.local:443": strings.TrimPrefix(aSrv.URL, "https://"),
		"b.local:443": strings.TrimPrefix(bSrv.URL, "https://"),
		"c.local:443": strings.TrimPrefix(cSrv.URL, "https://"),
	})
	require.NoError(t, err)
	_, err = dids.RegisterPreseed(RootPreseed{
		DID: didT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKeyHex: pubT,
		DIDDocumentDigest: digT, RawDocument: docs[didT],
	})
	require.NoError(t, err)

	depID := strings.Repeat("7", 64)
	bClaims := []string{"domain", "role"}
	if withDepartmentClaim {
		bClaims = []string{"department", "domain", "role"}
	}

	issueCert := func(domID, domDID, issuerDID, certID string, kv uint64, claims []string) (string, string, registry.Domain, registry.Certification) {
		scopes := []IssuerScope{{ID: issuerDID, AppKeyVersion: kv, CredentialTypes: []string{CredentialTypeEnterpriseIdentity}, ClaimNames: claims}}
		jws, dig, err := SignDomainAuthorityCredential(privT, didT+"#key-1", &DomainAuthorityCredential{
			Type: []string{CredentialTypeVC, CredentialTypeDomainAuthority}, ID: certID, DeploymentID: depID,
			Issuer: didT, Iss: didT, Sub: domDID, IssuerKeyVersion: 1,
			ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
			CredentialStatus: CredentialStatus{ID: certID, Type: StatusTypeDomainCertification},
			CredentialSubject: DomainAuthoritySubject{
				ID: domDID, DomainID: domID,
				IdentityIssuers: scopes,
			},
		})
		require.NoError(t, err)
		dom := registry.Domain{Bound: registry.Bound{DeploymentID: depID}, ID: domID, DID: domDID, Issuers: []string{issuerDID}, Certification: certID, Version: registry.Version{Status: registry.Active, Revision: 1}}
		cert := registry.Certification{
			Bound: registry.Bound{DeploymentID: depID}, ID: certID, Domain: domID, RootKeyVersion: 1, Digest: dig,
			Scopes:   scopes,
			Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1},
		}
		return jws, dig, dom, cert
	}

	certAJWS, _, domA, certA := issueCert("A", "did:web:a.local", didIA, "urn:grad:cert:A-v1", 1, []string{"domain", "role"})
	certBJWS, certBDig, domB, certB := issueCert("B", "did:web:b.local", didIB, "urn:grad:cert:B-v1", 1, bClaims)
	certCJWS, _, domC, certC := issueCert("C", "did:web:c.local", didIC, "urn:grad:cert:C-v1", 1, []string{"domain", "role"})

	issueVC := func(priv *ecdsa.PrivateKey, issDID, subDID, dom, role, cid string, kv uint64, extra map[string]string, claims []string) (*SignedSDJWTCredential, registry.Credential) {
		pub := &privB1.PublicKey
		if subDID == didU {
			pub = &privU.PublicKey
		} else if subDID == didC {
			pub = &privC.PublicKey
		}
		jwk, err := JWKFromPublicKey(pub)
		require.NoError(t, err)
		sd, err := IssueEnterpriseIdentityCredential(priv, issDID+"#key-1", EnterpriseIdentityCredential{
			Type: []string{CredentialTypeVC, CredentialTypeEnterpriseIdentity}, ID: cid, DeploymentID: depID,
			Issuer: issDID, Iss: issDID, Sub: subDID, IssuerKeyVersion: kv, AppKeyVersion: 1,
			ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
			CredentialStatus:  CredentialStatus{ID: cid, Type: StatusTypeCredential},
			CredentialSubject: SDJWTCredentialSubject{ID: subDID},
			Cnf:               ConfirmationKey{JWK: jwk},
		}, dom, role, extra)
		require.NoError(t, err)
		rec := registry.Credential{
			Bound: registry.Bound{DeploymentID: depID}, ID: cid, Issuer: issDID, Subject: subDID,
			IssuerKeyVersion: kv, SubjectKeyVersion: 1, Type: CredentialTypeEnterpriseIdentity,
			ClaimNames: claims, Digest: sd.AnchorDigest, Interval: registry.Interval{NBF: nbf, EXP: exp},
			Version: registry.Version{Status: registry.Active, Revision: 1},
		}
		return sd, rec
	}

	sdU, credU := issueVC(privIA, didIA, didU, "A", "USER", "urn:cred:u", 1, nil, []string{"domain", "role"})
	sdC, credC := issueVC(privIC, didIC, didC, "C", "SERVICE", "urn:cred:c", 1, nil, []string{"domain", "role"})
	var extraB1 map[string]string
	if withDepartmentClaim {
		extraB1 = map[string]string{"department": "procurement"}
	}
	sdB1, credB1 := issueVC(privIB, didIB, didB1, "B", "AGENT", "urn:cred:b1", 1, extraB1, bClaims)

	spec := TaskSpec{
		SupplierID: "urn:grad:supplier:C", ProductID: "urn:grad:product:P1", MaxQuantity: 1, Currency: "CNY",
		Resources: []string{ResourceQuotes}, Actions: []string{ActionQuoteRead}, Description: "quote-read-task",
	}
	specDig, err := spec.Digest()
	require.NoError(t, err)
	taskID := "urn:grad:task:dynamic-1"
	taskRec := registry.Task{
		Bound: registry.Bound{DeploymentID: depID}, ID: taskID, Creator: didU, CreatorCredential: credU.ID,
		CreatorKeyVersion: 1, Domain: "A", Mode: ModeResourcePreauthorized, Resource: ResourceQuotes,
		Digest: specDig, Interval: registry.Interval{NBF: nbf, EXP: exp}, Version: registry.Version{Status: registry.Active, Revision: 1},
	}

	g0JWS, g0Dig, err := SignGrant(privC, didC+"#key-1", &GrantClaims{
		ID: "urn:grant:dynamic:g0", SchemaVersion: SchemaVersion, DeploymentID: depID,
		RootID: "urn:grant:dynamic:g0", TaskID: taskID, AuthorizationMode: ModeResourcePreauthorized,
		PrincipalDomain: "A", ResourceID: ResourceQuotes, Issuer: didC, Grantee: didU,
		IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: credC.ID, GranteeCredentialID: credU.ID,
		MaxAmountMinor: 100000, Resources: []string{ResourceQuotes}, Actions: []string{ActionQuoteRead},
		Suppliers: []string{"urn:grad:supplier:C"}, Aud: "https://c.local", Currency: "CNY", RemainingDepth: 1,
		NBF: nbf + 2, EXP: exp - 2,
	})
	require.NoError(t, err)
	g1JWS, g1Dig, err := SignGrant(privU, didU+"#key-1", &GrantClaims{
		ID: "urn:grant:dynamic:g1", SchemaVersion: SchemaVersion, DeploymentID: depID,
		ParentID: strPtr("urn:grant:dynamic:g0"), ParentDigest: strPtr(g0Dig),
		RootID: "urn:grant:dynamic:g0", TaskID: taskID, AuthorizationMode: ModeResourcePreauthorized,
		PrincipalDomain: "A", ResourceID: ResourceQuotes, Issuer: didU, Grantee: didB1,
		IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: credU.ID, GranteeCredentialID: credB1.ID,
		MaxAmountMinor: 100000, Resources: []string{ResourceQuotes}, Actions: []string{ActionQuoteRead},
		Suppliers: []string{"urn:grad:supplier:C"}, Aud: "https://c.local", Currency: "CNY", RemainingDepth: 0,
		NBF: nbf + 2, EXP: exp - 2,
	})
	require.NoError(t, err)

	g0Rec := registry.Grant{
		Bound: registry.Bound{DeploymentID: depID}, ID: "urn:grant:dynamic:g0", Schema: SchemaVersion,
		Root: "urn:grant:dynamic:g0", Task: taskID, Mode: ModeResourcePreauthorized, Domain: "A", Resource: ResourceQuotes,
		Issuer: didC, Grantee: didU, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: credC.ID, GranteeCredential: credU.ID,
		Depth: 1, Digest: g0Dig, Interval: registry.Interval{NBF: nbf + 2, EXP: exp - 2}, Version: registry.Version{Status: registry.Active, Revision: 1},
	}
	g1Rec := registry.Grant{
		Bound: registry.Bound{DeploymentID: depID}, ID: "urn:grant:dynamic:g1", Schema: SchemaVersion,
		Parent: "urn:grant:dynamic:g0", ParentDigest: g0Dig, Root: "urn:grant:dynamic:g0", Task: taskID, Mode: ModeResourcePreauthorized,
		Domain: "A", Resource: ResourceQuotes, Issuer: didU, Grantee: didB1, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredential: credU.ID, GranteeCredential: credB1.ID, Depth: 0, Digest: g1Dig,
		Interval: registry.Interval{NBF: nbf + 2, EXP: exp - 2}, Version: registry.Version{Status: registry.Active, Revision: 1},
	}

	snap := &SnapshotView{
		Height: 10, Now: now, ClockError: registry.ClockError, DeploymentID: depID,
		Root:           registry.RootRecord{DID: didT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKey: pubT, DocumentDigest: digT},
		Domains:        map[string]registry.Domain{"A": domA, "B": domB, "C": domC},
		Certifications: map[string]registry.Certification{certA.ID: certA, certB.ID: certB, certC.ID: certC},
		Identities: map[string]registry.Identity{
			didIA: {Bound: registry.Bound{DeploymentID: depID}, ID: didIA, Domain: "A", Kind: "ISSUER", DocumentDigest: digIA, KeyID: didIA + "#key-1", KeyVersion: 1, PublicKey: pubIA, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didIB: {Bound: registry.Bound{DeploymentID: depID}, ID: didIB, Domain: "B", Kind: "ISSUER", DocumentDigest: digIB, KeyID: didIB + "#key-1", KeyVersion: 1, PublicKey: pubIB, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didIC: {Bound: registry.Bound{DeploymentID: depID}, ID: didIC, Domain: "C", Kind: "ISSUER", DocumentDigest: digIC, KeyID: didIC + "#key-1", KeyVersion: 1, PublicKey: pubIC, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didU:  {Bound: registry.Bound{DeploymentID: depID}, ID: didU, Domain: "A", Kind: "USER", DocumentDigest: digU, KeyID: didU + "#key-1", KeyVersion: 1, PublicKey: pubU, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didB1: {Bound: registry.Bound{DeploymentID: depID}, ID: didB1, Domain: "B", Kind: "USER", DocumentDigest: digB1, KeyID: didB1 + "#key-1", KeyVersion: 1, PublicKey: pubB1, Version: registry.Version{Status: registry.Active, Revision: 1}},
			didC:  {Bound: registry.Bound{DeploymentID: depID}, ID: didC, Domain: "C", Kind: "SERVICE", DocumentDigest: digC, KeyID: didC + "#key-1", KeyVersion: 1, PublicKey: pubC, Version: registry.Version{Status: registry.Active, Revision: 1}},
		},
		Credentials: map[string]registry.Credential{credU.ID: credU, credB1.ID: credB1, credC.ID: credC},
		Tasks:       map[string]registry.Task{taskRec.ID: taskRec},
		Grants:      map[string]registry.Grant{g0Rec.ID: g0Rec, g1Rec.ID: g1Rec},
	}

	req := AccessRequest{
		SchemaVersion: SchemaVersion, DeploymentID: depID, Actor: didB1, PrincipalDomain: "A",
		AuthorizationMode: ModeResourcePreauthorized, TaskID: taskID, Audience: "https://c.local",
		Resource: ResourceQuotes, Action: ActionQuoteRead, SupplierID: "urn:grad:supplier:C",
		ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 0, IdempotencyKey: "dynamic-ik-1",
	}
	pkg := AccessEvidencePackage{
		Request: req, TaskSpec: spec,
		AncestorCredentials: []AncestorCredential{{CredentialID: credU.ID, Presentation: sdU.PresentationPrefix}, {CredentialID: credC.ID, Presentation: sdC.PresentationPrefix}},
		Grants:              []string{g0JWS, g1JWS},
		TrustPaths: []TrustPathEntry{
			{Issuer: didIA, DomainCertification: certAJWS},
			{Issuer: didIB, DomainCertification: certBJWS},
			{Issuer: didIC, DomainCertification: certCJWS},
		},
	}

	return &dynamicProtocolFixture{
		ctx: ctx, now: now, nbf: nbf, exp: exp, vf: vf, vu: vu, depID: depID, ca: ca, dids: dids,
		tCalls: &tCalls, tServer: tSrv, docs: docs,
		privT: privT, pubT: pubT, privIA: privIA, pubIA: pubIA, privIB: privIB, pubIB: pubIB, privIB2: privIB2, pubIB2: pubIB2,
		privU: privU, pubU: pubU, privB1: privB1, pubB1: pubB1, privB1Rot: privB1Rot, pubB1Rot: pubB1Rot, privIC: privIC, pubIC: pubIC, privC: privC, pubC: pubC,
		snap: snap, pkg: pkg, sdB1Dept: sdB1, certBJWS: certBJWS, certBDig: certBDig, grantID: g1Rec.ID,
	}
}

func (e *dynamicProtocolFixture) signPackage(t *testing.T, chalID, presPrefix string) (AccessEvidencePackage, ChallengeContext) {
	t.Helper()
	nonce, err := GenerateNonce()
	require.NoError(t, err)
	chal := ChallengeContext{
		ChallengeID: chalID, Nonce: nonce, Audience: "https://c.local",
		IssuedAt: e.now.Unix(), ExpiresAt: e.now.Unix() + 30,
	}
	p := e.pkg
	_, _, err = AssembleAccessEvidencePackage(&p, presPrefix, "did:web:b.local:b1#key-1", e.privB1, chal, e.now.Unix(), false)
	require.NoError(t, err)
	return p, chal
}

func TestSignatureCacheAndStaleKeyVersion(t *testing.T) {
	env := newDynamicProtocolFixture(t, false)
	cache := NewSignatureCache()

	// 1. Cold request populates B1 cache (3 TrustPaths + 2 Grants + 3 SD-JWTs = 8 JWS signatures).
	pkg1, chal1 := env.signPackage(t, "chal-cold", env.sdB1Dept.PresentationPrefix)
	_, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkg1, env.snap, env.dids, chal1, cache)
	require.NoError(t, err)
	assert.Equal(t, int64(0), cache.Hits())
	assert.Equal(t, int64(8), cache.Misses())

	// 2. Warm request with new challenge/KB-JWT skips all 8 static JWS verifications.
	cache.ResetStats()
	pkg2, chal2 := env.signPackage(t, "chal-warm", env.sdB1Dept.PresentationPrefix)
	_, err = VerifyAccessEvidencePackageWithCache(env.ctx, &pkg2, env.snap, env.dids, chal2, cache)
	require.NoError(t, err)
	assert.Equal(t, int64(8), cache.Hits())
	assert.Equal(t, int64(0), cache.Misses())

	// 3. B1 rotates key (KeyVersion 1->2); warm cache hit must NOT bypass dynamic state -> KEY_VERSION_STALE.
	cache.ResetStats()
	rotSnap := *env.snap
	rotSnap.Identities = maps.Clone(env.snap.Identities)
	b1Rot := rotSnap.Identities["did:web:b.local:b1"]
	b1Rot.KeyVersion = 2
	b1Rot.KeyID = "did:web:b.local:b1#key-2"
	b1Rot.PublicKey = env.pubB1Rot
	rotSnap.Identities["did:web:b.local:b1"] = b1Rot

	pkg3, chal3 := env.signPackage(t, "chal-rot", env.sdB1Dept.PresentationPrefix)
	_, err = VerifyAccessEvidencePackageWithCache(env.ctx, &pkg3, &rotSnap, env.dids, chal3, cache)
	assert.True(t, HasCode(err, ErrCodeKeyVersionStale), "got %v", err)
	assert.Greater(t, cache.Hits(), int64(0))

	// 4. Domain B suspended -> DOMAIN_INACTIVE despite cached cert and ACTIVE VC/G1.
	suspSnap := *env.snap
	suspSnap.Domains = maps.Clone(env.snap.Domains)
	domB := suspSnap.Domains["B"]
	domB.Status = registry.Suspended
	suspSnap.Domains["B"] = domB
	pkg4, chal4 := env.signPackage(t, "chal-dom-susp", env.sdB1Dept.PresentationPrefix)
	_, err = VerifyAccessEvidencePackageWithCache(env.ctx, &pkg4, &suspSnap, env.dids, chal4, cache)
	assert.True(t, HasCode(err, ErrCodeDomainInactive), "got %v", err)

	// 5. Atomic domain certification replacement (v1 -> v2, preserving IB key/scope). Old cert rejected; new cert allowed.
	scopesV2 := []IssuerScope{{ID: "did:web:b.local:ib", AppKeyVersion: 1, CredentialTypes: []string{CredentialTypeEnterpriseIdentity}, ClaimNames: []string{"domain", "role"}}}
	certB2JWS, certB2Dig, err := SignDomainAuthorityCredential(env.privT, "did:web:t.local#key-1", &DomainAuthorityCredential{
		Type: []string{CredentialTypeVC, CredentialTypeDomainAuthority}, ID: "urn:grad:cert:B-v2", DeploymentID: env.depID,
		Issuer: "did:web:t.local", Iss: "did:web:t.local", Sub: "did:web:b.local", IssuerKeyVersion: 1,
		ValidFrom: env.vf, ValidUntil: env.vu, NBF: env.nbf, EXP: env.exp,
		CredentialStatus: CredentialStatus{ID: "urn:grad:cert:B-v2", Type: StatusTypeDomainCertification},
		CredentialSubject: DomainAuthoritySubject{
			ID: "did:web:b.local", DomainID: "B",
			IdentityIssuers: scopesV2,
		},
	})
	require.NoError(t, err)
	v2Snap := *env.snap
	v2Snap.Domains = maps.Clone(env.snap.Domains)
	db2 := v2Snap.Domains["B"]
	db2.Certification = "urn:grad:cert:B-v2"
	db2.Revision = 2
	v2Snap.Domains["B"] = db2
	v2Snap.Certifications = maps.Clone(env.snap.Certifications)
	v2Snap.Certifications["urn:grad:cert:B-v2"] = registry.Certification{
		Bound: registry.Bound{DeploymentID: env.depID}, ID: "urn:grad:cert:B-v2", Domain: "B", RootKeyVersion: 1, Digest: certB2Dig,
		Scopes: scopesV2, Interval: registry.Interval{NBF: env.nbf, EXP: env.exp}, Version: registry.Version{Status: registry.Active, Revision: 1},
	}

	pkgOldCert, chalOldCert := env.signPackage(t, "chal-oldcert", env.sdB1Dept.PresentationPrefix)
	_, err = VerifyAccessEvidencePackageWithCache(env.ctx, &pkgOldCert, &v2Snap, env.dids, chalOldCert, cache)
	assert.True(t, HasCode(err, ErrCodeDomainCertificationInvalid), "got %v", err)

	env.pkg.TrustPaths[1].DomainCertification = certB2JWS
	pkgNewCert, chalNewCert := env.signPackage(t, "chal-newcert", env.sdB1Dept.PresentationPrefix)
	_, err = VerifyAccessEvidencePackageWithCache(env.ctx, &pkgNewCert, &v2Snap, env.dids, chalNewCert, cache)
	require.NoError(t, err)

	// 6. IB updates key (v1 -> v2) and re-issues VC; presenting old cert fails until T renews certification for IB v2.
	newIBDoc, err := NewDIDDocument("did:web:b.local:ib", "did:web:b.local:ib#key-2", &env.privIB2.PublicKey, KeyPurposeAssertionMethod)
	require.NoError(t, err)
	newIBDig, err := newIBDoc.Digest()
	require.NoError(t, err)
	env.docs["did:web:b.local:ib"], err = MarshalJCS(newIBDoc)
	require.NoError(t, err)

	sdB1IB2, err := IssueEnterpriseIdentityCredential(env.privIB2, "did:web:b.local:ib#key-2", EnterpriseIdentityCredential{
		Type: []string{CredentialTypeVC, CredentialTypeEnterpriseIdentity}, ID: "urn:cred:b1-ib2", DeploymentID: env.depID,
		Issuer: "did:web:b.local:ib", Iss: "did:web:b.local:ib", Sub: "did:web:b.local:b1", IssuerKeyVersion: 2, AppKeyVersion: 1,
		ValidFrom: env.vf, ValidUntil: env.vu, NBF: env.nbf, EXP: env.exp,
		CredentialStatus:  CredentialStatus{ID: "urn:cred:b1-ib2", Type: StatusTypeCredential},
		CredentialSubject: SDJWTCredentialSubject{ID: "did:web:b.local:b1"},
		Cnf:               env.sdB1Dept.Claims.Cnf,
	}, "B", "AGENT", nil)
	require.NoError(t, err)

	ib2CredRec := registry.Credential{
		Bound: registry.Bound{DeploymentID: env.depID}, ID: sdB1IB2.Claims.ID, Issuer: "did:web:b.local:ib", Subject: "did:web:b.local:b1",
		IssuerKeyVersion: 2, SubjectKeyVersion: 1, Type: CredentialTypeEnterpriseIdentity, ClaimNames: []string{"domain", "role"},
		Digest: sdB1IB2.AnchorDigest, Interval: registry.Interval{NBF: env.nbf, EXP: env.exp}, Version: registry.Version{Status: registry.Active, Revision: 1},
	}
	g1NewJWS, g1NewDig, err := SignGrant(env.privU, "did:web:a.local:u#key-1", &GrantClaims{
		ID: "urn:grant:dynamic:g1", SchemaVersion: SchemaVersion, DeploymentID: env.depID,
		ParentID: strPtr("urn:grant:dynamic:g0"), ParentDigest: strPtr(env.snap.Grants["urn:grant:dynamic:g0"].Digest),
		RootID: "urn:grant:dynamic:g0", TaskID: env.pkg.Request.TaskID, AuthorizationMode: ModeResourcePreauthorized,
		PrincipalDomain: "A", ResourceID: ResourceQuotes, Issuer: "did:web:a.local:u", Grantee: "did:web:b.local:b1",
		IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: "urn:cred:u", GranteeCredentialID: sdB1IB2.Claims.ID,
		MaxAmountMinor: 100000, Resources: []string{ResourceQuotes}, Actions: []string{ActionQuoteRead},
		Suppliers: []string{"urn:grad:supplier:C"}, Aud: "https://c.local", Currency: "CNY", RemainingDepth: 0,
		NBF: env.nbf + 2, EXP: env.exp - 2,
	})
	require.NoError(t, err)

	ib2Snap := v2Snap
	ib2Snap.Identities = maps.Clone(v2Snap.Identities)
	ib2ID := ib2Snap.Identities["did:web:b.local:ib"]
	ib2ID.KeyID, ib2ID.KeyVersion, ib2ID.PublicKey, ib2ID.DocumentDigest = "did:web:b.local:ib#key-2", 2, env.pubIB2, newIBDig
	ib2Snap.Identities["did:web:b.local:ib"] = ib2ID
	ib2Snap.Credentials = maps.Clone(v2Snap.Credentials)
	ib2Snap.Credentials[sdB1IB2.Claims.ID] = ib2CredRec
	ib2Snap.Grants = maps.Clone(v2Snap.Grants)
	g1IB2 := ib2Snap.Grants["urn:grant:dynamic:g1"]
	g1IB2.GranteeCredential = sdB1IB2.Claims.ID
	g1IB2.Digest = g1NewDig
	ib2Snap.Grants["urn:grant:dynamic:g1"] = g1IB2

	env.pkg.Grants[1] = g1NewJWS
	pkgStaleIBCert, chalStaleIBCert := env.signPackage(t, "chal-ib2-stale", sdB1IB2.PresentationPrefix)
	_, err = VerifyAccessEvidencePackageWithCache(env.ctx, &pkgStaleIBCert, &ib2Snap, env.dids, chalStaleIBCert, cache)
	assert.True(t, HasCode(err, ErrCodeIssuerScopeInvalid), "got %v", err)

	scopesV3 := []IssuerScope{{ID: "did:web:b.local:ib", AppKeyVersion: 2, CredentialTypes: []string{CredentialTypeEnterpriseIdentity}, ClaimNames: []string{"domain", "role"}}}
	certB3JWS, certB3Dig, err := SignDomainAuthorityCredential(env.privT, "did:web:t.local#key-1", &DomainAuthorityCredential{
		Type: []string{CredentialTypeVC, CredentialTypeDomainAuthority}, ID: "urn:grad:cert:B-v3", DeploymentID: env.depID,
		Issuer: "did:web:t.local", Iss: "did:web:t.local", Sub: "did:web:b.local", IssuerKeyVersion: 1,
		ValidFrom: env.vf, ValidUntil: env.vu, NBF: env.nbf, EXP: env.exp,
		CredentialStatus:  CredentialStatus{ID: "urn:grad:cert:B-v3", Type: StatusTypeDomainCertification},
		CredentialSubject: DomainAuthoritySubject{ID: "did:web:b.local", DomainID: "B", IdentityIssuers: scopesV3},
	})
	require.NoError(t, err)
	ib2Snap.Domains = maps.Clone(ib2Snap.Domains)
	db3 := ib2Snap.Domains["B"]
	db3.Certification = "urn:grad:cert:B-v3"
	ib2Snap.Domains["B"] = db3
	ib2Snap.Certifications = maps.Clone(ib2Snap.Certifications)
	ib2Snap.Certifications["urn:grad:cert:B-v3"] = registry.Certification{
		Bound: registry.Bound{DeploymentID: env.depID}, ID: "urn:grad:cert:B-v3", Domain: "B", RootKeyVersion: 1, Digest: certB3Dig,
		Scopes: scopesV3, Interval: registry.Interval{NBF: env.nbf, EXP: env.exp}, Version: registry.Version{Status: registry.Active, Revision: 1},
	}
	env.pkg.TrustPaths[1].DomainCertification = certB3JWS
	pkgValidIB2, chalValidIB2 := env.signPackage(t, "chal-ib2-ok", sdB1IB2.PresentationPrefix)
	_, err = VerifyAccessEvidencePackageWithCache(env.ctx, &pkgValidIB2, &ib2Snap, env.dids, chalValidIB2, cache)
	require.NoError(t, err)
}

func TestDepartmentScopeShrink(t *testing.T) {
	env := newDynamicProtocolFixture(t, true)
	cache := NewSignatureCache()

	// 1. Before scope shrink: full presentation with domain, role, department passes.
	pkgFull1, chalFull1 := env.signPackage(t, "chal-shrink-before", env.sdB1Dept.PresentationPrefix)
	resBefore, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkgFull1, env.snap, env.dids, chalFull1, cache)
	require.NoError(t, err)
	assert.Equal(t, "procurement", resBefore.LeafCredential.Disclosed["department"])

	// 2. T same-key renews B certification removing "department" from ClaimNames (VC_B1 & G1 unchanged).
	shrunkScopes := []IssuerScope{{ID: "did:web:b.local:ib", AppKeyVersion: 1, CredentialTypes: []string{CredentialTypeEnterpriseIdentity}, ClaimNames: []string{"domain", "role"}}}
	certShrunkJWS, certShrunkDig, err := SignDomainAuthorityCredential(env.privT, "did:web:t.local#key-1", &DomainAuthorityCredential{
		Type: []string{CredentialTypeVC, CredentialTypeDomainAuthority}, ID: "urn:grad:cert:B-shrunk", DeploymentID: env.depID,
		Issuer: "did:web:t.local", Iss: "did:web:t.local", Sub: "did:web:b.local", IssuerKeyVersion: 1,
		ValidFrom: env.vf, ValidUntil: env.vu, NBF: env.nbf, EXP: env.exp,
		CredentialStatus:  CredentialStatus{ID: "urn:grad:cert:B-shrunk", Type: StatusTypeDomainCertification},
		CredentialSubject: DomainAuthoritySubject{ID: "did:web:b.local", DomainID: "B", IdentityIssuers: shrunkScopes},
	})
	require.NoError(t, err)
	db := env.snap.Domains["B"]
	db.Certification = "urn:grad:cert:B-shrunk"
	env.snap.Domains["B"] = db
	env.snap.Certifications["urn:grad:cert:B-shrunk"] = registry.Certification{
		Bound: registry.Bound{DeploymentID: env.depID}, ID: "urn:grad:cert:B-shrunk", Domain: "B", RootKeyVersion: 1, Digest: certShrunkDig,
		Scopes: shrunkScopes, Interval: registry.Interval{NBF: env.nbf, EXP: env.exp}, Version: registry.Version{Status: registry.Active, Revision: 1},
	}
	env.pkg.TrustPaths[1].DomainCertification = certShrunkJWS

	// 3. With department hidden (only domain & role disclosed), re-signed KB-JWT passes and Disclosed lacks "department".
	hiddenPrefix := env.sdB1Dept.IssuerSignedJWT + "~" + env.sdB1Dept.DisclosureByClaim["domain"] + "~" + env.sdB1Dept.DisclosureByClaim["role"] + "~"
	pkgHidden, chalHidden := env.signPackage(t, "chal-shrink-hidden", hiddenPrefix)
	resHidden, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkgHidden, env.snap, env.dids, chalHidden, cache)
	require.NoError(t, err)
	_, exists := resHidden.LeafCredential.Disclosed["department"]
	assert.False(t, exists)

	// 4. Disclosing removed "department" claim -> ISSUER_SCOPE_INVALID.
	pkgDisclosed, chalDisclosed := env.signPackage(t, "chal-shrink-disclosed", env.sdB1Dept.PresentationPrefix)
	_, err = VerifyAccessEvidencePackageWithCache(env.ctx, &pkgDisclosed, env.snap, env.dids, chalDisclosed, cache)
	assert.True(t, HasCode(err, ErrCodeIssuerScopeInvalid), "got %v", err)

	// 5. Omitting mandatory "role" claim -> INVALID_DISCLOSURE.
	noRolePrefix := env.sdB1Dept.IssuerSignedJWT + "~" + env.sdB1Dept.DisclosureByClaim["domain"] + "~"
	pkgNoRole, chalNoRole := env.signPackage(t, "chal-shrink-norole", noRolePrefix)
	_, err = VerifyAccessEvidencePackageWithCache(env.ctx, &pkgNoRole, env.snap, env.dids, chalNoRole, cache)
	assert.True(t, HasCode(err, ErrCodeInvalidDisclosure), "got %v", err)
}

func TestRootTOfflineAndUnsyncedMaterial(t *testing.T) {
	env := newDynamicProtocolFixture(t, false)
	cache := NewSignatureCache()
	// Stop T's online HTTP DID server completely before verification.
	env.tServer.Close()
	before := env.tCalls.Load()

	pkg, chal := env.signPackage(t, "chal-offline-root", env.sdB1Dept.PresentationPrefix)
	_, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkg, env.snap, env.dids, chal, cache)
	require.NoError(t, err)
	assert.Equal(t, before, env.tCalls.Load())
}
