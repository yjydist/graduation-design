package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"
)

type m3ProtocolEnv struct {
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

func strPtrM3(s string) *string { return &s }

func newM3ProtocolEnv(t *testing.T, withDepartmentClaim bool) *m3ProtocolEnv {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	nbf := now.Add(-time.Minute).Unix()
	exp := now.Add(time.Hour).Unix()
	vf := time.Unix(nbf, 0).UTC().Format(time.RFC3339)
	vu := time.Unix(exp, 0).UTC().Format(time.RFC3339)

	ca, err := GenerateTestCA(now)
	if err != nil {
		t.Fatal(err)
	}
	caPool, err := ParseTestCAPublic(ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	certs := make(map[string]*HostTLSCert, len(ControlledTestDomains))
	for _, host := range ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		if err != nil {
			t.Fatal(err)
		}
		certs[host] = hc
	}

	privT, pubT, _ := GenerateP256KeyPair()
	privIA, pubIA, _ := GenerateP256KeyPair()
	privIB, pubIB, _ := GenerateP256KeyPair()
	privIB2, pubIB2, _ := GenerateP256KeyPair()
	privIC, pubIC, _ := GenerateP256KeyPair()
	privU, pubU, _ := GenerateP256KeyPair()
	privB1, pubB1, _ := GenerateP256KeyPair()
	privB1Rot, pubB1Rot, _ := GenerateP256KeyPair()
	privC, pubC, _ := GenerateP256KeyPair()

	didT := "did:web:t.local"
	didIA := "did:web:a.local:ia"
	didU := "did:web:a.local:u"
	didIB := "did:web:b.local:ib"
	didB1 := "did:web:b.local:b1"
	didIC := "did:web:c.local:ic"
	didC := "did:web:c.local:supplier"

	docs := map[string][]byte{}
	makeDoc := func(did, keyID, pub string, purposes ...string) string {
		d, err := NewDIDDocument(did, keyID, pub, purposes...)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := MarshalJCS(d)
		dig, _ := d.Digest()
		docs[did] = raw
		return dig
	}
	digT := makeDoc(didT, didT+"#key-1", pubT, KeyPurposeAssertionMethod)
	digIA := makeDoc(didIA, didIA+"#key-1", pubIA, KeyPurposeAssertionMethod)
	digU := makeDoc(didU, didU+"#key-1", pubU, KeyPurposeAssertionMethod, KeyPurposeAuthentication)
	digIB := makeDoc(didIB, didIB+"#key-1", pubIB, KeyPurposeAssertionMethod)
	digB1 := makeDoc(didB1, didB1+"#key-1", pubB1, KeyPurposeAssertionMethod, KeyPurposeAuthentication)
	digIC := makeDoc(didIC, didIC+"#key-1", pubIC, KeyPurposeAssertionMethod)
	digC := makeDoc(didC, didC+"#key-1", pubC, KeyPurposeAssertionMethod, KeyPurposeAuthentication)

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
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dids.RegisterPreseed(RootPreseed{
		DID: didT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKeyHex: pubT,
		DIDDocumentDigest: digT, RawDocument: docs[didT],
	}); err != nil {
		t.Fatal(err)
	}

	depID := strings.Repeat("7", 64)
	bClaims := []string{"domain", "role"}
	if withDepartmentClaim {
		bClaims = []string{"department", "domain", "role"}
	}

	issueCert := func(domID, domDID, issuerDID, certID string, kv uint64, claims []string) (string, string, api.Domain, api.Certification) {
		jws, dig, err := SignDomainAuthorityCredential(privT, didT+"#key-1", &DomainAuthorityCredential{
			Type: []string{CredentialTypeVC, CredentialTypeDomainAuthority}, ID: certID, DeploymentID: depID,
			Issuer: didT, Iss: didT, Sub: domDID, IssuerKeyVersion: 1,
			ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
			CredentialStatus: CredentialStatus{ID: certID, Type: StatusTypeDomainCertification},
			CredentialSubject: DomainAuthoritySubject{
				ID: domDID, DomainID: domID,
				IdentityIssuers: []IssuerScope{{ID: issuerDID, AppKeyVersion: kv, CredentialTypes: []string{CredentialTypeEnterpriseIdentity}, ClaimNames: claims}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		dom := api.Domain{Bound: api.Bound{DeploymentID: depID}, ID: domID, DID: domDID, Issuers: []string{issuerDID}, Certification: certID, Version: api.Version{Status: api.Active, Revision: 1}}
		cert := api.Certification{
			Bound: api.Bound{DeploymentID: depID}, ID: certID, Domain: domID, RootKeyVersion: 1, Digest: dig,
			Scopes: []api.Scope{{ID: issuerDID, KeyVersion: kv, Types: []string{CredentialTypeEnterpriseIdentity}, Claims: claims}},
			Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
		}
		return jws, dig, dom, cert
	}

	certAJWS, _, domA, certA := issueCert("A", "did:web:a.local", didIA, "urn:grad:cert:A-v1", 1, []string{"domain", "role"})
	certBJWS, certBDig, domB, certB := issueCert("B", "did:web:b.local", didIB, "urn:grad:cert:B-v1", 1, bClaims)
	certCJWS, _, domC, certC := issueCert("C", "did:web:c.local", didIC, "urn:grad:cert:C-v1", 1, []string{"domain", "role"})

	issueVC := func(priv *ecdsa.PrivateKey, issDID, subDID, dom, role, cid string, kv uint64, extra map[string]string, claims []string) (*SignedSDJWTCredential, api.Credential) {
		pub := pubB1
		if subDID == didU {
			pub = pubU
		} else if subDID == didC {
			pub = pubC
		}
		jwk, err := AppPublicKeyToJWK(pub)
		if err != nil {
			t.Fatal(err)
		}
		sd, err := IssueEnterpriseIdentityCredential(priv, issDID+"#key-1", EnterpriseIdentityCredential{
			Type: []string{CredentialTypeVC, CredentialTypeEnterpriseIdentity}, ID: cid, DeploymentID: depID,
			Issuer: issDID, Iss: issDID, Sub: subDID, IssuerKeyVersion: kv, AppKeyVersion: 1,
			ValidFrom: vf, ValidUntil: vu, NBF: nbf, EXP: exp,
			CredentialStatus:  CredentialStatus{ID: cid, Type: StatusTypeCredential},
			CredentialSubject: SDJWTCredentialSubject{ID: subDID},
			Cnf:               ConfirmationKey{JWK: jwk},
		}, dom, role, extra)
		if err != nil {
			t.Fatal(err)
		}
		rec := api.Credential{
			Bound: api.Bound{DeploymentID: depID}, ID: cid, Issuer: issDID, Subject: subDID,
			IssuerKeyVersion: kv, SubjectKeyVersion: 1, Type: CredentialTypeEnterpriseIdentity,
			ClaimNames: claims, Digest: sd.AnchorDigest, Interval: api.Interval{NBF: nbf, EXP: exp},
			Version: api.Version{Status: api.Active, Revision: 1},
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
		Resources: []string{"urn:grad:resource:C:quotes"}, Actions: []string{"quote.read"}, Description: "m3",
	}
	specDig, _ := spec.Digest()
	taskID := "urn:grad:task:m3-1"
	taskRec := api.Task{
		Bound: api.Bound{DeploymentID: depID}, ID: taskID, Creator: didU, CreatorCredential: credU.ID,
		CreatorKeyVersion: 1, Domain: "A", Mode: ModeResourcePreauthorized, Resource: "urn:grad:resource:C:quotes",
		Digest: specDig, Interval: api.Interval{NBF: nbf, EXP: exp}, Version: api.Version{Status: api.Active, Revision: 1},
	}

	g0JWS, g0Dig, err := SignGrant(privC, didC+"#key-1", &GrantClaims{
		ID: "urn:grant:m3:g0", SchemaVersion: SchemaVersion, DeploymentID: depID,
		RootID: "urn:grant:m3:g0", TaskID: taskID, AuthorizationMode: ModeResourcePreauthorized,
		PrincipalDomain: "A", ResourceID: "urn:grad:resource:C:quotes", Issuer: didC, Grantee: didU,
		IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: credC.ID, GranteeCredentialID: credU.ID,
		MaxAmountMinor: 100000, Resources: []string{"urn:grad:resource:C:quotes"}, Actions: []string{"quote.read"},
		Suppliers: []string{"urn:grad:supplier:C"}, Aud: "https://c.local", Currency: "CNY", RemainingDepth: 1,
		NBF: nbf + 2, EXP: exp - 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	g1JWS, g1Dig, err := SignGrant(privU, didU+"#key-1", &GrantClaims{
		ID: "urn:grant:m3:g1", SchemaVersion: SchemaVersion, DeploymentID: depID,
		ParentID: strPtrM3("urn:grant:m3:g0"), ParentDigest: strPtrM3(g0Dig),
		RootID: "urn:grant:m3:g0", TaskID: taskID, AuthorizationMode: ModeResourcePreauthorized,
		PrincipalDomain: "A", ResourceID: "urn:grad:resource:C:quotes", Issuer: didU, Grantee: didB1,
		IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: credU.ID, GranteeCredentialID: credB1.ID,
		MaxAmountMinor: 100000, Resources: []string{"urn:grad:resource:C:quotes"}, Actions: []string{"quote.read"},
		Suppliers: []string{"urn:grad:supplier:C"}, Aud: "https://c.local", Currency: "CNY", RemainingDepth: 0,
		NBF: nbf + 2, EXP: exp - 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	g0Rec := api.Grant{
		Bound: api.Bound{DeploymentID: depID}, ID: "urn:grant:m3:g0", Schema: SchemaVersion,
		Root: "urn:grant:m3:g0", Task: taskID, Mode: ModeResourcePreauthorized, Domain: "A", Resource: "urn:grad:resource:C:quotes",
		Issuer: didC, Grantee: didU, IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredential: credC.ID, GranteeCredential: credU.ID,
		Depth: 1, Digest: g0Dig, Interval: api.Interval{NBF: nbf + 2, EXP: exp - 2}, Version: api.Version{Status: api.Active, Revision: 1},
	}
	g1Rec := api.Grant{
		Bound: api.Bound{DeploymentID: depID}, ID: "urn:grant:m3:g1", Schema: SchemaVersion,
		Parent: "urn:grant:m3:g0", ParentDigest: g0Dig, Root: "urn:grant:m3:g0", Task: taskID, Mode: ModeResourcePreauthorized,
		Domain: "A", Resource: "urn:grad:resource:C:quotes", Issuer: didU, Grantee: didB1, IssuerKeyVersion: 1, GranteeKeyVersion: 1,
		IssuerCredential: credU.ID, GranteeCredential: credB1.ID, Depth: 0, Digest: g1Dig,
		Interval: api.Interval{NBF: nbf + 2, EXP: exp - 2}, Version: api.Version{Status: api.Active, Revision: 1},
	}

	snap := &SnapshotView{
		Height: 10, Now: now, ClockError: api.ClockError, DeploymentID: depID,
		Root: api.RootRecord{DID: didT, KeyID: didT + "#key-1", KeyVersion: 1, PublicKey: pubT, DocumentDigest: digT},
		Domains: map[string]api.Domain{"A": domA, "B": domB, "C": domC},
		Certifications: map[string]api.Certification{certA.ID: certA, certB.ID: certB, certC.ID: certC},
		Identities: map[string]api.Identity{
			didIA: {Bound: api.Bound{DeploymentID: depID}, ID: didIA, Domain: "A", Kind: "ISSUER", DocumentDigest: digIA, KeyID: didIA + "#key-1", KeyVersion: 1, PublicKey: pubIA, Version: api.Version{Status: api.Active, Revision: 1}},
			didIB: {Bound: api.Bound{DeploymentID: depID}, ID: didIB, Domain: "B", Kind: "ISSUER", DocumentDigest: digIB, KeyID: didIB + "#key-1", KeyVersion: 1, PublicKey: pubIB, Version: api.Version{Status: api.Active, Revision: 1}},
			didIC: {Bound: api.Bound{DeploymentID: depID}, ID: didIC, Domain: "C", Kind: "ISSUER", DocumentDigest: digIC, KeyID: didIC + "#key-1", KeyVersion: 1, PublicKey: pubIC, Version: api.Version{Status: api.Active, Revision: 1}},
			didU:  {Bound: api.Bound{DeploymentID: depID}, ID: didU, Domain: "A", Kind: "USER", DocumentDigest: digU, KeyID: didU + "#key-1", KeyVersion: 1, PublicKey: pubU, Version: api.Version{Status: api.Active, Revision: 1}},
			didB1: {Bound: api.Bound{DeploymentID: depID}, ID: didB1, Domain: "B", Kind: "USER", DocumentDigest: digB1, KeyID: didB1 + "#key-1", KeyVersion: 1, PublicKey: pubB1, Version: api.Version{Status: api.Active, Revision: 1}},
			didC:  {Bound: api.Bound{DeploymentID: depID}, ID: didC, Domain: "C", Kind: "SERVICE", DocumentDigest: digC, KeyID: didC + "#key-1", KeyVersion: 1, PublicKey: pubC, Version: api.Version{Status: api.Active, Revision: 1}},
		},
		Credentials: map[string]api.Credential{credU.ID: credU, credB1.ID: credB1, credC.ID: credC},
		Tasks:       map[string]api.Task{taskRec.ID: taskRec},
		Grants:      map[string]api.Grant{g0Rec.ID: g0Rec, g1Rec.ID: g1Rec},
	}

	req := AccessRequest{
		SchemaVersion: SchemaVersion, DeploymentID: depID, Actor: didB1, PrincipalDomain: "A",
		AuthorizationMode: ModeResourcePreauthorized, TaskID: taskID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:quotes", Action: "quote.read", SupplierID: "urn:grad:supplier:C",
		ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 0, IdempotencyKey: "m3-ik-1",
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

	return &m3ProtocolEnv{
		ctx: ctx, now: now, nbf: nbf, exp: exp, vf: vf, vu: vu, depID: depID, ca: ca, dids: dids,
		tCalls: &tCalls, tServer: tSrv, docs: docs,
		privT: privT, pubT: pubT, privIA: privIA, pubIA: pubIA, privIB: privIB, pubIB: pubIB, privIB2: privIB2, pubIB2: pubIB2,
		privU: privU, pubU: pubU, privB1: privB1, pubB1: pubB1, privB1Rot: privB1Rot, pubB1Rot: pubB1Rot, privIC: privIC, pubIC: pubIC, privC: privC, pubC: pubC,
		snap: snap, pkg: pkg, sdB1Dept: sdB1, certBJWS: certBJWS, certBDig: certBDig, grantID: g1Rec.ID,
	}
}

func (e *m3ProtocolEnv) signPackage(t *testing.T, chalID, presPrefix string) (AccessEvidencePackage, ChallengeContext) {
	t.Helper()
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	chal := ChallengeContext{
		ChallengeID: chalID, Nonce: nonce, Audience: "https://c.local",
		IssuedAt: e.now.Unix(), ExpiresAt: e.now.Unix() + 30,
	}
	p := e.pkg
	if _, _, err := AssembleAccessEvidencePackage(&p, presPrefix, "did:web:b.local:b1#key-1", e.privB1, chal, e.now.Unix(), false); err != nil {
		t.Fatalf("AssembleAccessEvidencePackage: %v", err)
	}
	return p, chal
}

func TestM3SignatureCacheB1AndKeyVersionStale(t *testing.T) {
	env := newM3ProtocolEnv(t, false)
	cache := NewSignatureCache()

	// 1. Cold request populates B1 cache (3 TrustPaths + 2 Grants + 3 SD-JWTs = 8 JWS signatures)
	pkg1, chal1 := env.signPackage(t, "chal-cold", env.sdB1Dept.PresentationPrefix)
	if _, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkg1, env.snap, env.dids, chal1, cache); err != nil {
		t.Fatalf("cold B1 verify failed: %v", err)
	}
	if cache.Hits() != 0 || cache.Misses() != 8 {
		t.Fatalf("expected 0 hits and 8 misses on cold run, got hits=%d misses=%d", cache.Hits(), cache.Misses())
	}

	// 2. Warm request with new challenge/KB-JWT skips all 8 static JWS verifications
	cache.ResetStats()
	pkg2, chal2 := env.signPackage(t, "chal-warm", env.sdB1Dept.PresentationPrefix)
	if _, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkg2, env.snap, env.dids, chal2, cache); err != nil {
		t.Fatalf("warm B1 verify failed: %v", err)
	}
	if cache.Hits() != 8 || cache.Misses() != 0 {
		t.Fatalf("expected 8 hits and 0 misses on warm run, got hits=%d misses=%d", cache.Hits(), cache.Misses())
	}

	// 3. S22: B1 rotates key (KeyVersion 1->2); warm cache hit must NOT bypass dynamic state -> 403 KEY_VERSION_STALE.
	cache.ResetStats()
	rotSnap := *env.snap
	rotIDs := make(map[string]api.Identity, len(env.snap.Identities))
	for k, v := range env.snap.Identities {
		rotIDs[k] = v
	}
	b1Rot := rotIDs["did:web:b.local:b1"]
	b1Rot.KeyVersion = 2
	b1Rot.KeyID = "did:web:b.local:b1#key-2"
	b1Rot.PublicKey = env.pubB1Rot
	rotIDs["did:web:b.local:b1"] = b1Rot
	rotSnap.Identities = rotIDs

	pkg3, chal3 := env.signPackage(t, "chal-s22", env.sdB1Dept.PresentationPrefix)
	if _, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkg3, &rotSnap, env.dids, chal3, cache); !HasCode(err, ErrCodeKeyVersionStale) {
		t.Fatalf("expected KEY_VERSION_STALE when B1 key rotated with warm cache, got %v", err)
	}
	if cache.Hits() == 0 {
		t.Fatalf("expected warm static cache lookup hit before KeyVersion rejection in S22")
	}

	// 4. S89: Domain B suspended -> DOMAIN_INACTIVE despite cached cert and ACTIVE VC/G1.
	suspSnap := *env.snap
	suspDoms := make(map[string]api.Domain, len(env.snap.Domains))
	for k, v := range env.snap.Domains {
		suspDoms[k] = v
	}
	domB := suspDoms["B"]
	domB.Status = api.Suspended
	suspDoms["B"] = domB
	suspSnap.Domains = suspDoms
	pkg4, chal4 := env.signPackage(t, "chal-s89", env.sdB1Dept.PresentationPrefix)
	if _, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkg4, &suspSnap, env.dids, chal4, cache); !HasCode(err, ErrCodeDomainInactive) {
		t.Fatalf("expected DOMAIN_INACTIVE when Domain B suspended, got %v", err)
	}

	// 5. S82: Atomic domain certification replacement (v1 -> v2, preserving IB key/scope). Old cert rejected; new cert allowed.
	certB2JWS, certB2Dig, err := SignDomainAuthorityCredential(env.privT, "did:web:t.local#key-1", &DomainAuthorityCredential{
		Type: []string{CredentialTypeVC, CredentialTypeDomainAuthority}, ID: "urn:grad:cert:B-v2", DeploymentID: env.depID,
		Issuer: "did:web:t.local", Iss: "did:web:t.local", Sub: "did:web:b.local", IssuerKeyVersion: 1,
		ValidFrom: env.vf, ValidUntil: env.vu, NBF: env.nbf, EXP: env.exp,
		CredentialStatus: CredentialStatus{ID: "urn:grad:cert:B-v2", Type: StatusTypeDomainCertification},
		CredentialSubject: DomainAuthoritySubject{
			ID: "did:web:b.local", DomainID: "B",
			IdentityIssuers: []IssuerScope{{ID: "did:web:b.local:ib", AppKeyVersion: 1, CredentialTypes: []string{CredentialTypeEnterpriseIdentity}, ClaimNames: []string{"domain", "role"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	v2Snap := *env.snap
	v2Doms := make(map[string]api.Domain, len(env.snap.Domains))
	for k, v := range env.snap.Domains {
		v2Doms[k] = v
	}
	db2 := v2Doms["B"]
	db2.Certification = "urn:grad:cert:B-v2"
	db2.Revision = 2
	v2Doms["B"] = db2
	v2Certs := make(map[string]api.Certification, len(env.snap.Certifications))
	for k, v := range env.snap.Certifications {
		v2Certs[k] = v
	}
	v2Certs["urn:grad:cert:B-v2"] = api.Certification{
		Bound: api.Bound{DeploymentID: env.depID}, ID: "urn:grad:cert:B-v2", Domain: "B", RootKeyVersion: 1, Digest: certB2Dig,
		Scopes: []api.Scope{{ID: "did:web:b.local:ib", KeyVersion: 1, Types: []string{CredentialTypeEnterpriseIdentity}, Claims: []string{"domain", "role"}}},
		Interval: api.Interval{NBF: env.nbf, EXP: env.exp}, Version: api.Version{Status: api.Active, Revision: 1},
	}
	v2Snap.Domains = v2Doms
	v2Snap.Certifications = v2Certs

	// Old cert-v1 now rejected as DOMAIN_CERTIFICATION_INVALID
	pkgOldCert, chalOldCert := env.signPackage(t, "chal-oldcert", env.sdB1Dept.PresentationPrefix)
	if _, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkgOldCert, &v2Snap, env.dids, chalOldCert, cache); !HasCode(err, ErrCodeDomainCertificationInvalid) {
		t.Fatalf("expected DOMAIN_CERTIFICATION_INVALID for superseded cert-B-v1, got %v", err)
	}
	// New cert-v2 with re-signed KB passes with original B1 VC and G1
	env.pkg.TrustPaths[1].DomainCertification = certB2JWS
	pkgNewCert, chalNewCert := env.signPackage(t, "chal-newcert", env.sdB1Dept.PresentationPrefix)
	if _, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkgNewCert, &v2Snap, env.dids, chalNewCert, cache); err != nil {
		t.Fatalf("expected cert-B-v2 with existing B1 VC & G1 to pass, got %v", err)
	}

	// 6. S81 / F15: IB updates key (v1 -> v2) and re-issues VC; presenting old cert fails until T renews certification for IB v2.
	newIBDoc, _ := NewDIDDocument("did:web:b.local:ib", "did:web:b.local:ib#key-2", env.pubIB2, KeyPurposeAssertionMethod)
	newIBDig, _ := newIBDoc.Digest()
	env.docs["did:web:b.local:ib"], _ = MarshalJCS(newIBDoc)
	dids2 := env.dids
	// Build a shrunk/updated IB doc key on existing bSrv dynamically via env.docs mutation (live map!).
	sdB1IB2, err := IssueEnterpriseIdentityCredential(env.privIB2, "did:web:b.local:ib#key-2", EnterpriseIdentityCredential{
		Type: []string{CredentialTypeVC, CredentialTypeEnterpriseIdentity}, ID: "urn:cred:b1-ib2", DeploymentID: env.depID,
		Issuer: "did:web:b.local:ib", Iss: "did:web:b.local:ib", Sub: "did:web:b.local:b1", IssuerKeyVersion: 2, AppKeyVersion: 1,
		ValidFrom: env.vf, ValidUntil: env.vu, NBF: env.nbf, EXP: env.exp,
		CredentialStatus:  CredentialStatus{ID: "urn:cred:b1-ib2", Type: StatusTypeCredential},
		CredentialSubject: SDJWTCredentialSubject{ID: "did:web:b.local:b1"},
		Cnf:               env.sdB1Dept.Claims.Cnf,
	}, "B", "AGENT", nil)
	if err != nil {
		t.Fatal(err)
	}
	ib2CredRec := api.Credential{
		Bound: api.Bound{DeploymentID: env.depID}, ID: sdB1IB2.Claims.ID, Issuer: "did:web:b.local:ib", Subject: "did:web:b.local:b1",
		IssuerKeyVersion: 2, SubjectKeyVersion: 1, Type: CredentialTypeEnterpriseIdentity, ClaimNames: []string{"domain", "role"},
		Digest: sdB1IB2.AnchorDigest, Interval: api.Interval{NBF: env.nbf, EXP: env.exp}, Version: api.Version{Status: api.Active, Revision: 1},
	}
	// Replace G1 GranteeCredentialID -> sdB1IB2 and re-sign G1 with privU
	g1NewJWS, g1NewDig, _ := SignGrant(env.privU, "did:web:a.local:u#key-1", &GrantClaims{
		ID: "urn:grant:m3:g1", SchemaVersion: SchemaVersion, DeploymentID: env.depID,
		ParentID: strPtrM3("urn:grant:m3:g0"), ParentDigest: strPtrM3(env.snap.Grants["urn:grant:m3:g0"].Digest),
		RootID: "urn:grant:m3:g0", TaskID: env.pkg.Request.TaskID, AuthorizationMode: ModeResourcePreauthorized,
		PrincipalDomain: "A", ResourceID: "urn:grad:resource:C:quotes", Issuer: "did:web:a.local:u", Grantee: "did:web:b.local:b1",
		IssuerKeyVersion: 1, GranteeKeyVersion: 1, IssuerCredentialID: "urn:cred:u", GranteeCredentialID: sdB1IB2.Claims.ID,
		MaxAmountMinor: 100000, Resources: []string{"urn:grad:resource:C:quotes"}, Actions: []string{"quote.read"},
		Suppliers: []string{"urn:grad:supplier:C"}, Aud: "https://c.local", Currency: "CNY", RemainingDepth: 0,
		NBF: env.nbf + 2, EXP: env.exp - 2,
	})
	ib2Snap := v2Snap
	ib2IDs := make(map[string]api.Identity, len(v2Snap.Identities))
	for k, v := range v2Snap.Identities {
		ib2IDs[k] = v
	}
	ib2ID := ib2IDs["did:web:b.local:ib"]
	ib2ID.KeyID, ib2ID.KeyVersion, ib2ID.PublicKey, ib2ID.DocumentDigest = "did:web:b.local:ib#key-2", 2, env.pubIB2, newIBDig
	ib2IDs["did:web:b.local:ib"] = ib2ID
	ib2Creds := make(map[string]api.Credential, len(v2Snap.Credentials))
	for k, v := range v2Snap.Credentials {
		ib2Creds[k] = v
	}
	ib2Creds[sdB1IB2.Claims.ID] = ib2CredRec
	ib2Grants := make(map[string]api.Grant, len(v2Snap.Grants))
	for k, v := range v2Snap.Grants {
		ib2Grants[k] = v
	}
	g1IB2 := ib2Grants["urn:grant:m3:g1"]
	g1IB2.GranteeCredential = sdB1IB2.Claims.ID
	g1IB2.Digest = g1NewDig
	ib2Grants["urn:grant:m3:g1"] = g1IB2
	ib2Snap.Identities, ib2Snap.Credentials, ib2Snap.Grants = ib2IDs, ib2Creds, ib2Grants

	env.pkg.Grants[1] = g1NewJWS
	// Still carrying T cert v2 pointing to IB v1 -> must fail ISSUER_SCOPE_INVALID
	pkgStaleIBCert, chalStaleIBCert := env.signPackage(t, "chal-s81-stale", sdB1IB2.PresentationPrefix)
	if _, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkgStaleIBCert, &ib2Snap, dids2, chalStaleIBCert, cache); !HasCode(err, ErrCodeIssuerScopeInvalid) {
		t.Fatalf("expected ISSUER_SCOPE_INVALID with new IB v2 VC under IB v1 certification, got %v", err)
	}
	// After T renews cert v3 with IB AppKeyVersion: 2 -> passes (F15, S81)
	certB3JWS, certB3Dig, err := SignDomainAuthorityCredential(env.privT, "did:web:t.local#key-1", &DomainAuthorityCredential{
		Type: []string{CredentialTypeVC, CredentialTypeDomainAuthority}, ID: "urn:grad:cert:B-v3", DeploymentID: env.depID,
		Issuer: "did:web:t.local", Iss: "did:web:t.local", Sub: "did:web:b.local", IssuerKeyVersion: 1,
		ValidFrom: env.vf, ValidUntil: env.vu, NBF: env.nbf, EXP: env.exp,
		CredentialStatus: CredentialStatus{ID: "urn:grad:cert:B-v3", Type: StatusTypeDomainCertification},
		CredentialSubject: DomainAuthoritySubject{
			ID: "did:web:b.local", DomainID: "B",
			IdentityIssuers: []IssuerScope{{ID: "did:web:b.local:ib", AppKeyVersion: 2, CredentialTypes: []string{CredentialTypeEnterpriseIdentity}, ClaimNames: []string{"domain", "role"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ib2Doms := make(map[string]api.Domain, len(ib2Snap.Domains))
	for k, v := range ib2Snap.Domains {
		ib2Doms[k] = v
	}
	db3 := ib2Doms["B"]
	db3.Certification = "urn:grad:cert:B-v3"
	ib2Doms["B"] = db3
	ib2Certs := make(map[string]api.Certification, len(ib2Snap.Certifications))
	for k, v := range ib2Snap.Certifications {
		ib2Certs[k] = v
	}
	ib2Certs["urn:grad:cert:B-v3"] = api.Certification{
		Bound: api.Bound{DeploymentID: env.depID}, ID: "urn:grad:cert:B-v3", Domain: "B", RootKeyVersion: 1, Digest: certB3Dig,
		Scopes: []api.Scope{{ID: "did:web:b.local:ib", KeyVersion: 2, Types: []string{CredentialTypeEnterpriseIdentity}, Claims: []string{"domain", "role"}}},
		Interval: api.Interval{NBF: env.nbf, EXP: env.exp}, Version: api.Version{Status: api.Active, Revision: 1},
	}
	ib2Snap.Domains, ib2Snap.Certifications = ib2Doms, ib2Certs
	env.pkg.TrustPaths[1].DomainCertification = certB3JWS
	pkgValidIB2, chalValidIB2 := env.signPackage(t, "chal-s81-ok", sdB1IB2.PresentationPrefix)
	if _, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkgValidIB2, &ib2Snap, dids2, chalValidIB2, cache); err != nil {
		t.Fatalf("expected F15/S81 pass after T renews cert for IB v2, got %v", err)
	}
}

func TestM3DepartmentScopeShrinkS93(t *testing.T) {
	env := newM3ProtocolEnv(t, true)
	cache := NewSignatureCache()

	// 1. Before scope shrink: full presentation with domain, role, department passes.
	pkgFull1, chalFull1 := env.signPackage(t, "chal-s93-before", env.sdB1Dept.PresentationPrefix)
	resBefore, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkgFull1, env.snap, env.dids, chalFull1, cache)
	if err != nil {
		t.Fatalf("pre-shrink S93 verify failed: %v", err)
	}
	if resBefore.LeafCredential.Disclosed["department"] != "procurement" {
		t.Fatalf("expected department=procurement before shrink, got %+v", resBefore.LeafCredential.Disclosed)
	}

	// 2. T same-key renews B certification removing "department" from ClaimNames (VC_B1 & G1 unchanged!).
	certShrunkJWS, certShrunkDig, err := SignDomainAuthorityCredential(env.privT, "did:web:t.local#key-1", &DomainAuthorityCredential{
		Type: []string{CredentialTypeVC, CredentialTypeDomainAuthority}, ID: "urn:grad:cert:B-shrunk", DeploymentID: env.depID,
		Issuer: "did:web:t.local", Iss: "did:web:t.local", Sub: "did:web:b.local", IssuerKeyVersion: 1,
		ValidFrom: env.vf, ValidUntil: env.vu, NBF: env.nbf, EXP: env.exp,
		CredentialStatus: CredentialStatus{ID: "urn:grad:cert:B-shrunk", Type: StatusTypeDomainCertification},
		CredentialSubject: DomainAuthoritySubject{
			ID: "did:web:b.local", DomainID: "B",
			IdentityIssuers: []IssuerScope{{ID: "did:web:b.local:ib", AppKeyVersion: 1, CredentialTypes: []string{CredentialTypeEnterpriseIdentity}, ClaimNames: []string{"domain", "role"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	db := env.snap.Domains["B"]
	db.Certification = "urn:grad:cert:B-shrunk"
	env.snap.Domains["B"] = db
	env.snap.Certifications["urn:grad:cert:B-shrunk"] = api.Certification{
		Bound: api.Bound{DeploymentID: env.depID}, ID: "urn:grad:cert:B-shrunk", Domain: "B", RootKeyVersion: 1, Digest: certShrunkDig,
		Scopes: []api.Scope{{ID: "did:web:b.local:ib", KeyVersion: 1, Types: []string{CredentialTypeEnterpriseIdentity}, Claims: []string{"domain", "role"}}},
		Interval: api.Interval{NBF: env.nbf, EXP: env.exp}, Version: api.Version{Status: api.Active, Revision: 1},
	}
	env.pkg.TrustPaths[1].DomainCertification = certShrunkJWS

	// 3. With department HIDDEN (only domain & role disclosed), re-signed KB-JWT passes and Disclosed lacks "department".
	hiddenPrefix := env.sdB1Dept.IssuerSignedJWT + "~" + env.sdB1Dept.DisclosureByClaim["domain"] + "~" + env.sdB1Dept.DisclosureByClaim["role"] + "~"
	pkgHidden, chalHidden := env.signPackage(t, "chal-s93-hidden", hiddenPrefix)
	resHidden, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkgHidden, env.snap, env.dids, chalHidden, cache)
	if err != nil {
		t.Fatalf("S93 hidden optional department failed: %v", err)
	}
	if _, exists := resHidden.LeafCredential.Disclosed["department"]; exists {
		t.Fatalf("undisclosed department must not be present or inferred in Disclosed: %+v", resHidden.LeafCredential.Disclosed)
	}

	// 4. Disclosing removed "department" claim -> 403 ISSUER_SCOPE_INVALID.
	pkgDisclosed, chalDisclosed := env.signPackage(t, "chal-s93-disclosed", env.sdB1Dept.PresentationPrefix)
	if _, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkgDisclosed, env.snap, env.dids, chalDisclosed, cache); !HasCode(err, ErrCodeIssuerScopeInvalid) {
		t.Fatalf("expected ISSUER_SCOPE_INVALID when disclosing removed department claim, got %v", err)
	}

	// 5. Omitting mandatory "role" claim -> 400 INVALID_DISCLOSURE.
	noRolePrefix := env.sdB1Dept.IssuerSignedJWT + "~" + env.sdB1Dept.DisclosureByClaim["domain"] + "~"
	pkgNoRole, chalNoRole := env.signPackage(t, "chal-s93-norole", noRolePrefix)
	if _, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkgNoRole, env.snap, env.dids, chalNoRole, cache); !HasCode(err, ErrCodeInvalidDisclosure) {
		t.Fatalf("expected INVALID_DISCLOSURE when omitting mandatory role claim, got %v", err)
	}
}

func TestM3RootTOfflineZeroCallsF14S84(t *testing.T) {
	env := newM3ProtocolEnv(t, false)
	cache := NewSignatureCache()
	// Stop T's online HTTP DID server completely before verification!
	env.tServer.Close()
	before := env.tCalls.Load()

	pkg, chal := env.signPackage(t, "chal-f14", env.sdB1Dept.PresentationPrefix)
	if _, err := VerifyAccessEvidencePackageWithCache(env.ctx, &pkg, env.snap, env.dids, chal, cache); err != nil {
		t.Fatalf("F14/S84 verification should succeed when T is offline: %v", err)
	}
	if after := env.tCalls.Load(); after != before {
		t.Fatalf("expected 0 online calls to T during verification, got %d", after-before)
	}
}
