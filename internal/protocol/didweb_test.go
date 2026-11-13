package protocol

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseDIDWebURLMapping(t *testing.T) {
	cases := []struct {
		did  string
		want string
	}{
		{"did:web:t.local", "https://t.local/.well-known/did.json"},
		{"did:web:a.local:u", "https://a.local/u/did.json"},
		{"did:web:b.local:brokers:b1", "https://b.local/brokers/b1/did.json"},
		{"did:web:example.test%3A8443:u", "https://example.test:8443/u/did.json"},
	}
	for _, tc := range cases {
		u, err := ParseDIDWebURL(tc.did)
		if err != nil {
			t.Fatalf("ParseDIDWebURL(%q) error: %v", tc.did, err)
		}
		if u.String() != tc.want {
			t.Fatalf("ParseDIDWebURL(%q) = %q, want %q", tc.did, u.String(), tc.want)
		}
	}

	badDIDs := []string{
		"did:key:z123",
		"did:web:",
		"did:web:a.local::u",
		"did:web:a.local:..",
		"did:web:a.local:u?foo=bar",
		"did:web:a.local:u#key-1",
	}
	for _, did := range badDIDs {
		if _, err := ParseDIDWebURL(did); !HasCode(err, ErrCodeInvalidSchema) {
			t.Fatalf("expected INVALID_SCHEMA for %q, got %v", did, err)
		}
	}
}

func TestDIDWebControlledHTTPSAndNegatives(t *testing.T) {
	now := time.Now().UTC()
	ca, err := GenerateTestCA(now)
	if err != nil {
		t.Fatalf("GenerateTestCA: %v", err)
	}
	caPool, err := ParseTestCAPublic(ca.CertPEM)
	if err != nil {
		t.Fatalf("ParseTestCAPublic: %v", err)
	}

	certs := make(map[string]*HostTLSCert, len(ControlledTestDomains))
	for _, host := range ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		if err != nil {
			t.Fatalf("IssueHostCert(%s): %v", host, err)
		}
		certs[host] = hc
	}

	// Build real P-256 keys & DID documents for t.local, a.local:u, b.local:b1, c.local:svc
	_, pubT, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, pubU, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, pubUAuthOnly, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_ = pubUAuthOnly
	_, pubB, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, pubC, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	docT, err := NewDIDDocument("did:web:t.local", "did:web:t.local#key-1", pubT, KeyPurposeAssertionMethod)
	if err != nil {
		t.Fatal(err)
	}
	rawT, _ := MarshalJCS(docT)
	digestT, _ := docT.Digest()

	// Auth-only key on did:web:a.local:u to test purpose check
	docU, err := NewDIDDocument("did:web:a.local:u", "did:web:a.local:u#key-1", pubU, KeyPurposeAuthentication)
	if err != nil {
		t.Fatal(err)
	}
	rawU, _ := MarshalJCS(docU)
	digestU, _ := docU.Digest()

	docB, err := NewDIDDocument("did:web:b.local:b1", "did:web:b.local:b1#key-1", pubB)
	if err != nil {
		t.Fatal(err)
	}
	rawB, _ := MarshalJCS(docB)
	digestB, _ := docB.Digest()

	docC, err := NewDIDDocument("did:web:c.local", "did:web:c.local#key-1", pubC)
	if err != nil {
		t.Fatal(err)
	}
	rawC, _ := MarshalJCS(docC)
	digestC, _ := docC.Digest()

	srv, err := NewDIDWebServer(certs, map[string][]byte{
		"did:web:t.local":    rawT,
		"did:web:a.local:u":  rawU,
		"did:web:b.local:b1": rawB,
		"did:web:c.local":    rawC,
	})
	if err != nil {
		t.Fatalf("NewDIDWebServer: %v", err)
	}
	defer srv.Close()

	resolver, err := NewDIDWebResolver(caPool, srv.Routes())
	if err != nil {
		t.Fatalf("NewDIDWebResolver: %v", err)
	}

	preT := RootPreseed{
		DID:               "did:web:t.local",
		KeyID:             "did:web:t.local#key-1",
		KeyVersion:        1,
		PublicKeyHex:      pubT,
		DIDDocumentDigest: digestT,
		RawDocument:       rawT,
	}
	if _, err := resolver.RegisterPreseed(preT); err != nil {
		t.Fatalf("RegisterPreseed: %v", err)
	}

	ctx := context.Background()

	// Positive offline preseed & online resolution checks
	if _, _, err := resolver.ResolvePreseededKey("did:web:t.local", "did:web:t.local#key-1", 1, KeyPurposeAssertionMethod, pubT); err != nil {
		t.Fatalf("ResolvePreseededKey: %v", err)
	}
	if _, _, gotDigest, err := resolver.ResolveDID(ctx, "did:web:t.local", DIDResolutionExpectation{
		ExpectedDigest:       digestT,
		ExpectedKeyID:        "did:web:t.local#key-1",
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: pubT,
		RequiredPurpose:      KeyPurposeAssertionMethod,
	}); err != nil || gotDigest != digestT {
		t.Fatalf("ResolveDID(t.local): err=%v digest=%s", err, gotDigest)
	}
	if _, _, _, err := resolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{
		ExpectedDigest:       digestU,
		ExpectedKeyID:        "did:web:a.local:u#key-1",
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: pubU,
		RequiredPurpose:      KeyPurposeAuthentication,
	}); err != nil {
		t.Fatalf("ResolveDID(a.local:u): %v", err)
	}
	if _, _, _, err := resolver.ResolveDID(ctx, "did:web:b.local:b1", DIDResolutionExpectation{
		ExpectedDigest:       digestB,
		ExpectedKeyID:        "did:web:b.local:b1#key-1",
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: pubB,
		RequiredPurpose:      KeyPurposeAssertionMethod,
	}); err != nil {
		t.Fatalf("ResolveDID(b.local:b1): %v", err)
	}
	if _, _, _, err := resolver.ResolveDID(ctx, "did:web:c.local", DIDResolutionExpectation{
		ExpectedDigest:       digestC,
		ExpectedKeyID:        "did:web:c.local#key-1",
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: pubC,
		RequiredPurpose:      KeyPurposeAuthentication,
	}); err != nil {
		t.Fatalf("ResolveDID(c.local): %v", err)
	}

	// Negative 1: untrusted CA must reject TLS handshake
	otherCA, err := GenerateTestCA(now)
	if err != nil {
		t.Fatal(err)
	}
	otherPool, _ := ParseTestCAPublic(otherCA.CertPEM)
	untrustedResolver, err := NewDIDWebResolver(otherPool, srv.Routes())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := untrustedResolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{ExpectedDigest: digestU}); !HasCode(err, ErrCodeDIDDocumentMismatch) {
		t.Fatalf("expected DID_DOCUMENT_MISMATCH for untrusted CA, got %v", err)
	}

	// Negative 2: hostname mismatch (server only holds cert for b.local, dialed as a.local)
	wrongHostSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write(rawU)
	}))
	wrongHostSrv.TLS = &tls.Config{
		Certificates: []tls.Certificate{certs["b.local"].TLSCert},
		MinVersion:   tls.VersionTLS13,
	}
	wrongHostSrv.StartTLS()
	defer wrongHostSrv.Close()
	wrongHostResolver, err := NewDIDWebResolver(caPool, map[string]string{
		"a.local:443": strings.TrimPrefix(wrongHostSrv.URL, "https://"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := wrongHostResolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{}); !HasCode(err, ErrCodeDIDDocumentMismatch) {
		t.Fatalf("expected hostname mismatch TLS failure, got %v", err)
	}

	// Negative 3: plaintext HTTP rejected
	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plainLn.Close()
	if _, err := resolver.ResolveRawURL(ctx, "http://a.local/u/did.json"); !HasCode(err, ErrCodeDIDDocumentMismatch) {
		t.Fatalf("expected plaintext HTTP rejection, got %v", err)
	}

	// Negative 4: tampered document digest rejected
	if _, _, _, err := resolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{
		ExpectedDigest: strings.Repeat("a", 64),
	}); !HasCode(err, ErrCodeDIDDocumentMismatch) {
		t.Fatalf("expected DID_DOCUMENT_MISMATCH on tampered digest, got %v", err)
	}

	// Negative 5: missing required key purpose rejected (u#key-1 lacks assertionMethod)
	if _, _, _, err := resolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{
		ExpectedDigest:       digestU,
		ExpectedKeyID:        "did:web:a.local:u#key-1",
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: pubU,
		RequiredPurpose:      KeyPurposeAssertionMethod,
	}); !HasCode(err, ErrCodeDIDKeyPurposeInvalid) {
		t.Fatalf("expected DID_KEY_PURPOSE_INVALID when assertionMethod missing, got %v", err)
	}

	// Negative 6: keyVersion mismatch (#key-1 with version 2)
	if _, _, _, err := resolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{
		ExpectedDigest:       digestU,
		ExpectedKeyID:        "did:web:a.local:u#key-1",
		ExpectedKeyVersion:   2,
		ExpectedPublicKeyHex: pubU,
		RequiredPurpose:      KeyPurposeAuthentication,
	}); !HasCode(err, ErrCodeDIDDocumentMismatch) {
		t.Fatalf("expected DID_DOCUMENT_MISMATCH on keyVersion mismatch, got %v", err)
	}

	// Negative 7: wrong Content-Type header rejected
	badCTServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(rawU)
	}))
	badCTServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{certs["a.local"].TLSCert},
		MinVersion:   tls.VersionTLS13,
	}
	badCTServer.StartTLS()
	defer badCTServer.Close()
	badCTResolver, err := NewDIDWebResolver(caPool, map[string]string{
		"a.local:443": strings.TrimPrefix(badCTServer.URL, "https://"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := badCTResolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{}); !HasCode(err, ErrCodeDIDDocumentMismatch) {
		t.Fatalf("expected rejection for wrong Content-Type application/json, got %v", err)
	}

	// Negative 8: preseeded offline tamper rejected
	badPre := preT
	badPre.DIDDocumentDigest = strings.Repeat("b", 64)
	if _, _, err := VerifyPreseededRootDID(badPre); !HasCode(err, ErrCodeDIDDocumentMismatch) {
		t.Fatalf("expected DID_DOCUMENT_MISMATCH for tampered preseeded root, got %v", err)
	}
}
