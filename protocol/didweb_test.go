package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustGenKeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := GenerateP256Key()
	require.NoError(t, err)
	pubHex, err := FormatAppPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return priv, pubHex
}

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
		require.NoError(t, err, tc.did)
		assert.Equal(t, tc.want, u.String())
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
		_, err := ParseDIDWebURL(did)
		assert.True(t, HasCode(err, ErrCodeInvalidSchema), "did=%q err=%v", did, err)
	}
}

func TestDIDWebControlledHTTPSAndNegatives(t *testing.T) {
	now := time.Now().UTC()
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

	privT, pubTHex := mustGenKeyPair(t)
	privU, pubUHex := mustGenKeyPair(t)
	privB, pubBHex := mustGenKeyPair(t)
	privC, pubCHex := mustGenKeyPair(t)

	docT, err := NewDIDDocument("did:web:t.local", "did:web:t.local#key-1", &privT.PublicKey, KeyPurposeAssertionMethod)
	require.NoError(t, err)
	rawT, err := MarshalJCS(docT)
	require.NoError(t, err)
	digestT, err := docT.Digest()
	require.NoError(t, err)

	// Auth-only key on did:web:a.local:u to test purpose separation.
	docU, err := NewDIDDocument("did:web:a.local:u", "did:web:a.local:u#key-1", &privU.PublicKey, KeyPurposeAuthentication)
	require.NoError(t, err)
	rawU, err := MarshalJCS(docU)
	require.NoError(t, err)
	digestU, err := docU.Digest()
	require.NoError(t, err)

	docB, err := NewDIDDocument("did:web:b.local:b1", "did:web:b.local:b1#key-1", &privB.PublicKey)
	require.NoError(t, err)
	rawB, err := MarshalJCS(docB)
	require.NoError(t, err)
	digestB, err := docB.Digest()
	require.NoError(t, err)

	docC, err := NewDIDDocument("did:web:c.local", "did:web:c.local#key-1", &privC.PublicKey)
	require.NoError(t, err)
	rawC, err := MarshalJCS(docC)
	require.NoError(t, err)
	digestC, err := docC.Digest()
	require.NoError(t, err)

	srv, err := NewDIDWebServer(certs, map[string][]byte{
		"did:web:t.local":    rawT,
		"did:web:a.local:u":  rawU,
		"did:web:b.local:b1": rawB,
		"did:web:c.local":    rawC,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	resolver, err := NewDIDWebResolver(caPool, srv.Routes())
	require.NoError(t, err)

	preT := RootPreseed{
		DID:               "did:web:t.local",
		KeyID:             "did:web:t.local#key-1",
		KeyVersion:        1,
		PublicKeyHex:      pubTHex,
		DIDDocumentDigest: digestT,
		RawDocument:       rawT,
	}
	_, err = resolver.RegisterPreseed(preT)
	require.NoError(t, err)

	ctx := context.Background()

	// Positive offline preseed & online resolution checks.
	_, _, err = resolver.ResolvePreseededKey("did:web:t.local", "did:web:t.local#key-1", 1, KeyPurposeAssertionMethod, pubTHex)
	require.NoError(t, err)

	_, _, gotDigest, err := resolver.ResolveDID(ctx, "did:web:t.local", DIDResolutionExpectation{
		ExpectedDigest:       digestT,
		ExpectedKeyID:        "did:web:t.local#key-1",
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: pubTHex,
		RequiredPurpose:      KeyPurposeAssertionMethod,
	})
	require.NoError(t, err)
	assert.Equal(t, digestT, gotDigest)

	_, _, _, err = resolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{
		ExpectedDigest:       digestU,
		ExpectedKeyID:        "did:web:a.local:u#key-1",
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: pubUHex,
		RequiredPurpose:      KeyPurposeAuthentication,
	})
	require.NoError(t, err)

	_, _, _, err = resolver.ResolveDID(ctx, "did:web:b.local:b1", DIDResolutionExpectation{
		ExpectedDigest:       digestB,
		ExpectedKeyID:        "did:web:b.local:b1#key-1",
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: pubBHex,
		RequiredPurpose:      KeyPurposeAssertionMethod,
	})
	require.NoError(t, err)

	_, _, _, err = resolver.ResolveDID(ctx, "did:web:c.local", DIDResolutionExpectation{
		ExpectedDigest:       digestC,
		ExpectedKeyID:        "did:web:c.local#key-1",
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: pubCHex,
		RequiredPurpose:      KeyPurposeAuthentication,
	})
	require.NoError(t, err)

	// Negative 1: untrusted CA must reject TLS handshake.
	otherCA, err := GenerateTestCA(now)
	require.NoError(t, err)
	otherPool, err := ParseTestCAPublic(otherCA.CertPEM)
	require.NoError(t, err)
	untrustedResolver, err := NewDIDWebResolver(otherPool, srv.Routes())
	require.NoError(t, err)
	_, _, _, err = untrustedResolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{ExpectedDigest: digestU})
	assert.True(t, HasCode(err, ErrCodeDIDDocumentMismatch), "got %v", err)

	// Negative 2: hostname mismatch (server holds cert for b.local, dialed as a.local).
	wrongHostSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		_, _ = w.Write(rawU)
	}))
	wrongHostSrv.TLS = &tls.Config{
		Certificates: []tls.Certificate{certs["b.local"].TLSCert},
		MinVersion:   tls.VersionTLS13,
	}
	wrongHostSrv.StartTLS()
	t.Cleanup(wrongHostSrv.Close)
	wrongHostResolver, err := NewDIDWebResolver(caPool, map[string]string{
		"a.local:443": strings.TrimPrefix(wrongHostSrv.URL, "https://"),
	})
	require.NoError(t, err)
	_, _, _, err = wrongHostResolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{})
	assert.True(t, HasCode(err, ErrCodeDIDDocumentMismatch), "got %v", err)

	// Negative 3: plaintext HTTP rejected.
	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = plainLn.Close() })
	_, err = resolver.ResolveRawURL(ctx, "http://a.local/u/did.json")
	assert.True(t, HasCode(err, ErrCodeDIDDocumentMismatch), "got %v", err)

	// Negative 4: tampered document digest rejected.
	_, _, _, err = resolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{
		ExpectedDigest: strings.Repeat("a", 64),
	})
	assert.True(t, HasCode(err, ErrCodeDIDDocumentMismatch), "got %v", err)

	// Negative 5: missing required key purpose rejected (u#key-1 lacks assertionMethod).
	_, _, _, err = resolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{
		ExpectedDigest:       digestU,
		ExpectedKeyID:        "did:web:a.local:u#key-1",
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: pubUHex,
		RequiredPurpose:      KeyPurposeAssertionMethod,
	})
	assert.True(t, HasCode(err, ErrCodeDIDKeyPurposeInvalid), "got %v", err)

	// Negative 6: keyVersion mismatch (#key-1 with version 2).
	_, _, _, err = resolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{
		ExpectedDigest:       digestU,
		ExpectedKeyID:        "did:web:a.local:u#key-1",
		ExpectedKeyVersion:   2,
		ExpectedPublicKeyHex: pubUHex,
		RequiredPurpose:      KeyPurposeAuthentication,
	})
	assert.True(t, HasCode(err, ErrCodeDIDDocumentMismatch), "got %v", err)

	// Negative 7: wrong Content-Type header rejected.
	badCTServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(rawU)
	}))
	badCTServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{certs["a.local"].TLSCert},
		MinVersion:   tls.VersionTLS13,
	}
	badCTServer.StartTLS()
	t.Cleanup(badCTServer.Close)
	badCTResolver, err := NewDIDWebResolver(caPool, map[string]string{
		"a.local:443": strings.TrimPrefix(badCTServer.URL, "https://"),
	})
	require.NoError(t, err)
	_, _, _, err = badCTResolver.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{})
	assert.True(t, HasCode(err, ErrCodeDIDDocumentMismatch), "got %v", err)

	// Negative 8: preseeded offline tamper rejected.
	badPre := preT
	badPre.DIDDocumentDigest = strings.Repeat("b", 64)
	_, _, err = VerifyPreseededRootDID(badPre)
	assert.True(t, HasCode(err, ErrCodeDIDDocumentMismatch), "got %v", err)

	// Archived historical DID resolver never makes network calls and rejects missing archived docs.
	archived, err := NewArchivedDIDResolver(map[string]json.RawMessage{
		"did:web:a.local:u": rawU,
	}, preT)
	require.NoError(t, err)
	_, _, gotArchDig, err := archived.ResolveDID(ctx, "did:web:a.local:u", DIDResolutionExpectation{
		ExpectedDigest:       digestU,
		ExpectedKeyID:        "did:web:a.local:u#key-1",
		ExpectedKeyVersion:   1,
		ExpectedPublicKeyHex: pubUHex,
		RequiredPurpose:      KeyPurposeAuthentication,
	})
	require.NoError(t, err)
	assert.Equal(t, digestU, gotArchDig)

	_, _, _, err = archived.ResolveDID(ctx, "did:web:b.local:b1", DIDResolutionExpectation{})
	assert.True(t, HasCode(err, ErrCodeMaterialNotSynced), "got %v", err)
}
