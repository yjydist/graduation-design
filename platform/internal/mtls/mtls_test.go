package mtls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/internal/mtls"
)

type testPKI struct {
	ca      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caPEM   []byte
	caPool  *x509.CertPool
	nextSer int64
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "service test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &testPKI{ca: ca, caKey: caKey, caPEM: caPEM, caPool: pool, nextSer: 2}
}

func (p *testPKI) issueClient(t *testing.T, ou string, uris ...string) (tls.Certificate, []byte, []byte, string) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	parsedURIs := make([]*url.URL, 0, len(uris))
	for _, raw := range uris {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		parsedURIs = append(parsedURIs, u)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.nextSer),
		Subject:      pkix.Name{OrganizationalUnit: []string{ou}},
		URIs:         parsedURIs,
		NotBefore:    p.ca.NotBefore,
		NotAfter:     p.ca.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	p.nextSer++
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &leafKey.PublicKey, p.caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	sum := sha256.Sum256(der)
	return cert, certPEM, keyPEM, hex.EncodeToString(sum[:])
}

func (p *testPKI) issueServer(t *testing.T) tls.Certificate {
	t.Helper()
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.nextSer),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		NotBefore:    p.ca.NotBefore,
		NotAfter:     p.ca.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	p.nextSer++
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &srvKey.PublicKey, p.caKey)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	require.NoError(t, err)
	return cert
}

func TestVerifiedMTLSCallerIgnoresSpoofedHeaders(t *testing.T) {
	pki := newTestPKI(t)
	cert, _, _, wantFP := pki.issueClient(t, "b_recovery", "did:web:b.local:services:recovery", "urn:grad:msp:OrgBMSP")

	var gotID mtls.Identity
	var gotOK bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID, gotOK = mtls.Caller(r)
		if !gotOK {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, gotID.Role+" "+gotID.DID)
	}))
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pki.caPool,
		MinVersion: tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	client := &http.Client{Transport: tr}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Caller-Role", "C_AUDITOR")
	req.Header.Set("X-Caller-DID", "did:web:c.local:auditors:c1")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "B_RECOVERY did:web:b.local:services:recovery", string(raw))
	require.True(t, gotOK)
	assert.Equal(t, "B_RECOVERY", gotID.Role)
	assert.Equal(t, "did:web:b.local:services:recovery", gotID.DID)
	assert.Equal(t, "OrgBMSP", gotID.MSPID)
	assert.Equal(t, wantFP, gotID.Fingerprint)

	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	plain.Header = req.Header.Clone()
	_, ok := mtls.Caller(plain)
	assert.False(t, ok, "headers must not authenticate a caller without verified TLS")
}

func TestCallerRejectsDuplicateDIDURI(t *testing.T) {
	pki := newTestPKI(t)
	cert, _, _, _ := pki.issueClient(t, "C_AUDITOR", "did:web:c.local:a1", "did:web:c.local:a2")
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{leaf}},
	}
	_, ok := mtls.Caller(req)
	assert.False(t, ok)
}

func TestNewLocalClientAndWithIdentity(t *testing.T) {
	want := mtls.Identity{
		DID:   "did:web:c.local:auditors:c1",
		Role:  "C_AUDITOR",
		MSPID: "OrgCMSP",
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := mtls.Caller(r)
		require.True(t, ok)
		assert.Equal(t, want, got)
		w.WriteHeader(http.StatusOK)
	})

	client := mtls.NewLocalClient(handler, want)
	resp, err := client.Get("http://in-process.local/check")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	emptyRoleReq := httptest.NewRequest(http.MethodGet, "/", nil)
	emptyRoleReq = emptyRoleReq.WithContext(mtls.WithIdentity(emptyRoleReq.Context(), mtls.Identity{DID: "did:web:x"}))
	_, ok := mtls.Caller(emptyRoleReq)
	assert.False(t, ok, "empty role in context identity must fail closed")
}

func TestNewMTLSClientHandshakeAndForbidRedirect(t *testing.T) {
	pki := newTestPKI(t)
	_, certPEM, keyPEM, _ := pki.issueClient(t, "A_ADMIN", "did:web:a.local:admin")
	srvCert := pki.issueServer(t)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	caPath := filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, pki.caPEM, 0o600))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		id, ok := mtls.Caller(r)
		require.True(t, ok)
		_, _ = io.WriteString(w, id.Role)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.caPool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	client, err := mtls.NewMTLSClient(certPath, keyPath, caPath)
	require.NoError(t, err)
	defer client.CloseIdleConnections()

	resp, err := client.Get(srv.URL + "/ok")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "A_ADMIN", string(body))

	_, err = client.Get(srv.URL + "/redirect")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirects forbidden")
}
