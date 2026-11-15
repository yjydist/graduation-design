package serviceauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestVerifiedMTLSCallerIgnoresSpoofedHeaders(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "service test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	did, _ := url.Parse("did:web:b.local:services:recovery")
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{OrganizationalUnit: []string{"B_RECOVERY"}}, URIs: []*url.URL{did}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := Caller(r)
		if !ok {
			w.WriteHeader(403)
			return
		}
		io.WriteString(w, id.Role+" "+id.DID)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	client := srv.Client()
	tr := client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	client = &http.Client{Transport: tr}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("X-Caller-Role", "C_AUDITOR")
	req.Header.Set("X-Caller-DID", "did:web:c.local:auditors:c1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if string(raw) != "B_RECOVERY did:web:b.local:services:recovery" {
		t.Fatalf("untrusted headers changed certificate identity: %s", raw)
	}
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	plain.Header = req.Header.Clone()
	if _, ok := Caller(plain); ok {
		t.Fatal("headers authenticated a caller without verified TLS")
	}
}
