package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ControlledTestDomains lists the four local trust/domain hosts used in D0 verification.
var ControlledTestDomains = []string{"t.local", "a.local", "b.local", "c.local"}

// TestCA holds a self-signed P-256 root CA certificate and key used for local did:web HTTPS hosts.
type TestCA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Key     *ecdsa.PrivateKey
	KeyPEM  []byte
}

// HostTLSCert holds a leaf TLS certificate and private key signed by a TestCA.
type HostTLSCert struct {
	Host    string
	CertPEM []byte
	KeyPEM  []byte
	TLSCert tls.Certificate
}

// GenerateTestCA generates a P-256 root CA certificate and private key in memory.
func GenerateTestCA(now time.Time) (*TestCA, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "grad-auth-test-root-ca",
			Organization: []string{"grad-auth-v1"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return &TestCA{
		Cert:    cert,
		CertPEM: certPEM,
		Key:     priv,
		KeyPEM:  keyPEM,
	}, nil
}

// ParseTestCAPublic reconstructs a CA CertPool from public PEM bytes (no private key required).
func ParseTestCAPublic(certPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, NewError(ErrCodeInvalidSchema, "invalid test CA PEM certificate")
	}
	return pool, nil
}

// IssueHostCert issues a leaf TLS server certificate for host signed by ca.
func (ca *TestCA) IssueHostCert(host string, now time.Time) (*HostTLSCert, error) {
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		return nil, NewError(ErrCodeInvalidSchema, "nil TestCA")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"grad-auth-v1"},
		},
		DNSNames:              []string{host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &priv.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &HostTLSCert{
		Host:    host,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		TLSCert: tlsCert,
	}, nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// ParseDIDWebURL maps a did:web identifier to its HTTPS resolution URL per the W3C did:web spec.
func ParseDIDWebURL(did string) (*url.URL, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("DID %q does not use did:web method", did))
	}
	rest := strings.TrimPrefix(did, "did:web:")
	if rest == "" || strings.ContainsAny(rest, "?#/") {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("malformed did:web identifier %q", did))
	}
	parts := strings.Split(rest, ":")
	for _, seg := range parts {
		if seg == "" || seg == "." || seg == ".." {
			return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("illegal path segment in did:web %q", did))
		}
	}
	host, err := url.PathUnescape(parts[0])
	if err != nil || host == "" || strings.ContainsAny(host, "/\\?#") {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid host segment in did:web %q", did))
	}
	var path string
	if len(parts) == 1 {
		path = "/.well-known/did.json"
	} else {
		path = "/" + strings.Join(parts[1:], "/") + "/did.json"
	}
	rawURL := "https://" + host + path
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host != host {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("invalid resolved did:web URL for %q", did))
	}
	return u, nil
}

// DIDWebServer serves registered application/did+json documents over local loopback HTTPS
// with SNI-selected certificates issued for controlled hosts.
type DIDWebServer struct {
	mu       sync.RWMutex
	certs    map[string]tls.Certificate
	docs     map[string][]byte // key: "<host><path>" -> raw JSON bytes
	listener net.Listener
	server   *http.Server
	addr     string
}

// NewDIDWebServer starts a local HTTPS server on 127.0.0.1:0 hosting certByHost and initial docs.
// Each doc key is a full DID ("did:web:a.local:u") automatically mapped via ParseDIDWebURL.
func NewDIDWebServer(certByHost map[string]*HostTLSCert, docsByDID map[string][]byte) (*DIDWebServer, error) {
	s := &DIDWebServer{
		certs: make(map[string]tls.Certificate, len(certByHost)),
		docs:  make(map[string][]byte, len(docsByDID)),
	}
	for host, hc := range certByHost {
		if hc == nil {
			continue
		}
		s.certs[host] = hc.TLSCert
	}
	for did, body := range docsByDID {
		if err := s.SetDocument(did, body); err != nil {
			return nil, err
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: s.getCertificate,
	})
	s.listener = tlsLn
	s.addr = ln.Addr().String()
	s.server = &http.Server{
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = s.server.Serve(tlsLn)
	}()
	return s, nil
}

// Addr returns the local TCP address (e.g. "127.0.0.1:54321") bound by the server.
func (s *DIDWebServer) Addr() string {
	return s.addr
}

// Routes returns a host:port -> Addr mapping for all TLS hosts configured on this server.
func (s *DIDWebServer) Routes() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	routes := make(map[string]string, len(s.certs))
	for host := range s.certs {
		routes[net.JoinHostPort(host, "443")] = s.addr
	}
	return routes
}

// SetDocument mounts raw DID JSON at the URL path derived from did.
func (s *DIDWebServer) SetDocument(did string, raw []byte) error {
	u, err := ParseDIDWebURL(did)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[u.Host+u.Path] = append([]byte(nil), raw...)
	return nil
}

// Close stops the local HTTPS did:web server.
func (s *DIDWebServer) Close() error {
	if s == nil || s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *DIDWebServer) getCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cert, ok := s.certs[chi.ServerName]
	if !ok {
		return nil, fmt.Errorf("no certificate configured for SNI host %q", chi.ServerName)
	}
	return &cert, nil
}

func (s *DIDWebServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := r.Host
	if h, port, err := net.SplitHostPort(host); err == nil && port == "443" {
		host = h
	}
	s.mu.RLock()
	body, ok := s.docs[host+r.URL.Path]
	s.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/did+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// RootPreseed pins the local offline root DID document alongside its expected registry metadata.
type RootPreseed struct {
	DID               string
	KeyID             string
	KeyVersion        uint64
	PublicKeyHex      string
	DIDDocumentDigest string
	RawDocument       []byte
}

// DIDWebResolver resolves controlled did:web HTTPS documents using a pinned CA pool and
// controlled DialContext host mapping (no OS DNS or /etc/hosts mutations).
type DIDWebResolver struct {
	client       *http.Client
	hostRoutes   map[string]string
	preseeded    map[string]RootPreseed
	requirePreID bool
}

// NewDIDWebResolver creates a resolver pinned to caPool and routing specified host:port targets
// to loopback addresses without external network resolution.
func NewDIDWebResolver(caPool *x509.CertPool, hostRoutes map[string]string) (*DIDWebResolver, error) {
	if caPool == nil {
		return nil, NewError(ErrCodeInvalidSchema, "DIDWebResolver requires non-nil RootCAs")
	}
	routes := make(map[string]string, len(hostRoutes))
	for k, v := range hostRoutes {
		routes[k] = v
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    caPool,
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if target, ok := routes[addr]; ok {
				return dialer.DialContext(ctx, network, target)
			}
			return nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("refusing dial to unrouted external host %q", addr))
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return NewError(ErrCodeDIDDocumentMismatch, "HTTP redirects are forbidden during did:web resolution")
		},
	}
	return &DIDWebResolver{
		client:     client,
		hostRoutes: routes,
		preseeded:  make(map[string]RootPreseed),
	}, nil
}

// RegisterPreseed stores and validates an offline pre-seeded trust root DID document (e.g. did:web:t.local).
func (r *DIDWebResolver) RegisterPreseed(pre RootPreseed) (*DIDDocument, error) {
	doc, pub, err := VerifyPreseededRootDID(pre)
	if err != nil {
		return nil, err
	}
	_ = pub
	r.preseeded[pre.DID] = pre
	return doc, nil
}

// VerifyPreseededRootDID validates a local offline root DID document against expected digest,
// keyID, key version (>0), assertionMethod purpose, and appPublicKey without network access.
func VerifyPreseededRootDID(pre RootPreseed) (*DIDDocument, *ecdsa.PublicKey, error) {
	if pre.KeyVersion == 0 {
		return nil, nil, NewError(ErrCodeInvalidSchema, "root keyVersion must be >= 1")
	}
	doc, digest, err := ParseDIDDocument(pre.RawDocument)
	if err != nil {
		return nil, nil, err
	}
	if doc.ID != pre.DID {
		return nil, nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("preseeded DID doc id %q != %q", doc.ID, pre.DID))
	}
	if pre.DIDDocumentDigest != "" && digest != pre.DIDDocumentDigest {
		return nil, nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("preseeded DID digest %s != %s", digest, pre.DIDDocumentDigest))
	}
	pub, _, err := doc.ResolveKey(pre.KeyID, KeyPurposeAssertionMethod, pre.PublicKeyHex)
	if err != nil {
		return nil, nil, err
	}
	return doc, pub, nil
}

// ResolvePreseededKey verifies keyID against the offline pre-seeded trust root document.
func (r *DIDWebResolver) ResolvePreseededKey(did, keyID string, keyVersion uint64, purpose, expectedPubHex string) (*DIDDocument, *ecdsa.PublicKey, error) {
	pre, ok := r.preseeded[did]
	if !ok {
		return nil, nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("no preseeded root document registered for %q", did))
	}
	if pre.KeyVersion != keyVersion || keyVersion == 0 {
		return nil, nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("root keyVersion %d mismatches registered %d", keyVersion, pre.KeyVersion))
	}
	doc, _, err := VerifyPreseededRootDID(pre)
	if err != nil {
		return nil, nil, err
	}
	pub, _, err := doc.ResolveKey(keyID, purpose, expectedPubHex)
	if err != nil {
		return nil, nil, err
	}
	return doc, pub, nil
}

// ResolveRawURL fetches a raw URL using the pinned client; used explicitly to enforce https-only scheme checks.
func (r *DIDWebResolver) ResolveRawURL(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "invalid URL", err)
	}
	if u.Scheme != "https" {
		return nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("plaintext or non-HTTPS scheme %q rejected", u.Scheme))
	}
	hostPort := u.Host
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		hostPort = net.JoinHostPort(u.Hostname(), "443")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, WrapError(ErrCodeInvalidSchema, "build HTTP request", err)
	}
	req.Header.Set("Accept", "application/did+json")
	if _, ok := r.hostRoutes[hostPort]; !ok {
		return nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("host %q not in controlled test CA routes", hostPort))
	}

	resp, err := r.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, WrapError(ErrCodeDIDDocumentMismatch, "HTTPS did:web fetch failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("HTTP status %d from %s", resp.StatusCode, u.String()))
	}
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/did+json" {
		return nil, NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("unexpected Content-Type %q (expected application/did+json)", resp.Header.Get("Content-Type")))
	}
	if cs, ok := params["charset"]; ok && !strings.EqualFold(cs, "utf-8") {
		return nil, NewError(ErrCodeInvalidSchema, fmt.Sprintf("unsupported charset %q", cs))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJSONBytes+1))
	if err != nil {
		return nil, WrapError(ErrCodeDIDDocumentMismatch, "read did:web response body", err)
	}
	if len(body) > MaxJSONBytes {
		return nil, NewError(ErrCodeInvalidSchema, "did:web response exceeds 256 KiB")
	}
	return body, nil
}

// DIDResolutionExpectation constrains HTTPS did:web resolution against anchored registry facts.
type DIDResolutionExpectation struct {
	ExpectedDigest       string
	ExpectedKeyID        string
	ExpectedKeyVersion   uint64
	ExpectedPublicKeyHex string
	RequiredPurpose      string
}

// ResolveDID resolves did via HTTPS using pinned CA and host routes, parses the DID Document,
// checks didDocumentDigest, appKeyVersion, appKeyId, purpose, and appPublicKey.
func (r *DIDWebResolver) ResolveDID(ctx context.Context, did string, exp DIDResolutionExpectation) (*DIDDocument, *ecdsa.PublicKey, string, error) {
	u, err := ParseDIDWebURL(did)
	if err != nil {
		return nil, nil, "", err
	}
	if exp.ExpectedKeyVersion == 0 && exp.ExpectedKeyID != "" {
		return nil, nil, "", NewError(ErrCodeInvalidSchema, "expected key version must be >= 1")
	}
	raw, err := r.ResolveRawURL(ctx, u.String())
	if err != nil {
		return nil, nil, "", err
	}
	doc, digest, err := ParseDIDDocument(raw)
	if err != nil {
		return nil, nil, "", err
	}
	if doc.ID != did {
		return nil, nil, "", NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("DID document id %q != %q", doc.ID, did))
	}
	if exp.ExpectedDigest != "" && digest != exp.ExpectedDigest {
		return nil, nil, "", NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("didDocumentDigest %s mismatches expected %s", digest, exp.ExpectedDigest))
	}
	var pub *ecdsa.PublicKey
	if exp.ExpectedKeyID != "" {
		if err := CheckVersionedKeyID(did, exp.ExpectedKeyID, exp.ExpectedKeyVersion); err != nil {
			return nil, nil, "", err
		}
		pub, _, err = doc.ResolveKey(exp.ExpectedKeyID, exp.RequiredPurpose, exp.ExpectedPublicKeyHex)
		if err != nil {
			return nil, nil, "", err
		}
	}
	// If preseeded root exists for this DID, remote doc must also equal preseeded digest.
	if pre, ok := r.preseeded[did]; ok && pre.DIDDocumentDigest != "" && digest != pre.DIDDocumentDigest {
		return nil, nil, "", NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("remote DID doc digest %s disagrees with preseeded %s", digest, pre.DIDDocumentDigest))
	}
	return doc, pub, digest, nil
}

// CheckVersionedKeyID checks that keyID is an absolute DID URL belonging to did and, if it carries
// a `-<number>` or `-v<number>` suffix (e.g. `#key-2`), confirms the suffix does not contradict keyVersion.
func CheckVersionedKeyID(did, keyID string, keyVersion uint64) error {
	if !strings.HasPrefix(keyID, did+"#") || len(keyID) <= len(did)+1 {
		return NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("keyID %q does not reference DID %q", keyID, did))
	}
	if keyVersion == 0 {
		return NewError(ErrCodeInvalidSchema, "appKeyVersion must be >= 1")
	}
	frag := strings.TrimPrefix(keyID, did+"#")
	if idx := strings.LastIndexByte(frag, '-'); idx >= 0 && idx+1 < len(frag) {
		tail := strings.TrimPrefix(frag[idx+1:], "v")
		if n, err := strconv.ParseUint(tail, 10, 64); err == nil && n != keyVersion {
			return NewError(ErrCodeDIDDocumentMismatch, fmt.Sprintf("keyID %q embedded version %d mismatches registered appKeyVersion %d", keyID, n, keyVersion))
		}
	}
	return nil
}
