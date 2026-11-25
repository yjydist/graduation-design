// Package interdomain provides the L3 mTLS inter-domain HTTP server, typed peer client,
// TLS 1.3 certificate-pinned transport builder, and Domain B wallet receipt handler.
package interdomain

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"grad/protocol"
	"grad/protocol/registry"
)

const (
	// RoleWorkbenchA is the mTLS certificate OU role for Domain A's workbench service.
	RoleWorkbenchA = "WORKBENCH_A"
	// RoleRecoveryB is the mTLS certificate OU role for Domain B's recovery/dispatch service.
	RoleRecoveryB = "B_RECOVERY"
	// RoleAuditServiceC is the mTLS certificate OU role for Domain C's audit/gateway service.
	RoleAuditServiceC = "C_AUDIT_SERVICE"

	// DIDWorkbenchA is the pinned did:web identity for Domain A's internal service certificate.
	DIDWorkbenchA = "did:web:a.local:services:workbench"
	// DIDRecoveryB is the pinned did:web identity for Domain B's internal service certificate.
	DIDRecoveryB = "did:web:b.local:services:recovery"
	// DIDAuditServiceC is the pinned did:web identity for Domain C's internal service certificate.
	DIDAuditServiceC = "did:web:c.local:services:audit"
)

// PeerBinding pins an internal domain peer's HTTPS endpoint URL and leaf X.509 DER SHA-256 digest.
type PeerBinding struct {
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
}

// TransportConfig configures TLS 1.3 mTLS transport, peer fingerprint pinning, and DID resolution.
type TransportConfig struct {
	DomainID    string
	CertPath    string
	KeyPath     string
	CAPath      string
	Peers       map[string]PeerBinding
	RootPreseed protocol.RootPreseed
}

// TransportRole returns the expected mTLS certificate role and DID for a domain's internal service.
func TransportRole(domain string) (role, did string) {
	switch domain {
	case "B":
		return RoleRecoveryB, DIDRecoveryB
	case "C":
		return RoleAuditServiceC, DIDAuditServiceC
	default:
		return RoleWorkbenchA, DIDWorkbenchA
	}
}

// BuildSecureTransport loads the local mTLS keypair and internal CA, validates all A/B/C peer
// bindings with leaf-certificate SHA-256 pinning over TLS 1.3, and constructs a pre-seeded
// mTLS DIDWebResolver.
func BuildSecureTransport(cfg TransportConfig) (*tls.Config, map[string]*http.Client, *protocol.DIDWebResolver, error) {
	if cfg.DomainID != "A" && cfg.DomainID != "B" && cfg.DomainID != "C" {
		return nil, nil, nil, fmt.Errorf("invalid transport domain %q", cfg.DomainID)
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	rawCA, err := os.ReadFile(cfg.CAPath)
	if err != nil {
		return nil, nil, nil, err
	}
	roots, err := protocol.ParseTestCAPublic(rawCA)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(cert.Certificate) == 0 || registry.Digest(cert.Certificate[0]) != cfg.Peers[cfg.DomainID].Fingerprint {
		return nil, nil, nil, fmt.Errorf("local service certificate differs from domain binding")
	}

	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
		Certificates: []tls.Certificate{cert},
	}

	routes := make(map[string]string, 3)
	clients := make(map[string]*http.Client, 3)
	for _, domain := range []string{"A", "B", "C"} {
		peer := cfg.Peers[domain]
		u, err := url.Parse(peer.URL)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Path != "" ||
			u.RawQuery != "" || u.Fragment != "" || !registry.IsDigest(peer.Fingerprint) {
			return nil, nil, nil, fmt.Errorf("invalid internal service binding for domain %s", domain)
		}
		host, port := u.Hostname(), u.Port()
		if port == "" {
			port = "443"
		}
		routes[strings.ToLower(domain)+".local:443"] = net.JoinHostPort(host, port)

		expectedFingerprint := peer.Fingerprint
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				RootCAs:      roots,
				Certificates: []tls.Certificate{cert},
				VerifyConnection: func(state tls.ConnectionState) error {
					if len(state.PeerCertificates) == 0 || registry.Digest(state.PeerCertificates[0].Raw) != expectedFingerprint {
						return fmt.Errorf("peer certificate differs from domain binding")
					}
					return nil
				},
			},
		}
		clients[domain] = &http.Client{
			Transport: tr,
			Timeout:   55 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("internal service redirects forbidden")
			},
		}
	}

	resolver, err := protocol.NewMTLSDIDWebResolver(roots, routes, cert)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := resolver.RegisterPreseed(cfg.RootPreseed); err != nil {
		return nil, nil, nil, err
	}
	return serverTLS, clients, resolver, nil
}
