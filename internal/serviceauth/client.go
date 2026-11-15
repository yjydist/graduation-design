package serviceauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// NewMTLSClient loads a service-specific credential and pinned server CA.
func NewMTLSClient(certPath, keyPath, caPath string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("invalid service server CA")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}}}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("service channel redirects forbidden") }}, nil
}
