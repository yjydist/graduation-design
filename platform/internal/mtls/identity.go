// Package mtls binds internal service callers to verified mTLS transport identities.
package mtls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
)

// Identity is installed by a trusted host or extracted from a verified client certificate,
// never decoded from self-asserted HTTP request headers.
type Identity struct {
	DID         string
	Role        string
	MSPID       string
	Fingerprint string
}

type identityKey struct{}

// WithIdentity attaches a trusted Identity for in-process dispatch by the service host.
// Network adapters must rely on verified client certificates instead.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// Caller extracts the verified transport Identity from r.
// Self-asserted headers are always ignored, even when a client certificate is present.
func Caller(r *http.Request) (Identity, bool) {
	if r == nil {
		return Identity{}, false
	}
	if id, ok := r.Context().Value(identityKey{}).(Identity); ok {
		return id, id.Role != ""
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return Identity{}, false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	sum := sha256.Sum256(leaf.Raw)
	id := Identity{
		Fingerprint: hex.EncodeToString(sum[:]),
	}
	for _, uri := range leaf.URIs {
		s := uri.String()
		if strings.HasPrefix(s, "did:") {
			if id.DID != "" {
				return Identity{}, false
			}
			id.DID = s
		}
		if strings.HasPrefix(s, "urn:grad:msp:") {
			id.MSPID = strings.TrimPrefix(s, "urn:grad:msp:")
		}
	}
	if len(leaf.Subject.OrganizationalUnit) == 1 {
		id.Role = strings.ToUpper(leaf.Subject.OrganizationalUnit[0])
	}
	return id, true
}

type localTransport struct {
	handler  http.Handler
	identity Identity
}

func (t localTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(WithIdentity(r.Context(), t.identity))
	w := httptest.NewRecorder()
	t.handler.ServeHTTP(w, r)
	return w.Result(), nil
}

// NewLocalClient creates an explicit role-bound in-process channel.
// It never grants identities to incoming network requests.
func NewLocalClient(handler http.Handler, identity Identity) *http.Client {
	return &http.Client{Transport: localTransport{handler: handler, identity: identity}}
}
