package registrysvc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/protocol"
	"grad/protocol/registry"
)

func assertUnifiedErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCode string) httpx.ErrorEnvelope {
	t.Helper()
	require.Equal(t, wantStatus, rec.Code, "body=%s", rec.Body.String())
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
	reqIDHeader := rec.Header().Get(httpx.HeaderRequestID)
	assert.NotEmpty(t, reqIDHeader)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	_, hasLegacy := raw["errorCode"]
	assert.False(t, hasLegacy, "legacy errorCode key must not appear in unified error envelope: %s", rec.Body.String())
	val, hasDecisionID := raw["decisionId"]
	assert.True(t, hasDecisionID, "decisionId must always be present in error envelope")
	assert.Nil(t, val, "decisionId must be null for registrysvc errors")

	var env httpx.ErrorEnvelope
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	assert.Equal(t, reqIDHeader, env.RequestID)
	assert.Equal(t, wantCode, env.Code)
	assert.Nil(t, env.DecisionID)
	assert.NotEmpty(t, env.Message)
	return env
}

func TestBuildAccessTrustPathsDedupAndOrder(t *testing.T) {
	_, err := BuildAccessTrustPaths(nil, nil, "did:web:a.local:ia")
	assert.True(t, protocol.HasCode(err, registry.ErrCodeStateUnavailable))

	snap := &protocol.SnapshotView{
		Identities: map[string]registry.Identity{
			"did:web:a.local:ia": {ID: "did:web:a.local:ia", Domain: "A"},
			"did:web:b.local:ib": {ID: "did:web:b.local:ib", Domain: "B"},
			"did:web:c.local:ic": {ID: "did:web:c.local:ic", Domain: "C"},
		},
	}
	certs := map[string]string{"A": "cert-A", "B": "cert-B"}

	tp, err := BuildAccessTrustPaths(certs, snap, "did:web:b.local:ib", "", "did:web:a.local:ia", "did:web:a.local:ia")
	require.NoError(t, err)
	require.Len(t, tp, 2)
	assert.Equal(t, protocol.TrustPathEntry{Issuer: "did:web:a.local:ia", DomainCertification: "cert-A"}, tp[0])
	assert.Equal(t, protocol.TrustPathEntry{Issuer: "did:web:b.local:ib", DomainCertification: "cert-B"}, tp[1])

	_, err = BuildAccessTrustPaths(certs, snap, "did:web:unknown:issuer")
	assert.True(t, protocol.HasCode(err, registry.ErrCodeIssuerScopeInvalid))

	_, err = BuildAccessTrustPaths(certs, snap, "did:web:c.local:ic")
	assert.True(t, protocol.HasCode(err, registry.ErrCodeMaterialNotSynced))
}

func TestGrantDeliveryPackageDigest(t *testing.T) {
	pkg := GrantDeliveryPackage{
		DeploymentID:           strings.Repeat("a", 64),
		Recipient:              "did:web:a.local:u",
		GrantID:                "urn:grad:grant:g0",
		GrantJWS:               "header.payload.sig",
		ServicePresentation:    "jwt~disc~",
		DomainCertificationJWS: "cert.jws.sig",
		TaskSpec: protocol.TaskSpec{
			SupplierID:  "did:web:c.local:supplier",
			ProductID:   "urn:grad:product:P1",
			MaxQuantity: 5,
			Currency:    "CNY",
			Resources:   []string{protocol.ResourceOrders, protocol.ResourceQuotes},
			Actions:     []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
			Description: "test procurement",
		},
	}
	raw1, dig1, err := pkg.Digest()
	require.NoError(t, err)
	assert.NotEmpty(t, raw1)
	assert.Len(t, dig1, 64)

	raw2, dig2, err := pkg.Digest()
	require.NoError(t, err)
	assert.Equal(t, raw1, raw2)
	assert.Equal(t, dig1, dig2)

	pkg.GrantID = "urn:grad:grant:g1"
	_, dig3, err := pkg.Digest()
	require.NoError(t, err)
	assert.NotEqual(t, dig1, dig3)
}

func TestVerifyAuthorizedMgmtCert(t *testing.T) {
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-msp-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "user@a.local"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	rogueKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rogueDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &rogueKey.PublicKey, rogueKey)
	require.NoError(t, err)
	rogueCert, err := x509.ParseCertificate(rogueDER)
	require.NoError(t, err)

	require.NoError(t, verifyAuthorizedMgmtCert(leafCert, []*x509.Certificate{caCert}))
	require.NoError(t, verifyAuthorizedMgmtCert(leafCert, []*x509.Certificate{leafCert}))

	err = verifyAuthorizedMgmtCert(rogueCert, []*x509.Certificate{caCert})
	assert.True(t, protocol.HasCode(err, registry.ErrCodeSignatureInvalid))

	err = verifyAuthorizedMgmtCert(rogueCert, []*x509.Certificate{leafCert})
	assert.True(t, protocol.HasCode(err, registry.ErrCodeSignatureInvalid))
}

func TestHandlerUnifiedErrorEnvelopeWithoutDB(t *testing.T) {
	caller := mtls.Identity{Role: "MANAGEMENT", MSPID: "AMsp", Fingerprint: strings.Repeat("a", 64)}

	// Service with nil backend -> 503 STATE_UNAVAILABLE on POST.
	svcNoBackend := NewService(nil, strings.Repeat("1", 64), registry.Management{}, nil)
	hNoBackend := svcNoBackend.Handler()

	// Unauthenticated POST -> 403 IDENTITY_MANAGEMENT_FORBIDDEN.
	req := httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	hNoBackend.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, registry.ErrCodeIdentityManagementForbidden)

	// Unauthenticated GET -> 403 IDENTITY_MANAGEMENT_FORBIDDEN.
	req = httptest.NewRequest(http.MethodGet, "/v1/operations/some-id", nil)
	rec = httptest.NewRecorder()
	hNoBackend.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusForbidden, registry.ErrCodeIdentityManagementForbidden)

	// Authenticated GET with empty operationId -> 400 INVALID_SCHEMA.
	req = httptest.NewRequest(http.MethodGet, "/v1/operations/", nil)
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	hNoBackend.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusBadRequest, registry.ErrCodeInvalidSchema)

	// Authenticated POST with nil backend -> 503 STATE_UNAVAILABLE.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	hNoBackend.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable)

	// Service with dummy backend and nil DB to test HTTP body validation errors.
	svcWithBackend := NewService(nil, strings.Repeat("1", 64), registry.Management{}, &noopBackend{})
	h := svcWithBackend.Handler()

	// Unsupported Content-Type -> 415 UNSUPPORTED_MEDIA_TYPE.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusUnsupportedMediaType, registry.ErrCodeUnsupportedMediaType)

	// Oversized payload -> 413 PAYLOAD_TOO_LARGE.
	bigBody := bytes.Repeat([]byte("a"), protocol.MaxJSONBytes+1)
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", bytes.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assertUnifiedErrorEnvelope(t, rec, http.StatusRequestEntityTooLarge, registry.ErrCodePayloadTooLarge)

	// Malformed JSON -> 400 INVALID_SCHEMA.
	req = httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", strings.NewReader(`{"broken":`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httpx.HeaderRequestID, "urn:grad:req:custom-1")
	req = req.WithContext(mtls.WithIdentity(req.Context(), caller))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	env := assertUnifiedErrorEnvelope(t, rec, http.StatusBadRequest, registry.ErrCodeInvalidSchema)
	assert.Equal(t, "urn:grad:req:custom-1", env.RequestID)
}

type noopBackend struct{}

func (*noopBackend) CurrentRevision(context.Context, string, json.RawMessage) (uint64, bool, error) {
	return 0, false, nil
}

func (*noopBackend) SubmitAsync(
	context.Context,
	string, string,
	registry.Management,
	string,
	json.RawMessage,
	func(string, string, string, int64, string, *string, *string, bool) error,
) {
}
