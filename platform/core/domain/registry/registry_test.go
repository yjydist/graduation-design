package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/protocol"
	preg "grad/protocol/registry"
)

func TestBuildAccessTrustPathsDedupAndOrder(t *testing.T) {
	_, err := BuildAccessTrustPaths(nil, nil, "did:web:a.local:ia")
	assert.True(t, protocol.HasCode(err, preg.ErrCodeStateUnavailable))

	snap := &protocol.SnapshotView{
		Identities: map[string]preg.Identity{
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
	assert.True(t, protocol.HasCode(err, preg.ErrCodeIssuerScopeInvalid))

	_, err = BuildAccessTrustPaths(certs, snap, "did:web:c.local:ic")
	assert.True(t, protocol.HasCode(err, preg.ErrCodeMaterialNotSynced))
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
	assert.True(t, protocol.HasCode(err, preg.ErrCodeSignatureInvalid))

	err = verifyAuthorizedMgmtCert(rogueCert, []*x509.Certificate{leafCert})
	assert.True(t, protocol.HasCode(err, preg.ErrCodeSignatureInvalid))
}

func TestServiceWithoutDBAndCallerResolution(t *testing.T) {
	ctx := t.Context()
	fpA := strings.Repeat("a", 64)
	fpB := strings.Repeat("b", 64)
	fpUnknown := strings.Repeat("f", 64)
	callerA := preg.Management{MSPID: "AMsp", CertificateSHA256: fpA}
	auditorB := preg.Management{MSPID: "BMsp", CertificateSHA256: fpB}

	// Nil DB -> STATE_UNAVAILABLE on Accept and Operation.
	svcNoBackend := NewService(nil, strings.Repeat("1", 64), preg.Management{}, nil)
	assert.False(t, svcNoBackend.HasBackend())

	_, err := svcNoBackend.Accept(ctx, "k1", callerA, "RotateIdentity", json.RawMessage(`{}`), true)
	assert.True(t, protocol.HasCode(err, preg.ErrCodeStateUnavailable))

	_, err = svcNoBackend.Operation(ctx, callerA, "op-1")
	assert.True(t, protocol.HasCode(err, preg.ErrCodeStateUnavailable))

	// Fallback caller resolution (backend does not expose ManagementForFingerprint).
	got, ok := svcNoBackend.ResolveManagementCaller(fpA, "AMsp")
	assert.True(t, ok)
	assert.Equal(t, callerA, got)

	_, ok = svcNoBackend.ResolveManagementCaller("", "AMsp")
	assert.False(t, ok)
	_, ok = svcNoBackend.ResolveManagementCaller(fpA, "")
	assert.False(t, ok)

	// Resolver-backed caller resolution & auditor lookup.
	resolverBackend := &resolvingNoopBackend{
		bound: map[string]preg.Management{fpA: callerA},
	}
	svc := NewService(nil, strings.Repeat("1", 64), preg.Management{}, resolverBackend)
	assert.True(t, svc.HasBackend())
	svc.SetOperationAuditors([]preg.Management{auditorB})

	got, ok = svc.ResolveManagementCaller(fpA, "")
	assert.True(t, ok)
	assert.Equal(t, callerA, got)

	got, ok = svc.ResolveManagementCaller(fpB, "")
	assert.True(t, ok)
	assert.Equal(t, auditorB, got)

	_, ok = svc.ResolveManagementCaller(fpUnknown, "AMsp")
	assert.False(t, ok)

	assert.True(t, svc.IsOperationAuditor(fpB, "BMsp"))
	assert.False(t, svc.IsOperationAuditor(fpB, "AMsp"))
	assert.False(t, svc.IsOperationAuditor(fpA, "AMsp"))
	assert.False(t, svc.IsOperationAuditor("", "BMsp"))
}

type noopBackend struct{}

func (*noopBackend) CurrentRevision(context.Context, string, string) (uint64, bool, error) {
	return 0, false, nil
}

func (*noopBackend) SubmitAsync(
	context.Context,
	string, string,
	preg.Management,
	string,
	json.RawMessage,
	OutcomeHandler,
) {
}

type resolvingNoopBackend struct {
	noopBackend
	bound map[string]preg.Management
}

func (b *resolvingNoopBackend) ManagementForFingerprint(fp string) (preg.Management, bool) {
	m, ok := b.bound[fp]
	return m, ok
}
