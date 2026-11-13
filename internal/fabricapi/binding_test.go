package fabricapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
)

func TestPublishedFabricBindings(t *testing.T) {
	data, err := os.ReadFile("../../docs/implementation/协议编码与测试向量.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(data), "## 4 部署绑定与管理证明")
	_, body, fence := strings.Cut(section, "```json\n")
	raw, _, end := strings.Cut(body, "\n```")
	if !found || !fence || !end {
		t.Fatal("published Fabric binding vector missing")
	}
	var v struct {
		Deployment               DeploymentFields
		DeploymentID             string
		Challenge                map[string]any
		ChallengeSHA256          string
		ManagementCertificateDER string
		ManagementSignatureDER   string
		AppJWSProtected          string
		AppJWSSignature          string
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	if v.Deployment.ID() != v.DeploymentID || v.Challenge["deploymentId"] != v.DeploymentID {
		t.Fatal("deployment digest mismatch")
	}
	b64 := func(s string) []byte {
		t.Helper()
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cert, err := x509.ParseCertificate(b64(v.ManagementCertificateDER))
	if err != nil {
		t.Fatal(err)
	}
	mgmt, ok := cert.PublicKey.(*ecdsa.PublicKey)
	binding := v.Challenge["managementIdentity"].(map[string]any)
	if !ok || binding["mspId"] != "AMsp" || binding["certificateSha256"] != Digest(cert.Raw) {
		t.Fatal("certificate binding mismatch")
	}
	sec1, err := hex.DecodeString(v.Challenge["appPublicKey"].(string))
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), sec1)
	app := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	sig := b64(v.AppJWSSignature)
	if x == nil || mgmt.Equal(app) || len(sig) != 64 {
		t.Fatal("invalid distinct application key or ES256 signature")
	}
	canonical := func() []byte {
		t.Helper()
		raw, err := json.Marshal(v.Challenge)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	verify := func(c []byte) (bool, bool) {
		hash := sha256.Sum256(c)
		appHash := sha256.Sum256([]byte(v.AppJWSProtected + "." + base64.RawURLEncoding.EncodeToString(c)))
		return ecdsa.VerifyASN1(mgmt, hash[:], b64(v.ManagementSignatureDER)),
			ecdsa.Verify(app, appHash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
	validManagement, validApp := verify(canonical())
	if !validManagement || !validApp || Digest(canonical()) != v.ChallengeSHA256 {
		t.Fatal("challenge proof mismatch")
	}
	for _, field := range []string{"deploymentId", "nonce"} {
		old := v.Challenge[field]
		v.Challenge[field] = "changed"
		if management, app := verify(canonical()); management || app {
			t.Fatalf("changed %s retained a valid proof", field)
		}
		v.Challenge[field] = old
	}
}
