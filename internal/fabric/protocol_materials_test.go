package fabric

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

func writeTestRoleCerts(t *testing.T, inst *instance) {
	t.Helper()
	now := time.Now().UTC()
	for _, r := range []string{"init", "T", "domainA", "registrarA", "IA", "U", "A1", "alt", "domainB", "registrarB", "IB", "B1", "domainC", "registrarC", "IC", "C"} {
		loc := roles[r]
		user := loc.user + "@" + loc.org + ".local"
		certPath := filepath.Join(inst.orgDir(loc.org), "users", user, "msp", "signcerts", user+"-cert.pem")
		if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
			t.Fatal(err)
		}
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: user},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBootstrapAndSeedProtocolMaterialsOffline(t *testing.T) {
	dir := t.TempDir()
	inst := &instance{dir: dir, env: map[string]string{}}
	writeTestRoleCerts(t, inst)

	genesis := &block{}
	genesis.Hash = api.Digest([]byte("test-genesis-block"))

	boot, bootRaw, err := inst.bootstrap(genesis)
	if err != nil {
		t.Fatalf("bootstrap failed: %v", err)
	}
	if boot.Root.DID != "did:web:t.local" || boot.Root.KeyID != "did:web:t.local#key-1" || boot.Root.KeyVersion != 1 {
		t.Fatalf("unexpected boot.Root: %+v", boot.Root)
	}

	// Idempotent resume must reuse persisted keys and match bootstrap.json.
	boot2, _, err := inst.bootstrap(genesis)
	if err != nil {
		t.Fatalf("resumed bootstrap failed: %v", err)
	}
	if boot2.Root != boot.Root {
		t.Fatalf("resumed bootstrap changed RootRecord")
	}

	// Check T private key permissions (0600) and location under <instance>/private/.
	info, err := os.Stat(inst.privatePath("app", "T.key.pem"))
	if err != nil {
		t.Fatalf("missing persisted T key: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 private key permissions, got %v", info.Mode().Perm())
	}

	dep := &deployment{
		DeploymentFields: boot.DeploymentFields,
		DeploymentID:     api.Digest(bootRaw),
		Bootstrap:        boot,
	}
	f, err := inst.fixtures(dep)
	if err != nil {
		t.Fatalf("fixtures failed: %v", err)
	}
	if f.Synthetic || f.SchemaVersion != protocol.SchemaVersion {
		t.Fatalf("expected verifiable non-synthetic fixtures")
	}
	if f.Task.Digest != "430541fe288ebcb3eaadbc6ba54765d45e4e56a1131148ff57a5e42c26e7c6ba" {
		t.Fatalf("unexpected taskSpecDigest: %s", f.Task.Digest)
	}

	// Registry directory must contain ZERO private key material.
	scanned, err := scanDirForPrivateKeys(filepath.Join(dir, "registry"))
	if err != nil {
		t.Fatalf("scanDirForPrivateKeys failed on clean registry: %v", err)
	}
	if len(scanned) < 20 {
		t.Fatalf("expected full set of public protocol files in registry, got %d", len(scanned))
	}

	// Leaked private key detection negative test.
	leakPath := filepath.Join(t.TempDir(), "leaked.pem")
	if err := os.WriteFile(leakPath, []byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := scanDirForPrivateKeys(filepath.Dir(leakPath)); err == nil || !strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("expected scanDirForPrivateKeys to reject leaked key PEM, got %v", err)
	}

	// Verify assembled evidence-sample.json against started controlled DIDWebServer and matching SnapshotView.
	srv, resolver, err := inst.startControlledDIDResolver()
	if err != nil {
		t.Fatalf("startControlledDIDResolver: %v", err)
	}
	defer srv.Close()

	tDocRaw, err := os.ReadFile(inst.registrySubPath(didRelPath(boot.Root.DID)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.RegisterPreseed(protocol.RootPreseed{
		DID:               boot.Root.DID,
		KeyID:             boot.Root.KeyID,
		KeyVersion:        boot.Root.KeyVersion,
		PublicKeyHex:      boot.Root.PublicKey,
		DIDDocumentDigest: boot.Root.DocumentDigest,
		RawDocument:       tDocRaw,
	}); err != nil {
		t.Fatal(err)
	}

	sampleRaw, err := os.ReadFile(inst.registrySubPath("evidence-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sample EvidenceSample
	if err := protocol.DecodeStrictJSON(sampleRaw, &sample); err != nil {
		t.Fatal(err)
	}

	snap := &protocol.SnapshotView{
		Height:         1,
		Now:            time.Now().UTC(),
		ClockError:     api.ClockError,
		DeploymentID:   dep.DeploymentID,
		Root:           boot.Root,
		Domains:        make(map[string]api.Domain),
		Certifications: make(map[string]api.Certification),
		Identities:     make(map[string]api.Identity),
		Credentials:    make(map[string]api.Credential),
		Tasks:          map[string]api.Task{f.Task.ID: activateTask(f.Task)},
		Grants: map[string]api.Grant{
			f.G0.ID: activateGrant(f.G0),
			f.G1.ID: activateGrant(f.G1),
		},
	}
	for domID, db := range f.Domains {
		d := db.Domain
		d.Issuers = []string{db.Issuers[0].ID}
		d.Certification = f.Certifications[domID].Certification.ID
		d.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Domains[domID] = d

		c := f.Certifications[domID].Certification
		c.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Certifications[c.ID] = c

		di := db.Identity
		di.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Identities[di.ID] = di

		ii := db.Issuers[0]
		ii.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Identities[ii.ID] = ii
	}
	for role, id := range f.Identities {
		id.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Identities[id.ID] = id
		cred := f.Credentials[role]
		cred.Version = api.Version{Status: api.Active, Revision: 1}
		snap.Credentials[cred.ID] = cred
	}

	res, err := protocol.VerifyAccessEvidencePackage(context.Background(), &sample.Package, snap, resolver, protocol.ChallengeContext{
		ChallengeID: sample.ChallengeID,
		Nonce:       sample.Nonce,
		Audience:    sample.Audience,
		IssuedAt:    sample.IssuedAt,
		ExpiresAt:   sample.ExpiresAt,
	})
	if err != nil {
		t.Fatalf("VerifyAccessEvidencePackage on offline seeded fixtures failed: %v", err)
	}
	if res.Bindings.EvidenceHash != sample.Bindings.EvidenceHash {
		t.Fatalf("evidenceHash mismatch")
	}

	// Verify legacy synthetic bootstrap is rejected.
	legacyDir := t.TempDir()
	legacyInst := &instance{dir: legacyDir, env: map[string]string{}}
	if err := os.MkdirAll(filepath.Join(legacyDir, "registry"), 0755); err != nil {
		t.Fatal(err)
	}
	legacyBoot := `{"channelId":"procurement","genesisHash":"` + genesis.Hash + `","instanceId":"` + strings.Repeat("a", 64) + `","registryName":"authregistry","schemaVersion":"grad-auth-v1","root":{"did":"did:web:t.local","appKeyId":"did:web:t.local#auth","appKeyVersion":1}}`
	if err := os.WriteFile(filepath.Join(legacyDir, "registry", "bootstrap.json"), []byte(legacyBoot), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := legacyInst.bootstrap(genesis); err == nil || !strings.Contains(err.Error(), "legacy synthetic bootstrap") {
		t.Fatalf("expected legacy synthetic bootstrap rejection, got %v", err)
	}
}

func activateTask(t api.Task) api.Task {
	t.Version = api.Version{Status: api.Active, Revision: 1}
	return t
}

func activateGrant(g api.Grant) api.Grant {
	g.Version = api.Version{Status: api.Active, Revision: 1}
	return g
}
