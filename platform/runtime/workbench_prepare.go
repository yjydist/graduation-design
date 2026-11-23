package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"grad/platform/state/fabric"
	"grad/platform/workbench"
	"grad/protocol"
	"grad/protocol/registry"
)

const workbenchBService = "did:web:b.local:pa"
const workbenchA1 = "did:web:a.local:a1"
const workbenchB1 = "did:web:b.local:b1"

type workbenchConfig struct {
	DomainID     string                    `json:"domainId"`
	DeploymentID string                    `json:"deploymentId"`
	FabricDir    string                    `json:"fabricDir"`
	BrowserAddr  string                    `json:"browserAddr"`
	InternalAddr string                    `json:"internalAddr"`
	DatabaseHost string                    `json:"databaseHost"`
	Peers        map[string]workbenchPeer  `json:"peers"`
	Accounts     []workbenchAccount        `json:"accounts"`
	Actors       map[string]workbenchActor `json:"actors"`
}

type workbenchPeer struct {
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
}

type workbenchActor struct {
	DID          string `json:"did"`
	CredentialID string `json:"credentialId"`
}

type workbenchAccount struct {
	Username     string         `json:"username"`
	Role         workbench.Role `json:"role"`
	Subject      string         `json:"subjectId"`
	FabricRole   string         `json:"fabricRole"`
	PasswordFile string         `json:"passwordFile"`
}

func workbenchLocalRoles(domain string) []string {
	switch domain {
	case "A":
		return []string{"domainA", "U", "PA", "A1"}
	case "B":
		return []string{"domainB", "B1"}
	case "C":
		return []string{"domainC", "C", "read", "probe1"}
	default:
		return nil
	}
}

func workbenchLocalActors(domain string) []string {
	switch domain {
	case "A":
		return []string{"U", "PA", "A1"}
	case "B":
		return []string{"B1"}
	case "C":
		return []string{"C"}
	default:
		return nil
	}
}

func workbenchAccountNames(domain string) []workbenchAccount {
	admin := workbenchAccount{
		Username: "admin", Role: workbench.RoleAdmin, Subject: "did:web:" + strings.ToLower(domain) + ".local",
		FabricRole: "domain" + domain, PasswordFile: "admin-password",
	}
	switch domain {
	case "A":
		return []workbenchAccount{admin, {Username: "u", Role: workbench.RoleBuyer, Subject: fabric.SubjectU, FabricRole: "U", PasswordFile: "buyer-password"}}
	case "C":
		auditor := admin
		auditor.Username, auditor.Role, auditor.PasswordFile = "auditor", workbench.RoleAuditor, "auditor-password"
		return []workbenchAccount{admin, auditor}
	default:
		return []workbenchAccount{admin}
	}
}

// PrepareWorkbench provisions isolated demo mounts from a dedicated, already seeded Fabric instance.
func PrepareWorkbench(ctx context.Context, fabricPath, output string) error {
	inst, err := fabric.OpenInstance(fabricPath)
	if err != nil {
		return err
	}
	dep, err := inst.LoadDeployment()
	if err != nil {
		return err
	}
	fixtures, err := LoadFixtures(inst)
	if err != nil {
		return err
	}
	if err := ensureWorkbenchBService(ctx, inst, dep); err != nil {
		return err
	}
	if err := os.Mkdir(output, 0o700); err != nil {
		return err
	}
	ca, err := protocol.GenerateTestCA(time.Now())
	if err != nil {
		return err
	}
	peers := make(map[string]workbenchPeer, 3)
	for _, domain := range []string{"A", "B", "C"} {
		dir := filepath.Join(output, strings.ToLower(domain))
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
		peer, err := prepareWorkbenchTLS(ca, dir, domain)
		if err != nil {
			return err
		}
		peers[domain] = peer
	}
	for _, domain := range []string{"A", "B", "C"} {
		dir := filepath.Join(output, strings.ToLower(domain))
		if err := prepareWorkbenchDomain(inst, dep, fixtures, dir, domain, peers); err != nil {
			return err
		}
	}
	return nil
}

func ensureWorkbenchBService(ctx context.Context, inst *fabric.Instance, dep *fabric.Deployment) error {
	reader, err := inst.ForDomain("B", "domainB", "")
	if err != nil {
		return err
	}
	peer, err := reader.ReadPeer()
	if err != nil {
		return err
	}
	defer peer.Close()
	if err := dep.ValidatePeer(ctx, peer); err != nil {
		return err
	}
	existing, err := fabric.ReadLedgerRecord[registry.Identity](ctx, peer, "identity", workbenchBService)
	if err == nil {
		if existing.Domain != "B" || existing.Kind != "SERVICE" || existing.Status != registry.Active {
			return fmt.Errorf("configured B purchasing authority is ineligible")
		}
		return nil
	}
	if !fabric.IsMissingRecord(err) {
		return err
	}
	_, mgmt, _, err := inst.Role("wrongB")
	if err != nil {
		return err
	}
	key := workbenchBService + "#key-1"
	_, public, document, _, err := inst.EnsureAppKey("workbench-pa-b", workbenchBService, key, protocol.KeyPurposeAuthentication, protocol.KeyPurposeAssertionMethod)
	if err != nil {
		return err
	}
	if err := inst.UpdateDIDIndex(map[string]string{workbenchBService: fabric.DIDRelPath(workbenchBService)}); err != nil {
		return err
	}
	db, err := inst.Database(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	identity := registry.Identity{
		Bound: registry.Bound{DeploymentID: dep.DeploymentID}, ID: workbenchBService, Domain: "B", Kind: "SERVICE",
		Management: mgmt, DocumentDigest: document, KeyID: key, KeyVersion: 1, PublicKey: public,
		AccountCommitment: registry.Digest([]byte(dep.DeploymentID + "/" + workbenchBService)),
	}
	body, err := protocol.MarshalJCS(identity)
	if err != nil {
		return err
	}
	op, err := fabric.NewJournal(reader, db, dep.DeploymentID).Write(ctx, "workbench/provision/pa-b", "registrarB", "RegisterIdentity", body)
	if err != nil {
		return err
	}
	if err := fabric.ExpectOperation(op, "VALID"); err != nil {
		return err
	}
	return inst.AwaitEndorsers(ctx, *op.Commit)
}

func workbenchTransportRole(domain string) (string, string) {
	switch domain {
	case "B":
		return "B_RECOVERY", defaultRecoveryDID
	case "C":
		return "C_AUDIT_SERVICE", defaultAuditSvcDID
	default:
		return "WORKBENCH_A", "did:web:a.local:services:workbench"
	}
}

func prepareWorkbenchTLS(ca *protocol.TestCA, dir, domain string) (workbenchPeer, error) {
	org := strings.ToLower(domain)
	name := "workbench-" + org
	role, did := workbenchTransportRole(domain)
	didURL, err := url.Parse(did)
	if err != nil {
		return workbenchPeer{}, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return workbenchPeer{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return workbenchPeer{}, err
	}
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name, OrganizationalUnit: []string{role}},
		DNSNames: []string{name, org + ".local", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		URIs: []*url.URL{didURL}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca.Cert, &priv.PublicKey, ca.Key)
	if err != nil {
		return workbenchPeer{}, err
	}
	key, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return workbenchPeer{}, err
	}
	for _, file := range []struct {
		name string
		raw  []byte
	}{
		{"internal.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})},
		{"internal.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key})},
		{"internal-ca.crt", ca.CertPEM},
	} {
		if err := fabric.WritePrivateFile(filepath.Join(dir, file.name), file.raw); err != nil {
			return workbenchPeer{}, err
		}
	}
	return workbenchPeer{URL: "https://" + name + ":8081", Fingerprint: registry.Digest(der)}, nil
}

func prepareWorkbenchDomain(inst *fabric.Instance, dep *fabric.Deployment, fixtures *Fixtures, dir, domain string, peers map[string]workbenchPeer) error {
	cfg := workbenchConfig{
		DomainID: domain, DeploymentID: dep.DeploymentID, FabricDir: "fabric", BrowserAddr: ":8080", InternalAddr: ":8081",
		DatabaseHost: "127.0.0.1:5432", Peers: peers, Accounts: workbenchAccountNames(domain),
		Actors: make(map[string]workbenchActor),
	}
	for _, actor := range []string{"U", "PA", "A1", "B1", "C"} {
		cfg.Actors[actor] = workbenchActor{DID: fixtures.Identities[actor].ID, CredentialID: fixtures.Credentials[actor].ID}
	}
	for _, role := range workbenchLocalRoles(domain) {
		_, binding, path, err := inst.Role(role)
		if err != nil {
			return err
		}
		if binding.MSPID != domain+"Msp" {
			return fmt.Errorf("non-local provisioning signer")
		}
		if err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if !d.Type().IsRegular() {
				return fmt.Errorf("unexpected file type in Fabric enrollment")
			}
			return copyWorkbenchFile(inst.Dir(), filepath.Join(dir, cfg.FabricDir), path)
		}); err != nil {
			return err
		}
	}
	files := []string{
		filepath.Join(inst.Dir(), "network.env"),
		inst.PeerTLS(strings.ToLower(domain)),
		inst.RegistryPath("deployment.json"),
		inst.RegistryPath("did", "index.json"),
	}
	docs, err := inst.LoadAllDIDDocs()
	if err != nil {
		return err
	}
	for did := range docs {
		files = append(files, inst.RegistryPath(fabric.DIDRelPath(did)))
	}
	for _, dom := range []string{"A", "B", "C"} {
		files = append(files, inst.RegistryPath("certifications", dom+".jws"))
	}
	for _, actor := range workbenchLocalActors(domain) {
		files = append(files, inst.PrivatePath("app", actor+".key.pem"), inst.RegistryPath("credentials", actor+".sdjwt"))
	}
	for _, path := range files {
		if err := copyWorkbenchFile(inst.Dir(), filepath.Join(dir, cfg.FabricDir), path); err != nil {
			return err
		}
	}
	passwords := []string{"postgres-password"}
	for _, acct := range cfg.Accounts {
		passwords = append(passwords, acct.PasswordFile)
	}
	for _, name := range passwords {
		var random [24]byte
		if _, err := rand.Read(random[:]); err != nil {
			return err
		}
		if err := fabric.WritePrivateFile(filepath.Join(dir, name), []byte(hex.EncodeToString(random[:])+"\n")); err != nil {
			return err
		}
	}
	return fabric.WriteJSON(filepath.Join(dir, "config.json"), cfg)
}

func copyWorkbenchFile(sourceRoot, targetRoot, source string) error {
	rel, err := filepath.Rel(sourceRoot, source)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return fabric.WritePrivateFile(filepath.Join(targetRoot, rel), raw)
}
