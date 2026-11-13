package fabric

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"graduation-design/internal/protocol"
)

// EvidenceSample bundles a seeded verifiable AccessEvidencePackage alongside the challenge context
// under which its KB-JWT was minted.
type EvidenceSample struct {
	ChallengeID string                         `json:"challengeId"`
	Nonce       string                         `json:"nonce"`
	Audience    string                         `json:"audience"`
	IssuedAt    int64                          `json:"issuedAt"`
	ExpiresAt   int64                          `json:"expiresAt"`
	Bindings    protocol.PackageBindings       `json:"bindings"`
	Package     protocol.AccessEvidencePackage `json:"package"`
}

func (i *instance) privatePath(parts ...string) string {
	return filepath.Join(append([]string{i.dir, "private"}, parts...)...)
}

func (i *instance) registrySubPath(parts ...string) string {
	return filepath.Join(append([]string{i.dir, "registry"}, parts...)...)
}

func writePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return writeFile(path, data, 0600)
}

func writePublicFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeFile(path, data, 0644)
}

func writePublicJSON(path string, value any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return err
	}
	return writePublicFile(path, buf.Bytes())
}

func didSlug(did string) string {
	rest := strings.TrimPrefix(did, "did:web:")
	return strings.ReplaceAll(rest, ":", "_")
}

func didRelPath(did string) string {
	return filepath.Join("did", didSlug(did)+".did.json")
}

func saveECPrivateKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return writePrivateFile(path, pemBytes)
}

func loadECPrivateKeyPEM(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("invalid EC private key PEM at %s", path)
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		if key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("expected P-256 key at %s", path)
		}
		return key, nil
	}
	pkcs8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := pkcs8.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("expected P-256 PKCS8 key at %s", path)
	}
	return key, nil
}

// ensureAppKey loads or generates a persisted P-256 keypair in <instance>/private/app/<role>.key.pem
// and its corresponding public DID document in <instance>/registry/did/<slug>.did.json.
func (i *instance) ensureAppKey(role, did, keyID string, purposes ...string) (*ecdsa.PrivateKey, string, string, []byte, error) {
	keyPath := i.privatePath("app", role+".key.pem")
	docPath := i.registrySubPath(didRelPath(did))

	keyBytes, keyErr := os.ReadFile(keyPath)
	docBytes, docErr := os.ReadFile(docPath)
	if keyErr == nil && docErr == nil {
		priv, err := loadECPrivateKeyPEM(keyPath)
		if err != nil {
			return nil, "", "", nil, err
		}
		doc, digest, err := protocol.ParseDIDDocument(docBytes)
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("invalid persisted DID doc for %s: %w", did, err)
		}
		pubHex, err := protocol.EncodeAppPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, "", "", nil, err
		}
		if doc.ID != did {
			return nil, "", "", nil, fmt.Errorf("persisted DID doc %s id %q != %q", docPath, doc.ID, did)
		}
		for _, p := range purposes {
			if _, _, err := doc.ResolveKey(keyID, p, pubHex); err != nil {
				return nil, "", "", nil, fmt.Errorf("persisted DID doc %s key mismatch: %w", docPath, err)
			}
		}
		return priv, pubHex, digest, docBytes, nil
	}
	if len(keyBytes) > 0 && os.IsNotExist(docErr) {
		return nil, "", "", nil, fmt.Errorf("private app key exists at %s without public DID doc at %s", keyPath, docPath)
	}
	if len(docBytes) > 0 && os.IsNotExist(keyErr) {
		return nil, "", "", nil, fmt.Errorf("public DID doc exists at %s without private key at %s", docPath, keyPath)
	}

	priv, pubHex, err := protocol.GenerateP256KeyPair()
	if err != nil {
		return nil, "", "", nil, err
	}
	doc, err := protocol.NewDIDDocument(did, keyID, pubHex, purposes...)
	if err != nil {
		return nil, "", "", nil, err
	}
	rawDoc, err := protocol.MarshalJCS(doc)
	if err != nil {
		return nil, "", "", nil, err
	}
	digest, err := doc.Digest()
	if err != nil {
		return nil, "", "", nil, err
	}
	if err := saveECPrivateKeyPEM(keyPath, priv); err != nil {
		return nil, "", "", nil, err
	}
	if err := writePublicFile(docPath, rawDoc); err != nil {
		return nil, "", "", nil, err
	}
	return priv, pubHex, digest, rawDoc, nil
}

// ensureTestCAAndHostCerts generates or reloads the offline test CA and host TLS server certificates
// for t.local, a.local, b.local, and c.local. Private keys stay solely under <instance>/private/tls/.
func (i *instance) ensureTestCAAndHostCerts(now time.Time) (*x509.CertPool, map[string]*protocol.HostTLSCert, error) {
	caKeyPath := i.privatePath("tls", "root-ca.key.pem")
	caCertPath := i.registrySubPath("ca", "root-ca.pem")

	allPresent := true
	for _, p := range []string{caKeyPath, caCertPath} {
		if _, err := os.Stat(p); err != nil {
			allPresent = false
			break
		}
	}
	if allPresent {
		for _, host := range protocol.ControlledTestDomains {
			if _, err := os.Stat(i.privatePath("tls", host+".key.pem")); err != nil {
				allPresent = false
				break
			}
			if _, err := os.Stat(i.registrySubPath("tls", host+".cert.pem")); err != nil {
				allPresent = false
				break
			}
		}
	}
	if allPresent {
		return i.loadTestCAAndHostCerts()
	}

	ca, err := protocol.GenerateTestCA(now)
	if err != nil {
		return nil, nil, err
	}
	if err := saveECPrivateKeyPEM(caKeyPath, ca.Key); err != nil {
		return nil, nil, err
	}
	if err := writePublicFile(caCertPath, ca.CertPEM); err != nil {
		return nil, nil, err
	}

	certs := make(map[string]*protocol.HostTLSCert, len(protocol.ControlledTestDomains))
	for _, host := range protocol.ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		if err != nil {
			return nil, nil, err
		}
		if err := writePrivateFile(i.privatePath("tls", host+".key.pem"), hc.KeyPEM); err != nil {
			return nil, nil, err
		}
		if err := writePublicFile(i.registrySubPath("tls", host+".cert.pem"), hc.CertPEM); err != nil {
			return nil, nil, err
		}
		certs[host] = hc
	}
	pool, err := protocol.ParseTestCAPublic(ca.CertPEM)
	if err != nil {
		return nil, nil, err
	}
	return pool, certs, nil
}

func (i *instance) loadTestCAAndHostCerts() (*x509.CertPool, map[string]*protocol.HostTLSCert, error) {
	caCertPEM, err := os.ReadFile(i.registrySubPath("ca", "root-ca.pem"))
	if err != nil {
		return nil, nil, err
	}
	pool, err := protocol.ParseTestCAPublic(caCertPEM)
	if err != nil {
		return nil, nil, err
	}
	certs := make(map[string]*protocol.HostTLSCert, len(protocol.ControlledTestDomains))
	for _, host := range protocol.ControlledTestDomains {
		certPEM, err := os.ReadFile(i.registrySubPath("tls", host+".cert.pem"))
		if err != nil {
			return nil, nil, err
		}
		keyPEM, err := os.ReadFile(i.privatePath("tls", host+".key.pem"))
		if err != nil {
			return nil, nil, err
		}
		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("host %s TLS keypair mismatch: %w", host, err)
		}
		certs[host] = &protocol.HostTLSCert{
			Host:    host,
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
			TLSCert: tlsCert,
		}
	}
	return pool, certs, nil
}

// ensureContextManifest writes and verifies the offline pinned W3C VC v2 base context copy and manifest.
func (i *instance) ensureContextManifest() (protocol.ContextManifestEntry, error) {
	rawCtx, _, manifest, err := protocol.LocalVCv2Context()
	if err != nil {
		return protocol.ContextManifestEntry{}, err
	}
	if err := writePublicFile(i.registrySubPath("vc-v2.context.json"), rawCtx); err != nil {
		return protocol.ContextManifestEntry{}, err
	}
	manifestBytes, err := protocol.MarshalJCS(manifest)
	if err != nil {
		return protocol.ContextManifestEntry{}, err
	}
	if err := writePublicFile(i.registrySubPath("context-manifest.json"), append(manifestBytes, '\n')); err != nil {
		return protocol.ContextManifestEntry{}, err
	}
	return manifest, nil
}

type bootstrapProtocolMaterials struct {
	RootPubHex    string
	RootDIDDigest string
	RootDIDRaw    []byte
	Manifest      protocol.ContextManifestEntry
}

func (i *instance) ensureBootstrapProtocolMaterials(now time.Time) (*bootstrapProtocolMaterials, error) {
	if _, _, err := i.ensureTestCAAndHostCerts(now); err != nil {
		return nil, err
	}
	manifest, err := i.ensureContextManifest()
	if err != nil {
		return nil, err
	}
	_, pubT, digT, rawT, err := i.ensureAppKey("T", "did:web:t.local", "did:web:t.local#key-1", protocol.KeyPurposeAssertionMethod)
	if err != nil {
		return nil, err
	}
	if err := i.updateDIDIndex(map[string]string{"did:web:t.local": didRelPath("did:web:t.local")}); err != nil {
		return nil, err
	}
	return &bootstrapProtocolMaterials{
		RootPubHex:    pubT,
		RootDIDDigest: digT,
		RootDIDRaw:    rawT,
		Manifest:      manifest,
	}, nil
}

func (i *instance) updateDIDIndex(entries map[string]string) error {
	indexPath := i.registrySubPath("did", "index.json")
	current := map[string]string{}
	if b, err := os.ReadFile(indexPath); err == nil {
		if err := protocol.DecodeStrictJSON(b, &current); err != nil {
			current = map[string]string{}
		}
	}
	for k, v := range entries {
		current[k] = v
	}
	return writePublicJSON(indexPath, current)
}

func (i *instance) loadAllDIDDocs() (map[string][]byte, error) {
	var index map[string]string
	indexBytes, err := os.ReadFile(i.registrySubPath("did", "index.json"))
	if err != nil {
		return nil, err
	}
	if err := protocol.DecodeStrictJSON(indexBytes, &index); err != nil {
		return nil, err
	}
	docs := make(map[string][]byte, len(index))
	for did, rel := range index {
		if !strings.HasPrefix(rel, "did"+string(filepath.Separator)) && !strings.HasPrefix(rel, "did/") {
			return nil, fmt.Errorf("invalid relative DID path %q in index", rel)
		}
		raw, err := os.ReadFile(i.registrySubPath(rel))
		if err != nil {
			return nil, err
		}
		docs[did] = raw
	}
	return docs, nil
}

func (i *instance) startControlledDIDResolver() (*protocol.DIDWebServer, *protocol.DIDWebResolver, error) {
	caPool, certs, err := i.loadTestCAAndHostCerts()
	if err != nil {
		return nil, nil, err
	}
	docs, err := i.loadAllDIDDocs()
	if err != nil {
		return nil, nil, err
	}
	srv, err := protocol.NewDIDWebServer(certs, docs)
	if err != nil {
		return nil, nil, err
	}
	resolver, err := protocol.NewDIDWebResolver(caPool, srv.Routes())
	if err != nil {
		_ = srv.Close()
		return nil, nil, err
	}
	return srv, resolver, nil
}

func collectRegistryPublicFiles(registryDir string) (map[string]string, error) {
	out := make(map[string]string)
	prefixes := []string{"ca", "tls", "did", "certifications", "credentials", "grants"}
	for _, sub := range prefixes {
		root := filepath.Join(registryDir, sub)
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(registryDir, p)
			if err != nil {
				return err
			}
			// Never include any private key artifacts under any circumstance.
			if sub == "tls" && !strings.HasSuffix(d.Name(), ".cert.pem") {
				return fmt.Errorf("unexpected non-cert file %q in registry/tls", rel)
			}
			out[rel] = p
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for _, single := range []string{"vc-v2.context.json", "context-manifest.json", "taskspec.json", "evidence-sample.json", "fixtures.json", "seed.json"} {
		p := filepath.Join(registryDir, single)
		if _, err := os.Stat(p); err == nil {
			out[single] = p
		}
	}
	return out, nil
}

// scanDirForPrivateKeys fails if any file path or file contents in root contain private key material.
func scanDirForPrivateKeys(root string) ([]string, error) {
	var scanned []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		lower := strings.ToLower(rel)
		if strings.HasSuffix(lower, ".key") || strings.Contains(lower, ".key.") || strings.Contains(lower, "keystore") || strings.Contains(lower, "private") {
			return fmt.Errorf("forbidden private key filename in public evidence: %s", rel)
		}
		scanned = append(scanned, rel)
		if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".pb") {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, []byte("EC PRIVATE KEY")) {
			return fmt.Errorf("forbidden PRIVATE KEY PEM content in public evidence: %s", rel)
		}
		return nil
	})
	sort.Strings(scanned)
	return scanned, err
}
