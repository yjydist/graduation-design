package fabric

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	gw "github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	msp "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	lb "github.com/hyperledger/fabric-protos-go-apiv2/peer/lifecycle"
	"google.golang.org/protobuf/proto"
)

const (
	version         = "1.0"
	sequence        = 1
	signaturePolicy = "OutOf(2,'AMsp.peer','BMsp.peer','CMsp.peer')"
	subjectU        = "did:web:a.local:u"
	subjectC        = "did:web:c.local:supplier"
)

var errDeploymentMismatch = errors.New("DEPLOYMENT_MISMATCH")

type deployment struct {
	api.DeploymentFields
	DeploymentID     string            `json:"deploymentId"`
	ConfigDigest     string            `json:"channelConfigSha256"`
	BootstrapDigest  string            `json:"bootstrapSha256"`
	BuildDigest      string            `json:"chaincodeBuildSha256"`
	SourceDigest     string            `json:"chaincodeSourceSha256"`
	PackageIDs       map[string]string `json:"packageIds"`
	DefinitionDigest string            `json:"definitionSha256"`
	DefinitionBlock  point             `json:"definitionBlock"`
	DefinitionTxID   string            `json:"definitionTxId"`
	InitBlock        point             `json:"initializationBlock"`
	Bootstrap        api.Bootstrap     `json:"bootstrap"`
}

type registryApproval struct {
	DeploymentID    string           `json:"deploymentId"`
	BootstrapDigest string           `json:"bootstrapSha256"`
	BuildDigest     string           `json:"buildSha256"`
	SourceDigest    string           `json:"sourceSha256"`
	Initializer     api.Management   `json:"initializer"`
	Probes          []api.Management `json:"probes"`
}

func (i *instance) registryPath(name string) string { return filepath.Join(i.dir, "registry", name) }

func digestBytes(b []byte) []byte {
	d := sha256.Sum256(b)
	return d[:]
}

func readBlockFile(path string) (*block, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeBlock(b)
}

func randomID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func publicKey() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	point, err := key.PublicKey.Bytes()
	return hex.EncodeToString(point), err
}

func (i *instance) bootstrap(genesis *block) (api.Bootstrap, []byte, error) {
	var boot api.Bootstrap
	path := i.registryPath("bootstrap.json")
	if data, err := os.ReadFile(path); err == nil {
		err = json.Unmarshal(data, &boot)
		if err == nil && boot.GenesisHash != genesis.Hash {
			err = fmt.Errorf("bootstrap genesis hash mismatch")
		}
		return boot, data, err
	} else if !os.IsNotExist(err) {
		return boot, nil, err
	}
	key, err := publicKey()
	if err != nil {
		return boot, nil, err
	}
	bindings := map[string]api.Management{}
	for _, role := range []string{"init", "T", "U", "C"} {
		_, m, _, err := i.role(role)
		if err != nil {
			return boot, nil, err
		}
		bindings[role] = m
	}
	boot = api.Bootstrap{
		DeploymentFields: api.DeploymentFields{ChannelID: api.Channel, GenesisHash: genesis.Hash, InstanceID: randomID(), RegistryName: api.Registry, SchemaVersion: api.Schema},
		Root: api.RootRecord{
			DID: "did:web:t.local", Management: bindings["T"], DocumentDigest: api.Digest([]byte("synthetic root document " + key)),
			KeyID: "did:web:t.local#auth", KeyVersion: 1, PublicKey: key,
		},
		Initializer: bindings["init"],
		TaskCreator: api.TaskAuthority{Domain: "A", Subject: subjectU, Management: bindings["U"]},
		ResourceID:  api.Digest([]byte("resource:" + subjectC)), ResourceOwner: subjectC, ResourceManagement: bindings["C"],
	}
	data, err := json.Marshal(boot)
	if err != nil {
		return boot, nil, err
	}
	return boot, data, writeFile(path, data, 0600)
}

func (i *instance) build(ctx context.Context, d *deployment) error {
	_, p1, _, err := i.role("probe1")
	if err != nil {
		return err
	}
	_, p2, _, err := i.role("probe2")
	if err != nil {
		return err
	}
	sourceDigest, err := registrySourceDigest()
	if err != nil {
		return err
	}
	d.SourceDigest = sourceDigest
	binary := i.registryPath("registry")
	flags := fmt.Sprintf("-X main.bootstrapDigest=%s -X main.initializer=%s -X main.probeOne=%s -X main.probeTwo=%s",
		d.BootstrapDigest, d.Bootstrap.Initializer, p1, p2)
	cmd := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", flags, "-o", binary+".new", "./chaincode/registry")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build chaincode: %w: %s", err, out)
	}
	b, err := os.ReadFile(binary + ".new")
	if err != nil {
		return err
	}
	d.BuildDigest = api.Digest(b)
	if err := os.Rename(binary+".new", binary); err != nil {
		return err
	}
	approval, err := json.Marshal(registryApproval{
		DeploymentID: d.DeploymentID, BootstrapDigest: d.BootstrapDigest,
		BuildDigest: d.BuildDigest, SourceDigest: d.SourceDigest,
		Initializer: d.Bootstrap.Initializer, Probes: []api.Management{p1, p2},
	})
	if err != nil {
		return err
	}
	if err := writeFile(i.registryPath("approval.json"), approval, 0600); err != nil {
		return err
	}
	for _, org := range []string{"a", "b", "c"} {
		id, err := i.packageRegistry(ctx, org, approval)
		if err != nil {
			return err
		}
		d.PackageIDs[org] = id
	}
	return nil
}

// A committed definition keeps the build and packages approved by the three organizations.
func (i *instance) reuseApprovedBuild(d *deployment) error {
	raw, err := os.ReadFile(i.registryPath("approval.json"))
	if err != nil {
		return err
	}
	var approval registryApproval
	if err := json.Unmarshal(raw, &approval); err != nil {
		return err
	}
	if approval.DeploymentID != d.DeploymentID || approval.BootstrapDigest != d.BootstrapDigest ||
		approval.Initializer != d.Bootstrap.Initializer || !api.IsDigest(approval.SourceDigest) {
		return fmt.Errorf("%w: chaincode approval does not match the bootstrap", errDeploymentMismatch)
	}
	binary, err := os.ReadFile(i.registryPath("registry"))
	if err != nil {
		return err
	}
	if api.Digest(binary) != approval.BuildDigest {
		return fmt.Errorf("%w: chaincode binary does not match its approved build", errDeploymentMismatch)
	}
	for _, org := range []string{"a", "b", "c"} {
		dir := filepath.Join(i.dir, "cc-"+org)
		cert, err := os.ReadFile(filepath.Join(dir, "server.crt"))
		if err != nil {
			return err
		}
		id, expected, err := registryPackage(org, cert, raw)
		if err != nil {
			return err
		}
		stored, err := os.ReadFile(i.registryPath(org + ".tar.gz"))
		if err != nil {
			return err
		}
		storedID, err := os.ReadFile(filepath.Join(dir, "package-id"))
		if err != nil {
			return err
		}
		if !bytes.Equal(stored, expected) || strings.TrimSpace(string(storedID)) != id {
			return fmt.Errorf("%w: chaincode package for %s does not match its approval", errDeploymentMismatch, org)
		}
		d.PackageIDs[org] = id
	}
	d.BuildDigest, d.SourceDigest = approval.BuildDigest, approval.SourceDigest
	return nil
}

func registrySourceDigest() (string, error) {
	names := []string{"go.mod", "go.sum"}
	for _, glob := range []string{"chaincode/registry/*.go", "internal/fabricapi/*.go"} {
		found, err := filepath.Glob(glob)
		if err != nil {
			return "", err
		}
		for _, path := range found {
			if !strings.HasSuffix(path, "_test.go") {
				names = append(names, path)
			}
		}
	}
	slices.Sort(names)
	h := sha256.New()
	for _, name := range names {
		b, err := os.ReadFile(name)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s %s\n", name, api.Digest(b))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type packageFile struct {
	name string
	data []byte
}

func packageArchive(files ...packageFile) ([]byte, error) {
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0644, Size: int64(len(f.data))}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (i *instance) packageRegistry(ctx context.Context, org string, approval []byte) (string, error) {
	name := "cc-" + org
	dir := filepath.Join(i.dir, name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		cmd := exec.CommandContext(ctx, "openssl", "req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
			"-nodes", "-days", "365", "-subj", "/CN="+name, "-addext", "subjectAltName=DNS:"+name, "-keyout", keyPath, "-out", certPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("chaincode TLS: %w: %s", err, out)
		}
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	id, data, err := registryPackage(org, cert, approval)
	if err != nil {
		return "", err
	}
	if err := writeFile(i.registryPath(org+".tar.gz"), data, 0600); err != nil {
		return "", err
	}
	return id, writeFile(filepath.Join(dir, "package-id"), []byte(id+"\n"), 0600)
}

func registryPackage(org string, cert, approval []byte) (string, []byte, error) {
	conn, err := json.Marshal(map[string]any{
		"address": "cc-" + org + ":9999", "dial_timeout": "4s", "tls_required": true, "client_auth_required": false, "root_cert": string(cert),
	})
	if err != nil {
		return "", nil, err
	}
	code, err := packageArchive(packageFile{"connection.json", conn}, packageFile{"approval.json", approval})
	if err != nil {
		return "", nil, err
	}
	label := api.Registry + "_" + org + "_" + api.Digest(approval)[:12]
	meta, err := json.Marshal(map[string]string{"type": "ccaas", "label": label})
	if err != nil {
		return "", nil, err
	}
	data, err := packageArchive(packageFile{"metadata.json", meta}, packageFile{"code.tar.gz", code})
	if err != nil {
		return "", nil, err
	}
	return label + ":" + api.Digest(data), data, nil
}

func (p *peerClient) definition(ctx context.Context) (*lb.QueryChaincodeDefinitionResult, error) {
	b, err := proto.Marshal(&lb.QueryChaincodeDefinitionArgs{Name: api.Registry})
	if err != nil {
		return nil, err
	}
	data, err := p.direct(ctx, "_lifecycle", "QueryChaincodeDefinition", string(b))
	if err != nil {
		return nil, err
	}
	definition, err := decode(data, &lb.QueryChaincodeDefinitionResult{})
	if err != nil {
		return nil, fmt.Errorf("%w: invalid committed registry definition: %w", errDeploymentMismatch, err)
	}
	return definition, nil
}

func definitionHash(d *lb.QueryChaincodeDefinitionResult) (string, error) {
	if d.Sequence != sequence || d.Version != version || d.EndorsementPlugin != "escc" ||
		d.ValidationPlugin != "vscc" || d.InitRequired || len(d.GetCollections().GetConfig()) != 0 {
		return "", fmt.Errorf("unexpected chaincode definition")
	}
	policy, err := decode(d.ValidationParameter, &pb.ApplicationPolicy{})
	if err != nil {
		return "", err
	}
	sig := policy.GetSignaturePolicy()
	n := sig.GetRule().GetNOutOf()
	if n.GetN() != 2 || len(n.GetRules()) != 3 || len(sig.GetIdentities()) != 3 {
		return "", fmt.Errorf("unexpected chaincode endorsement threshold")
	}
	members := make([]string, 0, 3)
	for _, r := range n.Rules {
		idx, ok := r.Type.(*cb.SignaturePolicy_SignedBy)
		if !ok || idx.SignedBy < 0 || int(idx.SignedBy) >= len(sig.Identities) {
			return "", fmt.Errorf("unexpected endorsement policy principal")
		}
		principal := sig.Identities[idx.SignedBy]
		role, err := decode(principal.Principal, &msp.MSPRole{})
		if err != nil || principal.PrincipalClassification != msp.MSPPrincipal_ROLE || role.Role != msp.MSPRole_PEER {
			return "", fmt.Errorf("unexpected endorsement identity: %v", err)
		}
		members = append(members, role.MspIdentifier)
	}
	slices.Sort(members)
	if !slices.Equal(members, []string{"AMsp", "BMsp", "CMsp"}) {
		return "", fmt.Errorf("unexpected endorsement organizations %v", members)
	}
	// Approvals are peer-local information and may vary during startup.
	canonical := proto.CloneOf(d)
	canonical.Approvals = nil
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return api.Digest(raw), nil
}

func (i *instance) loadDeployment() (*deployment, error) {
	var d deployment
	if err := readJSON(i.registryPath("deployment.json"), &d); err != nil {
		return nil, err
	}
	if !d.DeploymentFields.Valid() || d.DeploymentID != d.ID() || d.Bootstrap.DeploymentFields != d.DeploymentFields ||
		len(d.PackageIDs) != 3 || !api.IsDigest(d.ConfigDigest) || !api.IsDigest(d.DefinitionDigest) ||
		!api.IsDigest(d.BootstrapDigest) || !api.IsDigest(d.DefinitionBlock.Hash) || !api.IsDigest(d.InitBlock.Hash) ||
		d.DefinitionBlock.Number >= d.InitBlock.Number || !api.IsDigest(d.DefinitionTxID) {
		return nil, fmt.Errorf("%w: malformed trusted deployment", errDeploymentMismatch)
	}
	for _, org := range []string{"a", "b", "c"} {
		label, sum, ok := strings.Cut(d.PackageIDs[org], ":")
		if !ok || label == "" || !api.IsDigest(sum) {
			return nil, fmt.Errorf("%w: missing package ID for %s", errDeploymentMismatch, org)
		}
	}
	return &d, nil
}

func (d *deployment) validatePeer(ctx context.Context, peer *peerClient) error {
	if !d.DeploymentFields.Valid() || d.ID() != d.DeploymentID || d.Bootstrap.DeploymentFields != d.DeploymentFields {
		return fmt.Errorf("%w: trusted deployment fields are inconsistent", errDeploymentMismatch)
	}
	genesis, err := peer.getBlock(ctx, 0)
	if errors.Is(err, errInvalidPeerBlock) {
		return fmt.Errorf("%w: Peer genesis: %w", errDeploymentMismatch, err)
	}
	if err != nil {
		return fmt.Errorf("read Peer genesis: %w", err)
	}
	if genesis.Hash != d.GenesisHash || genesis.ConfigDigest != d.ConfigDigest {
		return fmt.Errorf("%w: genesis/config does not match the trusted channel", errDeploymentMismatch)
	}
	cfg, err := peer.direct(ctx, "cscc", "GetConfigBlock", api.Channel)
	if err != nil {
		return fmt.Errorf("read active channel configuration: %w", err)
	}
	latestConfig, err := decodeBlock(cfg)
	if err != nil {
		return fmt.Errorf("%w: invalid active channel configuration: %w", errDeploymentMismatch, err)
	}
	if latestConfig.ConfigDigest != d.ConfigDigest {
		return fmt.Errorf("%w: active channel configuration changed", errDeploymentMismatch)
	}
	def, err := peer.definition(ctx)
	if err != nil {
		return fmt.Errorf("read committed registry definition: %w", err)
	}
	h, err := definitionHash(def)
	if err != nil {
		return fmt.Errorf("%w: invalid committed registry definition: %w", errDeploymentMismatch, err)
	}
	if h != d.DefinitionDigest {
		return fmt.Errorf("%w: committed registry definition changed", errDeploymentMismatch)
	}
	boot, err := peer.direct(ctx, api.Registry, "Read", api.BootstrapKey)
	if missingRegistryRecord(err) {
		return fmt.Errorf("%w: committed bootstrap record is missing", errDeploymentMismatch)
	}
	if err != nil {
		return fmt.Errorf("read committed bootstrap record: %w", err)
	}
	var b api.Bootstrap
	if err := json.Unmarshal(boot, &b); err != nil {
		return fmt.Errorf("%w: invalid committed bootstrap record: %w", errDeploymentMismatch, err)
	}
	if b != d.Bootstrap || api.Digest(boot) != d.BootstrapDigest {
		return fmt.Errorf("%w: immutable root, instance or qualification mismatch", errDeploymentMismatch)
	}
	return nil
}

func (i *instance) deploy(ctx context.Context, retryInitialization bool) (*deployment, error) {
	p, err := i.peer("c", "read")
	if err != nil {
		return nil, err
	}
	defer p.close()
	if d, err := i.loadDeployment(); err == nil {
		return d, d.validatePeer(ctx, p)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	pool, err := i.database(ctx)
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	if err := initSchema(ctx, pool, operationsSchema); err != nil {
		return nil, err
	}
	// Serialize build, approvals and manifest creation for the same instance.
	bootstrapJournal := journal{instance: i, deploymentID: "provision", db: pool}
	_, unlock, err := bootstrapJournal.lock(ctx, "provision")
	if err != nil {
		return nil, err
	}
	defer unlock()
	if d, err := i.loadDeployment(); err == nil {
		return d, d.validatePeer(ctx, p)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	d, raw, err := i.provisionRegistry(ctx, p)
	if err != nil {
		return nil, err
	}
	j := journal{instance: i, deploymentID: d.DeploymentID, db: pool}
	if err := i.initializeRegistry(ctx, j, p, d, raw, retryInitialization); err != nil {
		return nil, err
	}
	if err := d.validatePeer(ctx, p); err != nil {
		return nil, err
	}
	return d, writeJSON(i.registryPath("deployment.json"), d)
}

func (i *instance) provisionRegistry(ctx context.Context, p *peerClient) (*deployment, []byte, error) {
	genesis, err := readBlockFile(filepath.Join(i.dir, "genesis.pb"))
	if err != nil {
		return nil, nil, err
	}
	for _, org := range []string{"a", "b", "c"} {
		peer, err := i.peer(org, "read")
		if err != nil {
			return nil, nil, err
		}
		observed, err := peer.getBlock(ctx, 0)
		peer.close()
		if err != nil || observed.Hash != genesis.Hash {
			return nil, nil, fmt.Errorf("peer %s genesis mismatch: %v", org, err)
		}
	}
	if err := os.MkdirAll(i.registryPath("."), 0700); err != nil {
		return nil, nil, err
	}
	boot, raw, err := i.bootstrap(genesis)
	if err != nil {
		return nil, nil, err
	}
	d := &deployment{
		DeploymentFields: boot.DeploymentFields, DeploymentID: boot.ID(), Bootstrap: boot,
		BootstrapDigest: api.Digest(raw), ConfigDigest: genesis.ConfigDigest, PackageIDs: map[string]string{},
	}
	_, err = os.Stat(i.registryPath("definition.json"))
	switch {
	case err == nil:
		err = i.reuseApprovedBuild(d)
	case os.IsNotExist(err):
		err = i.build(ctx, d)
	}
	if err != nil {
		return nil, nil, err
	}
	if err := i.approveAndCommit(ctx, p, d); err != nil {
		return nil, nil, err
	}
	if err := i.recordDefinition(ctx, p, d); err != nil {
		return nil, nil, err
	}
	if err := i.waitRegistryEndorsement(ctx); err != nil {
		return nil, nil, err
	}
	return d, raw, nil
}

func (i *instance) ordererArgs() ([]string, error) {
	address, err := i.port("FABRIC_ORDERER_A")
	if err != nil {
		return nil, err
	}
	ca := filepath.Join(i.dir, "crypto", "ordererOrganizations", "oa.local", "orderers", "orderer-a.oa.local", "tls", "ca.crt")
	return []string{"-o", address, "--tls", "--cafile", ca, "--ordererTLSHostnameOverride", "orderer-a", "--connTimeout", "4s"}, nil
}

func (i *instance) approveAndCommit(ctx context.Context, reader *peerClient, d *deployment) error {
	orderer, err := i.ordererArgs()
	if err != nil {
		return err
	}
	defArgs := []string{"-C", api.Channel, "-n", api.Registry, "-v", version, "--sequence", "1", "--signature-policy", signaturePolicy}
	for _, org := range []string{"a", "b", "c"} {
		list, err := i.run(ctx, "peer", org, "Admin", "lifecycle", "chaincode", "queryinstalled", "--output", "json")
		if err != nil {
			return err
		}
		if !bytes.Contains(list, []byte(d.PackageIDs[org])) {
			if _, err := i.run(ctx, "peer", org, "Admin", "lifecycle", "chaincode", "install", i.registryPath(org+".tar.gz")); err != nil {
				return err
			}
		}
		args := []string{"peer", org, "Admin", "lifecycle", "chaincode", "queryapproved", "-C", api.Channel, "-n", api.Registry, "--sequence", "1", "--output", "json"}
		list, err = i.run(ctx, args...)
		if err == nil {
			if !bytes.Contains(list, []byte(d.PackageIDs[org])) {
				return fmt.Errorf("%s has an approval for a different chaincode package", org)
			}
			continue
		}
		args = []string{"peer", org, "Admin", "lifecycle", "chaincode", "approveformyorg", "--package-id", d.PackageIDs[org], "--waitForEventTimeout", "15s"}
		args = append(args, defArgs...)
		if _, err := i.run(ctx, append(args, orderer...)...); err != nil {
			return err
		}
	}
	if _, err := i.run(ctx, "compose", "--profile", "registry", "up", "-d", "--wait", "--wait-timeout", "25", "cc-a", "cc-b", "cc-c"); err != nil {
		return err
	}
	if def, err := reader.definition(ctx); err == nil {
		_, err := definitionHash(def)
		return err
	}
	args := append([]string{"peer", "c", "Admin", "lifecycle", "chaincode", "commit", "--waitForEventTimeout", "20s"}, defArgs...)
	for _, org := range []string{"a", "b", "c"} {
		address, err := i.port("FABRIC_PEER_" + strings.ToUpper(org))
		if err != nil {
			return err
		}
		args = append(args, "--peerAddresses", address, "--tlsRootCertFiles", i.peerTLS(org))
	}
	_, err = i.run(ctx, append(args, orderer...)...)
	return err
}

func (i *instance) recordDefinition(ctx context.Context, p *peerClient, d *deployment) error {
	def, err := p.definition(ctx)
	if err != nil {
		return err
	}
	d.DefinitionDigest, err = definitionHash(def)
	if err != nil {
		return err
	}
	height, err := p.height(ctx)
	if err != nil {
		return err
	}
	for n := uint64(1); n < height; n++ {
		b, err := p.getBlock(ctx, n)
		if err != nil {
			return err
		}
		for _, t := range b.Transactions {
			if t.DefinitionChange {
				if d.DefinitionTxID != "" {
					return fmt.Errorf("multiple registry definition changes")
				}
				d.DefinitionBlock, d.DefinitionTxID = b.point, t.ID
			}
		}
	}
	if d.DefinitionTxID == "" {
		return fmt.Errorf("no committed definition transaction")
	}
	return writeJSON(i.registryPath("definition.json"), def)
}

func (op *operation) rejectedBeforeSigning() bool {
	return op.Status == "FAILED" && op.Stage == "ENDORSE" &&
		op.FailureCode != nil && *op.FailureCode != "" && op.Observation != "" &&
		api.IsDigest(op.TxID) && len(op.Proposal) > 0 &&
		len(op.Signed) == 0 && op.SignedAt == nil && op.BroadcastAt == nil && op.Commit == nil
}

func (p *peerClient) requireEmptyBootstrap(ctx context.Context) error {
	_, err := p.direct(ctx, api.Registry, "Read", api.BootstrapKey)
	if missingRegistryRecord(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot verify registry root is empty: %w", err)
	}
	return fmt.Errorf("registry root is already initialized")
}

func (i *instance) initializeRegistry(ctx context.Context, j journal, p *peerClient, d *deployment, raw []byte, retry bool) error {
	observations := map[string]*operation{}
	run := func(label, role, wantRejection string, input []byte) (*operation, error) {
		baseKey := "initialize/" + label
		key := baseKey
		op, err := j.load(ctx, key, j.db)
		for err == nil && op != nil {
			if op.Role != role || op.Method != "Initialize" {
				return nil, fmt.Errorf("%s: unexpected initialization operation", key)
			}
			if wantRejection == "" {
				op, err = j.write(ctx, key, role, "Initialize", input)
			} else if op.Status == "PENDING" {
				// Older deployments may have randomized the negative test input.
				op, err = j.recover(ctx, key, nil)
			}
			if err != nil || !op.rejectedBeforeSigning() || *op.FailureCode == wantRejection {
				return op, err
			}
			// Derive the next key from the rejected attempt. The provision lock
			// serializes deployment and a restart can find any accepted retry.
			previous := op
			key = baseKey + "/retry/" + previous.TxID
			if key == previous.Key {
				return nil, fmt.Errorf("%s: initialization retry reused its predecessor's transaction ID", key)
			}
			op, err = j.load(ctx, key, j.db)
			if err != nil {
				return nil, err
			}
			observations[previous.Key] = previous
			if op == nil {
				if !retry {
					return previous, fmt.Errorf("%s returned %s. Run deploy --retry-initialization to request a new operation. Original response was %s",
						previous.Key, *previous.FailureCode, previous.Observation)
				}
				if err := p.requireEmptyBootstrap(ctx); err != nil {
					return previous, fmt.Errorf("%s: cannot retry initialization: %w", previous.Key, err)
				}
			}
		}
		if err != nil {
			return nil, err
		}
		return j.write(ctx, key, role, "Initialize", input)
	}
	reject := func(label, role, code string, input []byte) error {
		op, err := run(label, role, code, input)
		if err != nil {
			return err
		}
		if op.Status != "FAILED" || op.FailureCode == nil || *op.FailureCode != code || op.Commit != nil {
			return fmt.Errorf("%s: wanted %s, got %s (%s)", op.Key, code, op.Status, op.Observation)
		}
		observations[label] = op
		return nil
	}
	if err := reject("wrong-client", "wrongA", "UNAUTHORIZED", raw); err != nil {
		return err
	}
	for _, change := range []struct {
		name   string
		mutate func(*api.Bootstrap)
	}{
		{"root", func(b *api.Bootstrap) {
			b.Root.DocumentDigest = api.Digest([]byte("changed-root/" + b.Root.DocumentDigest))
		}},
		{"instance", func(b *api.Bootstrap) { b.InstanceID = api.Digest([]byte("changed-instance/" + b.InstanceID)) }},
		{"task-authority", func(b *api.Bootstrap) { b.TaskCreator.Subject = "did:web:a.local:unapproved" }},
	} {
		mutated := d.Bootstrap
		change.mutate(&mutated)
		input, err := json.Marshal(mutated)
		if err != nil {
			return err
		}
		if err := reject("changed-"+change.name, "init", "INVALID_STRUCTURE", input); err != nil {
			return err
		}
	}
	op, err := run("approved", "init", "", raw)
	if err != nil {
		return err
	}
	observations["approved"] = op
	if op.Status != "CONFIRMED" || op.Commit == nil || op.Commit.Code != "VALID" {
		return fmt.Errorf("initialization %s: %s", op.Status, op.Observation)
	}
	signed, err := decode(op.Signed, &gw.PreparedTransaction{})
	if err != nil {
		return err
	}
	if err := validateOriginal(signed, op); err != nil {
		return err
	}
	confirmed, err := p.original(ctx, op, signed)
	if err != nil {
		return err
	}
	if *confirmed != *op.Commit {
		return fmt.Errorf("%w: original initialization commit changed", errDeploymentMismatch)
	}
	d.InitBlock = confirmed.point
	// Older deployments journaled the repeat check here. Keep its evidence without advancing it.
	legacy, err := j.load(ctx, "initialize/repeat", j.db)
	if err != nil {
		return err
	}
	if legacy != nil {
		observations["repeat"] = legacy
	}
	return writeJSON(i.registryPath("initialization.json"), observations)
}

// Discovery can lag after the lifecycle commit. Establish a working
// endorsement plan before creating the immutable, time-windowed init proposal.
func (i *instance) waitRegistryEndorsement(ctx context.Context) error {
	p, err := i.peer("c", "probe1")
	if err != nil {
		return err
	}
	defer p.close()
	var last error
	err = poll(ctx, 45*time.Second, func() (bool, error) {
		proposal, _, err := p.proposal("Probe", nil, nil)
		if err != nil {
			return false, err
		}
		c, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		_, last = proposal.EndorseWithContext(c)
		return last == nil, nil
	})
	if err != nil {
		return fmt.Errorf("registry endorsement discovery not ready: %w (%v)", err, last)
	}
	return nil
}
