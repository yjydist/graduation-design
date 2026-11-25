package ledger

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/renameio/v2"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	gw "github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	msp "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	lb "github.com/hyperledger/fabric-protos-go-apiv2/peer/lifecycle"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"grad/platform/core/dao"
	"grad/protocol"
	"grad/protocol/registry"
)

const (
	RegistryVersion  = "1.0"
	RegistrySequence = 1
	SignaturePolicy  = "OutOf(2,'AMsp.peer','BMsp.peer','CMsp.peer')"
	SubjectU         = "did:web:a.local:u"
	SubjectC         = "did:web:c.local:supplier"
)

// ErrDeploymentMismatch indicates that the peer or persisted state disagrees with the pinned deployment manifest.
var ErrDeploymentMismatch = errors.New("DEPLOYMENT_MISMATCH")

// Instance represents a local isolated Fabric network directory and its runtime environment.
type Instance struct {
	dir        string
	env        map[string]string
	clientOrg  string
	clientAddr string
	readRole   string
}

// Deployment captures the immutable, verified Fabric channel, chaincode definition,
// and bootstrap anchors bound to a single deploymentId.
type Deployment struct {
	registry.DeploymentFields
	DeploymentID     string             `json:"deploymentId"`
	ConfigDigest     string             `json:"channelConfigSha256"`
	BootstrapDigest  string             `json:"bootstrapSha256"`
	BuildDigest      string             `json:"chaincodeBuildSha256"`
	SourceDigest     string             `json:"chaincodeSourceSha256"`
	PackageIDs       map[string]string  `json:"packageIds"`
	DefinitionDigest string             `json:"definitionSha256"`
	DefinitionBlock  Point              `json:"definitionBlock"`
	DefinitionTxID   string             `json:"definitionTxId"`
	InitBlock        Point              `json:"initializationBlock"`
	Bootstrap        registry.Bootstrap `json:"bootstrap"`
}

type registryApproval struct {
	DeploymentID    string                `json:"deploymentId"`
	BootstrapDigest string                `json:"bootstrapSha256"`
	BuildDigest     string                `json:"buildSha256"`
	SourceDigest    string                `json:"sourceSha256"`
	Initializer     registry.Management   `json:"initializer"`
	Probes          []registry.Management `json:"probes"`
}

// PeerClient wraps an authenticated gRPC connection and Fabric Gateway client pinned to one peer.
type PeerClient struct {
	name    string
	conn    *grpc.ClientConn
	gateway *client.Gateway
	signer  identity.Sign
	role    registry.Management
}

// PeerResponseError records a non-200 chaincode endorsement response from a direct peer call.
type PeerResponseError struct {
	Status  int32
	Message string
}

func (e *PeerResponseError) Error() string {
	return fmt.Sprintf("peer response %d: %s", e.Status, e.Message)
}

// IsMissingRecord reports whether err is a canonical MISSING_DEPENDENCY response from the registry chaincode.
func IsMissingRecord(err error) bool {
	var response *PeerResponseError
	return errors.As(err, &response) && response.Status == 500 && response.Message == registry.ErrCodeMissingDependency
}

type roleLocation struct{ org, user string }

var roleLocations = map[string]roleLocation{
	"init":       {"a", "User1"},
	"T":          {"t", "User1"},
	"domainA":    {"a", "User2"},
	"registrarA": {"a", "User3"},
	"IA":         {"a", "User4"},
	"U":          {"a", "User5"},
	"A1":         {"a", "User6"},
	"alt":        {"a", "User7"},
	"wrongA":     {"a", "User8"},
	"PA":         {"a", "User9"},
	"domainB":    {"b", "User2"},
	"registrarB": {"b", "User3"},
	"IB":         {"b", "User4"},
	"B1":         {"b", "User5"},
	"U-in-B":     {"b", "User6"},
	"wrongB":     {"b", "User7"},
	"B2":         {"b", "User8"},
	"recoverB":   {"b", "User9"},
	"domainC":    {"c", "User2"},
	"registrarC": {"c", "User3"},
	"IC":         {"c", "User4"},
	"C":          {"c", "User5"},
	"probe1":     {"c", "User6"},
	"probe2":     {"c", "User7"},
	"read":       {"c", "User8"},
	"rogue":      {"x", "User1"},
	"adminA":     {"a", "Admin"},
	"adminB":     {"b", "Admin"},
	"adminC":     {"c", "Admin"},
}

// OpenInstance loads a Fabric instance directory containing network.env.
func OpenInstance(dir string) (*Instance, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(abs, "network.env"))
	if err != nil && errors.Is(err, os.ErrNotExist) && !filepath.IsAbs(dir) {
		if root, rErr := findRepoRoot(); rErr == nil {
			cand := filepath.Join(root, dir)
			if cb, cErr := os.ReadFile(filepath.Join(cand, "network.env")); cErr == nil {
				abs, b, err = cand, cb, nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	inst := &Instance{dir: abs, env: map[string]string{}, clientOrg: "c", readRole: "read"}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid network setting %q", line)
		}
		inst.env[key] = value
	}
	return inst, nil
}

// ForDomain returns an instance client configured to use only the domain's peer
// and a local enrollment for ledger reads.
func (i *Instance) ForDomain(domain, readRole, address string) (*Instance, error) {
	org := strings.ToLower(domain)
	role, ok := roleLocations[readRole]
	if !ok || role.org != org || (org != "a" && org != "b" && org != "c") {
		return nil, fmt.Errorf("invalid local Fabric reader for domain %q", domain)
	}
	if address != "" {
		host, port, err := net.SplitHostPort(address)
		n, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || host == "" || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid local peer address")
		}
	}
	client := *i
	client.clientOrg, client.clientAddr, client.readRole = org, address, readRole
	return &client, nil
}

// ReadPeer connects with the enrollment configured for committed registry reads.
func (i *Instance) ReadPeer() (*PeerClient, error) {
	return i.Peer(i.clientOrg, i.readRole)
}

// Dir returns the absolute path of the Fabric instance directory.
func (i *Instance) Dir() string { return i.dir }

// Env returns a setting loaded from network.env.
func (i *Instance) Env(key string) string { return i.env[key] }

// EnvMap returns a copy of all network.env settings.
func (i *Instance) EnvMap() map[string]string {
	out := make(map[string]string, len(i.env))
	for k, v := range i.env {
		out[k] = v
	}
	return out
}

// OrgDir returns the MSP/TLS crypto root directory for peer organization org.
func (i *Instance) OrgDir(org string) string {
	return filepath.Join(i.dir, "crypto", "peerOrganizations", org+".local")
}

// PeerTLS returns the TLS root CA path for peer-<org>.
func (i *Instance) PeerTLS(org string) string {
	return filepath.Join(i.OrgDir(org), "peers", "peer-"+org+"."+org+".local", "tls", "ca.crt")
}

// RegistryPath joins parts under <instance>/registry.
func (i *Instance) RegistryPath(parts ...string) string {
	return filepath.Join(append([]string{i.dir, "registry"}, parts...)...)
}

// PrivatePath joins parts under <instance>/private.
func (i *Instance) PrivatePath(parts ...string) string {
	return filepath.Join(append([]string{i.dir, "private"}, parts...)...)
}

// Port resolves a local 127.0.0.1:<port> endpoint from network.env.
func (i *Instance) Port(name string) (string, error) {
	v := i.env[name]
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port %s", name)
	}
	return net.JoinHostPort("127.0.0.1", v), nil
}

// RunNetwork executes infra/fabric/network.sh from the repository root with FABRIC_INSTANCE bound.
func (i *Instance) RunNetwork(ctx context.Context, args ...string) ([]byte, error) {
	root, err := findRepoRoot()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "sh", append([]string{"infra/fabric/network.sh"}, args...)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "FABRIC_INSTANCE="+i.dir)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return b, fmt.Errorf("network %s: %w: %s", args[0], err, b)
	}
	return b, nil
}

// Database opens and pings the instance's PostgreSQL view/journal pool.
func (i *Instance) Database(ctx context.Context) (*pgxpool.Pool, error) {
	host, err := i.Port("FABRIC_DB")
	if err != nil {
		return nil, err
	}
	pw, err := os.ReadFile(filepath.Join(i.dir, "view-password"))
	if err != nil {
		return nil, err
	}
	dsn := url.URL{
		Scheme:   "postgres",
		Host:     host,
		User:     url.UserPassword("view", strings.TrimSpace(string(pw))),
		Path:     "/fabric",
		RawQuery: "sslmode=disable",
	}
	cfg, err := pgxpool.ParseConfig(dsn.String())
	if err != nil {
		return nil, errors.New("invalid local view database configuration")
	}
	cfg.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// Role loads the Fabric X.509 identity, canonical Management binding, and MSP directory for role.
func (i *Instance) Role(role string) (*identity.X509Identity, registry.Management, string, error) {
	r, ok := roleLocations[role]
	if !ok {
		return nil, registry.Management{}, "", fmt.Errorf("unknown client role %q", role)
	}
	user := r.user + "@" + r.org + ".local"
	mspDir := filepath.Join(i.OrgDir(r.org), "users", user, "msp")
	certPEM, err := os.ReadFile(filepath.Join(mspDir, "signcerts", user+"-cert.pem"))
	if err != nil {
		return nil, registry.Management{}, "", err
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, registry.Management{}, "", err
	}
	mspID := strings.ToUpper(r.org) + "Msp"
	id, err := identity.NewX509Identity(mspID, cert)
	return id, registry.Management{MSPID: mspID, CertificateSHA256: registry.Digest(cert.Raw)}, mspDir, err
}

// RoleForManagement resolves a Management identity (mspId + SHA-256 DER fingerprint) back to its local Fabric role name.
func (i *Instance) RoleForManagement(m registry.Management) (string, bool) {
	for role := range roleLocations {
		_, binding, _, err := i.Role(role)
		if err == nil && binding == m {
			return role, true
		}
	}
	return "", false
}

// AllRoles returns all configured client role names in sorted order.
func AllRoles() []string {
	out := make([]string, 0, len(roleLocations))
	for k := range roleLocations {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Peer connects a pinned gRPC + Fabric Gateway client to peer-<org> authenticated as role.
func (i *Instance) Peer(org, role string) (*PeerClient, error) {
	address := i.clientAddr
	if org != i.clientOrg || address == "" {
		var err error
		address, err = i.Port("FABRIC_PEER_" + strings.ToUpper(org))
		if err != nil {
			return nil, err
		}
	}
	id, binding, mspDir, err := i.Role(role)
	if err != nil {
		return nil, err
	}
	keys, err := filepath.Glob(filepath.Join(mspDir, "keystore", "*"))
	if err != nil || len(keys) != 1 {
		return nil, fmt.Errorf("expected one enrollment signing key for %s", role)
	}
	b, err := os.ReadFile(keys[0])
	if err != nil {
		return nil, err
	}
	key, err := identity.PrivateKeyFromPEM(b)
	if err != nil {
		return nil, err
	}
	sign, err := identity.NewPrivateKeySign(key)
	if err != nil {
		return nil, err
	}
	peerName := "peer-" + org
	conn, err := DialTLS(address, peerName, i.PeerTLS(org))
	if err != nil {
		return nil, err
	}
	g, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(conn),
		client.WithEndorseTimeout(6*time.Second),
		client.WithEvaluateTimeout(3*time.Second),
		client.WithSubmitTimeout(4*time.Second),
		client.WithCommitStatusTimeout(4*time.Second),
	)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &PeerClient{name: peerName, conn: conn, gateway: g, signer: sign, role: binding}, nil
}

// DialTLS creates a TLS 1.2+ gRPC client connection pinned to rootPath and serverName.
func DialTLS(address, serverName, rootPath string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
	ca, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid TLS root: %s", rootPath)
	}
	creds := credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12})
	options = append(options, grpc.WithTransportCredentials(creds), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16<<20)))
	return grpc.NewClient(address, options...)
}

// Close closes the underlying Gateway and gRPC connection.
func (p *PeerClient) Close() {
	if p == nil {
		return
	}
	if p.gateway != nil {
		p.gateway.Close()
	}
	if p.conn != nil {
		p.conn.Close()
	}
}

// Role returns the Management identity bound to this PeerClient.
func (p *PeerClient) Role() registry.Management { return p.role }

// Gateway returns the underlying Fabric Gateway client.
func (p *PeerClient) Gateway() *client.Gateway { return p.gateway }

// Conn returns the underlying pinned gRPC connection.
func (p *PeerClient) Conn() *grpc.ClientConn { return p.conn }

// Contract returns a Fabric Gateway Contract handle on the canonical channel.
func (p *PeerClient) Contract(name string) *client.Contract {
	return p.gateway.GetNetwork(registry.Channel).GetContract(name)
}

// Direct invokes the pinned Peer Endorser endpoint directly without Gateway peer selection.
func (p *PeerClient) Direct(ctx context.Context, chaincode, method string, args ...string) ([]byte, error) {
	proposal, err := p.Contract(chaincode).NewProposal(method, client.WithArguments(args...))
	if err != nil {
		return nil, err
	}
	b, err := proposal.Bytes()
	if err != nil {
		return nil, err
	}
	wire := &gw.ProposedTransaction{}
	if err := proto.Unmarshal(b, wire); err != nil {
		return nil, err
	}
	wire.Proposal.Signature, err = p.signer(proposal.Digest())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	res, err := pb.NewEndorserClient(p.conn).ProcessProposal(ctx, wire.Proposal)
	if err != nil {
		return nil, err
	}
	response := res.GetResponse()
	if response.GetStatus() != 200 {
		return nil, &PeerResponseError{Status: response.GetStatus(), Message: response.GetMessage()}
	}
	return response.GetPayload(), nil
}

// Definition queries _lifecycle on the pinned peer for the committed registry chaincode definition.
func (p *PeerClient) Definition(ctx context.Context) (*lb.QueryChaincodeDefinitionResult, error) {
	b, err := proto.Marshal(&lb.QueryChaincodeDefinitionArgs{Name: registry.Registry})
	if err != nil {
		return nil, err
	}
	data, err := p.Direct(ctx, "_lifecycle", "QueryChaincodeDefinition", string(b))
	if err != nil {
		return nil, err
	}
	definition, err := decodeProto(data, &lb.QueryChaincodeDefinitionResult{})
	if err != nil {
		return nil, fmt.Errorf("%w: invalid committed registry definition: %w", ErrDeploymentMismatch, err)
	}
	return definition, nil
}

// RequireEmptyBootstrap confirms that the ledger bootstrap key has not been written yet.
func (p *PeerClient) RequireEmptyBootstrap(ctx context.Context) error {
	_, err := p.Direct(ctx, registry.Registry, "Read", registry.BootstrapKey)
	if IsMissingRecord(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot verify registry root is empty: %w", err)
	}
	return fmt.Errorf("registry root is already initialized")
}

// ReadLedgerRecord queries a single JSON ledger record directly from the pinned peer.
func ReadLedgerRecord[T any](ctx context.Context, p *PeerClient, kind, id string) (T, error) {
	var v T
	b, err := p.Direct(ctx, registry.Registry, "Read", registry.Key(kind, id))
	if err == nil {
		err = json.Unmarshal(b, &v)
	}
	return v, err
}

// AwaitEndorsers waits for committed to be observed identically across all three endorsing peers (a, b, c).
func (i *Instance) AwaitEndorsers(ctx context.Context, committed Outcome) error {
	for _, org := range []string{"a", "b", "c"} {
		p, err := i.Peer(org, "read")
		if err != nil {
			return err
		}
		err = Poll(ctx, 8*time.Second, func() (bool, error) {
			b, err := p.GetBlock(ctx, committed.Number)
			if err != nil {
				return false, nil
			}
			if b.Hash != committed.Hash || committed.Index < 0 || committed.Index >= len(b.Transactions) ||
				b.Transactions[committed.Index].Code.String() != committed.Code {
				return false, fmt.Errorf("Peer %s has a conflicting dependency at block %d", org, committed.Number)
			}
			return true, nil
		})
		p.Close()
		if err != nil {
			return fmt.Errorf("wait for dependency at Peer %s: %w", org, err)
		}
	}
	return nil
}

// Poll invokes f periodically until it returns true, returns an error, or d/ctx expires.
func Poll(ctx context.Context, d time.Duration, f func() (bool, error)) error {
	c, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	for c.Err() == nil {
		ok, err := f()
		if err != nil || ok {
			return err
		}
		select {
		case <-c.Done():
		case <-time.After(80 * time.Millisecond):
		}
	}
	return c.Err()
}

// WriteAtomic writes data to path atomically using github.com/google/renameio/v2.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	return renameio.WriteFile(path, data, mode)
}

// WriteJSON marshals value with indentation and writes it atomically with 0600 permissions.
func WriteJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return WriteAtomic(path, append(b, '\n'), 0600)
}

// WritePrivateFile writes private key or sensitive material atomically with 0600 permissions.
func WritePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return WriteAtomic(path, data, 0600)
}

// WritePublicFile writes public registry material atomically with 0644 permissions.
func WritePublicFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return WriteAtomic(path, data, 0644)
}

// WritePublicJSON encodes value with HTML escaping disabled and writes it publicly and atomically.
func WritePublicJSON(path string, value any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return err
	}
	return WritePublicFile(path, buf.Bytes())
}

// ReadJSON reads and unmarshals JSON from path into into.
func ReadJSON(path string, into any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

// LoadDeployment reads and validates the instance's persisted deployment.json manifest.
func (i *Instance) LoadDeployment() (*Deployment, error) {
	var d Deployment
	if err := ReadJSON(i.RegistryPath("deployment.json"), &d); err != nil {
		return nil, err
	}
	if !d.DeploymentFields.Valid() || d.DeploymentID != d.DeploymentFields.DeploymentID() || d.Bootstrap.DeploymentFields != d.DeploymentFields ||
		len(d.PackageIDs) != 3 || !registry.IsDigest(d.ConfigDigest) || !registry.IsDigest(d.DefinitionDigest) ||
		!registry.IsDigest(d.BootstrapDigest) || !registry.IsDigest(d.DefinitionBlock.Hash) || !registry.IsDigest(d.InitBlock.Hash) ||
		d.DefinitionBlock.Number >= d.InitBlock.Number || !registry.IsDigest(d.DefinitionTxID) {
		return nil, fmt.Errorf("%w: malformed trusted deployment", ErrDeploymentMismatch)
	}
	for _, org := range []string{"a", "b", "c"} {
		label, sum, ok := strings.Cut(d.PackageIDs[org], ":")
		if !ok || label == "" || !registry.IsDigest(sum) {
			return nil, fmt.Errorf("%w: missing package ID for %s", ErrDeploymentMismatch, org)
		}
	}
	return &d, nil
}

// ValidatePeer verifies that peer serves the exact genesis, channel config, chaincode definition,
// and immutable bootstrap record pinned in d.
func (d *Deployment) ValidatePeer(ctx context.Context, peer *PeerClient) error {
	if !d.DeploymentFields.Valid() || d.DeploymentFields.DeploymentID() != d.DeploymentID || d.Bootstrap.DeploymentFields != d.DeploymentFields {
		return fmt.Errorf("%w: trusted deployment fields are inconsistent", ErrDeploymentMismatch)
	}
	genesis, err := peer.GetBlock(ctx, 0)
	if errors.Is(err, ErrInvalidPeerBlock) {
		return fmt.Errorf("%w: Peer genesis: %w", ErrDeploymentMismatch, err)
	}
	if err != nil {
		return fmt.Errorf("read Peer genesis: %w", err)
	}
	if genesis.Hash != d.GenesisHash || genesis.ConfigDigest != d.ConfigDigest {
		return fmt.Errorf("%w: genesis/config does not match the trusted channel", ErrDeploymentMismatch)
	}
	cfg, err := peer.Direct(ctx, "cscc", "GetConfigBlock", registry.Channel)
	if err != nil {
		return fmt.Errorf("read active channel configuration: %w", err)
	}
	latestConfig, err := DecodeBlock(cfg)
	if err != nil {
		return fmt.Errorf("%w: invalid active channel configuration: %w", ErrDeploymentMismatch, err)
	}
	if latestConfig.ConfigDigest != d.ConfigDigest {
		return fmt.Errorf("%w: active channel configuration changed", ErrDeploymentMismatch)
	}
	def, err := peer.Definition(ctx)
	if err != nil {
		return fmt.Errorf("read committed registry definition: %w", err)
	}
	h, err := definitionHash(def)
	if err != nil {
		return fmt.Errorf("%w: invalid committed registry definition: %w", ErrDeploymentMismatch, err)
	}
	if h != d.DefinitionDigest {
		return fmt.Errorf("%w: committed registry definition changed", ErrDeploymentMismatch)
	}
	boot, err := peer.Direct(ctx, registry.Registry, "Read", registry.BootstrapKey)
	if IsMissingRecord(err) {
		return fmt.Errorf("%w: committed bootstrap record is missing", ErrDeploymentMismatch)
	}
	if err != nil {
		return fmt.Errorf("read committed bootstrap record: %w", err)
	}
	var b registry.Bootstrap
	if err := json.Unmarshal(boot, &b); err != nil {
		return fmt.Errorf("%w: invalid committed bootstrap record: %w", ErrDeploymentMismatch, err)
	}
	if b != d.Bootstrap || registry.Digest(boot) != d.BootstrapDigest {
		return fmt.Errorf("%w: immutable root, instance or qualification mismatch", ErrDeploymentMismatch)
	}
	return nil
}

// Deploy provisions, approves, commits, initializes, and validates the Fabric registry chaincode
// for the instance. If already deployed, it refreshes the chaincode binary if source files changed
// and re-validates the pinned peer.
func (i *Instance) Deploy(ctx context.Context, retryInit bool) (*Deployment, error) {
	p, err := i.Peer("c", "read")
	if err != nil {
		return nil, err
	}
	defer p.Close()
	if d, err := i.LoadDeployment(); err == nil {
		if err := i.refreshChaincodeIfChanged(ctx, d); err != nil {
			return nil, err
		}
		return d, d.ValidatePeer(ctx, p)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	pool, err := i.Database(ctx)
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	if err := dao.Up(ctx, pool); err != nil {
		return nil, err
	}
	// Serialize build, approvals and manifest creation for the same instance.
	bootstrapJournal := NewJournal(i, pool, "provision")
	_, unlock, err := bootstrapJournal.Lock(ctx, "provision")
	if err != nil {
		return nil, err
	}
	defer unlock()
	if d, err := i.LoadDeployment(); err == nil {
		return d, d.ValidatePeer(ctx, p)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	d, raw, err := i.provisionRegistry(ctx, p)
	if err != nil {
		return nil, err
	}
	j := NewJournal(i, pool, d.DeploymentID)
	if err := i.initializeRegistry(ctx, j, p, d, raw, retryInit); err != nil {
		return nil, err
	}
	if err := d.ValidatePeer(ctx, p); err != nil {
		return nil, err
	}
	return d, WriteJSON(i.RegistryPath("deployment.json"), d)
}

func (i *Instance) provisionRegistry(ctx context.Context, p *PeerClient) (*Deployment, []byte, error) {
	genesis, err := readBlockFile(filepath.Join(i.dir, "genesis.pb"))
	if err != nil {
		return nil, nil, err
	}
	for _, org := range []string{"a", "b", "c"} {
		peer, err := i.Peer(org, "read")
		if err != nil {
			return nil, nil, err
		}
		observed, err := peer.GetBlock(ctx, 0)
		peer.Close()
		if err != nil || observed.Hash != genesis.Hash {
			return nil, nil, fmt.Errorf("peer %s genesis mismatch: %v", org, err)
		}
	}
	if err := os.MkdirAll(i.RegistryPath("."), 0700); err != nil {
		return nil, nil, err
	}
	boot, raw, err := i.bootstrap(genesis)
	if err != nil {
		return nil, nil, err
	}
	d := &Deployment{
		DeploymentFields: boot.DeploymentFields,
		DeploymentID:     boot.DeploymentFields.DeploymentID(),
		Bootstrap:        boot,
		BootstrapDigest:  registry.Digest(raw),
		ConfigDigest:     genesis.ConfigDigest,
		PackageIDs:       map[string]string{},
	}
	_, err = os.Stat(i.RegistryPath("definition.json"))
	switch {
	case err == nil:
		err = i.reuseApprovedBuild(d)
	case os.IsNotExist(err):
		err = i.ChaincodeBuild(ctx, d)
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

// ChaincodeBuild compiles the registry chaincode from <repoRoot>/chaincode with pinned ldflags
// and packages CCaaS archives for organizations a, b, and c.
func (i *Instance) ChaincodeBuild(ctx context.Context, d *Deployment) error {
	_, p1, _, err := i.Role("probe1")
	if err != nil {
		return err
	}
	_, p2, _, err := i.Role("probe2")
	if err != nil {
		return err
	}
	sourceDigest, err := RegistrySourceDigest()
	if err != nil {
		return err
	}
	d.SourceDigest = sourceDigest
	binary := i.RegistryPath("registry")
	buildDigest, err := buildChaincodeBinary(ctx, binary, d.BootstrapDigest, d.Bootstrap.Initializer, p1, p2)
	if err != nil {
		return err
	}
	d.BuildDigest = buildDigest
	approval, err := json.Marshal(registryApproval{
		DeploymentID:    d.DeploymentID,
		BootstrapDigest: d.BootstrapDigest,
		BuildDigest:     d.BuildDigest,
		SourceDigest:    d.SourceDigest,
		Initializer:     d.Bootstrap.Initializer,
		Probes:          []registry.Management{p1, p2},
	})
	if err != nil {
		return err
	}
	if err := WriteAtomic(i.RegistryPath("approval.json"), approval, 0600); err != nil {
		return err
	}
	for _, org := range []string{"a", "b", "c"} {
		id, err := i.PackageChaincode(ctx, org, approval)
		if err != nil {
			return err
		}
		d.PackageIDs[org] = id
	}
	return nil
}

func buildChaincodeBinary(ctx context.Context, outPath, bootstrapDigest string, initializer, probeOne, probeTwo registry.Management) (string, error) {
	root, err := findRepoRoot()
	if err != nil {
		return "", err
	}
	absOut, err := filepath.Abs(outPath)
	if err != nil {
		return "", err
	}
	tmpOut := absOut + ".new"
	defer os.Remove(tmpOut)
	flags := fmt.Sprintf("-X main.bootstrapDigest=%s -X main.initializer=%s -X main.probeOne=%s -X main.probeTwo=%s",
		bootstrapDigest, initializer, probeOne, probeTwo)
	cmd := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", flags, "-o", tmpOut, "./registry")
	cmd.Dir = filepath.Join(root, "chaincode")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build chaincode: %w: %s", err, out)
	}
	b, err := os.ReadFile(tmpOut)
	if err != nil {
		return "", err
	}
	if err := WriteAtomic(absOut, b, 0755); err != nil {
		return "", err
	}
	return registry.Digest(b), nil
}

func (i *Instance) reuseApprovedBuild(d *Deployment) error {
	raw, err := os.ReadFile(i.RegistryPath("approval.json"))
	if err != nil {
		return err
	}
	var approval registryApproval
	if err := json.Unmarshal(raw, &approval); err != nil {
		return err
	}
	if approval.DeploymentID != d.DeploymentID || approval.BootstrapDigest != d.BootstrapDigest ||
		approval.Initializer != d.Bootstrap.Initializer || !registry.IsDigest(approval.SourceDigest) {
		return fmt.Errorf("%w: chaincode approval does not match the bootstrap", ErrDeploymentMismatch)
	}
	binary, err := os.ReadFile(i.RegistryPath("registry"))
	if err != nil {
		return err
	}
	if registry.Digest(binary) != approval.BuildDigest {
		return fmt.Errorf("%w: chaincode binary does not match its approved build", ErrDeploymentMismatch)
	}
	for _, org := range []string{"a", "b", "c"} {
		dir := filepath.Join(i.dir, "cc-"+org)
		cert, err := os.ReadFile(filepath.Join(dir, "server.crt"))
		if err != nil {
			return err
		}
		id, expected, err := BuildChaincodePackage(org, cert, raw)
		if err != nil {
			return err
		}
		stored, err := os.ReadFile(i.RegistryPath(org + ".tar.gz"))
		if err != nil {
			return err
		}
		storedID, err := os.ReadFile(filepath.Join(dir, "package-id"))
		if err != nil {
			return err
		}
		if !bytes.Equal(stored, expected) || strings.TrimSpace(string(storedID)) != id {
			return fmt.Errorf("%w: chaincode package for %s does not match its approval", ErrDeploymentMismatch, org)
		}
		d.PackageIDs[org] = id
	}
	d.BuildDigest, d.SourceDigest = approval.BuildDigest, approval.SourceDigest
	return nil
}

// RegistrySourceDigest hashes only chaincode/go.mod, chaincode/go.sum,
// chaincode/registry/*.go (excluding tests), and protocol/registry/*.go (excluding tests).
func RegistrySourceDigest() (string, error) {
	root, err := findRepoRoot()
	if err != nil {
		return "", err
	}
	return registrySourceDigestAt(root)
}

func registrySourceDigestAt(root string) (string, error) {
	relNames := []string{"chaincode/go.mod", "chaincode/go.sum"}
	for _, pattern := range []string{"chaincode/registry/*.go", "protocol/registry/*.go"} {
		found, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		if err != nil {
			return "", err
		}
		for _, abs := range found {
			if strings.HasSuffix(abs, "_test.go") {
				continue
			}
			rel, err := filepath.Rel(root, abs)
			if err != nil {
				return "", err
			}
			relNames = append(relNames, filepath.ToSlash(rel))
		}
	}
	slices.Sort(relNames)
	h := sha256.New()
	for _, rel := range relNames {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s %s\n", rel, registry.Digest(b))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func findRepoRoot() (string, error) {
	isRoot := func(dir string) bool {
		if _, err := os.Stat(filepath.Join(dir, "chaincode", "go.mod")); err != nil {
			return false
		}
		if _, err := os.Stat(filepath.Join(dir, "protocol", "registry", "types.go")); err != nil {
			return false
		}
		return true
	}
	walkUp := func(start string) (string, bool) {
		cur, err := filepath.Abs(start)
		if err != nil {
			return "", false
		}
		for {
			if isRoot(cur) {
				return cur, true
			}
			parent := filepath.Dir(cur)
			if parent == cur {
				return "", false
			}
			cur = parent
		}
	}
	if wd, err := os.Getwd(); err == nil {
		if root, ok := walkUp(wd); ok {
			return root, nil
		}
	}
	if _, file, _, ok := runtime.Caller(0); ok {
		if root, ok := walkUp(filepath.Dir(file)); ok {
			return root, nil
		}
	}
	return "", fmt.Errorf("cannot locate repository root containing chaincode/go.mod and protocol/registry")
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

// PackageChaincode generates a CCaaS TLS certificate (if absent) and deterministically writes
// <instance>/registry/<org>.tar.gz and <instance>/cc-<org>/package-id.
func (i *Instance) PackageChaincode(ctx context.Context, org string, approval []byte) (string, error) {
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
	id, data, err := BuildChaincodePackage(org, cert, approval)
	if err != nil {
		return "", err
	}
	if err := WriteAtomic(i.RegistryPath(org+".tar.gz"), data, 0600); err != nil {
		return "", err
	}
	return id, WriteAtomic(filepath.Join(dir, "package-id"), []byte(id+"\n"), 0600)
}

// BuildChaincodePackage deterministically builds a CCaaS tar.gz archive and its Fabric package ID.
func BuildChaincodePackage(org string, cert, approval []byte) (string, []byte, error) {
	conn, err := json.Marshal(map[string]any{
		"address":              "cc-" + org + ":9999",
		"dial_timeout":         "4s",
		"tls_required":         true,
		"client_auth_required": false,
		"root_cert":            string(cert),
	})
	if err != nil {
		return "", nil, err
	}
	code, err := packageArchive(packageFile{"connection.json", conn}, packageFile{"approval.json", approval})
	if err != nil {
		return "", nil, err
	}
	label := registry.Registry + "_" + org + "_" + registry.Digest(approval)[:12]
	meta, err := json.Marshal(map[string]string{"type": "ccaas", "label": label})
	if err != nil {
		return "", nil, err
	}
	data, err := packageArchive(packageFile{"metadata.json", meta}, packageFile{"code.tar.gz", code})
	if err != nil {
		return "", nil, err
	}
	return label + ":" + registry.Digest(data), data, nil
}

func definitionHash(d *lb.QueryChaincodeDefinitionResult) (string, error) {
	if d.Sequence != RegistrySequence || d.Version != RegistryVersion || d.EndorsementPlugin != "escc" ||
		d.ValidationPlugin != "vscc" || d.InitRequired || len(d.GetCollections().GetConfig()) != 0 {
		return "", fmt.Errorf("unexpected chaincode definition")
	}
	policy, err := decodeProto(d.ValidationParameter, &pb.ApplicationPolicy{})
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
		role, err := decodeProto(principal.Principal, &msp.MSPRole{})
		if err != nil || principal.PrincipalClassification != msp.MSPPrincipal_ROLE || role.Role != msp.MSPRole_PEER {
			return "", fmt.Errorf("unexpected endorsement identity: %v", err)
		}
		members = append(members, role.MspIdentifier)
	}
	slices.Sort(members)
	if !slices.Equal(members, []string{"AMsp", "BMsp", "CMsp"}) {
		return "", fmt.Errorf("unexpected endorsement organizations %v", members)
	}
	canonical := proto.CloneOf(d)
	canonical.Approvals = nil
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return registry.Digest(raw), nil
}

func (i *Instance) ordererArgs() ([]string, error) {
	address, err := i.Port("FABRIC_ORDERER_A")
	if err != nil {
		return nil, err
	}
	ca := filepath.Join(i.dir, "crypto", "ordererOrganizations", "oa.local", "orderers", "orderer-a.oa.local", "tls", "ca.crt")
	return []string{"-o", address, "--tls", "--cafile", ca, "--ordererTLSHostnameOverride", "orderer-a", "--connTimeout", "4s"}, nil
}

func (i *Instance) approveAndCommit(ctx context.Context, reader *PeerClient, d *Deployment) error {
	orderer, err := i.ordererArgs()
	if err != nil {
		return err
	}
	defArgs := []string{"-C", registry.Channel, "-n", registry.Registry, "-v", RegistryVersion, "--sequence", "1", "--signature-policy", SignaturePolicy}
	for _, org := range []string{"a", "b", "c"} {
		list, err := i.RunNetwork(ctx, "peer", org, "Admin", "lifecycle", "chaincode", "queryinstalled", "--output", "json")
		if err != nil {
			return err
		}
		if !bytes.Contains(list, []byte(d.PackageIDs[org])) {
			if _, err := i.RunNetwork(ctx, "peer", org, "Admin", "lifecycle", "chaincode", "install", i.RegistryPath(org+".tar.gz")); err != nil {
				return err
			}
		}
		args := []string{"peer", org, "Admin", "lifecycle", "chaincode", "queryapproved", "-C", registry.Channel, "-n", registry.Registry, "--sequence", "1", "--output", "json"}
		list, err = i.RunNetwork(ctx, args...)
		if err == nil {
			if !bytes.Contains(list, []byte(d.PackageIDs[org])) {
				return fmt.Errorf("%s has an approval for a different chaincode package", org)
			}
			continue
		}
		args = []string{"peer", org, "Admin", "lifecycle", "chaincode", "approveformyorg", "--package-id", d.PackageIDs[org], "--waitForEventTimeout", "15s"}
		args = append(args, defArgs...)
		if _, err := i.RunNetwork(ctx, append(args, orderer...)...); err != nil {
			return err
		}
	}
	if _, err := i.RunNetwork(ctx, "compose", "--profile", "registry", "up", "-d", "--wait", "--wait-timeout", "25", "cc-a", "cc-b", "cc-c"); err != nil {
		return err
	}
	if def, err := reader.Definition(ctx); err == nil {
		_, err := definitionHash(def)
		return err
	}
	args := append([]string{"peer", "c", "Admin", "lifecycle", "chaincode", "commit", "--waitForEventTimeout", "20s"}, defArgs...)
	for _, org := range []string{"a", "b", "c"} {
		address, err := i.Port("FABRIC_PEER_" + strings.ToUpper(org))
		if err != nil {
			return err
		}
		args = append(args, "--peerAddresses", address, "--tlsRootCertFiles", i.PeerTLS(org))
	}
	_, err = i.RunNetwork(ctx, append(args, orderer...)...)
	return err
}

func (i *Instance) recordDefinition(ctx context.Context, p *PeerClient, d *Deployment) error {
	def, err := p.Definition(ctx)
	if err != nil {
		return err
	}
	d.DefinitionDigest, err = definitionHash(def)
	if err != nil {
		return err
	}
	height, err := p.Height(ctx)
	if err != nil {
		return err
	}
	for n := uint64(1); n < height; n++ {
		b, err := p.GetBlock(ctx, n)
		if err != nil {
			return err
		}
		for _, t := range b.Transactions {
			if t.DefinitionChange {
				if d.DefinitionTxID != "" {
					return fmt.Errorf("multiple registry definition changes")
				}
				d.DefinitionBlock, d.DefinitionTxID = b.Point, t.ID
			}
		}
	}
	if d.DefinitionTxID == "" {
		return fmt.Errorf("no committed definition transaction")
	}
	return WriteJSON(i.RegistryPath("definition.json"), def)
}

func (i *Instance) initializeRegistry(ctx context.Context, j Journal, p *PeerClient, d *Deployment, raw []byte, retry bool) error {
	observations := map[string]*Operation{}
	run := func(label, role, wantRejection string, input []byte) (*Operation, error) {
		baseKey := "initialize/" + label
		key := baseKey
		op, err := j.Load(ctx, key, j.DB)
		for err == nil && op != nil {
			if op.Role != role || op.Method != "Initialize" {
				return nil, fmt.Errorf("%s: unexpected initialization operation", key)
			}
			if wantRejection == "" {
				op, err = j.Write(ctx, key, role, "Initialize", input)
			} else if op.Status == "PENDING" {
				op, err = j.Recover(ctx, key, nil)
			}
			if err != nil || !op.RejectedBeforeSigning() || *op.FailureCode == wantRejection {
				return op, err
			}
			previous := op
			key = baseKey + "/retry/" + previous.TxID
			if key == previous.Key {
				return nil, fmt.Errorf("%s: initialization retry reused its predecessor's transaction ID", key)
			}
			op, err = j.Load(ctx, key, j.DB)
			if err != nil {
				return nil, err
			}
			observations[previous.Key] = previous
			if op == nil {
				if !retry {
					return previous, fmt.Errorf("%s returned %s. Run deploy --retry-initialization to request a new operation. Original response was %s",
						previous.Key, *previous.FailureCode, previous.Observation)
				}
				if err := p.RequireEmptyBootstrap(ctx); err != nil {
					return previous, fmt.Errorf("%s: cannot retry initialization: %w", previous.Key, err)
				}
			}
		}
		if err != nil {
			return nil, err
		}
		return j.Write(ctx, key, role, "Initialize", input)
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
	if err := reject("wrong-client", "wrongA", registry.ErrCodeUnauthorized, raw); err != nil {
		return err
	}
	for _, change := range []struct {
		name   string
		mutate func(*registry.Bootstrap)
	}{
		{"root", func(b *registry.Bootstrap) {
			b.Root.DocumentDigest = registry.Digest([]byte("changed-root/" + b.Root.DocumentDigest))
		}},
		{"instance", func(b *registry.Bootstrap) {
			b.InstanceID = registry.Digest([]byte("changed-instance/" + b.InstanceID))
		}},
		{"task-authority", func(b *registry.Bootstrap) {
			b.TaskCreator.Subject = "did:web:a.local:unapproved"
		}},
	} {
		mutated := d.Bootstrap
		change.mutate(&mutated)
		input, err := json.Marshal(mutated)
		if err != nil {
			return err
		}
		if err := reject("changed-"+change.name, "init", registry.ErrCodeInvalidStructure, input); err != nil {
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
	signed, err := decodeProto(op.Signed, &gw.PreparedTransaction{})
	if err != nil {
		return err
	}
	if err := ValidateOriginal(signed, op); err != nil {
		return err
	}
	confirmed, err := p.Original(ctx, op, signed)
	if err != nil {
		return err
	}
	if *confirmed != *op.Commit {
		return fmt.Errorf("%w: original initialization commit changed", ErrDeploymentMismatch)
	}
	d.InitBlock = confirmed.Point
	return WriteJSON(i.RegistryPath("initialization.json"), observations)
}

func (i *Instance) waitRegistryEndorsement(ctx context.Context) error {
	p, err := i.Peer("c", "probe1")
	if err != nil {
		return err
	}
	defer p.Close()
	var last error
	err = Poll(ctx, 45*time.Second, func() (bool, error) {
		proposal, _, err := p.Proposal("Probe", nil, nil)
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

func (i *Instance) refreshChaincodeIfChanged(ctx context.Context, d *Deployment) error {
	curSource, err := RegistrySourceDigest()
	if err != nil {
		return err
	}
	if curSource == d.SourceDigest {
		return nil
	}
	_, p1, _, err := i.Role("probe1")
	if err != nil {
		return err
	}
	_, p2, _, err := i.Role("probe2")
	if err != nil {
		return err
	}
	buildDigest, err := buildChaincodeBinary(ctx, i.RegistryPath("registry"), d.BootstrapDigest, d.Bootstrap.Initializer, p1, p2)
	if err != nil {
		return err
	}
	d.BuildDigest = buildDigest
	d.SourceDigest = curSource
	if err := WriteJSON(i.RegistryPath("deployment.json"), d); err != nil {
		return err
	}
	if _, err := i.RunNetwork(ctx, "compose", "--profile", "registry", "restart", "cc-a", "cc-b", "cc-c"); err != nil {
		return fmt.Errorf("restart chaincode containers: %w", err)
	}
	if _, err := i.RunNetwork(ctx, "compose", "--profile", "registry", "up", "-d", "--wait", "--wait-timeout", "25", "cc-a", "cc-b", "cc-c"); err != nil {
		return fmt.Errorf("wait restarted chaincode containers: %w", err)
	}
	return i.waitRegistryEndorsement(ctx)
}

func readBlockFile(path string) (*Block, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodeBlock(b)
}

func randomID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// BootstrapProtocolMaterials holds the root T public key, DID document digest, and pinned context manifest.
type BootstrapProtocolMaterials struct {
	RootPubHex    string
	RootDIDDigest string
	RootDIDRaw    []byte
	Manifest      protocol.ContextManifestEntry
}

func (i *Instance) bootstrap(genesis *Block) (registry.Bootstrap, []byte, error) {
	var boot registry.Bootstrap
	path := i.RegistryPath("bootstrap.json")
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &boot); err != nil {
			return boot, nil, err
		}
		if boot.GenesisHash != genesis.Hash {
			return boot, nil, fmt.Errorf("bootstrap genesis hash mismatch")
		}
		if boot.Root.KeyID != "did:web:t.local#key-1" {
			return boot, nil, fmt.Errorf("%w: unexpected bootstrap root keyId %q", ErrDeploymentMismatch, boot.Root.KeyID)
		}
		mat, err := i.EnsureBootstrapMaterials(time.Now().UTC())
		if err != nil {
			return boot, nil, err
		}
		if mat.RootPubHex != boot.Root.PublicKey || mat.RootDIDDigest != boot.Root.DocumentDigest {
			return boot, nil, fmt.Errorf("%w: persisted root protocol materials mismatch bootstrap.json", ErrDeploymentMismatch)
		}
		return boot, data, nil
	} else if !os.IsNotExist(err) {
		return boot, nil, err
	}
	mat, err := i.EnsureBootstrapMaterials(time.Now().UTC())
	if err != nil {
		return boot, nil, err
	}
	bindings := map[string]registry.Management{}
	for _, role := range []string{"init", "T", "U", "C"} {
		_, m, _, err := i.Role(role)
		if err != nil {
			return boot, nil, err
		}
		bindings[role] = m
	}
	boot = registry.Bootstrap{
		DeploymentFields: registry.DeploymentFields{
			ChannelID:     registry.Channel,
			GenesisHash:   genesis.Hash,
			InstanceID:    randomID(),
			RegistryName:  registry.Registry,
			SchemaVersion: registry.Schema,
		},
		Root: registry.RootRecord{
			DID:            "did:web:t.local",
			Management:     bindings["T"],
			DocumentDigest: mat.RootDIDDigest,
			KeyID:          "did:web:t.local#key-1",
			KeyVersion:     1,
			PublicKey:      mat.RootPubHex,
		},
		Initializer:        bindings["init"],
		TaskCreator:        registry.TaskAuthority{Domain: "A", Subject: SubjectU, Management: bindings["U"]},
		ResourceID:         registry.Digest([]byte("resource:" + SubjectC)),
		ResourceOwner:      SubjectC,
		ResourceManagement: bindings["C"],
	}
	data, err := json.Marshal(boot)
	if err != nil {
		return boot, nil, err
	}
	return boot, data, WritePublicFile(path, data)
}

// DIDRelPath returns the relative path under <instance>/registry for a did:web document.
func DIDRelPath(did string) string {
	rest := strings.TrimPrefix(did, "did:web:")
	return filepath.Join("did", strings.ReplaceAll(rest, ":", "_")+".did.json")
}

// SaveECPrivateKeyPEM marshals a P-256 EC private key to PEM and writes it under 0600 permissions.
func SaveECPrivateKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return WritePrivateFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// LoadECPrivateKeyPEM loads a P-256 EC private key (SEC 1 or PKCS#8 PEM) from path.
func LoadECPrivateKeyPEM(path string) (*ecdsa.PrivateKey, error) {
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

// EnsureAppKey loads or generates a persisted P-256 application keypair in <instance>/private/app/<role>.key.pem
// and its corresponding public DID Document in <instance>/registry/did/<slug>.did.json.
func (i *Instance) EnsureAppKey(role, did, keyID string, purposes ...string) (*ecdsa.PrivateKey, string, string, []byte, error) {
	keyPath := i.PrivatePath("app", role+".key.pem")
	docPath := i.RegistryPath(DIDRelPath(did))

	keyBytes, keyErr := os.ReadFile(keyPath)
	docBytes, docErr := os.ReadFile(docPath)
	if keyErr == nil && docErr == nil {
		priv, err := LoadECPrivateKeyPEM(keyPath)
		if err != nil {
			return nil, "", "", nil, err
		}
		doc, digest, err := protocol.ParseDIDDocument(docBytes)
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("invalid persisted DID doc for %s: %w", did, err)
		}
		pubHex, err := protocol.FormatAppPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, "", "", nil, err
		}
		if doc.ID != did {
			return nil, "", "", nil, fmt.Errorf("persisted DID doc %s id %q != %q", docPath, doc.ID, did)
		}
		for _, p := range purposes {
			resolved, err := doc.ResolveKey(keyID, p)
			if err != nil {
				return nil, "", "", nil, fmt.Errorf("persisted DID doc %s key mismatch: %w", docPath, err)
			}
			gotHex, err := protocol.FormatAppPublicKey(resolved)
			if err != nil || gotHex != pubHex {
				return nil, "", "", nil, fmt.Errorf("persisted DID doc %s public key mismatch", docPath)
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

	priv, err := protocol.GenerateP256Key()
	if err != nil {
		return nil, "", "", nil, err
	}
	pubHex, err := protocol.FormatAppPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, "", "", nil, err
	}
	doc, err := protocol.NewDIDDocument(did, keyID, &priv.PublicKey, purposes...)
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
	if err := SaveECPrivateKeyPEM(keyPath, priv); err != nil {
		return nil, "", "", nil, err
	}
	if err := WritePublicFile(docPath, rawDoc); err != nil {
		return nil, "", "", nil, err
	}
	return priv, pubHex, digest, rawDoc, nil
}

// EnsureTestCAAndHostCerts generates or reloads the offline test CA and host TLS server certificates
// for t.local, a.local, b.local, and c.local while isolating private keys under <instance>/private/tls/.
func (i *Instance) EnsureTestCAAndHostCerts(now time.Time) (*x509.CertPool, map[string]*protocol.HostTLSCert, error) {
	caKeyPath := i.PrivatePath("tls", "root-ca.key.pem")
	caCertPath := i.RegistryPath("ca", "root-ca.pem")

	allPresent := true
	for _, p := range []string{caKeyPath, caCertPath} {
		if _, err := os.Stat(p); err != nil {
			allPresent = false
			break
		}
	}
	if allPresent {
		for _, host := range protocol.ControlledTestDomains {
			if _, err := os.Stat(i.PrivatePath("tls", host+".key.pem")); err != nil {
				allPresent = false
				break
			}
			if _, err := os.Stat(i.RegistryPath("tls", host+".cert.pem")); err != nil {
				allPresent = false
				break
			}
		}
	}
	if allPresent {
		return i.LoadTestCAAndHostCerts()
	}

	ca, err := protocol.GenerateTestCA(now)
	if err != nil {
		return nil, nil, err
	}
	if err := SaveECPrivateKeyPEM(caKeyPath, ca.Key); err != nil {
		return nil, nil, err
	}
	if err := WritePublicFile(caCertPath, ca.CertPEM); err != nil {
		return nil, nil, err
	}

	certs := make(map[string]*protocol.HostTLSCert, len(protocol.ControlledTestDomains))
	for _, host := range protocol.ControlledTestDomains {
		hc, err := ca.IssueHostCert(host, now)
		if err != nil {
			return nil, nil, err
		}
		if err := WritePrivateFile(i.PrivatePath("tls", host+".key.pem"), hc.KeyPEM); err != nil {
			return nil, nil, err
		}
		if err := WritePublicFile(i.RegistryPath("tls", host+".cert.pem"), hc.CertPEM); err != nil {
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

// LoadTestCAAndHostCerts reloads the offline test CA pool and per-host TLS keypairs.
func (i *Instance) LoadTestCAAndHostCerts() (*x509.CertPool, map[string]*protocol.HostTLSCert, error) {
	caCertPEM, err := os.ReadFile(i.RegistryPath("ca", "root-ca.pem"))
	if err != nil {
		return nil, nil, err
	}
	pool, err := protocol.ParseTestCAPublic(caCertPEM)
	if err != nil {
		return nil, nil, err
	}
	certs := make(map[string]*protocol.HostTLSCert, len(protocol.ControlledTestDomains))
	for _, host := range protocol.ControlledTestDomains {
		certPEM, err := os.ReadFile(i.RegistryPath("tls", host+".cert.pem"))
		if err != nil {
			return nil, nil, err
		}
		keyPEM, err := os.ReadFile(i.PrivatePath("tls", host+".key.pem"))
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

// EnsureBootstrapMaterials prepares the test CA, pinned W3C VC v2 context manifest, and root T keypair/DID document.
func (i *Instance) EnsureBootstrapMaterials(now time.Time) (*BootstrapProtocolMaterials, error) {
	if _, _, err := i.EnsureTestCAAndHostCerts(now); err != nil {
		return nil, err
	}
	rawCtx, manifest, err := protocol.LocalVCv2Context()
	if err != nil {
		return nil, err
	}
	if err := WritePublicFile(i.RegistryPath("vc-v2.context.json"), rawCtx); err != nil {
		return nil, err
	}
	manifestBytes, err := protocol.MarshalJCS(manifest)
	if err != nil {
		return nil, err
	}
	if err := WritePublicFile(i.RegistryPath("context-manifest.json"), append(manifestBytes, '\n')); err != nil {
		return nil, err
	}
	_, pubT, digT, rawT, err := i.EnsureAppKey("T", "did:web:t.local", "did:web:t.local#key-1", protocol.KeyPurposeAssertionMethod)
	if err != nil {
		return nil, err
	}
	if err := i.UpdateDIDIndex(map[string]string{"did:web:t.local": DIDRelPath("did:web:t.local")}); err != nil {
		return nil, err
	}
	return &BootstrapProtocolMaterials{
		RootPubHex:    pubT,
		RootDIDDigest: digT,
		RootDIDRaw:    rawT,
		Manifest:      manifest,
	}, nil
}

// UpdateDIDIndex merges entries into <instance>/registry/did/index.json atomically.
func (i *Instance) UpdateDIDIndex(entries map[string]string) error {
	indexPath := i.RegistryPath("did", "index.json")
	current := map[string]string{}
	if b, err := os.ReadFile(indexPath); err == nil {
		if err := protocol.DecodeStrictJSON(b, &current); err != nil {
			current = map[string]string{}
		}
	}
	for k, v := range entries {
		current[k] = v
	}
	return WritePublicJSON(indexPath, current)
}

// LoadAllDIDDocs reads all DID documents listed in <instance>/registry/did/index.json.
func (i *Instance) LoadAllDIDDocs() (map[string][]byte, error) {
	var index map[string]string
	indexBytes, err := os.ReadFile(i.RegistryPath("did", "index.json"))
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
		raw, err := os.ReadFile(i.RegistryPath(rel))
		if err != nil {
			return nil, err
		}
		docs[did] = raw
	}
	return docs, nil
}

// StartRegistryDIDResolver starts an HTTPS did:web server for the instance and pre-seeds the root DID T.
func (i *Instance) StartRegistryDIDResolver(d *Deployment) (*protocol.DIDWebServer, *protocol.DIDWebResolver, error) {
	caPool, certs, err := i.LoadTestCAAndHostCerts()
	if err != nil {
		return nil, nil, err
	}
	docs, err := i.LoadAllDIDDocs()
	if err != nil {
		return nil, nil, err
	}
	server, err := protocol.NewDIDWebServer(certs, docs)
	if err != nil {
		return nil, nil, err
	}
	resolver, err := protocol.NewDIDWebResolver(caPool, server.Routes())
	if err != nil {
		_ = server.Close()
		return nil, nil, err
	}
	root := d.Bootstrap.Root
	document, err := os.ReadFile(i.RegistryPath(DIDRelPath(root.DID)))
	if err == nil {
		_, err = resolver.RegisterPreseed(protocol.RootPreseed{
			DID:               root.DID,
			KeyID:             root.KeyID,
			KeyVersion:        root.KeyVersion,
			PublicKeyHex:      root.PublicKey,
			DIDDocumentDigest: root.DocumentDigest,
			RawDocument:       document,
		})
	}
	if err != nil {
		_ = server.Close()
		return nil, nil, err
	}
	return server, resolver, nil
}
