package fabric

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	gw "github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

type instance struct {
	dir string
	env map[string]string
}

func loadInstance(dir string) (*instance, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "network.env"))
	if err != nil {
		return nil, err
	}
	i := &instance{dir: dir, env: map[string]string{}}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid network setting %q", line)
		}
		i.env[key] = value
	}
	return i, nil
}

func (i *instance) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sh", append([]string{"infra/fabric/network.sh"}, args...)...)
	cmd.Env = append(os.Environ(), "FABRIC_INSTANCE="+i.dir)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return b, fmt.Errorf("network %s: %w: %s", args[0], err, b)
	}
	return b, nil
}

func (i *instance) port(name string) (string, error) {
	v := i.env[name]
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port %s", name)
	}
	return net.JoinHostPort("127.0.0.1", v), nil
}

func (i *instance) database(ctx context.Context) (*pgxpool.Pool, error) {
	host, err := i.port("FABRIC_DB")
	if err != nil {
		return nil, err
	}
	pw, err := os.ReadFile(filepath.Join(i.dir, "view-password"))
	if err != nil {
		return nil, err
	}
	dsn := url.URL{Scheme: "postgres", Host: host, User: url.UserPassword("view", strings.TrimSpace(string(pw))), Path: "/fabric", RawQuery: "sslmode=disable"}
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

type roleLocation struct{ org, user string }

var roles = map[string]roleLocation{
	"init": {"a", "User1"}, "T": {"t", "User1"},
	"domainA": {"a", "User2"}, "registrarA": {"a", "User3"}, "IA": {"a", "User4"},
	"U": {"a", "User5"}, "A1": {"a", "User6"}, "alt": {"a", "User7"}, "wrongA": {"a", "User8"},
	"domainB": {"b", "User2"}, "registrarB": {"b", "User3"}, "IB": {"b", "User4"}, "B1": {"b", "User5"},
	"domainC": {"c", "User2"}, "registrarC": {"c", "User3"}, "IC": {"c", "User4"},
	"C": {"c", "User5"}, "probe1": {"c", "User6"}, "probe2": {"c", "User7"},
	"read": {"c", "User8"}, "rogue": {"x", "User1"},
	"adminA": {"a", "Admin"}, "adminB": {"b", "Admin"}, "adminC": {"c", "Admin"},
}

func (i *instance) orgDir(org string) string {
	return filepath.Join(i.dir, "crypto", "peerOrganizations", org+".local")
}

func (i *instance) peerTLS(org string) string {
	return filepath.Join(i.orgDir(org), "peers", "peer-"+org+"."+org+".local", "tls", "ca.crt")
}

func (i *instance) role(role string) (*identity.X509Identity, api.Management, string, error) {
	r, ok := roles[role]
	if !ok {
		return nil, api.Management{}, "", fmt.Errorf("unknown client role %q", role)
	}
	user := r.user + "@" + r.org + ".local"
	mspDir := filepath.Join(i.orgDir(r.org), "users", user, "msp")
	certPEM, err := os.ReadFile(filepath.Join(mspDir, "signcerts", user+"-cert.pem"))
	if err != nil {
		return nil, api.Management{}, "", err
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		return nil, api.Management{}, "", err
	}
	mspID := strings.ToUpper(r.org) + "Msp"
	id, err := identity.NewX509Identity(mspID, cert)
	return id, api.Management{MSPID: mspID, Fingerprint: api.Digest(cert.Raw)}, mspDir, err
}

type peerClient struct {
	conn    *grpc.ClientConn
	gateway *client.Gateway
	signer  identity.Sign
	role    api.Management
}

func (i *instance) peer(org, role string) (*peerClient, error) {
	address, err := i.port("FABRIC_PEER_" + strings.ToUpper(org))
	if err != nil {
		return nil, err
	}
	id, binding, mspDir, err := i.role(role)
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
	conn, err := dialTLS(address, "peer-"+org, i.peerTLS(org))
	if err != nil {
		return nil, err
	}
	g, err := client.Connect(id, client.WithSign(sign), client.WithClientConnection(conn),
		client.WithEndorseTimeout(6*time.Second), client.WithEvaluateTimeout(3*time.Second),
		client.WithSubmitTimeout(4*time.Second), client.WithCommitStatusTimeout(4*time.Second))
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &peerClient{conn: conn, gateway: g, signer: sign, role: binding}, nil
}

func dialTLS(address, serverName, rootPath string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
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

func (p *peerClient) close() {
	p.gateway.Close()
	p.conn.Close()
}

func (p *peerClient) contract(name string) *client.Contract {
	return p.gateway.GetNetwork(api.Channel).GetContract(name)
}

type peerResponseError struct {
	status  int32
	message string
}

func (e *peerResponseError) Error() string {
	return fmt.Sprintf("peer response %d: %s", e.status, e.message)
}

func missingRegistryRecord(err error) bool {
	var response *peerResponseError
	return errors.As(err, &response) && response.status == 500 && response.message == "D0:MISSING_DEPENDENCY"
}

// direct uses the pinned Peer Endorser endpoint. Gateway Evaluate may select another Peer.
func (p *peerClient) direct(ctx context.Context, chaincode, method string, args ...string) ([]byte, error) {
	proposal, err := p.contract(chaincode).NewProposal(method, client.WithArguments(args...))
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
		return nil, &peerResponseError{status: response.GetStatus(), message: response.GetMessage()}
	}
	return response.GetPayload(), nil
}

func writeJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(b, '\n'), 0600)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func readJSON(path string, into any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

// awaitEndorsers lets fixture producers wait for a known dependency to reach
// the entire healthy acceptance topology before creating a dependent proposal.
func (i *instance) awaitEndorsers(ctx context.Context, committed outcome) error {
	for _, org := range []string{"a", "b", "c"} {
		p, err := i.peer(org, "read")
		if err != nil {
			return err
		}
		err = poll(ctx, 8*time.Second, func() (bool, error) {
			b, err := p.getBlock(ctx, committed.Number)
			if err != nil {
				return false, nil
			}
			if b.Hash != committed.Hash || committed.Index < 0 || committed.Index >= len(b.Transactions) ||
				b.Transactions[committed.Index].Code.String() != committed.Code {
				return false, fmt.Errorf("Peer %s has a conflicting dependency at block %d", org, committed.Number)
			}
			return true, nil
		})
		p.close()
		if err != nil {
			return fmt.Errorf("wait for dependency at Peer %s: %w", org, err)
		}
	}
	return nil
}
func poll(ctx context.Context, d time.Duration, f func() (bool, error)) error {
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
