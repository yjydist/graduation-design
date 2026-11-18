package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"graduation-design/internal/fabric"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"
)

// These are the fields read from the existing ledgerctl JSON and public fixture files.
type deployment struct {
	DeploymentID string          `json:"deploymentId"`
	Bootstrap    api.Bootstrap   `json:"bootstrap"`
	Raw          json.RawMessage `json:"-"`
}

type fixture struct {
	Domains                            map[string]api.DomainBootstrap
	Certifications                     map[string]api.Certify
	Identities                         map[string]api.Identity
	Credentials                        map[string]api.Credential
	IdentityLink                       api.IdentityLink
	M2TaskSpec                         protocol.TaskSpec
	RPTask, BMTask                     api.Task
	RPG0, RPG1, RPG2, BMG0, BMG1, BMG2 api.Grant
}

type point struct {
	Number uint64 `json:"blockNumber"`
	Hash   string `json:"blockHash"`
}

type operation struct {
	Key         string  `json:"operationKey"`
	TxID        string  `json:"txId"`
	Status      string  `json:"status"`
	Stage       string  `json:"stage"`
	FailureCode *string `json:"failureCode"`
	Observation string  `json:"observation"`
	Commit      *struct {
		point
		Code string `json:"validationCode"`
	} `json:"commit"`
}

type seedReport struct {
	Operations []*operation `json:"operations"`
}
type instance struct{ dir string }

func (i instance) registrySubPath(parts ...string) string {
	return filepath.Join(append([]string{i.dir, "registry"}, parts...)...)
}

func (i instance) privatePath(parts ...string) string {
	return filepath.Join(append([]string{i.dir, "private"}, parts...)...)
}

func (i instance) database(ctx context.Context) (*pgxpool.Pool, error) {
	data, err := os.ReadFile(filepath.Join(i.dir, "network.env"))
	if err != nil {
		return nil, err
	}
	var port string
	for _, line := range strings.Split(string(data), "\n") {
		if name, value, ok := strings.Cut(line, "="); ok && name == "FABRIC_DB" {
			port = value
			break
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("invalid Fabric view port")
	}
	password, err := os.ReadFile(filepath.Join(i.dir, "view-password"))
	if err != nil {
		return nil, err
	}
	dsn := url.URL{Scheme: "postgres", Host: net.JoinHostPort("127.0.0.1", port),
		User: url.UserPassword("view", strings.TrimSpace(string(password))), Path: "/fabric", RawQuery: "sslmode=disable"}
	pool, err := pgxpool.New(ctx, dsn.String())
	if err != nil {
		return nil, fmt.Errorf("invalid local view database configuration")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("isolated view database unavailable")
	}
	return pool, nil
}

func (e *e1Trial) command(ctx context.Context, output any, command string, extra ...string) error {
	args := append([]string{command, "--dir", e.instance.dir}, extra...)
	cmd := exec.CommandContext(ctx, e.ledgerctl, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if len(raw) != 0 && output != nil {
		if decodeErr := json.Unmarshal(raw, output); decodeErr != nil {
			return fmt.Errorf("ledgerctl %s malformed JSON: %w", command, decodeErr)
		}
	}
	if err != nil {
		return fmt.Errorf("ledgerctl %s: %w: %s", command, err, e.redact(strings.TrimSpace(stderr.String())))
	}
	if d, ok := output.(*deployment); ok {
		d.Raw = raw
	}
	return nil
}

func (e *e1Trial) prepareRegistry() error {
	// The stock MCP command prepares the fixture files when its wallet starts.
	// Listing tools opens that wallet without executing any business tool.
	cmd := exec.CommandContext(e.ctx, e.ledgerctl, "mcp", "--dir", e.instance.dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "E1 fixture client", Version: "1"}, nil)
	session, err := client.Connect(e.ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		return fmt.Errorf("open stock MCP wallet: %w: %s", err, e.redact(stderr.String()))
	}
	if _, err := session.ListTools(e.ctx, nil); err != nil {
		_ = session.Close()
		return fmt.Errorf("list stock MCP tools: %w", err)
	}
	if err := session.Close(); err != nil {
		return err
	}
	source, err := os.ReadFile(e.instance.registrySubPath("fixtures.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(source, &e.f); err != nil {
		return err
	}
	pending := map[string]*operation{}
	for _, pair := range []struct{ domain, role string }{{"A", "U"}, {"B", "B1"}, {"C", "C"}} {
		// Use the same operation key and bytes as seed so its normal retry resumes from this step.
		if _, err := e.invoke("seed/domain-"+pair.domain, "T", "BootstrapDomain", e.f.Domains[pair.domain], "VALID"); err != nil {
			return err
		}
		op, err := e.invoke(e.id+"/F01-pending-"+pair.domain, "registrar"+pair.domain, "RegisterIdentity", e.f.Identities[pair.role], "INVALID_STATE")
		if err != nil {
			return err
		}
		pending[pair.domain] = op
	}
	if err := e.save("F01-pending", pending); err != nil {
		return err
	}
	var raw json.RawMessage
	runErr := e.command(e.ctx, &raw, "seed")
	if len(raw) != 0 {
		runErr = errors.Join(runErr, e.save("seed", raw), json.Unmarshal(raw, &e.seed))
	}
	e.seed.Operations = append(e.seed.Operations, pending["A"], pending["B"], pending["C"])
	return runErr
}

func (e *e1Trial) invoke(label, role, method string, input any, expected string) (*operation, error) {
	file, err := os.CreateTemp(e.instance.dir, "e1-input-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(file.Name())
	// ledgerctl hashes its compact argument, so use json.Marshal and retain the seed field order.
	data, err := json.Marshal(input)
	if err == nil {
		_, err = file.Write(data)
	}
	if err := errors.Join(err, file.Close()); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	runErr := e.command(e.ctx, &raw, "invoke", "--key", label, "--role", role, "--method", method, "--input", file.Name())
	if len(raw) == 0 {
		return nil, runErr
	}
	e.event("operation", raw)
	var op operation
	if err := json.Unmarshal(raw, &op); err != nil {
		return nil, errors.Join(runErr, err)
	}
	if runErr != nil {
		return &op, runErr
	}
	if expected == "VALID" && op.Status == "CONFIRMED" && op.Commit != nil && op.Commit.Code == "VALID" {
		return &op, nil
	}
	if expected != "VALID" && op.Status == "FAILED" && op.FailureCode != nil && *op.FailureCode == expected {
		return &op, nil
	}
	return &op, fmt.Errorf("%s expected %s; observed %s at %s (%s)", label, expected, op.Status, op.Stage, op.Observation)
}

func (e *e1Trial) op(label, role, method string, input any, expected string) (*operation, error) {
	return e.invoke(e.id+"/"+label, role, method, input, expected)
}

func (e *e1Trial) seedOperation(label string) *operation {
	for _, op := range e.seed.Operations {
		if op != nil && op.Key == "seed/"+label {
			return op
		}
	}
	return nil
}

type checkResult struct {
	point
	DeploymentID string                     `json:"deploymentId"`
	Probe        fabric.ProbeSnapshot       `json:"probe"`
	Records      map[string]json.RawMessage `json:"records"`
}

type liveState struct {
	gateway.StateSource
	trial *e1Trial
}

func (s *liveState) AssembleSnapshot(ctx context.Context, leaf string, now time.Time) (*gateway.ConsistentSnapshot, error) {
	if _, err := s.trial.refresh(ctx, leaf); err != nil {
		return nil, err
	}
	return s.StateSource.AssembleSnapshot(ctx, leaf, now)
}

func (e *e1Trial) refresh(ctx context.Context, leaf string) (checkResult, error) {
	if leaf == "" {
		leaf = e.f.RPG2.ID
	}
	send := time.Now()
	var check checkResult
	if err := e.command(ctx, &check, "check", "--grant", leaf, "--timeout", "18s"); err != nil {
		e.event("probe_failed", e.redact(err.Error()))
		return check, protocol.WrapError(protocol.ErrCodeStateUnavailable, "ledgerctl check", err)
	}
	received := time.Now()
	p := check.Probe
	duration := p.Deadline.Sub(p.SentAt)
	if check.DeploymentID != e.d.DeploymentID || p.TxID == "" || p.ProbeBlock > check.Number ||
		p.SentAt.Before(send) || p.SentAt.After(received) || duration != api.ProbeLifetime ||
		p.DeadlineMonoNs-p.SentMonoNs != duration.Nanoseconds() || !received.Before(p.Deadline) {
		return check, protocol.NewError(protocol.ErrCodeStateStale, "expired or foreign ledgerctl probe")
	}
	// Re-anchor wall timestamps to the driver's local monotonic clock on the same host.
	// The probe ID, relative monotonic budget and original expiry come from the subprocess.
	p.SentAt = received.Add(p.SentAt.Sub(received))
	p.Deadline = p.SentAt.Add(duration)
	e.sp.SetStaticProbe(&p)
	e.event("probe", map[string]any{"case": e.stage, "deploymentId": check.DeploymentID, "checkpoint": check.point, "probe": p})
	return check, nil
}

func (e *e1Trial) currentView(ctx context.Context, leaf string) (*fabric.ConsistentProtocolView, error) {
	if _, err := e.refresh(ctx, leaf); err != nil {
		return nil, err
	}
	return e.sp.AssembleProtocolSnapshot(ctx, leaf, time.Now())
}

func (e *e1Trial) waitApplied(block uint64) error {
	check, err := e.refresh(e.ctx, e.f.RPG2.ID)
	if err != nil {
		return err
	}
	if check.Number < block {
		return fmt.Errorf("block %d has not been applied; current %d", block, check.Number)
	}
	return nil
}

func (e *e1Trial) rawAt(kind, id string, block uint64) ([]byte, error) {
	var raw []byte
	err := e.db.QueryRow(e.ctx, `SELECT value FROM fabric_version WHERE deployment=$1 AND key=$2 AND block_no<=$3 ORDER BY block_no DESC,tx_index DESC LIMIT 1`,
		e.d.DeploymentID, api.Key(kind, id), block).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

func currentRecord[T any](e *e1Trial, kind, id string) (T, error) {
	var value T
	var raw []byte
	if err := e.db.QueryRow(e.ctx, `SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2`, e.d.DeploymentID, api.Key(kind, id)).Scan(&raw); err != nil {
		return value, err
	}
	return value, json.Unmarshal(raw, &value)
}

func (e *e1Trial) absent(kind, id string) error {
	if _, err := currentRecord[json.RawMessage](e, kind, id); errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return fmt.Errorf("expected %s/%s absent from the Fabric view", kind, id)
}

func loadECPrivateKeyPEM(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("invalid EC key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func didRelPath(did string) string {
	return filepath.Join("did", strings.ReplaceAll(strings.TrimPrefix(did, "did:web:"), ":", "_")+".did.json")
}

func (i instance) loadTestCAAndHostCerts() (*x509.CertPool, map[string]*protocol.HostTLSCert, error) {
	raw, err := os.ReadFile(i.registrySubPath("ca", "root-ca.pem"))
	if err != nil {
		return nil, nil, err
	}
	ca, err := protocol.ParseTestCAPublic(raw)
	if err != nil {
		return nil, nil, err
	}
	certs := map[string]*protocol.HostTLSCert{}
	for _, host := range protocol.ControlledTestDomains {
		cert, err := tls.LoadX509KeyPair(i.registrySubPath("tls", host+".cert.pem"), i.privatePath("tls", host+".key.pem"))
		if err != nil {
			return nil, nil, err
		}
		certs[host] = &protocol.HostTLSCert{Host: host, TLSCert: cert}
	}
	return ca, certs, nil
}

func (e *e1Trial) newControlledDIDResolver() (*protocol.DIDWebServer, *protocol.DIDWebResolver, error) {
	ca, certs, err := e.instance.loadTestCAAndHostCerts()
	if err != nil {
		return nil, nil, err
	}
	rawIndex, err := os.ReadFile(e.instance.registrySubPath("did", "index.json"))
	if err != nil {
		return nil, nil, err
	}
	index := map[string]string{}
	if err := json.Unmarshal(rawIndex, &index); err != nil {
		return nil, nil, err
	}
	docs := map[string][]byte{}
	for did, path := range index {
		if path != didRelPath(did) {
			return nil, nil, fmt.Errorf("unexpected DID path for %s", did)
		}
		raw, err := os.ReadFile(e.instance.registrySubPath(path))
		if err != nil {
			return nil, nil, err
		}
		docs[did] = raw
	}
	server, err := protocol.NewDIDWebServer(certs, docs)
	if err != nil {
		return nil, nil, err
	}
	resolver, err := protocol.NewDIDWebResolver(ca, server.Routes())
	if err != nil {
		_ = server.Close()
		return nil, nil, err
	}
	root := e.d.Bootstrap.Root
	_, err = resolver.RegisterPreseed(protocol.RootPreseed{DID: root.DID, KeyID: root.KeyID, KeyVersion: root.KeyVersion, PublicKeyHex: root.PublicKey,
		DIDDocumentDigest: root.DocumentDigest, RawDocument: docs[root.DID]})
	if err != nil {
		_ = server.Close()
		return nil, nil, err
	}
	return server, resolver, nil
}

func decodeGrantPayload(jws string) (protocol.GrantClaims, error) {
	var claims protocol.GrantClaims
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return claims, fmt.Errorf("invalid compact grant JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, err
	}
	return claims, protocol.DecodeStrictJSON(raw, &claims)
}

func derefStr(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
