package bootstrap

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"grad/platform/core/dao/central"
	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/domain/policy"
	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/platform/core/ledger"
	"grad/platform/internal/mtls"
	apigw "grad/platform/service/api/gateway"
	"grad/platform/service/api/interdomain"
	apireg "grad/platform/service/api/registry"
	svcmcp "grad/platform/service/mcp"
	"grad/protocol"
)

const (
	defaultAudience     = "https://c.local"
	defaultSupplierID   = "urn:grad:supplier:C"
	defaultCurrency     = "CNY"
	defaultGatewayURL   = "http://127.0.0.1:8103"
	defaultAuditorDID   = "did:web:c.local:auditors:c1"
	defaultRecoveryDID  = "did:web:b.local:services:recovery"
	defaultAuditSvcDID  = "did:web:c.local:services:audit"
	receiptEndpointPath = "https://c.local" + interdomain.PathOrderOutcomeReceipts
)

// NewLocalMTLSClient creates an in-process HTTP client authenticated with a host-bound
// mTLS identity (DID, role, MSPID) without exposing internal/mtls outside grad/platform.
func NewLocalMTLSClient(handler http.Handler, did, role, mspID string) *http.Client {
	return mtls.NewLocalClient(handler, mtls.Identity{
		DID:   did,
		Role:  role,
		MSPID: mspID,
	})
}

// NewLocalMTLSClientWithFingerprint creates an in-process HTTP client authenticated with a
// host-bound mTLS identity including an X.509 DER SHA-256 certificate fingerprint.
func NewLocalMTLSClientWithFingerprint(handler http.Handler, did, role, mspID, fingerprint string) *http.Client {
	return mtls.NewLocalClient(handler, mtls.Identity{
		DID:         did,
		Role:        role,
		MSPID:       mspID,
		Fingerprint: fingerprint,
	})
}

// NewMTLSClient loads a real network mTLS client certificate, private key, and server CA bundle.
func NewMTLSClient(certPath, keyPath, caPath string) (*http.Client, error) {
	return mtls.NewMTLSClient(certPath, keyPath, caPath)
}

// RunMCP builds the instance's isolated wallet MCP server and serves JSON-RPC over in/out
// (or stdin/stdout when both in and out are nil).
func RunMCP(
	ctx context.Context,
	inst *ledger.Instance,
	dep *ledger.Deployment,
	db *pgxpool.Pool,
	gatewayURL string,
	in io.Reader,
	out io.Writer,
) error {
	if strings.TrimSpace(gatewayURL) == "" {
		gatewayURL = os.Getenv("GATEWAY_URL")
	}
	if strings.TrimSpace(gatewayURL) == "" {
		gatewayURL = defaultGatewayURL
	}
	f, err := LoadFixtures(inst)
	if err != nil {
		return err
	}
	w, err := BuildWallet(ctx, inst, dep, f, db, nil, WithGatewayURL(gatewayURL))
	if err != nil {
		return err
	}
	return RunMCPServer(ctx, svcmcp.NewMCPServer(w), in, out)
}

// RunMCPStdio serves the instance's isolated wallet MCP server on os.Stdin/os.Stdout.
func RunMCPStdio(ctx context.Context, inst *ledger.Instance, dep *ledger.Deployment, db *pgxpool.Pool, gatewayURL string) error {
	return RunMCP(ctx, inst, dep, db, gatewayURL, nil, nil)
}

// RunMCPServer runs srv over StdioTransport when in and out are both nil,
// or over IOTransport bound to in/out for deterministic stdio testing.
func RunMCPServer(ctx context.Context, srv *mcp.Server, in io.Reader, out io.Writer) error {
	return svcmcp.RunMCPServer(ctx, srv, in, out)
}

// RunInstanceMCP loads the deployment for inst, optionally opens PostgreSQL when
// offline is false, and serves the isolated wallet MCP server over in/out.
func RunInstanceMCP(
	ctx context.Context,
	inst *ledger.Instance,
	offline bool,
	gatewayURL string,
	in io.Reader,
	out io.Writer,
) error {
	if inst == nil {
		return fmt.Errorf("fabric instance is required")
	}
	dep, err := inst.LoadDeployment()
	if err != nil {
		return err
	}
	var db *pgxpool.Pool
	if !offline {
		db, err = inst.Database(ctx)
		if err != nil {
			return err
		}
		defer db.Close()
	}
	return RunMCP(ctx, inst, dep, db, gatewayURL, in, out)
}

// InvokeOperation submits or idempotently resumes a durable original-txID
// Fabric registry operation from raw JSON input against inst.
func InvokeOperation(
	ctx context.Context,
	inst *ledger.Instance,
	key, role, method string,
	raw []byte,
) (*ledger.Operation, error) {
	if inst == nil {
		return nil, fmt.Errorf("fabric instance is required")
	}
	dep, err := inst.LoadDeployment()
	if err != nil {
		return nil, err
	}
	db, err := inst.Database(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := ledger.EnsureSchema(ctx, db); err != nil {
		return nil, err
	}
	return ledger.NewJournal(inst, db, dep.DeploymentID).SubmitOrResume(ctx, dep, key, role, method, raw)
}

// InspectOperation queries or recovers an existing durable original-txID
// Fabric registry operation by key against inst.
func InspectOperation(ctx context.Context, inst *ledger.Instance, key string) (*ledger.Operation, error) {
	if inst == nil {
		return nil, fmt.Errorf("fabric instance is required")
	}
	dep, err := inst.LoadDeployment()
	if err != nil {
		return nil, err
	}
	db, err := inst.Database(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if err := ledger.EnsureSchema(ctx, db); err != nil {
		return nil, err
	}
	return ledger.NewJournal(inst, db, dep.DeploymentID).QueryOrRecover(ctx, dep, key)
}

// Stack holds a fully wired procurement runtime combining state source, DID resolver,
// OPA policy bundle, delivery service, optional management service + HTTP API, supplier gateway,
// and isolated wallet context.
type Stack struct {
	Instance      *ledger.Instance
	Deployment    *ledger.Deployment
	Fixtures      *Fixtures
	DB            *pgxpool.Pool
	State         ledger.StateSource
	FabricSP      *ledger.StateProvider
	Central       *central.Source
	DIDServer     *protocol.DIDWebServer
	DIDs          *protocol.DIDWebResolver
	Policy        *policy.VerifiedBundle
	Delivery      *domreg.DeliveryService
	Management    *domreg.Service
	ManagementAPI *apireg.Server
	Gateway       *apigw.Server
	Wallet        *wallet.WalletContext

	closeFns []func()
}

// Close releases background goroutines, streams, and local DID servers owned by the Stack.
func (s *Stack) Close() {
	if s == nil {
		return
	}
	for i := len(s.closeFns) - 1; i >= 0; i-- {
		if s.closeFns[i] != nil {
			s.closeFns[i]()
		}
	}
	s.closeFns = nil
}

type stackOptions struct {
	probeRole     string
	probeGrant    string
	probeInterval time.Duration
	probeLifetime time.Duration
	observe       func(event string, at time.Time, details any)
	policyBundle  *policy.VerifiedBundle
	sigCache      *protocol.SignatureCache
	nowFn         func() time.Time
	auditorDIDs   []string
	skipWallet    bool
}

// StackOption customizes StartFabricGatewayStack and StartCentralGatewayStack.
type StackOption func(*stackOptions)

// WithProbeRole selects the dedicated Fabric probe role ("probe1" or "probe2").
func WithProbeRole(role string) StackOption {
	return func(o *stackOptions) { o.probeRole = role }
}

// WithProbeCadence sets the Fabric liveness probe interval and original probe lifetime.
func WithProbeCadence(interval, lifetime time.Duration) StackOption {
	return func(o *stackOptions) {
		o.probeInterval = interval
		o.probeLifetime = lifetime
	}
}

// WithProbeGrant overrides the grant ID awaited when starting the online Fabric state view.
func WithProbeGrant(grantID string) StackOption {
	return func(o *stackOptions) { o.probeGrant = grantID }
}

// WithStateObserver installs an observer callback for Fabric block_applied, adopt, and probe events.
func WithStateObserver(fn func(event string, at time.Time, details any)) StackOption {
	return func(o *stackOptions) { o.observe = fn }
}

// WithPolicyBundle overrides the default compiled procurement OPA policy bundle.
func WithPolicyBundle(b *policy.VerifiedBundle) StackOption {
	return func(o *stackOptions) { o.policyBundle = b }
}

// WithSignatureCache installs a B1 static JWS signature verification cache on the gateway.
func WithSignatureCache(c *protocol.SignatureCache) StackOption {
	return func(o *stackOptions) { o.sigCache = c }
}

// WithStackNow overrides the wall-clock source shared by gateway and wallet.
func WithStackNow(fn func() time.Time) StackOption {
	return func(o *stackOptions) { o.nowFn = fn }
}

// WithAuditorDIDs overrides the authorized C auditor DID allowlist on the gateway.
func WithAuditorDIDs(dids ...string) StackOption {
	return func(o *stackOptions) { o.auditorDIDs = append([]string(nil), dids...) }
}

// StartFabricGatewayStack assembles a live Fabric-backed Stack (core/ledger + core/domain/policy +
// core/domain/registry + core/domain/gateway + service/api/{gateway,registry} + core/domain/wallet).
func StartFabricGatewayStack(
	ctx context.Context,
	inst *ledger.Instance,
	db *pgxpool.Pool,
	d *ledger.Deployment,
	f *Fixtures,
	opts ...StackOption,
) (*Stack, error) {
	if inst == nil || db == nil || d == nil {
		return nil, fmt.Errorf("instance, database pool, and deployment are required")
	}
	var cfg stackOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if f == nil {
		var err error
		f, err = LoadFixtures(inst)
		if err != nil {
			return nil, err
		}
	}
	if err := domgw.EnsureSchema(ctx, db, d.DeploymentID, defaultSupplierID); err != nil {
		return nil, err
	}
	probeRole := cfg.probeRole
	if probeRole == "" {
		probeRole = "probe1"
	}
	probeGrant := cfg.probeGrant
	if probeGrant == "" {
		probeGrant = f.RPG2.ID
		if probeGrant == "" {
			probeGrant = f.G1.ID
		}
	}
	sp, stopSP, err := inst.StartObservedStateProvider(ctx, db, d, probeRole, probeGrant, cfg.probeInterval, cfg.probeLifetime, cfg.observe)
	if err != nil {
		return nil, err
	}
	mgmtSvc, _, err := domreg.NewFabricServiceWithDB(db, inst, d)
	if err != nil {
		stopSP()
		return nil, err
	}
	st, err := assembleGatewayStack(ctx, inst, db, d, f, sp, sp, nil, mgmtSvc, cfg, stopSP)
	if err != nil {
		stopSP()
		return nil, err
	}
	return st, nil
}

// StartCentralGatewayStack assembles a PostgreSQL centralized-registry Stack
// (core/dao/central + core/domain/policy + core/domain/registry + core/domain/gateway +
// service/api/gateway + core/domain/wallet).
func StartCentralGatewayStack(
	ctx context.Context,
	inst *ledger.Instance,
	db *pgxpool.Pool,
	d *ledger.Deployment,
	f *Fixtures,
	opts ...StackOption,
) (*Stack, error) {
	if inst == nil || db == nil || d == nil {
		return nil, fmt.Errorf("instance, database pool, and deployment are required")
	}
	var cfg stackOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if f == nil {
		var err error
		f, err = LoadFixtures(inst)
		if err != nil {
			return nil, err
		}
	}
	if err := domgw.EnsureSchema(ctx, db, d.DeploymentID, defaultSupplierID); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if cfg.nowFn != nil {
		now = cfg.nowFn().UTC()
	}
	snap := BuildFixtureSnapshot(d, f, now)
	src, err := central.Initialize(ctx, db, snap)
	if err != nil {
		return nil, err
	}
	return assembleGatewayStack(ctx, inst, db, d, f, src, nil, src, nil, cfg, nil)
}

func assembleGatewayStack(
	ctx context.Context,
	inst *ledger.Instance,
	db *pgxpool.Pool,
	d *ledger.Deployment,
	f *Fixtures,
	src ledger.StateSource,
	fabricSP *ledger.StateProvider,
	centralSrc *central.Source,
	mgmtSvc *domreg.Service,
	cfg stackOptions,
	stopState func(),
) (*Stack, error) {
	didSrv, resolver, err := inst.StartRegistryDIDResolver(d)
	if err != nil {
		return nil, err
	}
	cleanup := []func(){func() { _ = didSrv.Close() }}
	if stopState != nil {
		cleanup = append([]func(){stopState}, cleanup...)
	}

	pol := cfg.policyBundle
	if pol == nil {
		files, digest, err := policy.BuildDefaultBundle(d.DeploymentID, f.Identities["C"].ID, policy.DefaultPolicyVersion, d.Bootstrap.Root, nil)
		if err != nil {
			_ = didSrv.Close()
			return nil, err
		}
		pol, err = policy.VerifyAndLoadBundle(files, d.DeploymentID, f.Identities["C"].ID, d.Bootstrap.Root, digest)
		if err != nil {
			_ = didSrv.Close()
			return nil, err
		}
	}

	auditors := cfg.auditorDIDs
	if len(auditors) == 0 {
		auditors = []string{defaultAuditorDID}
	}
	ds := domreg.NewDeliveryService(db, d.DeploymentID)
	gwSvc, err := domgw.NewService(domgw.Config{
		DB:             db,
		State:          src,
		CertChecker:    ds,
		DIDs:           resolver,
		Policy:         pol,
		SignatureCache: cfg.sigCache,
		AuditorDIDs:    auditors,
		VerifierID:     auditors[0],
		DeploymentID:   d.DeploymentID,
		ServiceDID:     f.Identities["C"].ID,
		Audience:       defaultAudience,
		SupplierID:     defaultSupplierID,
		NowFn:          cfg.nowFn,
	})
	if err != nil {
		_ = didSrv.Close()
		return nil, err
	}
	gw, err := apigw.NewServer(gwSvc)
	if err != nil {
		_ = didSrv.Close()
		return nil, err
	}

	var mgmtAPI *apireg.Server
	if mgmtSvc != nil {
		mgmtAPI = apireg.NewServer(mgmtSvc)
	}

	var walletCtx *wallet.WalletContext
	if !cfg.skipWallet {
		walletCtx, err = BuildWallet(ctx, inst, d, f, db, gw.Handler(), WithNow(cfg.nowFn))
		if err != nil {
			_ = didSrv.Close()
			return nil, err
		}
	}

	return &Stack{
		Instance:      inst,
		Deployment:    d,
		Fixtures:      f,
		DB:            db,
		State:         src,
		FabricSP:      fabricSP,
		Central:       centralSrc,
		DIDServer:     didSrv,
		DIDs:          resolver,
		Policy:        pol,
		Delivery:      ds,
		Management:    mgmtSvc,
		ManagementAPI: mgmtAPI,
		Gateway:       gw,
		Wallet:        walletCtx,
		closeFns:      cleanup,
	}, nil
}
