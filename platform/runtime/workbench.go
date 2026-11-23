package runtime

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/agent"
	"grad/platform/gateway"
	"grad/platform/migrations"
	"grad/platform/policy"
	"grad/platform/registrysvc"
	"grad/platform/state/fabric"
	"grad/platform/workbench"
	"grad/protocol"
	"grad/protocol/registry"
)

// Workbench exposes distinct browser and mutually authenticated service listeners.
type Workbench struct {
	Browser, Internal         http.Handler
	BrowserAddr, InternalAddr string
	InternalTLS               *tls.Config
	close                     func()
}

func (w *Workbench) Close() {
	if w != nil && w.close != nil {
		w.close()
	}
}

type domainWorkbench struct {
	cfg     workbenchConfig
	inst    *fabric.Instance
	dep     *fabric.Deployment
	db      *pgxpool.Pool
	mgmt    *registrysvc.Service
	grants  *GrantOperations
	wallet  *agent.WalletContext
	runner  agent.RunnerConfig
	actors  map[string]GrantActor
	clients map[string]*http.Client
	gateway *gateway.Server
	proc    *workbench.Procurement
}

func StartWorkbench(parent context.Context, configPath string) (*Workbench, error) {
	var cfg workbenchConfig
	if err := fabric.ReadJSON(configPath, &cfg); err != nil {
		return nil, fmt.Errorf("read workbench configuration: %w", err)
	}
	localRoles := workbenchLocalRoles(cfg.DomainID)
	if len(localRoles) == 0 || !registry.IsDigest(cfg.DeploymentID) || cfg.FabricDir == "" || cfg.BrowserAddr == "" || cfg.InternalAddr == "" {
		return nil, fmt.Errorf("invalid workbench deployment, domain, or listeners")
	}
	if len(cfg.Peers) != 3 {
		return nil, fmt.Errorf("A, B and C peer bindings are required")
	}
	dir := filepath.Dir(configPath)
	inst, err := fabric.OpenInstance(filepath.Join(dir, cfg.FabricDir))
	if err != nil {
		return nil, err
	}
	reader := "domain" + cfg.DomainID
	if cfg.DomainID == "C" {
		reader = "read"
	}
	inst, err = inst.ForDomain(cfg.DomainID, reader, os.Getenv("WORKBENCH_PEER_ENDPOINT"))
	if err != nil {
		return nil, err
	}
	dep, err := inst.LoadDeployment()
	if err != nil {
		return nil, err
	}
	if dep.DeploymentID != cfg.DeploymentID {
		return nil, fmt.Errorf("%w: workbench deployment pin", fabric.ErrDeploymentMismatch)
	}
	ctx, cancel := context.WithCancel(parent)
	out := &Workbench{BrowserAddr: cfg.BrowserAddr, InternalAddr: cfg.InternalAddr}
	var wg sync.WaitGroup
	var cleanup []func()
	out.close = sync.OnceFunc(func() {
		cancel()
		wg.Wait()
		for i := len(cleanup) - 1; i >= 0; i-- {
			cleanup[i]()
		}
	})
	started := false
	defer func() {
		if !started {
			out.Close()
		}
	}()
	setup, stopSetup := context.WithTimeout(ctx, 45*time.Second)
	defer stopSetup()
	d := &domainWorkbench{cfg: cfg, inst: inst, dep: dep}
	d.db, err = openWorkbenchDB(setup, dir, cfg)
	if err != nil {
		return nil, err
	}
	cleanup = append(cleanup, d.db.Close)
	if err := migrations.Up(setup, d.db); err != nil {
		return nil, err
	}
	if err := d.bindDatabase(setup); err != nil {
		return nil, err
	}
	if err := d.sync(setup); err != nil {
		return nil, err
	}
	d.mgmt, _, err = registrysvc.NewFabricServiceForRoles(d.db, inst, dep, localRoles)
	if err != nil {
		return nil, err
	}
	d.actors, err = d.readLocalActors(setup)
	if err != nil {
		return nil, err
	}
	certifications, err := d.syncCertifications(setup)
	if err != nil {
		return nil, err
	}
	d.grants, err = NewGrantOperations(GrantOperationsConfig{
		Deployment: dep, DomainID: cfg.DomainID, DB: d.db, Management: d.mgmt,
		Actors: d.actors, Certifications: certifications, Sync: d.sync,
	})
	if err != nil {
		return nil, err
	}

	var resolver *protocol.DIDWebResolver
	out.InternalTLS, d.clients, resolver, err = d.secureTransport(dir)
	if err != nil {
		return nil, err
	}
	if cfg.DomainID == "C" {
		closeGateway, err := d.startWorkbenchGateway(ctx, setup, resolver)
		if err != nil {
			return nil, err
		}
		cleanup = append(cleanup, closeGateway)
	} else {
		d.runner = agent.LoadRunnerConfigFromEnv()
		if keyFile := os.Getenv("LLM_API_KEY_FILE"); keyFile != "" {
			key, err := os.ReadFile(keyFile)
			if err != nil && (!os.IsNotExist(err) || d.runner.APIKey == "") {
				return nil, fmt.Errorf("read mounted model credential")
			}
			if err == nil {
				d.runner.APIKey = strings.TrimSpace(string(key))
			}
		}
		if d.runner.Model == "" || d.runner.APIKey == "" {
			return nil, fmt.Errorf("workbench domain %s requires model configuration", cfg.DomainID)
		}
		d.wallet, err = d.newWorkbenchWallet()
		if err != nil {
			return nil, err
		}
	}

	authority := workbench.FabricAuthority{Deployment: dep, Instance: inst}
	switch cfg.DomainID {
	case "A":
		authority.EligibleServiceIDs = []string{cfg.Actors["PA"].DID}
		d.proc = workbench.NewProcurement(d.db, dep.DeploymentID, cfg.DomainID, cfg.Actors["A1"].DID, d)
	case "B":
		authority.EligibleServiceIDs = []string{workbenchBService}
	case "C":
		authority.EligibleServiceIDs = []string{dep.Bootstrap.ResourceOwner}
	}
	browserConfig := workbench.Config{
		DeploymentID: dep.DeploymentID, DomainID: cfg.DomainID, DB: d.db, Registry: d.mgmt, Ready: d.ready,
		VerifyPrincipal: authority.VerifyPrincipal, ReadPurchasingAuthority: authority.ReadPurchasingAuthority,
		CheckPurchasingAuthority: authority.CheckPurchasingAuthority,
		Evidence:                 workbench.EvidenceHandlers{Decision: d.decision},
	}
	if d.proc != nil {
		browserConfig.Procurement = d.proc.Handlers()
		browserConfig.Evidence.RunEvidence = d.proc.EvidenceHandler(d.evidence)
	}
	server, err := workbench.NewServer(browserConfig)
	if err != nil {
		return nil, err
	}
	accounts, err := d.accountSeeds(dir)
	if err != nil {
		return nil, err
	}
	if err := server.SeedAccounts(setup, accounts); err != nil {
		return nil, err
	}
	out.Browser = server.Handler()
	out.Internal, err = d.internalHandler()
	if err != nil {
		return nil, err
	}
	workers := []func(context.Context) error{d.mgmt.RunRecovery}
	if d.proc != nil {
		workers = append(workers, loopWorkbench(d.proc.ProcessPending))
	}
	if cfg.DomainID == "B" {
		workers = append(workers, loopWorkbench(d.processDispatch))
	}
	if cfg.DomainID == "C" {
		workers = append(workers, loopWorkbench(func(ctx context.Context) error {
			_, err := d.gateway.DeliverPendingReceipts(ctx, d.clients["B"], d.cfg.Peers["B"].URL+"/v1/internal/order-outcome-receipts")
			return err
		}))
	}
	for _, worker := range workers {
		wg.Go(func() { _ = worker(ctx) })
	}
	started = true
	return out, nil
}

func loopWorkbench(run func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for ctx.Err() == nil {
			_ = run(ctx)
			select {
			case <-ctx.Done():
			case <-tick.C:
			}
		}
		return ctx.Err()
	}
}

func openWorkbenchDB(ctx context.Context, dir string, cfg workbenchConfig) (*pgxpool.Pool, error) {
	pwd, err := os.ReadFile(filepath.Join(dir, "postgres-password"))
	if err != nil {
		return nil, err
	}
	host := os.Getenv("WORKBENCH_DATABASE_HOST")
	if host == "" {
		host = cfg.DatabaseHost
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		return nil, fmt.Errorf("invalid workbench database address")
	}
	dsn := url.URL{
		Scheme: "postgres", Host: host, User: url.UserPassword("workbench", strings.TrimSpace(string(pwd))),
		Path: "/workbench", RawQuery: "sslmode=disable",
	}
	poolConfig, err := pgxpool.ParseConfig(dsn.String())
	if err != nil {
		return nil, fmt.Errorf("invalid workbench database configuration")
	}
	poolConfig.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open workbench database")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("workbench database unavailable")
	}
	return pool, nil
}

func (d *domainWorkbench) bindDatabase(ctx context.Context) error {
	_, err := d.db.Exec(ctx, `INSERT INTO workbench_store_binding(singleton,deployment_id,domain_id)
		VALUES(true,$1,$2) ON CONFLICT DO NOTHING`, d.dep.DeploymentID, d.cfg.DomainID)
	if err != nil {
		return err
	}
	var deployment, domain string
	if err := d.db.QueryRow(ctx, "SELECT deployment_id,domain_id FROM workbench_store_binding WHERE singleton").Scan(&deployment, &domain); err != nil {
		return err
	}
	if deployment != d.dep.DeploymentID || domain != d.cfg.DomainID {
		return fmt.Errorf("workbench database belongs to another domain or deployment")
	}
	return nil
}

func (d *domainWorkbench) sync(ctx context.Context) error {
	return d.inst.SyncCommittedRegistry(ctx, d.db, d.dep)
}

func (d *domainWorkbench) ready(ctx context.Context) error {
	if err := d.db.Ping(ctx); err != nil {
		return err
	}
	peer, err := d.inst.ReadPeer()
	if err != nil {
		return err
	}
	defer peer.Close()
	if err := d.dep.ValidatePeer(ctx, peer); err != nil {
		return err
	}
	if d.gateway != nil {
		return callLocalJSON(ctx, d.gateway.Handler(), http.MethodGet, "/v1/health/ready", nil, nil)
	}
	return nil
}

func (d *domainWorkbench) accountSeeds(dir string) ([]workbench.AccountSeed, error) {
	var out []workbench.AccountSeed
	for _, acct := range d.cfg.Accounts {
		if !slices.Contains(workbenchLocalRoles(d.cfg.DomainID), acct.FabricRole) ||
			acct.PasswordFile == "" || filepath.Base(acct.PasswordFile) != acct.PasswordFile {
			return nil, fmt.Errorf("invalid local workbench account configuration")
		}
		_, mgmt, _, err := d.inst.Role(acct.FabricRole)
		if err != nil {
			return nil, err
		}
		pwd, err := os.ReadFile(filepath.Join(dir, acct.PasswordFile))
		if err != nil {
			return nil, err
		}
		out = append(out, workbench.AccountSeed{
			Username: acct.Username, Password: strings.TrimSpace(string(pwd)),
			Principal: workbench.Principal{DomainID: d.cfg.DomainID, SubjectID: acct.Subject, Role: acct.Role, Management: mgmt},
		})
	}
	return out, nil
}

func (d *domainWorkbench) readLocalActors(ctx context.Context) (map[string]GrantActor, error) {
	peer, err := d.inst.ReadPeer()
	if err != nil {
		return nil, err
	}
	defer peer.Close()
	out := make(map[string]GrantActor)
	for _, role := range workbenchLocalActors(d.cfg.DomainID) {
		ref := d.cfg.Actors[role]
		identity, err := fabric.ReadLedgerRecord[registry.Identity](ctx, peer, "identity", ref.DID)
		if err != nil {
			return nil, err
		}
		cred, err := fabric.ReadLedgerRecord[registry.Credential](ctx, peer, "credential", ref.CredentialID)
		if err != nil {
			return nil, err
		}
		_, management, _, err := d.inst.Role(role)
		if err != nil {
			return nil, err
		}
		if identity.Domain != d.cfg.DomainID || identity.Management != management || cred.Subject != identity.ID ||
			identity.Status != registry.Active || cred.Status != registry.Active || cred.SubjectKeyVersion != identity.KeyVersion ||
			!cred.Interval.Current(time.Now(), registry.ClockError) {
			return nil, fmt.Errorf("workbench actor %s lacks active local binding", role)
		}
		private, err := fabric.LoadECPrivateKeyPEM(d.inst.PrivatePath("app", role+".key.pem"))
		if err != nil {
			return nil, err
		}
		key, err := protocol.FormatAppPublicKey(&private.PublicKey)
		if err != nil || key != identity.PublicKey {
			return nil, fmt.Errorf("workbench actor %s application key mismatch", role)
		}
		presentation, err := os.ReadFile(d.inst.RegistryPath("credentials", role+".sdjwt"))
		if err != nil {
			return nil, err
		}
		out[role] = GrantActor{Signer: agent.Signer{
			Actor: role, DID: identity.ID, KeyID: identity.KeyID, KeyVersion: identity.KeyVersion, DomainID: identity.Domain,
			EntityType: identity.Kind, CredentialID: cred.ID, PrivateKey: private, SDJWTPresentation: string(presentation),
		}, Management: management}
	}
	return out, nil
}

func (d *domainWorkbench) syncCertifications(ctx context.Context) (map[string]string, error) {
	certs := make(map[string]string, 3)
	domainKeys := []string{registry.Key("domain", "A"), registry.Key("domain", "B"), registry.Key("domain", "C")}
	read, err := fabric.ReadAppliedRegistry(ctx, d.db, d.dep, domainKeys)
	if err != nil {
		return nil, err
	}
	snap := &protocol.SnapshotView{
		DeploymentID: d.dep.DeploymentID, Root: read.Root, Height: read.Number,
		Now: time.Now(), ClockError: registry.ClockError,
		Domains: map[string]registry.Domain{}, Certifications: map[string]registry.Certification{},
		Identities: map[string]registry.Identity{},
	}
	keys := slices.Clone(domainKeys)
	var issuerKeys []string
	for _, key := range domainKeys {
		var item registry.Domain
		if err := json.Unmarshal(read.Records[key], &item); err != nil {
			return nil, err
		}
		keys = append(keys, registry.Key("certification", item.Certification))
		for _, issuer := range item.Issuers {
			issuerKeys = append(issuerKeys, registry.Key("identity", issuer))
		}
	}
	read, err = fabric.ReadAppliedRegistry(ctx, d.db, d.dep, append(keys, issuerKeys...))
	if err != nil {
		return nil, err
	}
	for i, key := range domainKeys {
		var domain registry.Domain
		var cert registry.Certification
		if err := json.Unmarshal(read.Records[key], &domain); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(read.Records[keys[i+len(domainKeys)]], &cert); err != nil {
			return nil, err
		}
		if domain.Certification != cert.ID {
			return nil, fmt.Errorf("domain certification changed during workbench startup")
		}
		snap.Domains[domain.ID], snap.Certifications[cert.ID] = domain, cert
	}
	for _, key := range issuerKeys {
		var issuer registry.Identity
		if err := json.Unmarshal(read.Records[key], &issuer); err != nil {
			return nil, err
		}
		snap.Identities[issuer.ID] = issuer
	}
	root, err := protocol.ParseAppPublicKey(d.dep.Bootstrap.Root.PublicKey)
	if err != nil {
		return nil, err
	}
	ds := registrysvc.NewDeliveryService(d.db, d.dep.DeploymentID)
	for _, domain := range []string{"A", "B", "C"} {
		certID := snap.Domains[domain].Certification
		var txID string
		var block int64
		err := d.db.QueryRow(ctx, `SELECT tx_id,block_no FROM fabric_version WHERE deployment=$1 AND key=$2 AND value IS NOT NULL
			ORDER BY block_no,tx_index LIMIT 1`, d.dep.DeploymentID, registry.Key("certification", certID)).Scan(&txID, &block)
		if err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(d.inst.RegistryPath("certifications", domain+".jws"))
		if err != nil {
			return nil, err
		}
		certs[domain] = string(raw)
		now := time.Now().Unix()
		recipient := "did:web:" + strings.ToLower(d.cfg.DomainID) + ".local"
		if err := ds.PublishDomainCertification(ctx, snap, recipient, domain, string(raw), root, txID, block, true, now); err != nil {
			return nil, err
		}
		if _, err := ds.SyncCertificationReceipt(ctx, snap, recipient, domain, root, now); err != nil {
			return nil, err
		}
	}
	return certs, nil
}

func (d *domainWorkbench) startWorkbenchGateway(ctx, setup context.Context, resolver *protocol.DIDWebResolver) (func(), error) {
	if err := gateway.EnsureSchema(setup, d.db, d.dep.DeploymentID, defaultSupplierID); err != nil {
		return nil, err
	}
	src, stop, err := d.inst.StartStateProvider(ctx, d.db, d.dep, "probe1", "")
	if err != nil {
		return nil, err
	}
	service := d.dep.Bootstrap.ResourceOwner
	pol, digest, err := policy.BuildDefaultBundle(d.dep.DeploymentID, service, policy.DefaultPolicyVersion, d.dep.Bootstrap.Root, nil)
	if err != nil {
		stop()
		return nil, err
	}
	bundle, err := policy.VerifyAndLoadBundle(pol, d.dep.DeploymentID, service, d.dep.Bootstrap.Root, digest)
	if err == nil {
		d.gateway, err = gateway.NewServer(gateway.ServerConfig{
			DB: d.db, State: src, DIDs: resolver, Policy: bundle, DeploymentID: d.dep.DeploymentID, ServiceDID: service,
			CertChecker: registrysvc.NewDeliveryService(d.db, d.dep.DeploymentID), Audience: defaultAudience, SupplierID: defaultSupplierID,
			AuditorDIDs: []string{defaultAuditorDID}, VerifierID: defaultAuditorDID, RecordWorkbenchEvidence: true,
		})
	}
	if err != nil {
		stop()
		return nil, err
	}
	return stop, nil
}

func (d *domainWorkbench) newWorkbenchWallet() (*agent.WalletContext, error) {
	cfg := agent.WalletConfig{
		DeploymentID: d.dep.DeploymentID, GatewayURL: d.cfg.Peers["C"].URL, Audience: defaultAudience,
		SupplierID: defaultSupplierID, SupplierDID: d.dep.Bootstrap.ResourceOwner, Currency: defaultCurrency,
		DB: d.db, HTTPClient: d.clients["C"], RecoveryClient: d.clients["C"], AuditClient: d.clients["C"],
		AuditorDID: defaultAuditorDID, RecoveryDID: defaultRecoveryDID, AnchorChildFunc: d.grants.AnchorChild,
		ResolveGrantRecipient: func(ctx context.Context, did string) (agent.GrantRecipient, error) {
			for _, name := range []string{"A1", "B1"} {
				if d.cfg.Actors[name].DID == did {
					return d.grants.ResolveRecipient(ctx, d.recipient(name))
				}
			}
			return agent.GrantRecipient{}, protocol.NewError(registry.ErrCodeBindingMismatch, "recipient outside workbench delegation path")
		},
	}
	wallet, err := agent.NewWalletContext(cfg)
	if err != nil {
		return nil, err
	}
	for _, actor := range d.actors {
		if err := wallet.RegisterActor(actor.Signer); err != nil {
			return nil, err
		}
	}
	return wallet, nil
}
