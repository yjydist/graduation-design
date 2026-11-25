package bootstrap

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

	"grad/platform/agent/llm"
	"grad/platform/agent/orchestrator"
	"grad/platform/core/dao"
	"grad/platform/core/domain/evidence"
	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/domain/policy"
	"grad/platform/core/domain/procurement"
	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/platform/core/ledger"
	apigw "grad/platform/service/api/gateway"
	"grad/platform/service/api/interdomain"
	apiwb "grad/platform/service/api/workbench"
	svcmcp "grad/platform/service/mcp"
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

// Close stops background loops, state providers, and database pools owned by Workbench.
func (w *Workbench) Close() {
	if w != nil && w.close != nil {
		w.close()
	}
}

// StartWorkbench composes one domain's L2 domain services, L3 HTTP/MCP servers,
// and L4 agent adapters from a local workbench config.json file.
func StartWorkbench(parent context.Context, configPath string) (*Workbench, error) {
	var cfg workbenchConfig
	if err := ledger.ReadJSON(configPath, &cfg); err != nil {
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
	inst, err := ledger.OpenInstance(filepath.Join(dir, cfg.FabricDir))
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
		return nil, fmt.Errorf("%w: workbench deployment pin", ledger.ErrDeploymentMismatch)
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

	db, err := openWorkbenchDB(setup, dir, cfg)
	if err != nil {
		return nil, err
	}
	cleanup = append(cleanup, db.Close)
	if err := dao.Up(setup, db); err != nil {
		return nil, err
	}
	if err := dao.BindWorkbenchStore(setup, db, dep.DeploymentID, cfg.DomainID); err != nil {
		return nil, err
	}
	syncFn := func(callCtx context.Context) error {
		return inst.SyncCommittedRegistry(callCtx, db, dep)
	}
	if err := syncFn(setup); err != nil {
		return nil, err
	}

	mgmt, _, err := domreg.NewFabricServiceForRoles(db, inst, dep, localRoles)
	if err != nil {
		return nil, err
	}
	actors, err := readLocalActors(setup, inst, cfg)
	if err != nil {
		return nil, err
	}
	rawCerts, err := loadRawCertifications(inst)
	if err != nil {
		return nil, err
	}
	certifications, err := procurement.SyncCertifications(setup, db, dep, cfg.DomainID, rawCerts, time.Now())
	if err != nil {
		return nil, err
	}
	grants, err := procurement.NewGrantOperations(procurement.GrantOperationsConfig{
		Deployment:     dep,
		DomainID:       cfg.DomainID,
		DB:             db,
		Management:     mgmt,
		Actors:         actors,
		Certifications: certifications,
		Sync:           syncFn,
	})
	if err != nil {
		return nil, err
	}

	root := dep.Bootstrap.Root
	rootDocRaw, err := os.ReadFile(inst.RegistryPath(ledger.DIDRelPath(root.DID)))
	if err != nil {
		return nil, err
	}
	internalTLS, clients, resolver, err := interdomain.BuildSecureTransport(interdomain.TransportConfig{
		DomainID: cfg.DomainID,
		CertPath: filepath.Join(dir, "internal.crt"),
		KeyPath:  filepath.Join(dir, "internal.key"),
		CAPath:   filepath.Join(dir, "internal-ca.crt"),
		Peers:    cfg.Peers,
		RootPreseed: protocol.RootPreseed{
			DID:               root.DID,
			KeyID:             root.KeyID,
			KeyVersion:        root.KeyVersion,
			PublicKeyHex:      root.PublicKey,
			DIDDocumentDigest: root.DocumentDigest,
			RawDocument:       rootDocRaw,
		},
	})
	if err != nil {
		return nil, err
	}
	out.InternalTLS = internalTLS
	peerClient := interdomain.NewPeerClient(cfg.Peers, clients)

	recipients := make(map[string]procurement.GrantRecipient, len(cfg.Actors))
	for name, ref := range cfg.Actors {
		recipients[name] = procurement.GrantRecipient{DID: ref.DID, CredentialID: ref.CredentialID}
	}

	var (
		gwSvc       *domgw.Service
		gwServer    *apigw.Server
		walletCtx   *wallet.WalletContext
		runnerCfg   llm.RunnerConfig
		procSvc     *procurement.Service
		browserProc *procurement.Service
		dispatchSvc *procurement.DispatchService
	)

	if cfg.DomainID == "C" {
		var closeGateway func()
		gwSvc, gwServer, closeGateway, err = startWorkbenchGateway(ctx, setup, inst, dep, db, resolver)
		if err != nil {
			return nil, err
		}
		cleanup = append(cleanup, closeGateway)
	} else {
		runnerCfg, err = loadWorkbenchRunnerConfig(cfg.DomainID)
		if err != nil {
			return nil, err
		}
		walletCtx, err = newWorkbenchWallet(dep, cfg, db, clients["C"], grants, actors, recipients)
		if err != nil {
			return nil, err
		}
	}

	authority := procurement.FabricAuthority{Deployment: dep, Instance: inst}
	switch cfg.DomainID {
	case "A":
		authority.EligibleServiceIDs = []string{cfg.Actors["PA"].DID}
		procSvc, err = procurement.NewService(procurement.ServiceConfig{
			DB:          db,
			Deployment:  dep,
			Instance:    inst,
			DomainID:    cfg.DomainID,
			DelegateDID: cfg.Actors["A1"].DID,
			Actors:      actors,
			Recipients:  recipients,
			Management:  mgmt,
			Grants:      grants,
			Wallet:      walletCtx,
			Advisor:     &draftAdvisorAdapter{runner: runnerCfg, delegateDID: cfg.Actors["A1"].DID},
			Delegator:   &delegateRunnerAdapter{runner: runnerCfg},
			Peers:       peerClient,
		})
		if err != nil {
			return nil, err
		}
		browserProc = procSvc
	case "B":
		authority.EligibleServiceIDs = []string{workbenchBService}
		dispatchSvc, err = procurement.NewDispatchService(procurement.DispatchConfig{
			DB:          db,
			Deployment:  dep,
			DomainID:    cfg.DomainID,
			DelegateDID: cfg.Actors["A1"].DID,
			ActorB1:     recipients["B1"],
			Grants:      grants,
			Wallet:      walletCtx,
			Executor:    &executeRunnerAdapter{runner: runnerCfg},
			Peers:       peerClient,
		})
		if err != nil {
			return nil, err
		}
	case "C":
		authority.EligibleServiceIDs = []string{dep.Bootstrap.ResourceOwner}
		procSvc, err = procurement.NewService(procurement.ServiceConfig{
			DB:          db,
			Deployment:  dep,
			Instance:    inst,
			DomainID:    cfg.DomainID,
			DelegateDID: cfg.Actors["A1"].DID,
			Actors:      actors,
			Recipients:  recipients,
			Management:  mgmt,
			Grants:      grants,
		})
		if err != nil {
			return nil, err
		}
	}

	authSvc := procurement.NewAuthorityService(dep.DeploymentID, authority, mgmt)
	sessionSvc, err := procurement.NewSessionService(db, dep.DeploymentID, cfg.DomainID, authSvc)
	if err != nil {
		return nil, err
	}
	evidenceSvc := evidence.NewService(evidence.Config{
		DB:          db,
		Deployment:  dep,
		Instance:    inst,
		Procurement: procSvc,
		Grants:      grants,
		Gateway:     gwSvc,
		Peers:       peerClient,
		ActorB1DID:  cfg.Actors["B1"].DID,
	})

	readyFn := func(callCtx context.Context) error {
		if err := db.Ping(callCtx); err != nil {
			return err
		}
		peer, err := inst.ReadPeer()
		if err != nil {
			return err
		}
		defer peer.Close()
		if err := dep.ValidatePeer(callCtx, peer); err != nil {
			return err
		}
		if gwSvc != nil {
			if _, err := gwSvc.CheckReady(callCtx); err != nil {
				return err
			}
		}
		return nil
	}

	browserServer, err := apiwb.NewServer(apiwb.Config{
		DeploymentID: dep.DeploymentID,
		DomainID:     cfg.DomainID,
		Sessions:     sessionSvc,
		Authority:    authSvc,
		Procurement:  browserProc,
		Evidence:     evidenceSvc,
		Ready:        readyFn,
	})
	if err != nil {
		return nil, err
	}
	accounts, err := accountSeeds(dir, inst, cfg)
	if err != nil {
		return nil, err
	}
	if err := sessionSvc.SeedAccounts(setup, accounts); err != nil {
		return nil, err
	}
	out.Browser = browserServer.Handler()

	docs, err := inst.LoadAllDIDDocs()
	if err != nil {
		return nil, err
	}
	interServer, err := interdomain.NewServer(interdomain.ServerConfig{
		DeploymentID: dep.DeploymentID,
		DomainID:     cfg.DomainID,
		ActorB1DID:   cfg.Actors["B1"].DID,
		AuditorDID:   defaultAuditorDID,
		Peers:        cfg.Peers,
		DIDDocs:      docs,
		Procurement:  procSvc,
		Dispatch:     dispatchSvc,
		Evidence:     evidenceSvc,
		Gateway:      gwServer,
		Wallet:       walletCtx,
	})
	if err != nil {
		return nil, err
	}
	out.Internal, err = interServer.Handler()
	if err != nil {
		return nil, err
	}

	workers := []func(context.Context) error{mgmt.RunRecovery}
	if browserProc != nil {
		workers = append(workers, loopWorkbench(browserProc.ProcessPending))
	}
	if dispatchSvc != nil {
		workers = append(workers, loopWorkbench(dispatchSvc.ProcessPending))
	}
	if gwServer != nil {
		workers = append(workers, loopWorkbench(func(callCtx context.Context) error {
			_, err := gwServer.DeliverPendingReceipts(callCtx, clients["B"], cfg.Peers["B"].URL+interdomain.PathOrderOutcomeReceipts)
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
		Scheme:   "postgres",
		Host:     host,
		User:     url.UserPassword("workbench", strings.TrimSpace(string(pwd))),
		Path:     "/workbench",
		RawQuery: "sslmode=disable",
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

func loadRawCertifications(inst *ledger.Instance) (map[string]string, error) {
	certs := make(map[string]string, 3)
	for _, dom := range []string{"A", "B", "C"} {
		raw, err := os.ReadFile(inst.RegistryPath("certifications", dom+".jws"))
		if err != nil {
			return nil, err
		}
		certs[dom] = string(raw)
	}
	return certs, nil
}

func accountSeeds(dir string, inst *ledger.Instance, cfg workbenchConfig) ([]procurement.AccountSeed, error) {
	var out []procurement.AccountSeed
	for _, acct := range cfg.Accounts {
		if !slices.Contains(workbenchLocalRoles(cfg.DomainID), acct.FabricRole) ||
			acct.PasswordFile == "" || filepath.Base(acct.PasswordFile) != acct.PasswordFile {
			return nil, fmt.Errorf("invalid local workbench account configuration")
		}
		_, mgmt, _, err := inst.Role(acct.FabricRole)
		if err != nil {
			return nil, err
		}
		pwd, err := os.ReadFile(filepath.Join(dir, acct.PasswordFile))
		if err != nil {
			return nil, err
		}
		out = append(out, procurement.AccountSeed{
			Username: acct.Username,
			Password: strings.TrimSpace(string(pwd)),
			Principal: procurement.Principal{
				DomainID:   cfg.DomainID,
				SubjectID:  acct.Subject,
				Role:       acct.Role,
				Management: mgmt,
			},
		})
	}
	return out, nil
}

func readLocalActors(ctx context.Context, inst *ledger.Instance, cfg workbenchConfig) (map[string]procurement.GrantActor, error) {
	peer, err := inst.ReadPeer()
	if err != nil {
		return nil, err
	}
	defer peer.Close()
	out := make(map[string]procurement.GrantActor)
	for _, role := range workbenchLocalActors(cfg.DomainID) {
		ref := cfg.Actors[role]
		identity, err := ledger.ReadLedgerRecord[registry.Identity](ctx, peer, "identity", ref.DID)
		if err != nil {
			return nil, err
		}
		cred, err := ledger.ReadLedgerRecord[registry.Credential](ctx, peer, "credential", ref.CredentialID)
		if err != nil {
			return nil, err
		}
		_, management, _, err := inst.Role(role)
		if err != nil {
			return nil, err
		}
		if identity.Domain != cfg.DomainID || identity.Management != management || cred.Subject != identity.ID ||
			identity.Status != registry.Active || cred.Status != registry.Active || cred.SubjectKeyVersion != identity.KeyVersion ||
			!cred.Interval.Current(time.Now(), registry.ClockError) {
			return nil, fmt.Errorf("workbench actor %s lacks active local binding", role)
		}
		private, err := ledger.LoadECPrivateKeyPEM(inst.PrivatePath("app", role+".key.pem"))
		if err != nil {
			return nil, err
		}
		key, err := protocol.FormatAppPublicKey(&private.PublicKey)
		if err != nil || key != identity.PublicKey {
			return nil, fmt.Errorf("workbench actor %s application key mismatch", role)
		}
		presentation, err := os.ReadFile(inst.RegistryPath("credentials", role+".sdjwt"))
		if err != nil {
			return nil, err
		}
		out[role] = procurement.GrantActor{
			Signer: wallet.Signer{
				Actor:             role,
				DID:               identity.ID,
				KeyID:             identity.KeyID,
				KeyVersion:        identity.KeyVersion,
				DomainID:          identity.Domain,
				EntityType:        identity.Kind,
				CredentialID:      cred.ID,
				PrivateKey:        private,
				SDJWTPresentation: string(presentation),
			},
			Management: management,
		}
	}
	return out, nil
}

func loadWorkbenchRunnerConfig(domainID string) (llm.RunnerConfig, error) {
	runner := llm.LoadRunnerConfigFromEnv()
	if keyFile := os.Getenv("LLM_API_KEY_FILE"); keyFile != "" {
		key, err := os.ReadFile(keyFile)
		if err != nil && (!os.IsNotExist(err) || runner.APIKey == "") {
			return llm.RunnerConfig{}, fmt.Errorf("read mounted model credential")
		}
		if err == nil {
			runner.APIKey = strings.TrimSpace(string(key))
		}
	}
	if runner.Model == "" || runner.APIKey == "" {
		return llm.RunnerConfig{}, fmt.Errorf("workbench domain %s requires model configuration", domainID)
	}
	return runner, nil
}

func startWorkbenchGateway(
	ctx, setup context.Context,
	inst *ledger.Instance,
	dep *ledger.Deployment,
	db *pgxpool.Pool,
	resolver *protocol.DIDWebResolver,
) (*domgw.Service, *apigw.Server, func(), error) {
	if err := domgw.EnsureSchema(setup, db, dep.DeploymentID, defaultSupplierID); err != nil {
		return nil, nil, nil, err
	}
	src, stop, err := inst.StartStateProvider(ctx, db, dep, "probe1", "")
	if err != nil {
		return nil, nil, nil, err
	}
	service := dep.Bootstrap.ResourceOwner
	pol, digest, err := policy.BuildDefaultBundle(dep.DeploymentID, service, policy.DefaultPolicyVersion, dep.Bootstrap.Root, nil)
	if err != nil {
		stop()
		return nil, nil, nil, err
	}
	bundle, err := policy.VerifyAndLoadBundle(pol, dep.DeploymentID, service, dep.Bootstrap.Root, digest)
	if err != nil {
		stop()
		return nil, nil, nil, err
	}
	gwSvc, err := domgw.NewService(domgw.Config{
		DB:                      db,
		State:                   src,
		DIDs:                    resolver,
		Policy:                  bundle,
		DeploymentID:            dep.DeploymentID,
		ServiceDID:              service,
		CertChecker:             domreg.NewDeliveryService(db, dep.DeploymentID),
		Audience:                defaultAudience,
		SupplierID:              defaultSupplierID,
		AuditorDIDs:             []string{defaultAuditorDID},
		VerifierID:              defaultAuditorDID,
		RecordWorkbenchEvidence: true,
	})
	if err != nil {
		stop()
		return nil, nil, nil, err
	}
	gwServer, err := apigw.NewServer(gwSvc)
	if err != nil {
		stop()
		return nil, nil, nil, err
	}
	return gwSvc, gwServer, stop, nil
}

func newWorkbenchWallet(
	dep *ledger.Deployment,
	cfg workbenchConfig,
	db *pgxpool.Pool,
	clientC *http.Client,
	grants *procurement.GrantOperations,
	actors map[string]procurement.GrantActor,
	recipients map[string]procurement.GrantRecipient,
) (*wallet.WalletContext, error) {
	w, err := wallet.NewWalletContext(wallet.WalletConfig{
		DeploymentID:    dep.DeploymentID,
		GatewayURL:      cfg.Peers["C"].URL,
		Audience:        defaultAudience,
		SupplierID:      defaultSupplierID,
		SupplierDID:     dep.Bootstrap.ResourceOwner,
		Currency:        defaultCurrency,
		DB:              db,
		HTTPClient:      clientC,
		RecoveryClient:  clientC,
		AuditClient:     clientC,
		AuditorDID:      defaultAuditorDID,
		RecoveryDID:     defaultRecoveryDID,
		AnchorChildFunc: grants.AnchorChild,
		ResolveGrantRecipient: func(ctx context.Context, did string) (wallet.GrantRecipient, error) {
			for _, name := range []string{"A1", "B1"} {
				if cfg.Actors[name].DID == did {
					return grants.ResolveRecipient(ctx, recipients[name])
				}
			}
			return wallet.GrantRecipient{}, protocol.NewError(registry.ErrCodeBindingMismatch, "recipient outside workbench delegation path")
		},
	})
	if err != nil {
		return nil, err
	}
	for _, actor := range actors {
		if err := w.RegisterActor(actor.Signer); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// --- Thin DI adapters bridging L4 agent/orchestrator + L3 service/mcp into L2 procurement ports ---

type draftAdvisorAdapter struct {
	runner      llm.RunnerConfig
	delegateDID string
}

func (a *draftAdvisorAdapter) SuggestDraft(ctx context.Context, message string, previous *procurement.Draft) (procurement.Draft, string, error) {
	prior, err := json.Marshal(previous)
	if err != nil {
		return procurement.Draft{}, "", err
	}
	callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	suggestion, err := orchestrator.SuggestDraft(callCtx, a.runner, message, string(prior), defaultSupplierID, domgw.DefaultProductID, defaultCurrency)
	if err != nil {
		return procurement.Draft{}, "", err
	}
	return procurement.Draft{
		ProductID:      suggestion.ProductID,
		Quantity:       suggestion.Quantity,
		Mode:           suggestion.Mode,
		MaxAmountMinor: suggestion.MaxAmountMinor,
		ExpiresAt:      time.Now().Add(time.Duration(suggestion.DurationMinutes) * time.Minute).Unix(),
		DelegateDID:    a.delegateDID,
		Description:    suggestion.Description,
	}, suggestion.Reply, nil
}

type delegateRunnerAdapter struct {
	runner llm.RunnerConfig
}

func (a *delegateRunnerAdapter) RunDelegate(ctx context.Context, ops *wallet.BoundOperations, req procurement.DelegateRunInput) (procurement.ModelRunResult, error) {
	cfg := a.runner
	if req.OnToolTrace != nil {
		cfg.OnToolTrace = func(t llm.ToolTrace) { req.OnToolTrace(toProcurementTrace(t)) }
	}
	res, err := orchestrator.RunDelegateTask(ctx, svcmcp.NewBoundMCPServer(ops), cfg, orchestrator.DelegateTaskParams{
		TaskID:            req.TaskID,
		AuthorizationMode: req.Mode,
		ParentGrantID:     req.ParentGrantID,
		ChildGrantID:      req.ChildGrantID,
		SubjectActor:      "B1",
		SubjectDID:        req.RecipientDID,
		MaxAmountMinor:    req.MaxAmountMinor,
		RemainingDepth:    0,
	})
	return toProcurementModelResult(res), err
}

type executeRunnerAdapter struct {
	runner llm.RunnerConfig
}

func (a *executeRunnerAdapter) RunExecute(ctx context.Context, ops *wallet.BoundOperations, req procurement.ExecuteRunInput) (procurement.ModelRunResult, error) {
	cfg := a.runner
	if req.OnToolTrace != nil {
		cfg.OnToolTrace = func(t llm.ToolTrace) { req.OnToolTrace(toProcurementTrace(t)) }
	}
	res, err := orchestrator.RunExecuteTask(ctx, svcmcp.NewBoundMCPServer(ops), cfg, orchestrator.ExecuteTaskParams{
		TaskID:            req.TaskID,
		AuthorizationMode: req.Mode,
		Actor:             "B1",
		GrantID:           req.GrantID,
		ProductID:         req.ProductID,
		Quantity:          req.Quantity,
		MaxAmountMinor:    req.MaxAmountMinor,
		Currency:          defaultCurrency,
		IdempotencyKey:    req.OrderKey,
	})
	return toProcurementModelResult(res), err
}

func toProcurementTrace(t llm.ToolTrace) procurement.ToolTrace {
	return procurement.ToolTrace{
		Step:       t.Step,
		ToolName:   t.ToolName,
		Arguments:  t.Arguments,
		Output:     t.Output,
		RawText:    t.RawText,
		IsError:    t.IsError,
		DurationMs: t.DurationMs,
	}
}

func toProcurementModelResult(res *llm.RunResult) procurement.ModelRunResult {
	if res == nil {
		return procurement.ModelRunResult{}
	}
	traces := make([]procurement.ToolTrace, len(res.ToolTraces))
	for i, t := range res.ToolTraces {
		traces[i] = toProcurementTrace(t)
	}
	return procurement.ModelRunResult{
		Summary:         res.FinalText,
		Traces:          traces,
		Provider:        res.Provider,
		RequestedModel:  res.RequestedModel,
		ResponseModels:  slices.Clone(res.ResponseModels),
		Steps:           res.Steps,
		TotalDurationMs: res.TotalDurationMs,
	}
}
