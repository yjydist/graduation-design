package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/core/dao"
	domgw "grad/platform/core/domain/gateway"
	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/platform/core/ledger"
	apigw "grad/platform/service/api/gateway"
	"grad/platform/service/api/interdomain"
	"grad/protocol"
	"grad/protocol/registry"
)

type walletOptions struct {
	gatewayURL     string
	receiptURL     string
	nowFn          func() time.Time
	httpClient     *http.Client
	recoveryClient *http.Client
	auditClient    *http.Client
	receiptClient  *http.Client
}

// WalletOption customizes BuildWallet wiring.
type WalletOption func(*walletOptions)

// WithGatewayURL configures the remote gateway base URL used when no in-process handler is supplied.
func WithGatewayURL(url string) WalletOption {
	return func(o *walletOptions) { o.gatewayURL = url }
}

// WithReceiptURL configures the remote receipt delivery base URL.
func WithReceiptURL(url string) WalletOption {
	return func(o *walletOptions) { o.receiptURL = url }
}

// WithNow overrides the clock function used by the wallet context.
func WithNow(fn func() time.Time) WalletOption {
	return func(o *walletOptions) { o.nowFn = fn }
}

// WithHTTPClient supplies a custom public HTTP client for gateway requests.
func WithHTTPClient(c *http.Client) WalletOption {
	return func(o *walletOptions) { o.httpClient = c }
}

// WithRecoveryClient supplies an authenticated B_RECOVERY mTLS HTTP client.
func WithRecoveryClient(c *http.Client) WalletOption {
	return func(o *walletOptions) { o.recoveryClient = c }
}

// WithAuditClient supplies an authenticated C_AUDITOR mTLS HTTP client.
func WithAuditClient(c *http.Client) WalletOption {
	return func(o *walletOptions) { o.auditClient = c }
}

// WithReceiptClient supplies an authenticated C_AUDIT_SERVICE mTLS HTTP client.
func WithReceiptClient(c *http.Client) WalletOption {
	return func(o *walletOptions) { o.receiptClient = c }
}

// BuildWallet constructs an isolated wallet.WalletContext wired with actor private keys,
// SD-JWT credentials, RP and BM grant bundles, Fabric AnchorChildFunc/ReplaceGrantFunc
// (backed by ledger.Journal + domreg.DeliveryService), gateway/mTLS clients,
// and outbox receipt delivery bridged to interdomain.NewWalletReceiptHandler.
func BuildWallet(
	ctx context.Context,
	inst *ledger.Instance,
	d *ledger.Deployment,
	f *Fixtures,
	db *pgxpool.Pool,
	handler http.Handler,
	opts ...WalletOption,
) (*wallet.WalletContext, error) {
	if inst == nil || d == nil {
		return nil, fmt.Errorf("fabric instance and deployment are required")
	}
	var cfg walletOptions
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
	if cfg.nowFn == nil {
		cfg.nowFn = time.Now
	}

	mat, err := loadWalletMaterials(inst, f)
	if err != nil {
		return nil, err
	}

	var anchorFn func(context.Context, wallet.AnchorChildGrantRequest) (*wallet.AnchorChildGrantResult, error)
	var replaceFn func(context.Context, wallet.ReplaceGrantRequest) (*wallet.ReplaceGrantResult, error)
	if db != nil {
		if err := dao.Up(ctx, db); err != nil {
			return nil, err
		}
		anchorer, err := newWalletGrantAnchorer(inst, d, f, mat, db, cfg.nowFn)
		if err != nil {
			return nil, err
		}
		anchorFn = func(callCtx context.Context, req wallet.AnchorChildGrantRequest) (*wallet.AnchorChildGrantResult, error) {
			res, err := anchorer.AnchorGrant(callCtx, domreg.AnchorGrantRequest{
				Claims:      req.Claims,
				RawGrantJWS: req.RawGrantJWS,
				GrantDigest: req.GrantDigest,
				ParentID:    req.ParentID,
				IssuerActor: req.IssuerActor,
			})
			if err != nil {
				return nil, err
			}
			return &wallet.AnchorChildGrantResult{
				Anchored:   res.Anchored,
				TrustPaths: mat.trustPathsForMode(req.Claims.AuthorizationMode),
			}, nil
		}
		replaceFn = func(callCtx context.Context, req wallet.ReplaceGrantRequest) (*wallet.ReplaceGrantResult, error) {
			res, err := anchorer.ReplaceGrant(callCtx, domreg.ReplaceGrantAnchorRequest{
				OldGrantID:       req.OldGrantID,
				OldGrantRevision: req.OldGrantRevision,
				OldGrantDigest:   req.OldGrantDigest,
				NewClaims:        req.NewClaims,
				NewRawGrantJWS:   req.NewRawGrantJWS,
				NewGrantDigest:   req.NewGrantDigest,
				IssuerActor:      req.IssuerActor,
				Reason:           req.Reason,
			})
			if err != nil {
				return nil, err
			}
			return &wallet.ReplaceGrantResult{
				Anchored:   res.Anchored,
				TrustPaths: mat.trustPathsForMode(req.NewClaims.AuthorizationMode),
			}, nil
		}
	}

	recoveryClient, auditClient, receiptClient, err := resolveWalletMTLSClients(handler, cfg)
	if err != nil {
		return nil, err
	}

	var w *wallet.WalletContext
	var receiptDelivery func(context.Context, wallet.OrderOutcomeReceipt) (*wallet.OrderOutcomeReceiptResponse, error)
	if db != nil && handler != nil && receiptClient == nil {
		receiptDelivery = buildLocalReceiptDelivery(db, d.DeploymentID, func() *wallet.WalletContext { return w })
	}

	w, err = wallet.NewWalletContext(wallet.WalletConfig{
		DeploymentID:     d.DeploymentID,
		GatewayURL:       cfg.gatewayURL,
		ReceiptURL:       cfg.receiptURL,
		Audience:         defaultAudience,
		SupplierID:       defaultSupplierID,
		SupplierDID:      f.Identities["C"].ID,
		DefaultTaskSpec:  f.ProcurementTaskSpec,
		Currency:         defaultCurrency,
		AuditorDID:       defaultAuditorDID,
		RecoveryDID:      defaultRecoveryDID,
		DB:               db,
		HTTPClient:       cfg.httpClient,
		HTTPHandler:      handler,
		RecoveryClient:   recoveryClient,
		AuditClient:      auditClient,
		ReceiptClient:    receiptClient,
		ReceiptDelivery:  receiptDelivery,
		Now:              cfg.nowFn,
		AnchorChildFunc:  anchorFn,
		ReplaceGrantFunc: replaceFn,
	})
	if err != nil {
		return nil, err
	}
	if db != nil {
		if err := domgw.EnsureSchema(ctx, db, d.DeploymentID, defaultSupplierID); err != nil {
			return nil, err
		}
	}
	if err := registerFixtureActors(w, inst, f); err != nil {
		return nil, err
	}
	if err := loadFixtureGrantChains(w, inst, f, mat); err != nil {
		return nil, err
	}
	return w, nil
}

type walletMaterials struct {
	certByDomain map[string]string
	sdByActor    map[string]string
	tpCSingle    []protocol.TrustPathEntry
	tpASingle    []protocol.TrustPathEntry
	tpAC         []protocol.TrustPathEntry
	tpAB         []protocol.TrustPathEntry
	tpABC        []protocol.TrustPathEntry
}

func (m *walletMaterials) trustPathsForMode(mode string) []protocol.TrustPathEntry {
	if mode == registry.RP {
		return m.tpABC
	}
	return m.tpAB
}

func loadWalletMaterials(inst *ledger.Instance, f *Fixtures) (*walletMaterials, error) {
	read := func(parts ...string) (string, error) {
		raw, err := os.ReadFile(inst.RegistryPath(parts...))
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	certA, err := read("certifications", "A.jws")
	if err != nil {
		return nil, err
	}
	certB, err := read("certifications", "B.jws")
	if err != nil {
		return nil, err
	}
	certC, err := read("certifications", "C.jws")
	if err != nil {
		return nil, err
	}
	cSD, err := read("credentials", "C.sdjwt")
	if err != nil {
		return nil, err
	}
	paSD, err := read("credentials", "PA.sdjwt")
	if err != nil {
		return nil, err
	}
	uSD, err := read("credentials", "U.sdjwt")
	if err != nil {
		return nil, err
	}
	a1SD, err := read("credentials", "A1.sdjwt")
	if err != nil {
		return nil, err
	}

	aIssuer := f.Domains["A"].Issuers[0].ID
	bIssuer := f.Domains["B"].Issuers[0].ID
	cIssuer := f.Domains["C"].Issuers[0].ID
	return &walletMaterials{
		certByDomain: map[string]string{"A": certA, "B": certB, "C": certC},
		sdByActor:    map[string]string{"C": cSD, "PA": paSD, "U": uSD, "A1": a1SD},
		tpCSingle:    []protocol.TrustPathEntry{{Issuer: cIssuer, DomainCertification: certC}},
		tpASingle:    []protocol.TrustPathEntry{{Issuer: aIssuer, DomainCertification: certA}},
		tpAC: []protocol.TrustPathEntry{
			{Issuer: aIssuer, DomainCertification: certA},
			{Issuer: cIssuer, DomainCertification: certC},
		},
		tpAB: []protocol.TrustPathEntry{
			{Issuer: aIssuer, DomainCertification: certA},
			{Issuer: bIssuer, DomainCertification: certB},
		},
		tpABC: []protocol.TrustPathEntry{
			{Issuer: aIssuer, DomainCertification: certA},
			{Issuer: bIssuer, DomainCertification: certB},
			{Issuer: cIssuer, DomainCertification: certC},
		},
	}, nil
}

func newWalletGrantAnchorer(
	inst *ledger.Instance,
	dep *ledger.Deployment,
	fx *Fixtures,
	mat *walletMaterials,
	db *pgxpool.Pool,
	nowFn func() time.Time,
) (*domreg.GrantAnchorService, error) {
	return domreg.NewGrantAnchorService(domreg.GrantAnchorConfig{
		Instance:   inst,
		DB:         db,
		Deployment: dep,
		TaskSpec:   fx.ProcurementTaskSpec,
		Now:        nowFn,
		SnapshotBuilder: func(at time.Time) *protocol.SnapshotView {
			return BuildFixtureSnapshot(dep, fx, at)
		},
		ResolveIssuer: func(actor string) (domreg.IssuerDeliveryMaterial, bool, error) {
			issuerRec, ok := fx.Identities[actor]
			if !ok {
				return domreg.IssuerDeliveryMaterial{}, false, nil
			}
			credIssuerPub, err := protocol.ParseAppPublicKey(fx.Domains[issuerRec.Domain].Issuers[0].PublicKey)
			if err != nil {
				return domreg.IssuerDeliveryMaterial{}, false, err
			}
			grantorPub, err := protocol.ParseAppPublicKey(issuerRec.PublicKey)
			if err != nil {
				return domreg.IssuerDeliveryMaterial{}, false, err
			}
			grantorSD := mat.sdByActor[actor]
			if grantorSD == "" {
				rawSD, readErr := os.ReadFile(inst.RegistryPath("credentials", actor+".sdjwt"))
				if readErr != nil {
					return domreg.IssuerDeliveryMaterial{}, false, readErr
				}
				grantorSD = string(rawSD)
			}
			return domreg.IssuerDeliveryMaterial{
				DomainID:               issuerRec.Domain,
				IssuerPublicKey:        grantorPub,
				CredentialIssuerPubKey: credIssuerPub,
				ServicePresentation:    grantorSD,
				DomainCertificationJWS: mat.certByDomain[issuerRec.Domain],
			}, true, nil
		},
	})
}

func resolveWalletMTLSClients(handler http.Handler, cfg walletOptions) (recovery, audit, receipt *http.Client, err error) {
	recovery, audit, receipt = cfg.recoveryClient, cfg.auditClient, cfg.receiptClient
	if handler != nil {
		if recovery == nil {
			recovery = NewLocalMTLSClient(handler, defaultRecoveryDID, "B_RECOVERY", "BMsp")
		}
		if audit == nil {
			audit = NewLocalMTLSClient(handler, defaultAuditorDID, "C_AUDITOR", "CMsp")
		}
		return recovery, audit, receipt, nil
	}
	loadEnv := func(prefix string) (*http.Client, error) {
		cert, key, ca := os.Getenv(prefix+"_MTLS_CERT"), os.Getenv(prefix+"_MTLS_KEY"), os.Getenv(prefix+"_MTLS_CA")
		if cert == "" && key == "" && ca == "" {
			return nil, nil
		}
		return NewMTLSClient(cert, key, ca)
	}
	if recovery == nil {
		if recovery, err = loadEnv("RECOVERY"); err != nil {
			return nil, nil, nil, err
		}
	}
	if audit == nil {
		if audit, err = loadEnv("AUDIT"); err != nil {
			return nil, nil, nil, err
		}
	}
	if receipt == nil {
		if receipt, err = loadEnv("RECEIPT"); err != nil {
			return nil, nil, nil, err
		}
	}
	return recovery, audit, receipt, nil
}

func buildLocalReceiptDelivery(
	db *pgxpool.Pool,
	deploymentID string,
	walletRef func() *wallet.WalletContext,
) func(context.Context, wallet.OrderOutcomeReceipt) (*wallet.OrderOutcomeReceiptResponse, error) {
	return func(ctx context.Context, r wallet.OrderOutcomeReceipt) (*wallet.OrderOutcomeReceiptResponse, error) {
		localClient := NewLocalMTLSClient(interdomain.NewWalletReceiptHandler(walletRef()), defaultAuditSvcDID, "C_AUDIT_SERVICE", "CMsp")
		var ack *wallet.OrderOutcomeReceiptResponse
		sender := func(sendCtx context.Context, persisted domgw.OrderOutcomeReceipt) error {
			decoded, err := apigw.SendHTTPReceipt(sendCtx, localClient, receiptEndpointPath, persisted)
			if err != nil {
				return err
			}
			ack = toWalletReceiptResponse(decoded)
			return nil
		}
		if err := domgw.DeliverReceiptWithDB(ctx, db, deploymentID, r.CaseID, r.SendRevision, r.CheckNo, sender); err != nil {
			return nil, err
		}
		return ack, nil
	}
}

func registerFixtureActors(w *wallet.WalletContext, inst *ledger.Instance, f *Fixtures) error {
	for _, role := range []string{"U", "A1", "B1", "B2", "U-in-B", "PA"} {
		id, ok := f.Identities[role]
		if !ok {
			continue
		}
		priv, err := ledger.LoadECPrivateKeyPEM(inst.PrivatePath("app", role+".key.pem"))
		if err != nil {
			return fmt.Errorf("load %s private key: %w", role, err)
		}
		sdBytes, err := os.ReadFile(inst.RegistryPath("credentials", role+".sdjwt"))
		if err != nil {
			return fmt.Errorf("load %s SD-JWT: %w", role, err)
		}
		credID := f.Credentials[role].ID
		if credID == "" {
			credID = "cred:" + role
		}
		if err := w.RegisterActor(wallet.Signer{
			Actor:             role,
			DID:               id.ID,
			KeyID:             id.KeyID,
			CredentialID:      credID,
			KeyVersion:        id.KeyVersion,
			DomainID:          id.Domain,
			EntityType:        id.Kind,
			Roles:             []string{id.Kind},
			PrivateKey:        priv,
			SDJWTPresentation: string(sdBytes),
		}); err != nil {
			return fmt.Errorf("register actor %s: %w", role, err)
		}
	}
	return nil
}

func loadFixtureGrantChains(w *wallet.WalletContext, inst *ledger.Instance, f *Fixtures, mat *walletMaterials) error {
	uCredID := f.Credentials["U"].ID
	a1CredID := f.Credentials["A1"].ID

	addChain := func(rootFile, g1File, g2File string, rootAnc protocol.AncestorCredential, rootTP, g1TP, g2TP []protocol.TrustPathEntry) error {
		g0Raw, err := os.ReadFile(inst.RegistryPath("grants", rootFile))
		if err != nil {
			return err
		}
		g1Raw, err := os.ReadFile(inst.RegistryPath("grants", g1File))
		if err != nil {
			return err
		}
		g0Claims, err := decodeGrantPayload(string(g0Raw))
		if err != nil {
			return err
		}
		g1Claims, err := decodeGrantPayload(string(g1Raw))
		if err != nil {
			return err
		}
		if err := w.AddGrantBundle(wallet.GrantBundle{
			Claims:              g0Claims,
			TaskSpec:            f.ProcurementTaskSpec,
			RawGrantJWS:         string(g0Raw),
			ChainRawGrants:      []string{string(g0Raw)},
			AncestorCredentials: []protocol.AncestorCredential{rootAnc},
			TrustPaths:          rootTP,
			Anchored:            true,
			Revision:            1,
		}); err != nil {
			return err
		}
		if err := w.AddGrantBundle(wallet.GrantBundle{
			Claims:         g1Claims,
			TaskSpec:       f.ProcurementTaskSpec,
			RawGrantJWS:    string(g1Raw),
			ChainRawGrants: []string{string(g0Raw), string(g1Raw)},
			AncestorCredentials: []protocol.AncestorCredential{
				rootAnc,
				{CredentialID: uCredID, Presentation: mat.sdByActor["U"]},
			},
			TrustPaths: g1TP,
			Anchored:   true,
			Revision:   1,
		}); err != nil {
			return err
		}
		if g2File == "" {
			return nil
		}
		g2Raw, err := os.ReadFile(inst.RegistryPath("grants", g2File))
		if err != nil {
			return err
		}
		g2Claims, err := decodeGrantPayload(string(g2Raw))
		if err != nil {
			return err
		}
		return w.AddGrantBundle(wallet.GrantBundle{
			Claims:         g2Claims,
			TaskSpec:       f.ProcurementTaskSpec,
			RawGrantJWS:    string(g2Raw),
			ChainRawGrants: []string{string(g0Raw), string(g1Raw), string(g2Raw)},
			AncestorCredentials: []protocol.AncestorCredential{
				rootAnc,
				{CredentialID: uCredID, Presentation: mat.sdByActor["U"]},
				{CredentialID: a1CredID, Presentation: mat.sdByActor["A1"]},
			},
			TrustPaths: g2TP,
			Anchored:   true,
			Revision:   1,
		})
	}

	if err := addChain("rp_g0.jws", "rp_g1.jws", "rp_g2.jws",
		protocol.AncestorCredential{CredentialID: f.Credentials["C"].ID, Presentation: mat.sdByActor["C"]},
		mat.tpCSingle, mat.tpAC, mat.tpABC,
	); err != nil {
		return err
	}
	return addChain("bm_g0.jws", "bm_g1.jws", "bm_g2.jws",
		protocol.AncestorCredential{CredentialID: f.Credentials["PA"].ID, Presentation: mat.sdByActor["PA"]},
		mat.tpASingle, mat.tpASingle, mat.tpAB,
	)
}

func decodeGrantPayload(compact string) (protocol.GrantClaims, error) {
	parts := strings.Split(strings.TrimSpace(compact), ".")
	if len(parts) != 3 {
		return protocol.GrantClaims{}, fmt.Errorf("invalid compact grant JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return protocol.GrantClaims{}, err
	}
	var claims protocol.GrantClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return protocol.GrantClaims{}, err
	}
	return claims, nil
}

func toWalletReceiptResponse(in *domgw.OrderOutcomeReceiptResponse) *wallet.OrderOutcomeReceiptResponse {
	if in == nil {
		return nil
	}
	return &wallet.OrderOutcomeReceiptResponse{
		Status:             in.Status,
		ClientActionStatus: in.ClientActionStatus,
		Receipt: wallet.OrderOutcomeReceipt{
			CaseID:             in.Receipt.CaseID,
			CheckNo:            in.Receipt.CheckNo,
			SendRevision:       in.Receipt.SendRevision,
			DeploymentID:       in.Receipt.DeploymentID,
			Actor:              in.Receipt.Actor,
			TaskID:             in.Receipt.TaskID,
			RequestHash:        in.Receipt.RequestHash,
			Outcome:            in.Receipt.Outcome,
			OrderID:            in.Receipt.OrderID,
			CreationDecisionID: in.Receipt.CreationDecisionID,
			HistoricalStatus:   in.Receipt.HistoricalStatus,
			AuditAt:            in.Receipt.AuditAt,
		},
	}
}
