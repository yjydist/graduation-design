package bootstrap

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"grad/platform/core/dao"
	"grad/platform/core/dao/central"
	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/domain/policy"
	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/platform/core/ledger"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	apigw "grad/platform/service/api/gateway"
	"grad/platform/service/api/interdomain"
	apireg "grad/platform/service/api/registry"
	svcmcp "grad/platform/service/mcp"
	"grad/protocol"
	"grad/protocol/registry"
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

	certA, err := os.ReadFile(inst.RegistryPath("certifications", "A.jws"))
	if err != nil {
		return nil, err
	}
	certB, err := os.ReadFile(inst.RegistryPath("certifications", "B.jws"))
	if err != nil {
		return nil, err
	}
	certC, err := os.ReadFile(inst.RegistryPath("certifications", "C.jws"))
	if err != nil {
		return nil, err
	}
	cSD, err := os.ReadFile(inst.RegistryPath("credentials", "C.sdjwt"))
	if err != nil {
		return nil, err
	}
	paSD, err := os.ReadFile(inst.RegistryPath("credentials", "PA.sdjwt"))
	if err != nil {
		return nil, err
	}
	uSD, err := os.ReadFile(inst.RegistryPath("credentials", "U.sdjwt"))
	if err != nil {
		return nil, err
	}
	a1SD, err := os.ReadFile(inst.RegistryPath("credentials", "A1.sdjwt"))
	if err != nil {
		return nil, err
	}

	certByDomain := map[string]string{
		"A": string(certA),
		"B": string(certB),
		"C": string(certC),
	}
	sdByActor := map[string]string{
		"C":  string(cSD),
		"PA": string(paSD),
		"U":  string(uSD),
		"A1": string(a1SD),
	}

	aIssuerDID := f.Domains["A"].Issuers[0].ID
	bIssuerDID := f.Domains["B"].Issuers[0].ID
	cIssuerDID := f.Domains["C"].Issuers[0].ID
	tpCSingle := []protocol.TrustPathEntry{{Issuer: cIssuerDID, DomainCertification: string(certC)}}
	tpASingle := []protocol.TrustPathEntry{{Issuer: aIssuerDID, DomainCertification: string(certA)}}
	tpAC := []protocol.TrustPathEntry{
		{Issuer: aIssuerDID, DomainCertification: string(certA)},
		{Issuer: cIssuerDID, DomainCertification: string(certC)},
	}
	tpAB := []protocol.TrustPathEntry{
		{Issuer: aIssuerDID, DomainCertification: string(certA)},
		{Issuer: bIssuerDID, DomainCertification: string(certB)},
	}
	tpABC := []protocol.TrustPathEntry{
		{Issuer: aIssuerDID, DomainCertification: string(certA)},
		{Issuer: bIssuerDID, DomainCertification: string(certB)},
		{Issuer: cIssuerDID, DomainCertification: string(certC)},
	}
	trustPathsForMode := func(mode string) []protocol.TrustPathEntry {
		if mode == registry.RP {
			return tpABC
		}
		return tpAB
	}

	buildChainGrant := func(claims protocol.GrantClaims, digest, parentOverride string) registry.Grant {
		parentID, parentDigest := parentOverride, ""
		if claims.ParentID != nil && *claims.ParentID != "" {
			parentID = *claims.ParentID
		}
		if claims.ParentDigest != nil {
			parentDigest = *claims.ParentDigest
		}
		return registry.Grant{
			Bound:             registry.Bound{DeploymentID: d.DeploymentID},
			ID:                claims.ID,
			Schema:            registry.Schema,
			Parent:            parentID,
			ParentDigest:      parentDigest,
			Root:              claims.RootID,
			Task:              claims.TaskID,
			Mode:              claims.AuthorizationMode,
			Domain:            claims.PrincipalDomain,
			Resource:          claims.ResourceID,
			Issuer:            claims.Issuer,
			Grantee:           claims.Grantee,
			IssuerKeyVersion:  claims.IssuerKeyVersion,
			GranteeKeyVersion: claims.GranteeKeyVersion,
			IssuerCredential:  claims.IssuerCredentialID,
			GranteeCredential: claims.GranteeCredentialID,
			Depth:             uint8(claims.RemainingDepth),
			Digest:            digest,
			Interval:          registry.Interval{NBF: claims.NBF, EXP: claims.EXP},
		}
	}

	var anchorFn func(context.Context, wallet.AnchorChildGrantRequest) (*wallet.AnchorChildGrantResult, error)
	var replaceFn func(context.Context, wallet.ReplaceGrantRequest) (*wallet.ReplaceGrantResult, error)
	if db != nil {
		if err := dao.Up(ctx, db); err != nil {
			return nil, err
		}
		j := ledger.NewJournal(inst, db, d.DeploymentID)
		ds := domreg.NewDeliveryService(db, d.DeploymentID)

		deliverAnchoredChild := func(callCtx context.Context, issuerActor string, chainGrant registry.Grant, rawJWS string, op *ledger.Operation) error {
			issuerRec, ok := f.Identities[issuerActor]
			if !ok {
				return nil
			}
			synced, err := ds.HasSyncedCertification(callCtx, issuerRec.Domain)
			if err != nil || !synced {
				return err
			}
			nowSec := cfg.nowFn().UTC().Unix()
			snap := BuildFixtureSnapshot(d, f, time.Unix(nowSec, 0).UTC())
			activeGrant := chainGrant
			activeGrant.Version = registry.Version{Status: registry.Active, Revision: 1}
			snap.Grants[activeGrant.ID] = activeGrant

			rootPub, err := protocol.ParseAppPublicKey(d.Bootstrap.Root.PublicKey)
			if err != nil {
				return err
			}
			credIssuerPub, err := protocol.ParseAppPublicKey(f.Domains[issuerRec.Domain].Issuers[0].PublicKey)
			if err != nil {
				return err
			}
			grantorPub, err := protocol.ParseAppPublicKey(issuerRec.PublicKey)
			if err != nil {
				return err
			}
			grantorSD := sdByActor[issuerActor]
			if grantorSD == "" {
				rawSD, readErr := os.ReadFile(inst.RegistryPath("credentials", issuerActor+".sdjwt"))
				if readErr != nil {
					return readErr
				}
				grantorSD = string(rawSD)
			}
			txID, blockNo := op.TxID, int64(1)
			if op.Commit != nil {
				blockNo = int64(op.Commit.Number)
			}
			pkg := domreg.GrantDeliveryPackage{
				DeploymentID:           d.DeploymentID,
				Recipient:              chainGrant.Grantee,
				GrantID:                chainGrant.ID,
				GrantJWS:               rawJWS,
				TaskSpec:               f.ProcurementTaskSpec,
				ServicePresentation:    grantorSD,
				DomainCertificationJWS: certByDomain[issuerRec.Domain],
			}
			if _, err := ds.PublishGrantOutbox(callCtx, snap, pkg, rootPub, credIssuerPub, grantorPub, txID, blockNo, true, nowSec); err != nil {
				return err
			}
			_, _, err = ds.DeliverGrantReceipt(callCtx, snap, d.DeploymentID, chainGrant.Grantee, chainGrant.ID, nil, rootPub, credIssuerPub, grantorPub, nowSec)
			return err
		}

		anchorFn = func(callCtx context.Context, req wallet.AnchorChildGrantRequest) (*wallet.AnchorChildGrantResult, error) {
			chainGrant := buildChainGrant(req.Claims, req.GrantDigest, req.ParentID)
			raw, err := json.Marshal(chainGrant)
			if err != nil {
				return nil, err
			}
			opKey := "mcp-anchor/" + registry.Digest([]byte(req.Claims.ID))[:24]
			op, err := j.Write(callCtx, opKey, req.IssuerActor, "RegisterGrant", raw)
			if err != nil {
				return nil, err
			}
			if err := ledger.ExpectOperation(op, "VALID"); err != nil {
				return nil, err
			}
			if err := inst.AwaitEndorsers(callCtx, *op.Commit); err != nil {
				return nil, err
			}
			if err := deliverAnchoredChild(callCtx, req.IssuerActor, chainGrant, req.RawGrantJWS, op); err != nil {
				return nil, err
			}
			return &wallet.AnchorChildGrantResult{
				Anchored:   true,
				TrustPaths: trustPathsForMode(req.Claims.AuthorizationMode),
			}, nil
		}

		replaceFn = func(callCtx context.Context, req wallet.ReplaceGrantRequest) (*wallet.ReplaceGrantResult, error) {
			rev := req.OldGrantRevision
			if rev == 0 {
				rev = 1
			}
			chainGrant := buildChainGrant(req.NewClaims, req.NewGrantDigest, "")
			rep := registry.Replacement{
				Old: registry.Mutation{
					Bound:            registry.Bound{DeploymentID: d.DeploymentID},
					ID:               req.OldGrantID,
					ExpectedRevision: rev,
					ExpectedDigest:   req.OldGrantDigest,
					Reason:           req.Reason,
				},
				New: chainGrant,
			}
			raw, err := json.Marshal(rep)
			if err != nil {
				return nil, err
			}
			opKey := "mcp-replace/" + registry.Digest([]byte(req.OldGrantID+"/"+req.NewClaims.ID))[:24]
			op, err := j.Write(callCtx, opKey, req.IssuerActor, "ReplaceGrant", raw)
			if err != nil {
				return nil, err
			}
			if err := ledger.ExpectOperation(op, "VALID"); err != nil {
				return nil, err
			}
			if err := inst.AwaitEndorsers(callCtx, *op.Commit); err != nil {
				return nil, err
			}
			if err := deliverAnchoredChild(callCtx, req.IssuerActor, chainGrant, req.NewRawGrantJWS, op); err != nil {
				return nil, err
			}
			return &wallet.ReplaceGrantResult{
				Anchored:   true,
				TrustPaths: trustPathsForMode(req.NewClaims.AuthorizationMode),
			}, nil
		}
	}

	recoveryClient := cfg.recoveryClient
	auditClient := cfg.auditClient
	receiptClient := cfg.receiptClient
	if handler != nil {
		if recoveryClient == nil {
			recoveryClient = NewLocalMTLSClient(handler, defaultRecoveryDID, "B_RECOVERY", "BMsp")
		}
		if auditClient == nil {
			auditClient = NewLocalMTLSClient(handler, defaultAuditorDID, "C_AUDITOR", "CMsp")
		}
	} else {
		loadEnvMTLS := func(prefix string) (*http.Client, error) {
			cert, key, ca := os.Getenv(prefix+"_MTLS_CERT"), os.Getenv(prefix+"_MTLS_KEY"), os.Getenv(prefix+"_MTLS_CA")
			if cert == "" && key == "" && ca == "" {
				return nil, nil
			}
			return NewMTLSClient(cert, key, ca)
		}
		if recoveryClient == nil {
			if recoveryClient, err = loadEnvMTLS("RECOVERY"); err != nil {
				return nil, err
			}
		}
		if auditClient == nil {
			if auditClient, err = loadEnvMTLS("AUDIT"); err != nil {
				return nil, err
			}
		}
		if receiptClient == nil {
			if receiptClient, err = loadEnvMTLS("RECEIPT"); err != nil {
				return nil, err
			}
		}
	}

	// Bridge C's durable order_outcome_outbox (domgw.DeliverReceiptWithDB) into B's mTLS-protected
	// interdomain.NewWalletReceiptHandler(w) when operating against an in-process gateway handler + PostgreSQL DB.
	var w *wallet.WalletContext
	var receiptDelivery func(context.Context, wallet.OrderOutcomeReceipt) (*wallet.OrderOutcomeReceiptResponse, error)
	if db != nil && handler != nil && receiptClient == nil {
		receiptDelivery = func(callCtx context.Context, r wallet.OrderOutcomeReceipt) (*wallet.OrderOutcomeReceiptResponse, error) {
			localClient := NewLocalMTLSClient(interdomain.NewWalletReceiptHandler(w), defaultAuditSvcDID, "C_AUDIT_SERVICE", "CMsp")
			var ack *wallet.OrderOutcomeReceiptResponse
			sender := func(sendCtx context.Context, persisted domgw.OrderOutcomeReceipt) error {
				payload, err := json.Marshal(persisted)
				if err != nil {
					return err
				}
				req, err := http.NewRequestWithContext(sendCtx, http.MethodPost, receiptEndpointPath, bytes.NewReader(payload))
				if err != nil {
					return err
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(httpx.HeaderRequestID, httpx.NewRequestID())

				resp, err := localClient.Do(req)
				if err != nil {
					return err
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("receipt delivery HTTP %d", resp.StatusCode)
				}
				body, err := io.ReadAll(io.LimitReader(resp.Body, domgw.MaxExecuteBodyBytes+1))
				if err != nil {
					return err
				}
				if int64(len(body)) > domgw.MaxExecuteBodyBytes {
					return fmt.Errorf("receipt acknowledgement exceeds %d bytes", domgw.MaxExecuteBodyBytes)
				}
				var decoded domgw.OrderOutcomeReceiptResponse
				if err := json.Unmarshal(body, &decoded); err != nil {
					return err
				}
				if err := domgw.VerifyReceiptEcho(persisted, decoded.Receipt); err != nil {
					return err
				}
				ack = toWalletReceiptResponse(&decoded)
				return nil
			}
			if err := domgw.DeliverReceiptWithDB(callCtx, db, d.DeploymentID, r.CaseID, r.SendRevision, r.CheckNo, sender); err != nil {
				return nil, err
			}
			return ack, nil
		}
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

	for _, role := range []string{"U", "A1", "B1", "B2", "U-in-B", "PA"} {
		id, ok := f.Identities[role]
		if !ok {
			continue
		}
		priv, err := ledger.LoadECPrivateKeyPEM(inst.PrivatePath("app", role+".key.pem"))
		if err != nil {
			return nil, fmt.Errorf("load %s private key: %w", role, err)
		}
		sdBytes, err := os.ReadFile(inst.RegistryPath("credentials", role+".sdjwt"))
		if err != nil {
			return nil, fmt.Errorf("load %s SD-JWT: %w", role, err)
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
			return nil, fmt.Errorf("register actor %s: %w", role, err)
		}
	}

	cCredID := f.Credentials["C"].ID
	paCredID := f.Credentials["PA"].ID
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
				{CredentialID: uCredID, Presentation: string(uSD)},
			},
			TrustPaths: g1TP,
			Anchored:   true,
			Revision:   1,
		}); err != nil {
			return err
		}
		if g2File != "" {
			g2Raw, err := os.ReadFile(inst.RegistryPath("grants", g2File))
			if err != nil {
				return err
			}
			g2Claims, err := decodeGrantPayload(string(g2Raw))
			if err != nil {
				return err
			}
			if err := w.AddGrantBundle(wallet.GrantBundle{
				Claims:         g2Claims,
				TaskSpec:       f.ProcurementTaskSpec,
				RawGrantJWS:    string(g2Raw),
				ChainRawGrants: []string{string(g0Raw), string(g1Raw), string(g2Raw)},
				AncestorCredentials: []protocol.AncestorCredential{
					rootAnc,
					{CredentialID: uCredID, Presentation: string(uSD)},
					{CredentialID: a1CredID, Presentation: string(a1SD)},
				},
				TrustPaths: g2TP,
				Anchored:   true,
				Revision:   1,
			}); err != nil {
				return err
			}
		}
		return nil
	}

	if err := addChain("rp_g0.jws", "rp_g1.jws", "rp_g2.jws",
		protocol.AncestorCredential{CredentialID: cCredID, Presentation: string(cSD)},
		tpCSingle, tpAC, tpABC,
	); err != nil {
		return nil, err
	}
	if err := addChain("bm_g0.jws", "bm_g1.jws", "bm_g2.jws",
		protocol.AncestorCredential{CredentialID: paCredID, Presentation: string(paSD)},
		tpASingle, tpASingle, tpAB,
	); err != nil {
		return nil, err
	}
	return w, nil
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
	j := ledger.NewJournal(inst, db, dep.DeploymentID)
	stored, err := j.Load(ctx, key, db)
	if err != nil {
		return nil, err
	}
	if stored != nil {
		if _, _, err := j.MatchInput(stored, role, method, raw); err != nil {
			return nil, err
		}
		if stored.Status != "PENDING" {
			return stored, nil
		}
	}
	p, err := inst.Peer("c", "read")
	if err != nil {
		return nil, err
	}
	defer p.Close()
	if err := dep.ValidatePeer(ctx, p); err != nil {
		if stored != nil {
			return stored, nil
		}
		return nil, err
	}
	return j.Write(ctx, key, role, method, raw)
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
	j := ledger.NewJournal(inst, db, dep.DeploymentID)
	stored, err := j.Load(ctx, key, db)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, fmt.Errorf("unknown operation %q", key)
	}
	if stored.Status != "PENDING" {
		return stored, nil
	}
	p, err := inst.Peer("c", "read")
	if err != nil {
		return nil, err
	}
	defer p.Close()
	if err := dep.ValidatePeer(ctx, p); err != nil {
		return stored, nil
	}
	return j.Recover(ctx, key, nil)
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
