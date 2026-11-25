package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/core/dao"
	"grad/protocol"
)

const (
	// ActionStatusPending marks an action row prior to network dispatch.
	ActionStatusPending = dao.ActionStatusPending
	// ActionStatusOutcomeUnknown marks a persisted order intent whose gateway outcome is not yet known.
	ActionStatusOutcomeUnknown = dao.ActionStatusOutcomeUnknown
	// ActionStatusSubmitted marks an action explicitly recorded as submitted.
	ActionStatusSubmitted = dao.ActionStatusSubmitted
	// ActionStatusCompleted marks an order intent confirmed directly by a 200 OK gateway response.
	ActionStatusCompleted = dao.ActionStatusCompleted
	// ActionStatusReconciled marks an order intent finalized via C audit receipt (CREATED or NOT_CREATED).
	ActionStatusReconciled = dao.ActionStatusReconciled
	// ActionStatusFailed marks an order intent definitively rejected by a 4xx gateway response.
	ActionStatusFailed = dao.ActionStatusFailed
)

// Re-exported DAO types for external callers (L3 services, bootstrap, and experiments).
type (
	ClientAction                = dao.ClientAction
	ClientActionView            = dao.ClientActionView
	ActionStore                 = dao.ActionStore
	OrderOutcomeReceipt         = dao.OrderOutcomeReceipt
	OrderOutcomeReceiptResponse = dao.OrderOutcomeReceiptResponse
)

// NewActionStore constructs an ActionStore bound to deploymentID. When db is nil, an in-memory store is used.
func NewActionStore(db *pgxpool.Pool, deploymentID string, now func() time.Time) *ActionStore {
	return dao.NewActionStore(db, deploymentID, now)
}

var (
	rePrivateKeyPEM = regexp.MustCompile(`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
	reSDJWTSegment  = regexp.MustCompile(`~[A-Za-z0-9_-]{8,}`)
	reJWSCompact    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
)

// Signer configures an isolated wallet actor with its authentication/assertion key and SD-JWT prefix.
// PrivateKey and SDJWTPresentation are excluded from JSON marshaling to prevent accidental leakage.
type Signer struct {
	Actor             string            `json:"actor"`
	DID               string            `json:"did"`
	KeyID             string            `json:"keyId"`
	CredentialID      string            `json:"credentialId"`
	KeyVersion        uint64            `json:"keyVersion"`
	DomainID          string            `json:"domainId"`
	EntityType        string            `json:"entityType"`
	Roles             []string          `json:"roles"`
	PrivateKey        *ecdsa.PrivateKey `json:"-"`
	SDJWTPresentation string            `json:"-"`
}

// GrantBundle captures a delivered delegation grant and its proof chain kept inside the local wallet.
type GrantBundle struct {
	Claims              protocol.GrantClaims          `json:"claims"`
	TaskSpec            protocol.TaskSpec             `json:"taskSpec"`
	RawGrantJWS         string                        `json:"-"`
	Digest              string                        `json:"digest"`
	ChainRawGrants      []string                      `json:"-"`
	AncestorCredentials []protocol.AncestorCredential `json:"-"`
	TrustPaths          []protocol.TrustPathEntry     `json:"-"`
	Anchored            bool                          `json:"anchored"`
	Revision            uint64                        `json:"revision"`
	Replaced            bool                          `json:"replaced,omitempty"`
}

// SanitizedGrantView exposes safe delegation metadata to callers and LLMs without raw tokens or salts.
type SanitizedGrantView struct {
	GrantID           string   `json:"grantId"`
	ParentID          string   `json:"parentId,omitempty"`
	RootID            string   `json:"rootId"`
	TaskID            string   `json:"taskId"`
	AuthorizationMode string   `json:"authorizationMode"`
	PrincipalDomain   string   `json:"principalDomain"`
	IssuerDID         string   `json:"issuerDid"`
	GranteeDID        string   `json:"granteeDid"`
	MaxAmountMinor    int64    `json:"maxAmountMinor"`
	Currency          string   `json:"currency"`
	RemainingDepth    int64    `json:"remainingDepth"`
	Resources         []string `json:"resources"`
	Actions           []string `json:"actions"`
	Suppliers         []string `json:"suppliers"`
	Audience          string   `json:"audience"`
	NBF               int64    `json:"nbf"`
	EXP               int64    `json:"exp"`
	Anchored          bool     `json:"anchored"`
	Replaced          bool     `json:"replaced,omitempty"`
	TrustPathCount    int      `json:"trustPathCount"`
	AncestorCount     int      `json:"ancestorCount"`
}

// QuoteRecord caches an immutable supplier quote inside the wallet for deterministic order creation.
type QuoteRecord struct {
	QuoteID          string `json:"quoteId"`
	TaskID           string `json:"taskId"`
	Actor            string `json:"actor"`
	SupplierID       string `json:"supplierId"`
	ProductID        string `json:"productId"`
	Quantity         int64  `json:"quantity"`
	Currency         string `json:"currency"`
	UnitPriceMinor   int64  `json:"unitPriceMinor"`
	TotalAmountMinor int64  `json:"totalAmountMinor"`
	IssuedAt         int64  `json:"issuedAt,omitempty"`
	ValidUntil       int64  `json:"validUntil"`
	IdempotencyKey   string `json:"-"`
}

// OrderRecord caches a confirmed supplier order inside the wallet.
type OrderRecord struct {
	OrderID          string `json:"orderId"`
	QuoteID          string `json:"quoteId"`
	TaskID           string `json:"taskId"`
	Actor            string `json:"actor"`
	SupplierID       string `json:"supplierId"`
	ProductID        string `json:"productId"`
	Quantity         int64  `json:"quantity"`
	Currency         string `json:"currency"`
	TotalAmountMinor int64  `json:"totalAmountMinor"`
	IdempotencyKey   string `json:"idempotencyKey"`
	Status           string `json:"status"`
	CreatedAt        int64  `json:"createdAt"`
}

// AnchorChildGrantRequest provides inputs from delegate_grant when anchoring a child grant onto a ledger.
type AnchorChildGrantRequest struct {
	Claims                   protocol.GrantClaims
	RawGrantJWS              string
	GrantDigest              string
	ParentID                 string
	IssuerActor              string
	GranteeDID               string
	RequestedLifetimeSeconds int64
}

// AnchorChildGrantResult returns the anchored trust paths and optional materials from the ledger.
type AnchorChildGrantResult struct {
	Anchored            bool
	TrustPaths          []protocol.TrustPathEntry
	AncestorCredentials []protocol.AncestorCredential
	Grant               *GrantBundle
}

// GrantRecipient is the public key and credential binding for a remote grantee.
type GrantRecipient struct {
	DID          string
	KeyVersion   uint64
	CredentialID string
}

// ReplaceGrantRequest provides inputs from replace_grant when atomically revoking an old child grant
// and issuing a replacement child grant to a new delegate (such as B2).
type ReplaceGrantRequest struct {
	OldGrantID       string
	OldGrantRevision uint64
	OldGrantDigest   string
	NewClaims        protocol.GrantClaims
	NewRawGrantJWS   string
	NewGrantDigest   string
	IssuerActor      string
	NewGranteeDID    string
	Reason           string
}

// ReplaceGrantResult returns the anchored trust paths and materials delivered to the new delegate.
type ReplaceGrantResult struct {
	Anchored            bool
	TrustPaths          []protocol.TrustPathEntry
	AncestorCredentials []protocol.AncestorCredential
}

// WalletConfig configures WalletContext.
type WalletConfig struct {
	DeploymentID          string
	GatewayURL            string
	ReceiptURL            string
	Audience              string
	SupplierID            string
	SupplierDID           string
	DefaultTaskSpec       protocol.TaskSpec
	Currency              string
	AuditorDID            string
	RecoveryDID           string
	DB                    *pgxpool.Pool
	ActionStore           *ActionStore
	GatewayClient         *GatewayClient
	HTTPClient            *http.Client
	HTTPHandler           http.Handler
	RecoveryClient        *http.Client
	AuditClient           *http.Client
	ReceiptClient         *http.Client
	ReceiptDelivery       func(context.Context, OrderOutcomeReceipt) (*OrderOutcomeReceiptResponse, error)
	Now                   func() time.Time
	AnchorChildFunc       func(ctx context.Context, req AnchorChildGrantRequest) (*AnchorChildGrantResult, error)
	ResolveGrantRecipient func(context.Context, string) (GrantRecipient, error)
	ReplaceGrantFunc      func(ctx context.Context, req ReplaceGrantRequest) (*ReplaceGrantResult, error)
}

// WalletContext isolates actor private keys and SD-JWT credentials behind a domain boundary,
// while owning local client_actions and order_outcome_receipts persistence via ActionStore.
type WalletContext struct {
	mu             sync.Mutex
	cfg            WalletConfig
	client         *GatewayClient
	store          *ActionStore
	signers        map[string]*Signer
	grants         []*GrantBundle
	quotes         map[string]QuoteRecord
	orders         map[string]OrderRecord
	actionRequests map[string]protocol.AccessRequest
	secrets        []string
}

// NewWalletContext validates cfg and returns an isolated WalletContext.
func NewWalletContext(cfg WalletConfig) (*WalletContext, error) {
	if cfg.DeploymentID == "" {
		return nil, errors.New("agent wallet requires DeploymentID")
	}
	if cfg.Audience == "" {
		cfg.Audience = defaultGatewayBaseURL
	}
	if cfg.SupplierID == "" {
		cfg.SupplierID = "urn:grad:supplier:C"
	}
	if cfg.Currency == "" {
		cfg.Currency = "CNY"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	gwClient := cfg.GatewayClient
	if gwClient == nil {
		gwClient = NewGatewayClient(GatewayClientConfig{
			BaseURL:        cfg.GatewayURL,
			ReceiptBaseURL: cfg.ReceiptURL,
			HTTPClient:     cfg.HTTPClient,
			HTTPHandler:    cfg.HTTPHandler,
			RecoveryClient: cfg.RecoveryClient,
			AuditClient:    cfg.AuditClient,
			ReceiptClient:  cfg.ReceiptClient,
		})
	}
	store := cfg.ActionStore
	if store == nil {
		store = dao.NewActionStore(cfg.DB, cfg.DeploymentID, cfg.Now)
	}
	return &WalletContext{
		cfg:            cfg,
		client:         gwClient,
		store:          store,
		signers:        make(map[string]*Signer),
		quotes:         make(map[string]QuoteRecord),
		orders:         make(map[string]OrderRecord),
		actionRequests: make(map[string]protocol.AccessRequest),
	}, nil
}

// ActionStore returns the underlying ActionStore owning client_actions and order_outcome_receipts.
func (w *WalletContext) ActionStore() *ActionStore {
	return w.store
}

// GatewayClient returns the HTTP gateway client configured for this wallet.
func (w *WalletContext) GatewayClient() *GatewayClient {
	return w.client
}

// BeginClientAction delegates to ActionStore.BeginClientAction.
func (w *WalletContext) BeginClientAction(
	ctx context.Context,
	actor, taskID, action, idempotencyKey, requestHash, requestJSON string,
) (*ClientAction, error) {
	return w.store.BeginClientAction(ctx, actor, taskID, action, idempotencyKey, requestHash, requestJSON)
}

// GetClientActionByKey delegates to ActionStore.GetClientActionByKey.
func (w *WalletContext) GetClientActionByKey(
	ctx context.Context,
	actor, taskID, action, idempotencyKey string,
) (*ClientAction, error) {
	return w.store.GetClientActionByKey(ctx, actor, taskID, action, idempotencyKey)
}

// ListClientActions delegates to ActionStore.ListClientActions.
func (w *WalletContext) ListClientActions(ctx context.Context, actor, taskID string) ([]ClientAction, error) {
	return w.store.ListClientActions(ctx, actor, taskID)
}

// RecordClientActionChallenge delegates to ActionStore.RecordClientActionChallenge.
func (w *WalletContext) RecordClientActionChallenge(
	ctx context.Context,
	actionID string,
	expectedSendRevision int64,
	challengeID, requestJSON string,
) (*ClientAction, error) {
	return w.store.RecordClientActionChallenge(ctx, actionID, expectedSendRevision, challengeID, requestJSON)
}

// DispatchClientAction delegates to ActionStore.DispatchClientAction.
func (w *WalletContext) DispatchClientAction(
	ctx context.Context,
	actionID string,
	expectedSendRevision int64,
	send func() error,
) error {
	return w.store.DispatchClientAction(ctx, actionID, expectedSendRevision, send)
}

// StopClientActionSend delegates to ActionStore.StopClientActionSend.
func (w *WalletContext) StopClientActionSend(
	ctx context.Context,
	actor, taskID, action, idempotencyKey, caseID, requestJSON string,
) (*ClientAction, error) {
	return w.store.StopClientActionSend(ctx, actor, taskID, action, idempotencyKey, caseID, requestJSON)
}

// UpdateClientAction delegates to ActionStore.UpdateClientAction.
func (w *WalletContext) UpdateClientAction(
	ctx context.Context,
	actionID, status, challengeID, quoteID, orderID, decisionID string,
) error {
	return w.store.UpdateClientAction(ctx, actionID, status, challengeID, quoteID, orderID, decisionID)
}

// ApplyOrderOutcomeReceipt validates and applies a reconciliation receipt to order_outcome_receipts and client_actions.
func (w *WalletContext) ApplyOrderOutcomeReceipt(ctx context.Context, receipt OrderOutcomeReceipt) (*OrderOutcomeReceiptResponse, error) {
	return w.store.ApplyOrderOutcomeReceipt(ctx, receipt)
}

// AuthorizeReceiptSender validates that an inbound receipt sender identity belongs to domain C
// and holds one of the authorized C audit service roles.
func AuthorizeReceiptSender(role, did string) error {
	if did == "" || didWebHost(did) != "c.local" {
		return protocol.NewError(protocol.ErrCodeAuditForbidden, "authenticated C receipt service required")
	}
	switch role {
	case "C_AUDIT_SERVICE", "C_AUDITOR", "C-AUDITOR":
		return nil
	default:
		return protocol.NewError(protocol.ErrCodeAuditForbidden, "caller lacks C audit service role")
	}
}

// IsAuthorizedReceiptSender reports whether (role, did) is authorized to deliver order outcome receipts.
func IsAuthorizedReceiptSender(role, did string) bool {
	return AuthorizeReceiptSender(role, did) == nil
}

// AuthorizeReceiptCaller checks whether an inbound caller (role, did) may deliver order outcome receipts to this wallet.
func (w *WalletContext) AuthorizeReceiptCaller(role, did string) error {
	return AuthorizeReceiptSender(role, did)
}

// RegisterSecret registers an extra secret value to scrub from tool outputs and error strings.
func (w *WalletContext) RegisterSecret(secret string) {
	if secret == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !slices.Contains(w.secrets, secret) {
		w.secrets = append(w.secrets, secret)
	}
}

// RegisterActor stores an actor's isolated signing key and SD-JWT presentation prefix inside the wallet.
func (w *WalletContext) RegisterActor(cfg Signer) error {
	if cfg.Actor == "" || cfg.DID == "" || cfg.KeyID == "" {
		return errors.New("actor, DID, and KeyID are required")
	}
	if cfg.PrivateKey == nil {
		return fmt.Errorf("actor %q missing isolated private key", cfg.Actor)
	}
	if cfg.SDJWTPresentation == "" || !strings.HasSuffix(cfg.SDJWTPresentation, "~") {
		return fmt.Errorf("actor %q sdJWTPresentation must end with '~'", cfg.Actor)
	}
	if cfg.KeyVersion == 0 {
		cfg.KeyVersion = 1
	}
	cp := cfg
	cp.Roles = slices.Clone(cfg.Roles)

	w.mu.Lock()
	defer w.mu.Unlock()
	w.signers[cp.Actor] = &cp
	w.registerSecretLocked(cp.SDJWTPresentation)
	if idx := strings.IndexByte(cp.SDJWTPresentation, '~'); idx >= 0 && idx+1 < len(cp.SDJWTPresentation) {
		for _, part := range strings.Split(cp.SDJWTPresentation[idx+1:], "~") {
			if len(part) >= 6 {
				w.registerSecretLocked(part)
			}
		}
	}
	return nil
}

func (w *WalletContext) registerSecretLocked(secret string) {
	if secret != "" && !slices.Contains(w.secrets, secret) {
		w.secrets = append(w.secrets, secret)
	}
}

// AddGrantBundle adds or replaces a grant bundle held in the wallet.
func (w *WalletContext) AddGrantBundle(bundle GrantBundle) error {
	if bundle.Claims.ID == "" {
		return errors.New("grant bundle missing Claims.ID")
	}
	if bundle.RawGrantJWS == "" {
		return fmt.Errorf("grant %q missing RawGrantJWS", bundle.Claims.ID)
	}
	if bundle.Digest == "" {
		sum := sha256.Sum256([]byte(bundle.RawGrantJWS))
		bundle.Digest = hex.EncodeToString(sum[:])
	}
	if len(bundle.ChainRawGrants) == 0 {
		bundle.ChainRawGrants = []string{bundle.RawGrantJWS}
	}
	copyBundle := bundle
	copyBundle.ChainRawGrants = slices.Clone(bundle.ChainRawGrants)
	copyBundle.AncestorCredentials = slices.Clone(bundle.AncestorCredentials)
	copyBundle.TrustPaths = slices.Clone(bundle.TrustPaths)
	copyBundle.TaskSpec.Resources = slices.Clone(bundle.TaskSpec.Resources)
	copyBundle.TaskSpec.Actions = slices.Clone(bundle.TaskSpec.Actions)

	w.mu.Lock()
	defer w.mu.Unlock()
	for _, anc := range copyBundle.AncestorCredentials {
		w.registerSecretLocked(anc.Presentation)
		if idx := strings.IndexByte(anc.Presentation, '~'); idx >= 0 && idx+1 < len(anc.Presentation) {
			for _, part := range strings.Split(anc.Presentation[idx+1:], "~") {
				if len(part) >= 6 {
					w.registerSecretLocked(part)
				}
			}
		}
	}
	for i, existing := range w.grants {
		if existing.Claims.ID == copyBundle.Claims.ID {
			w.grants[i] = &copyBundle
			return nil
		}
	}
	w.grants = append(w.grants, &copyBundle)
	return nil
}

// SanitizeString scrubs PEM keys, SD-JWT disclosure salts, JWS compact tokens, and registered secrets.
func (w *WalletContext) SanitizeString(input string) string {
	out := rePrivateKeyPEM.ReplaceAllString(input, "[REDACTED_PRIVATE_KEY]")
	out = reJWSCompact.ReplaceAllString(out, "[REDACTED_TOKEN]")
	out = reSDJWTSegment.ReplaceAllString(out, "~[REDACTED_DISCLOSURE]")
	w.mu.Lock()
	secrets := slices.Clone(w.secrets)
	w.mu.Unlock()
	for _, s := range secrets {
		if len(s) >= 6 {
			out = strings.ReplaceAll(out, s, "[REDACTED_SECRET]")
		}
	}
	return out
}

// SanitizeJSONForLog marshals v and scrubs any accidental secret fragments before writing traces or logs.
func (w *WalletContext) SanitizeJSONForLog(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return w.SanitizeString(err.Error())
	}
	return w.SanitizeString(string(b))
}

func (b *GrantBundle) view() SanitizedGrantView {
	parentID := ""
	if b.Claims.ParentID != nil {
		parentID = *b.Claims.ParentID
	}
	return SanitizedGrantView{
		GrantID:           b.Claims.ID,
		ParentID:          parentID,
		RootID:            b.Claims.RootID,
		TaskID:            b.Claims.TaskID,
		AuthorizationMode: b.Claims.AuthorizationMode,
		PrincipalDomain:   b.Claims.PrincipalDomain,
		IssuerDID:         b.Claims.Issuer,
		GranteeDID:        b.Claims.Grantee,
		MaxAmountMinor:    b.Claims.MaxAmountMinor,
		Currency:          b.Claims.Currency,
		RemainingDepth:    b.Claims.RemainingDepth,
		Resources:         slices.Clone(b.Claims.Resources),
		Actions:           slices.Clone(b.Claims.Actions),
		Suppliers:         slices.Clone(b.Claims.Suppliers),
		Audience:          b.Claims.Aud,
		NBF:               b.Claims.NBF,
		EXP:               b.Claims.EXP,
		Anchored:          b.Anchored,
		Replaced:          b.Replaced,
		TrustPathCount:    len(b.TrustPaths),
		AncestorCount:     len(b.AncestorCredentials),
	}
}

func (w *WalletContext) findGrantLocked(actorDID, grantID, taskID, mode string) (*GrantBundle, error) {
	if grantID != "" {
		for _, g := range w.grants {
			if g.Claims.ID == grantID {
				if actorDID != "" && g.Claims.Grantee != actorDID {
					return nil, fmt.Errorf("grant %q belongs to %q, not actor %q", grantID, g.Claims.Grantee, actorDID)
				}
				return g, nil
			}
		}
		return nil, fmt.Errorf("grant %q not found in wallet", grantID)
	}
	var matches []*GrantBundle
	for _, g := range w.grants {
		if g.Replaced {
			continue
		}
		if g.Claims.Grantee != actorDID {
			continue
		}
		if taskID != "" && g.Claims.TaskID != taskID {
			continue
		}
		if mode != "" && g.Claims.AuthorizationMode != mode {
			continue
		}
		matches = append(matches, g)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no wallet grant found for actor=%s task=%s mode=%s", actorDID, taskID, mode)
	}
	// Prefer the most specific grant (lowest remainingDepth, deterministic newest ID).
	slices.SortStableFunc(matches, func(a, b *GrantBundle) int {
		if a.Claims.RemainingDepth != b.Claims.RemainingDepth {
			if a.Claims.RemainingDepth < b.Claims.RemainingDepth {
				return -1
			}
			return 1
		}
		return strings.Compare(b.Claims.ID, a.Claims.ID)
	})
	return matches[0], nil
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func didWebHost(did string) string {
	if !strings.HasPrefix(did, "did:web:") {
		return ""
	}
	rest := strings.TrimPrefix(did, "did:web:")
	host, _, _ := strings.Cut(rest, ":")
	return strings.Split(host, "%3A")[0]
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
