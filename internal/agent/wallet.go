package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"graduation-design/internal/protocol"
)

var (
	rePrivateKeyPEM = regexp.MustCompile(`(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
	reSDJWTSegment  = regexp.MustCompile(`~[A-Za-z0-9_-]{8,}`)
	reJWSCompact    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
)

// ActorConfig configures a local wallet actor with isolated key material and SD-JWT prefix.
type ActorConfig struct {
	Actor             string
	DID               string
	KeyID             string
	CredentialID      string
	KeyVersion        uint64
	DomainID          string
	EntityType        string
	Roles             []string
	PrivateKey        *ecdsa.PrivateKey
	SDJWTPresentation string
}

type actorSigner struct {
	actor             string
	did               string
	keyID             string
	credentialID      string
	keyVersion        uint64
	domainID          string
	entityType        string
	roles             []string
	privateKey        *ecdsa.PrivateKey
	sdJWTPresentation string
}

// GrantBundle captures a delivered delegation grant and its proof chain kept inside the local wallet.
type GrantBundle struct {
	Claims              protocol.GrantClaims
	TaskSpec            protocol.TaskSpec
	RawGrantJWS         string
	Digest              string
	ChainRawGrants      []string
	AncestorCredentials []protocol.AncestorCredential
	TrustPaths          []protocol.TrustPathEntry
	Anchored            bool
}

// SanitizedGrantView exposes safe delegation metadata to MCP clients and LLMs without raw tokens or salts.
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
	TrustPathCount    int      `json:"trustPathCount"`
	AncestorCount     int      `json:"ancestorCount"`
}

// ClientActionView summarizes an order execution intent lock for inspection without sensitive secrets.
type ClientActionView struct {
	ActionID       string `json:"actionId"`
	Actor          string `json:"actor"`
	TaskID         string `json:"taskId"`
	Action         string `json:"action"`
	IdempotencyKey string `json:"idempotencyKey"`
	Status         string `json:"status"`
	ChallengeID    string `json:"challengeId,omitempty"`
	QuoteID        string `json:"quoteId,omitempty"`
	OrderID        string `json:"orderId,omitempty"`
	DecisionID     string `json:"decisionId,omitempty"`
}

// QuoteSummary remembers quote fields internally so create_order can construct deterministic requests.
type QuoteSummary struct {
	QuoteID          string `json:"quoteId"`
	TaskID           string `json:"taskId"`
	Actor            string `json:"actor"`
	SupplierID       string `json:"supplierId"`
	ProductID        string `json:"productId"`
	Quantity         int64  `json:"quantity"`
	Currency         string `json:"currency"`
	UnitPriceMinor   int64  `json:"unitPriceMinor"`
	TotalAmountMinor int64  `json:"totalAmountMinor"`
	ValidUntil       int64  `json:"validUntil"`
}

// AnchorChildGrantRequest provides inputs from delegate_grant when anchoring a child grant onto a ledger.
type AnchorChildGrantRequest struct {
	Claims      protocol.GrantClaims
	RawGrantJWS string
	GrantDigest string
	ParentID    string
	IssuerActor string
	GranteeDID  string
}

// AnchorChildGrantResult returns the anchored trust paths and optional receipt metadata from the ledger.
type AnchorChildGrantResult struct {
	Anchored            bool
	TrustPaths          []protocol.TrustPathEntry
	AncestorCredentials []protocol.AncestorCredential
}

// WalletConfig configures WalletContext.
type WalletConfig struct {
	DeploymentID    string
	GatewayURL      string
	Audience        string
	SupplierID      string
	SupplierDID     string
	DefaultTaskSpec protocol.TaskSpec
	Currency        string
	DB              *pgxpool.Pool
	HTTPClient      *http.Client
	HTTPHandler     http.Handler
	Now             func() time.Time
	AnchorChildFunc func(ctx context.Context, req AnchorChildGrantRequest) (*AnchorChildGrantResult, error)
}

// WalletContext isolates actor private keys and SD-JWT credentials behind an MCP tool boundary.
type WalletContext struct {
	mu        sync.Mutex
	cfg       WalletConfig
	signers   map[string]*actorSigner
	grants    []*GrantBundle
	quotes    map[string]QuoteSummary
	actions   map[string]*ClientActionView
	actionSeq int
	secrets   []string
}

// NewWalletContext validates cfg and returns an empty isolated WalletContext.
func NewWalletContext(cfg WalletConfig) (*WalletContext, error) {
	if cfg.DeploymentID == "" {
		return nil, errors.New("agent wallet requires DeploymentID")
	}
	if cfg.Audience == "" {
		cfg.Audience = "https://c.local"
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
	if cfg.HTTPClient == nil && cfg.HTTPHandler == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &WalletContext{
		cfg:     cfg,
		signers: make(map[string]*actorSigner),
		quotes:  make(map[string]QuoteSummary),
		actions: make(map[string]*ClientActionView),
	}, nil
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
func (w *WalletContext) RegisterActor(cfg ActorConfig) error {
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
	w.mu.Lock()
	defer w.mu.Unlock()
	w.signers[cfg.Actor] = &actorSigner{
		actor:             cfg.Actor,
		did:               cfg.DID,
		keyID:             cfg.KeyID,
		credentialID:      cfg.CredentialID,
		keyVersion:        cfg.KeyVersion,
		domainID:          cfg.DomainID,
		entityType:        cfg.EntityType,
		roles:             slices.Clone(cfg.Roles),
		privateKey:        cfg.PrivateKey,
		sdJWTPresentation: cfg.SDJWTPresentation,
	}
	w.secrets = append(w.secrets, cfg.SDJWTPresentation)
	if idx := strings.IndexByte(cfg.SDJWTPresentation, '~'); idx >= 0 && idx+1 < len(cfg.SDJWTPresentation) {
		for _, part := range strings.Split(cfg.SDJWTPresentation[idx+1:], "~") {
			if len(part) >= 6 {
				w.secrets = append(w.secrets, part)
			}
		}
	}
	return nil
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
		bundle.Digest = base64.RawURLEncoding.EncodeToString(sum[:])
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
	// Prefer the most specific grant (lowest remainingDepth, newest order) when multiple match.
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

// ResolveDefaultOutputDir returns a clean path inside workspace for ephemeral wallet or evidence artifacts.
func ResolveDefaultOutputDir(base, name string) string {
	if base == "" {
		return filepath.Join(os.TempDir(), name)
	}
	return filepath.Join(base, name)
}

func actionMapKey(actor, taskID, action, idempotencyKey string) string {
	return strings.Join([]string{actor, taskID, action, idempotencyKey}, "|")
}

// SanitizeJSONForLog marshals v and scrubs any accidental secret fragments before writing traces or logs.
func (w *WalletContext) SanitizeJSONForLog(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return w.SanitizeString(err.Error())
	}
	return w.SanitizeString(string(b))
}
