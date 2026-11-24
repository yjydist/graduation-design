package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"grad/platform/internal/httpx"
	"grad/protocol"
)

// InspectWalletInput filters wallet metadata returned to an AI agent without exposing private keys or salts.
type InspectWalletInput struct {
	Actor             string `json:"actor" jsonschema:"Logical actor name such as A1 or B1 whose wallet grants and intent actions should be inspected."`
	TaskID            string `json:"taskId,omitempty" jsonschema:"Optional task ID filter."`
	AuthorizationMode string `json:"authorizationMode,omitempty" jsonschema:"Optional authorization mode filter (RESOURCE_PREAUTHORIZED or BUYER_MANDATE)."`
}

// InspectWalletOutput exposes safe actor identity metadata, active grants, quotes, orders, and persisted client actions.
type InspectWalletOutput struct {
	DeploymentID  string               `json:"deploymentId"`
	Actor         string               `json:"actor"`
	DID           string               `json:"did,omitempty"`
	DomainID      string               `json:"domainId,omitempty"`
	Roles         []string             `json:"roles,omitempty"`
	Grants        []SanitizedGrantView `json:"grants"`
	Quotes        []QuoteRecord        `json:"quotes,omitempty"`
	Orders        []OrderRecord        `json:"orders,omitempty"`
	ClientActions []ClientActionView   `json:"clientActions,omitempty"`
}

// DelegateGrantInput describes child grant creation (for example A1 issuing G2 to B1).
type DelegateGrantInput struct {
	IssuerActor       string `json:"issuerActor" jsonschema:"Actor issuing the child grant, for example A1."`
	SubjectActor      string `json:"subjectActor,omitempty" jsonschema:"Logical recipient actor name (for example B1) if subjectDid is omitted."`
	SubjectDID        string `json:"subjectDid,omitempty" jsonschema:"Recipient DID (grantee). Resolved from subjectActor if omitted."`
	ParentGrantID     string `json:"parentGrantId" jsonschema:"Parent grant ID held by issuerActor (for example G1)."`
	GrantID           string `json:"grantId,omitempty" jsonschema:"Child grant ID to issue; auto-generated if omitted."`
	TaskID            string `json:"taskId,omitempty" jsonschema:"Task ID bound to this delegation; defaults to parent grant taskId."`
	AuthorizationMode string `json:"authorizationMode,omitempty" jsonschema:"Authorization mode; defaults to parent grant mode."`
	MaxAmountMinor    int64  `json:"maxAmountMinor" jsonschema:"Narrowed minor currency ceiling for the child grant."`
	RemainingDepth    int    `json:"remainingDepth" jsonschema:"Remaining delegation depth (must be strictly less than parent remainingDepth)."`
	ExpiresInSeconds  int64  `json:"expiresInSeconds,omitempty" jsonschema:"Optional lifetime in seconds clamped to parent exp."`
}

// DelegateGrantOutput returns sanitized metadata for the newly issued child grant.
type DelegateGrantOutput struct {
	Grant    SanitizedGrantView `json:"grant"`
	Anchored bool               `json:"anchored"`
	Note     string             `json:"note,omitempty"`
}

// ReplaceGrantInput atomically revokes an old child grant and issues a narrowed replacement to a new delegate.
type ReplaceGrantInput struct {
	IssuerActor      string `json:"issuerActor" jsonschema:"Actor revoking and replacing the old child grant, for example A1."`
	OldGrantID       string `json:"oldGrantId" jsonschema:"Existing child grant ID to atomically revoke and replace (for example G2 issued to B1)."`
	NewSubjectActor  string `json:"newSubjectActor,omitempty" jsonschema:"New logical recipient actor (for example B2) if newSubjectDid is omitted."`
	NewSubjectDID    string `json:"newSubjectDid,omitempty" jsonschema:"New recipient DID (grantee). Resolved from newSubjectActor if omitted."`
	NewGrantID       string `json:"newGrantId,omitempty" jsonschema:"Replacement child grant ID; auto-generated if omitted."`
	MaxAmountMinor   int64  `json:"maxAmountMinor,omitempty" jsonschema:"Narrowed minor currency ceiling for the replacement grant; defaults to parent ceiling clamped to old grant."`
	RemainingDepth   int    `json:"remainingDepth" jsonschema:"Remaining delegation depth (must be strictly less than parent remainingDepth)."`
	ExpiresInSeconds int64  `json:"expiresInSeconds,omitempty" jsonschema:"Optional lifetime in seconds clamped to parent exp."`
	Reason           string `json:"reason,omitempty" jsonschema:"Optional replacement reason."`
}

// ReplaceGrantOutput returns sanitized metadata for the revoked grant ID and newly delivered replacement grant.
type ReplaceGrantOutput struct {
	RevokedGrantID   string             `json:"revokedGrantId"`
	ReplacementGrant SanitizedGrantView `json:"replacementGrant"`
	Anchored         bool               `json:"anchored"`
	Note             string             `json:"note,omitempty"`
}

// RequestQuoteInput triggers quote.read against supplier gateway C using the actor's active wallet grant.
type RequestQuoteInput struct {
	Actor             string  `json:"actor" jsonschema:"Acting wallet agent (for example B1)."`
	GrantID           string  `json:"grantId,omitempty" jsonschema:"Optional explicit grant ID held by actor; automatically selects matching leaf grant when omitted."`
	TaskID            string  `json:"taskId" jsonschema:"Target procurement task ID."`
	AuthorizationMode string  `json:"authorizationMode" jsonschema:"RESOURCE_PREAUTHORIZED or BUYER_MANDATE."`
	ProductID         string  `json:"productId" jsonschema:"Product identifier such as urn:grad:product:P1."`
	Quantity          int64   `json:"quantity" jsonschema:"Requested integer quantity >= 1."`
	IdempotencyKey    string  `json:"idempotencyKey,omitempty" jsonschema:"Optional caller idempotency key; generated if empty."`
	BlockHeight       *uint64 `json:"blockHeight,omitempty" jsonschema:"Optional Fabric block height pinned in the access request."`
}

// RequestQuoteOutput returns gateway quote.read decision details and quoted pricing.
type RequestQuoteOutput struct {
	Decision         string `json:"decision"`
	StatusCode       int    `json:"statusCode"`
	DecisionID       string `json:"decisionId,omitempty"`
	QuoteID          string `json:"quoteId,omitempty"`
	TaskID           string `json:"taskId"`
	ProductID        string `json:"productId"`
	Quantity         int64  `json:"quantity"`
	UnitPriceMinor   int64  `json:"unitPriceMinor,omitempty"`
	TotalAmountMinor int64  `json:"totalAmountMinor,omitempty"`
	Currency         string `json:"currency,omitempty"`
	ValidUntil       int64  `json:"validUntil,omitempty"`
	ErrorCode        string `json:"errorCode,omitempty"`
	ErrorMessage     string `json:"errorMessage,omitempty"`
}

// CreateOrderInput triggers order.create after persisting an intent lock into client_actions.
type CreateOrderInput struct {
	Actor             string  `json:"actor" jsonschema:"Acting wallet agent (for example B1)."`
	GrantID           string  `json:"grantId,omitempty" jsonschema:"Optional explicit grant ID held by actor."`
	TaskID            string  `json:"taskId" jsonschema:"Target procurement task ID."`
	AuthorizationMode string  `json:"authorizationMode" jsonschema:"RESOURCE_PREAUTHORIZED or BUYER_MANDATE."`
	QuoteID           string  `json:"quoteId" jsonschema:"Quote ID returned by request_quote."`
	ProductID         string  `json:"productId,omitempty" jsonschema:"Product ID matching the quote; filled from cached quote if omitted."`
	Quantity          int64   `json:"quantity,omitempty" jsonschema:"Quantity matching the quote; filled from cached quote if omitted."`
	AmountMinor       int64   `json:"amountMinor" jsonschema:"Order amount in minor currency units presented for authorization and quote verification."`
	Currency          string  `json:"currency,omitempty" jsonschema:"ISO currency code (defaults to CNY)."`
	IdempotencyKey    string  `json:"idempotencyKey" jsonschema:"Deterministic caller idempotency key persisted in client_actions before gateway submission."`
	BlockHeight       *uint64 `json:"blockHeight,omitempty" jsonschema:"Optional Fabric block height pinned in the access request."`
}

// CreateOrderOutput returns gateway order.create decision details plus intent lock tracking metadata.
type CreateOrderOutput struct {
	Decision         string `json:"decision"`
	StatusCode       int    `json:"statusCode"`
	ActionID         string `json:"actionId,omitempty"`
	ActionStatus     string `json:"actionStatus,omitempty"`
	SendRevision     int64  `json:"sendRevision,omitempty"`
	DecisionID       string `json:"decisionId,omitempty"`
	OrderID          string `json:"orderId,omitempty"`
	QuoteID          string `json:"quoteId"`
	ProductID        string `json:"productId,omitempty"`
	Quantity         int64  `json:"quantity,omitempty"`
	TotalAmountMinor int64  `json:"totalAmountMinor,omitempty"`
	Currency         string `json:"currency,omitempty"`
	ErrorCode        string `json:"errorCode,omitempty"`
	ErrorMessage     string `json:"errorMessage,omitempty"`
}

// ReconcileOrderInput stops retrying an unknown order intent and reconciles its ground-truth outcome via C audit.
type ReconcileOrderInput struct {
	Actor          string `json:"actor" jsonschema:"Original acting wallet agent (for example B1) whose unknown order intent should be stopped and reconciled."`
	TaskID         string `json:"taskId" jsonschema:"Procurement task ID."`
	IdempotencyKey string `json:"idempotencyKey" jsonschema:"Original order idempotencyKey persisted in client_actions."`
	CaseID         string `json:"caseId,omitempty" jsonschema:"Optional deterministic case ID."`
	Action         string `json:"action,omitempty" jsonschema:"Action name (defaults to order.create)."`
}

// ReconcileOrderOutput returns sanitized reconciliation outcome and historical audit result without exposing secrets.
type ReconcileOrderOutput struct {
	CaseID             string   `json:"caseId"`
	SendRevision       int64    `json:"sendRevision"`
	Outcome            string   `json:"outcome"`
	HistoricalStatus   string   `json:"historicalStatus,omitempty"`
	HistoricalReason   string   `json:"historicalReason,omitempty"`
	OrderID            string   `json:"orderId,omitempty"`
	CreationDecisionID string   `json:"creationDecisionId,omitempty"`
	ActionStatus       string   `json:"actionStatus"`
	CheckNo            int64    `json:"checkNo"`
	ChallengeIDs       []string `json:"challengeIds,omitempty"`
	ErrorCode          string   `json:"errorCode,omitempty"`
	ErrorMessage       string   `json:"errorMessage,omitempty"`
}

var (
	inspectWalletTool = mcp.Tool{
		Name:        "inspect_wallet",
		Description: "Inspect actor DID, authorized grants, remaining delegation depth, amount ceilings, cached quotes, orders, and client_actions intent locks without exposing private keys or SD-JWT disclosures.",
	}
	delegateGrantTool = mcp.Tool{
		Name:        "delegate_grant",
		Description: "Sign and optionally anchor a narrowed child delegation grant (such as A1 issuing G2 to B1) using isolated wallet key material.",
	}
	replaceGrantTool = mcp.Tool{
		Name:        "replace_grant",
		Description: "Atomically revoke an existing child grant and issue/deliver a narrowed replacement grant to another delegate (such as B2) using isolated wallet key material.",
	}
	requestQuoteTool = mcp.Tool{
		Name:        "request_quote",
		Description: "Obtain a binding supplier quote via gateway quote.read with fresh challenge authentication and KB-JWT proof.",
	}
	createOrderTool = mcp.Tool{
		Name:        "create_order",
		Description: "Persist a client_actions intent lock (OUTCOME_UNKNOWN + sendRevision) first, then submit an authenticated order.create request bound to a quoteId and idempotencyKey.",
	}
	reconcileOrderTool = mcp.Tool{
		Name:        "reconcile_order",
		Description: "Increment sendRevision to stop delayed retries on an unknown order, register the reconciliation case with C, trigger C audit and historical h/r review, and persist the receipt.",
	}
)

func newWalletMCPServer() *mcp.Server {
	return mcp.NewServer(&mcp.Implementation{Name: "grad-auth-wallet", Version: "v1.0.0"}, nil)
}

func addWalletTool[In, Out any](srv *mcp.Server, tool mcp.Tool, run func(context.Context, In) (Out, error), bound bool) {
	mcp.AddTool(srv, &tool, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		out, err := run(ctx, in)
		if !bound || err == nil {
			return nil, out, err
		}
		code := protocol.CodeOf(err)
		if code == "" {
			code = protocol.ErrCodeInvalidSchema
		}
		body, _ := json.Marshal(map[string]string{"code": code, "message": "workbench operation declined"})
		return nil, out, errors.New(string(body))
	})
}

// NewMCPServer registers the six grad-auth-v1 agent wallet tools over the official MCP Go SDK.
func NewMCPServer(wallet *WalletContext) *mcp.Server {
	srv := newWalletMCPServer()
	addWalletTool(srv, inspectWalletTool, wallet.InspectWallet, false)
	addWalletTool(srv, delegateGrantTool, wallet.DelegateGrant, false)
	addWalletTool(srv, replaceGrantTool, wallet.ReplaceGrant, false)
	addWalletTool(srv, requestQuoteTool, wallet.RequestQuote, false)
	addWalletTool(srv, createOrderTool, wallet.CreateOrder, false)
	addWalletTool(srv, reconcileOrderTool, wallet.ReconcileOrder, false)
	return srv
}

// InspectWallet returns sanitized wallet state for direct Go callers and the inspect_wallet MCP tool.
func (w *WalletContext) InspectWallet(ctx context.Context, in InspectWalletInput) (InspectWalletOutput, error) {
	w.mu.Lock()
	out := InspectWalletOutput{
		DeploymentID: w.cfg.DeploymentID,
		Actor:        in.Actor,
		Grants:       []SanitizedGrantView{},
	}
	var actorDID string
	if in.Actor != "" {
		signer, ok := w.signers[in.Actor]
		if !ok {
			w.mu.Unlock()
			return InspectWalletOutput{}, fmt.Errorf("unknown actor %q in wallet", in.Actor)
		}
		actorDID = signer.DID
		out.DID = signer.DID
		out.DomainID = signer.DomainID
		out.Roles = slices.Clone(signer.Roles)
	}
	for _, g := range w.grants {
		if actorDID != "" && g.Claims.Grantee != actorDID {
			continue
		}
		if in.TaskID != "" && g.Claims.TaskID != in.TaskID {
			continue
		}
		if in.AuthorizationMode != "" && g.Claims.AuthorizationMode != in.AuthorizationMode {
			continue
		}
		out.Grants = append(out.Grants, g.view())
	}
	for _, q := range w.quotes {
		if in.Actor != "" && q.Actor != in.Actor && q.Actor != actorDID {
			continue
		}
		if in.TaskID != "" && q.TaskID != in.TaskID {
			continue
		}
		out.Quotes = append(out.Quotes, q)
	}
	for _, ord := range w.orders {
		if in.Actor != "" && ord.Actor != in.Actor && ord.Actor != actorDID {
			continue
		}
		if in.TaskID != "" && ord.TaskID != in.TaskID {
			continue
		}
		out.Orders = append(out.Orders, ord)
	}
	w.mu.Unlock()

	slices.SortFunc(out.Quotes, func(a, b QuoteRecord) int {
		return strings.Compare(a.QuoteID, b.QuoteID)
	})
	slices.SortFunc(out.Orders, func(a, b OrderRecord) int {
		return strings.Compare(a.OrderID, b.OrderID)
	})

	actions, err := w.store.ListClientActions(ctx, actorDID, in.TaskID)
	if err == nil && len(actions) > 0 {
		out.ClientActions = make([]ClientActionView, len(actions))
		for i, a := range actions {
			out.ClientActions[i] = a.View()
		}
	}
	return out, nil
}

// DelegateGrant signs and optionally anchors a narrowed child delegation grant.
func (w *WalletContext) DelegateGrant(ctx context.Context, in DelegateGrantInput) (DelegateGrantOutput, error) {
	if in.IssuerActor == "" {
		return DelegateGrantOutput{}, errors.New("issuerActor is required")
	}
	if in.ParentGrantID == "" {
		return DelegateGrantOutput{}, errors.New("parentGrantId is required")
	}
	if in.MaxAmountMinor <= 0 {
		return DelegateGrantOutput{}, errors.New("maxAmountMinor must be > 0")
	}
	if in.RemainingDepth < 0 {
		return DelegateGrantOutput{}, errors.New("remainingDepth must be >= 0")
	}

	var recipient *GrantRecipient
	if w.cfg.ResolveGrantRecipient != nil && in.SubjectDID != "" && in.SubjectActor == "" {
		resolved, err := w.cfg.ResolveGrantRecipient(ctx, in.SubjectDID)
		if err != nil {
			return DelegateGrantOutput{}, err
		}
		if resolved.DID != in.SubjectDID || resolved.KeyVersion == 0 || resolved.CredentialID == "" {
			return DelegateGrantOutput{}, executionMismatch("resolved recipient differs from delegation")
		}
		recipient = &resolved
	}

	w.mu.Lock()
	issuer, ok := w.signers[in.IssuerActor]
	if !ok {
		w.mu.Unlock()
		return DelegateGrantOutput{}, fmt.Errorf("unknown issuerActor %q", in.IssuerActor)
	}
	parent, err := w.findGrantLocked(issuer.DID, in.ParentGrantID, in.TaskID, in.AuthorizationMode)
	if err != nil {
		w.mu.Unlock()
		return DelegateGrantOutput{}, err
	}
	subjectDID, granteeSigner, err := w.resolveSubjectLocked(in.SubjectActor, in.SubjectDID)
	if err != nil {
		w.mu.Unlock()
		return DelegateGrantOutput{}, err
	}
	if recipient != nil {
		granteeSigner = &Signer{DID: recipient.DID, KeyVersion: recipient.KeyVersion, CredentialID: recipient.CredentialID}
	}
	signed, err := w.signChildGrantLocked(issuer, parent, granteeSigner, subjectDID, in.GrantID, in.TaskID, in.AuthorizationMode, in.MaxAmountMinor, in.RemainingDepth, in.ExpiresInSeconds)
	if err != nil {
		w.mu.Unlock()
		return DelegateGrantOutput{}, errors.New(w.SanitizeString(err.Error()))
	}
	parentID := parent.Claims.ID
	anchorHook := w.cfg.AnchorChildFunc
	w.mu.Unlock()

	anchored := false
	note := "signed locally with isolated actor key"
	if anchorHook != nil {
		res, err := anchorHook(ctx, AnchorChildGrantRequest{
			Claims:                   signed.claims,
			RawGrantJWS:              signed.rawJWS,
			GrantDigest:              signed.digest,
			ParentID:                 parentID,
			IssuerActor:              in.IssuerActor,
			GranteeDID:               subjectDID,
			RequestedLifetimeSeconds: in.ExpiresInSeconds,
		})
		if err != nil {
			if code := protocol.CodeOf(err); code != "" {
				return DelegateGrantOutput{}, protocol.NewError(code, w.SanitizeString(err.Error()))
			}
			return DelegateGrantOutput{}, fmt.Errorf("anchor child grant: %s", w.SanitizeString(err.Error()))
		}
		if res != nil {
			anchored = res.Anchored
			if res.Grant != nil {
				signed.claims = res.Grant.Claims
				signed.rawJWS = res.Grant.RawGrantJWS
				signed.digest = res.Grant.Digest
				signed.chain = slices.Clone(res.Grant.ChainRawGrants)
				signed.ancestors = slices.Clone(res.Grant.AncestorCredentials)
				signed.trustPaths = slices.Clone(res.Grant.TrustPaths)
				signed.taskSpec = res.Grant.TaskSpec
			}
			if len(res.TrustPaths) > 0 {
				signed.trustPaths = slices.Clone(res.TrustPaths)
			}
			if len(res.AncestorCredentials) > 0 {
				signed.ancestors = slices.Clone(res.AncestorCredentials)
			}
		}
		if anchored {
			note = "signed and anchored onto registry"
		}
	}

	childBundle := GrantBundle{
		Claims:              signed.claims,
		TaskSpec:            signed.taskSpec,
		RawGrantJWS:         signed.rawJWS,
		Digest:              signed.digest,
		ChainRawGrants:      signed.chain,
		AncestorCredentials: signed.ancestors,
		TrustPaths:          signed.trustPaths,
		Anchored:            anchored,
		Revision:            1,
	}
	if err := w.AddGrantBundle(childBundle); err != nil {
		return DelegateGrantOutput{}, err
	}
	return DelegateGrantOutput{
		Grant:    childBundle.view(),
		Anchored: anchored,
		Note:     note,
	}, nil
}

// ReplaceGrant atomically revokes an old child grant and issues/delivers a narrowed replacement to a new delegate.
func (w *WalletContext) ReplaceGrant(ctx context.Context, in ReplaceGrantInput) (ReplaceGrantOutput, error) {
	if in.IssuerActor == "" || in.OldGrantID == "" {
		return ReplaceGrantOutput{}, errors.New("issuerActor and oldGrantId are required")
	}
	if in.RemainingDepth < 0 {
		return ReplaceGrantOutput{}, errors.New("remainingDepth must be >= 0")
	}

	w.mu.Lock()
	issuer, ok := w.signers[in.IssuerActor]
	if !ok {
		w.mu.Unlock()
		return ReplaceGrantOutput{}, fmt.Errorf("unknown issuerActor %q", in.IssuerActor)
	}
	oldBundle, err := w.findGrantLocked("", in.OldGrantID, "", "")
	if err != nil {
		w.mu.Unlock()
		return ReplaceGrantOutput{}, err
	}
	if oldBundle.Claims.Issuer != issuer.DID {
		w.mu.Unlock()
		return ReplaceGrantOutput{}, fmt.Errorf("old grant %q was issued by %q, not %q", in.OldGrantID, oldBundle.Claims.Issuer, issuer.DID)
	}
	if oldBundle.Replaced {
		w.mu.Unlock()
		return ReplaceGrantOutput{}, fmt.Errorf("old grant %q already replaced", in.OldGrantID)
	}
	if oldBundle.Claims.ParentID == nil || *oldBundle.Claims.ParentID == "" {
		w.mu.Unlock()
		return ReplaceGrantOutput{}, fmt.Errorf("old grant %q missing parentId", in.OldGrantID)
	}
	parent, err := w.findGrantLocked(issuer.DID, *oldBundle.Claims.ParentID, oldBundle.Claims.TaskID, oldBundle.Claims.AuthorizationMode)
	if err != nil {
		w.mu.Unlock()
		return ReplaceGrantOutput{}, fmt.Errorf("parent grant %q for replacement not held by %s: %w", *oldBundle.Claims.ParentID, in.IssuerActor, err)
	}
	subjectDID, granteeSigner, err := w.resolveSubjectLocked(in.NewSubjectActor, in.NewSubjectDID)
	if err != nil {
		w.mu.Unlock()
		return ReplaceGrantOutput{}, err
	}
	maxAmt := in.MaxAmountMinor
	if maxAmt <= 0 {
		maxAmt = min(oldBundle.Claims.MaxAmountMinor, parent.Claims.MaxAmountMinor)
	}
	oldRev := oldBundle.Revision
	if oldRev == 0 {
		oldRev = 1
	}
	oldDigest := oldBundle.Digest
	signed, err := w.signChildGrantLocked(issuer, parent, granteeSigner, subjectDID, in.NewGrantID, oldBundle.Claims.TaskID, oldBundle.Claims.AuthorizationMode, maxAmt, in.RemainingDepth, in.ExpiresInSeconds)
	if err != nil {
		w.mu.Unlock()
		return ReplaceGrantOutput{}, errors.New(w.SanitizeString(err.Error()))
	}
	replaceHook := w.cfg.ReplaceGrantFunc
	w.mu.Unlock()

	anchored := false
	note := "replaced locally with isolated actor key"
	if replaceHook != nil {
		res, err := replaceHook(ctx, ReplaceGrantRequest{
			OldGrantID:       in.OldGrantID,
			OldGrantRevision: oldRev,
			OldGrantDigest:   oldDigest,
			NewClaims:        signed.claims,
			NewRawGrantJWS:   signed.rawJWS,
			NewGrantDigest:   signed.digest,
			IssuerActor:      in.IssuerActor,
			NewGranteeDID:    subjectDID,
			Reason:           in.Reason,
		})
		if err != nil {
			return ReplaceGrantOutput{}, fmt.Errorf("replace grant on registry: %s", w.SanitizeString(err.Error()))
		}
		if res != nil {
			anchored = res.Anchored
			if len(res.TrustPaths) > 0 {
				signed.trustPaths = slices.Clone(res.TrustPaths)
			}
			if len(res.AncestorCredentials) > 0 {
				signed.ancestors = slices.Clone(res.AncestorCredentials)
			}
		}
		if anchored {
			note = "atomically revoked old grant and delivered replacement onto registry"
		}
	}

	w.mu.Lock()
	if ob, err := w.findGrantLocked("", in.OldGrantID, "", ""); err == nil {
		ob.Replaced = true
	}
	w.mu.Unlock()

	newBundle := GrantBundle{
		Claims:              signed.claims,
		TaskSpec:            signed.taskSpec,
		RawGrantJWS:         signed.rawJWS,
		Digest:              signed.digest,
		ChainRawGrants:      signed.chain,
		AncestorCredentials: signed.ancestors,
		TrustPaths:          signed.trustPaths,
		Anchored:            anchored,
		Revision:            1,
	}
	if err := w.AddGrantBundle(newBundle); err != nil {
		return ReplaceGrantOutput{}, err
	}
	return ReplaceGrantOutput{
		RevokedGrantID:   in.OldGrantID,
		ReplacementGrant: newBundle.view(),
		Anchored:         anchored,
		Note:             note,
	}, nil
}

// RequestQuote obtains a binding supplier quote via gateway quote.read using canonical urn:grad:resource:C:quotes.
func (w *WalletContext) RequestQuote(ctx context.Context, in RequestQuoteInput) (RequestQuoteOutput, error) {
	return w.requestQuote(ctx, in, false)
}

func (w *WalletContext) requestQuote(ctx context.Context, in RequestQuoteInput, persistBoundQuote bool) (RequestQuoteOutput, error) {
	if in.Actor == "" || in.TaskID == "" || in.ProductID == "" || in.Quantity <= 0 {
		return RequestQuoteOutput{}, errors.New("actor, taskId, productId, and quantity > 0 are required")
	}
	idem := in.IdempotencyKey
	if idem == "" {
		idem = "quote-" + randomHex(6)
	}

	w.mu.Lock()
	signer, ok := w.signers[in.Actor]
	if !ok {
		w.mu.Unlock()
		return RequestQuoteOutput{}, fmt.Errorf("unknown actor %q in wallet", in.Actor)
	}
	grant, err := w.findGrantLocked(signer.DID, in.GrantID, in.TaskID, in.AuthorizationMode)
	if err != nil {
		w.mu.Unlock()
		return RequestQuoteOutput{}, err
	}
	currency := grant.Claims.Currency
	if currency == "" {
		currency = w.cfg.Currency
	}
	req := protocol.AccessRequest{
		SchemaVersion:     protocol.SchemaVersion,
		DeploymentID:      w.cfg.DeploymentID,
		Actor:             signer.DID,
		PrincipalDomain:   grant.Claims.PrincipalDomain,
		AuthorizationMode: grant.Claims.AuthorizationMode,
		TaskID:            in.TaskID,
		Audience:          w.cfg.Audience,
		Resource:          protocol.ResourceQuotes,
		Action:            protocol.ActionQuoteRead,
		SupplierID:        w.cfg.SupplierID,
		QuoteID:           nil,
		ProductID:         in.ProductID,
		Quantity:          in.Quantity,
		Currency:          currency,
		AmountMinor:       0,
		IdempotencyKey:    idem,
	}
	grantCopy := cloneGrantBundle(grant)
	signerCopy := *signer
	w.mu.Unlock()

	reqHash, err := req.Hash(false)
	if err != nil {
		return RequestQuoteOutput{}, err
	}
	code, execResp, gwErr, _, err := w.submitAccessExecute(ctx, &signerCopy, &grantCopy, req, reqHash, "", 0, "")
	if err != nil {
		return RequestQuoteOutput{}, errors.New(w.SanitizeString(err.Error()))
	}

	out := RequestQuoteOutput{
		StatusCode: code,
		TaskID:     in.TaskID,
		ProductID:  in.ProductID,
		Quantity:   in.Quantity,
		Currency:   req.Currency,
	}
	if code == http.StatusOK && execResp != nil {
		if persistBoundQuote && w.cfg.DB != nil {
			if err := w.saveBoundQuote(ctx, req, execResp.Quote); err != nil {
				return RequestQuoteOutput{}, err
			}
		}
		out.Decision = "ALLOW"
		out.DecisionID = execResp.DecisionID
		if execResp.Quote != nil {
			out.QuoteID = execResp.Quote.QuoteID
			out.UnitPriceMinor = execResp.Quote.UnitPriceMinor
			out.TotalAmountMinor = execResp.Quote.TotalAmountMinor
			out.Currency = execResp.Quote.Currency
			out.ValidUntil = execResp.Quote.ValidUntil
			w.mu.Lock()
			w.quotes[execResp.Quote.QuoteID] = QuoteRecord{
				QuoteID:          execResp.Quote.QuoteID,
				TaskID:           execResp.Quote.TaskID,
				Actor:            in.Actor,
				SupplierID:       execResp.Quote.SupplierID,
				ProductID:        execResp.Quote.ProductID,
				Quantity:         execResp.Quote.Quantity,
				Currency:         execResp.Quote.Currency,
				UnitPriceMinor:   execResp.Quote.UnitPriceMinor,
				TotalAmountMinor: execResp.Quote.TotalAmountMinor,
				IssuedAt:         execResp.Quote.IssuedAt,
				ValidUntil:       execResp.Quote.ValidUntil,
				IdempotencyKey:   idem,
			}
			w.mu.Unlock()
		}
		return out, nil
	}

	out.Decision = "DENY"
	if gwErr != nil {
		if gwErr.DecisionID != nil {
			out.DecisionID = *gwErr.DecisionID
		}
		out.ErrorCode = gwErr.Code
		out.ErrorMessage = w.SanitizeString(gwErr.Message)
	}
	return out, nil
}

// CreateOrder persists a durable OUTCOME_UNKNOWN client_actions intent lock BEFORE contacting gateway,
// binds the challenge nonce verbatim into a deterministic KB-JWT, and submits order.create against urn:grad:resource:C:orders.
func (w *WalletContext) CreateOrder(ctx context.Context, in CreateOrderInput) (CreateOrderOutput, error) {
	if in.Actor == "" || in.TaskID == "" || in.QuoteID == "" || in.IdempotencyKey == "" || in.AmountMinor <= 0 {
		return CreateOrderOutput{}, errors.New("actor, taskId, quoteId, idempotencyKey, and amountMinor > 0 are required")
	}

	w.mu.Lock()
	signer, ok := w.signers[in.Actor]
	if !ok {
		w.mu.Unlock()
		return CreateOrderOutput{}, fmt.Errorf("unknown actor %q in wallet", in.Actor)
	}
	grant, err := w.findGrantLocked(signer.DID, in.GrantID, in.TaskID, in.AuthorizationMode)
	if err != nil {
		w.mu.Unlock()
		return CreateOrderOutput{}, err
	}
	quote, hasQuote := w.quotes[in.QuoteID]
	productID := in.ProductID
	quantity := in.Quantity
	if productID == "" && hasQuote {
		productID = quote.ProductID
	}
	if quantity <= 0 && hasQuote {
		quantity = quote.Quantity
	}
	if productID == "" {
		productID = "urn:grad:product:P1"
	}
	if quantity <= 0 {
		quantity = 1
	}
	currency := in.Currency
	if currency == "" {
		currency = grant.Claims.Currency
	}
	if currency == "" {
		currency = w.cfg.Currency
	}
	quoteID := in.QuoteID
	req := protocol.AccessRequest{
		SchemaVersion:     protocol.SchemaVersion,
		DeploymentID:      w.cfg.DeploymentID,
		Actor:             signer.DID,
		PrincipalDomain:   grant.Claims.PrincipalDomain,
		AuthorizationMode: grant.Claims.AuthorizationMode,
		TaskID:            in.TaskID,
		Audience:          w.cfg.Audience,
		Resource:          protocol.ResourceOrders,
		Action:            protocol.ActionOrderCreate,
		SupplierID:        w.cfg.SupplierID,
		QuoteID:           &quoteID,
		ProductID:         productID,
		Quantity:          quantity,
		Currency:          currency,
		AmountMinor:       in.AmountMinor,
		IdempotencyKey:    in.IdempotencyKey,
	}
	grantCopy := cloneGrantBundle(grant)
	signerCopy := *signer
	w.mu.Unlock()

	reqHash, err := req.Hash(false)
	if err != nil {
		return CreateOrderOutput{}, err
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return CreateOrderOutput{}, err
	}

	// Persist durable OUTCOME_UNKNOWN intent lock BEFORE contacting gateway.
	actionRec, err := w.store.BeginClientAction(ctx, signerCopy.DID, in.TaskID, protocol.ActionOrderCreate, in.IdempotencyKey, reqHash, string(reqBytes))
	if err != nil {
		return CreateOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
	}
	w.mu.Lock()
	w.actionRequests[actionRec.ActionID] = req
	w.mu.Unlock()

	if actionRec.Status == ActionStatusCompleted || (actionRec.Status == ActionStatusReconciled && actionRec.Outcome == "CREATED") {
		return CreateOrderOutput{
			Decision:     "ALLOW",
			StatusCode:   http.StatusOK,
			ActionID:     actionRec.ActionID,
			ActionStatus: actionRec.Status,
			SendRevision: actionRec.SendRevision,
			DecisionID:   actionRec.DecisionID,
			OrderID:      actionRec.OrderID,
			QuoteID:      in.QuoteID,
			ProductID:    productID,
			Quantity:     quantity,
			Currency:     currency,
		}, nil
	}
	if actionRec.CaseID != "" || actionRec.Status == ActionStatusReconciled {
		return CreateOrderOutput{
			Decision:     "UNKNOWN",
			StatusCode:   http.StatusConflict,
			ActionID:     actionRec.ActionID,
			ActionStatus: actionRec.Status,
			SendRevision: actionRec.SendRevision,
			QuoteID:      in.QuoteID,
			ProductID:    productID,
			Quantity:     quantity,
			Currency:     currency,
			ErrorCode:    protocol.ErrCodeStateChanged,
			ErrorMessage: "intent is stopped for reconciliation",
		}, nil
	}

	code, execResp, gwErr, chalID, callErr := w.submitAccessExecute(ctx, &signerCopy, &grantCopy, req, reqHash, actionRec.ActionID, actionRec.SendRevision, string(reqBytes))

	// A stale/stopped worker rejected by STATE_CHANGED MUST NOT overwrite client_actions status.
	if protocol.HasCode(callErr, protocol.ErrCodeStateChanged) || (gwErr != nil && gwErr.Code == protocol.ErrCodeStateChanged && code == http.StatusConflict) {
		msg := "intent stopped before dispatch"
		if callErr != nil {
			msg = w.SanitizeString(callErr.Error())
		} else if gwErr != nil && gwErr.Message != "" {
			msg = w.SanitizeString(gwErr.Message)
		}
		return CreateOrderOutput{
			Decision:     "UNKNOWN",
			StatusCode:   http.StatusConflict,
			ActionID:     actionRec.ActionID,
			ActionStatus: ActionStatusOutcomeUnknown,
			SendRevision: actionRec.SendRevision,
			QuoteID:      in.QuoteID,
			ProductID:    productID,
			Quantity:     quantity,
			Currency:     currency,
			ErrorCode:    protocol.ErrCodeStateChanged,
			ErrorMessage: msg,
		}, nil
	}

	if callErr != nil || code >= http.StatusInternalServerError {
		// Preserve OUTCOME_UNKNOWN so reconcile_order can stop retries and query C audit.
		errCode := ActionStatusOutcomeUnknown
		errMsg := ""
		if callErr != nil {
			errMsg = w.SanitizeString(callErr.Error())
		}
		if gwErr != nil {
			if gwErr.Code != "" {
				errCode = gwErr.Code
			}
			if gwErr.Message != "" {
				errMsg = w.SanitizeString(gwErr.Message)
			}
		}
		return CreateOrderOutput{
			Decision:     "UNKNOWN",
			StatusCode:   code,
			ActionID:     actionRec.ActionID,
			ActionStatus: ActionStatusOutcomeUnknown,
			SendRevision: actionRec.SendRevision,
			QuoteID:      in.QuoteID,
			ProductID:    productID,
			Quantity:     quantity,
			Currency:     currency,
			ErrorCode:    errCode,
			ErrorMessage: errMsg,
		}, nil
	}

	out := CreateOrderOutput{
		StatusCode:   code,
		ActionID:     actionRec.ActionID,
		SendRevision: actionRec.SendRevision,
		QuoteID:      in.QuoteID,
		ProductID:    productID,
		Quantity:     quantity,
		Currency:     currency,
	}
	if code == http.StatusOK && execResp != nil && execResp.Order != nil {
		out.Decision = "ALLOW"
		out.ActionStatus = ActionStatusCompleted
		out.DecisionID = execResp.DecisionID
		out.OrderID = execResp.Order.OrderID
		out.ProductID = execResp.Order.ProductID
		out.Quantity = execResp.Order.Quantity
		out.TotalAmountMinor = execResp.Order.TotalAmountMinor
		out.Currency = execResp.Order.Currency
		if err := w.store.UpdateClientAction(ctx, actionRec.ActionID, ActionStatusCompleted, chalID, in.QuoteID, execResp.Order.OrderID, execResp.DecisionID); err != nil {
			return CreateOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
		}
		w.mu.Lock()
		w.orders[execResp.Order.OrderID] = OrderRecord{
			OrderID:          execResp.Order.OrderID,
			QuoteID:          execResp.Order.QuoteID,
			TaskID:           execResp.Order.TaskID,
			Actor:            in.Actor,
			SupplierID:       execResp.Order.SupplierID,
			ProductID:        execResp.Order.ProductID,
			Quantity:         execResp.Order.Quantity,
			Currency:         execResp.Order.Currency,
			TotalAmountMinor: execResp.Order.TotalAmountMinor,
			IdempotencyKey:   execResp.Order.IdempotencyKey,
			Status:           execResp.Order.Status,
			CreatedAt:        execResp.Order.CreatedAt,
		}
		w.mu.Unlock()
		return out, nil
	}

	out.Decision = "DENY"
	out.ActionStatus = ActionStatusFailed
	if gwErr != nil {
		if gwErr.DecisionID != nil {
			out.DecisionID = *gwErr.DecisionID
		}
		out.ErrorCode = gwErr.Code
		out.ErrorMessage = w.SanitizeString(gwErr.Message)
	}
	if err := w.store.UpdateClientAction(ctx, actionRec.ActionID, ActionStatusFailed, chalID, in.QuoteID, "", out.DecisionID); err != nil {
		return CreateOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
	}
	return out, nil
}

// ReconcileOrder atomically increments sendRevision to stop delayed retries, registers the order-outcome case
// via HTTP client, triggers/queries C audit, applies the returned receipt, and returns the sanitized recovery result.
func (w *WalletContext) ReconcileOrder(ctx context.Context, in ReconcileOrderInput) (ReconcileOrderOutput, error) {
	if in.Actor == "" || in.TaskID == "" || in.IdempotencyKey == "" {
		return ReconcileOrderOutput{}, errors.New("actor, taskId, and idempotencyKey are required")
	}
	action := in.Action
	if action == "" {
		action = protocol.ActionOrderCreate
	}

	w.mu.Lock()
	signer, ok := w.signers[in.Actor]
	if !ok {
		w.mu.Unlock()
		return ReconcileOrderOutput{}, fmt.Errorf("unknown actor %q in wallet", in.Actor)
	}
	actorDID := signer.DID
	w.mu.Unlock()

	existing, err := w.store.GetClientActionByKey(ctx, actorDID, in.TaskID, action, in.IdempotencyKey)
	if err != nil {
		return ReconcileOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
	}
	if existing.Status == ActionStatusReconciled || existing.Status == ActionStatusCompleted {
		outcome := existing.Outcome
		if outcome == "" && existing.OrderID != "" {
			outcome = "CREATED"
		}
		return ReconcileOrderOutput{
			CaseID:             existing.CaseID,
			SendRevision:       existing.SendRevision,
			Outcome:            outcome,
			OrderID:            existing.OrderID,
			CreationDecisionID: existing.DecisionID,
			ActionStatus:       existing.Status,
			ChallengeIDs:       slices.Clone(existing.ChallengeIDs),
		}, nil
	}

	var fallbackJSON string
	w.mu.Lock()
	if cachedReq, ok := w.actionRequests[existing.ActionID]; ok {
		if b, mErr := json.Marshal(cachedReq); mErr == nil {
			fallbackJSON = string(b)
		}
	}
	w.mu.Unlock()

	stopped, err := w.store.StopClientActionSend(ctx, actorDID, in.TaskID, action, in.IdempotencyKey, in.CaseID, fallbackJSON)
	if err != nil {
		return ReconcileOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
	}

	reqObj, err := w.resolveActionRequest(stopped, fallbackJSON)
	if err != nil {
		return ReconcileOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
	}
	reqHash, err := reqObj.Hash(false)
	if err != nil {
		return ReconcileOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
	}

	caseReq := OrderOutcomeCaseRequest{
		CaseID:       stopped.CaseID,
		SendRevision: stopped.SendRevision,
		DeploymentID: w.cfg.DeploymentID,
		Request:      reqObj,
		RequestHash:  reqHash,
		ChallengeIDs: slices.Clone(stopped.ChallengeIDs),
	}
	if _, caseCode, gwErr, err := w.client.RegisterOrderOutcomeCase(ctx, caseReq); err != nil {
		return ReconcileOrderOutput{
			CaseID:       stopped.CaseID,
			SendRevision: stopped.SendRevision,
			Outcome:      "UNKNOWN",
			ActionStatus: ActionStatusOutcomeUnknown,
			ChallengeIDs: slices.Clone(stopped.ChallengeIDs),
			ErrorCode:    protocol.ErrCodeStateUnavailable,
			ErrorMessage: w.SanitizeString(err.Error()),
		}, nil
	} else if caseCode != http.StatusAccepted {
		return ReconcileOrderOutput{
			CaseID:       stopped.CaseID,
			SendRevision: stopped.SendRevision,
			Outcome:      "UNKNOWN",
			ActionStatus: ActionStatusOutcomeUnknown,
			ChallengeIDs: slices.Clone(stopped.ChallengeIDs),
			ErrorCode:    gwErr.Code,
			ErrorMessage: w.SanitizeString(gwErr.Message),
		}, nil
	}

	auditReq := AuditOrderOutcomeRequest{
		CaseID:       stopped.CaseID,
		DeploymentID: w.cfg.DeploymentID,
		Request:      &reqObj,
		RequestHash:  reqHash,
		ChallengeIDs: slices.Clone(stopped.ChallengeIDs),
	}
	auditResp, auditCode, gwErr, err := w.client.AuditOrderOutcome(ctx, auditReq)
	if err != nil {
		return ReconcileOrderOutput{
			CaseID:       stopped.CaseID,
			SendRevision: stopped.SendRevision,
			Outcome:      "UNKNOWN",
			ActionStatus: ActionStatusOutcomeUnknown,
			ChallengeIDs: slices.Clone(stopped.ChallengeIDs),
			ErrorCode:    protocol.ErrCodeStateUnavailable,
			ErrorMessage: w.SanitizeString(err.Error()),
		}, nil
	}
	if auditCode != http.StatusOK || auditResp == nil {
		return ReconcileOrderOutput{
			CaseID:       stopped.CaseID,
			SendRevision: stopped.SendRevision,
			Outcome:      "UNKNOWN",
			ActionStatus: ActionStatusOutcomeUnknown,
			ChallengeIDs: slices.Clone(stopped.ChallengeIDs),
			ErrorCode:    gwErr.Code,
			ErrorMessage: w.SanitizeString(gwErr.Message),
		}, nil
	}

	var recResp *OrderOutcomeReceiptResponse
	switch {
	case w.cfg.ReceiptDelivery != nil:
		recResp, err = w.cfg.ReceiptDelivery(ctx, auditResp.Receipt)
	case w.client.HasReceiptClient():
		var recCode int
		var recErr *GatewayError
		recResp, recCode, recErr, err = w.client.DeliverOrderOutcomeReceipt(ctx, auditResp.Receipt)
		if err == nil && recCode != http.StatusOK {
			return ReconcileOrderOutput{
				CaseID:       stopped.CaseID,
				SendRevision: stopped.SendRevision,
				Outcome:      "UNKNOWN",
				ActionStatus: ActionStatusOutcomeUnknown,
				ChallengeIDs: slices.Clone(stopped.ChallengeIDs),
				ErrorCode:    recErr.Code,
				ErrorMessage: w.SanitizeString(recErr.Message),
			}, nil
		}
	default:
		recResp, err = w.ApplyOrderOutcomeReceipt(ctx, auditResp.Receipt)
	}
	if err != nil {
		errCode := protocol.CodeOf(err)
		if errCode == "" {
			errCode = "RECEIPT_DELIVERY_FAILED"
		}
		return ReconcileOrderOutput{
			CaseID:       stopped.CaseID,
			SendRevision: stopped.SendRevision,
			Outcome:      "UNKNOWN",
			ActionStatus: ActionStatusOutcomeUnknown,
			ChallengeIDs: slices.Clone(stopped.ChallengeIDs),
			ErrorCode:    errCode,
			ErrorMessage: w.SanitizeString(err.Error()),
		}, nil
	}

	finalActionStatus := ""
	if recResp != nil {
		finalActionStatus = recResp.ClientActionStatus
	}
	if finalActionStatus == "" {
		if auditResp.Outcome == "CREATED" || auditResp.Outcome == "NOT_CREATED" {
			finalActionStatus = ActionStatusReconciled
		} else {
			finalActionStatus = ActionStatusOutcomeUnknown
		}
	}

	return ReconcileOrderOutput{
		CaseID:             auditResp.CaseID,
		SendRevision:       auditResp.SendRevision,
		Outcome:            auditResp.Outcome,
		HistoricalStatus:   auditResp.HistoricalStatus,
		HistoricalReason:   auditResp.HistoricalReason,
		OrderID:            derefString(auditResp.OrderID),
		CreationDecisionID: derefString(auditResp.CreationDecisionID),
		ActionStatus:       finalActionStatus,
		CheckNo:            auditResp.CheckNo,
		ChallengeIDs:       slices.Clone(auditResp.LockedChallengeIDs),
	}, nil
}

func (w *WalletContext) resolveActionRequest(act *ClientAction, fallbackJSON string) (protocol.AccessRequest, error) {
	rawJSON := act.RequestJSON
	if rawJSON == "" {
		rawJSON = fallbackJSON
	}
	if rawJSON != "" {
		var reqObj protocol.AccessRequest
		if err := json.Unmarshal([]byte(rawJSON), &reqObj); err != nil {
			return protocol.AccessRequest{}, fmt.Errorf("decode stored request_json: %w", err)
		}
		return reqObj, nil
	}
	w.mu.Lock()
	cached, ok := w.actionRequests[act.ActionID]
	w.mu.Unlock()
	if !ok {
		return protocol.AccessRequest{}, errors.New("stored request payload unavailable for reconciliation")
	}
	return cached, nil
}

func (w *WalletContext) submitAccessExecute(
	ctx context.Context,
	signer *Signer,
	grant *GrantBundle,
	req protocol.AccessRequest,
	reqHash string,
	actionID string,
	expectedSendRevision int64,
	requestJSON string,
) (int, *ExecuteResponse, *GatewayError, string, error) {
	chal, chalCode, gwErr, err := w.client.CreateChallenge(ctx, ChallengeRequest{
		Actor:       req.Actor,
		TaskID:      req.TaskID,
		RequestHash: reqHash,
	})
	if err != nil {
		return 0, nil, nil, "", err
	}
	if chalCode != http.StatusCreated || chal == nil {
		return chalCode, nil, gwErr, "", nil
	}

	if actionID != "" {
		if _, err := w.store.RecordClientActionChallenge(ctx, actionID, expectedSendRevision, chal.ChallengeID, requestJSON); err != nil {
			return http.StatusConflict, nil, &GatewayError{
				StatusCode: http.StatusConflict,
				ErrorEnvelope: httpx.ErrorEnvelope{
					Code:    protocol.ErrCodeStateChanged,
					Message: err.Error(),
				},
			}, chal.ChallengeID, err
		}
	}

	taskSpec := grant.TaskSpec
	if taskSpec.SupplierID == "" {
		taskSpec = w.cfg.DefaultTaskSpec
	}
	pkg := protocol.AccessEvidencePackage{
		Request:             req,
		TaskSpec:            taskSpec,
		ChallengeID:         chal.ChallengeID,
		AncestorCredentials: slices.Clone(grant.AncestorCredentials),
		Grants:              slices.Clone(grant.ChainRawGrants),
		TrustPaths:          slices.Clone(grant.TrustPaths),
	}
	if _, _, err := protocol.AssembleAccessEvidencePackage(
		&pkg,
		signer.SDJWTPresentation,
		signer.KeyID,
		signer.PrivateKey,
		protocol.ChallengeContext{
			ChallengeID: chal.ChallengeID,
			Nonce:       chal.Nonce,
			Audience:    chal.Audience,
			IssuedAt:    chal.IssuedAt,
			ExpiresAt:   chal.ExpiresAt,
		},
		w.cfg.Now().UTC().Unix(),
		false,
	); err != nil {
		return 0, nil, nil, chal.ChallengeID, fmt.Errorf("assemble AccessEvidencePackage: %w", err)
	}

	var (
		execResp *ExecuteResponse
		execCode int
		execErr  *GatewayError
	)
	send := func() error {
		var e error
		execResp, execCode, execErr, e = w.client.ExecuteAccess(ctx, pkg)
		return e
	}
	if actionID == "" {
		err = send()
	} else {
		err = w.store.DispatchClientAction(ctx, actionID, expectedSendRevision, send)
	}
	if err != nil {
		if protocol.HasCode(err, protocol.ErrCodeStateChanged) {
			return http.StatusConflict, nil, &GatewayError{
				StatusCode: http.StatusConflict,
				ErrorEnvelope: httpx.ErrorEnvelope{
					Code:    protocol.ErrCodeStateChanged,
					Message: err.Error(),
				},
			}, chal.ChallengeID, err
		}
		return 0, nil, nil, chal.ChallengeID, err
	}
	return execCode, execResp, execErr, chal.ChallengeID, nil
}

func (w *WalletContext) resolveSubjectLocked(subjectActor, subjectDID string) (string, *Signer, error) {
	var granteeSigner *Signer
	if subjectActor != "" {
		s, ok := w.signers[subjectActor]
		if !ok {
			return "", nil, fmt.Errorf("unknown subjectActor %q", subjectActor)
		}
		granteeSigner = s
		if subjectDID == "" {
			subjectDID = s.DID
		}
	} else if subjectDID != "" {
		for _, s := range w.signers {
			if s.DID == subjectDID {
				granteeSigner = s
				break
			}
		}
	}
	if subjectDID == "" {
		return "", nil, errors.New("subjectDid or subjectActor is required")
	}
	return subjectDID, granteeSigner, nil
}

type signedChildGrant struct {
	claims     protocol.GrantClaims
	rawJWS     string
	digest     string
	chain      []string
	ancestors  []protocol.AncestorCredential
	trustPaths []protocol.TrustPathEntry
	taskSpec   protocol.TaskSpec
}

func (w *WalletContext) signChildGrantLocked(
	issuer *Signer,
	parent *GrantBundle,
	granteeSigner *Signer,
	subjectDID, childID, taskID, mode string,
	maxAmountMinor int64,
	remainingDepth int,
	expiresInSeconds int64,
) (*signedChildGrant, error) {
	if int64(remainingDepth) >= parent.Claims.RemainingDepth {
		return nil, fmt.Errorf("remainingDepth %d must be strictly less than parent %s remainingDepth %d", remainingDepth, parent.Claims.ID, parent.Claims.RemainingDepth)
	}
	if maxAmountMinor > parent.Claims.MaxAmountMinor {
		return nil, fmt.Errorf("maxAmountMinor %d exceeds parent %s ceiling %d", maxAmountMinor, parent.Claims.ID, parent.Claims.MaxAmountMinor)
	}
	granteeKeyVersion := uint64(1)
	granteeCredentialID := "cred:" + subjectDID
	if granteeSigner != nil {
		granteeKeyVersion = granteeSigner.KeyVersion
		if granteeSigner.CredentialID != "" {
			granteeCredentialID = granteeSigner.CredentialID
		}
	}
	if taskID == "" {
		taskID = parent.Claims.TaskID
	}
	if taskID != parent.Claims.TaskID {
		return nil, fmt.Errorf("taskId %q does not match parent taskId %q", taskID, parent.Claims.TaskID)
	}
	if mode == "" {
		mode = parent.Claims.AuthorizationMode
	}
	if mode != parent.Claims.AuthorizationMode {
		return nil, fmt.Errorf("authorizationMode %q does not match parent mode %q", mode, parent.Claims.AuthorizationMode)
	}
	if childID == "" {
		childID = fmt.Sprintf("G-%s-%s", taskID, randomHex(4))
	}
	now := w.cfg.Now().UTC().Unix()
	nbf := parent.Claims.NBF
	if now > nbf {
		nbf = max(parent.Claims.NBF, now-5)
	}
	exp := parent.Claims.EXP
	if expiresInSeconds > 0 && now+expiresInSeconds < exp {
		exp = now + expiresInSeconds
	}
	if exp <= nbf {
		return nil, errors.New("child grant expiration window is empty")
	}

	parentIDCopy := parent.Claims.ID
	parentDigestCopy := parent.Digest
	issuerCredID := issuer.CredentialID
	if issuerCredID == "" {
		issuerCredID = "cred:" + issuer.DID
	}

	claims := protocol.GrantClaims{
		ID:                  childID,
		SchemaVersion:       parent.Claims.SchemaVersion,
		DeploymentID:        w.cfg.DeploymentID,
		ParentID:            &parentIDCopy,
		ParentDigest:        &parentDigestCopy,
		RootID:              parent.Claims.RootID,
		TaskID:              taskID,
		AuthorizationMode:   mode,
		PrincipalDomain:     parent.Claims.PrincipalDomain,
		ResourceID:          parent.Claims.ResourceID,
		Issuer:              issuer.DID,
		Grantee:             subjectDID,
		IssuerKeyVersion:    issuer.KeyVersion,
		GranteeKeyVersion:   granteeKeyVersion,
		IssuerCredentialID:  issuerCredID,
		GranteeCredentialID: granteeCredentialID,
		Resources:           slices.Clone(parent.Claims.Resources),
		Actions:             slices.Clone(parent.Claims.Actions),
		Suppliers:           slices.Clone(parent.Claims.Suppliers),
		Aud:                 parent.Claims.Aud,
		Currency:            parent.Claims.Currency,
		MaxAmountMinor:      maxAmountMinor,
		NBF:                 nbf,
		EXP:                 exp,
		RemainingDepth:      int64(remainingDepth),
	}
	rawJWS, digest, err := protocol.SignGrant(issuer.PrivateKey, issuer.KeyID, &claims)
	if err != nil {
		return nil, fmt.Errorf("sign child grant: %w", err)
	}
	return &signedChildGrant{
		claims:     claims,
		rawJWS:     rawJWS,
		digest:     digest,
		chain:      append(slices.Clone(parent.ChainRawGrants), rawJWS),
		ancestors:  append(slices.Clone(parent.AncestorCredentials), protocol.AncestorCredential{CredentialID: issuerCredID, Presentation: issuer.SDJWTPresentation}),
		trustPaths: slices.Clone(parent.TrustPaths),
		taskSpec:   parent.TaskSpec,
	}, nil
}

func cloneGrantBundle(g *GrantBundle) GrantBundle {
	cp := *g
	cp.ChainRawGrants = slices.Clone(g.ChainRawGrants)
	cp.AncestorCredentials = slices.Clone(g.AncestorCredentials)
	cp.TrustPaths = slices.Clone(g.TrustPaths)
	cp.TaskSpec.Resources = slices.Clone(g.TaskSpec.Resources)
	cp.TaskSpec.Actions = slices.Clone(g.TaskSpec.Actions)
	return cp
}
