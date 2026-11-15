package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"
)

// InspectWalletInput filters wallet metadata returned to an AI agent without exposing private keys or salts.
type InspectWalletInput struct {
	Actor             string `json:"actor" jsonschema:"Logical actor name such as A1 or B1 whose wallet grants and intent actions should be inspected."`
	TaskID            string `json:"taskId,omitempty" jsonschema:"Optional task ID filter."`
	AuthorizationMode string `json:"authorizationMode,omitempty" jsonschema:"Optional authorization mode filter (RESOURCE_PREAUTHORIZED or BUYER_MANDATE)."`
}

// InspectWalletOutput exposes safe actor identity metadata, active grants, quotes, and persisted client actions.
type InspectWalletOutput struct {
	DeploymentID  string               `json:"deploymentId"`
	Actor         string               `json:"actor"`
	DID           string               `json:"did,omitempty"`
	DomainID      string               `json:"domainId,omitempty"`
	Roles         []string             `json:"roles,omitempty"`
	Grants        []SanitizedGrantView `json:"grants"`
	Quotes        []QuoteSummary       `json:"quotes,omitempty"`
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

// NewMCPServer registers the six grad-auth-v1 agent wallet tools over official MCP Server SDK.
func NewMCPServer(w *WalletContext) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "grad-auth-wallet",
		Version: "v0.3.0",
	}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "inspect_wallet",
		Description: "Inspect actor DID, authorized grants, remaining delegation depth, amount ceilings, cached quotes, and client_actions intent locks without exposing private keys or SD-JWT disclosures.",
	}, w.handleInspectWallet)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "delegate_grant",
		Description: "Sign and optionally anchor a narrowed child delegation grant (such as A1 issuing G2 to B1) using isolated wallet key material.",
	}, w.handleDelegateGrant)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "replace_grant",
		Description: "Atomically revoke an existing child grant and issue/deliver a narrowed replacement grant to another delegate (such as B2) using isolated wallet key material.",
	}, w.handleReplaceGrant)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "request_quote",
		Description: "Obtain a binding supplier quote via gateway quote.read with fresh challenge authentication and KB-JWT proof.",
	}, w.handleRequestQuote)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_order",
		Description: "Persist a client_actions intent lock (OUTCOME_UNKNOWN + sendRevision) first, then submit an authenticated order.create request bound to a quoteId and idempotencyKey.",
	}, w.handleCreateOrder)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "reconcile_order",
		Description: "Increment sendRevision to stop delayed retries on an unknown order, register the reconciliation case with C, trigger C audit and historical h/r review, and persist the receipt.",
	}, w.handleReconcileOrder)

	return srv
}

func (w *WalletContext) handleInspectWallet(ctx context.Context, _ *mcp.CallToolRequest, in InspectWalletInput) (*mcp.CallToolResult, InspectWalletOutput, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	out := InspectWalletOutput{
		DeploymentID: w.cfg.DeploymentID,
		Actor:        in.Actor,
		Grants:       []SanitizedGrantView{},
	}
	var actorDID string
	if in.Actor != "" {
		signer, ok := w.signers[in.Actor]
		if !ok {
			return nil, InspectWalletOutput{}, fmt.Errorf("unknown actor %q in wallet", in.Actor)
		}
		actorDID = signer.did
		out.DID = signer.did
		out.DomainID = signer.domainID
		out.Roles = slices.Clone(signer.roles)
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
		if in.Actor != "" && q.Actor != in.Actor {
			continue
		}
		if in.TaskID != "" && q.TaskID != in.TaskID {
			continue
		}
		out.Quotes = append(out.Quotes, q)
	}
	actions := w.listClientActionsLocked(ctx, in.Actor, in.TaskID)
	out.ClientActions = actions
	return nil, out, nil
}

func (w *WalletContext) resolveSubjectLocked(subjectActor, subjectDID string) (string, *actorSigner, error) {
	var granteeSigner *actorSigner
	if subjectActor != "" {
		s, ok := w.signers[subjectActor]
		if !ok {
			return "", nil, fmt.Errorf("unknown subjectActor %q", subjectActor)
		}
		granteeSigner = s
		if subjectDID == "" {
			subjectDID = s.did
		}
	} else if subjectDID != "" {
		for _, s := range w.signers {
			if s.did == subjectDID {
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
	issuer *actorSigner,
	parent *GrantBundle,
	granteeSigner *actorSigner,
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
		granteeKeyVersion = granteeSigner.keyVersion
		if granteeSigner.credentialID != "" {
			granteeCredentialID = granteeSigner.credentialID
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
		nbf = now - 5
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
	issuerCredID := issuer.credentialID
	if issuerCredID == "" {
		issuerCredID = "cred:" + issuer.did
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
		Issuer:              issuer.did,
		Grantee:             subjectDID,
		IssuerKeyVersion:    issuer.keyVersion,
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
	rawJWS, digest, err := protocol.SignGrant(issuer.privateKey, issuer.keyID, &claims)
	if err != nil {
		return nil, fmt.Errorf("sign child grant: %w", err)
	}
	return &signedChildGrant{
		claims:     claims,
		rawJWS:     rawJWS,
		digest:     digest,
		chain:      append(slices.Clone(parent.ChainRawGrants), rawJWS),
		ancestors:  append(slices.Clone(parent.AncestorCredentials), protocol.AncestorCredential{CredentialID: issuerCredID, Presentation: issuer.sdJWTPresentation}),
		trustPaths: slices.Clone(parent.TrustPaths),
		taskSpec:   parent.TaskSpec,
	}, nil
}

func (w *WalletContext) handleDelegateGrant(ctx context.Context, _ *mcp.CallToolRequest, in DelegateGrantInput) (*mcp.CallToolResult, DelegateGrantOutput, error) {
	if in.IssuerActor == "" {
		return nil, DelegateGrantOutput{}, errors.New("issuerActor is required")
	}
	if in.ParentGrantID == "" {
		return nil, DelegateGrantOutput{}, errors.New("parentGrantId is required")
	}
	if in.MaxAmountMinor <= 0 {
		return nil, DelegateGrantOutput{}, errors.New("maxAmountMinor must be > 0")
	}
	if in.RemainingDepth < 0 {
		return nil, DelegateGrantOutput{}, errors.New("remainingDepth must be >= 0")
	}

	w.mu.Lock()
	issuer, ok := w.signers[in.IssuerActor]
	if !ok {
		w.mu.Unlock()
		return nil, DelegateGrantOutput{}, fmt.Errorf("unknown issuerActor %q", in.IssuerActor)
	}
	parent, err := w.findGrantLocked(issuer.did, in.ParentGrantID, in.TaskID, in.AuthorizationMode)
	if err != nil {
		w.mu.Unlock()
		return nil, DelegateGrantOutput{}, err
	}
	subjectDID, granteeSigner, err := w.resolveSubjectLocked(in.SubjectActor, in.SubjectDID)
	if err != nil {
		w.mu.Unlock()
		return nil, DelegateGrantOutput{}, err
	}
	signed, err := w.signChildGrantLocked(issuer, parent, granteeSigner, subjectDID, in.GrantID, in.TaskID, in.AuthorizationMode, in.MaxAmountMinor, in.RemainingDepth, in.ExpiresInSeconds)
	if err != nil {
		w.mu.Unlock()
		return nil, DelegateGrantOutput{}, errors.New(w.SanitizeString(err.Error()))
	}
	anchorHook := w.cfg.AnchorChildFunc
	w.mu.Unlock()

	anchored := false
	note := "signed locally with isolated actor key"
	if anchorHook != nil {
		res, err := anchorHook(ctx, AnchorChildGrantRequest{
			Claims:      signed.claims,
			RawGrantJWS: signed.rawJWS,
			GrantDigest: signed.digest,
			ParentID:    parent.Claims.ID,
			IssuerActor: in.IssuerActor,
			GranteeDID:  subjectDID,
		})
		if err != nil {
			return nil, DelegateGrantOutput{}, fmt.Errorf("anchor child grant: %s", w.SanitizeString(err.Error()))
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
			note = "signed and anchored onto Fabric registry"
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
		return nil, DelegateGrantOutput{}, err
	}
	return nil, DelegateGrantOutput{
		Grant:    childBundle.view(),
		Anchored: anchored,
		Note:     note,
	}, nil
}

func (w *WalletContext) handleReplaceGrant(ctx context.Context, _ *mcp.CallToolRequest, in ReplaceGrantInput) (*mcp.CallToolResult, ReplaceGrantOutput, error) {
	if in.IssuerActor == "" || in.OldGrantID == "" {
		return nil, ReplaceGrantOutput{}, errors.New("issuerActor and oldGrantId are required")
	}
	if in.RemainingDepth < 0 {
		return nil, ReplaceGrantOutput{}, errors.New("remainingDepth must be >= 0")
	}

	w.mu.Lock()
	issuer, ok := w.signers[in.IssuerActor]
	if !ok {
		w.mu.Unlock()
		return nil, ReplaceGrantOutput{}, fmt.Errorf("unknown issuerActor %q", in.IssuerActor)
	}
	oldBundle, err := w.findGrantLocked("", in.OldGrantID, "", "")
	if err != nil {
		w.mu.Unlock()
		return nil, ReplaceGrantOutput{}, err
	}
	if oldBundle.Claims.Issuer != issuer.did {
		w.mu.Unlock()
		return nil, ReplaceGrantOutput{}, fmt.Errorf("old grant %q was issued by %q, not %q", in.OldGrantID, oldBundle.Claims.Issuer, issuer.did)
	}
	if oldBundle.Replaced {
		w.mu.Unlock()
		return nil, ReplaceGrantOutput{}, fmt.Errorf("old grant %q already replaced", in.OldGrantID)
	}
	if oldBundle.Claims.ParentID == nil || *oldBundle.Claims.ParentID == "" {
		w.mu.Unlock()
		return nil, ReplaceGrantOutput{}, fmt.Errorf("old grant %q missing parentId", in.OldGrantID)
	}
	parent, err := w.findGrantLocked(issuer.did, *oldBundle.Claims.ParentID, oldBundle.Claims.TaskID, oldBundle.Claims.AuthorizationMode)
	if err != nil {
		w.mu.Unlock()
		return nil, ReplaceGrantOutput{}, fmt.Errorf("parent grant %q for replacement not held by %s: %w", *oldBundle.Claims.ParentID, in.IssuerActor, err)
	}
	subjectDID, granteeSigner, err := w.resolveSubjectLocked(in.NewSubjectActor, in.NewSubjectDID)
	if err != nil {
		w.mu.Unlock()
		return nil, ReplaceGrantOutput{}, err
	}
	maxAmt := in.MaxAmountMinor
	if maxAmt <= 0 {
		maxAmt = oldBundle.Claims.MaxAmountMinor
		if parent.Claims.MaxAmountMinor < maxAmt {
			maxAmt = parent.Claims.MaxAmountMinor
		}
	}
	oldRev := oldBundle.Revision
	if oldRev == 0 {
		oldRev = 1
	}
	oldDigest := oldBundle.Digest
	signed, err := w.signChildGrantLocked(issuer, parent, granteeSigner, subjectDID, in.NewGrantID, oldBundle.Claims.TaskID, oldBundle.Claims.AuthorizationMode, maxAmt, in.RemainingDepth, in.ExpiresInSeconds)
	if err != nil {
		w.mu.Unlock()
		return nil, ReplaceGrantOutput{}, errors.New(w.SanitizeString(err.Error()))
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
			return nil, ReplaceGrantOutput{}, fmt.Errorf("replace grant on ledger: %s", w.SanitizeString(err.Error()))
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
			note = "atomically revoked old grant and delivered replacement onto Fabric registry"
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
		return nil, ReplaceGrantOutput{}, err
	}
	return nil, ReplaceGrantOutput{
		RevokedGrantID:   in.OldGrantID,
		ReplacementGrant: newBundle.view(),
		Anchored:         anchored,
		Note:             note,
	}, nil
}

func (w *WalletContext) handleRequestQuote(ctx context.Context, _ *mcp.CallToolRequest, in RequestQuoteInput) (*mcp.CallToolResult, RequestQuoteOutput, error) {
	if in.Actor == "" || in.TaskID == "" || in.ProductID == "" || in.Quantity <= 0 {
		return nil, RequestQuoteOutput{}, errors.New("actor, taskId, productId, and quantity > 0 are required")
	}
	idem := in.IdempotencyKey
	if idem == "" {
		idem = "quote-" + randomHex(6)
	}

	w.mu.Lock()
	signer, ok := w.signers[in.Actor]
	if !ok {
		w.mu.Unlock()
		return nil, RequestQuoteOutput{}, fmt.Errorf("unknown actor %q in wallet", in.Actor)
	}
	grant, err := w.findGrantLocked(signer.did, in.GrantID, in.TaskID, in.AuthorizationMode)
	if err != nil {
		w.mu.Unlock()
		return nil, RequestQuoteOutput{}, err
	}
	req := protocol.AccessRequest{
		SchemaVersion:     protocol.SchemaVersion,
		DeploymentID:      w.cfg.DeploymentID,
		Actor:             signer.did,
		PrincipalDomain:   grant.Claims.PrincipalDomain,
		AuthorizationMode: grant.Claims.AuthorizationMode,
		TaskID:            in.TaskID,
		Audience:          w.cfg.Audience,
		Resource:          "urn:grad:resource:C:quotes",
		Action:            "quote.read",
		SupplierID:        w.cfg.SupplierID,
		QuoteID:           nil,
		ProductID:         in.ProductID,
		Quantity:          in.Quantity,
		Currency:          grant.Claims.Currency,
		AmountMinor:       0,
		IdempotencyKey:    idem,
	}
	if req.Currency == "" {
		req.Currency = w.cfg.Currency
	}
	grantCopy := *grant
	signerCopy := *signer
	w.mu.Unlock()

	code, execResp, errResp, err := w.submitAccessExecute(ctx, &signerCopy, &grantCopy, req)
	if err != nil {
		return nil, RequestQuoteOutput{}, errors.New(w.SanitizeString(err.Error()))
	}
	out := RequestQuoteOutput{
		StatusCode: code,
		TaskID:     in.TaskID,
		ProductID:  in.ProductID,
		Quantity:   in.Quantity,
		Currency:   req.Currency,
	}
	if code == http.StatusOK && execResp != nil {
		out.Decision = "ALLOW"
		out.DecisionID = execResp.DecisionID
		if execResp.Quote != nil {
			out.QuoteID = execResp.Quote.QuoteID
			out.UnitPriceMinor = execResp.Quote.UnitPriceMinor
			out.TotalAmountMinor = execResp.Quote.TotalAmountMinor
			out.Currency = execResp.Quote.Currency
			out.ValidUntil = execResp.Quote.ValidUntil
			w.mu.Lock()
			w.quotes[execResp.Quote.QuoteID] = QuoteSummary{
				QuoteID:          execResp.Quote.QuoteID,
				TaskID:           execResp.Quote.TaskID,
				Actor:            in.Actor,
				SupplierID:       execResp.Quote.SupplierID,
				ProductID:        execResp.Quote.ProductID,
				Quantity:         execResp.Quote.Quantity,
				Currency:         execResp.Quote.Currency,
				UnitPriceMinor:   execResp.Quote.UnitPriceMinor,
				TotalAmountMinor: execResp.Quote.TotalAmountMinor,
				ValidUntil:       execResp.Quote.ValidUntil,
			}
			w.mu.Unlock()
		}
		return nil, out, nil
	}
	out.Decision = "DENY"
	if errResp != nil {
		if errResp.DecisionID != nil {
			out.DecisionID = *errResp.DecisionID
		}
		out.ErrorCode = errResp.Code
		out.ErrorMessage = w.SanitizeString(errResp.Message)
	}
	return nil, out, nil
}

func (w *WalletContext) handleCreateOrder(ctx context.Context, _ *mcp.CallToolRequest, in CreateOrderInput) (*mcp.CallToolResult, CreateOrderOutput, error) {
	if in.Actor == "" || in.TaskID == "" || in.QuoteID == "" || in.IdempotencyKey == "" || in.AmountMinor <= 0 {
		return nil, CreateOrderOutput{}, errors.New("actor, taskId, quoteId, idempotencyKey, and amountMinor > 0 are required")
	}

	w.mu.Lock()
	signer, ok := w.signers[in.Actor]
	if !ok {
		w.mu.Unlock()
		return nil, CreateOrderOutput{}, fmt.Errorf("unknown actor %q in wallet", in.Actor)
	}
	grant, err := w.findGrantLocked(signer.did, in.GrantID, in.TaskID, in.AuthorizationMode)
	if err != nil {
		w.mu.Unlock()
		return nil, CreateOrderOutput{}, err
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
		Actor:             signer.did,
		PrincipalDomain:   grant.Claims.PrincipalDomain,
		AuthorizationMode: grant.Claims.AuthorizationMode,
		TaskID:            in.TaskID,
		Audience:          w.cfg.Audience,
		Resource:          "urn:grad:resource:C:orders",
		Action:            "order.create",
		SupplierID:        w.cfg.SupplierID,
		QuoteID:           &quoteID,
		ProductID:         productID,
		Quantity:          quantity,
		Currency:          currency,
		AmountMinor:       in.AmountMinor,
		IdempotencyKey:    in.IdempotencyKey,
	}
	grantCopy := *grant
	signerCopy := *signer
	w.mu.Unlock()

	reqHash, err := req.Hash(false)
	if err != nil {
		return nil, CreateOrderOutput{}, err
	}
	reqBytes, _ := json.Marshal(req)

	// Persist durable client_actions intent lock BEFORE dispatching order.create to gateway.
	actionRec, err := w.beginClientAction(ctx, signerCopy.did, in.TaskID, "order.create", in.IdempotencyKey, reqHash, req)
	if err != nil {
		return nil, CreateOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
	}
	if actionRec.Status == "COMPLETED" || (actionRec.Status == "RECONCILED" && actionRec.Outcome == "CREATED") {
		return nil, CreateOrderOutput{
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

	if actionRec.CaseID != "" || actionRec.Status == "RECONCILED" {
		return nil, CreateOrderOutput{Decision: "UNKNOWN", StatusCode: http.StatusConflict, ActionID: actionRec.ActionID, ActionStatus: actionRec.Status, SendRevision: actionRec.SendRevision, ErrorCode: protocol.ErrCodeStateChanged, ErrorMessage: "intent is stopped for reconciliation"}, nil
	}
	code, execResp, errResp, callErr := w.submitAccessExecuteWithReqHash(ctx, &signerCopy, &grantCopy, req, reqHash, actionRec.ActionID, actionRec.SendRevision, string(reqBytes))
	if callErr != nil || code >= http.StatusInternalServerError {
		// Preserve OUTCOME_UNKNOWN so reconcile_order can stop retries and query C audit DB.
		errCode := "OUTCOME_UNKNOWN"
		errMsg := ""
		if callErr != nil {
			errMsg = w.SanitizeString(callErr.Error())
		}
		if errResp != nil {
			if errResp.Code != "" {
				errCode = errResp.Code
			}
			if errResp.Message != "" {
				errMsg = w.SanitizeString(errResp.Message)
			}
		}
		return nil, CreateOrderOutput{
			Decision:     "UNKNOWN",
			StatusCode:   code,
			ActionID:     actionRec.ActionID,
			ActionStatus: "OUTCOME_UNKNOWN",
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
	w.mu.Lock()
	var chalIDLookup string
	if rec, ok := w.actions[actionRec.ActionID]; ok {
		chalIDLookup = rec.ChallengeID
	}
	w.mu.Unlock()
	if code == http.StatusOK && execResp != nil && execResp.Order != nil {
		out.Decision = "ALLOW"
		out.ActionStatus = "COMPLETED"
		out.DecisionID = execResp.DecisionID
		out.OrderID = execResp.Order.OrderID
		out.ProductID = execResp.Order.ProductID
		out.Quantity = execResp.Order.Quantity
		out.TotalAmountMinor = execResp.Order.TotalAmountMinor
		out.Currency = execResp.Order.Currency
		if err := w.updateClientAction(ctx, actionRec.ActionID, "COMPLETED", chalIDLookup, in.QuoteID, execResp.Order.OrderID, execResp.DecisionID); err != nil {
			return nil, CreateOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
		}
		return nil, out, nil
	}

	out.Decision = "DENY"
	out.ActionStatus = "FAILED"
	if errResp != nil {
		if errResp.DecisionID != nil {
			out.DecisionID = *errResp.DecisionID
		}
		out.ErrorCode = errResp.Code
		out.ErrorMessage = w.SanitizeString(errResp.Message)
	}
	if err := w.updateClientAction(ctx, actionRec.ActionID, "FAILED", chalIDLookup, in.QuoteID, "", out.DecisionID); err != nil {
		return nil, CreateOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
	}
	return nil, out, nil
}

func (w *WalletContext) handleReconcileOrder(ctx context.Context, _ *mcp.CallToolRequest, in ReconcileOrderInput) (*mcp.CallToolResult, ReconcileOrderOutput, error) {
	if in.Actor == "" || in.TaskID == "" || in.IdempotencyKey == "" {
		return nil, ReconcileOrderOutput{}, errors.New("actor, taskId, and idempotencyKey are required")
	}
	action := in.Action
	if action == "" {
		action = "order.create"
	}

	w.mu.Lock()
	signer, ok := w.signers[in.Actor]
	if !ok {
		w.mu.Unlock()
		return nil, ReconcileOrderOutput{}, fmt.Errorf("unknown actor %q in wallet", in.Actor)
	}
	actorDID := signer.did
	w.mu.Unlock()

	stopped, reqObj, err := w.stopClientActionSend(ctx, actorDID, in.TaskID, action, in.IdempotencyKey, in.CaseID)
	if err != nil {
		return nil, ReconcileOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
	}
	if stopped.Status == "RECONCILED" || stopped.Status == "COMPLETED" {
		outcome := stopped.Outcome
		if outcome == "" && stopped.OrderID != "" {
			outcome = "CREATED"
		}
		return nil, ReconcileOrderOutput{
			CaseID:             stopped.CaseID,
			SendRevision:       stopped.SendRevision,
			Outcome:            outcome,
			OrderID:            stopped.OrderID,
			CreationDecisionID: stopped.DecisionID,
			ActionStatus:       stopped.Status,
			ChallengeIDs:       slices.Clone(stopped.ChallengeIDs),
		}, nil
	}

	reqHash, err := reqObj.Hash(false)
	if err != nil {
		return nil, ReconcileOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
	}

	caseReq := gateway.OrderOutcomeCaseRequest{
		CaseID:       stopped.CaseID,
		SendRevision: stopped.SendRevision,
		DeploymentID: w.cfg.DeploymentID,
		Request:      reqObj,
		RequestHash:  reqHash,
		ChallengeIDs: stopped.ChallengeIDs,
	}
	caseCode, caseRaw, err := w.doServiceJSON(ctx, w.cfg.RecoveryClient, "/v1/internal/order-outcome-cases", caseReq)
	if err != nil {
		return nil, ReconcileOrderOutput{
			CaseID:       stopped.CaseID,
			SendRevision: stopped.SendRevision,
			Outcome:      "UNKNOWN",
			ActionStatus: "OUTCOME_UNKNOWN",
			ChallengeIDs: stopped.ChallengeIDs,
			ErrorCode:    "STATE_UNAVAILABLE",
			ErrorMessage: w.SanitizeString(err.Error()),
		}, nil
	}
	if caseCode != http.StatusAccepted {
		eb := parseErrorResponse(caseRaw)
		return nil, ReconcileOrderOutput{
			CaseID:       stopped.CaseID,
			SendRevision: stopped.SendRevision,
			Outcome:      "UNKNOWN",
			ActionStatus: "OUTCOME_UNKNOWN",
			ChallengeIDs: stopped.ChallengeIDs,
			ErrorCode:    eb.Code,
			ErrorMessage: w.SanitizeString(eb.Message),
		}, nil
	}

	auditReq := gateway.AuditOrderOutcomeRequest{
		CaseID:       stopped.CaseID,
		DeploymentID: w.cfg.DeploymentID,
		Request:      &reqObj,
		RequestHash:  reqHash,
		ChallengeIDs: stopped.ChallengeIDs,
	}
	auditCode, auditRaw, err := w.doServiceJSON(ctx, w.cfg.AuditClient, "/v1/audit/order-outcomes", auditReq)
	if err != nil {
		return nil, ReconcileOrderOutput{
			CaseID:       stopped.CaseID,
			SendRevision: stopped.SendRevision,
			Outcome:      "UNKNOWN",
			ActionStatus: "OUTCOME_UNKNOWN",
			ChallengeIDs: stopped.ChallengeIDs,
			ErrorCode:    "STATE_UNAVAILABLE",
			ErrorMessage: w.SanitizeString(err.Error()),
		}, nil
	}
	if auditCode != http.StatusOK {
		eb := parseErrorResponse(auditRaw)
		return nil, ReconcileOrderOutput{
			CaseID:       stopped.CaseID,
			SendRevision: stopped.SendRevision,
			Outcome:      "UNKNOWN",
			ActionStatus: "OUTCOME_UNKNOWN",
			ChallengeIDs: stopped.ChallengeIDs,
			ErrorCode:    eb.Code,
			ErrorMessage: w.SanitizeString(eb.Message),
		}, nil
	}

	var auditResp gateway.AuditOrderOutcomeResponse
	if err := json.Unmarshal(auditRaw, &auditResp); err != nil {
		return nil, ReconcileOrderOutput{}, fmt.Errorf("decode audit response: %w", err)
	}

	var recCode int
	var recRaw []byte
	if w.cfg.ReceiptDelivery != nil {
		var response *gateway.OrderOutcomeReceiptResponse
		response, err = w.cfg.ReceiptDelivery(ctx, auditResp.Receipt)
		if err == nil {
			recCode = http.StatusOK
			recRaw, _ = json.Marshal(response)
		}
	} else {
		recCode, recRaw, err = w.doServiceJSON(ctx, w.cfg.ReceiptClient, "/v1/internal/order-outcome-receipts", auditResp.Receipt)
	}
	if err != nil || recCode != http.StatusOK {
		errMsg := ""
		errCode := "RECEIPT_DELIVERY_FAILED"
		if err != nil {
			errMsg = w.SanitizeString(err.Error())
		} else {
			eb := parseErrorResponse(recRaw)
			errCode = eb.Code
			errMsg = w.SanitizeString(eb.Message)
		}
		return nil, ReconcileOrderOutput{
			CaseID:       stopped.CaseID,
			SendRevision: stopped.SendRevision,
			Outcome:      "UNKNOWN",
			ActionStatus: "OUTCOME_UNKNOWN",
			ChallengeIDs: stopped.ChallengeIDs,
			ErrorCode:    errCode,
			ErrorMessage: errMsg,
		}, nil
	}
	var recResp gateway.OrderOutcomeReceiptResponse
	_ = json.Unmarshal(recRaw, &recResp)

	finalActionStatus := recResp.ClientActionStatus
	if finalActionStatus == "" {
		if auditResp.Outcome == "CREATED" || auditResp.Outcome == "NOT_CREATED" {
			finalActionStatus = "RECONCILED"
		} else {
			finalActionStatus = "OUTCOME_UNKNOWN"
		}
	}
	var ordID, decID string
	if auditResp.OrderID != nil {
		ordID = *auditResp.OrderID
	}
	if auditResp.CreationDecisionID != nil {
		decID = *auditResp.CreationDecisionID
	}

	w.mu.Lock()
	if act, ok := w.actions[stopped.ActionID]; ok {
		act.Status = finalActionStatus
		act.Outcome = auditResp.Outcome
		act.CaseID = auditResp.CaseID
		act.SendRevision = auditResp.SendRevision
		if ordID != "" {
			act.OrderID = ordID
		}
		if decID != "" {
			act.DecisionID = decID
		}
	}
	w.mu.Unlock()

	return nil, ReconcileOrderOutput{
		CaseID:             auditResp.CaseID,
		SendRevision:       auditResp.SendRevision,
		Outcome:            auditResp.Outcome,
		HistoricalStatus:   auditResp.HistoricalStatus,
		HistoricalReason:   auditResp.HistoricalReason,
		OrderID:            ordID,
		CreationDecisionID: decID,
		ActionStatus:       finalActionStatus,
		CheckNo:            auditResp.CheckNo,
		ChallengeIDs:       slices.Clone(auditResp.LockedChallengeIDs),
	}, nil
}

func (w *WalletContext) submitAccessExecute(
	ctx context.Context,
	signer *actorSigner,
	grant *GrantBundle,
	req protocol.AccessRequest,
) (int, *gateway.ExecuteResponse, *gateway.ErrorBody, error) {
	reqHash, err := req.Hash(false)
	if err != nil {
		return 0, nil, nil, err
	}
	return w.submitAccessExecuteWithReqHash(ctx, signer, grant, req, reqHash, "", 0, "")
}

func (w *WalletContext) submitAccessExecuteWithReqHash(
	ctx context.Context,
	signer *actorSigner,
	grant *GrantBundle,
	req protocol.AccessRequest,
	reqHash string,
	actionID string,
	expectedSendRevision int64,
	requestJSON string,
) (int, *gateway.ExecuteResponse, *gateway.ErrorBody, error) {
	chalReq := gateway.ChallengeRequest{
		Actor:       req.Actor,
		TaskID:      req.TaskID,
		RequestHash: reqHash,
	}
	chalCode, chalRaw, err := w.doJSON(ctx, http.MethodPost, "/v1/auth/challenges", chalReq)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("request challenge: %w", err)
	}
	if chalCode != http.StatusCreated {
		return chalCode, nil, parseErrorResponse(chalRaw), nil
	}
	var chal gateway.ChallengeResponse
	if err := json.Unmarshal(chalRaw, &chal); err != nil {
		return 0, nil, nil, fmt.Errorf("decode challenge: %w", err)
	}
	if actionID != "" {
		if err := w.recordClientActionChallenge(ctx, actionID, expectedSendRevision, chal.ChallengeID, requestJSON); err != nil {
			return http.StatusConflict, nil, &gateway.ErrorBody{Code: protocol.ErrCodeStateChanged, Message: err.Error()}, nil
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
		signer.sdJWTPresentation,
		signer.keyID,
		signer.privateKey,
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
		return 0, nil, nil, fmt.Errorf("assemble AccessEvidencePackage: %w", err)
	}

	var execCode int
	var execRaw []byte
	send := func() error {
		var e error
		execCode, execRaw, e = w.doJSON(ctx, http.MethodPost, "/v1/access/execute", pkg)
		return e
	}
	if actionID == "" {
		err = send()
	} else if w.cfg.DB != nil {
		err = gateway.DispatchClientAction(ctx, w.cfg.DB, w.cfg.DeploymentID, actionID, expectedSendRevision, send)
	} else {
		w.sendMu.Lock()
		w.mu.Lock()
		rec := w.actions[actionID]
		allowed := rec != nil && rec.CaseID == "" && rec.SendRevision == expectedSendRevision && (rec.Status == "PENDING" || rec.Status == "OUTCOME_UNKNOWN" || rec.Status == "FAILED")
		w.mu.Unlock()
		if allowed {
			err = send()
		} else {
			err = protocol.NewError(protocol.ErrCodeStateChanged, "intent stopped before dispatch")
		}
		w.sendMu.Unlock()
	}
	if protocol.HasCode(err, protocol.ErrCodeStateChanged) {
		return http.StatusConflict, nil, &gateway.ErrorBody{Code: protocol.ErrCodeStateChanged, Message: err.Error()}, nil
	}
	if err != nil {
		return 0, nil, nil, fmt.Errorf("call /v1/access/execute: %w", err)
	}
	if execCode == http.StatusOK {
		var okResp gateway.ExecuteResponse
		if err := json.Unmarshal(execRaw, &okResp); err != nil {
			return 0, nil, nil, fmt.Errorf("decode ExecuteResponse: %w", err)
		}
		return execCode, &okResp, nil, nil
	}
	return execCode, nil, parseErrorResponse(execRaw), nil
}

// doServiceJSON uses a host-provisioned channel; tools cannot choose its identity.
func (w *WalletContext) doServiceJSON(ctx context.Context, client *http.Client, path string, payload any) (int, []byte, error) {
	if client == nil {
		return 0, nil, errors.New("authenticated service client is not configured")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	base := w.cfg.GatewayURL
	if base == "" {
		base = "https://c.local"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

func (w *WalletContext) doJSON(ctx context.Context, method, path string, payload any) (int, []byte, error) {
	return w.doJSONWithHeaders(ctx, method, path, nil, payload)
}

func (w *WalletContext) doJSONWithHeaders(ctx context.Context, method, path string, headers map[string]string, payload any) (int, []byte, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	if w.cfg.HTTPHandler != nil {
		req := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		w.cfg.HTTPHandler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes(), nil
	}
	if w.cfg.GatewayURL == "" {
		return 0, nil, errors.New("gatewayURL or httpHandler is required")
	}
	target := strings.TrimRight(w.cfg.GatewayURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := w.cfg.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, respBytes, nil
}

func parseErrorResponse(raw []byte) *gateway.ErrorBody {
	var out gateway.ErrorBody
	if err := json.Unmarshal(raw, &out); err != nil {
		return &gateway.ErrorBody{
			Code:    "HTTP_ERROR",
			Message: strings.TrimSpace(string(raw)),
		}
	}
	return &out
}

func didHost(did string) string {
	if !strings.HasPrefix(did, "did:web:") {
		return ""
	}
	rest := strings.TrimPrefix(did, "did:web:")
	host, _, _ := strings.Cut(rest, ":")
	return strings.Split(host, "%3A")[0]
}

func actionViewFromGateway(rec *gateway.ClientActionRecord) ClientActionView {
	return ClientActionView{
		ActionID:       rec.ActionID,
		Actor:          rec.Actor,
		TaskID:         rec.TaskID,
		Action:         rec.Action,
		IdempotencyKey: rec.IdempotencyKey,
		Status:         rec.Status,
		SendRevision:   rec.SendRevision,
		ChallengeID:    rec.ChallengeID,
		ChallengeIDs:   slices.Clone(rec.ChallengeIDs),
		QuoteID:        rec.QuoteID,
		OrderID:        rec.OrderID,
		DecisionID:     rec.DecisionID,
		CaseID:         rec.CaseID,
		Outcome:        rec.Outcome,
	}
}

func (w *WalletContext) beginClientAction(ctx context.Context, actor, taskID, action, idempotencyKey, reqHash string, reqObj protocol.AccessRequest) (*ClientActionView, error) {
	nowSec := w.cfg.Now().UTC().Unix()
	if w.cfg.DB != nil {
		rec, err := gateway.BeginClientAction(ctx, w.cfg.DB, w.cfg.DeploymentID, actor, taskID, action, idempotencyKey, reqHash, nowSec)
		if err != nil {
			return nil, err
		}
		view := actionViewFromGateway(rec)
		w.mu.Lock()
		cp := view
		w.actions[view.ActionID] = &cp
		w.actionRequests[view.ActionID] = reqObj
		w.mu.Unlock()
		return &view, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	key := actionMapKey(actor, taskID, action, idempotencyKey)
	for _, existing := range w.actions {
		if actionMapKey(existing.Actor, existing.TaskID, existing.Action, existing.IdempotencyKey) == key {
			cp := *existing
			cp.ChallengeIDs = slices.Clone(existing.ChallengeIDs)
			return &cp, nil
		}
	}
	w.actionSeq++
	view := &ClientActionView{
		ActionID:       fmt.Sprintf("act-local-%04d", w.actionSeq),
		Actor:          actor,
		TaskID:         taskID,
		Action:         action,
		IdempotencyKey: idempotencyKey,
		Status:         "PENDING",
		SendRevision:   1,
	}
	w.actions[view.ActionID] = view
	w.actionRequests[view.ActionID] = reqObj
	cp := *view
	return &cp, nil
}

func (w *WalletContext) recordClientActionChallenge(ctx context.Context, actionID string, expectedSendRevision int64, challengeID, reqJSON string) error {
	nowSec := w.cfg.Now().UTC().Unix()
	if w.cfg.DB != nil {
		rec, err := gateway.RecordClientActionChallenge(ctx, w.cfg.DB, w.cfg.DeploymentID, actionID, expectedSendRevision, challengeID, reqJSON, nowSec)
		if err != nil {
			return err
		}
		view := actionViewFromGateway(rec)
		w.mu.Lock()
		cp := view
		w.actions[actionID] = &cp
		w.mu.Unlock()
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	rec, ok := w.actions[actionID]
	if !ok {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "unknown local client action")
	}
	if rec.CaseID != "" || rec.SendRevision != expectedSendRevision || (rec.Status != "PENDING" && rec.Status != "OUTCOME_UNKNOWN" && rec.Status != "FAILED") {
		return protocol.NewError(protocol.ErrCodeStateChanged, "client action send_revision mismatch or finalized")
	}
	rec.Status = "OUTCOME_UNKNOWN"
	rec.ChallengeID = challengeID
	if challengeID != "" && !slices.Contains(rec.ChallengeIDs, challengeID) {
		rec.ChallengeIDs = append(rec.ChallengeIDs, challengeID)
	}
	return nil
}

func (w *WalletContext) stopClientActionSend(ctx context.Context, actorDID, taskID, action, idempotencyKey, caseID string) (ClientActionView, protocol.AccessRequest, error) {
	w.sendMu.Lock()
	defer w.sendMu.Unlock()
	nowSec := w.cfg.Now().UTC().Unix()
	if w.cfg.DB != nil {
		existing, err := gateway.GetClientActionByKey(ctx, w.cfg.DB, w.cfg.DeploymentID, actorDID, taskID, action, idempotencyKey)
		if err != nil {
			return ClientActionView{}, protocol.AccessRequest{}, err
		}
		if existing.Status == "RECONCILED" || existing.Status == "COMPLETED" {
			var reqObj protocol.AccessRequest
			_ = json.Unmarshal([]byte(existing.RequestJSON), &reqObj)
			return actionViewFromGateway(existing), reqObj, nil
		}
		var fallbackJSON string
		w.mu.Lock()
		if cachedReq, ok := w.actionRequests[existing.ActionID]; ok {
			b, _ := json.Marshal(cachedReq)
			fallbackJSON = string(b)
		}
		w.mu.Unlock()
		stopped, err := gateway.StopClientActionSend(ctx, w.cfg.DB, w.cfg.DeploymentID, actorDID, taskID, action, idempotencyKey, caseID, fallbackJSON, nowSec)
		if err != nil {
			return ClientActionView{}, protocol.AccessRequest{}, err
		}
		var reqObj protocol.AccessRequest
		rawJSON := stopped.RequestJSON
		if rawJSON == "" {
			rawJSON = fallbackJSON
		}
		if rawJSON != "" {
			if err := json.Unmarshal([]byte(rawJSON), &reqObj); err != nil {
				return ClientActionView{}, protocol.AccessRequest{}, fmt.Errorf("decode stored request_json: %w", err)
			}
		} else {
			w.mu.Lock()
			cachedReq, ok := w.actionRequests[stopped.ActionID]
			w.mu.Unlock()
			if !ok {
				return ClientActionView{}, protocol.AccessRequest{}, errors.New("stored request payload unavailable for reconciliation")
			}
			reqObj = cachedReq
		}
		view := actionViewFromGateway(stopped)
		w.mu.Lock()
		cp := view
		w.actions[view.ActionID] = &cp
		w.actionRequests[view.ActionID] = reqObj
		w.mu.Unlock()
		return view, reqObj, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	key := actionMapKey(actorDID, taskID, action, idempotencyKey)
	for _, rec := range w.actions {
		if actionMapKey(rec.Actor, rec.TaskID, rec.Action, rec.IdempotencyKey) == key {
			if rec.Status == "RECONCILED" || rec.Status == "COMPLETED" {
				return *rec, w.actionRequests[rec.ActionID], nil
			}
			rec.Status = "OUTCOME_UNKNOWN"
			if rec.CaseID == "" {
				rec.SendRevision++
				if caseID != "" {
					rec.CaseID = caseID
				} else {
					rec.CaseID = "urn:grad:case:" + randomHex(8)
				}
			}
			return *rec, w.actionRequests[rec.ActionID], nil
		}
	}
	return ClientActionView{}, protocol.AccessRequest{}, errors.New("client action not found")
}

func (w *WalletContext) updateClientAction(ctx context.Context, actionID, status, challengeID, quoteID, orderID, decisionID string) error {
	nowSec := w.cfg.Now().UTC().Unix()
	w.mu.Lock()
	if rec, ok := w.actions[actionID]; ok {
		rec.Status = status
		if challengeID != "" {
			rec.ChallengeID = challengeID
			if !slices.Contains(rec.ChallengeIDs, challengeID) {
				rec.ChallengeIDs = append(rec.ChallengeIDs, challengeID)
			}
		}
		if quoteID != "" {
			rec.QuoteID = quoteID
		}
		if orderID != "" {
			rec.OrderID = orderID
		}
		if decisionID != "" {
			rec.DecisionID = decisionID
		}
	}
	w.mu.Unlock()

	if w.cfg.DB != nil {
		return gateway.UpdateClientAction(ctx, w.cfg.DB, w.cfg.DeploymentID, actionID, status, challengeID, quoteID, orderID, decisionID, nowSec)
	}
	return nil
}

func (w *WalletContext) listClientActionsLocked(ctx context.Context, actor, taskID string) []ClientActionView {
	if w.cfg.DB != nil && actor != "" && taskID != "" {
		rows, err := w.cfg.DB.Query(ctx, `
			SELECT action_id, actor, task_id, action, idempotency_key, status, send_revision,
			       COALESCE(challenge_id,''), challenge_ids, COALESCE(quote_id,''), COALESCE(order_id,''),
			       COALESCE(decision_id,''), COALESCE(case_id,''), COALESCE(outcome,'')
			FROM client_actions
			WHERE deployment_id = $1 AND actor = $2 AND task_id = $3
			ORDER BY updated_at ASC, action_id ASC`,
			w.cfg.DeploymentID, actor, taskID,
		)
		if err == nil {
			defer rows.Close()
			var res []ClientActionView
			for rows.Next() {
				var item ClientActionView
				if scanErr := rows.Scan(
					&item.ActionID, &item.Actor, &item.TaskID, &item.Action, &item.IdempotencyKey, &item.Status, &item.SendRevision,
					&item.ChallengeID, &item.ChallengeIDs, &item.QuoteID, &item.OrderID,
					&item.DecisionID, &item.CaseID, &item.Outcome,
				); scanErr == nil {
					res = append(res, item)
				}
			}
			if len(res) > 0 {
				return res
			}
		}
	}
	var out []ClientActionView
	for _, rec := range w.actions {
		if actor != "" && rec.Actor != actor {
			continue
		}
		if taskID != "" && rec.TaskID != taskID {
			continue
		}
		out = append(out, *rec)
	}
	slices.SortFunc(out, func(a, b ClientActionView) int {
		return strings.Compare(a.ActionID, b.ActionID)
	})
	return out
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
