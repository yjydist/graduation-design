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

// NewMCPServer registers the four grad-auth-v1 agent wallet tools over official MCP Server SDK.
func NewMCPServer(w *WalletContext) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "grad-auth-wallet",
		Version: "v0.2.0",
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
		Name:        "request_quote",
		Description: "Obtain a binding supplier quote via gateway quote.read with fresh challenge authentication and KB-JWT proof.",
	}, w.handleRequestQuote)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_order",
		Description: "Persist a client_actions intent lock first, then submit an authenticated order.create request bound to a quoteId and idempotencyKey.",
	}, w.handleCreateOrder)

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
	if int64(in.RemainingDepth) >= parent.Claims.RemainingDepth {
		w.mu.Unlock()
		return nil, DelegateGrantOutput{}, fmt.Errorf("remainingDepth %d must be strictly less than parent %s remainingDepth %d", in.RemainingDepth, parent.Claims.ID, parent.Claims.RemainingDepth)
	}
	if in.MaxAmountMinor > parent.Claims.MaxAmountMinor {
		w.mu.Unlock()
		return nil, DelegateGrantOutput{}, fmt.Errorf("maxAmountMinor %d exceeds parent %s ceiling %d", in.MaxAmountMinor, parent.Claims.ID, parent.Claims.MaxAmountMinor)
	}

	subjectDID := in.SubjectDID
	var granteeSigner *actorSigner
	if in.SubjectActor != "" {
		granteeSigner, ok = w.signers[in.SubjectActor]
		if !ok {
			w.mu.Unlock()
			return nil, DelegateGrantOutput{}, fmt.Errorf("unknown subjectActor %q", in.SubjectActor)
		}
		if subjectDID == "" {
			subjectDID = granteeSigner.did
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
		w.mu.Unlock()
		return nil, DelegateGrantOutput{}, errors.New("subjectDid or subjectActor is required")
	}

	granteeKeyVersion := uint64(1)
	granteeCredentialID := "cred:" + subjectDID
	if granteeSigner != nil {
		granteeKeyVersion = granteeSigner.keyVersion
		if granteeSigner.credentialID != "" {
			granteeCredentialID = granteeSigner.credentialID
		}
	}

	taskID := in.TaskID
	if taskID == "" {
		taskID = parent.Claims.TaskID
	}
	if taskID != parent.Claims.TaskID {
		w.mu.Unlock()
		return nil, DelegateGrantOutput{}, fmt.Errorf("taskId %q does not match parent taskId %q", taskID, parent.Claims.TaskID)
	}
	mode := in.AuthorizationMode
	if mode == "" {
		mode = parent.Claims.AuthorizationMode
	}
	if mode != parent.Claims.AuthorizationMode {
		w.mu.Unlock()
		return nil, DelegateGrantOutput{}, fmt.Errorf("authorizationMode %q does not match parent mode %q", mode, parent.Claims.AuthorizationMode)
	}

	childID := in.GrantID
	if childID == "" {
		childID = fmt.Sprintf("G-%s-%s", taskID, randomHex(4))
	}
	now := w.cfg.Now().UTC().Unix()
	nbf := parent.Claims.NBF
	if now > nbf {
		nbf = now - 5
	}
	exp := parent.Claims.EXP
	if in.ExpiresInSeconds > 0 && now+in.ExpiresInSeconds < exp {
		exp = now + in.ExpiresInSeconds
	}
	if exp <= nbf {
		w.mu.Unlock()
		return nil, DelegateGrantOutput{}, errors.New("child grant expiration window is empty")
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
		MaxAmountMinor:      in.MaxAmountMinor,
		NBF:                 nbf,
		EXP:                 exp,
		RemainingDepth:      int64(in.RemainingDepth),
	}
	rawJWS, digest, err := protocol.SignGrant(issuer.privateKey, issuer.keyID, &claims)
	if err != nil {
		w.mu.Unlock()
		return nil, DelegateGrantOutput{}, fmt.Errorf("sign child grant: %s", w.SanitizeString(err.Error()))
	}

	chain := append(slices.Clone(parent.ChainRawGrants), rawJWS)
	ancestors := append(slices.Clone(parent.AncestorCredentials), protocol.AncestorCredential{
		CredentialID: issuerCredID,
		Presentation: issuer.sdJWTPresentation,
	})
	trustPaths := slices.Clone(parent.TrustPaths)
	anchorHook := w.cfg.AnchorChildFunc
	w.mu.Unlock()

	anchored := false
	note := "signed locally with isolated actor key"
	if anchorHook != nil {
		res, err := anchorHook(ctx, AnchorChildGrantRequest{
			Claims:      claims,
			RawGrantJWS: rawJWS,
			GrantDigest: digest,
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
				trustPaths = slices.Clone(res.TrustPaths)
			}
			if len(res.AncestorCredentials) > 0 {
				ancestors = slices.Clone(res.AncestorCredentials)
			}
		}
		if anchored {
			note = "signed and anchored onto Fabric registry"
		}
	}

	childBundle := GrantBundle{
		Claims:              claims,
		TaskSpec:            parent.TaskSpec,
		RawGrantJWS:         rawJWS,
		Digest:              digest,
		ChainRawGrants:      chain,
		AncestorCredentials: ancestors,
		TrustPaths:          trustPaths,
		Anchored:            anchored,
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

	// Persist durable client_actions intent lock BEFORE dispatching order.create to gateway.
	actionRec, err := w.beginClientAction(ctx, signerCopy.did, in.TaskID, "order.create", in.IdempotencyKey, reqHash)
	if err != nil {
		return nil, CreateOrderOutput{}, errors.New(w.SanitizeString(err.Error()))
	}

	code, execResp, errResp, callErr := w.submitAccessExecuteWithReqHash(ctx, &signerCopy, &grantCopy, req, reqHash, actionRec.ActionID)
	if callErr != nil {
		_ = w.updateClientAction(ctx, actionRec.ActionID, "FAILED", "", in.QuoteID, "", "")
		return nil, CreateOrderOutput{}, errors.New(w.SanitizeString(callErr.Error()))
	}

	out := CreateOrderOutput{
		StatusCode: code,
		ActionID:   actionRec.ActionID,
		QuoteID:    in.QuoteID,
		ProductID:  productID,
		Quantity:   quantity,
		Currency:   currency,
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
	return w.submitAccessExecuteWithReqHash(ctx, signer, grant, req, reqHash, "")
}

func (w *WalletContext) submitAccessExecuteWithReqHash(
	ctx context.Context,
	signer *actorSigner,
	grant *GrantBundle,
	req protocol.AccessRequest,
	reqHash string,
	actionID string,
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
		w.mu.Lock()
		if rec, ok := w.actions[actionID]; ok {
			rec.ChallengeID = chal.ChallengeID
		}
		w.mu.Unlock()
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

	execCode, execRaw, err := w.doJSON(ctx, http.MethodPost, "/v1/access/execute", pkg)
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

func (w *WalletContext) doJSON(ctx context.Context, method, path string, payload any) (int, []byte, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	if w.cfg.HTTPHandler != nil {
		req := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
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

func (w *WalletContext) beginClientAction(ctx context.Context, actor, taskID, action, idempotencyKey, reqHash string) (*ClientActionView, error) {
	nowSec := w.cfg.Now().UTC().Unix()
	if w.cfg.DB != nil {
		rec, err := gateway.BeginClientAction(ctx, w.cfg.DB, w.cfg.DeploymentID, actor, taskID, action, idempotencyKey, reqHash, nowSec)
		if err != nil {
			return nil, err
		}
		view := ClientActionView{
			ActionID:       rec.ActionID,
			Actor:          rec.Actor,
			TaskID:         rec.TaskID,
			Action:         rec.Action,
			IdempotencyKey: rec.IdempotencyKey,
			Status:         rec.Status,
			ChallengeID:    rec.ChallengeID,
			QuoteID:        rec.QuoteID,
			OrderID:        rec.OrderID,
			DecisionID:     rec.DecisionID,
		}
		w.mu.Lock()
		cp := view
		w.actions[view.ActionID] = &cp
		w.mu.Unlock()
		return &view, nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	key := actionMapKey(actor, taskID, action, idempotencyKey)
	for _, existing := range w.actions {
		if actionMapKey(existing.Actor, existing.TaskID, existing.Action, existing.IdempotencyKey) == key {
			cp := *existing
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
	}
	w.actions[view.ActionID] = view
	cp := *view
	return &cp, nil
}

func (w *WalletContext) updateClientAction(ctx context.Context, actionID, status, challengeID, quoteID, orderID, decisionID string) error {
	nowSec := w.cfg.Now().UTC().Unix()
	w.mu.Lock()
	if rec, ok := w.actions[actionID]; ok {
		rec.Status = status
		if challengeID != "" {
			rec.ChallengeID = challengeID
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
			SELECT action_id, actor, task_id, action, idempotency_key, status,
			       COALESCE(challenge_id,''), COALESCE(quote_id,''), COALESCE(order_id,''), COALESCE(decision_id,'')
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
					&item.ActionID, &item.Actor, &item.TaskID, &item.Action, &item.IdempotencyKey, &item.Status,
					&item.ChallengeID, &item.QuoteID, &item.OrderID, &item.DecisionID,
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
