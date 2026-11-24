package agent

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"grad/protocol"
	"grad/protocol/registry"
)

type ExecutionStage string

const (
	StageDelegate ExecutionStage = "delegate"
	StageExecute  ExecutionStage = "execute"
)

// ExecutionBinding is supplied by the service that owns the confirmed run.
// Verify can additionally check durable run and grant state on each call.
type ExecutionBinding struct {
	DeploymentID string
	DomainID     string
	Actor        string
	DID          string
	TaskID       string
	Mode         string
	GrantID      string
	Stage        ExecutionStage
	ProductID    string
	Quantity     int64
	SubjectDID   string
	SubjectActor string
	ChildGrantID string
	RunID        string
	Verify       func(context.Context, ExecutionBinding) error
}

// BoundOperations is the typed operation surface for an approved execution run.
// HTTP callers and MCP use the same server-owned scope and wallet operations.
type BoundOperations struct {
	wallet *WalletContext
	scope  ExecutionBinding
}

func NewBoundOperations(wallet *WalletContext, b ExecutionBinding) (*BoundOperations, error) {
	if wallet == nil || b.DeploymentID == "" || b.DomainID == "" || b.Actor == "" ||
		b.DID == "" || b.TaskID == "" || b.GrantID == "" || b.RunID == "" ||
		(b.Mode != registry.RP && b.Mode != registry.BM) {
		return nil, executionMismatch("complete run binding required")
	}
	switch b.Stage {
	case StageDelegate:
		if b.SubjectDID == "" || !registry.IsDigest(b.ChildGrantID) || wallet.cfg.AnchorChildFunc == nil {
			return nil, executionMismatch("delegation recipient, child ID and registry required")
		}
	case StageExecute:
		if b.ProductID == "" || b.Quantity <= 0 {
			return nil, executionMismatch("confirmed product and quantity required")
		}
	default:
		return nil, executionMismatch("unknown execution stage")
	}
	out := &BoundOperations{wallet: wallet, scope: b}
	if err := out.verifyWallet(false); err != nil {
		return nil, err
	}
	return out, nil
}

func executionMismatch(message string) error {
	return protocol.NewError(protocol.ErrCodeBindingMismatch, message)
}

func executionFailure(err error) error {
	if err == nil || protocol.CodeOf(err) != "" {
		return err
	}
	return protocol.WrapError(protocol.ErrCodeStateUnavailable, "wallet operation failed", err)
}

func (o *BoundOperations) verifyWallet(requireCurrent bool) error {
	w, b := o.wallet, o.scope
	w.mu.Lock()
	defer w.mu.Unlock()
	signer := w.signers[b.Actor]
	if w.cfg.DeploymentID != b.DeploymentID || signer == nil || signer.DID != b.DID || signer.DomainID != b.DomainID {
		return executionMismatch("execution signer differs from run binding")
	}
	grant, err := w.findGrantLocked(b.DID, b.GrantID, b.TaskID, b.Mode)
	if err != nil || grant.Replaced || !grant.Anchored || grant.Claims.DeploymentID != b.DeploymentID ||
		grant.Claims.TaskID != b.TaskID || grant.Claims.AuthorizationMode != b.Mode ||
		grant.Claims.GranteeKeyVersion != signer.KeyVersion || grant.Claims.GranteeCredentialID != signer.CredentialID {
		return executionMismatch("wallet lacks the delivered grant for this run")
	}
	now := w.cfg.Now().UTC().Unix()
	if requireCurrent && (now < grant.Claims.NBF || now >= grant.Claims.EXP) {
		return protocol.NewError(protocol.ErrCodeAncestorInactive, "bound grant is outside its validity interval")
	}
	if b.Stage == StageExecute && (grant.TaskSpec.ProductID != b.ProductID || grant.TaskSpec.MaxQuantity < b.Quantity) {
		return executionMismatch("confirmed item differs from delivered task specification")
	}
	return nil
}

func (o *BoundOperations) verify(ctx context.Context) error {
	if err := o.verifyWallet(true); err != nil {
		return err
	}
	if o.scope.Verify != nil {
		return executionFailure(o.scope.Verify(ctx, o.scope))
	}
	return nil
}

func matchesBinding(value, bound string) bool {
	return value == "" || value == bound
}

func (o *BoundOperations) matches(actor, grant, task, mode string) bool {
	b := o.scope
	return matchesBinding(actor, b.Actor) && matchesBinding(grant, b.GrantID) &&
		matchesBinding(task, b.TaskID) && matchesBinding(mode, b.Mode)
}

func (o *BoundOperations) key(action string) string {
	b := o.scope
	raw, _ := json.Marshal([]string{b.DeploymentID, b.DomainID, b.DID, b.TaskID, b.Mode, b.GrantID, b.RunID, action})
	return "wb-" + registry.Digest(raw)[:40]
}

func (o *BoundOperations) QuoteKey() string { return o.key(protocol.ActionQuoteRead) }
func (o *BoundOperations) OrderKey() string { return o.key(protocol.ActionOrderCreate) }

func (o *BoundOperations) InspectWallet(ctx context.Context, in InspectWalletInput) (InspectWalletOutput, error) {
	b := o.scope
	if !o.matches(in.Actor, "", in.TaskID, in.AuthorizationMode) {
		return InspectWalletOutput{}, executionMismatch("wallet inspection differs from run binding")
	}
	if err := o.verify(ctx); err != nil {
		return InspectWalletOutput{}, err
	}
	out, err := o.wallet.InspectWallet(ctx, InspectWalletInput{Actor: b.Actor, TaskID: b.TaskID, AuthorizationMode: b.Mode})
	out.Grants = slices.DeleteFunc(out.Grants, func(g SanitizedGrantView) bool { return g.GrantID != b.GrantID })
	out.Quotes = slices.DeleteFunc(out.Quotes, func(q QuoteRecord) bool { return q.IdempotencyKey != o.QuoteKey() })
	out.Orders = slices.DeleteFunc(out.Orders, func(order OrderRecord) bool { return order.IdempotencyKey != o.OrderKey() })
	out.ClientActions = slices.DeleteFunc(out.ClientActions, func(a ClientActionView) bool {
		return a.Action != protocol.ActionOrderCreate || a.IdempotencyKey != o.OrderKey()
	})
	return out, executionFailure(err)
}

func (o *BoundOperations) DelegateGrant(ctx context.Context, in DelegateGrantInput) (DelegateGrantOutput, error) {
	b := o.scope
	if b.Stage != StageDelegate || !o.matches(in.IssuerActor, in.ParentGrantID, in.TaskID, in.AuthorizationMode) ||
		!matchesBinding(in.SubjectDID, b.SubjectDID) || !matchesBinding(in.SubjectActor, b.SubjectActor) ||
		!matchesBinding(in.GrantID, b.ChildGrantID) {
		return DelegateGrantOutput{}, executionMismatch("delegation differs from run binding")
	}
	if in.MaxAmountMinor <= 0 || in.RemainingDepth < 0 || in.ExpiresInSeconds < 0 {
		return DelegateGrantOutput{}, protocol.NewError(protocol.ErrCodeInvalidSchema, "invalid delegation amount, depth or duration")
	}
	if err := o.verify(ctx); err != nil {
		return DelegateGrantOutput{}, err
	}
	in.IssuerActor, in.ParentGrantID, in.TaskID, in.AuthorizationMode = b.Actor, b.GrantID, b.TaskID, b.Mode
	in.SubjectDID, in.SubjectActor, in.GrantID = b.SubjectDID, "", b.ChildGrantID
	out, err := o.wallet.DelegateGrant(ctx, in)
	return out, executionFailure(err)
}

func (o *BoundOperations) RequestQuote(ctx context.Context, in RequestQuoteInput) (RequestQuoteOutput, error) {
	b := o.scope
	if b.Stage != StageExecute || !o.matches(in.Actor, in.GrantID, in.TaskID, in.AuthorizationMode) ||
		!matchesBinding(in.ProductID, b.ProductID) || (in.Quantity != 0 && in.Quantity != b.Quantity) ||
		!matchesBinding(in.IdempotencyKey, o.QuoteKey()) || in.BlockHeight != nil {
		return RequestQuoteOutput{}, executionMismatch("quote differs from run binding")
	}
	if err := o.verify(ctx); err != nil {
		return RequestQuoteOutput{}, err
	}
	in.Actor, in.GrantID, in.TaskID, in.AuthorizationMode = b.Actor, b.GrantID, b.TaskID, b.Mode
	in.ProductID, in.Quantity, in.IdempotencyKey = b.ProductID, b.Quantity, o.QuoteKey()
	out, err := o.wallet.requestQuote(ctx, in, true)
	return out, executionFailure(err)
}

func (w *WalletContext) saveBoundQuote(ctx context.Context, req protocol.AccessRequest, quote *QuotePayload) error {
	if quote == nil || quote.QuoteID == "" || quote.Actor != req.Actor || quote.TaskID != req.TaskID ||
		quote.SupplierID != req.SupplierID || quote.ProductID != req.ProductID || quote.Quantity != req.Quantity ||
		quote.Currency != req.Currency || quote.TotalAmountMinor <= 0 {
		return executionMismatch("gateway quote differs from the run request")
	}
	// A repeat of the same quote may confirm the stored terms, but may never change them.
	tag, err := w.cfg.DB.Exec(ctx, `INSERT INTO wallet_bound_quotes
		(deployment_id, actor, task_id, quote_key, quote_id, currency, total_amount_minor)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (deployment_id, actor, task_id, quote_key) DO UPDATE SET quote_id=EXCLUDED.quote_id
		WHERE (wallet_bound_quotes.quote_id, wallet_bound_quotes.currency, wallet_bound_quotes.total_amount_minor)
			= (EXCLUDED.quote_id, EXCLUDED.currency, EXCLUDED.total_amount_minor)`,
		req.DeploymentID, req.Actor, req.TaskID, req.IdempotencyKey, quote.QuoteID, quote.Currency, quote.TotalAmountMinor)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return executionMismatch("quote terms differ from the original run quote")
	}
	return nil
}

func (o *BoundOperations) CreateOrder(ctx context.Context, in CreateOrderInput) (CreateOrderOutput, error) {
	b := o.scope
	if b.Stage != StageExecute || !o.matches(in.Actor, in.GrantID, in.TaskID, in.AuthorizationMode) ||
		!matchesBinding(in.ProductID, b.ProductID) || (in.Quantity != 0 && in.Quantity != b.Quantity) ||
		!matchesBinding(in.IdempotencyKey, o.OrderKey()) || in.BlockHeight != nil {
		return CreateOrderOutput{}, executionMismatch("order differs from run binding")
	}
	if err := o.verify(ctx); err != nil {
		return CreateOrderOutput{}, err
	}
	currency, amount, err := o.orderQuoteTerms(ctx, in.QuoteID)
	if err != nil {
		return CreateOrderOutput{}, err
	}
	if !matchesBinding(in.Currency, currency) || in.AmountMinor != amount {
		return CreateOrderOutput{}, executionMismatch("order must use the confirmed run quote and its terms")
	}
	in.Actor, in.GrantID, in.TaskID, in.AuthorizationMode = b.Actor, b.GrantID, b.TaskID, b.Mode
	in.ProductID, in.Quantity, in.IdempotencyKey, in.Currency = b.ProductID, b.Quantity, o.OrderKey(), currency
	out, err := o.wallet.CreateOrder(ctx, in)
	if out.Decision == "ALLOW" {
		out.TotalAmountMinor = amount
	}
	return out, executionFailure(err)
}

func (o *BoundOperations) orderQuoteTerms(ctx context.Context, id string) (string, int64, error) {
	w, b := o.wallet, o.scope
	if w.cfg.DB != nil {
		var quoteID, currency string
		var amount int64
		err := w.cfg.DB.QueryRow(ctx, `SELECT quote_id, currency, total_amount_minor FROM wallet_bound_quotes
			WHERE deployment_id=$1 AND actor=$2 AND task_id=$3 AND quote_key=$4`,
			b.DeploymentID, b.DID, b.TaskID, o.QuoteKey()).Scan(&quoteID, &currency, &amount)
		if err == nil {
			if id != quoteID {
				return "", 0, executionMismatch("quote differs from the run binding")
			}
			return currency, amount, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", 0, executionFailure(err)
		}
	} else {
		w.mu.Lock()
		quote, found := w.quotes[id]
		w.mu.Unlock()
		if found {
			if quote.Actor != b.Actor || quote.TaskID != b.TaskID || quote.IdempotencyKey != o.QuoteKey() {
				return "", 0, executionMismatch("quote differs from the run binding")
			}
			return quote.Currency, quote.TotalAmountMinor, nil
		}
	}

	// An existing order intent can still supply its original terms after an upgrade.
	action, err := w.GetClientActionByKey(ctx, b.DID, b.TaskID, protocol.ActionOrderCreate, o.OrderKey())
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, executionMismatch("order must use the confirmed run quote")
	}
	if err != nil {
		return "", 0, executionFailure(err)
	}
	var request protocol.AccessRequest
	if err := protocol.DecodeStrictJSON([]byte(action.RequestJSON), &request); err != nil {
		return "", 0, executionFailure(err)
	}
	if request.QuoteID == nil || *request.QuoteID != id {
		return "", 0, executionMismatch("quote differs from the original order intent")
	}
	return request.Currency, request.AmountMinor, nil
}

func (o *BoundOperations) ReconcileOrder(ctx context.Context, in ReconcileOrderInput) (ReconcileOrderOutput, error) {
	b := o.scope
	if b.Stage != StageExecute || !o.matches(in.Actor, "", in.TaskID, "") ||
		!matchesBinding(in.IdempotencyKey, o.OrderKey()) || !matchesBinding(in.Action, protocol.ActionOrderCreate) ||
		in.CaseID != "" {
		return ReconcileOrderOutput{}, executionMismatch("reconciliation differs from run binding")
	}
	// Reconciliation of an existing intent remains available when its grant expires.
	if err := o.verifyWallet(false); err != nil {
		return ReconcileOrderOutput{}, err
	}
	in.Actor, in.TaskID, in.IdempotencyKey = b.Actor, b.TaskID, o.OrderKey()
	out, err := o.wallet.ReconcileOrder(ctx, in)
	return out, executionFailure(err)
}

func (o *BoundOperations) MCPServer() *mcp.Server {
	srv := newWalletMCPServer()
	addWalletTool(srv, inspectWalletTool, o.InspectWallet, true)
	if o.scope.Stage == StageDelegate {
		addWalletTool(srv, delegateGrantTool, o.DelegateGrant, true)
	} else {
		addWalletTool(srv, requestQuoteTool, o.RequestQuote, true)
		addWalletTool(srv, createOrderTool, o.CreateOrder, true)
		addWalletTool(srv, reconcileOrderTool, o.ReconcileOrder, true)
	}
	return srv
}
