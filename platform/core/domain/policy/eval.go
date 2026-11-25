package policy

import (
	"context"
	"fmt"
	"slices"

	"grad/protocol"

	"github.com/open-policy-agent/opa/v1/rego"
)

// SupplierFacts carries verified server-side facts (never client-supplied flags) used to compute supplierAcceptance.
type SupplierFacts struct {
	AuthorizationMode   string
	BuyerDomain         string
	AuthorityRole       string
	ServiceDID          string
	ServiceRole         string
	Resource            string
	ProductID           string
	Quantity            int64
	Action              string
	AmountMinor         int64
	MaxPathAmountMinor  int64
	NowUnix             int64
	VerifiedCrypto      bool
	TaskActive          bool
	PathActive          bool
	ContextFresh        bool
	ContextRiskLevel    string
	WithinTimeAndBounds bool
	Attributes          map[string]string
}

// EvalTask is the task status object passed into OPA input.
type EvalTask struct {
	Active bool `json:"active"`
}

// EvalPath is the delegation path summary passed into OPA input.
type EvalPath struct {
	Active         bool  `json:"active"`
	MaxAmountMinor int64 `json:"maxAmountMinor"`
}

// EvalRequest is the normalized business request passed into OPA input.
type EvalRequest struct {
	Action      string `json:"action"`
	Resource    string `json:"resource"`
	ProductID   string `json:"productId"`
	Quantity    int64  `json:"quantity"`
	AmountMinor int64  `json:"amountMinor"`
}

// EvalContext is the locked trusted context passed into OPA input.
type EvalContext struct {
	Fresh     bool   `json:"fresh"`
	RiskLevel string `json:"riskLevel"`
}

// EvalConstraints summarizes verified bounds and deadline checks passed into OPA input.
type EvalConstraints struct {
	WithinBounds   bool `json:"withinBounds"`
	BeforeDeadline bool `json:"beforeDeadline"`
}

// OPAInput defines the strict schema input evaluated by package procurement.
type OPAInput struct {
	Verified           bool              `json:"verified"`
	SupplierAcceptance bool              `json:"supplierAcceptance"`
	Task               EvalTask          `json:"task"`
	Path               EvalPath          `json:"path"`
	Request            EvalRequest       `json:"request"`
	Context            EvalContext       `json:"context"`
	Constraints        EvalConstraints   `json:"constraints"`
	Attributes         map[string]string `json:"attributes,omitempty"`
}

// Decision captures the deterministic policy evaluation output.
type Decision struct {
	Allow        bool     `json:"allow"`
	Code         string   `json:"code"`
	Reason       string   `json:"reason,omitempty"`
	PolicyDigest string   `json:"policyDigest"`
	Input        OPAInput `json:"input"`
}

// ComputeSupplierAcceptance derives supplierAcceptance purely on the server side from verified ledger,
// credential, and bundle configuration facts.
func (b *VerifiedBundle) ComputeSupplierAcceptance(f SupplierFacts) (bool, string) {
	if !slices.Contains(b.Roles.AcceptedAuthorizationModes, f.AuthorizationMode) {
		return false, protocol.ErrCodeSupplierPolicyDenied
	}
	if !slices.Contains(b.Roles.AcceptedBuyerDomains, f.BuyerDomain) {
		return false, protocol.ErrCodeSupplierPolicyDenied
	}
	if f.ServiceDID != b.Manifest.ServiceDID || !slices.Contains(b.Roles.AcceptedServiceRoles, f.ServiceRole) {
		return false, protocol.ErrCodeSupplierPolicyDenied
	}
	if f.AuthorizationMode == protocol.ModeBuyerMandate && !slices.Contains(b.Roles.AcceptedAuthorityRoles, f.AuthorityRole) {
		return false, protocol.ErrCodeSupplierPolicyDenied
	}
	resource, err := resolveCanonicalResource(f.Action, f.Resource)
	if err != nil {
		return false, protocol.ErrCodeSupplierPolicyDenied
	}
	if !slices.Contains(b.Resources.AllowedActions, f.Action) || !slices.Contains(b.Resources.AllowedResources, resource) {
		return false, protocol.ErrCodeSupplierPolicyDenied
	}
	if !slices.Contains(b.Resources.AllowedProductIDs, f.ProductID) || f.Quantity <= 0 || f.Quantity > b.Resources.MaxQuantity {
		return false, protocol.ErrCodeSupplierPolicyDenied
	}
	return true, ""
}

// BuildInput validates all server-verified facts and constructs the canonical OPAInput.
func (b *VerifiedBundle) BuildInput(f SupplierFacts) (OPAInput, error) {
	resource, err := resolveCanonicalResource(f.Action, f.Resource)
	if err != nil {
		return OPAInput{}, err
	}
	if !isValidRiskLevel(f.ContextRiskLevel) {
		return OPAInput{}, protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("invalid riskLevel %q for policy input", f.ContextRiskLevel))
	}
	if f.AmountMinor < 0 || f.MaxPathAmountMinor < 0 || f.Quantity <= 0 || f.ProductID == "" {
		return OPAInput{}, protocol.NewError(protocol.ErrCodeInvalidSchema, "invalid quantity, productId, or amount in policy input")
	}

	beforePolicyDeadline := f.WithinTimeAndBounds
	if b.Resources.PolicyDeadline != nil && f.NowUnix >= *b.Resources.PolicyDeadline {
		beforePolicyDeadline = false
	}

	accepted, _ := b.ComputeSupplierAcceptance(f)

	return OPAInput{
		Verified:           f.VerifiedCrypto,
		SupplierAcceptance: accepted,
		Task:               EvalTask{Active: f.TaskActive},
		Path:               EvalPath{Active: f.PathActive, MaxAmountMinor: f.MaxPathAmountMinor},
		Request: EvalRequest{
			Action:      f.Action,
			Resource:    resource,
			ProductID:   f.ProductID,
			Quantity:    f.Quantity,
			AmountMinor: f.AmountMinor,
		},
		Context:     EvalContext{Fresh: f.ContextFresh, RiskLevel: f.ContextRiskLevel},
		Constraints: EvalConstraints{WithinBounds: f.WithinTimeAndBounds, BeforeDeadline: beforePolicyDeadline},
		Attributes:  f.Attributes,
	}, nil
}

// ValidateInput checks strict required fields, canonical action-resource pairing, and enum invariants on OPAInput before invoking OPA.
func ValidateInput(in OPAInput) error {
	if err := protocol.ValidateCanonicalResource(in.Request.Action, in.Request.Resource); err != nil {
		return err
	}
	if in.Request.ProductID == "" || in.Request.Quantity <= 0 || in.Request.AmountMinor < 0 {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "incomplete or invalid policy request input")
	}
	if in.Path.MaxAmountMinor < 0 {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, "negative path maxAmountMinor")
	}
	if !isValidRiskLevel(in.Context.RiskLevel) {
		return protocol.NewError(protocol.ErrCodeInvalidSchema, fmt.Sprintf("invalid context riskLevel %q", in.Context.RiskLevel))
	}
	return nil
}

// EvaluateFacts validates SupplierFacts, computes server-side supplierAcceptance, validates OPAInput,
// and executes the prepared deterministic Rego v1 query (fail-closed on undefined/error).
func (b *VerifiedBundle) EvaluateFacts(ctx context.Context, f SupplierFacts) (Decision, error) {
	if b == nil {
		return Decision{Allow: false, Code: protocol.ErrCodePolicyDenied, Reason: "policy bundle missing"},
			protocol.NewError(protocol.ErrCodePolicyDenied, "policy bundle missing")
	}
	accepted, denyCode := b.ComputeSupplierAcceptance(f)
	in, err := b.BuildInput(f)
	if err != nil {
		code := protocol.CodeOf(err)
		if code == "" {
			code = protocol.ErrCodePolicyDenied
		}
		return Decision{Allow: false, Code: code, PolicyDigest: b.PolicyDigest, Reason: err.Error()}, err
	}
	res, err := b.EvaluateRawInput(ctx, in)
	if !res.Allow && !accepted && denyCode == protocol.ErrCodeSupplierPolicyDenied && res.Code == protocol.ErrCodePolicyDenied {
		res.Code = protocol.ErrCodeSupplierPolicyDenied
	}
	return res, err
}

// EvaluateRawInput evaluates a validated OPAInput against the prepared Rego v1 query.
// It fails closed unless the query returns exactly one result expression with boolean true.
func (b *VerifiedBundle) EvaluateRawInput(ctx context.Context, in OPAInput) (Decision, error) {
	if b == nil {
		return Decision{Allow: false, Code: protocol.ErrCodePolicyDenied, Reason: "policy bundle missing", Input: in},
			protocol.NewError(protocol.ErrCodePolicyDenied, "policy bundle missing")
	}
	dec := Decision{Allow: false, Code: protocol.ErrCodePolicyDenied, PolicyDigest: b.PolicyDigest, Input: in}
	if err := ValidateInput(in); err != nil {
		dec.Code = protocol.ErrCodeInvalidSchema
		dec.Reason = err.Error()
		return dec, err
	}
	if !in.SupplierAcceptance {
		dec.Code = protocol.ErrCodeSupplierPolicyDenied
	}

	rs, err := b.query.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		dec.Reason = "opa evaluation error: " + err.Error()
		return dec, protocol.WrapError(dec.Code, dec.Reason, err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		dec.Reason = "opa evaluation produced undefined or ambiguous result"
		return dec, protocol.NewError(dec.Code, dec.Reason)
	}
	allowed, ok := rs[0].Expressions[0].Value.(bool)
	if !ok || !allowed {
		dec.Reason = fmt.Sprintf("policy denied action=%s resource=%s riskLevel=%s", in.Request.Action, in.Request.Resource, in.Context.RiskLevel)
		return dec, protocol.NewError(dec.Code, dec.Reason)
	}
	dec.Allow = true
	dec.Code = "OK"
	return dec, nil
}

func resolveCanonicalResource(action, resource string) (string, error) {
	if resource == "" {
		return defaultResourceForAction(action)
	}
	if err := protocol.ValidateCanonicalResource(action, resource); err != nil {
		return "", err
	}
	return resource, nil
}

func isValidRiskLevel(level string) bool {
	return level == RiskNormal || level == RiskElevated || level == RiskBlocked
}
