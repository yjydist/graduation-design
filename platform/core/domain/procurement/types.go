// Package procurement implements the workbench domain logic across domains A, B, and C:
// browser session authentication, purchasing-authority management, grant issuance and
// verified outbox/receipt delivery, procurement draft/run lifecycle coordination, and
// Domain B dispatch execution without inbound HTTP or L4 agent coupling.
package procurement

import (
	"context"
	"errors"
	"time"
	"unicode/utf8"

	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/protocol"
	preg "grad/protocol/registry"
)

// Role is assigned to a local workbench account when it is provisioned.
type Role string

const (
	RoleAdmin   Role = "ADMIN"
	RoleBuyer   Role = "BUYER"
	RoleAuditor Role = "AUDITOR"

	SessionLifetime = 8 * time.Hour

	StageTask       = "REGISTER_TASK"
	StageRoot       = "DELIVER_G0"
	StageDelegation = "DELIVER_G1"
	StageDispatch   = "EXECUTE"

	RunPending = "PENDING"
	RunFailed  = "FAILED"
	RunStopped = "MODEL_STOPPED"
	RunDenied  = "GATEWAY_DENIED"
	RunUnknown = "OUTCOME_UNKNOWN"
	RunDecided = "DECIDED"

	DefaultAudience   = "https://c.local"
	DefaultSupplierID = "urn:grad:supplier:C"
	DefaultCurrency   = "CNY"

	MaxChatMessageLength      = 4000
	MaxDraftDescriptionLength = 512

	SetPurchasingAuthorityMethod = "SetPurchasingAuthority"

	riskLevelNormal = "NORMAL"
)

var (
	ErrLoginFailed          = errors.New("invalid login")
	ErrSessionRequired      = errors.New("active local session required")
	ErrDraftVersionConflict = errors.New("draft version changed")
	ErrNotFound             = errors.New("object not found")
	ErrUnavailable          = errors.New("service unavailable")
)

// Principal binds a browser login to the deployment's local registered identity.
type Principal struct {
	DomainID   string          `json:"domainId"`
	SubjectID  string          `json:"subjectId"`
	Role       Role            `json:"role"`
	Management preg.Management `json:"management"`
}

// AccountSeed supplies a credential and identity binding from local host configuration.
type AccountSeed struct {
	Principal
	Username string `json:"username"`
	Password string `json:"password"`
}

// SessionView is the authenticated browser session payload returned after login or session lookup.
type SessionView struct {
	DomainID  string   `json:"domainId"`
	SubjectID string   `json:"subjectId"`
	Role      Role     `json:"role"`
	Actions   []string `json:"actions"`
	CSRFToken string   `json:"csrfToken"`
}

// PurchasingAuthority describes a domain's current purchasing authority configuration and eligible services.
type PurchasingAuthority struct {
	DomainID            string   `json:"domainId"`
	ExpectedRevision    uint64   `json:"expectedRevision"`
	PurchasingAuthority *string  `json:"purchasingAuthority"`
	EligibleServiceIDs  []string `json:"eligibleServiceIds"`
}

// Draft captures buyer-editable procurement terms prior to explicit confirmation.
type Draft struct {
	DraftID        string `json:"draftId"`
	Version        int64  `json:"version"`
	ProductID      string `json:"productId"`
	Quantity       int64  `json:"quantity"`
	Mode           string `json:"mode"`
	MaxAmountMinor int64  `json:"maxAmountMinor"`
	ExpiresAt      int64  `json:"expiresAt"`
	DelegateDID    string `json:"delegateDid"`
	Description    string `json:"description"`
}

// TaskSpec converts Draft into the canonical protocol.TaskSpec hashed into RegisterTask.
func (d Draft) TaskSpec() protocol.TaskSpec {
	return protocol.TaskSpec{
		SupplierID:  DefaultSupplierID,
		ProductID:   d.ProductID,
		MaxQuantity: d.Quantity,
		Currency:    DefaultCurrency,
		Description: d.Description,
		Resources:   []string{protocol.ResourceOrders, protocol.ResourceQuotes},
		Actions:     []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
	}
}

// Validate checks Draft fields against workbench procurement bounds and delegate binding.
func (d Draft) Validate(delegate string, now time.Time) error {
	spec := d.TaskSpec()
	switch {
	case d.Mode != preg.RP && d.Mode != preg.BM:
		return protocol.NewError(preg.ErrCodeInvalidSchema, "mode must be RP or BM")
	case d.DelegateDID != delegate:
		return protocol.NewError(preg.ErrCodeInvalidSchema, "delegate must be the configured A1")
	case d.MaxAmountMinor < 1 || d.MaxAmountMinor > protocol.MaxSafeInt:
		return protocol.NewError(preg.ErrCodeInvalidSchema, "amount outside supported range")
	case d.ExpiresAt <= now.Add(preg.ClockError).Unix() || d.ExpiresAt > now.Add(24*time.Hour).Unix():
		return protocol.NewError(preg.ErrCodeInvalidSchema, "expiration must be within the next 24 hours")
	case d.ProductID != "urn:grad:product:P1" && d.ProductID != "urn:grad:product:P2":
		return protocol.NewError(preg.ErrCodeInvalidSchema, "unknown product")
	case utf8.RuneCountInString(d.Description) > MaxDraftDescriptionLength:
		return protocol.NewError(preg.ErrCodeInvalidSchema, "description is too long")
	default:
		return spec.Validate()
	}
}

// ToolTrace mirrors agent/llm.ToolTrace JSON fields so L2 never imports L4 agent/llm.
type ToolTrace struct {
	Step       int            `json:"step"`
	ToolName   string         `json:"toolName"`
	Arguments  map[string]any `json:"arguments,omitempty"`
	Output     map[string]any `json:"output,omitempty"`
	RawText    string         `json:"rawText,omitempty"`
	IsError    bool           `json:"isError"`
	DurationMs int64          `json:"durationMs"`
}

// ModelRunResult summarizes an L4 agent execution returned to L2 coordinators.
type ModelRunResult struct {
	Summary         string      `json:"summary,omitempty"`
	Traces          []ToolTrace `json:"traces,omitempty"`
	Provider        string      `json:"provider,omitempty"`
	RequestedModel  string      `json:"requestedModel,omitempty"`
	ResponseModels  []string    `json:"responseModels,omitempty"`
	Steps           int         `json:"steps,omitempty"`
	TotalDurationMs int64       `json:"totalDurationMs,omitempty"`
}

// RunStep records one observed transition or management operation for a procurement run.
type RunStep struct {
	Stage          string `json:"stage"`
	Status         string `json:"status"`
	OperationID    string `json:"operationId,omitempty"`
	TxID           string `json:"txId,omitempty"`
	ValidationCode string `json:"validationCode,omitempty"`
	Code           string `json:"code,omitempty"`
	GrantID        string `json:"grantId,omitempty"`
	At             int64  `json:"at"`
}

// Run captures the persisted Domain A procurement run projection.
type Run struct {
	RunID          string      `json:"runId"`
	TaskID         string      `json:"taskId"`
	DraftID        string      `json:"draftId"`
	Stage          string      `json:"stage"`
	Status         string      `json:"status"`
	ConfirmedAt    int64       `json:"confirmedAt"`
	Task           Draft       `json:"task"`
	Steps          []RunStep   `json:"steps"`
	Traces         []ToolTrace `json:"traces"`
	GrantRevision  uint64      `json:"grantRevision,omitempty"`
	GrantStatus    string      `json:"grantStatus,omitempty"`
	AllowedActions []string    `json:"allowedActions"`
}

// GrantID derives the deterministic grant identifier for hop ("G0", "G1", "G2") under r.TaskID.
func (r Run) GrantID(hop string) string {
	return preg.Digest([]byte(r.TaskID + "/" + hop))
}

// StageResult reports the outcome of advancing one procurement stage.
type StageResult struct {
	Operation *domreg.OperationView
	GrantID   string
	Status    string
	Code      string
	Traces    []ToolTrace
}

// GrantActor is one locally configured grant issuer with its wallet signer and Fabric management identity.
type GrantActor struct {
	Signer     wallet.Signer
	Management preg.Management
}

// GrantRecipient identifies the intended recipient DID and credential ID.
type GrantRecipient struct {
	DID          string `json:"did"`
	CredentialID string `json:"credentialId"`
}

// RootGrantRequest requests issuance of a root grant G0 for a confirmed task.
type RootGrantRequest struct {
	GrantID        string            `json:"grantId"`
	TaskID         string            `json:"taskId"`
	Recipient      GrantRecipient    `json:"recipient"`
	TaskSpec       protocol.TaskSpec `json:"taskSpec"`
	MaxAmountMinor int64             `json:"maxAmountMinor"`
	Depth          int               `json:"depth"`
}

// GrantDelivery travels on the authenticated inter-domain channel with the confirmed operation,
// signed grant package, and verified package digest.
type GrantDelivery struct {
	Operation domreg.OperationView        `json:"operation"`
	Package   domreg.GrantDeliveryPackage `json:"package"`
	Digest    string                      `json:"digest"`
}

// RootGrantResponse is the inter-domain reply from Domain C's root issuance endpoint.
type RootGrantResponse struct {
	Operation *domreg.OperationView `json:"operation,omitempty"`
	Delivery  *GrantDelivery        `json:"delivery,omitempty"`
	Code      string                `json:"code,omitempty"`
}

// RootGrantReceipt acknowledges recipient-side receipt of a delivered root grant.
type RootGrantReceipt struct {
	GrantID string `json:"grantId"`
	Digest  string `json:"digest"`
}

// DispatchRun is the confirmed run summary forwarded from Domain A to Domain B.
type DispatchRun struct {
	RunID  string `json:"runId"`
	TaskID string `json:"taskId"`
	Task   Draft  `json:"task"`
}

// DispatchRequest carries a confirmed run and its verified G2 delivery from Domain A to Domain B.
type DispatchRequest struct {
	Run      DispatchRun   `json:"run"`
	Delivery GrantDelivery `json:"delivery"`
}

// DispatchStatusView reports Domain B's current execution status, receipt digest, and bounded tool traces.
type DispatchStatusView struct {
	Receipt string      `json:"receipt"`
	Status  string      `json:"status"`
	Code    string      `json:"code,omitempty"`
	Traces  []ToolTrace `json:"traces,omitempty"`
}

// ProbeRequest triggers deterministic B1 bound quote/order probes from Domain A.
type ProbeRequest struct {
	RunID string `json:"runId"`
	Key   string `json:"key"`
	Order bool   `json:"order"`
}

// ProbeResponse returns the quote and optional order outputs from a B1 probe.
type ProbeResponse struct {
	Quote wallet.RequestQuoteOutput `json:"quote"`
	Order *wallet.CreateOrderOutput `json:"order,omitempty"`
}

// DelegateRunInput supplies confirmed parameters to an L4 A1 delegation runner.
type DelegateRunInput struct {
	RunID          string
	TaskID         string
	Mode           string
	ParentGrantID  string
	ChildGrantID   string
	RecipientDID   string
	MaxAmountMinor int64
	OnToolTrace    func(ToolTrace)
}

// ExecuteRunInput supplies confirmed parameters to an L4 B1 execution runner.
type ExecuteRunInput struct {
	RunID          string
	TaskID         string
	Mode           string
	GrantID        string
	ProductID      string
	Quantity       int64
	MaxAmountMinor int64
	OrderKey       string
	OnToolTrace    func(ToolTrace)
}

// AuthorityVerifier validates whether a local principal is active and authorized by the registry.
type AuthorityVerifier interface {
	VerifyPrincipal(ctx context.Context, principal Principal) error
}

// AuthorityReader extends AuthorityVerifier with purchasing-authority queries and eligibility checks.
type AuthorityReader interface {
	AuthorityVerifier
	ReadPurchasingAuthority(ctx context.Context, principal Principal) (PurchasingAuthority, error)
	CheckPurchasingAuthority(ctx context.Context, principal Principal, subject string) error
}

// DraftAdvisor produces a buyer-facing draft proposal from natural language chat input.
type DraftAdvisor interface {
	SuggestDraft(ctx context.Context, message string, previous *Draft) (Draft, string, error)
}

// DelegateRunner executes the L4 A1 agent delegation loop over server-bound wallet operations.
type DelegateRunner interface {
	RunDelegate(ctx context.Context, ops *wallet.BoundOperations, req DelegateRunInput) (ModelRunResult, error)
}

// ExecuteRunner executes the L4 B1 agent procurement loop over server-bound wallet operations.
type ExecuteRunner interface {
	RunExecute(ctx context.Context, ops *wallet.BoundOperations, req ExecuteRunInput) (ModelRunResult, error)
}

// PeerClient abstracts outbound mTLS inter-domain calls between A, B, and C.
type PeerClient interface {
	RequestRoot(ctx context.Context, req RootGrantRequest) (RootGrantResponse, error)
	AckRootReceipt(ctx context.Context, grantID, digest string) error
	EnsureContext(ctx context.Context, taskID string) error
	SubmitDispatch(ctx context.Context, req DispatchRequest) (DispatchStatusView, error)
	GetDispatch(ctx context.Context, runID string) (DispatchStatusView, error)
	RequestDispatchProbe(ctx context.Context, req ProbeRequest) (ProbeResponse, error)
}

// ContextUpdater installs or updates a supplier C trusted environment context for a confirmed task.
type ContextUpdater func(ctx context.Context, taskID string, expectedVersion int64, riskLevel string, policyDeadline int64) error
