package orchestrator

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"grad/platform/agent/llm"
	"grad/protocol"
)

const (
	// DelegateSystemPrompt guides A1 when delegating G2 via bound MCP tools.
	DelegateSystemPrompt = "You are A1. Use delegate_grant to issue one G2 for the assigned B1 under the exact user-confirmed limits. Only use the provided MCP tools."

	// ExecuteSystemPrompt guides B1 when requesting a quote, placing an order, or reconciling via bound MCP tools.
	ExecuteSystemPrompt = "You are B1. Use the bound MCP tools to request one quote, then place one order only if it fits the confirmed cap. Use reconcile_order for an unknown order. Use amountMinor exactly as returned by the quote. No alternative item, quantity or grant."
)

// DraftSuggestion captures the validated strict-JSON procurement draft proposal produced by A1.
type DraftSuggestion struct {
	ProductID       string `json:"productId"`
	Quantity        int64  `json:"quantity"`
	Mode            string `json:"mode"`
	MaxAmountMinor  int64  `json:"maxAmountMinor"`
	DurationMinutes int64  `json:"durationMinutes"`
	Description     string `json:"description"`
	Reply           string `json:"reply"`
}

// BuildDraftPrompt constructs the system and user prompts for the A1 procurement draft dialogue.
func BuildDraftPrompt(message, previousDraftJSON, supplierID, productID, currency string) (string, string) {
	supplier := strings.TrimSpace(supplierID)
	if supplier == "" {
		supplier = "urn:grad:supplier:C"
	}
	defaultProduct := strings.TrimSpace(productID)
	if defaultProduct == "" {
		defaultProduct = "urn:grad:product:P1"
	}
	curr := strings.TrimSpace(currency)
	if curr == "" {
		curr = "CNY"
	}
	prior := strings.TrimSpace(previousDraftJSON)
	if prior == "" {
		prior = "null"
	}

	systemPrompt := fmt.Sprintf(
		"You are A1, a procurement draft assistant for supplier %s. Respond only with one JSON object with fields "+
			"productId, quantity, mode, maxAmountMinor, durationMinutes, description, reply. Use urn:grad:product:P1 (800 yuan) "+
			"or urn:grad:product:P2 (1200 yuan), positive integer quantity, mode RP or BM, and integer amount in minor units (%s). "+
			"Use up to 600 minutes. If omitted default to %s, 1, RP, 100000 and 60 minutes. Keep previous fields that the "+
			"buyer did not ask to change. Write the description and brief reply in the buyer's language. Send a draft for "+
			"confirmation only. You have no authority to register, delegate or place orders.",
		supplier, curr, defaultProduct,
	)
	userPrompt := "Previous draft: " + prior + "\nBuyer message: " + message
	return systemPrompt, userPrompt
}

// SuggestDraft runs the A1 draft dialogue and strictly validates the returned JSON proposal.
func SuggestDraft(
	ctx context.Context,
	cfg llm.RunnerConfig,
	message string,
	previousDraftJSON string,
	supplierID string,
	productID string,
	currency string,
) (DraftSuggestion, error) {
	if strings.TrimSpace(message) == "" {
		return DraftSuggestion{}, protocol.NewError(protocol.ErrCodeInvalidSchema, "buyer message is required")
	}

	systemPrompt, userPrompt := BuildDraftPrompt(message, previousDraftJSON, supplierID, productID, currency)
	if strings.TrimSpace(cfg.SystemPrompt) != "" {
		systemPrompt = cfg.SystemPrompt
	}

	raw, err := RunDraftDialogue(ctx, cfg, systemPrompt, userPrompt)
	if err != nil {
		return DraftSuggestion{}, err
	}

	cleaned := stripJSONFence(raw)
	var out DraftSuggestion
	if err := protocol.DecodeStrictJSON([]byte(cleaned), &out); err != nil {
		return DraftSuggestion{}, protocol.NewError(protocol.ErrCodeInvalidSchema, "invalid draft proposal")
	}
	if strings.TrimSpace(out.ProductID) == "" ||
		out.Quantity < 1 ||
		out.MaxAmountMinor < 1 ||
		out.DurationMinutes < 1 || out.DurationMinutes > 600 ||
		strings.TrimSpace(out.Reply) == "" || len(out.Reply) > 1200 {
		return DraftSuggestion{}, protocol.NewError(protocol.ErrCodeInvalidSchema, "invalid draft proposal")
	}

	switch strings.ToUpper(strings.TrimSpace(out.Mode)) {
	case "RP", protocol.ModeResourcePreauthorized:
		out.Mode = protocol.ModeResourcePreauthorized
	case "BM", protocol.ModeBuyerMandate:
		out.Mode = protocol.ModeBuyerMandate
	default:
		return DraftSuggestion{}, protocol.NewError(protocol.ErrCodeInvalidSchema, "invalid draft proposal")
	}
	return out, nil
}

// DelegateTaskParams holds the domain-agnostic parameters for A1 to delegate G2 via MCP.
type DelegateTaskParams struct {
	TaskID            string `json:"taskId"`
	AuthorizationMode string `json:"authorizationMode"`
	ParentGrantID     string `json:"parentGrantId"`
	ChildGrantID      string `json:"childGrantId"`
	SubjectActor      string `json:"subjectActor,omitempty"`
	SubjectDID        string `json:"subjectDid"`
	MaxAmountMinor    int64  `json:"maxAmountMinor"`
	RemainingDepth    int64  `json:"remainingDepth"`
}

// BuildDelegatePrompt validates DelegateTaskParams and builds the system and user prompts for A1.
func BuildDelegatePrompt(params DelegateTaskParams) (string, string, error) {
	if strings.TrimSpace(params.TaskID) == "" {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "taskId is required")
	}
	if strings.TrimSpace(params.AuthorizationMode) == "" {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "authorizationMode is required")
	}
	if strings.TrimSpace(params.ParentGrantID) == "" {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "parentGrantId is required")
	}
	if strings.TrimSpace(params.ChildGrantID) == "" {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "childGrantId is required")
	}
	if strings.TrimSpace(params.SubjectDID) == "" {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "subjectDid is required")
	}
	if params.MaxAmountMinor <= 0 {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "maxAmountMinor must be positive")
	}
	if params.RemainingDepth < 0 {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "remainingDepth must be non-negative")
	}

	subjectActor := strings.TrimSpace(params.SubjectActor)
	if subjectActor == "" {
		subjectActor = "B1"
	}

	userPrompt := fmt.Sprintf(
		"Inspect the assigned grant and issue G2 to %s (%s) with remainingDepth %d, maxAmountMinor %d. Use parentGrantId %s and grantId %s. Task %s mode %s.",
		subjectActor,
		params.SubjectDID,
		params.RemainingDepth,
		params.MaxAmountMinor,
		params.ParentGrantID,
		params.ChildGrantID,
		params.TaskID,
		params.AuthorizationMode,
	)
	return DelegateSystemPrompt, userPrompt, nil
}

// RunDelegateTask runs A1 grant delegation strictly through mcpServer.
func RunDelegateTask(
	ctx context.Context,
	mcpServer *mcp.Server,
	cfg llm.RunnerConfig,
	params DelegateTaskParams,
) (*llm.RunResult, error) {
	systemPrompt, userPrompt, err := BuildDelegatePrompt(params)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.SystemPrompt) == "" {
		cfg.SystemPrompt = systemPrompt
	}
	return RunAgentTask(ctx, mcpServer, cfg, userPrompt)
}

// ExecuteTaskParams holds the domain-agnostic parameters for B1 quote/order/reconcile execution via MCP.
type ExecuteTaskParams struct {
	TaskID            string `json:"taskId"`
	AuthorizationMode string `json:"authorizationMode"`
	Actor             string `json:"actor,omitempty"`
	GrantID           string `json:"grantId"`
	ProductID         string `json:"productId"`
	Quantity          int64  `json:"quantity"`
	MaxAmountMinor    int64  `json:"maxAmountMinor"`
	Currency          string `json:"currency,omitempty"`
	IdempotencyKey    string `json:"idempotencyKey"`
}

// BuildExecutePrompt validates ExecuteTaskParams and builds the system and user prompts for B1.
func BuildExecutePrompt(params ExecuteTaskParams) (string, string, error) {
	if strings.TrimSpace(params.TaskID) == "" {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "taskId is required")
	}
	if strings.TrimSpace(params.AuthorizationMode) == "" {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "authorizationMode is required")
	}
	if strings.TrimSpace(params.GrantID) == "" {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "grantId is required")
	}
	if strings.TrimSpace(params.ProductID) == "" {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "productId is required")
	}
	if params.Quantity <= 0 {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "quantity must be positive")
	}
	if params.MaxAmountMinor <= 0 {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "maxAmountMinor must be positive")
	}
	if strings.TrimSpace(params.IdempotencyKey) == "" {
		return "", "", protocol.NewError(protocol.ErrCodeInvalidSchema, "idempotencyKey is required")
	}

	actor := strings.TrimSpace(params.Actor)
	if actor == "" {
		actor = "B1"
	}
	currency := strings.TrimSpace(params.Currency)
	if currency == "" {
		currency = "CNY"
	}

	userPrompt := fmt.Sprintf(
		"Task %s, mode %s, as actor %s using grant %s. Quote %d of %s. Amount cap %d minor (%s). If the quote fits, submit the order with quoteId and idempotencyKey %s. Otherwise stop.",
		params.TaskID,
		params.AuthorizationMode,
		actor,
		params.GrantID,
		params.Quantity,
		params.ProductID,
		params.MaxAmountMinor,
		currency,
		params.IdempotencyKey,
	)
	return ExecuteSystemPrompt, userPrompt, nil
}

// RunExecuteTask runs B1 quote/order/reconcile execution strictly through mcpServer.
func RunExecuteTask(
	ctx context.Context,
	mcpServer *mcp.Server,
	cfg llm.RunnerConfig,
	params ExecuteTaskParams,
) (*llm.RunResult, error) {
	systemPrompt, userPrompt, err := BuildExecutePrompt(params)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.SystemPrompt) == "" {
		cfg.SystemPrompt = systemPrompt
	}
	return RunAgentTask(ctx, mcpServer, cfg, userPrompt)
}

func stripJSONFence(raw string) string {
	cleaned := strings.TrimSpace(raw)
	if strings.HasPrefix(cleaned, "```json") && strings.HasSuffix(cleaned, "```") {
		cleaned = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(cleaned, "```json"), "```"))
	} else if strings.HasPrefix(cleaned, "```") && strings.HasSuffix(cleaned, "```") {
		cleaned = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(cleaned, "```"), "```"))
	}
	return cleaned
}
