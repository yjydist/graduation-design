package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"grad/platform/internal/httpx"
	"grad/protocol"
)

const (
	defaultGatewayBaseURL = "https://c.local"
	defaultHTTPTimeout    = 30 * time.Second
)

// ChallengeRequest models POST /v1/auth/challenges.
type ChallengeRequest struct {
	Actor       string `json:"actor"`
	TaskID      string `json:"taskId"`
	RequestHash string `json:"requestHash"`
}

// ChallengeResponse models 201 Created from POST /v1/auth/challenges.
type ChallengeResponse struct {
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	Audience    string `json:"audience"`
	IssuedAt    int64  `json:"issuedAt"`
	ExpiresAt   int64  `json:"expiresAt"`
}

// QuotePayload is the immutable quote payload returned by quote.read.
type QuotePayload struct {
	QuoteID          string `json:"quoteId"`
	TaskID           string `json:"taskId"`
	Actor            string `json:"actor"`
	SupplierID       string `json:"supplierId"`
	ProductID        string `json:"productId"`
	Quantity         int64  `json:"quantity"`
	Currency         string `json:"currency"`
	UnitPriceMinor   int64  `json:"unitPriceMinor"`
	TotalAmountMinor int64  `json:"totalAmountMinor"`
	IssuedAt         int64  `json:"issuedAt"`
	ValidUntil       int64  `json:"validUntil"`
}

// OrderPayload is the immutable order payload returned by order.create.
type OrderPayload struct {
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

// ExecuteResponse models 200 OK from POST /v1/access/execute.
type ExecuteResponse struct {
	DecisionID string        `json:"decisionId"`
	Code       string        `json:"code"`
	Quote      *QuotePayload `json:"quote,omitempty"`
	Order      *OrderPayload `json:"order,omitempty"`
}

// OrderOutcomeCaseRequest models POST /v1/internal/order-outcome-cases.
type OrderOutcomeCaseRequest struct {
	CaseID       string                 `json:"caseId"`
	SendRevision int64                  `json:"sendRevision"`
	DeploymentID string                 `json:"deploymentId"`
	Request      protocol.AccessRequest `json:"request"`
	RequestHash  string                 `json:"requestHash"`
	ChallengeIDs []string               `json:"challengeIds"`
}

// OrderOutcomeCaseResponse models 202 Accepted from POST /v1/internal/order-outcome-cases.
type OrderOutcomeCaseResponse struct {
	CaseID         string   `json:"caseId"`
	SendRevision   int64    `json:"sendRevision"`
	DeploymentID   string   `json:"deploymentId"`
	Actor          string   `json:"actor"`
	TaskID         string   `json:"taskId"`
	IdempotencyKey string   `json:"idempotencyKey"`
	RequestHash    string   `json:"requestHash"`
	ChallengeIDs   []string `json:"challengeIds"`
	Status         string   `json:"status"`
}

// AuditOrderOutcomeRequest models POST /v1/audit/order-outcomes.
type AuditOrderOutcomeRequest struct {
	CaseID         string                  `json:"caseId,omitempty"`
	DeploymentID   string                  `json:"deploymentId,omitempty"`
	Request        *protocol.AccessRequest `json:"request,omitempty"`
	Actor          string                  `json:"actor,omitempty"`
	TaskID         string                  `json:"taskId,omitempty"`
	IdempotencyKey string                  `json:"idempotencyKey,omitempty"`
	RequestHash    string                  `json:"requestHash,omitempty"`
	ChallengeIDs   []string                `json:"challengeIds,omitempty"`
}

// AuditOrderOutcomeResponse models 200 OK from POST /v1/audit/order-outcomes.
type AuditOrderOutcomeResponse struct {
	CaseID             string              `json:"caseId"`
	CheckNo            int64               `json:"checkNo"`
	SendRevision       int64               `json:"sendRevision"`
	DeploymentID       string              `json:"deploymentId"`
	Actor              string              `json:"actor"`
	TaskID             string              `json:"taskId"`
	IdempotencyKey     string              `json:"idempotencyKey"`
	RequestHash        string              `json:"requestHash"`
	Outcome            string              `json:"outcome"`
	OrderID            *string             `json:"orderId"`
	CreationDecisionID *string             `json:"creationDecisionId"`
	DenialDecisionIDs  []string            `json:"denialDecisionIds,omitempty"`
	HistoricalStatus   string              `json:"historicalStatus"`
	HistoricalReason   string              `json:"historicalReason,omitempty"`
	DecisionBlock      *int64              `json:"decisionBlock,omitempty"`
	RevocationBlock    *int64              `json:"revocationBlock,omitempty"`
	LockedChallengeIDs []string            `json:"lockedChallengeIds"`
	VerifierID         string              `json:"verifierId,omitempty"`
	AuditAt            int64               `json:"auditAt"`
	Receipt            OrderOutcomeReceipt `json:"receipt"`
}

// GatewayError captures a structured non-2xx error envelope returned by gateway endpoints.
type GatewayError struct {
	StatusCode int
	httpx.ErrorEnvelope
}

// Error implements the error interface.
func (e *GatewayError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return fmt.Sprintf("gateway HTTP %d %s: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("gateway HTTP %d %s", e.StatusCode, e.Code)
}

// ParseGatewayError decodes a gateway ErrorEnvelope or synthesizes a fallback HTTP_ERROR.
func ParseGatewayError(status int, raw []byte) *GatewayError {
	var env httpx.ErrorEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Code == "" {
		return &GatewayError{
			StatusCode: status,
			ErrorEnvelope: httpx.ErrorEnvelope{
				Code:    "HTTP_ERROR",
				Message: strings.TrimSpace(string(raw)),
			},
		}
	}
	return &GatewayError{
		StatusCode:    status,
		ErrorEnvelope: env,
	}
}

// GatewayClientConfig configures a pure HTTP/in-process GatewayClient without importing gateway internals.
type GatewayClientConfig struct {
	BaseURL        string
	ReceiptBaseURL string
	HTTPClient     *http.Client
	HTTPHandler    http.Handler
	RecoveryClient *http.Client
	AuditClient    *http.Client
	ReceiptClient  *http.Client
}

// GatewayClient invokes gateway REST and role-bound recovery/audit endpoints over HTTP or an in-process http.Handler.
type GatewayClient struct {
	baseURL        string
	receiptBaseURL string
	httpClient     *http.Client
	httpHandler    http.Handler
	recoveryClient *http.Client
	auditClient    *http.Client
	receiptClient  *http.Client
}

// NewGatewayClient constructs a GatewayClient from cfg.
func NewGatewayClient(cfg GatewayClientConfig) *GatewayClient {
	client := cfg.HTTPClient
	if client == nil && cfg.HTTPHandler == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &GatewayClient{
		baseURL:        strings.TrimRight(cfg.BaseURL, "/"),
		receiptBaseURL: strings.TrimRight(cfg.ReceiptBaseURL, "/"),
		httpClient:     client,
		httpHandler:    cfg.HTTPHandler,
		recoveryClient: cfg.RecoveryClient,
		auditClient:    cfg.AuditClient,
		receiptClient:  cfg.ReceiptClient,
	}
}

// HasReceiptClient reports whether an explicit role-bound HTTP client is configured for receipt delivery.
func (c *GatewayClient) HasReceiptClient() bool {
	return c != nil && c.receiptClient != nil
}

// CreateChallenge calls POST /v1/auth/challenges.
func (c *GatewayClient) CreateChallenge(ctx context.Context, req ChallengeRequest) (*ChallengeResponse, int, *GatewayError, error) {
	status, raw, err := c.doPublicJSON(ctx, http.MethodPost, "/v1/auth/challenges", req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("request challenge: %w", err)
	}
	if status != http.StatusCreated {
		return nil, status, ParseGatewayError(status, raw), nil
	}
	var resp ChallengeResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, status, nil, fmt.Errorf("decode challenge response: %w", err)
	}
	return &resp, status, nil, nil
}

// ExecuteAccess calls POST /v1/access/execute with a signed AccessEvidencePackage.
func (c *GatewayClient) ExecuteAccess(ctx context.Context, pkg protocol.AccessEvidencePackage) (*ExecuteResponse, int, *GatewayError, error) {
	status, raw, err := c.doPublicJSON(ctx, http.MethodPost, "/v1/access/execute", pkg)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("call /v1/access/execute: %w", err)
	}
	if status != http.StatusOK {
		return nil, status, ParseGatewayError(status, raw), nil
	}
	var resp ExecuteResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, status, nil, fmt.Errorf("decode execute response: %w", err)
	}
	return &resp, status, nil, nil
}

// RegisterOrderOutcomeCase calls POST /v1/internal/order-outcome-cases over the B_RECOVERY channel.
func (c *GatewayClient) RegisterOrderOutcomeCase(ctx context.Context, req OrderOutcomeCaseRequest) (*OrderOutcomeCaseResponse, int, *GatewayError, error) {
	status, raw, err := c.doServiceJSON(ctx, c.recoveryClient, c.serviceBaseURL(), "/v1/internal/order-outcome-cases", req)
	if err != nil {
		return nil, 0, nil, err
	}
	if status != http.StatusAccepted {
		return nil, status, ParseGatewayError(status, raw), nil
	}
	var resp OrderOutcomeCaseResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, status, nil, fmt.Errorf("decode order-outcome-case response: %w", err)
	}
	return &resp, status, nil, nil
}

// AuditOrderOutcome calls POST /v1/audit/order-outcomes over the C_AUDITOR channel.
func (c *GatewayClient) AuditOrderOutcome(ctx context.Context, req AuditOrderOutcomeRequest) (*AuditOrderOutcomeResponse, int, *GatewayError, error) {
	status, raw, err := c.doServiceJSON(ctx, c.auditClient, c.serviceBaseURL(), "/v1/audit/order-outcomes", req)
	if err != nil {
		return nil, 0, nil, err
	}
	if status != http.StatusOK {
		return nil, status, ParseGatewayError(status, raw), nil
	}
	var resp AuditOrderOutcomeResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, status, nil, fmt.Errorf("decode audit order-outcome response: %w", err)
	}
	return &resp, status, nil, nil
}

// DeliverOrderOutcomeReceipt calls POST /v1/internal/order-outcome-receipts over the C_AUDIT_SERVICE channel.
func (c *GatewayClient) DeliverOrderOutcomeReceipt(ctx context.Context, receipt OrderOutcomeReceipt) (*OrderOutcomeReceiptResponse, int, *GatewayError, error) {
	base := c.receiptBaseURL
	if base == "" {
		base = c.serviceBaseURL()
	}
	status, raw, err := c.doServiceJSON(ctx, c.receiptClient, base, "/v1/internal/order-outcome-receipts", receipt)
	if err != nil {
		return nil, 0, nil, err
	}
	if status != http.StatusOK {
		return nil, status, ParseGatewayError(status, raw), nil
	}
	var resp OrderOutcomeReceiptResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, status, nil, fmt.Errorf("decode order-outcome-receipt response: %w", err)
	}
	return &resp, status, nil, nil
}

func (c *GatewayClient) serviceBaseURL() string {
	if c.baseURL != "" {
		return c.baseURL
	}
	return defaultGatewayBaseURL
}

func (c *GatewayClient) doPublicJSON(ctx context.Context, method, path string, payload any) (int, []byte, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	if c.httpHandler != nil {
		req := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(httpx.HeaderRequestID, httpx.NewRequestID())
		rec := httptest.NewRecorder()
		c.httpHandler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes(), nil
	}
	if c.baseURL == "" {
		return 0, nil, errors.New("gateway BaseURL or HTTPHandler is required")
	}
	if c.httpClient == nil {
		return 0, nil, errors.New("gateway HTTPClient is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httpx.HeaderRequestID, httpx.NewRequestID())
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, raw, nil
}

// doServiceJSON uses a host-provisioned role-bound HTTP channel; callers cannot choose its identity.
func (c *GatewayClient) doServiceJSON(ctx context.Context, client *http.Client, baseURL, path string, payload any) (int, []byte, error) {
	if client == nil {
		return 0, nil, errors.New("authenticated service client is not configured")
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httpx.HeaderRequestID, httpx.NewRequestID())
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, raw, nil
}
