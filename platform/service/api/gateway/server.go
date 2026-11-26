// Package gateway exposes the L3 HTTP/mTLS REST adapter over the L2 supplier C gateway domain service.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	domgw "grad/platform/core/domain/gateway"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/protocol"
)

// ErrorBody is the canonical structured error envelope returned by gateway HTTP endpoints.
type ErrorBody = httpx.ErrorEnvelope

type domainService interface {
	CreateChallenge(ctx context.Context, req domgw.ChallengeRequest) (*domgw.ChallengeResponse, error)
	UpdateContext(ctx context.Context, taskID string, req domgw.ContextUpdateRequest) (*domgw.ContextResponse, error)
	ExecuteAccess(ctx context.Context, requestID string, rawBody []byte) (*domgw.ExecuteResponse, error)
	GetDecision(ctx context.Context, id string) (*domgw.DecisionRecord, error)
	CheckReady(ctx context.Context) (*domgw.ReadyStatus, error)
	RegisterOrderOutcomeCase(ctx context.Context, caller domgw.CallerIdentity, req domgw.OrderOutcomeCaseRequest) (*domgw.OrderOutcomeCaseResponse, error)
	AuditOrderOutcome(ctx context.Context, caller domgw.CallerIdentity, req domgw.AuditOrderOutcomeRequest) (*domgw.AuditOrderOutcomeResponse, error)
	DeliverReceipt(ctx context.Context, entry domgw.OutboxEntry, send domgw.ReceiptSender) error
	DeliverPendingReceipts(ctx context.Context, send domgw.ReceiptSender) (int, error)
}

// Server serves REST endpoints for supplier C's resource access gateway over an L2 domain Service.
type Server struct {
	svc     *domgw.Service
	ops     domainService
	mux     *http.ServeMux
	handler http.Handler
}

// NewServer constructs a configured gateway HTTP Server backed by svc.
func NewServer(svc *domgw.Service) (*Server, error) {
	if svc == nil {
		return nil, fmt.Errorf("gateway domain service is required")
	}
	return newServerWithOps(svc, svc), nil
}

func newServerWithOps(svc *domgw.Service, ops domainService) *Server {
	s := &Server{
		svc: svc,
		ops: ops,
		mux: http.NewServeMux(),
	}
	s.mux.HandleFunc("POST /v1/auth/challenges", s.handleCreateChallenge)
	s.mux.HandleFunc("POST /v1/contexts/{taskId}", s.handleUpdateContext)
	s.mux.HandleFunc("POST /v1/access/execute", s.handleExecute)
	s.mux.HandleFunc("GET /v1/decisions/{id}", s.handleGetDecision)
	s.mux.HandleFunc("GET /v1/health/ready", s.handleReady)
	s.mux.HandleFunc("POST /v1/internal/order-outcome-cases", s.handleRegisterOrderOutcomeCase)
	s.mux.HandleFunc("POST /v1/audit/order-outcomes", s.handleAuditOrderOutcome)
	s.handler = httpx.WithRequestID(s.mux)
	return s
}

// Service returns the underlying L2 gateway domain service.
func (s *Server) Service() *domgw.Service {
	return s.svc
}

// Handler returns the HTTP handler for the gateway wrapped with X-Request-Id middleware.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// SendHTTPReceipt POSTs a reconciliation receipt with X-Request-Id to targetURL via client,
// validates HTTP 200 OK, decodes the bounded acknowledgement envelope, and verifies canonical
// receipt echo binding before returning the verified acknowledgement.
func SendHTTPReceipt(
	ctx context.Context,
	client *http.Client,
	targetURL string,
	receipt domgw.OrderOutcomeReceipt,
) (*domgw.OrderOutcomeReceiptResponse, error) {
	if client == nil {
		return nil, fmt.Errorf("authenticated receipt client is required")
	}
	if strings.TrimSpace(targetURL) == "" {
		return nil, fmt.Errorf("receipt endpoint URL is required")
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(httpx.HeaderRequestID, httpx.NewRequestID())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("receipt delivery HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, domgw.MaxExecuteBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > domgw.MaxExecuteBodyBytes {
		return nil, fmt.Errorf("receipt acknowledgement exceeds %d bytes", domgw.MaxExecuteBodyBytes)
	}
	var ack domgw.OrderOutcomeReceiptResponse
	if err := json.Unmarshal(body, &ack); err != nil {
		return nil, err
	}
	if err := domgw.VerifyReceiptEcho(receipt, ack.Receipt); err != nil {
		return nil, err
	}
	return &ack, nil
}

// NewHTTPReceiptSender constructs an outbound HTTP domgw.ReceiptSender backed by SendHTTPReceipt.
func NewHTTPReceiptSender(client *http.Client, targetURL string) domgw.ReceiptSender {
	return func(ctx context.Context, receipt domgw.OrderOutcomeReceipt) error {
		_, err := SendHTTPReceipt(ctx, client, targetURL, receipt)
		return err
	}
}

// DeliverReceipt delivers one committed outbox entry to targetURL via client.
func (s *Server) DeliverReceipt(ctx context.Context, client *http.Client, targetURL string, entry domgw.OutboxEntry) error {
	if client == nil {
		return fmt.Errorf("authenticated receipt client is required")
	}
	if strings.TrimSpace(targetURL) == "" {
		return fmt.Errorf("receipt endpoint URL is required")
	}
	return s.ops.DeliverReceipt(ctx, entry, NewHTTPReceiptSender(client, targetURL))
}

// DeliverPendingReceipts delivers all undelivered outbox receipts for this server's
// deployment to targetURL via client.
func (s *Server) DeliverPendingReceipts(ctx context.Context, client *http.Client, targetURL string) (int, error) {
	if client == nil {
		return 0, fmt.Errorf("authenticated receipt client is required")
	}
	if strings.TrimSpace(targetURL) == "" {
		return 0, fmt.Errorf("receipt endpoint URL is required")
	}
	return s.ops.DeliverPendingReceipts(ctx, NewHTTPReceiptSender(client, targetURL))
}

func (s *Server) handleCreateChallenge(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONBody(r, domgw.MaxExecuteBodyBytes)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	var req domgw.ChallengeRequest
	if err := protocol.DecodeStrictJSON(body, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	resp, err := s.ops.CreateChallenge(r.Context(), req)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleUpdateContext(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("taskId")
	if strings.TrimSpace(taskID) == "" {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, "taskId path parameter is required")
		return
	}
	body, err := readJSONBody(r, domgw.MaxExecuteBodyBytes)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	var req domgw.ContextUpdateRequest
	if err := protocol.DecodeStrictJSON(body, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	resp, err := s.ops.UpdateContext(r.Context(), taskID, req)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	body, err := readJSONBody(r, domgw.MaxExecuteBodyBytes)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	resp, err := s.ops.ExecuteAccess(r.Context(), reqID, body)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetDecision(w http.ResponseWriter, r *http.Request) {
	decID := r.PathValue("id")
	if strings.TrimSpace(decID) == "" {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, "decision id is required")
		return
	}
	rec, err := s.ops.GetDecision(r.Context(), decID)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rec)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	status, err := s.ops.CheckReady(r.Context())
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, status)
}

func (s *Server) handleRegisterOrderOutcomeCase(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONBody(r, domgw.MaxExecuteBodyBytes)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	var req domgw.OrderOutcomeCaseRequest
	if err := protocol.DecodeStrictJSON(body, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	resp, err := s.ops.RegisterOrderOutcomeCase(r.Context(), extractCallerIdentity(r), req)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, resp)
}

func (s *Server) handleAuditOrderOutcome(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONBody(r, domgw.MaxExecuteBodyBytes)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	var req domgw.AuditOrderOutcomeRequest
	if err := protocol.DecodeStrictJSON(body, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	resp, err := s.ops.AuditOrderOutcome(r.Context(), extractCallerIdentity(r), req)
	if err != nil {
		writeMappedError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func extractCallerIdentity(r *http.Request) domgw.CallerIdentity {
	id, ok := mtls.Caller(r)
	if !ok {
		return domgw.CallerIdentity{}
	}
	return domgw.CallerIdentity{
		Role: id.Role,
		DID:  id.DID,
	}
}

func readJSONBody(r *http.Request, maxBytes int64) ([]byte, error) {
	body, err := httpx.ReadBoundedBody(r, maxBytes)
	if err != nil {
		switch {
		case errors.Is(err, httpx.ErrUnsupportedMediaType):
			return nil, protocol.WrapError(protocol.ErrCodeUnsupportedMediaType, "unsupported media type", err)
		case errors.Is(err, httpx.ErrPayloadTooLarge):
			return nil, protocol.WrapError(protocol.ErrCodePayloadTooLarge, fmt.Sprintf("request body exceeds %d bytes", maxBytes), err)
		default:
			return nil, protocol.WrapError(protocol.ErrCodeInvalidSchema, "failed reading request body", err)
		}
	}
	return body, nil
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code string, decisionID *string, msg string) {
	httpx.WriteError(w, status, httpx.RequestID(r), code, decisionID, msg)
}

func writeMappedError(w http.ResponseWriter, r *http.Request, err error) {
	decisionID := domgw.DecisionIDOf(err)
	code := protocol.CodeOf(err)
	if code == "" {
		code = protocol.ErrCodeInvalidSchema
	}
	if errors.Is(err, domgw.ErrDecisionNotFound) {
		writeError(w, r, http.StatusNotFound, code, decisionID, err.Error())
		return
	}
	writeError(w, r, httpStatusForCode(code), code, decisionID, err.Error())
}

func httpStatusForCode(code string) int {
	switch code {
	case protocol.ErrCodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case protocol.ErrCodeUnsupportedMediaType:
		return http.StatusUnsupportedMediaType
	case protocol.ErrCodeInvalidSchema, protocol.ErrCodeInvalidDisclosure, protocol.ErrCodeRecoveryProofInvalid:
		return http.StatusBadRequest
	case protocol.ErrCodeSignatureInvalid,
		protocol.ErrCodeHolderMismatch,
		protocol.ErrCodeDIDDocumentMismatch,
		protocol.ErrCodeDIDKeyPurposeInvalid,
		protocol.ErrCodeBindingMismatch,
		protocol.ErrCodeChallengeMismatch,
		protocol.ErrCodeChallengeUnknown,
		protocol.ErrCodeChallengeExpired:
		return http.StatusUnauthorized
	case protocol.ErrCodeChallengeReplay,
		protocol.ErrCodeIdempotencyConflict,
		protocol.ErrCodeStateChanged,
		protocol.ErrCodeDeliveryConflict,
		protocol.ErrCodeQuoteExpired,
		protocol.ErrCodeAmountMismatch,
		protocol.ErrCodeLinkStateConflict,
		protocol.ErrCodeIdentityStateConflict,
		protocol.ErrCodeTaskStateConflict,
		protocol.ErrCodeGrantStateConflict:
		return http.StatusConflict
	case protocol.ErrCodePolicyDenied,
		protocol.ErrCodeSupplierPolicyDenied,
		protocol.ErrCodeRootAuthorityInvalid,
		protocol.ErrCodePurchasingAuthorityInvalid,
		protocol.ErrCodeDelegationExpansion,
		protocol.ErrCodePathInvalid,
		protocol.ErrCodeAuthorizationModeMismatch,
		protocol.ErrCodeAncestorInactive,
		protocol.ErrCodeAmountLimitExceeded,
		protocol.ErrCodeQuoteScopeMismatch,
		protocol.ErrCodeTaskScopeMismatch,
		protocol.ErrCodeTaskInactive,
		protocol.ErrCodeGrantExpired,
		protocol.ErrCodeGrantInactive,
		protocol.ErrCodeGrantChainInvalid,
		protocol.ErrCodeCredentialStatusInvalid,
		protocol.ErrCodeDomainCertificationInvalid,
		protocol.ErrCodeDomainInactive,
		protocol.ErrCodeKeyVersionStale,
		protocol.ErrCodeIdentityInactive,
		protocol.ErrCodeIdentityManagementForbidden,
		protocol.ErrCodeIdentityRecoveryForbidden,
		protocol.ErrCodeTrustManagementForbidden,
		protocol.ErrCodeAuditForbidden,
		protocol.ErrCodeIssuerScopeInvalid,
		protocol.ErrCodeLinkApprovalForbidden,
		protocol.ErrCodeLinkProposalMismatch,
		protocol.ErrCodeLinkProofInvalid:
		return http.StatusForbidden
	case protocol.ErrCodeStateUnavailable,
		protocol.ErrCodeStateStale,
		protocol.ErrCodeMaterialNotSynced,
		protocol.ErrCodeContextStale,
		protocol.ErrCodePriceUnavailable:
		return http.StatusServiceUnavailable
	default:
		if strings.Contains(code, "INVALID") {
			return http.StatusBadRequest
		}
		return http.StatusInternalServerError
	}
}
