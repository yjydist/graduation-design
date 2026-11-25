// Package registry provides the L3 HTTP/mTLS API adapter over the L2
// management operation domain service.
package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	domreg "grad/platform/core/domain/registry"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/protocol"
	preg "grad/protocol/registry"
)

type operationService interface {
	HasBackend() bool
	ResolveManagementCaller(fingerprint, mspID string) (preg.Management, bool)
	IsOperationAuditor(fingerprint, mspID string) bool
	Accept(ctx context.Context, opKey string, caller preg.Management, method string, input json.RawMessage, triggerBackend bool) (*domreg.OperationView, error)
	Operation(ctx context.Context, caller preg.Management, opID string) (*domreg.OperationView, error)
}

// Server adapts L2 core/domain/registry.Service to the management HTTP/mTLS API.
type Server struct {
	svc *domreg.Service
	ops operationService
}

// NewServer constructs a Server backed by svc.
func NewServer(svc *domreg.Service) *Server {
	s := &Server{svc: svc}
	if svc != nil {
		s.ops = svc
	}
	return s
}

func newServerWithOps(ops operationService) *Server {
	return &Server{ops: ops}
}

// Handler exposes POST /v1/management/{method} and GET /v1/operations/{operationId}
// wrapped with X-Request-Id propagation and unified httpx error envelopes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/operations/{operationId...}", s.handleGetOperation)
	mux.HandleFunc("POST /v1/management/{method}", s.handlePostManagement)
	return httpx.WithRequestID(mux)
}

func (s *Server) resolveCaller(w http.ResponseWriter, r *http.Request, reqID string) (preg.Management, bool) {
	id, authenticated := mtls.Caller(r)
	if !authenticated || id.Fingerprint == "" {
		httpx.WriteError(w, http.StatusForbidden, reqID, preg.ErrCodeIdentityManagementForbidden, nil, "verified mTLS management caller required")
		return preg.Management{}, false
	}
	if s == nil || s.ops == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, reqID, preg.ErrCodeStateUnavailable, nil, "registry service unavailable")
		return preg.Management{}, false
	}
	if caller, ok := s.ops.ResolveManagementCaller(id.Fingerprint, id.MSPID); ok {
		return caller, true
	}
	if s.ops.IsOperationAuditor(id.Fingerprint, id.MSPID) {
		return preg.Management{MSPID: id.MSPID, CertificateSHA256: id.Fingerprint}, true
	}
	httpx.WriteError(w, http.StatusForbidden, reqID, preg.ErrCodeIdentityManagementForbidden, nil, "verified mTLS management caller required")
	return preg.Management{}, false
}

func (s *Server) handleGetOperation(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	caller, ok := s.resolveCaller(w, r, reqID)
	if !ok {
		return
	}
	opID := r.PathValue("operationId")
	if opID == "" {
		httpx.WriteError(w, http.StatusBadRequest, reqID, preg.ErrCodeInvalidSchema, nil, "missing operationId")
		return
	}
	view, err := s.ops.Operation(r.Context(), caller, opID)
	if err != nil {
		if protocol.HasCode(err, preg.ErrCodeIdentityManagementForbidden) {
			httpx.WriteError(w, http.StatusForbidden, reqID, preg.ErrCodeIdentityManagementForbidden, nil, "operation query forbidden")
			return
		}
		status, code := statusForError(err)
		httpx.WriteError(w, status, reqID, code, nil, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

func (s *Server) handlePostManagement(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	caller, ok := s.resolveCaller(w, r, reqID)
	if !ok {
		return
	}
	if !s.ops.HasBackend() {
		httpx.WriteError(w, http.StatusServiceUnavailable, reqID, preg.ErrCodeStateUnavailable, nil, "management submission backend unavailable")
		return
	}
	body, err := httpx.ReadBoundedBody(r, protocol.MaxJSONBytes)
	if err != nil {
		switch {
		case errors.Is(err, httpx.ErrUnsupportedMediaType):
			httpx.WriteError(w, http.StatusUnsupportedMediaType, reqID, preg.ErrCodeUnsupportedMediaType, nil, err.Error())
		case errors.Is(err, httpx.ErrPayloadTooLarge):
			httpx.WriteError(w, http.StatusRequestEntityTooLarge, reqID, preg.ErrCodePayloadTooLarge, nil, err.Error())
		default:
			httpx.WriteError(w, http.StatusBadRequest, reqID, preg.ErrCodeInvalidSchema, nil, err.Error())
		}
		return
	}
	if len(bytes.TrimSpace(body)) == 0 || !json.Valid(body) {
		httpx.WriteError(w, http.StatusBadRequest, reqID, preg.ErrCodeInvalidSchema, nil, "invalid JSON request body")
		return
	}
	method := r.PathValue("method")
	opKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	view, err := s.ops.Accept(r.Context(), opKey, caller, method, json.RawMessage(body), true)
	if err != nil {
		status, code := statusForError(err)
		httpx.WriteError(w, status, reqID, code, nil, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, view)
}

func statusForError(err error) (int, string) {
	code := protocol.CodeOf(err)
	switch code {
	case preg.ErrCodeInvalidSchema,
		preg.ErrCodeInvalidStructure:
		return http.StatusBadRequest, code

	case preg.ErrCodeIdentityManagementForbidden,
		preg.ErrCodeTrustManagementForbidden,
		preg.ErrCodeIdentityRecoveryForbidden,
		preg.ErrCodeRecoveryProofInvalid,
		preg.ErrCodeRegistrationProofInvalid,
		preg.ErrCodeSignatureInvalid,
		preg.ErrCodeChallengeUnknown,
		preg.ErrCodeChallengeReplay,
		preg.ErrCodeChallengeMismatch,
		preg.ErrCodeChallengeExpired,
		preg.ErrCodeDIDDocumentMismatch,
		preg.ErrCodeAuditForbidden,
		preg.ErrCodeUnauthorized,
		preg.ErrCodePolicyDenied,
		preg.ErrCodeLinkApprovalForbidden:
		return http.StatusForbidden, code

	case preg.ErrCodeOperationUnknown:
		return http.StatusNotFound, code

	case preg.ErrCodeIdempotencyConflict,
		preg.ErrCodeStateChanged,
		preg.ErrCodeDeliveryConflict,
		preg.ErrCodeIdentityStateConflict,
		preg.ErrCodeTaskStateConflict,
		preg.ErrCodeGrantStateConflict,
		preg.ErrCodeLinkStateConflict,
		preg.ErrCodeIDAlreadyUsed,
		preg.ErrCodeAlreadyRevoked,
		preg.ErrCodeInvalidState:
		return http.StatusConflict, code

	case preg.ErrCodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge, code

	case preg.ErrCodeUnsupportedMediaType:
		return http.StatusUnsupportedMediaType, code

	case preg.ErrCodeStateUnavailable,
		preg.ErrCodeStateStale,
		preg.ErrCodeMaterialNotSynced:
		return http.StatusServiceUnavailable, code

	default:
		if code == "" {
			code = preg.ErrCodeStateUnavailable
		}
		return http.StatusServiceUnavailable, code
	}
}
