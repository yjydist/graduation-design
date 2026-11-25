package interdomain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"time"

	"grad/platform/core/domain/evidence"
	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/domain/procurement"
	"grad/platform/core/domain/wallet"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	apigw "grad/platform/service/api/gateway"
	"grad/protocol"
	"grad/protocol/registry"
)

const (
	// DefaultAuditorDID is used when ServerConfig.AuditorDID is omitted.
	DefaultAuditorDID = "did:web:c.local:auditor"

	workbenchContextSourceID = "C-workbench-demo-environment"
	maxServiceRequestBytes   = 512 * 1024
)

// ServerConfig configures an L3 inter-domain mTLS HTTP Server for Domain A, B, or C.
type ServerConfig struct {
	DeploymentID string
	DomainID     string
	ActorB1DID   string
	AuditorDID   string
	Peers        map[string]PeerBinding
	DIDDocs      map[string][]byte
	Procurement  *procurement.Service
	Dispatch     *procurement.DispatchService
	Evidence     *evidence.Service
	Gateway      *apigw.Server
	Wallet       *wallet.WalletContext
}

// Server exposes authenticated inter-domain mTLS routes for DID documents, Domain B dispatch/receipt
// services, and Domain C root/context/evidence/gateway/reconciliation services.
type Server struct {
	cfg            ServerConfig
	receiptHandler http.Handler

	// Test-only hooks allowing offline verification of reconcileFromB without PostgreSQL.
	hasOrderOutcomeCase func(ctx context.Context, caseID, actor, taskID, requestHash string) (bool, error)
	gatewayHandler      http.Handler
}

// NewServer validates cfg and constructs an inter-domain Server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.DomainID != "A" && cfg.DomainID != "B" && cfg.DomainID != "C" {
		return nil, fmt.Errorf("interdomain server requires domainId A, B, or C (got %q)", cfg.DomainID)
	}
	if cfg.AuditorDID == "" {
		cfg.AuditorDID = DefaultAuditorDID
	}
	cfg.Peers = maps.Clone(cfg.Peers)
	if cfg.DIDDocs != nil {
		cloned := make(map[string][]byte, len(cfg.DIDDocs))
		for k, v := range cfg.DIDDocs {
			cloned[k] = bytes.Clone(v)
		}
		cfg.DIDDocs = cloned
	}
	s := &Server{cfg: cfg}
	if cfg.Wallet != nil {
		s.receiptHandler = NewWalletReceiptHandler(cfg.Wallet)
	}
	return s, nil
}

// Handler builds the domain-scoped mTLS HTTP handler with peer pinning and X-Request-Id middleware.
func (s *Server) Handler() (http.Handler, error) {
	mux := http.NewServeMux()
	localDIDHost := strings.ToLower(s.cfg.DomainID) + ".local"
	for did, doc := range s.cfg.DIDDocs {
		u, err := protocol.ParseDIDWebURL(did)
		if err != nil {
			return nil, err
		}
		if u.Host != localDIDHost {
			continue
		}
		raw := bytes.Clone(doc)
		mux.HandleFunc("GET "+localDIDHost+u.Path, s.fromDomain("C", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/did+json")
			_, _ = w.Write(raw)
		}))
	}

	switch s.cfg.DomainID {
	case "B":
		mux.HandleFunc("POST "+PathDispatch, s.fromDomain("A", s.handleAcceptDispatch))
		mux.HandleFunc("GET "+PathDispatch+"/{runId}", s.fromDomain("A", s.handleDispatchStatus))
		mux.HandleFunc("POST "+PathDispatch+"/{runId}/quote", s.fromDomain("A", s.handleDispatchQuote))
		mux.HandleFunc("POST "+PathDispatch+"/{runId}/order", s.fromDomain("A", s.handleDispatchOrder))
		mux.HandleFunc("POST "+PathProbe, s.fromDomain("A", s.handleRunProbe))
		mux.HandleFunc("POST "+PathOrderOutcomeReceipts, s.fromDomain("C", s.handleWalletReceipt))
	case "C":
		mux.HandleFunc("POST "+PathRoot, s.fromDomain("A", s.handleRemoteRoot))
		mux.HandleFunc("GET "+PathRootAmountPrefix+"{taskId}", s.fromDomain("A", s.handleRemoteRootAmount))
		mux.HandleFunc("POST "+PathRootReceipt, s.fromDomain("A", s.handleRemoteRootReceipt))
		mux.HandleFunc("POST "+PathContext, s.fromDomain("B", s.handleRemoteContext))
		mux.HandleFunc("GET "+PathEvidencePrefix+"{taskId}", s.fromDomain("A", s.handleRemoteEvidence))
		mux.HandleFunc("POST /v1/auth/challenges", s.fromDomain("B", s.handleGatewayPassthrough))
		mux.HandleFunc("POST /v1/access/execute", s.fromDomain("B", s.handleGatewayPassthrough))
		mux.HandleFunc("POST /v1/internal/order-outcome-cases", s.fromDomain("B", s.handleGatewayPassthrough))
		mux.HandleFunc("POST /v1/audit/order-outcomes", s.fromDomain("B", s.reconcileFromB))
	}

	return httpx.WithRequestID(mux), nil
}

func (s *Server) fromDomain(domain string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := mtls.Caller(r)
		role, did := TransportRole(domain)
		peer, hasPeer := s.cfg.Peers[domain]
		if !ok || !hasPeer || peer.Fingerprint == "" ||
			id.Fingerprint != peer.Fingerprint || id.Role != role || id.DID != did {
			writeServiceError(w, r, http.StatusForbidden, registry.ErrCodeBindingMismatch, "internal service binding rejected")
			return
		}
		next(w, r)
	}
}

// --- Domain B handlers ---

func (s *Server) handleAcceptDispatch(w http.ResponseWriter, r *http.Request) {
	var in procurement.DispatchRequest
	if !readServiceJSON(w, r, &in) {
		return
	}
	if s.cfg.Dispatch == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "dispatch service unavailable")
		return
	}
	view, replayed, err := s.cfg.Dispatch.AcceptDispatch(r.Context(), in)
	if err != nil {
		if protocol.HasCode(err, registry.ErrCodeBindingMismatch) {
			status := http.StatusForbidden
			if strings.Contains(err.Error(), "differs from original binding") {
				status = http.StatusConflict
			}
			writeServiceError(w, r, status, registry.ErrCodeBindingMismatch, err.Error())
			return
		}
		if errors.Is(err, procurement.ErrUnavailable) {
			writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "dispatch service unavailable")
			return
		}
		writeInternalError(w, r, err)
		return
	}
	if replayed {
		httpx.WriteJSON(w, http.StatusOK, view)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, view)
}

func (s *Server) handleDispatchStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("runId")
	if !registry.IsDigest(id) {
		writeServiceError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid workbench run ID")
		return
	}
	if s.cfg.Dispatch == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "dispatch service unavailable")
		return
	}
	view, err := s.cfg.Dispatch.GetDispatchStatus(r.Context(), id)
	if errors.Is(err, procurement.ErrNotFound) {
		writeServiceError(w, r, http.StatusNotFound, "NOT_FOUND", "dispatch not found")
		return
	}
	if protocol.HasCode(err, registry.ErrCodeInvalidSchema) {
		writeServiceError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid workbench run ID")
		return
	}
	if err != nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "dispatch store unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

func (s *Server) handleDispatchQuote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("runId")
	if !registry.IsDigest(id) {
		writeServiceError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid workbench run ID")
		return
	}
	var input wallet.RequestQuoteInput
	if !readServiceJSON(w, r, &input) {
		return
	}
	if s.cfg.Dispatch == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "dispatch service unavailable")
		return
	}
	out, err := s.cfg.Dispatch.InvokeBoundQuote(r.Context(), id, input)
	if errors.Is(err, procurement.ErrNotFound) {
		writeServiceError(w, r, http.StatusNotFound, "NOT_FOUND", "dispatch not found")
		return
	}
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) handleDispatchOrder(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("runId")
	if !registry.IsDigest(id) {
		writeServiceError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid workbench run ID")
		return
	}
	var input wallet.CreateOrderInput
	if !readServiceJSON(w, r, &input) {
		return
	}
	if s.cfg.Dispatch == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "dispatch service unavailable")
		return
	}
	out, err := s.cfg.Dispatch.InvokeBoundOrder(r.Context(), id, input)
	if errors.Is(err, procurement.ErrNotFound) {
		writeServiceError(w, r, http.StatusNotFound, "NOT_FOUND", "dispatch not found")
		return
	}
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) handleRunProbe(w http.ResponseWriter, r *http.Request) {
	var in procurement.ProbeRequest
	if !readServiceJSON(w, r, &in) {
		return
	}
	if !registry.IsDigest(in.RunID) || !registry.IsDigest(in.Key) {
		writeServiceError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid probe binding")
		return
	}
	if s.cfg.Dispatch == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "dispatch service unavailable")
		return
	}
	out, err := s.cfg.Dispatch.RunProbe(r.Context(), in)
	if protocol.HasCode(err, registry.ErrCodeInvalidSchema) {
		writeServiceError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid probe binding")
		return
	}
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) handleWalletReceipt(w http.ResponseWriter, r *http.Request) {
	if s.receiptHandler == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "wallet receipt service unavailable")
		return
	}
	s.receiptHandler.ServeHTTP(w, r)
}

// --- Domain C handlers ---

func (s *Server) handleRemoteRoot(w http.ResponseWriter, r *http.Request) {
	var req procurement.RootGrantRequest
	if !readServiceJSON(w, r, &req) {
		return
	}
	if s.cfg.Procurement == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "procurement service unavailable")
		return
	}
	delivery, op, err := s.cfg.Procurement.IssueRemoteRoot(r.Context(), req)
	if err != nil && op == nil && delivery == nil && protocol.HasCode(err, registry.ErrCodeBindingMismatch) {
		writeServiceError(w, r, http.StatusForbidden, registry.ErrCodeBindingMismatch, "root request outside workbench scope")
		return
	}
	out := procurement.RootGrantResponse{Operation: op, Delivery: delivery}
	if err != nil {
		out.Code = protocol.CodeOf(err)
		if out.Code == "" {
			out.Code = registry.ErrCodeStateUnavailable
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) handleRemoteRootReceipt(w http.ResponseWriter, r *http.Request) {
	var in procurement.RootGrantReceipt
	if !readServiceJSON(w, r, &in) {
		return
	}
	if s.cfg.Procurement == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "procurement service unavailable")
		return
	}
	if err := s.cfg.Procurement.AckRemoteRootReceipt(r.Context(), in.GrantID, in.Digest); err != nil {
		writeServiceError(w, r, http.StatusConflict, registry.ErrCodeMaterialNotSynced, "root receipt unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoteRootAmount(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("taskId")
	if !registry.IsDigest(taskID) {
		writeServiceError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid workbench task ID")
		return
	}
	if s.cfg.Evidence == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "evidence service unavailable")
		return
	}
	amount, err := s.cfg.Evidence.ReadRemoteRootAmount(r.Context(), taskID)
	if errors.Is(err, evidence.ErrNotFound) {
		writeServiceError(w, r, http.StatusNotFound, "NOT_FOUND", "workbench RP root not found")
		return
	}
	if protocol.HasCode(err, registry.ErrCodeInvalidSchema) {
		writeServiceError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid workbench task ID")
		return
	}
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, amount)
}

func (s *Server) handleRemoteContext(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TaskID string `json:"taskId"`
	}
	if !readServiceJSON(w, r, &in) {
		return
	}
	if s.cfg.Procurement == nil || s.cfg.Gateway == nil || s.cfg.Gateway.Service() == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "supplier context service unavailable")
		return
	}
	updater := func(ctx context.Context, taskID string, expectedVersion int64, riskLevel string, policyDeadline int64) error {
		_, err := s.cfg.Gateway.Service().UpdateContext(ctx, taskID, domgw.ContextUpdateRequest{
			SourceID:               workbenchContextSourceID,
			ExpectedContextVersion: expectedVersion,
			ObservedAt:             time.Now().Unix(),
			AccessDeadline:         policyDeadline,
			RiskLevel:              riskLevel,
		})
		return err
	}
	if err := s.cfg.Procurement.EnsureSupplierContext(r.Context(), in.TaskID, updater); err != nil {
		switch protocol.CodeOf(err) {
		case registry.ErrCodeTaskInactive:
			writeServiceError(w, r, http.StatusConflict, registry.ErrCodeTaskInactive, "workbench task is no longer active")
		case registry.ErrCodeStateUnavailable:
			status := http.StatusServiceUnavailable
			msg := "supplier environment unavailable"
			if strings.Contains(err.Error(), "confirmed workbench task unavailable") {
				status = http.StatusConflict
				msg = "confirmed workbench task unavailable"
			}
			writeServiceError(w, r, status, registry.ErrCodeStateUnavailable, msg)
		default:
			writeInternalError(w, r, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRemoteEvidence(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("taskId")
	if s.cfg.Evidence == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "evidence service unavailable")
		return
	}
	proof, err := s.cfg.Evidence.ReadRemoteTaskEvidence(r.Context(), taskID)
	if errors.Is(err, evidence.ErrNotFound) {
		writeServiceError(w, r, http.StatusNotFound, "NOT_FOUND", "task evidence not found")
		return
	}
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, proof)
}

func (s *Server) handleGatewayPassthrough(w http.ResponseWriter, r *http.Request) {
	h := s.resolveGatewayHandler()
	if h == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "gateway service unavailable")
		return
	}
	h.ServeHTTP(w, r)
}

func (s *Server) reconcileFromB(w http.ResponseWriter, r *http.Request) {
	var request domgw.AuditOrderOutcomeRequest
	if !readServiceJSON(w, r, &request) {
		return
	}
	if request.Request == nil || s.cfg.ActorB1DID == "" || request.Request.Actor != s.cfg.ActorB1DID ||
		s.cfg.DeploymentID == "" || request.Request.DeploymentID != s.cfg.DeploymentID ||
		request.DeploymentID != s.cfg.DeploymentID || request.CaseID == "" {
		writeServiceError(w, r, http.StatusForbidden, registry.ErrCodeBindingMismatch, "original B1 case required")
		return
	}
	exists, err := s.lookupOrderOutcomeCase(r.Context(), request.CaseID, request.Request.Actor, request.Request.TaskID, request.RequestHash)
	if err != nil || !exists {
		writeServiceError(w, r, http.StatusForbidden, registry.ErrCodeBindingMismatch, "original B1 case required")
		return
	}
	h := s.resolveGatewayHandler()
	if h == nil {
		writeServiceError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "gateway service unavailable")
		return
	}
	raw, err := json.Marshal(request)
	if err != nil {
		writeServiceError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid audit input")
		return
	}
	ctx := mtls.WithIdentity(r.Context(), mtls.Identity{
		DID:   s.cfg.AuditorDID,
		Role:  "C_AUDITOR",
		MSPID: "CMsp",
	})
	local := r.Clone(ctx)
	local.Header.Set("Content-Type", "application/json")
	local.ContentLength = int64(len(raw))
	local.Body = io.NopCloser(bytes.NewReader(raw))
	h.ServeHTTP(w, local)
}

func (s *Server) lookupOrderOutcomeCase(ctx context.Context, caseID, actor, taskID, requestHash string) (bool, error) {
	if s.hasOrderOutcomeCase != nil {
		return s.hasOrderOutcomeCase(ctx, caseID, actor, taskID, requestHash)
	}
	if s.cfg.Gateway == nil || s.cfg.Gateway.Service() == nil {
		return false, protocol.NewError(registry.ErrCodeStateUnavailable, "gateway service unavailable")
	}
	return s.cfg.Gateway.Service().HasOrderOutcomeCase(ctx, caseID, actor, taskID, requestHash)
}

func (s *Server) resolveGatewayHandler() http.Handler {
	if s.gatewayHandler != nil {
		return s.gatewayHandler
	}
	if s.cfg.Gateway != nil {
		return s.cfg.Gateway.Handler()
	}
	return nil
}

func readServiceJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	body := http.MaxBytesReader(w, r.Body, maxServiceRequestBytes)
	defer body.Close()
	raw, err := io.ReadAll(body)
	if err != nil || protocol.DecodeStrictJSON(raw, out) != nil {
		writeServiceError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid service request")
		return false
	}
	return true
}

func writeServiceError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	httpx.WriteError(w, status, httpx.RequestID(r), code, nil, message)
}

func writeInternalError(w http.ResponseWriter, r *http.Request, err error) {
	code := protocol.CodeOf(err)
	if code == "" {
		code = registry.ErrCodeStateUnavailable
	}
	writeServiceError(w, r, http.StatusConflict, code, "internal business operation unavailable")
}
