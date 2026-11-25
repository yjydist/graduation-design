// Package workbench provides the L3 browser REST API adapter over L2
// core/domain/procurement and core/domain/evidence services.
package workbench

import (
	"context"
	_ "embed"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"grad/platform/core/domain/evidence"
	"grad/platform/core/domain/procurement"
	"grad/platform/internal/httpx"
	"grad/protocol"
	preg "grad/protocol/registry"
)

// Config binds the L3 browser workbench API to its L2 domain services and readiness probe.
type Config struct {
	DeploymentID string
	DomainID     string
	Sessions     *procurement.SessionService
	Authority    *procurement.AuthorityService
	Procurement  *procurement.Service
	Evidence     *evidence.Service
	Ready        func(context.Context) error
}

// Server serves the /api/v1/* browser REST API for one workbench domain (A, B, or C).
type Server struct {
	cfg Config
}

// NewServer validates required workbench bindings and constructs a Server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.DeploymentID == "" || (cfg.DomainID != "A" && cfg.DomainID != "B" && cfg.DomainID != "C") {
		return nil, errors.New("valid workbench deployment and domain required")
	}
	if cfg.Sessions == nil || cfg.Authority == nil || cfg.Ready == nil {
		return nil, errors.New("workbench session, authority, and readiness bindings required")
	}
	return &Server{cfg: cfg}, nil
}

const apiPrefix = "/api/v1"

//go:embed openapi.json
var openAPI []byte

type route struct {
	method, path string
	handler      http.HandlerFunc
}

func (s *Server) routes() []route {
	return []route{
		{"GET", "/openapi.json", serveOpenAPI},
		{"GET", "/health/ready", s.readiness},
		{"POST", "/session/login", s.login},
		{"GET", "/session", s.authenticated("", s.currentSession)},
		{"POST", "/session/logout", s.sessionHandler("", s.logout, false)},
		{"GET", "/management/purchasing-authority", s.authenticated(procurement.RoleAdmin, s.purchasingAuthority)},
		{"POST", "/management/purchasing-authority", s.authenticated(procurement.RoleAdmin, s.setPurchasingAuthority)},
		{"GET", "/operations/{operationId}", s.authenticated("", s.operation)},
		{"POST", "/chat", s.authenticated(procurement.RoleBuyer, s.chat)},
		{"GET", "/drafts/{draftId}", s.authenticated(procurement.RoleBuyer, s.getDraft)},
		{"PUT", "/drafts/{draftId}", s.authenticated(procurement.RoleBuyer, s.updateDraft)},
		{"POST", "/drafts/{draftId}/confirm", s.authenticated(procurement.RoleBuyer, s.confirmDraft)},
		{"GET", "/runs", s.authenticated(procurement.RoleBuyer, s.listRuns)},
		{"GET", "/runs/{runId}", s.authenticated(procurement.RoleBuyer, s.getRun)},
		{"POST", "/runs/{runId}/suspend", s.authenticated(procurement.RoleBuyer, s.suspendRun)},
		{"POST", "/runs/{runId}/resume", s.authenticated(procurement.RoleBuyer, s.resumeRun)},
		{"GET", "/runs/{runId}/evidence", s.authenticated(procurement.RoleBuyer, s.runEvidence)},
		{"GET", "/decisions/{decisionId}", s.authenticated("", s.decision)},
	}
}

// Handler returns the HTTP handler exposing all 18 /api/v1/* browser routes with
// method/route error envelopes, security headers, and X-Request-Id propagation.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	methodsByPath := make(map[string][]string)
	for _, endpoint := range s.routes() {
		path := apiPrefix + endpoint.path
		mux.HandleFunc(endpoint.method+" "+path, endpoint.handler)
		methodsByPath[path] = append(methodsByPath[path], endpoint.method)
		if endpoint.method == http.MethodGet {
			methodsByPath[path] = append(methodsByPath[path], http.MethodHead)
		}
	}
	for path, methods := range methodsByPath {
		sort.Strings(methods)
		allow := strings.Join(methods, ", ")
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Allow", allow)
			WriteError(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method unavailable for this endpoint")
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, http.StatusNotFound, "ROUTE_NOT_FOUND", "unknown browser API route")
	})
	return httpx.WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	}))
}

func serveOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(openAPI)
}

func (s *Server) readiness(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Ready == nil {
		WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "workbench domain not ready")
		return
	}
	if err := s.cfg.Ready(r.Context()); err != nil {
		WriteError(w, r, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable, "workbench domain not ready")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct {
		DomainID string `json:"domainId"`
		Ready    bool   `json:"ready"`
	}{s.cfg.DomainID, true})
}

// ReadJSON strictly decodes a bounded JSON request or writes a browser error envelope.
func ReadJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httpx.DecodeJSON(r, protocol.MaxJSONBytes, dst); err != nil {
		switch {
		case errors.Is(err, httpx.ErrUnsupportedMediaType):
			WriteError(w, r, http.StatusUnsupportedMediaType, preg.ErrCodeUnsupportedMediaType, "application/json required")
		case errors.Is(err, httpx.ErrPayloadTooLarge):
			WriteError(w, r, http.StatusRequestEntityTooLarge, preg.ErrCodePayloadTooLarge, "request body too large")
		default:
			WriteError(w, r, http.StatusBadRequest, preg.ErrCodeInvalidSchema, "invalid JSON request body")
		}
		return false
	}
	return true
}

// WriteError writes the shared structured HTTP error envelope.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	httpx.WriteError(w, status, httpx.RequestID(r), code, nil, message)
}

var operationKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// IdempotencyKey validates the management request key header format.
func IdempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) != 1 || !operationKeyPattern.MatchString(values[0]) {
		WriteError(w, r, http.StatusBadRequest, preg.ErrCodeInvalidSchema, "valid Idempotency-Key required")
		return "", false
	}
	return values[0], true
}
