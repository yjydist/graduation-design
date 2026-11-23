// Package workbench adapts trusted local identities and existing platform operations to the browser API.
package workbench

import (
	"context"
	_ "embed"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/internal/httpx"
	"grad/platform/registrysvc"
	"grad/protocol"
	"grad/protocol/registry"
)

// PrincipalHandler receives the server-verified principal, with route and CSRF checks already applied.
type PrincipalHandler func(http.ResponseWriter, *http.Request, Principal)

type ProcurementHandlers struct {
	Chat, Draft, UpdateDraft, ConfirmDraft PrincipalHandler
	Runs, Run, SuspendRun, ResumeRun       PrincipalHandler
}

type EvidenceHandlers struct {
	RunEvidence, Decision PrincipalHandler
}

type Config struct {
	DeploymentID string
	DomainID     string
	DB           *pgxpool.Pool
	Registry     *registrysvc.Service

	VerifyPrincipal          func(context.Context, Principal) error
	ReadPurchasingAuthority  func(context.Context, Principal) (PurchasingAuthority, error)
	CheckPurchasingAuthority func(context.Context, Principal, string) error
	Ready                    func(context.Context) error
	Procurement              ProcurementHandlers
	Evidence                 EvidenceHandlers
}

type Server struct {
	cfg Config
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.DeploymentID == "" || cfg.DomainID != "A" && cfg.DomainID != "B" && cfg.DomainID != "C" {
		return nil, errors.New("valid workbench deployment and domain required")
	}
	if cfg.DB == nil || cfg.Registry == nil || cfg.VerifyPrincipal == nil || cfg.ReadPurchasingAuthority == nil ||
		cfg.CheckPurchasingAuthority == nil || cfg.Ready == nil {
		return nil, errors.New("workbench database, local authority and readiness bindings required")
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
	p := s.cfg.Procurement
	e := s.cfg.Evidence
	return []route{
		{"GET", "/openapi.json", serveOpenAPI},
		{"GET", "/health/ready", s.readiness},
		{"POST", "/session/login", s.login},
		{"GET", "/session", s.authenticated("", s.currentSession)},
		{"POST", "/session/logout", s.sessionHandler("", s.logout, nil)},
		{"GET", "/management/purchasing-authority", s.authenticated(RoleAdmin, s.purchasingAuthority)},
		{"POST", "/management/purchasing-authority", s.authenticated(RoleAdmin, s.setPurchasingAuthority)},
		{"GET", "/operations/{operationId}", s.authenticated("", s.operation)},
		{"POST", "/chat", s.authenticated(RoleBuyer, p.Chat)},
		{"GET", "/drafts/{draftId}", s.authenticated(RoleBuyer, p.Draft)},
		{"PUT", "/drafts/{draftId}", s.authenticated(RoleBuyer, p.UpdateDraft)},
		{"POST", "/drafts/{draftId}/confirm", s.authenticated(RoleBuyer, p.ConfirmDraft)},
		{"GET", "/runs", s.authenticated(RoleBuyer, p.Runs)},
		{"GET", "/runs/{runId}", s.authenticated(RoleBuyer, p.Run)},
		{"POST", "/runs/{runId}/suspend", s.authenticated(RoleBuyer, p.SuspendRun)},
		{"POST", "/runs/{runId}/resume", s.authenticated(RoleBuyer, p.ResumeRun)},
		{"GET", "/runs/{runId}/evidence", s.authenticated(RoleBuyer, e.RunEvidence)},
		{"GET", "/decisions/{decisionId}", s.authenticated("", e.Decision)},
	}
}

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
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Allow", strings.Join(methods, ", "))
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
	if err := s.cfg.DB.Ping(r.Context()); err != nil {
		WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "workbench database unavailable")
		return
	}
	if err := s.cfg.Ready(r.Context()); err != nil {
		WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "workbench domain not ready")
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
			WriteError(w, r, http.StatusUnsupportedMediaType, registry.ErrCodeUnsupportedMediaType, "application/json required")
		case errors.Is(err, httpx.ErrPayloadTooLarge):
			WriteError(w, r, http.StatusRequestEntityTooLarge, registry.ErrCodePayloadTooLarge, "request body too large")
		default:
			WriteError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid JSON request body")
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

// IdempotencyKey validates the existing management request key format.
func IdempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	values := r.Header.Values("Idempotency-Key")
	if len(values) != 1 || !operationKeyPattern.MatchString(values[0]) {
		WriteError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "valid Idempotency-Key required")
		return "", false
	}
	return values[0], true
}
