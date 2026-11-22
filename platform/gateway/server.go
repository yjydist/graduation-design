// Package gateway implements the supplier C resource access gateway, trusted context store,
// decision audit ledger, and order-outcome reconciliation service.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/internal/httpx"
	"grad/platform/migrations"
	"grad/platform/policy"
	"grad/platform/state"
	"grad/protocol"
)

const (
	// ChallengeTTLSeconds is C's fixed short lifetime for access challenges.
	ChallengeTTLSeconds = int64(30)
	// MaxExecuteBodyBytes enforces the 256 KiB payload limit on gateway JSON endpoints.
	MaxExecuteBodyBytes = 256 * 1024

	// DefaultProductID is the seeded P1 procurement catalog identifier.
	DefaultProductID = "urn:grad:product:P1"
	// DefaultProductPriceMinor is the seeded P1 unit price in CNY minor units (80000 fen).
	DefaultProductPriceMinor = int64(80000)
	// SecondaryProductID is the seeded P2 catalog identifier (120000 fen, exceeds G2 100000 fen cap).
	SecondaryProductID = "urn:grad:product:P2"
	// SecondaryProductPriceMinor is the seeded P2 unit price in CNY minor units (120000 fen).
	SecondaryProductPriceMinor = int64(120000)
	// DefaultCurrency is the seeded CNY currency code.
	DefaultCurrency = "CNY"
	// DefaultSupplierID is the fallback supplier identifier used when seeding catalog prices.
	DefaultSupplierID = "urn:grad:supplier:C"
)

var (
	hex64Re          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idempotencyKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// ErrorBody is the canonical structured error envelope returned by gateway HTTP endpoints.
// Re-exported here so external callers such as runtime and experiments do not import internal packages.
type ErrorBody = httpx.ErrorEnvelope

// CertificationChecker verifies whether a domain's active certification body has been synced locally.
type CertificationChecker interface {
	HasSyncedCertification(ctx context.Context, domainID string) (bool, error)
}

// DecisionTiming captures sub-second post-lock decision and commit timestamps linked by decisionId.
type DecisionTiming struct {
	DecisionID          string    `json:"decisionId"`
	RequestID           string    `json:"requestId"`
	ChallengeID         string    `json:"challengeId"`
	Action              string    `json:"action"`
	Outcome             string    `json:"outcome"`
	Code                string    `json:"code"`
	StateSource         string    `json:"stateSource"`
	BlockNumber         int64     `json:"blockNumber"`
	BlockHash           string    `json:"blockHash"`
	ProbeTxID           string    `json:"probeTxId"`
	ProbeBlock          int64     `json:"probeBlock"`
	ProbeSentAt         time.Time `json:"probeSentAt"`
	ProbeDeadline       time.Time `json:"probeDeadline"`
	ProbeSentMonoNs     int64     `json:"probeSentMonoNs"`
	ProbeDeadlineMonoNs int64     `json:"probeDeadlineMonoNs"`
	ProbeCheckedMonoNs  int64     `json:"probeCheckedMonoNs"`
	DecisionAtSec       int64     `json:"decisionAtSec"`
	DecisionAt          time.Time `json:"decisionAt"`
	CommittedAt         time.Time `json:"committedAt"`
}

// ServerConfig configures the C resource gateway HTTP server.
type ServerConfig struct {
	DB               *pgxpool.Pool
	State            state.StateSource
	CertChecker      CertificationChecker
	DIDs             *protocol.DIDWebResolver
	Policy           *policy.VerifiedBundle
	PolicyArchive    map[string]*policy.VerifiedBundle
	SignatureCache   *protocol.SignatureCache
	AuditorDIDs      []string
	VerifierID       string
	DeploymentID     string
	ServiceDID       string
	Audience         string
	SupplierID       string
	ClockErrorMargin time.Duration
	NowFn            func() time.Time

	// AfterInitialCheck is an optional deterministic test hook invoked after precheck
	// completes and right before opening the execute transaction.
	AfterInitialCheck func(attempt int)
	// BeforeChallengeLock is an optional deterministic test hook invoked inside the execute
	// transaction immediately before locking the challenge row FOR UPDATE.
	BeforeChallengeLock func(attempt int)
	// BeforeLockHead is an optional deterministic test hook invoked inside the execute
	// transaction after locking business rows and before acquiring the state checkpoint lock.
	BeforeLockHead func(attempt int)
	// OnDecisionCommitted is an optional callback invoked immediately after a decision transaction commits.
	OnDecisionCommitted func(DecisionTiming)
	// BeforeWriteResponse is an optional test hook invoked after transaction commit and before writing the HTTP response.
	BeforeWriteResponse func(decisionID string)
}

// Server serves REST endpoints for C's resource access gateway.
type Server struct {
	cfg     ServerConfig
	mux     *http.ServeMux
	handler http.Handler
}

// ContextUpdateRequest models POST /v1/contexts/{taskId}.
type ContextUpdateRequest struct {
	ExpectedContextVersion int64  `json:"expectedContextVersion"`
	SourceID               string `json:"sourceId"`
	ObservedAt             int64  `json:"observedAt"`
	RiskLevel              string `json:"riskLevel"`
	AccessDeadline         int64  `json:"accessDeadline"`
}

// ContextResponse models 200 OK from POST /v1/contexts/{taskId}.
type ContextResponse struct {
	DeploymentID   string `json:"deploymentId"`
	TaskID         string `json:"taskId"`
	ContextVersion int64  `json:"contextVersion"`
	SourceID       string `json:"sourceId"`
	ObservedAt     int64  `json:"observedAt"`
	RiskLevel      string `json:"riskLevel"`
	AccessDeadline int64  `json:"accessDeadline"`
}

// DecisionRecord models GET /v1/decisions/{id} and rows in the decisions table.
type DecisionRecord struct {
	StateSource           string     `json:"stateSource" db:"state_source"`
	Revision              *int64     `json:"revision" db:"revision"`
	StateReadAt           *time.Time `json:"stateReadAt" db:"state_read_at"`
	StateRechecks         int        `json:"stateRechecks" db:"state_rechecks"`
	DeploymentID          string     `json:"deploymentId" db:"deployment_id"`
	DecisionID            string     `json:"decisionId" db:"decision_id"`
	RequestID             string     `json:"requestId" db:"request_id"`
	ChallengeID           string     `json:"challengeId" db:"challenge_id"`
	Actor                 string     `json:"actor" db:"actor"`
	TaskID                string     `json:"taskId" db:"task_id"`
	Action                string     `json:"action" db:"action"`
	IdempotencyKey        string     `json:"idempotencyKey" db:"idempotency_key"`
	Outcome               string     `json:"outcome" db:"outcome"`
	Code                  string     `json:"code" db:"code"`
	Reason                string     `json:"reason,omitempty" db:"reason"`
	QuoteID               *string    `json:"quoteId,omitempty" db:"quote_id"`
	OrderID               *string    `json:"orderId,omitempty" db:"order_id"`
	BlockNumber           int64      `json:"blockNumber" db:"block_number"`
	BlockHash             string     `json:"blockHash" db:"block_hash"`
	RevocationEpoch       int64      `json:"revocationEpoch" db:"revocation_epoch"`
	ProbeTxID             string     `json:"probeTxId" db:"probe_tx_id"`
	ProbeBlock            int64      `json:"probeBlock" db:"probe_block"`
	ProbeSentAt           int64      `json:"probeSentAt" db:"probe_sent_at"`
	ProbeDeadline         int64      `json:"probeDeadline" db:"probe_deadline"`
	ProbeSentAtNs         *int64     `json:"probeSentAtNs,omitempty" db:"probe_sent_at_ns"`
	ProbeDeadlineNs       *int64     `json:"probeDeadlineNs,omitempty" db:"probe_deadline_ns"`
	ProbeSentMonoNs       int64      `json:"probeSentMonoNs" db:"probe_sent_mono_ns"`
	ProbeDeadlineMonoNs   int64      `json:"probeDeadlineMonoNs" db:"probe_deadline_mono_ns"`
	ProbeCheckedMonoNs    *int64     `json:"probeCheckedMonoNs" db:"probe_checked_mono_ns"`
	DecisionAt            int64      `json:"decisionAt" db:"decision_at"`
	DecisionAtNs          *int64     `json:"decisionAtNs,omitempty" db:"decision_at_ns"`
	RootDID               string     `json:"rootDid" db:"root_did"`
	RootKeyVersion        int64      `json:"rootKeyVersion" db:"root_key_version"`
	DomainID              string     `json:"domainId,omitempty" db:"domain_id"`
	CertificationID       string     `json:"certificationId,omitempty" db:"certification_id"`
	CertificationDigest   string     `json:"certificationDigest,omitempty" db:"certification_digest"`
	DomainRevision        int64      `json:"domainRevision" db:"domain_revision"`
	IdentityIssuer        string     `json:"identityIssuer,omitempty" db:"identity_issuer"`
	PolicyDigest          string     `json:"policyDigest" db:"policy_digest"`
	ContextVersion        int64      `json:"contextVersion" db:"context_version"`
	ContextRiskLevel      string     `json:"contextRiskLevel" db:"context_risk_level"`
	ContextObservedAt     int64      `json:"contextObservedAt" db:"context_observed_at"`
	ContextAccessDeadline int64      `json:"contextAccessDeadline" db:"context_access_deadline"`
	EffectiveDeadline     int64      `json:"effectiveDeadline" db:"effective_deadline"`
	GrantPath             []string   `json:"grantPath" db:"grant_path"`
	FailedObjectID        *string    `json:"failedObjectId,omitempty" db:"failed_object_id"`
}

const selectDecisionColumns = `
	deployment_id, decision_id, request_id, challenge_id, actor, task_id, action, idempotency_key,
	outcome, code, COALESCE(reason, '') AS reason, quote_id, order_id,
	COALESCE(block_number, 0) AS block_number,
	COALESCE(block_hash, '') AS block_hash,
	COALESCE(revocation_epoch, 0) AS revocation_epoch,
	COALESCE(probe_tx_id, '') AS probe_tx_id,
	COALESCE(probe_block, 0) AS probe_block,
	COALESCE(probe_sent_at, 0) AS probe_sent_at,
	COALESCE(probe_deadline, 0) AS probe_deadline,
	COALESCE(probe_sent_mono_ns, 0) AS probe_sent_mono_ns,
	COALESCE(probe_deadline_mono_ns, 0) AS probe_deadline_mono_ns,
	decision_at, root_did, root_key_version,
	COALESCE(domain_id, '') AS domain_id,
	COALESCE(certification_id, '') AS certification_id,
	COALESCE(certification_digest, '') AS certification_digest,
	domain_revision,
	COALESCE(identity_issuer, '') AS identity_issuer,
	policy_digest, context_version, context_risk_level, context_observed_at,
	context_access_deadline, effective_deadline, grant_path, failed_object_id,
	state_source, revision, state_read_at, state_rechecks, probe_checked_mono_ns,
	decision_at_ns, probe_sent_at_ns, probe_deadline_ns`

// MarshalJSON preserves Fabric fields for Fabric decisions and marks them null for centralized state.
func (d DecisionRecord) MarshalJSON() ([]byte, error) {
	type record DecisionRecord
	raw, err := json.Marshal(record(d))
	if err != nil {
		return nil, err
	}
	if d.StateSource != state.SourceCentralized {
		return raw, nil
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	for _, key := range []string{
		"blockNumber", "blockHash", "revocationEpoch",
		"probeTxId", "probeBlock", "probeSentAt", "probeDeadline",
		"probeSentAtNs", "probeDeadlineNs", "probeSentMonoNs", "probeDeadlineMonoNs",
	} {
		fields[key] = json.RawMessage("null")
	}
	return json.Marshal(fields)
}

// EnsureSchema applies embedded PostgreSQL migrations and idempotently seeds default
// P1 (80000 CNY) and P2 (120000 CNY) catalog prices when deploymentID is non-empty.
func EnsureSchema(ctx context.Context, db *pgxpool.Pool, deploymentID, supplierID string) error {
	if db == nil {
		return fmt.Errorf("gateway database pool is required")
	}
	if err := migrations.Up(ctx, db); err != nil {
		return err
	}
	if strings.TrimSpace(deploymentID) == "" {
		return nil
	}
	return EnsureCatalogPrices(ctx, db, deploymentID, supplierID)
}

// EnsureCatalogPrices idempotently seeds the P1 (80000 CNY) and P2 (120000 CNY) catalog rows.
// Callers must run migrations.Up beforehand to create the catalog_prices table.
func EnsureCatalogPrices(ctx context.Context, db *pgxpool.Pool, deploymentID, supplierID string) error {
	if db == nil {
		return fmt.Errorf("gateway database pool is required")
	}
	if strings.TrimSpace(deploymentID) == "" {
		return fmt.Errorf("deploymentId is required to seed catalog prices")
	}
	if strings.TrimSpace(supplierID) == "" {
		supplierID = DefaultSupplierID
	}
	for _, item := range []struct {
		productID string
		price     int64
	}{
		{DefaultProductID, DefaultProductPriceMinor},
		{SecondaryProductID, SecondaryProductPriceMinor},
	} {
		if _, err := db.Exec(ctx, `INSERT INTO catalog_prices(
			deployment_id, product_id, supplier_id, currency, unit_price_minor
		) VALUES($1, $2, $3, $4, $5)
		ON CONFLICT(deployment_id, product_id) DO NOTHING`,
			deploymentID, item.productID, supplierID, DefaultCurrency, item.price,
		); err != nil {
			return fmt.Errorf("seed catalog price %s: %w", item.productID, err)
		}
	}
	return nil
}

// NewServer constructs a configured gateway Server with its Go 1.22+ ServeMux routes.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("gateway db pool is required")
	}
	if cfg.State == nil {
		return nil, fmt.Errorf("gateway state source is required")
	}
	if cfg.DIDs == nil {
		return nil, fmt.Errorf("gateway did resolver is required")
	}
	if cfg.Policy == nil {
		return nil, fmt.Errorf("gateway policy bundle is required")
	}
	if cfg.DeploymentID == "" || cfg.ServiceDID == "" || cfg.Audience == "" {
		return nil, fmt.Errorf("gateway deploymentId, serviceDid, and audience are required")
	}
	if cfg.SupplierID == "" {
		cfg.SupplierID = cfg.ServiceDID
	}
	s := &Server{
		cfg: cfg,
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
	return s, nil
}

// Handler returns the HTTP handler for the gateway wrapped with X-Request-Id middleware.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// SetTestHooks configures deterministic concurrency hooks for testing.
func (s *Server) SetTestHooks(afterInitialCheck, beforeChallengeLock, beforeLockHead func(attempt int)) {
	s.cfg.AfterInitialCheck = afterInitialCheck
	s.cfg.BeforeChallengeLock = beforeChallengeLock
	s.cfg.BeforeLockHead = beforeLockHead
}

func (s *Server) now() time.Time {
	if s.cfg.NowFn != nil {
		return s.cfg.NowFn()
	}
	return time.Now()
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code string, decisionID *string, msg string) {
	httpx.WriteError(w, status, httpx.RequestID(r), code, decisionID, msg)
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

func (s *Server) handleUpdateContext(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("taskId")
	if strings.TrimSpace(taskID) == "" {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, "taskId path parameter is required")
		return
	}
	body, err := readJSONBody(r, MaxExecuteBodyBytes)
	if err != nil {
		writeMappedError(w, r, nil, err)
		return
	}
	var req ContextUpdateRequest
	if err := protocol.DecodeStrictJSON(body, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	if strings.TrimSpace(req.SourceID) == "" ||
		(req.RiskLevel != policy.RiskNormal && req.RiskLevel != policy.RiskElevated && req.RiskLevel != policy.RiskBlocked) ||
		req.ObservedAt <= 0 || req.AccessDeadline <= req.ObservedAt || req.ExpectedContextVersion < 0 {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, "invalid context observation fields")
		return
	}

	var newVersion int64
	if req.ExpectedContextVersion == 0 {
		newVersion = 1
		tag, err := s.cfg.DB.Exec(r.Context(), `INSERT INTO trusted_contexts(
			deployment_id, task_id, context_version, source_id, observed_at, risk_level, access_deadline
		) VALUES($1,$2,1,$3,$4,$5,$6)
		ON CONFLICT(deployment_id, task_id) DO NOTHING`,
			s.cfg.DeploymentID, taskID, req.SourceID, req.ObservedAt, req.RiskLevel, req.AccessDeadline,
		)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, protocol.ErrCodeStateUnavailable, nil, err.Error())
			return
		}
		if tag.RowsAffected() == 0 {
			writeError(w, r, http.StatusConflict, protocol.ErrCodeStateChanged, nil, "trusted context already exists with higher version")
			return
		}
	} else {
		newVersion = req.ExpectedContextVersion + 1
		tag, err := s.cfg.DB.Exec(r.Context(), `UPDATE trusted_contexts
			SET context_version=$1, source_id=$2, observed_at=$3, risk_level=$4, access_deadline=$5, updated_at=NOW()
			WHERE deployment_id=$6 AND task_id=$7 AND context_version=$8`,
			newVersion, req.SourceID, req.ObservedAt, req.RiskLevel, req.AccessDeadline,
			s.cfg.DeploymentID, taskID, req.ExpectedContextVersion,
		)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, protocol.ErrCodeStateUnavailable, nil, err.Error())
			return
		}
		if tag.RowsAffected() == 0 {
			writeError(w, r, http.StatusConflict, protocol.ErrCodeStateChanged, nil, "trusted context expectedContextVersion mismatch")
			return
		}
	}

	httpx.WriteJSON(w, http.StatusOK, ContextResponse{
		DeploymentID:   s.cfg.DeploymentID,
		TaskID:         taskID,
		ContextVersion: newVersion,
		SourceID:       req.SourceID,
		ObservedAt:     req.ObservedAt,
		RiskLevel:      req.RiskLevel,
		AccessDeadline: req.AccessDeadline,
	})
}

func (s *Server) handleGetDecision(w http.ResponseWriter, r *http.Request) {
	decID := r.PathValue("id")
	if strings.TrimSpace(decID) == "" {
		writeError(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, "decision id is required")
		return
	}

	rows, err := s.cfg.DB.Query(r.Context(), `SELECT `+selectDecisionColumns+`
		FROM decisions WHERE deployment_id=$1 AND decision_id=$2`,
		s.cfg.DeploymentID, decID,
	)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, protocol.ErrCodeStateUnavailable, nil, err.Error())
		return
	}
	rec, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[DecisionRecord])
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, r, http.StatusNotFound, protocol.ErrCodeInvalidSchema, nil, "decision not found")
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, protocol.ErrCodeStateUnavailable, nil, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rec)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Policy == nil {
		writeError(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, "policy bundle not loaded")
		return
	}
	view, err := s.cfg.State.AssembleSnapshot(r.Context(), "", s.now())
	if err != nil {
		writeMappedError(w, r, nil, err)
		return
	}
	probe, err := s.cfg.State.CheckFresh(r.Context(), view)
	if err != nil {
		writeMappedError(w, r, nil, err)
		return
	}
	if err := s.cfg.DB.Ping(r.Context()); err != nil {
		writeError(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, err.Error())
		return
	}
	if s.cfg.CertChecker != nil {
		for _, domID := range []string{"A", "C"} {
			dom, ok := view.Snapshot.Domains[domID]
			if !ok {
				writeError(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, "required readiness domain missing")
				return
			}
			if _, ok := view.Snapshot.Certifications[dom.Certification]; !ok {
				writeError(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, "required readiness certification missing")
				return
			}
			if err := s.checkSyncedCertification(r.Context(), domID); err != nil {
				writeMappedError(w, r, nil, err)
				return
			}
		}
	}

	var probeBlock any
	if view.StateSource == state.SourceFabric {
		probeBlock = probe.ProbeBlock
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":       "READY",
		"deploymentId": s.cfg.DeploymentID,
		"serviceDid":   s.cfg.ServiceDID,
		"policyDigest": s.cfg.Policy.PolicyDigest,
		"stateSource":  view.StateSource,
		"revision":     centralRevision(view),
		"stateReadAt":  centralReadAt(view),
		"probeBlock":   probeBlock,
	})
}

func (s *Server) checkSyncedCertification(ctx context.Context, domainID string) error {
	if s.cfg.CertChecker == nil {
		return nil
	}
	synced, err := s.cfg.CertChecker.HasSyncedCertification(ctx, domainID)
	if err != nil {
		if protocol.CodeOf(err) != "" {
			return err
		}
		return protocol.WrapError(protocol.ErrCodeMaterialNotSynced, fmt.Sprintf("check synced certification for domain %q", domainID), err)
	}
	if !synced {
		return protocol.NewError(protocol.ErrCodeMaterialNotSynced, fmt.Sprintf("domain %q certification material is not synced", domainID))
	}
	return nil
}
