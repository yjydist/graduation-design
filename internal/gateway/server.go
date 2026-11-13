package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/policy"
	"graduation-design/internal/protocol"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// ChallengeTTLSeconds is C's fixed short lifetime for access challenges.
	ChallengeTTLSeconds = int64(30)
	// MaxExecuteBodyBytes enforces the 256 KiB payload limit on POST /v1/access/execute.
	MaxExecuteBodyBytes = 256 * 1024
)

var (
	hex64Re          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idempotencyKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// ProbeInfo describes the monotonic freshness lease of a synchronized ledger probe.
type ProbeInfo struct {
	TxID           string
	ProbeBlock     uint64
	SentAt         time.Time
	Deadline       time.Time
	SentMonoNs     int64
	DeadlineMonoNs int64
}

// ConsistentSnapshot holds a fixed-height ledger snapshot and its verified checkpoint/probe metadata.
type ConsistentSnapshot struct {
	DeploymentID    string
	BlockNumber     int64
	BlockHash       string
	RevocationEpoch int64
	Probe           ProbeInfo
	Snapshot        *protocol.SnapshotView
}

// StateSource provides fixed-height consistent snapshots and monotonic probe freshness checks.
type StateSource interface {
	IsProbeFresh() (ProbeInfo, error)
	AssembleSnapshot(ctx context.Context, leafGrantID string, now time.Time) (*ConsistentSnapshot, error)
}

// MaterialChecker verifies synced domain certifications before resource access.
type MaterialChecker interface {
	HasSyncedCertification(ctx context.Context, deploymentID, domainID, certID, certDigest string) (string, error)
}

// Config configures the C resource gateway HTTP server.
type Config struct {
	DB               *pgxpool.Pool
	State            StateSource
	Delivery         MaterialChecker
	DIDs             *protocol.DIDWebResolver
	Policy           *policy.VerifiedBundle
	DeploymentID     string
	ServiceDID       string
	Audience         string
	SupplierID       string
	ClockErrorMargin time.Duration
	NowFn            func() time.Time
	// BeforeLockTx is an optional deterministic test hook invoked right before opening the execute transaction.
	BeforeLockTx func(attempt int)
	// BeforeLockHead is an optional deterministic test hook invoked inside the execute transaction
	// right after locking business rows and before acquiring fabric_head FOR SHARE.
	BeforeLockHead func(attempt int)
}

// Server serves REST endpoints for C's resource access gateway.
type Server struct {
	cfg Config
	mux *http.ServeMux
}

// ErrorBody is the canonical structured error envelope returned by gateway endpoints.
type ErrorBody struct {
	RequestID  string  `json:"requestId"`
	Code       string  `json:"code"`
	DecisionID *string `json:"decisionId"`
	Message    string  `json:"message,omitempty"`
}

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

// DecisionRecord models GET /v1/decisions/{id}.
type DecisionRecord struct {
	DeploymentID          string   `json:"deploymentId"`
	DecisionID            string   `json:"decisionId"`
	RequestID             string   `json:"requestId"`
	ChallengeID           string   `json:"challengeId"`
	Actor                 string   `json:"actor"`
	TaskID                string   `json:"taskId"`
	Action                string   `json:"action"`
	IdempotencyKey        string   `json:"idempotencyKey"`
	Outcome               string   `json:"outcome"`
	Code                  string   `json:"code"`
	Reason                string   `json:"reason,omitempty"`
	QuoteID               *string  `json:"quoteId,omitempty"`
	BlockNumber           int64    `json:"blockNumber"`
	BlockHash             string   `json:"blockHash"`
	RevocationEpoch       int64    `json:"revocationEpoch"`
	ProbeTxID             string   `json:"probeTxId"`
	ProbeBlock            int64    `json:"probeBlock"`
	ProbeSentAt           int64    `json:"probeSentAt"`
	ProbeDeadline         int64    `json:"probeDeadline"`
	ProbeSentMonoNs       int64    `json:"probeSentMonoNs"`
	ProbeDeadlineMonoNs   int64    `json:"probeDeadlineMonoNs"`
	DecisionAt            int64    `json:"decisionAt"`
	RootDID               string   `json:"rootDid"`
	RootKeyVersion        int64    `json:"rootKeyVersion"`
	DomainID              string   `json:"domainId,omitempty"`
	CertificationID       string   `json:"certificationId,omitempty"`
	CertificationDigest   string   `json:"certificationDigest,omitempty"`
	DomainRevision        int64    `json:"domainRevision"`
	IdentityIssuer        string   `json:"identityIssuer,omitempty"`
	PolicyDigest          string   `json:"policyDigest"`
	ContextVersion        int64    `json:"contextVersion"`
	ContextRiskLevel      string   `json:"contextRiskLevel"`
	ContextObservedAt     int64    `json:"contextObservedAt"`
	ContextAccessDeadline int64    `json:"contextAccessDeadline"`
	EffectiveDeadline     int64    `json:"effectiveDeadline"`
	GrantPath             []string `json:"grantPath"`
	FailedObjectID        *string  `json:"failedObjectId,omitempty"`
}

// QuoteDTO is the immutable quote response returned by quote.read.
type QuoteDTO struct {
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

// ExecuteResponse models 200 OK from POST /v1/access/execute.
type ExecuteResponse struct {
	DecisionID string    `json:"decisionId"`
	Code       string    `json:"code"`
	Quote      *QuoteDTO `json:"quote,omitempty"`
}

// NewServer constructs a configured gateway Server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("gateway db pool is required")
	}
	if cfg.State == nil {
		return nil, fmt.Errorf("gateway state provider is required")
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
	s.mux.HandleFunc("POST /v1/auth/challenges", s.withRequestID(s.handleCreateChallenge))
	s.mux.HandleFunc("POST /v1/contexts/{taskId}", s.withRequestID(s.handleUpdateContext))
	s.mux.HandleFunc("POST /v1/access/execute", s.withRequestID(s.handleExecute))
	s.mux.HandleFunc("GET /v1/decisions/{id}", s.withRequestID(s.handleGetDecision))
	s.mux.HandleFunc("GET /v1/health/ready", s.withRequestID(s.handleReady))
	return s, nil
}

// Handler returns the HTTP handler for the gateway.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// SetTestHooks configures deterministic concurrency hooks for testing.
func (s *Server) SetTestHooks(beforeLockTx, beforeLockHead func(attempt int)) {
	s.cfg.BeforeLockTx = beforeLockTx
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

type ctxKeyRequestID struct{}

func requestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID{}).(string); ok && v != "" {
		return v
	}
	return "urn:grad:req:" + newUUID()
}

func (s *Server) withRequestID(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
		if reqID == "" {
			reqID = "urn:grad:req:" + newUUID()
		}
		w.Header().Set("X-Request-Id", reqID)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID{}, reqID)
		next(w, r.WithContext(ctx))
	}
}

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"code":"INTERNAL_ERROR"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func writeErrorResponse(w http.ResponseWriter, r *http.Request, status int, code string, decisionID *string, msg string) {
	reqID := requestIDFromContext(r.Context())
	w.Header().Set("X-Request-Id", reqID)
	writeJSONResponse(w, status, ErrorBody{
		RequestID:  reqID,
		Code:       code,
		DecisionID: decisionID,
		Message:    msg,
	})
}

func checkJSONContentType(r *http.Request) error {
	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if ct == "" {
		return protocol.NewError(protocol.ErrCodeUnsupportedMediaType, "Content-Type application/json is required")
	}
	media, _, _ := strings.Cut(ct, ";")
	if strings.TrimSpace(media) != "application/json" {
		return protocol.NewError(protocol.ErrCodeUnsupportedMediaType, fmt.Sprintf("unsupported Content-Type %q", ct))
	}
	return nil
}

func readBoundedBody(r *http.Request, maxBytes int64) ([]byte, error) {
	if err := checkJSONContentType(r); err != nil {
		return nil, err
	}
	if r.ContentLength > maxBytes {
		return nil, protocol.NewError(protocol.ErrCodePayloadTooLarge, fmt.Sprintf("request body exceeds %d bytes", maxBytes))
	}
	limited := io.LimitReader(r.Body, maxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, protocol.WrapError(protocol.ErrCodeInvalidSchema, "failed reading request body", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, protocol.NewError(protocol.ErrCodePayloadTooLarge, fmt.Sprintf("request body exceeds %d bytes", maxBytes))
	}
	return body, nil
}

func (s *Server) handleCreateChallenge(w http.ResponseWriter, r *http.Request) {
	body, err := readBoundedBody(r, MaxExecuteBodyBytes)
	if err != nil {
		writeMappedError(w, r, nil, err)
		return
	}
	var req ChallengeRequest
	if err := protocol.DecodeStrictJSON(body, &req); err != nil {
		writeErrorResponse(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	if strings.TrimSpace(req.Actor) == "" || strings.TrimSpace(req.TaskID) == "" || !hex64Re.MatchString(req.RequestHash) {
		writeErrorResponse(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, "actor, taskId, and lowercase 64-hex requestHash are required")
		return
	}

	nonce, err := protocol.GenerateNonce()
	if err != nil {
		writeErrorResponse(w, r, http.StatusInternalServerError, protocol.ErrCodeStateUnavailable, nil, err.Error())
		return
	}
	issuedAt := s.now().Unix()
	expiresAt := issuedAt + ChallengeTTLSeconds
	challengeID := "urn:grad:challenge:" + newUUID()

	if _, err := s.cfg.DB.Exec(r.Context(), `INSERT INTO challenges(
		deployment_id, challenge_id, nonce, actor, task_id, request_hash, audience, issued_at, expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		s.cfg.DeploymentID, challengeID, nonce, req.Actor, req.TaskID, req.RequestHash, s.cfg.Audience, issuedAt, expiresAt,
	); err != nil {
		writeErrorResponse(w, r, http.StatusInternalServerError, protocol.ErrCodeStateUnavailable, nil, err.Error())
		return
	}

	writeJSONResponse(w, http.StatusCreated, ChallengeResponse{
		ChallengeID: challengeID,
		Nonce:       nonce,
		Audience:    s.cfg.Audience,
		IssuedAt:    issuedAt,
		ExpiresAt:   expiresAt,
	})
}

func (s *Server) handleUpdateContext(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("taskId")
	if strings.TrimSpace(taskID) == "" {
		writeErrorResponse(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, "taskId path parameter is required")
		return
	}
	body, err := readBoundedBody(r, MaxExecuteBodyBytes)
	if err != nil {
		writeMappedError(w, r, nil, err)
		return
	}
	var req ContextUpdateRequest
	if err := protocol.DecodeStrictJSON(body, &req); err != nil {
		writeErrorResponse(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	if strings.TrimSpace(req.SourceID) == "" ||
		(req.RiskLevel != "NORMAL" && req.RiskLevel != "ELEVATED" && req.RiskLevel != "BLOCKED") ||
		req.ObservedAt <= 0 || req.AccessDeadline <= req.ObservedAt || req.ExpectedContextVersion < 0 {
		writeErrorResponse(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, "invalid context observation fields")
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
			writeErrorResponse(w, r, http.StatusInternalServerError, protocol.ErrCodeStateUnavailable, nil, err.Error())
			return
		}
		if tag.RowsAffected() == 0 {
			writeErrorResponse(w, r, http.StatusConflict, protocol.ErrCodeStateChanged, nil, "trusted context already exists with higher version")
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
			writeErrorResponse(w, r, http.StatusInternalServerError, protocol.ErrCodeStateUnavailable, nil, err.Error())
			return
		}
		if tag.RowsAffected() == 0 {
			writeErrorResponse(w, r, http.StatusConflict, protocol.ErrCodeStateChanged, nil, "trusted context expectedContextVersion mismatch")
			return
		}
	}

	writeJSONResponse(w, http.StatusOK, ContextResponse{
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
		writeErrorResponse(w, r, http.StatusBadRequest, protocol.ErrCodeInvalidSchema, nil, "decision id is required")
		return
	}

	var rec DecisionRecord
	var reason, quoteID, domID, certID, certDigest, idIssuer, failedObj *string
	err := s.cfg.DB.QueryRow(r.Context(), `SELECT
		deployment_id, decision_id, request_id, challenge_id, actor, task_id, action, idempotency_key,
		outcome, code, reason, quote_id, block_number, block_hash, revocation_epoch,
		probe_tx_id, probe_block, probe_sent_at, probe_deadline, probe_sent_mono_ns, probe_deadline_mono_ns, decision_at,
		root_did, root_key_version, domain_id, certification_id, certification_digest, domain_revision,
		identity_issuer, policy_digest, context_version, context_risk_level, context_observed_at,
		context_access_deadline, effective_deadline, grant_path, failed_object_id
		FROM decisions WHERE deployment_id=$1 AND decision_id=$2`,
		s.cfg.DeploymentID, decID,
	).Scan(
		&rec.DeploymentID, &rec.DecisionID, &rec.RequestID, &rec.ChallengeID, &rec.Actor, &rec.TaskID, &rec.Action, &rec.IdempotencyKey,
		&rec.Outcome, &rec.Code, &reason, &quoteID, &rec.BlockNumber, &rec.BlockHash, &rec.RevocationEpoch,
		&rec.ProbeTxID, &rec.ProbeBlock, &rec.ProbeSentAt, &rec.ProbeDeadline, &rec.ProbeSentMonoNs, &rec.ProbeDeadlineMonoNs, &rec.DecisionAt,
		&rec.RootDID, &rec.RootKeyVersion, &domID, &certID, &certDigest, &rec.DomainRevision,
		&idIssuer, &rec.PolicyDigest, &rec.ContextVersion, &rec.ContextRiskLevel, &rec.ContextObservedAt,
		&rec.ContextAccessDeadline, &rec.EffectiveDeadline, &rec.GrantPath, &failedObj,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		writeErrorResponse(w, r, http.StatusNotFound, protocol.ErrCodeInvalidSchema, nil, "decision not found")
		return
	}
	if err != nil {
		writeErrorResponse(w, r, http.StatusInternalServerError, protocol.ErrCodeStateUnavailable, nil, err.Error())
		return
	}
	if reason != nil {
		rec.Reason = *reason
	}
	rec.QuoteID = quoteID
	if domID != nil {
		rec.DomainID = *domID
	}
	if certID != nil {
		rec.CertificationID = *certID
	}
	if certDigest != nil {
		rec.CertificationDigest = *certDigest
	}
	if idIssuer != nil {
		rec.IdentityIssuer = *idIssuer
	}
	rec.FailedObjectID = failedObj
	writeJSONResponse(w, http.StatusOK, rec)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Policy == nil {
		writeErrorResponse(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, "policy bundle not loaded")
		return
	}
	probe, err := s.cfg.State.IsProbeFresh()
	if err != nil {
		writeMappedError(w, r, nil, err)
		return
	}
	// Verify DB connectivity and active snapshot domains + synced domain certifications without leaking secrets.
	if err := s.cfg.DB.Ping(r.Context()); err != nil {
		writeErrorResponse(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, err.Error())
		return
	}
	if s.cfg.Delivery != nil {
		tx, err := s.cfg.DB.BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			writeErrorResponse(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, err.Error())
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()
		for _, domID := range []string{"A", "C"} {
			rawDom, ok, err := readCurrentObjectJSON(r.Context(), tx, s.cfg.DeploymentID, "domain", domID)
			if err != nil {
				writeErrorResponse(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, err.Error())
				return
			}
			if !ok {
				writeErrorResponse(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, fmt.Sprintf("domain %s missing in snapshot", domID))
				return
			}
			var dom api.Domain
			if err := json.Unmarshal(rawDom, &dom); err != nil {
				writeErrorResponse(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, err.Error())
				return
			}
			rawCert, ok, err := readCurrentObjectJSON(r.Context(), tx, s.cfg.DeploymentID, "certification", dom.Certification)
			if err != nil || !ok {
				writeErrorResponse(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, fmt.Sprintf("certification %s missing in snapshot", dom.Certification))
				return
			}
			var cert api.Certification
			if err := json.Unmarshal(rawCert, &cert); err != nil {
				writeErrorResponse(w, r, http.StatusServiceUnavailable, protocol.ErrCodeStateUnavailable, nil, err.Error())
				return
			}
			if _, err := s.cfg.Delivery.HasSyncedCertification(r.Context(), s.cfg.DeploymentID, domID, cert.ID, cert.Digest); err != nil {
				writeMappedError(w, r, nil, err)
				return
			}
		}
	}

	writeJSONResponse(w, http.StatusOK, map[string]any{
		"status":       "READY",
		"deploymentId": s.cfg.DeploymentID,
		"serviceDid":   s.cfg.ServiceDID,
		"policyDigest": s.cfg.Policy.PolicyDigest,
		"probeBlock":   probe.ProbeBlock,
	})
}

func readCurrentObjectJSON(ctx context.Context, tx pgx.Tx, deploymentID, kind, id string) ([]byte, bool, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2`,
		deploymentID, api.Key(kind, id)).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}
