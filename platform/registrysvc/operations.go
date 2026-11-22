// Package registrysvc implements management operation HTTP admission and status projection,
// identity registration and recovery dual-proof coordination, and controlled outbox/receipt
// delivery synchronization backed by PostgreSQL.
package registrysvc

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/platform/migrations"
	"grad/platform/state/fabric"
	"grad/protocol"
	"grad/protocol/registry"
)

const (
	// ErrCodeOperationUnknown indicates that GET /v1/operations/{operationId} referenced an unknown ID.
	ErrCodeOperationUnknown = "OPERATION_UNKNOWN"
	// ErrCodeEndorsementRejected indicates deterministic endorsement rejection without a specific registry code.
	ErrCodeEndorsementRejected = "ENDORSEMENT_REJECTED"
	// ErrCodeCommitInvalid indicates a non-VALID Fabric commit validation code other than MVCC_READ_CONFLICT.
	ErrCodeCommitInvalid = "COMMIT_INVALID"
)

var errOperationQueryForbidden = errors.New("operation query forbidden")

// EnsureSchema applies embedded PostgreSQL migrations required by registrysvc tables.
func EnsureSchema(ctx context.Context, db *pgxpool.Pool) error {
	return migrations.Up(ctx, db)
}

// OperationView represents the HTTP JSON view returned by POST /v1/management/{method}
// and GET /v1/operations/{operationId}.
type OperationView struct {
	OperationID    string  `json:"operationId" db:"operation_id"`
	OperationKey   string  `json:"operationKey" db:"operation_key"`
	Method         string  `json:"method" db:"method"`
	TxID           string  `json:"txId" db:"tx_id"`
	Stage          string  `json:"stage" db:"stage"`
	Status         string  `json:"status" db:"status"`
	ErrorCode      *string `json:"errorCode" db:"failure_code"`
	ValidationCode *string `json:"validationCode" db:"validation_code"`
	BlockNumber    int64   `json:"blockNumber" db:"block_no"`
	BlockHash      string  `json:"blockHash,omitempty" db:"block_hash"`
	Delivered      bool    `json:"delivered" db:"delivered"`
}

// OperationSubmitBackend executes pre-acceptance revision lookup and asynchronous
// endorse/broadcast/commit recovery steps on behalf of Service.
type OperationSubmitBackend interface {
	CurrentRevision(ctx context.Context, method string, input json.RawMessage) (uint64, bool, error)
	SubmitAsync(
		ctx context.Context,
		opKey, opID string,
		caller registry.Management,
		method string,
		input json.RawMessage,
		onUpdate func(stage, status string, txID string, blockNo int64, blockHash string, valCode, failCode *string, delivered bool) error,
	)
}

// FabricBackend bridges Service to fabric.Journal using the original-transaction journal.
type FabricBackend struct {
	journal         fabric.Journal
	roles           map[registry.Management]string
	BeforeBroadcast func(context.Context, string)
}

// NewFabricBackend constructs a FabricBackend indexed by all configured local Fabric role certificates.
func NewFabricBackend(j fabric.Journal) (*FabricBackend, error) {
	if j.Instance == nil {
		return nil, fmt.Errorf("registrysvc: fabric instance is required")
	}
	b := &FabricBackend{
		journal: j,
		roles:   make(map[registry.Management]string),
	}
	for _, role := range fabric.AllRoles() {
		_, caller, _, err := j.Instance.Role(role)
		if err != nil {
			return nil, err
		}
		b.roles[caller] = role
	}
	return b, nil
}

// ManagementForFingerprint resolves a verified mTLS certificate fingerprint to its bound Fabric Management identity.
func (b *FabricBackend) ManagementForFingerprint(fp string) (registry.Management, bool) {
	for caller := range b.roles {
		if caller.CertificateSHA256 == fp {
			return caller, true
		}
	}
	return registry.Management{}, false
}

// AuthorizeRecovery validates the current domain registrar and approved new management certificate
// against trusted Fabric ledger state and the target domain's MSP CA certificates.
func (b *FabricBackend) AuthorizeRecovery(ctx context.Context, caller registry.Management, bundle *protocol.RecoveryDualProofBundle) error {
	c := bundle.Challenge
	p, err := b.journal.Instance.Peer("c", "read")
	if err != nil {
		return err
	}
	defer p.Close()

	domain, err := fabric.ReadLedgerRecord[registry.Domain](ctx, p, "domain", c.DomainID)
	if err != nil {
		return err
	}
	if caller != domain.Registrar || c.NewManagementIdentity.MSPID != domain.ID+"Msp" {
		return protocol.NewError(registry.ErrCodeIdentityManagementForbidden, "current domain registrar required")
	}
	id, err := fabric.ReadLedgerRecord[registry.Identity](ctx, p, "identity", c.SubjectID)
	if err != nil {
		return err
	}
	if id.Domain != domain.ID || (id.Kind != "USER" && id.Kind != "AGENT" && id.Kind != "SERVICE") ||
		(id.Status != registry.Active && id.Status != registry.Suspended) || id.Management != recoveryMutation(c).OldManagement ||
		id.AccountCommitment != c.AccountCommitment || id.KeyVersion != c.ExpectedKeyVersion {
		return protocol.NewError(registry.ErrCodeRecoveryProofInvalid, "recovery approval does not match current ordinary identity")
	}
	certification, err := fabric.ReadLedgerRecord[registry.Certification](ctx, p, "certification", domain.Certification)
	if err != nil {
		return err
	}
	if domain.Status != registry.Active || certification.Status != registry.Active ||
		!certification.Interval.Current(time.Now(), registry.PeerTimeWindow+registry.ClockError) {
		return protocol.NewError(registry.ErrCodeRecoveryProofInvalid, "domain qualification inactive")
	}
	switch domain.ID {
	case "A", "B", "C":
	default:
		return protocol.NewError(registry.ErrCodeRecoveryProofInvalid, "unknown recovery domain")
	}
	paths, err := filepath.Glob(filepath.Join(b.journal.Instance.OrgDir(strings.ToLower(domain.ID)), "msp", "cacerts", "*.pem"))
	if err != nil {
		return err
	}
	var authorized []*x509.Certificate
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return fmt.Errorf("invalid MSP CA certificate")
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		authorized = append(authorized, ca)
	}
	if len(authorized) == 0 {
		return protocol.NewError(registry.ErrCodeStateUnavailable, "recovery MSP CA unavailable")
	}
	der, err := protocol.DecodeStrictBase64URL(bundle.NewManagementCertificateDER)
	if err != nil {
		return protocol.WrapError(registry.ErrCodeRecoveryProofInvalid, "decode new management certificate", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return protocol.WrapError(registry.ErrCodeRecoveryProofInvalid, "parse new management certificate", err)
	}
	return verifyAuthorizedMgmtCert(leaf, authorized)
}

// CurrentRevision queries the pinned Fabric peer for the current revision of the target ledger record.
func (b *FabricBackend) CurrentRevision(ctx context.Context, method string, input json.RawMessage) (uint64, bool, error) {
	var v struct {
		ID            string                 `json:"id"`
		SubjectID     string                 `json:"subjectId"`
		DomainID      string                 `json:"domainId"`
		Certification registry.Certification `json:"certification"`
	}
	if err := json.Unmarshal(input, &v); err != nil {
		return 0, false, err
	}
	kind, id := "", v.ID
	switch method {
	case "CertifyDomain":
		kind = "domain"
		id = v.Certification.Domain
	case "SetDomainStatus", "SetPurchasingAuthority":
		kind = "domain"
		if id == "" {
			id = v.DomainID
		}
	case "RotateIdentity", "SetIdentityStatus", "RecoverIdentity", "UpdateAuthorityIdentity":
		kind = "identity"
		if id == "" {
			id = v.SubjectID
		}
	case "RevokeCertification":
		kind = "certification"
	case "RevokeCredential":
		kind = "credential"
	case "CancelTask":
		kind = "task"
	case "RevokeGrant", "SuspendGrant", "ResumeGrant":
		kind = "grant"
	case "ApproveIdentityLink", "RevokeIdentityLink":
		kind = "link"
	default:
		return 0, false, nil
	}
	p, err := b.journal.Instance.Peer("c", "read")
	if err != nil {
		return 0, false, err
	}
	defer p.Close()
	raw, err := p.Direct(ctx, registry.Registry, "Read", registry.Key(kind, id))
	if err != nil {
		if fabric.IsMissingRecord(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	var version registry.Version
	if err := json.Unmarshal(raw, &version); err != nil {
		return 0, false, err
	}
	return version.Revision, true, nil
}

// SubmitAsync prepares, endorses, broadcasts, and observes the original Fabric transaction via fabric.Journal.
func (b *FabricBackend) SubmitAsync(
	ctx context.Context,
	key, _ string,
	caller registry.Management,
	method string,
	input json.RawMessage,
	onUpdate func(string, string, string, int64, string, *string, *string, bool) error,
) {
	role, ok := b.roles[caller]
	if !ok {
		code := registry.ErrCodeIdentityManagementForbidden
		_ = onUpdate("ENDORSE", "FAILED", "", 0, "", nil, &code, false)
		return
	}
	op, err := b.journal.Prepare(ctx, key, role, method, input)
	if err == nil && op != nil && op.Status == "PENDING" && b.BeforeBroadcast != nil {
		b.BeforeBroadcast(ctx, key)
	}
	for err == nil && op != nil {
		var val *string
		var blockNo int64
		var blockHash string
		if op.Commit != nil {
			c := op.Commit.Code
			val = &c
			blockNo = int64(op.Commit.Number)
			blockHash = op.Commit.Hash
		}
		if err = onUpdate(op.Stage, op.Status, op.TxID, blockNo, blockHash, val, op.FailureCode, false); err != nil {
			return
		}
		if op.Status != "PENDING" {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
		op, err = b.journal.Recover(ctx, key, nil)
	}
	// Transport failures leave the persisted request and original journal PENDING.
}

// Service provides synchronous pre-acceptance version checks, idempotent 202 acceptance,
// GET /v1/operations/{operationId} status projection, mTLS auditor scoping, crash recovery,
// and DUPLICATE_TXID-safe commit outcome recording.
type Service struct {
	db           *pgxpool.Pool
	deploymentID string
	rootMgmt     registry.Management
	backend      OperationSubmitBackend

	mu                    sync.RWMutex
	suppressVisibilityIDs map[string]bool
	deliveredOps          map[string]bool
	running               map[string]bool
	operationAuditors     map[registry.Management]bool
}

// NewService constructs a management operation Service bound to db, deploymentID, rootMgmt, and backend.
func NewService(db *pgxpool.Pool, deploymentID string, rootMgmt registry.Management, backend OperationSubmitBackend) *Service {
	return &Service{
		db:                    db,
		deploymentID:          deploymentID,
		rootMgmt:              rootMgmt,
		backend:               backend,
		suppressVisibilityIDs: make(map[string]bool),
		deliveredOps:          make(map[string]bool),
		running:               make(map[string]bool),
		operationAuditors:     make(map[registry.Management]bool),
	}
}

// NewFabricService opens a durable Service backed by an existing Fabric instance directory.
// The caller owns invoking the returned cleanup function and running RunRecovery.
func NewFabricService(ctx context.Context, dir string) (*Service, func(), error) {
	inst, err := fabric.OpenInstance(dir)
	if err != nil {
		return nil, nil, err
	}
	dep, err := inst.LoadDeployment()
	if err != nil {
		return nil, nil, err
	}
	db, err := inst.Database(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := EnsureSchema(ctx, db); err != nil {
		db.Close()
		return nil, nil, err
	}
	svc, _, err := NewFabricServiceWithDB(db, inst, dep)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	return svc, db.Close, nil
}

// NewFabricServiceWithDB constructs a Service and its FabricBackend using an already open pool and deployment.
func NewFabricServiceWithDB(db *pgxpool.Pool, inst *fabric.Instance, dep *fabric.Deployment) (*Service, *FabricBackend, error) {
	if db == nil || inst == nil || dep == nil {
		return nil, nil, fmt.Errorf("registrysvc: db, instance, and deployment are required")
	}
	backend, err := NewFabricBackend(fabric.NewJournal(inst, db, dep.DeploymentID))
	if err != nil {
		return nil, nil, err
	}
	return NewService(db, dep.DeploymentID, dep.Bootstrap.Root.Management, backend), backend, nil
}

// SetOperationAuditors installs exact, host-approved certificate bindings.
// A role asserted in headers or a certificate alone never grants operation audit access.
// An auditor may read only operations belonging to its own MSP.
func (s *Service) SetOperationAuditors(auditors []registry.Management) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operationAuditors = make(map[registry.Management]bool, len(auditors))
	for _, auditor := range auditors {
		if auditor.Valid() {
			s.operationAuditors[auditor] = true
		}
	}
}

// SetVisibilitySuppressed temporarily hides terminal commit fields for opID so
// GET /v1/operations/{operationId} reports PENDING/null until visibility is restored.
func (s *Service) SetVisibilitySuppressed(opID string, hidden bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hidden {
		s.suppressVisibilityIDs[opID] = true
	} else {
		delete(s.suppressVisibilityIDs, opID)
	}
}

// MarkDelivered records whether post-confirmation material delivery executed for opID.
func (s *Service) MarkDelivered(opID string, delivered bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveredOps[opID] = delivered
}

// IsDelivered reports whether post-confirmation material delivery ran for opID.
func (s *Service) IsDelivered(opID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deliveredOps[opID]
}

type operationAcceptRow struct {
	OperationID    string  `db:"operation_id"`
	Method         string  `db:"method"`
	TxID           string  `db:"tx_id"`
	Stage          string  `db:"stage"`
	Status         string  `db:"status"`
	ValidationCode *string `db:"validation_code"`
	FailureCode    *string `db:"failure_code"`
	BlockNumber    int64   `db:"block_no"`
	BlockHash      string  `db:"block_hash"`
	PayloadHash    string  `db:"payload_hash"`
	Delivered      bool    `db:"delivered"`
}

type operationOutcomeRow struct {
	Status         string  `db:"status"`
	ValidationCode *string `db:"validation_code"`
}

type operationOwnerRow struct {
	MSPID             string `db:"caller_msp_id"`
	CertificateSHA256 string `db:"caller_fingerprint"`
}

type pendingOperationRow struct {
	OperationKey      string `db:"operation_key"`
	OperationID       string `db:"operation_id"`
	CallerMSPID       string `db:"caller_msp_id"`
	CallerFingerprint string `db:"caller_fingerprint"`
	Method            string `db:"method"`
	RequestJSON       []byte `db:"request_json"`
}

// Accept submits a management operation with pre-acceptance expectedRevision validation
// and idempotency deduplication. Returns HTTP status (202 on accept/exact retry, 400/403/409/503
// on rejection), OperationView on 202, and structured error on rejection.
func (s *Service) Accept(
	ctx context.Context,
	opKey string,
	caller registry.Management,
	method string,
	input json.RawMessage,
	triggerBackend bool,
) (int, *OperationView, error) {
	if s == nil || s.db == nil {
		return http.StatusServiceUnavailable, nil, protocol.NewError(registry.ErrCodeStateUnavailable, "operation store unavailable")
	}
	if opKey == "" || method == "" {
		return http.StatusBadRequest, nil, protocol.NewError(registry.ErrCodeInvalidSchema, "operationKey and method required")
	}

	// Recovery accepts the complete dual-proof bundle, never raw caller-supplied ledger mutations.
	var recovery *protocol.RecoveryDualProofBundle
	hashInput := input
	if method == "RecoverIdentity" {
		var err error
		recovery, input, err = s.parseRecoveryRequest(input)
		if err != nil {
			return http.StatusForbidden, nil, err
		}
		hashInput, err = protocol.MarshalJCS(recovery)
		if err != nil {
			return http.StatusBadRequest, nil, err
		}
	}

	// Trust management endpoints are restricted to T (rootMgmt) at the HTTP boundary.
	if (method == "CertifyDomain" || method == "RevokeCertification" || method == "SetDomainStatus" || method == "UpdateAuthorityIdentity") &&
		s.rootMgmt.Valid() && caller != s.rootMgmt {
		return http.StatusForbidden, nil, protocol.NewError(registry.ErrCodeTrustManagementForbidden, fmt.Sprintf("caller %s not permitted for %s", caller, method))
	}

	var compactBuf bytes.Buffer
	if err := json.Compact(&compactBuf, input); err != nil {
		return http.StatusBadRequest, nil, protocol.WrapError(registry.ErrCodeInvalidSchema, "invalid JSON payload", err)
	}
	canonInput := compactBuf.Bytes()
	if recovery == nil {
		hashInput = canonInput
	}
	mat, err := json.Marshal([]string{s.deploymentID, caller.String(), registry.Channel, registry.Registry, method, string(hashInput)})
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	payloadHash := registry.Digest(mat)

	// 1. Check idempotency record first so exact retries return 202 with original operationId even after completion/failure.
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return http.StatusServiceUnavailable, nil, err
	}
	defer tx.Rollback(context.Background())

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, s.deploymentID+":"+opKey); err != nil {
		return http.StatusServiceUnavailable, nil, err
	}
	rows, err := tx.Query(ctx, `SELECT operation_id, method, tx_id, stage, status, validation_code, failure_code, block_no, block_hash, payload_hash, delivered
		FROM operations WHERE deployment_id=$1 AND operation_key=$2 FOR UPDATE`,
		s.deploymentID, opKey)
	if err != nil {
		return http.StatusServiceUnavailable, nil, err
	}
	existing, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[operationAcceptRow])
	if err == nil {
		if existing.PayloadHash != payloadHash {
			return http.StatusConflict, nil, protocol.NewError(registry.ErrCodeIdempotencyConflict, fmt.Sprintf("operationKey %q reused with different payload", opKey))
		}
		if err := tx.Commit(ctx); err != nil {
			return http.StatusServiceUnavailable, nil, err
		}
		view := OperationView{
			OperationID:    existing.OperationID,
			OperationKey:   opKey,
			Method:         existing.Method,
			TxID:           existing.TxID,
			Stage:          existing.Stage,
			Status:         existing.Status,
			ErrorCode:      existing.FailureCode,
			ValidationCode: existing.ValidationCode,
			BlockNumber:    existing.BlockNumber,
			BlockHash:      existing.BlockHash,
			Delivered:      existing.Delivered || s.IsDelivered(existing.OperationID),
		}
		if view.Status != "FAILED" {
			view.ErrorCode = nil
		}
		if triggerBackend && view.Status == "PENDING" && s.backend != nil {
			s.dispatch(opKey, view.OperationID, caller, method, canonInput)
		}
		return http.StatusAccepted, &view, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return http.StatusServiceUnavailable, nil, err
	}

	// 2. Pre-acceptance expectedRevision check BEFORE inserting operations row or creating proposal.
	if s.backend != nil {
		var revCheck struct {
			ExpectedRevision *uint64 `json:"expectedRevision"`
		}
		_ = json.Unmarshal(canonInput, &revCheck)
		if revCheck.ExpectedRevision != nil && *revCheck.ExpectedRevision > 0 {
			curRev, found, rErr := s.backend.CurrentRevision(ctx, method, canonInput)
			if rErr != nil {
				return http.StatusServiceUnavailable, nil, rErr
			}
			if found && curRev != *revCheck.ExpectedRevision {
				return http.StatusConflict, nil, protocol.NewError(registry.ErrCodeStateChanged,
					fmt.Sprintf("pre-acceptance revision conflict: expected %d, current %d", *revCheck.ExpectedRevision, curRev))
			}
		}
	}

	opID := s.deploymentID + ":" + opKey
	if recovery != nil {
		validator, ok := s.backend.(recoveryAuthorizer)
		if !ok {
			return http.StatusServiceUnavailable, nil, protocol.NewError(registry.ErrCodeStateUnavailable, "recovery authority verifier unavailable")
		}
		if err := validator.AuthorizeRecovery(ctx, caller, recovery); err != nil {
			return http.StatusForbidden, nil, err
		}
		if err := consumeRecoveryChallenge(ctx, tx, s.deploymentID, opID, recovery); err != nil {
			return http.StatusForbidden, nil, err
		}
	}

	txID := "pending:" + registry.Digest([]byte(opID))[:24]
	if _, err := tx.Exec(ctx, `INSERT INTO operations(
		deployment_id, operation_key, operation_id, caller_msp_id, caller_fingerprint,
		method, tx_id, block_no, block_hash, stage, status, validation_code, failure_code, payload_hash, request_json, updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,0,'','ACCEPT','PENDING',NULL,NULL,$8,$9,NOW())`,
		s.deploymentID, opKey, opID, caller.MSPID, caller.CertificateSHA256, method, txID, payloadHash, canonInput); err != nil {
		return http.StatusServiceUnavailable, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return http.StatusServiceUnavailable, nil, err
	}

	if triggerBackend && s.backend != nil {
		s.dispatch(opKey, opID, caller, method, canonInput)
	}

	return http.StatusAccepted, &OperationView{
		OperationID:  opID,
		OperationKey: opKey,
		Method:       method,
		TxID:         txID,
		Stage:        "ACCEPT",
		Status:       "PENDING",
	}, nil
}

// RecordOutcome updates an operation row monotonically while protecting terminal CONFIRMED
// and FAILED outcomes against late DUPLICATE_TXID overwrites. Only CONFIRMED opens delivery.
func (s *Service) RecordOutcome(
	ctx context.Context,
	opID, stage, statusStr, txID string,
	blockNo int64,
	blockHash string,
	valCode, failCode *string,
	delivered bool,
) error {
	if s == nil || s.db == nil {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())

	rows, err := tx.Query(ctx, `SELECT status, validation_code FROM operations WHERE deployment_id=$1 AND operation_id=$2 FOR UPDATE`,
		s.deploymentID, opID)
	if err != nil {
		return err
	}
	cur, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[operationOutcomeRow])
	if err != nil {
		return err
	}

	// DUPLICATE_TXID must never overwrite an existing terminal outcome.
	if (cur.Status == "CONFIRMED" || cur.Status == "FAILED") && valCode != nil && *valCode == "DUPLICATE_TXID" {
		return tx.Commit(ctx)
	}
	// Terminal FAILED outcome is immutable.
	if cur.Status == "FAILED" {
		return tx.Commit(ctx)
	}
	// Terminal CONFIRMED outcome preserves its original commit coordinates; only delivery may advance false -> true.
	if cur.Status == "CONFIRMED" {
		if statusStr == "CONFIRMED" && delivered {
			if _, err := tx.Exec(ctx, `UPDATE operations SET delivered=TRUE, updated_at=NOW() WHERE deployment_id=$1 AND operation_id=$2`,
				s.deploymentID, opID); err != nil {
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return err
			}
			s.MarkDelivered(opID, true)
			return nil
		}
		return tx.Commit(ctx)
	}

	// Normalize failureCode when not explicitly set.
	if statusStr == "FAILED" && failCode == nil {
		mapped := ErrCodeCommitInvalid
		if valCode != nil && *valCode == "MVCC_READ_CONFLICT" {
			mapped = registry.ErrCodeStateChanged
		} else if stage == "ENDORSE" {
			mapped = ErrCodeEndorsementRejected
		}
		failCode = &mapped
	}

	openDelivery := statusStr == "CONFIRMED" && delivered
	if _, err := tx.Exec(ctx, `UPDATE operations SET
		stage=$3, status=$4, tx_id=CASE WHEN $5<>'' THEN $5 ELSE tx_id END,
		block_no=$6, block_hash=$7, validation_code=$8, failure_code=$9, delivered=delivered OR $10, updated_at=NOW()
		WHERE deployment_id=$1 AND operation_id=$2`,
		s.deploymentID, opID, stage, statusStr, txID, blockNo, blockHash, valCode, failCode, openDelivery); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if openDelivery {
		s.MarkDelivered(opID, true)
	}
	return nil
}

// GetOperation returns the current OperationView for opID, masking terminal fields
// as PENDING/null while visibility is suppressed.
func (s *Service) GetOperation(ctx context.Context, opID string) (*OperationView, error) {
	if s == nil || s.db == nil {
		return nil, protocol.NewError(registry.ErrCodeStateUnavailable, "operation store unavailable")
	}
	rows, err := s.db.Query(ctx, `SELECT operation_id, operation_key, method, tx_id, stage, status, validation_code, failure_code, block_no, block_hash, delivered
		FROM operations WHERE deployment_id=$1 AND operation_id=$2`,
		s.deploymentID, opID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[OperationView])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, protocol.NewError(ErrCodeOperationUnknown, fmt.Sprintf("unknown operationId %q", opID))
	}
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	hidden := s.suppressVisibilityIDs[opID]
	s.mu.RUnlock()
	if hidden {
		out.Status = "PENDING"
		out.Stage = "SUBMIT"
		out.ErrorCode = nil
		out.ValidationCode = nil
		out.BlockNumber = 0
		out.BlockHash = ""
		out.Delivered = false
		return &out, nil
	}
	if out.Status != "FAILED" {
		out.ErrorCode = nil
	}
	out.Delivered = out.Delivered || s.IsDelivered(opID)
	return &out, nil
}

func (s *Service) dispatch(key, id string, caller registry.Management, method string, input json.RawMessage) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.submitPending(ctx, key, id, caller, method, input)
	}()
}

func (s *Service) submitPending(ctx context.Context, key, id string, caller registry.Management, method string, input json.RawMessage) {
	s.mu.Lock()
	if s.running[id] {
		s.mu.Unlock()
		return
	}
	s.running[id] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.running, id)
		s.mu.Unlock()
	}()

	if method == "RecoverIdentity" {
		if err := s.verifyRecoveryAdmission(ctx, key, id, caller, input); err != nil {
			if protocol.HasCode(err, registry.ErrCodeRecoveryProofInvalid) {
				code := registry.ErrCodeRecoveryProofInvalid
				_ = s.RecordOutcome(ctx, id, "ACCEPT", "FAILED", "", 0, "", nil, &code, false)
			}
			return
		}
	}
	s.backend.SubmitAsync(ctx, key, id, caller, method, input, func(stage, status, txID string, n int64, hash string, val, fail *string, delivered bool) error {
		return s.RecordOutcome(ctx, id, stage, status, txID, n, hash, val, fail, delivered)
	})
}

// ResumePending recovers requests accepted before a crash using their exact persisted input.
func (s *Service) ResumePending(ctx context.Context) error {
	if s.backend == nil {
		return fmt.Errorf("management submission backend unavailable")
	}
	rows, err := s.db.Query(ctx, `SELECT operation_key, operation_id, caller_msp_id, caller_fingerprint, method, request_json
		FROM operations WHERE deployment_id=$1 AND status='PENDING' AND request_json IS NOT NULL ORDER BY operation_key`,
		s.deploymentID)
	if err != nil {
		return err
	}
	pending, err := pgx.CollectRows(rows, pgx.RowToStructByName[pendingOperationRow])
	if err != nil {
		return err
	}
	// A temporarily invisible original transaction must not block unrelated recovery.
	var workers sync.WaitGroup
	slots := make(chan struct{}, 4)
	for _, item := range pending {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			workers.Wait()
			return ctx.Err()
		}
		v := item
		workers.Go(func() {
			defer func() { <-slots }()
			attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			caller := registry.Management{MSPID: v.CallerMSPID, CertificateSHA256: v.CallerFingerprint}
			s.submitPending(attempt, v.OperationKey, v.OperationID, caller, v.Method, v.RequestJSON)
		})
	}
	workers.Wait()
	return ctx.Err()
}

// RunRecovery is a host-owned durable queue consumer that continuously resumes pending operations.
func (s *Service) RunRecovery(ctx context.Context) error {
	for {
		if err := s.ResumePending(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s *Service) managementCaller(r *http.Request) (registry.Management, bool) {
	id, authenticated := mtls.Caller(r)
	if !authenticated || id.Fingerprint == "" {
		return registry.Management{}, false
	}
	caller := registry.Management{MSPID: id.MSPID, CertificateSHA256: id.Fingerprint}
	if resolver, ok := s.backend.(interface {
		ManagementForFingerprint(string) (registry.Management, bool)
	}); ok {
		if resolved, found := resolver.ManagementForFingerprint(id.Fingerprint); found {
			return resolved, resolved.Valid()
		}
		// Audit credentials need not have access to a Fabric signing key.
		s.mu.RLock()
		defer s.mu.RUnlock()
		for auditor := range s.operationAuditors {
			if auditor.CertificateSHA256 == id.Fingerprint {
				return auditor, true
			}
		}
		return registry.Management{}, false
	}
	return caller, caller.Valid()
}

func (s *Service) authorizeOperationQuery(ctx context.Context, opID string, caller registry.Management) error {
	rows, err := s.db.Query(ctx, `SELECT caller_msp_id, caller_fingerprint FROM operations WHERE deployment_id=$1 AND operation_id=$2`,
		s.deploymentID, opID)
	if err != nil {
		return err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[operationOwnerRow])
	if errors.Is(err, pgx.ErrNoRows) {
		// Authenticated callers retain the ordinary 404 for unknown IDs.
		return nil
	}
	if err != nil {
		return err
	}
	owner := registry.Management{MSPID: row.MSPID, CertificateSHA256: row.CertificateSHA256}
	if caller == owner {
		return nil
	}
	s.mu.RLock()
	allowed := s.operationAuditors[caller] && caller.MSPID == owner.MSPID
	s.mu.RUnlock()
	if !allowed {
		return errOperationQueryForbidden
	}
	return nil
}

// Handler exposes POST /v1/management/{method} and GET /v1/operations/{operationId}
// wrapped with X-Request-Id propagation and unified httpx error envelopes.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/operations/{operationId...}", s.handleGetOperation)
	mux.HandleFunc("POST /v1/management/{method}", s.handlePostManagement)
	return httpx.WithRequestID(mux)
}

func (s *Service) handleGetOperation(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	caller, authenticated := s.managementCaller(r)
	if !authenticated {
		httpx.WriteError(w, http.StatusForbidden, reqID, registry.ErrCodeIdentityManagementForbidden, nil, "verified mTLS management caller required")
		return
	}
	opID := r.PathValue("operationId")
	if opID == "" {
		httpx.WriteError(w, http.StatusBadRequest, reqID, registry.ErrCodeInvalidSchema, nil, "missing operationId")
		return
	}
	if err := s.authorizeOperationQuery(r.Context(), opID, caller); err != nil {
		if errors.Is(err, errOperationQueryForbidden) {
			httpx.WriteError(w, http.StatusForbidden, reqID, registry.ErrCodeIdentityManagementForbidden, nil, "operation query forbidden")
		} else {
			httpx.WriteError(w, http.StatusServiceUnavailable, reqID, registry.ErrCodeStateUnavailable, nil, "operation authorization store unavailable")
		}
		return
	}
	view, err := s.GetOperation(r.Context(), opID)
	if err != nil {
		if protocol.HasCode(err, ErrCodeOperationUnknown) {
			httpx.WriteError(w, http.StatusNotFound, reqID, ErrCodeOperationUnknown, nil, err.Error())
			return
		}
		code := protocol.CodeOf(err)
		if code == "" {
			code = registry.ErrCodeStateUnavailable
		}
		httpx.WriteError(w, http.StatusServiceUnavailable, reqID, code, nil, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

func (s *Service) handlePostManagement(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	caller, authenticated := s.managementCaller(r)
	if !authenticated {
		httpx.WriteError(w, http.StatusForbidden, reqID, registry.ErrCodeIdentityManagementForbidden, nil, "verified mTLS management caller required")
		return
	}
	if s.backend == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, reqID, registry.ErrCodeStateUnavailable, nil, "management submission backend unavailable")
		return
	}
	body, err := httpx.ReadBoundedBody(r, protocol.MaxJSONBytes)
	if err != nil {
		switch {
		case errors.Is(err, httpx.ErrUnsupportedMediaType):
			httpx.WriteError(w, http.StatusUnsupportedMediaType, reqID, registry.ErrCodeUnsupportedMediaType, nil, err.Error())
		case errors.Is(err, httpx.ErrPayloadTooLarge):
			httpx.WriteError(w, http.StatusRequestEntityTooLarge, reqID, registry.ErrCodePayloadTooLarge, nil, err.Error())
		default:
			httpx.WriteError(w, http.StatusBadRequest, reqID, registry.ErrCodeInvalidSchema, nil, err.Error())
		}
		return
	}
	if len(bytes.TrimSpace(body)) == 0 || !json.Valid(body) {
		httpx.WriteError(w, http.StatusBadRequest, reqID, registry.ErrCodeInvalidSchema, nil, "invalid JSON request body")
		return
	}
	method := r.PathValue("method")
	opKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	status, view, err := s.Accept(r.Context(), opKey, caller, method, json.RawMessage(body), true)
	if err != nil {
		errCode := protocol.CodeOf(err)
		if errCode == "" {
			if status >= http.StatusInternalServerError {
				errCode = registry.ErrCodeStateUnavailable
			} else {
				errCode = registry.ErrCodeInvalidSchema
			}
		}
		httpx.WriteError(w, status, reqID, errCode, nil, err.Error())
		return
	}
	httpx.WriteJSON(w, status, view)
}
