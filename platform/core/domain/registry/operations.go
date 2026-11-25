// Package registry implements management operation admission and status projection,
// identity registration and recovery dual-proof coordination, and controlled outbox/receipt
// delivery synchronization backed by PostgreSQL.
package registry

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/core/dao"
	"grad/platform/core/ledger"
	"grad/protocol"
	preg "grad/protocol/registry"
)

var errOperationQueryForbidden = errors.New("operation query forbidden")

// EnsureSchema applies embedded PostgreSQL migrations required by registry tables.
func EnsureSchema(ctx context.Context, db *pgxpool.Pool) error {
	return dao.Up(ctx, db)
}

// OperationView represents the management operation status projection returned on
// admission and status queries.
type OperationView struct {
	OperationID      string  `json:"operationId" db:"operation_id"`
	OperationKey     string  `json:"operationKey" db:"operation_key"`
	Method           string  `json:"method" db:"method"`
	TxID             string  `json:"txId" db:"tx_id"`
	Stage            string  `json:"stage" db:"stage"`
	Status           string  `json:"status" db:"status"`
	FailureCode      *string `json:"failureCode" db:"failure_code"`
	ValidationCode   *string `json:"validationCode" db:"validation_code"`
	BlockNumber      int64   `json:"blockNumber" db:"block_no"`
	BlockHash        string  `json:"blockHash,omitempty" db:"block_hash"`
	TransactionIndex *int    `json:"transactionIndex" db:"transaction_index"`
	ObservedPeer     *string `json:"observedPeer" db:"observed_peer"`
	Delivered        bool    `json:"delivered" db:"delivered"`
}

// OutcomeHandler persists the latest journal observation for an accepted operation.
type OutcomeHandler func(stage, status, txID string, commit *ledger.Outcome, failure *string, delivered bool) error

// OperationSubmitBackend executes pre-acceptance revision lookup and asynchronous
// endorse/broadcast/commit recovery steps on behalf of Service.
type OperationSubmitBackend interface {
	CurrentRevision(ctx context.Context, kind, id string) (uint64, bool, error)
	SubmitAsync(
		ctx context.Context,
		opKey, opID string,
		caller preg.Management,
		method string,
		input json.RawMessage,
		onUpdate OutcomeHandler,
	)
}

// FabricBackend bridges Service to ledger.Journal using the original-transaction journal.
type FabricBackend struct {
	journal         ledger.Journal
	roles           map[preg.Management]string
	BeforeBroadcast func(context.Context, string)
}

// NewFabricBackend constructs a FabricBackend indexed by all configured local Fabric role certificates.
func NewFabricBackend(j ledger.Journal) (*FabricBackend, error) {
	return newFabricBackend(j, ledger.AllRoles())
}

func newFabricBackend(j ledger.Journal, roles []string) (*FabricBackend, error) {
	if j.Instance == nil {
		return nil, fmt.Errorf("registry: fabric instance is required")
	}
	b := &FabricBackend{
		journal: j,
		roles:   make(map[preg.Management]string),
	}
	for _, role := range roles {
		_, caller, _, err := j.Instance.Role(role)
		if err != nil {
			return nil, err
		}
		b.roles[caller] = role
	}
	return b, nil
}

// ManagementForFingerprint resolves a verified mTLS certificate fingerprint to its bound Fabric Management identity.
func (b *FabricBackend) ManagementForFingerprint(fp string) (preg.Management, bool) {
	for caller := range b.roles {
		if caller.CertificateSHA256 == fp {
			return caller, true
		}
	}
	return preg.Management{}, false
}

// AuthorizeRecovery validates the current domain registrar and approved new management certificate
// against trusted Fabric ledger state and the target domain's MSP CA certificates.
func (b *FabricBackend) AuthorizeRecovery(ctx context.Context, caller preg.Management, bundle *protocol.RecoveryDualProofBundle) error {
	c := bundle.Challenge
	p, err := b.journal.Instance.ReadPeer()
	if err != nil {
		return err
	}
	defer p.Close()

	domain, err := ledger.ReadLedgerRecord[preg.Domain](ctx, p, "domain", c.DomainID)
	if err != nil {
		if ledger.IsMissingRecord(err) {
			return protocol.WrapError(preg.ErrCodeRecoveryProofInvalid, "recovery domain missing", err)
		}
		return err
	}
	if caller != domain.Registrar || c.NewManagementIdentity.MSPID != domain.ID+"Msp" {
		return protocol.NewError(preg.ErrCodeIdentityManagementForbidden, "current domain registrar required")
	}
	id, err := ledger.ReadLedgerRecord[preg.Identity](ctx, p, "identity", c.SubjectID)
	if err != nil {
		if ledger.IsMissingRecord(err) {
			return protocol.WrapError(preg.ErrCodeRecoveryProofInvalid, "recovery subject missing", err)
		}
		return err
	}
	if id.Domain != domain.ID || (id.Kind != "USER" && id.Kind != "AGENT" && id.Kind != "SERVICE") ||
		(id.Status != preg.Active && id.Status != preg.Suspended) || id.Management != recoveryMutation(c).OldManagement ||
		id.AccountCommitment != c.AccountCommitment || id.KeyVersion != c.ExpectedKeyVersion {
		return protocol.NewError(preg.ErrCodeRecoveryProofInvalid, "recovery approval does not match current ordinary identity")
	}
	certification, err := ledger.ReadLedgerRecord[preg.Certification](ctx, p, "certification", domain.Certification)
	if err != nil {
		if ledger.IsMissingRecord(err) {
			return protocol.WrapError(preg.ErrCodeRecoveryProofInvalid, "domain certification missing", err)
		}
		return err
	}
	if domain.Status != preg.Active || certification.Status != preg.Active ||
		!certification.Interval.Current(time.Now(), preg.PeerTimeWindow+preg.ClockError) {
		return protocol.NewError(preg.ErrCodeRecoveryProofInvalid, "domain qualification inactive")
	}
	switch domain.ID {
	case "A", "B", "C":
	default:
		return protocol.NewError(preg.ErrCodeRecoveryProofInvalid, "unknown recovery domain")
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
		return protocol.NewError(preg.ErrCodeStateUnavailable, "recovery MSP CA unavailable")
	}
	der, err := protocol.DecodeStrictBase64URL(bundle.NewManagementCertificateDER)
	if err != nil {
		return protocol.WrapError(preg.ErrCodeRecoveryProofInvalid, "decode new management certificate", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return protocol.WrapError(preg.ErrCodeRecoveryProofInvalid, "parse new management certificate", err)
	}
	return verifyAuthorizedMgmtCert(leaf, authorized)
}

func revisionTarget(method string, input json.RawMessage) (string, string, *uint64, error) {
	var v struct {
		ID               string             `json:"id"`
		SubjectID        string             `json:"subjectId"`
		DomainID         string             `json:"domainId"`
		ExpectedRevision *uint64            `json:"expectedRevision"`
		Old              preg.Mutation      `json:"old"`
		Certification    preg.Certification `json:"certification"`
	}
	if err := json.Unmarshal(input, &v); err != nil {
		return "", "", nil, err
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
	case "ReplaceGrant":
		return "grant", v.Old.ID, &v.Old.ExpectedRevision, nil
	case "RevokeGrant", "SuspendGrant", "ResumeGrant":
		kind = "grant"
	case "ApproveIdentityLink", "RevokeIdentityLink":
		kind = "link"
	default:
		return "", "", nil, nil
	}
	return kind, id, v.ExpectedRevision, nil
}

// CurrentRevision queries the pinned peer for the current record revision.
func (b *FabricBackend) CurrentRevision(ctx context.Context, kind, id string) (uint64, bool, error) {
	p, err := b.journal.Instance.ReadPeer()
	if err != nil {
		return 0, false, err
	}
	defer p.Close()
	version, err := ledger.ReadLedgerRecord[preg.Version](ctx, p, kind, id)
	if err != nil {
		if ledger.IsMissingRecord(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return version.Revision, true, nil
}

// SubmitAsync prepares, endorses, broadcasts, and observes the original Fabric transaction via ledger.Journal.
func (b *FabricBackend) SubmitAsync(
	ctx context.Context,
	key, opID string,
	caller preg.Management,
	method string,
	input json.RawMessage,
	onUpdate OutcomeHandler,
) {
	role, ok := b.roles[caller]
	if !ok {
		code := preg.ErrCodeIdentityManagementForbidden
		_ = onUpdate("ENDORSE", "FAILED", "", nil, &code, false)
		return
	}
	op, err := b.journal.Prepare(ctx, opID, role, method, input)
	if err == nil && op != nil && op.Status == "PENDING" && b.BeforeBroadcast != nil {
		b.BeforeBroadcast(ctx, key)
	}
	for err == nil && op != nil {
		if err = onUpdate(op.Stage, op.Status, op.TxID, op.Commit, op.FailureCode, false); err != nil {
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
		op, err = b.journal.Recover(ctx, opID, nil)
	}
	// Transport failures leave the persisted request and original journal PENDING.
}

// Service provides synchronous pre-acceptance version checks, idempotent admission,
// operation status projection, auditor scoping, crash recovery, and DUPLICATE_TXID-safe
// commit outcome recording.
type Service struct {
	db           *pgxpool.Pool
	deploymentID string
	rootMgmt     preg.Management
	backend      OperationSubmitBackend

	mu                    sync.RWMutex
	suppressVisibilityIDs map[string]bool
	deliveredOps          map[string]bool
	running               map[string]bool
	operationAuditors     map[preg.Management]bool
}

// NewService constructs a management operation Service bound to db, deploymentID, rootMgmt, and backend.
func NewService(db *pgxpool.Pool, deploymentID string, rootMgmt preg.Management, backend OperationSubmitBackend) *Service {
	return &Service{
		db:                    db,
		deploymentID:          deploymentID,
		rootMgmt:              rootMgmt,
		backend:               backend,
		suppressVisibilityIDs: make(map[string]bool),
		deliveredOps:          make(map[string]bool),
		running:               make(map[string]bool),
		operationAuditors:     make(map[preg.Management]bool),
	}
}

// NewFabricService opens a durable Service backed by an existing Fabric instance directory.
// The caller owns invoking the returned cleanup function and running RunRecovery.
func NewFabricService(ctx context.Context, dir string) (*Service, func(), error) {
	inst, err := ledger.OpenInstance(dir)
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
func NewFabricServiceWithDB(db *pgxpool.Pool, inst *ledger.Instance, dep *ledger.Deployment) (*Service, *FabricBackend, error) {
	return NewFabricServiceForRoles(db, inst, dep, ledger.AllRoles())
}

// NewFabricServiceForRoles binds the management service to the configured local signers.
func NewFabricServiceForRoles(db *pgxpool.Pool, inst *ledger.Instance, dep *ledger.Deployment, roles []string) (*Service, *FabricBackend, error) {
	if db == nil || inst == nil || dep == nil {
		return nil, nil, fmt.Errorf("registry: db, instance, and deployment are required")
	}
	backend, err := newFabricBackend(ledger.NewJournal(inst, db, dep.DeploymentID), roles)
	if err != nil {
		return nil, nil, err
	}
	return NewService(db, dep.DeploymentID, dep.Bootstrap.Root.Management, backend), backend, nil
}

// HasBackend reports whether the service has a configured submission backend.
func (s *Service) HasBackend() bool {
	return s != nil && s.backend != nil
}

// SetOperationAuditors installs exact, host-approved certificate bindings.
// A role asserted in headers or a certificate alone never grants operation audit access.
// An auditor may read only operations belonging to its own MSP.
func (s *Service) SetOperationAuditors(auditors []preg.Management) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.operationAuditors = make(map[preg.Management]bool, len(auditors))
	for _, auditor := range auditors {
		if auditor.Valid() {
			s.operationAuditors[auditor] = true
		}
	}
}

// ResolveManagementCaller resolves an authenticated mTLS certificate fingerprint and MSP ID
// to a bound management identity via the backend signer table or approved operation auditors.
func (s *Service) ResolveManagementCaller(fingerprint, mspID string) (preg.Management, bool) {
	if s == nil || fingerprint == "" {
		return preg.Management{}, false
	}
	caller := preg.Management{MSPID: mspID, CertificateSHA256: fingerprint}
	if resolver, ok := s.backend.(interface {
		ManagementForFingerprint(string) (preg.Management, bool)
	}); ok {
		if resolved, found := resolver.ManagementForFingerprint(fingerprint); found {
			return resolved, resolved.Valid()
		}
		// Audit credentials need not have access to a Fabric signing key.
		s.mu.RLock()
		defer s.mu.RUnlock()
		for auditor := range s.operationAuditors {
			if auditor.CertificateSHA256 == fingerprint {
				return auditor, true
			}
		}
		return preg.Management{}, false
	}
	return caller, caller.Valid()
}

// IsOperationAuditor reports whether the exact (mspID, fingerprint) binding is registered
// as an approved operation auditor.
func (s *Service) IsOperationAuditor(fingerprint, mspID string) bool {
	if s == nil || fingerprint == "" || mspID == "" {
		return false
	}
	candidate := preg.Management{MSPID: mspID, CertificateSHA256: fingerprint}
	if !candidate.Valid() {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.operationAuditors[candidate]
}

// SetVisibilitySuppressed temporarily hides terminal commit fields for opID so
// status queries report PENDING/null until visibility is restored.
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
	OperationView
	PayloadHash string `db:"payload_hash"`
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

// ManagementOperationID identifies a management operation and its Fabric journal entry.
// Each method has one route within the deployment and authenticated caller scope.
func ManagementOperationID(deployment string, caller preg.Management, method, key string) string {
	scope, _ := json.Marshal([]string{deployment, caller.MSPID, caller.CertificateSHA256, method, key})
	return "management:" + preg.Digest(scope)
}

// Submit accepts a typed management request using the same journal as the API layer.
func (s *Service) Submit(ctx context.Context, caller preg.Management, method, key string, input any) (*OperationView, error) {
	if !caller.Valid() {
		return nil, protocol.NewError(preg.ErrCodeIdentityManagementForbidden, "verified management caller required")
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, protocol.WrapError(preg.ErrCodeInvalidSchema, "encode management request", err)
	}
	return s.Accept(ctx, key, caller, method, raw, true)
}

// Operation reads the original transaction for its owner or an authorized local auditor.
func (s *Service) Operation(ctx context.Context, caller preg.Management, opID string) (*OperationView, error) {
	if s == nil || s.db == nil {
		return nil, protocol.NewError(preg.ErrCodeStateUnavailable, "operation store unavailable")
	}
	if !caller.Valid() {
		return nil, protocol.NewError(preg.ErrCodeIdentityManagementForbidden, "verified management caller required")
	}
	if err := s.authorizeOperationQuery(ctx, opID, caller); err != nil {
		if errors.Is(err, errOperationQueryForbidden) {
			return nil, protocol.NewError(preg.ErrCodeIdentityManagementForbidden, "operation query forbidden")
		}
		return nil, protocol.WrapError(preg.ErrCodeStateUnavailable, "operation authorization store unavailable", err)
	}
	return s.GetOperation(ctx, opID)
}

// Accept submits a management operation with pre-acceptance expectedRevision validation
// and idempotency deduplication. Returns the accepted or deduplicated OperationView on success,
// or a typed protocol.Error on rejection.
func (s *Service) Accept(
	ctx context.Context,
	opKey string,
	caller preg.Management,
	method string,
	input json.RawMessage,
	triggerBackend bool,
) (*OperationView, error) {
	if s == nil || s.db == nil {
		return nil, protocol.NewError(preg.ErrCodeStateUnavailable, "operation store unavailable")
	}
	if opKey == "" || method == "" {
		return nil, protocol.NewError(preg.ErrCodeInvalidSchema, "operationKey and method required")
	}

	// Recovery accepts the complete dual-proof bundle, never raw caller-supplied ledger mutations.
	var recovery *protocol.RecoveryDualProofBundle
	hashInput := input
	if method == "RecoverIdentity" {
		var err error
		recovery, input, err = s.parseRecoveryRequest(input)
		if err != nil {
			return nil, err
		}
		hashInput, err = protocol.MarshalJCS(recovery)
		if err != nil {
			if protocol.CodeOf(err) == "" {
				return nil, protocol.WrapError(preg.ErrCodeInvalidSchema, "canonicalize recovery bundle", err)
			}
			return nil, err
		}
	}

	// Trust management endpoints are restricted to T (rootMgmt) at the admission boundary.
	if (method == "CertifyDomain" || method == "RevokeCertification" || method == "SetDomainStatus" || method == "UpdateAuthorityIdentity") &&
		s.rootMgmt.Valid() && caller != s.rootMgmt {
		return nil, protocol.NewError(preg.ErrCodeTrustManagementForbidden, fmt.Sprintf("caller %s not permitted for %s", caller, method))
	}

	canonInput, err := protocol.CanonicalizeJSON(input)
	if err != nil {
		if protocol.CodeOf(err) == "" {
			return nil, protocol.WrapError(preg.ErrCodeInvalidSchema, "canonicalize management request", err)
		}
		return nil, err
	}
	if recovery == nil {
		hashInput = canonInput
	}
	payloadHash := preg.Digest(hashInput)
	opID := ManagementOperationID(s.deploymentID, caller, method, opKey)

	var (
		view    OperationView
		matched bool
	)
	err = dao.RunInTx(ctx, s.db, func(tx dao.Tx) error {
		// 1. Check idempotency record first so exact retries return the original operationId even after completion/failure.
		if err := tx.AdvisoryXactLock(ctx, opID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT operation_id, operation_key, method, tx_id, stage, status, validation_code, failure_code, block_no, block_hash, transaction_index, observed_peer, payload_hash, delivered
			FROM operations WHERE deployment_id=$1 AND caller_msp_id=$2 AND caller_fingerprint=$3 AND method=$4 AND operation_key=$5 FOR UPDATE`,
			s.deploymentID, caller.MSPID, caller.CertificateSHA256, method, opKey)
		if err != nil {
			return err
		}
		existing, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[operationAcceptRow])
		if err == nil {
			if existing.PayloadHash != payloadHash {
				return protocol.NewError(preg.ErrCodeIdempotencyConflict, fmt.Sprintf("operationKey %q reused with different payload", opKey))
			}
			view = existing.OperationView
			matched = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		// 2. Pre-acceptance expectedRevision check BEFORE inserting operations row or creating proposal.
		if s.backend != nil {
			kind, id, expected, err := revisionTarget(method, canonInput)
			if err != nil {
				return protocol.WrapError(preg.ErrCodeInvalidSchema, "invalid revision target", err)
			}
			if expected != nil {
				curRev, found, rErr := s.backend.CurrentRevision(ctx, kind, id)
				if rErr != nil {
					if protocol.CodeOf(rErr) == "" {
						return protocol.WrapError(preg.ErrCodeStateUnavailable, "current revision lookup failed", rErr)
					}
					return rErr
				}
				if found && curRev != *expected {
					return protocol.NewError(preg.ErrCodeStateChanged,
						fmt.Sprintf("pre-acceptance revision conflict: expected %d, current %d", *expected, curRev))
				}
			}
		}

		if recovery != nil {
			validator, ok := s.backend.(recoveryAuthorizer)
			if !ok {
				return protocol.NewError(preg.ErrCodeStateUnavailable, "recovery authority verifier unavailable")
			}
			if err := validator.AuthorizeRecovery(ctx, caller, recovery); err != nil {
				return err
			}
			if err := consumeRecoveryChallenge(ctx, tx, s.deploymentID, opID, recovery); err != nil {
				return err
			}
		}

		txID := "pending:" + preg.Digest([]byte(opID))[:24]
		if _, err := tx.Exec(ctx, `INSERT INTO operations(
			deployment_id, operation_key, operation_id, caller_msp_id, caller_fingerprint,
			method, tx_id, block_no, block_hash, stage, status, validation_code, failure_code, payload_hash, request_json, updated_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,0,'','ACCEPT','PENDING',NULL,NULL,$8,$9,NOW())`,
			s.deploymentID, opKey, opID, caller.MSPID, caller.CertificateSHA256, method, txID, payloadHash, canonInput); err != nil {
			return err
		}

		view = OperationView{
			OperationID:  opID,
			OperationKey: opKey,
			Method:       method,
			TxID:         txID,
			Stage:        "ACCEPT",
			Status:       "PENDING",
		}
		return nil
	})
	if err != nil {
		if protocol.CodeOf(err) == "" {
			return nil, protocol.WrapError(preg.ErrCodeStateUnavailable, "accept management operation", err)
		}
		return nil, err
	}

	if matched {
		view.Delivered = view.Delivered || s.IsDelivered(view.OperationID)
		if view.Status != "FAILED" {
			view.FailureCode = nil
		}
		if triggerBackend && view.Status == "PENDING" && s.backend != nil {
			s.dispatch(opKey, view.OperationID, caller, method, canonInput)
		}
		return &view, nil
	}

	if triggerBackend && s.backend != nil {
		s.dispatch(opKey, opID, caller, method, canonInput)
	}
	return &view, nil
}

func hasValidCommit(txID string, commit *ledger.Outcome) bool {
	return txID != "" && commit != nil && commit.Code == "VALID" && commit.Hash != "" && commit.ObservedPeer != ""
}

// RecordOutcome updates an operation row monotonically while protecting terminal CONFIRMED
// and FAILED outcomes against late DUPLICATE_TXID overwrites. Only CONFIRMED opens delivery.
func (s *Service) RecordOutcome(
	ctx context.Context,
	opID, stage, statusStr, txID string,
	commit *ledger.Outcome,
	failCode *string,
	delivered bool,
) error {
	if s == nil || s.db == nil {
		return nil
	}
	markDelivered := false
	err := dao.RunInTx(ctx, s.db, func(tx dao.Tx) error {
		rows, err := tx.Query(ctx, `SELECT status, validation_code FROM operations WHERE deployment_id=$1 AND operation_id=$2 FOR UPDATE`,
			s.deploymentID, opID)
		if err != nil {
			return err
		}
		cur, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[operationOutcomeRow])
		if err != nil {
			return err
		}

		var blockNo uint64
		var blockHash string
		var valCode, observedPeer *string
		var index *int
		if commit != nil {
			blockNo, blockHash = commit.Number, commit.Hash
			valCode, observedPeer, index = &commit.Code, &commit.ObservedPeer, &commit.Index
		}

		// DUPLICATE_TXID must never overwrite an existing terminal outcome.
		if (cur.Status == "CONFIRMED" || cur.Status == "FAILED") && valCode != nil && *valCode == "DUPLICATE_TXID" {
			return nil
		}
		// Terminal FAILED outcome is immutable.
		if cur.Status == "FAILED" {
			return nil
		}
		// Terminal CONFIRMED outcome preserves its original commit coordinates; only delivery may advance false -> true.
		if cur.Status == "CONFIRMED" {
			if statusStr == "CONFIRMED" && delivered {
				if _, err := tx.Exec(ctx, `UPDATE operations SET delivered=TRUE, updated_at=NOW() WHERE deployment_id=$1 AND operation_id=$2`,
					s.deploymentID, opID); err != nil {
					return err
				}
				markDelivered = true
			}
			return nil
		}

		if statusStr == "CONFIRMED" && !hasValidCommit(txID, commit) {
			return protocol.NewError(preg.ErrCodeInvalidState, "confirmed operation requires original VALID commit evidence")
		}

		// Normalize failureCode when not explicitly set.
		if statusStr == "FAILED" && failCode == nil {
			mapped := preg.ErrCodeCommitInvalid
			if valCode != nil && *valCode == "MVCC_READ_CONFLICT" {
				mapped = preg.ErrCodeStateChanged
			} else if stage == "ENDORSE" {
				mapped = preg.ErrCodeEndorsementRejected
			}
			failCode = &mapped
		}

		openDelivery := statusStr == "CONFIRMED" && delivered
		if _, err := tx.Exec(ctx, `UPDATE operations SET
			stage=$3, status=$4, tx_id=CASE WHEN $5<>'' THEN $5 ELSE tx_id END,
			block_no=$6, block_hash=$7, validation_code=$8, failure_code=$9, delivered=delivered OR $10, transaction_index=$11, observed_peer=$12, updated_at=NOW()
			WHERE deployment_id=$1 AND operation_id=$2`,
			s.deploymentID, opID, stage, statusStr, txID, blockNo, blockHash, valCode, failCode, openDelivery, index, observedPeer); err != nil {
			return err
		}
		markDelivered = openDelivery
		return nil
	})
	if err != nil {
		return err
	}
	if markDelivered {
		s.MarkDelivered(opID, true)
	}
	return nil
}

// GetOperation returns the current OperationView for opID, masking terminal fields
// as PENDING/null while visibility is suppressed.
func (s *Service) GetOperation(ctx context.Context, opID string) (*OperationView, error) {
	if s == nil || s.db == nil {
		return nil, protocol.NewError(preg.ErrCodeStateUnavailable, "operation store unavailable")
	}
	rows, err := s.db.Query(ctx, `SELECT operation_id, operation_key, method, tx_id, stage, status, validation_code, failure_code, block_no, block_hash, transaction_index, observed_peer, delivered
		FROM operations WHERE deployment_id=$1 AND operation_id=$2`,
		s.deploymentID, opID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[OperationView])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, protocol.NewError(preg.ErrCodeOperationUnknown, fmt.Sprintf("unknown operationId %q", opID))
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
		out.FailureCode = nil
		out.ValidationCode = nil
		out.BlockNumber = 0
		out.BlockHash = ""
		out.TransactionIndex = nil
		out.ObservedPeer = nil
		out.Delivered = false
		return &out, nil
	}
	if out.Status != "FAILED" {
		out.FailureCode = nil
	}
	out.Delivered = out.Delivered || s.IsDelivered(opID)
	return &out, nil
}

func (s *Service) dispatch(key, id string, caller preg.Management, method string, input json.RawMessage) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.submitPending(ctx, key, id, caller, method, input)
	}()
}

func (s *Service) submitPending(ctx context.Context, key, id string, caller preg.Management, method string, input json.RawMessage) {
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
			if protocol.HasCode(err, preg.ErrCodeRecoveryProofInvalid) {
				code := preg.ErrCodeRecoveryProofInvalid
				_ = s.RecordOutcome(ctx, id, "ACCEPT", "FAILED", "", nil, &code, false)
			}
			return
		}
	}
	s.backend.SubmitAsync(ctx, key, id, caller, method, input, func(stage, status, txID string, commit *ledger.Outcome, fail *string, delivered bool) error {
		return s.RecordOutcome(ctx, id, stage, status, txID, commit, fail, delivered)
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
			caller := preg.Management{MSPID: v.CallerMSPID, CertificateSHA256: v.CallerFingerprint}
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

func (s *Service) authorizeOperationQuery(ctx context.Context, opID string, caller preg.Management) error {
	rows, err := s.db.Query(ctx, `SELECT caller_msp_id, caller_fingerprint FROM operations WHERE deployment_id=$1 AND operation_id=$2`,
		s.deploymentID, opID)
	if err != nil {
		return err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[operationOwnerRow])
	if errors.Is(err, pgx.ErrNoRows) {
		// Authenticated callers retain the ordinary OPERATION_UNKNOWN error for unknown IDs.
		return nil
	}
	if err != nil {
		return err
	}
	owner := preg.Management{MSPID: row.MSPID, CertificateSHA256: row.CertificateSHA256}
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
