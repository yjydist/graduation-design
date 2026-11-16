package fabric

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

// journalOperationBackend uses the same original-transaction journal as ledgerctl invoke.
type journalOperationBackend struct {
	journal         journal
	roles           map[api.Management]string
	beforeBroadcast func(context.Context, string)
}

func newJournalOperationBackend(j journal) (*journalOperationBackend, error) {
	b := &journalOperationBackend{journal: j, roles: make(map[api.Management]string)}
	for role := range roles {
		_, caller, _, err := j.instance.role(role)
		if err != nil {
			return nil, err
		}
		b.roles[caller] = role
	}
	return b, nil
}

// NewFabricManagementOperationService opens a durable service for an existing deployment.
// Its host runs RunRecovery and mounts Handler behind verified client-certificate TLS.
func NewFabricManagementOperationService(ctx context.Context, dir string) (*ManagementOperationService, func(), error) {
	i, err := loadInstance(dir)
	if err != nil {
		return nil, nil, err
	}
	d, err := i.loadDeployment()
	if err != nil {
		return nil, nil, err
	}
	db, err := i.database(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err = initSchema(ctx, db, operationsSchema); err != nil {
		db.Close()
		return nil, nil, err
	}
	s, err := newFabricManagementService(db, i, d)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	return s, db.Close, nil
}

func newFabricManagementService(db *pgxpool.Pool, i *instance, d *deployment) (*ManagementOperationService, error) {
	b, err := newJournalOperationBackend(journal{instance: i, db: db, deploymentID: d.DeploymentID})
	if err != nil {
		return nil, err
	}
	return NewManagementOperationService(db, d.DeploymentID, d.Bootstrap.Root.Management, b), nil
}

func (b *journalOperationBackend) ManagementForFingerprint(fp string) (api.Management, bool) {
	for caller := range b.roles {
		if caller.Fingerprint == fp {
			return caller, true
		}
	}
	return api.Management{}, false
}

// AuthorizeRecovery checks the current registrar and the approved new certificate
// against trusted ledger facts and the target domain's MSP, never HTTP fields.
func (b *journalOperationBackend) AuthorizeRecovery(ctx context.Context, caller api.Management, bundle *protocol.RecoveryDualProofBundle) error {
	c := bundle.Challenge
	p, err := b.journal.instance.peer("c", "read")
	if err != nil {
		return err
	}
	defer p.close()
	domain, err := ledgerRecord[api.Domain](ctx, p, "domain", c.DomainID)
	if err != nil {
		return err
	}
	if caller != domain.Registrar || c.NewManagementIdentity.MSPID != domain.ID+"Msp" {
		return protocol.NewError(protocol.ErrCodeIdentityManagementForbidden, "current domain registrar required")
	}
	id, err := ledgerRecord[api.Identity](ctx, p, "identity", c.SubjectID)
	if err != nil {
		return err
	}
	if id.Domain != domain.ID || (id.Kind != "USER" && id.Kind != "AGENT" && id.Kind != "SERVICE") ||
		(id.Status != api.Active && id.Status != api.Suspended) || id.Management != recoveryMutation(c).OldManagement ||
		id.AccountCommitment != c.AccountCommitment || id.KeyVersion != c.ExpectedKeyVersion {
		return protocol.NewError(protocol.ErrCodeRecoveryProofInvalid, "recovery approval does not match current ordinary identity")
	}
	certification, err := ledgerRecord[api.Certification](ctx, p, "certification", domain.Certification)
	if err != nil {
		return err
	}
	if domain.Status != api.Active || certification.Status != api.Active || !certification.Interval.Current(time.Now(), api.PeerTimeWindow+api.ClockError) {
		return protocol.NewError(protocol.ErrCodeRecoveryProofInvalid, "domain qualification inactive")
	}
	switch domain.ID {
	case "A", "B", "C":
	default:
		return protocol.NewError(protocol.ErrCodeRecoveryProofInvalid, "unknown recovery domain")
	}
	paths, err := filepath.Glob(filepath.Join(b.journal.instance.orgDir(strings.ToLower(domain.ID)), "msp", "cacerts", "*.pem"))
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
		return protocol.NewError(protocol.ErrCodeStateUnavailable, "recovery MSP CA unavailable")
	}
	der, err := base64.RawURLEncoding.DecodeString(bundle.NewManagementCertificateDER)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	return verifyAuthorizedMgmtCert(leaf, authorized)
}

func (b *journalOperationBackend) CurrentRevision(ctx context.Context, method string, input json.RawMessage) (uint64, bool, error) {
	var v struct {
		ID            string            `json:"id"`
		SubjectID     string            `json:"subjectId"`
		DomainID      string            `json:"domainId"`
		Certification api.Certification `json:"certification"`
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
	default:
		return 0, false, nil
	}
	p, err := b.journal.instance.peer("c", "read")
	if err != nil {
		return 0, false, err
	}
	defer p.close()
	raw, err := p.direct(ctx, api.Registry, "Read", api.Key(kind, id))
	if err != nil {
		if missingRegistryRecord(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	var version api.Version
	if err = json.Unmarshal(raw, &version); err != nil {
		return 0, false, err
	}
	return version.Revision, true, nil
}

func (b *journalOperationBackend) SubmitAsync(ctx context.Context, key, id string, caller api.Management, method string, input json.RawMessage, onUpdate func(string, string, string, int64, string, *string, *string, bool) error) {
	role, ok := b.roles[caller]
	if !ok {
		code := "IDENTITY_MANAGEMENT_FORBIDDEN"
		_ = onUpdate("ENDORSE", "FAILED", "", 0, "", nil, &code, false)
		return
	}
	op, err := b.journal.prepare(ctx, key, role, method, input)
	if err == nil && op != nil && op.Status == "PENDING" && b.beforeBroadcast != nil {
		b.beforeBroadcast(ctx, key)
	}
	for err == nil && op != nil {
		var val *string
		var n int64
		var hash string
		if op.Commit != nil {
			c := op.Commit.Code
			val = &c
			n = int64(op.Commit.Number)
			hash = op.Commit.Hash
		}
		if err = onUpdate(op.Stage, op.Status, op.TxID, n, hash, val, op.FailureCode, false); err != nil {
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
		op, err = b.journal.recover(ctx, key, nil)
	}
	// Transport failures leave the persisted request and original journal PENDING.
}

func (s *ManagementOperationService) dispatch(key, id string, caller api.Management, method string, input json.RawMessage) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.submitPending(ctx, key, id, caller, method, input)
	}()
}

func (s *ManagementOperationService) submitPending(ctx context.Context, key, id string, caller api.Management, method string, input json.RawMessage) {
	s.mu.Lock()
	if s.running[id] {
		s.mu.Unlock()
		return
	}
	s.running[id] = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.running, id); s.mu.Unlock() }()
	if method == "RecoverIdentity" {
		if err := s.verifyRecoveryAdmission(ctx, key, id, caller, input); err != nil {
			if protocol.HasCode(err, protocol.ErrCodeRecoveryProofInvalid) {
				code := protocol.ErrCodeRecoveryProofInvalid
				_ = s.RecordOutcome(ctx, id, "ACCEPT", "FAILED", "", 0, "", nil, &code, false)
			}
			return
		}
	}
	s.backend.SubmitAsync(ctx, key, id, caller, method, input, func(stage, status, txID string, n int64, hash string, val, fail *string, delivered bool) error {
		return s.RecordOutcome(ctx, id, stage, status, txID, n, hash, val, fail, delivered)
	})
}

// ResumePending recovers requests accepted before a crash using their exact stored input.
func (s *ManagementOperationService) ResumePending(ctx context.Context) error {
	if s.backend == nil {
		return fmt.Errorf("management submission backend unavailable")
	}
	rows, err := s.db.Query(ctx, `SELECT operation_key,operation_id,caller_msp_id,caller_fingerprint,method,request_json FROM operations WHERE deployment_id=$1 AND status='PENDING' AND request_json IS NOT NULL ORDER BY operation_key`, s.deploymentID)
	if err != nil {
		return err
	}
	type item struct {
		key, id, method string
		caller          api.Management
		input           []byte
	}
	var pending []item
	for rows.Next() {
		var v item
		if err = rows.Scan(&v.key, &v.id, &v.caller.MSPID, &v.caller.Fingerprint, &v.method, &v.input); err != nil {
			break
		}
		pending = append(pending, v)
	}
	rows.Close()
	if err != nil {
		return err
	}
	if err = rows.Err(); err != nil {
		return err
	}
	// A temporarily invisible original transaction must not block unrelated recovery.
	var workers sync.WaitGroup
	slots := make(chan struct{}, 4)
	for _, v := range pending {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			workers.Wait()
			return ctx.Err()
		}
		workers.Go(func() {
			defer func() { <-slots }()
			attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			s.submitPending(attempt, v.key, v.id, v.caller, v.method, v.input)
		})
	}
	workers.Wait()
	return ctx.Err()
}

// RunRecovery is a host-owned durable queue consumer, including recovery on startup.
func (s *ManagementOperationService) RunRecovery(ctx context.Context) error {
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
