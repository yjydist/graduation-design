package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/core/dao"
	"grad/platform/core/ledger"
	"grad/protocol"
	preg "grad/protocol/registry"
)

// IssueChallengeRequest defines parameters for issuing a single-use registration challenge.
type IssueChallengeRequest struct {
	ChallengeID       string
	DomainID          string
	SubjectID         string
	AppKeyID          string
	AppKeyVersion     int64
	AppPublicKey      string
	DIDDocumentDigest string
	AccountCommitment string
	MSPID             string
	CertificateSHA256 string
	IssuedAt          int64
	TTLSeconds        int64
}

// RegistrationCoordinator manages identity registration and recovery challenges
// and dual-proof verification in PostgreSQL.
type RegistrationCoordinator struct {
	db *pgxpool.Pool
}

// NewRegistrationCoordinator constructs a RegistrationCoordinator backed by db.
func NewRegistrationCoordinator(db *pgxpool.Pool) *RegistrationCoordinator {
	return &RegistrationCoordinator{db: db}
}

type registrationChallengeRow struct {
	DeploymentID      string `db:"deployment_id"`
	ChallengeSHA256   string `db:"challenge_sha256"`
	MSPID             string `db:"msp_id"`
	CertificateSHA256 string `db:"certificate_sha256"`
	DomainID          string `db:"domain_id"`
	SubjectID         string `db:"subject_id"`
	AppKeyID          string `db:"app_key_id"`
	Nonce             string `db:"nonce"`
	IssuedAt          int64  `db:"issued_at"`
	ExpiresAt         int64  `db:"expires_at"`
	Consumed          bool   `db:"consumed"`
}

// IssueRegistrationChallenge creates and persists a fresh single-use registration challenge
// in registration_challenges.
func (rc *RegistrationCoordinator) IssueRegistrationChallenge(
	ctx context.Context,
	dep protocol.DeploymentBinding,
	req IssueChallengeRequest,
) (*protocol.RegistrationChallenge, string, error) {
	if rc == nil || rc.db == nil {
		return nil, "", protocol.NewError(preg.ErrCodeStateUnavailable, "registration store not configured")
	}
	depID, err := protocol.ComputeDeploymentID(dep)
	if err != nil {
		return nil, "", err
	}
	nonce, err := protocol.GenerateNonce()
	if err != nil {
		return nil, "", err
	}
	chalID := req.ChallengeID
	if chalID == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return nil, "", err
		}
		chalID = "urn:grad:reg-challenge:" + hex.EncodeToString(raw)
	}
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 60
	}
	keyVer := req.AppKeyVersion
	if keyVer <= 0 {
		keyVer = 1
	}
	chal := &protocol.RegistrationChallenge{
		AccountCommitment: req.AccountCommitment,
		AppKeyID:          req.AppKeyID,
		AppKeyVersion:     keyVer,
		AppPublicKey:      req.AppPublicKey,
		ChallengeID:       chalID,
		DeploymentID:      depID,
		DIDDocumentDigest: req.DIDDocumentDigest,
		DomainID:          req.DomainID,
		ExpiresAt:         req.IssuedAt + ttl,
		IssuedAt:          req.IssuedAt,
		ManagementIdentity: protocol.ManagementIdentity{
			MSPID:             req.MSPID,
			CertificateSHA256: req.CertificateSHA256,
		},
		Nonce:     nonce,
		Purpose:   protocol.RegistrationChallengePurpose,
		SubjectID: req.SubjectID,
	}
	jcsBytes, err := protocol.MarshalJCS(chal)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(jcsBytes)
	chalSHA256 := hex.EncodeToString(sum[:])

	_, err = rc.db.Exec(ctx, `INSERT INTO registration_challenges(
		challenge_id, deployment_id, challenge_sha256, msp_id, certificate_sha256,
		domain_id, subject_id, app_key_id, nonce, challenge_json, issued_at, expires_at, consumed
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,FALSE)`,
		chal.ChallengeID, depID, chalSHA256, req.MSPID, req.CertificateSHA256,
		req.DomainID, req.SubjectID, req.AppKeyID, nonce, jcsBytes, chal.IssuedAt, chal.ExpiresAt,
	)
	if err != nil {
		return nil, "", err
	}
	return chal, chalSHA256, nil
}

// AcceptRegistrationBundle validates a submitted ManagementDualProofBundle against the persisted
// registration challenge, optional authorized MSP certificates, and optional DID document before
// atomically consuming the challenge and persisting the operations record.
func (rc *RegistrationCoordinator) AcceptRegistrationBundle(
	ctx context.Context,
	operationKey string,
	caller preg.Management,
	bundle *protocol.ManagementDualProofBundle,
	expectedMSPID string,
	authorizedCerts []*x509.Certificate,
	didDocBytes []byte,
	now int64,
	submitFn func(context.Context, string) (*ledger.Operation, error),
) error {
	if rc == nil || rc.db == nil {
		return protocol.NewError(preg.ErrCodeStateUnavailable, "registration store not configured")
	}
	if bundle == nil {
		return protocol.NewError(preg.ErrCodeInvalidSchema, "nil ManagementDualProofBundle")
	}
	if bundle.ManagementSignatureDER == "" || bundle.ManagementCertificateDER == "" ||
		bundle.AppJWSProtected == "" || bundle.AppJWSSignature == "" {
		return protocol.NewError(preg.ErrCodeRegistrationProofInvalid, "missing management or DID proof")
	}

	const method = "RegisterIdentity"
	operationID := ManagementOperationID(bundle.DeploymentID, caller, method, operationKey)
	payloadHash, err := protocol.DigestValueJCS(bundle)
	if err != nil {
		return err
	}

	return dao.RunInTx(ctx, rc.db, func(tx dao.Tx) error {
		if err := tx.AdvisoryXactLock(ctx, operationID); err != nil {
			return err
		}
		var existingHash string
		var registered bool
		err := tx.QueryRow(ctx, `SELECT o.payload_hash, o.status='CONFIRMED' AND EXISTS (
			SELECT 1 FROM registration_challenges c WHERE c.challenge_id=$2
			AND c.consumed AND c.consumed_by_operation_id=o.operation_id
		) FROM operations o WHERE o.operation_id=$1`, operationID, bundle.Challenge.ChallengeID).Scan(&existingHash, &registered)
		if err == nil {
			if payloadHash != existingHash {
				return protocol.NewError(preg.ErrCodeIdempotencyConflict, "registration key already used for another request")
			}
			if !registered {
				return protocol.NewError(preg.ErrCodeStateUnavailable, "confirmed registration evidence unavailable")
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		rows, err := tx.Query(ctx, `SELECT deployment_id, challenge_sha256, msp_id, certificate_sha256,
			domain_id, subject_id, app_key_id, nonce, issued_at, expires_at, consumed
			FROM registration_challenges WHERE challenge_id=$1 FOR UPDATE`, bundle.Challenge.ChallengeID)
		if err != nil {
			return err
		}
		stored, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[registrationChallengeRow])
		if errors.Is(err, pgx.ErrNoRows) {
			return protocol.NewError(preg.ErrCodeChallengeUnknown, "unknown registration challenge")
		}
		if err != nil {
			return err
		}
		if stored.Consumed {
			return protocol.NewError(preg.ErrCodeChallengeReplay, "registration challenge already consumed")
		}
		if expectedMSPID != "" && expectedMSPID != stored.MSPID {
			return protocol.NewError(preg.ErrCodeRegistrationProofInvalid, "caller MSP mismatch")
		}
		if now < stored.IssuedAt || now >= stored.ExpiresAt {
			return protocol.NewError(preg.ErrCodeChallengeExpired, "registration challenge expired")
		}

		if bundle.DeploymentID != stored.DeploymentID ||
			bundle.Challenge.DeploymentID != stored.DeploymentID ||
			bundle.ChallengeSha256 != stored.ChallengeSHA256 ||
			bundle.Challenge.Nonce != stored.Nonce ||
			bundle.Challenge.DomainID != stored.DomainID ||
			bundle.Challenge.SubjectID != stored.SubjectID ||
			bundle.Challenge.AppKeyID != stored.AppKeyID ||
			bundle.Challenge.ManagementIdentity.MSPID != stored.MSPID ||
			bundle.Challenge.ManagementIdentity.CertificateSHA256 != stored.CertificateSHA256 {
			return protocol.NewError(preg.ErrCodeChallengeMismatch, "registration bundle does not match issued challenge")
		}

		if err := bundle.Verify(); err != nil {
			return protocol.WrapError(preg.ErrCodeRegistrationProofInvalid, "dual proof verification failed", err)
		}

		certDER, err := protocol.DecodeStrictBase64URL(bundle.ManagementCertificateDER)
		if err != nil {
			return protocol.WrapError(preg.ErrCodeRegistrationProofInvalid, "decode management certificate", err)
		}
		leafCert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return protocol.WrapError(preg.ErrCodeRegistrationProofInvalid, "parse management certificate", err)
		}
		if len(authorizedCerts) > 0 {
			if err := verifyAuthorizedMgmtCert(leafCert, authorizedCerts); err != nil {
				return err
			}
		}

		if len(didDocBytes) > 0 {
			doc, dig, err := protocol.ParseDIDDocument(didDocBytes)
			if err != nil {
				return protocol.WrapError(preg.ErrCodeRegistrationProofInvalid, "parse DID document", err)
			}
			if dig != bundle.Challenge.DIDDocumentDigest {
				return protocol.NewError(preg.ErrCodeDIDDocumentMismatch, "DID document digest mismatches challenge")
			}
			pub, err := doc.ResolveKey(bundle.Challenge.AppKeyID, protocol.KeyPurposeAuthentication)
			if err != nil {
				return protocol.WrapError(preg.ErrCodeDIDDocumentMismatch, "DID key mismatch", err)
			}
			pubHex, err := protocol.FormatAppPublicKey(pub)
			if err != nil || pubHex != bundle.Challenge.AppPublicKey {
				return protocol.NewError(preg.ErrCodeDIDDocumentMismatch, "DID public key mismatches challenge appPublicKey")
			}
		}

		if submitFn == nil {
			return protocol.NewError(preg.ErrCodeStateUnavailable, "registration submission unavailable")
		}
		res, err := submitFn(ctx, operationID)
		if err != nil {
			return err
		}
		if res == nil || res.Key != operationID || res.Status != "CONFIRMED" ||
			!hasValidCommit(res.TxID, res.Commit) {
			return protocol.NewError(preg.ErrCodeStateUnavailable, "confirmed registration transaction evidence required")
		}

		if _, err := tx.Exec(ctx, `UPDATE registration_challenges
			SET consumed=TRUE, consumed_by_operation_id=$2, consumed_at=$3
			WHERE challenge_id=$1`, bundle.Challenge.ChallengeID, operationID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO operations(
			deployment_id, operation_key, operation_id, caller_msp_id, caller_fingerprint,
			method, tx_id, block_no, block_hash, transaction_index, observed_peer, stage, status, validation_code, failure_code, payload_hash, updated_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'COMMIT','CONFIRMED','VALID',NULL,$12,NOW())`,
			bundle.DeploymentID, operationKey, operationID, caller.MSPID, caller.CertificateSHA256,
			method, res.TxID, res.Commit.Number, res.Commit.Hash, res.Commit.Index, res.Commit.ObservedPeer, payloadHash); err != nil {
			return err
		}
		return nil
	})
}

// IssueRecoveryChallengeRequest defines parameters for issuing a grad-identity-recovery-v1 challenge.
type IssueRecoveryChallengeRequest struct {
	ChallengeID           string
	DomainID              string
	SubjectID             string
	AccountCommitment     string
	OldManagementIdentity protocol.ManagementIdentity
	NewManagementIdentity protocol.ManagementIdentity
	ExpectedRevision      uint64
	ExpectedKeyVersion    uint64
	NewAppKeyID           string
	NewAppPublicKey       string
	DIDDocumentDigest     string
	IssuedAt              int64
	TTLSeconds            int64
}

// IssueRecoveryChallenge creates and persists a single-use recovery challenge (TTL <= 300s)
// in recovery_challenges.
func (rc *RegistrationCoordinator) IssueRecoveryChallenge(
	ctx context.Context,
	dep protocol.DeploymentBinding,
	req IssueRecoveryChallengeRequest,
) (*protocol.RecoveryChallenge, string, error) {
	if rc == nil || rc.db == nil {
		return nil, "", protocol.NewError(preg.ErrCodeStateUnavailable, "recovery store not configured")
	}
	depID, err := protocol.ComputeDeploymentID(dep)
	if err != nil {
		return nil, "", err
	}
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 300
	}
	if ttl > 300 {
		return nil, "", protocol.NewError(preg.ErrCodeRecoveryProofInvalid, "recovery challenge TTL cannot exceed 300 seconds")
	}
	nonce, err := protocol.GenerateNonce()
	if err != nil {
		return nil, "", err
	}
	chalID := req.ChallengeID
	if chalID == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return nil, "", err
		}
		chalID = "urn:grad:rec-challenge:" + hex.EncodeToString(raw)
	}
	chal := &protocol.RecoveryChallenge{
		AccountCommitment:     req.AccountCommitment,
		ChallengeID:           chalID,
		DeploymentID:          depID,
		DIDDocumentDigest:     req.DIDDocumentDigest,
		DomainID:              req.DomainID,
		ExpectedKeyVersion:    req.ExpectedKeyVersion,
		ExpectedRevision:      req.ExpectedRevision,
		ExpiresAt:             req.IssuedAt + ttl,
		IssuedAt:              req.IssuedAt,
		NewAppKeyID:           req.NewAppKeyID,
		NewAppKeyVersion:      req.ExpectedKeyVersion + 1,
		NewAppPublicKey:       req.NewAppPublicKey,
		NewManagementIdentity: req.NewManagementIdentity,
		Nonce:                 nonce,
		OldManagementIdentity: req.OldManagementIdentity,
		Purpose:               protocol.RecoveryChallengePurpose,
		SubjectID:             req.SubjectID,
	}
	jcsBytes, err := protocol.MarshalJCS(chal)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(jcsBytes)
	chalSHA256 := hex.EncodeToString(sum[:])

	_, err = rc.db.Exec(ctx, `INSERT INTO recovery_challenges(
		challenge_id, deployment_id, challenge_sha256, domain_id, subject_id, account_commitment,
		old_msp_id, old_certificate_sha256, new_msp_id, new_certificate_sha256,
		expected_revision, expected_key_version, new_app_key_id, new_app_key_version,
		nonce, challenge_json, issued_at, expires_at, consumed
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,FALSE)`,
		chal.ChallengeID, depID, chalSHA256, req.DomainID, req.SubjectID, req.AccountCommitment,
		req.OldManagementIdentity.MSPID, req.OldManagementIdentity.CertificateSHA256,
		req.NewManagementIdentity.MSPID, req.NewManagementIdentity.CertificateSHA256,
		req.ExpectedRevision, req.ExpectedKeyVersion, req.NewAppKeyID, chal.NewAppKeyVersion,
		nonce, jcsBytes, chal.IssuedAt, chal.ExpiresAt,
	)
	if err != nil {
		return nil, "", err
	}
	return chal, chalSHA256, nil
}

func verifyAuthorizedMgmtCert(leaf *x509.Certificate, authorized []*x509.Certificate) error {
	var leafAllowed []*x509.Certificate
	roots := x509.NewCertPool()
	hasCA := false
	for _, c := range authorized {
		if c.IsCA {
			roots.AddCert(c)
			hasCA = true
		} else {
			leafAllowed = append(leafAllowed, c)
		}
	}
	if len(leafAllowed) > 0 {
		matched := false
		for _, allowed := range leafAllowed {
			if bytes.Equal(leaf.Raw, allowed.Raw) {
				matched = true
				break
			}
		}
		if !matched {
			return protocol.NewError(preg.ErrCodeSignatureInvalid, "management certificate does not match authorized account certificate in MSP")
		}
	}
	if hasCA {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
			return protocol.WrapError(preg.ErrCodeSignatureInvalid, "management certificate not issued by MSP CA", err)
		}
	}
	return nil
}

type recoveryAuthorizer interface {
	AuthorizeRecovery(context.Context, preg.Management, *protocol.RecoveryDualProofBundle) error
}

func recoveryMutation(c protocol.RecoveryChallenge) preg.RecoverIdentityInput {
	return preg.RecoverIdentityInput{
		Bound:              preg.Bound{DeploymentID: c.DeploymentID},
		ID:                 c.SubjectID,
		ExpectedRevision:   c.ExpectedRevision,
		ExpectedKeyVersion: c.ExpectedKeyVersion,
		AccountCommitment:  c.AccountCommitment,
		OldManagement:      c.OldManagementIdentity,
		NewManagement:      c.NewManagementIdentity,
		DocumentDigest:     c.DIDDocumentDigest,
		KeyID:              c.NewAppKeyID,
		PublicKey:          c.NewAppPublicKey,
	}
}

func (s *Service) parseRecoveryRequest(raw json.RawMessage) (*protocol.RecoveryDualProofBundle, json.RawMessage, error) {
	var bundle protocol.RecoveryDualProofBundle
	if err := protocol.DecodeStrictJSON(raw, &bundle); err != nil {
		return nil, nil, protocol.WrapError(preg.ErrCodeRecoveryProofInvalid, "complete recovery proof bundle required", err)
	}
	if err := bundle.Verify(); err != nil {
		return nil, nil, protocol.WrapError(preg.ErrCodeRecoveryProofInvalid, "invalid recovery dual proof", err)
	}
	if bundle.DeploymentID != s.deploymentID {
		return nil, nil, protocol.NewError(preg.ErrCodeRecoveryProofInvalid, "recovery deployment mismatch")
	}
	input, err := protocol.MarshalJCS(recoveryMutation(bundle.Challenge))
	if err != nil {
		return nil, nil, protocol.WrapError(preg.ErrCodeRecoveryProofInvalid, "encode recovery mutation", err)
	}
	return &bundle, input, nil
}

type recoveryChallengeRow struct {
	ChallengeJSON   []byte `db:"challenge_json"`
	ChallengeSHA256 string `db:"challenge_sha256"`
	Consumed        bool   `db:"consumed"`
	IssuedAt        int64  `db:"issued_at"`
	ExpiresAt       int64  `db:"expires_at"`
	Now             int64  `db:"now_epoch"`
}

// consumeRecoveryChallenge executes inside the admission transaction so challenge consumption
// and the derived immutable operation row commit atomically.
func consumeRecoveryChallenge(ctx context.Context, tx dao.Tx, deploymentID, opID string, bundle *protocol.RecoveryDualProofBundle) error {
	rows, err := tx.Query(ctx, `SELECT challenge_json, challenge_sha256, consumed, issued_at, expires_at,
		FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint AS now_epoch
		FROM recovery_challenges WHERE deployment_id=$1 AND challenge_id=$2 FOR UPDATE`,
		deploymentID, bundle.Challenge.ChallengeID)
	if err != nil {
		return err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[recoveryChallengeRow])
	if errors.Is(err, pgx.ErrNoRows) {
		return protocol.NewError(preg.ErrCodeChallengeUnknown, "server-issued recovery challenge required")
	}
	if err != nil {
		return err
	}
	if row.Consumed {
		return protocol.NewError(preg.ErrCodeChallengeReplay, "recovery challenge already consumed")
	}
	issued, err := protocol.CanonicalizeJSON(row.ChallengeJSON)
	if err != nil {
		return err
	}
	provided, err := protocol.MarshalJCS(bundle.Challenge)
	if err != nil {
		return err
	}
	if row.ChallengeSHA256 != bundle.ChallengeSha256 || !bytes.Equal(issued, provided) {
		return protocol.NewError(preg.ErrCodeChallengeMismatch, "recovery challenge differs from server approval")
	}
	if row.Now < row.IssuedAt || row.Now >= row.ExpiresAt {
		return protocol.NewError(preg.ErrCodeChallengeExpired, "recovery challenge expired")
	}
	_, err = tx.Exec(ctx, `UPDATE recovery_challenges SET consumed=TRUE, consumed_by_operation_id=$3, consumed_at=$4
		WHERE deployment_id=$1 AND challenge_id=$2`,
		deploymentID, bundle.Challenge.ChallengeID, opID, row.Now)
	return err
}

type recoveryAdmissionRow struct {
	ChallengeJSON []byte `db:"challenge_json"`
}

// verifyRecoveryAdmission re-checks the durable recovery approval on every dispatch and crash recovery.
// Unapproved or modified durable requests fail closed.
func (s *Service) verifyRecoveryAdmission(ctx context.Context, key, opID string, caller preg.Management, input json.RawMessage) error {
	rows, err := s.db.Query(ctx, `SELECT c.challenge_json
		FROM recovery_challenges c
		JOIN operations o ON o.deployment_id=c.deployment_id AND o.operation_id=c.consumed_by_operation_id
		WHERE c.deployment_id=$1 AND o.operation_id=$2 AND o.operation_key=$3
		  AND o.caller_msp_id=$4 AND o.caller_fingerprint=$5 AND c.consumed AND o.method='RecoverIdentity'`,
		s.deploymentID, opID, key, caller.MSPID, caller.CertificateSHA256)
	if err != nil {
		return err
	}
	row, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[recoveryAdmissionRow])
	if errors.Is(err, pgx.ErrNoRows) {
		return protocol.NewError(preg.ErrCodeRecoveryProofInvalid, "durable recovery approval unavailable")
	}
	if err != nil {
		return err
	}
	var challenge protocol.RecoveryChallenge
	if err := json.Unmarshal(row.ChallengeJSON, &challenge); err != nil {
		return err
	}
	want, err := protocol.MarshalJCS(recoveryMutation(challenge))
	if err != nil {
		return err
	}
	actual, err := protocol.CanonicalizeJSON(input)
	if err != nil || !bytes.Equal(want, actual) {
		return protocol.NewError(preg.ErrCodeRecoveryProofInvalid, "pending recovery differs from approved challenge")
	}
	return nil
}
