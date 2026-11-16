package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"

	"github.com/jackc/pgx/v5"
)

type recoveryAuthorizer interface {
	AuthorizeRecovery(context.Context, api.Management, *protocol.RecoveryDualProofBundle) error
}

func recoveryMutation(c protocol.RecoveryChallenge) api.RecoverIdentityInput {
	return api.RecoverIdentityInput{
		Bound: api.Bound{DeploymentID: c.DeploymentID}, ID: c.SubjectID,
		ExpectedRevision: c.ExpectedRevision, ExpectedKeyVersion: c.ExpectedKeyVersion,
		AccountCommitment: c.AccountCommitment,
		OldManagement:     api.Management{MSPID: c.OldManagementIdentity.MSPID, Fingerprint: c.OldManagementIdentity.CertificateSha256},
		NewManagement:     api.Management{MSPID: c.NewManagementIdentity.MSPID, Fingerprint: c.NewManagementIdentity.CertificateSha256},
		DocumentDigest:    c.DIDDocumentDigest, KeyID: c.NewAppKeyID, PublicKey: c.NewAppPublicKey,
	}
}

func (s *ManagementOperationService) parseRecoveryRequest(raw json.RawMessage) (*protocol.RecoveryDualProofBundle, json.RawMessage, error) {
	var bundle protocol.RecoveryDualProofBundle
	if err := protocol.DecodeStrictJSON(raw, &bundle); err != nil {
		return nil, nil, protocol.WrapError(protocol.ErrCodeRecoveryProofInvalid, "complete recovery proof bundle required", err)
	}
	if err := bundle.Verify(); err != nil {
		return nil, nil, protocol.WrapError(protocol.ErrCodeRecoveryProofInvalid, "invalid recovery dual proof", err)
	}
	if bundle.DeploymentID != s.deploymentID {
		return nil, nil, protocol.NewError(protocol.ErrCodeRecoveryProofInvalid, "recovery deployment mismatch")
	}
	input, err := protocol.MarshalJCS(recoveryMutation(bundle.Challenge))
	return &bundle, input, err
}

// consumeRecoveryChallenge runs in the admission transaction. No backend may run
// until challenge consumption and the derived, immutable request commit together.
func consumeRecoveryChallenge(ctx context.Context, tx pgx.Tx, deploymentID, opID string, bundle *protocol.RecoveryDualProofBundle) error {
	var raw []byte
	var digest string
	var consumed bool
	var now, issuedAt, expiresAt int64
	err := tx.QueryRow(ctx, `SELECT challenge_json,challenge_sha256,consumed,issued_at,expires_at FROM recovery_challenges WHERE deployment_id=$1 AND challenge_id=$2 FOR UPDATE`, deploymentID, bundle.Challenge.ChallengeID).Scan(&raw, &digest, &consumed, &issuedAt, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return protocol.NewError(protocol.ErrCodeChallengeUnknown, "server-issued recovery challenge required")
	}
	if err != nil {
		return err
	}
	if consumed {
		return protocol.NewError(protocol.ErrCodeChallengeReplay, "recovery challenge already consumed")
	}
	issued, err := protocol.CanonicalizeJSON(raw)
	if err != nil {
		return err
	}
	provided, err := protocol.MarshalJCS(bundle.Challenge)
	if err != nil {
		return err
	}
	if digest != bundle.ChallengeSha256 || !bytes.Equal(issued, provided) {
		return protocol.NewError(protocol.ErrCodeChallengeMismatch, "recovery challenge differs from server approval")
	}
	if err := tx.QueryRow(ctx, `SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint`).Scan(&now); err != nil {
		return err
	}
	if now < issuedAt || now >= expiresAt {
		return protocol.NewError(protocol.ErrCodeChallengeExpired, "recovery challenge expired")
	}
	_, err = tx.Exec(ctx, `UPDATE recovery_challenges SET consumed=TRUE,consumed_by_operation_id=$3,consumed_at=$4 WHERE deployment_id=$1 AND challenge_id=$2`, deploymentID, bundle.Challenge.ChallengeID, opID, now)
	return err
}

// Check the durable approval again on every dispatch, including after restart.
// Legacy raw recovery requests admitted before proof enforcement fail closed.
func (s *ManagementOperationService) verifyRecoveryAdmission(ctx context.Context, key, opID string, caller api.Management, input json.RawMessage) error {
	var raw []byte
	err := s.db.QueryRow(ctx, `SELECT c.challenge_json FROM recovery_challenges c JOIN operations o ON o.deployment_id=c.deployment_id AND o.operation_id=c.consumed_by_operation_id WHERE c.deployment_id=$1 AND o.operation_id=$2 AND o.operation_key=$3 AND o.caller_msp_id=$4 AND o.caller_fingerprint=$5 AND c.consumed AND o.method='RecoverIdentity'`, s.deploymentID, opID, key, caller.MSPID, caller.Fingerprint).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return protocol.NewError(protocol.ErrCodeRecoveryProofInvalid, "durable recovery approval unavailable")
	}
	if err != nil {
		return err
	}
	var challenge protocol.RecoveryChallenge
	if err := json.Unmarshal(raw, &challenge); err != nil {
		return err
	}
	want, err := protocol.MarshalJCS(recoveryMutation(challenge))
	if err != nil {
		return err
	}
	actual, err := protocol.CanonicalizeJSON(input)
	if err != nil || !bytes.Equal(want, actual) {
		return protocol.NewError(protocol.ErrCodeRecoveryProofInvalid, "pending recovery differs from approved challenge")
	}
	return nil
}
