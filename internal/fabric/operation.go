package fabric

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
	"graduation-design/internal/serviceauth"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	gw "github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	msp "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const operationsSchema = `
CREATE TABLE IF NOT EXISTS fabric_operation (
    deployment text NOT NULL,
    operation_key text NOT NULL,
    data jsonb NOT NULL,
    PRIMARY KEY (deployment, operation_key)
);
CREATE TABLE IF NOT EXISTS operations (
    deployment_id text NOT NULL,
    operation_key text NOT NULL,
    operation_id text NOT NULL UNIQUE,
    caller_msp_id text NOT NULL,
    caller_fingerprint text NOT NULL,
    method text NOT NULL,
    tx_id text NOT NULL,
    block_no bigint NOT NULL DEFAULT 0,
    block_hash text NOT NULL DEFAULT '',
    stage text NOT NULL,
    status text NOT NULL,
    validation_code text,
    failure_code text,
    payload_hash text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (deployment_id, operation_key)
);
ALTER TABLE operations ADD COLUMN IF NOT EXISTS request_json BYTEA;
ALTER TABLE operations ADD COLUMN IF NOT EXISTS delivered BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE IF NOT EXISTS registration_challenges (
    challenge_id text PRIMARY KEY,
    deployment_id text NOT NULL,
    challenge_sha256 text NOT NULL,
    msp_id text NOT NULL,
    certificate_sha256 text NOT NULL,
    domain_id text NOT NULL,
    subject_id text NOT NULL,
    app_key_id text NOT NULL,
    nonce text NOT NULL UNIQUE,
    challenge_json jsonb NOT NULL,
    issued_at bigint NOT NULL,
    expires_at bigint NOT NULL,
    consumed boolean NOT NULL DEFAULT FALSE,
    consumed_by_operation_id text,
    consumed_at bigint
);
CREATE TABLE IF NOT EXISTS recovery_challenges (
    challenge_id text PRIMARY KEY,
    deployment_id text NOT NULL,
    challenge_sha256 text NOT NULL,
    domain_id text NOT NULL,
    subject_id text NOT NULL,
    account_commitment text NOT NULL,
    old_msp_id text NOT NULL,
    old_certificate_sha256 text NOT NULL,
    new_msp_id text NOT NULL,
    new_certificate_sha256 text NOT NULL,
    expected_revision bigint NOT NULL,
    expected_key_version bigint NOT NULL,
    new_app_key_id text NOT NULL,
    new_app_key_version bigint NOT NULL,
    nonce text NOT NULL UNIQUE,
    challenge_json jsonb NOT NULL,
    issued_at bigint NOT NULL,
    expires_at bigint NOT NULL,
    consumed boolean NOT NULL DEFAULT FALSE,
    consumed_by_operation_id text,
    consumed_at bigint
);
CREATE TABLE IF NOT EXISTS certification_outbox (
    deployment_id text NOT NULL,
    domain_id text NOT NULL,
    certification_id text NOT NULL,
    recipient text NOT NULL,
    cert_jws text NOT NULL,
    cert_digest text NOT NULL,
    root_key_version bigint NOT NULL,
    tx_id text NOT NULL,
    block_no bigint NOT NULL,
    created_at bigint NOT NULL,
    PRIMARY KEY (deployment_id, domain_id, certification_id, recipient)
);
CREATE TABLE IF NOT EXISTS certification_receipts (
    deployment_id text NOT NULL,
    domain_id text NOT NULL,
    certification_id text NOT NULL,
    recipient text NOT NULL,
    cert_jws text NOT NULL,
    cert_digest text NOT NULL,
    received_at bigint NOT NULL,
    PRIMARY KEY (deployment_id, domain_id, certification_id, recipient)
);
CREATE TABLE IF NOT EXISTS grant_outbox (
    deployment_id text NOT NULL,
    recipient text NOT NULL,
    grant_id text NOT NULL,
    package_json jsonb NOT NULL,
    package_digest text NOT NULL,
    tx_id text NOT NULL,
    block_no bigint NOT NULL,
    created_at bigint NOT NULL,
    PRIMARY KEY (deployment_id, recipient, grant_id)
);
CREATE TABLE IF NOT EXISTS wallet_receipts (
    deployment_id text NOT NULL,
    recipient text NOT NULL,
    grant_id text NOT NULL,
    package_json jsonb NOT NULL,
    package_digest text NOT NULL,
    received_at bigint NOT NULL,
    PRIMARY KEY (deployment_id, recipient, grant_id)
);`

type outcome struct {
	point
	Index int    `json:"transactionIndex"`
	Code  string `json:"validationCode"`
}

type operation struct {
	DeploymentID string         `json:"deploymentId"`
	Key          string         `json:"operationKey"`
	InputDigest  string         `json:"inputSha256"`
	Role         string         `json:"role"`
	Caller       api.Management `json:"caller"`
	Channel      string         `json:"channelId"`
	Chaincode    string         `json:"chaincode"`
	Method       string         `json:"method"`
	TxID         string         `json:"txId"`
	Proposal     []byte         `json:"signedProposal"`
	Signed       []byte         `json:"signedTransaction,omitempty"`
	Status       string         `json:"status"`
	Stage        string         `json:"stage"`
	FailureCode  *string        `json:"failureCode"`
	Observation  string         `json:"observation,omitempty"`
	Commit       *outcome       `json:"commit,omitempty"`
	AcceptedAt   time.Time      `json:"acceptedAt"`
	SignedAt     *time.Time     `json:"signedAt,omitempty"`
	BroadcastAt  *time.Time     `json:"firstBroadcastAt,omitempty"`
	ObservedAt   *time.Time     `json:"firstObservedAt,omitempty"`
}

type journal struct {
	instance     *instance
	deploymentID string
	db           *pgxpool.Pool
}

func initSchema(ctx context.Context, db *pgxpool.Pool, statements string) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(376602444033251)"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, statements); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (j journal) lock(ctx context.Context, key string) (*pgxpool.Conn, func(), error) {
	if key == "" || len(key) > 180 || strings.ContainsRune(key, 0) {
		return nil, nil, fmt.Errorf("invalid operation key")
	}
	conn, err := j.db.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	lock := int64(binary.BigEndian.Uint64(digestBytes([]byte(j.deploymentID + "/" + key))))
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lock); err != nil {
		// A lost response may have acquired the session lock.
		conn.Hijack().Close(context.Background())
		return nil, nil, err
	}
	return conn, func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := conn.Exec(c, "SELECT pg_advisory_unlock($1)", lock); err != nil {
			conn.Hijack().Close(c)
		} else {
			conn.Release()
		}
	}, nil
}

func (j journal) load(ctx context.Context, key string, conn rowReader) (*operation, error) {
	var raw []byte
	err := conn.QueryRow(ctx, "SELECT data FROM fabric_operation WHERE deployment=$1 AND operation_key=$2",
		j.deploymentID, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var op operation
	if err := json.Unmarshal(raw, &op); err != nil {
		return nil, err
	}
	if op.DeploymentID != j.deploymentID || op.Key != key || op.Channel != api.Channel || op.Chaincode != api.Registry {
		return nil, fmt.Errorf("operation journal deployment mismatch")
	}
	return &op, nil
}

func (j journal) save(ctx context.Context, conn *pgxpool.Conn, op *operation) error {
	raw, err := json.Marshal(op)
	if err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `INSERT INTO fabric_operation(deployment,operation_key,data) VALUES($1,$2,$3)
		ON CONFLICT(deployment,operation_key) DO UPDATE SET data=EXCLUDED.data`, j.deploymentID, op.Key, raw); err != nil {
		return err
	}
	var blockNo int64
	var blockHash string
	var valCode *string
	if op.Commit != nil {
		blockNo = int64(op.Commit.Number)
		blockHash = op.Commit.Hash
		c := op.Commit.Code
		valCode = &c
	}
	opID := j.deploymentID + ":" + op.Key
	_, err = conn.Exec(ctx, `INSERT INTO operations(
		deployment_id, operation_key, operation_id, caller_msp_id, caller_fingerprint,
		method, tx_id, block_no, block_hash, stage, status, validation_code, failure_code, payload_hash, updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW())
	ON CONFLICT(deployment_id, operation_key) DO UPDATE SET
		tx_id=EXCLUDED.tx_id, block_no=EXCLUDED.block_no, block_hash=EXCLUDED.block_hash,
		stage=EXCLUDED.stage, status=EXCLUDED.status, validation_code=EXCLUDED.validation_code,
		failure_code=EXCLUDED.failure_code, updated_at=NOW()`,
		j.deploymentID, op.Key, opID, op.Caller.MSPID, op.Caller.Fingerprint,
		op.Method, op.TxID, blockNo, blockHash, op.Stage, op.Status, valCode, op.FailureCode, op.InputDigest)
	return err
}

func (p *peerClient) proposal(method string, input []byte, orgs []string) (*client.Proposal, []byte, error) {
	options := []client.ProposalOption{client.WithBytesArguments(input)}
	if len(orgs) > 0 {
		options = append(options, client.WithEndorsingOrganizations(orgs...))
	}
	proposal, err := p.contract(api.Registry).NewProposal(method, options...)
	if err != nil {
		return nil, nil, err
	}
	b, err := proposal.Bytes()
	if err != nil {
		return nil, nil, err
	}
	sig, err := p.signer(proposal.Digest())
	if err != nil {
		return nil, nil, err
	}
	proposal, err = p.gateway.NewSignedProposal(b, sig)
	if err != nil {
		return nil, nil, err
	}
	raw, err := proposal.Bytes()
	return proposal, raw, err
}

func (p *peerClient) signTransaction(tx *client.Transaction) (*client.Transaction, []byte, error) {
	b, err := tx.Bytes()
	if err != nil {
		return nil, nil, err
	}
	sig, err := p.signer(tx.Digest())
	if err != nil {
		return nil, nil, err
	}
	tx, err = p.gateway.NewSignedTransaction(b, sig)
	if err != nil {
		return nil, nil, err
	}
	signed, err := tx.Bytes()
	return tx, signed, err
}

func (j journal) matchInput(stored *operation, role, method string, input []byte) (api.Management, string, error) {
	_, caller, _, err := j.instance.role(role)
	if err != nil {
		return api.Management{}, "", err
	}
	material, err := json.Marshal([]string{j.deploymentID, caller.String(), api.Channel, api.Registry, method, string(input)})
	if err != nil {
		return api.Management{}, "", err
	}
	hash := api.Digest(material)
	if stored != nil && stored.InputDigest != hash {
		return api.Management{}, "", fmt.Errorf("OPERATION_KEY_CONFLICT: %s", stored.Key)
	}
	return caller, hash, nil
}

func (j journal) prepare(ctx context.Context, key, role, method string, input []byte, orgs ...string) (*operation, error) {
	conn, unlock, err := j.lock(ctx, key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	op, err := j.load(ctx, key, conn)
	if err != nil {
		return nil, err
	}
	caller, hash, err := j.matchInput(op, role, method, input)
	if err != nil {
		return nil, err
	}
	if op != nil && (op.Status != "PENDING" || len(op.Signed) > 0 || op.BroadcastAt != nil) {
		return op, nil
	}
	p, err := j.instance.peer("c", role)
	if err != nil {
		return op, err
	}
	defer p.close()
	var proposal *client.Proposal
	if op == nil {
		p0, raw, err := p.proposal(method, input, orgs)
		if err != nil {
			return nil, err
		}
		proposal = p0
		op = &operation{DeploymentID: j.deploymentID, Key: key, InputDigest: hash, Role: role, Caller: caller,
			Channel: api.Channel, Chaincode: api.Registry, Method: method, TxID: proposal.TransactionID(), Proposal: raw,
			Status: "PENDING", Stage: "ENDORSE", AcceptedAt: time.Now().UTC()}
		if err := j.save(ctx, conn, op); err != nil {
			return nil, err
		}
	} else {
		proposal, err = p.gateway.NewProposal(op.Proposal)
		if err != nil {
			return op, err
		}
	}
	return j.endorse(ctx, conn, p, proposal, op)
}

func (j journal) endorse(ctx context.Context, conn *pgxpool.Conn, p *peerClient, proposal *client.Proposal, op *operation) (*operation, error) {
	endorseCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	tx, err := proposal.EndorseWithContext(endorseCtx)
	cancel()
	if err != nil {
		op.Observation = err.Error()
		if code := endorsementFailure(err); code != "" {
			op.Status, op.FailureCode = "FAILED", &code
		}
		return op, j.save(ctx, conn, op)
	}
	if tx.TransactionID() != op.TxID {
		return op, fmt.Errorf("endorsed transaction ID mismatch")
	}
	_, op.Signed, err = p.signTransaction(tx)
	if err != nil {
		return op, err
	}
	now := time.Now().UTC()
	op.SignedAt, op.Stage, op.Observation = &now, "SUBMIT", ""
	return op, j.save(ctx, conn, op)
}

func endorsementFailure(err error) string {
	switch status.Code(err) {
	case codes.Aborted, codes.PermissionDenied, codes.InvalidArgument:
	default:
		return ""
	}
	var e *client.EndorseError
	reason := ""
	if errors.As(err, &e) {
		for _, d := range e.Details() {
			for _, c := range []string{
				"UNAUTHORIZED", "INVALID_STRUCTURE", "MISSING_DEPENDENCY", "STATE_CHANGED", "INVALID_STATE", "ID_ALREADY_USED",
				"PURCHASING_AUTHORITY_INVALID", "LINK_PROOF_INVALID", "LINK_APPROVAL_FORBIDDEN", "LINK_PROPOSAL_MISMATCH", "LINK_STATE_CONFLICT",
				"TRUST_MANAGEMENT_FORBIDDEN", "IDENTITY_MANAGEMENT_FORBIDDEN", "IDENTITY_RECOVERY_FORBIDDEN", "IDENTITY_STATE_CONFLICT",
				"RECOVERY_PROOF_INVALID", "TASK_STATE_CONFLICT", "GRANT_STATE_CONFLICT", "ALREADY_REVOKED",
			} {
				if strings.HasSuffix(d.Message, "D0:"+c) && strings.Contains(d.Message, "chaincode response") {
					if reason != "" && reason != c {
						return "ENDORSEMENT_REJECTED"
					}
					reason = c
				}
			}
		}
	}
	if reason != "" {
		return reason
	}
	// ABORTED also covers endorsement layouts with insufficient reachable peers.
	if status.Code(err) == codes.Aborted && !strings.Contains(err.Error(), "chaincode response") &&
		!strings.Contains(err.Error(), "proposal time") && !strings.Contains(err.Error(), "incorrect timestamp") && !strings.Contains(err.Error(), "access denied") {
		return ""
	}
	return "ENDORSEMENT_REJECTED"
}

func (j journal) write(ctx context.Context, key, role, method string, input []byte) (*operation, error) {
	op, err := j.prepare(ctx, key, role, method, input)
	if err != nil || op.Status != "PENDING" || len(op.Signed) == 0 {
		return op, err
	}
	return j.recover(ctx, key, nil)
}

// submitOverride is used by acceptance to lose the first response after a real broadcast.
func (j journal) recover(ctx context.Context, key string, submitOverride func(context.Context, *client.Transaction) error) (*operation, error) {
	conn, unlock, err := j.lock(ctx, key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	op, err := j.load(ctx, key, conn)
	if err != nil {
		return op, err
	}
	if op == nil {
		return nil, fmt.Errorf("unknown operation %q", key)
	}
	if op.Status != "PENDING" {
		return op, nil
	}
	p, err := j.instance.peer("c", op.Role)
	if err != nil {
		return op, err
	}
	defer p.close()
	if p.role != op.Caller {
		return op, fmt.Errorf("operation signer binding changed")
	}
	if len(op.Signed) == 0 {
		proposal, err := p.gateway.NewProposal(op.Proposal)
		if err != nil {
			return op, err
		}
		op, err = j.endorse(ctx, conn, p, proposal, op)
		if err != nil || op.Status != "PENDING" || len(op.Signed) == 0 {
			return op, err
		}
	}
	prepared, err := decode(op.Signed, &gw.PreparedTransaction{})
	if err != nil {
		return op, err
	}
	if err := validateOriginal(prepared, op); err != nil {
		return op, err
	}
	if op.BroadcastAt != nil {
		commit, err := p.original(ctx, op, prepared)
		if err == nil {
			op.confirm(commit)
			return op, j.save(ctx, conn, op)
		}
	} else {
		now := time.Now().UTC()
		op.BroadcastAt = &now
		op.Stage = "COMMIT"
		if err := j.save(ctx, conn, op); err != nil {
			return op, err
		}
	}
	tx, err := p.gateway.NewTransaction(op.Signed)
	if err != nil {
		return op, err
	}
	submitCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	if submitOverride != nil {
		err = submitOverride(submitCtx, tx)
	} else {
		_, err = tx.SubmitWithContext(submitCtx)
	}
	cancel()
	if err != nil {
		op.Observation = err.Error()
		// A rejected or lost submission response is not a commit result.
		return op, j.save(ctx, conn, op)
	}
	op.Observation = "broadcast acknowledged"
	commit, err := p.original(ctx, op, prepared)
	if err != nil {
		op.Observation += "; " + err.Error()
	} else {
		op.confirm(commit)
	}
	return op, j.save(ctx, conn, op)
}

func validateOriginal(prepared *gw.PreparedTransaction, op *operation) error {
	pl, ch, err := envelopeHeader(prepared.Envelope)
	if err != nil || ch.ChannelId != op.Channel || ch.TxId != op.TxID || prepared.TransactionId != op.TxID ||
		len(prepared.GetEnvelope().GetSignature()) == 0 {
		return fmt.Errorf("signed transaction header mismatch")
	}
	creator, cc, err := transactionIdentity(pl, ch)
	if err != nil || cc != op.Chaincode || creator != op.Caller {
		return fmt.Errorf("signed transaction creator or chaincode mismatch")
	}
	return nil
}

func (p *peerClient) commitStatus(ctx context.Context, txID string) (*gw.CommitStatusResponse, error) {
	id := p.gateway.Identity()
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: id.MspID(), IdBytes: id.Credentials()})
	if err != nil {
		return nil, err
	}
	raw, err := proto.Marshal(&gw.CommitStatusRequest{ChannelId: api.Channel, TransactionId: txID, Identity: creator})
	if err != nil {
		return nil, err
	}
	sig, err := p.signer(digestBytes(raw))
	if err != nil {
		return nil, err
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return gw.NewGatewayClient(p.conn).CommitStatus(c, &gw.SignedCommitStatusRequest{Request: raw, Signature: sig})
}

func (p *peerClient) original(ctx context.Context, op *operation, prepared *gw.PreparedTransaction) (*outcome, error) {
	seen, seenErr := p.commitStatus(ctx, op.TxID)
	b, err := p.queryBlock(ctx, "GetBlockByTxID", op.TxID)
	if err != nil {
		return nil, fmt.Errorf("original transaction is not available: %w", err)
	}
	match := func(b *block) *outcome {
		for _, t := range b.Transactions {
			if t.ID == op.TxID && t.Code != pb.TxValidationCode_DUPLICATE_TXID && proto.Equal(t.Envelope, prepared.Envelope) {
				return &outcome{point: b.point, Index: t.Index, Code: t.Code.String()}
			}
		}
		return nil
	}
	if found := match(b); found != nil && (seenErr != nil || seen.Result == pb.TxValidationCode_DUPLICATE_TXID ||
		(seen.BlockNumber == found.Number && seen.Result.String() == found.Code)) {
		return found, nil
	}
	// Some indexes can report a replay. Search earlier blocks for the original signed envelope.
	for n := uint64(0); n < b.Number; n++ {
		old, err := p.getBlock(ctx, n)
		if err != nil {
			return nil, err
		}
		if found := match(old); found != nil && (seenErr != nil || seen.Result == pb.TxValidationCode_DUPLICATE_TXID ||
			(seen.BlockNumber == found.Number && seen.Result.String() == found.Code)) {
			return found, nil
		}
	}
	return nil, fmt.Errorf("could not bind original signed transaction to the Peer validation result")
}

func (op *operation) confirm(commit *outcome) {
	op.Commit, op.Stage = commit, "COMMIT"
	now := time.Now().UTC()
	op.ObservedAt = &now
	switch commit.Code {
	case "VALID":
		op.Status = "CONFIRMED"
	case "MVCC_READ_CONFLICT":
		code := "STATE_CHANGED"
		op.Status, op.FailureCode = "FAILED", &code
	default:
		code := "COMMIT_INVALID"
		op.Status, op.FailureCode = "FAILED", &code
	}
}

// OperationView represents the HTTP JSON view returned by POST management operations and GET /v1/operations/{id}.
type OperationView struct {
	OperationID    string  `json:"operationId"`
	OperationKey   string  `json:"operationKey"`
	Method         string  `json:"method"`
	TxID           string  `json:"txId"`
	Stage          string  `json:"stage"`
	Status         string  `json:"status"`
	ErrorCode      *string `json:"errorCode"`
	ValidationCode *string `json:"validationCode"`
	BlockNumber    int64   `json:"blockNumber"`
	BlockHash      string  `json:"blockHash,omitempty"`
	Delivered      bool    `json:"delivered"`
}

// OperationSubmitBackend executes endorse/broadcast/commit recovery steps on behalf of ManagementOperationService.
type OperationSubmitBackend interface {
	CurrentRevision(ctx context.Context, method string, input json.RawMessage) (uint64, bool, error)
	SubmitAsync(ctx context.Context, opKey, opID string, caller api.Management, method string, input json.RawMessage, onUpdate func(stage, status string, txID string, blockNo int64, blockHash string, valCode, failCode *string, delivered bool) error)
}

// ManagementOperationService provides synchronous pre-acceptance version checks, idempotent 202 acceptance,
// GET /v1/operations/{id} status projection, and DUPLICATE_TXID-safe commit outcome recording.
type ManagementOperationService struct {
	db           *pgxpool.Pool
	deploymentID string
	rootMgmt     api.Management
	backend      OperationSubmitBackend

	mu                    sync.RWMutex
	suppressVisibilityIDs map[string]bool
	deliveredOps          map[string]bool
	running               map[string]bool
}

// NewManagementOperationService creates a ManagementOperationService bound to db and deploymentID.
func NewManagementOperationService(db *pgxpool.Pool, deploymentID string, rootMgmt api.Management, backend OperationSubmitBackend) *ManagementOperationService {
	return &ManagementOperationService{
		db:                    db,
		deploymentID:          deploymentID,
		rootMgmt:              rootMgmt,
		backend:               backend,
		suppressVisibilityIDs: make(map[string]bool),
		deliveredOps:          make(map[string]bool),
		running:               make(map[string]bool),
	}
}

// SetVisibilitySuppressed temporarily hides final commit status for opID so GET /v1/operations/{id} reports PENDING (S101).
func (s *ManagementOperationService) SetVisibilitySuppressed(opID string, hidden bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hidden {
		s.suppressVisibilityIDs[opID] = true
	} else {
		delete(s.suppressVisibilityIDs, opID)
	}
}

// MarkDelivered records whether post-confirmation material delivery executed (must remain false on FAILED ops).
func (s *ManagementOperationService) MarkDelivered(opID string, delivered bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deliveredOps[opID] = delivered
}

// IsDelivered reports whether post-confirmation material delivery ran for opID.
func (s *ManagementOperationService) IsDelivered(opID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deliveredOps[opID]
}

// Accept submits a management operation with pre-acceptance expectedRevision check and idempotency deduplication.
// Returns HTTP status (202 on accept/exact retry, 403/409 on rejection), view (when 202), and error (when rejected).
func (s *ManagementOperationService) Accept(
	ctx context.Context,
	opKey string,
	caller api.Management,
	method string,
	input json.RawMessage,
	triggerBackend bool,
) (int, *OperationView, error) {
	if s == nil || s.db == nil {
		return http.StatusServiceUnavailable, nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "operation store unavailable")
	}
	if opKey == "" || method == "" {
		return http.StatusBadRequest, nil, protocol.NewError(protocol.ErrCodeInvalidSchema, "operationKey and method required")
	}
	// Trust management endpoints are restricted to T (boot.Root.Management) at the HTTP boundary (S85).
	if (method == "CertifyDomain" || method == "RevokeCertification" || method == "SetDomainStatus" || method == "UpdateAuthorityIdentity") &&
		s.rootMgmt.Valid() && caller != s.rootMgmt {
		return http.StatusForbidden, nil, protocol.NewError(protocol.ErrCodeTrustManagementForbidden, fmt.Sprintf("caller %s not permitted for %s", caller, method))
	}

	var compactBuf bytes.Buffer
	if err := json.Compact(&compactBuf, input); err != nil {
		return http.StatusBadRequest, nil, protocol.WrapError(protocol.ErrCodeInvalidSchema, "invalid JSON payload", err)
	}
	canonInput := compactBuf.Bytes()
	mat, err := json.Marshal([]string{s.deploymentID, caller.String(), api.Channel, api.Registry, method, string(canonInput)})
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	payloadHash := api.Digest(mat)

	// 1. Check idempotency record first so exact retries still return 202 with original operationId even after completion/failure.
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return http.StatusServiceUnavailable, nil, err
	}
	defer tx.Rollback(context.Background())

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, s.deploymentID+":"+opKey); err != nil {
		return http.StatusServiceUnavailable, nil, err
	}
	var existing OperationView
	var existingPayloadHash string
	var existingBlockNo int64
	err = tx.QueryRow(ctx, `SELECT operation_id, method, tx_id, stage, status, validation_code, failure_code, block_no, block_hash, payload_hash
		FROM operations WHERE deployment_id=$1 AND operation_key=$2 FOR UPDATE`,
		s.deploymentID, opKey).
		Scan(&existing.OperationID, &existing.Method, &existing.TxID, &existing.Stage, &existing.Status,
			&existing.ValidationCode, &existing.ErrorCode, &existingBlockNo, &existing.BlockHash, &existingPayloadHash)
	if err == nil {
		if existingPayloadHash != payloadHash {
			return http.StatusConflict, nil, protocol.NewError(protocol.ErrCodeIdempotencyConflict, fmt.Sprintf("operationKey %q reused with different payload", opKey))
		}
		if err := tx.Commit(ctx); err != nil {
			return http.StatusServiceUnavailable, nil, err
		}
		existing.OperationKey = opKey
		existing.BlockNumber = existingBlockNo
		if existing.Status != "FAILED" {
			existing.ErrorCode = nil
		}
		existing.Delivered = s.IsDelivered(existing.OperationID)
		if triggerBackend && existing.Status == "PENDING" && s.backend != nil {
			s.dispatch(opKey, existing.OperationID, caller, method, canonInput)
		}
		return http.StatusAccepted, &existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return http.StatusServiceUnavailable, nil, err
	}

	// 2. Pre-acceptance expectedRevision check BEFORE inserting operations row or creating proposal (S100).
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
				return http.StatusConflict, nil, protocol.NewError(protocol.ErrCodeStateChanged,
					fmt.Sprintf("pre-acceptance revision conflict: expected %d, current %d", *revCheck.ExpectedRevision, curRev))
			}
		}
	}

	opID := s.deploymentID + ":" + opKey
	txID := "pending:" + api.Digest([]byte(opID))[:24]
	if _, err := tx.Exec(ctx, `INSERT INTO operations(
		deployment_id, operation_key, operation_id, caller_msp_id, caller_fingerprint,
		method, tx_id, block_no, block_hash, stage, status, validation_code, failure_code, payload_hash, request_json, updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,0,'','ACCEPT','PENDING',NULL,NULL,$8,$9,NOW())`,
		s.deploymentID, opKey, opID, caller.MSPID, caller.Fingerprint, method, txID, payloadHash, canonInput); err != nil {
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

// RecordOutcome updates an operation row monotonically while protecting terminal VALID/CONFIRMED
// outcomes against late DUPLICATE_TXID overwrites (S101).
func (s *ManagementOperationService) RecordOutcome(
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

	var curStatus string
	var curVal *string
	err = tx.QueryRow(ctx, `SELECT status, validation_code FROM operations WHERE deployment_id=$1 AND operation_id=$2 FOR UPDATE`,
		s.deploymentID, opID).Scan(&curStatus, &curVal)
	if err != nil {
		return err
	}
	// DUPLICATE_TXID must never overwrite an existing terminal outcome (or revert VALID -> INVALID) (S101).
	if (curStatus == "CONFIRMED" || curStatus == "FAILED") && valCode != nil && *valCode == "DUPLICATE_TXID" {
		return tx.Commit(ctx)
	}
	if (curStatus == "FAILED" && statusStr == "PENDING") || (curStatus == "CONFIRMED" && statusStr != "CONFIRMED") {
		return tx.Commit(ctx)
	}
	// Normalize failureCode per S100/S101 when failureCode not explicitly set.
	if statusStr == "FAILED" && failCode == nil {
		mapped := "COMMIT_INVALID"
		if valCode != nil && *valCode == "MVCC_READ_CONFLICT" {
			mapped = "STATE_CHANGED"
		} else if stage == "ENDORSE" {
			mapped = "ENDORSEMENT_REJECTED"
		}
		failCode = &mapped
	}
	if _, err := tx.Exec(ctx, `UPDATE operations SET
		stage=$3, status=$4, tx_id=CASE WHEN $5<>'' THEN $5 ELSE tx_id END,
		block_no=$6, block_hash=$7, validation_code=$8, failure_code=$9, delivered=delivered OR $10, updated_at=NOW()
		WHERE deployment_id=$1 AND operation_id=$2`,
		s.deploymentID, opID, stage, statusStr, txID, blockNo, blockHash, valCode, failCode, statusStr == "CONFIRMED" && delivered); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if statusStr == "CONFIRMED" && delivered {
		s.MarkDelivered(opID, true)
	}
	return nil
}

// GetOperation returns HTTP 200 status for opID, masking terminal fields as PENDING/null while visibility is hidden (S101).
func (s *ManagementOperationService) GetOperation(ctx context.Context, opID string) (*OperationView, error) {
	if s == nil || s.db == nil {
		return nil, protocol.NewError(protocol.ErrCodeStateUnavailable, "operation store unavailable")
	}
	var out OperationView
	err := s.db.QueryRow(ctx, `SELECT operation_id, operation_key, method, tx_id, stage, status, validation_code, failure_code, block_no, block_hash, delivered
		FROM operations WHERE deployment_id=$1 AND operation_id=$2`,
		s.deploymentID, opID).
		Scan(&out.OperationID, &out.OperationKey, &out.Method, &out.TxID, &out.Stage, &out.Status,
			&out.ValidationCode, &out.ErrorCode, &out.BlockNumber, &out.BlockHash, &out.Delivered)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, protocol.NewError(protocol.ErrCodeChallengeUnknown, fmt.Sprintf("unknown operationId %q", opID))
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

// Handler exposes POST /v1/management/{method} (202/403/409) and GET /v1/operations/{operationId} (200/404).
func (s *ManagementOperationService) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/operations/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		opID := strings.TrimPrefix(r.URL.Path, "/v1/operations/")
		if opID == "" {
			http.Error(w, "missing operationId", http.StatusBadRequest)
			return
		}
		view, err := s.GetOperation(r.Context(), opID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": "OPERATION_UNKNOWN", "message": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(view)
	})
	mux.HandleFunc("/v1/management/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		method := strings.TrimPrefix(r.URL.Path, "/v1/management/")
		opKey := r.Header.Get("Idempotency-Key")
		id, authenticated := serviceauth.Caller(r)
		caller := api.Management{MSPID: id.MSPID, Fingerprint: id.Fingerprint}
		if resolver, ok := s.backend.(interface {
			ManagementForFingerprint(string) (api.Management, bool)
		}); ok {
			caller, authenticated = resolver.ManagementForFingerprint(id.Fingerprint)
			authenticated = authenticated && id.Fingerprint != "" && (r.TLS != nil || id.Role != "")
		}
		if !authenticated || !caller.Valid() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"errorCode": "IDENTITY_MANAGEMENT_FORBIDDEN"})
			return
		}
		if s.backend == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		var raw json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": protocol.ErrCodeInvalidSchema, "message": err.Error()})
			return
		}
		code, view, err := s.Accept(r.Context(), opKey, caller, method, raw, true)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if err != nil {
			errCode := protocol.ErrCodeInvalidSchema
			var pe *protocol.Error
			if errors.As(err, &pe) && pe.Code != "" {
				errCode = pe.Code
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": errCode, "message": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(view)
	})
	return mux
}
