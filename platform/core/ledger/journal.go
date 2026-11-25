package ledger

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	gw "github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	msp "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"grad/protocol/registry"
)

// Outcome records the block coordinate, transaction index, and peer validation code
// of an original committed Fabric transaction.
type Outcome struct {
	ObservedPeer string `json:"observedPeer"`
	Point
	Index int    `json:"transactionIndex"`
	Code  string `json:"validationCode"`
}

// Operation records the durable original-txID journal state stored in fabric_operation.
type Operation struct {
	DeploymentID string              `json:"deploymentId"`
	Key          string              `json:"operationKey"`
	InputDigest  string              `json:"inputSha256"`
	Role         string              `json:"role"`
	Caller       registry.Management `json:"caller"`
	Channel      string              `json:"channelId"`
	Chaincode    string              `json:"chaincode"`
	Method       string              `json:"method"`
	TxID         string              `json:"txId"`
	Proposal     []byte              `json:"signedProposal"`
	Signed       []byte              `json:"signedTransaction,omitempty"`
	Status       string              `json:"status"`
	Stage        string              `json:"stage"`
	FailureCode  *string             `json:"failureCode"`
	Observation  string              `json:"observation,omitempty"`
	Commit       *Outcome            `json:"commit,omitempty"`
	AcceptedAt   time.Time           `json:"acceptedAt"`
	SignedAt     *time.Time          `json:"signedAt,omitempty"`
	BroadcastAt  *time.Time          `json:"firstBroadcastAt,omitempty"`
	ObservedAt   *time.Time          `json:"firstObservedAt,omitempty"`
}

// RevocationEvent captures original-tx revocation submission and trusted-peer VALID observation timings.
type RevocationEvent struct {
	OperationKey    string    `json:"operationKey"`
	TxID            string    `json:"txId"`
	Role            string    `json:"role"`
	GrantID         string    `json:"grantId"`
	BlockNumber     uint64    `json:"blockNumber"`
	BlockHash       string    `json:"blockHash"`
	TxIndex         int       `json:"transactionIndex"`
	ValidationCode  string    `json:"validationCode"`
	Status          string    `json:"status"`
	SubmittedAt     time.Time `json:"submittedAt"`
	ValidObservedAt time.Time `json:"validObservedAt"`
}

// Journal persists and recovers idempotent Fabric operations strictly in the fabric_operation table,
// preserving the original signed proposal and transaction bytes across retries and DUPLICATE_TXID replays.
type Journal struct {
	Instance     *Instance
	DeploymentID string
	DB           *pgxpool.Pool
}

// NewJournal constructs a Journal bound to inst, db, and deploymentID.
func NewJournal(inst *Instance, db *pgxpool.Pool, deploymentID string) Journal {
	return Journal{Instance: inst, DB: db, DeploymentID: deploymentID}
}

// RejectedBeforeSigning reports whether op failed during endorsement before any signed transaction
// was created, broadcast, or committed.
func (op *Operation) RejectedBeforeSigning() bool {
	return op != nil && op.Status == "FAILED" && op.Stage == "ENDORSE" &&
		op.FailureCode != nil && *op.FailureCode != "" && op.Observation != "" &&
		registry.IsDigest(op.TxID) && len(op.Proposal) > 0 &&
		len(op.Signed) == 0 && op.SignedAt == nil && op.BroadcastAt == nil && op.Commit == nil
}

func (op *Operation) confirmAt(commit *Outcome, observedAt time.Time) {
	op.Commit, op.Stage = commit, "COMMIT"
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	op.ObservedAt = &observedAt
	switch commit.Code {
	case "VALID":
		op.Status = "CONFIRMED"
	case "MVCC_READ_CONFLICT":
		code := registry.ErrCodeStateChanged
		op.Status, op.FailureCode = "FAILED", &code
	default:
		code := registry.ErrCodeCommitInvalid
		op.Status, op.FailureCode = "FAILED", &code
	}
}

// Lock acquires a PostgreSQL session advisory lock for (DeploymentID, key) on a dedicated connection.
func (j Journal) Lock(ctx context.Context, key string) (*pgxpool.Conn, func(), error) {
	if key == "" || len(key) > 180 || strings.ContainsRune(key, 0) {
		return nil, nil, fmt.Errorf("invalid operation key")
	}
	conn, err := j.DB.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	lockID := int64(binary.BigEndian.Uint64(digestBytes([]byte(j.DeploymentID + "/" + key))))
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		// A lost response may have acquired the session lock; discard the connection.
		conn.Hijack().Close(context.Background())
		return nil, nil, err
	}
	return conn, func() {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := conn.Exec(c, "SELECT pg_advisory_unlock($1)", lockID); err != nil {
			conn.Hijack().Close(c)
		} else {
			conn.Release()
		}
	}, nil
}

// Load retrieves a journaled Operation from fabric_operation, returning (nil, nil) if absent.
func (j Journal) Load(ctx context.Context, key string, conn RowReader) (*Operation, error) {
	var raw []byte
	err := conn.QueryRow(ctx, "SELECT data FROM fabric_operation WHERE deployment=$1 AND operation_key=$2",
		j.DeploymentID, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var op Operation
	if err := json.Unmarshal(raw, &op); err != nil {
		return nil, err
	}
	if op.DeploymentID != j.DeploymentID || op.Key != key || op.Channel != registry.Channel || op.Chaincode != registry.Registry {
		return nil, fmt.Errorf("operation journal deployment mismatch")
	}
	return &op, nil
}

// Save upserts op into fabric_operation. Higher-level HTTP operation projection belongs to registrysvc.
func (j Journal) Save(ctx context.Context, conn *pgxpool.Conn, op *Operation) error {
	raw, err := json.Marshal(op)
	if err != nil {
		return err
	}
	_, err = conn.Exec(ctx, `INSERT INTO fabric_operation(deployment, operation_key, data) VALUES($1,$2,$3)
		ON CONFLICT(deployment, operation_key) DO UPDATE SET data=EXCLUDED.data`, j.DeploymentID, op.Key, raw)
	return err
}

// MatchInput verifies that role, method, and input match stored's persisted input digest.
func (j Journal) MatchInput(stored *Operation, role, method string, input []byte) (registry.Management, string, error) {
	_, caller, _, err := j.Instance.Role(role)
	if err != nil {
		return registry.Management{}, "", err
	}
	material, err := json.Marshal([]string{j.DeploymentID, caller.String(), registry.Channel, registry.Registry, method, string(input)})
	if err != nil {
		return registry.Management{}, "", err
	}
	hash := registry.Digest(material)
	if stored != nil && stored.InputDigest != hash {
		return registry.Management{}, "", fmt.Errorf("OPERATION_KEY_CONFLICT: %s", stored.Key)
	}
	return caller, hash, nil
}

// Prepare durably persists an original signed proposal (if new) and collects endorsements without broadcasting.
func (j Journal) Prepare(ctx context.Context, key, role, method string, input []byte, orgs ...string) (*Operation, error) {
	conn, unlock, err := j.Lock(ctx, key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	op, err := j.Load(ctx, key, conn)
	if err != nil {
		return nil, err
	}
	caller, hash, err := j.MatchInput(op, role, method, input)
	if err != nil {
		return nil, err
	}
	if op != nil && (op.Status != "PENDING" || len(op.Signed) > 0 || op.BroadcastAt != nil) {
		return op, nil
	}
	p, err := j.Instance.Peer(j.Instance.clientOrg, role)
	if err != nil {
		return op, err
	}
	defer p.Close()
	var proposal *client.Proposal
	if op == nil {
		p0, raw, err := p.Proposal(method, input, orgs)
		if err != nil {
			return nil, err
		}
		proposal = p0
		op = &Operation{
			DeploymentID: j.DeploymentID,
			Key:          key,
			InputDigest:  hash,
			Role:         role,
			Caller:       caller,
			Channel:      registry.Channel,
			Chaincode:    registry.Registry,
			Method:       method,
			TxID:         proposal.TransactionID(),
			Proposal:     raw,
			Status:       "PENDING",
			Stage:        "ENDORSE",
			AcceptedAt:   time.Now().UTC(),
		}
		if err := j.Save(ctx, conn, op); err != nil {
			return nil, err
		}
	} else {
		proposal, err = p.gateway.NewProposal(op.Proposal)
		if err != nil {
			return op, err
		}
	}
	return j.Endorse(ctx, conn, p, proposal, op)
}

// Endorse collects Fabric endorsements for proposal, signs the endorsed transaction, and persists op.
func (j Journal) Endorse(ctx context.Context, conn *pgxpool.Conn, p *PeerClient, proposal *client.Proposal, op *Operation) (*Operation, error) {
	endorseCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	tx, err := proposal.EndorseWithContext(endorseCtx)
	cancel()
	if err != nil {
		op.Observation = err.Error()
		if code := ParseEndorsementFailure(err); code != "" {
			op.Status, op.FailureCode = "FAILED", &code
		}
		return op, j.Save(ctx, conn, op)
	}
	if tx.TransactionID() != op.TxID {
		return op, fmt.Errorf("endorsed transaction ID mismatch")
	}
	_, op.Signed, err = p.SignTransaction(tx)
	if err != nil {
		return op, err
	}
	now := time.Now().UTC()
	op.SignedAt, op.Stage, op.Observation = &now, "SUBMIT", ""
	return op, j.Save(ctx, conn, op)
}

type endorseErrorDetails interface {
	Details() []*gw.ErrorDetail
}

var _ endorseErrorDetails = (*client.EndorseError)(nil)

// ParseEndorsementFailure extracts a canonical registry.ErrCode* from a deterministic Fabric endorsement error,
// or returns "" for transient transport/availability errors that must remain PENDING.
func ParseEndorsementFailure(err error) string {
	switch status.Code(err) {
	case codes.Aborted, codes.PermissionDenied, codes.InvalidArgument:
	default:
		return ""
	}
	var e endorseErrorDetails
	reason := ""
	if errors.As(err, &e) {
		for _, d := range e.Details() {
			if code := extractChaincodeErrorCode(d.Message); code != "" {
				if reason != "" && reason != code {
					return registry.ErrCodeEndorsementRejected
				}
				reason = code
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
	return registry.ErrCodeEndorsementRejected
}

func extractChaincodeErrorCode(msg string) string {
	if !strings.Contains(msg, "chaincode response") {
		return ""
	}
	_, after, ok := strings.Cut(msg, "chaincode response")
	if !ok {
		return ""
	}
	_, payload, ok := strings.Cut(after, ",")
	if !ok {
		return ""
	}
	payload = strings.TrimSpace(payload)
	if registry.IsProposalCode(payload) {
		return payload
	}
	if prefix, _, ok := strings.Cut(payload, ":"); ok {
		prefix = strings.TrimSpace(prefix)
		if registry.IsProposalCode(prefix) {
			return prefix
		}
	}
	return ""
}

// Write prepares, endorses, broadcasts, and observes the original commit outcome for (key, role, method, input).
func (j Journal) Write(ctx context.Context, key, role, method string, input []byte) (*Operation, error) {
	op, err := j.Prepare(ctx, key, role, method, input)
	if err != nil || op.Status != "PENDING" || len(op.Signed) == 0 {
		return op, err
	}
	return j.Recover(ctx, key, nil)
}

// Recover resumes a PENDING journaled operation strictly using its original proposal/signed transaction bytes.
// submitOverride is an optional test hook used to inject lost submit responses after broadcast.
func (j Journal) Recover(ctx context.Context, key string, submitOverride func(context.Context, *client.Transaction) error) (*Operation, error) {
	conn, unlock, err := j.Lock(ctx, key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	op, err := j.Load(ctx, key, conn)
	if err != nil {
		return op, err
	}
	if op == nil {
		return nil, fmt.Errorf("unknown operation %q", key)
	}
	if op.Status != "PENDING" {
		return op, nil
	}
	p, err := j.Instance.Peer(j.Instance.clientOrg, op.Role)
	if err != nil {
		return op, err
	}
	defer p.Close()
	if p.role != op.Caller {
		return op, fmt.Errorf("operation signer binding changed")
	}
	if len(op.Signed) == 0 {
		proposal, err := p.gateway.NewProposal(op.Proposal)
		if err != nil {
			return op, err
		}
		op, err = j.Endorse(ctx, conn, p, proposal, op)
		if err != nil || op.Status != "PENDING" || len(op.Signed) == 0 {
			return op, err
		}
	}
	prepared, err := decodeProto(op.Signed, &gw.PreparedTransaction{})
	if err != nil {
		return op, err
	}
	if err := ValidateOriginal(prepared, op); err != nil {
		return op, err
	}
	if op.BroadcastAt != nil {
		commit, observedAt, err := p.OriginalObserved(ctx, op, prepared)
		if err == nil {
			op.confirmAt(commit, observedAt)
			return op, j.Save(ctx, conn, op)
		}
	} else {
		now := time.Now().UTC()
		op.BroadcastAt = &now
		op.Stage = "COMMIT"
		if err := j.Save(ctx, conn, op); err != nil {
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
		return op, j.Save(ctx, conn, op)
	}
	op.Observation = "broadcast acknowledged"
	commit, observedAt, err := p.OriginalObserved(ctx, op, prepared)
	if err != nil {
		op.Observation += "; " + err.Error()
	} else {
		op.confirmAt(commit, observedAt)
	}
	return op, j.Save(ctx, conn, op)
}

// ValidateOriginal verifies that prepared carries the exact channel, txID, chaincode, creator,
// and non-empty signature recorded in op.
func ValidateOriginal(prepared *gw.PreparedTransaction, op *Operation) error {
	pl, ch, err := EnvelopeHeader(prepared.Envelope)
	if err != nil || ch.ChannelId != op.Channel || ch.TxId != op.TxID || prepared.TransactionId != op.TxID ||
		len(prepared.GetEnvelope().GetSignature()) == 0 {
		return fmt.Errorf("signed transaction header mismatch")
	}
	creator, cc, err := TransactionIdentity(pl, ch)
	if err != nil || cc != op.Chaincode || creator != op.Caller {
		return fmt.Errorf("signed transaction creator or chaincode mismatch")
	}
	return nil
}

// ExpectOperation asserts that op reached the expected terminal or pending state.
func ExpectOperation(op *Operation, expected string) error {
	if op == nil {
		return fmt.Errorf("expected operation %s", expected)
	}
	switch expected {
	case "VALID":
		if op.Status == "CONFIRMED" && op.Commit != nil && op.Commit.Code == "VALID" {
			return nil
		}
	case "PENDING":
		if op.Status == "PENDING" && op.Commit == nil {
			return nil
		}
	default:
		if op.Status == "FAILED" && ((op.Commit != nil && op.Commit.Code == expected) ||
			(op.Commit == nil && op.FailureCode != nil && *op.FailureCode == expected)) {
			return nil
		}
	}
	failure := ""
	if op.FailureCode != nil {
		failure = *op.FailureCode
	}
	return fmt.Errorf("%s: expected %s, got %s at %s (failure=%s, commit=%+v, %s)",
		op.Key, expected, op.Status, op.Stage, failure, op.Commit, op.Observation)
}

// Proposal creates and signs a new Fabric chaincode proposal for method on the registry chaincode.
func (p *PeerClient) Proposal(method string, input []byte, orgs []string) (*client.Proposal, []byte, error) {
	options := []client.ProposalOption{client.WithBytesArguments(input)}
	if len(orgs) > 0 {
		options = append(options, client.WithEndorsingOrganizations(orgs...))
	}
	proposal, err := p.Contract(registry.Registry).NewProposal(method, options...)
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

// SignTransaction signs an endorsed Fabric transaction and returns its serialized bytes.
func (p *PeerClient) SignTransaction(tx *client.Transaction) (*client.Transaction, []byte, error) {
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

// CommitStatus queries the Fabric Gateway CommitStatus RPC on the pinned peer for txID.
func (p *PeerClient) CommitStatus(ctx context.Context, txID string) (*gw.CommitStatusResponse, error) {
	id := p.gateway.Identity()
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: id.MspID(), IdBytes: id.Credentials()})
	if err != nil {
		return nil, err
	}
	raw, err := proto.Marshal(&gw.CommitStatusRequest{ChannelId: registry.Channel, TransactionId: txID, Identity: creator})
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

// Original resolves the original (non-DUPLICATE_TXID) committed Outcome matching prepared.Envelope.
func (p *PeerClient) Original(ctx context.Context, op *Operation, prepared *gw.PreparedTransaction) (*Outcome, error) {
	c, _, err := p.OriginalObserved(ctx, op, prepared)
	return c, err
}

// OriginalObserved resolves the original committed Outcome and observation time while ignoring DUPLICATE_TXID replays.
func (p *PeerClient) OriginalObserved(ctx context.Context, op *Operation, prepared *gw.PreparedTransaction) (*Outcome, time.Time, error) {
	seen, seenErr := p.CommitStatus(ctx, op.TxID)
	observedAt := time.Now().UTC()
	b, err := p.QueryBlock(ctx, "GetBlockByTxID", op.TxID)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("original transaction is not available: %w", err)
	}
	match := func(b *Block) *Outcome {
		for _, t := range b.Transactions {
			if t.ID == op.TxID && t.Code != pb.TxValidationCode_DUPLICATE_TXID && proto.Equal(t.Envelope, prepared.Envelope) {
				return &Outcome{ObservedPeer: p.name, Point: b.Point, Index: t.Index, Code: t.Code.String()}
			}
		}
		return nil
	}
	if found := match(b); found != nil && (seenErr != nil || seen.Result == pb.TxValidationCode_DUPLICATE_TXID ||
		(seen.BlockNumber == found.Number && seen.Result.String() == found.Code)) {
		return found, observedAt, nil
	}
	// Some indexes can report a replay. Search earlier blocks for the original signed envelope.
	for n := uint64(0); n < b.Number; n++ {
		old, err := p.GetBlock(ctx, n)
		if err != nil {
			return nil, time.Time{}, err
		}
		if found := match(old); found != nil && (seenErr != nil || seen.Result == pb.TxValidationCode_DUPLICATE_TXID ||
			(seen.BlockNumber == found.Number && seen.Result.String() == found.Code)) {
			return found, observedAt, nil
		}
	}
	return nil, time.Time{}, fmt.Errorf("could not bind original signed transaction to the Peer validation result")
}

// RevokeGrant submits an original-txID RevokeGrant management operation and returns its submit and VALID timings.
func (i *Instance) RevokeGrant(ctx context.Context, db *pgxpool.Pool, d *Deployment, opKey, role, grantID, reason string) (*RevocationEvent, error) {
	var rawGrant []byte
	if err := db.QueryRow(ctx, `SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2`, d.DeploymentID, registry.Key("grant", grantID)).Scan(&rawGrant); err != nil {
		return nil, fmt.Errorf("load current grant %s before revocation: %w", grantID, err)
	}
	var current registry.Grant
	if err := json.Unmarshal(rawGrant, &current); err != nil {
		return nil, fmt.Errorf("decode current grant %s: %w", grantID, err)
	}
	mut := registry.Mutation{
		Bound:            registry.Bound{DeploymentID: d.DeploymentID},
		ID:               current.ID,
		ExpectedRevision: current.Revision,
		ExpectedDigest:   current.Digest,
		Reason:           reason,
	}
	payload, err := json.Marshal(mut)
	if err != nil {
		return nil, err
	}
	j := NewJournal(i, db, d.DeploymentID)
	op, err := j.Write(ctx, opKey, role, "RevokeGrant", payload)
	if err != nil {
		return nil, err
	}
	if op == nil || op.Status != "CONFIRMED" || op.Commit == nil || op.Commit.Code != "VALID" {
		statusStr := ""
		obs := ""
		if op != nil {
			statusStr = op.Status
			obs = op.Observation
		}
		return nil, fmt.Errorf("RevokeGrant did not confirm VALID: status=%s observation=%s", statusStr, obs)
	}
	ev := &RevocationEvent{
		OperationKey:   op.Key,
		TxID:           op.TxID,
		Role:           role,
		GrantID:        grantID,
		BlockNumber:    op.Commit.Number,
		BlockHash:      op.Commit.Hash,
		TxIndex:        op.Commit.Index,
		ValidationCode: op.Commit.Code,
		Status:         op.Status,
	}
	if op.BroadcastAt != nil {
		ev.SubmittedAt = op.BroadcastAt.UTC()
	}
	if op.ObservedAt != nil {
		ev.ValidObservedAt = op.ObservedAt.UTC()
	}
	return ev, nil
}
