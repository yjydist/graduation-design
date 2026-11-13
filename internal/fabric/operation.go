package fabric

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	api "graduation-design/internal/fabricapi"

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
	_, err = conn.Exec(ctx, `INSERT INTO fabric_operation(deployment,operation_key,data) VALUES($1,$2,$3)
		ON CONFLICT(deployment,operation_key) DO UPDATE SET data=EXCLUDED.data`, j.deploymentID, op.Key, raw)
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
			for _, c := range []string{"UNAUTHORIZED", "INVALID_STRUCTURE", "MISSING_DEPENDENCY", "STATE_CHANGED", "INVALID_STATE", "ID_ALREADY_USED"} {
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
