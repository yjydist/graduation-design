package fabric

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	msp "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"grad/protocol/registry"
)

// ErrInvalidPeerBlock indicates a malformed or integrity-failed block returned by a Fabric Peer.
var ErrInvalidPeerBlock = errors.New("invalid block from Peer")

// Point identifies a Fabric block by height and ASN.1 header hash.
type Point struct {
	Number uint64 `json:"blockNumber"`
	Hash   string `json:"blockHash"`
}

// Block represents a parsed and integrity-checked Fabric block.
type Block struct {
	Point
	Parent       string
	ConfigDigest string
	Transactions []BlockTx
	Raw          *cb.Block
}

// BlockTx represents one transaction inside a Fabric block along with its validation code and KV writes.
type BlockTx struct {
	Index            int                 `json:"transactionIndex"`
	ID               string              `json:"txId"`
	Code             pb.TxValidationCode `json:"-"`
	Chaincode        string              `json:"chaincode"`
	Creator          registry.Management `json:"creator"`
	Envelope         *cb.Envelope        `json:"-"`
	Writes           []*kvrwset.KVWrite  `json:"-"`
	DefinitionChange bool                `json:"-"`
}

func digestBytes(b []byte) []byte {
	d := sha256.Sum256(b)
	return d[:]
}

func decodeProto[T proto.Message](b []byte, dst T) (T, error) {
	err := proto.Unmarshal(b, dst)
	return dst, err
}

// HeaderHash computes the canonical Fabric ASN.1 DER SHA-256 hash of a block header.
func HeaderHash(h *cb.BlockHeader) string {
	der, _ := asn1.Marshal(struct {
		Number       *big.Int
		PreviousHash []byte
		DataHash     []byte
	}{new(big.Int).SetUint64(h.Number), h.PreviousHash, h.DataHash})
	return registry.Digest(der)
}

// EnvelopeHeader decodes the Payload and ChannelHeader from a Fabric Envelope.
func EnvelopeHeader(envelope *cb.Envelope) (*cb.Payload, *cb.ChannelHeader, error) {
	payload, err := decodeProto(envelope.GetPayload(), &cb.Payload{})
	if err != nil || payload.GetHeader() == nil {
		return nil, nil, fmt.Errorf("invalid transaction payload or header: %v", err)
	}
	ch, err := decodeProto(payload.Header.ChannelHeader, &cb.ChannelHeader{})
	return payload, ch, err
}

// DecodeBlock unmarshals a serialized common.Block and verifies its integrity via ParseBlock.
func DecodeBlock(data []byte) (*Block, error) {
	raw, err := decodeProto(data, &cb.Block{})
	if err != nil {
		return nil, err
	}
	return ParseBlock(raw)
}

// ParseBlock verifies block header linkage, data hash, transaction validation filter,
// channel binding, transaction identities, and registry/lifecycle write sets.
func ParseBlock(raw *cb.Block) (*Block, error) {
	h := raw.GetHeader()
	if h == nil || raw.GetData() == nil || len(raw.Data.Data) == 0 ||
		(h.Number == 0 && len(h.PreviousHash) != 0) || (h.Number > 0 && len(h.PreviousHash) != 32) {
		return nil, fmt.Errorf("incomplete Fabric block")
	}
	digest := sha256.New()
	for _, data := range raw.Data.Data {
		digest.Write(data)
	}
	if hex.EncodeToString(digest.Sum(nil)) != hex.EncodeToString(h.DataHash) {
		return nil, fmt.Errorf("block %d data hash mismatch", h.Number)
	}
	b := &Block{
		Point:  Point{Number: h.Number, Hash: HeaderHash(h)},
		Parent: hex.EncodeToString(h.PreviousHash),
		Raw:    raw,
	}
	index := int(cb.BlockMetadataIndex_TRANSACTIONS_FILTER)
	var filter []byte
	if len(raw.GetMetadata().GetMetadata()) > index {
		filter = raw.Metadata.Metadata[index]
	}
	// configtxgen's genesis has no validation filter before a Peer joins.
	if !(h.Number == 0 && len(filter) == 0 && len(raw.Data.Data) == 1) && len(filter) != len(raw.Data.Data) {
		return nil, fmt.Errorf("block %d transaction validation metadata length mismatch", h.Number)
	}
	for n, data := range raw.Data.Data {
		t := BlockTx{Index: n}
		if len(filter) > 0 {
			t.Code = pb.TxValidationCode(filter[n])
			if _, ok := pb.TxValidationCode_name[int32(t.Code)]; !ok || t.Code == pb.TxValidationCode_NOT_VALIDATED {
				return nil, fmt.Errorf("block %d transaction %d has unknown validation code %d", h.Number, n, t.Code)
			}
		}
		env, err := decodeProto(data, &cb.Envelope{})
		if err != nil {
			if t.Code != pb.TxValidationCode_VALID {
				b.Transactions = append(b.Transactions, t)
				continue
			}
			return nil, err
		}
		t.Envelope = env
		payload, ch, err := EnvelopeHeader(env)
		if err != nil {
			if t.Code != pb.TxValidationCode_VALID {
				b.Transactions = append(b.Transactions, t)
				continue
			}
			return nil, err
		}
		if ch.ChannelId != registry.Channel {
			return nil, fmt.Errorf("block %d unexpected channel %q", h.Number, ch.ChannelId)
		}
		t.ID = ch.TxId
		switch cb.HeaderType(ch.Type) {
		case cb.HeaderType_CONFIG:
			if t.Code != pb.TxValidationCode_VALID || len(raw.Data.Data) != 1 {
				return nil, fmt.Errorf("block %d invalid config transaction", h.Number)
			}
			config, err := decodeProto(payload.Data, &cb.ConfigEnvelope{})
			if err != nil || config.GetConfig().GetChannelGroup() == nil {
				return nil, fmt.Errorf("block %d missing config: %v", h.Number, err)
			}
			c, err := proto.MarshalOptions{Deterministic: true}.Marshal(config.Config)
			if err != nil {
				return nil, err
			}
			b.ConfigDigest = registry.Digest(c)
		case cb.HeaderType_ENDORSER_TRANSACTION:
			t.Creator, t.Chaincode, err = TransactionIdentity(payload, ch)
			if err != nil && t.Code == pb.TxValidationCode_VALID {
				return nil, err
			}
			if t.Code == pb.TxValidationCode_VALID {
				if err := ParseWrites(payload.Data, &t); err != nil {
					return nil, err
				}
			}
		default:
			if t.Code == pb.TxValidationCode_VALID {
				return nil, fmt.Errorf("block %d unexpected valid transaction type %d", h.Number, ch.Type)
			}
		}
		b.Transactions = append(b.Transactions, t)
	}
	if h.Number == 0 && b.ConfigDigest == "" {
		return nil, fmt.Errorf("genesis is missing channel config")
	}
	return b, nil
}

// TransactionIdentity extracts and verifies the creator Management identity, txId-nonce binding,
// and target chaincode name from a transaction payload.
func TransactionIdentity(payload *cb.Payload, ch *cb.ChannelHeader) (registry.Management, string, error) {
	sh, err := decodeProto(payload.GetHeader().GetSignatureHeader(), &cb.SignatureHeader{})
	if err != nil {
		return registry.Management{}, "", err
	}
	id, err := decodeProto(sh.Creator, &msp.SerializedIdentity{})
	if err != nil {
		return registry.Management{}, "", err
	}
	cert, err := identity.CertificateFromPEM(id.IdBytes)
	if err != nil {
		return registry.Management{}, "", err
	}
	digest := sha256.New()
	digest.Write(sh.Nonce)
	digest.Write(sh.Creator)
	if ch.TxId != hex.EncodeToString(digest.Sum(nil)) {
		return registry.Management{}, "", fmt.Errorf("transaction %s ID does not bind the creator and nonce", ch.TxId)
	}
	ext, err := decodeProto(ch.Extension, &pb.ChaincodeHeaderExtension{})
	if err != nil || ext.GetChaincodeId().GetName() == "" {
		return registry.Management{}, "", fmt.Errorf("transaction %s has no chaincode: %v", ch.TxId, err)
	}
	return registry.Management{MSPID: id.Mspid, CertificateSHA256: registry.Digest(cert.Raw)}, ext.ChaincodeId.Name, nil
}

// ParseWrites decodes the registry KV write set and _lifecycle definition changes for a VALID transaction.
func ParseWrites(data []byte, t *BlockTx) error {
	tx, err := decodeProto(data, &pb.Transaction{})
	if err != nil || len(tx.Actions) != 1 {
		return fmt.Errorf("transaction %s invalid actions: %v", t.ID, err)
	}
	action, err := decodeProto(tx.Actions[0].Payload, &pb.ChaincodeActionPayload{})
	if err != nil {
		return err
	}
	response, err := decodeProto(action.GetAction().GetProposalResponsePayload(), &pb.ProposalResponsePayload{})
	if err != nil {
		return err
	}
	cc, err := decodeProto(response.Extension, &pb.ChaincodeAction{})
	if err != nil || cc.GetChaincodeId().GetName() != t.Chaincode {
		return fmt.Errorf("transaction %s has inconsistent chaincode action: %v", t.ID, err)
	}
	set, err := decodeProto(cc.Results, &rwset.TxReadWriteSet{})
	if err != nil || set.DataModel != rwset.TxReadWriteSet_KV {
		return fmt.Errorf("transaction %s invalid read/write set: %v", t.ID, err)
	}
	for _, ns := range set.NsRwset {
		if ns.Namespace != registry.Registry && ns.Namespace != "_lifecycle" {
			continue
		}
		kv, err := decodeProto(ns.Rwset, &kvrwset.KVRWSet{})
		if err != nil {
			return err
		}
		if ns.Namespace == registry.Registry {
			t.Writes = append(t.Writes, kv.Writes...)
		} else {
			for _, w := range kv.Writes {
				if w.Key == "namespaces/metadata/"+registry.Registry ||
					w.Key == "namespaces/fields/"+registry.Registry+"/Sequence" ||
					w.Key == "namespaces/fields/"+registry.Registry+"/ValidationInfo" ||
					w.Key == "namespaces/fields/"+registry.Registry+"/EndorsementInfo" ||
					w.Key == "namespaces/fields/"+registry.Registry+"/Collections" {
					t.DefinitionChange = true
				}
			}
		}
	}
	return nil
}

// Height queries qscc GetChainInfo directly on the pinned peer.
func (p *PeerClient) Height(ctx context.Context) (uint64, error) {
	b, err := p.Direct(ctx, "qscc", "GetChainInfo", registry.Channel)
	if err != nil {
		return 0, err
	}
	info, err := decodeProto(b, &cb.BlockchainInfo{})
	return info.GetHeight(), err
}

// GetBlock queries qscc GetBlockByNumber directly on the pinned peer and parses it.
func (p *PeerClient) GetBlock(ctx context.Context, n uint64) (*Block, error) {
	return p.QueryBlock(ctx, "GetBlockByNumber", strconv.FormatUint(n, 10))
}

// QueryBlock executes a qscc block query (GetBlockByNumber / GetBlockByTxID) and validates the block.
func (p *PeerClient) QueryBlock(ctx context.Context, method, value string) (*Block, error) {
	b, err := p.Direct(ctx, "qscc", method, registry.Channel, value)
	if err != nil {
		return nil, err
	}
	result, err := DecodeBlock(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPeerBlock, err)
	}
	return result, nil
}

func (p *PeerClient) signedEnvelope(kind cb.HeaderType, data []byte) (*cb.Envelope, error) {
	id := p.gateway.Identity()
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: id.MspID(), IdBytes: id.Credentials()})
	if err != nil {
		return nil, err
	}
	sh, err := proto.Marshal(&cb.SignatureHeader{Creator: creator})
	if err != nil {
		return nil, err
	}
	ch, err := proto.Marshal(&cb.ChannelHeader{Type: int32(kind), ChannelId: registry.Channel, Timestamp: timestamppb.Now()})
	if err != nil {
		return nil, err
	}
	payload, err := proto.Marshal(&cb.Payload{Header: &cb.Header{SignatureHeader: sh, ChannelHeader: ch}, Data: data})
	if err != nil {
		return nil, err
	}
	sig, err := p.signer(digestBytes(payload))
	if err != nil {
		return nil, err
	}
	return &cb.Envelope{Payload: payload, Signature: sig}, nil
}

// Deliver opens a full-block Peer Deliver stream from block start through block stop inclusive.
func (p *PeerClient) Deliver(ctx context.Context, start, stop uint64) (pb.Deliver_DeliverClient, error) {
	pos := func(n uint64) *ab.SeekPosition {
		return &ab.SeekPosition{Type: &ab.SeekPosition_Specified{Specified: &ab.SeekSpecified{Number: n}}}
	}
	seek, err := proto.Marshal(&ab.SeekInfo{Start: pos(start), Stop: pos(stop), Behavior: ab.SeekInfo_BLOCK_UNTIL_READY})
	if err != nil {
		return nil, err
	}
	env, err := p.signedEnvelope(cb.HeaderType_DELIVER_SEEK_INFO, seek)
	if err != nil {
		return nil, err
	}
	stream, err := pb.NewDeliverClient(p.conn).Deliver(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.Send(env); err != nil {
		return nil, err
	}
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}
	return stream, nil
}

// ReceiveBlock reads and validates the next full block from a Peer Deliver stream.
func ReceiveBlock(stream pb.Deliver_DeliverClient) (*Block, error) {
	result, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	switch v := result.Type.(type) {
	case *pb.DeliverResponse_Block:
		return ParseBlock(v.Block)
	case *pb.DeliverResponse_Status:
		return nil, fmt.Errorf("Peer Deliver status %s", v.Status)
	default:
		return nil, fmt.Errorf("unexpected Peer Deliver response %T", v)
	}
}
