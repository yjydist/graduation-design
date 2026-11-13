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

	api "graduation-design/internal/fabricapi"

	"github.com/hyperledger/fabric-gateway/pkg/identity"
	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	msp "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"
)

type point struct {
	Number uint64 `json:"blockNumber"`
	Hash   string `json:"blockHash"`
}

type block struct {
	point
	Parent       string
	ConfigDigest string
	Transactions []blockTx
	raw          *cb.Block
}

type blockTx struct {
	Index            int                 `json:"transactionIndex"`
	ID               string              `json:"txId"`
	Code             pb.TxValidationCode `json:"-"`
	Chaincode        string              `json:"chaincode"`
	Creator          api.Management      `json:"creator"`
	Envelope         *cb.Envelope        `json:"-"`
	Writes           []*kvrwset.KVWrite  `json:"-"`
	DefinitionChange bool                `json:"-"`
}

var errInvalidPeerBlock = errors.New("invalid block from Peer")

func headerHash(h *cb.BlockHeader) string {
	der, _ := asn1.Marshal(struct {
		Number       *big.Int
		PreviousHash []byte
		DataHash     []byte
	}{new(big.Int).SetUint64(h.Number), h.PreviousHash, h.DataHash})
	return api.Digest(der)
}

func envelopeHeader(envelope *cb.Envelope) (*cb.Payload, *cb.ChannelHeader, error) {
	payload, err := decode(envelope.GetPayload(), &cb.Payload{})
	if err != nil || payload.GetHeader() == nil {
		return nil, nil, fmt.Errorf("invalid transaction payload or header: %v", err)
	}
	ch, err := decode(payload.Header.ChannelHeader, &cb.ChannelHeader{})
	return payload, ch, err
}

func decode[T proto.Message](b []byte, dst T) (T, error) {
	err := proto.Unmarshal(b, dst)
	return dst, err
}

func decodeBlock(data []byte) (*block, error) {
	raw, err := decode(data, &cb.Block{})
	if err != nil {
		return nil, err
	}
	return parseBlock(raw)
}

func parseBlock(raw *cb.Block) (*block, error) {
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
	b := &block{point: point{h.Number, headerHash(h)}, Parent: hex.EncodeToString(h.PreviousHash), raw: raw}
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
		t := blockTx{Index: n}
		if len(filter) > 0 {
			t.Code = pb.TxValidationCode(filter[n])
			if _, ok := pb.TxValidationCode_name[int32(t.Code)]; !ok || t.Code == pb.TxValidationCode_NOT_VALIDATED {
				return nil, fmt.Errorf("block %d transaction %d has unknown validation code %d", h.Number, n, t.Code)
			}
		}
		env, err := decode(data, &cb.Envelope{})
		if err != nil {
			if t.Code != pb.TxValidationCode_VALID {
				b.Transactions = append(b.Transactions, t)
				continue
			}
			return nil, err
		}
		t.Envelope = env
		payload, ch, err := envelopeHeader(env)
		if err != nil {
			if t.Code != pb.TxValidationCode_VALID {
				b.Transactions = append(b.Transactions, t)
				continue
			}
			return nil, err
		}
		if ch.ChannelId != api.Channel {
			return nil, fmt.Errorf("block %d unexpected channel %q", h.Number, ch.ChannelId)
		}
		t.ID = ch.TxId
		switch cb.HeaderType(ch.Type) {
		case cb.HeaderType_CONFIG:
			if t.Code != pb.TxValidationCode_VALID || len(raw.Data.Data) != 1 {
				return nil, fmt.Errorf("block %d invalid config transaction", h.Number)
			}
			config, err := decode(payload.Data, &cb.ConfigEnvelope{})
			if err != nil || config.GetConfig().GetChannelGroup() == nil {
				return nil, fmt.Errorf("block %d missing config: %v", h.Number, err)
			}
			c, err := proto.MarshalOptions{Deterministic: true}.Marshal(config.Config)
			if err != nil {
				return nil, err
			}
			b.ConfigDigest = api.Digest(c)
		case cb.HeaderType_ENDORSER_TRANSACTION:
			t.Creator, t.Chaincode, err = transactionIdentity(payload, ch)
			if err != nil && t.Code == pb.TxValidationCode_VALID {
				return nil, err
			}
			if t.Code == pb.TxValidationCode_VALID {
				if err := parseWrites(payload.Data, &t); err != nil {
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

func transactionIdentity(payload *cb.Payload, ch *cb.ChannelHeader) (api.Management, string, error) {
	sh, err := decode(payload.GetHeader().GetSignatureHeader(), &cb.SignatureHeader{})
	if err != nil {
		return api.Management{}, "", err
	}
	id, err := decode(sh.Creator, &msp.SerializedIdentity{})
	if err != nil {
		return api.Management{}, "", err
	}
	cert, err := identity.CertificateFromPEM(id.IdBytes)
	if err != nil {
		return api.Management{}, "", err
	}
	digest := sha256.New()
	digest.Write(sh.Nonce)
	digest.Write(sh.Creator)
	if ch.TxId != hex.EncodeToString(digest.Sum(nil)) {
		return api.Management{}, "", fmt.Errorf("transaction %s ID does not bind the creator and nonce", ch.TxId)
	}
	ext, err := decode(ch.Extension, &pb.ChaincodeHeaderExtension{})
	if err != nil || ext.GetChaincodeId().GetName() == "" {
		return api.Management{}, "", fmt.Errorf("transaction %s has no chaincode: %v", ch.TxId, err)
	}
	return api.Management{MSPID: id.Mspid, Fingerprint: api.Digest(cert.Raw)}, ext.ChaincodeId.Name, nil
}

func parseWrites(data []byte, t *blockTx) error {
	tx, err := decode(data, &pb.Transaction{})
	if err != nil || len(tx.Actions) != 1 {
		return fmt.Errorf("transaction %s invalid actions: %v", t.ID, err)
	}
	action, err := decode(tx.Actions[0].Payload, &pb.ChaincodeActionPayload{})
	if err != nil {
		return err
	}
	response, err := decode(action.GetAction().GetProposalResponsePayload(), &pb.ProposalResponsePayload{})
	if err != nil {
		return err
	}
	cc, err := decode(response.Extension, &pb.ChaincodeAction{})
	if err != nil || cc.GetChaincodeId().GetName() != t.Chaincode {
		return fmt.Errorf("transaction %s has inconsistent chaincode action: %v", t.ID, err)
	}
	set, err := decode(cc.Results, &rwset.TxReadWriteSet{})
	if err != nil || set.DataModel != rwset.TxReadWriteSet_KV {
		return fmt.Errorf("transaction %s invalid read/write set: %v", t.ID, err)
	}
	for _, ns := range set.NsRwset {
		if ns.Namespace != api.Registry && ns.Namespace != "_lifecycle" {
			continue
		}
		kv, err := decode(ns.Rwset, &kvrwset.KVRWSet{})
		if err != nil {
			return err
		}
		if ns.Namespace == api.Registry {
			t.Writes = append(t.Writes, kv.Writes...)
		} else {
			// Lifecycle approvals are private to their org. The committed definition is public.
			for _, w := range kv.Writes {
				if w.Key == "namespaces/metadata/"+api.Registry ||
					w.Key == "namespaces/fields/"+api.Registry+"/Sequence" ||
					w.Key == "namespaces/fields/"+api.Registry+"/ValidationInfo" ||
					w.Key == "namespaces/fields/"+api.Registry+"/EndorsementInfo" ||
					w.Key == "namespaces/fields/"+api.Registry+"/Collections" {
					t.DefinitionChange = true
				}
			}
		}
	}
	return nil
}

func (p *peerClient) height(ctx context.Context) (uint64, error) {
	b, err := p.direct(ctx, "qscc", "GetChainInfo", api.Channel)
	if err != nil {
		return 0, err
	}
	info, err := decode(b, &cb.BlockchainInfo{})
	return info.GetHeight(), err
}

func (p *peerClient) getBlock(ctx context.Context, n uint64) (*block, error) {
	return p.queryBlock(ctx, "GetBlockByNumber", strconv.FormatUint(n, 10))
}

func (p *peerClient) queryBlock(ctx context.Context, method, value string) (*block, error) {
	b, err := p.direct(ctx, "qscc", method, api.Channel, value)
	if err != nil {
		return nil, err
	}
	result, err := decodeBlock(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidPeerBlock, err)
	}
	return result, nil
}
