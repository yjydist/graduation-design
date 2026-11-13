package fabric

import (
	"context"
	"fmt"

	api "graduation-design/internal/fabricapi"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	msp "github.com/hyperledger/fabric-protos-go-apiv2/msp"
	ab "github.com/hyperledger/fabric-protos-go-apiv2/orderer"
	pb "github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (p *peerClient) signedEnvelope(kind cb.HeaderType, data []byte) (*cb.Envelope, error) {
	id := p.gateway.Identity()
	creator, err := proto.Marshal(&msp.SerializedIdentity{Mspid: id.MspID(), IdBytes: id.Credentials()})
	if err != nil {
		return nil, err
	}
	sh, err := proto.Marshal(&cb.SignatureHeader{Creator: creator})
	if err != nil {
		return nil, err
	}
	ch, err := proto.Marshal(&cb.ChannelHeader{Type: int32(kind), ChannelId: api.Channel, Timestamp: timestamppb.Now()})
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

func (p *peerClient) deliver(ctx context.Context, start, stop uint64) (pb.Deliver_DeliverClient, error) {
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

func receiveBlock(stream pb.Deliver_DeliverClient) (*block, error) {
	result, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	switch v := result.Type.(type) {
	case *pb.DeliverResponse_Block:
		return parseBlock(v.Block)
	case *pb.DeliverResponse_Status:
		return nil, fmt.Errorf("Peer Deliver status %s", v.Status)
	default:
		return nil, fmt.Errorf("unexpected Peer Deliver response %T", v)
	}
}
