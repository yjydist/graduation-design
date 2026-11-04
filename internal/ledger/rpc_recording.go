package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

type RPCRequest struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      json.RawMessage   `json:"id"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}
type RPCSample struct {
	ObservedAt time.Time       `json:"observedAt"`
	Request    RPCRequest      `json:"request"`
	Response   json.RawMessage `json:"response,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// RPCRecorder saves public RPC bodies, without HTTP authorization headers.
// Hooks are for controlled verification faults; normal commands leave them nil.
type RPCRecorder struct {
	mu      sync.Mutex
	Samples []RPCSample
	Before  func(RPCRequest) error
	After   func(RPCRequest, []byte) ([]byte, error)
	Base    http.RoundTripper
}

func (r *RPCRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	b, err := io.ReadAll(io.LimitReader(request.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(b))
	var q RPCRequest
	if err = json.Unmarshal(b, &q); err != nil {
		return nil, err
	}
	s := RPCSample{ObservedAt: time.Now().UTC(), Request: q}
	defer func() { r.mu.Lock(); r.Samples = append(r.Samples, s); r.mu.Unlock() }()
	if r.Before != nil {
		if err = r.Before(q); err != nil {
			s.Error = err.Error()
			return nil, err
		}
	}
	base := r.Base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	if err != nil {
		s.Error = err.Error()
		return nil, err
	}
	b, err = io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	response.Body.Close()
	if err == nil && len(b) > 16<<20 {
		err = fmt.Errorf("RPC response exceeds recording limit")
	}
	if err == nil && r.After != nil {
		b, err = r.After(q, b)
	}
	if err != nil {
		s.Error = err.Error()
		return nil, err
	}
	s.Response = append([]byte{}, b...)
	response.Body = io.NopCloser(bytes.NewReader(b))
	response.ContentLength = int64(len(b))
	return response, nil
}

func (r *RPCRecorder) Snapshot() []RPCSample {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RPCSample{}, r.Samples...)
}

func RecordedClient(ctx context.Context, endpoint string, recorder *RPCRecorder) (*ethclient.Client, error) {
	c, err := rpc.DialOptions(ctx, endpoint, rpc.WithHTTPClient(&http.Client{Transport: recorder, Timeout: 15 * time.Second}))
	if err != nil {
		return nil, err
	}
	return ethclient.NewClient(c), nil
}
