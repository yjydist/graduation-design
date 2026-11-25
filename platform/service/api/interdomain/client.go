package interdomain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"

	"grad/platform/core/domain/evidence"
	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/domain/procurement"
	"grad/platform/internal/httpx"
	"grad/protocol"
	"grad/protocol/registry"
)

const (
	// PathRoot issues a Domain C RP root grant G0 for a confirmed Domain A task.
	PathRoot = "/internal/workbench/root"
	// PathRootReceipt acknowledges receipt of a delivered Domain C root grant G0.
	PathRootReceipt = "/internal/workbench/root-receipt"
	// PathRootAmountPrefix serves authenticated RP root grant digest and amount lookups by taskId.
	PathRootAmountPrefix = "/internal/workbench/root-amount/"
	// PathContext ensures supplier C's trusted environment context for a confirmed task.
	PathContext = "/internal/workbench/context"
	// PathEvidencePrefix serves Domain C gateway task evidence projections by taskId.
	PathEvidencePrefix = "/internal/workbench/evidence/"
	// PathDispatch is the Domain B dispatch submission and status endpoint base path.
	PathDispatch = "/internal/workbench/dispatch"
	// PathProbe invokes Domain B's deterministic bound quote/order probe.
	PathProbe = "/internal/workbench/probe"
	// PathOrderOutcomeReceipts is Domain B's reconciliation receipt delivery endpoint.
	PathOrderOutcomeReceipts = "/v1/internal/order-outcome-receipts"

	maxPeerResponseBytes = 2 * 1024 * 1024
)

var (
	_ procurement.PeerClient      = (*PeerClient)(nil)
	_ evidence.PeerEvidenceClient = (*PeerClient)(nil)
)

// PeerClient executes typed mTLS JSON calls between Domains A, B, and C.
type PeerClient struct {
	peers   map[string]PeerBinding
	clients map[string]*http.Client
}

// NewPeerClient constructs a PeerClient backed by domain peer bindings and authenticated HTTP clients.
func NewPeerClient(peers map[string]PeerBinding, clients map[string]*http.Client) *PeerClient {
	return &PeerClient{
		peers:   maps.Clone(peers),
		clients: maps.Clone(clients),
	}
}

// RequestRoot posts a root grant request to Domain C.
func (c *PeerClient) RequestRoot(ctx context.Context, req procurement.RootGrantRequest) (procurement.RootGrantResponse, error) {
	var out procurement.RootGrantResponse
	err := c.callPeer(ctx, "C", http.MethodPost, PathRoot, req, &out)
	return out, err
}

// AckRootReceipt acknowledges receipt of a Domain C root grant G0.
func (c *PeerClient) AckRootReceipt(ctx context.Context, grantID, digest string) error {
	return c.callPeer(ctx, "C", http.MethodPost, PathRootReceipt, procurement.RootGrantReceipt{
		GrantID: grantID,
		Digest:  digest,
	}, nil)
}

// EnsureContext requests Domain C to install or confirm the trusted context for taskID.
func (c *PeerClient) EnsureContext(ctx context.Context, taskID string) error {
	return c.callPeer(ctx, "C", http.MethodPost, PathContext, map[string]string{"taskId": taskID}, nil)
}

// SubmitDispatch submits a confirmed run and verified G2 delivery to Domain B.
func (c *PeerClient) SubmitDispatch(ctx context.Context, req procurement.DispatchRequest) (procurement.DispatchStatusView, error) {
	var out procurement.DispatchStatusView
	err := c.callPeer(ctx, "B", http.MethodPost, PathDispatch, req, &out)
	return out, err
}

// GetDispatch retrieves Domain B's persisted dispatch status and bounded tool traces for runID.
func (c *PeerClient) GetDispatch(ctx context.Context, runID string) (procurement.DispatchStatusView, error) {
	var out procurement.DispatchStatusView
	err := c.callPeer(ctx, "B", http.MethodGet, PathDispatch+"/"+runID, nil, &out)
	return out, err
}

// RequestDispatchProbe triggers a deterministic B1 quote/order probe on Domain B.
func (c *PeerClient) RequestDispatchProbe(ctx context.Context, req procurement.ProbeRequest) (procurement.ProbeResponse, error) {
	var out procurement.ProbeResponse
	err := c.callPeer(ctx, "B", http.MethodPost, PathProbe, req, &out)
	return out, err
}

// FetchTaskEvidence retrieves Domain C's gateway evidence projection for taskID.
func (c *PeerClient) FetchTaskEvidence(ctx context.Context, taskID string) (domgw.TaskEvidence, error) {
	var out domgw.TaskEvidence
	err := c.callPeer(ctx, "C", http.MethodGet, PathEvidencePrefix+taskID, nil, &out)
	return out, err
}

// FetchRootAmount retrieves Domain C's digest-authenticated RP root grant amount for taskID.
func (c *PeerClient) FetchRootAmount(ctx context.Context, taskID string) (evidence.RootGrantAmount, error) {
	var out evidence.RootGrantAmount
	err := c.callPeer(ctx, "C", http.MethodGet, PathRootAmountPrefix+taskID, nil, &out)
	return out, err
}

func (c *PeerClient) callPeer(ctx context.Context, domain, method, path string, payload, out any) error {
	if c == nil {
		return protocol.NewError(registry.ErrCodeStateUnavailable, "peer client unavailable")
	}
	peer, ok := c.peers[domain]
	if !ok || peer.URL == "" {
		return protocol.NewError(registry.ErrCodeStateUnavailable, fmt.Sprintf("peer binding for domain %s unavailable", domain))
	}
	client, ok := c.clients[domain]
	if !ok || client == nil {
		return protocol.NewError(registry.ErrCodeStateUnavailable, fmt.Sprintf("peer client for domain %s unavailable", domain))
	}
	var raw []byte
	var err error
	if payload != nil {
		raw, err = json.Marshal(payload)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, peer.URL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return readPeerResponse(resp.StatusCode, resp.Body, out)
}

func readPeerResponse(status int, body io.Reader, out any) error {
	raw, err := io.ReadAll(io.LimitReader(body, maxPeerResponseBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxPeerResponseBytes {
		return fmt.Errorf("workbench response exceeds limit")
	}
	if status < 200 || status >= 300 {
		var envelope httpx.ErrorEnvelope
		if json.Unmarshal(raw, &envelope) == nil && envelope.Code != "" {
			return protocol.NewError(envelope.Code, "service operation rejected")
		}
		return fmt.Errorf("service operation returned HTTP %d", status)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
