package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"grad/platform/core/domain/wallet"
	"grad/protocol"
)

var (
	inspectWalletTool = sdkmcp.Tool{
		Name:        "inspect_wallet",
		Description: "Inspect actor DID, authorized grants, remaining delegation depth, amount ceilings, cached quotes, orders, and client_actions intent locks without exposing private keys or SD-JWT disclosures.",
	}
	delegateGrantTool = sdkmcp.Tool{
		Name:        "delegate_grant",
		Description: "Sign and optionally anchor a narrowed child delegation grant (such as A1 issuing G2 to B1) using isolated wallet key material.",
	}
	replaceGrantTool = sdkmcp.Tool{
		Name:        "replace_grant",
		Description: "Atomically revoke an existing child grant and issue/deliver a narrowed replacement grant to another delegate (such as B2) using isolated wallet key material.",
	}
	requestQuoteTool = sdkmcp.Tool{
		Name:        "request_quote",
		Description: "Obtain a binding supplier quote via gateway quote.read with fresh challenge authentication and KB-JWT proof.",
	}
	createOrderTool = sdkmcp.Tool{
		Name:        "create_order",
		Description: "Persist a client_actions intent lock (OUTCOME_UNKNOWN + sendRevision) first, then submit an authenticated order.create request bound to a quoteId and idempotencyKey.",
	}
	reconcileOrderTool = sdkmcp.Tool{
		Name:        "reconcile_order",
		Description: "Increment sendRevision to stop delayed retries on an unknown order, register the reconciliation case with C, trigger C audit and historical h/r review, and persist the receipt.",
	}
)

func newWalletMCPServer() *sdkmcp.Server {
	return sdkmcp.NewServer(&sdkmcp.Implementation{Name: "grad-auth-wallet", Version: "v1.0.0"}, nil)
}

func addWalletTool[In, Out any](
	srv *sdkmcp.Server,
	tool sdkmcp.Tool,
	run func(context.Context, In) (Out, error),
	bound bool,
) {
	sdkmcp.AddTool(srv, &tool, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in In) (*sdkmcp.CallToolResult, Out, error) {
		out, err := run(ctx, in)
		if !bound || err == nil {
			return nil, out, err
		}
		code := protocol.CodeOf(err)
		if code == "" {
			code = protocol.ErrCodeInvalidSchema
		}
		body, _ := json.Marshal(map[string]string{
			"code":    code,
			"message": "workbench operation declined",
		})
		return nil, out, errors.New(string(body))
	})
}

// NewMCPServer registers the six grad-auth-v1 wallet tools over the official MCP Go SDK.
func NewMCPServer(w *wallet.WalletContext) *sdkmcp.Server {
	srv := newWalletMCPServer()
	addWalletTool(srv, inspectWalletTool, w.InspectWallet, false)
	addWalletTool(srv, delegateGrantTool, w.DelegateGrant, false)
	addWalletTool(srv, replaceGrantTool, w.ReplaceGrant, false)
	addWalletTool(srv, requestQuoteTool, w.RequestQuote, false)
	addWalletTool(srv, createOrderTool, w.CreateOrder, false)
	addWalletTool(srv, reconcileOrderTool, w.ReconcileOrder, false)
	return srv
}

// NewBoundMCPServer registers the stage-restricted tool subset backed by ops with sanitized error envelopes.
// StageDelegate exposes only inspect_wallet and delegate_grant;
// StageExecute exposes only inspect_wallet, request_quote, create_order, and reconcile_order.
func NewBoundMCPServer(ops *wallet.BoundOperations) *sdkmcp.Server {
	srv := newWalletMCPServer()
	addWalletTool(srv, inspectWalletTool, ops.InspectWallet, true)
	switch ops.Scope().Stage {
	case wallet.StageDelegate:
		addWalletTool(srv, delegateGrantTool, ops.DelegateGrant, true)
	case wallet.StageExecute:
		addWalletTool(srv, requestQuoteTool, ops.RequestQuote, true)
		addWalletTool(srv, createOrderTool, ops.CreateOrder, true)
		addWalletTool(srv, reconcileOrderTool, ops.ReconcileOrder, true)
	}
	return srv
}

// RunMCPServer runs srv over StdioTransport when in and out are both nil,
// or over IOTransport bound to in/out for deterministic stdio and pipe transport.
func RunMCPServer(ctx context.Context, srv *sdkmcp.Server, in io.Reader, out io.Writer) error {
	if srv == nil {
		return fmt.Errorf("mcp server is required")
	}
	if in == nil && out == nil {
		return srv.Run(ctx, &sdkmcp.StdioTransport{})
	}
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	return srv.Run(ctx, &sdkmcp.IOTransport{
		Reader: io.NopCloser(in),
		Writer: nopWriteCloser{Writer: out},
	})
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
