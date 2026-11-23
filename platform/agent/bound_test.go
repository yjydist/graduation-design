package agent_test

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/agent"
	"grad/protocol"
)

func TestBoundOperationsShareToolJudgmentsAndOrderEffects(t *testing.T) {
	fx := newUnitFixture(t, nil)
	ctx := t.Context()
	const productID = "urn:grad:product:P1"
	const mode = protocol.ModeBuyerMandate
	g2ID := protocol.DigestBytes([]byte("bound-g2"))
	scope := agent.ExecutionBinding{
		DeploymentID: fx.depID, DomainID: "A", Actor: "A1", DID: fx.didA1, TaskID: fx.taskID,
		Mode: mode, GrantID: fx.g1ID, Stage: agent.StageDelegate, RunID: "run",
		SubjectDID: fx.didB1, SubjectActor: "B1", ChildGrantID: g2ID,
	}
	delegate, err := agent.NewBoundOperations(fx.wallet, scope)
	require.NoError(t, err)
	delegateSession := boundSession(t, delegate, []string{"inspect_wallet", "delegate_grant"})
	good := agent.DelegateGrantInput{
		IssuerActor: "A1", SubjectActor: "B1", ParentGrantID: fx.g1ID, GrantID: g2ID, TaskID: fx.taskID,
		AuthorizationMode: mode, MaxAmountMinor: 100000,
	}
	for label, mutate := range map[string]func(*agent.DelegateGrantInput){
		"signer":    func(in *agent.DelegateGrantInput) { in.IssuerActor = "B1" },
		"task":      func(in *agent.DelegateGrantInput) { in.TaskID = "other" },
		"mode":      func(in *agent.DelegateGrantInput) { in.AuthorizationMode = protocol.ModeResourcePreauthorized },
		"grant":     func(in *agent.DelegateGrantInput) { in.ParentGrantID = "other" },
		"recipient": func(in *agent.DelegateGrantInput) { in.SubjectDID = fx.didB2 },
	} {
		t.Run(label, func(t *testing.T) {
			bad := good
			mutate(&bad)
			_, err := delegate.DelegateGrant(ctx, bad)
			require.True(t, protocol.HasCode(err, protocol.ErrCodeBindingMismatch), "%v", err)
			code := protocol.CodeOf(err)
			res, err := delegateSession.CallTool(ctx, &mcp.CallToolParams{Name: "delegate_grant", Arguments: bad})
			require.NoError(t, err)
			require.True(t, res.IsError)
			require.Len(t, res.Content, 1)
			var result struct {
				Code string `json:"code"`
			}
			require.NoError(t, json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &result))
			require.Equal(t, code, result.Code)
		})
	}
	_, err = agent.NewBoundOperations(fx.wallet, agent.ExecutionBinding{
		DeploymentID: fx.depID, DomainID: "A", Actor: "B1", DID: fx.didB1, TaskID: fx.taskID,
		Mode: mode, GrantID: g2ID, Stage: agent.StageExecute, RunID: "run", ProductID: productID, Quantity: 1,
	})
	require.True(t, protocol.HasCode(err, protocol.ErrCodeBindingMismatch), "invalid delegated calls must not add a grant")
	issued, err := delegate.DelegateGrant(ctx, good)
	require.NoError(t, err)
	require.True(t, issued.Anchored)

	scope = agent.ExecutionBinding{
		DeploymentID: fx.depID, DomainID: "A", Actor: "B1", DID: fx.didB1, TaskID: fx.taskID,
		Mode: mode, GrantID: g2ID, Stage: agent.StageExecute, RunID: "run", ProductID: productID, Quantity: 1,
	}
	ops, err := agent.NewBoundOperations(fx.wallet, scope)
	require.NoError(t, err)
	executionSession := boundSession(t, ops, []string{"inspect_wallet", "request_quote", "create_order", "reconcile_order"})
	quote, err := ops.RequestQuote(ctx, agent.RequestQuoteInput{})
	require.NoError(t, err)
	require.Equal(t, "ALLOW", quote.Decision)
	in := agent.CreateOrderInput{
		Actor: "B1", TaskID: fx.taskID, QuoteID: quote.QuoteID, AuthorizationMode: mode,
		AmountMinor: quote.TotalAmountMinor, IdempotencyKey: ops.OrderKey(),
	}
	direct, err := ops.CreateOrder(ctx, in)
	require.NoError(t, err)
	require.Equal(t, "ALLOW", direct.Decision)
	res, err := executionSession.CallTool(ctx, &mcp.CallToolParams{Name: "create_order", Arguments: in})
	require.NoError(t, err)
	require.False(t, res.IsError)
	var throughMCP agent.CreateOrderOutput
	raw, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &throughMCP))
	require.Equal(t, direct, throughMCP)
	fx.gw.mu.Lock()
	defer fx.gw.mu.Unlock()
	require.Len(t, fx.gw.ordersByKey, 1)
	require.Len(t, fx.gw.verifiedRequests, 2)
	assert.Equal(t, fx.didB1, fx.gw.verifiedRequests[1].Actor)
	assert.Equal(t, ops.OrderKey(), fx.gw.verifiedRequests[1].IdempotencyKey)
}

func boundSession(t *testing.T, operations *agent.BoundOperations, want []string) *mcp.ClientSession {
	t.Helper()
	server, client := mcp.NewInMemoryTransports()
	srv, err := operations.MCPServer().Connect(t.Context(), server, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	sess, err := mcp.NewClient(&mcp.Implementation{Name: "workbench-pair-test"}, nil).Connect(t.Context(), client, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })
	tools, err := sess.ListTools(t.Context(), nil)
	require.NoError(t, err)
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	require.ElementsMatch(t, want, names)
	return sess
}
