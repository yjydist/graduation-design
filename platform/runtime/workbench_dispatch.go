package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/agent"
	"grad/platform/internal/httpx"
	"grad/platform/workbench"
	"grad/protocol"
	"grad/protocol/registry"
)

const workbenchDispatchPath = "/internal/workbench/dispatch"

func (d *domainWorkbench) readDispatch(ctx context.Context, id string) (dispatchResult, error) {
	var result dispatchResult
	err := d.callPeer(ctx, "B", http.MethodGet, workbenchDispatchPath+"/"+id, nil, &result)
	return result, err
}

// DispatchTraces retrieves B1's current projection without advancing the run.
func (d *domainWorkbench) DispatchTraces(ctx context.Context, run workbench.Run) ([]agent.ToolTrace, error) {
	result, err := d.readDispatch(ctx, run.RunID)
	return result.Traces, err
}

func (d *domainWorkbench) storedDispatch(ctx context.Context, id string) (workbench.Run, dispatchResult, error) {
	var run workbench.Run
	var result dispatchResult
	err := d.db.QueryRow(ctx, `SELECT body,result FROM workbench_dispatch WHERE deployment_id=$1 AND run_id=$2`,
		d.dep.DeploymentID, id).Scan(&run, &result)
	return run, result, err
}

func (d *domainWorkbench) dispatchStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("runId")
	if !registry.IsDigest(id) {
		workbench.WriteError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid workbench run ID")
		return
	}
	_, result, err := d.storedDispatch(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		workbench.WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "dispatch not found")
		return
	}
	if err != nil {
		workbench.WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "dispatch store unavailable")
		return
	}
	d.writeDispatchResult(w, r, id, result)
}

func (d *domainWorkbench) writeDispatchResult(w http.ResponseWriter, r *http.Request, id string, result dispatchResult) {
	traces, err := d.executionTraces(r.Context(), id)
	if err != nil {
		workbench.WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "dispatch traces unavailable")
		return
	}
	result.Traces = traces
	httpx.WriteJSON(w, http.StatusOK, result)
}

func (d *domainWorkbench) processDispatch(ctx context.Context) error {
	rows, err := d.db.Query(ctx, `SELECT run_id FROM workbench_dispatch
		WHERE deployment_id=$1 AND status IN ('PENDING','OUTCOME_UNKNOWN')
		AND next_attempt_at <= statement_timestamp() ORDER BY next_attempt_at,run_id LIMIT 50`, d.dep.DeploymentID)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := d.executeDispatch(ctx, id); err != nil && ctx.Err() != nil {
			return err
		}
	}
	return nil
}

func (d *domainWorkbench) executeDispatch(ctx context.Context, id string) error {
	_, err := d.withDispatchLock(ctx, id, func(conn *pgxpool.Conn) error {
		var run workbench.Run
		var result dispatchResult
		err := conn.QueryRow(ctx, `UPDATE workbench_dispatch SET next_attempt_at=clock_timestamp()
			WHERE deployment_id=$1 AND run_id=$2 AND status IN ('PENDING','OUTCOME_UNKNOWN')
			AND next_attempt_at <= statement_timestamp() RETURNING body,result`,
			d.dep.DeploymentID, id).Scan(&run, &result)
		if err != nil {
			return err
		}
		attempt, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		result.Status, result.Code = d.executeB1(attempt, run)
		result.Traces = nil
		_, err = conn.Exec(ctx, `UPDATE workbench_dispatch SET status=$3,result=$4 WHERE deployment_id=$1 AND run_id=$2`,
			d.dep.DeploymentID, id, result.Status, result)
		return err
	})
	return err
}

func (d *domainWorkbench) withDispatchLock(ctx context.Context, id string, fn func(*pgxpool.Conn) error) (bool, error) {
	conn, err := d.db.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	lock := d.dep.DeploymentID + "/workbench/dispatch/" + id
	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", lock).Scan(&acquired); err != nil || !acquired {
		return acquired, err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", lock); err != nil {
			_ = conn.Hijack().Close(ctx)
		}
	}()
	return true, fn(conn)
}

func (d *domainWorkbench) b1Binding(run workbench.Run, scope string, verify func(context.Context, agent.ExecutionBinding) error) agent.ExecutionBinding {
	return agent.ExecutionBinding{
		DeploymentID: d.dep.DeploymentID, DomainID: "B", Actor: "B1", DID: d.cfg.Actors["B1"].DID,
		TaskID: run.TaskID, Mode: run.Task.Mode, GrantID: run.GrantID("G2"), Stage: agent.StageExecute,
		ProductID: run.Task.ProductID, Quantity: run.Task.Quantity, RunID: scope, Verify: verify,
	}
}

func (d *domainWorkbench) loadB1(ctx context.Context, run workbench.Run, ensureContext bool) (*agent.BoundOperations, error) {
	bundle, err := d.grants.LoadRetained(ctx, d.recipient("B1"), run.GrantID("G2"))
	if err != nil {
		return nil, err
	}
	if err := d.wallet.AddGrantBundle(bundle); err != nil {
		return nil, err
	}
	return agent.NewBoundOperations(d.wallet, d.b1Binding(run, run.RunID, func(ctx context.Context, _ agent.ExecutionBinding) error {
		if err := d.localGrant(ctx, "B1", run.GrantID("G2")); err != nil {
			return err
		}
		if ensureContext {
			return d.ensureSupplierContext(ctx, run.TaskID)
		}
		return nil
	}))
}

func (d *domainWorkbench) ensureSupplierContext(ctx context.Context, taskID string) error {
	return d.callPeer(ctx, "C", http.MethodPost, "/internal/workbench/context", map[string]string{"taskId": taskID}, nil)
}

func (d *domainWorkbench) executeB1(ctx context.Context, run workbench.Run) (string, string) {
	// Recover an existing intent before considering a new model invocation.
	ops, err := d.loadB1(ctx, run, false)
	if err != nil {
		return workbench.RunPending, statusCode(err)
	}
	if status, code, found := d.orderIntent(ctx, run, ops); found {
		return status, code
	}
	if d.grants.cfg.Now().Unix() >= run.Task.ExpiresAt {
		return workbench.RunFailed, registry.ErrCodeTaskInactive
	}
	if err := d.localGrant(ctx, "B1", run.GrantID("G2")); err != nil {
		if code := protocol.CodeOf(err); code == registry.ErrCodeGrantInactive || code == registry.ErrCodeAncestorInactive {
			return workbench.RunFailed, code
		}
		return workbench.RunPending, statusCode(err)
	}
	if err := d.ensureSupplierContext(ctx, run.TaskID); err != nil {
		return workbench.RunPending, statusCode(err)
	}
	cfg := d.runner
	var traceErr error
	cfg.OnToolTrace = func(trace agent.ToolTrace) {
		if err := d.storeTrace(ctx, run.RunID, trace); err != nil {
			traceErr = err
		}
	}
	cfg.SystemPrompt = "You are B1. Use the bound MCP tools to request one quote, then place one order only if it fits the confirmed cap. Use reconcile_order for an unknown order. Use amountMinor exactly as returned by the quote. No alternative item, quantity or grant."
	prompt := fmt.Sprintf("Task %s, mode %s, as actor B1 using grant %s. Quote %d of %s. Amount cap %d fen. If the quote fits, submit the order with quoteId and idempotencyKey %s. Otherwise stop.",
		run.TaskID, run.Task.Mode, run.GrantID("G2"), run.Task.Quantity, run.Task.ProductID, run.Task.MaxAmountMinor, ops.OrderKey())
	res, modelErr := agent.RunAgentTask(ctx, ops.MCPServer(), cfg, prompt)
	if err := d.storeModelRun(ctx, run.RunID, res); err != nil || traceErr != nil {
		return workbench.RunPending, registry.ErrCodeStateUnavailable
	}
	if status, code, found := d.orderIntent(ctx, run, ops); found {
		return status, code
	}
	// A denied quote can be final even though the wallet has no order intent.
	for _, trace := range boundedTraces(res) {
		if trace.ToolName == "request_quote" && trace.Output["decision"] == "DENY" {
			code, _ := trace.Output["errorCode"].(string)
			if code != "" && code != registry.ErrCodeStateUnavailable && code != registry.ErrCodeStateStale &&
				code != registry.ErrCodeContextStale {
				return workbench.RunDenied, code
			}
			return workbench.RunPending, code
		}
	}
	if modelErr != nil {
		return workbench.RunPending, "MODEL_REQUEST_FAILED"
	}
	return workbench.RunStopped, ""
}

func dispatchOperation[In, Out any](d *domainWorkbench, tool string, invoke func(*agent.BoundOperations, context.Context, In) (Out, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("runId")
		if !registry.IsDigest(id) {
			workbench.WriteError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid workbench run ID")
			return
		}
		var input In
		if !readServiceJSON(w, r, &input) {
			return
		}
		ctx := r.Context()
		var out Out
		acquired, err := d.withDispatchLock(ctx, id, func(conn *pgxpool.Conn) error {
			var run workbench.Run
			var status string
			err := conn.QueryRow(ctx, `SELECT body,status FROM workbench_dispatch WHERE deployment_id=$1 AND run_id=$2`,
				d.dep.DeploymentID, id).Scan(&run, &status)
			if err != nil {
				return err
			}
			if status != workbench.RunPending && status != workbench.RunDecided {
				return protocol.NewError(registry.ErrCodeInvalidState, "dispatch is outside its execution stage")
			}
			ops, err := d.loadB1(ctx, run, true)
			if err != nil {
				return err
			}
			out, err = invoke(ops, ctx, input)
			trace := agent.ToolTrace{ToolName: tool, IsError: err != nil}
			if err != nil {
				trace.Output = map[string]any{"code": statusCode(err)}
			} else {
				raw, marshalErr := json.Marshal(out)
				if marshalErr != nil {
					return marshalErr
				}
				if decodeErr := json.Unmarshal(raw, &trace.Output); decodeErr != nil {
					return decodeErr
				}
			}
			if traceErr := d.storeTrace(ctx, id, trace); traceErr != nil {
				return traceErr
			}
			return err
		})
		if errors.Is(err, pgx.ErrNoRows) {
			workbench.WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "dispatch not found")
			return
		}
		if err != nil {
			writeInternalError(w, r, err)
			return
		}
		if !acquired {
			workbench.WriteError(w, r, http.StatusConflict, registry.ErrCodeStateChanged, "dispatch is executing")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, out)
	}
}

func (d *domainWorkbench) orderIntent(ctx context.Context, run workbench.Run, ops *agent.BoundOperations) (status, code string, found bool) {
	actor := d.cfg.Actors["B1"].DID
	action, err := d.wallet.GetClientActionByKey(ctx, actor, run.TaskID, protocol.ActionOrderCreate, ops.OrderKey())
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false
	}
	if err != nil {
		return workbench.RunPending, registry.ErrCodeStateUnavailable, true
	}
	switch action.Status {
	case agent.ActionStatusCompleted, agent.ActionStatusReconciled:
		return workbench.RunDecided, action.Outcome, true
	case agent.ActionStatusFailed:
		traces, err := d.executionTraces(ctx, run.RunID)
		if err != nil {
			return workbench.RunPending, registry.ErrCodeStateUnavailable, true
		}
		for i := len(traces) - 1; i >= 0; i-- {
			if traces[i].ToolName == "create_order" {
				code, _ = traces[i].Output["errorCode"].(string)
				break
			}
		}
		return workbench.RunDenied, code, true
	default:
		out, err := ops.ReconcileOrder(ctx, agent.ReconcileOrderInput{})
		if err != nil {
			return workbench.RunUnknown, statusCode(err), true
		}
		trace := agent.ToolTrace{ToolName: "reconcile_order", Output: map[string]any{
			"caseId": out.CaseID, "orderId": out.OrderID, "decisionId": out.CreationDecisionID,
			"outcome": out.Outcome, "actionStatus": out.ActionStatus, "errorCode": out.ErrorCode,
		}}
		if err := d.storeTrace(ctx, run.RunID, trace); err != nil {
			return workbench.RunUnknown, registry.ErrCodeStateUnavailable, true
		}
		if out.ActionStatus == agent.ActionStatusReconciled || out.ActionStatus == agent.ActionStatusCompleted {
			return workbench.RunDecided, out.Outcome, true
		}
		return workbench.RunUnknown, out.ErrorCode, true
	}
}

func statusCode(err error) string {
	code := protocol.CodeOf(err)
	if code == "" {
		return registry.ErrCodeStateUnavailable
	}
	return code
}

// runProbe exposes shared typed operations solely to the authenticated dispatch origin.
// It supports the deterministic negative demo and a quote after restoration.
func (d *domainWorkbench) runProbe(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RunID string `json:"runId"`
		Key   string `json:"key"`
		Order bool   `json:"order"`
	}
	if !readServiceJSON(w, r, &in) {
		return
	}
	if !registry.IsDigest(in.RunID) || !registry.IsDigest(in.Key) {
		workbench.WriteError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid probe binding")
		return
	}
	ctx := r.Context()
	var run workbench.Run
	if err := d.db.QueryRow(ctx, `SELECT body FROM workbench_dispatch WHERE deployment_id=$1 AND run_id=$2`,
		d.dep.DeploymentID, in.RunID).Scan(&run); err != nil {
		writeInternalError(w, r, err)
		return
	}
	bundle, err := d.grants.LoadRetained(ctx, d.recipient("B1"), run.GrantID("G2"))
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	if err := d.wallet.AddGrantBundle(bundle); err != nil {
		writeInternalError(w, r, err)
		return
	}
	ops, err := agent.NewBoundOperations(d.wallet, d.b1Binding(run, "probe-"+in.Key, nil))
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	quote, err := ops.RequestQuote(ctx, agent.RequestQuoteInput{})
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	trace := agent.ToolTrace{ToolName: "request_quote", Output: map[string]any{
		"decision": quote.Decision, "decisionId": quote.DecisionID, "quoteId": quote.QuoteID,
		"totalAmountMinor": quote.TotalAmountMinor, "currency": quote.Currency, "errorCode": quote.ErrorCode,
	}}
	if err := d.storeTrace(ctx, run.RunID, trace); err != nil {
		writeInternalError(w, r, err)
		return
	}
	var order *agent.CreateOrderOutput
	if in.Order && quote.Decision == "ALLOW" && quote.TotalAmountMinor > bundle.Claims.MaxAmountMinor {
		out, err := ops.CreateOrder(ctx, agent.CreateOrderInput{QuoteID: quote.QuoteID, AmountMinor: quote.TotalAmountMinor})
		if err != nil {
			writeInternalError(w, r, err)
			return
		}
		order = &out
		if err := d.storeTrace(ctx, run.RunID, agent.ToolTrace{ToolName: "create_order", Output: map[string]any{
			"decision": out.Decision, "decisionId": out.DecisionID, "orderId": out.OrderID, "quoteId": out.QuoteID,
			"actionId": out.ActionID, "totalAmountMinor": quote.TotalAmountMinor, "errorCode": out.ErrorCode,
		}}); err != nil {
			writeInternalError(w, r, err)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, struct {
		Quote agent.RequestQuoteOutput `json:"quote"`
		Order *agent.CreateOrderOutput `json:"order,omitempty"`
	}{quote, order})
}

func boundedTrace(trace agent.ToolTrace) agent.ToolTrace {
	out := agent.ToolTrace{Step: trace.Step, ToolName: trace.ToolName, IsError: trace.IsError, DurationMs: trace.DurationMs}
	switch out.ToolName {
	case "inspect_wallet", "delegate_grant", "request_quote", "create_order", "reconcile_order", "model_result":
	default:
		out.ToolName = "unknown_tool"
	}
	out.Output = make(map[string]any)
	for _, key := range []string{"decision", "decisionId", "quoteId", "orderId", "caseId", "outcome", "anchored", "actionStatus",
		"totalAmountMinor", "currency", "errorCode", "code", "statusCode", "historicalStatus", "provider", "requestedModel", "responseModel"} {
		if value, ok := trace.Output[key]; ok {
			switch v := value.(type) {
			case string:
				if len(v) <= 200 {
					out.Output[key] = v
				}
			case bool, float64, int, int64:
				out.Output[key] = v
			}
		}
	}
	var key string
	var reference any
	switch out.ToolName {
	case "delegate_grant":
		key = "grantId"
		grant, _ := trace.Output["grant"].(map[string]any)
		reference = grant[key]
	case "create_order":
		key = "actionId"
		reference = trace.Output[key]
	case "reconcile_order":
		key = "decisionId"
		reference = trace.Output["creationDecisionId"]
	}
	if id, ok := reference.(string); ok && id != "" && len(id) <= 200 {
		out.Output[key] = id
	}
	return out
}

func boundedTraces(res *agent.RunResult) []agent.ToolTrace {
	if res == nil {
		return nil
	}
	out := make([]agent.ToolTrace, 0, len(res.ToolTraces))
	for _, trace := range res.ToolTraces {
		out = append(out, boundedTrace(trace))
	}
	return out
}

func (d *domainWorkbench) storeTrace(ctx context.Context, id string, trace agent.ToolTrace) error {
	_, err := d.db.Exec(ctx, `INSERT INTO workbench_tool_trace(deployment_id,domain_id,run_id,body) VALUES($1,$2,$3,$4)`,
		d.dep.DeploymentID, d.cfg.DomainID, id, boundedTrace(trace))
	return err
}

func (d *domainWorkbench) executionTraces(ctx context.Context, id string) ([]agent.ToolTrace, error) {
	rows, err := d.db.Query(ctx, `SELECT body FROM workbench_tool_trace WHERE deployment_id=$1 AND domain_id=$2 AND run_id=$3 ORDER BY seq`,
		d.dep.DeploymentID, d.cfg.DomainID, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[agent.ToolTrace])
}

func (d *domainWorkbench) storeModelRun(ctx context.Context, id string, result *agent.RunResult) error {
	if result == nil || len(result.ResponseModels) == 0 {
		return nil
	}
	return d.storeTrace(ctx, id, agent.ToolTrace{ToolName: "model_result", Step: result.Steps,
		DurationMs: result.TotalDurationMs, Output: map[string]any{
			"provider": result.Provider, "requestedModel": result.RequestedModel,
			"responseModel": result.ResponseModels[len(result.ResponseModels)-1],
		}})
}
