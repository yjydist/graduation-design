package procurement

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/core/dao"
	"grad/platform/core/domain/wallet"
	"grad/platform/core/ledger"
	"grad/protocol"
	preg "grad/protocol/registry"
)

// DispatchConfig configures the Domain B dispatch & execution coordinator.
type DispatchConfig struct {
	DB          *pgxpool.Pool
	Deployment  *ledger.Deployment
	DomainID    string
	DelegateDID string
	ActorB1     GrantRecipient
	Grants      *GrantOperations
	Wallet      *wallet.WalletContext
	Executor    ExecuteRunner
	Peers       PeerClient
	Now         func() time.Time
}

// DispatchService owns Domain B's dispatch acceptance, persisted execution queue,
// bound quote/order invocations, order-intent recovery, and probe operations.
type DispatchService struct {
	cfg DispatchConfig
}

// NewDispatchService constructs a DispatchService for Domain B.
func NewDispatchService(cfg DispatchConfig) (*DispatchService, error) {
	if cfg.DB == nil || cfg.Deployment == nil || cfg.Deployment.DeploymentID == "" {
		return nil, errors.New("dispatch service requires database and deployment")
	}
	if cfg.DomainID == "" {
		cfg.DomainID = "B"
	}
	if cfg.Now == nil {
		if cfg.Grants != nil {
			cfg.Now = cfg.Grants.Now
		} else {
			cfg.Now = time.Now
		}
	}
	return &DispatchService{cfg: cfg}, nil
}

func (s *DispatchService) deploymentID() string { return s.cfg.Deployment.DeploymentID }
func (s *DispatchService) now() time.Time       { return s.cfg.Now() }

// ValidDispatchID verifies that run.RunID is a 64-hex digest and run.TaskID matches the
// deterministic workbench task derivation for deployment.
func ValidDispatchID(deployment string, run Run) bool {
	return preg.IsDigest(run.RunID) && run.TaskID == preg.Digest([]byte(deployment+"/workbench/"+run.RunID))
}

// AcceptDispatch verifies the delivered G2 grant against the confirmed run, persists the
// dispatch entry prior to task expiry, and returns replayed=true when an identical dispatch
// was already accepted.
func (s *DispatchService) AcceptDispatch(ctx context.Context, req DispatchRequest) (DispatchStatusView, bool, error) {
	run := Run{RunID: req.Run.RunID, TaskID: req.Run.TaskID, Task: req.Run.Task}
	if !ValidDispatchID(s.deploymentID(), run) || req.Delivery.Package.GrantID != run.GrantID("G2") ||
		run.Task.DelegateDID != s.cfg.DelegateDID {
		return DispatchStatusView{}, false, protocol.NewError(preg.ErrCodeBindingMismatch, "dispatch binding rejected")
	}
	if view, found, err := s.checkDispatchReplay(ctx, run, req.Delivery.Digest); found || err != nil {
		return view, found, err
	}
	if s.cfg.Grants == nil {
		return DispatchStatusView{}, false, ErrUnavailable
	}
	bundle, receipt, err := s.cfg.Grants.Receive(ctx, s.cfg.ActorB1, req.Delivery)
	if err != nil {
		return DispatchStatusView{}, false, err
	}
	claims := bundle.Claims
	spec := run.Task.TaskSpec()
	digest, err := spec.Digest()
	otherDigest, otherErr := bundle.TaskSpec.Digest()
	if err != nil || otherErr != nil || digest != otherDigest || claims.Issuer != s.cfg.DelegateDID ||
		claims.TaskID != run.TaskID || claims.AuthorizationMode != run.Task.Mode || claims.ParentID == nil ||
		*claims.ParentID != run.GrantID("G1") || claims.RootID != run.GrantID("G0") ||
		claims.MaxAmountMinor > run.Task.MaxAmountMinor || claims.EXP > run.Task.ExpiresAt {
		return DispatchStatusView{}, false, protocol.NewError(preg.ErrCodeBindingMismatch, "dispatch does not match delivered G2")
	}
	pending := DispatchStatusView{Receipt: receipt, Status: RunPending}
	tag, err := s.cfg.DB.Exec(ctx, `INSERT INTO workbench_dispatch(deployment_id,run_id,task_id,status,body,result)
		SELECT $1,$2,$3,$4,$5,$6 WHERE clock_timestamp() < to_timestamp($7)
		ON CONFLICT DO NOTHING`, s.deploymentID(), run.RunID, run.TaskID, RunPending, run, pending, run.Task.ExpiresAt)
	if err != nil {
		return DispatchStatusView{}, false, err
	}
	if tag.RowsAffected() == 0 {
		if view, found, err := s.checkDispatchReplay(ctx, run, req.Delivery.Digest); found || err != nil {
			return view, found, err
		}
		return DispatchStatusView{}, false, protocol.NewError(preg.ErrCodeTaskInactive, "dispatch deadline passed")
	}
	return pending, false, nil
}

func (s *DispatchService) checkDispatchReplay(ctx context.Context, run Run, receipt string) (DispatchStatusView, bool, error) {
	existing, result, err := s.storedDispatch(ctx, run.RunID)
	if errors.Is(err, pgx.ErrNoRows) {
		return DispatchStatusView{}, false, nil
	}
	if err != nil {
		return DispatchStatusView{}, false, err
	}
	if existing.TaskID != run.TaskID || existing.Task != run.Task || result.Receipt != receipt {
		return DispatchStatusView{}, false, protocol.NewError(preg.ErrCodeBindingMismatch, "dispatch differs from original binding")
	}
	traces, err := s.ExecutionTraces(ctx, run.RunID)
	if err != nil {
		return DispatchStatusView{}, false, err
	}
	result.Traces = traces
	return result, true, nil
}

func (s *DispatchService) storedDispatch(ctx context.Context, id string) (Run, DispatchStatusView, error) {
	var run Run
	var result DispatchStatusView
	err := s.cfg.DB.QueryRow(ctx, `SELECT body,result FROM workbench_dispatch WHERE deployment_id=$1 AND run_id=$2`,
		s.deploymentID(), id).Scan(&run, &result)
	return run, result, err
}

// GetDispatchStatus reads Domain B's persisted dispatch projection and bounded execution traces.
func (s *DispatchService) GetDispatchStatus(ctx context.Context, runID string) (DispatchStatusView, error) {
	if !preg.IsDigest(runID) {
		return DispatchStatusView{}, protocol.NewError(preg.ErrCodeInvalidSchema, "invalid workbench run ID")
	}
	_, result, err := s.storedDispatch(ctx, runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return DispatchStatusView{}, ErrNotFound
	}
	if err != nil {
		return DispatchStatusView{}, err
	}
	traces, err := s.ExecutionTraces(ctx, runID)
	if err != nil {
		return DispatchStatusView{}, err
	}
	result.Traces = traces
	return result, nil
}

// ProcessPending advances up to 50 pending or unknown dispatches in fair next_attempt_at order.
func (s *DispatchService) ProcessPending(ctx context.Context) error {
	rows, err := s.cfg.DB.Query(ctx, `SELECT run_id FROM workbench_dispatch
		WHERE deployment_id=$1 AND status IN ('PENDING','OUTCOME_UNKNOWN')
		AND next_attempt_at <= statement_timestamp() ORDER BY next_attempt_at,run_id LIMIT 50`, s.deploymentID())
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.executeDispatch(ctx, id); err != nil && ctx.Err() != nil {
			return err
		}
	}
	return nil
}

func (s *DispatchService) executeDispatch(ctx context.Context, id string) error {
	_, err := s.withDispatchLock(ctx, id, func(ctx context.Context, conn *pgxpool.Conn) error {
		var run Run
		var result DispatchStatusView
		err := conn.QueryRow(ctx, `UPDATE workbench_dispatch SET next_attempt_at=clock_timestamp()
			WHERE deployment_id=$1 AND run_id=$2 AND status IN ('PENDING','OUTCOME_UNKNOWN')
			AND next_attempt_at <= statement_timestamp() RETURNING body,result`,
			s.deploymentID(), id).Scan(&run, &result)
		if err != nil {
			return err
		}
		attempt, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		result.Status, result.Code = s.executeB1(attempt, run)
		result.Traces = nil
		_, err = conn.Exec(ctx, `UPDATE workbench_dispatch SET status=$3,result=$4 WHERE deployment_id=$1 AND run_id=$2`,
			s.deploymentID(), id, result.Status, result)
		return err
	})
	return err
}

func (s *DispatchService) withDispatchLock(ctx context.Context, id string, fn func(context.Context, *pgxpool.Conn) error) (bool, error) {
	lock := s.deploymentID() + "/workbench/dispatch/" + id
	return dao.TryWithSessionAdvisoryLock(ctx, s.cfg.DB, lock, fn)
}

func (s *DispatchService) b1Binding(run Run, scope string, verify func(context.Context, wallet.ExecutionBinding) error) wallet.ExecutionBinding {
	return wallet.ExecutionBinding{
		DeploymentID: s.deploymentID(),
		DomainID:     s.cfg.DomainID,
		Actor:        "B1",
		DID:          s.cfg.ActorB1.DID,
		TaskID:       run.TaskID,
		Mode:         run.Task.Mode,
		GrantID:      run.GrantID("G2"),
		Stage:        wallet.StageExecute,
		ProductID:    run.Task.ProductID,
		Quantity:     run.Task.Quantity,
		RunID:        scope,
		Verify:       verify,
	}
}

func (s *DispatchService) localGrant(ctx context.Context, grantID string) error {
	bundle, err := s.cfg.Grants.Load(ctx, s.cfg.ActorB1, grantID)
	if err != nil {
		return err
	}
	return s.cfg.Wallet.AddGrantBundle(bundle)
}

func (s *DispatchService) loadB1(ctx context.Context, run Run, ensureContext bool) (*wallet.BoundOperations, error) {
	if s.cfg.Grants == nil || s.cfg.Wallet == nil {
		return nil, protocol.NewError(preg.ErrCodeMaterialNotSynced, "grant operations or wallet unavailable")
	}
	bundle, err := s.cfg.Grants.LoadRetained(ctx, s.cfg.ActorB1, run.GrantID("G2"))
	if err != nil {
		return nil, err
	}
	if err := s.cfg.Wallet.AddGrantBundle(bundle); err != nil {
		return nil, err
	}
	return wallet.NewBoundOperations(s.cfg.Wallet, s.b1Binding(run, run.RunID, func(ctx context.Context, _ wallet.ExecutionBinding) error {
		if err := s.localGrant(ctx, run.GrantID("G2")); err != nil {
			return err
		}
		if ensureContext && s.cfg.Peers != nil {
			return s.cfg.Peers.EnsureContext(ctx, run.TaskID)
		}
		return nil
	}))
}

func (s *DispatchService) executeB1(ctx context.Context, run Run) (string, string) {
	// Recover an existing intent before considering a new model invocation.
	ops, err := s.loadB1(ctx, run, false)
	if err != nil {
		return RunPending, statusCode(err)
	}
	if status, code, found := s.orderIntentWithOps(ctx, run, ops); found {
		return status, code
	}
	if s.now().Unix() >= run.Task.ExpiresAt {
		return RunFailed, preg.ErrCodeTaskInactive
	}
	if err := s.localGrant(ctx, run.GrantID("G2")); err != nil {
		if code := protocol.CodeOf(err); code == preg.ErrCodeGrantInactive || code == preg.ErrCodeAncestorInactive {
			return RunFailed, code
		}
		return RunPending, statusCode(err)
	}
	if s.cfg.Peers != nil {
		if err := s.cfg.Peers.EnsureContext(ctx, run.TaskID); err != nil {
			return RunPending, statusCode(err)
		}
	}
	if s.cfg.Executor == nil {
		return RunPending, preg.ErrCodeStateUnavailable
	}
	var traceErr error
	res, modelErr := s.cfg.Executor.RunExecute(ctx, ops, ExecuteRunInput{
		RunID:          run.RunID,
		TaskID:         run.TaskID,
		Mode:           run.Task.Mode,
		GrantID:        run.GrantID("G2"),
		ProductID:      run.Task.ProductID,
		Quantity:       run.Task.Quantity,
		MaxAmountMinor: run.Task.MaxAmountMinor,
		OrderKey:       ops.OrderKey(),
		OnToolTrace: func(trace ToolTrace) {
			if err := s.StoreTrace(ctx, run.RunID, trace); err != nil {
				traceErr = err
			}
		},
	})
	if err := s.storeModelRun(ctx, run.RunID, res); err != nil || traceErr != nil {
		return RunPending, preg.ErrCodeStateUnavailable
	}
	if status, code, found := s.orderIntentWithOps(ctx, run, ops); found {
		return status, code
	}
	// A denied quote can be final even though the wallet has no order intent.
	for _, trace := range boundedTraces(res.Traces) {
		if trace.ToolName == "request_quote" && trace.Output["decision"] == "DENY" {
			code, _ := trace.Output["errorCode"].(string)
			if code != "" && code != preg.ErrCodeStateUnavailable && code != preg.ErrCodeStateStale &&
				code != preg.ErrCodeContextStale {
				return RunDenied, code
			}
			return RunPending, code
		}
	}
	if modelErr != nil {
		return RunPending, "MODEL_REQUEST_FAILED"
	}
	return RunStopped, ""
}

// InvokeBoundQuote executes request_quote under the run's server-owned B1 binding.
func (s *DispatchService) InvokeBoundQuote(ctx context.Context, runID string, input wallet.RequestQuoteInput) (wallet.RequestQuoteOutput, error) {
	return invokeBoundOperation(s, ctx, runID, "request_quote", (*wallet.BoundOperations).RequestQuote, input)
}

// InvokeBoundOrder executes create_order under the run's server-owned B1 binding.
func (s *DispatchService) InvokeBoundOrder(ctx context.Context, runID string, input wallet.CreateOrderInput) (wallet.CreateOrderOutput, error) {
	return invokeBoundOperation(s, ctx, runID, "create_order", (*wallet.BoundOperations).CreateOrder, input)
}

func invokeBoundOperation[In, Out any](
	s *DispatchService,
	ctx context.Context,
	runID string,
	tool string,
	invoke func(*wallet.BoundOperations, context.Context, In) (Out, error),
	input In,
) (Out, error) {
	var zero Out
	if !preg.IsDigest(runID) {
		return zero, protocol.NewError(preg.ErrCodeInvalidSchema, "invalid workbench run ID")
	}
	var out Out
	acquired, err := s.withDispatchLock(ctx, runID, func(ctx context.Context, conn *pgxpool.Conn) error {
		var run Run
		var status string
		err := conn.QueryRow(ctx, `SELECT body,status FROM workbench_dispatch WHERE deployment_id=$1 AND run_id=$2`,
			s.deploymentID(), runID).Scan(&run, &status)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if status != RunPending && status != RunDecided {
			return protocol.NewError(preg.ErrCodeInvalidState, "dispatch is outside its execution stage")
		}
		ops, err := s.loadB1(ctx, run, true)
		if err != nil {
			return err
		}
		out, err = invoke(ops, ctx, input)
		trace := ToolTrace{ToolName: tool, IsError: err != nil}
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
		if traceErr := s.StoreTrace(ctx, runID, trace); traceErr != nil {
			return traceErr
		}
		return err
	})
	if err != nil {
		return zero, err
	}
	if !acquired {
		return zero, protocol.NewError(preg.ErrCodeStateChanged, "dispatch is executing")
	}
	return out, nil
}

// OrderIntent inspects and reconciles any existing B1 order intent for run.
func (s *DispatchService) OrderIntent(ctx context.Context, run Run) (status, code string, found bool) {
	ops, err := s.loadB1(ctx, run, false)
	if err != nil {
		return RunPending, statusCode(err), false
	}
	return s.orderIntentWithOps(ctx, run, ops)
}

func (s *DispatchService) orderIntentWithOps(ctx context.Context, run Run, ops *wallet.BoundOperations) (status, code string, found bool) {
	action, err := s.cfg.Wallet.GetClientActionByKey(ctx, s.cfg.ActorB1.DID, run.TaskID, protocol.ActionOrderCreate, ops.OrderKey())
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false
	}
	if err != nil {
		return RunPending, preg.ErrCodeStateUnavailable, true
	}
	switch action.Status {
	case wallet.ActionStatusCompleted, wallet.ActionStatusReconciled:
		return RunDecided, action.Outcome, true
	case wallet.ActionStatusFailed:
		traces, err := s.ExecutionTraces(ctx, run.RunID)
		if err != nil {
			return RunPending, preg.ErrCodeStateUnavailable, true
		}
		for i := len(traces) - 1; i >= 0; i-- {
			if traces[i].ToolName == "create_order" {
				code, _ = traces[i].Output["errorCode"].(string)
				break
			}
		}
		return RunDenied, code, true
	default:
		out, err := ops.ReconcileOrder(ctx, wallet.ReconcileOrderInput{})
		if err != nil {
			return RunUnknown, statusCode(err), true
		}
		trace := ToolTrace{
			ToolName: "reconcile_order",
			Output: map[string]any{
				"caseId":       out.CaseID,
				"orderId":      out.OrderID,
				"decisionId":   out.CreationDecisionID,
				"outcome":      out.Outcome,
				"actionStatus": out.ActionStatus,
				"errorCode":    out.ErrorCode,
			},
		}
		if err := s.StoreTrace(ctx, run.RunID, trace); err != nil {
			return RunUnknown, preg.ErrCodeStateUnavailable, true
		}
		if out.ActionStatus == wallet.ActionStatusReconciled || out.ActionStatus == wallet.ActionStatusCompleted {
			return RunDecided, out.Outcome, true
		}
		return RunUnknown, out.ErrorCode, true
	}
}

// RunProbe executes deterministic B1 bound quote/order probes for the authenticated dispatch origin.
func (s *DispatchService) RunProbe(ctx context.Context, req ProbeRequest) (ProbeResponse, error) {
	if !preg.IsDigest(req.RunID) || !preg.IsDigest(req.Key) {
		return ProbeResponse{}, protocol.NewError(preg.ErrCodeInvalidSchema, "invalid probe binding")
	}
	var run Run
	err := s.cfg.DB.QueryRow(ctx, `SELECT body FROM workbench_dispatch WHERE deployment_id=$1 AND run_id=$2`,
		s.deploymentID(), req.RunID).Scan(&run)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProbeResponse{}, ErrNotFound
	}
	if err != nil {
		return ProbeResponse{}, err
	}
	if s.cfg.Grants == nil || s.cfg.Wallet == nil {
		return ProbeResponse{}, ErrUnavailable
	}
	bundle, err := s.cfg.Grants.LoadRetained(ctx, s.cfg.ActorB1, run.GrantID("G2"))
	if err != nil {
		return ProbeResponse{}, err
	}
	if err := s.cfg.Wallet.AddGrantBundle(bundle); err != nil {
		return ProbeResponse{}, err
	}
	ops, err := wallet.NewBoundOperations(s.cfg.Wallet, s.b1Binding(run, "probe-"+req.Key, nil))
	if err != nil {
		return ProbeResponse{}, err
	}
	quote, err := ops.RequestQuote(ctx, wallet.RequestQuoteInput{})
	if err != nil {
		return ProbeResponse{}, err
	}
	trace := ToolTrace{
		ToolName: "request_quote",
		Output: map[string]any{
			"decision":         quote.Decision,
			"decisionId":       quote.DecisionID,
			"quoteId":          quote.QuoteID,
			"totalAmountMinor": quote.TotalAmountMinor,
			"currency":         quote.Currency,
			"errorCode":        quote.ErrorCode,
		},
	}
	if err := s.StoreTrace(ctx, run.RunID, trace); err != nil {
		return ProbeResponse{}, err
	}
	var order *wallet.CreateOrderOutput
	if req.Order && quote.Decision == "ALLOW" && quote.TotalAmountMinor > bundle.Claims.MaxAmountMinor {
		out, err := ops.CreateOrder(ctx, wallet.CreateOrderInput{QuoteID: quote.QuoteID, AmountMinor: quote.TotalAmountMinor})
		if err != nil {
			return ProbeResponse{}, err
		}
		order = &out
		if err := s.StoreTrace(ctx, run.RunID, ToolTrace{
			ToolName: "create_order",
			Output: map[string]any{
				"decision":         out.Decision,
				"decisionId":       out.DecisionID,
				"orderId":          out.OrderID,
				"quoteId":          out.QuoteID,
				"actionId":         out.ActionID,
				"totalAmountMinor": quote.TotalAmountMinor,
				"errorCode":        out.ErrorCode,
			},
		}); err != nil {
			return ProbeResponse{}, err
		}
	}
	return ProbeResponse{Quote: quote, Order: order}, nil
}

// StoreTrace persists a sanitized bounded tool trace for runID.
func (s *DispatchService) StoreTrace(ctx context.Context, runID string, trace ToolTrace) error {
	_, err := s.cfg.DB.Exec(ctx, `INSERT INTO workbench_tool_trace(deployment_id,domain_id,run_id,body) VALUES($1,$2,$3,$4)`,
		s.deploymentID(), s.cfg.DomainID, runID, BoundedTrace(trace))
	return err
}

// ExecutionTraces reads Domain B's persisted bounded tool traces for runID in sequence order.
func (s *DispatchService) ExecutionTraces(ctx context.Context, runID string) ([]ToolTrace, error) {
	rows, err := s.cfg.DB.Query(ctx, `SELECT body FROM workbench_tool_trace WHERE deployment_id=$1 AND domain_id=$2 AND run_id=$3 ORDER BY seq`,
		s.deploymentID(), s.cfg.DomainID, runID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[ToolTrace])
}

func (s *DispatchService) storeModelRun(ctx context.Context, runID string, result ModelRunResult) error {
	if len(result.ResponseModels) == 0 {
		return nil
	}
	return s.StoreTrace(ctx, runID, ToolTrace{
		ToolName:   "model_result",
		Step:       result.Steps,
		DurationMs: result.TotalDurationMs,
		Output: map[string]any{
			"provider":       result.Provider,
			"requestedModel": result.RequestedModel,
			"responseModel":  result.ResponseModels[len(result.ResponseModels)-1],
		},
	})
}

func statusCode(err error) string {
	code := protocol.CodeOf(err)
	if code == "" {
		return preg.ErrCodeStateUnavailable
	}
	return code
}

// BoundedTrace sanitizes trace so only allowlisted tool names and bounded business references are persisted.
func BoundedTrace(trace ToolTrace) ToolTrace {
	out := ToolTrace{
		Step:       trace.Step,
		ToolName:   trace.ToolName,
		IsError:    trace.IsError,
		DurationMs: trace.DurationMs,
	}
	switch out.ToolName {
	case "inspect_wallet", "delegate_grant", "request_quote", "create_order", "reconcile_order", "model_result":
	default:
		out.ToolName = "unknown_tool"
	}
	out.Output = make(map[string]any)
	for _, key := range []string{
		"decision", "decisionId", "quoteId", "orderId", "caseId", "outcome", "anchored", "actionStatus",
		"totalAmountMinor", "currency", "errorCode", "code", "statusCode", "historicalStatus",
		"provider", "requestedModel", "responseModel",
	} {
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

func boundedTraces(traces []ToolTrace) []ToolTrace {
	if len(traces) == 0 {
		return nil
	}
	out := make([]ToolTrace, 0, len(traces))
	for _, trace := range traces {
		out = append(out, BoundedTrace(trace))
	}
	return out
}
