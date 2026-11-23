package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"grad/platform/agent"
	"grad/platform/gateway"
	"grad/platform/internal/httpx"
	"grad/platform/policy"
	"grad/platform/registrysvc"
	"grad/platform/state/fabric"
	"grad/platform/workbench"
	"grad/protocol"
	"grad/protocol/registry"
)

type proposal struct {
	ProductID       string `json:"productId"`
	Quantity        int64  `json:"quantity"`
	Mode            string `json:"mode"`
	MaxAmountMinor  int64  `json:"maxAmountMinor"`
	DurationMinutes int64  `json:"durationMinutes"`
	Description     string `json:"description"`
	Reply           string `json:"reply"`
}

func (d *domainWorkbench) Suggest(ctx context.Context, message string, previous *workbench.Draft) (workbench.Draft, string, error) {
	cfg := d.runner
	cfg.SystemPrompt = `You are A1, a procurement draft assistant. Respond only with one JSON object with fields
productId, quantity, mode, maxAmountMinor, durationMinutes, description, reply. Use urn:grad:product:P1 (800 yuan)
or urn:grad:product:P2 (1200 yuan), positive integer quantity, mode RP or BM, and integer amount in fen.
Use up to 600 minutes. If omitted default to P1, 1, RP, 100000 fen and 60 minutes. Keep previous fields that the
buyer did not ask to change. Write the description and brief reply in the buyer's language. Send a draft for
confirmation only. You have no authority to register, delegate or place orders.`
	prior, err := json.Marshal(previous)
	if err != nil {
		return workbench.Draft{}, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	res, err := agent.RunDraftDialogue(ctx, cfg, "Previous draft: "+string(prior)+"\nBuyer message: "+message)
	if err != nil {
		return workbench.Draft{}, "", err
	}
	raw := strings.TrimSpace(res.FinalText)
	if strings.HasPrefix(raw, "```json") && strings.HasSuffix(raw, "```") {
		raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "```json"), "```"))
	}
	var p proposal
	if err := protocol.DecodeStrictJSON([]byte(raw), &p); err != nil || p.DurationMinutes < 1 || p.DurationMinutes > 600 ||
		len(p.Reply) > 1200 || p.Reply == "" {
		return workbench.Draft{}, "", protocol.NewError(registry.ErrCodeInvalidSchema, "invalid draft proposal")
	}
	switch strings.ToUpper(p.Mode) {
	case "RP":
		p.Mode = registry.RP
	case "BM":
		p.Mode = registry.BM
	}
	return workbench.Draft{
		ProductID: p.ProductID, Quantity: p.Quantity, Mode: p.Mode, MaxAmountMinor: p.MaxAmountMinor,
		ExpiresAt:   time.Now().Add(time.Duration(p.DurationMinutes) * time.Minute).Unix(),
		DelegateDID: d.cfg.Actors["A1"].DID, Description: p.Description,
	}, p.Reply, nil
}

func (d *domainWorkbench) recipient(actor string) GrantRecipient {
	cfg := d.cfg.Actors[actor]
	return GrantRecipient{DID: cfg.DID, CredentialID: cfg.CredentialID}
}

func (d *domainWorkbench) Advance(ctx context.Context, owner string, run workbench.Run) (workbench.StageResult, error) {
	if owner != d.dep.Bootstrap.TaskCreator.Subject || run.Task.DelegateDID != d.cfg.Actors["A1"].DID {
		return workbench.StageResult{Status: workbench.RunFailed, Code: registry.ErrCodeBindingMismatch}, nil
	}
	if run.Status != workbench.RunUnknown && time.Now().Unix() >= run.Task.ExpiresAt {
		return workbench.StageResult{Status: workbench.RunFailed, Code: registry.ErrCodeTaskInactive}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	switch run.Stage {
	case workbench.StageTask:
		return d.registerTask(ctx, run)
	case workbench.StageRoot:
		return d.obtainRoot(ctx, run)
	case workbench.StageDelegation:
		return d.issueG1(ctx, run)
	case workbench.StageDispatch:
		return d.delegateDispatch(ctx, run)
	default:
		return workbench.StageResult{Status: workbench.RunFailed, Code: registry.ErrCodeInvalidState}, nil
	}
}

func (d *domainWorkbench) registerTask(ctx context.Context, run workbench.Run) (workbench.StageResult, error) {
	actor := d.actors["U"]
	spec := run.Task.TaskSpec()
	digest, err := spec.Digest()
	if err != nil {
		return workbench.StageResult{}, err
	}
	input := registry.Task{
		Bound: registry.Bound{DeploymentID: d.dep.DeploymentID}, ID: run.TaskID,
		Creator: actor.Signer.DID, CreatorCredential: actor.Signer.CredentialID, CreatorKeyVersion: actor.Signer.KeyVersion,
		Domain: d.cfg.DomainID, Mode: run.Task.Mode, Resource: d.dep.Bootstrap.ResourceID, Digest: digest,
		Interval: registry.Interval{NBF: run.ConfirmedAt - 5, EXP: run.Task.ExpiresAt},
	}
	op, err := d.mgmt.Submit(ctx, actor.Management, "RegisterTask", "workbench-task/"+run.RunID, input)
	return workbench.StageResult{Operation: op}, err
}

type rootResponse struct {
	Operation *registrysvc.OperationView `json:"operation,omitempty"`
	Delivery  *GrantDelivery             `json:"delivery,omitempty"`
	Code      string                     `json:"code,omitempty"`
}

func rootRequest(run workbench.Run, buyer GrantRecipient) RootGrantRequest {
	return RootGrantRequest{
		GrantID: run.GrantID("G0"), TaskID: run.TaskID, Recipient: buyer, TaskSpec: run.Task.TaskSpec(),
		MaxAmountMinor: run.Task.MaxAmountMinor, Depth: 2,
	}
}

func (d *domainWorkbench) obtainRoot(ctx context.Context, run workbench.Run) (workbench.StageResult, error) {
	req := rootRequest(run, d.recipient("U"))
	key := "workbench-root/" + req.TaskID
	var result rootResponse
	var err error
	if run.Task.Mode == registry.RP {
		err = d.callPeer(ctx, "C", http.MethodPost, "/internal/workbench/root", req, &result)
	} else {
		result.Operation, result.Delivery, err = d.grants.IssueRoot(ctx, "PA", key, req)
	}
	step := workbench.StageResult{Operation: result.Operation, GrantID: req.GrantID}
	if err != nil {
		return stageError(step, err)
	}
	if result.Code != "" {
		return stageError(step, protocol.NewError(result.Code, "root publication awaiting verification"))
	}
	if result.Delivery == nil {
		if result.Operation == nil || result.Operation.Status != "FAILED" {
			step.Status = workbench.RunPending
		}
		return step, nil
	}
	bundle, receipt, err := d.grants.Receive(ctx, req.Recipient, *result.Delivery)
	if err != nil {
		return stageError(step, err)
	}
	if bundle.Claims.TaskID != run.TaskID || bundle.Claims.AuthorizationMode != run.Task.Mode || bundle.Claims.Issuer !=
		map[string]string{registry.RP: d.cfg.Actors["C"].DID, registry.BM: d.cfg.Actors["PA"].DID}[run.Task.Mode] {
		return stageError(step, protocol.NewError(registry.ErrCodeBindingMismatch, "root receipt differs from confirmed task"))
	}
	if run.Task.Mode == registry.BM {
		err = d.grants.MarkReceived(ctx, *result.Delivery, receipt)
	} else {
		err = d.callPeer(ctx, "C", http.MethodPost, "/internal/workbench/root-receipt", rootReceipt{GrantID: req.GrantID, Digest: receipt}, nil)
	}
	if err != nil {
		return stageError(step, err)
	}
	step.Status = "DELIVERED"
	return step, nil
}

func stageError(step workbench.StageResult, err error) (workbench.StageResult, error) {
	switch protocol.CodeOf(err) {
	case registry.ErrCodeInvalidSchema, registry.ErrCodeBindingMismatch, registry.ErrCodeTaskInactive,
		registry.ErrCodeRootAuthorityInvalid, registry.ErrCodePurchasingAuthorityInvalid,
		registry.ErrCodeCredentialStatusInvalid, registry.ErrCodeMaterialInvalid, registry.ErrCodeDeliveryConflict:
		step.Status, step.Code = workbench.RunFailed, protocol.CodeOf(err)
		return step, nil
	default:
		return step, err
	}
}

func (d *domainWorkbench) remoteRoot(w http.ResponseWriter, r *http.Request) {
	var req RootGrantRequest
	if !readServiceJSON(w, r, &req) {
		return
	}
	if req.Recipient != d.recipient("U") || req.GrantID != (workbench.Run{TaskID: req.TaskID}).GrantID("G0") ||
		req.Depth != 2 || req.TaskSpec.SupplierID != defaultSupplierID {
		workbench.WriteError(w, r, http.StatusForbidden, registry.ErrCodeBindingMismatch, "root request outside workbench scope")
		return
	}
	op, delivery, err := d.grants.IssueRoot(r.Context(), "C", "workbench-root/"+req.TaskID, req)
	out := rootResponse{Operation: op, Delivery: delivery}
	if err != nil {
		out.Code = protocol.CodeOf(err)
		if out.Code == "" {
			out.Code = registry.ErrCodeStateUnavailable
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type rootReceipt struct {
	GrantID string `json:"grantId"`
	Digest  string `json:"digest"`
}

func (d *domainWorkbench) remoteRootReceipt(w http.ResponseWriter, r *http.Request) {
	var in rootReceipt
	if !readServiceJSON(w, r, &in) {
		return
	}
	delivery, err := d.grants.Published(r.Context(), d.recipient("U"), in.GrantID)
	if err == nil {
		err = d.grants.MarkReceived(r.Context(), *delivery, in.Digest)
	}
	if err != nil {
		workbench.WriteError(w, r, http.StatusConflict, registry.ErrCodeMaterialNotSynced, "root receipt unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *domainWorkbench) localGrant(ctx context.Context, actor, grantID string) error {
	bundle, err := d.grants.Load(ctx, d.recipient(actor), grantID)
	if err != nil {
		return err
	}
	return d.wallet.AddGrantBundle(bundle)
}

func (d *domainWorkbench) childOperation(ctx context.Context, actor, grantID string) *registrysvc.OperationView {
	caller := d.actors[actor].Management
	key := ChildGrantOperationKey(grantID)
	op, _ := d.mgmt.Operation(ctx, caller, registrysvc.ManagementOperationID(d.dep.DeploymentID, caller, "RegisterGrant", key))
	return op
}

func (d *domainWorkbench) issueG1(ctx context.Context, run workbench.Run) (workbench.StageResult, error) {
	id := run.GrantID("G1")
	step := workbench.StageResult{GrantID: id, Status: workbench.RunPending}
	recipient := d.recipient("A1")
	delivery, err := d.grants.Published(ctx, recipient, id)
	if err != nil {
		step.Operation, delivery, err = d.grants.ResumeChild(ctx, "U", id)
		if step.Operation != nil && step.Operation.Status == "FAILED" {
			step.Status = workbench.RunFailed
			return step, nil
		}
		if delivery == nil && (step.Operation != nil || !protocol.HasCode(err, registry.ErrCodeMaterialNotSynced)) {
			if err != nil {
				return stageError(step, err)
			}
			return step, nil
		}
	}
	if delivery == nil {
		if err := d.localGrant(ctx, "U", run.GrantID("G0")); err != nil {
			return stageError(step, err)
		}
		_, err = d.wallet.DelegateGrant(ctx, agent.DelegateGrantInput{
			IssuerActor: "U", SubjectActor: "A1", ParentGrantID: run.GrantID("G0"), GrantID: id,
			TaskID: run.TaskID, AuthorizationMode: run.Task.Mode, MaxAmountMinor: run.Task.MaxAmountMinor, RemainingDepth: 1,
		})
		step.Operation = d.childOperation(ctx, "U", id)
		if step.Operation != nil && step.Operation.Status == "FAILED" {
			step.Status = workbench.RunFailed
			return step, nil
		}
		if err != nil {
			return stageError(step, err)
		}
		delivery, err = d.grants.Published(ctx, recipient, id)
		if err != nil {
			return stageError(step, err)
		}
	}
	step.Operation = &delivery.Operation
	_, receipt, err := d.grants.Receive(ctx, recipient, *delivery)
	if err != nil {
		return stageError(step, err)
	}
	if err := d.grants.MarkReceived(ctx, *delivery, receipt); err != nil {
		return stageError(step, err)
	}
	step.Status = "DELIVERED"
	return step, nil
}

type dispatchRun struct {
	RunID  string          `json:"runId"`
	TaskID string          `json:"taskId"`
	Task   workbench.Draft `json:"task"`
}

type dispatchInput struct {
	Run      dispatchRun   `json:"run"`
	Delivery GrantDelivery `json:"delivery"`
}

type dispatchResult struct {
	Receipt string            `json:"receipt"`
	Status  string            `json:"status"`
	Code    string            `json:"code,omitempty"`
	Traces  []agent.ToolTrace `json:"traces,omitempty"`
}

func (d *domainWorkbench) delegateDispatch(ctx context.Context, run workbench.Run) (workbench.StageResult, error) {
	id := run.GrantID("G2")
	step := workbench.StageResult{GrantID: id, Status: workbench.RunPending}
	recipient := d.recipient("B1")
	delivery, err := d.grants.Published(ctx, recipient, id)
	if err != nil {
		step.Operation, delivery, err = d.grants.ResumeChild(ctx, "A1", id)
		if step.Operation != nil && step.Operation.Status == "FAILED" {
			step.Status = workbench.RunFailed
			return step, nil
		}
		if delivery == nil && (step.Operation != nil || !protocol.HasCode(err, registry.ErrCodeMaterialNotSynced)) {
			if err != nil {
				return stageError(step, err)
			}
			return step, nil
		}
	}
	if delivery == nil {
		if err := d.localGrant(ctx, "A1", run.GrantID("G1")); err != nil {
			return stageError(step, err)
		}
		binding := agent.ExecutionBinding{
			DeploymentID: d.dep.DeploymentID, DomainID: "A", Actor: "A1", DID: d.cfg.Actors["A1"].DID,
			TaskID: run.TaskID, Mode: run.Task.Mode, GrantID: run.GrantID("G1"), Stage: agent.StageDelegate,
			SubjectDID: recipient.DID, SubjectActor: "B1", ChildGrantID: id, RunID: run.RunID,
			Verify: func(ctx context.Context, _ agent.ExecutionBinding) error {
				return d.localGrant(ctx, "A1", run.GrantID("G1"))
			},
		}
		ops, err := agent.NewBoundOperations(d.wallet, binding)
		if err != nil {
			return stageError(step, err)
		}
		cfg := d.runner
		var traceErr error
		cfg.OnToolTrace = func(trace agent.ToolTrace) {
			if err := d.storeTrace(ctx, run.RunID, trace); err != nil {
				traceErr = err
			}
		}
		cfg.SystemPrompt = "You are A1. Use delegate_grant to issue one G2 for the assigned B1 under the exact user-confirmed limits. Only use the provided MCP tools."
		prompt := fmt.Sprintf("Inspect the assigned grant and issue G2 to B1 (%s) with remainingDepth 0, maxAmountMinor %d. Use parentGrantId %s and grantId %s. Task %s mode %s.",
			recipient.DID, run.Task.MaxAmountMinor, binding.GrantID, id, run.TaskID, run.Task.Mode)
		modelRun, runnerErr := agent.RunAgentTask(ctx, ops.MCPServer(), cfg, prompt)
		if err := d.storeModelRun(ctx, run.RunID, modelRun); err != nil {
			return step, err
		}
		if traceErr != nil {
			return step, traceErr
		}
		step.Operation = d.childOperation(ctx, "A1", id)
		if step.Operation != nil && step.Operation.Status == "FAILED" {
			step.Status = workbench.RunFailed
			return step, nil
		}
		delivery, err = d.grants.Published(ctx, recipient, id)
		if err != nil {
			if step.Operation == nil && runnerErr == nil {
				step.Status = workbench.RunStopped
			}
			if runnerErr != nil {
				step.Code = "MODEL_REQUEST_FAILED"
			}
			return step, nil
		}
	}
	step.Operation = &delivery.Operation
	var result dispatchResult
	wire := dispatchInput{Run: dispatchRun{RunID: run.RunID, TaskID: run.TaskID, Task: run.Task}, Delivery: *delivery}
	err = d.callPeer(ctx, "B", http.MethodPost, "/internal/workbench/dispatch", wire, &result)
	if err != nil {
		return stageError(step, err)
	}
	if err := d.grants.MarkReceived(ctx, *delivery, result.Receipt); err != nil {
		return stageError(step, err)
	}
	step.Status, step.Code = result.Status, result.Code
	step.Traces = result.Traces
	return step, nil
}

func (d *domainWorkbench) GrantMutation(ctx context.Context, run workbench.Run) (registry.Mutation, error) {
	id := run.GrantID("G1")
	p, err := d.inst.ReadPeer()
	if err != nil {
		return registry.Mutation{}, err
	}
	defer p.Close()
	g, err := fabric.ReadLedgerRecord[registry.Grant](ctx, p, "grant", id)
	if fabric.IsMissingRecord(err) {
		return registry.Mutation{}, pgx.ErrNoRows
	}
	if err != nil {
		return registry.Mutation{}, err
	}
	if g.Task != run.TaskID || g.Issuer != d.dep.Bootstrap.TaskCreator.Subject {
		return registry.Mutation{}, protocol.NewError(registry.ErrCodeBindingMismatch, "grant differs from current run")
	}
	return registry.Mutation{Bound: g.Bound, ID: g.ID, ExpectedRevision: g.Revision, ExpectedDigest: g.Digest}, nil
}

func (d *domainWorkbench) Control(ctx context.Context, owner, key, method string, mutation registry.Mutation) (*registrysvc.OperationView, error) {
	u := d.actors["U"]
	if owner != u.Signer.DID || (method != "SuspendGrant" && method != "ResumeGrant") {
		return nil, protocol.NewError(registry.ErrCodeBindingMismatch, "invalid workbench grant control")
	}
	return d.mgmt.Submit(ctx, u.Management, method, key, mutation)
}

func (d *domainWorkbench) remoteContext(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TaskID string `json:"taskId"`
	}
	if !readServiceJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	task, err := d.readWorkbenchTask(ctx, in.TaskID)
	if err != nil {
		workbench.WriteError(w, r, http.StatusConflict, registry.ErrCodeStateUnavailable, "confirmed workbench task unavailable")
		return
	}
	current := time.Now()
	if !task.Interval.Current(current, 0) || task.Status != registry.Active {
		workbench.WriteError(w, r, http.StatusConflict, registry.ErrCodeTaskInactive, "workbench task is no longer active")
		return
	}
	inContext := gateway.ContextUpdateRequest{
		SourceID: "C-workbench-demo-environment", ExpectedContextVersion: 0, ObservedAt: current.Unix(),
		AccessDeadline: task.EXP, RiskLevel: policy.RiskNormal,
	}
	err = callLocalJSON(ctx, d.gateway.Handler(), http.MethodPost, "/v1/contexts/"+task.ID, inContext, nil)
	if err != nil {
		var exists bool
		readErr := d.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trusted_contexts
			WHERE deployment_id=$1 AND task_id=$2)`, d.dep.DeploymentID, in.TaskID).Scan(&exists)
		if readErr != nil || !exists {
			workbench.WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "supplier environment unavailable")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *domainWorkbench) readWorkbenchTask(ctx context.Context, id string) (registry.Task, error) {
	if !registry.IsDigest(id) {
		return registry.Task{}, protocol.NewError(registry.ErrCodeInvalidSchema, "invalid workbench task ID")
	}
	p, err := d.inst.ReadPeer()
	if err != nil {
		return registry.Task{}, err
	}
	defer p.Close()
	task, err := fabric.ReadLedgerRecord[registry.Task](ctx, p, "task", id)
	if err == nil && (task.Creator != d.dep.Bootstrap.TaskCreator.Subject || task.Domain != "A" || task.DeploymentID != d.dep.DeploymentID) {
		err = protocol.NewError(registry.ErrCodeBindingMismatch, "task is outside the workbench owner scope")
	}
	return task, err
}

func validDispatchID(deployment string, run workbench.Run) bool {
	return registry.IsDigest(run.RunID) && run.TaskID == registry.Digest([]byte(deployment+"/workbench/"+run.RunID))
}

func (d *domainWorkbench) acceptDispatch(w http.ResponseWriter, r *http.Request) {
	var in dispatchInput
	if !readServiceJSON(w, r, &in) {
		return
	}
	run := workbench.Run{RunID: in.Run.RunID, TaskID: in.Run.TaskID, Task: in.Run.Task}
	if !validDispatchID(d.dep.DeploymentID, run) || in.Delivery.Package.GrantID != run.GrantID("G2") ||
		run.Task.DelegateDID != d.cfg.Actors["A1"].DID {
		workbench.WriteError(w, r, http.StatusForbidden, registry.ErrCodeBindingMismatch, "dispatch binding rejected")
		return
	}
	ctx := r.Context()
	var existing workbench.Run
	var result *dispatchResult
	err := d.db.QueryRow(ctx, `SELECT body,result FROM workbench_dispatch WHERE deployment_id=$1 AND run_id=$2`,
		d.dep.DeploymentID, run.RunID).Scan(&existing, &result)
	if err == nil {
		if existing.TaskID != run.TaskID || existing.Task != run.Task {
			workbench.WriteError(w, r, http.StatusConflict, registry.ErrCodeBindingMismatch, "dispatch differs from original binding")
			return
		}
		if result == nil {
			result = &dispatchResult{Receipt: in.Delivery.Digest, Status: workbench.RunPending}
		}
		if result.Receipt != in.Delivery.Digest {
			workbench.WriteError(w, r, http.StatusConflict, registry.ErrCodeBindingMismatch, "dispatch receipt differs from original binding")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, result)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		workbench.WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "dispatch store unavailable")
		return
	}
	bundle, receipt, err := d.grants.Receive(ctx, d.recipient("B1"), in.Delivery)
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	claims := bundle.Claims
	spec := run.Task.TaskSpec()
	digest, err := spec.Digest()
	otherDigest, otherErr := bundle.TaskSpec.Digest()
	if err != nil || otherErr != nil || digest != otherDigest || claims.Issuer != d.cfg.Actors["A1"].DID ||
		claims.TaskID != run.TaskID || claims.AuthorizationMode != run.Task.Mode || claims.ParentID == nil ||
		*claims.ParentID != run.GrantID("G1") || claims.RootID != run.GrantID("G0") ||
		claims.MaxAmountMinor > run.Task.MaxAmountMinor || claims.EXP > run.Task.ExpiresAt {
		workbench.WriteError(w, r, http.StatusForbidden, registry.ErrCodeBindingMismatch, "dispatch does not match delivered G2")
		return
	}
	pending := dispatchResult{Receipt: receipt, Status: workbench.RunPending}
	_, err = d.db.Exec(ctx, `INSERT INTO workbench_dispatch(deployment_id,run_id,task_id,status,body,result)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		d.dep.DeploymentID, run.RunID, run.TaskID, workbench.RunPending, run, pending)
	if err != nil {
		writeInternalError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, pending)
}

func writeInternalError(w http.ResponseWriter, r *http.Request, err error) {
	code := protocol.CodeOf(err)
	if code == "" {
		code = registry.ErrCodeStateUnavailable
	}
	workbench.WriteError(w, r, http.StatusConflict, code, "internal business operation unavailable")
}
