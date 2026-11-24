package workbench

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/agent"
	"grad/platform/internal/httpx"
	"grad/platform/registrysvc"
	"grad/protocol"
	"grad/protocol/registry"
)

const (
	StageTask       = "REGISTER_TASK"
	StageRoot       = "DELIVER_G0"
	StageDelegation = "DELIVER_G1"
	StageDispatch   = "EXECUTE"
	RunPending      = "PENDING"
	RunFailed       = "FAILED"
	RunStopped      = "MODEL_STOPPED"
	RunDenied       = "GATEWAY_DENIED"
	RunUnknown      = "OUTCOME_UNKNOWN"
	RunDecided      = "DECIDED"

	maxChatMessageLength      = 4000
	maxDraftDescriptionLength = 512
)

type Draft struct {
	DraftID        string `json:"draftId"`
	Version        int64  `json:"version"`
	ProductID      string `json:"productId"`
	Quantity       int64  `json:"quantity"`
	Mode           string `json:"mode"`
	MaxAmountMinor int64  `json:"maxAmountMinor"`
	ExpiresAt      int64  `json:"expiresAt"`
	DelegateDID    string `json:"delegateDid"`
	Description    string `json:"description"`
}

func (d Draft) TaskSpec() protocol.TaskSpec {
	return protocol.TaskSpec{
		SupplierID: "urn:grad:supplier:C", ProductID: d.ProductID, MaxQuantity: d.Quantity,
		Currency: "CNY", Description: d.Description,
		Resources: []string{protocol.ResourceOrders, protocol.ResourceQuotes},
		Actions:   []string{protocol.ActionOrderCreate, protocol.ActionQuoteRead},
	}
}

func (d Draft) validate(delegate string, now time.Time) error {
	spec := d.TaskSpec()
	switch {
	case d.Mode != registry.RP && d.Mode != registry.BM:
		return protocol.NewError(registry.ErrCodeInvalidSchema, "mode must be RP or BM")
	case d.DelegateDID != delegate:
		return protocol.NewError(registry.ErrCodeInvalidSchema, "delegate must be the configured A1")
	case d.MaxAmountMinor < 1 || d.MaxAmountMinor > protocol.MaxSafeInt:
		return protocol.NewError(registry.ErrCodeInvalidSchema, "amount outside supported range")
	case d.ExpiresAt <= now.Add(registry.ClockError).Unix() || d.ExpiresAt > now.Add(24*time.Hour).Unix():
		return protocol.NewError(registry.ErrCodeInvalidSchema, "expiration must be within the next 24 hours")
	case d.ProductID != "urn:grad:product:P1" && d.ProductID != "urn:grad:product:P2":
		return protocol.NewError(registry.ErrCodeInvalidSchema, "unknown product")
	case utf8.RuneCountInString(d.Description) > maxDraftDescriptionLength:
		return protocol.NewError(registry.ErrCodeInvalidSchema, "description is too long")
	default:
		return spec.Validate()
	}
}

type RunStep struct {
	Stage          string `json:"stage"`
	Status         string `json:"status"`
	OperationID    string `json:"operationId,omitempty"`
	TxID           string `json:"txId,omitempty"`
	ValidationCode string `json:"validationCode,omitempty"`
	Code           string `json:"code,omitempty"`
	GrantID        string `json:"grantId,omitempty"`
	At             int64  `json:"at"`
}

type Run struct {
	RunID          string            `json:"runId"`
	TaskID         string            `json:"taskId"`
	DraftID        string            `json:"draftId"`
	Stage          string            `json:"stage"`
	Status         string            `json:"status"`
	ConfirmedAt    int64             `json:"confirmedAt"`
	Task           Draft             `json:"task"`
	Steps          []RunStep         `json:"steps"`
	Traces         []agent.ToolTrace `json:"traces"`
	GrantRevision  uint64            `json:"grantRevision,omitempty"`
	GrantStatus    string            `json:"grantStatus,omitempty"`
	AllowedActions []string          `json:"allowedActions"`
}

func (r Run) GrantID(hop string) string {
	return registry.Digest([]byte(r.TaskID + "/" + hop))
}

type StageResult struct {
	Operation *registrysvc.OperationView
	GrantID   string
	Status    string
	Code      string
	Traces    []agent.ToolTrace
}

type ProcurementExecutor interface {
	Suggest(context.Context, string, *Draft) (Draft, string, error)
	Advance(context.Context, string, Run) (StageResult, error)
	DispatchTraces(context.Context, Run) ([]agent.ToolTrace, error)
	GrantMutation(context.Context, Run) (registry.Mutation, error)
	Control(context.Context, string, string, string, registry.Mutation) (*registrysvc.OperationView, error)
}

type Procurement struct {
	db         *pgxpool.Pool
	deployment string
	domain     string
	delegate   string
	executor   ProcurementExecutor
}

func NewProcurement(db *pgxpool.Pool, deployment, domain, delegate string, executor ProcurementExecutor) *Procurement {
	return &Procurement{db: db, deployment: deployment, domain: domain, delegate: delegate, executor: executor}
}

func (p *Procurement) Handlers() ProcurementHandlers {
	return ProcurementHandlers{
		Chat: p.chat, Draft: p.draft, UpdateDraft: p.updateDraft, ConfirmDraft: p.confirmDraft,
		Runs: p.runs, Run: p.run, SuspendRun: p.suspend, ResumeRun: p.resume,
	}
}

var errDraftVersion = errors.New("draft version changed")

func procurementError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		WriteError(w, r, http.StatusNotFound, "NOT_FOUND", "object not found")
	case errors.Is(err, errDraftVersion):
		WriteError(w, r, http.StatusConflict, "DRAFT_VERSION_CONFLICT", "reload the draft and confirm its current version")
	case protocol.CodeOf(err) == registry.ErrCodeInvalidSchema:
		WriteError(w, r, http.StatusBadRequest, registry.ErrCodeInvalidSchema, "invalid procurement input")
	default:
		WriteError(w, r, http.StatusServiceUnavailable, registry.ErrCodeStateUnavailable, "procurement state unavailable")
	}
}

func newObjectID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (p *Procurement) readDraft(ctx context.Context, owner, id string) (Draft, error) {
	var d Draft
	err := p.db.QueryRow(ctx, `SELECT body FROM workbench_drafts
		WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND draft_id=$4`,
		p.deployment, p.domain, owner, id).Scan(&d)
	return d, err
}

func (p *Procurement) chat(w http.ResponseWriter, r *http.Request, principal Principal) {
	var in struct {
		Message string `json:"message"`
		DraftID string `json:"draftId,omitempty"`
	}
	if !ReadJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	msg := strings.TrimSpace(in.Message)
	if msg == "" || utf8.RuneCountInString(in.Message) > maxChatMessageLength {
		procurementError(w, r, protocol.NewError(registry.ErrCodeInvalidSchema, "invalid message"))
		return
	}
	var previous *Draft
	if in.DraftID != "" {
		d, err := p.readDraft(ctx, principal.SubjectID, in.DraftID)
		if err != nil {
			procurementError(w, r, err)
			return
		}
		previous = &d
	}
	d, reply, err := p.executor.Suggest(ctx, msg, previous)
	if err != nil {
		procurementError(w, r, err)
		return
	}
	if err = d.validate(p.delegate, time.Now()); err == nil {
		if previous == nil {
			d.DraftID, err = newObjectID()
			d.Version = 1
			if err == nil {
				_, err = p.db.Exec(ctx, `INSERT INTO workbench_drafts(deployment_id,domain_id,owner_id,draft_id,version,body) VALUES($1,$2,$3,$4,$5,$6)`,
					p.deployment, p.domain, principal.SubjectID, d.DraftID, d.Version, d)
			}
		} else {
			d.DraftID = previous.DraftID
			d.Version = previous.Version
			d, err = p.saveDraft(ctx, principal.SubjectID, d)
		}
	}
	if err != nil {
		procurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct {
		Reply string `json:"reply"`
		Draft Draft  `json:"draft"`
	}{reply, d})
}

func (p *Procurement) draft(w http.ResponseWriter, r *http.Request, principal Principal) {
	d, err := p.readDraft(r.Context(), principal.SubjectID, r.PathValue("draftId"))
	if err != nil {
		procurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (p *Procurement) updateDraft(w http.ResponseWriter, r *http.Request, principal Principal) {
	var d Draft
	if !ReadJSON(w, r, &d) {
		return
	}
	id := r.PathValue("draftId")
	if d.DraftID != "" && d.DraftID != id {
		procurementError(w, r, protocol.NewError(registry.ErrCodeInvalidSchema, "draft ID mismatch"))
		return
	}
	d.DraftID = id
	out, err := p.saveDraft(r.Context(), principal.SubjectID, d)
	if err != nil {
		procurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (p *Procurement) saveDraft(ctx context.Context, owner string, d Draft) (Draft, error) {
	if err := d.validate(p.delegate, time.Now()); err != nil {
		return Draft{}, err
	}
	version := d.Version
	d.Version++
	tag, err := p.db.Exec(ctx, `UPDATE workbench_drafts SET version=$6,body=$7
		WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND draft_id=$4 AND version=$5 AND run_id IS NULL`,
		p.deployment, p.domain, owner, d.DraftID, version, d.Version, d)
	if err == nil && tag.RowsAffected() != 1 {
		if _, err := p.readDraft(ctx, owner, d.DraftID); err != nil {
			return Draft{}, err
		}
		return Draft{}, errDraftVersion
	}
	return d, err
}

func (p *Procurement) confirmDraft(w http.ResponseWriter, r *http.Request, principal Principal) {
	var in struct {
		Version int64 `json:"version"`
	}
	if !ReadJSON(w, r, &in) {
		return
	}
	run, err := p.confirm(r.Context(), principal.SubjectID, r.PathValue("draftId"), in.Version, time.Now())
	if err != nil {
		procurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, run)
}

func (p *Procurement) confirm(ctx context.Context, owner, draftID string, version int64, now time.Time) (Run, error) {
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return Run{}, err
	}
	defer tx.Rollback(context.Background())
	var d Draft
	var existing *string
	err = tx.QueryRow(ctx, `SELECT body,run_id FROM workbench_drafts
		WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND draft_id=$4 FOR UPDATE`,
		p.deployment, p.domain, owner, draftID).Scan(&d, &existing)
	if err != nil {
		return Run{}, err
	}
	if version != d.Version {
		return Run{}, errDraftVersion
	}
	if existing != nil {
		return p.readRun(ctx, tx, owner, *existing)
	}
	if err := d.validate(p.delegate, now); err != nil {
		return Run{}, err
	}
	runID, err := newObjectID()
	if err != nil {
		return Run{}, err
	}
	run := Run{
		RunID: runID, TaskID: registry.Digest([]byte(p.deployment + "/workbench/" + runID)), DraftID: draftID,
		Stage: StageTask, Status: RunPending, ConfirmedAt: now.Unix(), Task: d,
		AllowedActions: []string{},
		Steps:          []RunStep{{Stage: StageTask, Status: RunPending, At: now.Unix()}}, Traces: []agent.ToolTrace{},
	}
	_, err = tx.Exec(ctx, `INSERT INTO workbench_runs(deployment_id,domain_id,owner_id,run_id,task_id,status,body)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, p.deployment, p.domain, owner, run.RunID, run.TaskID, run.Status, run)
	if err != nil {
		return Run{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE workbench_drafts SET run_id=$5 WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND draft_id=$4`,
		p.deployment, p.domain, owner, draftID, run.RunID)
	if err != nil {
		return Run{}, err
	}
	return run, tx.Commit(ctx)
}

func (p *Procurement) readRun(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, owner, id string) (Run, error) {
	var run Run
	err := q.QueryRow(ctx, `SELECT body FROM workbench_runs WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND run_id=$4`,
		p.deployment, p.domain, owner, id).Scan(&run)
	return run, err
}

func (p *Procurement) runs(w http.ResponseWriter, r *http.Request, principal Principal) {
	rows, err := p.db.Query(r.Context(), `SELECT body FROM workbench_runs
		WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 ORDER BY created_at DESC`, p.deployment, p.domain, principal.SubjectID)
	if err != nil {
		procurementError(w, r, err)
		return
	}
	runs, err := pgx.CollectRows(rows, pgx.RowTo[Run])
	if err != nil {
		procurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct {
		Runs []Run `json:"runs"`
	}{runs})
}

func (p *Procurement) run(w http.ResponseWriter, r *http.Request, principal Principal) {
	run, err := p.readRun(r.Context(), p.db, principal.SubjectID, r.PathValue("runId"))
	if err != nil {
		procurementError(w, r, err)
		return
	}
	run, err = p.addToolTraces(r.Context(), run)
	if err != nil {
		procurementError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, run)
}

func (p *Procurement) addToolTraces(ctx context.Context, run Run) (Run, error) {
	rows, err := p.db.Query(ctx, `SELECT body FROM workbench_tool_trace
		WHERE deployment_id=$1 AND domain_id=$2 AND run_id=$3 ORDER BY seq`, p.deployment, p.domain, run.RunID)
	if err != nil {
		return run, err
	}
	local, err := pgx.CollectRows(rows, pgx.RowTo[agent.ToolTrace])
	if err != nil {
		return run, err
	}
	if run.Stage == StageDispatch {
		readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		// Keep the last observed B1 traces available during a peer outage.
		if traces, err := p.executor.DispatchTraces(readCtx, run); err == nil {
			run.Traces = traces
		}
	}
	run.Traces = append(local, run.Traces...)
	return run, nil
}

func (p *Procurement) suspend(w http.ResponseWriter, r *http.Request, pr Principal) {
	p.control(w, r, pr, "SuspendGrant")
}

func (p *Procurement) resume(w http.ResponseWriter, r *http.Request, pr Principal) {
	p.control(w, r, pr, "ResumeGrant")
}

func (p *Procurement) control(w http.ResponseWriter, r *http.Request, pr Principal, method string) {
	requestKey, ok := IdempotencyKey(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	id := r.PathValue("runId")
	var terminal bool
	run, err := p.withRun(ctx, pr.SubjectID, id, true, func(ctx context.Context, conn *pgxpool.Conn, run *Run) error {
		var mutation registry.Mutation
		var savedMethod string
		err := conn.QueryRow(ctx, `SELECT method,input FROM workbench_grant_controls
			WHERE deployment_id=$1 AND domain_id=$2 AND run_id=$3 AND request_key=$4`,
			p.deployment, p.domain, id, requestKey).Scan(&savedMethod, &mutation)
		if errors.Is(err, pgx.ErrNoRows) {
			mutation, err = p.executor.GrantMutation(ctx, *run)
			if err != nil {
				return err
			}
			_, err = conn.Exec(ctx, `INSERT INTO workbench_grant_controls(deployment_id,domain_id,run_id,request_key,method,input)
				VALUES($1,$2,$3,$4,$5,$6)`, p.deployment, p.domain, id, requestKey, method, mutation)
			savedMethod = method
		}
		if err != nil {
			return err
		}
		if savedMethod != method {
			return errDraftVersion
		}
		key := "workbench/" + id + "/control/" + registry.Digest([]byte(requestKey))
		op, err := p.executor.Control(ctx, pr.SubjectID, key, method, mutation)
		if err != nil {
			return err
		}
		terminal = applyControlResult(run, method, mutation, op)
		return nil
	})
	if err != nil {
		procurementError(w, r, err)
		return
	}
	if terminal {
		if err := p.markControlTerminal(ctx, id, requestKey); err != nil {
			procurementError(w, r, err)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusAccepted, run)
}

func (p *Procurement) withRun(ctx context.Context, owner, id string, wait bool, fn func(context.Context, *pgxpool.Conn, *Run) error) (Run, error) {
	conn, err := p.db.Acquire(ctx)
	if err != nil {
		return Run{}, err
	}
	defer conn.Release()
	lockKey := p.deployment + "/" + p.domain + "/" + id
	if wait {
		_, err = conn.Exec(ctx, "SELECT pg_advisory_lock(hashtextextended($1, 0))", lockKey)
	} else {
		var locked bool
		err = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1, 0))", lockKey).Scan(&locked)
		if err == nil && !locked {
			return Run{}, nil
		}
	}
	if err != nil {
		return Run{}, err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1, 0))", lockKey); err != nil {
			_ = conn.Hijack().Close(ctx)
		}
	}()
	run, err := p.readRun(ctx, conn, owner, id)
	if err != nil {
		return Run{}, err
	}
	if err := fn(ctx, conn, &run); err != nil {
		return Run{}, err
	}
	_, err = conn.Exec(ctx, `UPDATE workbench_runs SET status=$5,body=$6
		WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND run_id=$4`,
		p.deployment, p.domain, owner, id, run.Status, run)
	return run, err
}

func appendStep(run *Run, stage string, result StageResult, now time.Time) {
	step := RunStep{Stage: stage, Status: result.Status, Code: result.Code, GrantID: result.GrantID}
	if op := result.Operation; op != nil {
		step.OperationID = op.OperationID
		if registry.IsDigest(op.TxID) {
			step.TxID = op.TxID
		}
		if step.Status == "" {
			step.Status = op.Status
		}
		if op.ValidationCode != nil {
			step.ValidationCode = *op.ValidationCode
		}
		if op.FailureCode != nil {
			step.Code = *op.FailureCode
		}
	}
	if step.Status == "" {
		step.Status = RunPending
	}
	for i := len(run.Steps) - 1; i >= 0; i-- {
		previous := run.Steps[i]
		if previous.Stage == stage && previous.OperationID == step.OperationID {
			previous.At = 0
			if previous == step {
				return
			}
			break
		}
	}
	step.At = now.Unix()
	run.Steps = append(run.Steps, step)
}

func (p *Procurement) advance(ctx context.Context, owner, id string) error {
	_, err := p.withRun(ctx, owner, id, false, func(ctx context.Context, conn *pgxpool.Conn, run *Run) error {
		if run.Status != RunPending && run.Status != RunUnknown {
			return nil
		}
		// Move attempted runs behind those already waiting, even if this attempt
		// cannot progress or the process restarts before saving the result.
		tag, err := conn.Exec(ctx, `UPDATE workbench_runs SET next_attempt_at=clock_timestamp()
			WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND run_id=$4
			AND next_attempt_at <= statement_timestamp()`, p.deployment, p.domain, owner, id)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		stage := run.Stage
		result, err := p.executor.Advance(ctx, owner, *run)
		if err != nil {
			result.Status = run.Status
			result.Code = protocol.CodeOf(err)
			if result.Code == "" {
				result.Code = registry.ErrCodeStateUnavailable
			}
		}
		if result.Operation != nil && result.Status == "" {
			result.Status = result.Operation.Status
		}
		appendStep(run, stage, result, time.Now())
		if result.Traces != nil {
			run.Traces = result.Traces
		}
		switch result.Status {
		case "CONFIRMED", "DELIVERED":
			switch stage {
			case StageTask:
				run.Stage = StageRoot
			case StageRoot:
				run.Stage = StageDelegation
			case StageDelegation:
				run.Stage = StageDispatch
				run.GrantRevision, run.GrantStatus = 1, registry.Active
				run.AllowedActions = []string{"suspend"}
			}
		case RunFailed, RunStopped, RunDenied, RunUnknown, RunDecided:
			run.Status = result.Status
		}
		return nil
	})
	return err
}

// ProcessPending advances persisted runs and polls accepted grant controls.
func (p *Procurement) ProcessPending(ctx context.Context) error {
	rows, err := p.db.Query(ctx, `SELECT owner_id,run_id FROM workbench_runs
		WHERE deployment_id=$1 AND domain_id=$2 AND status IN ('PENDING','OUTCOME_UNKNOWN')
		AND next_attempt_at <= statement_timestamp() ORDER BY next_attempt_at,run_id LIMIT 50`, p.deployment, p.domain)
	if err != nil {
		return err
	}
	type key struct{ Owner, ID string }
	var keys []key
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.Owner, &k.ID); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var advanceErr error
	for _, k := range keys {
		if err := p.advance(ctx, k.Owner, k.ID); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			advanceErr = errors.Join(advanceErr, fmt.Errorf("advance procurement run %s: %w", k.ID, err))
		}
	}
	return errors.Join(advanceErr, p.refreshControls(ctx))
}

func (p *Procurement) refreshControls(ctx context.Context) error {
	rows, err := p.db.Query(ctx, `SELECT r.owner_id,c.run_id,c.request_key,c.method,c.input
		FROM workbench_grant_controls c JOIN workbench_runs r USING(deployment_id,domain_id,run_id)
		WHERE c.deployment_id=$1 AND c.domain_id=$2 AND NOT c.terminal`, p.deployment, p.domain)
	if err != nil {
		return err
	}
	type control struct {
		owner, run, key, method string
		input                   registry.Mutation
	}
	var controls []control
	for rows.Next() {
		var c control
		if err := rows.Scan(&c.owner, &c.run, &c.key, &c.method, &c.input); err != nil {
			rows.Close()
			return err
		}
		controls = append(controls, c)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range controls {
		var terminal bool
		_, err := p.withRun(ctx, c.owner, c.run, false, func(ctx context.Context, _ *pgxpool.Conn, run *Run) error {
			key := "workbench/" + c.run + "/control/" + registry.Digest([]byte(c.key))
			op, err := p.executor.Control(ctx, c.owner, key, c.method, c.input)
			if err != nil {
				return err
			}
			terminal = applyControlResult(run, c.method, c.input, op)
			return nil
		})
		if err != nil {
			return err
		}
		if terminal {
			if err := p.markControlTerminal(ctx, c.run, c.key); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyControlResult(run *Run, method string, mutation registry.Mutation, op *registrysvc.OperationView) bool {
	appendStep(run, method, StageResult{Operation: op, GrantID: mutation.ID}, time.Now())
	if op == nil || op.Status == RunPending {
		if mutation.ExpectedRevision >= run.GrantRevision {
			run.AllowedActions = []string{}
		}
		return false
	}
	if op.Status == "CONFIRMED" && mutation.ExpectedRevision >= run.GrantRevision {
		run.GrantRevision = mutation.ExpectedRevision + 1
		if method == "SuspendGrant" {
			run.GrantStatus = registry.Suspended
		} else {
			run.GrantStatus = registry.Active
		}
	}
	if run.GrantStatus == registry.Active {
		run.AllowedActions = []string{"suspend"}
	} else if run.GrantStatus == registry.Suspended {
		run.AllowedActions = []string{"resume"}
	}
	return true
}

func (p *Procurement) markControlTerminal(ctx context.Context, runID, key string) error {
	_, err := p.db.Exec(ctx, `UPDATE workbench_grant_controls SET terminal=true
		WHERE deployment_id=$1 AND domain_id=$2 AND run_id=$3 AND request_key=$4`,
		p.deployment, p.domain, runID, key)
	return err
}
