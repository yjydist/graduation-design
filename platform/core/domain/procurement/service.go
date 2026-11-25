package procurement

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"grad/platform/core/dao"
	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/platform/core/ledger"
	"grad/protocol"
	preg "grad/protocol/registry"
)

// ServiceConfig configures the Domain A procurement coordinator and Domain C root/context handlers.
type ServiceConfig struct {
	DB          *pgxpool.Pool
	Deployment  *ledger.Deployment
	Instance    *ledger.Instance
	DomainID    string
	DelegateDID string
	Actors      map[string]GrantActor
	Recipients  map[string]GrantRecipient
	Management  *domreg.Service
	Grants      *GrantOperations
	Wallet      *wallet.WalletContext
	Advisor     DraftAdvisor
	Delegator   DelegateRunner
	Peers       PeerClient
	Now         func() time.Time
}

// Service owns procurement drafts, runs, grant controls, background stage progression,
// and Domain C remote root/context operations without inbound HTTP or L4 callback inversion.
type Service struct {
	cfg ServiceConfig

	// Test-only overrides for isolated DB unit tests without live Fabric peers.
	advanceOverride   func(ctx context.Context, owner string, run Run) (StageResult, error)
	readGrantOverride func(ctx context.Context, grantID string) (preg.Grant, error)
	readTaskOverride  func(ctx context.Context, taskID string) (preg.Task, error)
}

// NewService constructs a procurement Service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.DB == nil || cfg.Deployment == nil || cfg.Deployment.DeploymentID == "" ||
		(cfg.DomainID != "A" && cfg.DomainID != "B" && cfg.DomainID != "C") {
		return nil, errors.New("procurement service requires database, deployment, and domainId (A/B/C)")
	}
	cfg.Actors = maps.Clone(cfg.Actors)
	cfg.Recipients = maps.Clone(cfg.Recipients)
	if cfg.Now == nil {
		if cfg.Grants != nil {
			cfg.Now = cfg.Grants.Now
		} else {
			cfg.Now = time.Now
		}
	}
	if cfg.DelegateDID == "" {
		if a1, ok := cfg.Recipients["A1"]; ok {
			cfg.DelegateDID = a1.DID
		}
	}
	return &Service{cfg: cfg}, nil
}

func (s *Service) deploymentID() string { return s.cfg.Deployment.DeploymentID }
func (s *Service) now() time.Time       { return s.cfg.Now() }

func (s *Service) recipient(actor string) GrantRecipient {
	if r, ok := s.cfg.Recipients[actor]; ok {
		return r
	}
	if a, ok := s.cfg.Actors[actor]; ok {
		return GrantRecipient{DID: a.Signer.DID, CredentialID: a.Signer.CredentialID}
	}
	return GrantRecipient{}
}

func newObjectID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// ChatDraft invokes the configured DraftAdvisor and persists or updates the buyer's draft.
func (s *Service) ChatDraft(ctx context.Context, principal Principal, message, draftID string) (string, Draft, error) {
	msg := strings.TrimSpace(message)
	if msg == "" || utf8.RuneCountInString(message) > MaxChatMessageLength {
		return "", Draft{}, protocol.NewError(preg.ErrCodeInvalidSchema, "invalid message")
	}
	if s.cfg.Advisor == nil {
		return "", Draft{}, ErrUnavailable
	}
	var previous *Draft
	if draftID != "" {
		d, err := s.GetDraft(ctx, principal.SubjectID, draftID)
		if err != nil {
			return "", Draft{}, err
		}
		previous = &d
	}
	d, reply, err := s.cfg.Advisor.SuggestDraft(ctx, msg, previous)
	if err != nil {
		return "", Draft{}, err
	}
	if err := d.Validate(s.cfg.DelegateDID, s.now()); err != nil {
		return "", Draft{}, err
	}
	if previous == nil {
		d.DraftID, err = newObjectID()
		if err != nil {
			return "", Draft{}, err
		}
		d.Version = 1
		if _, err := s.cfg.DB.Exec(ctx, `INSERT INTO workbench_drafts(deployment_id,domain_id,owner_id,draft_id,version,body)
			VALUES($1,$2,$3,$4,$5,$6)`,
			s.deploymentID(), s.cfg.DomainID, principal.SubjectID, d.DraftID, d.Version, d); err != nil {
			return "", Draft{}, err
		}
	} else {
		d.DraftID = previous.DraftID
		d.Version = previous.Version
		d, err = s.UpdateDraft(ctx, principal.SubjectID, d)
		if err != nil {
			return "", Draft{}, err
		}
	}
	return reply, d, nil
}

// GetDraft reads an owner-scoped procurement draft.
func (s *Service) GetDraft(ctx context.Context, owner, draftID string) (Draft, error) {
	var d Draft
	err := s.cfg.DB.QueryRow(ctx, `SELECT body FROM workbench_drafts
		WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND draft_id=$4`,
		s.deploymentID(), s.cfg.DomainID, owner, draftID).Scan(&d)
	if errors.Is(err, pgx.ErrNoRows) {
		return Draft{}, ErrNotFound
	}
	return d, err
}

// UpdateDraft validates and saves an unconfirmed draft with optimistic version checking.
func (s *Service) UpdateDraft(ctx context.Context, owner string, draft Draft) (Draft, error) {
	if err := draft.Validate(s.cfg.DelegateDID, s.now()); err != nil {
		return Draft{}, err
	}
	version := draft.Version
	draft.Version++
	tag, err := s.cfg.DB.Exec(ctx, `UPDATE workbench_drafts SET version=$6,body=$7
		WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND draft_id=$4 AND version=$5 AND run_id IS NULL`,
		s.deploymentID(), s.cfg.DomainID, owner, draft.DraftID, version, draft.Version, draft)
	if err != nil {
		return Draft{}, err
	}
	if tag.RowsAffected() != 1 {
		if _, err := s.GetDraft(ctx, owner, draft.DraftID); err != nil {
			return Draft{}, err
		}
		return Draft{}, ErrDraftVersionConflict
	}
	return draft, nil
}

// ConfirmDraft atomically converts a version-matched draft into a persisted procurement Run,
// returning the existing Run idempotently on repeated confirmations of the same version.
func (s *Service) ConfirmDraft(ctx context.Context, owner, draftID string, version int64) (Run, error) {
	var out Run
	now := s.now()
	err := dao.RunInTx(ctx, s.cfg.DB, func(tx dao.Tx) error {
		var d Draft
		var existing *string
		err := tx.QueryRow(ctx, `SELECT body,run_id FROM workbench_drafts
			WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND draft_id=$4 FOR UPDATE`,
			s.deploymentID(), s.cfg.DomainID, owner, draftID).Scan(&d, &existing)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if version != d.Version {
			return ErrDraftVersionConflict
		}
		if existing != nil {
			out, err = s.readRun(ctx, tx, owner, *existing)
			return err
		}
		if err := d.Validate(s.cfg.DelegateDID, now); err != nil {
			return err
		}
		runID, err := newObjectID()
		if err != nil {
			return err
		}
		run := Run{
			RunID:          runID,
			TaskID:         preg.Digest([]byte(s.deploymentID() + "/workbench/" + runID)),
			DraftID:        draftID,
			Stage:          StageTask,
			Status:         RunPending,
			ConfirmedAt:    now.Unix(),
			Task:           d,
			AllowedActions: []string{},
			Steps:          []RunStep{{Stage: StageTask, Status: RunPending, At: now.Unix()}},
			Traces:         []ToolTrace{},
		}
		if _, err := tx.Exec(ctx, `INSERT INTO workbench_runs(deployment_id,domain_id,owner_id,run_id,task_id,status,body)
			VALUES($1,$2,$3,$4,$5,$6,$7)`,
			s.deploymentID(), s.cfg.DomainID, owner, run.RunID, run.TaskID, run.Status, run); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE workbench_drafts SET run_id=$5
			WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND draft_id=$4`,
			s.deploymentID(), s.cfg.DomainID, owner, draftID, run.RunID); err != nil {
			return err
		}
		out = run
		return nil
	})
	return out, err
}

func (s *Service) readRun(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, owner, id string) (Run, error) {
	var run Run
	err := q.QueryRow(ctx, `SELECT body FROM workbench_runs WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND run_id=$4`,
		s.deploymentID(), s.cfg.DomainID, owner, id).Scan(&run)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	return run, err
}

// GetRunRecord returns the persisted Run record without remote B1 trace queries (used by evidence).
func (s *Service) GetRunRecord(ctx context.Context, owner, runID string) (Run, error) {
	return s.readRun(ctx, s.cfg.DB, owner, runID)
}

// ListRuns lists all runs owned by owner in reverse chronological order.
func (s *Service) ListRuns(ctx context.Context, owner string) ([]Run, error) {
	rows, err := s.cfg.DB.Query(ctx, `SELECT body FROM workbench_runs
		WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 ORDER BY created_at DESC`,
		s.deploymentID(), s.cfg.DomainID, owner)
	if err != nil {
		return nil, err
	}
	runs, err := pgx.CollectRows(rows, pgx.RowTo[Run])
	if err != nil {
		return nil, err
	}
	if runs == nil {
		runs = []Run{}
	}
	return runs, nil
}

// GetRun returns the owner-scoped Run enriched with local A1 tool traces and live B1 dispatch traces.
func (s *Service) GetRun(ctx context.Context, owner, runID string) (Run, error) {
	run, err := s.GetRunRecord(ctx, owner, runID)
	if err != nil {
		return Run{}, err
	}
	return s.addToolTraces(ctx, run)
}

func (s *Service) addToolTraces(ctx context.Context, run Run) (Run, error) {
	rows, err := s.cfg.DB.Query(ctx, `SELECT body FROM workbench_tool_trace
		WHERE deployment_id=$1 AND domain_id=$2 AND run_id=$3 ORDER BY seq`,
		s.deploymentID(), s.cfg.DomainID, run.RunID)
	if err != nil {
		return run, err
	}
	local, err := pgx.CollectRows(rows, pgx.RowTo[ToolTrace])
	if err != nil {
		return run, err
	}
	if run.Stage == StageDispatch && s.cfg.Peers != nil {
		readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		// Keep the last observed B1 traces available during a peer outage.
		if status, err := s.cfg.Peers.GetDispatch(readCtx, run.RunID); err == nil {
			run.Traces = status.Traces
		}
	}
	run.Traces = append(local, run.Traces...)
	return run, nil
}

// SuspendRun submits an idempotent SuspendGrant control for the run's G1 grant.
func (s *Service) SuspendRun(ctx context.Context, owner, runID, requestKey string) (Run, error) {
	return s.controlRun(ctx, owner, runID, requestKey, "SuspendGrant")
}

// ResumeRun submits an idempotent ResumeGrant control for the run's G1 grant.
func (s *Service) ResumeRun(ctx context.Context, owner, runID, requestKey string) (Run, error) {
	return s.controlRun(ctx, owner, runID, requestKey, "ResumeGrant")
}

func (s *Service) controlRun(ctx context.Context, owner, runID, requestKey, method string) (Run, error) {
	if requestKey == "" {
		return Run{}, protocol.NewError(preg.ErrCodeInvalidSchema, "idempotency key required")
	}
	var terminal bool
	run, err := s.withRun(ctx, owner, runID, true, func(ctx context.Context, conn *pgxpool.Conn, run *Run) error {
		var mutation preg.Mutation
		var savedMethod string
		err := conn.QueryRow(ctx, `SELECT method,input FROM workbench_grant_controls
			WHERE deployment_id=$1 AND domain_id=$2 AND run_id=$3 AND request_key=$4`,
			s.deploymentID(), s.cfg.DomainID, runID, requestKey).Scan(&savedMethod, &mutation)
		if errors.Is(err, pgx.ErrNoRows) {
			mutation, err = s.grantMutation(ctx, *run)
			if err != nil {
				return err
			}
			_, err = conn.Exec(ctx, `INSERT INTO workbench_grant_controls(deployment_id,domain_id,run_id,request_key,method,input)
				VALUES($1,$2,$3,$4,$5,$6)`, s.deploymentID(), s.cfg.DomainID, runID, requestKey, method, mutation)
			savedMethod = method
		}
		if err != nil {
			return err
		}
		if savedMethod != method {
			return ErrDraftVersionConflict
		}
		key := "workbench/" + runID + "/control/" + preg.Digest([]byte(requestKey))
		op, err := s.submitControl(ctx, owner, key, method, mutation)
		if err != nil {
			return err
		}
		terminal = applyControlResult(run, method, mutation, op, s.now())
		return nil
	})
	if err != nil {
		return Run{}, err
	}
	if terminal {
		if err := s.markControlTerminal(ctx, runID, requestKey); err != nil {
			return Run{}, err
		}
	}
	return run, nil
}

func (s *Service) grantMutation(ctx context.Context, run Run) (preg.Mutation, error) {
	id := run.GrantID("G1")
	g, err := s.readGrantFromLedger(ctx, id)
	if err != nil {
		return preg.Mutation{}, err
	}
	if g.Task != run.TaskID || g.Issuer != s.cfg.Deployment.Bootstrap.TaskCreator.Subject {
		return preg.Mutation{}, protocol.NewError(preg.ErrCodeBindingMismatch, "grant differs from current run")
	}
	return preg.Mutation{Bound: g.Bound, ID: g.ID, ExpectedRevision: g.Revision, ExpectedDigest: g.Digest}, nil
}

func (s *Service) readGrantFromLedger(ctx context.Context, grantID string) (preg.Grant, error) {
	if s.readGrantOverride != nil {
		return s.readGrantOverride(ctx, grantID)
	}
	if s.cfg.Instance == nil {
		return preg.Grant{}, ErrUnavailable
	}
	p, err := s.cfg.Instance.ReadPeer()
	if err != nil {
		return preg.Grant{}, err
	}
	defer p.Close()
	g, err := ledger.ReadLedgerRecord[preg.Grant](ctx, p, "grant", grantID)
	if ledger.IsMissingRecord(err) {
		return preg.Grant{}, ErrNotFound
	}
	return g, err
}

func (s *Service) submitControl(ctx context.Context, owner, key, method string, mutation preg.Mutation) (*domreg.OperationView, error) {
	if s.cfg.Management == nil {
		return nil, ErrUnavailable
	}
	u, ok := s.cfg.Actors["U"]
	if !ok || owner != u.Signer.DID || (method != "SuspendGrant" && method != "ResumeGrant") {
		return nil, protocol.NewError(preg.ErrCodeBindingMismatch, "invalid workbench grant control")
	}
	return s.cfg.Management.Submit(ctx, u.Management, method, key, mutation)
}

func (s *Service) withRun(ctx context.Context, owner, id string, wait bool, fn func(context.Context, *pgxpool.Conn, *Run) error) (Run, error) {
	lockKey := s.deploymentID() + "/" + s.cfg.DomainID + "/" + id
	var out Run
	work := func(ctx context.Context, conn *pgxpool.Conn) error {
		run, err := s.readRun(ctx, conn, owner, id)
		if err != nil {
			return err
		}
		if err := fn(ctx, conn, &run); err != nil {
			return err
		}
		_, err = conn.Exec(ctx, `UPDATE workbench_runs SET status=$5,body=$6
			WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND run_id=$4`,
			s.deploymentID(), s.cfg.DomainID, owner, id, run.Status, run)
		if err != nil {
			return err
		}
		out = run
		return nil
	}
	if wait {
		err := dao.WithSessionAdvisoryLock(ctx, s.cfg.DB, lockKey, work)
		return out, err
	}
	acquired, err := dao.TryWithSessionAdvisoryLock(ctx, s.cfg.DB, lockKey, work)
	if err != nil || !acquired {
		return Run{}, err
	}
	return out, nil
}

func appendStep(run *Run, stage string, result StageResult, now time.Time) {
	step := RunStep{Stage: stage, Status: result.Status, Code: result.Code, GrantID: result.GrantID}
	if op := result.Operation; op != nil {
		step.OperationID = op.OperationID
		if preg.IsDigest(op.TxID) {
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

func (s *Service) advanceRun(ctx context.Context, owner, id string) error {
	_, err := s.withRun(ctx, owner, id, false, func(ctx context.Context, conn *pgxpool.Conn, run *Run) error {
		if run.Status != RunPending && run.Status != RunUnknown {
			return nil
		}
		// Move attempted runs behind those already waiting, even if this attempt
		// cannot progress or the process restarts before saving the result.
		tag, err := conn.Exec(ctx, `UPDATE workbench_runs SET next_attempt_at=clock_timestamp()
			WHERE deployment_id=$1 AND domain_id=$2 AND owner_id=$3 AND run_id=$4
			AND next_attempt_at <= statement_timestamp()`, s.deploymentID(), s.cfg.DomainID, owner, id)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		stage := run.Stage
		result, err := s.AdvanceStage(ctx, owner, *run)
		if err != nil {
			result.Status = run.Status
			result.Code = protocol.CodeOf(err)
			if result.Code == "" {
				result.Code = preg.ErrCodeStateUnavailable
			}
		}
		if result.Operation != nil && result.Status == "" {
			result.Status = result.Operation.Status
		}
		appendStep(run, stage, result, s.now())
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
				run.GrantRevision, run.GrantStatus = 1, preg.Active
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
func (s *Service) ProcessPending(ctx context.Context) error {
	rows, err := s.cfg.DB.Query(ctx, `SELECT owner_id,run_id FROM workbench_runs
		WHERE deployment_id=$1 AND domain_id=$2 AND status IN ('PENDING','OUTCOME_UNKNOWN')
		AND next_attempt_at <= statement_timestamp() ORDER BY next_attempt_at,run_id LIMIT 50`,
		s.deploymentID(), s.cfg.DomainID)
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
		if err := s.advanceRun(ctx, k.Owner, k.ID); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			advanceErr = errors.Join(advanceErr, fmt.Errorf("advance procurement run %s: %w", k.ID, err))
		}
	}
	return errors.Join(advanceErr, s.refreshControls(ctx))
}

func (s *Service) refreshControls(ctx context.Context) error {
	rows, err := s.cfg.DB.Query(ctx, `SELECT r.owner_id,c.run_id,c.request_key,c.method,c.input
		FROM workbench_grant_controls c JOIN workbench_runs r USING(deployment_id,domain_id,run_id)
		WHERE c.deployment_id=$1 AND c.domain_id=$2 AND NOT c.terminal`,
		s.deploymentID(), s.cfg.DomainID)
	if err != nil {
		return err
	}
	type control struct {
		owner, run, key, method string
		input                   preg.Mutation
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
		_, err := s.withRun(ctx, c.owner, c.run, false, func(ctx context.Context, _ *pgxpool.Conn, run *Run) error {
			key := "workbench/" + c.run + "/control/" + preg.Digest([]byte(c.key))
			op, err := s.submitControl(ctx, c.owner, key, c.method, c.input)
			if err != nil {
				return err
			}
			terminal = applyControlResult(run, c.method, c.input, op, s.now())
			return nil
		})
		if err != nil {
			return err
		}
		if terminal {
			if err := s.markControlTerminal(ctx, c.run, c.key); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyControlResult(run *Run, method string, mutation preg.Mutation, op *domreg.OperationView, now time.Time) bool {
	appendStep(run, method, StageResult{Operation: op, GrantID: mutation.ID}, now)
	if op == nil || op.Status == RunPending {
		if mutation.ExpectedRevision >= run.GrantRevision {
			run.AllowedActions = []string{}
		}
		return false
	}
	if op.Status == "CONFIRMED" && mutation.ExpectedRevision >= run.GrantRevision {
		run.GrantRevision = mutation.ExpectedRevision + 1
		if method == "SuspendGrant" {
			run.GrantStatus = preg.Suspended
		} else {
			run.GrantStatus = preg.Active
		}
	}
	if run.GrantStatus == preg.Active {
		run.AllowedActions = []string{"suspend"}
	} else if run.GrantStatus == preg.Suspended {
		run.AllowedActions = []string{"resume"}
	}
	return true
}

func (s *Service) markControlTerminal(ctx context.Context, runID, key string) error {
	_, err := s.cfg.DB.Exec(ctx, `UPDATE workbench_grant_controls SET terminal=true
		WHERE deployment_id=$1 AND domain_id=$2 AND run_id=$3 AND request_key=$4`,
		s.deploymentID(), s.cfg.DomainID, runID, key)
	return err
}

// AdvanceStage executes one deterministic progression attempt for run's current stage.
func (s *Service) AdvanceStage(ctx context.Context, owner string, run Run) (StageResult, error) {
	if s.advanceOverride != nil {
		return s.advanceOverride(ctx, owner, run)
	}
	if owner != s.cfg.Deployment.Bootstrap.TaskCreator.Subject || run.Task.DelegateDID != s.cfg.DelegateDID {
		return StageResult{Status: RunFailed, Code: preg.ErrCodeBindingMismatch}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	now := s.now()
	if now.Unix() >= run.Task.ExpiresAt {
		if run.Stage == StageDispatch {
			return s.resumeExpiredDispatch(ctx, run, now)
		}
		return StageResult{Status: RunFailed, Code: preg.ErrCodeTaskInactive}, nil
	}
	switch run.Stage {
	case StageTask:
		return s.registerTask(ctx, run)
	case StageRoot:
		return s.obtainRoot(ctx, run)
	case StageDelegation:
		return s.issueG1(ctx, run)
	case StageDispatch:
		return s.delegateDispatch(ctx, run)
	default:
		return StageResult{Status: RunFailed, Code: preg.ErrCodeInvalidState}, nil
	}
}

func (s *Service) registerTask(ctx context.Context, run Run) (StageResult, error) {
	actor, ok := s.cfg.Actors["U"]
	if !ok || s.cfg.Management == nil {
		return StageResult{}, ErrUnavailable
	}
	spec := run.Task.TaskSpec()
	digest, err := spec.Digest()
	if err != nil {
		return StageResult{}, err
	}
	input := preg.Task{
		Bound:             preg.Bound{DeploymentID: s.deploymentID()},
		ID:                run.TaskID,
		Creator:           actor.Signer.DID,
		CreatorCredential: actor.Signer.CredentialID,
		CreatorKeyVersion: actor.Signer.KeyVersion,
		Domain:            s.cfg.DomainID,
		Mode:              run.Task.Mode,
		Resource:          s.cfg.Deployment.Bootstrap.ResourceID,
		Digest:            digest,
		Interval:          preg.Interval{NBF: run.ConfirmedAt - 5, EXP: run.Task.ExpiresAt},
	}
	op, err := s.cfg.Management.Submit(ctx, actor.Management, "RegisterTask", "workbench-task/"+run.RunID, input)
	return StageResult{Operation: op}, err
}

func rootRequest(run Run, buyer GrantRecipient) RootGrantRequest {
	return RootGrantRequest{
		GrantID:        run.GrantID("G0"),
		TaskID:         run.TaskID,
		Recipient:      buyer,
		TaskSpec:       run.Task.TaskSpec(),
		MaxAmountMinor: run.Task.MaxAmountMinor,
		Depth:          2,
	}
}

func (s *Service) obtainRoot(ctx context.Context, run Run) (StageResult, error) {
	req := rootRequest(run, s.recipient("U"))
	key := "workbench-root/" + req.TaskID
	var result RootGrantResponse
	var err error
	if run.Task.Mode == preg.RP {
		if s.cfg.Peers == nil {
			return StageResult{GrantID: req.GrantID}, ErrUnavailable
		}
		result, err = s.cfg.Peers.RequestRoot(ctx, req)
	} else {
		if s.cfg.Grants == nil {
			return StageResult{GrantID: req.GrantID}, ErrUnavailable
		}
		result.Operation, result.Delivery, err = s.cfg.Grants.IssueRoot(ctx, "PA", key, req)
	}
	step := StageResult{Operation: result.Operation, GrantID: req.GrantID}
	if err != nil {
		return stageError(step, err)
	}
	if result.Code != "" {
		return stageError(step, protocol.NewError(result.Code, "root publication awaiting verification"))
	}
	if result.Delivery == nil {
		if result.Operation == nil || result.Operation.Status != "FAILED" {
			step.Status = RunPending
		}
		return step, nil
	}
	bundle, receipt, err := s.cfg.Grants.Receive(ctx, req.Recipient, *result.Delivery)
	if err != nil {
		return stageError(step, err)
	}
	expectedIssuer := s.recipient("PA").DID
	if run.Task.Mode == preg.RP {
		expectedIssuer = s.recipient("C").DID
	}
	if bundle.Claims.TaskID != run.TaskID || bundle.Claims.AuthorizationMode != run.Task.Mode || bundle.Claims.Issuer != expectedIssuer {
		return stageError(step, protocol.NewError(preg.ErrCodeBindingMismatch, "root receipt differs from confirmed task"))
	}
	if run.Task.Mode == preg.BM {
		err = s.cfg.Grants.MarkReceived(ctx, *result.Delivery, receipt)
	} else {
		err = s.cfg.Peers.AckRootReceipt(ctx, req.GrantID, receipt)
	}
	if err != nil {
		return stageError(step, err)
	}
	step.Status = "DELIVERED"
	return step, nil
}

func stageError(step StageResult, err error) (StageResult, error) {
	switch protocol.CodeOf(err) {
	case preg.ErrCodeInvalidSchema, preg.ErrCodeBindingMismatch, preg.ErrCodeTaskInactive,
		preg.ErrCodeRootAuthorityInvalid, preg.ErrCodePurchasingAuthorityInvalid,
		preg.ErrCodeCredentialStatusInvalid, preg.ErrCodeMaterialInvalid, preg.ErrCodeDeliveryConflict:
		step.Status, step.Code = RunFailed, protocol.CodeOf(err)
		return step, nil
	default:
		return step, err
	}
}

func (s *Service) localGrant(ctx context.Context, actor, grantID string) error {
	bundle, err := s.cfg.Grants.Load(ctx, s.recipient(actor), grantID)
	if err != nil {
		return err
	}
	return s.cfg.Wallet.AddGrantBundle(bundle)
}

func (s *Service) childOperation(ctx context.Context, actor, grantID string) *domreg.OperationView {
	if s.cfg.Management == nil {
		return nil
	}
	a, ok := s.cfg.Actors[actor]
	if !ok {
		return nil
	}
	key := ChildGrantOperationKey(grantID)
	op, _ := s.cfg.Management.Operation(ctx, a.Management, domreg.ManagementOperationID(s.deploymentID(), a.Management, "RegisterGrant", key))
	return op
}

func (s *Service) issueG1(ctx context.Context, run Run) (StageResult, error) {
	id := run.GrantID("G1")
	step := StageResult{GrantID: id, Status: RunPending}
	recipient := s.recipient("A1")
	delivery, err := s.cfg.Grants.Published(ctx, recipient, id)
	if err != nil {
		step.Operation, delivery, err = s.cfg.Grants.ResumeChild(ctx, "U", id)
		if step.Operation != nil && step.Operation.Status == "FAILED" {
			step.Status = RunFailed
			return step, nil
		}
		if delivery == nil && (step.Operation != nil || !protocol.HasCode(err, preg.ErrCodeMaterialNotSynced)) {
			if err != nil {
				return stageError(step, err)
			}
			return step, nil
		}
	}
	if delivery == nil {
		if err := s.localGrant(ctx, "U", run.GrantID("G0")); err != nil {
			return stageError(step, err)
		}
		_, err = s.cfg.Wallet.DelegateGrant(ctx, wallet.DelegateGrantInput{
			IssuerActor:       "U",
			SubjectActor:      "A1",
			ParentGrantID:     run.GrantID("G0"),
			GrantID:           id,
			TaskID:            run.TaskID,
			AuthorizationMode: run.Task.Mode,
			MaxAmountMinor:    run.Task.MaxAmountMinor,
			RemainingDepth:    1,
		})
		step.Operation = s.childOperation(ctx, "U", id)
		if step.Operation != nil && step.Operation.Status == "FAILED" {
			step.Status = RunFailed
			return step, nil
		}
		if err != nil {
			return stageError(step, err)
		}
		delivery, err = s.cfg.Grants.Published(ctx, recipient, id)
		if err != nil {
			return stageError(step, err)
		}
	}
	step.Operation = &delivery.Operation
	_, receipt, err := s.cfg.Grants.Receive(ctx, recipient, *delivery)
	if err != nil {
		return stageError(step, err)
	}
	if err := s.cfg.Grants.MarkReceived(ctx, *delivery, receipt); err != nil {
		return stageError(step, err)
	}
	step.Status = "DELIVERED"
	return step, nil
}

func (s *Service) delegateDispatch(ctx context.Context, run Run) (StageResult, error) {
	id := run.GrantID("G2")
	step := StageResult{GrantID: id, Status: RunPending}
	recipient := s.recipient("B1")
	delivery, err := s.cfg.Grants.Published(ctx, recipient, id)
	if err != nil {
		step.Operation, delivery, err = s.cfg.Grants.ResumeChild(ctx, "A1", id)
		if step.Operation != nil && step.Operation.Status == "FAILED" {
			step.Status = RunFailed
			return step, nil
		}
		if delivery == nil && (step.Operation != nil || !protocol.HasCode(err, preg.ErrCodeMaterialNotSynced)) {
			if err != nil {
				return stageError(step, err)
			}
			return step, nil
		}
	}
	if delivery == nil {
		if s.cfg.Delegator == nil {
			return step, ErrUnavailable
		}
		if err := s.localGrant(ctx, "A1", run.GrantID("G1")); err != nil {
			return stageError(step, err)
		}
		binding := wallet.ExecutionBinding{
			DeploymentID: s.deploymentID(),
			DomainID:     "A",
			Actor:        "A1",
			DID:          s.cfg.DelegateDID,
			TaskID:       run.TaskID,
			Mode:         run.Task.Mode,
			GrantID:      run.GrantID("G1"),
			Stage:        wallet.StageDelegate,
			SubjectDID:   recipient.DID,
			SubjectActor: "B1",
			ChildGrantID: id,
			RunID:        run.RunID,
			Verify: func(ctx context.Context, _ wallet.ExecutionBinding) error {
				return s.localGrant(ctx, "A1", run.GrantID("G1"))
			},
		}
		ops, err := wallet.NewBoundOperations(s.cfg.Wallet, binding)
		if err != nil {
			return stageError(step, err)
		}
		var traceErr error
		modelRun, runnerErr := s.cfg.Delegator.RunDelegate(ctx, ops, DelegateRunInput{
			RunID:          run.RunID,
			TaskID:         run.TaskID,
			Mode:           run.Task.Mode,
			ParentGrantID:  binding.GrantID,
			ChildGrantID:   id,
			RecipientDID:   recipient.DID,
			MaxAmountMinor: run.Task.MaxAmountMinor,
			OnToolTrace: func(trace ToolTrace) {
				if err := s.storeTrace(ctx, run.RunID, trace); err != nil {
					traceErr = err
				}
			},
		})
		if err := s.storeModelRun(ctx, run.RunID, modelRun); err != nil {
			return step, err
		}
		if traceErr != nil {
			return step, traceErr
		}
		step.Operation = s.childOperation(ctx, "A1", id)
		if step.Operation != nil && step.Operation.Status == "FAILED" {
			step.Status = RunFailed
			return step, nil
		}
		delivery, err = s.cfg.Grants.Published(ctx, recipient, id)
		if err != nil {
			if step.Operation == nil && runnerErr == nil {
				step.Status = RunStopped
			}
			if runnerErr != nil {
				step.Code = "MODEL_REQUEST_FAILED"
			}
			return step, nil
		}
	}
	if s.cfg.Peers == nil {
		return step, ErrUnavailable
	}
	var result DispatchStatusView
	if delivery.Operation.Delivered {
		result, err = s.cfg.Peers.GetDispatch(ctx, run.RunID)
	} else {
		wire := DispatchRequest{
			Run:      DispatchRun{RunID: run.RunID, TaskID: run.TaskID, Task: run.Task},
			Delivery: *delivery,
		}
		result, err = s.cfg.Peers.SubmitDispatch(ctx, wire)
	}
	if err != nil {
		step.Operation = &delivery.Operation
		if protocol.HasCode(err, preg.ErrCodeTaskInactive) {
			// Let the expiry path check for an existing acceptance after an overlapping POST.
			return step, err
		}
		return stageError(step, err)
	}
	return s.applyDispatchReceipt(ctx, step, *delivery, result)
}

func (s *Service) resumeExpiredDispatch(ctx context.Context, run Run, now time.Time) (StageResult, error) {
	step := StageResult{GrantID: run.GrantID("G2"), Status: run.Status}
	if s.cfg.Peers == nil {
		return step, ErrUnavailable
	}
	result, err := s.cfg.Peers.GetDispatch(ctx, run.RunID)
	if err != nil {
		// Allow both domains' clock error before treating absence as final.
		if run.Status != RunUnknown && (errors.Is(err, ErrNotFound) || protocol.HasCode(err, "NOT_FOUND")) &&
			!now.Before(time.Unix(run.Task.ExpiresAt, 0).Add(2*preg.ClockError)) {
			step.Status, step.Code = RunFailed, preg.ErrCodeTaskInactive
			return step, nil
		}
		return step, err
	}
	delivery, err := s.cfg.Grants.Published(ctx, s.recipient("B1"), step.GrantID)
	if err != nil {
		return step, err
	}
	return s.applyDispatchReceipt(ctx, step, *delivery, result)
}

func (s *Service) applyDispatchReceipt(ctx context.Context, step StageResult, delivery GrantDelivery, result DispatchStatusView) (StageResult, error) {
	step.Operation = &delivery.Operation
	if result.Receipt != delivery.Digest {
		return stageError(step, protocol.NewError(preg.ErrCodeBindingMismatch, "dispatch receipt differs from delivery"))
	}
	if !delivery.Operation.Delivered {
		if err := s.cfg.Grants.MarkReceived(ctx, delivery, result.Receipt); err != nil {
			return stageError(step, err)
		}
	}
	step.Status, step.Code = result.Status, result.Code
	step.Traces = result.Traces
	return step, nil
}

func (s *Service) storeTrace(ctx context.Context, runID string, trace ToolTrace) error {
	_, err := s.cfg.DB.Exec(ctx, `INSERT INTO workbench_tool_trace(deployment_id,domain_id,run_id,body) VALUES($1,$2,$3,$4)`,
		s.deploymentID(), s.cfg.DomainID, runID, BoundedTrace(trace))
	return err
}

func (s *Service) storeModelRun(ctx context.Context, runID string, result ModelRunResult) error {
	if len(result.ResponseModels) == 0 {
		return nil
	}
	return s.storeTrace(ctx, runID, ToolTrace{
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

// --- Domain C operations ---

// IssueRemoteRoot validates a Domain A root grant request and issues G0 under Domain C's service authority.
func (s *Service) IssueRemoteRoot(ctx context.Context, req RootGrantRequest) (*GrantDelivery, *domreg.OperationView, error) {
	if req.Recipient != s.recipient("U") || req.GrantID != (Run{TaskID: req.TaskID}).GrantID("G0") ||
		req.Depth != 2 || req.TaskSpec.SupplierID != DefaultSupplierID {
		return nil, nil, protocol.NewError(preg.ErrCodeBindingMismatch, "root request outside workbench scope")
	}
	if s.cfg.Grants == nil {
		return nil, nil, ErrUnavailable
	}
	op, delivery, err := s.cfg.Grants.IssueRoot(ctx, "C", "workbench-root/"+req.TaskID, req)
	return delivery, op, err
}

// AckRemoteRootReceipt marks Domain C's published G0 operation as delivered after verifying the recipient receipt digest.
func (s *Service) AckRemoteRootReceipt(ctx context.Context, grantID, digest string) error {
	if s.cfg.Grants == nil {
		return ErrUnavailable
	}
	delivery, err := s.cfg.Grants.Published(ctx, s.recipient("U"), grantID)
	if err != nil {
		return err
	}
	return s.cfg.Grants.MarkReceived(ctx, *delivery, digest)
}

// ReadWorkbenchTask reads a confirmed Domain A buyer task from the pinned peer ledger.
func (s *Service) ReadWorkbenchTask(ctx context.Context, taskID string) (preg.Task, error) {
	if !preg.IsDigest(taskID) {
		return preg.Task{}, protocol.NewError(preg.ErrCodeInvalidSchema, "invalid workbench task ID")
	}
	var task preg.Task
	var err error
	if s.readTaskOverride != nil {
		task, err = s.readTaskOverride(ctx, taskID)
	} else {
		if s.cfg.Instance == nil {
			return preg.Task{}, ErrUnavailable
		}
		p, peerErr := s.cfg.Instance.ReadPeer()
		if peerErr != nil {
			return preg.Task{}, peerErr
		}
		defer p.Close()
		task, err = ledger.ReadLedgerRecord[preg.Task](ctx, p, "task", taskID)
		if ledger.IsMissingRecord(err) {
			return preg.Task{}, ErrNotFound
		}
	}
	if err == nil && (task.Creator != s.cfg.Deployment.Bootstrap.TaskCreator.Subject || task.Domain != "A" || task.DeploymentID != s.deploymentID()) {
		err = protocol.NewError(preg.ErrCodeBindingMismatch, "task is outside the workbench owner scope")
	}
	return task, err
}

// EnsureSupplierContext installs the supplier C trusted context for a confirmed active task
// via updater, succeeding idempotently if the context already exists.
func (s *Service) EnsureSupplierContext(ctx context.Context, taskID string, updater ContextUpdater) error {
	task, err := s.ReadWorkbenchTask(ctx, taskID)
	if err != nil {
		return protocol.WrapError(preg.ErrCodeStateUnavailable, "confirmed workbench task unavailable", err)
	}
	current := s.now()
	if !task.Interval.Current(current, 0) || task.Status != preg.Active {
		return protocol.NewError(preg.ErrCodeTaskInactive, "workbench task is no longer active")
	}
	if updater == nil {
		return protocol.NewError(preg.ErrCodeStateUnavailable, "supplier context updater unavailable")
	}
	if err := updater(ctx, task.ID, 0, riskLevelNormal, task.EXP); err != nil {
		var exists bool
		readErr := s.cfg.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM trusted_contexts
			WHERE deployment_id=$1 AND task_id=$2)`, s.deploymentID(), taskID).Scan(&exists)
		if readErr != nil || !exists {
			return protocol.NewError(preg.ErrCodeStateUnavailable, "supplier environment unavailable")
		}
	}
	return nil
}
