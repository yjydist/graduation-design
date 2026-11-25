//go:build db

package procurement

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/domain/wallet"
	"grad/platform/core/ledger"
	"grad/platform/internal/testutil"
	"grad/protocol"
	preg "grad/protocol/registry"
)

type stubAdvisor struct {
	draft Draft
	reply string
}

func (a stubAdvisor) SuggestDraft(_ context.Context, _ string, _ *Draft) (Draft, string, error) {
	if a.reply == "" {
		return a.draft, "Drafted procurement terms", nil
	}
	return a.draft, a.reply, nil
}

type stubPeerClient struct {
	getDispatchFn func(ctx context.Context, runID string) (DispatchStatusView, error)
}

func (p *stubPeerClient) RequestRoot(context.Context, RootGrantRequest) (RootGrantResponse, error) {
	return RootGrantResponse{}, ErrUnavailable
}
func (p *stubPeerClient) AckRootReceipt(context.Context, string, string) error { return nil }
func (p *stubPeerClient) EnsureContext(context.Context, string) error          { return nil }
func (p *stubPeerClient) SubmitDispatch(context.Context, DispatchRequest) (DispatchStatusView, error) {
	return DispatchStatusView{}, ErrUnavailable
}
func (p *stubPeerClient) GetDispatch(ctx context.Context, runID string) (DispatchStatusView, error) {
	if p.getDispatchFn != nil {
		return p.getDispatchFn(ctx, runID)
	}
	return DispatchStatusView{}, ErrUnavailable
}
func (p *stubPeerClient) RequestDispatchProbe(context.Context, ProbeRequest) (ProbeResponse, error) {
	return ProbeResponse{}, ErrUnavailable
}

func TestProcurementTextLimits(t *testing.T) {
	ctx := t.Context()
	const deploy, domain, delegate = "procurement-text", "A", "did:web:a.local:a1"
	db := testutil.OpenMigratedPool(t)
	buyer := testAccount(domain, "buyer", RoleBuyer, "a")
	svc, err := NewService(ServiceConfig{
		DB:          db,
		Deployment:  &ledger.Deployment{DeploymentID: deploy},
		DomainID:    domain,
		DelegateDID: delegate,
		Advisor: stubAdvisor{draft: Draft{
			ProductID:      "urn:grad:product:P1",
			Quantity:       1,
			Mode:           preg.RP,
			MaxAmountMinor: 100000,
			ExpiresAt:      time.Now().Add(time.Hour).Unix(),
			DelegateDID:    delegate,
			Description:    "Procurement demo",
		}},
	})
	require.NoError(t, err)

	for _, tc := range []struct{ name, char string }{{"CJK", "采"}, {"supplementary plane", "\U00020000"}} {
		t.Run(tc.name, func(t *testing.T) {
			_, draft, err := svc.ChatDraft(ctx, buyer.Principal, strings.Repeat(tc.char, MaxChatMessageLength), "")
			require.NoError(t, err)
			_, _, err = svc.ChatDraft(ctx, buyer.Principal, strings.Repeat(tc.char, MaxChatMessageLength+1), "")
			require.Equal(t, preg.ErrCodeInvalidSchema, protocol.CodeOf(err))

			draft.Description = strings.Repeat(tc.char, MaxDraftDescriptionLength)
			updated, err := svc.UpdateDraft(ctx, buyer.SubjectID, draft)
			require.NoError(t, err)
			require.Equal(t, draft.Description, updated.Description)
			require.Equal(t, int64(2), updated.Version)

			updated.Description += tc.char
			_, err = svc.UpdateDraft(ctx, buyer.SubjectID, updated)
			require.Equal(t, preg.ErrCodeInvalidSchema, protocol.CodeOf(err))
		})
	}
}

func TestProcurementConfirmAndRestartPreserveRunAndOriginalOperation(t *testing.T) {
	ctx := t.Context()
	db := testutil.OpenMigratedPool(t)
	const deploy, domain, delegate = "procurement-test", "A", "did:web:a.local:a1"
	buyer := testAccount(domain, "buyer", RoleBuyer, "a")
	other := testAccount(domain, "other", RoleBuyer, "b")
	initDraft := Draft{
		ProductID:      "urn:grad:product:P1",
		Quantity:       1,
		Mode:           preg.RP,
		MaxAmountMinor: 100000,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
		DelegateDID:    delegate,
		Description:    "Procurement demo",
	}

	var lastStage string
	var dispatch StageResult
	var liveTraces []ToolTrace
	rootDelivered := false

	peers := &stubPeerClient{
		getDispatchFn: func(_ context.Context, _ string) (DispatchStatusView, error) {
			if liveTraces == nil {
				return DispatchStatusView{}, errors.New("dispatcher unavailable")
			}
			return DispatchStatusView{Traces: liveTraces}, nil
		},
	}

	newSvc := func(regSvc *domreg.Service) *Service {
		svc, err := NewService(ServiceConfig{
			DB:          db,
			Deployment:  &ledger.Deployment{DeploymentID: deploy},
			DomainID:    domain,
			DelegateDID: delegate,
			Management:  regSvc,
			Advisor:     stubAdvisor{draft: initDraft},
			Peers:       peers,
		})
		require.NoError(t, err)
		svc.advanceOverride = func(ctx context.Context, owner string, run Run) (StageResult, error) {
			if owner != buyer.SubjectID {
				return StageResult{}, errors.New("unexpected run owner")
			}
			lastStage = run.Stage
			switch run.Stage {
			case StageTask:
				spec := run.Task.TaskSpec()
				digest, err := spec.Digest()
				if err != nil {
					return StageResult{}, err
				}
				op, err := regSvc.Submit(ctx, buyer.Management, "RegisterTask", run.RunID+"/task", preg.Task{
					Bound:    preg.Bound{DeploymentID: deploy},
					ID:       run.TaskID,
					Creator:  owner,
					Domain:   domain,
					Mode:     run.Task.Mode,
					Digest:   digest,
					Interval: preg.Interval{NBF: run.ConfirmedAt, EXP: run.Task.ExpiresAt},
				})
				return StageResult{Operation: op}, err
			case StageRoot:
				if rootDelivered {
					return StageResult{Status: "DELIVERED", GrantID: run.GrantID("G0")}, nil
				}
				return StageResult{Status: RunPending, GrantID: run.GrantID("G0")}, nil
			case StageDelegation:
				return StageResult{Status: "DELIVERED", GrantID: run.GrantID("G1")}, nil
			case StageDispatch:
				return dispatch, nil
			default:
				return StageResult{}, errors.New("unexpected stage")
			}
		}
		return svc
	}

	regSvc := domreg.NewService(db, deploy, preg.Management{}, nil)
	svc := newSvc(regSvc)

	reply, initial, err := svc.ChatDraft(ctx, buyer.Principal, "please draft a purchase", "")
	require.NoError(t, err)
	require.NotEmpty(t, reply)
	require.True(t, preg.IsDigest(initial.DraftID))
	require.Equal(t, int64(1), initial.Version)

	changed := initial
	changed.Quantity = 2
	changed.Mode = preg.BM
	changed, err = svc.UpdateDraft(ctx, buyer.SubjectID, changed)
	require.NoError(t, err)
	require.Equal(t, int64(2), changed.Version)

	_, err = svc.ConfirmDraft(ctx, buyer.SubjectID, initial.DraftID, 1)
	require.ErrorIs(t, err, ErrDraftVersionConflict)
	_, err = svc.ConfirmDraft(ctx, other.SubjectID, initial.DraftID, 2)
	require.ErrorIs(t, err, ErrNotFound)

	require.NoError(t, svc.ProcessPending(ctx))
	require.Empty(t, lastStage, "unconfirmed draft must not execute")
	var runs, operations int
	require.NoError(t, db.QueryRow(ctx, "SELECT (SELECT count(*) FROM workbench_runs), (SELECT count(*) FROM operations)").Scan(&runs, &operations))
	require.Zero(t, runs)
	require.Zero(t, operations)

	// Concurrent confirmations race on the same draft version.
	const confirmations = 8
	type confirmOutcome struct {
		run Run
		err error
	}
	replies := make(chan confirmOutcome, confirmations)
	for range confirmations {
		go func() {
			r, err := svc.ConfirmDraft(ctx, buyer.SubjectID, initial.DraftID, 2)
			replies <- confirmOutcome{run: r, err: err}
		}()
	}
	first := <-replies
	require.NoError(t, first.err)
	run := first.run
	require.True(t, preg.IsDigest(run.RunID))
	require.True(t, preg.IsDigest(run.TaskID))
	require.Equal(t, changed, run.Task)
	for range confirmations - 1 {
		next := <-replies
		require.NoError(t, next.err)
		require.Equal(t, run.RunID, next.run.RunID)
		require.Equal(t, run.TaskID, next.run.TaskID)
	}
	require.NoError(t, db.QueryRow(ctx, "SELECT count(*) FROM workbench_runs").Scan(&runs))
	require.Equal(t, 1, runs)

	// Owner isolation.
	_, err = svc.GetRun(ctx, other.SubjectID, run.RunID)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = svc.GetDraft(ctx, other.SubjectID, initial.DraftID)
	require.ErrorIs(t, err, ErrNotFound)
	otherRuns, err := svc.ListRuns(ctx, other.SubjectID)
	require.NoError(t, err)
	require.Empty(t, otherRuns)

	// Advance StageTask -> PENDING with original OperationID.
	require.NoError(t, svc.ProcessPending(ctx))
	pending, err := svc.GetRun(ctx, buyer.SubjectID, run.RunID)
	require.NoError(t, err)
	require.Equal(t, StageTask, pending.Stage)
	require.Equal(t, RunPending, pending.Status)
	original := pending.Steps[len(pending.Steps)-1]
	require.Equal(t, RunPending, original.Status)
	require.NotEmpty(t, original.OperationID)

	txID := preg.Digest([]byte("original procurement registration"))
	require.NoError(t, regSvc.RecordOutcome(ctx, original.OperationID, "COMMIT", "CONFIRMED", txID, &ledger.Outcome{
		Point:        ledger.Point{Number: 14, Hash: preg.Digest([]byte("confirmed block"))},
		Code:         "VALID",
		ObservedPeer: "peer0.a.local",
	}, nil, false))

	// Restart service and resume without duplicating operation.
	restarted := newSvc(domreg.NewService(db, deploy, preg.Management{}, nil))
	require.NoError(t, restarted.ProcessPending(ctx))
	resumed, err := restarted.GetRun(ctx, buyer.SubjectID, run.RunID)
	require.NoError(t, err)
	require.Equal(t, StageRoot, resumed.Stage)
	confirmed := resumed.Steps[len(resumed.Steps)-1]
	require.Equal(t, original.OperationID, confirmed.OperationID)
	require.Equal(t, txID, confirmed.TxID)
	require.Equal(t, "VALID", confirmed.ValidationCode)
	require.NoError(t, db.QueryRow(ctx, "SELECT count(*) FROM operations").Scan(&operations))
	require.Equal(t, 1, operations)

	require.NoError(t, restarted.ProcessPending(ctx))
	waiting, err := restarted.GetRun(ctx, buyer.SubjectID, run.RunID)
	require.NoError(t, err)
	require.Equal(t, StageRoot, waiting.Stage)
	require.Equal(t, run.GrantID("G0"), waiting.Steps[len(waiting.Steps)-1].GrantID)

	rootDelivered = true
	require.NoError(t, restarted.ProcessPending(ctx))
	require.NoError(t, restarted.ProcessPending(ctx))
	require.Equal(t, StageDelegation, lastStage)

	decision := "urn:grad:decision:workbench-restart"
	action := "urn:grad:action:workbench-restart"
	dispatch = StageResult{
		Status: RunUnknown,
		Traces: []ToolTrace{{
			ToolName: "create_order",
			Step:     2,
			Output:   map[string]any{"decision": "UNKNOWN", "actionId": action},
		}},
	}
	require.NoError(t, restarted.ProcessPending(ctx))
	unknown, err := restarted.GetRun(ctx, buyer.SubjectID, run.RunID)
	require.NoError(t, err)
	require.Equal(t, StageDispatch, unknown.Stage)
	require.Equal(t, RunUnknown, unknown.Status)
	require.Equal(t, dispatch.Traces, unknown.Traces)

	dispatch.Status = RunDecided
	dispatch.Traces = append(dispatch.Traces, ToolTrace{
		ToolName: "reconcile_order",
		Output:   map[string]any{"outcome": "CREATED", "decisionId": decision},
	})
	require.NoError(t, restarted.ProcessPending(ctx))
	decided, err := restarted.GetRun(ctx, buyer.SubjectID, run.RunID)
	require.NoError(t, err)
	require.Equal(t, RunDecided, decided.Status)
	require.Equal(t, dispatch.Traces, decided.Traces)

	// Local A1 trace prepends live B1 traces, and falls back to stored B1 traces on peer outage.
	rawDelegation := ToolTrace{ToolName: "delegate_grant", Step: 1, Output: map[string]any{"grant": map[string]any{"grantId": run.GrantID("G2")}}}
	delegation := ToolTrace{ToolName: "delegate_grant", Step: 1, Output: map[string]any{"grantId": run.GrantID("G2")}}
	require.NoError(t, restarted.storeTrace(ctx, run.RunID, rawDelegation))
	liveTraces = append(dispatch.Traces, ToolTrace{
		ToolName: "request_quote",
		Output:   map[string]any{"decision": "DENY", "errorCode": preg.ErrCodeAncestorInactive},
	})
	refreshed, err := restarted.GetRun(ctx, buyer.SubjectID, run.RunID)
	require.NoError(t, err)
	require.Equal(t, append([]ToolTrace{delegation}, liveTraces...), refreshed.Traces)

	liveTraces = nil
	reloaded, err := newSvc(regSvc).GetRun(ctx, buyer.SubjectID, run.RunID)
	require.NoError(t, err)
	require.Equal(t, append([]ToolTrace{delegation}, dispatch.Traces...), reloaded.Traces)
}

func TestProcurementGrantControlsSuspendAndResume(t *testing.T) {
	ctx := t.Context()
	db := testutil.OpenMigratedPool(t)
	const deploy, domain, delegate = "control-test", "A", "did:web:a.local:a1"
	buyer := testAccount(domain, "buyer", RoleBuyer, "a")

	regSvc := domreg.NewService(db, deploy, preg.Management{}, nil)
	dep := &ledger.Deployment{
		DeploymentID: deploy,
		Bootstrap: preg.Bootstrap{
			TaskCreator: preg.TaskAuthority{Domain: domain, Subject: buyer.SubjectID, Management: buyer.Management},
		},
	}
	svc, err := NewService(ServiceConfig{
		DB:          db,
		Deployment:  dep,
		DomainID:    domain,
		DelegateDID: delegate,
		Management:  regSvc,
		Actors: map[string]GrantActor{
			"U": {
				Signer:     wallet.Signer{Actor: "U", DomainID: domain, DID: buyer.SubjectID},
				Management: buyer.Management,
			},
		},
	})
	require.NoError(t, err)

	runID := preg.Digest([]byte("control-run"))
	taskID := preg.Digest([]byte(deploy + "/workbench/" + runID))
	run := Run{
		RunID:          runID,
		TaskID:         taskID,
		Stage:          StageDispatch,
		Status:         RunDecided,
		GrantRevision:  1,
		GrantStatus:    preg.Active,
		AllowedActions: []string{"suspend"},
		Steps:          []RunStep{},
		Traces:         []ToolTrace{},
	}
	_, err = db.Exec(ctx, `INSERT INTO workbench_runs(deployment_id,domain_id,owner_id,run_id,task_id,status,body)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, deploy, domain, buyer.SubjectID, run.RunID, run.TaskID, run.Status, run)
	require.NoError(t, err)

	g1 := preg.Grant{
		Bound:    preg.Bound{DeploymentID: deploy},
		ID:       run.GrantID("G1"),
		Task:     taskID,
		Issuer:   buyer.SubjectID,
		Digest:   preg.Digest([]byte("g1-jws")),
		Version:  preg.Version{Status: preg.Active, Revision: 1},
	}
	svc.readGrantOverride = func(_ context.Context, grantID string) (preg.Grant, error) {
		if grantID != g1.ID {
			return preg.Grant{}, ErrNotFound
		}
		return g1, nil
	}

	// Submit SuspendGrant control -> PENDING, allowedActions cleared.
	suspended, err := svc.SuspendRun(ctx, buyer.SubjectID, runID, "suspend-1")
	require.NoError(t, err)
	require.Empty(t, suspended.AllowedActions)
	require.Len(t, suspended.Steps, 1)
	opID := suspended.Steps[0].OperationID
	require.NotEmpty(t, opID)

	// Reusing the same requestKey with a different method returns conflict.
	_, err = svc.ResumeRun(ctx, buyer.SubjectID, runID, "suspend-1")
	require.ErrorIs(t, err, ErrDraftVersionConflict)

	// Confirm the management operation and poll via ProcessPending.
	txID := preg.Digest([]byte("suspend-tx"))
	require.NoError(t, regSvc.RecordOutcome(ctx, opID, "COMMIT", "CONFIRMED", txID, &ledger.Outcome{
		Point:        ledger.Point{Number: 20, Hash: preg.Digest([]byte("suspend-blk"))},
		Code:         "VALID",
		ObservedPeer: "peer0.a.local",
	}, nil, false))
	require.NoError(t, svc.ProcessPending(ctx))

	afterSuspend, err := svc.GetRunRecord(ctx, buyer.SubjectID, runID)
	require.NoError(t, err)
	require.Equal(t, uint64(2), afterSuspend.GrantRevision)
	require.Equal(t, preg.Suspended, afterSuspend.GrantStatus)
	require.Equal(t, []string{"resume"}, afterSuspend.AllowedActions)

	// Resume grant with incremented revision.
	g1.Revision = 2
	g1.Status = preg.Suspended
	resumed, err := svc.ResumeRun(ctx, buyer.SubjectID, runID, "resume-1")
	require.NoError(t, err)
	resumeOpID := resumed.Steps[len(resumed.Steps)-1].OperationID
	require.NoError(t, regSvc.RecordOutcome(ctx, resumeOpID, "COMMIT", "CONFIRMED", preg.Digest([]byte("resume-tx")), &ledger.Outcome{
		Point:        ledger.Point{Number: 21, Hash: preg.Digest([]byte("resume-blk"))},
		Code:         "VALID",
		ObservedPeer: "peer0.a.local",
	}, nil, false))
	require.NoError(t, svc.ProcessPending(ctx))

	afterResume, err := svc.GetRunRecord(ctx, buyer.SubjectID, runID)
	require.NoError(t, err)
	require.Equal(t, uint64(3), afterResume.GrantRevision)
	require.Equal(t, preg.Active, afterResume.GrantStatus)
	require.Equal(t, []string{"suspend"}, afterResume.AllowedActions)
}

func TestProcurementPendingRunsRotateAcrossRestart(t *testing.T) {
	ctx := t.Context()
	db := testutil.OpenMigratedPool(t)
	const deployment, domain, owner = "pending-test", "A", "buyer"
	const batch = 50
	scheduled := time.Now().Truncate(time.Second).Add(-time.Minute)
	backlog := make([]string, 0, batch+1)
	for i := 0; i <= batch; i++ {
		run := Run{RunID: fmt.Sprintf("%064x", i), TaskID: fmt.Sprintf("task-%d", i), Stage: StageDispatch, Status: RunUnknown}
		if i == batch {
			run.Status = RunPending
		}
		_, err := db.Exec(ctx, `INSERT INTO workbench_runs(deployment_id,domain_id,owner_id,run_id,task_id,status,body,created_at,next_attempt_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8)`, deployment, domain, owner, run.RunID, run.TaskID, run.Status, run, scheduled)
		require.NoError(t, err)
		backlog = append(backlog, run.RunID)
	}
	var attempted []string
	newSvc := func() *Service {
		svc, err := NewService(ServiceConfig{
			DB:         db,
			Deployment: &ledger.Deployment{DeploymentID: deployment},
			DomainID:   domain,
		})
		require.NoError(t, err)
		svc.advanceOverride = func(_ context.Context, _ string, run Run) (StageResult, error) {
			attempted = append(attempted, run.RunID)
			if run.RunID == backlog[batch] {
				return StageResult{Status: RunDecided}, nil
			}
			return StageResult{Status: RunUnknown}, nil
		}
		return svc
	}

	require.NoError(t, newSvc().ProcessPending(ctx))
	require.Equal(t, backlog[:batch], attempted)

	attempted = nil
	restarted := newSvc()
	require.NoError(t, restarted.ProcessPending(ctx))
	require.Len(t, attempted, batch)
	require.Equal(t, backlog[batch], attempted[0])
	run, err := restarted.GetRunRecord(ctx, owner, backlog[batch])
	require.NoError(t, err)
	require.Equal(t, RunDecided, run.Status)
}

func TestDomainCEnsureSupplierContextAndReadWorkbenchTask(t *testing.T) {
	ctx := t.Context()
	db := testutil.OpenMigratedPool(t)
	now := time.Now().UTC().Truncate(time.Second)
	const deploy = "ctx-test"
	buyerDID := "did:web:a.local:u"
	dep := &ledger.Deployment{
		DeploymentID: deploy,
		Bootstrap: preg.Bootstrap{
			TaskCreator: preg.TaskAuthority{Domain: "A", Subject: buyerDID},
		},
	}
	svc, err := NewService(ServiceConfig{
		DB:         db,
		Deployment: dep,
		DomainID:   "C",
		Now:        func() time.Time { return now },
	})
	require.NoError(t, err)

	taskID := preg.Digest([]byte("confirmed-task"))
	task := preg.Task{
		Bound:    preg.Bound{DeploymentID: deploy},
		ID:       taskID,
		Creator:  buyerDID,
		Domain:   "A",
		Version:  preg.Version{Status: preg.Active, Revision: 1},
		Interval: preg.Interval{NBF: now.Add(-time.Minute).Unix(), EXP: now.Add(time.Hour).Unix()},
	}
	svc.readTaskOverride = func(_ context.Context, id string) (preg.Task, error) {
		if id != taskID {
			return preg.Task{}, ErrNotFound
		}
		return task, nil
	}

	got, err := svc.ReadWorkbenchTask(ctx, taskID)
	require.NoError(t, err)
	require.Equal(t, task, got)

	_, err = svc.ReadWorkbenchTask(ctx, "not-a-digest")
	require.Equal(t, preg.ErrCodeInvalidSchema, protocol.CodeOf(err))

	var called bool
	err = svc.EnsureSupplierContext(ctx, taskID, func(_ context.Context, id string, expectedVersion int64, risk string, deadline int64) error {
		called = true
		require.Equal(t, taskID, id)
		require.Zero(t, expectedVersion)
		require.Equal(t, "NORMAL", risk)
		require.Equal(t, task.EXP, deadline)
		return nil
	})
	require.NoError(t, err)
	require.True(t, called)

	// If updater reports a conflict because trusted_contexts already exists, EnsureSupplierContext succeeds idempotently.
	_, err = db.Exec(ctx, `INSERT INTO trusted_contexts(deployment_id, task_id, source_id, context_version, observed_at, risk_level, access_deadline)
		VALUES($1,$2,'C-workbench-demo-environment',1,$3,'NORMAL',$4)`, deploy, taskID, now.Unix(), task.EXP)
	require.NoError(t, err)
	err = svc.EnsureSupplierContext(ctx, taskID, func(context.Context, string, int64, string, int64) error {
		return errors.New("already exists")
	})
	require.NoError(t, err)
}
