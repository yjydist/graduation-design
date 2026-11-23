//go:build db

package workbench

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"grad/platform/agent"
	"grad/platform/internal/testutil"
	"grad/platform/registrysvc"
	"grad/platform/state/fabric"
	"grad/protocol/registry"
)

func TestProcurementConfirmAndRestartPreserveRunAndOriginalOperation(t *testing.T) {
	ctx := t.Context()
	db := testutil.OpenMigratedPool(t)
	const deploy, domain, delegate = "procurement-test", "A", "did:web:a.local:a1"
	buyer := testAccount(domain, "buyer", RoleBuyer, "a")
	other := testAccount(domain, "other", RoleBuyer, "b")
	initDraft := Draft{
		ProductID: "urn:grad:product:P1", Quantity: 1, Mode: registry.RP, MaxAmountMinor: 100000,
		ExpiresAt: time.Now().Add(time.Hour).Unix(), DelegateDID: delegate, Description: "Procurement demo",
	}
	var lastStage string
	var dispatch StageResult
	rootDelivered := false
	executor := func(service *registrysvc.Service) procurementTestExecutor {
		return procurementTestExecutor{
			draft: initDraft,
			advance: func(ctx context.Context, owner string, run Run) (StageResult, error) {
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
					op, err := service.Submit(ctx, buyer.Management, "RegisterTask", run.RunID+"/task", registry.Task{
						Bound: registry.Bound{DeploymentID: deploy}, ID: run.TaskID, Creator: owner, Domain: domain,
						Mode: run.Task.Mode, Digest: digest, Interval: registry.Interval{NBF: run.ConfirmedAt, EXP: run.Task.ExpiresAt},
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
			},
		}
	}
	service := registrysvc.NewService(db, deploy, registry.Management{}, nil)
	api := testServer(t, db, nil, deploy, domain)
	require.NoError(t, api.SeedAccounts(ctx, []AccountSeed{buyer, other}))
	p := NewProcurement(db, deploy, domain, delegate, executor(service))
	api.cfg.Procurement = p.Handlers()
	h := api.Handler()
	token := loginTestAccount(t, h, buyer)
	otherToken := loginTestAccount(t, h, other)

	resp := browserRequest(h, http.MethodPost, "/chat", `{"message":"please draft a purchase"}`, token, "")
	var initial struct {
		Reply string `json:"reply"`
		Draft Draft  `json:"draft"`
	}
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &initial))
	require.NotEmpty(t, initial.Reply)
	require.True(t, registry.IsDigest(initial.Draft.DraftID))
	require.Equal(t, int64(1), initial.Draft.Version)
	draftPath := "/drafts/" + initial.Draft.DraftID

	changed := initial.Draft
	changed.Quantity = 2
	changed.Mode = registry.BM
	input, err := json.Marshal(changed)
	require.NoError(t, err)
	resp = browserRequest(h, http.MethodPut, draftPath, string(input), token, "")
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &changed))
	require.Equal(t, int64(2), changed.Version)

	resp = browserRequest(h, http.MethodPost, draftPath+"/confirm", `{"version":1}`, token, "")
	assertError(t, resp, http.StatusConflict, "DRAFT_VERSION_CONFLICT")
	resp = browserRequest(h, http.MethodPost, draftPath+"/confirm", `{"version":2}`, otherToken, "")
	assertError(t, resp, http.StatusNotFound, "NOT_FOUND")
	require.NoError(t, p.ProcessPending(ctx))
	require.Empty(t, lastStage, "unconfirmed draft must not execute")
	var runs, operations int
	require.NoError(t, db.QueryRow(ctx, "SELECT (SELECT count(*) FROM workbench_runs), (SELECT count(*) FROM operations)").Scan(&runs, &operations))
	require.Zero(t, runs)
	require.Zero(t, operations)

	// Concurrent browser confirmations race on the same stored draft version.
	const confirmations = 8
	replies := make(chan *httptest.ResponseRecorder, confirmations)
	for range confirmations {
		go func() {
			replies <- browserRequest(h, http.MethodPost, draftPath+"/confirm", `{"version":2}`, token, "")
		}()
	}
	run := readProcurementRun(t, <-replies, http.StatusAccepted)
	require.True(t, registry.IsDigest(run.RunID))
	require.True(t, registry.IsDigest(run.TaskID))
	require.Equal(t, changed, run.Task)
	for range confirmations - 1 {
		repeated := readProcurementRun(t, <-replies, http.StatusAccepted)
		require.Equal(t, run.RunID, repeated.RunID)
		require.Equal(t, run.TaskID, repeated.TaskID)
	}
	require.NoError(t, db.QueryRow(ctx, "SELECT count(*) FROM workbench_runs").Scan(&runs))
	require.Equal(t, 1, runs)
	runPath := "/runs/" + run.RunID
	assertError(t, browserRequest(h, http.MethodGet, runPath, "", otherToken, ""), http.StatusNotFound, "NOT_FOUND")
	assertError(t, browserRequest(h, http.MethodGet, draftPath, "", otherToken, ""), http.StatusNotFound, "NOT_FOUND")
	resp = browserRequest(h, http.MethodGet, "/runs", "", otherToken, "")
	require.Equal(t, http.StatusOK, resp.Code)
	require.JSONEq(t, `{"runs":[]}`, resp.Body.String())

	require.NoError(t, p.ProcessPending(ctx))
	pending := readProcurementRun(t, browserRequest(h, http.MethodGet, runPath, "", token, ""), http.StatusOK)
	require.Equal(t, StageTask, pending.Stage)
	require.Equal(t, RunPending, pending.Status)
	original := pending.Steps[len(pending.Steps)-1]
	require.Equal(t, RunPending, original.Status)
	require.NotEmpty(t, original.OperationID)

	txID := registry.Digest([]byte("original procurement registration"))
	require.NoError(t, service.RecordOutcome(ctx, original.OperationID, "COMMIT", "CONFIRMED", txID, &fabric.Outcome{
		Point: fabric.Point{Number: 14, Hash: registry.Digest([]byte("confirmed block"))}, Code: "VALID", ObservedPeer: "peer0.a.local",
	}, nil, false))

	restarted := NewProcurement(db, deploy, domain, delegate, executor(registrysvc.NewService(db, deploy, registry.Management{}, nil)))
	api.cfg.Procurement = restarted.Handlers()
	h = api.Handler()
	require.NoError(t, restarted.ProcessPending(ctx))
	resumed := readProcurementRun(t, browserRequest(h, http.MethodGet, runPath, "", token, ""), http.StatusOK)
	require.Equal(t, StageRoot, resumed.Stage)
	require.Equal(t, run.TaskID, resumed.TaskID)
	confirmed := resumed.Steps[len(resumed.Steps)-1]
	require.Equal(t, original.OperationID, confirmed.OperationID)
	require.Equal(t, txID, confirmed.TxID)
	require.Equal(t, "VALID", confirmed.ValidationCode)
	require.NoError(t, db.QueryRow(ctx, "SELECT count(*) FROM operations").Scan(&operations))
	require.Equal(t, 1, operations)

	require.NoError(t, restarted.ProcessPending(ctx))
	waiting := readProcurementRun(t, browserRequest(h, http.MethodGet, runPath, "", token, ""), http.StatusOK)
	require.Equal(t, StageRoot, waiting.Stage)
	require.Equal(t, RunPending, waiting.Status)
	require.Equal(t, run.GrantID("G0"), waiting.Steps[len(waiting.Steps)-1].GrantID)
	rootDelivered = true
	require.NoError(t, restarted.ProcessPending(ctx))
	require.NoError(t, restarted.ProcessPending(ctx))
	require.Equal(t, StageDelegation, lastStage)

	decision := "urn:grad:decision:workbench-restart"
	dispatch = StageResult{Status: RunUnknown, Traces: []agent.ToolTrace{{
		ToolName: "create_order", Output: map[string]any{"decision": "UNKNOWN", "decisionId": decision},
	}}}
	require.NoError(t, restarted.ProcessPending(ctx))
	unknown := readProcurementRun(t, browserRequest(h, http.MethodGet, runPath, "", token, ""), http.StatusOK)
	require.Equal(t, StageDispatch, unknown.Stage)
	require.Equal(t, RunUnknown, unknown.Status)
	require.Equal(t, dispatch.Traces, unknown.Traces)

	dispatch.Status = RunDecided
	dispatch.Traces = append(dispatch.Traces, agent.ToolTrace{
		ToolName: "reconcile_order", Output: map[string]any{"outcome": "CREATED", "decisionId": decision},
	})
	require.NoError(t, restarted.ProcessPending(ctx))
	decided := readProcurementRun(t, browserRequest(h, http.MethodGet, runPath, "", token, ""), http.StatusOK)
	require.Equal(t, RunDecided, decided.Status)
	require.Equal(t, dispatch.Traces, decided.Traces)
}

func readProcurementRun(t *testing.T, response *httptest.ResponseRecorder, status int) Run {
	t.Helper()
	require.Equal(t, status, response.Code, response.Body.String())
	var run Run
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &run))
	return run
}

type procurementTestExecutor struct {
	draft   Draft
	advance func(context.Context, string, Run) (StageResult, error)
}

func (e procurementTestExecutor) Suggest(context.Context, string, *Draft) (Draft, string, error) {
	return e.draft, "Drafted procurement terms", nil
}

func (e procurementTestExecutor) Advance(ctx context.Context, owner string, run Run) (StageResult, error) {
	return e.advance(ctx, owner, run)
}

func (procurementTestExecutor) GrantMutation(context.Context, Run) (registry.Mutation, error) {
	return registry.Mutation{}, errors.New("unexpected grant mutation")
}

func (procurementTestExecutor) Control(context.Context, string, string, string, registry.Mutation) (*registrysvc.OperationView, error) {
	return nil, errors.New("unexpected grant control")
}
