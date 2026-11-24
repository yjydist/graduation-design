//go:build db

package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/stretchr/testify/require"

	"grad/platform/agent"
	"grad/platform/internal/testutil"
	"grad/platform/registrysvc"
	"grad/platform/state/fabric"
	"grad/protocol/registry"
)

func TestProcurementTextLimitsMatchOpenAPI(t *testing.T) {
	const deploy, domain, delegate = "procurement-text", "A", "did:web:a.local:a1"
	db := testutil.OpenMigratedPool(t)
	buyer := testAccount(domain, "buyer", RoleBuyer, "a")
	api := testServer(t, db, nil, deploy, domain)
	require.NoError(t, api.SeedAccounts(t.Context(), []AccountSeed{buyer}))
	executor := procurementTestExecutor{draft: Draft{
		ProductID: "urn:grad:product:P1", Quantity: 1, Mode: registry.RP, MaxAmountMinor: 100000,
		ExpiresAt: time.Now().Add(time.Hour).Unix(), DelegateDID: delegate, Description: "Procurement demo",
	}}
	api.cfg.Procurement = NewProcurement(db, deploy, domain, delegate, executor).Handlers()
	h := api.Handler()
	token := loginTestAccount(t, h, buyer)
	chatSchema := browserOpenAPISchema(t, h, "ChatInput")
	draftEditSchema := browserOpenAPISchema(t, h, "DraftEdit")
	draftSchema := browserOpenAPISchema(t, h, "Draft")

	for _, tc := range []struct{ name, char string }{{"CJK", "采"}, {"supplementary plane", "\U00020000"}} {
		t.Run(tc.name, func(t *testing.T) {
			request := func(method, path string, schema *jsonschema.Resolved, body any, valid bool) *httptest.ResponseRecorder {
				t.Helper()
				raw, err := json.Marshal(body)
				require.NoError(t, err)
				var input any
				require.NoError(t, json.Unmarshal(raw, &input))
				res := browserRequest(h, method, path, string(raw), token, "")
				if valid {
					require.NoError(t, schema.Validate(input))
					require.Equal(t, http.StatusOK, res.Code, res.Body.String())
				} else {
					require.Error(t, schema.Validate(input))
					assertError(t, res, http.StatusBadRequest, registry.ErrCodeInvalidSchema)
				}
				return res
			}

			chat := map[string]string{"message": strings.Repeat(tc.char, 4000)}
			res := request(http.MethodPost, "/chat", chatSchema, chat, true)
			var result struct{ Draft Draft }
			require.NoError(t, json.Unmarshal(res.Body.Bytes(), &result))
			chat["message"] += tc.char
			request(http.MethodPost, "/chat", chatSchema, chat, false)

			edit := result.Draft
			path := "/drafts/" + edit.DraftID
			edit.Description = strings.Repeat(tc.char, 512)
			res = request(http.MethodPut, path, draftEditSchema, edit, true)
			var stored map[string]any
			require.NoError(t, json.Unmarshal(res.Body.Bytes(), &stored))
			require.NoError(t, draftSchema.Validate(stored))
			require.Equal(t, edit.Description, stored["description"])
			edit.Version++
			edit.Description += tc.char
			request(http.MethodPut, path, draftEditSchema, edit, false)
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
		ProductID: "urn:grad:product:P1", Quantity: 1, Mode: registry.RP, MaxAmountMinor: 100000,
		ExpiresAt: time.Now().Add(time.Hour).Unix(), DelegateDID: delegate, Description: "Procurement demo",
	}
	var lastStage string
	var dispatch StageResult
	var liveTraces []agent.ToolTrace
	rootDelivered := false
	executor := func(service *registrysvc.Service) procurementTestExecutor {
		return procurementTestExecutor{
			draft: initDraft,
			dispatchTraces: func(_ context.Context, _ Run) ([]agent.ToolTrace, error) {
				if liveTraces == nil {
					return nil, errors.New("dispatcher unavailable")
				}
				return liveTraces, nil
			},
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
	action := "urn:grad:action:workbench-restart"
	dispatch = StageResult{Status: RunUnknown, Traces: []agent.ToolTrace{{
		ToolName: "create_order", Step: 2, Output: map[string]any{"decision": "UNKNOWN", "actionId": action},
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

	delegation := agent.ToolTrace{ToolName: "delegate_grant", Step: 1, Output: map[string]any{"grantId": run.GrantID("G2")}}
	_, err = db.Exec(ctx, `INSERT INTO workbench_tool_trace(deployment_id,domain_id,run_id,body)
		VALUES($1,$2,$3,$4)`, deploy, domain, run.RunID, delegation)
	require.NoError(t, err)
	liveTraces = append(dispatch.Traces, agent.ToolTrace{
		ToolName: "request_quote", Output: map[string]any{"decision": "DENY", "errorCode": registry.ErrCodeAncestorInactive},
	})
	resp = browserRequest(h, http.MethodGet, runPath, "", token, "")
	refreshed := readProcurementRun(t, resp, http.StatusOK)
	require.Equal(t, RunDecided, refreshed.Status)
	require.Equal(t, append([]agent.ToolTrace{delegation}, liveTraces...), refreshed.Traces)
	schema := browserOpenAPISchema(t, h, "Run")
	var body any
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.NoError(t, schema.Validate(body))

	// A fresh handler still returns the stored references while B is unavailable.
	liveTraces = nil
	api.cfg.Procurement = NewProcurement(db, deploy, domain, delegate, executor(service)).Handlers()
	reloaded := readProcurementRun(t, browserRequest(api.Handler(), http.MethodGet, runPath, "", token, ""), http.StatusOK)
	require.Equal(t, append([]agent.ToolTrace{delegation}, dispatch.Traces...), reloaded.Traces)
}

func browserOpenAPISchema(t *testing.T, h http.Handler, name string) *jsonschema.Resolved {
	t.Helper()
	doc := browserRequest(h, http.MethodGet, "/openapi.json", "", browserToken{}, "")
	require.Equal(t, http.StatusOK, doc.Code)
	var contract struct {
		Components struct {
			Schemas json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	require.NoError(t, json.Unmarshal(doc.Body.Bytes(), &contract))
	// Expose the OpenAPI components as JSON Schema definitions for validation.
	raw := bytes.ReplaceAll(contract.Components.Schemas, []byte(`"#/components/schemas/`), []byte(`"#/$defs/`))
	var schemas map[string]*jsonschema.Schema
	require.NoError(t, json.Unmarshal(raw, &schemas))
	schema, err := (&jsonschema.Schema{Defs: schemas, Ref: "#/$defs/" + name}).Resolve(nil)
	require.NoError(t, err)
	return schema
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
	executor := procurementTestExecutor{advance: func(_ context.Context, _ string, run Run) (StageResult, error) {
		attempted = append(attempted, run.RunID)
		if run.RunID == backlog[batch] {
			return StageResult{Status: RunDecided}, nil
		}
		return StageResult{Status: RunUnknown}, nil
	}}
	require.NoError(t, NewProcurement(db, deployment, domain, "", executor).ProcessPending(ctx))
	require.Equal(t, backlog[:batch], attempted)

	attempted = nil
	restarted := NewProcurement(db, deployment, domain, "", executor)
	require.NoError(t, restarted.ProcessPending(ctx))
	require.Len(t, attempted, batch)
	require.Equal(t, backlog[batch], attempted[0])
	run, err := restarted.readRun(ctx, db, owner, backlog[batch])
	require.NoError(t, err)
	require.Equal(t, RunDecided, run.Status)
}

func readProcurementRun(t *testing.T, response *httptest.ResponseRecorder, status int) Run {
	t.Helper()
	require.Equal(t, status, response.Code, response.Body.String())
	var run Run
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &run))
	return run
}

type procurementTestExecutor struct {
	draft          Draft
	advance        func(context.Context, string, Run) (StageResult, error)
	dispatchTraces func(context.Context, Run) ([]agent.ToolTrace, error)
}

func (e procurementTestExecutor) Suggest(context.Context, string, *Draft) (Draft, string, error) {
	return e.draft, "Drafted procurement terms", nil
}

func (e procurementTestExecutor) Advance(ctx context.Context, owner string, run Run) (StageResult, error) {
	return e.advance(ctx, owner, run)
}

func (e procurementTestExecutor) DispatchTraces(ctx context.Context, run Run) ([]agent.ToolTrace, error) {
	return e.dispatchTraces(ctx, run)
}

func (procurementTestExecutor) GrantMutation(context.Context, Run) (registry.Mutation, error) {
	return registry.Mutation{}, errors.New("unexpected grant mutation")
}

func (procurementTestExecutor) Control(context.Context, string, string, string, registry.Mutation) (*registrysvc.OperationView, error) {
	return nil, errors.New("unexpected grant control")
}
