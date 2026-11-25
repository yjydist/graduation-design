//go:build db

package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"grad/platform/core/domain/evidence"
	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/domain/procurement"
	domreg "grad/platform/core/domain/registry"
	"grad/platform/core/ledger"
	"grad/platform/internal/testutil"
	preg "grad/protocol/registry"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

func TestBrowserSessionsAndLocalManagement(t *testing.T) {
	ctx := t.Context()
	db := testutil.OpenMigratedPool(t)
	backend := &testManagementBackend{}

	sa, sessA, authA := testServer(t, db, backend, "dep-1", "A")
	sb, sessB, _ := testServer(t, db, backend, "dep-1", "B")
	sc, sessC, _ := testServer(t, db, backend, "dep-1", "C")

	a := testAccount("A", "admin", procurement.RoleAdmin, "a")
	b := testAccount("B", "admin", procurement.RoleAdmin, "b")
	c := testAccount("C", "admin", procurement.RoleAdmin, "c")
	u := testAccount("A", "buyer", procurement.RoleBuyer, "d")
	caudit := procurement.AccountSeed{Principal: c.Principal, Username: "audit", Password: c.Password}
	caudit.Role = procurement.RoleAuditor

	require.NoError(t, sessA.SeedAccounts(ctx, []procurement.AccountSeed{a, u}))
	require.NoError(t, sessB.SeedAccounts(ctx, []procurement.AccountSeed{b}))
	require.NoError(t, sessC.SeedAccounts(ctx, []procurement.AccountSeed{c, caudit}))

	const management = "/management/purchasing-authority"
	type adminRun struct {
		server  *Server
		account procurement.AccountSeed
	}
	var operations []string
	var aToken browserToken
	for _, admin := range []adminRun{{sa, a}, {sb, b}, {sc, c}} {
		server, account := admin.server, admin.account
		h := server.Handler()
		token := loginTestAccount(t, h, account)
		if account.DomainID == "A" {
			aToken = token
		}
		res := browserRequest(h, "GET", "/health/ready", "", browserToken{}, "")
		require.JSONEq(t, `{"domainId":"`+account.DomainID+`","ready":true}`, res.Body.String())
		res = browserRequest(h, "GET", management, "", token, "")
		require.Equal(t, http.StatusOK, res.Code)
		var qualification procurement.PurchasingAuthority
		require.NoError(t, json.Unmarshal(res.Body.Bytes(), &qualification))
		require.Equal(t, account.DomainID, qualification.DomainID)
		require.Len(t, qualification.EligibleServiceIDs, 1)

		update := `{"expectedRevision":2,"purchasingAuthority":"` + qualification.EligibleServiceIDs[0] + `"}`
		res = browserRequest(h, "POST", management, update, browserToken{cookie: token.cookie}, "update")
		assertError(t, res, http.StatusForbidden, "CSRF_INVALID")
		res = browserRequest(h, "POST", management, `{"expectedRevision":2,"purchasingAuthority":null,"domainId":"C"}`, token, "update")
		assertError(t, res, http.StatusBadRequest, preg.ErrCodeInvalidSchema)
		res = browserRequest(h, "POST", management, `{"expectedRevision":1,"purchasingAuthority":null}`, token, "stale")
		assertError(t, res, http.StatusConflict, preg.ErrCodeStateChanged)
		res = browserRequest(h, "POST", management, `{"expectedRevision":2,"purchasingAuthority":"did:web:foreign.local:pa"}`, token, "foreign")
		assertError(t, res, http.StatusForbidden, preg.ErrCodePurchasingAuthorityInvalid)

		res = browserRequest(h, "POST", management, update, token, "update")
		op := decodeBrowserOperation(t, res, http.StatusAccepted)
		require.Equal(t, "PENDING", op.Status)
		require.Nil(t, op.TxID)
		operations = append(operations, op.OperationID)

		res = browserRequest(h, "POST", management, update, token, "update")
		require.Equal(t, op.OperationID, decodeBrowserOperation(t, res, http.StatusAccepted).OperationID)
		res = browserRequest(h, "POST", management, `{"expectedRevision":2,"purchasingAuthority":null}`, token, "update")
		assertError(t, res, http.StatusConflict, preg.ErrCodeIdempotencyConflict)

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			res := browserRequest(h, "GET", "/operations/"+op.OperationID, "", token, "")
			if !assert.Equal(ct, http.StatusOK, res.Code) {
				return
			}
			var result browserOperation
			if assert.NoError(ct, json.Unmarshal(res.Body.Bytes(), &result)) && assert.Equal(ct, "CONFIRMED", result.Status) {
				assert.NotNil(ct, result.TxID)
				assert.NotNil(ct, result.BlockNumber)
				if assert.NotNil(ct, result.ValidationCode) {
					assert.Equal(ct, "VALID", *result.ValidationCode)
				}
			}
		}, 2*time.Second, 10*time.Millisecond)
	}
	require.Equal(t, int32(3), backend.submissionCount.Load())

	h := sa.Handler()
	buyerToken := loginTestAccount(t, h, u)
	res := browserRequest(h, "POST", management, `{"expectedRevision":2,"purchasingAuthority":null}`, buyerToken, "forged")
	assertError(t, res, http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden)
	// Without Procurement configured, buyer routes fail closed with 503 STATE_UNAVAILABLE.
	res = browserRequest(h, "GET", "/runs", "", buyerToken, "")
	assertError(t, res, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable)
	res = browserRequest(h, "GET", "/runs/some-run/evidence", "", buyerToken, "")
	assertError(t, res, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable)
	// Without Evidence/Gateway configured, decision lookup returns 404 NOT_FOUND.
	res = browserRequest(h, "GET", "/decisions/dec-unknown", "", buyerToken, "")
	assertError(t, res, http.StatusNotFound, "NOT_FOUND")

	res = browserRequest(h, "GET", "/operations/"+operations[0], "", buyerToken, "")
	assertError(t, res, http.StatusNotFound, preg.ErrCodeOperationUnknown)
	res = browserRequest(h, "GET", "/operations/"+operations[1], "", aToken, "")
	assertError(t, res, http.StatusNotFound, preg.ErrCodeOperationUnknown)
	require.Equal(t, int32(3), backend.submissionCount.Load())

	var operationCount int
	require.NoError(t, db.QueryRow(ctx, `SELECT COUNT(*) FROM operations WHERE deployment_id='dep-1'`).Scan(&operationCount))
	require.Equal(t, 3, operationCount)

	res = browserRequest(h, "POST", management, `{"expectedRevision":2,"purchasingAuthority":"did:web:a.local:pa"}`, aToken, "reject-endorsement")
	failed := decodeBrowserOperation(t, res, http.StatusAccepted)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		res := browserRequest(h, "GET", "/operations/"+failed.OperationID, "", aToken, "")
		if !assert.Equal(ct, http.StatusOK, res.Code) {
			return
		}
		var result browserOperation
		if assert.NoError(ct, json.Unmarshal(res.Body.Bytes(), &result)) && assert.Equal(ct, "FAILED", result.Status) {
			if assert.NotNil(ct, result.FailureCode) {
				assert.Equal(ct, preg.ErrCodeEndorsementRejected, *result.FailureCode)
			}
			assert.Nil(ct, result.BlockNumber)
			assert.Nil(ct, result.ValidationCode)
		}
	}, 2*time.Second, 10*time.Millisecond)

	wrongCookie := *aToken.cookie
	wrongCookie.Name = sb.cookieName()
	res = browserRequest(sb.Handler(), "GET", "/session", "", browserToken{cookie: &wrongCookie}, "")
	assertError(t, res, http.StatusUnauthorized, "SESSION_REQUIRED")
	otherDeployment, _, _ := testServer(t, db, backend, "dep-2", "A")
	res = browserRequest(otherDeployment.Handler(), "GET", "/session", "", aToken, "")
	assertError(t, res, http.StatusUnauthorized, "SESSION_REQUIRED")

	restarted, restartedSess, _ := testServer(t, db, backend, "dep-1", "A")
	require.NoError(t, restartedSess.SeedAccounts(ctx, []procurement.AccountSeed{a, u}))
	res = browserRequest(restarted.Handler(), "GET", "/session", "", buyerToken, "")
	require.Equal(t, http.StatusOK, res.Code)
	res = browserRequest(h, "POST", "/session/logout", "", browserToken{cookie: buyerToken.cookie}, "")
	assertError(t, res, http.StatusForbidden, "CSRF_INVALID")

	// Revoking principal authority blocks GET /session (403) while still allowing POST /session/logout (204).
	authA.verifyErr = preg.NewError(preg.ErrCodeIdentityManagementForbidden, "revoked")
	res = browserRequest(sa.Handler(), "GET", "/session", "", buyerToken, "")
	assertError(t, res, http.StatusForbidden, preg.ErrCodeIdentityManagementForbidden)
	res = browserRequest(sa.Handler(), "POST", "/session/logout", "", buyerToken, "")
	require.Equal(t, http.StatusNoContent, res.Code)
	require.Equal(t, -1, res.Result().Cookies()[0].MaxAge)
	authA.verifyErr = nil
	res = browserRequest(restarted.Handler(), "GET", "/session", "", buyerToken, "")
	assertError(t, res, http.StatusUnauthorized, "SESSION_REQUIRED")

	oldAudit := loginTestAccount(t, sc.Handler(), caudit)
	require.NoError(t, sessC.SeedAccounts(ctx, []procurement.AccountSeed{c}))
	res = browserRequest(sc.Handler(), "GET", "/session", "", oldAudit, "")
	assertError(t, res, http.StatusUnauthorized, "SESSION_REQUIRED")

	a.Password = "updated-example-password"
	require.NoError(t, restartedSess.SeedAccounts(ctx, []procurement.AccountSeed{a, u}))
	res = browserRequest(restarted.Handler(), "GET", "/session", "", aToken, "")
	assertError(t, res, http.StatusUnauthorized, "SESSION_REQUIRED")
	loginTestAccount(t, restarted.Handler(), a)
	var hash []byte
	require.NoError(t, db.QueryRow(ctx, `SELECT password_hash FROM workbench_accounts WHERE deployment_id='dep-1' AND domain_id='A' AND username='admin'`).Scan(&hash))
	require.NoError(t, bcrypt.CompareHashAndPassword(hash, []byte(a.Password)))
}

func TestProcurementTextLimitsMatchOpenAPI(t *testing.T) {
	ctx := t.Context()
	const deploy, domain, delegate = "procurement-text", "A", "did:web:a.local:a1"
	db := testutil.OpenMigratedPool(t)
	buyer := testAccount(domain, "buyer", procurement.RoleBuyer, "a")

	api, sess, _ := testServer(t, db, nil, deploy, domain)
	require.NoError(t, sess.SeedAccounts(ctx, []procurement.AccountSeed{buyer}))
	procSvc, err := procurement.NewService(procurement.ServiceConfig{
		DB:          db,
		Deployment:  &ledger.Deployment{DeploymentID: deploy},
		DomainID:    domain,
		DelegateDID: delegate,
		Advisor: stubAdvisor{draft: procurement.Draft{
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
	api.cfg.Procurement = procSvc

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
					assertError(t, res, http.StatusBadRequest, preg.ErrCodeInvalidSchema)
				}
				return res
			}

			chat := map[string]string{"message": strings.Repeat(tc.char, 4000)}
			res := request(http.MethodPost, "/chat", chatSchema, chat, true)
			var result struct{ Draft procurement.Draft }
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

func TestProcurementAndEvidenceEndpoints(t *testing.T) {
	ctx := t.Context()
	db := testutil.OpenMigratedPool(t)
	const deploy, domain, delegate = "procurement-http", "A", "did:web:a.local:a1"
	buyer := testAccount(domain, "buyer", procurement.RoleBuyer, "a")
	other := testAccount(domain, "other", procurement.RoleBuyer, "b")

	initDraft := procurement.Draft{
		ProductID:      "urn:grad:product:P1",
		Quantity:       1,
		Mode:           preg.RP,
		MaxAmountMinor: 100000,
		ExpiresAt:      time.Now().Add(time.Hour).Unix(),
		DelegateDID:    delegate,
		Description:    "Procurement demo",
	}

	var liveTraces []procurement.ToolTrace
	peers := &stubPeerClient{
		getDispatchFn: func(_ context.Context, _ string) (procurement.DispatchStatusView, error) {
			if liveTraces == nil {
				return procurement.DispatchStatusView{}, errors.New("dispatcher unavailable")
			}
			return procurement.DispatchStatusView{Traces: liveTraces}, nil
		},
	}

	procSvc, err := procurement.NewService(procurement.ServiceConfig{
		DB:          db,
		Deployment:  &ledger.Deployment{DeploymentID: deploy},
		DomainID:    domain,
		DelegateDID: delegate,
		Advisor:     stubAdvisor{draft: initDraft},
		Peers:       peers,
	})
	require.NoError(t, err)

	evSvc := evidence.NewService(evidence.Config{
		Procurement: procSvc,
		ReadGrant: func(_ context.Context, _ string) (preg.Grant, error) {
			return preg.Grant{}, evidence.ErrNotFound
		},
		Peers: stubPeerEvidence{
			taskEvidence: domgw.TaskEvidence{
				Identity:    []domgw.IdentityEvidence{},
				Disclosures: []domgw.DisclosureEvidence{},
				Decisions:   []domgw.DecisionSummary{},
				Quotes:      []domgw.QuotePayload{},
				Orders:      []domgw.OrderPayload{},
			},
		},
	})

	api, sess, _ := testServer(t, db, nil, deploy, domain)
	api.cfg.Procurement = procSvc
	api.cfg.Evidence = evSvc
	require.NoError(t, sess.SeedAccounts(ctx, []procurement.AccountSeed{buyer, other}))

	h := api.Handler()
	token := loginTestAccount(t, h, buyer)
	otherToken := loginTestAccount(t, h, other)

	// POST /chat -> creates draft v1
	resp := browserRequest(h, http.MethodPost, "/chat", `{"message":"please draft a purchase"}`, token, "")
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	var initial struct {
		Reply string            `json:"reply"`
		Draft procurement.Draft `json:"draft"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &initial))
	require.NotEmpty(t, initial.Reply)
	require.True(t, preg.IsDigest(initial.Draft.DraftID))
	require.Equal(t, int64(1), initial.Draft.Version)
	draftPath := "/drafts/" + initial.Draft.DraftID

	// GET /drafts/{draftId}
	resp = browserRequest(h, http.MethodGet, draftPath, "", token, "")
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assertError(t, browserRequest(h, http.MethodGet, draftPath, "", otherToken, ""), http.StatusNotFound, "NOT_FOUND")

	// PUT /drafts/{draftId}: mismatched body draftId -> 400
	badDraft := initial.Draft
	badDraft.DraftID = "other-id"
	badRaw, err := json.Marshal(badDraft)
	require.NoError(t, err)
	assertError(t, browserRequest(h, http.MethodPut, draftPath, string(badRaw), token, ""), http.StatusBadRequest, preg.ErrCodeInvalidSchema)

	// PUT /drafts/{draftId}: valid update -> v2
	changed := initial.Draft
	changed.Quantity = 2
	changed.Mode = preg.BM
	input, err := json.Marshal(changed)
	require.NoError(t, err)
	resp = browserRequest(h, http.MethodPut, draftPath, string(input), token, "")
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &changed))
	require.Equal(t, int64(2), changed.Version)

	// POST /drafts/{draftId}/confirm: stale version -> 409, foreign owner -> 404
	assertError(t, browserRequest(h, http.MethodPost, draftPath+"/confirm", `{"version":1}`, token, ""), http.StatusConflict, "DRAFT_VERSION_CONFLICT")
	assertError(t, browserRequest(h, http.MethodPost, draftPath+"/confirm", `{"version":2}`, otherToken, ""), http.StatusNotFound, "NOT_FOUND")

	// Concurrent confirm race -> all return 202 with same runId/taskId
	const confirmations = 8
	replies := make(chan *httptest.ResponseRecorder, confirmations)
	for range confirmations {
		go func() {
			replies <- browserRequest(h, http.MethodPost, draftPath+"/confirm", `{"version":2}`, token, "")
		}()
	}
	run := readProcurementRun(t, <-replies, http.StatusAccepted)
	require.True(t, preg.IsDigest(run.RunID))
	require.True(t, preg.IsDigest(run.TaskID))
	require.Equal(t, changed, run.Task)
	for range confirmations - 1 {
		repeated := readProcurementRun(t, <-replies, http.StatusAccepted)
		require.Equal(t, run.RunID, repeated.RunID)
		require.Equal(t, run.TaskID, repeated.TaskID)
	}

	// GET /runs & GET /runs/{runId}
	runPath := "/runs/" + run.RunID
	assertError(t, browserRequest(h, http.MethodGet, runPath, "", otherToken, ""), http.StatusNotFound, "NOT_FOUND")
	resp = browserRequest(h, http.MethodGet, "/runs", "", otherToken, "")
	require.Equal(t, http.StatusOK, resp.Code)
	require.JSONEq(t, `{"runs":[]}`, resp.Body.String())

	resp = browserRequest(h, http.MethodGet, "/runs", "", token, "")
	require.Equal(t, http.StatusOK, resp.Code)
	var listed struct {
		Runs []procurement.Run `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &listed))
	require.Len(t, listed.Runs, 1)
	require.Equal(t, run.RunID, listed.Runs[0].RunID)

	// Local tool trace appears on GET /runs/{runId} and matches OpenAPI Run schema.
	delegation := procurement.ToolTrace{ToolName: "delegate_grant", Step: 1, Output: map[string]any{"grantId": run.GrantID("G2")}}
	_, err = db.Exec(ctx, `INSERT INTO workbench_tool_trace(deployment_id,domain_id,run_id,body) VALUES($1,$2,$3,$4)`,
		deploy, domain, run.RunID, delegation)
	require.NoError(t, err)
	resp = browserRequest(h, http.MethodGet, runPath, "", token, "")
	fetched := readProcurementRun(t, resp, http.StatusOK)
	require.Equal(t, []procurement.ToolTrace{delegation}, fetched.Traces)
	runSchema := browserOpenAPISchema(t, h, "Run")
	var runBody any
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &runBody))
	require.NoError(t, runSchema.Validate(runBody))

	// POST /runs/{runId}/suspend & /resume validation (missing Idempotency-Key -> 400, unknown run -> 404)
	assertError(t, browserRequest(h, http.MethodPost, runPath+"/suspend", "", token, ""), http.StatusBadRequest, preg.ErrCodeInvalidSchema)
	assertError(t, browserRequest(h, http.MethodPost, runPath+"/resume", "", token, ""), http.StatusBadRequest, preg.ErrCodeInvalidSchema)
	assertError(t, browserRequest(h, http.MethodPost, "/runs/missing-run/suspend", "", token, "k1"), http.StatusNotFound, "NOT_FOUND")
	assertError(t, browserRequest(h, http.MethodPost, "/runs/missing-run/resume", "", token, "k2"), http.StatusNotFound, "NOT_FOUND")

	// GET /runs/{runId}/evidence -> 200 matching OpenAPI RunEvidence schema, 404 for foreign owner
	resp = browserRequest(h, http.MethodGet, runPath+"/evidence", "", token, "")
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	evSchema := browserOpenAPISchema(t, h, "RunEvidence")
	var evBody any
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &evBody))
	require.NoError(t, evSchema.Validate(evBody))
	assertError(t, browserRequest(h, http.MethodGet, runPath+"/evidence", "", otherToken, ""), http.StatusNotFound, "NOT_FOUND")

	// GET /decisions/{decisionId} -> 404 when no gateway configured on evidence service
	assertError(t, browserRequest(h, http.MethodGet, "/decisions/dec-1", "", token, ""), http.StatusNotFound, "NOT_FOUND")
}

type stubAuthorityReader struct {
	domain    string
	verifyErr error
}

func (a *stubAuthorityReader) VerifyPrincipal(_ context.Context, principal procurement.Principal) error {
	if a.verifyErr != nil {
		return a.verifyErr
	}
	if !procurement.ValidPrincipal(principal, a.domain) {
		return preg.NewError(preg.ErrCodeIdentityManagementForbidden, "principal forbidden")
	}
	return nil
}

func (a *stubAuthorityReader) ReadPurchasingAuthority(_ context.Context, principal procurement.Principal) (procurement.PurchasingAuthority, error) {
	if principal.Role != procurement.RoleAdmin {
		return procurement.PurchasingAuthority{}, preg.NewError(preg.ErrCodeIdentityManagementForbidden, "admin required")
	}
	return procurement.PurchasingAuthority{
		DomainID:           a.domain,
		ExpectedRevision:   2,
		EligibleServiceIDs: []string{testServiceDID(a.domain)},
	}, nil
}

func (a *stubAuthorityReader) CheckPurchasingAuthority(_ context.Context, _ procurement.Principal, did string) error {
	if did != testServiceDID(a.domain) {
		return preg.Reject(preg.ErrCodePurchasingAuthorityInvalid)
	}
	return nil
}

func testServer(t *testing.T, db *pgxpool.Pool, backend domreg.OperationSubmitBackend, deployment, domain string) (*Server, *procurement.SessionService, *stubAuthorityReader) {
	t.Helper()
	auth := &stubAuthorityReader{domain: domain}
	sessions, err := procurement.NewSessionService(db, deployment, domain, auth)
	require.NoError(t, err)
	regSvc := domreg.NewService(db, deployment, preg.Management{}, backend)
	authority := procurement.NewAuthorityService(deployment, auth, regSvc)
	server, err := NewServer(Config{
		DeploymentID: deployment,
		DomainID:     domain,
		Sessions:     sessions,
		Authority:    authority,
		Ready:        func(context.Context) error { return nil },
	})
	require.NoError(t, err)
	return server, sessions, auth
}

func testServiceDID(domain string) string {
	return "did:web:" + strings.ToLower(domain) + ".local:pa"
}

func testAccount(domain, name string, role procurement.Role, hashChar string) procurement.AccountSeed {
	return procurement.AccountSeed{
		Principal: procurement.Principal{
			DomainID:  domain,
			SubjectID: "did:web:" + strings.ToLower(domain) + ".local:" + name,
			Role:      role,
			Management: preg.Management{
				MSPID:             domain + "Msp",
				CertificateSHA256: strings.Repeat(hashChar, 64),
			},
		},
		Username: name,
		Password: "example-password",
	}
}

type browserToken struct {
	cookie *http.Cookie
	csrf   string
}

func browserRequest(h http.Handler, method, path, body string, token browserToken, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://workbench.example"+apiPrefix+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token.cookie != nil {
		req.AddCookie(token.cookie)
	}
	if token.csrf != "" {
		req.Header.Set(csrfHeader, token.csrf)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	req.Header.Set("X-Role", "ADMIN")
	req.Header.Set("X-Domain", "C")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	return res
}

func loginTestAccount(t *testing.T, h http.Handler, account procurement.AccountSeed) browserToken {
	t.Helper()
	credentials, err := json.Marshal(map[string]string{"username": account.Username, "password": account.Password})
	require.NoError(t, err)
	res := browserRequest(h, "POST", "/session/login", string(credentials), browserToken{}, "")
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	var view procurement.SessionView
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &view))
	require.Equal(t, account.DomainID, view.DomainID)
	require.Equal(t, account.SubjectID, view.SubjectID)
	require.Equal(t, account.Role, view.Role)
	require.Equal(t, procurement.BuildSessionView(account.Principal, "").Actions, view.Actions)
	require.NotEmpty(t, view.CSRFToken)
	cookies := res.Result().Cookies()
	require.Len(t, cookies, 1)
	require.True(t, cookies[0].HttpOnly)
	require.True(t, cookies[0].Secure)
	require.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
	require.Equal(t, "/", cookies[0].Path)
	require.Empty(t, cookies[0].Domain)
	return browserToken{cookie: cookies[0], csrf: view.CSRFToken}
}

func decodeBrowserOperation(t *testing.T, res *httptest.ResponseRecorder, status int) browserOperation {
	t.Helper()
	require.Equal(t, status, res.Code, res.Body.String())
	var out browserOperation
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &out))
	require.NotEmpty(t, out.OperationID)
	return out
}

func readProcurementRun(t *testing.T, response *httptest.ResponseRecorder, status int) procurement.Run {
	t.Helper()
	require.Equal(t, status, response.Code, response.Body.String())
	var run procurement.Run
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &run))
	return run
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
	raw := bytes.ReplaceAll(contract.Components.Schemas, []byte(`"#/components/schemas/`), []byte(`"#/$defs/`))
	var schemas map[string]*jsonschema.Schema
	require.NoError(t, json.Unmarshal(raw, &schemas))
	schema, err := (&jsonschema.Schema{Defs: schemas, Ref: "#/$defs/" + name}).Resolve(nil)
	require.NoError(t, err)
	return schema
}

type stubAdvisor struct {
	draft procurement.Draft
}

func (a stubAdvisor) SuggestDraft(_ context.Context, _ string, _ *procurement.Draft) (procurement.Draft, string, error) {
	return a.draft, "Drafted procurement terms", nil
}

type stubPeerClient struct {
	getDispatchFn func(ctx context.Context, runID string) (procurement.DispatchStatusView, error)
}

func (*stubPeerClient) RequestRoot(context.Context, procurement.RootGrantRequest) (procurement.RootGrantResponse, error) {
	return procurement.RootGrantResponse{}, procurement.ErrUnavailable
}
func (*stubPeerClient) AckRootReceipt(context.Context, string, string) error { return nil }
func (*stubPeerClient) EnsureContext(context.Context, string) error          { return nil }
func (*stubPeerClient) SubmitDispatch(context.Context, procurement.DispatchRequest) (procurement.DispatchStatusView, error) {
	return procurement.DispatchStatusView{}, procurement.ErrUnavailable
}
func (p *stubPeerClient) GetDispatch(ctx context.Context, runID string) (procurement.DispatchStatusView, error) {
	if p.getDispatchFn != nil {
		return p.getDispatchFn(ctx, runID)
	}
	return procurement.DispatchStatusView{}, procurement.ErrUnavailable
}
func (*stubPeerClient) RequestDispatchProbe(context.Context, procurement.ProbeRequest) (procurement.ProbeResponse, error) {
	return procurement.ProbeResponse{}, procurement.ErrUnavailable
}

type stubPeerEvidence struct {
	taskEvidence domgw.TaskEvidence
}

func (s stubPeerEvidence) FetchTaskEvidence(context.Context, string) (domgw.TaskEvidence, error) {
	return s.taskEvidence, nil
}

func (stubPeerEvidence) FetchRootAmount(context.Context, string) (evidence.RootGrantAmount, error) {
	return evidence.RootGrantAmount{}, evidence.ErrNotFound
}

type testManagementBackend struct {
	submissionCount atomic.Int32
	submitted       sync.Map
}

func (*testManagementBackend) CurrentRevision(_ context.Context, kind, id string) (uint64, bool, error) {
	if kind != "domain" || (id != "A" && id != "B" && id != "C") {
		return 0, false, errors.New("unexpected record lookup")
	}
	return 2, true, nil
}

func (b *testManagementBackend) SubmitAsync(
	_ context.Context,
	key, id string,
	caller preg.Management,
	method string,
	input json.RawMessage,
	update domreg.OutcomeHandler,
) {
	var body preg.PurchasingAuthorityUpdate
	if method != procurement.SetPurchasingAuthorityMethod || json.Unmarshal(input, &body) != nil || body.DeploymentID != "dep-1" ||
		caller.MSPID != body.DomainID+"Msp" || body.PurchasingAuthority != testServiceDID(body.DomainID) {
		return
	}
	if _, replay := b.submitted.LoadOrStore(id, struct{}{}); replay {
		return
	}
	b.submissionCount.Add(1)
	txID := preg.Digest([]byte(id))
	if key == "reject-endorsement" {
		_ = update("ENDORSE", "FAILED", txID, nil, nil, false)
		return
	}
	_ = update("COMMIT", "CONFIRMED", txID, &ledger.Outcome{
		Point:        ledger.Point{Number: 17, Hash: preg.Digest([]byte(txID))},
		Code:         "VALID",
		ObservedPeer: "peer-" + strings.ToLower(body.DomainID),
	}, nil, false)
}
