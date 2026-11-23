//go:build db

package workbench

import (
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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"grad/platform/internal/testutil"
	"grad/platform/registrysvc"
	"grad/platform/state/fabric"
	"grad/protocol/registry"
)

func TestMain(m *testing.M) {
	os.Exit(testutil.RunWithPostgres(m))
}

func TestBrowserSessionsAndLocalManagement(t *testing.T) {
	ctx := context.Background()
	db := testutil.OpenMigratedPool(t)
	backend := &testManagementBackend{}
	sa := testServer(t, db, backend, "dep-1", "A")
	sb := testServer(t, db, backend, "dep-1", "B")
	sc := testServer(t, db, backend, "dep-1", "C")
	a := testAccount("A", "admin", RoleAdmin, "a")
	b := testAccount("B", "admin", RoleAdmin, "b")
	c := testAccount("C", "admin", RoleAdmin, "c")
	u := testAccount("A", "buyer", RoleBuyer, "d")
	caudit := AccountSeed{Principal: c.Principal, Username: "audit", Password: c.Password}
	caudit.Role = RoleAuditor
	require.NoError(t, sa.SeedAccounts(ctx, []AccountSeed{a, u}))
	require.NoError(t, sb.SeedAccounts(ctx, []AccountSeed{b}))
	require.NoError(t, sc.SeedAccounts(ctx, []AccountSeed{c, caudit}))

	const management = "/management/purchasing-authority"
	type adminRun struct {
		server  *Server
		account AccountSeed
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
		var qualification PurchasingAuthority
		require.NoError(t, json.Unmarshal(res.Body.Bytes(), &qualification))
		require.Equal(t, account.DomainID, qualification.DomainID)
		require.Len(t, qualification.EligibleServiceIDs, 1)
		update := `{"expectedRevision":2,"purchasingAuthority":"` + qualification.EligibleServiceIDs[0] + `"}`
		res = browserRequest(h, "POST", management, update, browserToken{cookie: token.cookie}, "update")
		assertError(t, res, http.StatusForbidden, "CSRF_INVALID")
		res = browserRequest(h, "POST", management, `{"expectedRevision":2,"purchasingAuthority":null,"domainId":"C"}`, token, "update")
		assertError(t, res, http.StatusBadRequest, registry.ErrCodeInvalidSchema)
		res = browserRequest(h, "POST", management, `{"expectedRevision":1,"purchasingAuthority":null}`, token, "stale")
		assertError(t, res, http.StatusConflict, registry.ErrCodeStateChanged)
		res = browserRequest(h, "POST", management, `{"expectedRevision":2,"purchasingAuthority":"did:web:foreign.local:pa"}`, token, "foreign")
		assertError(t, res, http.StatusForbidden, registry.ErrCodePurchasingAuthorityInvalid)
		res = browserRequest(h, "POST", management, update, token, "update")
		op := decodeBrowserOperation(t, res, http.StatusAccepted)
		require.Equal(t, "PENDING", op.Status)
		require.Nil(t, op.TxID)
		operations = append(operations, op.OperationID)
		res = browserRequest(h, "POST", management, update, token, "update")
		require.Equal(t, op.OperationID, decodeBrowserOperation(t, res, http.StatusAccepted).OperationID)
		res = browserRequest(h, "POST", management, `{"expectedRevision":2,"purchasingAuthority":null}`, token, "update")
		assertError(t, res, http.StatusConflict, registry.ErrCodeIdempotencyConflict)
		require.EventuallyWithT(t, func(t *assert.CollectT) {
			res := browserRequest(h, "GET", "/operations/"+op.OperationID, "", token, "")
			if !assert.Equal(t, http.StatusOK, res.Code) {
				return
			}
			var result browserOperation
			if assert.NoError(t, json.Unmarshal(res.Body.Bytes(), &result)) && assert.Equal(t, "CONFIRMED", result.Status) {
				assert.NotNil(t, result.TxID)
				assert.NotNil(t, result.BlockNumber)
				if assert.NotNil(t, result.ValidationCode) {
					assert.Equal(t, "VALID", *result.ValidationCode)
				}
			}
		}, 2*time.Second, 10*time.Millisecond)
	}
	require.Equal(t, int32(3), backend.submissionCount.Load())

	h := sa.Handler()
	buyerToken := loginTestAccount(t, h, u)
	res := browserRequest(h, "POST", management, `{"expectedRevision":2,"purchasingAuthority":null}`, buyerToken, "forged")
	assertError(t, res, http.StatusForbidden, registry.ErrCodeIdentityManagementForbidden)
	res = browserRequest(h, "GET", "/operations/"+operations[0], "", buyerToken, "")
	assertError(t, res, http.StatusNotFound, registry.ErrCodeOperationUnknown)
	res = browserRequest(h, "GET", "/operations/"+operations[1], "", aToken, "")
	assertError(t, res, http.StatusNotFound, registry.ErrCodeOperationUnknown)
	require.Equal(t, int32(3), backend.submissionCount.Load())
	var operationCount int
	require.NoError(t, db.QueryRow(ctx, `SELECT COUNT(*) FROM operations WHERE deployment_id='dep-1'`).Scan(&operationCount))
	require.Equal(t, 3, operationCount)
	res = browserRequest(h, "POST", management, `{"expectedRevision":2,"purchasingAuthority":"did:web:a.local:pa"}`, aToken, "reject-endorsement")
	failed := decodeBrowserOperation(t, res, http.StatusAccepted)
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		res := browserRequest(h, "GET", "/operations/"+failed.OperationID, "", aToken, "")
		if !assert.Equal(t, http.StatusOK, res.Code) {
			return
		}
		var result browserOperation
		if assert.NoError(t, json.Unmarshal(res.Body.Bytes(), &result)) && assert.Equal(t, "FAILED", result.Status) {
			if assert.NotNil(t, result.FailureCode) {
				assert.Equal(t, registry.ErrCodeEndorsementRejected, *result.FailureCode)
			}
			assert.Nil(t, result.BlockNumber)
			assert.Nil(t, result.ValidationCode)
		}
	}, 2*time.Second, 10*time.Millisecond)

	wrongCookie := *aToken.cookie
	wrongCookie.Name = sb.cookieName()
	res = browserRequest(sb.Handler(), "GET", "/session", "", browserToken{cookie: &wrongCookie}, "")
	assertError(t, res, http.StatusUnauthorized, "SESSION_REQUIRED")
	otherDeployment := testServer(t, db, backend, "dep-2", "A")
	res = browserRequest(otherDeployment.Handler(), "GET", "/session", "", aToken, "")
	assertError(t, res, http.StatusUnauthorized, "SESSION_REQUIRED")

	restarted := testServer(t, db, backend, "dep-1", "A")
	require.NoError(t, restarted.SeedAccounts(ctx, []AccountSeed{a, u}))
	res = browserRequest(restarted.Handler(), "GET", "/session", "", buyerToken, "")
	require.Equal(t, http.StatusOK, res.Code)
	res = browserRequest(h, "POST", "/session/logout", "", browserToken{cookie: buyerToken.cookie}, "")
	assertError(t, res, http.StatusForbidden, "CSRF_INVALID")
	revoked := *restarted
	revoked.cfg.VerifyPrincipal = func(context.Context, Principal) error { return principalForbidden() }
	res = browserRequest(revoked.Handler(), "GET", "/session", "", buyerToken, "")
	assertError(t, res, http.StatusForbidden, registry.ErrCodeIdentityManagementForbidden)
	res = browserRequest(revoked.Handler(), "POST", "/session/logout", "", buyerToken, "")
	require.Equal(t, http.StatusNoContent, res.Code)
	require.Equal(t, -1, res.Result().Cookies()[0].MaxAge)
	res = browserRequest(restarted.Handler(), "GET", "/session", "", buyerToken, "")
	assertError(t, res, http.StatusUnauthorized, "SESSION_REQUIRED")
	oldAudit := loginTestAccount(t, sc.Handler(), caudit)
	require.NoError(t, sc.SeedAccounts(ctx, []AccountSeed{c}))
	res = browserRequest(sc.Handler(), "GET", "/session", "", oldAudit, "")
	assertError(t, res, http.StatusUnauthorized, "SESSION_REQUIRED")

	a.Password = "updated-example-password"
	require.NoError(t, restarted.SeedAccounts(ctx, []AccountSeed{a, u}))
	res = browserRequest(restarted.Handler(), "GET", "/session", "", aToken, "")
	assertError(t, res, http.StatusUnauthorized, "SESSION_REQUIRED")
	loginTestAccount(t, restarted.Handler(), a)
	var hash []byte
	require.NoError(t, db.QueryRow(ctx, `SELECT password_hash FROM workbench_accounts WHERE deployment_id='dep-1' AND domain_id='A' AND username='admin'`).Scan(&hash))
	require.NoError(t, bcrypt.CompareHashAndPassword(hash, []byte(a.Password)))
}

func testServer(t *testing.T, db *pgxpool.Pool, backend *testManagementBackend, deployment, domain string) *Server {
	t.Helper()
	server, err := NewServer(Config{
		DeploymentID: deployment, DomainID: domain, DB: db,
		Registry: registrysvc.NewService(db, deployment, registry.Management{}, backend),
		VerifyPrincipal: func(_ context.Context, principal Principal) error {
			if !validPrincipal(principal, domain) {
				return principalForbidden()
			}
			return nil
		},
		ReadPurchasingAuthority: func(context.Context, Principal) (PurchasingAuthority, error) {
			return PurchasingAuthority{DomainID: domain, ExpectedRevision: 2, EligibleServiceIDs: []string{testServiceDID(domain)}}, nil
		},
		CheckPurchasingAuthority: func(_ context.Context, _ Principal, did string) error {
			if did != testServiceDID(domain) {
				return registry.Reject(registry.ErrCodePurchasingAuthorityInvalid)
			}
			return nil
		},
		Ready: func(context.Context) error { return nil },
	})
	require.NoError(t, err)
	return server
}

func testServiceDID(domain string) string {
	return "did:web:" + strings.ToLower(domain) + ".local:pa"
}

func testAccount(domain, name string, role Role, hashChar string) AccountSeed {
	return AccountSeed{Principal: Principal{DomainID: domain, SubjectID: "did:web:" + strings.ToLower(domain) + ".local:" + name,
		Role: role, Management: registry.Management{MSPID: domain + "Msp", CertificateSHA256: strings.Repeat(hashChar, 64)}},
		Username: name, Password: "example-password"}
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

func loginTestAccount(t *testing.T, h http.Handler, account AccountSeed) browserToken {
	t.Helper()
	credentials, err := json.Marshal(map[string]string{"username": account.Username, "password": account.Password})
	require.NoError(t, err)
	res := browserRequest(h, "POST", "/session/login", string(credentials), browserToken{}, "")
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	var view sessionView
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &view))
	require.Equal(t, account.DomainID, view.DomainID)
	require.Equal(t, account.SubjectID, view.SubjectID)
	require.Equal(t, account.Role, view.Role)
	require.Equal(t, sessionResponse(account.Principal, "").Actions, view.Actions)
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

type testManagementBackend struct {
	submissionCount atomic.Int32
	submitted       sync.Map
}

func (*testManagementBackend) CurrentRevision(_ context.Context, kind, id string) (uint64, bool, error) {
	if kind != "domain" || id != "A" && id != "B" && id != "C" {
		return 0, false, errors.New("unexpected record lookup")
	}
	return 2, true, nil
}

func (b *testManagementBackend) SubmitAsync(_ context.Context, key, id string, caller registry.Management,
	method string, input json.RawMessage, update registrysvc.OutcomeHandler) {
	var body registry.PurchasingAuthorityUpdate
	if method != setPurchasingAuthorityMethod || json.Unmarshal(input, &body) != nil || body.DeploymentID != "dep-1" ||
		caller.MSPID != body.DomainID+"Msp" || body.PurchasingAuthority != testServiceDID(body.DomainID) {
		return
	}
	if _, replay := b.submitted.LoadOrStore(id, struct{}{}); replay {
		return
	}
	b.submissionCount.Add(1)
	txID := registry.Digest([]byte(id))
	if key == "reject-endorsement" {
		_ = update("ENDORSE", "FAILED", txID, nil, nil, false)
		return
	}
	_ = update("COMMIT", "CONFIRMED", txID, &fabric.Outcome{
		Point: fabric.Point{Number: 17, Hash: registry.Digest([]byte(txID))}, Code: "VALID", ObservedPeer: "peer-" + strings.ToLower(body.DomainID),
	}, nil, false)
}
