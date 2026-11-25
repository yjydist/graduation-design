package workbench

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	domreg "grad/platform/core/domain/registry"
	"grad/platform/internal/httpx"
	preg "grad/protocol/registry"
)

func TestBrowserOpenAPIAndErrorEnvelope(t *testing.T) {
	server := &Server{}
	handler := server.Handler()
	doc := httptest.NewRecorder()
	handler.ServeHTTP(doc, httptest.NewRequest(http.MethodGet, apiPrefix+"/openapi.json", nil))
	require.Equal(t, http.StatusOK, doc.Code)
	require.Equal(t, "application/json", doc.Header().Get("Content-Type"))
	require.Equal(t, "no-store", doc.Header().Get("Cache-Control"))
	require.Equal(t, "nosniff", doc.Header().Get("X-Content-Type-Options"))

	var contract struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(doc.Body.Bytes(), &contract))
	require.Equal(t, "3.1.0", contract.OpenAPI)
	require.Len(t, server.routes(), 18)
	for _, endpoint := range server.routes() {
		method := strings.ToLower(endpoint.method)
		require.NotEmpty(t, contract.Paths[endpoint.path][method], "%s %s", endpoint.method, endpoint.path)
		delete(contract.Paths[endpoint.path], method)
		if len(contract.Paths[endpoint.path]) == 0 {
			delete(contract.Paths, endpoint.path)
		}
	}
	require.Empty(t, contract.Paths)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(doc.Body.Bytes(), &raw))
	checkOpenAPIReferences(t, raw, raw)
	components := raw["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	schema := schemas["ErrorEnvelope"].(map[string]any)
	properties := schema["properties"].(map[string]any)

	for _, tc := range []struct {
		method, path, body, contentType, code string
		status                                int
		allow                                 string
	}{
		{http.MethodGet, "/missing", "", "", "ROUTE_NOT_FOUND", http.StatusNotFound, ""},
		{http.MethodDelete, "/session", "", "", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed, "GET, HEAD"},
		{http.MethodGet, "/session", "", "", "SESSION_REQUIRED", http.StatusUnauthorized, ""},
		{http.MethodPost, "/session/login", `{}`, "text/plain", "UNSUPPORTED_MEDIA_TYPE", http.StatusUnsupportedMediaType, ""},
		{http.MethodPost, "/session/login", `{"username":"u","password":"example","role":"ADMIN"}`, "application/json", "INVALID_SCHEMA", http.StatusBadRequest, ""},
	} {
		t.Run(tc.code, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, apiPrefix+tc.path, strings.NewReader(tc.body))
			req.Header.Set(httpx.HeaderRequestID, "req-test-browser")
			req.Header.Set("Content-Type", tc.contentType)
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			assertError(t, res, tc.status, tc.code)
			if tc.allow != "" {
				require.Equal(t, tc.allow, res.Header().Get("Allow"))
			}
			var body map[string]any
			require.NoError(t, json.Unmarshal(res.Body.Bytes(), &body))
			require.Len(t, body, len(properties))
			for key := range properties {
				require.Contains(t, body, key)
			}
		})
	}
}

func TestNewServerValidation(t *testing.T) {
	_, err := NewServer(Config{})
	require.Error(t, err)
	_, err = NewServer(Config{DeploymentID: "dep-1", DomainID: "X"})
	require.Error(t, err)
	_, err = NewServer(Config{DeploymentID: "dep-1", DomainID: "A"})
	require.Error(t, err)
}

func TestLoginCrossSiteAndReadiness(t *testing.T) {
	readyErr := errors.New("peer down")
	server := &Server{cfg: Config{
		DomainID: "A",
		Ready:    func(context.Context) error { return readyErr },
	}}
	h := server.Handler()

	req := httptest.NewRequest(http.MethodPost, apiPrefix+"/session/login", strings.NewReader(`{"username":"admin","password":"example-password"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	assertError(t, res, http.StatusForbidden, "CSRF_INVALID")

	res = httptest.NewRecorder()
	h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, apiPrefix+"/health/ready", nil))
	assertError(t, res, http.StatusServiceUnavailable, preg.ErrCodeStateUnavailable)

	readyErr = nil
	res = httptest.NewRecorder()
	h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, apiPrefix+"/health/ready", nil))
	require.Equal(t, http.StatusOK, res.Code)
	require.JSONEq(t, `{"domainId":"A","ready":true}`, res.Body.String())
}

func TestOperationResponseProjection(t *testing.T) {
	pending := operationResponse(&domreg.OperationView{
		OperationID: "op-1",
		TxID:        "pending:op-1",
		Status:      "PENDING",
		BlockNumber: 0,
	})
	require.Nil(t, pending.TxID)
	require.Nil(t, pending.BlockNumber)

	valid := "VALID"
	committed := operationResponse(&domreg.OperationView{
		OperationID:    "op-2",
		TxID:           preg.Digest([]byte("tx-2")),
		Status:         "CONFIRMED",
		BlockNumber:    42,
		BlockHash:      preg.Digest([]byte("blk-42")),
		ValidationCode: &valid,
	})
	require.NotNil(t, committed.TxID)
	require.Equal(t, preg.Digest([]byte("tx-2")), *committed.TxID)
	require.NotNil(t, committed.BlockNumber)
	require.Equal(t, int64(42), *committed.BlockNumber)
}

func checkOpenAPIReferences(t *testing.T, root map[string]any, item any) {
	t.Helper()
	switch node := item.(type) {
	case map[string]any:
		for key, child := range node {
			if key == "$ref" {
				ref := child.(string)
				require.True(t, strings.HasPrefix(ref, "#/"))
				var target any = root
				for _, part := range strings.Split(ref[2:], "/") {
					parent, ok := target.(map[string]any)
					require.True(t, ok, ref)
					target, ok = parent[part]
					require.True(t, ok, ref)
				}
			} else {
				checkOpenAPIReferences(t, root, child)
			}
		}
	case []any:
		for _, child := range node {
			checkOpenAPIReferences(t, root, child)
		}
	}
}

func assertError(t *testing.T, res *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	require.Equal(t, status, res.Code, res.Body.String())
	require.Equal(t, "application/json", res.Header().Get("Content-Type"))
	var out httpx.ErrorEnvelope
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &out))
	require.Equal(t, code, out.Code)
	require.NotEmpty(t, out.Message)
	require.Nil(t, out.DecisionID)
	require.NotEmpty(t, out.RequestID)
	require.Equal(t, res.Header().Get(httpx.HeaderRequestID), out.RequestID)
}
