package httpx_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/internal/httpx"
)

func TestWriteErrorPreservesNullAndNonNullDecisionID(t *testing.T) {
	t.Run("nil decisionId emits explicit null", func(t *testing.T) {
		rec := httptest.NewRecorder()
		httpx.WriteError(rec, http.StatusForbidden, "urn:grad:req:1", "ACCESS_DENIED", nil, "forbidden")

		require.Equal(t, http.StatusForbidden, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, "urn:grad:req:1", rec.Header().Get(httpx.HeaderRequestID))

		var raw map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
		decisionVal, exists := raw["decisionId"]
		require.True(t, exists, "decisionId key must be present when nil")
		assert.Equal(t, "null", string(decisionVal))
		assert.Equal(t, `"urn:grad:req:1"`, string(raw["requestId"]))
		assert.Equal(t, `"ACCESS_DENIED"`, string(raw["code"]))
		assert.Equal(t, `"forbidden"`, string(raw["message"]))
	})

	t.Run("non-nil decisionId emits string value", func(t *testing.T) {
		rec := httptest.NewRecorder()
		decID := "urn:grad:decision:abc"
		httpx.WriteError(rec, http.StatusForbidden, "urn:grad:req:2", "REVOKED", &decID, "grant revoked")

		require.Equal(t, http.StatusForbidden, rec.Code)
		var env httpx.ErrorEnvelope
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
		assert.Equal(t, "urn:grad:req:2", env.RequestID)
		assert.Equal(t, "REVOKED", env.Code)
		require.NotNil(t, env.DecisionID)
		assert.Equal(t, decID, *env.DecisionID)
		assert.Equal(t, "grant revoked", env.Message)
	})
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	httpx.WriteJSON(rec, http.StatusCreated, map[string]string{"status": "ok"})

	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestRequireJSONContentType(t *testing.T) {
	cases := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{name: "exact", header: "application/json", wantErr: false},
		{name: "with charset", header: "application/json; charset=utf-8", wantErr: false},
		{name: "uppercase", header: "APPLICATION/JSON", wantErr: false},
		{name: "missing", header: "", wantErr: true},
		{name: "text plain", header: "text/plain", wantErr: true},
		{name: "malformed", header: "application/json; =bad", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tc.header != "" {
				req.Header.Set("Content-Type", tc.header)
			}
			err := httpx.RequireJSONContentType(req)
			if tc.wantErr {
				require.ErrorIs(t, err, httpx.ErrUnsupportedMediaType)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDecodeJSONStrictAndBounded(t *testing.T) {
	type payload struct {
		Actor string `json:"actor"`
		Count int    `json:"count"`
	}

	t.Run("valid payload", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"actor":"did:web:a","count":2}`))
		req.Header.Set("Content-Type", "application/json")
		var dst payload
		require.NoError(t, httpx.DecodeJSON(req, 1024, &dst))
		assert.Equal(t, payload{Actor: "did:web:a", Count: 2}, dst)
	})

	t.Run("rejects wrong content type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"actor":"a"}`))
		req.Header.Set("Content-Type", "text/plain")
		var dst payload
		require.ErrorIs(t, httpx.DecodeJSON(req, 1024, &dst), httpx.ErrUnsupportedMediaType)
	})

	t.Run("rejects payload exceeding maxBytes by ContentLength", func(t *testing.T) {
		body := bytes.Repeat([]byte("a"), 64)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		var dst payload
		require.ErrorIs(t, httpx.DecodeJSON(req, 32, &dst), httpx.ErrPayloadTooLarge)
	})

	t.Run("rejects payload exceeding maxBytes with unknown ContentLength", func(t *testing.T) {
		body := `{"actor":"` + strings.Repeat("x", 64) + `","count":1}`
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		req.ContentLength = -1
		req.Header.Set("Content-Type", "application/json")
		var dst payload
		require.ErrorIs(t, httpx.DecodeJSON(req, 32, &dst), httpx.ErrPayloadTooLarge)
	})

	t.Run("rejects unknown field", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"actor":"a","extra":true}`))
		req.Header.Set("Content-Type", "application/json")
		var dst payload
		require.ErrorIs(t, httpx.DecodeJSON(req, 1024, &dst), httpx.ErrInvalidJSON)
	})

	t.Run("rejects duplicate key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"actor":"a","actor":"b"}`))
		req.Header.Set("Content-Type", "application/json")
		var dst payload
		require.ErrorIs(t, httpx.DecodeJSON(req, 1024, &dst), httpx.ErrInvalidJSON)
	})

	t.Run("rejects trailing data", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"actor":"a"}{"actor":"b"}`))
		req.Header.Set("Content-Type", "application/json")
		var dst payload
		require.ErrorIs(t, httpx.DecodeJSON(req, 1024, &dst), httpx.ErrInvalidJSON)
	})

	t.Run("rejects empty body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("   "))
		req.Header.Set("Content-Type", "application/json")
		var dst payload
		require.ErrorIs(t, httpx.DecodeJSON(req, 1024, &dst), httpx.ErrInvalidJSON)
	})
}

func TestRequestIDAndMiddleware(t *testing.T) {
	t.Run("uses caller header when present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(httpx.HeaderRequestID, "urn:grad:req:custom-123")
		assert.Equal(t, "urn:grad:req:custom-123", httpx.RequestID(req))
	})

	t.Run("generates stable id through middleware", func(t *testing.T) {
		var seenFirst, seenSecond string
		h := httpx.WithRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenFirst = httpx.RequestID(r)
			seenSecond = httpx.RequestID(r)
			w.WriteHeader(http.StatusNoContent)
		}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		assert.True(t, strings.HasPrefix(seenFirst, "urn:grad:req:"))
		assert.Equal(t, seenFirst, seenSecond)
		assert.Equal(t, seenFirst, rec.Header().Get(httpx.HeaderRequestID))
	})
}

func TestInvokeHandler(t *testing.T) {
	t.Run("captures explicit status, headers, and body", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NotNil(t, r.Body)
			w.Header().Set("X-Test", "before")
			httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"ok": "yes"})
			w.Header().Set("X-Test", "after-write")
		})
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://c.local/ping", nil)
		require.NoError(t, err)

		resp := httpx.InvokeHandler(h, req)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusAccepted, resp.StatusCode)
		assert.Equal(t, "before", resp.Header.Get("X-Test"))
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"ok":"yes"}`, string(body))
		assert.Equal(t, int64(len(body)), resp.ContentLength)
	})

	t.Run("defaults to 200 OK when handler writes nothing", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Empty", "1")
		})
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://c.local/empty", nil)
		require.NoError(t, err)

		resp := httpx.InvokeHandler(h, req)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "1", resp.Header.Get("X-Empty"))
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Empty(t, body)
	})
}
