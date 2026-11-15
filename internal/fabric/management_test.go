package fabric

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/serviceauth"
)

type observedManagementBackend struct {
	calls    chan string
	blockKey string
	entered  chan struct{}
	release  chan struct{}
}

func (b *observedManagementBackend) CurrentRevision(context.Context, string, json.RawMessage) (uint64, bool, error) {
	return 2, true, nil
}
func (b *observedManagementBackend) SubmitAsync(ctx context.Context, key, id string, caller api.Management, method string, input json.RawMessage, update func(string, string, string, int64, string, *string, *string, bool) error) {
	if key == b.blockKey {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			return
		}
	}
	code := "VALID"
	if err := update("COMMIT", "CONFIRMED", "unit-original-tx", 1, strings.Repeat("f", 64), &code, nil, false); err == nil {
		b.calls <- key
	}
}

func TestManagementHTTPDispatchAndDurableRestart(t *testing.T) {
	pool := testPgPool(t)
	ctx := t.Context()
	depID := strings.Repeat("8", 64)
	defer func() { _, _ = pool.Exec(context.Background(), `DELETE FROM operations WHERE deployment_id=$1`, depID) }()
	b := &observedManagementBackend{calls: make(chan string, 4)}
	caller := api.Management{MSPID: "AMsp", Fingerprint: strings.Repeat("a", 64)}
	s := NewManagementOperationService(pool, depID, api.Management{}, b)
	raw := []byte(`{"id":"did:web:a.local:u","expectedRevision":2}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/management/RotateIdentity", bytes.NewReader(raw))
	req.Header.Set("Idempotency-Key", "http-submit")
	req.Header.Set("X-Caller-MSPID", caller.MSPID)
	req.Header.Set("X-Caller-Fingerprint", caller.Fingerprint)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("self-asserted management headers accepted: %d", w.Code)
	}
	client := serviceauth.NewLocalClient(s.Handler(), serviceauth.Identity{Role: "MANAGEMENT", MSPID: caller.MSPID, Fingerprint: caller.Fingerprint})
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, "https://c.local/v1/management/RotateIdentity", bytes.NewReader(raw))
	req.Header.Set("Idempotency-Key", "http-submit")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatalf("admission: %d", resp.StatusCode)
	}
	select {
	case key := <-b.calls:
		if key != "http-submit" {
			t.Fatal(key)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP never dispatched accepted request")
	}
	code, v, err := s.Accept(ctx, "restart-queued", caller, "RotateIdentity", raw, false)
	if err != nil || code != 202 {
		t.Fatalf("queue for restart: %d %v", code, err)
	}
	restarted := NewManagementOperationService(pool, depID, api.Management{}, b)
	if err = restarted.ResumePending(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := restarted.GetOperation(ctx, v.OperationID)
	if err != nil || got.Status != "CONFIRMED" || got.TxID != "unit-original-tx" {
		t.Fatalf("recovery: %+v %v", got, err)
	}
	code, retry, err := restarted.Accept(ctx, "restart-queued", caller, "RotateIdentity", raw, true)
	if err != nil || code != 202 || retry.TxID != got.TxID {
		t.Fatalf("retry changed result: %+v %v", retry, err)
	}
}

func TestManagementRecoveryDoesNotBlockOtherOriginalRequests(t *testing.T) {
	pool := testPgPool(t)
	ctx := t.Context()
	depID := strings.Repeat("7", 64)
	defer func() { _, _ = pool.Exec(context.Background(), `DELETE FROM operations WHERE deployment_id=$1`, depID) }()
	backend := &observedManagementBackend{calls: make(chan string, 2), blockKey: "a-invisible", entered: make(chan struct{}), release: make(chan struct{})}
	svc := NewManagementOperationService(pool, depID, api.Management{}, backend)
	caller := api.Management{MSPID: "AMsp", Fingerprint: strings.Repeat("a", 64)}
	for _, key := range []string{"a-invisible", "b-independent"} {
		if code, _, err := svc.Accept(ctx, key, caller, "RotateIdentity", json.RawMessage(`{"id":"u","expectedRevision":2}`), false); err != nil || code != 202 {
			t.Fatalf("admission: %d %v", code, err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- svc.ResumePending(ctx) }()
	<-backend.entered
	select {
	case key := <-backend.calls:
		if key != "b-independent" {
			t.Fatal(key)
		}
	case <-time.After(time.Second):
		close(backend.release)
		t.Fatal("unavailable original transaction blocked unrelated recovery")
	}
	close(backend.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
