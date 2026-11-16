package fabric

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/serviceauth"
)

func TestOperationQueryRequiresOwnerOrExplicitSameDomainAuditor(t *testing.T) {
	pool := testPgPool(t)
	dep := api.Digest([]byte(t.Name()))
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM operations WHERE deployment_id=$1`, dep) })
	svc := NewManagementOperationService(pool, dep, api.Management{}, &stubOpBackend{revision: 1, exists: true})
	owner := api.Management{MSPID: "BMsp", Fingerprint: strings.Repeat("a", 64)}
	sameDomainAuditor := api.Management{MSPID: "BMsp", Fingerprint: strings.Repeat("b", 64)}
	otherDomainAuditor := api.Management{MSPID: "AMsp", Fingerprint: strings.Repeat("c", 64)}
	svc.SetOperationAuditors([]api.Management{sameDomainAuditor, otherDomainAuditor})
	_, view, err := svc.Accept(t.Context(), "private", owner, "RotateIdentity", json.RawMessage(`{"id":"b1","expectedRevision":1}`), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		identity serviceauth.Identity
		code     int
	}{
		{"owner", serviceauth.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.Fingerprint}, 200},
		{"approved-auditor", serviceauth.Identity{Role: "AUDITOR", MSPID: sameDomainAuditor.MSPID, Fingerprint: sameDomainAuditor.Fingerprint}, 200},
		{"unauthenticated", serviceauth.Identity{}, 403},
		{"other-same-domain-manager", serviceauth.Identity{Role: "MANAGEMENT", MSPID: "BMsp", Fingerprint: strings.Repeat("d", 64)}, 403},
		{"other-domain-manager", serviceauth.Identity{Role: "MANAGEMENT", MSPID: "AMsp", Fingerprint: strings.Repeat("e", 64)}, 403},
		{"cross-domain-auditor", serviceauth.Identity{Role: "AUDITOR", MSPID: otherDomainAuditor.MSPID, Fingerprint: otherDomainAuditor.Fingerprint}, 403},
		{"unapproved-auditor", serviceauth.Identity{Role: "AUDITOR", MSPID: "BMsp", Fingerprint: strings.Repeat("f", 64)}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/operations/"+view.OperationID, nil)
			// Self-asserted owner headers must not affect any decision.
			req.Header.Set("X-Caller-MSPID", owner.MSPID)
			req.Header.Set("X-Caller-Fingerprint", owner.Fingerprint)
			req.Header.Set("X-Caller-Role", "AUDITOR")
			if tc.identity.Role != "" {
				req = req.WithContext(serviceauth.WithIdentity(req.Context(), tc.identity))
			}
			w := httptest.NewRecorder()
			svc.Handler().ServeHTTP(w, req)
			if w.Code != tc.code {
				t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
			}
			if tc.code == 403 && (strings.Contains(w.Body.String(), "operationKey") || strings.Contains(w.Body.String(), view.OperationID)) {
				t.Fatal("forbidden response leaked operation")
			}
		})
	}
	for _, state := range []string{"PENDING", "CONFIRMED", "FAILED"} {
		if _, err := pool.Exec(t.Context(), `UPDATE operations SET status=$2 WHERE deployment_id=$1`, dep, state); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/v1/operations/"+view.OperationID, nil)
		req = req.WithContext(serviceauth.WithIdentity(req.Context(), serviceauth.Identity{Role: "MANAGEMENT", MSPID: owner.MSPID, Fingerprint: owner.Fingerprint}))
		w := httptest.NewRecorder()
		svc.Handler().ServeHTTP(w, req)
		var got OperationView
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 || got.Status != state {
			t.Fatalf("authorized %s query: %d %s %v", state, w.Code, w.Body.String(), err)
		}
	}
}
