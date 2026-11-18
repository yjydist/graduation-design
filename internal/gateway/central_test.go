package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"graduation-design/internal/centralstate"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/protocol"
)

func centralHarness(t *testing.T) (*procurementGatewayHarness, *centralstate.Source) {
	t.Helper()
	h := newProcurementGatewayHarness(t)
	rp, err := h.state.AssembleProtocolSnapshot(t.Context(), leafID(t, h.rp), h.fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	bm, err := h.state.AssembleProtocolSnapshot(t.Context(), leafID(t, h.bm), h.fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	mergeMap(rp.Snapshot.Domains, bm.Snapshot.Domains)
	mergeMap(rp.Snapshot.Certifications, bm.Snapshot.Certifications)
	mergeMap(rp.Snapshot.Identities, bm.Snapshot.Identities)
	mergeMap(rp.Snapshot.Credentials, bm.Snapshot.Credentials)
	mergeMap(rp.Snapshot.Tasks, bm.Snapshot.Tasks)
	mergeMap(rp.Snapshot.Grants, bm.Snapshot.Grants)
	s, err := centralstate.Initialize(t.Context(), h.pool, rp.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// C0 must remain usable after all Fabric view data for this deployment disappears.
	for _, table := range []string{"fabric_current", "fabric_version", "fabric_block", "fabric_head"} {
		if _, err := h.pool.Exec(t.Context(), `DELETE FROM `+table+` WHERE deployment=$1`, h.depID); err != nil {
			t.Fatal(err)
		}
	}
	return h, s
}

func mergeMap[T any](a, b map[string]T) {
	for k, v := range b {
		a[k] = v
	}
}
func leafID(t *testing.T, c procurementChainFixture) string {
	t.Helper()
	j, err := protocol.ParseCompactJWS(c.grants[len(c.grants)-1], protocol.TypGrantDelegation)
	if err != nil {
		t.Fatal(err)
	}
	var g protocol.GrantClaims
	if err = json.Unmarshal(j.PayloadBytes, &g); err != nil {
		t.Fatal(err)
	}
	return g.ID
}
func centralServer(t *testing.T, h *procurementGatewayHarness, s *centralstate.Source, hook func(int), cache *protocol.SignatureCache) *gateway.Server {
	t.Helper()
	srv, err := gateway.NewServer(gateway.Config{DB: h.pool, State: s, Delivery: h.delivery, DIDs: h.dids, Policy: h.bundle, SignatureCache: cache, DeploymentID: h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID, NowFn: func() time.Time { return h.fixedNow }, BeforeLockTx: hook})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}
func centralRequest(h *procurementGatewayHarness, c procurementChainFixture, action, key string, quote *string, amount int64) protocol.AccessRequest {
	resource := "urn:grad:resource:C:quotes"
	if action == "order.create" {
		resource = "urn:grad:resource:C:orders"
	}
	return protocol.AccessRequest{SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1, PrincipalDomain: "A", AuthorizationMode: c.mode, TaskID: c.taskID, Audience: h.audience, Resource: resource, Action: action, SupplierID: h.supplierID, QuoteID: quote, ProductID: gateway.DefaultProductID, Quantity: 1, Currency: "CNY", AmountMinor: amount, IdempotencyKey: key}
}
func centralExec(t *testing.T, h *procurementGatewayHarness, srv *gateway.Server, c procurementChainFixture, req protocol.AccessRequest) *httptest.ResponseRecorder {
	return h.execReq(t, srv.Handler(), c, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, req)
}

func TestCentralSnapshotAtomicityAndMissingDependencies(t *testing.T) {
	h, s := centralHarness(t)
	leaf := leafID(t, h.rp)
	var once sync.Once
	s.AfterRead = func() {
		once.Do(func() {
			if err := s.Update(t.Context(), 1, func(v *protocol.SnapshotView) error {
				g := v.Grants[h.rp.g1ID]
				g.Status = api.Revoked
				v.Grants[g.ID] = g
				d := v.Domains["A"]
				d.Revision++
				v.Domains["A"] = d
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	old, err := s.AssembleSnapshot(t.Context(), leaf, h.fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if old.Revision != 1 || old.Snapshot.Grants[h.rp.g1ID].Status != api.Active {
		t.Fatal("read mixed registry versions")
	}
	s.AfterRead = nil
	current, err := s.AssembleSnapshot(t.Context(), leaf, h.fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != 2 || current.Snapshot.Grants[h.rp.g1ID].Status != api.Revoked || current.Snapshot.Domains["A"].Revision != old.Snapshot.Domains["A"].Revision+1 {
		t.Fatal("update was not atomic")
	}
	if err := s.Update(t.Context(), 2, func(v *protocol.SnapshotView) error {
		delete(v.Credentials, v.Grants[leaf].GranteeCredential)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AssembleSnapshot(t.Context(), leaf, h.fixedNow); !protocol.HasCode(err, protocol.ErrCodeStateUnavailable) {
		t.Fatalf("missing credential did not stop assembly: %v", err)
	}
	if err := s.Update(t.Context(), 3, func(v *protocol.SnapshotView) error { v.Grants = nil; return context.Canceled }); err != context.Canceled {
		t.Fatal(err)
	}
	var revision int64
	if err := h.pool.QueryRow(t.Context(), `SELECT revision FROM centralized_registry WHERE deployment_id=$1`, h.depID).Scan(&revision); err != nil || revision != 3 {
		t.Fatalf("failed update advanced revision: %d %v", revision, err)
	}
}

func TestCentralSnapshotExcludesUnrelatedDomains(t *testing.T) {
	h, s := centralHarness(t)
	view, err := s.AssembleSnapshot(t.Context(), leafID(t, h.bm), h.fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := view.Snapshot.Domains["C"]; ok {
		t.Fatal("BM snapshot added an unrelated supplier-domain delivery dependency")
	}
	if len(view.Snapshot.Grants) != 3 || len(view.Snapshot.Tasks) != 1 {
		t.Fatal("snapshot mixed independent task paths")
	}
}

func TestCentralBusinessDecisionsWithoutFabric(t *testing.T) {
	h, s := centralHarness(t)
	srv := centralServer(t, h, s, nil, nil)
	ready := httptest.NewRecorder()
	srv.Handler().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil))
	var health map[string]any
	if err := json.Unmarshal(ready.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if ready.Code != 200 || health["probeBlock"] != nil || health["stateSource"] != "centralized" {
		t.Fatalf("C0 readiness invented a probe: %s", ready.Body.String())
	}
	for _, c := range []procurementChainFixture{h.rp, h.bm} {
		h.postContext(t, srv.Handler(), c.taskID, 0, "NORMAL", h.policyDeadline)
		for _, amount := range []int64{80000, 120000} {
			if _, err := h.pool.Exec(t.Context(), `UPDATE catalog_prices SET unit_price_minor=$2 WHERE deployment_id=$1 AND product_id=$3`, h.depID, amount, gateway.DefaultProductID); err != nil {
				t.Fatal(err)
			}
			key := strings.ReplaceAll(c.mode, "_", "") + "-" + strconv.FormatInt(amount, 10)
			q := centralExec(t, h, srv, c, centralRequest(h, c, "quote.read", "q"+key, nil, 0))
			if q.Code != 200 {
				t.Fatal(q.Body.String())
			}
			var qr gateway.ExecuteResponse
			if err := json.Unmarshal(q.Body.Bytes(), &qr); err != nil {
				t.Fatal(err)
			}
			r := centralExec(t, h, srv, c, centralRequest(h, c, "order.create", "o"+key, &qr.Quote.QuoteID, amount))
			want := 200
			if amount == 120000 {
				want = 403
			}
			if r.Code != want {
				t.Fatalf("%d %s", r.Code, r.Body.String())
			}
			var response struct {
				DecisionID string `json:"decisionId"`
			}
			if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			d := httptest.NewRecorder()
			srv.Handler().ServeHTTP(d, httptest.NewRequest(http.MethodGet, "/v1/decisions/"+response.DecisionID, nil))
			if d.Code != 200 {
				t.Fatal(d.Body.String())
			}
			var fields map[string]any
			if err := json.Unmarshal(d.Body.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			if fields["stateSource"] != "centralized" || fields["revision"] != float64(1) || fields["stateReadAt"] == nil || fields["blockNumber"] != nil || fields["probeTxId"] != nil {
				t.Fatalf("wrong C0 metadata: %s", d.Body.String())
			}
			var nulls bool
			if err := h.pool.QueryRow(t.Context(), `SELECT block_number IS NULL AND block_hash IS NULL AND probe_tx_id IS NULL AND probe_deadline IS NULL FROM decisions WHERE deployment_id=$1 AND decision_id=$2`, h.depID, response.DecisionID).Scan(&nulls); err != nil || !nulls {
				t.Fatalf("C0 persisted invented Fabric metadata: %v", err)
			}
			allowedDecisions := []string{qr.DecisionID}
			if want == 200 {
				allowedDecisions = append(allowedDecisions, response.DecisionID)
			}
			for _, decisionID := range allowedDecisions {
				var checkedMonoNs *int64
				if err := h.pool.QueryRow(t.Context(), `SELECT checked_mono_ns FROM decision_evidence WHERE deployment_id=$1 AND decision_id=$2`, h.depID, decisionID).Scan(&checkedMonoNs); err != nil {
					t.Fatalf("read C0 decision evidence for %s: %v", decisionID, err)
				}
				if checkedMonoNs != nil {
					t.Fatalf("C0 decision evidence for %s has checked_mono_ns=%d, want NULL", decisionID, *checkedMonoNs)
				}
			}
		}
	}
}

func TestCentralVersionChangeDuringBusinessLockWait(t *testing.T) {
	h, s := centralHarness(t)
	entered := make(chan struct{}, 1)
	srv := centralServer(t, h, s, func(attempt int) {
		if attempt == 0 {
			entered <- struct{}{}
		}
	}, nil)
	h.postContext(t, srv.Handler(), h.rp.taskID, 0, "NORMAL", h.policyDeadline)
	// Block the common business context lock before the source checkpoint can be acquired.
	tx, err := h.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var blocker int
	if err = tx.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(t.Context(), `SELECT 1 FROM trusted_contexts WHERE deployment_id=$1 AND task_id=$2 FOR UPDATE`, h.depID, h.rp.taskID); err != nil {
		t.Fatal(err)
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- centralExec(t, h, srv, h.rp, centralRequest(h, h.rp, "quote.read", "version-wait", nil, 0))
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not enter transaction")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting bool
		if err = h.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, blocker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("request did not wait on business lock")
		}
		time.Sleep(time.Millisecond)
	}
	if err = s.Update(t.Context(), 1, func(*protocol.SnapshotView) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-result:
		if r.Code != 200 {
			t.Fatalf("retry failed: %s", r.Body.String())
		}
		var response gateway.ExecuteResponse
		if err = json.Unmarshal(r.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		var revision int64
		var rechecks int
		if err = h.pool.QueryRow(t.Context(), `SELECT revision,state_rechecks FROM decisions WHERE deployment_id=$1 AND decision_id=$2`, h.depID, response.DecisionID).Scan(&revision, &rechecks); err != nil || revision != 2 || rechecks != 1 {
			t.Fatalf("old-version decision committed: %d %d %v", revision, rechecks, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request failed to leave lock wait")
	}
}

func TestDecisionMigrationPreservesFabricRows(t *testing.T) {
	h := newProcurementGatewayHarness(t)
	srv := h.newServer(func() time.Time { return h.fixedNow }, nil)
	h.postContext(t, srv.Handler(), h.rp.taskID, 0, "NORMAL", h.policyDeadline)
	r := centralExec(t, h, srv, h.rp, centralRequest(h, h.rp, "quote.read", "legacy", nil, 0))
	if r.Code != 200 {
		t.Fatal(r.Body.String())
	}
	var response gateway.ExecuteResponse
	if err := json.Unmarshal(r.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	get := func() string {
		d := httptest.NewRecorder()
		srv.Handler().ServeHTTP(d, httptest.NewRequest(http.MethodGet, "/v1/decisions/"+response.DecisionID, nil))
		if d.Code != 200 {
			t.Fatal(d.Body.String())
		}
		return d.Body.String()
	}
	before := get()
	for range 2 {
		if err := gateway.EnsureSchema(t.Context(), h.pool, h.depID, h.supplierID); err != nil {
			t.Fatal(err)
		}
	}
	if after := get(); after != before {
		t.Fatalf("migration changed Fabric decision: %s", after)
	}
}

func TestSignatureCacheAcrossStateSourcesAndDynamicRecheck(t *testing.T) {
	profiles := []struct {
		name    string
		central bool
		cached  bool
	}{
		{name: "central-uncached", central: true},
		{name: "fabric-uncached"},
		{name: "fabric-cached", cached: true},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			var cache *protocol.SignatureCache
			if profile.cached {
				cache = protocol.NewSignatureCache()
			}
			var h *procurementGatewayHarness
			var state gateway.StateSource
			if profile.central {
				var s *centralstate.Source
				h, s = centralHarness(t)
				state = s
			} else {
				h = newProcurementGatewayHarness(t)
				state = h.state.GatewayAdapter()
			}
			srv, err := gateway.NewServer(gateway.Config{DB: h.pool, State: state, Delivery: h.delivery, DIDs: h.dids, Policy: h.bundle, SignatureCache: cache, DeploymentID: h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID, NowFn: func() time.Time { return h.fixedNow }})
			if err != nil {
				t.Fatal(err)
			}
			h.postContext(t, srv.Handler(), h.rp.taskID, 0, "NORMAL", h.policyDeadline)
			for _, key := range []string{"cold", "warm"} {
				r := centralExec(t, h, srv, h.rp, centralRequest(h, h.rp, "quote.read", key, nil, 0))
				if r.Code != 200 {
					t.Fatal(r.Body.String())
				}
			}
			if !profile.cached {
				if cache != nil || cache.Hits() != 0 || cache.Misses() != 0 {
					t.Fatal("disabled group reused signature computation")
				}
				return
			}
			if cache.Hits() == 0 {
				t.Fatal("repeated material did not hit cache")
			}
			g := h.rp.g1
			g.Status = api.Revoked
			g.Revision++
			raw, err := json.Marshal(g)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = h.pool.Exec(t.Context(), `UPDATE fabric_current SET value=$3 WHERE deployment=$1 AND key=$2`, h.depID, api.Key("grant", g.ID), raw); err != nil {
				t.Fatal(err)
			}
			r := centralExec(t, h, srv, h.rp, centralRequest(h, h.rp, "quote.read", "after-revoke", nil, 0))
			if r.Code != 403 || !strings.Contains(r.Body.String(), "ANCESTOR_INACTIVE") {
				t.Fatalf("warm cache bypassed new state: %d %s", r.Code, r.Body.String())
			}
		})
	}
}
