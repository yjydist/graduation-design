package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"graduation-design/internal/fabric"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/policy"
	"graduation-design/internal/protocol"
)

func TestGatewayM3SignatureCacheB1MaterialNotSyncedStateStaleAndPolicyAttributes(t *testing.T) {
	h := newM2GatewayHarness(t)
	ctx := t.Context()
	cache := protocol.NewSignatureCache()

	srv, err := gateway.NewServer(gateway.Config{
		DB: h.pool, State: h.state.GatewayAdapter(), Delivery: h.delivery, DIDs: h.dids, Policy: h.bundle,
		SignatureCache: cache,
		DeploymentID:   h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID,
		ClockErrorMargin: api.ClockError, NowFn: func() time.Time { return h.fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := srv.Handler()
	h.postContext(t, handler, h.rp.taskID, 0, "NORMAL", h.policyDeadline)

	makeReq := func(ik string) protocol.AccessRequest {
		return protocol.AccessRequest{
			SchemaVersion: protocol.SchemaVersion, DeploymentID: h.depID, Actor: h.didB1,
			PrincipalDomain: "A", AuthorizationMode: h.rp.mode, TaskID: h.rp.taskID,
			Audience: h.audience, Resource: "urn:grad:resource:C:quotes", Action: "quote.read",
			SupplierID: h.supplierID, ProductID: gateway.DefaultProductID, Quantity: 1,
			Currency: "CNY", AmountMinor: 0, IdempotencyKey: ik,
		}
	}

	// 1. Cold & Warm execute populate and reuse SignatureCache (B1).
	r1 := h.execReq(t, handler, h.rp, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq("m3-gw-cold"))
	if r1.Code != http.StatusOK {
		t.Fatalf("cold quote failed: %d %s", r1.Code, r1.Body.String())
	}
	if cache.Misses() == 0 || cache.Hits() != 0 {
		t.Fatalf("expected cold misses > 0 and hits == 0, got hits=%d misses=%d", cache.Hits(), cache.Misses())
	}
	cache.ResetStats()
	r2 := h.execReq(t, handler, h.rp, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq("m3-gw-warm"))
	if r2.Code != http.StatusOK {
		t.Fatalf("warm quote failed: %d %s", r2.Code, r2.Body.String())
	}
	if cache.Hits() == 0 || cache.Misses() != 0 {
		t.Fatalf("expected warm hits > 0 and misses == 0, got hits=%d misses=%d", cache.Hits(), cache.Misses())
	}

	// Verify OPAInput built without undisclosed optional attributes has nil Attributes (S93).
	inNoAttr, err := h.bundle.BuildInput(policy.SupplierFacts{
		AuthorizationMode:   h.rp.mode,
		BuyerDomain:         "A",
		AuthorityRole:       "supplier-service",
		ServiceDID:          h.serviceDID,
		ServiceRole:         "supplier-service",
		ProductID:           gateway.DefaultProductID,
		Quantity:            1,
		Action:              "quote.read",
		AmountMinor:         0,
		MaxPathAmountMinor:  100000,
		NowUnix:             h.fixedNow.Unix(),
		VerifiedCrypto:      true,
		TaskActive:          true,
		PathActive:          true,
		ContextFresh:        true,
		ContextRiskLevel:    "NORMAL",
		WithinTimeAndBounds: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawIn, _ := json.Marshal(inNoAttr)
	if strings.Contains(string(rawIn), "department") || inNoAttr.Attributes != nil {
		t.Fatalf("policy input must not contain inferred/undisclosed attributes: %s", string(rawIn))
	}

	// 2. S84: Remove synced certification receipts -> 503 MATERIAL_NOT_SYNCED (no fallback).
	if _, err := h.pool.Exec(ctx, `DELETE FROM certification_receipts WHERE deployment_id=$1 AND domain_id='B'`, h.depID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM certification_outbox WHERE deployment_id=$1 AND domain_id='B'`, h.depID); err != nil {
		t.Fatal(err)
	}
	rNoMat := h.execReq(t, handler, h.rp, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq("m3-gw-nomat"))
	if rNoMat.Code != http.StatusServiceUnavailable || !strings.Contains(rNoMat.Body.String(), protocol.ErrCodeMaterialNotSynced) {
		t.Fatalf("expected 503 MATERIAL_NOT_SYNCED, got %d %s", rNoMat.Code, rNoMat.Body.String())
	}

	// 3. S84: Expired probe deadline while calling execute -> 503 STATE_STALE.
	// Restore domain B receipt first via PublishDomainCertification or direct insert from h.rp.tp.
	var domB api.Domain
	var rawDomB []byte
	if err := h.pool.QueryRow(ctx, `SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2`, h.depID, api.Key("domain", "B")).Scan(&rawDomB); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(rawDomB, &domB)
	var certB api.Certification
	var rawCertB []byte
	if err := h.pool.QueryRow(ctx, `SELECT value FROM fabric_current WHERE deployment=$1 AND key=$2`, h.depID, api.Key("certification", domB.Certification)).Scan(&rawCertB); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(rawCertB, &certB)
	for _, tp := range h.rp.tp {
		if strings.Contains(tp.Issuer, ":b.local:") {
			if _, err := h.pool.Exec(ctx, `INSERT INTO certification_receipts (deployment_id, domain_id, certification_id, recipient, cert_jws, cert_digest, received_at) VALUES ($1,'B',$2,$3,$4,$5,$6)`,
				h.depID, certB.ID, h.didB1, tp.DomainCertification, certB.Digest, h.fixedNow.Unix()); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Custom server using a stale probe clock!
	staleState := fabric.NewStateProviderFromBootstrap(h.pool, h.depID, h.boot, nil)
	staleNow := h.fixedNow.Add(10 * time.Second)
	staleState.SetMonoClock(func() time.Time { return staleNow })
	staleState.SetStaticProbe(&fabric.ProbeSnapshot{
		TxID: "probe-stale", ProbeBlock: 1, SentAt: h.fixedNow, Deadline: h.fixedNow.Add(5 * time.Second),
		SentMonoNs: h.fixedNow.UnixNano(), DeadlineMonoNs: h.fixedNow.Add(5 * time.Second).UnixNano(),
	})
	staleSrv, err := gateway.NewServer(gateway.Config{
		DB: h.pool, State: staleState.GatewayAdapter(), Delivery: h.delivery, DIDs: h.dids, Policy: h.bundle,
		SignatureCache: cache, DeploymentID: h.depID, ServiceDID: h.serviceDID, Audience: h.audience, SupplierID: h.supplierID,
		ClockErrorMargin: api.ClockError, NowFn: func() time.Time { return h.fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	rStale := h.execReq(t, staleSrv.Handler(), h.rp, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq("m3-gw-stale"))
	// Restore fresh probe on h.state after execReq didn't reset staleSrv's state
	_ = context.Background
	if rStale.Code != http.StatusServiceUnavailable || !strings.Contains(rStale.Body.String(), protocol.ErrCodeStateStale) {
		t.Fatalf("expected 503 STATE_STALE when original probe expired, got %d %s", rStale.Code, rStale.Body.String())
	}

	// 4. S89: Domain B suspended in snapshot -> 403 DOMAIN_INACTIVE even with Delivery configured!
	domB.Status = api.Suspended
	rawSuspDomB, _ := json.Marshal(domB)
	if _, err := h.pool.Exec(ctx, `UPDATE fabric_current SET value=$3 WHERE deployment=$1 AND key=$2`, h.depID, api.Key("domain", "B"), rawSuspDomB); err != nil {
		t.Fatal(err)
	}
	rSuspDom := h.execReq(t, handler, h.rp, h.fixedNow.Unix(), h.didB1, h.b1PresPrefix, h.b1KeyID, h.privB1, makeReq("m3-gw-domsusp"))
	if rSuspDom.Code != http.StatusForbidden || !strings.Contains(rSuspDom.Body.String(), protocol.ErrCodeDomainInactive) {
		t.Fatalf("expected 403 DOMAIN_INACTIVE when Domain B suspended, got %d %s", rSuspDom.Code, rSuspDom.Body.String())
	}
}
