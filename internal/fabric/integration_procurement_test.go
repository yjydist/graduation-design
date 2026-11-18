package fabric

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"graduation-design/internal/agent"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/gateway"
	"graduation-design/internal/policy"
	"graduation-design/internal/protocol"
)

type procurementEvidenceReport struct {
	DeploymentID          string            `json:"deploymentId"`
	RunID                 string            `json:"runId"`
	DualRootsIdentityLink map[string]any    `json:"dualRootsAndIdentityLink,omitempty"`
	DualModeAgentOrders   map[string]any    `json:"dualModeAgentOrders,omitempty"`
	RevocationAndPostLock map[string]any    `json:"revocationAndPostLockGuards,omitempty"`
	ConcurrentIdempotency map[string]any    `json:"dualGatewayConcurrentIdempotency,omitempty"`
	AgentTraces           []agent.RunResult `json:"agentTraces,omitempty"`
}

var (
	procurementEvidenceMu    sync.Mutex
	procurementEvidenceByRun = map[string]*procurementEvidenceReport{}
)

func (a acceptance) recordProcurementEvidence(update func(*procurementEvidenceReport)) error {
	procurementEvidenceMu.Lock()
	defer procurementEvidenceMu.Unlock()
	ev := procurementEvidenceByRun[a.dir]
	if ev == nil {
		ev = &procurementEvidenceReport{
			DeploymentID: a.d.DeploymentID,
			RunID:        a.id,
		}
		procurementEvidenceByRun[a.dir] = ev
	}
	update(ev)
	if err := writePublicJSON(filepath.Join(a.dir, "procurement-delegation.json"), ev); err != nil {
		return err
	}
	if _, err := scanDirForPrivateKeys(a.dir); err != nil {
		return err
	}
	return nil
}

func (a acceptance) ensureTaskContextNormal(srv http.Handler, taskID string, baseNow int64) (int64, error) {
	var curVer int64
	err := a.j.db.QueryRow(a.ctx,
		`SELECT COALESCE(MAX(context_version), 0) FROM trusted_contexts WHERE deployment_id=$1 AND task_id=$2`,
		a.d.DeploymentID, taskID,
	).Scan(&curVer)
	if err != nil {
		return 0, err
	}
	resp, err := gatewaySetContext(srv, taskID, curVer, baseNow-1, "NORMAL", a.f.RPTask.Interval.EXP)
	if err != nil {
		return 0, err
	}
	return resp.ContextVersion, nil
}

func (a acceptance) countOrdersForDeployment() (int, error) {
	var n int
	err := a.j.db.QueryRow(a.ctx, `SELECT count(*) FROM orders WHERE deployment_id=$1`, a.d.DeploymentID).Scan(&n)
	return n, err
}

func (a acceptance) buildLeafExecutePackage(
	srv http.Handler,
	req protocol.AccessRequest,
	taskSpec protocol.TaskSpec,
	leafPriv *ecdsa.PrivateKey,
	leafKeyID string,
	leafPres string,
	ancestors []protocol.AncestorCredential,
	grants []string,
	trustPaths []protocol.TrustPathEntry,
	iatSec int64,
) (protocol.AccessEvidencePackage, gateway.ChallengeResponse, error) {
	reqHash, err := req.Hash(false)
	if err != nil {
		return protocol.AccessEvidencePackage{}, gateway.ChallengeResponse{}, err
	}
	chal, err := gatewayReqChallenge(srv, req.Actor, req.TaskID, reqHash)
	if err != nil {
		return protocol.AccessEvidencePackage{}, gateway.ChallengeResponse{}, err
	}
	pkg := protocol.AccessEvidencePackage{
		Request:             req,
		TaskSpec:            taskSpec,
		ChallengeID:         chal.ChallengeID,
		AncestorCredentials: ancestors,
		Grants:              grants,
		TrustPaths:          trustPaths,
	}
	if _, _, err := protocol.AssembleAccessEvidencePackage(&pkg, leafPres, leafKeyID, leafPriv, protocol.ChallengeContext{
		ChallengeID: chal.ChallengeID,
		Nonce:       chal.Nonce,
		Audience:    chal.Audience,
		IssuedAt:    chal.IssuedAt,
		ExpiresAt:   chal.ExpiresAt,
	}, iatSec, false); err != nil {
		return protocol.AccessEvidencePackage{}, gateway.ChallengeResponse{}, err
	}
	return pkg, chal, nil
}

func (a acceptance) dualRootsAndIdentityLink() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	waitCtx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	_, err = waitOnline(waitCtx, rt, a.f.BMG2.ID)
	cancel()
	if err != nil {
		return err
	}

	sp := NewStateProvider(a.j.db, a.d, rt)
	view, err := sp.AssembleProtocolSnapshot(a.ctx, a.f.BMG2.ID, time.Now().UTC())
	if err != nil {
		return err
	}
	domA, ok := view.Snapshot.Domains["A"]
	if !ok || domA.PurchasingAuthority != a.f.Identities["PA"].ID {
		return fmt.Errorf("Domain A PurchasingAuthority mismatch: got %q want %q", domA.PurchasingAuthority, a.f.Identities["PA"].ID)
	}
	link, ok := view.Snapshot.Links[a.f.IdentityLink.ID]
	if !ok || link.Status != api.Active {
		return fmt.Errorf("IdentityLink %s not ACTIVE on verified snapshot: found=%v status=%q", a.f.IdentityLink.ID, ok, link.Status)
	}

	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()

	baseNow := time.Now().UTC().Truncate(time.Second)
	if err := gateway.EnsureSchema(a.ctx, a.j.db, a.d.DeploymentID, "urn:grad:supplier:C"); err != nil {
		return err
	}
	if _, err := a.j.db.Exec(a.ctx, `UPDATE catalog_prices SET unit_price_minor=80000 WHERE deployment_id=$1 AND product_id=$2`,
		a.d.DeploymentID, gateway.DefaultProductID); err != nil {
		return err
	}

	// Build a custom supplier policy rejecting BUYER_MANDATE to prove C's independent acceptance rule.
	cDID := a.f.Identities["C"].ID
	policyDeadline := baseNow.Add(4 * time.Hour).Unix()
	noBMFiles, noBMDig, err := policy.BuildCustomBundle(
		a.d.DeploymentID, cDID, policy.DefaultPolicyVersion+"-no-bm", a.d.Bootstrap.Root,
		policy.RolesConfig{
			AcceptedAuthorizationModes: []string{api.RP},
			AcceptedAuthorityRoles:     []string{"procurement-authority", "PURCHASING_AUTHORITY"},
			AcceptedBuyerDomains:       []string{"A"},
			AcceptedServiceRoles:       []string{"supplier-service", "RESOURCE_AUTHORITY", "SERVICE", "ResourceOwner"},
		},
		policy.ResourcesConfig{
			AllowedActions:    []string{"quote.read", "order.create"},
			AllowedProductIDs: []string{"urn:grad:product:P1"},
			MaxQuantity:       10,
			PolicyDeadline:    &policyDeadline,
		},
	)
	if err != nil {
		return err
	}
	noBMBundle, err := policy.VerifyAndLoadBundle(noBMFiles, a.d.DeploymentID, cDID, a.d.Bootstrap.Root, noBMDig)
	if err != nil {
		return err
	}
	noBMSrv, err := gateway.NewServer(gateway.Config{
		DB: a.j.db, State: sp.GatewayAdapter(), Delivery: NewDeliveryService(a.j.db), DIDs: resolver, Policy: noBMBundle,
		DeploymentID: a.d.DeploymentID, ServiceDID: cDID, Audience: "https://c.local", SupplierID: "urn:grad:supplier:C",
		NowFn: func() time.Time { return baseNow },
	})
	if err != nil {
		return err
	}

	if _, err := a.ensureTaskContextNormal(noBMSrv.Handler(), a.f.RPTask.ID, baseNow.Unix()); err != nil {
		return err
	}
	if _, err := a.ensureTaskContextNormal(noBMSrv.Handler(), a.f.BMTask.ID, baseNow.Unix()); err != nil {
		return err
	}

	// Load materials cleanly for U-in-B isolation test & BM supplier policy rejection test.
	uInBPriv, err := loadECPrivateKeyPEM(a.instance.privatePath("app", "U-in-B.key.pem"))
	if err != nil {
		return err
	}
	uInBSD, err := os.ReadFile(a.instance.registrySubPath("credentials", "U-in-B.sdjwt"))
	if err != nil {
		return err
	}
	b1Priv, err := loadECPrivateKeyPEM(a.instance.privatePath("app", "B1.key.pem"))
	if err != nil {
		return err
	}
	b1SD, err := os.ReadFile(a.instance.registrySubPath("credentials", "B1.sdjwt"))
	if err != nil {
		return err
	}
	certA, err := os.ReadFile(a.instance.registrySubPath("certifications", "A.jws"))
	if err != nil {
		return err
	}
	certC, err := os.ReadFile(a.instance.registrySubPath("certifications", "C.jws"))
	if err != nil {
		return err
	}
	cSvcSD, err := os.ReadFile(a.instance.registrySubPath("credentials", "C-service.sdjwt"))
	if err != nil {
		cSvcSD, err = os.ReadFile(a.instance.registrySubPath("credentials", "C.sdjwt"))
		if err != nil {
			return err
		}
	}
	paSD, err := os.ReadFile(a.instance.registrySubPath("credentials", "PA.sdjwt"))
	if err != nil {
		return err
	}
	uSD, err := os.ReadFile(a.instance.registrySubPath("credentials", "U.sdjwt"))
	if err != nil {
		return err
	}
	a1SD, err := os.ReadFile(a.instance.registrySubPath("credentials", "A1.sdjwt"))
	if err != nil {
		return err
	}
	rpG0Raw, _ := os.ReadFile(a.instance.registrySubPath("grants", "rp_g0.jws"))
	bmG0Raw, _ := os.ReadFile(a.instance.registrySubPath("grants", "bm_g0.jws"))
	bmG1Raw, _ := os.ReadFile(a.instance.registrySubPath("grants", "bm_g1.jws"))
	bmG2Raw, _ := os.ReadFile(a.instance.registrySubPath("grants", "bm_g2.jws"))
	certB, _ := os.ReadFile(a.instance.registrySubPath("certifications", "B.jws"))
	cCredID := a.f.Credentials["C"].ID
	if cSvc, ok := a.f.Credentials["C-service"]; ok && cSvc.ID != "" {
		cCredID = cSvc.ID
	}

	ordersBefore, err := a.countOrdersForDeployment()
	if err != nil {
		return err
	}

	// 1. U-in-B impersonating U on RP G0 -> must reject with 401 HOLDER_MISMATCH without creating orders.
	uInBReq := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["U-in-B"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.RP, TaskID: a.f.RPTask.ID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:quotes", Action: "quote.read", SupplierID: "urn:grad:supplier:C",
		ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 0, IdempotencyKey: "procurement-uinb-iso-" + a.id,
	}
	uInBPkg, _, err := a.buildLeafExecutePackage(
		noBMSrv.Handler(), uInBReq, a.f.ProcurementTaskSpec, uInBPriv, a.f.Identities["U-in-B"].KeyID, string(uInBSD),
		[]protocol.AncestorCredential{{CredentialID: cCredID, Presentation: string(cSvcSD)}},
		[]string{string(rpG0Raw)},
		[]protocol.TrustPathEntry{
			{Issuer: a.f.Domains["B"].Issuers[0].ID, DomainCertification: string(certB)},
			{Issuer: a.f.Domains["C"].Issuers[0].ID, DomainCertification: string(certC)},
		},
		baseNow.Unix(),
	)
	if err != nil {
		return err
	}
	uInBRec := gatewayPostExecute(noBMSrv.Handler(), uInBPkg)
	if uInBRec.Code != http.StatusUnauthorized || !strings.Contains(uInBRec.Body.String(), protocol.ErrCodeHolderMismatch) {
		return fmt.Errorf("expected 401 HOLDER_MISMATCH rejecting linked U-in-B exercising U path, got %d %s", uInBRec.Code, uInBRec.Body.String())
	}

	// 2. Valid BM path rejected when C policy does not accept BUYER_MANDATE -> 403 SUPPLIER_POLICY_DENIED.
	bmDenyReq := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["B1"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.BM, TaskID: a.f.BMTask.ID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:quotes", Action: "quote.read", SupplierID: "urn:grad:supplier:C",
		ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 0, IdempotencyKey: "procurement-c-deny-bm-" + a.id,
	}
	bmDenyPkg, _, err := a.buildLeafExecutePackage(
		noBMSrv.Handler(), bmDenyReq, a.f.ProcurementTaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD),
		[]protocol.AncestorCredential{
			{CredentialID: a.f.Credentials["PA"].ID, Presentation: string(paSD)},
			{CredentialID: a.f.Credentials["U"].ID, Presentation: string(uSD)},
			{CredentialID: a.f.Credentials["A1"].ID, Presentation: string(a1SD)},
		},
		[]string{string(bmG0Raw), string(bmG1Raw), string(bmG2Raw)},
		[]protocol.TrustPathEntry{
			{Issuer: a.f.Domains["A"].Issuers[0].ID, DomainCertification: string(certA)},
			{Issuer: a.f.Domains["B"].Issuers[0].ID, DomainCertification: string(certB)},
		},
		baseNow.Unix(),
	)
	if err != nil {
		return err
	}
	bmDenyRec := gatewayPostExecute(noBMSrv.Handler(), bmDenyPkg)
	if bmDenyRec.Code != http.StatusForbidden || !strings.Contains(bmDenyRec.Body.String(), protocol.ErrCodeSupplierPolicyDenied) {
		return fmt.Errorf("expected 403 SUPPLIER_POLICY_DENIED for BM under RP-only policy, got %d %s", bmDenyRec.Code, bmDenyRec.Body.String())
	}

	ordersAfter, err := a.countOrdersForDeployment()
	if err != nil {
		return err
	}
	if ordersAfter != ordersBefore {
		return fmt.Errorf("negative dual-root/link checks unexpectedly changed orders count %d -> %d", ordersBefore, ordersAfter)
	}

	return a.recordProcurementEvidence(func(ev *procurementEvidenceReport) {
		ev.DualRootsIdentityLink = map[string]any{
			"purchasingAuthority":    domA.PurchasingAuthority,
			"identityLinkId":         link.ID,
			"identityLinkStatus":     link.Status,
			"uInBIsolationStatus":    uInBRec.Code,
			"supplierPolicyDenyCode": protocol.ErrCodeSupplierPolicyDenied,
			"supplierPolicyStatus":   bmDenyRec.Code,
		}
	})
}

func (a acceptance) mcpDualRootOrders() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	waitCtx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	_, err = waitOnline(waitCtx, rt, a.f.BMG2.ID)
	cancel()
	if err != nil {
		return err
	}

	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()

	baseNow := time.Now().UTC().Truncate(time.Second)
	sp := NewStateProvider(a.j.db, a.d, rt)
	srv, _, err := a.newDirectAccessServer(sp, resolver, nil, func() time.Time { return baseNow })
	if err != nil {
		return err
	}
	if _, err := a.ensureTaskContextNormal(srv.Handler(), a.f.RPTask.ID, baseNow.Unix()); err != nil {
		return err
	}
	if _, err := a.ensureTaskContextNormal(srv.Handler(), a.f.BMTask.ID, baseNow.Unix()); err != nil {
		return err
	}
	defer func() {
		_, _ = a.j.db.Exec(context.Background(), `UPDATE catalog_prices SET unit_price_minor=80000 WHERE deployment_id=$1 AND product_id=$2`,
			a.d.DeploymentID, gateway.DefaultProductID)
	}()

	w, err := buildWalletContext(a.ctx, a.instance, *a.d, a.f, a.j.db, "", srv.Handler(), func() time.Time { return baseNow })
	if err != nil {
		return err
	}

	ordersBefore, err := a.countOrdersForDeployment()
	if err != nil {
		return err
	}

	runModeLoop := func(provider, mode, taskID, grantID string) (*agent.RunResult, error) {
		type scriptAct struct {
			tool string
			args map[string]any
		}
		acts := []scriptAct{
			{"inspect_wallet", map[string]any{"actor": "B1", "taskId": taskID, "authorizationMode": mode}},
			{"request_quote", map[string]any{"actor": "B1", "grantId": grantID, "taskId": taskID, "authorizationMode": mode, "productId": "urn:grad:product:P1", "quantity": 1}},
			{"create_order", map[string]any{"actor": "B1", "grantId": grantID, "taskId": taskID, "authorizationMode": mode, "quoteId": "{{LAST_QUOTE_ID}}", "amountMinor": 80000, "idempotencyKey": fmt.Sprintf("procurement-%s-%s-ok", a.id, mode)}},
			{"request_quote", map[string]any{"actor": "B1", "grantId": grantID, "taskId": taskID, "authorizationMode": mode, "productId": "urn:grad:product:P1", "quantity": 1}},
			{"create_order", map[string]any{"actor": "B1", "grantId": grantID, "taskId": taskID, "authorizationMode": mode, "quoteId": "{{LAST_QUOTE_ID}}", "amountMinor": 100000, "idempotencyKey": fmt.Sprintf("procurement-%s-%s-mismatch", a.id, mode)}},
			{"create_order", map[string]any{"actor": "B1", "grantId": grantID, "taskId": taskID, "authorizationMode": mode, "quoteId": "{{LAST_QUOTE_ID}}", "amountMinor": 120000, "idempotencyKey": fmt.Sprintf("procurement-%s-%s-over", a.id, mode)}},
		}

		var mu sync.Mutex
		step := 0
		lastQuote := ""
		extractQuote := func(txt string) string {
			var m map[string]any
			if json.Unmarshal([]byte(txt), &m) == nil {
				if qid, ok := m["quoteId"].(string); ok && qid != "" {
					return qid
				}
			}
			return ""
		}
		resolve := func(raw map[string]any) map[string]any {
			out := map[string]any{}
			for k, v := range raw {
				if s, ok := v.(string); ok && s == "{{LAST_QUOTE_ID}}" {
					out[k] = lastQuote
				} else {
					out[k] = v
				}
			}
			return out
		}

		var mockSrv *httptest.Server
		if provider == agent.ProviderOpenAI {
			mockSrv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				var req struct {
					Messages []struct {
						Content any `json:"content"`
					} `json:"messages"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				mu.Lock()
				defer mu.Unlock()
				if n := len(req.Messages); n > 0 {
					if cs, ok := req.Messages[n-1].Content.(string); ok {
						if q := extractQuote(cs); q != "" {
							lastQuote = q
						}
					}
				}
				rw.Header().Set("Content-Type", "application/json")
				if step >= len(acts) {
					_, _ = a.j.db.Exec(a.ctx, `UPDATE catalog_prices SET unit_price_minor=80000 WHERE deployment_id=$1 AND product_id=$2`, a.d.DeploymentID, gateway.DefaultProductID)
					_ = json.NewEncoder(rw).Encode(map[string]any{
						"id": "cmpl-m2", "object": "chat.completion", "model": "verify-openai",
						"choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": mode + " closed loop verified."}}},
					})
					return
				}
				act := acts[step]
				if step == 3 {
					_, _ = a.j.db.Exec(a.ctx, `UPDATE catalog_prices SET unit_price_minor=120000 WHERE deployment_id=$1 AND product_id=$2`, a.d.DeploymentID, gateway.DefaultProductID)
				} else if step == 1 {
					_, _ = a.j.db.Exec(a.ctx, `UPDATE catalog_prices SET unit_price_minor=80000 WHERE deployment_id=$1 AND product_id=$2`, a.d.DeploymentID, gateway.DefaultProductID)
				}
				step++
				ab, _ := json.Marshal(resolve(act.args))
				_ = json.NewEncoder(rw).Encode(map[string]any{
					"id": fmt.Sprintf("cmpl-%d", step), "object": "chat.completion", "model": "verify-openai",
					"choices": []any{map[string]any{"index": 0, "finish_reason": "tool_calls", "message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{"id": fmt.Sprintf("call_%d", step), "type": "function", "function": map[string]any{"name": act.tool, "arguments": string(ab)}}},
					}}},
				})
			}))
		} else {
			mockSrv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				var req struct {
					Messages []struct {
						Content []json.RawMessage `json:"content"`
					} `json:"messages"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				mu.Lock()
				defer mu.Unlock()
				if n := len(req.Messages); n > 0 {
					for _, raw := range req.Messages[n-1].Content {
						var blk struct {
							Type    string          `json:"type"`
							Content json.RawMessage `json:"content"`
						}
						if json.Unmarshal(raw, &blk) == nil && blk.Type == "tool_result" {
							var s string
							if json.Unmarshal(blk.Content, &s) == nil {
								if q := extractQuote(s); q != "" {
									lastQuote = q
								}
							} else {
								var arr []struct {
									Text string `json:"text"`
								}
								if json.Unmarshal(blk.Content, &arr) == nil {
									for _, it := range arr {
										if q := extractQuote(it.Text); q != "" {
											lastQuote = q
										}
									}
								}
							}
						}
					}
				}
				rw.Header().Set("Content-Type", "application/json")
				if step >= len(acts) {
					_, _ = a.j.db.Exec(a.ctx, `UPDATE catalog_prices SET unit_price_minor=80000 WHERE deployment_id=$1 AND product_id=$2`, a.d.DeploymentID, gateway.DefaultProductID)
					_ = json.NewEncoder(rw).Encode(map[string]any{
						"id": "msg_done", "type": "message", "role": "assistant", "model": "verify-anthropic",
						"stop_reason": "end_turn", "content": []any{map[string]any{"type": "text", "text": mode + " closed loop verified."}},
						"usage": map[string]any{"input_tokens": 50, "output_tokens": 20},
					})
					return
				}
				act := acts[step]
				if step == 3 {
					_, _ = a.j.db.Exec(a.ctx, `UPDATE catalog_prices SET unit_price_minor=120000 WHERE deployment_id=$1 AND product_id=$2`, a.d.DeploymentID, gateway.DefaultProductID)
				} else if step == 1 {
					_, _ = a.j.db.Exec(a.ctx, `UPDATE catalog_prices SET unit_price_minor=80000 WHERE deployment_id=$1 AND product_id=$2`, a.d.DeploymentID, gateway.DefaultProductID)
				}
				step++
				_ = json.NewEncoder(rw).Encode(map[string]any{
					"id": fmt.Sprintf("msg_%d", step), "type": "message", "role": "assistant", "model": "verify-anthropic",
					"stop_reason": "tool_use",
					"content":     []any{map[string]any{"type": "tool_use", "id": fmt.Sprintf("tu_%d", step), "name": act.tool, "input": resolve(act.args)}},
					"usage":       map[string]any{"input_tokens": 50, "output_tokens": 30},
				})
			}))
		}
		defer mockSrv.Close()

		baseURL := mockSrv.URL
		if provider == agent.ProviderOpenAI {
			baseURL += "/v1"
		}
		return agent.RunAgentTask(a.ctx, agent.NewMCPServer(w), agent.RunnerConfig{
			Provider: provider, BaseURL: baseURL, APIKey: "sk-verify-local", Model: "verify-" + provider, MaxSteps: 10,
		}, "Verify "+mode+" closed loop.")
	}

	rpRes, err := runModeLoop(agent.ProviderOpenAI, api.RP, a.f.RPTask.ID, a.f.RPG2.ID)
	if err != nil {
		return fmt.Errorf("RP OpenAI agent run: %w", err)
	}
	bmRes, err := runModeLoop(agent.ProviderAnthropic, api.BM, a.f.BMTask.ID, a.f.BMG2.ID)
	if err != nil {
		return fmt.Errorf("BM Anthropic agent run: %w", err)
	}

	checkModeResult := func(mode string, r *agent.RunResult) error {
		if r.ToolCallsCount != 6 {
			return fmt.Errorf("%s expected 6 tool calls, got %d", mode, r.ToolCallsCount)
		}
		okOut := r.ToolTraces[2].Output
		if okOut["decision"] != "ALLOW" || okOut["orderId"] == "" || okOut["actionStatus"] != "COMPLETED" {
			return fmt.Errorf("%s 800 order did not ALLOW/COMPLETED: %+v", mode, okOut)
		}
		misOut := r.ToolTraces[4].Output
		if misOut["decision"] != "DENY" || misOut["errorCode"] != protocol.ErrCodeAmountMismatch {
			return fmt.Errorf("%s expected AMOUNT_MISMATCH on 100000 vs Q1200, got %+v", mode, misOut)
		}
		overOut := r.ToolTraces[5].Output
		if overOut["decision"] != "DENY" || overOut["errorCode"] != protocol.ErrCodeAmountLimitExceeded {
			return fmt.Errorf("%s expected AMOUNT_LIMIT_EXCEEDED on 120000, got %+v", mode, overOut)
		}
		return nil
	}
	if err := checkModeResult(api.RP, rpRes); err != nil {
		return err
	}
	if err := checkModeResult(api.BM, bmRes); err != nil {
		return err
	}

	traces := []agent.RunResult{*rpRes, *bmRes}

	// Optional live LLM closed loop when configured in environment.
	if liveCfg := agent.LoadRunnerConfigFromEnv(); liveCfg.APIKey != "" && liveCfg.BaseURL != "" && liveCfg.Model != "" {
		w.RegisterSecret(liveCfg.APIKey)
		livePrompt := fmt.Sprintf("Inspect B1 grants for task %s (%s). Request a quote for productId %s quantity 1 (80000 minor), then create_order using amountMinor 80000 and unique idempotencyKey procurement-live-%s. Also inspect whether 120000 minor would exceed G2 limit.",
			a.f.RPTask.ID, api.RP, gateway.DefaultProductID, a.id)
		liveRes, liveErr := agent.RunAgentTask(a.ctx, agent.NewMCPServer(w), liveCfg, livePrompt)
		if liveErr != nil {
			return fmt.Errorf("configured live LLM agent closed loop failed: %w", liveErr)
		}
		if liveRes.ToolCallsCount < 2 {
			return fmt.Errorf("live LLM run made too few tool calls: %d", liveRes.ToolCallsCount)
		}
		traces = append(traces, *liveRes)
	}

	ordersAfter, err := a.countOrdersForDeployment()
	if err != nil {
		return err
	}
	expectedNew := 2
	if len(traces) > 2 {
		// Live LLM run may also place at most one 80000 order if it executed create_order.
		if ordersAfter < ordersBefore+2 {
			return fmt.Errorf("expected at least 2 new orders (RP 800 + BM 800), got %d", ordersAfter-ordersBefore)
		}
		expectedNew = ordersAfter - ordersBefore
	} else if ordersAfter != ordersBefore+2 {
		return fmt.Errorf("expected exactly 2 new orders (RP 800 + BM 800), got %d", ordersAfter-ordersBefore)
	}

	if err := writePublicJSON(filepath.Join(a.dir, "procurement-agent-traces.json"), traces); err != nil {
		return err
	}
	return a.recordProcurementEvidence(func(ev *procurementEvidenceReport) {
		ev.AgentTraces = traces
		ev.DualModeAgentOrders = map[string]any{
			"rpOrderId":     rpRes.ToolTraces[2].Output["orderId"],
			"bmOrderId":     bmRes.ToolTraces[2].Output["orderId"],
			"newOrders":     expectedNew,
			"q1200Mismatch": protocol.ErrCodeAmountMismatch,
			"q1200OverCode": protocol.ErrCodeAmountLimitExceeded,
		}
	})
}

func (a acceptance) revocationAndPostLockOrderGuards() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	waitCtx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	_, err = waitOnline(waitCtx, rt, a.f.RPG2.ID)
	cancel()
	if err != nil {
		return err
	}

	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()

	baseNow := time.Now().UTC().Truncate(time.Second)
	sp := NewStateProvider(a.j.db, a.d, rt)
	srvNormal, _, err := a.newDirectAccessServer(sp, resolver, nil, func() time.Time { return baseNow })
	if err != nil {
		return err
	}
	curVer, err := a.ensureTaskContextNormal(srvNormal.Handler(), a.f.RPTask.ID, baseNow.Unix())
	if err != nil {
		return err
	}

	// Obtain a valid 800 quote while context is NORMAL.
	b1Priv, err := loadECPrivateKeyPEM(a.instance.privatePath("app", "B1.key.pem"))
	if err != nil {
		return err
	}
	b1SD, err := os.ReadFile(a.instance.registrySubPath("credentials", "B1.sdjwt"))
	if err != nil {
		return err
	}
	certA, _ := os.ReadFile(a.instance.registrySubPath("certifications", "A.jws"))
	certB, _ := os.ReadFile(a.instance.registrySubPath("certifications", "B.jws"))
	certC, _ := os.ReadFile(a.instance.registrySubPath("certifications", "C.jws"))
	cSvcSD, err := os.ReadFile(a.instance.registrySubPath("credentials", "C-service.sdjwt"))
	if err != nil {
		cSvcSD, _ = os.ReadFile(a.instance.registrySubPath("credentials", "C.sdjwt"))
	}
	uSD, _ := os.ReadFile(a.instance.registrySubPath("credentials", "U.sdjwt"))
	a1SD, _ := os.ReadFile(a.instance.registrySubPath("credentials", "A1.sdjwt"))
	rpG0Raw, _ := os.ReadFile(a.instance.registrySubPath("grants", "rp_g0.jws"))
	rpG1Raw, _ := os.ReadFile(a.instance.registrySubPath("grants", "rp_g1.jws"))
	rpG2Raw, _ := os.ReadFile(a.instance.registrySubPath("grants", "rp_g2.jws"))
	cCredID := a.f.Credentials["C"].ID
	if cSvc, ok := a.f.Credentials["C-service"]; ok && cSvc.ID != "" {
		cCredID = cSvc.ID
	}

	ancestors := []protocol.AncestorCredential{
		{CredentialID: cCredID, Presentation: string(cSvcSD)},
		{CredentialID: a.f.Credentials["U"].ID, Presentation: string(uSD)},
		{CredentialID: a.f.Credentials["A1"].ID, Presentation: string(a1SD)},
	}
	tpRP := []protocol.TrustPathEntry{
		{Issuer: a.f.Domains["A"].Issuers[0].ID, DomainCertification: string(certA)},
		{Issuer: a.f.Domains["B"].Issuers[0].ID, DomainCertification: string(certB)},
		{Issuer: a.f.Domains["C"].Issuers[0].ID, DomainCertification: string(certC)},
	}

	qReq := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["B1"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.RP, TaskID: a.f.RPTask.ID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:quotes", Action: "quote.read", SupplierID: "urn:grad:supplier:C",
		ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 0, IdempotencyKey: "procurement-lock-q-" + a.id,
	}
	qPkg, _, err := a.buildLeafExecutePackage(srvNormal.Handler(), qReq, a.f.ProcurementTaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), ancestors, []string{string(rpG0Raw), string(rpG1Raw), string(rpG2Raw)}, tpRP, baseNow.Unix())
	if err != nil {
		return err
	}
	qRec := gatewayPostExecute(srvNormal.Handler(), qPkg)
	if qRec.Code != http.StatusOK {
		return fmt.Errorf("pre-lock quote failed: %d %s", qRec.Code, qRec.Body.String())
	}
	var qResp gateway.ExecuteResponse
	_ = json.Unmarshal(qRec.Body.Bytes(), &qResp)

	// 1. Post-lock context transition to BLOCKED -> 403 POLICY_DENIED & 0 orders added.
	var flipped atomic.Bool
	srvBlocked, _, err := a.newDirectAccessServer(sp, resolver, nil, func() time.Time { return baseNow })
	if err != nil {
		return err
	}
	srvBlocked.SetTestHooks(func(attempt int) {
		if attempt == 0 && flipped.CompareAndSwap(false, true) {
			_, _ = gatewaySetContext(srvNormal.Handler(), a.f.RPTask.ID, curVer, baseNow.Unix(), "BLOCKED", a.f.RPTask.Interval.EXP)
		}
	}, nil)
	ordersBefore, err := a.countOrdersForDeployment()
	if err != nil {
		return err
	}
	ordBlockedReq := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["B1"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.RP, TaskID: a.f.RPTask.ID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:orders", Action: "order.create", SupplierID: "urn:grad:supplier:C",
		QuoteID: &qResp.Quote.QuoteID, ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 80000,
		IdempotencyKey: "procurement-postlock-blocked-" + a.id,
	}
	ordBlockedPkg, _, err := a.buildLeafExecutePackage(srvBlocked.Handler(), ordBlockedReq, a.f.ProcurementTaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), ancestors, []string{string(rpG0Raw), string(rpG1Raw), string(rpG2Raw)}, tpRP, baseNow.Unix())
	if err != nil {
		return err
	}
	ordBlockedRec := gatewayPostExecute(srvBlocked.Handler(), ordBlockedPkg)
	if ordBlockedRec.Code != http.StatusForbidden || !strings.Contains(ordBlockedRec.Body.String(), protocol.ErrCodePolicyDenied) {
		return fmt.Errorf("expected 403 POLICY_DENIED on post-lock BLOCKED order, got %d %s", ordBlockedRec.Code, ordBlockedRec.Body.String())
	}
	ordersAfterBlocked, _ := a.countOrdersForDeployment()
	if ordersAfterBlocked != ordersBefore {
		return fmt.Errorf("post-lock BLOCKED unexpectedly added order row")
	}
	// Restore NORMAL context cleanly.
	_, _ = gatewaySetContext(srvNormal.Handler(), a.f.RPTask.ID, curVer+1, baseNow.Unix()+1, "NORMAL", a.f.RPTask.Interval.EXP)

	// 2. Live Fabric G1 revocation block adoption -> ANCESTOR_INACTIVE on child G2 order.create.
	uPriv, err := loadECPrivateKeyPEM(a.instance.privatePath("app", "U.key.pem"))
	if err != nil {
		return err
	}
	a1Priv, err := loadECPrivateKeyPEM(a.instance.privatePath("app", "A1.key.pem"))
	if err != nil {
		return err
	}
	cPriv, err := loadECPrivateKeyPEM(a.instance.privatePath("app", "C.key.pem"))
	if err != nil {
		return err
	}
	revTaskID := api.Digest([]byte("procurement-rev-task:" + a.id))
	revG0ID := api.Digest([]byte("procurement-rev-g0:" + a.id))
	revG1ID := api.Digest([]byte("procurement-rev-g1:" + a.id))
	revG2ID := api.Digest([]byte("procurement-rev-g2:" + a.id))
	specDig, _ := a.f.ProcurementTaskSpec.Digest()
	valid := a.f.RPTask.Interval
	revTask := api.Task{
		Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: revTaskID, Creator: a.f.Identities["U"].ID,
		CreatorKeyVersion: 1, CreatorCredential: a.f.Credentials["U"].ID, Resource: a.f.RPTask.Resource,
		Mode: api.RP, Domain: "A", Digest: specDig, Interval: valid,
	}
	if _, err := a.op("procurement-rev-task-"+a.id, "U", "RegisterTask", revTask, "VALID"); err != nil {
		return err
	}
	mkChainGrant := func(opName, issuerRole, id string, parent, parentDig *string, iss, issCred string, issPriv *ecdsa.PrivateKey, sub, subCred string, maxAmt int64, depth int64) (api.Grant, string, string, *operation, error) {
		claims := protocol.GrantClaims{
			SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, ID: id, RootID: revG0ID,
			ParentID: parent, ParentDigest: parentDig, TaskID: revTaskID, AuthorizationMode: api.RP,
			PrincipalDomain: "A", ResourceID: revTask.Resource, Aud: "https://c.local",
			Issuer: iss, IssuerKeyVersion: 1, IssuerCredentialID: issCred,
			Grantee: sub, GranteeKeyVersion: 1, GranteeCredentialID: subCred,
			Resources: a.f.ProcurementTaskSpec.Resources, Actions: a.f.ProcurementTaskSpec.Actions, Suppliers: []string{"urn:grad:supplier:C"},
			Currency: "CNY", MaxAmountMinor: maxAmt, NBF: valid.NBF, EXP: valid.EXP, RemainingDepth: depth,
		}
		jws, dig, signErr := protocol.SignGrant(issPriv, iss+"#key-1", &claims)
		if signErr != nil {
			return api.Grant{}, "", "", nil, signErr
		}
		var pID, pDig string
		if parent != nil {
			pID = *parent
		}
		if parentDig != nil {
			pDig = *parentDig
		}
		g := api.Grant{
			Bound: api.Bound{DeploymentID: a.d.DeploymentID}, ID: id, Schema: api.Schema, Parent: pID, ParentDigest: pDig,
			Root: revG0ID, Task: revTaskID, Mode: api.RP, Domain: "A", Resource: revTask.Resource,
			Issuer: iss, IssuerKeyVersion: 1, IssuerCredential: issCred, Grantee: sub, GranteeKeyVersion: 1, GranteeCredential: subCred,
			Depth: uint8(depth), Digest: dig, Interval: valid,
		}
		op, opErr := a.op(opName, issuerRole, "RegisterGrant", g, "VALID")
		return g, jws, dig, op, opErr
	}
	revG0, revG0JWS, revG0Dig, op0, err := mkChainGrant("procurement-rev-g0-"+a.id, "C", revG0ID, nil, nil, a.f.Identities["C"].ID, cCredID, cPriv, a.f.Identities["U"].ID, a.f.Credentials["U"].ID, 500000, 2)
	if err != nil {
		return err
	}
	revG1, revG1JWS, revG1Dig, op1, err := mkChainGrant("procurement-rev-g1-"+a.id, "U", revG1ID, &revG0.ID, &revG0Dig, a.f.Identities["U"].ID, a.f.Credentials["U"].ID, uPriv, a.f.Identities["A1"].ID, a.f.Credentials["A1"].ID, 500000, 1)
	if err != nil {
		return err
	}
	revG2, revG2JWS, _, op2, err := mkChainGrant("procurement-rev-g2-"+a.id, "A1", revG2ID, &revG1.ID, &revG1Dig, a.f.Identities["A1"].ID, a.f.Credentials["A1"].ID, a1Priv, a.f.Identities["B1"].ID, a.f.Credentials["B1"].ID, 100000, 0)
	if err != nil {
		return err
	}

	// Material assembly must wait for the VALID registration block, not an older fresh checkpoint.
	if err := a.waitApplied(op2.Commit.Number); err != nil {
		return err
	}
	waitActiveCtx, cancelActive := context.WithTimeout(a.ctx, 12*time.Second)
	_, err = waitOnline(waitActiveCtx, rt, revG2.ID)
	cancelActive()
	if err != nil {
		return err
	}

	// Publish & confirm outbox receipts for revG0, revG1, revG2 so delivery check passes cleanly.
	ds := NewDeliveryService(a.j.db)
	rootPub, _, _ := protocol.ParseAppPublicKey(a.d.Bootstrap.Root.PublicKey)
	icPub, _, _ := protocol.ParseAppPublicKey(a.f.Domains["C"].Issuers[0].PublicKey)
	iaPub, _, _ := protocol.ParseAppPublicKey(a.f.Domains["A"].Issuers[0].PublicKey)
	snapView, err := sp.AssembleProtocolSnapshot(a.ctx, revG2.ID, baseNow)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		g         api.Grant
		jws       string
		anc       []string
		grantorSD []byte
		cert      []byte
		issPub    *ecdsa.PublicKey
		grantor   *ecdsa.PublicKey
		op        *operation
	}{
		{revG0, revG0JWS, nil, cSvcSD, certC, icPub, &cPriv.PublicKey, op0},
		{revG1, revG1JWS, []string{revG0JWS}, uSD, certA, iaPub, &uPriv.PublicKey, op1},
		{revG2, revG2JWS, []string{revG0JWS, revG1JWS}, a1SD, certA, iaPub, &a1Priv.PublicKey, op2},
	} {
		pkg := GrantDeliveryPackage{
			DeploymentID: a.d.DeploymentID, Recipient: item.g.Grantee, GrantID: item.g.ID, GrantJWS: item.jws,
			TaskSpec: a.f.ProcurementTaskSpec, ServicePresentation: string(item.grantorSD), DomainCertificationJWS: string(item.cert), AncestorGrants: item.anc,
		}
		if _, err := ds.PublishGrantOutbox(a.ctx, snapView.Snapshot, pkg, rootPub, item.issPub, item.grantor, item.op.TxID, int64(item.op.Commit.Number), true, baseNow.Unix()); err != nil {
			return err
		}
		if _, _, err := ds.DeliverGrantReceipt(a.ctx, snapView.Snapshot, a.d.DeploymentID, item.g.Grantee, item.g.ID, nil, rootPub, item.issPub, item.grantor, baseNow.Unix()); err != nil {
			return err
		}
	}

	if _, err := a.ensureTaskContextNormal(srvNormal.Handler(), revTaskID, baseNow.Unix()); err != nil {
		return err
	}
	revQReq := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["B1"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.RP, TaskID: revTaskID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:quotes", Action: "quote.read", SupplierID: "urn:grad:supplier:C",
		ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 0, IdempotencyKey: "procurement-rev-q-" + a.id,
	}
	revQPkg, _, err := a.buildLeafExecutePackage(srvNormal.Handler(), revQReq, a.f.ProcurementTaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), ancestors, []string{revG0JWS, revG1JWS, revG2JWS}, tpRP, baseNow.Unix())
	if err != nil {
		return err
	}
	revQRec := gatewayPostExecute(srvNormal.Handler(), revQPkg)
	if revQRec.Code != http.StatusOK {
		return fmt.Errorf("ephemeral quote before revocation failed: %d %s", revQRec.Code, revQRec.Body.String())
	}
	var revQResp gateway.ExecuteResponse
	_ = json.Unmarshal(revQRec.Body.Bytes(), &revQResp)

	// Revoke G1 on Fabric and adopt block r!
	revStored := snapView.Snapshot.Grants[revG1.ID]
	revOp, err := a.op("procurement-revoke-g1-"+a.id, "U", "RevokeGrant", revokeOf(revStored), "VALID")
	if err != nil {
		return err
	}
	if err := poll(a.ctx, 12*time.Second, func() (bool, error) {
		cur, sErr := sp.AssembleProtocolSnapshot(a.ctx, revG2.ID, baseNow)
		if sErr != nil {
			return false, nil
		}
		if g, ok := cur.Snapshot.Grants[revG1.ID]; ok && g.Version.Status == api.Revoked && cur.Snapshot.Height >= revOp.Commit.Number {
			return true, nil
		}
		return false, nil
	}); err != nil {
		return fmt.Errorf("wait revocation block %d adoption: %w", revOp.Commit.Number, err)
	}

	revOrdReq := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["B1"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.RP, TaskID: revTaskID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:orders", Action: "order.create", SupplierID: "urn:grad:supplier:C",
		QuoteID: &revQResp.Quote.QuoteID, ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 80000,
		IdempotencyKey: "procurement-rev-ord-" + a.id,
	}
	revOrdPkg, _, err := a.buildLeafExecutePackage(srvNormal.Handler(), revOrdReq, a.f.ProcurementTaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), ancestors, []string{revG0JWS, revG1JWS, revG2JWS}, tpRP, baseNow.Unix())
	if err != nil {
		return err
	}
	revOrdRec := gatewayPostExecute(srvNormal.Handler(), revOrdPkg)
	if revOrdRec.Code != http.StatusForbidden || !strings.Contains(revOrdRec.Body.String(), protocol.ErrCodeAncestorInactive) {
		return fmt.Errorf("expected 403 ANCESTOR_INACTIVE after G1 revocation block, got %d %s", revOrdRec.Code, revOrdRec.Body.String())
	}
	ordersAfterRev, _ := a.countOrdersForDeployment()
	if ordersAfterRev != ordersBefore {
		return fmt.Errorf("ANCESTOR_INACTIVE order unexpectedly created row in orders")
	}

	return a.recordProcurementEvidence(func(ev *procurementEvidenceReport) {
		ev.RevocationAndPostLock = map[string]any{
			"postLockBlockedStatus":   ordBlockedRec.Code,
			"postLockBlockedCode":     protocol.ErrCodePolicyDenied,
			"revokedGrantId":          revG1.ID,
			"revocationBlockNumber":   revOp.Commit.Number,
			"ancestorInactiveStatus":  revOrdRec.Code,
			"ancestorInactiveErrCode": protocol.ErrCodeAncestorInactive,
		}
	})
}

func (a acceptance) dualGatewayConcurrentIdempotency() error {
	rt := newRuntime(a)
	stop, err := rt.start(a.ctx)
	if err != nil {
		return err
	}
	defer stop()
	waitCtx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	_, err = waitOnline(waitCtx, rt, a.f.RPG2.ID)
	cancel()
	if err != nil {
		return err
	}

	didSrv, resolver, err := a.newControlledDIDResolver()
	if err != nil {
		return err
	}
	defer didSrv.Close()

	baseNow := time.Now().UTC().Truncate(time.Second)
	sp := NewStateProvider(a.j.db, a.d, rt)
	gw1, _, err := a.newDirectAccessServer(sp, resolver, nil, func() time.Time { return baseNow })
	if err != nil {
		return err
	}
	gw2, _, err := a.newDirectAccessServer(sp, resolver, nil, func() time.Time { return baseNow })
	if err != nil {
		return err
	}
	if _, err := a.ensureTaskContextNormal(gw1.Handler(), a.f.RPTask.ID, baseNow.Unix()); err != nil {
		return err
	}

	b1Priv, _ := loadECPrivateKeyPEM(a.instance.privatePath("app", "B1.key.pem"))
	b1SD, _ := os.ReadFile(a.instance.registrySubPath("credentials", "B1.sdjwt"))
	certA, _ := os.ReadFile(a.instance.registrySubPath("certifications", "A.jws"))
	certB, _ := os.ReadFile(a.instance.registrySubPath("certifications", "B.jws"))
	certC, _ := os.ReadFile(a.instance.registrySubPath("certifications", "C.jws"))
	cSvcSD, err := os.ReadFile(a.instance.registrySubPath("credentials", "C-service.sdjwt"))
	if err != nil {
		cSvcSD, _ = os.ReadFile(a.instance.registrySubPath("credentials", "C.sdjwt"))
	}
	uSD, _ := os.ReadFile(a.instance.registrySubPath("credentials", "U.sdjwt"))
	a1SD, _ := os.ReadFile(a.instance.registrySubPath("credentials", "A1.sdjwt"))
	rpG0Raw, _ := os.ReadFile(a.instance.registrySubPath("grants", "rp_g0.jws"))
	rpG1Raw, _ := os.ReadFile(a.instance.registrySubPath("grants", "rp_g1.jws"))
	rpG2Raw, _ := os.ReadFile(a.instance.registrySubPath("grants", "rp_g2.jws"))
	cCredID := a.f.Credentials["C"].ID
	if cSvc, ok := a.f.Credentials["C-service"]; ok && cSvc.ID != "" {
		cCredID = cSvc.ID
	}

	ancestors := []protocol.AncestorCredential{
		{CredentialID: cCredID, Presentation: string(cSvcSD)},
		{CredentialID: a.f.Credentials["U"].ID, Presentation: string(uSD)},
		{CredentialID: a.f.Credentials["A1"].ID, Presentation: string(a1SD)},
	}
	tpRP := []protocol.TrustPathEntry{
		{Issuer: a.f.Domains["A"].Issuers[0].ID, DomainCertification: string(certA)},
		{Issuer: a.f.Domains["B"].Issuers[0].ID, DomainCertification: string(certB)},
		{Issuer: a.f.Domains["C"].Issuers[0].ID, DomainCertification: string(certC)},
	}

	qReq := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["B1"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.RP, TaskID: a.f.RPTask.ID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:quotes", Action: "quote.read", SupplierID: "urn:grad:supplier:C",
		ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 0, IdempotencyKey: "procurement-dual-q-" + a.id,
	}
	qPkg, _, err := a.buildLeafExecutePackage(gw1.Handler(), qReq, a.f.ProcurementTaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), ancestors, []string{string(rpG0Raw), string(rpG1Raw), string(rpG2Raw)}, tpRP, baseNow.Unix())
	if err != nil {
		return err
	}
	qRec := gatewayPostExecute(gw1.Handler(), qPkg)
	if qRec.Code != http.StatusOK {
		return fmt.Errorf("dual-gw quote failed: %d %s", qRec.Code, qRec.Body.String())
	}
	var qResp gateway.ExecuteResponse
	_ = json.Unmarshal(qRec.Body.Bytes(), &qResp)

	sharedIdem := "procurement-dual-ord-" + a.id
	ordReq := protocol.AccessRequest{
		SchemaVersion: api.Schema, DeploymentID: a.d.DeploymentID, Actor: a.f.Identities["B1"].ID,
		PrincipalDomain: "A", AuthorizationMode: api.RP, TaskID: a.f.RPTask.ID, Audience: "https://c.local",
		Resource: "urn:grad:resource:C:orders", Action: "order.create", SupplierID: "urn:grad:supplier:C",
		QuoteID: &qResp.Quote.QuoteID, ProductID: "urn:grad:product:P1", Quantity: 1, Currency: "CNY", AmountMinor: 80000,
		IdempotencyKey: sharedIdem,
	}
	pkg1, ch1, err := a.buildLeafExecutePackage(gw1.Handler(), ordReq, a.f.ProcurementTaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), ancestors, []string{string(rpG0Raw), string(rpG1Raw), string(rpG2Raw)}, tpRP, baseNow.Unix())
	if err != nil {
		return err
	}
	pkg2, ch2, err := a.buildLeafExecutePackage(gw2.Handler(), ordReq, a.f.ProcurementTaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), ancestors, []string{string(rpG0Raw), string(rpG1Raw), string(rpG2Raw)}, tpRP, baseNow.Unix())
	if err != nil {
		return err
	}
	if ch1.ChallengeID == ch2.ChallengeID {
		return fmt.Errorf("expected two distinct challenges for dual-instance test")
	}

	var rec1, rec2 *httptest.ResponseRecorder
	var wg sync.WaitGroup
	startGate := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-startGate
		rec1 = gatewayPostExecute(gw1.Handler(), pkg1)
	}()
	go func() {
		defer wg.Done()
		<-startGate
		rec2 = gatewayPostExecute(gw2.Handler(), pkg2)
	}()
	close(startGate)
	wg.Wait()

	if rec1.Code != http.StatusOK || rec2.Code != http.StatusOK {
		return fmt.Errorf("dual gateway concurrent responses failed: gw1=(%d %s) gw2=(%d %s)", rec1.Code, rec1.Body.String(), rec2.Code, rec2.Body.String())
	}
	var resp1, resp2 gateway.ExecuteResponse
	_ = json.Unmarshal(rec1.Body.Bytes(), &resp1)
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
	if resp1.Order == nil || resp2.Order == nil || resp1.Order.OrderID != resp2.Order.OrderID {
		return fmt.Errorf("concurrent dual gateway returned mismatched orders: %+v vs %+v", resp1.Order, resp2.Order)
	}

	var cnt int
	if err := a.j.db.QueryRow(a.ctx, `SELECT count(*) FROM orders WHERE deployment_id=$1 AND idempotency_key=$2`,
		a.d.DeploymentID, sharedIdem).Scan(&cnt); err != nil {
		return err
	}
	if cnt != 1 {
		return fmt.Errorf("expected exactly 1 order row for idempotency_key=%s, got %d", sharedIdem, cnt)
	}

	// Same idempotencyKey + altered amountMinor -> 409 IDEMPOTENCY_CONFLICT.
	conflictReq := ordReq
	conflictReq.AmountMinor = 90000
	conflictPkg, _, err := a.buildLeafExecutePackage(gw2.Handler(), conflictReq, a.f.ProcurementTaskSpec, b1Priv, a.f.Identities["B1"].KeyID, string(b1SD), ancestors, []string{string(rpG0Raw), string(rpG1Raw), string(rpG2Raw)}, tpRP, baseNow.Unix())
	if err != nil {
		return err
	}
	conflictRec := gatewayPostExecute(gw2.Handler(), conflictPkg)
	if conflictRec.Code != http.StatusConflict || !bytes.Contains(conflictRec.Body.Bytes(), []byte(protocol.ErrCodeIdempotencyConflict)) {
		return fmt.Errorf("expected 409 IDEMPOTENCY_CONFLICT on same key / different requestHash, got %d %s", conflictRec.Code, conflictRec.Body.String())
	}

	return a.recordProcurementEvidence(func(ev *procurementEvidenceReport) {
		ev.ConcurrentIdempotency = map[string]any{
			"challenge1":      ch1.ChallengeID,
			"challenge2":      ch2.ChallengeID,
			"sharedOrderId":   resp1.Order.OrderID,
			"orderRowsForKey": cnt,
			"conflictStatus":  conflictRec.Code,
			"conflictErrCode": protocol.ErrCodeIdempotencyConflict,
		}
	})
}
