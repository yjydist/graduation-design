package fabric

import (
	"fmt"
	"net/http"
	"time"

	"graduation-design/internal/agent"
	api "graduation-design/internal/fabricapi"
	"graduation-design/internal/protocol"
)

func (a acceptance) runLiveAgentRecoveryChecks(rt *online, sp *StateProvider, handler http.Handler,
	buildWallet func(*ephemeralRPChain) (*agent.WalletContext, error),
	dropRT *dropAfterHTTPTransport, baseNow time.Time, cfg agent.RunnerConfig,
) ([]agent.RunResult, error) {
	var traces []agent.RunResult
	for _, scenario := range []string{"b2-replacement", "b1-reconciliation"} {
		chain, err := a.provisionEphemeralRPChain(rt, sp, "llm-"+scenario+"-"+a.id[:8], 500000, false, baseNow)
		if err != nil {
			return traces, err
		}
		if _, err := a.ensureTaskContextNormal(handler, chain.Task.ID, baseNow.Unix()); err != nil {
			return traces, err
		}
		wallet, err := buildWallet(chain)
		if err != nil {
			return traces, err
		}
		wallet.RegisterSecret(cfg.APIKey)
		g2 := api.Digest([]byte("agent-recovery-llm-g2-" + scenario + a.id))
		g2p := api.Digest([]byte("agent-recovery-llm-g2p-" + scenario + a.id))
		key := "agent-recovery-llm-" + scenario + "-" + a.id[:8]
		prompt := fmt.Sprintf("Run this controlled procurement acceptance scenario strictly in order using MCP tools. "+
			"Use authorizationMode=%q and taskId=%q for ALL calls.\n"+
			"1. delegate_grant issuerActor=A1 subjectActor=B1 parentGrantId=%q grantId=%q maxAmountMinor=100000 remainingDepth=0.\n"+
			"2. request_quote actor=B1 grantId=%q productId=urn:grad:product:P1 quantity=1. Save B1's quoteId.\n",
			api.RP, chain.Task.ID, chain.G1.ID, g2, g2)
		if scenario == "b2-replacement" {
			prompt += fmt.Sprintf("3. replace_grant issuerActor=A1 oldGrantId=%q newSubjectActor=B2 newGrantId=%q maxAmountMinor=100000 remainingDepth=0.\n"+
				"4. As a required negative control, create_order actor=B2 grantId=%q using B1's quoteId, amountMinor=80000 idempotencyKey=%q. Expect 403 QUOTE_SCOPE_MISMATCH; do not stop on that expected denial.\n"+
				"5. request_quote actor=B2 grantId=%q productId=urn:grad:product:P1 quantity=1.\n"+
				"6. create_order actor=B2 grantId=%q using B2's NEW quoteId, amountMinor=80000 idempotencyKey=%q. Expect success.\n",
				g2, g2p, g2p, key+"-wrong-quote", g2p, g2p, key)
		} else {
			dropRT.MarkDropAfter(key, func() error {
				op, err := a.op("agent-recovery-llm-s63-revoke-"+a.id[:8], "U", "RevokeGrant", revokeOf(chain.G1), "VALID")
				if err != nil {
					return err
				}
				return poll(a.ctx, 12*time.Second, func() (bool, error) {
					cur, err := sp.AssembleProtocolSnapshot(a.ctx, g2, time.Now())
					return err == nil && cur.Snapshot.Height >= op.Commit.Number && cur.Snapshot.Grants[chain.G1.ID].Status == api.Revoked, nil
				})
			})
			prompt += fmt.Sprintf("3. create_order actor=B1 grantId=%q using B1's quoteId, amountMinor=80000 idempotencyKey=%q. The test commits the order, drops its response and revokes G1: expect OUTCOME_UNKNOWN.\n"+
				"4. Retry create_order exactly once with the SAME actor, grantId, quoteId, amount and idempotencyKey. Expect 403 ANCESTOR_INACTIVE.\n"+
				"5. reconcile_order actor=B1 idempotencyKey=%q. Expect CREATED and historicalStatus=MATCHED with the original orderId.\n",
				g2, key, key)
		}
		prompt += "Use the actual returned quoteIds. Finish with a short result after all required tools complete."
		cfg.MaxSteps = 12
		a.log.event("llm_case_start", map[string]any{"scenario": scenario, "provider": cfg.Provider, "model": cfg.Model})
		res, err := agent.RunAgentTask(a.ctx, agent.NewMCPServer(wallet), cfg, prompt)
		if err != nil {
			return traces, fmt.Errorf("live LLM E3 %s failed (%s/%s): %w", scenario, cfg.Provider, cfg.Model, err)
		}
		traces = append(traces, *res)
		if err := verifyAgentRecoveryTrace(scenario, res); err != nil {
			return traces, err
		}
		a.log.event("llm_case_result", map[string]any{"scenario": scenario, "toolCalls": res.ToolCallsCount, "llmLatencyMs": res.LLMLatencyMs})
	}
	return traces, nil
}

func verifyAgentRecoveryTrace(scenario string, res *agent.RunResult) error {
	var negative, completed, unknown bool
	for _, tr := range res.ToolTraces {
		if scenario == "b2-replacement" {
			negative = negative || tr.Output["errorCode"] == protocol.ErrCodeQuoteScopeMismatch
			completed = completed || tr.ToolName == "create_order" && tr.Output["decision"] == "ALLOW" && tr.Arguments["actor"] == "B2"
		} else {
			unknown = unknown || tr.Output["actionStatus"] == "OUTCOME_UNKNOWN"
			negative = negative || tr.Output["errorCode"] == protocol.ErrCodeAncestorInactive
			completed = completed || tr.ToolName == "reconcile_order" && tr.Output["outcome"] == "CREATED" && tr.Output["historicalStatus"] == "MATCHED"
		}
	}
	if !negative || !completed || scenario == "b1-reconciliation" && !unknown {
		return fmt.Errorf("live LLM %s omitted required outcomes: negative=%v completed=%v unknown=%v", scenario, negative, completed, unknown)
	}
	return nil
}
