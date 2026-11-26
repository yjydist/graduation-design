package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"grad/platform/agent/llm"
	domgw "grad/platform/core/domain/gateway"
	"grad/platform/core/domain/procurement"
	"grad/platform/core/domain/wallet"
	"grad/platform/internal/httpx"
	"grad/platform/internal/mtls"
	"grad/protocol"
	"grad/protocol/registry"
)

type stubWorkbenchGateway struct {
	mu              sync.Mutex
	depID           string
	audience        string
	supplierID      string
	now             func() time.Time
	seq             atomic.Int64
	challenges      map[string]wallet.ChallengeResponse
	quotes          map[string]wallet.QuotePayload
	ordersByKey     map[string]wallet.OrderPayload
	decisionsByKey  map[string]string
	cases           map[string]wallet.OrderOutcomeCaseRequest
	auditCheckNo    map[string]int64
	failExecuteOnce map[string]bool
}

func newStubWorkbenchGateway(depID string, now func() time.Time) *stubWorkbenchGateway {
	return &stubWorkbenchGateway{
		depID:           depID,
		audience:        defaultAudience,
		supplierID:      defaultSupplierID,
		now:             now,
		challenges:      make(map[string]wallet.ChallengeResponse),
		quotes:          make(map[string]wallet.QuotePayload),
		ordersByKey:     make(map[string]wallet.OrderPayload),
		decisionsByKey:  make(map[string]string),
		cases:           make(map[string]wallet.OrderOutcomeCaseRequest),
		auditCheckNo:    make(map[string]int64),
		failExecuteOnce: make(map[string]bool),
	}
}

func (g *stubWorkbenchGateway) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenges", g.handleChallenge)
	mux.HandleFunc("POST /v1/access/execute", g.handleExecute)
	mux.HandleFunc("POST /v1/internal/order-outcome-cases", g.handleRegisterCase)
	mux.HandleFunc("POST /v1/audit/order-outcomes", g.handleAuditOutcome)
	return httpx.WithRequestID(mux)
}

func (g *stubWorkbenchGateway) handleChallenge(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	var req wallet.ChallengeRequest
	if err := httpx.DecodeJSON(r, 64*1024, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	n := g.seq.Add(1)
	nowSec := g.now().UTC().Unix()
	sum := sha256.Sum256(fmt.Appendf(nil, "wb-stub-nonce-%s-%d", g.depID, n))
	resp := wallet.ChallengeResponse{
		ChallengeID: fmt.Sprintf("urn:grad:chal:%04d", n),
		Nonce:       base64.RawURLEncoding.EncodeToString(sum[:]),
		Audience:    g.audience,
		IssuedAt:    nowSec,
		ExpiresAt:   nowSec + 30,
	}
	g.mu.Lock()
	g.challenges[resp.ChallengeID] = resp
	g.mu.Unlock()
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

func (g *stubWorkbenchGateway) handleExecute(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	raw, err := httpx.ReadBoundedBody(r, 256*1024)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	pkg, err := protocol.ParseAccessEvidencePackage(raw)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.CodeOf(err), nil, err.Error())
		return
	}
	bindings, err := pkg.ComputeBindings(false)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.CodeOf(err), nil, err.Error())
		return
	}

	g.mu.Lock()
	chal, ok := g.challenges[pkg.ChallengeID]
	if ok {
		delete(g.challenges, pkg.ChallengeID)
	}
	g.mu.Unlock()
	if !ok {
		httpx.WriteError(w, http.StatusConflict, reqID, protocol.ErrCodeChallengeUnknown, nil, "unknown or replayed challenge")
		return
	}

	lastTilde := strings.LastIndexByte(pkg.LeafPresentation, '~')
	parsedKB, err := protocol.ParseCompactJWS(pkg.LeafPresentation[lastTilde+1:], protocol.TypeKBJWT)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	var kbClaims protocol.KBJWTClaims
	if err := protocol.DecodeStrictJSON(parsedKB.PayloadBytes, &kbClaims); err != nil {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	if kbClaims.Nonce != chal.Nonce || kbClaims.Aud != chal.Audience ||
		kbClaims.SDHash != bindings.SDHash ||
		kbClaims.GradBinding.ChallengeID != chal.ChallengeID ||
		kbClaims.GradBinding.RequestHash != bindings.RequestHash ||
		kbClaims.GradBinding.ChainHash != bindings.ChainHash ||
		kbClaims.GradBinding.EvidenceHash != bindings.EvidenceHash {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeBindingMismatch, nil, "KB-JWT bindings mismatch")
		return
	}

	decID := fmt.Sprintf("urn:grad:decision:%04d", g.seq.Add(1))
	nowSec := g.now().UTC().Unix()

	switch pkg.Request.Action {
	case protocol.ActionQuoteRead:
		q := wallet.QuotePayload{
			QuoteID:          fmt.Sprintf("urn:grad:quote:%04d", g.seq.Add(1)),
			TaskID:           pkg.Request.TaskID,
			Actor:            pkg.Request.Actor,
			SupplierID:       g.supplierID,
			ProductID:        pkg.Request.ProductID,
			Quantity:         pkg.Request.Quantity,
			Currency:         pkg.Request.Currency,
			UnitPriceMinor:   domgw.DefaultProductPriceMinor,
			TotalAmountMinor: domgw.DefaultProductPriceMinor * pkg.Request.Quantity,
			IssuedAt:         nowSec,
			ValidUntil:       nowSec + 600,
		}
		g.mu.Lock()
		g.quotes[q.QuoteID] = q
		g.mu.Unlock()
		httpx.WriteJSON(w, http.StatusOK, wallet.ExecuteResponse{
			DecisionID: decID,
			Code:       "ALLOW",
			Quote:      &q,
		})

	case protocol.ActionOrderCreate:
		if pkg.Request.QuoteID == nil {
			httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, &decID, "quoteId required")
			return
		}
		g.mu.Lock()
		q, hasQuote := g.quotes[*pkg.Request.QuoteID]
		shouldFail500 := g.failExecuteOnce[pkg.Request.IdempotencyKey]
		if shouldFail500 {
			delete(g.failExecuteOnce, pkg.Request.IdempotencyKey)
		}
		g.mu.Unlock()
		if !hasQuote || q.Actor != pkg.Request.Actor || q.TaskID != pkg.Request.TaskID {
			httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeQuoteScopeMismatch, &decID, "quote scope mismatch")
			return
		}
		ord := wallet.OrderPayload{
			OrderID:          fmt.Sprintf("urn:grad:order:%04d", g.seq.Add(1)),
			QuoteID:          *pkg.Request.QuoteID,
			TaskID:           pkg.Request.TaskID,
			Actor:            pkg.Request.Actor,
			SupplierID:       g.supplierID,
			ProductID:        pkg.Request.ProductID,
			Quantity:         pkg.Request.Quantity,
			Currency:         pkg.Request.Currency,
			TotalAmountMinor: pkg.Request.AmountMinor,
			IdempotencyKey:   pkg.Request.IdempotencyKey,
			Status:           "CONFIRMED",
			CreatedAt:        nowSec,
		}
		g.mu.Lock()
		g.ordersByKey[pkg.Request.IdempotencyKey] = ord
		g.decisionsByKey[pkg.Request.IdempotencyKey] = decID
		g.mu.Unlock()
		if shouldFail500 {
			httpx.WriteError(w, http.StatusInternalServerError, reqID, "INTERNAL_ERROR", nil, "simulated response drop after commit")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, wallet.ExecuteResponse{
			DecisionID: decID,
			Code:       "ALLOW",
			Order:      &ord,
		})

	default:
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, &decID, "unsupported action")
	}
}

func (g *stubWorkbenchGateway) handleRegisterCase(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	id, ok := mtls.Caller(r)
	if !ok || id.Role != "B_RECOVERY" {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeAuditForbidden, nil, "B_RECOVERY identity required")
		return
	}
	var req wallet.OrderOutcomeCaseRequest
	if err := httpx.DecodeJSON(r, 256*1024, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	g.mu.Lock()
	g.cases[req.CaseID] = req
	g.mu.Unlock()
	httpx.WriteJSON(w, http.StatusAccepted, wallet.OrderOutcomeCaseResponse{
		CaseID:         req.CaseID,
		SendRevision:   req.SendRevision,
		DeploymentID:   req.DeploymentID,
		Actor:          req.Request.Actor,
		TaskID:         req.Request.TaskID,
		IdempotencyKey: req.Request.IdempotencyKey,
		RequestHash:    req.RequestHash,
		ChallengeIDs:   slices.Clone(req.ChallengeIDs),
		Status:         "REGISTERED",
	})
}

func (g *stubWorkbenchGateway) handleAuditOutcome(w http.ResponseWriter, r *http.Request) {
	reqID := httpx.RequestID(r)
	id, ok := mtls.Caller(r)
	if !ok || id.Role != "C_AUDITOR" {
		httpx.WriteError(w, http.StatusForbidden, reqID, protocol.ErrCodeAuditForbidden, nil, "C_AUDITOR identity required")
		return
	}
	var req wallet.AuditOrderOutcomeRequest
	if err := httpx.DecodeJSON(r, 256*1024, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, reqID, protocol.ErrCodeInvalidSchema, nil, err.Error())
		return
	}
	g.mu.Lock()
	caseReq, ok := g.cases[req.CaseID]
	g.auditCheckNo[req.CaseID]++
	checkNo := g.auditCheckNo[req.CaseID]
	ord, hasOrd := g.ordersByKey[caseReq.Request.IdempotencyKey]
	decID := g.decisionsByKey[caseReq.Request.IdempotencyKey]
	g.mu.Unlock()
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, reqID, protocol.ErrCodeInvalidSchema, nil, "case not found")
		return
	}

	outcome := "NOT_CREATED"
	histStatus := "NO_DECISION"
	var orderPtr, decPtr *string
	if hasOrd {
		outcome = "CREATED"
		histStatus = "MATCHED"
		oid := ord.OrderID
		did := decID
		orderPtr = &oid
		decPtr = &did
	}
	nowSec := g.now().UTC().Unix()
	receipt := wallet.OrderOutcomeReceipt{
		CaseID:             caseReq.CaseID,
		CheckNo:            checkNo,
		SendRevision:       caseReq.SendRevision,
		DeploymentID:       g.depID,
		Actor:              caseReq.Request.Actor,
		TaskID:             caseReq.Request.TaskID,
		RequestHash:        caseReq.RequestHash,
		Outcome:            outcome,
		OrderID:            orderPtr,
		CreationDecisionID: decPtr,
		HistoricalStatus:   histStatus,
		AuditAt:            nowSec,
	}
	httpx.WriteJSON(w, http.StatusOK, wallet.AuditOrderOutcomeResponse{
		CaseID:             caseReq.CaseID,
		CheckNo:            checkNo,
		SendRevision:       caseReq.SendRevision,
		DeploymentID:       g.depID,
		Actor:              caseReq.Request.Actor,
		TaskID:             caseReq.Request.TaskID,
		IdempotencyKey:     caseReq.Request.IdempotencyKey,
		RequestHash:        caseReq.RequestHash,
		Outcome:            outcome,
		OrderID:            orderPtr,
		CreationDecisionID: decPtr,
		HistoricalStatus:   histStatus,
		LockedChallengeIDs: slices.Clone(caseReq.ChallengeIDs),
		VerifierID:         id.DID,
		AuditAt:            nowSec,
		Receipt:            receipt,
	})
}

func TestWorkbenchDraftAdvisorAdapter(t *testing.T) {
	t.Parallel()

	var (
		mu          sync.Mutex
		sawUserText string
	)
	oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content any    `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		for _, m := range body.Messages {
			if m.Role == "user" {
				sawUserText, _ = m.Content.(string)
			}
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "draft-1", "object": "chat.completion", "model": "mock-draft",
			"choices": []any{map[string]any{
				"index": 0, "finish_reason": "stop",
				"message": map[string]any{
					"role":    "assistant",
					"content": `{"productId":"urn:grad:product:P1","quantity":1,"mode":"BM","maxAmountMinor":100000,"durationMinutes":90,"description":"Buy 1 P1 via BM","reply":"Draft ready for buyer confirmation."}`,
				},
			}},
		})
	}))
	defer oaiSrv.Close()

	adapter := &draftAdvisorAdapter{
		runner: llm.RunnerConfig{
			Provider: llm.ProviderOpenAI,
			BaseURL:  oaiSrv.URL + "/v1",
			APIKey:   "sk-wb-draft-secret",
			Model:    "mock-draft",
		},
		delegateDID: workbenchA1,
	}

	before := time.Now().Unix()
	prior := &procurement.Draft{
		ProductID:      domgw.DefaultProductID,
		Quantity:       2,
		Mode:           protocol.ModeResourcePreauthorized,
		MaxAmountMinor: 200000,
	}
	draft, reply, err := adapter.SuggestDraft(t.Context(), "Change to 1 unit in BM mode", prior)
	require.NoError(t, err)
	assert.Equal(t, domgw.DefaultProductID, draft.ProductID)
	assert.Equal(t, int64(1), draft.Quantity)
	assert.Equal(t, protocol.ModeBuyerMandate, draft.Mode)
	assert.Equal(t, int64(100000), draft.MaxAmountMinor)
	assert.Equal(t, workbenchA1, draft.DelegateDID)
	assert.Equal(t, "Buy 1 P1 via BM", draft.Description)
	assert.GreaterOrEqual(t, draft.ExpiresAt, before+90*60-5)
	assert.Equal(t, "Draft ready for buyer confirmation.", reply)

	mu.Lock()
	assert.Contains(t, sawUserText, `"maxAmountMinor":200000`)
	assert.Contains(t, sawUserText, "Change to 1 unit in BM mode")
	mu.Unlock()
}

func TestWorkbenchDelegateAndExecuteAdaptersOverBoundMCP(t *testing.T) {
	t.Parallel()

	inst, dep := newOfflineInstanceAndDeployment(t)
	fx, err := PrepareFixtures(inst, dep, nil)
	require.NoError(t, err)
	mat, err := loadWalletMaterials(inst, fx)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	gw := newStubWorkbenchGateway(dep.DeploymentID, func() time.Time { return now })
	gwHandler := gw.handler()

	var (
		anchoredMu  sync.Mutex
		anchoredReq *wallet.AnchorChildGrantRequest
	)
	var w *wallet.WalletContext
	w, err = wallet.NewWalletContext(wallet.WalletConfig{
		DeploymentID:    dep.DeploymentID,
		Audience:        defaultAudience,
		SupplierID:      defaultSupplierID,
		SupplierDID:     fx.Identities["C"].ID,
		DefaultTaskSpec: fx.ProcurementTaskSpec,
		Currency:        defaultCurrency,
		HTTPHandler:     gwHandler,
		RecoveryClient:  NewLocalMTLSClient(gwHandler, defaultRecoveryDID, "B_RECOVERY", "BMsp"),
		AuditClient:     NewLocalMTLSClient(gwHandler, defaultAuditorDID, "C_AUDITOR", "CMsp"),
		ReceiptDelivery: func(ctx context.Context, receipt wallet.OrderOutcomeReceipt) (*wallet.OrderOutcomeReceiptResponse, error) {
			return w.ApplyOrderOutcomeReceipt(ctx, receipt)
		},
		Now: func() time.Time { return now },
		AnchorChildFunc: func(_ context.Context, req wallet.AnchorChildGrantRequest) (*wallet.AnchorChildGrantResult, error) {
			anchoredMu.Lock()
			cp := req
			anchoredReq = &cp
			anchoredMu.Unlock()
			return &wallet.AnchorChildGrantResult{
				Anchored:   true,
				TrustPaths: mat.trustPathsForMode(req.Claims.AuthorizationMode),
			}, nil
		},
		ResolveGrantRecipient: func(_ context.Context, did string) (wallet.GrantRecipient, error) {
			b1 := fx.Identities["B1"]
			if did != b1.ID {
				return wallet.GrantRecipient{}, protocol.NewError(protocol.ErrCodeBindingMismatch, "unexpected recipient")
			}
			return wallet.GrantRecipient{
				DID:          b1.ID,
				KeyVersion:   b1.KeyVersion,
				CredentialID: fx.Credentials["B1"].ID,
			}, nil
		},
	})
	require.NoError(t, err)
	require.NoError(t, registerFixtureActors(w, inst, fx))
	require.NoError(t, loadFixtureGrantChains(w, inst, fx, mat))

	// Collect private keys, SD-JWT presentations, and raw grants to assert zero secret leakage.
	var secrets []string
	for _, role := range []string{"U", "A1", "B1", "B2"} {
		pemBytes, readErr := os.ReadFile(inst.PrivatePath("app", role+".key.pem"))
		require.NoError(t, readErr)
		secrets = append(secrets, string(pemBytes))
		sdBytes, readErr := os.ReadFile(inst.RegistryPath("credentials", role+".sdjwt"))
		require.NoError(t, readErr)
		secrets = append(secrets, string(sdBytes))
	}
	assertNoSecrets := func(t *testing.T, label, payload string, apiKey string) {
		t.Helper()
		assert.NotContains(t, payload, "PRIVATE KEY", "%s leaked private key marker", label)
		assert.NotContains(t, payload, apiKey, "%s leaked LLM API key", label)
		for _, s := range secrets {
			assert.NotContains(t, payload, s, "%s leaked wallet secret material", label)
		}
	}

	childGrantID := registry.Digest([]byte("workbench-adapter-g2-" + t.Name()))
	delegateAPIKey := "sk-wb-delegate-secret-999"

	// 1. StageDelegate: L4 orchestrator (OpenAI) -> L3 svcmcp.NewBoundMCPServer -> L2 wallet.BoundOperations.
	delegateOps, err := wallet.NewBoundOperations(w, wallet.ExecutionBinding{
		DeploymentID: dep.DeploymentID,
		DomainID:     "A",
		Actor:        "A1",
		DID:          fx.Identities["A1"].ID,
		TaskID:       fx.BMTask.ID,
		Mode:         protocol.ModeBuyerMandate,
		GrantID:      fx.BMG1.ID,
		Stage:        wallet.StageDelegate,
		RunID:        "run-wb-delegate-1",
		SubjectDID:   fx.Identities["B1"].ID,
		SubjectActor: "B1",
		ChildGrantID: childGrantID,
	})
	require.NoError(t, err)

	var (
		delMu        sync.Mutex
		delStep      int
		delToolNames []string
	)
	delegateLLMSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tools []struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		delMu.Lock()
		defer delMu.Unlock()
		if delStep == 0 {
			for _, tool := range body.Tools {
				delToolNames = append(delToolNames, tool.Function.Name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		delStep++
		switch delStep {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "del-1", "object": "chat.completion", "model": "mock-oai",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "tool_calls",
					"message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{
							"id": "call_1", "type": "function",
							"function": map[string]any{"name": "inspect_wallet", "arguments": `{"actor":"A1"}`},
						}},
					},
				}},
			})
		case 2:
			// Attempt a forged recipient DID; L3 bound MCP must return sanitized BINDING_MISMATCH.
			args, _ := json.Marshal(map[string]any{
				"issuerActor": "A1", "subjectDid": fx.Identities["B2"].ID,
				"parentGrantId": fx.BMG1.ID, "grantId": childGrantID,
				"taskId": fx.BMTask.ID, "authorizationMode": protocol.ModeBuyerMandate,
				"maxAmountMinor": 100000, "remainingDepth": 0,
			})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "del-2", "object": "chat.completion", "model": "mock-oai",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "tool_calls",
					"message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{
							"id": "call_2", "type": "function",
							"function": map[string]any{"name": "delegate_grant", "arguments": string(args)},
						}},
					},
				}},
			})
		case 3:
			args, _ := json.Marshal(map[string]any{
				"issuerActor": "A1", "subjectActor": "B1", "subjectDid": fx.Identities["B1"].ID,
				"parentGrantId": fx.BMG1.ID, "grantId": childGrantID,
				"taskId": fx.BMTask.ID, "authorizationMode": protocol.ModeBuyerMandate,
				"maxAmountMinor": 100000, "remainingDepth": 0,
			})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "del-3", "object": "chat.completion", "model": "mock-oai",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "tool_calls",
					"message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{
							"id": "call_3", "type": "function",
							"function": map[string]any{"name": "delegate_grant", "arguments": string(args)},
						}},
					},
				}},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "del-4", "object": "chat.completion", "model": "mock-oai",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "stop",
					"message": map[string]any{"role": "assistant", "content": "Delegated G2 using " + delegateAPIKey},
				}},
			})
		}
	}))
	defer delegateLLMSrv.Close()

	var streamedDelegateTraces []procurement.ToolTrace
	delAdapter := &delegateRunnerAdapter{
		runner: llm.RunnerConfig{
			Provider: llm.ProviderOpenAI,
			BaseURL:  delegateLLMSrv.URL + "/v1",
			APIKey:   delegateAPIKey,
			Model:    "mock-oai",
			MaxSteps: 6,
		},
	}
	delRes, err := delAdapter.RunDelegate(t.Context(), delegateOps, procurement.DelegateRunInput{
		TaskID:         fx.BMTask.ID,
		Mode:           protocol.ModeBuyerMandate,
		ParentGrantID:  fx.BMG1.ID,
		ChildGrantID:   childGrantID,
		RecipientDID:   fx.Identities["B1"].ID,
		MaxAmountMinor: 100000,
		OnToolTrace: func(tr procurement.ToolTrace) {
			streamedDelegateTraces = append(streamedDelegateTraces, tr)
		},
	})
	require.NoError(t, err)

	delMu.Lock()
	assert.ElementsMatch(t, []string{"inspect_wallet", "delegate_grant"}, delToolNames, "StageDelegate must expose only inspect_wallet and delegate_grant")
	delMu.Unlock()

	require.Len(t, delRes.Traces, 3)
	assert.Equal(t, delRes.Traces, streamedDelegateTraces)
	assert.Equal(t, "inspect_wallet", delRes.Traces[0].ToolName)
	assert.False(t, delRes.Traces[0].IsError)
	assert.Equal(t, "delegate_grant", delRes.Traces[1].ToolName)
	assert.True(t, delRes.Traces[1].IsError)
	assert.Equal(t, protocol.ErrCodeBindingMismatch, delRes.Traces[1].Output["code"])
	assert.Equal(t, "delegate_grant", delRes.Traces[2].ToolName)
	assert.False(t, delRes.Traces[2].IsError)
	assert.Equal(t, true, delRes.Traces[2].Output["anchored"])
	assert.Contains(t, delRes.Summary, "[REDACTED_API_KEY]")

	anchoredMu.Lock()
	require.NotNil(t, anchoredReq)
	assert.Equal(t, childGrantID, anchoredReq.Claims.ID)
	assert.Equal(t, fx.Identities["B1"].ID, anchoredReq.GranteeDID)
	anchoredMu.Unlock()

	delRaw, err := json.Marshal(delRes)
	require.NoError(t, err)
	assertNoSecrets(t, "delegateRunnerAdapter result", string(delRaw), delegateAPIKey)

	// 2. StageExecute: L4 orchestrator (Anthropic) -> L3 svcmcp.NewBoundMCPServer -> L2 wallet.BoundOperations.
	execOps, err := wallet.NewBoundOperations(w, wallet.ExecutionBinding{
		DeploymentID: dep.DeploymentID,
		DomainID:     "B",
		Actor:        "B1",
		DID:          fx.Identities["B1"].ID,
		TaskID:       fx.BMTask.ID,
		Mode:         protocol.ModeBuyerMandate,
		GrantID:      childGrantID,
		Stage:        wallet.StageExecute,
		RunID:        "run-wb-exec-1",
		ProductID:    domgw.DefaultProductID,
		Quantity:     1,
	})
	require.NoError(t, err)

	// Force post-commit 500 on first create_order to exercise quote -> create_order (UNKNOWN) -> reconcile_order (CREATED).
	gw.mu.Lock()
	gw.failExecuteOnce[execOps.OrderKey()] = true
	gw.mu.Unlock()

	executeAPIKey := "sk-wb-execute-secret-888"
	var (
		execMu        sync.Mutex
		execStep      int
		execToolNames []string
		lastQuoteID   string
	)
	executeLLMSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
			Messages []struct {
				Role    string `json:"role"`
				Content []struct {
					Type    string          `json:"type"`
					Content json.RawMessage `json:"content"`
				} `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		execMu.Lock()
		defer execMu.Unlock()
		if execStep == 0 {
			for _, tool := range body.Tools {
				execToolNames = append(execToolNames, tool.Name)
			}
		}
		// Extract quoteId from the Anthropic tool_result payload (string or text block array).
		extractQuoteID := func(rawText string) {
			var parsed map[string]any
			if json.Unmarshal([]byte(rawText), &parsed) == nil {
				if qid, ok := parsed["quoteId"].(string); ok && qid != "" {
					lastQuoteID = qid
				}
			}
		}
		for _, msg := range body.Messages {
			for _, block := range msg.Content {
				if block.Type != "tool_result" || len(block.Content) == 0 {
					continue
				}
				var asStr string
				if json.Unmarshal(block.Content, &asStr) == nil {
					extractQuoteID(asStr)
					continue
				}
				var parts []struct {
					Text string `json:"text"`
				}
				if json.Unmarshal(block.Content, &parts) == nil {
					for _, p := range parts {
						extractQuoteID(p.Text)
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		execStep++
		switch execStep {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "ex-1", "type": "message", "role": "assistant", "model": "mock-ant",
				"stop_reason": "tool_use",
				"content": []any{map[string]any{
					"type": "tool_use", "id": "tu_1", "name": "request_quote",
					"input": map[string]any{
						"actor": "B1", "grantId": childGrantID, "taskId": fx.BMTask.ID,
						"authorizationMode": protocol.ModeBuyerMandate,
						"productId":         domgw.DefaultProductID, "quantity": 1,
					},
				}},
				"usage": map[string]any{"input_tokens": 10, "output_tokens": 10},
			})
		case 2:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "ex-2", "type": "message", "role": "assistant", "model": "mock-ant",
				"stop_reason": "tool_use",
				"content": []any{map[string]any{
					"type": "tool_use", "id": "tu_2", "name": "create_order",
					"input": map[string]any{
						"actor": "B1", "grantId": childGrantID, "taskId": fx.BMTask.ID,
						"authorizationMode": protocol.ModeBuyerMandate,
						"quoteId":           lastQuoteID, "amountMinor": domgw.DefaultProductPriceMinor,
						"idempotencyKey": execOps.OrderKey(),
					},
				}},
				"usage": map[string]any{"input_tokens": 10, "output_tokens": 10},
			})
		case 3:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "ex-3", "type": "message", "role": "assistant", "model": "mock-ant",
				"stop_reason": "tool_use",
				"content": []any{map[string]any{
					"type": "tool_use", "id": "tu_3", "name": "reconcile_order",
					"input": map[string]any{
						"actor": "B1", "taskId": fx.BMTask.ID, "idempotencyKey": execOps.OrderKey(),
					},
				}},
				"usage": map[string]any{"input_tokens": 10, "output_tokens": 10},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "ex-4", "type": "message", "role": "assistant", "model": "mock-ant",
				"stop_reason": "end_turn",
				"content":     []any{map[string]any{"type": "text", "text": "Reconciled order with " + executeAPIKey}},
				"usage":       map[string]any{"input_tokens": 10, "output_tokens": 10},
			})
		}
	}))
	defer executeLLMSrv.Close()

	var streamedExecTraces []procurement.ToolTrace
	execAdapter := &executeRunnerAdapter{
		runner: llm.RunnerConfig{
			Provider: llm.ProviderAnthropic,
			BaseURL:  executeLLMSrv.URL,
			APIKey:   executeAPIKey,
			Model:    "mock-ant",
			MaxSteps: 6,
		},
	}
	execRes, err := execAdapter.RunExecute(t.Context(), execOps, procurement.ExecuteRunInput{
		TaskID:         fx.BMTask.ID,
		Mode:           protocol.ModeBuyerMandate,
		GrantID:        childGrantID,
		ProductID:      domgw.DefaultProductID,
		Quantity:       1,
		MaxAmountMinor: 100000,
		OrderKey:       execOps.OrderKey(),
		OnToolTrace: func(tr procurement.ToolTrace) {
			streamedExecTraces = append(streamedExecTraces, tr)
		},
	})
	require.NoError(t, err)

	execMu.Lock()
	assert.ElementsMatch(t, []string{"inspect_wallet", "request_quote", "create_order", "reconcile_order"}, execToolNames, "StageExecute must expose only execute-stage tools")
	execMu.Unlock()

	require.Len(t, execRes.Traces, 3)
	assert.Equal(t, execRes.Traces, streamedExecTraces)
	assert.Equal(t, "request_quote", execRes.Traces[0].ToolName)
	assert.Equal(t, "ALLOW", execRes.Traces[0].Output["decision"])
	assert.Equal(t, "create_order", execRes.Traces[1].ToolName)
	assert.Equal(t, "UNKNOWN", execRes.Traces[1].Output["decision"])
	assert.Equal(t, wallet.ActionStatusOutcomeUnknown, execRes.Traces[1].Output["actionStatus"])
	assert.Equal(t, "reconcile_order", execRes.Traces[2].ToolName)
	assert.Equal(t, "CREATED", execRes.Traces[2].Output["outcome"])
	assert.Equal(t, wallet.ActionStatusReconciled, execRes.Traces[2].Output["actionStatus"])
	assert.NotEmpty(t, execRes.Traces[2].Output["orderId"])
	assert.Contains(t, execRes.Summary, "[REDACTED_API_KEY]")

	execRaw, err := json.Marshal(execRes)
	require.NoError(t, err)
	assertNoSecrets(t, "executeRunnerAdapter result", string(execRaw), executeAPIKey)
}

func TestSeedInstanceRejectsNilInstance(t *testing.T) {
	t.Parallel()
	_, err := SeedInstance(t.Context(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fabric instance is required")
}
