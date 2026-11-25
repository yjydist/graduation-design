package orchestrator_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"grad/platform/agent/llm"
	"grad/platform/agent/orchestrator"
	"grad/protocol"
)

type mockMCPState struct {
	mu          sync.Mutex
	calls       []string
	lastArgs    map[string]map[string]any
	leakInTool  string
	orderStatus string
}

func newMockProcurementMCPServer(state *mockMCPState) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "mock-procurement-mcp",
		Version: "v1.0.0",
	}, nil)

	record := func(name string, in any) {
		b, _ := json.Marshal(in)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		state.mu.Lock()
		state.calls = append(state.calls, name)
		if state.lastArgs == nil {
			state.lastArgs = map[string]map[string]any{}
		}
		state.lastArgs[name] = m
		state.mu.Unlock()
	}

	type inspectIn struct {
		Actor string `json:"actor"`
	}
	type inspectOut struct {
		Actor   string `json:"actor"`
		GrantID string `json:"grantId"`
		Note    string `json:"note,omitempty"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "inspect_wallet",
		Description: "Inspect actor grants",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in inspectIn) (*mcp.CallToolResult, inspectOut, error) {
		record("inspect_wallet", in)
		state.mu.Lock()
		leak := state.leakInTool
		state.mu.Unlock()
		return nil, inspectOut{Actor: in.Actor, GrantID: "grant-g1", Note: leak}, nil
	})

	type delegateIn struct {
		IssuerActor       string `json:"issuerActor"`
		SubjectActor      string `json:"subjectActor"`
		ParentGrantID     string `json:"parentGrantId"`
		GrantID           string `json:"grantId"`
		TaskID            string `json:"taskId"`
		AuthorizationMode string `json:"authorizationMode"`
		MaxAmountMinor    int64  `json:"maxAmountMinor"`
		RemainingDepth    int64  `json:"remainingDepth"`
	}
	type delegateOut struct {
		GrantID  string `json:"grantId"`
		Anchored bool   `json:"anchored"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "delegate_grant",
		Description: "Delegate narrowed child grant",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in delegateIn) (*mcp.CallToolResult, delegateOut, error) {
		record("delegate_grant", in)
		return nil, delegateOut{GrantID: in.GrantID, Anchored: true}, nil
	})

	type quoteIn struct {
		Actor             string `json:"actor"`
		GrantID           string `json:"grantId"`
		TaskID            string `json:"taskId"`
		AuthorizationMode string `json:"authorizationMode"`
		ProductID         string `json:"productId"`
		Quantity          int64  `json:"quantity"`
	}
	type quoteOut struct {
		Decision         string `json:"decision"`
		QuoteID          string `json:"quoteId"`
		TotalAmountMinor int64  `json:"totalAmountMinor"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "request_quote",
		Description: "Request supplier quote",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in quoteIn) (*mcp.CallToolResult, quoteOut, error) {
		record("request_quote", in)
		return nil, quoteOut{
			Decision:         "ALLOW",
			QuoteID:          "urn:grad:quote:0001",
			TotalAmountMinor: 80000 * in.Quantity,
		}, nil
	})

	type orderIn struct {
		Actor             string `json:"actor"`
		GrantID           string `json:"grantId"`
		TaskID            string `json:"taskId"`
		AuthorizationMode string `json:"authorizationMode"`
		QuoteID           string `json:"quoteId"`
		AmountMinor       int64  `json:"amountMinor"`
		IdempotencyKey    string `json:"idempotencyKey"`
	}
	type orderOut struct {
		Decision     string `json:"decision"`
		ActionStatus string `json:"actionStatus"`
		OrderID      string `json:"orderId,omitempty"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_order",
		Description: "Create supplier order",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in orderIn) (*mcp.CallToolResult, orderOut, error) {
		record("create_order", in)
		state.mu.Lock()
		status := state.orderStatus
		state.mu.Unlock()
		if status == "UNKNOWN" {
			return nil, orderOut{Decision: "UNKNOWN", ActionStatus: "OUTCOME_UNKNOWN"}, nil
		}
		return nil, orderOut{Decision: "ALLOW", ActionStatus: "COMPLETED", OrderID: "urn:grad:order:0001"}, nil
	})

	type reconcileIn struct {
		Actor          string `json:"actor"`
		TaskID         string `json:"taskId"`
		IdempotencyKey string `json:"idempotencyKey"`
	}
	type reconcileOut struct {
		Outcome      string `json:"outcome"`
		ActionStatus string `json:"actionStatus"`
		OrderID      string `json:"orderId"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "reconcile_order",
		Description: "Reconcile unknown order outcome",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in reconcileIn) (*mcp.CallToolResult, reconcileOut, error) {
		record("reconcile_order", in)
		return nil, reconcileOut{Outcome: "CREATED", ActionStatus: "RECONCILED", OrderID: "urn:grad:order:0001"}, nil
	})

	return srv
}

func TestRunAgentTaskAndMCPSessionOpenAIAndAnthropic(t *testing.T) {
	t.Parallel()

	t.Run("OpenAI via RunAgentTask with redaction", func(t *testing.T) {
		t.Parallel()
		apiKey := "sk-orch-oai-secret-777"
		pemLeak := "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILeakTest123\n-----END EC PRIVATE KEY-----"
		state := &mockMCPState{leakInTool: "secret=" + pemLeak}
		mcpSrv := newMockProcurementMCPServer(state)

		var mu sync.Mutex
		step := 0
		oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			step++
			switch step {
			case 1:
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "c1", "object": "chat.completion", "model": "mock-oai",
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
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "c2", "object": "chat.completion", "model": "mock-oai",
					"choices": []any{map[string]any{
						"index": 0, "finish_reason": "tool_calls",
						"message": map[string]any{
							"role": "assistant", "content": "",
							"tool_calls": []any{map[string]any{
								"id": "call_2", "type": "function",
								"function": map[string]any{
									"name":      "request_quote",
									"arguments": `{"actor":"B1","grantId":"g2","taskId":"t1","authorizationMode":"BUYER_MANDATE","productId":"urn:grad:product:P1","quantity":1}`,
								},
							}},
						},
					}},
				})
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "c3", "object": "chat.completion", "model": "mock-oai-final",
					"choices": []any{map[string]any{
						"index": 0, "finish_reason": "stop",
						"message": map[string]any{"role": "assistant", "content": "Done with " + apiKey},
					}},
				})
			}
		}))
		defer oaiSrv.Close()

		res, err := orchestrator.RunAgentTask(t.Context(), mcpSrv, llm.RunnerConfig{
			Provider: llm.ProviderOpenAI,
			BaseURL:  oaiSrv.URL + "/v1",
			APIKey:   apiKey,
			Model:    "oai-test",
			MaxSteps: 6,
		}, "Inspect wallet and request a quote")
		if err != nil {
			t.Fatalf("RunAgentTask failed: %v", err)
		}

		state.mu.Lock()
		calls := append([]string(nil), state.calls...)
		state.mu.Unlock()
		if !reflect.DeepEqual(calls, []string{"inspect_wallet", "request_quote"}) {
			t.Fatalf("MCP calls = %v, want [inspect_wallet request_quote]", calls)
		}
		if res.ToolCallsCount != 2 || len(res.ToolTraces) != 2 {
			t.Fatalf("unexpected tool counts: %+v", res)
		}
		if res.ToolTraces[1].Output["quoteId"] != "urn:grad:quote:0001" {
			t.Fatalf("expected quoteId in trace output, got %+v", res.ToolTraces[1].Output)
		}
		rawRes, _ := json.Marshal(res)
		if strings.Contains(string(rawRes), apiKey) || strings.Contains(string(rawRes), "PRIVATE KEY-----") {
			t.Fatalf("RunResult leaked secret: %s", string(rawRes))
		}
		if !strings.Contains(res.FinalText, "[REDACTED_API_KEY]") {
			t.Fatalf("expected redacted api key in FinalText: %q", res.FinalText)
		}
	})

	t.Run("Anthropic via explicit RunWithMCPSession", func(t *testing.T) {
		t.Parallel()
		state := &mockMCPState{}
		mcpSrv := newMockProcurementMCPServer(state)

		tServer, tClient := mcp.NewInMemoryTransports()
		srvSess, err := mcpSrv.Connect(t.Context(), tServer, nil)
		if err != nil {
			t.Fatalf("connect server: %v", err)
		}
		defer srvSess.Close()

		client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1.0.0"}, nil)
		cliSess, err := client.Connect(t.Context(), tClient, nil)
		if err != nil {
			t.Fatalf("connect client: %v", err)
		}
		defer cliSess.Close()

		var mu sync.Mutex
		step := 0
		antSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			step++
			if step == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "m1", "type": "message", "role": "assistant", "model": "mock-ant",
					"stop_reason": "tool_use",
					"content": []any{map[string]any{
						"type": "tool_use", "id": "tu_1", "name": "inspect_wallet",
						"input": map[string]any{"actor": "B1"},
					}},
					"usage": map[string]any{"input_tokens": 10, "output_tokens": 10},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "m2", "type": "message", "role": "assistant", "model": "mock-ant-final",
				"stop_reason": "end_turn",
				"content":     []any{map[string]any{"type": "text", "text": "Wallet inspected."}},
				"usage":       map[string]any{"input_tokens": 15, "output_tokens": 5},
			})
		}))
		defer antSrv.Close()

		res, err := orchestrator.RunWithMCPSession(t.Context(), cliSess, llm.RunnerConfig{
			Provider: llm.ProviderAnthropic,
			BaseURL:  antSrv.URL,
			APIKey:   "sk-ant-sess",
			Model:    "ant-test",
		}, "Inspect B1 wallet")
		if err != nil {
			t.Fatalf("RunWithMCPSession failed: %v", err)
		}
		if res.FinalText != "Wallet inspected." || res.ToolCallsCount != 1 {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("validation errors", func(t *testing.T) {
		t.Parallel()
		cfg := llm.RunnerConfig{Provider: llm.ProviderOpenAI, APIKey: "k", Model: "m"}
		if _, err := orchestrator.RunAgentTask(t.Context(), nil, cfg, "hi"); err == nil {
			t.Fatalf("expected error for nil mcpServer")
		}
		if _, err := orchestrator.RunWithMCPSession(t.Context(), nil, cfg, "hi"); err == nil {
			t.Fatalf("expected error for nil session")
		}
	})
}

func TestRunDraftDialogueAndSuggestDraft(t *testing.T) {
	t.Parallel()

	makeServer := func(reply string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "c-draft", "object": "chat.completion", "model": "mock-oai",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "stop",
					"message": map[string]any{"role": "assistant", "content": reply},
				}},
			})
		}))
	}

	t.Run("RunDraftDialogue returns final text", func(t *testing.T) {
		t.Parallel()
		srv := makeServer("Draft ready.")
		defer srv.Close()

		text, err := orchestrator.RunDraftDialogue(t.Context(), llm.RunnerConfig{
			Provider: llm.ProviderOpenAI,
			BaseURL:  srv.URL + "/v1",
			APIKey:   "sk-draft",
			Model:    "m",
		}, "", "Prepare a draft")
		if err != nil {
			t.Fatalf("RunDraftDialogue failed: %v", err)
		}
		if text != "Draft ready." {
			t.Fatalf("got %q, want %q", text, "Draft ready.")
		}
	})

	t.Run("SuggestDraft parses plain JSON and normalizes RP", func(t *testing.T) {
		t.Parallel()
		srv := makeServer(`{"productId":"urn:grad:product:P1","quantity":2,"mode":"RP","maxAmountMinor":200000,"durationMinutes":60,"description":"Buy 2 P1","reply":"Draft prepared for 2 P1."}`)
		defer srv.Close()

		got, err := orchestrator.SuggestDraft(t.Context(), llm.RunnerConfig{
			Provider: llm.ProviderOpenAI,
			BaseURL:  srv.URL + "/v1",
			APIKey:   "sk-draft",
			Model:    "m",
		}, "Buy 2 units of P1", "", "urn:grad:supplier:C", "urn:grad:product:P1", "CNY")
		if err != nil {
			t.Fatalf("SuggestDraft failed: %v", err)
		}
		if got.Mode != protocol.ModeResourcePreauthorized || got.Quantity != 2 || got.MaxAmountMinor != 200000 {
			t.Fatalf("unexpected draft suggestion: %+v", got)
		}
	})

	t.Run("SuggestDraft strips markdown fence and normalizes BM", func(t *testing.T) {
		t.Parallel()
		fenced := "```json\n" +
			`{"productId":"urn:grad:product:P2","quantity":1,"mode":"bm","maxAmountMinor":150000,"durationMinutes":90,"description":"Buy P2","reply":"Updated to P2 in BM mode."}` +
			"\n```"
		srv := makeServer(fenced)
		defer srv.Close()

		got, err := orchestrator.SuggestDraft(t.Context(), llm.RunnerConfig{
			Provider: llm.ProviderOpenAI,
			BaseURL:  srv.URL + "/v1",
			APIKey:   "sk-draft",
			Model:    "m",
		}, "Switch to P2 BM", `{"productId":"urn:grad:product:P1"}`, "urn:grad:supplier:C", "urn:grad:product:P1", "CNY")
		if err != nil {
			t.Fatalf("SuggestDraft failed: %v", err)
		}
		if got.Mode != protocol.ModeBuyerMandate || got.ProductID != "urn:grad:product:P2" {
			t.Fatalf("unexpected draft suggestion: %+v", got)
		}
	})

	t.Run("SuggestDraft rejects malformed or out-of-range responses", func(t *testing.T) {
		t.Parallel()
		badPayloads := []struct {
			name    string
			payload string
		}{
			{"non-json", "not json"},
			{"unknown field", `{"productId":"urn:grad:product:P1","quantity":1,"mode":"RP","maxAmountMinor":100000,"durationMinutes":60,"description":"d","reply":"r","extra":1}`},
			{"duration too high", `{"productId":"urn:grad:product:P1","quantity":1,"mode":"RP","maxAmountMinor":100000,"durationMinutes":601,"description":"d","reply":"r"}`},
			{"empty reply", `{"productId":"urn:grad:product:P1","quantity":1,"mode":"RP","maxAmountMinor":100000,"durationMinutes":60,"description":"d","reply":""}`},
			{"invalid mode", `{"productId":"urn:grad:product:P1","quantity":1,"mode":"INVALID","maxAmountMinor":100000,"durationMinutes":60,"description":"d","reply":"r"}`},
		}
		for _, tc := range badPayloads {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				srv := makeServer(tc.payload)
				defer srv.Close()
				_, err := orchestrator.SuggestDraft(t.Context(), llm.RunnerConfig{
					Provider: llm.ProviderOpenAI,
					BaseURL:  srv.URL + "/v1",
					APIKey:   "sk-draft",
					Model:    "m",
				}, "Buy P1", "", "", "", "")
				if !protocol.HasCode(err, protocol.ErrCodeInvalidSchema) {
					t.Fatalf("case %s: expected ErrCodeInvalidSchema, got %v", tc.name, err)
				}
			})
		}
	})
}

func TestRunDelegateTask(t *testing.T) {
	t.Parallel()

	state := &mockMCPState{}
	mcpSrv := newMockProcurementMCPServer(state)

	var (
		mu              sync.Mutex
		step            int
		sawSystemPrompt string
		sawUserPrompt   string
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
		defer mu.Unlock()
		if step == 0 {
			for _, m := range body.Messages {
				if m.Role == "system" {
					sawSystemPrompt, _ = m.Content.(string)
				}
				if m.Role == "user" {
					sawUserPrompt, _ = m.Content.(string)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		step++
		switch step {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "d1", "object": "chat.completion", "model": "mock-oai",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "tool_calls",
					"message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{
							"id": "call_del", "type": "function",
							"function": map[string]any{
								"name":      "delegate_grant",
								"arguments": `{"issuerActor":"A1","subjectActor":"B1","parentGrantId":"g1-id","grantId":"g2-id","taskId":"task-1","authorizationMode":"BUYER_MANDATE","maxAmountMinor":100000,"remainingDepth":0}`,
							},
						}},
					},
				}},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "d2", "object": "chat.completion", "model": "mock-oai",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "stop",
					"message": map[string]any{"role": "assistant", "content": "Delegated G2 to B1."},
				}},
			})
		}
	}))
	defer oaiSrv.Close()

	params := orchestrator.DelegateTaskParams{
		TaskID:            "task-1",
		AuthorizationMode: protocol.ModeBuyerMandate,
		ParentGrantID:     "g1-id",
		ChildGrantID:      "g2-id",
		SubjectDID:        "did:web:b.local:b1",
		MaxAmountMinor:    100000,
		RemainingDepth:    0,
	}
	res, err := orchestrator.RunDelegateTask(t.Context(), mcpSrv, llm.RunnerConfig{
		Provider: llm.ProviderOpenAI,
		BaseURL:  oaiSrv.URL + "/v1",
		APIKey:   "sk-del",
		Model:    "oai-del",
	}, params)
	if err != nil {
		t.Fatalf("RunDelegateTask failed: %v", err)
	}
	if sawSystemPrompt != orchestrator.DelegateSystemPrompt {
		t.Fatalf("systemPrompt = %q, want %q", sawSystemPrompt, orchestrator.DelegateSystemPrompt)
	}
	for _, want := range []string{"did:web:b.local:b1", "g1-id", "g2-id", "task-1", "100000", protocol.ModeBuyerMandate} {
		if !strings.Contains(sawUserPrompt, want) {
			t.Fatalf("userPrompt %q missing %q", sawUserPrompt, want)
		}
	}
	if res.ToolCallsCount != 1 || res.ToolTraces[0].ToolName != "delegate_grant" {
		t.Fatalf("unexpected delegate result: %+v", res)
	}

	if _, _, err := orchestrator.BuildDelegatePrompt(orchestrator.DelegateTaskParams{}); !protocol.HasCode(err, protocol.ErrCodeInvalidSchema) {
		t.Fatalf("expected ErrCodeInvalidSchema on empty DelegateTaskParams, got %v", err)
	}
}

func TestRunExecuteTask(t *testing.T) {
	t.Parallel()

	state := &mockMCPState{orderStatus: "UNKNOWN"}
	mcpSrv := newMockProcurementMCPServer(state)

	var (
		mu              sync.Mutex
		step            int
		sawSystemPrompt string
		sawUserPrompt   string
	)
	antSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			System []struct {
				Text string `json:"text"`
			} `json:"system"`
			Messages []struct {
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		defer mu.Unlock()
		if step == 0 {
			if len(body.System) > 0 {
				sawSystemPrompt = body.System[0].Text
			}
			if len(body.Messages) > 0 && len(body.Messages[0].Content) > 0 {
				sawUserPrompt = body.Messages[0].Content[0].Text
			}
		}
		w.Header().Set("Content-Type", "application/json")
		step++
		switch step {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "e1", "type": "message", "role": "assistant", "model": "mock-ant",
				"stop_reason": "tool_use",
				"content": []any{map[string]any{
					"type": "tool_use", "id": "tu_q", "name": "request_quote",
					"input": map[string]any{
						"actor": "B1", "grantId": "g2-id", "taskId": "task-exec-1",
						"authorizationMode": protocol.ModeResourcePreauthorized,
						"productId":         "urn:grad:product:P1", "quantity": 1,
					},
				}},
				"usage": map[string]any{"input_tokens": 10, "output_tokens": 10},
			})
		case 2:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "e2", "type": "message", "role": "assistant", "model": "mock-ant",
				"stop_reason": "tool_use",
				"content": []any{map[string]any{
					"type": "tool_use", "id": "tu_o", "name": "create_order",
					"input": map[string]any{
						"actor": "B1", "grantId": "g2-id", "taskId": "task-exec-1",
						"authorizationMode": protocol.ModeResourcePreauthorized,
						"quoteId":           "urn:grad:quote:0001", "amountMinor": 80000,
						"idempotencyKey": "idem-exec-1",
					},
				}},
				"usage": map[string]any{"input_tokens": 10, "output_tokens": 10},
			})
		case 3:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "e3", "type": "message", "role": "assistant", "model": "mock-ant",
				"stop_reason": "tool_use",
				"content": []any{map[string]any{
					"type": "tool_use", "id": "tu_r", "name": "reconcile_order",
					"input": map[string]any{
						"actor": "B1", "taskId": "task-exec-1", "idempotencyKey": "idem-exec-1",
					},
				}},
				"usage": map[string]any{"input_tokens": 10, "output_tokens": 10},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "e4", "type": "message", "role": "assistant", "model": "mock-ant-final",
				"stop_reason": "end_turn",
				"content":     []any{map[string]any{"type": "text", "text": "Order reconciled as CREATED."}},
				"usage":       map[string]any{"input_tokens": 10, "output_tokens": 10},
			})
		}
	}))
	defer antSrv.Close()

	params := orchestrator.ExecuteTaskParams{
		TaskID:            "task-exec-1",
		AuthorizationMode: protocol.ModeResourcePreauthorized,
		GrantID:           "g2-id",
		ProductID:         "urn:grad:product:P1",
		Quantity:          1,
		MaxAmountMinor:    100000,
		IdempotencyKey:    "idem-exec-1",
	}
	res, err := orchestrator.RunExecuteTask(t.Context(), mcpSrv, llm.RunnerConfig{
		Provider: llm.ProviderAnthropic,
		BaseURL:  antSrv.URL,
		APIKey:   "sk-exec",
		Model:    "ant-exec",
	}, params)
	if err != nil {
		t.Fatalf("RunExecuteTask failed: %v", err)
	}
	if sawSystemPrompt != orchestrator.ExecuteSystemPrompt {
		t.Fatalf("systemPrompt = %q, want %q", sawSystemPrompt, orchestrator.ExecuteSystemPrompt)
	}
	for _, want := range []string{"task-exec-1", "g2-id", "urn:grad:product:P1", "100000", "idem-exec-1"} {
		if !strings.Contains(sawUserPrompt, want) {
			t.Fatalf("userPrompt %q missing %q", sawUserPrompt, want)
		}
	}

	state.mu.Lock()
	calls := append([]string(nil), state.calls...)
	state.mu.Unlock()
	if !reflect.DeepEqual(calls, []string{"request_quote", "create_order", "reconcile_order"}) {
		t.Fatalf("MCP calls = %v, want [request_quote create_order reconcile_order]", calls)
	}
	if res.ToolCallsCount != 3 || res.ToolTraces[2].Output["outcome"] != "CREATED" {
		t.Fatalf("unexpected execute result: %+v", res)
	}

	if _, _, err := orchestrator.BuildExecutePrompt(orchestrator.ExecuteTaskParams{}); !protocol.HasCode(err, protocol.ErrCodeInvalidSchema) {
		t.Fatalf("expected ErrCodeInvalidSchema on empty ExecuteTaskParams, got %v", err)
	}

	// Sanity check formatting of returned error for missing quantity.
	_, _, err = orchestrator.BuildExecutePrompt(orchestrator.ExecuteTaskParams{
		TaskID: "t", AuthorizationMode: "BM", GrantID: "g", ProductID: "p", Quantity: 0, MaxAmountMinor: 100, IdempotencyKey: "k",
	})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("quantity")) {
		t.Fatalf("expected quantity validation error, got %v", err)
	}
}
