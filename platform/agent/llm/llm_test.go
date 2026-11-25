package llm_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"grad/platform/agent/llm"
)

func TestSanitizeTextAndMap(t *testing.T) {
	t.Parallel()

	pemBlock := "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIExamplePrivateKeyMaterial123456\n-----END EC PRIVATE KEY-----"
	jws := "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6d2ViOmEubG9jYWwifQ.abcdefghijklmnopqrstuvwxyz0123456789"
	sd := "prefix~WyJzYWx0MTIzNCIsImRvbWFpbiIsIkEiXQ"
	apiKey := "sk-super-secret-llm-key-123456"

	dirty := fmt.Sprintf("pem=%s jws=%s sd=%s key=%s", pemBlock, jws, sd, apiKey)
	clean := llm.SanitizeText(dirty, apiKey)

	if strings.Contains(clean, "PRIVATE KEY-----") {
		t.Fatalf("expected PEM private key to be redacted, got %q", clean)
	}
	if strings.Contains(clean, jws) {
		t.Fatalf("expected compact JWS to be redacted, got %q", clean)
	}
	if strings.Contains(clean, "WyJzYWx0MTIzNCIsImRvbWFpbiIsIkEiXQ") {
		t.Fatalf("expected SD-JWT disclosure to be redacted, got %q", clean)
	}
	if strings.Contains(clean, apiKey) {
		t.Fatalf("expected API key to be redacted, got %q", clean)
	}
	for _, marker := range []string{"[REDACTED_PRIVATE_KEY]", "[REDACTED_TOKEN]", "~[REDACTED_DISCLOSURE]", "[REDACTED_API_KEY]"} {
		if !strings.Contains(clean, marker) {
			t.Fatalf("expected %s marker in %q", marker, clean)
		}
	}

	nested := map[string]any{
		"pem": pemBlock,
		"nested": map[string]any{
			"token": jws,
			"list":  []any{sd, apiKey, 42},
		},
		"structVal": struct {
			Secret string `json:"secret"`
		}{Secret: apiKey},
	}
	cleanMap := llm.SanitizeMap(nested, apiKey)
	encoded, err := json.Marshal(cleanMap)
	if err != nil {
		t.Fatalf("marshal sanitized map: %v", err)
	}
	payload := string(encoded)
	for _, leak := range []string{"PRIVATE KEY-----", jws, "WyJzYWx0MTIzNCIsImRvbWFpbiIsIkEiXQ", apiKey} {
		if strings.Contains(payload, leak) {
			t.Fatalf("sanitized map leaked %q: %s", leak, payload)
		}
	}
	if llm.SanitizeMap(nil, apiKey) != nil {
		t.Fatalf("expected nil map to stay nil")
	}
}

func TestLoadRunnerConfigFromEnv(t *testing.T) {
	t.Run("explicit LLM env vars", func(t *testing.T) {
		t.Setenv("LLM_PROVIDER", "OPENAI")
		t.Setenv("LLM_BASE_URL", "https://llm.example.test/v1")
		t.Setenv("LLM_API_KEY", "sk-explicit-key")
		t.Setenv("LLM_MODEL", "gpt-test")
		t.Setenv("LLM_MAX_STEPS", "6")
		t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
		t.Setenv("ANTHROPIC_BASE_URL", "")

		cfg := llm.LoadRunnerConfigFromEnv()
		if cfg.Provider != llm.ProviderOpenAI {
			t.Fatalf("provider = %q, want %q", cfg.Provider, llm.ProviderOpenAI)
		}
		if cfg.BaseURL != "https://llm.example.test/v1" {
			t.Fatalf("baseURL = %q", cfg.BaseURL)
		}
		if cfg.APIKey != "sk-explicit-key" {
			t.Fatalf("apiKey = %q", cfg.APIKey)
		}
		if cfg.Model != "gpt-test" {
			t.Fatalf("model = %q", cfg.Model)
		}
		if cfg.MaxSteps != 6 {
			t.Fatalf("maxSteps = %d, want 6", cfg.MaxSteps)
		}
	})

	t.Run("anthropic env fallback and invalid maxSteps default", func(t *testing.T) {
		t.Setenv("LLM_PROVIDER", "")
		t.Setenv("LLM_BASE_URL", "")
		t.Setenv("LLM_API_KEY", "")
		t.Setenv("LLM_MODEL", "claude-test")
		t.Setenv("LLM_MAX_STEPS", "-3")
		t.Setenv("ANTHROPIC_AUTH_TOKEN", "ant-secret-token")
		t.Setenv("ANTHROPIC_BASE_URL", "https://anthropic.example.test")

		cfg := llm.LoadRunnerConfigFromEnv()
		if cfg.Provider != llm.ProviderAnthropic {
			t.Fatalf("provider = %q, want %q", cfg.Provider, llm.ProviderAnthropic)
		}
		if cfg.BaseURL != "https://anthropic.example.test" {
			t.Fatalf("baseURL = %q", cfg.BaseURL)
		}
		if cfg.APIKey != "ant-secret-token" {
			t.Fatalf("apiKey = %q", cfg.APIKey)
		}
		if cfg.MaxSteps != 8 {
			t.Fatalf("maxSteps = %d, want default 8", cfg.MaxSteps)
		}
	})
}

func TestRunToolLoopOpenAI(t *testing.T) {
	t.Parallel()

	apiKey := "sk-openai-loop-secret-111"
	jws := "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6d2ViOmEubG9jYWwifQ.abcdefghijklmnopqrstuvwxyz0123456789"

	var (
		mu              sync.Mutex
		step            int
		sawToolNames    []string
		sawSystemPrompt string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content any    `json:"content"`
			} `json:"messages"`
			Tools []struct {
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			} `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()
		if step == 0 {
			for _, m := range body.Messages {
				if m.Role == "system" {
					sawSystemPrompt, _ = m.Content.(string)
				}
			}
			for _, tool := range body.Tools {
				sawToolNames = append(sawToolNames, tool.Function.Name)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		step++
		switch step {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "chatcmpl-1", "object": "chat.completion", "model": "mock-oai-1",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "tool_calls",
					"message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{
							"id": "call_1", "type": "function",
							"function": map[string]any{
								"name":      "lookup_price",
								"arguments": fmt.Sprintf(`{"item":"P1","leak":"%s"}`, apiKey),
							},
						}},
					},
				}},
			})
		case 2:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "chatcmpl-2", "object": "chat.completion", "model": "mock-oai-2",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "tool_calls",
					"message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{
							"id": "call_2", "type": "function",
							"function": map[string]any{
								"name":      "submit_order",
								"arguments": `{"item":"P1","price":80000}`,
							},
						}},
					},
				}},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "chatcmpl-3", "object": "chat.completion", "model": "mock-oai-final",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "stop",
					"message": map[string]any{
						"role":    "assistant",
						"content": "Order placed using " + apiKey + " and " + jws,
					},
				}},
			})
		}
	}))
	defer srv.Close()

	tools := []llm.ToolSpec{
		{
			Name:        "lookup_price",
			Description: "Look up unit price",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"item": map[string]any{"type": "string"},
				},
				"required": []string{"item"},
			},
		},
		{
			Name:        "submit_order",
			Description: "Submit confirmed order",
		},
	}

	var traced []llm.ToolTrace
	exec := func(_ context.Context, name, argsJSON string) (string, bool, error) {
		switch name {
		case "lookup_price":
			return fmt.Sprintf(`{"price":80000,"rawToken":"%s"}`, jws), false, nil
		case "submit_order":
			return `{"orderId":"ord-1","status":"CONFIRMED"}`, false, nil
		default:
			return "", true, fmt.Errorf("unexpected tool %s with %s", name, argsJSON)
		}
	}

	res, err := llm.RunToolLoop(t.Context(), llm.RunnerConfig{
		Provider: llm.ProviderOpenAI,
		BaseURL:  srv.URL + "/v1",
		APIKey:   apiKey,
		Model:    "oai-requested",
		MaxSteps: 6,
		OnToolTrace: func(tr llm.ToolTrace) {
			traced = append(traced, tr)
		},
	}, "System prompt for OpenAI test", "Buy P1", tools, exec)
	if err != nil {
		t.Fatalf("RunToolLoop failed: %v", err)
	}

	if sawSystemPrompt != "System prompt for OpenAI test" {
		t.Fatalf("system prompt = %q", sawSystemPrompt)
	}
	if !reflect.DeepEqual(sawToolNames, []string{"lookup_price", "submit_order"}) {
		t.Fatalf("tool names = %v", sawToolNames)
	}
	if res.Provider != llm.ProviderOpenAI || res.RequestedModel != "oai-requested" {
		t.Fatalf("unexpected result header: %+v", res)
	}
	wantModels := []string{"mock-oai-1", "mock-oai-2", "mock-oai-final"}
	if !reflect.DeepEqual(res.ResponseModels, wantModels) {
		t.Fatalf("responseModels = %v, want %v", res.ResponseModels, wantModels)
	}
	if res.Steps != 3 || res.ToolCallsCount != 2 || len(res.ToolTraces) != 2 || len(traced) != 2 {
		t.Fatalf("unexpected counts: steps=%d calls=%d traces=%d cb=%d", res.Steps, res.ToolCallsCount, len(res.ToolTraces), len(traced))
	}
	if res.ToolTraces[1].Output["orderId"] != "ord-1" {
		t.Fatalf("expected decoded output map, got %+v", res.ToolTraces[1].Output)
	}

	rawRes, _ := json.Marshal(res)
	if strings.Contains(string(rawRes), apiKey) || strings.Contains(string(rawRes), jws) {
		t.Fatalf("RunResult leaked secret: %s", string(rawRes))
	}
	if !strings.Contains(res.FinalText, "[REDACTED_API_KEY]") || !strings.Contains(res.FinalText, "[REDACTED_TOKEN]") {
		t.Fatalf("expected redaction markers in FinalText: %q", res.FinalText)
	}
}

func TestRunToolLoopAnthropic(t *testing.T) {
	t.Parallel()

	apiKey := "sk-ant-loop-secret-222"
	var (
		mu             sync.Mutex
		step           int
		sawRequired    []string
		sawToolIsError bool
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tools []struct {
				Name        string `json:"name"`
				InputSchema struct {
					Required []string `json:"required"`
				} `json:"input_schema"`
			} `json:"tools"`
			Messages []struct {
				Content []struct {
					Type    string `json:"type"`
					IsError bool   `json:"is_error"`
				} `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()
		if step == 0 && len(body.Tools) > 0 {
			sawRequired = body.Tools[0].InputSchema.Required
		}
		if len(body.Messages) > 0 {
			for _, blk := range body.Messages[len(body.Messages)-1].Content {
				if blk.Type == "tool_result" && blk.IsError {
					sawToolIsError = true
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		step++
		switch step {
		case 1:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "msg_1", "type": "message", "role": "assistant", "model": "mock-ant-1",
				"stop_reason": "tool_use",
				"content": []any{map[string]any{
					"type": "tool_use", "id": "toolu_1",
					"name": "check_cap", "input": map[string]any{"amount": 999999},
				}},
				"usage": map[string]any{"input_tokens": 20, "output_tokens": 10},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "msg_2", "type": "message", "role": "assistant", "model": "mock-ant-final",
				"stop_reason": "end_turn",
				"content": []any{
					map[string]any{"type": "text", "text": "Refused due to cap."},
					map[string]any{"type": "text", "text": "Key was " + apiKey},
				},
				"usage": map[string]any{"input_tokens": 30, "output_tokens": 15},
			})
		}
	}))
	defer srv.Close()

	tools := []llm.ToolSpec{
		{
			Name:        "check_cap",
			Description: "Validate spending cap",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"amount": map[string]any{"type": "integer"}},
				"required":   []any{"amount"},
			},
		},
	}

	res, err := llm.RunToolLoop(t.Context(), llm.RunnerConfig{
		Provider: llm.ProviderAnthropic,
		BaseURL:  srv.URL,
		APIKey:   apiKey,
		Model:    "ant-requested",
		MaxSteps: 4,
	}, "Anthropic system prompt", "Check cap", tools, func(_ context.Context, name, _ string) (string, bool, error) {
		if name != "check_cap" {
			t.Fatalf("unexpected tool %q", name)
		}
		return `{"decision":"DENY","errorCode":"AMOUNT_LIMIT_EXCEEDED"}`, true, nil
	})
	if err != nil {
		t.Fatalf("RunToolLoop anthropic failed: %v", err)
	}
	if !reflect.DeepEqual(sawRequired, []string{"amount"}) {
		t.Fatalf("required = %v, want [amount]", sawRequired)
	}
	if !sawToolIsError {
		t.Fatalf("expected is_error=true to be sent in Anthropic tool_result")
	}
	if res.Provider != llm.ProviderAnthropic || res.ToolCallsCount != 1 || len(res.ToolTraces) != 1 || !res.ToolTraces[0].IsError {
		t.Fatalf("unexpected anthropic result: %+v", res)
	}
	if !strings.Contains(res.FinalText, "Refused due to cap.") || !strings.Contains(res.FinalText, "[REDACTED_API_KEY]") {
		t.Fatalf("unexpected FinalText: %q", res.FinalText)
	}
	if strings.Contains(res.FinalText, apiKey) {
		t.Fatalf("API key leaked in FinalText: %q", res.FinalText)
	}
}

func TestRunToolLoopErrorHandlingAndMaxSteps(t *testing.T) {
	t.Parallel()

	t.Run("config and input validation", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name   string
			cfg    llm.RunnerConfig
			prompt string
			tools  []llm.ToolSpec
			exec   llm.ToolExecutor
		}{
			{"unsupported provider", llm.RunnerConfig{Provider: "bogus", Model: "m", APIKey: "k"}, "hi", nil, nil},
			{"missing model", llm.RunnerConfig{Provider: llm.ProviderOpenAI, APIKey: "k"}, "hi", nil, nil},
			{"missing apiKey", llm.RunnerConfig{Provider: llm.ProviderOpenAI, Model: "m"}, "hi", nil, nil},
			{"empty prompt", llm.RunnerConfig{Provider: llm.ProviderOpenAI, Model: "m", APIKey: "k"}, "   ", nil, nil},
			{"tools without executor", llm.RunnerConfig{Provider: llm.ProviderOpenAI, Model: "m", APIKey: "k"}, "hi", []llm.ToolSpec{{Name: "t"}}, nil},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := llm.RunToolLoop(t.Context(), tc.cfg, "sys", tc.prompt, tc.tools, tc.exec); err == nil {
					t.Fatalf("expected validation error for %s", tc.name)
				}
			})
		}
	})

	t.Run("invalid JSON args and executor error recovery", func(t *testing.T) {
		t.Parallel()
		apiKey := "sk-err-secret-333"
		var step int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
							"tool_calls": []any{
								map[string]any{
									"id": "bad_json", "type": "function",
									"function": map[string]any{"name": "t1", "arguments": "{not-json"},
								},
								map[string]any{
									"id": "exec_err", "type": "function",
									"function": map[string]any{"name": "t2", "arguments": `{"ok":true}`},
								},
							},
						},
					}},
				})
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id": "c2", "object": "chat.completion", "model": "mock-oai",
					"choices": []any{map[string]any{
						"index": 0, "finish_reason": "stop",
						"message": map[string]any{"role": "assistant", "content": "Recovered cleanly"},
					}},
				})
			}
		}))
		defer srv.Close()

		execCalls := 0
		res, err := llm.RunToolLoop(t.Context(), llm.RunnerConfig{
			Provider: llm.ProviderOpenAI,
			BaseURL:  srv.URL + "/v1",
			APIKey:   apiKey,
			Model:    "m",
		}, "sys", "go", []llm.ToolSpec{{Name: "t1"}, {Name: "t2"}}, func(_ context.Context, name, _ string) (string, bool, error) {
			execCalls++
			if name == "t1" {
				t.Fatalf("executor should not be called on malformed JSON args")
			}
			return "", true, errors.New("backend failure with " + apiKey)
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if execCalls != 1 || len(res.ToolTraces) != 2 {
			t.Fatalf("execCalls=%d traces=%d", execCalls, len(res.ToolTraces))
		}
		if !res.ToolTraces[0].IsError || !strings.Contains(res.ToolTraces[0].RawText, "invalid tool JSON arguments") {
			t.Fatalf("unexpected trace[0]: %+v", res.ToolTraces[0])
		}
		if !res.ToolTraces[1].IsError || strings.Contains(res.ToolTraces[1].RawText, apiKey) || !strings.Contains(res.ToolTraces[1].RawText, "[REDACTED_API_KEY]") {
			t.Fatalf("expected sanitized executor error trace[1]: %+v", res.ToolTraces[1])
		}
	})

	t.Run("maxSteps exceeded OpenAI", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "c-loop", "object": "chat.completion", "model": "mock-oai",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "tool_calls",
					"message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{
							"id": "call_loop", "type": "function",
							"function": map[string]any{"name": "ping", "arguments": "{}"},
						}},
					},
				}},
			})
		}))
		defer srv.Close()

		res, err := llm.RunToolLoop(t.Context(), llm.RunnerConfig{
			Provider: llm.ProviderOpenAI,
			BaseURL:  srv.URL + "/v1",
			APIKey:   "sk-loop",
			Model:    "m",
			MaxSteps: 2,
		}, "sys", "loop", []llm.ToolSpec{{Name: "ping"}}, func(_ context.Context, _, _ string) (string, bool, error) {
			return `{"ok":true}`, false, nil
		})
		if err == nil || !strings.Contains(err.Error(), "exceeded maxSteps (2)") {
			t.Fatalf("expected maxSteps error, got %v", err)
		}
		if res == nil || res.Steps != 2 || res.ToolCallsCount != 2 {
			t.Fatalf("unexpected partial result: %+v", res)
		}
	})

	t.Run("maxSteps exceeded Anthropic", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "msg_loop", "type": "message", "role": "assistant", "model": "mock-ant",
				"stop_reason": "tool_use",
				"content": []any{map[string]any{
					"type": "tool_use", "id": "toolu_loop", "name": "ping", "input": map[string]any{},
				}},
				"usage": map[string]any{"input_tokens": 5, "output_tokens": 5},
			})
		}))
		defer srv.Close()

		res, err := llm.RunToolLoop(t.Context(), llm.RunnerConfig{
			Provider: llm.ProviderAnthropic,
			BaseURL:  srv.URL,
			APIKey:   "sk-loop",
			Model:    "m",
			MaxSteps: 2,
		}, "sys", "loop", []llm.ToolSpec{{Name: "ping"}}, func(_ context.Context, _, _ string) (string, bool, error) {
			return `{"ok":true}`, false, nil
		})
		if err == nil || !strings.Contains(err.Error(), "exceeded maxSteps (2)") {
			t.Fatalf("expected maxSteps error, got %v", err)
		}
		if res == nil || res.Steps != 2 || res.ToolCallsCount != 2 {
			t.Fatalf("unexpected partial result: %+v", res)
		}
	})

	t.Run("HTTP 400 error redacts api key", func(t *testing.T) {
		t.Parallel()
		apiKey := "sk-http-err-secret-444"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": "bad request for key " + apiKey,
					"type":    "invalid_request_error",
				},
			})
		}))
		defer srv.Close()

		_, err := llm.RunDialogue(t.Context(), llm.RunnerConfig{
			Provider: llm.ProviderOpenAI,
			BaseURL:  srv.URL + "/v1",
			APIKey:   apiKey,
			Model:    "m",
		}, "sys", "hello")
		if err == nil {
			t.Fatalf("expected error on HTTP 400")
		}
		if strings.Contains(err.Error(), apiKey) {
			t.Fatalf("error leaked api key: %v", err)
		}
		if !strings.Contains(err.Error(), "[REDACTED_API_KEY]") {
			t.Fatalf("expected redacted marker in error: %v", err)
		}
	})
}

func TestRunDialogue(t *testing.T) {
	t.Parallel()

	t.Run("OpenAI single turn", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "c-dlg", "object": "chat.completion", "model": "mock-oai-dlg",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "stop",
					"message": map[string]any{"role": "assistant", "content": `{"ok":true}`},
				}},
			})
		}))
		defer srv.Close()

		res, err := llm.RunDialogue(t.Context(), llm.RunnerConfig{
			Provider: llm.ProviderOpenAI,
			BaseURL:  srv.URL + "/v1",
			APIKey:   "sk-dlg",
			Model:    "m",
		}, "Respond with JSON", "Ping")
		if err != nil {
			t.Fatalf("RunDialogue OpenAI failed: %v", err)
		}
		if res.FinalText != `{"ok":true}` || res.Steps != 1 {
			t.Fatalf("unexpected dialogue result: %+v", res)
		}
	})

	t.Run("Anthropic single turn", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "msg-dlg", "type": "message", "role": "assistant", "model": "mock-ant-dlg",
				"stop_reason": "end_turn",
				"content":     []any{map[string]any{"type": "text", "text": `{"ok":true}`}},
				"usage":       map[string]any{"input_tokens": 10, "output_tokens": 5},
			})
		}))
		defer srv.Close()

		res, err := llm.RunDialogue(t.Context(), llm.RunnerConfig{
			Provider: llm.ProviderAnthropic,
			BaseURL:  srv.URL,
			APIKey:   "sk-dlg",
			Model:    "m",
		}, "Respond with JSON", "Ping")
		if err != nil {
			t.Fatalf("RunDialogue Anthropic failed: %v", err)
		}
		if res.FinalText != `{"ok":true}` || res.Steps != 1 {
			t.Fatalf("unexpected dialogue result: %+v", res)
		}
	})

	t.Run("dialogue rejects unexpected tool call", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "c-bad", "object": "chat.completion", "model": "mock-oai",
				"choices": []any{map[string]any{
					"index": 0, "finish_reason": "tool_calls",
					"message": map[string]any{
						"role": "assistant", "content": "",
						"tool_calls": []any{map[string]any{
							"id": "call_bad", "type": "function",
							"function": map[string]any{"name": "forbidden", "arguments": "{}"},
						}},
					},
				}},
			})
		}))
		defer srv.Close()

		_, err := llm.RunDialogue(t.Context(), llm.RunnerConfig{
			Provider: llm.ProviderOpenAI,
			BaseURL:  srv.URL + "/v1",
			APIKey:   "sk-dlg",
			Model:    "m",
		}, "sys", "hello")
		if err == nil || !strings.Contains(err.Error(), "dialogue returned a tool call") {
			t.Fatalf("expected tool call rejection error, got %v", err)
		}
	})
}
