package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ProviderOpenAI    = "openai"
	ProviderAnthropic = "anthropic"

	DefaultSystemPrompt = "You are a procurement delegation assistant operating strictly via MCP tools. Inspect wallet grants before delegating or ordering, never exceed grant maxAmountMinor or remainingDepth, quote before ordering (never reuse a quote issued for a different actor), use replace_grant when migrating to a replacement delegate, use reconcile_order instead of blind retries whenever create_order returns UNKNOWN or OUTCOME_UNKNOWN, and explain refusals clearly when limits are exceeded."
)

// RunnerConfig configures dual-SDK LLM execution on top of an MCP tool session.
type RunnerConfig struct {
	Provider     string
	BaseURL      string
	APIKey       string `json:"-"`
	Model        string
	MaxSteps     int
	SystemPrompt string
	HTTPClient   *http.Client
}

// LoadRunnerConfigFromEnv reads LLM_PROVIDER, LLM_BASE_URL, LLM_API_KEY, LLM_MODEL, and LLM_MAX_STEPS.
func LoadRunnerConfigFromEnv() RunnerConfig {
	maxSteps := 8
	if raw := strings.TrimSpace(os.Getenv("LLM_MAX_STEPS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			maxSteps = n
		}
	}
	out := RunnerConfig{
		Provider: strings.ToLower(strings.TrimSpace(os.Getenv("LLM_PROVIDER"))),
		BaseURL:  strings.TrimSpace(os.Getenv("LLM_BASE_URL")),
		APIKey:   strings.TrimSpace(os.Getenv("LLM_API_KEY")),
		Model:    strings.TrimSpace(os.Getenv("LLM_MODEL")),
		MaxSteps: maxSteps,
	}
	if out.APIKey == "" {
		out.APIKey = strings.TrimSpace(os.Getenv("ANTHROPIC_AUTH_TOKEN"))
	}
	if out.BaseURL == "" {
		out.BaseURL = strings.TrimSpace(os.Getenv("ANTHROPIC_BASE_URL"))
	}
	if out.Provider == "" && out.BaseURL != "" && out.APIKey != "" {
		out.Provider = ProviderAnthropic
	}
	if out.Model == "" && out.BaseURL != "" {
		switch out.Provider {
		case ProviderOpenAI:
			out.Model = "deepseek-v4.1-flash"
		case ProviderAnthropic:
			out.Model = "deepseek-flash"
		}
	}
	return out
}

// ToolTrace records a single sanitized MCP tool invocation produced during an agent run.
type ToolTrace struct {
	Step       int            `json:"step"`
	ToolName   string         `json:"toolName"`
	Arguments  map[string]any `json:"arguments,omitempty"`
	Output     map[string]any `json:"output,omitempty"`
	RawText    string         `json:"rawText,omitempty"`
	IsError    bool           `json:"isError"`
	DurationMs int64          `json:"durationMs"`
}

// RunResult summarizes a bounded dual-SDK + MCP agent run without exposing credentials.
type RunResult struct {
	Provider        string      `json:"provider"`
	Model           string      `json:"model"`
	FinalText       string      `json:"finalText"`
	LLMLatencyMs    int64       `json:"llmLatencyMs"`
	TotalDurationMs int64       `json:"totalDurationMs"`
	ToolCallsCount  int         `json:"toolCallsCount"`
	Steps           int         `json:"steps"`
	ToolTraces      []ToolTrace `json:"toolTraces"`
}

func (c RunnerConfig) normalized() (RunnerConfig, error) {
	out := c
	out.Provider = strings.ToLower(strings.TrimSpace(out.Provider))
	if out.Provider == "" {
		out.Provider = ProviderOpenAI
	}
	if out.Provider != ProviderOpenAI && out.Provider != ProviderAnthropic {
		return out, fmt.Errorf("unsupported LLM provider %q (want %q or %q)", out.Provider, ProviderOpenAI, ProviderAnthropic)
	}
	if strings.TrimSpace(out.Model) == "" {
		return out, errors.New("RunnerConfig requires Model (or LLM_MODEL)")
	}
	if strings.TrimSpace(out.APIKey) == "" {
		return out, errors.New("RunnerConfig requires APIKey (or LLM_API_KEY)")
	}
	if out.MaxSteps <= 0 {
		out.MaxSteps = 8
	}
	if out.MaxSteps > 32 {
		out.MaxSteps = 32
	}
	if strings.TrimSpace(out.SystemPrompt) == "" {
		out.SystemPrompt = DefaultSystemPrompt
	}
	return out, nil
}

// RunAgentTask connects an in-memory MCP client session to mcpServer and executes the bounded LLM tool loop.
func RunAgentTask(ctx context.Context, mcpServer *mcp.Server, cfg RunnerConfig, userPrompt string) (*RunResult, error) {
	if mcpServer == nil {
		return nil, errors.New("mcpServer is required")
	}
	tServer, tClient := mcp.NewInMemoryTransports()
	srvSession, err := mcpServer.Connect(ctx, tServer, nil)
	if err != nil {
		return nil, fmt.Errorf("connect in-memory MCP server: %w", err)
	}
	defer srvSession.Close()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "grad-auth-runner",
		Version: "v0.2.0",
	}, nil)
	cliSession, err := client.Connect(ctx, tClient, nil)
	if err != nil {
		return nil, fmt.Errorf("connect in-memory MCP client: %w", err)
	}
	defer cliSession.Close()

	return RunWithMCPSession(ctx, cliSession, cfg, userPrompt)
}

// RunWithMCPSession executes a bounded OpenAI or Anthropic tool-calling loop against an active MCP ClientSession.
func RunWithMCPSession(ctx context.Context, session *mcp.ClientSession, cfg RunnerConfig, userPrompt string) (*RunResult, error) {
	if session == nil {
		return nil, errors.New("MCP ClientSession is required")
	}
	norm, err := cfg.normalized()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(userPrompt) == "" {
		return nil, errors.New("userPrompt is required")
	}

	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list MCP tools: %s", redactAPIKey(err.Error(), norm.APIKey))
	}

	started := time.Now()
	var res *RunResult
	switch norm.Provider {
	case ProviderOpenAI:
		res, err = runOpenAILoop(ctx, session, listed.Tools, norm, userPrompt)
	case ProviderAnthropic:
		res, err = runAnthropicLoop(ctx, session, listed.Tools, norm, userPrompt)
	default:
		return nil, fmt.Errorf("unsupported LLM provider %q", norm.Provider)
	}
	if err != nil {
		return nil, errors.New(redactAPIKey(err.Error(), norm.APIKey))
	}
	res.TotalDurationMs = time.Since(started).Milliseconds()
	res.FinalText = redactAPIKey(res.FinalText, norm.APIKey)
	return res, nil
}

func executeMCPTool(ctx context.Context, session *mcp.ClientSession, step int, name, rawArgsJSON, apiKey string) (ToolTrace, string, error) {
	args := map[string]any{}
	if strings.TrimSpace(rawArgsJSON) != "" {
		if err := json.Unmarshal([]byte(rawArgsJSON), &args); err != nil {
			trace := ToolTrace{
				Step:      step,
				ToolName:  name,
				RawText:   "invalid tool JSON arguments: " + err.Error(),
				IsError:   true,
			}
			errJSON, _ := json.Marshal(map[string]any{"error": trace.RawText})
			return trace, string(errJSON), nil
		}
	}

	t0 := time.Now()
	callRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	durMs := time.Since(t0).Milliseconds()
	trace := ToolTrace{
		Step:       step,
		ToolName:   name,
		Arguments:  args,
		DurationMs: durMs,
	}
	if err != nil {
		msg := redactAPIKey(err.Error(), apiKey)
		trace.IsError = true
		trace.RawText = msg
		errJSON, _ := json.Marshal(map[string]any{"error": msg})
		return trace, string(errJSON), nil
	}
	trace.IsError = callRes.IsError
	var textParts []string
	for _, c := range callRes.Content {
		if tc, ok := c.(*mcp.TextContent); ok && tc.Text != "" {
			textParts = append(textParts, redactAPIKey(tc.Text, apiKey))
		}
	}
	joined := strings.Join(textParts, "\n")
	trace.RawText = joined
	if callRes.StructuredContent != nil {
		b, mErr := json.Marshal(callRes.StructuredContent)
		if mErr == nil {
			var decoded map[string]any
			if uErr := json.Unmarshal(b, &decoded); uErr == nil {
				trace.Output = decoded
			}
			if joined == "" {
				joined = redactAPIKey(string(b), apiKey)
				trace.RawText = joined
			}
		}
	} else if joined != "" {
		var decoded map[string]any
		if uErr := json.Unmarshal([]byte(joined), &decoded); uErr == nil {
			trace.Output = decoded
		}
	}
	if joined == "" {
		joined = "{}"
	}
	return trace, joined, nil
}

func schemaMapFromTool(tool *mcp.Tool) map[string]any {
	if tool == nil || tool.InputSchema == nil {
		return map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		}
	}
	b, err := json.Marshal(tool.InputSchema)
	if err != nil {
		return map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		}
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil || out == nil {
		return map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		}
	}
	return out
}

func redactAPIKey(s, apiKey string) string {
	out := rePrivateKeyPEM.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")
	if apiKey != "" {
		out = strings.ReplaceAll(out, apiKey, "[REDACTED_API_KEY]")
	}
	return out
}
