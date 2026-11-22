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

	"github.com/anthropics/anthropic-sdk-go"
	anthropicOption "github.com/anthropics/anthropic-sdk-go/option"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openai/openai-go"
	openaiOption "github.com/openai/openai-go/option"
	"github.com/openai/openai-go/shared"
)

const (
	// ProviderOpenAI selects the OpenAI Chat Completions SDK runner.
	ProviderOpenAI = "openai"
	// ProviderAnthropic selects the Anthropic Messages SDK runner.
	ProviderAnthropic = "anthropic"

	// DefaultSystemPrompt guides bounded MCP procurement tool use without leaking credentials.
	DefaultSystemPrompt = "You are a procurement delegation assistant operating strictly via MCP tools. Inspect wallet grants before delegating or ordering, never exceed grant maxAmountMinor or remainingDepth, quote before ordering (never reuse a quote issued for a different actor), use replace_grant when migrating to a replacement delegate, use reconcile_order instead of blind retries whenever create_order returns UNKNOWN or OUTCOME_UNKNOWN, and explain refusals clearly when limits are exceeded."
)

// RunnerConfig configures dual-SDK LLM execution on top of an MCP tool session.
type RunnerConfig struct {
	Provider     string       `json:"provider"`
	BaseURL      string       `json:"baseUrl,omitempty"`
	APIKey       string       `json:"-"`
	Model        string       `json:"model"`
	MaxSteps     int          `json:"maxSteps"`
	SystemPrompt string       `json:"systemPrompt,omitempty"`
	HTTPClient   *http.Client `json:"-"`
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
		Version: "v1.0.0",
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
		return nil, fmt.Errorf("list MCP tools: %s", sanitizeLLMText(err.Error(), norm.APIKey))
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
		return nil, errors.New(sanitizeLLMText(err.Error(), norm.APIKey))
	}
	res.TotalDurationMs = time.Since(started).Milliseconds()
	res.FinalText = sanitizeLLMText(res.FinalText, norm.APIKey)
	return res, nil
}

func runOpenAILoop(
	ctx context.Context,
	session *mcp.ClientSession,
	mcpTools []*mcp.Tool,
	cfg RunnerConfig,
	userPrompt string,
) (*RunResult, error) {
	opts := []openaiOption.RequestOption{
		openaiOption.WithAPIKey(cfg.APIKey),
	}
	if cfg.BaseURL != "" {
		opts = append(opts, openaiOption.WithBaseURL(cfg.BaseURL))
	}
	if cfg.HTTPClient != nil {
		opts = append(opts, openaiOption.WithHTTPClient(cfg.HTTPClient))
	}
	client := openai.NewClient(opts...)

	tools := make([]openai.ChatCompletionToolParam, 0, len(mcpTools))
	for _, t := range mcpTools {
		fn := shared.FunctionDefinitionParam{
			Name:       t.Name,
			Parameters: shared.FunctionParameters(schemaMapFromTool(t)),
		}
		if t.Description != "" {
			fn.Description = openai.String(t.Description)
		}
		tools = append(tools, openai.ChatCompletionToolParam{Function: fn})
	}

	messages := []openai.ChatCompletionMessageParamUnion{
		openai.SystemMessage(cfg.SystemPrompt),
		openai.UserMessage(userPrompt),
	}

	res := &RunResult{
		Provider: ProviderOpenAI,
		Model:    cfg.Model,
	}

	for step := 1; step <= cfg.MaxSteps; step++ {
		res.Steps = step
		t0 := time.Now()
		resp, err := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
			Model:    shared.ChatModel(cfg.Model),
			Messages: messages,
			Tools:    tools,
		})
		res.LLMLatencyMs += time.Since(t0).Milliseconds()
		if err != nil {
			return nil, fmt.Errorf("openai chat completions step %d: %w", step, err)
		}
		if len(resp.Choices) == 0 {
			return nil, fmt.Errorf("openai chat completions step %d returned zero choices", step)
		}

		msg := resp.Choices[0].Message
		if len(msg.ToolCalls) == 0 {
			res.FinalText = msg.Content
			return res, nil
		}

		messages = append(messages, msg.ToParam())
		for _, tc := range msg.ToolCalls {
			trace, contentStr := executeMCPTool(ctx, session, step, tc.Function.Name, tc.Function.Arguments, cfg.APIKey)
			res.ToolCallsCount++
			res.ToolTraces = append(res.ToolTraces, trace)
			messages = append(messages, openai.ToolMessage(contentStr, tc.ID))
		}
	}
	return nil, fmt.Errorf("openai agent loop exceeded maxSteps (%d)", cfg.MaxSteps)
}

func runAnthropicLoop(
	ctx context.Context,
	session *mcp.ClientSession,
	mcpTools []*mcp.Tool,
	cfg RunnerConfig,
	userPrompt string,
) (*RunResult, error) {
	opts := []anthropicOption.RequestOption{
		anthropicOption.WithAPIKey(cfg.APIKey),
	}
	if cfg.BaseURL != "" {
		opts = append(opts, anthropicOption.WithBaseURL(cfg.BaseURL))
	}
	if cfg.HTTPClient != nil {
		opts = append(opts, anthropicOption.WithHTTPClient(cfg.HTTPClient))
	}
	client := anthropic.NewClient(opts...)

	tools := make([]anthropic.ToolUnionParam, 0, len(mcpTools))
	for _, t := range mcpTools {
		schemaMap := schemaMapFromTool(t)
		required, _ := toStringSlice(schemaMap["required"])
		tp := anthropic.ToolParam{
			Name: t.Name,
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: schemaMap["properties"],
				Required:   required,
			},
		}
		if t.Description != "" {
			tp.Description = anthropic.String(t.Description)
		}
		tools = append(tools, anthropic.ToolUnionParam{OfTool: &tp})
	}

	messages := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock(userPrompt)),
	}

	res := &RunResult{
		Provider: ProviderAnthropic,
		Model:    cfg.Model,
	}

	for step := 1; step <= cfg.MaxSteps; step++ {
		res.Steps = step
		t0 := time.Now()
		resp, err := client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     anthropic.Model(cfg.Model),
			MaxTokens: 2048,
			System: []anthropic.TextBlockParam{
				{Text: cfg.SystemPrompt},
			},
			Messages: messages,
			Tools:    tools,
		})
		res.LLMLatencyMs += time.Since(t0).Milliseconds()
		if err != nil {
			return nil, fmt.Errorf("anthropic messages step %d: %w", step, err)
		}

		var toolUses []anthropic.ContentBlockUnion
		var textParts []string
		for _, block := range resp.Content {
			switch block.Type {
			case "tool_use":
				toolUses = append(toolUses, block)
			case "text":
				if block.Text != "" {
					textParts = append(textParts, block.Text)
				}
			}
		}

		if len(toolUses) == 0 {
			res.FinalText = strings.Join(textParts, "\n")
			return res, nil
		}

		messages = append(messages, resp.ToParam())
		toolResults := make([]anthropic.ContentBlockParamUnion, 0, len(toolUses))
		for _, tu := range toolUses {
			rawArgs := "{}"
			if len(tu.Input) > 0 {
				var compact any
				if json.Unmarshal(tu.Input, &compact) == nil {
					if b, err := json.Marshal(compact); err == nil {
						rawArgs = string(b)
					}
				}
			}
			trace, contentStr := executeMCPTool(ctx, session, step, tu.Name, rawArgs, cfg.APIKey)
			res.ToolCallsCount++
			res.ToolTraces = append(res.ToolTraces, trace)
			toolResults = append(toolResults, anthropic.NewToolResultBlock(tu.ID, contentStr, trace.IsError))
		}
		messages = append(messages, anthropic.NewUserMessage(toolResults...))
	}
	return nil, fmt.Errorf("anthropic agent loop exceeded maxSteps (%d)", cfg.MaxSteps)
}

func executeMCPTool(ctx context.Context, session *mcp.ClientSession, step int, name, rawArgsJSON, apiKey string) (ToolTrace, string) {
	args := map[string]any{}
	if strings.TrimSpace(rawArgsJSON) != "" {
		if err := json.Unmarshal([]byte(rawArgsJSON), &args); err != nil {
			msg := sanitizeLLMText("invalid tool JSON arguments: "+err.Error(), apiKey)
			trace := ToolTrace{
				Step:     step,
				ToolName: name,
				RawText:  msg,
				IsError:  true,
			}
			errJSON, _ := json.Marshal(map[string]any{"error": msg})
			return trace, string(errJSON)
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
		Arguments:  sanitizeMap(args, apiKey),
		DurationMs: durMs,
	}
	if err != nil {
		msg := sanitizeLLMText(err.Error(), apiKey)
		trace.IsError = true
		trace.RawText = msg
		errJSON, _ := json.Marshal(map[string]any{"error": msg})
		return trace, string(errJSON)
	}

	trace.IsError = callRes.IsError
	var textParts []string
	for _, c := range callRes.Content {
		if tc, ok := c.(*mcp.TextContent); ok && tc.Text != "" {
			textParts = append(textParts, sanitizeLLMText(tc.Text, apiKey))
		}
	}
	joined := strings.Join(textParts, "\n")
	trace.RawText = joined
	if callRes.StructuredContent != nil {
		if b, mErr := json.Marshal(callRes.StructuredContent); mErr == nil {
			sanitized := sanitizeLLMText(string(b), apiKey)
			var decoded map[string]any
			if uErr := json.Unmarshal([]byte(sanitized), &decoded); uErr == nil {
				trace.Output = decoded
			}
			if joined == "" {
				joined = sanitized
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
	return trace, joined
}

func schemaMapFromTool(tool *mcp.Tool) map[string]any {
	fallback := map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
	if tool == nil || tool.InputSchema == nil {
		return fallback
	}
	b, err := json.Marshal(tool.InputSchema)
	if err != nil {
		return fallback
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil || out == nil {
		return fallback
	}
	return out
}

func toStringSlice(v any) ([]string, bool) {
	raw, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out, true
}

func sanitizeMap(in map[string]any, apiKey string) map[string]any {
	if len(in) == 0 {
		return in
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return in
	}
	sanitized := sanitizeLLMText(string(raw), apiKey)
	var out map[string]any
	if err := json.Unmarshal([]byte(sanitized), &out); err != nil {
		return in
	}
	return out
}

func sanitizeLLMText(s, apiKey string) string {
	out := rePrivateKeyPEM.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")
	out = reJWSCompact.ReplaceAllString(out, "[REDACTED_TOKEN]")
	out = reSDJWTSegment.ReplaceAllString(out, "~[REDACTED_DISCLOSURE]")
	if apiKey != "" {
		out = strings.ReplaceAll(out, apiKey, "[REDACTED_API_KEY]")
	}
	return out
}
