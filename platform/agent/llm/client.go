package llm

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
	"github.com/openai/openai-go"
	openaiOption "github.com/openai/openai-go/option"
	"github.com/openai/openai-go/shared"
)

const (
	// ProviderOpenAI selects the OpenAI Chat Completions SDK runner.
	ProviderOpenAI = "openai"
	// ProviderAnthropic selects the Anthropic Messages SDK runner.
	ProviderAnthropic = "anthropic"
)

// RunnerConfig configures dual-SDK LLM execution.
type RunnerConfig struct {
	Provider     string          `json:"provider"`
	BaseURL      string          `json:"baseUrl,omitempty"`
	APIKey       string          `json:"-"`
	Model        string          `json:"model"`
	MaxSteps     int             `json:"maxSteps"`
	SystemPrompt string          `json:"systemPrompt,omitempty"`
	HTTPClient   *http.Client    `json:"-"`
	OnToolTrace  func(ToolTrace) `json:"-"`
}

// LoadRunnerConfigFromEnv reads LLM_PROVIDER, LLM_BASE_URL, LLM_API_KEY, LLM_MODEL,
// and LLM_MAX_STEPS, falling back to ANTHROPIC_AUTH_TOKEN and ANTHROPIC_BASE_URL.
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

// ToolSpec describes a callable tool in a transport-agnostic form for LLM tool calling.
type ToolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

// ToolExecutor invokes a single named tool with raw JSON arguments and returns the
// serialized output payload, whether the tool returned an application-level error,
// or an invocation error.
type ToolExecutor func(ctx context.Context, name string, argsJSON string) (outputJSON string, isError bool, err error)

// ToolTrace records a single sanitized tool invocation produced during an LLM loop.
type ToolTrace struct {
	Step       int            `json:"step"` // Model turns start at 1. Non-LLM service calls use 0.
	ToolName   string         `json:"toolName"`
	Arguments  map[string]any `json:"arguments,omitempty"`
	Output     map[string]any `json:"output,omitempty"`
	RawText    string         `json:"rawText,omitempty"`
	IsError    bool           `json:"isError"`
	DurationMs int64          `json:"durationMs"`
}

// RunResult summarizes a bounded LLM run without exposing credentials.
type RunResult struct {
	Provider        string      `json:"provider"`
	RequestedModel  string      `json:"requestedModel"`
	ResponseModels  []string    `json:"responseModels"`
	FinalText       string      `json:"finalText"`
	LLMLatencyMs    int64       `json:"llmLatencyMs"`
	TotalDurationMs int64       `json:"totalDurationMs"`
	ToolCallsCount  int         `json:"toolCallsCount"`
	Steps           int         `json:"steps"`
	ToolTraces      []ToolTrace `json:"toolTraces"`
}

func (c RunnerConfig) normalized(systemPrompt string) (RunnerConfig, error) {
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
	if strings.TrimSpace(systemPrompt) != "" {
		out.SystemPrompt = systemPrompt
	}
	return out, nil
}

// RunToolLoop executes a bounded OpenAI or Anthropic multi-step tool-calling loop.
func RunToolLoop(
	ctx context.Context,
	cfg RunnerConfig,
	systemPrompt string,
	userPrompt string,
	tools []ToolSpec,
	exec ToolExecutor,
) (*RunResult, error) {
	norm, err := cfg.normalized(systemPrompt)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(userPrompt) == "" {
		return nil, errors.New("userPrompt is required")
	}
	if len(tools) > 0 && exec == nil {
		return nil, errors.New("tool executor is required when tools are provided")
	}
	return runModel(ctx, norm, userPrompt, tools, exec)
}

// RunDialogue executes a single-turn text/JSON completion with no tools.
func RunDialogue(
	ctx context.Context,
	cfg RunnerConfig,
	systemPrompt string,
	userPrompt string,
) (*RunResult, error) {
	norm, err := cfg.normalized(systemPrompt)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(userPrompt) == "" {
		return nil, errors.New("userPrompt is required")
	}
	norm.MaxSteps = 1
	return runModel(ctx, norm, userPrompt, nil, nil)
}

func runModel(
	ctx context.Context,
	norm RunnerConfig,
	userPrompt string,
	tools []ToolSpec,
	exec ToolExecutor,
) (*RunResult, error) {
	started := time.Now()
	var (
		res *RunResult
		err error
	)
	switch norm.Provider {
	case ProviderOpenAI:
		res, err = runOpenAILoop(ctx, norm, userPrompt, tools, exec)
	case ProviderAnthropic:
		res, err = runAnthropicLoop(ctx, norm, userPrompt, tools, exec)
	default:
		return nil, fmt.Errorf("unsupported LLM provider %q", norm.Provider)
	}
	if err != nil {
		return res, errors.New(SanitizeText(err.Error(), norm.APIKey))
	}
	res.TotalDurationMs = time.Since(started).Milliseconds()
	res.FinalText = SanitizeText(res.FinalText, norm.APIKey)
	return res, nil
}

func runOpenAILoop(
	ctx context.Context,
	cfg RunnerConfig,
	userPrompt string,
	toolSpecs []ToolSpec,
	exec ToolExecutor,
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

	tools := make([]openai.ChatCompletionToolParam, 0, len(toolSpecs))
	for _, t := range toolSpecs {
		fn := shared.FunctionDefinitionParam{
			Name:       t.Name,
			Parameters: shared.FunctionParameters(normalizedSchemaMap(t.InputSchema)),
		}
		if t.Description != "" {
			fn.Description = openai.String(t.Description)
		}
		tools = append(tools, openai.ChatCompletionToolParam{Function: fn})
	}

	messages := make([]openai.ChatCompletionMessageParamUnion, 0, 2)
	if strings.TrimSpace(cfg.SystemPrompt) != "" {
		messages = append(messages, openai.SystemMessage(cfg.SystemPrompt))
	}
	messages = append(messages, openai.UserMessage(userPrompt))

	res := &RunResult{
		Provider:       ProviderOpenAI,
		RequestedModel: cfg.Model,
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
			return res, fmt.Errorf("openai chat completions step %d: %w", step, err)
		}
		model := SanitizeText(string(resp.Model), cfg.APIKey)
		if strings.TrimSpace(model) == "" {
			return res, fmt.Errorf("openai step %d returned no model identifier", step)
		}
		res.ResponseModels = append(res.ResponseModels, model)
		if len(resp.Choices) == 0 {
			return res, fmt.Errorf("openai chat completions step %d returned zero choices", step)
		}

		msg := resp.Choices[0].Message
		if len(msg.ToolCalls) == 0 {
			res.FinalText = msg.Content
			return res, nil
		}
		if exec == nil {
			return res, errors.New("dialogue returned a tool call")
		}

		messages = append(messages, msg.ToParam())
		for _, tc := range msg.ToolCalls {
			trace, contentStr := executeTool(ctx, exec, step, tc.Function.Name, tc.Function.Arguments, cfg.APIKey)
			res.ToolCallsCount++
			res.ToolTraces = append(res.ToolTraces, trace)
			if cfg.OnToolTrace != nil {
				cfg.OnToolTrace(trace)
			}
			messages = append(messages, openai.ToolMessage(contentStr, tc.ID))
		}
	}
	return res, fmt.Errorf("openai agent loop exceeded maxSteps (%d)", cfg.MaxSteps)
}

func runAnthropicLoop(
	ctx context.Context,
	cfg RunnerConfig,
	userPrompt string,
	toolSpecs []ToolSpec,
	exec ToolExecutor,
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

	tools := make([]anthropic.ToolUnionParam, 0, len(toolSpecs))
	for _, t := range toolSpecs {
		schemaMap := normalizedSchemaMap(t.InputSchema)
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

	var systemBlocks []anthropic.TextBlockParam
	if strings.TrimSpace(cfg.SystemPrompt) != "" {
		systemBlocks = []anthropic.TextBlockParam{{Text: cfg.SystemPrompt}}
	}

	res := &RunResult{
		Provider:       ProviderAnthropic,
		RequestedModel: cfg.Model,
	}

	for step := 1; step <= cfg.MaxSteps; step++ {
		res.Steps = step
		t0 := time.Now()
		resp, err := client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     anthropic.Model(cfg.Model),
			MaxTokens: 2048,
			System:    systemBlocks,
			Messages:  messages,
			Tools:     tools,
		})
		res.LLMLatencyMs += time.Since(t0).Milliseconds()
		if err != nil {
			return res, fmt.Errorf("anthropic messages step %d: %w", step, err)
		}

		model := SanitizeText(string(resp.Model), cfg.APIKey)
		if strings.TrimSpace(model) == "" {
			return res, fmt.Errorf("anthropic step %d returned no model identifier", step)
		}
		res.ResponseModels = append(res.ResponseModels, model)

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
		if exec == nil {
			return res, errors.New("dialogue returned a tool call")
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
			trace, contentStr := executeTool(ctx, exec, step, tu.Name, rawArgs, cfg.APIKey)
			res.ToolCallsCount++
			res.ToolTraces = append(res.ToolTraces, trace)
			if cfg.OnToolTrace != nil {
				cfg.OnToolTrace(trace)
			}
			toolResults = append(toolResults, anthropic.NewToolResultBlock(tu.ID, contentStr, trace.IsError))
		}
		messages = append(messages, anthropic.NewUserMessage(toolResults...))
	}
	return res, fmt.Errorf("anthropic agent loop exceeded maxSteps (%d)", cfg.MaxSteps)
}

func executeTool(
	ctx context.Context,
	exec ToolExecutor,
	step int,
	name string,
	rawArgsJSON string,
	apiKey string,
) (ToolTrace, string) {
	args := map[string]any{}
	trimmedArgs := strings.TrimSpace(rawArgsJSON)
	if trimmedArgs == "" {
		trimmedArgs = "{}"
	} else if err := json.Unmarshal([]byte(trimmedArgs), &args); err != nil {
		msg := SanitizeText("invalid tool JSON arguments: "+err.Error(), apiKey)
		trace := ToolTrace{
			Step:     step,
			ToolName: name,
			RawText:  msg,
			IsError:  true,
		}
		errJSON, _ := json.Marshal(map[string]any{"error": msg})
		return trace, string(errJSON)
	}

	t0 := time.Now()
	outputJSON, isErr, err := exec(ctx, name, trimmedArgs)
	durMs := time.Since(t0).Milliseconds()

	trace := ToolTrace{
		Step:       step,
		ToolName:   name,
		Arguments:  SanitizeMap(args, apiKey),
		DurationMs: durMs,
	}
	if err != nil {
		msg := SanitizeText(err.Error(), apiKey)
		trace.IsError = true
		trace.RawText = msg
		errJSON, _ := json.Marshal(map[string]any{"error": msg})
		return trace, string(errJSON)
	}

	sanitized := SanitizeText(outputJSON, apiKey)
	trace.IsError = isErr
	trace.RawText = sanitized
	if sanitized != "" {
		var decoded map[string]any
		if uErr := json.Unmarshal([]byte(sanitized), &decoded); uErr == nil && decoded != nil {
			trace.Output = decoded
		}
	} else {
		sanitized = "{}"
	}
	return trace, sanitized
}

func normalizedSchemaMap(schema map[string]any) map[string]any {
	if len(schema) == 0 {
		return map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		}
	}
	out := make(map[string]any, len(schema))
	for k, v := range schema {
		out[k] = v
	}
	if _, ok := out["type"]; !ok {
		out["type"] = "object"
	}
	if _, ok := out["properties"]; !ok {
		out["properties"] = map[string]any{}
	}
	return out
}

func toStringSlice(v any) ([]string, bool) {
	switch raw := v.(type) {
	case []string:
		out := make([]string, len(raw))
		copy(out, raw)
		return out, true
	case []any:
		out := make([]string, 0, len(raw))
		for _, item := range raw {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out, true
	default:
		return nil, false
	}
}
