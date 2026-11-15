package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	anthropicOption "github.com/anthropics/anthropic-sdk-go/option"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
		inputSchema := anthropic.ToolInputSchemaParam{
			Properties: schemaMap["properties"],
			Required:   required,
		}
		tp := anthropic.ToolParam{
			Name:        t.Name,
			InputSchema: inputSchema,
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
			trace, contentStr, execErr := executeMCPTool(ctx, session, step, tu.Name, rawArgs, cfg.APIKey)
			if execErr != nil {
				return nil, execErr
			}
			res.ToolCallsCount++
			res.ToolTraces = append(res.ToolTraces, trace)
			toolResults = append(toolResults, anthropic.NewToolResultBlock(tu.ID, contentStr, trace.IsError))
		}
		messages = append(messages, anthropic.NewUserMessage(toolResults...))
	}
	return nil, fmt.Errorf("anthropic agent loop exceeded maxSteps (%d)", cfg.MaxSteps)
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
