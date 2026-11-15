package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/shared"
)

func runOpenAILoop(
	ctx context.Context,
	session *mcp.ClientSession,
	mcpTools []*mcp.Tool,
	cfg RunnerConfig,
	userPrompt string,
) (*RunResult, error) {
	opts := []option.RequestOption{
		option.WithAPIKey(cfg.APIKey),
	}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}
	if cfg.HTTPClient != nil {
		opts = append(opts, option.WithHTTPClient(cfg.HTTPClient))
	}
	client := openai.NewClient(opts...)

	tools := make([]openai.ChatCompletionToolParam, 0, len(mcpTools))
	for _, t := range mcpTools {
		fn := shared.FunctionDefinitionParam{
			Name:        t.Name,
			Parameters:  shared.FunctionParameters(schemaMapFromTool(t)),
		}
		if t.Description != "" {
			fn.Description = openai.String(t.Description)
		}
		tools = append(tools, openai.ChatCompletionToolParam{
			Function: fn,
		})
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
			trace, contentStr, execErr := executeMCPTool(ctx, session, step, tc.Function.Name, tc.Function.Arguments, cfg.APIKey)
			if execErr != nil {
				return nil, execErr
			}
			res.ToolCallsCount++
			res.ToolTraces = append(res.ToolTraces, trace)
			messages = append(messages, openai.ToolMessage(contentStr, tc.ID))
		}
	}
	return nil, fmt.Errorf("openai agent loop exceeded maxSteps (%d)", cfg.MaxSteps)
}
