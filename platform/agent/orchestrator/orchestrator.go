package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"grad/platform/agent/llm"
)

const (
	// DefaultSystemPrompt guides bounded MCP procurement tool use without leaking credentials.
	DefaultSystemPrompt = "You are a procurement delegation assistant operating strictly via MCP tools. Inspect wallet grants before delegating or ordering, never exceed grant maxAmountMinor or remainingDepth, quote before ordering (never reuse a quote issued for a different actor), use replace_grant when migrating to a replacement delegate, use reconcile_order instead of blind retries whenever create_order returns UNKNOWN or OUTCOME_UNKNOWN, and explain refusals clearly when limits are exceeded."

	defaultDraftDialoguePrompt = "Help the buyer prepare a procurement task draft from the provided context."
)

// RunAgentTask connects an in-memory MCP client session to mcpServer and executes
// a bounded LLM tool-calling loop where every tool call goes through MCP.
func RunAgentTask(
	ctx context.Context,
	mcpServer *mcp.Server,
	cfg llm.RunnerConfig,
	prompt string,
) (*llm.RunResult, error) {
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

	return RunWithMCPSession(ctx, cliSession, cfg, prompt)
}

// RunWithMCPSession lists tools from an active MCP ClientSession and drives a
// bounded LLM tool-calling loop where every tool invocation uses session.CallTool.
func RunWithMCPSession(
	ctx context.Context,
	session *mcp.ClientSession,
	cfg llm.RunnerConfig,
	prompt string,
) (*llm.RunResult, error) {
	if session == nil {
		return nil, errors.New("MCP ClientSession is required")
	}
	if strings.TrimSpace(prompt) == "" {
		return nil, errors.New("prompt is required")
	}

	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list MCP tools: %s", llm.SanitizeText(err.Error(), cfg.APIKey))
	}

	specs := toolSpecsFromMCP(listed.Tools)
	systemPrompt := cfg.SystemPrompt
	if strings.TrimSpace(systemPrompt) == "" {
		systemPrompt = DefaultSystemPrompt
	}

	exec := func(callCtx context.Context, name, argsJSON string) (string, bool, error) {
		args := map[string]any{}
		if strings.TrimSpace(argsJSON) != "" {
			if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
				return "", true, fmt.Errorf("invalid tool JSON arguments: %w", err)
			}
		}
		callRes, err := session.CallTool(callCtx, &mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		})
		if err != nil {
			return "", true, err
		}
		return extractMCPToolOutput(callRes), callRes.IsError, nil
	}

	return llm.RunToolLoop(ctx, cfg, systemPrompt, prompt, specs, exec)
}

// RunDraftDialogue executes a single-turn text/JSON completion with no MCP tools.
func RunDraftDialogue(
	ctx context.Context,
	cfg llm.RunnerConfig,
	systemPrompt string,
	userPrompt string,
) (string, error) {
	if strings.TrimSpace(systemPrompt) == "" {
		if strings.TrimSpace(cfg.SystemPrompt) != "" {
			systemPrompt = cfg.SystemPrompt
		} else {
			systemPrompt = defaultDraftDialoguePrompt
		}
	}
	res, err := llm.RunDialogue(ctx, cfg, systemPrompt, userPrompt)
	if err != nil {
		return "", err
	}
	return res.FinalText, nil
}

func toolSpecsFromMCP(tools []*mcp.Tool) []llm.ToolSpec {
	specs := make([]llm.ToolSpec, 0, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}
		specs = append(specs, llm.ToolSpec{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: schemaMapFromMCPTool(t),
		})
	}
	return specs
}

func schemaMapFromMCPTool(tool *mcp.Tool) map[string]any {
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

func extractMCPToolOutput(callRes *mcp.CallToolResult) string {
	if callRes == nil {
		return "{}"
	}
	var textParts []string
	for _, c := range callRes.Content {
		if tc, ok := c.(*mcp.TextContent); ok && tc.Text != "" {
			textParts = append(textParts, tc.Text)
		}
	}
	joined := strings.Join(textParts, "\n")

	if callRes.StructuredContent != nil {
		if b, err := json.Marshal(callRes.StructuredContent); err == nil {
			if joined == "" {
				return string(b)
			}
			var decoded map[string]any
			if json.Unmarshal([]byte(joined), &decoded) != nil {
				return string(b)
			}
		}
	}
	if joined == "" {
		return "{}"
	}
	return joined
}
