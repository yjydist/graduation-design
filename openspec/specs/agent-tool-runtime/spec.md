# agent-tool-runtime Specification

## Purpose

为采购智能体 `A1` 与协作智能体 `B1` 提供基于标准 MCP 协议的确定性钱包与协议工具服务, 持久化意图防重放锁, 以及支持 OpenAI 与 Anthropic 双官方 SDK 的可控推理调用闭环.

## Requirements

### Requirement: 基于官方 MCP SDK 的确定性钱包与协议工具服务

系统 SHALL 使用官方 MCP Go SDK (`github.com/modelcontextprotocol/go-sdk/mcp`) 封装 `inspect_wallet`, `delegate_grant`, `request_quote` 与 `create_order` 四个强类型工具, 强制隔离应用私钥与原始披露盐值, 在发送 `order.create` 前持久化 `client_actions` 意图锁, 并同时支持进程内传输, `ledgerctl mcp` stdio 服务及基准测试底层 Go 函数直调.

#### Scenario: 私钥隔离与发送前意图锁持久化

- **WHEN** 上层通过 MCP `tools/call` 调用 `inspect_wallet`, `delegate_grant`, `request_quote` 或 `create_order`
- **THEN** 工具输出仅包含业务摘要, 委托约束, 报价或订单结果, 不得包含应用私钥字节或原始披露盐值
- **AND** `create_order` 在请求 C 网关前必先持久化 `client_actions` 意图行 (`OUTCOME_UNKNOWN`, `intentId`, `requestHash`, `idempotencyKey`), 挑战 `nonce` 原样绑定与 `KB-JWT` 签名均由确定性工具核完成

#### Scenario: 进程内与 stdio 标准 MCP 传输一致工作

- **WHEN** 内置智能体运行器通过 `mcp.NewInMemoryTransports()`, 或外部 MCP 客户端通过 `ledgerctl mcp` stdio 进程连接 `mcp.Server` 并执行 `tools/list` 与 `tools/call`
- **THEN** 两类传输返回的 JSON Schema 与工具执行结果一致, 底层核心函数同时可供高频基准测试直接调用

### Requirement: 双协议官方 LLM SDK 驱动的智能体推理与工具闭环

系统 SHALL 提供同时集成官方 OpenAI Go SDK (`github.com/openai/openai-go`) 与官方 Anthropic Go SDK (`github.com/anthropics/anthropic-sdk-go`) 的智能体运行器, 按 `LLM_PROVIDER` (`openai`|`anthropic`), `LLM_BASE_URL`, `LLM_API_KEY` 与 `LLM_MODEL` 连接可配置模型服务并通过 `mcp.ClientSession` 完成 `A1` 签发 `G2` 及 `B1` 在 RP/BM 下的 800 元下单与 1200 元超额拒绝闭环, 同时记录推理耗时与工具调用轨迹.

#### Scenario: A1 与 B1 通过 MCP 工具调用完成 RP 与 BM 采购闭环

- **WHEN** `A1` 与 `B1` 智能体运行器接入真实模型服务 (或离线测试中的协议模拟服务端点), 在有界推理步数内按 `taskSpec` 自主发起 MCP 工具调用
- **THEN** `A1` 查阅 `G1` 后调用 `delegate_grant` 向 `B1` 签发符合收缩规则的 `G2` (`100000` 分, 深度 `0`); `B1` 调用 `request_quote` 与 `create_order` 在 RP 与 BM 模式下均完成 800 元订单闭环 (`CREATED`)
- **AND** 面对 1200 元真实报价 `Q1200` 或诱导超额下单时, 无论模型拒绝调用还是尝试发起 `create_order`, 最终均无新订单产生, 运行器输出完整的 `llmLatencyMs`, `toolCallsCount` 与工具轨迹 (不含 `LLM_API_KEY` 或私钥)
