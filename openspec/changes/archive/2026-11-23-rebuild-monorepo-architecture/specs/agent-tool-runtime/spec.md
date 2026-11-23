# Spec Delta: agent-tool-runtime

## MODIFIED Requirements

### Requirement: 基于官方 MCP SDK 的确定性钱包与协议工具服务

系统 SHALL 使用官方 MCP Go SDK (`github.com/modelcontextprotocol/go-sdk/mcp`) 封装 `inspect_wallet`, `delegate_grant`, `replace_grant`, `request_quote`, `create_order` 与 `reconcile_order` 六个强类型工具, 强制隔离应用私钥与原始披露盐值. 钱包工具运行时 SHALL 独立拥有 `client_actions` 意图锁持久化 (`OUTCOME_UNKNOWN` 与 `sendRevision`) 且仅通过 HTTP/Handler 客户端边界与 C 网关交互 (不依赖网关内部数据库实现), 支持原子替换子授权改派新受托者及响应丢失后的停发核账恢复, 并同时支持进程内传输, 由顶层运行时装配的 `ledgerctl mcp` stdio 服务及基准测试底层 Go 函数直调.

#### Scenario: 私钥隔离与发送前意图锁持久化

- **WHEN** 上层通过 MCP `tools/call` 调用 `inspect_wallet`, `delegate_grant`, `replace_grant`, `request_quote`, `create_order` 或 `reconcile_order`
- **THEN** 工具输出仅包含业务摘要, 委托约束, 报价, 订单或核账结果, 不得包含应用私钥字节或原始披露盐值
- **AND** `create_order` 在请求 C 网关前必先在智能体侧独立存储持久化 `client_actions` 意图行 (`OUTCOME_UNKNOWN`, `actionId`, `requestHash`, `idempotencyKey`, `sendRevision`), 挑战 `nonce` 原样绑定与 `KB-JWT` 签名均由确定性工具核完成

#### Scenario: 进程内与 stdio 标准 MCP 传输一致工作

- **WHEN** 内置智能体运行器通过 `mcp.NewInMemoryTransports()`, 或外部 MCP 客户端通过 `ledgerctl mcp` stdio 进程连接 `mcp.Server` 并执行 `tools/list` 与 `tools/call`
- **THEN** 两类传输返回的 JSON Schema 与工具执行结果一致, 底层核心函数同时可供高频基准测试直接调用

#### Scenario: replace_grant 与 reconcile_order 工具确定性执行改派与未知订单核账

- **WHEN** 上层分别调用 `replace_grant` 由 `A1` 原子撤旧 `G2` 并向 `B2` 签发 `G2'`, 以及在 `create_order` 响应截断且上级撤销后调用 `reconcile_order` 停发并提交核账单
- **THEN** `replace_grant` 校验 `A1` 权限与约束收缩后执行链上 `ReplaceGrant` 并完成对 `B2` 的新材料逐跳交付
- **AND** `reconcile_order` 递增 `sendRevision` 锁定原意图拒绝延迟重发, 经网关接口提交核账单并取回 `CREATED`/`NOT_CREATED`/`UNKNOWN` 回执后脱敏返回恢复结果
