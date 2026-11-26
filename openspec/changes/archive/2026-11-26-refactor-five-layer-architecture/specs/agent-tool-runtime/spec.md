## MODIFIED Requirements

### Requirement: 基于官方 MCP SDK 的确定性钱包与协议工具服务

系统 SHALL 将 L2 确定性钱包领域核与 L3 官方 MCP Go SDK 工具服务显式解耦. L3 MCP 服务 SHALL 封装 `inspect_wallet`, `delegate_grant`, `replace_grant`, `request_quote`, `create_order` 与 `reconcile_order` 六个强类型工具, 仅调用 L2 钱包领域服务并强制隔离应用私钥与原始披露盐值. L2 钱包层 SHALL 独立维护 `client_actions` 意图锁并通过 HTTP 客户端与 C 网关交互, 支持改派与停发核账恢复. L3 MCP 服务 SHALL 同时支持进程内传输与 `ledgerctl mcp` stdio 服务.

#### Scenario: 私钥隔离与发送前意图锁持久化

- **WHEN** 上层通过 MCP `tools/call` 调用 `inspect_wallet`, `delegate_grant`, `replace_grant`, `request_quote`, `create_order` 或 `reconcile_order`
- **THEN** 工具输出仅包含业务摘要, 委托约束, 报价, 订单或核账结果, 不得包含应用私钥字节或原始披露盐值
- **AND** `create_order` 在请求 C 网关前必先在 L2 钱包持久化层写入 `client_actions` 意图行 (`OUTCOME_UNKNOWN`, `actionId`, `requestHash`, `idempotencyKey`, `sendRevision`), 挑战 `nonce` 原样绑定与 `KB-JWT` 签名均由 L2 确定性核完成

#### Scenario: 进程内与 stdio 标准 MCP 传输一致工作

- **WHEN** L4 智能体编排器通过 `mcp.NewInMemoryTransports()`, 或外部 MCP 客户端通过 `ledgerctl mcp` stdio 进程连接 L3 `mcp.Server` 并执行 `tools/list` 与 `tools/call`
- **THEN** 两类传输返回的 JSON Schema 与工具执行结果一致, L2 确定性钱包操作同时可供高频基准测试直接调用

#### Scenario: replace_grant 与 reconcile_order 工具确定性执行改派与未知订单核账

- **WHEN** 上层分别调用 `replace_grant` 由 `A1` 原子撤旧 `G2` 并向 `B2` 签发 `G2'`, 以及在 `create_order` 响应截断且上级撤销后调用 `reconcile_order` 停发并提交核账单
- **THEN** `replace_grant` 校验 `A1` 权限与约束收缩后执行链上 `ReplaceGrant` 并完成对 `B2` 的新材料逐跳交付
- **AND** `reconcile_order` 递增 `sendRevision` 锁定原意图拒绝延迟重发, 经网关接口提交核账单并取回 `CREATED`/`NOT_CREATED`/`UNKNOWN` 回执后脱敏返回恢复结果

## ADDED Requirements

### Requirement: 五层单向依赖与智能体协议隔离边界

平台模块 (`grad/platform`) SHALL 按 L1 基础设施, L2 逻辑封装 (`core/`), L3 服务 (`service/api`, `service/mcp`), L4 Agent (`agent/`) 与薄装配入口 (`bootstrap/`, `cmd/`) 组织严格单向依赖, 任一层 SHALL 仅依赖其下方允许层与 `grad/protocol`. L4 Agent 层 SHALL 仅通过 L3 MCP 协议执行工具调用, 不得直接导入 L2, 数据库或 Fabric SDK. 平台测试套件 SHALL 包含自动化导入红线校验 (`arch_test.go`), 在单测期阻断任何越层依赖.

#### Scenario: L4 Agent 与 L3 服务层满足单向导入红线

- **WHEN** 运行平台单元测试 (含 `arch_test.go`) 静态扫描 `grad/platform/...` 全部生产与测试包的导入图
- **THEN** `platform/agent/...` 的导入中不含 `platform/core/...`, `platform/service/api/...`, `pgx` 或 `fabric-gateway`
- **AND** `platform/service/...` 的导入中不含 `platform/agent/...`, `pgxpool` 直接业务查询或 LLM SDK, `platform/core/...` 不含 `platform/service/...` 或 `platform/agent/...`
- **AND** 任何新增越层导入都会立即导致架构校验测试失败

#### Scenario: 单域二进制通过标准 MCP 协议隔离 L4 与 L3

- **WHEN** A/B/C 域后端进程启动并处理采购对话, A1 转委托及 B1 询价下单流程
- **THEN** L4 编排层通过标准 MCP 会话调用 L3 MCP Server 暴露的受限工具集, 不绕过 MCP 直接持有或读取 L2 钱包私钥上下文
- **AND** `platform/bootstrap` 与 `platform/cmd` 仅承担依赖注入装配与生命周期管理, 不承载业务领域判断或协议状态机逻辑
