# agent-tool-runtime Specification

## Purpose

为采购智能体 `A1` 与协作智能体 `B1` 提供基于标准 MCP 协议的确定性钱包与协议工具服务, 持久化意图防重放锁, 以及支持 OpenAI 与 Anthropic 双官方 SDK 的可控推理调用闭环.

## Requirements

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

### Requirement: 双协议官方 LLM SDK 驱动的智能体推理与工具闭环

系统 SHALL 提供同时集成官方 OpenAI Go SDK (`github.com/openai/openai-go`) 与官方 Anthropic Go SDK (`github.com/anthropics/anthropic-sdk-go`) 的智能体运行器, 按 `LLM_PROVIDER` (`openai`|`anthropic`), `LLM_BASE_URL`, `LLM_API_KEY` 与 `LLM_MODEL` 连接可配置模型服务并通过 `mcp.ClientSession` 完成 `A1` 签发与改派 `G2`, `B1`/`B2` 在 RP/BM 下的 800 元下单与 1200 元超额拒绝, 以及 `B1` 订单响应丢失后的核账恢复闭环, 同时记录推理耗时与工具调用轨迹.

#### Scenario: A1 与 B1 通过 MCP 工具调用完成 RP 与 BM 采购闭环

- **WHEN** `A1` 与 `B1` 智能体运行器接入真实模型服务 (或离线测试中的协议模拟服务端点), 在有界推理步数内按 `taskSpec` 自主发起 MCP 工具调用
- **THEN** `A1` 查阅 `G1` 后调用 `delegate_grant` 向 `B1` 签发符合收缩规则的 `G2` (`100000` 分, 深度 `0`); `B1` 调用 `request_quote` 与 `create_order` 在 RP 与 BM 模式下均完成 800 元订单闭环 (`CREATED`)
- **AND** 面对 1200 元真实报价 `Q1200` 或诱导超额下单时, 无论模型拒绝调用还是尝试发起 `create_order`, 最终均无新订单产生, 运行器输出完整的 `llmLatencyMs`, `toolCallsCount` 与工具轨迹 (不含 `LLM_API_KEY` 或私钥)

#### Scenario: A1 改派 B2 重新询价建单与 B1 响应丢失后核账恢复轨迹

- **WHEN** 分别运行 M3 动态轨迹: (1) `A1` 调用 `replace_grant` 将 `G2` 改派给 `B2`, `B2` 先尝试引用 `B1` 的 `Q800` 下单失败 (`403 QUOTE_SCOPE_MISMATCH`) 再自主重新询价并下单; (2) `B1` 下单响应丢失且 `G1` 已被撤销, `B1` 重试遇 `403 ANCESTOR_INACTIVE` 后调用 `reconcile_order` 完成核账恢复
- **THEN** 改派轨迹中 `B1` 旧路径失效, `B2` 引用 `B1` 报价不产生订单并在重新询价后生成属于 `B2` 的唯一订单 (`CREATED`)
- **AND** 核账恢复轨迹中 `B1` 停发并成功找回原 `orderId`, 运行器记录两条轨迹的完整工具调用顺序, 状态转移与脱敏推理耗时

### Requirement: Web 与 MCP 共用确定性业务操作

系统 SHALL 为 Web 后端及 MCP 提供共同的强类型业务操作. 同一操作 SHALL 在两个入口使用相同的身份, 输入, 授权和幂等规则, 并沿原业务服务取得结果. MCP SHALL 仅暴露当前执行获准使用的操作.

A 域工作台后端 SHALL 可通过受控域间 HTTP 调用 B1 已接收运行的询价和下单操作. B 域 SHALL 从原派单加载运行绑定, 并使用与该运行 MCP 相同的有效授权检查及业务键.

#### Scenario: 相同业务输入通过两个入口获得一致判据

- **WHEN** 以相同主体和业务输入分别经获准的 Web 操作与 MCP 发起配对操作, 或任一入口收到不满足相同约束的输入
- **THEN** 两个入口使用相同的确定性规则, 返回可核对的业务结果或错误码, 业务副作用服从原事务与幂等约束
- **AND** 工作台 Agent 工具清单不开放域管理写入, 用户确认或超出当前执行阶段的能力

#### Scenario: 首次下单前重启后继续使用原报价

- **WHEN** B1 已返回成功报价, 并在首次下单前重启
- **THEN** 任一获准入口 SHALL 可用原报价 ID 和金额提交首次订单, 沿用原运行的报价和订单业务键
- **AND** C 网关仍 SHALL 在首次下单时校验报价有效期和当前授权, 两个入口的同键重试只对应一笔订单

### Requirement: 工作台派单绑定各域智能体身份与当前任务

工作台发起的运行 SHALL 在服务端绑定部署, 域, 智能体 DID, 已确认任务和当前有效授权. 每次工具调用 SHALL 复核该绑定. A1 转委托给 B1 后, B 域 SHALL 在核对并接收 `G2` 后使用本域钱包执行, 保留与原任务和运行关联的结果.

#### Scenario: 两域智能体按已交付的授权执行

- **WHEN** A1 使用已交付的 `G1` 通过 MCP 有效提交并交付 `G2`, B 域收到对应任务的执行请求
- **THEN** A 域记录 A1 的签发及交付结果, B 域验证来源, 任务及收件绑定后以 B1 身份调用询价和订单工具, C 验证实际展示材料及持有者证明
- **AND** 每域仅调用本域获准的签名主体, 重复派发或交付沿用同一运行和业务键, 任务视图可核对跨域执行结果

#### Scenario: 伪造工具参数不能选择其它签名主体或任务

- **WHEN** Agent 输入或工具参数试图改变执行域, 签名主体, 任务, 授权模式, 或引用不属于当前任务的委托
- **THEN** 运行时拒绝调用并记录结构化失败, 不以其它身份查询钱包, 签名或发起业务请求
- **AND** Web 会话及模型提示不授予 Agent 额外权限, 工具轨迹排除凭据和未披露材料

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
