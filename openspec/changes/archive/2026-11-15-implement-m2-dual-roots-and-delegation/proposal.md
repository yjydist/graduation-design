# 变更提案

## 为什么

Fabric D0 最小网络, D0 最小协议与 M1 直接访问已完成单跳 `C -> U` RP `G0` 与 `quote.read` 询价闭环, 但尚未覆盖双根权源, 多级委托, 模拟订单执行与智能体推理闭环. 按照 [阶段任务](../../../TODO.md), [部署与链上登记](../../../docs/implementation/部署与链上登记.md), [委托授权与策略](../../../docs/design/委托授权与策略.md), [证据交付与网关执行](../../../docs/implementation/证据交付与网关执行.md), [策略输入与数据约束](../../../docs/implementation/策略输入与数据约束.md) 和 [REST接口与响应码](../../../docs/implementation/REST接口与响应码.md), M2 阶段需要交付首个完整 MVP (D0-M2): 补齐 T 对 A/B/C 三域及 `IA`/`IB`/`IC` 的认证, `PA` 采购授权资格与 `BUYER_MANDATE` (`BM`) 根授权 `G0`, 双域身份关联 (`IdentityLink`) 审批, `G0 -> G1 -> G2` 两级委托交付与祖先状态核验, `order.create` 与双实例唯一订单约束, 以及基于三大官方 Go SDK (`github.com/modelcontextprotocol/go-sdk`, `github.com/openai/openai-go`, `github.com/anthropics/anthropic-sdk-go`) 的 `A1`/`B1` 智能体工具调用闭环.

## 变更内容

- 链码与链上登记扩展 (`chaincode/registry`, `internal/fabricapi`, `internal/fabric`): 支持 A 域管理员设置 `PA` 的 `purchasingAuthority` 资格, 支持创建 `BUYER_MANDATE` (`BM`) 任务并由当前有效 `PA` 签发 `BM` 根授权 `G0`; 新增双域身份关联 (`IdentityLink`) 提案, 另一域注册机构审批 (`effectiveActive`) 与撤销操作, 验证关联不转移采购权限 (`F02`, `S35-S40`).
- 三域完整身份引导与两级委托 (`G0 -> G1 -> G2`) 逐跳交付 (`internal/fabric`, `internal/protocol`): 完成 T 对 A/B/C 三域及 `IA`/`IB`/`IC` 的认证, 登记 `U`, `PA`, `A1`, `B1`, `U-in-B`, `C` 服务并签发 SD-JWT 凭证; 实现 RP (`C -> U -> A1 -> B1`) 与 BM (`PA -> U -> A1 -> B1`) 的 `G0`/`G1`/`G2` 逐跳签发, 范围收缩 (`500000 -> 500000 -> 100000` 分, 深度 `2 -> 1 -> 0`) 与 `grant_outbox` / `wallet_receipts` 的祖先最小出示及 `trustPaths` 去重装配 (`F01`, `F03-F05`).
- 网关 `order.create` 订单事务与双实例唯一订单约束 (`internal/gateway`, `internal/policy`): 建立 `orders` 表 (`UNIQUE (deployment_id, actor, task_id, idempotency_key)`) 与客户端意图锁表 `client_actions`; 扩展 `POST /v1/access/execute` 支持 `order.create`, 核对报价归属, 有效期, 真实总额与整条委托链最小上限 (`path.maxAmountMinor`), 核对 `BM` 模式下 `PA` 的当前资格 (`ROOT_AUTHORITY_INVALID`) 与 C 独立准入配置 (`SUPPLIER_POLICY_DENIED`), 锁后比对视图检查点 (采用 `G1` 撤销块后拒绝旧路径 `ANCESTOR_INACTIVE`), 锁后 `ELEVATED`/`BLOCKED` 拒绝建单, 以及双网关实例 (8103/8104) 同键并发仅生成一笔订单 (`F06-F13`).
- 基于三大官方 SDK 的 `A1`/`B1` 智能体与标准 MCP 工具层 (`internal/agent`, `cmd/ledgerctl`): 在 `go.mod` 引入官方 MCP Go SDK (`github.com/modelcontextprotocol/go-sdk`), 官方 OpenAI Go SDK (`github.com/openai/openai-go`) 与官方 Anthropic Go SDK (`github.com/anthropics/anthropic-sdk-go`); 将确定性钱包与协议工具 (`inspect_wallet`, `delegate_grant`, `request_quote`, `create_order`) 封装为标准 `mcp.Server` (同时支持进程内 `mcp.NewInMemoryTransports()`, `ledgerctl mcp` stdio 服务及基准测试底层 Go 函数直调), 由持 `mcp.ClientSession` 的 `AgentRunner` 通过可配置环境变量 (`LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`) 驱动 `A1` 签发 `G2`, 驱动 `B1` 在 RP/BM 下完成 800 元询价下单与 1200 元超额拒绝闭环, 并纳入 `ledgerctl verify` 联合验收.

## 能力

### 新增能力

- `agent-tool-runtime`: 定义基于官方 MCP Go SDK (`github.com/modelcontextprotocol/go-sdk`) 的确定性钱包与协议工具服务 (`inspect_wallet`, `delegate_grant`, `request_quote`, `create_order`), `client_actions` 意图锁, 以及基于官方 `openai-go` / `anthropic-sdk-go` 的 `A1`/`B1` 智能体 MCP Client 推理与工具调用闭环.

### 修改能力

- `authorization-registry`: 增加 B 域引导与认证, `PA` 采购授权资格 (`purchasingAuthority`) 配置, `BUYER_MANDATE` (`BM`) 任务与根授权 `G0` 登记, `G1 -> G2` 两级子委托登记与逐跳材料交付, 以及双域身份关联 (`IdentityLink`) 提案, 双域审批与撤销约束.
- `verifiable-protocol`: 增加 `BUYER_MANDATE` 模式下 `PA` 根资格与多跳委托链 (`G0 -> G1 -> G2`) 的路径收缩 (`maxAmountMinor`, `maxDelegationDepth`), 多跳祖先最小出示及跨三域 `trustPaths` 去重核验.
- `direct-access-gateway`: 增加 `order.create` 模拟订单执行分支, 报价归属与总额核验, 委托链金额上限与祖先状态 (`ANCESTOR_INACTIVE`) 校验, 两种根权源与 C 独立准入策略 (`SUPPLIER_POLICY_DENIED`) 判定, 锁后 `ELEVATED`/`BLOCKED` 拒绝建单及双网关实例同键并发唯一订单事务.

## 影响

- 新增 `internal/agent` 包并在 `cmd/ledgerctl` 增加 `mcp` 子命令, 扩展 `chaincode/registry`, `internal/fabricapi`, `internal/fabric`, `internal/protocol`, `internal/policy`, `internal/gateway`, 并在 `go.mod` 引入 `github.com/modelcontextprotocol/go-sdk`, `github.com/openai/openai-go`, `github.com/anthropics/anthropic-sdk-go`.
- 静态验签缓存, 身份状态管理与管理账户恢复, 域资格续发/收缩, 密钥轮换, `B2` 改派与未知订单核账 (`reconcile_order`) 留在 M3 阶段实施.
