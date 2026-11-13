# 实施任务

本清单交付 M2 两种根与两级委托实现及绑定当前 Fabric 部署的验证证据. 机制见 [设计](design.md), 行为验收依据为 [授权登记](specs/authorization-registry/spec.md), [可验证协议](specs/verifiable-protocol/spec.md), [直接访问网关](specs/direct-access-gateway/spec.md) 和 [智能体工具运行时](specs/agent-tool-runtime/spec.md).

## 1. 链码与登记扩展: PA 采购资格, BM 根与双域身份关联

- [ ] 1.1 扩展 `internal/fabricapi` 与 `chaincode/registry`, 为 `Domain` 增加 `PurchasingAuthority` 字段并实现 `SetPurchasingAuthority` 交易 (限本域登记管理员将有效本域 `SERVICE` 设为 `PA`, 配合 `expectedRevision` 防竞争), 运行单元测试验证非管理员, 非本域身份或非 `SERVICE` 主体均被拒绝.
- [ ] 1.2 扩展 `chaincode/registry/grant.go` 与 `internal/fabric/view.go`, 支持 `BUYER_MANDATE` (`BM`) 任务创建及由当前有效 `PA` 签发 `BM` 根授权 `G0`, 并拒绝 `IA`/`IB`/`IC`/`T` 或在 `RP` 模式下使用 `PA` 签发 `G0`; 运行单元测试与视图装配测试验证 `BM` 根与 `RP` 根各自的权源约束.
- [ ] 1.3 在 `chaincode/registry` 与 `internal/fabricapi` 实现双域身份关联 (`ProposeIdentityLink`, `ApproveIdentityLink`, `RevokeIdentityLink`) 与 PostgreSQL 视图应用, 要求两端 PoP 与账号认证并仅在另一域注册机构批准同一提案摘要后变为 `effectiveActive`, 运行测试验证单方待审批状态, 冒充他域审批拒绝及撤销后互不影响.

## 2. 三域身份引导与两级委托 (G0->G1->G2) 逐跳交付

- [ ] 2.1 扩展 `internal/fabric` 引导与材料交付流程, 补齐 `T` 对 `B` 域与 `IB` 认证, 经注册挑战与双证明登记 `A1`, `B1`, `U-in-B` 与 `PA` 并签发 SD-JWT 凭证, 运行测试验证 `B` 域认证, 凭证锚有效期边界与 `U` vs `U-in-B` 权限隔离.
- [ ] 2.2 扩展 `internal/protocol` 委托链与证据包验证, 支持 `RP` (`C -> U -> A1 -> B1`) 与 `BM` (`PA -> U -> A1 -> B1`) 三级委托核验 (`500000 -> 500000 -> 100000`, 深度 `2 -> 1 -> 0`), 按域认证 ID 去重 `trustPaths`, 运行测试验证 `DELEGATION_EXPANSION`, `PATH_INVALID`, `AUTHORIZATION_MODE_MISMATCH` 与 `ROOT_AUTHORITY_INVALID`.
- [ ] 2.3 扩展 `grant_outbox` 与 `wallet_receipts` 逐跳交付逻辑, 使 `C`/`PA -> U -> A1 -> B1` 在原交易 `VALID` 且资格/期限有效时交付祖先最小凭证出示与去重 `trustPaths`, 运行测试验证多跳收件去重与 `DELIVERY_CONFLICT`.

## 3. C 网关 order.create 事务, 锁后复核与双实例唯一订单

- [ ] 3.1 在 `internal/gateway/schema.go` 新增 `orders` 表 (`UNIQUE (deployment_id, actor, task_id, idempotency_key)`) 与 `client_actions` 意图锁表, 更新 `internal/policy` 策略包同时支持 `RESOURCE_PREAUTHORIZED` 与 `BUYER_MANDATE` 独立准入及 `order.create` (`NORMAL` 允许, `ELEVATED`/`BLOCKED` 拒绝), 运行单元测试验证 `SUPPLIER_POLICY_DENIED` 与 `POLICY_DENIED`.
- [ ] 3.2 在 `internal/gateway/execute.go` 实现 `order.create` schema 校验与 `READ COMMITTED` 锁后复核事务 (`challenges -> business_keys -> quotes -> trusted_contexts -> fabric_head`), 校验 `quoteId` 归属 (`QUOTE_SCOPE_MISMATCH`), 报价有效期 (`QUOTE_EXPIRED`), 真实总额 (`AMOUNT_MISMATCH`) 与委托路径 `maxAmountMinor` 上限 (`AMOUNT_LIMIT_EXCEEDED`), 运行测试验证 800 元建单成功与 1200 元超额拒绝.
- [ ] 3.3 验证 `order.create` 的锁后动态边界: 锁后风险升级为 `ELEVATED`/`BLOCKED` 时拒绝建单 (`403 POLICY_DENIED`); 采用 `G1` 撤销块 `r` 后拒绝旧路径 (`403 ANCESTOR_INACTIVE`); 使用 `U-in-B` 冒用 `U` 路径被拒绝; 均确保主库无新订单行写入.
- [ ] 3.4 运行双 C 网关实例并发集成测试 (模拟 `8103` 与 `8104` 共享同一业务主库), 验证不同有效挑战但相同 `(actor, taskId, "order.create", idempotencyKey)` 并发请求仅产生一笔不可变订单并均返回同一 `orderId`, 同键异摘要返回 `409 IDEMPOTENCY_CONFLICT`.

## 4. 三大官方 SDK 智能体运行时与 MCP 协议工具层

- [ ] 4.1 在 `go.mod` 引入官方 MCP Go SDK (`github.com/modelcontextprotocol/go-sdk`), 官方 OpenAI Go SDK (`github.com/openai/openai-go`) 与官方 Anthropic Go SDK (`github.com/anthropics/anthropic-sdk-go`), 并确保离线 `go test -count=1 ./...` 与 `CGO_ENABLED=0` 链码构建无回归.
- [ ] 4.2 新建 `internal/agent` 工具层与标准 MCP Server: 使用 `mcp.NewServer` 与 `mcp.AddTool` 注册 `inspect_wallet`, `delegate_grant`, `request_quote`, `create_order`, 在发送 `order.create` 前持久化 `client_actions` 意图锁, 隔离应用私钥与披露盐值; 在 `cmd/ledgerctl` 增加 `mcp` 子命令挂载 `mcp.StdioTransport`, 运行单测验证进程内传输与脱敏输出.
- [ ] 4.3 实现基于 `mcp.ClientSession` 与 `openai-go` / `anthropic-sdk-go` 双官方 SDK 的 `AgentRunner` (支持 `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` 配置与有界推理步数, 记录 `llmLatencyMs`, `toolCallsCount` 与完整工具轨迹), 内置 OpenAI 与 Anthropic `httptest` 双协议模拟服务跑通 `A1` 签发 `G2` 与 `B1` 在 RP/BM 下 800 元成功和 1200 元拒绝离线闭环.

## 5. Fabric M2 端到端联合验收与证据归档

- [ ] 5.1 扩展 `cmd/ledgerctl` 与 `internal/fabric/verify.go`, 在 D0 + M1 (26 项) 之上新增 M2 联合验收用例: RP 与 BM 双模式各跑通 800 元成功与 1200 元拒绝 (含真实 LLM 智能体 `A1`/`B1` 工具调用闭环), 双域身份关联审批与权限隔离, C 独立策略拒绝合法 PA 根, 采用 `G1` 撤销块后拒绝旧路径, 锁后 `ELEVATED`/`BLOCKED` 不建单, 以及双实例并发同键唯一订单.
- [ ] 5.2 在真实 Fabric 实例上运行 `mise run test:unit` 与 `mise run ledger:verify` (接入可配置 LLM API 运行 `A1`/`B1` 闭环), 核对全部 M2 验收项通过并输出不含私钥与 `LLM_API_KEY` 的结构化证据.
- [ ] 5.3 更新 [技术栈](../../../docs/implementation/技术栈.md), [TODO](../../../TODO.md) 与 [证据索引](../../../infra/fabric/evidence/README.md) 中 M2 阶段状态, 依赖说明与验收证据链接.

## 工作流后续

- 实施完成后运行 `/openspec-verify-change` 对照全部需求与场景核验代码, 测试与实机证据, 同步主规范后归档 `implement-m2-dual-roots-and-delegation`.
