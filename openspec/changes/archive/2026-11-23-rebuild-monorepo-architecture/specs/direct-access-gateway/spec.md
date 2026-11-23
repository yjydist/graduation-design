# Spec Delta: direct-access-gateway

## MODIFIED Requirements

### Requirement: 直接访问询价生成与业务键幂等

当 `U` 或受托主体持有效授权链与真实身份凭证, 以规范资源 URI `urn:grad:resource:C:quotes` 发起 `quote.read` 并通过锁后复核与 OPA 求值时, C 网关 SHALL 按目录基准单价 (`80000` 分) 生成不可变报价行 (`quotes`), 设置 `validUntil = min(decision_at + 300, task.validUntil)`, 并将挑战消费, 审计决策和 `(actor, taskId, action, idempotencyKey)` 业务键在同一事务提交. 网关 SHALL 拒绝非规范资源短别名, 并使用平台统一的结构化 REST 错误信封返回错误.

#### Scenario: U 持 RP G0 直接询价成功及同键幂等重试

- **WHEN** `U` 出示绑定当前部署的 `C -> U` `G0`, `U`/`C` 凭证, T 域认证与 `KB-JWT`, 以 `resource="urn:grad:resource:C:quotes"` 发起 `quote.read` 询价并提交成功
- **THEN** 网关返回 `200` 及 `{decisionId, code:"ALLOW", quote}` (`unitPriceMinor=80000`), 数据库同时可见已消费挑战, 一条 `ALLOW` 决策与一份报价
- **AND** 在报价有效期内使用新挑战与同一 `(actor, taskId, "quote.read", idempotencyKey)` 和相同请求摘要重试返回同一 `quoteId` 与新的 `decisionId`, 同键异摘要返回 `409 IDEMPOTENCY_CONFLICT`

#### Scenario: 错误叶子私钥签名被拒绝

- **WHEN** 请求使用与 `U` 登记 `appKeyId` 不匹配的错误 P-256 私钥签发 `KB-JWT`
- **THEN** 网关在验证持有者阶段返回 `401 SIGNATURE_INVALID` 且 `decisionId` 为 `null`, 原挑战未消费且无报价或业务键写入

#### Scenario: 拒绝历史资源短别名

- **WHEN** 请求使用旧资源别名 (如 `"quotes"` 或 `"urn:grad:resource:quotes"`) 发起 `quote.read`
- **THEN** 网关以统一结构化错误信封返回 `400 INVALID_SCHEMA` 且 `decisionId` 为 `null`, 原挑战未消费且无报价或业务键写入

### Requirement: 模拟订单创建与双实例唯一订单约束

C 网关 SHALL 扩展 `POST /v1/access/execute` 支持以规范资源 URI `urn:grad:resource:C:orders` 发起 `order.create`, 在锁后复核中核验 `quoteId` 归属, 有效期与真实总额, 检查整条委托链状态与 `path.maxAmountMinor` 上限, 并在共享业务主库上保证跨多个网关实例对同一 `(deployment_id, actor, task_id, idempotency_key)` 至多创建一笔不可变订单.

#### Scenario: RP 与 BM 模式下 800 元下单成功及 1200 元超额拒绝

- **WHEN** `B1` 持有效 `G0 -> G1 -> G2` (`G2` 单笔上限 `100000` 分) 分别在 RP 与 BM 模式下先取得有效报价 (`Q800` 为 `80000` 分, `Q1200` 为 `120000` 分), 再以 `resource="urn:grad:resource:C:orders"` 提交真实总额匹配的 `order.create` 请求
- **THEN** 800 元订单提交成功返回 `200 {decisionId, code:"ALLOW", order}` (`status="CREATED"`), 数据库可见消费挑战, `ALLOW` 决策与唯一订单行
- **AND** 1200 元真实订单触发 `403 AMOUNT_LIMIT_EXCEEDED` 且无新订单行; 篡改 `Q1200` 金额为 `80000` 分先触发 `409 AMOUNT_MISMATCH`; 引用其他主体或任务报价返回 `403 QUOTE_SCOPE_MISMATCH`; 报价到期当秒返回 `409 QUOTE_EXPIRED`

#### Scenario: 锁后风险升级为 ELEVATED/BLOCKED 或采用 G1 撤销块后拒绝建单

- **WHEN** 持有有效 `Q800` 的合法 `order.create` 在初验时满足条件, 但锁后可信环境变为 `ELEVATED`/`BLOCKED`, 或所采用的固定高度检查点已包含 `G1` 撤销块 `r`
- **THEN** 锁后风险为 `ELEVATED` 或 `BLOCKED` 时拒绝建单并返回 `403 POLICY_DENIED`; 采用 `G1` 撤销块后拒绝旧路径并返回 `403 ANCESTOR_INACTIVE`; 两种拒绝均不产生订单行

#### Scenario: 双网关实例同键并发仅产生一笔订单

- **WHEN** 两个共享同一业务主库的 C 网关实例同时收到不同有效挑战但相同 `(actor, taskId, "order.create", idempotencyKey)` 与相同摘要的合法订单请求, 或随后收到同键异摘要请求
- **THEN** 同摘要并发仅创建一笔不可变订单并均返回同一 `orderId` (各自关联自己的 `decisionId`); 同键异摘要返回 `409 IDEMPOTENCY_CONFLICT` 且不新增订单

### Requirement: 两实例未知订单核账与审计权限隔离

智能体侧恢复服务在发送 `order.create` 前 SHALL 在其独立维护的本地意图存储 (`client_actions`) 持久化意图锁 (`OUTCOME_UNKNOWN`), 当响应丢失且原路径被撤销或超时无法确认时 SHALL 递增 `sendRevision` 停发延迟工作进程, 并经角色绑定通道向网关 `POST /v1/internal/order-outcome-cases` 登记 `{caseId, sendRevision, deploymentId, request, requestHash, challengeIds}` (同一 `caseId` 内容不可变). C 网关数据边界 SHALL 仅维护服务端核账案例, 决策证据, 回执发件箱及业务主库表, 不承担智能体本地意图持久化. `POST /v1/audit/order-outcomes` SHALL 仅允许 `C` 审计员角色执行, 非审计员 (如 `B1` 或 `A` 域管理员) 调用 SHALL 返回 `403 AUDIT_FORBIDDEN` 且不得泄露订单是否存在.

#### Scenario: 订单响应丢失且 G1 撤销后经核账找回原订单并复核历史 h 小于 r

- **WHEN** `B1` 提交合法 `order.create` 后网关已成功提交但响应在返回前截断, 随后 `G1` 在块 `r` 被撤销, `B1` 重试触发 `403 ANCESTOR_INACTIVE` 并锁定本地意图停发后发起核账单与审计请求
- **THEN** `C` 审计员锁定挑战并集与业务键后确认订单与 `business_keys` 双向匹配, 返回 `CREATED` 与原 `orderId`, 并对创建决策 `d1` 复核 `h < r` 与原探针期限得出 `MATCHED`
- **AND** `C` 原子持久化审计记录与回执并投递至 `B` 端完结意图, 不新建第二笔订单且不改动原订单或原挑战行

#### Scenario: 非 C 审计员调用核账接口被拒绝且不泄露订单状态

- **WHEN** 分别以 `B1` 或 `A` 域管理员身份直接调用 `POST /v1/audit/order-outcomes`, 对照以 `C` 审计员身份查询同一提交记录
- **THEN** 非 `C` 审计员调用返回 `403 AUDIT_FORBIDDEN`, 响应体不泄露目标订单是否存在
- **AND** `C` 审计员调用正常返回核账与历史复核结果, 且原有报价, 订单, 业务键与挑战行均无变更

#### Scenario: 并发挑战其一在等锁时过期而另一有效挑战完成唯一建单

- **WHEN** `G1` 合法且 `Q800` 有效, 在不同秒签发两个挑战后并发提交同键同订单请求, 通过屏障使较早挑战在最终获锁时恰达 `expiresAt` 而另一挑战仍有效
- **THEN** 等锁后过期的请求按锁后 `clock_timestamp()` 返回 `401 CHALLENGE_EXPIRED` 且不消费该过期挑战
- **AND** 另一有效挑战完成 `order.create`, 业务主库恰存在一笔订单和一条 `ALLOW` 终态决策

#### Scenario: 未创建或未决订单与重复回执的确定性处理

- **WHEN** 核账服务收到已停发意图, 挑战清单或重复及迟到回执
- **THEN** 核账时 C 审计员 SHALL 按 `(actor, taskId, requestHash)` 枚举主库相关挑战并与请求 `challengeIds` 取并集按 ID 排序加锁, 随后锁定读取 `business_keys` 与 `orders`, 依主库事实返回 `CREATED` (附原 `orderId` 并执行历史 `h`/`r` 复核), `NOT_CREATED` (已验证停发与清单完整, 所有挑战均已消费拒绝或按锁后 `clock_timestamp()` 已过期且无待提交事务) 或 `UNKNOWN`; 读库或锁等待失败 SHALL 返回 `503` 以保持 B 端未知状态. 核账审计记录与回执 SHALL 原子持久化并经 `POST /v1/internal/order-outcome-receipts` 幂等交付 B 恢复服务, 同代次同序号同内容仅入库一次, 迟到的 `UNKNOWN` 回执不得重开已完结意图.
- **AND** 并发使用不同有效挑战提交同一订单键时, 若较早挑战在等锁时恰到 `expiresAt`, 该请求 SHALL 在不消费该挑战的前提下被拒绝, 另一有效挑战 SHALL 完成唯一建单.
