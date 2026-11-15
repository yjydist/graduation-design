# direct-access-gateway Specification

## Purpose

为供应商 C 访问网关提供挑战签发与一次性消费, OPA 策略包校验与确定性求值, 可信风险上下文管控, 锁后固定高度与时钟边界复核, 以及直接访问询价与业务键幂等事务.

## Requirements

### Requirement: 挑战签发, 原值绑定与一次性消费

C 网关 SHALL 通过 `POST /v1/auth/challenges` 为提交 `{actor, taskId, requestHash}` 的客户端签发唯一 `challengeId` 与 32 字节随机数编码的 43 字符无填充 base64url `nonce`, 固定服务配置 `audience` 及 30 秒有效期限. 客户端提交 `POST /v1/access/execute` 时 SHALL 原样绑定该 `nonce` 字符串与对应请求摘要; 挑战未消费前允许并发检查竞争且至多一次终态消费.

#### Scenario: 原样绑定挑战并完成消费

- **WHEN** 客户端申请新挑战并在 30 秒有效期内提交与 `actor`, `taskId`, `requestHash` 和原样 `nonce` 字符串一致的合法 `KB-JWT`
- **THEN** 网关在事务提交时原子写入 `consumedAt` 并生成关联该挑战的终态 `decisionId`
- **AND** 后续再次提交相同 `challengeId` 返回 `409 CHALLENGE_REPLAY`, 无新增业务行或终态决策

#### Scenario: 拒绝未知, 替换绑定或已过期挑战

- **WHEN** 客户端分别提交不存在的 `challengeId`, 替换了合法 `nonce` 或 `requestHash` 的绑定, 或在 `now >= expiresAt` 时使用未消费挑战
- **THEN** 网关依次返回 `401 CHALLENGE_UNKNOWN`, `401 REQUEST_BINDING_MISMATCH` 或 `401 CHALLENGE_EXPIRED` 且 `decisionId` 为 `null`
- **AND** 上述拒绝均不消费原未用挑战且不写入 `business_keys` 或 `quotes`

### Requirement: 策略包完整性校验与确定性 OPA 求值

C 网关 SHALL 加载包含 `manifest.json`, Rego v1 (`package procurement`), 输入 schema 及角色/资源配置的策略包, 按文件名排序校验内容文件 SHA-256 与 `JCS(manifest)` 摘要, 并强制策略 `trustRoots` 与部署 `RootRecord` 完全一致. 求值 SHALL 启用严格 built-in 错误处理并禁用网络及 `time.now_ns()`, 根据已核验主体的 `authorizationMode`, `principalDomain`, `productId`, `quantity` 与当前策略接受列表计算 `supplierAcceptance`, 并按 `quote.read` (`NORMAL`/`ELEVATED` 允许) 与 `order.create` (`NORMAL` 且总额不超过 `path.maxAmountMinor` 才允许) 执行确定性求值.

#### Scenario: 拒绝篡改策略包或替换根的策略配置

- **WHEN** 策略包正文的 `.rego` 或配置发生未更新版本的修改, 或 `trustRoots` 尝试将预置 T 根替换为其他根密钥或 DID
- **THEN** 策略包加载与预检立即拒绝该策略包, 网关不进入就绪状态且不采用该策略执行任何访问决策

#### Scenario: 按可信风险环境执行 quote.read 策略求值

- **WHEN** 其余密码学, 身份路径与范围条件均合法时, 任务可信环境 `riskLevel` 分别为 `NORMAL`, `ELEVATED` 或 `BLOCKED`
- **THEN** `NORMAL` 与 `ELEVATED` 下的 `quote.read` 均由 OPA 返回唯一布尔 `true`
- **AND** `BLOCKED` 下 OPA 返回拒绝 (`403 POLICY_DENIED`), 不采信客户端自报的 `verified=true`, `NORMAL` 或 `supplierAcceptance=true`, 求值异常或 `undefined` 一律拒绝

#### Scenario: 按可信风险环境与 C 独立准入执行 OPA 策略求值

- **WHEN** 其余密码学, 身份路径与范围条件均合法时, 分别在 `NORMAL`/`ELEVATED`/`BLOCKED` 下发起 `quote.read` 或 `order.create`, 以及在 C 策略拒绝对应买方域, 商品或 `BUYER_MANDATE` 模式时提交合法 `PA` 根或 `C` 根请求
- **THEN** `quote.read` 在 `NORMAL`/`ELEVATED` 下允许而在 `BLOCKED` 下返回 `403 POLICY_DENIED`; `order.create` 仅在 `NORMAL` 且未超 `path.maxAmountMinor` 时允许, 在 `ELEVATED` 或 `BLOCKED` 下返回 `403 POLICY_DENIED`; C 独立准入拒绝时返回 `403 SUPPLIER_POLICY_DENIED` 且不自动降级切换模式
- **AND** 不采信客户端自报的 `verified=true`, `NORMAL` 或 `supplierAcceptance=true`, 求值异常或 `undefined` 一律拒绝

### Requirement: 锁后状态复核与到期当秒拒绝

C 网关执行 `POST /v1/access/execute` 时 SHALL 在 `READ COMMITTED` 事务中依次锁定 `challenges` 行, 协调 `business_keys` 占位, 共享锁定 `trusted_contexts` 行并共享锁定 `fabric_head` 检查点. 取得全部锁后, 网关 SHALL 比对初验块高/哈希, 使用 PostgreSQL `clock_timestamp()` 与单调钟复核原探针及全部业务截止并重跑 OPA 求值; 任一期限到达截止当秒 (`now == deadline`) SHALL 拒绝.

#### Scenario: 初验通过但锁后环境变为 BLOCKED 时拒绝且无业务效果

- **WHEN** `U` 持合法 `C -> U` 根授权在 `NORMAL` 状态下通过初验, 但在网关取得 `trusted_contexts` 共享锁前观测器已提交 `BLOCKED`
- **THEN** 锁后最终 OPA 求值读取 `BLOCKED` 副本并拒绝放行, 返回 `403 POLICY_DENIED`
- **AND** 网关撤销暂存的 `business_keys` 占位, 不生成 `quotes` 行, 仅提交挑战消费及记录包含锁后 `contextVersion` 的拒绝 `decisions`

#### Scenario: 探针到期与业务期限到期当秒拒绝

- **WHEN** 本进程原探针到达单调期限 (`nowMono >= probe.deadlineMono`), 或锁后 `clock_timestamp()` 恰等于 `challenge.expiresAt`, `context.accessDeadline`, `policyDeadline`, `task.validUntil`, 域认证/凭证/`G0` `exp`
- **THEN** 探针到期返回 `503 STATE_STALE`, 其余到期当秒在各自校验点拒绝放行, 无 `quotes` 行产生

### Requirement: 直接访问询价生成与业务键幂等

当 `U` 持 `C` 签发的 `RESOURCE_PREAUTHORIZED` 根授权 `G0` 与真实身份凭证通过锁后复核与 OPA 求值时, C 网关 SHALL 按目录基准单价 (`80000` 分) 生成不可变报价行 (`quotes`), 设置 `validUntil = min(decision_at + 300, task.validUntil)`, 并将挑战消费, 审计决策和 `(actor, taskId, action, idempotencyKey)` 业务键在同一事务提交.

#### Scenario: U 持 RP G0 直接询价成功及同键幂等重试

- **WHEN** `U` 出示绑定制备部署的 `C -> U` `G0`, `U`/`C` 凭证, T 域认证与 `KB-JWT` 发起 `quote.read` 询价并提交成功
- **THEN** 网关返回 `200` 及 `{decisionId, code:"ALLOW", quote}` (`unitPriceMinor=80000`), 数据库同时可见已消费挑战, 一条 `ALLOW` 决策与一份报价
- **AND** 在报价有效期内使用新挑战与同一 `(actor, taskId, "quote.read", idempotencyKey)` 和相同请求摘要重试返回同一 `quoteId` 与新的 `decisionId`, 同键异摘要返回 `409 IDEMPOTENCY_CONFLICT`

#### Scenario: 错误叶子私钥签名被拒绝

- **WHEN** 请求使用与 `U` 登记 `appKeyId` 不匹配的错误 P-256 私钥签发 `KB-JWT`
- **THEN** 网关在验证持有者阶段返回 `401 SIGNATURE_INVALID` 且 `decisionId` 为 `null`, 原挑战未消费且无报价或业务键写入

### Requirement: 模拟订单创建与双实例唯一订单约束

C 网关 SHALL 扩展 `POST /v1/access/execute` 支持 `order.create`, 在锁后复核中核验 `quoteId` 归属, 有效期与真实总额, 检查整条委托链状态与 `path.maxAmountMinor` 上限, 并在共享业务主库上保证跨多个网关实例对同一 `(deployment_id, actor, task_id, idempotency_key)` 至多创建一笔不可变订单.

#### Scenario: RP 与 BM 模式下 800 元下单成功及 1200 元超额拒绝

- **WHEN** `B1` 持有效 `G0 -> G1 -> G2` (`G2` 单笔上限 `100000` 分) 分别在 RP 与 BM 模式下先取得有效报价 (`Q800` 为 `80000` 分, `Q1200` 为 `120000` 分), 再提交真实总额匹配的 `order.create` 请求
- **THEN** 800 元订单提交成功返回 `200 {decisionId, code:"ALLOW", order}` (`status="CREATED"`), 数据库可见消费挑战, `ALLOW` 决策与唯一订单行
- **AND** 1200 元真实订单触发 `403 AMOUNT_LIMIT_EXCEEDED` 且无新订单行; 篡改 `Q1200` 金额为 `80000` 分先触发 `409 AMOUNT_MISMATCH`; 引用其他主体或任务报价返回 `403 QUOTE_SCOPE_MISMATCH`; 报价到期当秒返回 `409 QUOTE_EXPIRED`

#### Scenario: 锁后风险升级为 ELEVATED/BLOCKED 或采用 G1 撤销块后拒绝建单

- **WHEN** 持有有效 `Q800` 的合法 `order.create` 在初验时满足条件, 但锁后可信环境变为 `ELEVATED`/`BLOCKED`, 或所采用的固定高度检查点已包含 `G1` 撤销块 `r`
- **THEN** 锁后风险为 `ELEVATED` 或 `BLOCKED` 时拒绝建单并返回 `403 POLICY_DENIED`; 采用 `G1` 撤销块后拒绝旧路径并返回 `403 ANCESTOR_INACTIVE`; 两种拒绝均不产生订单行

#### Scenario: 双网关实例同键并发仅产生一笔订单

- **WHEN** 两个共享同一业务主库的 C 网关实例同时收到不同有效挑战但相同 `(actor, taskId, "order.create", idempotencyKey)` 与相同摘要的合法订单请求, 或随后收到同键异摘要请求
- **THEN** 同摘要并发仅创建一笔不可变订单并均返回同一 `orderId` (各自关联自己的 `decisionId`); 同键异摘要返回 `409 IDEMPOTENCY_CONFLICT` 且不新增订单
