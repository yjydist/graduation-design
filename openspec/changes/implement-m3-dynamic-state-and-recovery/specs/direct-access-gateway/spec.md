# direct-access-gateway Specification

## ADDED Requirements

### Requirement: 两实例未知订单核账与审计权限隔离

B 恢复服务在发送 `order.create` 前 SHALL 持久化意图锁 (`OUTCOME_UNKNOWN`), 当响应丢失且原路径被撤销或超时无法确认时 SHALL 递增 `sendRevision` 停发延迟工作进程, 并经角色绑定通道向 `POST /v1/internal/order-outcome-cases` 登记 `{caseId, sendRevision, deploymentId, request, requestHash, challengeIds}` (同一 `caseId` 内容不可变). `POST /v1/audit/order-outcomes` SHALL 仅允许 `C` 审计员角色执行, 非审计员 (如 `B1` 或 `A` 域管理员) 调用 SHALL 返回 `403 AUDIT_FORBIDDEN` 且不得泄露订单是否存在.

#### Scenario: 订单响应丢失且 G1 撤销后经核账找回原订单并复核历史 h 小于 r

- **WHEN** `B1` 提交合法 `order.create` 后网关已成功提交但响应在返回前截断, 随后 `G1` 在块 `r` 被撤销, `B1` 重试触发 `403 ANCESTOR_INACTIVE` 并锁定意图停发后发起核账单与审计请求
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
