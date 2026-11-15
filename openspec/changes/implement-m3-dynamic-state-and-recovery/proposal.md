# 变更提案

## 为什么

Fabric D0 最小网络, D0 最小协议, M1 直接访问与 M2 两种根与两级委托已完成首个完整 MVP (`30/30` 联合验收), 但尚未补齐运行期动态生命周期管理, 静态验签复用缓存, 未知订单核账与异常恢复能力. 按照 [阶段任务](../../../TODO.md), [部署与链上登记](../../../docs/implementation/部署与链上登记.md), [证据交付与网关执行](../../../docs/implementation/证据交付与网关执行.md), [订单核账](../../../docs/implementation/订单核账.md), [REST接口与响应码](../../../docs/implementation/REST接口与响应码.md), [验证用例](../../../docs/experiments/验证用例.md) 和 [实验计划](../../../docs/experiments/实验计划.md), 项目进入 M3 阶段 ("动态状态与恢复"), 需要完成域资格续发/收缩/撤销与 T 离线本地验证, 普通身份状态管理/轮换与双证明管理账户恢复, 凭证撤销/任务取消/委托暂停与替换, 静态验签缓存 (`B1`), 两实例未知订单核账与历史高度复核, 以及 `B2` 改派和核账恢复的智能体工具轨迹与 E2/E3/E6/E7 预跑验收.

## 变更内容

- 链码与链上登记动态生命周期扩展 (`chaincode/registry`, `internal/fabricapi`, `internal/fabric`): 支持 T 域认证原子续发/替换, 同钥收缩声明范围 (`department` 隐藏/披露边界 `S93`), 机构换钥重认证 (`UpdateAuthorityIdentity`, `F15`, `S81`, `S82`), 域认证撤销 (`RevokeCertification`, `S78`) 及 T 离线本地核验 (`F14`, `S84`); 支持普通身份状态转换 (`SetIdentityStatus`: `ACTIVE <-> SUSPENDED -> REVOKED`, `S94`), 应用密钥轮换 (`RotateIdentity`, `S22`, `S47`, `S100`) 与基于 `grad-identity-recovery-v1` 双证明的管理账户恢复 (`RecoverIdentity`, 保留原 `status`, 递增 `keyVersion`, `S95-S97`); 支持凭证撤销 (`RevokeCredential`), 任务取消 (`CancelTask`), 委托暂停/恢复 (`SuspendGrant`/`ResumeGrant`) 及异步管理操作状态机 (`S100-S101`).
- 静态验签缓存 (`B1`) 与披露范围边界 (`internal/protocol`, `internal/gateway`): 引入按 `(原始材料摘要, 算法, appKeyId, appKeyVersion)` 索引的并发安全静态验签缓存, 每次命中缓存后仍在固定高度 `REPEATABLE READ` 快照上强制校验 `keyVersion`, 域认证指针与当前声明范围, 确保换钥 (`403 KEY_VERSION_STALE`, `S22`) 或声明范围收缩 (`403 ISSUER_SCOPE_INVALID`, `S93`) 绝不绕过动态状态.
- 两实例未知订单核账与历史高度复核 (`internal/gateway`, `internal/fabric`): 扩展 `client_actions` 支持 `OUTCOME_UNKNOWN` 与 `sendRevision` 递增停发, 新增 `order_outcome_cases` 与 `order_outcome_receipts` 表及核账接口 (`POST /v1/internal/order-outcome-cases`, `POST /v1/audit/order-outcomes`, `POST /v1/internal/order-outcome-receipts`), 强制 `C` 审计员权限隔离 (`403 AUDIT_FORBIDDEN`, `S67`), 锁挑战并集与业务键判定 `CREATED`/`NOT_CREATED`/`UNKNOWN`, 并基于创建决策 `d1` 的历史高度 `h`, 撤销高度 `r` 与原探针期限执行历史完整性复核 (`MATCHED`/`MISMATCH`/`INCOMPLETE`/`NO_DECISION`).
- `B2` 改派/核账智能体工具轨迹与 E2/E3/E6/E7 联合验收 (`internal/agent`, `internal/fabric`, `cmd/ledgerctl`): 在 MCP Server 新增 `replace_grant` 与 `reconcile_order` 工具, 跑通 `A1` 将 `G2` 原子改派给 `B2` (`B2` 复用 `B1` 报价触发 `403 QUOTE_SCOPE_MISMATCH` 后重新询价建单) 与 `B1` 订单响应丢失后核账恢复的 LLM 智能体闭环, 并完成 `S76-S103`, `E2`/`E3` 生命周期以及 `E6`/`E7` 预跑验收.

## 能力

### 新增能力

- 无 (均在既有能力规范上扩展).

### 修改能力

- `authorization-registry`: 增加 T 域认证原子续发/收缩/撤销与 T 离线可用性约束, 普通身份状态管理, 应用密钥轮换, `grad-identity-recovery-v1` 双证明管理账户恢复, 凭证/任务/委托动态状态操作, 以及受理前版本预检与受理后异步操作状态查询 (`S100`/`S101`).
- `verifiable-protocol`: 增加按 `(rawDigest, alg, appKeyId, appKeyVersion)` 索引的 `B1` 静态验签缓存及命中后的固定高度状态强制核验 (`403 KEY_VERSION_STALE`), 并增加 T 域认证同钥收缩属性范围后的 SD-JWT 隐藏/披露边界判定 (`S93`).
- `fixed-height-state`: 扩展历史复查能力以支持未知订单核账对创建决策高度 `h`, 撤销块 `r`, 历史域认证 `certificationId`/`digest` 与原探针期限的审计重构 (`MATCHED`/`MISMATCH`/`INCOMPLETE`/`NO_DECISION`).
- `direct-access-gateway`: 增加两实例未知订单核账 (`order_outcome_cases`, `order_outcome_receipts`), `sendRevision` 停发与 `C` 审计员权限隔离 (`403 AUDIT_FORBIDDEN`), 锁后历史复核与并发挑战等锁超时边界 (`S66`/`S67`).
- `agent-tool-runtime`: 在 MCP Server 新增 `replace_grant` 与 `reconcile_order` 两个确定性协议工具, 并扩展双协议 LLM 运行器支持 `A1 -> B2` 改派重新询价建单与 `B1` 响应丢失核账恢复轨迹 (`E3`).

## 影响

- 扩展 `chaincode/registry`, `internal/fabricapi`, `internal/fabric`, `internal/protocol`, `internal/gateway`, `internal/agent` 与 `cmd/ledgerctl`, 需对部署通道执行一次链码序列升级 (`sequence++`) 或干净重建后完成 M3 联合验收.
- `C0`/`B0`/`B1` 大规模重复消融实验, `E4`/`E5`/`E8` 性能测试与五个前端演示视图留在 M4 阶段实施.
