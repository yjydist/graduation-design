# 实施任务

本清单交付 M1 直接访问实现及绑定当前 Fabric 部署的验证证据. 机制见 [设计](design.md), 行为验收依据为 [直接访问网关](specs/direct-access-gateway/spec.md), [授权登记](specs/authorization-registry/spec.md) 和 [固定高度状态](specs/fixed-height-state/spec.md).

## 1. 注册双证明, 身份凭证与 C->U 根材料交付

- [x] 1.1 在 `internal/fabric` 与 PostgreSQL 初始化脚本中建立 `operations`, `certification_outbox`, `certification_receipts`, `grant_outbox` 和 `wallet_receipts` 表结构与键约束, 实现普通身份注册挑战 (`grad-identity-registration-v1`) 及 `ManagementDualProofBundle` 核验受理流程, 运行单元测试验证同 MSP 错误证书, 替换挑战和缺任一证明被拒绝且不消费挑战.
- [x] 1.2 核对 T 对 A/C 域认证及 IA/IC 签发资格, 完成 `PA` 身份登记及 `U`/`PA`/`C` 服务 (`supplier-service`) 的 SD-JWT 身份凭证签发, 并实现 `certification_outbox`/`certification_receipts` 的原文保存与受控同步, 运行单元测试验证 `MATERIAL_NOT_SYNCED` 与域认证锚点一致性检查.
- [x] 1.3 实现 `U` 创建采购任务及 `C` 签发并向 `U` 交付 RP 根授权 `G0` (附 IC 签发的 C 服务最小出示与 T 的 C 域认证), 仅在原交易 `VALID` 且当前资格及有效期通过复核时开放 `grant_outbox` 并写入 `wallet_receipts`, 运行单元测试验证 `(deploymentId, recipient, grantId)` 去重, 幂等确认与 `DELIVERY_CONFLICT`.

## 2. PostgreSQL 固定高度协议视图装配与 OPA 策略引擎

- [x] 2.1 扩展 `internal/fabric/view.go`, 实现在单个 PostgreSQL `REPEATABLE READ` 只读事务中从 `fabric_head` 和 `Grant` 出发装配 `protocol.SnapshotView` (`Root`, `Domain`, `Certification`, `Identity`, `Credential`, `Task`, `Grant`) 及原探针单调截止时间的 `StateProvider`, 运行集成测试验证缺依赖时返回 `STATE_UNAVAILABLE` 且不回退最新状态, 以及探针到期返回 `503 STATE_STALE`.
- [x] 2.2 在 `go.mod` 引入 OPA Go SDK (`github.com/open-policy-agent/opa`), 新建 `internal/policy` 包实现策略包 (`manifest.json`, `procurement.rego`, 输入 schema 与角色/资源配置) 的加载, 按文件名排序的 SHA-256 与 `JCS(manifest)` 摘要校验以及 `trustRoots` 固定 T 根核对, 运行单元测试验证篡改 `.rego` 或替换 T 根即被拒绝.
- [x] 2.3 在 `internal/policy` 中实现基于 Rego v1 (`package procurement`) 的确定性求值器, 启用 `StrictBuiltinErrors`, 禁止 `time.now_ns()` 与外部网络调用, 由服务端计算 `supplierAcceptance` 与严格类型输入, 运行单元测试验证 `quote.read` 在 `NORMAL`/`ELEVATED` 下允许, `BLOCKED` 下拒绝以及 `undefined`/异常 fail-closed 行为.

## 3. C 访问网关, 挑战消费与锁后复核幂等事务

- [x] 3.1 新建 `internal/gateway` 包及 PostgreSQL 业务主库模式 (`challenges`, `trusted_contexts`, `business_keys`, `quotes`, `decisions`, `catalog_prices`), 预置产品 P1 (`80000` 分 CNY) 目录价格, 并实现 `POST /v1/auth/challenges`, `POST /v1/contexts/{taskId}`, `GET /v1/decisions/{id}` 与 `GET /v1/health/ready` HTTP 端点及单测.
- [x] 3.2 实现 `POST /v1/access/execute` (`quote.read`) 的严格 schema 校验 (256 KiB 限制, `quoteId == null`, `amountMinor == 0`, `quantity > 0`) 与基于 `StateProvider` 的一致视图初验 (持有者签名, `nonce` 原值绑定, 信任路径, `G0` 与 `taskSpec`), 运行单测验证 `400 INVALID_SCHEMA`, `401 SIGNATURE_INVALID` 及错误密钥不消费挑战.
- [x] 3.3 实现 `READ COMMITTED` 业务锁事务 (`challenges` `FOR UPDATE` -> `business_keys` 占位 -> `trusted_contexts` `FOR SHARE` -> `fabric_head` `FOR SHARE` 比对初验块高/哈希), 锁后显式查询 `clock_timestamp()` 与单调钟执行到期当秒拒绝 (`now >= deadline`), 并重跑 OPA 最终求值, 运行并发与锁竞争测试验证初验 `NORMAL` 但锁后变为 `BLOCKED` 返回 `403 POLICY_DENIED` 且无报价行, 以及检查点推进重验与 `409 STATE_CHANGED`.
- [x] 3.4 完成 `quote.read` 原子提交 (消费挑战, 写 `ALLOW` 审计 `decisions`, 生成 `validUntil = min(decision_at + 300, task.validUntil)` 不可变 `quotes` 行与 `business_keys`) 及同键幂等重试逻辑, 运行测试验证同键同摘要新挑战重试返回原 `quoteId` 与新 `decisionId`, 同键异摘要返回 `409 IDEMPOTENCY_CONFLICT`.

## 4. Fabric M1 端到端集成验收与证据归档

- [x] 4.1 扩展 `cmd/ledgerctl` 与 `internal/fabric/verify.go`, 在保留 D0 20 项验收的基础上新增 M1 直接访问自动化验收用例: U 持 `C -> U` RP `G0` 询价成功 (查验已消费挑战, 决策与报价行), 同键幂等重试, 错误叶子私钥拒绝, 原探针到期 `STATE_STALE`, 锁后变为 `BLOCKED` 无报价副作用, 以及到期当秒拒绝.
- [x] 4.2 在真实 Fabric 实例上运行 `mise run test:unit` 与 `mise run ledger:verify`, 确认全部 D0 + M1 验收项通过并输出无私钥泄漏的结构化证据.
- [x] 4.3 更新 [任务安排与退出条件](../../../TODO.md) 中 M1 阶段状态与证据索引链接.

## 工作流后续

- 实施完成后运行 `/openspec-verify-change` 对照全部需求与场景核验代码, 测试与实机证据, 同步主规范后归档 `implement-m1-direct-access`.
