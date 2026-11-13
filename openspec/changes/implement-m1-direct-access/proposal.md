# 变更提案

## 为什么

Fabric D0 最小网络与 D0 最小协议已完成单通道 Fabric 部署, 固定高度状态视图与真实 ES256/SD-JWT/Grant/KB-JWT 静态及单次夹具验证, 但尚未建立端到端在线访问网关与业务主库事务闭环. 按照 [阶段任务](../../../TODO.md), [部署与链上登记](../../../docs/implementation/部署与链上登记.md), [证据交付与网关执行](../../../docs/implementation/证据交付与网关执行.md), [策略输入与数据约束](../../../docs/implementation/策略输入与数据约束.md) 和 [REST接口与响应码](../../../docs/implementation/REST接口与响应码.md), M1 直接访问阶段需要补齐 T 对 A/C 域认证及 IA/IC 资格核对, 普通身份注册挑战与双证明入链, U/PA/C 服务 VC 与任务及 `C -> U` 的 RP 根 (`G0`) 交付, PostgreSQL 固定高度视图逐次在线装配, OPA 策略包校验与求值, 以及 C 网关挑战消费, 锁后复核与幂等询价事务.

## 变更内容

- 实现 M1 登记与材料交付最小闭环: 接入普通身份注册挑战与双证明 (`ManagementDualProofBundle`) 校验登记, 核对 T 对 A/C 域认证与 IA/IC 签发资格, 签发并交付 `U`, `PA` 与 `C` 服务 (`supplier-service`) 的 SD-JWT 身份凭证, `U` 创建采购任务, 以及 `C` 签发并向 `U` 交付 RP 根授权 `G0` (附 IC 签发的 C 服务最小出示与 T 的 C 域认证, 持久化 `operations`, `certification_outbox`/`certification_receipts`, `grant_outbox`/`wallet_receipts`).
- 打通 PostgreSQL 固定高度一致视图在线逐次装配 (`StateProvider`): 扩展 `internal/fabric`, 在 `REPEATABLE READ` 只读事务中按叶授权 (`G0`) 一次性装配 T 根, 域状态与当前域认证锚, IA/IC/U/PA/C 身份与凭证锚, 任务及 `G0` 为 `protocol.SnapshotView`, 结合已同步域认证正文与 C 服务材料完成固定高度核验, 并强制核对本进程原探针单调时钟期限 (`nowMono < probe.deadline`).
- 实现 OPA 策略包校验与确定性求值 (`internal/policy`): 校验策略包 `manifest` JCS 摘要与 `trustRoots` 固定 T 根约束, 计算 `supplierAcceptance`, 集成 Rego v1 (`package procurement`) 执行严格求值 (禁用 `time.now_ns()` 与外部网络, 严格处理 built-in 错误与 `undefined` fail-closed).
- 实现 C 访问网关与锁后复核幂等事务 (`internal/gateway`): 在 PostgreSQL 建立 `challenges`, `trusted_contexts`, `business_keys`, `quotes`, `decisions` 与价格目录表, 实现 `POST /v1/auth/challenges`, `POST /v1/access/execute` (`quote.read`), `POST /v1/contexts/{taskId}`, `GET /v1/decisions/{id}` 与 `GET /v1/health/ready`; 在 `READ COMMITTED` 事务中按序加锁挑战行, 业务键占位, 环境共享行锁与 `fabric_head` 检查点共享锁, 用 `clock_timestamp()` 和单调钟执行锁后期限复核 (到期当秒拒绝) 与 OPA 重求值, 原子提交挑战消费, 审计决策与报价, 并纳入 `ledgerctl verify` 验收.

## 能力

### 新增能力

- `direct-access-gateway`: 定义 C 网关的挑战签发与消费, OPA 策略包核验与求值, 可信风险上下文管理, 锁后固定高度与环境复核, 当秒到期拒绝及 `quote.read` 询价幂等事务.

### 修改能力

- `authorization-registry`: 增加普通身份注册挑战与双证明 (`ManagementDualProofBundle`) 核验受理, U/PA/C 服务凭证锚登记, 以及域认证与 `C -> U` 根授权 (`G0`) 的发件/收件箱交付确认约束.
- `fixed-height-state`: 增加从 PostgreSQL `REPEATABLE READ` 一致视图直接装配 `protocol.SnapshotView` 完整协议依赖, 并在业务定案锁后共享锁定 `fabric_head` 检查点比对 `h/hash` 的在线复核要求.

## 影响

- 新增 `internal/policy` 与 `internal/gateway` 包, 扩展 `internal/fabric` 和 `internal/protocol`, 并在 `go.mod` 引入 OPA Go 库 (`github.com/open-policy-agent/opa`).
- 扩展 `ledgerctl verify` 在 D0 20 项验收之上增加 M1 直接访问验收套件; B 域 (`IB`/`B1`), 双域关联审批, `PA -> U` 的 BM 根, `G1`/`G2` 子委托与 `order.create` 下单及 LLM 智能体工具闭环留在 M2 实施.
