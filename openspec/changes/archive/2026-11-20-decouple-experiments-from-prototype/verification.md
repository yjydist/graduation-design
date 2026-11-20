# 原型与实验解耦核验

## 迁移前的基线

迁移起点为提交 `d22889501880859d7cda2ce4b7255475a40a1e59`, 原命令为 `ledgerctl experiment baseline`. 用种子 `1109` 的历史运行 `baseline-89ca8dd2d7ad0d57` 作参考. 清单记录当时的基底提交 `ca880c15dd7a5243ef33c2b4dc138ef0d1c0c760` 及实际源码指纹. 对照确认 `baseline.go`, `baseline_checks.go` 和 `baseline_test.go` 的指纹与迁移起点一致. [历史清单](../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-1/manifest.json), [历史对照](../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/comparison.json).

- C0/B0/B1 各含 RP 和 BM 的 800 元与 1200 元订单, 共 12 个订单和 12 次前置询价. 12 次询价允许. 800 元用例共新增 6 笔唯一订单, 每笔均有消费的挑战, 创建决定和完成的业务键. 1200 元用例均返回 `403 AMOUNT_LIMIT_EXCEEDED`, 共 6 次, 无新增订单或订单业务键. [请求](../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-1/requests.csv), [订单核对](../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-1/order_checks.csv).
- 逻辑夹具摘要为 `47e91ed3d170b501914cad44dd5309646bd5c5e458e53a2b9ec0beca1fcc20a5`. C0 与 Fabric 分别回读 39 项登记锚点, 共同摘要相同. 对照核对 C0 快照版本, Fabric 块高和原探针, 以及缓存命中 C0/B0/B1 分别为 0/0/62. [汇总](../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-1/summary.json).
- 迁移后继续核对准备失败和挑战失败留全计划, 报价执行返回 503 时保留实际请求 ID 和 `execute` 阶段, 依赖订单标记未执行. 公开的四份导出均需通过敏感材料检查. [准备失败](../../../infra/fabric/evidence/baseline/failure-preparation/summary.json), [挑战失败](../../../infra/fabric/evidence/baseline/verification/fixes/challenge-quote.read/summary.json), [执行失败](../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/fault-quote-execute/summary.json).

## 明确传入采购输入

`TestBootstrapAndSeedProtocolMaterialsOffline` 与 `TestProcurementSetupMaterialSigningAndDelivery` 通过. 真实 PostgreSQL 中验证了逐跳材料交付和钱包可装配. 迁移前入口接线轮 `baseline-66b6a9720f4931e0` 通过 12/12, 数量为 1, 与参考轮的逻辑摘要一致. RP 和 BM 的原登记交易分别为 `daa43cf5e5b440e95901efdc25b088ae1b235dd5f2c825351389ff32015d236f` 和 `19e9454f439a62541b51d4a225a69e6017801e109a127593cad329cc729ae58a`, 均为 `VALID`, 两种状态来源的锚点摘要相同.

## 迁移后的固定构建双轮对照

同一个实验二进制以种子 `1109` 在两个干净 Fabric 实例运行. 两轮的 `binary_sha256` 和 113 项源码及配置指纹一致. 逐行核对请求和主库 CSV, 两轮各通过 12/12, 12 次询价允许, 6 笔唯一订单, 6 次超额拒绝且无订单或业务键副作用. 逻辑输入和业务结果与迁移前参考轮一致, 部署 ID 各自独立. [对照汇总](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/comparison.json).

| 运行 ID | 原始输入与登记回读 | 原始结果 |
| --- | --- | --- |
| `baseline-5678d2531eb15a2b` | [清单](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/round-1/manifest.json) | [请求](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/round-1/requests.csv), [订单](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/round-1/order_checks.csv), [汇总](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/round-1/summary.json) |
| `baseline-9dfb2676b7c8fd18` | [清单](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/round-2/manifest.json) | [请求](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/round-2/requests.csv), [订单](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/round-2/order_checks.csv), [汇总](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/round-2/summary.json) |

两轮的 C0 与 Fabric 各有 39 项登记锚点, 每轮两个来源的锚点摘要相同. 每轮 24 项请求可关联挑战和决定, C0 均记录快照版本, B0/B1 均在原探针有效区间内定案. 缓存命中为 0/0/62, 公开证据扫描通过. 同次 PostgreSQL 回归验证了 C0 锁等待后的版本重验, 以及 Fabric 静态验签命中后仍拒绝已撤销祖先的路径.

新入口的准备失败样本使用非法 C0 数据库名, 按预期非零退出, 完整保留 24 项未执行计划. 基线测试同时通过挑战失败, 执行 503, 超时和登记回读不匹配的留证核对. [准备失败汇总](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/fault-preparation/summary.json).

`go list -deps -test ./cmd/... ./internal/... ./chaincode/...` 确认原型及其测试的传递依赖中没有实验包. `mise run ledger:build` 和 `mise run test:unit` 通过. 旧子命令返回未知命令, 新入口的参数帮助和实际失败留证通过.

## 联合回归场景迁移

以迁移前 `internal/fabric/verify.go` 的 34 项联合验收和 `TestM3LiveAcceptance` 的六个定点入口为清单. 下列测试文件均位于 `internal/fabric/`, 按场景名称定位.

| 原联合场景 | 计划去向 |
| --- | --- |
| 通道准入与排序治理, 部署绑定, 初始化恢复, 角色与凭证版本, 凭证期限, RP 任务与路径, 撤销与替换 | `integration_registry_test.go` |
| 提案期限与延迟提交, 持久化管理操作与 MVCC, 丢响应后原交易重放 | `integration_transactions_test.go` |
| 区块应用原子性, 固定高度与探针, 并行视图检查点, 查询故障, 排序与 Peer 故障, 链码故障, 重启恢复 | `integration_view_test.go` |
| 编码向量, DID 与上下文, 出示验签与篡改拒绝 | `integration_protocol_test.go` |
| 注册与交付, 询价幂等, 错叶钥拒绝, 探针过期, 锁后风险拒绝, 到期当秒拒绝 | `integration_access_test.go` |
| 双根与身份关联, MCP 采购, 撤销与锁后校验, 双网关并发幂等 | `integration_procurement_test.go` |
| 域和身份生命周期, 改派与核账, 管理与业务并发故障 | `integration_lifecycle_test.go` |
| 撤销窗口预跑 | 采样与统计按 [历史预跑](../../../experiments/README.md#历史预跑) 重现. 采用撤销块后的拒绝和探针过期拒绝分别由 `integration_procurement_test.go` 和 `integration_access_test.go` 核对 |

原定点入口的 `authority`, `offline`, `agent`, `e6`, `faults` 和 `management` 分别由域及身份生命周期, 离线信任与缓存, 改派与核账, 撤销拒绝, 管理及并发故障, 管理原交易恢复场景覆盖. E6 的采样时间线与 E7 的专题结果仍可从原预跑证据查阅. [预跑证据索引](../../../infra/fabric/evidence/README.md).

旧命令迁入测试后, 首轮三项跨进程用例误启动了测试二进制. 调整测试入口为单独构建和调用真实 `ledgerctl`, 在新实例复跑原联合清单 34/34. 同一入口按部署绑定选择器只执行一个场景并通过. [失败轮](../../../infra/fabric/evidence/integration/decouple-experiments/run-e976b726a5166e79/summary.json), [修复后完整轮](../../../infra/fabric/evidence/integration/decouple-experiments/run-5c337410a9970039/summary.json), [定点轮](../../../infra/fabric/evidence/integration/decouple-experiments/run-0f100a92d03b5b9e/summary.json).

移出旧采样后, 定点复跑验证采用撤销块后返回 `403 ANCESTOR_INACTIVE`, 无新增订单, 以及原探针过期后就绪检查和执行均返回 `503 STATE_STALE`. 故障注入的事务和锁后断言继续执行, 其诊断写入事件流. [撤销定点](../../../infra/fabric/evidence/integration/decouple-experiments/run-b90bf43d0bc7fcdd/summary.json), [过期定点](../../../infra/fabric/evidence/integration/decouple-experiments/run-a090a540e5473597/summary.json).

## 能力命名与兼容

实现和测试文件, 类型, 函数及回归选择器按能力命名. 阶段字面量仅留在已有协议或实例兼容面. `D0:` 由 `RegistryErrorPrefix` 集中维护, `m2TaskSpec` 是已有夹具的 JSON 键, `/m2/` 保持部署内登记标识的派生规则, `.local/fabric-d0` 继续定位默认实例. 历史证据和归档继续使用各自的原名称.

新构建的 `ledgerctl` 连接重命名前已部署的链码, 将原响应 `D0:UNAUTHORIZED` 映射为 `UNAUTHORIZED`. 同一实例使用带 `m2TaskSpec` 的存量夹具成功启动 MCP 并列出全部六个工具, 夹具和部署清单字节保持一致. 历史证据和归档的已跟踪文件无改动, 证据索引新增了本次记录. [兼容核对](../../../infra/fabric/evidence/integration/decouple-experiments/legacy-compatibility.json).

## 最终回归

- 原型的构建和测试依赖图只从 `cmd/`, `internal/` 和 `chaincode/` 展开, 校验结果中无实验包. 项目构建, 离线测试, 使用隔离 PostgreSQL 的串行测试及基线测试通过. E1 驱动通过编译.
- 最终代码通过 `mise run ledger:verify` 的 33/33 项集成回归. 相较迁移中间轮的 34 项, 窗口采样已移出, 撤销与过期拒绝各自的业务回归通过. 本轮使用确定性工具和本地协议模拟执行相关验证. [集成回归汇总](../../../infra/fabric/evidence/integration/decouple-experiments/final/run-bcaa7b32cd3dcec6/summary.json), [原始事件](../../../infra/fabric/evidence/integration/decouple-experiments/final/run-bcaa7b32cd3dcec6/events.jsonl).
- `mise run experiment:baseline` 在最终代码上的独立运行 `baseline-ba8cb1aa67eacdcc` 通过 12/12, 登记回读一致, 夹具摘要与双轮参考相同. 正式实验工作流的提案和设计均已引用新入口. [最终基线汇总](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/final/summary.json), [运行清单](../../../infra/fabric/evidence/baseline/verification/decouple-experiments/final/manifest.json).

## 独立复核

复核提交 `208ac63f02dbab41450e452717f02219630b0453`. 12/12 项任务已标记完成, OpenSpec 严格校验通过. 变更显式配置 `skip_specs: true`, 增量规范覆盖, 需求实现映射和规范场景覆盖不适用.

- 原型构建, 未使用测试结果缓存的项目测试和实验测试通过. 原型及其测试的传递依赖中有 0 个实验包. 原型 CLI 对两个旧命令均返回未知命令, 已有归档和原始证据字节未变.
- 用新建的独立 Fabric 实例复跑完整回归 `run-60dfc20846c7183f`, 通过 33/33. 用另一实例定点复跑 `management-http-recovery`, `run-c95a671081c99daf` 通过 1/1. 极短期限的运行 `run-2df0440405834da5` 非零退出, 并记录预检超时.
- 从 CSV 重算历史参考轮, 固定构建双轮和最终轮, 核对计划, 订单副作用和两种来源的登记回读. 新实例基线 `baseline-167a530670fc5f8f` 同样通过 12/12. 每轮均有 6 笔唯一新订单, 6 笔超额拒绝且无订单或订单业务键副作用, 两个来源各回读 39 项登记锚点. 新轮清单的 112 项源码和配置指纹与已保存的最终轮一致. 准备失败复跑 `baseline-104e6f934c995eea` 非零退出, 保留 24 条未执行计划. 本次复跑原始记录保存在本机 `.local/verify-decouple-XmOF1z/`.

### 警告

- 项目回归仍会根据继承的环境配置调用真实模型并生成轨迹. 本次完整回归继承了 mise 的 Anthropic 配置, 采购闭环, 改派和核账各执行了一条真实模型轨迹. 建议将真实模型轨迹移至显式实验入口, 项目回归保留确定性工具和本地协议模拟. 入口见 `internal/fabric/integration_procurement_test.go:577` 和 `internal/fabric/integration_lifecycle_test.go:1483`.
- `ledger:verify --timeout` 在构建子进程用的 `ledgerctl` 之后才开始计时, 同时 Go 测试的总计时已禁用. 本次 `--timeout 1ns` 仍先经过约 0.95 秒的测试入口准备才进入超时留证. 建议将传入的期限覆盖子进程构建, 并为构建失败保留预检诊断. 见 `internal/fabric/integration_test.go:41` 和 `mise.toml:58`.

### 建议

- `ledger:seed` 的任务帮助仍包含阶段名 `D0`. 可按能力描述为"提交 Fabric 登记夹具". 见 `mise.toml:45`.

无关键问题, 有 2 项警告和 1 项建议. 可以归档.
