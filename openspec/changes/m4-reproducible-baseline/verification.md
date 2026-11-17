# m4-reproducible-baseline 核验报告

核验基于 `8237ef0` 的修复工作区. 使用本地 `spec-driven` 工作流, 读取提案, 设计, 任务和增量规范. 实机清单的 `source_commit` 记录当时的 HEAD, `artifact_locks` 记录修复后实际文件的 SHA-256 摘要.

## 汇总

| 维度 | 结论 |
| --- | --- |
| 完整性 | 12/12 项任务完成, 4/4 项新增需求均有实现 |
| 正确性 | 4/4 项需求完成实现映射, 5/5 个场景通过核对. 两次干净重建的全部配对用例通过 |
| 一致性 | 已核对设计与代码模式. Fabric 判定, 挑战失败导出和超额检查顺序符合修订后的制品 |

## 需求与场景核对

| 需求 | 实现与核验证据 |
| --- | --- |
| 三种对照配置共享业务准入语义 | `internal/fabric/baseline.go:255` 装配三个网关配置. `internal/gateway/execute.go:166` 执行共同初验. 两轮 C0/B0 缓存计数为零, B1 各命中 62 次. B1 更新状态后拒绝失效材料的回归通过. 新订单超额检查先于最终 OPA 求值 |
| C0 使用可在锁后复核的中心化一致快照 | `internal/centralstate/source.go:86` 一次只读一致事务装配依赖, 同文件第 121 行在业务事务内共享锁定版本行. `internal/gateway/central_test.go:214` 复现锁等待期间版本由 1 推进到 2, 最终决定记录版本 2 和一次重验. 一致快照, 缺依赖停止装配, C0 独立业务决定以及旧 Fabric 决策迁移回归通过 |
| 使用固定夹具和可查询的实验记录复跑 | `internal/experiment/fixture.go` 固定夹具, `internal/experiment/evidence.go:73` 导出四文件. 108 个依赖和源码指纹均匹配修复工作区. 挑战失败, 执行超时和主库查询失败回归通过. 修复前真实准备失败保留 24 条 `dropped` 记录并以退出码 1 结束 |
| 首轮三组配对核对两档订单的业务结果 | `internal/fabric/baseline_checks.go:64` 核对 HTTP 结果, 挑战消费, 创建决定和主库副作用. 两轮均有 12 次询价允许, 6 笔 800 元唯一订单和 6 次 1200 元超额拒绝. 拒绝侧新增订单与订单键均为 0 |

## 实测证据

用种子 `1109` 从两个独立空实例启动并创建各自的 C0 数据库. 逐行核对 48 条请求和 24 条主库订单记录, 其中 32 条 Fabric 动作具备有效块哈希和原探针时点, 16 条 C0 动作具备中心化版本且 Fabric 字段为空. 两轮的夹具摘要, 配对矩阵及业务事实一致, 部署, T 根, 材料及请求标识分别生成. 四文件扫描均通过. [独立比较结果](../../../infra/fabric/evidence/baseline/verification/fixes/comparison.json)

| 运行 | 原始证据 |
| --- | --- |
| 修复后第一轮 | [清单](../../../infra/fabric/evidence/baseline/verification/fixes/round1/manifest.json), [请求](../../../infra/fabric/evidence/baseline/verification/fixes/round1/requests.csv), [主库核对](../../../infra/fabric/evidence/baseline/verification/fixes/round1/order_checks.csv), [汇总](../../../infra/fabric/evidence/baseline/verification/fixes/round1/summary.json) |
| 修复后第二轮 | [清单](../../../infra/fabric/evidence/baseline/verification/fixes/round2/manifest.json), [请求](../../../infra/fabric/evidence/baseline/verification/fixes/round2/requests.csv), [主库核对](../../../infra/fabric/evidence/baseline/verification/fixes/round2/order_checks.csv), [汇总](../../../infra/fabric/evidence/baseline/verification/fixes/round2/summary.json) |
| 询价挑战失败 | [请求](../../../infra/fabric/evidence/baseline/verification/fixes/challenge-quote.read/requests.csv), [汇总](../../../infra/fabric/evidence/baseline/verification/fixes/challenge-quote.read/summary.json) |
| 下单挑战失败 | [请求](../../../infra/fabric/evidence/baseline/verification/fixes/challenge-order.create/requests.csv), [主库核对](../../../infra/fabric/evidence/baseline/verification/fixes/challenge-order.create/order_checks.csv), [汇总](../../../infra/fabric/evidence/baseline/verification/fixes/challenge-order.create/summary.json) |

连接独立 PostgreSQL 实例运行 `go test -json -count=1 -p 1 ./...`, 9 个测试包通过, 200 个含子测试通过事件. 两项需显式配置的 Fabric 初始化测试和一项 M3 实机测试跳过. M4 实机采购由上述两轮运行覆盖. [Go 原始事件](../../../infra/fabric/evidence/baseline/verification/fixes/test-events.jsonl), [OpenSpec 严格校验](../../../infra/fabric/evidence/baseline/verification/fixes/openspec-validation.json)

## 已关闭的警告

1. **Fabric 证据字段和原探针期限.** `internal/fabric/baseline_checks.go:224` 校验 SHA-256 块哈希, 探针交易 ID, 块高关系及墙钟和单调时点. 14 个子测试覆盖 B0 询价及 B1 下单的缺失字段, 无效哈希, 探针块越界和核验时间越界. 到达原期限的样例判为失败, 两轮实机的有效记录均通过.
2. **挑战失败响应与未执行项.** `internal/fabric/baseline.go:445` 把非 201 的已观测 HTTP 状态, 错误码和请求 ID 保存到请求和失败汇总. 询价挑战失败时, 下单动作标记为 `dropped` 和 `quote-dependency`. 下单挑战失败时保留已知报价与失败原因, 主库订单行和订单键计数为空. 两个回归均注入 `503 STATE_UNAVAILABLE`. [挑战回归日志](../../../infra/fabric/evidence/baseline/verification/fixes/challenge-tests.log)
3. **超额检查与 OPA 求值顺序.** 增量规范和设计已明确新订单在锁后校验报价与额度, 超额时先定案, 通过前置检查后执行最终 OPA 求值. 核对 `internal/gateway/execute.go:635` 和同文件第 684 行. 既有额度回归通过, 两轮各 6 次超额拒绝均保存拒绝决定且无订单副作用. [增量规范](specs/reproducible-procurement-experiments/spec.md)

修复前的故障和配对样本继续按原源码指纹保留. [故障日志](../../../infra/fabric/evidence/baseline/verification/boundary-tests.log), [测试补丁](../../../infra/fabric/evidence/baseline/verification/boundary-tests.patch), [配对比较](../../../infra/fabric/evidence/baseline/verification/comparison.json), [准备失败样本](../../../infra/fabric/evidence/baseline/verification/fault-preparation/summary.json)

## 归档评估

任务完成, 规范覆盖, 需求实现映射, 场景覆盖, 设计遵循和代码模式一致性六项检查均通过. 0 项 CRITICAL, 0 项 WARNING, 0 项 SUGGESTION, 可进入归档工作流.
