# m4-reproducible-baseline 核验报告

使用本地 `spec-driven` 工作流, 对照提案, 设计, 任务和增量规范核验基于 `ca880c1` 的执行接口故障留证修复. 两轮实机清单的源码指纹均对应修复后的工作区.

## 汇总

| 维度 | 结论 |
| --- | --- |
| 完整性 | 13/13 项任务完成, 4/4 项新增需求均有实现 |
| 正确性 | 4/4 项需求完成实现映射, 6/6 个场景通过核验 |
| 一致性 | 三组状态来源, 锁后复核, 业务路径及故障留证符合设计. 代码复用既有网关和钱包路径 |

## 需求与场景核对

| 需求 | 实现与核验证据 |
| --- | --- |
| 三种对照配置共享业务准入语义 | `internal/fabric/baseline.go:286` 装配三个网关配置. `internal/gateway/execute.go:166` 执行共同初验. 两轮 C0/B0 缓存计数为零, B1 各命中 62 次. B1 更新状态后拒绝失效材料的回归通过. 新订单超额检查先于最终 OPA 求值 |
| C0 使用可在锁后复核的中心化一致快照 | `internal/centralstate/source.go:102` 在一次只读一致事务读取登记快照, 业务事务内以共享锁复核版本. `internal/gateway/central_test.go:227` 复现锁等待期间版本由 1 推进到 2, 最终决定记录版本 2 和一次重验. 一致快照, 缺依赖停止装配, C0 独立业务决定以及旧 Fabric 决策迁移回归通过 |
| 使用固定夹具和可查询的实验记录复跑 | `internal/experiment/fixture.go` 固定夹具, `internal/experiment/evidence.go:73` 导出四文件. `internal/fabric/baseline_registry.go:87` 比对已提交的登记锚点. 登记缺失或不匹配, 挑战失败, 执行接口 503, 执行超时和主库查询失败的回归通过. 早期真实准备失败保留 24 条 `dropped` 记录并以退出码 1 结束 |
| 首轮三组配对核对两档订单的业务结果 | `internal/fabric/baseline_checks.go:66` 核对 HTTP 结果, 挑战消费, 创建决定和主库副作用. 两轮均有 12 次询价允许, 6 笔 800 元唯一订单和 6 次 1200 元超额拒绝. 拒绝侧新增订单与订单键均为 0 |

## C0 探针证据修复后复核

`internal/gateway/execute.go:867` 复用 `checkedProbe` 写入 `decision_evidence.checked_mono_ns`. `internal/gateway/central_test.go:211` 对 RP/BM 的允许询价和允许下单查库, 断言附表存在且该字段为 `NULL`. 新断言在修复前复现值为 0, 修复后通过. [修复前回归](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/regression-before.log), [修复后回归](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/regression-after.log)

使用种子 `1109` 从两个独立空实例重建. 直接查库确认每轮 C0 六条允许决定的附表字段全部为 `NULL`, B0/B1 共 12 条允许决定的附表时点均等于主表记录, 且落在原探针的有效区间. 每轮 24 条挑战与决定正确关联, 39 条登记锚点的回读摘要匹配, 12 次询价允许, 6 笔 800 元订单创建, 6 次 1200 元超额拒绝均无订单或订单业务键. B1 每轮命中 62 次. [修复后双轮对照](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/comparison.json)

| 运行 | 原始证据 |
| --- | --- |
| 第一轮 | [清单](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/round-1/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/round-1/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/round-1/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/round-1/summary.json) |
| 第二轮 | [清单](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/round-2/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/round-2/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/round-2/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/round-2/summary.json) |

独立 PostgreSQL 串行回归通过 9 个包, 共 206 个测试及子测试通过事件, 两项 Fabric 初始化专项和一项 M3 实机测试未配置. OpenSpec 严格校验通过. [回归汇总](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/test-summary.json), [OpenSpec 严格校验](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/openspec-validation.json)

## 提交 `6e10507` 的双轮复核

用种子 `1109` 从两个独立空实例重建. 两轮分别从 C0 主库和 Fabric 块高 41 的历史视图独立复算 T 根和 39 条共同登记记录的摘要, 均匹配清单. 逐行核对两轮共 48 条请求的挑战及决定关联, 以及 24 条订单用例的主库结果. 每轮有 12 次询价允许, 6 笔 800 元唯一订单和 6 次 `403 AMOUNT_LIMIT_EXCEEDED`. 六次拒绝均无订单或订单业务键. 每轮 B1 命中 62 次, C0/B0 均为 0. 逻辑夹具摘要, 用例矩阵及规范化业务事实跨轮一致. [独立比对](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/comparison.json)

| 运行 | 原始证据 |
| --- | --- |
| 第一轮 | [清单](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/round-1/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/round-1/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/round-1/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/round-1/summary.json) |
| 第二轮 | [清单](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/round-2/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/round-2/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/round-2/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/round-2/summary.json) |
| 准备失败 | [清单](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/fault-preparation/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/fault-preparation/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/fault-preparation/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/fault-preparation/summary.json), [退出码](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/fault-preparation.exit) |

缺失实例的 CLI 样本以退出码 1 结束, 四文件保留全部 24 个动作, 均标记为 `dropped` 和 `preparation`. 独立 PostgreSQL 串行回归通过 9 个包, 共 206 个测试及子测试通过事件, 两项 Fabric 初始化专项和一项 M3 实机测试未配置. OpenSpec 严格校验通过. [回归汇总](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/test-summary.json)

## 早期实测证据

用种子 `1109` 从两个独立空实例启动并创建各自的 C0 数据库. 逐行核对 48 条请求和 24 条主库订单记录, 其中 32 条 Fabric 动作具备有效块哈希和原探针时点, 16 条 C0 动作具备中心化版本且 Fabric 字段为空. 两轮的夹具摘要, 配对矩阵及业务事实一致, 部署, T 根, 材料及请求标识分别生成. 四文件扫描均通过. [独立比较结果](../../../../infra/fabric/evidence/baseline/verification/fixes/comparison.json)

| 运行 | 原始证据 |
| --- | --- |
| 修复后第一轮 | [清单](../../../../infra/fabric/evidence/baseline/verification/fixes/round1/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/fixes/round1/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/fixes/round1/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/fixes/round1/summary.json) |
| 修复后第二轮 | [清单](../../../../infra/fabric/evidence/baseline/verification/fixes/round2/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/fixes/round2/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/fixes/round2/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/fixes/round2/summary.json) |
| 询价挑战失败 | [请求](../../../../infra/fabric/evidence/baseline/verification/fixes/challenge-quote.read/requests.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/fixes/challenge-quote.read/summary.json) |
| 下单挑战失败 | [请求](../../../../infra/fabric/evidence/baseline/verification/fixes/challenge-order.create/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/fixes/challenge-order.create/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/fixes/challenge-order.create/summary.json) |

连接独立 PostgreSQL 实例运行 `go test -json -count=1 -p 1 ./...`, 9 个测试包通过, 200 个含子测试通过事件. 两项需显式配置的 Fabric 初始化测试和一项 M3 实机测试跳过. M4 实机采购由上述两轮运行覆盖. [Go 原始事件](../../../../infra/fabric/evidence/baseline/verification/fixes/test-events.jsonl), [OpenSpec 严格校验](../../../../infra/fabric/evidence/baseline/verification/fixes/openspec-validation.json)

登记摘要修复前另用临时测试将已有 Fabric 决定的表恢复为 M4 前结构, 连续迁移两次. 原块高和探针保持一致, M3 的历史复查回归通过.

## 已关闭的警告

1. **Fabric 证据字段和原探针期限.** `internal/fabric/baseline_checks.go:224` 校验 SHA-256 块哈希, 探针交易 ID, 块高关系及墙钟和单调时点. 14 个子测试覆盖 B0 询价及 B1 下单的缺失字段, 无效哈希, 探针块越界和核验时间越界. 到达原期限的样例判为失败, 两轮实机的有效记录均通过.
2. **挑战失败响应与未执行项.** `internal/fabric/baseline.go:476` 把非 201 的已观测 HTTP 状态, 错误码和请求 ID 保存到请求和失败汇总. 询价挑战失败时, 下单动作标记为 `dropped` 和 `quote-dependency`. 下单挑战失败时保留已知报价与失败原因, 主库订单行和订单键计数为空. 两个回归均注入 `503 STATE_UNAVAILABLE`. [挑战回归日志](../../../../infra/fabric/evidence/baseline/verification/fixes/challenge-tests.log)
3. **超额检查与 OPA 求值顺序.** 增量规范和设计已明确新订单在锁后校验报价与额度, 超额时先定案, 通过前置检查后执行最终 OPA 求值. 核对 `internal/gateway/execute.go:635` 和同文件第 684 行. 既有额度回归通过, 两轮各 6 次超额拒绝均保存拒绝决定且无订单副作用. [增量规范](specs/reproducible-procurement-experiments/spec.md)

4. **清单的登记摘要取值来源.** 修复前两项摘要取自同一份预置输入, 同轮 A 域对象在 C0 和 Fabric 的版本分别为 1 和 3. 修复后清单以 `registry_input_digest` 标注预置输入, 两种来源分别计算锚点摘要并记录检查点和对象版本. `TestBaselineRegistryReadbackUsesStoredAnchors` 验证不同对象版本可通过, 更新已登记委托摘要以及删除委托记录均使回读失败, 比对结果或部分回读证据仍可追溯. [修复前数据库回读](../../../../infra/fabric/evidence/baseline/verification/registry-readback/readback.json)
5. **默认实例的符号链接绕过.** 修复前经符号链接指定默认实例时, 入口写入 `baseline-run` 后才因已有夹具退出. `internal/fabric/baseline.go:240` 现在先解析目标路径, 用 `os.SameFile` 比较已打开目录和默认目录, 再通过同一个已打开目录独占创建标记. `TestBaselineRejectsDefaultInstanceAliases` 覆盖直接指定默认路径, 目标路径为符号链接, 默认路径为符号链接三种情况. 两种符号链接回归均在修复前复现写入, 修复后确认写入前拒绝. `TestBaselineClaimsIsolatedInstanceThroughAlias` 验证独立实例可通过链接占用, 重复占用保留首次标记.
6. **C0 决策证据附表的探针核验时点.** 修复前两轮各有 6 条 C0 允许决定在附表写入 0. 复用 `checkedProbe` 后, 两轮各 6 条 C0 允许决定的附表字段均为 `NULL`, 已由直接查库和回归断言确认. [修复前主库复核](../../../../infra/fabric/evidence/baseline/verification/commit-6e10507/comparison.json), [修复后双轮对照](../../../../infra/fabric/evidence/baseline/verification/c0-evidence-null-fix/comparison.json)

早期故障和配对样本继续按原源码指纹保留. [故障日志](../../../../infra/fabric/evidence/baseline/verification/boundary-tests.log), [测试补丁](../../../../infra/fabric/evidence/baseline/verification/boundary-tests.patch), [配对比较](../../../../infra/fabric/evidence/baseline/verification/comparison.json), [准备失败样本](../../../../infra/fabric/evidence/baseline/verification/fault-preparation/summary.json)

## 登记回读修复后复跑

用种子 `1109` 从两个独立空实例重建. 每轮从 C0 已提交快照和 Fabric 清单所记块高的历史视图独立重算 39 条登记记录及 T 根的摘要, 均匹配清单. 两轮的 C0 登记版本均为 1, Fabric 回读块高均为 41, 块哈希各自独立. A 域对象的 C0 和 Fabric 版本分别为 1 和 3. 每轮有 12 次询价允许, 6 笔 800 元订单创建, 6 次 1200 元超额拒绝, 拒绝侧新增订单和订单业务键均为 0. B1 每轮有 62 次缓存命中. [独立复算与两轮对照](../../../../infra/fabric/evidence/baseline/verification/registry-readback-fixed/comparison.json)

| 运行 | 原始证据 |
| --- | --- |
| round2 | [清单](../../../../infra/fabric/evidence/baseline/verification/registry-readback-fixed/round2/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/registry-readback-fixed/round2/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/registry-readback-fixed/round2/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/registry-readback-fixed/round2/summary.json) |
| round3 | [清单](../../../../infra/fabric/evidence/baseline/verification/registry-readback-fixed/round3/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/registry-readback-fixed/round3/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/registry-readback-fixed/round3/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/registry-readback-fixed/round3/summary.json) |

独立 PostgreSQL 上运行 `go test -json -count=1 -p 1 ./...`, 9 个包通过, 共 201 个测试及子测试通过事件. 两项 Fabric 初始化专项和一项 M3 实机测试跳过. OpenSpec 严格校验通过.

## 提交 `29e93be` 的独立复核

使用种子 `1109` 和两个新 Fabric 实例复跑. 每轮从 C0 主库和 Fabric 指定块高的历史记录独立重算 39 条共同登记记录及 T 根的摘要, 均匹配清单. C0 回读版本为 1, Fabric 回读块高为 41. 从主库核对每轮 24 条挑战与决定的关联, 确认 12 次询价允许, 6 笔 800 元订单和 6 次 1200 元 `403 AMOUNT_LIMIT_EXCEEDED`. 超额请求均未生成订单或订单业务键. 每轮 B1 静态验签命中 62 次, C0/B0 均为 0. 两轮的逻辑夹具摘要, 用例矩阵和业务结果一致. 四文件扫描通过.

独立 PostgreSQL 串行回归再次通过 9 个包, 共 201 个测试及子测试通过事件. 两项 Fabric 初始化专项和一项 M3 实机测试跳过. OpenSpec 严格校验通过.

## 实例隔离修复复核

在临时工作目录用实际 CLI 构造两种符号链接场景. 两次均以退出码 1 拒绝, 默认实例均无 `baseline-run` 标记. 四份结果文件保留 24 项准备阶段未执行的计划.

通过符号链接指定新建的独立 Fabric 实例, 用种子 `1109` 跑完一轮. 清单记录解析后的实例目录, 109 项源码与配置指纹匹配修复工作区, 两种来源的登记回读摘要一致. 24 个动作全部完成, 12 次询价允许, 6 笔 800 元订单创建, 6 次 1200 元超额拒绝均无新增订单或订单业务键. B1 静态验签命中 62 次, 四文件扫描通过.

独立 PostgreSQL 串行回归通过 9 个包, 共 206 个测试及子测试通过事件. 两项 Fabric 初始化专项和一项 M3 实机测试跳过. OpenSpec 严格校验通过.

## 提交 `ca880c1` 的独立复核

用种子 `1109` 重建两个隔离实例, 两轮清单的 109 项源码和配置指纹均与当前提交一致. 每轮从 C0 主库和 Fabric 指定块高的历史视图独立重算 T 根和 39 条登记锚点的摘要, 直接查库确认 24 条请求的挑战及决定关联. 两轮的夹具, 计划和业务结果一致, 每轮通过 12 次询价, 6 笔 800 元唯一订单及 6 次 1200 元超额拒绝. B1 每轮命中 62 次, C0/B0 均为 0. 独立 PostgreSQL 串行回归通过 9 个包, 共 206 个测试及子测试通过事件. OpenSpec 严格校验通过. [当前提交双轮对照](../../../../infra/fabric/evidence/baseline/verification/commit-ca880c1/comparison.json)

### 修复前发现的警告

- **执行接口故障被记为决定核对故障.** 定点测试使询价挑战返回 201, 随后的执行请求返回 `503 STATE_UNAVAILABLE`, 且没有决策 ID. 请求与汇总保留 HTTP 状态, 错误码及请求 ID, 依赖该询价的下单标记为 `dropped`. `internal/fabric/baseline.go:539` 清空执行阶段, `internal/fabric/baseline.go:581` 将该故障写成 `quote-check`. 建议在观测到执行阶段的 HTTP 错误时保存 `execute` 及错误码, 再按已观测的决策 ID 核对主库. 增加挑战成功后执行返回 503 的回归, 同时保留预期超额拒绝的通过判定. [故障注入日志](../../../../infra/fabric/evidence/baseline/verification/commit-ca880c1/execute-fault.log)

## 执行接口故障留证修复后复核

`TestBaselineQuoteExecuteFailureRetainsResponse` 注入询价挑战 201 及随后的 `503 STATE_UNAVAILABLE`. 新回归在修复前复现 `quote-check`, 修复后在请求及失败汇总中均读到 `execute`, 状态码, 错误码, 请求 ID 和挑战 ID. 决定 ID 为 `null`, 依赖订单标记为 `dropped` 和 `quote-dependency`, 运行汇总为失败. 订单执行无决定 ID 的数据库专项同时验证已读取的订单和业务键计数仍会保留. [修复前回归](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/regression-before.log), [修复后回归](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/regression-after.log)

用修复后的工作区构建 `ledgerctl`, 以种子 `1109` 从两个独立环境复跑. 两轮的 109 项清单指纹均与工作区对应, 独立重算各 39 条登记锚点, 查库核对各 24 条挑战及决定, 逐例比较两轮业务结果. 每轮 12 次询价允许, 6 笔 800 元唯一订单, 6 次 1200 元 `403 AMOUNT_LIMIT_EXCEEDED` 拒绝且无新增订单或订单键, B1 静态验签命中 62 次. [双轮对照](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/comparison.json)

| 尝试 | 原始证据 |
| --- | --- |
| 第一轮 | [清单](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-1/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-1/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-1/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-1/summary.json) |
| 第二轮 | [清单](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-2/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-2/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-2/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/round-2/summary.json) |
| 询价执行 503 | [清单](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/fault-quote-execute/manifest.json), [请求](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/fault-quote-execute/requests.csv), [主库核对](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/fault-quote-execute/order_checks.csv), [汇总](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/fault-quote-execute/summary.json) |

独立 PostgreSQL 上运行 `go test -json -count=1 -p 1 ./...`, 9 个测试包通过, 共 208 个测试及子测试通过事件. 两项 Fabric 初始化专项及一项 M3 实机测试未配置. OpenSpec 严格校验通过. [回归汇总](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/test-summary.json), [OpenSpec 严格校验](../../../../infra/fabric/evidence/baseline/verification/execute-failure-fix/openspec-validation.json)

## 归档评估

0 项 CRITICAL, 0 项 WARNING, 0 项 SUGGESTION. 可归档.
