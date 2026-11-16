# 实施检验记录

## 范围与结果

本变更已接通固定夹具, C0/B0/B1 状态与缓存配置, 确定性钱包驱动及四文件证据导出. 实施范围遵循[设计](design.md)和[任务](tasks.md), 正式性能采样, 真实 LLM 重复实验, 消融, 演示与论文继续由 M4 后续工作完成. 本记录是 apply 阶段的实际检验记录, 归档前仍可执行独立 OpenSpec verify.

最终两轮使用相同实现与种子 `1109`, 从不同 Fabric 空实例及不同 C0 数据库重建. [比较结果](../../../infra/fabric/evidence/baseline/validation/comparison.json)确认逻辑夹具摘要为 `47e91ed3d170b501914cad44dd5309646bd5c5e458e53a2b9ec0beca1fcc20a5`, 用例矩阵, 策略源码, 108 个依赖及源码文件指纹和规范化业务事实一致. 实际部署, 根密钥及材料摘要不同并各自记录, 没有用种子派生密钥, 披露盐或挑战.

| 判据 | round5 | round6 |
| --- | --- | --- |
| 询价允许 | 12 | 12 |
| 800 元唯一订单 | 6 | 6 |
| 1200 元按原报价提交并超额拒绝 | 6 | 6 |
| 拒绝侧新增订单或订单键 | 0 | 0 |
| 动作数, 独立挑战及决定 | 各 24 | 各 24 |
| B1 静态验签命中 | 62 | 62 |
| 缺测或超时 | 0 | 0 |

原始清单, 请求及主库核对由[证据索引](../../../infra/fabric/evidence/README.md#m4-采购基线)定位. [逐例追溯](../../../infra/fabric/evidence/baseline/validation/trace-samples.json)覆盖成功和拒绝用例, 包含 CSV 行号, 请求摘要, 挑战, 决定, C0 版本或 Fabric 块与原探针及实际副作用. 两轮的 C0 Fabric 列为空, B0/B1 中心化列为空, 所有 Fabric 决定的原探针检查时点均在其单调期限内.

## 代码回归

- 固定夹具覆盖五个种子, 相同种子的逻辑摘要和执行顺序可复现, 三组按 RP/BM 与两档金额配对.
- 真实 ES256 委托逐跳验签, 登记摘要与深度核对, PostgreSQL 六份基线授权交付及钱包装配通过.
- C0 的登记更新与 revision 同事务提交. 并发读取不混版本, 缺少所需记录停止装配, BM 不增加无关 C 域依赖. 删除测试部署的 Fabric 视图后仍可处理请求及 readiness, 无模拟探针.
- 实际业务锁等待期间版本推进会触发整次重验, 最终记录 revision=2 和一次重验. Fabric 现有块推进, 原探针不续期及锁后风险回归通过.
- 决策迁移可重复执行, 原 Fabric 行的读取与历史 h/r 复查通过. C0 决策在数据库和接口中保存实际版本及读取时点, Fabric 字段为空.
- C0/B0 不创建缓存, B1 重复材料命中后采用新撤销状态仍拒绝.
- CSV 列序, 转义, UTC 时间, 纳秒单位, 空值, 计划对账, 挑战关联及跨组副作用检查通过. 预期超额拒绝判为用例通过.
- 准备失败入口非零退出并保留完整计划. 超时和主库查询失败样本保留缺测原因, 查询失败未被当作订单不存在. 实际私钥文本, 完整出示, 披露盐与访问令牌编码扫描通过.

[全量原始测试](../../../infra/fabric/evidence/baseline/validation/final-serial-test-events.jsonl)记录 `go test -json -count=1 -p 1 ./...` 通过, 共 174 个含子测试通过事件及 9 个测试包通过. 两项初始化中断专项及显式 M3 实机测试未在该命令启用. 本变更的独立实机验收由 round5/round6 的实验入口覆盖. [OpenSpec 严格校验](../../../infra/fabric/evidence/baseline/validation/openspec-validation.json)通过.

## 保留的失败与运行边界

一次默认并行包测试中, `TestM3AgentReconcileOrderCreatedAndNotCreatedS63` 收到回执 `503`. [原失败事件](../../../infra/fabric/evidence/baseline/validation/final-unit-test-events.jsonl)和[PostgreSQL 日志](../../../infra/fabric/evidence/baseline/validation/migration-deadlock.log)显示多个测试包共用 schema 时, 迁移 DDL 与回执事务形成死锁. [单项复查](../../../infra/fabric/evidence/baseline/validation/reconcile-recheck.log)及全量顺序包执行通过. 未修改本变更范围外的迁移与在线业务并发调度; 运行说明已给出顺序包回归命令, 各测试内部的显式并发仍保留.

早期接线运行和测试生成器样本均保留, 最终对比采用相同源码指纹的 round5/round6. 本轮验证业务一致性和可重建性, 不据此推导性能优劣或真实 LLM 的正式实验结论.
