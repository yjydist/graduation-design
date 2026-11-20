# 正式实验

按编号选择方法, 再查看已有运行入口和报告. [实验计划](../docs/experiments/实验计划.md)定义共用对照和复现约定. 表和图通过运行 ID 追溯到原始记录. 实现验收及预跑样本见[验收证据索引](../infra/fabric/evidence/README.md).

| 编号 | 方法 | 正式运行入口 | 结果 |
| --- | --- | --- | --- |
| E1 | [采购功能闭环](../docs/experiments/E1-采购功能闭环.md) | [独立驱动](e1-procurement/README.md) | [结果](e1-procurement/result.md) |
| E2 | [安全与状态机检查](../docs/experiments/E2-安全与状态机检查.md) | 待建 | 待建 |
| E3 | [动态调整与恢复](../docs/experiments/E3-动态调整与恢复.md) | 待建 | 待建 |
| E4 | [微基准](../docs/experiments/E4-微基准.md) | 待建 | 待建 |
| E5 | [开放到达负载](../docs/experiments/E5-开放到达负载.md) | 待建 | 待建 |
| E6 | [撤销窗口](../docs/experiments/E6-撤销窗口.md) | [独立驱动](e6-revocation/README.md) | [短跑结果与模板](e6-revocation/result.md) |
| E7 | [故障与并发](../docs/experiments/E7-故障与并发.md) | 待建 | 待建 |
| E8 | [账本与通信开销](../docs/experiments/E8-账本与通信开销.md) | 待建 | 待建 |

## 历史预跑

E3 的模型轨迹, E6 的撤销窗口采样和 E7 的故障专题导出来自 [M3 联合验收](../infra/fabric/evidence/README.md#既有网络与协议验收). 如需重放旧采样逻辑, 可在迁移前提交 `d22889501880859d7cda2ce4b7255475a40a1e59` 上用独立实例运行当时的 `ledgerctl verify`; 原始运行的构建标识和数据仍从各自的证据清单查阅. 正式采样由各实验驱动按上表方法执行.

## 实验用 LLM 配置

编辑 `experiments/llm.env` 指定 `LLM_MODEL` (模型名), `LLM_PROVIDER` (`openai` 或 `anthropic` 接口协议) 和 `LLM_BASE_URL` (服务地址). 运行前在项目根目录加载配置. API 密钥通过当前环境的 `LLM_API_KEY` 提供.

```bash
source experiments/llm.env
```

真实 LLM 实验在每轮清单记录实际模型名, 接口协议和服务地址.

## 目录约定

| 实验目录内的路径 | 内容 |
| --- | --- |
| `result.md` | 正式结果, 含实际配置, 样本量, 图表, 异常, 结论和适用范围 |
| `runs/<run-id>/` | 一轮实验的配置, 原始数据和汇总, 包含失败或中止样本 |
| `figures/` | 结果报告和论文引用的图 |

完整约定见[项目说明](../AGENTS.md#正式实验制品). 新实验目录采用 `e<编号>-<英文主题>` 格式, 正式结果发布后在上表链接相应的 `result.md`.
