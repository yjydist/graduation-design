# rebuild-monorepo-architecture 核验报告

首次核验对象为提交 `aaa5ba9`, 比较基线为 `ccfbb10`. 复核对象为基于该提交的修复工作区. 原 4 项警告均已处理, 已执行的检查未发现严重问题或剩余警告. E1 真实模型场景仅部分核实, 归档就绪性尚未确认.

| 维度 | 结果 |
| --- | --- |
| 完整性 | OpenSpec 聚合任务 18/18 已勾选, 5 份增量规范共 7 项修改要求均找到实现. 无新增, 删除或重命名要求. |
| 正确性 | 7/7 项已映射. 协议, 登记, 钱包和网关的 6 项有针对性回归. 实验调价接口和 E1 配置导出边界已通过专项回归. 已检查全部 23 个场景, 其中真实模型轨迹未完成本提交的端到端核验. |
| 一致性 | 已核对四模块拓扑, 领域包组织, 库选型, 协议简化和链码构建范围. 目录与现有代码风格一致. 修订后的依赖验收命令通过, 代码规模已按统一口径记录. |

## 警告处理与复核

1. **目录调价接口.** 采购基线, E1 和 E6 均调用 `gateway.SetCatalogPrice`. 基线另行回读价格作为证据. PostgreSQL 回归覆盖已存在商品从 80000 分调至 120000 分, 调价后的询价, 无效价格和未登记商品. [接口与回归](../../../platform/gateway/gateway_db_test.go), [目录契约](../../../docs/implementation/REST接口与响应码.md).
2. **E1 公开导出.** 模型提供方, 名称与服务端点由清单显式记录. 快照排除本机 `llm.env`. 先校验端点再写清单, 拒绝凭据, 查询参数或片段, 错误信息不回显输入. 使用含虚构敏感字段的临时配置执行计划模式, 检查解压后的归档和实际清单. 另通过真实 CLI 生成并核对本机计划 `repaired-e1-plan`. [编排](../../../experiments/cmd/exp/run.go), [导出回归](../../../experiments/cmd/exp/exp_test.go).
3. **模块边界.** 项目侧检查 `go list -deps -test` 列出的完整依赖, 实验侧检查 `.Imports`, `.TestImports` 和 `.XTestImports` 三组直接导入. 两项均通过. [验收命令](../../../AGENTS.md), [任务 6.1 和 7.2](tasks.md).
4. **代码规模.** 按用户决定, 行数作为观察指标. 统计 Git 跟踪的 Go 源文件物理行, 包含注释和空行. 生产代码与含测试代码采用相同统计口径. [设计目标](design.md#goals--non-goals).

| 范围 | 基线 `ccfbb10` | 首次核验 `aaa5ba9` | 修复工作区 |
| --- | --- | --- | --- |
| 生产 Go 文件 / 行 | 74 / 30774 | 65 / 33706 | 65 / 33725 |
| 含测试 Go 文件 / 行 | 124 / 52706 | 104 / 50660 | 104 / 50715 |

## 规范与证据

| 修改要求 | 场景 | 实现与验证位置 |
| --- | --- | --- |
| 规范编码与静态向量 | 3 | `protocol/request.go:143` 校验访问请求. `protocol/request_test.go:97`, `protocol/crypto_test.go:192` 和 `protocol/codec_test.go:270` 等覆盖向量, 非规范输入和旧 URI. |
| 管理交易确认与失败证据 | 4 | `platform/registrysvc/operations.go:435` 和 `platform/state/fabric/journal.go` 处理受理, 原交易恢复与终态. `operations_db_test.go:91` 和 `fabric_live_test.go:652` 覆盖异步状态, 拒绝, 重试和竞争. |
| 六个 MCP 钱包工具 | 3 | `platform/agent/tools.go:168` 注册工具. `agent_db_test.go:28`, `agent_test.go:616`, `agent_test.go:647` 和 `platform/cmd/ledgerctl/main_test.go:221` 覆盖发送前持久化, 输出隔离, 改派, 核账及传输接入. |
| 直接询价与业务键幂等 | 3 | `platform/gateway/execute.go:142` 校验请求, `execute.go:361` 进入事务. `gateway_db_test.go:686` 覆盖同键重试, 错误签名和历史别名拒绝. |
| 建单与跨实例唯一性 | 3 | `platform/gateway/execute.go:361`. `gateway_db_test.go:810`, `:930` 和 `:1039` 覆盖金额, 锁后风险或撤销, 并发唯一建单. |
| 两实例核账与审计隔离 | 4 | `platform/gateway/audit.go:195`, `:347` 和 `:740`. `gateway_db_test.go:1039`, `:1205` 与 `platform/agent/agent_db_test.go:134` 覆盖过期并发, 历史复核, 权限及回执重放. |
| 可重建的正式实验输入 | 3 | `experiments/cmd/exp/run.go:285` 建运行目录和快照. `exp_test.go:137` 和 `:385` 验证计划与构建. E6 两种模式有实测和独立复算. 真实模型场景已有驱动和工具测试, 当前提交可定位的 E1 两份计划均为 0/16 已执行. 本轮环境缺少 `LLM_API_KEY`, 未核实真实会话记录. |

## 运行结果

- 首次核验通过 OpenSpec 严格校验, `mise run ledger:build`, `mise run test:unit`, 额外的三模块无缓存单测, `mise run test:db` 和 `mise -C experiments run experiment:test`. 构建产物帮助列出全部 7 个业务子命令. `grad/protocol/registry` 的直接导入均属标准库.
- 首次核验采用 `aaa5ba9` 已有的隔离实例日志, 6 个顶层实机测试均为 PASS. 可在本机 `.local/openspec-verify-monorepo-aaa5ba9/verify-live.log` 复核. 两份采购基线汇总均为通过.
- 首次核验对同目录下的 `verify-e6-rp` 和 `verify-e6-bm` 原始样本分别运行 `exp analyze`. 双实例 RP 完成 1102/1102 个采样, BM 完成 1126/1126 个采样, 两组违规均为 0. 两份重算 JSON 与此前保存的对应结果逐字段一致. E6 数据为短跑样本.

## 修复工作区验证

- 通过 `mise run ledger:build`, `mise run test:unit`, `mise run test:db`, `mise -C experiments run experiment:test`, 两项依赖边界检查和 OpenSpec 严格校验.
- 新建两个隔离 Fabric 环境, 通过 `exp run --workspace-sut` 执行 E6 双实例短跑并用 `exp analyze` 离线复算. RP 完成 1112/1112, BM 完成 1104/1104. 两组均为 0 次违规和 1 个延迟响应样本. RP 轮使用接口初版, BM 轮使用最终实现. 本机原始样本位于 `.local/monorepo-fixes.S0dwVAYA/runs/{repaired-e6-rp,repaired-e6-bm}`.
- E1 已复核计划, 配置与归档. 当前环境缺少 `LLM_API_KEY`, 真实模型会话仍待验证.
