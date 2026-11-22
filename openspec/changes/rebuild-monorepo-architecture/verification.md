# rebuild-monorepo-architecture 核验报告

## 6 项警告的修复复核

基于 `ec86062` 的工作区已修复该次核验的全部 6 项警告. 已执行的检查发现 0 项严重问题, 0 项剩余警告. E1 真实模型会话的端到端场景仍待核实, 本次未确认归档就绪.

| 维度 | 复核结果 |
| --- | --- |
| 完整性 | 原任务 18/18 已勾选, 5 份增量规范共 7 项修改要求均有实现. |
| 正确性 | 已对管理操作的线上 JSON, 幂等重试, 旧版本预检和实验模型记录执行针对性回归. 23 个场景中, E1 真实模型会话的端到端证据仍不完整, 当前环境未设置 `LLM_API_KEY`. |
| 一致性 | 四模块依赖边界检查通过. 管理服务和 Fabric 日志使用共享错误码, 链码提案解析单独限制适用范围. |

| 原警告 | 修复与验证 |
| --- | --- |
| 1. 操作查询字段 | 原交易日志保存实际观测 Peer 和交易索引. 服务在同一事务内持久化提交证据, 查询以 `failureCode`, `transactionIndex`, `observedPeer` 返回. 数据库回归逐字段检查三种状态, 实机测试经管理 HTTP 撤销委托后将查询结果与原交易逐项比对. [数据库回归](../../../platform/registrysvc/operations_db_test.go), [Fabric 实机回归](../../../platform/runtime/stack_live_test.go). |
| 2. JSON 字段顺序影响重试 | 普通管理请求使用协议 JCS 规范化后计算正文摘要. 同一作用域内调换字段顺序仍返回 202 和原操作 ID, 正文值不同返回 409. [受理实现](../../../platform/registrysvc/operations.go), [幂等回归](../../../platform/registrysvc/operations_db_test.go). |
| 3. 操作键跨身份和方法碰撞 | 数据库约束, 事务锁和操作 ID 使用部署, 已认证调用者, 管理方法对应的 POST 路径及客户端键. Fabric 首次提交和恢复共用该操作 ID 作为日志键. 注册双证明受理也使用相同规则. 回归覆盖跨方法, 跨身份, 重启重试及重复注册确认. [登记表](../../../platform/migrations/003_registrysvc.sql), [注册回归](../../../platform/registrysvc/identity_db_test.go). |
| 4. 替换委托缺少预检 | 受理端用 `old.id` 查询原委托并比较 `old.expectedRevision`. 过时请求返回 409 STATE_CHANGED, 数据库无待提交操作, 后端提交次数为 0. 当前版本返回 202. [预检与回归](../../../platform/registrysvc/operations_db_test.go). |
| 5. 请求名与响应模型混用 | 两种 SDK 均逐步保存响应中的模型标识. E1 清单分别记录请求名和去重后的响应模型集合, 离线分析器从轨迹独立重建该集合并核对. 两种 SDK 均通过请求别名与响应名不同的测试, 离线回归也验证了清单声称使用未观测模型时核对失败. [双 SDK 回归](../../../platform/agent/agent_test.go), [离线复算回归](../../../experiments/cmd/exp/exp_test.go). |
| 6. 错误码多处定义 | `OPERATION_UNKNOWN`, `ENDORSEMENT_REJECTED`, `COMMIT_INVALID` 均由登记共享包定义. 提案解析回归确认这 3 个服务级码不能充当链码拒绝原因. [规范错误码](../../../protocol/registry/errors.go), [提案解析回归](../../../platform/state/fabric/instance_test.go). |

通过 OpenSpec 严格校验, CLI 构建, 项目单测, PostgreSQL 集成测试, 实验模块测试和隔离 Fabric 实机验收. 实机 6 个顶层用例均通过, 验收实例已停止. 本机日志位于 `.local/monorepo-warning-fixes-ay2fpehn/final-verify.log`. E1 的计划模式已通过真实 CLI 生成清单, 本轮 SDK 调用使用测试服务.

## 提交 `ec86062` 的归档判断

已执行的检查发现 0 项严重问题, 6 项警告. E1 真实模型会话的场景覆盖尚未完全核实, 本次无法确认归档就绪.

| 维度 | 结果 |
| --- | --- |
| 完整性 | OpenSpec 聚合任务 18/18 已勾选. 5 份增量规范的 7 项修改要求均找到实现. 新增, 删除和重命名要求均为 0. |
| 正确性 | 7/7 项要求已映射, 已逐项检查 23 个场景. 管理操作的返回字段, 幂等行为, 版本预检和 E1 模型标识存在下列偏差. 场景覆盖部分未核实, 当前环境未设置 `LLM_API_KEY`, 可定位的新架构 E1 计划未执行模型会话. |
| 一致性 | 已核对 5 项设计决策及代码组织. 四模块依赖方向, 状态源分层, 钱包与网关边界, 库选型和链码摘要范围有实现及回归证据. 统一错误码表仍有一处设计偏差. |

### 警告

| 项目 | 发现与修正建议 |
| --- | --- |
| 1. 操作查询的返回字段 | `platform/registrysvc/operations.go:57` 将失败码序列化为 `errorCode`. 查询处理器直接输出该结构, 增量场景要求的 `failureCode` 缺失. REST 契约所列的 `transactionIndex` 和 `observedPeer` 也没有投影到查询响应. 建议从原交易证据补齐字段, 对 PENDING, CONFIRMED 和 FAILED 的原始 HTTP JSON 分别断言字段名和值. [规范场景](specs/authorization-registry/spec.md), [查询契约](../../../docs/implementation/REST接口与响应码.md). |
| 2. 同一请求调整 JSON 字段顺序后重试冲突 | `platform/registrysvc/operations.go:471` 对普通请求使用 `json.Compact` 计算摘要, 保留对象字段原序. PostgreSQL 定向检查中, 首次受理后仅交换字段顺序即返回 409 IDEMPOTENCY_CONFLICT. 建议复用 `protocol.CanonicalizeJSON` 生成契约要求的 JCS 输入, 回归断言第二次返回 202 和原 operationId. [幂等契约](../../../docs/implementation/REST接口与响应码.md). |
| 3. 管理操作键的唯一范围过宽 | `platform/migrations/003_registrysvc.sql:20` 仅按部署和操作键唯一. `platform/registrysvc/operations.go:492` 的锁和查找也只按这两项, 不同管理方法使用同一键时实测返回 409. 建议按登录管理身份, 方法和路径区分操作键, 同步调整 operationId 及底层交易日志键, 覆盖跨方法与跨身份独立受理. [幂等契约](../../../docs/implementation/REST接口与响应码.md). |
| 4. 替换委托跳过受理前版本预检 | `protocol/registry/types.go:285` 将旧委托的版本放在 `old.expectedRevision`, `platform/registrysvc/operations.go:534` 仅读取顶层版本, `CurrentRevision` 也没有 ReplaceGrant 分支. 旧版本请求可先得到 202. 建议用替换请求的旧委托 ID 查当前版本, 覆盖过时请求返回 409 STATE_CHANGED 且未写入待提交操作. [管理交易要求](specs/authorization-registry/spec.md). |
| 5. E1 仅记录配置中的模型名 | `platform/agent/llm.go:216` 和 `:293` 用请求配置填充结果, 两个 SDK 循环都未记录响应中的模型标识. `experiments/e1/driver/main.go:299` 同样只写配置名. 当服务解析模型别名时, 无法从清单或轨迹确定服务实际报告的模型. 建议分别保存请求名与响应模型标识, 用两者不同的 SDK 响应覆盖清单与用例轨迹. [真实模型场景](specs/reproducible-procurement-experiments/spec.md). |
| 6. 管理交易错误码存在多个来源 | `platform/registrysvc/operations.go:34` 在服务内定义了 3 个错误码, `platform/state/fabric/journal.go:107` 和 `:288` 重复使用其中两个字符串. 它们未列入 `protocol/registry/errors.go` 的规范表. 建议集中定义这些平台规范码, 同时保留链码提案拒绝码的适用范围, 增加异步失败码映射回归. [统一错误码设计](design.md). |

### 本轮验证证据

- OpenSpec 严格校验, CLI 构建, 项目单测, PostgreSQL 集成测试和实验模块测试通过. 协议, 链码及实验包另以 `-count=1` 重跑通过.
- 在新建的隔离 Fabric 实例上执行部署, 播种, 状态检查及实机验收. 6 个顶层实机用例全部通过, 包含真实子进程的 `ledgerctl check`, `inspect` 和 MCP 握手. 本轮实例已停止. 本机日志位于 `.local/verify-head-n5f0c4_2/verify.log`.
- PostgreSQL 定向检查通过真实的 `Service.Accept` 和操作视图序列化观察受理结果, 版本源使用固定当前版本的测试后端. 记录位于 `.local/verify-head-n5f0c4_2/management-contract.log`. 以上版本预检发现针对受理阶段.
- 依赖图检查通过. 项目模块及测试无实验依赖, 实验的普通导入和两类测试导入均未引用平台私有包. 状态源不依赖钱包或网关, 登记模型的传递依赖均为标准库.
- 本轮以当前分析器复算已有 E6 双实例原始样本. RP 完成 1112/1112 个采样, BM 完成 1104/1104 个采样, 两组均为 0 次违规和 1 个延迟响应. 派生结果位于 `.local/verify-head-n5f0c4_2/analysis-rp` 和 `analysis-bm`. E1 计划和 SDK 测试能验证配置与工具调用代码, 真实会话记录仍缺少本轮实测证据.

## 前次核验记录

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
