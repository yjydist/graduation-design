# m4-domain-web-workbench 核验报告

## 中文输入与核账状态修复复核

两项警告已修复. OpenSpec 任务完成度为 25/25.

| 警告 | 修复及验证 |
| --- | --- |
| 中文输入长度契约不一致 | 浏览器与 Go 按 OpenAPI 的 Unicode 码点计数. Chrome 测试和隔离 PostgreSQL HTTP 回归均确认, 汉字与补充平面字符在 4000 码点的消息上限和 512 码点的草稿说明上限处可提交, 超出 1 个码点时被拒绝. 草稿返回值也通过 OpenAPI 验证. [浏览器校验](../../../web/app.js#L384), [后端校验](../../../platform/workbench/procurement.go#L184), [HTTP 回归](../../../platform/workbench/procurement_db_test.go#L27). |
| 未知核账轨迹显示为"已返回" | 页面按 `actionStatus: OUTCOME_UNKNOWN` 或 `outcome: UNKNOWN` 显示"业务结果未知". Chrome 加载实际前端和测试响应, 验证 `step: 0` 的后台核账及模型发起的 MCP 核账均显示该状态, 同时保留拒绝与正常返回的状态. [轨迹渲染](../../../web/app.js#L584). |

OpenSpec 严格校验, 三模块无缓存单测, 全量 PostgreSQL 集成测试, 工作台数据库回归竞态检测, 前端语法检查和前后端镜像构建均通过. 浏览器定向回归使用测试响应, 三域实机和真实模型全流程采用[既有验收记录](../../../infra/workbench/evidence/m4-domain-web-workbench/README.md).

## 提交 `e96619b` 的独立复核

| 维度 | 结果 |
| --- | --- |
| 完整性 | 23/23 项任务已勾选, 7/7 项新增要求均找到实现. 修改, 删除和重命名要求均为 0. |
| 正确性 | 7/7 项要求已映射, 10/10 个场景均有回归或已留存实机证据. 核账轨迹的未知状态提示存在偏差. |
| 一致性 | 已核对 4 项设计决策及代码组织. 双镜像, 本域身份与运行绑定, 持久化流程及证据投影均有对应实现. 浏览器输入长度契约存在偏差. 四模块依赖边界检查通过. |

### 警告

1. **中文输入的长度限制在 OpenAPI 与 Go 处理器之间不一致.** OpenAPI 的 `maxLength` 按字符计数, Go 的 `len` 按 UTF-8 字节计数. 隔离 PostgreSQL 回归通过已登录的 HTTP 处理器复现, 1500 个汉字的对话消息和 200 个汉字的草稿说明均通过发布的 OpenAPI 校验, 实际请求均返回 `400 INVALID_SCHEMA`. 建议统一前端, OpenAPI 和 Go 的长度单位, 并用多字节输入验证 `ChatInput` 和 `DraftEdit` 的边界. [对话处理器](../../../platform/workbench/procurement.go#L173), [草稿限制](../../../platform/workbench/procurement.go#L57), [消息契约](../../../platform/workbench/openapi.json#L440), [草稿契约](../../../platform/workbench/openapi.json#L482).
2. **未知核账结果在工具轨迹上显示为"已返回".** 后台及 MCP 核账可返回 `actionStatus: OUTCOME_UNKNOWN` 和 `outcome: UNKNOWN`. 轨迹渲染判断的是 `actionStatus === 'UNKNOWN'`, 此类轨迹没有 `decision` 时便显示"已返回". 对实际 `toolTraces` 函数的定向检查复现了该结果. 建议用 `OUTCOME_UNKNOWN` 或核账 `outcome` 映射"业务结果未知", 并覆盖 `step: 0` 后台核账与模型核账轨迹. [后台核账投影](../../../platform/runtime/workbench_dispatch.go#L305), [核账输出](../../../platform/agent/tools.go#L934), [轨迹渲染](../../../web/app.js#L573).

### 要求与场景证据

| 新增要求 | 场景数 | 核验依据 |
| --- | --- | --- |
| Web 与 MCP 共用确定性业务操作 | 2 | 域间 HTTP 和 MCP 使用同一组绑定操作及业务键. 钱包重启后, 原报价可用于首次下单, 重试只对应一笔订单. 网关的报价有效期和当前授权有独立回归. [域间路由](../../../platform/runtime/workbench_transport.go#L125), [配对回归](../../../platform/runtime/workbench_grants_db_test.go#L355), [网关回归](../../../platform/gateway/gateway_db_test.go#L811). |
| 工作台派单绑定各域智能体身份与当前任务 | 2 | A1 按 G1 与收件者绑定转委托. B 域验证 G2, 签发者, 任务摘要与派单重放. MCP 回归覆盖伪造主体, 任务, 模式与委托参数. [A1 执行](../../../platform/runtime/workbench_flow.go#L318), [B 域接单](../../../platform/runtime/workbench_flow.go#L520), [绑定回归](../../../platform/agent/bound_test.go#L15). |
| 三域复用独立构建的前后端 | 1 | 当前前后端镜像均可构建, 三域 Compose 配置通过. 已留存的干净部署记录覆盖镜像复用, 就绪, 独立存储及凭据隔离. [Compose 模板](../../../infra/workbench/compose.yaml), [部署记录](../../../infra/workbench/evidence/m4-domain-web-workbench/clean-rerun.json). |
| 浏览器会话绑定可信域身份和权限 | 2 | 会话, CSRF, 本域角色校验及原交易查询均有回归. 三域管理员的真实管理操作在原块确认. [会话校验](../../../platform/workbench/session.go#L292), [浏览器 API 回归](../../../platform/workbench/server_db_test.go#L33), [实机管理记录](../../../infra/workbench/evidence/m4-domain-web-workbench/live-admin.json). |
| 采购员确认结构化任务后派发智能体 | 1 | 回归覆盖草稿修改, 旧版本拒绝, 并发确认, 原登记操作恢复及等待交付. 实机记录区分 C 签发的 RP 根和 PA 签发的 BM 根. [采购回归](../../../platform/workbench/procurement_db_test.go#L26), [流程推进](../../../platform/runtime/workbench_flow.go#L80), [实机证据](../../../infra/workbench/evidence/m4-domain-web-workbench/README.md). |
| 角色可见的采购与决策证据 | 1 | 五个视图引用真实记录, 逐跳金额可在 C 定案前读取. 核对了摘要与原决定权限, 业务 ID 重载及 `step: 0` 响应. 核账状态提示见警告. [证据投影](../../../platform/runtime/workbench_evidence.go#L40), [决定权限回归](../../../platform/gateway/gateway_db_test.go#L1394), [运行详情回归](../../../platform/workbench/procurement_db_test.go#L186). |
| 浏览器复现两种根和动态状态变化 | 1 | 留存的主库与交易证据显示唯一 800 元订单, 1200 元订单请求以 `AMOUNT_LIMIT_EXCEEDED` 拒绝, C 在第 507 块返回 `ANCESTOR_INACTIVE`. G1 恢复沿用原截止, 随后询价成功. [主库与交易对账](../../../infra/workbench/evidence/m4-domain-web-workbench/ledger-reconciliation.json), [恢复后询价](../../../infra/workbench/evidence/m4-domain-web-workbench/resumed-probe.json). |

### 本轮验证结果

- 通过 OpenSpec 严格校验, 三模块无缓存单测, 全量 PostgreSQL 集成测试, `agent`, `runtime` 和 `workbench` 的数据库回归竞态检测, `fabriclive` 标签编译, 四模块依赖边界检查, 前端脚本语法检查, 两个镜像构建及三域 Compose 配置检查.
- 当前 OpenAPI 校验通过 4 份留存运行响应, 2 份任务证据投影及 2 份 C 审计决定. 另用临时定向检查复现两项警告.
- 三域实机部署, 浏览器和真实模型全流程采用仓库已留存的隔离实例证据. 本轮重新核对镜像一致性记录, 主库订单, 网关决定, G1 截止和恢复回执.

0 项严重问题, 2 项警告, 0 项建议, 0 项未核实检查. 可归档, 建议优先修正中文输入契约和未知核账的状态提示.

## 工具轨迹警告修复复核

两项警告均已修复. OpenSpec 任务完成度为 23/23.

| 警告 | 修复及证据 |
| --- | --- |
| 轨迹丢失原业务结果 ID | 转委托提取 `grantId`, 下单保留 `actionId`, MCP 核账将 `creationDecisionId` 投影为 `decisionId`. 定向测试确认三个字段保留, 原始参数, 文本和完整委托材料继续脱敏. PostgreSQL 回归确认重新创建运行详情处理器后仍能读回三个 ID. [轨迹投影](../../../platform/runtime/workbench_dispatch.go#L403), [投影回归](../../../platform/runtime/workbench_flow_test.go#L16), [重载回归](../../../platform/workbench/procurement_db_test.go#L187). |
| 服务调用轨迹不符合 OpenAPI | `step: 0` 表示服务发起, 模型轮次从 1 开始. 前端仅为正数显示模型步骤. 域间 HTTP 配对回归从 B 读回 `step: 0` 及原业务 ID. 浏览器回归用发布的 OpenAPI 校验实际运行详情响应, 并将测试发现的 `mode` 枚举偏差修正为协议中的完整授权模式值. [OpenAPI](../../../platform/workbench/openapi.json#L519), [HTTP 回归](../../../platform/runtime/workbench_grants_db_test.go#L391), [响应契约回归](../../../platform/workbench/procurement_db_test.go#L226). |

通过 OpenSpec 严格校验, 三模块无缓存单测, 全量 PostgreSQL 集成测试, 工作台相关竞态检测, `fabriclive` 标签编译, 前端语法和轨迹渲染检查, 前后端镜像构建. 浏览器和真实模型全流程仍以已留存的 [实机证据](../../../infra/workbench/evidence/m4-domain-web-workbench/README.md) 为依据. 修复前已持久化的轨迹中, 当时丢失的字段无法从轨迹原文补回.

## 提交 `e3f9b65` 的独立复核

| 维度 | 结果 |
| --- | --- |
| 完整性 | 21/21 项任务已勾选, 7/7 项新增要求找到实现. 修改, 删除和重命名要求均为 0. |
| 正确性 | 7/7 项要求已映射, 10 个场景均已核对. 报价恢复通过. 工具轨迹存在关联字段丢失和响应契约偏差. |
| 一致性 | 已核对 4 项设计决策及代码组织. 双镜像, 本域会话与执行绑定, 持久化队列和证据投影均有对应实现. 轨迹关联存在下述偏差. 四模块依赖边界检查通过. |

### 警告

1. **脱敏投影丢失关联原业务结果所需的 ID.** 通过临时定向测试确认, `delegate_grant` 的 `grant.grantId`, 订单结果未知时的 `actionId`, 以及 MCP 核账返回的 `creationDecisionId` 经 `boundedTrace` 后均消失. 从相应工具调用无法直接关联链上 G2, 原订单意图或 C 的原决定. 建议仅保留这些获准展示的结构化 ID, 将 `creationDecisionId` 投影到 `decisionId`, 并增加运行详情重载后仍可逐项对账的回归. [规范场景](specs/domain-web-workbench/spec.md#scenario-从采购任务追踪真实业务事实), [轨迹投影](../../../platform/runtime/workbench_dispatch.go#L403), [委托结果](../../../platform/agent/tools.go#L53), [订单与核账结果](../../../platform/agent/tools.go#L125).
2. **受控 HTTP 产生的轨迹不符合浏览器 OpenAPI.** `ToolTrace.step` 为必填项且最小值为 1. 在隔离 PostgreSQL 配对回归中, 经实际域间 HTTP 入口询价成功, A 侧读回的持久化轨迹 `step` 为 0. 浏览器运行详情直接返回该轨迹. 确定性探针和后台自动核账也未赋步骤值. 建议文档明确非模型轨迹的步骤语义, 统一写入及读取行为, 并用实际运行详情响应验证 `Run` 模型. [OpenAPI 定义](../../../platform/workbench/openapi.json#L515), [HTTP 轨迹写入](../../../platform/runtime/workbench_dispatch.go#L247), [运行详情读取](../../../platform/workbench/procurement.go#L358), [配对回归](../../../platform/runtime/workbench_grants_db_test.go#L355).

### 要求与场景证据

| 新增要求 | 场景数 | 核对结果 |
| --- | --- | --- |
| Web 与 MCP 共用确定性业务操作 | 2 | HTTP 和 MCP 使用同一绑定及业务键. 钱包重建后原报价可用于首次下单, 重试返回同一订单. 绑定判据, 过期报价和当前授权分别由配对回归和 C 网关回归覆盖. [HTTP 入口](../../../platform/runtime/workbench_transport.go#L125), [报价恢复](../../../platform/runtime/workbench_grants_db_test.go#L355), [报价有效期回归](../../../platform/gateway/gateway_db_test.go#L918). |
| 工作台派单绑定各域智能体身份与当前任务 | 2 | A1 绑定 G1 及指定收件人, B 校验已交付的 G2 及原任务, MCP 裁剪阶段工具. 身份, 模式及任务绑定错误有回归, 两域模型执行有实机记录. [A1 装配](../../../platform/runtime/workbench_flow.go#L318), [B 域派单](../../../platform/runtime/workbench_flow.go#L520), [绑定回归](../../../platform/agent/bound_test.go#L15). |
| 三域复用独立构建的前后端 | 1 | 两个镜像重新构建成功, 三域 Compose 配置通过. 已有实机记录覆盖镜像一致, 运行时配置, 就绪, 独立存储和凭据隔离. OpenAPI 响应发现上述警告. [Compose 模板](../../../infra/workbench/compose.yaml), [干净部署记录](../../../infra/workbench/evidence/m4-domain-web-workbench/clean-rerun.json). |
| 浏览器会话绑定可信域身份和权限 | 2 | 三域管理员读取原 `operationId` 及有效交易结果. 跨域会话, 无效会话, 越权及 CSRF 均有回归. [会话校验](../../../platform/workbench/session.go#L292), [管理回归](../../../platform/workbench/server_db_test.go#L33), [实机管理记录](../../../infra/workbench/evidence/m4-domain-web-workbench/live-admin.json). |
| 采购员确认结构化任务后派发智能体 | 1 | 草稿版本, 并发确认, 待确认状态恢复和未交付材料门槛有回归. RP/BM 分别使用 C 和 PA 的根. [草稿确认](../../../platform/workbench/procurement.go#L286), [采购回归](../../../platform/workbench/procurement_db_test.go#L24), [阶段推进](../../../platform/runtime/workbench_flow.go#L80). |
| 角色可见的采购与决策证据 | 1 | 核对五个视图和摘要与完整决定的访问边界, 确认 C 尚无决定时能显示逐跳金额. 工具结果关联存在上述警告. [逐跳金额回归](../../../platform/runtime/workbench_grants_db_test.go#L281), [证据权限回归](../../../platform/gateway/gateway_db_test.go#L1394), [实机证据索引](../../../infra/workbench/evidence/m4-domain-web-workbench/README.md). |
| 浏览器复现两种根和动态状态变化 | 1 | 已有实机记录和主库导出相符. RP 唯一 800 元订单, BM 的 1200 元下单以 `AMOUNT_LIMIT_EXCEEDED` 拒绝, C 采用第 507 块后返回 `ANCESTOR_INACTIVE`, G1 恢复后沿用原期限且询价成功. [主库与交易对账](../../../infra/workbench/evidence/m4-domain-web-workbench/ledger-reconciliation.json), [恢复后询价](../../../infra/workbench/evidence/m4-domain-web-workbench/resumed-probe.json). |

### 验证结果

- 通过 OpenSpec 严格校验, 三模块无缓存单测, 平台全量 PostgreSQL 集成测试, 工作台相关竞态检测, `fabriclive` 标签编译, 四模块依赖边界检查, 前端脚本语法检查, 前后端镜像构建及三域 Compose 配置检查.
- 两项新增轨迹问题均通过临时定向检查复现. 定向检查未写入仓库.
- 三域实机启动, 浏览器和真实模型全流程采用仓库中已有的隔离实例证据. 本轮重新对账留存的交易, 网关结果和 C 主库导出.

0 项严重问题, 2 项警告, 0 项建议, 0 项未核实检查. 可归档, 建议先补齐工具轨迹关联和 OpenAPI 响应契约.

## 报价恢复警告修复复核

21/21 项任务已完成. 7 项新增要求和 10 个场景均有实现及回归或既有实机证据. 报价恢复警告已关闭.

- B1 钱包在返回报价前按原运行询价键保存 C 返回的报价 ID, 币种和总价. 重启后直接使用已持久化的原报价提交首次订单, 业务键和 C 网关判据继续适用. [报价持久化](../../../platform/agent/bound.go#L192), [迁移 012](../../../platform/migrations/012_bound_quotes.sql), [首次下单恢复](../../../platform/agent/bound.go#L241).
- 配对回归先在修复前复现 `BINDING_MISMATCH`, 再在隔离 PostgreSQL 和 C 网关事务上验证修复. 清空 B1 钱包内存后, 原报价可用于首次 HTTP 下单, 随后 MCP 和再重启后的两入口重试均返回原订单. C 的询价决策数保持不变且主库只有一笔订单. 错误报价 ID, 金额和不同运行的询价键绑定均被拒绝. [配对回归](../../../platform/runtime/workbench_grants_db_test.go#L355).
- OpenSpec 严格校验, 三模块无缓存单测, 平台全量 PostgreSQL 集成测试, 相关竞态检测, `fabriclive` 标签编译和后端镜像构建均通过. 浏览器和真实模型全流程采用既有实机证据. [实机证据索引](../../../infra/workbench/evidence/m4-domain-web-workbench/README.md).

## 提交 `b824210` 的独立复核

| 维度 | 结果 |
| --- | --- |
| 完整性 | 20/20 项任务已勾选, 7/7 项新增要求找到实现. 修改, 删除和重命名要求均为 0. |
| 正确性 | 7/7 项要求映射到实现, 9/9 个场景有回归或实机证据. 新增 1 项报价恢复警告. |
| 一致性 | 核对 4 项设计决策及现有模块惯例. 双镜像, 本域会话与执行绑定, 持久化队列和证据投影均有对应实现. 已接受报价的恢复存在下述偏差. |

### 警告

1. **B1 取得报价后若在首次下单前重启, 会丢失原报价的运行绑定.** 在现有隔离 PostgreSQL 配对回归中, 于取得有效报价后重建 B1 钱包. HTTP 和 MCP 随即对使用原 `quoteId` 的首次下单都返回 `BINDING_MISMATCH`. `orderQuoteTerms` 从钱包内存读取报价, 或从已有订单意图恢复. 此时订单意图尚未创建. 用同一个运行键重新询价可取回原 `quoteId`, 随后成功下单, C 主库仍只有一笔订单. 建议持久化并恢复可信报价与原运行键的绑定, 并在配对回归中保留报价成功与首次下单之间的重启断点. [报价查找](../../../platform/agent/bound.go#L218), [内存报价写入](../../../platform/agent/tools.go#L601), [现有配对回归](../../../platform/runtime/workbench_grants_db_test.go#L355), [恢复设计](design.md#3-区分交互草稿与已确认执行).

### 验证结果

- OpenSpec 严格校验, 三模块无缓存单测, 平台全量 PostgreSQL 集成测试, 工作台相关回归的竞态检测, `fabriclive` 标签编译, 两份前端脚本语法检查和四模块依赖边界检查均通过.
- 当前源码的前后端镜像分别构建成功, 三域 Compose 配置校验通过. 现有隔离实例的三域 HTTPS 入口通过各自 CA 验证并报告就绪. 浏览器和真实模型全流程采用已留存的实机证据. [实机证据索引](../../../infra/workbench/evidence/m4-domain-web-workbench/README.md).
- 只读查询 C 主库确认唯一 800 元订单, 两条 `AMOUNT_LIMIT_EXCEEDED` 均未关联订单, 以及第 507 块下的 `ANCESTOR_INACTIVE`. 恢复后询价及 G1 原截止时间沿用实机记录. [主库与交易对账](../../../infra/workbench/evidence/m4-domain-web-workbench/ledger-reconciliation.json).

0 项严重问题, 1 项警告, 0 项建议, 0 项未核实检查. 可归档, 建议补齐报价恢复.

## 原三项警告的修复复核

三项警告均已修复并通过回归. 任务完成度为 20/20. 7 项要求和 9 个场景均有对应实现及回归或实机证据. 本轮使用隔离 PostgreSQL 验证修复, 测试中的 C 网关执行实际报价, 订单事务和业务键约束. 浏览器及真实模型全流程沿用原实机记录, 当前后端镜像完成了构建核验.

| 原警告 | 修复及验证 |
| --- | --- |
| Web HTTP 与 MCP 配对缺少证据 | A 经实际域间 HTTP handler 请求 B1 询价和建单, 与 B1 MCP 比对同一报价, 订单, 绑定错误码及暂停祖先的拒绝. 钱包重建后可用原意图重试, C 主库中该任务仍只有一笔订单, 业务键与运行绑定一致. [配对回归](../../../platform/runtime/workbench_grants_db_test.go#L355), [域间接口](../../../docs/implementation/REST接口与响应码.md#41-域间工作台接口). |
| C 尚无决定时委托树缺少逐跳金额 | 通过锚点对照签发材料或钱包回执, 取得 G0/G1/G2 的实际额度. 回归验证 RP 根确认且尚未送达 A 时可从 C 获取额度摘要, 并在 C 尚无决定时显示不同的三跳金额. 不匹配的签发材料被拒绝. [根额度回归](../../../platform/runtime/workbench_grants_db_test.go#L184), [逐跳额度回归](../../../platform/runtime/workbench_grants_db_test.go#L281). |
| 固定批次可能长期跳过后续运行 | A/B 均在取得运行锁后持久化下次处理顺序. 两个回归各保留 51 项, 首轮处理前 50 项, 重建 Worker 后第 51 项得到推进机会. 迁移回归核对已有待处理任务和 B 域回执. [A 域回归](../../../platform/workbench/procurement_db_test.go#L214), [B 域回归](../../../platform/runtime/workbench_grants_db_test.go#L469), [迁移回归](../../../platform/migrations/migrations_test.go#L138). |

OpenSpec 严格校验, 项目三模块无缓存单测, 全量 PostgreSQL 集成测试, 工作台相关回归的竞态检测, `fabriclive` 标签编译和后端镜像构建均通过.

## 提交 `cd58e23` 的初次核验

核验实现提交 `cd58e23`. 已执行的检查发现 0 项严重问题, 3 项警告. 场景覆盖部分未核实, 同一主体经 Web HTTP 与 MCP 发起同一业务操作的配对场景缺少端到端证据. 本轮无法确认归档就绪.

## 汇总

| 维度 | 结果 |
| --- | --- |
| 完整性 | 17/17 项任务已勾选. 2 份增量规范通过严格校验, 7 项新增要求均找到实现入口. 修改, 删除和重命名要求均为 0. |
| 正确性 | 7/7 项要求已映射, 9 个场景已核对. 7 个场景有回归或实机证据, 委托树场景有 1 处实现偏差, Web HTTP 与 MCP 配对场景部分未核实. |
| 一致性 | 已核对 4 项设计决策及代码组织. 双镜像部署, 同源 API, 本域会话与签名, 分阶段执行及证据读取均有实现. 待处理运行的轮询存在 1 处恢复偏差. 四模块依赖边界检查通过. |

## 警告

1. **Web HTTP 与 MCP 配对场景部分未核实.** 现有回归配对调用 `BoundOperations` 和 MCP, 核对了参数错误码与唯一订单. 浏览器 HTTP 路由中没有可用来配对的询价或建单操作. 受控的确定性探针使用独立业务键, 并以保留材料让 C 判定停用祖先. 建议明确规范所指的获准 HTTP 入口, 经实际 HTTP handler 和 MCP 使用相同部署, 主体, 任务和业务输入, 核对权限变化时的错误码及重复提交后的副作用. [配对场景](specs/agent-tool-runtime/spec.md#scenario-相同业务输入通过两个入口获得一致判据), [现有回归](../../../platform/agent/bound_test.go#L15), [浏览器路由](../../../platform/workbench/server.go#L72), [确定性探针](../../../platform/runtime/workbench_dispatch.go#L259).
2. **委托树在 C 尚无决定时缺少实际逐跳金额.** A 域用链上锚点展示已登记的 `G0/G1/G2`, 只从 C 的决定证据补入 `maxAmountMinor`. 因此, 已签发但仍等待派单或在 C 定案之前停止的任务, 委托树可显示来源, 期限和深度, 缺少已签发额度. 建议从已验证的签发材料或交付回执投影对应跳的金额, 并补一条尚无 C 决定的运行证据回归. [场景要求](specs/domain-web-workbench/spec.md#scenario-从采购任务追踪真实业务事实), [委托树投影](../../../platform/runtime/workbench_evidence.go#L54), [链上锚点投影](../../../platform/gateway/workbench.go#L147).
3. **待处理队列可能长期跳过部分运行.** A 和 B 每轮按固定顺序获取前 50 项 `PENDING` 或 `OUTCOME_UNKNOWN`. 当前 50 项持续等待外部结果时, 同一批记录反复入选, 其余已接受运行在重启后也可能一直得不到推进. 建议以持久化的下次处理时间和稳定的并列排序调度, 并用超过 50 项且含长期等待核账记录的回归验证后续运行仍会推进. [持久化恢复设计](design.md#3-区分交互草稿与已确认执行), [A 域轮询](../../../platform/workbench/procurement.go#L566), [B 域轮询](../../../platform/runtime/workbench_dispatch.go#L69).

## 需求与证据

| 新增要求 | 场景数 | 实现与验证 |
| --- | --- | --- |
| Web 与 MCP 共用确定性业务操作 | 1 | `platform/agent/bound.go:41` 提供阶段化工具与共享操作. `platform/agent/bound_test.go:15` 核对绑定错误, 工具清单和重复建单. `platform/cmd/ledgerctl/main_test.go:221` 覆盖既有 stdio. HTTP 配对场景部分未核实. |
| 工作台派单绑定各域智能体身份与当前任务 | 2 | `platform/runtime/workbench_flow.go:318` 绑定 A1 与 G1, `platform/runtime/workbench_flow.go:520` 核对派单与 G2, `platform/runtime/workbench_dispatch.go:124` 绑定 B1. `platform/agent/bound_test.go:33` 覆盖主体, 任务, 模式, 委托及收件者参数. `platform/runtime/workbench_grants_db_test.go:273` 核对原交付回执, 到期读取和轨迹. 真实 A1/B1 调用见 RP 和 BM 运行记录. |
| 三域复用独立构建的前后端 | 1 | `infra/workbench/compose.yaml:1`, `infra/workbench/backend.Dockerfile:1`, `web/Dockerfile:1` 和 `web/Caddyfile:8` 对应独立构建和同源代理. 本轮构建两个镜像, 校验三域 Compose 配置, 读取在运行的相同镜像标识和 HTTPS 就绪响应. |
| 浏览器会话绑定可信域身份和权限 | 2 | `platform/workbench/session.go:268` 核对域, 角色和 CSRF, `platform/workbench/management.go:53` 复用原管理操作. `platform/workbench/server_db_test.go:33` 与实机管理日志覆盖三域管理, 重试, 越权及退出. |
| 采购员确认结构化任务后派发智能体 | 1 | `platform/workbench/procurement.go:286` 对版本加锁并持久化运行, `platform/runtime/workbench_flow.go:80` 按已确认任务推进. `platform/workbench/procurement_db_test.go:109` 覆盖旧版本, 未确认, 并发确认和重启恢复. RP/BM 网页证据分别追溯到 C 和 PA 的 G0. |
| 角色可见的采购与决策证据 | 1 | `platform/runtime/workbench_evidence.go:31`, `platform/gateway/workbench.go:86` 和 `web/app.js:497` 提供页面证据. `platform/gateway/gateway_db_test.go:1394` 与实机审计记录核对摘要和完整决定权限. 委托树逐跳金额仍受 C 决定记录是否存在的限制. |
| 浏览器复现两种根和动态状态变化 | 1 | 已核对同一隔离实例的网页, 管理交易, 模型轨迹, 网关原决定与主库. 本轮从 C 域主库只读确认唯一 800 元订单, 1200 元超额拒绝和采用第 507 块后的 `ANCESTOR_INACTIVE`. 签发, 暂停和恢复的 G1 截止一致, 恢复后询价成功. |

## 本轮验证

- `openspec validate m4-domain-web-workbench --strict`, 项目三模块无缓存单测, `mise run test:db`, `fabriclive` 标签编译, 前端 JavaScript 语法检查和导入边界检查均通过. 当前源码的前端和后端镜像分别构建成功.
- 使用各域导出的 CA 访问现有三域 HTTPS 入口, 均返回各自域 ID 和 `ready: true`. 三域前端镜像标识一致, 三域后端镜像标识一致. 现有实机记录同时覆盖干净部署, 重启和镜像凭据隔离. [部署烟雾记录](../../../infra/workbench/evidence/m4-domain-web-workbench/deployment-smoke.json), [干净部署与重启](../../../infra/workbench/evidence/m4-domain-web-workbench/clean-rerun.json).
- 浏览器登录, 真实模型及采购写操作的端到端结论采用已有隔离实机记录. 本轮在运行实例进行了只读核对, 当前源码的新镜像完成了构建检查. 主库两条 `AMOUNT_LIMIT_EXCEEDED` 分别对应早期 BM 负例和最终 BM 演示, 两次均无新增订单. [实机证据索引](../../../infra/workbench/evidence/m4-domain-web-workbench/README.md), [主库与交易对账](../../../infra/workbench/evidence/m4-domain-web-workbench/ledger-reconciliation.json).
