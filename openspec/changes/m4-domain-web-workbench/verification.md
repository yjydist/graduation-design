# m4-domain-web-workbench 核验报告

## 三项警告的修复复核

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
