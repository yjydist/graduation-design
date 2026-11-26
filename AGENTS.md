# AGENTS.md

## 仓库结构与五层架构

| 路径 | 说明 |
| --- | --- |
| `README.md` | 仓库总入口, 指向毕设项目和论文实验. |
| `毕设要求.md` | 毕设任务要求, 需求编号与项目边界. |
| `TODO.md` | 项目进度, 交付与论文写作清单. |
| `go.work`, `go.work.sum` | Go 1.27 四模块工作区与校验和锁定. |
| `mise.toml` | 工具链版本和项目构建, 测试与部署命令. |
| `protocol/` | 独立 Go 模块 `grad/protocol`: 协议编解码, 密码学原语, 凭证/委托/证据包校验与链上登记共享类型. |
| `chaincode/` | 独立 Go 模块 `grad/chaincode`: Fabric 登记链码 `authregistry`. |
| `platform/` | 独立 Go 模块 `grad/platform`: 按五层架构组织的 `core/` (`ledger/`, `dao/`, `domain/`), `service/` (`api/`, `mcp/`), `agent/` (`llm/`, `orchestrator/`), `bootstrap/`, `cmd/` 与架构守卫 `arch_test.go`. |
| `web/` | A/B/C 共用的工作台前端与同源 HTTPS 代理镜像. |
| `experiments/` | 独立 Go 模块 `grad/experiments`: 论文实验方法, 统一 `exp` CLI, 底座, 驱动, 进度和证据. |
| `infra/` | 基础设施配置, Fabric 与工作台部署脚本及集成验收记录. |
| `docs/` | 项目设计书 (`DESIGN.md`, 含 R1-R5 需求追踪总表) 与实现契约 (`IMPLEMENTATION.md`). |
| `openspec/` | 工作流配置 (`config.yaml`), 已接受的能力规范 (`specs/`) 与变更制品及历史归档 (`changes/`). |
| `paper/` | 毕设论文 Markdown 单文件写作工作区 (`thesis.md`, `references.md`, `README.md`). |

目录结构只列直属文件和目录. 下一级细节由顶层模块的 `AGENTS.md` 维护 (`protocol/`, `chaincode/`, `platform/`, `web/`, `experiments/`, `infra/`), 其余子目录继承最近的父级指引.

平台系统遵循严格自顶向下的五层单向依赖架构 (各业务层并行共享零反向依赖的纯协议核 `grad/protocol`, 由 `platform/arch_test.go` 在测试期静态强制校验, 顶层装配统一收口于 `platform/bootstrap/`):

- **L5 应用层**: `web/` 工作台前端与极薄进程/CLI 入口 (`platform/cmd/workbench/`, `platform/cmd/ledgerctl/`).
- **L4 Agent 层**: `platform/agent/` (`llm/`, `orchestrator/`) 中的 LLM 客户端与任务编排智能体, 严格通过标准 MCP 协议调用 L3 工具, 严禁直接导入 L2 领域层, 私钥钱包, PostgreSQL 或 Fabric SDK.
- **L3 服务层**: `platform/service/` (`api/`, `mcp/`) 中的入站 REST/mTLS HTTP API 与标准 MCP 工具服务, 仅做编解码, 认证鉴权并调用 L2 领域逻辑, 不直连基础设施或反向导入 L4.
- **L2 逻辑封装层**: `platform/core/` (`ledger/`, `dao/`, `domain/`) 中的账本封装, 数据持久化访问与无 HTTP 耦合的深模块领域逻辑 (策略, 登记, 网关执行与核账, 隔离钱包, 采购编排状态与证据投影).
- **L1 基础设施层**: Hyperledger Fabric 通道网络 (Peer, SmartBFT Orderer, CCaaS `authregistry`) 与 PostgreSQL 17.9.

## 模块边界与常用命令

- 同仓四模块工作区采用严格单向依赖: `grad/protocol` 为纯协议基础模块 (子包 `grad/protocol/registry` 零第三方依赖), `grad/chaincode` 仅依赖 `grad/protocol/registry` 与 Fabric 链码运行时, `grad/platform` 单向依赖 `grad/protocol`, `grad/experiments` 仅调用 `grad/protocol` 与 `grad/platform` 的公开 API, 严禁导入 `grad/platform/internal/...` 或让项目模块反向依赖 `grad/experiments`.
- 项目维护协议与业务语义, 部署入口, 通用观测接口和行为回归. 实验侧维护实验场景, 比较配置, 编排, 采样, 分析, 实验配置及证据. 实验需要新增能力时, 先定义和独立验证可复用的项目接口, 再在实验侧接入.
- 项目任务从[仓库入口](README.md)进入相关设计, 实现契约和模块手册; 实验任务从[实验索引](experiments/README.md)定位方法, 用例和运行入口. 常用验证命令:
  - `mise run ledger:build`: 构建 `build/ledgerctl` 可执行文件.
  - `mise run test:unit`: 运行 `protocol`, `chaincode`, `platform` 三模块离线单元测试.
  - `mise run test:db`: 运行 `platform` PostgreSQL 集成测试 (`//go:build db`, 自动通过 `testcontainers-go` 启动 `postgres:17-alpine` 或读取 `TEST_POSTGRES_DSN`).
  - `mise run ledger:verify`: 在已启动的隔离实例 (`FABRIC_INSTANCE`) 上运行 Fabric 实机集成验收 (`//go:build fabriclive`).
  - `mise -C experiments run experiment:test`: 在仓库根目录运行实验模块测试.
  - 依赖边界检查: 用 `mise exec -- go list -deps -test grad/protocol/... grad/chaincode/... grad/platform/...` 核对无 `grad/experiments`, 并用 `mise exec -- go list -f '{{.Imports}} {{.TestImports}} {{.XTestImports}}' grad/experiments/...` 核对实验包及其测试的直接导入中无 `grad/platform/internal/`.

## 软件设计与工程准则

### 核心工程价值观

- **代码 "能跑" 远远不够 (Working code isn't enough)**: 严禁用临时拼凑 (kludge) 掩盖结构缺陷. 交付质量必须以可阅读, 易演进和易维护为第一标准.
- **战略性编程投资 (10%~20% 规则)**: 开发不是纯粹赶进度, 必须持续将精力主动投入到架构优化, 简化接口与补充抽象文档中, 把每次修改视作降低技术负债的长期投资.
- **架构保护业务价值 (Software is Soft)**: 软件的核心价值在于应对变化的可塑性. 保护高层业务策略的独立性远比迁就短期交付更为重要.

### 宏观架构与依赖规则

- **单向内向依赖原则 (The Dependency Rule)**: 结合本仓五层单向依赖架构与同心圆整洁架构边界 (Entities -> Use Cases -> Interface Adapters -> Frameworks & Drivers), 源代码依赖必须严格单向指向更内层, 更稳定的抽象; 内核绝不能提及外层的概念, 传输细节或具体实现类名.
- **业务与机制彻底解耦 (Independence of Mechanism)**: 核心业务逻辑 (协议核 `grad/protocol`, 实体规则与 L2 业务用例) 严禁直接依赖 UI 框架, 持久层数据库实现, RPC/HTTP 通信协议或第三方库. 所有底层机制必须作为外围插件 (Plugins), 通过接口依赖反转 (DIP) 被内核调用.
- **组件内聚与闭包原则 (Common Closure Principle - CCP)**: 将由于相同原因, 在相同时间发生变化的代码归入同一模块; 将因不同原因发生变动的逻辑彻底物理隔离.
- **稳定依赖与稳定抽象原则 (SDP & SAP)**: 依赖流向必须朝向更稳定的方向; 越是处于架构核心, 被大量依赖的组件, 其抽象程度应当越高 (通过纯抽象接口表达), 确保核心稳定且具备多态可扩展性.

### 模块化与深度设计

- **追求深模块, 抵制类膨胀 (Deep Modules vs. Classitis)**: 模块应当具备 "极简外部接口 + 强大内部实现". 警惕教条式将类, 类型和方法拆分得极小极浅, 大量浅模块不仅无法解耦, 反而会导致全系统认知负荷激增.
- **深度信息隐藏 (Information Hiding)**: 具体数据存储模型, 底层通信报文格式及算法实现细节必须完全封闭在模块内部. 严禁通过无节制的 Getter/Setter 或穿透性 DTO 泄露内核知识.
- **警惕时序分解 (Temporal Decomposition)**: 严禁仅因为执行先后次序就把依赖同一知识领域 (如某种特定文件格式, 协议解析或状态机规则) 的代码机械切分到不同类型或包中; 模块聚合的依据是 "所需的知识", 而非时序.

### 接口契约与分层交互

- **不同层级, 不同抽象 (Different Layer, Different Abstraction)**: 相邻层级若使用相似的抽象即为设计缺陷. 坚决消除不产生任何业务价值, 仅作转发的透传方法 (Pass-Through Methods).
- **下推复杂度 (Pull Complexity Downward)**: 模块接口的极简远比实现的简短更重要. 将边界情况, 默认容错策略和繁琐的生命周期机制收敛在模块内部, 绝不通过参数或配置将难题甩给上层调用方.
- **接口适度通用 (Somewhat General-Purpose)**: 底层核心模块的实现只需满足当前诉求, 但其接口设计应保持正交与通用语义, 严禁渗入上层业务专用的特定场景逻辑.
- **消除透传变量 (No Pass-Through Variables)**: 避免在长调用链路中机械式逐级透传全局状态或配置, 采用集中式的 Context 对象或依赖注入统一治理.

### 异常治理与防御机制

- **重新定义语义消灭异常 (Define Errors Out of Existence)**: 在设计阶段重新审视边界语义, 使常规流程自然覆盖边缘情况 (例如使删除不存在的对象成为幂等的无害操作, 而非抛出 `NotFound` 错误).
- **底层隐蔽与顶层聚合 (Masking & Aggregation)**: 底层能安全自愈的偶发故障 (如瞬时重试, 网络抖动) 应在模块内部静默解决, 不向外扩散; 无法就地处理的异常应由统一的顶层全局分发器 (Global Handler) 集中捕获与映射, 杜绝在每个业务调用处散落脆弱重复的错误处理或 try-catch.
- **致命错误果断崩溃 (Just Crash)**: 针对无法恢复的系统级损坏或内部断言失败, 立即输出诊断上下文并终止进程, 绝不进行无意义的伪恢复以防数据污染.
- **消除特殊分支**: 优化算法与数据模型, 使主逻辑天然兼容空集合, 极值和边界截断, 减少碎片化的 `if-else` 条件判断.

### 代码直观性与表达力

- **为阅读而设计 (Design for Reading)**: 代码被阅读的频率远高于编写. 禁止使用缺乏领域语义的通用元组 (如 Pair, Tuple) 返回复合数据, 必须构建具备显式命名字段的领域结构体.
- **精准且一致的命名**: 拒绝含义模糊的泛化词汇 (如 `data`, `status`, `temp`, `result`); 相同的业务概念在整个代码库中必须使用完全一致的术语与边界定义.
- **警惕重命名与抽象不匹配**: 如果无法用一两句准确简练的语言概括一个模块, 类型或函数的职责, 通常说明其抽象边界本身存在裂痕, 必须重新设计.

### 注释驱动设计

- **先写注释 (Write Comments First)**: 在具体编码前先编写接口注释以验证抽象的纯度和深度. 如果发现接口难以用精简语言阐明, 即代表设计失误, 应当立即推倒重构.
- **记录非显式知识**: 接口注释详述高层抽象职责, 前置条件, 后置状态, 并发语义及副作用; 实现注释阐明代码 "在做什么 (What)" 以及 "为什么这样做 (Why)", 严禁机械翻译代码字面逻辑 (How).
- **集中维护架构决策**: 针对跨越多个组件的系统级协议与设计决策, 在集中式设计文档 ([docs/DESIGN.md](docs/DESIGN.md), [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) 等 Design Notes) 进行单点维护, 避免散落注释产生信息漂移.

### 代码修改, 重构与演进

- **拒绝最小补丁心态**: 在既有代码库中新增功能或修复缺陷时, 不要只寻找成本最低的补丁方案. 必须思考 "如果系统最初就包含该需求, 其优雅架构应该长成什么样", 并主动将代码重构至该理想形态.
- **v1.0.0 前允许破坏性重构**: 在打上 `git tag v1.0.0` 之前, 允许破坏性重构, 不考虑任何历史兼容性, 一切选择最优设计. 涉及目录组织, 模块边界, 公开 API, 协议字节格式, REST 接口, 链码接口, 数据库表结构与 CLI 时, 优先追求高内聚, 低耦合, 深模块与严格五层单向依赖, 直接移除过时字段, 历史前缀, 上帝包与过渡适配层, 并同步更新契约与规范.
- **架构红旗自查清单 (Red Flags)**: 设计评审与代码变更前逐项核查, 命中即重构:
  - 浅模块 (Shallow Module): 接口复杂但内部功能微薄.
  - 信息泄漏 (Information Leakage): 同一设计决策或协议细节在多处重复出现.
  - 核心污染 (Core Contamination): 业务用例层直接导入了具体 UI, DB 或第三方驱动包.
  - 循环依赖 (Circular Dependencies): 组件间依赖图出现回环.
  - 职责模糊 (Hard to Name / Hard to Describe): 模块, 类型或方法难以命名, 说明职责混杂.

## 文档, OpenSpec 与论文规范

- **格式与标点**: 项目文档使用 Markdown (`.md`), 直接阅读和编辑, 不生成文档 PDF 或维护文档构建脚本; 不写文档版本号或创建/更新/修订日期等维护元信息 (论文版本, 依赖版本, 任务期限和实验时间等正文事实按需保留). 文档间使用相对链接指向 `.md` 源文件; 需要引用章节编号的标题显式保留编号并同步更新引用. 所有文档正文与代码统一使用 ASCII 半角标点 (顿号用半角逗号加空格替代, 句末用半角句号, 引号用半角双引号; 引用他人原文按原样保留并标注出处). 图形优先使用 Mermaid 源码 (`flowchart TB` 方向) 放在 `mermaid` 围栏代码块中.
- **内容边界**: 机制由 [docs/DESIGN.md](docs/DESIGN.md) 定义 (内置 R1-R5 需求追踪总表), 契约与测试向量由 [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) 维护, 仅在设计或契约变化时更新, 不记录阶段状态, 排期或运行日志, 不得链接 TODO, 变更任务, 核验记录, 证据索引或含进度内容的模块 README (任务和核验记录可引用 `docs/`). `README.md` 维护阅读与运行入口, `TODO.md` 与 `experiments/TODO.md` 维护进度与退出条件; 运行时证据目录保留历史原始材料和失败样本.
- **OpenSpec 工作流**: 项目契约或实验规范变化时走 OpenSpec. 所有 OpenSpec 制品与 `openspec-verify-change` 检验报告必须使用简体中文和 ASCII 标点符号. 活动变更制品随规划, 实施和核验更新, `openspec/changes/archive/` 历史归档保留当时的任务与结论, 不随当前进度改写.
- **论文工作区与原创要求**: `paper/` 仅保留单文件论文草稿 (`thesis.md`), 稳定编号的参考文献元信息表 (`references.md`) 与工作区入口 (`README.md`), 不在仓库内保存参考论文 PDF. 论文文字复制比必须小于等于 10%.
