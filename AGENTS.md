# AGENTS.md

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `README.md` | 仓库总入口, 指向毕设项目和论文实验. |
| `毕设要求.md` | 毕设任务要求, 需求编号与项目边界. |
| `TODO.md` | 项目进度, 交付与论文写作清单. |
| `go.work`, `go.work.sum` | Go 1.27 四模块工作区与校验和锁定. |
| `mise.toml` | 工具链版本和项目构建, 测试与部署命令. |
| `protocol/` | 独立 Go 模块 `grad/protocol`: 协议编解码, 密码学原语, 凭证/委托/证据包校验与链上登记共享类型. |
| `chaincode/` | 独立 Go 模块 `grad/chaincode`: Fabric 登记链码 `authregistry`. |
| `platform/` | 独立 Go 模块 `grad/platform`: 状态源, OPA 策略, 管理服务, 网关, 智能体钱包, 运行时装配与 `ledgerctl` CLI. |
| `web/` | A/B/C 共用的工作台前端与同源 HTTPS 代理镜像. |
| `experiments/` | 独立 Go 模块 `grad/experiments`: 论文实验方法, 统一 `exp` CLI, 底座, 驱动, 进度和证据. |
| `infra/` | 基础设施配置与 Fabric 网络脚本及集成验收记录. |
| `docs/` | 项目设计, 需求追踪及实现契约. |
| `openspec/` | 工作流配置 (`config.yaml`), 已接受的能力规范 (`specs/`) 与变更制品及历史归档 (`changes/`). |
| `paper/` | 原始论文 PDF 和阅读笔记. |

目录结构只列直属文件和目录. 下一级细节由顶层模块的 `AGENTS.md` 维护 (`protocol/`, `chaincode/`, `platform/`, `experiments/`, `docs/`, `infra/`), 其余子目录继承最近的父级指引.

## 项目与实验边界

- 同仓四模块工作区采用严格单向依赖: `grad/protocol` 为纯协议基础模块 (子包 `grad/protocol/registry` 零第三方依赖), `grad/chaincode` 仅依赖 `grad/protocol/registry` 与 Fabric 链码运行时, `grad/platform` 单向依赖 `grad/protocol`, `grad/experiments` 仅调用 `grad/protocol` 与 `grad/platform` 的公开 API, 严禁导入 `grad/platform/internal/...` 或让项目模块反向依赖 `grad/experiments`.
- 项目维护协议与业务语义, 部署入口, 通用观测接口和行为回归. 实验侧维护实验场景, 比较配置, 编排, 采样, 分析, 实验配置及证据. 实验需要新增能力时, 先定义和独立验证可复用的项目接口, 再在实验侧接入.
- 项目任务从[仓库入口](README.md)进入相关设计, 实现契约和模块手册. 常用验证命令:
  - `mise run ledger:build`: 构建 `build/ledgerctl` 可执行文件.
  - `mise run test:unit`: 运行 `protocol`, `chaincode`, `platform` 三模块离线单元测试.
  - `mise run test:db`: 运行 `platform` PostgreSQL 集成测试 (`//go:build db`, 自动通过 `testcontainers-go` 启动 `postgres:17-alpine` 或读取 `TEST_POSTGRES_DSN`).
  - `mise run ledger:verify`: 在已启动的隔离实例 (`FABRIC_INSTANCE`) 上运行 Fabric 实机集成验收 (`//go:build fabriclive`).
  - 依赖边界用 `mise exec -- go list -deps -test grad/protocol/... grad/chaincode/... grad/platform/...` 核对无 `grad/experiments`, 并用 `mise exec -- go list -f '{{.Imports}} {{.TestImports}} {{.XTestImports}}' grad/experiments/...` 核对实验包及其测试的直接导入中无 `grad/platform/internal/`.
- 实验任务从[实验索引](experiments/README.md)定位方法, 用例和运行入口. 在仓库根目录用 `mise -C experiments run experiment:test` 验证实验模块, 其他实验命令见对应运行说明.

## 项目原则

### 演进与重构

- 在打上 `git tag v1.0.0` 之前, 允许破坏性重构, 不考虑任何历史兼容性, 一切选择最优设计.
- 涉及目录组织, 模块边界, 公开 API, 协议字节格式, REST 接口, 链码接口, 数据库表结构与 CLI 时, 优先追求高内聚, 低耦合与深模块, 直接移除过时字段, 历史前缀与过渡适配层, 并同步更新契约与规范.

### 文档格式

- 项目文档使用 Markdown (`.md`), 直接阅读和编辑, 不生成文档 PDF.
- Markdown 不写文档版本号或创建, 更新, 修订日期等维护元信息. 论文版本, 依赖版本, 任务期限和实验时间等正文事实按需保留.
- 文档之间使用相对链接, 指向 `.md` 源文件. 原始论文 PDF 和任务书保留为来源材料.
- 不维护文档构建流程, Makefile 或自动检查脚本.
- 标题使用 Markdown 标题语法, 表格使用 Markdown 表格, 代码示例使用带语言标识的围栏代码块.
- 需要引用章节编号的文档在标题中显式保留编号, 修改章节结构时同步更新引用.

### 标点

- 所有文档的正文与代码使用 ASCII 半角标点.
- 顿号用半角逗号加空格替代, 句末用半角句号, 引号用半角双引号.
- 例外: 引用他人原文时按原样保留, 并在上下文中标注出处.

### 图形

- 图形优先使用 Mermaid 源码, 放在 `mermaid` 围栏代码块中, 避免纯文本字符画.
- 流程图 (flowchart) 使用 `TB` 方向.
- 保留可直接复制到 GitHub, GitLab 或支持 Mermaid 的 Markdown 编辑器中的源码.

### 内容维护

- 机制由设计主题文档定义. 变更时同步核对实现规格, 项目回归和技术栈. 项目需求到实现的追踪集中在[项目文档导航](docs/AGENTS.md#从任务书到实现), 实验侧维护研究问题到用例和结果的追踪.
- `docs/` 正文和导航只在设计或契约变化时更新, 不记录阶段状态, 排期, 单次运行结果或复跑记录. 可引用其他设计资料, 任务书, 论文和技术规范, 不得链接 TODO, 变更实施任务, 核验记录, 证据索引或含进度内容的模块 README. 任务和核验记录可以引用 `docs/`.
- README 维护阅读和运行入口. 根 TODO 维护项目状态及交付, 实验 TODO 维护实验阶段, 下一步和退出条件. 任务应引用适用的契约, 核验结论和证据. 复用这些入口管理进度.
- OpenSpec 主规范在能力要求变化时按工作流更新. 修改规范前查阅现有契约和活动变更; 活动变更制品随规划, 实施和核验更新, 历史归档保留当时的任务与结论, 不随当前进度改写.
- 既有模块 README 维护运行命令及前置条件, 在运行方式变化时更新. 证据目录在运行时保存实例配置, 原始数据, 实际结果及失败样本, 由证据索引和变更核验记录定位; 保留历史原始材料和失败记录.
- 文献编号保持稳定, 下载与阅读是不同状态. 原始论文 PDF 不因文档格式调整而删除或改写.

### OpenSpec 工作流

- 项目契约或实验规范发生变化时走 OpenSpec. 目录和入口维护沿用已接受的契约和规范.
- OpenSpec 的所有制品 (artifacts) 使用简体中文作为自然语言, 且只能使用 ASCII 标点符号.
- `openspec-verify-change` 的检验报告使用简体中文作为自然语言, 且只能使用 ASCII 标点符号.

## 论文原则

- 文字复制比小于等于 10%
