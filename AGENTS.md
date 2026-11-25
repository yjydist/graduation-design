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
| `platform/` | 独立 Go 模块 `grad/platform`: 状态源, OPA 策略, 管理服务, 网关, 智能体钱包, 工作台后端与 `ledgerctl` CLI. |
| `web/` | A/B/C 共用的工作台前端与同源 HTTPS 代理镜像. |
| `experiments/` | 独立 Go 模块 `grad/experiments`: 论文实验方法, 统一 `exp` CLI, 底座, 驱动, 进度和证据. |
| `infra/` | 基础设施配置, Fabric 与工作台部署脚本及集成验收记录. |
| `docs/` | 项目设计书 (`DESIGN.md`, 含 R1-R5 需求追踪总表) 与实现契约 (`IMPLEMENTATION.md`). |
| `openspec/` | 工作流配置 (`config.yaml`), 已接受的能力规范 (`specs/`) 与变更制品及历史归档 (`changes/`). |
| `paper/` | 毕设论文 Markdown 单文件写作工作区 (`thesis.md`, `references.md`, `README.md`). |

目录结构只列直属文件和目录. 下一级细节由顶层模块的 `AGENTS.md` 维护 (`protocol/`, `chaincode/`, `platform/`, `web/`, `experiments/`, `infra/`), 其余子目录继承最近的父级指引.

平台系统遵循严格自顶向下的五层单向依赖架构 (各业务层并行共享零反向依赖的纯协议核 `grad/protocol`):

- **L5 应用层**: `web/` 工作台前端与极薄进程/CLI 入口 (`workbench`, `ledgerctl`).
- **L4 Agent 层**: LLM 客户端与任务编排智能体, 严格通过标准 MCP 协议调用 L3 工具, 严禁直接导入 L2 领域层, 私钥钱包, PostgreSQL 或 Fabric SDK.
- **L3 服务层**: 入站 REST/mTLS HTTP API 与标准 MCP 工具服务, 仅做编解码, 认证鉴权并调用 L2 领域逻辑, 不直连基础设施或反向导入 L4.
- **L2 逻辑封装层**: 账本封装, 数据持久化访问与无 HTTP 耦合的深模块领域逻辑 (策略, 登记, 网关执行与核账, 隔离钱包, 采购编排状态与证据投影).
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

## 工程重构与架构准则

- 在打上 `git tag v1.0.0` 之前, 允许破坏性重构, 不考虑任何历史兼容性, 一切选择最优设计.
- 涉及目录组织, 模块边界, 公开 API, 协议字节格式, REST 接口, 链码接口, 数据库表结构与 CLI 时, 优先追求高内聚, 低耦合, 深模块与严格五层单向依赖, 直接移除过时字段, 历史前缀, 上帝包与过渡适配层, 并同步更新契约与规范.

## 文档, OpenSpec 与论文规范

- **格式与标点**: 项目文档使用 Markdown (`.md`), 直接阅读和编辑, 不生成文档 PDF 或维护文档构建脚本; 不写文档版本号或创建/更新/修订日期等维护元信息 (论文版本, 依赖版本, 任务期限和实验时间等正文事实按需保留). 文档间使用相对链接指向 `.md` 源文件; 需要引用章节编号的标题显式保留编号并同步更新引用. 所有文档正文与代码统一使用 ASCII 半角标点 (顿号用半角逗号加空格替代, 句末用半角句号, 引号用半角双引号; 引用他人原文按原样保留并标注出处). 图形优先使用 Mermaid 源码 (`flowchart TB` 方向) 放在 `mermaid` 围栏代码块中.
- **内容边界**: 机制由 [docs/DESIGN.md](docs/DESIGN.md) 定义 (内置 R1-R5 需求追踪总表), 契约与测试向量由 [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) 维护, 仅在设计或契约变化时更新, 不记录阶段状态, 排期或运行日志, 不得链接 TODO, 变更任务, 核验记录, 证据索引或含进度内容的模块 README (任务和核验记录可引用 `docs/`). `README.md` 维护阅读与运行入口, `TODO.md` 与 `experiments/TODO.md` 维护进度与退出条件; 运行时证据目录保留历史原始材料和失败样本.
- **OpenSpec 工作流**: 项目契约或实验规范变化时走 OpenSpec. 所有 OpenSpec 制品与 `openspec-verify-change` 检验报告必须使用简体中文和 ASCII 标点符号. 活动变更制品随规划, 实施和核验更新, `openspec/changes/archive/` 历史归档保留当时的任务与结论, 不随当前进度改写.
- **论文工作区与原创要求**: `paper/` 仅保留单文件论文草稿 (`thesis.md`), 稳定编号的参考文献元信息表 (`references.md`) 与工作区入口 (`README.md`), 不在仓库内保存参考论文 PDF. 论文文字复制比必须小于等于 10%.
