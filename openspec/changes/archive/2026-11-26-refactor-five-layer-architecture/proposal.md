# Proposal

## Why

当前 `platform/` 的包组织未落实"五层单向依赖, 高内聚低耦合深模块"架构: `platform/agent` 混杂了 L2 钱包与数据库访问, L3 MCP Server 与 L4 LLM 推理; `platform/runtime` 膨胀为超过 5500 行的上帝包, 吞并了 L2/L3/L4 逻辑并通过回调钩子与 `platform/workbench` 形成倒置依赖; `gateway` 与 `registrysvc` 同时混写 HTTP 路由, 领域逻辑与 SQL 事务. 趁尚未打上 `v1.0.0` 标签且允许破坏性重构, 需在正式运行 E1-E8 论文实验前彻底重构 `platform/` 分层与目录结构.

## What Changes

- **BREAKING**: 保留 4 个 Go 工作区模块 (`protocol`, `chaincode`, `platform`, `experiments`), 在 `platform/` 内按五层架构彻底重组目录为 `core/` (L2 逻辑封装层: `ledger/`, `dao/`, `domain/`), `service/` (L3 服务层: `api/`, `mcp/`), `agent/` (L4 Agent 层: `llm/`, `orchestrator/`), `bootstrap/` (薄 DI 装配层) 与 `cmd/` (L5 CLI/服务入口).
- **BREAKING**: 删除旧 `platform/runtime/`, `platform/state/`, `platform/policy/`, `platform/registrysvc/`, `platform/gateway/`, `platform/workbench/` 与混杂的旧 `platform/agent/` 包, 零保留过渡适配层或兼容别名.
- 落实单域单二进制部署下的严格包级隔离: L4 (`platform/agent/...`) 仅通过标准 MCP 协议 (`mcp.NewInMemoryTransports()` 或 stdio) 调用 L3 (`platform/service/mcp`), 禁止直接导入 L2 (`platform/core/...`), `pgxpool` 或 `fabric-gateway`; L3 (`platform/service/...`) 仅调用 L2 (`platform/core/domain/...`), 禁止直连基础设施或反向导入 L4.
- 新增 `platform/arch_test.go`, 基于 Go AST 在 `go test` 中自动校验五层单向导入红线, 任何越层依赖直接导致构建与测试失败.
- 同步更新 `experiments/` 对 `grad/platform` 公开 API 的导入路径, `infra/workbench/backend.Dockerfile`, `mise.toml`, `platform/AGENTS.md` 以及 `docs/IMPLEMENTATION.md` 中的架构与目录章节.

## Capabilities

### New Capabilities

无.

### Modified Capabilities

- `agent-tool-runtime`: 强化 L2 确定性钱包领域核, L3 MCP 工具服务与 L4 Agent 推理编排的单向分层契约, 明确 L4 仅通过标准 MCP 传输访问 L3 工具且在编译与测试期隔离 L2 及基础设施依赖.

## Impact

- 依赖前序变更: 建议在 `consolidate-docs-and-paper-workspace` 归档后实施, 并在 `rebuild-workbench-web-ui` 之前完成归档.
- 影响代码: `platform/` 全量包重组, `experiments/` 公开 API 导入适配, `mise.toml`, `infra/workbench/backend.Dockerfile`, `platform/AGENTS.md`, `docs/IMPLEMENTATION.md`.
- 保持对外行为, 协议字节编码 (`grad/protocol`), 链码 (`grad/chaincode`) 与浏览器 OpenAPI `/api/v1` 语义兼容测试全绿; 完整回归覆盖单测, PostgreSQL 集成测试, `arch_test.go`, 实验模块测试与隔离 Fabric 实机验收.
