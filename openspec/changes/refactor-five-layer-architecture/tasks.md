# Tasks

## 1. 建立五层架构红线测试与 L2 基础设施封装 (`core/dao` 与 `core/ledger`)

- [ ] 1.1 在 `platform/arch_test.go` 编写基于 `go/parser` 的五层单向导入红线测试, 定义 L2 (`core/ledger`, `core/dao`, `core/domain`), L3 (`service/api`, `service/mcp`), L4 (`agent`), `bootstrap` 与 `cmd` 的允许与禁止导入规则, 确认测试框架可独立编译执行.
- [ ] 1.2 建立 `platform/core/dao/` (迁移原 `migrations/`, `state/central/` 及各业务表的 PostgreSQL 持久化与显式事务封装 `Tx`), 保留全量数据库迁移与单元测试并验证 `go test -tags=db -race ./core/dao/...` 通过.
- [ ] 1.3 建立 `platform/core/ledger/` (迁移原 `state/` 契约与 `state/fabric/` 的链码封装, Deliver 块流, 固定高度视图, 原探针与原交易日志), 迁移单测与 `fabriclive` 编译验证 (`go test -race ./core/ledger/...` 与 `go test -tags=fabriclive -c -o /dev/null ./core/ledger`).

## 2. 拆分 L2 深模块领域层 (`core/domain`)

- [ ] 2.1 建立 `platform/core/domain/policy/` (迁移原 `policy/` OPA 策略包校验与求值) 与 `platform/core/domain/registry/` (剥离原 `registrysvc/` 中的身份双证明, 管理操作受理/投影与受控交付领域逻辑, 不含 `net/http` 路由), 验证对应单测与数据库集成测试通过.
- [ ] 2.2 建立 `platform/core/domain/gateway/` (剥离原 `gateway/` 的挑战管理, 锁后固定高度复核执行核与未知订单核账领域逻辑, 通过 `core/dao` 事务保持原行锁顺序) 与 `platform/core/domain/wallet/` (从原 `agent/` 剥离隔离密钥钱包, `client_actions` 意图锁, `BoundOperations` 与出站网关 HTTP 客户端), 验证对应单测与数据库集成测试通过.
- [ ] 2.3 建立 `platform/core/domain/procurement/` 与 `platform/core/domain/evidence/` (从原 `workbench/` 与 `runtime/` 剥离采购草稿, 确认状态机, 域间执行协调与五类证据投影逻辑, 消除回调倒置), 验证对应单测与数据库集成测试通过.

## 3. 拆分 L3 服务层 (`service/api` 与 `service/mcp`) 与 L4 Agent 层 (`agent`)

- [ ] 3.1 建立 `platform/service/api/` (`gateway`, `registry`, `workbench`, `interdomain` 四个 HTTP 服务集, 复用 `internal/httpx` 与 `internal/mtls`, 仅调用 `core/domain`, 保留嵌入的 `openapi.json`), 验证 HTTP 路由, CSRF, 会话权限与 OpenAPI 响应契约测试全部通过.
- [ ] 3.2 建立 `platform/service/mcp/` (将原 `agent/tools.go` 注册的 6 个 MCP 工具与阶段受限工作台工具集迁入 L3, 仅调用 `core/domain/wallet`), 验证进程内与 stdio MCP `tools/list` 和 `tools/call` 回归通过.
- [ ] 3.3 重建 `platform/agent/` 为纯 L4 层 (`agent/llm/` 双协议官方 SDK 与 `agent/orchestrator/` 草稿对话, A1 转委托与 B1/B2 采购核账编排), 强制所有工具调用仅经标准 MCP 会话执行且零 `core/` 导入, 验证离线双协议模型与 MCP 编排测试通过.

## 4. 替换上帝包 `runtime/`, 适配入口, 实验模块与文档

- [ ] 4.1 建立薄装配层 `platform/bootstrap/` (纯 DI 装配与测试/演示协议夹具 `fixture`, 零业务逻辑), 更新 `platform/cmd/workbench` 与 `platform/cmd/ledgerctl`, 彻底删除旧 `platform/runtime/`, `platform/state/`, `platform/policy/`, `platform/registrysvc/`, `platform/gateway/`, `platform/workbench/` 目录.
- [ ] 4.2 更新 `experiments/` 中所有对 `grad/platform` 公开 API 的导入路径, `mise.toml` 测试目标与 `infra/workbench/backend.Dockerfile`, 验证 `mise run ledger:build`, `mise -C experiments run experiment:test` 与后端镜像构建通过.
- [ ] 4.3 更新 `platform/AGENTS.md`, `docs/IMPLEMENTATION.md` 与根 `AGENTS.md` 中的目录表与分层说明, 核对描述与实际包结构完全一致.

## 5. 全量分层红线与端到端集成验收

- [ ] 5.1 运行全量无缓存离线单测 (`go test -race -count=1` 含 `platform/arch_test.go`), 全量 PostgreSQL 集成测试 (`mise run test:db`), 四模块依赖边界 `go list` 检查以及脱离工作区 (`GOWORK=off`) 的四模块只读解析与单测, 确认全部零失败.
- [ ] 5.2 在新建隔离 Fabric 实例上运行 `ledger:deploy`, `ledger:seed`, `ledger:check` 与 `ledger:verify` (`//go:build fabriclive`) 全栈实机验收, 确认链上登记, 网关执行, 核账与 MCP stdio 全部通过.

## Workflow follow-up

- 完成核验并归档本变更后, 核对最终 `openapi.json` 并进入 `rebuild-workbench-web-ui` 实施.
