# 提案: 重建 Go Workspace Monorepo 与深模块架构

## Why

当前仓库在单 Go 模块内演进出了约 5.3 万行代码, 存在严重的结构性耦合与维护负担: `internal/fabric` 膨胀为包含 40 个文件, 混杂五类职责并反向依赖 `agent`/`gateway` 的上帝包; `experiments/` 直接依赖 7 个 `internal/*` 包导致项目与实验边界仅靠约定维系; `chaincode/registry` 与 CLI, LLM SDK 及实验工具共享同一个 `go.mod`; 同时存在大量手写 JSON/JCS, JWS/JWK, SQL 扫描, 散落 DDL 与历史兼容补丁 (`D0:` 前缀, `m2TaskSpec`, 资源名多别名等). 在打上 `v1.0.0` 标签之前, 按 `AGENTS.md` 的破坏性重构原则一次性重建为 4-Module Go Workspace 架构与深模块分层, 可显著降低代码量, 以编译器强制边界并方便各层独立测试.

## What Changes

- **BREAKING** 改造仓库为 4-Module Go Workspace (`go.work`):
  - `protocol/` (`grad/protocol`): 纯 Go 协议与领域核心, 含零第三方依赖的 `protocol/registry` 共享模型与统一错误码, 取代原 `internal/fabricapi` 与 `internal/protocol`.
  - `chaincode/` (`grad/chaincode`): 独立 Fabric 登记链码模块, 仅依赖 `fabric-chaincode-go/v2` 与 `grad/protocol`, 拆分为 `main.go`, `domain.go`, `identity.go`, `grant.go`.
  - `platform/` (`grad/platform`): 单向分层平台深模块 (`policy`, `state/{central,fabric}`, `registrysvc`, `gateway`, `agent`, `runtime`, `migrations`, `internal/{httpx,mtls,testutil}`, `cmd/ledgerctl`).
  - `experiments/` (`grad/experiments`): 独立实验模块, 编译器强制仅依赖 `grad/protocol` 与 `grad/platform` 公开 API, 统一 Cobra CLI (`cmd/exp`) 与共用底座 (`harness`).
- **BREAKING** 消灭依赖倒挂与浅层碎片:
  - 将 `StateSource` / `HistoricalStateSource` 抽入 `platform/state`, 解除 `fabric`/`centralstate` 对 `gateway` 的反向依赖.
  - 将 `mcp.go` 与 `seed.go` 升格并精简重构至顶层 `platform/runtime`, 使 `platform/state/fabric` 回归纯粹的 Fabric 基础设施 (5 个核心文件).
  - 将管理操作 HTTP 服务, 注册/恢复双证明及材料受控交付从 `fabric` 抽离为独立深模块 `platform/registrysvc`.
  - 将 `client_actions` 持久化归位至 `platform/agent`, 斩断 `agent -> gateway` 数据库层耦合.
  - 吸收微包 (`centralstate` 入 `state/central`, `serviceauth` 入 `platform/internal/mtls`), 合并过碎文件, 保留 CLI 名称 `ledgerctl`.
- **BREAKING** 清理协议, 链码, REST 与数据库历史包袱:
  - 链码移除 `"D0:"` 历史错误前缀, 与 `protocol/registry` 共用唯一规范错误码表; 合并重复的 `IssuerScope` / `Scope` 结构体.
  - 网关收敛资源标识为唯一规范 URI (`urn:grad:resource:C:quotes` 与 `urn:grad:resource:C:orders`), 移除 `"quotes"` / `"urn:grad:resource:quotes"` 历史别名; 统一 Gateway 与 RegistrySvc 的 REST 错误信封格式.
  - 夹具与序列化移除 `"m2TaskSpec"` 与 `"synthetic"` 等历史遗留字段.
- 引入成熟库与 Go 1.27 标准库大幅缩减手写代码:
  - Go 1.27 `encoding/json/jsontext` 替代 931 行手写 `jcs.go`; `github.com/go-jose/v4` + Go 1.27 `crypto/ecdsa` 收敛 ES256 JWS/JWK 与公钥校验.
  - `pgx.CollectRows` / `pgx.RowToStructByName` + `github.com/pressly/goose/v3` 嵌入迁移替代散落 DDL 与手写 `row.Scan`.
  - 统一 `github.com/spf13/cobra` 管理 `ledgerctl` 与实验 CLI `exp`; `testcontainers-go/modules/postgres` + `stretchr/testify` + Go build tags 建立三层隔离测试; `google/renameio/v2` 与 `jszwec/csvutil` 收敛原子写入与实验 CSV.
- **BREAKING** 清理重构前的历史实验运行产物 (`experiments/e1/{runs,analysis,source-archive}`, `experiments/e6/{runs,analysis}`, 旧试跑残留与根目录 `./ledgerctl`), 精简过度碎片化的叶子目录 `AGENTS.md`, 重构完成后在新架构上重新运行正式实验.

## Capabilities

### New Capabilities

无. 本次重构保持论文核心安全与协议能力集合不变, 对受架构与接口优化影响的既有能力通过下方修改规范同步契约.

### Modified Capabilities

- `verifiable-protocol`: 统一协议与登记错误码表, 合并重复结构体定义, 明确采用规范资源 URI 及 Go 1.27 `jsontext` / `go-jose/v4` 后的规范编码与向量复算边界.
- `authorization-registry`: 移除链码错误响应 `"D0:"` 历史前缀改用规范错误码, 统一管理服务 REST 错误信封, 移除夹具中的 `synthetic` 与 `m2TaskSpec` 遗留字段.
- `direct-access-gateway`: 收敛访问请求的资源标识为唯一规范 URI, 统一网关 REST 错误信封, 明确 `client_actions` 持久化归属迁移至智能体侧而非网关表集合.
- `agent-tool-runtime`: 明确 `client_actions` 意图锁由 `agent` 模块独立持有并经 HTTP/Handler 边界调用网关, `ledgerctl mcp` 由顶层 `runtime` 装配.
- `reproducible-procurement-experiments`: 明确实验侧作为独立 Go Workspace 模块通过公开 API/CLI/HTTP/MCP 调用平台, 统一 `exp` CLI 入口并面向新架构产出全新独立运行记录, 不再维护重构前旧运行目录兼容.

## Impact

- **代码与模块**: 重组全部 Go 源码至 `protocol/`, `chaincode/`, `platform/`, `experiments/`, 新增根 `go.work`, 删除根旧 `go.mod`/`go.sum`, `cmd/`, `internal/` 及残留 `./ledgerctl`.
- **依赖**: 引入 `go-jose/v4`, `goose/v3`, `cobra`, `testcontainers-go`, `testify`, `renameio/v2`, `csvutil`; `chaincode/go.mod` 与 `protocol/go.mod` 保持最小依赖面.
- **数据库与部署**: 按领域重组 `goose` SQL 迁移; 链码构建命令与摘要范围调整为 `chaincode/` + `protocol/registry/`, `mise.toml` 与 `infra/fabric/` 脚本同步适配.
- **文档与证据**: 同步更新 `AGENTS.md`, `README.md`, `docs/implementation/` 与 `experiments/` 方法/索引文档, 清理旧实验运行目录以便重构后重跑正式实验.
