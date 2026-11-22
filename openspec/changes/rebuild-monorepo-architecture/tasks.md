# 重构实施任务清单

## 1. 工作区脚手架与基线清理

- [x] 1.1 清理根目录残留二进制 `./ledgerctl` 与重构前旧实验运行目录 (`experiments/e1/{runs,analysis,source-archive}`, `experiments/e6/{runs,analysis}`), 检查 `.gitignore` 防止编译产物入库. 验证: `git status` 确认待清理产物已移除且保留 `experiments/llm.env` 与历史归档文档.
- [x] 1.2 创建根 `go.work` 以及 `protocol/go.mod` (`grad/protocol`), `chaincode/go.mod` (`grad/chaincode`), `platform/go.mod` (`grad/platform`), `experiments/go.mod` (`grad/experiments`) 四个独立模块定义, 并按需锁定成熟依赖 (`go-jose/v4`, `goose/v3`, `cobra`, `testcontainers-go`, `testify`, `renameio/v2`, `csvutil`). 验证: `go work sync` 与 `go list -m all` 在各模块正常解析且 `chaincode/go.mod` 不包含 `pgx`, `opa`, `mcp`, `openai`, `anthropic` 或 `cobra`.

## 2. 构建 `protocol` 模块 (`grad/protocol`)

- [x] 2.1 在 `protocol/registry/` 下建立共享领域模型 (`types.go`, `errors.go`, `validate.go`), 统一协议与链码唯一错误码表, 移除 `"D0:"` 历史前缀并合并原 `fabricapi.Scope` 与 `protocol.IssuerScope`. 验证: `cd protocol && go test ./registry/...` 通过且 `go list -f '{{.Imports}}' ./registry` 仅依赖 Go 标准库.
- [x] 2.2 在 `protocol/codec.go` 与 `protocol/crypto.go` 中以 Go 1.27 `encoding/json/jsontext` (`Value.Canonicalize()`) 重构严格 JSON/JCS 编解码, 以 `go-jose/v4` 与 Go 1.27 `crypto/ecdsa` 重构 ES256 JWS, JWK 与 RFC 7638 指纹校验, 收敛资源标识为唯一规范 URI (`urn:grad:resource:C:quotes` 与 `urn:grad:resource:C:orders`). 验证: 编写并运行覆盖 256 KiB, 深度, 重复键, 代理项, 安全整数边界, 历史资源别名拒绝及非法 `nonce` 的单元测试全部通过.
- [x] 2.3 迁移并精简 `didweb.go`, `credential.go`, `grant.go`, `request.go`, `evidence.go` 与 `contexts/vc-v2.json` 至 `protocol/`, 保持 SD-JWT 选择性披露, KB-JWT 持有者绑定, 委托链逐跳衰减与 B1 静态验签缓存语义, 同步更新 `docs/implementation/协议编码与测试向量.md` 与 `protocol/AGENTS.md`. 验证: `cd protocol && go test -v ./...` 全部通过并精确复算更新后的静态协议向量.

## 3. 构建独立 `chaincode` 模块 (`grad/chaincode`)

- [x] 3.1 将 `chaincode/registry/` 按领域拆分为 `main.go`, `domain.go`, `identity.go`, `grant.go`, 改为依赖 `grad/protocol/registry`, 移除 `"D0:"` 历史错误前缀直接返回规范错误码. 验证: `cd chaincode && go build ./registry` 成功且 `go list -deps ./registry` 不包含平台或实验包.
- [x] 3.2 更新并补充 `chaincode/registry/registry_test.go` (引入 `testify` 精简断言), 覆盖受限初始化, 域认证续发/收缩/撤销, 身份状态/轮换/恢复, 双域关联, 任务取消及委托暂停/恢复/撤销/原子替换, 同步更新 `chaincode/AGENTS.md`. 验证: `cd chaincode && go test -v ./...` 全部通过.

## 4. 构建 `platform` 基础层 (`migrations`, `internal`, `policy`, `state`)

- [x] 4.1 建立 `platform/migrations/` (`//go:embed` + `goose/v3`), 按领域拆分并整理 `001_fabric.sql`, `002_central.sql`, `003_registrysvc.sql`, `004_gateway.sql`, `005_agent.sql` 五组表结构迁移, 在 `platform/internal/` 下实现 `httpx` (统一 `{requestId, code, decisionId, message}` 错误信封与 JSON 读写), `mtls` (吸收原 `serviceauth`) 及 `testutil` (`testcontainers-go/modules/postgres` 单包共享容器 + 每测试独立库/schema 封装, 支持 `TEST_POSTGRES_DSN` 覆盖). 验证: `cd platform && go test ./internal/...` 与 `go test -tags=db ./migrations/...` 自动建库并全量迁移成功.
- [x] 4.2 迁移并精简 `platform/policy/` (`bundle.go`, `eval.go`), 保持 OPA Rego v1 策略包完整性校验, `trustRoots` 绑定与确定性求值. 验证: `cd platform && go test -v ./policy/...` 覆盖篡改策略, 替换根, `NORMAL`/`ELEVATED`/`BLOCKED` 与 `supplierAcceptance` 全部通过.
- [x] 4.3 建立 `platform/state/` 公共状态源接口 (`state.go`), 在 `platform/state/central/` 实现中心化 Postgres 快照源 (改用 `pgx` 原生行映射与 `goose` 迁移), 并在 `platform/state/fabric/` 将原 Fabric 基础设施瘦身为 5 个核心文件 (`instance.go`, `stream.go`, `view.go`, `probe.go`, `journal.go`), 彻底移除对 `agent`, `gateway`, `mcp` 与 `seed` 的反向依赖; 更新链码构建与源码摘要逻辑仅覆盖 `chaincode/` 与 `protocol/registry/`. 验证: `cd platform && go test ./state/...` 与 `go test -tags=db ./state/...` 通过, `go list -deps ./state/...` 确认零 `agent`/`gateway` 依赖.

## 5. 构建 `platform` 业务层 (`registrysvc`, `gateway`, `agent`, `runtime`, `cmd/ledgerctl`)

- [x] 5.1 实现 `platform/registrysvc/` (`operations.go`, `identity.go`, `delivery.go`), 承接原 `fabric` 中的管理操作 HTTP 受理与状态查询, 注册/恢复双证明及材料受控发件箱交付, 统一采用 `httpx` 错误信封与 `pgx.CollectRows`/`RowToStructByName`. 验证: `cd platform && go test -tags=db -v ./registrysvc/...` 覆盖 `202`/`409 STATE_CHANGED`/`409 IDEMPOTENCY_CONFLICT`, 注册/恢复双证明与材料交付去重全部通过.
- [x] 5.2 重构 `platform/gateway/` (`server.go`, `challenge.go`, `execute.go`, `audit.go`), 使用 Go 1.22+ `http.ServeMux` 与 `httpx`, 仅接受规范资源 URI (`urn:grad:resource:C:quotes` 与 `urn:grad:resource:C:orders`), 依赖 `state.StateSource` 与 `pgx` 行映射, 移除原 `client_actions.go` 与历史资源别名; 同步更新 `docs/implementation/REST接口与响应码.md`, `docs/implementation/证据交付与网关执行.md` 与 `docs/implementation/订单核账.md`. 验证: `cd platform && go test -tags=db -v ./gateway/...` 覆盖挑战一次性消费, 锁后复核, 双实例唯一订单, 响应丢失核账与历史 `h < r` 审计全部通过.
- [x] 5.3 重构 `platform/agent/` (`wallet.go`, `tools.go`, `client.go`, `llm.go`), 将 `client_actions` 本地意图锁持久化归位到 `agent` 并改用 `pgx` 原生映射, 仅通过 HTTP/`http.Handler` 客户端与网关交互 (零 `gateway` 数据库耦合), 合并 OpenAI/Anthropic 双 SDK 运行器并删除冗余 `deterministic.go`. 验证: `cd platform && go test -tags=db -v ./agent/...` 覆盖私钥脱敏隔离, 6 个 MCP 工具 (进程内传输), 改派 `B2` 与响应丢失核账恢复全部通过, 且 `go list -deps ./agent` 确认无网关 DB 存储耦合.
- [x] 5.4 实现顶层装配 `platform/runtime/` (`stack.go`, `fixtures.go`, 移除 `synthetic` 与 `m2TaskSpec` 遗留字段) 与 `platform/cmd/ledgerctl/` (Cobra 7 个子命令: `deploy`, `seed`, `check`, `inspect`, `invoke`, `operation`, `mcp`), 同步更新 `platform/AGENTS.md` 与 `docs/implementation/部署与链上登记.md`. 验证: `cd platform && go build -o ../build/ledgerctl ./cmd/ledgerctl` 成功, `build/ledgerctl --help` 与各子命令单测, MCP stdio 握手测试通过.

## 6. 重构 `experiments` 独立模块 (`grad/experiments`)

- [x] 6.1 建立 `experiments/harness/` 共用底座 (环境装配, 指标采集, 敏感信息扫描, 源码快照, 基于 `renameio/v2` 的原子写入与基于 `csvutil` 的表格导出) 与统一 Cobra CLI `experiments/cmd/exp/` (`baseline`, `run`, `analyze`). 验证: `cd experiments && go build ./cmd/exp` 成功且 `go list -deps ./...` 确认未导入 `platform/internal/*`.
- [x] 6.2 重构 `experiments/baseline/`, `experiments/e1/driver/` 与 `experiments/e6/driver/` 适配新 `grad/protocol` 与 `grad/platform` 公开 API 及规范资源 URI, 清除对重构前旧运行目录格式的兼容分支; 同步更新 `experiments/AGENTS.md`, `experiments/README.md`, `experiments/TODO.md` 及 E1/E6 运行说明与 `result.md` 占位状态. 验证: `cd experiments && go test -v ./...` 全部通过.

## 7. 删除旧代码结构, 收敛工具链入口与全栈集成验收

- [x] 7.1 删除根目录旧 `go.mod`, `go.sum`, `cmd/`, `internal/` 以及过碎的叶子目录 `AGENTS.md`, 更新根 `mise.toml`, `experiments/mise.toml`, `AGENTS.md`, `README.md` 与 `docs/implementation/技术栈.md` 指向新的 4-Module 工作区和三层测试命令 (`test:unit`, `test:db`, `ledger:verify`, `experiment:test`). 验证: 仓库内无失效文档相对链接, `mise run ledger:build` 与 `mise run test:unit` 在干净环境下全部通过.
- [x] 7.2 执行跨模块编译期边界校验, 数据库回归与隔离 Fabric 实机集成验收 (`//go:build fabriclive`): 在干净隔离实例上验证 `ledgerctl deploy`, `seed`, `check`, `inspect`, `mcp` 与 E1/E6 驱动 smoke 检查, 并统计重构前后手写 Go 行数与文件数对比. 验证: `go list -deps -test` 确认 `protocol`/`chaincode`/`platform` 零实验依赖且 `experiments` 零 `internal/` 依赖, `mise run test:unit`, `mise run test:db`, `mise run ledger:verify` 与 `mise -C experiments run experiment:test` 全部通过.

## Workflow follow-up

- 完成上述任务并执行 `/openspec-verify-change` 核验后, 归档 `rebuild-monorepo-architecture` 并将 5 份 delta spec 同步至主规范.
- 在新架构上重新执行论文正式实验并记录新运行 ID, 稳定后打上 `git tag v1.0.0`.
