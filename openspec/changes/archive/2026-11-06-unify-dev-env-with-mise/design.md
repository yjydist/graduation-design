# 开发环境与命令入口统一设计

## Context

当前仓库横跨本地四节点 Besu 网络 (`infra/besu/compose.yaml`), Solidity 合约编译 (`contracts/`, 通过 `npm exec --yes --package=solc@0.8.30 -- solcjs` 调用), Go 账本管理与核验工具 (`cmd/ledgerctl`, `internal/ledger/`) 以及预留的 Python 实验环境 (`docs/implementation/技术栈.md`). 本机虽已配置 `mise` shim 路径, 但因仓库根目录缺少 `mise.toml`, 实际执行回退至 Homebrew 全局二进制. 同时 `infra/besu/compose.yaml` 默认将 `BESU_INSTANCE` 指向 `../../.local/besu` 且 `BESU_UID:BESU_GID` 默认为 `1000:1000`, 而 `ledgerctl` 默认 `--dir` 为 `.local/besu-qbft`, 造成手工执行时的环境变量易错点. 变更动机见[提案](proposal.md).

## Goals / Non-Goals

**Goals:**
- 通过根目录 `mise.toml` 锁定 `go`, `node`, `python` 版本, 消除对全局 Homebrew 环境的隐式回退.
- 在全局 `[env]` 中统一无副作用的构建与默认实例变量 (`CGO_ENABLED`, `BESU_INSTANCE`), 消除日常命令重复前缀与默认目录不一致问题.
- 以 `<模块>:<动作>` 命名空间 (`besu:*`, `ledger:*`, `test:*`) 收拢三份模块 README 中的常用命令, 保持底层 `ledgerctl` 与 `docker compose` 的自包含语义不变.

**Non-Goals:**
- 不将 `ledgerctl verify` 中的编排, 交易恢复, 状态快照或 `materials/` 哈希取证逻辑拆入 shell 脚本.
- 本阶段不实现多实例切换 (`besu-rebuild`) 的任务级参数化封装, 干净重建流程保持显式路径指定.
- 不引入文档构建流水线, Makefile 或自动格式/lint 检查脚本, 严格遵守 `AGENTS.md` 的文档格式原则.

## Decisions

### 1. 按副作用边界分层管理环境变量 (全局 `[env]` vs 任务内注入)

在 `internal/ledger/*_integration_test.go` 中, 测试用例通过检查 `LEDGER_DEPLOYMENT`, `LEDGER_INSTANCE`, `LEDGER_MANIFEST` 是否为空决定是否 `t.Skip`. 若将这些变量放入 `mise.toml` 的全局 `[env]`, 在未启动 Besu 时执行 `go test ./...` 会因连接失败报错; 在启动 Besu 时执行则会触发 `TestRevocationIntegration` 等真实链上写交易, 将当前实例的 `RP-G1` 委托直接撤销.

因此环境变量按副作用分为两层:

| 层级 | 变量与取值 | 理由 |
| --- | --- | --- |
| 全局 `[env]` | `CGO_ENABLED = "0"`<br>`BESU_INSTANCE = "{{config_root}}/.local/besu-qbft"` | 纯 Go 编译约束与默认实例路径对所有日常命令安全无副作用, 且对齐 `ledgerctl` 与 `compose.yaml` 的默认目录. |
| `besu:*` 任务内注入 | `BESU_UID="$(id -u)"`<br>`BESU_GID="$(id -g)"` | 动态获取当前操作者 UID/GID, 保证容器能访问 `0700` 目录与 `0600` 私钥文件, 避免静态写死 `1000:1000`. |
| `test:*-probe` 任务内注入 | `LEDGER_INSTANCE`, `LEDGER_DEPLOYMENT`, `LEDGER_MANIFEST`, `LEDGER_EVIDENCE` | 仅在显式运行链上集成探针时激活对应环境变量, 保证 `test:unit` (或直接运行 `go test ./...`) 默认只跑离线单元测试. |

备选方案是将 `LEDGER_*` 放入全局 `[env]` 并通过 `-short` 区分测试, 但这需要修改既有 `internal/ledger/*_test.go` 的跳过逻辑与 `ledgerctl verify` 的调用契约, 超出本次工具引入边界, 故不采用.

### 2. 采用 `<模块>:<动作>` 命名空间与薄封装 (Thin Facade)

所有任务按操作对象划分为 `besu:*`, `ledger:*`, `test:*` 三个前缀, 避免无前缀动词 (如 `up`, `init`, `check`) 在后续引入 T/A/B/C 域服务和数据库后产生歧义:

| 任务名 | 封装命令 | 备注 |
| --- | --- | --- |
| `besu:config` | `docker compose -f infra/besu/compose.yaml config --quiet` | 校验 Compose 配置语法与变量解析 |
| `besu:up` | `BESU_UID="$(id -u)" BESU_GID="$(id -g)" docker compose -f infra/besu/compose.yaml up -d` | 后台启动四节点 QBFT 网络 |
| `besu:down` | `docker compose -f infra/besu/compose.yaml down` | 停止并移除容器, 保留实例数据与密钥 |
| `besu:ps` | `docker compose -f infra/besu/compose.yaml ps` | 查看四节点容器运行状态 |
| `besu:logs` | `docker compose -f infra/besu/compose.yaml logs --tail 30 c` | 查看 C 节点近期日志 (支持追加参数) |
| `ledger:build` | `go build -o build/ledgerctl ./cmd/ledgerctl` | 构建 `build/ledgerctl` 可执行文件 |
| `ledger:init` | `go run ./cmd/ledgerctl init --dir "$BESU_INSTANCE"` | 初始化或复核默认实例材料 |
| `ledger:compile` | `go run ./cmd/ledgerctl compile` | 调用锁定的 `solc@0.8.30` 编译合约 |
| `ledger:deploy` | `go run ./cmd/ledgerctl deploy --dir "$BESU_INSTANCE" --name registry` | 部署合约并写入 `deployment-registry.json` |
| `ledger:seed` | `go run ./cmd/ledgerctl seed --dir "$BESU_INSTANCE"` | 执行 15 笔管理交易建立 D0 夹具 |
| `ledger:check` | `go run ./cmd/ledgerctl check --dir "$BESU_INSTANCE" --rpc-log .local/check-rpc.json` | 在线模式读取最新固定高度状态快照 |
| `ledger:inspect` | `go run ./cmd/ledgerctl inspect --dir "$BESU_INSTANCE" --rpc-log .local/inspect-rpc.json` | 历史模式读取指定高度 (通过 `-- --block <height>` 传入) |
| `ledger:verify` | `go run ./cmd/ledgerctl verify --dir "$BESU_INSTANCE" --out .local/evidence` | 运行完整 D0 自动验收并生成独立证据目录 |
| `test:unit` | `go test ./...` | 运行离线单元测试 |
| `test:account-probe` | 注入 `LEDGER_INSTANCE` 与 `LEDGER_EVIDENCE="$PWD/.local/account-probe"` 运行 `TestAccountPermissioningIntegration` | 链上账户许可拒绝探针 |
| `test:deployment-probe` | 注入 `LEDGER_DEPLOYMENT`, `LEDGER_INSTANCE` 与 `LEDGER_EVIDENCE="$PWD/.local/deployment-probe"` 运行 `TestDeploymentBindingIntegration\|TestRootMutationIntegration` | 链上部署绑定与改根负例探针 |

### 3. 锁定与实测基线一致的工具链版本 (`[tools]`)

在 `mise.toml` 的 `[tools]` 中固定:
- `go = "1.27.3"`: 与 `go.mod` 及 `docs/implementation/技术栈.md` 第 4 节严格一致.
- `node = "26.13.0"`: 提供 `npm` 供 `ledgerctl compile` 执行 `npm exec --yes --package=solc@0.8.30 -- solcjs`, 编译器版本与完整性继续由 `contracts/compiler-lock.json` 和 `internal/ledger/compiler.go` 校验.
- `python = "3.15.2"`: 对齐本机实验分析与负载脚本环境.

### 4. 文档更新范围与原则对齐

- 在根 `AGENTS.md` 的"项目结构"表中登记 `mise.toml`, 明确其作为开发环境版本锁定与运行命令统一入口的职责, 与"文档格式"中禁止的文档构建流程/自动检查脚本划清界限.
- 更新 `infra/besu/README.md`, `contracts/README.md`, `internal/ledger/README.md`, 将日常单实例命令更新为 `mise run` 入口 (或并列说明底层命令等价关系), 同时在 `infra/besu/README.md` 的干净重建 (`.local/besu-rebuild`) 章节保留显式命令, 避免误导操作者以为 `besu-rebuild` 会自动覆盖全局 `BESU_INSTANCE`.

## Risks / Trade-offs

- [本机 `mise` 尚未在受管目录安装指定版本] -> 实施时执行 `mise install`, 验证 `mise which go`, `mise which node`, `mise which python3` 均解析到 `mise` 受管路径且版本与配置完全一致.
- [干净重建场景下全局 `BESU_INSTANCE` 默认指向 `.local/besu-qbft`] -> 在 `infra/besu/README.md` 中明确标注 `mise.toml` 默认指向 `.local/besu-qbft`, 重建新实例 `.local/besu-rebuild` 时需显式指定 `--dir` 与 `BESU_INSTANCE`; 多实例任务参数化留待后续阶段演进.
- [`ledger:inspect` 需要必选参数 `--block`] -> 利用 `mise run ledger:inspect -- --block <height>` 原生参数透传机制, 并在 `internal/ledger/README.md` 中给出完整调用示例.
