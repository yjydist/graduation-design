# 实施任务

## 1. 建立 mise 工具链与基础环境配置

- [x] 1.1 在仓库根目录创建 `mise.toml`, 配置 `[tools]` (`go = "1.27.3"`, `node = "26.13.0"`, `python = "3.15.2"`) 与全局 `[env]` (`CGO_ENABLED = "0"`, `BESU_INSTANCE = "{{config_root}}/.local/besu-qbft"`), 执行 `mise trust` 与 `mise install`, 并验证 `mise which go`, `mise which node`, `mise which python3` 及 `mise env` 输出符合预期.
- [x] 1.2 更新根 `AGENTS.md` 的项目结构表, 补充 `mise.toml` 作为开发环境版本锁定与运行命令入口的说明, 并核对文档内容符合 ASCII 标点及职责边界原则.

## 2. 封装 Besu 网络管理任务与文档

- [x] 2.1 在 `mise.toml` 中实现 `besu:config`, `besu:up`, `besu:down`, `besu:ps`, `besu:logs` 任务, 在任务内动态注入 `BESU_UID` 与 `BESU_GID`, 并通过 `mise run besu:config` 及 `mise tasks ls` 验证配置解析与任务注册成功.
- [x] 2.2 更新 `infra/besu/README.md` 中的网络启停说明, 提供 `mise run besu:*` 入口并保留干净重建 (`.local/besu-rebuild`) 的显式路径说明, 核对文档中的命令与相对链接有效.

## 3. 封装账本生命周期与测试探针任务及文档

- [x] 3.1 在 `mise.toml` 中实现 `ledger:build`, `ledger:init`, `ledger:compile`, `ledger:deploy`, `ledger:seed`, `ledger:check`, `ledger:inspect`, `ledger:verify` 任务, 并执行 `mise run ledger:build`, `mise run ledger:init`, `mise run ledger:compile` 验证二进制构建, 默认实例复核与合约编译通过.
- [x] 3.2 在 `mise.toml` 中实现 `test:unit`, `test:account-probe`, `test:deployment-probe` 任务, 将 `LEDGER_*` 环境变量严格限制在探针任务内部注入, 并执行 `mise run test:unit` 验证离线单元测试通过且链上集成测试按预期跳过.
- [x] 3.3 更新 `contracts/README.md`, `internal/ledger/README.md` 及 `infra/besu/README.md` 中的编译, 部署, 灌数据, 状态读取与探针测试说明, 补充 `mise run ledger:*` 与 `mise run test:*` 调用方式 (含 `ledger:inspect` 的 `-- --block` 参数透传示例), 并核对全文仅使用 ASCII 半角标点.

## 4. 端到端集成核验

- [x] 4.1 使用 `mise run besu:up`, `mise run ledger:check`, `mise run ledger:inspect` (带 `-- --block` 参数), `mise run test:account-probe`, `mise run test:deployment-probe` 在本地网络上完成端到端链路验证, 确认既有命令行为与证据生成不受影响.
