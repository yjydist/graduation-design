# 提案

## Why

当前项目的工具链版本 (`go`, `node`, `python`), 环境变量 (`CGO_ENABLED`, `BESU_INSTANCE`, `BESU_UID`, `BESU_GID`, `LEDGER_*`) 以及 Besu 网络启停, `ledgerctl` 生命周期操作和 Go 测试命令分散在多份运行说明中, 日常执行需反复手动拼接环境变量与长命令, 且本机未激活仓库级 `mise` 配置时会回退到 Homebrew 全局工具链, 存在版本漂移和默认实例路径不一致的风险.

## What Changes

- 在仓库根目录新增 `mise.toml`, 锁定与当前实测环境一致的工具链版本 (`go = "1.27.3"`, `node = "26.13.0"`, `python = "3.15.2"`).
- 在 `mise.toml` 的全局 `[env]` 中统一配置无副作用的基础环境变量 (`CGO_ENABLED = "0"`, `BESU_INSTANCE = "{{config_root}}/.local/besu-qbft"`), 并将触发链上真实交易或要求节点在线的 `LEDGER_*` 变量及宿主 `BESU_UID`/`BESU_GID` 严格限制在对应任务内部注入, 保证离线单元测试与链上集成探针互不干扰.
- 在 `mise.toml` 的 `[tasks]` 中按 `<模块>:<动作>` 命名空间提供薄封装入口, 覆盖 `besu:*` (`config`, `up`, `down`, `ps`, `logs`), `ledger:*` (`build`, `init`, `compile`, `deploy`, `seed`, `check`, `inspect`, `verify`) 和 `test:*` (`unit`, `account-probe`, `deployment-probe`), 底层继续调用既有 `docker compose`, `ledgerctl` 和 `go test`, 不迁移业务或取证逻辑.
- 同步更新根 `AGENTS.md` 的项目结构说明以及 `infra/besu/README.md`, `contracts/README.md`, `internal/ledger/README.md` 中的运行命令说明.

## Capabilities

### New Capabilities

无.

### Modified Capabilities

无. 本变更仅引入开发环境锁定与命令入口薄封装, 不改变账本, 授权登记或固定高度读取的系统行为规范, 使用 `skip_specs: true`.

## Impact

涉及新增根目录 `mise.toml`, 并更新 `AGENTS.md`, `infra/besu/README.md`, `contracts/README.md` 和 `internal/ledger/README.md`. `cmd/ledgerctl/`, `internal/ledger/`, `contracts/`, `infra/besu/compose.yaml` 的代码与配置语义保持不变, 已归档的 D0 证据与 OpenSpec 主规范不受影响.
