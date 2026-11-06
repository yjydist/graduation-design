# 提案

## Why

设计导航和正文混入了阶段状态, 运行结果和复跑入口, 使设计说明随实施进度变动. [GitHub #8](https://github.com/yjydist/graduation-design/issues/8) 要求以设计推动实施, 由任务和验证记录引用设计.

## What Changes

- `docs/` 的正文和导航只保留总体设计, 技术细节, 实现契约和实验设计. 清除进度叙述及指向进度材料的链接, 保留技术约束, 设计假设和实验判据.
- 在根 `AGENTS.md` 明确 `docs/`, `TODO.md`, OpenSpec 主规范和变更记录, 根 `README.md` 及既有证据目录的职责, 并规定各自的更新时点和引用方向.
- 根 `README.md` 提供设计和进度入口. `TODO.md` 提供阶段状态和退出条件, 并链接既有变更任务, 验证结论和原始证据. 复用现有记录, 避免增加另一份进展日志.

## Capabilities

### New Capabilities

无.

### Modified Capabilities

无. 本变更调整文档职责与引用关系, 使用 `skip_specs: true`.

## Impact

涉及根 `AGENTS.md`, `README.md`, `TODO.md` 及 `docs/` 的相关正文和导航. 复用已有的 D0 运行说明, OpenSpec 归档和 `infra/besu/evidence/` 证据. 账本, 授权登记和固定高度读取的能力规范维持原有要求.
