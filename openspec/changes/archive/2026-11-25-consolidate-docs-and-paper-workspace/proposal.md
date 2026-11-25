# Proposal

## Why

当前 `docs/` 下包含 12 份细碎文档和独立索引 (其中 `docs/design/` 5 份合计不足 200 行), 根 `AGENTS.md` 标题层级偏碎, 导致阅读, 检索与维护成本上升. 同时 `paper/` 的定位已从"相关论文 PDF 存档"转为"毕设论文 Markdown 写作工作区", 需清理旧 PDF 与零散笔记并建立清晰的单文件写作入口.

## What Changes

- **BREAKING**: 将 `docs/design/*.md` 全部合并为单文件 `docs/DESIGN.md` (内置 R1-R5 需求追踪表), 将 `docs/implementation/*.md` 全部合并为单文件 `docs/IMPLEMENTATION.md`, 删除 `docs/design/`, `docs/implementation/` 与 `docs/AGENTS.md`.
- **BREAKING**: 重新定位 `paper/` 为毕设论文写作工作区, 删除全部 13 篇相关论文 PDF, 旧阅读笔记与旧 `paper/论文.md`, 仅保留提取后的极简文献引用表 `paper/references.md`, 单文件论文正文入口 `paper/thesis.md` 与简洁索引 `paper/README.md`.
- 精简根 `AGENTS.md`, 将分散的小节收拢为 4 个紧凑板块, 写入五层单向架构约束并移除过时的 PDF 保留条款.
- 同步更新 `README.md`, `TODO.md`, `experiments/` 及各模块 `AGENTS.md` 中指向 `docs/` 与 `paper/` 的相对链接 (`openspec/changes/archive/` 历史归档保持不变).

## Capabilities

### New Capabilities

无. 本变更为纯文档结构与论文工作区整理, 不改变系统行为规范 (`skip_specs: true`).

### Modified Capabilities

无.

## Impact

- 影响目录: `docs/`, `paper/`, 根 `AGENTS.md`, `README.md`, `TODO.md`, `experiments/` 与各模块 `AGENTS.md` 中的文档链接.
- 不修改任何 Go 代码, 链码, 数据库迁移, 前端代码或运行时行为.
- 为后续 `refactor-five-layer-architecture` 与 `rebuild-workbench-web-ui` 提供精简, 统一的文档与协作规范基线.
