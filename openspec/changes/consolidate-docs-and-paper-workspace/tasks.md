# Tasks

## 1. 合并 `docs/` 为设计书与实现书两份核心文档

- [ ] 1.1 将 `docs/design/` 下 5 篇文档与原 `docs/AGENTS.md` 中的 R1-R5 需求追踪表整合为 `docs/DESIGN.md`, 核对全部机制, 信任假设与 SG1-SG6 内容完整保留且仅使用 ASCII 标点.
- [ ] 1.2 将 `docs/implementation/` 下 7 篇文档整合为 `docs/IMPLEMENTATION.md`, 保持全部字段, 测试向量, REST 响应码, 数据约束与核账规则完整且章节编号清晰, 核对无内容遗漏与非 ASCII 标点.
- [ ] 1.3 删除原 `docs/design/`, `docs/implementation/` 与 `docs/AGENTS.md`, 确认 `docs/` 目录下仅保留 `DESIGN.md` 与 `IMPLEMENTATION.md` 两份文件.

## 2. 重建 `paper/` 为毕设论文单文件写作工作区

- [ ] 2.1 从原 `paper/论文.md` 与 `paper/README.md` 提取全部已核对文献的精简引用元信息 (编号, 题名, 作者, 会议/期刊, 年份, DOI 或官方链接) 写入 `paper/references.md`, 核对 13 篇文献条目及链接完整准确.
- [ ] 2.2 删除 `paper/` 下全部 PDF 文件, DOI 子目录, 3 篇旧阅读笔记与原 `paper/论文.md`, 核对仓库中不再存在任何参考论文 PDF.
- [ ] 2.3 创建单文件毕设论文骨架 `paper/thesis.md` (按 R1-R5 组织完整章节标题与占位纲要) 与简洁入口 `paper/README.md`, 核对文件结构清晰且符合 ASCII 标点规范.

## 3. 精简根 `AGENTS.md` 并同步全仓活跃文档链接

- [ ] 3.1 重写根 `AGENTS.md`, 将零碎小节收拢为 4 个紧凑板块, 写入五层单向架构总则与 `paper/` 新定位, 移除旧 PDF 保留条款, 核对所有构建测试命令与边界规则准确无误.
- [ ] 3.2 同步更新 `README.md`, `TODO.md`, `毕设要求.md`, `experiments/` 及各模块 `AGENTS.md` 中指向旧 `docs/design/`, `docs/implementation/`, `docs/AGENTS.md` 和 `paper/论文.md` 的相对链接 (`openspec/changes/archive/` 保持不变), 通过全仓相对链接扫描确认活跃 Markdown 零断链且无非 ASCII 标点回归.

## Workflow follow-up

- 完成核验并归档本变更后, 按顺序推进 `refactor-five-layer-architecture` 与 `rebuild-workbench-web-ui`.
