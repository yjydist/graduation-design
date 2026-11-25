# Design

## Context

详见 `proposal.md`. 当前仓库在 `docs/` 下拆出了 12 份篇幅偏短的设计与实现文档以及 1 份导航文档 (`docs/AGENTS.md`), 在 `paper/` 下存放了 13 篇下载的参考论文 PDF (合计 333 页) 与旧阅读笔记, 根 `AGENTS.md` 则包含过多 2-4 行的细分小节. 接下来项目将连续实施五层架构重构与 Web 工作台重写, 需要先收拢文档与论文工作区结构, 建立清晰, 低碎片的协作基线.

## Goals / Non-Goals

**Goals:**

- 将 `docs/` 精简为 `docs/DESIGN.md` 与 `docs/IMPLEMENTATION.md` 两份核心文档, 保留全部现有设计事实, 协议字段, 测试向量与契约内容, 不丢信息.
- 将 `paper/` 彻底转为毕设论文单文件 Markdown 写作工作区 (`paper/thesis.md`, `paper/references.md`, `paper/README.md`), 删除全部参考论文 PDF 与旧笔记.
- 将根 `AGENTS.md` 压平为 4 个紧凑板块, 写入五层单向架构红线并移除旧 PDF 保留条款.
- 确保仓库内所有活跃 Markdown 文档 (`README.md`, `TODO.md`, `experiments/`, 各模块 `AGENTS.md`) 无失效相对链接.

**Non-Goals:**

- 不改动任何 Go 源码, 链码, 数据库迁移, 前端代码或实验驱动.
- 不改写 `openspec/changes/archive/` 下的历史归档记录.
- 不在本变更中撰写论文正文或填充 E1-E8 实测数据 (仅搭建 `paper/thesis.md` 骨架与 `paper/references.md`).

## Decisions

### 决策 1: `docs/` 合并为 `DESIGN.md` 与 `IMPLEMENTATION.md` 两份单文件

- **选择**: 按逻辑阅读顺序整合 `docs/design/` 5 篇为 `docs/DESIGN.md` (约 220 行), 整合 `docs/implementation/` 7 篇为 `docs/IMPLEMENTATION.md` (约 850 行), 删除原 `docs/design/`, `docs/implementation/` 与 `docs/AGENTS.md`.
- **结构规划**:
  - `docs/DESIGN.md`: R1-R5 需求追踪总表 -> 1. 采购场景与总体设计 -> 2. 跨域身份与信任 -> 3. 委托授权与策略 -> 4. 请求认证与状态一致性 -> 5. 威胁模型与安全目标 (SG1-SG6).
  - `docs/IMPLEMENTATION.md`: 1. 技术栈与五层架构基线 -> 2. 部署与链上登记 -> 3. 协议编码与测试向量 -> 4. 证据交付与网关执行 -> 5. 策略输入与数据约束 -> 6. REST 接口与响应码 -> 7. 订单核账.
- **备选方案与取舍**: 保留子目录仅合并部分文件 -> 仍需维护多级索引和跨文件锚点, 无法根治碎片化; 合并为单文件 `DOCS.md` -> 超过 1100 行且混杂设计动机与编码向量. 两文件划分在可读性与维护成本之间最均衡.

### 决策 2: `paper/` 转为单文件论文写作工作区并保留精简引用表

- **选择**: 删除 `paper/` 下全部 13 个 PDF, 3 篇旧笔记与旧 `paper/论文.md`, 新建:
  - `paper/README.md`: 论文目录定位, 写作规范 (只关注内容, 完成后复制至 `.docx`, 查重 <= 10%) 与章节进度入口.
  - `paper/thesis.md`: 毕设论文单文件正文骨架 (按任务书 R1-R5 组织章节标题, 预留摘要, 绪论, 相关工作, 总体设计与身份机制, 认证协议与委托授权模型, 原型实现与实验评估, 总结与展望).
  - `paper/references.md`: 从旧 `paper/论文.md` 提取的精简参考文献元信息表 (编号, 题名, 作者, 会议/期刊, 年份, DOI/官方链接, 对应章节), 不保存任何本地 PDF.
- **备选方案与取舍**: 按章节拆分为多个 `.md` -> 用户明确偏好单文件编写便于整体校对与粘贴到 `.docx`; 完全清空 `paper/` 不留引用表 -> 后续写参考文献时需重新逐条核对 13 篇已查实的 DOI 与发表卷期, 徒增重复劳动.

### 决策 3: 根 `AGENTS.md` 收拢为 4 个紧凑板块

- **选择**: 保留全部有效规则 (四模块依赖红线, `v1.0.0` 前允许破坏性重构, Markdown/ASCII 标点/Mermaid 约定, OpenSpec 简体中文+ASCII 标点, 论文查重 <= 10%), 新增五层单向架构总则, 删除过时的"原始论文 PDF 不删除"条款, 统一组织为:
  1. `仓库结构与五层架构`
  2. `模块边界与常用命令`
  3. `工程重构与架构准则`
  4. `文档, OpenSpec 与论文规范`

## Risks / Trade-offs

- [跨文档锚点失效] -> 合并 `docs/` 后, `README.md`, `TODO.md`, `experiments/` 与模块 `AGENTS.md` 中旧链接会失效. 缓解措施: 实施时用脚本扫描全仓活跃 `.md` (排除 `openspec/changes/archive/`), 逐一替换并做断链检查.
- [删除 PDF 后的历史查找] -> 本地不再保留 333 页 PDF. 缓解措施: `paper/references.md` 保留每篇文献的正式 DOI 与官方公开链接, 需要复查页码时可直接通过链接获取, 且 Git 历史中仍可回溯元数据.
- [后续架构重构导致 `IMPLEMENTATION.md` 更新] -> 变更 2 重构 `platform/` 目录后需同步更新 `docs/IMPLEMENTATION.md` 与 `AGENTS.md` 的目录表. 缓解措施: 属于预期增量同步, 且集中到单文件后更新成本极低.
