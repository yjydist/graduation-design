# Tasks

## 1. 初始化 React 19 + Tailwind v4 + shadcn/ui 前端工程与设计底座

- [ ] 1.1 清理旧原生 `web/index.html`, `web/app.js`, `web/api.js`, `web/style.css`, 按 `web/AGENTS.md` 初始化 React 19 + TypeScript 5.7+ (`strict: true`) + Vite + Tailwind CSS v4 (`@tailwindcss/vite`) + shadcn/ui (`base-vega`, `stone`, `cssVariables: true`) + `lucide-react` + `sonner`, 并安装本地 `Geist` / `Geist Mono` 字体包, 验证 `npm run typecheck` 与 `npm run build` 通过.
- [ ] 1.2 编写 `web/src/styles/globals.css` (完整 `oklch` 浅色/暗色语义 tokens 与 `@theme inline`), `web/public/theme-init.js` (兼容严格 CSP 的防闪烁初始化脚本) 与 `web/src/lib/{utils.ts,format.ts}` (含 Unicode 码点计数与金额/空值格式化), 编写前端工具函数单测验证码点限制与金额格式化边界.
- [ ] 1.3 通过 shadcn CLI 安装必需原语至 `web/src/components/ui/`, 并构建 `web/src/components/app/` (`AppShell`, `Sidebar`, `Topbar`, `ThemeToggle`, `DomainBadge`) 与 `web/src/components/patterns/` (`PageHeader`, `DataTable`, `EmptyState`, `StatCard`, `ConfirmDialog`, `FilterBar`, `AuthLayout`, `StatusBadge`), 核对零 Tailwind 原始调色板与零任意值.

## 2. 对接 L3 后端 API 与 L4 Agent API 客户端层

- [ ] 2.1 实现 `web/src/api/types.ts` 与 `web/src/api/http.ts` (严格对齐重构后的后端 `openapi.json`, 统一 CSRF 令牌注入, `X-Request-Id` 与 `ErrorEnvelope` 错误解码), 并拆分 `web/src/api/backend.ts` (L3 会话, 健康检查, 域管理, 原交易, 运行列表, 证据与决定) 与 `web/src/api/agent.ts` (L4 对话, 草稿, 确认与派单轨迹), 编写客户端单测验证错误处理与 CSRF 透传.

## 3. 实现登录, 域管理, 采购派单与五类证据页面

- [ ] 3.1 实现认证与本域管理界面 (`features/auth`, `features/management`): `AuthLayout` 登录页, 域状态概览 `StatCard`, A/B/C 本域管理员配置表单 (含二次确认 `ConfirmDialog`), 原操作 ID / `txId` 与入块状态核对视图, 覆盖 `loading`/`empty`/`error`/`pending` 全状态与 Sonner Toast 反馈.
- [ ] 3.2 实现 A 域采购员对话与派单界面 (`features/procurement`): 与 A1 的文字交互面板, 结构化草稿编辑与版本确认表单 (严格执行 4000 / 512 Unicode 码点上限校验), 运行列表 `DataTable` 与详情页 (含挂起/恢复二次确认, `step: 0` 服务调用与 `step >= 1` 模型轮次区分, 以及 `OUTCOME_UNKNOWN` / `UNKNOWN` 状态与原业务 ID 展示).
- [ ] 3.3 实现五类角色可见证据视图 (`features/evidence`): 身份与信任链视图, 凭证披露边界视图, `G0/G1/G2` 委托树与逐跳收缩/失效祖先视图, 采购任务与 800/1200 元报价订单对照视图, 以及决策时间线视图 (策略与环境版本, 块高/哈希, 原探针期限与拒绝理由), 确认权限边界与后端一致.

## 4. 升级多阶段镜像构建, CSP 代理与端到端质量验收

- [ ] 4.1 升级 `web/Dockerfile` 为 `node -> caddy` 两阶段构建并更新 `web/Caddyfile` (`try_files {path} /index.html` 与严格 `Content-Security-Policy: default-src 'self'`), 校验前端镜像构建成功且 `infra/workbench/compose.yaml` 配置校验通过.
- [ ] 4.2 逐项核对 `web/AGENTS.md` 第 9 节自检清单: 执行 `tsc --noEmit` 与 lint 检查, 在无头浏览器中验证 Light/Dark 双主题切换无闪烁与无 CSP 报错, 320/768/1024/1440px 视口零横向溢出, 键盘主流程可访问性, 以及对接三域工作台实机的登录, 管理, 采购派单与证据视图回归.

## Workflow follow-up

- 实施前先确认 `refactor-five-layer-architecture` 已归档; 若后端 OpenAPI 存在调整, 先通过 `openspec-update-change` 同步本变更制品再开始实施.
- 完成核验与归档后, 即可基于最终冻结架构推进 E1-E8 正式实验与论文写作.
