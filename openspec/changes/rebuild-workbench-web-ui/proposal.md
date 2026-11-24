# Proposal

## Why

当前 `web/` 前端为 4 个原生静态文件 (约 900 行手写 HTML/JS/CSS), 缺少类型检查, 组件体系, 暗色模式与完整交互状态覆盖, 不符合项目新增的 `web/AGENTS.md` ("Quiet Tool / Modern SaaS" 视觉与工程规范), 也不利于毕设演示与论文截图质量.

## What Changes

- **BREAKING**: 删除旧原生 `web/index.html`, `web/app.js`, `web/api.js`, `web/style.css`, 依据 `web/AGENTS.md` 使用 React 19 + TypeScript 5.7+ (`strict: true`) + Vite + Tailwind CSS v4 (`@tailwindcss/vite`) + shadcn/ui (`base-vega`, `stone`, CSS variables) + `lucide-react` 完整重写三域共用工作台前端.
- 按五层架构在前端显式分离 L3 后端 API 客户端 (`src/api/backend.ts`) 与 L4 Agent 交互客户端 (`src/api/agent.ts`), 严格复用后端 OpenAPI `/api/v1` 契约.
- 实现完整的语义 Design Tokens (`oklch` 浅色与暗色双模式, 外链防闪烁主题脚本兼容严格 CSP), AppShell (Sidebar + Topbar + 独立滚动主区), 标准页面模板 (Auth / Dashboard / List / Detail / Empty), 状态矩阵 (Skeleton / Empty / Error / Loading / Sonner Toast) 与 WCAG 2.2 AA 可访问性.
- 升级 `web/Dockerfile` 为 `node -> vite build -> caddy` 两阶段构建并更新 `web/Caddyfile` 支持 SPA 路由回退与严格 `Content-Security-Policy: default-src 'self'`, 本地打包 `Geist` / `Geist Mono` 字体以支持离线运行, 保持 A/B/C 三域复用同一前端镜像摘要.

## Capabilities

### New Capabilities

无.

### Modified Capabilities

- `domain-web-workbench`: 升级三域共用 Web 工作台前端的工程交付基线, 视觉与状态矩阵要求, 浅色/暗色主题与严格 CSP 离线运行约束, 同时保持三域同镜像复用, 本域会话与 CSRF 安全, 采购派单流程及五类证据视图语义不变.

## Impact

- 依赖前序变更: 须在 `refactor-five-layer-architecture` 归档后再实施, 以对接最终定型的 L3/L4 `/api/v1` 接口契约 (若前序变更微调了 OpenAPI 字段, 实施前先通过 `openspec-update-change` 同步本变更制品).
- 影响代码与构建: `web/` 全量重写, `web/Dockerfile`, `web/Caddyfile`, 以及三域 Compose 前端镜像构建与浏览器端到端回归.
- 不修改后端协议语义, 链码或数据库表结构.
