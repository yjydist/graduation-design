# Design

## Context

详见 `proposal.md`. 当前 `web/` 仅为 4 个原生静态文件 (`index.html`, `api.js`, `app.js`, `style.css`), 直接复制到 Caddy 镜像提供服务. 项目已引入完整的 [web/AGENTS.md](../../../web/AGENTS.md) 规范, 明确采用 React 19 + TypeScript 5.7+ + Vite + Tailwind CSS v4 + shadcn/ui (`base-vega`, `stone`) 的 Quiet Tool / Modern SaaS 体系. 本变更须在 `refactor-five-layer-architecture` 归档后实施, 直接对接定型的 L3/L4 `/api/v1` 接口契约.

## Goals / Non-Goals

**Goals:**

- 按 `web/AGENTS.md` 全部硬性约束与 Design Tokens 重建 `web/` 前端工程, 彻底移除旧原生脚本与样式.
- 实现三域共用的专业级工作台界面: Auth 登录页, AppShell (侧栏+顶栏+域状态/主题切换), 管理员域配置与原交易状态页, 采购员 A1 对话草稿与确认派单页, 以及五类证据视图 (身份与信任, 凭证披露, 委托树, 采购任务与报价/订单对照, 决策时间线).
- 在前端源码层呼应五层架构: 拆分 `src/api/backend.ts` (L3 后端业务与证据 API) 与 `src/api/agent.ts` (L4 采购对话与智能体运行 API).
- 保持单前端镜像三域复用, 离线运行能力与严格 CSP (`default-src 'self'`).

**Non-Goals:**

- 不修改后端协议语义, 链码或数据库表结构.
- 不引入第二套 UI 库, 图标库, 玻璃拟态, 渐变装饰或 Tailwind 原始调色板/任意值.
- 不在前端存放或构造任何私钥, 盐值, 模型密钥或未披露属性.

## Decisions

### 决策 1: 前端工程与目录分层严格对齐 `web/AGENTS.md`

- **技术栈**: React 19 + TypeScript 5.7+ (`strict: true`) + Vite + Tailwind CSS v4 (`@tailwindcss/vite`, 无 `tailwind.config.js`) + shadcn/ui (`style: "base-vega"`, `baseColor: "stone"`, `cssVariables: true`) + `lucide-react` + `sonner`.
- **目录结构**:
  ```text
  web/
    public/
      theme-init.js         # 暗色模式防闪烁外链脚本 (兼容严格 CSP)
    src/
      api/
        http.ts             # 统一 fetch 封装, CSRF 头注入, Request-ID 与 ErrorEnvelope 解析
        backend.ts          # L3 后端 API: session, health, management, operations, runs, evidence, decisions
        agent.ts            # L4 Agent API: chat, draft, confirm, dispatch trace
        types.ts            # 与后端 openapi.json 严格对齐的强类型 DTO
      components/
        ui/                 # shadcn/ui 原语 (通过 shadcn CLI 安装)
        app/                # AppShell, Sidebar, Topbar, ThemeToggle, DomainBadge
        patterns/           # PageHeader, DataTable, EmptyState, StatCard, ConfirmDialog, FilterBar, AuthLayout, StatusBadge
      features/
        auth/               # 登录表单与会话守卫
        management/         # A/B/C 域管理与原交易 (operationId / txId) 核对
        procurement/        # 采购员对话, 结构化草稿编辑/版本确认, 运行监控与挂起/恢复
        evidence/           # 5 大证据视图 (身份信任链, 凭证披露边界, G0/G1/G2 委托树, 报价/订单对照, 决策时间线)
      styles/
        globals.css         # @import "tailwindcss"; oklch light/dark tokens; @theme inline
      lib/
        utils.ts            # cn()
        format.ts           # 金额 (分转货币格式), 日期时间, 空值占位符, Unicode 码点计数校验
      pages/                # 路由页面布局组合 (List / Detail / Dashboard / Auth / Empty)
      main.tsx
      App.tsx
  ```

### 决策 2: 严格 CSP 下的暗色模式防闪烁与离线字体方案

- **防闪烁脚本**: `web/Caddyfile` 启用了不含 `'unsafe-inline'` 的严格 `Content-Security-Policy "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"`. 因此将暗色模式初始化脚本放在 `web/public/theme-init.js`, 在 `index.html` 的 `<head>` 中以同步 `<script src="/theme-init.js"></script>` 先于 CSS 加载, 既零闪烁又保持 CSP 零放宽.
- **离线字体**: 通过 `@fontsource-variable/geist` 与 `@fontsource-variable/geist-mono` (或本地打包 WOFF2) 内嵌 Latin 与等宽字体, 中文主字体优先本地可用 `Noto Sans SC` 并平滑回退系统无衬线字体 (`PingFang SC`, `Microsoft YaHei`), 确保离线隔离容器内零外部字体请求.

### 决策 3: 两阶段 Docker 构建与 Caddy SPA 代理

- `web/Dockerfile` 升级为两阶段构建:
  - Stage 1 (`node:22-alpine`): `npm ci` -> `npm run typecheck` -> `npm run build` 输出 `/app/dist`.
  - Stage 2 (`caddy:2.11.9-alpine`, 沿用固定摘要): 复制 `Caddyfile` 与 `/app/dist` 至 `/srv/`.
- `web/Caddyfile`: 保留 `/api/v1*` 反向代理至 `{$WORKBENCH_BACKEND}`, 静态处理增加 `try_files {path} /index.html` 支持 SPA 客户端路由刷新.

### 决策 4: 领域细节与既有契约完全对齐

- 保留既有核验确认过的关键边界:
  - Unicode 码点计数 (`Array.from(str).length`) 校验对话消息 (4000 码点) 与草稿说明 (512 码点), 与后端 OpenAPI `maxLength` 一致.
  - 工具轨迹正确区分 `step === 0` (服务发起) 与 `step >= 1` (模型轮次), `OUTCOME_UNKNOWN` / `UNKNOWN` 清晰显示"业务结果未知"及原 `grantId` / `actionId` / `decisionId`.
  - 金额统一由分 (`minor`) 格式化为带币种的右对齐 `tabular-nums` (如 800.00 元与 1,200.00 元, 渲染按 `web/AGENTS.md` 第 7 节规范带人民币符号), 空值按该规范渲染为破折号占位符而非 `0` 或 `null`.

## Risks / Trade-offs

- [前序变更 2 可能调整少量 API 路径或字段] -> 本变更严格排在 `refactor-five-layer-architecture` 之后执行; 开始实施前先核对最终 `openapi.json`, 如有字段变更先用 `openspec-update-change` 同步本变更设计.
- [Docker 镜像构建引入 Node 依赖] -> 首次构建需下载 npm 依赖并锁定 `package-lock.json`. 缓解措施: 提交 `package-lock.json` 并使用多阶段构建, 最终运行镜像仍仅为轻量 Caddy + 静态文件, 不包含 Node 运行时.
- [中文字体体积过大] -> 全量 `Noto Sans SC` 静态打包会显著增大镜像体积. 缓解措施: 本地打包 `Geist` / `Geist Mono`, CJK 按 `web/AGENTS.md` 要求优先使用按需子集或系统字体回退, 保持镜像轻量且严格遵守 `default-src 'self'`.
