# AGENTS.md — Web UI 开发规范

> 本文档是 AI Agent 编写 Web 界面的唯一执行准则（完全独立，不依赖外部文档）。
> **核心定位**：Quiet Tool / Modern SaaS（中性、克制、高信息密度，参考 Linear / Vercel / Stripe Dashboard 气质）。
> 新项目初始化命令、`components.json` 与完整 `globals.css` Token 实现见文末附录。

---

## 1. 硬性禁令（绝对禁止）

违反以下任意一条均视为不通过：

- **禁止引入第二套库**：不得混用 Ant Design / MUI / Chakra / Mantine；不得引入 Lucide 以外的图标库（FontAwesome / Heroicons / Tabler）；不得引入 Geist / Noto Sans SC 以外的字体。
- **禁止原始调色板与任意值**：不得使用 `bg-gray-100`、`text-blue-500`、`bg-slate-900` 等 Tailwind 调色板；不得使用 `text-[13px]`、`p-[18px]`、`gap-[13px]`、`bg-[#005ecb]` 等任意值（仅安全区 `env(safe-area-inset-*)`、`dvh`、第三方组件内部尺寸例外）。
- **禁止过度装饰**：不得使用玻璃拟态（`backdrop-blur`）、新拟态、大面积渐变、霓虹发光、3D 阴影；静态卡片禁止加阴影或统一 hover 上浮。
- **禁止纯黑/纯白与透明度造色**：文字不用 `#000`/`#fff`；彩色底上不用灰色文字（必须用对应 `-foreground`）；除弹窗遮罩 `bg-black/40` 和图片遮罩 `bg-black/5` 外，禁止用透明度合成语义面。
- **禁止单态交付**：不得只实现 `default` 状态；不得仅靠颜色传递状态（必须辅以图标、文案或 `aria-*`）。
- **禁止反语义 HTML 与去焦点**：不得写 `<div onClick>`（跳转用 `<a>`，动作用 `<button>`）；不得写 `outline-none` 而不提供可见的 `focus-visible` 焦点环。
- **禁止私自发明 Token**：现有 token 不够时先向用户确认，不要就地硬编码。

---

## 2. 技术栈与工程约定

### 2.1 技术基线

- **框架**：React 19 + TypeScript 5.7+（`strict: true`），Vite 默认（Next.js App Router 适用，仅 `components.json` 中 `rsc: true`）。
- **样式与组件**：Tailwind CSS v4（CSS-first，无 `tailwind.config.js`）+ shadcn/ui（Base UI 底座，`style: "base-vega"`，`baseColor: "stone"`，`cssVariables: true`）。
- **图标与字体**：`lucide-react`（16 / 20 / 24px，`strokeWidth={2}`）；`Geist` + `Noto Sans SC` + `Geist Mono`。

### 2.2 目录分层与组件复用顺序

```text
src/
  components/
    ui/         # shadcn 原语；优先通过 variant/size/className 组合，修改源码需在说明中注明原因
    app/        # 应用壳：AppShell / Sidebar / Topbar / NavItem
    patterns/   # 业务通用模式：PageHeader / DataTable / EmptyState / StatCard / FormSection / ConfirmDialog / FilterBar / SettingsSection / AuthLayout
  styles/
    globals.css # @import "tailwindcss"; tokens; @theme inline
  lib/
    utils.ts    # cn()
  pages/        # 页面只做布局与组合，不写基础样式
```

**开发新 UI 时的决策顺序**：
1. 优先复用 `src/components/ui` 和 `src/components/patterns` 已有组件。
2. 缺少基础原语时，执行 `npx shadcn@latest add <name>` 安装，不要手写等效组件。
   - Phase 1 骨架：`button input textarea label select checkbox switch card badge separator skeleton tabs table dialog alert-dialog sheet dropdown-menu tooltip sonner avatar breadcrumb pagination`
   - Phase 2 增强：`command calendar form popover scroll-area sidebar chart resizable`
3. 仅当新组件被 ≥ 2 个页面复用或属于明确 pattern 时才抽入 `patterns/`；否则先放页面局部。不擅自修改已有组件的 prop 语义。
4. 新增通用组件必须同时支持 light / dark，并注册到 `/styleguide`（若项目存在）。

### 2.3 编码规范

- 类名合并统一用 `cn()`，禁止字符串拼接。
- 组件变体用 `cva`、`data-*` 或 `aria-*`，避免布尔 prop 堆叠。
- 原则：**约束优先**、**层级靠排版和留白**、**中性为底 + 单一强调色**、**状态先于装饰**、**全站一致性大于局部创意**。

---

## 3. Design Tokens（仅允许以下类名与数值）

### 3.1 语义颜色

| 场景 | 必须使用 | 严禁使用 |
| --- | --- | --- |
| 页面底 / 主文字 | `bg-background` / `text-foreground` | `bg-white` / `bg-gray-50` / `text-black` |
| 卡片 / 面板 | `bg-card text-card-foreground border border-border` | 白底 + 大阴影 |
| 浮层 | `bg-popover text-popover-foreground shadow-e2 border border-border` | 半透明毛玻璃 |
| 主操作（近黑 Ink） | `bg-primary text-primary-foreground` | `bg-blue-600`（主按钮不是蓝色） |
| 次操作 / 弱化面 | `bg-secondary text-secondary-foreground` / `bg-muted` | 第二个主按钮 |
| Hover / 交互底 | `bg-accent text-accent-foreground` | `hover:bg-gray-100` |
| 强调色（Cobalt） | `text-brand` / `bg-brand text-brand-foreground` / `bg-brand-muted` | 自定义蓝色 hex |
| 危险 / 成功 | `bg-destructive` / `text-destructive` / `bg-success` / `text-success` | 橙色代红、随意绿 |
| 警告 | 底色 `bg-warning text-warning-foreground`；白底文字 `text-warning-text` | 直接用 `text-warning` 做白底文字 |
| 次要文字 / 边框 / 焦点 | `text-muted-foreground` / `border-border` / `border-input` / `ring-ring` | `text-gray-500` |
| 侧栏 | `bg-sidebar` / `text-sidebar-foreground` / `border-sidebar-border` / `bg-sidebar-accent` | 硬编码灰底 |
| 图表 | `chart-1` ~ `chart-5`（超过 5 类合并为“其他”） | 随机取色 |

- **强调色面积 ≤ 10%**；**一屏最多 1 个主按钮**（`variant="default"`）。

### 3.2 字体与排版

| 角色 | Tailwind 类名 | 用途 |
| --- | --- | --- |
| Page title | `text-2xl font-semibold` | 页面主标题（唯一 `h1`） |
| Section title | `text-lg font-semibold` | 区块标题 |
| Card / Dialog title | `text-base font-semibold` | 卡片 / 弹窗标题（弹窗可用 `text-lg`） |
| Body（应用默认） | `text-sm leading-6` | 应用正文（14/24） |
| Body large（长文） | `text-base leading-7` | 内容页 / 长文（最大宽 `65ch` / `40em`） |
| Label | `text-sm font-medium` | 表单标签 / 按钮文案 |
| Meta | `text-xs text-muted-foreground` | 时间 / 计数 / 辅助说明 |
| Code | `text-sm font-mono` | 代码 / ID / 命令 / 快捷键 |
| Display | `text-4xl` 或 `text-5xl font-semibold` | 仅限营销页首屏 |

- **字体家族最多两个**（`font-sans`：`Geist` + `Noto Sans SC`；`font-mono`：`Geist Mono`）；字体加载使用 `font-display: swap`，仅 preload Latin 主字体，CJK 按需子集化。
- **字重只用 `font-normal` (400) / `font-medium` (500) / `font-semibold` (600)**；禁用 `font-bold` (700) / `800`（中文会糊）。
- 中文正文行高 1.7–1.8，**不加 `letter-spacing`**，不用斜体强调，不全大写（英文 overline 才用 `uppercase tracking-wider`）；大号 Latin 标题可用 `tracking-tight`。
- 表格与指标数字加 `tabular-nums`，金额右对齐。
- 中英/数字之间留一个空格，中文使用全角标点。

### 3.3 间距与布局尺寸

- **仅用默认 4px scale**：常用 `1` (4) / `1.5` (6) / `2` (8) / `3` (12) / `4` (16) / `5` (20) / `6` (24) / `8` (32) / `12` (48) / `16` (64)。
  - 图标与文字 `gap-1.5` / `gap-2`；表单字段 `gap-4`；卡片内 `p-4` / `p-5` / `p-6`；区块间 `gap-6` / `gap-8` / `gap-12`；页面水平 padding `px-4 md:px-6 lg:px-8`（绝不小于 16px），垂直 `py-6` / `py-8`。
- **固定尺寸**：
  - Sidebar：展开 `w-64` (256px) / 收起 `w-16` (64px)
  - Topbar：`h-14` (56px)
  - 内容最大宽：`max-w-7xl` (1280px) / 表格页 `1440px` / 长文 `720px` / 表单 `480–640px`
  - 控件高度：`h-8` (32) / `h-9` (36 默认) / `h-10` (40)；表格行高 40px（紧凑 32px）；图标按钮 ≥ `size-9` (36px)

### 3.4 圆角、阴影、动效、断点与层级

- **圆角（`--radius: 0.5rem`）**：
  - `rounded-sm` (4px) 复选框/微徽章；`rounded-md` (6px) 小控件/标签；`rounded-lg` (8px) 按钮/输入/Tab；`rounded-xl` (12px) 卡片/面板/表格容器；`rounded-2xl` (16px) 弹窗/抽屉；`rounded-full` 头像/状态点/胶囊徽章。
  - 嵌套圆角：内层 = 外层 − padding（如外 12 + 内边距 4 → 内 8）。
- **阴影（仅浮层用）**：
  - 静态卡片**无阴影**（靠 `border-border`）；`shadow-e1` 卡片 hover（可选）；`shadow-e2` Dropdown / Popover / Toast；`shadow-e3` Dialog / Sheet / Command。同屏浮层 ≤ 3 个。
- **动效**：
  - 时长仅用 `duration-150`（hover/颜色）/ `duration-200`（默认微交互）/ `duration-300`（Dropdown/Popover）/ `duration-500`（Dialog/Sheet）。
  - 缓动：`ease-standard`（进场/默认）、`ease-exit`（退场）、`ease-spring`（拖拽，少用）。
  - **只动 `color` / `background-color` / `border-color` / `opacity` / `transform`**，不动宽高或位置。不做首屏入场动画、视差、自动轮播。遵守 `prefers-reduced-motion: reduce`。
- **响应式断点（Mobile-first）**：
  - 仅用默认 `sm` (640) / `md` (768) / `lg` (1024) / `xl` (1280) / `2xl` (1536)。
  - `< 1024` 侧栏收起为 64px；`< 768` 改为 Topbar + Sheet 菜单（底部加 `pb-[env(safe-area-inset-bottom)]`）；320px 宽度下**零横向溢出**。
- **Z-index**：内容 `z-0` / Sticky header `z-30` / Dropdown & Popover `z-40` / Overlay `z-overlay` (50) / Modal & Sheet `z-modal` (60) / Toast `z-toast` (70) / Tooltip `z-tooltip` (80)。

---

## 4. 布局与页面模板

### 4.1 App Shell

- 左侧 Sidebar（`bg-sidebar border-r border-sidebar-border`）+ 顶部 Topbar（`h-14 border-b border-border`，不悬浮不毛玻璃）+ 独立滚动的 `<main>` 内容区。
- 导航项：高 36px、`rounded-lg`、图标 20px、文字 `text-sm font-medium`；当前项必须同时有 `bg-brand-muted text-brand` + 左侧 2px 指示条。分组标题用 `text-xs font-medium text-muted-foreground`。
- 一级导航 ≤ 7 项，导航层级 ≤ 2 层（二级用页面内 Tabs 或侧栏分组）；面包屑仅出现在详情页且末项不可点击。

### 4.2 六种标准页面模板（禁止自创杂糅模板）

| 模板 | 结构 | 适用场景 |
| --- | --- | --- |
| **List** | `PageHeader` + `FilterBar` + `DataTable` / `CardGrid` + `Pagination` | 资源列表、搜索 |
| **Detail** | `PageHeader` + 2 列（主 2/3，侧 1/3，`<1024` 堆叠且侧栏在后）+ `Tabs` | 单条详情 |
| **Settings** | `PageHeader` + 左侧 200px 子导航 + 右侧 640px 表单 | 设置与配置 |
| **Dashboard** | `PageHeader` + ≤ 4 列 `StatCard` + 2 列图表 + 最近列表 | 概览页 |
| **Auth** | 居中卡片 400px，无 Sidebar | 登录 / 注册 / 重置 |
| **Empty / Onboarding** | 居中 480px：图标 + 标题 + 说明 + 1 个主操作 | 首次使用 / 无数据 |

- 单页最多 3 种布局模式；页面级操作放 `PageHeader` 右侧；行内操作放行尾 `...` 下拉菜单（禁止一排图标按钮）。
- 卡片网格：12 列栅格，跨 3/4/6 列，`gap-4`/`gap-6`，卡片最小宽 280px，`<640` 单列，同行 `items-stretch`；卡片内顺序固定为**标题 → 描述 → 元信息 → 操作**。

---

## 5. 核心组件实现细则

- **Button**：`default`（唯一主操作）/ `secondary` / `outline` / `ghost` / `destructive` / `link`。尺寸 `sm`(32) / `default`(36) / `lg`(40)，水平内边距 12/16/20，图标 16px，`gap-1.5`。
  - loading：Spinner 替换左侧图标、保持原宽度、禁用点击；disabled：`opacity-50 pointer-events-none` 并用 Tooltip 解释原因；图标按钮必须带 `aria-label` 且 ≥ 36px；危险操作必须二次确认。
- **Form**：Label 在上（`text-sm font-medium`），输入框高 36px，helper `text-xs text-muted-foreground`，error `text-xs text-destructive`。字段 `gap-4`，分组 `gap-8`，最大宽 480–640px。
  - 必填用 `*` + `aria-required`；错误用 `border-destructive` + 下方文案 + `aria-invalid` + `aria-describedby`；Placeholder 不可替代 Label；提交中禁用并 loading；成功用 Toast 不用 `alert`。
- **DataTable**：容器 `rounded-xl border border-border`（不要每行卡片化）；表头高 40px `text-xs font-medium text-muted-foreground` 且 sticky；行高 40px（紧凑 32px）；单元格 `px-3` / `px-4`。
  - 文本左对齐，数字右对齐 + `tabular-nums`，操作列右对齐；行 hover `bg-muted`，选中 `bg-brand-muted`（不要斑马纹 + hover 同时用）；`<768` 优先横向滚动 + 首列 sticky；loading 用 5–8 行 Skeleton，empty 保留表头并在表体渲染 `EmptyState`；排序/筛选/分页必须有真实 URL 或 state 驱动。
- **Dialog / Sheet**：Dialog 最大宽 480px（确认）/ 640px（表单），`rounded-2xl p-6`，标题 `text-lg font-semibold`，描述 `text-sm text-muted-foreground`，底部操作右对齐且主操作在最右；遮罩 `bg-black/40`（无 blur）。必须支持 focus trap、Esc 关闭、关闭后焦点回原触发元素。危险确认标题写明对象，按钮用具体动词（如“删除项目”）。
- **Toast（Sonner）**：桌面右下角 / 移动顶部居中，宽 360px，`rounded-xl shadow-e2 border border-border`；成功 3s / 错误 6s，可手动关闭，hover 暂停；同时最多 3 条；错误必须说明怎么办，必要时提供“重试”按钮；不用于需要用户决策的场景。
- **EmptyState**：居中 `max-w-sm`（约 360–384px）`py-12`；顶部 40px 图标置入 `bg-muted rounded-full` 圆底，标题 `text-base font-semibold`，描述 `text-sm text-muted-foreground`（≤ 2 行），底部放主操作 + 可选次链接。
- **StatCard**：`rounded-xl border border-border bg-card p-5`；Label `text-xs text-muted-foreground`，Value `text-2xl` 或 `text-3xl font-semibold tabular-nums`（带单位，空值显示 `—` 而非 `0`），Delta `text-xs`（成功/危险色），一屏 ≤ 4 个。

---

## 6. 状态矩阵（交付必填）

| 组件 / 范围 | 必须实现的状态 |
| --- | --- |
| Button | default / hover / active / focus-visible / disabled / loading |
| Input / Textarea | default / hover / focus / filled / disabled / readonly / invalid / success |
| Select / Combobox | closed / open / hover / selected / disabled / loading / empty / error |
| Checkbox / Radio / Switch | default / hover / focus / checked / disabled / invalid |
| Table | loading / empty / error / selected / sorted / filtered / paginated |
| Dialog / Sheet | closed / opening / open / closing / error / loading |
| Toast | success / error / warning / info / with action |
| Page | loading / empty / error / partial / offline（适用时） |
| Async action | idle / pending / success / error / retry |
| Navigation | default / hover / active / current / disabled |

- **底线要求**：每个交互元素至少有 `hover` + `focus-visible` + `disabled`；每个数据页至少有 `loading` + `empty` + `error`；每个异步按钮至少有 `pending` + `success`/`error`。
- **加载策略**：形状已知用 **Skeleton**，未知且 <300ms 用 Spinner，全程不产生布局跳动（CLS）。

---

## 7. 文案与数据格式

- **语气**：中文优先（i18n 就绪，不拼接翻译字符串，预留 1.5× 英文长度），简洁、具体、动词开头，使用 sentence case；禁用“赋能 / 一站式 / 极致”等空词。
- **按钮文案**：2–4 个汉字（英文 ≤ 3 词）；禁用模糊的“确定 / 取消”，改为“保存更改 / 放弃修改”、“删除项目 / 保留”。
- **文案公式**：
  - **空状态**（状态 + 下一步）：“还没有成员。邀请第一个人加入。”（禁止只写“暂无数据”）
  - **错误**（发生了什么 + 原因 + 怎么办）：“保存失败：网络连接中断。请检查网络后重试。”
  - **危险确认**（对象 + 后果 + 动词按钮）：“删除「测试项目」？此操作不可撤销。” / “删除项目”
  - **成功**（动作 + 结果）：“已保存 3 项更改。”
  - **加载**（正在 + 动作）：“正在同步仓库…”
- **格式**：千分位 `1,234`；大数同页统一 `1.2 万` / `12.3k`；金额带币种 `¥1,234.00`；日期 `2026-11-23`、时间 `14:30`（相对时间仅用于 < 7 天）；百分比保留 1 位小数；空值统一用 `—`（不用 `0` 或 `null`）。

---

## 8. 可访问性（WCAG 2.2 AA）与暗色模式

### 8.1 可访问性

- 对比度：正文 ≥ 4.5:1，大字号 / UI 边界 / 焦点环 ≥ 3:1（使用既定语义 token 即已通过校验）。
- 焦点可见：统一 `focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background`。
- 键盘操作：Tab 顺序合理，Esc 关闭浮层，菜单支持方向键，Modal 内 focus trap。
- 语义与 ARIA：
  - 单页唯一 `<h1>`，标题不跳级；使用 `<header>` / `<nav>` / `<main>` / `<aside>` / `<footer>` 及顶部 Skip to content 链接。
  - 表单配 `<label htmlFor>`、`autocomplete`、`type`、`inputmode`、`aria-invalid`、`aria-describedby`。
  - 表格配 `<caption>` 或 `aria-label`、表头 `scope="col"`；装饰图标 `aria-hidden="true"`；Toast 用 `role="status"` / `aria-live="polite"`，错误用 `role="alert"`。
  - 交互目标 ≥ 36px（移动端 ≥ 44px），支持 200% 缩放。

### 8.2 暗色模式

- 策略：`<html>` 挂 `class="dark"` + `color-scheme: dark`；首次跟随 `prefers-color-scheme`，之后读 `localStorage("theme")`。
- 防闪烁：在 `<head>` 中先于 CSS 内联以下脚本：

```html
<script>
  (() => {
    const saved = localStorage.getItem("theme");
    const dark =
      saved === "dark" ||
      (!saved && matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", dark);
  })();
</script>
```

- 层级靠**表面逐级变亮**（`background` → `card` → `popover` → `muted`）与更明显的 `border-border`，不要加大阴影。
- 图片不整体反相，过亮时加 `dark:brightness-90`；图表自动走暗色 `--chart-1..5`。

---

## 9. 交付前自检清单（Definition of Done）

完成任意 Web UI 任务前，逐项核对：

- [ ] 仅使用语义 token 与 `ui/` / `patterns/` 组件，无 Tailwind 调色板、无任意值、无内联 hex
- [ ] 一屏最多一个主按钮（`bg-primary`），静态卡片无阴影，圆角符合 8/12/16/full 规范
- [ ] 所有交互元素的 `hover` / `focus-visible` / `active` / `disabled` / `loading` 齐全
- [ ] 数据页具备 `loading`（Skeleton）/ `empty`（含下一步）/ `error`（含原因与重试）
- [ ] 表单有 `<label>`、错误 ARIA 关联、`autocomplete` 与校验反馈
- [ ] 键盘可走完主流程，焦点清晰可见，语义标签正确
- [ ] Light 与 Dark 模式均已检查无对比度或层次问题
- [ ] 320 / 768 / 1024 / 1440px 宽度均无横向溢出
- [ ] 文案符合第 7 节公式，无“暂无数据”“确定/取消”等敷衍文案
- [ ] 新增通用组件已加入 `/styleguide`（若项目包含）
- [ ] `tsc -b`（或 `tsc --noEmit`）与 lint 检查全部通过

---

## 附录：新项目初始化模板

### A. 初始化命令与配置

```bash
npm create vite@latest my-app -- --template react-ts
cd my-app
npm i tailwindcss @tailwindcss/vite
npx shadcn@latest init
```

`vite.config.ts` 注册 `@tailwindcss/vite` 插件；`shadcn init` 选项为 `React` / `Vega (Base UI) -> base-vega` / `Stone` / `CSS variables: Yes` / `Lucide` / `Menu color: Default` / `Menu accent: Subtle`。

目标 `components.json`（Next.js 项目将 `rsc` 改为 `true`）：

```json
{
  "$schema": "https://ui.shadcn.com/schema.json",
  "style": "base-vega",
  "rsc": false,
  "tsx": true,
  "tailwind": {
    "config": "",
    "css": "src/styles/globals.css",
    "baseColor": "stone",
    "cssVariables": true,
    "prefix": ""
  },
  "iconLibrary": "lucide",
  "aliases": {
    "components": "@/components",
    "utils": "@/lib/utils",
    "ui": "@/components/ui",
    "lib": "@/lib",
    "hooks": "@/hooks"
  },
  "menuColor": "default",
  "menuAccent": "subtle"
}
```

### B. 完整 `src/styles/globals.css`

```css
@import "tailwindcss";

@theme {
  --font-sans: "Geist", "Noto Sans SC", -apple-system, BlinkMacSystemFont,
    "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  --font-mono: "Geist Mono", "JetBrains Mono", ui-monospace, SFMono-Regular,
    Menlo, monospace;

  --shadow-e1: 0 1px 2px 0 oklch(0 0 0 / 0.05);
  --shadow-e2: 0 4px 12px -2px oklch(0 0 0 / 0.08),
    0 2px 4px -2px oklch(0 0 0 / 0.04);
  --shadow-e3: 0 16px 48px -12px oklch(0 0 0 / 0.18);

  --ease-standard: cubic-bezier(0.2, 0, 0, 1);
  --ease-exit: cubic-bezier(0.4, 0, 1, 1);
  --ease-spring: cubic-bezier(0.34, 1.56, 0.64, 1);
}

:root {
  --radius: 0.5rem;

  --background: oklch(0.985 0.002 90);
  --foreground: oklch(0.205 0.006 90);
  --card: oklch(1 0 0);
  --card-foreground: oklch(0.205 0.006 90);
  --popover: oklch(1 0 0);
  --popover-foreground: oklch(0.205 0.006 90);
  --primary: oklch(0.24 0.006 90);
  --primary-foreground: oklch(0.985 0.002 90);
  --secondary: oklch(0.96 0.003 90);
  --secondary-foreground: oklch(0.24 0.006 90);
  --muted: oklch(0.96 0.003 90);
  --muted-foreground: oklch(0.52 0.008 90);
  --accent: oklch(0.95 0.004 90);
  --accent-foreground: oklch(0.24 0.006 90);

  --brand: oklch(0.5 0.19 255);
  --brand-foreground: oklch(1 0 0);
  --brand-muted: oklch(0.95 0.03 255);

  --destructive: oklch(0.55 0.2 25);
  --destructive-foreground: oklch(1 0 0);
  --success: oklch(0.52 0.13 155);
  --success-foreground: oklch(1 0 0);
  --warning: oklch(0.75 0.15 80);
  --warning-foreground: oklch(0.205 0.006 90);
  --warning-text: oklch(0.55 0.13 70);

  --border: oklch(0.91 0.004 90);
  --input: oklch(0.89 0.004 90);
  --ring: oklch(0.5 0.19 255);

  --chart-1: oklch(0.5 0.19 255);
  --chart-2: oklch(0.6 0.12 190);
  --chart-3: oklch(0.72 0.14 75);
  --chart-4: oklch(0.58 0.16 300);
  --chart-5: oklch(0.62 0.16 15);

  --sidebar: oklch(0.975 0.002 90);
  --sidebar-foreground: oklch(0.205 0.006 90);
  --sidebar-primary: oklch(0.5 0.19 255);
  --sidebar-primary-foreground: oklch(1 0 0);
  --sidebar-accent: oklch(0.95 0.03 255);
  --sidebar-accent-foreground: oklch(0.5 0.19 255);
  --sidebar-border: oklch(0.91 0.004 90);
  --sidebar-ring: oklch(0.5 0.19 255);
}

.dark {
  color-scheme: dark;

  --background: oklch(0.16 0.006 90);
  --foreground: oklch(0.96 0.002 90);
  --card: oklch(0.19 0.006 90);
  --card-foreground: oklch(0.96 0.002 90);
  --popover: oklch(0.21 0.006 90);
  --popover-foreground: oklch(0.96 0.002 90);
  --primary: oklch(0.96 0.002 90);
  --primary-foreground: oklch(0.18 0.006 90);
  --secondary: oklch(0.24 0.006 90);
  --secondary-foreground: oklch(0.96 0.002 90);
  --muted: oklch(0.24 0.006 90);
  --muted-foreground: oklch(0.7 0.006 90);
  --accent: oklch(0.26 0.006 90);
  --accent-foreground: oklch(0.96 0.002 90);

  --brand: oklch(0.72 0.14 255);
  --brand-foreground: oklch(0.16 0.006 90);
  --brand-muted: oklch(0.28 0.04 255);

  --destructive: oklch(0.55 0.2 25);
  --destructive-foreground: oklch(1 0 0);
  --success: oklch(0.7 0.13 155);
  --success-foreground: oklch(0.16 0.006 90);
  --warning: oklch(0.82 0.14 80);
  --warning-foreground: oklch(0.16 0.006 90);
  --warning-text: oklch(0.82 0.14 80);

  --border: oklch(0.28 0.006 90);
  --input: oklch(0.3 0.006 90);
  --ring: oklch(0.72 0.14 255);

  --chart-1: oklch(0.72 0.14 255);
  --chart-2: oklch(0.75 0.1 190);
  --chart-3: oklch(0.82 0.12 75);
  --chart-4: oklch(0.72 0.13 300);
  --chart-5: oklch(0.75 0.13 15);

  --sidebar: oklch(0.175 0.006 90);
  --sidebar-foreground: oklch(0.96 0.002 90);
  --sidebar-primary: oklch(0.72 0.14 255);
  --sidebar-primary-foreground: oklch(0.16 0.006 90);
  --sidebar-accent: oklch(0.28 0.04 255);
  --sidebar-accent-foreground: oklch(0.72 0.14 255);
  --sidebar-border: oklch(0.26 0.006 90);
  --sidebar-ring: oklch(0.72 0.14 255);
}

@theme inline {
  --color-background: var(--background);
  --color-foreground: var(--foreground);
  --color-card: var(--card);
  --color-card-foreground: var(--card-foreground);
  --color-popover: var(--popover);
  --color-popover-foreground: var(--popover-foreground);
  --color-primary: var(--primary);
  --color-primary-foreground: var(--primary-foreground);
  --color-secondary: var(--secondary);
  --color-secondary-foreground: var(--secondary-foreground);
  --color-muted: var(--muted);
  --color-muted-foreground: var(--muted-foreground);
  --color-accent: var(--accent);
  --color-accent-foreground: var(--accent-foreground);

  --color-brand: var(--brand);
  --color-brand-foreground: var(--brand-foreground);
  --color-brand-muted: var(--brand-muted);

  --color-destructive: var(--destructive);
  --color-destructive-foreground: var(--destructive-foreground);
  --color-success: var(--success);
  --color-success-foreground: var(--success-foreground);
  --color-warning: var(--warning);
  --color-warning-foreground: var(--warning-foreground);
  --color-warning-text: var(--warning-text);

  --color-border: var(--border);
  --color-input: var(--input);
  --color-ring: var(--ring);

  --color-chart-1: var(--chart-1);
  --color-chart-2: var(--chart-2);
  --color-chart-3: var(--chart-3);
  --color-chart-4: var(--chart-4);
  --color-chart-5: var(--chart-5);

  --color-sidebar: var(--sidebar);
  --color-sidebar-foreground: var(--sidebar-foreground);
  --color-sidebar-primary: var(--sidebar-primary);
  --color-sidebar-primary-foreground: var(--sidebar-primary-foreground);
  --color-sidebar-accent: var(--sidebar-accent);
  --color-sidebar-accent-foreground: var(--sidebar-accent-foreground);
  --color-sidebar-border: var(--sidebar-border);
  --color-sidebar-ring: var(--sidebar-ring);

  --radius-sm: calc(var(--radius) - 4px);
  --radius-md: calc(var(--radius) - 2px);
  --radius-lg: var(--radius);
  --radius-xl: calc(var(--radius) + 4px);
}

@utility z-overlay {
  z-index: 50;
}

@utility z-modal {
  z-index: 60;
}

@utility z-toast {
  z-index: 70;
}

@utility z-tooltip {
  z-index: 80;
}

@layer base {
  * {
    @apply border-border;
  }

  html {
    @apply bg-background text-foreground antialiased;
    font-synthesis-weight: none;
    text-rendering: optimizeLegibility;
  }

  body {
    @apply bg-background text-foreground;
    font-family: var(--font-sans);
  }

  @media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
      scroll-behavior: auto !important;
    }
  }
}
```
