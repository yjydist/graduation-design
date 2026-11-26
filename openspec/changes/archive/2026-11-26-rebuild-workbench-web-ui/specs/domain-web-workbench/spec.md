## MODIFIED Requirements

### Requirement: 三域复用独立构建的前后端

系统 SHALL 提供分别构建和发布的 Web 前端及后端容器镜像, 使 A/B/C 用同一份 Compose 模板和同一组镜像独立启动. 前端镜像 SHALL 采用构建期编译打包与轻量静态代理分离的多阶段构建 (`node -> caddy`), 静态代理 SHALL 支持 SPA 路由回退并保持严格 `Content-Security-Policy` (`default-src 'self'`, 无 `'unsafe-inline'`). 字体与静态资产 SHALL 本地随镜像打包以支持离线内网运行. 域身份, 服务端点, 存储及凭据 SHALL 由运行时配置绑定. 浏览器业务请求 SHALL 通过有 OpenAPI 契约的版本化 HTTP API 进入本域后端.

#### Scenario: 同一组镜像启动三域工作台

- **WHEN** 部署者用相同前后端镜像摘要分别加载 A/B/C 的配置, 存储和凭据并启动三个实例
- **THEN** 每个工作台报告自己的域及就绪状态, 各域用户在同一套界面中看到自己的数据和可用操作
- **AND** 切换后端服务地址或部署另一域无需重建前端镜像, 浏览器交付物不包含数据库, Fabric, 钱包或模型凭据
- **AND** 前端静态资源与字体在无外网访问和严格 `Content-Security-Policy` 下正常加载, 刷新任意 SPA 子路径均正常回到应用壳

## ADDED Requirements

### Requirement: 工作台前端组件体系, 双主题与完整交互状态

工作台 Web 前端 SHALL 遵循 `web/AGENTS.md` 的 "Quiet Tool / Modern SaaS" 工程与视觉基线, 基于强类型组件体系与语义 Design Tokens 构建浅色与暗色双模式界面, 并保持 L3 后端接口客户端与 L4 智能体交互客户端的职责分离. 界面 SHALL 提供统一的 AppShell (侧栏, 顶栏与独立滚动主区), 按标准页面模板承载登录, 域概览与管理, 采购对话与派单及五类证据视图, 为每个交互与数据页面提供完整的状态反馈与 WCAG 2.2 AA 可访问性支持.

#### Scenario: 浅色与暗色主题切换且无首屏闪烁

- **WHEN** 用户首次访问工作台或手动切换浅色/暗色主题后刷新页面
- **THEN** 页面在首屏渲染前通过符合严格 CSP 的外链初始化脚本应用 `dark` 类与 `color-scheme`, 无白屏闪烁
- **AND** 浅色与暗色模式下所有文本, 边框, 徽章与表格行均使用语义 token, 保持对比度与视觉层级清晰

#### Scenario: 完整状态矩阵, 响应式布局与键盘可访问性

- **WHEN** 用户在 320px, 768px, 1024px 与 1440px 视口宽度下分别经历数据加载, 空数据, 请求错误, 表单提交与危险操作确认流程, 或仅使用键盘 (Tab / Enter / Esc) 操作主流程
- **THEN** 数据页面依次呈现 Skeleton 加载态, 含下一步引导的 EmptyState 空态与含原因及重试按钮的错误态, 异步按钮展示 pending 并防重复提交, 危险操作 (如暂停委托或变更域资格) 提供二次确认弹窗
- **AND** 各视口宽度下零横向溢出, 所有交互控件具备清晰的 `focus-visible` 焦点环与语义 HTML/ARIA 属性
