# 项目任务入口

## Purpose

开发者, 演示者和实验操作者可以在同一个仓库根目录发现并运行本项目公开的命令. 每个入口说明执行目标和前置条件, 保留所属模块的参数, 执行结果和可追溯的产物位置.

## ADDED Requirements

### Requirement: 从仓库根发现并执行公开项目命令

项目 SHALL 以根 `mise.toml` 注册公开任务. 使用者 SHALL 能用 `mise tasks` 查到带用途说明的构建, 测试, Fabric, 账本, 工作台, 前端, 实验, 演示与规范维护命令, 再用 `mise run <任务名>` 运行. 带参数的任务 SHALL 保留参数边界, 环境配置, 工具的标准输入输出契约及失败退出状态.

#### Scenario: 按工具核对可调用的操作

- **WHEN** 维护者在根目录将任务列表与各工具的公开入口对照
- **THEN** 现有 13 个根任务仍按原名称可用, `ledgerctl` 的七个业务子命令全部有 `ledger:*` 入口, Fabric 网络脚本的公开动作全部有 `fabric:*` 入口
- **AND** 可单独准备或启动工作台后端, 构建三域共用镜像, 操作指定域的 Compose 服务, 以及通过 `demo:*` 操作完整演示
- **AND** 安装项目使用的 OpenSpec CLI 后, 可通过 `mise run spec -- list --specs` 枚举本仓规范, 也可用同一入口校验指定变更

#### Scenario: 调用方得到底层命令的真实结果

- **WHEN** 使用者运行 `mise run ledger:inspect -- --help`, 或向实验 CLI 传入不支持的实验编号
- **THEN** 前者返回该子命令的帮助, 后者返回有原因的非零退出状态. 含空格的路径作为一个参数传给目标命令
- **AND** 以 `ledger:mcp` 启动标准输入输出服务时, 客户端收到的标准输出仅承载 MCP 消息

### Requirement: 项目构建与验证可按环境独立执行

项目 SHALL 提供根 `build` 和 `test` 任务, 并公开模块构建, 静态检查, 依赖边界检查, 竞态检查, 数据库集成及 Fabric 实机验收入口. 安装工具链和项目依赖后, 默认构建与离线测试 SHALL 可在没有运行中的 Docker 服务和模型凭据的环境完成.

#### Scenario: 选择本地验证或实机验收

- **WHEN** 开发者在根目录运行 `mise run build` 和 `mise run test`
- **THEN** 能定位链码, 账本 CLI, 工作台后端, 实验 CLI 和浏览器静态产物, 并运行项目单测, 前端单测, 实验模块测试及演示编排的离线回归
- **AND** 数据库集成, 真实 Fabric 故障验收和浏览器回归各有显式入口, 可以分别准备其所需环境并单独执行

### Requirement: 前端开发和校验任务完整映射

项目 SHALL 通过 `web:install` 按锁文件安装依赖, 并用 `web:dev`, `web:build`, `web:preview`, `web:typecheck`, `web:lint`, `web:test` 和 `web:test:browser` 公开前端脚本. `web:check` SHALL 汇总类型检查, 代码检查和单测. 预览和浏览器回归 SHALL 面向当前源码的构建产物.

#### Scenario: 从干净前端目录运行浏览器回归

- **WHEN** 使用者在根目录安装锁定的前端依赖, 在已具备 Chrome 或 Chromium 且尚无 `web/dist/` 的环境运行 `mise run web:test:browser`
- **THEN** 任务先构建当前前端, 随后运行浏览器回归并返回其结果
- **AND** `web:check` 可独立执行, 任一检查失败时返回非零状态

### Requirement: 实验参数和证据位置以仓库根为准

项目 SHALL 从根目录提供 `experiment:baseline`, `experiment:run`, `experiment:analyze` 和 `experiment:test`. 基线沿用 C0/B0/B1, 正式运行和复算采用现有实验 CLI 支持的编号. 从这些入口传入的相对实例, 原始记录和输出路径 SHALL 相对仓库根解析, 绝对路径 SHALL 指向调用者指定的位置.

#### Scenario: 使用手册中的相对路径离线复算

- **WHEN** 使用者以 `experiment:analyze` 指定 E1, 传入 `--run-dir experiments/e1/runs/<run-id>` 和 `--out experiments/e1/analysis/<run-id>`, 或以同样的根目录约定指定 E6 的输入和输出
- **THEN** 复算读取指定原始目录, 只向指定派生目录写出结果, 原始文件摘要与复算前一致
- **AND** `experiment:run -- --help` 可从同一入口展示实验参数, `experiment:test` 运行整个实验模块并保留串行包测试语义

#### Scenario: 迁移任务定义后复核新运行的入口

- **WHEN** 基线计算入口文件摘要, 或 E1/E6 生成驱动源码快照
- **THEN** 可从新清单或快照核对实际使用的根 `mise.toml` 和适用的启动脚本, 并能重算所记录的摘要
- **AND** 已有实验的运行目录及历史快照可按原文件内容核对
