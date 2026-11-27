# 项目 mise 任务入口提案

## Why

根目录的 13 个任务覆盖了账本操作和 Go 测试, 但前端需要切换到 `web/`, 实验需要指定 `-C experiments`, 三域演示还要从手册复制镜像构建, Compose 和证书检查命令. 这使首次演示难以复现, 也使实验手册中的根目录相对路径在复算时被多解析一层.

## What Changes

- 把根 `mise.toml` 作为公开项目命令的统一入口. 在根目录用 `mise tasks` 发现任务, 用 `mise run <任务名>` 完成构建, 验证, Fabric 运维, 账本操作, 工作台运行, 前端开发, 论文实验及项目规范维护. 每个任务给出用途, 支持原工具的参数和失败反馈.
- 接入 Node 22 和前端全部 npm 脚本, 补齐依赖安装, 组合检查及浏览器测试的构建前置. 补齐 Go 模块验证, `ledgerctl` 子命令, Fabric 运维和工作台命令.
- **BREAKING** 将 `experiments/mise.toml` 的任务声明迁到根目录. 对外实验路径按仓库根解析, 同步迁移 E1 启动脚本, 基线文件摘要及 E1/E6 源码快照所引用的入口.
- 提供 `demo:up` 一键部署可登录的 A/B/C 工作台, `demo:down` 保留现场停机, `demo:clean` 一键关闭并清除演示实例. `demo:status` 和 `demo:logs` 用于核对状态和定位失败域.

## Capabilities

### New Capabilities

- `project-task-interface` 定义根目录的任务发现, 命令覆盖, 参数和路径语义, 以及前端和实验执行入口.

### Modified Capabilities

- `domain-web-workbench` 增加本地完整演示的单命令部署, 就绪判据, 恢复和定向清理要求.

## Impact

- 任务与装配涉及根 `mise.toml`, `infra/workbench/`, 既有 Fabric 脚本, 两个项目 CLI, 前端 npm 脚本和实验 CLI. 演示使用项目已支持的 arm64 macOS/Linux, Docker Compose, 各域 PostgreSQL 与 A/B 模型配置.
- 更新根入口及模块手册中的命令和路径示例. 日常停机沿用账本持久化约定. 实验继续在独立实例运行, 新运行记录实际入口的摘要, 历史证据按原字节保存.
