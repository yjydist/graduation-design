# 项目基础设施

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `fabric/` | Fabric 3.1.5 + SmartBFT + PostgreSQL 17.9 项目运行环境与集成验收入口. |
| `fabric/README.md` | 集成回归, 实例管理和服务装配手册. |
| `fabric/compose.yaml` | Fabric 节点, 链码服务和 PostgreSQL 容器配置. |
| `fabric/network.sh` | 实例启停与独立重建脚本. |
| `fabric/channel.sh` | 通道, 创世块和 MSP 身份材料准备脚本. |
| `fabric/tools.sh` | Fabric 本机二进制工具校验与准备脚本. |
| `fabric/evidence/` | 历史阶段验收与预跑的保留记录. |
| `workbench/` | 三域 Compose 模板, 镜像, 单域运维与本地演示生命周期. 入口和账号见[运行手册](workbench/README.md). |
| `check_go_dependencies.py` | 按工作区实际 Go 包依赖图检查模块方向与协议登记包的标准库边界. |

需要重建或注入故障的项目回归使用独立实例目录和端口范围, 避免污染默认实例, 从[Fabric 运行手册](fabric/README.md)选择命令和前置条件.

首次在 `.local/demo-config/{a,b}/` 配置模型后, 从根运行 `mise run demo:up`, 按输出在演示浏览器信任每域根 CA. `demo:status` 和 `demo:logs -- b backend` 可从新终端查询. `demo:down` 保留现场, `demo:clean` 清除专属部署. 超过夹具期限后, 复核完旧记录再清理并重新启动. 离线回归由 `mise run test:demo` 执行.
