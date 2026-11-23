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
| `workbench/` | 三域工作台的 Compose 模板, 后端镜像构建与[运行手册](workbench/README.md). |

需要重建或注入故障的项目回归使用独立实例目录和端口范围, 避免污染默认实例, 从[Fabric 运行手册](fabric/README.md)选择命令和前置条件.
