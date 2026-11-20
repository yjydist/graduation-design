# Fabric 运行与验收

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `README.md` | 项目集成回归, 实例管理和服务装配入口. |
| `compose.yaml` | Fabric 和 PostgreSQL 服务配置. |
| `network.sh` | 实例启停与独立重建. |
| `channel.sh` | 通道和身份材料准备. |
| `tools.sh` | Fabric 工具准备. |
| `evidence/` | 项目验收与历史预跑的保留记录. |

需要重建或注入故障的项目回归使用独立实例, 从运行手册选择命令和前置条件.
