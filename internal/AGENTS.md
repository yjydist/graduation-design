# 项目实现

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `agent/` | 钱包, MCP 工具和智能体运行时. |
| `centralstate/` | 中心化主库的登记版本, 一致快照及事务检查点. |
| `fabric/` | Fabric 实例, 管理交易, 区块视图, 探针及集成回归. |
| `fabricapi/` | Fabric 登记类型和协议常量. |
| `gateway/` | 访问决策, 业务事务, 订单核账和回执. |
| `policy/` | 策略构造和求值. |
| `protocol/` | 证据编码, 签名, 凭证及委托校验. |
| `serviceauth/` | 服务间身份认证. |

对照[实现契约](../docs/implementation/AGENTS.md)定位接口与测试. 局部回归从受影响的包开始.
