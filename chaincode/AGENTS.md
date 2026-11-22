# Fabric 链码

独立 Go 模块 `grad/chaincode`, 仅依赖 Fabric 链码运行时 (`fabric-chaincode-go/v2`) 与共享协议注册类型 (`grad/protocol/registry`), 不反向依赖 `platform/` 或 `experiments/`.

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `go.mod`, `go.sum` | `grad/chaincode` 模块定义与依赖锁定. |
| `registry/main.go` | 链码服务入口, `Init`/`Invoke` 分发, 调用者 MSP 与证书提取, 交易时间窗检查, `Initialize`, `Probe`, `Read` 及状态读写辅助. |
| `registry/domain.go` | 域引导, 域资格认证签发/续期/缩权/吊销, 域状态流转, 采购授权主体配置及域/签发方权威身份更新. |
| `registry/identity.go` | 普通身份注册/状态管理/密钥轮换/身份恢复, 双域身份链接状态机及凭证登记与吊销. |
| `registry/grant.go` | 任务登记与取消, 委托授权登记/暂停/恢复/吊销及原子替换 (`ReplaceGrant`). |
| `registry/registry_test.go` | 链码行为单测 (覆盖初始化约束, 域认证, 身份生命周期, 身份链接, 任务与授权状态机及规范错误码). |

## 构建与测试

```bash
cd chaincode && go build -o /dev/null ./registry
cd chaincode && go test -v -race ./...
```

变更登记行为时核对[部署与链上登记契约](../docs/implementation/部署与链上登记.md).
