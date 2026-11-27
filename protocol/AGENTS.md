# protocol/AGENTS.md

`protocol/` 为独立 Go 模块 `grad/protocol`, 负责 `grad-auth-v1` 协议的全部规范化编解码, 密码学原语, 凭证/委托/证据包验证以及链上登记共享模型.

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `go.mod`, `go.sum` | `grad/protocol` 模块定义与依赖锁定. |
| `registry/` | 链上登记共享数据结构, 规范错误码 (`67` 项) 与基础校验原语. |
| `errors.go` | 重导出 `registry` 规范错误码, 协议常量及规范资源 URI 校验. |
| `codec.go` | 严格 I-JSON 校验, RFC 8785 JCS 规范化, 安全整数与结构体严格解码. |
| `crypto.go` | P-256 密钥与公钥编码, RFC 7638 JWK 指纹, DID 文档, 43 字符 nonce 与 ES256 JWS 签验. |
| `didweb.go` | 受控 `did:web` HTTPS 解析, TestCA 与离线预置根文档, 历史归档解析器. |
| `credential.go` | 离线固定 W3C VC v2 上下文校验, 域认证 (`vc+jwt`) 与企业身份 SD-JWT (`vc+sd-jwt`) 签验. |
| `grant.go` | 委托声明 (`grad-delegation+jwt`) 签验与单调缩权链校验. |
| `request.go` | `TaskSpec`, `AccessRequest`, 部署绑定, 注册/恢复管理双证明与双域关联双证明. |
| `evidence.go` | 访问证据包组装, 绑定摘要复算, 固定高度 `SnapshotView` 端到端校验与 B1 静态签名缓存. |
| `contexts/vc-v2.json` | 离线固定 SHA-256 的 W3C VC v2 基础上下文副本. |

## 模块边界与不变量

- `grad/protocol/registry` 必须保持**零第三方依赖** (仅导入 Go 标准库), 以便 `chaincode/` 在 Fabric 链码容器中直接复用而无需拉入 `go-jose` 或测试框架.
- 根包 `grad/protocol` 复用 `registry.Management`, `registry.DeploymentFields`, `registry.IssuerScope` 等共享类型, 禁止重复定义同类结构或引入历史短资源别名 (`"quotes"`, `"urn:grad:resource:quotes"` 等).
- 校验逻辑坚持 fail-closed: 拒绝重复 JSON 键, 未知字段, 超过 `2^53-1` 的数值, 超过 `256 KiB` 的载荷, 非规范 base64url, 非曲线点及非规范资源 URI.
- B1 `SignatureCache` 仅缓存静态 JWS 数学验签结果, 绝不缓存或跳过任何动态链上状态 (`Status`, `KeyVersion`, `Certification`, `ClaimNames`, `Interval`, KB-JWT 绑定).

## 验证命令

从仓库根目录运行协议检查.

```bash
mise run test:vet
mise run test:race -- -v -count=1 grad/protocol/...
mise run test:arch
```

`test:arch` 核对 `grad/protocol/registry` 的传递依赖均为 Go 标准库.
