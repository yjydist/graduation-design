# Spec Delta: verifiable-protocol

## MODIFIED Requirements

### Requirement: 规范编码与静态向量复算

协议实现 SHALL 使用 `grad-auth-v1` 严格解析 UTF-8 JSON, 拒绝重复键, 未知业务字段, 超过 `2^53-1` 的整数, 非法集合及超过 256 KiB 的输入, 并按 RFC 8785 JCS 计算 SHA-256 小写 hex 摘要. 系统 SHALL 按固定规则转换 65 字节 P-256 非压缩公钥与 JWK 坐标, 按 RFC 7638 计算公钥指纹, 并强制挑战 `nonce` 为严格解码 32 字节且重编码逐字相等的 43 字符无填充 base64url 字符串. 协议与登记域模型 SHALL 共享唯一一份规范错误码表与对象结构定义, 访问请求 `resource` 字段 SHALL 仅接受规范资源 URI (`urn:grad:resource:C:quotes` 与 `urn:grad:resource:C:orders`), 不再接受历史短别名. 实现 SHALL 精确复算同步更新后的 DID/JWK, `nonce`, `taskSpecDigest`, 订单/询价 `requestHash` 及管理双证明向量.

#### Scenario: 复算静态编码与签名测试向量

- **WHEN** 对编码契约中的 DID 文档, 连续 32 字节 `nonce`, `taskSpec`, 使用规范资源 URI 的 800 元与 1200 元订单请求, 询价请求及部署绑定管理双证明运行复算
- **THEN** 计算出的 `didDocumentDigest`, `appPublicKey`, JWK 指纹, 43 字符 `nonce`, `taskSpecDigest`, 三个 `requestHash`, `deploymentId`, `challengeSha256` 及双证明验签结果与发布向量逐字一致
- **AND** 修改挑战中的 `deploymentId` 或 `nonce` 后, 管理证明与应用证明验证均失败

#### Scenario: 拒绝非规范 JSON 与非法挑战 nonce

- **WHEN** 输入包含重复 JSON 键, 未知字段, 重复集合元素, 带 `=` 填充的 `nonce`, 非 base64url 字符, 或重编码不相等的 43 字符末位变形 (如末字符 `8` 改为 `9`)
- **THEN** 解析器直接返回规范 schema 校验错误码, 不自动修正或宽松接受非规范字节

#### Scenario: 拒绝历史资源短别名

- **WHEN** 访问请求使用历史资源短别名 (如 `"quotes"` 或 `"urn:grad:resource:quotes"`) 而非规范资源 URI
- **THEN** 请求校验直接返回规范 schema 校验错误码, 不接受历史别名
