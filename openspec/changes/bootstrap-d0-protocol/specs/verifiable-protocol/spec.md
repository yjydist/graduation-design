# 可验证协议增量规范

## Purpose

为跨域身份认证与采购委托提供确定性的字节编码, 本地固定的 W3C VC v2 上下文, 基于受信 CA 的 `did:web` 解析, 以及 ES256 域认证, SD-JWT 身份凭证, 委托 JWS 与 `KB-JWT` 访问证据包的生成, 固定高度锚点比对和篡改拒绝.

## ADDED Requirements

### Requirement: 规范编码与静态向量复算

协议实现 SHALL 使用 `grad-auth-v1` 严格解析 UTF-8 JSON, 拒绝重复键, 未知业务字段, 超过 `2^53-1` 的整数, 非法集合及超过 256 KiB 的输入, 并按 RFC 8785 JCS 计算 SHA-256 小写 hex 摘要. 系统 SHALL 按固定规则转换 65 字节 P-256 非压缩公钥与 JWK 坐标, 按 RFC 7638 计算公钥指纹, 并强制挑战 `nonce` 为严格解码 32 字节且重编码逐字相等的 43 字符无填充 base64url 字符串. 实现 SHALL 精确复算已发布的 DID/JWK, `nonce`, `taskSpecDigest`, 订单/询价 `requestHash` 及管理双证明向量.

#### Scenario: 复算静态编码与签名测试向量

- **WHEN** 对编码契约中的 DID 文档, 连续 32 字节 `nonce`, `taskSpec`, 800 元与 1200 元订单请求, 询价请求及部署绑定管理双证明运行复算
- **THEN** 计算出的 `didDocumentDigest`, `appPublicKey`, JWK 指纹, 43 字符 `nonce`, `taskSpecDigest`, 三个 `requestHash`, `deploymentId`, `challengeSha256` 及双证明验签结果与已发布向量逐字一致
- **AND** 修改挑战中的 `deploymentId` 或 `nonce` 后, 管理证明与应用证明验证均失败

#### Scenario: 拒绝非规范 JSON 与非法挑战 nonce

- **WHEN** 输入包含重复 JSON 键, 未知字段, 重复集合元素, 带 `=` 填充的 `nonce`, 非 base64url 字符, 或重编码不相等的 43 字符末位变形 (如末字符 `8` 改为 `9`)
- **THEN** 解析器直接返回 schema 校验错误, 不自动修正或宽松接受非规范字节

### Requirement: 本地上下文固定与 did:web 解析

系统 SHALL 内置固定顺序的凭证 `@context` 数组 `["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://grad-auth.example.test/vocab#"}]`, 随部署依赖固定基础 VC v2 上下文本地副本的 SHA-256 摘要, 并在离线状态下完成上下文校验. `did:web` 解析器 SHALL 通过受信 CA 校验 HTTPS 服务端证书链与主机名, 要求响应类型为 `application/did+json`, 按 JCS 复算并核对链上 `didDocumentDigest`, 且仅提取登记 `appKeyId` 对应的 P-256 `publicKeyJwk` 并验证 `authentication` 或 `assertionMethod` 用途. T 根 DID 文档 SHALL 从核对过摘要的预置本地副本加载并支持同规则在线核验.

#### Scenario: 通过测试 CA 解析并核验 did:web 文档

- **WHEN** 解析器使用预置测试 CA 访问受控 `did:web` HTTPS 主机获取主体 DID 文档, 或加载预置 T 根 DID 文档副本
- **THEN** TLS 证书链与主机名校验通过, 文档 JCS 摘要与链上 `RootRecord` 或 `IdentityRecord` 的 `didDocumentDigest` 一致
- **AND** 解析出的 `appKeyId`, `controller`, P-256 公钥坐标及方法用途与链上登记的 `appPublicKey` 和 `appKeyVersion` 完全匹配

#### Scenario: 拒绝不可信 TLS, 篡改文档或非法凭证上下文

- **WHEN** `did:web` 端点使用非受信 CA 证书, 主机名不匹配, 明文 HTTP, 篡改后的 DID JSON, 缺失所需密钥用途, 或凭证携带不相等的 `@context` 及被篡改的本地基础上下文副本
- **THEN** 验证立即失败并返回对应错误码, 不跟随外部密钥引用且不发起外部网络下载

### Requirement: 域认证, 身份凭证与采购委托签名核验

系统 SHALL 使用 ES256 和登记的 `appKeyId` 签发并核验三类协议材料: T 签发的 `DomainAuthorityCredential` (`typ="vc+jwt"`), IA/IB/IC 签发的 `EnterpriseIdentityCredential` (`typ="vc+sd-jwt"`, `domain` 与 `role` 作为 `credentialSubject` 内独立带盐披露), 以及签发者签发的 `Grant` (`typ="grad-delegation+jwt"`). 域认证与委托的链上锚定摘要 SHALL 为原始 compact JWS 的 `SHA256(ASCII(compactJws))`; SD-JWT 身份凭证的链上锚定摘要 SHALL 仅覆盖不含披露与 `KB-JWT` 的 `issuer-signed compact JWT`. 验证端 SHALL 对照同一高度快照核对签发者资格, 主体归属, 密钥版本, 有效区间, `deploymentId`, `cnf.jwk` 指纹及父子委托关系.

#### Scenario: 签发并核验绑定当前部署的三类签名材料

- **WHEN** 基于当前 Fabric 部署的 `deploymentId` 和真实角色私钥签发 A/B/C 域认证, U/A1/B1/C 身份凭证及 RP `G0`/`G1` 委托, 并将其锚定摘要登记上链
- **THEN** 链上登记的 `Certification`, `Credential` 和 `Grant` 摘要与链下签名材料计算的锚定摘要完全一致
- **AND** 验证端使用同一高度快照与解析出的签发者 `assertionMethod` 公钥验签通过, 正确还原披露的 `domain` 与 `role`

#### Scenario: 拒绝披露不匹配, 锚定摘要失配或越界签发

- **WHEN** SD-JWT 缺失必需的 `domain`/`role` 披露, 包含重复或未被引用的披露, 篡改任一披露盐或声明值, 改变 compact JWS 字节导致与链上摘要不符, 或引用非当前有效版本与越界声明范围
- **THEN** 签名或锚点核验拒绝该材料, 不产生有效身份或委托结论

### Requirement: 访问证据包与持有者绑定核验

访问出示 SHALL 组装包含 `request`, `taskSpec`, `challengeId`, `leafPresentation`, `ancestorCredentials`, `grants` 和 `trustPaths` 的 `AccessEvidencePackage`. 叶子持有者 SHALL 使用当前 `authentication` 密钥签发 `KB-JWT` (`typ="kb+jwt"`), 绑定受众 `aud`, 原样挑战 `nonce`, 签发时间 `iat`, `leafPrefix` 的无填充 base64url `sd_hash`, 以及 `urn:grad:binding` 中的 `{challengeId, requestHash, chainHash, evidenceHash}`. 验证端 SHALL 在同一固定高度快照上核对从 T 根到叶子的完整信任路径, 委托链, `taskSpecDigest` 和持有者绑定, 任一字段或字节被篡改时 SHALL 拒绝出示.

#### Scenario: 在固定高度快照上核验完整访问出示

- **WHEN** 持有者基于当前部署的已登记夹具, 有效挑战 `nonce` 和固定高度快照构造 `AccessEvidencePackage` 与 `KB-JWT`
- **THEN** 验证端复算的 `requestHash`, `chainHash`, `evidenceHash` 和 `sd_hash` 与 `KB-JWT` 完全一致, T 根, 域认证, 祖先与叶子凭证, 任务及委托链在同一快照高度上全部核验通过

#### Scenario: 篡改证据包或绑定摘要任一字段必被拒绝

- **WHEN** 分别篡改 `request` 字段, `taskSpec`, `challengeId`, `nonce`, `leafPresentation` 披露或签名, `ancestorCredentials` 顺序或内容, `grants` 字节, `trustPaths` 认证字节, 或跨部署复用旧证据包
- **THEN** 每次篡改均被签名校验, 摘要绑定或链上锚点比对确定性拒绝
