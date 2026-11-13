# 变更提案

## 为什么

Fabric D0 最小网络已锁定单通道, 三域 Peer, 四 SmartBFT 排序节点, Go 登记链码及固定高度状态视图, 但当前引导与夹具仍使用丢弃私钥的临时公钥和合成字符串摘要. 在进入 M1 直接访问前, 必须在已锁定的 Fabric 部署和 T 根基础上补齐规范编码, 本地 VC v2 上下文摘要固定, 测试 CA 的 `did:web` 解析, 以及真实 ES256/VC/SD-JWT/委托/KB-JWT 签名与出示核验, 使链上登记锚点与链下可验证协议材料逐字节绑定. [阶段任务](../../../TODO.md), [协议编码与测试向量](../../../docs/implementation/协议编码与测试向量.md).

## 变更内容

- 实现 `grad-auth-v1` 规范编码与静态向量复算, 包含 RFC 8785 JCS 规范化, 严格 JSON 输入校验, P-256 `appPublicKey` 与 RFC 7638 JWK 指纹转换, 43 字符无填充 base64url 挑战 `nonce` 校验, 以及 DID 文档, `taskSpec`, 询价/下单 `requestHash` 和管理双证明固定向量验证.
- 固定 W3C VC v2 基础上下文 (`https://www.w3.org/ns/credentials/v2`) 本地副本摘要与项目内联 `@vocab` 扩展上下文, 拒绝任何不匹配的 `@context` 或在线上下文下载; 使用测试 CA 为本地受控 `did:web` 主机签发服务端 TLS 证书, 验证 HTTPS 解析, `didDocumentDigest`, `appKeyId` 版本及密钥用途, 并核对预置 T 根 DID 文档副本.
- 实现三类真实签名材料与访问出示包: T 签发的 `DomainAuthorityCredential` (`typ="vc+jwt"`), IA/IB/IC 签发的 `EnterpriseIdentityCredential` (`typ="vc+sd-jwt"`, `domain` 与 `role` 独立带盐披露), C/U 签发的采购委托 `Grant` (`typ="grad-delegation+jwt"`), 以及绑定挑战 `nonce`, `sd_hash` 和四项业务/证据哈希的 `AccessEvidencePackage` 与 `KB-JWT` (`typ="kb+jwt"`).
- **BREAKING** 将 `ledgerctl` 的 `bootstrap` 与 `seed` 夹具升级为真实 P-256 应用密钥和真实签名协议材料: 应用私钥与测试 TLS 私钥保存在实例私有目录并严格排除在公开证据导出之外, 链上 `RootRecord`, 域认证, 身份与凭证锚, 任务及 `G0`/`G1` 均登记真实紧凑字节或 JCS 摘要, 并在同一高度视图上完成出示核验与单字段篡改必败验收.

## 能力

### 新增能力

- `verifiable-protocol`: 定义 JCS 严格编码与测试向量复算, 本地固定 VC v2 上下文摘要, 基于测试 CA 的 `did:web` HTTPS 解析与 DID/JWK 校验, 以及域认证 JWS, 身份凭证 SD-JWT, 采购委托 JWS 和 `AccessEvidencePackage`/`KB-JWT` 的签发, 锚定比对与篡改拒绝.

### 修改能力

- `authorization-registry`: 将 D0 根初始化与 RP 登记夹具的摘要来源从合成占位字符串更新为绑定当前部署的真实 DID 文档, 域认证, SD-JWT 凭证, `taskSpec` 与委托签名摘要.
- `permissioned-ledger`: 明确实例私有应用密钥与测试 CA/TLS 私钥的隔离保存规则, 公开运行材料与证据归档包含可复核的公开协议材料并继续排除全部私钥.

## 影响

- 新增协议编码与可验证凭证 Go 实现包, 扩展 `internal/fabricapi` 和 `internal/fabric` 的引导, 夹具生成与 `ledgerctl verify` 验收用例.
- 复用现有 Go 标准库 (`crypto/ecdsa`, `crypto/elliptic`, `crypto/tls`, `crypto/x509`, `net/http`) 完成 ES256, SD-JWT 与测试 CA `did:web` 验证, 无需引入破坏构建确定性的外部重型依赖.
- 验收通过后同步更新 [任务安排与退出条件](../../../TODO.md) 和 [Fabric 证据索引](../../../infra/fabric/evidence/README.md) 的 D0 最小协议证据记录. M1 的 OPA 策略求值, 挑战消费事务及报价/订单服务留在下一阶段变更实施.
