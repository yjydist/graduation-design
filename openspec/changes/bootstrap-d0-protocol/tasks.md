# 实施任务

本清单交付 D0 最小协议实现及绑定当前 Fabric 部署的验证证据. 机制见 [设计](design.md), 行为验收依据为 [可验证协议](specs/verifiable-protocol/spec.md), [授权登记](specs/authorization-registry/spec.md) 和 [许可账本](specs/permissioned-ledger/spec.md).

## 1. 规范编码与静态测试向量

- [ ] 1.1 实现 `grad-auth-v1` 严格 JSON 解析器与 RFC 8785 JCS 规范化函数, 拒绝重复键, 未知业务字段, 超过 `2^53-1` 的整数, 非法集合和超过 256 KiB 的输入, 运行单元测试验证正反例通过.
- [ ] 1.2 实现 P-256 65 字节非压缩点 (`appPublicKey`), `publicKeyJwk` 坐标转换与 RFC 7638 JWK 指纹计算, 以及 DID 文档严格解析与 `didDocumentDigest` 计算, 用单元测试复算 [协议编码与测试向量](../../../docs/implementation/协议编码与测试向量.md#14-did文档-公钥与凭证上下文编码) 中的固定 DID/JWK 向量 (`e08e529f...`, `xx0BcA-w...`, `046b17d1...`) 并验证非曲线点, 压缩点和额外字段被拒绝.
- [ ] 1.3 实现挑战 `nonce` 生成与 43 字符无填充 base64url 严格校验, 复算连续 32 字节固定向量 (`AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8`), 用单元测试验证 `=` 填充, 非法字符及重编码不相等的末字符变形 (`8` 改 `9`) 均返回 schema 错误.
- [ ] 1.4 实现 `taskSpec` 与访问 `request` 的结构校验及 JCS 摘要计算, 用单元测试复算 `taskSpecDigest` (`430541fe...`), 800 元订单 `requestHash` (`ebaa3f79...`), 1200 元订单 `requestHash` (`9ed920b6...`), 询价 `requestHash` (`bb00c19d...`) 以及管理证书双证明向量 (`5fe902e9...`, `29d51c58...`).

## 2. 本地 VC v2 上下文固定与测试 CA did:web 解析

- [ ] 2.1 内置 W3C VC v2 基础上下文规范本地副本并固定其 SHA-256 摘要, 校验凭证 `@context` 数组严格等于 `["https://www.w3.org/ns/credentials/v2", {"@vocab": "https://grad-auth.example.test/vocab#"}]`, 用单元测试验证上下文篡改, 次序错误或非内置项返回 `INVALID_SCHEMA` 且无外部网络请求.
- [ ] 2.2 实现测试 CA 根证书与服务端 TLS 证书生成, 为 `t.local`, `a.local`, `b.local`, `c.local` 启动本地受控 HTTPS `did:web` 服务并挂载 `application/did+json` 文档, 实现绑定测试 CA 的 `did:web` 解析器与 T 根本地预置文档校验.
- [ ] 2.3 为 `did:web` 解析器编写单元测试, 验证 `.well-known/did.json` 与路径式 DID URL 映射, TLS 证书链与主机名校验, `didDocumentDigest` 比对, `appKeyId` 版本及 `authentication`/`assertionMethod` 用途检查, 并覆盖非受信 CA, 主机名失配, 明文 HTTP, 篡改文档和缺失用途负例.

## 3. 域认证, SD-JWT 身份凭证, 采购委托与访问证据包

- [ ] 3.1 实现 `DomainAuthorityCredential` (`typ="vc+jwt"`) 的 ES256 签发, 原始 compact JWS 锚定摘要 (`SHA256(ASCII(compactJws))`) 计算及结构校验, 用单元测试验证 T 根签名, `identityIssuers` 字典序有限范围及与链上 `DomainRecord`/`Certification` 的一致性.
- [ ] 3.2 实现 `EnterpriseIdentityCredential` (`typ="vc+sd-jwt"`) 的签发, `domain` 与 `role` 独立带盐披露构造, `_sd` 字典序摘要排序及不含披露与 `KB-JWT` 的 `issuer-signed compact JWT` 锚定摘要计算, 用单元测试验证选择性披露还原, `cnf.jwk` 指纹匹配, 缺失必需披露和未引用/重复披露拒绝.
- [ ] 3.3 实现 `Grant` (`typ="grad-delegation+jwt"`) 的 ES256 签发与验证, 校验 `parentId`, `parentDigest`, `rootId`, `taskId`, `authorizationMode`, 双方密钥版本与凭证引用, 资源/动作/供应商集合, `maxAmountMinor`, 有效区间与 `remainingDepth`, 用单元测试覆盖正反例.
- [ ] 3.4 实现 `AccessEvidencePackage` 与 `KB-JWT` (`typ="kb+jwt"`) 的组装与固定高度快照核验, 复算 `requestHash`, `chainHash`, `evidenceHash` 和 `sd_hash`, 用单元测试验证完整信任路径与委托链核验通过, 且篡改 `request`, `taskSpec`, `challengeId`, `nonce`, `leafPresentation`, `ancestorCredentials`, `grants` 或 `trustPaths` 任一字段必失败.

## 4. Fabric D0 真实夹具绑定与集成验收

- [ ] 4.1 升级 `bootstrap` 与 `seed` 在 `<instance>/private/` 持久化 T 根与各角色的 P-256 应用私钥及测试 TLS 私钥, 在 `<instance>/registry/` 保存公开 DID 文档, 测试 CA 根证书, 本地上下文摘要清单与真实签发的域认证, SD-JWT 凭证, `taskSpec`, `G0`/`G1` 委托和示例访问出示包, 使链上登记全部锚定真实协议摘要.
- [ ] 4.2 扩展 `ledgerctl verify` 与 `publicMaterials`, 在保留原有 17 项通道, 链码, 事务恢复和视图探针验收的基础上, 新增静态编码与向量复算, 测试 CA `did:web` 与本地上下文固定, 以及绑定当前部署的真实签名出示与单字段篡改拒绝验收用例, 并确认导出的公开证据目录不含任何私钥.
- [ ] 4.3 在当前 Fabric 实例和干净重建的独立实例上完整运行 `mise run test:unit` 与 `mise run ledger:verify`, 保存 D0 最小协议验收证据并更新 [任务安排与退出条件](../../../TODO.md), [网络与复跑说明](../../../infra/fabric/README.md) 及 [Fabric 证据索引](../../../infra/fabric/evidence/README.md).

## 工作流后续

- 运行 `/openspec-verify-change` 核验全部实现, 测试与实机证据, 同步主规范后归档 `bootstrap-d0-protocol`.
