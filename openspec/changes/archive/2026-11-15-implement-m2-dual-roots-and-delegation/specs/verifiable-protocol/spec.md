# verifiable-protocol Specification

## MODIFIED Requirements

### Requirement: 访问证据包与持有者绑定核验

访问出示 SHALL 组装包含 `request`, `taskSpec`, `challengeId`, `leafPresentation`, `ancestorCredentials`, `grants` 和 `trustPaths` 的 `AccessEvidencePackage`. 叶子持有者 SHALL 使用当前 `authentication` 密钥签发 `KB-JWT` (`typ="kb+jwt"`), 绑定受众 `aud`, 原样挑战 `nonce`, 签发时间 `iat`, `leafPrefix` 的无填充 base64url `sd_hash`, 以及 `urn:grad:binding` 中的 `{challengeId, requestHash, chainHash, evidenceHash}`. 验证端 SHALL 在同一固定高度快照上核对从 T 根到三域认证与本域主体凭证的完整信任路径, `RESOURCE_PREAUTHORIZED` (`C` 根) 或 `BUYER_MANDATE` (`A` 域当前有效 `PA` 根) 的根权源资格, 从 `G0 -> G1 -> G2` 逐跳不扩张且连续的委托链, `taskSpecDigest` 和持有者绑定, 任一字段, 模式或字节被篡改时 SHALL 拒绝出示.

#### Scenario: 在固定高度快照上核验完整访问出示

- **WHEN** 持有者基于当前部署的已登记夹具, 有效挑战 `nonce` 和固定高度快照构造 `AccessEvidencePackage` 与 `KB-JWT`
- **THEN** 验证端复算的 `requestHash`, `chainHash`, `evidenceHash` 和 `sd_hash` 与 `KB-JWT` 完全一致, T 根, 域认证, 祖先与叶子凭证, 任务及委托链在同一快照高度上全部核验通过

#### Scenario: 在固定高度快照上核验 RP 与 BM 两级委托访问出示

- **WHEN** 叶子主体 `B1` 基于当前部署的已登记夹具, 有效挑战 `nonce`, 去重后的 A/B/C 三域 `trustPaths`, 祖先最小出示以及逐跳收缩的 `G0 -> G1 -> G2` (`500000 -> 500000 -> 100000`, 剩余深度 `2 -> 1 -> 0`) 分别构造 RP 与 BM 两种模式的 `AccessEvidencePackage` 与 `KB-JWT`
- **THEN** 验证端复算的 `requestHash`, `chainHash`, `evidenceHash` 和 `sd_hash` 与 `KB-JWT` 完全一致, T 根, 三域认证, `PA`/`C` 根服务与祖先/叶子凭证, 任务及三级委托链在同一快照高度上全部核验通过

#### Scenario: 拒绝越权收缩, 兄弟拼接, 模式混用或非法根签发者

- **WHEN** 请求分别提交子授权额度/动作/期限扩张或深度未递减的委托链, 拼接兄弟分支凭证, 混用 `RESOURCE_PREAUTHORIZED` 与 `BUYER_MANDATE` 模式, 或使用无采购根资格的身份 (如 `IA`, 非当前 `PA` 或在 RP 下使用 `PA`) 签发 `G0`
- **THEN** 验证端确定性返回 `DELEGATION_EXPANSION`, `PATH_INVALID`, `AUTHORIZATION_MODE_MISMATCH` 或 `ROOT_AUTHORITY_INVALID` 并拒绝整次出示

#### Scenario: 篡改证据包或绑定摘要任一字段必被拒绝

- **WHEN** 分别篡改 `request` 字段, `taskSpec`, `challengeId`, `nonce`, `leafPresentation` 披露或签名, `ancestorCredentials` 顺序或内容, `grants` 字节, `trustPaths` 认证字节, 或跨部署复用旧证据包
- **THEN** 每次篡改均被签名校验, 摘要绑定或链上锚点比对确定性拒绝
