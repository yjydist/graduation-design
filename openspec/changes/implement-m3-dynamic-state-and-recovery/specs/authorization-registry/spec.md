# authorization-registry Specification

## ADDED Requirements

### Requirement: 域资格续发, 收缩, 撤销与 T 离线可用性

系统 SHALL 支持 T 管理身份原子续发, 同钥收缩声明范围与换钥重认证当前域认证 (`CertifyDomain`, 核对 `expectedRevision` 与 `expectedCertificationId`), 支持更新或恢复非终态域 DID 与身份机构引导身份 (`UpdateAuthorityIdentity`), 并支持 T 撤销指定域认证 (`RevokeCertification`) 或暂停/恢复/撤销域状态 (`SetDomainStatus`). 域认证或域状态置为 `REVOKED` SHALL 为不可逆终态; 暂停域仅可在其当前认证仍有效时恢复. 已完成本地预置 T 根 DID 文档与当前域认证正文交付后, 在线材料准备与业务验证期间对 T 的在线调用数 SHALL 为 `0`, 当前认证指针有效但本地正文缺失时 SHALL 返回 `503 MATERIAL_NOT_SYNCED`.

#### Scenario: T 原子续发域认证与 IB 换钥后重新认证

- **WHEN** T 对同一机构, 密钥和范围原子续发新 `certificationId` 并推进域 `revision`, 或对 `IB` 换钥后更新引导身份并重新签发域认证
- **THEN** 同钥续发在替换旧认证后可凭新认证材料直接核验原有效凭证与委托且不延长其到期时间, 原子替换竞争冲突不产生半改配置
- **AND** `IB` 换钥未重认证前引用旧版本的出示被拒绝, `T` 完成重认证且重签引用旧版本的凭证与委托后正例通过

#### Scenario: T 撤销或暂停域资格及 T 离线本地核验

- **WHEN** T 撤销 B 域认证或暂停/恢复 B 域, 或在已持久化域认证后停止 T 服务与 DID 主机再执行合法采购
- **THEN** B 域认证撤销后依赖 B 的路径返回 `403 DOMAIN_CERTIFICATION_INVALID` 而 A/C 独立路径仍可用, B 域暂停返回 `403 DOMAIN_INACTIVE` 且有效认证未到期时可恢复, 撤销域不可恢复且期间仅允许原管理者撤销既有凭证或委托
- **AND** T 离线期间依赖本地副本且资格与探针有效时采购成功并记录 T 在线调用数为 `0`, 本地缺当前认证正文时返回 `503 MATERIAL_NOT_SYNCED` 且不回退旧认证

### Requirement: 普通身份状态管理, 密钥轮换与管理账户恢复

系统 SHALL 支持普通身份 (`USER`/`AGENT`/`SERVICE`) 状态转换 (`SetIdentityStatus`: `ACTIVE <-> SUSPENDED -> REVOKED`), 应用密钥轮换 (`RotateIdentity`, 仅本人当前管理账户在有效域下递增 `appKeyVersion`) 与普通管理账户恢复 (`RecoverIdentity`), 以及凭证撤销 (`RevokeCredential`), 任务取消 (`CancelTask`) 和委托暂停/恢复 (`SuspendGrant`/`ResumeGrant`). 普通身份暂停或撤销 SHALL 仅允许本人当前管理账户或本域当前注册机构发起, 从 `SUSPENDED` 恢复为 `ACTIVE` SHALL 仅允许本域当前注册机构发起, 域 DID 与身份机构引导身份 SHALL 仅允许 T 管理, 非法状态转换或自 `REVOKED` 变更 SHALL 返回 `409 IDENTITY_STATE_CONFLICT`.

#### Scenario: 普通身份暂停, 恢复与撤销的角色权限边界

- **WHEN** 本人管理账户或本域注册机构暂停普通身份后, 分别由本人, 域管理员, 跨域注册机构和本域注册机构尝试恢复该身份, 以及本域机构尝试管理 `IA`/`IB`/`IC` 状态或操作已撤销身份
- **THEN** 非本域当前注册机构恢复普通身份或非 T 管理引导身份均返回 `403 IDENTITY_MANAGEMENT_FORBIDDEN` 或被链码提案拒绝, 只有本域当前注册机构可恢复有效域下的暂停普通身份
- **AND** 同状态重复转换或对 `REVOKED` 身份发起状态变更, 轮换或同 DID 重注册均返回 `409 IDENTITY_STATE_CONFLICT`

#### Scenario: 普通身份管理账户恢复双证明与原状态保留

- **WHEN** 普通身份原管理私钥丢失, 本域注册机构核验原账号承诺并签发 `grad-identity-recovery-v1` 挑战, 提交新应用密钥与新管理证书双证明完成 `RecoverIdentity`, 分别针对 `ACTIVE` 与 `SUSPENDED` 原身份以及并发修改 `revision` 场景测试
- **THEN** 缺任一证明, 换主体/证书/部署/版本, 复用已消费挑战或在域资格失效时提交均被拒绝; 有效恢复原子切换 `managementIdentity` 并递增 `revision` 与 `appKeyVersion`, 旧管理证书与旧版本凭证/关联/委托立即失效
- **AND** 原为 `SUSPENDED` 的身份恢复管理账户后仍保持 `SUSPENDED`, 须由本域注册机构另行恢复状态并重新签发材料后方可访问

- **AND** 普通管理账户恢复 SHALL 由本域当前注册机构重新核验原域内账号承诺, 签发绑定 `purpose="grad-identity-recovery-v1"` 的 300 秒内一次性恢复挑战, 并核验新应用密钥 ES256 JWS 与新管理证书 P-256 ECDSA 双证明后提交链码原子替换 `managementIdentity`, `didDocumentDigest` 与应用公钥, 递增 `revision` 和 `appKeyVersion` 并保留原 `status`.

#### Scenario: 委托暂停恢复, 原子替换改派 B2 与任务取消

- **WHEN** 对同一有效链先后执行委托 `G1` 暂停与恢复, 由 `A1` 原子替换 `G2` 改派给 `B2`, 撤销叶子 `VC`, 以及取消采购任务 (`CancelTask`)
- **THEN** 暂停期间旧路径在采用变更块后被拒绝 (`GRANT_INACTIVE`/`ANCESTOR_INACTIVE`), 恢复后保持原 `exp` 并重新可用; 原子替换使旧 `G2` 终态撤销且 `B1` 旧路径被拒, `B2` 凭新 `G2'` 与本人 `Q800` 可下单
- **AND** 任务取消后进入不可逆 `CANCELLED` 终态并返回 `409 TASK_STATE_CONFLICT` 拒绝重复取消, 凭证撤销后依新高度拒绝使用该凭证的访问

## MODIFIED Requirements

### Requirement: 管理交易确认与失败证据

系统 SHALL 在首次提交前持久化原操作键, 输入摘要, txID 及已签交易, 将结果绑定调用者, 通道和链码. 接受前预检发现 `expectedRevision` 过时 SHALL 同步返回 `409 STATE_CHANGED` 且不生成待提交 `operations` 或提案; 已受理请求 SHALL 返回 `202` 与原 `operationId`, 同操作键同摘要精确重试 SHALL 仍以 `202` 返回原 `operationId` (即使原操作已失败), 同键异摘要 SHALL 返回 `409 IDEMPOTENCY_CONFLICT`. 查询 `GET /v1/operations/{id}` SHALL 返回 `HTTP 200` 与 `PENDING`/`CONFIRMED`/`FAILED`, 并映射具体提案拒绝, `ENDORSEMENT_REJECTED`, `STATE_CHANGED` (`MVCC_READ_CONFLICT`) 或 `COMMIT_INVALID`. 只有 Peer 提交校验为 VALID SHALL 确认登记并允许后续交付. 入块结果 SHALL 记录原区块标识, 交易位置及校验码. 具体失败原因 SHALL 由原提案响应或原提交校验码支持, 不以事后模拟补判.

#### Scenario: 有效提交确认

- **WHEN** 合法操作取得背书和提交接收响应, 随后由可信 Peer 观测到 VALID
- **THEN** 核对 txID, 调用者, 通道, 链码和区块位置后才将操作从 PENDING 改为 CONFIRMED, 开放后续依赖步骤

#### Scenario: 区分提案拒绝与入块无效

- **WHEN** 分别遇到可核对的原提案拒绝, MVCC_READ_CONFLICT 或无可细分原因的非 VALID 提交结果
- **THEN** 记录对应阶段及原始证据, MVCC 冲突报告 STATE_CHANGED, 无法细分的入块无效使用通用失败码
- **AND** 所有失败均不触发材料交付

#### Scenario: 提交结果暂不可见或出现重复提交

- **WHEN** 原提交响应或提交状态暂不可见, 操作进程恢复或客户端以同操作键重试
- **THEN** 保持 PENDING, 查同一 txID 或重投原已签字节, 不生成替代交易
- **AND** 同键异输入冲突, 重投引发的重复交易不能覆盖原交易的有效提交结论

#### Scenario: 受理前版本冲突预检与受理后异步操作状态查询

- **WHEN** 普通身份换钥或状态操作先提交过时 `expectedRevision`, 再使两笔不同操作键通过同一有效版本预检并取得背书后在 `202` 后广播, 以及在 `202` 后隐藏提交结果并在恢复可信 Peer 查询前后查询状态与重试
- **THEN** 受理前过时版本返回 `409 STATE_CHANGED` 且无待提交操作; 两笔背书竞争经 `GET /v1/operations/{id}` 均返回 `HTTP 200`, 胜出者为 `CONFIRMED`/`failureCode=null`, 冲突者为 `FAILED`/`STATE_CHANGED` (`MVCC_READ_CONFLICT`) 且无材料交付
- **AND** 暂不可见结果时查询返回 `200 PENDING/null`, 恢复查询后准确反映原提案拒绝或入块校验阶段及 `ENDORSEMENT_REJECTED`/`COMMIT_INVALID`, `DUPLICATE_TXID` 不覆盖原结果, 同键同正文重试返回 `202` 原 `operationId`, 同键异正文返回 `409 IDEMPOTENCY_CONFLICT`
