# authorization-registry Specification

## Purpose

提供基于固定 T 根和 X.509 客户端身份的 Fabric 授权登记. 真实管理交易建立 RP 委托夹具, 通过原提案响应和 Peer 提交校验分别核对拒绝, 有效提交, 入块无效及未知结果.

## Requirements

### Requirement: 固定根与最小登记路径

登记系统 SHALL 以经三域批准的清单执行一次受限初始化, 固定并只读暴露 RootRecord, instanceId 及 A 域/U 的任务创建资格. 系统 SHALL 通过调用者的 MSPID 和 X.509 客户端证书指纹匹配登记角色, 提供 T 对 A/B/C 域与 IA/IB/IC 的引导及首份域认证, 本域管理员配置 PA 的 `purchasingAuthority` 资格, 经注册挑战与双证明校验的本域身份与凭证锚, U 创建 RP/BM 任务, `C`/`PA` 签发对应根授权 `G0` 以及 `G1`/`G2` 子委托登记. U 创建任务 SHALL 检查其当前管理身份, 主体归属, 域认证及引用凭证的状态, 版本和期限. 系统 SHALL 拒绝绕过角色约束及运行期改变根或任务创建资格的操作.

#### Scenario: 受限初始化

- **WHEN** 普通通道客户端尝试抢先初始化, 或受信初始化方提交偏离已批准清单的根或任务创建资格
- **THEN** 提案被拒绝, 根记录不被占用
- **AND** 合法初始化提交为 VALID 后, 再次初始化不能更改任一固定字段

#### Scenario: 初始化提案中断后续跑

- **WHEN** 首次初始化的提案和 txID 已保存, 但背书前中断并在恢复时被明确拒绝
- **THEN** 系统 SHALL 保留原操作, 提案, txID 和拒绝结果
- **AND** 仅在操作者显式请求, 原操作未生成已签交易且可信 Peer 确认根仍为空时, 系统 SHALL 用新操作键提交原批准清单

#### Scenario: 根已有效提交后恢复部署清单

- **WHEN** 初始化原交易已有效提交, 但在写出部署清单前中断
- **THEN** 续跑核对可信 Peer 的原交易及根记录, 使用原安装包及原初始化区块恢复部署清单
- **AND** 已有重复初始化验证操作保持原结果, 重复初始化拒绝由验收单独检查

#### Scenario: 按角色建立 RP 夹具

- **WHEN** T 引导 A/C 域和 IA/IC 并登记首份认证, 各域获准调用者登记 U, PA, A1, C 服务及凭证锚, U 创建任务, C 登记交给 U 的 G0, U 登记交给 A1 的 G1
- **THEN** 每一步在依赖满足状态, 当前指针, 密钥版本和期限规则时才能有效提交, 最终 G0/G1 均为 ACTIVE
- **AND** 根, 身份, 域认证, 凭证锚, 任务及 G0/G1 的链上摘要均由绑定当前部署的真实 DID 文档, ES256/SD-JWT 签名材料与 `taskSpec` 计算并可在同一高度视图复核

#### Scenario: 按角色建立 RP 与 BM 三域多级夹具

- **WHEN** T 引导 A/B/C 域和 IA/IB/IC 并登记首份认证, A 域管理员设置 PA 的 `purchasingAuthority` 资格, 各域获准调用者登记 U, PA, A1, B1, U-in-B, C 服务及凭证锚, U 分别创建 RP 与 BM 任务, C 或当前有效 PA 登记交给 U 的 G0, U 登记交给 A1 的 G1, A1 登记交给 B1 的 G2
- **THEN** 每一步在依赖满足状态, 当前指针, 密钥版本, 模式权源和期限规则时才能有效提交, 最终两模式路径的 G0/G1/G2 均为 ACTIVE
- **AND** 根, 身份, 域认证, 凭证锚, 任务及 G0/G1/G2 的链上摘要均由绑定当前部署的真实 DID 文档, ES256/SD-JWT 签名材料与 `taskSpec` 计算并可在同一高度视图复核

#### Scenario: 绕过域权限或父受托者

- **WHEN** 普通域客户端执行 T 的域准入, 跨域注册机构登记普通身份, 非本域签发者登记凭证锚, 非资源方签 RP 根, 非父 grantee 登记 G1, 或同 MSP 的另一张证书冒用已登记角色
- **THEN** 对应提案被拒绝, 目标记录与已有记录均无变更

#### Scenario: 绕过采购资格或二跳父受托者

- **WHEN** 非有效 PA 签发 BM 根, PA 在 RP 下签发 G0, 非本域管理员设置 PA 资格, 或非父 grantee 登记 G2
- **THEN** 对应提案被拒绝, 目标记录与已有记录均无变更

#### Scenario: 未配置的合法主体尝试创建任务

- **WHEN** 同属 A 域且身份及凭证有效的其他主体尝试创建任务
- **THEN** 提案被拒绝, 使用同等合法输入的 U 可有效提交
- **AND** T 和域管理员均不能在运行期增加任务创建资格

#### Scenario: 注册挑战双证明缺失或证书不匹配

- **WHEN** 普通身份注册受理时提交错误的管理证明证书 (同 MSP 另一证书), 替换挑战或缺少任一双证明
- **THEN** 注册机构拒绝受理该登记且不消费挑战, 无待提交 `operations` 或链上身份写入
- **AND** 应用证明与管理证明均有效时消费挑战并持久化 `operations` 后提交上链

### Requirement: 标识和路径约束

登记对象 SHALL 绑定当前 deploymentId 并拒绝 ID 复用. G1 SHALL 引用已登记的 parentId, parentDigest, rootId, 同一任务和模式, 并绑定有效身份及凭证锚和密钥版本. 链码 SHALL 检查父子结构, 时间区间和深度边界, 将用于决定的对象, 角色, 域认证指针及路径依赖纳入交易读集. 完整集合包含及单笔金额检查 SHALL 由后续 C 验权执行.

#### Scenario: 路径结构不匹配

- **WHEN** 从合法夹具分别只改变 G1 的父摘要, 根引用, 任务, 模式, 密钥版本, 时间边界或剩余深度
- **THEN** 各不合规提案被拒绝, 其它对象保持原值
- **AND** 对应合法字段的配对交易可有效提交

#### Scenario: ID 已经使用

- **WHEN** 已登记的委托被撤销后再次尝试登记同一个 ID
- **THEN** 提案被拒绝, 原终态记录和摘要保留

#### Scenario: 背书后依赖变更

- **WHEN** 登记 G1 的合法提案已获背书, 但其父委托或引用资格指针的有效变更在该登记前排序
- **THEN** 旧读集的登记在提交校验时无效, 不产生子记录

### Requirement: 撤销权限与版本竞争

委托撤销 SHALL 按调用者当前登记身份检查 issuer, grantee, 本路径根签发者或资源方权限, 核对 expectedRevision 及预期摘要, 并读取目标记录以参与提交时版本校验. 有效撤销 SHALL 将状态置为终态 REVOKED 并增加 revision. 只有原 issuer SHALL 可原子撤销旧授权并登记符合父, 根, 任务及模式约束的新 ID. T 的身份根角色 SHALL 不获得采购委托撤销权.

#### Scenario: 合法撤销和终态

- **WHEN** 有权调用者使用当前 revision 和摘要撤销 ACTIVE 的 G1 并提交为 VALID
- **THEN** 撤销区块末尾 G1 为 REVOKED 且 revision 增加, 旧高度保留撤销前状态
- **AND** 后续恢复该 ID 或以新操作重复执行终态转换均被拒绝

#### Scenario: 两笔交易竞争同一版本

- **WHEN** 两笔合法独立交易在同一有效 expectedRevision 上获背书, 随后均进入区块
- **THEN** 至多一笔为 VALID, 同一目标已由先排序交易修改时另一笔以 MVCC_READ_CONFLICT 无效, 最终记录只变更一次

#### Scenario: 已许可账户仍无合约权限

- **WHEN** 有通道写入资格的无关客户端或 T 直接提议撤销 G1
- **THEN** 授权检查拒绝该提案, 无法取得所需的成功背书, G1 的状态, 摘要及 revision 保持原值

#### Scenario: 替换原子性

- **WHEN** 分别提交原 issuer 的合法替换, 仅有撤销权的调用者发起的替换, 新授权不合规或背书后旧记录变更的替换
- **THEN** 只有有效提交同时产生旧授权 REVOKED 和新授权 ACTIVE, 其它情形均无替换写入

### Requirement: 管理提案的时间资格

需要当前资格的管理操作 SHALL 检查有效区间及当前指针. 背书 Peer SHALL 限制提案时间戳相对可信时钟的偏差, 链码 SHALL 按该窗口及校时误差预留边界检查所依赖的 nbf 和 exp. 凭证锚签发时的 nbf 和 exp SHALL 落在当前 T 域认证的有效区间内, 允许端点相等. 提案时间 SHALL 仅用于受理资格, 材料交付及业务定案 SHALL 用可信当前时间核验实际期限. 有权调用者 SHALL 可撤销已到期但仍可撤销的登记记录.

#### Scenario: 伪造提案时间

- **WHEN** 调用者使用已过期的资格回填提案时间, 或构造其时间容差区间越过资格截止的提案
- **THEN** 提案在时间检查处被拒绝, 同一角色在满足期限的条件下可有效登记

#### Scenario: 凭证锚签发区间边界

- **WHEN** 当前具备签发资格的调用者提交凭证锚, 其 nbf 早于域认证的 nbf 或 exp 晚于域认证的 exp
- **THEN** 提案被拒绝, 目标凭证锚无登记写入
- **AND** 同一签发者提交两端等于域认证边界的配对材料时可有效登记

#### Scenario: 到期后提交已背书交易

- **WHEN** 提案受理时资格有效, 交易持有到资格到期后才提交, 且读集未发生变化
- **THEN** 若交易通过提交校验, 记录原有效交易及登记状态
- **AND** 后续材料交付及业务验权按实际期限拒绝使用到期资格

### Requirement: 管理交易确认与失败证据

系统 SHALL 在首次提交前持久化原操作键, 输入摘要, txID 及已签交易并绑定调用者, 通道和链码. 链码拒绝提案时 SHALL 直接返回无 `"D0:"` 前缀的规范错误码, 管理服务与网关 SHALL 共用统一 REST 错误信封. 受理前 `expectedRevision` 过时返回 `409 STATE_CHANGED`; 已受理返回 `202` 与原 `operationId`, 同键同摘要重试仍返回 `202` 原 `operationId`, 同键异摘要返回 `409 IDEMPOTENCY_CONFLICT`. 查询 `GET /v1/operations/{id}` SHALL 返回 `HTTP 200` 与 `PENDING`/`CONFIRMED`/`FAILED` 及原提案或提交校验码; 仅 `VALID` 提交可确认并开放后续交付. 公开夹具与部署清单 SHALL 排除 `synthetic` 和 `m2TaskSpec` 等历史遗留键.

#### Scenario: 有效提交确认

- **WHEN** 合法操作取得背书和提交接收响应, 随后由可信 Peer 观测到 VALID
- **THEN** 核对 txID, 调用者, 通道, 链码和区块位置后才将操作从 PENDING 改为 CONFIRMED, 开放后续依赖步骤

#### Scenario: 区分提案拒绝与入块无效

- **WHEN** 分别遇到链码提案拒绝, MVCC_READ_CONFLICT 或无可细分原因的非 VALID 提交结果
- **THEN** 链码直接输出无 `"D0:"` 前缀的规范错误码, 管理服务记录对应阶段及原始证据, MVCC 冲突报告 `STATE_CHANGED`, 无法细分的入块无效使用通用失败码 `COMMIT_INVALID`, HTTP 错误响应遵循统一结构化错误信封
- **AND** 所有失败均不触发材料交付

#### Scenario: 提交结果暂不可见或出现重复提交

- **WHEN** 原提交响应或提交状态暂不可见, 操作进程恢复或客户端以同操作键重试
- **THEN** 保持 PENDING, 查同一 txID 或重投原已签字节, 不生成替代交易
- **AND** 同键异输入冲突, 重投引发的重复交易不能覆盖原交易的有效提交结论

#### Scenario: 受理前版本冲突预检与受理后异步操作状态查询

- **WHEN** 普通身份换钥或状态操作先提交过时 `expectedRevision`, 再使两笔不同操作键通过同一有效版本预检并取得背书后在 `202` 后广播, 以及在 `202` 后隐藏提交结果并在恢复可信 Peer 查询前后查询状态与重试
- **THEN** 受理前过时版本返回 `409 STATE_CHANGED` (统一错误信封) 且无待提交操作; 两笔背书竞争经 `GET /v1/operations/{id}` 均返回 `HTTP 200`, 胜出者为 `CONFIRMED`/`failureCode=null`, 冲突者为 `FAILED`/`STATE_CHANGED` (`MVCC_READ_CONFLICT`) 且无材料交付
- **AND** 暂不可见结果时查询返回 `200 PENDING/null`, 恢复查询后准确反映原提案拒绝或入块校验阶段及 `ENDORSEMENT_REJECTED`/`COMMIT_INVALID`, `DUPLICATE_TXID` 不覆盖原结果, 同键同正文重试返回 `202` 原 `operationId`, 同键异正文返回 `409 IDEMPOTENCY_CONFLICT`

### Requirement: 域认证与根授权材料受控交付

域认证与各级委托材料 SHALL 仅在原链上交易确认 `VALID`, 且交付时刻当前资格和有效期仍满足约束时, 经发件箱逐跳开放给目标域或受托者. 接收方 SHALL 在固定高度一致视图上核对签名, 链上锚定摘要, 祖先最小身份出示, 去重 `trustPaths` 与实际收件人后按 `(deploymentId, recipient, grantId)` 原子写入本地收件回执.

#### Scenario: 原交易确认后完成 C 到 U 的材料交付与去重

- **WHEN** T 对 A/C 域认证和 `C -> U` 的 RP `G0` 原交易均在可信 Peer 上确认为 `VALID`, 且 `C` 服务最小凭证出示与 `C` 域认证正文齐全
- **THEN** `C` 经发件箱向 `U` 交付 `G0`, `taskSpec` 及相关信任路径材料, `U` 核验一致视图后写入 `wallet_receipts`
- **AND** 相同投递键和包摘要重复投递返回确认, 同 `(deploymentId, recipient, grantId)` 提交不同包摘要返回 `409 DELIVERY_CONFLICT`, 当前域认证正文暂缺时返回 `503 MATERIAL_NOT_SYNCED` 且不写回执

#### Scenario: 原交易确认后完成 C/PA 到 U 到 A1 到 B1 的多跳交付与去重

- **WHEN** T 对 A/B/C 域认证以及 `G0 -> G1 -> G2` 原交易均在可信 Peer 上确认为 `VALID`, 且对应根服务与祖先最小凭证出示及各域认证正文齐全
- **THEN** 每跳签发者经发件箱向受托者交付包含 `taskSpec`, 上游委托链, 祖先最小出示与按域认证 ID 去重 `trustPaths` 的材料包, 接收方核验一致视图后写入 `wallet_receipts`
- **AND** 相同投递键和包摘要重复投递返回确认, 同 `(deploymentId, recipient, grantId)` 提交不同包摘要返回 `409 DELIVERY_CONFLICT`, 当前域认证正文暂缺时返回 `503 MATERIAL_NOT_SYNCED` 且不写回执

### Requirement: 双域身份关联提案与双域审批

系统 SHALL 支持本域与外域已登记主体之间发起跨部署隔离的双域身份关联提案 (`ProposeIdentityLink`), 并仅在另一端所属域当前注册机构核对同一提案摘要与两端有效资格后审批 (`ApproveIdentityLink`) 才变为 `effectiveActive`. 任一端点主体或所属域注册机构 SHALL 可终态撤销关联 (`RevokeIdentityLink`), 且关联状态 SHALL 不转移或替代任一端的采购授权路径.

#### Scenario: 双域身份关联审批与权限隔离

- **WHEN** A 域已登记主体 `U` 与 B 域已登记主体 `U-in-B` 出示各自域内账号认证与应用密钥 PoP 提交关联提案, 随后分别在单方确认阶段及 B 域注册机构审批后查询 `effectiveActive` 状态
- **THEN** 仅首方登记后关联处于待审批且 `effectiveActive` 为 `false`; 同域冒充另一域审批, 缺失一端 PoP 或提交不匹配提案摘要均被拒绝
- **AND** B 域注册机构批准同一提案摘要后关联变为 `effectiveActive == true`, 且尝试用 `U-in-B` 替代 `G0` 中的 `U` 访问仍被拒绝, 撤销关联后各自独立路径不受影响

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
