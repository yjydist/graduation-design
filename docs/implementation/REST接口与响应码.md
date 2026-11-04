# REST接口与响应码

## 1 客户端调用顺序

request 的全部字段必填, idempotencyKey 为 1-64 个 ASCII 字母, 数字, 下划线或连字符. 询价时切换到 quotes 资源和 quote.read, quoteId 为 null, amountMinor 为 0, 使用新的询价键. 下单时只使用询价响应中的 quoteId, 商品, 数量, 币种和总价, 改为订单资源, 动作和订单键. 每个动作依次调用以下接口.

| 调用 | 成功响应 JSON | 客户端如何使用 |
| --- | --- | --- |
| POST /v1/auth/challenges | 201, {challengeId,nonce,audience,issuedAt,expiresAt} | C 根据服务配置填 audience, 绑定提交的 actor, taskId 和 requestHash. actor 的自报值仅标识待证明者 |
| POST /v1/access/execute, 询价 | 200, {decisionId,code:"ALLOW",quote} | quote 含 quoteId, taskId, actor, supplierId, productId, quantity, currency, unitPriceMinor, totalAmountMinor, issuedAt, validUntil |
| POST /v1/access/execute, 下单 | 200, {decisionId,code:"ALLOW",order} | order 含 orderId, taskId, actor, principalDomain, authorizationMode, quoteId, currency, amountMinor, status. CREATED 后订单记录不可改 |
| execute 拒绝 | 对应 HTTP 状态, {requestId,code,decisionId} | 未形成审计决策时 decisionId 为 null. 客户端用 requestId 查故障, 用 decisionId 查该次决策. 成功重试返回新的 decisionId 和原业务 ID |

C 数据库按部署隔离. C 目录基准单价为 80000 分. 报价 ID 由 C 分配, validUntil=min(issuedAt+300, task.validUntil). 测试驱动在独立用例的 C 目录中预置 90000 或 120000 分, 再调用同一询价接口, 将返回的 ID 记作 Q900 或 Q1200. 更新目录不改变已签发报价. 订单按如下顺序比较: 找到同部署/任务/主体的报价, 校验商品/数量/币种/供应商, 检查 now < validUntil, 检查真实总额与请求相同, 再判总额不超过整条路径最小上限. 授权和报价期限在事务最终检查时仍须满足.

| 时点 | B₁读取什么 | 写入或核对什么 |
| --- | --- | --- |
| 收到委托 | 已核验的 C 服务凭证及 T 的 C 域认证, 本地钱包的叶子 DID 和私钥, 交付包的 G0-G2 与 taskSpec, 部署清单中的 schemaVersion, deploymentId 和 C 服务地址 | actor 取钱包 DID, 等于 G2.grantee. taskId, principalDomain, authorizationMode 和 audience 取已验证的 G2 的 taskId, principalDomain, authorizationMode, aud. audience 必须与配置的 C 受众逐字相同. 真实 HTTPS 地址由清单映射, 不从响应发现 |
| 准备询价 | taskSpec 的 supplierId, productId, currency, maxQuantity, resources 和 actions | 固定购买 1 件, 要求 1 <= maxQuantity. 填 quotes 资源, quote.read, quoteId=null, amountMinor=0. 生成询价业务键并保存完整 request 后再算 requestHash |
| 申请并使用挑战 | 向 C 提交且仅提交 {actor,taskId,requestHash}. 核对 201 的 audience, challengeId, 按[nonce 编码](协议编码与测试向量.md#21-挑战-nonce-编码)表示的 32 字节随机数和 30 秒有效区间 | 将响应中的 nonce 字符串原样写入 KB, 不重新编码. 对本次请求和证据生成 KB, execute 只提交[证据包规范](协议编码与测试向量.md#2-证据包与摘要)规定的七个字段. 挑战响应丢失可重新申请. 一次动作的响应与发起它的 HTTP 调用配对 |
| 接收报价 | 200 ALLOW 且仅有 quote 业务对象 | 校验 quoteId 非空, actor/taskId 和商品, 供应商, 数量, 币种与询价相同. 按整数分重算 unitPriceMinor * quantity = totalAmountMinor, 核对 issuedAt < validUntil 及报价仍可用. 核对失败不得据此组订单 |
| 构造订单 | 前一步持久化的可信 C 响应和当前有效路径 | 保留主体, 任务, 模式及商品各字段, 切换为 orders 资源和 order.create, 填收到的 quoteId 和 totalAmountMinor, 生成独立订单键. 新算摘要, 再走一次挑战和 execute. 测试别名 Q800 不可代替真实 ID |
| 接收订单 | 200 ALLOW 且仅有 order, decisionId 非空 | 核对 orderId 非空, status=CREATED, quoteId, actor, taskId, principalDomain, authorizationMode, currency, amountMinor 与原订单请求相同. 在本地保存 orderId 和本次 decisionId 后结束 |

两个业务 POST 均发送 application/json. B₁使用请求正文中的 idempotencyKey, 管理写接口的 Idempotency-Key 请求头不参与业务键比较. 服务生成的 challengeId, quoteId, orderId, decisionId 分别使用 urn:grad:challenge:, urn:grad:quote:, urn:grad:order:, urn:grad:decision: 加随机 UUID, 以数据库唯一约束保证部署内不复用. 接收端按完整字符串比较. 正常 201/200 以及错误响应均由 C 在响应头 X-Request-Id 返回本次 HTTP 调用标识, 错误体的 requestId 与其相同.

字段解析先于访问验证. 数量必须是正整数, 请求金额是非负安全整数, 类型错误或越界返回 400 INVALID_SCHEMA. quote.read 只接受显式 null 的 quoteId 及零金额, order.create 必须有非空字符串 quoteId. 未知动作或动作与资源搭配错误同样返回 INVALID_SCHEMA. 结构正确后才检查任务上限, 供应商归属和真实价格, 相应返回 TASK_SCOPE_MISMATCH, QUOTE_SCOPE_MISMATCH 或 AMOUNT_MISMATCH.

## 2 REST 接口

管理接口只供 T 认证服务, 域服务和已登录管理员使用, 采用 HTTPS, 域间 mTLS 及服务端角色校验; 浏览器写操作须防 CSRF. 浏览器不能直接把任意管理地址当成签名者, 服务端按当前登录主体选择测试钱包. 测试密钥仅用于可重置的本地实验.

| 方法和路径 (均在 /v1 下) | 请求要点 | 结果及约束 |
| --- | --- | --- |
| POST /trust/domain-certifications/challenges | 企业域身份核实材料, 候选域/机构/密钥/范围和期限 | 201; 限 T 审核角色建立挑战, 返回 challengeId/nonce/expiresAt, 原始核实材料受控保存 |
| POST /domains | challengeId, 域管理员证明, 域 DID 与机构双证明, 候选 DomainRecord 和引导身份记录 | 202; 仅 T 服务完成核实和挑战消费后提交, 域初态 PENDING, 不含普通主体 |
| POST /domains/{id}/authority-identities | challengeId, 域及机构控制权证明, 新机构或恢复后的引导身份记录 | 202; 限 T, 仅处理域 DID/身份机构, 生效后仍须新域认证才取得签发资格 |
| POST /trust/domain-certifications | T 签名的完整 DomainAuthorityCredential, expectedDomainRevision, expectedCurrentCertificationId, 首份认证的引导 operationId 或续发/变更的新 challengeId 及控制权证明 | 202; 限 T 管理角色, 校验根签名/部署/机构控制权/范围和挑战批准内容, 首次引用已确认引导, 续发/变更原子消费新挑战, 激活域或原子替换当前认证 |
| POST /trust/domain-certifications/{id}/revoke | expectedDigest, expectedRevision, reason | 202; 限 T, REVOKED 为终态, 域状态虽可仍 ACTIVE 但有效资格已失效 |
| GET /trust/domain-certifications/{id} | 认证 ID | 经 mTLS 向获准域服务返回原始 compact JWS 及登记状态/读取块, 核对后可持久缓存正文 |
| POST /domains/{id}/status | status, expectedRevision, reason | 202; 限 T, 暂停/恢复/撤销域, 恢复仍须当前认证有效 |
| POST /domains/{id}/purchasing-authority | purchasingAuthority 为该域有效服务 DID 或 null, expectedRevision | 202; 限该域登记的管理员. 提交生效后网关重查 PA 根资格 |
| POST /identities/{id}/status | status, expectedRevision, reason | 202; 普通身份由本人当前管理账户/本域当前注册机构暂停或撤销, 仅注册机构恢复暂停; 域 DID/机构引导身份仅 T 管理. 按[身份状态表](部署与链上登记.md#3-身份状态与管理账户恢复)检查, REVOKED 终态 |
| POST /identities/challenges | 已认证域内账户, 候选 DID, 管理身份和文档/公钥字段 | 201; 返回绑定本次登记的注册挑战 |
| POST /identities | challengeId, applicationProof, managementProof | 202 operationId; 域当前有效, 本域注册机构核验并提交 |
| POST /identity-links | 完整关联提案, 双域认证及绑定 PoP | 202; 首方登记, 关联仍待另一域审批 |
| POST /identity-links/{id}/approve | 提案 digest, 预期状态 | 202; 限另一端所属域注册机构, 双方确认后可用 |
| POST /identity-links/{id}/revoke | 原因, 预期状态 | 202; 任一端 managementIdentity 或所属域注册机构, 不可恢复 |
| GET /identity-links/{id} | 关联 ID | 记录, effectiveActive 及 stateRevision; 仅端点与授权审计者可查 |
| POST /identities/{id}/rotate | 新 DID 文档及 newKeyProof, 绑定 expectedRevision 和 expectedKeyVersion, 绑定新公钥及文档摘要 | 202; 限该主体的登记管理身份. 接受前发现版本冲突返回 409 STATE_CHANGED, 接受后发生冲突按 operation 查询失败结果 |
| POST /identities/{id}/recovery-challenges | 原域内账号的重新认证材料, 候选新管理地址/新应用密钥/文档及预期版本, reason | 201; 限本域当前注册机构审核普通非终态身份, 返回[恢复规格](部署与链上登记.md#3-身份状态与管理账户恢复)定义的完整挑战; 域 DID/机构使用 T 引导接口 |
| POST /identities/{id}/recover | challengeId, applicationProof, managementProof | 202 operationId; 仅当前注册机构核验新钥双证明后提交, 原子消费挑战并持久化操作. 保留原 status, 增加密钥版本, 不要求旧管理私钥 |
| POST /credentials | credentialId, subjectId, nbf, exp; IA/IB/IC 从本域账户取得核验声明 | 202 operationId; 核对 T 域认证及当前签发资格, 只能签本域身份, 确认后交付 |
| GET /credentials/{id}/wallet-copy | 本域主体登录, credentialId | 仅向该凭证主体返回 {credentialId,issuerJwt,disclosures}, disclosures 是完整的原始披露字符串数组 |
| POST /credentials/{id}/revoke | expectedDigest, expectedRevision, reason | 202; 限签发者 |
| POST /tasks | taskId, resourceOwner, authorizationMode, taskSpec, validUntil | 202; creator 取已登录且与受信部署任务创建资格一致的 U, 管理账户和当前资格仍由合约核对 |
| POST /tasks/{id}/cancel | expectedRevision, reason | 202; 创建者或该任务资源方 C 可取消, 不可恢复 |
| POST /grants/root | 模式, 采购主体, 任务, 约束 | 202; 按模式由 C 或 PA 核实资格签发 |
| POST /grants/delegate | 父对象, 子约束, grantee | 202; 服务执行完整校验 |
| GET /grants/{id}/state | 对象 ID, 登录的该对象管理者或审计者 | 返回 id, digest, status, revision, exp 和读取所用 stateRevision |
| POST /grants/{id}/revoke | expectedDigest, expectedRevision, reason | 202; 限该路径有撤销权限的管理身份 |
| POST /grants/{id}/replace | newGrantJws, expectedDigest, expectedRevision, reason | 202; 限原 issuer, 可收缩范围/期限或更换受托者, 原子撤销/替换 |
| POST /grants/{id}/suspend 或 /resume | expectedDigest, expectedRevision, reason | 202; 限 issuer |
| POST /policies | expectedPolicyVersion, bundle (含新版本及签名 manifest) | 202; 限 C 策略管理员, 编译测试成功才提交 |
| POST /contexts/{taskId} | expectedContextVersion, observedAt, riskLevel, accessDeadline | 200; 由 C 观测服务写主库, 返回已提交观测 |
| POST /auth/challenges | actor, taskId, requestHash | 201; nonce 为 32 字节随机数的规范无填充 base64url 字符串, 长度 43, 受众及 30 秒期限由 C 固定 |
| POST /access/execute | 规范请求, 证据包, 挑战及叶子 KB | 200/4xx/503; 直接执行, 不签发宽权限 token |
| GET /operations/{id} | operationId | 查询成功为 HTTP 200, 返回 PENDING/CONFIRMED/FAILED, txHash, receiptStatus, block, observedNode, failureCode; FAILED 不把该 GET 改成 HTTP 409 |
| GET /grants/{id}/path | 叶子 ID | 授权路径和当前验证结果; 需审计权限 |
| POST /internal/order-outcome-cases | caseId, sendRevision, deploymentId, request, requestHash, challengeIds | B 恢复服务经 mTLS 向 C 登记已停发的核账单; 202 只确认登记 |
| POST /audit/order-outcomes | 原订单 request 及可能已发送的 challengeIds; 已登记核账单另带 caseId | 仅 C 审计员按核账规程查主库, 读取历史结果 |
| POST /internal/order-outcome-receipts | 绑定原意图的最小核账回执 | 仅 C 核账服务向 B 恢复服务交付, 200 表示 B 已持久化 |
| GET /decisions/{id} | decisionId | 决策解释; 限请求主体及审计者 |
| GET /health/ready | 无 | 状态完整且新鲜才 ready; 不暴露密钥 |

**管理请求与交付边界.** 管理写请求须提供 Idempotency-Key, 其格式与业务键一致. 对 (登录管理身份, 方法, 路径, key) 建唯一索引, 保存请求正文 JCS 摘要和 operationId. 链上管理写同键同摘要仍以 202 返回原 operationId, 包括原操作已 FAILED 时; 环境写返回原已提交的 200 结果, 同键异摘要均返回 409 IDEMPOTENCY_CONFLICT. 已认证请求先查操作键, 精确重试不因原 expectedRevision 已过时而变成新冲突. 新链上管理操作及待提交材料在本域同一事务持久化后才算接受并返回 202. 链上对象的生命周期操作带 expectedRevision, 接受前预检发现旧 revision 返回 409 STATE_CHANGED, 不创建待提交操作或分配交易 nonce. 新域认证的激活/替换使用 expectedDomainRevision 和 expectedCurrentCertificationId 检查域配置竞争, 认证撤销使用认证自身的 expectedRevision/expectedDigest. 模式或角色由已认证主体与登记记录决定, 登录人无权指定另一个主体的钱包.

**接受后的管理结果.** 202 只表示操作已持久化并可查询, 不表示合约执行成功. 两笔操作均通过预检并被接受后, 后入块的一笔仍可能因版本竞争回退. 原 POST 不再补发 409, 客户端查询原 operationId 取得结果. 查询限发起身份或本域审计者, 响应字段为 operationId, status, txHash, receiptStatus, block, observedNode, failureCode, 尚未知的交易/区块字段用 null.

| 阶段或结果 | HTTP 行为 | operation 状态及 failureCode |
| --- | --- | --- |
| 新请求接受前发现版本不符 | 原 POST 返回 409 STATE_CHANGED | 不创建待提交 operation, 不广播交易 |
| 操作已接受, 尚无确定回执 | 原 POST 返回 202; GET 查询成功为 200 | PENDING, failureCode=null. 超时或失联不当作交易失败 |
| 原交易成功回执 status=0x1 | GET 查询成功为 200 | CONFIRMED, failureCode=null |
| 原交易回退 status=0x0, 确认原因为版本竞争 | GET 查询成功为 200 | FAILED, failureCode=STATE_CHANGED, 保留原 txHash 和失败回执 |
| 原交易回退, 确认是其它权限/生命周期错误 | GET 查询成功为 200 | FAILED, failureCode 为对应的管理业务码, 如 IDENTITY_MANAGEMENT_FORBIDDEN 或 GRANT_STATE_CONFLICT |
| 原交易回退, 尚无可信的具体原因 | GET 查询成功为 200 | FAILED, failureCode=TRANSACTION_REVERTED. 仅凭 status=0x0 不推断具体业务码 |

具体失败码的证据要求见[交易确认与重试](部署与链上登记.md#2-谁能改合约中的哪一行). 原操作的精确重试不重新签发材料或提交新交易; FAILED 后确需重新申请时, 客户端先读取当前状态, 使用新的操作键和更新后的预期版本. [HTTP 202 语义](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.3).

T 服务与各域使用同样的操作键/回执规则. 域认证更新必须走 T 接口, 普通域管理员没有单独修改 administrator/registrar/identityIssuers 的入口. 已撤销或资格到期时仍允许原管理者撤销旧对象.

管理角色与交易提交规则见[部署与链上登记](部署与链上登记.md), 核账单与回执字段见[订单核账](订单核账.md). 域间 GET /internal/tasks/{id}/spec 仅供本任务获准根签发者取明细. POST /internal/grantee-presentations 按任务与该跳分工授权, 仅返回受托者批准的最小出示和域认证, 本地当前认证正文缺失时返回 MATERIAL_NOT_SYNCED. GET /internal/resource-identities/{did} 向获准域服务返回 C 服务最小出示及当前域认证, 核对配置端点, 资源所有者和新鲜登记后更新本地材料. POST /internal/grant-deliveries 投递 {deploymentId,recipient,grantId,taskSpec,grants,credentials,trustPaths}, 凭证数组只含祖先的最小出示. IA/IB/IC 经 GET /trust/domain-certifications/{id} 取本域当前认证正文并向获准验证方交付. 新的 trustPaths 固定为 issuer 和 domainCertification, C 的 RP 根交付包须含 IC 签发的 C 服务凭证及 T 的 C 域认证. 不再提供域间背书接口.

## 3 响应码

本表用于当前 HTTP 请求的同步结果. 管理 POST 已返回 202 后的链上失败使用 operation.failureCode, 不再次返回本表的 HTTP 错误. TRANSACTION_REVERTED 仅为异步操作的通用失败码, 不新增同名 HTTP 响应.

| HTTP | code | 含义 |
| --- | --- | --- |
| 400 | INVALID_SCHEMA / INVALID_DISCLOSURE | 格式, 缺失字段, 非法披露或非规范数值 |
| 401 | SIGNATURE_INVALID / HOLDER_MISMATCH | 签名或持有者公钥绑定失败 |
| 401 | CHALLENGE_EXPIRED / REQUEST_BINDING_MISMATCH | 挑战过期或被替换 |
| 401 | CHALLENGE_UNKNOWN | 本部署无此 challengeId |
| 413 / 415 | PAYLOAD_TOO_LARGE / UNSUPPORTED_MEDIA_TYPE | 请求体超过上限或请求体类型错误, 在验签前返回 |
| 403 | IDENTITY_UNTRUSTED / CREDENTIAL_INACTIVE / KEY_VERSION_STALE | 身份来源, 凭证或密钥状态无效 |
| 403 | DOMAIN_INACTIVE / DOMAIN_CERTIFICATION_INVALID / ISSUER_SCOPE_INVALID | 域非 ACTIVE, 或域认证不受预置 T 认可/非当前/撤销/到期/字段不符, 或域机构越界签发 |
| 403 | TRUST_MANAGEMENT_FORBIDDEN | 非 T 角色试图准入域, 变更认证范围或管理域状态 |
| 403 | IDENTITY_MANAGEMENT_FORBIDDEN / IDENTITY_RECOVERY_PROOF_INVALID | 无权变更身份状态或恢复管理地址 / 恢复挑战的账号核实, 绑定或新钥双证明无效 |
| 409 | IDENTITY_STATE_CONFLICT | 身份状态转换非法, 或试图轮换/恢复已撤销身份 |
| 403 | GRANT_INACTIVE / GRANT_MANAGEMENT_FORBIDDEN | 访问所用叶子已暂停或撤销 / 调用者无权变更该授权 |
| 409 | TASK_STATE_CONFLICT | 新的取消操作不满足 ACTIVE 到 CANCELLED 的转换前提 |
| 409 | GRANT_STATE_CONFLICT | 管理操作的目标状态转换非法或授权已到期 |
| 403 | DELEGATION_EXPANSION / PATH_INVALID / ANCESTOR_INACTIVE | 子权限扩张, 链拼接或祖先失效 |
| 403 | TASK_MISMATCH / TASK_INACTIVE / GRANT_EXPIRED | 任务或时间约束失败 |
| 403 | POLICY_DENIED / SUPPLIER_POLICY_DENIED | 动态策略或 C 准入/销售策略明确拒绝 |
| 403 | ROOT_AUTHORITY_INVALID / AUTHORIZATION_MODE_MISMATCH | 根来源/采购授权机构无效, 或请求/任务/路径模式不一致 |
| 403 | DID_DOCUMENT_MISMATCH / DID_KEY_PURPOSE_INVALID | 文档与当前锚不符, 或 kid 不具备要求用途 |
| 403 | TASK_SCOPE_MISMATCH | 商品/数量/供应商超出已锚定任务范围 |
| 403 | LINK_PROOF_INVALID / LINK_APPROVAL_FORBIDDEN | 关联认证/持有证明无效, 或审批者不是对应端所属域注册机构 |
| 409 | CHALLENGE_REPLAY / IDEMPOTENCY_CONFLICT / STATE_CHANGED | 并发重放, 同键不同请求或状态竞争 |
| 409 | LINK_PROPOSAL_MISMATCH / LINK_STATE_CONFLICT | 关联提案摘要不符, 重复关联/审批, 版本变化或超出可审批期限 |
| 403 | REGISTRATION_PROOF_INVALID / MATERIAL_FORBIDDEN | 注册双证明或域内归属无效 / 调用方或收件人不符合已批准的交付范围 |
| 409 | DELIVERY_CONFLICT / MATERIAL_INVALID | 同一收件键的包摘要冲突 / 登记已可见但正文, 路径或引用不能通过核验 |
| 503 | MATERIAL_NOT_SYNCED | 指定块的登记或锚定材料尚不可用, 含有效认证对应正文暂缺; 不写钱包收件回执 |
| 403 | AUDIT_FORBIDDEN | 已登录但不是 C 审计员, 不能按业务键核账 |
| 403 | AMOUNT_LIMIT_EXCEEDED | 可信总额与请求一致但超过任一祖先或叶子上限 |
| 403 | QUOTE_SCOPE_MISMATCH | 报价不存在, 不属于当前任务/主体或商品等字段不匹配 |
| 409 | AMOUNT_MISMATCH / QUOTE_EXPIRED | 可信报价与提交业务不一致 |
| 409 | PRICE_UNAVAILABLE | 已通过任务和准入校验, 新询价在 C 目录无对应价格行 |
| 503 | STATE_STALE / CONTEXT_STALE / POLICY_UNAVAILABLE | 无法在新鲜且完整状态下决策 |
| 503 | STORE_UNAVAILABLE / COMMIT_UNKNOWN | 数据库不可用或锁等待超时并已回滚 / 已发送 COMMIT 但未取得确定结果 |
| 500 | POLICY_EVALUATION_ERROR / INTERNAL_ERROR | 内部错误; 不得退化成允许 |

只有已确认提交的终态决策返回 decisionId. 未证明持有者, 挑战已用或过期, 暂时不可判定和提交结果不明均返回 decisionId=null. 不返回原挑战对应的订单或原决策 ID. 拒绝体没有 quote/order. 传输中断时客户端可能连 requestId 都收不到, 可按本地已持久化的 challengeId 对账.
