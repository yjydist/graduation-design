# AuthRegistry 合约

本目录用于最小 RP 登记切片和固定 Solidity standard JSON 编译配置. 已实现固定根, 域/身份/凭证锚, 任务和 RP 委托登记/撤销, 在真实四节点 Besu 上完成对应验证. 最终完整运行和覆盖边界见[D0 证据索引](../infra/besu/evidence/README.md), 读取接口见[StateReader](../internal/ledger/README.md).

## 编译和基础部署

在项目根目录执行, 需要 Node.js/npm 和已启动的本地 Besu:

```bash
CGO_ENABLED=0 go run ./cmd/ledgerctl compile
CGO_ENABLED=0 go run ./cmd/ledgerctl deploy --dir .local/besu-qbft --name registry
```

编译器使用 npm 的 solc 0.8.30, 实测版本为 `0.8.30+commit.73712a01.Emscripten.clang`, 包完整性值见 [编译器锁](compiler-lock.json). [standard JSON 输入](compiler-input.json)固定 optimizer=true/runs=200, viaIR=true, evmVersion=berlin, 与 genesis 的 Berlin 规则一致. 编译命令核对完整版本, 检查编译输出中的 error, 在被忽略的 build/ 导出完整输出, ABI, 字节码和含源文件/输入摘要的制品. 部署拒绝与当前源文件或输入不一致的旧制品.

构造参数来自已核对的本地公开清单, 固定 RootRecord, instanceId, schemaVersion, 本轮 orders 资源到 C 服务及 A 域/U 任务创建资格的绑定, 并固定可信 genesisHash. RootRecord 检查非空字段和合法 P-256 曲线点. 固定字段通过只读入口暴露, 没有改根或任意写状态入口. 当前不验证 ES256/SD-JWT, did:web 控制权或完整授权包含关系.

部署先在 operations/ 持久化原签名交易, 随后广播, 核对可信节点返回的交易哈希, 区块哈希, 交易位置和成功回执. 重试同一部署名复用原操作; 更改输入后同名重试报冲突. 当前完整切片将清单写入 `deployment-registry.json`, 不输出私钥. QBFT 块哈希使用可信节点原始响应中的 hash, 不调用 Go Ethereum 通用 Header.Hash() 重新散列带 QBFT commit seals 的头.

[真实基础部署清单](../infra/besu/evidence/base-deployment/deployment.json)包含原交易, 成功回执, 编译器, 运行时代码哈希和 deploymentId; [运行时代码查询](../infra/besu/evidence/base-deployment/runtime-code.json)保存原始 RPC. 同目录保存了该次基础合约源码和编译输入, 便于区分后续扩展合约.

## 部署绑定验证

deploymentId 按部署契约的六字段 JCS 和 SHA-256 计算, 启动逐项核对可信节点的 chainId, genesisHash, 实际代码, instanceId, schemaVersion 以及完整 T 根. 资源和所有者绑定也核对实际只读值. 当前校验只针对链和根锚, 不代表已经完成后续网关的业务验证.

```bash
LEDGER_DEPLOYMENT="$PWD/.local/besu-qbft/deployment-registry.json" \
  LEDGER_INSTANCE="$PWD/.local/besu-qbft" \
  LEDGER_EVIDENCE="$PWD/.local/deployment-probe" \
  CGO_ENABLED=0 go test ./internal/ledger \
  -run 'TestDeploymentBindingIntegration|TestRootMutationIntegration' -count=1 -v
```

[字段失配结果](../infra/besu/evidence/base-deployment/deployment-binding.json)覆盖六个部署身份字段, 六个 T 根字段及资源绑定字段. 负例重新计算了清单内的 deploymentId, 仍因链上实值不匹配而拒绝. [改根负例](../infra/besu/evidence/base-deployment/root-mutation.json)由 T 真实签交易调用不存在的改根入口, 取得失败回执且根不变.

[部署后重启](../infra/besu/evidence/base-deployment/deployment-restart.json)复用原部署名和 txHash, 完整清单保持相同. [独立重建对照](../infra/besu/evidence/base-deployment/rebuild-comparison.json)及[新部署清单](../infra/besu/evidence/base-deployment/rebuild-deployment.json)证明干净实例的 instanceId, deploymentId 和合约地址均不同. 此处只验证基础合约, 不计作完整网络/合约/读取验收的干净重建.

基础部署证据保存了初始只读构造切片, 当前完整登记/交易恢复与版本竞争证据见后文及最终证据索引. 同名部署的输入变化会被拒绝, 原地升级入口不存在.

## 域引导切片

已实现 bootstrapDomain, registerDomainCertification 和 getDomain/getIdentity/getDomainCertification. 仅 T 可引导域及最多 8 个本域身份机构, 并登记首份认证. 域先为 PENDING/revision=1, 通过认证后为 ACTIVE/revision=2 且 currentCertificationId 指向认证的 SHA-256 索引. 范围使用非空, 有限, 排序且去重的类型/声明名称集合, 禁止通配符. 身份机构须属于本域且密钥版本匹配, 新身份的管理地址和 DID 不复用.

[真实域登记证据](../infra/besu/evidence/domains/domains.json)覆盖 A/C 引导及认证, 普通账户越权, 缺失域依赖, 非法公钥, 预期版本/指针和范围失配. 所有负例保存真实失败交易/回执及前后记录, 未产生部分变更. [该次部署](../infra/besu/evidence/domains/deployment.json)与同目录源码固定测试对象. 本轮使用带 synthetic 标记的域认证 JSON 摘要, 没有实现控制权挑战, T 应用签名或 HTTP 交付.

## 普通身份和凭证锚

registerIdentity 仅允许有效域的当前注册机构登记普通 USER/AGENT/SERVICE, 不能借此引导身份机构. 首次密钥版本为 1, 检查 DID/keyId 绑定, 非压缩 P-256 点, 非零摘要/账号承诺及管理地址唯一性. registerCredential 仅允许本域当前获认证机构的管理账户登记, 核对当前认证范围, 签发者及主体版本, 域归属和期限. getCredential 提供指定高度查询.

[真实身份与凭证测试](../infra/besu/evidence/identities/identities.json)覆盖 U/A1/C 及同域另一合法主体的正例, 跨域注册, T 冒充注册机构, 非法曲线点, 版本失配, 错误凭证签发者, 超范围类型, 到期和缺失主体, 以及 PENDING 域拒绝普通登记. [同次域引导](../infra/besu/evidence/identities/domains.json)及[部署清单](../infra/besu/evidence/identities/deployment.json)关联同一测试实例. 所有失败均有回执和状态未变证据. synthetic 凭证材料仅是 JSON 摘要, 完整 ES256/SD-JWT 验证, 控制权挑战和字段与签名正文一致性验证尚未实现.

## RP 任务和委托

构造时固定 taskDomain=SHA256(A 域 ID) 和 taskCreator=SHA256(U 主体 ID), 并只读暴露. registerTask 核对当前 U 管理地址, 有效身份/域认证和引用凭证, registerGrant 按 C 资源方和父受托者关系登记 G0/G1. 任务和委托的 ID/主体/父根/凭证引用使用 32 字节 SHA-256 索引, 减少重复字符串编码; 原 URI 在合成材料和命令输入中保留. 实现保留 optimizer runs=200, 初次 RP 登记部署的运行时代码为 21536 字节, 最终含撤销入口的切片为 22141 字节, 均使用标准 EVM 代码尺寸限制.

新构造还固定可信 genesisHash. deploymentId() 在运行期按既有六字段 JCS 公式计算部署摘要, 包含实际 address(this).codehash; Go 在部署后交叉核对. 任务和委托入口核对传入部署摘要, 不接受其它部署的材料引用. 资源绑定当前仅覆盖本轮 orders 资源, 不包含已实现的询价业务接口.

[RP 真实登记证据](../infra/besu/evidence/rp/rp-registration.json)记录 U 创建任务, C 登记交给 U 的 G0, U 登记交给 A1 的 G1, 两份委托均 ACTIVE/revision=1. 未配置但身份/凭证有效的同域 B1, T, 非资源方根签发者, 错误根受托者和非父受托者均被拒绝, 保存失败回执和未变记录. [该次部署](../infra/besu/evidence/rp/deployment.json)绑定构造参数, 同目录包含源码和引导/身份测试结果.

[委托结构配对](../infra/besu/evidence/rp/grant-structure.json)覆盖父摘要/父引用, 根, 任务, 模式, 主体域, 签发者/受托者版本及凭证, 时间包含, 深度, 资源, 部署和 schemaVersion. 每对先提交只改一个字段的负例, 确认已有记录及候选 ID 未变, 再用同一候选 ID 提交正确字段并成功. 另有 ACTIVE ID 复用负例. 记录的合成材料仅用于摘要关联, 完整资源集合, 动作, 金额包含及应用签名仍须在链下验证.

## 撤销与终态

revokeGrant 检查 issuer, grantee, 本路径根签发者或已绑定资源方的当前管理地址, 核对 expectedRevision 和 expectedDigest 后将 ACTIVE 转为 REVOKED, revision 仅增加一次, 保留原摘要和字段. 撤销不要求原资格仍有效, 没有恢复或复用终态 ID 的入口. T 没有采购撤销权.

[撤销真实交易](../infra/besu/evidence/registry/revocation.json)验证 U, A1 和 C 的关系权限, T/无关账户拒绝, 版本/摘要失配, 撤销后重复转换/恢复/ID 复用失败. RP 中根签发者与资源方均为 C, 两个关系标签的样本不作为独立角色隔离证明. [最终登记切片部署](../infra/besu/evidence/registry/deployment.json)和同目录的域/身份/RP/结构测试使用同一合约, 运行时代码为 22141 字节.

## 夹具命令与验证边界

```bash
CGO_ENABLED=0 go run ./cmd/ledgerctl compile
CGO_ENABLED=0 go run ./cmd/ledgerctl deploy --dir .local/besu-qbft --name registry
CGO_ENABLED=0 go run ./cmd/ledgerctl seed --dir .local/besu-qbft
```

seed 使用 15 笔真实管理交易顺序建立 A/C 域及认证, U/A1/C 和一位同域有效测试主体, 凭证锚, U 任务及 G0/G1. 测试账户 B1 在 D0 仅用作 A 域另一合法主体的权限负例, 正式 B 域智能体流程尚未实现. 写入口仅有 bootstrapDomain, registerDomainCertification, registerIdentity, registerCredential, registerTask, registerGrant, revokeGrant, 分别按本文权限执行. 无任意写入状态或绕过权限的夹具接口.

[干净实例夹具](../infra/besu/evidence/seed-rebuild/seed.json)记录独立新网络上的全部原签名交易/回执和合成材料, G0/G1 均为 ACTIVE. [新部署](../infra/besu/evidence/seed-rebuild/deployment.json)及[重复运行/入口清单](../infra/besu/evidence/seed-rebuild/replay-and-entrypoints.json)证明重试复用相同操作, 不生成替代交易. seed 保留当前终态, 不会恢复已撤销的委托. 本次重建尚不代替最终完整集成判据重跑.

输出中的 synthetic=true 及 unimplementedValidation 明确列出 HTTP 挑战消费/DID 控制权证明, 在线 did:web, ES256/SD-JWT, 完整集合/金额包含, 采购策略和订单均未实现. 锚摘要来自标记为 synthetic 的 JSON, 不是有效签名凭证. 应用公钥曲线点检查和真实管理交易签名不等于完整应用协议验签.

## 管理交易恢复

部署目录使用非阻塞独占文件锁, 跨进程串行分配 nonce. 签名交易和操作日志以临时文件写入, fsync, rename 及目录 fsync 落盘后才广播. 已确认/失败操作保留终态, 无回执保持 PENDING. 重试同一操作核对输入, 原签名字节, 调用者, 目标和 nonce, 不生成替代操作; 新操作同时参考节点 pending nonce 和本地日志下限.

`CGO_ENABLED=0 go test ./internal/ledger -run 'TestPendingTransactionRecovery|TestOperatorLockAndNonceSequence|TestReceiptMismatchStaysPending|TestJournalTargetMismatch'` 使用可控 RPC 测试广播响应丢失, 回执隐藏, 广播未送达后的相同字节重播, 锁冲突, nonce 分配, 输入/目标冲突及失配回执. 恢复使用新客户端重读原日志, 不再次请求 nonce 分配. 这些故障注入与真实部署回执验证相互补充, 不计作多实例管理服务的数据库事务验证.

## 原交易回退证据

[原交易取证](../infra/besu/evidence/transactions/original-transaction-trace.json)由已许可且预充值的 unrelated 账户显式签发撤销交易, gasLimit=8000000. 该交易入块且 receipt.status=0x0, 记录未变. 使用同一 txHash 的 debug_traceTransaction/callTracer 返回 output, 经 ABI 解码为 UNAUTHORIZED. 解码前核对原签名交易/回执/块/交易位置, 以及 trace 根调用的 from/to/input/gasUsed, 保留完整原始响应.

同一交易的 opcode 探针保存了真实 returnValue=0x 和 REVERT 步骤. 本镜像使用 callTracer.output 取得具体回退数据, 不把空 returnValue 或失败 receipt 推断成具体业务原因. receipt 本身不包含具体原因, 不调用 latest 或父块上的独立模拟猜失败码. trace 原因不可得时保留 FAILED/TRANSACTION_REVERTED.

[原因缺失与恢复](../infra/besu/evidence/transactions/trace-failure-recovery.json)在同一真实失败交易上注入 trace 不可得, 截断, 未知选择子和非法 hex 回退数据. 各分支首先保存 FAILED/TRANSACTION_REVERTED, 恢复原节点响应后补充 UNAUTHORIZED, 原 txHash, 签名字节和 receipt 不变. 原因恢复的 RPC 记录中没有分配 nonce 或广播新交易.

## 同块版本竞争与整块取证

[版本竞争](../infra/besu/evidence/transactions/revision-competition.json)使用 U/A1 两个有权账户, 先在独占锁内保存两笔 expectedRevision=1 的原签名交易, 再广播两笔, 最后跟踪回执. 一笔成功, 另一笔失败, 最终 REVOKED/revision=2. 失败原因 STATE_CHANGED 来自绑定原执行的回退数据.

[最初不一致样本](../infra/besu/evidence/transactions/competition-probe/competition.json)记录了本镜像 debug_traceTransaction 对同块第二笔失败交易返回成功 trace 的问题. [原块哈希探针](../infra/besu/evidence/transactions/competition-probe/block-hash.json)则按完整交易顺序返回正确结果. 实现仅在单交易 trace 与回执执行不一致时使用 debug_traceBlockByHash, 核对原块哈希/号, 完整交易顺序, 原 transactionIndex/txHash, failed 和 gas, 并从该原执行的 returnValue 或 depth=1 的 REVERT.reason 解码. 保留单交易错误 trace 和整块原文, 不使用父块独立模拟.

[整块取证拒绝与恢复](../infra/besu/evidence/transactions/block-trace-fallback-faults.json)覆盖缺失, 顺序失配, 截断, gas/状态失配和缺少根 REVERT. 无可信原因时继续 FAILED/TRANSACTION_REVERTED, 恢复后只补 STATE_CHANGED, 原交易和回执不变.

实施范围见 [变更设计](../openspec/changes/archive/2026-11-04-bootstrap-besu-state-verification/design.md).
