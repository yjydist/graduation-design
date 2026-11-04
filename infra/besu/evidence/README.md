# D0 最小网络证据

本轮完成四节点许可账本, 正常 RP 登记/撤销切片, 管理交易恢复与原执行取证, 固定高度读取和在线状态新鲜度验证. 完整运行均包含 7 项验收, Go 日志有 26 个顶层测试通过, 正负例在各自 test-cases/ 中保存. 不包含私钥.

## 完整运行与重建

| 运行 | 原始汇总 | 撤销前 h / 撤销块 r | 结果 |
| --- | --- | --- | --- |
| 原实例 | [summary.json](final-original/run-81978d048975816a/summary.json) | 0x142b / 0x142c | h 为 ACTIVE, r 为 REVOKED, 全部 7 项通过 |
| 干净重建 | [summary.json](final-rebuild/run-6fd973b340a6334c/summary.json) | 0x8f / 0x90 | 相同判据重跑通过, 使用独立新密钥和账本数据 |

[重建对照](rebuild-comparison.json)核对源码, 编译器/输入, chainId 和 schemaVersion 相同, instanceId, deploymentId, genesisHash 和合约地址不同. 两次均未执行订单级 E6/E7, D0 完整凭证协议或 M1/M2 业务闭环. 同机四容器的结论限于节点故障, 四把验证密钥由同一实验操作者分别代管 A/B/C/实验运维.

原 deploymentId 为 `4918853e0821c4ab69efbd09ba8fa7c0b9ed301d0af35456c54ad8478f9db416`, 新 deploymentId 为 `429b7c647d2d1336306bed3c6bfd4944a059189b6e169d596fff7f0aebe1c6d9`. 原实例恢复后的[在线读取](restored-original.json)及[RPC](restored-original-rpc.json)保存部署核对和新鲜快照. 新实例的数据与密钥仍保留在被忽略的本地目录.

每个完整运行目录包含 configuration.json, deployment.json, materials/, events.jsonl, rpc.jsonl, go-tests.jsonl 和独立判据 JSON. 各交易样本保留原签名字节, txHash, 回执及块/位置绑定; 失败 trace 和原因补充样本同样保留. 其它目录保存实施各阶段的探针和失败记录.

[停机窗口复核](window-review.json)保留了一次早期计数偏差: 当时从停机前快照起算, 干净重建只能确认停机后 2 个新块. 上表最终运行已改为从停机命令完成后的头起算, 两次均确认 3 个新块, 并保存超过 15 秒的稳定窗口起止时间及最终采样. 原始早期报告保留, 最终覆盖以本索引所列重跑为准.

## 判据与原始入口

下表使用原实例, 干净重建目录保存相同名称的判据和用例.

| 判据 | 证据入口 |
| --- | --- |
| 四节点身份一致, 四验证者, 连续空块及实际间隔 | [network-baseline.json](final-original/run-81978d048975816a/network-baseline.json) |
| 未许可节点连接拒绝及原始日志 | [unpermitted-node.json](final-original/run-81978d048975816a/unpermitted-node.json), [日志](final-original/run-81978d048975816a/unpermitted-node.log) |
| 未许可账户准入拒绝 | [account-permissioning.json](final-original/run-81978d048975816a/test-cases/account-permissioning.json) |
| 根字段/部署绑定, 改根回退 | [deployment-binding.json](final-original/run-81978d048975816a/test-cases/deployment-binding.json), [root-mutation.json](final-original/run-81978d048975816a/test-cases/root-mutation.json) |
| T 域引导与认证, 本域普通身份/凭证锚及负例 | [domains.json](final-original/run-81978d048975816a/test-cases/domains.json), [identities.json](final-original/run-81978d048975816a/test-cases/identities.json) |
| 任务创建资格, G0/G1 角色权限, 结构配对及撤销终态 | [rp-registration.json](final-original/run-81978d048975816a/test-cases/rp-registration.json), [grant-structure.json](final-original/run-81978d048975816a/test-cases/grant-structure.json), [revocation.json](final-original/run-81978d048975816a/test-cases/revocation.json) |
| 原交易失败原因与原因缺失/恢复 | [original-transaction-trace.json](final-original/run-81978d048975816a/test-cases/original-transaction-trace.json), [trace-failure-recovery.json](final-original/run-81978d048975816a/test-cases/trace-failure-recovery.json) |
| 同版本竞争, 严格整块取证与失配拒绝 | [revision-competition.json](final-original/run-81978d048975816a/test-cases/revision-competition.json), [block-trace-fallback-faults.json](final-original/run-81978d048975816a/test-cases/block-trace-fallback-faults.json) |
| 固定高度装配失败, 链头异常/重启/恢复 | [assembly-failures.json](final-original/run-81978d048975816a/test-cases/assembly-failures.json), [highest-head.json](final-original/run-81978d048975816a/test-cases/highest-head.json) |
| 撤销后重查旧高度, 查询之间撤销而保持同高 | [historical-and-interleaved-revocation.json](final-original/run-81978d048975816a/historical-and-interleaved-revocation.json) |
| 停一节点后至少 3 个新块, 停两节点稳定 15 秒, 超龄/重启拒绝及恢复 | [node-fault-staleness-recovery.json](final-original/run-81978d048975816a/node-fault-staleness-recovery.json) |
| nonce/交易恢复及可注入双时钟测试 | [go-tests.jsonl](final-original/run-81978d048975816a/go-tests.jsonl), [必需测试结果](final-original/run-81978d048975816a/unit-and-integration-tests.json) |
| 强制超时和 RPC 不可用均非零退出并留存失败运行 | [verification-failures/index.json](verification-failures/index.json) |

本镜像的单交易 trace 在同块第二笔竞争交易上曾与失败回执不一致, [最初样本](transactions/competition-probe/competition.json)及[原块跟踪](transactions/competition-probe/block-hash.json)均保留. 已实现按原块哈希/交易顺序/原位置严格取证的回退, 不能绑定或解码时保持 FAILED/TRANSACTION_REVERTED. 没有以父块独立模拟猜失败码.

## 安全用例覆盖边界

| 对应部分 | 本轮证据 | 仍待实施 |
| --- | --- | --- |
| D0 最小网络 | 网络, 最小合约, 管理交易, 历史状态, 读取新鲜度及干净重建 | D0 最小协议仍须真实 ES256/SD-JWT, did:web/TLS, 挑战及上下文验证 |
| S26 | 停链后重复读取和重启均 STATE_STALE, 旧块接收不续期 | 网关与订单定案的业务效果 |
| S49 | 已许可无权交易回退, 两笔同版本合法交易仅一笔成功, 原回执/原因可追溯 | HTTP 接受前/后的 409/202/operation 行为及材料交付 |
| S50 | G0/G1 读取之间确认撤销仍固定 h, 失败项不回退 latest, 后续读到撤销 | G2 与真实采购请求的拒绝效果 |
| S51 | 同高异头, 节点回退, 部署变化, 未来时间/回拨及可信新鲜头恢复 | 完整网关 ready/定案及订单效果 |

未将任何完整 S 用例, E6/E7 或 M1/M2 标为通过. 合成凭证和委托不作为真实应用验签通过的证据. 复跑命令见[网络说明](../README.md), [合约说明](../../../contracts/README.md)和[读取说明](../../../internal/ledger/README.md).
