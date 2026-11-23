# 毕设实施与验收

项目当前处于 [M4 演示与交付阶段](#m4-演示与交付). 任务书结束日期为 2027-05-21. [实验进度](experiments/TODO.md).

每项完成后附运行 ID, 报告章节或核验文件. 周报可直接引用交付物, 概述实际配置, 结果和缺测. 复跑保留原运行及失败证据.

## D0 最小原型

### Fabric 网络与登记

[归档任务](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/tasks.md), [Fabric 验收证据](infra/fabric/evidence/README.md#既有网络与协议验收).

- [x] 搭建三域许可通道及四个 SmartBFT 排序身份. 三个 Peer 的创世哈希一致, 区块签名门槛为 3/4. [治理与通道核验](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/verification.md#判据追踪).
- [x] 部署三域共同批准的登记链码并初始化 T 根. 验收记录可核对定义, 批准和根记录, 单组织变更与无权登记被拒. [部署与登记核验](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/verification.md#实现与场景依据).
- [x] 验收委托登记, 撤销, 原子替换与版本竞争. 父授权先撤销时, 已背书的子授权登记以 `MVCC_READ_CONFLICT` 入块, 子记录保持未创建. [链码状态与竞争核验](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/verification.md#实现与场景依据).
- [x] 持久化管理交易并恢复原提交结果. 同键重试沿用原 txID, 重播产生 `DUPLICATE_TXID` 时仍按原交易的校验码和块位置定案. [交易恢复核验](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/verification.md#判据追踪).
- [x] 原子应用有效区块并实现 PostgreSQL 固定高度读取. 依赖装配期间应用撤销块时, 当次仍取 `h`, 后续读取在 `r` 查到撤销. [视图与历史复查核验](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/verification.md#判据追踪).
- [x] 用原探针期限控制在线读取并验收停机恢复. 停一个排序节点仍可确认探针, 停两个或 C Peer 断流时按原期限拒绝, 恢复补块并采用新探针后就绪. [故障回归](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/verification.md#判据追踪).
- [x] 完成独立重建与跨部署材料隔离对照. 原实例和干净重建各 12/12, 旧部署材料在新实例被拒. [两轮运行](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/verification.md#运行结果), [重建对照](infra/fabric/evidence/comparison/rebuild.json).

### 最小协议

[归档任务](openspec/changes/archive/2026-11-13-bootstrap-d0-protocol/tasks.md), [协议编码与测试向量](docs/implementation/协议编码与测试向量.md).

- [x] 实现严格 JSON 解析, JCS 和挑战编码. 固定向量可复算 `taskSpecDigest`, 询价和订单的 `requestHash` 及 nonce 编码. [编码与向量验收](infra/fabric/evidence/protocol/rebuilt/run-7361ca2734fcc311/summary.json).
- [x] 实现 P-256 公钥与 DID/JWK 指纹校验. 固定向量可复算公钥坐标和文档摘要, 非法点和错误密钥用途配对被拒. [DID/JWK 验证记录](infra/fabric/evidence/protocol/rebuilt/run-7361ca2734fcc311/summary.json).
- [x] 接通测试 CA 下的 `did:web` 并固定本地 VC v2 上下文. TLS 信任, 主机名及文档摘要得到核对, 上下文篡改被拒. [解析与上下文验收](infra/fabric/evidence/protocol/rebuilt/run-7361ca2734fcc311/summary.json).
- [x] 签发真实 ES256 域认证和委托以及 SD-JWT 凭证, 绑定 `KB-JWT` 出示. 完整材料通过固定高度验证, 八类证据字段的单字段篡改被拒. [出示验收](infra/fabric/evidence/protocol/rebuilt/run-7361ca2734fcc311/summary.json).
- [x] 将真实协议夹具登记到 Fabric 并完成独立重建. 默认实例和干净重建各 20/20, 公开材料经私钥检查. [默认轮汇总](infra/fabric/evidence/protocol/original/run-174750e6dc3e2e4d/summary.json), [重建轮汇总](infra/fabric/evidence/protocol/rebuilt/run-7361ca2734fcc311/summary.json).

## M1 直接访问

[归档任务](openspec/changes/archive/2026-11-13-implement-m1-direct-access/tasks.md), [实机联合验收 26/26](infra/fabric/evidence/direct-access/original/run-d317a93ba562e854/summary.json).

- [x] 实现身份注册挑战, 应用密钥与管理证书双证明. 验收覆盖正确注册和缺任一证明或错管理证书拒绝. [注册与材料交付验收](infra/fabric/evidence/direct-access/original/run-d317a93ba562e854/direct-access.json).
- [x] 接通 T 对 A/C 域及签发机构的资格认证, 签发 U, PA 与 C 服务的凭证并交付 C 给 U 的 RP 根. 钱包收件关联原有效交易, 重投按收件键去重. [根材料交付任务](openspec/changes/archive/2026-11-13-implement-m1-direct-access/tasks.md#1-注册双证明-身份凭证与-c-u-根材料交付).
- [x] 给网关接入 PostgreSQL 固定高度视图及原探针期限. 缺依赖停止装配, 探针过期返回 `503 STATE_STALE`. [状态装配与期限验收](infra/fabric/evidence/direct-access/original/run-d317a93ba562e854/direct-access.json).
- [x] 校验 OPA 策略包与固定 T 根, 锁后重新求值. 初验允许但锁后风险升为 `BLOCKED` 时拒绝询价, 主库无新增报价. [锁后风险验收](infra/fabric/evidence/direct-access/original/run-d317a93ba562e854/direct-access.json).
- [x] 接通挑战, 持有者证明和 `quote.read` 事务. U 持 RP 根询价后, 已消费挑战, 允许决定和不可变报价行可互相核对. [询价事务验收](infra/fabric/evidence/direct-access/original/run-d317a93ba562e854/direct-access.json).
- [x] 验收询价幂等和业务截止. 同键重试复用原报价, 同键异摘要冲突, 到期当秒和错误叶子密钥分别被拒绝. [边界与幂等验收](infra/fabric/evidence/direct-access/original/run-d317a93ba562e854/direct-access.json).

## M2 两种根与两级委托

[归档任务](openspec/changes/archive/2026-11-15-implement-m2-dual-roots-and-delegation/tasks.md), [实机联合验收 30/30](infra/fabric/evidence/m2-delegation/original/run-acd4ab7dc0c992f7/summary.json).

- [x] 补齐 T 对 B 域及 IB 的认证和三域身份夹具. A1, B1, U-in-B 及 PA 的身份登记, 凭证和域资格可关联核对. [三域引导与交付任务](openspec/changes/archive/2026-11-15-implement-m2-dual-roots-and-delegation/tasks.md#2-三域身份引导与两级委托-g0-g1-g2-逐跳交付).
- [x] 实现 PA 采购资格和两种根路径. 实机核对 RP 使用 C 根, BM 使用 PA 根, C 仍能独立拒绝合法 PA 根. [两种根与准入验收](infra/fabric/evidence/m2-delegation/original/run-acd4ab7dc0c992f7/m2-delegation.json).
- [x] 实现双域身份关联提议和审批. 单方批准保持待定, 两域审批后生效, U-in-B 仍使用自己的权限. [身份关联配对](infra/fabric/evidence/m2-delegation/original/run-acd4ab7dc0c992f7/m2-delegation.json).
- [x] 实现 G0/G1/G2 逐跳签发, 约束收缩和钱包交付. 两种根的路径各验证 5000/5000/1000 元和深度 2/1/0, 收件关联有效提交并支持去重. [逐跳交付任务](openspec/changes/archive/2026-11-15-implement-m2-dual-roots-and-delegation/tasks.md#2-三域身份引导与两级委托-g0-g1-g2-逐跳交付).
- [x] 接通 `order.create` 并核对报价归属, 时效和额度. RP/BM 各通过 800 元唯一成单及 1200 元拒绝. [两组订单结果](infra/fabric/evidence/m2-delegation/original/run-acd4ab7dc0c992f7/m2-delegation.json).
- [x] 验收撤销和锁后风险对订单的影响. 采用 G1 撤销块或锁后为 `ELEVATED`/`BLOCKED` 时拒绝, 主库无新增订单. [动态边界验收](infra/fabric/evidence/m2-delegation/original/run-acd4ab7dc0c992f7/m2-delegation.json).
- [x] 实现双网关下单幂等. 并发同键同摘要只生成一笔订单, 同键异摘要返回 `409`. [并发与主库核对](infra/fabric/evidence/m2-delegation/original/run-acd4ab7dc0c992f7/m2-delegation.json).
- [x] 接入 MCP 钱包工具及 OpenAI, Anthropic 双协议模型运行器. 离线验证双协议, 实机保存 A1 签发 G2 和 B1 询价下单的真实模型工具轨迹. [SDK 验收任务](openspec/changes/archive/2026-11-15-implement-m2-dual-roots-and-delegation/tasks.md#4-三大官方-sdk-智能体运行时与-mcp-协议工具层), [实机工具轨迹](infra/fabric/evidence/m2-delegation/original/run-acd4ab7dc0c992f7/m2-agent-traces.json).

## M3 动态状态与恢复

[归档任务](openspec/changes/archive/2026-11-16-implement-m3-dynamic-state-and-recovery/tasks.md), [独立核验](openspec/changes/archive/2026-11-16-implement-m3-dynamic-state-and-recovery/verification.md), [预跑与回归索引](infra/fabric/evidence/README.md#既有网络与协议验收).

- [x] 实现域认证同钥续发, 声明收缩, 撤销与域暂停恢复. 配对核对旧认证失效, 机构换钥重认证及越权操作拒绝. [域与身份生命周期验收](openspec/changes/archive/2026-11-16-implement-m3-dynamic-state-and-recovery/verification.md#需求与场景覆盖).
- [x] 实现普通主体状态变更和应用密钥轮换. 不同角色的操作权限, 密钥版本推进和旧材料失效有专项回归. [身份生命周期验收](openspec/changes/archive/2026-11-16-implement-m3-dynamic-state-and-recovery/verification.md#需求与场景覆盖).
- [x] 接通管理账户恢复入口和一次性挑战双证明. 新证书绑定与应用密钥版本原子更新, 原身份状态保持, 重放被拒. [恢复入口边界回归与实机证据](openspec/changes/archive/2026-11-16-implement-m3-dynamic-state-and-recovery/verification.md#本轮修复与验证).
- [x] 实现凭证撤销, 任务取消及委托暂停恢复. 暂停恢复保持原截止, 取消后的任务请求被拒. [动态状态运行记录](infra/fabric/evidence/m3-recovery/original/run-f71a13453be0384e/m3-dynamic-recovery.json).
- [x] 实现 B1 静态验签缓存及命中后的动态复核. 轮换后即使签名缓存命中, 旧密钥版本仍被拒. [验签缓存核验](openspec/changes/archive/2026-11-16-implement-m3-dynamic-state-and-recovery/verification.md#需求与场景覆盖).
- [x] 验证声明范围收缩和 T 离线核验. 隐藏和披露可选声明分别判定, 本地材料有效且状态新鲜时, 请求无需在线调用 T. [声明与离线验证记录](infra/fabric/evidence/m3-recovery/original/run-f71a13453be0384e/m3-dynamic-recovery.json).
- [x] 接通异步管理交易的原 txID 持久化, 重启恢复和授权查询. 实机核对受理前冲突, 受理后提交结果以及本人或授权本域审计者的查询权限. [原交易回归](infra/fabric/evidence/m3-recovery/fixes/supplemental/run-48e2661bcc4b7434/management-http.json), [查询权限实机核验](openspec/changes/archive/2026-11-16-implement-m3-dynamic-state-and-recovery/verification.md#本轮修复与验证).
- [x] 实现双实例未知订单核账与停发. 通过可信服务身份绑定审计与恢复角色, 以回执区分 `CREATED`, `NOT_CREATED` 和 `UNKNOWN`, 迟到重发被拒. [停发与核账验收](openspec/changes/archive/2026-11-16-implement-m3-dynamic-state-and-recovery/verification.md#已修复问题).
- [x] 按原 `h/r` 和探针期限复核历史决定并恢复待送回执. 归档验收覆盖历史材料与策略重放, 回执重投保持原序号及结果. [历史复核与回执验收](openspec/changes/archive/2026-11-16-implement-m3-dynamic-state-and-recovery/verification.md#已修复问题).
- [x] 跑通真实模型的 B2 改派及订单响应丢失恢复. 保存旧报价被拒, 重新询价成单和查明原订单的 MCP 工具轨迹. [实机工具轨迹](infra/fabric/evidence/m3-recovery/original/run-f71a13453be0384e/m3-agent-traces.json).
- [x] 完成 D0-M3 实机联合验收. 修复后独立实例 34/34. [联合验收汇总](infra/fabric/evidence/m3-recovery/fixes/run-a297ef63438bdd10/summary.json).

## M4 演示与交付

[演示与交付规格](docs/implementation/证据交付与网关执行.md#4-演示与交付), [三域 Web 工作台提案](openspec/changes/m4-domain-web-workbench/proposal.md), [实施任务](openspec/changes/m4-domain-web-workbench/tasks.md).

- [ ] 建立 Web 与 MCP 共用的业务操作. 交付按主体及任务约束的工具入口, 以及人工操作和智能体调用共用授权与幂等判据的回归.
- [ ] 交付三域共用的前后端镜像和 Compose 模板. 验证 A/B/C 用相同镜像摘要及各自运行配置独立启动, 浏览器按版本化 API 访问本域后端.
- [ ] 交付三域登录和本域管理. A/B/C 管理员分别完成获准的管理写操作, 在页面核对原操作 ID, 原交易和确认结果, 跨域越权被拒.
- [ ] 交付采购员对话和派单. A 域 U 从网页确认任务及委托, A1 转委托给 B1, B1 以本域钱包向 C 询价和模拟下单. 页面可恢复查看任务进度及实际工具结果.
- [ ] 完成身份与信任视图. 交付能沿 T, 域机构与主体查到实际认证, 状态和密钥版本的界面及演示记录.
- [ ] 完成凭证披露视图. 交付能展示实际披露属性, 资格核对结果和保护字段边界的界面及演示记录.
- [ ] 完成委托树视图. 交付能展示 RP/BM 的根来源, 逐跳收缩及失效祖先的界面和用例截图.
- [ ] 完成采购任务视图. 交付能对照 800 元成单与 1200 元被拒的任务, 报价及业务结果界面.
- [ ] 完成决策时间线视图. 交付可追溯策略, 环境版本, 块高/哈希, 原探针期限和拒绝理由的界面及样例.
- [ ] 串联从浏览器登录开始的三域实机演示. 交付演示步骤, 录屏或截图及可追查证据, 覆盖两种根, 800 元唯一成单, 1200 元超额被拒, 以及至少一次动态失效及恢复或核账.

## 论文

[毕设要求](毕设要求.md), [需求与验证证据](experiments/README.md#任务书需求与实验用例), [论文清单](paper/论文.md).

- [ ] 起草研究方法与实验设计章节. 交付可审阅初稿, 含对照变量, 采样设计和 E1-E8 对应问题.
- [ ] 整理论文结果表, 图和图注. 交付标明样本, 单位, 不确定性, 运行 ID 和原始数据入口的图表.
- [ ] 写出结果论证. 交付将 R1-R5 的主张关联实验指标, 对照和实际结果的章节.
- [ ] 写出局限与适用范围. 交付覆盖信任假设, 同机故障, 时钟分辨率及缺测的段落.
- [ ] 复核引用. 交付与正文对应的参考文献, 采用机制和关键出处页码核对结果.
- [ ] 复核文字复制比. 交付复制比不超过 10% 的报告及需要修改时的复核结果.
