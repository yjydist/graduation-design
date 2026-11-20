# 毕设实施与验收

当前处于 [M4 实验, 演示与论文阶段](#m4-实验-演示与论文). 任务书结束日期为 2027-05-21. [正式实验索引](experiments/README.md), [实验共用方法](docs/experiments/实验计划.md), [实验工作流变更任务](openspec/changes/standardize-experiment-workflow/tasks.md).

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
- [x] 完成 D0-M3 实机联合验收. 修复后独立实例 34/34, 并保存 E6 撤销窗口和 E7 故障样本作为预跑证据. [联合验收汇总](infra/fabric/evidence/m3-recovery/fixes/run-a297ef63438bdd10/summary.json), [预跑索引](infra/fabric/evidence/README.md#既有网络与协议验收).

## M4 实验, 演示与论文

### C0/B0/B1 采购对照基线

[归档任务](openspec/changes/archive/2026-11-18-m4-reproducible-baseline/tasks.md), [主规范](openspec/specs/reproducible-procurement-experiments/spec.md), [独立核验](openspec/changes/archive/2026-11-18-m4-reproducible-baseline/verification.md).

- [x] 固定三域逻辑夹具, RP/BM 用例矩阵, 策略和种子. 两轮独立部署的逻辑夹具摘要与用例矩阵一致. [两轮输入对照](infra/fabric/evidence/baseline/validation/comparison.json).
- [x] 接通 C0 主库一致快照和锁后版本复核. 等锁期间版本改变时整次重验, 决定记录实际版本和读取时间. [C0 场景核验](openspec/changes/archive/2026-11-18-m4-reproducible-baseline/verification.md#需求与场景核对).
- [x] 独立回读 C0 和 Fabric 已应用视图的共同登记锚点. 预置摘要, 实际锚点摘要和来源版本都可核对. [登记锚点复算](infra/fabric/evidence/baseline/verification/registry-readback-fixed/comparison.json).
- [x] 核对三组静态验签缓存配置. C0/B0 无跨请求复用, B1 同材料有命中且状态变更后仍拒绝失效材料. [三组配置核验](openspec/changes/archive/2026-11-18-m4-reproducible-baseline/verification.md#需求与场景核对).
- [x] 接通隔离实例的确定性采购基线入口. 每轮 12 次询价允许, 6 笔 800 元唯一订单, 6 次 1200 元拒绝, 拒绝侧无新增订单或业务键. [原始请求与主库对账](infra/fabric/evidence/README.md#m4-采购基线).
- [x] 完成基线导出和失败留证. 准备失败, 挑战失败, 执行接口失败及依赖订单未执行均有阶段和关联记录. [基线故障回归](openspec/changes/archive/2026-11-18-m4-reproducible-baseline/verification.md#执行接口故障留证修复后复核).
- [x] 用同一种子复跑两轮干净环境. 各通过 12 个订单用例, 判定与业务副作用一致, 各轮部署和材料标识独立. [修复后双轮对照](infra/fabric/evidence/baseline/verification/execute-failure-fix/comparison.json).

### E1 采购功能闭环

[E1 方法](docs/experiments/E1-采购功能闭环.md), [E1 报告](experiments/e1-procurement/result.md).

- [x] 用迁移前驱动在两个独立实例验证 F01-F16. 两轮均为 16/16, 各轮有清单, 请求和模型轨迹. [E1 运行批次](experiments/e1-procurement/result.md#2-运行批次).
- [x] 用独立驱动完成固定构建复跑. `run-3f8a7a6db26d582c` 的 F01-F16 为 16/16. [正式轮次汇总](experiments/e1-procurement/runs/run-3f8a7a6db26d582c/summary.json).
- [x] 核对固定构建轮次的模型工具轨迹和网关请求. `run-3f8a7a6db26d582c` 记录 8 个真实模型会话, 19 次工具调用和 78 次网关请求. [模型轨迹](experiments/e1-procurement/runs/run-3f8a7a6db26d582c/llm-traces.json), [请求](experiments/e1-procurement/runs/run-3f8a7a6db26d582c/requests.csv), [对账](experiments/e1-procurement/runs/run-3f8a7a6db26d582c/audit.json).
- [x] 对账固定构建轮次的 RP/BM 采购效果. `run-3f8a7a6db26d582c` 中两种根各创建一笔 800 元订单, 1200 元原价和改报的四个负例均无订单或订单业务键. [结果与主库核对](experiments/e1-procurement/result.md#5-固定构建复跑), [对账文件](experiments/e1-procurement/runs/run-3f8a7a6db26d582c/audit.json).
- [x] 整理迁移前和固定构建中的失败轮次. 已记录失败运行 ID, 首个受阻阶段和处理结果. [迁移前异常](experiments/e1-procurement/result.md#4-失败轮次与结论边界), [固定构建异常](experiments/e1-procurement/result.md#5-固定构建复跑).
- [x] 从固定构建轮次的原始请求, 模型及主库记录离线重算 RP/BM 结果. `run-3f8a7a6db26d582c` 在 `e1-analyzer/v1` 下只读复算通过并与已发布计数一致, 另核对失败样本 `run-f6b3cc4a627e1a49` 的缺测识别. [复算表](experiments/e1-procurement/analysis/run-3f8a7a6db26d582c/recomputed-table.md), [复算 JSON](experiments/e1-procurement/analysis/run-3f8a7a6db26d582c/recomputed.json), [报告说明](experiments/e1-procurement/result.md#6-离线复算与来源引用).

### E2 安全与状态机检查

[E2 方法](docs/experiments/E2-安全与状态机检查.md).

- [ ] 运行 S01-S25 身份, 请求与父子约束配对. 交付首个拒绝点和业务副作用核对表.
- [ ] 运行 S26-S51 状态, 关联与根授权配对. 交付按状态版本和独立根模式汇总的判定表.
- [ ] 运行 S52-S75 报价, 并发与材料交付配对. 交付挑战, 报价, 订单及材料交付的核对表.
- [ ] 运行 S76-S90 共同根与域资格配对. 交付含实际认证 ID, 域 revision 和响应码的记录.
- [ ] 运行 S91-S99 锁后求值, 身份生命周期与编码检查. 交付风险和时点证据, 恢复前后管理证书绑定与密钥版本对照.
- [ ] 运行 S100-S103 异步管理结果和 nonce 检查. 交付受理前后 HTTP 响应, 原 txID, 查询状态与挑战绑定的核对记录.
- [ ] 执行至少 10000 组父子约束检查. 交付独立判据的对照表, 扰动维度, 分歧与种子.
- [ ] 执行 100 个种子各 100 步的状态机检查. 交付各轮轨迹, 最短反例或分歧数为零的汇总.
- [ ] 汇总 E2 正式结果. 交付 S01-S103 配对覆盖表, 缺测和异常清单, 可回查各组运行 ID.

### E3 动态调整与恢复

[E3 方法](docs/experiments/E3-动态调整与恢复.md). M3 已有[真实 LLM 预跑轨迹](infra/fabric/evidence/m3-recovery/original/run-f71a13453be0384e/m3-agent-traces.json).

- [ ] 对照暂停和撤销 G1. 交付采用变更块后的拒绝, 暂停恢复与撤销后新路径的时间线.
- [ ] 运行改派 B2. 交付旧报价被拒, B2 重新询价成单和仅重签叶子的轨迹与行数对账.
- [ ] 对照 B1 换钥和叶子 VC 撤销. 交付旧材料拒绝, 新材料通过及同主体原报价适用条件的轨迹.
- [ ] 对照撤销 B 域认证和暂停 B 域. 交付依赖 B 的路径失效, A/C 对照通过及各自恢复条件的轨迹.
- [ ] 对照 T 同钥续发和 IB 换钥后重新认证. 交付凭证及委托的复用与重签计数, 原报价有效截止.
- [ ] 验证同钥收缩声明范围和普通主体账户恢复. 交付披露配对, 原 `status` 与新旧管理绑定及应用密钥版本的对照.
- [ ] 验证 T 离线与 C 收紧准入. 交付本地验证可用条件, 超龄或业务禁止拒绝的记录.
- [ ] 验证任务取消, 风险变化及期限缩短. 交付各条件下询价和下单的决定, 截止与恢复条件.
- [ ] 用真实模型运行响应丢失后的核账轨迹. 交付工具调用顺序, 停发记录, 原创建决定和核账回执.
- [ ] 汇总 E3 正式轨迹. 交付生效点, 权限和有效期, 重签与交付次数表, 附对应运行 ID 及模型轨迹.

### E4 微基准

[E4 方法](docs/experiments/E4-微基准.md).

- [ ] 测量材料生成及 ES256 签名和验签. 交付分阶段耗时和分配量原始表.
- [ ] 测量披露处理及 A-FULL 对照. 交付属性数, 出示字节, 耗时与同语义核对表.
- [ ] 测量路径遍历与收缩. 交付各深度的耗时与分配量对照表.
- [ ] 测量 OPA 求值. 交付各策略规模的耗时, 分配与判定表.
- [ ] 测量挑战和业务事务. 交付分段耗时与查询, 分配记录.
- [ ] 对照 C0/B0 状态装配. 交付一致快照开启和依赖读取的耗时, 查询次数及字节表.
- [ ] 对照 B0/B1 与 A-REUSE 的适用配置. 交付冷热耗时, 复用率, 缓存命中和动态校验结果.
- [ ] 汇总 E4 结果. 交付阶段图和冷热对照表, 注明独立轮数, 样本量与源运行.

### E5 开放到达负载

[E5 方法](docs/experiments/E5-开放到达负载.md).

- [ ] 短跑验证开放到达, 超时和排空对账. 交付计划, 启动, 完成和漏测计数, 并核对三条恒等式.
- [ ] 完成默认负载的 C0/B0/B1 配对重复. 交付每组 5 轮的种子, 实际到达率, 询价和订单样本及吞吐.
- [ ] 完成 10/50/100/200/500 操作每秒的到达率扫描. 交付各档完成率, 拒绝率, 排队, 丢弃与超时表.
- [ ] 完成主体数扫描. 交付 100/1000/10000 主体下的吞吐和延迟对照.
- [ ] 完成深度扫描及 RP/BM 配对. 交付深度 1/2/4/8 的结果及相同深度下两种根的对照.
- [ ] 核对不同配置的验签命中, 端到端延迟与业务副作用. 交付缓存与请求计数对账和负例记录.
- [ ] 发布 E5 负载图. 交付按实际样本量报告的 P50/P95, 完成率和失败比例图, 满足阈值时另列 P99.

### E6 撤销窗口

[E6 方法](docs/experiments/E6-撤销窗口.md), [结果模板](experiments/e6-revocation/result.md). M3 [预跑时间线](infra/fabric/evidence/m3-recovery/original/run-f71a13453be0384e/m3-e6-revocation-window.json)用于核对观测点.

- [x] 校验网关锁后定案采集点和实际时钟精度. 已持久化 `decision_at_ns` 与亚秒探针时点并增加 `OnDecisionCommitted` 钩子, 延迟响应回归测试核对定案, 业务提交与响应分离且原秒级期限判据通过. [定案时点回归](internal/gateway/decision_timing_test.go).
- [x] 完成 RP 隔离短跑. `run-c3a21eb94efa9dcc` 导出撤销原 txID, `t_valid`, `t_apply`, 双实例 `t_adopt`, 定案及响应关联记录 (`0` 违规放行, 分辨率 `1000 ns`). [RP 撤销时间线](experiments/e6-revocation/runs/run-c3a21eb94efa9dcc/revocations.csv), [RP 汇总](experiments/e6-revocation/runs/run-c3a21eb94efa9dcc/summary.json).
- [x] 完成 BM 隔离短跑. `run-86facf71a9d07b81` 在独立隔离实例完成双实例持续探针采样, 计划与完成数 `1106/1106`, `0` 漏探测与 `0` 违规放行. [BM 撤销时间线](experiments/e6-revocation/runs/run-86facf71a9d07b81/revocations.csv), [BM 汇总](experiments/e6-revocation/runs/run-86facf71a9d07b81/summary.json).
- [x] 离线复算一轮窗口. 停止服务后用 `e6-analyzer/v1` 对 `run-c3a21eb94efa9dcc` 与 `run-86facf71a9d07b81` 重算阶段耗时, 窗口, 删失归类与样本对账, 原始目录摘要不变. [RP 复算表](experiments/e6-revocation/analysis/run-c3a21eb94efa9dcc/recomputed-table.md), [BM 复算表](experiments/e6-revocation/analysis/run-86facf71a9d07b81/recomputed-table.md), [E6 短跑报告](experiments/e6-revocation/result.md).
- [ ] 完成主要场景正式重复. 交付至少 30 次独立运行的清单与汇总, 核对每轮时长, 业务前置条件及违规放行.
- [ ] 核验并扫描 `deltaState` 为 1/5/15 秒. 交付各档实际生效配置, 原探针时点, 撤销窗口和可用率对照.
- [ ] 完成撤销对象专项. 交付不同撤销对象及合法兄弟支的对照表.
- [ ] 完成深度与后代数扩展. 交付深度 2/8, 后代数 1/10/100 各档的样本及删失统计.
- [ ] 发布 E6 正式结果. 交付带运行 ID 的实例时间线, 窗口和可用率图, 注明实际分辨率, 独立轮数和未观测情况.

### E7 故障与并发

[E7 方法](docs/experiments/E7-故障与并发.md). M3 [故障预跑](infra/fabric/evidence/m3-recovery/original/run-f71a13453be0384e/m3-e7-fault-injection.json)用于核对主库和恢复观测点.

- [ ] 验证读取期间应用撤销块. 交付同一读取固定高度, 后续采用新块及缺依赖拒绝的记录.
- [ ] 分别验证停一个和两个排序节点. 交付探针确认, 原期限拒绝及恢复追块的时间线.
- [ ] 验证 C Peer 或交付中断. 交付 A/B 提交, C 末次高度及恢复后有效探针的记录.
- [ ] 对账两实例视图不一致的同键请求. 交付两个实例的探针与决定, 主库唯一订单和业务键核对.
- [ ] 验证等业务锁时撤销或过期. 交付锁前后检查点, 重验, 期限拒绝及挑战终态计数.
- [ ] 验证初验后风险升高. 交付锁后 OPA 求值及实际时点, 拒绝和主库副作用核对.
- [ ] 验证管理交易未知及授权交付响应丢失. 交付原 txID, 操作状态及原材料投递记录.
- [ ] 验证订单提交后丢响应再撤销 G1. 交付停发, 创建决定, 核账回执和历史完整性核对.
- [ ] 验证风险观测停更, 策略缺失及墙钟异常. 交付拒绝码, 零新增订单和恢复条件对照.
- [ ] 完成延迟和丢包对照. 交付各链路的实际配置, 拒绝, 恢复与订单行数矩阵.
- [ ] 汇总 E7 正式结果. 交付故障和并发场景判定表, 代表性时间线及各场景运行 ID.

### E8 账本与通信开销

[E8 方法](docs/experiments/E8-账本与通信开销.md).

- [ ] 测量 T 引导, 域认证, 本域登记和 C 服务准备. 交付分阶段耗时, 字节和对象数表.
- [ ] 测量授权, 轮换, 撤销与替换. 每类交付至少 30 个独立对象的交易阶段及校验记录.
- [ ] 测量空闲和负载下的探针与区块流. 交付发送, 确认, 采用率及消息和字节对照.
- [ ] 测量视图应用开销. 交付视图事务耗时, 检查点冲突与重验率记录.
- [ ] 采集 Peer, Orderer 及数据库资源. 交付每秒 CPU, RSS, 网络, 磁盘和适用队列记录.
- [ ] 测量客户端两次往返和每次出示大小. 交付 RP/BM 及适用消融的时延, 字节与材料计数.
- [ ] 发布 E8 开销结果. 交付分列客户端与后台阶段的配置对照表和图, 附运行 ID 及原始文件.

### 演示

[演示与交付规格](docs/implementation/证据交付与网关执行.md#4-演示与交付).

- [ ] 完成身份与信任视图. 交付能沿 T, 域机构与主体查到实际认证, 状态和密钥版本的界面及演示记录.
- [ ] 完成凭证披露视图. 交付能展示实际披露属性, 资格核对结果和保护字段边界的界面及演示记录.
- [ ] 完成委托树视图. 交付能展示 RP/BM 的根来源, 逐跳收缩及失效祖先的界面和用例截图.
- [ ] 完成采购任务视图. 交付能对照 800 元成单与 1200 元被拒的任务, 报价及业务结果界面.
- [ ] 完成决策时间线视图. 交付可追溯策略, 环境版本, 块高/哈希, 原探针期限和拒绝理由的界面及样例.
- [ ] 串联一次端到端演示. 交付演示步骤与录屏或截图, 覆盖两种根, 至少一次动态失效及恢复或核账.

### 论文

[毕设要求](毕设要求.md), [需求与验证证据](docs/design/AGENTS.md#从任务书到验证证据), [论文清单](paper/论文.md).

- [ ] 起草研究方法与实验设计章节. 交付可审阅初稿, 含对照变量, 采样设计和 E1-E8 对应问题.
- [ ] 整理论文结果表, 图和图注. 交付标明样本, 单位, 不确定性, 运行 ID 和原始数据入口的图表.
- [ ] 写出结果论证. 交付将 R1-R5 的主张关联实验指标, 对照和实际结果的章节.
- [ ] 写出局限与适用范围. 交付覆盖信任假设, 同机故障, 时钟分辨率及缺测的段落.
- [ ] 复核引用. 交付与正文对应的参考文献, 采用机制和关键出处页码核对结果.
- [ ] 复核文字复制比. 交付复制比不超过 10% 的报告及需要修改时的复核结果.
