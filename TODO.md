# 毕设实施与验收

**当前状态.** Fabric D0 最小网络, D0 最小协议, M1 直接访问与 M2 两种根与两级委托已全部完成并通过验证. 离线单元测试 `go test -count=1 ./...` 全部通过, 在真实 Fabric 实例 `.local/fabric-d0` 上通过全部 30 项联合验收 (`30/30`, `run-acd4ab7dc0c992f7`), 完成 T 对 A/B/C 及 PA 业务资格认证, 双域身份关联 (`IdentityLink`) 审批与权限隔离, RP/BM 双根两级委托 (`G0`/`G1`/`G2`) 与 ANCESTOR_INACTIVE 撤销传播, C 独立策略拒绝合法 PA 根, 双网关实例同键并发唯一订单与锁后阻塞守卫, 以及基于 MCP Go SDK (`ledgerctl mcp`) 与 OpenAI/Anthropic 官方 Go SDK 的 800 元成单 / 1200 元超限拒绝闭环. 后续动态状态与实验按 M3-M4 阶段推进. 任务书结束日期为 2027-05-21.

[Fabric 任务](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/tasks.md), [Fabric 核验](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/verification.md), [D0 协议任务](openspec/changes/archive/2026-11-13-bootstrap-d0-protocol/tasks.md), [M1 直接访问任务](openspec/changes/archive/2026-11-13-implement-m1-direct-access/tasks.md), [M2 双根与委托任务](openspec/changes/implement-m2-dual-roots-and-delegation/tasks.md)与[证据索引](infra/fabric/evidence/README.md)记录实施和复跑.

| 阶段 | 待办 | 可进入下一阶段的证据 |
| --- | --- | --- |
| D0 最小网络 | [x] Fabric 单通道, 三域 Peer, 四 SmartBFT 排序身份, Go RP 登记链码, 原操作恢复和 PostgreSQL 固定高度视图 | 原实例和干净重建各 12/12. 覆盖 h/r, 版本竞争, 停一继续提交, 停两和 Peer 断流到期拒绝, 保留卷和失败样本. [Fabric D0 证据](infra/fabric/evidence/README.md) |
| D0 最小协议 | [x] 在已锁定的 Fabric 部署和 T 根基础上, 按固定 DID/JWK/上下文编码用测试 CA 验 did:web, 生成真实 ES256/SD-JWT 证据 | `go test -count=1 ./...` 离线通过; 默认实例与独立重建各 20/20 (`run-174750e6dc3e2e4d`, `run-7361ca2734fcc311`), 复算[请求, 任务, DID/JWK 及 nonce 向量](docs/implementation/协议编码与测试向量.md), 覆盖测试 CA `did:web` 解析, 上下文摘要固定, 真实签名出示与 8 字段篡改拒绝及零私钥泄漏扫描. [Fabric D0 证据](infra/fabric/evidence/README.md) |
| M1 直接访问 | [x] 实现 T 域认证及 IA/IC 资格, 注册双证明, U/PA/C 服务 VC, 任务, C→U 根, OPA, Fabric 一致视图逐次装配, 锁后求值/期限复核, 挑战与幂等事务 | `go test -count=1 ./...` 离线通过; 真实 Fabric 实例 `.local/fabric-d0` 通过 26 项 D0 + 直接访问联合验收 (`26/26`, `run-d317a93ba562e854`): U 询价成功且库内可见已消费挑战/决策与不可变报价行, 同键重试复用原 `quoteId`, 异摘要冲突 `409`; 错误叶子私钥, 原探针到期 (`STATE_STALE`), 锁后 `BLOCKED` (`403`) 均无报价副作用, 到期当秒拒绝 (`CHALLENGE_EXPIRED`) 及零私钥泄漏. [Fabric D0 与直接访问证据](infra/fabric/evidence/README.md) |
| M2 两种根与两级委托 | [x] 完成 T 对 A/B/C 及 IA/IB/IC 的认证, PA 业务资格, 双域关联审批, G0/G1/G2 签发与收件, 祖先状态检查, 双实例唯一订单约束, 以及接入 MCP Go SDK (`ledgerctl mcp`) 与 OpenAI/Anthropic 官方 Go SDK (`LLM_PROVIDER`/`LLM_BASE_URL`/`LLM_API_KEY`/`LLM_MODEL`) 的 A₁/B₁ 智能体协议工具调用闭环 | RP/BM 各自跑通 800 元成功与 1200 元拒绝 (含 OpenAI/Anthropic SDK 智能体工具调用闭环); 采用 G1 撤销块后拒绝旧路径, 同键并发只一笔订单, 锁后 ELEVATED/BLOCKED 不新建订单, 关联不转移权限. [功能用例](docs/experiments/验证用例.md) |
| M3 动态状态与恢复 | [ ] 在 M1 的一致视图与锁后求值基础上添加静态验签缓存, 身份状态管理/账户恢复, 域资格续发/收缩, 轮换/替换, 两实例未知订单核账, 以及 B₂ 改派与核账恢复的 LLM 智能体工具轨迹 | E2/E3 的域认证及身份生命周期用例, S91-S103 配对用例和 T 离线场景通过, E6/E7 预跑通过. 可据原键查到未知订单及对应区块. [订单核账](docs/implementation/订单核账.md) |
| M4 实验与论文 | [ ] 完成 C0/B0/B1 及消融, 冻结夹具, 按"同核双驱动"重复执行 E1-E8 (E1/E3 使用真实 LLM 智能体, E2/E4-E8 复用底层确定性工具高频驱动), 实现五个演示视图 | 干净环境可重建, 有包含失败样本和模型调用记录的原始数据, 现象可追到具体请求, 工具轨迹和决策. [实验](docs/experiments/实验计划.md) |

首个 MVP 以 D0-M2 为边界, 具备真实凭证/签名, 两种根, 两级委托, 接入可配置 LLM API 的 A₁/B₁ 智能体工具闭环, 800 元成功/1200 元拒绝, 祖先撤销拒绝及并发幂等. 固定高度, 状态新鲜度, 最终期限和锁后策略求值随首个闭环验收, 不延期到缓存优化阶段. M3/M4 继续补齐完整生命周期, 故障恢复, 视图及实验, 不把 MVP 通过等同于全部研究任务完成.

文献工作可并行. 按[论文清单](paper/论文.md)记录采用机制, 假设与页码, 与导师核对贡献定位, 证明深度和比较范围. 设计参数与性能实测分开报告.
