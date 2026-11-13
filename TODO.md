# 毕设实施与验收

**当前状态.** Fabric D0 最小网络与 D0 最小协议已完成并通过验证. 离线单元测试通过, 在默认实例 `.local/fabric-d0` 与干净重建独立实例 `.local/fabric-d0-protocol` 上均通过 20 项 D0 网络与协议联合验收 (`20/20`), 完成 P-256 应用密钥与测试 CA `did:web` 根信任, W3C VC v2 本地上下文摘要固定, 以及绑定制备部署的 ES256/SD-JWT 凭证和 `AccessEvidencePackage` 出示闭环. 业务服务端点, OPA 求值与订单核账按 M1-M4 阶段推进. 任务书结束日期为 2027-05-21.

[Fabric 任务](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/tasks.md), [Fabric 核验](openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/verification.md), [D0 协议任务](openspec/changes/bootstrap-d0-protocol/tasks.md)与[证据索引](infra/fabric/evidence/README.md)记录实施和复跑.

| 阶段 | 待办 | 可进入下一阶段的证据 |
| --- | --- | --- |
| D0 最小网络 | [x] Fabric 单通道, 三域 Peer, 四 SmartBFT 排序身份, Go RP 登记链码, 原操作恢复和 PostgreSQL 固定高度视图 | 原实例和干净重建各 12/12. 覆盖 h/r, 版本竞争, 停一继续提交, 停两和 Peer 断流到期拒绝, 保留卷和失败样本. [Fabric D0 证据](infra/fabric/evidence/README.md) |
| D0 最小协议 | [x] 在已锁定的 Fabric 部署和 T 根基础上, 按固定 DID/JWK/上下文编码用测试 CA 验 did:web, 生成真实 ES256/SD-JWT 证据 | `go test -count=1 ./...` 离线通过; 默认实例与独立重建各 20/20 (`run-174750e6dc3e2e4d`, `run-7361ca2734fcc311`), 复算[请求, 任务, DID/JWK 及 nonce 向量](docs/implementation/协议编码与测试向量.md), 覆盖测试 CA `did:web` 解析, 上下文摘要固定, 真实签名出示与 8 字段篡改拒绝及零私钥泄漏扫描. [Fabric D0 证据](infra/fabric/evidence/README.md) |
| M1 直接访问 | [ ] 实现 T 域认证及 IA/IC 资格, 注册双证明, U/PA/C 服务 VC, 任务, C→U 根, OPA, Fabric 一致视图逐次装配, 锁后求值/期限复核, 挑战与幂等事务 | U 询价成功, 数据库可见已消费挑战和一份报价; 错误密钥, 原探针到期和锁后变为 BLOCKED 均无业务效果, 到期当秒拒绝 |
| M2 两种根与两级委托 | [ ] 完成 T 对 A/B/C 及 IA/IB/IC 的认证, PA 业务资格, 双域关联审批, G0/G1/G2 签发与收件, 祖先状态检查及双实例唯一订单约束 | RP/BM 各自跑通 800 元成功与 1200 元拒绝; 采用 G1 撤销块后拒绝旧路径, 同键并发只一笔订单, 锁后 ELEVATED/BLOCKED 不新建订单, 关联不转移权限. [功能用例](docs/experiments/验证用例.md) |
| M3 动态状态与恢复 | [ ] 在 M1 的一致视图与锁后求值基础上添加静态验签缓存, 身份状态管理/账户恢复, 域资格续发/收缩, 轮换/替换, 两实例未知订单核账 | E2/E3 的域认证及身份生命周期用例, S91-S103 配对用例和 T 离线场景通过, E6/E7 预跑通过. 可据原键查到未知订单及对应区块. [订单核账](docs/implementation/订单核账.md) |
| M4 实验与论文 | [ ] 完成 C0/B0/B1 及消融, 冻结夹具, 重复执行 E1-E8, 实现五个演示视图 | 干净环境可重建, 有包含失败样本的原始数据, 现象可追到具体请求和决策. [实验](docs/experiments/实验计划.md) |

首个 MVP 以 D0-M2 为边界, 具备真实凭证/签名, 两种根, 两级委托, 800 元成功/1200 元拒绝, 祖先撤销拒绝及并发幂等. 固定高度, 状态新鲜度, 最终期限和锁后策略求值随首个闭环验收, 不延期到缓存优化阶段. M3/M4 继续补齐完整生命周期, 故障恢复, 视图及实验, 不把 MVP 通过等同于全部研究任务完成.

文献工作可并行. 按[论文清单](paper/论文.md)记录采用机制, 假设与页码, 与导师核对贡献定位, 证明深度和比较范围. 设计参数与性能实测分开报告.
