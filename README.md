# 基于区块链的智能体跨域认证与委托授权方法研究

采购企业 A 把询价和下单委托给服务企业 B. 供应商 C 收到 B₁的订单时, 怎样确认它代表 A, 而且此刻仍有权下单?

```mermaid
flowchart TB
    B["B₁提交 800 元报价和本次下单证明"] --> C["C 选定一个已确认的 QBFT 区块"]
    C --> I["在该块核对 T 的域认证, 身份密钥和签发资格"]
    C --> G["在该块核对从根到叶的每一份委托"]
    I --> P["C 验签, 查当前策略和报价, 检查状态年龄"]
    G --> P
    P -->|"条件齐全"| O["原子记录决策和模拟订单"]
    P -->|"上级已撤销或状态过旧"| D["拒绝下单"]
```

身份采用三域共同认可的权威机构 T 作为唯一信任根. T 认证 A/B/C 域及 IA/IB/IC 的签发资格, 各域机构证明本域用户, 智能体和服务的身份. 采购委托由业务方签发, C 独立决定销售准入. 见[跨域身份与信任](docs/design/跨域身份与信任.md).

**D0 最小网络已完成.** [四节点 Besu](infra/besu/README.md), [AuthRegistry 最小 RP 登记/撤销切片](contracts/README.md)和[固定高度读取器](internal/ledger/README.md)已在 arm64 实际运行, 原实例与干净重建均通过完整验收. 证据包含 h/r 的 ACTIVE/REVOKED, 无权及版本竞争交易回退, 查询之间撤销仍同高读取, 停链超龄拒绝和恢复. [D0 证据索引](infra/besu/evidence/README.md)明确覆盖范围, [变更任务](openspec/changes/archive/2026-11-04-bootstrap-besu-state-verification/tasks.md)记录逐项进度.

D0 最小协议, 完整 ES256/SD-JWT/HTTP 证明, OPA/订单事务和 M1/M2 业务闭环仍待实施, 本轮未执行订单级 E6/E7. 当前夹具使用明确标记的合成应用材料.

| 想做什么 | 从这里开始 |
| --- | --- |
| 看懂一次采购为何获准或被拒 | [采购场景与总体设计](docs/design/采购场景与总体设计.md) |
| 查任务书要求与对应证据 | [毕设要求](毕设要求.md), [设计导航与需求追踪](docs/design/AGENTS.md) |
| 搭建网络, 编写验证器 | [技术栈](docs/implementation/技术栈.md), [实现导航](docs/implementation/AGENTS.md) |
| 复跑已完成的 D0 验收 | [网络命令](infra/besu/README.md), [状态读取](internal/ledger/README.md), [证据索引](infra/besu/evidence/README.md) |
| 测量撤销后还能下单多久 | [E6 撤销窗口](docs/experiments/实验计划.md#2-e6-撤销窗口), [实验导航](docs/experiments/AGENTS.md) |
| 按验收条件推进 | [任务安排](TODO.md) |
| 阅读论文或准备写作 | [文献清单](paper/论文.md), [全文与笔记索引](paper/README.md) |
