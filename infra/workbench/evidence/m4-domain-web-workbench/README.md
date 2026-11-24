# M4 三域工作台实机核验

在同一隔离 Fabric 项目 `grad-fabric-499a67adbca3` 中, 从 A/B/C 浏览器登录到原链上交易和 C 订单主库对账. 三域使用相同的前后端镜像, 各自绑定独立存储, 本域账号和签名材料. [操作手册](../../README.md), [归档任务](../../../../openspec/changes/archive/2026-11-24-m4-domain-web-workbench/tasks.md).

| 场景 | 实际结果 | 证据 |
| --- | --- | --- |
| A/B/C 管理员办理本域 PA 操作 | 原交易分别在第 93, 94, 96 块确认 `VALID`. 同键重试返回原交易. 越权和缺少 CSRF 的写请求无新增操作. | [管理操作日志](live-admin.json), [A 域](a-management.png), [B 域](b-management.png), [C 域](c-management.png) |
| U 网页对话并确认 RP | C 签发 G0, U 签发 G1, A1 模型通过 MCP 签发 G2, B1 模型询价并创建一笔 800 元订单. | [草稿](rp-draft.png), [运行与模型轨迹](rp-run.json), [任务投影](rp-final-projection.json) |
| U 网页对话并确认 BM | PA 签发 G0, A1 模型完成转委托, B1 模型通过 MCP 得到 1200 元报价后停止. 确定性调用补发订单, C 返回 `AMOUNT_LIMIT_EXCEEDED`. | [草稿](bm-draft.png), [运行与模型轨迹](bm-run.json), [确定性调用](bm-probe.json), [任务投影](bm-final-projection.json) |
| U 暂停和恢复原 G1 | 暂停交易在第 459 块确认. C 在第 507 块以 `ANCESTOR_INACTIVE` 拒绝 B1. 恢复交易在第 509 块确认后询价成功. 三次 G1 版本的原截止均为 `1795424645`. | [暂停页面](suspend.png), [拒绝响应](suspended-probe.json), [恢复页面](resume.png), [恢复后询价](resumed-probe.json) |
| C 主库对账 | 实例只有一笔 800 元订单. 1200 元拒绝及暂停拒绝均未新增订单. 原始管理操作与 G2 接收回执通过 ID 关联. | [登记与主库对账](ledger-reconciliation.json) |
| 页面及证据授权 | U 可读取自己任务的摘要. U 和 C 普通管理员读取完整决定返回 404, 授权 C 审计账号返回 200. 审计读取与任务摘要的块哈希和原探针期限一致. | [浏览器核验](browser-proof.json), [原决定和权限结果](c-audited-decisions.json), [C 审计页](rp-c-auditor-decision.png) |
| 部署检查 | 三域就绪, 镜像标识相同, 各域 DB 卷和账号数据隔离. 后端挂载各自的 Fabric 和应用签名材料. 镜像与静态资源检查通过. | [三域烟雾](deployment-smoke.json), [凭据隔离](credential-isolation.json), [独立干净部署与重启](clean-rerun.json) |

RP 运行 ID 为 `d139978f67c3fea87d9050a92461f6537de4636ad9fcce3540ac5790b752a0bf`. BM 运行 ID 为 `b36ea9a7670b468e44540caea74d38a6b377b7bfe097376904a3a0e531d74081`.

五个视图已从实际交易和模型运行读取数据. 可查 [身份与信任](rp-identity.png), [凭证披露](rp-disclosure.png), [委托树](rp-delegations.png), [采购任务](rp-purchase.png), [RP 预检拒绝时间线](rp-pause-timeline.png) 和 [BM 定案时间线](bm-timeline.png).

首轮 RP 和 BM 的链上委托有效, B 域严格解码拒绝了派发报文中的 null 数组. 修正报文后重新从浏览器确认任务. 修正后的首笔 BM 运行也保留了 B1 模型工具参数的 `BINDING_MISMATCH` 和随后的确定性拒绝证据. 最终 BM 复跑由模型真实询价后停止. [首轮 RP](initial-dispatch-failure-rp.json), [首轮 BM](initial-dispatch-failure-bm.json), [BM 工具绑定拒绝](bm-initial-model-stop.json), [该次确定性拒绝](bm-initial-negative-probe.json).
