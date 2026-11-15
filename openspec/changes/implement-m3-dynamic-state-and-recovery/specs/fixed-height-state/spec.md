# fixed-height-state Specification

## MODIFIED Requirements

### Requirement: 历史复查与在线检查分离

历史复查 SHALL 按显式区块号在保留范围内重建该块结束后的登记事实并输出对应区块哈希, 并支持针对已记录决策 `d1` 的完整历史审计重构. 历史输出 SHALL 独立于在线就绪和探针期限, 不生成在线可用或采购许可结论, 也不为原探针续期. 历史决策复核 SHALL 根据 `d1` 记录的 `block_number` (`h`), `certification_id`/`certification_digest`, 原探针期限与可信 Peer 上目标撤销交易 `VALID` 区块高度 `r`, 按 `h` 块末尾状态用固定 T 根核对当时域认证, 身份, 凭证, 委托路径和策略摘要, 并对比 `h` 与 `r` 及 `decision_at` 相对原探针期限判定 `MATCHED`, `MISMATCH`, `INCOMPLETE` 或 `NO_DECISION`; 历史不可读时 SHALL 显式记录缺口. 在线检查 SHALL 使用当前一致视图及已应用且在原期限内的探针.

#### Scenario: 撤销后重新查询撤销前高度

- **WHEN** G1 已在 r 块有效撤销, 且撤销前的高度 h 和撤销块 r 均在保留范围内
- **THEN** 历史复查分别返回 h 的 ACTIVE 与 r 的 REVOKED, 记录各自块号/哈希及查询对象
- **AND** 即使 h 对应探针已过期, 仍能复查历史事实, 查询不改变在线检查点

#### Scenario: 未知订单核账按创建决策高度 h 与撤销高度 r 复核历史完整性

- **WHEN** 审计核账针对已创建订单的首次允许决策 `d1` 发起历史完整性复核, 分别覆盖 `h < r` 且 `decision_at` 在原探针期限内, 以及历史记录缺失或 `h >= r` / 越过原探针期限的异常对照样本
- **THEN** 历史复查使用 `d1` 保存的历史 `certification_id`/`digest` 与固定 T 根验证当时资格 (不使用当前新域认证替代), 并在可信 Peer 的 `r` 块核对撤销交易 `VALID` 与 `REVOKED` 状态
- **AND** 合规历史样本标记为 `MATCHED`, 缺创建决策或历史状态缺失分别标记为 `INCOMPLETE`, 在 `h >= r` 凭失效祖先放行或超原探针期限放行标记为 `MISMATCH`, 整个过程不修改原订单或原挑战记录
