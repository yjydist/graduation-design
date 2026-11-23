# Spec Delta: authorization-registry

## MODIFIED Requirements

### Requirement: 管理交易确认与失败证据

系统 SHALL 在首次提交前持久化原操作键, 输入摘要, txID 及已签交易并绑定调用者, 通道和链码. 链码拒绝提案时 SHALL 直接返回无 `"D0:"` 前缀的规范错误码, 管理服务与网关 SHALL 共用统一 REST 错误信封. 受理前 `expectedRevision` 过时返回 `409 STATE_CHANGED`; 已受理返回 `202` 与原 `operationId`, 同键同摘要重试仍返回 `202` 原 `operationId`, 同键异摘要返回 `409 IDEMPOTENCY_CONFLICT`. 查询 `GET /v1/operations/{id}` SHALL 返回 `HTTP 200` 与 `PENDING`/`CONFIRMED`/`FAILED` 及原提案或提交校验码; 仅 `VALID` 提交可确认并开放后续交付. 公开夹具与部署清单 SHALL 排除 `synthetic` 和 `m2TaskSpec` 等历史遗留键.

#### Scenario: 有效提交确认

- **WHEN** 合法操作取得背书和提交接收响应, 随后由可信 Peer 观测到 VALID
- **THEN** 核对 txID, 调用者, 通道, 链码和区块位置后才将操作从 PENDING 改为 CONFIRMED, 开放后续依赖步骤

#### Scenario: 区分提案拒绝与入块无效

- **WHEN** 分别遇到链码提案拒绝, MVCC_READ_CONFLICT 或无可细分原因的非 VALID 提交结果
- **THEN** 链码直接输出无 `"D0:"` 前缀的规范错误码, 管理服务记录对应阶段及原始证据, MVCC 冲突报告 `STATE_CHANGED`, 无法细分的入块无效使用通用失败码 `COMMIT_INVALID`, HTTP 错误响应遵循统一结构化错误信封
- **AND** 所有失败均不触发材料交付

#### Scenario: 提交结果暂不可见或出现重复提交

- **WHEN** 原提交响应或提交状态暂不可见, 操作进程恢复或客户端以同操作键重试
- **THEN** 保持 PENDING, 查同一 txID 或重投原已签字节, 不生成替代交易
- **AND** 同键异输入冲突, 重投引发的重复交易不能覆盖原交易的有效提交结论

#### Scenario: 受理前版本冲突预检与受理后异步操作状态查询

- **WHEN** 普通身份换钥或状态操作先提交过时 `expectedRevision`, 再使两笔不同操作键通过同一有效版本预检并取得背书后在 `202` 后广播, 以及在 `202` 后隐藏提交结果并在恢复可信 Peer 查询前后查询状态与重试
- **THEN** 受理前过时版本返回 `409 STATE_CHANGED` (统一错误信封) 且无待提交操作; 两笔背书竞争经 `GET /v1/operations/{id}` 均返回 `HTTP 200`, 胜出者为 `CONFIRMED`/`failureCode=null`, 冲突者为 `FAILED`/`STATE_CHANGED` (`MVCC_READ_CONFLICT`) 且无材料交付
- **AND** 暂不可见结果时查询返回 `200 PENDING/null`, 恢复查询后准确反映原提案拒绝或入块校验阶段及 `ENDORSEMENT_REJECTED`/`COMMIT_INVALID`, `DUPLICATE_TXID` 不覆盖原结果, 同键同正文重试返回 `202` 原 `operationId`, 同键异正文返回 `409 IDEMPOTENCY_CONFLICT`
