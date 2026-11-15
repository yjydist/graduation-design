# 核验报告: implement-m3-dynamic-state-and-recovery

原 2 项 CRITICAL 和 3 项 WARNING 均已修复并通过回归. 当前 0 项 CRITICAL, 0 项 WARNING, 0 项 SUGGESTION. 全量 Go 测试, 定点竞态检测与独立 Fabric 联合验收通过.

## 范围与汇总

使用本地 `spec-driven` 工作流, 已核对 proposal, design, tasks 和 5 份增量规范. 共 8 项需求, 包括 4 项 ADDED 和 4 项 MODIFIED, 22 个场景, 无 REMOVED 或 RENAMED. 本报告覆盖原实现与正式核验后的修复.

| 维度 | 结果 |
| --- | --- |
| 完整性 | 21/21 任务完成, 8/8 需求有实现和验证证据. |
| 正确性 | 已核对 8/8 需求映射和 22/22 场景, 130 个含子测试的通过事件, 完整实机联合验收 34/34, 另有管理 HTTP 和 E6 时间线补充实机证据. |
| 一致性 | 4 组设计决策已核对, 认证通道, 原交易恢复, 历史重放, 停发锁与回执 outbox 均与设计一致. 新代码延续既有 Go 包和事务模式. |

任务完成, 规范覆盖, 需求实现映射, 场景覆盖, 设计遵循和代码模式一致性六项检查均已执行, 无未核验或不适用项. 全量测试命令中的 3 项显式启用测试会跳过, M3 的实机验证由完整 CLI 验收和显式定点命令完成, 两项初始化专项沿用既有证据. 跳过测试项与跳过核验检查分别记录.

## 已修复问题

| 原编号 | 修复 | 回归与实机证据 |
| --- | --- | --- |
| C1. 审计与恢复通道缺少可信角色身份绑定 | `internal/serviceauth/identity.go:30` 只读取已验证客户端证书或宿主安装的认证上下文. `internal/gateway/audit.go:124` 不再信任 X-Caller-* 头, 核对资源域审计员和恢复主体域. 钱包使用宿主配置的独立恢复, 审计与回执客户端, 外部连接由独立 mTLS 凭据配置. | `TestVerifiedMTLSCallerIgnoresSpoofedHeaders` 使用真实 mTLS, 验证 B 证书不能通过头声明 C 角色. 网关 `RejectHeaderOnlyAuditorAndForgedReceipt` 覆盖无证书与 B 身份伪造 C 角色, 两个接口均拒绝. |
| C2. 管理 REST 受理后未提交 | `internal/fabric/management.go:35` 装配真实后端, `operation.go` 的 HTTP 受理触发提交并持久化原输入. 后端复用原交易 journal 保存提案与签名字节, `ResumePending`/`RunRecovery` 按原 txID 恢复, 限制单次恢复并发及期限, 暂不可见请求不会阻塞其它待定请求. 交付标志也持久化. | `TestManagementHTTPDispatchAndDurableRestart` 和 `TestManagementRecoveryDoesNotBlockOtherOriginalRequests` 通过. `verify_management.go:24` 通过真实 mTLS HTTP 获得 409 预检, 202 受理, PENDING 查询, 同块 VALID/MVCC_READ_CONFLICT 配对, 同键重试和保留原 txID 的重启恢复. 实机验收已移除手工注入确认结果. |
| W1. 历史凭证和密码学检查不完整 | `internal/gateway/execute.go:859` 与原 ALLOW 决策原子保存原出示, DID 文档及原探针单调核验时点. `audit.go:999` 从 decision_evidence 重放, 用 h 快照校验凭证状态/期限/版本, 固定 T 根与历史域认证签名, 委托与 KB-JWT, 并从实际角色, 披露属性和路径上界构造策略输入. 缺材料返回 INCOMPLETE, 矛盾返回 MISMATCH. | `HistoricalRevokedCredentialAndMissingEvidence` 验证 h 中凭证已撤销时为 MISMATCH, 缺历史认证正文时为 INCOMPLETE. 既有 h>=r, 原探针超期, 缺块/缺创建决策对照继续通过. 实机核账轨迹返回原订单及 MATCHED. |
| W2. 停发意图仍允许新工作进程 | `internal/gateway/server.go:400` 以意图行锁串行化最后一次网络发送与停发. 已绑定 caseId 的意图拒绝旧代次和当前代次工作进程. `internal/agent/mcp_server.go:780` 在工具入口拒绝已停发意图, 内存路径也执行相同检查和幂等停发. | `StoppedIntentRejectsCurrentRevision`, `TestStoppedIntentSerializesFinalDispatch` 及 `TestMemoryIntentStopRejectsCurrentRevisionAndIsIdempotent` 通过. 屏障验证发送持锁期间停发不能完成, 完成停发后不再派发. |
| W3. 待送回执未原子保存 | `internal/gateway/audit.go:771` 在审计事务内写入不可变 order_outcome_outbox. `receipt_delivery.go:23` 经宿主认证客户端投递原回执, `DeliverPendingReceipts` 从持久化队列恢复, 保留原 checkNo. 接收端对绑定, 创建决策, 历史状态与原审计时点一并去重. | `DurableOutboxSurvivesRestartAndLostAcknowledgement` 在 B 已提交收件后注入响应丢失, 确认 outbox 仍待送, 新服务实例恢复原回执且重复投递幂等, 迟到 UNKNOWN 不重开终态意图. |

首次核验的[5 项失败日志](../../../infra/fabric/evidence/m3-recovery/verification/boundary-tests.log)和[临时补丁](../../../infra/fabric/evidence/m3-recovery/verification/boundary-tests.patch)继续保留. 这些边界已纳入正式 Go 回归, 当前结果见[修复回归](../../../infra/fabric/evidence/m3-recovery/fixes/boundary-tests.log).

## 验证结果

- [全量测试汇总](../../../infra/fabric/evidence/m3-recovery/fixes/unit-test-summary.json)和[原始事件](../../../infra/fabric/evidence/m3-recovery/fixes/unit-test-events.jsonl): `mise exec -- go test -json -count=1 ./...` 退出码 0, 8 个测试包通过, 130 个含子测试通过事件. `cmd/ledgerctl` 无测试文件. `TestInterruptedInitialization`, `TestDeploymentResumesAfterCommittedInitialization`, `TestM3LiveAcceptance` 在此命令中跳过.
- [认证与发送锁竞态检测](../../../infra/fabric/evidence/m3-recovery/fixes/race-tests.log)和[管理队列竞态检测](../../../infra/fabric/evidence/m3-recovery/fixes/management-race.log): `CGO_ENABLED=1` 下对新增认证, 发送锁和管理恢复场景执行 `go test -race`, 均通过.
- [OpenSpec 严格校验](../../../infra/fabric/evidence/m3-recovery/fixes/openspec-validation.json)通过. `git diff --check` 通过.
- [独立空卷联合验收](../../../infra/fabric/evidence/m3-recovery/fixes/run-a297ef63438bdd10/summary.json): `.local/fabric-m3-fix-final`, `run-a297ef63438bdd10`, 34/34. deploymentId 为 `04ba01e1fd488fbfa11cbb0901bf4b3c5b8466d1a4e18591a81d92f7e6ee2406`.
- [真实 LLM 工具轨迹](../../../infra/fabric/evidence/m3-recovery/fixes/run-a297ef63438bdd10/m3-agent-traces.json)使用 Anthropic 协议与 `deepseek-flash`, 两条轨迹分别执行 9 次和 6 次工具调用, 推理耗时 19066 ms 和 11531 ms. 改派轨迹包含错误主体报价拒绝及重新询价成单, 恢复轨迹包含响应丢失, 祖先撤销拒绝和原订单 CREATED/MATCHED 核账. OpenAI 与 Anthropic 双 SDK 的模拟协议测试也通过.
- [管理 HTTP 补充结果](../../../infra/fabric/evidence/m3-recovery/fixes/supplemental/run-48e2661bcc4b7434/management-http.json)和[定点命令日志](../../../infra/fabric/evidence/m3-recovery/fixes/supplemental/command.log)确认最新恢复实现经实际 mTLS HTTP 与可信 Peer 原提交结果验证, 原 txID 未替换.
- [E6 最终补充时间线](../../../infra/fabric/evidence/m3-recovery/fixes/supplemental/run-c0de4231e976a55c/m3-e6-revocation-window.json)保存 20 ms 间隔的 18 个样本, 4 次允许和 14 次拒绝, 采用 r 后零允许, 本次 windowAfterValidMs=0. t_submit, t_valid, t_apply 和 t_adopt 均有有效时点. E6 完整重复测量仍属于 M4.
- [E7 实机结果](../../../infra/fabric/evidence/m3-recovery/fixes/run-a297ef63438bdd10/m3-e7-fault-injection.json)保存停机与补块关联, 过期挑战 401 且未消费, 另一有效挑战 200, 唯一订单和锁后风险 403.
- [完整联合验收原块复核](../../../infra/fabric/evidence/m3-recovery/fixes/run-a297ef63438bdd10/raw-block-audit.json)核对 230 个连续区块和 254 笔交易. [E6 补测原块](../../../infra/fabric/evidence/m3-recovery/fixes/supplemental/run-c0de4231e976a55c/raw-block-audit.json)与[管理补测原块](../../../infra/fabric/evidence/m3-recovery/fixes/supplemental/run-48e2661bcc4b7434/raw-block-audit.json)分别核对 249/256 个区块及 277/286 笔交易, 校验父哈希, 数据摘要, ASN.1 块头摘要与 txID/原校验码.
- [公开材料与结果扫描](../../../infra/fabric/evidence/m3-recovery/fixes/material-and-results-audit.json)检查 849 个文件, 无私钥, 已配置 API Key 或智能体轨迹中的原始凭证/披露泄漏. decision_evidence 仅保留在业务主库, 不随公开材料导出.

## 复验中的补充修正与失败样本

- [首轮 31/34](../../../infra/fabric/evidence/failures/m3-fixes/run-706cbbe117a56403/summary.json)保留 D0 探针提交及检查点恢复等待超时. 当轮 M3 四项全部通过.
- [第二轮 33/34](../../../infra/fabric/evidence/failures/m3-fixes/run-fc33538d07c30c64/summary.json)定位 M2 用例在本地应用新登记块之前装配新授权. `internal/fabric/verify_m2.go` 已补齐等待 op2 的实际提交高度, 第三独立空卷全量验收通过.
- 完整 34/34 运行的 E6 原采样存在 t_apply 漏记, 原 JSON 保留. 已改为直接记录区块应用事件, 缺时点或缺正反样本时拒绝通过, 并修正拒绝码的解码. 最终 E6 时间线使用上述补充运行, 原始材料未改写.
- 管理定点测试最初的 DER/PEM 证书夹具和零 revision 夹具失败保留在 `infra/fabric/evidence/failures/m3-fixes/management-fixture/`, 后续真实 HTTP 与恢复回归通过.

## 需求与场景覆盖

| 能力 | 需求数 / 场景数 | 主要实现与验证 |
| --- | --- | --- |
| authorization-registry | 3 / 9 | 链码域与身份生命周期, 双证明恢复, 凭证/任务/委托动态状态; registry_test.go 的三组 M3 测试, operation_m3_test.go, management_test.go 和 verify_management.go 的真实 HTTP 原交易证据. |
| agent-tool-runtime | 2 / 5 | 六个强类型 MCP 工具, 私钥/盐值隔离, 意图持久化和停发, 进程内/stdio 一致性; agent_m3_test.go, wallet_regression_test.go, 双 SDK 模拟端点及两条真实 LLM 轨迹. |
| direct-access-gateway | 1 / 4 | 两实例核账, 可信角色隔离, 等锁到期与唯一订单, CREATED/NOT_CREATED/UNKNOWN, 原回执恢复; order_m3_test.go 与完整实机 E3/E7. |
| fixed-height-state | 1 / 2 | 独立历史模式, 原 h/r 状态, 历史密码学与策略重放, MATCHED/MISMATCH/INCOMPLETE/NO_DECISION; operation_m3_test.go, order_m3_test.go 和实机核账结果. |
| verifiable-protocol | 1 / 2 | 并发安全静态缓存, 命中后的动态状态/版本检查, department 隐藏/披露及必需 role; evidence_m3_test.go, gateway_m3_test.go 与 T 离线/缓存实机结果. |

八项需求与二十二个场景均有对应代码, 测试或保留实机证据. 当前修复覆盖原核验发现的边界, 未将既有 34/34 汇总单独作为正确性依据.

## CRITICAL

无未解决项.

## WARNING

无未解决项.

## SUGGESTION

无.

## 归档评估

全部核验检查通过. 0 项 CRITICAL, 0 项 WARNING, 0 项 SUGGESTION. 可进入主规范同步与归档工作流. M4 的完整重复实验与性能数据产出仍按原阶段边界执行.
