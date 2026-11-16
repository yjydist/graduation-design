# 实施任务

本清单交付 M3 动态状态与恢复实现及绑定当前 Fabric 部署的验证证据. 机制见 [设计](design.md), 行为验收依据为 [授权登记](specs/authorization-registry/spec.md), [可验证协议](specs/verifiable-protocol/spec.md), [固定高度状态](specs/fixed-height-state/spec.md), [直接访问网关](specs/direct-access-gateway/spec.md) 和 [智能体工具运行时](specs/agent-tool-runtime/spec.md).

## 1. 链码与登记扩展: 域资格动态管理, 身份生命周期与管理账户恢复

- [x] 1.1 扩展 `chaincode/registry/identity.go` 与 `internal/fabricapi/types.go`, 实现 T 域认证原子替换 (`CertifyDomain` 支持 `ACTIVE`/`SUSPENDED` 域按 `expectedRevision` 与 `expectedCertificationId` 续发与收缩声明范围), `RevokeCertification`, `SetDomainStatus` 与 `UpdateAuthorityIdentity` (仅 T 可更新/恢复引导身份), 运行链码单测验证同钥续发, `IB` 换钥重认证及越权拒绝 (`F15`, `S78`, `S81`, `S82`, `S85`, `S89`).
- [x] 1.2 在 `chaincode/registry/identity.go` 与 `internal/fabric` 实现 `SetIdentityStatus` (`ACTIVE <-> SUSPENDED -> REVOKED`, 本人/注册机构权限隔离与 `IDENTITY_STATE_CONFLICT`), `RotateIdentity` (`KeyVersion++`) 与 `RecoverIdentity` (校验 `grad-identity-recovery-v1` 挑战及新应用密钥/新管理证书双证明, 原子替换 `binding` 并保留原 `Status`, 拒绝 `REVOKED` 或无效域恢复), 运行单测验证 `S94-S97`.
- [x] 1.3 在 `chaincode/registry/identity.go` 与 `chaincode/registry/grant.go` 实现 `RevokeCredential`, `CancelTask` (`ACTIVE -> CANCELLED`) 与 `SuspendGrant`/`ResumeGrant` (`ACTIVE <-> SUSPENDED`, 不改 `exp`), 运行链码与 `StateProvider` 单测验证 `E3` 状态切换与无效状态拒绝.
- [x] 1.4 扩展 `internal/fabric/operation.go` 与 `internal/protocol` 编码测试, 完成受理前 `expectedRevision` 冲突返回 `409 STATE_CHANGED` 且不入队, 受理后 `202` 与 `GET /v1/operations/{id}` 返回 `200` (`PENDING`/`CONFIRMED`/`FAILED` 与 `ENDORSEMENT_REJECTED`/`STATE_CHANGED`/`COMMIT_INVALID`), `DUPLICATE_TXID` 保原结果 (`S100`/`S101`), 以及 `nonce` (`S102`/`S103`) 与 DID/JWK/本地上下文 (`S98`/`S99`) 边界测试通过.

## 2. 静态验签缓存 (B1), 披露范围收缩与 T 离线本地核验

- [x] 2.1 在 `internal/protocol/evidence.go` 与 `internal/gateway` 实现按 `(SHA256(rawMaterialBytes), alg, appKeyId, appKeyVersion)` 索引的并发安全 `SignatureCache` (`B1` 模式), 命中缓存后仍强制对照固定高度快照核验 `Identity.Status`, `Identity.KeyVersion`, `Domain.Certification` 与区间约束, 运行测试验证 `B1` 命中统计以及轮换密钥后命中缓存仍返回 `403 KEY_VERSION_STALE` (`S22`, `S81`).
- [x] 2.2 扩展 `internal/protocol/credentials.go`, `evidence.go` 与 `internal/policy` 策略输入装配, 支持包含可选合成声明 `department` 的 SD-JWT 凭证及 `T` 同钥收缩声明范围边界校验, 运行测试验证隐藏 `department` 通过且策略输入不含未披露属性, 披露 `department` 返回 `403 ISSUER_SCOPE_INVALID`, 省略必需 `role` 被拒绝 (`S93`).
- [x] 2.3 扩展 `internal/fabric/delivery.go` 与 `internal/gateway/execute.go` 验证完成域认证交付后停止 T 服务与 DID 主机时的本地核验 (`F14`, `S84`), 运行集成测试验证在线请求调用 T 次数为 `0` 且正常通过, 本地缺当前认证正文时返回 `503 MATERIAL_NOT_SYNCED` 而非回退旧认证.

## 3. 两实例未知订单核账与历史高度复核

- [x] 3.1 扩展 `internal/gateway/schema.go` 与 `internal/gateway/server.go`, 为 `client_actions` 增加 `send_revision`, `challenge_ids`, `case_id`, `outcome` 与 `OUTCOME_UNKNOWN`/`RECONCILED` 状态, 并新建 `order_outcome_cases` 与 `order_outcome_receipts` 表, 运行迁移与意图锁单测验证停发后递增 `send_revision` 拒绝迟到重发.
- [x] 3.2 在 `internal/gateway` 实现 `POST /v1/internal/order-outcome-cases`, `POST /v1/audit/order-outcomes` 与 `POST /v1/internal/order-outcome-receipts`, 强制 `C` 审计员权限检查 (`403 AUDIT_FORBIDDEN` 隔离 `B1`/`A` 管理员, `S67`), 并按 ID 升序锁定挑战并集, `business_keys` 与 `orders`, 运行双网关实例测试验证 `CREATED`, `NOT_CREATED` 与 `UNKNOWN` 分支及幂等回执交付.
- [x] 3.3 在 `internal/fabric/view.go` 与 `internal/gateway` 实现基于 `StateProvider` 历史视图 (`mode=historical`) 对创建决策 `d1` 块高 `h`, 撤销交易 `VALID` 块高 `r`, 历史 `certificationId`/`digest` 与原探针期限的审计复核 (`MATCHED`/`MISMATCH`/`INCOMPLETE`/`NO_DECISION`), 并运行 `S66` 并发屏障测试验证等锁过期挑战不消费且另一有效挑战生成唯一订单.

## 4. B2 改派与未知订单核账的智能体 MCP 工具轨迹

- [x] 4.1 扩展 `internal/agent/wallet.go` 与 `internal/agent/mcp_server.go`, 注册强类型 MCP 工具 `replace_grant` 与 `reconcile_order`, 强制私钥与盐值脱敏隔离及意图停发锁, 运行单测验证进程内与 `ledgerctl mcp` stdio 传输一致返回结构化结果.
- [x] 4.2 扩展 `internal/agent/runner.go` 与 `internal/agent/agent_test.go`, 使用 OpenAI 与 Anthropic 官方 Go SDK 跑通 `A1` 原子替换 `G2` 改派 `B2` (`B2` 误用 `B1` 的 `Q800` 触发 `403 QUOTE_SCOPE_MISMATCH` 后重新询价建单, `S41`/`S55`) 与 `B1` 响应丢失及 `G1` 撤销后的核账恢复轨迹 (`S63`), 记录完整推理耗时与脱敏工具轨迹.

## 5. E2/E3/E6/E7 联合验收与文档证据同步

- [x] 5.1 新建 `internal/fabric/verify_m3.go` 并扩展 `internal/fabric/verify.go` 与 `cmd/ledgerctl`, 覆盖 `F14-F15`, `S76-S103` 配对用例, `E3` 动态轨迹 (`B2` 改派与核账恢复), `E6` 20 ms 撤销窗口探测预跑 (核对 `t_submit`/`t_valid`/`t_apply`/`t_adopt`/`t_last_allow`/`t_first_deny` 且采用 `r` 后零允许) 与 `E7` 故障注入预跑 (停排序节点, Peer 断流补块, 等锁超时 `S66`, 锁后风险升级 `S91` 与核账恢复).
- [x] 5.2 在真实 Fabric 实例 `.local/fabric-d0` 上完成链码序列升级或干净重建, 运行 `go test -count=1 ./...` (`mise run test:unit`) 与 `mise run ledger:verify` (接入可配置 LLM API 运行 `A1`/`B1`/`B2` 轨迹), 核对全部 D0-M3 验收项通过并输出排除私钥与 `LLM_API_KEY` 的结构化证据.
- [x] 5.3 更新 [阶段任务](../../../../TODO.md) 与 [证据索引](../../../../infra/fabric/evidence/README.md) 中 M3 阶段完成状态, `S76-S103` / `E6` / `E7` 预跑结论与运行证据索引.

## 6. 正式核验缺陷修复

- [x] 6.1 修复 C1: 从可信 mTLS 或服务器认证上下文绑定审计, 恢复和回执角色, 隔离 B/C 服务凭据并回归无证书, 伪造角色和伪造回执拒绝.
- [x] 6.2 修复 C2: 接通管理 REST 与真实 Fabric 原交易持久化提交, 实现重启恢复和原提交结果查询, 通过 HTTP 到 Fabric 的 VALID/MVCC 及同键重试回归.
- [x] 6.3 修复 W1: 按 h 验证全部路径凭证状态, 期限和版本, 核对历史认证正文与固定 T 根签名, 根据实际路径重放策略, 覆盖撤销与缺材料对照.
- [x] 6.4 修复 W2: 对已停发意图原子禁止新增发送, 同步数据库与内存路径, 覆盖当前代次新工作进程及停发并发屏障.
- [x] 6.5 修复 W3: 在审计事务内持久化待送回执, 支持认证投递, 重启恢复和同代次同序号幂等.
- [x] 6.6 运行相关回归, 全量 Go 测试和真实 Fabric 联合验收, 保存修复证据并更新核验报告, TODO 与证据索引.

## 7. 入口边界复核修复

- [x] 7.1 修复 C3: 管理恢复入口强制验证服务端一次性挑战及新应用密钥/新管理证书双证明, 原子消费挑战并持久化原始待提交请求, 覆盖缺证明, 篡改, 重放与重启恢复.
- [x] 7.2 修复 W4: 操作查询限定为原发起身份或宿主明确授权的本域审计者, 覆盖无身份, 跨身份和跨域拒绝及本人/审计者成功, 更新核验结论和证据.

## 工作流后续

- 实施完成后运行 `/openspec-verify-change` 对照全部需求与场景核验代码, 测试与实机证据, 同步主规范后归档 `implement-m3-dynamic-state-and-recovery`.
