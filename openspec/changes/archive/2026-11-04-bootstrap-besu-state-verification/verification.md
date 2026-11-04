# 变更检验报告: bootstrap-besu-state-verification

## 结论

全部适用检查通过, 可以进入归档流程. 未发现 CRITICAL, WARNING 或 SUGGESTION 问题, 没有未验证项. 本次仅执行验证并保存报告, 未修改实现或归档变更.

| 维度 | 检验结果 |
| --- | --- |
| 完整性 | 任务 26/26 完成, 14/14 项新增需求存在对应实现. 无修改, 删除或重命名需求 |
| 正确性 | 14/14 项需求完成实现映射, 25/25 个场景有实现和测试或实际运行证据 |
| 一致性 | 6 项设计决策均有对应实现和证据, 工程目录及实现模式符合本项目约定 |

## 检验依据与执行结果

已读取 [提案](proposal.md), [设计](design.md), [任务](tasks.md)及三份增量规格. `openspec status` 返回 `spec-driven`, 全部规划制品存在; `openspec instructions apply` 返回任务总数 26, 完成 26, 剩余 0, 没有不可读的任务文件.

| 检查 | 结果与证据 |
| --- | --- |
| OpenSpec 结构 | `openspec validate bootstrap-besu-state-verification --strict --json` 通过, 无结构问题 |
| 本地构建 | `CGO_ENABLED=0 go build -o .local/openspec-verify-ledgerctl ./cmd/ledgerctl` 通过 |
| 单元测试 | `CGO_ENABLED=0 go test ./... -count=1 -json` 通过. 未配置链上环境变量的单独运行跳过 14 个集成测试, 随后的完整验收已实际执行这些测试 |
| 当前实现完整验收 | `.local/openspec-verify-ledgerctl verify --dir .local/besu-qbft --out .local/openspec-verification` 退出码为 0, 7/7 项通过, 26 个顶层 Go 测试通过, 无测试跳过或失败 |
| 原实例与干净重建 | 两轮既有完整运行均为 7/7 项通过, 各有 26 个顶层 Go 测试通过. 已核对原始状态, 停机窗口及部署差异, 见[证据索引](../../../../infra/besu/evidence/README.md)和[重建对照](../../../../infra/besu/evidence/rebuild-comparison.json) |
| 材料一致性 | 两轮证据记录的 AuthRegistry.sol, compiler-input.json, compiler-lock.json, compose.yaml, node.toml, go.mod 和 go.sum 的 SHA-256 均与当前文件一致 |
| 证据与格式 | 证据目录及本轮输出未发现 PEM 私钥标记或私钥字段. 已检查输出路径和序列化内容只保存公开材料, 原签名交易及运行证据. `git diff --check` 通过 |

首次未设置 `CGO_ENABLED=0` 的测试因本机缺少 macOS SDK 头文件而构建失败, 与[运行说明](../../../../infra/besu/README.md#初始化)记录的环境限制一致. 按文中纯 Go 配置重跑成功, 不计为实现缺陷.

本轮复跑的[完整汇总](../../../../.local/openspec-verification/run-6005d2925a9cf3e9/summary.json), [测试日志](../../../../.local/openspec-verification/run-6005d2925a9cf3e9/go-tests.jsonl)及[原始 RPC](../../../../.local/openspec-verification/run-6005d2925a9cf3e9/rpc.jsonl)保存在 Git 忽略的本地运行目录. 可随仓库保留的原实例和重建证据入口仍由上述证据索引维护.

本轮 G1 的 h/r 为 `0x274d`/`0x274e`, 在读取期间确认撤销后, 当前快照及全部依赖仍固定 h, 历史重查分别得到 ACTIVE/REVOKED. 停止 A 完成后确认 3 个新块; 再停止 B 后, 稳定窗口为 15.007 秒且头不增长. 连续 3 次检查和新读取器均拒绝超龄头, 恢复后取得新鲜快照, 最终 C 的对等连接数恢复为 3.

## 完整性与需求实现映射

以下 14 项均为 ADDED 需求. 代码引用中的行号对应本次检验时的源码.

| 能力与需求 | 实现依据 | 测试或运行依据 |
| --- | --- | --- |
| 许可账本: 四节点许可网络 | `infra/besu/compose.yaml:1`, `infra/besu/node.toml:1`, `internal/ledger/instance.go:100`, `internal/ledger/instance.go:186` | network-baseline, unpermitted-node, TestAccountPermissioningIntegration, TestPermissionsSeparateValidatorsAndAccounts |
| 许可账本: 持续空块与节点故障 | `internal/ledger/verify_scenarios.go:19`, `internal/ledger/verify_scenarios.go:205` | 连续 11 个空块和 10 个间隔, 停一节点后 3 个新块, 停两节点稳定窗口及恢复 |
| 许可账本: 部署绑定和持久化 | `internal/ledger/instance.go:71`, `internal/ledger/deployment.go:78`, `internal/ledger/deployment.go:226`, Compose 的数据挂载 | TestInstanceReopenAndRebuild, TestDeploymentBindingIntegration, network/restart.json, rebuild-comparison.json |
| 许可账本: 运行材料可复现 | `internal/ledger/compiler.go:37`, `internal/ledger/verify.go:273`, 编译器锁和运行说明 | 原实例与干净重建完整运行, 材料哈希核对, genesis/许可/部署材料与镜像记录 |
| 授权登记: 固定根与最小登记路径 | `contracts/AuthRegistry.sol:166`, `contracts/AuthRegistry.sol:226`, `contracts/AuthRegistry.sol:250`, `contracts/AuthRegistry.sol:297`, `contracts/AuthRegistry.sol:304`, `contracts/AuthRegistry.sol:326`, `contracts/AuthRegistry.sol:338` | TestRootMutationIntegration, TestDomainRegistrationIntegration, TestIdentityRegistrationIntegration, TestRPRegistrationIntegration |
| 授权登记: 标识和路径约束 | `contracts/AuthRegistry.sol:338`, `contracts/AuthRegistry.sol:402`, `contracts/AuthRegistry.sol:415` | TestGrantStructureIntegration, TestRevocationIntegration, 16 组单字段结构负例及合法配对 |
| 授权登记: 撤销权限与版本竞争 | `contracts/AuthRegistry.sol:381`, `internal/ledger/transaction.go:205` | TestRevocationIntegration, TestRevisionCompetitionIntegration, 终态与字段保留检查 |
| 授权登记: 交易结果和原交易失败证据 | `internal/ledger/transaction.go:89`, `internal/ledger/transaction.go:105`, `internal/ledger/transaction.go:244`, `internal/ledger/transaction.go:294`, `internal/ledger/trace.go:53`, `internal/ledger/trace.go:131` | 交易恢复单元测试, TestOriginalTransactionTraceIntegration, TestTraceFailureRecoveryIntegration, TestBlockTraceFallbackFaultsIntegration |
| 固定高度状态: 所有依赖固定同一高度 | `internal/ledger/state.go:177`, `internal/ledger/state.go:253`, `internal/ledger/state.go:283` | historical-and-interleaved-revocation 的全部查询参数, 固定高度调用断言 |
| 固定高度状态: 历史复查与在线检查分离 | `internal/ledger/state.go:177`, `internal/ledger/state.go:222`, `internal/ledger/state_cli.go:33` | h/r 状态对照, 历史模式不含 fresh, 两种模式不含采购 allow |
| 固定高度状态: 查询失败不退回最新状态 | `internal/ledger/state.go:253`, `internal/ledger/state.go:283`, `internal/ledger/deployment.go:198` | TestStateAssemblyFailuresIntegration 的缺失高度/记录, 单项失败, 空输出和块哈希变化注入 |
| 固定高度状态: 新鲜度从区块时间计算 | `internal/ledger/state.go:106`, `internal/ledger/state.go:177` | 4 个双时钟测试, 真实停链重复读取/重启拒绝与恢复 |
| 固定高度状态: 链头异常停止在线检查 | `internal/ledger/state.go:141`, `internal/ledger/state.go:177`, `internal/ledger/state.go:222` | TestHighestHeadRecoveryIntegration 的冲突, 回退, 重启, 历史隔离, 部署变化和可信头恢复 |
| 固定高度状态: 验证结果可追溯 | `internal/ledger/verify.go:64`, `internal/ledger/verify.go:139`, `internal/ledger/verify.go:273`, `cmd/ledgerctl/main.go:10` | 本轮 7 项独立结果及原始 RPC/交易/块, 既有 verification-failures 的两份非零退出样本 |

## 正确性与场景覆盖

### 许可账本

对应[许可账本规格](specs/permissioned-ledger/spec.md)的全部 7 个场景.

| 场景 | 核对结果 |
| --- | --- |
| 干净环境启动 | 干净重建证据包含相同链身份, 恰好四个预期验证者, 三个对等连接及连续空块. 公开实例和配置记录角色, arm64 与资源约束 |
| 许可名单阻止未授权参与 | 未许可节点使用相同 genesis, 12 次观测无有效连接且不能同步; 未许可账户广播返回 -32007, 无交易/回执且余额不变 |
| 无交易时持续出块 | 连续空块的父哈希和交易数量均有检查, 时间间隔来自实际区块, RPC 另有本地观测时间 |
| 单节点停止和双节点停止 | 本轮与两轮既有最终证据均满足停一后至少 3 个新块, 停两后至少 15 秒稳定窗口, 新鲜块恢复后在线检查成功 |
| 重启与重建的部署标识 | network/restart.json 保留旧块哈希和密钥材料摘要不变的观测; 重建对照确认 instanceId/deploymentId 不同 |
| 部署材料不匹配 | TestDeploymentBindingIntegration 覆盖 chainId, genesisHash, 合约地址/代码, instanceId, schemaVersion, 六个根字段和资源绑定的单项篡改 |
| 按锁定材料重建验证 | 干净重建完整执行 7 项验收及 26 个顶层测试, 编译器/输入和源码一致, 部署独立, 历史状态可读 |

### 授权登记

对应[授权登记规格](specs/authorization-registry/spec.md)的全部 11 个场景.

| 场景 | 核对结果 |
| --- | --- |
| 按角色建立 RP 夹具 | seed 的 15 个正常管理步骤和域/身份/RP 集成测试覆盖 PENDING 到 ACTIVE, 当前指针, 版本和 G0/G1 字段; 输出有 synthetic 和未实现验证层说明 |
| 绕过域权限或父受托者 | 普通账户引导, 跨域登记/签发, 非资源方根和非父 grantee 子授权均有真实回退记录及状态不变检查 |
| 未配置的合法主体尝试创建任务 | 同域且身份/凭证有效的 B1 被拒绝, U 成功; 任务资格是构造不可变字段, 没有运行期增授权入口 |
| 路径结构不匹配 | 16 组单字段负例及同 ID 合法配对覆盖父/根/任务/模式/域/密钥/凭证/时间/深度/资源/部署/模式版本 |
| ID 已经使用 | ACTIVE 及 REVOKED ID 复用失败, 原状态和摘要保留 |
| 合法撤销和终态 | U/A1/C 对各自样本撤销成功, revision 由 1 到 2, 委托不可变字段保留; 重复终态转换, 恢复和复用均失败 |
| 两笔交易竞争同一版本 | 两份签名交易在首次广播前均已落盘, 两个合法账户竞争 expectedRevision=1, 一成一败, 最终 REVOKED/revision=2 |
| 已许可账户仍无合约权限 | T/unrelated 已许可且有余额, 真实交易入块但 status=0, 状态/摘要/revision 不变, 原执行取证得到 UNAUTHORIZED |
| 成功回执核对 | validateReceipt 核对 txHash, 原块哈希, transactionIndex 与部署地址; 后续登记只接受 CONFIRMED |
| 原交易回退原因和缺失分支 | 原 txHash 的 callTracer 与必要时的原块跟踪绑定原执行. 缺失/截断/解码及整块顺序/gas/状态失配保持通用失败, 恢复只补原因且不改原交易和失败终态 |
| 回执暂不可见 | TestPendingTransactionRecovery 覆盖广播响应丢失, 回执隐藏和未送达, 重启仅查询或重播相同签名字节, 不重新分配 nonce |

RP 切片的路径根签发者与资源方均为 C, 两个关系标签不作为独立角色隔离证明, 与合约说明和本变更范围一致.

### 固定高度状态

对应[固定高度状态规格](specs/fixed-height-state/spec.md)的全部 7 个场景.

| 场景 | 核对结果 |
| --- | --- |
| 查询之间确认撤销 | 本轮读取期间撤销在 r 确认, 当前依赖查询全部固定 h, 输出 ACTIVE; 下一次在线读取输出 REVOKED |
| 撤销后重新查询撤销前高度 | 撤销后重新查询 h/r, 同一 grant 分别为 ACTIVE/REVOKED, 保留块哈希和参数, 历史输出不含在线可用字段 |
| 单项固定高度调用失败 | 缺失高度/记录, 指定调用失败, 空记录和块哈希改变均返回 nil 快照及错误, RPC 没有 eth_call 降级到 latest |
| 停链后反复读取 | 真实停链后 3 次检查和新读取器均为 STATE_STALE, 同高度仍能历史复查, 旧块预算不因重读或重启更新 |
| 墙钟回拨与未来区块时间 | 单元测试覆盖 5 秒/1 秒边界, 墙钟回拨, 未来超界, 单调期限, 重读/重连, 校时与超龄重启 |
| 异常链头与恢复 | 同高异哈希和回退均拒绝, 检查点保留; 重启核验下限, 历史读取不改写检查点, 部署变化拒绝, 可信新鲜头恢复成功 |
| 汇总首轮验证 | 本轮 7 项均有独立 JSON, 汇总绑定 deploymentId, 交易及块证据可定位; 超时/RPC 失败的既有样本非零退出并保存失败记录 |

## 一致性

| 设计决策 | 核对结果 |
| --- | --- |
| 四节点 Compose 和本地验证命令 | A/B/C/ops, C 读取, 受限 RPC, 持续空块, arm64 固定镜像及 Berlin 编译/运行配置一致 |
| 最小合约切片和正常引导夹具 | 仅实现正常登记, RP 委托及撤销路径, 固定 T 根和 A/U 资格, 没有任意状态写入后门; 应用验签及完整包含验证边界明确 |
| 交易跟踪使用原交易执行证据 | 广播前持久化, 独占锁和串行 nonce, 原签名字节恢复, 失败回执终态, 严格单交易/整块 trace 与通用失败分支均落实 |
| 历史读取和在线检查分开 | 显式模式, 单一高度, 完整装配失败即停止, 部署绑定及最高头持久化均落实 |
| 双时钟预算和故障观察 | 默认 5 秒/1 秒, 同块预算不续期, 回拨拒绝, 真节点停机与注入测试相互补充, 等待和恢复有界 |
| 工程布局和证据目录 | cmd/internal/contracts/infra 各自职责与设计一致. 密钥/数据/构建产物被忽略, 没有新增 Makefile 或文档构建/检查流程 |

[README](../../../../README.md), [TODO](../../../../TODO.md), [设计导航](../../../../docs/design/AGENTS.md), [实现导航](../../../../docs/implementation/AGENTS.md), [实验导航](../../../../docs/experiments/AGENTS.md), 技术栈和部署/网关规格均已说明当前切片及证据入口. D0 最小协议, M1/M2, 完整安全用例和订单级 E6/E7 没有被标为完成.

## 按优先级列出的问题

- CRITICAL: 0 项.
- WARNING: 0 项.
- SUGGESTION: 0 项.

## 最终评估

任务完整性, 规格覆盖, 需求实现映射, 场景覆盖, 设计遵循和工程模式一致性全部完成检验, 无未验证项. 全部检查通过, 可以进入归档流程. 本结论仅适用于 D0 最小网络与状态可用性切片; 明确排除的完整凭证协议, HTTP 服务, OPA/订单事务及业务实验不构成本变更的缺失项.
