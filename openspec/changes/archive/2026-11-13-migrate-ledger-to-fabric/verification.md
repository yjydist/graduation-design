# Fabric D0 核验

## C Peer 停机时同键重试修复复验

35/35 项任务完成. 独立空卷 D0 验收 17/17 通过. 上一轮的同键重试警告已关闭.

- `invoke` 先从本地日志查询操作并校验原输入摘要. C Peer 停机时, 同键同输入返回原 `PENDING` 和原签名字节, 退出码为 0. 同键异输入返回 `OPERATION_KEY_CONFLICT`, 退出码为 1. 待定操作的推进须通过可信 Peer 核验. 修复前同一回归的两次调用均返回连接失败. `internal/fabric/cli.go:148`, `internal/fabric/operation.go:180`, `internal/fabric/verify_transactions.go:279`. [修复前事件](../../../infra/fabric/evidence/failures/invoke-retry/run-11aed7f325b19af7/retry-events.jsonl), [修复后事件](../../../infra/fabric/evidence/recovery/run-bc125193b2161108/events.jsonl).
- 复用旧版写入的日志, 用新版 CLI 核对停机时的原操作及冲突. 停机期间使用新键提交返回连接失败, 查询该键确认日志无记录. 恢复后仍用原提案, txID 和已签交易, 在旧实例第 70 块有效提交. [旧日志复验](../../../infra/fabric/evidence/recovery/run-bc125193b2161108/previous-journal/result.log), [恢复后的原交易](../../../infra/fabric/evidence/recovery/run-bc125193b2161108/previous-journal/recovered.json), [原提交块](../../../infra/fabric/evidence/recovery/run-bc125193b2161108/previous-journal/recovered-block.pb).
- 在 arm64 空卷上用 Fabric 3.1.5 和 Go 1.27.3 复跑. 从 protobuf 核对 75 个连续区块, 87 笔交易, 39 条原交易提交观测和 93 次探针采用. 新增回归在 Peer 恢复后确认原已签交易, 退出码和操作记录均已核对. OpenSpec 严格校验, Go 测试, `go vet`, 依赖锁及 Compose 配置检查通过. [D0 汇总](../../../infra/fabric/evidence/recovery/run-bc125193b2161108/summary.json), [同键重试复核](../../../infra/fabric/evidence/recovery/run-bc125193b2161108/retry-audit.log), [原块复核](../../../infra/fabric/evidence/recovery/run-bc125193b2161108/block-audit.log).

## 本轮归档前核验

| 维度 | 核验结果 |
| --- | --- |
| 完整性 | 34/34 项任务已勾选. 4 项新增及 11 项修改均有对应实现, 三项主规范与增量逐条一致. 依据迁移前主规范确认 3 项删除, 2 项重命名随对应修改核对 |
| 正确性 | 核对 15 项需求及 35 个场景. 独立空卷 D0 验收 17/17 通过, 两项初始化中断回归通过. 管理交易的同键重试在 C Peer 不可用时有 1 处偏差 |
| 一致性 | 通道治理, 登记规则, 固定高度视图及探针符合设计. Go, Compose 和 `ledgerctl` 入口沿用项目约定. `invoke` 的原操作查询顺序与设计有偏差 |

### 警告

1. **C Peer 不可用时, 管理操作同键重试无法返回原结果.** 停止两个排序节点后提交合法 `RegisterGrant`, CLI 已保存原提案和已签交易并返回 `PENDING`. 再停止 C Peer, 使用同一操作键分别重试相同输入和变更输入, 两次 `invoke` 均退出 1 并报告 Peer 连接失败. 同时 `operation --key` 返回与受理时一致的 `PENDING` 和原 txID. 恢复后, 同一已签交易在 76 号块为 `VALID`, 变更输入被判 `OPERATION_KEY_CONFLICT`. `internal/fabric/cli.go:164` 先核验 Peer, `internal/fabric/cli.go:183` 才进入操作日志及摘要检查. 建议先查询已受理操作并校验输入摘要, 无法查询 Peer 时返回原操作, 在受理新操作或推进原交易前核验可信 Peer. 补测 Peer 不可用时的同键同输入与同键异输入. [规范场景](specs/authorization-registry/spec.md#scenario-提交结果暂不可见或出现重复提交), [结果对照](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/retry-outage/comparison.json), [原提交块](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/retry-outage/recovered-block.pb).

### 复验证据

- 在 arm64 独立通道和空卷使用 Go 1.27.3 和 Fabric 3.1.5 复跑. 从 protobuf 核对 76 个连续区块, 88 笔交易, 39 条原交易提交观测和 93 次探针采用. 复算部署标识, 源码及构建摘要和三域安装标识. 公开文件及嵌套归档的私钥标记和路径检查通过. [D0 汇总](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/summary.json), [原块复核](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/block-audit.log), [运行材料](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/runtime.log), [公开材料复核](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/public-material-audit.log).
- 两个独立空卷上的初始化中断专项回归均通过. 首次初始化明确拒绝后, 并发显式续跑仅确认一次原清单. 根已提交后的续跑复用原安装包与原初始化区块, 并保留旧重复提案. 凭证锚的两个越界输入均被拒绝, 两端相等的配对交易在 31 号块为 `VALID`. [首次初始化](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/initialization/init-unendorsed-test.log), [根提交后续跑](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/initialization/init-committed-test.log), [原始事件](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/events.jsonl).
- 健康空闲且暂停探针时, C Peer 高度在 3 秒内保持 77, 恢复发送后 `check` 采用本进程的有效探针. C Peer 停机时, `inspect` 对同一授权在 62 号块返回 `ACTIVE`, 在 63 号块返回 `REVOKED`. 注入 `1ns` 超时返回退出码 1 并保存 `FAIL` 汇总. [空闲对照](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/cli-checks/idle.json), [历史 h](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/cli-checks/historical-62.json), [历史 r](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/cli-checks/historical-63.json), [超时汇总](../../../infra/fabric/evidence/verification/run-7c3014890c67c66b/timeout/run-6ee6e6d0f8633270/summary.json).
- OpenSpec 变更及三项主规范严格校验, `go test -count=1 ./...`, `go vet ./...`, `go mod verify` 和 Compose 配置校验均通过. 迁移前主规范中的 EVM 回执及 trace, 基于区块时间的新鲜度和持续空块行为已从运行入口移除. R1-R5 按仓库 Markdown 核对, 原始任务书 `.doc` 的链接目标缺失. [毕设要求](../../../毕设要求.md).

严重问题 0 项, 警告 1 项, 建议 0 项. 可按 OpenSpec 流程归档, 建议先处理同键重试偏差. 本轮实测覆盖真实 Fabric 管理交易, 合成登记材料和容器级故障. 真实 DID/VC, M1/M2 采购闭环和订单级 E6/E7 按各自阶段验收.

## 部署续跑与凭证期限修复复验

| 维度 | 核验结果 |
| --- | --- |
| 完整性 | 34/34 项任务完成. 三项主规范与增量一致, 15 项需求共 35 个场景, 含本轮补充的两个场景 |
| 正确性 | 独立空卷 D0 验收 17/17 通过. 根提交前后的两项初始化回归通过, 修复前失败的实例续跑成功 |
| 一致性 | 部署续跑复用经三域批准的构建和原交易. 凭证锚签发按当前域认证约束起止边界. 重复初始化拒绝由 D0 验收检查 |

### 两项警告的复验

1. **根已有效提交后的部署续跑.** 修复前, 回归在 `initialize/repeat` 提案保存后中断, 等提案过期后普通部署失败. 修复后, 独立空卷上的同一回归复用 5 号块的原初始化交易, 恢复部署清单, Peer 高度保持 6, 旧重复提案和原批准包逐项一致. 在修复前已失败的实例中, 新版 CLI 也用旧链码构建完成续跑, 原操作和批准文件逐字节一致. 本轮 D0 另行提交重复初始化提案, 取得 `ID_ALREADY_USED`. `internal/fabric/deployment.go:190`, `internal/fabric/deployment_test.go:121`. [修复前回归](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/initialization/before-committed.log), [修复后回归](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/initialization/after-committed.log), [原初始化区块](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/initialization/after-committed-block.pb), [旧实例续跑对照](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/initialization/legacy/comparison.json).
2. **凭证锚有效区间.** 同一 IA, 主体和凭证 ID 的三个配对输入中, 起点比当前 T 域认证早一秒及截止比认证晚一秒的提案均以 `INVALID_STRUCTURE` 拒绝, 两次均核对目标凭证缺失. 起止两端等于认证边界的配对交易在 30 号块为 `VALID`, 链上凭证状态为 `ACTIVE`. `chaincode/registry/identity.go:267`, `internal/fabric/verify_registry.go:417`. [配对结果](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/credential-boundaries.json), [原始事件](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/events.jsonl), [有效提交原块](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/blocks/000030.pb).

### 运行证据

- 在 arm64 独立通道和空卷使用 Go 1.27.3 与 Fabric 3.1.5, 从 protobuf 核对 75 个连续区块, 87 笔交易, 39 条原交易提交观测和 96 次探针采用. 部署标识, 源码, 构建及三域安装标识均复算一致. 公开文件和嵌套归档的私钥标记及文件名检查通过. [D0 汇总](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/summary.json), [原块复核](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/block-audit.log), [材料复核](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/materials-audit.log).
- 首次初始化提案在背书前中断的回归通过, 显式并发续跑只确认一次原批准输入. 注入 `1ns` 超时得到退出码 1 和失败汇总. OpenSpec 变更和三项主规范严格校验, Go 测试, `go vet`, 依赖及 Compose 配置检查通过. [首次初始化回归](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/initialization/after-unendorsed.log), [超时汇总](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/timeout/run-40a78835f077e58b/summary.json), [规范对照](../../../infra/fabric/evidence/recovery/run-f8d3f2a2bd6db7c7/spec-audit.log).

两项警告均已关闭. 本轮严重问题 0 项, 警告 0 项, 建议 0 项, 可按 OpenSpec 流程归档.

## 归档前核验与边界补测

| 维度 | 核验结果 |
| --- | --- |
| 完整性 | 31/31 项任务已勾选. 4 项新增及 11 项修改均定位到实现, 三项主规范与增量逐条一致. 3 项删除依据迁移前主规范确认, 2 项重命名随对应修改核对 |
| 正确性 | 已核对 15 项需求及 33 个场景. 独立空卷 D0 验收 16/16 通过, 首次初始化中断专项回归通过. 额外复现两处偏差 |
| 一致性 | 通道治理, 原交易确认, 固定高度视图及探针符合设计. Go, CLI 和 Compose 的组织方式沿用项目约定. 初始化收尾及凭证锚有效期的契约偏差见下文 |

### 警告

1. **根记录已经有效提交后, 重复初始化负例可阻塞部署续跑.** 在锁定的 Go 工具链和独立空卷上, 于 `initialize/repeat` 的提案保存后, 背书前退出. 可信 C Peer 的 5 号块确认原 `initialize/approved` 为 `VALID`. 等原提案超过 2 秒窗口后, 普通部署及 `deploy --retry-initialization` 均以退出码 1 结束, 保留同一失败提案且缺少部署清单. `internal/fabric/deployment.go:621` 对 `repeat` 直接返回原结果, 第 694 行要求该负例返回 `ID_ALREADY_USED`, 因此第 453 行无法写出清单. 建议在核实原 `VALID` 初始化及根记录后允许恢复清单, 将重复初始化负例移入验收, 并加入这一中断点的回归. [注入差异](../../../infra/fabric/evidence/failures/initialization/repeat-0a2fa6e60975c7cd/injection.diff), [原操作](../../../infra/fabric/evidence/failures/initialization/repeat-0a2fa6e60975c7cd/journal-after.json), [显式续跑日志](../../../infra/fabric/evidence/failures/initialization/repeat-0a2fa6e60975c7cd/retry-explicit.log).
2. **凭证锚的有效期可超过 T 批准的签发资格区间.** 以同一 IA 管理证书提交同主体, 类型, 声明及密钥版本的配对材料. 截止时间等于域认证截止的凭证锚在 75 号块为 `VALID`, 截止时间超过域认证一小时的凭证锚也在 76 号块为 `VALID`. `chaincode/registry/identity.go:260` 分别检查凭证和当前域认证在提案时有效, 签发分支随后允许超出认证区间的凭证锚. 建议在签发时校验 `c.Interval.Within(cert.Interval)`, 补测起点早于及截止晚于认证区间的配对负例. [期限契约](../../../docs/implementation/部署与链上登记.md#2-登记权限与交易结果), [配对交易](../../../infra/fabric/evidence/verification/run-19d92814752d9d32/supplemental/credential-expiry.json), [越界交易原块](../../../infra/fabric/evidence/verification/run-19d92814752d9d32/supplemental/blocks/76.pb).

### 复验证据

- 在 arm64 独立通道和空卷上使用 Go 1.27.3 与 Fabric 3.1.5. 从 protobuf 核对 74 个连续区块, 86 笔交易, 38 次原已签交易提交观测和 93 次探针采用. 部署标识, 源码与构建摘要及三域安装标识复算一致. 已扫描公开材料和嵌套归档的私钥标记及文件名. [D0 汇总](../../../infra/fabric/evidence/verification/run-19d92814752d9d32/summary.json), [原块复核](../../../infra/fabric/evidence/verification/run-19d92814752d9d32/block-audit.log), [初始化回归](../../../infra/fabric/evidence/verification/run-19d92814752d9d32/initialization-regression.log).
- 健康空闲且暂停探针时, C Peer 高度在 3 秒内保持 74. 重新启动 `check` 后采用 74 号块中本进程提交的有效探针. C Peer 停机时, `inspect` 仍在 60 号块返回 `ACTIVE`, 在 61 号块返回 `REVOKED`, 两次均以历史模式输出登记事实. `1ns` 验收超时返回退出码 1 并保存失败汇总. [空闲对照](../../../infra/fabric/evidence/verification/run-19d92814752d9d32/supplemental/idle.json), [历史 h](../../../infra/fabric/evidence/verification/run-19d92814752d9d32/supplemental/historical-60.json), [历史 r](../../../infra/fabric/evidence/verification/run-19d92814752d9d32/supplemental/historical-61.json), [超时退出码](../../../infra/fabric/evidence/verification/run-19d92814752d9d32/supplemental/timeout-exit-status.log).
- OpenSpec 变更及三项主规范严格校验, `go test -count=1 ./...`, `go vet ./...`, `go mod verify` 和 Compose 配置校验通过. 从 Git 迁移前版本恢复三个已删除条目的正文, 确认当前运行入口已去除原 EVM 回执和 trace, 基于区块时间的在线新鲜度以及持续空块判据. R1-R5 对照依据仓库 Markdown, 原始任务书 `.doc` 链接目标缺失. [毕设要求](../../../毕设要求.md), [规范对照](../../../infra/fabric/evidence/verification/run-19d92814752d9d32/spec-audit.log).

严重问题 0 项, 警告 2 项, 建议 0 项. 可按 OpenSpec 流程归档, 建议先处理上述偏差. 本轮实测范围为真实 Fabric 管理交易, 合成登记材料及容器级故障. 真实凭证, 采购闭环及订单级 E6/E7 按后续阶段验收.

## 首次初始化中断修复复验

| 维度 | 核验结果 |
| --- | --- |
| 完整性 | 31/31 项任务完成. 15 项需求均有实现, 新增的初始化中断场景与主规范同步 |
| 正确性 | 初始化中断回归通过. 上轮的实际中断实例以原引导清单续跑成功. 另一组独立空卷 D0 验收 16/16 通过 |
| 一致性 | 续跑沿用原操作日志及部署锁. 显式请求在核对背书拒绝, 无已签交易及可信 C Peer 的空根结果后, 用关联旧 txID 的新键受理同一清单 |

- 在独立空卷上停止 C Peer, 通过正常日志入口持久化原提案. 恢复 C Peer 后, 普通部署取得原时间窗口拒绝并提示显式续跑, 日志中只有原操作. 两次并发显式续跑仅创建一条新操作, 其交易在 5 号块为 `VALID`. 原操作的提案, txID 和拒绝证据保持一致. 单元测试覆盖待定, 缺拒绝证据, 已签名, 已广播及已入块等禁止新建操作的条件. `internal/fabric/deployment.go:587`, `internal/fabric/deployment_test.go:51`. [回归日志](../../../infra/fabric/evidence/recovery/initialization-retry/regression.log), [原操作与续跑结果](../../../infra/fabric/evidence/recovery/initialization-retry/fresh-initialization.json).
- 复用上轮在提案落盘后注入进程退出的实例, `mise run ledger:deploy -- --retry-initialization` 提交新交易并生成部署清单. 原失败日志与上轮逐字段一致, 引导清单逐字节一致. 移开两个本地清单文件后重跑普通部署, 恢复出的部署清单和初始化证据均逐字节一致. 两次续跑的已签交易均与可信 C Peer 的 5 号块和校验码相符. [旧实例初始化日志](../../../infra/fabric/evidence/recovery/initialization-retry/prior-interruption/initialization.json), [清单重建对照](../../../infra/fabric/evidence/recovery/initialization-retry/prior-interruption/manifest-resume.json), [原块复核](../../../infra/fabric/evidence/recovery/initialization-retry/block-audit.log).
- 在 arm64 独立通道和空卷使用 Go 1.27.3 与 Fabric 3.1.5 复跑 D0. 从 protobuf 复核 74 个区块和 85 笔交易, 对照 38 条原操作提交观测和 93 次探针采用. 部署标识, 源码与构建摘要及三域安装标识复算一致. OpenSpec 变更与三项主规范严格校验, Go 测试, `go vet`, 依赖和 Compose 配置检查均通过. [D0 汇总](../../../infra/fabric/evidence/recovery/run-41970887f9a83b5d/summary.json), [原始区块](../../../infra/fabric/evidence/recovery/run-41970887f9a83b5d/blocks.jsonl), [材料复核](../../../infra/fabric/evidence/recovery/run-41970887f9a83b5d/materials-audit.log).

首次初始化恢复警告已关闭. 本轮复验发现严重问题 0 项, 警告 0 项, 可按 OpenSpec 流程归档.

## 归档前复验

| 维度 | 核验结果 |
| --- | --- |
| 完整性 | 30/30 项任务已勾选. 4 项新增和 11 项修改均有实现. 3 项删除依据迁移前主规范核对, 相应行为已移除. 2 项重命名随对应修改核对, 三项主规范与增量一致 |
| 正确性 | 核对 15 项需求及 32 个规范场景. 独立空卷 D0 验收 16/16 通过, 补测复现 1 处首次部署恢复问题 |
| 一致性 | 通道治理, 登记权限, 原交易取证, 固定高度快照与探针沿用设计. Go, CLI 和 Compose 结构符合项目约定. 首次部署在原提案已保存且尚未背书时存在恢复缺口 |

### 警告

1. **首次部署在提案已落盘且尚未背书时中断, 之后可能无法续跑.** 在独立空卷上用 Go overlay 注入进程退出, 保留 `initialize/approved` 的原签名提案和 txID. 等待 4 秒后用原版 CLI 两次运行 `ledger:deploy`, 均以退出码 1 结束. C Peer 拒绝超出 2 秒窗口的原提案, 操作转为 `FAILED / ENDORSEMENT_REJECTED`. 再次部署复用固定操作键, 直接返回同一失败结果. 可信 Peer 查不到原交易和根记录, 部署清单仍缺失. 建议保留旧操作及 txID, 在确认原提案已被拒绝, 原操作从未生成已签交易且链上根仍为空后, 提供使用新操作键的显式续跑入口. 增加在保存提案与背书之间中断的回归场景. `internal/fabric/operation.go:202`, `internal/fabric/operation.go:220`, `internal/fabric/deployment.go:627`. [注入差异](../../../infra/fabric/evidence/failures/initialization/5cecee150e9b6691/injection.diff), [重跑日志](../../../infra/fabric/evidence/failures/initialization/5cecee150e9b6691/second-retry.log), [Peer 根查询](../../../infra/fabric/evidence/failures/initialization/5cecee150e9b6691/bootstrap-read.log).

### 核验证据

- 在 arm64 独立通道和空卷使用 Go 1.27.3 与 Fabric 3.1.5 复跑. 从 protobuf 复核 75 个区块和 87 笔交易, 对照 38 条原操作提交观测和 91 次探针采用. 58 号块为原 `VALID`, 59 号块为同一签名交易的 `DUPLICATE_TXID`. 复算部署标识, 链码源码及构建摘要与三域安装标识. 114 个公开文件及归档成员通过私钥标记和路径检查. [D0 汇总](../../../infra/fabric/evidence/verification/run-9e4d72ad29981721/summary.json), [原始区块](../../../infra/fabric/evidence/verification/run-9e4d72ad29981721/blocks.jsonl), [材料复核](../../../infra/fabric/evidence/verification/run-9e4d72ad29981721/supplemental/materials-audit.log).
- 健康空闲时暂停探针 3 秒, C Peer 高度保持 76. C Peer 停机期间, 同一授权在 61 号块为 `ACTIVE`, 在 62 号块为 `REVOKED`. 恢复 C Peer 后, `check` 采用本进程新发的探针. 注入 `1ns` 验收超时得到退出码 1 和 `FAIL` 汇总. [历史与恢复证据](../../../infra/fabric/evidence/README.md), [超时汇总](../../../infra/fabric/evidence/failures/timeout/run-e4489cc509abed4d/summary.json).
- OpenSpec 变更及三项主规范严格校验, `go test -count=1 ./...`, `go vet ./...`, `go mod verify` 和 Compose 配置校验均通过. R1-R5 依据仓库 Markdown 核对, 原始任务书的 `.doc` 链接目标缺失. [毕设要求](../../../毕设要求.md).

严重问题 0 项, 警告 1 项, 建议 0 项. 可按 OpenSpec 流程归档, 建议先处理上述部署恢复问题.

## 部署与检查点恢复修复复验

| 维度 | 核验结果 |
| --- | --- |
| 完整性 | 30/30 项任务完成. 三项主规范与增量保持一致 |
| 正确性 | 独立空卷 D0 验收 16/16 通过. 两项警告对应的回归均通过 |
| 一致性 | 初始化续跑使用原操作日志. 检查点查询临时断流沿用原探针期限, 并保留检查点异常时的拒绝 |

1. 根和实例的初始化篡改用例从同一引导清单生成固定输入. 续跑优先读取已受理的原操作, 兼容旧实例中随机生成的负例. 在旧隔离实例中临时移走部署清单和初始化取证文件后, `ledger:deploy` 重新生成两个文件, 内容与原文件逐字节一致, 复用第 5 块的原初始化交易. 空卷验收的 `initialization-resume` 用例也核对了原操作和初始化块. `internal/fabric/deployment.go:579`, `internal/fabric/verify_registry.go:311`. [旧日志续跑对照](../../../infra/fabric/evidence/recovery/legacy-resume.json).
2. 在通过通道和部署核验后, 对 65 号检查点查询分别注入 gRPC `Unavailable`, `DeadlineExceeded` 和 `NotFound`. 前两种在无可用探针时返回 `STATE_STALE`, 明确缺块时返回 `STATE_UNAVAILABLE`. 三种情况均保留检查点. 恢复后, 读取实例续读并采用 66 号块中新发的有效探针. `internal/fabric/view.go:432`, `internal/fabric/verify_view.go:440`. [原始事件](../../../infra/fabric/evidence/recovery/run-4641834ccc6a733d/events.jsonl).

- 使用 Go 1.27.3 和 Fabric 3.1.5 在 arm64 独立空卷复跑. 从 protobuf 复核 74 个区块和 86 笔交易, 核对 38 条原交易提交观测和 91 次探针采用. 部署标识, 链码构建与安装包摘要复算一致. 公开材料和嵌套归档未检出 PEM 私钥标记或私钥文件成员. [D0 汇总](../../../infra/fabric/evidence/recovery/run-4641834ccc6a733d/summary.json), [区块索引](../../../infra/fabric/evidence/recovery/run-4641834ccc6a733d/blocks.jsonl).
- OpenSpec 变更与三项主规范严格校验, `go test -count=1 ./...`, `go vet ./...`, `go mod verify` 和 Compose 配置校验均通过. 注入 `1ns` 验收超时返回退出码 1, 并保存失败汇总. [超时汇总](../../../infra/fabric/evidence/failures/timeout/run-9116c85a00109ae0/summary.json), [退出码](../../../infra/fabric/evidence/failures/timeout/run-9116c85a00109ae0/exit-status.json).

本轮复验通过, 严重问题和警告各 0 项.

## 部署与检查点恢复修复前核验

| 维度 | 核验结果 |
| --- | --- |
| 完整性 | 30/30 项任务已勾选. 4 项新增和 11 项修改均有实现. 从迁移前 Git 版本恢复旧规范, 确认 3 项删除行为已移除. 2 项重命名随对应修改核对, 三项主规范与增量一致 |
| 正确性 | 已核对 15 项需求和 32 个场景. 独立空卷 D0 复跑 14/14 通过. 补测复现首次部署续跑失败和检查点查询断流误报 |
| 一致性 | 通道治理, 登记, 提交恢复及固定高度视图沿用设计与项目的 Go, CLI 和 Compose 结构. 检查点查询断流时的处理与探针期限规则有偏差 |

### 警告

1. **首次部署中断后可能无法续跑.** 在独立实例中保留通道, 卷和操作日志, 临时移走最终部署清单, 模拟初始化已经落盘但清单尚未写出. 再运行 `ledger:deploy` 以退出码 1 返回 `OPERATION_KEY_CONFLICT: initialize/changed-root`. 根和实例篡改负例每次生成随机输入, 却沿用固定操作键. 建议从同一引导清单确定性地生成负例, 使续跑能复用已记录的原操作, 并增加清单写出前中断的用例. `internal/fabric/deployment.go:595`, `internal/fabric/operation.go:199`. [部署续跑日志](../../../.local/openspec-fabric-verify-current.GBOFzp/deploy-resume.stderr).
2. **查询原检查点时短暂断流会误报视图异常.** 已从可信 C Peer 核对部署和 73 号检查点. 仅让随后读取该检查点原块的请求返回 gRPC `Unavailable`, 无可用探针的新读取实例立即返回 `STATE_UNAVAILABLE`. 规范要求该条件下返回 `STATE_STALE`. 建议重试传输错误并按原探针期限判定新鲜度, 对确证的缺块, 哈希或校验元数据失配继续停止在线读取. `internal/fabric/view.go:430`, `internal/fabric/probe.go:129`, `internal/fabric/cli.go:208`. [提交探针限定状态新鲜度](specs/fixed-height-state/spec.md#requirement-提交探针限定状态新鲜度), [断流注入日志](../../../.local/openspec-fabric-verify-current.GBOFzp/checkpoint-transport.log).

### 复跑与证据

- 使用锁定的 Go 1.27.3 和 Fabric 3.1.5 镜像, 在 arm64 独立通道与空卷运行 `run-970018905beab8eb`. 复算部署标识, 源码和链码构建摘要及三域安装包标识. 新实例与上轮的创世块, 实例和部署标识均不同. 公开材料和嵌套归档未检出 PEM 私钥标记或私钥文件成员. [运行汇总](../../../.local/openspec-fabric-verify-current.GBOFzp/evidence/run-970018905beab8eb/summary.json).
- 从原始 protobuf 复核 74 个区块和 91 笔交易, 核对 38 条原交易提交观测与 89 次探针采用. 57 号块原交易为 `VALID`, 58 号块相同已签交易为 `DUPLICATE_TXID`. 停止 C Peer 后, `inspect` 仍从本地历史返回 60 号块的 `ACTIVE` 和 61 号块的 `REVOKED`. 健康空闲时暂停探针 3 秒, Peer 高度保持 75. [原始事件](../../../.local/openspec-fabric-verify-current.GBOFzp/evidence/run-970018905beab8eb/events.jsonl), [区块索引](../../../.local/openspec-fabric-verify-current.GBOFzp/evidence/run-970018905beab8eb/blocks.jsonl), [复核日志](../../../.local/openspec-fabric-verify-current.GBOFzp/evidence-audit.log).
- OpenSpec 变更和三项主规范的严格校验, `go test -count=1 ./...`, `go vet ./...`, `go mod verify` 及 Compose 配置校验均通过. 注入 `1ns` 验收超时返回退出码 1, 保存 `FAIL` 汇总. R1-R5 依据仓库 Markdown 核对, 其引用的原始 `.doc` 缺失. 真实 DID/VC, 采购闭环及订单级 E6/E7 按对应阶段验收. [超时汇总](../../../.local/openspec-fabric-verify-current.GBOFzp/timeout/run-edab4bc6242af3e5/summary.json), [毕设要求](../../../毕设要求.md), [阶段任务](../../../TODO.md).

严重问题 0 项, 警告 2 项, 建议 0 项. 可按 OpenSpec 流程归档, 建议先修复上述两处恢复问题.

## 上轮空卷复验

| 维度 | 核验结果 |
| --- | --- |
| 完整性 | 30/30 项任务完成. 4 项新增和 11 项修改均有实现, 3 项删除行为已移除, 2 项重命名随对应修改核验. 三项主规范与增量一致 |
| 正确性 | 已核对 15 项需求和 32 个规范场景. 两项回归在修复前均复现, 修复后同一隔离实例和独立空卷各通过 14/14 项 D0 验收 |
| 一致性 | 通道治理, 链码登记, 原交易确认, 固定高度视图及提交探针均符合设计. Go 实现和回归用例沿用现有 CLI 与验收结构 |

### 回归结果

1. 续读先从 PostgreSQL 取得检查点, 随后查询 C Peer 高度, 并用取得的检查点核对原块和续读位置. 回归用例在返回高度 66 前通过有效探针推进共享视图至 66 号块. 读取实例连续续读, 对另一消费路径已应用的区块完成幂等校验. 真正的回退, 同高冲突和缺块仍由异常用例覆盖. `internal/fabric/view.go:405`, `internal/fabric/verify_view.go:380`. [检查点异常停止在线检查](specs/fixed-height-state/spec.md#requirement-检查点异常停止在线检查).
2. 部署核验区分查询失败与已取得材料的失配. 停止 `cc-c` 时, C Peer 仍返回高度 73, 持久化检查点为 72 号块. 新 `check` 等待后返回 `STATE_STALE`, 退出码 1. 恢复链码后, 故障期间启动的读取实例在 73 号块采用新发的有效探针. 配置摘要失配仍报 `DEPLOYMENT_MISMATCH` 并阻止在线续读. `internal/fabric/deployment.go:358`, `internal/fabric/verify_view.go:594`, `internal/fabric/verify_registry.go:294`. [提交探针限定状态新鲜度](specs/fixed-height-state/spec.md#requirement-提交探针限定状态新鲜度).

### 复跑与证据

| 运行 | 结果 | 证据 |
| --- | --- | --- |
| 修复前对照 `run-530750fbf1fd7c28` | 12/14. 共享视图误报 Peer 回退, 链码连接超时误报部署失配 | [汇总](../../../infra/fabric/evidence/failures/online-view/run-530750fbf1fd7c28/summary.json), [事件](../../../infra/fabric/evidence/failures/online-view/run-530750fbf1fd7c28/events.jsonl) |
| 同一隔离实例复测 `run-56a6e0db16307d89` | 14/14. 两项回归通过, deploymentId 与对照相同 | [汇总](../../../infra/fabric/evidence/online-view/run-56a6e0db16307d89/summary.json), [事件](../../../infra/fabric/evidence/online-view/run-56a6e0db16307d89/events.jsonl) |
| 首次空卷复跑 `run-573e012a0b91ad43` | 13/14. 两项回归通过. 原交易重播已入块, 验收等待排序端应答超时 | [汇总](../../../infra/fabric/evidence/failures/online-view/run-573e012a0b91ad43/summary.json), [区块索引](../../../infra/fabric/evidence/failures/online-view/run-573e012a0b91ad43/blocks.jsonl) |
| 最终空卷复验 `run-8af51ccf8fdde7d7` | 14/14. 独立通道和命名卷, Go 1.27.3, Fabric 3.1.5, arm64 | [汇总](../../../infra/fabric/evidence/online-view/run-8af51ccf8fdde7d7/summary.json), [事件](../../../infra/fabric/evidence/online-view/run-8af51ccf8fdde7d7/events.jsonl), [区块索引](../../../infra/fabric/evidence/online-view/run-8af51ccf8fdde7d7/blocks.jsonl) |

- 首次空卷复跑的 58 号块记录原交易 `VALID`, 59 号块记录同一 txID 的 `DUPLICATE_TXID`. 现有验收在等待排序端应答时一并查询可信 Peer 的区块. 仍须取得重复入块的校验码, 并核对原操作的 `VALID` 结果, 块位置和已签字节. `internal/fabric/verify_transactions.go:315`.
- 四次运行共核对 344 个原始区块和 410 笔交易, 对照区块数据和父块哈希, 校验码, 原交易与重播, 以及有效探针的发送和采用期限. 复算部署标识和链码包摘要, 公开证据与嵌套归档未检出 PEM 私钥标记或私钥文件成员. [证据索引](../../../infra/fabric/evidence/README.md).
- 变更与三项主规范的 OpenSpec 严格校验, `go test -count=1 ./...`, `go vet ./...`, `go mod verify` 和 Compose 配置校验均通过. 注入 `1ns` 验收超时, 退出码 1 并保留失败汇总. 原始任务书的 `.doc` 链接目标缺失, R1-R5 依据仓库中的 Markdown 核对. [超时汇总](../../../infra/fabric/evidence/failures/timeout/run-556745e8bfc474de/summary.json), [毕设要求](../../../毕设要求.md).

全部适用核验通过, 可按 OpenSpec 流程归档. 严重问题, 警告和建议各 0 项.

## 修复前核验

| 维度 | 核验结果 |
| --- | --- |
| 完整性 | 30/30 项任务已勾选. 4 项新增和 11 项修改均有实现. 从 Git HEAD 取得旧规范, 确认 3 项删除的行为已移除. 2 项重命名随对应修改核对. 三项主规范与增量一致 |
| 正确性 | 已对照 15 项需求与 32 个场景的实现和证据. 锁定工具链下 D0 复跑 12/12 通过. 补测发现 2 个故障或并发分支存在偏差 |
| 一致性 | 核对通道治理, 链码登记, 原交易确认, 固定高度视图和提交探针. 共享视图续读及探针不可用时的错误归类有偏差. Go 模块, CLI 和 Compose 结构符合项目约定 |

### 警告

1. **共享视图推进时可能误报 Peer 回退.** 补测保留第一个读取实例从 C Peer 取得的高度 74, 让第二个实例以有效探针应用 74 号块, 再恢复第一个实例. 同一 Peer 此时的实际高度为 75, 第一个实例仍因比较先前的高度 74 和新检查点而返回 `STATE_UNAVAILABLE`. 建议先读取持久化检查点, 再查询 Peer 高度, 并用同一检查点核对区块及续读. 用两实例共享同一数据库补足回归覆盖. `internal/fabric/view.go:405`, `internal/fabric/view.go:479`. [检查点异常停止在线检查](specs/fixed-height-state/spec.md#requirement-检查点异常停止在线检查).
2. **C 链码暂时失联会误报部署失配.** 独立停止 `cc-c` 后, C Peer 仍能返回高度 73, 部署清单摘要相同, 新 `check` 却将链码连接超时报为 `STATE_UNAVAILABLE` 和 `DEPLOYMENT_MISMATCH`. 恢复同一链码容器后, `check` 采用新探针并成功. 建议区分查询暂时失败和已核实的材料不匹配, 对已保存视图在等待期限内重试, 缺少可用探针时返回 `STATE_STALE`. `internal/fabric/deployment.go:355`, `internal/fabric/deployment.go:393`, `internal/fabric/view.go:419`. [提交探针限定状态新鲜度](specs/fixed-height-state/spec.md#requirement-提交探针限定状态新鲜度).

### 复跑与证据

- 首次隔离复跑 `run-79da08921627543e` 通过 12 项, 链码使用宿主 Go 1.27.4 构建. 以 `mise` 锁定的 Go 1.27.3 重建独立通道和空卷, 复核链码构建信息后, `run-0ae5baa60f8ed613` 再次通过 12 项. 以锁定工具链复跑作为验收依据.
- 在锁定工具链复跑中, 停两个排序节点时 Peer 高度保持 69. C Peer 停机后, 新 `check` 返回 `STATE_STALE`, 退出码 1. 另用 `inspect` 在 C Peer 停机时复查同一授权, 62 号块为 `ACTIVE`, 63 号块为 `REVOKED`, 两次均无探针. 注入 `1ns` 总超时得到退出码 1 和 `FAIL` 汇总 `run-1a35fa5d7bf9b07d`.
- 重新核对索引中的 4 次成功验收及本轮锁定工具链复跑, 共 538 个原始区块, 665 笔交易. 块号, 块头及父块哈希, 数据哈希和校验码与索引一致. 复算部署标识与链码包摘要, 对照原 `VALID`, 重播 `DUPLICATE_TXID` 和采用的有效探针. 公开证据和嵌套归档未检出 PEM 私钥标记或私钥文件成员. [证据索引](../../../infra/fabric/evidence/README.md).
- 本机 `.local/openspec-fabric-pinned.d0BcO9/` 保存复跑材料. `evidence/run-0ae5baa60f8ed613/` 保存验收汇总, 事件和区块. `shared-view/test.log` 保存共享视图的并发失败, `supplemental/chaincode-outage-check.stderr` 及同目录的高度, 清单摘要和恢复结果保存链码失联样本.
- OpenSpec 变更及三项主规范严格校验, `go test -count=1 ./...`, `go vet ./...`, `go mod verify` 和 Compose 配置校验均通过. 原始任务书的 `.doc` 链接目标缺失, R1-R5 依据仓库中的 Markdown 核对. [毕设要求](../../../毕设要求.md).

本轮无严重问题, 有 2 项警告. 可按 OpenSpec 流程归档, 建议先处理两处在线读取误报.

## 上轮归档前核验

| 维度 | 核验结果 |
| --- | --- |
| 完整性 | 30/30 项任务已勾选. 4 项新增和 11 项修改均有实现. 从 Git HEAD 恢复旧规格后, 确认 3 项删除的行为已移除. 2 项重命名随对应修改核验 |
| 正确性 | 15 项需求的实现与 32 个场景均符合规格 |
| 一致性 | 已核对通道治理, 链码登记, 原交易确认, 固定高度视图及探针 5 组设计决策. Go 模块, CLI 和 Compose 结构符合项目约定 |

### C Peer 断流启动回归

`online.lease` 优先报告已经检测到的部署或检查点错误. 有持久化检查点时, 新进程等待续读校验或缺少可用探针会返回 `STATE_STALE`. `sorter-and-peer-failures` 在 C Peer 停机且原探针过期后启动独立的 `ledgerctl check --timeout 2s` 进程, 核对退出码 1 和 `STATE_STALE` 前缀. `internal/fabric/probe.go:129`, `internal/fabric/verify_view.go:506`. [停链后反复读取](specs/fixed-height-state/spec.md#scenario-停链后反复读取).

| 运行 | D0 结果 | 断流后新进程结果 |
| --- | --- | --- |
| 修复前 `run-603cb65a2adb6cf3` | 11/12, 新增回归失败 | 在检查点 67 返回 `STATE_UNAVAILABLE`, 退出码 1 |
| 修复后 `run-74ce4b2657a229fa` | 12/12, 含新增回归 | 在检查点 67 返回 `STATE_STALE`, 退出码 1 |

两轮均在 arm64 独立通道及空卷上运行. 本机 `.local/openspec-fabric-stale.t6i213/` 保存汇总, 区块和 `peer_c_outage_new_check` 原始事件. 恢复 C Peer 后, 新启动的 `check` 在第 71 块采用有效探针. 使用失配的通道配置摘要补测, `check` 返回 `STATE_UNAVAILABLE` 并附带 `DEPLOYMENT_MISMATCH`.

本轮 OpenSpec 严格校验, `go test -count=1 ./...`, `go vet ./...`, 依赖及 Compose 配置校验均通过. 全部适用检查通过, 可进入归档流程. CRITICAL, WARNING 和 SUGGESTION 均为 0 项.

### 实现与场景依据

| 需求 | 实现及验收定位 |
| --- | --- |
| 许可通道与四个排序节点 | `infra/fabric/channel.sh:88` 和 `infra/fabric/channel.sh:137` 配置 SmartBFT 和三域生命周期策略. `internal/fabric/verify_registry.go:27` 验证创世块, 四排序身份, 未许可提案/交付及单组织升级失败. `internal/fabric/verify_transactions.go:218` 对照单组织及多组织背书 |
| 部署绑定和持久化 | `internal/fabricapi/types.go:68` 计算部署标识, `internal/fabric/deployment.go:355` 核对实际配置, 定义及引导记录. `internal/fabric/verify_registry.go:257` 和 `internal/fabric/verify_view.go:529` 覆盖材料失配, 旧部署材料和停启保留 |
| 运行材料可复现 | `infra/fabric/compose.yaml:1` 和 `infra/fabric/tools.sh:4` 锁定架构及摘要. `internal/fabric/verify.go:171` 导出公开材料, `internal/fabric/verify.go:201` 导出完整块. 首轮重建复算了 deploymentId, 源码摘要及三个 package ID |
| 排序可用性与故障恢复 | `internal/fabric/verify_view.go:379` 检验停一, 停二及 C Peer 独立断流. 首轮额外停止排序节点 A 后仍采用 VALID 探针. 无登记且无探针时 Peer 高度 3 秒内保持 71, 恢复发探针后 `check` 成功 |
| 固定根与最小登记路径 | `chaincode/registry/main.go:183` 限定初始化证书及清单. `chaincode/registry/identity.go:41` 和 `chaincode/registry/grant.go:9` 落实 T 与 U 角色. 初始化样本及 `internal/fabric/verify_registry.go:299` 覆盖合法路径, 越权和同 MSP 错证书 |
| 标识和路径约束 | `chaincode/registry/grant.go:50` 逐键检查 ID, 任务及祖先. `internal/fabric/verify_registry.go:361` 覆盖路径配对. 首轮补测第 74 块父授权撤销为 VALID, 此前已背书的子授权登记在第 75 块为 MVCC_READ_CONFLICT, 子记录未生成 |
| 撤销权限与版本竞争 | `chaincode/registry/grant.go:133` 实施角色, 版本及终态检查, `chaincode/registry/grant.go:185` 在同一写集替换. `internal/fabric/verify_registry.go:418` 和 `internal/fabric/verify_transactions.go:190` 覆盖原子替换, 终态和版本竞争 |
| 管理提案的时间资格 | `infra/fabric/compose.yaml:14` 配置 2 秒 Peer 时间窗口, `chaincode/registry/main.go:179` 叠加 1 秒校时误差. `internal/fabric/verify_transactions.go:64` 验证回填, 临界时间, 到期后提交及交付期限复核 |
| 管理交易确认与失败证据 | `internal/fabric/operation.go:180` 持久化原操作, `internal/fabric/operation.go:295` 恢复原签名交易, `internal/fabric/operation.go:408` 按可信 Peer 原块校验. `internal/fabric/verify_transactions.go:144` 和 `internal/fabric/verify_transactions.go:278` 覆盖并发, 失联与重复入块 |
| 所有依赖固定同一高度 | `internal/fabric/view.go:79` 原子应用有效写集和检查点, `internal/fabric/view.go:204` 用同一只读事务装配. `internal/fabric/verify_view.go:21` 注入无效写入和事务中断, `internal/fabric/verify_view.go:199` 在装配期间应用撤销 |
| 历史复查与在线检查分离 | `internal/fabric/cli.go:113` 要求显式高度, `internal/fabric/view.go:257` 核对历史范围. 首轮 C Peer 停机时以历史 CLI 复查 h/r, 两次结果均无探针字段 |
| 查询失败不退回最新状态 | `internal/fabric/view.go:182` 遇缺记录即停止, `internal/fabric/view.go:257` 检查历史缺口. `internal/fabric/verify_view.go:151` 和 `internal/fabric/verify_view.go:250` 覆盖缺口及缺依赖 |
| 检查点异常停止在线检查 | `internal/fabric/block.go:70` 校验通道, 数据和交易校验元数据. `internal/fabric/view.go:405` 核对检查点并续读. `internal/fabric/verify_view.go:52` 起注入缺块, 回退, 同高冲突和配置变更 |
| 验证结果可追溯 | `internal/fabric/verify.go:64` 输出逐项结果及原始证据. 首轮复算五次成功运行的区块索引连续性, h/r 和探针 txID, 核对原 VALID 和重播 DUPLICATE_TXID. 注入 1ns 总超时得到退出码 1 和 FAIL 汇总 |
| 提交探针限定状态新鲜度 | `chaincode/registry/main.go:92` 只允许专用身份写对应探针键. `internal/fabric/probe.go:74` 记录首次发送时刻, `internal/fabric/probe.go:116` 用同一视图核对原 txID 和期限. `internal/fabric/verify_view.go:258` 覆盖无效, 未应用, 迟到, 重复及期限等值, `internal/fabric/verify_view.go:506` 覆盖断流启动 |

### 首轮复跑

- 在 arm64 宿主的独立通道和空卷上执行 `ledger:verify`, 运行 `run-241992e35e3f855e` 的 12 项验收全部通过. 新证据存于本机 `.local/openspec-fabric-verify.Let2YC/`. 核对版本锁, Compose 及通道脚本与清理旧账本后保存的证据一致. 对公开证据和压缩包成员扫描私钥标记, 无命中. [证据索引](../../../infra/fabric/evidence/README.md).
- `openspec validate migrate-ledger-to-fabric --strict`, `openspec validate --specs --strict`, `go test -count=1 ./...`, `go vet ./...`, `go mod verify` 和 Compose 配置校验均通过. 三项主规范与增量逐条一致. 任务书条款按仓库中的 Markdown 核对, 第 5 行既有 `.doc` 链接目标缺失. [毕设要求](../../../毕设要求.md).

## 运行结果

| 实例 | 判据 | 证据 |
| --- | --- | --- |
| 原实例 | 12/12 通过. 撤销对照 h=193, r=194. 停两个排序节点的稳定窗口内 Peer 高度为 200 | [汇总](../../../infra/fabric/evidence/original/run-271437baa239da4e/summary.json), [事件](../../../infra/fabric/evidence/original/run-271437baa239da4e/events.jsonl) |
| 新建独立卷和通道的实例 | 12/12 通过. 撤销对照 h=60, r=61. 停两个排序节点的稳定窗口内 Peer 高度为 67 | [汇总](../../../infra/fabric/evidence/clean/run-f008fd88766dd7c6/summary.json), [事件](../../../infra/fabric/evidence/clean/run-f008fd88766dd7c6/events.jsonl) |
| 部署绑定 | 源码锁相同, 新实例的 genesisHash, instanceId, deploymentId 和 package ID 均独立. 用新实例的 U 证书提交原实例材料时提案拒绝, 本部署材料入块 VALID | [重建对照](../../../infra/fabric/evidence/comparison/rebuild.json) |
| 验收超时 | 注入超时, 退出码 1, 保留失败汇总和事件 | [失败样本](../../../infra/fabric/evidence/failures/timeout/run-ecfd28d9fdf0bed7/summary.json) |
| 默认入口 | mise 和 ledgerctl 直接运行 Fabric 部署, 夹具, 在线检查, 历史复查和验收 | [同高度读取对照](../../../infra/fabric/evidence/comparison/default-entrypoints.json), [复跑命令](../../../README.md) |
| 清理旧账本后空卷复验 | 用仅含 Fabric 运行所需的依赖锁构建和部署, 12/12 通过 | [汇总](../../../infra/fabric/evidence/fabric-only/run-3c17f751689aba29/summary.json), [原始事件](../../../infra/fabric/evidence/fabric-only/run-3c17f751689aba29/events.jsonl) |

当前项目只包含 Fabric 的运行入口及实现. 许可账本, 授权登记和固定高度状态三项主规范已同步. 旧账本的历史归档可在迁移前 Git 提交 `8a76f63eaeee1896474a66ec1048f8de88eeaa72` 下连同原验收材料查阅.

## 判据追踪

- 通道及治理. 三个 Peer 创世哈希一致, 四个 consenter 的签名和 TLS 证书匹配, BFT 区块签名门槛为 3/4. 未获准读写分别在 Deliver 和提案阶段拒绝, 未配置的第五身份的排序连接返回 Unauthenticated. A 单独批准的定义变更入块无效.
- 登记与部署. 初始清单篡改, 错证书及重复初始化均拒绝. 真实管理证书验证 T, 本域机构, U 和资源方的权限. RP 正反例覆盖父摘要, 根, 任务, 模式, 密钥版本, 期限与深度. 撤销保留终态, 替换的两项写入随同一交易生效. Peer 拒绝回填时间, 临界提案符合 3 秒边界规则, 到期后提交的已背书交易仍以 VALID 记录, 交付时间检查为不可用.
- 原交易. 同键并发和独立进程恢复保留原 txID 和签名字节. 两笔已背书交易竞争产生 MVCC_READ_CONFLICT, 资格先变更同样使旧读集无效. 单组织背书产生 ENDORSEMENT_POLICY_FAILURE. 丢失原广播响应时先保持 PENDING. SmartBFT 可拦截立即重投, 保留账本重启排序节点后重投产生 DUPLICATE_TXID, 原 VALID 块及位置保持不变.
- 视图与新鲜度. 原块连续性及校验元数据经过核对. 隔离数据库注入同块多次写入, 无效写入, 删除与事务中断, 实测检查点和版本原子性. 真实撤销在两次依赖读取之间应用后, 当次仍取 h, 后续 r 为 REVOKED. 无效, 未应用, 迟到和重复探针均不续期. 按 1 秒间隔和 5 秒期限实测, 原期限等值时拒绝.
- 故障及恢复. 停一个排序节点仍采用新 VALID 探针, 停两个无新确认且原探针到期后返回 STATE_STALE. C Peer 独立停机时 A/B 仍能完成提交, C 到期后拒绝并在恢复补齐和采用新探针后可用. 正常停启保留命名卷, deploymentId, 历史和检查点.

[证据索引](../../../infra/fabric/evidence/README.md)保留原始区块, 校验码, 运行材料及失败记录. [离线检查](../../../infra/fabric/evidence/comparison/checks.log)覆盖 Go 测试, vet 和 OpenSpec 严格校验, 部署及双证明向量由 Go 测试复算.

## 范围

D0 覆盖合成登记夹具与真实 Fabric 管理交易, 固定高度读取及探针, 容器级故障和恢复. 真实 DID/VC, U 持 RP 根的询价在 M1 验收. 两种根的订单, 策略, 幂等和订单级 E6/E7 使用各自业务证据. [阶段任务](../../../TODO.md), [实验判据](../../../docs/experiments/验证用例.md).
