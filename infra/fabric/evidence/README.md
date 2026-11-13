# Fabric D0 验收证据

在 arm64 Docker Desktop 上, 原实例与干净重建实例各通过 12 项. 加入在线读取回归后, 同一隔离实例和独立空卷各通过 14 项. 加入初始化续跑及检查点查询断流回归后, 独立空卷通过 16 项. 补齐根提交后的续跑及凭证期限边界后, 独立空卷通过 17 项. 运行命令和环境要求见[网络说明](../README.md), 判据和覆盖范围见[变更核验](../../../openspec/changes/archive/2026-11-13-migrate-ledger-to-fabric/verification.md).

| 运行 | 汇总 | 原始记录 |
| --- | --- | --- |
| 原实例 run-271437baa239da4e | [12/12](original/run-271437baa239da4e/summary.json) | [事件](original/run-271437baa239da4e/events.jsonl), [区块及交易校验码](original/run-271437baa239da4e/blocks.jsonl), [部署与安装标识](original/run-271437baa239da4e/materials/deployment.json) |
| 干净重建 run-f008fd88766dd7c6 | [12/12](clean/run-f008fd88766dd7c6/summary.json) | [事件](clean/run-f008fd88766dd7c6/events.jsonl), [区块及交易校验码](clean/run-f008fd88766dd7c6/blocks.jsonl), [部署与安装标识](clean/run-f008fd88766dd7c6/materials/deployment.json) |
| 清理旧账本后空卷复验 run-3c17f751689aba29 | [12/12](fabric-only/run-3c17f751689aba29/summary.json) | [事件](fabric-only/run-3c17f751689aba29/events.jsonl), [区块及交易校验码](fabric-only/run-3c17f751689aba29/blocks.jsonl), [Go 依赖锁](fabric-only/run-3c17f751689aba29/materials/go.mod) |
| 重建实例复跑 run-e9458c77e71f1f5f | [12/12](rebuilt/run-e9458c77e71f1f5f/summary.json) | [事件](rebuilt/run-e9458c77e71f1f5f/events.jsonl), [区块及交易校验码](rebuilt/run-e9458c77e71f1f5f/blocks.jsonl) |
| 在线读取修复后同实例复跑 run-56a6e0db16307d89 | [14/14](online-view/run-56a6e0db16307d89/summary.json) | [事件](online-view/run-56a6e0db16307d89/events.jsonl), [区块及交易校验码](online-view/run-56a6e0db16307d89/blocks.jsonl) |
| 在线读取修复后空卷复验 run-8af51ccf8fdde7d7 | [14/14](online-view/run-8af51ccf8fdde7d7/summary.json) | [事件](online-view/run-8af51ccf8fdde7d7/events.jsonl), [区块及交易校验码](online-view/run-8af51ccf8fdde7d7/blocks.jsonl), [链码工具链](online-view/run-8af51ccf8fdde7d7/materials/chaincode-toolchain.log) |
| 部署与检查点恢复修复后空卷复验 run-4641834ccc6a733d | [16/16](recovery/run-4641834ccc6a733d/summary.json) | [事件](recovery/run-4641834ccc6a733d/events.jsonl), [区块及交易校验码](recovery/run-4641834ccc6a733d/blocks.jsonl), [旧日志续跑对照](recovery/legacy-resume.json) |
| 归档前空卷复验 run-9e4d72ad29981721 | [16/16](verification/run-9e4d72ad29981721/summary.json) | [事件](verification/run-9e4d72ad29981721/events.jsonl), [区块及交易校验码](verification/run-9e4d72ad29981721/blocks.jsonl), [停机时历史 h](verification/run-9e4d72ad29981721/supplemental/historical-h.json), [历史 r](verification/run-9e4d72ad29981721/supplemental/historical-r.json), [恢复后在线读取](verification/run-9e4d72ad29981721/supplemental/online-recovered.json) |
| 初始化中断修复后空卷复验 run-41970887f9a83b5d | [16/16](recovery/run-41970887f9a83b5d/summary.json) | [事件](recovery/run-41970887f9a83b5d/events.jsonl), [区块及交易校验码](recovery/run-41970887f9a83b5d/blocks.jsonl) |
| 归档前空卷及边界补测 run-19d92814752d9d32 | [16/16](verification/run-19d92814752d9d32/summary.json) | [事件](verification/run-19d92814752d9d32/events.jsonl), [原块复核](verification/run-19d92814752d9d32/block-audit.log), [初始化专项回归](verification/run-19d92814752d9d32/initialization-regression.log) |
| 部署续跑与凭证期限修复后空卷复验 run-f8d3f2a2bd6db7c7 | [17/17](recovery/run-f8d3f2a2bd6db7c7/summary.json) | [事件](recovery/run-f8d3f2a2bd6db7c7/events.jsonl), [区块](recovery/run-f8d3f2a2bd6db7c7/blocks.jsonl), [根提交后续跑](recovery/run-f8d3f2a2bd6db7c7/initialization/after-committed.log), [旧实例续跑](recovery/run-f8d3f2a2bd6db7c7/initialization/legacy/comparison.json), [凭证边界配对](recovery/run-f8d3f2a2bd6db7c7/credential-boundaries.json) |
| 独立空卷复验及同键重试补测 run-7c3014890c67c66b | [17/17](verification/run-7c3014890c67c66b/summary.json) | [事件](verification/run-7c3014890c67c66b/events.jsonl), [区块](verification/run-7c3014890c67c66b/blocks.jsonl), [首次初始化续跑](verification/run-7c3014890c67c66b/initialization/init-unendorsed-test.log), [根提交后续跑](verification/run-7c3014890c67c66b/initialization/init-committed-test.log), [重试对照](verification/run-7c3014890c67c66b/retry-outage/comparison.json) |
| 同键重试修复后空卷复验 run-bc125193b2161108 | [17/17](recovery/run-bc125193b2161108/summary.json) | [事件](recovery/run-bc125193b2161108/events.jsonl), [区块](recovery/run-bc125193b2161108/blocks.jsonl), [重试复核](recovery/run-bc125193b2161108/retry-audit.log), [旧日志复验](recovery/run-bc125193b2161108/previous-journal/result.log) |
| 初始化中断回归与旧实例续跑 | [专项回归](recovery/initialization-retry/regression.log) | [独立实例原操作和续跑](recovery/initialization-retry/fresh-initialization.json), [旧实例原操作和续跑](recovery/initialization-retry/prior-interruption/initialization.json), [原块复核](recovery/initialization-retry/block-audit.log) |
| 跨部署配对 | [实例对照](comparison/rebuild.json) | [旧夹具拒绝](comparison/old-material.json), [本部署交易](comparison/new-material.json), [原提交块](comparison/new-material-block.pb) |

每个运行目录的 blocks.jsonl 用 raw 指向保留的完整区块 protobuf, 记录块号/哈希/父哈希和交易位置. events.jsonl 记录各判据, 原签名提案/交易及失败阶段, 故障时刻, 探针发送/提交观测/采用与本地单调期限. materials 保存公开创世块, 包含 MSP, consenter 和策略, 另有 Compose, 依赖锁, 引导清单和初始化样本. 两个主验收运行还保存三域原始安装及批准查询结果和链码构建信息. seed.json 保存标记为 synthetic 的应用材料和真实登记结果.

宿主, 容器资源, 工具链和镜像锁见[arm64 运行记录](arm64-environment.log). 四排序身份分别对应 A/B/C/实验运维, 实际同属一个 Docker Desktop 宿主和操作者. [时钟与控制方样本](clock-and-control.log)的时钟采样精度为秒. 提案偏差窗口 2 秒, 校时误差界 1 秒是实验假设. [默认入口读取对照](comparison/default-entrypoints.json)及[离线检查](comparison/checks.log)另存.

## 失败与恢复样本

| 原因 | 记录 |
| --- | --- |
| 排序入口抑制立即重复广播, 同时容器重启后链码尚未可查询 | [run-861130d0ce3b7e0f](original/run-861130d0ce3b7e0f/summary.json) |
| C Peer 停机后自动背书布局首先尝试已停机 Peer, 余下提案超过 2 秒窗口 | [run-c7aea21ab6d14cfb](original/run-c7aea21ab6d14cfb/summary.json) |
| 整网重启后跨域背书发现超过旧验收等待时间 | [run-b394cf9bee291940](original/run-b394cf9bee291940/summary.json) |
| C 已应用登记, A/B 尚未提交到相同高度, 后续提案缺依赖 | [run-e2de08a694924a9b](rebuilt/run-e2de08a694924a9b/summary.json) |
| 空卷首跑的链码定义提交后, 初始化时跨组织背书尚未就绪 | [run-8084e289cf0f578f](clean/run-8084e289cf0f578f/summary.json) |
| 共享视图推进误报 Peer 回退, C 链码连接超时误报部署失配 | [修复前汇总](failures/online-view/run-530750fbf1fd7c28/summary.json), [原始事件](failures/online-view/run-530750fbf1fd7c28/events.jsonl) |
| 原交易重播已入块, 验收仍在等待排序端应答 | [首次空卷汇总](failures/online-view/run-573e012a0b91ad43/summary.json), [区块及交易校验码](failures/online-view/run-573e012a0b91ad43/blocks.jsonl) |
| 验收超时注入 | [失败汇总](failures/timeout/run-ecfd28d9fdf0bed7/summary.json), [退出码](failures/timeout/run-ecfd28d9fdf0bed7/exit-status.json) |
| 在线读取修复后验收超时注入 | [失败汇总](failures/timeout/run-556745e8bfc474de/summary.json), [退出码](failures/timeout/run-556745e8bfc474de/exit-status.json) |
| 部署与检查点恢复修复后验收超时注入 | [失败汇总](failures/timeout/run-9116c85a00109ae0/summary.json), [退出码](failures/timeout/run-9116c85a00109ae0/exit-status.json) |
| 首次初始化保存原提案后退出, 原提案过期且固定操作键无法续跑 | [续跑前操作日志](failures/initialization/5cecee150e9b6691/journal-before.json), [首次续跑](failures/initialization/5cecee150e9b6691/first-retry.log), [再次续跑](failures/initialization/5cecee150e9b6691/second-retry.log), [原交易查询](failures/initialization/5cecee150e9b6691/original-tx-read.log) |
| 根已提交, 重复初始化负例保存提案后退出, 普通和显式续跑均无法生成部署清单 | [中断前操作](failures/initialization/repeat-0a2fa6e60975c7cd/journal-before.json), [续跑结果](failures/initialization/repeat-0a2fa6e60975c7cd/journal-after.json), [根记录原块](failures/initialization/repeat-0a2fa6e60975c7cd/approved-block.pb) |
| IA 登记的凭证锚超过 T 域认证截止一小时, 交易仍有效提交 | [配对交易](verification/run-19d92814752d9d32/supplemental/credential-expiry.json), [越界原块](verification/run-19d92814752d9d32/supplemental/blocks/76.pb) |
| 归档前复验超时注入 | [失败汇总](failures/timeout/run-e4489cc509abed4d/summary.json), [退出码](failures/timeout/run-e4489cc509abed4d/exit-status.json) |
| C Peer 停机时 `invoke` 同键重试先返回连接失败 | [原受理结果](verification/run-7c3014890c67c66b/retry-outage/accepted.json), [退出码](verification/run-7c3014890c67c66b/retry-outage/exit-status.log), [停机时查原操作](verification/run-7c3014890c67c66b/retry-outage/query.json), [恢复后的原提交块](verification/run-7c3014890c67c66b/retry-outage/recovered-block.pb) |
| 修复前 D0 同键重试回归失败 | [汇总](failures/invoke-retry/run-11aed7f325b19af7/summary.json), [重试原始事件](failures/invoke-retry/run-11aed7f325b19af7/retry-events.jsonl), [原输入](failures/invoke-retry/run-11aed7f325b19af7/invoke-retry-original.json), [变更输入](failures/invoke-retry/run-11aed7f325b19af7/invoke-retry-changed.json) |
