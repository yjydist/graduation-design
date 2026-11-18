# 设计

## 背景

[实验计划](../../../../docs/experiments/实验计划.md#1-实验地图与同语义对照)定义了三组状态与缓存对照. 当前网关从 `StateSource` 取得快照, 但在业务事务内直接查询 `fabric_head` 并复核 Fabric 探针. 决策表也要求填写 Fabric 字段. 只替换快照读取端无法完成 C0 定案. 现有 M2 闭环已提供真实 RP/BM 材料和钱包工具. M3 提供了通过网关配置开启的静态验签缓存.

## 目标与边界

- 用同一条网关业务路径执行 C0, B0, B1, 对比状态来源及静态验签复用两个因素. 使用可独立校验的主库记录核对行为等价.
- 首轮使用确定性钱包工具和实际时钟, 为后续正式实验提供夹具和输出契约. 正式 E1/E3 保留真实 LLM 驱动, 首轮结果用于验收接线与业务语义.

## 决策

### 1 状态来源只接管快照和锁后状态复核

| 配置 | 初验视图 | 在业务行锁之后复核 | 静态验签缓存 |
| --- | --- | --- | --- |
| C0 | 从独立中心化主库的只读 `REPEATABLE READ` 事务读取 `revision`, 实际读取时点及完整登记记录 | 在同一业务事务中对中心化版本行加共享锁, 比对初验 `revision` | 关 |
| B0 | 现有 Fabric 固定高度快照, 每次装配全部依赖 | 同事务共享锁定 `fabric_head`, 比对块高/哈希, 并检查本进程原探针 | 关 |
| B1 | 与 B0 同一个 Fabric 部署和已应用视图, 每次装配全部依赖 | 同 B0, 使用自身实例的原探针 | 每个实验网关新建缓存, 仅在该轮内复用静态验签 |

C0 受信预置器使用与 Fabric 相同的夹具登记输入和真实签名材料, 将 T 根, 域, 域认证, 身份, 凭证锚, 任务及委托路径写入独立 PostgreSQL 主库. 初始记录和 `revision=1` 原子提交. 后续登记状态变动与版本递增同事务提交, 写入端先锁版本行. C0 在准备完成后只依赖本地主库, 受控 DID 解析及已核验交付材料. 三组实际核对相同身份及委托材料. C0 不调用 Fabric 查询, 块流或探针, 也不以 `fabric_current` 或假探针模拟中心化主库.

将锁定和比对状态来源的动作放在现有网关业务事务的相同位置, 让各来源提供检查点和对应的新鲜度元数据. 检查点不匹配时回滚并整次重验, 上限耗尽按现有 `409 STATE_CHANGED` 处理. 三组共用挑战绑定, 协议验签与资格校验, 报价核对, 当前风险, 锁后时钟和 OPA, 业务键及原子写入逻辑. C0 记录快照读取时点与共同业务有效截止. B0/B1 仍另外受原探针期限约束, 默认每秒发送探针且 `deltaState=5s`. B0/B1 均记录请求实际使用的块高和探针, 因实时探针推进可以观测到不同块高.

决策记录按来源保存实际元数据. C0 写入 `revision` 和读取时点, 区块及探针列允许 `NULL`; Fabric 记录实际区块及探针, 保留原字段语义. Fabric 历史审计继续使用原区块与探针. 首轮 C0 证据通过 `revision`, 请求, 决策和主库核对关联.

新订单在锁后依次核对报价归属, 期限, 请求金额及委托路径额度. 超额先以 `AMOUNT_LIMIT_EXCEEDED` 定案. 通过前置检查的请求使用锁住的风险上下文执行最终 OPA 求值.

### 2 冻结夹具与策略

| 控制项 | 首轮规则 |
| --- | --- |
| 身份与材料 | 使用 T 对 IA/IB/IC 的三域认证, U 和 A1/B1 的合法身份凭证及 PA/C 服务资格. 在同一轮内共用一个 T 根, 相同部署绑定, 同一套真实 ES256/SD-JWT 凭证与签名委托, 通过受控 DID 解析核验. 使用最小必要披露 `domain` 和 `role` |
| 根与路径 | RP 用 C 签发 G0, BM 用合法 PA 签发 G0. 每种根使用独立任务及 `G0 -> G1 -> G2`, 经 `U -> A1 -> B1` 逐跳交付. 金额上限依次为 `500000/500000/100000` 分, 剩余深度 `2/1/0`, 路径状态均有效 |
| 商品, 请求及报价 | C 的 `urn:grad:product:P1`, 每次 `quantity=1`, CNY. 两档目录单价分别为 `80000/120000` 分. 串行设置价格并确认写入后, 经真实 `quote.read` 取得 Q800 或 Q1200, 再用原价和报价 ID 下单 |
| 策略与风险 | 复用固定源码的 OPA 默认采购策略包与版本 `1.0.0`, 固定信任根及 C 资源配置, 允许 RP/BM 和 A 域买方, P1, 询价及下单. 三组同轮使用相同策略文件和经校验的包摘要, 保存策略内容摘要及绑定部署后的实际摘要. 每个用例开始前通过可信观测器提交有效 `NORMAL` 上下文, 记录实际版本, 观察时点及截止 |
| 时钟与期限 | 复用 `seed` 有效期和网关挑战, 报价期限规则. 同轮以同一套实际签发时间及有效区间装配三组. 可选策略截止在同轮一致, 首轮采用同一轮 RP/BM 任务截止的较早值. 各用例开始前检查材料与上下文仍有效. 按当前网关真实时钟定案 |
| 配对种子 | 固定 `1109, 1110, 1111, 1112, 1113`. 与现有重复实验计划一致. 首轮及干净环境复跑固定 `1109`; 入口接受该集合中的种子. 种子及用例标签用于生成逻辑夹具标识和配对 ID, 按 C0/B0/B1, RP/BM, 800/1200 顺序执行 |

将可公开的逻辑夹具描述作为固定输入纳入版本控制. 对种子, 逻辑角色与路径, 商品与价格, 期望判据, 披露与期限规则, 策略配置和策略源码摘要计算 JCS/SHA-256 摘要. 同轮将签好的同一套材料与锚点分别装入两种登记来源, 核对实际公共材料摘要一致. 干净重建时按同一规则生成新的密钥, 签名, 随机挑战和真实时间, 清单分别记录实际部署及公开材料摘要. 配对种子只影响逻辑标识和用例, 密钥, 盐及 nonce 使用原有密码学随机源.

采购开始前, 从 C0 主库读取已提交的登记快照和 `revision`, 并将已提交的 Fabric 区块按顺序应用到视图后读取该视图. 两种来源分别在各自的只读 `REPEATABLE READ` 事务中读取检查点和登记值. 比对 T 根及夹具中的域, 域认证, 身份, 凭证, 任务和委托记录. 按记录种类和 ID 索引登记字段, 保留状态, 密钥版本和签名锚点, 提取对象的 `revision` 单独记录, 对剩余字段分别计算 JCS/SHA-256 摘要. 两边均已读出才报告比对结果. 缺失记录, 无效版本或锚点不同均使准备阶段失败, 保存已读出的回读元数据和完整请求计划.

### 3 运行与首轮验收

增加 `ledgerctl experiment baseline` 入口, 明确输入独立实验实例, 配对种子和新证据目录. 复用 `fabric:up` 与部署, 种子, 交付及真实钱包工具. 每轮使用独立 Fabric 实例和 C0 主库. C0 由实验入口显式启用, 使用自己的挑战, 其登记与业务表位于同一个独立主库, 供定案事务同时持有业务锁和版本锁. B0/B1 顺序运行, 共用同一 Fabric 状态视图, 每组等待自己的有效探针. 三组各用新的钱包意图及不同业务键命名空间, 按运行与用例的订单键核对, 避免将前一组业务结果或缓存计入本组.

执行 3 组 x 2 种根 x 2 档金额. 每个用例先询价再下单, 两个动作各申请新挑战, 使用 B1 主体的钱包签发绑定当前请求的持有者证明. 将真实下单金额固定为报价总额. 每个动作计入计划及实际执行结果. 单个请求失败后保留原样本, 依赖它的未执行请求标记原因. 实验驱动不以补发替换失败请求, 网关内部有界重验照常执行并记录.

验收以 HTTP 响应与主库两者为准. 800 元应新增一笔匹配报价的 `CREATED` 订单, 一条允许决定和一个已完成订单键. 1200 元应提交一条 `AMOUNT_LIMIT_EXCEEDED` 拒绝决定, 实际订单行和目标订单键均不存在. 两种结果均核对挑战与决定的关联. 每轮应有 12 次成功询价, 6 次允许下单和 6 次预期超额拒绝. 按 `(种子, 授权模式, 金额)` 比较三组的响应码, 业务结果和主库副作用. 核对 B1 在首个重复使用的签名材料上出现缓存命中, C0/B0 的计数始终为零. 只比较规范化后的业务事实与预期, 并保留每轮的实际状态, 随机 ID 和时点.

B0/B1 的每个动作都须提供实际块高, SHA-256 块哈希, 原探针交易 ID, 探针所在块和墙钟及单调时点. 原探针所在块不得高于视图块高, 探针墙钟期限须晚于发送时点, 单调核验时点须不早于发送且严格早于原期限.

### 4 原始数据契约

每次运行独占证据目录. JSON 和 CSV 使用 UTF-8, CSV 固定首行列名和列序, 按标准 CSV 规则转义, 以 `null` 表示缺测或不适用值. JSON 可空字段使用 JSON `null`. 绝对时间使用 UTC RFC 3339 格式, 允许小数秒. 单调时间和持续时间以纳秒记录, 用 `_ns` 后缀. 探针单调时点只在同一进程实例内比较. 金额, 计数, 版本和块高使用整数. `case_id` 由种子, 授权模式小写短名和分单位金额经连字符拼接, 如 `1109-rp-80000`. `run_id + configuration + case_id + action` 唯一标识动作, `action` 取 `quote.read` 或 `order.create`.

| 文件 | 首轮结构 |
| --- | --- |
| `manifest.json` | `run_id`, `seed`, `started_at`, `source_commit`, `go_version`, `host`, `clock`, `topology`, `artifact_locks`, `deployment_id`, `channel_id`, `genesis_hash`, `chaincode`, `root`, `fixture_digest`, `material_digest`, `registry_input_digest`, `registry_readback`, `policy_source_digest`, `policy_digest`, `configurations`, `driver`, `planned_cases`. `configurations` 记录每组源类型, 数据库和网关实例标识, 缓存开关与适用的探针参数. `planned_cases` 按执行顺序给出 `configuration`, `case_id`, `mode`, `amount_minor` 和期望响应码 |
| `requests.csv` | `run_id,configuration,case_id,mode,action,actor,task_id,amount_minor,idempotency_key,planned_at,started_at,finished_at,challenge_ns,execute_ns,request_id,request_hash,challenge_id,decision_id,quote_id,order_id,http_status,code,disposition,failure_stage,state_source,revision,state_read_at,block_number,block_hash,probe_tx_id,probe_block,probe_sent_at,probe_deadline,probe_sent_mono_ns,probe_deadline_mono_ns,probe_checked_mono_ns,context_version,context_observed_at,context_access_deadline,decision_at,effective_deadline,state_rechecks,signature_cache_hits,signature_cache_misses` |
| `order_checks.csv` | `run_id,configuration,case_id,task_id,quote_id,idempotency_key,challenge_id,challenge_consumed,decision_id,decision_outcome,decision_code,quote_amount_minor,order_rows_before,order_rows_after,order_key_rows,order_key_status,order_id,creation_decision_id,order_status,verdict,failure_reason` |
| `summary.json` | `run_id`, `seed`, `passed`, `by_configuration_and_mode`, `case_results`, `pair_results`, `request_accounting`, `failures`. `case_results` 和 `pair_results` 按矩阵键列出期望, 实际及核验结果. `failures` 记录作用范围, 失败阶段, 可用的关联 ID 和脱敏原因 |

`requests.csv` 每个计划动作恰有一行, 以 `allowed`, `denied`, `error`, `timeout`, `dropped` 表示实际结果. 未启动的计划动作为 `dropped`, 并标明原因. 汇总按 `planned = started + dropped`, `started = completed + timeout`, `completed = allowed + denied + error` 对账. 预期 `denied` 在用例汇总可判为通过. 未返回或未观察到的响应, 决定或时点用 `null`. B0/B1 的中心化字段以及 C0 的 Fabric 字段用 `null`. `order_checks.csv` 每个计划订单一行, 按数据库, 部署和任务统计前后订单行数, 按该次业务键查对应订单键和业务结果. 主库查询失败时保留查询失败原因和可读取的部分, 不推断不存在. 准备阶段失败也保存已知清单信息, 计划用例和汇总. 对外导出只含白名单字段, 摘要及经脱敏的错误信息.

`registry_input_digest` 是 C0 预置输入的 JCS/SHA-256 摘要. `registry_readback.c0` 和 `registry_readback.fabric` 分别保存实际计算的 `anchor_digest` 和按种类及 ID 索引的 `object_revisions`. C0 另记录 `revision` 和 `state_read_at`, Fabric 另记录 `block_number` 和 `block_hash`. `registry_readback.matched` 记录两份回读摘要的比对结果. 无法完成回读时, 未读取的来源及比对结果为 `null`, 汇总记录 `registry-readback` 失败阶段.

挑战接口返回非 201 时, `requests.csv` 和 `summary.json` 的失败记录均保留 `challenge` 阶段及已观测的 HTTP 状态, 错误码和请求 ID. 该动作以 `error` 对账, 请求超过期限时以 `timeout` 对账. 询价挑战失败后, 对应的订单动作为 `dropped`, 阶段为 `quote-dependency`. 订单自身的挑战失败时, 主库核对只保留已知信息和失败原因.

执行接口返回 503 时, 两份记录保留 `execute` 阶段以及已观测的 HTTP 状态, 错误码, 请求 ID 和挑战 ID. 有决定 ID 时核对主库决定, 缺少决定 ID 时该字段为 `null`, 订单核对仍保留可读取的订单和业务键计数. 询价执行失败后, 对应的订单动作为 `dropped`, 阶段为 `quote-dependency`.

## 风险与取舍

- 中心化读写之间的竞态会改变授权. 用业务事务中的版本锁和完整重验兜住变更, 以确定性并发测试覆盖锁等待期间的版本推进.
- 同轮复用签名材料有助于比较缓存, 逐轮重建仍会生成不同的实际部署与时钟数据. 固定逻辑夹具摘要, 每轮保存实测指纹和时点.
- 单一目录价格变动会串扰并发请求. 首轮串行切换并读取校验, 按业务键隔离统计. 正式负载的夹具及采样沿用实验计划的后续要求.

## 部署与兼容

中心化预置与实验入口仅对显式选择的独立数据库和实验实例运行. 若需要扩展决策表, 保留旧 Fabric 行的块与探针语义, 为已有实例提供可重复执行的迁移, 并验证现有 Fabric 读取和历史复查仍可使用旧记录. 实验失败后保留该轮证据, 下一次从新的独立实例与证据目录启动.
