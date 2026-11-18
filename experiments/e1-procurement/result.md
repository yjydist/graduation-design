# E1 采购功能闭环实验结果

## 1 实验范围与配置

迁移前的四轮实验中, 两个独立重建的三域 Fabric 网络通过 F01-F16 共 16 项, RP (`RESOURCE_PREAUTHORIZED`) 与 BM (`BUYER_MANDATE`) 均完成采购闭环. 四轮原始记录与各自的源码一并保留. 驱动迁移后的固定构建验证见第 5 节. [E1 方法](../../docs/experiments/E1-采购功能闭环.md), [F01-F16 判据](../../docs/experiments/验证用例.md#1-采购闭环), [旧批次源码归档](source-archive/README.md).

- 采用 B0, 由 C 在每次请求装配 Fabric 一致视图并使用本地探针, 关闭跨请求静态验签缓存. 每轮的部署标识, 创世块, 链码包标识及源码指纹见运行清单.
- 通过 Anthropic SDK 和本地模型代理调用 `deepseek-flash`. A1 读取 G1 后签发并逐跳交付 G2, B1 对独立的 RP/BM 任务发起询价与下单. 两个钱包各从已交付的 G1 装入父路径, 实验用 G2 在运行中由 A1 创建. F15 换钥后再由 A1 签发叶子委托.
- 采用合成商品和人民币金额, 5000 元的 G0/G1 收缩为 1000 元的 G2, 深度为 2/1/0. 主闭环与超额负例由模型通过 MCP 工具发起. 初始化, 负例注入, 定案核对及历史复验由实验驱动执行.

## 2 运行批次

| 运行 ID | F01-F16 通过数 | 模型会话 / 工具调用 | 记录的网关请求 | 原始记录 |
| --- | --- | --- | --- | --- |
| `run-e9278cc882927ca1` | 16/16 | 8 / 18 | 76 | [清单](runs/run-e9278cc882927ca1/manifest.json), [汇总](runs/run-e9278cc882927ca1/summary.json), [模型轨迹](runs/run-e9278cc882927ca1/llm-traces.json), [请求](runs/run-e9278cc882927ca1/requests.csv), [交叉复算](runs/run-e9278cc882927ca1/audit.json) |
| `run-471362d68defc766` | 16/16 | 8 / 18 | 76 | [清单](runs/run-471362d68defc766/manifest.json), [汇总](runs/run-471362d68defc766/summary.json), [模型轨迹](runs/run-471362d68defc766/llm-traces.json), [请求](runs/run-471362d68defc766/requests.csv), [交叉复算](runs/run-471362d68defc766/audit.json) |

两轮的源码与输入指纹一致, Fabric 实例标识, 创世块哈希和部署标识均不同. 每轮记录 11 条报价, 8 笔模拟订单和 28 条决定, 包含下表中的功能和配对控制. `requests.csv` 用 `challenge_id`, `decision_id`, `quote_id` 和 `order_id` 连接 `db-*.json`, 用决定的块高, 块哈希和探针交易 ID 连接 `blocks.jsonl` 及原始块. 另从主库导出挑战和业务键, 验证 F06/F07 决定使用的探针在有效期内, 并核对拒绝请求的业务副作用. [首轮主库决定](runs/run-e9278cc882927ca1/db-decisions.json), [次轮主库决定](runs/run-471362d68defc766/db-decisions.json).

## 3 实测结果

下表和采购结果汇总均来自 `run-e9278cc882927ca1` 与 `run-471362d68defc766`. 每项在两轮各核验一次, 两种根适用的用例按 RP/BM 分开执行. 各轮目录中的 `Fxx*.json` 和 `events.jsonl` 保存相应观测.

| 采购结果 | RP | BM | 业务影响 |
| --- | --- | --- | --- |
| F06 使用 Q800 提交 800 元 | 2 次 `200 ALLOW` | 2 次 `200 ALLOW` | 每笔各 1 条报价和 1 笔订单. 每个闭环记录 4 次网关 HTTP 请求 |
| F07 使用 Q1200 改报 800 元 | 2 次 `409 AMOUNT_MISMATCH` | 2 次 `409 AMOUNT_MISMATCH` | 0 笔新订单, 0 条订单业务键 |
| F07 使用 Q1200 提交 1200 元 | 2 次 `403 AMOUNT_LIMIT_EXCEEDED` | 2 次 `403 AMOUNT_LIMIT_EXCEEDED` | 0 笔新订单, 0 条订单业务键 |
| F08 丢弃首个响应后以新挑战重试 | 2 次返回原订单 ID | 2 次返回原订单 ID | 每次原提交和重试合计只创建 1 笔订单 |

| 用例 | 核验结果 |
| --- | --- |
| F01 | 从三域部署及 Peer `VALID` 记录核对 T 根. A/B/C 处于 `PENDING` 时提交身份登记均被拒绝, 认证后正常登记. 另核对 A 域 PA 采购资格 |
| F02 | 双方应用密钥 PoP 对应同一关联提案摘要. 单方后为 `PENDING`, 双方审批后 `effectiveActive=true`, 关联账号单独访问原采购权限被拒绝 |
| F03 | PA, U, A1, B1 和 C 的凭证在各自确认块前无登记锚点, 确认后为 `ACTIVE` 且摘要一致. 针对完整出示包隔离缺失的 B1 锚点时, 验证返回 `CREDENTIAL_STATUS_INVALID` |
| F04 | T 对 A/B/C 的认证签名及 IA/IB/IC 的资格与链上锚点一致. 验证域内身份, C 服务身份及用途绑定 |
| F05 | 两种根都从已交付的 G1 起步, 模型选择 1000 元上限和深度 0, A1 签发 G2 后 Fabric 返回 `VALID`, 并记录 B1 收件摘要 |
| F06 | 真实模型完成两种根的 Q800 询价及下单, 请求关联到主库决定. 复算首末 F06 决定之间采纳的块, 新写入键均为探针键 |
| F07 | 真实模型取得 Q1200 并提交两种负例, 分别命中报价金额不一致和委托额度超限. 四次负例每轮均无订单副作用 |
| F08 | 驱动丢弃正常下单响应, 以同一幂等键和新挑战重新出示. 响应返回原订单 ID, 主库只增加一笔订单 |
| F09 | 逐模式复读允许决定, 核对 T 根, B1 身份, 任务, G0/G1/G2 路径, 视图高度, 块哈希, 策略和原探针 |
| F10 | BM 的三份委托分别由 PA, U, A1 签发, 所属任务查得 0 个 C 签发的根, C 策略独立允许下单 |
| F11 | 按模式限制 C 的准入策略, 有效的 RP/BM 根都收到 `SUPPLIER_POLICY_DENIED`, 新订单数为 0. 恢复允许策略后同一根可下单 |
| F12 | 为 B1 提供同 DID 的未锚定文档时拒绝访问, 换回匹配文档后询价成功. 另核验断言用途密钥用于认证时被拒绝 |
| F13 | 请求模式和任务模式交叉配置, 两种根均收到 `AUTHORIZATION_MODE_MISMATCH`. PA 签发用于 RP 的根提交被拒绝, 无落链记录 |
| F14 | 在验证端隔离 T 的 DID 路由后, RP/BM 仍分别成功下单. 短期 B 域认证到期后均收到 `403 DOMAIN_CERTIFICATION_INVALID`, 主库订单数不变 |
| F15 | T 同钥同范围续发后, 旧认证被拒绝, 换用新认证即可使用原凭证和委托. IB 换钥并重新认证后旧 B1 凭证以 `KEY_VERSION_STALE` 拒绝. 按新认证有效期重签 B1 凭证及两种模式的叶子委托, 两方重新询价成功 |
| F16 | 原始 KB-JWT 中的 `evidenceHash`, 钱包侧中间字节复算及网关侧历史验证结果三者一致. 改动认证签名字节改变摘要并被拒绝, 颠倒 `trustPaths` 顺序触发结构校验拒绝 |

## 4 失败轮次与结论边界

| 运行 ID | 汇总 | 观测及处理 |
| --- | --- | --- |
| `run-8f53b15eb6cfc887` | [4/16](runs/run-8f53b15eb6cfc887/summary.json) | 模型已完成 BM 的主闭环和超额负例. RP 钱包误把 C 的服务凭证文件限定为 `C-service.sdjwt`, 实例实际登记在 `C.sdjwt`. 按根委托引用的凭证 ID 选择正确材料后复跑 |
| `run-584097e92389b59c` | [15/16](runs/run-584097e92389b59c/summary.json) | RP/BM 主闭环均通过. F15 中旧的凭证起始时间超出新 B 域认证范围, 新凭证注册在背书阶段被 `INVALID_STRUCTURE` 拒绝. 按新域认证区间收缩凭证时效后独立复跑 |

两个通过批次支持 B0 配置下两种采购根的功能结论. F07 的模型提示明确要求提交负例, 结果用于判断服务端是否强制执行报价和额度. F14 通过实验环境中的 T 路由隔离验证本地根预置行为. 模型轨迹的计时为工具调用闭环的记录, 状态提供与缓存开销按 E4-E8 的独立测量判定.

## 5 固定构建复跑

独立驱动使用提交 `79125cc40855014c16fcfb0a962bc276202023d8`, 分别构建 `ledgerctl` 和实验程序. 网关通过现有 Go 接口装配. 新批次使用原有 `ledgerctl check` 生成探针, 将实际交易及原期限交给网关. 可按块高及挑战 ID 交叉核对原始区块和主库决定. [独立驱动](README.md).

| 运行 ID | 实际模型 | 观测 |
| --- | --- | --- |
| `run-f6b3cc4a627e1a49` | `openai / deepseek-v4.1-flash` | F01-F04 通过. 两种根的 F05 首次模型请求均收到上游余额不足, 后续闭环缺少模型签发的 G2. [清单](runs/run-f6b3cc4a627e1a49/manifest.json), [汇总](runs/run-f6b3cc4a627e1a49/summary.json), [模型调用记录](runs/run-f6b3cc4a627e1a49/llm-traces.json), [该轮驱动源码](runs/run-f6b3cc4a627e1a49/driver-source.tar.gz) |
| `run-8e823c1f2d3bc13a` | `openai / deepseek-v4.1-flash` | F01-F04 通过. F05 代理返回 `model_not_found`, 配置的模型未列在代理目录. F06/F07 检测到缺少 F05 签发的 G2 后结束. [清单](runs/run-8e823c1f2d3bc13a/manifest.json), [汇总](runs/run-8e823c1f2d3bc13a/summary.json), [模型调用记录](runs/run-8e823c1f2d3bc13a/llm-traces.json), [该轮驱动源码](runs/run-8e823c1f2d3bc13a/driver-source.tar.gz) |
| `run-3f8a7a6db26d582c` | `openai / deepseek-flash` | F01-F16 全部通过. 8 个真实模型会话, 19 次工具调用, 78 次网关请求. [清单](runs/run-3f8a7a6db26d582c/manifest.json), [汇总](runs/run-3f8a7a6db26d582c/summary.json), [模型轨迹](runs/run-3f8a7a6db26d582c/llm-traces.json), [请求](runs/run-3f8a7a6db26d582c/requests.csv), [交叉复算](runs/run-3f8a7a6db26d582c/audit.json), [该轮驱动源码](runs/run-3f8a7a6db26d582c/driver-source.tar.gz) |

迁移诊断用脚本发送 MCP 工具调用, 在固定构建实机环境通过 F01-F16. 正式通过批次 `run-3f8a7a6db26d582c` 在 RP/BM 分别创建一笔 800 元订单, 1200 元原价及改报 800 元的四次负例均无订单和订单业务键. 核对 F06/F07 的决定关联到已消费的挑战和原探针交易, 定案时点落在原探针有效期内. [交叉复算](runs/run-3f8a7a6db26d582c/audit.json).

启动 Docker, 通过环境提供 `LLM_API_KEY`, 为每轮选择新的实例目录及端口. 模型与接口地址见[实验用 LLM 配置](../README.md#实验用-llm-配置).

```bash
bash experiments/e1-procurement/run.sh 79125cc40855014c16fcfb0a962bc276202023d8 \
  .local/fabric-e1-rerun 19100
```

脚本自动部署并登记实验材料, 为每次尝试分配新的运行 ID. 运行清单记录固定提交, 二进制摘要, 驱动源码摘要, 模型标识和实际 API 地址.
