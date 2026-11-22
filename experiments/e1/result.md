# E1 采购功能闭环实验结果

**状态.** 重构前的旧批次运行产物 (`runs/`, `analysis/`, `source-archive/`) 已在 `rebuild-monorepo-architecture` 期间清理. 正式 E1 批次待在新 4 模块工作区架构下通过统一 `exp` CLI 重新执行后按实际运行 ID 填充本报告. [E1 方法](method.md), [独立驱动说明](README.md), [F01-F16 判据](../验证用例.md#1-采购闭环).

## 1 实验范围与配置

本实验在独立重建的三域 Fabric 网络上验证 F01-F16 共 16 项功能用例, 核对共同身份根下 RP (`RESOURCE_PREAUTHORIZED`) 与 BM (`BUYER_MANDATE`) 两种采购根均可独立完成采购闭环.

- 采用 B0 配置, 由 C 在每次请求装配 Fabric 一致视图并使用本地探针, 关闭跨请求静态验签缓存. 每轮的部署标识, 创世块哈希, 链码包标识, 二进制摘要及驱动源码指纹记录在 `runs/<run-id>/manifest.json`.
- 通过真实 LLM 与 MCP 工具完成主闭环与超额负例调用. A1 读取已交付的 G1 后签发并逐跳交付 G2, B1 对独立的 RP/BM 任务发起询价与下单. F15 换钥后再由 A1 签发叶子委托. 初始化, 负例注入, 定案核对及历史复验由实验驱动执行.
- 采用合成商品和人民币金额, 5000 元的 G0/G1 收缩为 1000 元的 G2, 深度为 2/1/0. 模型选择与接口地址见[实验用 LLM 配置](../README.md#实验用-llm-配置).

## 2 运行批次

待新 4 模块架构下完成固定提交正式复跑后按实际 `<run-id>` 填入:

| 运行 ID | 固定提交 | 实际模型 | F01-F16 通过数 | 模型会话 / 工具调用 | 记录的网关请求 | 原始记录路径 |
| --- | --- | --- | --- | --- | --- | --- |
| `<run-id>` (待补跑) | `<revision>` | 待记录 | 待填 (`/16`) | 待填 | 待填 | `runs/<run-id>/{manifest.json,summary.json,llm-traces.json,requests.csv,audit.json}` |

运行完成后, 应核对两轮独立隔离实例的输入指纹一致且部署标识与创世块哈希独立; 通过 `requests.csv` 的 `challenge_id`, `decision_id`, `quote_id` 和 `order_id` 关联 `db-*.json`, 并通过块高, 块哈希与探针交易 ID 关联 `blocks.jsonl` 及原始区块.

## 3 实测结果骨架

以下采购结果对账表与 F01-F16 核验表待正式批次完成后按源运行 ID 填充:

| 采购结果 | RP | BM | 预期业务影响 |
| --- | --- | --- | --- |
| F06 使用 Q800 提交 800 元 | 待填 (`200 ALLOW`) | 待填 (`200 ALLOW`) | 每笔各 1 条报价和 1 笔唯一订单 |
| F07 使用 Q1200 改报 800 元 | 待填 (`409 AMOUNT_MISMATCH`) | 待填 (`409 AMOUNT_MISMATCH`) | 0 笔新订单, 0 条订单业务键 |
| F07 使用 Q1200 提交 1200 元 | 待填 (`403 AMOUNT_LIMIT_EXCEEDED`) | 待填 (`403 AMOUNT_LIMIT_EXCEEDED`) | 0 笔新订单, 0 条订单业务键 |
| F08 丢弃首个响应后以新挑战重试 | 待填 (返回原订单 ID) | 待填 (返回原订单 ID) | 原提交与重试合计仅创建 1 笔订单 |

| 用例 | 核验项与待填结果 |
| --- | --- |
| F01 | T 根与三域部署核验, `PENDING` 域登记拒绝及认证后登记通过, A 域 PA 采购资格核验 (待补跑) |
| F02 | 双方应用密钥 PoP 关联提案, 单方 `PENDING`, 双方审批后 `effectiveActive=true` 与关联账号隔离 (待补跑) |
| F03 | PA, U, A1, B1, C 凭证锚点确认前后状态对照与缺失锚点 `CREDENTIAL_STATUS_INVALID` 拒绝 (待补跑) |
| F04 | T 对 A/B/C 的认证签名, IA/IB/IC 资格与用途绑定核验 (待补跑) |
| F05 | 两种根由模型选择 1000 元上限与深度 0, A1 签发 G2 落链 `VALID` 并交付 B1 (待补跑) |
| F06 | 真实模型完成 RP/BM 的 Q800 询价与下单, 复算 F06 区间区块仅含探针写入 (待补跑) |
| F07 | 真实模型提交 Q1200 改报 800 元与 1200 元超额两类负例, 主库零订单副作用 (待补跑) |
| F08 | 丢弃首个下单响应后以同幂等键和新挑战重试, 返回原订单 ID 且仅 1 笔订单 (待补跑) |
| F09 | 逐模式复读允许决定并核对 T 根, 身份, 任务, G0/G1/G2 路径, 视图高度, 块哈希, 策略与原探针 (待补跑) |
| F10 | BM 路径无 C 签发根, C 准入策略独立放行下单 (待补跑) |
| F11 | C 策略收紧时 RP/BM 均收到 `SUPPLIER_POLICY_DENIED` 且零新订单, 恢复后同一根放行 (待补跑) |
| F12 | 未锚定 DID 文档拒绝, 换回匹配文档通过, 断言用途密钥用于认证拒绝 (待补跑) |
| F13 | 请求与任务模式交叉返回 `AUTHORIZATION_MODE_MISMATCH`, PA 签发 RP 根拒绝且无落链 (待补跑) |
| F14 | 验证端隔离 T 的 DID 路由仍放行, 短期 B 域认证到期后返回 `403 DOMAIN_CERTIFICATION_INVALID` (待补跑) |
| F15 | T 同钥续发复用原凭证与委托, IB 换钥后旧 B1 凭证以 `KEY_VERSION_STALE` 拒绝, 重签后恢复 (待补跑) |
| F16 | KB-JWT `evidenceHash`, 钱包中间字节复算与网关历史验证一致, 篡改或乱序触发拒绝 (待补跑) |

## 4 失败轮次与结论边界

新架构复跑期间如出现模型代理异常, 环境故障或用例失败, 按原运行 ID 保留只读原始目录并登记下表:

| 失败运行 ID | 首个受阻阶段 | 原因与处理 | 原始记录路径 |
| --- | --- | --- | --- |
| 待记录 | 待记录 | 失败样本与缺测诊断保留原字节, 修复后使用新构建与新运行 ID 复跑 | `runs/<failed-run-id>/{manifest.json,summary.json,llm-traces.json}` |

结论边界约定: F06/F07 模型轨迹计时仅作工具调用闭环记录, 验签, 视图装配与缓存开销以 E4-E8 独立测量为准.

## 5 离线复算与来源引用

正式批次完成后, 在脱离 Fabric, PostgreSQL 和模型服务的离线环境下执行只读复算:

```bash
mise -C experiments run experiment:run -- --experiment E1 \
  --revision <revision> \
  --instance .local/fabric-e1-run \
  --port 19100

mise -C experiments run experiment:analyze -- --experiment E1 \
  --run-dir experiments/e1/runs/<run-id> \
  --out experiments/e1/analysis/<run-id>
```

| 源运行 ID | 分析版本 | 离线复算结论 | 关键计数 | 原始与派生路径 |
| --- | --- | --- | --- | --- |
| `<run-id>` (待补跑) | `e1-analyzer/v1` | 待填 (`PASS` / `FAIL`) | 待填 | 原始: `runs/<run-id>/`; 派生: `analysis/<run-id>/{recomputed.json,recomputed-table.md}` |

复算须核对同一输入重复运行产出逐字节一致的 `recomputed.json`, 且复算前后 `runs/<run-id>/` 内全部原始文件的 SHA-256 摘要保持不变.
