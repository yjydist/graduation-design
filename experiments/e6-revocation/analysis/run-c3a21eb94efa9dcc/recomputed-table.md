# E6 撤销窗口离线复算结果 (run-c3a21eb94efa9dcc)

- 分析版本: `e6-analyzer/v1`
- 源运行 ID: `run-c3a21eb94efa9dcc`
- 原始运行目录: `experiments/e6-revocation/runs/run-c3a21eb94efa9dcc`
- 根模式 / 验证配置: `RESOURCE_PREAUTHORIZED` / `B0`
- 撤销目标 G1: `66c1cdf05a2a69052605fb76731a17b6d3565601ae282d68a496b9294c2d625d`
- 撤销原交易 txID / 块 r: `5c534b5f15a850766d0cf1790191335bff218bedd0d2083c5087b5f67f6e362c` / `46`
- 复算判定: `passed=true` (违规放行 0, 旧块定案后延迟响应 0, 时间精度不足 0)

## 实例阶段耗时与窗口汇总

| 实例 | 探针角色 | `t_valid-t_submit` (ms) | `t_apply-t_valid` (ms) | `t_adopt-t_apply` (ms) | 确认后窗口 (ms) | 相对提交窗口 (ms) | 窗口状态 | 违规放行 | 计划/完成/漏探测/超时 | 时钟分辨率 (ns) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `gw-1` | `probe1` | 93.342 | 2.395 | 10.638 | null | 85.845 | `post_valid_allow_unobserved` | 0 | 553/552/1/0 | 1000 |
| `gw-2` | `probe2` | 93.342 | 2.395 | 10.301 | null | 83.104 | `post_valid_allow_unobserved` | 0 | 553/552/1/0 | 1000 |

## 样本对账与删失说明

- 预热样本: 2, 计划探测: 1106, 启动: 1104, 完成: 1104, 漏探测: 2, 超时: 0, 允许: 108, 拒绝: 994, 错误: 2
- `gw-1` 删失/缺测备注: `post_valid_allow_unobserved, missed_probes:1`
- `gw-1` 首次拒绝观测: `code=ANCESTOR_INACTIVE`, `source=responded_at_ns`, `unobserved_reason=precheck_deny_no_decision_row`
- `gw-2` 删失/缺测备注: `post_valid_allow_unobserved, missed_probes:1`
- `gw-2` 首次拒绝观测: `code=ANCESTOR_INACTIVE`, `source=responded_at_ns`, `unobserved_reason=precheck_deny_no_decision_row`

## 原始输入文件摘要 (SHA-256)

| 原始文件 | SHA-256 |
| --- | --- |
| `manifest.json` | `ea9763d622cd6c7462aaa61b54fc6705cedde0ab3975a289f61e21e19fe45d0e` |
| `requests.csv` | `57c9f1962b3ef918f213a47fe7a7484fc821d51101fbe1a058c17946f97a5868` |
| `revocations.csv` | `ac77070115cbdd7c4a129cb649315f5df476b641425b56f4c6354196e9118781` |
| `summary.json` | `c9791752fa3224e5c95dbf9958aed95ef4b8385e0ee35df227d023602a6993db` |
