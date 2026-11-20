# E6 撤销窗口离线复算结果 (run-86facf71a9d07b81)

- 分析版本: `e6-analyzer/v1`
- 源运行 ID: `run-86facf71a9d07b81`
- 原始运行目录: `experiments/e6-revocation/runs/run-86facf71a9d07b81`
- 根模式 / 验证配置: `BUYER_MANDATE` / `B0`
- 撤销目标 G1: `e9bc7da1880bbd7b392e79371ba1da12aaa4c908a8dfae8308139f449d097820`
- 撤销原交易 txID / 块 r: `0f7abbfcbdfd89d6629149022c254001efdefa2c510cd5d81e987fb83e07315a` / `46`
- 复算判定: `passed=true` (违规放行 0, 旧块定案后延迟响应 0, 时间精度不足 0)

## 实例阶段耗时与窗口汇总

| 实例 | 探针角色 | `t_valid-t_submit` (ms) | `t_apply-t_valid` (ms) | `t_adopt-t_apply` (ms) | 确认后窗口 (ms) | 相对提交窗口 (ms) | 窗口状态 | 违规放行 | 计划/完成/漏探测/超时 | 时钟分辨率 (ns) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `gw-1` | `probe1` | 51.391 | 4.233 | 9.746 | null | 42.822 | `post_valid_allow_unobserved` | 0 | 553/553/0/0 | 1000 |
| `gw-2` | `probe2` | 51.391 | 4.233 | 9.284 | null | 46.663 | `post_valid_allow_unobserved` | 0 | 553/553/0/0 | 1000 |

## 样本对账与删失说明

- 预热样本: 2, 计划探测: 1106, 启动: 1106, 完成: 1106, 漏探测: 0, 超时: 0, 允许: 104, 拒绝: 1000, 错误: 2
- `gw-1` 删失/缺测备注: `post_valid_allow_unobserved`
- `gw-1` 首次拒绝观测: `code=ANCESTOR_INACTIVE`, `source=responded_at_ns`, `unobserved_reason=precheck_deny_no_decision_row`
- `gw-2` 删失/缺测备注: `post_valid_allow_unobserved`
- `gw-2` 首次拒绝观测: `code=ANCESTOR_INACTIVE`, `source=responded_at_ns`, `unobserved_reason=precheck_deny_no_decision_row`

## 原始输入文件摘要 (SHA-256)

| 原始文件 | SHA-256 |
| --- | --- |
| `manifest.json` | `b46e6816630fc0910bba6bb257bacfc7e7b7143105a9f7bb31bfc6199c46d8ae` |
| `requests.csv` | `2cf39c9472162ae97cafe4b6a52502c062184f2822bdbe86856f79638734d8da` |
| `revocations.csv` | `f52d818ad8e859594f6ca367f694ad8ffbd3c828e38e152f3446ac4cfaf9970a` |
| `summary.json` | `ad26e9c5af147fbe529714e3bdc2910aa43339a38fba219e5b033cd9716bc6a8` |
