# E6 撤销窗口实验结果

**状态.** 重构前的旧批次 E6 短跑与复算产物 (`runs/`, `analysis/`) 已在 `rebuild-monorepo-architecture` 期间清理. RP/BM 隔离短跑, 离线复算验收, 主要场景 30 次独立重复, `deltaState` 1/5/15 秒参数扫描及深度/后代数扩展待在新 4 模块工作区架构下通过统一 `exp` CLI 重新执行后按运行 ID 填充. [独立驱动说明](README.md), [E6 方法](method.md).

## 1 实验问题与判据

测量上级委托 G1 被撤销后, 各网关实例还能沿旧路径成功下单多久. 对每个实例记录可信 Peer 首次观测原撤销交易为 `VALID` 的时点 `t_valid`, 以及最后一次允许的 `t_last_allow,j`. 按[E6 方法](method.md)计算确认后的窗口, 同时报告相对首次提交的窗口, 标记确认后允许未观测到的轮次 (`post_valid_allow_unobserved`), 并注明探测分辨率和删失原因.

采用撤销块或更高块后仍允许旧路径, 或在所用原探针到期时及之后仍允许, 均判为失败. 锁后定案 (`decision_at_ns`), 业务提交 (`committed_at_ns`) 与客户端响应 (`responded_at_ns`) 分别记录.

## 2 实验配置与运行批次骨架

各轮均在全新的隔离 Fabric 实例上执行, 默认采用 B0 配置 (关闭跨请求静态验签缓存), 委托深度 2 (撤销对象 G1, 后代数 1), 两个网关实例 (`gw-1`/`probe1`, `gw-2`/`probe2`) 共享 C 的 PostgreSQL 视图, 探针发送间隔 `1 s`, 探针寿命 `deltaState = 5 s` (并在参数扫描中扩展至 `1/5/15 s`), 计划探测间隔 `20 ms`, 撤销前基线 `1 s`, 撤销后持续探测 `10 s`. 每轮完整配置, 时钟分辨率与校时误差记录在 `runs/<run-id>/manifest.json`.

| 运行 ID | 根配置 | 验证配置 | `deltaState` (s) | 运行状态 | 原始文件与离线复算路径 |
| --- | --- | --- | --- | --- | --- |
| `<rp-run-id>` (待补跑) | `RP` (`RESOURCE_PREAUTHORIZED`) | `B0` | `5` | 待执行 | 原始: `runs/<rp-run-id>/{manifest.json,revocations.csv,requests.csv,summary.json}`; 复算 (`e6-analyzer/v1`): `analysis/<rp-run-id>/{recomputed.json,recomputed-table.md}` |
| `<bm-run-id>` (待补跑) | `BM` (`BUYER_MANDATE`) | `B0` | `5` | 待执行 | 原始: `runs/<bm-run-id>/{manifest.json,revocations.csv,requests.csv,summary.json}`; 复算 (`e6-analyzer/v1`): `analysis/<bm-run-id>/{recomputed.json,recomputed-table.md}` |

原始请求记录在 `requests.csv`, 撤销与视图采用时间线记录在 `revocations.csv`, 单轮汇总记录在 `summary.json`. 新架构复跑期间如出现失败轮次, 保留原目录并登记下表:

| 失败运行 ID | 失败阶段 | 原因与处理 | 原始记录路径 |
| --- | --- | --- | --- |
| 待记录 | 待记录 | 失败样本与日志保留原字节, 修复后使用新隔离实例与新运行 ID 复跑 | `runs/<failed-run-id>/{summary.json,driver.log}` |

## 3 离线复算结果骨架

停止 Fabric 与 PostgreSQL 容器后, 使用 `mise run experiment:analyze -- --experiment E6 --run-dir experiments/e6/runs/<run-id> --out experiments/e6/analysis/<run-id>` (`e6-analyzer/v1`) 对原始目录进行只读复算, 原始目录文件摘要保持不变. 正式或短跑批次完成后按实例填入下表:

| 配置与实例 | 源运行 ID | `t_valid-t_submit` (ms) | `t_apply-t_valid` (ms) | `t_adopt-t_apply` (ms) | 确认后窗口 (ms) | 相对提交窗口 (ms) | 窗口状态 | 违规放行数 | 计划 / 完成 / 漏探测 / 超时 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `RP / B0 / gw-1` | `<rp-run-id>` | 待填 | 待填 | 待填 | 待填 | 待填 | 待填 | 待填 (`0`) | 待填 |
| `RP / B0 / gw-2` | `<rp-run-id>` | 待填 | 待填 | 待填 | 待填 | 待填 | 待填 | 待填 (`0`) | 待填 |
| `BM / B0 / gw-1` | `<bm-run-id>` | 待填 | 待填 | 待填 | 待填 | 待填 | 待填 | 待填 (`0`) | 待填 |
| `BM / B0 / gw-2` | `<bm-run-id>` | 待填 | 待填 | 待填 | 待填 | 待填 | 待填 | 待填 (`0`) | 待填 |

复算完成后需逐轮核对:
- 采用撤销块或更高块后旧路径放行数为 `0`, 探针到期时及之后放行数为 `0`.
- 记录延迟响应样本归类, `post_valid_allow_unobserved` 原因, 预检拒绝响应时点以及任何漏探测槽位 (`missed_probe_slot`) 或收尾中断样本.

## 4 后续正式采样与图表

待新 4 模块架构下完成短跑验收后, 继续补齐主要场景 30 次独立重复, `deltaState` 1/5/15 秒参数扫描, 不同撤销对象/深度/后代数扩展以及 `figures/` 下的实例时间线与窗口/可用率图, 并按运行 ID 更新本报告. 实现阶段的预跑参考见[历史预跑](../README.md#历史预跑).
