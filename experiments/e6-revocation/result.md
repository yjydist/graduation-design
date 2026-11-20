# E6 撤销窗口实验结果

**状态.** 已完成 RP 与 BM 各一轮隔离短跑及离线复算验收; 主要场景 30 次独立重复, `deltaState` 1/5/15 秒参数扫描及深度/后代数扩展待正式采样. [独立驱动说明](README.md), [E6 方法](../../docs/experiments/E6-撤销窗口.md).

## 1 实验问题与判据

测量上级委托 G1 被撤销后, 各网关实例还能沿旧路径成功下单多久. 对每个实例记录可信 Peer 首次观测原撤销交易为 `VALID` 的时点 `t_valid`, 以及最后一次允许的 `t_last_allow,j`. 按[E6 方法](../../docs/experiments/E6-撤销窗口.md)计算确认后的窗口, 同时报告相对首次提交的窗口, 标记确认后允许未观测到的轮次, 并注明探测分辨率和删失原因.

采用撤销块或更高块后仍允许旧路径, 或在所用原探针到期时及之后仍允许, 均判为失败. 锁后定案 (`decision_at_ns`), 业务提交 (`committed_at_ns`) 与客户端响应 (`responded_at_ns`) 分别记录.

## 2 实际配置与隔离短跑批次

两轮短跑在各自全新的隔离 Fabric 实例上执行, 采用 B0 配置 (关闭跨请求静态验签缓存), 委托深度 2 (撤销对象 G1, 后代数 1), 两个网关实例 (`gw-1`/`probe1`, `gw-2`/`probe2`) 共享 C 的 PostgreSQL 视图, 探针发送间隔 `1 s`, 现有探针寿命 `deltaState = 5 s`, 计划探测间隔 `20 ms`, 撤销前基线 `1 s`, 撤销后持续探测 `10 s`. 同机时基为 `host-utc-unix-ns`, 实测时钟分辨率 `1000 ns`, 校时误差 `0 ns`. 各轮完整配置见对应 `manifest.json`.

| 运行 ID | 根配置 | 验证配置 | `deltaState` (s) | 运行状态 | 原始文件与离线复算 |
| --- | --- | --- | --- | --- | --- |
| `run-c3a21eb94efa9dcc` | `RP` (`RESOURCE_PREAUTHORIZED`) | `B0` | `5` | `PASS` (隔离短跑) | 原始: [清单](runs/run-c3a21eb94efa9dcc/manifest.json), [撤销时间线](runs/run-c3a21eb94efa9dcc/revocations.csv), [请求](runs/run-c3a21eb94efa9dcc/requests.csv), [汇总](runs/run-c3a21eb94efa9dcc/summary.json); 复算 (`e6-analyzer/v1`): [复算 JSON](analysis/run-c3a21eb94efa9dcc/recomputed.json), [复算表](analysis/run-c3a21eb94efa9dcc/recomputed-table.md) |
| `run-86facf71a9d07b81` | `BM` (`BUYER_MANDATE`) | `B0` | `5` | `PASS` (隔离短跑) | 原始: [清单](runs/run-86facf71a9d07b81/manifest.json), [撤销时间线](runs/run-86facf71a9d07b81/revocations.csv), [请求](runs/run-86facf71a9d07b81/requests.csv), [汇总](runs/run-86facf71a9d07b81/summary.json); 复算 (`e6-analyzer/v1`): [复算 JSON](analysis/run-86facf71a9d07b81/recomputed.json), [复算表](analysis/run-86facf71a9d07b81/recomputed-table.md) |

原始请求在 `requests.csv`, 撤销与视图采用时间线在 `revocations.csv`, 单轮汇总在 `summary.json`. 短跑调试阶段的失败留证一并保留:

| 失败运行 ID | 失败阶段 | 原因与处理 | 原始记录 |
| --- | --- | --- | --- |
| `run-48b5ec7f62451a0f` | `execution` (`deploy`) | 在 `fabric.outcome` 结构中添加观测时间导致 `deployment.go` 值比较 `*confirmed != *op.Commit` 误报 `DEPLOYMENT_MISMATCH`. 保持 `outcome` 纯值结构并独立返回 `observedAt` 后用新实例复跑 | [汇总](runs/run-48b5ec7f62451a0f/summary.json), [驱动日志](runs/run-48b5ec7f62451a0f/driver.log) |
| `run-a44579c85d070c6d` | `execution` (`loadProbeMaterial`) | 驱动读取 `rp-g0.jws` 而非种子生成的 `rp_g0.jws`. 修正文件名约定后用新实例复跑 | [汇总](runs/run-a44579c85d070c6d/summary.json), [驱动日志](runs/run-a44579c85d070c6d/driver.log) |

## 3 短跑离线复算结果

停止 Fabric 与 PostgreSQL 容器后, 使用 `mise run experiment:analyze -- --experiment E6` (`e6-analyzer/v1`) 对两轮隔离短跑进行只读复算, 原始目录保持不变.

| 配置与实例 | 源运行 ID | `t_valid-t_submit` (ms) | `t_apply-t_valid` (ms) | `t_adopt-t_apply` (ms) | 确认后窗口 (ms) | 相对提交窗口 (ms) | 窗口状态 | 违规放行数 | 计划 / 完成 / 漏探测 / 超时 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `RP / B0 / gw-1` | `run-c3a21eb94efa9dcc` | `93.342` | `2.395` | `10.638` | 未观测 (`post_valid_allow_unobserved`) | `85.845` | `post_valid_allow_unobserved` | `0` | `553 / 552 / 1 / 0` |
| `RP / B0 / gw-2` | `run-c3a21eb94efa9dcc` | `93.342` | `2.395` | `10.301` | 未观测 (`post_valid_allow_unobserved`) | `83.104` | `post_valid_allow_unobserved` | `0` | `553 / 552 / 1 / 0` |
| `BM / B0 / gw-1` | `run-86facf71a9d07b81` | `51.391` | `4.233` | `9.746` | 未观测 (`post_valid_allow_unobserved`) | `42.822` | `post_valid_allow_unobserved` | `0` | `553 / 553 / 0 / 0` |
| `BM / B0 / gw-2` | `run-86facf71a9d07b81` | `51.391` | `4.233` | `9.284` | 未观测 (`post_valid_allow_unobserved`) | `46.663` | `post_valid_allow_unobserved` | `0` | `553 / 553 / 0 / 0` |

样本对账与异常说明:

- 两轮短跑在采用撤销块 `r = 46` 后均无任何旧路径放行 (`0` 次违规), 亦无探针过期后放行 (`0` 次违规) 及旧块定案后延迟响应样本 (`0` 例).
- 同机部署下从 `t_valid` 到 `t_adopt` 仅约 `12.7-14.0 ms`, 短于 `20 ms` 计划探测周期 (实测中位发送间隔 `20.000 ms`), 因此在 `t_valid` 与 `t_adopt` 之间未落入新的允许样本, 复算按规范归类为 `post_valid_allow_unobserved`, 并同步给出相对 `t_submit` 的窗口 (`42.8-85.8 ms`).
- 四个实例在采用 `r = 46` 后的首次拒绝均命中 `ANCESTOR_INACTIVE` (预检拒绝, 不写入 `decisions` 表, 记录响应时点及 `unobserved_reason=precheck_deny_no_decision_row`).
- 两轮各在 `10 s` 探测窗口结束取消上下文瞬间出现 `2` 条收尾中断请求 (`seq=553`, 每实例 1 条, 记为 `error`); RP 轮次在探测高峰出现每实例 `1` 次漏探测槽位 (`missed_probe_slot`), 已在样本对账和删失备注中显式留证.

## 4 后续正式采样与图表

当前结论仅用于验证 E6 持续探针采样, 亚秒锁后定案采集, 撤销事件关联和离线复算链路. 正式 30 次独立重复, `deltaState` 1/5/15 秒参数扫描, 不同撤销对象/深度/后代数扩展以及 `figures/` 下的实例时间线与窗口/可用率图, 待正式批次完成后按运行 ID 补充. 实现阶段的时间线和复跑入口见[历史预跑](../README.md#历史预跑).
