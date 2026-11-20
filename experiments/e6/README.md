# E6 撤销窗口实验驱动

E6 通过共用工作流入口 `mise -C experiments run experiment:run` 编排执行, 使用确定性钱包工具与持续运行的状态提供器 (`probe1` 与 `probe2` 两个独立原探针共享 C 的 PostgreSQL 视图), 测量 U 撤销上级委托 G1 后的撤销窗口与阶段耗时. 方法与判据见 [E6 方法](method.md), 短跑与后续正式结果见[结果报告](result.md).

## 运行

启动 Docker, 在项目根目录指定模式 (`RP` 或 `BM`), 全新的隔离实例目录及可用起始端口. 当前短跑使用现有 1 秒探针发送间隔与 5 秒探针寿命 (`deltaState = 5s`), 默认 20 ms 计划探测间隔及双网关实例 (`gw-1`, `gw-2`).

```bash
# RP 隔离短跑
mise -C experiments run experiment:run -- --experiment E6 \
  --mode RP \
  --instance .local/fabric-e6-rp-short \
  --port 19300 \
  --duration 10s \
  --revoke-after 1s \
  --instances 2

# BM 隔离短跑
mise -C experiments run experiment:run -- --experiment E6 \
  --mode BM \
  --instance .local/fabric-e6-bm-short \
  --port 19400 \
  --duration 10s \
  --revoke-after 1s \
  --instances 2
```

在包含未提交改动的开发工作区验收时可附加 `--workspace-sut`, 清单会同时记录工作区提交, 脏状态和实际二进制摘要. 每次运行自动分配新运行 ID 并在 `runs/<run-id>/` 保存初始清单 `manifest.json`, 源码快照 `driver-source.tar.gz`, `revocations.csv`, `requests.csv`, `events.jsonl` 与 `summary.json`, 结束后停止当轮容器并执行敏感字段检查.

## 离线复算

停止 Fabric 与 PostgreSQL 容器后, 从原始运行目录只读复算阶段耗时, 确认后窗口, 样本对账, 延迟响应归类与删失状态:

```bash
mise -C experiments run experiment:analyze -- --experiment E6 \
  --run-dir experiments/e6/runs/<run-id> \
  --out experiments/e6/analysis/<run-id>
```

输出 `recomputed.json` 与 `recomputed-table.md` 写入独立分析目录, 记录分析版本 (`e6-analyzer/v1`), 源运行 ID 以及所有参与复算原始文件的 SHA-256 摘要, 不修改原始运行目录.
