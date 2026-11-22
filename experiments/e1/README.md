# E1 独立实验驱动

E1 通过统一实验 CLI (`cmd/exp`) 的 `mise -C experiments run experiment:run` (或封装脚本 `run.sh`) 编排执行. 构建前先分配独立运行 ID, 保存计划清单 `manifest.json` 及包含编排与驱动源码的 `driver-source.tar.gz`, 再将指定 Git 提交导出到临时构建目录, 构建 `ledgerctl` 与 `e1-driver` 并补录二进制 SHA-256 及隔离实例信息. 场景和判据见 [E1 方法](method.md), 实验结果模板和原始记录约定见[结果报告](result.md).

## 运行

启动 Docker, 将模型凭据放入当前环境的 `LLM_API_KEY`. 在项目根目录指定固定提交, 全新的实例目录与可用端口:

```bash
mise -C experiments run experiment:run -- --experiment E1 \
  --revision <revision> \
  --instance .local/fabric-e1-run \
  --port 19100
```

也可通过封装脚本 `run.sh` (透传参数至 `experiment:run -- --experiment E1`) 或在 `experiments/` 目录直接调用 `exp` CLI:

```bash
bash experiments/e1/run.sh \
  --revision <revision> \
  --instance .local/fabric-e1-run \
  --port 19100

cd experiments && go run ./cmd/exp run --experiment E1 \
  --revision <revision> \
  --instance .local/fabric-e1-run \
  --port 19100
```

在包含未提交改动的开发工作区验收时可附加 `--workspace-sut`, 清单会同时记录工作区提交, 脏状态和实际二进制摘要.

运行前从 `experiments/llm.env` 读取模型选择. OpenAI 兼容地址只有主机名时, 驱动使用 `/v1` 作为 API 路径, 并在清单同时记录原地址和生效地址. 公开清单记录模型选择, 源码快照排除本地 `llm.env`. 服务地址只接受无凭据, 查询参数和片段的 HTTP(S) 端点. 每次启动在 `runs/<run-id>/` 创建独立目录 (拒绝覆盖已有目录). 结束后无论成功, 失败或中止均停止当轮容器并保留已写证据, 标记失败阶段与缺测原因, 并对公开导出执行敏感字段检查.

## 离线复算

停止 Fabric, PostgreSQL 和模型服务后, 可从原始运行目录只读复算 F01-F16 关键计数, RP/BM 主库对账, 模型轨迹与失败缺测诊断, 并将派生汇总输出到独立目录:

```bash
mise -C experiments run experiment:analyze -- --experiment E1 \
  --run-dir experiments/e1/runs/<run-id> \
  --out experiments/e1/analysis/<run-id>
```

输出包含 `recomputed.json` 与 `recomputed-table.md`, 记录分析版本 (`e1-analyzer/v1`), 源运行 ID 以及所有参与复算原始文件的 SHA-256 摘要. 原始运行目录在复算前后保持只读且摘要不变.

## 项目接口

- `experiments/` 为独立 Go 模块 (`grad/experiments`), 仅通过公开的 `grad/protocol`, `grad/platform` API 以及 `ledgerctl` CLI (`platform/cmd/ledgerctl`) 交互.
- 使用 `ledgerctl deploy`, `mcp`, `invoke`, `seed` 和 `check` 创建并读取 Fabric 状态. 使用 MCP 会话初始化钱包夹具, 通过 `invoke` 核验待认证域的登记拒绝, 然后由 `seed` 继续初始化.
- 网关及钱包通过固定提交的公开 Go 接口装配, 按网关 HTTP JSON 协议和 MCP 工具执行请求. 驱动用 `ledgerctl check` 获取 C 的真实探针, 在同一宿主机内把原交易, 发送时点和有效期交给状态提供器, 实际请求按块高装配并在定案时复核探针与检查点.
- PostgreSQL 用于控制合成目录价格, 回读挑战, 决定和订单, 并导出连续区块.
