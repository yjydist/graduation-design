# E1 独立实验驱动

`run.sh` 将指定 Git 提交导出到临时构建目录. 在其中构建项目原有的 `ledgerctl`, 然后单独构建 `driver/` 下的实验编排程序. 每轮记录项目提交, 两个可执行文件的 SHA-256 以及实验驱动源码. 场景和判据见 [E1 方法](../../docs/experiments/E1-采购功能闭环.md), 实验结果和原始记录见[结果报告](result.md).

## 运行

启动 Docker, 将模型凭据放入当前环境的 `LLM_API_KEY`. 在项目根目录指定固定提交, 全新的实例目录与可用端口.

```bash
bash experiments/e1-procurement/run.sh 79125cc40855014c16fcfb0a962bc276202023d8 \
  .local/fabric-e1-rerun 19100
```

脚本从 `experiments/llm.env` 读取模型选择. OpenAI 兼容地址只有主机名时, 驱动使用 `/v1` 作为 API 路径, 并在清单同时记录原地址和生效地址. 每次启动在 `runs/<run-id>/` 创建独立记录. 结束后停止当轮容器并保留卷和实例目录.

## 项目接口

- 使用原有的 `ledgerctl deploy`, `mcp`, `invoke`, `seed` 和 `check` 创建并读取 Fabric 状态. 使用 MCP 会话初始化钱包夹具, 通过 `invoke` 核验待认证域的登记拒绝, 然后由 `seed` 继续初始化.
- 网关及钱包使用固定提交的 Go 库接口, 按网关 HTTP JSON 协议和 MCP 工具执行请求. 驱动用 `ledgerctl check` 获取 C 的真实探针, 在同一宿主机内把原交易, 发送时点和有效期交给现有状态提供器. 实际请求按块高装配并在定案时复核探针与检查点.
- PostgreSQL 用于控制合成目录价格, 回读挑战, 决定和订单, 并导出连续区块. 新旧运行的探针调度方式各见其运行清单.

[迁移前源码归档](source-archive/README.md).
