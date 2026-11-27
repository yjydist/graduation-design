# 三域 Web 工作台

A/B/C 使用同一前端镜像, 后端镜像与 Compose 模板. 浏览器以 HTTPS 连接本域前端, 前端同源转发 `/api/v1`. 后端在 Fabric 实例网络上另设 mTLS 端口用于域间材料交付, 采购派发及 C 网关调用. 每域使用自己的 PostgreSQL 数据卷和账号. 浏览器入口默认只绑定环回地址.

## 1 首次配置和启动

在 arm64 macOS 或 Linux 的仓库根目录执行. 主机需要 mise, Docker Engine 和 Compose, curl, OpenSSL 与 shasum. 本地演示占用环回端口 18441-18443 和 18460-18469.

```sh
mise install
mkdir -p .local/demo-config/a .local/demo-config/b
```

在 A/B 的源目录各准备一个 `llm.env` 和一个只含本域模型密钥的 `model-api-key`. 将下例的服务地址和模型名替换为实际值. 容器需要能到达模型端点, Docker Desktop 上的本机代理可通过 `host.docker.internal` 访问.

```dotenv
LLM_PROVIDER=openai
LLM_BASE_URL=https://model.example/v1
LLM_MODEL=your-model
LLM_MAX_STEPS=8
```

```sh
chmod 600 .local/demo-config/a/model-api-key .local/demo-config/b/model-api-key
mise run demo:up
```

启动成功时, 三个入口均已通过本域 CA 校验, 健康接口返回对应域标识. 在演示浏览器的受信任根证书设置中分别导入输出指向的 `browser-root.crt`. 表中口令文件路径相对于 `.local/demo/workbench/`.

| 浏览器入口 | 演示账号 | 口令文件 |
| --- | --- | --- |
| `https://a.localhost:18441` | `u` | `a/buyer-password` |
| `https://b.localhost:18442` | `admin` | `b/admin-password` |
| `https://c.localhost:18443` | `auditor` | `c/auditor-password` |

各域也提供本域 `admin`, 其口令在本域的 `admin-password`. 归属记录 `.local/demo/instance.json` 绑定本机 Docker Engine, 随机 Compose 项目, 部署标识, 数据卷, 有效期限和镜像. 本地镜像按内容保留, 各实例可以复用原镜像 ID. 同一有效实例可重跑 `demo:up` 复用已发布的域挂载, 数据卷和口令. 若中断, 从新终端在仓库根查询失败阶段和对应域的日志.

```sh
mise run demo:status
mise run demo:logs -- b backend
mise run demo:logs -- fabric peer-c --tail 20
```

## 2 单域运维

在已启动的演示上, 以下命令从归属记录取得实例和镜像.

```sh
mise run workbench:compose -- b ps
mise run workbench:certs -- b
mise run workbench:ready
```

独立的手工部署可指定 `FABRIC_INSTANCE` 和 `WORKBENCH_ROOT`. 先用 `fabric:rebuild`, `ledger:deploy`, `ledger:seed` 和 `ledger:check` 准备并校验隔离账本, 详见[Fabric 手册](../fabric/README.md). 以下示例使用已登记的实例和一个新的挂载目录.

```sh
export FABRIC_INSTANCE="$PWD/.local/fabric-workbench-manual"
export WORKBENCH_ROOT="$PWD/.local/workbench-manual"
mise run workbench:prepare -- --fabric "$FABRIC_INSTANCE" --output "$WORKBENCH_ROOT"
mise run workbench:images
```

将各域模型输入放入 A/B 的私有挂载, 将镜像命令输出的两个 ID 分别设为 `WORKBENCH_FRONTEND_IMAGE` 和 `WORKBENCH_BACKEND_IMAGE`. 对每个域运行 `mise run workbench:compose -- <域> up -d --wait --wait-timeout 180`, 然后用 `workbench:certs` 和 `workbench:ready` 核实 HTTPS. 单域后端可通过 `mise run workbench:serve -- --config <域配置文件>` 启动. 各域独立绑定数据库, 本域 Fabric 身份和钱包. 管理员可按挂载所有者设置 `WORKBENCH_UID` 和 `WORKBENCH_GID`.

## 3 浏览器操作

- 用三个域各自的 `admin` 登录, 选择本域合资格服务并提交 PA 资格操作. 保存各自的操作 ID, 核对原交易 txId, 链上校验码及最终状态. A 域的 BM 演示需选择本域 PA.
- 用 A 域的 `u` 登录, 与 A1 对话提出采购要求. 查看或修订草稿后确认版本, 再从运行页查看任务, G0/G1 的签发交付和 A1/B1 工具轨迹. 原型 C 目录的 P1 和 P2 分别用于 800 元和 1200 元演示. 分别提出 RP 采购一件 P1 和 BM 采购一件 P2, 单笔上限 1000 元, 委托 A1 并在一小时内执行. 核对 C 的实际报价.
- 通过运行页核对身份与信任, 凭证披露, 委托树, 采购任务和决策时间线. 记录实际决定 ID. 由 C 域的 `auditor` 登录后用决定 ID 查询其获准查看的原决定.
- 在运行页暂停 G1, 核对原交易有效确认. C 采用该块后的业务请求与恢复后的原期限, 用 C 决定记录和原交易对账. 工具轨迹中的模型停止与网关实际拒绝分别核对.

保存演示截图前遮盖口令输入, 会话及密钥材料. 证据采用已关联的运行 ID, 操作 ID, 原交易 txId, 决定 ID 和 C 主库的业务结果. 位置及证据范围见[网关执行](../../docs/IMPLEMENTATION.md#4-证据交付与网关执行).

### 3.1 补发确定性负例

将 `RUN_ID` 设为已派发的运行 ID, `PROBE_KEY` 设为该探针的 64 位十六进制重试键. 新探针可用 `openssl rand -hex 32` 生成键. 运维入口用 A 域的 mTLS 证书经实例内部网络访问 B 域.

```sh
mise run workbench:probe -- --run-id "$RUN_ID" --key "$PROBE_KEY" --order
```

使用 `--order` 时, B1 在 C 已返回超出 G2 上限的报价后补发订单请求. 省略该参数可在暂停或恢复后询价. 重试同一探针沿用原键.

## 4 停机, 恢复和重建

```sh
mise run demo:down
mise run demo:up
```

停机会先关闭三域服务, 再关闭 Fabric, 并保留账本, 域数据库, 口令及浏览器 CA. 在有效期内启动后, 可按原运行和订单 ID 核对业务记录.

需要清除演示数据时, 直接运行 `mise run demo:clean`. 运行中, 部分部署和已停机的实例都支持清理. 若中断, 处理输出指出的资源后重跑同一命令. 演示源配置在 `.local/demo-config/`, 可供下一次部署使用.

夹具签发后有效 24 小时. 到期后, `demo:up` 显示截止时间. 完成旧记录复核后运行 `mise run demo:clean` 和 `mise run demo:up`, 使用新口令并在演示浏览器中信任新 CA. 使用 `mise run test:demo` 可离线检查这些部署行为.
