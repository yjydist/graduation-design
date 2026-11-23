# 三域 Web 工作台

A/B/C 使用同一前端镜像, 后端镜像与 Compose 模板. 浏览器以 HTTPS 连接本域前端, 前端同源转发 `/api/v1`. 后端在 Fabric 实例网络上另设 mTLS 端口用于域间材料交付, 采购派发及 C 网关调用. 每域使用自己的 PostgreSQL 数据卷和账号. 浏览器入口默认只绑定环回地址.

## 1 准备隔离 Fabric 实例

在仓库根目录执行. 需要 Docker Engine, Compose, OpenSSL, `curl` 和项目 Go 工具链. Fabric 环境和最新的域认证, 身份凭证由[Fabric 运行手册](../fabric/README.md)说明.

```sh
export FABRIC_INSTANCE="$PWD/.local/fabric-workbench-demo"
export WORKBENCH_ROOT="$PWD/.local/workbench-demo"
mise run fabric:rebuild -- "$FABRIC_INSTANCE" 18460
mise run ledger:deploy
mise run ledger:seed
mise run ledger:check
mise exec -- go build -o build/workbench grad/platform/cmd/workbench
build/workbench prepare --fabric "$FABRIC_INSTANCE" --output "$WORKBENCH_ROOT"
```

选择未使用的实例目录和端口范围. `prepare` 使用已登记的部署与域身份, 为 B 补齐演示所需的本域服务登记, 再生成 `a/`, `b/`, `c/` 独立挂载目录. 域配置绑定部署标识, 允许的本域主体, 受信域间端点及证书指纹. 各域仅挂载自己的私有目录, 公共 DID 文档用于验证跨域身份. 现有工作台重启时复用原目录.

| 域 | 账号 | 口令文件 (相对各域挂载目录) |
| --- | --- | --- |
| A/B/C | `admin` | `admin-password` |
| A | `u` | `buyer-password` |
| C | `auditor` | `auditor-password` |

后端启动时通过平台迁移创建表, 核验账号与本域登记映射, 初始化服务端账号. `postgres-password` 用于数据库初始化和后端连接. 域间 mTLS 密钥, Fabric MSP 和钱包文件由 `prepare` 生成或按域选取. 将这些文件留在本地私有目录.

在 A 和 B 的挂载目录各设置 `llm.env` 和 `model-api-key`. `llm.env` 写入模型连接信息, 例如以下配置. 将 `LLM_BASE_URL` 和 `LLM_MODEL` 替换为当前真实模型端点及名称.

```dotenv
LLM_PROVIDER=openai
LLM_BASE_URL=https://model.example/v1
LLM_MODEL=your-model
LLM_MAX_STEPS=8
```

本机模型代理需接受来自 Docker 的连接, Docker Desktop 可用 `host.docker.internal` 访问宿主. 模型密钥只写入各域的 `model-api-key` 文件, 权限设为 `0600`. C 域不需要模型连接.

## 2 构建并启动三域

两个镜像各构建一次. 用镜像标识固定三个实例的构建, Compose 配置变化无需重建镜像.

```sh
docker build -t grad-workbench-frontend:local ./web
docker build -f infra/workbench/backend.Dockerfile -t grad-workbench-backend:local .
export WORKBENCH_FRONTEND_IMAGE="$(docker image inspect -f '{{.Id}}' grad-workbench-frontend:local)"
export WORKBENCH_BACKEND_IMAGE="$(docker image inspect -f '{{.Id}}' grad-workbench-backend:local)"
fabric_project="$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' "$FABRIC_INSTANCE/network.env")"
export WORKBENCH_FABRIC_NETWORK="${fabric_project}_default"
export WORKBENCH_UID="$(id -u)" WORKBENCH_GID="$(id -g)"

workbench_compose() {
    domain="$1"
    shift
    case "$domain" in
        a) port=18441 ;;
        b) port=18442 ;;
        c) port=18443 ;;
        *) return 2 ;;
    esac
    WORKBENCH_DOMAIN="$domain" \
    WORKBENCH_BROWSER_HOST="$domain.localhost" \
    WORKBENCH_PORT="$port" \
    WORKBENCH_CONFIG_DIR="$WORKBENCH_ROOT/$domain" \
    docker compose -p "$fabric_project-workbench-$domain" -f infra/workbench/compose.yaml "$@"
}

for domain in a b c; do
    workbench_compose "$domain" config --quiet || break
    workbench_compose "$domain" up -d --wait --wait-timeout 180 || break
done
```

`WORKBENCH_FRONTEND_IMAGE` 和 `WORKBENCH_BACKEND_IMAGE` 也可设为仓库中的 OCI 摘要. `WORKBENCH_UID` 和 `WORKBENCH_GID` 对应准备目录的宿主所有者. 每域的浏览器主机名, 端口, 挂载目录, 数据卷与 Compose 项目名各自独立. 浏览器代理默认使用本项目的 `backend:8080`, 可用 `WORKBENCH_BROWSER_UPSTREAM` 绑定另一个运行端点.

三个浏览器入口分别为 `https://a.localhost:18441`, `https://b.localhost:18442`, `https://c.localhost:18443`. 本地演示的浏览器证书由各前端自己的 Caddy CA 签发. 导出各 CA 的公钥证书, 在演示浏览器或系统信任库中按本地环境信任. 重新启动会沿用原证书卷.

```sh
for domain in a b c; do
    workbench_compose "$domain" cp \
        frontend:/data/caddy/pki/authorities/local/root.crt \
        "$WORKBENCH_ROOT/$domain/browser-root.crt" || break
done
```

## 3 就绪检查和浏览器操作

```sh
for item in a:18441 b:18442 c:18443; do
    domain="${item%:*}"
    port="${item#*:}"
    curl --fail --silent --show-error --noproxy '*' \
        --resolve "$domain.localhost:$port:127.0.0.1" \
        --cacert "$WORKBENCH_ROOT/$domain/browser-root.crt" \
        "https://$domain.localhost:$port/api/v1/health/ready" || break
    printf '\n'
    workbench_compose "$domain" images
done
```

核对每域就绪结果中的 `domainId`, 前后端镜像标识, 数据库卷和后端只读挂载. 用 `workbench_compose a ps` 或 `workbench_compose a logs backend` 排查就绪错误. 浏览器从每域入口读取同源 API, 业务接口定义可在该入口的 `/api/v1/openapi.json` 查看.

- 用三个域各自的 `admin` 登录, 选择本域合资格服务并提交 PA 资格操作. 保存各自的操作 ID, 核对原交易 txId, 链上校验码及最终状态. A 域的 BM 演示需选择本域 PA.
- 用 A 域的 `u` 登录, 与 A1 对话提出采购要求. 查看或修订草稿后确认版本, 再从运行页查看任务, G0/G1 的签发交付和 A1/B1 工具轨迹. 原型 C 目录的 P1 和 P2 分别用于 800 元和 1200 元演示. 分别提出 RP 采购一件 P1 和 BM 采购一件 P2, 单笔上限 1000 元, 委托 A1 并在一小时内执行. 核对 C 的实际报价.
- 通过运行页核对身份与信任, 凭证披露, 委托树, 采购任务和决策时间线. 记录实际决定 ID. 由 C 域的 `auditor` 登录后用决定 ID 查询其获准查看的原决定.
- 在运行页暂停 G1, 核对原交易有效确认. C 采用该块后的业务请求与恢复后的原期限, 用 C 决定记录和原交易对账. 工具轨迹中的模型停止与网关实际拒绝分别核对.

保存演示截图前遮盖口令输入, 会话及密钥材料. 证据采用已关联的运行 ID, 操作 ID, 原交易 txId, 决定 ID 和 C 主库的业务结果. 位置及证据范围见[网关执行](../../docs/implementation/证据交付与网关执行.md).

### 3.1 补发确定性负例

从与三域内部服务同一隔离网络的管理环境调用以下接口. 使用 A 域服务证书和内部 CA. `RUN_ID` 取自已派发任务, 每次新的探针使用独立的 由 64 个十六进制字符组成的键. 原探针重试沿用同一键.

```sh
probe_key="$(openssl rand -hex 32)"
curl --fail-with-body --silent --show-error \
    --cacert "$WORKBENCH_ROOT/a/internal-ca.crt" \
    --cert "$WORKBENCH_ROOT/a/internal.crt" \
    --key "$WORKBENCH_ROOT/a/internal.key" \
    --json "{\"runId\":\"$RUN_ID\",\"key\":\"$probe_key\",\"order\":true}" \
    "https://workbench-b:8081/internal/workbench/probe"
```

当 `order` 为 true 时, B1 仅在 C 已返回超出 G2 上限的报价后补发订单请求. 暂停后和恢复后的探针使用 `order: false` 询价. 用工作台决策时间线及 C 主库核对原拒绝码, 区块和订单数.

## 4 停止与再次启动

先停止工作台, 再按 Fabric 手册停止其网络. 保留三个 Compose 项目的数据卷, 私有目录和 Fabric 实例目录.

```sh
for domain in a b c; do
    workbench_compose "$domain" down
done
mise run fabric:down
```

再次启动时用相同的 Fabric 实例, 域挂载目录, 镜像标识和 Compose 项目名.

```sh
mise run fabric:up
for domain in a b c; do
    workbench_compose "$domain" up -d --wait --wait-timeout 180 || break
done
```

检查重启前的原操作 ID 和采购运行 ID 仍可查询. 三域数据库通过各自项目的私有网络访问. 镜像构建只复制前端静态资源, 以及编译 Go 后端所需的源码和依赖. 运行口令, Fabric 私钥, 钱包和模型密钥均在启动时提供.
