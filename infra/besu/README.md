# 本地 Besu 网络

本目录提供四验证节点 QBFT 网络, 原实例和独立重建的账本切片验收见[D0 证据索引](evidence/README.md). 合约, 管理交易和状态读取分别见[合约说明](../../contracts/README.md)及[读取说明](../../internal/ledger/README.md).

## 初始化

在项目根目录执行:

```bash
mise run ledger:init
mise run test:unit
mise run ledger:build
```

等价底层命令:

```bash
CGO_ENABLED=0 go run ./cmd/ledgerctl init --dir .local/besu-qbft
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build -o build/ledgerctl ./cmd/ledgerctl
```

本机 Go 为 1.27.3, darwin/arm64. 本机默认 CGO 编译缺少 macOS SDK 头文件, 因此当前采用纯 Go 构建. Go Ethereum 依赖锁定于 go.mod/go.sum.

首次初始化创建随机 32 字节 instanceId, 四把独立 secp256k1 验证密钥, 各角色独立的 secp256k1 管理密钥及 P-256 应用密钥. A/B/C/实验运维分别控制四把验证密钥, T 没有验证者角色. 域管理员, 注册机构, IA/IB/IC, U/A1/B1/C 服务分别使用独立管理账户. `unrelated` 是已许可且有余额的无权账户, `unpermitted` 已预充值但不在账户许可名单内, 用于后续区分两类拒绝.

密钥只保存在本地实例的 nodes/ 和 keys/ 中, 私钥文件权限为 0600. instance.json 只含公开材料和 synthetic 标记. 应用公钥使用 65 字节 P-256 非压缩点, DID 公钥使用公共 JWK; 测试 DID 文档的固定 ASCII schema 按排序 JSON 求 SHA-256. 不提供 did:web 在线服务或真实凭证验签.

实例目录默认位于 Git 忽略的 `.local/` 中. 如显式使用其他目录, 操作者须保证私钥和数据不进入版本库. 再次执行同一初始化命令会复算并核对公钥, 地址, DID 摘要, genesis 和许可配置, 返回 `created=false`. 材料缺失或不匹配时失败, 不自动覆盖或重新生成. 新实例须显式使用不存在的目录, 例如 `--dir .local/besu-rebuild`; 不删除原实例.

实施范围见 [变更设计](../../openspec/changes/archive/2026-11-04-bootstrap-besu-state-verification/design.md).

## 网络启停与重建

在项目根目录执行以下命令. 根目录 `mise.toml` 默认将 `BESU_INSTANCE` 指向 `.local/besu-qbft`, 并在 `besu:*` 任务内动态注入当前操作者的 `BESU_UID` 与 `BESU_GID`, 使节点能够访问 0700 目录和 0600 密钥. Docker Desktop 须允许该项目目录的 bind mount.

```bash
mise run besu:config
mise run besu:up
mise run besu:ps
mise run besu:logs
```

等价底层命令:

```bash
export BESU_INSTANCE="$PWD/.local/besu-qbft"
export BESU_UID="$(id -u)"
export BESU_GID="$(id -g)"
docker compose -f infra/besu/compose.yaml config --quiet
docker compose -f infra/besu/compose.yaml up -d
docker compose -f infra/besu/compose.yaml ps
docker compose -f infra/besu/compose.yaml logs --tail 30 c
```

四个节点为 A/B/C/ops, C RPC 为 `http://127.0.0.1:18547`, A/B/ops 为 18545/18546/18548. 仅映射回环 RPC, 不映射 P2P. Docker 使用独立 bridge 和静态地址 172.28.61.11-14, 关闭发现, 静态连接其余已许可节点. Host allowlist 限 localhost/127.0.0.1, 不启用 CORS, 账户在客户端本地签名. DEBUG 仅用于本地受控回退取证, 不将此 RPC 暴露到公共网络.

Besu 26.11.0 的 linux/arm64 镜像已实际运行, Compose 固定 digest `sha256:3d6ac0368d449c13c4ba075acac90d6b96afa5b3113295385d88c4d5122c8808`. genesis 使用 chainId 20261104, Berlin 规则, QBFT 周期 1 秒, request timeout 4 秒, epoch 30000, 持续生成空块. 节点使用 FOREST/FULL, 不启用历史裁剪, 合约编译使用 Berlin EVM 目标. 已取得 h/r 合约历史状态及原交易跟踪证据, 原因缺失时保持通用失败.

宿主为 arm64, Docker 可用 14 CPU 和 8318910464 字节内存. 每容器上限 2 CPU, 1280 MiB 内存, 512 PID, JVM heap 为 256-512 MiB; 四节点内存上限合计 5 GiB. 建议为 Docker 至少分配 6 GiB 内存并保留磁盘空间, FOREST 数据会持续增长. 四把验证密钥由同一操作者在本机分别代管 A/B/C/实验运维, 不能据此宣称机构独立控制.

正常关闭与重启:

```bash
mise run besu:down
mise run ledger:init
mise run besu:up
```

`down` 保留 bind mount 中的密钥和账本数据. 启动后应核对原高度的块哈希和新头, 不以容器处于 running 状态代替网络就绪. 首轮启动等待上限 120 秒.

显式创建独立新实例, 保留旧实例和证据 (`mise.toml` 默认将 `BESU_INSTANCE` 指向 `.local/besu-qbft`, 重建新实例 `.local/besu-rebuild` 时需显式指定 `--dir` 与 `BESU_INSTANCE`):

```bash
mise run besu:down
CGO_ENABLED=0 go run ./cmd/ledgerctl init --dir .local/besu-rebuild
export BESU_INSTANCE="$PWD/.local/besu-rebuild"
BESU_UID="$(id -u)" BESU_GID="$(id -g)" docker compose -f infra/besu/compose.yaml up -d
```

新目录须不存在, 新 instanceId 和全部密钥重新生成. 本轮不提供原地清除实例或合约升级命令.

## 完整验收命令

确认四节点已启动, 在项目根目录运行:

```bash
mise run ledger:compile
mise run ledger:deploy
mise run ledger:seed
mise run ledger:verify
```

等价底层命令:

```bash
CGO_ENABLED=0 go run ./cmd/ledgerctl compile
CGO_ENABLED=0 go run ./cmd/ledgerctl deploy --dir "$BESU_INSTANCE" --name registry
CGO_ENABLED=0 go run ./cmd/ledgerctl seed --dir "$BESU_INSTANCE"
CGO_ENABLED=0 go run ./cmd/ledgerctl verify --dir "$BESU_INSTANCE" --out .local/evidence
```

verify 每次创建独立 run 目录, 保存配置, 清单, 原始 RPC/交易/块关联, Go 测试, 各判据及失败记录. 默认总期限 10 分钟, 单次交易确认 30 秒, 节点启动/恢复 120 秒; 可用 --timeout/--startup-timeout 设置更短的明确期限. 超时或必需判据失败均非零退出, 失败运行不会覆盖成功运行.

命令会暂时停止 A, 再停止 B, C 始终提供读 RPC. 停一节点后从停机完成时的链头再等待至少 3 个新块; 停两节点先稳定 5 秒, 再观察至少 15 秒, 检查重复读取/重启均超龄拒绝. 恢复足够节点并取得真实新鲜块后再次检查, 结束或失败时有界恢复 A/B. 也会启动同 genesis 的未许可测试节点并在结束时移除该探针. 数据和密钥始终留在被忽略的实例目录.

历史复查和在线模式的参数/输出见[StateReader](../../internal/ledger/README.md). 真实管理签名与合成应用材料的边界见[合约说明](../../contracts/README.md). 本轮不执行订单级 E6/E7.

## 阶段证据

- [网络原始结果](evidence/network/network.json), [RPC 请求与响应](evidence/network/rpc.jsonl)和[解析后的实际 Compose](evidence/network/compose-resolved.yaml)记录四个验证者, 相同 genesisHash, 每节点三个对等连接及连续 11 个空块. 10 个间隔均为 1 秒, 是本轮小样本观测, 不是性能保证.
- [公开实例清单](evidence/network/instance-public.json), [genesis](evidence/network/genesis.json)和[许可名单](evidence/network/permissions_config.toml)只含公开材料. 私钥仍留在 Git 忽略目录.
- [未许可节点观测](evidence/network/node-permissioning.json)使用相同 genesis 和静态对等节点, 新节点密钥未在四节点许可名单内, 连续观察中主网 C 保持三个对等连接而未许可节点为零. [探针日志](evidence/network/unpermitted-node.log)保存连接后断开及不能同步的过程.
- [账户许可拒绝](evidence/network/account-permissioning.json)保留原签名交易及 RPC 错误. 这是交易准入拒绝, 不作为合约执行回退证据. 可显式运行下列真实网络测试, 所选实例和证据目录均须使用绝对路径:

```bash
mise run test:account-probe
# 等价底层命令:
LEDGER_INSTANCE="$BESU_INSTANCE" LEDGER_EVIDENCE="$PWD/.local/account-probe" \
  CGO_ENABLED=0 go test ./internal/ledger -run TestAccountPermissioningIntegration -count=1 -v
```

[重启观测](evidence/network/restart.json)记录按上述 down/init/up 命令重启后, 原高度块哈希不变, instanceId 与全部私钥文件摘要不变, 链头继续增长. Besu 会移除许可文件末尾换行, 初始化核对允许这一非语义格式差异. [早期账户探针失败](evidence/network/account-probe-assertion-failure.json)记录了正确拒绝响应但断言误用关键词的情况, 修正后按实际 RPC 错误码 -32007 及消息核对并通过.

[初次失败样本](evidence/bootstrap/network.json)保留了首次启动期间的 RPC 失败. 初始 QBFT 投票字段曾误编码为空字节串, 已修正为空列表并补充 RLP 解码测试. Docker internal 网络在本机未映射回环端口, 已改用独立 bridge. 正式观测使用新实例 `besu-qbft`, 原试验目录保留.
