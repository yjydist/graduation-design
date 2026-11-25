# Fabric 网络与集成验收

要求 arm64 macOS 或 Linux, Docker Engine 和 Compose, curl, shasum, OpenSSL, 以及 `mise.toml` 中锁定的 Go 1.27. Fabric 3.1.5 的本机工具按发布归档 SHA-256 校验, Peer, Orderer, 链码 baseos 和 PostgreSQL 镜像按 OCI digest 锁定为 `linux/arm64`. 历史验收记录见[证据索引](evidence/README.md).

## 1 启动并复跑

在项目根目录执行.

```bash
mise run fabric:config
mise run fabric:up
mise run ledger:deploy
mise run ledger:seed
mise run ledger:check
FABRIC_INSTANCE="$PWD/.local/fabric-d0" mise run ledger:verify
```

`fabric:up` 用创世块加入四个排序节点和 A/B/C 的 Peer. 首次 `deploy` 从独立模块 `chaincode/` 编译链码并安装每域自己的 TLS 链码服务, 生成或加载持久化 P-256 应用与测试 TLS 私钥 (`<instance>/private/`), 写出公开 DID 文档, 测试 CA 根证书与本地 VC v2 上下文摘要清单 (`<instance>/registry/`), 批准和提交定义, 核验初始化并保存 `registry/deployment.json`. `seed` 为各角色持久化应用私钥并使用原操作键提交绑定该部署的真实 ES256 `vc+jwt` 域认证, `vc+sd-jwt` 身份凭证, `procurementTaskSpec`, `G0`/`G1`/`G2` (`grad-delegation+jwt`) 委托和示例 `AccessEvidencePackage`, 同时同步写入交付发件箱. 夹具有效期 24 小时, 超期可用历史模式复查, 新的在线验收使用独立实例和新夹具.

首次部署中断后, 先在同一实例重跑 `mise run ledger:deploy`. 原初始化已有效提交时, 续跑复用原安装包, 核对原交易和根记录并恢复部署清单. 若提示原初始化提案被拒绝并要求显式续跑, 执行以下命令.

```bash
mise run ledger:deploy -- --retry-initialization
```

续跑会查验原背书拒绝, 确认操作从未生成已签交易, 并向可信 C Peer 查询根是否为空. 条件齐备时, 使用关联原 txID 的新操作键提交同一引导清单. 原操作及新操作均保留在日志中, `registry/initialization.json` 记录已完成部署的初始化取证.

`check` 连接 C 的可信 Peer, 从原检查点续读并等待本进程探针被有效提交和应用. 输出该次装配的区块号和哈希, 原探针 txID, 发送和采用时点及期限. 默认探针间隔 1 秒, 原期限 5 秒. 可用 `--probe-role probe2` 使用第二个专用身份. `inspect --block <十进制块号>` 从已应用的保留历史复查, 默认目标为种子委托, 可用 `--grant` 指定其他授权.

```bash
mise run ledger:build
build/ledgerctl inspect --block 24
build/ledgerctl operation --key seed/RP/G0
```

历史输出只有登记事实. `invoke --key <操作键> --role <角色> --method <链码方法> --input <JSON文件>` 接受并推进操作. `operation --key` 查原操作并在需要时恢复. 同键同输入返回原操作, C Peer 停机时仍可从本地日志取得原提案, txID 和已签交易. 同键异输入返回 `OPERATION_KEY_CONFLICT`. 受理新操作或推进待定操作前核对可信 Peer. 结果字段区分 `PENDING`, `CONFIRMED` 和 `FAILED`.

## 2 停止和独立重建

`mise run fabric:down` 移除本实例容器及网络, 保留实例目录和命名卷. 再次启动沿用原通道, package ID, 登记和 PostgreSQL 检查点. 如需重建, 指定尚不存在的本地目录和未使用的连续端口范围, 例如下列命令. 默认实例使用 `.local/fabric-d0` 和 17000-17009.

```bash
mise run fabric:rebuild -- .local/fabric-d0-rebuilt 17100
FABRIC_INSTANCE="$PWD/.local/fabric-d0-rebuilt" mise run ledger:deploy
FABRIC_INSTANCE="$PWD/.local/fabric-d0-rebuilt" mise run ledger:seed
FABRIC_INSTANCE="$PWD/.local/fabric-d0-rebuilt" mise run ledger:verify
FABRIC_INSTANCE="$PWD/.local/fabric-d0-rebuilt" mise run fabric:down
```

重建生成新的 Compose 项目, 创世块, 证书, 数据卷, `instanceId`, `deploymentId` 以及新的 T 根/角色应用密钥与测试 TLS 证书. 私钥与数据库口令留在 `.local/` 和 `<instance>/private/`.

## 3 实机回归与故障边界

`mise run ledger:verify` 运行 `//go:build fabriclive` 集成测试 (`grad/platform/core/ledger` 与 `grad/platform/bootstrap`), 覆盖通道治理与 BFT, 部署绑定与断点恢复, 角色写权限与委托替换, 时间窗口与并发 MVCC 竞争, 视图故障与探针期限, 以及全栈网关/钱包/MCP 验收. 未设置 `FABRIC_INSTANCE` 时自动跳过; 回归会修改登记并停止/重启节点, 应使用隔离实例.

可按需指定单个实机测试函数:

```bash
FABRIC_INSTANCE="$PWD/.local/fabric-d0-rebuilt" mise run ledger:verify -- -run '^TestFabricLiveViewFaultsAndProbes$'
FABRIC_INSTANCE="$PWD/.local/fabric-d0-rebuilt" mise run ledger:verify -- -run '^TestFabricLiveFullStackAcceptance$'
```

三个业务组织与独立运维方分别对应四个排序身份. 当前容器均由同一宿主和运维控制, 停机仅检验容器级故障和连续恢复. 应用层使用持久化 P-256 应用密钥, 测试 CA `did:web` 解析, 固定 W3C VC v2 本地上下文摘要与真实 ES256/SD-JWT 凭证和 `AccessEvidencePackage` 出示. 业务服务端点, 策略求值与订单事务见[网关执行规格](../../docs/IMPLEMENTATION.md#4-证据交付与网关执行).

## 4 管理与核账服务装配

管理服务库入口 `core/domain/registry` 的 `NewFabricService` / `NewFabricServiceWithDB` (或顶层装配 `bootstrap.StartFabricGatewayStack`) 连接已有部署与原交易日志 (`ledger.Journal`). 宿主经 `service/api/registry` 在验证客户端证书的 TLS 服务上挂载 Handler, 并运行 `RunRecovery`, 启动时恢复已受理的待定请求.

`POST /v1/management/RecoverIdentity` 只接受完整 `protocol.RecoveryDualProofBundle`, 不接受原始链码恢复参数. 宿主先重新核验原域内账号, 通过 `RegistrationCoordinator.IssueRecoveryChallenge` 保存一次性挑战. 受理时校验新应用密钥与新管理证书双证明, 当前注册机构和目标域 MSP, 对照服务端批准的完整挑战, 在同一事务消费挑战并保存从挑战派生的待提交请求. 重启恢复再次核对持久化批准与原请求的绑定; 没有批准的旧待定恢复请求拒绝提交. 同操作键精确重试返回原操作, 换操作键复用已消费挑战被拒绝.

`GET /v1/operations/{id}` 要求可信认证身份, 仅原发起身份或宿主明确授权的本域审计者可查询. 宿主每次启动调用 `SetOperationAuditors` 装配审计证书的 MSP 与指纹白名单, 仅声明审计角色不会获得权限. 受权查询仍返回 HTTP 200 与 `PENDING`/`CONFIRMED`/`FAILED`, 无认证或越权查询返回 403.

外部 `ledgerctl mcp` 的核账工具分别从 `RECOVERY_MTLS_CERT`/`RECOVERY_MTLS_KEY`/`RECOVERY_MTLS_CA`, `AUDIT_MTLS_CERT`/`AUDIT_MTLS_KEY`/`AUDIT_MTLS_CA` 和 `RECEIPT_MTLS_CERT`/`RECEIPT_MTLS_KEY`/`RECEIPT_MTLS_CA` 读取三个服务客户端的证书, 私钥与服务端 CA 文件路径. 客户端证书用 DID URI 和角色 OU 绑定恢复, 审计和回执服务, 通过 HTTPS 网关连接; `X-Caller-*` 头不能认证身份. 未配置认证客户端时, 核账工具保留 `UNKNOWN` 并返回配置错误. 进程内验收由宿主通过 `bootstrap.NewLocalMTLSClient` 显式装配三个固定身份的通道.

核账 C 服务在同一事务保存审计记录和 `order_outcome_outbox`. 嵌入式宿主用 `DeliverStoredReceipt` 交付该原回执, 服务重启或响应丢失时用 `DeliverPendingReceipts` 继续投递, 接收端按原 `caseId`/`sendRevision`/`checkNo` 和全部内容去重. `decision_evidence` 保存原出示和 DID 文档供历史复核, 这些数据库材料不属于公开证据导出.

启用 PostgreSQL 的项目回归统一通过 `//go:build db` 与 `testcontainers-go` 隔离运行 (也可通过 `TEST_POSTGRES_DSN` 指定外部库):

```bash
mise run test:unit
mise run test:db
```
