# Fabric D0 网络与验收

要求 arm64 macOS 或 Linux, Docker Engine 和 Compose, curl, shasum, OpenSSL, 以及 mise 中锁定的 Go 1.27.3. Fabric 3.1.5 的本机工具按发布归档 SHA-256 校验, Peer, Orderer, 链码 baseos 和 PostgreSQL 镜像按 OCI digest 锁定为 linux/arm64. 本机运行记录见[证据索引](evidence/README.md).

## 1 启动并复跑

在项目根目录执行.

```bash
mise run fabric:config
mise run fabric:up
mise run ledger:deploy
mise run ledger:seed
mise run ledger:check
mise run ledger:verify -- --out .local/fabric-evidence
```

`fabric:up` 用创世块加入四个排序节点和 A/B/C 的 Peer. 首次 `deploy` 安装每域自己的 TLS 链码服务, 生成或加载持久化 P-256 应用与测试 TLS 私钥 (`<instance>/private/`), 写出公开 DID 文档, 测试 CA 根证书与本地 VC v2 上下文摘要清单 (`<instance>/registry/`), 批准和提交定义, 核验初始化并保存 `registry/deployment.json` (不接受旧版无持久化私钥的合成 `bootstrap.json`). `seed` 为各角色持久化应用私钥并使用原操作键提交绑定制备部署的真实 ES256 `vc+jwt` 域认证, `vc+sd-jwt` 身份凭证, `taskSpec`, `G0`/`G1` (`grad-delegation+jwt`) 委托和示例 `AccessEvidencePackage`. 夹具有效期 24 小时, 超期可用历史模式复查, 新的在线验收使用独立实例和新夹具. 复跑 `verify` 包含停机, 恢复, 重启及协议验签场景, 在独立实验实例运行.

首次部署中断后, 先在同一实例重跑 `mise run ledger:deploy`. 原初始化已有效提交时, 续跑复用原安装包, 核对原交易和根记录并恢复部署清单. 若提示原初始化提案被拒绝并要求显式续跑, 执行以下命令.

```bash
mise run ledger:deploy -- --retry-initialization
```

续跑会查验原背书拒绝, 确认操作从未生成已签交易, 并向可信 C Peer 查询根是否为空. 条件齐备时, 使用关联原 txID 的新操作键提交同一引导清单. 原操作及新操作均保留在日志中, `registry/initialization.json` 记录已完成部署的初始化取证.

`check` 连接 C 的可信 Peer, 从原检查点续读并等待本进程探针被有效提交和应用. 输出该次装配的区块号和哈希, 原探针 txID, 发送和采用时点及期限. 默认探针间隔 1 秒, 原期限 5 秒. 可用 `--probe-role probe2` 使用第二个专用身份. `inspect --block <十进制块号>` 从已应用的保留历史复查, 默认目标为 G1, 可用 `--grant` 指定其它授权.

```bash
mise run ledger:build
build/ledgerctl inspect --block 24
build/ledgerctl operation --key seed/G1
```

历史输出只有登记事实. `invoke --key <操作键> --role <角色> --method <链码方法> --input <JSON文件>` 接受并推进操作. `operation --key` 查原操作并在需要时恢复. 同键同输入返回原操作, C Peer 停机时仍可从本地日志取得原提案, txID 和已签交易. 同键异输入返回 `OPERATION_KEY_CONFLICT`. 受理新操作或推进待定操作前核对可信 Peer. 结果字段区分 PENDING, CONFIRMED 和 FAILED.

## 2 停止和独立重建

`mise run fabric:down` 移除本实例容器及网络, 保留实例目录和命名卷. 再次启动沿用原通道, package ID, 登记和 PostgreSQL 检查点. 如需重建, 指定尚不存在的本地目录和未使用的连续端口范围, 例如下列命令. 默认实例使用 `.local/fabric-d0` 和 17000-17009.

```bash
mise run fabric:rebuild -- .local/fabric-d0-rebuilt 17100
FABRIC_INSTANCE=.local/fabric-d0-rebuilt mise run ledger:deploy
FABRIC_INSTANCE=.local/fabric-d0-rebuilt mise run ledger:seed
FABRIC_INSTANCE=.local/fabric-d0-rebuilt mise run ledger:verify -- --out .local/fabric-evidence
FABRIC_INSTANCE=.local/fabric-d0-rebuilt mise run fabric:down
```

重建生成新的 Compose 项目, 创世块, 证书, 数据卷, instanceId, deploymentId 以及新的 T 根/角色应用密钥与测试 TLS 证书. 私钥与数据库口令留在 `.local/` 和 `<instance>/private/`.

## 3 取证和故障边界

`verify` 为每次运行分配独立目录, 保存公开运行材料 (含 `materials/protocol/` 中的 DID 文档, 测试 CA 证书, 本地上下文清单与非合成凭证/委托/出示包并扫描确认零私钥泄漏), 完整块, 逐笔校验码, 原操作, 探针单调时间和通过或失败的判据. 必需判据失败或超时以非零状态退出. 默认验收上限 5 分钟, 可通过 `--timeout` 设定.

两项初始化中断回归各用一个刚启动且尚未执行 `deploy` 的独立空卷实例. 测试分别覆盖首次提案在背书前中断, 以及根已有效提交但部署清单尚未写出. 两项测试均会停止和恢复各自实例的 C Peer, 并完成部署.

```bash
mise run fabric:rebuild -- .local/fabric-init-retry-test 17200
FABRIC_INIT_RETRY_TEST_DIR="$PWD/.local/fabric-init-retry-test" mise exec -- go test -v -count=1 ./internal/fabric -run '^TestInterruptedInitialization$'

mise run fabric:rebuild -- .local/fabric-init-committed-test 17220
FABRIC_INIT_COMMITTED_TEST_DIR="$PWD/.local/fabric-init-committed-test" mise exec -- go test -v -count=1 ./internal/fabric -run '^TestDeploymentResumesAfterCommittedInitialization$'
```

M3 定点回归通过 `FABRIC_M3_TEST_DIR` 显式指定已部署并完成 `seed` 的实验实例. 可选择 `offline`, `agent`, `e6`, `faults` 或 `management` 子测试定位失败; `authority` 会修改域认证和管理证书绑定, 应使用干净实例. 定点回归的事件和结果保存到实例目录的 `m3-regression/`, 完整联合验收仍使用 `ledger:verify`.

```bash
FABRIC_M3_TEST_DIR="$PWD/.local/fabric-d0" mise exec -- go test -v -count=1 -timeout=5m ./internal/fabric -run 'TestM3LiveAcceptance/(agent|e6|faults|management)$'
```

三个业务组织与实验运维分别对应四个排序身份. 当前容器均由同一宿主和运维控制, 停机仅检验容器级故障和连续恢复. D0 的管理交易使用真实 Fabric 证书和背书, 应用层已切换为持久化 P-256 应用密钥, 测试 CA `did:web` 解析, 固定 W3C VC v2 本地上下文摘要与真实 ES256/SD-JWT 凭证和 `AccessEvidencePackage` 出示; 业务服务端点, 策略求值与订单实验的判据见[实验计划](../../docs/experiments/实验计划.md).

## 4 管理与核账服务装配

管理服务库入口 NewFabricManagementOperationService 连接已有部署与原交易日志. 宿主在验证客户端证书的 TLS 服务上挂载 Handler, 并运行 RunRecovery, 启动时恢复已受理的待定请求. management 定点回归使用真实 mTLS HTTP, 两笔背书竞争, 原块校验及保留 txID 的重启恢复.

`POST /v1/management/RecoverIdentity` 只接受完整 `protocol.RecoveryDualProofBundle`, 不接受原始链码恢复参数. 宿主先重新核验原域内账号, 通过 `RegistrationCoordinator.IssueRecoveryChallenge` 保存一次性挑战. 受理时校验新应用密钥与新管理证书双证明, 当前注册机构和目标域 MSP, 对照服务端批准的完整挑战, 在同一事务消费挑战并保存从挑战派生的待提交请求. 重启恢复再次核对持久化批准与原请求的绑定; 没有批准的旧待定恢复请求拒绝提交. 同操作键精确重试返回原操作, 换操作键复用已消费挑战被拒绝.

`GET /v1/operations/{id}` 要求可信认证身份, 仅原发起身份或宿主明确授权的本域审计者可查询. 宿主每次启动调用 `SetOperationAuditors` 装配审计证书的 MSP 与指纹白名单, 仅声明审计角色不会获得权限. 受权查询仍返回 HTTP 200 与 `PENDING`/`CONFIRMED`/`FAILED`, 无认证或越权查询返回 403.

外部 ledgerctl mcp 的核账工具分别从 RECOVERY_MTLS_CERT/RECOVERY_MTLS_KEY/RECOVERY_MTLS_CA, AUDIT_MTLS_CERT/AUDIT_MTLS_KEY/AUDIT_MTLS_CA 和 RECEIPT_MTLS_CERT/RECEIPT_MTLS_KEY/RECEIPT_MTLS_CA 读取三个服务客户端的证书, 私钥与服务端 CA 文件路径. 客户端证书用 DID URI 和角色 OU 绑定恢复, 审计和回执服务, 通过 HTTPS 网关连接; X-Caller-* 头不能认证身份. 未配置认证客户端时, 核账工具保留 UNKNOWN 并返回配置错误. 进程内验收由宿主显式装配三个固定身份的通道.

核账 C 服务在同一事务保存审计记录和 order_outcome_outbox. 嵌入式宿主用 DeliverStoredReceipt 交付该原回执, 服务重启或响应丢失时用 DeliverPendingReceipts 继续投递, 接收端按原 caseId/sendRevision/checkNo 和全部内容去重. decision_evidence 保存原出示和 DID 文档供历史复核, 这些数据库材料不属于公开证据导出.
