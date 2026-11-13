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

`fabric:up` 用创世块加入四个排序节点和 A/B/C 的 Peer. 首次 `deploy` 安装每域自己的 TLS 链码服务, 批准和提交定义, 核验初始化并保存 `registry/deployment.json`. `seed` 生成并持久化本实例合成夹具, 使用原操作键复跑. 夹具有效期 24 小时, 超期可用历史模式复查, 新的在线验收使用独立实例和新夹具. 复跑 `verify` 包含停机, 恢复及重启场景, 在独立实验实例运行.

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

重建生成新的 Compose 项目, 创世块, 证书, 数据卷, instanceId 和 deploymentId. 密钥与数据库口令留在 `.local/`.

## 3 取证和故障边界

`verify` 为每次运行分配独立目录, 保存公开运行材料, 完整块, 逐笔校验码, 原操作, 探针单调时间和通过或失败的判据. 必需判据失败或超时以非零状态退出. 默认验收上限 5 分钟, 可通过 `--timeout` 设定.

两项初始化中断回归各用一个刚启动且尚未执行 `deploy` 的独立空卷实例. 测试分别覆盖首次提案在背书前中断, 以及根已有效提交但部署清单尚未写出. 两项测试均会停止和恢复各自实例的 C Peer, 并完成部署.

```bash
mise run fabric:rebuild -- .local/fabric-init-retry-test 17200
FABRIC_INIT_RETRY_TEST_DIR="$PWD/.local/fabric-init-retry-test" mise exec -- go test -v -count=1 ./internal/fabric -run '^TestInterruptedInitialization$'

mise run fabric:rebuild -- .local/fabric-init-committed-test 17220
FABRIC_INIT_COMMITTED_TEST_DIR="$PWD/.local/fabric-init-committed-test" mise exec -- go test -v -count=1 ./internal/fabric -run '^TestDeploymentResumesAfterCommittedInitialization$'
```

三个业务组织与实验运维分别对应四个排序身份. 当前容器均由同一宿主和运维控制, 停机仅检验容器级故障和连续恢复. D0 的管理交易使用真实 Fabric 证书和背书, 应用材料为合成锚. 真实凭证, 策略求值与订单实验的判据见[实验计划](../../docs/experiments/实验计划.md).
