# 三组采购基线实验

`mise -C experiments run experiment:baseline` 启动 `experiments/baseline/` 下的独立驱动, 使用确定性钱包工具, 实际时钟和真实持有者证明. 入口依次运行 C0, B0, B1, 每组分别执行 RP/BM 的 800 元与 1200 元用例, 每个用例先询价再按原报价下单. 首轮范围与原始字段见[实验变更设计](../../openspec/changes/archive/2026-11-18-m4-reproducible-baseline/design.md). 此入口用于接线与业务一致性验收, 正式性能采样见 [E4 微基准](../e4/method.md), [E5 开放到达负载](../e5/method.md)和 [E8 账本与通信开销](../e8/method.md).

在仓库根目录执行下列命令. 准备一个新 Fabric 实例, 显式指定新 C0 数据库名和不存在的证据目录. 入口自动部署, 签发, 登记及逐跳交付. 不要先对该实例执行 `ledger:seed`. C0 数据库与该轮 Fabric 视图数据库位于同一 PostgreSQL 服务的不同数据库中, 登记与业务表共同提交; C0 请求不连接 Fabric Peer, 块流或探针. B0/B1 共用已应用视图, 分别等待本进程的专用探针. C0/B0 关闭验签缓存, B1 每轮新建缓存.

```bash
mise run fabric:rebuild -- .local/fabric-baseline-a 18680
mise -C experiments run experiment:baseline -- \
  --dir .local/fabric-baseline-a \
  --c0-database baseline_c0_a \
  --seed 1109 \
  --out .local/baseline-a-evidence
```

`--dir`, `--c0-database`, `--out` 必须显式提供. 默认实例不能用于该入口. C0 数据库名须匹配 `baseline_[a-z0-9_]{1,48}`, 已有数据库不复用或清空. 每个实例使用独占运行标记, 失败后也不能沿用同一实例或覆盖原证据. 可选种子为 `1109, 1110, 1111, 1112, 1113`. 默认总期限为 10 分钟, 单次钱包动作为 15 秒, 可通过 `--timeout` 与 `--request-timeout` 设置.

复跑时改用新实例, 端口, C0 数据库名及证据目录, 逻辑种子保持一致.

```bash
mise run fabric:rebuild -- .local/fabric-baseline-b 18700
mise -C experiments run experiment:baseline -- \
  --dir .local/fabric-baseline-b \
  --c0-database baseline_c0_b \
  --seed 1109 \
  --out .local/baseline-b-evidence
```

每次尝试均保存 `manifest.json`, `requests.csv`, `order_checks.csv`, `summary.json`. 从清单的计划用例找到配置及 `case_id`, 再按动作定位请求和挑战, 用决定 ID 关联状态版本与主库核对. C0 保存 `revision` 和读取时点, Fabric 列为 `null`; B0/B1 保存实际块和原探针, 中心化列为 `null`. 汇总通过要求 12 次询价, 6 笔唯一订单, 6 次明确超额拒绝, 挑战与决定关联, 拒绝侧无订单或订单键, 跨组三组配对一致且 B1 出现验签命中. 比较两轮的 `fixture_digest`, `planned_cases` 及规范化业务事实, 实际部署, 密钥材料摘要, 状态版本, 随机 ID 和时点各自保留.

固定构建核验可先执行 `mise exec -- go build -o build/procurement-baseline ./experiments/baseline`, 两轮均用 `build/procurement-baseline` 接收相同参数. 保持运行期间源码与配置不变, 从清单核对 `binary_sha256` 和 `artifact_locks`.

清单的 `registry_input_digest` 标记 C0 预置输入. 采购开始前, 入口分别从 C0 主库和已应用 Fabric 视图读取共同登记锚点. 在 `registry_readback` 查看各自的锚点摘要, C0 版本和实际读取时点, Fabric 块高和块哈希, 以及各登记对象的版本. 锚点摘要按运行内比对, 对象版本按来源记录. 缺失或不匹配会在 `registry-readback` 阶段失败并保留证据.

准备失败, 超时或主库查询出错时保存已知记录与完整计划并非零退出. 未执行动作为 `dropped`, 未观测字段为 `null`; 主库查询出错不能推断订单不存在. 公开文件仅导出白名单字段, 入口扫描私钥编码, 访问令牌与实际披露盐. 失败处理定点测试可额外保留各样本的四个文件.

```bash
mkdir -p .local/baseline-fault-samples
BASELINE_FAULT_EVIDENCE_DIR="$PWD/.local/baseline-fault-samples" \
  mise exec -- go test -v -count=1 ./experiments/baseline \
  -run '^TestBaselineManagedFailuresRetainPlan$'
```

停止实验实例会保留卷和材料. 若只检验 C0 对 Fabric 服务的独立性, 保留 PostgreSQL 服务, 仅停止 Peer, Orderer 或链码服务; C0 所用的数据库本身仍须可用.

```bash
FABRIC_INSTANCE=.local/fabric-baseline-a mise run fabric:down
FABRIC_INSTANCE=.local/fabric-baseline-b mise run fabric:down
```

[基线规范](../../openspec/specs/reproducible-procurement-experiments/spec.md), [历史基线记录](../../infra/fabric/evidence/README.md#m4-采购基线).
