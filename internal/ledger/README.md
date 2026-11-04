# 账本读取与管理模块

命令从项目根目录运行. 初始化/网络见[网络说明](../../infra/besu/README.md), 登记/交易见[合约说明](../../contracts/README.md). 当前实现 RP 登记状态读取, 不输出采购 allow, 不代替签名验证, OPA 或订单事务.

## 历史与在线模式

```bash
CGO_ENABLED=0 go run ./cmd/ledgerctl check --dir .local/besu-qbft --rpc-log .local/check-rpc.json
CGO_ENABLED=0 go run ./cmd/ledgerctl inspect --dir .local/besu-qbft --block 0x7db --rpc-log .local/inspect-rpc.json
```

默认使用 C RPC `http://127.0.0.1:18547`, 清单为 `<dir>/deployment-registry.json`, grant 为 `urn:grad:grant:RP-G1`. 可用 `--manifest`, `--rpc`, `--grant` 显式选择. grant 也接受 0x 前缀 SHA-256 索引. inspect 必须指定非负十进制或十六进制高度, 不接受 latest. 上述 0x7db 是本轮原实例的 G1 登记高度, 新实例须从自己的 seed 回执选择高度.

实际输出的精简摘录:

```json
{"mode":"historical","header":{"number":"0x7db"}}
```

```json
{"mode":"online","fresh":true,"header":{"number":"0xce4"}}
```

完整结果含 deploymentId, grantId, number/hash/timestamp, checkedAt, RootRecord, grants/tasks/identities/credentials/domains/certifications 和每项查询的 method/id/block/data. header.timestamp 为十六进制 Unix 秒. fresh 仅表示这次快照的新鲜度, 不表示委托链已通过应用验签或业务授权. 历史输出没有 fresh, 可以核对旧事实, 不产生当前可用结论.

记录中的 status 保留 ABI 数值: PENDING=1, ACTIVE=2, REVOKED=4. 管理操作的 PENDING/CONFIRMED/FAILED 是独立交易状态, 不能与登记对象的 status 混淆.

[在线结果](../../infra/besu/evidence/state/check.json)和[在线 RPC](../../infra/besu/evidence/state/check-rpc.json), [历史结果](../../infra/besu/evidence/state/inspect.json)和[历史 RPC](../../infra/besu/evidence/state/inspect-rpc.json)分别有 27 次同高度 eth_call. [模式对照](../../infra/besu/evidence/state/mode-comparison.json)确认历史查询未修改在线头, 两种模式均没有采购 allow.

## 一次快照如何装配

NewStateReader 接收可信清单, 客户端, 本地检查点目录和可注入时钟. Check 每次选一个已提交头, Inspect 使用显式高度. 部署绑定检查的代码及所有 view 也在该高度读取. 装配包括 G1 到根的路径, 任务, 签发者/受托者身份和凭证, 凭证签发机构, 主体及本地 C 服务所属域, 当前域认证和机构引导身份. 额外发现的依赖仍使用原高度. 当前每次最多 256 项依赖, 路径最多 33 个登记对象, 没有跨请求记录缓存或后台轮询.

指定高度缺失, 任一必要记录缺失/调用失败/输出失配, 或读取前后块哈希变化时返回错误和 nil 快照, 不交付部分结果, 不把失败项改为 latest. [装配故障证据](../../infra/besu/evidence/state/assembly-failures.json)包含各失败样本及全部 RPC.

## 在线头和双时钟

最高已见头按 deploymentId 存在 `<dir>/heads/<deploymentId>.json`, 更新使用独占读端锁和原子落盘. 重启核对该高度下限及哈希/时间, 同高异头, 节点回退, 检查点失配或部署变化均停止在线输出. 新头超过下限时仍回查原下限的哈希. 显式历史查询不更新在线检查点. [链头异常与恢复](../../infra/besu/evidence/state/highest-head.json)覆盖冲突, 回退, 重启, 部署变化及恢复可信新鲜头.

默认要求 `-1s <= now - blockTime <= 5s`. 首见块时固定单调预算 `max(0, 5s - max(0, now - blockTime))`, 重读/更换连接不续期. 用 Unix 墙钟值检测回拨, 避免 Go time.Time 的单调部分掩盖墙钟变化. Revalidate 可在校时后重新核验, 保留原预算, 后续仍检查部署/最高头/新鲜度. 进程重启从原块时间重算年龄, 不宣称跨进程且墙钟不可信时能延续单调预算.

[确定性时钟及交易恢复单元结果](../../infra/besu/evidence/state/unit-tests.jsonl)覆盖年龄/未来边界, 墙钟回拨, 单调超时, 重读/重连和超龄重启. 真实停链及独立重建的完整判据见[D0 证据](../../infra/besu/evidence/README.md).
