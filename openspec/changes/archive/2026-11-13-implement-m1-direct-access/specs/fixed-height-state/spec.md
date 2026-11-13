# fixed-height-state Specification

## MODIFIED Requirements

### Requirement: 所有依赖固定同一高度

系统 SHALL 从绑定部署的可信 Peer 按区块及块内交易顺序应用登记状态, 只采用 VALID 交易的写入. 每个完整区块的状态变更, 历史和区块检查点 SHALL 原子可见. 一次读取 SHALL 在单个 PostgreSQL `REPEATABLE READ` 只读事务内使用同一检查点对应的快照装配全部协议依赖 (`Root`, `Domain`, `Certification`, `Identity`, `Credential`, `Task` 与委托链), 输出部署标识, 区块号/哈希和本进程原探针期限. 在线定案取得业务行锁后若共享锁定 `fabric_head` 发现检查点已推进, 消费方 SHALL 回滚事务并用新视图整次重验.

#### Scenario: 查询之间确认撤销

- **WHEN** 读取从已应用块 h 开始, 在查 G0 和 G1 之间应用含 G1 有效撤销的区块 r, 且 r > h
- **THEN** 当前读取的域, 身份, 凭证锚, 任务及委托依赖均为 h 的值, 采用 r 或更高视图的下一次读取看到 G1 为 REVOKED
- **AND** 定案前若发现检查点已推进, 重新装配全部依赖并核验新视图, 状态读取结果只陈述登记事实及新鲜度

#### Scenario: 同块包含有效和无效写入

- **WHEN** 同一区块包含有效撤销和 MVCC 无效的替换, 或应用该块时在写历史与更新检查点之间中断
- **THEN** 读取者只能看到应用前或完整应用后的视图, 无效交易不改变状态
- **AND** 恢复后同块有效写入及历史记录只应用一次

#### Scenario: 锁后共享锁定检查点变化触发整次重验

- **WHEN** 在线请求在检查点 `h_1` 完成初验并随后进入数据库锁阶段, 期间后台视图应用器将 `fabric_head` 推进至 `h_2`
- **THEN** 网关在共享锁定 `fabric_head` 检测到 `h_2 != h_1` 后回滚当前事务并基于 `h_2` 重新装配快照执行完整初验与锁后复核
- **AND** 若连续重验仍遇高度竞争, 返回 `409 STATE_CHANGED` 且不写入业务结果
