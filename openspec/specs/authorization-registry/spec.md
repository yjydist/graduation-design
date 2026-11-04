# authorization-registry Specification

## Purpose

提供由固定 T 根和已登记管理账户约束的最小授权状态登记能力, 使调用者能够通过真实管理交易建立 RP 委托夹具, 撤销其中的上级委托, 并核对成功, 回退及回执未知三种结果而不混淆业务授权结论.

## Requirements

### Requirement: 固定根与最小登记路径

登记系统 SHALL 在构造时固定 RootRecord 和 instanceId, 对外提供只读查询且不提供后续改根入口. 系统 SHALL 支持经 T 域引导, 首份域认证, 本域身份与凭证锚, 任务, RP G0 和 G1 的必要登记路径. 所有写入 SHALL 通过既有角色规则约束, 不提供绕过规则的测试入口. D0 的 A 域任务创建者 U SHALL 由受信部署清单在构造时固定, 只读暴露, 无运行期增授权入口; 登记任务仍须验证 U 当前管理账户, 身份归属, 域认证及引用凭证的状态, 版本和期限.

#### Scenario: 按角色建立 RP 夹具
- **WHEN** T 管理账户引导 A/C 域和 IA/IC 并登记首份认证, 各域获准账户登记 U, A1, C 服务及凭证锚, U 创建任务, C 登记交给 U 的 G0, U 登记交给 A1 的 G1
- **THEN** 每一步仅在所需依赖已登记且满足状态, 当前指针, 密钥版本和期限检查时成功, 最后 G0/G1 均为 ACTIVE
- **AND** 夹具标明凭证及应用签名验证尚未覆盖, 不能凭登记成功宣称采购请求已获授权

#### Scenario: 绕过域权限或父受托者
- **WHEN** 普通域账户试图执行 T 的域准入, 跨域注册机构登记普通身份, 非本域身份签发者登记凭证锚, 非资源方签 RP 根, 或非父 grantee 登记 G1
- **THEN** 交易执行回退, 不产生对应新记录, 不改变现有记录

#### Scenario: 未配置的合法主体尝试创建任务
- **WHEN** 与 U 同域且身份及凭证有效, 但未列入受信部署任务创建资格的主体提交任务登记
- **THEN** 交易执行回退且不产生任务; 由已配置 U 提交同等合法任务可成功
- **AND** T 和域管理员不能通过运行期入口增加任务创建资格

### Requirement: 标识和路径约束

登记对象 SHALL 按现有部署契约绑定本部署并拒绝 ID 复用. G1 SHALL 引用已登记的 parentId/parentDigest/rootId 和同一任务及模式, 绑定有效身份及凭证锚和密钥版本. 委托写入 SHALL 检查结构化父子关系, 时间和深度边界; 集合及金额等完整授权包含验证仍属于后续链下验证.

#### Scenario: 路径结构不匹配
- **WHEN** 从合法夹具分别只改变 G1 的父摘要, 根引用, 任务, 模式, 密钥版本, 时间边界或剩余深度
- **THEN** 每个违反链上结构化约束的登记交易回退, 其它对象保持原值
- **AND** 相同条件下合法字段的配对交易可成功, 完整集合包含验证不记为已通过

#### Scenario: ID 已经使用
- **WHEN** 已登记的委托被撤销后再次尝试使用同一个 ID 登记
- **THEN** 交易回退, 原终态记录和摘要保留

### Requirement: 撤销权限与版本竞争

委托撤销 SHALL 按已登记 msg.sender 关系检查 issuer, grantee, 本路径根签发者或资源方权限, 并核对 expectedRevision 及预期摘要. 撤销成功 SHALL 将状态置为终态 REVOKED 并增加 revision. T SHALL 不因身份根角色获得采购委托撤销权.

#### Scenario: 合法撤销和终态
- **WHEN** 有权管理账户使用当前 revision 和摘要撤销 ACTIVE 的 G1
- **THEN** 成功回执所在区块起 G1 为 REVOKED 且 revision 增加, 更早区块保留撤销前状态
- **AND** 后续尝试恢复该 ID 或以新操作重复执行终态转换均失败

#### Scenario: 两笔交易竞争同一版本
- **WHEN** 两笔独立交易使用相同有效 expectedRevision 修改同一个 G1 并进入区块
- **THEN** 至多一笔成功, 另一笔回退, 最终记录与成功交易一致且不存在部分写入

#### Scenario: 已许可账户仍无合约权限
- **WHEN** 已列入账户许可名单且有足够 gas 的无关账户或 T 管理账户直接提交撤销 G1 的交易
- **THEN** 交易可进入区块但 receipt.status 为 0x0, G1 的状态, 摘要和 revision 均不变

### Requirement: 交易结果和原交易失败证据

管理交易结果 SHALL 绑定原始已签交易, txHash, 调用者, 目标合约, 区块号/哈希和回执. 仅 status=0x1 SHALL 判成功, status=0x0 SHALL 判失败, 无回执 SHALL 保持 PENDING. 具体失败码 SHALL 只来自可信节点对原交易实际执行的回退数据; 不可得或不可解码时 SHALL 使用 TRANSACTION_REVERTED.

单交易 trace 与原回执的执行结果或 gas 不一致时, 系统 MAY 使用固定原 blockHash 的整块 trace, 但 SHALL 核对块号, 完整交易哈希顺序及原 transactionIndex/txHash, 确认选中结果 failed=true, gas 与回执一致且 trace 完整. 回退数据 SHALL 只来自该结果的 returnValue 或 depth=1 的 REVERT.reason. 任一绑定检查失败 SHALL 保留通用失败, 不以父块独立模拟猜原因.

#### Scenario: 成功回执核对
- **WHEN** 提交合法登记或撤销交易并取得回执
- **THEN** 验证回执与原 txHash, 目标合约及已确认块一致, 保存 gasUsed 和交易位置, 仅成功回执触发后续依赖步骤

#### Scenario: 原交易回退原因和缺失分支
- **WHEN** 已入块交易回退, 分别能够取得和暂时无法取得绑定原交易的回退数据
- **THEN** 前者保存并解码原始数据为对应错误, 后者记录失败和 TRANSACTION_REVERTED
- **AND** 不以最新状态或父块上的独立模拟猜测具体失败码, 补到原交易证据时只补充原因而不改写失败终态

#### Scenario: 回执暂不可见
- **WHEN** 已广播交易的回执查询超时或暂时不可见
- **THEN** 保持原交易 PENDING 并继续按同一 txHash 查询或重播相同已签字节, 不把它判为成功或重新分配 nonce 生成替代操作
