# verifiable-protocol Specification

## ADDED Requirements

### Requirement: 静态验签缓存与动态状态及披露范围隔离

协议验证器 SHALL 支持 `B1` 模式的并发安全静态验签缓存, 缓存键 SHALL 严格绑定 `(SHA256(rawMaterialBytes), alg, appKeyId, appKeyVersion)`. 静态验签缓存命中 SHALL 仅跳过椭圆曲线签名计算, 不得缓存或跳过动态状态, 密钥版本, 域资格或声明范围核验; 当 T 同钥续发域认证并收缩 `claimNames` 范围 (如移除可选声明 `department`) 后, 隐藏未获准可选声明且包含全部必需声明 (`domain`, `role`) 的原有效 SD-JWT 出示 SHALL 通过核验, 披露已移除声明的出示 SHALL 返回 `403 ISSUER_SCOPE_INVALID`, 且系统 SHALL 不根据未披露摘要推断属性名或填充策略输入.

#### Scenario: 命中静态验签缓存但密钥已轮换时返回 KEY_VERSION_STALE

- **WHEN** `B1` 凭证在密钥版本 `1` 下已完成一次静态验签缓存填充, 随后 `B1` 在链上轮换应用密钥 (`appKeyVersion` 升至 `2`) 或 `IB` 换钥但请求仍携带旧版本材料触发静态缓存
- **THEN** 启用静态验签缓存的验证端在固定高度采用新块后命中旧材料摘要仍确定性返回 `403 KEY_VERSION_STALE` 或 `403 DOMAIN_CERTIFICATION_INVALID`, 绝不沿用缓存绕过状态或密钥版本检查
- **AND** 更换为匹配新密钥版本与重签材料后验证通过并记录缓存命中与未命中统计

- **AND** 每次请求仍必须在当前固定高度快照 `h` 上核对目标主体与签发者的 `Identity.Status == ACTIVE`, `Identity.KeyVersion == cachedKeyVersion` (不匹配返回 `403 KEY_VERSION_STALE`), `Domain.CurrentCertificationID` 以及有效区间.

#### Scenario: T 同钥收缩声明范围后隐藏与披露属性的边界判定

- **WHEN** 原 `B1` SD-JWT 凭证合法包含合成属性 `department` 与必需声明 `domain`/`role`, 随后 T 同钥续发域认证仅移除 `department` 声明资格, 保持原凭证, `G2` 与 `Q800` 不变, 并分别以隐藏 `department`, 披露 `department` 和省略 `role` 提交访问
- **THEN** 携当前域认证重签 `KB-JWT` 且仅披露 `domain`/`role` 的隐藏出示核验通过, 披露 `department` 时返回 `403 ISSUER_SCOPE_INVALID`, 省略必需声明 `role` 时返回 `400 INVALID_DISCLOSURE` 或 `INVALID_SCHEMA`
- **AND** 隐藏 `department` 通过核验时未披露摘要不推断属性名, 且策略输入中不包含未披露声明名
