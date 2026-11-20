# E1 离线复算结果 (run-3f8a7a6db26d582c)

- 分析版本: `e1-analyzer/v1`
- 源运行 ID: `run-3f8a7a6db26d582c`
- 原始运行目录: `experiments/e1-procurement/runs/run-3f8a7a6db26d582c`
- 运行状态: `PASS` (对账通过: `true`)
- 实际模型: `openai / deepseek-flash`

## 关键计数

| 指标 | 离线复算值 |
| --- | --- |
| F01-F16 通过数 | 16/16 (失败 0, 上游阻断 0, 未执行 0) |
| 模型会话 / 工具调用 / 异常会话 | 8 / 19 / 0 |
| 记录的网关请求 | 78 |
| 主库报价 / 订单 / 决定 / 挑战 / 业务键 | 11 / 8 / 27 / 38 / 19 |
| 导出区块数 (连续性) | 106 (true) |
| F06 决定区间非探针链上写入 | 0 (区块 (51, 54]) |

## RP/BM 主库与轨迹对账

| 检查项 | RP | BM |
| --- | --- | --- |
| F05/F15 模型签发落链 | true / true | true / true |
| F06 往返数 / 主库对账 | 4 / true | 4 / true |
| F06 订单金额 / 订单 ID | 80000 / `urn:grad:order:4eab56ee-41d2-4471-8631-e91829325f8b` | 80000 / `urn:grad:order:d7297627-92ea-4869-abaa-2acb5c6a6dbc` |
| F07 Q1200 零订单副作用 | true | true |
| F08 同键重试复用原订单 | true (`urn:grad:order:8fea6511-5c3c-4633-99cc-a456ffcfd796`) | true (`urn:grad:order:ef7ff7d5-e179-455e-831a-ff16dc38e9e1`) |
| F06/F07 探针与区块核对通过数 | 5/5 | 5/5 |
| F14 过期拒绝 / F15 重签放行 / F16 绑定复算 | true / true / true | true / true / true |

## 原始输入文件摘要 (SHA-256)

| 原始文件 | SHA-256 |
| --- | --- |
| `F08-bm.json` | `ba01c86504055301ddfe8b3e4432eb5079dbe0dc87447d8668842d79c2ac2422` |
| `F08-rp.json` | `10c04d28469b3a4123bd1f23f1361a9d4876743d6787752f1dc3ef4f2fd54d8a` |
| `F14-expired-bm.json` | `39e02a09c3170124ebce49f2165f8cab5acc900628071f96d2db134625e9f664` |
| `F14-expired-rp.json` | `39e02a09c3170124ebce49f2165f8cab5acc900628071f96d2db134625e9f664` |
| `F15-reissued-bm.json` | `dabc1218df60962f09f58276808decb21ca0231752dc800d8149051d7eeaf51d` |
| `F15-reissued-rp.json` | `1eba077518d641662fd6b1393ba6331a13a420058f09ff101ee7065d30ead37e` |
| `F16-bm.json` | `9c30ecc29b49fdfc6ca479eb72e704153180e2201555ce7ae96c446b0928cf61` |
| `F16-rp.json` | `e3197a514882669dd08de6aae09269d3ef26d21bf7928f6a82a41907f5275e35` |
| `audit.json` | `6a57524d5b689c3e29f23ccdc218c35b6dcfa65851dc2352abda9b3ca2e364a0` |
| `blocks.jsonl` | `c31538a081d4e63a5db4e27999c56774aa6c7afad6f9c8b91fb03f2a4a19c805` |
| `db-business-keys.json` | `6dfa7be1aa2a02da151f8eb071460db5faab3b5b4ecb6504580b545a3f84c9b0` |
| `db-challenges.json` | `94a5a60cc9e8d9e7a87307d1c3a0e8c3d3c427e38707c2829da3d1094d616f9f` |
| `db-decisions.json` | `6dd5e3a401451ea64c5a77f7eb8c1e5df71efca8502bf9f87f4ea3a18c2f2b73` |
| `db-orders.json` | `cad89549fe12b24cacdee20692536144ed33e48be919f4da4cb9982382f0dab9` |
| `db-quotes.json` | `96e0acc3de634b6bcdceb58a565a2a7c30040fabfede57215144da7fe095a52e` |
| `llm-traces.json` | `4728110a8bd330c1eea6e93e2d2473fc1187092285d201879190d98367dc8546` |
| `manifest.json` | `7ab2cac7e93e4aec686331c97e830be19a425bf230849c50c8f3dfd997409642` |
| `requests.csv` | `402c6b2ed07ad80ce0493717e67c6065d19212630df22a44aa55e3a407276794` |
| `summary.json` | `c077d9c5087a27d7b508fc300e4f71ee2f0424307643ab9352b3af8dbc20d593` |
