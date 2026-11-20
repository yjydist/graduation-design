# E1 离线复算结果 (run-f6b3cc4a627e1a49)

- 分析版本: `e1-analyzer/v1`
- 源运行 ID: `run-f6b3cc4a627e1a49`
- 原始运行目录: `experiments/e1-procurement/runs/run-f6b3cc4a627e1a49`
- 运行状态: `FAIL` (对账通过: `false`)
- 实际模型: `openai / deepseek-v4.1-flash`

## 关键计数

| 指标 | 离线复算值 |
| --- | --- |
| F01-F16 通过数 | 4/16 (失败 12, 上游阻断 9, 未执行 0) |
| 模型会话 / 工具调用 / 异常会话 | 6 / 0 / 6 |
| 记录的网关请求 | 2 |
| 主库报价 / 订单 / 决定 / 挑战 / 业务键 | 0 / 0 / 0 / 1 / 0 |
| 导出区块数 (连续性) | 45 (true) |

## RP/BM 主库与轨迹对账

| 检查项 | RP | BM |
| --- | --- | --- |
| F05/F15 模型签发落链 | false / false | false / false |
| F06 往返数 / 主库对账 | 0 / false | 0 / false |
| F06 订单金额 / 订单 ID | 0 / `` | 0 / `` |
| F07 Q1200 零订单副作用 | false | false |
| F08 同键重试复用原订单 | false (``) | false (``) |
| F06/F07 探针与区块核对通过数 | 0/5 | 0/5 |
| F14 过期拒绝 / F15 重签放行 / F16 绑定复算 | false / false / false | false / false / false |

## 失败与缺测诊断

- run status=FAIL stage=cases passed=4/16 failed=12 upstreamBlocked=9 notExecuted=0 llmErrorSessions=6
- root failure F05: rp: openai chat completions step 1: POST "http://127.0.0.1:8317/v1/chat/completions": 400 Bad Request {"message":"You have insufficient credits to make this request. Please purchase more credits to continue using the service.","type":"invalid_request_error","code":"BAD_REQUEST"}
- root failure F06: rp: openai chat completions step 1: POST "http://127.0.0.1:8317/v1/chat/completions": 400 Bad Request {"message":"You have insufficient credits to make this request. Please purchase more credits to continue using the service.","type":"invalid_request_error","code":"BAD_REQUEST"}
- root failure F07: rp: openai chat completions step 1: POST "http://127.0.0.1:8317/v1/chat/completions": 400 Bad Request {"message":"You have insufficient credits to make this request. Please purchase more credits to continue using the service.","type":"invalid_request_error","code":"BAD_REQUEST"}

## 原始输入文件摘要 (SHA-256)

| 原始文件 | SHA-256 |
| --- | --- |
| `blocks.jsonl` | `4bcc3e8077095f2e69c52be4539818350c45223def9821f38ac694e0443cc9c0` |
| `db-business-keys.json` | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| `db-challenges.json` | `75e0bd1e76c0387f4373d52e607d382b7ade5a002f10cbe7f9ac26f375a0a555` |
| `db-decisions.json` | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| `db-orders.json` | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| `db-quotes.json` | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| `llm-traces.json` | `4bc3104d81192c0c446d0a2287d90e6ffdce5e4b9be7f91019836656b6c8a9d4` |
| `manifest.json` | `27997001d9dfc67df39cb002aff990fe8e578586970bd96313dbb13617f50045` |
| `requests.csv` | `f61bbd4251f232de8442d70b03e6c527a78451e9405e911febd72071c1ab7f05` |
| `summary.json` | `414c58d863391eab3c954a9edd42b6dfca57aa23e462c25811394314a63dd78e` |
