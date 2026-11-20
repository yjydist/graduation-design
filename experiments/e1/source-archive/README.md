# E1 迁移前源码归档

四轮旧采样以提交 `79125cc40855014c16fcfb0a962bc276202023d8` 为底稿, 在该版本上添加当时的 E1 子命令和驱动. 归档文件以 `.go.txt` 保存, 用于把运行清单中的源码摘要与实际字节对应起来.

| 历史运行 ID | 对应文件 |
| --- | --- |
| `run-8f53b15eb6cfc887` | `first/` 中的 4 个文件, 以及 `reference/baseline_cli.go.txt` |
| `run-584097e92389b59c` | `second/` 中的 4 个文件, 以及 `reference/baseline_cli.go.txt` |
| `run-e9278cc882927ca1` | `reference/` 中的 6 个文件 |
| `run-471362d68defc766` | `reference/` 中的 6 个文件 |

按表收集文件, 原路径均为 `internal/fabric/`. 去掉文件名末尾的 `.txt` 即得到该轮的源码. 首两轮的 `seed.go` 取自固定提交. 各轮清单 `fileSHA256` 中的所有文件均已按原字节复算匹配.

历史结果和原始运行记录见[E1 结果](../result.md). 迁移后的运行由[独立驱动](../README.md)发起.
