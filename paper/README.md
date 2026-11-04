# 论文 PDF 索引

与 [论文.md](论文.md) 的板块编号保持一致.

- **核心阅读 8 篇: 全部已下载.** A 板块 3 篇, B 板块 3 篇, C 板块 2 篇; 交叉关联见主清单.
- **补充阅读 5 篇: 全部已下载.** 明确区分正式研究论文, 立场论文和预印本.
- **候选记录 3 篇: 未下载, 不计入上述 13 篇全文.** 原因见下表.

阅读时可从 B₁的三个问题回查材料. 身份是谁核验的查 A1, 一次挑战如何绑定持有者查 B2, 委托范围为何不能扩张查 C2. 各篇机制的适用边界见[论文清单](论文.md), 本项目实际采用的编码和权限规则见[协议编码](../docs/implementation/协议编码与测试向量.md)和[委托授权与策略](../docs/design/委托授权与策略.md).

## 已有阅读材料

| 想追的机制 | 本地材料 |
| --- | --- |
| A2 的临时密钥如何绑定登录凭据 | [zkLogin 阅读笔记](10.1145/3658644.3690356.阅读.md) |
| B1 的隐藏属性证明如何构造 | [zk-creds 组会笔记](10.1109/SP46215.2023.10179430.组会.md) |
| B2 如何将属性证明绑定到认证会话 | [FIDO-AC 阅读笔记](usenix/usenixsecurity23-yeoh.阅读.md) |

## 文件组织与版本

继续按 DOI 中的 `/` 分层保存为 `paper/<DOI 前缀>/<DOI 后缀>.pdf`. 文件名使用正式论文 DOI, 并不表示本地内容必定是出版排版版; 具体版本见表格.

USENIX 官方条目未列 DOI, 保存为 `paper/usenix/<官方论文标识>.pdf`. ICML 的 S4 官方页面未列 DOI, 沿用 `paper/pmlr/v267/south25a.pdf`. 不为这些条目编造 DOI. S5 的 DOI 是 arXiv 预印本 DOI, 不代表正式同行评审发表.

页数包括可能存在的会议封面与附录. 本地有全文不代表已完成阅读, 独立核实安全证明或复现实验. 原始 PDF 保持原样.

## 已下载核心论文

| 编号 | 论文 | DOI / 官方标识 | 本地文件 | 页数 | 来源与版本 |
| --- | --- | --- | --- | --- | --- |
| A1 | SoK: Trusting Self-Sovereign Identity | `10.56553/popets-2024-0079` | [PDF](10.56553/popets-2024-0079.pdf) | 17 | [来源](https://petsymposium.org/popets/2024/popets-2024-0079.pdf); PoPETs 正式版 |
| A2 | zkLogin: Privacy-Preserving Blockchain Authentication with Existing Credentials | `10.1145/3658644.3690356` | [PDF](10.1145/3658644.3690356.pdf) | 20 | [来源](https://arxiv.org/pdf/2401.11735v2); 作者完整版本; arXiv v2, 2024-09-27 |
| A3 | Delegatable Anonymous Credentials from Mercurial Signatures with Stronger Privacy | `10.1007/978-981-96-0888-1_10` | [PDF](10.1007/978-981-96-0888-1_10.pdf) | 42 | [来源](https://scottgriffy.com/papers/spdac.pdf); 作者扩展版本; 不是出版排版版 |
| B1 | zk-creds: Flexible Anonymous Credentials from zkSNARKs and Existing Identity Infrastructure | `10.1109/SP46215.2023.10179430` | [PDF](10.1109/SP46215.2023.10179430.pdf) | 56 | [来源](https://www.cs.umd.edu/~imiers/pdf/zkcreds.pdf); 作者完整版本 |
| B2 | Fast IDentity Online with Anonymous Credentials (FIDO-AC) | `usenix/usenixsecurity23-yeoh` | [PDF](usenix/usenixsecurity23-yeoh.pdf) | 19 | [来源](https://www.usenix.org/system/files/usenixsecurity23-yeoh.pdf); USENIX 官方正式版, 含会议封面 |
| B3 | EVOKE: Efficient Revocation of Verifiable Credentials in IoT Networks | `usenix/usenixsecurity24-mazzocca` | [PDF](usenix/usenixsecurity24-mazzocca.pdf) | 18 | [来源](https://www.usenix.org/system/files/usenixsecurity24-mazzocca.pdf); USENIX 官方正式版, 含会议封面 |
| C1 | Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization | `10.1145/3649835` | [PDF](10.1145/3649835.pdf) | 39 | [来源](https://arxiv.org/pdf/2403.04651v2); 作者扩展版本; arXiv v2, 2024-03-08 |
| C2 | Practical Delegatable Anonymous Credentials From Equivalence Class Signatures | `10.56553/popets-2023-0093` | [PDF](10.56553/popets-2023-0093.pdf) | 26 | [来源](https://petsymposium.org/popets/2023/popets-2023-0093.pdf); PoPETs 正式版 |

## 已下载补充论文

| 编号 | 论文 | DOI / 官方标识 | 本地文件 | 页数 | 来源与版本 |
| --- | --- | --- | --- | --- | --- |
| S1 | Efficient Blockchain-Based Mutual Authentication and Session Key Agreement for Cross-Domain IIoT | `10.1109/JIOT.2024.3351892` | [PDF](10.1109/JIOT.2024.3351892.pdf) | 14 | [来源](https://qyzhang.tech/papers/cui2024BC-crossAKA.pdf); 作者托管的正式版; 沿用既有文件与原下载来源, 2026-10-25 书目核查时检索到作者现用 qyzhang.com 镜像 |
| S2 | DACP: Enforcing a dynamic access control policy in cross-domain environments | `10.1016/j.comnet.2023.110049` | [PDF](10.1016/j.comnet.2023.110049.pdf) | 11 | [来源](https://researchmgt.monash.edu/ws/files/567346039/556683261_oa.pdf); 大学仓储中的正式版 |
| S3 | A Novel Model for Authority and Access Delegation Utilizing Self-Sovereign Identity and Verifiable Credentials | `10.1109/ACCESS.2025.3582312` | [PDF](10.1109/ACCESS.2025.3582312.pdf) | 33 | [来源](https://dk.um.si/IzpisGradiva.php?id=93898&lang=eng); 大学仓储中的正式版; 来源为下载入口页 |
| S4 | Position: AI Agents Need Authenticated Delegation | `pmlr/v267/south25a` | [PDF](pmlr/v267/south25a.pdf) | 21 | [来源](https://raw.githubusercontent.com/mlresearch/v267/main/assets/south25a/south25a.pdf); PMLR 正式版; ICML 立场论文 |
| S5 | CRSet: Private Non-Interactive Verifiable Credential Revocation | `10.48550/arXiv.2501.17089` | [PDF](10.48550/arXiv.2501.17089.pdf) | 17 | [来源](https://arxiv.org/pdf/2501.17089v3); arXiv v3, 2025-09-17; 预印本 |

## 未下载的候选记录

| 编号 | 论文 | 正式 DOI | 状态与处理 |
| --- | --- | --- | --- |
| P1 | FDAAC-CR: Practical Delegatable Attribute-Based Anonymous Credentials With Fine-Grained Delegation Management and Chainable Revocation | [10.1109/TIFS.2025.3587182](https://doi.org/10.1109/TIFS.2025.3587182) | 最终版未取得.[ePrint 页面](https://eprint.iacr.org/2024/610)明确警示旧稿含错误, 已撤回, 应使用 TIFS 最终版及支持材料. 因此没有下载旧稿替代正式版. |
| P2 | Blockchain-based access control architecture for multi-domain environments | [10.1016/j.pmcj.2024.101878](https://doi.org/10.1016/j.pmcj.2024.101878) | 旧清单已有记录; 完整 PDF 未取得.2026-10-25 书目核查时出版页面返回 403, 原作者上传入口也曾受限. |
| P3 | A zk-SNARK-Enhanced Blockchain-Based Lightweight Scheme for Cross-Domain Authentication | [10.1016/j.bcra.2026.100550](https://doi.org/10.1016/j.bcra.2026.100550) | 旧清单已有记录; 完整 PDF 未取得.2026-10-25 书目核查时出版页面返回 403, 未重新确认最终卷期状态. |

不得将 HTML 错误页面保存为 PDF, 不以相近题名, 错误旧稿或摘要页替代正式论文全文. 候选取得可靠全文后, 应同时更新[论文清单](论文.md)和本索引.

## 论文版本与来源说明

- A2 下载固定的 arXiv v2; B1 继续使用原有 56 页完整版本, 未换成较短的会议版本.
- A3 的 ePrint PDF 下载返回 403, 改从作者主页获取 42 页扩展版本, 并核对题名; 没有冒充 30 页出版排版版.
- C1 的 Amazon Science PDF 入口返回 404, 改为固定的 arXiv v2 扩展版本, 共 39 页.
- S1 保留原下载来源; 主清单另外提供2026-10-25 书目核查时检索到的作者现用域名 `qyzhang.com` 的 PDF 入口.
- 仅改变旧论文的阅读分类与编号; 旧编号与新编号对应关系见 [论文.md](论文.md) 末尾.

## 索引维护

论文的本地路径, 来源, 版本与页数统一记录在本索引中, 本地全文合计 333 页. 新增论文或取得新版本时, 更新本索引和[论文清单](论文.md). 区分作者扩展版, 出版排版版和预印本, 保留已撤回稿的风险说明.
