# 300秒同输入诊断：请求已返回，仍未产出完整候选

2026-09-09，Refs #12 / #97。本轮用量已结束并通知用户撤销key。没有自动重试或使用剩余一次名额继续调用。

## 实际结果

| 项目 | 观察值 |
| --- | --- |
| 正式执行源码 | `17175b2559272215a12f7f0cf425326a8440cac9` |
| 运行树 | `5d8cfbc7f0bc0c50190310a25d56f6524375251e` |
| 固定输入 | 原两份已见诊断输入；不是新样本或盲测 |
| 模型配置 | DeepSeek V4 Pro / t2-json-v4，high、8192输出上限、单请求300秒 |
| HTTP请求 | 5次，全部成功；plan 2、semantic_judge 2、reflection 1 |
| tokens | prompt 57,864 + completion 9,829 = **67,693**；缓存命中2,304、未命中55,560 |
| 耗时 | 进程218.475秒（含隐藏输入等待及本地工作）；HTTP累计176.099秒 |
| 受控工具调用 | 31次，均success |
| 完整Entry / T1 | **0 / 0** |
| 终态 | 两条manual_review；第一条语义阶段defer，第二条自检阶段defer |
| 进程退出 | 0，`processed_not_quality_verified`；模型调用错误0 |

这是已见输入的复测结果。原首次新输入0/2、历史开发1/2、旧120秒超时诊断分别保留，不能合并为新成绩或覆盖失败。两题完整产出率仍0/2；没有完整候选，候选语义准确率仍null，不以弃答率代替准确率。

本次每个请求均在120秒内实际返回，虽然配置上限300秒，也**不能证明放宽超时导致恢复响应**。只能说这次传输完整，收到了两次语义判断和一次自检结果。

## 模型给出的具体理由

1. `VG-NEW-20260908-001`：语义阶段`unsupported_relationship`。模型指出源码窗口标记关系未验证，diff中的条件变化没有在给定上下文内证明候选入口到关键操作的联系。
2. `VG-NEW-20260908-002`：语义阶段作出选择，随后自检以`ambiguous_candidate_roles`弃答。模型认为函数名提名的入口、变更条件行的操作角色及两者关系证据不充分。**中间选择不是已通过自检的完整Entry，不计入产出。**

这些是模型自述，不是独立复核结论，也不能据此确认唯一根因。原文、引用及阶段保存在[summary.json](../evidence/t2-context-retest-20260909-v2/summary.json)与[handoff.json](../evidence/t2-context-retest-20260909-v2/handoff.json)。

离线代码核对发现，[窗口生成器](../vulngym_agent/agents/t2_semantic_context.py)把`call_relationship_verified`固定为False，意味着采集器未核实关系，而不是已发现关系不成立。两条回答将“未验证”标记列入理由。因此下一步要分开核对：源码窗口是否真的缺少必要连接，以及模型是否把来源标记误读成必须预先具备的裁决。此处仅记录可核对的问题，不直接把标记改True，不强迫emit，也不宣布已定位全部原因。本轮未修改prompt或生产运行时代码。

## 授权、计费与凭证

用户本次重新提供同一枚凭证，在明确询问仍有效、20元平台硬限额及最多6次零重试范围后回复“授权”。这是本轮新的显式授权，不是agent自行沿用旧授权；执行开始记录保留。

输入清单保留准备时的`pending_fresh_key_and_explicit_operator_confirmation`文字，不事后改写冻结字节；实际授权由用户确认及run-start记录补充。只运行一次，没有第二份会话、后台补跑或轮询自动化。

67,693是本次5个成功请求的服务端报告用量，**不是该key自创建以来的总用量，也不是人民币账单**。同一key以前超时请求的费用仍未知；平台硬限额和有效性按用户确认，未声称程序独立查询。key已在进程结束时清空引用并通知用户撤销，尚未验证平台撤销。

## 回读和交付证据

- replay、review、handoff、verify-handoff各用两个独立进程执行，均退出0、stdout逐字节一致。
- 新旧运行各23个固定文件在采集前后保持原字节。没有删除、改写输入、原运行或旧ZIP。
- 新handoff为3,352字节，只保留两条弃答及理由，`formal_submission_export=false`。
- 数据集摘要：`582b6f59f18181f474105a39a648577397d820cd5835e85c09d255cda5609f64`。
- handoff逻辑摘要：`19f848b049d4fee522eb4869fd31ed85c45058cc2c34b6f2075c215c5b7fdb68`。
- handoff文件SHA-256：`dda02a2322d819a7538ddac45a03ea5c528ea648b252da547d1fdf60c42c5ef8`。
- [公共证据清单](../evidence/t2-context-retest-20260909-v2/manifest.json)：8文件、21,152字节；清单SHA-256 `fe2d89ce9228673c32ba5062bec0e9a1c1c35d49c9955b00257da0aa328fb735`。
- 发布前核验不含密钥格式、绝对本机路径、禁用私有数据标记；原始模型/工具日志不直接发布。

60项相关离线测试通过，37.327秒：`tests.test_t2_context_retest_v2_receipt`、`tests.test_t2_context_retest_v2`、`tests.test_submission_handoff`、`tests.test_t2_production_cli`。它们验证传输计数、弃答阶段区分及回读契约，不算60个真实模型样本。

可无key重复核对本次已完成结果：

```powershell
python -B scripts/collect_t2_context_retest_v2.py
```

采集器只接受本次已完成形态，遇不一致就保全，不启动生产。#12/#97的有效产出与质量问题仍未完成，保持开放；#90/#94不变。旧交付ZIP仍是原源码快照，本回执在后续仓库提交中，不伪称已在旧包内。
