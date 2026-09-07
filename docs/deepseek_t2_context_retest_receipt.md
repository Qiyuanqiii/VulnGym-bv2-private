# DeepSeek T2 v3：同两条开发输入的真实复测

2026-09-08（香港时间）：**4 次实际请求全部返回成功，完整 Entry 仍为 0/2，T1 调用为 0。**
这次验证了具体弃答说明能落盘，但没有证明产出质量改善。不是新输入评价，也不关闭 #12/#97。

## 1. 固定范围与执行结果

- 执行代码：`8b8e265fff170c40e4cca4becc5d62b26063fe18`；生产实现未在本次运行中修改。
- `deepseek-v4-pro`、`t2-json-v3`，high、max_tokens=8192、单次超时120秒，无自动重试。
- 用户为复测提供新的临时凭证，要求用完通知。只处理原 Langflow/Python、Flowise/TypeScript 两条开发输入；6个准备文件逐字节保持不变，没有逐题预写模型回答。
- 每任务最多3次模型调用、80次本地工具调用、repair=0；整个批次最多6次HTTP请求。这是调用预算，不是金额上限。
- 新目录为 `D:\VulnGym-bv2-runtime\deepseek-context-retest-20260908-v1`；没有覆盖任何历史运行。

| 指标 | 实际结果 |
| --- | --- |
| HTTP成功 / 模型标识匹配 | 4 / 4 |
| 模型阶段 | plan 2，semantic_judge 2，reflection/repair 0 |
| 本地工具 | 26次，全部success |
| 完整候选 / 完整Entry / T1报告 | 0 / 0 / 0 |
| 合法deferred / manual_review | 2 / 2 |
| 输入 / 输出 / 总tokens（服务方报告） | 26,707 / 6,501 / 33,208 |
| 第一次请求至批次结束 | 106.369秒；不是包含准备、检查的整段开发耗时 |
| 金额 | 未测量，以服务方账单为准 |
| CLI退出码 | 0；表示允许终态完整记账，不是质量通过 |

UTC运行时间为2026-09-07 16:33:43至16:35:29，对应香港时间9月8日00:33:43至00:35:29。日期差异不是两个批次。

## 2. 具体弃答与核对边界

以下先区分**模型自述**和**我们实际核对到的候选事实**，不把弃答理由当独立语义裁决。

| 输入 | 模型自述 | 本地核对到的候选/范围事实 |
| --- | --- | --- |
| Langflow | `no_supported_candidate`；缺critical_operation、relationship | 当前3个关键候选在路由调用行、其return行和测试断言；公告/diff涉及的辅助函数查询位置没有作为可选关键候选签发 |
| Flowise | `ambiguous_candidate_roles`；缺entry_point、critical_operation、relationship | 关键候选只有旧代码第29行和第27行，未包含diff中的第28行；唯一入口候选是第1行import，明确只是同文件复核锚点；输入只允许service文件，没有route/controller文件 |

两个defer都有结构化说明、当前任务的有效证据引用和`model_self_report_not_independently_verified`标记。没有补充收费解释请求，也没有修改返回内容使其select/emit。

本地核对使用现有非模型诊断后端，在相同输入与生产代码上重新生成候选；明确是诊断脚本，网络调用0，未生成完整候选或运行T1。它验证候选可见范围，不证明某个位置是唯一正确答案。

实际落盘上下文：Langflow为12块、14,686字符、11个完整Python函数文本；Flowise为2个窗口、2,263字符。两条主要源码diff未截断，Langflow测试diff有截断。上下文增加不等于可选候选范围同时增加；当前semantic_judge只能选择控制器签发的ID。

代码层已核对：

- `agents/t2_toolbox.py`的关键候选来自固定diff的词法分析与位置核对，入口只在输入声明路径中搜索。
- `analyzers/patch_analyzer.py::_candidates`仍以有限词法模式、邻近旧行/上下文提名；不能覆盖所有报告描述的位置。
- `source/entry_search.py::_same_file_review_anchor`在没有识别到入口结构时选择第一个非空行，只作待复核锚点。将它放入可选入口清单不等于证明它是入口。

因此下一步应改善**候选提名覆盖与入口资料组织**。不宜继续只加上下文、扩大调用预算或把保守拒选改成强制出数。具体替代位置和关系仍需语义评价，不能仅凭模型理由就下正确结论。

## 3. 回验、文件与凭证

两次独立进程只读回验退出0，stdout逐字节相同。22个运行/输入文件合计170,213字节，回验前后哈希不变；公共投影为6个小文件、12,580字节。

运行dataset SHA-256：
`936e6158f2cd552603c4737a67898ff4493be79d56b050fec83340d10ef5e403`。

67项离线回归全部通过，55.267秒，退出0；它们不调用真实模型：

```powershell
python -B -m unittest tests.test_deepseek_backend tests.test_t2_semantic_context tests.test_t2_evidence_first_planning -q
```

临时目录统一在D盘。凭证通过不回显的输入交给前台进程，不读旧聊天或其他应用凭证，不写入源码、Git、Issue或运行文件；使用结束清除进程内引用并退出，随即提醒用户撤销。未访问管理平台核验撤销，也不声称聊天/工具调用记录中的原始输入已清除。

公共投影检查未发现凭证形态、绝对本机路径或排除的评测输入标记；没有发布完整公告/源码/模型原始响应。元数据投影脚本第一次误用了digest字段名，随后路径匹配又把`https://`误作盘符；修正这两处本地汇总错误后通过。**未因此重跑任何模型请求或改写正式运行文件。**

证据：[结果及模型自述](../evidence/deepseek-context-retest-20260908/summary.json)、[运行文件哈希](../evidence/deepseek-context-retest-20260908/runtime_files.json)、[输入哈希](../evidence/deepseek-context-retest-20260908/input_files.json)、[回验结果](../evidence/deepseek-context-retest-20260908/readback.json)、[请求计数/耗时/用量](../evidence/deepseek-context-retest-20260908/transport_events.jsonl)、[公共文件清单](../evidence/deepseek-context-retest-20260908/manifest.json)。

## 4. 下一步与验收状态

1. 先做候选覆盖的离线改进与反例回归：一般化提名有来源的旧侧变更位置，避免仅由新增条件或固定函数名决定可选范围；事实可核对不自动授予语义角色。
2. 将同文件复核锚点与真正入口候选区分；补齐有界入口线索/声明路径的准备流程。不能偷偷扩大文件访问范围或逐题硬编码答案。
3. 保留旧回放兼容性；用诊断样例验证候选覆盖后，再决定新的获准实跑。不复用本次key，不自动重复收费调用。
4. #97的12条开发复核包仍有108个未填写评价格，冻结后新输入仍未选定。本次两条不能重复计作“至少2份新输入”。

#12、#97、#90、#94均保持开放。历史40条候选及35 uncertain/5 incorrect不变；A1/A3/A5尚未通过。
