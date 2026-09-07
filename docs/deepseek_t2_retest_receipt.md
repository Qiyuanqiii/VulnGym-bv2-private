# DeepSeek 两条公开输入复测：路由通过，语义阶段仍弃答

2026-09-07，执行代码 `8313bac54ccd139a339c768914123a5705562b32`。
**两条真实输入都已进入语义判断，但完整 Entry=0、T1=0；T2 自主生产验收仍未完成。**
本次使用用户重新提供并授权的限额临时凭证，调用已结束并立即提醒用户撤销。

## 1. 固定范围

- 与 [首次试跑](deepseek_t2_smoke_receipt.md)相同的 Langflow/Python、Flowise/TypeScript 两条公开开发输入；6 个准备文件逐字节不变，未加载旧模型回答或评测答案。
- 模型 `deepseek-v4-pro`，官方端点；提示词 `t2-json-v2`，high，max_tokens=8192，单请求超时 120 秒，不重试。
- 每条最多 3 次模型调用、全批最多 6 次，每条最多 80 次本地工具调用，repair=0。不是货币金额上限，不扩大任务集。
- 使用新 D 盘目录 `deepseek-retest-20260907-v1`，不覆盖首次试跑。没有启动旧 finalizer、后台监控或定期轮询。
- 这些是已有开发输入，不是未见盲测；原 40 条候选的质量统计不变。

## 2. 实际结果与前后对比

| 指标 | 首次试跑 / t2-json-v1 | 本次复测 / t2-json-v2 |
| --- | ---: | ---: |
| HTTP 200，服务返回模型标识匹配 | 2 | 4 |
| plan / semantic_judge | 2 / 0 | 2 / 2 |
| reflection / repair | 0 / 0 | 0 / 0 |
| 本地工具调用（均 success） | 18 | 23 |
| 完整 Entry / T1 | 0 / 0 | 0 / 0 |
| 弃答位置 | resolve_critical | semantic_judge |
| 弃答代码 | no_vulnerable_side_candidate | model_deferred |

两条 plan 均选择 `guard`，两条 semantic_judge 均返回合法的 defer 结构，而不是传输、认证、额度、输出截断或 JSON 格式失败。CLI 退出 0、manual_review=2 只表示终态记录成功，**不是 2 条完整候选已交人工，也不是质量通过**。

本次服务报告输入 token **11,770**、输出 **2,935**，合计 **14,705**。实际金额未测量，以管理平台账单为准。首个请求开始到运行结束记录约 54 秒；4 个请求均未重试，没有额外问模型解释原因。

## 3. 已证实的上下文限制，而非臆测模型理由

本地按实际记录的模型身份、输入和固定代码重建请求；4 次请求与规范化响应哈希全部匹配。此步骤不调用外部模型、不改写原输出，仅用于核对当时送入模型的结构。

| 语义请求内容 | Langflow | Flowise |
| --- | ---: | ---: |
| 公告摘要字符 | 2,000 | 2,000 |
| 关键操作候选 | 3 个，代码各 1 行 | 2 个，代码各 1 行 |
| 入口候选 | 12 个，代码各 1–11 行 | 1 个，代码 1 行 |
| 独立 diff 上下文 | 未传入 | 未传入 |
| 具体模型弃答理由 | 无此响应字段 | 无此响应字段 |

新 plan 确实看到了 diff，但每次模型调用没有隐式聊天历史；semantic_judge 没有继承 plan 的 diff。这是可核实的上下文缺口。候选代码和摘要可能不足以支撑角色/关系判断，但**目前不能认定这是两条弃答的唯一原因**，也不能宣称选出的 guard 一定是正确标注。

工件中的 `semantic evidence was insufficient for a safe selection` 是 producer 固定生成的通用说明，不是模型提供的具体缺证据理由。当前严格响应契约只允许 action=defer，其余字段为空，因此不足以给人工一份具体的“缺什么、怎么补”说明。

## 4. 回验及凭证处理

- 两个独立进程执行 `verify_closed_loop_artifacts`，均退出 0，规范化 stdout 完全相同；验证的是工件闭合，不是语义质量。
- dataset SHA-256：`227b305523e44894bf10eb6dd7099fa33ba8c7207d80a13222736a8dbefd5915`。
- 本次结束后离线回归 `tests.test_deepseek_backend` 与 `tests.test_t2_evidence_first_planning`：40 项通过、0 跳过、0 失败，26.716 秒；没有新增模型请求。
- 检查 21 个本次运行文件，合计 98,120 字节；未发现凭证格式串。15 个运行元数据/输出文件的精确长度和哈希另列，6 个输入文件与首次试跑一致。
- 用户确认上一枚凭证已撤销。本枚只用于本次运行，进程已退出，已通知用户到平台撤销；尚未核实本枚的服务端撤销状态。没有把凭证副本写入源码、Git、Issue 或运行工件，也不声称聊天中的原始消息被清除。

只读回验示例（替换为本次运行的 output 目录，不运行 producer）：

```powershell
python -B -c "import json; from vulngym_agent.orchestrator.replay import verify_closed_loop_artifacts; print(json.dumps(verify_closed_loop_artifacts(r'D:\T2-output\retest').to_dict(),sort_keys=True,separators=(',',':')))"
```

净化证据：[摘要与配置](../evidence/deepseek-retest-20260907/summary.json)、[运行文件哈希](../evidence/deepseek-retest-20260907/runtime_files.json)、[实际请求计数/耗时/用量](../evidence/deepseek-retest-20260907/transport_events.jsonl)、[请求结构核对](../evidence/deepseek-retest-20260907/request_structure.json)。

## 5. 下一步，不直接扩大付费批次

1. 先在离线样例中补齐新生产语义阶段的有界 diff、必要函数/调用上下文，明确证据关联和截断；不以自动放宽事实条件、强行选候选解决零产出。
2. 为真实模型的弃答增加结构化、可引用证据的原因及缺失项；与工具能力不足、运行错误、格式失败分开，保留旧回放契约。
3. 对这两项做离线回归后再确认下一次受限复测；有完整产物后进行语义质量评价，再按 #97 的冻结口径选新资料。

#12、#90、#94 保持开放。路由改进已被真实请求证实，但没有因此产生合格完整数据；不能以“更保守”替代 T2 可用性与质量交验。
