# VulnGym B-v2 自评报告模板

> 状态：未评分草稿。所有 `TODO` 必须由正式输出与隔离评分替换；不得用单元测试、
> smoke run、source-sealing receipt、训练结果或 Lane B Finding 冒充 Lane A 完整 Entry
> 的 blind-test 成绩。

## 1. 版本与评测身份

| 项目 | 值 |
| --- | --- |
| 最终 Git commit / tag | TODO |
| Python / OS / OCI image ID / inspect digest | TODO |
| 50/20 profile manifest digest | TODO（从正式可信输入记录） |
| Lane A task/replay、`entries.jsonl`、`validation.jsonl` digest | TODO |
| Lane B test replay manifest semantic/wire digest | TODO |
| Lane B train replay manifest semantic/wire digest | TODO |
| final-gate receipt semantic/wire digest | TODO |
| 独立 reviewer / 外部评分者 | TODO |
| 评测日期与评分工具版本 | TODO |

## 2. T1 数据自动化验证指标

以下指标对应考题 T1；Test 只能填隔离评分结果，Train 可填独立复算但必须标明数据面。

| 指标 | Test 20 | Train 50 | 分母、口径与证据 |
| --- | ---: | ---: | --- |
| 完成报告数 | TODO/20 | TODO/50 | `validation.jsonl` 行数与 task closure |
| 字段级准确率 | TODO | TODO | 字段判定与金标一致数 / 可评分字段数 |
| 找错召回率 | TODO | TODO | 被判错字段数 / 金标错误字段数 |
| `uncertain` 数与比例 | TODO | TODO | 按字段及按条目分别统计 |
| 证据可追溯 | TODO | TODO | 人工抽样 N=TODO；合理数/N |
| 鲁棒性 | TODO | TODO | 缺字段、坏 commit、404/缺缓存等用例；应不崩且输出 uncertain |

T1 结论：**TODO；外部评分前不得写“达到 0.85/0.90 阈值”或“通过”。**

## 3. T2 完整 Entry 生产指标

以下指标对应考题 T2，必须针对 Lane A 的完整 `entries.jsonl` 计算。Lane B
`findings.jsonl` 缺少完整 Entry 字段与 location `code`，不能填入本表。

| 指标 | Test 20 | Train 50 | 分母、口径与证据 |
| --- | ---: | ---: | --- |
| 完整执行 task 数 | TODO/20 | TODO/50 | Lane A run manifest |
| 输出 Entry 数 | TODO | TODO | `entries.jsonl` 实际行数 |
| 字段级 F1 | TODO | TODO | 外部 scorer；注明字段集合与 micro/macro 口径 |
| Hallucination 率 | TODO | TODO | 金标不存在或仓库不存在的值 / 被评分值 |
| Schema 合规率 | TODO | TODO | 严格通过 `SCHEMA.md` 的 Entry 数 / 输出 Entry 数 |
| 代码字段准确率 | TODO | TODO | 路径完全一致且行号在官方 ±5 容忍内 |
| `verify=0` 合规率 | TODO | TODO | 应为 100%；填真实分子/分母 |
| trace / 业务逻辑专项 | TODO | TODO | 分开报告样本量、口径与 scorer 版本 |

T2 结论：**TODO；不得把 exact replay、schema 单测或 D3 accept 当作语义正确。**

## 4. Lane B formal-70 工程闭合指标

本表证明 source-only D2/D3/D4/D0 与原生 Linux 门禁，不等价于 T1/T2 质量分。

| 指标 | Test 20 | Train 50 | 证据 |
| --- | ---: | ---: | --- |
| exact replay 闭合 task | TODO/20 | TODO/50 | replay manifest / receipt |
| finalized / D2 defer / D3 defer | TODO | TODO | `task_results.jsonl` |
| accepted Finding 数 | TODO | TODO | `findings.jsonl` |
| clean failure / poison / identity drift | TODO | TODO | final-gate receipt；目标均为 0 |
| 残留 container / execution image | TODO | TODO | 主机收口检查；目标均为 0 |
| train aggregate 独立复算 | 不适用 | TODO | 独立 evaluator |

## 5. 高质量条目复盘

只选训练集或经隔离评分确认且允许披露的测试条目，不复制隐藏答案或逐题测试真值。

| Task/Entry ID | 为什么质量高 | Planner→工具→Judge→Reflection | T1 反馈与修正 | 可披露评分依据 |
| --- | --- | --- | --- | --- |
| TODO | TODO：入口可达性、关键操作、trace 连续性等 | TODO | TODO | TODO |
| TODO | TODO | TODO | TODO | TODO |
| TODO | TODO | TODO | TODO | TODO |

复盘至少回答：哪些本地公告/patch/源码事实使结论可复现；模型最初选择了什么；T1 或 D3
否掉了什么；修正是否只改获批字段；最终仍有哪些语义只能由人工或外部 scorer 判断。

## 6. 拿不准、失败与系统性错误

| Task/Entry ID | 结果 | 不确定来源 | 当前处理 | 更好方案 |
| --- | --- | --- | --- | --- |
| TODO | uncertain / defer / FP / FN / field error | TODO | TODO | TODO |
| TODO | TODO | TODO | TODO | TODO |

| 错误模式 | 观测数/样本量 | 根因证据 | 影响指标 | 修正建议 | 是否需重跑 |
| --- | ---: | --- | --- | --- | --- |
| Entry Point 可达性证据不足 | TODO | TODO | 代码字段准确率/召回 | 调用图/框架路由解析 | TODO |
| Critical Operation 误定位 | TODO | TODO | 代码字段准确率/Hallucination | 数据流/污点摘要 | TODO |
| Trace 不连续 | TODO | TODO | 字段级 F1 | 跨文件 symbol resolution | TODO |
| 漏洞/fix commit 混淆 | TODO | TODO | F1/Hallucination | parent/merge/backport 裁决 | TODO |
| 标题/分类语义过拟合 | TODO | TODO | 字段级 F1 | 本地公告证据与反例校准 | TODO |
| Reviewer 过宽或过严 | TODO | TODO | precision/recall | 固定准则与反例集 | TODO |

## 7. 工程、安全与诚实声明

- 已实现优势：严格 schema、固定 task identity、有界工具与预算、ordered exact replay、
  原子发布、双 digest、独立 readback、test-first 和 OCI 隔离控制面。
- 已知限制：Lane A 没有正式在线模型 backend；Lane B 不调用 T1 且输出不是完整 Entry；
  全字段 `required_check` verifier、AST/调用图/数据流语义与复杂版本裁决仍不完整。
- TODO：填写跨平台 CI、native Linux 资源/残留、70-task 时长和失败恢复事实。

本报告只引用可披露摘要和 digest。gold、密钥、原始 source mapping、目标源码快照、宿主
路径及未净化日志不进入公开包。若任一 TODO 未完成，最终结论必须保留“未完成”或
“未验证”；机械闭合、D3 accept 和 digest 均不能替代数据质量评分。
