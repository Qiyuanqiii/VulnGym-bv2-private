# T2 语义上下文与可解释弃答：离线修正记录

2026-09-07，接续 [真实复测](deepseek_t2_retest_receipt.md)。用户确认临时 key 已撤销；本轮不读取、不重用凭证，不调用外部模型。**本轮完成的是上下文和弃答契约修正，尚未验证真实模型的完整产出或质量提升。**

## 1. 改了什么

上一轮已证实：plan 看到了 diff，但独立的 semantic_judge 请求没有继承它；候选代码很短，defer 契约没有具体理由字段。本次没有猜测模型的隐藏理由，也没有通过放宽条件强行输出。

- 新生产 CLI 同时启用 evidence-first planning、semantic context 和 reflection context；初始语义判断及后续自检收到同一份有界证据。默认 `LocalStructuredT2Producer()` 保持原回放契约。
- 公告使用**已经加载的原文**，不再把上游已截成 2,000 字符的摘要当作可扩展全文。复用加载工件，不增加文件读取。
- diff 来自已执行的固定 before/fix 比较，不依赖模型记住上一轮请求；保留文件、提交及截断标记。
- 源码只经现有 `git_show` 能力读取声明路径、固定受影响 commit；每个文件本阶段最多读取一次。小型 Python 函数用 AST 选取含装饰器的完整函数文本；其他语言、无法解析的 Python 或大型函数提供明确标识的附近行窗口。只解析文本，不运行目标源码。
- 源码窗口保留精确起止行、文本摘要哈希、tool call ID、证据 ID、候选关联和预算遗漏。覆盖状态只表示**候选锚点所在行**，不是整个候选跨度或完整调用关系。新上下文也写入既有 EvidenceItem，供弃答后回读。

| 上限 | 当前值 |
| --- | ---: |
| 公告字符 | 6,000 |
| diff | 最多 8 个，每个 2,000 字符 |
| 源码文件 / 代码块 | 8 / 12 |
| 源码总字符 / 单块字符 | 16,000 / 3,000 |
| 默认窗口 | 锚点前后各最多 24 行 |
| 优先保留完整 Python 函数 | 含装饰器共不超过 120 行，且字符预算允许 |

较长函数、过长单行、未覆盖候选和公告/diff 截断均明确标识；不是全仓检索或完整调用图。先按现有候选顺序保留关键操作，再保留入口；这只是确定性预算策略，不是角色优先级的正确性证明。

## 2. 新的 semantic defer 契约

`semantic_judge` 请求版本为 2；select 仍只有原来的七个字段。defer 时原六个内容字段必须为 null，另外必须提供 `defer_details`：

- `reason_code`：insufficient_context / ambiguous_candidate_roles / unsupported_relationship / conflicting_evidence / insufficient_advisory / no_supported_candidate。
- `missing_fields`：从 entry_point、critical_operation、relationship、version、classification、title 中选取，非空且不重复。
- `evidence_refs`：1–8 个当前语义请求中提供的证据 ID，不接受其他任务或历史引用。
- `explanation`：非空、最多 400 字符的简短说明，不是隐藏推理过程；禁止控制字符。

通过结构校验后，以 `model_defer_details:` 开头的规范化 JSON 保留在现有 `missing_information` 中；并标注 `assessment_origin=model_self_report_not_independently_verified`。**它是模型自述，不是独立确认的缺陷或正确结论。**证据不足仍不产出伪 Entry、不调用 T1。缺少详情、非法引用或 defer 同时塞入候选内容会记为 invalid_model_output，不能伪装成合法弃答。

DeepSeek 提示词版本改为 `t2-json-v3`，身份随提示词哈希变更；此版本**还未真实调用**。plan/reflection 的简短 defer、repair 阶段的上下文范围未在本轮扩展。

## 3. 同两条公开输入的离线探针

复用上次运行的已许可 input 文件；不加载旧模型回答，不访问评测答案，不改写真实运行目录。诊断 backend 明确是非模型脚本，故意在语义阶段 defer。

| 上下文 | Langflow / Python | Flowise / TypeScript |
| --- | ---: | ---: |
| 公告字符 | 2,164，未截断 | 6,000，截断 |
| diff 数 | 2 | 1 |
| 源码块 / 字符 | 12 / 14,686 | 2 / 2,263 |
| 完整 Python 函数文本 | 11 | 0，使用行窗口 |
| 未覆盖候选 | 1，代码块上限 | 0 |
| 完整 Entry / T1 调用 | 0 / 0 | 0 / 0 |

Flowise 两个窗口为 39、25 行。Langflow 仍有测试文件候选且一项未覆盖；范围限制可见，但未证明候选角色正确。该探针只验证上下文投递及记录，不计入语义质量、模型成功率或 A1 完成度。

复现命令沿用 [路由探针说明](t2_evidence_first_planning.md#3-两条公开输入的离线诊断)，将占位目录替换为已许可资料包；无须配置 key。计数和执行时 producer 哈希见 [offline_probe.json](../evidence/t2-semantic-context-20260907/offline_probe.json)。

## 4. 验证与历史保护

Python 3.13.12；临时目录在 D 盘。针对性回归 **276 项：275 通过、1 跳过、0 失败，181.523 秒，退出 0**。新增 27 项覆盖函数/窗口边界、装饰器、字符预算、遗漏标记、defer 字段与当前证据引用、真实工件写入及两次只读回验、上下文一致性、模型/工具预算和默认旧契约。跳过的是既有 Windows 符号链接权限用例，未更改权限。

```powershell
python -B -m unittest tests.test_t2_semantic_context tests.test_t2_evidence_first_planning tests.test_deepseek_backend tests.test_t2_production_cli tests.test_closed_loop_batch tests.test_real_t2_producer tests.test_model_runtime tests.test_t2_execution tests.test_t2_inputs tests.test_t2_toolbox tests.test_producer_contracts tests.test_producer_context tests.test_closed_loop_replay tests.test_submission_prediction tests.test_critical_resolver tests.test_patch_analyzer -q
```

另将修改前 `bda058f3690002305b750ad510ffe0b479621649` 的 producer 和本次默认 producer 在同一个构造 Git 样例上执行：draft、全部模型请求和控制器最终记录的规范化字节相同。没有重跑 70 条历史批次。上次真实复测的 15 个运行文件长度和 SHA-256 全部保持匹配；其 dataset digest 仍为 `227b305523e44894bf10eb6dd7099fa33ba8c7207d80a13222736a8dbefd5915`。

输入/代码磁盘字节哈希与检查结果见 [verification.json](../evidence/t2-semantic-context-20260907/verification.json)。换行转换可能改变工作树字节哈希，完整实现以承载本记录的 Git commit 为准。用户确认撤销凭证属于用户报告，不冒充服务端核验；没有尝试用已撤销 key 验证撤销状态。

## 5. 下一步 / #12 → #97

1. 新代码已通过离线检查；如继续实测，须先取得新的受限调用授权和可用凭证，保持相同两条开发输入、同一预算、新输出目录，不使用已撤销 key。
2. 若仍 defer，读取新增的具体缺失项与引用，再核对上下文覆盖或提取能力；不得靠模型自述就断言原因已被证实。若产生完整 Entry，核对版本、入口/关键操作角色、分类和 trace；机器数据仍为 verify=0。
3. 真实可用性确认后，冻结新输入评价口径；原 40 条中的 5 incorrect 核查、35 uncertain 分类、代表性质量评价与交验演示仍未完成。

#12、#90、#94 保持开放。不启动旧 finalizer、后台轮询或扩大付费批次。上次真实复测完整产出为 0 的结论不变；不能把这次离线改进称为 T2 主产品已经通过验收。
