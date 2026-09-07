# Lane A：40 条历史候选复核分流与完整行截断修复

> 2026-09-07，Refs #12 / #97。仅离线检查既有标注的文本事实与报告限制。
> 未调用外部模型，未执行目标代码，未改写旧批次或人工 verify 标志。

## 1. 本次完成与没有完成的事

对摘要匹配的既有 40 个 Entry/报告对完成逐字段分流；只对 5 个 `incorrect`
入口读取固定 commit、指定路径的源码并比较精确文本。五条都确认是本工具的
**2,000 字符硬截断切断了最后一行**，不是位置检查器凭空误报。

新生产入口改用完整行片段；同一文件、commit 和起始行上的五个修正片段在
`line_tolerance=0` 下均通过位置事实检查。**这只证明修正后的文本位置，不证明
该位置是合理入口，不证明完整 Entry 正确。**原始报告仍为 35 uncertain、5 incorrect，
没有生成替代提交包或新的完整 T1 实际数据批次，新增 finalized=0。

40 份机器可读复核卡已生成，全部 `semantic_review_completed=false`、`verify=0`；
这是待审清单，不是已经完成的人工复核，也不是独立语义质量评价。

## 2. 五条确定错误的文本证据

每条均满足：旧 code 长度恰为 2,000 字符；从声明起始行读取的源码以旧 code 为
字符前缀，但旧 code 最后一行不是完整源代码行；只去掉这个末尾残行便得到
新生产搜索器返回的片段。新片段没有移动起点、修改源码或扩宽匹配容差。

| 合并 Entry | 报告 | 原始起始行 | 新片段结束行 | 新字符数 | 旧/新位置事实 |
| --- | --- | ---: | ---: | ---: | --- |
| entry-00006 | GHSA-3M3Q-X3GJ-F79X | 31 | 87 | 1,976 | incorrect → correct |
| entry-00021 | GHSA-W235-X559-36MG | 27 | 97 | 1,970 | incorrect → correct |
| entry-00024 | GHSA-V4PR-FM98-W9PG | 215 | 293 | 1,971 | incorrect → correct |
| entry-00025 | GHSA-65H8-27JH-Q8WV | 88 | 158 | 1,932 | incorrect → correct |
| entry-00038 | GHSA-5H2W-QMFP-GGP6 | 61 | 137 | 1,946 | incorrect → correct |

固定 commit、原文件字节 SHA-256、相对文件名 SHA-256、原/新 code SHA-256、任务
绑定和精确匹配行记录在复核卡的 `entry_excerpt_fact_check` 中。仅读取两个已许可
本地仓库中的这五个固定文件，不读取隐藏答案或原始映射。净化证据不包含目标源码、
原始证据文本、模型响应、凭据或机器绝对路径；复核者按原 Entry/报告摘要找回原资料。

## 3. 35 uncertain 不等于 35 份资料本身不足

40 个报告各有 16 个字段检查：**360 correct、5 incorrect、275 uncertain**。
其中 35 个 uncertain 报告各有 7 个待定字段；5 个 incorrect 报告仍各有 6 个待定字段。

| 从原报告确认的类型 | 字段数 | 含义与下一步 |
| --- | ---: | --- |
| checker_semantic_capability_gap | 160 | project、title、两级分类各 40；原报告明确说确定性检查不能判断，需对照资料评价，不能写成资料天然不足 |
| role_semantics_unverified | 75 | 40 个关键操作、35 个入口；原报告确认文件/行/code 事实，但角色语义未检查；需上下文及关系评价 |
| trace_completeness_unverified | 40 | 空数组符合 schema，但是否遗漏有依据的联系尚未确认；不能把空 trace 视为完整链路 |
| reported_incorrect_fact | 5 | 入口文本不匹配，根因及修正片段见上表；修正片段不替代角色复核 |

分流只识别原报告明确的字段/证据措辞；未知理由保留为 `unclassified_uncertain`，
不推断成缺输入、歧义或已完成检查。当前 40 条没有落入该未知类。
75 个角色字段的“事实已匹配”引用原报告口径；本轮零容差重检仅针对上表五个修正片段。

## 4. 实现范围与历史兼容

- `EntryPointSearcher(whole_line_snippets=True)` 在 2,000 字符上限内只保留完整行，
  并按实际片段计算 `end_line`；裁短时说明剩余构造文本未包含。
- 如果连首个非空锚点行都超出预算，不签发残行候选，记录
  `entry_snippet_first_line_too_large`。不通过截断字符伪装成位置事实正确。
- `LocalProductionTaskRunner` 强制启用该策略，不能显式禁用。调用链经
  `LocalT2ContextFactory` 和 `LocalT2Toolbox` 传递。
- 低层默认及旧 exact-replay 仍保留旧字符裁剪，避免已登记请求/证据字节改变。
  **旧回放复现可能保留原始格式错误；新数据应走生产入口。**没有重新生成或覆盖旧包。
- T1 的语义规则、位置容差、预算、人工 verify 和最终化条件均未放宽。

## 5. 复核包与复现

脚本：[audit_lane_a_review_offline.py](../scripts/audit_lane_a_review_offline.py)。
它验证三文件提交包、任务绑定和指定 digest，再输出新目录；不能据此声称重新
执行了 replay source/封存流程。已有输出不覆盖，`--check` 只重算并逐字节比较。

| 生成物 | 字节 | SHA-256 |
| --- | ---: | --- |
| [summary.json](../evidence/lane-a-review-audit-20260907/summary.json) | 1,560 | `317d5e89ce216459624ea978ee31b93208e4d4fa9b8688dbc689333af34311fa` |
| [review_cards.jsonl](../evidence/lane-a-review-audit-20260907/review_cards.jsonl) | 150,206 | `d74004538289054c3bdd30f22a3f8f0b2160665cedf7fa313be67775b2c981ea` |

替换下列两个操作者配置占位路径为已许可的原始提交包及可信仓库映射；不要使用
benchmark 隐藏标注目录。首次生成选择一个不存在的输出目录；核验已提交证据则保留
所示输出目录并加 `--check`，无需 key：

```powershell
$env:TEMP='D:\VulnGym-bv2-runtime\tmp'
$env:TMP=$env:TEMP
$auditArgs=@(
  'scripts/audit_lane_a_review_offline.py',
  '--submission-dir','D:\T2-input\approved-submission-export',
  '--repo-map','D:\T2-input\approved-repos.json',
  '--source-set-sha256','7ae810b9b157c071b77f494d69dacbbad9b062297cfb75af6c2c4f80d870ab48',
  '--submission-sha256','0ff24779c984e82f4f83773d3f9b1694a8a4a4bb2c0134c5c6eeaa89b1430508',
  '--task-count','40',
  '--output-dir','evidence/lane-a-review-audit-20260907'
)
python -B @auditArgs --check
if ($LASTEXITCODE -ne 0) { throw 'First readback failed; preserve artifacts.' }
python -B @auditArgs --check
```

本次首次生成退出 0，两次 `--check` 均退出 0，文件集与字节完全一致。
两文件合计 151,766 字节；未复制仓库、未启动旧 finalizer 或后台轮询。
对净化文件的机器路径/私有标记/凭据形态检查为零命中，40 卡的语义复核完成数与
非零 verify 数均为 0。原始包两份 JSONL 的长度、行数、摘要仍匹配；manifest
SHA-256 为 `dfd34e631a9d291767067da76f696126900555f26fc622de0e76e7bb259a0ec4`。

## 6. 回归与基线

Python 3.13.12，Windows，临时文件在 D 盘。**338 项：337 通过、1 跳过、0 失败，
214.070 秒，退出 0。**跳过的是既有 Windows 符号链接权限用例，没有修改权限。
新增 24 项覆盖整行/单行/Unicode/预算边界、真实本地位置检查、生产接线与 T1 保持
uncertain、复核分类、原记录不变、输出拒绝覆盖及损坏回读拒绝。

```powershell
python -B -m unittest tests.test_t2_semantic_context tests.test_t2_evidence_first_planning tests.test_deepseek_backend tests.test_t2_production_cli tests.test_closed_loop_batch tests.test_real_t2_producer tests.test_model_runtime tests.test_t2_execution tests.test_t2_inputs tests.test_t2_toolbox tests.test_producer_contracts tests.test_producer_context tests.test_closed_loop_replay tests.test_submission_prediction tests.test_critical_resolver tests.test_patch_analyzer tests.test_entry_search tests.test_git_fact_gate tests.test_entry_snippet_lines tests.test_lane_a_review_audit -q
```

另从修改前 `14cae64f5e50d5e9dac7f01c56e2ee8b186ac3ea` 加载原 entry-search，在同一个
含长函数的构造 Git 样例上与当前默认策略比较；搜索结果规范字节一致。将该原搜索器
接入默认 producer 后，draft、全部模型请求及控制器最终记录也与当前默认策略逐字节
一致。脚本 backend 是 test double；这不是新的模型服务实验或 70 条历史全量重跑。

代码由承载本记录的 commit 固定。本机验证时磁盘字节 SHA-256（换行转换会影响它）：

- 审计脚本：`a826554c68b5c1f5d9214667a42910804ceb746448358d3fb55b5845fd7ce68e`。
- `entry_search.py`：`b50143405b56f8d32acc813a46350b00bb002c2d60efb076234b6947b1e95772`。

## 7. 下一步与验收影响

A4 的历史报告分流、A6 的真实格式缺陷修正、A7 的五条错误根因核查已有证据，
但不是这些验收项或 #12 全部完成。接下来：

1. 对有代表性的 Entry 做版本/字段/角色实质评价；若采用这五个修正片段，应另建
   修订候选包并重新检查，保留旧错误记录，不直接替换旧 digest。
2. 新提示词/上下文的真实模型生产仍未复测；旧受限 key 已撤销，不重用、不自动
   扩大付费批次。下一次真实调用需要新授权与配置，不能把本轮离线测试计作产出。
3. 按 #97 冻结评价样本/准则，#99 补齐真实示例与交验演示。主线仍是 T2；不转回
   耗时的可选签收链，也不为提高 finalized 比例放宽语义判定。

#12、#90、#94 保持开放。历史 40 条的覆盖率、35/5 判定和新模型完整 Entry=0 的
真实成绩不因本次修复而被改写。
