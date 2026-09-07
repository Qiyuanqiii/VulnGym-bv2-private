# T2 质量评价协议 v1：开发复核与新输入分开

> 2026-09-08，Refs #97 / #12。当前完成了准则、开发子集和复核工具准备，
> **没有完成实质语义评价，也没有新的真实模型产出**。
> T2 为主、T1 辅助，沿用 [当前任务参考](../current_task_reference.md) 的 A3/A5/A6。

2026-09-08后续：原固定cohort、空模板和初始null指标保持不变；另存的
[实际开发自评](../../evidence/t2-quality-self-review-dev12-20260908/review_report.md)现已考虑108项。
这是AI辅助自评，不是独立人审或新输入成绩。正文“未评价”描述的是协议首次发布状态，
不可用新版自评反写原模板。最新模型单例按[另一分组](../../evidence/t2-current-candidate-self-review-20260908/review_report.md)记录，不并入本协议的固定12条分母。

## 1. 这次固定了什么

协议 ID 为 `t2-quality-review-v1`。准则和开发子集由承载本文件的 Git commit 固定。
这是对已知历史结果的回顾性复核方案，**不是在历史生产之前预注册的试验**。
若日后改变选样、字段定义或分母，建立新版本并保留原包，不能按得分改写本版。

已固定的开发子集为 **12 份报告 / 12 个任务 / 12 个 Entry，覆盖 8 个仓库**，
包含全部 5 个原始 incorrect 和 7 个 uncertain；它们都是已有、看过输出的开发案例。
名字中的 `VG-TEST` 只是旧数据集分区，不意味着本次是未见盲测。

完整正式评价仍缺：至少 2 份规则/协议冻结后选定的新输入、实际运行与独立或明确标为
自评的内容评价，以及各业务/资料场景的核实。本协议不是 A5 达标声明。

## 2. 选样策略及已知偏差

原始 40 条中 29 条来自 openclaw/openclaw，不能用原数量直接声称样本均衡。
固定脚本不根据“容易判对”选案例，规则依次为：

1. 保留原 T1 报告为 incorrect 的全部案例；指定大小容纳不下时直接报错，不删错例。
2. 对尚未覆盖的仓库按规范 URL 排序，每仓库选择 task ID 最小的案例。
3. 剩余名额先选 EP/CO 文件名不同的案例，再按 task ID 排序填足；这只是位置布局，
   **不是已确认的跨文件调用关系**。
4. 最终按 task ID 排序签发 DEV 编号，记录每条选中原因、原 Entry/报告 SHA-256。

所得仓库为 openclaw、n8n、Flowise、langflow、open-webui、paperclip、NeMo、WeKnora。
这是**已知错例占比较高的开发子集**，不是随机抽样，不可把子集质量率外推为产品总体
准确率。生成顺序改变不会改变选择或输出字节。

分组边界：

| 分组 | 本次状态 | 允许作何用途 |
| --- | --- | --- |
| development_regression | 已固定 12 条，原40条保留 | 错例核查、迭代与开发自评，不充当盲测 |
| new_input | 至少2份的队列尚空，未选样、未运行 | 冻结后自主生产评价，不预写逐题 response |
| synthetic_exception | 有工具/契约单测，独立记账 | 验证失败处理与计数，不算真实报告质量样本 |

资料充分、缺 patch/版本不明、多候选、业务逻辑、应弃答等场景须由获准资料逐例核实。
当前仅记录仓库、原报告状态、原 trace 长度和是否异文件，`scenario_evaluation=not_reviewed`；
不由仓库名、原候选类别或不同文件名推断这些场景已经覆盖。

## 3. 九个维度及状态

| 维度 | 层面 | 评价内容 |
| --- | --- | --- |
| source_identity | fact | 来源、标识和报告对应关系 |
| version_basis | fact | 为什么是受影响版本，是否只假设 fix-parent 正确 |
| entry_location | fact | EP 的 commit/file/line/code 文本对应 |
| operation_location | fact | CO 的 commit/file/line/code 文本对应 |
| entry_role | semantic | 入口角色、可达性及合理替代 |
| operation_role | semantic | 与报告问题相关的操作/决策角色及合理替代 |
| trace | semantic | 每步及衔接的依据、空 trace 是否遗漏已知联系 |
| title_and_project | semantic | 标题、项目名与实际资料是否相符 |
| classification | semantic | 两级分类是否有依据、是否存在争议 |

每个维度恰好一种状态：

- `not_reviewed`：尚未做本维度的实质检查，理由/证据/动作均留空。
- `supported`：评审认为证据支持原值；必须填写证据引用和简短理由。
- `reasonable_alternative`：有依据的合理替代，不能只因为偏离单一参考就判错；同样须给证据和理由。
- `contradicted`：有反证或确定错误，填写具体矛盾及证据，不删除分母。
- `uncertain`：已经检查但不能裁决，明确缺口及下一步；与完全没检查分开。

证据引用/理由的格式校验只是填表约束，**不证明所引用内容真的支持结论**。
禁止直接复制 T1 状态、D3 supported、模型自述、引用存在性或 ±5 行命中作为语义结论。
已有五条截断错误的证据见 [根因记录](../lane_a_review_audit_receipt.md)；若采用修正
片段，应另存候选/报告，重新绑定摘要，不能把原始错误候选当成已经修正。

## 4. 评价者、记录和人工边界

从 `review_template.jsonl` 复制到新的结果文件再填写，保留模板和原数据不变。
每条都绑定 case ID、task ID、原 Entry SHA-256；不接受少行、重复案例或错配候选。

只要填写了一个维度，就必须记录真实 reviewer：

- name：实际人员/工具身份，不写不存在的独立评审。
- kind：human、ai_assisted_self_review 或 rule_tool。
- independence：self、independent_declared 或 unknown；工具/AI 不得声称独立人审。
- assessed_at：实际评价日期/时间；不回填一个尚未发生的时间。

工具不会核实人员身份或独立性，结果中明确 `reviewer_identity_and_independence_verified=false`。
汇总按评审类型、独立性声明列出案例数；机器和人审不混称，必要时分别发布其子集结果。
评价表不是 VulnGym Entry，不会更新 `verify`，也不会触发 finalized、签收或关闭 Issue。

## 5. 指标和分母

每个案例有 4 个事实维度、5 个语义维度。分别统计，不合成一个模糊的总分：

```text
已作裁决 = supported + reasonable_alternative + contradicted
支持的已裁决字段率 = (supported + reasonable_alternative) / 已作裁决
未解决字段 = uncertain + not_reviewed
```

分母为 0 时输出 `null`，不是 0% 或 100%。始终展示各状态数、全部字段槽位、
至少评价一项的案例数、所有维度已考虑的案例数，避免少量选择性裁决造成误导。
“所有维度已考虑”允许其中有 uncertain，**不是全部正确**。

上述都是**评价者填写结果的汇总**，不是工具独立证实的准确率。
完整产出率、schema 合规、读取/模型失败、耗时/用量、人工准备和修订次数仍须从实际
生产批次另账统计；本工具不能从12条完整历史候选推断这些生产指标，也不提供虚假 F1。

当前初始基线：12个案例、48个事实评价格、60个语义评价格全部 `not_reviewed`，
两个层面的裁决分母都为0，质量率都为null；评价者未填写，新输入选择数与新生产运行数均为0。

## 6. 已生成文件与操作

- [可读复核包](../../evidence/t2-quality-review-dev12-20260907/review_packet.md)：逐案原始绑定、已知限制和问题清单。
- [固定样本与准则](../../evidence/t2-quality-review-dev12-20260907/cohort.json)：12例、选样原因、来源分母和后续运行基线。
- [未填写模板](../../evidence/t2-quality-review-dev12-20260907/review_template.jsonl)：12行，不是完成的评价。
- [初始指标](../../evidence/t2-quality-review-dev12-20260907/baseline_metrics.json)：未评价状态，不是成绩单。
- [文件哈希清单](../../evidence/t2-quality-review-dev12-20260907/manifest.json)：其余4个文件的精确长度和SHA-256。

目录名保留本轮开始日期20260907，完成准备与文档记录日期为2026-09-08。
脚本为 [prepare_t2_quality_review.py](../../scripts/prepare_t2_quality_review.py)，只读取批准的
三文件提交包，不读取源码仓库、答案目录、模型凭证或网络资源。

核验命令中的输入路径为操作者配置占位符，替换为已许可的原始提交包。
首次 `prepare` 必须指定不存在的新输出目录；以下对已提交包只读核验：

```powershell
$env:TEMP='D:\VulnGym-bv2-runtime\tmp'
$env:TMP=$env:TEMP
$reviewArgs=@(
  'scripts/prepare_t2_quality_review.py','prepare',
  '--submission-dir','D:\T2-input\approved-submission-export',
  '--source-set-sha256','7ae810b9b157c071b77f494d69dacbbad9b062297cfb75af6c2c4f80d870ab48',
  '--submission-sha256','0ff24779c984e82f4f83773d3f9b1694a8a4a4bb2c0134c5c6eeaa89b1430508',
  '--task-count','40',
  '--system-commit','a65044bcac15c61be3e6b03b970521fc3bf15971',
  '--output-dir','evidence/t2-quality-review-dev12-20260907'
)
python -B @reviewArgs --check
```

按实际填写的文件汇总；下面先对未填写模板作可复现示例，不包含任何真实评价结论：

```powershell
python -B scripts/prepare_t2_quality_review.py summarize `
  --cohort evidence/t2-quality-review-dev12-20260907/cohort.json `
  --cohort-sha256 2258428587893c05de812e6e1e6a1b1788edb9639c370e7b307069d581e1d180 `
  --reviews evidence/t2-quality-review-dev12-20260907/review_template.jsonl
```

汇总打印 JSON，不写回输入文件。输出同时绑定固定cohort摘要、实际评价文件字节摘要
和评价内容规范摘要。评价文件允许正常JSONL空格格式；固定cohort必须保持原规范字节，
额外/缺失字段、未知状态、错摘要或未记录评价者的结论会拒绝，不能静默忽略。

## 7. 冻结后新输入及真实模型的下一步

下一次生产拟用代码 `a65044bcac15c61be3e6b03b970521fc3bf15971`、DeepSeek V4 Pro、
提示词 `t2-json-v3`（SHA-256 `d356413caa0251319945d9a1ff9e6e6c11a0cc17b8c379f35ee8d15d9275bf7b`）。
这是声明的待运行基线，不是本轮发生了真实调用，也不是说历史40条由此版本生成。

1. 先对已有两条开发输入进行受限真实复测，确认上下文修正后是否能产生有用候选。
   它们仍不算新输入盲测。临时key已撤销；实际调用要重新确认授权、可用配置和预算。
2. 再依据已冻结准则，从获准公开资料中选至少两份此前没有逐题预写response的新报告；
   在运行前另存输入清单、选择理由、取得的资料哈希、缺失项和运行配置，不根据结果换题。
3. 准备12条开发案例的实质评价；资料/语义场景不能确认时保留待定，不据此假称整个
   代表性样本要求已满足。新输入、开发案例、构造异常始终分母独立。
4. 评价修改应保留原结果、差异、评审身份和理由；若修改生产代码/prompt则登记新版本，
   受影响样本重新运行，不把不同版本结果混写成一次试验。

## 8. 本轮验证与验收状态

Python 3.13.12，临时目录在D盘。**90项针对性回归全部通过，8.640秒，退出0**，
其中27项新增用例；只改评价准备工具、测试和文档，不改生产运行时代码。

```powershell
python -B -m unittest tests.test_t2_quality_review tests.test_lane_a_review_audit tests.test_submission_prediction tests.test_deepseek_backend -q
```

覆盖错例不遗漏、仓库分层、输入顺序不影响字节、任务/候选绑定、零分母、事实/语义
分开、合理替代/反证/待定分母、评审身份声明、恶劣JSON与边界、拒绝覆盖、两次回读，
以及禁用网络的准备流程。单测中的评价内容全部是构造夹具，不混入本轮真实质量数据。

实际生成退出0，两次prepare --check均退出0，5个文件逐字节一致；summarize对初始
模板的规范结果与baseline_metrics一致。原40条entries/validation摘要仍匹配，未改写。
净化5文件合计53,086字节，机器路径/私有标记/凭据形态检查均零命中。

| 文件 | SHA-256 |
| --- | --- |
| cohort.json | `2258428587893c05de812e6e1e6a1b1788edb9639c370e7b307069d581e1d180` |
| review_template.jsonl | `ecc6c22635b671fe11f0da78fd154fb4e0b5154af9d41bba786293457cd3546a` |
| review_packet.md | `f7a369eb052b48df95aedb777e7cb1bbe6d945e98cf18a93ec1b6bb3b628c006` |
| baseline_metrics.json | `67ecc1951924810c9ed2171342d231ce48b5d89a84ebb34e1823f207fc6994bf` |
| manifest.json | `b7df2c3347bf44d611b96829ec82c2d628e1325d42c3b97872f4fd5d87189238` |

脚本本机磁盘字节SHA-256：`e414b8e4c73fdca814e25c112788a415d94cb24f8e1aef403ef4aedbebe234a6`；
换行转换可影响工作树字节，完整实现由承载本文件的commit固定。
本轮仅推进#97的可执行准备；A1/A3/A5仍未通过，#12/#97/#90/#94均保持开放。
