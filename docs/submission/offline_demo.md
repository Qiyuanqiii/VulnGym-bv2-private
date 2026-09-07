# 当前已有结果的离线演示

2026-09-08。演示对象是既有真实生产结果、混合任务交接和后续自评，**不是新模型调用、盲测或最终成片**。
执行Python命令前将工作目录切到本私人分支，临时目录设到操作者批准的D盘目录；不要操作只读主工作区。

## 1. 先看真实数据和边界

本地t2-mixed-handoff-20260908-v1/handoff.json包含2个任务、1份完整候选及1份真实T1报告、1个defer。
原始数据仍verify=0，两个任务仍manual_review，T1整体现有判定仍uncertain。
交接JSON有9,663字节，文件SHA-256：d72d6d38e3ab9ed24d8d6aa4691e43ca627cd150ce307354f6392b7d77d7093b。

它含候选代码和报告证据，只转交获准评审或协作者，不公开整个包。

## 2. 在有原运行目录的机器回验

将下面两个值设为操作者已批准的实际路径，不是让程序重跑生产：

```powershell
$ReplayDir = '<existing-model-run>/output'
$HandoffFile = '<approved-handoff-directory>/handoff.json'
python -B -m vulngym_agent.submission_prediction_cli verify-handoff --replay-dir $ReplayDir --replay-dataset-sha256 0b779638a4fd9230133a97e2268e942d3daf48f46c7041e277232839a9662c22 --expected-task-count 2 --handoff-file $HandoffFile --handoff-sha256 54787d8ed7566dbbdff0d459684dd6e76feb67cd7fb5e0f784fb68668d853197
```

命令读既有replay并比对交接字节，不读取模型凭证，不发起新模型/目标代码执行。
没有原运行目录时，只能验证包内文件与计数，不能冒称重做了来源回读。

## 3. 展示两类评价，分母不能混

先看[历史12条逐案表](../../evidence/t2-quality-self-review-dev12-20260908/review_report.md)：
108项已考虑，38个事实支持、5个事实反证、5个事实待定；语义11支持、3合理替代、16反证、30待定。
这是已知错例富集开发自评。用DEV-004的错误路由或DEV-006的测试替身说明“能匹配源码不等于角色对”。

再看[当前模型单例](../../evidence/t2-current-candidate-self-review-20260908/review_report.md)：
6支持、1合理替代、2待定；可展示后补的路由→控制器→服务证据，但要明说它不是原模型trace。
这两组不是同输入、同策略的受控对比，不能用其数值差异宣称某改动带来了准确率提升。

在原分支可重新汇总开发评价：

```powershell
python -B scripts/prepare_t2_quality_review.py summarize --cohort evidence/t2-quality-review-dev12-20260907/cohort.json --cohort-sha256 2258428587893c05de812e6e1e6a1b1788edb9639c370e7b307069d581e1d180 --reviews evidence/t2-quality-self-review-dev12-20260908/reviews.jsonl
```

## 4. 转交预览压缩包

本轮另外制作的离线包内带README、文件清单、校验脚本、混合handoff、两组自评、任务目标与验收说明。
接收方解压后可用标准库Python运行`python -B verify_bundle.py`，无需API key或安装依赖。
包内校验只证明文件和内部计数一致，不证明独立人审、模型实跑或源码来源重新验证。

实际演示和核验结果记录在[机器记录](../../evidence/t2-offline-demo-20260908/verification.json)。
此包是交验预览，不是最终源码发布或完整提交：至少2份冻结后新输入、真实生产、最终环境与演示成片仍待完成。
