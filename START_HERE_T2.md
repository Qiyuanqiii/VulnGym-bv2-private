# T2 工具：从这里开始

2026-09-10。主T2、辅T1。当前是可运行的工程候选，不是“高质量全部验收通过”。本页取代旧包之间反复切换的启动建议；旧运行、旧ZIP和旧视频仍保留原始版本。

## 1. 推荐交付形式

使用 `t2-submission-20260910-v3.zip`：当前源码、最新候选/T1/弃答JSONL、逐项复核、三页PDF、离线演示和历史视频集中在一包。打包源码提交与真实运行提交分开标注，校验器重算Git运行树，不能仅凭文件名“v3”认定同版。具体ZIP摘要及导出环境测试结果以发布时的包回执为准。

视频在 `media/archival/`，是旧结果讲解，不是当前现场生产。最新状态以 `demo.py`、`evidence/latest/` 和[逐项复核](docs/t2_current_review_20260910.md)为准。本包不含key、目标仓库、本机映射、原始对话或完整Git历史。

## 2. 接收方先做免费离线演示

在解压根目录运行：

```powershell
python -I -B verify_delivery.py
python -B demo.py
python -B demo.py --json
cd source
python -B -m vulngym_agent.t2_production_cli --help
python -B -m vulngym_agent.submission_prediction_cli --help
```

Python 3.13用于本次验证。核心CLI使用标准库，无需安装模型SDK；上述命令不调用模型。选定回归测试及D盘临时目录配置见包内README。完整开发测试的可选依赖见requirements-dev.txt；演示不要求先完成Linux正式签收。

只想核验ZIP而不解压，可使用仓库中的 `python -I -B scripts/verify_t2_submission_v3.py --zip <zip路径>`。先将ZIP摘要与发送者另行提供的回执比较；内部hash不是签名或语义正确证明。

## 3. 当前真实结果，不再混读旧状态

最新实际运行49959f9：6请求均成功返回结构化结果，无重试、无截断、89,577 tokens、退出0。同两份已看过输入中：1完整候选/T1 + 1自检弃答；产出1/2，不是新增盲测或准确率。

第1题没有完整Entry，原弃答保留；新复核纠正解释的源码先后顺序，但不据此finalized。第2题完整候选及T1均保留，T1为9 correct/7 uncertain；新候选九维AI开发自评4支持/1合理替代/4待定。分类有依据但粒度需确认；版本、入口角色、操作角色、trace仍待补证据。机器verify=0、状态manual_review。

最新8个公共文件及4类双回读已由[真实复测回执](docs/t2_stage_budget_retest_receipt.md)记录；本次打包不增加模型样本。旧v3诊断的截断和退出1不得改写成这轮退出0。

## 4. 真实生产的前置条件

当前支持单一GHSA、可解析修复提交及唯一父提交、显式源码路径；获准的tasks JSONL、公告/patch资料包、本地可信repo-map和固定Git对象都须预先准备。不是任意URL/PDF一键抓取器，也不执行目标项目。

另需有效临时凭证、资料发送许可和实际费用上限。所有已宣布结束使用的key不可复用。不要运行冻结的历史批次入口来“试一下”；应按[生产说明](docs/t2_production_runbook.md)准备新的输出目录，并核对[DeepSeek配置](docs/deepseek_t2_setup.md)。

默认等待120秒，可显式配置300秒；零自动重试。分阶段输出预算可显式设置plan=2048、semantic_judge=16384、reflection=4096，见[预算说明](docs/t2_stage_budget_receipt.md)。这些是上限，不是实际消耗，也不是质量或费用保证。

## 5. 验收和接下来的主线

[A1-A9当前验收表](docs/submission/acceptance_report.md)是主线，不以全部finalized作为唯一标准：

1. 有价值的完整候选、明确的不足与实际T1证据可以交验；没有完整候选的defer必须单列。
2. 仍需稳定的新报告产出和代表性质量评价，不能把同两题重复诊断算新样本。
3. 历史12条有反证的候选暂不采用，28条未评；分流不是实际修订错误。
4. 优先交可运行、有证据的包；若评审要求现场生产或操作录屏，单独安排，不拿旧视频替代。

#12/#97保留质量缺口；#99/#102核对交付和最终确认；#90/#94为可选工程，不占主T2交验时间。
