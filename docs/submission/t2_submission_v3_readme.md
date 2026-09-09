# VulnGym T2：当前源码与真实结果交验候选包

2026-09-10 v3。主T2、辅T1。**可运行工程、真实记录和明确复核说明；不声明高质量全部完成。**

## 先看当前结果：无需key，不收费

使用Python 3.13，解压到空间充足的普通目录。在解压根目录执行：

```powershell
python -I -B verify_delivery.py
python -B demo.py
python -B demo.py --json
cd source
python -B -m vulngym_agent.t2_production_cli --help
python -B -m vulngym_agent.submission_prediction_cli --help
```

这些命令不联网生成新数据，不运行目标项目。它们校验并解释既有真实两题诊断：**1份完整候选及原T1，1次自检弃答**。原批次6请求/89,577 tokens/无重试/退出0；本演示新增请求0。退出0不是质量通过，产出1/2不是准确率。

## 文件怎么找

| 文件 | 内容与使用边界 |
| --- | --- |
| `data/latest/entries.jsonl` | 第2题的完整候选，verify=0；不是已认证正确数据 |
| `data/latest/validation.jsonl` | 原T1报告：9 correct、7 uncertain；非独立人审 |
| `data/latest/deferred.jsonl` | 第1题原reflection弃答，不算完整Entry |
| `evidence/latest/` | 最新真实运行的8个原始公共文件，含完整handoff、摘要与用量 |
| `evidence/current-review.json` | 本次两个任务的AI开发复核，原始输出不改写 |
| `output/pdf/T2-design.pdf` | 当前三页设计、真实结果、边界和下一步 |
| `source/` | 固定提交导出的运行代码、schema、测试、说明和选定公开历史证据 |
| `media/archival/T2-existing-results-demo.mp4` | 201秒历史结果讲解，旧画面、合成旁白；非当前实况或操作系统录屏 |
| `MANIFEST.json` | 打包源码commit、实际运行commit、运行树、逐文件摘要 |

最新状态用`demo.py`和PDF查看；旧视频有已过时的结果与待办，仅作历史开发过程说明。完整Git历史可在私人仓库按manifest的source_commit核对：`Qiyuanqiii/VulnGym-bv2-private`，访问需对应权限。选定源码文档中的历史链接若未随包附带，可在该提交的私人仓库查阅。

## 内容复核的关键结论

第1题：旧297行未改赋值对应新332行；新策略检查在309-330行，位于赋值之前。纠正原解释的先后关系，不等于证明候选角色或生成完整Entry。原弃答保留。

第2题：新分类XSS与公告浏览器JavaScript执行描述相容，作为较宽分类合理；粒度仍需确认。九维开发自评4支持/1合理替代/4待定，版本、入口角色、操作角色、trace需补证据。原T1、manual_review和verify=0均不变。

两题是已看过输入的诊断，不是新盲测。历史12条/8仓库的错例富集自评与其余28条未评数据分开处理；本次没有修好历史反证，也不把暂不采用当作质量提升。

## 运行回归测试

核心CLI和以下选定测试使用Python标准库；测试需要本机Git，部分以本地回环服务模拟响应，无外部模型调用。不要直接把全部测试发现当作本包支持的安装验收；可选开发依赖另见`source/requirements-dev.txt`。

在自己的工作盘创建临时目录，将TEMP/TMP指向它。在Windows的D盘示例（如无D盘自行换到可用工作盘）：

```powershell
New-Item -ItemType Directory -Path 'D:\T2-check\tmp' -Force | Out-Null
$env:TEMP='D:\T2-check\tmp'
$env:TMP=$env:TEMP
$env:PYTHONDONTWRITEBYTECODE='1'
cd source
python -B -m unittest tests.test_deepseek_backend tests.test_deepseek_stage_budget tests.test_real_t2_producer tests.test_t2_production_cli tests.test_t2_semantic_context tests.test_t2_context_allocation tests.test_t2_reflection_defer tests.test_t2_submission_v3 -q
```

若前面已进入source，不要再次`cd source`。导出环境的实际测试数和结果见随包提供的外置发布回执；上述测试是构造的工程回归，不增加真实模型样本或准确率。用`-B`避免在包目录产生bytecode，否则逐文件核验会如实拒绝新增文件。

## 为什么源码提交与运行提交不同

实际模型执行固定在49959f942185955cac77d218cbb0e628cbfe6731；之后增加了复核、文档、打包与测试。运行模块树仍为8945df9255bbc3f330a48f85e0afc2dd8f7a15bf。校验器使用导出模块的实际字节重算Git树，不仅检查manifest字符串；相同运行树不意味着在打包提交上又运行了一次模型。

候选与T1的JSONL从原handoff等值投影；原8个公共文件由固定manifest摘要核对。内部hash用于一致性检查，不是数字签名。接收时先把ZIP的SHA-256与发送者另行给出的发布回执比较，不能只信包自己声明的hash。

## 真实生产需另行准备

本包不附带目标仓库、真实key、本机repo-map、原始聊天或Git数据库。参照`source/START_HERE_T2.md`及生产runbook准备批准的tasks JSONL、公告/patch资料和固定Git对象，使用全新输出目录。当前不是任意URL/PDF一键抓取器，也不执行目标项目。

真实调用需有效临时凭证、资料发送权限和明确费用上限；所有此前已宣布用完的key不可复用。无需为演示本包而立即再买额度或重跑两题。

## 最后验收仍未通过的部分

主质量缺口是稳定的新报告产出、代表性评价、当前及历史问题的实际证据补充/修订。若评审要求实况录屏或现场生产，另行安排并核准权限；历史视频不能替代。#12/#97保留质量问题，#99/#102保留实际交验确认；#90/#94为可选工程。详细A1-A9见`source/docs/submission/acceptance_report.md`。
