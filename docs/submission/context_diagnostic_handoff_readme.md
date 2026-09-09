# T2 v5 真实诊断增量交接包

2026-09-09。本包保留最近一次真实生产的完整候选、T1报告、失败记录、九维AI开发自评与下一步。它是**增量结果交接，不是最终源码包、盲测成绩或人工验收证明**；无需key即可阅读和核对。

## 直接看什么

1. [本轮结果与后续动作](docs/t2_context_retest_v3_receipt.md)：两题中的一题完整候选/T1、另一题输出截断，整批退出1。
2. [混合handoff](evidence/t2-context-retest-20260909-v3/handoff.json)：保留两任务，其中entries/validation各一份；机器verify=0，T1 uncertain，未finalized。
3. [九维内容自评](evidence/t2-context-candidate-review-20260909-v1/review.json)：5支持/4待定，AI开发自评，非独立人审。

本文件是ZIP根目录README模板，上面链接按包根目录解析。

## 不联网核验

解压后在包根目录运行（Python 3.12+，仅标准库）：

```powershell
python -I -B verify_bundle.py
```

校验只读取本包，核对文件集合/哈希、候选/T1绑定、计数和自评声明；不会调用模型、读取凭证或执行目标项目。成功输出`verified=true`只证明这些一致性条件，**不证明语义正确或资料真实来源已独立认证**。

## 版本、剩余任务与费用边界

- 实跑执行提交：`8df0154bfa95a6c2f89b10b795be6b72d5725cb7`；源码仍在获准的私人仓库`Qiyuanqiii/VulnGym-bv2-private`、分支`codex/b-v2-source-discovery`，本包不附带源码或目标仓库。回执/本包工具的固定提交见`MANIFEST.json`的`source_commit`。
- 本轮5请求、零重试、71,741 tokens，使用已结束；实扣人民币和平台撤销状态未独立查询。**不得拿剩余请求或以前给过的key继续调用**。
- 下一步先离线分析第一题输出预算适配；第二题复核版本关联、入口/操作角色、trace四项。原候选、T1、verify和失败记录不可覆盖；如要修订或复测，另立版本并取得必要授权。
- 代表性新输入质量、历史反证的实际修订、最终同版交验仍未完成；#12/#97/#99/#102不因此全部关闭，#90/#94是可选开放项。
- 旧`v2-final`ZIP/视频保留原快照，本增量不修改旧包，不将旧演示冒称本轮现场生成。
