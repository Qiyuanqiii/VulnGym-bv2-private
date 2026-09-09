# 当前交付选择与下一次受限诊断

2026-09-09。本轮只做离线数据分流、入口准备及回归；新增模型请求为0，未读取或复用历史key。T2为主、T1辅助。

## 1. 现在怎样交已有数据

机器可读[分流索引](../evidence/t2-submission-disposition-20260909-v1/disposition.jsonl)及[复核动作表](../evidence/t2-submission-disposition-20260909-v1/README.md)分别保留两个分组：

| 分组 | 实际决定 | 不能声称什么 |
| --- | --- | --- |
| 历史Lane A的40个候选 | 12条九维自评均有具体反证，暂不作为正确数据；其余28条未做九维内容评价 | 不是40份已正确数据，也不是12条错误已经修好 |
| 已有真实模型开发候选1条 | 保留带限制的完整Entry/T1示例，仍manual_review、verify=0 | 不是新输入成绩，不是已人工验证或已finalized |

历史12条共有21个反证字段（事实5、语义16）、35个待定字段。它们的评价分母不因排除使用而删去；原数据字节、原T1及verify均不变。下一步逐条纠正时必须另存候选、绑定新摘要并重新检查。

单列候选的两项缺口：

1. **版本关联**：要有来源支持的发行标签、修复提交及受影响快照对应关系；提交父子关系本身不充分。
2. **trace范围**：原模型输出为空；后补说明不是原模型当时生成的trace。可以明确披露边界和后补证据，也可以另存修订版本再验，不能覆盖原样例。

分流器只根据既有复核决定工作，不自行给源码作新判断。即使某条全获支持，也只标为`reviewed_unverified`，不会赋予人工身份或改verify=1。三类无候选任务（既有reflection defer、首次新输入semantic defer、最近的传输失败）仍在各自原回执中，不能放进完整候选分母。

复算（不调用模型）：

```powershell
python -B scripts/prepare_t2_submission_disposition.py --output-dir evidence/t2-submission-disposition-20260909-v1 --check
```

## 2. 下次模型运行准备到了哪里

新入口：`scripts/run_t2_context_retest_v2.py`。开发机上的新目录为`D:\VulnGym-bv2-runtime\t2-context-retest-20260909-v2-longwait`；这是本机复测脚本，不是通用安装路径。

- 状态：**已准备且离线预检通过，未获本轮新凭证/费用确认，未启动。**
- 本次实际清单摘要：`ca37cb9bb7661c5ad000e381665bd374fb9c6a6ed3b6f81a4265d2152be93533`。仅供与离线`check`输出比较，不是运行许可。
- 原两份输入、允许资料及固定源码保持不变；两题都是已见的诊断样本，不重新记为新输入。
- 运行树：`5d8cfbc7f0bc0c50190310a25d56f6524375251e`；来自`1f48e5ed937596dc5ad1995a30eaf50f8f58f7ac`，包括失败状态与阶段诊断改进。
- 模型/prompt仍为DeepSeek V4 Pro/t2-json-v4；high、8192输出上限、不启用stream。
- 此脚本显式选择单请求300秒，产品默认仍120秒。它并不能保证服务端按时返回；DNS解析等系统环节也不因此获得严格整进程时限。
- 全批最多6次发送尝试、每题3次、零自动重试/repair。失败停止后续发送；开始标记独占创建，不重启同一输出目录。
- 拟议预算仍20元，真正金额上限依赖用户设置的平台硬限额；不能把token数换算成已知账单。
- 仅记录请求摘要、长度、阶段、耗时和可用usage；超时用量未知，禁止记录key/原始模型回复到公开回执。

离线预检：

```powershell
python -B scripts/run_t2_context_retest_v2.py check
```

预检打印实际`input_manifest_sha256`。真正运行前，用户需要提供新的有效临时key并明确授权该范围及平台20元硬限额。只在获准后使用下列命令，将占位摘要替换成当次已核对的完整摘要；脚本通过终端隐藏输入读取key，不使用历史对话或环境中的旧key。

```powershell
python -B scripts/run_t2_context_retest_v2.py run --confirm-paid-retest --confirm-platform-cap --expected-manifest-sha256 <已核对的64位摘要>
```

三个确认参数不是授权本身，不能由agent在用户尚未确认时自行代填。平台余额、限额及撤销情况均不冒称已由程序查询。结束后明确通知用户撤销key。不得改写v1输入清单、旧运行/输出或已发布ZIP来复用授权。

## 3. 下次结束后的验收顺序

1. 记录真实退出码和传输日志。正常语义defer、完整候选、传输失败分开计数；退出0不是质量通过。
2. 若有完整候选，按原九维协议给出具体证据/反证/待定项；模型自述、T1和格式通过不能替代内容评价。
3. 若仍无完整产出，不改输入挑容易题、不自动加请求、不宣布完成；保留失败并判断具体限制。
4. 以新版公开回执单列同输入诊断效果；首次新输入0/2的历史结果不覆盖。没有盲测成绩就明确写没有。
5. 复核当前Entry交付集合与相应T1绑定；仅追加经净化材料到私人仓库，不关闭尚未达到条件的主Issue。

当前[含视频交付包](t2_results_video_receipt.md)保持原样；它是3156d0b源码快照，不包含本轮新增分流脚本/复测入口。新增代码在后续仓库提交中。本轮不再重打大包或重录视频来代替真实质量工作。

## 4. 本轮验证范围

127项离线相关测试通过，涵盖既有质量协议、分流器、旧/新受限传输、DeepSeek适配器及生产CLI。测试验证分母不丢、反证不变成不确定、机器verify不提升、300秒选择不改默认、最多6/每题3、零重试、日志失败先停、旧目录保全和未经确认不读取key。

实际命令为`python -B -m unittest tests.test_t2_submission_disposition tests.test_t2_quality_review tests.test_t2_context_retest_v2 tests.test_t2_context_retest_run tests.test_t2_new_input_run tests.test_deepseek_backend tests.test_t2_production_cli -q`，127项、38.085秒、退出0。分流`--check`和诊断`check`各用两个独立进程读回，均退出0且输出相同；分流4个公共文件共69,861字节，未发现密钥格式、绝对本机路径或禁用私有数据标记。新诊断目录没有`run-start.json`或`output`，不会将准备成功计为运行成功。

这是代码/契约测试，不是127个真实生产样本。仍缺成功的修正后语义复测、有效新输入数据和独立或明确标为自评的质量验收。#12/#97保留开放，#90/#94不作为主交验阻塞且不关闭。
