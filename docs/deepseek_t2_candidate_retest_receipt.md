# 候选覆盖修正后的真实复测：1 份完整候选，仍需语义复核

2026-09-08：用户新授权的同两条开发输入，在代码
`0190850e5814210584808932a729fc9a1cf83137` 上完成一次受限真实批次。
**完整候选由上次 0/2 变为本次 1/2，并产生 1 份真实 T1 报告；不是 50% 正确率，也不是新输入验收通过。**
两条最终均为 `manual_review`，没有把不确定结论改成正确。

## 1. 范围、预算及实际执行

- 原两条公开开发任务；6 个准备文件与上次逐字节一致。未加载旧模型回答或评测答案，
  未扩大任务声明的源码路径，未逐题预写模型 response。
- `deepseek-v4-pro`、`t2-json-v3`、reasoning `high`、每次输出上限 8,192 tokens、
  HTTP 超时 120 秒；每题最多 3 次模型调用、80 次受控工具调用，repair 次数为 0。
- 全批上限 6 次 HTTP，实际恰好 6 次，全部 HTTP 200 且返回模型身份与配置相符。
  两题分别经过 plan、semantic_judge、reflection；逻辑调用状态全部 success，没有自动重试。
- 28 次受控 producer 工具调用；这个数字不包含所有底层 Git/辅助检查操作。
- 首个请求至运行退出：香港时间 05:03:54–05:06:51，176.660 秒。
  HTTP 用时合计 168.963 秒，不含准备/离线核验时间。
- 服务端报告 prompt 50,770、completion 11,137，合计 **61,907 tokens**。
  未查询账户账单，不估算人民币费用。
- 进程退出 0，`failed=0`、`input_failures=0`。这是运行正常结束，不是质量验收成功。
- **临时 key 使用已结束，并已通知用户可以撤销。**不再调用，也不检查其剩余额度或撤销状态。
  凭证未写入项目/证据；不声称已替用户撤销或能删除聊天中已有的凭证记录。

## 2. 两条真实结果

| 开发任务 | 本次终点 | 完整候选 / T1 报告 | 当前结论 |
| --- | --- | --- | --- |
| Langflow，`VG-TRAIN-40D4B88B06CDE8FCFF5C` | reflection 选择 defer | 0 / 0 | 自检拒绝输出，保留待复核 |
| Flowise，`VG-TRAIN-46D6453D5B4663CF0D13` | reflection emit 后调用 T1 | 1 / 1 | 候选完整，T1 verdict 为 uncertain |

Langflow 记录为 `stage=reflection`、`reason_code=model_deferred`，说明只有
`reflection declined to emit the candidate`。当前 reflection 响应契约没有详细理由字段；
不能挪用上轮 semantic 的理由或臆测本轮拒选原因。可离线检查已有选择与证据、
为以后运行补充有界自检理由，但不能追写到本次结果里。该契约缺口仍未解决。

Flowise 的 `entry-00268` 保持 `verify=0`：EP 位于 `packages/server/src/services/leads/index.ts`
第 23 行，是 `createLead` 的 service 层 callable 候选；CO 位于同文件第 28 行，trace 为空。
新 producer 对选中关键位置使用零行容差；本次 T1 的 EP/CO 文本匹配也实际偏移 0，
但 T1 现有允许窗口仍为 5，没有修改它的全局契约，更没有用窗口命中证明语义。

T1 的 **16 项字段检查为 9 correct、7 uncertain、0 incorrect**。7 个待定字段为
EP、CO、trace、project、标题及两级分类。9 项是结构、身份、版本关系等受支持检查，
不能由此推出整条正确或 9/16 的语义准确率。普通函数存在、片段真实、提交是祖先，
不等于外部可达、关键角色正确或该版本确实受影响。空 trace 完整性仍未确认。
检查器未实现的语义检查也不能统称原报告资料不足。

新 producer 取消首行入口占位符；T1 逆向搜索中的旧首行锚点启发式仍存在，只给待定证据。
本轮没有宣称整个 T1 入口搜索都已升级。

### 为什么 entries_written=0 但确实有产出

内部 `entries.jsonl` 只收 finalized/correct 的终态 Entry，因此仍为空。
完整候选在原运行 `output/candidates.jsonl`；真实报告在 `output/validations.jsonl` 和
终态投影 `output/validation.jsonl`，后两者报告内容一致。`deferred.jsonl` 保留另一题结果，
两个任务均有对账终态，没有静默丢输入。

本轮只用固定 digest 的 `review` 生成公共索引，**没有执行完整批次正式 export**：
一条缺完整候选/报告对，现有 export 不接纳这种整批输入。没有删掉缺失任务伪装 2/2，
没有修改导出成功含义。混合完整/弃答批次的交付体验仍需整理或另行完善；此记录不是最终提交包。

## 3. 验证、现场与证据

- 实跑后 83 项针对性单测全通过，0 跳过、0 失败，103.027 秒。
- 两个独立进程运行 `verify_closed_loop_artifacts`，退出均 0，stdout 字节一致。
- 用实际 dataset digest，两次独立 `submission_prediction_cli review` 也退出 0、字节一致；
  complete=1、incomplete=1，候选/报告摘要匹配原记录。
- 本次 22 个受核运行/输入文件共 232,175 字节，读回前后哈希不变；上次 22 文件
  170,213 字节仍匹配已发布清单，未改写历史。
- 公共投影 **7 文件、20,143 字节**，只有状态、计数、版本、相对位置和摘要；
  不复制源码正文、模型原始回答或凭证。路径/凭证形态/排除输入标记检查通过。
  运行和临时文件在 D 盘；这不是全机器/C 盘总占用统计，没有删除旧数据。
- 汇总脚本首次沿用“无 T1 则 validation.jsonl 为空”的旧断言被拒绝；离线确认本次有报告后，
  改为验证它与唯一终态 T1 报告相等。未修改原运行或再次请求模型，不是生产失败或补造报告。

离线回归（无需 key）：

```powershell
python -B -m unittest tests.test_deepseek_backend tests.test_t2_semantic_context tests.test_t2_evidence_first_planning tests.test_t2_review_candidates -q
```

只读复核（替换路径占位符为本次已有输出目录，不重新生产）：

```powershell
python -B -m vulngym_agent.submission_prediction_cli review --replay-dir <existing-output> --replay-dataset-sha256 0b779638a4fd9230133a97e2268e942d3daf48f46c7041e277232839a9662c22 --expected-task-count 2
```

| 身份 | SHA-256 |
| --- | --- |
| 运行 dataset | `0b779638a4fd9230133a97e2268e942d3daf48f46c7041e277232839a9662c22` |
| Flowise 候选 | `01e90ad3525187349041df42f24bae1b40c525577136a6b9b248f6e362237f02` |
| Flowise T1 报告 | `d505c3c1fef8feaf83d7d10e078da471898133225ae8851da543e8ee996e568c` |
| Langflow deferred | `f42387f1a3568fadacccf00df07c968965446c34d4fdaf71fc8c5ed26d40cb1c` |
| review 证据摘要（非文件哈希） | `556b273cc67dad8436b03eaea993bc3c65ca35bfefd7ce930a9aebc2f43d05a8` |
| 公共 manifest 文件 | `5debaabb0341177df6206304f13391b2374aade3c91978ac91dec2b1d6392212` |

[汇总](../evidence/deepseek-candidate-retest-20260908/summary.json) ·
[逐任务/字段复核索引](../evidence/deepseek-candidate-retest-20260908/review.json) ·
[输入哈希](../evidence/deepseek-candidate-retest-20260908/input_files.json) ·
[运行文件哈希](../evidence/deepseek-candidate-retest-20260908/runtime_files.json) ·
[读回](../evidence/deepseek-candidate-retest-20260908/readback.json) ·
[HTTP 元数据](../evidence/deepseek-candidate-retest-20260908/transport_events.jsonl) ·
[公共清单](../evidence/deepseek-candidate-retest-20260908/manifest.json)。

## 4. 接下来，不继续付费重复同一对输入

1. 离线评价本次完整候选的版本、EP/CO 角色和 trace；检查另一题已有选择与证据。
   新增 caller/router 资料须显式列入新输入版本及许可路径，未知原因不编造。
2. 处理 reflection 具体理由与混合批次交付说明两个产品缺口，保留旧数据和回放兼容。
3. 继续填写已固定 12 条开发子集的 108 个评价格（目前未评价），注明评价者与是否独立。
   规则冻结后另选至少 2 份新输入；本轮不能抵扣。
4. 在同一最终版本完成 CLI 演练、数据/复核包、自评、真实 AI 开发记录和演示。

此次证明新链路能到完整候选与 T1；样本极小且已用于调试，模型有随机性，
不能将差异全部归因于一个改动，不能声称新输入能力或语义质量已达标。
A1/A3/A5 不升级；#12/#97 与工程扩展 #90/#94 保持开放。
