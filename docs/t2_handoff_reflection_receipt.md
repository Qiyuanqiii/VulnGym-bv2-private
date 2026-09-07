# 自检理由与混合批次交接：离线产品增量

2026-09-08，承接上次真实复测的两个已观察缺口。本轮没有调用真实模型，
没有重跑真实输入的 T2/T1，没有使用已结束使用的 key。
代码基线为 ccdb294；新的实际质量成绩仍待评价，不因增加接口而升级 A1/A3/A5。

## 1. 新生产的自检弃答不再只有 action

新生产开启 reflection contract_version=2，DeepSeek 提示词身份升为 t2-json-v4。
emit 仍只有 action；defer 必须另外给 defer_details：

- 一个允许的 reason_code，1–6 个缺失字段，1–8 个唯一的本轮 evidence_refs；
- 1–400 字符、不含控制字符的具体缺失事实/冲突说明，不要求或保存隐含思维过程；
- 引用必须属于当前请求，不能引用别题/别轮证据；多余键、无理由、过期引用等视为
  invalid_model_output，不伪装成有依据的合法弃答；
- 记录明确标识 model_reflection_defer_v1 / model_self_report_not_independently_verified，
  保存在 deferred missing_information 中，能通过原 replay 和新 handoff 回读；
- 初始自检引用本次 semantic_context；repair 自检引用当前尝试的检查证据。
  repair 另保留事实性 schema 结果，明确 semantic_verified=false。schema 通过不证明角色正确。

低层 include_reflection_defer_details=False 保留默认行为；仅新生产强制启用，
且要求已有 reflection/semantic 上下文。旧 semantic 契约及默认请求字节不变。
**不会给上次 Langflow 的旧记录补写原因**。新契约的实际服务遵从性还未付费复测，
离线模拟通过不能当作模型解释能力已改善的实测成绩。

## 2. 新增混合批次 handoff，不改变正式 export

新增两个只读 CLI 操作：

- handoff：生成一个规范 UTF-8 JSON 到 stdout，包含完整 entries/validation 数组，
  所有任务的状态、物理输入行、1-based pair_ordinal 或 null、候选/报告摘要及弃答信息。
  不完整任务不伪造 Entry；已有 incorrect 不过滤、不升级，verify 必须为 0。
- verify-handoff：要求原 replay、外部固定的 replay digest 及 handoff digest，
  从来源重新构造并逐字节比较文件。篡改内容后自算新摘要也不能绕过来源比对。

类型独立为 vulngym.mixed-batch-handoff.v1，formal_submission_export=false。
原 export/verify/combine 和 finalized-only 内部 entries.jsonl 契约未改；
缺完整候选/报告对的批次仍不能通过原正式 export。

handoff 含完整候选代码和 T1 证据，**不是适合直接发布的元数据摘要**；
公开协作只提交净化验证数据。handoff/verify-handoff 不修改原 replay、不运行模型/T1/Git 源码操作，
也不提供目录发布、锁定或断电恢复保证。输入失败仍明确拒绝，须先核对原 errors；
这不是任意异常批次都能导出。单个交接 JSON 上限 64 MiB。

用法及无覆盖的保存示例见[投影 runbook](submission_prediction_runbook.md#mixed-batch-handoff)。

## 3. 已有真实数据的只读演练

上次两题的来源 dataset 固定为
0b779638a4fd9230133a97e2268e942d3daf48f46c7041e277232839a9662c22。
两次独立 handoff stdout 字节一致，保存后两次独立 verify-handoff 均通过。

- 2 个任务全部保留：Flowise 的 1 份完整候选/uncertain 报告；Langflow 的 1 份 reflection defer。
- 两条仍 manual_review；历史无具体理由仍无具体理由，没有改成新协议输出。
- 本地 handoff.json 为 9,663 字节，机器数据 verify=0。
- handoff 逻辑摘要：54787d8ed7566dbbdff0d459684dd6e76feb67cd7fb5e0f784fb68668d853197。
- 文件 SHA-256：d72d6d38e3ab9ed24d8d6aa4691e43ca627cd150ce307354f6392b7d77d7093b。
- 原 22 个运行/输入文件、232,175 字节仍匹配已发布清单；既有 review stdout 逐字节不变。

本地完整交接文件放在 D 盘 t2-mixed-handoff-20260908-v1 目录，未纳入 Git。
净化公共证据仅 3 文件、3,129 字节；这不是 C 盘或全机器空间统计，没有清理旧运行。

## 4. 验证与实际调试记录

最终 324 项针对性回归：323 通过、1 项既有平台条件跳过、0 失败，140.280 秒。
新增 17 项测试覆盖合法自检弃答/非法响应/过期引用/repair 当前证据/默认行为，
以及完整、弃答、incorrect、finalized 混合状态、输入失败、摘要/计数错误、来源与文件变更、
CLI 往返、原正式 export 仍拒绝混合批次。

新增 handoff 测试夹具最初未同步第二题 input_line、复用了 entry_id，随后默认 repair
又移除了用于测试的 incorrect 终态对。修正的是构造夹具：独立身份/物理行、禁用该测试的 repair；
未修改生产校验来容忍这些错误。原 91 项基础回归先通过，最终按完整列表重跑。

同一构造 Git 样例对比 ccdb294 与新低层默认 producer：draft、全部请求和控制器投影的
14,152 个规范字节完全一致（本轮序列化包含末尾换行）。
另一个新 reflection-defer 构造样例成功写入 replay、两次读回并进入 handoff，具体理由保留，
没有完整候选，也没有真实 API 调用。

回归命令：

```powershell
python -B -m unittest tests.test_t2_reflection_defer tests.test_submission_handoff tests.test_t2_review_candidates tests.test_t2_semantic_context tests.test_t2_evidence_first_planning tests.test_deepseek_backend tests.test_t2_production_cli tests.test_closed_loop_batch tests.test_real_t2_producer tests.test_model_runtime tests.test_t2_execution tests.test_t2_inputs tests.test_t2_toolbox tests.test_producer_contracts tests.test_producer_context tests.test_closed_loop_replay tests.test_submission_prediction tests.test_critical_resolver tests.test_patch_analyzer tests.test_entry_search -q
```

[代码身份及只读演练](../evidence/t2-handoff-reflection-20260908/verification.json) ·
[交接核验](../evidence/t2-handoff-reflection-20260908/handoff_verification.json) ·
[公共清单](../evidence/t2-handoff-reflection-20260908/manifest.json)。
公共清单文件 SHA-256：
7a260d5707946c353d9a7551cec85e05aeb4100804ff6a1d48a3e31b896a157d。

## 5. 下一步仍是实质质量，而不是继续扩大工程流程

优先对现有候选和资料做版本、入口/关键角色、trace 等实际评价，补充有来源的证据和评价者记录。
12 条开发复核包的 108 个格仍未实质评价；至少 2 份冻结后新输入仍待选定。
新模型调用需另行限定输入和预算，不能重复花费旧授权。
随后完成最终 CLI 演练、自评与演示。#12/#97/#90/#94 均保持开放。
