# T2 报告到数据的系统设计（T1 辅助）

> 2026-09-07设计源稿，目标是简短可读的交验说明；尚非最终PDF/演示。
> 用户登记T2，双题保留但主次明确。适用目标、验收和限制见
> [当前任务参考](../current_task_reference.md)。

## 1. 主用户流程

用户需要把真实报告变成可使用的VulnGym记录，而非手工准备答案后只做回放验签。
主产品形态是CLI/批处理，先复用现有Lane A：

```text
公告/资料 + 固定版本源码
  → 资料与版本查证 → 候选字段/EP/CO/trace → 结构与语义自检
  → 完整Entry（verify=0）或明确待复核/失败记录
  → [辅助T1 → 有依据的有限修正 → 重新验证]
```

这是交付目标；**当前Lane A CLI依赖exact replay，新报告自主生产入口和质量证据仍是#12/#97缺口**。
现有40个完整候选/报告对不等于40条已确认为正确的数据。缺失字段应保留证据和原因，
不能为凑schema编造值；完整记录与partial/deferred记录须分流。

## 2. 已有Lane A：结构化T2与真实T1

`LocalStructuredT2Producer`、`ClosedLoopOrchestrator` 和
`python -m vulngym_agent.closed_loop_cli` 已有受控生产/复现基础。

- plan选择analyze/defer及critical mode。
- 控制器读取本地公告、引用/patch和Git对象，提取字段、定位有界代码候选、检查schema。
- semantic_judge选择控制器签发的候选ID，可补充有界标题/分类等文本；
  候选身份约束可以防止任意编路径，但本身不保证语义正确。
- reflection选择emit/defer；T1对候选进行真实检查，可靠suggested_fix可触发有限字段修正，
  然后重新schema/self-check和新T1检查，保留修改轨迹。
- 任务、工具/模型记录、预算、replay及sidecar用于追踪过程；发布为新目录，保留不确定现场。
- `T2TaskInputV2` 固定公开repo/commit identity；当前要求与唯一脆弱父提交推导一致。
  这是当前支持范围，并非所有报告都有唯一fix-parent。多父/回移/无patch需另行裁决或明确defer。
- `submission_prediction_cli` 能投影完整候选与报告对，并通过外部digest重读源replay。
  投影不重新执行T1，也不增加语义正确性的证据。

`python -m vulngym_agent` 是独立T1入口。当前部分语义检查仍保守返回uncertain；
代码位置存在性/容忍窗口也不能代替EP/CO角色判断。缺失能力要明说，不能全归因于输入资料。

## 3. Lane B：保留的工程扩展

```text
source-only task + sealed source + D2/D3 replay
  → D2候选 → D3审核接口 → D4/D0 Finding
  → [E3/E4 OCI、native Linux、receipt/readback]
```

`final_gate_cli` 的 `findings.jsonl` 不是完整 `entries.jsonl`，
不含全部公告/分类/code/verify等字段，且不调用T1。
因此70组Lane B authoring不能代替T2报告到完整Entry的主交付。

D3控制面使用独立context/tree/budget，不等于每一份生成的review都做了独立语义审查。
当前 `scripts/author_replay_batch_offline.py::_build_d3_response` 可按role refs存在性
填supported；该辅助策略不能作为真实语义评价。须明确标识并补证据或另做评价。

此工程分支仍保留固定test-first、身份pin和fail-stop协议；选择执行时不能跳过。
但它不再阻塞T2主验收，不因改范围而宣布已运行或已通过。

## 4. 质量与不确定性

先检查来源/版本/代码位置事实，再评价角色/链路语义；允许有证据的合理替代定位。
PDF已划掉的±5行和缺return模板不作正确性标准。
机器数据保持verify=0；T1 correct、D3 accept和哈希都不能伪装成人工验证。

不确定、资料冲突、未支持检查、预算/工具失败分别记账。
复核包给候选、依据、缺口、人工下一步；只有实际完成复核才记录人审决定。
标准schema不容许缺失时，保留单独任务结果而不是非法或编造Entry。

评价采取预先声明的代表性报告集，区分开发样例、冻结后新输入与构造异常。
结构合规、覆盖率、语义质量、弃答和人工负担分开报；评价者是否独立据实填写。

## 5. 来源和运行边界

会议撤回一概禁止联网，不意味着当前项目自动获得新的联网/工具权限。
本次仍按本地获准资料与普通git/gh工作；不读取隐藏答案，不启用受保护扫描或浏览器。
将来若扩展资料入口/模型后端，须明确授权、成本、资料许可和运行边界，不能把权限绕过当实现。

固定代码、输入pin和本地配置构成声明的运行基础；源文本、模型输出和候选结论仍需核验。
已有工程worker配置和限制按对应runbook保留，不能把开发环境声称为正式原生Linux。

canonical JSON、哈希链和receipt证明字节绑定与机械闭合，不证明语义正确。
22repo/70task封存完成的净化证据提交为
`c52f48b770736d403b2ce090b10a70e5498804e0`，其含义限定为source阶段。

## 6. 当前取舍与下一步

优先#12的新报告自主生产、5条incorrect核查、uncertain分类和高收益T2质量改进；
#97记录真实评估和迭代；#99整理可运行入口、结果、过程记录及短演示。
T1全面覆盖所有类型、全70扩展和原生Linux长跑放后，不让辅助工程取代主题。

工程经验可在短稿中精选：fix/vulnerable版本混淆、回放与真实推理的差别、语义评价不能
用引用存在性代替、失败保全与日志/磁盘成本。只写实际遇到并可追溯的案例，
细节留在历史记录与专用runbook，不让摘要淹没产品能力。

本文与最终README必须在#12实现变化后同步；当前文档不会把计划写成已完成能力。
