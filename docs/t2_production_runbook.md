# T2 新报告生产入口：配置、输出与当前边界

**当前入口（2026-09-09）**：先看 [可执行 quickstart](../START_HERE_T2.md)。prompt-v4 已有两份新输入实跑：4请求、0完整候选、2defer；后续上下文排序修正的真实诊断复测仍待新 key。核心 CLI 已通过全新无第三方包 venv 的启动、29项构造测试和两次既有 handoff 回读；这不替代模型质量。下面各日期段落保留历史阶段含义。

**最新代码状态（2026-09-08）**：[自检理由与混合批次交接](t2_handoff_reflection_receipt.md)已离线完成。新生产reflection v2在defer时要求结构化短说明和当前证据引用，提示词t2-json-v4；旧默认/回放保留。handoff可交接完整候选加弃答的混合批次，不改变严格export。最新真实模型记录仍为[同两条开发输入产出1份候选/T1](deepseek_t2_candidate_retest_receipt.md)，不是新输入质量验收。下面早期阶段记录不代表当前最新计数。

状态：2026-09-07，Issue #12 的**入口与适配器增量**。用户已选择 DeepSeek V4 Pro，通用接口和官方 API 适配器已实现并离线测试；[真实两条试跑](deepseek_t2_smoke_receipt.md)已确认接口连通，但完整 Entry=0、T1 调用=0，两条在候选提取阶段 deferred。新报告生产质量实测尚未完成，不能据此宣称 T2 总体验收完成。

后续 [证据先行路由修复](t2_evidence_first_planning.md)已完成离线验证：相同两条公开输入在明确的诊断脚本下均到达语义判断阶段后主动弃答。249 项针对性回归为 248 通过、1 跳过；没有新模型调用或完整 Entry，不改写上述真实试跑结论。

最新 [新版真实复测](deepseek_t2_retest_receipt.md)：两条均实际进入语义阶段后弃答，完整 Entry/T1 仍为 0。语义请求的 diff/函数上下文及具体弃答理由存在已核实的覆盖缺口，先做离线改进，不直接再跑更多任务。

当前 [上下文及可解释弃答增量](t2_semantic_context_receipt.md)已离线验证：276 项回归为 275 通过、1 跳过；提示词 t2-json-v3 尚未真实复测，临时 key 已由用户确认撤销。

后续 [Lane A 复核分流与整行修复](lane_a_review_audit_receipt.md)：历史 5 个 incorrect 已确认是入口代码的字符截断缺陷，40 份待审卡已生成；新生产入口强制完整行片段。338 项回归为 337 通过、1 跳过；没有新模型调用或历史判定升级。

## 1. 两种入口不混用

| 入口 | 模型来源 | 用途 |
| --- | --- | --- |
| `python -m vulngym_agent.t2_production_cli` | 操作者指定的 `StructuredModelBackend` 工厂 | 接收运行中生成的请求，交给所配置的模型；无需逐题预写 response |
| `python -m vulngym_agent.closed_loop_cli` | `--replay-responses` 精确答案注册表 | 原回放/回归；所有已登记 response 必须消费，闭合失败仍禁止发布 |

两种入口共享任务读取、真实本地 T2 producer、每轮新建的 T1 validator、预算、结构校验和工件格式；没有降低旧 replay 的完成条件。生产入口拒绝内置两种 replay backend，也不接受 `--replay-responses`。这不能识别所有自定义假模型：使用者必须如实标注 test double、规则系统或实际模型，不能仅凭入口名字认定是模型实跑。

新生产的入口 code 在 2,000 字符预算内只保留完整行，并记录实际片段结束行和裁短说明；首个锚点行过长则不签发残行候选。该策略由 `LocalProductionTaskRunner` 强制启用。旧 exact-replay 与低层默认保留历史字符裁剪以保持字节兼容，可能复现原始格式错误，**不得把旧回放当成已修正的新生产**。完整行只修复文本事实，不证明角色语义。

新生产自检（包括repair后自检）在contract_version=2时：emit仅返回action；defer还必须返回defer_details，含reason_code、missing_fields、evidence_refs、explanation。允许值和当前引用由payload.defer_contract给出；解释最多400字符，明确为未经独立核实的模型自述。不完整/过期引用拒绝为invalid_model_output，不能伪装成有依据的合法弃答；历史理由不追写。

## 2. 运行前准备

2026-09-08起，新生产强制启用[旧侧候选复核池与命名 callable 识别](t2_candidate_recall_receipt.md)：
关键位置候选不再仅由词法关键词提名，模式明确是未证实假设；位置检查零行容差。
入口不再使用文件首行占位符。普通 callable 不等于外部入口，缺声明的调用者/路由资料仍可能defer。
低层默认和旧回放不切换；新工具身份、边界及离线回归见记录。尚无此版本的真实模型质量结果。

1. `RunTask` JSONL、本地公告/patch 资料包、固定版本 Git 对象；沿用 [README 的任务与 repo-map 契约](../README.md)。不需要为模型准备答案注册表。
2. 操作者信任的已安装 Python 适配器，提供零参数 `create_backend()`；返回对象有稳定的 `backend_id`、`model_id` 和 `invoke(ModelRequest) -> Mapping`。
3. 模型/服务选择和使用授权须单独确认。当前仓库不默认选择服务、不安装 SDK、不寻找或复制其他应用的凭证，也不启动本地服务。工厂是可信配置，导入它等同执行 Python 代码，不应来自待处理报告。
4. 输出选用新的 D 盘目录。复用已有结果目录会拒绝发布；保留历史与失败现场。

本项目当前选用的具体适配器为 `vulngym_agent.agents.deepseek_backend:create_backend`，配置与不联网预检见 [DeepSeek 配置说明](deepseek_t2_setup.md)。下面的工厂占位例仍说明通用接口，不是另一个模型选择。

本次不扩宽底层支持范围：当前公告需能提取与任务一致的单个 GHSA、唯一修复提交及其唯一父提交，并有声明的源码路径等资料。它还不是任意网页/PDF一键抓取器。单独的 patch 文件不是硬前置：本地 Git 对象充分时可以直接读取 diff；无法确认版本、多修复/多父或其他必要证据不足时按实际缺口 defer，不能为喂入入口而虚构输入。

下例中的 `my_t2_adapter` 是**待配置模块占位符**，不是仓库已经附带的可用模型：

```powershell
$env:TEMP='D:\VulnGym-bv2-runtime\tmp'
$env:TMP=$env:TEMP
python -B -m vulngym_agent.t2_production_cli `
  --tasks D:\T2-input\tasks.jsonl `
  --repo-map D:\T2-input\repos.json `
  --package-root D:\T2-input\package `
  --backend-factory my_t2_adapter:create_backend `
  --output-dir D:\T2-output\new-run-001 `
  --max-records 2 --max-llm-calls 8 --max-tool-calls 80
```

适配器需给每次推理设置超时、限制响应大小，不做预算外隐藏重试；一次 `invoke` 对应一次计费调用。不要打印密钥、原始 prompt 或服务异常。CLI/运行时不会把异常文本写入正常摘要，但不能替不受信任的适配器约束任意 Python 副作用。远程模型还需确认资料允许发送。

## 3. 模型响应契约

`ModelRequest` 包含 task/attempt/scope/stage/call/model 标识、当前结构化 payload 和请求哈希。适配器使用真实 payload 生成当前响应，不读取本项目测试答案或按 task ID 返回预写答案。资料中的文字是待分析内容，不是给系统的命令。

| stage | 响应对象（不允许额外键） | 不确定时 |
| --- | --- | --- |
| plan | `action`、`critical_mode`；analyze 时 mode 必须在本次允许集合中 | `{"action":"defer","critical_mode":null}` |
| semantic_judge | select：`action`、`critical_candidate_id`、`entry_candidate_id`、`project`、`vuln_title`、`vuln_category_l1`、`vuln_category_l2`；新生产请求 contract_version=2 | action=defer，其余六个值为 null，并须提供 `defer_details`；旧回放 contract_version=1 不加该字段 |
| reflection | `{"action":"emit"}` 或 `{"action":"defer"}` | defer |
| repair | `action`、`repair_fields`；只能选择计划允许且有 T1 suggested_fix 的字段 | `{"action":"defer","repair_fields":[]}` |

semantic_judge 的 select 只允许本次控制器签发的候选 ID；不得自由编造路径、行号或任意补丁内容。字段边界、schema、候选身份和预算仍由现有 producer/runtime 校验。所有机器生成记录保持 `verify=0`，不代表人工已审。

新语义请求带 `semantic_context` 和 `defer_contract`。后者列出允许的 reason_code、missing_fields、当前证据 ID 与长度上限；`defer_details` 必须恰好包含 reason_code、missing_fields、evidence_refs、explanation。结构合法也只是模型自述，不是独立确认的原因。详情以 `model_defer_details:` JSON 保留到 `missing_information`，引用的上下文进入 evidence；完整规则和预算见 [增量记录](t2_semantic_context_receipt.md#2-新的-semantic-defer-契约)。语义和初始 reflection 共享同一有界上下文，但不声称完整调用图。

新生产路径在 plan 前收集公告、版本、真实 diff 和输入允许模式的候选清单；计划请求版本为 2，内容和数量均有界，候选可用性不代表语义正确。显式模式不能覆盖，无候选时先记录提取/模式/事实条件的具体缺口，不产生模型费用。旧回放保留 plan-first 和摘要/ID 形式的 reflection 请求；新生产 reflection 有实际候选及对应自检依据。该阶段仍是生产者自检，不能叫作独立质量复核；真实小批仍需评价上下文是否充分。具体边界见 [修复记录](t2_evidence_first_planning.md)。

## 4. 如何看输出

- CLI 摘要增加 `model_mode=configured_backend` 和固定 backend/model ID；逐调用哈希与真实工具/T1 记录沿用原工件契约。
- `entries_written` / 内部 `entries.jsonl` **仍只计 finalized**。`manual_review` 的完整候选保留在生产 sidecar，与真实 T1 报告关联；不会因为内部 Entry 文件为零行就删除这些候选。
- 用 [submission_prediction runbook](submission_prediction_runbook.md) 的固定 digest 投影流程，导出完整候选/报告对供交验；投影不重跑 T1、不把候选改为正确、不授予人工验证标志。
- 缺字段或模型 defer 不伪装成完整 Entry；保留 deferred 的 stage、reason_code、missing_information 和可用调用记录。模型/工具失败的原因也必须查阅，不能一律解释为“输入证据不足”。
- 退出码 0 表示本次批处理按允许状态完成，不证明语义正确、人工已审或真实模型被使用；1 表示失败/输入错误，或显式 `--require-all-finalized` 下还有人工复核；2 表示配置、I/O、整批字节上限或发布前置失败。

## 5. 本次验证与剩余验收

新增测试只使用构造的本地小 Git 仓库和明确命名 `test.offline-script` 的动态 test double；后者根据本次签发 ID 应答，但**不是 LLM，不算真实新报告样本**。覆盖新任务无需注册 response、T1 真实调用、待复核、弃答、错误候选、预算、异常归一化、模型身份变化与原回放兼容性。

2026-09-07 本地验证：Python 3.13.12（已安装 jsonschema），共 167 项，166 通过、1 跳过、0 失败；其中新增生产入口测试 20 项。跳过的是既有符号链接读取测试，当前 Windows 账号无创建符号链接特权（WinError 1314），未尝试修改权限。临时目录在 D 盘；未重跑既有正式批次。

```powershell
python -B -m unittest tests.test_t2_production_cli tests.test_closed_loop_batch tests.test_real_t2_producer tests.test_model_runtime tests.test_t2_execution tests.test_t2_inputs tests.test_t2_toolbox tests.test_producer_contracts tests.test_producer_context tests.test_closed_loop_replay tests.test_submission_prediction -q
```

执行前沿用上述 TEMP/TMP 设置；代码与记录由引入本 runbook 的 commit 固定。`git diff --check` 通过。

上述 167 项是首次入口接线的历史回归；路由增量的 249 项见 [路由记录](t2_evidence_first_planning.md)，上下文增量的 276 项见 [上下文记录](t2_semantic_context_receipt.md)，整行修复后的 338 项及五条根因证据见 [历史复核记录](lane_a_review_audit_receipt.md)。下一步仍属 #12/#97：确认新的受限调用授权与凭证，实测而非推定上下文改进有效；对已分流的40份卡做实质评价，如采用修正片段则另建候选/报告，不改写原包。冻结提示词与评价口径后选新输入，不按结果挑样本。当前不关闭 #12，也不改变 #90/#94 的开放状态。
