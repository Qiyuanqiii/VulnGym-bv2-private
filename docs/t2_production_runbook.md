# T2 新报告生产入口：配置、输出与当前边界

状态：2026-09-07，Issue #12 的**入口接线增量**。已接入通用结构化模型接口并用构造样例验证；尚未选定/调用真实模型服务，不能据此宣称新报告语义质量或 T2 总体验收完成。

## 1. 两种入口不混用

| 入口 | 模型来源 | 用途 |
| --- | --- | --- |
| `python -m vulngym_agent.t2_production_cli` | 操作者指定的 `StructuredModelBackend` 工厂 | 接收运行中生成的请求，交给所配置的模型；无需逐题预写 response |
| `python -m vulngym_agent.closed_loop_cli` | `--replay-responses` 精确答案注册表 | 原回放/回归；所有已登记 response 必须消费，闭合失败仍禁止发布 |

两种入口共享任务读取、真实本地 T2 producer、每轮新建的 T1 validator、预算、结构校验和工件格式；没有降低旧 replay 的完成条件。生产入口拒绝内置两种 replay backend，也不接受 `--replay-responses`。这不能识别所有自定义假模型：使用者必须如实标注 test double、规则系统或实际模型，不能仅凭入口名字认定是模型实跑。

## 2. 运行前准备

1. `RunTask` JSONL、本地公告/patch 资料包、固定版本 Git 对象；沿用 [README 的任务与 repo-map 契约](../README.md)。不需要为模型准备答案注册表。
2. 操作者信任的已安装 Python 适配器，提供零参数 `create_backend()`；返回对象有稳定的 `backend_id`、`model_id` 和 `invoke(ModelRequest) -> Mapping`。
3. 模型/服务选择和使用授权须单独确认。当前仓库不默认选择服务、不安装 SDK、不寻找或复制其他应用的凭证，也不启动本地服务。工厂是可信配置，导入它等同执行 Python 代码，不应来自待处理报告。
4. 输出选用新的 D 盘目录。复用已有结果目录会拒绝发布；保留历史与失败现场。

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
| semantic_judge | `action`、`critical_candidate_id`、`entry_candidate_id`、`project`、`vuln_title`、`vuln_category_l1`、`vuln_category_l2` | action=defer，其余六个值均为 null |
| reflection | `{"action":"emit"}` 或 `{"action":"defer"}` | defer |
| repair | `action`、`repair_fields`；只能选择计划允许且有 T1 suggested_fix 的字段 | `{"action":"defer","repair_fields":[]}` |

semantic_judge 的 select 只允许本次控制器签发的候选 ID；不得自由编造路径、行号或任意补丁内容。字段边界、schema、候选身份和预算仍由现有 producer/runtime 校验。所有机器生成记录保持 `verify=0`，不代表人工已审。

当前仍有限制：plan 在读取公告正文前执行；reflection 的输入仅含 schema 状态、候选摘要/ID，没有独立的完整证据审查上下文。不能把该反思阶段叫作独立质量复核。适配器接入与真实小批评价需继续验证上下文是否充分。

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

下一步仍属 #12/#97：确认模型入口并实现/验证具体适配器；小批真实新报告运行；检查原 40 条中的 5 incorrect、分类 35 uncertain；冻结提示词与评价口径后选新输入，不按结果挑样本。当前不关闭 #12，也不改变 #90/#94 的开放状态。
