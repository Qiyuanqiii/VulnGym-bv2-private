# VulnGym T1 × T2 自动化闭环：B-v2 首版设计

> 状态：确定性 T1 基础、受控闭环编排与本地结构化 T2 Producer 纵切，2026-08-20。本文以考题、`SCHEMA.md` 和 B-v2 计划书为边界；“已实现”不表示语义 T1、批量回放或最终数据验收已经完成。

## 1. 目标与总体架构

B-v2 用 T2 生产候选，Fact Gate 消除可机械核验的错误，再由与 T2 推理隔离的 T1 逐字段盲审。T1 发现明确错误后，Orchestrator 生成 `RepairPlan`，T2 只重做错误字段；初始候选之后最多自动修复两轮，仍不收敛或证据不足则转人工。

```mermaid
flowchart TD
    P["本地漏洞资料包<br/>advisory / patch / repo"] --> T2["T2 Producer<br/>规划 → 工具 → 反思"]
    T2 --> C["候选 Entry<br/>证据与候选写入 sidecar"]
    C --> G["Deterministic Fact Gate<br/>Schema → ID → Commit → File → Line/Code"]
    G --> T1["T1 Independent Validator<br/>逐字段三态 + 置信度 + 可读证据"]
    T1 -->|correct| O["正式 JSONL"]
    T1 -->|uncertain| M["自评报告 / 人工审核"]
    T1 -->|incorrect| R["Orchestrator<br/>锁定 correct 字段并生成 RepairPlan"]
    R -->|未触发停止条件，最多 2 轮| TR["T2 Repair Mode<br/>仅重查 repair_fields"]
    TR --> G
    R -->|预算耗尽或无进展| M
```

T1 只接收原始资料包和待审 Entry，不读取 T2 的推理或自报置信度。T2 的 Planner、Semantic Judge 与 Reflection 已有严格 JSON 模型调用边界，并只能引用受控工具签发的候选和证据；这仍不等于语义正确性已经得到证明。独立 T1 的完整语义正判、反证审查与全字段裁决仍待实现。

## 2. 核心契约

### 2.1 Deterministic-first 与语义边界

硬事实按 `Schema/ID → commit 对象 → 精确路径 → 行号 → ±5 行代码匹配` 执行，失败直接形成结构化证据。通过门禁只代表“事实存在”：commit 存在不证明它是漏洞版本，代码匹配也不证明外部可达性或漏洞语义。因此 `fact_status=correct` 仍可对应 `status=uncertain`，语义必须由公告、patch 和漏洞版本源码交叉裁决。

`critical_operation` 采用双模式：

- **Sink 模式**：面向 XSS、注入、SSRF、路径访问等，从 patch 找危险操作变化，再回到漏洞 commit 确认真正 sink；不得引用修复后新增代码。
- **Guard 模式**：面向鉴权、租户隔离和状态机错误，定位错误/缺失的条件、归属检查或提前返回点。若漏洞版本没有有证据的可落地位置，则转人工，不能虚构行号。

Entry Point 需由路由、RPC/CLI、消息回调或反向调用关系证明“外部可达”。完整 trace 可为空数组，不能为补链而虚构节点。

### 2.2 正式输出、sidecar 与证据

| 边界 | 内容 | 约束 |
| --- | --- | --- |
| `outputs/entries.jsonl` | T2 正式 Entry | 仅 15 个 Schema 字段；`verify=0`；不得混入状态、证据、假设或日志。 |
| `outputs/validation.jsonl` | T1 正式报告 | 核心字段三态、置信度、可读证据，可附修正建议。 |
| `outputs/self_assessment.md` | 人工分流说明 | 汇总低置信、冲突和未收敛条目。 |
| `artifacts/*.jsonl` | 内部 sidecar | `evidence`、`candidates`、`tool_calls`、`repair_history`、`run_manifest`；不得回流污染 Entry。 |

以上是目标落盘边界；确定性 T1 CLI 已写出验证、证据和运行清单，闭环批处理 CLI 及 candidate/tool-call/repair-history 的统一 artifact writer 尚未完成。

统一证据模型如下；`line_start`/`line_end` 如出现必须成对且有序：

```json
{
  "evidence_id": "EV-GHSA-001-SOURCE-04",
  "report_id": "GHSA-W7XJ-8FX7-WFCH",
  "source_type": "source",
  "commit": "9942de8011d4b5a141ac507c974c061c0cdad59a",
  "file": "src/lib/components/common/RichTextInput.svelte",
  "line_start": 348,
  "line_end": 348,
  "snippet": "tempDiv.innerHTML = htmlContent;",
  "tool_call_id": "TOOL-00031"
}
```

`source_type` 取 `advisory/patch/source/git/schema` 之一；除 `evidence_id/report_id/source_type/snippet` 外，其余字段可选。`evidence_refs` 只用于追踪；T1 报告仍须内嵌可读证据。正式必填事实拿不到时不伪造 Entry：`vuln_ids`、`trace` 可用合法空数组，其余关键缺失进入人工队列。

### 2.3 离线、只读与预算

证据层默认离线：只读本地公告、patch 和仓库，禁止 HTTP 取数、`git fetch`、答案 API、执行仓库二进制/安装脚本或动态导入目标代码。严格离线配置使用本地模型；若显式启用远程 LLM，只发送最少片段，API Key 不入库、不入日志。

Git 工具用固定参数数组读取 `cat-file/ls-tree/show`，无任意 shell，不 checkout、不运行 hook/diff driver/textconv；校验 SHA 和相对路径，拒绝绝对路径、`..` 与选项/pathspec 注入，并限制超时和 blob 大小。确定性门禁只接受对象库位于授权根目录内的普通 clone/bare repo，拒绝 gitfile、`commondir`、alternate object database 和 `info/grafts` 历史覆盖；固定 `core.commitGraph=false` 使祖先关系回到原始 commit 对象，并以 `GIT_NO_REPLACE_OBJECTS=1` / `GIT_NO_LAZY_FETCH=1` 阻止 replace refs 与 partial clone 隐式联网/写对象。AST 如需展开源码，只能由后续受控工具创建每任务独立临时目录，不能把该目录绕回只读事实门禁。

确定性输入门禁已接入资源上限：默认单行 JSONL 1 MiB、每批 10,000 条、每条 trace 64 节点、每包 64 个文件；对应硬上限为 32 MiB、100,000 条、256 节点和 256 文件。超限在仓库/Git 扇出前形成结构化单条错误，超长行以固定大小缓冲排空。闭环预算默认每任务 `max_llm_calls=16`、`max_tool_calls=80`、`max_repair_iterations=2`；调用开始前计费，失败不退款，事件账本可用于确定性的内部一致性对账。全字段正确、只剩 `uncertain`、两轮耗尽、无变化/错误重复、预算耗尽、改坏锁定字段、原正确字段回归或证据冲突时立即停止。`uncertain` 不会被自动改写，直接进入人工分流。

## 3. 交付边界与实施状态

### Standard 与 Bonus

B-v2 的 Standard 包含：T1 全核心字段三态、可读证据、多源与批处理；T2 全必填字段、漏洞/fix commit 区分、真实代码位置和 Entry/Critical 语义；以及基础 Guard、Fact Gate、两轮修复、错误隔离和离线安全。B-v2 将题目加分方向中的 Guard 与 T1×T2 联动提升为 Standard。

Bonus 后置为完整 trace、多语言 AST/轻量数据流、系统性错误归因、复杂 merge/backport、完整 taint 与自动发布。Standard 不建设第三个 Repair Agent、通用平台或远程 Artifact Store。

### 当前已实现：受控编排与本地结构化 T2 Producer 纵切

- 三份严格机器契约：Entry、Validation、Evidence Schema；`additionalProperties=false`，并有 `EvidenceItem`、`FieldValidation`、`ValidationReport` 可序列化模型。
- `SchemaAdapter` 覆盖 15 个正式字段、额外/缺失字段、行范围、GHSA URL 与 `report_id` 一致性、ID 大写/去重/CVE-before-GHSA 排序及正式 T2 的 `verify=0`；它不会补造内容字段。
- `LocalEvidencePackage` 支持每行 `{"package": {...}, "entry": {...}}`，在显式只读根内读取必填公告和可选引用/patch。它拒绝绝对路径、盘符/UNC、`..`、反斜杠、控制符、符号链接、junction/reparse point、重复路径和越界输出；默认单文件/单包/文件数上限为 8 MiB、32 MiB、64，并记录原始字节 SHA-256。加载前后核对完整父链 identity；POSIX 支持时逐级使用目录句柄与 no-follow 打开，Windows 额外核对已打开句柄的最终内核路径。原始 Entry 行继续兼容。
- 公告事实层只提取正文中出现的 GHSA/CVE 和显式标注的 fix commit；`report_id/source_link/vuln_ids` 可与本地公告独立核对。缺公告、不可读或歧义返回 `uncertain`，明确错配与危险资料路径返回 `incorrect`。
- 只读 `GitRepository` 除对象/路径/源码外，已支持全部父提交、祖先关系、历史完整性判断和有界的进程内 UTF-8 unified diff；仍不执行 checkout/fetch/hook/textconv/diff driver。`CommitTransitionValidator` 能明确拒绝 candidate==fix、非祖先和声明路径未变化；正向拓扑/diff 事实仍不冒充漏洞语义证明。
- `T1DeterministicValidator` 已将公告与 Git 历史事实接入字段级报告；无法读取的可选 package 文件通过 `evidence_package=uncertain`、闭合 Evidence 引用与 `missing_information` 明示，不会静默丢弃。`python -m vulngym_agent` 支持 JSONL 逐行错误隔离、单仓库或 `repo_url → 本地路径` 映射，并原子写出 `validation.jsonl`、`evidence.jsonl` 与 `run_manifest.jsonl`。
- `PatchAnalyzer` 有界解析 Git 或本地 unified diff，输出 changed files/hunks、added/removed 坐标、Guard/early-return/removed-dangerous-call 词法候选、冲突与未决项；本地 patch 可与同一路径的不可变 Git diff 交叉核对。解析事实与漏洞语义分开，`semantic_status` 固定为 `uncertain`。
- `CriticalOperationResolver` 以 Sink/Guard 双模式核对候选是否位于漏洞 commit 的真实源码及 fix diff 的 removed/replaced side。fix 新增 Guard 只作为旧版控制流缺口线索，不会被转换为漏洞版本位置；即使事实完全吻合，最终角色仍为 `uncertain`。
- `EntryPointSearcher` 只读取调用者显式提供的不可变 Git blob，支持 Python、JS/TS、Java、Go、Ruby、PHP 的 route/RPC/CLI/handler/export 结构线索，并执行文件数、总字节和候选数预算。它不枚举仓库，也不声称运行时可达性或到达 Critical 的调用图已经证明。
- `T1DeterministicValidator` 已组合以上三层：Patch 解析失败被隔离到单条记录，字段仍保留可读证据与完整 evidence refs；结构事实绝不把 Entry/Critical 字段提升为语义 `correct`。以上仍是确定性 T1 基础设施，不是完整的语义 T1。
- `T2TaskInputV1` 是严格、版本化、无本机路径的任务契约。公告/patch 相对路径、规范化 GitHub URL 和有界 hints 都视为不受信任务数据；本地资料根、仓库映射、模型后端和凭据只存在于受信进程配置中。
- `ProducerExecutionContext` 由 Orchestrator 持有的 attempt controller 签发，`LocalT2ContextFactory` 才能把无路径任务绑定到受信本地根、固定工具注册表和模型后端。Producer 不能自行扩大工具 allowlist、伪造调用记录或绕过工具/模型预算；调用记录与预算事件按 task、attempt、policy scope 和事件序号闭合。
- `RunTask`、`ProductionOutcome` / `ProductionDeferred`、`ToolCallRecord` / `ModelCallRecord`、`RepairPlan`、`Budget` 与 sanitized `RunState` 已形成严格契约。无法建立唯一证据、模型拒绝、预算不足或契约/工具失败时产生显式 defer，而不是拼出部分 Entry。
- `RepairPlan` 对 repair/dependent/locked 字段做完整分区，并以 canonical SHA-256 锁定不可改字段。版本化 repair tool policy 对各字段给出固定 `required_checks` 与 `allowed_tools`：工具权限只能收窄，必需检查不能删减；空 allowlist 明确表示 deny-all。任何缺少受信验证器或权限的必需检查都 fail closed 为 defer。
- `LocalStructuredT2Producer` 已支持离线读取真实本地 Git 对象的 generate 流程：严格任务 → plan → 公告/仓库/fix-parent/diff 事实 → 有界候选 → semantic judge → 15 字段 Schema → reflection。模型只能在工具签发的候选 ID 中选择位置，`verify` 固定为 `0`；歧义 fix、非唯一父提交、缺失 source diff、Guard 无法落到漏洞版本等情况都会 defer。
- 受限 repair 已支持标题、分类等有界字段，并实际执行当前可用的任务、公告与 Schema 检查；其中 semantic check 仍是受限模型判断，不是最终 T1 正判。repair 只能采用 RepairPlan 中 T1 已给出的 `suggested_fix`，只能修改获批字段，且必须保持任务身份与 locked 字段；源码位置、patch 区域、祖先和 trace 连续性等尚无专用全字段 verifier 的检查不会被当作 prompt 文本“默认通过”。
- `ClosedLoopOrchestrator` 同时支持 FakeT2 回归测试和上述真实 Producer 接口：每轮创建全新 T1，仅传原始任务与正式候选；初始候选后最多修复两轮、最多验证三次。它拒绝越权改锁字段、无变化、错误重复、原正确字段回归、调用/预算对账不闭合及跨轮 sidecar 冲突，所有停止原因进入 Schema-valid 状态快照。

代码实现、固定策略和本地运行配置属于受信计算基；模型输出与全部任务/资料数据均不受信。Git/公告/Schema 等事实必须由受限工具重新建立，模型提出的标题、分类和语义选择仍受严格输出契约约束，并等待独立 T1 裁决。canonical digest、哈希链和 unsigned JSON transcript 只证明一次记录内部的 closure、绑定和一致性，不提供数字签名，也不证明公告、仓库或模型结论的外部真实性；抵抗拥有持久化写权限者的整体重写仍需外部签名或可信事件根。

尚未完成：closed-loop 批量 CLI、统一 replay artifact writer 与跨进程重放入口；覆盖所有字段的 `required_check` 确定性 verifier；受影响版本范围及 merge/backport/squash 裁决；AST/调用图/数据流支撑的最终 Entry/Critical/trace 语义；独立 T1 的语义正判；以及题目要求的最终训练集与公开测试集验收。数据集由独立数据生产流程构建并接入本项目，本仓库当前实现不声称已完成最终 50+20 数据验收。

### 下一阶段

下一阶段先把现有 Producer/Orchestrator 接入逐任务隔离的 closed-loop 批量 CLI，落盘可校验、可重放的 candidate/tool-call/model-call/repair-history artifacts；再逐项补齐全字段 `required_check` verifier 与独立语义 T1。随后接入独立流程提供的数据集，完成训练集与公开测试集的端到端 50+20 验收，再决定完整 trace、AST/数据流与更多语言增强。
