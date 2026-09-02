# VulnGym T1 × T2 自动化闭环设计说明（提交源稿）

> 文档状态：草稿，更新于 2026-09-02。最终版须导出为 1-3 页 PDF，并完成逐页
> 渲染检查；当前尚未生成可验收 PDF。正式 replay、原生 Linux 全量门禁、完整
> Entry 提交输出与外部评分仍为 TODO，不构成通过验收的声明。

## 1. 两条已实现但不可混称的执行链

当前代码包含两个用途不同的入口，二者共享安全与证据原则，但输出契约不同。

```text
Lane A：完整 Entry 的 T2 → T1 闭环
本地公告/patch + 受信 repo + exact replay
  → Planner → 本地工具 → Semantic Judge → schema → Reflection
  → T1DeterministicValidator → [受限 repair → schema → Reflection → 新 T1]
  → entries.jsonl + validation.jsonl + sidecars

Lane B：formal-70 的 source-only 发现与隔离门禁
无答案 task + sealed source + ordered D2/D3 replay
  → E4 串行调度 E3 OCI [D2 多候选 → D3 独立复核 → D4/D0]
  → findings.jsonl + task_results.jsonl (+ train aggregate) + receipt/readback
```

Lane A 由 `python -m vulngym_agent.closed_loop_cli` 驱动，候选是完整 VulnGym
Entry，只有真实 T1 报告闭合的结果才进入 `entries.jsonl`。Lane B 由
`python -m vulngym_agent.final_gate_cli run|verify-output` 驱动；其 D0 Finding
只包含评测所需的 task/finding 身份、repo/commit、Entry/Critical 位置及可选 trace，
**没有调用 `T1DeterministicValidator`，也不是完整 `entries.jsonl`**。因此 Lane B 的
20+50 `findings.jsonl` 不能替代考题要求的公开测试 Entry JSONL；最终提交前必须另行
产出并校验完整 Entry（含 `code` 与 `verify=0`），或由评测方书面确认 Finding 契约可替代。

补充入口：`python -m vulngym_agent` 是独立 T1 批量校验器；
`replay_authoring_cli` 逐题制备 D2/D3 replay；`benchmark_cli` 校验固定 50/20
profile 并执行投影；`native_linux_final_gate_preflight` 只做正式主机只读预检。
仓库当前没有 wheel/console-script 安装包，从固定 commit 的只读 checkout 运行，要求
Python 3.10 或更高。

## 2. Planner、工具、prompt 与反幻觉约束

Lane A 的模型协议不是一次性 prompt。`plan` 先选择 analyze/defer 与 critical mode；
控制器随后调用本地 `read_local_advisory`、`extract_advisory_fields`、
`read_local_patch`、Git parents/show/diff/ancestry、critical candidate search、route
recognition 和 `validate_schema`。`semantic_judge` 只能选择控制器签发的不透明候选 ID，
只能补充有界的 project/title/category 文本；模型不能自行提交 commit、路径、行号或
代码。初始候选通过 schema 后由 `reflection` 选择 emit/defer；T1 若提出可验证的
`suggested_fix`，repair 只能改获批字段，并再次通过 schema、Reflection 与新建 T1。
信息不足、契约错误、工具失败或检查能力缺失均 defer。

Lane B 的 D2 prompt 采用 SCOUT/SELECT 两阶段，只允许 inventory、literal search、
span read、lexical structure、mechanical link、source validate 六类 source-only 工具；
选择结果必须引用 runtime 签发的 opaque refs。D3 使用重新获取的 tree、budget 与
context，不读取 D2 推理，对 entry role、critical role、trace continuity 和
counter-evidence 分别给出 supported/contradicted/insufficient。D4 只有在 D3 严格
accept 时才投影 Finding。作者/批评者是 replay 制备与 QA 角色，不是运行时第三个
Reviewer；运行时独立 Reviewer 专指 D3。

生产数据面只读取出题方提供的本地缓存、patch 和源码，不联网爬取，也不调用“已知答案
API”。test gold 必须物理隔离，不能进入 task、replay、日志或调试输入。

## 3. 信任边界、可复现性与当前证据

代码、固定策略、受信输入 pin 和 evaluator 属于信任基；task、源码内容、模型输出、
replay response 与候选结论均不可信。正式 worker 目标配置为断网、非 root、只读
rootfs、drop-all capabilities、`no-new-privileges`，并限制 CPU、内存、进程和超时。
测试必须闭合后才能进入训练。canonical JSON、哈希链和 receipt 证明字节绑定与机械
闭合，不是数字签名，也不证明漏洞语义正确；质量结论只能引用隔离评分。

22 个仓库、70 个 task 的 source sealing 已完成。实现 commit 为
`fb1c74be16ed36dc5dba11c8ae30230a2e6368c6`，净化可披露证据 commit 为
`c52f48b770736d403b2ce090b10a70e5498804e0`；evidence index 为
`06de018ed3de2483adcfc0ab000b42e937e238a459908d19c023187388349c69`，closure
receipt semantic/wire pin 为
`e7e2e263ad05e785bb28fa252eb8f953c46dd046d4f8c00d5a1b99e57d6cbca1` /
`2d2767f57712042d885a2512062a87b2e281f65aa5ef6f444cd584e0d6d95bac`。
这些值来自 #60 收口记录及其 13 文件净化证据包；它们只证明 source-sealing 阶段，
当前仓库为私有仓库，“可披露”不等于已经公开发布。

工程踩坑主要是：不能把 fix commit 当漏洞 commit；浅历史、packed object/MIDX、gitlink、
Windows 长路径与重命名目录都需按对象/字节身份处理；发布必须 staging + no-replace，
不能用名称回滚掩盖不确定状态；高频轮询会放大日志与磁盘压力。

## 4. 提交前阻断项

- 完成 70/70 有意义的 Lane B D2/D3 replay、native Linux preflight、20 test-first +
  50 train、独立 readback 和外部评分；
- 为考题交付生成 Lane A 完整公开测试 `entries.jsonl` 与 `validation.jsonl`，逐行通过
  `SCHEMA.md`，并明确它与 Lane B `findings.jsonl` 的关系；
- 填入真实指标、版本、receipt、CI URL、已知限制与视频链接；
- 导出 1-3 页 PDF；若新增 prompt/工具表导致超页，优先移走 digest 细节而不是删掉题目
  明确要求的 prompt、工具和踩坑说明。
