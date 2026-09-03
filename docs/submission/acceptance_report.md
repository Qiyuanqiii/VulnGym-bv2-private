# VulnGym B-v2 验收报告模板

> 当前判定：**NOT READY - 尚未完成最终验收。**
>
> 本模板更新于 2026-09-03。只把可回读事实标为完成；框架测试、source sealing 和
> evaluator Finding 均不得冒充完整 Entry 质量验收。

## 1. 提交包身份与必需交付物

| 项目 | 当前记录 |
| --- | --- |
| 最终提交 commit / tag / release | TODO |
| 受审查分支 | `codex/b-v2-source-discovery`（最终版改为冻结 commit） |
| Python / OS / OCI 版本 | TODO |
| README / 一键复现命令 | 现有 `README.md`、`README_zh.md`；最终 quickstart TODO |
| 1-3 页设计文档 PDF | 源稿 `docs/submission/design.md`；PDF 导出与视觉验收 TODO |
| 公开测试完整 Entry JSONL | TODO：`entries.jsonl`，逐行符合 `SCHEMA.md`，`verify=0` |
| T1 报告 JSONL | TODO：与上述 Entry 同批的 `validation.jsonl` |
| evaluator Finding 输出 | TODO：Lane B `findings.jsonl` / `task_results.jsonl` / manifest |
| 自评 | `docs/submission/self_assessment.md` 草稿；真实评分 TODO |
| 5 分钟演示 | `docs/submission/demo_script.md` 草稿；视频链接 TODO |
| Issue/PR/commit/AI coding 使用记录 | 私有追踪已有；最终可访问的净化索引 TODO |

## 2. 两条执行链与验收状态

| 链路/阶段 | 验收项 | 当前状态 | 证据或待办 |
| --- | --- | --- | --- |
| 公共输入 | 固定 50 train + 20 test、schema、来源与 hash | 已有实现；最终 release 祖先与文件集仍需回读 | TODO |
| Source | 22 repositories、70 task source sealing | **完成** | 私有 Issues #60/#11；净化可披露 evidence commit `c52f48b770736d403b2ce090b10a70e5498804e0` |
| Lane A | 完整 Entry 的 `closed_loop_cli` T2→真实 T1 | **部分完成**：40 条 strict+fallback 真实闭环已跑通，0 input failure；仍未达到全量 20+50 finalized | `docs/lane_a_hybrid_readiness_receipt.md`、`docs/submission/lane_a_manual_review_evidence.md`；仍需最终 `entries.jsonl` + `validation.jsonl` + manifest |
| Lane B | 70/70 source-only D2/D3 replay、D4/D0 | **未完成** | Issue #90 当前 0/70；TODO |
| Runtime | 最终 OCI 与 native Linux preflight | **未完成** | Issues #91/#92；TODO |
| Gate | test-first 20/20 | **未完成** | Issue #94；TODO |
| Gate | train 50/50 与独立 readback | **未完成** | Issue #95；TODO |
| Eval | blind-test 外部评分与 train aggregate | **未完成** | Issue #97；TODO |
| Submit | 文档、自评、演示 | 草稿 | Issue #99；真实结果、PDF、视频 TODO |
| Release | 全局审计、tag/release、Epic closure | **未完成** | Issue #102；TODO |

Lane A 和 Lane B 不能合并表述。Lane A 候选包含完整 VulnGym Entry，并真正调用
`T1DeterministicValidator`；Lane B final gate 执行 source-only D2/D3/D4/D0，随后发布
评测 Finding，**不调用 T1**。当前 Finding 只有 task/finding ID、repo/commit、
Entry/Critical 的 file/line 和可选 trace，不含完整 Entry 的公告、标题、分类、code、
`verify` 等字段。除非评测方书面确认替代契约，否则它不是考题要求的公开测试 JSONL。

## 3. 已完成 source-sealing 证据与来源边界

13 文件净化可披露证据包位于
`evidence/issue-60-source-sealing-fb1c74b-recovery-a2/`：evidence index 记录 11 个
受索引文件，另有 `evidence-index.json` 和 `closure-comment.md` 两个自描述/收口文件。
该目录可直接回读的事实包括：

- implementation commit：`fb1c74be16ed36dc5dba11c8ae30230a2e6368c6`；
- sanitized evidence commit：`c52f48b770736d403b2ce090b10a70e5498804e0`
  （当前仓库为私有仓库，尚不表示已公开发布）；
- 22 repositories / 70 tasks（20 test、50 train），blocked=0；
- evidence index SHA-256：
  `06de018ed3de2483adcfc0ab000b42e937e238a459908d19c023187388349c69`；
- closure receipt semantic/wire SHA-256：
  `e7e2e263ad05e785bb28fa252eb8f953c46dd046d4f8c00d5a1b99e57d6cbca1` /
  `2d2767f57712042d885a2512062a87b2e281f65aa5ef6f444cd584e0d6d95bac`；
- test/train task closure：
  `d42a2d3cd4fc497d99175314d9ae1fc6086340c091962f14087a42eddcf16642` /
  `9ed1d4dd31b323789fedbdbe0b3809c4507ab4835e67ce40dd872937e4990ed2`。

下列事实来自私有 Issue #60 的收口记录，而不是上述 13 文件单独、直接证明：固定
finalizer tests 29/29；两次 `--readback-only` 均 exit 0、stderr 为空且 stdout
逐字节一致；readback stdout SHA-256 为
`15d5e50b281bc98dab4150368fda5e6a181fae205d61061f54192ffdb5077d7e`。
最终提交若引用这些事实，必须附评审者可访问的净化记录或把对应 receipt 纳入提交包。

控制用 publication plan、源码、密钥、原始 source mapping、宿主路径与未净化日志不属于
公开提交物。发布前对最终文件集重新做路径/凭据/隐藏答案扫描，不能把本模板的声明当扫描证据。

## 4. 必须记录的正式命令与结果

### 4.1 回归与版本冻结

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python -m compileall -q examples scripts tests vulngym_agent
```

- 当前绿色基线：commit `58740947b16880901b49cd76ea24372d06891069` 的
  [CI run 33591385570](https://github.com/Qiyuanqiii/VulnGym-bv2-private/actions/runs/33591385570)
  已通过 Ubuntu/Windows 的 Python 3.10/3.13 及 native Linux OCI 单题门禁。
- TODO：最终 SHA 变更后重跑同一 matrix；只有最终 SHA 全绿后才能冻结正式 OCI。

### 4.2 Lane A：完整 Entry 的 T2→T1

```bash
python -B -m vulngym_agent.closed_loop_cli \
  --tasks <approved-public-test-tasks.jsonl> \
  --replay-responses <exact-replay.json> \
  --repo-map <trusted-repo-map.json> \
  --package-root <local-cache-root> \
  --output-dir <new-output-dir> \
  --require-all-finalized
```

- 已完成扩展 hybrid 批次：test 12/20、train 28/50，共 40/70。strict+local
  fallback 批次、identifier-subset v2 增量批次以及 `strict-v2/train-43ac81`
  的 `closed_loop_cli` 均 exit 0，`input_failures=0`，全部进入
  `manual_review`。
- reviewer evidence 已记录：test11 digest
  `367bd779089dbb5942b323cfd553d3d8c4908f526e4e3ecb1fe02492c5a3b46a`；
  train23 digest
  `a1c49ec59abbbe0df612826594026a436158aab2c34a5c126f89ba7bf2ca8d72`；
  identifier-subset-v2/test1 digest
  `4988b1e6d5c490fc8878b377679fa128dc73e1ce4595796f1a2723b25eb5f652`；
  identifier-subset-v2/train4 digest
  `ba9d2403d1c4f28a9a738b16c8825539e01d93f515079f262bbd6382874764b0`；
  strict-v2/train-43ac81 digest
  `86fad1282f1b5f25f26c3b19fc0bffd15cd3798d2d6d95e5a120f284f0737e0b`。
- TODO：继续增强 T1 或整理人工复核证据，使最终公开测试能形成评审认可的
  `entries.jsonl`、`validation.jsonl` 和 manifest。
- TODO：用 `submission_prediction_cli export` 从固定 replay 生成三文件提交面，再用
  `verify` 携带外部 replay/submission 双 pin 重读源 replay；不能只验证输出自己的 manifest。

### 4.3 Native Linux preflight

按 `docs/native_linux_final_gate_runbook.md` 使用固定主机、Unix socket、OCI image、
plan 和两组 replay/source pin 执行。

- readiness semantic SHA-256：TODO
- readiness wire SHA-256：TODO
- operator assertion wire SHA-256：TODO
- preflight exit/status：TODO（必须为 0/`ready`）

### 4.4 Lane B：test-first final gate

```bash
python -B -m vulngym_agent.final_gate_cli run \
  --benchmark-root <trusted-public-benchmark-root> \
  --output-root <new-final-gate-output> \
  --docker-executable /usr/bin/docker \
  --docker-host unix:///run/vulngym/docker.sock \
  --runtime-image-id <fixed-image-id> \
  --readiness-file <readiness-report> \
  --expected-readiness-sha256 <sha256> \
  --expected-readiness-wire-sha256 <sha256> \
  --plan-file <final-gate-plan> \
  --expected-plan-sha256 <sha256> \
  --expected-plan-wire-sha256 <sha256> \
  --test-sealed-batch-root <test-sealed> \
  --test-replay-config-root <test-replay> \
  --train-sealed-batch-root <train-sealed> \
  --train-replay-config-root <train-replay> \
  --test-key-file <test-key> \
  --train-key-file <train-key>
```

- Test：TODO/20；只有 test receipt 关闭后才允许启动 train。
- Train：TODO/50；final receipt semantic/wire SHA-256：TODO。
- 输出：TODO `findings.jsonl` / `task_results.jsonl` / manifest / train aggregate digest。
- 残留 container/execution image：TODO（必须为 0）。

### 4.5 独立读回

```bash
python -B -m vulngym_agent.final_gate_cli verify-output \
  --output-root <final-gate-output> \
  --benchmark-root <trusted-public-benchmark-root> \
  --expected-receipt-sha256 <sha256> \
  --expected-wire-sha256 <sha256>
```

- Reviewer：TODO；exit/status：TODO；结果 digest：TODO。
- 该命令读回 Lane B publication，不验证 Lane A 完整 Entry 语义。

## 5. 外部评分与发布前清单

- T1：字段级准确率、找错召回、证据可追溯人工抽样、异常输入鲁棒性：TODO。
- T2：字段级 F1、Hallucination 率、Schema 合规率、代码字段准确率：TODO。
- Lane B：blind output 路径/行数/digest、train aggregate 独立复算：TODO。
- 评分工具版本、评分者、输入/输出 digest 对账：TODO。

- [ ] 70/70 replay 非空、有意义、exact closure，并具备作者/批评者/Reviewer 证据；
- [ ] CI 全绿，最终 image 从同一已审查 commit 构建；
- [ ] 20/20 test 在 50/50 train 之前完成；
- [ ] `verify-output` 独立通过，receipt semantic/wire pin 均保留；
- [ ] 完整公开测试 `entries.jsonl` 与 `validation.jsonl` 已提交并通过 `SCHEMA.md`；
- [ ] Finding 输出没有被误称为 Entry 或 T1 结果；
- [ ] 外部评分完成，T1/T2 指标分开报告，训练 aggregate 可独立复算；
- [ ] README quickstart、1-3 页设计 PDF、自评、视频和 AI coding 记录齐全；
- [ ] release 不含密钥、gold、源码快照、原始 source mapping、宿主路径或敏感日志；
- [ ] Issue/commit/PR/reviewer/receipt 关系无孤儿、倒置或伪关闭；
- [ ] 最终 tag 指向实际通过门禁的 commit。

只有全部项目完成，标题处的 `NOT READY` 才能改为最终结论。
