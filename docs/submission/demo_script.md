# VulnGym B-v2 五分钟演示脚本

> 状态：录制前模板。正式 20+50 门禁、完整 Entry 输出与外部评分完成前只能说
> “待验收”。35 小时是固定串行最坏预算，不在视频中重跑；正式运行可预录，现场必须
> 对同一输出执行快速 readback。目标成片 4:40-4:50，留 10-20 秒切屏余量。

## 录制前硬准备

- 冻结并展示同一个 commit/tag、CI、OCI image ID 与输入 pin，填完所有 `TODO`；
- 准备一条允许披露、确实发生过“首次候选 → T1 反馈 → 受限修正 → 复验”的 Lane A
  样例；若没有真实样例，删除修正演示，不能编造；
- 为下方命令准备相对路径的 `demo/approved/` 本地缓存、repo map、task 和 exact replay，
  并先在干净 checkout 完整试录；
- 准备 Lane A 的完整 `entries.jsonl` / `validation.jsonl`，以及 Lane B 的
  `findings.jsonl` / `task_results.jsonl` / receipt；二者必须分屏标注，不能混称；
- 设计稿先导出 1-3 页 PDF 并逐页检查，视频只展示最终 PDF；
- 关闭通知、命令历史补全和凭据窗口。禁止展示 gold、密钥、原始 source mapping、目标
  源码快照、宿主绝对路径、未净化日志或 Git 凭据。可以展示净化后的 prompt 阶段契约、
  tool 名称、状态、计数和 digest，以证明规划/工具/反思，而不泄露原始敏感内容。

## 0:00-0:20　问题、版本与诚实结论

画面：标题、最终 commit/tag 和一句话结论。

讲稿模板：

> VulnGym B-v2 用受限 Agent 从本地公告、patch 和源码生成候选，再让确定性验证或独立
> Reviewer 拦截幻觉。今天展示的是 commit `TODO`：完整 Entry 的 T1/T2 指标为
> `TODO`，source-only 20+50 门禁为 `TODO`。任何未完成项都明确标为待验收。

## 0:20-0:50　先讲清两条 Lane

画面：最终设计 PDF 的双 Lane 架构图。

- Lane A：完整 Entry，`closed_loop_cli` 执行 Planner → 本地工具 → Semantic Judge →
  schema/self-check/Reflection → 真实 T1 → 获批 repair → 复验，发布 `entries.jsonl` 和
  `validation.jsonl`。
- Lane B：formal-70 的 source-only D2/D3/D4/D0 在 E3 OCI 内执行，E4 先 test 后
  train，发布 evaluator `findings.jsonl` 与 receipt；**这条 Lane 不调用 T1，也不是完整
  Entry 输出**。

## 0:50-2:15　真实 Lane A：一次反馈修正闭环

画面：先用半屏展示获准披露 task 的本地公告/patch 标识与模型阶段 schema，随后运行：

```bash
python -B -m vulngym_agent.closed_loop_cli \
  --tasks demo/approved/tasks.jsonl \
  --replay-responses demo/approved/exact-replay.json \
  --repo-map demo/approved/repo-map.json \
  --package-root demo/approved/packages \
  --output-dir demo/output/run-001 \
  --require-all-finalized
```

录制前保证 `demo/output/` 已存在而 `run-001/` 不存在。若复录，使用新目录名，不覆盖旧证据。

讲稿要点：

1. Planner 只能 analyze/defer；所有公告、patch、Git parents/diff/ancestry、源码候选和
   schema 事实都来自本地工具，生产数据面不联网。
2. Semantic Judge 只能选择 controller 签发的候选 ID，不能编路径、行号、commit 或
   code；Reflection 只能 emit/defer。
3. 展示 attempt sidecar `validations.jsonl` 中首次 T1 对具体字段的
   `incorrect/uncertain` 及证据，再展示 `repair_history.jsonl`：只应用 T1
   `suggested_fix` 所批准的字段，locked 字段未改；`validation.jsonl` 只作为正式报告流。
4. 最后展示复验后的 `entries.jsonl` 单行：完整必填字段、location `code`、`verify=0`，
   并报真实 exit code 和 digest。若最终仍 uncertain，应展示 defer，而不是伪装成功。

## 2:15-3:15　真实 Lane B：20→50 与独立 readback

前提：#90/#91/#92/#94/#95 均真实完成。正式运行画面可加速播放；随后现场执行：

```bash
python -B -m vulngym_agent.final_gate_cli verify-output \
  --output-root <final-gate-output> \
  --benchmark-root <trusted-public-benchmark-root> \
  --expected-receipt-sha256 <receipt-semantic-sha256> \
  --expected-wire-sha256 <receipt-wire-sha256>
```

讲稿模板：

> 在固定 native Linux 主机和 OCI image 上，preflight 为 `TODO`。E4 先串行完成
> `TODO/20` test，只有 test receipt 闭合后才执行 `TODO/50` train；现场 readback
> 返回 `TODO`，残留 container/execution image 为 `TODO`。输出的 Finding 是评测投影，
> 不含 gold，也不冒充 Lane A 的完整 Entry 或 T1 结果。

画面角落用 10 秒显示 #60 的 22 repo/70 task source-sealing 摘要与净化 evidence commit；
不要口播长 digest，也不要打开私有 Issue 评论或原始 mapping。

## 3:15-4:10　外部评分、自评与失败案例

画面：自评中的两张指标表和各一个允许披露的高质量/不确定案例。

讲稿模板：

> T1 按字段级准确率、找错召回、证据可追溯和鲁棒性报告；T2 按字段级 F1、
> Hallucination 率、Schema 合规率和代码字段准确率报告。blind test 结果为 `TODO`，
> train 独立复算为 `TODO`。最常见错误是 `TODO`；系统保留 uncertain/defer，并计划用
> `TODO` 修正。单元测试、D3 accept 与 digest 都不是语义分数。

不要把测试条目与逐题得分对应公开；案例优先选 train，测试案例须经评分方允许披露。

## 4:10-4:40　可复现性与安全边界

画面：CI、release、receipt/readback 和提交文件清单。

讲稿：

> 机械状态由固定 commit/image/input pin、canonical digest、test-first receipt 和独立
> readback 复现；质量结论只来自隔离评分。worker 断网、非 root、只读 rootfs，并限制
> capabilities 与资源。公开包不含 key、gold、源码快照、原始 mapping 或宿主路径。

## 4:40-5:00　限制与交付

讲稿模板：

> 交付包括源代码与 README、可追溯历史和 AI coding 记录、1-3 页设计 PDF、公开测试
> 完整 Entry JSONL、T1 报告、自评和演示；Lane B Finding/receipt 是额外工程证据。已知
> 限制是没有正式在线模型 backend，且全字段语义 verifier、AST/调用图/数据流仍有限。
> release 为 `TODO`，最终结论为 `TODO`。

## 未通过时的替代结尾

若任一正式门禁、完整 Entry 输出或评分未完成，结尾必须改为：

> 当前完成了 `实际完成项`，但 `未完成项` 尚未满足考题验收；这里展示失败状态、保全
> 证据和下一步，不把 smoke、Finding 投影或部分运行表述为完整 T1/T2 通过。
