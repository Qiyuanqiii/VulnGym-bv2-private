# T2 证据先行路由：离线修复记录

2026-09-07，Issue #12 的实现增量。**首次真实试跑仍是完整 Entry=0、T1=0；本次没有新增模型请求。**本次修复使相同两条公开输入在诊断脚本下到达 `semantic_judge`，不代表模型已经正确生成数据，也不代表 A1/A3/A5 验收完成。

## 1. 复现与根因

[首次真实试跑](deepseek_t2_smoke_receipt.md)中，模型在看见公告正文和代码差异前选择了 `sink`，后续两条均报 `no_vulnerable_side_candidate`。离线读取相同公开资料与固定 Git 对象发现：现有词法提取器在这两条输入上只提出 `guard` 形态的候选；`sink` 模式将其全部按 `candidate_mode_mismatch` 排除。因此，旧报错不能被解释为这些报告没有可分析内容。

没有为这两题手写 Entry、扩大位置接受范围或把所有候选改成有效。位置事实通过仅表示候选可以进入后续语义判断，不表示它的角色、调用关系或分类正确。

## 2. 实际修改

- 生产入口开启 `evidence_first_planning=True`：先读公告、确认版本、读声明路径的真实 diff，再按输入允许的模式收集候选，最后请模型选择可用模式或弃答。
- `auto` 可收集 `sink` 与 `guard`；显式模式只检查指定模式，不能自动改成另一模式。没有事实条件合格的候选时，不调用模型。
- 计划请求版本升为 2。上下文包含公告摘要（最多 2,000 字符）、固定版本、最多 8 段 diff（每段最多 2,000 字符）、各模式计数和最多 4 个候选样本（代码最多 1,000 字符）；提供截断标记及遗漏 diff 计数。
- 每个模式最多接受 64 个候选，超过上限仍停止。位置、版本、源码侧、ID、预算和后续 schema/T1 条件不放宽；机器 Entry 仍为 `verify=0`。
- `DeepSeek` 提示词身份更新为 `t2-json-v2`，明确“有候选不等于语义正确”，允许拒绝不合适的模式；并未运行真实模型验证此提示词。
- 精确回放默认仍走旧版 plan-first 路径，不改变已存 response 的请求形状。反思仍是生产者自检，不是独立人工复核。

无候选的原因现在分开记录，逐文件/模式清单保留 assessed、provisional、accepted 和 resolver 原因计数：

| code | 意义与下一步 |
| --- | --- |
| `critical_extractor_no_candidates` | 提取器没有提出词法候选；核对声明路径和提取能力，不直接归因于报告无法判断 |
| `critical_mode_unsupported_by_candidates` | 全部候选与显式允许模式不符；核对输入约束及提取覆盖，不暗中切换模式 |
| `critical_candidates_rejected` | 存在候选但没有通过事实条件；查阅清单中的具体排除原因，如仅在修复侧新增 |

## 3. 相同公开输入的离线诊断

[诊断脚本](../scripts/probe_t2_routing_offline.py)不读取任何密钥、不调用服务，只在 plan 选择第一个可用模式，并在 `semantic_judge` **固定弃答**。它不能发出完整 Entry 或调用 T1，不能作为准确率样本。

| 公开输入 | 合格 guard / sink 候选 | 入口候选 | 诊断停止位置 | 新完整 Entry / T1 |
| --- | ---: | ---: | --- | ---: |
| Langflow / Python | 3 / 0 | 12 | semantic_judge，脚本主动弃答 | 0 / 0 |
| Flowise / TypeScript | 2 / 0 | 1 | semantic_judge，脚本主动弃答 | 0 / 0 |

Langflow 的 3 个候选中有 1 个来自已声明的测试文件；这也说明计数不能代替真实语义筛选。当前仍只覆盖声明路径和有界词法候选，不声称全仓分析或任意报告输入支持。

本地复现（占位路径须替换为已获准的公开资料包；不传 response 文件）：

```powershell
$env:TEMP='D:\VulnGym-bv2-runtime\tmp'
$env:TMP=$env:TEMP
python -B scripts/probe_t2_routing_offline.py `
  --tasks D:\T2-input\tasks.jsonl `
  --repo-map D:\T2-input\repos.json `
  --package-root D:\T2-input\package --max-records 2
```

本次实际使用首次试跑 v2 目录下原有 `input/` 资料，未改写旧输出。计数和 producer 文件哈希见 [offline_probe.json](../evidence/t2-evidence-first-20260907/offline_probe.json)；输入、代码文件指纹及验证记录见 [verification.json](../evidence/t2-evidence-first-20260907/verification.json)。文件指纹是执行时磁盘字节 SHA-256，跨环境换行变化会改变它；完整实现 SHA 由承载本文和证据的同一 Git commit 固定。

## 4. 回归与历史保护

Python 3.13.12，临时目录在 D 盘，以下针对性回归共 **249 项：248 通过、1 跳过、0 失败**，耗时 131.544 秒，退出码 0。其中本次新增证据路由/诊断测试 15 项；跳过的是既有 Windows 符号链接权限用例，没有修改权限。

```powershell
python -B -m unittest tests.test_t2_evidence_first_planning tests.test_deepseek_backend tests.test_t2_production_cli tests.test_closed_loop_batch tests.test_real_t2_producer tests.test_model_runtime tests.test_t2_execution tests.test_t2_inputs tests.test_t2_toolbox tests.test_producer_contracts tests.test_producer_context tests.test_closed_loop_replay tests.test_submission_prediction tests.test_critical_resolver tests.test_patch_analyzer -q
```

另把修改前 `4579620e90a7fa286c420bb9884e5597c343e4f0` 的 producer 与本次默认 producer 放在**同一个构造 Git 样例**上执行：候选/证据、全部模型请求的规范化字节、控制器最终执行记录一致。这是旧请求兼容性检查，不是 70 条回放重跑。首次真实试跑清单的 15 个运行文件长度和 SHA-256 全部仍匹配。

## 5. 尚待完成

1. 用户重新配置并授权凭证后，对这 2 条开发输入做受限真实复测，记录是否到达语义阶段、完整 Entry/T1 数和失败原因；旧临时凭证不再使用。
2. 对实际产物核对版本、入口/关键操作角色、分类及 trace；不能因为合格 guard 存在就强行输出。需要改提取器时，再以具体失败证据另做迭代。
3. 冻结提示词及评价口径后选择未预编排的新资料进行 #97 质量评价，原 40 条的 5 incorrect / 35 uncertain 仍单独处理。

#12、#90、#94 保持开放。本次不新增付费批次、不启动旧 finalizer、不把离线诊断算作真实生产或独立质量审核。
