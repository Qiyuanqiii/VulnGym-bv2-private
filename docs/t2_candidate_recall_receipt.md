# T2 候选覆盖修正：离线结果与剩余限制

2026-09-08：修正上次真实复测暴露的候选范围问题。**这是离线提取能力改进，不是新的模型质量成绩。**
新增模型调用、完整 Entry 和 T1 调用均为 0；上次实际模型完整产出仍为 0/2。

## 1. 修改内容

新生产路径由 `LocalProductionTaskRunner` 强制启用以下规则：

1. 保留旧词法候选的 ID 和顺序，再补入固定 diff 中非空的旧侧删除/替换行。
   不要求查询、赋值等语句命中某个函数名关键词。只提供位置提名，不能据此认定语义角色。
2. `sink` / `guard` 是待判断假设。新工具工件、plan 和 semantic 请求明确记录
   `old-side-review-pool-v1` 及 `mode_is_unverified_hypothesis=true`。
   auto 可有两种假设；显式指定的模式仍不可被模型越权替换。模型仍可 defer。
3. 提名继续经过固定 Git 版本、变更旧侧和源码位置检查；新路径的行容差为 0。
   新增池上限 128 个候选、每行 2,000 字符；生产语义候选每模式/最终集合上限仍为 64。
   超限明确停止，不静默裁掉候选后声称完整。候选增加不会自动增加上下文预算。
4. JavaScript/TypeScript 补充普通命名函数及单行、花括号函数体的箭头声明。
   新类型为 `callable`，明确不是已证明的外部入口，不自动产生路由/调用关系证据。
5. 新生产不再将文件第一个非空行作为可选入口占位符。声明路径中没有相关入口结构时，
   工具记录 `no_entry_construct_in_declared_path`；最终没有入口候选则 `no_entry_candidate` defer。
   不再因为文件首行是 import 或普通声明，就将该行作为入口候选。

源码范围不扩大：只读取任务明确声明路径在固定 commit 下的内容；没有仓库遍历、额外网络、
目标代码执行或自动补入 caller/router 文件。普通函数可以成为待复核候选，但其外部可达性仍需资料。

这是有界文本提取，不是完整语法树/调用图分析器。新增箭头识别不覆盖所有多行声明、表达式体、
复杂类型与语言组合；上下文窗口也不是完整函数保证。没有修改原目标仓库代码。

## 2. 默认回放与新生产分开

低层 `review_candidate_pool=False`、`review_callables=False` 保持历史行为，旧 exact replay 不切换。
新工具身份为：

| 工具 | 新生产身份 |
| --- | --- |
| dataflow_candidate_search | `vulngym.local-t2.dataflow_candidate_search@3-old-side-review` |
| route_recognition | `vulngym.local-t2.route_recognition@2-callables-no-anchors` |

其他工具身份未因本次修改改变。DeepSeek 提示词文本仍为 `t2-json-v3`，不冒称已经验证新的模型版本。
上下文及候选变化通过实际请求摘要、代码和上述工具身份区分。
低层单独启用复核池但保留旧字符裁剪时，入口工具使用独立的 `@2-callables-partial` 身份；
新生产强制完整行策略，不使用该组合，避免两种片段内容共享同一个新工具身份。

## 3. 相同两条开发输入：只检查覆盖

复用上次已许可的 6 个准备文件，未加载历史模型回答，也未读取评测答案。
诊断后端明确为 `offline-script-not-a-model`：选择第一个可用模式，在语义阶段主动 defer，
不生成完整数据、不运行 reflection/T1。以下计数不能当作语义正确率。

| 检查 | Langflow / Python | Flowise / TypeScript |
| --- | ---: | ---: |
| 关键候选 sink / guard | 17 / 19 | 2 / 3 |
| 入口待判断候选 | 11 | 2 |
| 本次验证补入的位置 | 原辅助函数旧侧 276–283 行 | 原赋值旧侧第 28 行 |
| 文件首行占位符 | 0 | 0 |
| 已传入源码块 / 字符 | 11 / 15,952 | 1 / 1,369 |
| 未覆盖候选锚点 | 6 | 0 |

上述新补入位置的锚点均在提供给语义阶段的上下文内。Langflow 仍有 6 个其他候选因预算未覆盖，
不能称为完整上下文；测试文件候选也没有因其文件名而被无依据排除。
Flowise 识别的 `getAllLeads`、`createLead` 都标为 callable、非外部绑定。
原输入仍只含 service 文件，**没有因此证明外部入口及其到关键位置的关系**。

候选索引只保存相对源码位置、标识、片段摘要和上下文覆盖状态，不发布源码正文、模型原始回答或凭证。
补入行号是已知开发样例的覆盖检查，不是唯一正确答案或未见样本质量评价。

可复现诊断（使用已许可资料目录，无需 key）：

```powershell
python -B scripts/probe_t2_routing_offline.py --tasks <input/tasks.jsonl> --repo-map <input/repos.json> --package-root <input/package> --max-records 2 --candidate-index
```

## 4. 验证与现场保护

- Python 3.13.12，临时目录在 D 盘；无后台轮询或重复 finalizer。
- 最终针对性回归 307 项：306 通过、1 项既有平台权限条件跳过、0 失败；135.591 秒，退出 0。
- 新测试覆盖无关键词的旧行、去重与 ID 保留、重命名旧路径、仅新增侧、字符/数量预算、
  普通 callable、无占位符、固定版本读取、零容差拒绝错位、路径范围、模式限制和拒选分流。
- 初次运行有 3 项旧测试仍假设“无关键词即无可用候选”；按新假设池契约调整，保留无候选拒选反例。
  新测试另有 2 处错误使用候选属性名，改为现有 `path` / `end_line` 后重跑。没有修改生产协议迎合这些属性名错误。
  补查后为两种片段配置分配独立工具身份，初次低层身份名超过既有长度限制，缩短名称后再跑完整回归；未放宽格式校验。
- 与 `1f72ae241b54fa0dacece2edb69b3a4272dd804d` 在同一个构造 Git 仓库上比较：默认 draft、
  全部模型请求及最终控制器记录的 14,151 个规范化字节完全相同；没有重跑历史 70 条。
- 两个独立进程的离线探针 stdout 逐字节相同；上次真实运行的 22 个运行/输入文件、170,213 字节全部保持原哈希。
- 新公共证据仅 3 文件、15,444 字节；未发现本机绝对路径、凭证形态或排除的私有评测标记。
  这不是全机器空间统计；没有清理或改写旧日志/运行数据。
- 本轮没有使用上一枚 key，也没有尝试检查它是否已撤销。

回归命令：

```powershell
python -B -m unittest tests.test_t2_review_candidates tests.test_t2_semantic_context tests.test_t2_evidence_first_planning tests.test_deepseek_backend tests.test_t2_production_cli tests.test_closed_loop_batch tests.test_real_t2_producer tests.test_model_runtime tests.test_t2_execution tests.test_t2_inputs tests.test_t2_toolbox tests.test_producer_contracts tests.test_producer_context tests.test_closed_loop_replay tests.test_submission_prediction tests.test_critical_resolver tests.test_patch_analyzer tests.test_entry_search -q
```

证据：[离线候选索引](../evidence/t2-candidate-recall-20260908/offline_probe.json)、
[代码/输入摘要及验证](../evidence/t2-candidate-recall-20260908/verification.json)、
[文件清单](../evidence/t2-candidate-recall-20260908/manifest.json)。
公共清单 SHA-256 为 `5e07ce190897681ae0490b42849eeaf64e773779cc829a821d2c1d8ef81c85d5`。
probe JSON SHA-256 为 `db58f22ad0c6d55e58a501ed31a27efc543d1088ad68699e8255ca2e6892588f`。

## 5. 接续顺序

1. 候选池已补齐上述可复现漏项。下一次实际调用需新的受限授权和有效凭证，在新输出目录小批复测；
   记录模型选择/具体 defer，不改写旧结果，不因候选数量上升就提高质量分。
2. 若仍缺入口关系，应独立整理有来源的调用者/路由资料，显式更新输入版本及许可路径，
   不暗中扩大当前任务可读范围；仍无法证明则保留待复核。
3. 新生产可用性确认后，另选并预先固定至少 2 份规则冻结后的新输入；12条开发复核包的108个格
   仍须实际评价、记录评价者和证据。不能用本次离线探针代替。
4. 按同一最终版本完成易用性演练、真实输出、自评、AI过程和演示。A1/A3/A5不升级，
   #12/#97继续开放；#90/#94不关闭。
