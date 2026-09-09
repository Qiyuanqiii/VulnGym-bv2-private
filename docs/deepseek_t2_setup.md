# DeepSeek V4 Pro：T2 模型配置与实跑前检查

**最新状态（2026-09-09）**：当前提示词`t2-json-v5`已完成[独立授权的真实诊断](t2_context_retest_v3_receipt.md)：5次HTTP返回，1份完整候选/T1，另1题达到8,192输出上限被拒收；整批退出1，不是网络超时或全部成功。零重试，key使用已结束；不得重跑原目录或复用已结束授权。下文历史“当前/最新”仅指各段日期阶段。

**当前状态（2026-09-09）**：prompt-v4首次[两份新输入实跑](t2_new_input_live_receipt.md)为4请求、0完整候选、2语义defer。随后修正上下文排序，[同输入诊断](t2_context_retest_receipt.md)在新key限额确认后已经执行：plan成功、语义请求120秒超时，第二题未发送；无新语义结果，不能判断修正效果。key已结束使用并通知撤销；不自动重跑。启动步骤见[quickstart](../START_HERE_T2.md)，以下旧状态保留历史含义。

**当前代码（2026-09-08离线增量）**：[自检弃答与交接](t2_handoff_reflection_receipt.md)已实现，提示词身份为t2-json-v4。新生产reflection contract_version=2的defer须给有当前证据引用的短说明，emit仍只有action；旧默认保持原形状。324项回归323通过、1跳过，尚未调用真实服务验证v4；下面最新实跑仍是0190850/t2-json-v3的历史结果，不再使用那枚key。

**最新（2026-09-08）**：[候选覆盖修正后的真实复测](deepseek_t2_candidate_retest_receipt.md)已结束：6次成功HTTP、61,907 tokens，Flowise生成1份完整候选及T1报告（uncertain），Langflow在reflection阶段defer；两条最终manual_review，finalized=0。完整候选由同输入上次0/2变为1/2，不是正确率。临时key已用完并通知撤销，不再调用。下一步离线评价、补自检理由/混合批次交付说明，然后做新输入评价。以下记录均保留各自历史阶段含义。

此前[v3同输入真实复测](deepseek_t2_context_retest_receipt.md)：4次成功请求、33,208 tokens，两条均在semantic阶段defer，完整Entry/T1为0。候选/入口范围局限随后已离线修正并由上方新批次复测，旧结果未覆盖。

2026-09-07：用户选择 DeepSeek V4 Pro。适配器已实现；随后获准的 [两条公开输入试跑](deepseek_t2_smoke_receipt.md)得到 2 次真实成功响应，但两条均在本地候选提取阶段 deferred，完整 Entry 和 T1 调用均为 0。**接口连通已验证，新报告生产质量尚未验证。**临时运行已结束并提醒用户撤销密钥；不再使用本次凭证。

后续 [离线路由修复](t2_evidence_first_planning.md)已将生产 plan 改为先看有界公告/diff/候选证据，提示词身份为 `t2-json-v2`；249 项回归为 248 通过、1 跳过。相同输入在非模型诊断下到达语义阶段后主动弃答；在该离线修复阶段还未进行新版真实模型复测。

此前[2条真实复测](deepseek_t2_retest_receipt.md)：4次成功请求、14,705 tokens，两条均到达semantic_judge后弃答，完整Entry/T1为0。当时确定先补语义上下文及具体弃答说明，不扩大付费批次；该次临时凭证已结束使用并通知撤销。

后续[离线上下文修正](t2_semantic_context_receipt.md)将提示词身份升为 **t2-json-v3**：新生产语义与初始自检共享固定diff/源码上下文，合法语义弃答须提供有当前证据引用的结构化说明。276项回归为275通过、1跳过。该离线阶段尚未实跑v3且用户确认当时key已撤销；后来真实调用按文首新记录计数，离线探针不作质量成绩。reflection弃答的详细理由仍不在此语义说明契约覆盖内。

## 1. 模型与调用约定

按 [DeepSeek 官方入口说明](https://api-docs.deepseek.com/) 使用模型 ID `deepseek-v4-pro` 和官方主机 `api.deepseek.com`。适配器调用 `/chat/completions`，不换成旧别名、Flash 或第三方中转。

按照 [JSON 输出说明](https://api-docs.deepseek.com/guides/json_mode/)，同时指定 JSON 输出格式和明确的 JSON 响应示例；返回空内容、非法 JSON 或截断内容均不当成成功。JSON 语法正确不等于字段/语义正确，后面仍有现有 producer/schema/T1 检查。

[官方思考模式文档](https://api-docs.deepseek.com/guides/thinking_mode/)列出 low/high/max。下面是**本项目的默认值和约束**，不是 DeepSeek 服务上限：

| 设置 | 默认 | 本项目允许范围/含义 |
| --- | --- | --- |
| 模型 | deepseek-v4-pro | 固定此 ID，不自动降级或替换 |
| thinking | enabled | 不发送无效的 temperature/top_p 组合 |
| reasoning_effort | high | low / high / max；首次小批先按 high |
| max_tokens | 8192 | 256–32768；长度截断单列为错误，不拼补残缺 JSON |
| timeout_seconds | 120 | 1–300；活动 socket 有截止定时器与每阶段剩余超时 |
| 自动重试 | 0 | 单个逻辑调用最多一次 POST |
| 请求/响应体 | 各 2 MiB | 拒绝超大内容和压缩响应，不自动跟随重定向 |

适配器使用 Python 标准库，无需安装模型 SDK。默认直连官方主机，不读取代理环境变量；如果必须使用其他网络路径，应先说明所需配置，不随意改发送目标。

超时定时器会关闭活动 socket，持续返回空白保活字节也不能无限延长读取；操作系统 DNS 解析本身不由 Python socket 取消控制，若解析晚于截止时间才返回，会放弃继续发送。首次实跑仍需记录实际耗时，不承诺任何环境下绝对秒级终止。

## 2. 密钥只在本机配置

不要把密钥发送到对话、Issue、源码或命令行明文参数。可在自己打开的 PowerShell 中隐藏输入，并只供该窗口及子进程使用：

```powershell
$env:DEEPSEEK_API_KEY = [System.Net.NetworkCredential]::new('', (Read-Host 'DeepSeek API Key' -AsSecureString)).Password
$env:TEMP='D:\VulnGym-bv2-runtime\tmp'
$env:TMP=$env:TEMP
python -B -m vulngym_agent.agents.deepseek_backend --check-config
```

从 producer 工作区运行。上述预检**不联网、不收费**，只返回已配置的非敏感参数；成功状态是 `configured_not_connected`，不是“密钥已验证”或“余额足够”。缺失/格式错误返回退出码 2。

该临时环境变量不会自动传到已运行的 Codex。若希望由本会话运行后续命令，需让它能继承你配置的环境；否则在上述同一 PowerShell 窗口运行生产命令。完成后可 `Remove-Item Env:DEEPSEEK_API_KEY` 清除当前窗口的值（不删除磁盘文件）。

可选配置变量：`VULNGYM_DEEPSEEK_REASONING_EFFORT`、`VULNGYM_DEEPSEEK_MAX_TOKENS`、`VULNGYM_DEEPSEEK_TIMEOUT_SECONDS`。未设置时采用上表默认值。适配器不会搜索 `.env`、浏览器、Qoder 或其他应用的登录数据。

## 3. 获准后的小批生产命令

先确认账号调用授权、费用预期，以及这批公告/源码片段允许发送给 DeepSeek；不要仅因本地预检成功就自动跑全量。首批上限 2 个公开任务，使用新输出目录：

```powershell
python -B -m vulngym_agent.t2_production_cli `
  --tasks D:\T2-input\tasks.jsonl `
  --repo-map D:\T2-input\repos.json `
  --package-root D:\T2-input\package `
  --backend-factory vulngym_agent.agents.deepseek_backend:create_backend `
  --output-dir D:\T2-output\deepseek-new-run-001 `
  --max-records 2 --max-llm-calls 8 --max-tool-calls 80
```

输入/输出路径是示例占位符，需换成经过确认的实际公开资料包，不是已有待执行批次。任务格式、完整候选的投影与错误计数参见 [T2 生产 runbook](t2_production_runbook.md)。8 次是每个任务的逻辑模型调用预算，不是全批总调用数，也不是费用上限。

401/402/403/429 会记录明确原因，并锁住该 backend 实例的后续网络调用，避免同批反复尝试；不自动重试、换账号、换模型或忽略权限阻断。确认账号/配额等条件已解决后，再决定是否启动新的、明确获准的运行。其他异常也保留真实 code，不把服务失败说成语义证据不足。

## 4. 可追溯性与质量边界

- backend ID 绑定提示词哈希、model ID、推理档位、预算、超时等配置；密钥不参与公开哈希。
- 每次模型请求只包含当前 task/attempt 的 payload，无隐式跨任务聊天历史。模型最终 JSON 进入既有调用哈希记录；服务的 `reasoning_content`、原始异常、响应头不写入工件。
- 新生产路径的 reflection 现在收到实际候选、对应公告/选中候选证据；repair reflection 收到修前/修后候选与检查依据。旧回放默认请求形状不变。缺少实际候选上下文时，DeepSeek 适配器在发送前拒绝自检调用。
- 自检仍不是独立复核，更不是人工签名；所有机器 Entry 保持 verify=0。不以 T1 finalized 比例或候选 ID 存在性代替质量评价。
- `deepseek-v4-pro` 是服务端可更新的别名，提示词/代码配置固定不代表模型权重固定。真实批次需记录日期与适用限制；本次没有伪造服务响应版本、token 消耗或费用数据。

后续 #12/#97 仍须真实小批、新输入评价、5 incorrect 核查及 35 uncertain 分类；#12 不因适配器接通就关闭。

## 5. 适配器首次实现时的离线验证记录

2026-09-07，Python 3.13.12，临时目录放 D 盘：针对性回归 192 项，191 通过、1 跳过、0 失败；其中新增 DeepSeek 配置/协议/传输/生产集成测试 25 项。跳过的是既有 Windows 符号链接读取测试（账号缺少创建链接特权），未更改权限。

```powershell
python -B -m unittest tests.test_deepseek_backend tests.test_t2_production_cli tests.test_closed_loop_batch tests.test_real_t2_producer tests.test_model_runtime tests.test_t2_execution tests.test_t2_inputs tests.test_t2_toolbox tests.test_producer_contracts tests.test_producer_context tests.test_closed_loop_replay tests.test_submission_prediction -q
```

首次实现时，本机 `--check-config` 返回 `deepseek_configuration_missing_or_invalid`，另以仅检查变量是否存在的方式确认 key 缺失；network_calls=0。此处的模拟 HTTP 测试、真实本地 T1 调用和缺配置预检，均不证明真实 DeepSeek 账号可用或新报告语义正确。`git diff --check` 通过；完整代码版本以引入本文的 commit 为准。后续真实试跑状态见本文开头，不改写该次离线测试的历史记录。
