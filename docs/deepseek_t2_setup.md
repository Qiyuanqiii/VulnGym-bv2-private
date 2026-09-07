# DeepSeek V4 Pro：T2 模型配置与实跑前检查

2026-09-07：用户选择 DeepSeek V4 Pro。适配器已实现；当前验证使用本地构造数据与模拟 HTTP，**尚未完成真实 API 连通性或新报告质量测试**。本会话的进程环境中没有 `DEEPSEEK_API_KEY`；未读取其他应用密钥，未产生模型调用费用。

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

## 5. 本次验证记录

2026-09-07，Python 3.13.12，临时目录放 D 盘：针对性回归 192 项，191 通过、1 跳过、0 失败；其中新增 DeepSeek 配置/协议/传输/生产集成测试 25 项。跳过的是既有 Windows 符号链接读取测试（账号缺少创建链接特权），未更改权限。

```powershell
python -B -m unittest tests.test_deepseek_backend tests.test_t2_production_cli tests.test_closed_loop_batch tests.test_real_t2_producer tests.test_model_runtime tests.test_t2_execution tests.test_t2_inputs tests.test_t2_toolbox tests.test_producer_contracts tests.test_producer_context tests.test_closed_loop_replay tests.test_submission_prediction -q
```

实际本机 `--check-config` 返回 `deepseek_configuration_missing_or_invalid`，另以仅检查变量是否存在的方式确认 key 缺失；network_calls=0。此处的模拟 HTTP 测试、真实本地 T1 调用和缺配置预检，均不证明真实 DeepSeek 账号可用或新报告语义正确。`git diff --check` 通过；完整代码版本以引入本文的 commit 为准。
