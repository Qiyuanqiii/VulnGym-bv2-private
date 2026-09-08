# T2 工具：先从这里运行

2026-09-09。主产品是报告到 VulnGym Entry 的 CLI，T1 为辅助检查。当前可交接代码与真实结果，但尚未证明新输入上的稳定完整产出；不要将本文件当作全部验收通过声明。

## 1. 先确认能启动，不需要 key

在包含 `vulngym_agent` 的源码目录执行：

```powershell
python -B -m vulngym_agent.t2_production_cli --help
python -B -m vulngym_agent.submission_prediction_cli --help
```

核心 CLI 和 DeepSeek 适配器使用 Python 标准库，不必先安装模型 SDK。2026-09-09 已在从固定提交导出的源码、全新且不含第三方包的 Python 3.13.12 venv 中验证以上入口、29 项构造生产/上下文测试，以及既有真实结果的两次交接回读。详情见 [干净运行环境记录](docs/t2_clean_runtime_receipt.md)。这不是全新操作系统、真实模型复测或所有可选功能的验证。

完整开发测试另用 `requirements-dev.txt`；其中 jsonschema 用于附加 schema 检查，cryptography 用于可选正式签名流程。主 T2 演示无需先完成可选 Linux/签收工程。

## 2. 实际生产需要什么

- Python、Git，以及操作者批准使用的模型服务和费用上限。
- `tasks.jsonl`：逐项任务；`repos.json`：本机可信仓库映射；`package`：公告及可用引用资料。目标仓库包含声明的固定 Git 对象，工具不执行目标项目。
- 当前支持单一 GHSA、可解析的修复提交及唯一父提交、显式声明的源码路径。不保证任意 URL/PDF 一键输入；缺少版本或资料时会记录 defer。
- 源码包不附带目标仓库、真实密钥或本机路径映射。输入准备和许可确认是实际前置工作，不能隐藏为“全自动抓取”。输入契约见 [生产说明](docs/t2_production_runbook.md)。

## 3. 两任务受限命令

下面的输入/输出路径是需由操作者替换的例子，不是已经存在的测试数据。先在平台限制本次 key 的费用，在自己的终端隐藏输入；配置检查不调用模型。

```powershell
New-Item -ItemType Directory -Path 'D:\T2-work\tmp' -Force | Out-Null
$env:TEMP='D:\T2-work\tmp'
$env:TMP=$env:TEMP
$env:DEEPSEEK_API_KEY=[System.Net.NetworkCredential]::new('', (Read-Host 'Temporary key' -AsSecureString)).Password
python -B -m vulngym_agent.agents.deepseek_backend --check-config
```

只有资料发送和费用均已获准、配置检查成功后，才执行生产：

```powershell
python -B -m vulngym_agent.t2_production_cli `
  --tasks D:\T2-input\tasks.jsonl `
  --repo-map D:\T2-input\repos.json `
  --package-root D:\T2-input\package `
  --backend-factory vulngym_agent.agents.deepseek_backend:create_backend `
  --output-dir D:\T2-output\new-run-001 `
  --max-records 2 --max-llm-calls 3 --max-tool-calls 80 --max-repair-iterations 0
```

这组 CLI 参数限制两条输入记录、每任务三次模型调用；适配器无隐藏重试。它不能检查平台实际人民币余额，不可用 token 数估算代替费用上限。检查 CLI 的 `record_limit_reached`，超出两条的输入不能称为已全部处理。输出必须是新的目录，不删除旧结果来重跑。

结束后在该终端移除临时环境变量，并到模型平台撤销临时 key：

```powershell
Remove-Item Env:DEEPSEEK_API_KEY -ErrorAction SilentlyContinue
```

删除环境变量并不等于平台撤销。不要将 key 放进脚本、演示画面或交接包。

## 4. 结果怎么看、怎么交

| 结果 | 含义 |
| --- | --- |
| `manual_review`，有完整候选与 T1 报告 | 可交给评审复核；不等于字段已正确或人工已审核 |
| `deferred.jsonl` 有记录，无完整候选 | 保留原因/证据和补充动作；不能算一份完整 Entry |
| `errors.jsonl` / `failed` | 先处理实际运行或输入错误，不统一改称语义不确定 |
| `entries_written=0` | 内部只统计 finalized；还要检查完整候选 sidecar，不能仅凭该值判断完全无数据 |

机器数据始终 `verify=0`。退出 0 只说明批处理按契约结束，不是准确率。使用 [review / handoff / verify-handoff](docs/submission_prediction_runbook.md) 回读已绑定摘要的结果；混合 handoff 保留候选与 defer，不把它冒称严格完整 export。

本地已有交接预览可以无 key 校验：解压 `t2-review-preview-20260908-v2.zip` 后运行 `python -I -B verify_bundle.py`。该包分开保留旧开发组的 1 候选/T1 + 1 defer，以及新输入组的 0 候选 + 2 defer。只核验包内一致性，不能证明语义正确。

## 5. 最近一次受限诊断已经结束

已修正版本的两份同输入诊断复测：`scripts/run_t2_context_retest_v1.py`。它只适用于当前开发机的已固定输入，复用原有六请求限制和独占运行标记，不是通用安装入口。`check` 不收费；`run` 还要求新 key、平台上限确认和脚本已提交。

本轮获准上限20元、最多6请求、每题3次、零自动重试/repair。用户确认新key平台限额后已实际执行：plan成功、semantic_judge请求超时，第二题在本地被阻止，实际发送2次。无新的完整候选或语义判断，详见[诊断回执](docs/t2_context_retest_receipt.md)。key使用已结束，不要再次运行同一目录或复用该key；最新失败不改写已有成功/弃答分组。最终还需真实产出质量复核和演示成片。
