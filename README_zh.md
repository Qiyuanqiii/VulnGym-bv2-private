<p align="center">
  <img src="./img/wukong_logo.png" alt="VulnGym" height="60">
</p>

<h4 align="center">
    <p>
        <a href="#">中文</a> |
        <a href="./README.md">English</a>
    </p>
</h4>

<p align="center">
  <a href="https://github.com/Tencent/VulnGym/stargazers"><img alt="GitHub Stars" src="https://img.shields.io/github/stars/Tencent/VulnGym?color=gold"></a>
  <a href="https://github.com/Tencent/VulnGym/network/members"><img alt="GitHub Forks" src="https://img.shields.io/github/forks/Tencent/VulnGym?color=gold"></a>
  <a href="./LICENSE"><img alt="License" src="https://img.shields.io/badge/License-CC--BY--4.0-blue.svg"></a>
</p>

<p align="center">
  <b>面向白盒漏洞检测 Agent 的真实工程级漏洞评测基准</b>
</p>

<p align="center">
  <a href="https://github.com/Tencent/VulnGym"><img src="https://img.shields.io/badge/⭐-给 VulnGym 点个 Star-yellow?style=flat&logo=github" alt="Give VulnGym a Star"></a>
  <a href="https://huggingface.co/datasets/tencent/VulnGym"><img src="https://img.shields.io/badge/🤗%20HuggingFace-数据集-yellow?style=flat" alt="HuggingFace Dataset"></a>
</p>

**VulnGym** 是面向白盒漏洞检测 Agent 的项目级评测基准，支持在**真实工程上下文**中评估 Agent 的漏洞识别能力，并提供**可验证的漏洞触发路径与业务语义证据链**。

**三个核心设计理念：**
- **🏗️ 真实项目级评测单元** — 每个样本绑定到含漏洞的特定版本代码仓库，评测 Agent 在真实多文件、多模块工程中的漏洞发现与定位能力
- **🧠 全面的漏洞类型覆盖** — 评测体系同时涵盖需要跨模块代码语义理解的业务逻辑漏洞（如权限绕过、认证缺失等）与传统安全漏洞（如注入、路径穿越等），旨在全面评估 Agent 对不同类型漏洞的发现能力
- **✅ 可验证的漏洞路径** — 每个样本提供人工审核的**漏洞入口（entry point）**、**敏感代码操作（critical operation）** 和**跨模块推理链路（trace）**，实现可复现、可解释的确定性评测

---

## 📢 最新动态
- **2026-06-26** — 🔧 v0.1.4 数据更新：人工审计通过数量继续提升，已审计 entry 从 **350 条增至 393 / 408 条 (96.3%)**，覆盖 advisory 从 **163 条增至 178 / 184 条 (96.7%)**。本次仅更新人工审计状态标记；数据行数、schema、`desc` 覆盖数量与漏洞类型分布均保持不变。
- **2026-06-18** — 🔧 v0.1.3 数据更新：人工审计通过数量进一步提升，已审计 entry 从 **274 条增至 350 / 408 条 (85.8%)**，覆盖 advisory 从 **137 条增至 163 / 184 条 (88.6%)**。此外，为 400 条 entry 的 `entry_point` / `critical_operation` / `trace` 节点新增 `desc` 字段，用自然语言说明每个节点在漏洞链路中的作用。
- **2026-05-31** — 🔧 v0.1.2 数据更新：人工审计通过数量大幅提升，已审计 entry 从 **113 条增至 274 / 408 条 (67.2%)**，覆盖 advisory 从 **61 条增至 137 / 184 条 (74.5%)**。此外，对 80 条 entry 的 `entry_point` / `critical_operation` / `trace` 标注进行了精度优化。
- **2026-05-17** — 🔧 v0.1.1 数据更新：为每条 entry 新增 `verify` 字段以标记人工审计状态；目前已有 **113 / 408 条 entry**（覆盖 **61 / 184 条 advisory**）通过人工审计。同时对部分 `entry_point` / `critical_operation` / `trace` 字段值做了优化。
- **2026-05-15** — 🎉 VulnGym v0.1.0 版本正式开源！



## 目录

- [🔍 为什么需要 VulnGym](#-为什么需要-vulngym)
- [✨ 数据集概览](#-数据集概览)
- [📈 基线评测结果](#-基线评测结果)
- [📦 目录结构](#-目录结构)
- [🚀 快速开始](#-快速开始)
- [📊 评测你的工具](#-评测你的工具)
- [📖 引用](#-引用)
- [🤝 贡献指南](#-贡献指南)
- [🙏 致谢](#-致谢)
- [📄 许可协议](#-许可协议)

---

## 🔍 为什么需要 VulnGym

现有漏洞评测集在评估 AI Agent 的真实漏洞挖掘能力时，存在以下局限：

| 局限 | 表现 |
|---|---|
| **评测粒度不足** | 多以函数或 diff 片段为评测单元，难以反映 Agent 在完整工程项目中定位漏洞的能力 |
| **漏洞类型单一** | 偏重 SQL 注入、缓冲区溢出等模式化 CWE 漏洞，较少涉及需要深度上下文推理的类别 |
| **Ground Truth 粗粒度** | 多为二分类标签（有漏洞 / 无漏洞）或 patch diff，无法精确验证 Agent 是否定位到了正确的入口和缺陷点 |


## ✨ 数据集概览

当前为 VulnGym 的 **v0.1.4 版本**。数据以两个 JSONL 文件提供于 `data/` 目录下：

- `reports.jsonl` — 以 GitHub Advisory 为粒度的聚合记录
- `entries.jsonl` — 以外部可达入口（entry point）为粒度的标注记录

每条记录包含 `repo_url` 和 `commit`，可据此拉取对应漏洞版本的完整源码树。

### 数据规模

| 指标 | 数值 |
|---|---|
| Advisory 数（reports） | **184** |
| 可达入口数（entries） | **408** |
| 涉及项目数 | 38 |
| 涉及仓库数 | 23 |
| 人工审计通过的入口（`verify = 1`） | **393 / 408 (96.3%)** |
| 人工审计通过的 advisory（至少一条入口已审计） | **178 / 184 (96.7%)** |

### 人工审计状态

自 v0.1.1 起，`entries.jsonl` 中每条记录均包含 `verify` 字段（`int`，取值 `0` 或 `1`）：

- `verify == 1` —— 该入口的 `entry_point`、`critical_operation`、`trace`
  已经过人工审计确认，可作为高置信 ground truth；推荐在严格、可复现的
  评测中优先使用此子集。
- `verify == 0` —— 自动标注，尚未经过人工确认。可用于规模化或召回类
  研究，但其字段值在后续版本中仍可能继续优化。

在全部 **184** 条 advisory 中，**174** 条 advisory 的所有入口均已审计通过，
**4** 条为部分审计通过，合计 **178** 条 advisory 至少包含一条人工审计入口。
后续版本将持续扩充已审计子集。

### 漏洞类型分布

每条数据包含两级分类字段：`vuln_category_l1`（粗粒度类型）和
`vuln_category_l2`（细粒度子类型）。**71.2%** 的漏洞为业务逻辑类，
按 **12 类 + 1 兜底** 的二级标签体系分类（见下表）；其余 28.8% 覆盖传统漏洞类型。
完整数据模型与字段定义详见 [`SCHEMA.md`](SCHEMA.md)。

首期（v0.1.0）样本主要来源于近期高 Star 开源项目，以高频出现的业务逻辑漏洞为主；后续版本将持续扩展更多漏洞类别与项目场景。

> 注：一个漏洞（Advisory）可能对应多个入口（Entry）——下表按 **漏洞数** 统计，而非入口数。

**业务逻辑类 (131 / 184, 71.2%) — `vuln_category_l2` 分布：**

| 二级分类 | 漏洞数 | 占比 |
|---|---|---|
| BL-AUTHZ-BROKEN — 授权逻辑错误 | 31 | 23.7% |
| BL-AUTHZ-MISSING — 授权缺失 | 23 | 17.6% |
| BL-AGENT-CAPABILITY — AI/Agent 能力边界绕过 | 20 | 15.3% |
| BL-PRIV-ESC — 特权提升 | 13 | 9.9% |
| BL-AUTH-BYPASS — 身份认证绕过 | 11 | 8.4% |

<details>
<summary>其余 7 类（共 33 个，占业务逻辑类 25.2%）</summary>

| 二级分类 | 漏洞数 | 占比 |
|---|---|---|
| BL-ORIGIN-INTEGRITY — 来源/签名/完整性校验缺失 | 8 | 6.1% |
| BL-WORKFLOW-VIOLATION — 业务流程/状态机违规 | 7 | 5.3% |
| BL-INSECURE-DEFAULT — 不安全默认配置 | 6 | 4.6% |
| BL-RACE-LOGIC — 业务层竞争条件 | 4 | 3.1% |
| BL-MULTI-TENANT — 多租户/隔离失效 | 3 | 2.3% |
| BL-MASS-ASSIGNMENT — 参数/属性污染 | 3 | 2.3% |
| BL-TRUST-BOUNDARY — 隐式信任内部输入 | 2 | 1.5% |

</details>

<br>

**传统漏洞类 (53 / 184, 28.8%) — 主要 `vuln_category_l1` 分布：**

| 类别 | 漏洞数 | 占比 |
|---|---|---|
| 代码注入（Code Injection） | 12 | 22.6% |
| 路径穿越/文件操作（Path Traversal） | 9 | 17.0% |
| 命令注入（Command Injection） | 8 | 15.1% |
| XSS | 5 | 9.4% |
| 沙箱逃逸（Sandbox Escape） | 5 | 9.4% |

<details>
<summary>其余 4 类（共 14 个，占传统漏洞类 26.4%）</summary>

| 类别 | 漏洞数 | 占比 |
|---|---|---|
| SSRF | 4 | 7.5% |
| 认证绕过（Authentication Bypass） | 3 | 5.7% |
| 反序列化（Deserialization） | 2 | 3.8% |
| 其他（模板注入、RCE、供应链等） | 5 | 9.4% |

</details>

> 后续版本将持续扩展更多漏洞类别与项目覆盖



## 📈 基线评测结果

> 🚧 **即将发布** — 我们正在对主流工具和 AI Agent 进行系统评测，结果将随技术报告一并公布。


## 📦 目录结构

```
VulnGym/
├── README.md                    # 英文版
├── README_zh.md                 # 当前文件
├── SCHEMA.md                    # 字段参考与校验不变量
├── CHANGELOG.md
├── CITATION.cff
├── LICENSE                      # CC-BY-4.0
├── data/
│   ├── reports.jsonl            # 184 行 —— 每行一条 GitHub Advisory
│   └── entries.jsonl            # 408 行 —— 每行一个入口点，含人工审计标记 verify
├── schemas/                      # Entry / T1 验证 / Evidence 严格契约
├── vulngym_agent/               # 实验性 B-v2 自动化基础
├── docs/                         # 字段字典、错误分类与 B-v2 设计
├── tests/                        # 标准库回归测试
└── examples/                     # 加载与评测工具
```

---

## 🚀 快速开始

```bash
git clone https://github.com/Tencent/VulnGym.git
cd VulnGym
python3 examples/load_dataset.py
```

或者直接在 Python 中加载：

```python
import json
with open("data/entries.jsonl", encoding="utf-8") as f:
    entries = [json.loads(line) for line in f if line.strip()]

xss = [e for e in entries if e["vuln_category_l1"] == "XSS"]
print(len(xss), "条 XSS entries")
print(xss[0]["entry_point"], "→", xss[0]["critical_operation"])

# 仅取人工审计通过的高置信子集
verified = [e for e in entries if e["verify"] == 1]
print(len(verified), "条人工审计通过的 entries")
```

Pandas：

```python
import pandas as pd
reports = pd.read_json("data/reports.jsonl", lines=True)
entries = pd.read_json("data/entries.jsonl", lines=True)
```

HuggingFace `datasets`：

VulnGym 也已发布至 HuggingFace Hub：[tencent/VulnGym](https://huggingface.co/datasets/tencent/VulnGym)。

```python
from datasets import load_dataset

# 直接从 HuggingFace Hub 加载
ds = load_dataset("tencent/VulnGym")

# 或者从本地 JSONL 文件加载
ds = load_dataset("json", data_files={
    "reports": "data/reports.jsonl",
    "entries": "data/entries.jsonl",
})
```

### 实验性 B-v2 T1 确定性门禁与受控 T2 Producer

B-v2 工具要求 Python 3.10 或更高版本。可按以下命令安装测试依赖并运行完整
标准库测试套件：

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

仓库现已包含 T1 × T2 自动化方案中可运行的确定性 T1 纵切：逐行隔离并校验
JSONL，安全读取有界的本地公告/引用/patch 资料包，以不 checkout 的方式读取
不可变 Git 对象，核对 GHSA/CVE、父提交、祖先关系、精确路径和 ±5 行容差内
的代码；同时有界解析 unified diff，生成保守的 Sink/Guard 审查候选，并且只在
显式给出的源码文件集合中搜索 route/RPC/CLI/handler/export 入口线索。

受控生产纵切也已通过 `vulngym_agent.agents` 与
`vulngym_agent.orchestrator` Python API 提供。`T2TaskInputV1` 是严格、版本化且
不携带本机路径的任务契约；由 Orchestrator 持有的 `ProducerExecutionContext`
经 `LocalT2ContextFactory` 绑定受信本地资料/仓库根、固定工具注册表、模型后端与
逐 attempt 预算。`LocalStructuredT2Producer` 已能离线读取真实本地 Git 对象生成
候选，并执行当前确定性检查所支持的受限 repair。证据有歧义、能力缺失或预算/
契约检查失败时，它会显式 defer，不会拼出不完整 Entry。

`RepairPlan` 采用 fail-closed 策略：字段工具权限只能收窄，`required_checks` 不能
删减，空工具 allowlist 明确表示 deny-all。repair 只能把 T1 已给出的
`suggested_fix` 写入获批字段，同时保持 locked 字段和任务身份。目前的 repair 路径
支持受限的标题和分类修复，并执行已有的任务、公告与 Schema 检查；其中语义选择仍是
不受信模型输出，不代表最终 T1 正判。若计划要求源码位置、patch 区域、祖先关系或
trace 连续性等尚无专用验证器的检查，则直接 defer。全字段 `required_check` verifier
仍未补齐。

`ClosedLoopOrchestrator` 同时支持确定性 FakeT2 回归和真实 Producer 接口。每轮都会
新建隔离的 T1，最多允许两轮字段受限修复，并将工具/模型调用记录与预算事件闭合；
不确定、字段回归、预算耗尽、无进展和 sidecar 冲突都会进入明确终态。代码、固定策略
和本地运行配置属于受信计算基；模型输出与所有任务/资料数据均不受信。canonical
digest、哈希链和 unsigned JSON transcript 只证明记录内部的 closure 与绑定关系，
不是数字签名，也不能证明仓库、公告或模型结论的外部真实性。

离线 closed-loop 批处理入口与原子 replay artifact writer 现已实现。它严格要求
每个物理 JSONL 行恰好包含一个 `RunTask`，每轮验证都以新建 T1 承接 T2 候选，且
`entries.jsonl` 只接收由 `correct` T1 报告闭合的 finalized Entry。

下面是一行 `tasks.jsonl` 的完整结构。资料包路径是相对受信 package root 的 POSIX
路径；任务数据中不得出现本机根目录：

```json
{"task_id":"task:ghsa-w7xj","report_id":"GHSA-W7XJ-8FX7-WFCH","entry_id":"entry-00057","inputs":{"contract_version":1,"input_line":1,"repo_url":"https://github.com/open-webui/open-webui","package":{"advisory":"advisories/GHSA-W7XJ-8FX7-WFCH.json","references":[],"patches":["patches/GHSA-W7XJ-8FX7-WFCH.diff"]},"hints":{"project":"open-webui","fix_commits":[],"source_paths":["src/lib/components/common/RichTextInput.svelte"],"entry_symbols":[],"critical_mode":"auto"}}}
```

`inputs.input_line` 必须等于所在物理行号。受信仓库映射另存为严格 JSON 文档，使用
规范 GitHub URL 和绝对本地根目录：

```json
{"contract_version":1,"repositories":[{"repo_url":"https://github.com/open-webui/open-webui","path":"/srv/vulngym/repos/open-webui"}]}
```

当前 CLI 刻意不内置在线模型适配器，而以有界、request-free 的精确 request fixture
作为离线后端：

```json
{"contract_version":2,"backend_id":"exact-replay","model_id":"offline-v1","responses":[{"task_id":"task:ghsa-w7xj","attempt":0,"policy_scope":"t2.initial","stage":"plan","model_call_id":"MODEL-example-plan","backend_id":"exact-replay","model_id":"offline-v1","request_sha256":"<64-lower-case-hex>","status":"success","response":{"stage-specific":"structured result"},"error_code":null}]}
```

上面的尖括号是文档占位符。真实 response 记录会离散绑定不可变 `ModelRequest` 的每个
身份字段：task、attempt、policy scope、stage、call ID、backend ID、model ID，以及
64 位小写 request digest；查找直接使用这组无碰撞字段 tuple，不能用调用方给出的单个
或经分隔符拼接的 operation 字符串替代逐字段核对。每组身份只能注册并消费一次，缺失、复用
或剩余响应都会中止发布。fixture 不保存 prompt 或 request payload，它只是测试/复现
输入，**不是** benchmark gold，也不是独立 T1 裁决。隐藏验收 gold 必须在物理上位于
task、fixture、package 与 repository root 之外，也绝不能用于准备模型响应。

准备好以上输入后的最小批处理命令为：

```bash
python -m vulngym_agent.closed_loop_cli \
  --tasks tasks.jsonl \
  --replay-responses replay-responses.json \
  --repo-map repo-map.json \
  --package-root /srv/vulngym/packages \
  --output-dir /srv/vulngym/runs/run-001
```

输出父目录必须已存在，而 `--output-dir` 本身必须不存在，也不得与 task、fixture、map、
资料包或仓库输入重叠。退出码 `0` 表示批次干净（默认允许 `manual_review`）；出现输入行/
任务失败时为 `1`，启用 `--require-all-finalized` 后任何人工审核结果也返回 `1`；配置/
I/O、任务总字节超限或 exact-replay 闭合失败等致命错误返回 `2`。输入默认限制为 JSONL
单行 1 MiB、完整 task 文件 64 MiB、10,000 条记录，分别由
`--max-input-line-bytes`、`--max-task-bytes`、`--max-records` 调整；硬上限依次为
32 MiB、1 GiB、100,000。replay fixture 另有默认 16 MiB、50,000 响应限制。若
`--max-records` 截断批次后仍留下属于后续记录的 unused fixture，精确闭合会失败，整个
输出目录都不会发布。

同一个 staging 事务会发布 `entries.jsonl`、`validation.jsonl`，以及
`states.jsonl`、`candidates.jsonl`、`validations.jsonl`、`evidence.jsonl`、
`tool_calls.jsonl`、`model_calls.jsonl`、`repair_history.jsonl`、`deferred.jsonl`、
`errors.jsonl` sidecar，最后以 `run_manifest.jsonl` 闭合。`validation.jsonl` 是正式
报告流，`validations.jsonl` 是关联各 attempt 的 replay sidecar。可通过 Python API
在不执行 T1、T2、Git 或模型的情况下读取/校验：

```python
from vulngym_agent.orchestrator import (
    read_closed_loop_artifacts,
    verify_closed_loop_artifacts,
)

bundle = read_closed_loop_artifacts("/srv/vulngym/runs/run-001")
manifest = verify_closed_loop_artifacts("/srv/vulngym/runs/run-001")
print(bundle.manifest.dataset_sha256, manifest.entry_count)
```

artifact 会有意保留有界且公开或已获许可的 Evidence snippet，以及 Entry Schema
必需的代码片段，因此必须保存在私有仓库或其他受控目录。它不会落盘 raw model
prompt/response、Producer assumptions、异常文本或配置的本机根目录；model-call sidecar
只含绑定后的元数据/digest，T1 也不会读取它。canonical digest 可发现损坏并闭合引用，
但没有签名能力，不能认证外部事实。

#### 固定 50/20 benchmark harness（阶段 A/B）

公开数据契约以及 replay-to-finding 投影 harness 已实现。benchmark bundle 应保留在
本实现仓库之外，由受信 harness 主机只读挂载，并通过 `--benchmark-root` 指向这个外部
根目录。运行时 profile 固定为 `vulngym-50-20-v1`，来源 revision 固定为
`cd69f7e163e08485ab5496115ae03439cda6e27e`，公开 manifest SHA-256 固定为
`d4ef4a663a30a39d2ccd89dc89f70d19a06686ae86179c537cd5139b8ff00a73`。
reader 不枚举 bundle，只打开固定 manifest、record schema、manifest schema 以及公开
train/test JSONL；任何 profile 替换或修改都会 fail closed。

```bash
# 校验完整固定公开 profile，并只输出计数摘要。
python -m vulngym_agent.benchmark_cli validate \
  --benchmark-root /srv/vulngym/benchmark-public

# 导出不带答案的源码快照任务；新输出目录只包含 tasks.jsonl 与 manifest.json。
python -m vulngym_agent.benchmark_cli export-tasks \
  --benchmark-root /srv/vulngym/benchmark-public \
  --split test \
  --output-dir /srv/vulngym/exports/test-tasks

# 逐个校验已索引 replay bundle、把正式 Entry 投影为 finding，并仅运行公开训练集
# aggregate oracle。
python -m vulngym_agent.benchmark_cli project-train \
  --benchmark-root /srv/vulngym/benchmark-public \
  --artifact-root /srv/vulngym/replays/train \
  --bundle-index /srv/vulngym/attestations/train-index.json \
  --bundle-index-sha256 <64-lower-case-index-file-sha256> \
  --output-dir /srv/vulngym/projections/train

# 生成盲测提交；不加载公开训练答案，也不调用评分 oracle。
python -m vulngym_agent.benchmark_cli project-test \
  --benchmark-root /srv/vulngym/benchmark-public \
  --artifact-root /srv/vulngym/replays/test \
  --bundle-index /srv/vulngym/attestations/test-index.json \
  --bundle-index-sha256 <64-lower-case-index-file-sha256> \
  --output-dir /srv/vulngym/projections/test
```

尖括号内是文档占位符；真实投影必须从受信通道取得 index 文件精确字节的 64 位小写
SHA-256。index 是不允许额外键的严格 JSON，结构如下：

```json
{"bundles":[{"dataset_sha256":"<64-lower-case-replay-dataset-sha256>","task_id":"VG-TEST-<20-UPPER-HEX>"}],"contract_version":1,"manifest_sha256":"d4ef4a663a30a39d2ccd89dc89f70d19a06686ae86179c537cd5139b8ff00a73","profile_id":"vulngym-50-20-v1","split":"test"}
```

它必须为所选 split 中每个 task 恰好列出一项，不能缺少、增加或重复 task ID，也不能
重复 dataset digest。每个 `dataset_sha256` 绑定
`<artifact-root>/<task_id>` 下已完整校验的 closed-loop replay 目录。index 文件 digest
与 replay dataset digest 能依据受信评测端提供的预期值发现替换或损坏，但**不能**证明
源码树、fixture 或模型结论的来源真实性。

两个投影命令都会在一次禁止覆盖的事务中发布 `findings.jsonl`、
`task_results.jsonl` 和 `manifest.json`。`project-train` 额外发布
`aggregate.json`；训练 oracle 只公开总数与 recall，不公开 task/advisory/Entry 身份或
逐项匹配。`project-test` 不读取公开 train 文件、不调用 oracle，也不产生分数或
`aggregate.json`。每题默认最多投影 Top 64 finding，`--top-k` 硬上限为 256；固定公开
训练 matcher 的 official inclusive 行号容差为 5。

阶段 A/B 已提供严格公开契约、无答案任务导出、replay 校验、有界一对多 finding 投影，
以及 train-only aggregate oracle。下文的阶段 C 已补齐源码交付边界，但并不表示当前依赖
公告/fix 锚点的 `LocalStructuredT2Producer` 已成为 source-only multi-finding Producer。
阶段 D（该 Producer 与独立 semantic T1）和阶段 E（50/20 隔离运行）仍待完成；显式在线
模型 backend 与全字段 required-check verifier 也尚未完成。

#### Sealed 源码快照准备（阶段 C）

`python -m vulngym_agent.snapshot_cli` 已能准备并独立校验经过认证的 source-only 快照
批次。受信 preparer 打开完整本地 Git 仓库，解析每个任务的精确 commit 与根 tree，只把
该 commit 的普通源码文件物化到 `bundles/<task_id>/tree`。发布树不含 `.git` 目录或其他
历史读取面；符号链接、Gitlink/submodule、LFS pointer、不安全或碰撞路径、空目录，以及
不受支持的 Git 存储布局都会 fail closed。

每题 canonical manifest 与 HMAC 会绑定 task ID、精确 repo URL 和 commit、根 tree 对象
ID、快照策略、文件 mode，以及逐文件 Git blob OID、字节数和 SHA-256。外层批次 manifest
还绑定公开 task-export manifest digest、精确 `tasks.jsonl` digest、source-map digest、
所有题目快照的 manifest/content root 和汇总计数；HMAC envelope 另行绑定 key ID。这里的
HMAC 只是受信评测域内部的完整性机制，不是公开来源签名，不能证明仓库由谁发布，也不能
认证外部来源事实。

preparer 对所有发现型输入都要求由受信通道提供 digest pin。source-map 是严格 canonical
JSON；其中排序后的 `sources` 数组必须按 `(repo_url, commit)` 与 task export 精确覆盖，
不得缺项或多项：

```json
{"kind":"sealed_snapshot_source_map","profile_id":"vulngym-50-20-v1","public_manifest_sha256":"<public-manifest-sha256>","schema_version":"1.0.0","sources":[{"commit":"<40-lower-case-hex>","repo_root":"/srv/vulngym/repos/project","repo_url":"https://github.com/owner/project"}],"tasks_sha256":"<tasks-jsonl-sha256>"}
```

```bash
# 在一个私有 staging 中准备全部任务、逐题校验、绑定批次、再次逐题校验，最后只发布一次。
python -m vulngym_agent.snapshot_cli prepare \
  --task-export-dir /srv/vulngym/exports/test-tasks \
  --expected-tasks-sha256 <tasks-jsonl-sha256> \
  --expected-public-manifest-sha256 <public-manifest-sha256> \
  --source-map /srv/vulngym/config/source-map.json \
  --expected-source-map-sha256 <source-map-file-sha256> \
  --output-dir /srv/vulngym/sealed/test \
  --key-file /srv/vulngym/secrets/snapshot-hmac.key \
  --key-id evaluator-snapshot-v1

# 认证外层 manifest，并深度复验每个任务 bundle。
python -m vulngym_agent.snapshot_cli verify-batch \
  --sealed-root /srv/vulngym/sealed/test \
  --expected-manifest-sha256 <sealed-batch-manifest-sha256> \
  --key-file /srv/vulngym/secrets/snapshot-hmac.key \
  --expected-key-id evaluator-snapshot-v1
```

准备过程是一次禁止覆盖的整批事务：所有题目的源码树及两轮完整校验闭合之前，正式输出
不会出现。固定批次总量上限为 100 个 task、1,000,000 个文件、1,000,000 个路径节点和
16 GiB 文件内容。Linux 的 no-replace `renameat2` 与 Windows 的 handle-anchored 目录
rename 都是发布提交点，也是当前支持的两个发布平台；其他 POSIX 系统会明确拒绝，而不会
降级到非原子 rename。若提交后的 identity 或 durability 检查失败，命令会报告发布状态
不确定；调用方必须把目标目录视为“可能已经提交”，依据精确预期 manifest 重新校验，
不能按路径名尝试清理。

HMAC key、source repo、task-export/control 材料和每个 bundle 的 `control/` 都留在受信
evaluator 一侧。Agent 只能拿到一题的 `tree/`，并以只读方式挂载，同时只提供该题无答案
task 与有界输出位置；sandbox 不得暴露 key、control、源 Git 仓库、其他题目的 tree、
benchmark 仓库、评测日志、评分材料或网络。阶段 C 只证明交付字节及其与 preparer 所选
Git 对象的绑定，不负责 source-only finding 发现或语义裁决。

最终盲测时，评分真值必须物理隔离在独立评测端存储中，绝不能用于准备 task、fixture
或模型响应。每个 Producer sandbox 必须断网，只接收一条无答案任务、对应 sealed 源码
树和有界输出目录；不得挂载 benchmark 仓库、训练 split、原始数据/生成器输入、评测
日志或评分材料。受信 evaluator 可在 Producer 退出后校验并投影输出；当前仓库仍不声称
已经通过 50/20 最终验收。

确定性 T1 CLI 的验证报告、证据和运行清单继续严格分开落盘：

```bash
python -m vulngym_agent data/entries.jsonl

# 使用一个本地目标仓库检查所有候选行
python -m vulngym_agent candidates.jsonl --repo-root /path/to/target-repo

# 每行可改用 {"package": {...}, "entry": {...}} wrapper；资料路径均相对该只读根
python -m vulngym_agent packaged-candidates.jsonl \
  --package-root /path/to/local-evidence \
  --repo-map repos.json
```

多仓库批处理可通过 `--repo-map` 传入 JSON 对象：键是精确的 `repo_url`，
值是本地仓库根目录（相对路径以映射文件所在目录为基准）。默认输出为
`outputs/validation.jsonl`、
`artifacts/evidence.jsonl` 和 `artifacts/run_manifest.jsonl`。wrapper 的
`package` 只接受必填 `advisory`，以及可选 `references` / `patches` 相对
POSIX 路径；不接受 `repo_path`，仓库仍只能由 Entry 的精确 `repo_url` 映射。
默认单文件/单包/声明文件数限制为 8 MiB、32 MiB、64，可通过 CLI 调整；
JSONL 单行、记录数和每条 trace 节点数默认限制为 1 MiB、10,000、64，并有
不可绕过的 CLI 硬上限。当前阶段能够明确识别
公告 ID 错配及“把已知 fix commit 填成漏洞 commit”，但仅有祖先关系或代码
客观存在时仍保守输出 `uncertain`，不会冒充漏洞语义证明；补丁新增 Guard、移除
危险调用及入口模式都只作为结构线索，绝不声称运行时可达性已证明。详见 [B-v2 架构](docs/b_v2_architecture.md)、
[字段字典](docs/field_dictionary.md) 与 [错误分类](docs/error_taxonomy.md)。

仓库映射必须指向普通 clone 或 bare repository 根目录。为防止证据读取越出授权
根目录，门禁会拒绝 linked-worktree/submodule gitfile、common directory、
alternate object database 与 `info/grafts` 历史覆盖；三份输出路径也必须位于
所有目标仓库之外。
拓扑事实读取同时禁用 commit-graph 与 replace-object 覆盖。
资料路径拒绝绝对路径、盘符/UNC、`..`、反斜杠、符号链接、junction/reparse
point 和重复声明；打开前后核对每级路径 identity，POSIX 支持时使用目录句柄
no-follow 遍历，Windows 核对已打开句柄的最终路径。三份输出同样不得写入
资料包根目录。


## 📊 评测你的工具

将工具检出结果写入一个 JSONL 文件（每行一条 finding），然后运行：

```bash
python3 examples/evaluate.py path/to/your_findings.jsonl -v
```

每条 finding 至少需要包含 `repo_url`、`commit`、`entry_point`（外部可达入口）和
`critical_operation`（核心缺陷位置）。`trace`（跨模块推理链路）可选，当前评测器不参与匹配。
完整格式参考 `examples/example_result.jsonl`。

评测脚本输出两个指标：

- **Advisory 级召回率**（主指标）—— `命中的 advisory 数 / 可用 advisory 数`。
  一个 advisory 只要**任意一条** entry 被命中，即视为覆盖。
- **Entry 级召回率**（副指标）—— `命中的 entry 数 / 可用 entry 数`。

**默认匹配策略**

| 维度 | 默认值 |
|---|---|
| 路径匹配 | 归一化后严格相等 |
| 行号容差 | entry_point 与 critical_operation 的闭区间距离均 `≤ 5`；提交范围宽度不得超过真实范围向两侧各扩展容差后的宽度 |
| 方向 | 严格（entry_point 对 entry_point，critical_operation 对 critical_operation） |
| ground truth 行号无效 | 同时从分子分母中剔除；兼容旧版/自定义数据中已废弃的 `line == 0` |

所有策略均有文档说明，并可通过 CLI 参数调整（`--line-tolerance` 等）。

> **注意：** 当前评测器**只计算召回率 / 覆盖率**，无法惩罚过度上报，
> 因此其数值应理解为覆盖率指标，而非完整的 precision-aware benchmark。


## 📖 引用

> 📚 **配套论文正在撰写中**。论文公开发布前，请使用以下数据集 BibTeX 条目引用 VulnGym；论文发布后我们会更新此处。

```bibtex
@misc{vulngym2026,
  title        = {VulnGym: A Real-World, Project-Level Vulnerability Benchmark
                  for White-Box Vulnerability-Hunting Agents},
  author       = {{Tencent Wukong Code Security Team and contributors}},
  year         = {2026},
  version      = {0.1.4},
  howpublished = {\url{https://github.com/Tencent/VulnGym}},
  note         = {Dataset. A companion paper is in preparation; please check
                  the repository for the latest citation.}
}
```

论文公开后，以下条目将被补全并作为推荐引用：

```bibtex
@inproceedings{vulngym2026paper,
  title     = {TBA — A companion paper for VulnGym is in preparation.},
  author    = {{To be announced}},
  year      = {TBA},
  note      = {Placeholder; will be replaced once the paper is publicly available.}
}
```

机器可读版本详见 `CITATION.cff`。

---

## 🤝 贡献指南

VulnGym 致力于成为**开放、可复现、持续演进**的社区评测基准，
欢迎学术界与产业界共同参与：

- 🧠 **数据贡献** — 新增 advisory、为已有 advisory 补充外部可达入口、
  修正 `entry_point` / `critical_operation` / `trace`
- 🔧 **评测器改进** — precision / F1、按类别拆分、
  统计显著性（bootstrap CI）、新增匹配策略等
- 📊 **评测结果提交** — 欢迎通过 PR 提交你的工具评测结果，纳入基线对比
- 💬 **讨论与反馈** — 欢迎通过
  [Issues](https://github.com/Tencent/VulnGym/issues) 或
  [Discussions](https://github.com/Tencent/VulnGym/discussions) 交流

提交数据变更前请先阅读 `SCHEMA.md`，其中列出的所有不变量都会在发布前被强校验。

---

## 🙏 致谢

VulnGym 由**腾讯悟空安全团队**联合以下学术单位共同建设（排名不分先后，顺序待定）：

- 香港中文大学 ARISE Lab
- 复旦大学系统软件与安全实验室
- 香港大学 JC STEM Lab of Intelligent Cybersecurity
- 北京大学 Narwhal-Lab
- 中国科学院信息工程研究所网络威胁分析研究室

感谢各方对 VulnGym 的卓越贡献！

---

## 📄 许可协议

数据集以 **CC-BY-4.0** 协议开源，详见 [`LICENSE`](LICENSE)，
允许商业与学术使用，惟需署名。`entry_point` / `critical_operation` / `trace` 字段中引用的
代码片段、路径与 commit 哈希归其上游项目所有，遵循各自原始开源协议，
再利用前请查阅对应上游仓库。
