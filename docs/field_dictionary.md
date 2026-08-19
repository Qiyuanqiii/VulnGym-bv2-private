# VulnGym 字段字典与输出边界

本字典是 `SCHEMA.md` 的工程化索引；如本文、JSON Schema 或代码与
`SCHEMA.md` 不一致，以仓库根目录的 `SCHEMA.md` 为唯一正式契约。

## Entry 正式字段

`outputs/entries.jsonl` 的每一行只能包含下列 15 个顶层字段，且全部必填。

| 字段 | 类型 | 约束或含义 |
| --- | --- | --- |
| `entry_id` | string | `entry-` 加 5 位数字，例如 `entry-00057`。 |
| `report_id` | string | 大写 GHSA ID。 |
| `source_link` | string | 对应 `report_id` 的 GitHub Advisory 规范 URL；URL 中 GHSA 大小写可不同。 |
| `vuln_ids` | string[] | 大写、去重；CVE 在前，GHSA 在后；允许 `[]`。 |
| `origin` | string | 固定为 `GitHub Advisory Database (reviewed)`。 |
| `project` | string | 项目短名。 |
| `repo_url` | string | 以 `https://github.com/` 开头。 |
| `commit` | string | 漏洞版本的 40 位小写十六进制提交 SHA。 |
| `vuln_title` | string | 单入口漏洞标题。 |
| `vuln_category_l1` | string | 一级漏洞分类。 |
| `vuln_category_l2` | string | 二级漏洞分类。 |
| `entry_point` | object | 外部可达入口，结构见下节。 |
| `critical_operation` | object | 核心缺陷位置，结构见下节。 |
| `trace` | object[] | 有序传播步骤；信息不足时允许 `[]`，不得虚构节点；正式契约最多 256 个节点。 |
| `verify` | integer | 只能是 `0` 或 `1`；正式 T2 候选一律输出 `0`。 |

顶层字段按字母顺序稳定序列化，便于 JSONL diff。Schema Adapter 会规范化
`report_id`、`vuln_ids` 和行号，但不会猜测任何内容字段。

## 位置对象

`entry_point`、`critical_operation` 和每个 `trace[i]` 共用下列结构：

| 字段 | 必填 | 类型 | 规则 |
| --- | --- | --- | --- |
| `file` | 是 | string | 漏洞 commit 下的仓库相对路径。 |
| `line` | 是 | integer 或 string | 正整数，或 `"start-end"`；两端均大于等于 1 且 `start <= end`。 |
| `code` | 是 | string | 对应位置的真实源码片段。 |
| `desc` | 否 | string | 自然语言说明，可省略。 |

Adapter 输入中的单行数字字符串（例如 `"97"`）会变成整数 `97`；范围字符串
保持字符串。`0`、`null`、`"missing"`、倒序范围均不合法。

## 合法空值与“不编造”规则

- `vuln_ids: []` 与 `trace: []` 是 `SCHEMA.md` 明确允许的空数组。
- `desc` 是唯一可以直接省略的位置字段。
- `SCHEMA.md` 只为部分普通字符串规定了类型而未规定最小长度，所以显式的
  `""` 在纯类型层可能合法；生产者仍应把它视为“证据不足”，不得用它掩盖
  `commit`、位置对象、ID、URL 等具有格式或结构约束的缺失信息。
- 所有顶层字段以及位置对象中的 `file`、`line`、`code` 都必须存在。Adapter
  对缺失字段产生逐字段错误，不会补造路径、行号、代码或分类。
- 唯一可确定性补入的必填字段是正式 T2 的 `verify: 0`，因为它表示“尚未人工
  确认”，不包含漏洞事实。

## 正式输出与 Sidecar 边界

| 数据 | 位置 | 性质 | 可含内容 |
| --- | --- | --- | --- |
| Entry | `outputs/entries.jsonl` | VulnGym 正式数据 | 仅上述 15 个字段。 |
| T1 Validation | `outputs/validation.jsonl` | 正式评审结果，但不是 Entry | 逐字段三态、置信度、可读证据、建议修正。 |
| Evidence | `artifacts/evidence.jsonl` | 内部 sidecar | 证据 ID、来源、源码片段、工具调用 ID 等。 |
| 其他运行资料 | `artifacts/*.jsonl` | 内部 sidecar | 候选、替代位置、假设、耗时、异常和修复历史。 |

`confidence`、`status`、`evidence_ids`、`alternatives`、`assumptions`、
`tool_calls` 等字段绝不能写入 Entry。Schema Adapter 对任何额外顶层字段或位置
字段直接报错，而不是静默丢弃，以便尽早发现 sidecar 泄漏。

每条 T1 Validation 额外保留 `entry_id` 与 1-based `input_line`，两者在无法解析
时可为 `null`。这样同一 `report_id` 下的多个入口以及连续坏 JSON 行都能一一回连
原始候选；这些关联字段只属于验证报告，不能回写或替代正式 Entry 字段。

当候选是坏 JSON 或缺少 `report_id` 时，T1 Validation 的 `report_id` 可以是
`null`，但 `verdict` 必须为可解释的三态结论。UTF-8/JSON 语法损坏是可确定的
格式错误，当前批处理将其判为 `incorrect` 并隔离该行；只有事实资料不足时才使用
`uncertain`。两种情况都必须在 `summary` 和字段证据中直接说明原因。此例外只属于
验证报告；Entry 的 `report_id` 仍是必填的大写 GHSA 字符串。

Validation 的 `fields` 除 15 个正式字段外，还允许两个只读伪字段：`schema`
记录 Entry 契约检查，`evidence_package` 记录已声明但缺失、超限、不可解码或在
读取期间发生变化的资料。它们只用于保证不完整资料可见，绝不能回写 Entry。

对应机器可读文件为：

- `schemas/entry.schema.json`：Entry 结构与可声明约束；
- `schemas/validation.schema.json`：T1 可读验证报告；
- `schemas/evidence.schema.json`：内部统一证据条目。

## T1 本地资料包输入

T1 仍接受一行一个原始 Entry。需要公告/patch 交叉验证时，物理 JSONL 行使用
以下 wrapper；`entry` 仍必须完整满足正式 Entry 契约：

```json
{
  "package": {
    "advisory": "advisories/GHSA-XXXX-XXXX-XXXX.json",
    "references": ["references/pr-123.md"],
    "patches": ["patches/fix.patch"]
  },
  "entry": {"...": "15 个正式字段"}
}
```

所有资料路径均相对 CLI 的 `--package-root`，必须使用规范 POSIX 正斜杠；不能
声明 `repo_path`。目标仓库仍由 `entry.repo_url` 与 `--repo-map` 的精确键绑定，
避免不可信输入任意扩大仓库读取权限。单文件/单包默认分别限制为 8/32 MiB，
每包最多声明 64 个文件（硬上限 256）。加载器对 root 到文件的每一级对象做
链接/reparse 与 identity 检查；支持目录句柄的平台使用逐级 no-follow 打开。

资料包契约或危险路径是确定性 `incorrect`；文件缺失、权限失败、超限或非 UTF-8
是材料不足的 `uncertain`。包状态和物理 `input_line` 只进入 Validation/Evidence
sidecar，不会写入正式 Entry。

批处理默认还限制单行 JSONL 为 1 MiB、每次运行 10,000 条记录、每条候选
64 个 trace 节点；硬上限分别为 32 MiB、100,000 条和 256 个节点。超长物理行
以有界缓冲排空并继续下一行，记录/trace 超限会在 Git 或资料读取前形成可关联的
结构化错误。

JSON Schema 无法直接比较范围字符串的两个数字，也无法表达任意长度列表中的
“所有 CVE 必须在 GHSA 前”。这两项语义约束由标准库 Schema Adapter 补充执行。
