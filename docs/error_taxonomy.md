# Schema Adapter 错误分类

Schema Adapter 不采用“第一个错误即退出”。一次检查会尽量收集所有独立问题，
每个问题以 `SchemaIssue` 表示：

```json
{
  "path": "$.critical_operation.line",
  "code": "range_order",
  "message": "line range start must be less than or equal to end",
  "context": {"start": 352, "end": 348}
}
```

`path` 使用以 `$` 开头的字段路径；数组元素写成 `$.trace[2].line`。调用者既可用
`SchemaAdapter.validate()` 获取非抛出式 `SchemaValidationResult`，也可由
`adapt()` / `validate_or_raise()` 捕获含完整 `issues` 列表的
`SchemaAdapterError`。这些对象都支持 `to_dict()` 与 `to_json()`。

## 错误代码

| code | 含义 | 常见示例 | 处理方式 |
| --- | --- | --- | --- |
| `missing_required` | 正式必填字段缺失 | 没有 `critical_operation`；位置对象没有 `line` | 回到证据收集，不能填 `null` 或占位字符串。 |
| `extra_field` | 出现契约外字段 | Entry 中混入 `confidence`；位置中混入 `evidence_ids` | 移至 validation/evidence sidecar，并检查输出分层。 |
| `type_error` | JSON 类型错误 | `trace` 是对象；`verify` 是布尔值；`line` 是 `null` | 修正类型，不做有损猜测。 |
| `max_items` | 数组超过确定性安全上限 | `trace` 超过 256 个节点，或运行时配置的更小上限 | 缩小到有证据的必要节点；不得靠提高到无界规避预算。 |
| `invalid_format` | 字符串形式不符合契约 | 大写 SHA、非法 ID、`line: "12~14"` | 从原始证据重新提取或执行无歧义规范化。 |
| `invalid_value` | 类型正确但值域错误 | `line: 0`、`verify: 2`、错误的 `origin` | 使用契约允许的实际值。 |
| `range_order` | 行号范围倒序 | `"352-348"` | 核实源码位置；只有证据确认后才能改成正序。 |
| `duplicate_value` | 本应去重的数组含重复值 | 重复 CVE/GHSA | 规范化并稳定去重。 |
| `invalid_order` | 标识符顺序不合约 | GHSA 后又出现 CVE | 保持各组内原顺序，将全部 CVE 移到 GHSA 前。 |
| `cross_field_mismatch` | 两个字段表达的事实冲突 | `source_link` 中 GHSA 与 `report_id` 不同 | 以公告证据确认正确 ID，不能只改一边掩盖冲突。 |
| `t2_verify_not_zero` | T2 正式候选错误地声称已人工确认 | `verify: 1` | 正式 T2 边界确定性改为 `0`。 |

## 规范化与报错边界

以下转换无歧义，Adapter 可在正式输出前自动执行：

- `report_id`、CVE、GHSA 转大写；
- `vuln_ids` 稳定去重，并按 CVE、GHSA 分组；
- 位置中的正数字符串转整数；
- 正式 T2 的 `verify` 设为 `0`。

以下行为可能编造事实，Adapter 明确禁止：

- 为缺失的 `commit`、分类、入口或关键操作生成值；
- 用 `null`、`"unknown"`、`"missing"` 填充正式位置字段；
- 自动交换倒序范围两端；
- 静默删除 Entry 中泄漏的 sidecar 字段。

验证报告中的 `correct` / `incorrect` / `uncertain` 是 T1 字段结论，不是 Schema
错误代码。Schema 错误应先按本表修复或转为字段级 `incorrect` / `uncertain`，并在
最终 `validation.jsonl` 中保留可直接阅读的证据说明。

若输入本身不是合法 JSON，或连 `report_id` 都无法提取，批处理不得崩溃：应产生
`report_id: null` 的验证报告。UTF-8/JSON 语法损坏属于确定性格式错误，当前实现
输出 `verdict: "incorrect"`；公告缺失、仓库不可用等事实不足才输出 `uncertain`。
两者都用非空 `summary` 和 `evidence` 记录原因。`FieldValidation` /
`ValidationReport` 构造时会拒绝非法三态、超出 `0..1` 的置信度以及空白证据或
摘要，防止无效 sidecar 进入 JSONL。
