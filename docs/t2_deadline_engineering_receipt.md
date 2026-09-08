# 截止前工程收口：可观察性与可运行交接

2026-09-09。本轮没有调用模型服务，没有复用此前已结束使用的 key，也没有重跑历史数据批次。

## 实际完成

- T2 CLI 独立汇总完整候选、T1 报告、语义弃答和模型调用问题。存在非成功模型调用时显示 `incomplete` 并退出 1；正常语义弃答不会冒称传输失败。持久化成功不再等同于任务有产出。
- `--progress` 把任务开始/结束元数据写入 stderr，stdout 保持单个最终 JSON。调用记录数明确不等于实际 HTTP 请求数。
- DeepSeek 适配器保存有限本地诊断：连接、发送、等待响应头或读取响应体阶段、经过时间、收到字节数。不保存 key、请求内容或服务端正文。历史 120 秒超时发生在哪个阶段仍未知，不能用新代码追溯补造。
- 默认 120 秒、单次请求、零自动重试和模型提示词均未更改。原已支持的显式 300 秒配置经过模拟 150 秒响应测试；这不是新的真实运行或服务延迟问题已经解决的证明。
- `scripts/demo_t2_results.py` 读取固定真实历史结果和最新失败回执，无新增生产；历史开发、新输入和同输入诊断分别展示。
- 三页设计说明 PDF 已生成并逐页渲染检查，正文来自 `docs/submission/T2_DELIVERY_BRIEF.md`，无裁切、乱码或溢出。PDF 不是质量验收或演示视频的替代品。

## 本轮验证

以下修正后的测试命令成功：104 项，56.176 秒，退出 0。

```powershell
python -B -m unittest tests.test_deepseek_backend tests.test_t2_production_cli tests.test_t2_new_input_run tests.test_t2_context_retest_receipt tests.test_submission_handoff tests.test_closed_loop_batch -q
```

此前一次扩大测试错误使用了不存在的 `tests.test_closed_loop_cli` 模块，退出非零，未计作通过；改为实际存在的 `tests.test_closed_loop_batch` 后取得上面的结果。测试使用本地构造数据/模拟传输，不是模型质量分数。

独立导出源码和最终 ZIP 的运行核验将在交接包的单独回执登记；本记录不提前声称这些检查已经完成。源码包不会含目标仓库、凭证、venv、原始路径映射或完整 Git 历史。

## 仍未完成

最新诊断仍为 0 份完整候选、无新的语义结果；首次新输入仍为 0/2 完整候选。既有真实开发组的 1 份完整候选/T1 及其 1 条弃答保持独立。真实产出质量和最终演示录像是主缺口；#12/#97/#99 不因增加 PDF、测试或压缩包而关闭。
