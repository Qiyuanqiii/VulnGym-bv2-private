# T2 分阶段输出预算与截断诊断

2026-09-09，Refs #12 / #97 / #102。**预算适配已实现并完成离线验证；尚未用新配置真实复测，不能宣布截断已被实际解决。** 本轮新增模型请求为0，没有使用旧key，也没有改变原1候选/1截断的记录。

## 已知原因与处理

上一轮第1题HTTP成功，但模型返回`finish_reason=length`，completion达到8,192上限，适配器按`deepseek_output_truncated`拒收。原日志没有保存回答/推理原文或分别的字符计数，无法事后确定预算主要花在哪里，也不能断言16,384一定足够。第2题的完整候选与T1报告保留。

本次不提高默认额度，而是新增显式可选配置`t2-balanced-v1`：

| 环节 | 原统一上限 | 新可选上限 |
| --- | ---: | ---: |
| plan | 8,192 | 2,048 |
| semantic_judge | 8,192 | 16,384 |
| reflection | 8,192 | 4,096 |
| repair（若另行启用） | 8,192 | 4,096 |

按每题仅执行plan、semantic_judge、reflection各一次、无repair/重试计算：每题上限22,528，两题45,056，低于原6×8,192=49,152。**这是指定调用序列的completion上限之和，不是人民币保证、实际用量或任意调用序列的总预算约束**；输入token和服务端计费另算，付费仍需平台硬限额。自检超过4,096也可能更早截断，因此这是待验证的权衡，不是万能修复。

- 默认`uniform`仍为原8,192，各阶段请求及backend身份逐字节兼容。
- 自定义`VULNGYM_DEEPSEEK_MAX_TOKENS`继续适用于uniform；固定profile拒绝与非默认uniform值混用，避免静默覆盖。
- 新profile把实际各阶段限制写入配置并改变backend身份；其中`max_tokens=16384`代表最大单次上限，每个请求使用其阶段限制。
- prompt仍为`t2-json-v5`，high、响应结构、T1、verify=0、拒收条件、零自动重试不变。
- 原冻结批次启动器不修改、不重跑；新profile不能套进旧8,192固定清单。

## 新增截断诊断

适配器现在保留`last_completion_failure`，CLI仅在有此类失败时追加该字段。内容仅有任务/阶段身份、配置额度、请求摘要/字节数、响应字节数、回答/服务端推理字符数、usage计数及一致性标记。

不保存或输出回答、推理原文、key或服务端错误文本；缺失计数为null而非0，不一致usage明确标记，人民币实扣仍未知。后续任务成功不会把先前失败错误归到新任务，因为诊断带有自身task/stage身份。

即使`length`返回的部分正文恰好是合法JSON，仍然拒收；不拼接、自动续写、自动加额度或重试。CLI继续退出1，不把模型结果不完整称为合理语义弃答。旧生产JSON不补写新字段。

## 无key检查配置

只检查非敏感配置，不读取凭证、不联网：

```powershell
$env:VULNGYM_DEEPSEEK_TOKEN_BUDGET_PROFILE='t2-balanced-v1'
$env:VULNGYM_DEEPSEEK_MAX_TOKENS='8192'
$env:VULNGYM_DEEPSEEK_REASONING_EFFORT='high'
$env:VULNGYM_DEEPSEEK_TIMEOUT_SECONDS='300'
python -B -m vulngym_agent.agents.deepseek_backend --check-settings
```

这里MAX_TOKENS=8192是固定profile要求的默认uniform基值，不是语义阶段额度；实际值见输出的`stage_max_tokens`。回到原配置可将profile改为`uniform`。原`--check-config`仍检查凭证配置，但也不进行连接测试。

`settings_only_not_connected`不证明服务账号可用或新配置效果。这里没有生产命令；真实复测需要新的明确授权、有效临时凭证和独立输出目录，最多6次/每题3次、零repair/重试，不复用已结束的key授权。

## 验证记录

- 73项适配器/生产CLI测试通过，含21项新增测试：四阶段额度、默认请求SHA兼容、profile身份、无key检查、只保留计数、缺失/异常usage、截断合法JSON仍拒收、CLI退出1和无重试。
- 另63项固定启动器、回执和交接包回归通过，共136项；不是136份真实模型样本或全仓测试声明。
- 两个独立配置检查进程退出0，stdout逐字节相同：637字节，SHA-256 `46358b76c0774de5ab377f515a9a36e91d412525c4bb936611ec129076d731ce`。
- 旧默认backend ID仍为`deepseek:t2-json-v5:e51cfb6d694bbdfda1fbee0d`；四阶段默认请求与改动前a7df33b基线完全相同。
- 原v5真实结果四类回读各两次一致；新旧各23个原运行文件不变。公共证据清单SHA仍为`49761c39287d0956e322637a0af188f031ea10057bbf1f43605785d5908e24b5`。

[机器可读记录](../evidence/t2-stage-budget-20260909-v1/offline_check.json)仅描述配置/兼容性核验。下一步是在独立授权下验证新profile；已有候选仍保留4项内容待复核，代表性质量缺口未消失。
