# 两份新输入：付费前预检记录

2026-09-08。T2主线，T1辅助。**输入准备和运行保护已完成；真实生产尚未执行，当前不能计入准确率或新增Entry。**

## 1. 已固定的批次

- 新报告：GHSA-JP4J-Q5FC-58GV（openclaw/openclaw）和GHSA-CM35-V4VP-5XVX（open-webui/open-webui），见[选择规则与偏差](t2_new_input_selection_v1.md)。这里的“修复提交”是原报告引用中的提交、由操作者核对其主题及diff关联，不表示仅凭父子关系就已证明全部受影响版本。
- 6个输入文件共18,056字节：2份规范化公告、2份固定diff、tasks和CLI格式的repo map。EP/CO、分类和trace未预写，entry_symbols为空；输入摘录规则和人工资料准备均披露。
- 与项目已登记40份报告（包括此前两份真实模型开发输入）的报告ID交集为0；不宣称模型训练未见、跨所有历史会话未见或代表性已经充分。
- 有效公共准备记录为[evidence v2](../evidence/t2-new-input-preflight-20260908-v2/input_manifest.json)，对应本地运行目录`D:\VulnGym-bv2-runtime\t2-new-input-live-20260908-v3`。
- 输入清单SHA-256：`1f85f4cad6ee17aa722bec985938ba76cea93bc6c0fe7bec52f050cca20c6a3f`。
- 运行时代码基线`56a073c69ae53f89428ba087b38fa491cfcad494`；`vulngym_agent`树为`7ed7ff1f7fa5bc383f9c26adb2f98273c194d8bc`。本次新增的是操作者脚本/测试/资料，不改运行时代码或历史结果。
- 模型配置固定为`deepseek-v4-pro`、`t2-json-v4`、high、8192最大输出tokens、120秒HTTP超时；提示词SHA-256为`8297bcb99ad8b9f9bd5b697272f61327296ac3dc084d680dffe9f846ee0d2d0f`。这是待执行配置，不是已验证的服务响应。

## 2. 实际完成的验证

```powershell
python -B scripts/run_t2_new_input_batch_v1.py check
python -B -m unittest tests.test_t2_new_input_run tests.test_deepseek_backend tests.test_t2_production_cli tests.test_t2_inputs -q
```

在生产工作区、D盘TEMP/TMP、禁用Git lazy fetch下执行：

- 两个独立`check`进程均退出0、stderr为空；实际310字节stdout（Windows末尾CRLF）逐字节相同，SHA-256均为`7c0ea9ba1da301e057c7f914ab92a13c21c226f6a39f7c50788988f2d64b3ba6`。
- `check`使用实际任务及repo-map加载器，核对6个输入文件、配置、运行时代码树、Git单父关系及固定源码前后字节；不请求key、不调用模型。
- 最终脚本版本的64项针对性测试全部通过，31.037秒，退出0、无跳过；这是本轮相关测试，不冒称重跑全库。
- 两份本地探针都到达plan入口后由测试替身主动终止，真实provider调用0。`manual_review`是探针的人工阻断结果，不是新报告的真实模型弃答或质量评价。
- 预检时不存在run-start、transport-events、output、run-exit或cli-stdout正式运行文件。

机器可读结果见[validation receipt](../evidence/t2-new-input-preflight-20260908-v2/validation_receipt.json)。公共元数据只记录资料标识、哈希、计数和结果；原公告全文、目标源码、机器路径映射和临时key不放入该证据目录。

## 3. 预算、启动和失败行为

[预算授权](t2_next_run_budget.md)：用户已确认临时key设置**平台侧20元人民币硬限额**。程序未查询该设置；请求次数上限不冒充人民币计费能力，账单以平台为准。

[一次性运行脚本](../scripts/run_t2_new_input_batch_v1.py)约束：

- 固定2个任务，最多6次实际HTTP请求、每题最多3次，工具调用每题80，repair=0，零自动重试。
- 开始前核对输入/配置/源码和脚本已提交状态；先创建独占运行标记，再通过隐藏输入接收新key。不读历史key或环境变量中的旧key。
- 每次请求前把最小计数事件写入D盘并flush/fsync；写入失败则不发送。认证、权限、余额、限流、超时或其他传输错误会停止后续请求。
- 日志不记录key、原始请求/响应或模型思考正文；只记计数、哈希、模型匹配、可用token计数及结构化错误。
- 无论成功、失败或中断，都保留已生成记录，不自动重跑；再次`run`遇已有标记会拒绝。不要删除标记来强行重试。
- 用完清除本进程的key引用并通知用户撤销；不能声称这已替用户在服务端撤销或完成内存安全擦除。

脚本是这台机器上此固定批次的**操作者启动器**，不是通用安装器。通用产品用法仍见[T2生产runbook](t2_production_runbook.md)。只有新的临时key到位且用户授权保持有效后才执行`run`；本记录期间没有执行。

## 4. 已保留的准备问题

| 阶段 | 检查发现 | 处理及证据边界 |
| --- | --- | --- |
| 报告预选 | GHSA-FF5C-56M7-VC75引用diff与报告主题不对应 | 发送模型前隔离，保留原因；不宣称报告本身无效 |
| 本地准备v1 | entry编号不符合既有`entry-[0-9]{5}`契约 | 保留失败目录，改用entry-90001/90002；未放宽schema |
| 本地准备v2 / 公共记录v1 | 内存探针通过，但序列化repo map不符合实际CLI格式 | 保留旧输入、原清单和[superseded状态](../evidence/t2-new-input-preflight-20260908-v1/status.json)，不用于付费运行 |
| 本地准备v3 / 公共记录v2 | 使用真实CLI加载器重新构建并验证 | 两次实际预检通过；唯一准备用于新付费批次的目录 |

以上均发生在任何本批模型调用之前，**真实请求及新模型费用为0**。旧公共v1的manifest仅覆盖它当时的input_manifest及offline_probe两个文件；后加status是保留历史的作废说明，不属于原manifest范围。公共v2的原manifest范围也不改写；本次新增验证回执由单独validation_manifest绑定。

## 5. 之后的验收顺序

1. 新key到位后只启动这个批次一次，记录实际退出码、请求/token计数，结束后通知用户撤销。
2. 逐项统计“任务 / 完整候选 / T1报告 / defer / 运行失败”，保留verify=0。`manual_review`、语义未知、运行错误必须分开。
3. 两份新输入单列分母，按冻结九维协议逐字段检查事实和语义；不因结果不好换题，不与开发12条混算，不把AI自评标为独立人审。
4. 生成并两次读回已有契约的混合批次handoff；完整候选与defer均可交接，但不冒充全部finalized的正式export。
5. 将新输入结果和真实失败/取舍纳入交验说明，再做同版本干净环境演练和最终演示。

A1/A3/A5尚未完全验收。#12/#97/#99继续开放；#90/#94可选分支不动。本轮不是新的源代码封存finalizer任务，不启动或重复旧批次。
