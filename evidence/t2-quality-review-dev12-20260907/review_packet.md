# T2 开发复核包（未完成实质评价）

本包是看过历史结果后选取的错例富集开发子集，不能当作盲测、随机样本或总体准确率。
所有评价格初始为 not_reviewed；T1 的原判定只作观察，不自动转为质量分。
原 Entry/报告按下列摘要获取；不向新生产模型提供本包或旧标注。

- 来源任务数：40；本包：12 条。
- 固定提交包摘要：0ff24779c984e82f4f83773d3f9b1694a8a4a4bb2c0134c5c6eeaa89b1430508。
- 新输入队列：至少 2 份，尚未选定；资料条件/业务场景尚未实质核定。
- 评审填写：复制 review_template.jsonl 到新文件，填写真实 reviewer、证据引用、简短理由和下一步。
- supported/合理替代/反证需要证据；uncertain 需要具体缺口和动作；机器 Entry verify 保持 0。

## 复核维度

| 维度 | 层面 | 必答问题 |
| --- | --- | --- |
| source_identity | fact | 来源与标识是否有对应依据，而不只是字段可解析？ |
| version_basis | fact | 受影响版本依据是什么，是否仅凭 fix 的父提交猜测？ |
| entry_location | fact | 入口 file/line/code 是否在所报 commit 精确对应？ |
| operation_location | fact | 关键操作 file/line/code 是否在所报 commit 精确对应？ |
| entry_role | semantic | 入口角色和可达性有何上下文依据，有无合理替代？ |
| operation_role | semantic | 该操作/决策与报告问题有何关系，有无合理替代？ |
| trace | semantic | 记录的步骤及衔接有无证据，空 trace 是否遗漏已知联系？ |
| title_and_project | semantic | 项目及标题是否准确描述资料，是否只是泛化模板？ |
| classification | semantic | 两级类别是否有内容依据，有无更合理或尚待定的分类？ |

## DEV-001 · GHSA-XJ9W-5R6Q-X6V4

- 仓库：https://github.com/openclaw/openclaw
- Task / Entry：VG-TEST-96AC24B151A1541B5ED6 / entry-00036
- 原候选 commit：6b38815f86d8d58e29745fe212d95650e13a936c
- 原 Entry SHA-256：d62f0c7ab956544b5c5de979e2f8cc001d492e36dbd2a8ad1157485b2e393ea8
- 原报告 SHA-256：25049eb15b180d36c3fd1d3938eb5fb519738af81c54fc7819761133a4cb6e8a
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-XJ9W-5R6Q-X6V4
- 选取理由：cross_file_then_task_id_fill；原工作流：manual_review；T1：uncertain。
- EP/CO 不同文件：True；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |

## DEV-002 · GHSA-3M3Q-X3GJ-F79X

- 仓库：https://github.com/openclaw/openclaw
- Task / Entry：VG-TEST-A08FA28D384BC16E91EE / entry-00006
- 原候选 commit：fa4b28d7af7464b07271bfef6c028e4135548f44
- 原 Entry SHA-256：97f9d443b84af28280cb9b22c2ae8690d63d4726ac04ca760625d1928ea62e87
- 原报告 SHA-256：db129dedbf3caebfb2074517ecb9239c2dd8da07895ac2bfc4ffdac62e36406b
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-3M3Q-X3GJ-F79X
- 选取理由：retain_all_reported_errors；原工作流：manual_review；T1：incorrect。
- EP/CO 不同文件：True；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | reported_incorrect_fact | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |

已知旧入口片段存在字符截断缺陷，见 lane_a_review_audit_receipt；本包保留原错误。
若采用完整行修订，另存候选/报告并重新绑定摘要，不能把旧候选当成已经修正。

## DEV-003 · GHSA-FVCW-9W9R-PXC7

- 仓库：https://github.com/FlowiseAI/Flowise
- Task / Entry：VG-TEST-BF91B957B02CA987C926 / entry-00010
- 原候选 commit：55b6913c03f0dba37cc207975f0c0d0786e0f3c7
- 原 Entry SHA-256：aeae7d78811c06417752f0820dab89161592675a3368fb5be72320bd1a310f13
- 原报告 SHA-256：595b5990ad1429aff7a1b6fda6d0f35dc5acc189b4d647ece39582276be52e99
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-FVCW-9W9R-PXC7
- 选取理由：uncovered_repository；原工作流：manual_review；T1：uncertain。
- EP/CO 不同文件：False；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |

## DEV-004 · GHSA-8C4J-F57C-35CF

- 仓库：https://github.com/langflow-ai/langflow
- Task / Entry：VG-TRAIN-40D4B88B06CDE8FCFF5C / entry-00013
- 原候选 commit：73c1f203b0205d00928a0af7fa0e0fc93170f03e
- 原 Entry SHA-256：52297768e7f1f5fdbcc7c0c06c9df306f16ee272e211dee0172ded6b5d02c9f3
- 原报告 SHA-256：f74954d79044cf5178556c0d75b6cff5b64a58f0df68225a5005c7c9efcc1fdc
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-8C4J-F57C-35CF
- 选取理由：uncovered_repository；原工作流：manual_review；T1：uncertain。
- EP/CO 不同文件：False；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |

## DEV-005 · GHSA-W7XJ-8FX7-WFCH

- 仓库：https://github.com/open-webui/open-webui
- Task / Entry：VG-TRAIN-43AC81B29F131DE6F550 / entry-00014
- 原候选 commit：9942de8011d4b5a141ac507c974c061c0cdad59a
- 原 Entry SHA-256：7e094a90153b5b019bf31c22db77e645de4ae47101a92d11692dac75d35ac049
- 原报告 SHA-256：87c262e89285254dec93c92cf5189d8875c6268612f5c3c72eab58207b2ee0dd
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-W7XJ-8FX7-WFCH
- 选取理由：uncovered_repository；原工作流：manual_review；T1：uncertain。
- EP/CO 不同文件：False；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |

## DEV-006 · GHSA-3XX2-MQJM-HG9X

- 仓库：https://github.com/paperclipai/paperclip
- Task / Entry：VG-TRAIN-727D94F6A27E96DB4DAC / entry-00019
- 原候选 commit：a07237779bd5391a4683a754ed95249d57a49b2c
- 原 Entry SHA-256：82f28bf36a0f8e204c375ad04a5a50e55ba92ea5e4e87965cc5ed38e585cd873
- 原报告 SHA-256：31d31051a26dfe4bea030ac87ca2eca374438580e47d49d9d5fb448a4a57f956
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-3XX2-MQJM-HG9X
- 选取理由：uncovered_repository；原工作流：manual_review；T1：uncertain。
- EP/CO 不同文件：True；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |

## DEV-007 · GHSA-V7V2-M736-CF3C

- 仓库：https://github.com/NVIDIA/NeMo
- Task / Entry：VG-TRAIN-747C63B97771B863292B / entry-00020
- 原候选 commit：d282d04322a8e3c9e30d743e15b1e409b05da0fd
- 原 Entry SHA-256：da9782cc1d340b4d921d6b1846e316ae6e2edf90ebeee4c66b48cde534a51aee
- 原报告 SHA-256：f5db6343d37ae667ca84d2b80c23a2bfe577f5f34e317fba392e58428b3c925b
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-V7V2-M736-CF3C
- 选取理由：uncovered_repository；原工作流：manual_review；T1：uncertain。
- EP/CO 不同文件：False；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |

## DEV-008 · GHSA-W235-X559-36MG

- 仓库：https://github.com/openclaw/openclaw
- Task / Entry：VG-TRAIN-74BA579055F87344AC56 / entry-00021
- 原候选 commit：d4bdcda32403cb8d1f100ae9e27a82f0ffaa04ca
- 原 Entry SHA-256：56088ef130925cae70a5314f888da460740d808f59caeda77c149a8a45db4ace
- 原报告 SHA-256：a6ad23441c97761521fd6c66760238105e7408d8843077cd185f6bb50ae4af3b
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-W235-X559-36MG
- 选取理由：retain_all_reported_errors；原工作流：manual_review；T1：incorrect。
- EP/CO 不同文件：False；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | reported_incorrect_fact | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |

已知旧入口片段存在字符截断缺陷，见 lane_a_review_audit_receipt；本包保留原错误。
若采用完整行修订，另存候选/报告并重新绑定摘要，不能把旧候选当成已经修正。

## DEV-009 · GHSA-5H2W-QMFP-GGP6

- 仓库：https://github.com/openclaw/openclaw
- Task / Entry：VG-TRAIN-759F58FDCD672B2F434B / entry-00038
- 原候选 commit：55cd272fe1a6822ec9be91022a257f195fe1639a
- 原 Entry SHA-256：a47e981610abd8d2f750df3dc187089e8cef19a4a1727dc36639aa6a134d12b3
- 原报告 SHA-256：417ae75bc1e502fb8344a2ab997c4202405cdbc3d28ad060030f6a60a8585abe
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-5H2W-QMFP-GGP6
- 选取理由：retain_all_reported_errors；原工作流：manual_review；T1：incorrect。
- EP/CO 不同文件：False；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | reported_incorrect_fact | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |

已知旧入口片段存在字符截断缺陷，见 lane_a_review_audit_receipt；本包保留原错误。
若采用完整行修订，另存候选/报告并重新绑定摘要，不能把旧候选当成已经修正。

## DEV-010 · GHSA-V4PR-FM98-W9PG

- 仓库：https://github.com/n8n-io/n8n
- Task / Entry：VG-TRAIN-8FEE6A4371C6C410BCB8 / entry-00024
- 原候选 commit：e45a4b1073d85d04d6455a4f18482838a7840124
- 原 Entry SHA-256：68ab3dc6cbd94f5a07dbae39dabdd92c9fa72d54c6c2650f462394abba8439a8
- 原报告 SHA-256：d9173b86f2217330179914a3ad369fb73f77ac5ef4bfa8429b978d17835373c5
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-V4PR-FM98-W9PG
- 选取理由：retain_all_reported_errors；原工作流：manual_review；T1：incorrect。
- EP/CO 不同文件：False；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | reported_incorrect_fact | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |

已知旧入口片段存在字符截断缺陷，见 lane_a_review_audit_receipt；本包保留原错误。
若采用完整行修订，另存候选/报告并重新绑定摘要，不能把旧候选当成已经修正。

## DEV-011 · GHSA-65H8-27JH-Q8WV

- 仓库：https://github.com/openclaw/openclaw
- Task / Entry：VG-TRAIN-A6D2E6F7C5F2EA9F04D7 / entry-00025
- 原候选 commit：a94ec3b79be9c8ee2cfd2e7a31067e94debc1912
- 原 Entry SHA-256：d413e7a56d73eca7637013deec85f2dfde7c8244106d539fe4ddd64a2ea824d8
- 原报告 SHA-256：3cf972653f7b5249d58ebc53cf1d008e9f4f429fe51b387d0d4ac2c3be998ba8
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-65H8-27JH-Q8WV
- 选取理由：retain_all_reported_errors；原工作流：manual_review；T1：incorrect。
- EP/CO 不同文件：False；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | reported_incorrect_fact | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |

已知旧入口片段存在字符截断缺陷，见 lane_a_review_audit_receipt；本包保留原错误。
若采用完整行修订，另存候选/报告并重新绑定摘要，不能把旧候选当成已经修正。

## DEV-012 · GHSA-H6GW-8F77-MMMP

- 仓库：https://github.com/Tencent/WeKnora
- Task / Entry：VG-TRAIN-C05D4C6BC35FEE353663 / entry-00027
- 原候选 commit：a5d1233b969f66219cf183ec43349089169f1f88
- 原 Entry SHA-256：9dff50115c937ef9734e5ae83c32a5a069d70d491a9a11c9da8288b427db41cd
- 原报告 SHA-256：7284f12e794c7291ac1fce8491fad1f9022b3bfcf27c90bacdf3d76be87740ab
- 来源链接原值（本轮未访问）：https://github.com/advisories/GHSA-H6GW-8F77-MMMP
- 选取理由：uncovered_repository；原工作流：manual_review；T1：uncertain。
- EP/CO 不同文件：False；原 trace 步数：0。这些不是语义判断。
- 本次实质评价：not_reviewed；评审身份：未填写。

| 原报告待审字段 | 原报告所示限制 | 当前动作 |
| --- | --- | --- |
| critical_operation | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| entry_point | role_semantics_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| project | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| trace | trace_completeness_unverified | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l1 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_category_l2 | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
| vuln_title | checker_semantic_capability_gap | 按对应维度查证并填写，不复制 T1 状态当结论 |
