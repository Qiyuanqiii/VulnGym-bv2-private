# 交验候选分流与复核动作

这是对已有复核决定的整理，不是新增语义评价，也没有修改或删除任何原候选。
12条历史开发自评与单条真实模型开发候选保持不同分组；同一任务的不同候选按摘要区分。

| 分组 | 候选数 | 存在反证，暂不采用 | 保留待复核 | 未作语义评价 | 已评但未人工验证 |
| --- | ---: | ---: | ---: | ---: | ---: |
| historical_lane_a_development | 40 | 12 | 0 | 28 | 0 |
| known_input_model_development | 1 | 0 | 1 | 0 | 0 |

## 使用方式

- `excluded_pending_correction`：保留为错例，暂不纳入正确数据；按字段修订成新版本后重新检查。原评价分母不删除。
- `manual_review`：可作为带限制的候选示例，不冒称正确或人工验证完成。
- `not_reviewed`：没有九维内容评价，不从T1或数量推断质量。
- `reviewed_unverified`：即使各字段获支持，也不自动改为verify=1或finalized。
- 仅对已有完整候选分流；defer及传输错误仍在各自运行回执中，不补造Entry。
- 当前建议保留MODEL-DEV-001作主展示候选，同时呈现两个待复核项；12条历史错例进入开发附录，其余28条不作质量承诺。

## 未解决字段与实际下一步

### DEV-001 — excluded_pending_correction

任务：VG-TEST-96AC24B151A1541B5ED6；候选摘要：d62f0c7ab956544b5c5de979e2f8cc001d492e36dbd2a8ad1157485b2e393ea8。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| operation_role | contradicted | 另存修订建议：核对生产message-handler.ts中965–982行的策略决策；不得把测试结束符继续当CO。 |
| trace | uncertain | 先更正CO，再按消息回调、配对筛选及后续处理记录已证实联系。 |

### DEV-002 — excluded_pending_correction

任务：VG-TEST-A08FA28D384BC16E91EE；候选摘要：97f9d443b84af28280cb9b22c2ae8690d63d4726ac04ca760625d1928ea62e87。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| classification | uncertain | 按项目分类词表明确Authentication与Authorization边界，记录具体机制后再裁决。 |
| entry_location | contradicted | 在新修订文件中使用完整行片段并重新检查；原候选继续记录为文本错误。 |
| entry_role | uncertain | 补齐Webhook分发到verifyWebhook的调用依据，采用具体方法边界；同时修正截断片段。 |
| operation_role | contradicted | 根据角色选择URL构造或签名验证实际语句，另存修订，不以邻近行容差认可注释。 |
| title_and_project | uncertain | 改为描述可选插件、代理配置前提及Webhook验证主题的标题，保留旧值。 |
| trace | uncertain | 先定位具体方法与操作，再记录转发头、URL重构和验证之间有依据的联系。 |

### DEV-003 — excluded_pending_correction

任务：VG-TEST-BF91B957B02CA987C926；候选摘要：aeae7d78811c06417752f0820dab89161592675a3368fb5be72320bd1a310f13。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| classification | contradicted | 依据公告机制映射SSRF相关分类；不因可能存在未认证部署便将机制改为Missing Authorization。 |
| entry_role | uncertain | 核对公告组件的实际注册/入口，不因通用loader可调用而认定它是本报告入口。 |
| operation_role | uncertain | 先纠正报告/版本关联，再检查真正相关的请求或决策位置；不从其他加载器猜测。 |
| title_and_project | contradicted | 以公告主题重新拟定标题，并单独验证代码位置，不能仅改标题使错配候选看似正确。 |
| trace | uncertain | 保留已知文档调用事实但不写入该报告trace，待组件关联成立后重建。 |
| version_basis | uncertain | 撤下该父提交推断作为已证实依据；取得报告对应的版本/修复关联后重新运行，不断言现commit一定无问题。 |

### DEV-004 — excluded_pending_correction

任务：VG-TRAIN-40D4B88B06CDE8FCFF5C；候选摘要：52297768e7f1f5fdbcc7c0c06c9df306f16ee272e211dee0172ded6b5d02c9f3。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| entry_role | contradicted | 另存修订建议为287行GET路由或有依据的PATCH/DELETE路由，并记录选择范围。 |
| trace | uncertain | 先修正EP，再把已知helper联系写为修订trace并重新验证；原空trace保持待复核。 |

### DEV-005 — excluded_pending_correction

任务：VG-TRAIN-43AC81B29F131DE6F550；候选摘要：7e094a90153b5b019bf31c22db77e645de4ae47101a92d11692dac75d35ac049。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| entry_role | contradicted | 将323行函数或其已证实UI调用点作为修订候选；不得继续使用文件头配置占位。 |
| operation_role | contradicted | 另存348行实际DOM赋值的建议，并记录进入该值的数据与条件。 |
| title_and_project | uncertain | 以既有公告事实补充prompt插入、富文本条件和DOM问题，不加入未经验证的后果。 |
| trace | uncertain | 修正两端后记录323–351行内已证实的数据处理步骤；不虚构UI外层关系。 |

### DEV-006 — excluded_pending_correction

任务：VG-TRAIN-727D94F6A27E96DB4DAC；候选摘要：82f28bf36a0f8e204c375ad04a5a50e55ba92ea5e4e87965cc5ed38e585cd873。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| entry_role | contradicted | 先重建正确版本关联，再检查报告明确的服务端路由；不在测试代码上补造入口。 |
| operation_role | contradicted | 撤下该CO作为本报告候选，回到获准的服务端资料核实操作与租户约束。 |
| trace | uncertain | 先解决版本及组件错配；无依据时保留defer，不用前端调用链填充此报告。 |
| version_basis | uncertain | 重新获取公告相关的服务端版本依据；不要把修复关联无效误写为候选commit已被证明不受影响。 |

### DEV-007 — excluded_pending_correction

任务：VG-TRAIN-747C63B97771B863292B；候选摘要：da9782cc1d340b4d921d6b1846e316ae6e2edf90ebeee4c66b48cde534a51aee。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| classification | uncertain | 保留未决分类并索取对应机制说明，不由后果或一个参数猜两级类别。 |
| entry_role | contradicted | 依据明确的checkpoint调用入口另存候选，拒绝文件首行兜底。 |
| operation_role | uncertain | 先确认公告到该载入路径的关联；若成立，参数锚点可与完整调用位置作为合理替代讨论。 |
| title_and_project | uncertain | 使用不超出厂商资料的标题，待组件/根因核实后细化。 |
| trace | uncertain | 补齐实际输入来源与方法调用边界，保持空trace的具体缺证据说明。 |
| version_basis | uncertain | 取得厂商对应版本/组件说明或明确修复链接；在此之前只声明本地前后代码事实。 |

### DEV-008 — excluded_pending_correction

任务：VG-TRAIN-74BA579055F87344AC56；候选摘要：56088ef130925cae70a5314f888da460740d808f59caeda77c149a8a45db4ace。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| classification | uncertain | 按配置校验/隔离边界的实际机制重新映射分类，并记录争议。 |
| entry_location | contradicted | 在新修订文件中使用完整行片段并重新检查；原候选继续记录为文本错误。 |
| entry_role | uncertain | 核对配置→参数构造→执行的方向，选定明确的输入边界并先修正文段截断。 |
| operation_role | contradicted | 选择已有参数应用语句或完整函数边界并说明为何是决策位置，不用补丁插入邻行代替语义。 |
| title_and_project | uncertain | 标题体现Docker配置验证及需要影响配置的前置条件。 |
| trace | uncertain | 先明确两端角色和顺序，再记录已核实的配置传播步骤。 |

### DEV-009 — excluded_pending_correction

任务：VG-TRAIN-759F58FDCD672B2F434B；候选摘要：a47e981610abd8d2f750df3dc187089e8cef19a4a1727dc36639aa6a134d12b3。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| entry_location | contradicted | 在新修订文件中使用完整行片段并重新检查；原候选继续记录为文本错误。 |
| entry_role | uncertain | 补充网关分发到该函数的调用/参数依据，修复片段后再裁决入口或合理替代。 |
| operation_role | contradicted | 另存345–346行的持久化决策建议，不使用±5行窗口掩盖语义差异。 |
| trace | uncertain | 先修正CO，再核对scope传递与持久化调用，保留未知外层步骤。 |

### DEV-010 — excluded_pending_correction

任务：VG-TRAIN-8FEE6A4371C6C410BCB8；候选摘要：68ab3dc6cbd94f5a07dbae39dabdd92c9fa72d54c6c2650f462394abba8439a8。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| classification | uncertain | 结合完整修复和公告机制裁决请求处理、输入校验与授权分类边界。 |
| entry_location | contradicted | 在新修订文件中使用完整行片段并重新检查；原候选继续记录为文本错误。 |
| entry_role | uncertain | 补齐webhook/handleFormData分发依据，选择具体入口并另存完整行片段。 |
| operation_role | uncertain | 核对错误数据假设发生的位置及文件处理依赖，允许有依据的多个锚点而不武断签发。 |
| title_and_project | uncertain | 用公告确认的文件访问/请求处理主题表达标题，不提前断言唯一根因。 |
| trace | uncertain | 记录有依据的局部步骤，外层及类型条件补齐后再写完整trace。 |
| version_basis | uncertain | 补充公告版本与对应修复的可追溯关联，区分主题相关和版本已证实。 |

### DEV-011 — excluded_pending_correction

任务：VG-TRAIN-A6D2E6F7C5F2EA9F04D7；候选摘要：d413e7a56d73eca7637013deec85f2dfde7c8244106d539fe4ddd64a2ea824d8。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| entry_location | contradicted | 在新修订文件中使用完整行片段并重新检查；原候选继续记录为文本错误。 |
| entry_role | uncertain | 核实总线接收边界，采用回调或有依据的外层入口，先修正文段截断。 |
| operation_role | contradicted | 回到消息回调与总线的实际操作，保留次序证据后提出修订CO。 |
| trace | uncertain | 补齐总线到回调的实际连接以及策略执行顺序，不将指标初始化纳入trace。 |

### DEV-012 — excluded_pending_correction

任务：VG-TRAIN-C05D4C6BC35FEE353663；候选摘要：9dff50115c937ef9734e5ae83c32a5a069d70d491a9a11c9da8288b427db41cd。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| classification | contradicted | 映射SSRF相关类别并记录TOCTOU特征，版本关联仍单独待确认。 |
| entry_role | contradicted | 另存Execute方法作为候选并核实工具注册/调用边界，不把构造函数当用户输入入口。 |
| title_and_project | contradicted | 以DNS rebinding/校验执行一致性拟定标题，不用权限泛称替代。 |
| trace | uncertain | 更正入口后保留已核实的验证→执行局部关系，分支及外层缺证据明确列出。 |
| version_basis | uncertain | 补齐报告到修复/版本的明确关联，保留现有代码对应作为线索而非最终版本裁决。 |

### MODEL-DEV-001 — manual_review

任务：VG-TRAIN-46D6453D5B4663CF0D13；候选摘要：01e90ad3525187349041df42f24bae1b40c525577136a6b9b248f6e362237f02。

| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |
| --- | --- | --- |
| trace | uncertain | 将本轮后补的可达性说明作为独立复核附件；若补trace应另存修订版本，不改原自动记录。 |
| version_basis | uncertain | 补充获准发行标签到该修复及受影响快照的关联，不能用提交主题取代来源证据。 |
