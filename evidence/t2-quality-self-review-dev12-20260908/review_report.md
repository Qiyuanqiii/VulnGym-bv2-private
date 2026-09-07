# 12条开发样本：实质字段自评

日期：2026-09-08。评价者：当前Codex助手，AI辅助自评、非独立人审。

已对固定12条/8仓库的108个维度逐项检查，不是只复制T1状态。原40条不变、verify均不变；本包不改finalized或人工签署。

样本是已知错例富集的历史开发集，不是新提示词/模型的盲测。原输入来源只用已许可公告缓存、提交包及固定Git对象；未联网、未执行目标代码。

## 汇总

| 层面 | supported | reasonable_alternative | contradicted | uncertain | not_reviewed |
| --- | ---: | ---: | ---: | ---: | ---: |
| fact | 38 | 0 | 5 | 5 | 0 |
| semantic | 11 | 3 | 16 | 30 | 0 |

12/12条至少含一个被本次自评指出的矛盾字段；不能把原T1的uncertain当作高质量通过。字段重复指向同一根因时不当作多个软件缺陷。
metrics.json中的比例仅为已裁决字段自评分母；不代表整体准确率，未解决字段与开发选样偏差必须同时展示。

## 优先修订清单

1. DEV-003/006：父提交来自不相关改动，先重新确认报告→修复/版本关联；在此之前隔离为待核实材料，不基于其扩大模型批次。
2. DEV-001/002/004/005/006/007/008/009/011/012：按逐字段说明处理注释/标点、测试替身、错误路由、构造器/配置占位或不充分方法边界。
3. DEV-003/012：题目主题和两级分类有反证；其他未决分类不得从通用access-control模板填充。
4. DEV-002/008/009/010/011：五个原始文本截断问题保留，修正只能另存并重新验证，不能悄悄替换原候选。
5. trace：12项已检查但均仍待定，逐案列出已知局部关系和缺证据；不把空数组合法当链路充分，也不为补齐而编链。

这些是历史数据的修订需求，不等于证明最新生产代码仍会产生同样错误。新模型批次须单独评价。

## 逐案评价

### DEV-001 / GHSA-XJ9W-5R6Q-X6V4

任务：VG-TEST-96AC24B151A1541B5ED6；原候选：entry-00036；SHA-256：d62f0c7ab956544b5c5de979e2f8cc001d492e36dbd2a8ad1157485b2e393ea8。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-XJ9W-5R6Q-X6V4、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | supported | 原公告正文及缓存引用都指向3886b65；本地确认候选是其直接父提交，旧侧节点命令筛选允许pairedCommands为null，变更针对同一配对策略。支持该源码快照的依据，不外推所有发行版。 | 保留公告、父子提交和旧侧条件三项依据。 |
| entry_location | supported | 独立读取固定commit的src/gateway/server/ws-connection/message-handler.ts，从139行开始的35行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| operation_location | supported | 独立读取固定commit的src/gateway/server.roles-allowlist-update.test.ts，从99行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | reasonable_alternative | 139行注册WebSocket消息处理器，同函数265行实际接收message，965行以后处理公告所述节点配对。注册函数可作为较宽的入口锚点，不声称它是唯一入口。 | 若要求更细粒度入口，可改为265行消息回调并说明连接前置条件。 |
| operation_role | contradicted | 原CO是测试文件99行的函数结束符；其上下文是测试连接辅助函数，不是生产消息处理器内的配对/命令筛选。文本存在不能支持该操作角色。 | 另存修订建议：核对生产message-handler.ts中965–982行的策略决策；不得把测试结束符继续当CO。 |
| trace | uncertain | 当前两端一端在生产消息处理器、一端在测试辅助函数，空trace不能解释二者的生产关系；没有依据可以直接给原两端补链。 | 先更正CO，再按消息回调、配对筛选及后续处理记录已证实联系。 |
| title_and_project | supported | 项目名与公告OpenClaw一致；标题虽为宽泛access control模板，但未改变公告中的节点配对授权主题。这里只认可主题一致，不能据此称标题信息充分。 | 建议标题补充device/node pairing差异，移除无业务意义的任务后缀。 |
| classification | supported | 公告明确区分device pairing与node pairing权限，旧侧筛选在无配对记录时放行命令；Access Control / Missing Authorization与此策略缺口一致。 | 保留配对和配置前置条件，不把高层后果当作分类依据。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

### DEV-002 / GHSA-3M3Q-X3GJ-F79X

任务：VG-TEST-A08FA28D384BC16E91EE；原候选：entry-00006；SHA-256：97f9d443b84af28280cb9b22c2ae8690d63d4726ac04ca760625d1928ea62e87。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-3M3Q-X3GJ-F79X、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | supported | 公告引用a749db9并给出插件版本范围；候选为其直接父提交。旧侧重构URL直接使用转发头，补丁引入显式信任及允许范围参数，和公告原因对应。 | 该结论限定源码快照；正式发行包仍按公告范围说明。 |
| entry_location | contradicted | 独立读取固定commit的extensions/voice-call/src/providers/plivo.ts，从31行开始不能逐行匹配原候选；候选为2,000字符硬截断的残行片段，源字节及候选摘要已分别固定。没有改写旧记录。 | 在新修订文件中使用完整行片段并重新检查；原候选继续记录为文本错误。 |
| operation_location | supported | 独立读取固定commit的extensions/voice-call/src/webhook-security.ts，从60行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | uncertain | EP是PlivoProvider类声明和初始化片段，实际verifyWebhook入口在91行。类确实包含相关方法，但当前片段没有证明外部Webhook如何进入该类。 | 补齐Webhook分发到verifyWebhook的调用依据，采用具体方法边界；同时修正截断片段。 |
| operation_role | contradicted | CO仅为webhook-security.ts第60行的注释起始符。URL重构函数从73行开始，转发头读取在76–83行，注释本身不是验证或重构操作。 | 根据角色选择URL构造或签名验证实际语句，另存修订，不以邻近行容差认可注释。 |
| trace | uncertain | 已经检查类与URL重构上下文，但原EP/CO没有形成可用的具体边界；调用分发及签名验证的完整连接仍未补齐。 | 先定位具体方法与操作，再记录转发头、URL重构和验证之间有依据的联系。 |
| title_and_project | uncertain | OpenClaw项目无误，但标题未区分可选voice-call插件和转发头信任造成的Webhook身份验证问题，泛称access control缺少关键范围。 | 改为描述可选插件、代理配置前提及Webhook验证主题的标题，保留旧值。 |
| classification | uncertain | 公告描述请求真实性/签名验证受转发头影响，而原二级类别是Missing Authorization；当前资料不足以把身份验证与授权缺失当作同一类。 | 按项目分类词表明确Authentication与Authorization边界，记录具体机制后再裁决。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

### DEV-003 / GHSA-FVCW-9W9R-PXC7

任务：VG-TEST-BF91B957B02CA987C926；原候选：entry-00010；SHA-256：aeae7d78811c06417752f0820dab89161592675a3368fb5be72320bd1a310f13。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-FVCW-9W9R-PXC7、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | uncertain | 缓存原引用没有该fix commit。64e9a15及其diff仅为自定义文档加载器传递workspaceId，与公告HTTP Node主题不一致。直接父子关系成立，但不能据此确认受影响版本。 | 撤下该父提交推断作为已证实依据；取得报告对应的版本/修复关联后重新运行，不断言现commit一定无问题。 |
| entry_location | supported | 独立读取固定commit的packages/server/src/services/documentstore/index.ts，从703行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| operation_location | supported | 独立读取固定commit的packages/server/src/services/documentstore/index.ts，从564行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | uncertain | previewChunks是文档加载预览服务；公告讨论AgentFlow/Chatflow HTTP Node。所读代码确有文档加载调用，但未建立它和公告中HTTP Node的对应关系。 | 核对公告组件的实际注册/入口，不因通用loader可调用而认定它是本报告入口。 |
| operation_role | uncertain | _splitIntoChunks执行文档加载和切分；当前片段没有展示HTTP Node的请求行为，已选修复又是workspaceId传递，因此该角色尚无报告对应证据。 | 先纠正报告/版本关联，再检查真正相关的请求或决策位置；不从其他加载器猜测。 |
| trace | uncertain | 源码717行支持previewChunks调用_splitIntoChunks，但这只是文档预览链，不能把它冒充公告HTTP Node链。原空trace的缺口是报告关联未解决。 | 保留已知文档调用事实但不写入该报告trace，待组件关联成立后重建。 |
| title_and_project | contradicted | 项目Flowise一致；公告明确主题为HTTP Node的服务器请求转发，原标题却声称access control issue，未描述同一机制。 | 以公告主题重新拟定标题，并单独验证代码位置，不能仅改标题使错配候选看似正确。 |
| classification | contradicted | 公告明确标为SSRF，原值Access Control / Missing Authorization把请求目标约束问题写成缺少授权；本地所读补丁也没有支持此分类。 | 依据公告机制映射SSRF相关分类；不因可能存在未认证部署便将机制改为Missing Authorization。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

### DEV-004 / GHSA-8C4J-F57C-35CF

任务：VG-TRAIN-40D4B88B06CDE8FCFF5C；原候选：entry-00013；SHA-256：52297768e7f1f5fdbcc7c0c06c9df306f16ee272e211dee0172ded6b5d02c9f3。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-8C4J-F57C-35CF、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | supported | 公告描述PR8956及_read_flow的旧查询。候选父版本269–284行与描述逐项对应；d437d01提交主题含8956，diff改为无条件按user_id过滤。不是只凭父提交选择。 | 保留旧查询、公告PR和对应diff的联合证据。 |
| entry_location | supported | 独立读取固定commit的src/backend/base/langflow/api/v1/flows.py，从145行开始的6行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| operation_location | supported | 独立读取固定commit的src/backend/base/langflow/api/v1/flows.py，从295行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | contradicted | 原EP145行是POST创建路由，调用_new_flow；公告涉及GET/PATCH/DELETE既有flow并调用_read_flow。源码清楚区分两组处理函数，不能以同文件认定相同入口。 | 另存修订建议为287行GET路由或有依据的PATCH/DELETE路由，并记录选择范围。 |
| operation_role | reasonable_alternative | 295行调用_read_flow并决定是否返回对象，公告将该helper作为所有权查询边界。调用点可作合理较宽锚点；更精细CO是277–284行的查询及执行。 | 注明这是helper调用边界而非声称295行包含全部查询条件；可提供更细粒度替代。 |
| trace | uncertain | 公告和源码已经支持read_flow→_read_flow→查询执行的局部联系；但原EP为create_flow，不能据这些事实证明原候选两端连接。空trace也没有说明这一不一致。 | 先修正EP，再把已知helper联系写为修订trace并重新验证；原空trace保持待复核。 |
| title_and_project | supported | 项目和access control主题与跨用户对象所有权缺失一致。标题粒度粗但没有引入不同机制；不把模板后缀当作有效描述。 | 建议补充对象所有权及读写删除范围，保留开发历史。 |
| classification | supported | 已认证用户读取他人对象、查询未按所有者约束与Missing Authorization一致；公告和旧查询共同支持，不是复制T1判定。 | 保留认证已开启这一前提。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

### DEV-005 / GHSA-W7XJ-8FX7-WFCH

任务：VG-TRAIN-43AC81B29F131DE6F550；原候选：entry-00014；SHA-256：7e094a90153b5b019bf31c22db77e645de4ae47101a92d11692dac75d35ac049。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-W7XJ-8FX7-WFCH、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | supported | 原缓存明确引用eb9c4c0；候选为其父提交，同文件348行保留公告展示的DOM赋值。diff在该数据转换前增加净化，支持源码快照及报告对应。 | 把快照证据与发行版本范围分开说明。 |
| entry_location | supported | 独立读取固定commit的src/lib/components/common/RichTextInput.svelte，从3行开始的25行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| operation_location | supported | 独立读取固定commit的src/lib/components/common/RichTextInput.svelte，从344行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | contradicted | EP3行是marked.use的全局渲染配置；接受本次prompt文本的replaceCommandWithText从323行开始。配置执行不是单次用户prompt进入该处理链的入口。 | 将323行函数或其已证实UI调用点作为修订候选；不得继续使用文件头配置占位。 |
| operation_role | contradicted | 344行.trim只去除首尾空白；公告和旧代码都把348行DOM赋值作为相关操作。二者相差4行也不能用位置窗口替代语义区别。 | 另存348行实际DOM赋值的建议，并记录进入该值的数据与条件。 |
| trace | uncertain | 已检查到文本转换、DOM赋值和解析步骤，但原EP配置与CO.trim不构成所声称角色。不能直接将已知步骤接到错误两端，也未证明当前空trace是充分解释。 | 修正两端后记录323–351行内已证实的数据处理步骤；不虚构UI外层关系。 |
| title_and_project | uncertain | open-webui项目正确，Rich text input handling issue只是中性模板，缺少持久化prompt和DOM上下文，尚不足以作为清晰的交验标题。 | 以既有公告事实补充prompt插入、富文本条件和DOM问题，不加入未经验证的后果。 |
| classification | supported | 公告的Stored DOM XSS描述与旧侧赋值、补丁引入净化一致，Cross-Site Scripting / Input Sanitization有具体依据。 | 保留Insert Prompt as Rich Text启用条件。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

### DEV-006 / GHSA-3XX2-MQJM-HG9X

任务：VG-TRAIN-727D94F6A27E96DB4DAC；原候选：entry-00019；SHA-256：82f28bf36a0f8e204c375ad04a5a50e55ba92ea5e4e87965cc5ed38e585cd873。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-3XX2-MQJM-HG9X、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | uncertain | 原缓存未引用d202631。该提交及全部变更路径属于Markdown编辑器，公告对应server/src/routes/agents.ts的跨租户API；父子关系不能支持本报告的版本关联。 | 重新获取公告相关的服务端版本依据；不要把修复关联无效误写为候选commit已被证明不受影响。 |
| entry_location | supported | 独立读取固定commit的ui/src/components/MarkdownEditor.test.tsx，从38行开始的4行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| operation_location | supported | 独立读取固定commit的ui/src/components/MarkdownEditor.tsx，从523行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | contradicted | EP在MarkdownEditor.test.tsx的useMemo测试替身，返回编辑器ref方法；公告描述服务端agents keys路由。测试替身不是该服务端请求入口。 | 先重建正确版本关联，再检查报告明确的服务端路由；不在测试代码上补造入口。 |
| operation_role | contradicted | CO执行Markdown粘贴归一化；公告讨论跨租户API key的查询、创建和撤销，两者组件和业务动作均不相符。 | 撤下该CO作为本报告候选，回到获准的服务端资料核实操作与租户约束。 |
| trace | uncertain | 已读到测试替身和前端粘贴回调，均不是公告服务端路径，缺少可支持原两端与报告关系的证据。 | 先解决版本及组件错配；无依据时保留defer，不用前端调用链填充此报告。 |
| title_and_project | supported | 项目paperclip和access control主题与公告跨租户对象授权问题一致；这不意味着所配前端代码也正确。 | 可细化为跨租户agent key授权问题；代码错配必须另行处理。 |
| classification | supported | 公告明确区分board身份检查与目标公司访问权，Missing Authorization是有内容依据的分类。 | 保留租户与目标agent的关系，不把仅有登录态当作对象授权。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

### DEV-007 / GHSA-V7V2-M736-CF3C

任务：VG-TRAIN-747C63B97771B863292B；原候选：entry-00020；SHA-256：da9782cc1d340b4d921d6b1846e316ae6e2edf90ebeee4c66b48cde534a51aee。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-V7V2-M736-CF3C、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | uncertain | 厂商缓存只有一般性后果描述，原references没有156f292。源码父子关系及weights_only参数变更真实，但还缺该变更与此公告的权威版本关联。 | 取得厂商对应版本/组件说明或明确修复链接；在此之前只声明本地前后代码事实。 |
| entry_location | supported | 独立读取固定commit的nemo/lightning/io/hf.py，从1行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| operation_location | supported | 独立读取固定commit的nemo/lightning/io/hf.py，从258行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | contradicted | EP第1行仅是版权声明，既不接受checkpoint输入也不是函数/方法边界。源码中真实载入方法在文件后部，不能把文件存在当入口。 | 依据明确的checkpoint调用入口另存候选，拒绝文件首行兜底。 |
| operation_role | uncertain | 258行确为torch.load调用参数，补丁也删除该参数，作为载入行为锚点有技术相关性；但缓存公告未明确组件和根因，尚不能确认它就是此报告CO。 | 先确认公告到该载入路径的关联；若成立，参数锚点可与完整调用位置作为合理替代讨论。 |
| trace | uncertain | 当前EP为版权行，公告又没有说明checkpoint如何进入该方法；只观察到局部载入不足以补出来源与完整连接。 | 补齐实际输入来源与方法调用边界，保持空trace的具体缺证据说明。 |
| title_and_project | uncertain | NeMo项目与公告一致，但公告只给出代码执行后果，没有依据支持标题中的access control机制。 | 使用不超出厂商资料的标题，待组件/根因核实后细化。 |
| classification | uncertain | Missing Authorization不是从当前简短厂商公告可推出的结论；参数差异也不能单独证明此公告的两级类别。 | 保留未决分类并索取对应机制说明，不由后果或一个参数猜两级类别。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

### DEV-008 / GHSA-W235-X559-36MG

任务：VG-TRAIN-74BA579055F87344AC56；原候选：entry-00021；SHA-256：56088ef130925cae70a5314f888da460740d808f59caeda77c149a8a45db4ace。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-W235-X559-36MG、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | supported | 原公告明确引用887b209及Docker配置问题；候选为直接父提交，旧侧构建参数未作新增的配置验证，diff和公告涉及同一函数及配置值。 | 仅支持所查源码快照，发行版范围沿用有日期的公告。 |
| entry_location | contradicted | 独立读取固定commit的src/agents/sandbox/docker.ts，从27行开始不能逐行匹配原候选；候选为2,000字符硬截断的残行片段，源字节及候选摘要已分别固定。没有改写旧记录。 | 在新修订文件中使用完整行片段并重新检查；原候选继续记录为文本错误。 |
| operation_location | supported | 独立读取固定commit的src/agents/sandbox/docker.ts，从242行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | uncertain | execDockerRaw接收已经构造的Docker参数并启动进程，处于下游执行边界；当前片段没有说明外部配置如何进入，不能自动称为报告的输入入口。 | 核对配置→参数构造→执行的方向，选定明确的输入边界并先修正文段截断。 |
| operation_role | contradicted | CO为buildSandboxCreateArgs签名末尾的})，没有参数应用或配置决策内容。补丁在其后新增验证并不使原标点自身成为操作。 | 选择已有参数应用语句或完整函数边界并说明为何是决策位置，不用补丁插入邻行代替语义。 |
| trace | uncertain | 原EP处于执行侧、CO落在构建函数签名，现有空trace没有证明调用方向或配置进入过程。 | 先明确两端角色和顺序，再记录已核实的配置传播步骤。 |
| title_and_project | uncertain | 项目正确，但access control通用标题没有表达配置注入和隔离设置这一具体主题，也没有给出攻击前提。 | 标题体现Docker配置验证及需要影响配置的前置条件。 |
| classification | uncertain | 公告强调危险配置缺少校验；Missing Authorization是否合适取决于具体信任边界，不能仅由可能的隔离后果认定缺少身份授权。 | 按配置校验/隔离边界的实际机制重新映射分类，并记录争议。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

### DEV-009 / GHSA-5H2W-QMFP-GGP6

任务：VG-TRAIN-759F58FDCD672B2F434B；原候选：entry-00038；SHA-256：a47e981610abd8d2f750df3dc187089e8cef19a4a1727dc36639aa6a134d12b3。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-5H2W-QMFP-GGP6、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | supported | 公告引用c603123；父提交旧侧345–346行应用verbose持久化，diff增加对应权限条件，主题、函数和变更一致。 | 保留原父版本，不将历史候选文本视为已修复。 |
| entry_location | contradicted | 独立读取固定commit的src/auto-reply/reply/directive-handling.impl.ts，从61行开始不能逐行匹配原候选；候选为2,000字符硬截断的残行片段，源字节及候选摘要已分别固定。没有改写旧记录。 | 在新修订文件中使用完整行片段并重新检查；原候选继续记录为文本错误。 |
| operation_location | supported | 独立读取固定commit的src/auto-reply/reply/directive-handling.impl.ts，从344行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | uncertain | handleDirectiveOnly是相关指令处理函数，函数体与公告一致；但本轮尚未核实外部chat.send如何调用它及scope传入，不能把内部函数直接宣称外部可达入口。 | 补充网关分发到该函数的调用/参数依据，修复片段后再裁决入口或合理替代。 |
| operation_role | contradicted | 344行右括号结束thinkingLevel降级分支，公告相关的verbose判断及applyVerboseOverride在345–346行；原CO指向不同逻辑块。 | 另存345–346行的持久化决策建议，不使用±5行窗口掩盖语义差异。 |
| trace | uncertain | 已核实同函数内的verbose处理，但外层chat.send入口、持久化落点尚未完整核对，原CO又不在该操作上。 | 先修正CO，再核对scope传递与持久化调用，保留未知外层步骤。 |
| title_and_project | supported | OpenClaw和access control主题与write/admin权限差异一致，虽然通用标题缺少verbose对象细节。 | 建议在标题注明持久化verbose默认值及scope差异。 |
| classification | supported | 公告明确是write作用域可触及admin-only持久化操作；旧侧条件及新增权限判断共同支持Missing Authorization。 | 保留已授权write而非完全未认证这一前提。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

### DEV-010 / GHSA-V4PR-FM98-W9PG

任务：VG-TRAIN-8FEE6A4371C6C410BCB8；原候选：entry-00024；SHA-256：68ab3dc6cbd94f5a07dbae39dabdd92c9fa72d54c6c2650f462394abba8439a8。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-V4PR-FM98-W9PG、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | uncertain | 候选确为c8d604d父提交，局部diff新增multipart类型断言，与请求处理主题相关；但原公告未给出此commit，当前未核实固定版本1.121.0和该快照关联。 | 补充公告版本与对应修复的可追溯关联，区分主题相关和版本已证实。 |
| entry_location | contradicted | 独立读取固定commit的packages/@n8n/nodes-langchain/nodes/trigger/ChatTrigger/ChatTrigger.node.ts，从215行开始不能逐行匹配原候选；候选为2,000字符硬截断的残行片段，源字节及候选摘要已分别固定。没有改写旧记录。 | 在新修订文件中使用完整行片段并重新检查；原候选继续记录为文本错误。 |
| operation_location | supported | 独立读取固定commit的packages/@n8n/nodes-langchain/nodes/trigger/ChatTrigger/ChatTrigger.node.ts，从568行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | uncertain | EP为ChatTrigger类及节点描述配置，代码说明它是触发器，但尚未核实SDK如何分发外部请求到其处理方法；原片段还被截断。 | 补齐webhook/handleFormData分发依据，选择具体入口并另存完整行片段。 |
| operation_role | uncertain | 568行取得请求对象，后文601–605行才处理文件；补丁围绕内容类型假设。请求读取有相关性，但不能直接等同于文件访问或具体错误决策。 | 核对错误数据假设发生的位置及文件处理依赖，允许有依据的多个锚点而不武断签发。 |
| trace | uncertain | 局部代码显示请求对象、body.files和文件处理，但入口分发与版本关联仍有缺口；原空trace没有区分已知局部关系和未知外层。 | 记录有依据的局部步骤，外层及类型条件补齐后再写完整trace。 |
| title_and_project | uncertain | n8n项目正确；access control通用标题不能说明公告中的Webhook请求处理和文件访问机制，缺少明确范围。 | 用公告确认的文件访问/请求处理主题表达标题，不提前断言唯一根因。 |
| classification | uncertain | 未认证可达是后果前提，不必然意味着Missing Authorization是根因；局部补丁是内容类型断言，当前证据不足以确认原两级类别。 | 结合完整修复和公告机制裁决请求处理、输入校验与授权分类边界。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

### DEV-011 / GHSA-65H8-27JH-Q8WV

任务：VG-TRAIN-A6D2E6F7C5F2EA9F04D7；原候选：entry-00025；SHA-256：d413e7a56d73eca7637013deec85f2dfde7c8244106d539fe4ddd64a2ea824d8。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-65H8-27JH-Q8WV、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | supported | 原公告明确引用1ee9611；父提交channel.ts的onMessage直接分发，diff先引入authorizeSender且与公告的处理顺序描述对应。支持该旧侧快照。 | 具体密码运算和运行开销未执行验证，不扩大为完整影响证明。 |
| entry_location | contradicted | 独立读取固定commit的extensions/nostr/src/channel.ts，从88行开始不能逐行匹配原候选；候选为2,000字符硬截断的残行片段，源字节及候选摘要已分别固定。没有改写旧记录。 | 在新修订文件中使用完整行片段并重新检查；原候选继续记录为文本错误。 |
| operation_location | supported | 独立读取固定commit的extensions/nostr/src/channel.ts，从37行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | uncertain | nostrPlugin对象声明包含插件配置；实际接收消息的onMessage回调在233行，声明片段本身不呈现消息输入或前置策略。 | 核实总线接收边界，采用回调或有依据的外层入口，先修正文段截断。 |
| operation_role | contradicted | 37行是用于状态上报的metricsSnapshots Map初始化，注释和后文均非消息解密或授权/分发操作，不能代表报告中的处理顺序问题。 | 回到消息回调与总线的实际操作，保留次序证据后提出修订CO。 |
| trace | uncertain | 当前已看到回调直接分发，但解密发生在另一总线文件，原CO是指标容器；不能据原两端重建完整处理顺序。 | 补齐总线到回调的实际连接以及策略执行顺序，不将指标初始化纳入trace。 |
| title_and_project | supported | 项目与访问策略主题一致，公告明确强调sender/pairing策略执行顺序；通用标题未引入相反机制，但应进一步具体化。 | 建议写明Nostr入站消息和策略检查过晚，不只写任务后缀。 |
| classification | supported | 原公告明确说明sender/pairing policy晚于处理，源码与patch支持授权检查时序缺口，可归入Access Control / Missing Authorization的宽分类。 | 保留时序性质，说明并非断言系统完全没有任何授权实现。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

### DEV-012 / GHSA-H6GW-8F77-MMMP

任务：VG-TRAIN-C05D4C6BC35FEE353663；原候选：entry-00027；SHA-256：9dff50115c937ef9734e5ae83c32a5a069d70d491a9a11c9da8288b427db41cd。

| 维度 | 自评状态 | 依据及限制 | 下一步 |
| --- | --- | --- | --- |
| source_identity | supported | 原始候选的GHSA-H6GW-8F77-MMMP、来源链接及标识集合与获准缓存和公告一致，项目与仓库也对应。此项只核对来源身份，不把衍生fix_commits或代码角色一起认证。 | 保持输入来源身份与版本/角色评价分开。 |
| version_basis | uncertain | 父子提交与DNS pinning变更真实，旧侧validateParams/executeFetch也与公告所述一致；但原缓存references没有2b3f76e，当前未确认该fix及受影响版本的来源关联。 | 补齐报告到修复/版本的明确关联，保留现有代码对应作为线索而非最终版本裁决。 |
| entry_location | supported | 独立读取固定commit的internal/agent/tools/web_fetch.go，从76行开始的11行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| operation_location | supported | 独立读取固定commit的internal/agent/tools/web_fetch.go，从127行开始的1行与候选逐行完全相符；没有使用±5行窗口或复制T1结论。位置事实不证明语义角色。 | 保留位置事实，角色单独评价。 |
| entry_role | contradicted | 76行NewWebFetchTool只接收chatModel并构建工具；实际解析外部工具args的是89行Execute。构造器不是该报告URL输入的入口。 | 另存Execute方法作为候选并核实工具注册/调用边界，不把构造函数当用户输入入口。 |
| operation_role | reasonable_alternative | 127行validateParams是公告明确列出的第一次检查边界；140行仍传原参数到执行。对TOCTOU问题可把检查点作为合理锚点，但它不是完整请求操作。 | 说明此CO只表示检查侧，另给执行侧候选，并用证据连接两次处理；不声称127行覆盖全部问题。 |
| trace | uncertain | 公告和旧代码支持验证后传原URL继续执行，但原EP是构造器，外层工具调用和后续浏览器/HTTP分支也未在本轮逐条核验。 | 更正入口后保留已核实的验证→执行局部关系，分支及外层缺证据明确列出。 |
| title_and_project | contradicted | WeKnora项目正确；公告具体主题是DNS校验与执行解析不一致的SSRF，原access control标题写成另一机制。 | 以DNS rebinding/校验执行一致性拟定标题，不用权限泛称替代。 |
| classification | contradicted | 公告及对应变更指向SSRF和解析时序，Missing Authorization没有描述该机制；拥有URL校验但未保持解析结果不能直接等同于缺少对象授权。 | 映射SSRF相关类别并记录TOCTOU特征，版本关联仍单独待确认。 |

证据键见reviews.jsonl，均可解析到evidence_index.json中的原候选、获准公告/缓存或固定源码摘要。

## 剩余验收

A3/A5由未评价推进为有可复核的开发自评，仍未完成新输入评价或独立人审。至少两份冻结后新输入、实际生产、质量提升复测及最终演示仍待完成。

本包没有替历史Langflow自检补写理由，没有调用外部API，也没有把候选verify改为1。
