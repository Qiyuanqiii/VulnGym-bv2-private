# 当前真实模型候选的独立分组自评

这是一条已知开发输入的AI辅助自评，不是独立人审，也不进入12条历史开发集的分母。

实际产出仍为原两题中的1份候选及1份T1报告，另一题弃答。本轮只有后补证据检查，没有新的模型/T1调用。

| 维度 | 自评状态 | 依据与限制 | 后续 |
| --- | --- | --- | --- |
| source_identity | supported | 实际候选的GHSA/CVE、来源与获准缓存一致，项目指向同一Flowise仓库。 | 来源身份与版本关联分别判断。 |
| version_basis | uncertain | 候选快照含公告相同的代码，1738fa9父子关系和定向字段变更也真实，较单纯父提交推断更强；但原缓存仅给发行标签等引用，尚未独立核实修复/标签与受影响版本的映射。 | 补充获准发行标签到该修复及受影响快照的关联，不能用提交主题取代来源证据。 |
| entry_location | supported | 从固定commit的23行开始，完整createLead片段逐行匹配，无截断末行或行号容差。 | 保留原自动候选字节。 |
| operation_location | supported | 固定commit的28行与Object.assign(newLead, body)逐行完全一致。 | 位置事实与角色证据分别保留。 |
| entry_role | reasonable_alternative | 本轮源码回读确认/api/v1挂载、/leads路由、POST控制器以及createLead(req.body)直接调用。服务层createLead接收HTTP body，是可解释的较内层入口；这比仅凭函数名判断多了实际调用证据。 | 交验说明该边界选择，并给POST路由/控制器作为更外层替代；不额外断言所有部署均未认证。 |
| operation_role | supported | 控制器传入原body，28行把其属性复制到Lead，随后创建/保存实体；公告与定向替换该复制方式的diff对应。此CO是实质操作而非标点或邻近注释。 | 保留字段处理前提及只读源码证据，不把本轮静态检查冒充运行时验证。 |
| trace | uncertain | 原trace为空，schema允许为空；服务边界内body到赋值很短，但原输出没有解释边界或范围。本轮才补查了HTTP到服务的联系，不能把后补证据说成模型当时已输出。 | 将本轮后补的可达性说明作为独立复核附件；若补trace应另存修订版本，不改原自动记录。 |
| title_and_project | supported | 标题明确leads端点、createLead及属性批量赋值，与公告和本地映射一致；项目使用仓库全名而非短名，不影响项目身份，兼容schema已接受。 | 交付时可统一短项目名，但须标记这是规范化而非新的模型产出。 |
| classification | supported | 公告明确Mass Assignment与CWE-915名称，原两级类别与属性复制机制一致，不是套用通用访问控制类别。 | 保留公告和源码双重依据；不由类名扩张未知后果。 |

汇总：6项supported、1项reasonable_alternative、2项uncertain、0项contradicted。不能换算成整体产品准确率。
原T1仍uncertain、verify仍0、trace原字节不变。新查到的可达性证据记录于本附件，不伪装成原模型trace；版本关联与trace说明仍需收口。
