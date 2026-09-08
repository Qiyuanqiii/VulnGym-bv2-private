# 干净 Python 环境：核心 CLI 与交接回读

2026-09-09，运行源码固定到 `1ef681cee12e88a941e821ff5858b5f6aee3e49c`。本轮补的是可运行性交验，不新增模型结果或语义评分。

- 从该提交只导出运行模块、schemas、三份相关测试及许可/契约文件：118 文件、3,859,370 字节；没有复制 benchmark 数据、隐藏答案、目标仓库、key 或现有 Python site-packages。
- D 盘新建 `venv --without-pip`，Python 3.13.12；实际确认 jsonschema、cryptography、pip 均不存在，模块从导出目录加载。未安装第三方依赖。
- 生产 CLI 和交接 CLI 的真实 `--help` 成功；没有凭证时配置检查按预期返回 2、`network_calls=0`。
- 29 项构造的生产组合/上下文测试全通过，26.818 秒。测试替身明确为 `test.offline-script`，覆盖完整候选到真实本地 T1 的接线、defer、配置和预算；不计作真实模型质量样本。
- 用同一干净环境两次回读此前真实两条新输入的 handoff，均退出 0、stdout 字节相同；原 23 个运行/输入文件不变，导出的源码字节也不变。
- 新模型请求 0；没有在本轮重跑 T2 实际生成。新 venv 仍使用本机 Python 标准库和 Git，不是新的操作系统、容器、网络隔离证明，也没有测试可选签名和附加 jsonschema 库路径。

第一次导出清单误列了并不存在的 `tests/__init__.py`，Git 在写入源码前拒绝；核实仅创建两个空目录后，移除这个不存在的路径并继续，没有删除或覆盖既有结果。Python namespace tests 在干净环境实际运行成功。

[机器结果](../evidence/t2-clean-runtime-20260909-v1/verification.json)及[导出文件哈希](../evidence/t2-clean-runtime-20260909-v1/source_manifest.json)可用于核对；不包含机器绝对路径或原始运行正文。后续文档/启动器提交若不改变运行树，这份核心运行验证仍对应相同源码字节。

接收方从 [START_HERE_T2.md](../START_HERE_T2.md) 启动。运行源码包和真实结果预览是两个用途不同的文件；源码能启动不代表最新真实输入已经产出完整 Entry。
