"""Explain existing genuine outcomes; no provider, target execution or writes."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.verify_t2_updated_preview import validate_members

PREVIEW_SHA = "452a0cf3e869573f7aaf18f36c92e2c9f9a7319a968c195422948835292f1a09"
RECEIPT_SHA = "74c03396af2eb3767426598e329ba5b86d901ddd69fd86dc63b2c7cefa826f55"


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preview-zip", required=True, type=Path)
    parser.add_argument("--timeout-receipt", required=True, type=Path)
    args = parser.parse_args(argv)
    raw = args.preview_zip.read_bytes()
    assert len(raw) == 136809 and sha256(raw).hexdigest() == PREVIEW_SHA
    with zipfile.ZipFile(args.preview_zip) as archive:
        assert len(archive.namelist()) == len(set(archive.namelist())) == 38
        members = {n: archive.read(n) for n in archive.namelist()}
    checked = validate_members(members)
    root = args.timeout_receipt
    manifest_raw = (root / "manifest.json").read_bytes()
    assert sha256(manifest_raw).hexdigest() == RECEIPT_SHA
    manifest = json.loads(manifest_raw)
    assert {p.name for p in root.iterdir()} == set(manifest["files"]) | {"manifest.json"}
    for name, expected in manifest["files"].items():
        value = (root / name).read_bytes()
        assert len(value) == expected["bytes"] and sha256(value).hexdigest() == expected["sha256"]
    current = json.loads((root / "summary.json").read_bytes())
    handoff = json.loads(members["data/handoff.json"])
    entry = handoff["entries"][0]
    print("VulnGym T2 | 已有真实结果演示 | 无模型调用、无新数据生成")
    print("1. 输入：事先准备的公告/patch与固定Git源码；不是任意URL一键抓取。")
    print("2. 真实开发组：2任务，1完整候选+真实T1报告，1自检弃答；不是新输入盲测。")
    print("   完整候选标题：" + str(entry.get("vuln_title", entry.get("title", "见完整JSON"))))
    print("   verify=" + str(entry["verify"]) + "；T1整体现有判定uncertain，不能声称人工已验证。")
    print("   候选九维自评：6支持、1合理替代、2待定；评价者为AI辅助开发自评。")
    print("3. 首次新输入组：2任务、0完整候选、2语义defer。产出0/2，语义准确率null。")
    print("4. 修改后同输入诊断：实际2请求，1成功、1超时；第二任务未发送到服务端。")
    print("   已知用量4854 tokens只是成功请求用量；超时请求用量/费用未知。")
    print("   没收到语义判断，不能据此认定改进有效或无效。")
    print("5. 新CLI改进：调用问题显示incomplete并退出1；正常defer不冒充网络失败。")
    print("   --progress在stderr输出任务进度；等待有上限，不启用自动重试。")
    print("6. 尚缺：稳定完整产出和质量证据、最终演示录像。此脚本不替代这些验收项。")
    print(json.dumps({"verified": checked["verified"], "new_provider_calls": 0,
        "demonstration": "existing_results_not_live_production", "development_complete_candidates": 1,
        "first_new_input_complete_candidates": 0, "diagnostic_complete_candidates": current["complete_candidates"],
        "diagnostic_status": current["run_status"]}, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
