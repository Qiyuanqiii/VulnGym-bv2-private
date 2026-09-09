"""Explain fixed real results offline; this never starts a production run."""
import argparse
import json
from pathlib import Path

try:
    from .verify_t2_submission_v3 import E, REVIEW, parse, read_directory, validate_members
except ImportError:
    try:
        from verify_delivery import E, REVIEW, parse, read_directory, validate_members
    except ModuleNotFoundError:
        from verify_t2_submission_v3 import E, REVIEW, parse, read_directory, validate_members


def explain(members):
    verified = validate_members(members)
    h = parse(members[E + "handoff.json"])
    r = parse(members[REVIEW])
    return {"demo_mode": "offline_readback_not_live_generation", "new_model_calls": 0,
            "source_commit": verified["source_commit"], "execution_commit": verified["execution_commit"],
            "tasks": [{"task_id": t["task_id"], "status": t["status"], "complete": t["complete"],
                       "verdict": t["verdict"], "candidate_sha256": t["candidate_sha256"]} for t in h["tasks"]],
            "complete_candidates": 1, "t1_reports": 1, "deferred_tasks": 1,
            "original_run": {"http_requests": 6, "cli_exit_code": 0, "tokens": 89577},
            "current_candidate_development_review": r["candidate_review"]["counts"],
            "defer_explanation_correction": "Added checks precede the unchanged assignment; original defer retained.",
            "semantic_accuracy": None, "independent_human_review_completed": False,
            "complete_T2_quality_acceptance": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = explain(read_directory(args.root))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print("VulnGym T2：已有真实结果的离线演示（本次模型请求 0）")
        print("1. 包内源码、结果和摘要核验通过；不是本次现场模型生成。")
        print("2. 原批次 2 题、6 请求、89,577 tokens；完整候选 1，T1 报告 1，弃答 1。")
        for task in result["tasks"]:
            print(f"   {task['task_id']}: complete={task['complete']}, status={task['status']}, verdict={task['verdict']}")
        print("3. 第1题纠正弃答解释的代码先后位置；没有伪造第2份完整 Entry。")
        print("4. 第2题九维开发自评：4 支持、1 合理替代、4 待定；不是独立人审。")
        print("5. 直接查看 data/latest/ 与 evidence/current-review.json；机器 verify=0。")
        print("6. 当前仍缺稳定的新输入产出、代表性质量证据及版本/角色/trace复核。")
        print("源码提交：" + result["source_commit"])
        print("实际运行提交：" + result["execution_commit"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
