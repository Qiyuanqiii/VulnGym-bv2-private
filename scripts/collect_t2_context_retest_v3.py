"""Offline receipt for the frozen v5 partial diagnostic; never calls a provider.

HTTP success, structured-result acceptance, complete candidates and T1 verdicts
are separate counters. Existing production/baseline artifacts are read only.
"""
from collections import Counter
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import collect_t2_new_input_batch_v1 as io
from scripts.collect_t2_context_retest_v2 import USAGE
from scripts.run_t2_context_retest_v3 import RUN, BASE, TASKS, RUNTIME_TREE

PUBLIC = ROOT / "evidence/t2-context-retest-20260909-v3"
EXECUTION_HEAD = "8df0154bfa95a6c2f89b10b795be6b72d5725cb7"
INPUT_SHA = "f6d82a48d6cc375a5419755b15c5e3a381aeb3a22be6704b4cd1a2cd7f01ee1c"
CANDIDATE_SHA = "2b1e946892889632aa5389afd81f8fbc4d7ab04bd746351cf1d14d8e90fcf19d"
BASE_PUBLIC = ROOT / "evidence/t2-context-retest-20260909-v2"


def transport_counts(events, calls, ended):
    """Accept this run's HTTP-success / structured-truncation distinction only."""
    started = [e for e in events if e["event"] == "started"]
    finished = [e for e in events if e["event"] == "finished"]
    assert ended["transport_halt_code"] is None
    assert len(started) == len(finished) == len(calls) == ended["transport_attempts"]
    assert 0 < len(started) <= 6
    assert [e["event"] for e in events] == ["started", "finished"] * len(started)
    assert all(n <= 3 for n in Counter(e["task_id"] for e in started).values())
    seen = set()
    for n, (a, b, c) in enumerate(zip(started, finished, calls, strict=True), 1):
        assert a["attempt"] == b["attempt"] == n
        assert all(a[k] == b[k] for k in ("task_id", "stage", "request_body_sha256", "timeout_seconds"))
        assert a["timeout_seconds"] == 300 and b["status"] == "http_200"
        identity = (a["task_id"], a["stage"])
        assert identity not in seen and identity == (c["task_id"], c["stage"])
        assert a["task_id"] in TASKS and a["stage"] in {"plan", "semantic_judge", "reflection"}
        seen.add(identity)
        assert (c["status"], c["error_code"]) in {
            ("success", None), ("blocked", "deepseek_output_truncated")}
        usage = b["usage"]
        assert all(type(usage.get(k)) is int and usage[k] >= 0 for k in USAGE)
        assert usage["prompt_tokens"] + usage["completion_tokens"] == usage["total_tokens"]
        assert usage["prompt_cache_hit_tokens"] + usage["prompt_cache_miss_tokens"] == usage["prompt_tokens"]
        if c["error_code"] == "deepseek_output_truncated":
            assert c["stage"] == "semantic_judge" and usage["completion_tokens"] == 8192
    return {
        "actual_http_requests": len(started), "http_successes": len(finished), "http_failures": 0,
        "model_invocations": len(calls), "locally_blocked_before_http": 0,
        "structured_results_accepted": sum(c["status"] == "success" for c in calls),
        "structured_results_rejected_after_http": sum(c["status"] != "success" for c in calls),
        "model_stage_counts": dict(sorted(Counter(c["stage"] for c in calls).items())),
        "model_error_counts": dict(Counter(c["error_code"] for c in calls if c["error_code"])),
        "provider_reported_usage": {k: sum(e["usage"][k] for e in finished) for k in USAGE},
        "usage_is_complete_for_this_run": True,
        "http_elapsed_seconds_sum": round(sum(e["elapsed_seconds"] for e in finished), 3),
    }


def reconcile(cli, ended, counts, candidates, deferred, validations):
    """Do not promote a partial batch, abstention or T1 uncertainty to success."""
    assert ended["exit_code"] == cli["exit_code"] == 1
    assert ended["credential_use_ended"] is True and ended["error_code"] is None
    assert cli["status"] == "incomplete" and cli["execution_status"] == "model_execution_incomplete"
    assert cli["tasks_run"] == cli["manual_review"] == 2
    assert all(cli[k] == 0 for k in ("failed", "input_failures", "entries_written", "finalized"))
    assert cli["execution_counts"] == {"complete_candidate_tasks": 1, "t1_report_tasks": 1,
        "deferred_tasks": 1, "model_declared_defer_tasks": 0, "model_problem_tasks": 1,
        "non_success_model_calls": 1}
    assert cli["model_error_counts"] == counts["model_error_counts"] == {"deepseek_output_truncated": 1}
    assert counts["actual_http_requests"] == 5 and counts["structured_results_accepted"] == 4
    assert len(candidates) == len(validations) == len(deferred) == 1
    assert candidates[0]["task_id"] == validations[0]["task_id"] == TASKS[1]
    assert deferred[0]["task_id"] == TASKS[0]
    candidate = candidates[0]["payload"]
    assert candidate["candidate_sha256"] == CANDIDATE_SHA and candidate["candidate"]["verify"] == 0
    report = validations[0]["payload"]["report"]
    assert report["verdict"] == "uncertain"
    assert Counter(v["status"] for v in report["fields"].values()) == {"correct": 9, "uncertain": 7}
    d = deferred[0]["payload"]["deferred"]
    assert d["stage"] == "semantic_judge" and d["reason_code"] == "model_blocked"
    return [
        {"task_id": TASKS[0], "workflow_status": "manual_review", "complete_candidate": False,
         "t1_report": False, "stage": d["stage"], "reason_code": d["reason_code"],
         "model_error": "deepseek_output_truncated", "semantic_abstention": False,
         "deferred_sha256": deferred[0]["payload"]["deferred_sha256"],
         "next_action": "Keep as incomplete. Diagnose response-budget fit offline; any new model run requires separate authorization."},
        {"task_id": TASKS[1], "workflow_status": "manual_review", "complete_candidate": True,
         "t1_report": True, "candidate_sha256": CANDIDATE_SHA, "verify": 0,
         "validation_sha256": validations[0]["payload"]["report_sha256"], "t1_verdict": "uncertain",
         "t1_field_counts": {"correct": 9, "uncertain": 7},
         "next_action": "Review version association, entry/operation roles and trace; do not treat candidate completeness as correctness."},
    ]


def check_baseline():
    ledger_raw = (BASE_PUBLIC / "runtime_files.json").read_bytes()
    manifest = json.loads((BASE_PUBLIC / "manifest.json").read_bytes())
    pin = manifest["files"]["runtime_files.json"]
    assert len(ledger_raw) == pin["bytes"] and sha256(ledger_raw).hexdigest() == pin["sha256"]
    ledger = json.loads(ledger_raw)["files"]
    assert len(ledger) == 23
    for row in ledger:
        path = BASE / row["path"]
        assert path.is_file() and not path.is_symlink()
        raw = path.read_bytes()
        assert len(raw) == row["bytes"] and sha256(raw).hexdigest() == row["sha256"]
    return ledger


def main():
    os.environ.update(TEMP=r"D:\VulnGym-bv2-runtime\tmp", TMP=r"D:\VulnGym-bv2-runtime\tmp",
        PYTHONIOENCODING="utf-8", GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0")
    io.RUN = RUN
    raw = (RUN / "input-manifest.json").read_bytes()
    assert sha256(raw).hexdigest() == INPUT_SHA
    plan = json.loads(raw)
    start = json.loads((RUN / "run-start.json").read_bytes())
    ended = json.loads((RUN / "run-exit.json").read_bytes())
    cli = json.loads((RUN / "cli-stdout.json").read_bytes())
    assert start["execution_head"] == EXECUTION_HEAD and start["input_manifest_sha256"] == INPUT_SHA
    assert plan["runtime_tree"] == RUNTIME_TREE and plan["model"]["timeout_seconds"] == 300
    assert plan["sample_group"] == "seen_input_diagnostic_retest_not_new_input_evaluation"
    output = RUN / "output"
    assert {p.name for p in output.iterdir()} == io.OUTPUT_NAMES
    names = sorted(["output/" + n for n in io.OUTPUT_NAMES] + ["input/" + n for n in plan["input_files"]]
        + ["input-manifest.json", "run-start.json", "run-exit.json", "cli-stdout.json", "transport-events.jsonl"])
    before = [io.pin(RUN / n) for n in names]
    baseline = check_baseline()
    for name, expected in plan["input_files"].items():
        actual = io.pin(RUN / "input" / name)
        assert {k: actual[k] for k in ("bytes", "sha256")} == expected
        assert (RUN / "input" / name).read_bytes() == (BASE / "input" / name).read_bytes()
    events = io.rows(RUN / "transport-events.jsonl")
    calls = [r["payload"]["call"] for r in io.rows(output / "model_calls.jsonl")]
    tools = [r["payload"]["call"] for r in io.rows(output / "tool_calls.jsonl")]
    counts = transport_counts(events, calls, ended)
    candidates, deferred, validations = [io.rows(output / n) for n in
        ("candidates.jsonl", "deferred.jsonl", "validations.jsonl")]
    results = reconcile(cli, ended, counts, candidates, deferred, validations)
    assert all((output / n).stat().st_size == 0 for n in ("entries.jsonl", "errors.jsonl", "repair_history.jsonl"))
    _, readback, readback_check = io.twice([sys.executable, "-B", "-c",
        "import json,sys; from vulngym_agent.orchestrator.replay import verify_closed_loop_artifacts; print(json.dumps(verify_closed_loop_artifacts(sys.argv[1]).to_dict(),sort_keys=True,separators=(',',':')))", str(output)])
    digest = readback["dataset_sha256"]
    command = [sys.executable, "-B", "-m", "vulngym_agent.submission_prediction_cli"]
    common = ["--replay-dir", str(output), "--replay-dataset-sha256", digest, "--expected-task-count", "2"]
    _, review, review_check = io.twice(command + ["review", *common])
    handoff_raw, handoff, handoff_check = io.twice(command + ["handoff", *common])
    assert handoff["complete_count"] == review["complete_count"] == 1
    assert handoff["incomplete_count"] == review["incomplete_count"] == 1
    assert handoff["formal_submission_export"] is False
    delivery = RUN / "verification"
    delivery.mkdir(exist_ok=True)
    io.put_or_compare(delivery / "handoff.json", handoff_raw)
    _, verified, verified_check = io.twice(command + ["verify-handoff", *common,
        "--handoff-file", str(delivery / "handoff.json"), "--handoff-sha256", handoff["handoff_sha256"]])
    assert verified["verified"] is True
    assert before == [io.pin(RUN / n) for n in names] and baseline == check_baseline()
    summary = dict(counts, schema="t2.context-diagnostic-receipt.v3", execution_commit=EXECUTION_HEAD,
        runtime_tree=RUNTIME_TREE, input_manifest_sha256=INPUT_SHA, model=plan["model"],
        sample_group=plan["sample_group"], tasks_planned=2, complete_candidates=1, t1_reports=1,
        candidate_completion_rate={"numerator": 1, "denominator": 2, "value": 0.5},
        semantic_accuracy=None, semantic_improvement_measured=False,
        run_status="partial_one_candidate_one_truncated_model_result", cli_exit_code=1, cli_summary=cli,
        maximum_http_requests=6, automatic_retries=0, budget_cny=20, currency_cost_measured=False,
        credential_use_ended=True, provider_revocation_verified=False,
        platform_hard_cap="operator_confirmed_not_programmatically_verified",
        run_started_at=start["started_at"], finished_at=ended["finished_at"],
        elapsed_seconds=round((datetime.fromisoformat(ended["finished_at"]) - datetime.fromisoformat(start["started_at"])).total_seconds(), 3),
        controlled_producer_tool_calls=len(tools), tool_status_counts=dict(Counter(c["status"] for c in tools)),
        run_dataset_sha256=digest, handoff_sha256=handoff["handoff_sha256"],
        handoff_file_sha256=sha256(handoff_raw).hexdigest(), handoff_bytes=len(handoff_raw),
        formal_submission_export=False, independent_human_review_completed=False,
        readback=readback_check, review=review_check, handoff_generation=handoff_check,
        handoff_verification=verified_check, runtime_files_unchanged=True, runtime_file_count=len(before),
        baseline_files_unchanged_during_collection=True, baseline_file_count=len(baseline), results=results)
    artifacts = {"summary.json": io.wire(summary), "runtime_files.json": io.wire({"files": before}),
        "readback.json": io.wire(readback), "review.json": io.wire(review), "handoff.json": handoff_raw,
        "handoff_verification.json": io.wire(verified), "transport_events.jsonl": b"".join(io.wire(e) for e in events)}
    assert all(io.FORBIDDEN.search(data) is None for data in artifacts.values()), "public_marker_check_failed_preserve"
    artifacts["manifest.json"] = io.wire({"schema": "t2.context-diagnostic-files.v3", "metadata_only": False,
        "contains_candidate_and_validation": True,
        "files": {n: {"bytes": len(b), "sha256": sha256(b).hexdigest()} for n, b in artifacts.items()}})
    PUBLIC.mkdir(exist_ok=True)
    assert {p.name for p in PUBLIC.iterdir()} <= set(artifacts)
    for name, data in artifacts.items():
        io.put_or_compare(PUBLIC / name, data)
    print(io.wire({"status": summary["run_status"], "production_exit_code": 1,
        "http_requests": counts["actual_http_requests"], "provider_reported_usage": counts["provider_reported_usage"],
        "complete_candidates": 1, "t1_reports": 1, "finalized": 0,
        "public_files": len(artifacts), "public_bytes": sum(len(b) for b in artifacts.values()),
        "public_manifest_sha256": sha256(artifacts["manifest.json"]).hexdigest(),
        "run_dataset_sha256": digest, "four_checks_twice_byte_equal": True,
        "original_and_current_run_preserved": True}).decode(), end="")


if __name__ == "__main__":
    main()
