"""Offline receipt for the completed, already-seen two-input diagnostic.

No provider calls, keys, target execution, or production reruns. Historical
files are read only; receipt output is new or must exactly match existing bytes.
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
from scripts.run_t2_context_retest_v2 import RUN, BASE, TASKS, RUNTIME_TREE

PUBLIC = ROOT / "evidence/t2-context-retest-20260909-v2"
EXECUTION_HEAD = "17175b2559272215a12f7f0cf425326a8440cac9"
INPUT_SHA = "ca37cb9bb7661c5ad000e381665bd374fb9c6a6ed3b6f81a4265d2152be93533"
USAGE = ("prompt_tokens", "completion_tokens", "total_tokens", "prompt_cache_hit_tokens", "prompt_cache_miss_tokens")


def successful_transport_counts(events, calls, ended):
    """This receipt accepts only a finished all-success transport run, not timeouts."""
    started = [e for e in events if e["event"] == "started"]
    finished = [e for e in events if e["event"] == "finished"]
    assert ended["transport_halt_code"] is None
    assert len(started) == len(finished) == len(calls) == ended["transport_attempts"] <= 6
    assert [e["event"] for e in events] == ["started", "finished"] * len(started)
    assert all(n <= 3 for n in Counter(e["task_id"] for e in started).values())
    seen = set()
    for n, (a, b, c) in enumerate(zip(started, finished, calls, strict=True), 1):
        assert a["attempt"] == b["attempt"] == n
        assert all(a[k] == b[k] for k in ("task_id", "stage", "request_body_sha256", "timeout_seconds"))
        assert a["task_id"] in TASKS and a["stage"] in {"plan", "semantic_judge", "reflection"}
        identity = (a["task_id"], a["stage"])
        assert identity not in seen
        seen.add(identity)
        assert (c["task_id"], c["stage"]) == identity
        assert a["timeout_seconds"] == 300 and b["status"] == "http_200" and c["status"] == "success"
        usage = b["usage"]
        assert all(type(usage.get(k)) is int and usage[k] >= 0 for k in USAGE)
        assert usage["prompt_tokens"] + usage["completion_tokens"] == usage["total_tokens"]
        assert usage["prompt_cache_hit_tokens"] + usage["prompt_cache_miss_tokens"] == usage["prompt_tokens"]
    return {"actual_http_requests": len(started), "http_successes": len(finished),
        "http_failures": 0, "model_invocations": len(calls), "locally_blocked_invocations": 0,
        "model_stage_counts": dict(sorted(Counter(c["stage"] for c in calls).items())),
        "provider_reported_usage": {k: sum(e["usage"][k] for e in finished) for k in USAGE},
        "usage_is_complete_for_this_run": True,
        "http_elapsed_seconds_sum": round(sum(e["elapsed_seconds"] for e in finished), 3)}


def defer_results(deferred):
    assert len(deferred) == 2 and tuple(row["task_id"] for row in deferred) == TASKS
    results = []
    for row in deferred:
        value = row["payload"]["deferred"]
        assert value["reason_code"] == "model_deferred"
        details = [json.loads(s.removeprefix("model_defer_details:"))
                   for s in value["missing_information"] if s.startswith("model_defer_details:")]
        assert len(details) == 1
        detail = details[0]
        assert detail["assessment_origin"] == "model_self_report_not_independently_verified"
        assert (value["stage"], detail["kind"]) in {
            ("semantic_judge", "model_semantic_defer_v1"), ("reflection", "model_reflection_defer_v1")}
        results.append({"task_id": row["task_id"], "report_id": value["report_id"],
            "workflow_status": "manual_review", "complete_candidate": False, "t1_report": False,
            "stage": value["stage"], "reason_code": value["reason_code"],
            "deferred_sha256": row["payload"]["deferred_sha256"], "model_self_report": detail})
    return results


def main():
    os.environ.update(TEMP=r"D:\VulnGym-bv2-runtime\tmp", TMP=r"D:\VulnGym-bv2-runtime\tmp",
        PYTHONIOENCODING="utf-8", GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0")
    io.RUN = RUN
    raw = (RUN / "input-manifest.json").read_bytes()
    assert sha256(raw).hexdigest() == INPUT_SHA
    plan = json.loads(raw)
    start = json.loads((RUN / "run-start.json").read_bytes())
    ended = json.loads((RUN / "run-exit.json").read_bytes())
    assert start["execution_head"] == EXECUTION_HEAD and start["input_manifest_sha256"] == INPUT_SHA
    assert ended["exit_code"] == 0 and ended["credential_use_ended"] is True
    assert ended["error_code"] is None and ended["transport_halt_code"] is None
    assert plan["runtime_tree"] == RUNTIME_TREE and plan["model"]["timeout_seconds"] == 300
    assert plan["sample_group"] == "seen_input_diagnostic_retest_not_new_input_evaluation"
    output = RUN / "output"
    assert {p.name for p in output.iterdir()} == io.OUTPUT_NAMES
    names = sorted(["output/" + n for n in io.OUTPUT_NAMES] + ["input/" + n for n in plan["input_files"]]
        + ["input-manifest.json", "run-start.json", "run-exit.json", "cli-stdout.json", "transport-events.jsonl"])
    before = [io.pin(RUN / n) for n in names]
    baseline = {name: sha256((BASE / name).read_bytes()).hexdigest() for name in names}
    for name, expected in plan["input_files"].items():
        actual = io.pin(RUN / "input" / name)
        assert {k: actual[k] for k in ("bytes", "sha256")} == expected
        assert (RUN / "input" / name).read_bytes() == (BASE / "input" / name).read_bytes()
    _, readback, readback_check = io.twice([sys.executable, "-B", "-c",
        "import json,sys; from vulngym_agent.orchestrator.replay import verify_closed_loop_artifacts; print(json.dumps(verify_closed_loop_artifacts(sys.argv[1]).to_dict(),sort_keys=True,separators=(',',':')))", str(output)])
    digest = readback["dataset_sha256"]
    cli_command = [sys.executable, "-B", "-m", "vulngym_agent.submission_prediction_cli"]
    common = ["--replay-dir", str(output), "--replay-dataset-sha256", digest, "--expected-task-count", "2"]
    _, review, review_check = io.twice(cli_command + ["review", *common])
    handoff_raw, handoff, handoff_check = io.twice(cli_command + ["handoff", *common])
    assert handoff["complete_count"] == review["complete_count"] == 0
    assert handoff["incomplete_count"] == review["incomplete_count"] == 2
    assert handoff["formal_submission_export"] is False
    delivery = RUN / "verification"
    delivery.mkdir(exist_ok=True)
    io.put_or_compare(delivery / "handoff.json", handoff_raw)
    _, verified, verified_check = io.twice(cli_command + ["verify-handoff", *common,
        "--handoff-file", str(delivery / "handoff.json"), "--handoff-sha256", handoff["handoff_sha256"]])
    assert verified["verified"] is True
    events = io.rows(RUN / "transport-events.jsonl")
    calls = [r["payload"]["call"] for r in io.rows(output / "model_calls.jsonl")]
    tools = [r["payload"]["call"] for r in io.rows(output / "tool_calls.jsonl")]
    counts = successful_transport_counts(events, calls, ended)
    assert counts["actual_http_requests"] == 5
    results = defer_results(io.rows(output / "deferred.jsonl"))
    assert [r["stage"] for r in results] == ["semantic_judge", "reflection"]
    cli = json.loads((RUN / "cli-stdout.json").read_bytes())
    assert cli["tasks_run"] == cli["manual_review"] == 2
    assert all(cli[k] == 0 for k in ("failed", "input_failures", "entries_written", "finalized"))
    assert cli["execution_counts"] == {"complete_candidate_tasks": 0, "t1_report_tasks": 0,
        "deferred_tasks": 2, "model_declared_defer_tasks": 2, "model_problem_tasks": 0, "non_success_model_calls": 0}
    assert all((output / n).stat().st_size == 0 for n in (
        "candidates.jsonl", "entries.jsonl", "errors.jsonl", "repair_history.jsonl", "validation.jsonl", "validations.jsonl"))
    assert before == [io.pin(RUN / n) for n in names]
    assert baseline == {name: sha256((BASE / name).read_bytes()).hexdigest() for name in names}
    summary = dict(counts, schema="t2.longwait-diagnostic-receipt.v2", execution_commit=EXECUTION_HEAD,
        runtime_tree=RUNTIME_TREE, input_manifest_sha256=INPUT_SHA, model=plan["model"],
        sample_group=plan["sample_group"], tasks_planned=2, complete_candidates=0, t1_reports=0,
        model_semantic_defer_tasks=1, model_reflection_defer_tasks=1, completed_semantic_evaluations=2,
        candidate_completion_rate={"numerator": 0, "denominator": 2, "value": 0.0},
        semantic_accuracy=None, semantic_improvement_measured=False,
        reason_interpretation="model_self_report_not_independently_verified_cause",
        run_status="processed_two_model_defers_not_quality_passed", cli_exit_code=0, cli_summary=cli,
        maximum_http_requests=6, automatic_retries=0, budget_cny=20, currency_cost_measured=False,
        credential_use_ended=True, provider_revocation_verified=False,
        authorization_record="User explicitly re-supplied prior credential, confirmed validity/platform cap and authorized this separate run; no autonomous reuse.",
        platform_hard_cap="operator_confirmed_not_programmatically_verified",
        run_started_at=start["started_at"], finished_at=ended["finished_at"],
        elapsed_seconds=round((datetime.fromisoformat(ended["finished_at"]) - datetime.fromisoformat(start["started_at"])).total_seconds(), 3),
        controlled_producer_tool_calls=len(tools), tool_status_counts=dict(Counter(c["status"] for c in tools)),
        run_dataset_sha256=digest, handoff_sha256=handoff["handoff_sha256"],
        handoff_file_sha256=sha256(handoff_raw).hexdigest(), handoff_bytes=len(handoff_raw),
        formal_submission_export=False, independent_human_review_completed=False,
        readback=readback_check, review=review_check, handoff_generation=handoff_check,
        handoff_verification=verified_check, runtime_files_unchanged=True,
        runtime_file_count=len(before), baseline_files_unchanged_during_collection=True,
        original_first_new_input_results_not_overwritten=True, results=results)
    artifacts = {"summary.json": io.wire(summary), "runtime_files.json": io.wire({"files": before}),
        "readback.json": io.wire(readback), "review.json": io.wire(review), "handoff.json": handoff_raw,
        "handoff_verification.json": io.wire(verified), "transport_events.jsonl": b"".join(io.wire(e) for e in events)}
    assert all(io.FORBIDDEN.search(data) is None for data in artifacts.values()), "public_marker_check_failed_preserve"
    artifacts["manifest.json"] = io.wire({"schema": "t2.longwait-diagnostic-files.v2", "metadata_only": True,
        "files": {n: {"bytes": len(b), "sha256": sha256(b).hexdigest()} for n, b in artifacts.items()}})
    PUBLIC.mkdir(exist_ok=True)
    assert {p.name for p in PUBLIC.iterdir()} <= set(artifacts)
    for name, data in artifacts.items():
        io.put_or_compare(PUBLIC / name, data)
    print(io.wire({"status": summary["run_status"], "http_requests": counts["actual_http_requests"],
        "provider_reported_usage": counts["provider_reported_usage"], "elapsed_seconds": summary["elapsed_seconds"],
        "complete_candidates": 0, "t1_reports": 0, "defer_stages": [r["stage"] for r in results],
        "public_files": len(artifacts), "public_bytes": sum(len(b) for b in artifacts.values()),
        "public_manifest_sha256": sha256(artifacts["manifest.json"]).hexdigest(),
        "run_dataset_sha256": digest, "four_checks_twice_byte_equal": True,
        "original_and_current_run_preserved": True}).decode(), end="")


if __name__ == "__main__":
    main()
