"""Offline receipt for the frozen stage-budget diagnostic; never calls a provider.

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
from scripts.run_t2_stage_budget_retest_v1 import RUN, BASE, TASKS, RUNTIME_TREE, STAGES, STAGE_LIMITS

PUBLIC = ROOT / "evidence/t2-stage-budget-retest-20260909-v1"
EXECUTION_HEAD = "49959f942185955cac77d218cbb0e628cbfe6731"
INPUT_SHA = "631c14604d29d404c2b8c40b523c41c7c5c7438133bbb62eb77d98ca7d24a537"
CANDIDATE_SHA = "922cb175c2607ba6bd38372bb26eb943d2ec13939667a4b7a5bda0ecafe0c6b3"
VALIDATION_SHA = "db7955888a931a08c1dc94f129e67d05e798a4590c4c6a61563fcb7a56dd9d67"
DEFERRED_SHA = "da910968d9bb07a7109d70de2a0df41a6c83ac945c13cf0644d1826567f37c9c"
BASE_PUBLIC = ROOT / "evidence/t2-context-retest-20260909-v3"
BASE_PUBLIC_SHA = "49761c39287d0956e322637a0af188f031ea10057bbf1f43605785d5908e24b5"


def transport_counts(events, calls, ended):
    """Six complete sends and successful structured results, not quality proof."""
    started = [e for e in events if e["event"] == "started"]
    finished = [e for e in events if e["event"] == "finished"]
    assert ended["transport_halt_code"] is None
    assert type(ended["transport_attempts"]) is int
    assert len(started) == len(finished) == len(calls) == ended["transport_attempts"] == 6
    assert [e["event"] for e in events] == ["started", "finished"] * 6
    expected = [(task, stage) for task in TASKS for stage in STAGES]
    assert [(e["task_id"], e["stage"]) for e in started] == expected
    seen = set()
    for n, (a, b, c) in enumerate(zip(started, finished, calls, strict=True), 1):
        assert type(a["attempt"]) is type(b["attempt"]) is int and a["attempt"] == b["attempt"] == n
        assert all(a[k] == b[k] for k in ("task_id", "stage", "model_call_id", "request_body_sha256",
                                         "request_bytes", "timeout_seconds", "configured_max_tokens"))
        assert a["timeout_seconds"] == 300 and b["status"] == "http_200"
        assert type(a["configured_max_tokens"]) is int and a["configured_max_tokens"] == STAGE_LIMITS[a["stage"]]
        assert b["response_model_matches"] is True and b["finish_reason"] == "stop"
        identity = (a["task_id"], a["stage"], a["model_call_id"])
        assert identity not in seen and identity == (c["task_id"], c["stage"], c["model_call_id"])
        seen.add(identity)
        assert c["status"] == "success" and c["error_code"] is None
        usage = b["usage"]
        assert all(type(usage.get(k)) is int and 0 <= usage[k] <= 1_000_000_000 for k in USAGE)
        assert usage["prompt_tokens"] + usage["completion_tokens"] == usage["total_tokens"]
        assert usage["prompt_cache_hit_tokens"] + usage["prompt_cache_miss_tokens"] == usage["prompt_tokens"]
        assert usage["completion_tokens"] <= a["configured_max_tokens"]
        assert all(type(b[k]) is int and b[k] >= 0 for k in
                   ("answer_characters", "provider_reasoning_characters", "response_bytes"))
    attempted_cap = sum(e["configured_max_tokens"] for e in started)
    assert type(ended["configured_completion_tokens_attempted"]) is int
    assert attempted_cap == ended["configured_completion_tokens_attempted"] == 45056
    return {
        "actual_http_requests": 6, "http_successes": 6, "http_failures": 0,
        "model_invocations": 6, "locally_blocked_before_http": 0,
        "structured_results_accepted": 6, "structured_results_rejected_after_http": 0,
        "model_stage_counts": dict(sorted(Counter(c["stage"] for c in calls).items())),
        "model_error_counts": {}, "finish_reason_counts": {"stop": 6},
        "configured_completion_tokens_attempted": attempted_cap,
        "provider_reported_usage": {k: sum(e["usage"][k] for e in finished) for k in USAGE},
        "usage_is_complete_for_this_run": True,
        "http_elapsed_seconds_sum": round(sum(e["elapsed_seconds"] for e in finished), 3),
    }


def reconcile(cli, ended, counts, candidates, deferred, validations):
    """Bind the actual one-candidate/one-reflection-defer result, without promotion."""
    assert type(ended["exit_code"]) is type(cli["exit_code"]) is int
    assert ended["exit_code"] == cli["exit_code"] == 0
    assert ended["credential_use_ended"] is True and ended["error_code"] is None
    assert cli["status"] == "ok" and cli["execution_status"] == "processed_not_quality_verified"
    assert type(cli["tasks_run"]) is type(cli["manual_review"]) is int
    assert cli["tasks_run"] == cli["manual_review"] == 2
    assert all(type(cli[k]) is int and cli[k] == 0 for k in
               ("failed", "input_failures", "entries_written", "finalized"))
    expected_counts = {"complete_candidate_tasks": 1, "t1_report_tasks": 1,
        "deferred_tasks": 1, "model_declared_defer_tasks": 1, "model_problem_tasks": 0,
        "non_success_model_calls": 0}
    assert all(type(v) is int for v in cli["execution_counts"].values())
    assert cli["execution_counts"] == expected_counts
    assert cli["model_error_counts"] == counts["model_error_counts"] == {}
    assert counts["actual_http_requests"] == counts["structured_results_accepted"] == 6
    assert len(candidates) == len(validations) == len(deferred) == 1
    assert candidates[0]["task_id"] == validations[0]["task_id"] == TASKS[1]
    assert deferred[0]["task_id"] == TASKS[0]
    candidate = candidates[0]["payload"]
    assert candidate["candidate_sha256"] == CANDIDATE_SHA
    assert type(candidate["candidate"]["verify"]) is int and candidate["candidate"]["verify"] == 0
    validation = validations[0]["payload"]
    assert validation["report_sha256"] == VALIDATION_SHA
    report = validation["report"]
    assert report["verdict"] == "uncertain"
    assert Counter(v["status"] for v in report["fields"].values()) == {"correct": 9, "uncertain": 7}
    d = deferred[0]["payload"]["deferred"]
    assert deferred[0]["payload"]["deferred_sha256"] == DEFERRED_SHA
    assert d["stage"] == "reflection" and d["reason_code"] == "model_deferred"
    records = [s.removeprefix("model_defer_details:") for s in d["missing_information"]
               if s.startswith("model_defer_details:")]
    assert len(records) == 1
    details = json.loads(records[0])
    assert details["assessment_origin"] == "model_self_report_not_independently_verified"
    assert details["kind"] == "model_reflection_defer_v1"
    assert details["reason_code"] == "ambiguous_candidate_roles"
    assert details["missing_fields"] == ["critical_operation", "relationship"]
    assert len(details["evidence_refs"]) == len(set(details["evidence_refs"])) == 3
    assert isinstance(details["explanation"], str) and 1 <= len(details["explanation"]) <= 400
    assert "\n" not in details["explanation"]
    return [
        {"task_id": TASKS[0], "workflow_status": "manual_review", "complete_candidate": False,
         "t1_report": False, "stage": d["stage"], "reason_code": d["reason_code"],
         "model_error": None, "semantic_abstention": True,
         "deferred_sha256": DEFERRED_SHA, "model_self_report": details,
         "next_action": "Review the selected critical-operation role and relationship using the cited evidence. This model self-report is not an independent correctness verdict."},
        {"task_id": TASKS[1], "workflow_status": "manual_review", "complete_candidate": True,
         "t1_report": True, "candidate_sha256": CANDIDATE_SHA, "verify": 0,
         "validation_sha256": VALIDATION_SHA, "t1_verdict": "uncertain",
         "t1_field_counts": {"correct": 9, "uncertain": 7},
         "next_action": "Version association, selected roles and trace remain pending; no automatic or human certification is claimed."},
    ]


def check_baseline():
    ledger_raw = (BASE_PUBLIC / "runtime_files.json").read_bytes()
    manifest_raw = (BASE_PUBLIC / "manifest.json").read_bytes()
    assert sha256(manifest_raw).hexdigest() == BASE_PUBLIC_SHA
    manifest = json.loads(manifest_raw)
    for name, expected in manifest["files"].items():
        data = (BASE_PUBLIC / name).read_bytes()
        assert len(data) == expected["bytes"] and sha256(data).hexdigest() == expected["sha256"]
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
    assert plan["model"]["token_budget_profile"] == "t2-balanced-v1"
    assert plan["stage_max_tokens"] == STAGE_LIMITS and plan["maximum_configured_completion_tokens"] == 45056
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
    old_candidates = io.rows(BASE / "output/candidates.jsonl")
    assert len(old_candidates) == 1 and old_candidates[0]["task_id"] == TASKS[1]
    old_payload, new_payload = old_candidates[0]["payload"], candidates[0]["payload"]
    old_candidate, new_candidate = old_payload["candidate"], new_payload["candidate"]
    assert set(old_candidate) == set(new_candidate)
    changed_fields = sorted(k for k in old_candidate if io.wire(old_candidate[k]) != io.wire(new_candidate[k]))
    assert changed_fields == ["vuln_category_l2"]
    comparison = {"baseline_candidate_sha256": old_payload["candidate_sha256"],
        "current_candidate_sha256": CANDIDATE_SHA, "changed_top_level_fields": changed_fields,
        "changed_values": {k: {"baseline": old_candidate[k], "current": new_candidate[k]} for k in changed_fields},
        "classification_equivalence_assessed": False,
        "t1_report_sha256_unchanged": io.rows(BASE / "output/validations.jsonl")[0]["payload"]["report_sha256"] == VALIDATION_SHA,
        "new_independent_semantic_review_performed": False}
    assert comparison["t1_report_sha256_unchanged"] is True
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
    summary = dict(counts, schema="t2.stage-budget-diagnostic-receipt.v1", execution_commit=EXECUTION_HEAD,
        runtime_tree=RUNTIME_TREE, input_manifest_sha256=INPUT_SHA, model=plan["model"],
        sample_group=plan["sample_group"], tasks_planned=2, complete_candidates=1, t1_reports=1,
        candidate_completion_rate={"numerator": 1, "denominator": 2, "value": 0.5},
        semantic_accuracy=None, semantic_improvement_measured=False,
        run_status="processed_one_candidate_one_reflection_defer", cli_exit_code=0, cli_summary=cli,
        candidate_comparison_to_baseline=comparison,
        budget_change_causally_proven=False, candidate_completion_improved=False,
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
    artifacts["manifest.json"] = io.wire({"schema": "t2.stage-budget-diagnostic-files.v1", "metadata_only": False,
        "contains_candidate_and_validation": True,
        "files": {n: {"bytes": len(b), "sha256": sha256(b).hexdigest()} for n, b in artifacts.items()}})
    PUBLIC.mkdir(exist_ok=True)
    assert {p.name for p in PUBLIC.iterdir()} <= set(artifacts)
    for name, data in artifacts.items():
        io.put_or_compare(PUBLIC / name, data)
    print(io.wire({"status": summary["run_status"], "production_exit_code": 0,
        "http_requests": counts["actual_http_requests"], "provider_reported_usage": counts["provider_reported_usage"],
        "complete_candidates": 1, "t1_reports": 1, "finalized": 0,
        "public_files": len(artifacts), "public_bytes": sum(len(b) for b in artifacts.values()),
        "public_manifest_sha256": sha256(artifacts["manifest.json"]).hexdigest(),
        "run_dataset_sha256": digest, "four_checks_twice_byte_equal": True,
        "original_and_current_run_preserved": True}).decode(), end="")


if __name__ == "__main__":
    main()
