"""Offline receipt for the frozen context retest, including transport failures.

Never starts production or retries a request. Existing run files are read only;
new receipt files are created exclusively or must already match exact bytes.
"""
from collections import Counter
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W))
from scripts import collect_t2_new_input_batch_v1 as io

RUN = Path(r"D:\VulnGym-bv2-runtime\t2-context-retest-20260909-v1")
OLD = Path(r"D:\VulnGym-bv2-runtime\t2-new-input-live-20260908-v3")
PUBLIC = W / "evidence/t2-context-retest-20260909-v1"
HEAD = "4be0ac88af8325be12e06e00746572989a1fa4d3"
INPUT_SHA = "7332b4ef71d6c5a96f5f0252d626f0c623a05d106515a5d3333d6e0757f1b54f"
TASKS = ("VG-NEW-20260908-001", "VG-NEW-20260908-002")


def transport_counts(events, calls, ended):
    """Count actual sends separately from calls blocked by the local halt latch."""
    started = [e for e in events if e["event"] == "started"]
    finished = [e for e in events if e["event"] == "finished"]
    assert len(started) == len(finished) == ended["transport_attempts"] <= 6
    assert [e["event"] for e in events] == ["started", "finished"] * len(started)
    assert all(n <= 3 for n in Counter(e["task_id"] for e in started).values())
    sent, seen = set(), set()
    for n, (a, b) in enumerate(zip(started, finished, strict=True), 1):
        assert a["attempt"] == b["attempt"] == n
        assert all(a[k] == b[k] for k in ("task_id", "stage", "request_body_sha256"))
        identity = (a["task_id"], a["stage"])
        assert identity not in sent and a["task_id"] in TASKS
        sent.add(identity)
        match = [c for c in calls if (c["task_id"], c["stage"]) == identity]
        assert len(match) == 1
        if b["status"] == "http_200":
            assert match[0]["status"] == "success" and b["reported_model_matches"] is True
        else:
            assert b["status"] == "blocked" and match[0]["status"] == "blocked"
            assert match[0]["error_code"] == b["error_code"] == ended["transport_halt_code"]
            assert n == len(started), "request_after_terminal_transport_failure"
    blocked_locally = 0
    for c in calls:
        identity = (c["task_id"], c["stage"])
        assert identity not in seen and c["task_id"] in TASKS
        seen.add(identity)
        if identity not in sent:
            assert ended["transport_halt_code"] is not None
            assert c["status"] == "blocked" and c["error_code"] == ended["transport_halt_code"]
            blocked_locally += 1
    successful = [e for e in finished if e["status"] == "http_200"]
    usage_names = ("prompt_tokens", "completion_tokens", "total_tokens",
                   "prompt_cache_hit_tokens", "prompt_cache_miss_tokens")
    return {
        "actual_http_requests": len(started), "http_successes": len(successful),
        "http_failures": len(finished) - len(successful), "model_invocations": len(calls),
        "locally_blocked_invocations_not_http_requests": blocked_locally,
        "model_stage_counts": dict(Counter(c["stage"] for c in calls)),
        "known_provider_usage": {k: sum(e.get("usage", {}).get(k, 0) for e in successful) for k in usage_names},
        "usage_is_complete": len(successful) == len(finished),
        "timed_out_request_usage_and_billing": "unknown" if ended["transport_halt_code"] == "deepseek_timeout" else "not_applicable",
    }


def main():
    os.environ.update(TEMP=r"D:\VulnGym-bv2-runtime\tmp", TMP=r"D:\VulnGym-bv2-runtime\tmp",
                      PYTHONIOENCODING="utf-8", GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0")
    io.RUN = RUN
    raw = (RUN / "input-manifest.json").read_bytes()
    assert sha256(raw).hexdigest() == INPUT_SHA
    manifest = json.loads(raw)
    start = json.loads((RUN / "run-start.json").read_bytes())
    ended = json.loads((RUN / "run-exit.json").read_bytes())
    assert start["execution_head"] == HEAD and start["manifest_sha256"] == INPUT_SHA
    assert ended["exit_code"] == 0 and ended["credential_use_ended"] is True
    assert ended["error_code"] is None and ended["transport_halt_code"] == "deepseek_timeout"
    output = RUN / "output"
    assert {p.name for p in output.iterdir()} == io.OUTPUT_NAMES
    assert manifest["sample_group"] == "seen_input_diagnostic_retest_not_new_input_evaluation"

    def baseline_unchanged():
        for expected in manifest["baseline_runtime_file_pins"]:
            data = (OLD / expected["path"]).read_bytes()
            assert len(data) == expected["bytes"] and sha256(data).hexdigest() == expected["sha256"]
    baseline_unchanged()
    names = sorted(["output/" + n for n in io.OUTPUT_NAMES] + ["input/" + n for n in manifest["input_files"]]
                   + ["input-manifest.json", "run-start.json", "run-exit.json", "cli-stdout.json", "transport-events.jsonl"])
    before = [io.pin(RUN / n) for n in names]
    for name, expected in manifest["input_files"].items():
        actual = io.pin(RUN / "input" / name)
        assert {k: actual[k] for k in ("bytes", "sha256")} == expected
        assert (RUN / "input" / name).read_bytes() == (OLD / "input" / name).read_bytes()
    _, readback, readback_check = io.twice([sys.executable, "-B", "-c",
        "import json,sys; from vulngym_agent.orchestrator.replay import verify_closed_loop_artifacts; print(json.dumps(verify_closed_loop_artifacts(sys.argv[1]).to_dict(),sort_keys=True,separators=(',',':')))", str(output)])
    digest = readback["dataset_sha256"]
    command = [sys.executable, "-B", "-m", "vulngym_agent.submission_prediction_cli"]
    common = ["--replay-dir", str(output), "--replay-dataset-sha256", digest, "--expected-task-count", "2"]
    _, review, review_check = io.twice(command + ["review", *common])
    handoff_raw, handoff, handoff_check = io.twice(command + ["handoff", *common])
    assert review["complete_count"] == handoff["complete_count"] == 0
    assert review["incomplete_count"] == handoff["incomplete_count"] == 2
    assert handoff["formal_submission_export"] is False
    delivery = RUN / "verification"
    delivery.mkdir(exist_ok=True)
    io.put_or_compare(delivery / "handoff.json", handoff_raw)
    _, verified, verification_check = io.twice(command + ["verify-handoff", *common,
        "--handoff-file", str(delivery / "handoff.json"), "--handoff-sha256", handoff["handoff_sha256"]])
    assert verified["verified"] is True
    events = io.rows(RUN / "transport-events.jsonl")
    calls = [r["payload"]["call"] for r in io.rows(output / "model_calls.jsonl")]
    tools = [r["payload"]["call"] for r in io.rows(output / "tool_calls.jsonl")]
    counts = transport_counts(events, calls, ended)
    assert counts["actual_http_requests"] == 2 and counts["http_successes"] == 1
    assert counts["locally_blocked_invocations_not_http_requests"] == 1
    assert all((output / n).stat().st_size == 0 for n in
               ["candidates.jsonl", "entries.jsonl", "errors.jsonl", "repair_history.jsonl", "validation.jsonl", "validations.jsonl"])
    results = []
    deferred = io.rows(output / "deferred.jsonl")
    assert len(deferred) == 2 and tuple(r["task_id"] for r in deferred) == TASKS
    for row in deferred:
        value = row["payload"]["deferred"]
        assert value["reason_code"] == "model_blocked"
        results.append({"task_id": row["task_id"], "report_id": value["report_id"],
            "stage": value["stage"], "workflow_status": "manual_review", "reason_code": value["reason_code"],
            "deferred_sha256": row["payload"]["deferred_sha256"],
            "missing_information": value["missing_information"], "complete_candidate": False, "t1_report": False,
            "execution_cause": "provider_request_timeout" if row["task_id"] == TASKS[0] else "local_halt_after_previous_timeout",
            "http_requests": sum(e["event"] == "started" and e["task_id"] == row["task_id"] for e in events),
            "semantic_judgment_received": False})
    cli = json.loads((RUN / "cli-stdout.json").read_bytes())
    assert cli["tasks_run"] == cli["manual_review"] == 2
    assert all(cli[k] == 0 for k in ("failed", "input_failures", "entries_written", "finalized"))
    baseline_unchanged()
    assert before == [io.pin(RUN / n) for n in names]
    summary = dict(counts, schema="t2.context-retest-receipt.v1", execution_commit=HEAD,
        runtime_tree=manifest["runtime_tree"], input_manifest_sha256=INPUT_SHA, model=manifest["model"],
        sample_group=manifest["sample_group"], tasks_planned=2, complete_candidates=0, t1_reports=0,
        workflow_deferred_tasks=2, model_semantic_abstentions=0, completed_semantic_evaluations=0,
        semantic_accuracy=None, semantic_improvement_measured=False, finalized=0,
        run_status="diagnostic_inconclusive_transport_timeout", transport_halt_code=ended["transport_halt_code"],
        cli_exit_code=ended["exit_code"], cli_summary=cli, automatic_retries=0, maximum_http_requests=6,
        budget_cny=20, platform_hard_limit="new_key_user_confirmed_before_run_not_programmatically_verified",
        confirmation_record="User confirmed setup; operator passed --confirm-platform-cap. Frozen input/start text retained unchanged.",
        currency_cost_measured=False, credential_use_ended=True, provider_revocation_verified=False,
        run_started_at=start["started_at"], finished_at=ended["finished_at"],
        elapsed_seconds=round((datetime.fromisoformat(ended["finished_at"]) - datetime.fromisoformat(start["started_at"])).total_seconds(), 3),
        controlled_producer_tool_calls=len(tools), tool_status_counts=dict(Counter(c["status"] for c in tools)),
        run_dataset_sha256=digest, handoff_sha256=handoff["handoff_sha256"],
        handoff_file_sha256=sha256(handoff_raw).hexdigest(), handoff_bytes=len(handoff_raw), formal_submission_export=False,
        readback=readback_check, review=review_check, handoff_generation=handoff_check,
        handoff_verification=verification_check, runtime_files_unchanged=True, runtime_file_count=len(before),
        runtime_total_bytes=sum(p["bytes"] for p in before), baseline_files_unchanged=True,
        baseline_file_count=len(manifest["baseline_runtime_file_pins"]), independent_human_review_completed=False,
        results=results)
    artifacts = {"summary.json": io.wire(summary), "runtime_files.json": io.wire({"files": before}),
        "readback.json": io.wire(readback), "review.json": io.wire(review), "handoff.json": handoff_raw,
        "handoff_verification.json": io.wire(verified),
        "transport_events.jsonl": b"".join(io.wire(e) for e in events)}
    assert all(io.FORBIDDEN.search(raw) is None for raw in artifacts.values()), "public_marker_check_failed"
    artifacts["manifest.json"] = io.wire({"schema": "t2.context-retest-files.v1", "metadata_only": True,
        "files": {n: {"bytes": len(b), "sha256": sha256(b).hexdigest()} for n, b in artifacts.items()}})
    PUBLIC.mkdir(exist_ok=True)
    assert {p.name for p in PUBLIC.iterdir()} <= set(artifacts)
    for name, data in artifacts.items():
        io.put_or_compare(PUBLIC / name, data)
    print(io.wire({k: summary[k] for k in ("run_status", "actual_http_requests", "http_successes",
        "known_provider_usage", "usage_is_complete", "elapsed_seconds", "controlled_producer_tool_calls",
        "run_dataset_sha256", "handoff_bytes")}
        | {"public_files": len(artifacts), "public_bytes": sum(map(len, artifacts.values())),
           "public_manifest_sha256": sha256(artifacts["manifest.json"]).hexdigest(),
           "original_and_current_run_files_unchanged": True, "readback_checks_twice_byte_equal": True}).decode(), end="")


if __name__ == "__main__":
    main()
