"""Read-only verification and new receipts for the frozen two-input live run.

Never calls a provider, reads a key, restarts production, or rewrites run files.
Generated handoff and receipt files are new outputs or must already match bytes.
"""
from collections import Counter
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys

WORKSPACE = Path(__file__).resolve().parents[1]
RUN = Path(r"D:\VulnGym-bv2-runtime\t2-new-input-live-20260908-v3")
PUBLIC = WORKSPACE / "evidence/t2-new-input-live-20260908-v1"
EXECUTION_HEAD = "713519a718d6d2a738bf73e5179e3766af5be1fd"
INPUT_SHA256 = "1f85f4cad6ee17aa722bec985938ba76cea93bc6c0fe7bec52f050cca20c6a3f"
OUTPUT_NAMES = {
    "candidates.jsonl", "deferred.jsonl", "entries.jsonl", "errors.jsonl", "evidence.jsonl",
    "model_calls.jsonl", "repair_history.jsonl", "run_manifest.jsonl", "states.jsonl",
    "tool_calls.jsonl", "validation.jsonl", "validations.jsonl",
}
FORBIDDEN = re.compile(rb"sk-[A-Za-z0-9_-]{16,}|(?<![A-Za-z0-9_])[A-Za-z]:[\\/]|selection_lock|source-map|test_gold|benchmark[s]?[/\\]+private", re.I)


def wire(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def rows(path):
    return [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]


def pin(path):
    assert path.is_file() and not path.is_symlink()
    data = path.read_bytes()
    return {"path": path.relative_to(RUN).as_posix(), "bytes": len(data), "sha256": sha256(data).hexdigest()}


def put_or_compare(path, data):
    if path.exists():
        assert path.is_file() and not path.is_symlink() and path.read_bytes() == data, "existing_receipt_differs_preserve"
    else:
        with path.open("xb") as stream:
            stream.write(data)


def twice(args):
    results = [subprocess.run(args, cwd=WORKSPACE, capture_output=True, timeout=60) for _ in range(2)]
    assert all(r.returncode == 0 and not r.stderr for r in results), "readback_failed_preserve"
    assert results[0].stdout == results[1].stdout, "readback_bytes_differ_preserve"
    raw = results[0].stdout
    return raw, json.loads(raw), {"processes": 2, "exit_codes": [0, 0], "byte_identical": True,
                                "stdout_bytes": len(raw), "stdout_sha256": sha256(raw).hexdigest()}


def main():
    os.environ.update(TEMP=r"D:\VulnGym-bv2-runtime\tmp", TMP=r"D:\VulnGym-bv2-runtime\tmp",
                      PYTHONIOENCODING="utf-8", GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0")
    inputs_raw = (RUN / "input-manifest.json").read_bytes()
    assert sha256(inputs_raw).hexdigest() == INPUT_SHA256
    inputs = json.loads(inputs_raw)
    start = json.loads((RUN / "run-start.json").read_bytes())
    ended = json.loads((RUN / "run-exit.json").read_bytes())
    assert start["execution_head"] == EXECUTION_HEAD and start["manifest_sha256"] == INPUT_SHA256
    assert ended["exit_code"] == 0 and ended["credential_use_ended"] is True
    assert ended["error_code"] is None and ended["transport_halt_code"] is None
    output = RUN / "output"
    assert {p.name for p in output.iterdir()} == OUTPUT_NAMES
    names = sorted(["output/" + n for n in OUTPUT_NAMES] + ["input/" + n for n in inputs["input_files"]]
                   + ["input-manifest.json", "run-start.json", "run-exit.json", "cli-stdout.json", "transport-events.jsonl"])
    before = [pin(RUN / n) for n in names]
    for name, expected in inputs["input_files"].items():
        actual = pin(RUN / "input" / name)
        assert {k: actual[k] for k in ("bytes", "sha256")} == expected
    verify = [sys.executable, "-B", "-c",
              "import json,sys; from vulngym_agent.orchestrator.replay import verify_closed_loop_artifacts; print(json.dumps(verify_closed_loop_artifacts(sys.argv[1]).to_dict(),sort_keys=True,separators=(',',':')))", str(output)]
    _, readback, readback_check = twice(verify)
    digest = readback["dataset_sha256"]
    command = [sys.executable, "-B", "-m", "vulngym_agent.submission_prediction_cli"]
    common = ["--replay-dir", str(output), "--replay-dataset-sha256", digest, "--expected-task-count", "2"]
    _, review, review_check = twice(command + ["review", *common])
    handoff_raw, handoff, handoff_check = twice(command + ["handoff", *common])
    assert review["complete_count"] == handoff["complete_count"] == 0
    assert review["incomplete_count"] == handoff["incomplete_count"] == 2
    assert handoff["formal_submission_export"] is False
    delivery = RUN / "verification"
    delivery.mkdir(exist_ok=True)
    put_or_compare(delivery / "handoff.json", handoff_raw)
    _, verified, verification_check = twice(command + ["verify-handoff", *common,
        "--handoff-file", str(delivery / "handoff.json"), "--handoff-sha256", handoff["handoff_sha256"]])
    assert verified["verified"] is True
    events = rows(RUN / "transport-events.jsonl")
    started = [e for e in events if e["event"] == "started"]
    finished = [e for e in events if e["event"] == "finished"]
    calls = [r["payload"]["call"] for r in rows(output / "model_calls.jsonl")]
    tools = [r["payload"]["call"] for r in rows(output / "tool_calls.jsonl")]
    assert len(events) == 2 * len(started) and len(started) == len(finished) == len(calls) == ended["transport_attempts"] == 4
    assert [e["event"] for e in events] == ["started", "finished"] * 4
    for index, (a, b, c) in enumerate(zip(started, finished, calls, strict=True), 1):
        assert a["attempt"] == b["attempt"] == index
        assert (a["task_id"], a["stage"], a["request_body_sha256"]) == (b["task_id"], b["stage"], b["request_body_sha256"])
        assert (b["task_id"], b["stage"]) == (c["task_id"], c["stage"])
        assert b["status"] == "http_200" and b["reported_model_matches"] is True and c["status"] == "success"
    assert max(Counter(e["task_id"] for e in started).values()) <= 3
    assert all((output / n).stat().st_size == 0 for n in ["candidates.jsonl", "entries.jsonl", "errors.jsonl", "repair_history.jsonl", "validation.jsonl", "validations.jsonl"])
    deferred = rows(output / "deferred.jsonl")
    assert len(deferred) == 2
    results = []
    for row in deferred:
        value = row["payload"]["deferred"]
        detail_text = [s.removeprefix("model_defer_details:") for s in value["missing_information"] if s.startswith("model_defer_details:")]
        assert len(detail_text) == 1
        details = json.loads(detail_text[0])
        assert details["assessment_origin"] == "model_self_report_not_independently_verified"
        results.append({"task_id": row["task_id"], "report_id": value["report_id"],
            "status": "manual_review", "complete_candidate": False, "t1_report": False,
            "stage": value["stage"], "reason_code": value["reason_code"],
            "deferred_sha256": row["payload"]["deferred_sha256"], "model_self_report": details})
    cli = json.loads((RUN / "cli-stdout.json").read_bytes())
    assert cli["tasks_run"] == cli["manual_review"] == 2
    assert all(cli[k] == 0 for k in ["failed", "input_failures", "entries_written", "finalized"])
    assert before == [pin(RUN / n) for n in names]
    totals = {k: sum(e["usage"].get(k, 0) for e in finished) for k in
              ["prompt_tokens", "completion_tokens", "total_tokens", "prompt_cache_hit_tokens", "prompt_cache_miss_tokens"]}
    summary = {"schema": "t2.new-input-live-receipt.v1", "execution_commit": EXECUTION_HEAD,
        "input_manifest_sha256": INPUT_SHA256, "model": inputs["model"], "runner_sha256": start["runner_sha256"],
        "sample_group": "new_input_not_model_training_blind", "task_count": 2, "repositories": 2,
        "actual_http_requests": 4, "http_successes": 4, "maximum_http_requests": 6, "automatic_retries": 0,
        "model_stage_counts": dict(Counter(c["stage"] for c in calls)), "provider_reported_usage": totals,
        "currency_cost_measured": False, "budget_cny": 20, "platform_hard_limit": inputs["platform_hard_limit"],
        "run_started_at": start["started_at"], "finished_at": ended["finished_at"],
        "elapsed_seconds": round((datetime.fromisoformat(ended["finished_at"]) - datetime.fromisoformat(start["started_at"])).total_seconds(), 3),
        "http_elapsed_seconds_sum": round(sum(e["elapsed_seconds"] for e in finished), 3),
        "controlled_producer_tool_calls": len(tools), "tool_status_counts": dict(Counter(c["status"] for c in tools)),
        "complete_candidates": 0, "t1_reports": 0, "deferred_tasks": 2, "finalized": 0,
        "candidate_completion_rate": {"numerator": 0, "denominator": 2, "value": 0.0},
        "semantic_accuracy": None, "semantic_accuracy_reason": "No complete candidate; abstention alone does not establish accuracy.",
        "cli_exit_code": 0, "cli_summary": cli, "run_dataset_sha256": digest,
        "readback": readback_check, "review": review_check, "handoff_generation": handoff_check,
        "handoff_verification": verification_check, "handoff_sha256": handoff["handoff_sha256"],
        "handoff_file_sha256": sha256(handoff_raw).hexdigest(), "handoff_bytes": len(handoff_raw),
        "formal_submission_export": False, "runtime_file_count": len(before),
        "runtime_total_bytes": sum(p["bytes"] for p in before), "runtime_files_unchanged": True,
        "credential_use_ended": True, "provider_revocation_verified": False,
        "independent_human_review_completed": False, "results": results}
    artifacts = {"summary.json": wire(summary), "runtime_files.json": wire({"files": before}),
                 "readback.json": wire(readback), "review.json": wire(review),
                 "handoff_verification.json": wire(verified),
                 "transport_events.jsonl": b"".join(wire(e) for e in events)}
    assert all(FORBIDDEN.search(raw) is None for raw in artifacts.values()), "public_marker_check_failed"
    artifacts["manifest.json"] = wire({"schema": "t2.new-input-live-manifest.v1", "metadata_only": True,
        "files": {n: {"bytes": len(b), "sha256": sha256(b).hexdigest()} for n, b in artifacts.items()}})
    PUBLIC.mkdir(exist_ok=True)
    assert {p.name for p in PUBLIC.iterdir()} <= set(artifacts)
    for name, raw in artifacts.items():
        put_or_compare(PUBLIC / name, raw)
    print(wire({k: summary[k] for k in ["actual_http_requests", "provider_reported_usage", "elapsed_seconds",
          "controlled_producer_tool_calls", "complete_candidates", "t1_reports", "deferred_tasks", "run_dataset_sha256", "handoff_bytes"]}
          | {"readback_review_handoff_twice_verified": True, "public_files": len(artifacts),
             "public_bytes": sum(len(b) for b in artifacts.values()), "public_manifest_sha256": sha256(artifacts["manifest.json"]).hexdigest()}).decode(), end="")


if __name__ == "__main__":
    main()
