"""Compare context delivery on the two already-seen inputs, without inference.

Only the recorded routing choice is replayed. Stop before semantic inference;
do not write production artifacts, load credentials, or contact a provider.
The old implementation must reproduce the actually delivered source windows.
"""
from collections import Counter
from contextlib import nullcontext
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.probe_t2_context_allocation_v1 import plain, wire
from scripts.prepare_t2_quality_review import read_bytes
from scripts.collect_t2_new_input_batch_v1 import FORBIDDEN, put_or_compare
from vulngym_agent.agents import deepseek_backend as adapter
from vulngym_agent.agents.model_runtime import ModelBlocked, structured_json_sha256
from vulngym_agent.agents.real_t2_producer import LocalStructuredT2Producer
from vulngym_agent.closed_loop_cli import iter_task_jsonl, load_trusted_repo_map
from vulngym_agent.orchestrator import Limits
from vulngym_agent.t2_production_cli import LocalProductionTaskRunner

RUN = Path(r"D:\VulnGym-bv2-runtime\t2-context-retest-20260909-v2-longwait")
BASE_COMMIT = "fb99d7ecf61418725ceb5528bdedf6daada16774"
INPUT_SHA = "ca37cb9bb7661c5ad000e381665bd374fb9c6a6ed3b6f81a4265d2152be93533"
DEST = ROOT / "evidence/t2-context-delivery-20260909-v1/summary.json"
PLAN = {"action": "analyze", "critical_mode": "guard"}
CODE_FILES = (
    "vulngym_agent/agents/t2_semantic_context.py",
    "vulngym_agent/agents/real_t2_producer.py",
    "vulngym_agent/agents/deepseek_backend.py",
    "scripts/probe_t2_context_delivery_v2.py",
    "scripts/probe_t2_context_allocation_v1.py",
)


def require(condition, code):
    if not condition:
        raise ValueError(code)


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=True, timeout=30).stdout


def pinned_run():
    require(sha256(read_bytes(RUN / "input-manifest.json")).hexdigest() == INPUT_SHA, "input_manifest_changed")
    manifest = json.loads(read_bytes(ROOT / "evidence/t2-context-retest-20260909-v2/runtime_files.json"))
    pins = []
    for item in manifest["files"]:
        path = Path(item["path"])
        require(not path.is_absolute() and ".." not in path.parts, "invalid_run_pin_path")
        raw = read_bytes(RUN / path)
        pin = {"path": item["path"], "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
        require(pin == item, "historical_run_changed")
        pins.append(pin)
    require(len(pins) == 23, "unexpected_run_file_count")
    return pins


def load_baseline_method():
    # Load only our own committed implementation, never target project code.
    modules = []
    for name in ("t2_semantic_context", "real_t2_producer"):
        module = types.ModuleType("vulngym_agent.agents._delivery_baseline_" + name)
        module.__package__ = "vulngym_agent.agents"
        sys.modules[module.__name__] = module
        code = git("show", BASE_COMMIT + ":vulngym_agent/agents/" + name + ".py")
        exec(compile(code, "<committed-delivery-baseline>", "exec"), module.__dict__)
        modules.append(module)
    modules[1].semantic_context_tools = modules[0]
    # The baseline method classifies runtime choice instances. Use current
    # dataclasses, whose issuance and contract have not changed in this patch.
    from vulngym_agent.agents import real_t2_producer as producer
    modules[1]._CriticalChoice = producer._CriticalChoice
    modules[1]._EntryChoice = producer._EntryChoice
    return modules[1].LocalStructuredT2Producer._semantic_context


class CaptureOnlyBackend:
    backend_id = "offline.context-delivery-probe-v2"
    model_id = "offline.no-provider"

    def __init__(self):
        self.requests = []
        self.semantic = None

    def invoke(self, request):
        self.requests.append(request.stage)
        if self.requests == ["plan"]:
            return dict(PLAN)
        require(self.requests == ["plan", "semantic_judge"], "probe_unexpected_stage")
        self.semantic = plain(request.payload)
        raise ModelBlocked("offline_context_capture_no_provider")


def metrics(context):
    blocks = context["source_contexts"]
    lines = [(b["file"], n) for b in blocks if b["anchor_line_complete"]
             for n in range(b["line_start"], b["line_end"] + 1)]
    return {"source_chars": context["source_chars"], "source_files_read": context["source_files_read"],
        "source_blocks": len(blocks), "unique_complete_source_lines": len(set(lines)),
        "repeated_complete_source_lines": len(lines) - len(set(lines)),
        "coverage_counts": dict(Counter(r["status"] for r in context["candidate_context_coverage"])),
        "source_contexts_sha256": sha256(wire(blocks)).hexdigest(),
        "ranges": [{k: b[k] for k in ("file", "line_start", "line_end", "candidate_ids", "complete_function")}
                   for b in blocks]}


def capture(task, repos, baseline=None):
    backend = CaptureOnlyBackend()
    runner = LocalProductionTaskRunner(package_root=RUN / "input/package", repo_map=repos, backend=backend,
        limits=Limits(max_llm_calls=2, max_tool_calls=80, max_repair_iterations=0))
    with (patch.object(LocalStructuredT2Producer, "_semantic_context", baseline) if baseline else nullcontext()):
        outcome = runner.run(task)
    runner.finalize_batch()
    require(backend.requests == ["plan", "semantic_judge"] and backend.semantic is not None, "probe_did_not_reach_context")
    require(not outcome.production_outcomes and not outcome.validation_outcomes
            and outcome.entry is None and outcome.report is None, "probe_must_not_produce_results")
    require(outcome.deferred_outcome.reason_code != "model_deferred", "probe_is_not_a_model_prediction")
    return backend.semantic


def main():
    os.environ.update(TEMP=r"D:\VulnGym-bv2-runtime\tmp", TMP=r"D:\VulnGym-bv2-runtime\tmp",
        GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", PYTHONDONTWRITEBYTECODE="1")
    require(git("branch", "--show-current").decode().strip() == "codex/b-v2-source-discovery", "wrong_branch")
    before = pinned_run()
    plan = json.loads(read_bytes(RUN / "input-manifest.json"))
    records = list(iter_task_jsonl(RUN / "input/tasks.jsonl"))
    require(len(records) == 2 and all(r.task for r in records), "unexpected_inputs")
    calls = [json.loads(r)["payload"]["call"] for r in read_bytes(RUN / "output/model_calls.jsonl").splitlines()]
    routing = [c for c in calls if c["stage"] == "plan"]
    require(len(routing) == 2 and all(c["status"] == "success" and c["response_sha256"] ==
            structured_json_sha256(PLAN) for c in routing), "recorded_plan_changed")
    original = {}
    for line in read_bytes(RUN / "output/evidence.jsonl").splitlines():
        row = json.loads(line)
        evidence = row["payload"]["evidence"]
        if "SEMANTIC-SOURCE" in evidence["evidence_id"]:
            original.setdefault(row["task_id"], []).append(json.loads(evidence["snippet"]))
    repos = load_trusted_repo_map(RUN / "input/repos.json")
    require(set(repos) == {c["repo_url"] for c in plan["cases"]}, "repository_set_changed")
    # Fixed-object reads only; no repository enumeration, target execution or fetching.
    for case in plan["cases"]:
        for name, versions in case["source_files"].items():
            raw = git("--git-dir=" + str(repos[case["repo_url"]]), "show", case["working_pre_fix_snapshot"] + ":" + name)
            require({"bytes": len(raw), "sha256": sha256(raw).hexdigest()} == versions["before"], "fixed_blob_changed")
    baseline = load_baseline_method()
    results = []
    with patch.object(adapter, "_post_official", side_effect=AssertionError("provider_forbidden")) as post:
        for record in records:
            old = capture(record.task, repos, baseline)
            new = capture(record.task, repos)
            old_ctx, new_ctx = old["semantic_context"], new["semantic_context"]
            require(old_ctx["source_contexts"] == original[record.task.task_id], "baseline_not_actual_delivered_windows")
            for field in ("critical_candidates", "entry_candidates"):
                require(old[field] == new[field], "candidate_catalog_changed")
            old_ids = {r["candidate_id"] for r in old_ctx["candidate_context_coverage"] if r["status"] == "included"}
            new_ids = {r["candidate_id"] for r in new_ctx["candidate_context_coverage"] if r["status"] == "included"}
            current = metrics(new_ctx)
            require(current["repeated_complete_source_lines"] == 0 and current["source_chars"] <= 16000
                    and current["source_blocks"] <= 12 and current["source_files_read"] <= 8, "context_budget_or_overlap")
            require(all(len(b["text"]) <= 3000 and b["call_relationship_verified"] is False for b in new_ctx["source_contexts"]), "window_claim_or_budget")
            results.append({"task_id": record.task.task_id, "before": metrics(old_ctx), "after": current,
                "newly_covered_candidate_ids": sorted(new_ids - old_ids),
                "no_longer_covered_candidate_ids": sorted(old_ids - new_ids),
                "candidate_catalog_unchanged": True, "baseline_matches_actual_delivery": True})
        post.assert_not_called()
    require(before == pinned_run(), "historical_run_changed_during_probe")
    data = wire({"schema": "t2.offline-context-delivery.v2", "baseline_implementation_commit": BASE_COMMIT,
        "input_manifest_sha256": INPUT_SHA, "sample_group": "seen_inputs_offline_geometry_not_model_evaluation",
        "real_provider_calls": 0, "new_candidate_count": 0, "new_t1_reports": 0,
        "semantic_accuracy": None, "semantic_improvement_measured": False,
        "historical_run_files_unchanged": len(before), "prompt": adapter.DeepSeekSettings().profile(),
        "code_sha256": {name: sha256(read_bytes(ROOT / name)).hexdigest() for name in CODE_FILES},
        "results": results})
    require(FORBIDDEN.search(data) is None, "public_marker_check_failed")
    DEST.parent.mkdir(exist_ok=True)
    put_or_compare(DEST, data)
    print(wire({"status": "offline_context_check_passed", "provider_calls": 0,
        "summary_sha256": sha256(data).hexdigest(), "summary_bytes": len(data),
        "cases": [{"task_id": r["task_id"], "before": {k:v for k,v in r["before"].items() if k != "ranges"},
                   "after": {k:v for k,v in r["after"].items() if k != "ranges"},
                   "newly_covered": r["newly_covered_candidate_ids"], "no_longer_covered": r["no_longer_covered_candidate_ids"]}
                  for r in results]}).decode(), end="")


if __name__ == "__main__":
    main()
