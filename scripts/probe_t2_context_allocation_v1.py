"""Offline context capture using only the recorded plan choice, not real inference."""
from collections import Counter
from collections.abc import Mapping
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import subprocess
import types
from contextlib import nullcontext
from unittest.mock import patch

W = Path(__file__).resolve().parents[1]
RUN = Path(r"D:\VulnGym-bv2-runtime\t2-new-input-live-20260908-v3")
DEST = Path(r"D:\VulnGym-bv2-runtime\t2-context-allocation-20260908-v1")
sys.path.insert(0, str(W))
from vulngym_agent.agents.model_runtime import ModelBlocked
from vulngym_agent.agents.real_t2_producer import LocalStructuredT2Producer
from vulngym_agent.closed_loop_cli import iter_task_jsonl, load_trusted_repo_map
from vulngym_agent.orchestrator import Limits
from vulngym_agent.t2_production_cli import LocalProductionTaskRunner


def plain(v):
    if isinstance(v, Mapping):
        return {k: plain(x) for k, x in v.items()}
    if isinstance(v, (tuple, list)):
        return [plain(x) for x in v]
    return v


def wire(v):
    return (json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def main(label):
    assert label in ("before", "after")
    os.environ.update(TEMP=r"D:\VulnGym-bv2-runtime\tmp", TMP=r"D:\VulnGym-bv2-runtime\tmp",
                      GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0")
    manifest = json.loads((W / "evidence/t2-new-input-live-20260908-v1/runtime_files.json").read_bytes())
    for f in manifest["files"]:
        b = (RUN / f["path"]).read_bytes()
        assert len(b) == f["bytes"] and sha256(b).hexdigest() == f["sha256"]
    plan = {"action": "analyze", "critical_mode": "guard"}
    plan_hash = sha256(wire(plan).rstrip(b"\n")).hexdigest()
    recorded = [json.loads(l)["payload"]["call"] for l in (RUN / "output/model_calls.jsonl").read_bytes().splitlines()]
    assert all(c["response_sha256"] == plan_hash for c in recorded if c["stage"] == "plan")
    original = {}
    for l in (RUN / "output/evidence.jsonl").read_bytes().splitlines():
        r = json.loads(l)
        e = r["payload"]["evidence"]
        if "SEMANTIC-SOURCE" in e["evidence_id"]:
            original.setdefault(r["task_id"], []).append(json.loads(e["snippet"]))
    class Probe:
        backend_id = "offline:recorded-plan-context-capture-v1"
        model_id = "offline.no-provider"
        def __init__(self):
            self.semantic = None
        def invoke(self, request):
            if request.stage == "plan":
                return dict(plan)
            assert request.stage == "semantic_judge"
            self.semantic = plain(request.payload)
            raise ModelBlocked("offline_context_capture_no_provider")
    repos = load_trusted_repo_map(RUN / "input/repos.json")
    records = list(iter_task_jsonl(RUN / "input/tasks.jsonl"))
    results, details = [], []
    for row in records:
        probe = Probe()
        runner = LocalProductionTaskRunner(package_root=RUN / "input/package", repo_map=repos, backend=probe,
            limits=Limits(max_llm_calls=3, max_tool_calls=80, max_repair_iterations=0))
        outcome = runner.run(row.task)
        runner.finalize_batch()
        assert probe.semantic is not None and outcome.entry is None and outcome.report is None
        ctx = probe.semantic["semantic_context"]
        if label == "before":
            assert ctx["source_contexts"] == original[row.task.task_id], "offline_baseline_does_not_match_real_delivered_source"
        ids = {c["candidate_id"]: c for c in [*probe.semantic["critical_candidates"], *probe.semantic["entry_candidates"]]}
        coverage = []
        for c in ctx["candidate_context_coverage"]:
            candidate = ids[c["candidate_id"]]
            coverage.append({**c, "file": candidate["location"]["file"], "line": candidate["location"]["line"],
                             "symbol": candidate.get("symbol")})
        results.append({"task_id": row.task.task_id, "critical_candidates": len(probe.semantic["critical_candidates"]),
            "entry_candidates": len(probe.semantic["entry_candidates"]), "source_chars": ctx["source_chars"],
            "source_files_read": ctx["source_files_read"], "source_blocks": len(ctx["source_contexts"]),
            "coverage_counts": dict(Counter(c["status"] for c in coverage)), "coverage": coverage,
            "source_contexts_sha256": sha256(wire(ctx["source_contexts"])).hexdigest(),
            "baseline_matches_actual_delivered_source": label == "before", "real_provider_calls": 0})
        details.append({"task_id": row.task.task_id, "semantic_payload": probe.semantic})
    DEST.mkdir(exist_ok=True)
    for name, value in [(label + "-summary.json", results), (label + "-context.json", details)]:
        data = wire(value)
        path = DEST / name
        if path.exists():
            assert path.read_bytes() == data, "previous_probe_bytes_differ_preserve"
        else:
            with path.open("xb") as stream:
                stream.write(data)
    print(json.dumps({"label": label, "cases": [{k: v for k, v in r.items() if k != "coverage"} for r in results]}, ensure_ascii=False))


def baseline_context(label):
    if label != "before":
        return nullcontext()
    # Load our committed producer as an in-memory reference, never checkout a
    # worktree or execute target-source files. Only context allocation is patched.
    baseline = types.ModuleType("vulngym_agent.agents._allocation_reference")
    baseline.__package__ = "vulngym_agent.agents"
    sys.modules[baseline.__name__] = baseline
    code = subprocess.check_output(["git", "show",
        "713519a718d6d2a738bf73e5179e3766af5be1fd:vulngym_agent/agents/real_t2_producer.py"], cwd=W)
    exec(compile(code, "<committed-context-reference>", "exec"), baseline.__dict__)
    return patch.object(LocalStructuredT2Producer, "_semantic_context",
                        baseline.LocalStructuredT2Producer._semantic_context)


if __name__ == "__main__":
    with baseline_context(sys.argv[1]):
        main(sys.argv[1])
