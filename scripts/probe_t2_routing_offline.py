"""Probe local T2 routing without any model service or candidate publication.

The diagnostic script selects the first available routing mode and deliberately
defers at semantic_judge. This is a test double, never semantic-quality evidence.
Only answer-free task inputs, a trusted repo map and cleared public packages are
accepted. Existing run directories and production outputs are never modified.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
from itertools import islice
import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vulngym_agent.closed_loop_cli import iter_task_jsonl, load_trusted_repo_map
from vulngym_agent.orchestrator import Limits
from vulngym_agent.t2_production_cli import LocalProductionTaskRunner


class _DiagnosticBackend:
    backend_id = "diagnostic.evidence-first-stop-at-semantic"
    model_id = "offline-script-not-a-model"

    def __init__(self):
        self.requests = []

    def invoke(self, request):
        self.requests.append(request)
        if request.stage == "plan":
            return {"action": "analyze", "critical_mode": request.payload["allowed_critical_modes"][0]}
        if request.stage == "semantic_judge":
            result = {"action": "defer", "critical_candidate_id": None, "entry_candidate_id": None,
                    "project": None, "vuln_title": None, "vuln_category_l1": None, "vuln_category_l2": None}
            if request.payload.get("contract_version") == 2:
                result["defer_details"] = {"reason_code": "insufficient_context", "missing_fields": ["relationship"],
                    "evidence_refs": [request.payload["defer_contract"]["allowed_evidence_refs"][0]],
                    "explanation": "Diagnostic script deliberately declines semantic evaluation; this is not a model quality finding."}
            return result
        raise ValueError("diagnostic_never_emits_reflects_or_repairs")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tasks", required=True, type=Path)
    parser.add_argument("--repo-map", required=True, type=Path)
    parser.add_argument("--package-root", required=True, type=Path)
    parser.add_argument("--max-records", type=int, default=2)
    parser.add_argument("--candidate-index", action="store_true",
                        help="Include issued locations, code digests and context coverage, never source text.")
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.max_records <= 100:
            raise ValueError("invalid_record_limit")
        records = tuple(islice(iter_task_jsonl(args.tasks, max_task_bytes=1024 * 1024),
                               args.max_records + 1))
        if not records or len(records) > args.max_records or any(r.task is None for r in records):
            raise ValueError("input_preflight_failed")
        backend = _DiagnosticBackend()
        runner = LocalProductionTaskRunner(
            package_root=args.package_root, repo_map=load_trusted_repo_map(args.repo_map),
            backend=backend, limits=Limits(max_llm_calls=3, max_tool_calls=80, max_repair_iterations=0),
        )
        rows = []
        for record in records:
            outcome = runner.run(record.task)
            requests = [r for r in backend.requests if r.task_id == record.task.task_id]
            plan = next((r for r in requests if r.stage == "plan"), None)
            semantic = next((r for r in requests if r.stage == "semantic_judge"), None)
            deferred = outcome.deferred_outcome
            if outcome.production_outcomes or outcome.validation_outcomes or deferred is None:
                raise ValueError("diagnostic_must_stop_before_production")
            row = {
                "task_id": record.task.task_id, "stage": deferred.stage, "reason_code": deferred.reason_code,
                "offered_modes": list(plan.payload["allowed_critical_modes"]) if plan else [],
                "candidate_counts": {item["mode"]: item["candidate_count"] for item in
                                     plan.payload["planning_evidence"]["mode_inventory"]} if plan else {},
                "semantic_stage_reached": semantic is not None,
                "entry_candidates": len(semantic.payload["entry_candidates"]) if semantic else None,
                "semantic_context": ({
                    "advisory_chars": len(semantic.payload["semantic_context"]["advisory"]["text"]),
                    "advisory_truncated": semantic.payload["semantic_context"]["advisory"]["truncated"],
                    "diffs": len(semantic.payload["semantic_context"]["diffs"]),
                    "source_blocks": len(semantic.payload["semantic_context"]["source_contexts"]),
                    "source_chars": semantic.payload["semantic_context"]["source_chars"],
                    "source_code_lines": [block["line_end"] - block["line_start"] + 1 for block in semantic.payload["semantic_context"]["source_contexts"]],
                    "complete_python_functions": sum(block["complete_function"] for block in semantic.payload["semantic_context"]["source_contexts"]),
                    "omitted_candidates": sum(row["status"] != "included" for row in semantic.payload["semantic_context"]["candidate_context_coverage"]),
                    "specific_defer_contract": True,
                } if semantic and "semantic_context" in semantic.payload else None),
                "complete_entries": 0, "t1_calls": 0,
            }
            if args.candidate_index:
                context = semantic.payload.get("semantic_context", {}) if semantic else {}
                coverage = {item["candidate_id"]: item["status"] for item in context.get("candidate_context_coverage", ())}
                indexed = []
                if semantic:
                    for role, key in (("critical", "critical_candidates"), ("entry", "entry_candidates")):
                        for candidate in semantic.payload[key]:
                            location = candidate["location"]
                            item = {"role": role, "candidate_id": candidate["candidate_id"],
                                    "file": location["file"], "line": location["line"],
                                    "code_sha256": sha256(location["code"].encode("utf-8")).hexdigest(),
                                    "context_status": coverage.get(candidate["candidate_id"], "not_provided"),
                                    "semantic_role_verified": False}
                            if role == "entry":
                                item.update(kind=candidate["kind"], symbol=candidate["symbol"],
                                            explicit_external_binding=candidate["explicit_external_binding"])
                            else:
                                item.update(mode=candidate["mode"], source_candidate_id=candidate["source_candidate_id"])
                            indexed.append(item)
                row["candidate_index"] = indexed
                row["candidate_policy"] = plan.payload["planning_evidence"].get("candidate_policy") if plan else None
                row["mode_is_unverified_hypothesis"] = bool(plan and plan.payload["planning_evidence"].get("mode_is_unverified_hypothesis"))
            rows.append(row)
            backend.requests.clear()
        runner.finalize_batch()
        result = {"schema_version": 1, "status": "diagnostic_complete", "network_calls": 0,
                  "backend": backend.backend_id, "model": backend.model_id,
                  "producer_sha256": sha256((REPO_ROOT / "vulngym_agent/agents/real_t2_producer.py").read_bytes()).hexdigest(),
                  "results": rows}
    except Exception:
        # No report, local path, source code, exception detail or credential echo.
        print('{"status":"invalid","error_code":"offline_probe_input_or_execution_error","network_calls":0}')
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
