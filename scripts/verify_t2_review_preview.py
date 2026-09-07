"""Verify this offline review preview's bytes/counts, not source or semantic truth.

Standard library only. This file is copied as verify_bundle.py into the preview.
No network, model credentials, target execution or output-file writes.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath

DEV = "evidence/t2-quality-self-review-dev12-20260908/"
COHORT = "evidence/t2-quality-review-dev12-20260907/cohort.json"
CURRENT = "evidence/t2-current-candidate-self-review-20260908/review.json"
FACT = {"source_identity", "version_basis", "entry_location", "operation_location"}
SEMANTIC = {"entry_role", "operation_role", "trace", "title_and_project", "classification"}
STATUSES = {"supported", "reasonable_alternative", "contradicted", "uncertain", "not_reviewed"}
MAX_BYTES = 10 * 1024 * 1024


def require(condition, code):
    if not condition:
        raise ValueError(code)


def parse(raw):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            require(key not in obj, "duplicate_json_key")
            obj[key] = value
        return obj
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)


def validate_members(members):
    require(1 <= len(members) <= 100 and sum(map(len, members.values())) <= MAX_BYTES, "preview_size_invalid")
    manifest = parse(members["MANIFEST.json"])
    expected = manifest["files"]
    require(set(members) == set(expected) | {"MANIFEST.json"}, "file_set_mismatch")
    for name, pin in expected.items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts and "\\" not in name and ":" not in name, "member_path_invalid")
        raw = members[name]
        require(len(raw) == pin["bytes"] and sha256(raw).hexdigest() == pin["sha256"], "file_digest_mismatch")
    require(sha256(members[COHORT]).hexdigest() == "2258428587893c05de812e6e1e6a1b1788edb9639c370e7b307069d581e1d180", "cohort_changed")
    cohort = parse(members[COHORT])
    rows = [parse(line) for line in members[DEV + "reviews.jsonl"].splitlines()]
    cases = {c["case_id"]: c for c in cohort["cases"]}
    require(len(rows) == len(cases) == 12 and {r["case_id"] for r in rows} == set(cases), "review_case_set_invalid")
    evidence = parse(members[DEV + "evidence_index.json"])["evidence"]
    metrics = parse(members[DEV + "metrics.json"])
    counts = {"fact": Counter(), "semantic": Counter()}
    for row in rows:
        case = cases[row["case_id"]]
        require(row["task_id"] == case["task_id"] and row["entry_sha256"] == case["entry_sha256"], "candidate_binding_mismatch")
        require(row["reviewer"]["kind"] == "ai_assisted_self_review" and row["reviewer"]["independence"] == "self", "reviewer_claim_changed")
        require(set(row["fields"]) == FACT | SEMANTIC, "review_dimensions_invalid")
        for name, field in row["fields"].items():
            require(field["status"] in STATUSES - {"not_reviewed"} and field["rationale"].strip(), "review_incomplete")
            require(field["evidence_refs"] and all(ref in evidence for ref in field["evidence_refs"]), "unresolved_evidence_reference")
            require(field["status"] != "uncertain" or field["next_action"].strip(), "unresolved_without_action")
            counts["fact" if name in FACT else "semantic"][field["status"]] += 1
    require(metrics["review_file_sha256"] == sha256(members[DEV + "reviews.jsonl"]).hexdigest(), "metrics_binding_mismatch")
    for group, count in counts.items():
        require(all(metrics["quality_groups"][group]["field_counts"][s] == count[s] for s in STATUSES), "metrics_count_mismatch")
    handoff = parse(members["data/handoff.json"])
    require(handoff["formal_submission_export"] is False, "handoff_claim_changed")
    require(len(handoff["tasks"]) == 2 and len(handoff["entries"]) == len(handoff["validation"]) == 1, "handoff_counts_changed")
    require(all(type(e["verify"]) is int and e["verify"] == 0 for e in handoff["entries"]), "machine_verify_changed")
    require(sum(t["complete"] is True for t in handoff["tasks"]) == 1, "task_coverage_changed")
    current = parse(members[CURRENT])
    require(set(current["fields"]) == FACT | SEMANTIC and current["human_review_completed"] is False, "current_review_claim_changed")
    require(current["reviewer"]["kind"] == "ai_assisted_self_review" and current["reviewer"]["independence"] == "self", "reviewer_claim_changed")
    for field in current["fields"].values():
        require(field["status"] in STATUSES - {"not_reviewed"} and field["rationale"].strip(), "review_incomplete")
        require(field["evidence_refs"] and all(ref in current["evidence"] for ref in field["evidence_refs"]), "unresolved_evidence_reference")
        require(field["status"] != "uncertain" or field["next_action"].strip(), "unresolved_without_action")
    task = next(t for t in handoff["tasks"] if t["task_id"] == current["task_id"])
    require(task["candidate_sha256"] == current["entry_sha256"] and task["validation_sha256"] == current["validation_sha256"], "current_binding_mismatch")
    require(current["source_handoff_file_sha256"] == sha256(members["data/handoff.json"]).hexdigest(), "current_handoff_binding_mismatch")
    return {"verified": True, "files": len(members), "historical_review_cases": 12, "historical_review_dimensions": 108,
            "current_candidate_dimensions": 9, "tasks": 2, "complete_candidates": 1,
            "scope": "bundle_bytes_and_internal_counts_not_semantic_truth_or_source_replay_verification"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args(argv)
    try:
        root = args.bundle_dir
        require(root.is_dir() and not root.is_symlink(), "preview_root_invalid")
        members = {}
        for path in root.rglob("*"):
            require(not path.is_symlink(), "preview_symlink_not_supported")
            if path.is_file():
                require(len(members) < 100 and path.stat().st_size <= MAX_BYTES, "preview_size_invalid")
                members[path.relative_to(root).as_posix()] = path.read_bytes()
                require(sum(map(len, members.values())) <= MAX_BYTES, "preview_size_invalid")
        result = validate_members(members)
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
        print(json.dumps({"verified": False, "code": str(exc) if isinstance(exc, ValueError) else "invalid_preview"}))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
