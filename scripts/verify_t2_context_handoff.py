"""Standalone, read-only diagnostic package checks; integrity is not quality."""
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath

E = "evidence/t2-context-retest-20260909-v3/"
REVIEW = "evidence/t2-context-candidate-review-20260909-v1/review.json"
FACT = {"source_identity", "version_basis", "entry_location", "operation_location"}
SEMANTIC = {"entry_role", "operation_role", "trace", "title_and_project", "classification"}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError("nonfinite_json")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def digest(value):
    return sha256(json.dumps(value, ensure_ascii=False, allow_nan=False,
                             sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_members(members):
    require(1 <= len(members) <= 30 and sum(map(len, members.values())) <= 5 * 1024 * 1024, "size_limit")
    manifest = parse(members["MANIFEST.json"])
    require(manifest["schema"] == "t2.context-diagnostic-handoff.v1"
            and manifest["scope"] == "diagnostic_increment_not_final_delivery", "package_scope_changed")
    require(set(members) == set(manifest["files"]) | {"MANIFEST.json"}, "file_set_mismatch")
    for name, pin in manifest["files"].items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts and ":" not in name
                and "\\" not in name, "invalid_member_path")
        raw = members[name]
        require({"bytes": len(raw), "sha256": sha256(raw).hexdigest()} == pin, "file_digest_mismatch")
    evidence_manifest = parse(members[E + "manifest.json"])
    for name, pin in evidence_manifest["files"].items():
        raw = members[E + name]
        require({"bytes": len(raw), "sha256": sha256(raw).hexdigest()} == pin, "evidence_digest_mismatch")
    s, h, r = [parse(members[name]) for name in (E + "summary.json", E + "handoff.json", REVIEW)]
    require(s["run_status"] == "partial_one_candidate_one_truncated_model_result"
            and type(s["cli_exit_code"]) is int and s["cli_exit_code"] == 1, "production_status_changed")
    require((s["actual_http_requests"], s["complete_candidates"], s["t1_reports"]) == (5, 1, 1), "run_counts_changed")
    require(s["semantic_accuracy"] is None and s["independent_human_review_completed"] is False, "quality_claim_changed")
    require(s["provider_reported_usage"]["total_tokens"] == 71741, "usage_changed")
    require(sha256(members[E + "handoff.json"]).hexdigest() == s["handoff_file_sha256"], "handoff_file_binding")
    require(h["handoff_sha256"] == s["handoff_sha256"]
            == digest({k: v for k, v in h.items() if k != "handoff_sha256"}), "handoff_core_binding")
    require(h["source_replay_dataset_sha256"] == s["run_dataset_sha256"] == r["run_dataset_sha256"], "dataset_binding")
    require(h["formal_submission_export"] is False and h["independent_quality_review_completed"] is False, "handoff_claim_changed")
    require(h["task_count"] == len(h["tasks"]) == 2 and h["complete_count"] == h["incomplete_count"] == 1
            and len(h["entries"]) == len(h["validation"]) == 1, "handoff_counts_changed")
    first, second = h["tasks"]
    require(first["task_id"] == "VG-NEW-20260908-001" and first["complete"] is False
            and first["candidate_sha256"] is None and first["pair_ordinal"] is None
            and first["deferred"][0]["reason_code"] == "model_blocked", "incomplete_task_changed")
    require(second["task_id"] == r["task_id"] == "VG-NEW-20260908-002" and second["complete"] is True
            and second["pair_ordinal"] == 1 and second["verdict"] == "uncertain"
            and all(t["status"] == "manual_review" for t in h["tasks"]), "candidate_task_changed")
    require(type(h["entries"][0]["verify"]) is int and h["entries"][0]["verify"] == 0, "verify_promoted")
    require(digest(h["entries"][0]) == second["candidate_sha256"] == r["candidate_sha256"], "candidate_binding")
    require(digest(h["validation"][0]) == second["validation_sha256"] == r["validation_sha256"], "validation_binding")
    require(r["reviewer"]["kind"] == "ai_assisted_self_review" and r["reviewer"]["independence"] == "self"
            and r["independent_human_review_completed"] is False
            and r["original_candidate_modified"] is False and r["semantic_accuracy"] is None, "review_claim_changed")
    require(set(r["fields"]) == FACT | SEMANTIC, "review_dimensions")
    counts = Counter()
    for name, field in r["fields"].items():
        require(field["level"] == ("fact" if name in FACT else "semantic"), "review_level")
        require(field["status"] in {"supported", "uncertain"} and field["reason"].strip(), "review_incomplete")
        require(field["evidence_refs"] and all(ref.split(":")[0] in r["source_evidence"]
                                                for ref in field["evidence_refs"]), "unresolved_reference")
        require(field["status"] != "uncertain" or field["next_action"].strip(), "missing_action")
        counts[field["status"]] += 1
    require(counts == {"supported": 5, "uncertain": 4}
            and all(counts[k] == n for k, n in r["counts"].items()), "review_counts_changed")
    return {"verified": True, "files": len(members), "source_commit": manifest["source_commit"],
        "production_exit_code": 1, "complete_candidates": 1, "incomplete_tasks": 1,
        "new_model_calls": 0, "scope": "byte_integrity_bindings_and_counts_not_semantic_certification"}


def read_directory(root):
    members = {}
    for path in root.rglob("*"):
        require(not path.is_symlink() and not path.is_junction(), "unexpected_link")
        if path.is_file():
            require(path.stat().st_size <= 5 * 1024 * 1024, "size_limit")
            members[path.relative_to(root).as_posix()] = path.read_bytes()
            require(len(members) <= 30 and sum(map(len, members.values())) <= 5 * 1024 * 1024, "size_limit")
    return members


if __name__ == "__main__":
    try:
        result = validate_members(read_directory(Path(__file__).resolve().parent))
    except (ValueError, OSError, KeyError, TypeError, IndexError, AttributeError):
        raise SystemExit("context_handoff_verification_failed") from None
    print(json.dumps(result, sort_keys=True))
