"""Offline v3 delivery integrity checks, not an independent quality assessment.

No provider, target repository, installation or network access is required.
The externally published ZIP digest is the trust anchor; this is not a signature.
"""
from collections import Counter
from hashlib import sha1, sha256
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

E = "evidence/latest/"
REVIEW = "evidence/current-review.json"
EXECUTION = "49959f942185955cac77d218cbb0e628cbfe6731"
RUNTIME = "8945df9255bbc3f330a48f85e0afc2dd8f7a15bf"
EVIDENCE_MANIFEST = "67edd751edfdc32fa9acaa5f455703470f46c5940f2c6c15c314d06106fc8ec9"
VIDEO = "9cc577297bc790438e2f3bdd206aaf70a80aae3aa7e6cec21e3787e723858261"
MAX_BYTES = 64 * 1024 * 1024
MAX_FILES = 500
DIMENSIONS = {"source_identity", "version_basis", "entry_location", "operation_location",
              "entry_role", "operation_role", "trace", "title_and_project", "classification"}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value

    def nonfinite(_):
        raise ValueError("nonfinite_json")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def wire(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(value):
    return sha256(wire(value)[:-1]).hexdigest()


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def safe_name(name):
    p = PurePosixPath(name)
    require(isinstance(name, str) and name and not p.is_absolute()
            and p.as_posix() == name and not any(c in name for c in "\\:\x00")
            and all(part not in {".", ".."} and not part.endswith((" ", "."))
                    for part in p.parts), "invalid_member_path")
    require(not any(part.casefold() in {"private", "gold", "selection_lock", ".git", ".venv"}
                    for part in p.parts), "prohibited_member")
    require(not any(re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)
                    for part in p.parts), "invalid_member_path")


def runtime_tree(members):
    """Recompute Git tree identity from all exported runtime bytes (no Git needed)."""
    root = {}
    for name, raw in members.items():
        prefix = "source/vulngym_agent/"
        if not name.startswith(prefix):
            continue
        parts = name[len(prefix):].split("/")
        parent = root
        for part in parts[:-1]:
            parent = parent.setdefault(part, {})
        parent[parts[-1]] = raw

    def obj(kind, raw):
        return sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).digest()

    def tree(node):
        raw = bytearray()
        for name, value in sorted(node.items(), key=lambda x: x[0] + ("/" if isinstance(x[1], dict) else "")):
            directory = isinstance(value, dict)
            raw.extend(("40000" if directory else "100644").encode() + b" " + name.encode() + b"\0")
            raw.extend(tree(value) if directory else obj("blob", value))
        return obj("tree", bytes(raw))

    return tree(root).hex()


def validate_members(members):
    require(1 <= len(members) <= MAX_FILES and sum(map(len, members.values())) <= MAX_BYTES, "size_limit")
    for name in members:
        safe_name(name)
    require(len({name.casefold() for name in members}) == len(members), "case_collision")
    m = parse(members["MANIFEST.json"])
    require(m["schema"] == "t2.submission-candidate.v3"
            and m["scope"] == "engineering_delivery_with_unresolved_quality", "package_scope_changed")
    require(m["new_model_calls"] == 0 and m["complete_T2_quality_acceptance"] is False
            and m["execution_commit"] == EXECUTION, "quality_claim_changed")
    require(re.fullmatch("[0-9a-f]{40}", m["source_commit"]) is not None, "invalid_source_commit")
    require(set(members) == set(m["files"]) | {"MANIFEST.json"}, "file_set_mismatch")
    for name, expected in m["files"].items():
        require(pin(members[name]) == expected, "file_digest_mismatch")
    source_pins = {n[len("source/"):]: pin(raw) for n, raw in members.items() if n.startswith("source/")}
    require(source_pins == m["source_hashes"] and len(source_pins) == m["source_files"], "source_inventory_mismatch")
    require(runtime_tree(members) == m["runtime_tree"] == RUNTIME, "runtime_tree_mismatch")
    require(sha256(members[E + "manifest.json"]).hexdigest() == EVIDENCE_MANIFEST, "historical_evidence_changed")
    em = parse(members[E + "manifest.json"])
    require({n[len(E):] for n in members if n.startswith(E)} == set(em["files"]) | {"manifest.json"}, "evidence_file_set")
    for name, expected in em["files"].items():
        require(pin(members[E + name]) == expected, "evidence_digest_mismatch")
    s, h, r = (parse(members[n]) for n in (E + "summary.json", E + "handoff.json", REVIEW))
    require(s["cli_exit_code"] == 0 and s["run_status"] == "processed_one_candidate_one_reflection_defer"
            and (s["actual_http_requests"], s["complete_candidates"], s["t1_reports"]) == (6, 1, 1)
            and s["provider_reported_usage"]["total_tokens"] == 89577, "run_counts_changed")
    require(s["semantic_accuracy"] is None and s["independent_human_review_completed"] is False,
            "quality_claim_changed")
    require(h["handoff_sha256"] == s["handoff_sha256"] == digest({k: v for k, v in h.items() if k != "handoff_sha256"}), "handoff_binding")
    require(pin(members[E + "handoff.json"])["sha256"] == s["handoff_file_sha256"], "handoff_binding")
    require(h["task_count"] == len(h["tasks"]) == 2 and h["complete_count"] == h["incomplete_count"] == 1
            and len(h["entries"]) == len(h["validation"]) == 1, "handoff_counts_changed")
    first, second = h["tasks"]
    require(first["complete"] is False and first["candidate_sha256"] is None
            and first["deferred"][0]["reason_code"] == "model_deferred"
            and first["deferred"][0]["stage"] == "reflection", "defer_promoted")
    require(second["complete"] is True and second["verdict"] == "uncertain"
            and all(t["status"] == "manual_review" for t in h["tasks"]), "status_promoted")
    require(type(h["entries"][0]["verify"]) is int and h["entries"][0]["verify"] == 0, "verify_promoted")
    require(digest(h["entries"][0]) == second["candidate_sha256"] == r["candidate_review"]["candidate_sha256"]
            and digest(h["validation"][0]) == second["validation_sha256"] == r["candidate_review"]["validation_sha256"], "review_binding")
    require(first["deferred"][0]["deferred_sha256"] == r["defer_review"]["deferred_sha256"], "review_binding")
    for field in ("entries", "validation"):
        require(members["data/latest/" + field + ".jsonl"] == b"".join(wire(v) for v in h[field]), "projection_changed")
    require(members["data/latest/deferred.jsonl"] == b"".join(wire({"task_id": t["task_id"], **d})
            for t in h["tasks"] for d in t["deferred"]), "projection_changed")
    require(r["reviewer"]["kind"] == "ai_assisted_self_review" and r["reviewer"]["independence"] == "self"
            and r["independent_human_review_completed"] is False and r["original_outputs_modified"] is False
            and r["semantic_accuracy"] is None, "review_claim_changed")
    fields = r["candidate_review"]["fields"]
    require(set(fields) == DIMENSIONS, "review_dimensions")
    counts = Counter(v["status"] for v in fields.values())
    require(counts == {"supported": 4, "reasonable_alternative": 1, "uncertain": 4}
            and dict(counts) == r["candidate_review"]["counts"], "review_counts_changed")
    for field in fields.values():
        require(field["reason"].strip() and field["evidence_refs"], "review_incomplete")
        require(all(ref.split(":")[0] in r["source_evidence"] for ref in field["evidence_refs"]), "unresolved_reference")
        require(field["status"] == "supported" or field["next_action"].strip(), "missing_action")
    require(r["defer_review"]["disposition"] == "retain_defer_correct_source_order_explanation",
            "defer_review_changed")
    require(sha256(members["media/archival/T2-existing-results-demo.mp4"]).hexdigest() == VIDEO
            and m["video_scope"] == "archival_existing_results_not_current_live_run", "video_scope_changed")
    pdf = parse(members["output/pdf/provenance.json"])
    require(pdf["pages"] == 3 and pdf["visual_check"] == "passed_three_pages"
            and pin(members["output/pdf/T2-design.pdf"]) == pdf["pdf"]
            and sha256(members["source/docs/submission/T2_DELIVERY_BRIEF.md"]).hexdigest() == pdf["source_sha256"],
            "pdf_binding_changed")
    for name, raw in members.items():
        if name.endswith((".mp4", ".pdf")):
            continue
        require(not re.search(rb"sk-[A-Za-z0-9]{20,}", raw), "credential_shape")
        require(not re.search(rb"[A-Z]:[\\/]Users[\\/]", raw, re.I), "personal_path")
        if name.startswith(("evidence/", "data/")):
            require(not re.search(rb"(?<![A-Za-z0-9_])[A-Z]:[\\/]", raw, re.I), "evidence_local_path")
    return {"verified": True, "files": len(members), "source_commit": m["source_commit"],
            "runtime_tree": RUNTIME, "execution_commit": EXECUTION, "production_exit_code": 0,
            "complete_candidates": 1, "deferred_tasks": 1, "t1_reports": 1, "new_model_calls": 0,
            "scope": "integrity_counts_and_bindings_not_semantic_certification"}


def read_directory(root):
    require(not root.is_symlink() and not root.is_junction(), "unexpected_link")
    members, total = {}, 0
    for p in root.rglob("*"):
        require(not p.is_symlink() and not p.is_junction(), "unexpected_link")
        if p.is_dir():
            continue
        require(p.is_file(), "unexpected_file_type")
        name = p.relative_to(root).as_posix()
        safe_name(name)
        total += p.stat().st_size
        require(total <= MAX_BYTES and len(members) < MAX_FILES, "size_limit")
        members[name] = p.read_bytes()
    return members


def read_archive(path):
    with zipfile.ZipFile(path) as z:
        items = z.infolist()
        require(len(items) <= MAX_FILES and sum(v.file_size for v in items) <= MAX_BYTES, "size_limit")
        require(len({v.filename.casefold() for v in items}) == len(items), "duplicate_zip_member")
        for item in items:
            safe_name(item.filename)
            require(not item.is_dir() and not stat.S_ISLNK(item.external_attr >> 16), "unexpected_link")
        return {v.filename: z.read(v) for v in items}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--zip", type=Path)
    args = parser.parse_args()
    try:
        result = validate_members(read_archive(args.zip) if args.zip else read_directory(args.root))
    except (ValueError, OSError, KeyError, TypeError, IndexError, AttributeError, zipfile.BadZipFile):
        print(json.dumps({"verified": False, "code": "delivery_verification_failed"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
