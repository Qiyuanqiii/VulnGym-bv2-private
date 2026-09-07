"""Triage pinned submitted annotations, not target vulnerabilities or semantic truth.

Reads only a cleared three-file submission and a caller-supplied trusted repo map.
Only incorrect entry snippets trigger fixed-commit, exact-path source checks.
No model, network, target execution, historical writes, or verdict promotion.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulngym_agent.closed_loop_cli import load_trusted_repo_map
from vulngym_agent.source.entry_search import EntryPointSearcher
from vulngym_agent.submission_prediction import read_submission_predictions
from vulngym_agent.tools.git import GitRepository
from vulngym_agent.validators.location_validator import LocationValidator


ACTIONS = {
    "checker_semantic_capability_gap": "Compare this field with cleared advisory/repository evidence; record support, contradiction or alternatives. No existing semantic verdict is implied.",
    "trace_completeness_unverified": "Check whether an empty trace omits an evidenced connection; provide supported links or explicitly retain the unresolved completeness limitation.",
    "role_semantics_unverified": "Review the candidate role and connection in context; a matching source location alone cannot resolve this field.",
    "reported_incorrect_fact": "Inspect the reported contradiction against the pinned source; retain the original and record any correction separately.",
    "unclassified_uncertain": "Inspect the original field report and supporting evidence; do not assume missing input or unsupported checking without evidence.",
}


def classify_field(name, field, entry):
    """Recognize explicit report limitations; unknown wording remains unclassified."""
    if field.status == "incorrect":
        return "reported_incorrect_fact"
    if field.status != "uncertain":
        return None
    if (name in {"project", "vuln_title", "vuln_category_l1", "vuln_category_l2"}
            and "确定性事实门禁不能判断" in field.evidence):
        return "checker_semantic_capability_gap"
    if name == "trace" and not entry.get("trace") and "trace 是 Schema 合法的空数组" in field.evidence:
        return "trace_completeness_unverified"
    if (name in {"entry_point", "critical_operation"}
            and "File/line/code facts are verified" in field.evidence
            and "semantics were not evaluated" in field.evidence):
        return "role_semantics_unverified"
    return "unclassified_uncertain"


def check_entry_excerpt(entry, repo_path):
    """Compare old/new text facts only. No execution and no semantic role decision."""
    location = entry["entry_point"]
    if type(location["line"]) is not int:
        return {"classification": "not_assessed_line_range", "semantic_role_verified": False}
    repository = GitRepository(repo_path)
    commit, path, code = entry["commit"], location["file"], location["code"]
    source = repository.read_file(commit, path)
    lines = source.decode("utf-8-sig", errors="strict").splitlines()
    anchor = location["line"]
    validator = LocationValidator(repository, line_tolerance=0)
    original = validator.validate_mapping(commit, location)
    result = EntryPointSearcher(repository, whole_line_snippets=True).search(
        commit, paths=[path], critical_paths=[path],
    )
    matching = [candidate for candidate in result.candidates if candidate.line == anchor]
    prefix_matches = 1 <= anchor <= len(lines) and "\n".join(lines[anchor - 1:]).startswith(code)
    last_index = anchor + len(code.splitlines()) - 2
    partial_last_line = (bool(code.splitlines()) and 0 <= last_index < len(lines)
                         and code.splitlines()[-1] != lines[last_index])
    proof = {
        "classification": "unresolved_location_mismatch",
        "original_code_chars": len(code), "original_code_sha256": sha256(code.encode()).hexdigest(),
        "source_bytes_sha256": sha256(source).hexdigest(), "commit": commit,
        "file_sha256": sha256(path.encode()).hexdigest(),
        "line_tolerance": 0, "original_fact_status": original.fact_status,
        "original_is_source_character_prefix": prefix_matches,
        "original_last_line_partial": partial_last_line,
        "semantic_role_verified": False, "historical_entry_modified": False,
    }
    if len(matching) != 1:
        return proof
    proposed = matching[0]
    revised = validator.validate_mapping(commit, {"file": path, "line": anchor, "code": proposed.code})
    proof["proposed_excerpt"] = {
        "code_sha256": sha256(proposed.code.encode()).hexdigest(), "code_chars": len(proposed.code),
        "line_start": anchor, "line_end": proposed.end_line, "fact_status": revised.fact_status,
        "matched_start": revised.matched_start, "matched_end": revised.matched_end,
        "semantic_role_verified": revised.semantic_role_verified,
    }
    if (len(code) == 2000 and prefix_matches and partial_last_line
            and original.fact_status == "incorrect" and revised.fact_status == "correct"
            and proposed.code == code.rsplit("\n", 1)[0]):
        proof["classification"] = "confirmed_producer_character_truncation"
    return proof


def audit_bundle(bundle, repo_map):
    cards, fields, categories = [], Counter(), Counter()
    original_verdicts = Counter()
    corrections = 0
    for binding, entry, report in zip(bundle.manifest.tasks, bundle.entries, bundle.validations, strict=True):
        original_verdicts[report.verdict] += 1
        items = []
        for name, field in sorted(report.fields.items()):
            fields[f"{name}:{field.status}"] += 1
            category = classify_field(name, field, entry)
            if category is None:
                continue
            categories[category] += 1
            items.append({
                "field": name, "original_status": field.status, "category": category,
                "original_evidence_sha256": sha256(field.evidence.encode()).hexdigest(),
                "reported_evidence_refs": list(field.evidence_refs), "next_action": ACTIONS[category],
                "resolution": "pending_review_not_signed",
            })
        card = {
            "task_id": binding["task_id"], "entry_id": entry["entry_id"], "report_id": report.report_id,
            "original_entry_sha256": binding["entry_sha256"],
            "original_validation_sha256": binding["validation_sha256"],
            "original_workflow_status": binding["status"], "original_verdict": report.verdict,
            "machine_verify": entry["verify"], "semantic_review_completed": False, "fields": items,
        }
        if "entry_point" in report.fields and report.fields["entry_point"].status == "incorrect":
            if entry["repo_url"] not in repo_map:
                raise ValueError("review_repo_missing")
            proof = check_entry_excerpt(entry, repo_map[entry["repo_url"]])
            card["entry_excerpt_fact_check"] = proof
            if proof["classification"] == "confirmed_producer_character_truncation":
                corrections += 1
                card["next_action"] = "A whole-line excerpt correction is available; preserve the original and review roles separately. Do not promote the full Entry or human verify flag."
        cards.append(card)
    summary = {
        "schema_version": 1, "scope": "historical_annotation_fact_triage_not_semantic_quality",
        "source_set_sha256": bundle.manifest.source_replay_dataset_sha256,
        "submission_sha256": bundle.manifest.submission_sha256,
        "source_export_files": {name: dict(value) for name, value in bundle.manifest.files.items()},
        "tasks": len(cards), "original_verdict_counts": dict(sorted(original_verdicts.items())),
        "field_status_counts": dict(sorted(fields.items())), "review_field_categories": dict(sorted(categories.items())),
        "confirmed_excerpt_truncations": corrections,
        "new_model_calls": 0, "historical_records_modified": 0, "semantic_review_completed": 0,
        "new_full_t1_runs": 0, "new_finalized_entries": 0,
        "reader_scope": "three_file_submission_integrity_not_replay_source_reexecution",
    }
    return summary, cards


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--submission-dir", required=True, type=Path)
    parser.add_argument("--repo-map", required=True, type=Path)
    parser.add_argument("--source-set-sha256", required=True)
    parser.add_argument("--submission-sha256", required=True)
    parser.add_argument("--task-count", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--check", action="store_true", help="Recompute and compare existing audit bytes; never overwrite.")
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.task_count <= 100:
            raise ValueError("audit_task_count_out_of_bounds")
        source = args.submission_dir.resolve(strict=True)
        output = args.output_dir.resolve()
        repo_map = load_trusted_repo_map(args.repo_map)
        protected = (source, args.repo_map.resolve(strict=True), *(Path(p).resolve(strict=True) for p in repo_map.values()))
        if any(output == p or output.is_relative_to(p) or p.is_relative_to(output) for p in protected):
            raise ValueError("audit_output_overlaps_inputs")
        bundle = read_submission_predictions(
            source, expected_source_replay_dataset_sha256=args.source_set_sha256,
            expected_task_count=args.task_count, expected_submission_sha256=args.submission_sha256,
        )
        summary, cards = audit_bundle(bundle, repo_map)
        encode = lambda value: (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        rows = b"".join(encode(card) for card in cards)
        summary["review_cards_sha256"] = sha256(rows).hexdigest()
        payloads = {"summary.json": encode(summary), "review_cards.jsonl": rows}
        if args.check:
            if set(p.name for p in output.iterdir()) != set(payloads):
                raise ValueError("audit_file_set_mismatch")
            if any((output / name).is_symlink() or (output / name).read_bytes() != value for name, value in payloads.items()):
                raise ValueError("audit_readback_mismatch")
        else:
            # New directory only; failures leave any partial output intact.
            output.mkdir()
            for name, value in payloads.items():
                with (output / name).open("xb") as handle:
                    handle.write(value)
        print(json.dumps({"status": "verified" if args.check else "written", "tasks": len(cards),
                          "confirmed_excerpt_truncations": summary["confirmed_excerpt_truncations"],
                          "review_cards_sha256": summary["review_cards_sha256"], "model_calls": 0}, sort_keys=True))
        return 0
    except Exception:
        print('{"status":"invalid","code":"offline_review_audit_failed","historical_records_modified":0}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
