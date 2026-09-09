"""Route existing reviewed candidates without relabelling, correcting or deleting them.

Only reads four pinned public evidence files. No model, target repositories,
credentials, hidden annotations, or historical production directories are read.
The resulting index is a submission decision aid, not a new accuracy evaluation.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import prepare_t2_quality_review as quality

INPUTS = {
    "inventory": ("evidence/lane-a-review-audit-20260907/review_cards.jsonl", "d74004538289054c3bdd30f22a3f8f0b2160665cedf7fa313be67775b2c981ea"),
    "cohort": ("evidence/t2-quality-review-dev12-20260907/cohort.json", "2258428587893c05de812e6e1e6a1b1788edb9639c370e7b307069d581e1d180"),
    "reviews": ("evidence/t2-quality-self-review-dev12-20260908/reviews.jsonl", "1e27ab67b03fb8d0bcfa86af9e301181d4d88b9762f56c16da7e5d30db964b37"),
    "current": ("evidence/t2-current-candidate-self-review-20260908/review.json", "6f43d03f0da5ad130fa75b5727428be10464db24ca0f7c551232e22da09e002e"),
}
STATES = ("excluded_pending_correction", "manual_review", "not_reviewed", "reviewed_unverified")


def disposition(fields, original_t1):
    """Contradiction outranks missing evidence; missing evidence never means correct."""
    if original_t1 not in {"correct", "incorrect", "uncertain"}:
        raise ValueError("invalid_original_t1_verdict")
    if fields is not None and (set(fields) != set(quality.RUBRIC)
            or any(f.get("status") not in quality.STATUSES for f in fields.values())):
        raise ValueError("invalid_disposition_fields")
    values = [] if fields is None else [f["status"] for f in fields.values()]
    if original_t1 == "incorrect" or "contradicted" in values:
        return "excluded_pending_correction"
    if not values or all(v == "not_reviewed" for v in values):
        return "not_reviewed"
    if "uncertain" in values or "not_reviewed" in values or original_t1 == "uncertain":
        return "manual_review"
    return "reviewed_unverified"


def make_row(card, fields, reviewer, case_id, group):
    if (type(card["machine_verify"]) is not int or card["machine_verify"] != 0
            or not re.fullmatch(r"[0-9a-f]{64}", card["original_entry_sha256"])
            or not re.fullmatch(r"[0-9a-f]{64}", card["original_validation_sha256"])):
        raise ValueError("machine_record_identity_invalid")
    unresolved = {} if fields is None else {
        name: value for name, value in sorted(fields.items())
        if value["status"] in {"contradicted", "uncertain", "not_reviewed"}}
    return {"case_id": case_id, "task_id": card["task_id"], "report_id": card["report_id"],
        "entry_id": card["entry_id"], "entry_sha256": card["original_entry_sha256"],
        "validation_sha256": card["original_validation_sha256"], "sample_group": group,
        "disposition": disposition(fields, card["original_verdict"]),
        "original_workflow_status": card["original_workflow_status"],
        "original_t1_verdict": card["original_verdict"], "machine_verify": 0,
        "reviewer": reviewer, "unresolved_fields": unresolved,
        "review_field_counts": dict(sorted(Counter(f["status"] for f in (fields or {}).values()).items())),
        "candidate_bytes_changed": False, "human_validation_claimed": False}


def build(inventory, cohort, reviews, current):
    # Reuse the established nine-field protocol, including all binding and reviewer checks.
    quality.summarize(cohort, reviews)
    if len({c["task_id"] for c in inventory}) != len(inventory):
        raise ValueError("duplicate_inventory_task")
    if len({c["original_entry_sha256"] for c in inventory}) != len(inventory):
        raise ValueError("duplicate_inventory_candidate")
    cards = {c["task_id"]: c for c in inventory}
    review_by_task = {r["task_id"]: r for r in reviews}
    if len(review_by_task) != len(reviews):
        raise ValueError("duplicate_review_task")
    for case in cohort["cases"]:
        card = cards.get(case["task_id"])
        if card is None or any(card[left] != case[right] for left, right in (
                ("entry_id", "entry_id"), ("report_id", "report_id"),
                ("original_entry_sha256", "entry_sha256"),
                ("original_validation_sha256", "validation_sha256"),
                ("original_verdict", "historical_t1_verdict"))):
            raise ValueError("inventory_review_binding_mismatch")
    # Validate the separately produced current candidate using the same rubric.
    if (current["schema"] != "t2.current-development-candidate-self-review.v1"
            or current["sample_group"] != "known_input_model_development"
            or current["human_review_completed"] is not False
            or current["finalized_status_promoted"] is not False
            or current["not_part_of_frozen_dev12"] is not True):
        raise ValueError("current_review_scope_changed")
    current_form = {k: current[k] for k in ("task_id", "entry_sha256", "fields", "reviewer")}
    current_form.update(protocol_id=quality.PROTOCOL, case_id="MODEL-DEV-001")
    current_case = {**current_form, "report_id": current["report_id"],
        "repo_url": "current-development-group", "sample_group": current["sample_group"],
        "historical_t1_verdict": current["original_t1_verdict"]}
    quality.summarize({**cohort, "cases": [current_case]}, [current_form])
    if current["entry_sha256"] in {c["original_entry_sha256"] for c in inventory}:
        raise ValueError("current_candidate_already_in_inventory")
    rows = []
    for task, card in sorted(cards.items()):
        review = review_by_task.get(task)
        rows.append(make_row(card, None if review is None else review["fields"],
            None if review is None else review["reviewer"], None if review is None else review["case_id"],
            "historical_lane_a_development"))
    current_card = {"task_id": current["task_id"], "report_id": current["report_id"],
        "entry_id": current["entry_id"], "machine_verify": current["original_machine_verify"],
        "original_entry_sha256": current["entry_sha256"],
        "original_validation_sha256": current["validation_sha256"],
        "original_verdict": current["original_t1_verdict"], "original_workflow_status": "manual_review"}
    rows.append(make_row(current_card, current["fields"], current["reviewer"], "MODEL-DEV-001", current["sample_group"]))
    groups = {}
    for group in sorted({r["sample_group"] for r in rows}):
        items = [r for r in rows if r["sample_group"] == group]
        groups[group] = {"candidate_records": len(items),
            "dispositions": {s: sum(r["disposition"] == s for r in items) for s in STATES},
            "review_field_counts": dict(sorted(sum((Counter(r["review_field_counts"]) for r in items), Counter()).items()))}
    summary = {"schema": "t2.submission-disposition.v1", "groups": groups,
        "scope": "existing_review_decisions_not_new_semantic_evaluation",
        "candidate_records": len(rows), "new_model_calls": 0, "new_t1_calls": 0,
        "historical_files_modified": 0, "machine_verify_mutations": 0,
        "human_validation_claimed": False, "product_accuracy": None,
        "all_reviewed_cases_retained_in_evaluation_denominators": True,
        "automatic_corrections_applied": 0,
        "deferred_or_transport_only_tasks": "excluded_from_candidate_denominator_reported_in_original_run_receipts"}
    lines = ["# 交验候选分流与复核动作", "",
        "这是对已有复核决定的整理，不是新增语义评价，也没有修改或删除任何原候选。",
        "12条历史开发自评与单条真实模型开发候选保持不同分组；同一任务的不同候选按摘要区分。", "",
        "| 分组 | 候选数 | 存在反证，暂不采用 | 保留待复核 | 未作语义评价 | 已评但未人工验证 |",
        "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for group, counts in groups.items():
        lines.append(f"| {group} | {counts['candidate_records']} | " + " | ".join(str(counts["dispositions"][s]) for s in STATES) + " |")
    lines += ["", "## 使用方式", "",
        "- `excluded_pending_correction`：保留为错例，暂不纳入正确数据；按字段修订成新版本后重新检查。原评价分母不删除。",
        "- `manual_review`：可作为带限制的候选示例，不冒称正确或人工验证完成。",
        "- `not_reviewed`：没有九维内容评价，不从T1或数量推断质量。",
        "- `reviewed_unverified`：即使各字段获支持，也不自动改为verify=1或finalized。",
        "- 仅对已有完整候选分流；defer及传输错误仍在各自运行回执中，不补造Entry。",
        "- 当前建议保留MODEL-DEV-001作主展示候选，同时呈现两个待复核项；12条历史错例进入开发附录，其余28条不作质量承诺。", "",
        "## 未解决字段与实际下一步", ""]
    for row in rows:
        if row["case_id"] is None:
            continue
        lines += [f"### {row['case_id']} — {row['disposition']}", "",
            f"任务：{row['task_id']}；候选摘要：{row['entry_sha256']}。", "",
            "| 字段 | 原复核结论 | 下一步（沿用原复核，不是本次已经修正） |",
            "| --- | --- | --- |"]
        for name, field in row["unresolved_fields"].items():
            lines.append(f"| {name} | {field['status']} | {quality.cell(field['next_action'])} |")
        lines.append("")
    payloads = {"disposition.jsonl": b"".join(quality.encode(r) for r in rows),
        "summary.json": quality.encode(summary), "README.md": ("\n".join(lines).rstrip() + "\n").encode("utf-8")}
    payloads["manifest.json"] = quality.encode({"schema": summary["schema"],
        "public_inputs": {path: digest for path, digest in INPUTS.values()},
        "files": {name: {"bytes": len(data), "sha256": sha256(data).hexdigest()} for name, data in sorted(payloads.items())}})
    return payloads


def load():
    data = {}
    for key, (name, digest) in INPUTS.items():
        raw = quality.read_bytes(ROOT / name)
        if sha256(raw).hexdigest() != digest:
            raise ValueError("pinned_public_input_changed")
        data[key] = [quality.parse(line) for line in raw.splitlines()] if name.endswith(".jsonl") else quality.parse(raw)
    if len(data["inventory"]) != 40 or len(data["reviews"]) != 12:
        raise ValueError("frozen_inventory_count_changed")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        output = args.output_dir.resolve()
        sources = [(ROOT / name).resolve().parent for name, _ in INPUTS.values()]
        if any(output == p or output.is_relative_to(p) or p.is_relative_to(output) for p in sources):
            raise ValueError("output_overlaps_public_input")
        payloads = build(**load())
        if args.check:
            if set(p.name for p in output.iterdir()) != set(payloads) or any(
                    quality.read_bytes(output / name) != raw for name, raw in payloads.items()):
                raise ValueError("disposition_readback_mismatch")
        else:
            output.mkdir()
            for name, raw in payloads.items():
                with (output / name).open("xb") as handle:
                    handle.write(raw)
        print(quality.encode({"status": "verified" if args.check else "created", "files": len(payloads),
            "candidate_records": 41, "provider_calls": 0,
            "manifest_sha256": sha256(payloads["manifest.json"]).hexdigest()}).decode().strip())
        return 0
    except (ValueError, KeyError, TypeError, OSError):
        print('{"status":"invalid","code":"disposition_failed_preserve_existing"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
