"""Prepare an outcome-enriched development review cohort; never judge its answers.

Only reads a pinned three-file submission, not source repositories, answer stores
or model credentials. Review summaries count reviewer-supplied assessments, not
independently verified truth. No production, target execution or network calls.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.audit_lane_a_review_offline import classify_field
from vulngym_agent.agents.deepseek_backend import MODEL_ID, PROMPT_SHA256, PROMPT_VERSION
from vulngym_agent.submission_prediction import read_submission_predictions

PROTOCOL = "t2-quality-review-v1"
MAX_BYTES = 4 * 1024 * 1024
RUBRIC = {
    "source_identity": ("fact", "来源与标识是否有对应依据，而不只是字段可解析？"),
    "version_basis": ("fact", "受影响版本依据是什么，是否仅凭 fix 的父提交猜测？"),
    "entry_location": ("fact", "入口 file/line/code 是否在所报 commit 精确对应？"),
    "operation_location": ("fact", "关键操作 file/line/code 是否在所报 commit 精确对应？"),
    "entry_role": ("semantic", "入口角色和可达性有何上下文依据，有无合理替代？"),
    "operation_role": ("semantic", "该操作/决策与报告问题有何关系，有无合理替代？"),
    "trace": ("semantic", "记录的步骤及衔接有无证据，空 trace 是否遗漏已知联系？"),
    "title_and_project": ("semantic", "项目及标题是否准确描述资料，是否只是泛化模板？"),
    "classification": ("semantic", "两级类别是否有内容依据，有无更合理或尚待定的分类？"),
}
STATUSES = ("not_reviewed", "supported", "reasonable_alternative", "contradicted", "uncertain")


def encode(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def read_bytes(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("review_input_not_regular")
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("review_input_too_large")
    return raw


def parse(raw):
    return json.loads(raw, object_pairs_hook=strict_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def select_records(bundle, size=12, min_repositories=4):
    if type(size) is not int or type(min_repositories) is not int or not 1 <= min_repositories <= size <= 100:
        raise ValueError("invalid_cohort_limits")
    rows = sorted(zip(bundle.manifest.tasks, bundle.entries, bundle.validations, strict=True),
                  key=lambda row: row[0]["task_id"])
    if size > len(rows) or len({r[0]["task_id"] for r in rows}) != len(rows):
        raise ValueError("cohort_source_count_or_identity")
    selected, reasons = {}, {}

    def include(row, reason):
        key = row[0]["task_id"]
        selected[key] = row
        reasons[key] = reason

    for row in rows:
        if row[2].verdict == "incorrect":
            include(row, "retain_all_reported_errors")
    if len(selected) > size:
        raise ValueError("cohort_too_small_to_keep_errors")
    covered = {r[1]["repo_url"] for r in selected.values()}
    for repo in sorted({r[1]["repo_url"] for r in rows}, key=str.casefold):
        if repo not in covered and len(selected) < size:
            include(next(r for r in rows if r[1]["repo_url"] == repo), "uncovered_repository")
            covered.add(repo)
    # Cross-file is an observed layout property, not a verified relationship.
    remaining = sorted((r for r in rows if r[0]["task_id"] not in selected), key=lambda r: (
        r[1]["entry_point"]["file"] == r[1]["critical_operation"]["file"], r[0]["task_id"],
    ))
    for row in remaining[:size - len(selected)]:
        include(row, "cross_file_then_task_id_fill")
    if len({r[1]["repo_url"] for r in selected.values()}) < min_repositories:
        raise ValueError("insufficient_repository_diversity")
    return [(selected[key], reasons[key]) for key in sorted(selected)]


def prepare(bundle, *, system_commit, size=12, min_repositories=4):
    if not isinstance(system_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", system_commit):
        raise ValueError("system_commit_must_be_full_sha")
    choices = select_records(bundle, size, min_repositories)
    cases = []
    for index, ((binding, entry, report), reason) in enumerate(choices, 1):
        if entry["verify"] != 0 or type(entry["verify"]) is not int:
            raise ValueError("cohort_requires_machine_unverified_entries")
        gaps = {name: classify_field(name, field, entry) for name, field in report.fields.items()
                if field.status != "correct"}
        cases.append({
            "case_id": f"DEV-{index:03d}", "task_id": binding["task_id"],
            "entry_id": entry["entry_id"], "report_id": entry["report_id"],
            "entry_sha256": binding["entry_sha256"], "validation_sha256": binding["validation_sha256"],
            "repo_url": entry["repo_url"], "candidate_commit": entry["commit"],
            "source_link_as_recorded": entry["source_link"],
            "selection_reason": reason, "sample_group": "development_regression",
            "historical_workflow_status": binding["status"], "historical_t1_verdict": report.verdict,
            "historical_review_gaps": gaps, "machine_verify": 0,
            "observations_not_semantic_labels": {
                "entry_operation_different_files": entry["entry_point"]["file"] != entry["critical_operation"]["file"],
                "trace_step_count": len(entry["trace"]),
            },
            "scenario_evaluation": "not_reviewed",
        })
    cohort = {
        "protocol_id": PROTOCOL, "selection_policy": "all_errors_then_repository_coverage_then_cross_file_task_id_v1",
        "selection_timing": "retrospective_after_historical_results_before_substantive_review",
        "bias_warning": "Outcome-enriched development cohort; not random, blind, prospective or generalizable accuracy evidence.",
        "source_set_sha256": bundle.manifest.source_replay_dataset_sha256,
        "source_submission_sha256": bundle.manifest.submission_sha256,
        "source_files": {name: dict(value) for name, value in bundle.manifest.files.items()},
        "source_task_count": len(bundle.entries),
        "source_unique_report_count": len({e["report_id"] for e in bundle.entries}),
        "source_repository_counts": dict(sorted(Counter(e["repo_url"] for e in bundle.entries).items())),
        "system_for_next_production_test": {"code_commit": system_commit, "model_id": MODEL_ID,
            "prompt_version": PROMPT_VERSION, "prompt_sha256": PROMPT_SHA256,
            "status": "planned_not_executed", "commit_origin": "operator_declared"},
        "rubric": {name: {"group": group, "question": question} for name, (group, question) in RUBRIC.items()},
        "new_input_cohort": {"minimum_reports": 2, "selected_report_ids": [],
            "status": "pending_selection_after_protocol_freeze", "prewritten_responses_allowed": False},
        "cases": cases,
    }
    forms = [{"protocol_id": PROTOCOL, "case_id": c["case_id"], "task_id": c["task_id"],
              "entry_sha256": c["entry_sha256"], "reviewer": None,
              "fields": {name: {"status": "not_reviewed", "evidence_refs": [], "rationale": "",
                                "next_action": ""} for name in RUBRIC}} for c in cases]
    template = b"".join(encode(r) for r in forms)
    metrics = summarize(cohort, forms, review_file_sha256=sha256(template).hexdigest())
    payloads = {"cohort.json": encode(cohort), "review_template.jsonl": template,
                "baseline_metrics.json": encode(metrics), "review_packet.md": render(cohort).encode("utf-8")}
    payloads["manifest.json"] = encode({"protocol_id": PROTOCOL, "files": {
        name: {"byte_count": len(raw), "sha256": sha256(raw).hexdigest()} for name, raw in sorted(payloads.items())}})
    return payloads


def text_value(value, limit=1200, *, empty=False):
    return (isinstance(value, str) and len(value) <= limit and (empty or bool(value.strip()))
            and not any(ord(c) < 32 for c in value))


def summarize(cohort, reviews, *, review_file_sha256=None):
    """Count supplied review decisions; no semantics, identity or independence verification."""
    if cohort.get("protocol_id") != PROTOCOL or cohort.get("rubric") != {
            name: {"group": group, "question": question} for name, (group, question) in RUBRIC.items()}:
        raise ValueError("review_protocol_mismatch")
    cases = cohort["cases"]
    if not 1 <= len(cases) <= 100 or len({c["case_id"] for c in cases}) != len(cases):
        raise ValueError("cohort_case_identity_invalid")
    expected = {c["case_id"]: c for c in cases}
    if len(reviews) != len(cases) or len({r["case_id"] for r in reviews}) != len(reviews):
        raise ValueError("review_case_set_mismatch")
    counts = {group: Counter({s: 0 for s in STATUSES}) for group in ("fact", "semantic")}
    any_reviewed = all_considered = 0
    reviewer_kinds = Counter()
    reviewer_independence = Counter()
    for row in reviews:
        if set(row) != {"protocol_id", "case_id", "task_id", "entry_sha256", "reviewer", "fields"}:
            raise ValueError("review_shape_invalid")
        case = expected.get(row["case_id"])
        if (case is None or row["protocol_id"] != PROTOCOL or row["task_id"] != case["task_id"]
                or row["entry_sha256"] != case["entry_sha256"] or set(row["fields"]) != set(RUBRIC)):
            raise ValueError("review_binding_mismatch")
        considered = 0
        for name, field in row["fields"].items():
            if set(field) != {"status", "evidence_refs", "rationale", "next_action"}:
                raise ValueError("review_field_shape_invalid")
            status = field["status"]
            refs = field["evidence_refs"]
            if (status not in STATUSES or not isinstance(refs, list) or len(refs) > 8
                    or any(not text_value(r, 240) for r in refs) or len(set(refs)) != len(refs)
                    or not text_value(field["rationale"], empty=True)
                    or not text_value(field["next_action"], empty=True)):
                raise ValueError("review_field_value_invalid")
            if status == "not_reviewed":
                if refs or field["rationale"] or field["next_action"]:
                    raise ValueError("unreviewed_field_has_assessment")
            else:
                considered += 1
                if not field["rationale"].strip() or (status != "uncertain" and not refs):
                    raise ValueError("assessed_field_missing_support")
                if status == "uncertain" and not field["next_action"].strip():
                    raise ValueError("uncertain_field_missing_next_action")
            counts[RUBRIC[name][0]][status] += 1
        reviewer = row["reviewer"]
        if reviewer is not None:
            if (not isinstance(reviewer, dict) or set(reviewer) != {"name", "kind", "independence", "assessed_at"}
                    or not text_value(reviewer["name"], 120)
                    or reviewer["kind"] not in {"human", "ai_assisted_self_review", "rule_tool"}
                    or reviewer["independence"] not in {"self", "independent_declared", "unknown"}
                    or not text_value(reviewer["assessed_at"], 80)):
                raise ValueError("reviewer_metadata_invalid")
            if reviewer["kind"] != "human" and reviewer["independence"] == "independent_declared":
                raise ValueError("nonhuman_review_cannot_claim_independent_human_review")
        if considered and reviewer is None:
            raise ValueError("assessed_case_missing_reviewer")
        if considered:
            reviewer_kinds[reviewer["kind"]] += 1
            reviewer_independence[reviewer["independence"]] += 1
        any_reviewed += considered > 0
        all_considered += considered == len(RUBRIC)
    groups = {}
    for group, values in counts.items():
        decisive = values["supported"] + values["reasonable_alternative"] + values["contradicted"]
        positive = values["supported"] + values["reasonable_alternative"]
        groups[group] = {"field_counts": dict(values), "field_slots": sum(values.values()),
                         "adjudicated_fields": decisive, "unresolved_fields": values["uncertain"] + values["not_reviewed"],
                         "positive_adjudicated_field_rate": {"numerator": positive, "denominator": decisive,
                                                             "value": positive / decisive if decisive else None}}
    return {"protocol_id": PROTOCOL, "cohort_sha256": sha256(encode(cohort)).hexdigest(),
            "canonical_reviews_sha256": sha256(b"".join(encode(row) for row in reviews)).hexdigest(),
            "review_file_sha256": review_file_sha256,
            "interpretation": "Reviewer-reported decisions, not independently verified accuracy or production success.",
            "case_count": len(cases), "unique_reports": len({c["report_id"] for c in cases}),
            "repositories": len({c["repo_url"] for c in cases}),
            "sample_groups": dict(Counter(c["sample_group"] for c in cases)),
            "historical_t1_verdict_counts": dict(Counter(c["historical_t1_verdict"] for c in cases)),
            "cases_with_any_review": any_reviewed, "cases_all_fields_considered": all_considered,
            "reviewer_kind_case_counts": dict(reviewer_kinds), "reviewer_identity_and_independence_verified": False,
            "reviewer_independence_case_counts": dict(reviewer_independence),
            "quality_groups": groups, "new_input_reports_selected": len(cohort["new_input_cohort"]["selected_report_ids"]),
            "new_production_runs": 0, "entry_verify_mutations": 0}


def cell(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "&#124;").replace("`", "&#96;").replace("\r", " ").replace("\n", " ")


def render(cohort):
    lines = ["# T2 开发复核包（未完成实质评价）", "",
             "本包是看过历史结果后选取的错例富集开发子集，不能当作盲测、随机样本或总体准确率。",
             "所有评价格初始为 not_reviewed；T1 的原判定只作观察，不自动转为质量分。",
             "原 Entry/报告按下列摘要获取；不向新生产模型提供本包或旧标注。", "",
             f"- 来源任务数：{cohort['source_task_count']}；本包：{len(cohort['cases'])} 条。",
             f"- 固定提交包摘要：{cohort['source_submission_sha256']}。",
             "- 新输入队列：至少 2 份，尚未选定；资料条件/业务场景尚未实质核定。",
             "- 评审填写：复制 review_template.jsonl 到新文件，填写真实 reviewer、证据引用、简短理由和下一步。",
             "- supported/合理替代/反证需要证据；uncertain 需要具体缺口和动作；机器 Entry verify 保持 0。", "",
             "## 复核维度", "", "| 维度 | 层面 | 必答问题 |", "| --- | --- | --- |"]
    lines += [f"| {name} | {group} | {question} |" for name, (group, question) in RUBRIC.items()]
    for case in cohort["cases"]:
        lines += ["", f"## {case['case_id']} · {cell(case['report_id'])}", "",
                  f"- 仓库：{cell(case['repo_url'])}", f"- Task / Entry：{cell(case['task_id'])} / {cell(case['entry_id'])}",
                  f"- 原候选 commit：{cell(case['candidate_commit'])}",
                  f"- 原 Entry SHA-256：{case['entry_sha256']}", f"- 原报告 SHA-256：{case['validation_sha256']}",
                  f"- 来源链接原值（本轮未访问）：{cell(case['source_link_as_recorded'])}",
                  f"- 选取理由：{case['selection_reason']}；原工作流：{case['historical_workflow_status']}；T1：{case['historical_t1_verdict']}。",
                  f"- EP/CO 不同文件：{case['observations_not_semantic_labels']['entry_operation_different_files']}；原 trace 步数：{case['observations_not_semantic_labels']['trace_step_count']}。这些不是语义判断。",
                  "- 本次实质评价：not_reviewed；评审身份：未填写。", "",
                  "| 原报告待审字段 | 原报告所示限制 | 当前动作 |", "| --- | --- | --- |"]
        lines += [f"| {cell(name)} | {cell(gap)} | 按对应维度查证并填写，不复制 T1 状态当结论 |"
                  for name, gap in sorted(case["historical_review_gaps"].items())]
        if case["historical_t1_verdict"] == "incorrect":
            lines += ["", "已知旧入口片段存在字符截断缺陷，见 lane_a_review_audit_receipt；本包保留原错误。",
                      "若采用完整行修订，另存候选/报告并重新绑定摘要，不能把旧候选当成已经修正。"]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    builder = commands.add_parser("prepare")
    for name in ("submission-dir", "output-dir"):
        builder.add_argument("--" + name, type=Path, required=True)
    for name in ("source-set-sha256", "submission-sha256", "system-commit"):
        builder.add_argument("--" + name, required=True)
    builder.add_argument("--task-count", type=int, required=True)
    builder.add_argument("--cohort-size", type=int, default=12)
    builder.add_argument("--min-repositories", type=int, default=4)
    builder.add_argument("--check", action="store_true")
    summarizer = commands.add_parser("summarize")
    summarizer.add_argument("--cohort", type=Path, required=True)
    summarizer.add_argument("--cohort-sha256", required=True)
    summarizer.add_argument("--reviews", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "summarize":
            raw = read_bytes(args.cohort)
            if sha256(raw).hexdigest() != args.cohort_sha256:
                raise ValueError("cohort_digest_mismatch")
            cohort = parse(raw)
            if encode(cohort) != raw:
                raise ValueError("cohort_bytes_not_canonical")
            review_bytes = read_bytes(args.reviews)
            review_lines = review_bytes.splitlines()
            if not 1 <= len(review_lines) <= 100:
                raise ValueError("review_line_count_invalid")
            result = summarize(cohort, [parse(line) for line in review_lines],
                               review_file_sha256=sha256(review_bytes).hexdigest())
            print(encode(result).decode(), end="")
            return 0
        if not 1 <= args.task_count <= 100:
            raise ValueError("source_task_count_out_of_bounds")
        source, output = args.submission_dir.resolve(strict=True), args.output_dir.resolve()
        if output == source or output.is_relative_to(source) or source.is_relative_to(output):
            raise ValueError("output_overlaps_source")
        bundle = read_submission_predictions(source, expected_source_replay_dataset_sha256=args.source_set_sha256,
            expected_submission_sha256=args.submission_sha256, expected_task_count=args.task_count)
        payloads = prepare(bundle, system_commit=args.system_commit, size=args.cohort_size,
                           min_repositories=args.min_repositories)
        if args.check:
            if set(p.name for p in output.iterdir()) != set(payloads):
                raise ValueError("review_file_set_mismatch")
            if any(read_bytes(output / name) != value for name, value in payloads.items()):
                raise ValueError("review_readback_mismatch")
        else:
            output.mkdir()
            for name, value in payloads.items():
                with (output / name).open("xb") as handle:
                    handle.write(value)
        cohort = parse(payloads["cohort.json"])
        print(json.dumps({"status": "verified" if args.check else "prepared", "cases": len(cohort["cases"]),
                          "repositories": len({c["repo_url"] for c in cohort["cases"]}),
                          "cohort_sha256": sha256(payloads["cohort.json"]).hexdigest(),
                          "substantive_reviews_completed": 0, "model_calls": 0}, sort_keys=True))
        return 0
    except Exception:
        print('{"status":"invalid","code":"quality_review_input_or_output_failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
