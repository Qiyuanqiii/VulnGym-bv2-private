"""Field-level ID validation against one safely loaded local advisory."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Literal, Mapping

from vulngym_agent.evidence import AdvisoryFacts, PackageLoadResult


ValidationStatus = Literal["correct", "incorrect", "uncertain"]
_GHSA_URL_RE = re.compile(
    r"^https://github\.com/advisories/(GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4})/?$"
)


@dataclass(frozen=True, slots=True)
class AdvisoryValidationResult:
    status: ValidationStatus
    facts: AdvisoryFacts | None
    field_statuses: Mapping[str, ValidationStatus]
    field_evidence: Mapping[str, str]
    suggested_fixes: Mapping[str, Any]
    evidence_snippet: str | None
    missing_information: tuple[str, ...]
    error_code: str | None = None


def validate_advisory_fields(
    candidate: Mapping[str, Any],
    package_result: PackageLoadResult | None,
    facts: AdvisoryFacts | None,
) -> AdvisoryValidationResult:
    fields = ("report_id", "source_link", "vuln_ids")
    if package_result is None:
        return AdvisoryValidationResult(
            "uncertain",
            None,
            {field: "uncertain" for field in fields},
            {field: "未提供本地 Evidence Package，无法用公告正文核对该字段。" for field in fields},
            {},
            None,
            ("本地缓存的 GHSA/CVE 公告正文",),
            "package_not_provided",
        )
    if not package_result.usable or facts is None:
        issue_text = "; ".join(issue.message for issue in package_result.issues)
        detail = issue_text or "本地公告不可用"
        return AdvisoryValidationResult(
            "uncertain",
            None,
            {field: "uncertain" for field in fields},
            {field: f"Evidence Package 未能提供可读公告：{detail}。" for field in fields},
            {},
            None,
            ("可读取且未超限的 UTF-8 本地公告",),
            "advisory_unavailable",
        )

    statuses: dict[str, ValidationStatus] = {}
    evidence: dict[str, str] = {}
    fixes: dict[str, Any] = {}
    candidate_report = candidate.get("report_id")
    candidate_link = candidate.get("source_link")
    candidate_ids = candidate.get("vuln_ids")

    if not facts.ghsa_ids:
        statuses["report_id"] = "uncertain"
        evidence["report_id"] = "本地公告中未找到 GHSA ID，无法确认候选 report_id。"
    elif len(facts.ghsa_ids) > 1:
        statuses["report_id"] = "uncertain"
        evidence["report_id"] = f"本地公告出现多个 GHSA ID：{', '.join(facts.ghsa_ids)}；无法唯一绑定任务。"
    elif candidate_report == facts.ghsa_ids[0]:
        statuses["report_id"] = "correct"
        evidence["report_id"] = f"本地公告明确包含唯一 GHSA ID {facts.ghsa_ids[0]}，与候选一致。"
    else:
        statuses["report_id"] = "incorrect"
        evidence["report_id"] = f"本地公告唯一 GHSA ID 为 {facts.ghsa_ids[0]}，候选 report_id 为 {candidate_report!r}。"
        fixes["report_id"] = facts.ghsa_ids[0]

    link_id = None
    if isinstance(candidate_link, str):
        match = _GHSA_URL_RE.fullmatch(candidate_link)
        link_id = match.group(1).upper() if match else None
    if len(facts.ghsa_ids) == 1 and link_id == facts.ghsa_ids[0]:
        statuses["source_link"] = "correct"
        evidence["source_link"] = f"source_link 中的 {link_id} 与本地公告唯一 GHSA ID 一致。"
    elif len(facts.ghsa_ids) == 1:
        statuses["source_link"] = "incorrect"
        evidence["source_link"] = f"候选 source_link 未指向本地公告唯一 GHSA ID {facts.ghsa_ids[0]}。"
        fixes["source_link"] = f"https://github.com/advisories/{facts.ghsa_ids[0]}"
    else:
        statuses["source_link"] = "uncertain"
        evidence["source_link"] = "本地公告无法提供唯一 GHSA ID，不能确定规范 source_link。"

    expected_supported = list(facts.cve_ids + facts.ghsa_ids)
    if not expected_supported and not facts.other_vuln_ids:
        statuses["vuln_ids"] = "uncertain"
        evidence["vuln_ids"] = "本地公告未出现 GHSA/CVE 标识符，无法判断 vuln_ids 是否完整。"
    elif isinstance(candidate_ids, list):
        candidate_supported = [
            value
            for value in candidate_ids
            if isinstance(value, str)
            and (value.startswith("CVE-") or value.startswith("GHSA-"))
        ]
        candidate_other = [
            value for value in candidate_ids if value not in candidate_supported
        ]
        if candidate_supported != expected_supported:
            statuses["vuln_ids"] = "incorrect"
            evidence["vuln_ids"] = (
                f"公告中的 CVE/GHSA 为 {expected_supported}，候选对应子集为 "
                f"{candidate_supported}；其他标识符不会被自动删除。"
            )
            fixes["vuln_ids"] = expected_supported + candidate_other
        elif all(value in facts.other_vuln_ids for value in candidate_other):
            statuses["vuln_ids"] = "correct"
            evidence["vuln_ids"] = (
                "候选 vuln_ids 中的 CVE/GHSA 与公告完全一致，且公告中出现的其他"
                f"标识符均被保留：{candidate_ids}。"
            )
        else:
            unconfirmed = [
                value for value in candidate_other if value not in facts.other_vuln_ids
            ]
            statuses["vuln_ids"] = "uncertain"
            evidence["vuln_ids"] = (
                "候选 CVE/GHSA 与公告一致，但以下其他标识符家族没有正式解析规则，"
                f"且未能从公告中逐字确认：{unconfirmed}；不会自动建议删除。"
            )
    else:
        statuses["vuln_ids"] = "incorrect"
        evidence["vuln_ids"] = f"候选 vuln_ids 不是数组，无法与公告 ID {expected_supported} 对照。"
        fixes["vuln_ids"] = expected_supported

    overall: ValidationStatus = (
        "incorrect" if "incorrect" in statuses.values()
        else "uncertain" if "uncertain" in statuses.values()
        else "correct"
    )
    missing = (
        ("只包含单一目标 GHSA 的本地公告",)
        if overall == "uncertain"
        else ()
    )
    return AdvisoryValidationResult(
        overall, facts, statuses, evidence, fixes, facts.snippet, missing
    )
