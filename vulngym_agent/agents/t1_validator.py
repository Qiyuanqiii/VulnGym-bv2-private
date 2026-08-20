"""Conservative T1 deterministic fact gate.

This is the first vertical slice of the B-v2 design.  It proves schema, Git,
and source-location facts without claiming that an existing commit is the
vulnerable commit or that a code location has the advertised semantic role.
Those unresolved questions intentionally remain ``uncertain`` until advisory,
patch, and code-semantic validators supply evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Any, Mapping

from vulngym_agent.adapters import ENTRY_FIELDS, SchemaAdapter
from vulngym_agent.analyzers import PatchAnalysis, PatchAnalysisError, analyze_patch
from vulngym_agent.evidence import PackageLoadResult, extract_advisory_facts
from vulngym_agent.models import EvidenceItem, FieldValidation, ValidationReport
from vulngym_agent.resolvers import CriticalOperationResolver
from vulngym_agent.source import EntryPointSearcher
from vulngym_agent.tools.git import GitFactError, GitRepository
from vulngym_agent.validators import (
    CommitTransitionValidator,
    CommitValidator,
    LocationValidator,
    validate_advisory_fields,
)


_REPORT_ID_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
_OFFICIAL_FIELDS = frozenset(ENTRY_FIELDS)
_SYMBOL_RE = re.compile(
    r"\b(?:def|function|func|fn|class)\s+([A-Za-z_$][A-Za-z0-9_$]*)"
)


@dataclass(frozen=True, slots=True)
class T1ValidationOutcome:
    """One human-readable report and its machine-replayable evidence sidecar."""

    report: ValidationReport
    evidence: tuple[EvidenceItem, ...]


def _issue_field(path: str) -> str:
    if not path.startswith("$."):
        return "schema"
    remainder = path[2:]
    for field in _OFFICIAL_FIELDS:
        if (
            remainder == field
            or remainder.startswith(f"{field}.")
            or remainder.startswith(f"{field}[")
        ):
            return field
    return "schema"


def _evidence_id(field: str, source_type: str, text: str) -> str:
    digest = sha256(f"{field}\0{source_type}\0{text}".encode("utf-8")).hexdigest()
    safe_field = re.sub(r"[^A-Z0-9._-]", "-", field.upper())
    return f"EV-{safe_field}-{digest[:16].upper()}"


def _overall_verdict(fields: Mapping[str, FieldValidation]) -> str:
    statuses = {value.status for value in fields.values()}
    if "incorrect" in statuses:
        return "incorrect"
    if "uncertain" in statuses:
        return "uncertain"
    return "correct"


class T1DeterministicValidator:
    """Validate one candidate using only immutable, locally provable facts."""

    def __init__(
        self,
        repository: GitRepository | None = None,
        *,
        line_tolerance: int = 5,
        repository_note: str | None = None,
        package_result: PackageLoadResult | None = None,
    ) -> None:
        self._repository = repository
        self._repository_note = repository_note
        self._package_result = package_result
        self._line_tolerance = line_tolerance
        self._evidence_scope = "FACT"
        self._evidence_sequence = 0
        self._entry_id: str | None = None
        self._schema = SchemaAdapter()
        self._commit = CommitValidator(repository) if repository is not None else None
        self._location = (
            LocationValidator(repository, line_tolerance=line_tolerance)
            if repository is not None
            else None
        )

    def validate(
        self, candidate: Any, *, input_line: int | None = None
    ) -> T1ValidationOutcome:
        fields: dict[str, FieldValidation] = {}
        evidence_items: list[EvidenceItem] = []
        missing: list[str] = []
        self._evidence_sequence = 0

        report_id: str | None = None
        entry_id: str | None = None
        if isinstance(candidate, Mapping):
            value = candidate.get("report_id")
            if isinstance(value, str) and _REPORT_ID_RE.fullmatch(value):
                report_id = value
            candidate_entry_id = candidate.get("entry_id")
            if isinstance(candidate_entry_id, str) and re.fullmatch(
                r"entry-[0-9]{5}", candidate_entry_id
            ):
                entry_id = candidate_entry_id
                self._evidence_scope = entry_id.upper()
            elif report_id is not None:
                self._evidence_scope = report_id
        self._entry_id = entry_id

        schema_result = self._schema.validate(candidate)
        package_contract_errors = (
            tuple(
                issue
                for issue in self._package_result.issues
                if issue.status == "incorrect"
            )
            if self._package_result is not None
            and self._package_result.status == "incorrect"
            else ()
        )
        package_read_issues = (
            tuple(
                issue
                for issue in self._package_result.issues
                if issue.status == "uncertain"
            )
            if self._package_result is not None
            else ()
        )
        package_issue_text = (
            "; ".join(
                f"{issue.field}: {issue.message}" for issue in package_contract_errors
            )
            if package_contract_errors
            else (
                "Evidence Package 被标记为 incorrect，但没有提供结构化问题"
                if self._package_result is not None
                and self._package_result.status == "incorrect"
                else ""
            )
        )
        if schema_result.valid and not package_issue_text:
            text = (
                "候选记录通过当前 SCHEMA.md 的必填字段、类型、嵌套结构、"
                "ID/commit 格式、行号和额外字段检查。"
            )
            fields["schema"] = self._field(
                "correct", 1.0, text, "schema", report_id, evidence_items
            )
        else:
            entry_issue_text = "; ".join(
                f"{issue.path}: {issue.message}" for issue in schema_result.issues
            )
            issue_parts: list[str] = []
            if entry_issue_text:
                issue_parts.append(entry_issue_text)
            if package_issue_text:
                issue_parts.append("Evidence Package 契约：" + package_issue_text)
            issue_count = len(schema_result.issues) + (
                len(package_contract_errors) or bool(package_issue_text)
            )
            fields["schema"] = self._field(
                "incorrect",
                1.0,
                f"输入契约检查发现 {issue_count} 个确定性问题："
                + "; ".join(issue_parts),
                "schema",
                report_id,
                evidence_items,
            )
            grouped: dict[str, list[str]] = {}
            for issue in schema_result.issues:
                name = _issue_field(issue.path)
                if name != "schema":
                    grouped.setdefault(name, []).append(
                        f"{issue.path}: {issue.message}"
                    )
            for name, messages in grouped.items():
                fields[name] = self._field(
                    "incorrect",
                    1.0,
                    "字段违反正式契约：" + "; ".join(messages),
                    "schema",
                    report_id,
                    evidence_items,
                )

        if package_read_issues:
            issue_text = "; ".join(
                (
                    f"{issue.field} [{issue.code}] "
                    f"{issue.relative_path or '<未提供路径>'}: {issue.message}"
                )
                for issue in package_read_issues
            )
            fields["evidence_package"] = self._field(
                "uncertain",
                0.95,
                "Evidence Package 声明的部分资料未能安全读取，后续判断基于不完整资料："
                + issue_text,
                "schema",
                report_id,
                evidence_items,
            )
            missing.append(
                "补齐或修复 Evidence Package 中未能安全读取的公告、reference 或 patch 资料"
            )

        if not isinstance(candidate, Mapping):
            report = self._report(
                report_id, entry_id, input_line, fields, missing
            )
            return T1ValidationOutcome(report, tuple(evidence_items))

        advisory_document = None
        if self._package_result is not None and self._package_result.package is not None:
            advisory_document = self._package_result.package.advisory
        advisory_facts = (
            extract_advisory_facts(advisory_document)
            if advisory_document is not None
            else None
        )
        advisory_validation = validate_advisory_fields(
            candidate, self._package_result, advisory_facts
        )
        for name in ("report_id", "source_link", "vuln_ids"):
            if name in fields:
                continue
            fields[name] = self._field(
                advisory_validation.field_statuses[name],
                0.95
                if advisory_validation.field_statuses[name] in {"correct", "incorrect"}
                else 0.35,
                advisory_validation.field_evidence[name],
                "advisory" if advisory_facts is not None else "schema",
                report_id,
                evidence_items,
                snippet=advisory_validation.evidence_snippet,
                suggested_fix=advisory_validation.suggested_fixes.get(name),
            )
        missing.extend(advisory_validation.missing_information)

        patch_analyses, patch_notes = self._analyze_local_patches()

        self._validate_commit(
            candidate,
            report_id,
            fields,
            evidence_items,
            missing,
            advisory_facts.fix_commits if advisory_facts is not None else (),
        )
        self._validate_location(
            "entry_point", candidate, report_id, fields, evidence_items, missing
        )
        self._augment_entry_point(
            candidate,
            report_id,
            fields,
            evidence_items,
            missing,
        )
        self._validate_location(
            "critical_operation",
            candidate,
            report_id,
            fields,
            evidence_items,
            missing,
        )
        self._augment_critical_operation(
            candidate,
            report_id,
            fields,
            evidence_items,
            missing,
            advisory_facts.fix_commits if advisory_facts is not None else (),
            patch_analyses,
            patch_notes,
        )
        self._validate_trace(candidate, report_id, fields, evidence_items, missing)

        for name, description in (
            ("vuln_title", "漏洞标题是否准确概括公告核心"),
            ("vuln_category_l1", "一级漏洞分类是否符合公告与源码语义"),
            ("vuln_category_l2", "二级漏洞分类是否符合公告与源码语义"),
        ):
            if name not in fields:
                fields[name] = self._field(
                    "uncertain",
                    0.35,
                    f"{name} 通过了结构检查，但确定性事实门禁不能判断{description}；需要公告、补丁和代码语义证据。",
                    "schema",
                    report_id,
                    evidence_items,
                )
        missing.append("公告、补丁与源码三方语义证据，用于标题和分类判断")

        report = self._report(report_id, entry_id, input_line, fields, missing)
        return T1ValidationOutcome(report, tuple(evidence_items))

    def _validate_commit(
        self,
        candidate: Mapping[str, Any],
        report_id: str | None,
        fields: dict[str, FieldValidation],
        evidence_items: list[EvidenceItem],
        missing: list[str],
        fix_commits: tuple[str, ...],
    ) -> None:
        if "commit" in fields:
            return
        commit = candidate.get("commit")
        if self._commit is None:
            note = f"（{self._repository_note}）" if self._repository_note else ""
            fields["commit"] = self._field(
                "uncertain",
                0.2,
                f"没有可用于该条目的本地只读仓库映射{note}，因此无法确认 commit 是否存在或是否属于目标仓库。",
                "git",
                report_id,
                evidence_items,
            )
            missing.append("与 repo_url 精确对应的本地 Git 仓库")
            return

        result = self._commit.validate(commit)
        if isinstance(commit, str) and commit in fix_commits:
            transition = CommitTransitionValidator(self._repository).validate(
                commit, commit
            )
            suggested_fix = None
            try:
                parents = self._repository.commit_parents(commit)
            except GitFactError:
                parents = ()
            if len(parents) == 1:
                suggested_fix = parents[0]
            fields["commit"] = self._field(
                "incorrect",
                0.99,
                transition.evidence,
                "git",
                report_id,
                evidence_items,
                commit=commit if re.fullmatch(r"[0-9a-f]{40}", commit) else None,
                suggested_fix=suggested_fix,
            )
            return
        if result.fact_status == "correct" and fix_commits:
            transitions = tuple(
                CommitTransitionValidator(self._repository).validate(commit, fix_commit)
                for fix_commit in fix_commits
            )
            matching_fix_transitions = tuple(
                transition
                for transition in transitions
                if transition.error_code == "candidate_equals_fix"
            )
            if matching_fix_transitions:
                transition = matching_fix_transitions[0]
            elif len(transitions) == 1:
                transition = transitions[0]
            else:
                valid_boundaries = tuple(
                    transition
                    for transition in transitions
                    if transition.fact_status == "correct"
                )
                invalid_boundaries = tuple(
                    transition
                    for transition in transitions
                    if transition.fact_status == "incorrect"
                )
                if len(valid_boundaries) == 1 and len(invalid_boundaries) == len(transitions) - 1:
                    transition = valid_boundaries[0]
                else:
                    boundary_details = " ".join(
                        f"{item.fix_commit}: {item.error_code or item.fact_status}."
                        for item in transitions
                    )
                    fields["commit"] = self._field(
                        "uncertain",
                        0.4,
                        "本地公告明确给出多个修复 commit，但无法从本地历史唯一确定"
                        f"适用的修复边界。{boundary_details}",
                        "advisory",
                        report_id,
                        evidence_items,
                    )
                    missing.append("唯一适用的修复 commit 或多提交修复顺序")
                    return
            suggested_fix = None
            if transition.error_code == "candidate_equals_fix":
                try:
                    assert transition.fix_commit is not None
                    parents = self._repository.commit_parents(transition.fix_commit)
                except GitFactError:
                    parents = ()
                if len(parents) == 1:
                    suggested_fix = parents[0]
            fields["commit"] = self._field(
                transition.status,
                0.99 if transition.status == "incorrect" else 0.75,
                transition.evidence,
                "git",
                report_id,
                evidence_items,
                commit=(commit if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit) else None),
                suggested_fix=suggested_fix,
            )
            if transition.status == "uncertain":
                missing.append("公告/patch 与源码语义证据，用于证明该祖先提交实际含漏洞")
            return
        fields["commit"] = self._field(
            result.status,
            0.99 if result.status == "incorrect" else 0.65,
            result.evidence,
            "git",
            report_id,
            evidence_items,
            commit=result.commit,
        )
        if result.status == "uncertain":
            missing.append("修复 commit/patch 与版本祖先关系，用于区分漏洞 commit 和修复 commit")

    def _validate_location(
        self,
        name: str,
        candidate: Mapping[str, Any],
        report_id: str | None,
        fields: dict[str, FieldValidation],
        evidence_items: list[EvidenceItem],
        missing: list[str],
    ) -> None:
        if name in fields:
            return
        location = candidate.get(name)
        if not isinstance(location, Mapping):
            return
        if self._location is None:
            note = f"（{self._repository_note}）" if self._repository_note else ""
            fields[name] = self._field(
                "uncertain",
                0.2,
                f"没有可用于该条目的本地只读仓库映射{note}，无法核实 {name} 的 file/line/code。",
                "source",
                report_id,
                evidence_items,
            )
            missing.append("与 repo_url 精确对应的本地 Git 仓库")
            return

        result = self._location.validate_mapping(candidate.get("commit"), location)
        evidence_commit = (
            result.commit
            if isinstance(result.commit, str)
            and re.fullmatch(r"[0-9a-f]{40}", result.commit)
            else None
        )
        fields[name] = self._field(
            result.status,
            0.99 if result.status == "incorrect" else 0.7,
            result.evidence,
            "source",
            report_id,
            evidence_items,
            commit=evidence_commit,
            file=result.file,
            line_start=result.matched_start or result.requested_start,
            line_end=result.matched_end or result.requested_end,
            snippet=result.matched_code,
        )
        if result.status == "uncertain":
            role = "外部可达入口" if name == "entry_point" else "漏洞关键操作"
            missing.append(f"调用流/控制流证据，用于确认 {name} 确实是{role}")

    def _analyze_local_patches(
        self,
    ) -> tuple[tuple[PatchAnalysis, ...], tuple[str, ...]]:
        """Parse safely loaded patch documents without turning failures fatal."""

        package = (
            self._package_result.package
            if self._package_result is not None
            else None
        )
        if package is None:
            return (), ()

        analyses: list[PatchAnalysis] = []
        notes: list[str] = []
        for patch in package.patches:
            try:
                analysis = analyze_patch(patch)
            except (PatchAnalysisError, TypeError, ValueError, RuntimeError) as error:
                notes.append(f"{patch.relative_path}: {error}")
                continue
            analyses.append(analysis)
            if analysis.conflicts:
                notes.append(
                    f"{patch.relative_path}: {len(analysis.conflicts)} 个 patch 事实冲突"
                )
            if analysis.uncertainties:
                notes.append(
                    f"{patch.relative_path}: {len(analysis.uncertainties)} 个 patch 事实未决"
                )
        return tuple(analyses), tuple(notes)

    @staticmethod
    def _patch_guard_clues(patch_analyses: tuple[PatchAnalysis, ...]) -> tuple[str, ...]:
        """Describe fix-side guards as clues, never vulnerable locations."""

        return tuple(
            f"{item.file}:{item.new_line or '?'} {item.code[:160]!r}"
            for analysis in patch_analyses
            for item in analysis.candidates
            if item.change_kind == "added" and item.mode in {"guard", "early_return"}
        )

    @staticmethod
    def _entry_search_paths(candidate: Mapping[str, Any]) -> tuple[str, ...]:
        """Build a small explicit allow-list from submitted locations only."""

        paths: list[str] = []
        for name in ("entry_point", "critical_operation"):
            location = candidate.get(name)
            if isinstance(location, Mapping):
                path = location.get("file")
                if isinstance(path, str) and path not in paths:
                    paths.append(path)
        trace = candidate.get("trace")
        if isinstance(trace, list):
            for node in trace:
                if not isinstance(node, Mapping):
                    continue
                path = node.get("file")
                if isinstance(path, str) and path not in paths:
                    paths.append(path)
        return tuple(paths[:64])

    @staticmethod
    def _critical_symbol(location: Mapping[str, Any]) -> tuple[str, ...]:
        code = location.get("code")
        if not isinstance(code, str):
            return ()
        match = _SYMBOL_RE.search(code)
        return (match.group(1),) if match is not None else ()

    def _augment_entry_point(
        self,
        candidate: Mapping[str, Any],
        _report_id: str | None,
        fields: dict[str, FieldValidation],
        _evidence_items: list[EvidenceItem],
        missing: list[str],
    ) -> None:
        """Attach bounded structural entry clues while preserving semantics."""

        field = fields.get("entry_point")
        if field is None or field.status == "incorrect" or self._repository is None:
            return
        entry = candidate.get("entry_point")
        critical = candidate.get("critical_operation")
        commit = candidate.get("commit")
        if not isinstance(entry, Mapping) or not isinstance(critical, Mapping):
            return
        paths = self._entry_search_paths(candidate)
        critical_file = critical.get("file")
        critical_paths = (critical_file,) if isinstance(critical_file, str) else ()
        symbols = self._critical_symbol(critical)
        if not paths or (not critical_paths and not symbols):
            return

        result = EntryPointSearcher(self._repository).search(
            commit,
            paths=paths,
            critical_paths=critical_paths,
            critical_symbols=symbols,
        )
        candidate_file = entry.get("file")
        exact_candidates = tuple(
            item for item in result.candidates if item.path == candidate_file
        )
        details = result.evidence
        if exact_candidates:
            details += " 候选 entry 文件内发现：" + " ".join(
                item.evidence for item in exact_candidates[:3]
            )
        else:
            details += (
                " 在显式文件集合中没有找到与候选 entry 文件绑定的入口线索；"
                "有界缺失不能证明仓库不存在其他入口。"
            )
        if result.issues:
            details += " 搜索问题：" + " ".join(
                issue.evidence for issue in result.issues[:3]
            )
        text = f"{field.evidence} Entry 反向搜索：{details}"
        fields["entry_point"] = FieldValidation(
            status="uncertain",
            confidence=(
                0.78
                if exact_candidates and result.fact_status == "correct"
                else 0.55
            ),
            evidence=text,
            evidence_refs=field.evidence_refs,
        )
        missing.append("运行时路由注册、调用图或数据流证据，用于证明 entry_point 真正外部可达并通向关键操作")

    @staticmethod
    def _candidate_matches_location(
        analysis: PatchAnalysis, location: Mapping[str, Any]
    ) -> bool:
        path = location.get("file")
        code = location.get("code")
        if not isinstance(path, str) or not isinstance(code, str):
            return False
        normalized = " ".join(code.split())
        return any(
            item.file == path
            and (
                " ".join(item.code.split()) == normalized
                or " ".join(item.code.split()) in normalized
                or normalized in " ".join(item.code.split())
            )
            for item in analysis.candidates
            if item.change_kind == "removed"
        )

    def _augment_critical_operation(
        self,
        candidate: Mapping[str, Any],
        report_id: str | None,
        fields: dict[str, FieldValidation],
        evidence_items: list[EvidenceItem],
        missing: list[str],
        fix_commits: tuple[str, ...],
        patch_analyses: tuple[PatchAnalysis, ...],
        patch_notes: tuple[str, ...],
    ) -> None:
        """Cross-check critical candidates against patch and immutable Git facts."""

        field = fields.get("critical_operation")
        if field is None or field.status == "incorrect":
            return
        if not patch_analyses and not patch_notes:
            return
        location = candidate.get("critical_operation")
        commit = candidate.get("commit")
        if not isinstance(location, Mapping):
            return

        facts = " ".join(
            f"patch#{index}: files={len(analysis.files)}, candidates={len(analysis.candidates)}, "
            f"fact_status={analysis.fact_status}."
            for index, analysis in enumerate(patch_analyses, 1)
        )
        if patch_notes:
            facts += " 未决或不可解析资料：" + "; ".join(patch_notes[:4])

        resolutions = []
        if self._repository is not None and isinstance(commit, str):
            resolver = CriticalOperationResolver(
                self._repository, line_tolerance=self._line_tolerance
            )
            for fix_commit in fix_commits[:8]:
                for mode in ("sink", "guard"):
                    for analysis in patch_analyses:
                        resolutions.append(
                            resolver.resolve(
                                commit,
                                fix_commit,
                                mode=mode,
                                candidates=analysis,
                            )
                        )

        provisional = tuple(
            resolved
            for resolution in resolutions
            for resolved in resolution.provisional_locations
        )
        matches = any(
            self._candidate_matches_location(analysis, location)
            for analysis in patch_analyses
        )
        if provisional:
            facts += (
                f" Git 对漏洞侧/removed-side 交叉核验得到 {len(provisional)} 个临时候选；"
                "这些位置仍未证明为最终漏洞 Sink/Guard。"
            )
        elif resolutions:
            facts += " Git Sink/Guard 交叉核验没有得到可确认的漏洞侧候选。"
        guard_clues = self._patch_guard_clues(patch_analyses)
        if guard_clues:
            facts += (
                " 修复侧新增 Guard/early-return 仅作为旧版控制流缺口线索，"
                "绝不转换成漏洞版本位置：" + "; ".join(guard_clues[:4])
            )

        text = f"{field.evidence} Patch/Critical 交叉核验：{facts}"
        patch_item = self._field(
            "uncertain",
            0.82 if matches and provisional else 0.62,
            text,
            "patch",
            report_id,
            evidence_items,
            snippet=facts,
        )
        fields["critical_operation"] = FieldValidation(
            status=patch_item.status,
            confidence=patch_item.confidence,
            evidence=patch_item.evidence,
            evidence_refs=field.evidence_refs + patch_item.evidence_refs,
        )
        missing.append("公告语义、调用/数据流和反证审查，用于确定唯一 Critical Sink 或业务 Guard")

    def _validate_trace(
        self,
        candidate: Mapping[str, Any],
        report_id: str | None,
        fields: dict[str, FieldValidation],
        evidence_items: list[EvidenceItem],
        missing: list[str],
    ) -> None:
        if "trace" in fields:
            return
        trace = candidate.get("trace")
        if not isinstance(trace, list):
            return
        if not trace:
            fields["trace"] = self._field(
                "uncertain",
                0.5,
                "trace 是 Schema 合法的空数组，且没有编造节点；仍无法证明候选没有遗漏可由现有资料确认的调用/数据流链路。",
                "schema",
                report_id,
                evidence_items,
            )
            missing.append("公告、补丁或源码调用关系，用于确认空 trace 是否完整")
            return
        if self._location is None:
            fields["trace"] = self._field(
                "uncertain",
                0.2,
                "trace 结构合法，但缺少本地仓库，无法逐节点核实 file/line/code 或链路语义。",
                "source",
                report_id,
                evidence_items,
            )
            missing.append("本地仓库及调用/数据流证据，用于核实 trace")
            return

        results = [
            self._location.validate_mapping(candidate.get("commit"), node)
            for node in trace
            if isinstance(node, Mapping)
        ]
        incorrect = [
            result for result in results if result.fact_status == "incorrect"
        ]
        unverified = [
            result for result in results if result.fact_status == "uncertain"
        ]
        if incorrect:
            text = (
                f"trace 的 {len(results)} 个节点中有 {len(incorrect)} 个确定性位置错误。"
                + " ".join(result.evidence for result in incorrect[:3])
            )
            status, confidence = "incorrect", 0.99
        elif unverified:
            text = (
                f"trace 的 {len(results)} 个节点中有 {len(unverified)} 个因源码读取或仓库错误而无法核实；"
                "不能声称所有 file/line/code 已通过。"
                + " ".join(result.evidence for result in unverified[:3])
            )
            status, confidence = "uncertain", 0.35
            missing.append("可读取的漏洞版本源码，用于完成 trace 节点事实核验")
        else:
            text = (
                f"trace 的 {len(results)} 个节点均通过本地 file/line/code 事实检查；"
                "尚未证明节点顺序构成真实调用链或数据流。"
            )
            status, confidence = "uncertain", 0.65
            missing.append("跨文件调用/数据流证据，用于确认 trace 顺序与连通性")
        fields["trace"] = self._field(
            status,
            confidence,
            text,
            "source",
            report_id,
            evidence_items,
            commit=(
                candidate.get("commit")
                if isinstance(candidate.get("commit"), str)
                and re.fullmatch(r"[0-9a-f]{40}", candidate["commit"])
                else None
            ),
        )

    def _field(
        self,
        status: str,
        confidence: float,
        text: str,
        source_type: str,
        report_id: str | None,
        evidence_items: list[EvidenceItem],
        *,
        commit: str | None = None,
        file: str | None = None,
        line_start: int | None = None,
        line_end: int | None = None,
        snippet: str | None = None,
        suggested_fix: Any = None,
    ) -> FieldValidation:
        refs: tuple[str, ...] = ()
        if report_id is not None:
            self._evidence_sequence += 1
            evidence_snippet = snippet or text
            identity = "\0".join(
                (
                    report_id,
                    self._entry_id or "",
                    source_type,
                    text,
                    commit or "",
                    file or "",
                    str(line_start or ""),
                    str(line_end or ""),
                    evidence_snippet,
                )
            )
            evidence_id = _evidence_id(
                f"{self._evidence_scope}-{self._evidence_sequence:02d}",
                source_type,
                identity,
            )
            item = EvidenceItem(
                evidence_id=evidence_id,
                report_id=report_id,
                entry_id=self._entry_id,
                source_type=source_type,
                snippet=evidence_snippet,
                commit=commit,
                file=file,
                line_start=line_start,
                line_end=line_end,
            )
            evidence_items.append(item)
            refs = (evidence_id,)
        return FieldValidation(
            status=status,
            confidence=confidence,
            evidence=text,
            evidence_refs=refs,
            suggested_fix=suggested_fix,
        )

    @staticmethod
    def _report(
        report_id: str | None,
        entry_id: str | None,
        input_line: int | None,
        fields: Mapping[str, FieldValidation],
        missing: list[str],
    ) -> ValidationReport:
        verdict = _overall_verdict(fields)
        counts = {status: 0 for status in ("correct", "incorrect", "uncertain")}
        for value in fields.values():
            counts[value.status] += 1
        summary = (
            "确定性事实门禁完成："
            f"correct={counts['correct']}，incorrect={counts['incorrect']}，"
            f"uncertain={counts['uncertain']}。"
            "本阶段不会把“对象存在”误报成“漏洞语义已经证实”。"
        )
        return ValidationReport(
            report_id=report_id,
            entry_id=entry_id,
            input_line=input_line,
            verdict=verdict,
            fields=dict(fields),
            summary=summary,
            missing_information=tuple(dict.fromkeys(missing)),
        )
