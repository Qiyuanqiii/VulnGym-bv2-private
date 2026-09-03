"""Offline, fail-closed materialization of Lane A advisory assignments.

Only answer-free task identity, public report metadata, a deliberately small
GitHub advisory cache, and immutable local Git objects cross this boundary.
The resulting assignment file is suitable for :mod:`lane_a_task_bundle`; it
never contains an Entry trace or an answer-derived location.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType
from typing import Final, Mapping, Sequence
import uuid

from vulngym_agent.agents.t2_inputs import T2Hints
from vulngym_agent.agents.t2_toolbox import (
    MAX_GIT_BLOB_BYTES,
    MAX_GIT_DIFF_BYTES,
    MAX_LOCAL_FILE_BYTES,
)
from vulngym_agent.benchmark.contracts import BenchmarkContractError, BenchmarkTask
from vulngym_agent.evidence import (
    LoadedEvidenceFile,
    PackageSpec,
    extract_advisory_facts,
)
from vulngym_agent.lane_a_task_bundle import (
    LANE_A_PUBLIC_TASKS_DOMAIN,
    LaneAAssignmentV1,
    LaneATaskBundleError,
    _assert_chain,
    _canonical_existing_path,
    _canonical_new_child,
    _directory_identity,
    _close_publication_descriptor,
    _close_windows_handle,
    _guard_chain,
    _is_reparse,
    _identity_at,
    _line,
    _parse_jsonl,
    _parse_line,
    _open_bound_directory,
    _open_windows_directory_lock,
    _named_directory_identity,
    _read_regular_at,
    _read_regular,
    _rename_noreplace,
    _require_directory,
    _require_sha256,
    _semantic,
    _windows_extended_path,
    _write_file,
)
from vulngym_agent.tools.git import GitFactError, GitRepository, validate_repo_relative_path
from vulngym_agent.trusted_inputs import paths_overlap_v1


LaneAAssignmentMaterializerError = LaneATaskBundleError

CONTRACT_VERSION: Final[int] = 1
MATERIALIZATION_KIND: Final[str] = "vulngym.lane-a-assignment-materialization.v1"
POLICY_ID: Final[str] = "lexicographic-report-entry-v1"
LOCAL_DIRECT_CHILD_POLICY_ID: Final[str] = "local-direct-child-fallback-v1"
ANCHOR_SEMANTICS: Final[str] = (
    "deterministic_evaluation_anchor_not_finding_provenance"
)
LOCAL_DIRECT_CHILD_ANCHOR_SEMANTICS: Final[str] = (
    "public_identifier_match_with_unique_local_single_parent_child"
)
ASSIGNMENTS_FILENAME: Final[str] = "assignments.jsonl"
COVERAGE_AUDIT_FILENAME: Final[str] = "coverage-audit.jsonl"
MANIFEST_FILENAME: Final[str] = "manifest.json"

REPORTS_DOMAIN: Final[bytes] = b"VulnGym Lane A public reports v1\0"
ADVISORY_CACHE_DOMAIN: Final[bytes] = b"VulnGym Lane A advisory cache v1\0"
REPO_MAP_DOMAIN: Final[bytes] = b"VulnGym Lane A offline repository map v1\0"
ASSIGNMENTS_DOMAIN: Final[bytes] = b"VulnGym Lane A assignments v1\0"
COVERAGE_DOMAIN: Final[bytes] = b"VulnGym Lane A coverage audit v1\0"
MATERIALIZATION_DOMAIN: Final[bytes] = b"VulnGym Lane A assignment materialization v1\0"

_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
_REPORT_ID_RE = re.compile(r"GHSA-[0-9A-Z]{4}(?:-[0-9A-Z]{4}){2}\Z")
_ENTRY_ID_RE = re.compile(r"entry-[0-9]{5}\Z")
_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
_REPO_URL_RE = re.compile(
    r"https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z"
)
_ADVISORY_URL_RE = re.compile(
    r"https://github\.com/advisories/(GHSA-[0-9A-Za-z]{4}"
    r"(?:-[0-9A-Za-z]{4}){2})\Z"
)
_COMMIT_URL_RE = re.compile(
    r"https://github\.com/"
    r"([A-Za-z0-9][A-Za-z0-9_.-]{0,99})/"
    r"([A-Za-z0-9][A-Za-z0-9_.-]{0,99})/commit/([0-9A-Fa-f]{40})\Z"
)
_REPORT_KEYS = frozenset(
    {
        "commit",
        "entry_ids",
        "num_entries",
        "origin",
        "project",
        "repo_url",
        "report_id",
        "source_link",
        "vuln_ids",
        "vuln_title",
    }
)
_CACHE_KEYS = frozenset(
    {"description", "ghsa_id", "identifiers", "references", "summary"}
)
_SOURCE_SUFFIXES = frozenset(
    {
        ".cjs",
        ".go",
        ".java",
        ".js",
        ".jsx",
        ".mjs",
        ".php",
        ".phtml",
        ".py",
        ".pyw",
        ".rb",
        ".ts",
        ".tsx",
    }
)
_FORBIDDEN_WIRE_MARKERS = (
    b'"critical_operation":',
    b'"entry_point":',
    b"selection_lock",
    b"source-map",
    b"source_map",
    b'"trace":',
)
_MAX_INPUT_BYTES = 64 * 1024 * 1024
_MAX_PATCH_BYTES = MAX_LOCAL_FILE_BYTES
_MAX_TASKS = 100_000


def _error(code: str, message: str, *, committed: bool = False) -> LaneATaskBundleError:
    return LaneATaskBundleError(code, message, committed=committed)


def _repo_key(value: str) -> str:
    return value.casefold()


def _safe_text(value: object, name: str, maximum: int, *, allow_empty: bool = False) -> str:
    if (
        type(value) is not str
        or (not allow_empty and not value)
        or len(value) > maximum
        or value != value.strip()
        or "\x00" in value
        or any(ord(character) == 127 for character in value)
    ):
        raise _error("invalid_metadata", f"{name} is not a bounded canonical string")
    return value


@dataclass(frozen=True, slots=True)
class _Report:
    report_id: str
    source_link: str
    vuln_ids: tuple[str, ...]
    origin: str
    project: str
    repo_url: str
    commit: str
    vuln_title: str
    entry_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "commit": self.commit,
            "entry_ids": list(self.entry_ids),
            "num_entries": len(self.entry_ids),
            "origin": self.origin,
            "project": self.project,
            "repo_url": self.repo_url,
            "report_id": self.report_id,
            "source_link": self.source_link,
            "vuln_ids": list(self.vuln_ids),
            "vuln_title": self.vuln_title,
        }


@dataclass(frozen=True, slots=True)
class _Advisory:
    description: str
    ghsa_id: str
    identifiers: tuple[Mapping[str, str], ...]
    references: tuple[str, ...]
    summary: str

    def to_dict(self) -> dict[str, object]:
        return {
            "description": self.description,
            "ghsa_id": self.ghsa_id,
            "identifiers": [dict(item) for item in self.identifiers],
            "references": list(self.references),
            "summary": self.summary,
        }


@dataclass(frozen=True, slots=True)
class _Inputs:
    paths: tuple[Path, ...]
    wires: tuple[bytes, ...]
    tasks: tuple[BenchmarkTask, ...]
    reports: tuple[_Report, ...]
    advisories: Mapping[str, _Advisory]
    repo_paths: Mapping[str, Path]
    repo_guards: Mapping[str, tuple[tuple[Path, tuple[int, int]], ...]]
    semantic: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class LaneAAssignmentMaterializationManifestV1:
    materialization_sha256: str
    manifest_wire_sha256: str
    task_count: int
    assignments_sha256: str
    assignments_wire_sha256: str
    coverage_audit_sha256: str


@dataclass(frozen=True, slots=True)
class _AnchorSelection:
    report: _Report
    entry_id: str
    candidate_fix_commits: tuple[str, ...]
    fix_commit: str
    anchor_policy: str
    anchor_semantics: str
    candidate_source: str


def _parse_report(value: object) -> _Report:
    if type(value) is not dict or frozenset(value) != _REPORT_KEYS:
        raise _error("report_fields", "public report fields differ")
    report_id = value["report_id"]
    repo_url = value["repo_url"]
    commit = value["commit"]
    source_link = value["source_link"]
    if type(report_id) is not str or _REPORT_ID_RE.fullmatch(report_id) is None:
        raise _error("report_invalid", "public report_id is invalid")
    if type(repo_url) is not str or _REPO_URL_RE.fullmatch(repo_url) is None:
        raise _error("report_invalid", "public report repository URL is invalid")
    if type(commit) is not str or _SHA_RE.fullmatch(commit) is None:
        raise _error("report_invalid", "public report commit is invalid")
    source_match = _ADVISORY_URL_RE.fullmatch(source_link) if type(source_link) is str else None
    if source_match is None or source_match.group(1).upper() != report_id:
        raise _error("report_invalid", "public report advisory URL differs")
    entries = value["entry_ids"]
    if (
        type(entries) is not list
        or not entries
        or any(type(item) is not str or _ENTRY_ID_RE.fullmatch(item) is None for item in entries)
        or entries != sorted(set(entries))
        or type(value["num_entries"]) is not int
        or value["num_entries"] != len(entries)
    ):
        raise _error("report_invalid", "public report entry membership is invalid")
    vuln_ids = value["vuln_ids"]
    if (
        type(vuln_ids) is not list
        or any(type(item) is not str or not item or len(item) > 128 for item in vuln_ids)
        or len(vuln_ids) != len(set(vuln_ids))
    ):
        raise _error("report_invalid", "public report vulnerability identifiers are invalid")
    if value["origin"] != "GitHub Advisory Database (reviewed)":
        raise _error("report_invalid", "public report origin is invalid")
    return _Report(
        report_id=report_id,
        source_link=f"https://github.com/advisories/{report_id}",
        vuln_ids=tuple(vuln_ids),
        origin=value["origin"],
        project=_safe_text(value["project"], "project", 256),
        repo_url=repo_url,
        commit=commit,
        vuln_title=_safe_text(value["vuln_title"], "vuln_title", 4096),
        entry_ids=tuple(entries),
    )


def _parse_advisory(value: object) -> _Advisory:
    if type(value) is not dict or frozenset(value) != _CACHE_KEYS:
        raise _error("advisory_fields", "sanitized advisory cache fields differ")
    ghsa_id = value["ghsa_id"]
    if type(ghsa_id) is not str or _REPORT_ID_RE.fullmatch(ghsa_id) is None:
        raise _error("advisory_invalid", "cached GHSA identifier is invalid")
    identifiers = value["identifiers"]
    frozen: list[Mapping[str, str]] = []
    seen: set[tuple[str, str]] = set()
    if type(identifiers) is not list or not 1 <= len(identifiers) <= 64:
        raise _error("advisory_invalid", "cached advisory identifiers are invalid")
    for item in identifiers:
        if type(item) is not dict or frozenset(item) != {"type", "value"}:
            raise _error("advisory_invalid", "cached advisory identifier fields differ")
        kind = _safe_text(item["type"], "identifier type", 32)
        identifier = _safe_text(item["value"], "identifier value", 128)
        if (
            (kind == "GHSA" and _REPORT_ID_RE.fullmatch(identifier) is None)
            or (kind == "CVE" and _CVE_RE.fullmatch(identifier) is None)
            or kind not in {"CVE", "GHSA"}
        ):
            raise _error("advisory_invalid", "cached advisory identifier is unsupported")
        pair = (kind, identifier)
        if pair in seen:
            raise _error("advisory_invalid", "cached advisory identifiers repeat")
        seen.add(pair)
        frozen.append(MappingProxyType({"type": kind, "value": identifier}))
    if ("GHSA", ghsa_id) not in seen:
        raise _error("advisory_invalid", "cached advisory does not identify itself")
    references = value["references"]
    if (
        type(references) is not list
        or not references
        or len(references) > 512
        or any(
            type(item) is not str
            or not item.startswith("https://")
            or len(item) > 2048
            or "\x00" in item
            or any(ord(character) < 32 for character in item)
            for item in references
        )
        or references != sorted(set(references))
    ):
        raise _error("advisory_invalid", "cached advisory references are invalid")
    description = _safe_text(
        value["description"], "description", 256 * 1024, allow_empty=True
    )
    summary = _safe_text(value["summary"], "summary", 4096)
    prose = (description + "\n" + summary).casefold()
    if any(
        marker in prose
        for marker in (
            '"critical_operation"',
            '"entry_point"',
            '"trace"',
            "'critical_operation'",
            "'entry_point'",
            "'trace'",
            "selection_lock",
            "source-map",
            "source_map",
        )
    ):
        raise _error("private_marker", "cached advisory prose contains an answer/control marker")
    return _Advisory(
        description=description,
        ghsa_id=ghsa_id,
        identifiers=tuple(frozen),
        references=tuple(references),
        summary=summary,
    )


def _parse_repo_map(value: object) -> Mapping[str, Path]:
    if type(value) is not dict or frozenset(value) != {"contract_version", "repositories"}:
        raise _error("repo_map_invalid", "offline repository map fields differ")
    repositories = value["repositories"]
    if value["contract_version"] != 1 or type(repositories) is not list or not repositories:
        raise _error("repo_map_invalid", "offline repository map header is invalid")
    if len(repositories) > 10_000:
        raise _error("repo_map_invalid", "offline repository map is too large")
    result: dict[str, Path] = {}
    identities: set[tuple[int, int]] = set()
    normalized_order: list[str] = []
    for item in repositories:
        if type(item) is not dict or frozenset(item) != {"path", "repo_url"}:
            raise _error("repo_map_invalid", "offline repository entry fields differ")
        repo_url = item["repo_url"]
        raw_path = item["path"]
        if type(repo_url) is not str or _REPO_URL_RE.fullmatch(repo_url) is None:
            raise _error("repo_map_invalid", "offline repository URL is invalid")
        if type(raw_path) is not str or not Path(raw_path).is_absolute():
            raise _error("repo_map_invalid", "offline repository path must be absolute")
        key = _repo_key(repo_url)
        if key in result:
            raise _error("repo_map_duplicate", "offline repository URLs repeat")
        try:
            path = _canonical_existing_path(raw_path, directory=True, status=2)
            identity = _directory_identity(_require_directory(path))
        except Exception as error:
            if isinstance(error, LaneATaskBundleError):
                raise
            raise _error("unsafe_path", "offline repository path is unsafe") from None
        if identity in identities:
            raise _error("repo_map_duplicate", "offline repository paths alias")
        identities.add(identity)
        normalized_order.append(key)
        result[key] = path
    if normalized_order != sorted(normalized_order):
        raise _error("repo_map_invalid", "offline repository map is not sorted")
    return MappingProxyType(result)


def _load_unpinned(
    public_tasks_file: str | os.PathLike[str],
    reports_file: str | os.PathLike[str],
    advisory_cache_file: str | os.PathLike[str],
    repo_map_file: str | os.PathLike[str],
) -> _Inputs:
    paths_and_wires = tuple(
        _read_regular(path, maximum=_MAX_INPUT_BYTES)
        for path in (public_tasks_file, reports_file, advisory_cache_file, repo_map_file)
    )
    paths = tuple(item[0] for item in paths_and_wires)
    wires = tuple(item[1] for item in paths_and_wires)
    if len(set(paths)) != len(paths):
        raise _error("path_overlap", "materializer input files overlap")
    try:
        tasks = tuple(BenchmarkTask.from_dict(value) for value in _parse_jsonl(wires[0], "public task"))
    except (BenchmarkContractError, TypeError, ValueError):
        raise _error("public_task_invalid", "answer-free public task export is invalid") from None
    if len({task.task_id for task in tasks}) != len(tasks) or len(
        {(_repo_key(task.repo_url), task.commit) for task in tasks}
    ) != len(tasks):
        raise _error("public_task_duplicate", "answer-free public tasks repeat")
    if len({task.split for task in tasks}) != 1:
        raise _error("split_mismatch", "answer-free public task export mixes splits")
    reports = tuple(_parse_report(value) for value in _parse_jsonl(wires[1], "public report"))
    if [item.report_id for item in reports] != sorted(item.report_id for item in reports):
        raise _error("report_order", "public reports are not sorted by report_id")
    if len({item.report_id for item in reports}) != len(reports):
        raise _error("report_duplicate", "public report identifiers repeat")
    all_entry_ids = [entry for report in reports for entry in report.entry_ids]
    if len(all_entry_ids) != len(set(all_entry_ids)):
        raise _error("report_duplicate", "public entry identifiers repeat across reports")
    advisory_values = tuple(_parse_advisory(value) for value in _parse_jsonl(wires[2], "advisory cache"))
    if [item.ghsa_id for item in advisory_values] != sorted(item.ghsa_id for item in advisory_values):
        raise _error("advisory_order", "advisory cache is not sorted by GHSA identifier")
    advisories = {item.ghsa_id: item for item in advisory_values}
    if len(advisories) != len(advisory_values):
        raise _error("advisory_duplicate", "advisory cache identifiers repeat")
    repo_map_value = _parse_line(wires[3], "offline repository map")
    repo_paths = _parse_repo_map(repo_map_value)
    repo_guards = MappingProxyType(
        {key: _guard_chain(path) for key, path in repo_paths.items()}
    )
    semantic = MappingProxyType(
        {
            "advisory_cache_sha256": _semantic(
                ADVISORY_CACHE_DOMAIN, [item.to_dict() for item in advisory_values]
            ),
            "public_tasks_sha256": _semantic(
                LANE_A_PUBLIC_TASKS_DOMAIN, [task.to_dict() for task in tasks]
            ),
            "reports_sha256": _semantic(REPORTS_DOMAIN, [item.to_dict() for item in reports]),
            "repo_map_sha256": _semantic(REPO_MAP_DOMAIN, repo_map_value),
        }
    )
    return _Inputs(
        paths=paths,
        wires=wires,
        tasks=tasks,
        reports=reports,
        advisories=MappingProxyType(advisories),
        repo_paths=repo_paths,
        repo_guards=repo_guards,
        semantic=semantic,
    )


def _load_inputs(
    public_tasks_file: str | os.PathLike[str],
    reports_file: str | os.PathLike[str],
    advisory_cache_file: str | os.PathLike[str],
    repo_map_file: str | os.PathLike[str],
    *,
    expected_public_tasks_sha256: str,
    expected_public_tasks_wire_sha256: str,
    expected_reports_sha256: str,
    expected_reports_wire_sha256: str,
    expected_advisory_cache_sha256: str,
    expected_advisory_cache_wire_sha256: str,
    expected_repo_map_sha256: str,
    expected_repo_map_wire_sha256: str,
    expected_task_count: int,
) -> _Inputs:
    expected = {
        "advisory_cache_sha256": _require_sha256(expected_advisory_cache_sha256, "expected_advisory_cache_sha256"),
        "public_tasks_sha256": _require_sha256(expected_public_tasks_sha256, "expected_public_tasks_sha256"),
        "reports_sha256": _require_sha256(expected_reports_sha256, "expected_reports_sha256"),
        "repo_map_sha256": _require_sha256(expected_repo_map_sha256, "expected_repo_map_sha256"),
    }
    expected_wires = tuple(
        _require_sha256(value, name)
        for value, name in (
            (expected_public_tasks_wire_sha256, "expected_public_tasks_wire_sha256"),
            (expected_reports_wire_sha256, "expected_reports_wire_sha256"),
            (expected_advisory_cache_wire_sha256, "expected_advisory_cache_wire_sha256"),
            (expected_repo_map_wire_sha256, "expected_repo_map_wire_sha256"),
        )
    )
    if type(expected_task_count) is not int or not 1 <= expected_task_count <= _MAX_TASKS:
        raise _error("invalid_count", "expected task count is invalid")
    inputs = _load_unpinned(public_tasks_file, reports_file, advisory_cache_file, repo_map_file)
    if len(inputs.tasks) != expected_task_count:
        raise _error("count_mismatch", "answer-free task count differs")
    if dict(inputs.semantic) != expected:
        raise _error("semantic_pin_mismatch", "a materializer input semantic pin differs")
    actual_wires = tuple(hashlib.sha256(item).hexdigest() for item in inputs.wires)
    if actual_wires != expected_wires:
        raise _error("wire_pin_mismatch", "a materializer input wire pin differs")
    return inputs


def compute_lane_a_assignment_input_pins(
    public_tasks_file: str | os.PathLike[str],
    reports_file: str | os.PathLike[str],
    advisory_cache_file: str | os.PathLike[str],
    repo_map_file: str | os.PathLike[str],
) -> dict[str, object]:
    """Compute review-time pins; ``build`` still requires them externally."""

    inputs = _load_unpinned(public_tasks_file, reports_file, advisory_cache_file, repo_map_file)
    return {
        **dict(inputs.semantic),
        "advisory_cache_wire_sha256": hashlib.sha256(inputs.wires[2]).hexdigest(),
        "public_tasks_wire_sha256": hashlib.sha256(inputs.wires[0]).hexdigest(),
        "reports_wire_sha256": hashlib.sha256(inputs.wires[1]).hexdigest(),
        "repo_map_wire_sha256": hashlib.sha256(inputs.wires[3]).hexdigest(),
        "task_count": len(inputs.tasks),
    }


def _candidate_commits(advisory: _Advisory, repo_url: str) -> tuple[str, ...]:
    expected = _repo_key(repo_url)
    candidates: set[str] = set()
    for reference in advisory.references:
        match = _COMMIT_URL_RE.fullmatch(reference)
        if match is None:
            continue
        referenced_repo = _repo_key(f"https://github.com/{match.group(1)}/{match.group(2)}")
        if referenced_repo == expected:
            candidates.add(match.group(3).lower())
    return tuple(sorted(candidates))


def _has_github_commit_reference(advisory: _Advisory) -> bool:
    return any(_COMMIT_URL_RE.fullmatch(reference) is not None for reference in advisory.references)


def _is_source(path: str) -> bool:
    return PurePosixPath(path).suffix.casefold() in _SOURCE_SUFFIXES


def _changed_source_paths(repository: GitRepository, before: str, after: str) -> tuple[str, ...]:
    try:
        changed_paths = repository.changed_paths(before, after)
    except GitFactError:
        raise _error("repository_fact_failed", "changed path facts could not be read") from None
    changed: list[str] = []
    for path in changed_paths:
        old = repository.tree_entry(before, path)
        new = repository.tree_entry(after, path)
        old_identity = (old.object_type, old.object_id) if old is not None else None
        new_identity = (new.object_type, new.object_id) if new is not None else None
        if old_identity == new_identity:
            continue
        try:
            canonical = validate_repo_relative_path(path)
            canonical.encode("utf-8", errors="strict")
        except (UnicodeError, ValueError):
            raise _error("invalid_source_path", "a changed repository path is unsafe") from None
        regular_old = old is None or (old.object_type == "blob" and old.mode in {"100644", "100755"})
        regular_new = new is None or (new.object_type == "blob" and new.mode in {"100644", "100755"})
        if _is_source(canonical) and regular_old and regular_new:
            changed.append(canonical)
    if not changed_paths:
        raise _error("missing_diff", "selected fix commit has no tree changes")
    if not changed:
        raise _error("non_source_diff", "selected fix commit changes no supported source file")
    if len(changed) > 64:
        raise _error("source_path_limit", "selected fix changes too many source files")
    return tuple(changed)


def _patch_bytes(repository: GitRepository, before: str, after: str, paths: tuple[str, ...]) -> bytes:
    parts: list[str] = []
    retained: list[str] = []
    size = 0
    for path in paths:
        try:
            diff = repository.diff_text_file(before, after, path)
        except GitFactError:
            raise _error("non_source_diff", "a changed source file has no bounded UTF-8 diff") from None
        if not diff.changed or not diff.unified_diff:
            continue
        text = f"diff --git a/{path} b/{path}\n{diff.unified_diff}"
        encoded = text.encode("utf-8")
        size += len(encoded)
        if size > _MAX_PATCH_BYTES:
            raise _error("patch_limit", "generated source patch exceeds its byte budget")
        parts.append(text)
        retained.append(path)
    if tuple(retained) != paths or not parts:
        raise _error("non_source_diff", "a changed source path has no textual content diff")
    return "".join(parts).encode("utf-8")


def _try_anchor_selection(
    task: BenchmarkTask,
    report: _Report,
    advisory: _Advisory,
    repository: GitRepository,
) -> tuple[_AnchorSelection | None, str | None]:
    actual_identifiers = {item["value"] for item in advisory.identifiers}
    if actual_identifiers != set(report.vuln_ids):
        return None, "advisory_identifier_mismatch"
    candidates = _candidate_commits(advisory, task.repo_url)
    if not candidates:
        return None, "fix_candidate_missing"
    matching: list[str] = []
    for candidate in candidates:
        try:
            parents = repository.commit_parents(candidate)
        except GitFactError:
            return None, "fix_candidate_unavailable"
        if parents == (task.commit,):
            matching.append(candidate)
    if len(matching) != 1:
        return (
            None,
            "ambiguous_fix_candidate" if len(matching) > 1 else "fix_parent_mismatch",
        )
    return (
        _AnchorSelection(
            report=report,
            entry_id=report.entry_ids[0],
            candidate_fix_commits=candidates,
            fix_commit=matching[0],
            anchor_policy=POLICY_ID,
            anchor_semantics=ANCHOR_SEMANTICS,
            candidate_source="public_advisory_commit_reference",
        ),
        None,
    )


def _select_anchor(
    task: BenchmarkTask,
    reports: Sequence[_Report],
    advisories: Mapping[str, _Advisory],
    repository: GitRepository,
) -> _AnchorSelection:
    selections: list[_AnchorSelection] = []
    failures: list[str] = []
    for report in reports:
        advisory = advisories.get(report.report_id)
        if advisory is None:
            failures.append("advisory_missing")
            continue
        selection, failure = _try_anchor_selection(
            task, report, advisory, repository
        )
        if selection is None:
            assert failure is not None
            failures.append(failure)
            continue
        selections.append(selection)
    distinct_fixes = sorted({selection.fix_commit for selection in selections})
    if len(distinct_fixes) > 1:
        raise _error(
            "ambiguous_report_candidate",
            "selected reports bind to multiple valid fix commits",
        )
    if selections:
        return sorted(selections, key=lambda item: item.report.report_id)[0]
    if any(
        (advisory := advisories.get(report.report_id)) is not None
        and _has_github_commit_reference(advisory)
        for report in reports
    ):
        if failures:
            raise _error(failures[0], "no selected report has a valid public anchor")
        raise _error("fix_candidate_missing", "no selected report has a public anchor")
    fallback_selections: list[_AnchorSelection] = []
    fallback_failures: list[str] = []
    local_children: tuple[str, ...] | None = None
    local_child_unavailable = False
    for report in reports:
        advisory = advisories.get(report.report_id)
        if advisory is None:
            continue
        actual_identifiers = {item["value"] for item in advisory.identifiers}
        if actual_identifiers != set(report.vuln_ids):
            continue
        if _has_github_commit_reference(advisory):
            continue
        if local_children is None and not local_child_unavailable:
            try:
                local_children = repository.direct_child_commits(task.commit)
            except GitFactError:
                local_child_unavailable = True
        if local_child_unavailable:
            fallback_failures.append("fix_candidate_unavailable")
            continue
        assert local_children is not None
        if len(local_children) != 1:
            fallback_failures.append(
                "ambiguous_fix_candidate" if len(local_children) > 1 else "fix_candidate_missing"
            )
            continue
        fallback_selections.append(
            _AnchorSelection(
                report=report,
                entry_id=report.entry_ids[0],
                candidate_fix_commits=local_children,
                fix_commit=local_children[0],
                anchor_policy=LOCAL_DIRECT_CHILD_POLICY_ID,
                anchor_semantics=LOCAL_DIRECT_CHILD_ANCHOR_SEMANTICS,
                candidate_source="local_commit_graph_direct_child",
            )
        )
    fallback_distinct_fixes = sorted(
        {selection.fix_commit for selection in fallback_selections}
    )
    if len(fallback_distinct_fixes) > 1:
        raise _error(
            "ambiguous_report_candidate",
            "selected fallback reports bind to multiple valid fix commits",
        )
    if fallback_selections:
        return sorted(fallback_selections, key=lambda item: item.report.report_id)[0]
    if fallback_failures:
        raise _error(
            fallback_failures[0],
            "no selected report has a unique local direct-child anchor",
        )
    if failures:
        raise _error(failures[0], "no selected report has a valid public anchor")
    raise _error("advisory_missing", "a selected report is absent from the advisory cache")


def _file_record(path: str, payload: bytes, kind: str) -> dict[str, object]:
    return {
        "byte_count": len(payload),
        "content_sha256": hashlib.sha256(payload).hexdigest(),
        "kind": kind,
        "path": path,
    }


def _storage_seal(repository: GitRepository) -> object:
    return repository.capture_storage_seal()


def _build_payloads(inputs: _Inputs) -> tuple[dict[str, bytes], LaneAAssignmentMaterializationManifestV1]:
    by_snapshot: dict[tuple[str, str], list[_Report]] = {}
    for report in inputs.reports:
        by_snapshot.setdefault((_repo_key(report.repo_url), report.commit), []).append(report)
    payloads: dict[str, bytes] = {}
    assignments: list[dict[str, object]] = []
    audits: list[dict[str, object]] = []
    selections: list[dict[str, object]] = []
    repo_seals: dict[str, object] = {}
    repositories: dict[str, GitRepository] = {}
    for task in inputs.tasks:
        reports = sorted(
            by_snapshot.get((_repo_key(task.repo_url), task.commit), ()),
            key=lambda item: item.report_id,
        )
        if not reports:
            raise _error("report_missing", "a public task has no exact normalized report match")
        repo_key = _repo_key(task.repo_url)
        repo_path = inputs.repo_paths.get(repo_key)
        if repo_path is None:
            raise _error("repository_missing", "a public task is absent from the offline repository map")
        repository = repositories.get(repo_key)
        if repository is None:
            try:
                _assert_chain(inputs.repo_guards[repo_key])
                # Match the downstream T2 toolbox exactly: every artifact and
                # Git fact accepted here must remain consumable during a run.
                repository = GitRepository(
                    repo_path,
                    max_blob_bytes=MAX_GIT_BLOB_BYTES,
                    max_diff_input_bytes=2 * MAX_GIT_BLOB_BYTES,
                    max_diff_output_bytes=MAX_GIT_DIFF_BYTES,
                )
                initial_seal = _storage_seal(repository)
                _assert_chain(inputs.repo_guards[repo_key])
            except (GitFactError, OSError, ValueError):
                raise _error("repository_unsafe", "an offline repository snapshot is unavailable or unsafe") from None
            repositories[repo_key] = repository
            repo_seals[repo_key] = initial_seal
        anchor = _select_anchor(task, reports, inputs.advisories, repository)
        selected = anchor.report
        entry_id = anchor.entry_id
        advisory = inputs.advisories[selected.report_id]
        candidates = anchor.candidate_fix_commits
        fix_commit = anchor.fix_commit
        try:
            source_paths = _changed_source_paths(repository, task.commit, fix_commit)
            patch = _patch_bytes(repository, task.commit, fix_commit, source_paths)
            fix_tree = repository.commit_tree(fix_commit)
            vulnerable_tree = repository.commit_tree(task.commit)
        except GitFactError:
            raise _error("repository_fact_failed", "offline repository facts could not be closed") from None
        advisory_name = f"advisory-{selected.report_id}.json"
        patch_name = f"patch-{selected.report_id}.diff"
        advisory_value = {
            "description": advisory.description,
            "fix_commits": [fix_commit],
            "ghsa_id": advisory.ghsa_id,
            "identifiers": [dict(item) for item in advisory.identifiers],
            "source_link": selected.source_link,
            "summary": advisory.summary,
        }
        advisory_wire = _line(advisory_value)
        if len(advisory_wire) > MAX_LOCAL_FILE_BYTES:
            raise _error(
                "advisory_limit",
                "materialized advisory exceeds the downstream T2 file budget",
            )
        advisory_facts = extract_advisory_facts(
            LoadedEvidenceFile(
                kind="advisory",
                relative_path=advisory_name,
                text=advisory_wire.decode("utf-8", errors="strict"),
                byte_size=len(advisory_wire),
                sha256=hashlib.sha256(advisory_wire).hexdigest(),
            )
        )
        if advisory_facts.vuln_ids != selected.vuln_ids:
            raise _error(
                "advisory_identifier_mismatch",
                "materialized advisory identifiers differ from the public report",
            )
        if (
            advisory_facts.ghsa_ids != (selected.report_id,)
            or advisory_facts.fix_commits != (fix_commit,)
            or advisory_facts.source_link != selected.source_link
        ):
            raise _error(
                "advisory_ambiguous",
                "materialized advisory facts are not uniquely bound to the selected fix",
            )
        payloads[advisory_name] = advisory_wire
        payloads[patch_name] = patch
        assignment = LaneAAssignmentV1(
            task_id=task.task_id,
            report_id=selected.report_id,
            entry_id=entry_id,
            package=PackageSpec(advisory=advisory_name, references=(), patches=(patch_name,)),
            hints=T2Hints(
                project=selected.project,
                fix_commits=(fix_commit,),
                source_paths=source_paths,
                entry_symbols=(),
                critical_mode="auto",
            ),
        ).to_dict()
        assignment = LaneAAssignmentV1.from_dict(assignment).to_dict()
        assignments.append(assignment)
        not_run = [
            {"entry_ids": list(report.entry_ids[1:] if report is selected else report.entry_ids), "report_id": report.report_id}
            for report in reports
            if report is not selected or len(report.entry_ids) > 1
        ]
        audits.append(
            {
                "anchor_candidate_source": anchor.candidate_source,
                "anchor_policy": anchor.anchor_policy,
                "anchor_semantics": anchor.anchor_semantics,
                "not_run": not_run,
                "selected_entry_id": entry_id,
                "selected_report_id": selected.report_id,
                "task_id": task.task_id,
            }
        )
        selections.append(
            {
                "advisory_path": advisory_name,
                "anchor_candidate_source": anchor.candidate_source,
                "anchor_policy": anchor.anchor_policy,
                "candidate_fix_commits": list(candidates),
                "entry_id": entry_id,
                "fix_commit": fix_commit,
                "patch_path": patch_name,
                "report_id": selected.report_id,
                "source_paths": list(source_paths),
                "task_id": task.task_id,
                "fix_tree": fix_tree,
                "vulnerable_commit": task.commit,
                "vulnerable_tree": vulnerable_tree,
            }
        )
    for key, repository in repositories.items():
        try:
            closing_seal = _storage_seal(repository)
            _assert_chain(inputs.repo_guards[key])
        except (GitFactError, OSError, ValueError):
            raise _error("input_changed", "an offline repository changed during materialization") from None
        if closing_seal != repo_seals[key]:
            raise _error("input_changed", "an offline repository changed during materialization")
    assignments_wire = b"".join(_line(item) for item in assignments)
    audit_wire = b"".join(_line(item) for item in audits)
    payloads[ASSIGNMENTS_FILENAME] = assignments_wire
    payloads[COVERAGE_AUDIT_FILENAME] = audit_wire
    file_records = [
        _file_record(
            name,
            payload,
            "assignments" if name == ASSIGNMENTS_FILENAME else
            "coverage_audit" if name == COVERAGE_AUDIT_FILENAME else
            "advisory" if name.startswith("advisory-") else "patch",
        )
        for name, payload in sorted(payloads.items())
    ]
    core = {
        "assignment_count": len(assignments),
        "assignments_sha256": _semantic(ASSIGNMENTS_DOMAIN, assignments),
        "contract_version": CONTRACT_VERSION,
        "coverage_audit_sha256": _semantic(COVERAGE_DOMAIN, audits),
        "files": file_records,
        "inputs": {
            **dict(inputs.semantic),
            "advisory_cache_wire_sha256": hashlib.sha256(inputs.wires[2]).hexdigest(),
            "public_tasks_wire_sha256": hashlib.sha256(inputs.wires[0]).hexdigest(),
            "reports_wire_sha256": hashlib.sha256(inputs.wires[1]).hexdigest(),
            "repo_map_wire_sha256": hashlib.sha256(inputs.wires[3]).hexdigest(),
        },
        "kind": MATERIALIZATION_KIND,
        "policy_id": POLICY_ID,
        "selected": selections,
        "task_count": len(inputs.tasks),
    }
    materialization_sha256 = _semantic(MATERIALIZATION_DOMAIN, core)
    manifest = {**core, "materialization_sha256": materialization_sha256}
    payloads[MANIFEST_FILENAME] = _line(manifest)
    combined = b"".join(payloads.values()).lower()
    if any(marker in combined for marker in _FORBIDDEN_WIRE_MARKERS):
        raise _error("private_marker", "materialized output contains an answer/control marker")
    return payloads, LaneAAssignmentMaterializationManifestV1(
        materialization_sha256=materialization_sha256,
        manifest_wire_sha256=hashlib.sha256(payloads[MANIFEST_FILENAME]).hexdigest(),
        task_count=len(inputs.tasks),
        assignments_sha256=core["assignments_sha256"],
        assignments_wire_sha256=hashlib.sha256(assignments_wire).hexdigest(),
        coverage_audit_sha256=core["coverage_audit_sha256"],
    )


def _read_payloads(root: Path, names: frozenset[str]) -> dict[str, bytes]:
    state = _require_directory(root, private=True)
    identity = _directory_identity(state)
    try:
        entries = tuple(os.scandir(_windows_extended_path(root)))
    except OSError:
        raise _error("directory_unavailable", "materialization cannot be enumerated") from None
    if frozenset(item.name for item in entries) != names:
        raise _error("layout_mismatch", "materialization file set differs")
    for entry in entries:
        try:
            item_state = os.lstat(entry.path)
        except OSError:
            raise _error("input_changed", "materialization changed while enumerating") from None
        if (
            not stat.S_ISREG(item_state.st_mode)
            or stat.S_ISLNK(item_state.st_mode)
            or _is_reparse(item_state)
            or item_state.st_nlink != 1
        ):
            raise _error("unsafe_path", "materialization contains an unsafe member")
    payloads = {name: _read_regular(root / name, maximum=_MAX_INPUT_BYTES)[1] for name in sorted(names)}
    if _directory_identity(_require_directory(root, private=True)) != identity:
        raise _error("input_changed", "materialization directory changed while reading")
    return payloads


def _read_payloads_at(descriptor: int, names: frozenset[str]) -> dict[str, bytes]:
    try:
        actual = frozenset(item.name for item in os.scandir(descriptor))
    except OSError:
        raise _error("directory_unavailable", "materialization cannot be enumerated") from None
    if actual != names:
        raise _error("layout_mismatch", "materialization file set differs")
    return {
        name: _read_regular_at(descriptor, name, maximum=_MAX_INPUT_BYTES)
        for name in sorted(names)
    }


def _assert_output_disjoint(
    output: Path,
    inputs: _Inputs,
    protected_paths: Sequence[str | os.PathLike[str]],
) -> tuple[tuple[Path, tuple[int, int]], ...]:
    for guard in inputs.repo_guards.values():
        _assert_chain(guard)
    candidates: list[tuple[Path, bool]] = [(path, False) for path in inputs.paths]
    candidates.extend((path, True) for path in inputs.repo_paths.values())
    for raw in protected_paths:
        path = Path(raw)
        try:
            state = os.lstat(_windows_extended_path(path))
            canonical = _canonical_existing_path(path, directory=stat.S_ISDIR(state.st_mode), status=2)
        except Exception:
            raise _error("path_check_failed", "a protected path cannot be checked") from None
        candidates.append((canonical, stat.S_ISDIR(state.st_mode)))
    output_guard = _guard_chain(output.parent, final_private=True)
    output_ids = {item[1] for item in output_guard}
    for path, directory in candidates:
        if paths_overlap_v1(output, path, left_exists=False, right_directory=directory):
            raise _error("path_overlap", "output overlaps a trusted input")
        if directory:
            chain = _guard_chain(path)
            identities = {item[1] for item in chain}
            protected_identity = _directory_identity(_require_directory(path))
            if protected_identity in output_ids or output_guard[-1][1] in identities:
                raise _error("path_overlap", "output aliases a trusted input directory")
    _assert_chain(output_guard, final_private=True)
    return output_guard


def _publish(
    output_dir: str | os.PathLike[str],
    payloads: Mapping[str, bytes],
    manifest: LaneAAssignmentMaterializationManifestV1,
    inputs: _Inputs,
    protected_paths: Sequence[str | os.PathLike[str]],
) -> LaneAAssignmentMaterializationManifestV1:
    try:
        output = _canonical_new_child(output_dir, status=2)
    except Exception:
        raise _error("invalid_output", "materialization output path is invalid") from None
    guard = _assert_output_disjoint(output, inputs, protected_paths)
    try:
        os.lstat(_windows_extended_path(output))
    except FileNotFoundError:
        pass
    except OSError:
        raise _error("output_unavailable", "materialization output state is unavailable") from None
    else:
        raise _error("output_exists", "materialization output already exists")
    staging = output.parent / f".{output.name}.lane-a-assignment-{uuid.uuid4().hex}"
    committed = False
    names = frozenset(payloads)
    parent_descriptor: int | None = None
    staging_descriptor: int | None = None
    output_descriptor: int | None = None
    windows_parent_handle: int | None = None
    staging_identity: tuple[int, int] | None = None
    try:
        for name in names:
            if "/" in name or "\\" in name or name in {"", ".", ".."}:
                raise _error("publication_failed", "materialization output name is unsafe")
        if os.name == "posix":
            parent_descriptor = _open_bound_directory(output.parent, guard[-1][1])
            if _identity_at(parent_descriptor, output.name) is not None:
                raise _error("output_exists", "materialization output already exists")
            os.mkdir(staging.name, 0o700, dir_fd=parent_descriptor)
            created = os.stat(staging.name, dir_fd=parent_descriptor, follow_symlinks=False)
            staging_identity = _directory_identity(created)
            staging_descriptor = _open_bound_directory(
                staging.name, staging_identity, dir_fd=parent_descriptor
            )
            for name in sorted(names):
                _write_file(name, payloads[name], dir_fd=staging_descriptor)
            os.fsync(staging_descriptor)
            before = _read_payloads_at(staging_descriptor, names)
        else:
            windows_parent_handle = _open_windows_directory_lock(output.parent)
            _assert_chain(guard, final_private=True)
            os.mkdir(_windows_extended_path(staging), 0o700)
            staging_identity = _directory_identity(_require_directory(staging, private=True))
            for name in sorted(names):
                _write_file(staging / name, payloads[name])
            before = _read_payloads(staging, names)
        if before != dict(payloads):
            raise _error("publication_failed", "materialization staging readback differs")
        _assert_chain(guard, final_private=True)
        observed = (
            _identity_at(parent_descriptor, staging.name)
            if parent_descriptor is not None
            else _directory_identity(_require_directory(staging, private=True))
        )
        if observed != staging_identity:
            raise _error("publication_changed", "materialization staging identity changed")
        try:
            if parent_descriptor is not None:
                _rename_noreplace(
                    Path(staging.name),
                    Path(output.name),
                    source_dir_fd=parent_descriptor,
                    destination_dir_fd=parent_descriptor,
                )
            else:
                _rename_noreplace(staging, output)
            committed = True
        except BaseException as error:
            if parent_descriptor is not None:
                stage_after = _identity_at(parent_descriptor, staging.name)
                output_after = _identity_at(parent_descriptor, output.name)
            else:
                stage_after = _named_directory_identity(staging)
                output_after = _named_directory_identity(output)
            if stage_after is None and output_after == staging_identity:
                committed = True
            elif stage_after == staging_identity and output_after != staging_identity:
                if isinstance(error, KeyboardInterrupt):
                    raise
                raise _error("output_exists" if isinstance(error, FileExistsError) else "publication_failed", "no-replace publication failed") from None
            else:
                raise _error("publication_uncertain", "publication state is uncertain", committed=True) from None
        if parent_descriptor is not None:
            os.fsync(parent_descriptor)
            if _identity_at(parent_descriptor, output.name) != staging_identity:
                raise _error("publication_uncertain", "published identity differs", committed=True)
            output_descriptor = _open_bound_directory(
                output.name, staging_identity, dir_fd=parent_descriptor
            )
            after = _read_payloads_at(output_descriptor, names)
            second = _read_payloads_at(output_descriptor, names)
        else:
            if _named_directory_identity(output) != staging_identity:
                raise _error("publication_uncertain", "published identity differs", committed=True)
            after = _read_payloads(output, names)
            second = _read_payloads(output, names)
        _assert_chain(guard, final_private=True)
        if after != before or second != before:
            raise _error("publication_uncertain", "published readback differs", committed=True)
        if hashlib.sha256(after[MANIFEST_FILENAME]).hexdigest() != manifest.manifest_wire_sha256:
            raise _error("publication_uncertain", "published manifest differs", committed=True)
        return manifest
    except LaneATaskBundleError as error:
        if committed and not error.committed:
            raise _error("publication_uncertain", "published output could not be confirmed", committed=True) from None
        raise
    except KeyboardInterrupt:
        if committed:
            raise _error("publication_uncertain", "published output could not be confirmed", committed=True) from None
        raise
    except BaseException:
        raise _error("publication_uncertain" if committed else "publication_failed", "publication failed", committed=committed) from None
    finally:
        active = __import__("sys").exc_info()[0] is not None
        close_failed = False
        for descriptor in (output_descriptor, staging_descriptor, parent_descriptor):
            if descriptor is not None:
                try:
                    _close_publication_descriptor(descriptor)
                except BaseException:
                    close_failed = True
        if windows_parent_handle is not None:
            try:
                _close_windows_handle(windows_parent_handle)
            except BaseException:
                close_failed = True
        if close_failed and not active:
            raise _error(
                "publication_uncertain" if committed else "publication_failed",
                "publication resource close failed",
                committed=committed,
            ) from None


def _common_build(
    public_tasks_file: str | os.PathLike[str],
    reports_file: str | os.PathLike[str],
    advisory_cache_file: str | os.PathLike[str],
    repo_map_file: str | os.PathLike[str],
    **pins: object,
) -> tuple[_Inputs, dict[str, bytes], LaneAAssignmentMaterializationManifestV1]:
    inputs = _load_inputs(public_tasks_file, reports_file, advisory_cache_file, repo_map_file, **pins)
    payloads, manifest = _build_payloads(inputs)
    try:
        repeated = _load_inputs(
            public_tasks_file,
            reports_file,
            advisory_cache_file,
            repo_map_file,
            **pins,
        )
    except LaneATaskBundleError as error:
        if error.code in {
            "wire_pin_mismatch",
            "semantic_pin_mismatch",
            "input_changed",
            "input_unavailable",
        }:
            raise _error("input_changed", "a pinned materializer input changed") from None
        raise
    repeated_payloads, repeated_manifest = _build_payloads(repeated)
    if repeated.wires != inputs.wires or repeated_payloads != payloads or repeated_manifest != manifest:
        raise _error("input_changed", "pinned materializer inputs changed")
    return repeated, payloads, manifest


def write_lane_a_assignment_materialization(
    output_dir: str | os.PathLike[str],
    public_tasks_file: str | os.PathLike[str],
    reports_file: str | os.PathLike[str],
    advisory_cache_file: str | os.PathLike[str],
    repo_map_file: str | os.PathLike[str],
    *,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
    **pins: object,
) -> LaneAAssignmentMaterializationManifestV1:
    inputs, payloads, manifest = _common_build(
        public_tasks_file, reports_file, advisory_cache_file, repo_map_file, **pins
    )
    return _publish(output_dir, payloads, manifest, inputs, protected_paths)


def verify_lane_a_assignment_materialization(
    materialization_dir: str | os.PathLike[str],
    public_tasks_file: str | os.PathLike[str],
    reports_file: str | os.PathLike[str],
    advisory_cache_file: str | os.PathLike[str],
    repo_map_file: str | os.PathLike[str],
    *,
    expected_materialization_sha256: str,
    expected_manifest_wire_sha256: str,
    **pins: object,
) -> LaneAAssignmentMaterializationManifestV1:
    expected_materialization = _require_sha256(expected_materialization_sha256, "expected_materialization_sha256")
    expected_manifest_wire = _require_sha256(expected_manifest_wire_sha256, "expected_manifest_wire_sha256")
    _inputs, expected_payloads, manifest = _common_build(
        public_tasks_file, reports_file, advisory_cache_file, repo_map_file, **pins
    )
    if manifest.materialization_sha256 != expected_materialization or manifest.manifest_wire_sha256 != expected_manifest_wire:
        raise _error("materialization_pin_mismatch", "expected materialization pins differ")
    try:
        root = _canonical_existing_path(materialization_dir, directory=True, status=2)
    except Exception:
        raise _error("unsafe_path", "materialization directory is unavailable") from None
    names = frozenset(expected_payloads)
    first = _read_payloads(root, names)
    second = _read_payloads(root, names)
    if first != expected_payloads or second != expected_payloads:
        raise _error("source_binding_mismatch", "materialization bytes differ from pinned inputs")
    return manifest


__all__ = [
    "ADVISORY_CACHE_DOMAIN",
    "ASSIGNMENTS_FILENAME",
    "COVERAGE_AUDIT_FILENAME",
    "LaneAAssignmentMaterializationManifestV1",
    "LaneAAssignmentMaterializerError",
    "MANIFEST_FILENAME",
    "MATERIALIZATION_KIND",
    "POLICY_ID",
    "REPORTS_DOMAIN",
    "REPO_MAP_DOMAIN",
    "compute_lane_a_assignment_input_pins",
    "verify_lane_a_assignment_materialization",
    "write_lane_a_assignment_materialization",
]
