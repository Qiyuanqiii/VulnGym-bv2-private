"""Strict standard-library adapter for official VulnGym entry rows.

``SCHEMA.md`` is the source of truth.  This adapter performs the semantic
checks that JSON Schema cannot express (notably ordered line ranges and
cross-field advisory IDs), while keeping internal sidecar fields out of the
official output.
"""

from __future__ import annotations

from copy import deepcopy
import json
import re
from typing import Any, Final, Mapping

from vulngym_agent.models import (
    SchemaAdapterError,
    SchemaIssue,
    SchemaValidationResult,
)


ENTRY_FIELDS = (
    "commit",
    "critical_operation",
    "entry_id",
    "entry_point",
    "origin",
    "project",
    "repo_url",
    "report_id",
    "source_link",
    "trace",
    "verify",
    "vuln_category_l1",
    "vuln_category_l2",
    "vuln_ids",
    "vuln_title",
)
LOCATION_FIELDS = ("code", "desc", "file", "line")
REQUIRED_LOCATION_FIELDS = ("code", "file", "line")
ORIGIN = "GitHub Advisory Database (reviewed)"
MAX_TRACE_NODES: Final[int] = 256

_ENTRY_FIELD_SET = frozenset(ENTRY_FIELDS)
_LOCATION_FIELD_SET = frozenset(LOCATION_FIELDS)
_REQUIRED_LOCATION_FIELD_SET = frozenset(REQUIRED_LOCATION_FIELDS)
_GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_ENTRY_ID_RE = re.compile(r"^entry-[0-9]{5}$")
_RANGE_RE = re.compile(r"^([1-9][0-9]*)-([1-9][0-9]*)$")
_ADVISORY_URL_RE = re.compile(
    r"^https://github\.com/advisories/(GHSA-[0-9A-Za-z]{4}-"
    r"[0-9A-Za-z]{4}-[0-9A-Za-z]{4})/?$"
)
_SIMPLE_PATH_MEMBER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _add_issue(
    issues: list[SchemaIssue],
    path: str,
    code: str,
    message: str,
    **context: Any,
) -> None:
    issues.append(
        SchemaIssue(path=path, code=code, message=message, context=context)
    )


def _path_member(parent: str, key: Any) -> str:
    """Append one unambiguous object member to a JSONPath-like path."""

    if isinstance(key, str) and _SIMPLE_PATH_MEMBER_RE.fullmatch(key):
        return f"{parent}.{key}"
    printable = key if isinstance(key, str) else str(key)
    return f"{parent}[{json.dumps(printable, ensure_ascii=True)}]"


def _normalize_identifier_list(value: Any) -> Any:
    if not isinstance(value, list):
        return value

    normalized: list[Any] = []
    seen_strings: set[str] = set()
    for item in value:
        if isinstance(item, str):
            item = item.upper()
            if item in seen_strings:
                continue
            seen_strings.add(item)
        normalized.append(item)

    # Preserve source order within each identifier family, but make the
    # contractually required CVE-before-GHSA grouping deterministic.
    return sorted(
        normalized,
        key=lambda item: (
            0
            if isinstance(item, str) and item.startswith("CVE-")
            else 1
            if isinstance(item, str) and item.startswith("GHSA-")
            else 2
        ),
    )


def _normalize_location(location: Any) -> None:
    if not isinstance(location, dict):
        return
    line = location.get("line")
    if isinstance(line, str) and line.isascii() and line.isdigit():
        try:
            location["line"] = int(line)
        except ValueError:
            # Python bounds decimal conversion length.  Leave an extreme value
            # unchanged so validation reports it instead of aborting the batch.
            pass


def _ordered_location(location: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(location[key])
        for key in LOCATION_FIELDS
        if key in location
    }


def _ordered_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    ordered: dict[str, Any] = {}
    for key in ENTRY_FIELDS:
        value = entry[key]
        if key in {"entry_point", "critical_operation"}:
            ordered[key] = _ordered_location(value)
        elif key == "trace":
            ordered[key] = [_ordered_location(item) for item in value]
        else:
            ordered[key] = deepcopy(value)
    return ordered


class SchemaAdapter:
    """Normalize and validate official VulnGym entry objects.

    ``validate`` checks an already-formal row without changing it.
    ``adapt`` additionally accepts positive numeric strings for location
    lines, canonicalizes IDs, and optionally enforces the T2 ``verify = 0``
    rule.  Both paths reject every unknown field and report all discovered
    issues in one result/error.
    """

    def __init__(self, *, max_trace_nodes: int = MAX_TRACE_NODES) -> None:
        if (
            isinstance(max_trace_nodes, bool)
            or not isinstance(max_trace_nodes, int)
            or not 1 <= max_trace_nodes <= MAX_TRACE_NODES
        ):
            raise ValueError(
                "max_trace_nodes must be an integer from 1 to "
                f"{MAX_TRACE_NODES}"
            )
        self.max_trace_nodes = max_trace_nodes

    def validate(
        self, entry: Any, *, formal_t2: bool = False
    ) -> SchemaValidationResult:
        return SchemaValidationResult(
            tuple(self._collect_entry_issues(entry, formal_t2=formal_t2))
        )

    def validate_or_raise(
        self, entry: Any, *, formal_t2: bool = False
    ) -> None:
        self.validate(entry, formal_t2=formal_t2).raise_for_errors()

    def normalize(self, entry: Any) -> dict[str, Any]:
        """Canonicalize a normal dataset row while preserving its verify flag."""

        return self.adapt(entry, formal_t2=False)

    def adapt(
        self, entry: Any, *, formal_t2: bool = True
    ) -> dict[str, Any]:
        """Return a canonical official row or raise ``SchemaAdapterError``.

        In formal T2 mode, ``verify`` is deterministically set to ``0``.  It is
        the only required field the adapter may insert; missing content-bearing
        fields are reported instead of being invented.
        """

        if not isinstance(entry, Mapping):
            issue = SchemaIssue(
                path="$",
                code="type_error",
                message="entry must be a JSON object",
                context={"expected": "object", "actual": type(entry).__name__},
            )
            raise SchemaAdapterError((issue,))

        candidate = deepcopy(dict(entry))
        report_id = candidate.get("report_id")
        if isinstance(report_id, str):
            candidate["report_id"] = report_id.upper()
        if "vuln_ids" in candidate:
            candidate["vuln_ids"] = _normalize_identifier_list(
                candidate["vuln_ids"]
            )

        _normalize_location(candidate.get("entry_point"))
        _normalize_location(candidate.get("critical_operation"))
        trace = candidate.get("trace")
        if isinstance(trace, list):
            for item in trace:
                _normalize_location(item)

        if formal_t2:
            candidate["verify"] = 0

        result = self.validate(candidate, formal_t2=formal_t2)
        result.raise_for_errors()
        return _ordered_entry(candidate)

    def dumps(
        self, entry: Any, *, formal_t2: bool = True, ensure_ascii: bool = False
    ) -> str:
        """Adapt an entry and serialize it as one stable JSONL-compatible row."""

        adapted = self.adapt(entry, formal_t2=formal_t2)
        return json.dumps(adapted, ensure_ascii=ensure_ascii, sort_keys=True)

    def _collect_entry_issues(
        self, entry: Any, *, formal_t2: bool
    ) -> list[SchemaIssue]:
        issues: list[SchemaIssue] = []
        if not isinstance(entry, Mapping):
            _add_issue(
                issues,
                "$",
                "type_error",
                "entry must be a JSON object",
                expected="object",
                actual=type(entry).__name__,
            )
            return issues

        actual_keys = set(entry)
        for key in sorted(actual_keys - _ENTRY_FIELD_SET, key=str):
            _add_issue(
                issues,
                _path_member("$", key),
                "extra_field",
                "field is not allowed in an official VulnGym entry",
            )
        for key in sorted(_ENTRY_FIELD_SET - actual_keys):
            _add_issue(
                issues,
                f"$.{key}",
                "missing_required",
                "required field is missing; the adapter will not invent it",
            )

        self._validate_string(entry, "project", issues)
        self._validate_string(entry, "vuln_title", issues)
        self._validate_string(entry, "vuln_category_l1", issues)
        self._validate_string(entry, "vuln_category_l2", issues)

        self._validate_pattern(
            entry, "entry_id", _ENTRY_ID_RE, "entry- followed by five digits", issues
        )
        self._validate_pattern(
            entry, "report_id", _GHSA_RE, "upper-case GHSA identifier", issues
        )
        self._validate_pattern(
            entry, "commit", _COMMIT_RE, "40 lower-case hexadecimal characters", issues
        )

        if "origin" in entry:
            origin = entry["origin"]
            if not isinstance(origin, str):
                _add_issue(
                    issues,
                    "$.origin",
                    "type_error",
                    "origin must be a string",
                    expected="string",
                    actual=type(origin).__name__,
                )
            elif origin != ORIGIN:
                _add_issue(
                    issues,
                    "$.origin",
                    "invalid_value",
                    f"origin must equal {ORIGIN!r}",
                )

        if "repo_url" in entry:
            repo_url = entry["repo_url"]
            if not isinstance(repo_url, str):
                _add_issue(
                    issues,
                    "$.repo_url",
                    "type_error",
                    "repo_url must be a string",
                    expected="string",
                    actual=type(repo_url).__name__,
                )
            elif not repo_url.startswith("https://github.com/"):
                _add_issue(
                    issues,
                    "$.repo_url",
                    "invalid_format",
                    "repo_url must start with https://github.com/",
                )

        self._validate_source_link(entry, issues)
        self._validate_vuln_ids(entry, issues)

        if "entry_point" in entry:
            self._validate_location(entry["entry_point"], "$.entry_point", issues)
        if "critical_operation" in entry:
            self._validate_location(
                entry["critical_operation"], "$.critical_operation", issues
            )
        if "trace" in entry:
            trace = entry["trace"]
            if not isinstance(trace, list):
                _add_issue(
                    issues,
                    "$.trace",
                    "type_error",
                    "trace must be an array",
                    expected="array",
                    actual=type(trace).__name__,
                )
            else:
                if len(trace) > self.max_trace_nodes:
                    _add_issue(
                        issues,
                        "$.trace",
                        "max_items",
                        "trace exceeds the configured node limit",
                        maximum=self.max_trace_nodes,
                        actual=len(trace),
                    )
                else:
                    for index, location in enumerate(trace):
                        self._validate_location(
                            location, f"$.trace[{index}]", issues
                        )

        if "verify" in entry:
            verify = entry["verify"]
            if not _is_integer(verify):
                _add_issue(
                    issues,
                    "$.verify",
                    "type_error",
                    "verify must be the integer 0 or 1",
                    expected="integer",
                    actual=type(verify).__name__,
                )
            elif verify not in (0, 1):
                _add_issue(
                    issues,
                    "$.verify",
                    "invalid_value",
                    "verify must be exactly 0 or 1",
                )
            elif formal_t2 and verify != 0:
                _add_issue(
                    issues,
                    "$.verify",
                    "t2_verify_not_zero",
                    "formal T2 output must set verify to 0",
                )

        return issues

    @staticmethod
    def _validate_string(
        entry: Mapping[str, Any], key: str, issues: list[SchemaIssue]
    ) -> None:
        if key in entry and not isinstance(entry[key], str):
            _add_issue(
                issues,
                f"$.{key}",
                "type_error",
                f"{key} must be a string",
                expected="string",
                actual=type(entry[key]).__name__,
            )

    @staticmethod
    def _validate_pattern(
        entry: Mapping[str, Any],
        key: str,
        pattern: re.Pattern[str],
        expected: str,
        issues: list[SchemaIssue],
    ) -> None:
        if key not in entry:
            return
        value = entry[key]
        if not isinstance(value, str):
            _add_issue(
                issues,
                f"$.{key}",
                "type_error",
                f"{key} must be a string",
                expected="string",
                actual=type(value).__name__,
            )
        elif not pattern.fullmatch(value):
            _add_issue(
                issues,
                f"$.{key}",
                "invalid_format",
                f"{key} must be {expected}",
            )

    @staticmethod
    def _validate_source_link(
        entry: Mapping[str, Any], issues: list[SchemaIssue]
    ) -> None:
        if "source_link" not in entry:
            return
        source_link = entry["source_link"]
        if not isinstance(source_link, str):
            _add_issue(
                issues,
                "$.source_link",
                "type_error",
                "source_link must be a string",
                expected="string",
                actual=type(source_link).__name__,
            )
            return
        match = _ADVISORY_URL_RE.fullmatch(source_link)
        if not match:
            _add_issue(
                issues,
                "$.source_link",
                "invalid_format",
                "source_link must be a canonical GitHub Advisory URL",
            )
            return
        report_id = entry.get("report_id")
        if isinstance(report_id, str) and match.group(1).upper() != report_id.upper():
            _add_issue(
                issues,
                "$.source_link",
                "cross_field_mismatch",
                "the advisory ID in source_link must equal report_id",
                report_id=report_id,
                source_link_id=match.group(1),
            )

    @staticmethod
    def _validate_vuln_ids(
        entry: Mapping[str, Any], issues: list[SchemaIssue]
    ) -> None:
        if "vuln_ids" not in entry:
            return
        vuln_ids = entry["vuln_ids"]
        if not isinstance(vuln_ids, list):
            _add_issue(
                issues,
                "$.vuln_ids",
                "type_error",
                "vuln_ids must be an array",
                expected="array",
                actual=type(vuln_ids).__name__,
            )
            return

        seen: set[str] = set()
        encountered_ghsa = False
        for index, identifier in enumerate(vuln_ids):
            path = f"$.vuln_ids[{index}]"
            if not isinstance(identifier, str):
                _add_issue(
                    issues,
                    path,
                    "type_error",
                    "vulnerability identifier must be a string",
                    expected="string",
                    actual=type(identifier).__name__,
                )
                continue
            if identifier != identifier.upper():
                _add_issue(
                    issues,
                    path,
                    "invalid_format",
                    "vulnerability identifiers must be upper-case",
                )
            # ``SCHEMA.md`` permits all known identifier families (the dataset
            # currently also contains ZDI IDs).  Apply family-specific format
            # checks only when a value claims to be a CVE or GHSA.
            if identifier.startswith("CVE-") and not _CVE_RE.fullmatch(identifier):
                _add_issue(
                    issues,
                    path,
                    "invalid_format",
                    "CVE identifier has an invalid format",
                )
            elif identifier.startswith("GHSA-") and not _GHSA_RE.fullmatch(identifier):
                _add_issue(
                    issues,
                    path,
                    "invalid_format",
                    "GHSA identifier has an invalid format",
                )
            if identifier in seen:
                _add_issue(
                    issues,
                    path,
                    "duplicate_value",
                    "vuln_ids must be deduplicated",
                )
            seen.add(identifier)
            if identifier.startswith("GHSA-"):
                encountered_ghsa = True
            elif identifier.startswith("CVE-") and encountered_ghsa:
                _add_issue(
                    issues,
                    path,
                    "invalid_order",
                    "all CVE identifiers must appear before GHSA identifiers",
                )

    @staticmethod
    def _validate_location(
        location: Any, path: str, issues: list[SchemaIssue]
    ) -> None:
        if not isinstance(location, Mapping):
            _add_issue(
                issues,
                path,
                "type_error",
                "location must be an object",
                expected="object",
                actual=type(location).__name__,
            )
            return

        actual_keys = set(location)
        for key in sorted(actual_keys - _LOCATION_FIELD_SET, key=str):
            _add_issue(
                issues,
                _path_member(path, key),
                "extra_field",
                "field is not allowed in a VulnGym location object",
            )
        for key in sorted(_REQUIRED_LOCATION_FIELD_SET - actual_keys):
            _add_issue(
                issues,
                f"{path}.{key}",
                "missing_required",
                "required location field is missing; the adapter will not invent it",
            )

        for key in ("code", "file", "desc"):
            if key in location and not isinstance(location[key], str):
                _add_issue(
                    issues,
                    f"{path}.{key}",
                    "type_error",
                    f"{key} must be a string",
                    expected="string",
                    actual=type(location[key]).__name__,
                )

        if "line" not in location:
            return
        line = location["line"]
        line_path = f"{path}.line"
        if _is_integer(line):
            if line < 1:
                _add_issue(
                    issues,
                    line_path,
                    "invalid_value",
                    "line must be a positive, 1-based integer",
                )
            return
        if isinstance(line, str):
            match = _RANGE_RE.fullmatch(line)
            if not match:
                _add_issue(
                    issues,
                    line_path,
                    "invalid_format",
                    'line string must use the positive range form "start-end"',
                )
                return
            try:
                start, end = int(match.group(1)), int(match.group(2))
            except ValueError:
                _add_issue(
                    issues,
                    line_path,
                    "invalid_format",
                    "line range integers are too large",
                )
                return
            if start > end:
                _add_issue(
                    issues,
                    line_path,
                    "range_order",
                    "line range start must be less than or equal to end",
                    start=start,
                    end=end,
                )
            return
        _add_issue(
            issues,
            line_path,
            "type_error",
            'line must be a positive integer or a "start-end" string',
            expected='integer | "start-end"',
            actual=type(line).__name__,
        )


_DEFAULT_ADAPTER = SchemaAdapter()


def validate_entry(
    entry: Any, *, formal_t2: bool = False
) -> SchemaValidationResult:
    """Validate an already-formal entry without normalizing it."""

    return _DEFAULT_ADAPTER.validate(entry, formal_t2=formal_t2)


def normalize_entry(entry: Any) -> dict[str, Any]:
    """Normalize a dataset entry while preserving its human verify flag."""

    return _DEFAULT_ADAPTER.normalize(entry)


def adapt_entry(entry: Any, *, formal_t2: bool = True) -> dict[str, Any]:
    """Adapt one candidate; formal T2 behavior is the safe default."""

    return _DEFAULT_ADAPTER.adapt(entry, formal_t2=formal_t2)


def adapt_t2_entry(entry: Any) -> dict[str, Any]:
    """Adapt one formal T2 output and force ``verify`` to zero."""

    return _DEFAULT_ADAPTER.adapt(entry, formal_t2=True)
