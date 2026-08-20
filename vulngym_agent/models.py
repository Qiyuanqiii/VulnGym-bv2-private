"""Shared, JSON-serializable data models for the VulnGym agents.

The models in this module deliberately use only the Python standard library.
They represent validation/evidence sidecars; they are never merged into an
official ``entries.jsonl`` row.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import re
from typing import Any, Mapping


VALIDATION_STATUSES = frozenset({"correct", "incorrect", "uncertain"})
EVIDENCE_SOURCE_TYPES = frozenset({"advisory", "patch", "source", "git", "schema"})
_EVIDENCE_ID_RE = re.compile(r"^EV-[A-Z0-9][A-Z0-9._-]*$")
_REPORT_ID_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
_ENTRY_ID_RE = re.compile(r"^entry-[0-9]{5}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_LINE_RANGE_RE = re.compile(r"^([1-9][0-9]*)-([1-9][0-9]*)$")
_VALIDATION_FIELD_NAMES = frozenset(
    {
        "schema",
        "evidence_package",
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
    }
)


def _jsonable(value: Any) -> Any:
    """Convert supported model values into plain JSON-compatible values."""

    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _valid_line_value(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 1
    if not isinstance(value, str):
        return False
    match = _LINE_RANGE_RE.fullmatch(value)
    return bool(match and int(match.group(1)) <= int(match.group(2)))


def _valid_location_value(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    keys = set(value)
    if not {"code", "file", "line"}.issubset(keys) or not keys <= {
        "code",
        "desc",
        "file",
        "line",
    }:
        return False
    if not isinstance(value["code"], str) or not isinstance(value["file"], str):
        return False
    if "desc" in value and not isinstance(value["desc"], str):
        return False
    return _valid_line_value(value["line"])


def _valid_official_field_value(value: Any) -> bool:
    """Mirror ``validation.schema.json#/$defs/officialFieldValue``."""

    if isinstance(value, str):
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value in {0, 1}
    if isinstance(value, Mapping):
        return _valid_location_value(value)
    if isinstance(value, (list, tuple)):
        return all(isinstance(item, str) for item in value) or all(
            _valid_location_value(item) for item in value
        )
    return False


class JsonSerializable:
    """Small serialization mixin shared by sidecar dataclasses."""

    def to_dict(self) -> dict[str, Any]:
        raise NotImplementedError

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(
            self.to_dict(), ensure_ascii=False, indent=indent, sort_keys=True
        )


@dataclass(frozen=True, slots=True)
class SchemaIssue(JsonSerializable):
    """One deterministic schema problem associated with a precise field path."""

    path: str
    code: str
    message: str
    context: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "path": self.path,
            "code": self.code,
            "message": self.message,
        }
        if self.context:
            value["context"] = _jsonable(self.context)
        return value


@dataclass(eq=False, slots=True)
class SchemaAdapterError(ValueError, JsonSerializable):
    """Raised when an entry cannot be adapted without violating the contract."""

    issues: tuple[SchemaIssue, ...]
    message: str = "VulnGym entry does not satisfy the schema contract"

    def __post_init__(self) -> None:
        self.issues = tuple(self.issues)
        ValueError.__init__(self, self.message)

    def __str__(self) -> str:
        if not self.issues:
            return self.message
        first = self.issues[0]
        suffix = "" if len(self.issues) == 1 else f" (+{len(self.issues) - 1} more)"
        return f"{self.message}: {first.path}: {first.message}{suffix}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": "schema_adapter_error",
            "message": self.message,
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(frozen=True, slots=True)
class SchemaValidationResult(JsonSerializable):
    """Non-throwing result returned by schema validation."""

    issues: tuple[SchemaIssue, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.issues

    @property
    def is_valid(self) -> bool:
        """Readable alias retained for validator call sites."""

        return self.valid

    def raise_for_errors(self) -> None:
        if self.issues:
            raise SchemaAdapterError(self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(frozen=True, slots=True)
class EvidenceItem(JsonSerializable):
    """One internal evidence record referenced by field validation output."""

    evidence_id: str
    report_id: str
    source_type: str
    snippet: str
    entry_id: str | None = None
    commit: str | None = None
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    tool_call_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, str) or not _EVIDENCE_ID_RE.fullmatch(
            self.evidence_id
        ):
            raise ValueError("evidence_id does not satisfy the evidence schema")
        if not isinstance(self.report_id, str) or not _REPORT_ID_RE.fullmatch(
            self.report_id
        ):
            raise ValueError("report_id must be an upper-case GHSA identifier")
        if self.entry_id is not None and (
            not isinstance(self.entry_id, str)
            or not _ENTRY_ID_RE.fullmatch(self.entry_id)
        ):
            raise ValueError("entry_id must match entry- followed by five digits")
        if (
            not isinstance(self.source_type, str)
            or self.source_type not in EVIDENCE_SOURCE_TYPES
        ):
            raise ValueError("source_type is not supported by the evidence schema")
        if not isinstance(self.snippet, str) or not self.snippet.strip():
            raise ValueError("snippet must be a non-empty string")
        if self.commit is not None and (
            not isinstance(self.commit, str) or not _COMMIT_RE.fullmatch(self.commit)
        ):
            raise ValueError("commit must be 40 lower-case hexadecimal characters")
        if self.file is not None and not isinstance(self.file, str):
            raise ValueError("file must be a string or None")
        if (self.line_start is None) != (self.line_end is None):
            raise ValueError("line_start and line_end must be provided together")
        if self.line_start is not None:
            if (
                isinstance(self.line_start, bool)
                or isinstance(self.line_end, bool)
                or not isinstance(self.line_start, int)
                or not isinstance(self.line_end, int)
                or self.line_start < 1
                or self.line_end < self.line_start
            ):
                raise ValueError("evidence line range must be positive and ordered")
        if self.tool_call_id is not None and not isinstance(self.tool_call_id, str):
            raise ValueError("tool_call_id must be a string or None")

    def to_dict(self) -> dict[str, Any]:
        values = {
            "evidence_id": self.evidence_id,
            "report_id": self.report_id,
            "entry_id": self.entry_id,
            "source_type": self.source_type,
            "commit": self.commit,
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "snippet": self.snippet,
            "tool_call_id": self.tool_call_id,
        }
        return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True, slots=True)
class FieldValidation(JsonSerializable):
    """Human-readable T1 verdict for one official entry field."""

    status: str
    confidence: float
    evidence: str
    evidence_refs: tuple[str, ...] = ()
    suggested_fix: Any = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.status, str)
            or self.status not in VALIDATION_STATUSES
        ):
            raise ValueError(
                "status must be one of: correct, incorrect, uncertain"
            )
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not math.isfinite(self.confidence)
            or not 0 <= self.confidence <= 1
        ):
            raise ValueError("confidence must be a finite number between 0 and 1")
        if not isinstance(self.evidence, str) or not self.evidence.strip():
            raise ValueError("evidence must be a non-empty string")
        try:
            refs = tuple(self.evidence_refs)
        except TypeError as error:
            raise ValueError("evidence_refs must be an iterable of IDs") from error
        if any(
            not isinstance(value, str) or not _EVIDENCE_ID_RE.fullmatch(value)
            for value in refs
        ) or len(refs) != len(set(refs)):
            raise ValueError("evidence_refs must contain unique valid evidence IDs")
        object.__setattr__(self, "evidence_refs", refs)
        if self.suggested_fix is not None:
            if not _valid_official_field_value(self.suggested_fix):
                raise ValueError(
                    "suggested_fix must be a valid official field value"
                )
            try:
                json.dumps(_jsonable(self.suggested_fix), allow_nan=False)
            except (TypeError, ValueError) as error:
                raise ValueError("suggested_fix must be JSON serializable") from error

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "status": self.status,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }
        if self.evidence_refs:
            value["evidence_refs"] = list(self.evidence_refs)
        if self.suggested_fix is not None:
            value["suggested_fix"] = _jsonable(self.suggested_fix)
        return value


@dataclass(frozen=True, slots=True)
class ValidationReport(JsonSerializable):
    """Directly readable T1 report for one candidate entry."""

    report_id: str | None
    verdict: str
    fields: Mapping[str, FieldValidation]
    summary: str
    missing_information: tuple[str, ...] = ()
    entry_id: str | None = None
    input_line: int | None = None

    def __post_init__(self) -> None:
        if self.report_id is not None and (
            not isinstance(self.report_id, str)
            or not _REPORT_ID_RE.fullmatch(self.report_id)
        ):
            raise ValueError("report_id must be an upper-case GHSA ID or None")
        if self.entry_id is not None and (
            not isinstance(self.entry_id, str)
            or not _ENTRY_ID_RE.fullmatch(self.entry_id)
        ):
            raise ValueError("entry_id must match entry- followed by five digits or None")
        if (
            self.input_line is not None
            and (
                isinstance(self.input_line, bool)
                or not isinstance(self.input_line, int)
                or self.input_line < 1
            )
        ):
            raise ValueError("input_line must be a positive integer or None")
        if (
            not isinstance(self.verdict, str)
            or self.verdict not in VALIDATION_STATUSES
        ):
            raise ValueError(
                "verdict must be one of: correct, incorrect, uncertain"
            )
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise ValueError("summary must be a non-empty string")
        if not isinstance(self.fields, Mapping) or not self.fields:
            raise ValueError("fields must be a non-empty mapping")
        if any(
            name not in _VALIDATION_FIELD_NAMES
            or not isinstance(validation, FieldValidation)
            for name, validation in self.fields.items()
        ):
            raise ValueError("fields contains an unsupported name or value")
        try:
            missing = tuple(self.missing_information)
        except TypeError as error:
            raise ValueError("missing_information must be an iterable of strings") from error
        if any(not isinstance(value, str) for value in missing) or len(
            missing
        ) != len(set(missing)):
            raise ValueError("missing_information must contain unique strings")
        object.__setattr__(self, "missing_information", missing)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "input_line": self.input_line,
            "report_id": self.report_id,
            "verdict": self.verdict,
            "fields": {
                name: validation.to_dict()
                for name, validation in self.fields.items()
            },
            "summary": self.summary,
            "missing_information": list(self.missing_information),
        }
