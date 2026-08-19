"""Strict, JSON-safe contracts shared by the B-v2 orchestrator and T2.

The official candidate is deliberately kept separate from producer evidence,
tool telemetry, and assumptions.  This module validates that boundary without
claiming that a syntactically shaped candidate is factually correct; T1 owns
that decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any, Mapping

from vulngym_agent.adapters import ENTRY_FIELDS, SchemaAdapter
from vulngym_agent.models import EvidenceItem, JsonSerializable


_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REPORT_ID_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
_ENTRY_ID_RE = re.compile(r"^entry-[0-9]{5}$")
_TOOL_CALL_ID_RE = re.compile(r"^TOOL-[A-Za-z0-9][A-Za-z0-9._-]*$")
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOOL_STATUSES = frozenset({"success", "error", "blocked"})
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 100_000
_FORMAL_T2_ADAPTER = SchemaAdapter()


def _validate_identifier(value: Any, *, name: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{name} has an invalid format")
    return value


def _validate_optional_identifier(
    value: Any, *, name: str, pattern: re.Pattern[str]
) -> str | None:
    if value is None:
        return None
    return _validate_identifier(value, name=name, pattern=pattern)


def _freeze_json(value: Any) -> Any:
    """Validate and recursively freeze a bounded JSON value."""

    seen = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal seen
        seen += 1
        if seen > _MAX_JSON_NODES:
            raise ValueError(f"JSON value exceeds {_MAX_JSON_NODES} nodes")
        if depth > _MAX_JSON_DEPTH:
            raise ValueError(f"JSON value exceeds depth {_MAX_JSON_DEPTH}")
        if item is None or isinstance(item, (str, bool, int)):
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("JSON numbers must be finite")
            return item
        if isinstance(item, Mapping):
            frozen: dict[str, Any] = {}
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                frozen[key] = visit(child, depth + 1)
            return MappingProxyType(frozen)
        if isinstance(item, (list, tuple)):
            return tuple(visit(child, depth + 1) for child in item)
        raise ValueError(f"unsupported JSON value type: {type(item).__name__}")

    return visit(value, 0)


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _strict_object(
    value: Mapping[str, Any], *, required: frozenset[str], name: str
) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    actual = set(value)
    if actual != required:
        missing = sorted(required - actual, key=str)
        extra = sorted(actual - required, key=str)
        raise ValueError(f"{name} keys differ; missing={missing}, extra={extra}")


def canonical_json(value: Any) -> str:
    """Return the stable JSON representation used by all integrity digests."""

    if isinstance(value, JsonSerializable):
        value = value.to_dict()
    frozen = _freeze_json(value)
    return json.dumps(
        _thaw_json(frozen),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_sha256(value: Any) -> str:
    """Hash one value after canonical JSON serialization."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def freeze_entry_candidate(candidate: Mapping[str, Any]) -> Mapping[str, Any]:
    """Freeze a candidate and enforce the formal 15-field output boundary."""

    if not isinstance(candidate, Mapping):
        raise ValueError("candidate must be an object")
    if any(not isinstance(name, str) for name in candidate):
        raise ValueError("candidate field names must be strings")
    actual = set(candidate)
    expected = set(ENTRY_FIELDS)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(
            "candidate must contain exactly the 15 official Entry fields; "
            f"missing={missing}, extra={extra}"
        )
    frozen = _freeze_json({name: candidate[name] for name in ENTRY_FIELDS})
    assert isinstance(frozen, Mapping)
    return frozen


@dataclass(frozen=True, slots=True)
class RunTask(JsonSerializable):
    """One opaque, JSON-safe input task passed unchanged to T2 and T1."""

    task_id: str
    inputs: Mapping[str, Any] = field(default_factory=dict)
    report_id: str | None = None
    entry_id: str | None = None

    def __post_init__(self) -> None:
        _validate_identifier(self.task_id, name="task_id", pattern=_TASK_ID_RE)
        object.__setattr__(
            self,
            "report_id",
            _validate_optional_identifier(
                self.report_id, name="report_id", pattern=_REPORT_ID_RE
            ),
        )
        object.__setattr__(
            self,
            "entry_id",
            _validate_optional_identifier(
                self.entry_id, name="entry_id", pattern=_ENTRY_ID_RE
            ),
        )
        frozen = _freeze_json(self.inputs)
        if not isinstance(frozen, Mapping):
            raise ValueError("inputs must be a JSON object")
        object.__setattr__(self, "inputs", frozen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "report_id": self.report_id,
            "entry_id": self.entry_id,
            "inputs": _thaw_json(self.inputs),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RunTask":
        _strict_object(
            value,
            required=frozenset({"task_id", "report_id", "entry_id", "inputs"}),
            name="RunTask",
        )
        return cls(
            task_id=value["task_id"],
            report_id=value["report_id"],
            entry_id=value["entry_id"],
            inputs=value["inputs"],
        )


@dataclass(frozen=True, slots=True)
class ToolCallRecord(JsonSerializable):
    """Minimal replay-safe metadata for a producer tool call."""

    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    status: str
    result_sha256: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        _validate_identifier(
            self.tool_call_id,
            name="tool_call_id",
            pattern=_TOOL_CALL_ID_RE,
        )
        _validate_identifier(self.tool_name, name="tool_name", pattern=_TOOL_NAME_RE)
        _validate_identifier(
            self.arguments_sha256,
            name="arguments_sha256",
            pattern=_SHA256_RE,
        )
        if not isinstance(self.status, str) or self.status not in _TOOL_STATUSES:
            raise ValueError("status must be success, error, or blocked")
        if self.result_sha256 is not None:
            _validate_identifier(
                self.result_sha256,
                name="result_sha256",
                pattern=_SHA256_RE,
            )
        if self.error_code is not None and (
            not isinstance(self.error_code, str) or not self.error_code.strip()
        ):
            raise ValueError("error_code must be a non-empty string or None")
        if self.status == "success" and self.error_code is not None:
            raise ValueError("a successful tool call cannot have error_code")
        if self.status != "success" and self.result_sha256 is not None:
            raise ValueError("a non-successful tool call cannot have result_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_call_id": self.tool_call_id,
            "tool_name": self.tool_name,
            "arguments_sha256": self.arguments_sha256,
            "status": self.status,
            "result_sha256": self.result_sha256,
            "error_code": self.error_code,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ToolCallRecord":
        _strict_object(
            value,
            required=frozenset(
                {
                    "tool_call_id",
                    "tool_name",
                    "arguments_sha256",
                    "status",
                    "result_sha256",
                    "error_code",
                }
            ),
            name="ToolCallRecord",
        )
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class ProductionOutcome(JsonSerializable):
    """T2 output with an isolated official candidate and internal sidecars."""

    candidate: Mapping[str, Any]
    evidence: tuple[EvidenceItem, ...] = ()
    tool_calls: tuple[ToolCallRecord, ...] = ()
    assumptions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        shaped = freeze_entry_candidate(self.candidate)
        formal_candidate = _FORMAL_T2_ADAPTER.adapt(
            _thaw_json(shaped), formal_t2=True
        )
        if type(formal_candidate["verify"]) is not int or formal_candidate["verify"] != 0:
            raise ValueError("formal T2 candidate verify must be integer 0")
        object.__setattr__(
            self, "candidate", freeze_entry_candidate(formal_candidate)
        )
        unordered_or_scalar = (str, bytes, set, frozenset, Mapping)
        if isinstance(self.evidence, unordered_or_scalar) or isinstance(
            self.tool_calls, unordered_or_scalar
        ) or isinstance(self.assumptions, unordered_or_scalar):
            raise ValueError(
                "evidence, tool_calls, and assumptions must be arrays"
            )
        try:
            evidence = tuple(self.evidence)
            tool_calls = tuple(self.tool_calls)
            assumptions = tuple(self.assumptions)
        except TypeError as error:
            raise ValueError(
                "evidence, tool_calls, and assumptions must be iterable"
            ) from error
        if any(not isinstance(item, EvidenceItem) for item in evidence):
            raise ValueError("evidence must contain only EvidenceItem values")
        evidence_ids = [item.evidence_id for item in evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence IDs must be unique within one outcome")
        if any(not isinstance(item, ToolCallRecord) for item in tool_calls):
            raise ValueError("tool_calls must contain only ToolCallRecord values")
        call_ids = [item.tool_call_id for item in tool_calls]
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("tool call IDs must be unique within one outcome")
        for item in evidence:
            if item.report_id != formal_candidate["report_id"]:
                raise ValueError(
                    "producer evidence report_id must match its candidate"
                )
            if (
                item.entry_id is not None
                and item.entry_id != formal_candidate["entry_id"]
            ):
                raise ValueError(
                    "producer evidence entry_id must match its candidate"
                )
            if (
                item.tool_call_id is not None
                and item.tool_call_id not in set(call_ids)
            ):
                raise ValueError(
                    "producer evidence tool_call_id must resolve within its outcome"
                )
        if any(
            not isinstance(item, str) or not item.strip() for item in assumptions
        ) or len(assumptions) != len(set(assumptions)):
            raise ValueError("assumptions must contain unique non-empty strings")
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "tool_calls", tool_calls)
        object.__setattr__(self, "assumptions", assumptions)

    @property
    def candidate_sha256(self) -> str:
        return canonical_sha256(self.candidate)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate": {
                name: _thaw_json(self.candidate[name]) for name in ENTRY_FIELDS
            },
            "evidence": [item.to_dict() for item in self.evidence],
            "tool_calls": [item.to_dict() for item in self.tool_calls],
            "assumptions": list(self.assumptions),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProductionOutcome":
        _strict_object(
            value,
            required=frozenset(
                {"candidate", "evidence", "tool_calls", "assumptions"}
            ),
            name="ProductionOutcome",
        )
        evidence_value = value["evidence"]
        tool_calls_value = value["tool_calls"]
        if not isinstance(evidence_value, list):
            raise ValueError("ProductionOutcome.evidence must be an array")
        if not isinstance(tool_calls_value, list):
            raise ValueError("ProductionOutcome.tool_calls must be an array")
        if not isinstance(value["assumptions"], list):
            raise ValueError("ProductionOutcome.assumptions must be an array")
        if any(not isinstance(item, Mapping) for item in evidence_value):
            raise ValueError("ProductionOutcome.evidence items must be objects")
        return cls(
            candidate=value["candidate"],
            evidence=tuple(EvidenceItem(**dict(item)) for item in evidence_value),
            tool_calls=tuple(
                ToolCallRecord.from_dict(item) for item in tool_calls_value
            ),
            assumptions=tuple(value["assumptions"]),
        )


__all__ = [
    "ProductionOutcome",
    "RunTask",
    "ToolCallRecord",
    "canonical_json",
    "canonical_sha256",
    "freeze_entry_candidate",
]
