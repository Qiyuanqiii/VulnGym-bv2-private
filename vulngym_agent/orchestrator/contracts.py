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
_MODEL_CALL_ID_RE = re.compile(r"^MODEL-[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MODEL_COMPONENT_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$"
)
_REASON_CODE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
_DEFERRED_STAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOOL_STATUSES = frozenset({"success", "error", "blocked"})
_MODEL_CALL_STAGES = frozenset(
    {"plan", "semantic_judge", "reflection", "repair"}
)
_MODEL_CALL_STATUSES = frozenset({"success", "error", "blocked"})
_DEFERRED_MODES = frozenset({"generate", "repair"})
_GENERATE_DEFERRED_STAGES = frozenset(
    {
        "task_contract",
        "configuration",
        "plan",
        "load_advisory",
        "extract_advisory",
        "resolve_repo",
        "resolve_commit",
        "analyze_patch",
        "resolve_critical",
        "resolve_entry",
        "semantic_judge",
        "compose",
        "validate_schema",
        "reflection",
    }
)
_REPAIR_DEFERRED_STAGES = frozenset(
    {
        "repair_contract",
        "configuration",
        "repair",
        "resolve_repo",
        "resolve_commit",
        "analyze_patch",
        "resolve_critical",
        "resolve_entry",
        "validate_schema",
        "reflection",
    }
)
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 100_000
_MAX_EVIDENCE_ITEMS = 4096
_MAX_TOOL_CALLS = 1024
_MAX_MODEL_CALLS = 256
_MAX_ASSUMPTIONS = 256
_MAX_MISSING_INFORMATION = 256
_MAX_SIDECAR_TEXT_LENGTH = 4096
_MAX_PRODUCTION_ATTEMPT = 2
_FORMAL_T2_ADAPTER = SchemaAdapter()

_EVIDENCE_REQUIRED_KEYS = frozenset(
    {"evidence_id", "report_id", "source_type", "snippet"}
)
_EVIDENCE_OPTIONAL_KEYS = frozenset(
    {
        "entry_id",
        "commit",
        "file",
        "line_start",
        "line_end",
        "tool_call_id",
    }
)


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


def _validate_attempt(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_PRODUCTION_ATTEMPT
    ):
        raise ValueError(
            "attempt must be an integer from 0 to "
            f"{_MAX_PRODUCTION_ATTEMPT}"
        )
    return value


def _expected_policy_scope(attempt: int) -> str:
    return "t2.initial" if attempt == 0 else f"t2.repair-{attempt}"


def _validate_call_scope(
    *, task_id: Any, attempt: Any, policy_scope: Any
) -> tuple[str, int, str]:
    task = _validate_identifier(task_id, name="task_id", pattern=_TASK_ID_RE)
    attempt_value = _validate_attempt(attempt)
    scope = _validate_identifier(
        policy_scope,
        name="policy_scope",
        pattern=_TOOL_NAME_RE,
    )
    if scope != _expected_policy_scope(attempt_value):
        raise ValueError("policy_scope does not match attempt")
    return task, attempt_value, scope


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

    task_id: str
    attempt: int
    policy_scope: str
    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    operation: str
    budget_event_sequence: int
    status: str
    result_sha256: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        _validate_call_scope(
            task_id=self.task_id,
            attempt=self.attempt,
            policy_scope=self.policy_scope,
        )
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
        expected_operation = (
            f"tool:{self.task_id}:{self.attempt}:{self.policy_scope}:"
            f"{self.tool_call_id}:{self.tool_name}"
        )
        if self.operation != expected_operation:
            raise ValueError("operation does not bind the exact scoped tool call")
        if (
            isinstance(self.budget_event_sequence, bool)
            or not isinstance(self.budget_event_sequence, int)
            or self.budget_event_sequence < 1
        ):
            raise ValueError("budget_event_sequence must be a positive integer")
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
        if self.status == "success":
            if self.result_sha256 is None:
                raise ValueError("a successful tool call requires result_sha256")
            if self.error_code is not None:
                raise ValueError("a successful tool call cannot have error_code")
        else:
            if self.result_sha256 is not None:
                raise ValueError(
                    "a non-successful tool call cannot have result_sha256"
                )
            if self.error_code is None:
                raise ValueError(
                    "a non-successful tool call requires error_code"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "tool_call_id": self.tool_call_id,
            "tool_name": self.tool_name,
            "arguments_sha256": self.arguments_sha256,
            "operation": self.operation,
            "budget_event_sequence": self.budget_event_sequence,
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
                    "task_id",
                    "attempt",
                    "policy_scope",
                    "tool_call_id",
                    "tool_name",
                    "arguments_sha256",
                    "operation",
                    "budget_event_sequence",
                    "status",
                    "result_sha256",
                    "error_code",
                }
            ),
            name="ToolCallRecord",
        )
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class ModelCallRecord(JsonSerializable):
    """Replay metadata for one bounded model call, never its raw content.

    Request and response bodies, prompts, hidden reasoning, credentials, and
    provider error text are deliberately outside this contract.  Only stable
    identifiers, canonical-content digests, and a machine-readable error code
    cross the sidecar boundary.
    """

    task_id: str
    attempt: int
    policy_scope: str
    model_call_id: str
    stage: str
    backend_id: str
    model_id: str
    request_sha256: str
    operation: str
    budget_event_sequence: int
    status: str
    response_sha256: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        _validate_call_scope(
            task_id=self.task_id,
            attempt=self.attempt,
            policy_scope=self.policy_scope,
        )
        _validate_identifier(
            self.model_call_id,
            name="model_call_id",
            pattern=_MODEL_CALL_ID_RE,
        )
        if not isinstance(self.stage, str) or self.stage not in _MODEL_CALL_STAGES:
            raise ValueError(
                "stage must be plan, semantic_judge, reflection, or repair"
            )
        _validate_identifier(
            self.backend_id,
            name="backend_id",
            pattern=_MODEL_COMPONENT_ID_RE,
        )
        _validate_identifier(
            self.model_id,
            name="model_id",
            pattern=_MODEL_COMPONENT_ID_RE,
        )
        _validate_identifier(
            self.request_sha256,
            name="request_sha256",
            pattern=_SHA256_RE,
        )
        expected_operation = (
            f"model:{self.task_id}:{self.attempt}:{self.policy_scope}:"
            f"{self.stage}:{self.model_call_id}:{self.backend_id}:"
            f"{self.model_id}:{self.request_sha256}"
        )
        if self.operation != expected_operation:
            raise ValueError("operation does not bind the exact scoped model call")
        if (
            isinstance(self.budget_event_sequence, bool)
            or not isinstance(self.budget_event_sequence, int)
            or self.budget_event_sequence < 1
        ):
            raise ValueError("budget_event_sequence must be a positive integer")
        if not isinstance(self.status, str) or self.status not in _MODEL_CALL_STATUSES:
            raise ValueError("status must be success, error, or blocked")
        if self.response_sha256 is not None:
            _validate_identifier(
                self.response_sha256,
                name="response_sha256",
                pattern=_SHA256_RE,
            )
        if self.error_code is not None:
            _validate_identifier(
                self.error_code,
                name="error_code",
                pattern=_REASON_CODE_RE,
            )
        if self.status == "success":
            if self.response_sha256 is None:
                raise ValueError("a successful model call requires response_sha256")
            if self.error_code is not None:
                raise ValueError("a successful model call cannot have error_code")
        else:
            if self.error_code is None:
                raise ValueError("a non-successful model call requires error_code")
            if self.response_sha256 is not None:
                raise ValueError(
                    "a non-successful model call cannot have response_sha256"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "model_call_id": self.model_call_id,
            "stage": self.stage,
            "backend_id": self.backend_id,
            "model_id": self.model_id,
            "request_sha256": self.request_sha256,
            "operation": self.operation,
            "budget_event_sequence": self.budget_event_sequence,
            "status": self.status,
            "response_sha256": self.response_sha256,
            "error_code": self.error_code,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelCallRecord":
        _strict_object(
            value,
            required=frozenset(
                {
                    "task_id",
                    "attempt",
                    "policy_scope",
                    "model_call_id",
                    "stage",
                    "backend_id",
                    "model_id",
                    "request_sha256",
                    "operation",
                    "budget_event_sequence",
                    "status",
                    "response_sha256",
                    "error_code",
                }
            ),
            name="ModelCallRecord",
        )
        return cls(**dict(value))


def _coerce_contract_array(value: Any, *, name: str, limit: int) -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{name} must be an array")
    if len(value) > limit:
        raise ValueError(f"{name} exceeds the limit of {limit} items")
    return tuple(value)


def _evidence_from_dict(value: Mapping[str, Any]) -> EvidenceItem:
    if not isinstance(value, Mapping):
        raise ValueError("evidence item must be an object")
    actual = set(value)
    missing = _EVIDENCE_REQUIRED_KEYS - actual
    extra = actual - (_EVIDENCE_REQUIRED_KEYS | _EVIDENCE_OPTIONAL_KEYS)
    if missing or extra:
        raise ValueError(
            "EvidenceItem keys differ; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )
    try:
        return EvidenceItem(**dict(value))
    except TypeError as error:
        raise ValueError("EvidenceItem has invalid fields") from error


def _validate_sidecars(
    *,
    evidence_value: Any,
    tool_calls_value: Any,
    model_calls_value: Any,
) -> tuple[
    tuple[EvidenceItem, ...],
    tuple[ToolCallRecord, ...],
    tuple[ModelCallRecord, ...],
]:
    evidence = _coerce_contract_array(
        evidence_value,
        name="evidence",
        limit=_MAX_EVIDENCE_ITEMS,
    )
    tool_calls = _coerce_contract_array(
        tool_calls_value,
        name="tool_calls",
        limit=_MAX_TOOL_CALLS,
    )
    model_calls = _coerce_contract_array(
        model_calls_value,
        name="model_calls",
        limit=_MAX_MODEL_CALLS,
    )
    if any(not isinstance(item, EvidenceItem) for item in evidence):
        raise ValueError("evidence must contain only EvidenceItem values")
    if any(not isinstance(item, ToolCallRecord) for item in tool_calls):
        raise ValueError("tool_calls must contain only ToolCallRecord values")
    if any(not isinstance(item, ModelCallRecord) for item in model_calls):
        raise ValueError("model_calls must contain only ModelCallRecord values")
    evidence_ids = [item.evidence_id for item in evidence]
    call_ids = [item.tool_call_id for item in tool_calls]
    model_call_ids = [item.model_call_id for item in model_calls]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("evidence IDs must be unique within one result")
    if len(call_ids) != len(set(call_ids)):
        raise ValueError("tool call IDs must be unique within one result")
    if len(model_call_ids) != len(set(model_call_ids)):
        raise ValueError("model call IDs must be unique within one result")
    call_id_set = set(call_ids)
    for item in evidence:
        if item.tool_call_id is not None and item.tool_call_id not in call_id_set:
            raise ValueError(
                "producer evidence tool_call_id must resolve within its result"
            )
    return evidence, tool_calls, model_calls


def _validate_draft_evidence(
    evidence_value: Any,
    *,
    name: str = "evidence",
) -> tuple[EvidenceItem, ...]:
    """Validate evidence before authority-owned call records are projected."""

    evidence = _coerce_contract_array(
        evidence_value,
        name=name,
        limit=_MAX_EVIDENCE_ITEMS,
    )
    if any(not isinstance(item, EvidenceItem) for item in evidence):
        raise ValueError(f"{name} must contain only EvidenceItem values")
    evidence_ids = [item.evidence_id for item in evidence]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError(f"{name} IDs must be unique within one draft")
    return evidence


def _validate_assumptions(assumptions_value: Any) -> tuple[str, ...]:
    assumptions = _coerce_contract_array(
        assumptions_value,
        name="assumptions",
        limit=_MAX_ASSUMPTIONS,
    )
    if any(
        not isinstance(item, str)
        or not item.strip()
        or len(item) > _MAX_SIDECAR_TEXT_LENGTH
        for item in assumptions
    ) or len(assumptions) != len(set(assumptions)):
        raise ValueError(
            "assumptions must contain unique, bounded, non-empty strings"
        )
    return assumptions


@dataclass(frozen=True, slots=True)
class ProductionDraft:
    """Producer-authored candidate data without authority-owned sidecars."""

    candidate: Mapping[str, Any]
    evidence: tuple[EvidenceItem, ...] = ()
    assumptions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        shaped = freeze_entry_candidate(self.candidate)
        formal_candidate = _FORMAL_T2_ADAPTER.adapt(
            _thaw_json(shaped), formal_t2=True
        )
        if (
            type(formal_candidate["verify"]) is not int
            or formal_candidate["verify"] != 0
        ):
            raise ValueError("formal T2 candidate verify must be integer 0")
        candidate = freeze_entry_candidate(formal_candidate)
        evidence = _validate_draft_evidence(self.evidence)
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
        object.__setattr__(self, "candidate", candidate)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(
            self, "assumptions", _validate_assumptions(self.assumptions)
        )

    @property
    def candidate_sha256(self) -> str:
        return canonical_sha256(self.candidate)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate": {
                name: _thaw_json(self.candidate[name]) for name in ENTRY_FIELDS
            },
            "evidence": [item.to_dict() for item in self.evidence],
            "assumptions": list(self.assumptions),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProductionDraft":
        _strict_object(
            value,
            required=frozenset({"candidate", "evidence", "assumptions"}),
            name="ProductionDraft",
        )
        evidence_value = value["evidence"]
        assumptions_value = value["assumptions"]
        if not isinstance(evidence_value, list):
            raise ValueError("ProductionDraft.evidence must be an array")
        if not isinstance(assumptions_value, list):
            raise ValueError("ProductionDraft.assumptions must be an array")
        if any(not isinstance(item, Mapping) for item in evidence_value):
            raise ValueError("ProductionDraft.evidence items must be objects")
        return cls(
            candidate=value["candidate"],
            evidence=tuple(_evidence_from_dict(item) for item in evidence_value),
            assumptions=tuple(assumptions_value),
        )


@dataclass(frozen=True, slots=True)
class ProductionDeferredDraft:
    """Producer-authored fail-closed result without topology or call sidecars."""

    stage: str
    reason_code: str
    missing_information: tuple[str, ...]
    evidence: tuple[EvidenceItem, ...] = ()

    def __post_init__(self) -> None:
        stage = _validate_identifier(
            self.stage,
            name="stage",
            pattern=_DEFERRED_STAGE_RE,
        )
        if stage not in _GENERATE_DEFERRED_STAGES | _REPAIR_DEFERRED_STAGES:
            raise ValueError("stage is not an allowed producer defer stage")
        _validate_identifier(
            self.reason_code,
            name="reason_code",
            pattern=_REASON_CODE_RE,
        )
        missing_information = _coerce_contract_array(
            self.missing_information,
            name="missing_information",
            limit=_MAX_MISSING_INFORMATION,
        )
        if not missing_information or any(
            not isinstance(item, str)
            or not item.strip()
            or len(item) > _MAX_SIDECAR_TEXT_LENGTH
            for item in missing_information
        ) or len(missing_information) != len(set(missing_information)):
            raise ValueError(
                "missing_information must contain unique, bounded, "
                "non-empty strings"
            )
        object.__setattr__(self, "missing_information", missing_information)
        object.__setattr__(self, "evidence", _validate_draft_evidence(self.evidence))

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "reason_code": self.reason_code,
            "missing_information": list(self.missing_information),
            "evidence": [item.to_dict() for item in self.evidence],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProductionDeferredDraft":
        _strict_object(
            value,
            required=frozenset(
                {"stage", "reason_code", "missing_information", "evidence"}
            ),
            name="ProductionDeferredDraft",
        )
        missing_value = value["missing_information"]
        evidence_value = value["evidence"]
        if not isinstance(missing_value, list):
            raise ValueError(
                "ProductionDeferredDraft.missing_information must be an array"
            )
        if not isinstance(evidence_value, list):
            raise ValueError("ProductionDeferredDraft.evidence must be an array")
        if any(not isinstance(item, Mapping) for item in evidence_value):
            raise ValueError(
                "ProductionDeferredDraft.evidence items must be objects"
            )
        return cls(
            stage=value["stage"],
            reason_code=value["reason_code"],
            missing_information=tuple(missing_value),
            evidence=tuple(_evidence_from_dict(item) for item in evidence_value),
        )


@dataclass(frozen=True, slots=True)
class ProductionOutcome(JsonSerializable):
    """T2 output with an isolated official candidate and internal sidecars."""

    candidate: Mapping[str, Any]
    evidence: tuple[EvidenceItem, ...] = ()
    tool_calls: tuple[ToolCallRecord, ...] = ()
    assumptions: tuple[str, ...] = ()
    model_calls: tuple[ModelCallRecord, ...] = ()

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
        evidence, tool_calls, model_calls = _validate_sidecars(
            evidence_value=self.evidence,
            tool_calls_value=self.tool_calls,
            model_calls_value=self.model_calls,
        )
        assumptions = _validate_assumptions(self.assumptions)
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
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "tool_calls", tool_calls)
        object.__setattr__(self, "model_calls", model_calls)
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
            "model_calls": [item.to_dict() for item in self.model_calls],
            "assumptions": list(self.assumptions),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProductionOutcome":
        _strict_object(
            value,
            required=frozenset(
                {
                    "candidate",
                    "evidence",
                    "tool_calls",
                    "model_calls",
                    "assumptions",
                }
            ),
            name="ProductionOutcome",
        )
        evidence_value = value["evidence"]
        tool_calls_value = value["tool_calls"]
        model_calls_value = value["model_calls"]
        if not isinstance(evidence_value, list):
            raise ValueError("ProductionOutcome.evidence must be an array")
        if not isinstance(tool_calls_value, list):
            raise ValueError("ProductionOutcome.tool_calls must be an array")
        if not isinstance(model_calls_value, list):
            raise ValueError("ProductionOutcome.model_calls must be an array")
        if not isinstance(value["assumptions"], list):
            raise ValueError("ProductionOutcome.assumptions must be an array")
        if any(not isinstance(item, Mapping) for item in evidence_value):
            raise ValueError("ProductionOutcome.evidence items must be objects")
        if any(not isinstance(item, Mapping) for item in tool_calls_value):
            raise ValueError("ProductionOutcome.tool_calls items must be objects")
        if any(not isinstance(item, Mapping) for item in model_calls_value):
            raise ValueError("ProductionOutcome.model_calls items must be objects")
        return cls(
            candidate=value["candidate"],
            evidence=tuple(_evidence_from_dict(item) for item in evidence_value),
            tool_calls=tuple(
                ToolCallRecord.from_dict(item) for item in tool_calls_value
            ),
            model_calls=tuple(
                ModelCallRecord.from_dict(item) for item in model_calls_value
            ),
            assumptions=tuple(value["assumptions"]),
        )


@dataclass(frozen=True, slots=True)
class ProductionDeferred(JsonSerializable):
    """A fail-closed T2 result when evidence is insufficient for a candidate.

    The task binding is intentionally reduced to identifiers and the canonical
    input digest.  Raw task inputs are never copied into this result.
    """

    task_id: str
    report_id: str
    entry_id: str
    inputs_sha256: str
    attempt: int
    mode: str
    parent_candidate_sha256: str | None
    repair_plan_sha256: str | None
    stage: str
    reason_code: str
    missing_information: tuple[str, ...]
    evidence: tuple[EvidenceItem, ...] = ()
    tool_calls: tuple[ToolCallRecord, ...] = ()
    model_calls: tuple[ModelCallRecord, ...] = ()

    def __post_init__(self) -> None:
        _validate_identifier(self.task_id, name="task_id", pattern=_TASK_ID_RE)
        _validate_identifier(
            self.report_id,
            name="report_id",
            pattern=_REPORT_ID_RE,
        )
        _validate_identifier(
            self.entry_id,
            name="entry_id",
            pattern=_ENTRY_ID_RE,
        )
        _validate_identifier(
            self.inputs_sha256,
            name="inputs_sha256",
            pattern=_SHA256_RE,
        )
        attempt = _validate_attempt(self.attempt)
        if not isinstance(self.mode, str) or self.mode not in _DEFERRED_MODES:
            raise ValueError("mode must be generate or repair")
        stage = _validate_identifier(
            self.stage,
            name="stage",
            pattern=_DEFERRED_STAGE_RE,
        )
        if self.mode == "generate":
            if attempt != 0:
                raise ValueError("generate defer must use attempt 0")
            if (
                self.parent_candidate_sha256 is not None
                or self.repair_plan_sha256 is not None
            ):
                raise ValueError("generate defer cannot bind a repair parent or plan")
            if stage not in _GENERATE_DEFERRED_STAGES:
                raise ValueError("stage is not allowed for generate defer")
        else:
            if attempt < 1:
                raise ValueError("repair defer must use attempt 1 or 2")
            _validate_identifier(
                self.parent_candidate_sha256,
                name="parent_candidate_sha256",
                pattern=_SHA256_RE,
            )
            _validate_identifier(
                self.repair_plan_sha256,
                name="repair_plan_sha256",
                pattern=_SHA256_RE,
            )
            if stage not in _REPAIR_DEFERRED_STAGES:
                raise ValueError("stage is not allowed for repair defer")
        _validate_identifier(
            self.reason_code,
            name="reason_code",
            pattern=_REASON_CODE_RE,
        )
        missing_information = _coerce_contract_array(
            self.missing_information,
            name="missing_information",
            limit=_MAX_MISSING_INFORMATION,
        )
        if not missing_information or any(
            not isinstance(item, str)
            or not item.strip()
            or len(item) > _MAX_SIDECAR_TEXT_LENGTH
            for item in missing_information
        ) or len(missing_information) != len(set(missing_information)):
            raise ValueError(
                "missing_information must contain unique, bounded, "
                "non-empty strings"
            )
        evidence, tool_calls, model_calls = _validate_sidecars(
            evidence_value=self.evidence,
            tool_calls_value=self.tool_calls,
            model_calls_value=self.model_calls,
        )
        for item in evidence:
            if item.report_id != self.report_id:
                raise ValueError(
                    "deferred evidence report_id must match its task binding"
                )
            if item.entry_id != self.entry_id:
                raise ValueError(
                    "deferred evidence entry_id must match its task binding"
                )
        expected_scope = _expected_policy_scope(attempt)
        for item in (*tool_calls, *model_calls):
            if (
                item.task_id != self.task_id
                or item.attempt != attempt
                or item.policy_scope != expected_scope
            ):
                raise ValueError(
                    "deferred call sidecar does not match its task attempt"
                )
        object.__setattr__(self, "missing_information", missing_information)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "tool_calls", tool_calls)
        object.__setattr__(self, "model_calls", model_calls)

    @classmethod
    def from_task(
        cls,
        task: RunTask,
        *,
        stage: str,
        reason_code: str,
        missing_information: tuple[str, ...] | list[str],
        attempt: int = 0,
        mode: str = "generate",
        parent_candidate_sha256: str | None = None,
        repair_plan_sha256: str | None = None,
        evidence: tuple[EvidenceItem, ...] | list[EvidenceItem] = (),
        tool_calls: tuple[ToolCallRecord, ...] | list[ToolCallRecord] = (),
        model_calls: tuple[ModelCallRecord, ...] | list[ModelCallRecord] = (),
    ) -> "ProductionDeferred":
        if not isinstance(task, RunTask):
            raise ValueError("task must be a RunTask")
        if task.report_id is None or task.entry_id is None:
            raise ValueError(
                "a deferred production result requires task report_id and entry_id"
            )
        return cls(
            task_id=task.task_id,
            report_id=task.report_id,
            entry_id=task.entry_id,
            inputs_sha256=canonical_sha256(task.inputs),
            attempt=attempt,
            mode=mode,
            parent_candidate_sha256=parent_candidate_sha256,
            repair_plan_sha256=repair_plan_sha256,
            stage=stage,
            reason_code=reason_code,
            missing_information=missing_information,
            evidence=evidence,
            tool_calls=tool_calls,
            model_calls=model_calls,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "report_id": self.report_id,
            "entry_id": self.entry_id,
            "inputs_sha256": self.inputs_sha256,
            "attempt": self.attempt,
            "mode": self.mode,
            "parent_candidate_sha256": self.parent_candidate_sha256,
            "repair_plan_sha256": self.repair_plan_sha256,
            "stage": self.stage,
            "reason_code": self.reason_code,
            "missing_information": list(self.missing_information),
            "evidence": [item.to_dict() for item in self.evidence],
            "tool_calls": [item.to_dict() for item in self.tool_calls],
            "model_calls": [item.to_dict() for item in self.model_calls],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProductionDeferred":
        _strict_object(
            value,
            required=frozenset(
                {
                    "task_id",
                    "report_id",
                    "entry_id",
                    "inputs_sha256",
                    "attempt",
                    "mode",
                    "parent_candidate_sha256",
                    "repair_plan_sha256",
                    "stage",
                    "reason_code",
                    "missing_information",
                    "evidence",
                    "tool_calls",
                    "model_calls",
                }
            ),
            name="ProductionDeferred",
        )
        missing_value = value["missing_information"]
        evidence_value = value["evidence"]
        tool_calls_value = value["tool_calls"]
        model_calls_value = value["model_calls"]
        if not isinstance(missing_value, list):
            raise ValueError("ProductionDeferred.missing_information must be an array")
        if not isinstance(evidence_value, list):
            raise ValueError("ProductionDeferred.evidence must be an array")
        if not isinstance(tool_calls_value, list):
            raise ValueError("ProductionDeferred.tool_calls must be an array")
        if not isinstance(model_calls_value, list):
            raise ValueError("ProductionDeferred.model_calls must be an array")
        if any(not isinstance(item, Mapping) for item in evidence_value):
            raise ValueError("ProductionDeferred.evidence items must be objects")
        if any(not isinstance(item, Mapping) for item in tool_calls_value):
            raise ValueError("ProductionDeferred.tool_calls items must be objects")
        if any(not isinstance(item, Mapping) for item in model_calls_value):
            raise ValueError("ProductionDeferred.model_calls items must be objects")
        return cls(
            task_id=value["task_id"],
            report_id=value["report_id"],
            entry_id=value["entry_id"],
            inputs_sha256=value["inputs_sha256"],
            attempt=value["attempt"],
            mode=value["mode"],
            parent_candidate_sha256=value["parent_candidate_sha256"],
            repair_plan_sha256=value["repair_plan_sha256"],
            stage=value["stage"],
            reason_code=value["reason_code"],
            missing_information=tuple(missing_value),
            evidence=tuple(_evidence_from_dict(item) for item in evidence_value),
            tool_calls=tuple(
                ToolCallRecord.from_dict(item) for item in tool_calls_value
            ),
            model_calls=tuple(
                ModelCallRecord.from_dict(item) for item in model_calls_value
            ),
        )


ProducerResult = ProductionOutcome | ProductionDeferred
ProducerDraftResult = ProductionDraft | ProductionDeferredDraft


__all__ = [
    "ModelCallRecord",
    "ProducerDraftResult",
    "ProducerResult",
    "ProductionDeferredDraft",
    "ProductionDeferred",
    "ProductionDraft",
    "ProductionOutcome",
    "RunTask",
    "ToolCallRecord",
    "canonical_json",
    "canonical_sha256",
    "freeze_entry_candidate",
]
