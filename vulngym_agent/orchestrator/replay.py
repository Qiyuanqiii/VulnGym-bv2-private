"""Deterministic, replay-safe artifacts for B-v2 closed-loop runs.

The writer consumes an ordered event stream once.  It never persists raw task
inputs, producer assumptions, model prompts/responses, or exception text.  A
directory is published only after every artifact has been written and checked
inside a sibling staging directory.

Bounded public or otherwise cleared evidence snippets are intentionally
retained: they are required to replay T1 evidence references.  The formal
Entry and terminal ValidationReport likewise retain their schema-required code
fields.  Text is not rewritten; an exact configured local root is rejected.

The integrity fields in this module detect accidental corruption and make all
artifact references locally closed.  They are not signatures and do not make
an untrusted artifact directory authentic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping, Sequence
import uuid

from vulngym_agent.models import EvidenceItem, FieldValidation, ValidationReport
from vulngym_agent.tools.git import validate_repo_relative_path

from .contracts import (
    ModelCallRecord,
    ProductionDeferred,
    ProductionOutcome,
    RunTask,
    ToolCallRecord,
    canonical_json,
    canonical_sha256,
)
from .repair_plan import RepairPlan
from .state_machine import ClosedLoopOutcome, TERMINAL_STATUSES


REPLAY_SCHEMA_VERSION = 1

_ENVELOPE_DATA_FILES = (
    "states.jsonl",
    "candidates.jsonl",
    "validations.jsonl",
    "evidence.jsonl",
    "tool_calls.jsonl",
    "model_calls.jsonl",
    "repair_history.jsonl",
    "deferred.jsonl",
    "errors.jsonl",
)
_ENTRY_FILE = "entries.jsonl"
_FORMAL_VALIDATION_FILE = "validation.jsonl"
_DATA_FILES = (*_ENVELOPE_DATA_FILES, _ENTRY_FILE, _FORMAL_VALIDATION_FILE)
_MANIFEST_FILE = "run_manifest.jsonl"
REPLAY_FILES = (*_DATA_FILES, _MANIFEST_FILE)

_FILE_KIND = {
    "states.jsonl": "state",
    "candidates.jsonl": "candidate",
    "validations.jsonl": "validation",
    "evidence.jsonl": "evidence",
    "tool_calls.jsonl": "tool_call",
    "model_calls.jsonl": "model_call",
    "repair_history.jsonl": "repair_plan",
    "deferred.jsonl": "deferred",
    "errors.jsonl": "input_failure",
}
_KIND_FILE = {value: key for key, value in _FILE_KIND.items()}
_ENVELOPE_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "record_id",
        "task_id",
        "input_line",
        "correlation_id",
        "attempt",
        "payload",
        "payload_sha256",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ERROR_CODE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
_RECORD_ID_RE = re.compile(r"^REC-[0-9a-f]{64}$")
_CORRELATION_RE = re.compile(r"^(?:RUN|INPUT|DATASET)-[0-9a-f]{64}$")


class ReplayArtifactError(ValueError):
    """Raised when replay artifacts violate their closed contract."""


@dataclass(frozen=True, slots=True)
class ReplayLimits:
    """Hard resource limits for artifact production and reading."""

    max_input_records: int = 100_001
    max_records_per_file: int = 500_000
    max_line_bytes: int = 1_048_576
    max_total_bytes: int = 268_435_456

    def __post_init__(self) -> None:
        for name in (
            "max_input_records",
            "max_records_per_file",
            "max_line_bytes",
            "max_total_bytes",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_line_bytes > self.max_total_bytes:
            raise ValueError("max_line_bytes cannot exceed max_total_bytes")


@dataclass(frozen=True, slots=True)
class ReplayRecord:
    """One valid physical input line and its closed-loop terminal outcome."""

    input_line: int
    task: RunTask
    outcome: ClosedLoopOutcome

    def __post_init__(self) -> None:
        _positive_input_line(self.input_line)
        if not isinstance(self.task, RunTask):
            raise ValueError("task must be a RunTask")
        if not isinstance(self.outcome, ClosedLoopOutcome):
            raise ValueError("outcome must be a ClosedLoopOutcome")
        declared = self.task.inputs.get("input_line")
        if type(declared) is not int or declared != self.input_line:
            raise ValueError("input_line must match task.inputs.input_line")
        if canonical_sha256(self.task) != canonical_sha256(self.outcome.state.task):
            raise ValueError("outcome state must bind the exact RunTask")


@dataclass(frozen=True, slots=True)
class InputFailureRecord:
    """Sanitized record for a physical line that could not become a RunTask."""

    input_line: int
    error_code: str
    raw_sha256: str
    task_id: str | None = None

    def __post_init__(self) -> None:
        _positive_input_line(self.input_line)
        if not isinstance(self.error_code, str) or not _ERROR_CODE_RE.fullmatch(
            self.error_code
        ):
            raise ValueError("error_code has an invalid format")
        _require_sha256(self.raw_sha256, "raw_sha256")
        if self.task_id is not None and (
            not isinstance(self.task_id, str) or not _TASK_ID_RE.fullmatch(self.task_id)
        ):
            raise ValueError("task_id has an invalid format")


ReplayEvent = ReplayRecord | InputFailureRecord


@dataclass(frozen=True, slots=True)
class ReplayManifest:
    """Verified dataset footer from ``run_manifest.jsonl``."""

    dataset_sha256: str
    input_records: int
    outcome_records: int
    input_failures: int
    entry_count: int
    formal_validation_count: int
    validation_attempt_count: int
    files: Mapping[str, Mapping[str, Any]]
    payload_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(self.dataset_sha256, "dataset_sha256")
        _require_sha256(self.payload_sha256, "payload_sha256")
        for name in (
            "input_records",
            "outcome_records",
            "input_failures",
            "entry_count",
            "formal_validation_count",
            "validation_attempt_count",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        frozen = {
            name: MappingProxyType(dict(summary))
            for name, summary in self.files.items()
        }
        object.__setattr__(self, "files", MappingProxyType(frozen))

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_sha256": self.dataset_sha256,
            "input_records": self.input_records,
            "outcome_records": self.outcome_records,
            "input_failures": self.input_failures,
            "entry_count": self.entry_count,
            "formal_validation_count": self.formal_validation_count,
            "validation_attempt_count": self.validation_attempt_count,
            "files": {
                name: dict(summary) for name, summary in self.files.items()
            },
            "payload_sha256": self.payload_sha256,
        }


def _freeze_formal_entries(
    entries: Iterable[Mapping[str, Any]],
) -> tuple[Mapping[str, Any], ...]:
    """Validate and recursively freeze a sequence of formal T2 Entries."""

    frozen: list[Mapping[str, Any]] = []
    seen_entry_ids: set[str] = set()
    for value in entries:
        formal = ProductionOutcome(candidate=value).candidate
        entry_id = formal["entry_id"]
        if entry_id in seen_entry_ids:
            raise ValueError("formal Entry entry_id values must be unique")
        seen_entry_ids.add(entry_id)
        frozen.append(formal)
    return tuple(frozen)


@dataclass(frozen=True, slots=True)
class VerifiedTaskEntries:
    """Formal Entries explicitly bound to one verified terminal state root."""

    task_id: str
    status: str
    entries: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not _TASK_ID_RE.fullmatch(
            self.task_id
        ):
            raise ValueError("task_id must be a valid task identifier")
        if not isinstance(self.status, str) or self.status not in TERMINAL_STATUSES:
            raise ValueError("status must be a terminal run status")
        entries = _freeze_formal_entries(self.entries)
        if self.status == "finalized":
            if len(entries) != 1:
                raise ValueError("a finalized task must bind exactly one formal Entry")
        elif entries:
            raise ValueError("a non-finalized task cannot bind a formal Entry")
        object.__setattr__(self, "entries", entries)


@dataclass(frozen=True, slots=True)
class VerifiedTaskPrediction:
    """One terminal T2 candidate paired with its exact T1 report.

    This projection may retain a schema-valid candidate whose terminal status
    is ``manual_review``.  It does not weaken the replay publication contract:
    the replay bundle's own ``entries.jsonl`` remains finalized/correct-only.
    """

    task_id: str
    input_line: int
    status: str
    entry: Mapping[str, Any] | None = None
    validation: ValidationReport | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not _TASK_ID_RE.fullmatch(
            self.task_id
        ):
            raise ValueError("task_id must be a valid task identifier")
        _positive_input_line(self.input_line)
        if not isinstance(self.status, str) or self.status not in TERMINAL_STATUSES:
            raise ValueError("status must be a terminal run status")
        entry = self.entry
        if entry is not None:
            entry = ProductionOutcome(candidate=entry).candidate
            object.__setattr__(self, "entry", entry)
        report = self.validation
        if report is not None and not isinstance(report, ValidationReport):
            raise ValueError("validation must be a ValidationReport or None")
        if report is not None and report.input_line != self.input_line:
            raise ValueError("validation input_line must match the task input line")
        if entry is not None and report is not None and (
            report.report_id != entry["report_id"]
            or report.entry_id != entry["entry_id"]
        ):
            raise ValueError("submission Entry and T1 validation identities differ")
        if self.status == "finalized" and (
            entry is None or report is None or report.verdict != "correct"
        ):
            raise ValueError(
                "a finalized prediction requires an Entry and correct validation"
            )

    @property
    def complete(self) -> bool:
        return self.entry is not None and self.validation is not None


def _freeze_verified_tasks(
    tasks: Iterable[VerifiedTaskEntries],
) -> tuple[VerifiedTaskEntries, ...]:
    frozen = tuple(tasks)
    if any(not isinstance(task, VerifiedTaskEntries) for task in frozen):
        raise ValueError("tasks must contain only VerifiedTaskEntries values")
    task_ids = [task.task_id for task in frozen]
    if len(task_ids) != len(set(task_ids)):
        raise ValueError("verified task IDs must be unique")
    entry_ids: list[str] = []
    entry_sha256s: list[str] = []
    for task in frozen:
        for entry in task.entries:
            entry_ids.append(entry["entry_id"])
            entry_sha256s.append(canonical_sha256(entry))
    if len(entry_ids) != len(set(entry_ids)):
        raise ValueError("formal Entry IDs must be unique across verified tasks")
    if len(entry_sha256s) != len(set(entry_sha256s)):
        raise ValueError("one formal Entry cannot bind to multiple verified tasks")
    return frozen


def _freeze_verified_predictions(
    tasks: Iterable[VerifiedTaskPrediction],
) -> tuple[VerifiedTaskPrediction, ...]:
    frozen = tuple(tasks)
    if any(not isinstance(task, VerifiedTaskPrediction) for task in frozen):
        raise ValueError(
            "predictions must contain only VerifiedTaskPrediction values"
        )
    task_ids = [task.task_id for task in frozen]
    input_lines = [task.input_line for task in frozen]
    if len(task_ids) != len(set(task_ids)):
        raise ValueError("prediction task IDs must be unique")
    if input_lines != sorted(set(input_lines)):
        raise ValueError("prediction input lines must be strictly increasing")
    entry_ids = [
        task.entry["entry_id"] for task in frozen if task.entry is not None
    ]
    if len(entry_ids) != len(set(entry_ids)):
        raise ValueError("prediction Entry IDs must be unique")
    return frozen


@dataclass(frozen=True, slots=True)
class ReplayBundle:
    """Compact result of an offline artifact read and integrity check."""

    manifest: ReplayManifest
    root_records: tuple[Mapping[str, Any], ...]
    record_counts: Mapping[str, int]
    verified_tasks: tuple[VerifiedTaskEntries, ...] = ()
    verified_predictions: tuple[VerifiedTaskPrediction, ...] = ()

    def __post_init__(self) -> None:
        roots = tuple(MappingProxyType(dict(item)) for item in self.root_records)
        object.__setattr__(self, "root_records", roots)
        object.__setattr__(
            self, "record_counts", MappingProxyType(dict(self.record_counts))
        )
        object.__setattr__(
            self, "verified_tasks", _freeze_verified_tasks(self.verified_tasks)
        )
        object.__setattr__(
            self,
            "verified_predictions",
            _freeze_verified_predictions(self.verified_predictions),
        )

    @property
    def formal_entries(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            entry for task in self.verified_tasks for entry in task.entries
        )


@dataclass(frozen=True, slots=True)
class VerifiedFormalEntries:
    """Narrow trusted projection of a complete replay read.

    Only the dataset digest, explicit terminal-task/Entry bindings, and input
    failure count are retained.  Full task bindings and inputs, model/tool
    metadata, evidence, and producer assumptions are omitted.  Every nested
    Entry value is recursively frozen.
    """

    dataset_sha256: str
    tasks: tuple[VerifiedTaskEntries, ...]
    input_failure_count: int = 0

    def __post_init__(self) -> None:
        _require_sha256(self.dataset_sha256, "dataset_sha256")
        object.__setattr__(self, "tasks", _freeze_verified_tasks(self.tasks))
        if (
            isinstance(self.input_failure_count, bool)
            or not isinstance(self.input_failure_count, int)
            or self.input_failure_count < 0
        ):
            raise ValueError("input_failure_count must be a non-negative integer")

    @property
    def entries(self) -> tuple[Mapping[str, Any], ...]:
        """Flattened compatibility view; use ``tasks`` for ownership."""

        return tuple(entry for task in self.tasks for entry in task.entries)

    @property
    def task_ids(self) -> tuple[str, ...]:
        return tuple(task.task_id for task in self.tasks)


@dataclass(frozen=True, slots=True)
class VerifiedSubmissionPredictions:
    """Narrow integrity-checked terminal candidates for submission export."""

    dataset_sha256: str
    tasks: tuple[VerifiedTaskPrediction, ...]
    input_failure_count: int = 0

    def __post_init__(self) -> None:
        _require_sha256(self.dataset_sha256, "dataset_sha256")
        object.__setattr__(
            self, "tasks", _freeze_verified_predictions(self.tasks)
        )
        if (
            isinstance(self.input_failure_count, bool)
            or not isinstance(self.input_failure_count, int)
            or self.input_failure_count < 0
        ):
            raise ValueError("input_failure_count must be a non-negative integer")

    @property
    def complete_tasks(self) -> tuple[VerifiedTaskPrediction, ...]:
        return tuple(task for task in self.tasks if task.complete)


@dataclass(slots=True)
class _FileState:
    handle: Any
    digest: Any = field(default_factory=hashlib.sha256)
    line_count: int = 0
    byte_count: int = 0


@dataclass(frozen=True, slots=True)
class _IndexedRecord:
    kind: str
    task_id: str | None
    input_line: int
    correlation_id: str
    attempt: int
    payload_sha256: str
    selected: Mapping[str, Any]


def _positive_input_line(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("input_line must be a positive integer")
    return value


def _require_sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lower-case SHA-256 digest")
    return value


def _record_id(kind: str, correlation_id: str, record_key: str) -> str:
    return "REC-" + canonical_sha256(
        {
            "schema_version": REPLAY_SCHEMA_VERSION,
            "kind": kind,
            "correlation_id": correlation_id,
            "record_key": record_key,
        }
    )


def _run_correlation(input_line: int, task: RunTask) -> str:
    return "RUN-" + canonical_sha256(
        {
            "input_line": input_line,
            "task_id": task.task_id,
            "report_id": task.report_id,
            "entry_id": task.entry_id,
            "inputs_sha256": canonical_sha256(task.inputs),
        }
    )


def _input_failure_correlation(record: InputFailureRecord) -> str:
    return "INPUT-" + canonical_sha256(
        {
            "input_line": record.input_line,
            "task_id": record.task_id,
            "raw_sha256": record.raw_sha256,
        }
    )


def _binding_correlation(
    *,
    input_line: int,
    task_id: str,
    report_id: str | None,
    entry_id: str | None,
    inputs_sha256: str,
) -> str:
    return "RUN-" + canonical_sha256(
        {
            "input_line": input_line,
            "task_id": task_id,
            "report_id": report_id,
            "entry_id": entry_id,
            "inputs_sha256": inputs_sha256,
        }
    )


def _make_envelope(
    *,
    kind: str,
    record_key: str,
    task_id: str | None,
    input_line: int,
    correlation_id: str,
    attempt: int,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    body = {"record_key": record_key, **dict(payload)}
    return {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "kind": kind,
        "record_id": _record_id(kind, correlation_id, record_key),
        "task_id": task_id,
        "input_line": input_line,
        "correlation_id": correlation_id,
        "attempt": attempt,
        "payload": body,
        "payload_sha256": canonical_sha256(body),
    }


def _plain_evidence(item: EvidenceItem) -> dict[str, Any]:
    return item.to_dict()


def _source_outcome_sha256(outcome: ClosedLoopOutcome) -> str:
    """Commit to the exact source outcome without persisting sensitive text."""

    return canonical_sha256(
        {
            "status": outcome.status,
            "state_sha256": canonical_sha256(outcome.state.to_dict()),
            "entry_sha256": (
                None if outcome.entry is None else canonical_sha256(outcome.entry)
            ),
            "report_sha256": (
                None if outcome.report is None else canonical_sha256(outcome.report)
            ),
            "production_outcome_sha256": [
                canonical_sha256(item) for item in outcome.production_outcomes
            ],
            "deferred_outcome_sha256": (
                None
                if outcome.deferred_outcome is None
                else canonical_sha256(outcome.deferred_outcome)
            ),
            "validation_outcome_sha256": [
                canonical_sha256(
                    {
                        "report_sha256": canonical_sha256(item.report),
                        "evidence_sha256": canonical_sha256(
                            [_plain_evidence(ev) for ev in item.evidence]
                        ),
                    }
                )
                for item in outcome.validation_outcomes
            ],
            "repair_plan_sha256": [
                canonical_sha256(item) for item in outcome.repair_plans
            ],
            "error_sha256": (
                None if outcome.error is None else canonical_sha256(outcome.error)
            ),
            "changed_fields": list(outcome.changed_fields),
        }
    )


def _is_relative_repo_file(value: str) -> bool:
    try:
        return validate_repo_relative_path(value) == value
    except (TypeError, ValueError):
        return False


def _protected_tokens(paths: Sequence[str | os.PathLike[str]]) -> tuple[str, ...]:
    tokens: set[str] = set()
    for raw in paths:
        supplied = Path(raw).expanduser()
        lexical = supplied if supplied.is_absolute() else Path.cwd() / supplied
        resolved = supplied.resolve(strict=False)
        # Keep both spellings.  CI runners and managed Windows hosts commonly
        # expose their temporary directories through junctions/aliases, so a
        # configured path can differ textually from its resolved target.  Both
        # are sensitive and neither may appear in an artifact payload.
        for path in (lexical, resolved):
            value = str(path)
            if not value:
                continue
            tokens.add(value.casefold())
            tokens.add(value.replace("\\", "/").casefold())
            tokens.add(value.replace("/", "\\").casefold())
    return tuple(sorted(tokens, key=lambda item: (-len(item), item)))


def _ensure_replay_safe(value: Any, protected_tokens: Sequence[str]) -> None:
    """Reject actual configured roots; do not rewrite arbitrary source text."""

    def visit(item: Any, *, key: str | None = None) -> None:
        if isinstance(item, Mapping):
            for child_key, child in item.items():
                visit(child, key=str(child_key))
            return
        if isinstance(item, (list, tuple)):
            for child in item:
                visit(child, key=key)
            return
        if not isinstance(item, str):
            return
        if key == "file" and not _is_relative_repo_file(item):
            raise ReplayArtifactError(
                "artifact file fields must contain repository-relative paths"
            )
        folded = item.casefold()
        slash = item.replace("\\", "/").casefold()
        backslash = item.replace("/", "\\").casefold()
        if any(
            token in candidate
            for token in protected_tokens
            for candidate in (folded, slash, backslash)
        ):
            raise ReplayArtifactError(
                "artifact payload contains a configured local path"
            )

    visit(value)


def _paths_overlap(
    output_dir: Path, protected_paths: Sequence[str | os.PathLike[str]]
) -> bool:
    output = output_dir.expanduser().resolve(strict=False)
    for raw in protected_paths:
        protected = Path(raw).expanduser().resolve(strict=False)
        if (
            output == protected
            or output in protected.parents
            or protected in output.parents
        ):
            return True
    return False


def _call_envelopes(
    *,
    result: ProductionOutcome | ProductionDeferred,
    owner_record_id: str,
    task_id: str,
    input_line: int,
    correlation_id: str,
    seen_tool_ids: set[str],
    seen_model_ids: set[str],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, str],
    dict[str, str],
]:
    tools: list[dict[str, Any]] = []
    models: list[dict[str, Any]] = []
    tool_refs: dict[str, str] = {}
    model_refs: dict[str, str] = {}
    for call in result.tool_calls:
        if call.tool_call_id in seen_tool_ids:
            raise ReplayArtifactError("duplicate tool_call_id within one run")
        seen_tool_ids.add(call.tool_call_id)
        envelope = _make_envelope(
            kind="tool_call",
            record_key=f"tool:{call.tool_call_id}",
            task_id=task_id,
            input_line=input_line,
            correlation_id=correlation_id,
            attempt=call.attempt,
            payload={
                "call": call.to_dict(),
                "call_sha256": canonical_sha256(call),
                "owner_record_id": owner_record_id,
            },
        )
        tools.append(envelope)
        tool_refs[call.tool_call_id] = envelope["record_id"]
    for call in result.model_calls:
        if call.model_call_id in seen_model_ids:
            raise ReplayArtifactError("duplicate model_call_id within one run")
        seen_model_ids.add(call.model_call_id)
        envelope = _make_envelope(
            kind="model_call",
            record_key=f"model:{call.model_call_id}",
            task_id=task_id,
            input_line=input_line,
            correlation_id=correlation_id,
            attempt=call.attempt,
            payload={
                "call": call.to_dict(),
                "call_sha256": canonical_sha256(call),
                "owner_record_id": owner_record_id,
            },
        )
        models.append(envelope)
        model_refs[call.model_call_id] = envelope["record_id"]
    return tools, models, tool_refs, model_refs


def _build_run_artifacts(
    record: ReplayRecord, protected: Sequence[str]
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    input_line = record.input_line
    task = record.task
    outcome = record.outcome
    state = outcome.state
    correlation = _run_correlation(input_line, task)
    task_id = task.task_id
    artifacts: dict[str, list[dict[str, Any]]] = {
        name: [] for name in _DATA_FILES
    }

    candidate_ids = [
        _record_id("candidate", correlation, f"candidate:{index}")
        for index in range(len(outcome.production_outcomes))
    ]
    validation_ids = [
        _record_id("validation", correlation, f"validation:{index}")
        for index in range(len(outcome.validation_outcomes))
    ]
    repair_ids = [
        _record_id("repair_plan", correlation, f"repair:{index}")
        for index in range(1, len(outcome.repair_plans) + 1)
    ]
    deferred_id = (
        None
        if outcome.deferred_outcome is None
        else _record_id(
            "deferred",
            correlation,
            f"deferred:{outcome.deferred_outcome.attempt}",
        )
    )
    state_id = _record_id("state", correlation, "state:terminal")

    producer_results: list[
        tuple[ProductionOutcome | ProductionDeferred, str, int]
    ] = [
        (item, candidate_ids[index], state.production_attempts[index].attempt)
        for index, item in enumerate(outcome.production_outcomes)
    ]
    if outcome.deferred_outcome is not None:
        assert deferred_id is not None
        producer_results.append(
            (
                outcome.deferred_outcome,
                deferred_id,
                outcome.deferred_outcome.attempt,
            )
        )

    seen_tool_ids: set[str] = set()
    seen_model_ids: set[str] = set()
    tool_ref_by_external: dict[str, str] = {}
    model_ref_by_external: dict[str, str] = {}
    owner_tool_refs: dict[str, list[str]] = {}
    owner_model_refs: dict[str, list[str]] = {}
    evidence_data: dict[str, dict[str, Any]] = {}
    evidence_order: list[str] = []

    def register_evidence(
        item: EvidenceItem, *, owner_id: str, attempt: int
    ) -> str:
        evidence_id = item.evidence_id
        plain = _plain_evidence(item)
        digest = canonical_sha256(plain)
        prior = evidence_data.get(evidence_id)
        if prior is None:
            prior = {
                "evidence": plain,
                "evidence_sha256": digest,
                "owners": [],
                "attempts": [],
            }
            evidence_data[evidence_id] = prior
            evidence_order.append(evidence_id)
        elif prior["evidence_sha256"] != digest:
            raise ReplayArtifactError("evidence_id has conflicting payloads")
        if owner_id not in prior["owners"]:
            prior["owners"].append(owner_id)
        if attempt not in prior["attempts"]:
            prior["attempts"].append(attempt)
        return _record_id("evidence", correlation, f"evidence:{evidence_id}")

    producer_evidence_refs: dict[str, list[str]] = {}
    for result, owner_id, attempt in producer_results:
        tools, models, tool_refs, model_refs = _call_envelopes(
            result=result,
            owner_record_id=owner_id,
            task_id=task_id,
            input_line=input_line,
            correlation_id=correlation,
            seen_tool_ids=seen_tool_ids,
            seen_model_ids=seen_model_ids,
        )
        artifacts["tool_calls.jsonl"].extend(tools)
        artifacts["model_calls.jsonl"].extend(models)
        tool_ref_by_external.update(tool_refs)
        model_ref_by_external.update(model_refs)
        owner_tool_refs[owner_id] = [
            tool_refs[item.tool_call_id] for item in result.tool_calls
        ]
        owner_model_refs[owner_id] = [
            model_refs[item.model_call_id] for item in result.model_calls
        ]
        producer_evidence_refs[owner_id] = [
            register_evidence(item, owner_id=owner_id, attempt=attempt)
            for item in result.evidence
        ]

    validation_evidence_refs: dict[str, list[str]] = {}
    for index, validation in enumerate(outcome.validation_outcomes):
        owner_id = validation_ids[index]
        attempt = state.validation_history[index].attempt
        validation_evidence_refs[owner_id] = [
            register_evidence(item, owner_id=owner_id, attempt=attempt)
            for item in validation.evidence
        ]

    evidence_envelopes: dict[str, dict[str, Any]] = {}
    for evidence_id in evidence_order:
        data = evidence_data[evidence_id]
        linked_tool = data["evidence"].get("tool_call_id")
        linked_tool_record_id = None
        if linked_tool is not None:
            linked_tool_record_id = tool_ref_by_external.get(linked_tool)
            if linked_tool_record_id is None:
                raise ReplayArtifactError(
                    "evidence references an unavailable tool call"
                )
        envelope = _make_envelope(
            kind="evidence",
            record_key=f"evidence:{evidence_id}",
            task_id=task_id,
            input_line=input_line,
            correlation_id=correlation,
            attempt=min(data["attempts"]),
            payload={
                "evidence": data["evidence"],
                "evidence_sha256": data["evidence_sha256"],
                "owner_record_ids": data["owners"],
                "observed_attempts": sorted(data["attempts"]),
                "tool_call_record_id": linked_tool_record_id,
            },
        )
        evidence_envelopes[evidence_id] = envelope
        artifacts["evidence.jsonl"].append(envelope)

    envelope_by_id: dict[str, dict[str, Any]] = {}
    for filename in ("tool_calls.jsonl", "model_calls.jsonl", "evidence.jsonl"):
        envelope_by_id.update(
            (item["record_id"], item) for item in artifacts[filename]
        )

    candidate_projection_sha256s: list[str] = []
    for index, production in enumerate(outcome.production_outcomes):
        summary = state.production_attempts[index]
        owner_id = candidate_ids[index]
        evidence_refs = producer_evidence_refs[owner_id]
        tool_refs = owner_tool_refs[owner_id]
        model_refs = owner_model_refs[owner_id]
        if canonical_sha256(production) != summary.outcome_sha256:
            raise ReplayArtifactError(
                "production outcome does not match its RunState summary"
            )
        projection_sha256 = canonical_sha256(
            {
                "candidate_sha256": production.candidate_sha256,
                "evidence_payload_sha256": [
                    envelope_by_id[item]["payload_sha256"] for item in evidence_refs
                ],
                "tool_call_payload_sha256": [
                    envelope_by_id[item]["payload_sha256"] for item in tool_refs
                ],
                "model_call_payload_sha256": [
                    envelope_by_id[item]["payload_sha256"] for item in model_refs
                ],
            }
        )
        candidate_projection_sha256s.append(projection_sha256)
        envelope = _make_envelope(
            kind="candidate",
            record_key=f"candidate:{index}",
            task_id=task_id,
            input_line=input_line,
            correlation_id=correlation,
            attempt=summary.attempt,
            payload={
                "candidate": dict(production.candidate),
                "candidate_sha256": production.candidate_sha256,
                "production_outcome_sha256": summary.outcome_sha256,
                "projection_sha256": projection_sha256,
                "mode": summary.mode,
                "disposition": summary.disposition,
                "parent_candidate_record_id": (
                    None if index == 0 else candidate_ids[index - 1]
                ),
                "repair_plan_record_id": (
                    None if index == 0 else repair_ids[index - 1]
                ),
                "evidence_record_ids": evidence_refs,
                "tool_call_record_ids": tool_refs,
                "model_call_record_ids": model_refs,
            },
        )
        artifacts["candidates.jsonl"].append(envelope)
        envelope_by_id[envelope["record_id"]] = envelope

    validation_projection_sha256s: list[str] = []
    for index, validation in enumerate(outcome.validation_outcomes):
        summary = state.validation_history[index]
        owner_id = validation_ids[index]
        evidence_refs = validation_evidence_refs[owner_id]
        report_sha256 = canonical_sha256(validation.report)
        source_evidence_sha256 = canonical_sha256(
            [_plain_evidence(item) for item in validation.evidence]
        )
        if (
            report_sha256 != summary.validation_sha256
            or source_evidence_sha256 != summary.evidence_sha256
        ):
            raise ReplayArtifactError(
                "validation outcome does not match its RunState summary"
            )
        projection_sha256 = canonical_sha256(
            {
                "report_sha256": report_sha256,
                "evidence_payload_sha256": [
                    envelope_by_id[item]["payload_sha256"] for item in evidence_refs
                ],
            }
        )
        validation_projection_sha256s.append(projection_sha256)
        envelope = _make_envelope(
            kind="validation",
            record_key=f"validation:{index}",
            task_id=task_id,
            input_line=input_line,
            correlation_id=correlation,
            attempt=summary.attempt,
            payload={
                "report": validation.report.to_dict(),
                "report_sha256": report_sha256,
                "source_evidence_sha256": source_evidence_sha256,
                "projection_sha256": projection_sha256,
                "candidate_record_id": candidate_ids[index],
                "evidence_record_ids": evidence_refs,
            },
        )
        artifacts["validations.jsonl"].append(envelope)
        envelope_by_id[envelope["record_id"]] = envelope

    repair_sha256s: list[str] = []
    for index, plan in enumerate(outcome.repair_plans, start=1):
        plan_sha256 = canonical_sha256(plan)
        repair_sha256s.append(plan_sha256)
        child_candidate = candidate_ids[index] if index < len(candidate_ids) else None
        child_deferred = (
            deferred_id
            if outcome.deferred_outcome is not None
            and outcome.deferred_outcome.attempt == index
            else None
        )
        envelope = _make_envelope(
            kind="repair_plan",
            record_key=f"repair:{index}",
            task_id=task_id,
            input_line=input_line,
            correlation_id=correlation,
            attempt=index,
            payload={
                "repair_plan": plan.to_dict(),
                "repair_plan_sha256": plan_sha256,
                "parent_candidate_record_id": candidate_ids[index - 1],
                "parent_validation_record_id": validation_ids[index - 1],
                "child_candidate_record_id": child_candidate,
                "deferred_record_id": child_deferred,
            },
        )
        artifacts["repair_history.jsonl"].append(envelope)
        envelope_by_id[envelope["record_id"]] = envelope

    deferred_projection_sha256: str | None = None
    if outcome.deferred_outcome is not None:
        deferred = outcome.deferred_outcome
        assert deferred_id is not None
        full = deferred.to_dict()
        core = {
            key: value
            for key, value in full.items()
            if key not in {"evidence", "tool_calls", "model_calls"}
        }
        core_sha256 = canonical_sha256(core)
        evidence_refs = producer_evidence_refs[deferred_id]
        tool_refs = owner_tool_refs[deferred_id]
        model_refs = owner_model_refs[deferred_id]
        deferred_projection_sha256 = canonical_sha256(
            {
                "deferred_core_sha256": core_sha256,
                "evidence_payload_sha256": [
                    envelope_by_id[item]["payload_sha256"] for item in evidence_refs
                ],
                "tool_call_payload_sha256": [
                    envelope_by_id[item]["payload_sha256"] for item in tool_refs
                ],
                "model_call_payload_sha256": [
                    envelope_by_id[item]["payload_sha256"] for item in model_refs
                ],
            }
        )
        envelope = _make_envelope(
            kind="deferred",
            record_key=f"deferred:{deferred.attempt}",
            task_id=task_id,
            input_line=input_line,
            correlation_id=correlation,
            attempt=deferred.attempt,
            payload={
                "deferred": core,
                "deferred_core_sha256": core_sha256,
                "deferred_sha256": canonical_sha256(deferred),
                "projection_sha256": deferred_projection_sha256,
                "parent_candidate_record_id": (
                    None
                    if deferred.attempt == 0
                    else candidate_ids[deferred.attempt - 1]
                ),
                "repair_plan_record_id": (
                    None
                    if deferred.attempt == 0
                    else repair_ids[deferred.attempt - 1]
                ),
                "evidence_record_ids": evidence_refs,
                "tool_call_record_ids": tool_refs,
                "model_call_record_ids": model_refs,
            },
        )
        artifacts["deferred.jsonl"].append(envelope)
        envelope_by_id[envelope["record_id"]] = envelope

    state_dict = state.to_dict()
    state_sha256 = canonical_sha256(state_dict)
    entry_sha256 = None if outcome.entry is None else canonical_sha256(outcome.entry)
    report_sha256 = (
        None if outcome.report is None else canonical_sha256(outcome.report)
    )
    error_sha256 = None if outcome.error is None else canonical_sha256(outcome.error)
    source_outcome_sha256 = _source_outcome_sha256(outcome)
    outcome_projection_sha256 = canonical_sha256(
        {
            "status": outcome.status,
            "state_sha256": state_sha256,
            "entry_sha256": entry_sha256,
            "report_sha256": report_sha256,
            "production_projection_sha256": candidate_projection_sha256s,
            "deferred_projection_sha256": deferred_projection_sha256,
            "validation_projection_sha256": validation_projection_sha256s,
            "repair_plan_sha256": repair_sha256s,
            "error_sha256": error_sha256,
            "changed_fields": list(outcome.changed_fields),
        }
    )
    state_envelope = _make_envelope(
        kind="state",
        record_key="state:terminal",
        task_id=task_id,
        input_line=input_line,
        correlation_id=correlation,
        attempt=state.repair_iteration,
        payload={
            "state": state_dict,
            "state_sha256": state_sha256,
            "entry_sha256": entry_sha256,
            "report_sha256": report_sha256,
            "error_sha256": error_sha256,
            "source_outcome_sha256": source_outcome_sha256,
            "outcome_projection_sha256": outcome_projection_sha256,
            "changed_fields": list(outcome.changed_fields),
            "candidate_record_ids": candidate_ids,
            "validation_record_ids": validation_ids,
            "repair_plan_record_ids": repair_ids,
            "deferred_record_id": deferred_id,
        },
    )
    artifacts["states.jsonl"].append(state_envelope)

    if (
        outcome.status == "finalized"
        and outcome.report is not None
        and outcome.report.verdict == "correct"
    ):
        if outcome.entry is None:
            raise ReplayArtifactError("a finalized correct outcome requires an entry")
        # This file is the consumable T2 dataset, so its lines deliberately
        # contain only the exact 15-field formal Entry and no replay metadata.
        formal_entry = dict(ProductionOutcome(candidate=outcome.entry).candidate)
        artifacts[_ENTRY_FILE].append(formal_entry)
    if outcome.report is not None:
        artifacts[_FORMAL_VALIDATION_FILE].append(outcome.report.to_dict())

    # Evidence can first appear in producer or validator sidecars.  Emit the
    # deduplicated records in canonical attempt order regardless of owner type.
    artifacts["evidence.jsonl"].sort(key=lambda item: item["attempt"])

    for envelopes in artifacts.values():
        for envelope in envelopes:
            _ensure_replay_safe(envelope, protected)

    root = _make_envelope(
        kind="run_manifest",
        record_key="manifest:run",
        task_id=task_id,
        input_line=input_line,
        correlation_id=correlation,
        attempt=state.repair_iteration,
        payload={
            "root_record_id": state_id,
            "root_kind": "state",
            "status": outcome.status,
            "state_sha256": state_sha256,
            "source_outcome_sha256": source_outcome_sha256,
            "outcome_projection_sha256": outcome_projection_sha256,
            "entry_sha256": (
                entry_sha256 if outcome.status == "finalized" else None
            ),
            "formal_validation_sha256": report_sha256,
        },
    )
    _ensure_replay_safe(root, protected)
    return artifacts, root


def _build_input_failure(
    record: InputFailureRecord, protected: Sequence[str]
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    correlation = _input_failure_correlation(record)
    artifacts = {name: [] for name in _DATA_FILES}
    error = _make_envelope(
        kind="input_failure",
        record_key="input:failure",
        task_id=record.task_id,
        input_line=record.input_line,
        correlation_id=correlation,
        attempt=0,
        payload={
            "error_code": record.error_code,
            "raw_sha256": record.raw_sha256,
        },
    )
    artifacts["errors.jsonl"].append(error)
    root = _make_envelope(
        kind="run_manifest",
        record_key="manifest:input_failure",
        task_id=record.task_id,
        input_line=record.input_line,
        correlation_id=correlation,
        attempt=0,
        payload={
            "root_record_id": error["record_id"],
            "root_kind": "input_failure",
            "status": "input_failure",
            "raw_sha256": record.raw_sha256,
            "error_code": record.error_code,
        },
    )
    _ensure_replay_safe(error, protected)
    _ensure_replay_safe(root, protected)
    return artifacts, root


class _ArtifactSink:
    def __init__(self, directory: Path, limits: ReplayLimits) -> None:
        self.directory = directory
        self.limits = limits
        self.files: dict[str, _FileState] = {}
        self.total_bytes = 0
        for filename in REPLAY_FILES:
            handle = (directory / filename).open("xb")
            self.files[filename] = _FileState(handle=handle)

    def emit(self, filename: str, envelope: Mapping[str, Any]) -> bytes:
        if filename not in self.files:
            raise ReplayArtifactError("unknown replay artifact file")
        state = self.files[filename]
        if state.line_count >= self.limits.max_records_per_file:
            raise ReplayArtifactError(f"{filename} exceeds its record limit")
        encoded = canonical_json(envelope).encode("utf-8") + b"\n"
        if len(encoded) > self.limits.max_line_bytes:
            raise ReplayArtifactError(f"{filename} contains an oversized line")
        if self.total_bytes + len(encoded) > self.limits.max_total_bytes:
            raise ReplayArtifactError("replay artifacts exceed the total byte limit")
        state.handle.write(encoded)
        state.digest.update(encoded)
        state.line_count += 1
        state.byte_count += len(encoded)
        self.total_bytes += len(encoded)
        return encoded

    def summary(self, filename: str) -> dict[str, Any]:
        state = self.files[filename]
        return {
            "content_sha256": state.digest.hexdigest(),
            "byte_count": state.byte_count,
            "line_count": state.line_count,
        }

    def close(self) -> None:
        first_error: OSError | None = None
        for state in self.files.values():
            try:
                if not state.handle.closed:
                    state.handle.flush()
                    os.fsync(state.handle.fileno())
                    state.handle.close()
            except OSError as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error


def _safe_remove_staging(staging: Path, output: Path) -> None:
    try:
        resolved = staging.resolve(strict=False)
        parent = output.parent.resolve(strict=True)
    except OSError:
        return
    if (
        resolved.parent == parent
        and resolved.name.startswith(f".{output.name}.staging-")
        and resolved.exists()
    ):
        shutil.rmtree(resolved)


def _is_reparse(stat_result: os.stat_result) -> bool:
    return bool(getattr(stat_result, "st_file_attributes", 0) & 0x400)


def _file_identity(stat_result: os.stat_result) -> tuple[int, int, int, int]:
    return (
        stat_result.st_dev,
        stat_result.st_ino,
        stat.S_IFMT(stat_result.st_mode),
        getattr(stat_result, "st_file_attributes", 0),
    )


def _safe_directory_identity(path: Path) -> tuple[int, int, int, int]:
    try:
        result = path.lstat()
    except OSError as error:
        raise ReplayArtifactError("replay directory is unavailable") from error
    if not stat.S_ISDIR(result.st_mode) or stat.S_ISLNK(result.st_mode) or _is_reparse(
        result
    ):
        raise ReplayArtifactError(
            "replay directory must not be a symlink, junction, or reparse point"
        )
    return _file_identity(result)


@contextmanager
def _safe_binary_reader(
    path: Path,
    *,
    root: Path | None = None,
    root_identity: tuple[int, int, int, int] | None = None,
) -> Iterator[Any]:
    """Open one regular file and detect link/reparse swaps around the read."""

    parent = path.parent if root is None else root
    expected_root = (
        _safe_directory_identity(parent) if root_identity is None else root_identity
    )
    if _safe_directory_identity(parent) != expected_root:
        raise ReplayArtifactError("replay directory identity changed")
    try:
        before = path.lstat()
    except OSError as error:
        raise ReplayArtifactError(f"{path.name} is unavailable") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
    ):
        raise ReplayArtifactError(
            f"{path.name} must be a regular non-link artifact file"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReplayArtifactError(f"{path.name} could not be opened safely") from error
    handle: Any | None = None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or _file_identity(opened) != _file_identity(before)
        ):
            raise ReplayArtifactError(f"{path.name} changed during safe open")
        handle = os.fdopen(descriptor, "rb", closefd=True)
        descriptor = -1
        yield handle
        after = path.lstat()
        if (
            _file_identity(after) != _file_identity(before)
            or stat.S_ISLNK(after.st_mode)
            or _is_reparse(after)
            or _safe_directory_identity(parent) != expected_root
        ):
            raise ReplayArtifactError(f"{path.name} changed while being read")
    except OSError as error:
        raise ReplayArtifactError(f"{path.name} changed while being read") from error
    finally:
        if handle is not None:
            handle.close()
        elif descriptor >= 0:
            os.close(descriptor)


def _rehash(
    path: Path,
    limits: ReplayLimits,
    *,
    root: Path | None = None,
    root_identity: tuple[int, int, int, int] | None = None,
) -> dict[str, Any]:
    digest = hashlib.sha256()
    byte_count = 0
    line_count = 0
    with _safe_binary_reader(
        path, root=root, root_identity=root_identity
    ) as handle:
        while True:
            line = handle.readline(limits.max_line_bytes + 1)
            if not line:
                break
            byte_count += len(line)
            if len(line) > limits.max_line_bytes:
                raise ReplayArtifactError(f"{path.name} contains an oversized line")
            if not line.endswith(b"\n"):
                raise ReplayArtifactError(f"{path.name} has an unterminated line")
            digest.update(line)
            line_count += 1
            if line_count > limits.max_records_per_file:
                raise ReplayArtifactError(f"{path.name} exceeds its record limit")
            if byte_count > limits.max_total_bytes:
                raise ReplayArtifactError("artifact file exceeds the total byte limit")
    return {
        "content_sha256": digest.hexdigest(),
        "byte_count": byte_count,
        "line_count": line_count,
    }


def write_closed_loop_artifacts(
    output_dir: str | os.PathLike[str],
    events: Iterable[ReplayEvent],
    *,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
    limits: ReplayLimits | None = None,
) -> ReplayManifest:
    """Atomically write a single-pass, input-line-ordered replay event stream.

    ``output_dir`` must not exist.  A protected path may not overlap the output
    directory, and its canonical spelling must not occur in emitted payloads.
    Callers that also publish non-replay files can invoke this writer inside
    their own outer staging directory before publishing that outer directory.
    """

    active_limits = limits or ReplayLimits()
    if not isinstance(active_limits, ReplayLimits):
        raise ValueError("limits must be ReplayLimits")
    output = Path(output_dir).expanduser().resolve(strict=False)
    parent = output.parent
    if not parent.exists() or not parent.is_dir():
        raise ReplayArtifactError("output parent must be an existing directory")
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"output directory already exists: {output.name}")
    if _paths_overlap(output, protected_paths):
        raise ReplayArtifactError("output directory overlaps a protected input path")
    protected = _protected_tokens((*protected_paths, output))
    staging = parent / f".{output.name}.staging-{uuid.uuid4().hex}"
    staging.mkdir(mode=0o700)
    sink: _ArtifactSink | None = None
    try:
        sink = _ArtifactSink(staging, active_limits)
        previous_line = 0
        input_records = 0
        outcome_records = 0
        failure_records = 0
        entry_count = 0
        formal_validation_count = 0
        validation_attempt_count = 0
        seen_task_ids: set[str] = set()
        seen_entry_ids: set[str] = set()
        seen_correlations: set[str] = set()
        roots_digest = hashlib.sha256()
        roots_bytes = 0
        roots_count = 0

        iterator = iter(events)
        for event in iterator:
            if not isinstance(event, (ReplayRecord, InputFailureRecord)):
                raise ReplayArtifactError(
                    "events must contain ReplayRecord or InputFailureRecord"
                )
            if event.input_line <= previous_line:
                raise ReplayArtifactError(
                    "events must be strictly ordered by unique input_line"
                )
            previous_line = event.input_line
            input_records += 1
            if input_records > active_limits.max_input_records:
                raise ReplayArtifactError("event stream exceeds max_input_records")
            task_id = event.task.task_id if isinstance(event, ReplayRecord) else event.task_id
            if task_id is not None:
                if task_id in seen_task_ids:
                    raise ReplayArtifactError("task_id must be globally unique")
                seen_task_ids.add(task_id)
            if isinstance(event, ReplayRecord):
                event_entry_ids = {
                    item.candidate["entry_id"]
                    for item in event.outcome.production_outcomes
                }
                if event.outcome.deferred_outcome is not None:
                    event_entry_ids.add(event.outcome.deferred_outcome.entry_id)
                if event.task.entry_id is not None:
                    event_entry_ids.add(event.task.entry_id)
                if len(event_entry_ids) > 1:
                    raise ReplayArtifactError(
                        "one run cannot contain multiple entry_id values"
                    )
                if event_entry_ids:
                    entry_id = next(iter(event_entry_ids))
                    if entry_id in seen_entry_ids:
                        raise ReplayArtifactError("entry_id must be globally unique")
                    seen_entry_ids.add(entry_id)
                artifacts, root = _build_run_artifacts(event, protected)
                outcome_records += 1
            else:
                artifacts, root = _build_input_failure(event, protected)
                failure_records += 1
            correlation = root["correlation_id"]
            if correlation in seen_correlations:
                raise ReplayArtifactError("correlation_id must be globally unique")
            seen_correlations.add(correlation)
            for filename in _DATA_FILES:
                for envelope in artifacts[filename]:
                    sink.emit(filename, envelope)
                    if filename == _ENTRY_FILE:
                        entry_count += 1
                    elif filename == _FORMAL_VALIDATION_FILE:
                        formal_validation_count += 1
                    elif filename == "validations.jsonl":
                        validation_attempt_count += 1
            root_bytes = sink.emit(_MANIFEST_FILE, root)
            roots_digest.update(root_bytes)
            roots_bytes += len(root_bytes)
            roots_count += 1

        file_summaries = {
            filename: sink.summary(filename) for filename in _DATA_FILES
        }
        manifest_roots = {
            "content_sha256": roots_digest.hexdigest(),
            "byte_count": roots_bytes,
            "line_count": roots_count,
        }
        dataset_core = {
            "schema_version": REPLAY_SCHEMA_VERSION,
            "files": file_summaries,
            "manifest_roots": manifest_roots,
            "input_records": input_records,
            "outcome_records": outcome_records,
            "input_failures": failure_records,
            "entry_count": entry_count,
            "formal_validation_count": formal_validation_count,
            "validation_attempt_count": validation_attempt_count,
        }
        dataset_sha256 = canonical_sha256(dataset_core)
        footer = _make_envelope(
            kind="dataset_manifest",
            record_key="manifest:dataset",
            task_id="_manifest",
            input_line=0,
            correlation_id=f"DATASET-{dataset_sha256}",
            attempt=0,
            payload={**dataset_core, "dataset_sha256": dataset_sha256},
        )
        _ensure_replay_safe(footer, protected)
        sink.emit(_MANIFEST_FILE, footer)
        footer_payload_sha256 = footer["payload_sha256"]
        sink.close()
        sink = None

        for filename in _DATA_FILES:
            if _rehash(staging / filename, active_limits) != file_summaries[filename]:
                raise ReplayArtifactError(
                    f"{filename} changed while the staging transaction was open"
                )
        manifest_summary = _rehash(staging / _MANIFEST_FILE, active_limits)
        if manifest_summary["line_count"] != roots_count + 1:
            raise ReplayArtifactError("manifest staging verification failed")
        total_bytes = sum(
            summary["byte_count"] for summary in file_summaries.values()
        ) + manifest_summary["byte_count"]
        if total_bytes > active_limits.max_total_bytes:
            raise ReplayArtifactError("replay artifacts exceed the total byte limit")

        os.rename(staging, output)
        return ReplayManifest(
            dataset_sha256=dataset_sha256,
            input_records=input_records,
            outcome_records=outcome_records,
            input_failures=failure_records,
            entry_count=entry_count,
            formal_validation_count=formal_validation_count,
            validation_attempt_count=validation_attempt_count,
            files=file_summaries,
            payload_sha256=footer_payload_sha256,
        )
    except BaseException:
        if sink is not None:
            try:
                sink.close()
            except OSError:
                pass
        _safe_remove_staging(staging, output)
        raise


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReplayArtifactError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _iter_canonical_lines(
    path: Path,
    limits: ReplayLimits,
    *,
    root: Path | None = None,
    root_identity: tuple[int, int, int, int] | None = None,
    summary: dict[str, Any] | None = None,
) -> Iterator[tuple[dict[str, Any], bytes]]:
    byte_count = 0
    line_count = 0
    digest = hashlib.sha256()
    with _safe_binary_reader(
        path, root=root, root_identity=root_identity
    ) as handle:
        while True:
            raw = handle.readline(limits.max_line_bytes + 1)
            if not raw:
                break
            byte_count += len(raw)
            line_count += 1
            if len(raw) > limits.max_line_bytes:
                raise ReplayArtifactError(f"{path.name} contains an oversized line")
            if line_count > limits.max_records_per_file:
                raise ReplayArtifactError(f"{path.name} exceeds its record limit")
            if byte_count > limits.max_total_bytes:
                raise ReplayArtifactError("artifact file exceeds the total byte limit")
            if not raw.endswith(b"\n") or raw.endswith(b"\r\n"):
                raise ReplayArtifactError(
                    f"{path.name} must contain canonical LF-terminated JSONL"
                )
            try:
                decoded = raw[:-1].decode("utf-8")
                value = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ReplayArtifactError(f"{path.name} contains invalid JSON") from error
            if not isinstance(value, dict):
                raise ReplayArtifactError(f"{path.name} lines must be objects")
            try:
                canonical = canonical_json(value).encode("utf-8") + b"\n"
            except (TypeError, ValueError) as error:
                raise ReplayArtifactError(
                    f"{path.name} contains non-canonical JSON data"
                ) from error
            if raw != canonical:
                raise ReplayArtifactError(f"{path.name} is not canonical JSONL")
            digest.update(raw)
            yield value, raw
    if summary is not None:
        summary.update(
            {
                "content_sha256": digest.hexdigest(),
                "byte_count": byte_count,
                "line_count": line_count,
            }
        )


def _validate_envelope(
    envelope: Mapping[str, Any],
    *,
    allowed_kind: str | frozenset[str],
    protected: Sequence[str],
) -> None:
    if set(envelope) != _ENVELOPE_KEYS:
        raise ReplayArtifactError("artifact envelope has missing or extra fields")
    if envelope["schema_version"] != REPLAY_SCHEMA_VERSION:
        raise ReplayArtifactError("unsupported replay schema version")
    kinds = {allowed_kind} if isinstance(allowed_kind, str) else set(allowed_kind)
    if envelope["kind"] not in kinds:
        raise ReplayArtifactError("artifact kind does not match its file")
    if not isinstance(envelope["record_id"], str) or not _RECORD_ID_RE.fullmatch(
        envelope["record_id"]
    ):
        raise ReplayArtifactError("record_id has an invalid format")
    task_id = envelope["task_id"]
    if task_id != "_manifest" and task_id is not None and (
        not isinstance(task_id, str) or not _TASK_ID_RE.fullmatch(task_id)
    ):
        raise ReplayArtifactError("task_id has an invalid format")
    if (
        isinstance(envelope["input_line"], bool)
        or not isinstance(envelope["input_line"], int)
        or envelope["input_line"] < 0
    ):
        raise ReplayArtifactError("input_line is invalid")
    if not isinstance(envelope["correlation_id"], str) or not _CORRELATION_RE.fullmatch(
        envelope["correlation_id"]
    ):
        raise ReplayArtifactError("correlation_id has an invalid format")
    if (
        isinstance(envelope["attempt"], bool)
        or not isinstance(envelope["attempt"], int)
        or not 0 <= envelope["attempt"] <= 2
    ):
        raise ReplayArtifactError("attempt is invalid")
    payload = envelope["payload"]
    if not isinstance(payload, Mapping) or not isinstance(
        payload.get("record_key"), str
    ):
        raise ReplayArtifactError("payload must contain record_key")
    if canonical_sha256(payload) != envelope["payload_sha256"]:
        raise ReplayArtifactError("payload_sha256 does not match payload")
    expected_id = _record_id(
        envelope["kind"], envelope["correlation_id"], payload["record_key"]
    )
    if envelope["record_id"] != expected_id:
        raise ReplayArtifactError("record_id does not bind its canonical identity")
    _ensure_replay_safe(envelope, protected)


def _expect_keys(payload: Mapping[str, Any], keys: set[str], kind: str) -> None:
    expected = {"record_key", *keys}
    if set(payload) != expected:
        raise ReplayArtifactError(f"{kind} payload has missing or extra fields")


def _validation_report_from_dict(value: Any) -> ValidationReport:
    if not isinstance(value, Mapping) or set(value) != {
        "entry_id",
        "input_line",
        "report_id",
        "verdict",
        "fields",
        "summary",
        "missing_information",
    }:
        raise ReplayArtifactError("validation report has an invalid shape")
    fields_value = value["fields"]
    if not isinstance(fields_value, Mapping):
        raise ReplayArtifactError("validation report fields must be an object")
    fields: dict[str, FieldValidation] = {}
    for name, item in fields_value.items():
        if not isinstance(item, Mapping):
            raise ReplayArtifactError("validation field must be an object")
        allowed = {
            "status",
            "confidence",
            "evidence",
            "evidence_refs",
            "suggested_fix",
        }
        if not {"status", "confidence", "evidence"}.issubset(item) or not set(
            item
        ) <= allowed:
            raise ReplayArtifactError("validation field has invalid properties")
        try:
            fields[name] = FieldValidation(
                status=item["status"],
                confidence=item["confidence"],
                evidence=item["evidence"],
                evidence_refs=tuple(item.get("evidence_refs", ())),
                suggested_fix=item.get("suggested_fix"),
            )
        except (TypeError, ValueError) as error:
            raise ReplayArtifactError("validation field is invalid") from error
    try:
        return ValidationReport(
            report_id=value["report_id"],
            entry_id=value["entry_id"],
            input_line=value["input_line"],
            verdict=value["verdict"],
            fields=fields,
            summary=value["summary"],
            missing_information=tuple(value["missing_information"]),
        )
    except (TypeError, ValueError) as error:
        raise ReplayArtifactError("validation report is invalid") from error


def _reference_list(value: Any, name: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) for item in value)
        or len(value) != len(set(value))
    ):
        raise ReplayArtifactError(f"{name} must be an ordered unique ID array")
    return tuple(value)


def _selected_payload(kind: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
    if kind == "tool_call":
        _expect_keys(payload, {"call", "call_sha256", "owner_record_id"}, kind)
        try:
            call = ToolCallRecord.from_dict(payload["call"])
        except (TypeError, ValueError) as error:
            raise ReplayArtifactError("invalid tool call payload") from error
        if canonical_sha256(call) != payload["call_sha256"]:
            raise ReplayArtifactError("tool call digest mismatch")
        return {
            "owner": payload["owner_record_id"],
            "task_id": call.task_id,
            "attempt": call.attempt,
            "external_id": call.tool_call_id,
            "sequence": call.budget_event_sequence,
            "operation": call.operation,
            "resource": "tool_calls",
        }
    if kind == "model_call":
        _expect_keys(payload, {"call", "call_sha256", "owner_record_id"}, kind)
        try:
            call = ModelCallRecord.from_dict(payload["call"])
        except (TypeError, ValueError) as error:
            raise ReplayArtifactError("invalid model call payload") from error
        if canonical_sha256(call) != payload["call_sha256"]:
            raise ReplayArtifactError("model call digest mismatch")
        return {
            "owner": payload["owner_record_id"],
            "task_id": call.task_id,
            "attempt": call.attempt,
            "external_id": call.model_call_id,
            "sequence": call.budget_event_sequence,
            "operation": call.operation,
            "resource": "llm_calls",
        }
    if kind == "evidence":
        _expect_keys(
            payload,
            {
                "evidence",
                "evidence_sha256",
                "owner_record_ids",
                "observed_attempts",
                "tool_call_record_id",
            },
            kind,
        )
        try:
            evidence = EvidenceItem(**dict(payload["evidence"]))
        except (TypeError, ValueError) as error:
            raise ReplayArtifactError("invalid evidence payload") from error
        if canonical_sha256(evidence) != payload["evidence_sha256"]:
            raise ReplayArtifactError("evidence digest mismatch")
        owners = payload["owner_record_ids"]
        attempts = payload["observed_attempts"]
        if (
            not isinstance(owners, list)
            or not owners
            or len(owners) != len(set(owners))
            or any(not isinstance(item, str) for item in owners)
            or not isinstance(attempts, list)
            or not attempts
            or attempts != sorted(set(attempts))
            or any(type(item) is not int or not 0 <= item <= 2 for item in attempts)
        ):
            raise ReplayArtifactError("invalid evidence owners or attempts")
        return {
            "owners": tuple(owners),
            "tool": payload["tool_call_record_id"],
            "tool_external_id": evidence.tool_call_id,
            "report_id": evidence.report_id,
            "entry_id": evidence.entry_id,
            "evidence_id": evidence.evidence_id,
            "attempts": tuple(attempts),
        }
    if kind == "candidate":
        _expect_keys(
            payload,
            {
                "candidate",
                "candidate_sha256",
                "production_outcome_sha256",
                "projection_sha256",
                "mode",
                "disposition",
                "parent_candidate_record_id",
                "repair_plan_record_id",
                "evidence_record_ids",
                "tool_call_record_ids",
                "model_call_record_ids",
            },
            kind,
        )
        try:
            candidate = ProductionOutcome(candidate=payload["candidate"])
        except (TypeError, ValueError) as error:
            raise ReplayArtifactError("invalid candidate payload") from error
        if candidate.candidate_sha256 != payload["candidate_sha256"]:
            raise ReplayArtifactError("candidate digest mismatch")
        for name in (
            "production_outcome_sha256",
            "projection_sha256",
        ):
            _require_sha256(payload[name], name)
        if payload["mode"] not in {"generated", "provided", "repair"} or payload[
            "disposition"
        ] not in {
            "accepted",
            "rejected_locked_fields",
            "rejected_no_progress",
        }:
            raise ReplayArtifactError("candidate mode or disposition is invalid")
        return {
            "candidate_sha256": payload["candidate_sha256"],
            "source_sha256": payload["production_outcome_sha256"],
            "projection_sha256": payload["projection_sha256"],
            "parent": payload["parent_candidate_record_id"],
            "repair": payload["repair_plan_record_id"],
            "evidence": _reference_list(
                payload["evidence_record_ids"], "candidate evidence refs"
            ),
            "tools": _reference_list(
                payload["tool_call_record_ids"], "candidate tool refs"
            ),
            "models": _reference_list(
                payload["model_call_record_ids"], "candidate model refs"
            ),
            "report_id": candidate.candidate["report_id"],
            "entry_id": candidate.candidate["entry_id"],
            "mode": payload["mode"],
            "disposition": payload["disposition"],
        }
    if kind == "validation":
        _expect_keys(
            payload,
            {
                "report",
                "report_sha256",
                "source_evidence_sha256",
                "projection_sha256",
                "candidate_record_id",
                "evidence_record_ids",
            },
            kind,
        )
        report = _validation_report_from_dict(payload["report"])
        if canonical_sha256(report) != payload["report_sha256"]:
            raise ReplayArtifactError("validation report digest mismatch")
        for name in (
            "report_sha256",
            "source_evidence_sha256",
            "projection_sha256",
        ):
            _require_sha256(payload[name], name)
        report_evidence_ids = {
            evidence_id
            for field in report.fields.values()
            for evidence_id in field.evidence_refs
        }
        return {
            "report_sha256": payload["report_sha256"],
            "source_evidence_sha256": payload["source_evidence_sha256"],
            "projection_sha256": payload["projection_sha256"],
            "candidate": payload["candidate_record_id"],
            "evidence": _reference_list(
                payload["evidence_record_ids"], "validation evidence refs"
            ),
            "report_evidence_ids": frozenset(report_evidence_ids),
            "report_id": report.report_id,
            "entry_id": report.entry_id,
            "input_line": report.input_line,
            "verdict": report.verdict,
        }
    if kind == "repair_plan":
        _expect_keys(
            payload,
            {
                "repair_plan",
                "repair_plan_sha256",
                "parent_candidate_record_id",
                "parent_validation_record_id",
                "child_candidate_record_id",
                "deferred_record_id",
            },
            kind,
        )
        try:
            plan = RepairPlan.from_dict(payload["repair_plan"])
        except (TypeError, ValueError) as error:
            raise ReplayArtifactError("invalid repair plan payload") from error
        if canonical_sha256(plan) != payload["repair_plan_sha256"]:
            raise ReplayArtifactError("repair plan digest mismatch")
        if (
            payload["child_candidate_record_id"] is not None
            and payload["deferred_record_id"] is not None
        ):
            raise ReplayArtifactError(
                "repair plan cannot have both candidate and deferred children"
            )
        return {
            "plan_sha256": payload["repair_plan_sha256"],
            "task_id": plan.task_id,
            "report_id": plan.report_id,
            "entry_id": plan.entry_id,
            "repair_iteration": plan.repair_iteration,
            "previous_candidate_sha256": plan.previous_candidate_sha256,
            "validation_sha256": plan.validation_sha256,
            "parent_candidate": payload["parent_candidate_record_id"],
            "parent_validation": payload["parent_validation_record_id"],
            "child_candidate": payload["child_candidate_record_id"],
            "deferred": payload["deferred_record_id"],
        }
    if kind == "deferred":
        _expect_keys(
            payload,
            {
                "deferred",
                "deferred_core_sha256",
                "deferred_sha256",
                "projection_sha256",
                "parent_candidate_record_id",
                "repair_plan_record_id",
                "evidence_record_ids",
                "tool_call_record_ids",
                "model_call_record_ids",
            },
            kind,
        )
        if not isinstance(payload["deferred"], Mapping) or canonical_sha256(
            payload["deferred"]
        ) != payload["deferred_core_sha256"]:
            raise ReplayArtifactError("deferred core digest mismatch")
        try:
            deferred_contract = ProductionDeferred.from_dict(
                {
                    **dict(payload["deferred"]),
                    "evidence": [],
                    "tool_calls": [],
                    "model_calls": [],
                }
            )
        except (TypeError, ValueError) as error:
            raise ReplayArtifactError("deferred core is invalid") from error
        for name in (
            "deferred_core_sha256",
            "deferred_sha256",
            "projection_sha256",
        ):
            _require_sha256(payload[name], name)
        return {
            "core_sha256": payload["deferred_core_sha256"],
            "source_sha256": payload["deferred_sha256"],
            "projection_sha256": payload["projection_sha256"],
            "parent": payload["parent_candidate_record_id"],
            "repair": payload["repair_plan_record_id"],
            "evidence": _reference_list(
                payload["evidence_record_ids"], "deferred evidence refs"
            ),
            "tools": _reference_list(
                payload["tool_call_record_ids"], "deferred tool refs"
            ),
            "models": _reference_list(
                payload["model_call_record_ids"], "deferred model refs"
            ),
            "task_id": deferred_contract.task_id,
            "report_id": deferred_contract.report_id,
            "entry_id": deferred_contract.entry_id,
            "attempt": deferred_contract.attempt,
            "mode": deferred_contract.mode,
            "inputs_sha256": deferred_contract.inputs_sha256,
            "parent_candidate_sha256": deferred_contract.parent_candidate_sha256,
            "repair_plan_sha256": deferred_contract.repair_plan_sha256,
        }
    if kind == "state":
        _expect_keys(
            payload,
            {
                "state",
                "state_sha256",
                "entry_sha256",
                "report_sha256",
                "error_sha256",
                "source_outcome_sha256",
                "outcome_projection_sha256",
                "changed_fields",
                "candidate_record_ids",
                "validation_record_ids",
                "repair_plan_record_ids",
                "deferred_record_id",
            },
            kind,
        )
        state = payload["state"]
        if not isinstance(state, Mapping) or canonical_sha256(state) != payload[
            "state_sha256"
        ]:
            raise ReplayArtifactError("state digest mismatch")
        for name in ("state_sha256", "source_outcome_sha256", "outcome_projection_sha256"):
            _require_sha256(payload[name], name)
        for name in ("entry_sha256", "report_sha256", "error_sha256"):
            if payload[name] is not None:
                _require_sha256(payload[name], name)
        changed_fields = payload["changed_fields"]
        if (
            not isinstance(changed_fields, list)
            or any(not isinstance(item, str) for item in changed_fields)
            or len(changed_fields) != len(set(changed_fields))
        ):
            raise ReplayArtifactError("changed_fields must be a unique string array")
        task = state.get("task")
        if not isinstance(task, Mapping) or set(task) != {
            "task_id",
            "report_id",
            "entry_id",
            "inputs_sha256",
        }:
            raise ReplayArtifactError("state task binding is invalid")
        _require_sha256(task["inputs_sha256"], "inputs_sha256")
        return {
            "state": state,
            "state_sha256": payload["state_sha256"],
            "entry_sha256": payload["entry_sha256"],
            "report_sha256": payload["report_sha256"],
            "error_sha256": payload["error_sha256"],
            "source_sha256": payload["source_outcome_sha256"],
            "projection_sha256": payload["outcome_projection_sha256"],
            "changed_fields": tuple(changed_fields),
            "candidates": _reference_list(
                payload["candidate_record_ids"], "state candidate refs"
            ),
            "validations": _reference_list(
                payload["validation_record_ids"], "state validation refs"
            ),
            "repairs": _reference_list(
                payload["repair_plan_record_ids"], "state repair refs"
            ),
            "deferred": payload["deferred_record_id"],
            "task": dict(task),
        }
    if kind == "input_failure":
        _expect_keys(payload, {"error_code", "raw_sha256"}, kind)
        if not isinstance(payload["error_code"], str) or not _ERROR_CODE_RE.fullmatch(
            payload["error_code"]
        ):
            raise ReplayArtifactError("input failure error_code is invalid")
        _require_sha256(payload["raw_sha256"], "raw_sha256")
        return {
            "error_code": payload["error_code"],
            "raw_sha256": payload["raw_sha256"],
        }
    raise ReplayArtifactError("unsupported artifact kind")


def _require_ref(
    index: Mapping[str, _IndexedRecord],
    source: _IndexedRecord,
    record_id: Any,
    expected_kinds: str | frozenset[str],
) -> _IndexedRecord:
    if not isinstance(record_id, str) or record_id not in index:
        raise ReplayArtifactError("artifact reference is unresolved")
    target = index[record_id]
    kinds = {expected_kinds} if isinstance(expected_kinds, str) else set(expected_kinds)
    if target.kind not in kinds:
        raise ReplayArtifactError("artifact reference has the wrong kind")
    if (
        target.correlation_id != source.correlation_id
        or target.input_line != source.input_line
        or target.task_id != source.task_id
    ):
        raise ReplayArtifactError("artifact reference crosses run identity")
    return target


def _verify_index(index: Mapping[str, _IndexedRecord]) -> None:
    by_correlation: dict[str, dict[str, set[str]]] = {}
    for record_id, source in index.items():
        selected = source.selected
        groups = by_correlation.setdefault(source.correlation_id, {})
        groups.setdefault(source.kind, set()).add(record_id)
        if source.kind in {"tool_call", "model_call"}:
            owner = _require_ref(
                index,
                source,
                selected["owner"],
                frozenset({"candidate", "deferred"}),
            )
            owner_key = "tools" if source.kind == "tool_call" else "models"
            if record_id not in owner.selected[owner_key]:
                raise ReplayArtifactError(
                    "call owner does not contain the reverse reference"
                )
        elif source.kind == "evidence":
            owner_attempts: set[int] = set()
            for owner in selected["owners"]:
                owner_record = _require_ref(
                    index,
                    source,
                    owner,
                    frozenset({"candidate", "validation", "deferred"}),
                )
                if record_id not in owner_record.selected["evidence"]:
                    raise ReplayArtifactError(
                        "evidence owner does not contain the reverse reference"
                    )
                owner_attempts.add(owner_record.attempt)
                if (
                    selected["report_id"] != owner_record.selected["report_id"]
                    or (
                        selected["entry_id"] is not None
                        and selected["entry_id"]
                        != owner_record.selected["entry_id"]
                    )
                ):
                    raise ReplayArtifactError(
                        "evidence identity does not match its owner"
                    )
            if owner_attempts != set(selected["attempts"]):
                raise ReplayArtifactError(
                    "evidence observed attempts do not match its owners"
                )
            if selected["tool"] is not None:
                tool = _require_ref(index, source, selected["tool"], "tool_call")
                if selected["tool_external_id"] != tool.selected["external_id"]:
                    raise ReplayArtifactError(
                        "evidence tool_call_id does not match its tool record"
                    )
            elif selected["tool_external_id"] is not None:
                raise ReplayArtifactError(
                    "evidence has an external tool ID without a tool record"
                )
        elif source.kind == "candidate":
            evidence = [
                _require_ref(index, source, item, "evidence")
                for item in selected["evidence"]
            ]
            tools = [
                _require_ref(index, source, item, "tool_call")
                for item in selected["tools"]
            ]
            models = [
                _require_ref(index, source, item, "model_call")
                for item in selected["models"]
            ]
            if any(item.selected["owner"] != record_id for item in tools + models):
                raise ReplayArtifactError("candidate call reference is not reciprocal")
            if any(record_id not in item.selected["owners"] for item in evidence):
                raise ReplayArtifactError(
                    "candidate evidence reference is not reciprocal"
                )
            parent = selected["parent"]
            repair = selected["repair"]
            if source.attempt == 0:
                if (
                    parent is not None
                    or repair is not None
                    or selected["mode"] not in {"generated", "provided"}
                    or selected["disposition"] != "accepted"
                ):
                    raise ReplayArtifactError("initial candidate cannot have lineage")
            else:
                parent_record = _require_ref(index, source, parent, "candidate")
                repair_record = _require_ref(index, source, repair, "repair_plan")
                if (
                    parent_record.attempt != source.attempt - 1
                    or repair_record.attempt != source.attempt
                    or selected["mode"] != "repair"
                ):
                    raise ReplayArtifactError("candidate repair lineage is invalid")
            projection = canonical_sha256(
                {
                    "candidate_sha256": selected["candidate_sha256"],
                    "evidence_payload_sha256": [item.payload_sha256 for item in evidence],
                    "tool_call_payload_sha256": [item.payload_sha256 for item in tools],
                    "model_call_payload_sha256": [item.payload_sha256 for item in models],
                }
            )
            if projection != selected["projection_sha256"]:
                raise ReplayArtifactError("candidate projection digest mismatch")
        elif source.kind == "validation":
            candidate = _require_ref(
                index, source, selected["candidate"], "candidate"
            )
            evidence = [
                _require_ref(index, source, item, "evidence")
                for item in selected["evidence"]
            ]
            if (
                selected["report_id"] != candidate.selected["report_id"]
                or selected["entry_id"] != candidate.selected["entry_id"]
                or source.attempt != candidate.attempt
                or any(record_id not in item.selected["owners"] for item in evidence)
                or selected["report_evidence_ids"]
                != {item.selected["evidence_id"] for item in evidence}
            ):
                raise ReplayArtifactError(
                    "validation identity or reverse evidence linkage is invalid"
                )
            projection = canonical_sha256(
                {
                    "report_sha256": selected["report_sha256"],
                    "evidence_payload_sha256": [item.payload_sha256 for item in evidence],
                }
            )
            if projection != selected["projection_sha256"]:
                raise ReplayArtifactError("validation projection digest mismatch")
        elif source.kind == "repair_plan":
            parent_candidate = _require_ref(
                index, source, selected["parent_candidate"], "candidate"
            )
            parent_validation = _require_ref(
                index, source, selected["parent_validation"], "validation"
            )
            if (
                source.attempt < 1
                or selected["repair_iteration"] != source.attempt
                or selected["task_id"] != source.task_id
                or parent_candidate.attempt != source.attempt - 1
                or parent_validation.attempt != source.attempt - 1
                or selected["previous_candidate_sha256"]
                != parent_candidate.selected["candidate_sha256"]
                or selected["validation_sha256"]
                != parent_validation.selected["report_sha256"]
                or selected["report_id"] != parent_candidate.selected["report_id"]
                or selected["entry_id"] != parent_candidate.selected["entry_id"]
                or parent_validation.selected["candidate"]
                != selected["parent_candidate"]
            ):
                raise ReplayArtifactError("repair parent lineage is invalid")
            if selected["child_candidate"] is not None:
                child = _require_ref(
                    index, source, selected["child_candidate"], "candidate"
                )
                if child.attempt != source.attempt:
                    raise ReplayArtifactError("repair candidate child attempt is invalid")
                if (
                    child.selected["parent"] != selected["parent_candidate"]
                    or child.selected["repair"] != record_id
                ):
                    raise ReplayArtifactError(
                        "repair candidate child linkage is not reciprocal"
                    )
            if selected["deferred"] is not None:
                child = _require_ref(index, source, selected["deferred"], "deferred")
                if child.attempt != source.attempt:
                    raise ReplayArtifactError("repair deferred child attempt is invalid")
                if (
                    child.selected["parent"] != selected["parent_candidate"]
                    or child.selected["repair"] != record_id
                ):
                    raise ReplayArtifactError(
                        "repair deferred child linkage is not reciprocal"
                    )
        elif source.kind == "deferred":
            evidence = [
                _require_ref(index, source, item, "evidence")
                for item in selected["evidence"]
            ]
            tools = [
                _require_ref(index, source, item, "tool_call")
                for item in selected["tools"]
            ]
            models = [
                _require_ref(index, source, item, "model_call")
                for item in selected["models"]
            ]
            if any(item.selected["owner"] != record_id for item in tools + models):
                raise ReplayArtifactError("deferred call reference is not reciprocal")
            if any(record_id not in item.selected["owners"] for item in evidence):
                raise ReplayArtifactError(
                    "deferred evidence reference is not reciprocal"
                )
            if source.attempt == 0:
                if (
                    selected["parent"] is not None
                    or selected["repair"] is not None
                    or selected["mode"] != "generate"
                    or selected["parent_candidate_sha256"] is not None
                    or selected["repair_plan_sha256"] is not None
                ):
                    raise ReplayArtifactError("initial deferral cannot have lineage")
            else:
                parent = _require_ref(index, source, selected["parent"], "candidate")
                repair = _require_ref(index, source, selected["repair"], "repair_plan")
                if (
                    parent.attempt != source.attempt - 1
                    or repair.attempt != source.attempt
                    or selected["mode"] != "repair"
                    or selected["parent_candidate_sha256"]
                    != parent.selected["candidate_sha256"]
                    or selected["repair_plan_sha256"]
                    != repair.selected["plan_sha256"]
                ):
                    raise ReplayArtifactError("deferred repair lineage is invalid")
            projection = canonical_sha256(
                {
                    "deferred_core_sha256": selected["core_sha256"],
                    "evidence_payload_sha256": [item.payload_sha256 for item in evidence],
                    "tool_call_payload_sha256": [item.payload_sha256 for item in tools],
                    "model_call_payload_sha256": [item.payload_sha256 for item in models],
                }
            )
            if projection != selected["projection_sha256"]:
                raise ReplayArtifactError("deferred projection digest mismatch")

    for source in index.values():
        if source.kind != "state":
            continue
        selected = source.selected
        candidates = [
            _require_ref(index, source, item, "candidate")
            for item in selected["candidates"]
        ]
        validations = [
            _require_ref(index, source, item, "validation")
            for item in selected["validations"]
        ]
        repairs = [
            _require_ref(index, source, item, "repair_plan")
            for item in selected["repairs"]
        ]
        deferred = (
            None
            if selected["deferred"] is None
            else _require_ref(index, source, selected["deferred"], "deferred")
        )
        actual = by_correlation[source.correlation_id]
        if set(selected["candidates"]) != actual.get("candidate", set()):
            raise ReplayArtifactError("state candidate references are not closed")
        if set(selected["validations"]) != actual.get("validation", set()):
            raise ReplayArtifactError("state validation references are not closed")
        if set(selected["repairs"]) != actual.get("repair_plan", set()):
            raise ReplayArtifactError("state repair references are not closed")
        deferred_ids = actual.get("deferred", set())
        if ({selected["deferred"]} if selected["deferred"] else set()) != deferred_ids:
            raise ReplayArtifactError("state deferred references are not closed")
        state = selected["state"]
        if state.get("status") not in {"finalized", "manual_review", "failed"}:
            raise ReplayArtifactError("replayed state is not terminal")
        if state.get("repair_iteration") != source.attempt:
            raise ReplayArtifactError("state attempt does not match repair_iteration")
        attempts = state.get("production_attempts")
        validations_summary = state.get("validation_history")
        repairs_state = state.get("active_repair_plan")
        if not isinstance(attempts, list) or len(attempts) != len(candidates):
            raise ReplayArtifactError("state production attempts do not close")
        for summary, candidate in zip(attempts, candidates):
            parent = (
                None
                if candidate.selected["parent"] is None
                else index[candidate.selected["parent"]]
            )
            repair = (
                None
                if candidate.selected["repair"] is None
                else index[candidate.selected["repair"]]
            )
            if (
                not isinstance(summary, Mapping)
                or summary.get("candidate_sha256")
                != candidate.selected["candidate_sha256"]
                or summary.get("outcome_sha256") != candidate.selected["source_sha256"]
                or summary.get("attempt") != candidate.attempt
                or summary.get("mode") != candidate.selected["mode"]
                or summary.get("disposition") != candidate.selected["disposition"]
                or summary.get("parent_candidate_sha256")
                != (
                    None if parent is None else parent.selected["candidate_sha256"]
                )
                or summary.get("repair_plan_sha256")
                != (None if repair is None else repair.selected["plan_sha256"])
            ):
                raise ReplayArtifactError("state production summary mismatch")
        if not isinstance(validations_summary, list) or len(validations_summary) != len(
            validations
        ):
            raise ReplayArtifactError("state validation summaries do not close")
        for summary, validation in zip(validations_summary, validations):
            if (
                not isinstance(summary, Mapping)
                or summary.get("validation_sha256")
                != validation.selected["report_sha256"]
                or summary.get("evidence_sha256")
                != validation.selected["source_evidence_sha256"]
                or summary.get("attempt") != validation.attempt
                or summary.get("candidate_sha256")
                != index[validation.selected["candidate"]].selected[
                    "candidate_sha256"
                ]
            ):
                raise ReplayArtifactError("state validation summary mismatch")
        production_history = state.get("production_history")
        accepted_candidates = [
            item for item in candidates if item.selected["disposition"] == "accepted"
        ]
        if not isinstance(production_history, list) or len(
            production_history
        ) != len(accepted_candidates):
            raise ReplayArtifactError("state accepted production history is not closed")
        for summary, candidate in zip(production_history, accepted_candidates):
            parent = (
                None
                if candidate.selected["parent"] is None
                else index[candidate.selected["parent"]]
            )
            repair = (
                None
                if candidate.selected["repair"] is None
                else index[candidate.selected["repair"]]
            )
            if (
                not isinstance(summary, Mapping)
                or summary.get("attempt") != candidate.attempt
                or summary.get("mode") != candidate.selected["mode"]
                or summary.get("candidate_sha256")
                != candidate.selected["candidate_sha256"]
                or summary.get("parent_candidate_sha256")
                != (
                    None if parent is None else parent.selected["candidate_sha256"]
                )
                or summary.get("repair_plan_sha256")
                != (None if repair is None else repair.selected["plan_sha256"])
            ):
                raise ReplayArtifactError("state accepted production summary mismatch")
        task_binding = selected["task"]
        for candidate in candidates:
            if (
                task_binding["report_id"] is not None
                and candidate.selected["report_id"] != task_binding["report_id"]
            ) or (
                task_binding["entry_id"] is not None
                and candidate.selected["entry_id"] != task_binding["entry_id"]
            ):
                raise ReplayArtifactError("candidate identity does not match task")
        if deferred is not None and (
            deferred.selected["report_id"] != task_binding["report_id"]
            or deferred.selected["entry_id"] != task_binding["entry_id"]
            or deferred.selected["inputs_sha256"] != task_binding["inputs_sha256"]
        ):
            raise ReplayArtifactError("deferred identity does not match task")
        if repairs:
            if not isinstance(repairs_state, Mapping) or canonical_sha256(
                repairs_state
            ) != repairs[-1].selected["plan_sha256"]:
                raise ReplayArtifactError("state active repair plan mismatch")
        elif repairs_state is not None:
            raise ReplayArtifactError("state has an unrecorded repair plan")
        if deferred is not None and state.get("deferred_sha256") != deferred.selected[
            "source_sha256"
        ]:
            raise ReplayArtifactError("state deferred digest mismatch")
        state_candidate = state.get("candidate")
        state_candidate_sha256 = (
            None if state_candidate is None else canonical_sha256(state_candidate)
        )
        if (
            state_candidate_sha256 != state.get("candidate_sha256")
            or state_candidate_sha256 != selected["entry_sha256"]
        ):
            raise ReplayArtifactError("state final candidate digest mismatch")
        if state_candidate is not None:
            history = production_history
            if not history:
                raise ReplayArtifactError("state candidate has no accepted history")
            accepted_attempt = history[-1].get("attempt")
            matching = [item for item in candidates if item.attempt == accepted_attempt]
            if (
                len(matching) != 1
                or matching[0].selected["candidate_sha256"] != state_candidate_sha256
            ):
                raise ReplayArtifactError("state candidate is not the accepted lineage tip")
        state_report = state.get("last_validation")
        state_report_sha256 = (
            None if state_report is None else canonical_sha256(state_report)
        )
        if state_report_sha256 != selected["report_sha256"]:
            raise ReplayArtifactError("state final validation digest mismatch")
        if validations and state_report_sha256 != validations[-1].selected[
            "report_sha256"
        ]:
            raise ReplayArtifactError("state report is not the validation lineage tip")
        if not validations and state_report is not None:
            raise ReplayArtifactError("state has an unrecorded validation report")
        termination = state.get("termination")
        if not isinstance(termination, Mapping) or termination.get(
            "error_sha256"
        ) != selected["error_sha256"]:
            raise ReplayArtifactError("state termination error digest mismatch")
        if state.get("status") == "finalized" and (
            not validations or validations[-1].selected["verdict"] != "correct"
        ):
            raise ReplayArtifactError("finalized state lacks a correct validation")

        budget = state.get("budget")
        events = None if not isinstance(budget, Mapping) else budget.get("events")
        if not isinstance(events, list):
            raise ReplayArtifactError("state budget events are invalid")
        budget_by_sequence = {
            event.get("sequence"): event
            for event in events
            if isinstance(event, Mapping)
        }
        call_records = [
            item
            for item in index.values()
            if item.correlation_id == source.correlation_id
            and item.kind in {"tool_call", "model_call"}
        ]
        if len(budget_by_sequence) != len(events):
            raise ReplayArtifactError("state budget event sequences are not unique")
        for call in call_records:
            event = budget_by_sequence.get(call.selected["sequence"])
            if (
                event is None
                or event.get("resource") != call.selected["resource"]
                or event.get("operation") != call.selected["operation"]
            ):
                raise ReplayArtifactError("call does not match its budget event")
        call_sequences = [item.selected["sequence"] for item in call_records]
        if len(call_sequences) != len(set(call_sequences)):
            raise ReplayArtifactError("call records reuse a budget event")
        charged_call_sequences = {
            event.get("sequence")
            for event in events
            if isinstance(event, Mapping)
            and event.get("resource") in {"tool_calls", "llm_calls"}
        }
        incomplete_transcript_reasons = {
            "producer_error",
            "unaccounted_tool_call",
            "unaccounted_model_call",
            "budget_exhausted",
            "sidecar_conflict",
        }
        if (
            state.get("stop_reason") not in incomplete_transcript_reasons
            and set(call_sequences) != charged_call_sequences
        ):
            raise ReplayArtifactError("budget call events are not closed")
        task = selected["task"]
        expected_correlation = _binding_correlation(
            input_line=source.input_line,
            task_id=task["task_id"],
            report_id=task["report_id"],
            entry_id=task["entry_id"],
            inputs_sha256=task["inputs_sha256"],
        )
        if (
            source.task_id != task["task_id"]
            or source.correlation_id != expected_correlation
        ):
            raise ReplayArtifactError("state correlation binding mismatch")
        projection = canonical_sha256(
            {
                "status": state["status"],
                "state_sha256": selected["state_sha256"],
                "entry_sha256": selected["entry_sha256"],
                "report_sha256": selected["report_sha256"],
                "production_projection_sha256": [
                    item.selected["projection_sha256"] for item in candidates
                ],
                "deferred_projection_sha256": (
                    None if deferred is None else deferred.selected["projection_sha256"]
                ),
                "validation_projection_sha256": [
                    item.selected["projection_sha256"] for item in validations
                ],
                "repair_plan_sha256": [
                    item.selected["plan_sha256"] for item in repairs
                ],
                "error_sha256": selected["error_sha256"],
                "changed_fields": list(selected["changed_fields"]),
            }
        )
        if projection != selected["projection_sha256"]:
            raise ReplayArtifactError("outcome projection digest mismatch")


def read_closed_loop_artifacts(
    directory: str | os.PathLike[str],
    *,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
    limits: ReplayLimits | None = None,
) -> ReplayBundle:
    """Read and verify a replay directory without executing T1, T2, Git, or a model."""

    active_limits = limits or ReplayLimits()
    requested_root = Path(directory).expanduser().absolute()
    root_identity = _safe_directory_identity(requested_root)
    try:
        root = requested_root.resolve(strict=True)
    except OSError as error:
        raise ReplayArtifactError("replay directory is unavailable") from error
    if _safe_directory_identity(root) != root_identity:
        raise ReplayArtifactError("replay directory identity changed")
    actual_names = {item.name for item in root.iterdir()}
    if actual_names != set(REPLAY_FILES):
        raise ReplayArtifactError("replay directory has missing or extra files")
    protected = _protected_tokens(protected_paths)
    index: dict[str, _IndexedRecord] = {}
    counts: dict[str, int] = {}
    total_bytes = 0
    last_order: dict[str, tuple[int, int]] = {}
    file_summaries: dict[str, dict[str, Any]] = {}

    entry_sha256s: list[str] = []
    formal_entries_by_sha256: dict[str, Mapping[str, Any]] = {}
    published_entry_ids: set[str] = set()
    entry_summary: dict[str, Any] = {}
    for entry, _ in _iter_canonical_lines(
        root / _ENTRY_FILE,
        active_limits,
        root=root,
        root_identity=root_identity,
        summary=entry_summary,
    ):
        try:
            formal = ProductionOutcome(candidate=entry)
        except (TypeError, ValueError) as error:
            raise ReplayArtifactError(
                "entries.jsonl contains a non-formal Entry"
            ) from error
        _ensure_replay_safe(entry, protected)
        entry_id = formal.candidate["entry_id"]
        if entry_id in published_entry_ids:
            raise ReplayArtifactError(
                "entries.jsonl contains a duplicate entry_id"
            )
        published_entry_ids.add(entry_id)
        if formal.candidate_sha256 in formal_entries_by_sha256:
            raise ReplayArtifactError(
                "entries.jsonl contains a duplicate Entry digest"
            )
        formal_entries_by_sha256[formal.candidate_sha256] = formal.candidate
        entry_sha256s.append(formal.candidate_sha256)
    total_bytes += entry_summary["byte_count"]
    file_summaries[_ENTRY_FILE] = entry_summary
    counts[_ENTRY_FILE] = entry_summary["line_count"]

    formal_validations: list[dict[str, Any]] = []
    formal_validation_summary: dict[str, Any] = {}
    for report_value, _ in _iter_canonical_lines(
        root / _FORMAL_VALIDATION_FILE,
        active_limits,
        root=root,
        root_identity=root_identity,
        summary=formal_validation_summary,
    ):
        report = _validation_report_from_dict(report_value)
        _ensure_replay_safe(report_value, protected)
        formal_validations.append(
            {
                "input_line": report.input_line,
                "report_id": report.report_id,
                "entry_id": report.entry_id,
                "report_sha256": canonical_sha256(report),
            }
        )
    total_bytes += formal_validation_summary["byte_count"]
    file_summaries[_FORMAL_VALIDATION_FILE] = formal_validation_summary
    counts[_FORMAL_VALIDATION_FILE] = formal_validation_summary["line_count"]

    for filename in _ENVELOPE_DATA_FILES:
        file_path = root / filename
        summary: dict[str, Any] = {}
        kind = _FILE_KIND[filename]
        for envelope, _ in _iter_canonical_lines(
            file_path,
            active_limits,
            root=root,
            root_identity=root_identity,
            summary=summary,
        ):
            _validate_envelope(envelope, allowed_kind=kind, protected=protected)
            order = (envelope["input_line"], envelope["attempt"])
            if order < last_order.get(filename, (0, 0)):
                raise ReplayArtifactError(f"{filename} records are out of order")
            last_order[filename] = order
            record_id = envelope["record_id"]
            if record_id in index:
                raise ReplayArtifactError("record_id must be globally unique")
            selected = _selected_payload(kind, envelope["payload"])
            if kind in {"tool_call", "model_call"} and (
                selected["task_id"] != envelope["task_id"]
                or selected["attempt"] != envelope["attempt"]
            ):
                raise ReplayArtifactError(
                    "call payload does not match envelope task/attempt"
                )
            if kind == "evidence" and (
                envelope["attempt"] not in selected["attempts"]
                or envelope["attempt"] != min(selected["attempts"])
            ):
                raise ReplayArtifactError(
                    "evidence envelope attempt does not match observations"
                )
            if kind == "validation" and selected["input_line"] != envelope[
                "input_line"
            ]:
                raise ReplayArtifactError(
                    "validation report input_line does not match envelope"
                )
            if kind == "deferred" and (
                selected["task_id"] != envelope["task_id"]
                or selected["attempt"] != envelope["attempt"]
            ):
                raise ReplayArtifactError(
                    "deferred core does not match envelope task/attempt"
                )
            index[record_id] = _IndexedRecord(
                kind=kind,
                task_id=envelope["task_id"],
                input_line=envelope["input_line"],
                correlation_id=envelope["correlation_id"],
                attempt=envelope["attempt"],
                payload_sha256=envelope["payload_sha256"],
                selected=selected,
            )
        total_bytes += summary["byte_count"]
        file_summaries[filename] = summary
        counts[filename] = summary["line_count"]

    manifest_path = root / _MANIFEST_FILE
    manifest_summary: dict[str, Any] = {}
    manifest_iterator = _iter_canonical_lines(
        manifest_path,
        active_limits,
        root=root,
        root_identity=root_identity,
        summary=manifest_summary,
    )
    pending = next(manifest_iterator, None)
    if pending is None:
        raise ReplayArtifactError("run_manifest.jsonl must contain a dataset footer")
    roots_digest = hashlib.sha256()
    roots_bytes = 0
    previous_line = 0
    seen_task_ids: set[str] = set()
    seen_entry_ids: set[str] = set()
    seen_correlations: set[str] = set()
    root_records: list[Mapping[str, Any]] = []
    rooted_ids: set[str] = set()
    outcome_records = 0
    failure_records = 0
    finalized_entry_sha256s: list[str] = []
    state_entry_bindings: list[tuple[str, str, str | None]] = []
    expected_formal_validations: list[dict[str, Any]] = []
    for next_line in manifest_iterator:
        envelope, raw = pending
        if len(root_records) >= active_limits.max_input_records:
            raise ReplayArtifactError("manifest exceeds max_input_records")
        _validate_envelope(
            envelope, allowed_kind="run_manifest", protected=protected
        )
        if envelope["input_line"] <= previous_line:
            raise ReplayArtifactError("manifest roots are not strictly input ordered")
        previous_line = envelope["input_line"]
        task_id = envelope["task_id"]
        if task_id is not None:
            if task_id in seen_task_ids:
                raise ReplayArtifactError("task_id must be globally unique")
            seen_task_ids.add(task_id)
        correlation = envelope["correlation_id"]
        if correlation in seen_correlations:
            raise ReplayArtifactError("correlation_id must be globally unique")
        seen_correlations.add(correlation)
        payload = envelope["payload"]
        root_kind = payload.get("root_kind")
        expected_keys = (
            {
                "record_key",
                "root_record_id",
                "root_kind",
                "status",
                "state_sha256",
                "source_outcome_sha256",
                "outcome_projection_sha256",
                "entry_sha256",
                "formal_validation_sha256",
            }
            if root_kind == "state"
            else {
                "record_key",
                "root_record_id",
                "root_kind",
                "status",
                "raw_sha256",
                "error_code",
            }
        )
        if set(payload) != expected_keys:
            raise ReplayArtifactError("manifest root payload is invalid")
        root_id = payload["root_record_id"]
        if root_id in rooted_ids or root_id not in index:
            raise ReplayArtifactError("manifest root is duplicate or unresolved")
        target = index[root_id]
        if (
            target.kind != root_kind
            or target.task_id != task_id
            or target.input_line != envelope["input_line"]
            or target.correlation_id != correlation
            or target.attempt != envelope["attempt"]
        ):
            raise ReplayArtifactError("manifest root does not bind its target")
        if root_kind == "state":
            outcome_records += 1
            if (
                payload["state_sha256"] != target.selected["state_sha256"]
                or payload["source_outcome_sha256"]
                != target.selected["source_sha256"]
                or payload["outcome_projection_sha256"]
                != target.selected["projection_sha256"]
                or payload["status"] != target.selected["state"].get("status")
            ):
                raise ReplayArtifactError("manifest state root digest mismatch")
            state_entry_id = target.selected["task"]["entry_id"]
            if state_entry_id is None and target.selected["state"].get("candidate"):
                state_entry_id = target.selected["state"]["candidate"].get("entry_id")
            if state_entry_id is not None:
                if state_entry_id in seen_entry_ids:
                    raise ReplayArtifactError("entry_id must be globally unique")
                seen_entry_ids.add(state_entry_id)
            if payload["status"] == "finalized":
                if payload["entry_sha256"] != target.selected["entry_sha256"]:
                    raise ReplayArtifactError(
                        "manifest finalized entry digest mismatch"
                    )
                finalized_entry_sha256s.append(payload["entry_sha256"])
            elif payload["entry_sha256"] is not None:
                raise ReplayArtifactError(
                    "non-finalized root cannot publish an entry"
                )
            if not isinstance(task_id, str):
                raise ReplayArtifactError("state root must have a task_id")
            state_entry_bindings.append(
                (task_id, payload["status"], payload["entry_sha256"])
            )
            if payload["formal_validation_sha256"] != target.selected[
                "report_sha256"
            ]:
                raise ReplayArtifactError(
                    "manifest formal validation digest mismatch"
                )
            if payload["formal_validation_sha256"] is not None:
                last_report = target.selected["state"].get("last_validation")
                if not isinstance(last_report, Mapping):
                    raise ReplayArtifactError(
                        "formal validation has no state report"
                    )
                expected_formal_validations.append(
                    {
                        "input_line": last_report.get("input_line"),
                        "report_id": last_report.get("report_id"),
                        "entry_id": last_report.get("entry_id"),
                        "report_sha256": payload["formal_validation_sha256"],
                    }
                )
        elif root_kind == "input_failure":
            failure_records += 1
            if (
                payload["status"] != "input_failure"
                or payload["raw_sha256"] != target.selected["raw_sha256"]
                or payload["error_code"] != target.selected["error_code"]
            ):
                raise ReplayArtifactError("manifest input failure root mismatch")
            expected_correlation = "INPUT-" + canonical_sha256(
                {
                    "input_line": envelope["input_line"],
                    "task_id": task_id,
                    "raw_sha256": payload["raw_sha256"],
                }
            )
            if correlation != expected_correlation:
                raise ReplayArtifactError("input failure correlation mismatch")
        else:
            raise ReplayArtifactError("manifest root_kind is invalid")
        rooted_ids.add(root_id)
        roots_digest.update(raw)
        roots_bytes += len(raw)
        root_records.append(
            {
                "task_id": task_id,
                "input_line": envelope["input_line"],
                "correlation_id": correlation,
                "root_record_id": root_id,
                "root_kind": root_kind,
                "status": payload["status"],
            }
        )
        pending = next_line

    footer, _ = pending
    total_bytes += manifest_summary["byte_count"]
    if total_bytes > active_limits.max_total_bytes:
        raise ReplayArtifactError("replay artifacts exceed the total byte limit")

    _validate_envelope(
        footer, allowed_kind="dataset_manifest", protected=protected
    )
    if (
        footer["task_id"] != "_manifest"
        or footer["input_line"] != 0
        or footer["attempt"] != 0
        or footer["payload"].get("record_key") != "manifest:dataset"
    ):
        raise ReplayArtifactError("dataset footer identity is invalid")
    payload = footer["payload"]
    _expect_keys(
        payload,
        {
            "schema_version",
            "files",
            "manifest_roots",
            "input_records",
            "outcome_records",
            "input_failures",
            "entry_count",
            "formal_validation_count",
            "validation_attempt_count",
            "dataset_sha256",
        },
        "dataset manifest",
    )
    if payload["schema_version"] != REPLAY_SCHEMA_VERSION:
        raise ReplayArtifactError("dataset schema version mismatch")
    if payload["files"] != file_summaries:
        raise ReplayArtifactError("dataset file summaries do not match contents")
    expected_roots = {
        "content_sha256": roots_digest.hexdigest(),
        "byte_count": roots_bytes,
        "line_count": len(root_records),
    }
    if payload["manifest_roots"] != expected_roots:
        raise ReplayArtifactError("manifest root summary does not match contents")
    if (
        payload["input_records"] != len(root_records)
        or payload["outcome_records"] != outcome_records
        or payload["input_failures"] != failure_records
        or payload["entry_count"] != len(entry_sha256s)
        or payload["formal_validation_count"] != len(formal_validations)
        or payload["validation_attempt_count"]
        != file_summaries["validations.jsonl"]["line_count"]
        or outcome_records + failure_records != len(root_records)
    ):
        raise ReplayArtifactError("dataset record counts do not match contents")
    dataset_core = {
        key: payload[key]
        for key in (
            "schema_version",
            "files",
            "manifest_roots",
            "input_records",
            "outcome_records",
            "input_failures",
            "entry_count",
            "formal_validation_count",
            "validation_attempt_count",
        )
    }
    dataset_sha256 = canonical_sha256(dataset_core)
    if (
        payload["dataset_sha256"] != dataset_sha256
        or footer["correlation_id"] != f"DATASET-{dataset_sha256}"
    ):
        raise ReplayArtifactError("dataset digest mismatch")
    if entry_sha256s != finalized_entry_sha256s:
        raise ReplayArtifactError(
            "entries.jsonl does not match finalized correct outcomes"
        )
    if formal_validations != expected_formal_validations:
        raise ReplayArtifactError(
            "validation.jsonl does not match terminal outcome reports"
        )
    terminal_ids = {
        record_id
        for record_id, item in index.items()
        if item.kind in {"state", "input_failure"}
    }
    if terminal_ids != rooted_ids:
        raise ReplayArtifactError("state/input-failure roots are not closed")
    state_correlations = {
        item.correlation_id for item in index.values() if item.kind == "state"
    }
    for item in index.values():
        if item.kind not in {"state", "input_failure"} and (
            item.correlation_id not in state_correlations
        ):
            raise ReplayArtifactError("artifact record has no state root")
    _verify_index(index)
    if (
        _safe_directory_identity(root) != root_identity
        or {item.name for item in root.iterdir()} != set(REPLAY_FILES)
    ):
        raise ReplayArtifactError("replay directory changed while being read")
    verified_tasks: list[VerifiedTaskEntries] = []
    bound_entry_sha256s: set[str] = set()
    for task_id, status, entry_sha256 in state_entry_bindings:
        entries: tuple[Mapping[str, Any], ...]
        if entry_sha256 is None:
            entries = ()
        else:
            if entry_sha256 in bound_entry_sha256s:
                raise ReplayArtifactError(
                    "one formal Entry digest is bound to multiple task roots"
                )
            entry = formal_entries_by_sha256.get(entry_sha256)
            if entry is None:
                raise ReplayArtifactError(
                    "state root Entry digest has no published formal Entry"
                )
            bound_entry_sha256s.add(entry_sha256)
            entries = (entry,)
        try:
            verified_tasks.append(
                VerifiedTaskEntries(
                    task_id=task_id,
                    status=status,
                    entries=entries,
                )
            )
        except ValueError as error:
            raise ReplayArtifactError(
                "state root has an invalid formal Entry binding"
            ) from error
    if bound_entry_sha256s != set(formal_entries_by_sha256):
        raise ReplayArtifactError(
            "published formal Entry has no verified state root"
        )
    verified_predictions: list[VerifiedTaskPrediction] = []
    for root_record in root_records:
        if root_record["root_kind"] != "state":
            continue
        state_record = index[root_record["root_record_id"]]
        state = state_record.selected["state"]
        status = state["status"]
        candidate_value = state.get("candidate")
        report_value = state.get("last_validation")
        validation_history = state.get("validation_history")
        candidate_sha256 = state.get("candidate_sha256")
        validation_candidate_sha256 = (
            validation_history[-1].get("candidate_sha256")
            if isinstance(validation_history, list) and validation_history
            and isinstance(validation_history[-1], Mapping)
            else None
        )
        # A failed run can retain an accepted repair candidate alongside the
        # previous round's last_validation when construction of the next T1
        # validator fails.  Never project that stale pair as one prediction.
        # Only successful terminal validation states are submission-eligible.
        pair_is_current = (
            status in {"finalized", "manual_review"}
            and candidate_value is not None
            and report_value is not None
            and isinstance(candidate_sha256, str)
            and candidate_sha256 == validation_candidate_sha256
        )
        try:
            report = (
                None
                if not pair_is_current
                else _validation_report_from_dict(report_value)
            )
            verified_predictions.append(
                VerifiedTaskPrediction(
                    task_id=state_record.task_id,
                    input_line=state_record.input_line,
                    status=status,
                    entry=candidate_value if pair_is_current else None,
                    validation=report,
                )
            )
        except (TypeError, ValueError) as error:
            raise ReplayArtifactError(
                "terminal state has an invalid submission prediction"
            ) from error
    counts[_MANIFEST_FILE] = manifest_summary["line_count"]
    manifest = ReplayManifest(
        dataset_sha256=dataset_sha256,
        input_records=payload["input_records"],
        outcome_records=outcome_records,
        input_failures=failure_records,
        entry_count=len(entry_sha256s),
        formal_validation_count=len(formal_validations),
        validation_attempt_count=file_summaries["validations.jsonl"]["line_count"],
        files=file_summaries,
        payload_sha256=footer["payload_sha256"],
    )
    return ReplayBundle(
        manifest=manifest,
        root_records=tuple(root_records),
        record_counts=counts,
        verified_tasks=tuple(verified_tasks),
        verified_predictions=tuple(verified_predictions),
    )


def read_verified_formal_entries(
    bundle_dir: str | os.PathLike[str],
    *,
    expected_dataset_sha256: str | None = None,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
    limits: ReplayLimits | None = None,
) -> VerifiedFormalEntries:
    """Return trusted formal Entries retained by one complete replay read.

    All replay files, digests, references, terminal validation lineage, and
    dataset counts are verified by :func:`read_closed_loop_artifacts`.  The
    already parsed ``entries.jsonl`` values from that same safe read are then
    narrowed to this immutable result; the file is never reopened by path.
    Callers that need authenticity, rather than internal integrity alone, must
    pin ``expected_dataset_sha256`` to a digest obtained through a trusted
    channel.
    """

    if expected_dataset_sha256 is not None:
        try:
            _require_sha256(expected_dataset_sha256, "expected_dataset_sha256")
        except ValueError as error:
            raise ReplayArtifactError(
                "expected_dataset_sha256 must be a lower-case SHA-256 digest"
            ) from error
    bundle = read_closed_loop_artifacts(
        bundle_dir,
        protected_paths=protected_paths,
        limits=limits,
    )
    if (
        expected_dataset_sha256 is not None
        and bundle.manifest.dataset_sha256 != expected_dataset_sha256
    ):
        raise ReplayArtifactError(
            "replay dataset SHA-256 does not match expected digest"
        )
    return VerifiedFormalEntries(
        dataset_sha256=bundle.manifest.dataset_sha256,
        tasks=bundle.verified_tasks,
        input_failure_count=bundle.manifest.input_failures,
    )


def read_verified_submission_predictions(
    bundle_dir: str | os.PathLike[str],
    *,
    expected_dataset_sha256: str,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
    limits: ReplayLimits | None = None,
) -> VerifiedSubmissionPredictions:
    """Return terminal candidates and T1 reports from one pinned replay bundle.

    A trusted dataset digest is mandatory because local replay integrity alone
    does not authenticate who produced the run.  No task inputs, prompts, model
    responses, repository paths, or evidence-package contents cross this
    projection boundary.
    """

    try:
        _require_sha256(expected_dataset_sha256, "expected_dataset_sha256")
    except ValueError as error:
        raise ReplayArtifactError(
            "expected_dataset_sha256 must be a lower-case SHA-256 digest"
        ) from error
    bundle = read_closed_loop_artifacts(
        bundle_dir,
        protected_paths=protected_paths,
        limits=limits,
    )
    if bundle.manifest.dataset_sha256 != expected_dataset_sha256:
        raise ReplayArtifactError(
            "replay dataset SHA-256 does not match expected digest"
        )
    return VerifiedSubmissionPredictions(
        dataset_sha256=bundle.manifest.dataset_sha256,
        tasks=bundle.verified_predictions,
        input_failure_count=bundle.manifest.input_failures,
    )


def verify_closed_loop_artifacts(
    directory: str | os.PathLike[str],
    *,
    expected_events: Iterable[ReplayEvent] | None = None,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
    limits: ReplayLimits | None = None,
) -> ReplayManifest:
    """Verify artifacts and optionally compare them to expected outcomes.

    Expected events are consumed exactly once and rendered into a temporary
    replay directory.  Byte-for-byte file digests are then compared; no model,
    Git repository, producer, or validator is invoked.
    """

    active_limits = limits or ReplayLimits()
    bundle = read_closed_loop_artifacts(
        directory, protected_paths=protected_paths, limits=active_limits
    )
    if expected_events is None:
        return bundle.manifest
    with tempfile.TemporaryDirectory(prefix="vulngym-replay-verify-") as temporary:
        expected_dir = Path(temporary) / "expected"
        write_closed_loop_artifacts(
            expected_dir,
            expected_events,
            protected_paths=protected_paths,
            limits=active_limits,
        )
        actual_root = Path(directory).expanduser().resolve(strict=True)
        for filename in REPLAY_FILES:
            actual = _rehash(actual_root / filename, active_limits)
            expected = _rehash(expected_dir / filename, active_limits)
            if actual != expected:
                raise ReplayArtifactError(
                    f"{filename} does not match the expected event stream"
                )
    return bundle.manifest


__all__ = [
    "InputFailureRecord",
    "REPLAY_FILES",
    "REPLAY_SCHEMA_VERSION",
    "ReplayArtifactError",
    "ReplayBundle",
    "ReplayEvent",
    "ReplayLimits",
    "ReplayManifest",
    "ReplayRecord",
    "VerifiedFormalEntries",
    "VerifiedSubmissionPredictions",
    "VerifiedTaskEntries",
    "VerifiedTaskPrediction",
    "read_closed_loop_artifacts",
    "read_verified_formal_entries",
    "read_verified_submission_predictions",
    "verify_closed_loop_artifacts",
    "write_closed_loop_artifacts",
]
