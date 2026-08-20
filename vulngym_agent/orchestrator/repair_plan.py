"""Repair-plan construction and locked-field integrity checks."""

from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from vulngym_agent.adapters import ENTRY_FIELDS
from vulngym_agent.models import JsonSerializable, ValidationReport

from .contracts import (
    RunTask,
    _freeze_json,
    _thaw_json,
    canonical_sha256,
    freeze_entry_candidate,
)


_FIELD_SET = frozenset(ENTRY_FIELDS)
_FIELD_POSITION = {name: position for position, name in enumerate(ENTRY_FIELDS)}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_ID_RE = re.compile(r"^EV-[A-Z0-9][A-Z0-9._-]*$")
_REPORT_ID_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
_ENTRY_ID_RE = re.compile(r"^entry-[0-9]{5}$")
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_DEPENDENCIES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "repo_url": frozenset(
            {
                "project",
                "commit",
                "entry_point",
                "critical_operation",
                "trace",
            }
        ),
        "commit": frozenset(
            {"entry_point", "critical_operation", "trace"}
        ),
        "entry_point": frozenset({"trace"}),
        "critical_operation": frozenset({"trace"}),
        "report_id": frozenset({"source_link", "vuln_ids"}),
    }
)


def _field_order(values: Iterable[str], *, name: str) -> tuple[str, ...]:
    if isinstance(values, str):
        raise ValueError(f"{name} must be an iterable of field names, not a string")
    try:
        items = tuple(values)
    except TypeError as error:
        raise ValueError(f"{name} must be an iterable of field names") from error
    if any(not isinstance(item, str) or item not in _FIELD_SET for item in items):
        raise ValueError(f"{name} contains a non-Entry field")
    if len(items) != len(set(items)):
        raise ValueError(f"{name} must not contain duplicates")
    return tuple(sorted(items, key=_FIELD_POSITION.__getitem__))


def _string_tuple(
    values: Iterable[str], *, name: str, allow_empty: bool = True
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, set, frozenset, Mapping)):
        raise ValueError(f"{name} must be an ordered array")
    try:
        items = tuple(values)
    except TypeError as error:
        raise ValueError(f"{name} must be an array of strings") from error
    if any(not isinstance(item, str) or not item.strip() for item in items):
        raise ValueError(f"{name} must contain only non-empty strings")
    if len(items) != len(set(items)):
        raise ValueError(f"{name} must contain unique strings")
    if not allow_empty and not items:
        raise ValueError(f"{name} must not be empty")
    return items


def dependent_field_closure(repair_fields: Iterable[str]) -> tuple[str, ...]:
    """Return the transitive dependency closure excluding explicit repairs."""

    repair = set(_field_order(repair_fields, name="repair_fields"))
    closure: set[str] = set()
    frontier = list(repair)
    while frontier:
        field_name = frontier.pop()
        for dependent in _DEPENDENCIES.get(field_name, ()):
            if dependent not in repair and dependent not in closure:
                closure.add(dependent)
                frontier.append(dependent)
    return tuple(sorted(closure, key=_FIELD_POSITION.__getitem__))


@dataclass(frozen=True, slots=True)
class RepairInstruction(JsonSerializable):
    """Actionable T1 feedback for one explicitly incorrect Entry field."""

    failure_codes: tuple[str, ...]
    evidence: str
    evidence_refs: tuple[str, ...]
    suggested_fix: Any
    required_checks: tuple[str, ...]
    allowed_tools: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "failure_codes",
            _string_tuple(
                self.failure_codes, name="failure_codes", allow_empty=False
            ),
        )
        if not isinstance(self.evidence, str) or not self.evidence.strip():
            raise ValueError("evidence must be a non-empty string")
        refs = _string_tuple(self.evidence_refs, name="evidence_refs")
        if any(not _EVIDENCE_ID_RE.fullmatch(value) for value in refs):
            raise ValueError("evidence_refs contains an invalid evidence ID")
        object.__setattr__(self, "evidence_refs", refs)
        object.__setattr__(self, "suggested_fix", _freeze_json(self.suggested_fix))
        object.__setattr__(
            self,
            "required_checks",
            _string_tuple(
                self.required_checks, name="required_checks", allow_empty=False
            ),
        )
        object.__setattr__(
            self,
            "allowed_tools",
            _string_tuple(self.allowed_tools, name="allowed_tools"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "failure_codes": list(self.failure_codes),
            "evidence": self.evidence,
            "evidence_refs": list(self.evidence_refs),
            "suggested_fix": _thaw_json(self.suggested_fix),
            "required_checks": list(self.required_checks),
            "allowed_tools": list(self.allowed_tools),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RepairInstruction":
        if not isinstance(value, Mapping):
            raise ValueError("RepairInstruction must be an object")
        required = {
            "failure_codes",
            "evidence",
            "evidence_refs",
            "suggested_fix",
            "required_checks",
            "allowed_tools",
        }
        if set(value) != required:
            raise ValueError("RepairInstruction has missing or extra properties")
        return cls(
            failure_codes=value["failure_codes"],
            evidence=value["evidence"],
            evidence_refs=value["evidence_refs"],
            suggested_fix=value["suggested_fix"],
            required_checks=value["required_checks"],
            allowed_tools=value["allowed_tools"],
        )


@dataclass(frozen=True, slots=True)
class RepairPlan(JsonSerializable):
    """One bounded repair request with immutable-field integrity digests."""

    task_id: str
    report_id: str | None
    entry_id: str | None
    repair_iteration: int
    previous_candidate_sha256: str
    validation_sha256: str
    repair_fields: tuple[str, ...]
    dependent_fields: tuple[str, ...]
    locked_fields: tuple[str, ...]
    locked_field_hashes: Mapping[str, str]
    global_actions: tuple[str, ...]
    instructions: Mapping[str, RepairInstruction]

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not _TASK_ID_RE.fullmatch(
            self.task_id
        ):
            raise ValueError("task_id has an invalid format")
        if self.report_id is not None and (
            not isinstance(self.report_id, str)
            or not _REPORT_ID_RE.fullmatch(self.report_id)
        ):
            raise ValueError("report_id must be a canonical GHSA ID or None")
        if self.entry_id is not None and (
            not isinstance(self.entry_id, str)
            or not _ENTRY_ID_RE.fullmatch(self.entry_id)
        ):
            raise ValueError("entry_id must be canonical or None")
        if (
            isinstance(self.repair_iteration, bool)
            or not isinstance(self.repair_iteration, int)
            or not 1 <= self.repair_iteration <= 2
        ):
            raise ValueError("repair_iteration must be 1 or 2")
        for name, digest in (
            ("previous_candidate_sha256", self.previous_candidate_sha256),
            ("validation_sha256", self.validation_sha256),
        ):
            if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                raise ValueError(f"{name} must be a lower-case SHA-256 digest")

        repair = _field_order(self.repair_fields, name="repair_fields")
        dependent = _field_order(self.dependent_fields, name="dependent_fields")
        locked = _field_order(self.locked_fields, name="locked_fields")
        if not repair:
            raise ValueError("repair_fields must not be empty")
        if set(repair) & set(dependent) or set(repair) & set(locked) or set(
            dependent
        ) & set(locked):
            raise ValueError(
                "repair_fields, dependent_fields, and locked_fields must be disjoint"
            )
        if set(repair) | set(dependent) | set(locked) != _FIELD_SET:
            raise ValueError("repair/dependent/locked fields must partition ENTRY_FIELDS")
        expected_dependent = dependent_field_closure(repair)
        if dependent != expected_dependent:
            raise ValueError(
                "dependent_fields must equal the declared dependency closure"
            )
        expected_locked = tuple(
            field_name
            for field_name in ENTRY_FIELDS
            if field_name not in set(repair) | set(dependent)
        )
        if locked != expected_locked:
            raise ValueError("locked_fields must contain every remaining Entry field")

        if not isinstance(self.locked_field_hashes, Mapping):
            raise ValueError("locked_field_hashes must be an object")
        if set(self.locked_field_hashes) != set(locked):
            raise ValueError("locked_field_hashes keys must exactly match locked_fields")
        hashes: dict[str, str] = {}
        for field_name in locked:
            digest = self.locked_field_hashes[field_name]
            if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
                raise ValueError("locked field hashes must be lower-case SHA-256 values")
            hashes[field_name] = digest

        actions = _string_tuple(self.global_actions, name="global_actions")
        if not isinstance(self.instructions, Mapping) or set(
            self.instructions
        ) != set(repair):
            raise ValueError("instructions keys must exactly match repair_fields")
        instruction_values: dict[str, RepairInstruction] = {}
        for field_name in repair:
            instruction = self.instructions[field_name]
            if not isinstance(instruction, RepairInstruction):
                raise ValueError("instructions must contain RepairInstruction values")
            instruction_values[field_name] = instruction

        object.__setattr__(self, "repair_fields", repair)
        object.__setattr__(self, "dependent_fields", dependent)
        object.__setattr__(self, "locked_fields", locked)
        object.__setattr__(
            self, "locked_field_hashes", MappingProxyType(hashes)
        )
        object.__setattr__(self, "global_actions", actions)
        object.__setattr__(
            self, "instructions", MappingProxyType(instruction_values)
        )

    @property
    def allowed_change_fields(self) -> tuple[str, ...]:
        allowed = set(self.repair_fields) | set(self.dependent_fields)
        return tuple(name for name in ENTRY_FIELDS if name in allowed)

    def locked_field_changes(
        self, candidate: Mapping[str, Any]
    ) -> tuple[str, ...]:
        """Return locked fields whose canonical value no longer matches."""

        frozen = freeze_entry_candidate(candidate)
        return tuple(
            field_name
            for field_name in self.locked_fields
            if canonical_sha256(frozen[field_name])
            != self.locked_field_hashes[field_name]
        )

    def assert_locked_fields(self, candidate: Mapping[str, Any]) -> None:
        changed = self.locked_field_changes(candidate)
        if changed:
            raise ValueError(f"repair changed locked fields: {list(changed)}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "report_id": self.report_id,
            "entry_id": self.entry_id,
            "repair_iteration": self.repair_iteration,
            "previous_candidate_sha256": self.previous_candidate_sha256,
            "validation_sha256": self.validation_sha256,
            "repair_fields": list(self.repair_fields),
            "dependent_fields": list(self.dependent_fields),
            "locked_fields": list(self.locked_fields),
            "locked_field_hashes": dict(self.locked_field_hashes),
            "global_actions": list(self.global_actions),
            "instructions": {
                field_name: self.instructions[field_name].to_dict()
                for field_name in self.repair_fields
            },
        }

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        previous_candidate: Mapping[str, Any],
        validation: ValidationReport | Mapping[str, Any],
        repair_iteration: int,
        repair_fields: Iterable[str],
        instructions: Mapping[str, RepairInstruction],
        report_id: str | None = None,
        entry_id: str | None = None,
        global_actions: Iterable[str] = (),
    ) -> "RepairPlan":
        candidate = freeze_entry_candidate(previous_candidate)
        repair = _field_order(repair_fields, name="repair_fields")
        dependent = dependent_field_closure(repair)
        allowed = set(repair) | set(dependent)
        locked = tuple(name for name in ENTRY_FIELDS if name not in allowed)
        validation_value = (
            validation.to_dict()
            if isinstance(validation, ValidationReport)
            else validation
        )
        if not isinstance(validation_value, Mapping):
            raise ValueError("validation must be a ValidationReport or JSON object")
        if isinstance(validation, ValidationReport):
            if report_id is None:
                report_id = validation.report_id
            if entry_id is None:
                entry_id = validation.entry_id
        return cls(
            task_id=task_id,
            report_id=report_id,
            entry_id=entry_id,
            repair_iteration=repair_iteration,
            previous_candidate_sha256=canonical_sha256(candidate),
            validation_sha256=canonical_sha256(validation_value),
            repair_fields=repair,
            dependent_fields=dependent,
            locked_fields=locked,
            locked_field_hashes={
                name: canonical_sha256(candidate[name]) for name in locked
            },
            global_actions=tuple(global_actions),
            instructions=instructions,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RepairPlan":
        if not isinstance(value, Mapping):
            raise ValueError("RepairPlan must be an object")
        required = {
            "task_id",
            "report_id",
            "entry_id",
            "repair_iteration",
            "previous_candidate_sha256",
            "validation_sha256",
            "repair_fields",
            "dependent_fields",
            "locked_fields",
            "locked_field_hashes",
            "global_actions",
            "instructions",
        }
        if set(value) != required:
            raise ValueError("RepairPlan has missing or extra properties")
        raw_instructions = value["instructions"]
        if not isinstance(raw_instructions, Mapping):
            raise ValueError("RepairPlan.instructions must be an object")
        return cls(
            task_id=value["task_id"],
            report_id=value["report_id"],
            entry_id=value["entry_id"],
            repair_iteration=value["repair_iteration"],
            previous_candidate_sha256=value["previous_candidate_sha256"],
            validation_sha256=value["validation_sha256"],
            repair_fields=value["repair_fields"],
            dependent_fields=value["dependent_fields"],
            locked_fields=value["locked_fields"],
            locked_field_hashes=value["locked_field_hashes"],
            global_actions=value["global_actions"],
            instructions={
                name: RepairInstruction.from_dict(instruction)
                for name, instruction in raw_instructions.items()
            },
        )


def build_repair_plan(
    *,
    task: RunTask,
    previous_candidate: Mapping[str, Any],
    validation: ValidationReport,
    repair_iteration: int,
    failure_codes: Mapping[str, Iterable[str]] | None = None,
    required_checks: Mapping[str, Iterable[str]] | None = None,
    allowed_tools: Mapping[str, Iterable[str]] | None = None,
    global_actions: Iterable[str] = (),
) -> RepairPlan:
    """Build a plan for at least one official field explicitly ``incorrect``.

    Pseudo-fields such as ``schema`` and ``evidence_package`` are intentionally
    not converted into unrestricted repairs.  A run with no incorrect official
    field must be routed to manual review by the state machine.
    """

    repair_fields = tuple(
        name
        for name in ENTRY_FIELDS
        if name in validation.fields and validation.fields[name].status == "incorrect"
    )
    if not repair_fields:
        raise ValueError("validation has no incorrect official Entry field")

    codes_by_field = failure_codes or {}
    checks_by_field = required_checks or {}
    tools_by_field = allowed_tools or {}
    instructions: dict[str, RepairInstruction] = {}
    for field_name in repair_fields:
        field_validation = validation.fields[field_name]
        instructions[field_name] = RepairInstruction(
            failure_codes=tuple(
                codes_by_field.get(field_name, ("t1_incorrect",))
            ),
            evidence=field_validation.evidence,
            evidence_refs=field_validation.evidence_refs,
            suggested_fix=field_validation.suggested_fix,
            required_checks=tuple(
                checks_by_field.get(field_name, (f"revalidate:{field_name}",))
            ),
            allowed_tools=tuple(tools_by_field.get(field_name, ())),
        )

    return RepairPlan.create(
        task_id=task.task_id,
        report_id=task.report_id or validation.report_id,
        entry_id=task.entry_id or validation.entry_id,
        previous_candidate=previous_candidate,
        validation=validation,
        repair_iteration=repair_iteration,
        repair_fields=repair_fields,
        instructions=instructions,
        global_actions=global_actions,
    )


__all__ = [
    "RepairInstruction",
    "RepairPlan",
    "build_repair_plan",
    "dependent_field_closure",
]
