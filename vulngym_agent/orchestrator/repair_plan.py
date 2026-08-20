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

REPAIR_TOOL_POLICY_VERSION = "repair-tools-v1"

_SAFE_REPAIR_TOOLS_V1 = frozenset(
    {
        "caller_search",
        "condition_extraction",
        "dataflow_candidate_search",
        "extract_advisory_fields",
        "function_index",
        "git_cat_file",
        "git_diff",
        "git_log",
        "git_ls_tree",
        "git_parents",
        "git_show",
        "normalized_code_compare",
        "read_local_advisory",
        "read_local_patch",
        "read_local_reference",
        "resolve_local_repo",
        "ripgrep",
        "route_recognition",
        "tree_sitter",
        "validate_schema",
        "version_ancestry",
    }
)

# The version is part of every serialized RepairPlan. Keeping the registry
# versioned prevents a replay from silently gaining tools when policy evolves.
SAFE_REPAIR_TOOL_REGISTRY: Mapping[str, frozenset[str]] = MappingProxyType(
    {REPAIR_TOOL_POLICY_VERSION: _SAFE_REPAIR_TOOLS_V1}
)

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


@dataclass(frozen=True, slots=True)
class FieldRepairPolicy:
    """Static checks and maximum tool authority for one Entry field."""

    required_checks: tuple[str, ...]
    allowed_tools: tuple[str, ...]

    def __post_init__(self) -> None:
        checks = _string_tuple(
            self.required_checks,
            name="policy required_checks",
            allow_empty=False,
        )
        tools = _string_tuple(
            self.allowed_tools,
            name="policy allowed_tools",
        )
        unknown = set(tools) - _SAFE_REPAIR_TOOLS_V1
        if unknown:
            raise ValueError(
                f"policy contains unknown or unsafe tools: {sorted(unknown)}"
            )
        object.__setattr__(self, "required_checks", checks)
        object.__setattr__(self, "allowed_tools", tools)


_DEFAULT_FIELD_REPAIR_POLICY_V1: Mapping[str, FieldRepairPolicy] = (
    MappingProxyType(
        {
            "commit": FieldRepairPolicy(
                required_checks=(
                    "advisory:fix_commits",
                    "git:commit_exists",
                    "git:vulnerable_parent",
                    "patch:changed_paths",
                ),
                allowed_tools=(
                    "read_local_advisory",
                    "read_local_patch",
                    "resolve_local_repo",
                    "extract_advisory_fields",
                    "git_cat_file",
                    "git_diff",
                    "git_parents",
                    "version_ancestry",
                ),
            ),
            "critical_operation": FieldRepairPolicy(
                required_checks=(
                    "source:location_exists",
                    "source:code_matches",
                    "patch:changed_region",
                    "semantic:critical_role",
                ),
                allowed_tools=(
                    "read_local_patch",
                    "resolve_local_repo",
                    "git_show",
                    "git_diff",
                    "ripgrep",
                    "tree_sitter",
                    "function_index",
                    "caller_search",
                    "route_recognition",
                    "condition_extraction",
                    "normalized_code_compare",
                    "dataflow_candidate_search",
                ),
            ),
            "entry_id": FieldRepairPolicy(
                required_checks=("task:entry_id", "schema:entry_id"),
                allowed_tools=(),
            ),
            "entry_point": FieldRepairPolicy(
                required_checks=(
                    "source:location_exists",
                    "source:code_matches",
                    "semantic:entry_reachability",
                ),
                allowed_tools=(
                    "read_local_patch",
                    "resolve_local_repo",
                    "git_show",
                    "git_diff",
                    "git_ls_tree",
                    "git_log",
                    "ripgrep",
                    "tree_sitter",
                    "function_index",
                    "caller_search",
                    "route_recognition",
                    "normalized_code_compare",
                ),
            ),
            "origin": FieldRepairPolicy(
                required_checks=("schema:origin_constant",),
                allowed_tools=(),
            ),
            "project": FieldRepairPolicy(
                required_checks=("advisory:project", "repo:identity"),
                allowed_tools=(
                    "read_local_advisory",
                    "read_local_reference",
                    "resolve_local_repo",
                    "extract_advisory_fields",
                ),
            ),
            "repo_url": FieldRepairPolicy(
                required_checks=("advisory:repo_url", "git:remote"),
                allowed_tools=(
                    "read_local_advisory",
                    "read_local_reference",
                    "resolve_local_repo",
                    "extract_advisory_fields",
                ),
            ),
            "report_id": FieldRepairPolicy(
                required_checks=("task:report_id", "advisory:id"),
                allowed_tools=(
                    "read_local_advisory",
                    "extract_advisory_fields",
                ),
            ),
            "source_link": FieldRepairPolicy(
                required_checks=(
                    "advisory:source_link",
                    "schema:source_link_report_id",
                ),
                allowed_tools=(
                    "read_local_advisory",
                    "extract_advisory_fields",
                ),
            ),
            "trace": FieldRepairPolicy(
                required_checks=(
                    "source:trace_locations",
                    "source:trace_code",
                    "semantic:trace_continuity",
                ),
                allowed_tools=(
                    "read_local_patch",
                    "resolve_local_repo",
                    "git_show",
                    "git_diff",
                    "ripgrep",
                    "tree_sitter",
                    "function_index",
                    "caller_search",
                    "route_recognition",
                    "condition_extraction",
                    "normalized_code_compare",
                    "dataflow_candidate_search",
                ),
            ),
            "verify": FieldRepairPolicy(
                required_checks=("schema:verify_zero",),
                allowed_tools=(),
            ),
            "vuln_category_l1": FieldRepairPolicy(
                required_checks=(
                    "advisory:vulnerability_type",
                    "semantic:category_l1",
                ),
                allowed_tools=(
                    "read_local_advisory",
                    "read_local_reference",
                    "read_local_patch",
                    "resolve_local_repo",
                    "extract_advisory_fields",
                    "git_show",
                    "git_diff",
                    "ripgrep",
                    "tree_sitter",
                    "condition_extraction",
                    "dataflow_candidate_search",
                ),
            ),
            "vuln_category_l2": FieldRepairPolicy(
                required_checks=(
                    "advisory:vulnerability_type",
                    "semantic:category_l2",
                ),
                allowed_tools=(
                    "read_local_advisory",
                    "read_local_reference",
                    "read_local_patch",
                    "resolve_local_repo",
                    "extract_advisory_fields",
                    "git_show",
                    "git_diff",
                    "ripgrep",
                    "tree_sitter",
                    "condition_extraction",
                    "dataflow_candidate_search",
                ),
            ),
            "vuln_ids": FieldRepairPolicy(
                required_checks=("task:vuln_ids", "advisory:vuln_ids"),
                allowed_tools=(
                    "read_local_advisory",
                    "extract_advisory_fields",
                ),
            ),
            "vuln_title": FieldRepairPolicy(
                required_checks=("advisory:title", "semantic:title"),
                allowed_tools=(
                    "read_local_advisory",
                    "read_local_reference",
                    "read_local_patch",
                    "resolve_local_repo",
                    "extract_advisory_fields",
                    "git_show",
                    "git_diff",
                    "ripgrep",
                    "tree_sitter",
                    "dataflow_candidate_search",
                ),
            ),
        }
    )
)

if set(_DEFAULT_FIELD_REPAIR_POLICY_V1) != _FIELD_SET:
    raise RuntimeError("repair policy must cover every official Entry field")

FIELD_REPAIR_POLICY_REGISTRY: Mapping[
    str, Mapping[str, FieldRepairPolicy]
] = MappingProxyType(
    {REPAIR_TOOL_POLICY_VERSION: _DEFAULT_FIELD_REPAIR_POLICY_V1}
)
DEFAULT_FIELD_REPAIR_POLICY = FIELD_REPAIR_POLICY_REGISTRY[
    REPAIR_TOOL_POLICY_VERSION
]


def _policy_subset(
    values: Iterable[str],
    *,
    maximum: tuple[str, ...],
    name: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    """Validate a caller override and return it in canonical policy order."""

    selected = _string_tuple(values, name=name, allow_empty=allow_empty)
    unauthorized = set(selected) - set(maximum)
    if unauthorized:
        raise ValueError(
            f"{name} exceeds the field policy: {sorted(unauthorized)}"
        )
    selected_set = set(selected)
    return tuple(item for item in maximum if item in selected_set)


def _required_policy_checks(
    values: Iterable[str], *, baseline: tuple[str, ...], name: str
) -> tuple[str, ...]:
    """Require the complete versioned check baseline in canonical order.

    Tool authority may be narrowed for a particular repair, but a caller must
    never turn a mandatory source, schema, or semantic check off.  The public
    override remains accepted for wire compatibility only when it names the
    exact baseline (possibly in a different order).
    """

    selected = _string_tuple(values, name=name, allow_empty=False)
    missing = set(baseline) - set(selected)
    extra = set(selected) - set(baseline)
    if missing or extra:
        raise ValueError(
            f"{name} must preserve the complete field policy; "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )
    return baseline


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
    tool_policy_version: str
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

        if (
            not isinstance(self.tool_policy_version, str)
            or self.tool_policy_version not in FIELD_REPAIR_POLICY_REGISTRY
        ):
            raise ValueError("tool_policy_version is unsupported")
        field_policies = FIELD_REPAIR_POLICY_REGISTRY[self.tool_policy_version]

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
            policy = field_policies[field_name]
            checks = _required_policy_checks(
                instruction.required_checks,
                baseline=policy.required_checks,
                name=f"instructions.{field_name}.required_checks",
            )
            tools = _policy_subset(
                instruction.allowed_tools,
                maximum=policy.allowed_tools,
                name=f"instructions.{field_name}.allowed_tools",
                allow_empty=True,
            )
            instruction_values[field_name] = RepairInstruction(
                failure_codes=instruction.failure_codes,
                evidence=instruction.evidence,
                evidence_refs=instruction.evidence_refs,
                suggested_fix=instruction.suggested_fix,
                required_checks=checks,
                allowed_tools=tools,
            )

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
            "tool_policy_version": self.tool_policy_version,
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
        tool_policy_version: str = REPAIR_TOOL_POLICY_VERSION,
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
            tool_policy_version=tool_policy_version,
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
            "tool_policy_version",
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
            tool_policy_version=value["tool_policy_version"],
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
    for name, overrides in (
        ("required_checks", required_checks),
        ("allowed_tools", allowed_tools),
    ):
        if overrides is None:
            continue
        if not isinstance(overrides, Mapping):
            raise ValueError(f"{name} overrides must be an object")
        extra_fields = set(overrides) - set(repair_fields)
        if extra_fields:
            raise ValueError(
                f"{name} overrides contain non-repair fields: "
                f"{sorted(extra_fields, key=str)}"
            )
    instructions: dict[str, RepairInstruction] = {}
    for field_name in repair_fields:
        field_validation = validation.fields[field_name]
        field_policy = DEFAULT_FIELD_REPAIR_POLICY[field_name]
        selected_checks = (
            field_policy.required_checks
            if field_name not in checks_by_field
            else _required_policy_checks(
                checks_by_field[field_name],
                baseline=field_policy.required_checks,
                name=f"required_checks.{field_name}",
            )
        )
        selected_tools = (
            field_policy.allowed_tools
            if field_name not in tools_by_field
            else _policy_subset(
                tools_by_field[field_name],
                maximum=field_policy.allowed_tools,
                name=f"allowed_tools.{field_name}",
                allow_empty=True,
            )
        )
        instructions[field_name] = RepairInstruction(
            failure_codes=tuple(
                codes_by_field.get(field_name, ("t1_incorrect",))
            ),
            evidence=field_validation.evidence,
            evidence_refs=field_validation.evidence_refs,
            suggested_fix=field_validation.suggested_fix,
            required_checks=selected_checks,
            # An empty tuple is an explicit deny-all policy, not a request to
            # fall back to the field defaults.
            allowed_tools=selected_tools,
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
    "DEFAULT_FIELD_REPAIR_POLICY",
    "FIELD_REPAIR_POLICY_REGISTRY",
    "FieldRepairPolicy",
    "REPAIR_TOOL_POLICY_VERSION",
    "RepairInstruction",
    "RepairPlan",
    "SAFE_REPAIR_TOOL_REGISTRY",
    "build_repair_plan",
    "dependent_field_closure",
]
