"""Deterministic T2 -> T1 -> bounded-repair orchestration.

The state machine deliberately accepts its validator through a factory.  A
fresh validator is created for every round and receives only the original
``RunTask`` plus a plain official Entry candidate.  Producer evidence,
assumptions, tool telemetry, and repair plans are retained as orchestrator
sidecars and are never passed to T1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol

from vulngym_agent.adapters import ENTRY_FIELDS
from vulngym_agent.agents.t1_validator import T1ValidationOutcome
from vulngym_agent.models import FieldValidation, ValidationReport

from .budget import Budget, BudgetEvent, BudgetExceeded, Limits, Usage
from .contracts import (
    ProductionDeferred,
    ProductionOutcome,
    ProducerResult,
    RunTask,
    canonical_sha256,
    freeze_entry_candidate,
)
from .repair_plan import RepairPlan, build_repair_plan

if TYPE_CHECKING:
    from vulngym_agent.agents.t2_producer import T2Producer


RUN_STATUSES = frozenset(
    {
        "pending",
        "producing",
        "validating",
        "repairing",
        "finalized",
        "manual_review",
        "failed",
    }
)
TERMINAL_STATUSES = frozenset({"finalized", "manual_review", "failed"})

STOP_VALIDATED_CORRECT = "validated_correct"
STOP_VALIDATION_UNCERTAIN = "validation_uncertain"
STOP_MAX_REPAIR_ITERATIONS = "max_repair_iterations"
STOP_NO_PROGRESS = "no_progress"
STOP_REPEATED_ERROR = "repeated_error"
STOP_LOCKED_FIELD_CHANGED = "locked_field_changed"
STOP_VALIDATION_REGRESSION = "validation_regression"
STOP_BUDGET_EXHAUSTED = "budget_exhausted"
STOP_PRODUCER_ERROR = "producer_error"
STOP_VALIDATOR_ERROR = "validator_error"
STOP_INVALID_CANDIDATE = "invalid_candidate"
STOP_NO_REPAIRABLE_FIELDS = "no_repairable_fields"
STOP_SIDECAR_CONFLICT = "producer_sidecar_conflict"
STOP_UNACCOUNTED_TOOL_CALL = "unaccounted_tool_call"
STOP_UNACCOUNTED_MODEL_CALL = "unaccounted_model_call"
STOP_PRODUCER_DEFERRED = "producer_deferred"

_UNACCOUNTED_TOOL_ERROR = (
    "producer tool-call records do not close the budget delta"
)
_UNACCOUNTED_MODEL_ERROR = (
    "producer model-call records do not close the budget delta"
)

_TERMINAL_STOP_REASONS = {
    "finalized": frozenset({STOP_VALIDATED_CORRECT}),
    "manual_review": frozenset(
        {
            STOP_VALIDATION_UNCERTAIN,
            STOP_MAX_REPAIR_ITERATIONS,
            STOP_NO_PROGRESS,
            STOP_REPEATED_ERROR,
            STOP_LOCKED_FIELD_CHANGED,
            STOP_VALIDATION_REGRESSION,
            STOP_BUDGET_EXHAUSTED,
            STOP_NO_REPAIRABLE_FIELDS,
            STOP_PRODUCER_DEFERRED,
        }
    ),
    "failed": frozenset(
        {
            STOP_BUDGET_EXHAUSTED,
            STOP_PRODUCER_ERROR,
            STOP_VALIDATOR_ERROR,
            STOP_INVALID_CANDIDATE,
            STOP_SIDECAR_CONFLICT,
            STOP_UNACCOUNTED_TOOL_CALL,
            STOP_UNACCOUNTED_MODEL_CALL,
        }
    ),
}

_STOP_REASON_PHASES = {
    STOP_VALIDATED_CORRECT: "validation",
    STOP_VALIDATION_UNCERTAIN: "validation",
    STOP_MAX_REPAIR_ITERATIONS: "validation",
    STOP_NO_PROGRESS: "repair",
    STOP_REPEATED_ERROR: "validation",
    STOP_LOCKED_FIELD_CHANGED: "repair",
    STOP_VALIDATION_REGRESSION: "validation",
    STOP_BUDGET_EXHAUSTED: "budget",
    STOP_PRODUCER_ERROR: "producer",
    STOP_VALIDATOR_ERROR: "validator",
    STOP_INVALID_CANDIDATE: "initial_candidate",
    STOP_NO_REPAIRABLE_FIELDS: "validation",
    STOP_SIDECAR_CONFLICT: "sidecar",
    STOP_UNACCOUNTED_TOOL_CALL: "tool_accounting",
    STOP_UNACCOUNTED_MODEL_CALL: "model_accounting",
    STOP_PRODUCER_DEFERRED: "producer",
}

_MAX_REPAIR_ITERATIONS = 2
_MAX_VALIDATIONS = _MAX_REPAIR_ITERATIONS + 1


class CandidateValidator(Protocol):
    """Small T1 surface required by the closed-loop runner."""

    def validate(
        self, candidate: Any, *, input_line: int | None = None
    ) -> T1ValidationOutcome:
        ...


ValidatorFactory = Callable[[RunTask], CandidateValidator]


def _plain_candidate(candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Return a detached JSON object without producer sidecars."""

    return ProductionOutcome(candidate=candidate).to_dict()["candidate"]


def _input_line(task: RunTask) -> int | None:
    value = task.inputs.get("input_line")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    return None


def _policy_scope_for_attempt(attempt: int) -> str:
    return "t2.initial" if attempt == 0 else f"t2.repair-{attempt}"


def _assert_deferred_bound(
    task: RunTask,
    deferred: ProductionDeferred,
    *,
    attempt: int,
    mode: str,
    parent_candidate_sha256: str | None = None,
    repair_plan_sha256: str | None = None,
) -> None:
    """Require a defer sidecar to identify exactly the active task row."""

    if deferred.task_id != task.task_id:
        raise ValueError("deferred task_id does not match the active task")
    if deferred.report_id != task.report_id:
        raise ValueError("deferred report_id does not match the active task")
    if deferred.entry_id != task.entry_id:
        raise ValueError("deferred entry_id does not match the active task")
    if deferred.inputs_sha256 != canonical_sha256(task.inputs):
        raise ValueError("deferred inputs_sha256 does not match the active task")
    if deferred.attempt != attempt or deferred.mode != mode:
        raise ValueError("deferred attempt/mode does not match the active round")
    if deferred.parent_candidate_sha256 != parent_candidate_sha256:
        raise ValueError("deferred parent digest does not match the active round")
    if deferred.repair_plan_sha256 != repair_plan_sha256:
        raise ValueError("deferred repair-plan digest does not match the active round")


def _accounting_error(
    result: ProducerResult,
    *,
    task: RunTask,
    attempt: int,
    before_event_count: int,
    budget: Budget,
) -> tuple[str, str] | None:
    """Close one returned producer result against exact scoped ledger events."""

    events = budget.events
    if before_event_count < 0 or len(events) < before_event_count:
        return STOP_PRODUCER_ERROR, "producer budget ledger was truncated"
    delta = events[before_event_count:]
    expected_scope = _policy_scope_for_attempt(attempt)
    event_by_sequence = {event.sequence: event for event in delta}
    claimed_sequences: set[int] = set()

    def bind(records: tuple[Any, ...], resource: str) -> bool:
        sequences = tuple(record.budget_event_sequence for record in records)
        if sequences != tuple(sorted(sequences)) or len(sequences) != len(
            set(sequences)
        ):
            return False
        for record in records:
            if (
                record.task_id != task.task_id
                or record.attempt != attempt
                or record.policy_scope != expected_scope
                or record.budget_event_sequence in claimed_sequences
            ):
                return False
            event = event_by_sequence.get(record.budget_event_sequence)
            if (
                event is None
                or event.resource != resource
                or event.amount != 1
                or event.operation != record.operation
            ):
                return False
            claimed_sequences.add(record.budget_event_sequence)
        expected_sequences = {
            event.sequence for event in delta if event.resource == resource
        }
        return set(sequences) == expected_sequences

    if not bind(result.tool_calls, "tool_calls"):
        return STOP_UNACCOUNTED_TOOL_CALL, _UNACCOUNTED_TOOL_ERROR
    if not bind(result.model_calls, "llm_calls"):
        return STOP_UNACCOUNTED_MODEL_CALL, _UNACCOUNTED_MODEL_ERROR
    if any(
        event.resource not in {"tool_calls", "llm_calls"} for event in delta
    ):
        return STOP_PRODUCER_ERROR, "producer charged an unauthorized budget resource"
    return None


def _report_expected_verdict(report: ValidationReport) -> str:
    statuses = {validation.status for validation in report.fields.values()}
    if "incorrect" in statuses:
        return "incorrect"
    if "uncertain" in statuses:
        return "uncertain"
    return "correct"


def _incorrect_official_fields(report: ValidationReport) -> tuple[str, ...]:
    return tuple(
        name
        for name in ENTRY_FIELDS
        if name in report.fields and report.fields[name].status == "incorrect"
    )


def _error_signature(report: ValidationReport) -> str:
    """Hash stable, actionable failure content rather than confidence values."""

    failures: dict[str, Any] = {}
    for field_name in sorted(report.fields):
        validation = report.fields[field_name]
        if validation.status != "incorrect":
            continue
        failures[field_name] = {
            "evidence": validation.evidence,
        }
    return canonical_sha256(failures)


def _changed_fields(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> tuple[str, ...]:
    return tuple(
        name
        for name in ENTRY_FIELDS
        if canonical_sha256(before[name]) != canonical_sha256(after[name])
    )


def _regressed_fields(
    before: ValidationReport, after: ValidationReport
) -> tuple[str, ...]:
    return tuple(
        field_name
        for field_name, prior in before.fields.items()
        if prior.status == "correct"
        and (
            field_name not in after.fields
            or after.fields[field_name].status != "correct"
        )
    )


def _freeze_budget_snapshot(value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate, replay, and detach one complete per-run budget ledger."""

    if not isinstance(value, Mapping) or set(value) != {
        "limits",
        "usage",
        "events",
    }:
        raise ValueError("budget must contain limits, usage, and events")
    limits_value = value["limits"]
    usage_value = value["usage"]
    events_value = value["events"]
    if not isinstance(limits_value, Mapping):
        raise ValueError("budget limits must be an object")
    limits = Limits.from_dict(limits_value)
    if not isinstance(usage_value, Mapping) or set(usage_value) != {
        "llm_calls",
        "tool_calls",
        "repair_iterations",
    }:
        raise ValueError("budget usage has an invalid shape")
    usage = Usage(**dict(usage_value))
    if isinstance(events_value, (str, bytes, set, frozenset, Mapping)):
        raise ValueError("budget events must be an ordered array")
    try:
        raw_events = tuple(events_value)
    except TypeError as error:
        raise ValueError("budget events must be an ordered array") from error

    events: list[BudgetEvent] = []
    replayed = Usage()
    for expected_sequence, raw in enumerate(raw_events, start=1):
        if not isinstance(raw, Mapping) or not {
            "sequence",
            "resource",
            "amount",
            "usage_after",
        } <= set(raw) <= {
            "sequence",
            "resource",
            "amount",
            "usage_after",
            "operation",
        }:
            raise ValueError("budget event has an invalid shape")
        raw_after = raw["usage_after"]
        if not isinstance(raw_after, Mapping) or set(raw_after) != {
            "llm_calls",
            "tool_calls",
            "repair_iterations",
        }:
            raise ValueError("budget event usage_after has an invalid shape")
        event = BudgetEvent(
            sequence=raw["sequence"],
            resource=raw["resource"],
            amount=raw["amount"],
            usage_after=Usage(**dict(raw_after)),
            operation=raw.get("operation"),
        )
        replayed = replayed.incremented(event.resource, event.amount)
        if event.sequence != expected_sequence or event.usage_after != replayed:
            raise ValueError("budget event ledger is not replayable")
        events.append(event)
    if replayed != usage:
        raise ValueError("budget usage does not equal its event ledger")
    for resource in ("llm_calls", "tool_calls", "repair_iterations"):
        if usage.value_for(resource) > getattr(limits, f"max_{resource}"):
            raise ValueError("budget usage exceeds its declared limits")

    return MappingProxyType(
        {
            "limits": MappingProxyType(limits.to_dict()),
            "usage": MappingProxyType(usage.to_dict()),
            "events": tuple(
                MappingProxyType(
                    {
                        **event.to_dict(),
                        "usage_after": MappingProxyType(
                            event.usage_after.to_dict()
                        ),
                    }
                )
                for event in events
            ),
        }
    )


def _assert_repair_budget_events(
    budget: Mapping[str, Any], repair_iteration: int
) -> None:
    """Bind each repair round to one unit canonical ledger operation."""

    repair_events = tuple(
        event
        for event in budget["events"]
        if event["resource"] == "repair_iterations"
    )
    if len(repair_events) != repair_iteration:
        raise ValueError("repair budget events must identify every repair round")
    for expected_iteration, event in enumerate(repair_events, start=1):
        if (
            event["amount"] != 1
            or event.get("operation") != f"repair:{expected_iteration}"
        ):
            raise ValueError(
                "repair budget event must be a unit canonical repair operation"
            )


def _apply_task_identity_gate(
    task: RunTask,
    candidate: Mapping[str, Any],
    outcome: T1ValidationOutcome,
) -> T1ValidationOutcome:
    """Bind validation to the candidate, then apply trusted task anchors.

    T1 must report the identifiers it actually inspected.  A mismatch between
    those candidate identifiers and an optional RunTask anchor is repairable,
    so the orchestrator adds deterministic ``incorrect`` fields instead of
    finalizing or failing the task.
    """

    report = outcome.report
    if report.report_id != candidate["report_id"]:
        raise ValueError("validator report_id does not identify its candidate")
    if report.entry_id != candidate["entry_id"]:
        raise ValueError("validator entry_id does not identify its candidate")

    identity_fixes: dict[str, str] = {}
    if task.report_id is not None and candidate["report_id"] != task.report_id:
        identity_fixes["report_id"] = task.report_id
    if task.entry_id is not None and candidate["entry_id"] != task.entry_id:
        identity_fixes["entry_id"] = task.entry_id
    if not identity_fixes:
        return outcome

    fields = dict(report.fields)
    for field_name, expected in identity_fixes.items():
        prior = fields.get(field_name)
        fields[field_name] = FieldValidation(
            status="incorrect",
            confidence=1.0,
            evidence=(
                f"Candidate {field_name} differs from the trusted RunTask "
                "correlation anchor."
            ),
            evidence_refs=() if prior is None else prior.evidence_refs,
            suggested_fix=expected,
        )
    augmented = ValidationReport(
        # The report continues to identify the candidate that T1 actually
        # inspected.  Trusted task anchors belong in the synthetic field
        # findings and the subsequent RepairPlan, not in the observation's
        # identity metadata.
        report_id=report.report_id,
        entry_id=report.entry_id,
        input_line=report.input_line,
        verdict="incorrect",
        fields=fields,
        summary=(
            f"{report.summary} RunTask identity mismatch requires bounded repair."
        ),
        missing_information=report.missing_information,
    )
    return T1ValidationOutcome(report=augmented, evidence=outcome.evidence)


def _assert_t1_outcome_closed(
    candidate: Mapping[str, Any],
    outcome: T1ValidationOutcome,
    *,
    expected_input_line: int | None,
) -> None:
    """Require one T1 report and evidence sidecar to close on its candidate."""

    if outcome.report.verdict != _report_expected_verdict(outcome.report):
        raise ValueError("validator report verdict disagrees with its fields")
    if outcome.report.report_id != candidate["report_id"]:
        raise ValueError("validator report_id does not identify its candidate")
    if outcome.report.entry_id != candidate["entry_id"]:
        raise ValueError("validator entry_id does not identify its candidate")
    if outcome.report.input_line != expected_input_line:
        raise ValueError("validator report input_line does not identify its task row")
    evidence_ids = [item.evidence_id for item in outcome.evidence]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("validator evidence IDs must be unique per round")
    for item in outcome.evidence:
        if item.report_id != candidate["report_id"]:
            raise ValueError(
                "validator evidence report_id does not identify its candidate"
            )
        if item.entry_id is not None and item.entry_id != candidate["entry_id"]:
            raise ValueError(
                "validator evidence entry_id does not identify its candidate"
            )
        if item.tool_call_id is not None:
            raise ValueError(
                "validator evidence cannot reference an unrecorded tool call"
            )
    referenced_ids = {
        evidence_id
        for validation in outcome.report.fields.values()
        for evidence_id in validation.evidence_refs
    }
    if referenced_ids != set(evidence_ids):
        raise ValueError(
            "validator evidence_refs and evidence sidecar must form a closed set"
        )


@dataclass(frozen=True, slots=True)
class ProductionSummary:
    """Sanitized candidate lineage persisted in ``RunState``."""

    attempt: int
    mode: str
    candidate_sha256: str
    parent_candidate_sha256: str | None = None
    repair_plan_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or not 0 <= self.attempt <= _MAX_REPAIR_ITERATIONS
        ):
            raise ValueError("attempt must be an integer from 0 through 2")
        if self.mode not in {"generated", "provided", "repair"}:
            raise ValueError("mode must be generated, provided, or repair")
        for name, value, nullable in (
            ("candidate_sha256", self.candidate_sha256, False),
            ("parent_candidate_sha256", self.parent_candidate_sha256, True),
            ("repair_plan_sha256", self.repair_plan_sha256, True),
        ):
            if value is None and nullable:
                continue
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{name} must be a lower-case SHA-256 digest")
        if self.mode in {"generated", "provided"} and (
            self.attempt != 0
            or self.parent_candidate_sha256 is not None
            or self.repair_plan_sha256 is not None
        ):
            raise ValueError(
                "initial candidate must be attempt zero without parents"
            )
        if self.mode == "repair" and (
            self.attempt < 1
            or self.parent_candidate_sha256 is None
            or self.repair_plan_sha256 is None
        ):
            raise ValueError("repair production requires its parent and plan digests")

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "mode": self.mode,
            "candidate_sha256": self.candidate_sha256,
            "parent_candidate_sha256": self.parent_candidate_sha256,
            "repair_plan_sha256": self.repair_plan_sha256,
        }


@dataclass(frozen=True, slots=True)
class ProductionAttemptSummary:
    """Persist every returned producer candidate and its disposition."""

    attempt: int
    mode: str
    candidate_sha256: str
    outcome_sha256: str
    disposition: str
    parent_candidate_sha256: str | None = None
    repair_plan_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or not 0 <= self.attempt <= _MAX_REPAIR_ITERATIONS
        ):
            raise ValueError("production attempt must be from zero through two")
        if self.mode not in {"generated", "provided", "repair"}:
            raise ValueError("attempt mode must be generated, provided, or repair")
        if self.disposition not in {
            "accepted",
            "rejected_locked_fields",
            "rejected_no_progress",
        }:
            raise ValueError("production attempt disposition is invalid")
        for name, value, nullable in (
            ("candidate_sha256", self.candidate_sha256, False),
            ("outcome_sha256", self.outcome_sha256, False),
            ("parent_candidate_sha256", self.parent_candidate_sha256, True),
            ("repair_plan_sha256", self.repair_plan_sha256, True),
        ):
            if value is None and nullable:
                continue
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{name} must be a lower-case SHA-256 digest")
        if self.attempt == 0 and (
            self.mode not in {"generated", "provided"}
            or self.disposition != "accepted"
            or self.parent_candidate_sha256 is not None
            or self.repair_plan_sha256 is not None
        ):
            raise ValueError("initial production attempt must be accepted")
        if self.attempt > 0 and (
            self.mode != "repair"
            or self.parent_candidate_sha256 is None
            or self.repair_plan_sha256 is None
        ):
            raise ValueError("repair attempt requires parent and RepairPlan digests")

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "mode": self.mode,
            "candidate_sha256": self.candidate_sha256,
            "outcome_sha256": self.outcome_sha256,
            "disposition": self.disposition,
            "parent_candidate_sha256": self.parent_candidate_sha256,
            "repair_plan_sha256": self.repair_plan_sha256,
        }


@dataclass(frozen=True, slots=True)
class ValidationSummary:
    """Bind one successful T1 report digest to its accepted candidate."""

    attempt: int
    candidate_sha256: str
    validation_sha256: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or not 0 <= self.attempt <= _MAX_REPAIR_ITERATIONS
        ):
            raise ValueError("validation attempt must be from zero through two")
        for name, value in (
            ("candidate_sha256", self.candidate_sha256),
            ("validation_sha256", self.validation_sha256),
            ("evidence_sha256", self.evidence_sha256),
        ):
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{name} must be a lower-case SHA-256 digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "candidate_sha256": self.candidate_sha256,
            "validation_sha256": self.validation_sha256,
            "evidence_sha256": self.evidence_sha256,
        }


@dataclass(frozen=True, slots=True)
class TerminationSummary:
    """Bind terminal status metadata to the retained error payload."""

    reason: str
    phase: str
    attempt: int
    error_sha256: str | None = None
    budget_resource: str | None = None
    budget_requested: int | None = None
    budget_remaining: int | None = None

    def __post_init__(self) -> None:
        if self.reason not in _STOP_REASON_PHASES:
            raise ValueError("termination reason is not supported")
        if self.phase != _STOP_REASON_PHASES[self.reason]:
            raise ValueError("termination phase does not match its reason")
        if (
            isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or not 0 <= self.attempt <= _MAX_REPAIR_ITERATIONS
        ):
            raise ValueError("termination attempt must be from zero through two")
        if self.error_sha256 is not None and (
            not isinstance(self.error_sha256, str)
            or len(self.error_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.error_sha256
            )
        ):
            raise ValueError("termination error_sha256 must be SHA-256 or None")
        if self.reason == STOP_PRODUCER_DEFERRED and self.error_sha256 is not None:
            raise ValueError("producer deferral is not an error termination")
        budget_values = (
            self.budget_resource,
            self.budget_requested,
            self.budget_remaining,
        )
        if self.reason == STOP_BUDGET_EXHAUSTED:
            if self.budget_resource not in {
                "llm_calls",
                "tool_calls",
                "repair_iterations",
            }:
                raise ValueError(
                    "budget termination requires a supported budget resource"
                )
            if (
                isinstance(self.budget_requested, bool)
                or not isinstance(self.budget_requested, int)
                or self.budget_requested < 1
                or isinstance(self.budget_remaining, bool)
                or not isinstance(self.budget_remaining, int)
                or self.budget_remaining < 0
                or self.budget_requested <= self.budget_remaining
            ):
                raise ValueError(
                    "budget termination requires a rejected charge and capacity"
                )
        elif any(value is not None for value in budget_values):
            raise ValueError(
                "non-budget termination cannot contain budget failure metadata"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "phase": self.phase,
            "attempt": self.attempt,
            "error_sha256": self.error_sha256,
            "budget_resource": self.budget_resource,
            "budget_requested": self.budget_requested,
            "budget_remaining": self.budget_remaining,
        }


@dataclass(frozen=True, slots=True)
class RunState:
    """Sanitized, deterministic snapshot of one closed-loop run."""

    task: RunTask
    status: str
    repair_iteration: int
    validation_count: int
    budget: Mapping[str, Any]
    candidate: Mapping[str, Any] | None = None
    candidate_sha256: str | None = None
    last_validation: ValidationReport | None = None
    active_repair_plan: RepairPlan | None = None
    production_history: tuple[ProductionSummary, ...] = ()
    production_attempts: tuple[ProductionAttemptSummary, ...] = ()
    validation_history: tuple[ValidationSummary, ...] = ()
    deferred_sha256: str | None = None
    stop_reason: str | None = None
    termination: TerminationSummary | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.task, RunTask):
            raise ValueError("task must be a RunTask")
        if self.status not in RUN_STATUSES:
            raise ValueError("status is not a supported run state")
        if (
            isinstance(self.repair_iteration, bool)
            or not isinstance(self.repair_iteration, int)
            or not 0 <= self.repair_iteration <= _MAX_REPAIR_ITERATIONS
        ):
            raise ValueError("repair_iteration must be between zero and two")
        if (
            isinstance(self.validation_count, bool)
            or not isinstance(self.validation_count, int)
            or not 0 <= self.validation_count <= _MAX_VALIDATIONS
        ):
            raise ValueError("validation_count must be between zero and three")
        if (self.candidate is None) != (self.candidate_sha256 is None):
            raise ValueError("candidate and candidate_sha256 must be null together")
        if self.candidate is not None:
            candidate = ProductionOutcome(candidate=self.candidate).candidate
            digest = canonical_sha256(candidate)
            if digest != self.candidate_sha256:
                raise ValueError("candidate_sha256 does not match candidate")
            object.__setattr__(self, "candidate", candidate)
        if self.last_validation is not None and not isinstance(
            self.last_validation, ValidationReport
        ):
            raise ValueError("last_validation must be a ValidationReport or None")
        if self.active_repair_plan is not None and not isinstance(
            self.active_repair_plan, RepairPlan
        ):
            raise ValueError("active_repair_plan must be a RepairPlan or None")
        history = tuple(self.production_history)
        if len(history) > _MAX_VALIDATIONS or any(
            not isinstance(item, ProductionSummary) for item in history
        ):
            raise ValueError("production_history is invalid or too long")
        object.__setattr__(self, "production_history", history)
        attempts = tuple(self.production_attempts)
        if len(attempts) > _MAX_VALIDATIONS or any(
            not isinstance(item, ProductionAttemptSummary) for item in attempts
        ):
            raise ValueError("production_attempts is invalid or too long")
        object.__setattr__(self, "production_attempts", attempts)
        validation_history = tuple(self.validation_history)
        if len(validation_history) != self.validation_count or any(
            not isinstance(item, ValidationSummary)
            for item in validation_history
        ):
            raise ValueError(
                "validation_history must contain one summary per validation"
            )
        object.__setattr__(self, "validation_history", validation_history)

        if self.deferred_sha256 is not None and (
            not isinstance(self.deferred_sha256, str)
            or len(self.deferred_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.deferred_sha256
            )
        ):
            raise ValueError("deferred_sha256 must be a lower-case SHA-256 digest")
        if (self.stop_reason == STOP_PRODUCER_DEFERRED) != (
            self.deferred_sha256 is not None
        ):
            raise ValueError(
                "producer-deferred state and deferred_sha256 must occur together"
            )

        if self.candidate is None:
            if history:
                raise ValueError("candidate-less states cannot have production history")
        else:
            if not history or history[-1].candidate_sha256 != self.candidate_sha256:
                raise ValueError(
                    "candidate must equal the final accepted production summary"
                )
        if history:
            if history[0].attempt != 0 or history[0].mode not in {
                "generated",
                "provided",
            }:
                raise ValueError("production history must start at attempt zero")
            for index, item in enumerate(history[1:], start=1):
                if (
                    item.mode != "repair"
                    or item.attempt != index
                    or item.parent_candidate_sha256
                    != history[index - 1].candidate_sha256
                ):
                    raise ValueError("production history parent chain is invalid")
        if history and not attempts:
            raise ValueError("production history requires attempt summaries")
        if attempts:
            if attempts[0].attempt != 0 or attempts[0].disposition != "accepted":
                raise ValueError("production attempts must start with acceptance")
            for index, item in enumerate(attempts):
                if item.attempt != index:
                    raise ValueError("production attempts must be contiguous")
                if index > 0 and (
                    len(history) < index
                    or item.parent_candidate_sha256
                    != history[index - 1].candidate_sha256
                ):
                    raise ValueError("production attempt parent is not accepted")
        accepted_attempts = tuple(
            item for item in attempts if item.disposition == "accepted"
        )
        if len(accepted_attempts) != len(history) or any(
            attempt.attempt != production.attempt
            or attempt.mode != production.mode
            or attempt.candidate_sha256 != production.candidate_sha256
            or attempt.parent_candidate_sha256
            != production.parent_candidate_sha256
            or attempt.repair_plan_sha256 != production.repair_plan_sha256
            for attempt, production in zip(accepted_attempts, history)
        ):
            raise ValueError("accepted attempts do not equal production history")
        rejected_attempts = tuple(
            item for item in attempts if item.disposition != "accepted"
        )
        if rejected_attempts and (
            len(rejected_attempts) != 1
            or rejected_attempts[0] is not attempts[-1]
            or len(attempts) != len(history) + 1
        ):
            raise ValueError("only the final production attempt may be rejected")
        expected_rejection = {
            STOP_LOCKED_FIELD_CHANGED: "rejected_locked_fields",
            STOP_NO_PROGRESS: "rejected_no_progress",
        }.get(self.stop_reason)
        if expected_rejection is None and rejected_attempts:
            raise ValueError("stop reason does not permit a rejected attempt")
        if expected_rejection is not None and (
            not rejected_attempts
            or rejected_attempts[0].disposition != expected_rejection
        ):
            raise ValueError("stop reason requires its rejected attempt disposition")
        if len(attempts) - 1 > self.repair_iteration:
            raise ValueError("production attempts exceed charged repairs")
        if len(validation_history) > len(history):
            raise ValueError("validation history cannot exceed production history")
        for index, item in enumerate(validation_history):
            production = history[index]
            if (
                item.attempt != production.attempt
                or item.candidate_sha256 != production.candidate_sha256
            ):
                raise ValueError(
                    "validation history must follow accepted production history"
                )
        if (self.last_validation is None) != (not validation_history):
            raise ValueError(
                "last_validation and validation_history must be null together"
            )
        if self.last_validation is not None and (
            canonical_sha256(self.last_validation)
            != validation_history[-1].validation_sha256
        ):
            raise ValueError(
                "last_validation does not match its validation summary"
            )
        if self.last_validation is not None and (
            self.last_validation.input_line != _input_line(self.task)
        ):
            raise ValueError("last_validation input_line does not match its task")
        if (
            self.last_validation is not None
            and self.candidate is not None
            and validation_history[-1].candidate_sha256 == self.candidate_sha256
            and (
                self.last_validation.report_id != self.candidate["report_id"]
                or self.last_validation.entry_id != self.candidate["entry_id"]
            )
        ):
            raise ValueError(
                "last_validation identity does not match its candidate"
            )
        if self.repair_iteration < max(0, len(history) - 1):
            raise ValueError("repair iteration cannot precede accepted history")
        if self.repair_iteration == 0 and self.active_repair_plan is not None:
            raise ValueError("attempt zero cannot have an active RepairPlan")
        if self.repair_iteration > 0:
            if (
                self.active_repair_plan is None
                or self.active_repair_plan.repair_iteration
                != self.repair_iteration
                or len(history) < self.repair_iteration
                or len(validation_history) < self.repair_iteration
                or self.active_repair_plan.previous_candidate_sha256
                != history[self.repair_iteration - 1].candidate_sha256
                or self.active_repair_plan.validation_sha256
                != validation_history[
                    self.repair_iteration - 1
                ].validation_sha256
                or self.active_repair_plan.task_id != self.task.task_id
                or (
                    self.task.report_id is not None
                    and self.active_repair_plan.report_id != self.task.report_id
                )
                or (
                    self.task.entry_id is not None
                    and self.active_repair_plan.entry_id != self.task.entry_id
                )
            ):
                raise ValueError(
                    "active RepairPlan does not match the charged repair attempt"
                )
            if len(history) > self.repair_iteration:
                accepted = history[self.repair_iteration]
                if accepted.repair_plan_sha256 != canonical_sha256(
                    self.active_repair_plan
                ):
                    raise ValueError(
                        "accepted repair does not match the active RepairPlan"
                    )
        if self.status in TERMINAL_STATUSES and (
            not isinstance(self.stop_reason, str) or not self.stop_reason.strip()
        ):
            raise ValueError("terminal states require a stop_reason")
        if self.status in TERMINAL_STATUSES and self.stop_reason not in (
            _TERMINAL_STOP_REASONS[self.status]
        ):
            raise ValueError("stop_reason is incompatible with terminal status")
        if self.status not in TERMINAL_STATUSES and self.stop_reason is not None:
            raise ValueError("non-terminal states cannot have a stop_reason")
        if self.status in TERMINAL_STATUSES:
            if (
                not isinstance(self.termination, TerminationSummary)
                or self.termination.reason != self.stop_reason
                or self.termination.attempt != self.repair_iteration
            ):
                raise ValueError(
                    "terminal state requires a matching termination summary"
                )
        elif self.termination is not None:
            raise ValueError("non-terminal states cannot have termination metadata")
        frozen_budget = _freeze_budget_snapshot(self.budget)
        repair_usage = frozen_budget["usage"]["repair_iterations"]
        if type(repair_usage) is not int or repair_usage != self.repair_iteration:
            raise ValueError(
                "budget repair usage must equal the run repair iteration"
            )
        _assert_repair_budget_events(frozen_budget, self.repair_iteration)
        if self.status in TERMINAL_STATUSES:
            history_count = len(history)
            attempt_count = len(attempts)
            validation_count = len(validation_history)
            initial_failure = (
                self.repair_iteration == 0
                and self.candidate is None
                and history_count == 0
                and attempt_count == 0
                and validation_count == 0
            )
            validated_round = (
                self.candidate is not None
                and history_count == self.repair_iteration + 1
                and attempt_count == history_count
                and validation_count == history_count
            )
            repair_producer_failure = (
                self.repair_iteration > 0
                and self.candidate is not None
                and history_count == self.repair_iteration
                and attempt_count == history_count
                and validation_count == history_count
            )
            validator_failure = (
                self.candidate is not None
                and history_count == self.repair_iteration + 1
                and attempt_count == history_count
                and validation_count == history_count - 1
            )
            rejected_repair = (
                self.repair_iteration > 0
                and self.candidate is not None
                and history_count == self.repair_iteration
                and attempt_count == history_count + 1
                and validation_count == history_count
            )
            initial_deferred = initial_failure and self.deferred_sha256 is not None
            repair_deferred = (
                repair_producer_failure and self.deferred_sha256 is not None
            )

            reason_matches_topology = False
            if self.stop_reason in {
                STOP_VALIDATED_CORRECT,
                STOP_VALIDATION_UNCERTAIN,
                STOP_REPEATED_ERROR,
                STOP_VALIDATION_REGRESSION,
                STOP_NO_REPAIRABLE_FIELDS,
            }:
                reason_matches_topology = validated_round
            elif self.stop_reason == STOP_MAX_REPAIR_ITERATIONS:
                reason_matches_topology = (
                    validated_round
                    and self.repair_iteration == _MAX_REPAIR_ITERATIONS
                )
            elif self.stop_reason in {
                STOP_NO_PROGRESS,
                STOP_LOCKED_FIELD_CHANGED,
            }:
                reason_matches_topology = rejected_repair
            elif self.stop_reason == STOP_PRODUCER_ERROR:
                reason_matches_topology = initial_failure or repair_producer_failure
            elif self.stop_reason == STOP_PRODUCER_DEFERRED:
                reason_matches_topology = initial_deferred or repair_deferred
            elif self.stop_reason == STOP_VALIDATOR_ERROR:
                reason_matches_topology = validator_failure
            elif self.stop_reason == STOP_INVALID_CANDIDATE:
                reason_matches_topology = (
                    initial_failure and not frozen_budget["events"]
                )
            elif self.stop_reason == STOP_SIDECAR_CONFLICT:
                reason_matches_topology = (
                    repair_producer_failure or validator_failure
                )
            elif self.stop_reason == STOP_UNACCOUNTED_TOOL_CALL:
                reason_matches_topology = initial_failure or repair_producer_failure
                reason_matches_topology = (
                    reason_matches_topology
                    and isinstance(self.termination, TerminationSummary)
                    and self.termination.error_sha256
                    == canonical_sha256(_UNACCOUNTED_TOOL_ERROR)
                )
            elif self.stop_reason == STOP_UNACCOUNTED_MODEL_CALL:
                reason_matches_topology = initial_failure or repair_producer_failure
                reason_matches_topology = (
                    reason_matches_topology
                    and isinstance(self.termination, TerminationSummary)
                    and self.termination.error_sha256
                    == canonical_sha256(_UNACCOUNTED_MODEL_ERROR)
                )
            elif self.stop_reason == STOP_BUDGET_EXHAUSTED:
                pre_repair_budget_failure = (
                    validated_round
                    and self.repair_iteration < _MAX_REPAIR_ITERATIONS
                )
                reason_matches_topology = (
                    initial_failure
                    or repair_producer_failure
                    or pre_repair_budget_failure
                )
                termination = self.termination
                if isinstance(termination, TerminationSummary):
                    resource = termination.budget_resource
                    if resource is not None:
                        declared_remaining = (
                            frozen_budget["limits"][f"max_{resource}"]
                            - frozen_budget["usage"][resource]
                        )
                        reason_matches_topology = (
                            reason_matches_topology
                            and termination.budget_remaining
                            == declared_remaining
                        )
                        expected_budget_error = (
                            f"budget exceeded for {resource}: requested "
                            f"{termination.budget_requested}, remaining "
                            f"{termination.budget_remaining}"
                        )
                        reason_matches_topology = (
                            reason_matches_topology
                            and termination.error_sha256
                            == canonical_sha256(expected_budget_error)
                        )
            if not reason_matches_topology:
                raise ValueError(
                    "termination reason does not match retained run topology"
                )
        if attempts:
            pre_repair_events: list[Mapping[str, Any]] = []
            for event in frozen_budget["events"]:
                if event["resource"] == "repair_iterations":
                    break
                pre_repair_events.append(event)
            initial_mode = attempts[0].mode
            if initial_mode == "generated" and not any(
                event["resource"] == "llm_calls"
                for event in pre_repair_events
            ):
                raise ValueError(
                    "generated provenance requires a pre-repair LLM charge"
                )
            if initial_mode == "provided" and pre_repair_events:
                raise ValueError(
                    "provided provenance cannot contain generation charges"
                )
        if self.status in {"finalized", "manual_review"} and (
            self.stop_reason != STOP_PRODUCER_DEFERRED
            or self.candidate is not None
        ):
            if (
                self.candidate_sha256 is None
                or not validation_history
                or validation_history[-1].candidate_sha256
                != self.candidate_sha256
            ):
                raise ValueError(
                    "non-failed terminal state requires a validated current candidate"
                )
        if self.status == "finalized" and (
            self.last_validation is None
            or self.last_validation.verdict != "correct"
        ):
            raise ValueError("finalized state requires a correct T1 validation")
        if self.status == "finalized" and self.candidate is not None and (
            (
                self.task.report_id is not None
                and self.candidate["report_id"] != self.task.report_id
            )
            or (
                self.task.entry_id is not None
                and self.candidate["entry_id"] != self.task.entry_id
            )
        ):
            raise ValueError("finalized candidate does not match trusted task anchors")
        if self.last_validation is not None and (
            self.last_validation.verdict
            != _report_expected_verdict(self.last_validation)
        ):
            raise ValueError("last validation verdict disagrees with its fields")
        object.__setattr__(self, "budget", frozen_budget)

    def to_dict(self) -> dict[str, Any]:
        candidate = (
            None if self.candidate is None else _plain_candidate(self.candidate)
        )
        return {
            "task": {
                "task_id": self.task.task_id,
                "report_id": self.task.report_id,
                "entry_id": self.task.entry_id,
                "inputs_sha256": canonical_sha256(self.task.inputs),
            },
            "status": self.status,
            "repair_iteration": self.repair_iteration,
            "validation_count": self.validation_count,
            "candidate": candidate,
            "candidate_sha256": self.candidate_sha256,
            "last_validation": (
                None
                if self.last_validation is None
                else self.last_validation.to_dict()
            ),
            "active_repair_plan": (
                None
                if self.active_repair_plan is None
                else self.active_repair_plan.to_dict()
            ),
            "budget": {
                "limits": dict(self.budget["limits"]),
                "usage": dict(self.budget["usage"]),
                "events": [
                    {
                        **dict(event),
                        "usage_after": dict(event["usage_after"]),
                    }
                    for event in self.budget["events"]
                ],
            },
            "production_history": [item.to_dict() for item in self.production_history],
            "production_attempts": [item.to_dict() for item in self.production_attempts],
            "validation_history": [item.to_dict() for item in self.validation_history],
            "deferred_sha256": self.deferred_sha256,
            "stop_reason": self.stop_reason,
            "termination": (
                None if self.termination is None else self.termination.to_dict()
            ),
        }


@dataclass(frozen=True, slots=True)
class ClosedLoopOutcome:
    """Final result plus separate producer and validator audit sidecars."""

    status: str
    state: RunState
    entry: Mapping[str, Any] | None = None
    report: ValidationReport | None = None
    production_outcomes: tuple[ProductionOutcome, ...] = ()
    deferred_outcome: ProductionDeferred | None = None
    validation_outcomes: tuple[T1ValidationOutcome, ...] = ()
    repair_plans: tuple[RepairPlan, ...] = ()
    error: str | None = None
    changed_fields: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.status not in TERMINAL_STATUSES or self.status != self.state.status:
            raise ValueError("outcome status must match a terminal RunState")
        if self.entry is not None:
            object.__setattr__(self, "entry", freeze_entry_candidate(self.entry))
        productions = tuple(self.production_outcomes)
        validations = tuple(self.validation_outcomes)
        if any(not isinstance(item, ProductionOutcome) for item in productions):
            raise ValueError("production_outcomes contains an invalid value")
        if any(not isinstance(item, T1ValidationOutcome) for item in validations):
            raise ValueError("validation_outcomes contains an invalid value")
        object.__setattr__(self, "production_outcomes", productions)
        object.__setattr__(self, "validation_outcomes", validations)
        deferred = self.deferred_outcome
        if deferred is not None and not isinstance(deferred, ProductionDeferred):
            raise ValueError("deferred_outcome must be ProductionDeferred or None")
        if (deferred is not None) != (
            self.state.stop_reason == STOP_PRODUCER_DEFERRED
        ):
            raise ValueError(
                "deferred_outcome must occur exactly for producer_deferred"
            )
        if deferred is not None and (
            canonical_sha256(deferred) != self.state.deferred_sha256
        ):
            raise ValueError(
                "deferred sidecar does not match its persisted digest"
            )
        plans = tuple(self.repair_plans)
        if any(not isinstance(plan, RepairPlan) for plan in plans):
            raise ValueError("repair_plans must contain RepairPlan values")
        if len(plans) != self.state.repair_iteration or any(
            plan.repair_iteration != index
            for index, plan in enumerate(plans, start=1)
        ):
            raise ValueError("repair_plans must identify every charged repair")
        object.__setattr__(self, "repair_plans", plans)
        if deferred is not None:
            deferred_attempt = self.state.repair_iteration
            deferred_mode = "generate" if deferred_attempt == 0 else "repair"
            deferred_parent_sha256 = (
                None
                if deferred_attempt == 0
                else canonical_sha256(productions[-1].candidate)
            )
            deferred_plan_sha256 = (
                None
                if deferred_attempt == 0
                else canonical_sha256(plans[-1])
            )
            _assert_deferred_bound(
                self.state.task,
                deferred,
                attempt=deferred_attempt,
                mode=deferred_mode,
                parent_candidate_sha256=deferred_parent_sha256,
                repair_plan_sha256=deferred_plan_sha256,
            )
        if len(validations) != len(self.state.validation_history):
            raise ValueError(
                "validation_outcomes must resolve every validation summary"
            )
        if len(productions) < len(validations):
            raise ValueError(
                "validation outcomes require accepted production sidecars"
            )
        for index, (outcome, summary) in enumerate(
            zip(validations, self.state.validation_history)
        ):
            _assert_t1_outcome_closed(
                productions[index].candidate,
                outcome,
                expected_input_line=_input_line(self.state.task),
            )
            evidence_digest = canonical_sha256(
                [item.to_dict() for item in outcome.evidence]
            )
            if (
                canonical_sha256(outcome.report) != summary.validation_sha256
                or evidence_digest != summary.evidence_sha256
            ):
                raise ValueError(
                    "validation outcome does not match its persisted summary"
                )
        if self.status == "finalized" and any(
            _regressed_fields(before.report, after.report)
            for before, after in zip(validations, validations[1:])
        ):
            raise ValueError("finalized outcome contains a validation regression")
        if plans and (
            self.state.active_repair_plan is None
            or canonical_sha256(plans[-1])
            != canonical_sha256(self.state.active_repair_plan)
        ):
            raise ValueError("active RepairPlan must be the latest repair plan")
        for index, plan in enumerate(plans, start=1):
            if index > len(productions) or index > len(validations):
                raise ValueError("RepairPlan has no replayable parent round")
            parent = productions[index - 1].candidate
            prior_validation = validations[index - 1].report
            expected_plan = build_repair_plan(
                task=self.state.task,
                previous_candidate=parent,
                validation=prior_validation,
                repair_iteration=index,
            )
            if canonical_sha256(plan) != canonical_sha256(expected_plan):
                raise ValueError("RepairPlan is not bound to its parent round")
            if index < len(productions):
                returned_candidate = productions[index].candidate
                disposition = self.state.production_attempts[index].disposition
                locked_changes = plan.locked_field_changes(returned_candidate)
                no_progress = canonical_sha256(
                    returned_candidate
                ) == canonical_sha256(parent)
                if disposition == "accepted" and (
                    locked_changes or no_progress
                ):
                    raise ValueError("accepted repair violates its RepairPlan")
                if disposition == "rejected_locked_fields" and not locked_changes:
                    raise ValueError(
                        "locked-field rejection has no locked field change"
                    )
                if disposition == "rejected_no_progress" and not no_progress:
                    raise ValueError(
                        "no-progress rejection changed the candidate"
                    )
        for production in self.state.production_history[1:]:
            plan = plans[production.attempt - 1]
            if canonical_sha256(plan) != production.repair_plan_sha256:
                raise ValueError(
                    "production history references an unresolved RepairPlan"
                )
        if (self.entry is None) != (self.state.candidate is None) or (
            self.entry is not None
            and canonical_sha256(self.entry) != self.state.candidate_sha256
        ):
            raise ValueError("outcome entry must match RunState candidate")
        if (self.report is None) != (self.state.last_validation is None) or (
            self.report is not None
            and canonical_sha256(self.report)
            != canonical_sha256(self.state.last_validation)
        ):
            raise ValueError("outcome report must match RunState validation")
        expected_error_digest = (
            None if self.error is None else canonical_sha256(self.error)
        )
        if self.state.termination.error_sha256 != expected_error_digest:
            raise ValueError("outcome error does not match termination summary")
        if len(productions) != len(self.state.production_attempts) or any(
            outcome.candidate_sha256 != attempt.candidate_sha256
            or canonical_sha256(outcome) != attempt.outcome_sha256
            for outcome, attempt in zip(
                productions, self.state.production_attempts
            )
        ):
            raise ValueError("production sidecars do not match attempt summaries")
        producer_results: tuple[ProducerResult, ...] = (
            productions
            if deferred is None
            else (*productions, deferred)
        )
        tool_ids: set[str] = set()
        model_ids: set[str] = set()
        evidence_payloads: dict[str, str] = {}
        for production in producer_results:
            for tool_call in production.tool_calls:
                if tool_call.tool_call_id in tool_ids:
                    raise ValueError("tool call IDs must be globally unique")
                tool_ids.add(tool_call.tool_call_id)
            for model_call in production.model_calls:
                if model_call.model_call_id in model_ids:
                    raise ValueError("model call IDs must be globally unique")
                model_ids.add(model_call.model_call_id)
            for evidence in production.evidence:
                digest = canonical_sha256(evidence)
                prior = evidence_payloads.get(evidence.evidence_id)
                if prior is not None and prior != digest:
                    raise ValueError("producer evidence ID has conflicting payloads")
                evidence_payloads[evidence.evidence_id] = digest
        for validation in validations:
            for evidence in validation.evidence:
                digest = canonical_sha256(evidence)
                prior = evidence_payloads.get(evidence.evidence_id)
                if prior is not None and prior != digest:
                    raise ValueError("T1 evidence ID conflicts with producer evidence")
                evidence_payloads[evidence.evidence_id] = digest
        event_by_sequence = {
            event["sequence"]: event for event in self.state.budget["events"]
        }
        _assert_repair_budget_events(
            self.state.budget, self.state.repair_iteration
        )
        claimed_tool_sequences: set[int] = set()
        claimed_model_sequences: set[int] = set()
        claimed_all_sequences: set[int] = set()
        for expected_attempt, producer_result in enumerate(producer_results):
            expected_scope = _policy_scope_for_attempt(expected_attempt)
            for records in (
                producer_result.tool_calls,
                producer_result.model_calls,
            ):
                record_sequences = tuple(
                    item.budget_event_sequence for item in records
                )
                if record_sequences != tuple(sorted(record_sequences)):
                    raise ValueError(
                        "producer call sidecars must follow budget-event order"
                    )
            for record, resource, claimed in (
                *(
                    (item, "tool_calls", claimed_tool_sequences)
                    for item in producer_result.tool_calls
                ),
                *(
                    (item, "llm_calls", claimed_model_sequences)
                    for item in producer_result.model_calls
                ),
            ):
                if (
                    record.task_id != self.state.task.task_id
                    or record.attempt != expected_attempt
                    or record.policy_scope != expected_scope
                    or record.budget_event_sequence in claimed_all_sequences
                ):
                    raise ValueError(
                        "producer call sidecar identity/scope is not replayable"
                    )
                event = event_by_sequence.get(record.budget_event_sequence)
                if (
                    event is None
                    or event["resource"] != resource
                    or event["amount"] != 1
                    or event.get("operation") != record.operation
                ):
                    raise ValueError(
                        "producer call sidecar does not bind its budget event"
                    )
                claimed.add(record.budget_event_sequence)
                claimed_all_sequences.add(record.budget_event_sequence)

        budget_tool_sequences = {
            event["sequence"]
            for event in self.state.budget["events"]
            if event["resource"] == "tool_calls"
        }
        budget_model_sequences = {
            event["sequence"]
            for event in self.state.budget["events"]
            if event["resource"] == "llm_calls"
        }
        incomplete_ledger_allowed = self.state.stop_reason in {
            STOP_UNACCOUNTED_TOOL_CALL,
            STOP_UNACCOUNTED_MODEL_CALL,
            STOP_PRODUCER_ERROR,
            STOP_SIDECAR_CONFLICT,
            STOP_BUDGET_EXHAUSTED,
        }
        if (
            claimed_tool_sequences != budget_tool_sequences
            and not incomplete_ledger_allowed
        ):
            raise ValueError("tool-call sidecars do not close the budget ledger")
        if (
            claimed_model_sequences != budget_model_sequences
            and not incomplete_ledger_allowed
        ):
            raise ValueError("model-call sidecars do not close the budget ledger")
        replayed_changes: list[str] = []
        for index, attempt in enumerate(self.state.production_attempts[1:], start=1):
            parent = productions[index - 1].candidate
            returned = productions[index].candidate
            if attempt.disposition == "accepted":
                replayed_changes.extend(_changed_fields(parent, returned))
            elif attempt.disposition == "rejected_locked_fields":
                replayed_changes.extend(
                    plans[index - 1].locked_field_changes(returned)
                )
        expected_changes = tuple(dict.fromkeys(replayed_changes))
        if tuple(self.changed_fields) != expected_changes:
            raise ValueError("changed_fields does not match replayed attempts")
        object.__setattr__(self, "changed_fields", expected_changes)


class ClosedLoopOrchestrator:
    """Run one candidate through T1 and at most two narrow T2 repairs."""

    def __init__(
        self,
        producer: "T2Producer",
        validator_factory: ValidatorFactory,
        *,
        limits: Limits | Mapping[str, Any] | None = None,
    ) -> None:
        if not callable(validator_factory):
            raise ValueError("validator_factory must be callable")
        self._producer = producer
        self._validator_factory = validator_factory
        self._limits = (
            limits
            if isinstance(limits, Limits)
            else Limits.from_dict(limits)
            if isinstance(limits, Mapping)
            else Limits()
        )

    def run(
        self,
        task: RunTask,
        *,
        initial_candidate: Mapping[str, Any] | ProductionOutcome | None = None,
        budget: Budget | None = None,
    ) -> ClosedLoopOutcome:
        if not isinstance(task, RunTask):
            raise ValueError("task must be a RunTask")
        run_budget = budget if budget is not None else Budget(self._limits)
        if not isinstance(run_budget, Budget):
            raise ValueError("budget must be a Budget or None")
        if run_budget.events:
            raise ValueError(
                "budget must be fresh for one run; shared or resumed ledgers "
                "require an explicit replay contract"
            )

        productions: list[ProductionOutcome] = []
        validations: list[T1ValidationOutcome] = []
        validation_history: list[ValidationSummary] = []
        repair_plans: list[RepairPlan] = []
        history: list[ProductionSummary] = []
        attempts: list[ProductionAttemptSummary] = []
        seen_evidence: dict[str, Mapping[str, Any]] = {}
        seen_tool_calls: dict[str, Mapping[str, Any]] = {}
        seen_model_calls: dict[str, Mapping[str, Any]] = {}
        candidate: Mapping[str, Any] | None = None
        report: ValidationReport | None = None
        deferred: ProductionDeferred | None = None
        active_plan: RepairPlan | None = None
        repair_iteration = 0
        all_changed: list[str] = []

        def finish(
            status: str,
            reason: str,
            *,
            error: str | None = None,
            budget_error: BudgetExceeded | None = None,
        ) -> ClosedLoopOutcome:
            state = RunState(
                task=task,
                status=status,
                repair_iteration=repair_iteration,
                validation_count=len(validations),
                candidate=candidate,
                candidate_sha256=(
                    None if candidate is None else canonical_sha256(candidate)
                ),
                last_validation=report,
                active_repair_plan=active_plan,
                budget=run_budget.to_dict(),
                production_history=tuple(history),
                production_attempts=tuple(attempts),
                validation_history=tuple(validation_history),
                deferred_sha256=(
                    None if deferred is None else canonical_sha256(deferred)
                ),
                stop_reason=reason,
                termination=TerminationSummary(
                    reason=reason,
                    phase=_STOP_REASON_PHASES[reason],
                    attempt=repair_iteration,
                    error_sha256=(
                        None if error is None else canonical_sha256(error)
                    ),
                    budget_resource=(
                        None if budget_error is None else budget_error.resource
                    ),
                    budget_requested=(
                        None if budget_error is None else budget_error.requested
                    ),
                    budget_remaining=(
                        None if budget_error is None else budget_error.remaining
                    ),
                ),
            )
            return ClosedLoopOutcome(
                status=status,
                state=state,
                entry=candidate,
                report=report,
                production_outcomes=tuple(productions),
                deferred_outcome=deferred,
                validation_outcomes=tuple(validations),
                repair_plans=tuple(repair_plans),
                error=error,
                changed_fields=tuple(dict.fromkeys(all_changed)),
            )

        try:
            if initial_candidate is None:
                before_event_count = len(run_budget.events)
                produced = self._producer.generate(task, run_budget)
                if not isinstance(
                    produced, (ProductionOutcome, ProductionDeferred)
                ):
                    raise ValueError(
                        "producer.generate must return a ProducerResult"
                    )
                accounting_error = _accounting_error(
                    produced,
                    task=task,
                    attempt=0,
                    before_event_count=before_event_count,
                    budget=run_budget,
                )
                if accounting_error is not None:
                    return finish(
                        "failed",
                        accounting_error[0],
                        error=accounting_error[1],
                    )
                if (
                    isinstance(produced, ProductionOutcome)
                    and not produced.model_calls
                ):
                    raise ValueError(
                        "producer.generate must charge at least one LLM call"
                    )
            elif isinstance(initial_candidate, ProductionOutcome):
                if initial_candidate.tool_calls or initial_candidate.model_calls:
                    raise ValueError(
                        "a provided ProductionOutcome cannot import calls without "
                        "an external budget ledger"
                    )
                produced = initial_candidate
            else:
                produced = ProductionOutcome(candidate=initial_candidate)
        except BudgetExceeded as error:
            return finish(
                "failed",
                STOP_BUDGET_EXHAUSTED,
                error=str(error),
                budget_error=error,
            )
        except Exception as error:
            reason = (
                STOP_PRODUCER_ERROR
                if initial_candidate is None
                else STOP_INVALID_CANDIDATE
            )
            return finish("failed", reason, error=str(error))

        if isinstance(produced, ProductionDeferred):
            try:
                _assert_deferred_bound(
                    task,
                    produced,
                    attempt=0,
                    mode="generate",
                )
            except Exception as error:
                return finish("failed", STOP_PRODUCER_ERROR, error=str(error))
            conflict = self._sidecar_conflict(
                produced,
                seen_evidence,
                seen_tool_calls,
                seen_model_calls,
            )
            if conflict is not None:
                return finish("failed", STOP_SIDECAR_CONFLICT, error=conflict)
            deferred = produced
            return finish("manual_review", STOP_PRODUCER_DEFERRED)

        conflict = self._sidecar_conflict(
            produced,
            seen_evidence,
            seen_tool_calls,
            seen_model_calls,
        )
        if conflict is not None:
            return finish("failed", STOP_SIDECAR_CONFLICT, error=conflict)
        productions.append(produced)
        candidate = freeze_entry_candidate(produced.candidate)
        initial_mode = "generated" if initial_candidate is None else "provided"
        initial_summary = ProductionSummary(
            attempt=0,
            mode=initial_mode,
            candidate_sha256=produced.candidate_sha256,
        )
        history.append(initial_summary)
        attempts.append(
            ProductionAttemptSummary(
                attempt=0,
                mode=initial_mode,
                candidate_sha256=produced.candidate_sha256,
                outcome_sha256=canonical_sha256(produced),
                disposition="accepted",
            )
        )

        validation_error = self._validate_once(task, candidate)
        if isinstance(validation_error, Exception):
            return finish("failed", STOP_VALIDATOR_ERROR, error=str(validation_error))
        outcome = validation_error
        conflict = self._validation_evidence_conflict(outcome, seen_evidence)
        if conflict is not None:
            return finish("failed", STOP_SIDECAR_CONFLICT, error=conflict)
        validations.append(outcome)
        validation_history.append(
            ValidationSummary(
                attempt=history[-1].attempt,
                candidate_sha256=canonical_sha256(candidate),
                validation_sha256=canonical_sha256(outcome.report),
                evidence_sha256=canonical_sha256(
                    [item.to_dict() for item in outcome.evidence]
                ),
            )
        )
        report = outcome.report

        seen_error_signatures = {_error_signature(report)}
        while True:
            if report.verdict == "correct":
                return finish("finalized", STOP_VALIDATED_CORRECT)
            incorrect_fields = _incorrect_official_fields(report)
            if not incorrect_fields:
                reason = (
                    STOP_NO_REPAIRABLE_FIELDS
                    if report.verdict == "incorrect"
                    else STOP_VALIDATION_UNCERTAIN
                )
                return finish("manual_review", reason)
            if repair_iteration >= _MAX_REPAIR_ITERATIONS:
                return finish("manual_review", STOP_MAX_REPAIR_ITERATIONS)

            next_iteration = repair_iteration + 1
            try:
                next_plan = build_repair_plan(
                    task=task,
                    previous_candidate=candidate,
                    validation=report,
                    repair_iteration=next_iteration,
                )
            except Exception as error:
                return finish(
                    "manual_review", STOP_NO_REPAIRABLE_FIELDS, error=str(error)
                )

            parent = candidate
            parent_digest = canonical_sha256(parent)
            prior_report = report
            try:
                run_budget.charge_repair_iteration(
                    operation=f"repair:{next_iteration}"
                )
                # An attempted repair counts even when the producer later
                # fails; the append-only budget charge and state stay aligned.
                repair_iteration = next_iteration
                active_plan = next_plan
                repair_plans.append(active_plan)
                before_event_count = len(run_budget.events)
                repaired = self._producer.repair(
                    task,
                    _plain_candidate(parent),
                    active_plan,
                    run_budget,
                )
                if not isinstance(
                    repaired, (ProductionOutcome, ProductionDeferred)
                ):
                    raise ValueError("producer.repair must return a ProducerResult")
                accounting_error = _accounting_error(
                    repaired,
                    task=task,
                    attempt=repair_iteration,
                    before_event_count=before_event_count,
                    budget=run_budget,
                )
                if accounting_error is not None:
                    return finish(
                        "failed",
                        accounting_error[0],
                        error=accounting_error[1],
                    )
            except BudgetExceeded as error:
                return finish(
                    "manual_review",
                    STOP_BUDGET_EXHAUSTED,
                    error=str(error),
                    budget_error=error,
                )
            except Exception as error:
                return finish("failed", STOP_PRODUCER_ERROR, error=str(error))

            if isinstance(repaired, ProductionDeferred):
                try:
                    _assert_deferred_bound(
                        task,
                        repaired,
                        attempt=repair_iteration,
                        mode="repair",
                        parent_candidate_sha256=parent_digest,
                        repair_plan_sha256=canonical_sha256(active_plan),
                    )
                except Exception as error:
                    return finish("failed", STOP_PRODUCER_ERROR, error=str(error))
                conflict = self._sidecar_conflict(
                    repaired,
                    seen_evidence,
                    seen_tool_calls,
                    seen_model_calls,
                )
                if conflict is not None:
                    return finish("failed", STOP_SIDECAR_CONFLICT, error=conflict)
                deferred = repaired
                return finish("manual_review", STOP_PRODUCER_DEFERRED)

            conflict = self._sidecar_conflict(
                repaired,
                seen_evidence,
                seen_tool_calls,
                seen_model_calls,
            )
            if conflict is not None:
                return finish("failed", STOP_SIDECAR_CONFLICT, error=conflict)
            productions.append(repaired)
            proposed = freeze_entry_candidate(repaired.candidate)
            proposed_digest = canonical_sha256(proposed)
            proposed_summary = ProductionSummary(
                attempt=repair_iteration,
                mode="repair",
                candidate_sha256=proposed_digest,
                parent_candidate_sha256=parent_digest,
                repair_plan_sha256=canonical_sha256(active_plan),
            )

            locked_changes = active_plan.locked_field_changes(proposed)
            if locked_changes:
                attempts.append(
                    ProductionAttemptSummary(
                        **proposed_summary.to_dict(),
                        outcome_sha256=canonical_sha256(repaired),
                        disposition="rejected_locked_fields",
                    )
                )
                all_changed.extend(locked_changes)
                return finish(
                    "manual_review",
                    STOP_LOCKED_FIELD_CHANGED,
                    error=f"repair changed locked fields: {list(locked_changes)}",
                )
            if proposed_digest == parent_digest:
                attempts.append(
                    ProductionAttemptSummary(
                        **proposed_summary.to_dict(),
                        outcome_sha256=canonical_sha256(repaired),
                        disposition="rejected_no_progress",
                    )
                )
                return finish("manual_review", STOP_NO_PROGRESS)

            # production_history is the accepted candidate lineage. Rejected
            # producer outcomes remain available in production_outcomes.
            attempts.append(
                ProductionAttemptSummary(
                    **proposed_summary.to_dict(),
                    outcome_sha256=canonical_sha256(repaired),
                    disposition="accepted",
                )
            )
            history.append(proposed_summary)
            changed = _changed_fields(parent, proposed)
            all_changed.extend(changed)
            candidate = proposed
            validation_error = self._validate_once(task, candidate)
            if isinstance(validation_error, Exception):
                return finish(
                    "failed", STOP_VALIDATOR_ERROR, error=str(validation_error)
                )
            outcome = validation_error
            conflict = self._validation_evidence_conflict(outcome, seen_evidence)
            if conflict is not None:
                return finish("failed", STOP_SIDECAR_CONFLICT, error=conflict)
            validations.append(outcome)
            validation_history.append(
                ValidationSummary(
                    attempt=history[-1].attempt,
                    candidate_sha256=canonical_sha256(candidate),
                    validation_sha256=canonical_sha256(outcome.report),
                    evidence_sha256=canonical_sha256(
                        [item.to_dict() for item in outcome.evidence]
                    ),
                )
            )
            report = outcome.report

            regressions = _regressed_fields(prior_report, report)
            if regressions:
                return finish(
                    "manual_review",
                    STOP_VALIDATION_REGRESSION,
                    error=f"previously correct fields regressed: {list(regressions)}",
                )
            if report.verdict == "correct":
                return finish("finalized", STOP_VALIDATED_CORRECT)
            if not _incorrect_official_fields(report):
                reason = (
                    STOP_NO_REPAIRABLE_FIELDS
                    if report.verdict == "incorrect"
                    else STOP_VALIDATION_UNCERTAIN
                )
                return finish("manual_review", reason)
            current_signature = _error_signature(report)
            if current_signature in seen_error_signatures:
                return finish("manual_review", STOP_REPEATED_ERROR)
            seen_error_signatures.add(current_signature)
            if repair_iteration >= _MAX_REPAIR_ITERATIONS:
                return finish("manual_review", STOP_MAX_REPAIR_ITERATIONS)

    def _validate_once(
        self, task: RunTask, candidate: Mapping[str, Any]
    ) -> T1ValidationOutcome | Exception:
        try:
            validator = self._validator_factory(task)
            if validator is None or not callable(getattr(validator, "validate", None)):
                raise ValueError("validator_factory must return a validator")
            outcome = validator.validate(
                _plain_candidate(candidate), input_line=_input_line(task)
            )
            if not isinstance(outcome, T1ValidationOutcome):
                raise ValueError("validator must return T1ValidationOutcome")
            if outcome.report.verdict != _report_expected_verdict(outcome.report):
                raise ValueError("validator report verdict disagrees with its fields")
            outcome = _apply_task_identity_gate(task, candidate, outcome)
            _assert_t1_outcome_closed(
                candidate,
                outcome,
                expected_input_line=_input_line(task),
            )
            return outcome
        except Exception as error:
            return error

    @staticmethod
    def _sidecar_conflict(
        outcome: ProducerResult,
        seen_evidence: dict[str, Mapping[str, Any]],
        seen_tool_calls: dict[str, Mapping[str, Any]],
        seen_model_calls: dict[str, Mapping[str, Any]],
    ) -> str | None:
        for item in outcome.evidence:
            value = item.to_dict()
            prior = seen_evidence.get(item.evidence_id)
            if prior is not None and canonical_sha256(prior) != canonical_sha256(value):
                return f"evidence ID {item.evidence_id} has conflicting payloads"
            seen_evidence[item.evidence_id] = value
        for item in outcome.tool_calls:
            value = item.to_dict()
            prior = seen_tool_calls.get(item.tool_call_id)
            if prior is not None:
                return f"tool call ID {item.tool_call_id} is reused across attempts"
            seen_tool_calls[item.tool_call_id] = value
        for item in outcome.model_calls:
            value = item.to_dict()
            prior = seen_model_calls.get(item.model_call_id)
            if prior is not None:
                return f"model call ID {item.model_call_id} is reused across attempts"
            seen_model_calls[item.model_call_id] = value
        return None

    @staticmethod
    def _validation_evidence_conflict(
        outcome: T1ValidationOutcome,
        seen_evidence: dict[str, Mapping[str, Any]],
    ) -> str | None:
        for item in outcome.evidence:
            value = item.to_dict()
            prior = seen_evidence.get(item.evidence_id)
            if prior is not None and canonical_sha256(prior) != canonical_sha256(value):
                return (
                    f"evidence ID {item.evidence_id} conflicts between T1 and "
                    "an earlier sidecar"
                )
            seen_evidence[item.evidence_id] = value
        return None


__all__ = [
    "CandidateValidator",
    "ClosedLoopOrchestrator",
    "ClosedLoopOutcome",
    "ProductionSummary",
    "ProductionAttemptSummary",
    "RUN_STATUSES",
    "RunState",
    "ValidationSummary",
    "TerminationSummary",
    "STOP_BUDGET_EXHAUSTED",
    "STOP_INVALID_CANDIDATE",
    "STOP_LOCKED_FIELD_CHANGED",
    "STOP_MAX_REPAIR_ITERATIONS",
    "STOP_NO_PROGRESS",
    "STOP_NO_REPAIRABLE_FIELDS",
    "STOP_PRODUCER_DEFERRED",
    "STOP_PRODUCER_ERROR",
    "STOP_REPEATED_ERROR",
    "STOP_SIDECAR_CONFLICT",
    "STOP_UNACCOUNTED_TOOL_CALL",
    "STOP_UNACCOUNTED_MODEL_CALL",
    "STOP_VALIDATED_CORRECT",
    "STOP_VALIDATION_REGRESSION",
    "STOP_VALIDATION_UNCERTAIN",
    "STOP_VALIDATOR_ERROR",
    "TERMINAL_STATUSES",
    "ValidatorFactory",
]
