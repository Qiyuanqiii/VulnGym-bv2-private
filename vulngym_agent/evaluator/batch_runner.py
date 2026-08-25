"""Deterministic E4 batch scheduling over the sole Linux OCI provider.

The scheduler is deliberately serial and single-attempt.  A provider failure
may be isolated only when it belongs to the fixed clean-failure allowlist and
the pinned runtime is freshly reverified after cleanup.  Every other failure
poisons the batch and stops dispatch.  Official result publication adds an E4
success receipt to the existing all-success supervisor transaction; partial
attempts produce a separate, non-publishable canonical report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
import re
from typing import Callable, Final

from vulngym_agent.evaluator.contracts import (
    DiscoveryBatchExecutionPlanV2,
    EvaluatorContractError,
    _embedded_sha256_from_canonical_wire,
)
from vulngym_agent.evaluator.e4_receipt import (
    E4_SCHEDULER_VERSION,
    E4BatchSuccessReceiptV2,
    E4ReceiptError,
    E4TaskSuccessClosureV1,
    _issue_e4_success_receipt_authority_v2,
)
from vulngym_agent.evaluator.linux_oci import (
    LinuxOciProviderError,
    VerifiedLinuxOciRuntimeV1,
    reverify_linux_oci_runtime_v1,
    run_discovery_worker_linux_oci_v1,
)
from vulngym_agent.evaluator.supervisor import (
    DiscoveryExecutionSession,
    EvaluatorSupervisorError,
    accept_discovery_worker_output_v1,
    close_failed_discovery_execution_v1,
    _publish_scheduled_postverified_discovery_execution_v1,
    postverify_discovery_execution_v1,
)
from vulngym_agent.evaluator.worker_completion import CompletedWorkerExecutionV1


E4_BATCH_RUNNER_VERSION: Final[str] = E4_SCHEDULER_VERSION
TASK_ATTEMPT_OUTCOME_KIND: Final[str] = "vulngym.discovery-task-attempt-outcome.v1"
BATCH_ATTEMPT_REPORT_KIND: Final[str] = "vulngym.discovery-batch-attempt-report.v2"
TASK_ATTEMPT_OUTCOME_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym discovery task attempt outcome v1\0"
)
BATCH_ATTEMPT_REPORT_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym discovery batch attempt report v2\0"
)
BATCH_ATTEMPT_REPORT_MAX_BYTES: Final[int] = 8 * 1024 * 1024
BATCH_ATTEMPT_REPORT_MAX_JSON_NODES: Final[int] = 250_000
BATCH_ATTEMPT_REPORT_MAX_JSON_DEPTH: Final[int] = 20

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_FAILURE_CODE_RE: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_SPLIT_COUNTS: Final[dict[str, int]] = {"train": 50, "test": 20}
_CLEAN_TASK_FAILURE_CODES: Final[frozenset[str]] = frozenset(
    {"evidence_failed", "generation_failed", "invalid_output", "worker_failed"}
)

_Provider = Callable[..., CompletedWorkerExecutionV1]
_RuntimeReverifier = Callable[[VerifiedLinuxOciRuntimeV1], None]


class BatchRunnerError(RuntimeError):
    """Stable, path-free failure in the trusted E4 scheduler."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "batch_runner_failed"
        super().__init__(message)


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise BatchRunnerError(
            "invalid_contract", "batch attempt value is not canonical JSON"
        ) from None


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise BatchRunnerError("invalid_contract", f"{name} is invalid")
    return value


def _strict_object(
    value: object, *, keys: frozenset[str], name: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise BatchRunnerError("invalid_contract", f"{name} has invalid exact keys")
    return value


def _validate_json_shape(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if (
            count > BATCH_ATTEMPT_REPORT_MAX_JSON_NODES
            or depth > BATCH_ATTEMPT_REPORT_MAX_JSON_DEPTH
        ):
            raise BatchRunnerError(
                "limit_exceeded", "batch attempt JSON exceeds its shape limit"
            )
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in {str, int, bool}:
            raise BatchRunnerError(
                "invalid_contract", "batch attempt JSON contains an invalid value"
            )


def _parse_canonical_line(payload: bytes) -> dict[str, object]:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > BATCH_ATTEMPT_REPORT_MAX_BYTES
        or not payload.endswith(b"\n")
        or payload.endswith(b"\n\n")
    ):
        raise BatchRunnerError("invalid_contract", "batch attempt wire is invalid")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")),
            object_pairs_hook=unique_object,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise BatchRunnerError("invalid_contract", "batch attempt wire is invalid") from None
    _validate_json_shape(value)
    if type(value) is not dict or _canonical_json(value) + b"\n" != payload:
        raise BatchRunnerError("noncanonical_json", "batch attempt wire is not canonical")
    return value


@dataclass(frozen=True, slots=True)
class TaskAttemptOutcomeV1:
    """One ordered scheduler outcome; never an official publication receipt."""

    task_plan_sha256: str
    task_id: str
    status: str
    run_sha256: str | None = None
    run_wire_sha256: str | None = None
    discovery_result_sha256: str | None = None
    runtime_evidence_sha256: str | None = None
    failure_code: str | None = None
    cleanup_complete: bool = False
    runtime_reverified: bool = False
    contract_version: int = 1
    kind: str = TASK_ATTEMPT_OUTCOME_KIND
    outcome_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _require_sha256(self.task_plan_sha256, name="task_plan_sha256")
        if (
            type(self.contract_version) is not int
            or self.contract_version != 1
            or type(self.kind) is not str
            or self.kind != TASK_ATTEMPT_OUTCOME_KIND
            or type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.status) is not str
            or self.status not in {"succeeded", "failed", "not_run"}
            or type(self.cleanup_complete) is not bool
            or type(self.runtime_reverified) is not bool
        ):
            raise BatchRunnerError("invalid_contract", "task attempt identity is invalid")
        success_hashes = (
            self.run_sha256,
            self.run_wire_sha256,
            self.discovery_result_sha256,
            self.runtime_evidence_sha256,
        )
        if self.status == "succeeded":
            for value, name in zip(
                success_hashes,
                (
                    "run_sha256",
                    "run_wire_sha256",
                    "discovery_result_sha256",
                    "runtime_evidence_sha256",
                ),
                strict=True,
            ):
                _require_sha256(value, name=name)
            if (
                self.failure_code is not None
                or not self.cleanup_complete
                or not self.runtime_reverified
            ):
                raise BatchRunnerError(
                    "invalid_contract", "successful task attempt is not cleanly closed"
                )
        elif self.status == "failed":
            if (
                any(value is not None for value in success_hashes)
                or type(self.failure_code) is not str
                or _FAILURE_CODE_RE.fullmatch(self.failure_code) is None
                or self.runtime_reverified
                and not self.cleanup_complete
            ):
                raise BatchRunnerError(
                    "invalid_contract", "failed task attempt union is invalid"
                )
        elif (
            any(value is not None for value in success_hashes)
            or self.failure_code is not None
            or self.cleanup_complete
            or self.runtime_reverified
        ):
            raise BatchRunnerError(
                "invalid_contract", "not-run task attempt union is invalid"
            )
        object.__setattr__(
            self,
            "outcome_sha256",
            hashlib.sha256(
                TASK_ATTEMPT_OUTCOME_DIGEST_DOMAIN + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "cleanup_complete": self.cleanup_complete,
            "contract_version": self.contract_version,
            "discovery_result_sha256": self.discovery_result_sha256,
            "failure_code": self.failure_code,
            "kind": self.kind,
            "run_sha256": self.run_sha256,
            "run_wire_sha256": self.run_wire_sha256,
            "runtime_evidence_sha256": self.runtime_evidence_sha256,
            "runtime_reverified": self.runtime_reverified,
            "status": self.status,
            "task_id": self.task_id,
            "task_plan_sha256": self.task_plan_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            TASK_ATTEMPT_OUTCOME_DIGEST_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.outcome_sha256 != expected:
            raise BatchRunnerError("invalid_binding", "task attempt digest changed")
        return {**self._core_dict(), "outcome_sha256": self.outcome_sha256}

    @classmethod
    def from_dict(cls, value: object) -> "TaskAttemptOutcomeV1":
        raw = _strict_object(
            value,
            keys=frozenset(
                {
                    "cleanup_complete",
                    "contract_version",
                    "discovery_result_sha256",
                    "failure_code",
                    "kind",
                    "outcome_sha256",
                    "run_sha256",
                    "run_wire_sha256",
                    "runtime_evidence_sha256",
                    "runtime_reverified",
                    "status",
                    "task_id",
                    "task_plan_sha256",
                }
            ),
            name="task attempt outcome",
        )
        expected = _require_sha256(raw["outcome_sha256"], name="outcome_sha256")
        result = cls(
            task_plan_sha256=raw["task_plan_sha256"],
            task_id=raw["task_id"],
            status=raw["status"],
            run_sha256=raw["run_sha256"],
            run_wire_sha256=raw["run_wire_sha256"],
            discovery_result_sha256=raw["discovery_result_sha256"],
            runtime_evidence_sha256=raw["runtime_evidence_sha256"],
            failure_code=raw["failure_code"],
            cleanup_complete=raw["cleanup_complete"],
            runtime_reverified=raw["runtime_reverified"],
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if result.outcome_sha256 != expected:
            raise BatchRunnerError("digest_mismatch", "task attempt digest differs")
        return result


@dataclass(frozen=True, slots=True)
class DiscoveryBatchAttemptReportV2:
    """Canonical non-publishable closure for a failed E4 batch attempt."""

    plan: DiscoveryBatchExecutionPlanV2
    status: str
    snapshot_reverified: bool
    outcomes: tuple[TaskAttemptOutcomeV1, ...]
    contract_version: int = 2
    kind: str = BATCH_ATTEMPT_REPORT_KIND
    scheduler_version: str = E4_BATCH_RUNNER_VERSION
    max_parallelism: int = 1
    max_attempts: int = 1
    report_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.plan) is not DiscoveryBatchExecutionPlanV2
            or type(self.status) is not str
            or self.status not in {"failed_clean", "runtime_poisoned", "closure_failed"}
            or type(self.snapshot_reverified) is not bool
            or type(self.outcomes) is not tuple
            or type(self.contract_version) is not int
            or self.contract_version != 2
            or type(self.kind) is not str
            or self.kind != BATCH_ATTEMPT_REPORT_KIND
            or type(self.scheduler_version) is not str
            or self.scheduler_version != E4_BATCH_RUNNER_VERSION
            or type(self.max_parallelism) is not int
            or self.max_parallelism != 1
            or type(self.max_attempts) is not int
            or self.max_attempts != 1
        ):
            raise BatchRunnerError("invalid_contract", "batch attempt root is invalid")
        plan_wire = self.plan.to_bytes()
        try:
            plan = DiscoveryBatchExecutionPlanV2.from_bytes(
                plan_wire,
                expected_plan_sha256=_embedded_sha256_from_canonical_wire(
                    plan_wire, field="plan_sha256"
                ),
                expected_wire_sha256=hashlib.sha256(plan_wire).hexdigest(),
            )
        except (EvaluatorContractError, TypeError, ValueError):
            raise BatchRunnerError("invalid_binding", "batch attempt plan is invalid") from None
        outcomes = tuple(self.outcomes)
        if (
            len(outcomes) != len(plan.tasks)
            or len(outcomes) != _SPLIT_COUNTS.get(plan.batch.split)
            or any(type(item) is not TaskAttemptOutcomeV1 for item in outcomes)
        ):
            raise BatchRunnerError(
                "invalid_binding", "batch attempt does not cover the exact split"
            )
        for task_plan, outcome in zip(plan.tasks, outcomes, strict=True):
            if (
                outcome.task_id != task_plan.task_id
                or outcome.task_plan_sha256 != task_plan.plan_sha256
            ):
                raise BatchRunnerError(
                    "invalid_binding", "batch attempt order differs from the plan"
                )
        failed = tuple(item for item in outcomes if item.status == "failed")
        not_run = tuple(item for item in outcomes if item.status == "not_run")
        if not failed:
            raise BatchRunnerError("invalid_binding", "batch attempt has no failure")
        clean_failures = tuple(
            item
            for item in failed
            if item.cleanup_complete and item.runtime_reverified
        )
        if any(
            item.failure_code not in _CLEAN_TASK_FAILURE_CODES
            for item in clean_failures
        ):
            raise BatchRunnerError(
                "invalid_binding", "clean task failure is outside the fixed allowlist"
            )
        if self.status == "failed_clean":
            if (
                not self.snapshot_reverified
                or not_run
                or any(
                    not item.cleanup_complete or not item.runtime_reverified
                    for item in failed
                )
            ):
                raise BatchRunnerError(
                    "invalid_binding", "clean failed attempt did not fully close"
                )
        elif self.status == "runtime_poisoned":
            unsafe_positions = tuple(
                index
                for index, item in enumerate(outcomes)
                if item.status == "failed"
                and (not item.cleanup_complete or not item.runtime_reverified)
            )
            if self.snapshot_reverified or not unsafe_positions:
                raise BatchRunnerError(
                    "invalid_binding", "poisoned attempt does not identify runtime uncertainty"
                )
            poison_position = unsafe_positions[0]
            if (
                any(item.status == "not_run" for item in outcomes[:poison_position])
                or any(
                    item.status != "not_run"
                    for item in outcomes[poison_position + 1 :]
                )
            ):
                raise BatchRunnerError(
                    "invalid_binding", "poisoned attempt has an invalid dispatch boundary"
                )
        elif (
            self.snapshot_reverified
            or not_run
            or not all(
                item.cleanup_complete and item.runtime_reverified for item in failed
            )
        ):
            raise BatchRunnerError(
                "invalid_binding", "closure-failed attempt has invalid task outcomes"
            )
        object.__setattr__(self, "plan", plan)
        object.__setattr__(self, "outcomes", outcomes)
        object.__setattr__(
            self,
            "report_sha256",
            hashlib.sha256(
                BATCH_ATTEMPT_REPORT_DIGEST_DOMAIN + _canonical_json(self._core_dict())
            ).hexdigest(),
        )
        if len(self.to_bytes()) > BATCH_ATTEMPT_REPORT_MAX_BYTES:
            raise BatchRunnerError("limit_exceeded", "batch attempt report is too large")

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "kind": self.kind,
            "max_attempts": self.max_attempts,
            "max_parallelism": self.max_parallelism,
            "outcomes": [item.to_dict() for item in self.outcomes],
            "plan": self.plan.to_dict(),
            "scheduler_version": self.scheduler_version,
            "snapshot_reverified": self.snapshot_reverified,
            "status": self.status,
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            BATCH_ATTEMPT_REPORT_DIGEST_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.report_sha256 != expected:
            raise BatchRunnerError("invalid_binding", "batch attempt report digest changed")
        return {**self._core_dict(), "report_sha256": self.report_sha256}

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_report_sha256: str,
        expected_wire_sha256: str,
    ) -> "DiscoveryBatchAttemptReportV2":
        _require_sha256(expected_report_sha256, name="expected_report_sha256")
        _require_sha256(expected_wire_sha256, name="expected_wire_sha256")
        if hashlib.sha256(payload).hexdigest() != expected_wire_sha256:
            raise BatchRunnerError("digest_mismatch", "batch attempt wire differs")
        raw = _strict_object(
            _parse_canonical_line(payload),
            keys=frozenset(
                {
                    "contract_version",
                    "kind",
                    "max_attempts",
                    "max_parallelism",
                    "outcomes",
                    "plan",
                    "report_sha256",
                    "scheduler_version",
                    "snapshot_reverified",
                    "status",
                }
            ),
            name="batch attempt report",
        )
        if raw["report_sha256"] != expected_report_sha256:
            raise BatchRunnerError("digest_mismatch", "batch attempt report differs")
        raw_plan = raw["plan"]
        if type(raw_plan) is not dict or type(raw["outcomes"]) is not list:
            raise BatchRunnerError(
                "invalid_contract", "batch attempt nested values are invalid"
            )
        plan_payload = _canonical_json(raw_plan) + b"\n"
        try:
            plan = DiscoveryBatchExecutionPlanV2.from_bytes(
                plan_payload,
                expected_plan_sha256=_require_sha256(
                    raw_plan.get("plan_sha256"), name="plan_sha256"
                ),
                expected_wire_sha256=hashlib.sha256(plan_payload).hexdigest(),
            )
        except (EvaluatorContractError, TypeError, ValueError):
            raise BatchRunnerError(
                "invalid_binding", "batch attempt plan did not normalize"
            ) from None
        result = cls(
            plan=plan,
            status=raw["status"],
            snapshot_reverified=raw["snapshot_reverified"],
            outcomes=tuple(
                TaskAttemptOutcomeV1.from_dict(item) for item in raw["outcomes"]
            ),
            contract_version=raw["contract_version"],
            kind=raw["kind"],
            scheduler_version=raw["scheduler_version"],
            max_parallelism=raw["max_parallelism"],
            max_attempts=raw["max_attempts"],
        )
        if result.report_sha256 != expected_report_sha256 or result.to_bytes() != payload:
            raise BatchRunnerError("noncanonical_json", "batch attempt report did not close")
        return result


def _success_outcome(pending: object) -> TaskAttemptOutcomeV1:
    try:
        plan = pending.task_plan
        run = pending.run
        return TaskAttemptOutcomeV1(
            task_plan_sha256=plan.plan_sha256,
            task_id=plan.task_id,
            status="succeeded",
            run_sha256=run.run_sha256,
            run_wire_sha256=pending.run_wire_sha256,
            discovery_result_sha256=pending.discovery_result_sha256,
            runtime_evidence_sha256=pending.runtime_evidence_sha256,
            cleanup_complete=True,
            runtime_reverified=True,
        )
    except (AttributeError, BatchRunnerError, TypeError, ValueError):
        raise BatchRunnerError(
            "invalid_output", "accepted worker output could not form an attempt outcome"
        ) from None


def _failed_outcome(
    task_plan: object,
    *,
    failure_code: str,
    cleanup_complete: bool,
    runtime_reverified: bool,
) -> TaskAttemptOutcomeV1:
    try:
        return TaskAttemptOutcomeV1(
            task_plan_sha256=task_plan.plan_sha256,
            task_id=task_plan.task_id,
            status="failed",
            failure_code=failure_code,
            cleanup_complete=cleanup_complete,
            runtime_reverified=runtime_reverified,
        )
    except (AttributeError, BatchRunnerError, TypeError, ValueError):
        raise BatchRunnerError(
            "invalid_plan", "task plan could not form a failed outcome"
        ) from None


def _not_run_outcome(task_plan: object) -> TaskAttemptOutcomeV1:
    try:
        return TaskAttemptOutcomeV1(
            task_plan_sha256=task_plan.plan_sha256,
            task_id=task_plan.task_id,
            status="not_run",
        )
    except (AttributeError, BatchRunnerError, TypeError, ValueError):
        raise BatchRunnerError(
            "invalid_plan", "task plan could not form a not-run outcome"
        ) from None


def _success_closure(
    outcome: TaskAttemptOutcomeV1,
) -> E4TaskSuccessClosureV1:
    if type(outcome) is not TaskAttemptOutcomeV1 or outcome.status != "succeeded":
        raise BatchRunnerError(
            "invalid_state", "E4 success closure requires a successful outcome"
        )
    try:
        return E4TaskSuccessClosureV1(
            task_plan_sha256=outcome.task_plan_sha256,
            task_id=outcome.task_id,
            run_sha256=outcome.run_sha256,
            run_wire_sha256=outcome.run_wire_sha256,
            discovery_result_sha256=outcome.discovery_result_sha256,
            runtime_evidence_sha256=outcome.runtime_evidence_sha256,
            cleanup_complete=outcome.cleanup_complete,
            runtime_reverified=outcome.runtime_reverified,
        )
    except (E4ReceiptError, TypeError, ValueError):
        raise BatchRunnerError(
            "invalid_state", "successful outcome did not form E4 closure"
        ) from None


def run_prepared_discovery_batch_v1(
    session: DiscoveryExecutionSession,
    runtime: VerifiedLinuxOciRuntimeV1,
    output_root: str | os.PathLike[str],
    *,
    provider: _Provider = run_discovery_worker_linux_oci_v1,
    runtime_reverifier: _RuntimeReverifier = reverify_linux_oci_runtime_v1,
) -> E4BatchSuccessReceiptV2 | DiscoveryBatchAttemptReportV2:
    """Run one exact 50/20 plan in order and publish only an all-success batch."""

    if type(session) is not DiscoveryExecutionSession:
        raise BatchRunnerError("invalid_argument", "session has an invalid exact type")
    if type(runtime) is not VerifiedLinuxOciRuntimeV1:
        raise BatchRunnerError("invalid_argument", "runtime has an invalid exact type")
    if not callable(provider) or not callable(runtime_reverifier):
        raise BatchRunnerError("invalid_argument", "trusted provider hooks are invalid")
    try:
        normalized_output_root = os.fspath(output_root)
    except TypeError:
        normalized_output_root = None
    if type(normalized_output_root) is not str or not normalized_output_root:
        raise BatchRunnerError("invalid_argument", "output root must be an exact string")
    plan = session.plan
    try:
        if runtime.execution_policy.to_bytes() != plan.execution_policy.to_bytes():
            raise BatchRunnerError(
                "policy_mismatch", "runtime policy differs from the batch plan"
            )
    except (EvaluatorContractError, LinuxOciProviderError, TypeError, ValueError):
        raise BatchRunnerError(
            "policy_mismatch", "runtime policy differs from the batch plan"
        ) from None

    outcomes: list[TaskAttemptOutcomeV1] = []
    runtime_poisoned = False
    for position, task_plan in enumerate(plan.tasks):
        try:
            launch, d2_replay, d3_replay = session.claim_task_execution(
                task_plan.task_id
            )
            completion = provider(
                runtime,
                launch,
                d2_replay=d2_replay,
                d3_replay=d3_replay,
            )
            runtime_reverifier(runtime)
            pending = accept_discovery_worker_output_v1(
                session, completion=completion
            )
            outcomes.append(_success_outcome(pending))
            continue
        except LinuxOciProviderError as error:
            code = error.code if _FAILURE_CODE_RE.fullmatch(error.code) else "provider_failed"
            clean_candidate = (
                not error.runtime_uncertain and code in _CLEAN_TASK_FAILURE_CODES
            )
            runtime_reverified = False
            if clean_candidate:
                try:
                    runtime_reverifier(runtime)
                    runtime_reverified = True
                except Exception:
                    code = "runtime_reverify_failed"
                except BaseException:
                    session.abort()
                    raise
            if clean_candidate and runtime_reverified:
                outcomes.append(
                    _failed_outcome(
                        task_plan,
                        failure_code=code,
                        cleanup_complete=True,
                        runtime_reverified=True,
                    )
                )
                continue
            outcomes.append(
                _failed_outcome(
                    task_plan,
                    failure_code=code,
                    cleanup_complete=clean_candidate,
                    runtime_reverified=False,
                )
            )
            runtime_poisoned = True
        except EvaluatorSupervisorError:
            outcomes.append(
                _failed_outcome(
                    task_plan,
                    failure_code="supervisor_failed",
                    cleanup_complete=False,
                    runtime_reverified=False,
                )
            )
            runtime_poisoned = True
        except Exception:
            outcomes.append(
                _failed_outcome(
                    task_plan,
                    failure_code="provider_unexpected",
                    cleanup_complete=False,
                    runtime_reverified=False,
                )
            )
            runtime_poisoned = True
        except BaseException:
            session.abort()
            raise
        if runtime_poisoned:
            outcomes.extend(_not_run_outcome(item) for item in plan.tasks[position + 1 :])
            session.abort()
            return DiscoveryBatchAttemptReportV2(
                plan=plan,
                status="runtime_poisoned",
                snapshot_reverified=False,
                outcomes=tuple(outcomes),
            )

    failures = tuple(item for item in outcomes if item.status == "failed")
    if failures:
        try:
            closure = close_failed_discovery_execution_v1(session)
            accepted = tuple(
                item.task_id for item in outcomes if item.status == "succeeded"
            )
            if (
                closure.plan.plan_sha256 != plan.plan_sha256
                or closure.accepted_task_ids != accepted
            ):
                raise BatchRunnerError(
                    "invalid_state", "failed attempt closure differs from scheduler state"
                )
        except (BatchRunnerError, EvaluatorSupervisorError):
            session.abort()
            return DiscoveryBatchAttemptReportV2(
                plan=plan,
                status="closure_failed",
                snapshot_reverified=False,
                outcomes=tuple(outcomes),
            )
        return DiscoveryBatchAttemptReportV2(
            plan=plan,
            status="failed_clean",
            snapshot_reverified=True,
            outcomes=tuple(outcomes),
        )

    token = postverify_discovery_execution_v1(session)
    try:
        authority = _issue_e4_success_receipt_authority_v2(
            plan,
            tuple(_success_closure(item) for item in outcomes),
        )
    except (E4ReceiptError, TypeError, ValueError):
        raise BatchRunnerError(
            "invalid_state", "successful scheduler closure could not be issued"
        ) from None
    return _publish_scheduled_postverified_discovery_execution_v1(
        token,
        authority,
        normalized_output_root,
    )


__all__ = [
    "BATCH_ATTEMPT_REPORT_KIND",
    "BatchRunnerError",
    "DiscoveryBatchAttemptReportV2",
    "E4_BATCH_RUNNER_VERSION",
    "TASK_ATTEMPT_OUTCOME_KIND",
    "TaskAttemptOutcomeV1",
    "run_prepared_discovery_batch_v1",
]
