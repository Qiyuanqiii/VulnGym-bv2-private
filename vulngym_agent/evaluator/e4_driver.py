"""Trusted, path-independent driver for one fixed E4 benchmark split.

The driver composes existing strict readers, the supervisor, the sole Linux
OCI provider, and the committed-output reader.  It deliberately exposes no
CLI and no policy tuning: the exact runtime image ID is the only execution
policy input, while backend/model identities and all worker limits remain the
fixed repository defaults.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Final, Literal

from vulngym_agent.benchmark.contracts import SnapshotTaskSpec
from vulngym_agent.benchmark.harness import (
    BenchmarkHarnessError,
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    PROFILE_SCHEMA_VERSION,
    PROFILE_TEST_TASKS,
    PROFILE_TRAIN_TASKS,
    load_answer_free_tasks,
)
from vulngym_agent.benchmark.sealed_snapshot import DEFAULT_SNAPSHOT_POLICY
from vulngym_agent.benchmark.sealed_tree_access import (
    DEFAULT_SEALED_TREE_ACCESS_LIMITS,
)
from vulngym_agent.evaluator.batch_configs import (
    BatchReplayConfigError,
    load_batch_replay_configs_v1,
)
from vulngym_agent.evaluator.batch_runner import (
    BatchRunnerError,
    DiscoveryBatchAttemptReportV2,
    run_prepared_discovery_batch_v1,
)
from vulngym_agent.evaluator.contracts import (
    DiscoveryBatchExecutionPlanV2,
    EvaluatorContractError,
    ExecutionPolicyBindingV1,
    snapshot_policy_sha256_v2,
)
from vulngym_agent.evaluator.e4_receipt import E4BatchSuccessReceiptV2
from vulngym_agent.evaluator.linux_oci import (
    LinuxOciProviderError,
    verify_linux_oci_runtime_v1,
)
from vulngym_agent.evaluator.oci_worker_entry import (
    OciReplayConfigV1,
    REPLAY_BACKEND_ID,
    REPLAY_MODEL_ID,
)
from vulngym_agent.evaluator.publication_reader import (
    E4PublicationReaderError,
    read_committed_e4_discovery_execution_v1,
)
from vulngym_agent.evaluator.supervisor import (
    DiscoveryExecutionSession,
    EvaluatorSupervisorError,
    budget_limits_sha256_v1,
    prepare_discovery_execution_plan_v1,
    tree_limits_sha256_v1,
)
from vulngym_agent.evaluator.worker import (
    DEFAULT_D2_WORKER_BUDGET_LIMITS,
    DEFAULT_D3_WORKER_BUDGET_LIMITS,
)


E4_DRIVER_VERSION: Final[str] = "discovery-e4-single-split-driver-v1"

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID_RE: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z"
)
_SPLIT_COUNTS: Final[dict[str, int]] = {
    "test": PROFILE_TEST_TASKS,
    "train": PROFILE_TRAIN_TASKS,
}
_MIN_KEY_BYTES: Final[int] = 32
_MAX_KEY_BYTES: Final[int] = 4096
_MISSING: Final[object] = object()


class E4DriverError(RuntimeError):
    """Stable, path-free failure at the one-split driver boundary."""

    def __init__(
        self, code: str, message: str, *, committed: bool = False
    ) -> None:
        self.code = code if type(code) is str and code else "driver_failed"
        self.committed = committed is True
        self.cleanup_failed = False
        super().__init__(message)


def fixed_e4_execution_policy_v1(
    runtime_image_id: str,
) -> ExecutionPolicyBindingV1:
    """Build the sole replay/offline-v1 policy from one exact image ID."""

    if (
        type(runtime_image_id) is not str
        or _IMAGE_ID_RE.fullmatch(runtime_image_id) is None
    ):
        raise E4DriverError(
            "invalid_argument", "E4 runtime image identity is invalid"
        )
    try:
        return ExecutionPolicyBindingV1(
            runtime_image_id=runtime_image_id,
            d2_backend_id=REPLAY_BACKEND_ID,
            d2_model_id=REPLAY_MODEL_ID,
            d3_backend_id=REPLAY_BACKEND_ID,
            d3_model_id=REPLAY_MODEL_ID,
            snapshot_policy_sha256=snapshot_policy_sha256_v2(
                DEFAULT_SNAPSHOT_POLICY
            ),
            d2_budget_sha256=budget_limits_sha256_v1(
                DEFAULT_D2_WORKER_BUDGET_LIMITS
            ),
            d3_budget_sha256=budget_limits_sha256_v1(
                DEFAULT_D3_WORKER_BUDGET_LIMITS
            ),
            tree_limits_sha256=tree_limits_sha256_v1(
                DEFAULT_SEALED_TREE_ACCESS_LIMITS
            ),
        )
    except (EvaluatorContractError, EvaluatorSupervisorError, TypeError, ValueError):
        raise E4DriverError(
            "policy_rejected", "fixed E4 execution policy did not close"
        ) from None


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise E4DriverError(
            "invalid_argument", f"{name} must be lower-case SHA-256"
        )
    return value


def _validate_arguments(
    *,
    split: object,
    expected_sealed_batch_manifest_sha256: object,
    expected_replay_manifest_sha256: object,
    expected_replay_manifest_wire_sha256: object,
    snapshot_key_id: object,
    snapshot_attestation_key: object,
) -> Literal["test", "train"]:
    if type(split) is not str or split not in _SPLIT_COUNTS:
        raise E4DriverError(
            "invalid_argument", "E4 split must be exactly test or train"
        )
    _require_sha256(
        expected_sealed_batch_manifest_sha256,
        name="expected_sealed_batch_manifest_sha256",
    )
    _require_sha256(
        expected_replay_manifest_sha256,
        name="expected_replay_manifest_sha256",
    )
    _require_sha256(
        expected_replay_manifest_wire_sha256,
        name="expected_replay_manifest_wire_sha256",
    )
    if (
        type(snapshot_key_id) is not str
        or _KEY_ID_RE.fullmatch(snapshot_key_id) is None
    ):
        raise E4DriverError(
            "invalid_argument", "snapshot attestation key ID is invalid"
        )
    if (
        type(snapshot_attestation_key) is not bytearray
        or not _MIN_KEY_BYTES
        <= len(snapshot_attestation_key)
        <= _MAX_KEY_BYTES
    ):
        raise E4DriverError(
            "invalid_argument",
            "snapshot attestation material must be an exact bounded bytearray",
        )
    return split


def _freeze_plan(value: object) -> DiscoveryBatchExecutionPlanV2:
    if type(value) is not DiscoveryBatchExecutionPlanV2:
        raise E4DriverError(
            "plan_mismatch", "prepared E4 plan has an invalid exact type"
        )
    try:
        wire = value.to_bytes()
        return DiscoveryBatchExecutionPlanV2.from_bytes(
            wire,
            expected_plan_sha256=value.plan_sha256,
            expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
        )
    except (AttributeError, EvaluatorContractError, TypeError, ValueError):
        raise E4DriverError(
            "plan_mismatch", "prepared E4 plan did not normalize"
        ) from None


def _assert_prepared_plan_matches_public_tasks(
    session: object,
    *,
    public_tasks: tuple[SnapshotTaskSpec, ...],
    replay_configs: tuple[tuple[OciReplayConfigV1, OciReplayConfigV1], ...],
    split: Literal["test", "train"],
    expected_sealed_batch_manifest_sha256: str,
    snapshot_key_id: str,
    execution_policy: ExecutionPolicyBindingV1,
) -> DiscoveryBatchExecutionPlanV2:
    if type(session) is not DiscoveryExecutionSession:
        raise E4DriverError(
            "plan_mismatch", "supervisor returned an invalid execution session"
        )
    try:
        supplied_plan = session.plan
    except (AttributeError, EvaluatorSupervisorError, TypeError, ValueError):
        raise E4DriverError(
            "plan_mismatch", "supervisor execution plan is unavailable"
        ) from None
    plan = _freeze_plan(supplied_plan)
    if (
        type(public_tasks) is not tuple
        or len(public_tasks) != _SPLIT_COUNTS[split]
        or any(type(task) is not SnapshotTaskSpec for task in public_tasks)
        or type(replay_configs) is not tuple
        or len(replay_configs) != len(public_tasks)
    ):
        raise E4DriverError(
            "public_task_mismatch", "public tasks do not define the fixed split"
        )
    batch = plan.batch
    policy_wire = execution_policy.to_bytes()
    if (
        batch.profile_id != PROFILE_ID
        or batch.profile_schema_version != PROFILE_SCHEMA_VERSION
        or batch.public_manifest_sha256 != PROFILE_MANIFEST_SHA256
        or batch.split != split
        or batch.task_count != _SPLIT_COUNTS[split]
        or batch.batch_manifest_sha256
        != expected_sealed_batch_manifest_sha256
        or batch.attestation_key_id != snapshot_key_id
        or batch.snapshot_policy != DEFAULT_SNAPSHOT_POLICY
        or plan.execution_policy.policy_sha256
        != execution_policy.policy_sha256
        or plan.execution_policy.wire_sha256
        != hashlib.sha256(policy_wire).hexdigest()
        or plan.execution_policy.to_bytes() != policy_wire
    ):
        raise E4DriverError(
            "plan_mismatch", "prepared E4 plan differs from its fixed bindings"
        )
    expected_identities = tuple(
        (
            task.task_id,
            task.repo_url,
            task.commit,
            task.split,
            task.instruction_id,
        )
        for task in public_tasks
    )
    observed_identities = tuple(
        (
            task.task_id,
            task.repo_url,
            task.commit,
            task.split,
            task.instruction_id,
        )
        for task in batch.tasks
    )
    if observed_identities != expected_identities:
        raise E4DriverError(
            "public_task_mismatch",
            "prepared E4 batch order differs from the public task order",
        )
    if len(plan.tasks) != len(public_tasks):
        raise E4DriverError(
            "plan_mismatch", "prepared E4 task plans do not cover the split"
        )
    for public, member, task_plan, pair in zip(
        public_tasks,
        batch.tasks,
        plan.tasks,
        replay_configs,
        strict=True,
    ):
        if (
            type(pair) is not tuple
            or len(pair) != 2
            or type(pair[0]) is not OciReplayConfigV1
            or type(pair[1]) is not OciReplayConfigV1
        ):
            raise E4DriverError(
                "replay_mismatch", "loaded replay pair has an invalid exact type"
            )
        d2, d3 = pair
        if (
            task_plan.task_id != public.task_id
            or task_plan.task_id != member.task_id
            or task_plan.snapshot_manifest_sha256
            != member.snapshot_manifest_sha256
            or task_plan.snapshot_content_root
            != member.snapshot_content_root
            or d2.task_id != public.task_id
            or d3.task_id != public.task_id
            or d2.role != "d2"
            or d3.role != "d3"
            or d2.backend_id != REPLAY_BACKEND_ID
            or d3.backend_id != REPLAY_BACKEND_ID
            or d2.model_id != REPLAY_MODEL_ID
            or d3.model_id != REPLAY_MODEL_ID
            or task_plan.d2_replay_sha256 != d2.config_sha256
            or task_plan.d2_replay_wire_sha256 != d2.wire_sha256
            or task_plan.d3_replay_sha256 != d3.config_sha256
            or task_plan.d3_replay_wire_sha256 != d3.wire_sha256
        ):
            raise E4DriverError(
                "replay_mismatch", "prepared task plan differs from its replay pair"
            )
    return plan


def _freeze_attempt_report(
    value: object,
    *,
    expected_plan: DiscoveryBatchExecutionPlanV2,
) -> DiscoveryBatchAttemptReportV2:
    if type(value) is not DiscoveryBatchAttemptReportV2:
        raise E4DriverError(
            "runner_contract_mismatch", "E4 runner returned an invalid result"
        )
    try:
        wire = value.to_bytes()
        result = DiscoveryBatchAttemptReportV2.from_bytes(
            wire,
            expected_report_sha256=value.report_sha256,
            expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
        )
    except (AttributeError, BatchRunnerError, TypeError, ValueError):
        raise E4DriverError(
            "runner_contract_mismatch", "E4 failure report did not normalize"
        ) from None
    expected_plan_wire = expected_plan.to_bytes()
    result_plan_wire = result.plan.to_bytes()
    if (
        result != value
        or result.to_bytes() != wire
        or result.plan.plan_sha256 != expected_plan.plan_sha256
        or result.plan.wire_sha256
        != hashlib.sha256(expected_plan_wire).hexdigest()
        or result_plan_wire != expected_plan_wire
    ):
        raise E4DriverError(
            "runner_contract_mismatch",
            "E4 failure report changed or used a detached plan",
        )
    return result


def _read_back_success(
    output_root: str | Path,
    value: object,
    *,
    expected_plan: DiscoveryBatchExecutionPlanV2,
) -> E4BatchSuccessReceiptV2:
    if type(value) is not E4BatchSuccessReceiptV2:
        raise E4DriverError(
            "runner_contract_mismatch", "E4 runner returned an invalid result"
        )
    try:
        wire = value.to_bytes()
        expected_wire_sha256 = hashlib.sha256(wire).hexdigest()
        supplied_plan = value.execution_receipt.plan
        expected_plan_wire = expected_plan.to_bytes()
        if (
            type(supplied_plan) is not DiscoveryBatchExecutionPlanV2
            or supplied_plan.plan_sha256 != expected_plan.plan_sha256
            or supplied_plan.wire_sha256
            != hashlib.sha256(expected_plan_wire).hexdigest()
            or supplied_plan.to_bytes() != expected_plan_wire
        ):
            raise E4DriverError(
                "runner_contract_mismatch",
                "E4 success receipt used a detached execution plan",
                committed=True,
            )
        result = read_committed_e4_discovery_execution_v1(
            output_root,
            expected_receipt_sha256=value.receipt_sha256,
            expected_wire_sha256=expected_wire_sha256,
        )
    except E4PublicationReaderError:
        raise
    except E4DriverError:
        raise
    except (AttributeError, TypeError, ValueError):
        raise E4DriverError(
            "publication_mismatch", "E4 success receipt is invalid", committed=True
        ) from None
    try:
        result_plan = result.execution_receipt.plan
        result_plan_wire = result_plan.to_bytes()
    except (AttributeError, TypeError, ValueError):
        raise E4DriverError(
            "publication_mismatch",
            "committed E4 success has no valid execution plan",
            committed=True,
        ) from None
    if (
        type(result) is not E4BatchSuccessReceiptV2
        or result != value
        or result.receipt_sha256 != value.receipt_sha256
        or result.wire_sha256 != expected_wire_sha256
        or result.to_bytes() != wire
        or type(result_plan) is not DiscoveryBatchExecutionPlanV2
        or result_plan.plan_sha256 != expected_plan.plan_sha256
        or result_plan.wire_sha256
        != hashlib.sha256(expected_plan_wire).hexdigest()
        or result_plan_wire != expected_plan_wire
    ):
        raise E4DriverError(
            "publication_mismatch",
            "committed E4 success differs from the runner result",
            committed=True,
        )
    return result


def _stable_driver_error(error: Exception) -> E4DriverError:
    if isinstance(error, E4DriverError):
        return error
    if isinstance(error, BenchmarkHarnessError):
        return E4DriverError(
            "public_input_rejected", "fixed public benchmark input was rejected"
        )
    if isinstance(error, BatchReplayConfigError):
        return E4DriverError(
            "replay_input_rejected", "fixed replay input was rejected"
        )
    if isinstance(error, EvaluatorSupervisorError):
        return E4DriverError(
            "preparation_rejected",
            "E4 supervisor preparation did not close",
            committed=error.committed,
        )
    if isinstance(error, EvaluatorContractError):
        return E4DriverError(
            "contract_rejected", "E4 execution contract was rejected"
        )
    if isinstance(error, LinuxOciProviderError):
        return E4DriverError(
            "runtime_rejected", "fixed Linux OCI runtime was rejected"
        )
    if isinstance(error, BatchRunnerError):
        return E4DriverError(
            "execution_rejected", "E4 batch execution was rejected"
        )
    if isinstance(error, E4PublicationReaderError):
        return E4DriverError(
            "publication_unverified",
            "committed E4 output did not verify",
            committed=True,
        )
    return E4DriverError(
        "driver_failed", "E4 single-split driver failed safely"
    )


def _zero_caller_key(value: object) -> None:
    if type(value) is bytearray:
        for index in range(len(value)):
            value[index] = 0


def run_e4_discovery_split_v1(
    benchmark_root: str | Path,
    sealed_batch_root: str | Path,
    replay_config_root: str | Path,
    output_root: str | Path,
    *,
    split: Literal["test", "train"],
    expected_sealed_batch_manifest_sha256: str,
    expected_replay_manifest_sha256: str,
    expected_replay_manifest_wire_sha256: str,
    snapshot_attestation_key: bytearray,
    snapshot_key_id: str,
    runtime_image_id: str,
    docker_executable: str | Path,
) -> E4BatchSuccessReceiptV2 | DiscoveryBatchAttemptReportV2:
    """Run and close one exact public test or train E4 batch."""

    session: DiscoveryExecutionSession | None = None
    result: object = _MISSING
    primary: BaseException | None = None
    cleanup_error: BaseException | None = None
    try:
        normalized_split = _validate_arguments(
            split=split,
            expected_sealed_batch_manifest_sha256=(
                expected_sealed_batch_manifest_sha256
            ),
            expected_replay_manifest_sha256=expected_replay_manifest_sha256,
            expected_replay_manifest_wire_sha256=(
                expected_replay_manifest_wire_sha256
            ),
            snapshot_key_id=snapshot_key_id,
            snapshot_attestation_key=snapshot_attestation_key,
        )
        policy = fixed_e4_execution_policy_v1(runtime_image_id)
        public_tasks = load_answer_free_tasks(
            benchmark_root, split=normalized_split
        )
        if (
            type(public_tasks) is not tuple
            or len(public_tasks) != _SPLIT_COUNTS[normalized_split]
            or any(type(task) is not SnapshotTaskSpec for task in public_tasks)
        ):
            raise E4DriverError(
                "public_task_mismatch",
                "public task reader did not return the fixed split",
            )
        task_ids = tuple(task.task_id for task in public_tasks)
        replay_configs = load_batch_replay_configs_v1(
            replay_config_root,
            expected_manifest_sha256=expected_replay_manifest_sha256,
            expected_manifest_wire_sha256=expected_replay_manifest_wire_sha256,
            expected_split=normalized_split,
            expected_task_ids=task_ids,
        )
        session = prepare_discovery_execution_plan_v1(
            sealed_batch_root,
            expected_batch_manifest_sha256=(
                expected_sealed_batch_manifest_sha256
            ),
            attestation_key=snapshot_attestation_key,
            expected_key_id=snapshot_key_id,
            execution_policy=policy,
            task_replay_configs=replay_configs,
        )
        prepared_plan = _assert_prepared_plan_matches_public_tasks(
            session,
            public_tasks=public_tasks,
            replay_configs=replay_configs,
            split=normalized_split,
            expected_sealed_batch_manifest_sha256=(
                expected_sealed_batch_manifest_sha256
            ),
            snapshot_key_id=snapshot_key_id,
            execution_policy=policy,
        )

        # No Docker CLI/daemon probe is reachable before every trusted input
        # and the complete prepared plan have passed the checks above.
        runtime = verify_linux_oci_runtime_v1(
            docker_executable, execution_policy=policy
        )
        outcome = run_prepared_discovery_batch_v1(
            session, runtime, output_root
        )
        if type(outcome) is E4BatchSuccessReceiptV2:
            result = _read_back_success(
                output_root, outcome, expected_plan=prepared_plan
            )
        elif type(outcome) is DiscoveryBatchAttemptReportV2:
            # A failed attempt is non-publishable.  Deliberately do not open
            # or inspect the requested success directory on this branch.
            result = _freeze_attempt_report(
                outcome, expected_plan=prepared_plan
            )
        else:
            raise E4DriverError(
                "runner_contract_mismatch", "E4 runner returned an invalid union"
            )
    except Exception as error:
        stable = _stable_driver_error(error)
        primary = stable
    except BaseException as error:
        primary = error
    finally:
        try:
            if session is not None:
                session.abort()
        except BaseException as error:
            cleanup_error = error
        finally:
            try:
                _zero_caller_key(snapshot_attestation_key)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error

    if primary is not None:
        if cleanup_error is not None and isinstance(primary, E4DriverError):
            # Preserve the first stable failure (including its publication
            # uncertainty) while making the independent abort failure visible.
            # BaseException control flow such as KeyboardInterrupt remains
            # untouched; the caller-owned key has already been zeroed above.
            primary.cleanup_failed = True
        if isinstance(primary, E4DriverError):
            raise primary from None
        raise primary
    if cleanup_error is not None:
        if isinstance(cleanup_error, Exception):
            raise E4DriverError(
                "cleanup_failed", "E4 driver cleanup did not close"
            ) from None
        raise cleanup_error
    if type(result) not in {
        E4BatchSuccessReceiptV2,
        DiscoveryBatchAttemptReportV2,
    }:
        raise E4DriverError(
            "driver_failed", "E4 driver produced no closed result"
        )
    return result


__all__ = [
    "E4_DRIVER_VERSION",
    "E4DriverError",
    "fixed_e4_execution_policy_v1",
    "run_e4_discovery_split_v1",
]
