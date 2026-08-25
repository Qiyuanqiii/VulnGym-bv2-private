"""Trusted pre/post batch verification state machine for evaluator stage E.

The supervisor is the only component allowed to hold batch attestation material.
It verifies the complete batch before constructing any launch input, derives all
worker handoffs itself, accepts only canonical task-bound run wires, and performs
a second complete batch verification before yielding an opaque publication
token.  Worker processes receive neither this session nor the attestation key.

This state machine verifies endpoint state; it does not itself make a mutable
host path immutable between those endpoints.  The E3 execution provider must
hold an exclusive immutable snapshot/lease for the source generation consumed
by the worker and must bind that generation into runtime evidence.  A plain
read-only container mount is not sufficient against a concurrent host writer.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from typing import Final

from vulngym_agent.benchmark.contracts import SnapshotTaskSpec
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.harness import (
    ArtifactBundleDigest,
    BenchmarkHarnessError,
    _rename_directory_noreplace,
    load_artifact_bundle_index,
    write_artifact_bundle_index,
)
from vulngym_agent.benchmark.sealed_snapshot import (
    DEFAULT_SNAPSHOT_POLICY,
    SealedSnapshotError,
    SnapshotPolicy,
    _windows_assert_no_named_streams,
)
from vulngym_agent.benchmark.sealed_tree_access import (
    DEFAULT_SEALED_TREE_ACCESS_LIMITS,
    SealedTreeAccessLimits,
)
from vulngym_agent.benchmark.snapshot_batch import (
    SnapshotBatchError,
    SnapshotBatchSummary,
    SnapshotBatchTask,
    _canonical_existing_path,
    verify_snapshot_batch,
)
from vulngym_agent.benchmark.worker_handoff import (
    WorkerHandoffError,
    WorkerHandoffV2,
    build_worker_handoff,
)
from vulngym_agent.evaluator.contracts import (
    EVALUATOR_CONTRACT_MAX_WIRE_BYTES,
    DiscoveryBatchExecutionPlanV2,
    DiscoveryBatchExecutionReceiptV2,
    DiscoveryTaskExecutionPlanV1,
    DiscoveryTaskExecutionReceiptV1,
    EvaluatorContractError,
    ExecutionPolicyBindingV1,
    SnapshotBatchBindingV2,
    _embedded_sha256_from_canonical_wire,
)
from vulngym_agent.evaluator.worker import (
    DEFAULT_D2_WORKER_BUDGET_LIMITS,
    DEFAULT_D3_WORKER_BUDGET_LIMITS,
)
from vulngym_agent.evaluator.runtime_evidence import (
    RuntimeEvidenceError,
    RuntimeEvidenceV1,
)
from vulngym_agent.evaluator.oci_worker_entry import (
    OciReplayConfigV1,
    OciWorkerEntryError,
)
from vulngym_agent.evaluator.worker_completion import (
    CompletedWorkerExecutionV1,
    WorkerCompletionError,
)
from vulngym_agent.evaluator.e4_receipt import (
    E4_SUCCESS_RECEIPT_FILENAME,
    E4_SUCCESS_RECEIPT_MAX_BYTES,
    E4BatchSuccessReceiptV2,
    E4ReceiptError,
    E4SuccessReceiptAuthorityV2,
    claim_e4_success_receipt_authority_v2,
)
from vulngym_agent.orchestrator.budget import Limits
from vulngym_agent.orchestrator.discovery_pipeline import (
    SOURCE_DISCOVERY_RUN_MAX_WIRE_BYTES,
    SourceDiscoveryRunV1,
)
from vulngym_agent.orchestrator.discovery_replay import (
    DiscoveryReplayError,
    read_discovery_result_bundle,
    write_discovery_result_bundle,
)


EVALUATOR_SUPERVISOR_VERSION: Final[str] = (
    "source-discovery-evaluator-supervisor-v1"
)
BUDGET_LIMITS_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator budget limits v1\0"
)
TREE_LIMITS_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator sealed tree limits v1\0"
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_MIN_KEY_BYTES: Final[int] = 32
_MAX_KEY_BYTES: Final[int] = 4096
_MAX_BATCH_REPLAY_WIRE_BYTES: Final[int] = 512 * 1024 * 1024
_SESSION_TOKEN: Final[object] = object()
_POSTVERIFIED_TOKEN: Final[object] = object()
_FAILED_CLOSURE_TOKEN: Final[object] = object()


class EvaluatorSupervisorError(RuntimeError):
    """Stable, path-free supervisor failure."""

    def __init__(
        self, code: str, message: str, *, committed: bool = False
    ) -> None:
        if type(code) is not str or not code:
            code = "supervisor_failed"
            message = "evaluator supervisor failed"
        self.code = code
        self.committed = committed is True
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
        raise EvaluatorSupervisorError(
            "invalid_argument", "supervisor input is not canonical JSON"
        ) from None


def _zero_key(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _canonical_snapshot_policy(value: object) -> SnapshotPolicy:
    if type(value) is not SnapshotPolicy:
        raise EvaluatorSupervisorError(
            "invalid_argument", "snapshot policy must have an exact type"
        )
    try:
        fields = (
            value.max_files,
            value.max_file_bytes,
            value.max_total_bytes,
            value.max_path_bytes,
            value.max_component_bytes,
            value.max_depth,
            value.max_tree_object_bytes,
            value.max_manifest_bytes,
            value.git_symlink_representation,
        )
    except (AttributeError, TypeError):
        raise EvaluatorSupervisorError(
            "invalid_argument", "snapshot policy fields are incomplete"
        ) from None
    if (
        any(type(item) is not int for item in fields[:-1])
        or type(fields[-1]) is not str
    ):
        raise EvaluatorSupervisorError(
            "invalid_argument", "snapshot policy fields have invalid exact types"
        )
    try:
        return SnapshotPolicy(
            max_files=fields[0],
            max_file_bytes=fields[1],
            max_total_bytes=fields[2],
            max_path_bytes=fields[3],
            max_component_bytes=fields[4],
            max_depth=fields[5],
            max_tree_object_bytes=fields[6],
            max_manifest_bytes=fields[7],
            git_symlink_representation=fields[8],
        )
    except (AttributeError, TypeError, ValueError):
        raise EvaluatorSupervisorError(
            "invalid_argument", "snapshot policy is invalid"
        ) from None


def _canonical_budget_limits(value: object) -> Limits:
    if type(value) is not Limits:
        raise EvaluatorSupervisorError(
            "invalid_argument", "budget limits must have an exact type"
        )
    try:
        fields = (
            value.max_llm_calls,
            value.max_tool_calls,
            value.max_repair_iterations,
        )
    except (AttributeError, TypeError):
        raise EvaluatorSupervisorError(
            "invalid_argument", "budget limit fields are incomplete"
        ) from None
    if any(type(item) is not int for item in fields):
        raise EvaluatorSupervisorError(
            "invalid_argument", "budget limits must be exact integers"
        )
    try:
        return Limits(
            max_llm_calls=fields[0],
            max_tool_calls=fields[1],
            max_repair_iterations=fields[2],
        )
    except (AttributeError, TypeError, ValueError):
        raise EvaluatorSupervisorError(
            "invalid_argument", "budget limits are invalid"
        ) from None


def _canonical_tree_limits(value: object) -> SealedTreeAccessLimits:
    if type(value) is not SealedTreeAccessLimits:
        raise EvaluatorSupervisorError(
            "invalid_argument", "tree limits must have an exact type"
        )
    try:
        fields = (
            value.max_inventory_calls,
            value.max_read_calls,
            value.max_bytes_per_read,
            value.max_total_bytes_read,
            value.version,
        )
    except (AttributeError, TypeError):
        raise EvaluatorSupervisorError(
            "invalid_argument", "tree limit fields are incomplete"
        ) from None
    if any(type(item) is not int for item in fields[:4]) or type(fields[4]) is not str:
        raise EvaluatorSupervisorError(
            "invalid_argument", "tree limits have invalid exact types"
        )
    try:
        return SealedTreeAccessLimits(
            max_inventory_calls=fields[0],
            max_read_calls=fields[1],
            max_bytes_per_read=fields[2],
            max_total_bytes_read=fields[3],
            version=fields[4],
        )
    except (AttributeError, TypeError, ValueError):
        raise EvaluatorSupervisorError(
            "invalid_argument", "tree limits are invalid"
        ) from None


def budget_limits_sha256_v1(value: Limits) -> str:
    limits = _canonical_budget_limits(value)
    return hashlib.sha256(
        BUDGET_LIMITS_DIGEST_DOMAIN + _canonical_json(limits.to_dict())
    ).hexdigest()


def tree_limits_sha256_v1(value: SealedTreeAccessLimits) -> str:
    limits = _canonical_tree_limits(value)
    return hashlib.sha256(
        TREE_LIMITS_DIGEST_DOMAIN
        + _canonical_json(
            {
                "max_bytes_per_read": limits.max_bytes_per_read,
                "max_inventory_calls": limits.max_inventory_calls,
                "max_read_calls": limits.max_read_calls,
                "max_total_bytes_read": limits.max_total_bytes_read,
                "version": limits.version,
            }
        )
    ).hexdigest()


def _canonical_execution_policy(
    value: object,
    *,
    d2_budget_limits: Limits,
    d3_budget_limits: Limits,
    tree_limits: SealedTreeAccessLimits,
) -> ExecutionPolicyBindingV1:
    if type(value) is not ExecutionPolicyBindingV1:
        raise EvaluatorSupervisorError(
            "invalid_argument", "execution policy must have an exact type"
        )
    try:
        payload = value.to_bytes()
        policy = ExecutionPolicyBindingV1.from_bytes(
            payload,
            expected_policy_sha256=value.policy_sha256,
            expected_wire_sha256=hashlib.sha256(payload).hexdigest(),
        )
    except (AttributeError, EvaluatorContractError, TypeError, ValueError):
        raise EvaluatorSupervisorError(
            "invalid_argument", "execution policy did not pass strict normalization"
        ) from None
    if (
        policy.d2_budget_sha256 != budget_limits_sha256_v1(d2_budget_limits)
        or policy.d3_budget_sha256 != budget_limits_sha256_v1(d3_budget_limits)
        or policy.tree_limits_sha256 != tree_limits_sha256_v1(tree_limits)
    ):
        raise EvaluatorSupervisorError(
            "policy_mismatch", "execution policy does not bind worker limits"
        )
    return policy


def _canonical_task_replay_configs(
    value: object,
    *,
    execution_policy: ExecutionPolicyBindingV1,
) -> tuple[tuple[OciReplayConfigV1, OciReplayConfigV1], ...]:
    """Freeze one exact, ordered D2/D3 replay pair for every batch task."""

    if type(value) is not tuple:
        raise EvaluatorSupervisorError(
            "invalid_argument", "task replay configurations must be an exact tuple"
        )
    normalized: list[tuple[OciReplayConfigV1, OciReplayConfigV1]] = []
    total_wire_bytes = 0
    for pair in value:
        if type(pair) is not tuple or len(pair) != 2:
            raise EvaluatorSupervisorError(
                "invalid_argument", "each task replay configuration must be a D2/D3 pair"
            )
        d2_supplied, d3_supplied = pair
        if (
            type(d2_supplied) is not OciReplayConfigV1
            or type(d3_supplied) is not OciReplayConfigV1
        ):
            raise EvaluatorSupervisorError(
                "invalid_argument", "task replay configurations have invalid exact types"
            )
        try:
            d2_wire = d2_supplied.to_bytes()
            d3_wire = d3_supplied.to_bytes()
            d2 = OciReplayConfigV1.from_bytes(d2_wire)
            d3 = OciReplayConfigV1.from_bytes(d3_wire)
        except (AttributeError, OciWorkerEntryError, TypeError, ValueError):
            raise EvaluatorSupervisorError(
                "invalid_argument", "task replay configurations did not normalize"
            ) from None
        total_wire_bytes += len(d2_wire) + len(d3_wire)
        if total_wire_bytes > _MAX_BATCH_REPLAY_WIRE_BYTES:
            raise EvaluatorSupervisorError(
                "limit_exceeded", "task replay configurations exceed the batch byte limit"
            )
        if (
            d2.task_id != d3.task_id
            or d2.role != "d2"
            or d3.role != "d3"
            or d2.backend_id != execution_policy.d2_backend_id
            or d2.model_id != execution_policy.d2_model_id
            or d3.backend_id != execution_policy.d3_backend_id
            or d3.model_id != execution_policy.d3_model_id
        ):
            raise EvaluatorSupervisorError(
                "policy_mismatch", "task replay configurations do not bind the policy"
            )
        normalized.append((d2, d3))
    task_ids = tuple(pair[0].task_id for pair in normalized)
    if len(set(task_ids)) != len(task_ids):
        raise EvaluatorSupervisorError(
            "invalid_binding", "task replay configurations repeat a task"
        )
    return tuple(normalized)


def _task_from_member(member: SnapshotBatchTask) -> DiscoveryTaskInputV1:
    try:
        return DiscoveryTaskInputV1(
            task_id=member.task_id,
            repo_url=member.repo_url,
            commit=member.commit,
            instruction_id=member.instruction_id,
            snapshot_manifest_sha256=member.snapshot_manifest_sha256,
            snapshot_content_root=member.snapshot_content_root,
        )
    except (AttributeError, TypeError, ValueError):
        raise EvaluatorSupervisorError(
            "batch_binding_mismatch", "batch member cannot form a discovery task"
        ) from None


class WorkerTaskLaunchV1:
    """Opaque trusted-launch input containing only one source mount and handoff."""

    __slots__ = (
        "__handoff_payload",
        "__handoff_sha256",
        "__handoff_wire_sha256",
        "__provider_claimed",
        "__provider_lock",
        "__task_plan_payload",
        "__task_plan_sha256",
        "__tree_root",
    )

    def __init__(
        self,
        token: object,
        *,
        task_plan: DiscoveryTaskExecutionPlanV1,
        handoff: WorkerHandoffV2,
        tree_root: Path,
    ) -> None:
        if token is not _SESSION_TOKEN:
            raise TypeError("worker launch values are supervisor-created")
        if (
            type(task_plan) is not DiscoveryTaskExecutionPlanV1
            or type(handoff) is not WorkerHandoffV2
            or type(tree_root) is not type(Path())
        ):
            raise EvaluatorSupervisorError(
                "invalid_launch", "worker launch inputs have invalid exact types"
            )
        task_plan_payload = task_plan.to_bytes()
        task_plan_sha256 = _embedded_sha256_from_canonical_wire(
            task_plan_payload, field="plan_sha256"
        )
        frozen_task_plan = DiscoveryTaskExecutionPlanV1.from_bytes(
            task_plan_payload,
            expected_plan_sha256=task_plan_sha256,
            expected_wire_sha256=hashlib.sha256(task_plan_payload).hexdigest(),
        )
        handoff_payload = handoff.to_bytes()
        handoff_sha256 = _embedded_sha256_from_canonical_wire(
            handoff_payload, field="handoff_sha256"
        )
        handoff_wire_sha256 = hashlib.sha256(handoff_payload).hexdigest()
        frozen_handoff = WorkerHandoffV2.from_bytes(
            handoff_payload,
            expected_sha256=handoff_sha256,
            expected_wire_sha256=handoff_wire_sha256,
        )
        handoff_task = frozen_handoff.task
        if (
            frozen_task_plan.handoff_sha256 != handoff_sha256
            or frozen_task_plan.handoff_wire_sha256 != handoff_wire_sha256
            or frozen_task_plan.task_id != handoff_task.task_id
            or frozen_task_plan.snapshot_id != handoff_task.snapshot_id
            or frozen_task_plan.snapshot_manifest_sha256
            != handoff_task.snapshot_manifest_sha256
            or frozen_task_plan.snapshot_content_root
            != handoff_task.snapshot_content_root
        ):
            raise EvaluatorSupervisorError(
                "invalid_launch", "worker handoff is detached from its task plan"
            )
        self.__task_plan_payload = task_plan_payload
        self.__task_plan_sha256 = task_plan_sha256
        self.__handoff_payload = handoff_payload
        self.__handoff_sha256 = handoff_sha256
        self.__handoff_wire_sha256 = handoff_wire_sha256
        self.__tree_root = tree_root
        self.__provider_claimed = False
        self.__provider_lock = threading.Lock()

    @property
    def task_plan(self) -> DiscoveryTaskExecutionPlanV1:
        return DiscoveryTaskExecutionPlanV1.from_bytes(
            self.__task_plan_payload,
            expected_plan_sha256=self.__task_plan_sha256,
            expected_wire_sha256=hashlib.sha256(
                self.__task_plan_payload
            ).hexdigest(),
        )

    @property
    def task(self) -> DiscoveryTaskInputV1:
        return WorkerHandoffV2.from_bytes(
            self.__handoff_payload,
            expected_sha256=self.__handoff_sha256,
            expected_wire_sha256=self.__handoff_wire_sha256,
        ).task

    @property
    def tree_root(self) -> Path:
        return self.__tree_root

    @property
    def handoff_payload(self) -> bytes:
        return self.__handoff_payload

    @property
    def handoff_sha256(self) -> str:
        return self.__handoff_sha256

    @property
    def handoff_wire_sha256(self) -> str:
        return self.__handoff_wire_sha256

    def _claim_for_provider(self) -> None:
        """Consume this launch exactly once before provider-side effects."""

        with self.__provider_lock:
            if self.__provider_claimed:
                raise EvaluatorSupervisorError(
                    "duplicate_launch", "worker launch was already consumed"
                )
            self.__provider_claimed = True

    def __reduce__(self):
        raise TypeError("worker launch values are not serializable")


class PendingTaskExecutionV1:
    """Strictly parsed worker output retained until post-verification."""

    __slots__ = (
        "__discovery_result_sha256",
        "__run",
        "__run_wire",
        "__run_wire_sha256",
        "__runtime_evidence",
        "__task_plan",
    )

    def __init__(
        self,
        token: object,
        *,
        task_plan: DiscoveryTaskExecutionPlanV1,
        run: SourceDiscoveryRunV1,
        run_wire: bytes,
        runtime_evidence: RuntimeEvidenceV1,
    ) -> None:
        if token is not _SESSION_TOKEN:
            raise TypeError("pending execution values are supervisor-created")
        self.__task_plan = task_plan
        self.__run = run
        self.__run_wire = run_wire
        self.__run_wire_sha256 = hashlib.sha256(run_wire).hexdigest()
        self.__discovery_result_sha256 = hashlib.sha256(
            _canonical_json(run.discovery_result.to_dict())
        ).hexdigest()
        if type(runtime_evidence) is not RuntimeEvidenceV1:
            raise EvaluatorSupervisorError(
                "invalid_output", "runtime evidence has an invalid exact type"
            )
        evidence_wire = runtime_evidence.to_bytes()
        try:
            evidence = RuntimeEvidenceV1.from_bytes(
                evidence_wire,
                expected_evidence_sha256=runtime_evidence.evidence_sha256,
                expected_wire_sha256=hashlib.sha256(evidence_wire).hexdigest(),
            )
        except (AttributeError, RuntimeEvidenceError, TypeError, ValueError):
            raise EvaluatorSupervisorError(
                "invalid_output", "runtime evidence did not pass strict normalization"
            ) from None
        if (
            evidence.task_plan_sha256 != task_plan.plan_sha256
            or evidence.execution_policy_sha256
            != task_plan.execution_policy_sha256
            or evidence.task_id != task_plan.task_id
            or evidence.snapshot_id != task_plan.snapshot_id
            or evidence.snapshot_manifest_sha256
            != task_plan.snapshot_manifest_sha256
            or evidence.snapshot_content_root != task_plan.snapshot_content_root
            or evidence.handoff_sha256 != task_plan.handoff_sha256
            or evidence.handoff_wire_sha256 != task_plan.handoff_wire_sha256
            or evidence.run_sha256 != run.run_sha256
            or evidence.run_wire_sha256 != hashlib.sha256(run_wire).hexdigest()
            or evidence.run_wire_size != len(run_wire)
        ):
            raise EvaluatorSupervisorError(
                "invalid_output", "runtime evidence is detached from worker output"
            )
        self.__runtime_evidence = evidence

    @property
    def task_plan(self) -> DiscoveryTaskExecutionPlanV1:
        wire = self.__task_plan.to_bytes()
        return DiscoveryTaskExecutionPlanV1.from_bytes(
            wire,
            expected_plan_sha256=_embedded_sha256_from_canonical_wire(
                wire, field="plan_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
        )

    @property
    def run(self) -> SourceDiscoveryRunV1:
        return SourceDiscoveryRunV1.from_wire(self.__run_wire)

    @property
    def run_wire(self) -> bytes:
        return self.__run_wire

    @property
    def run_wire_sha256(self) -> str:
        return self.__run_wire_sha256

    @property
    def discovery_result_sha256(self) -> str:
        return self.__discovery_result_sha256

    @property
    def runtime_evidence_sha256(self) -> str:
        return self.__runtime_evidence.evidence_sha256

    @property
    def runtime_evidence(self) -> RuntimeEvidenceV1:
        wire = self.__runtime_evidence.to_bytes()
        return RuntimeEvidenceV1.from_bytes(
            wire,
            expected_evidence_sha256=self.__runtime_evidence.evidence_sha256,
            expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
        )

    def __reduce__(self):
        raise TypeError("pending execution values are not serializable")


class PostVerifiedDiscoveryExecutionV1:
    """Opaque one-use publication authority issued only after fresh post-verify."""

    __slots__ = (
        "__batch_root",
        "__claimed",
        "__lock",
        "__pending",
        "__plan",
    )

    def __init__(
        self,
        token: object,
        *,
        batch_root: Path,
        plan: DiscoveryBatchExecutionPlanV2,
        pending: tuple[PendingTaskExecutionV1, ...],
    ) -> None:
        if token is not _POSTVERIFIED_TOKEN:
            raise TypeError("post-verified values are supervisor-created")
        self.__batch_root = batch_root
        self.__plan = plan
        self.__pending = pending
        self.__claimed = False
        self.__lock = threading.Lock()

    @property
    def plan(self) -> DiscoveryBatchExecutionPlanV2:
        wire = self.__plan.to_bytes()
        return DiscoveryBatchExecutionPlanV2.from_bytes(
            wire,
            expected_plan_sha256=_embedded_sha256_from_canonical_wire(
                wire, field="plan_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
        )

    @property
    def pending(self) -> tuple[PendingTaskExecutionV1, ...]:
        return tuple(
            PendingTaskExecutionV1(
                _SESSION_TOKEN,
                task_plan=item.task_plan,
                run=item.run,
                run_wire=item.run_wire,
                runtime_evidence=item.runtime_evidence,
            )
            for item in self.__pending
        )

    @property
    def batch_root(self) -> Path:
        return self.__batch_root

    def _claim(self) -> None:
        with self.__lock:
            if self.__claimed:
                raise EvaluatorSupervisorError(
                    "invalid_state", "post-verified publication token is already claimed"
                )
            self.__claimed = True

    def __reduce__(self):
        raise TypeError("post-verified values are not serializable")


class FailedDiscoveryExecutionClosureV1:
    """Opaque proof that a non-publishable attempt ended with a fresh snapshot check."""

    __slots__ = ("__accepted_task_ids", "__plan")

    def __init__(
        self,
        token: object,
        *,
        plan: DiscoveryBatchExecutionPlanV2,
        accepted_task_ids: tuple[str, ...],
    ) -> None:
        if token is not _FAILED_CLOSURE_TOKEN:
            raise TypeError("failed execution closures are supervisor-created")
        plan_wire = plan.to_bytes()
        self.__plan = DiscoveryBatchExecutionPlanV2.from_bytes(
            plan_wire,
            expected_plan_sha256=_embedded_sha256_from_canonical_wire(
                plan_wire, field="plan_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(plan_wire).hexdigest(),
        )
        expected_order = tuple(task.task_id for task in self.__plan.tasks)
        if (
            type(accepted_task_ids) is not tuple
            or len(set(accepted_task_ids)) != len(accepted_task_ids)
            or any(task_id not in expected_order for task_id in accepted_task_ids)
            or accepted_task_ids
            != tuple(task_id for task_id in expected_order if task_id in accepted_task_ids)
        ):
            raise EvaluatorSupervisorError(
                "invalid_state", "accepted task closure order is invalid"
            )
        self.__accepted_task_ids = accepted_task_ids

    @property
    def plan(self) -> DiscoveryBatchExecutionPlanV2:
        wire = self.__plan.to_bytes()
        return DiscoveryBatchExecutionPlanV2.from_bytes(
            wire,
            expected_plan_sha256=self.__plan.plan_sha256,
            expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
        )

    @property
    def accepted_task_ids(self) -> tuple[str, ...]:
        return self.__accepted_task_ids

    def __reduce__(self):
        raise TypeError("failed execution closures are not serializable")


class DiscoveryExecutionSession:
    """One-way trusted state from fresh pre-verification to post-verification."""

    __slots__ = (
        "__batch_root",
        "__claimed_launches",
        "__expected_key_id",
        "__expected_manifest_sha256",
        "__key",
        "__launches",
        "__lock",
        "__pending",
        "__plan",
        "__policy",
        "__replay_wires",
        "__state",
    )

    def __init__(
        self,
        token: object,
        *,
        batch_root: Path,
        expected_manifest_sha256: str,
        expected_key_id: str,
        key: bytearray,
        policy: SnapshotPolicy,
        plan: DiscoveryBatchExecutionPlanV2,
        handoffs: tuple[WorkerHandoffV2, ...],
        replay_configs: tuple[tuple[OciReplayConfigV1, OciReplayConfigV1], ...],
    ) -> None:
        if token is not _SESSION_TOKEN:
            raise TypeError("execution sessions are supervisor-created")
        if type(plan) is not DiscoveryBatchExecutionPlanV2:
            raise EvaluatorSupervisorError(
                "invalid_plan", "execution session plan has an invalid exact type"
            )
        plan_payload = plan.to_bytes()
        frozen_plan = DiscoveryBatchExecutionPlanV2.from_bytes(
            plan_payload,
            expected_plan_sha256=_embedded_sha256_from_canonical_wire(
                plan_payload, field="plan_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(plan_payload).hexdigest(),
        )
        if type(handoffs) is not tuple or len(handoffs) != len(frozen_plan.tasks):
            raise EvaluatorSupervisorError(
                "invalid_plan", "execution handoffs do not cover the frozen plan"
            )
        if type(replay_configs) is not tuple or len(replay_configs) != len(
            frozen_plan.tasks
        ):
            raise EvaluatorSupervisorError(
                "invalid_plan", "execution replay inputs do not cover the frozen plan"
            )
        replay_wires: dict[str, tuple[bytes, bytes]] = {}
        for task_plan, pair in zip(frozen_plan.tasks, replay_configs, strict=True):
            if type(pair) is not tuple or len(pair) != 2:
                raise EvaluatorSupervisorError(
                    "invalid_plan", "execution replay pair is invalid"
                )
            d2, d3 = pair
            if type(d2) is not OciReplayConfigV1 or type(d3) is not OciReplayConfigV1:
                raise EvaluatorSupervisorError(
                    "invalid_plan", "execution replay values have invalid exact types"
                )
            try:
                d2_wire = d2.to_bytes()
                d3_wire = d3.to_bytes()
                d2 = OciReplayConfigV1.from_bytes(d2_wire)
                d3 = OciReplayConfigV1.from_bytes(d3_wire)
            except (AttributeError, OciWorkerEntryError, TypeError, ValueError):
                raise EvaluatorSupervisorError(
                    "invalid_plan", "execution replay values did not normalize"
                ) from None
            if (
                d2.task_id != task_plan.task_id
                or d3.task_id != task_plan.task_id
                or d2.role != "d2"
                or d3.role != "d3"
                or d2.backend_id != frozen_plan.execution_policy.d2_backend_id
                or d2.model_id != frozen_plan.execution_policy.d2_model_id
                or d3.backend_id != frozen_plan.execution_policy.d3_backend_id
                or d3.model_id != frozen_plan.execution_policy.d3_model_id
                or d2.config_sha256 != task_plan.d2_replay_sha256
                or d2.wire_sha256 != task_plan.d2_replay_wire_sha256
                or d3.config_sha256 != task_plan.d3_replay_sha256
                or d3.wire_sha256 != task_plan.d3_replay_wire_sha256
            ):
                raise EvaluatorSupervisorError(
                    "invalid_plan", "execution replay values do not bind the task plan"
                )
            replay_wires[task_plan.task_id] = (d2_wire, d3_wire)
        self.__batch_root = batch_root
        self.__expected_manifest_sha256 = expected_manifest_sha256
        self.__expected_key_id = expected_key_id
        self.__key = key
        self.__policy = policy
        self.__plan = frozen_plan
        self.__replay_wires = replay_wires
        self.__lock = threading.RLock()
        self.__pending: dict[str, PendingTaskExecutionV1] = {}
        self.__claimed_launches: set[str] = set()
        self.__state = "prepared"
        self.__launches = {
            task_plan.task_id: WorkerTaskLaunchV1(
                _SESSION_TOKEN,
                task_plan=task_plan,
                handoff=handoff,
                tree_root=batch_root
                / "bundles"
                / task_plan.task_id
                / "tree",
            )
            for task_plan, handoff in zip(
                frozen_plan.tasks, handoffs, strict=True
            )
        }

    @property
    def plan(self) -> DiscoveryBatchExecutionPlanV2:
        wire = self.__plan.to_bytes()
        return DiscoveryBatchExecutionPlanV2.from_bytes(
            wire,
            expected_plan_sha256=_embedded_sha256_from_canonical_wire(
                wire, field="plan_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
        )

    @property
    def state(self) -> str:
        with self.__lock:
            return self.__state

    def _require_prepared(self) -> None:
        if self.__state != "prepared":
            raise EvaluatorSupervisorError(
                "invalid_state", "execution session is not active"
            )

    def _fail(self) -> None:
        _zero_key(self.__key)
        self.__state = "failed"

    def launch_for(self, task_id: str) -> WorkerTaskLaunchV1:
        if type(task_id) is not str:
            raise EvaluatorSupervisorError(
                "invalid_argument", "task_id must be an exact string"
            )
        with self.__lock:
            self._require_prepared()
            try:
                launch = self.__launches[task_id]
            except KeyError:
                raise EvaluatorSupervisorError(
                    "unknown_task", "task is not a member of this execution plan"
                ) from None
            if task_id in self.__claimed_launches:
                raise EvaluatorSupervisorError(
                    "duplicate_launch", "task launch was already claimed"
                )
            self.__claimed_launches.add(task_id)
            payload = launch.handoff_payload
            handoff = WorkerHandoffV2.from_bytes(
                payload,
                expected_sha256=launch.handoff_sha256,
                expected_wire_sha256=launch.handoff_wire_sha256,
            )
            return WorkerTaskLaunchV1(
                _SESSION_TOKEN,
                task_plan=launch.task_plan,
                handoff=handoff,
                tree_root=launch.tree_root,
            )

    def replay_for(
        self, task_id: str
    ) -> tuple[OciReplayConfigV1, OciReplayConfigV1]:
        """Return detached canonical replay values already bound into the plan."""

        if type(task_id) is not str:
            raise EvaluatorSupervisorError(
                "invalid_argument", "task_id must be an exact string"
            )
        with self.__lock:
            self._require_prepared()
            try:
                d2_wire, d3_wire = self.__replay_wires[task_id]
            except KeyError:
                raise EvaluatorSupervisorError(
                    "unknown_task", "task is not a member of this execution plan"
                ) from None
            try:
                return (
                    OciReplayConfigV1.from_bytes(d2_wire),
                    OciReplayConfigV1.from_bytes(d3_wire),
                )
            except (OciWorkerEntryError, TypeError, ValueError):
                self._fail()
                raise EvaluatorSupervisorError(
                    "invalid_state", "frozen task replay configuration changed"
                ) from None

    def claim_task_execution(
        self, task_id: str
    ) -> tuple[
        WorkerTaskLaunchV1,
        OciReplayConfigV1,
        OciReplayConfigV1,
    ]:
        """Atomically claim the sole launch and its frozen replay pair."""

        with self.__lock:
            d2, d3 = self.replay_for(task_id)
            launch = self.launch_for(task_id)
            return launch, d2, d3

    def accept_worker_output(
        self,
        completion: CompletedWorkerExecutionV1,
    ) -> PendingTaskExecutionV1:
        with self.__lock:
            self._require_prepared()
            if type(completion) is not CompletedWorkerExecutionV1:
                self._fail()
                raise EvaluatorSupervisorError(
                    "invalid_argument", "worker completion envelope is invalid"
                )
            try:
                task_id = completion.task_id
                if task_id in self.__pending:
                    raise EvaluatorSupervisorError(
                        "duplicate_output", "worker output repeats a task"
                    )
                launch = self.__launches.get(task_id)
                if launch is None:
                    raise EvaluatorSupervisorError(
                        "unknown_task", "worker output task is not in the plan"
                    )
                if task_id not in self.__claimed_launches:
                    raise EvaluatorSupervisorError(
                        "invalid_output", "worker output has no claimed launch"
                    )
                claimed = completion._claim_for_plan(launch.task_plan)
                run_wire = claimed.run_wire
                if (
                    type(run_wire) is not bytes
                    or not run_wire
                    or len(run_wire) > SOURCE_DISCOVERY_RUN_MAX_WIRE_BYTES
                ):
                    raise EvaluatorSupervisorError(
                        "invalid_output", "worker run wire has an invalid size"
                    )
                run = SourceDiscoveryRunV1.from_wire(run_wire)
                if run.to_wire() != run_wire or run.task != launch.task:
                    raise EvaluatorSupervisorError(
                        "task_binding_mismatch",
                        "worker output does not match its execution task",
                    )
                pending = PendingTaskExecutionV1(
                    _SESSION_TOKEN,
                    task_plan=launch.task_plan,
                    run=run,
                    run_wire=run_wire,
                    runtime_evidence=claimed.runtime_evidence,
                )
                self.__pending[task_id] = pending
                return pending
            except EvaluatorSupervisorError:
                self._fail()
                raise
            except WorkerCompletionError as error:
                self._fail()
                raise EvaluatorSupervisorError(
                    "invalid_output", "worker completion did not bind to the plan"
                ) from error
            except (AttributeError, KeyError, RecursionError, RuntimeError, TypeError, ValueError):
                self._fail()
                raise EvaluatorSupervisorError(
                    "invalid_output", "worker output did not pass strict normalization"
                ) from None
            except BaseException:
                self._fail()
                raise

    def postverify(self) -> PostVerifiedDiscoveryExecutionV1:
        with self.__lock:
            self._require_prepared()
            expected_ids = tuple(task.task_id for task in self.__plan.tasks)
            if set(self.__pending) != set(expected_ids):
                self._fail()
                raise EvaluatorSupervisorError(
                    "incomplete_batch", "worker outputs do not cover the plan in order"
                )
            try:
                summary = verify_snapshot_batch(
                    self.__batch_root,
                    expected_manifest_sha256=self.__expected_manifest_sha256,
                    attestation_key=self.__key,
                    expected_key_id=self.__expected_key_id,
                    policy=self.__policy,
                )
                post_binding = SnapshotBatchBindingV2.from_verified_summary(
                    summary, snapshot_policy=self.__policy
                )
                if post_binding != self.__plan.batch:
                    raise EvaluatorSupervisorError(
                        "postverify_mismatch",
                        "post-run batch binding differs from the execution plan",
                    )
                pending = tuple(self.__pending[task_id] for task_id in expected_ids)
                token = PostVerifiedDiscoveryExecutionV1(
                    _POSTVERIFIED_TOKEN,
                    batch_root=self.__batch_root,
                    plan=self.__plan,
                    pending=pending,
                )
                _zero_key(self.__key)
                self.__state = "postverified"
                return token
            except EvaluatorSupervisorError:
                self._fail()
                raise
            except (
                EvaluatorContractError,
                SnapshotBatchError,
                AttributeError,
                OSError,
                TypeError,
                ValueError,
            ):
                self._fail()
                raise EvaluatorSupervisorError(
                    "postverify_failed", "post-run batch verification did not close"
                ) from None
            except BaseException:
                self._fail()
                raise

    def close_failed_attempt(self) -> FailedDiscoveryExecutionClosureV1:
        """Reverify source after a clean partial attempt without granting publication."""

        with self.__lock:
            self._require_prepared()
            expected_ids = tuple(task.task_id for task in self.__plan.tasks)
            if set(self.__pending) == set(expected_ids):
                self._fail()
                raise EvaluatorSupervisorError(
                    "invalid_state", "complete execution must use success post-verification"
                )
            try:
                summary = verify_snapshot_batch(
                    self.__batch_root,
                    expected_manifest_sha256=self.__expected_manifest_sha256,
                    attestation_key=self.__key,
                    expected_key_id=self.__expected_key_id,
                    policy=self.__policy,
                )
                post_binding = SnapshotBatchBindingV2.from_verified_summary(
                    summary, snapshot_policy=self.__policy
                )
                if post_binding != self.__plan.batch:
                    raise EvaluatorSupervisorError(
                        "postverify_mismatch",
                        "post-run batch binding differs from the execution plan",
                    )
                accepted = tuple(
                    task_id for task_id in expected_ids if task_id in self.__pending
                )
                closure = FailedDiscoveryExecutionClosureV1(
                    _FAILED_CLOSURE_TOKEN,
                    plan=self.__plan,
                    accepted_task_ids=accepted,
                )
                _zero_key(self.__key)
                self.__state = "failed_closed"
                return closure
            except EvaluatorSupervisorError:
                self._fail()
                raise
            except (
                EvaluatorContractError,
                SnapshotBatchError,
                AttributeError,
                OSError,
                TypeError,
                ValueError,
            ):
                self._fail()
                raise EvaluatorSupervisorError(
                    "postverify_failed", "failed attempt snapshot verification did not close"
                ) from None
            except BaseException:
                self._fail()
                raise

    def abort(self) -> None:
        with self.__lock:
            if self.__state == "prepared":
                _zero_key(self.__key)
                self.__state = "aborted"

    def __reduce__(self):
        raise TypeError("execution sessions are not serializable")

    def __del__(self) -> None:
        try:
            self.abort()
        except BaseException:
            pass


def prepare_discovery_execution_plan_v1(
    batch_root: str | os.PathLike[str],
    *,
    expected_batch_manifest_sha256: str,
    attestation_key: bytes | bytearray | memoryview,
    expected_key_id: str,
    execution_policy: ExecutionPolicyBindingV1,
    task_replay_configs: tuple[
        tuple[OciReplayConfigV1, OciReplayConfigV1], ...
    ],
    snapshot_policy: SnapshotPolicy = DEFAULT_SNAPSHOT_POLICY,
    d2_budget_limits: Limits = DEFAULT_D2_WORKER_BUDGET_LIMITS,
    d3_budget_limits: Limits = DEFAULT_D3_WORKER_BUDGET_LIMITS,
    tree_limits: SealedTreeAccessLimits = DEFAULT_SEALED_TREE_ACCESS_LIMITS,
) -> DiscoveryExecutionSession:
    """Freshly verify a complete batch and derive all fixed launch inputs."""

    if (
        type(expected_batch_manifest_sha256) is not str
        or _SHA256_RE.fullmatch(expected_batch_manifest_sha256) is None
        or type(expected_key_id) is not str
        or not expected_key_id
        or not isinstance(attestation_key, (bytes, bytearray, memoryview))
    ):
        raise EvaluatorSupervisorError(
            "invalid_argument", "batch verification pins are invalid"
        )
    try:
        key_size = (
            attestation_key.nbytes
            if isinstance(attestation_key, memoryview)
            else len(attestation_key)
        )
    except (TypeError, ValueError):
        raise EvaluatorSupervisorError(
            "invalid_argument", "attestation material is unreadable"
        ) from None
    if not _MIN_KEY_BYTES <= key_size <= _MAX_KEY_BYTES:
        raise EvaluatorSupervisorError(
            "invalid_argument", "attestation material is outside its byte limit"
        )
    try:
        key = bytearray(attestation_key)
    except (BufferError, TypeError, ValueError):
        raise EvaluatorSupervisorError(
            "invalid_argument", "attestation material must be contiguous bytes"
        ) from None
    try:
        policy = _canonical_snapshot_policy(snapshot_policy)
        d2_limits = _canonical_budget_limits(d2_budget_limits)
        d3_limits = _canonical_budget_limits(d3_budget_limits)
        source_limits = _canonical_tree_limits(tree_limits)
        if (
            d2_limits.max_llm_calls
            > DEFAULT_D2_WORKER_BUDGET_LIMITS.max_llm_calls
            or d2_limits.max_tool_calls
            > DEFAULT_D2_WORKER_BUDGET_LIMITS.max_tool_calls
            or d2_limits.max_repair_iterations != 0
            or d3_limits.max_llm_calls
            > DEFAULT_D3_WORKER_BUDGET_LIMITS.max_llm_calls
            or d3_limits.max_tool_calls
            > DEFAULT_D3_WORKER_BUDGET_LIMITS.max_tool_calls
            or d3_limits.max_repair_iterations != 0
            or source_limits.max_inventory_calls
            > DEFAULT_SEALED_TREE_ACCESS_LIMITS.max_inventory_calls
            or source_limits.max_read_calls
            > DEFAULT_SEALED_TREE_ACCESS_LIMITS.max_read_calls
            or source_limits.max_bytes_per_read
            > DEFAULT_SEALED_TREE_ACCESS_LIMITS.max_bytes_per_read
            or source_limits.max_total_bytes_read
            > DEFAULT_SEALED_TREE_ACCESS_LIMITS.max_total_bytes_read
        ):
            raise EvaluatorSupervisorError(
                "policy_mismatch", "worker limits broaden the fixed execution policy"
            )
        runtime_policy = _canonical_execution_policy(
            execution_policy,
            d2_budget_limits=d2_limits,
            d3_budget_limits=d3_limits,
            tree_limits=source_limits,
        )
        replay_configs = _canonical_task_replay_configs(
            task_replay_configs, execution_policy=runtime_policy
        )
        supplied_root = Path(os.path.abspath(os.fspath(batch_root)))
        expected_root = _canonical_existing_path(
            supplied_root, directory=True, status=4
        )
        summary = verify_snapshot_batch(
            supplied_root,
            expected_manifest_sha256=expected_batch_manifest_sha256,
            attestation_key=key,
            expected_key_id=expected_key_id,
            policy=policy,
        )
        if type(summary) is not SnapshotBatchSummary:
            raise EvaluatorSupervisorError(
                "batch_verification_failed", "batch verifier returned an invalid summary"
            )
        if (
            type(summary.batch_root) is not type(Path())
            or summary.batch_root != expected_root
        ):
            raise EvaluatorSupervisorError(
                "batch_binding_mismatch", "batch verifier returned a different root"
            )
        binding = SnapshotBatchBindingV2.from_verified_summary(
            summary, snapshot_policy=policy
        )
        if (
            binding.batch_manifest_sha256 != expected_batch_manifest_sha256
            or binding.attestation_key_id != expected_key_id
        ):
            raise EvaluatorSupervisorError(
                "batch_binding_mismatch", "verified batch does not match its pins"
            )
        handoffs: list[WorkerHandoffV2] = []
        task_plans: list[DiscoveryTaskExecutionPlanV1] = []
        if len(replay_configs) != len(binding.tasks):
            raise EvaluatorSupervisorError(
                "invalid_binding", "task replay configurations do not cover the batch"
            )
        for member, (d2_replay, d3_replay) in zip(
            binding.tasks, replay_configs, strict=True
        ):
            if d2_replay.task_id != member.task_id or d3_replay.task_id != member.task_id:
                raise EvaluatorSupervisorError(
                    "invalid_binding", "task replay configuration order differs from the batch"
                )
            task = _task_from_member(member)
            handoff = build_worker_handoff(
                task,
                summary.batch_root / member.bundle_path,
                attestation_key=key,
                expected_key_id=expected_key_id,
                policy=policy,
            )
            task_plan = DiscoveryTaskExecutionPlanV1.from_handoff(
                binding,
                runtime_policy,
                handoff,
                d2_replay_sha256=d2_replay.config_sha256,
                d2_replay_wire_sha256=d2_replay.wire_sha256,
                d3_replay_sha256=d3_replay.config_sha256,
                d3_replay_wire_sha256=d3_replay.wire_sha256,
            )
            handoffs.append(handoff)
            task_plans.append(task_plan)
        plan = DiscoveryBatchExecutionPlanV2(
            batch=binding,
            execution_policy=runtime_policy,
            tasks=tuple(task_plans),
        )
        return DiscoveryExecutionSession(
            _SESSION_TOKEN,
            batch_root=summary.batch_root,
            expected_manifest_sha256=expected_batch_manifest_sha256,
            expected_key_id=expected_key_id,
            key=key,
            policy=policy,
            plan=plan,
            handoffs=tuple(handoffs),
            replay_configs=replay_configs,
        )
    except EvaluatorSupervisorError:
        _zero_key(key)
        raise
    except (EvaluatorContractError, SnapshotBatchError, WorkerHandoffError) as error:
        _zero_key(key)
        raise EvaluatorSupervisorError(
            "batch_verification_failed",
            "execution plan could not be derived from the verified batch",
        ) from error
    except (AttributeError, OSError, TypeError, ValueError) as error:
        _zero_key(key)
        raise EvaluatorSupervisorError(
            "batch_verification_failed", "batch preparation did not close"
        ) from error
    except BaseException:
        _zero_key(key)
        raise


def accept_discovery_worker_output_v1(
    session: DiscoveryExecutionSession,
    *,
    completion: CompletedWorkerExecutionV1,
) -> PendingTaskExecutionV1:
    if type(session) is not DiscoveryExecutionSession:
        raise EvaluatorSupervisorError(
            "invalid_argument", "session must have an exact supervisor type"
        )
    return session.accept_worker_output(completion)


def postverify_discovery_execution_v1(
    session: DiscoveryExecutionSession,
) -> PostVerifiedDiscoveryExecutionV1:
    if type(session) is not DiscoveryExecutionSession:
        raise EvaluatorSupervisorError(
            "invalid_argument", "session must have an exact supervisor type"
        )
    return session.postverify()


def close_failed_discovery_execution_v1(
    session: DiscoveryExecutionSession,
) -> FailedDiscoveryExecutionClosureV1:
    if type(session) is not DiscoveryExecutionSession:
        raise EvaluatorSupervisorError(
            "invalid_argument", "session must have an exact supervisor type"
        )
    return session.close_failed_attempt()


def _path_relation(left: Path, right: Path) -> bool:
    try:
        left_name = os.path.normcase(os.path.abspath(os.fspath(left)))
        right_name = os.path.normcase(os.path.abspath(os.fspath(right)))
        return os.path.commonpath((left_name, right_name)) == right_name
    except (OSError, TypeError, ValueError):
        return False


def _is_reparse(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _assert_publication_chain(
    chain: tuple[tuple[Path, tuple[int, int]], ...]
) -> None:
    for component, identity in chain:
        state = os.lstat(component)
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
            or (state.st_dev, state.st_ino) != identity
        ):
            raise EvaluatorSupervisorError(
                "output_parent_changed", "publication parent chain changed"
            )


def _publication_output_path(
    value: str | os.PathLike[str], *, protected: Path
) -> tuple[Path, tuple[tuple[Path, tuple[int, int]], ...]]:
    if type(value) not in {str, type(Path())}:
        raise EvaluatorSupervisorError(
            "invalid_argument", "publication output must be an exact path value"
        )
    try:
        output = Path(os.path.abspath(os.fspath(value)))
    except (OSError, TypeError, ValueError):
        raise EvaluatorSupervisorError(
            "invalid_argument", "publication output path is invalid"
        ) from None
    if not output.name or output.name in {".", ".."}:
        raise EvaluatorSupervisorError(
            "invalid_argument", "publication output name is invalid"
        )
    checked_chain: list[tuple[Path, tuple[int, int]]] = []
    try:
        for component in reversed((output.parent, *output.parent.parents)):
            state = os.lstat(component)
            if (
                not stat.S_ISDIR(state.st_mode)
                or stat.S_ISLNK(state.st_mode)
                or _is_reparse(state)
            ):
                raise EvaluatorSupervisorError(
                    "unsafe_output", "publication output parent chain is unsafe"
                )
            checked_chain.append(
                (component, (state.st_dev, state.st_ino))
            )
    except EvaluatorSupervisorError:
        raise
    except OSError as error:
        raise EvaluatorSupervisorError(
            "unsafe_output", "publication output parent is unavailable"
        ) from error
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise EvaluatorSupervisorError(
            "unsafe_output", "publication output state is unavailable"
        ) from error
    else:
        raise EvaluatorSupervisorError(
            "output_exists", "publication output already exists"
        )
    try:
        output_resolved = output.parent.resolve(strict=True) / output.name
        protected_resolved = protected.resolve(strict=True)
    except OSError:
        raise EvaluatorSupervisorError(
            "unsafe_output", "publication path resolution failed"
        ) from None
    if (
        _path_relation(output, protected)
        or _path_relation(protected, output)
        or _path_relation(output_resolved, protected_resolved)
        or _path_relation(protected_resolved, output_resolved)
    ):
        raise EvaluatorSupervisorError(
            "path_overlap", "publication output overlaps the verified batch"
        )
    return output, tuple(checked_chain)


def _write_exact_file(path: Path, payload: bytes) -> str:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count < 1:
                raise OSError("short execution contract write")
            written += count
        os.fsync(descriptor)
        state = os.fstat(descriptor)
        if (
            not stat.S_ISREG(state.st_mode)
            or state.st_size != len(payload)
            or state.st_nlink != 1
        ):
            raise OSError("execution contract file changed while writing")
    finally:
        os.close(descriptor)
    return hashlib.sha256(payload).hexdigest()


def _sync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        if os.name == "posix":
            raise
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_bounded_regular_file(path: Path, *, maximum_bytes: int) -> bytes:
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or before.st_size > maximum_bytes
    ):
        raise EvaluatorSupervisorError(
            "staging_changed", "execution contract file is unsafe or oversized"
        )
    if os.name == "nt":
        try:
            _windows_assert_no_named_streams(path)
        except SealedSnapshotError:
            raise EvaluatorSupervisorError(
                "staging_changed", "execution contract file has alternate streams"
            ) from None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise EvaluatorSupervisorError(
                "staging_changed", "execution contract changed while opening"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise EvaluatorSupervisorError(
                    "staging_changed", "execution contract exceeds its byte limit"
                )
        finished = os.fstat(descriptor)
        if (
            (finished.st_dev, finished.st_ino, finished.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_size)
            or total != opened.st_size
        ):
            raise EvaluatorSupervisorError(
                "staging_changed", "execution contract changed while reading"
            )
    finally:
        os.close(descriptor)
    after = os.lstat(path)
    if (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ) != (before.st_dev, before.st_ino, before.st_size):
        raise EvaluatorSupervisorError(
            "staging_changed", "execution contract name changed while reading"
        )
    return b"".join(chunks)


def _materialized_identity(root: Path) -> tuple[tuple[object, ...], ...]:
    """Capture a bounded, link-free identity map for final publication comparison."""

    records: list[tuple[object, ...]] = []
    pending = [(root, "")]
    total_bytes = 0
    while pending:
        directory, relative = pending.pop()
        state = os.lstat(directory)
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
        ):
            raise EvaluatorSupervisorError(
                "staging_changed", "execution publication contains an unsafe directory"
            )
        records.append(
            (
                "directory",
                relative,
                state.st_dev,
                state.st_ino,
                *(
                    ()
                    if not relative
                    else (
                        getattr(state, "st_mtime_ns", None),
                        getattr(state, "st_ctime_ns", None),
                    )
                ),
            )
        )
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise EvaluatorSupervisorError(
                "staging_changed", "execution publication cannot be scanned"
            ) from error
        for entry in reversed(entries):
            child_relative = entry.name if not relative else f"{relative}/{entry.name}"
            child = directory / entry.name
            child_state = os.lstat(child)
            if stat.S_ISDIR(child_state.st_mode) and not _is_reparse(child_state):
                pending.append((child, child_relative))
                continue
            if (
                not stat.S_ISREG(child_state.st_mode)
                or stat.S_ISLNK(child_state.st_mode)
                or _is_reparse(child_state)
                or child_state.st_nlink != 1
            ):
                raise EvaluatorSupervisorError(
                    "staging_changed", "execution publication contains an unsafe file"
                )
            if os.name == "nt":
                try:
                    _windows_assert_no_named_streams(child)
                except SealedSnapshotError:
                    raise EvaluatorSupervisorError(
                        "staging_changed", "execution publication has alternate streams"
                    ) from None
            total_bytes += child_state.st_size
            if total_bytes > 512 * 1024 * 1024:
                raise EvaluatorSupervisorError(
                    "staging_changed",
                    "execution publication exceeds its total byte limit",
                )
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(child, flags)
            try:
                opened = os.fstat(descriptor)
                opened_identity = (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    getattr(opened, "st_mtime_ns", None),
                )
                expected_open_identity = (
                    child_state.st_dev,
                    child_state.st_ino,
                    child_state.st_size,
                    getattr(child_state, "st_mtime_ns", None),
                )
                expected_name_identity = (
                    *expected_open_identity,
                    getattr(child_state, "st_ctime_ns", None),
                )
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or _is_reparse(opened)
                    or opened.st_nlink != 1
                    or opened_identity != expected_open_identity
                ):
                    raise EvaluatorSupervisorError(
                        "staging_changed",
                        "execution publication file changed while opening",
                    )
                digest = hashlib.sha256()
                consumed = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    consumed += len(chunk)
                    digest.update(chunk)
                finished = os.fstat(descriptor)
                if (
                    consumed != opened.st_size
                    or (
                        finished.st_dev,
                        finished.st_ino,
                        finished.st_size,
                        getattr(finished, "st_mtime_ns", None),
                    )
                    != opened_identity
                ):
                    raise EvaluatorSupervisorError(
                        "staging_changed",
                        "execution publication file changed while hashing",
                    )
            finally:
                os.close(descriptor)
            named_after = os.lstat(child)
            if (
                named_after.st_dev,
                named_after.st_ino,
                named_after.st_size,
                getattr(named_after, "st_mtime_ns", None),
                getattr(named_after, "st_ctime_ns", None),
            ) != expected_name_identity:
                raise EvaluatorSupervisorError(
                    "staging_changed",
                    "execution publication file name changed while hashing",
                )
            records.append(
                (
                    "file",
                    child_relative,
                    *expected_name_identity,
                    digest.hexdigest(),
                )
            )
        if len(records) > 4096:
            raise EvaluatorSupervisorError(
                "staging_changed", "execution publication exceeds its node limit"
            )
    return tuple(sorted(records, key=lambda item: (str(item[1]), str(item[0]))))


def _publish_postverified_discovery_execution_v1_impl(
    token: PostVerifiedDiscoveryExecutionV1,
    output_root: str | os.PathLike[str],
    *,
    success_authority: E4SuccessReceiptAuthorityV2 | None,
) -> DiscoveryBatchExecutionReceiptV2 | E4BatchSuccessReceiptV2:
    """Publish every result, index, plan, and receipt in one outer transaction."""

    if type(token) is not PostVerifiedDiscoveryExecutionV1:
        raise EvaluatorSupervisorError(
            "invalid_argument", "publication requires an exact post-verified token"
        )
    if success_authority is not None and type(
        success_authority
    ) is not E4SuccessReceiptAuthorityV2:
        raise EvaluatorSupervisorError(
            "invalid_argument", "scheduled publication authority has an invalid type"
        )
    output, parent_chain = _publication_output_path(
        output_root, protected=token.batch_root
    )
    token._claim()
    parent = output.parent
    staging: Path | None = None
    staging_identity: tuple[int, int] | None = None
    committed = False
    plan = token.plan
    pending = token.pending
    try:
        for _ in range(128):
            candidate = parent / (
                f".{output.name}.{secrets.token_hex(16)}.execution-staging"
            )
            try:
                candidate.mkdir(mode=0o700)
            except FileExistsError:
                continue
            staging = candidate
            break
        if staging is None:
            raise OSError("could not allocate execution staging directory")
        state = os.lstat(staging)
        if not stat.S_ISDIR(state.st_mode):
            raise OSError("execution staging is not a directory")
        staging_identity = (state.st_dev, state.st_ino)
        bundles_root = staging / "bundles"
        bundles_root.mkdir(mode=0o700)

        verified_results = []
        bundle_digests: list[ArtifactBundleDigest] = []
        task_specs: list[SnapshotTaskSpec] = []
        for member, task_pending in zip(
            plan.batch.tasks, pending, strict=True
        ):
            if task_pending.task_plan.task_id != member.task_id:
                raise EvaluatorSupervisorError(
                    "task_binding_mismatch", "pending result order differs from the plan"
                )
            output_bundle = bundles_root / member.task_id
            verified = write_discovery_result_bundle(
                output_bundle,
                task_pending.run,
                protected_paths=(token.batch_root,),
            )
            if (
                verified.result != task_pending.run.discovery_result
                or verified.result.task.task_id != member.task_id
            ):
                raise EvaluatorSupervisorError(
                    "result_binding_mismatch", "published result differs from its run"
                )
            verified_results.append(verified)
            bundle_digests.append(
                ArtifactBundleDigest(
                    task_id=member.task_id,
                    dataset_sha256=verified.dataset_sha256,
                )
            )
            task_specs.append(
                SnapshotTaskSpec(
                    task_id=member.task_id,
                    repo_url=member.repo_url,
                    commit=member.commit,
                    split=member.split,
                    instruction_id=member.instruction_id,
                )
            )

        index_path = staging / "artifact-index.json"
        index_sha256 = write_artifact_bundle_index(
            index_path,
            split=plan.batch.split,
            tasks=tuple(task_specs),
            bundles=tuple(bundle_digests),
            protected_paths=(token.batch_root,),
        )
        task_receipts = tuple(
            DiscoveryTaskExecutionReceiptV1(
                task_plan_sha256=task_pending.task_plan.plan_sha256,
                execution_policy_sha256=plan.execution_policy.policy_sha256,
                task_id=task_pending.task_plan.task_id,
                snapshot_id=task_pending.task_plan.snapshot_id,
                run_sha256=task_pending.run.run_sha256,
                run_wire_sha256=task_pending.run_wire_sha256,
                discovery_result_sha256=task_pending.discovery_result_sha256,
                dataset_sha256=verified.dataset_sha256,
                artifact_index_sha256=index_sha256,
                runtime_evidence=task_pending.runtime_evidence,
            )
            for task_pending, verified in zip(
                pending, verified_results, strict=True
            )
        )
        receipt = DiscoveryBatchExecutionReceiptV2(
            plan=plan,
            pre_batch_binding_sha256=plan.batch.binding_sha256,
            post_batch_binding_sha256=plan.batch.binding_sha256,
            artifact_index_sha256=index_sha256,
            tasks=task_receipts,
        )
        success_receipt = (
            None
            if success_authority is None
            else claim_e4_success_receipt_authority_v2(
                success_authority, receipt
            )
        )
        plan_payload = plan.to_bytes()
        receipt_payload = receipt.to_bytes()
        _write_exact_file(staging / "execution-plan.json", plan_payload)
        _write_exact_file(staging / "execution-receipt.json", receipt_payload)
        if success_receipt is not None:
            _write_exact_file(
                staging / E4_SUCCESS_RECEIPT_FILENAME,
                success_receipt.to_bytes(),
            )

        # Full readback while the tree is still unpublished.
        loaded_index = load_artifact_bundle_index(
            index_path,
            expected_sha256=index_sha256,
            split=plan.batch.split,
            tasks=tuple(task_specs),
        )
        if tuple(loaded_index.bundles) != tuple(bundle_digests):
            raise EvaluatorSupervisorError(
                "index_binding_mismatch", "artifact index differs from result bundles"
            )
        for member, verified in zip(
            plan.batch.tasks, verified_results, strict=True
        ):
            readback = read_discovery_result_bundle(
                bundles_root / member.task_id,
                expected_dataset_sha256=verified.dataset_sha256,
                expected_task_id=member.task_id,
                protected_paths=(token.batch_root,),
            )
            if readback != verified:
                raise EvaluatorSupervisorError(
                    "result_binding_mismatch", "result bundle readback changed"
                )
        parsed_plan = DiscoveryBatchExecutionPlanV2.from_bytes(
            _read_bounded_regular_file(
                staging / "execution-plan.json",
                maximum_bytes=EVALUATOR_CONTRACT_MAX_WIRE_BYTES,
            ),
            expected_plan_sha256=plan.plan_sha256,
            expected_wire_sha256=plan.wire_sha256,
        )
        parsed_receipt = DiscoveryBatchExecutionReceiptV2.from_bytes(
            _read_bounded_regular_file(
                staging / "execution-receipt.json",
                maximum_bytes=EVALUATOR_CONTRACT_MAX_WIRE_BYTES,
            ),
            expected_receipt_sha256=receipt.receipt_sha256,
            expected_wire_sha256=receipt.wire_sha256,
        )
        if parsed_plan != plan or parsed_receipt != receipt:
            raise EvaluatorSupervisorError(
                "receipt_binding_mismatch", "execution contracts failed readback"
            )
        if success_receipt is not None:
            parsed_success_receipt = E4BatchSuccessReceiptV2.from_bytes(
                _read_bounded_regular_file(
                    staging / E4_SUCCESS_RECEIPT_FILENAME,
                    maximum_bytes=E4_SUCCESS_RECEIPT_MAX_BYTES,
                ),
                expected_receipt_sha256=success_receipt.receipt_sha256,
                expected_wire_sha256=success_receipt.wire_sha256,
            )
            if parsed_success_receipt != success_receipt:
                raise EvaluatorSupervisorError(
                    "receipt_binding_mismatch",
                    "E4 success receipt failed staging readback",
                )
        expected_root_members = {
            "artifact-index.json",
            "bundles",
            "execution-plan.json",
            "execution-receipt.json",
        }
        if success_receipt is not None:
            expected_root_members.add(E4_SUCCESS_RECEIPT_FILENAME)
        if {item.name for item in os.scandir(staging)} != expected_root_members:
            raise EvaluatorSupervisorError(
                "staging_changed", "execution staging has unexpected members"
            )
        if {item.name for item in os.scandir(bundles_root)} != {
            task.task_id for task in plan.tasks
        }:
            raise EvaluatorSupervisorError(
                "staging_changed", "execution bundle membership changed"
            )
        _sync_directory(bundles_root)
        _sync_directory(staging)
        _assert_publication_chain(parent_chain)
        final_staging_state = os.lstat(staging)
        if (
            final_staging_state.st_dev,
            final_staging_state.st_ino,
        ) != staging_identity:
            raise EvaluatorSupervisorError(
                "staging_changed", "execution staging identity changed"
            )
        pre_publication_identity = _materialized_identity(staging)
        _assert_publication_chain(parent_chain)
        final_staging_state = os.lstat(staging)
        if (
            final_staging_state.st_dev,
            final_staging_state.st_ino,
        ) != staging_identity:
            raise EvaluatorSupervisorError(
                "staging_changed", "execution staging identity changed"
            )
        try:
            _rename_directory_noreplace(staging, output)
        except BaseException as error:
            try:
                published_after_error = os.lstat(output)
                committed = (
                    published_after_error.st_dev,
                    published_after_error.st_ino,
                ) == staging_identity
            except OSError:
                committed = False
            if committed and isinstance(error, Exception):
                raise EvaluatorSupervisorError(
                    "publication_uncertain",
                    "execution publication was interrupted at commit",
                    committed=True,
                ) from error
            if committed:
                try:
                    setattr(error, "committed", True)
                except BaseException:
                    pass
            raise
        committed = True
        published = os.lstat(output)
        if (published.st_dev, published.st_ino) != staging_identity:
            raise EvaluatorSupervisorError(
                "publication_uncertain",
                "published execution identity is uncertain",
                committed=True,
            )
        _sync_directory(parent)
        _assert_publication_chain(parent_chain)

        # Only the committed name can be returned as verified.
        final_plan_payload = _read_bounded_regular_file(
            output / "execution-plan.json",
            maximum_bytes=EVALUATOR_CONTRACT_MAX_WIRE_BYTES,
        )
        final_plan = DiscoveryBatchExecutionPlanV2.from_bytes(
            final_plan_payload,
            expected_plan_sha256=plan.plan_sha256,
            expected_wire_sha256=plan.wire_sha256,
        )
        final_receipt_payload = _read_bounded_regular_file(
            output / "execution-receipt.json",
            maximum_bytes=EVALUATOR_CONTRACT_MAX_WIRE_BYTES,
        )
        final_receipt = DiscoveryBatchExecutionReceiptV2.from_bytes(
            final_receipt_payload,
            expected_receipt_sha256=receipt.receipt_sha256,
            expected_wire_sha256=receipt.wire_sha256,
        )
        final_success_receipt = None
        if success_receipt is not None:
            final_success_receipt = E4BatchSuccessReceiptV2.from_bytes(
                _read_bounded_regular_file(
                    output / E4_SUCCESS_RECEIPT_FILENAME,
                    maximum_bytes=E4_SUCCESS_RECEIPT_MAX_BYTES,
                ),
                expected_receipt_sha256=success_receipt.receipt_sha256,
                expected_wire_sha256=success_receipt.wire_sha256,
            )
        for member, verified in zip(
            plan.batch.tasks, verified_results, strict=True
        ):
            final_result = read_discovery_result_bundle(
                output / "bundles" / member.task_id,
                expected_dataset_sha256=verified.dataset_sha256,
                expected_task_id=member.task_id,
                protected_paths=(token.batch_root,),
            )
            if final_result != verified:
                raise EvaluatorSupervisorError(
                    "publication_uncertain",
                    "published result changed after commit",
                    committed=True,
                )
        final_index = load_artifact_bundle_index(
            output / "artifact-index.json",
            expected_sha256=index_sha256,
            split=plan.batch.split,
            tasks=tuple(task_specs),
        )
        if (
            final_plan != plan
            or final_receipt != receipt
            or final_receipt.plan != final_plan
            or final_success_receipt != success_receipt
            or tuple(final_index.bundles) != tuple(bundle_digests)
            or {item.name for item in os.scandir(output)}
            != expected_root_members
            or {
                item.name for item in os.scandir(output / "bundles")
            }
            != {task.task_id for task in plan.tasks}
        ):
            raise EvaluatorSupervisorError(
                "publication_uncertain",
                "published execution closure changed after commit",
                committed=True,
            )
        final_publication_identity = _materialized_identity(output)
        final_output_state = os.lstat(output)
        _assert_publication_chain(parent_chain)
        if (
            final_publication_identity != pre_publication_identity
            or (
                final_output_state.st_dev,
                final_output_state.st_ino,
            )
            != staging_identity
        ):
            raise EvaluatorSupervisorError(
                "publication_uncertain",
                "published execution identity changed after commit",
                committed=True,
            )
        return (
            final_receipt
            if final_success_receipt is None
            else final_success_receipt
        )
    except EvaluatorSupervisorError as error:
        if committed and not error.committed:
            raise EvaluatorSupervisorError(
                error.code, str(error), committed=True
            ) from error
        raise
    except (
        BenchmarkHarnessError,
        DiscoveryReplayError,
        E4ReceiptError,
        EvaluatorContractError,
        AttributeError,
        OSError,
        TypeError,
        ValueError,
    ) as error:
        raise EvaluatorSupervisorError(
            "publication_uncertain" if committed else "publication_failed",
            "execution publication did not close",
            committed=committed,
        ) from error
    except BaseException as error:
        if committed:
            try:
                setattr(error, "committed", True)
            except BaseException:
                pass
        raise
    finally:
        # An unpublished staging tree is retained deliberately.  Python has no
        # atomic recursive conditional delete that is safe against name swaps.
        _ = (staging, staging_identity)


def publish_postverified_discovery_execution_v1(
    token: PostVerifiedDiscoveryExecutionV1,
    output_root: str | os.PathLike[str],
) -> DiscoveryBatchExecutionReceiptV2:
    """Publish an E3 execution receipt without claiming E4 scheduler closure."""

    result = _publish_postverified_discovery_execution_v1_impl(
        token,
        output_root,
        success_authority=None,
    )
    if type(result) is not DiscoveryBatchExecutionReceiptV2:
        raise EvaluatorSupervisorError(
            "invalid_state", "unscheduled publication returned an invalid receipt"
        )
    return result


def _publish_scheduled_postverified_discovery_execution_v1(
    token: PostVerifiedDiscoveryExecutionV1,
    authority: E4SuccessReceiptAuthorityV2,
    output_root: str | os.PathLike[str],
) -> E4BatchSuccessReceiptV2:
    """Internal E4 path that atomically adds the scheduler success receipt."""

    if type(authority) is not E4SuccessReceiptAuthorityV2:
        raise EvaluatorSupervisorError(
            "invalid_argument", "scheduled publication requires an exact authority"
        )
    result = _publish_postverified_discovery_execution_v1_impl(
        token,
        output_root,
        success_authority=authority,
    )
    if type(result) is not E4BatchSuccessReceiptV2:
        raise EvaluatorSupervisorError(
            "invalid_state", "scheduled publication returned an invalid receipt"
        )
    return result


__all__ = [
    "BUDGET_LIMITS_DIGEST_DOMAIN",
    "DiscoveryExecutionSession",
    "EVALUATOR_SUPERVISOR_VERSION",
    "EvaluatorSupervisorError",
    "FailedDiscoveryExecutionClosureV1",
    "PendingTaskExecutionV1",
    "PostVerifiedDiscoveryExecutionV1",
    "TREE_LIMITS_DIGEST_DOMAIN",
    "WorkerTaskLaunchV1",
    "accept_discovery_worker_output_v1",
    "budget_limits_sha256_v1",
    "close_failed_discovery_execution_v1",
    "postverify_discovery_execution_v1",
    "prepare_discovery_execution_plan_v1",
    "publish_postverified_discovery_execution_v1",
    "tree_limits_sha256_v1",
]
