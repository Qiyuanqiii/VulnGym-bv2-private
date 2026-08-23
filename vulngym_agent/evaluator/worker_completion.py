"""Opaque handoff from the verified OCI provider to the evaluator supervisor.

The evaluator Python process and its imported code are part of the trusted
computing base.  The private token and underscore-prefixed issuer prevent
accidental use through the supported API; they are not a security boundary
against arbitrary Python already executing inside that trusted process.
"""

from __future__ import annotations

import hashlib
import threading
from typing import Final

from vulngym_agent.evaluator.contracts import DiscoveryTaskExecutionPlanV1
from vulngym_agent.evaluator.runtime_evidence import RuntimeEvidenceV1
from vulngym_agent.orchestrator.discovery_pipeline import (
    SOURCE_DISCOVERY_RUN_MAX_WIRE_BYTES,
    SourceDiscoveryRunV1,
)


_ISSUER_TOKEN: Final[object] = object()


class WorkerCompletionError(RuntimeError):
    """Stable failure for detached, repeated, or malformed worker completion."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "invalid_completion"
        super().__init__(message)


class ClaimedWorkerExecutionV1:
    """Canonical provider result available only after exact plan binding."""

    __slots__ = ("__evidence", "__run_wire")

    def __init__(
        self, token: object, *, run_wire: bytes, evidence: RuntimeEvidenceV1
    ) -> None:
        if token is not _ISSUER_TOKEN:
            raise TypeError("claimed worker executions are provider-created")
        self.__run_wire = run_wire
        self.__evidence = evidence

    @property
    def run_wire(self) -> bytes:
        return self.__run_wire

    @property
    def run(self) -> SourceDiscoveryRunV1:
        return SourceDiscoveryRunV1.from_wire(self.__run_wire)

    @property
    def runtime_evidence(self) -> RuntimeEvidenceV1:
        wire = self.__evidence.to_bytes()
        return RuntimeEvidenceV1.from_bytes(
            wire,
            expected_evidence_sha256=self.__evidence.evidence_sha256,
            expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
        )

    def __reduce__(self):
        raise TypeError("claimed worker executions are not serializable")


class CompletedWorkerExecutionV1:
    """One-use provider-issued output with a fully embedded evidence record."""

    __slots__ = (
        "__claimed",
        "__evidence",
        "__lock",
        "__run_wire",
    )

    def __init__(
        self,
        token: object,
        *,
        run_wire: bytes,
        evidence: RuntimeEvidenceV1,
    ) -> None:
        if token is not _ISSUER_TOKEN:
            raise TypeError("completed worker executions are provider-created")
        if (
            type(run_wire) is not bytes
            or not run_wire
            or len(run_wire) > SOURCE_DISCOVERY_RUN_MAX_WIRE_BYTES
            or type(evidence) is not RuntimeEvidenceV1
        ):
            raise WorkerCompletionError(
                "invalid_completion", "provider completion envelope is invalid"
            )
        try:
            run = SourceDiscoveryRunV1.from_wire(run_wire)
            evidence_wire = evidence.to_bytes()
            frozen_evidence = RuntimeEvidenceV1.from_bytes(
                evidence_wire,
                expected_evidence_sha256=evidence.evidence_sha256,
                expected_wire_sha256=hashlib.sha256(evidence_wire).hexdigest(),
            )
        except (AttributeError, RecursionError, RuntimeError, TypeError, ValueError):
            raise WorkerCompletionError(
                "invalid_completion", "provider completion did not normalize"
            ) from None
        if (
            run.to_wire() != run_wire
            or frozen_evidence.run_sha256 != run.run_sha256
            or frozen_evidence.run_wire_sha256
            != hashlib.sha256(run_wire).hexdigest()
            or frozen_evidence.run_wire_size != len(run_wire)
            or frozen_evidence.task_id != run.task.task_id
            or frozen_evidence.snapshot_id != run.task.snapshot_id
            or frozen_evidence.snapshot_manifest_sha256
            != run.task.snapshot_manifest_sha256
            or frozen_evidence.snapshot_content_root
            != run.task.snapshot_content_root
        ):
            raise WorkerCompletionError(
                "detached_completion", "provider evidence is detached from its run"
            )
        self.__run_wire = run_wire
        self.__evidence = frozen_evidence
        self.__claimed = False
        self.__lock = threading.Lock()

    @property
    def task_id(self) -> str:
        return self.__evidence.task_id

    def _claim_for_plan(
        self, task_plan: DiscoveryTaskExecutionPlanV1
    ) -> ClaimedWorkerExecutionV1:
        if type(task_plan) is not DiscoveryTaskExecutionPlanV1:
            raise WorkerCompletionError(
                "invalid_completion", "worker completion plan has an invalid type"
            )
        try:
            plan_wire = task_plan.to_bytes()
            frozen_plan = DiscoveryTaskExecutionPlanV1.from_bytes(
                plan_wire,
                expected_plan_sha256=task_plan.plan_sha256,
                expected_wire_sha256=hashlib.sha256(plan_wire).hexdigest(),
            )
        except (AttributeError, TypeError, ValueError):
            raise WorkerCompletionError(
                "invalid_completion", "worker completion plan did not normalize"
            ) from None
        with self.__lock:
            if self.__claimed:
                raise WorkerCompletionError(
                    "completion_reused", "worker completion was already claimed"
                )
            self.__claimed = True
            evidence = self.__evidence
            if (
                evidence.task_plan_sha256 != frozen_plan.plan_sha256
                or evidence.execution_policy_sha256
                != frozen_plan.execution_policy_sha256
                or evidence.task_id != frozen_plan.task_id
                or evidence.snapshot_id != frozen_plan.snapshot_id
                or evidence.snapshot_manifest_sha256
                != frozen_plan.snapshot_manifest_sha256
                or evidence.snapshot_content_root
                != frozen_plan.snapshot_content_root
                or evidence.handoff_sha256 != frozen_plan.handoff_sha256
                or evidence.handoff_wire_sha256
                != frozen_plan.handoff_wire_sha256
            ):
                raise WorkerCompletionError(
                    "detached_completion",
                    "worker completion does not match its execution plan",
                )
            return ClaimedWorkerExecutionV1(
                _ISSUER_TOKEN,
                run_wire=self.__run_wire,
                evidence=evidence,
            )

    def __reduce__(self):
        raise TypeError("completed worker executions are not serializable")


def _issue_completed_worker_execution_v1(
    run_wire: bytes, runtime_evidence: RuntimeEvidenceV1
) -> CompletedWorkerExecutionV1:
    """Issue an opaque completion for intended use by the trusted provider layer."""

    return CompletedWorkerExecutionV1(
        _ISSUER_TOKEN, run_wire=run_wire, evidence=runtime_evidence
    )


__all__ = [
    "ClaimedWorkerExecutionV1",
    "CompletedWorkerExecutionV1",
    "WorkerCompletionError",
]
