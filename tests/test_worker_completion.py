from __future__ import annotations

from dataclasses import replace
import hashlib
import pickle
import unittest

from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.producer_contracts import ProducerDeferredV1
from vulngym_agent.benchmark.reviewer_projection import project_discovery_run_v1
from vulngym_agent.evaluator.contracts import DiscoveryTaskExecutionPlanV1
from vulngym_agent.evaluator.runtime_evidence import (
    DockerServerIdentityV1,
    RuntimeEvidenceV1,
    RuntimeIsolationV1,
    RuntimeResourceLimitsV1,
)
from vulngym_agent.evaluator.worker_completion import (
    CompletedWorkerExecutionV1,
    WorkerCompletionError,
    _issue_completed_worker_execution_v1,
)
from vulngym_agent.orchestrator.discovery_pipeline import SourceDiscoveryRunV1


def _sha(marker: int | bytes) -> str:
    if type(marker) is bytes:
        return hashlib.sha256(marker).hexdigest()
    return f"{marker:064x}"


class WorkerCompletionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.task = DiscoveryTaskInputV1(
            task_id="VG-TEST-0123456789ABCDEF0123",
            repo_url="https://github.com/example/project",
            commit="1" * 40,
            instruction_id=INSTRUCTION_ID,
            snapshot_manifest_sha256=_sha(1),
            snapshot_content_root=_sha(2),
        )
        producer = ProducerDeferredV1(
            task=self.task,
            stage="SCOUT",
            reason_code="model_deferred",
            missing_information=("source evidence",),
        )
        discovery = project_discovery_run_v1(producer, None)
        self.run_wire = SourceDiscoveryRunV1(
            producer, None, discovery
        ).to_wire()
        self.run = SourceDiscoveryRunV1.from_wire(self.run_wire)
        self.plan = DiscoveryTaskExecutionPlanV1(
            batch_binding_sha256=_sha(3),
            execution_policy_sha256=_sha(4),
            task_id=self.task.task_id,
            snapshot_id=self.task.snapshot_id,
            snapshot_manifest_sha256=self.task.snapshot_manifest_sha256,
            snapshot_content_root=self.task.snapshot_content_root,
            handoff_sha256=_sha(5),
            handoff_wire_sha256=_sha(6),
        )
        self.evidence = RuntimeEvidenceV1(
            docker_server=DockerServerIdentityV1(
                operating_system="linux",
                architecture="amd64",
                engine_version="29.6.2",
                api_version="1.55",
                docker_executable_sha256=_sha(7),
                daemon_endpoint_sha256=_sha(20),
                server_observation_sha256=_sha(21),
            ),
            isolation=RuntimeIsolationV1(),
            resources=RuntimeResourceLimitsV1(),
            runtime_image_id="sha256:" + "a" * 64,
            runtime_image_inspect_sha256=_sha(22),
            execution_image_id="sha256:" + "b" * 64,
            execution_image_inspect_sha256=_sha(14),
            execution_policy_sha256=self.plan.execution_policy_sha256,
            task_plan_sha256=self.plan.plan_sha256,
            task_id=self.task.task_id,
            snapshot_id=self.task.snapshot_id,
            snapshot_manifest_sha256=self.task.snapshot_manifest_sha256,
            snapshot_content_root=self.task.snapshot_content_root,
            handoff_sha256=self.plan.handoff_sha256,
            handoff_wire_sha256=self.plan.handoff_wire_sha256,
            source_generation_sha256=_sha(8),
            runtime_config_sha256=_sha(9),
            materializer_container_create_spec_sha256=_sha(15),
            materializer_container_pre_inspect_sha256=_sha(16),
            materializer_container_post_inspect_sha256=_sha(17),
            materializer_container_diff_sha256=_sha(18),
            materializer_container_identity_sha256=_sha(19),
            container_create_spec_sha256=_sha(10),
            container_pre_inspect_sha256=_sha(11),
            container_post_inspect_sha256=_sha(12),
            container_identity_sha256=_sha(13),
            run_sha256=self.run.run_sha256,
            run_wire_sha256=hashlib.sha256(self.run_wire).hexdigest(),
            run_wire_size=len(self.run_wire),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            stderr_size=0,
            exit_code=0,
            timed_out=False,
            oom_killed=False,
            restart_count=0,
            container_diff_empty=True,
            cleanup_complete=True,
        )

    def test_completion_claim_binds_run_evidence_and_plan_once(self) -> None:
        completion = _issue_completed_worker_execution_v1(
            self.run_wire, self.evidence
        )
        claimed = completion._claim_for_plan(self.plan)
        self.assertEqual(claimed.run_wire, self.run_wire)
        self.assertEqual(claimed.runtime_evidence, self.evidence)
        with self.assertRaises(WorkerCompletionError) as caught:
            completion._claim_for_plan(self.plan)
        self.assertEqual(caught.exception.code, "completion_reused")
        with self.assertRaises(TypeError):
            pickle.dumps(completion)

    def test_direct_construction_is_forbidden(self) -> None:
        with self.assertRaises(TypeError):
            CompletedWorkerExecutionV1(
                object(), run_wire=self.run_wire, evidence=self.evidence
            )

    def test_detached_run_or_plan_is_rejected(self) -> None:
        with self.assertRaises(WorkerCompletionError) as caught:
            _issue_completed_worker_execution_v1(
                self.run_wire,
                replace(self.evidence, run_wire_sha256=_sha(99)),
            )
        self.assertEqual(caught.exception.code, "detached_completion")

        completion = _issue_completed_worker_execution_v1(
            self.run_wire, self.evidence
        )
        wrong_plan = replace(self.plan, handoff_sha256=_sha(100))
        with self.assertRaises(WorkerCompletionError) as caught:
            completion._claim_for_plan(wrong_plan)
        self.assertEqual(caught.exception.code, "detached_completion")


if __name__ == "__main__":
    unittest.main()
