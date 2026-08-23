from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
import unittest
from unittest import mock

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.harness import (
    ARTIFACT_INDEX_CONTRACT_VERSION,
    ArtifactBundleDigest,
    ArtifactBundleIndex,
    artifact_bundle_index_payload_v1,
)
from vulngym_agent.benchmark.sealed_snapshot import DEFAULT_SNAPSHOT_POLICY
from vulngym_agent.benchmark.snapshot_batch import (
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    SnapshotBatchSummary,
    SnapshotBatchTask,
)
from vulngym_agent.evaluator.contracts import (
    DiscoveryBatchExecutionPlanV1,
    DiscoveryBatchExecutionReceiptV1,
    DiscoveryTaskExecutionPlanV1,
    DiscoveryTaskExecutionReceiptV1,
    EvaluatorContractError,
    ExecutionPolicyBindingV1,
    SnapshotBatchBindingV1,
    snapshot_policy_sha256_v1,
)
from vulngym_agent.evaluator.runtime_evidence import (
    DockerServerIdentityV1,
    RuntimeEvidenceV1,
    RuntimeIsolationV1,
    RuntimeResourceLimitsV1,
)


def _sha(marker: int) -> str:
    return f"{marker:064x}"


class EvaluatorContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.members = tuple(
            SnapshotBatchTask(
                task_id=f"VG-TEST-{index:020X}",
                repo_url=f"https://github.com/example/project-{index}",
                commit=f"{index + 1:040x}",
                split="test",
                instruction_id=INSTRUCTION_ID,
                snapshot_manifest_sha256=_sha(100 + index),
                snapshot_content_root=_sha(200 + index),
                file_count=1,
                node_count=1,
                total_bytes=10 + index,
            )
            for index in range(20)
        )
        self.binding = SnapshotBatchBindingV1(
            profile_id=PROFILE_ID,
            profile_schema_version="1.0.0",
            split="test",
            task_count=len(self.members),
            total_files=sum(item.file_count for item in self.members),
            total_nodes=sum(item.node_count for item in self.members),
            total_bytes=sum(item.total_bytes for item in self.members),
            tasks_sha256=_sha(1),
            public_manifest_sha256=PROFILE_MANIFEST_SHA256,
            source_map_sha256=_sha(3),
            batch_manifest_sha256=_sha(4),
            batch_content_root=_sha(5),
            attestation_key_id="evaluator-contract-test",
            snapshot_policy=DEFAULT_SNAPSHOT_POLICY,
            tasks=self.members,
        )
        self.policy = ExecutionPolicyBindingV1(
            runtime_image_id="sha256:" + "a" * 64,
            d2_backend_id="replay",
            d2_model_id="offline-d2",
            d3_backend_id="replay",
            d3_model_id="offline-d3",
            snapshot_policy_sha256=snapshot_policy_sha256_v1(
                DEFAULT_SNAPSHOT_POLICY
            ),
            d2_budget_sha256=_sha(13),
            d3_budget_sha256=_sha(14),
            tree_limits_sha256=_sha(15),
        )
        self.task_plans = tuple(
            self._task_plan(member, position)
            for position, member in enumerate(self.members, 1)
        )
        self.plan = DiscoveryBatchExecutionPlanV1(
            batch=self.binding,
            execution_policy=self.policy,
            tasks=self.task_plans,
        )
        self.dataset_sha256s = tuple(
            _sha(1300 + index) for index in range(len(self.task_plans))
        )
        artifact_index = ArtifactBundleIndex(
            contract_version=ARTIFACT_INDEX_CONTRACT_VERSION,
            profile_id=PROFILE_ID,
            manifest_sha256=PROFILE_MANIFEST_SHA256,
            split="test",
            bundles=tuple(
                ArtifactBundleDigest(
                    task_id=task.task_id,
                    dataset_sha256=self.dataset_sha256s[index],
                )
                for index, task in enumerate(self.task_plans)
            ),
        )
        self.artifact_index_sha256 = hashlib.sha256(
            artifact_bundle_index_payload_v1(artifact_index)
        ).hexdigest()
        self.task_receipts = tuple(
            DiscoveryTaskExecutionReceiptV1(
                task_plan_sha256=task.plan_sha256,
                execution_policy_sha256=self.policy.policy_sha256,
                task_id=task.task_id,
                snapshot_id=task.snapshot_id,
                run_sha256=_sha(1000 + index),
                run_wire_sha256=_sha(1100 + index),
                discovery_result_sha256=_sha(1200 + index),
                dataset_sha256=self.dataset_sha256s[index],
                artifact_index_sha256=self.artifact_index_sha256,
                runtime_evidence=self._runtime_evidence(
                    task,
                    run_sha256=_sha(1000 + index),
                    run_wire_sha256=_sha(1100 + index),
                    marker=1400 + index,
                ),
            )
            for index, task in enumerate(self.task_plans)
        )
        self.receipt = DiscoveryBatchExecutionReceiptV1(
            plan=self.plan,
            pre_batch_binding_sha256=self.binding.binding_sha256,
            post_batch_binding_sha256=self.binding.binding_sha256,
            artifact_index_sha256=self.artifact_index_sha256,
            tasks=self.task_receipts,
        )

    def _task_plan(
        self, member: SnapshotBatchTask, position: int
    ) -> DiscoveryTaskExecutionPlanV1:
        task = DiscoveryTaskInputV1(
            task_id=member.task_id,
            repo_url=member.repo_url,
            commit=member.commit,
            instruction_id=member.instruction_id,
            snapshot_manifest_sha256=member.snapshot_manifest_sha256,
            snapshot_content_root=member.snapshot_content_root,
        )
        return DiscoveryTaskExecutionPlanV1(
            batch_binding_sha256=self.binding.binding_sha256,
            execution_policy_sha256=self.policy.policy_sha256,
            task_id=task.task_id,
            snapshot_id=task.snapshot_id,
            snapshot_manifest_sha256=task.snapshot_manifest_sha256,
            snapshot_content_root=task.snapshot_content_root,
            handoff_sha256=_sha(300 + position),
            handoff_wire_sha256=_sha(400 + position),
            d2_replay_sha256=_sha(500 + position),
            d2_replay_wire_sha256=_sha(600 + position),
            d3_replay_sha256=_sha(700 + position),
            d3_replay_wire_sha256=_sha(800 + position),
        )

    def _runtime_evidence(
        self,
        task: DiscoveryTaskExecutionPlanV1,
        *,
        run_sha256: str,
        run_wire_sha256: str,
        marker: int,
    ) -> RuntimeEvidenceV1:
        return RuntimeEvidenceV1(
            docker_server=DockerServerIdentityV1(
                operating_system="linux",
                architecture="amd64",
                engine_version="29.6.2",
                api_version="1.55",
                docker_executable_sha256=_sha(9001),
                daemon_endpoint_sha256=_sha(9002),
                server_observation_sha256=_sha(9003),
            ),
            isolation=RuntimeIsolationV1(),
            resources=RuntimeResourceLimitsV1(),
            runtime_image_id=self.policy.runtime_image_id,
            runtime_image_inspect_sha256=_sha(9004),
            execution_image_id="sha256:" + _sha(marker + 17),
            execution_image_inspect_sha256=_sha(marker + 8),
            execution_policy_sha256=self.policy.policy_sha256,
            task_plan_sha256=task.plan_sha256,
            task_id=task.task_id,
            snapshot_id=task.snapshot_id,
            snapshot_manifest_sha256=task.snapshot_manifest_sha256,
            snapshot_content_root=task.snapshot_content_root,
            handoff_sha256=task.handoff_sha256,
            handoff_wire_sha256=task.handoff_wire_sha256,
            source_generation_sha256=_sha(marker + 2),
            runtime_config_sha256=_sha(marker + 3),
            materializer_container_create_spec_sha256=_sha(marker + 9),
            materializer_container_pre_inspect_sha256=_sha(marker + 10),
            materializer_container_post_inspect_sha256=_sha(marker + 11),
            materializer_container_diff_sha256=_sha(marker + 12),
            materializer_container_identity_sha256=_sha(marker + 13),
            container_create_spec_sha256=_sha(marker + 4),
            container_pre_inspect_sha256=_sha(marker + 5),
            container_post_inspect_sha256=_sha(marker + 6),
            container_identity_sha256=_sha(marker + 7),
            run_sha256=run_sha256,
            run_wire_sha256=run_wire_sha256,
            run_wire_size=100,
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            stderr_size=0,
            exit_code=0,
            timed_out=False,
            oom_killed=False,
            restart_count=0,
            container_diff_empty=True,
            cleanup_complete=True,
        )

    @staticmethod
    def _roundtrip(value, parser, digest_name: str):
        payload = value.to_bytes()
        parsed = parser(
            payload,
            **{
                digest_name: getattr(
                    value,
                    "binding_sha256"
                    if digest_name == "expected_binding_sha256"
                    else "policy_sha256"
                    if digest_name == "expected_policy_sha256"
                    else "plan_sha256"
                    if digest_name == "expected_plan_sha256"
                    else "receipt_sha256",
                ),
                "expected_wire_sha256": hashlib.sha256(payload).hexdigest(),
            },
        )
        return payload, parsed

    def test_all_contracts_roundtrip_canonically(self) -> None:
        cases = (
            (
                self.binding,
                SnapshotBatchBindingV1.from_bytes,
                "expected_binding_sha256",
            ),
            (
                self.policy,
                ExecutionPolicyBindingV1.from_bytes,
                "expected_policy_sha256",
            ),
            (
                self.task_plans[0],
                DiscoveryTaskExecutionPlanV1.from_bytes,
                "expected_plan_sha256",
            ),
            (
                self.plan,
                DiscoveryBatchExecutionPlanV1.from_bytes,
                "expected_plan_sha256",
            ),
            (
                self.task_receipts[0],
                DiscoveryTaskExecutionReceiptV1.from_bytes,
                "expected_receipt_sha256",
            ),
            (
                self.receipt,
                DiscoveryBatchExecutionReceiptV1.from_bytes,
                "expected_receipt_sha256",
            ),
        )
        for value, parser, digest_name in cases:
            with self.subTest(contract=type(value).__name__):
                payload, parsed = self._roundtrip(value, parser, digest_name)
                self.assertEqual(parsed, value)
                self.assertEqual(parsed.to_bytes(), payload)

    def test_binding_detaches_summary_members_and_omits_local_state(self) -> None:
        summary = SnapshotBatchSummary(
            batch_root=(Path.cwd() / "not-serialized-batch-root").resolve(),
            profile_id=PROFILE_ID,
            split="test",
            task_count=len(self.members),
            total_files=sum(item.file_count for item in self.members),
            total_nodes=sum(item.node_count for item in self.members),
            total_bytes=sum(item.total_bytes for item in self.members),
            tasks_sha256=_sha(1),
            public_manifest_sha256=_sha(2),
            source_map_sha256=_sha(3),
            manifest_sha256=_sha(4),
            batch_content_root=_sha(5),
            key_id="evaluator-contract-test",
            tasks=self.members,
        )
        binding = SnapshotBatchBindingV1.from_verified_summary(
            summary, snapshot_policy=DEFAULT_SNAPSHOT_POLICY
        )
        original_repo = binding.tasks[0].repo_url
        object.__setattr__(summary.tasks[0], "repo_url", "https://invalid.example")
        self.assertEqual(binding.tasks[0].repo_url, original_repo)
        self.assertNotIn(str(summary.batch_root).encode(), binding.to_bytes())
        self.assertNotIn(b"batch_root", binding.to_bytes())

    def test_wire_pin_is_checked_before_json_parsing(self) -> None:
        payload = self.receipt.to_bytes()
        with mock.patch(
            "vulngym_agent.evaluator.contracts.json.loads",
            side_effect=AssertionError("parser must remain unreachable"),
        ) as parser:
            with self.assertRaises(EvaluatorContractError) as captured:
                DiscoveryBatchExecutionReceiptV1.from_bytes(
                    payload,
                    expected_receipt_sha256=self.receipt.receipt_sha256,
                    expected_wire_sha256="f" * 64,
                )
        self.assertEqual(captured.exception.code, "digest_mismatch")
        parser.assert_not_called()

    def test_batch_plan_rejects_cross_task_order_and_policy_swap(self) -> None:
        swapped = (self.task_plans[1], self.task_plans[0], *self.task_plans[2:])
        with self.assertRaises(EvaluatorContractError) as captured:
            DiscoveryBatchExecutionPlanV1(
                batch=self.binding,
                execution_policy=self.policy,
                tasks=swapped,
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

        wrong_policy = ExecutionPolicyBindingV1(
            runtime_image_id="sha256:" + "b" * 64,
            d2_backend_id="replay",
            d2_model_id="offline-d2",
            d3_backend_id="replay",
            d3_model_id="offline-d3",
            snapshot_policy_sha256=_sha(23),
            d2_budget_sha256=_sha(24),
            d3_budget_sha256=_sha(25),
            tree_limits_sha256=_sha(26),
        )
        with self.assertRaises(EvaluatorContractError) as captured:
            DiscoveryBatchExecutionPlanV1(
                batch=self.binding,
                execution_policy=wrong_policy,
                tasks=self.task_plans,
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

    def test_batch_receipt_rejects_postverify_swap(self) -> None:
        with self.assertRaises(EvaluatorContractError) as captured:
            DiscoveryBatchExecutionReceiptV1(
                plan=self.plan,
                pre_batch_binding_sha256=self.binding.binding_sha256,
                post_batch_binding_sha256=_sha(9999),
                artifact_index_sha256=self.artifact_index_sha256,
                tasks=self.task_receipts,
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

    def test_batch_receipt_rejects_cross_task_runtime_drift_or_reuse(self) -> None:
        first = self.task_receipts[0]
        second = self.task_receipts[1]
        evidence_cases = (
            replace(
                second.runtime_evidence,
                docker_server=replace(
                    second.runtime_evidence.docker_server,
                    server_observation_sha256=_sha(9901),
                ),
            ),
            replace(
                second.runtime_evidence,
                runtime_image_inspect_sha256=_sha(9902),
            ),
            replace(
                second.runtime_evidence,
                execution_image_id=first.runtime_evidence.execution_image_id,
            ),
            replace(
                second.runtime_evidence,
                container_identity_sha256=(
                    first.runtime_evidence.container_identity_sha256
                ),
            ),
        )
        for evidence in evidence_cases:
            with self.subTest(evidence=evidence.evidence_sha256):
                detached = replace(second, runtime_evidence=evidence)
                with self.assertRaises(EvaluatorContractError) as captured:
                    DiscoveryBatchExecutionReceiptV1(
                        plan=self.plan,
                        pre_batch_binding_sha256=self.binding.binding_sha256,
                        post_batch_binding_sha256=self.binding.binding_sha256,
                        artifact_index_sha256=self.artifact_index_sha256,
                        tasks=(first, detached, *self.task_receipts[2:]),
                    )
                self.assertEqual(captured.exception.code, "invalid_binding")

    def test_batch_receipt_rejects_evidence_plan_policy_and_index_drift(self) -> None:
        original = self.task_receipts[0]
        resource_drifts = (
            ("wall_time_seconds", 1799),
            ("memory_bytes", 8 * 1024 * 1024 * 1024),
            ("cpu_millis", 1999),
            ("pids_limit", 63),
            ("open_files_limit", 255),
            ("stdout_max_bytes", 5 * 1024 * 1024),
            ("stderr_max_bytes", 1024 * 1024 - 1),
            ("tmpfs_bytes", 63 * 1024 * 1024),
        )
        evidence_cases = (
            replace(
                original.runtime_evidence,
                snapshot_manifest_sha256=_sha(9001),
                snapshot_content_root=_sha(9002),
                handoff_sha256=_sha(9003),
                handoff_wire_sha256=_sha(9004),
            ),
            replace(
                original.runtime_evidence,
                runtime_image_id="sha256:" + "c" * 64,
            ),
            *(
                replace(
                    original.runtime_evidence,
                    resources=replace(
                        original.runtime_evidence.resources,
                        **{name: value},
                    ),
                )
                for name, value in resource_drifts
            ),
        )
        for evidence in evidence_cases:
            with self.subTest(evidence=evidence.evidence_sha256):
                detached = DiscoveryTaskExecutionReceiptV1(
                    task_plan_sha256=original.task_plan_sha256,
                    execution_policy_sha256=original.execution_policy_sha256,
                    task_id=original.task_id,
                    snapshot_id=original.snapshot_id,
                    run_sha256=original.run_sha256,
                    run_wire_sha256=original.run_wire_sha256,
                    discovery_result_sha256=original.discovery_result_sha256,
                    dataset_sha256=original.dataset_sha256,
                    artifact_index_sha256=original.artifact_index_sha256,
                    runtime_evidence=evidence,
                )
                with self.assertRaises(EvaluatorContractError) as captured:
                    DiscoveryBatchExecutionReceiptV1(
                        plan=self.plan,
                        pre_batch_binding_sha256=self.binding.binding_sha256,
                        post_batch_binding_sha256=self.binding.binding_sha256,
                        artifact_index_sha256=self.artifact_index_sha256,
                        tasks=(detached, *self.task_receipts[1:]),
                    )
                self.assertEqual(captured.exception.code, "invalid_binding")

        detached_dataset = DiscoveryTaskExecutionReceiptV1(
            task_plan_sha256=self.task_plans[0].plan_sha256,
            execution_policy_sha256=self.policy.policy_sha256,
            task_id=self.task_plans[0].task_id,
            snapshot_id=self.task_plans[0].snapshot_id,
            run_sha256=_sha(8101),
            run_wire_sha256=_sha(8102),
            discovery_result_sha256=_sha(8103),
            dataset_sha256=_sha(8104),
            artifact_index_sha256=self.artifact_index_sha256,
            runtime_evidence=self._runtime_evidence(
                self.task_plans[0],
                run_sha256=_sha(8101),
                run_wire_sha256=_sha(8102),
                marker=8106,
            ),
        )
        with self.assertRaises(EvaluatorContractError) as captured:
            DiscoveryBatchExecutionReceiptV1(
                plan=self.plan,
                pre_batch_binding_sha256=self.binding.binding_sha256,
                post_batch_binding_sha256=self.binding.binding_sha256,
                artifact_index_sha256=self.artifact_index_sha256,
                tasks=(detached_dataset, *self.task_receipts[1:]),
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

        wrong_index = DiscoveryTaskExecutionReceiptV1(
            task_plan_sha256=self.task_plans[0].plan_sha256,
            execution_policy_sha256=self.policy.policy_sha256,
            task_id=self.task_plans[0].task_id,
            snapshot_id=self.task_plans[0].snapshot_id,
            run_sha256=_sha(8001),
            run_wire_sha256=_sha(8002),
            discovery_result_sha256=_sha(8003),
            dataset_sha256=_sha(8004),
            artifact_index_sha256=_sha(8005),
            runtime_evidence=self._runtime_evidence(
                self.task_plans[0],
                run_sha256=_sha(8001),
                run_wire_sha256=_sha(8002),
                marker=8006,
            ),
        )
        with self.assertRaises(EvaluatorContractError) as captured:
            DiscoveryBatchExecutionReceiptV1(
                plan=self.plan,
                pre_batch_binding_sha256=self.binding.binding_sha256,
                post_batch_binding_sha256=self.binding.binding_sha256,
                artifact_index_sha256=self.artifact_index_sha256,
                tasks=(wrong_index, *self.task_receipts[1:]),
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

    def test_execution_policy_cannot_relax_fixed_provider_properties(self) -> None:
        arguments = {
            "runtime_image_id": "sha256:" + "a" * 64,
            "d2_backend_id": "replay",
            "d2_model_id": "offline-d2",
            "d3_backend_id": "replay",
            "d3_model_id": "offline-d3",
            "snapshot_policy_sha256": snapshot_policy_sha256_v1(
                DEFAULT_SNAPSHOT_POLICY
            ),
            "d2_budget_sha256": _sha(33),
            "d3_budget_sha256": _sha(34),
            "tree_limits_sha256": _sha(35),
        }
        for override in (
            {"network_mode": "host"},
            {"rootfs_mode": "writable"},
            {"source_mount_mode": "writable"},
            {"no_new_privileges": False},
            {"memory_bytes": 16 * 1024 * 1024 * 1024},
        ):
            with self.subTest(override=override):
                with self.assertRaises(EvaluatorContractError):
                    ExecutionPolicyBindingV1(**arguments, **override)


if __name__ == "__main__":
    unittest.main()
