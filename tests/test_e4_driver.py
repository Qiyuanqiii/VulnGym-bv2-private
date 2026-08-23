from __future__ import annotations

import hashlib
import unittest
from unittest import mock

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID, SnapshotTaskSpec
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.harness import (
    BenchmarkHarnessError,
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    PROFILE_SCHEMA_VERSION,
    PROFILE_TEST_TASKS,
    PROFILE_TRAIN_TASKS,
)
from vulngym_agent.benchmark.sealed_snapshot import DEFAULT_SNAPSHOT_POLICY
from vulngym_agent.benchmark.sealed_tree_access import (
    DEFAULT_SEALED_TREE_ACCESS_LIMITS,
)
from vulngym_agent.benchmark.snapshot_batch import SnapshotBatchTask
from vulngym_agent.evaluator.contracts import (
    DiscoveryBatchExecutionPlanV1,
    DiscoveryTaskExecutionPlanV1,
    SnapshotBatchBindingV1,
    snapshot_policy_sha256_v1,
)
import vulngym_agent.evaluator.e4_driver as driver
from vulngym_agent.evaluator.e4_driver import (
    E4DriverError,
    fixed_e4_execution_policy_v1,
    run_e4_discovery_split_v1,
)
from vulngym_agent.evaluator.oci_worker_entry import (
    OciReplayConfigV1,
    REPLAY_BACKEND_ID,
    REPLAY_MODEL_ID,
)
from vulngym_agent.evaluator.supervisor import (
    budget_limits_sha256_v1,
    tree_limits_sha256_v1,
)
from vulngym_agent.evaluator.worker import (
    DEFAULT_D2_WORKER_BUDGET_LIMITS,
    DEFAULT_D3_WORKER_BUDGET_LIMITS,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class _FakeSession:
    def __init__(
        self,
        plan: DiscoveryBatchExecutionPlanV1,
        events: list[str],
        *,
        abort_error: BaseException | None = None,
    ) -> None:
        self._plan = plan
        self._events = events
        self._abort_error = abort_error

    @property
    def plan(self) -> DiscoveryBatchExecutionPlanV1:
        return self._plan

    def abort(self) -> None:
        self._events.append("abort")
        if self._abort_error is not None:
            raise self._abort_error


class _FakeExecutionReceipt:
    def __init__(self, plan: DiscoveryBatchExecutionPlanV1) -> None:
        self.plan = plan


class _FakeSuccess:
    def __init__(self, label: str, plan: DiscoveryBatchExecutionPlanV1) -> None:
        self._payload = f'{{"receipt":"{label}"}}\n'.encode("utf-8")
        self.receipt_sha256 = _sha(f"{label}:semantic")
        self.execution_receipt = _FakeExecutionReceipt(plan)

    def to_bytes(self) -> bytes:
        return self._payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self._payload).hexdigest()

    def __eq__(self, other: object) -> bool:
        return (
            type(other) is _FakeSuccess
            and other.receipt_sha256 == self.receipt_sha256
            and other.to_bytes() == self.to_bytes()
            and other.execution_receipt.plan == self.execution_receipt.plan
        )


class _FakeFailure:
    _plans: dict[bytes, DiscoveryBatchExecutionPlanV1] = {}

    def __init__(self, label: str, plan: DiscoveryBatchExecutionPlanV1) -> None:
        self._payload = f'{{"report":"{label}"}}\n'.encode("utf-8")
        self.report_sha256 = _sha(f"{label}:semantic")
        self.plan = plan
        self._plans[self._payload] = plan

    def to_bytes(self) -> bytes:
        return self._payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self._payload).hexdigest()

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_report_sha256: str,
        expected_wire_sha256: str,
    ) -> "_FakeFailure":
        if hashlib.sha256(payload).hexdigest() != expected_wire_sha256:
            raise ValueError("wire mismatch")
        try:
            plan = cls._plans[payload]
        except KeyError:
            raise ValueError("unknown report") from None
        result = cls(payload.decode("utf-8").split('"')[3], plan)
        if result.report_sha256 != expected_report_sha256:
            raise ValueError("semantic mismatch")
        return result

    def __eq__(self, other: object) -> bool:
        return (
            type(other) is _FakeFailure
            and other.report_sha256 == self.report_sha256
            and other.to_bytes() == self.to_bytes()
            and other.plan == self.plan
        )


class E4DriverTests(unittest.TestCase):
    IMAGE_A = "sha256:" + "a" * 64
    IMAGE_B = "sha256:" + "b" * 64
    KEY_ID = "driver-test-key"

    def _prepared(
        self,
        split: str,
        *,
        image_id: str | None = None,
        sealed_manifest_sha256: str | None = None,
    ) -> tuple[
        tuple[SnapshotTaskSpec, ...],
        tuple[tuple[OciReplayConfigV1, OciReplayConfigV1], ...],
        DiscoveryBatchExecutionPlanV1,
    ]:
        count = PROFILE_TEST_TASKS if split == "test" else PROFILE_TRAIN_TASKS
        prefix = "TEST" if split == "test" else "TRAIN"
        public: list[SnapshotTaskSpec] = []
        members: list[SnapshotBatchTask] = []
        configs: list[tuple[OciReplayConfigV1, OciReplayConfigV1]] = []
        for index in range(count):
            task_id = f"VG-{prefix}-{index:020X}"
            repo_url = f"https://github.com/example/repo-{split}-{index:02d}"
            commit = f"{index + 1:040x}"
            task = SnapshotTaskSpec(
                task_id=task_id,
                repo_url=repo_url,
                commit=commit,
                split=split,
                instruction_id=INSTRUCTION_ID,
            )
            public.append(task)
            members.append(
                SnapshotBatchTask(
                    task_id=task.task_id,
                    repo_url=task.repo_url,
                    commit=task.commit,
                    split=task.split,
                    instruction_id=task.instruction_id,
                    snapshot_manifest_sha256=_sha(f"{split}:{index}:manifest"),
                    snapshot_content_root=_sha(f"{split}:{index}:content"),
                    file_count=1,
                    node_count=1,
                    total_bytes=1,
                )
            )
            configs.append(
                (
                    OciReplayConfigV1(
                        task_id=task.task_id, role="d2", responses=()
                    ),
                    OciReplayConfigV1(
                        task_id=task.task_id, role="d3", responses=()
                    ),
                )
            )

        sealed_digest = sealed_manifest_sha256 or _sha(f"{split}:sealed")
        binding = SnapshotBatchBindingV1(
            profile_id=PROFILE_ID,
            profile_schema_version=PROFILE_SCHEMA_VERSION,
            split=split,
            task_count=count,
            total_files=count,
            total_nodes=count,
            total_bytes=count,
            tasks_sha256=_sha(f"{split}:tasks"),
            public_manifest_sha256=PROFILE_MANIFEST_SHA256,
            source_map_sha256=_sha(f"{split}:source-map"),
            batch_manifest_sha256=sealed_digest,
            batch_content_root=_sha(f"{split}:batch-content"),
            attestation_key_id=self.KEY_ID,
            snapshot_policy=DEFAULT_SNAPSHOT_POLICY,
            tasks=tuple(members),
        )
        policy = fixed_e4_execution_policy_v1(image_id or self.IMAGE_A)
        task_plans: list[DiscoveryTaskExecutionPlanV1] = []
        for index, (member, pair) in enumerate(zip(members, configs, strict=True)):
            task = DiscoveryTaskInputV1(
                task_id=member.task_id,
                repo_url=member.repo_url,
                commit=member.commit,
                instruction_id=member.instruction_id,
                snapshot_manifest_sha256=member.snapshot_manifest_sha256,
                snapshot_content_root=member.snapshot_content_root,
            )
            d2, d3 = pair
            task_plans.append(
                DiscoveryTaskExecutionPlanV1(
                    batch_binding_sha256=binding.binding_sha256,
                    execution_policy_sha256=policy.policy_sha256,
                    task_id=task.task_id,
                    snapshot_id=task.snapshot_id,
                    snapshot_manifest_sha256=task.snapshot_manifest_sha256,
                    snapshot_content_root=task.snapshot_content_root,
                    handoff_sha256=_sha(f"{split}:{index}:handoff"),
                    handoff_wire_sha256=_sha(f"{split}:{index}:handoff-wire"),
                    d2_replay_sha256=d2.config_sha256,
                    d2_replay_wire_sha256=d2.wire_sha256,
                    d3_replay_sha256=d3.config_sha256,
                    d3_replay_wire_sha256=d3.wire_sha256,
                )
            )
        plan = DiscoveryBatchExecutionPlanV1(
            batch=binding,
            execution_policy=policy,
            tasks=tuple(task_plans),
        )
        return tuple(public), tuple(configs), plan

    def _run_success(
        self,
        *,
        split: str = "test",
        plan_image: str | None = None,
        call_image: str | None = None,
        expected_sealed: str | None = None,
        plan_sealed: str | None = None,
        outcome_plan_image: str | None = None,
        reader_result: _FakeSuccess | None = None,
        abort_error: BaseException | None = None,
    ) -> tuple[object, bytearray, list[str], dict[str, object]]:
        public, configs, plan = self._prepared(
            split,
            image_id=plan_image,
            sealed_manifest_sha256=plan_sealed,
        )
        events: list[str] = []
        session = _FakeSession(plan, events, abort_error=abort_error)
        outcome_plan = plan
        if outcome_plan_image is not None:
            _, _, outcome_plan = self._prepared(
                split,
                image_id=outcome_plan_image,
                sealed_manifest_sha256=plan.batch.batch_manifest_sha256,
            )
        success = _FakeSuccess(f"{split}:success", outcome_plan)
        captured: dict[str, object] = {}

        def load_tasks(_root, *, split):
            events.append(f"tasks:{split}")
            captured["task_split"] = split
            return public

        def load_replay(_root, **kwargs):
            events.append("replay")
            captured["replay"] = dict(kwargs)
            return configs

        def prepare(_root, **kwargs):
            events.append("prepare")
            captured["prepare"] = {
                **kwargs,
                "attestation_key": bytes(kwargs["attestation_key"]),
            }
            return session

        def verify(_docker, **kwargs):
            events.append("verify")
            captured["runtime_policy"] = kwargs["execution_policy"]
            return object()

        def run(_session, _runtime, _output):
            events.append("run")
            return success

        def read(_output, **kwargs):
            events.append("read")
            captured["read"] = dict(kwargs)
            return reader_result if reader_result is not None else success

        key = bytearray(b"K" * 40)
        sealed = expected_sealed or plan.batch.batch_manifest_sha256
        replay_semantic = _sha(f"{split}:replay-manifest:semantic")
        replay_wire = _sha(f"{split}:replay-manifest:wire")
        with (
            mock.patch.object(driver, "DiscoveryExecutionSession", _FakeSession),
            mock.patch.object(driver, "E4BatchSuccessReceiptV1", _FakeSuccess),
            mock.patch.object(driver, "load_answer_free_tasks", side_effect=load_tasks),
            mock.patch.object(
                driver, "load_batch_replay_configs_v1", side_effect=load_replay
            ),
            mock.patch.object(
                driver, "prepare_discovery_execution_plan_v1", side_effect=prepare
            ),
            mock.patch.object(
                driver, "verify_linux_oci_runtime_v1", side_effect=verify
            ),
            mock.patch.object(
                driver, "run_prepared_discovery_batch_v1", side_effect=run
            ),
            mock.patch.object(
                driver,
                "read_committed_e4_discovery_execution_v1",
                side_effect=read,
            ),
        ):
            result = run_e4_discovery_split_v1(
                "benchmark-root",
                "sealed-root",
                "replay-root",
                "output-root",
                split=split,
                expected_sealed_batch_manifest_sha256=sealed,
                expected_replay_manifest_sha256=replay_semantic,
                expected_replay_manifest_wire_sha256=replay_wire,
                snapshot_attestation_key=key,
                snapshot_key_id=self.KEY_ID,
                runtime_image_id=call_image or self.IMAGE_A,
                docker_executable="docker",
            )
        return result, key, events, captured

    def test_fixed_policy_has_one_input_and_all_replay_defaults(self) -> None:
        policy = fixed_e4_execution_policy_v1(self.IMAGE_A)
        self.assertEqual(policy.runtime_image_id, self.IMAGE_A)
        self.assertEqual(policy.d2_backend_id, REPLAY_BACKEND_ID)
        self.assertEqual(policy.d3_backend_id, REPLAY_BACKEND_ID)
        self.assertEqual(policy.d2_model_id, REPLAY_MODEL_ID)
        self.assertEqual(policy.d3_model_id, REPLAY_MODEL_ID)
        self.assertEqual(
            policy.snapshot_policy_sha256,
            snapshot_policy_sha256_v1(DEFAULT_SNAPSHOT_POLICY),
        )
        self.assertEqual(
            policy.d2_budget_sha256,
            budget_limits_sha256_v1(DEFAULT_D2_WORKER_BUDGET_LIMITS),
        )
        self.assertEqual(
            policy.d3_budget_sha256,
            budget_limits_sha256_v1(DEFAULT_D3_WORKER_BUDGET_LIMITS),
        )
        self.assertEqual(
            policy.tree_limits_sha256,
            tree_limits_sha256_v1(DEFAULT_SEALED_TREE_ACCESS_LIMITS),
        )
        self.assertEqual(policy.network_mode, "none")
        self.assertEqual(policy.rootfs_mode, "read-only")
        with self.assertRaises(E4DriverError):
            fixed_e4_execution_policy_v1("python:latest")
        with self.assertRaises(E4DriverError):
            fixed_e4_execution_policy_v1(True)

    def test_success_checks_every_input_before_oci_and_reads_back_exact_bytes(self) -> None:
        result, key, events, captured = self._run_success(split="test")
        self.assertIs(type(result), _FakeSuccess)
        self.assertEqual(
            events,
            ["tasks:test", "replay", "prepare", "verify", "run", "read", "abort"],
        )
        self.assertEqual(key, bytearray(40))
        self.assertEqual(captured["task_split"], "test")
        replay = captured["replay"]
        self.assertEqual(replay["expected_split"], "test")
        self.assertEqual(len(replay["expected_task_ids"]), 20)
        self.assertEqual(
            replay["expected_manifest_sha256"],
            _sha("test:replay-manifest:semantic"),
        )
        self.assertEqual(
            replay["expected_manifest_wire_sha256"],
            _sha("test:replay-manifest:wire"),
        )
        prepare = captured["prepare"]
        self.assertEqual(prepare["attestation_key"], b"K" * 40)
        self.assertEqual(prepare["expected_key_id"], self.KEY_ID)
        self.assertEqual(
            prepare["execution_policy"].to_bytes(),
            captured["runtime_policy"].to_bytes(),
        )
        self.assertEqual(
            captured["read"],
            {
                "expected_receipt_sha256": result.receipt_sha256,
                "expected_wire_sha256": result.wire_sha256,
            },
        )

    def test_public_task_order_mismatch_stops_before_any_oci_probe(self) -> None:
        public, configs, plan = self._prepared("test")
        events: list[str] = []
        session = _FakeSession(plan, events)
        key = bytearray(b"Q" * 40)
        verify = mock.Mock()
        run = mock.Mock()
        reader = mock.Mock()
        with (
            mock.patch.object(driver, "DiscoveryExecutionSession", _FakeSession),
            mock.patch.object(
                driver, "load_answer_free_tasks", return_value=tuple(reversed(public))
            ),
            mock.patch.object(
                driver, "load_batch_replay_configs_v1", return_value=configs
            ),
            mock.patch.object(
                driver, "prepare_discovery_execution_plan_v1", return_value=session
            ),
            mock.patch.object(driver, "verify_linux_oci_runtime_v1", verify),
            mock.patch.object(driver, "run_prepared_discovery_batch_v1", run),
            mock.patch.object(
                driver, "read_committed_e4_discovery_execution_v1", reader
            ),
        ):
            with self.assertRaises(E4DriverError) as captured:
                run_e4_discovery_split_v1(
                    "benchmark",
                    "sealed",
                    "replay",
                    "output",
                    split="test",
                    expected_sealed_batch_manifest_sha256=(
                        plan.batch.batch_manifest_sha256
                    ),
                    expected_replay_manifest_sha256=_sha("replay"),
                    expected_replay_manifest_wire_sha256=_sha("replay-wire"),
                    snapshot_attestation_key=key,
                    snapshot_key_id=self.KEY_ID,
                    runtime_image_id=self.IMAGE_A,
                    docker_executable="docker",
                )
        self.assertEqual(captured.exception.code, "public_task_mismatch")
        verify.assert_not_called()
        run.assert_not_called()
        reader.assert_not_called()
        self.assertEqual(events, ["abort"])
        self.assertEqual(key, bytearray(40))

    def test_manifest_and_policy_mismatch_both_stop_before_oci(self) -> None:
        cases = (
            {
                "name": "manifest",
                "plan_image": self.IMAGE_A,
                "call_image": self.IMAGE_A,
                "plan_sealed": _sha("plan-sealed"),
                "expected_sealed": _sha("other-sealed"),
            },
            {
                "name": "policy",
                "plan_image": self.IMAGE_B,
                "call_image": self.IMAGE_A,
                "plan_sealed": _sha("same-sealed"),
                "expected_sealed": _sha("same-sealed"),
            },
        )
        for case in cases:
            with self.subTest(case=case["name"]):
                with self.assertRaises(E4DriverError) as captured:
                    self._run_success(
                        plan_image=case["plan_image"],
                        call_image=case["call_image"],
                        plan_sealed=case["plan_sealed"],
                        expected_sealed=case["expected_sealed"],
                    )
                self.assertEqual(captured.exception.code, "plan_mismatch")

    def test_failure_report_is_normalized_without_reading_success_directory(self) -> None:
        public, configs, plan = self._prepared("train")
        events: list[str] = []
        session = _FakeSession(plan, events)
        failure = _FakeFailure("train-failed", plan)
        key = bytearray(b"R" * 40)
        reader = mock.Mock(side_effect=AssertionError("must not read success output"))
        with (
            mock.patch.object(driver, "DiscoveryExecutionSession", _FakeSession),
            mock.patch.object(
                driver, "DiscoveryBatchAttemptReportV1", _FakeFailure
            ),
            mock.patch.object(driver, "load_answer_free_tasks", return_value=public),
            mock.patch.object(
                driver, "load_batch_replay_configs_v1", return_value=configs
            ),
            mock.patch.object(
                driver, "prepare_discovery_execution_plan_v1", return_value=session
            ),
            mock.patch.object(
                driver, "verify_linux_oci_runtime_v1", return_value=object()
            ),
            mock.patch.object(
                driver, "run_prepared_discovery_batch_v1", return_value=failure
            ),
            mock.patch.object(
                driver, "read_committed_e4_discovery_execution_v1", reader
            ),
        ):
            result = run_e4_discovery_split_v1(
                "benchmark",
                "sealed",
                "replay",
                "output",
                split="train",
                expected_sealed_batch_manifest_sha256=(
                    plan.batch.batch_manifest_sha256
                ),
                expected_replay_manifest_sha256=_sha("replay"),
                expected_replay_manifest_wire_sha256=_sha("replay-wire"),
                snapshot_attestation_key=key,
                snapshot_key_id=self.KEY_ID,
                runtime_image_id=self.IMAGE_A,
                docker_executable="docker",
            )
        self.assertEqual(result, failure)
        reader.assert_not_called()
        self.assertEqual(events, ["abort"])
        self.assertEqual(key, bytearray(40))

    def test_success_readback_mismatch_is_committed_stable_failure(self) -> None:
        with self.assertRaises(E4DriverError) as captured:
            _, _, plan = self._prepared("test")
            self._run_success(reader_result=_FakeSuccess("substituted", plan))
        self.assertEqual(captured.exception.code, "publication_mismatch")
        self.assertTrue(captured.exception.committed)
        self.assertNotIn("output-root", str(captured.exception))

    def test_success_receipt_with_another_valid_plan_is_rejected_before_read(self) -> None:
        with self.assertRaises(E4DriverError) as captured:
            self._run_success(outcome_plan_image=self.IMAGE_B)
        self.assertEqual(captured.exception.code, "runner_contract_mismatch")
        self.assertTrue(captured.exception.committed)

    def test_failure_report_with_another_valid_plan_is_rejected_without_read(self) -> None:
        public, configs, prepared_plan = self._prepared("test")
        _, _, swapped_plan = self._prepared("test", image_id=self.IMAGE_B)
        events: list[str] = []
        session = _FakeSession(prepared_plan, events)
        failure = _FakeFailure("swapped-plan", swapped_plan)
        key = bytearray(b"V" * 40)
        reader = mock.Mock()
        with (
            mock.patch.object(driver, "DiscoveryExecutionSession", _FakeSession),
            mock.patch.object(
                driver, "DiscoveryBatchAttemptReportV1", _FakeFailure
            ),
            mock.patch.object(driver, "load_answer_free_tasks", return_value=public),
            mock.patch.object(
                driver, "load_batch_replay_configs_v1", return_value=configs
            ),
            mock.patch.object(
                driver, "prepare_discovery_execution_plan_v1", return_value=session
            ),
            mock.patch.object(
                driver, "verify_linux_oci_runtime_v1", return_value=object()
            ),
            mock.patch.object(
                driver, "run_prepared_discovery_batch_v1", return_value=failure
            ),
            mock.patch.object(
                driver, "read_committed_e4_discovery_execution_v1", reader
            ),
        ):
            with self.assertRaises(E4DriverError) as captured:
                run_e4_discovery_split_v1(
                    "benchmark",
                    "sealed",
                    "replay",
                    "output",
                    split="test",
                    expected_sealed_batch_manifest_sha256=(
                        prepared_plan.batch.batch_manifest_sha256
                    ),
                    expected_replay_manifest_sha256=_sha("replay"),
                    expected_replay_manifest_wire_sha256=_sha("replay-wire"),
                    snapshot_attestation_key=key,
                    snapshot_key_id=self.KEY_ID,
                    runtime_image_id=self.IMAGE_A,
                    docker_executable="docker",
                )
        self.assertEqual(captured.exception.code, "runner_contract_mismatch")
        reader.assert_not_called()
        self.assertEqual(key, bytearray(40))

    def test_public_reader_error_is_path_free_and_key_is_zeroed(self) -> None:
        key = bytearray(b"S" * 40)
        leaked = "C:\\private\\benchmark\\answer.jsonl"
        with mock.patch.object(
            driver,
            "load_answer_free_tasks",
            side_effect=BenchmarkHarnessError("rejected", leaked),
        ):
            with self.assertRaises(E4DriverError) as captured:
                run_e4_discovery_split_v1(
                    leaked,
                    "sealed",
                    "replay",
                    "output",
                    split="test",
                    expected_sealed_batch_manifest_sha256=_sha("sealed"),
                    expected_replay_manifest_sha256=_sha("replay"),
                    expected_replay_manifest_wire_sha256=_sha("replay-wire"),
                    snapshot_attestation_key=key,
                    snapshot_key_id=self.KEY_ID,
                    runtime_image_id=self.IMAGE_A,
                    docker_executable="docker",
                )
        self.assertEqual(captured.exception.code, "public_input_rejected")
        self.assertNotIn(leaked, str(captured.exception))
        self.assertIsNone(captured.exception.__cause__)
        self.assertEqual(key, bytearray(40))

    def test_base_exception_after_prepare_still_aborts_and_zeroes_key(self) -> None:
        public, configs, plan = self._prepared("test")
        events: list[str] = []
        session = _FakeSession(plan, events)
        key = bytearray(b"T" * 40)
        with (
            mock.patch.object(driver, "DiscoveryExecutionSession", _FakeSession),
            mock.patch.object(driver, "load_answer_free_tasks", return_value=public),
            mock.patch.object(
                driver, "load_batch_replay_configs_v1", return_value=configs
            ),
            mock.patch.object(
                driver, "prepare_discovery_execution_plan_v1", return_value=session
            ),
            mock.patch.object(
                driver, "verify_linux_oci_runtime_v1", return_value=object()
            ),
            mock.patch.object(
                driver,
                "run_prepared_discovery_batch_v1",
                side_effect=KeyboardInterrupt(),
            ),
        ):
            with self.assertRaises(KeyboardInterrupt):
                run_e4_discovery_split_v1(
                    "benchmark",
                    "sealed",
                    "replay",
                    "output",
                    split="test",
                    expected_sealed_batch_manifest_sha256=(
                        plan.batch.batch_manifest_sha256
                    ),
                    expected_replay_manifest_sha256=_sha("replay"),
                    expected_replay_manifest_wire_sha256=_sha("replay-wire"),
                    snapshot_attestation_key=key,
                    snapshot_key_id=self.KEY_ID,
                    runtime_image_id=self.IMAGE_A,
                    docker_executable="docker",
                )
        self.assertEqual(events, ["abort"])
        self.assertEqual(key, bytearray(40))

    def test_primary_base_exception_wins_over_abort_error_but_key_is_zeroed(self) -> None:
        public, configs, plan = self._prepared("test")
        events: list[str] = []
        session = _FakeSession(plan, events, abort_error=RuntimeError("abort"))
        key = bytearray(b"U" * 40)
        with (
            mock.patch.object(driver, "DiscoveryExecutionSession", _FakeSession),
            mock.patch.object(driver, "load_answer_free_tasks", return_value=public),
            mock.patch.object(
                driver, "load_batch_replay_configs_v1", return_value=configs
            ),
            mock.patch.object(
                driver, "prepare_discovery_execution_plan_v1", return_value=session
            ),
            mock.patch.object(
                driver, "verify_linux_oci_runtime_v1", return_value=object()
            ),
            mock.patch.object(
                driver,
                "run_prepared_discovery_batch_v1",
                side_effect=KeyboardInterrupt(),
            ),
        ):
            with self.assertRaises(KeyboardInterrupt):
                run_e4_discovery_split_v1(
                    "benchmark",
                    "sealed",
                    "replay",
                    "output",
                    split="test",
                    expected_sealed_batch_manifest_sha256=(
                        plan.batch.batch_manifest_sha256
                    ),
                    expected_replay_manifest_sha256=_sha("replay"),
                    expected_replay_manifest_wire_sha256=_sha("replay-wire"),
                    snapshot_attestation_key=key,
                    snapshot_key_id=self.KEY_ID,
                    runtime_image_id=self.IMAGE_A,
                    docker_executable="docker",
                )
        self.assertEqual(events, ["abort"])
        self.assertEqual(key, bytearray(40))

    def test_stable_primary_error_preserves_code_and_marks_abort_failure(self) -> None:
        with self.assertRaises(E4DriverError) as captured:
            self._run_success(
                plan_image=self.IMAGE_B,
                call_image=self.IMAGE_A,
                abort_error=RuntimeError("abort path must stay hidden"),
            )
        self.assertEqual(captured.exception.code, "plan_mismatch")
        self.assertTrue(captured.exception.cleanup_failed)
        self.assertNotIn("abort path", str(captured.exception))

    def test_invalid_exact_bytearray_is_rejected_and_short_key_is_zeroed(self) -> None:
        with self.assertRaises(E4DriverError) as captured:
            run_e4_discovery_split_v1(
                "benchmark",
                "sealed",
                "replay",
                "output",
                split="test",
                expected_sealed_batch_manifest_sha256=_sha("sealed"),
                expected_replay_manifest_sha256=_sha("replay"),
                expected_replay_manifest_wire_sha256=_sha("replay-wire"),
                snapshot_attestation_key=b"not-a-bytearray",
                snapshot_key_id=self.KEY_ID,
                runtime_image_id=self.IMAGE_A,
                docker_executable="docker",
            )
        self.assertEqual(captured.exception.code, "invalid_argument")

        short = bytearray(b"short")
        with self.assertRaises(E4DriverError) as captured:
            run_e4_discovery_split_v1(
                "benchmark",
                "sealed",
                "replay",
                "output",
                split="test",
                expected_sealed_batch_manifest_sha256=_sha("sealed"),
                expected_replay_manifest_sha256=_sha("replay"),
                expected_replay_manifest_wire_sha256=_sha("replay-wire"),
                snapshot_attestation_key=short,
                snapshot_key_id=self.KEY_ID,
                runtime_image_id=self.IMAGE_A,
                docker_executable="docker",
            )
        self.assertEqual(captured.exception.code, "invalid_argument")
        self.assertEqual(short, bytearray(5))


if __name__ == "__main__":
    unittest.main()
