from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest import mock

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.harness import (
    DiscoveryProjectionSummary,
    PROFILE_TEST_TASKS,
    PROFILE_TRAIN_TASKS,
    TrainingAggregate,
)
from vulngym_agent.benchmark.projection_reader import (
    DiscoveryProjectionReaderError,
    VerifiedDiscoveryProjectionV1,
)
from vulngym_agent.evaluator.batch_configs import (
    BatchReplayConfigManifestV1,
    TaskReplayConfigBindingV1,
)
from vulngym_agent.evaluator.e4_driver import fixed_e4_execution_policy_v1
from vulngym_agent.evaluator.e4_driver import E4DriverError
from vulngym_agent.evaluator.final_gate import (
    FINAL_GATE_PLAN_FILENAME,
    FINAL_GATE_RECEIPT_FILENAME,
    FinalGatePlanV1,
    FinalGateReceiptV1,
    FinalGateSplitPlanV1,
)
import vulngym_agent.evaluator.final_gate_runner as runner
from vulngym_agent.evaluator.final_gate_runner import (
    FinalGateRunnerError,
    run_e4_final_gate_v1,
)
from vulngym_agent.evaluator.runtime_evidence import (
    RuntimeBindingPinsV1,
    docker_endpoint_sha256_v1,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class _FakeExecutionPlan:
    def __init__(
        self,
        *,
        split: str,
        count: int,
        policy: object,
        sealed_sha256: str,
        key_id: str,
    ) -> None:
        prefix = "TEST" if split == "test" else "TRAIN"
        members = []
        plans = []
        for index in range(count):
            task_id = f"VG-{prefix}-{index:020X}"
            members.append(
                SimpleNamespace(
                    task_id=task_id,
                    repo_url=f"https://github.com/example/{split}-{index:02d}",
                    commit=f"{index + 1:040x}",
                    split=split,
                    instruction_id=INSTRUCTION_ID,
                )
            )
            plans.append(
                SimpleNamespace(
                    task_id=task_id,
                    snapshot_id=f"VGS-{index + (0 if split == 'test' else 100):032X}",
                    d2_replay_sha256=_sha(f"{split}:{index}:d2"),
                    d2_replay_wire_sha256=_sha(f"{split}:{index}:d2-wire"),
                    d3_replay_sha256=_sha(f"{split}:{index}:d3"),
                    d3_replay_wire_sha256=_sha(f"{split}:{index}:d3-wire"),
                )
            )
        self.batch = SimpleNamespace(
            split=split,
            task_count=count,
            batch_manifest_sha256=sealed_sha256,
            attestation_key_id=key_id,
            tasks=tuple(members),
        )
        self.execution_policy = policy
        self.tasks = tuple(plans)
        self.plan_sha256 = _sha(f"{split}:execution-plan")

    def to_bytes(self) -> bytes:
        return f'{{"split":"{self.batch.split}"}}\n'.encode("ascii")

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()


class _FakeSuccess:
    _registry: dict[bytes, "_FakeSuccess"] = {}

    def __init__(
        self,
        *,
        split: str,
        count: int,
        policy: object,
        sealed_sha256: str,
        key_id: str,
    ) -> None:
        execution_plan = _FakeExecutionPlan(
            split=split,
            count=count,
            policy=policy,
            sealed_sha256=sealed_sha256,
            key_id=key_id,
        )
        task_receipts = tuple(
            SimpleNamespace(
                task_id=item.task_id,
                dataset_sha256=_sha(f"{split}:dataset:{index}"),
            )
            for index, item in enumerate(execution_plan.tasks)
        )
        self.execution_receipt = SimpleNamespace(
            plan=execution_plan,
            tasks=task_receipts,
            artifact_index_sha256=_sha(f"{split}:artifact-index"),
        )
        self.receipt_sha256 = _sha(f"{split}:e4-receipt")
        self._wire = f'{{"e4":"{split}"}}\n'.encode("ascii")
        self._registry[self._wire] = self

    def to_bytes(self) -> bytes:
        return self._wire

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self._wire).hexdigest()

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_receipt_sha256: str,
        expected_wire_sha256: str,
    ) -> "_FakeSuccess":
        result = cls._registry[payload]
        if (
            result.receipt_sha256 != expected_receipt_sha256
            or result.wire_sha256 != expected_wire_sha256
        ):
            raise ValueError("detached fake success")
        return result


class _FakeAttempt:
    def __init__(self, split: str) -> None:
        self.split = split


class FinalGateRunnerTests(unittest.TestCase):
    IMAGE = "sha256:" + "a" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.paths: dict[str, Path] = {}
        for name in (
            "benchmark",
            "test-sealed",
            "test-replay",
            "train-sealed",
            "train-replay",
        ):
            path = self.base / name
            path.mkdir()
            self.paths[name] = path
        policy = fixed_e4_execution_policy_v1(self.IMAGE)
        self.policy = policy
        self.runtime_binding = RuntimeBindingPinsV1(
            daemon_endpoint_sha256=docker_endpoint_sha256_v1(
                "unix:///run/vulngym/docker.sock"
            ),
            docker_executable_sha256=_sha("docker-cli"),
            docker_socket_identity_sha256=_sha("docker-socket"),
            server_observation_sha256=_sha("docker-server"),
            daemon_info_sha256=_sha("docker-info"),
            runtime_image_id=self.IMAGE,
            runtime_image_inspect_sha256=_sha("runtime-image"),
        )
        replay_manifests = {
            split: BatchReplayConfigManifestV1(
                split=split,
                tasks=tuple(
                    TaskReplayConfigBindingV1(
                        task_id=f"VG-{'TEST' if split == 'test' else 'TRAIN'}-{index:020X}",
                        d2_replay_sha256=_sha(f"{split}:{index}:d2"),
                        d2_replay_wire_sha256=_sha(
                            f"{split}:{index}:d2-wire"
                        ),
                        d3_replay_sha256=_sha(f"{split}:{index}:d3"),
                        d3_replay_wire_sha256=_sha(
                            f"{split}:{index}:d3-wire"
                        ),
                    )
                    for index in range(
                        PROFILE_TEST_TASKS
                        if split == "test"
                        else PROFILE_TRAIN_TASKS
                    )
                ),
            )
            for split in ("test", "train")
        }
        self.plan = FinalGatePlanV1(
            execution_policy_sha256=policy.policy_sha256,
            execution_policy_wire_sha256=policy.wire_sha256,
            test=FinalGateSplitPlanV1(
                split="test",
                task_count=PROFILE_TEST_TASKS,
                sealed_batch_manifest_sha256=_sha("test:sealed"),
                replay_manifest_sha256=replay_manifests[
                    "test"
                ].manifest_sha256,
                replay_manifest_wire_sha256=replay_manifests["test"].wire_sha256,
                snapshot_key_id="test-key",
            ),
            train=FinalGateSplitPlanV1(
                split="train",
                task_count=PROFILE_TRAIN_TASKS,
                sealed_batch_manifest_sha256=_sha("train:sealed"),
                replay_manifest_sha256=replay_manifests[
                    "train"
                ].manifest_sha256,
                replay_manifest_wire_sha256=replay_manifests[
                    "train"
                ].wire_sha256,
                snapshot_key_id="train-key",
            ),
        )

    def _successes(self) -> dict[str, _FakeSuccess]:
        return {
            "test": _FakeSuccess(
                split="test",
                count=PROFILE_TEST_TASKS,
                policy=self.policy,
                sealed_sha256=self.plan.test.sealed_batch_manifest_sha256,
                key_id=self.plan.test.snapshot_key_id,
            ),
            "train": _FakeSuccess(
                split="train",
                count=PROFILE_TRAIN_TASKS,
                policy=self.policy,
                sealed_sha256=self.plan.train.sealed_batch_manifest_sha256,
                key_id=self.plan.train.snapshot_key_id,
            ),
        }

    def _arguments(
        self,
        *,
        output: Path | None = None,
        test_key: bytearray | None = None,
        train_key: bytearray | None = None,
        plan: FinalGatePlanV1 | None = None,
    ) -> dict[str, object]:
        return {
            "benchmark_root": self.paths["benchmark"],
            "output_root": output or (self.base / "final-output"),
            "docker_executable": "docker",
            "runtime_image_id": self.IMAGE,
            "docker_endpoint": "unix:///run/vulngym/docker.sock",
            "expected_runtime_binding": self.runtime_binding,
            "plan": plan or self.plan,
            "test_sealed_batch_root": self.paths["test-sealed"],
            "test_replay_config_root": self.paths["test-replay"],
            "train_sealed_batch_root": self.paths["train-sealed"],
            "train_replay_config_root": self.paths["train-replay"],
            "test_snapshot_attestation_key": test_key or bytearray(b"T" * 40),
            "train_snapshot_attestation_key": train_key or bytearray(b"R" * 40),
        }

    def _projection_summary(
        self, split: str, success: _FakeSuccess
    ) -> DiscoveryProjectionSummary:
        count = PROFILE_TEST_TASKS if split == "test" else PROFILE_TRAIN_TASKS
        aggregate = None
        if split == "train":
            aggregate = TrainingAggregate(
                total_advisories=1,
                covered_advisories=0,
                advisory_recall=0.0,
                total_entries=1,
                matched_entries=0,
                entry_recall=0.0,
                submitted_findings=count,
            )
        return DiscoveryProjectionSummary(
            split=split,
            task_count=count,
            finalized_task_count=count,
            deferred_task_count=0,
            candidate_count=count,
            finding_count=count,
            bundle_index_sha256=(
                success.execution_receipt.artifact_index_sha256
            ),
            output_manifest_sha256=_sha(f"{split}:projection-manifest"),
            aggregate=aggregate,
        )

    def _patch_success_pipeline(
        self,
        events: list[str],
        *,
        driver_override=None,
        projection_reader_override=None,
        final_reader_override=None,
        expected_mount_table=None,
    ) -> ExitStack:
        successes = self._successes()
        summaries = {
            split: self._projection_summary(split, success)
            for split, success in successes.items()
        }

        def drive(_benchmark, _sealed, _replay, output, **kwargs):
            split = kwargs["split"]
            events.append(f"execute:{split}")
            if expected_mount_table is not None:
                self.assertIs(
                    kwargs["expected_mount_table"], expected_mount_table
                )
            self.assertNotEqual(bytes(kwargs["snapshot_attestation_key"]), bytes(40))
            Path(output).mkdir(mode=0o700)
            if driver_override is not None:
                return driver_override(split, output, kwargs, successes)
            return successes[split]

        def project(_benchmark, **kwargs):
            split = kwargs["split"]
            events.append(f"project:{split}")
            self.assertEqual(kwargs["top_k"], 64)
            self.assertEqual(
                kwargs["bundle_index_sha256"],
                successes[split].execution_receipt.artifact_index_sha256,
            )
            Path(kwargs["output_dir"]).mkdir(mode=0o700)
            return summaries[split]

        def read_projection(_output, **kwargs):
            split = kwargs["expected_split"]
            events.append(f"read_projection:{split}")
            if split == "test":
                self.assertIsNone(kwargs["benchmark_root"])
            else:
                self.assertEqual(
                    Path(kwargs["benchmark_root"]),
                    self.paths["benchmark"].resolve(),
                )
            self.assertEqual(len(kwargs["expected_tasks"]), summaries[split].task_count)
            if projection_reader_override is not None:
                return projection_reader_override(split, kwargs, summaries)
            return VerifiedDiscoveryProjectionV1(
                summary=summaries[split],
                aggregate_file_sha256=(
                    None if split == "test" else _sha("train:aggregate-file")
                ),
            )

        def read_final(output, **kwargs):
            events.append("read_final")
            if final_reader_override is not None:
                return final_reader_override(output, kwargs)
            payload = (Path(output) / FINAL_GATE_RECEIPT_FILENAME).read_bytes()
            return FinalGateReceiptV1.from_bytes(
                payload,
                expected_receipt_sha256=kwargs["expected_receipt_sha256"],
                expected_wire_sha256=kwargs["expected_wire_sha256"],
            )

        stack = ExitStack()
        stack.enter_context(
            mock.patch.object(runner, "E4BatchSuccessReceiptV2", _FakeSuccess)
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "run_e4_discovery_split_v1",
                side_effect=drive,
            )
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "project_verified_discovery_bundles",
                side_effect=project,
            )
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "read_committed_discovery_projection_v1",
                side_effect=read_projection,
            )
        )
        stack.enter_context(
            mock.patch.object(
                runner,
                "read_committed_e4_final_gate_v1",
                side_effect=read_final,
            )
        )
        return stack

    def test_success_is_test_first_and_publishes_one_exact_outer_tree(self) -> None:
        events: list[str] = []
        test_key = bytearray(b"T" * 40)
        train_key = bytearray(b"R" * 40)
        output = self.base / "closed"
        with self._patch_success_pipeline(events):
            result = run_e4_final_gate_v1(
                **self._arguments(
                    output=output, test_key=test_key, train_key=train_key
                )
            )

        self.assertIs(type(result), FinalGateReceiptV1)
        self.assertEqual(
            events,
            [
                "execute:test",
                "project:test",
                "read_projection:test",
                "execute:train",
                "project:train",
                "read_projection:train",
                "read_final",
            ],
        )
        self.assertEqual(test_key, bytearray(40))
        self.assertEqual(train_key, bytearray(40))
        self.assertEqual(
            {item.name for item in output.iterdir()},
            {FINAL_GATE_PLAN_FILENAME, FINAL_GATE_RECEIPT_FILENAME, "test", "train"},
        )
        self.assertEqual(
            {item.name for item in (output / "test").iterdir()},
            {"execution", "projection"},
        )
        self.assertEqual(
            {item.name for item in (output / "train").iterdir()},
            {"execution", "projection"},
        )
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((output / FINAL_GATE_PLAN_FILENAME).stat().st_mode),
                0o600,
            )
            self.assertEqual(
                stat.S_IMODE((output / FINAL_GATE_RECEIPT_FILENAME).stat().st_mode),
                0o600,
            )
        self.assertEqual(list(self.base.glob(".closed.*.staging")), [])

    def test_test_attempt_report_returns_without_projection_train_or_publication(self) -> None:
        events: list[str] = []
        report = _FakeAttempt("test")

        def attempt(split, _output, _kwargs, _successes):
            self.assertEqual(split, "test")
            return report

        test_key = bytearray(b"T" * 40)
        train_key = bytearray(b"R" * 40)
        output = self.base / "attempt"
        with (
            self._patch_success_pipeline(events, driver_override=attempt),
            mock.patch.object(runner, "DiscoveryBatchAttemptReportV2", _FakeAttempt),
        ):
            result = run_e4_final_gate_v1(
                **self._arguments(
                    output=output, test_key=test_key, train_key=train_key
                )
            )

        self.assertIs(result, report)
        self.assertEqual(events, ["execute:test"])
        self.assertFalse(output.exists())
        self.assertEqual(test_key, bytearray(40))
        self.assertEqual(train_key, bytearray(40))
        staging = list(self.base.glob(".attempt.*.staging"))
        self.assertEqual(len(staging), 1)
        self.assertEqual({item.name for item in staging[0].iterdir()}, {"test"})

    def test_test_projection_read_failure_never_creates_or_calls_train(self) -> None:
        events: list[str] = []

        def reject(split, _kwargs, _summaries):
            if split == "test":
                raise DiscoveryProjectionReaderError(
                    "projection_invalid", "test projection rejected"
                )
            self.fail("train projection reader must not run")

        test_key = bytearray(b"T" * 40)
        train_key = bytearray(b"R" * 40)
        output = self.base / "test-rejected"
        with self._patch_success_pipeline(
            events, projection_reader_override=reject
        ):
            with self.assertRaises(FinalGateRunnerError) as captured:
                run_e4_final_gate_v1(
                    **self._arguments(
                        output=output, test_key=test_key, train_key=train_key
                    )
                )

        self.assertFalse(captured.exception.committed)
        self.assertEqual(
            events, ["execute:test", "project:test", "read_projection:test"]
        )
        self.assertFalse(output.exists())
        self.assertEqual(test_key, bytearray(40))
        self.assertEqual(train_key, bytearray(40))
        staging = list(self.base.glob(".test-rejected.*.staging"))
        self.assertEqual(len(staging), 1)
        self.assertNotIn("train", {item.name for item in staging[0].iterdir()})

    def test_detached_test_success_stops_before_projection_and_train(self) -> None:
        events: list[str] = []
        detached_policy = fixed_e4_execution_policy_v1(
            "sha256:" + "b" * 64
        )

        def detached(split, _output, _kwargs, successes):
            self.assertEqual(split, "test")
            return _FakeSuccess(
                split="test",
                count=PROFILE_TEST_TASKS,
                policy=detached_policy,
                sealed_sha256=self.plan.test.sealed_batch_manifest_sha256,
                key_id=self.plan.test.snapshot_key_id,
            )

        output = self.base / "detached"
        with self._patch_success_pipeline(events, driver_override=detached):
            with self.assertRaises(FinalGateRunnerError) as captured:
                run_e4_final_gate_v1(**self._arguments(output=output))
        self.assertEqual(captured.exception.code, "execution_mismatch")
        self.assertEqual(events, ["execute:test"])
        self.assertFalse(output.exists())

    def test_actual_replay_manifest_must_match_both_split_plan_pins(self) -> None:
        events: list[str] = []

        def detached_replay(split, _output, _kwargs, successes):
            self.assertEqual(split, "test")
            success = successes[split]
            first = success.execution_receipt.plan.tasks[0]
            first.d2_replay_sha256 = _sha("detached-actual-d2-replay")
            return success

        output = self.base / "detached-replay"
        with self._patch_success_pipeline(
            events, driver_override=detached_replay
        ):
            with self.assertRaises(FinalGateRunnerError) as captured:
                run_e4_final_gate_v1(**self._arguments(output=output))

        self.assertEqual(captured.exception.code, "replay_mismatch")
        self.assertEqual(events, ["execute:test"])
        self.assertFalse(output.exists())

    def test_train_attempt_is_not_published_after_closed_test(self) -> None:
        events: list[str] = []
        report = _FakeAttempt("train")

        def attempt(split, _output, _kwargs, successes):
            return successes[split] if split == "test" else report

        output = self.base / "train-attempt"
        with (
            self._patch_success_pipeline(events, driver_override=attempt),
            mock.patch.object(runner, "DiscoveryBatchAttemptReportV2", _FakeAttempt),
        ):
            result = run_e4_final_gate_v1(**self._arguments(output=output))

        self.assertIs(result, report)
        self.assertEqual(
            events,
            [
                "execute:test",
                "project:test",
                "read_projection:test",
                "execute:train",
            ],
        )
        self.assertFalse(output.exists())

    def test_postrename_reader_failure_is_stable_and_committed(self) -> None:
        events: list[str] = []

        def reject(_output, _kwargs):
            raise RuntimeError("reader internals must not escape")

        output = self.base / "committed-reader-failure"
        with self._patch_success_pipeline(
            events, final_reader_override=reject
        ):
            with self.assertRaises(FinalGateRunnerError) as captured:
                run_e4_final_gate_v1(**self._arguments(output=output))

        self.assertTrue(captured.exception.committed)
        self.assertEqual(captured.exception.code, "publication_uncertain")
        self.assertTrue(output.is_dir())
        self.assertNotIn(str(output), str(captured.exception))

    def test_interrupted_rename_that_committed_is_reported_committed(self) -> None:
        for failure in (KeyboardInterrupt(), SystemExit(9)):
            with self.subTest(failure=type(failure).__name__):
                events: list[str] = []

                def rename_then_interrupt(source, destination):
                    os.rename(source, destination)
                    raise failure

                output = self.base / f"rename-{type(failure).__name__}"
                with (
                    self._patch_success_pipeline(events),
                    mock.patch.object(
                        runner,
                        "_rename_directory_noreplace",
                        side_effect=rename_then_interrupt,
                    ),
                    self.assertRaises(type(failure)) as captured,
                ):
                    run_e4_final_gate_v1(**self._arguments(output=output))

                self.assertTrue(
                    getattr(captured.exception, "committed", False)
                )
                self.assertTrue(output.is_dir())

    def test_rigid_baseexception_after_rename_uses_shared_commit_state(self) -> None:
        class RigidFatal(BaseException):
            def __setattr__(self, _name, _value):
                raise TypeError("rigid exception")

        failure = RigidFatal("rename returned by side effect only")
        observations: list[str] = []

        def rename_then_fail(source, destination):
            os.rename(source, destination)
            raise failure

        output = self.base / "rename-rigid-baseexception"
        with (
            self._patch_success_pipeline([]),
            mock.patch.object(
                runner,
                "_rename_directory_noreplace",
                side_effect=rename_then_fail,
            ),
            self.assertRaises(RigidFatal) as captured,
        ):
            run_e4_final_gate_v1(
                **self._arguments(output=output),
                commit_callback=observations.append,
            )

        self.assertIs(captured.exception, failure)
        self.assertEqual(observations, ["possible", "committed"])
        self.assertTrue(output.is_dir())

    def test_rename_failure_uses_strict_three_state_classification(self) -> None:
        def fail_rename(_source, _destination):
            raise OSError("rename failed")

        output = self.base / "rename-confirmed-absent"
        with (
            self._patch_success_pipeline([]),
            mock.patch.object(
                runner, "_rename_directory_noreplace", side_effect=fail_rename
            ),
            self.assertRaises(FinalGateRunnerError) as captured,
        ):
            run_e4_final_gate_v1(**self._arguments(output=output))
        self.assertFalse(captured.exception.committed)
        self.assertEqual(captured.exception.code, "publication_failed")
        self.assertFalse(output.exists())

        for classifier in (
            mock.Mock(return_value="unknown"),
            mock.Mock(side_effect=KeyboardInterrupt()),
        ):
            with self.subTest(classifier=repr(classifier.side_effect)):
                output = self.base / f"rename-unknown-{id(classifier)}"
                with (
                    self._patch_success_pipeline([]),
                    mock.patch.object(
                        runner,
                        "_rename_directory_noreplace",
                        side_effect=fail_rename,
                    ),
                    mock.patch.object(
                        runner,
                        "_classify_publication_state",
                        side_effect=classifier,
                    ),
                    self.assertRaises(FinalGateRunnerError) as captured,
                ):
                    run_e4_final_gate_v1(**self._arguments(output=output))
                self.assertTrue(captured.exception.committed)
                self.assertEqual(
                    captured.exception.code, "publication_uncertain"
                )

    def test_classifier_baseexception_preserves_original_interrupt(self) -> None:
        original = KeyboardInterrupt()
        output = self.base / "rename-classifier-interrupted"
        with (
            self._patch_success_pipeline([]),
            mock.patch.object(
                runner,
                "_rename_directory_noreplace",
                side_effect=original,
            ),
            mock.patch.object(
                runner,
                "_classify_publication_state",
                side_effect=SystemExit(7),
            ),
            self.assertRaises(KeyboardInterrupt) as captured,
        ):
            run_e4_final_gate_v1(**self._arguments(output=output))
        self.assertIs(captured.exception, original)
        self.assertTrue(getattr(captured.exception, "committed", False))

    def test_baseexception_before_commit_zeros_both_keys_and_preserves_signal(self) -> None:
        events: list[str] = []

        def interrupt(split, _output, _kwargs, _successes):
            self.assertEqual(split, "test")
            raise KeyboardInterrupt()

        test_key = bytearray(b"T" * 40)
        train_key = bytearray(b"R" * 40)
        output = self.base / "precommit-interrupt"
        with self._patch_success_pipeline(events, driver_override=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                run_e4_final_gate_v1(
                    **self._arguments(
                        output=output, test_key=test_key, train_key=train_key
                    )
                )

        self.assertEqual(events, ["execute:test"])
        self.assertEqual(test_key, bytearray(40))
        self.assertEqual(train_key, bytearray(40))
        self.assertFalse(output.exists())

    def test_every_test_stage_failure_variant_blocks_train_and_zeros_keys(self) -> None:
        cases = (
            ("execution", "exception"),
            ("execution", "keyboard"),
            ("execution", "system_exit"),
            ("projection", "exception"),
            ("projection", "keyboard"),
            ("projection", "system_exit"),
            ("projection_read", "exception"),
            ("projection_read", "keyboard"),
            ("projection_read", "system_exit"),
        )
        for position, error_kind in cases:
            with self.subTest(position=position, error_kind=error_kind):
                events: list[str] = []
                test_key = bytearray(b"T" * 40)
                train_key = bytearray(b"R" * 40)
                output = self.base / f"stop-{position}-{error_kind}"

                def failure() -> BaseException:
                    if error_kind == "keyboard":
                        return KeyboardInterrupt()
                    if error_kind == "system_exit":
                        return SystemExit(9)
                    if position == "execution":
                        return E4DriverError(
                            "inner_committed",
                            "private inner output committed",
                            committed=True,
                        )
                    return RuntimeError("stage failure")

                def fail_execution(
                    split, _output, _kwargs, _successes
                ):
                    self.assertEqual(split, "test")
                    raise failure()

                def fail_projection(_benchmark, **kwargs):
                    events.append(f"project:{kwargs['split']}")
                    raise failure()

                def fail_projection_read(_output, **kwargs):
                    events.append(
                        f"read_projection:{kwargs['expected_split']}"
                    )
                    raise failure()

                with self._patch_success_pipeline(
                    events,
                    driver_override=(
                        fail_execution if position == "execution" else None
                    ),
                ):
                    patches: list[object] = []
                    if position == "projection":
                        patches.append(
                            mock.patch.object(
                                runner,
                                "project_verified_discovery_bundles",
                                side_effect=fail_projection,
                            )
                        )
                    elif position == "projection_read":
                        patches.append(
                            mock.patch.object(
                                runner,
                                "read_committed_discovery_projection_v1",
                                side_effect=fail_projection_read,
                            )
                        )
                    with ExitStack() as stack:
                        for item in patches:
                            stack.enter_context(item)
                        if error_kind == "exception":
                            with self.assertRaises(
                                FinalGateRunnerError
                            ) as captured:
                                run_e4_final_gate_v1(
                                    **self._arguments(
                                        output=output,
                                        test_key=test_key,
                                        train_key=train_key,
                                    )
                                )
                            self.assertFalse(captured.exception.committed)
                        elif error_kind == "keyboard":
                            with self.assertRaises(KeyboardInterrupt):
                                run_e4_final_gate_v1(
                                    **self._arguments(
                                        output=output,
                                        test_key=test_key,
                                        train_key=train_key,
                                    )
                                )
                        else:
                            with self.assertRaises(SystemExit):
                                run_e4_final_gate_v1(
                                    **self._arguments(
                                        output=output,
                                        test_key=test_key,
                                        train_key=train_key,
                                    )
                                )
                self.assertNotIn("execute:train", events)
                self.assertNotIn("project:train", events)
                self.assertNotIn("read_projection:train", events)
                self.assertEqual(test_key, bytearray(40))
                self.assertEqual(train_key, bytearray(40))
                self.assertFalse(output.exists())

    def test_control_tamper_after_write_is_detected_before_outer_rename(self) -> None:
        events: list[str] = []
        original = runner._write_control_file

        def write_then_tamper(path: Path, payload: bytes):
            result = original(path, payload)
            if path.name == FINAL_GATE_RECEIPT_FILENAME:
                plan_path = path.parent / FINAL_GATE_PLAN_FILENAME
                plan_payload = bytearray(plan_path.read_bytes())
                plan_payload[0] = ord("[")
                with plan_path.open("r+b") as stream:
                    stream.write(plan_payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            return result

        output = self.base / "control-tamper"
        with (
            self._patch_success_pipeline(events),
            mock.patch.object(
                runner, "_write_control_file", side_effect=write_then_tamper
            ),
        ):
            with self.assertRaises(FinalGateRunnerError) as captured:
                run_e4_final_gate_v1(**self._arguments(output=output))

        self.assertFalse(captured.exception.committed)
        self.assertFalse(output.exists())

    def test_control_change_between_snapshot_and_rename_is_precommit_rejection(self) -> None:
        events: list[str] = []
        original = runner._outer_composite_identity
        captures = 0

        def capture_then_change(root: Path):
            nonlocal captures
            result = original(root)
            captures += 1
            if captures == 1:
                plan_path = root / FINAL_GATE_PLAN_FILENAME
                payload = bytearray(plan_path.read_bytes())
                payload[0] = ord("[")
                with plan_path.open("r+b") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            return result

        output = self.base / "pre-rename-control-change"
        with (
            self._patch_success_pipeline(events),
            mock.patch.object(
                runner,
                "_outer_composite_identity",
                side_effect=capture_then_change,
            ),
        ):
            with self.assertRaises(FinalGateRunnerError) as captured:
                run_e4_final_gate_v1(**self._arguments(output=output))

        self.assertGreaterEqual(captures, 2)
        self.assertFalse(captured.exception.committed)
        self.assertEqual(captured.exception.code, "staging_changed")
        self.assertFalse(output.exists())

    def test_postreader_component_change_is_committed_uncertainty(self) -> None:
        events: list[str] = []

        def mutate_after_read(output, kwargs):
            payload = (Path(output) / FINAL_GATE_RECEIPT_FILENAME).read_bytes()
            result = FinalGateReceiptV1.from_bytes(
                payload,
                expected_receipt_sha256=kwargs["expected_receipt_sha256"],
                expected_wire_sha256=kwargs["expected_wire_sha256"],
            )
            (Path(output) / "test" / "execution" / "late-member").write_bytes(
                b"changed"
            )
            return result

        output = self.base / "postreader-change"
        with self._patch_success_pipeline(
            events, final_reader_override=mutate_after_read
        ):
            with self.assertRaises(FinalGateRunnerError) as captured:
                run_e4_final_gate_v1(**self._arguments(output=output))

        self.assertTrue(captured.exception.committed)
        self.assertEqual(captured.exception.code, "publication_uncertain")
        self.assertTrue(output.exists())

    def test_preflight_rejects_key_alias_output_overlap_and_policy_mismatch(self) -> None:
        alias = bytearray(b"K" * 40)
        with self.assertRaises(FinalGateRunnerError) as captured:
            run_e4_final_gate_v1(
                **self._arguments(test_key=alias, train_key=alias)
            )
        self.assertEqual(captured.exception.code, "invalid_argument")
        self.assertEqual(alias, bytearray(40))

        left = bytearray(b"L" * 40)
        right = bytearray(b"R" * 40)
        with self.assertRaises(FinalGateRunnerError) as captured:
            run_e4_final_gate_v1(
                **self._arguments(
                    output=self.paths["benchmark"] / "nested-output",
                    test_key=left,
                    train_key=right,
                )
            )
        self.assertEqual(captured.exception.code, "path_overlap")
        self.assertEqual(left, bytearray(40))
        self.assertEqual(right, bytearray(40))

        wrong_image = "sha256:" + "c" * 64
        arguments = self._arguments(output=self.base / "wrong-policy")
        arguments["runtime_image_id"] = wrong_image
        with self.assertRaises(FinalGateRunnerError) as captured:
            run_e4_final_gate_v1(**arguments)
        self.assertEqual(captured.exception.code, "policy_mismatch")
        self.assertFalse((self.base / "wrong-policy").exists())

    def test_bind_mount_alias_overlap_is_fail_closed(self) -> None:
        with (
            mock.patch.object(
                runner, "_linux_mount_table", return_value=mock.sentinel.mounts
            ),
            mock.patch.object(runner, "_physical_overlap", return_value=True),
            self.assertRaises(FinalGateRunnerError) as captured,
        ):
            runner._assert_output_disjoint(
                self.base / "physical-alias-output",
                (self.paths["benchmark"], self.paths["test-sealed"]),
            )
        self.assertEqual(captured.exception.code, "path_overlap")

    def test_one_mount_binding_spans_execution_and_publication(self) -> None:
        events: list[str] = []
        mount_table = runner.LinuxMountTableV1(payload=b"bound\n", entries=())
        arguments = self._arguments(output=self.base / "mount-bound")
        arguments["expected_mount_table"] = mount_table
        with (
            self._patch_success_pipeline(
                events, expected_mount_table=mount_table
            ),
            mock.patch.object(runner, "_physical_overlap", return_value=False),
            mock.patch.object(
                runner, "assert_linux_mount_table_stable_v1"
            ) as stable,
        ):
            result = run_e4_final_gate_v1(**arguments)
        self.assertIs(type(result), FinalGateReceiptV1)
        self.assertGreaterEqual(stable.call_count, 10)
        self.assertTrue(
            all(call.args == (mount_table,) for call in stable.call_args_list)
        )

    def test_postrename_mount_change_is_committed_uncertainty(self) -> None:
        events: list[str] = []
        output = self.base / "postrename-mount-change"
        mount_table = runner.LinuxMountTableV1(payload=b"bound\n", entries=())
        arguments = self._arguments(output=output)
        arguments["expected_mount_table"] = mount_table

        def stable(_table, *, committed=False):
            if committed:
                raise FinalGateRunnerError(
                    "publication_uncertain",
                    "mount namespace changed",
                    committed=True,
                )

        with (
            self._patch_success_pipeline(events),
            mock.patch.object(runner, "_physical_overlap", return_value=False),
            mock.patch.object(
                runner, "_assert_bound_mount_table_stable", side_effect=stable
            ),
            self.assertRaises(FinalGateRunnerError) as captured,
        ):
            run_e4_final_gate_v1(**arguments)
        self.assertTrue(captured.exception.committed)
        self.assertEqual(captured.exception.code, "publication_uncertain")
        self.assertTrue(output.exists())

    def test_public_path_preflight_finishes_before_key_validation(self) -> None:
        test_key = bytearray(b"T" * 8)
        train_key = bytearray(b"R" * 8)
        arguments = self._arguments(
            output=self.base / "not-created",
            test_key=test_key,
            train_key=train_key,
        )
        arguments["test_sealed_batch_root"] = self.base / "missing-public-path"
        with mock.patch.object(runner, "_validate_key") as validate_key:
            with self.assertRaises(FinalGateRunnerError):
                run_e4_final_gate_v1(**arguments)
        validate_key.assert_not_called()
        self.assertEqual(test_key, bytearray(8))
        self.assertEqual(train_key, bytearray(8))

    def test_errors_are_path_free_and_existing_output_is_never_replaced(self) -> None:
        missing = self.base / "PRIVATE-SENSITIVE-MISSING"
        arguments = self._arguments(output=self.base / "unused")
        arguments["test_replay_config_root"] = missing
        with self.assertRaises(FinalGateRunnerError) as captured:
            run_e4_final_gate_v1(**arguments)
        self.assertNotIn(str(missing), str(captured.exception))
        self.assertNotIn("PRIVATE-SENSITIVE-MISSING", str(captured.exception))

        output = self.base / "already-there"
        output.mkdir()
        marker = output / "marker"
        marker.write_text("keep", encoding="utf-8")
        with self.assertRaises(FinalGateRunnerError) as captured:
            run_e4_final_gate_v1(**self._arguments(output=output))
        self.assertEqual(captured.exception.code, "output_exists")
        self.assertEqual(marker.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
