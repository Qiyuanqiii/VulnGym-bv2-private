from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.harness import (
    PROFILE_TEST_TASKS,
    PROFILE_TRAIN_ADVISORIES,
    PROFILE_TRAIN_ENTRIES,
    PROFILE_TRAIN_TASKS,
    DiscoveryProjectionSummary,
    TrainingAggregate,
)
from vulngym_agent.benchmark.projection_reader import (
    DiscoveryProjectionReaderError,
    VerifiedDiscoveryProjectionV1,
)
from vulngym_agent.evaluator.final_gate import (
    FINAL_GATE_EXECUTION_DIRECTORY,
    FINAL_GATE_PLAN_FILENAME,
    FINAL_GATE_PROJECTION_DIRECTORY,
    FINAL_GATE_RECEIPT_FILENAME,
    FINAL_GATE_TEST_DIRECTORY,
    FINAL_GATE_TRAIN_DIRECTORY,
    FinalGatePlanV1,
    FinalGateReceiptV1,
    FinalGateSplitPlanV1,
    FinalGateSplitReceiptClosureV1,
)
from vulngym_agent.evaluator.batch_configs import (
    BatchReplayConfigManifestV1,
    TaskReplayConfigBindingV1,
)
from vulngym_agent.evaluator.e4_receipt import E4BatchSuccessReceiptV2
from vulngym_agent.evaluator.contracts import DiscoveryTaskExecutionPlanV1
import vulngym_agent.evaluator.final_gate_reader as reader_module
from vulngym_agent.evaluator.final_gate_reader import (
    FinalGateReaderError,
    read_committed_e4_final_gate_v1,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class FinalGateReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.benchmark_root = self.base / "trusted-benchmark"
        self.benchmark_root.mkdir()
        self.policy_sha256 = _sha("policy:semantic")
        self.policy_wire_sha256 = _sha("policy:wire")
        self.replay_bindings: dict[
            str, tuple[TaskReplayConfigBindingV1, ...]
        ] = {}
        replay_manifests: dict[str, BatchReplayConfigManifestV1] = {}
        for split, count in (
            ("test", PROFILE_TEST_TASKS),
            ("train", PROFILE_TRAIN_TASKS),
        ):
            prefix = "VG-TEST" if split == "test" else "VG-TRAIN"
            bindings = tuple(
                TaskReplayConfigBindingV1(
                    task_id=f"{prefix}-{index:020X}",
                    d2_replay_sha256=_sha(f"{split}:d2:{index}:semantic"),
                    d2_replay_wire_sha256=_sha(f"{split}:d2:{index}:wire"),
                    d3_replay_sha256=_sha(f"{split}:d3:{index}:semantic"),
                    d3_replay_wire_sha256=_sha(f"{split}:d3:{index}:wire"),
                )
                for index in range(count)
            )
            self.replay_bindings[split] = bindings
            replay_manifests[split] = BatchReplayConfigManifestV1(
                split=split, tasks=bindings
            )
        self.split_plans = {
            split: FinalGateSplitPlanV1(
                split=split,
                task_count=count,
                sealed_batch_manifest_sha256=_sha(f"{split}:sealed"),
                replay_manifest_sha256=(
                    replay_manifests[split].manifest_sha256
                ),
                replay_manifest_wire_sha256=(
                    replay_manifests[split].wire_sha256
                ),
                snapshot_key_id=f"snapshot-key-{split}",
            )
            for split, count in (
                ("test", PROFILE_TEST_TASKS),
                ("train", PROFILE_TRAIN_TASKS),
            )
        }
        self.plan = FinalGatePlanV1(
            execution_policy_sha256=self.policy_sha256,
            execution_policy_wire_sha256=self.policy_wire_sha256,
            test=self.split_plans["test"],
            train=self.split_plans["train"],
        )
        self.e4: dict[str, E4BatchSuccessReceiptV2] = {}
        self.e4_wire_payloads: dict[str, bytes] = {}
        self.projections: dict[str, VerifiedDiscoveryProjectionV1] = {}
        closures: dict[str, FinalGateSplitReceiptClosureV1] = {}
        for split in ("test", "train"):
            e4, closure, projection = self._split_fixture(split)
            self.e4[split] = e4
            closures[split] = closure
            self.projections[split] = projection
        self.receipt = FinalGateReceiptV1(
            plan=self.plan,
            test=closures["test"],
            train=closures["train"],
        )
        self.root = self._write_layout("committed-final-gate")
        self.e4_wire_patcher = mock.patch.object(
            E4BatchSuccessReceiptV2,
            "to_bytes",
            autospec=True,
            side_effect=lambda value: self.e4_wire_payloads[
                value.receipt_sha256
            ],
        )
        self.e4_wire_patcher.start()

    def tearDown(self) -> None:
        self.e4_wire_patcher.stop()
        self.temporary.cleanup()

    def _split_fixture(
        self, split: str
    ) -> tuple[
        E4BatchSuccessReceiptV2,
        FinalGateSplitReceiptClosureV1,
        VerifiedDiscoveryProjectionV1,
    ]:
        split_plan = self.split_plans[split]
        count = split_plan.task_count
        prefix = "VG-TEST" if split == "test" else "VG-TRAIN"
        batch_tasks = tuple(
            SimpleNamespace(
                task_id=f"{prefix}-{index:020X}",
                repo_url=f"https://github.com/example/repo-{index}",
                commit=hashlib.sha1(
                    f"{split}:commit:{index}".encode("utf-8")
                ).hexdigest(),
                split=split,
                instruction_id=INSTRUCTION_ID,
            )
            for index in range(count)
        )
        task_plans = tuple(
            self._forge_task_plan(
                binding=binding,
                snapshot_id=f"VGS-{index:032X}",
            )
            for index, binding in enumerate(self.replay_bindings[split])
        )
        task_receipts = tuple(
            SimpleNamespace(
                task_id=task_plan.task_id,
                snapshot_id=task_plan.snapshot_id,
                dataset_sha256=_sha(f"{split}:dataset:{index}"),
            )
            for index, task_plan in enumerate(task_plans)
        )
        policy = SimpleNamespace(
            policy_sha256=self.policy_sha256,
            wire_sha256=self.policy_wire_sha256,
        )
        execution_plan = SimpleNamespace(
            batch=SimpleNamespace(
                split=split,
                task_count=count,
                tasks=batch_tasks,
                batch_manifest_sha256=split_plan.sealed_batch_manifest_sha256,
                attestation_key_id=split_plan.snapshot_key_id,
                public_manifest_sha256=self.plan.public_manifest_sha256,
            ),
            execution_policy=policy,
            tasks=task_plans,
            plan_sha256=_sha(f"{split}:execution-plan:semantic"),
            wire_sha256=_sha(f"{split}:execution-plan:wire"),
        )
        artifact_index_sha256 = _sha(f"{split}:artifact-index")
        execution_receipt = SimpleNamespace(
            plan=execution_plan,
            tasks=task_receipts,
            artifact_index_sha256=artifact_index_sha256,
        )
        e4 = self._forge_exact_e4(
            execution_receipt=execution_receipt,
            success_closures=tuple(object() for _ in range(count)),
            receipt_sha256=_sha(f"{split}:e4:semantic"),
        )
        e4_wire_payload = f"{split}:exact-e4-wire\n".encode("utf-8")
        self.e4_wire_payloads[e4.receipt_sha256] = e4_wire_payload
        finalized = count
        deferred = 0
        candidate_count = count * 2
        finding_count = count
        aggregate_file_sha256 = (
            None if split == "test" else _sha("train:aggregate-file")
        )
        projection_manifest_sha256 = _sha(f"{split}:projection-manifest")
        closure = FinalGateSplitReceiptClosureV1(
            split=split,
            split_plan_sha256=split_plan.split_plan_sha256,
            split_plan_wire_sha256=split_plan.wire_sha256,
            e4_receipt_sha256=e4.receipt_sha256,
            e4_receipt_wire_sha256=hashlib.sha256(
                e4_wire_payload
            ).hexdigest(),
            execution_policy_sha256=self.policy_sha256,
            execution_policy_wire_sha256=self.policy_wire_sha256,
            execution_plan_sha256=execution_plan.plan_sha256,
            execution_plan_wire_sha256=execution_plan.wire_sha256,
            artifact_index_sha256=artifact_index_sha256,
            projection_manifest_sha256=projection_manifest_sha256,
            task_count=count,
            finalized_task_count=finalized,
            deferred_task_count=deferred,
            candidate_count=candidate_count,
            finding_count=finding_count,
            aggregate_file_sha256=aggregate_file_sha256,
        )
        aggregate = None
        if split == "train":
            aggregate = TrainingAggregate(
                total_advisories=PROFILE_TRAIN_ADVISORIES,
                covered_advisories=0,
                advisory_recall=0.0,
                total_entries=PROFILE_TRAIN_ENTRIES,
                matched_entries=0,
                entry_recall=0.0,
                submitted_findings=finding_count,
            )
        summary = DiscoveryProjectionSummary(
            split=split,
            task_count=count,
            finalized_task_count=finalized,
            deferred_task_count=deferred,
            candidate_count=candidate_count,
            finding_count=finding_count,
            bundle_index_sha256=artifact_index_sha256,
            output_manifest_sha256=projection_manifest_sha256,
            aggregate=aggregate,
        )
        projection = VerifiedDiscoveryProjectionV1(
            summary=summary,
            aggregate_file_sha256=aggregate_file_sha256,
        )
        return e4, closure, projection

    @staticmethod
    def _forge_task_plan(
        *,
        binding: TaskReplayConfigBindingV1,
        snapshot_id: str,
    ) -> DiscoveryTaskExecutionPlanV1:
        value = object.__new__(DiscoveryTaskExecutionPlanV1)
        for name, field_value in (
            ("task_id", binding.task_id),
            ("snapshot_id", snapshot_id),
            ("d2_replay_sha256", binding.d2_replay_sha256),
            ("d2_replay_wire_sha256", binding.d2_replay_wire_sha256),
            ("d3_replay_sha256", binding.d3_replay_sha256),
            ("d3_replay_wire_sha256", binding.d3_replay_wire_sha256),
        ):
            object.__setattr__(value, name, field_value)
        return value

    @staticmethod
    def _forge_exact_e4(
        *,
        execution_receipt: object,
        success_closures: tuple[object, ...],
        receipt_sha256: str,
    ) -> E4BatchSuccessReceiptV2:
        """Make an exact-type inner-reader stand-in without faking its class."""

        value = object.__new__(E4BatchSuccessReceiptV2)
        object.__setattr__(value, "execution_receipt", execution_receipt)
        object.__setattr__(value, "success_closures", success_closures)
        object.__setattr__(value, "receipt_sha256", receipt_sha256)
        return value

    def _write_layout(self, name: str) -> Path:
        root = self.base / name
        root.mkdir()
        for split_directory in (
            FINAL_GATE_TEST_DIRECTORY,
            FINAL_GATE_TRAIN_DIRECTORY,
        ):
            split_root = root / split_directory
            split_root.mkdir()
            (split_root / FINAL_GATE_EXECUTION_DIRECTORY).mkdir()
            (split_root / FINAL_GATE_PROJECTION_DIRECTORY).mkdir()
        (root / FINAL_GATE_PLAN_FILENAME).write_bytes(self.plan.to_bytes())
        (root / FINAL_GATE_RECEIPT_FILENAME).write_bytes(
            self.receipt.to_bytes()
        )
        if os.name == "posix":
            os.chmod(root / FINAL_GATE_PLAN_FILENAME, 0o600)
            os.chmod(root / FINAL_GATE_RECEIPT_FILENAME, 0o600)
        return root

    def _read_with_mocks(
        self,
        *,
        e4_override: dict[str, object] | None = None,
        projection_override: dict[str, object] | None = None,
        timeline: list[tuple[str, object]] | None = None,
    ) -> tuple[FinalGateReceiptV1, list[tuple[str, object]], mock.Mock, mock.Mock]:
        e4_values = {**self.e4, **(e4_override or {})}
        projection_values = {
            **self.projections,
            **(projection_override or {}),
        }
        call_order: list[tuple[str, object]] = []

        def read_e4(path: Path, **kwargs: object) -> object:
            split = Path(path).parent.name
            call_order.append(("execution", split))
            if timeline is not None:
                timeline.append(("execution", split))
            closure = self.receipt.test if split == "test" else self.receipt.train
            self.assertEqual(
                kwargs,
                {
                    "expected_receipt_sha256": closure.e4_receipt_sha256,
                    "expected_wire_sha256": closure.e4_receipt_wire_sha256,
                },
            )
            value = e4_values[split]
            if isinstance(value, BaseException):
                raise value
            return value

        def read_projection(path: Path, **kwargs: object) -> object:
            split = kwargs["expected_split"]
            call_order.append(("projection", split))
            if timeline is not None:
                timeline.append(("projection", split))
            closure = self.receipt.test if split == "test" else self.receipt.train
            self.assertEqual(
                kwargs["expected_manifest_sha256"],
                closure.projection_manifest_sha256,
            )
            self.assertEqual(
                kwargs["expected_artifact_index_sha256"],
                closure.artifact_index_sha256,
            )
            self.assertEqual(
                len(kwargs["expected_tasks"]), closure.task_count
            )
            if split == "test":
                self.assertIsNone(kwargs["benchmark_root"])
            else:
                self.assertEqual(kwargs["benchmark_root"], self.benchmark_root)
            value = projection_values[split]
            if isinstance(value, BaseException):
                raise value
            return value

        e4_mock = mock.Mock(side_effect=read_e4)
        projection_mock = mock.Mock(side_effect=read_projection)
        with (
            mock.patch.object(
                reader_module,
                "read_committed_e4_discovery_execution_v1",
                e4_mock,
            ),
            mock.patch.object(
                reader_module,
                "read_committed_discovery_projection_v1",
                projection_mock,
            ),
        ):
            result = read_committed_e4_final_gate_v1(
                self.root,
                expected_receipt_sha256=self.receipt.receipt_sha256,
                expected_wire_sha256=self.receipt.wire_sha256,
                benchmark_root=self.benchmark_root,
            )
        return result, call_order, e4_mock, projection_mock

    def test_real_contract_files_close_test_first_union_from_external_pins(self) -> None:
        timeline: list[tuple[str, object]] = []
        original_identity = reader_module._materialized_identity

        def capture_identity(path: Path):
            relative = Path(path).relative_to(self.root).as_posix()
            timeline.append(("identity", relative))
            return original_identity(path)

        with (
            mock.patch.object(
                reader_module.FinalGateReceiptV1,
                "from_bytes",
                wraps=reader_module.FinalGateReceiptV1.from_bytes,
            ) as receipt_parser,
            mock.patch.object(
                reader_module.FinalGatePlanV1,
                "from_bytes",
                wraps=reader_module.FinalGatePlanV1.from_bytes,
            ) as plan_parser,
            mock.patch.object(
                reader_module,
                "_materialized_identity",
                side_effect=capture_identity,
            ),
        ):
            result, order, e4_mock, projection_mock = self._read_with_mocks(
                timeline=timeline
            )

        self.assertEqual(result, self.receipt)
        self.assertEqual(
            order,
            [
                ("execution", "test"),
                ("projection", "test"),
                ("execution", "train"),
                ("projection", "train"),
            ],
        )
        self.assertEqual(receipt_parser.call_count, 2)
        # Each receipt parse verifies its embedded plan and each pass then
        # verifies the independently published plan file as well.
        self.assertEqual(plan_parser.call_count, 4)
        self.assertEqual(e4_mock.call_count, 2)
        self.assertEqual(projection_mock.call_count, 2)
        first_train_action = next(
            index
            for index, event in enumerate(timeline)
            if event[1] == "train" or str(event[1]).startswith("train/")
        )
        test_projection_action = timeline.index(("projection", "test"))
        self.assertGreater(first_train_action, test_projection_action)
        test_bindings = projection_mock.call_args_list[0].kwargs[
            "expected_tasks"
        ]
        self.assertEqual(test_bindings[0].task.task_id, "VG-TEST-00000000000000000000")
        self.assertEqual(test_bindings[0].snapshot_id, "VGS-00000000000000000000000000000000")
        self.assertEqual(
            test_bindings[0].dataset_sha256, _sha("test:dataset:0")
        )

    def test_detached_test_train_union_is_rejected_before_projection(self) -> None:
        with self.assertRaises(FinalGateReaderError) as captured:
            self._read_with_mocks(e4_override={"test": self.e4["train"]})
        self.assertEqual(captured.exception.code, "binding_mismatch")
        self.assertTrue(captured.exception.committed)
        self.assertNotIn(str(self.root), str(captured.exception))

    def test_exact_layout_and_contract_file_tampering_are_rejected(self) -> None:
        cases: list[tuple[str, callable]] = [
            (
                "extra-root-member",
                lambda root: (root / "unexpected.bin").write_bytes(b"x"),
            ),
            (
                "extra-split-member",
                lambda root: (root / "test" / "unexpected").mkdir(),
            ),
            (
                "detached-plan",
                lambda root: (root / FINAL_GATE_PLAN_FILENAME).write_bytes(b"{}\n"),
            ),
            (
                "tampered-receipt",
                lambda root: (root / FINAL_GATE_RECEIPT_FILENAME).write_bytes(b"{}\n"),
            ),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                root = self._write_layout(f"tamper-{label}")
                mutate(root)
                with self.assertRaises(FinalGateReaderError) as captured:
                    with (
                        mock.patch.object(
                            reader_module,
                            "read_committed_e4_discovery_execution_v1",
                        ),
                        mock.patch.object(
                            reader_module,
                            "read_committed_discovery_projection_v1",
                        ),
                    ):
                        read_committed_e4_final_gate_v1(
                            root,
                            expected_receipt_sha256=self.receipt.receipt_sha256,
                            expected_wire_sha256=self.receipt.wire_sha256,
                            benchmark_root=self.benchmark_root,
                        )
                self.assertTrue(captured.exception.committed)
                self.assertNotIn(str(root), str(captured.exception))

    def test_contract_hardlink_is_rejected_on_real_windows_root(self) -> None:
        external = self.base / "external-receipt.json"
        external.write_bytes(self.receipt.to_bytes())
        target = self.root / FINAL_GATE_RECEIPT_FILENAME
        target.unlink()
        try:
            os.link(external, target)
        except (NotImplementedError, OSError):
            self.skipTest("hardlinks are unavailable")
        with self.assertRaises(FinalGateReaderError) as captured:
            self._read_with_mocks()
        self.assertEqual(captured.exception.code, "unsafe_member")
        self.assertTrue(captured.exception.committed)

    @unittest.skipUnless(os.name == "posix", "POSIX permission test")
    def test_posix_contract_member_must_be_owner_private(self) -> None:
        target = self.root / FINAL_GATE_RECEIPT_FILENAME
        os.chmod(target, 0o640)
        with self.assertRaises(FinalGateReaderError) as captured:
            self._read_with_mocks()
        self.assertEqual(captured.exception.code, "unsafe_member")
        self.assertTrue(captured.exception.committed)

    def test_blind_test_failure_never_enters_train_oracle_surface(self) -> None:
        call_benchmark_roots: list[object] = []

        def read_e4(path: Path, **_kwargs: object) -> object:
            split = Path(path).parent.name
            return self.e4[split]

        def reject_test(_path: Path, **kwargs: object) -> object:
            call_benchmark_roots.append(kwargs["benchmark_root"])
            raise DiscoveryProjectionReaderError(
                "projection_invalid", "blind projection rejected"
            )

        with (
            mock.patch.object(
                reader_module,
                "read_committed_e4_discovery_execution_v1",
                side_effect=read_e4,
            ) as e4_reader,
            mock.patch.object(
                reader_module,
                "read_committed_discovery_projection_v1",
                side_effect=reject_test,
            ) as projection_reader,
            self.assertRaises(FinalGateReaderError) as captured,
        ):
            read_committed_e4_final_gate_v1(
                self.root,
                expected_receipt_sha256=self.receipt.receipt_sha256,
                expected_wire_sha256=self.receipt.wire_sha256,
                benchmark_root=self.benchmark_root,
            )
        self.assertEqual(captured.exception.code, "final_gate_invalid")
        self.assertEqual(call_benchmark_roots, [None])
        self.assertEqual(e4_reader.call_count, 1)
        self.assertEqual(projection_reader.call_count, 1)

    def test_training_aggregate_file_digest_must_match_closure(self) -> None:
        wrong = VerifiedDiscoveryProjectionV1(
            summary=self.projections["train"].summary,
            aggregate_file_sha256=_sha("wrong-train-aggregate"),
        )
        with self.assertRaises(FinalGateReaderError) as captured:
            self._read_with_mocks(projection_override={"train": wrong})
        self.assertEqual(captured.exception.code, "binding_mismatch")
        self.assertTrue(captured.exception.committed)

    def test_single_task_replay_pin_drift_stops_before_projection(self) -> None:
        original_e4 = self.e4["test"]
        original_plan = original_e4.execution_receipt.plan
        first = original_plan.tasks[0]
        changed_binding = TaskReplayConfigBindingV1(
            task_id=first.task_id,
            d2_replay_sha256=_sha("detached-single-d2-semantic"),
            d2_replay_wire_sha256=first.d2_replay_wire_sha256,
            d3_replay_sha256=first.d3_replay_sha256,
            d3_replay_wire_sha256=first.d3_replay_wire_sha256,
        )
        changed_first = self._forge_task_plan(
            binding=changed_binding,
            snapshot_id=first.snapshot_id,
        )
        changed_plan = SimpleNamespace(**vars(original_plan))
        changed_plan.tasks = (changed_first, *original_plan.tasks[1:])
        changed_execution = SimpleNamespace(
            **vars(original_e4.execution_receipt)
        )
        changed_execution.plan = changed_plan
        changed_e4 = self._forge_exact_e4(
            execution_receipt=changed_execution,
            success_closures=original_e4.success_closures,
            receipt_sha256=original_e4.receipt_sha256,
        )

        e4_reader = mock.Mock(return_value=changed_e4)
        projection_reader = mock.Mock()
        with (
            mock.patch.object(
                reader_module,
                "read_committed_e4_discovery_execution_v1",
                e4_reader,
            ),
            mock.patch.object(
                reader_module,
                "read_committed_discovery_projection_v1",
                projection_reader,
            ),
            self.assertRaises(FinalGateReaderError) as captured,
        ):
            read_committed_e4_final_gate_v1(
                self.root,
                expected_receipt_sha256=self.receipt.receipt_sha256,
                expected_wire_sha256=self.receipt.wire_sha256,
                benchmark_root=self.benchmark_root,
            )
        self.assertEqual(captured.exception.code, "binding_mismatch")
        self.assertEqual(e4_reader.call_count, 1)
        projection_reader.assert_not_called()

    def test_inner_readers_must_return_exact_contract_types(self) -> None:
        non_exact_e4 = SimpleNamespace(
            execution_receipt=self.e4["test"].execution_receipt,
            success_closures=self.e4["test"].success_closures,
            receipt_sha256=self.e4["test"].receipt_sha256,
        )
        with self.assertRaises(FinalGateReaderError) as captured:
            self._read_with_mocks(e4_override={"test": non_exact_e4})
        self.assertEqual(captured.exception.code, "binding_mismatch")

        def read_e4(path: Path, **_kwargs: object) -> E4BatchSuccessReceiptV2:
            return self.e4[Path(path).parent.name]

        projection_reader = mock.Mock(return_value=SimpleNamespace())
        with (
            mock.patch.object(
                reader_module,
                "read_committed_e4_discovery_execution_v1",
                side_effect=read_e4,
            ),
            mock.patch.object(
                reader_module,
                "read_committed_discovery_projection_v1",
                projection_reader,
            ),
            self.assertRaises(FinalGateReaderError) as captured,
        ):
            read_committed_e4_final_gate_v1(
                self.root,
                expected_receipt_sha256=self.receipt.receipt_sha256,
                expected_wire_sha256=self.receipt.wire_sha256,
                benchmark_root=self.benchmark_root,
            )
        self.assertEqual(captured.exception.code, "binding_mismatch")
        self.assertEqual(projection_reader.call_count, 1)

    def test_missing_training_benchmark_root_fails_after_blind_test_only(self) -> None:
        e4_calls: list[str] = []
        projection_calls: list[str] = []

        def read_e4(path: Path, **_kwargs: object) -> E4BatchSuccessReceiptV2:
            split = Path(path).parent.name
            e4_calls.append(split)
            return self.e4[split]

        def read_projection(_path: Path, **kwargs: object) -> object:
            split = kwargs["expected_split"]
            projection_calls.append(split)
            self.assertIsNone(kwargs["benchmark_root"])
            return self.projections[split]

        with (
            mock.patch.object(
                reader_module,
                "read_committed_e4_discovery_execution_v1",
                side_effect=read_e4,
            ),
            mock.patch.object(
                reader_module,
                "read_committed_discovery_projection_v1",
                side_effect=read_projection,
            ),
            self.assertRaises(FinalGateReaderError) as captured,
        ):
            read_committed_e4_final_gate_v1(
                self.root,
                expected_receipt_sha256=self.receipt.receipt_sha256,
                expected_wire_sha256=self.receipt.wire_sha256,
                benchmark_root=None,
            )
        self.assertEqual(captured.exception.code, "invalid_argument")
        self.assertEqual(e4_calls, ["test"])
        self.assertEqual(projection_calls, ["test"])

    def test_external_semantic_and_wire_pins_are_both_required(self) -> None:
        for label, semantic, wire, expected_code in (
            (
                "semantic",
                _sha("wrong-semantic"),
                self.receipt.wire_sha256,
                "final_gate_invalid",
            ),
            (
                "wire",
                self.receipt.receipt_sha256,
                _sha("wrong-wire"),
                "final_gate_invalid",
            ),
            (
                "invalid",
                "not-a-digest",
                self.receipt.wire_sha256,
                "invalid_argument",
            ),
        ):
            with self.subTest(label=label):
                with self.assertRaises(FinalGateReaderError) as captured:
                    with (
                        mock.patch.object(
                            reader_module,
                            "read_committed_e4_discovery_execution_v1",
                        ),
                        mock.patch.object(
                            reader_module,
                            "read_committed_discovery_projection_v1",
                        ),
                    ):
                        read_committed_e4_final_gate_v1(
                            self.root,
                            expected_receipt_sha256=semantic,
                            expected_wire_sha256=wire,
                            benchmark_root=self.benchmark_root,
                        )
                self.assertEqual(captured.exception.code, expected_code)
                self.assertTrue(captured.exception.committed)

    def test_split_policy_plan_index_and_projection_counts_all_bind(self) -> None:
        original_e4 = self.e4["test"]
        detached_plan = SimpleNamespace(
            **vars(original_e4.execution_receipt.plan)
        )
        detached_plan.execution_policy = SimpleNamespace(
            policy_sha256=self.policy_sha256,
            wire_sha256=_sha("detached-policy-wire"),
        )
        detached_execution = SimpleNamespace(
            **vars(original_e4.execution_receipt)
        )
        detached_execution.plan = detached_plan
        detached_e4 = self._forge_exact_e4(
            execution_receipt=detached_execution,
            success_closures=original_e4.success_closures,
            receipt_sha256=original_e4.receipt_sha256,
        )
        with self.assertRaises(FinalGateReaderError) as captured:
            self._read_with_mocks(e4_override={"test": detached_e4})
        self.assertEqual(captured.exception.code, "binding_mismatch")

        detached_summary = replace(
            self.projections["test"].summary,
            candidate_count=self.projections["test"].summary.candidate_count + 1,
        )
        detached_projection = VerifiedDiscoveryProjectionV1(
            summary=detached_summary,
            aggregate_file_sha256=None,
        )
        with self.assertRaises(FinalGateReaderError) as captured:
            self._read_with_mocks(
                projection_override={"test": detached_projection}
            )
        self.assertEqual(captured.exception.code, "binding_mismatch")


if __name__ == "__main__":
    unittest.main()
