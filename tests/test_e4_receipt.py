from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import pickle
import unittest
from unittest import mock

import tests.test_evaluator_contracts as contract_fixtures
import vulngym_agent.evaluator.e4_receipt as e4_receipt_module

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.snapshot_batch import SnapshotBatchTask
from vulngym_agent.evaluator.contracts import (
    DiscoveryBatchExecutionPlanV1,
    DiscoveryBatchExecutionReceiptV1,
    DiscoveryTaskExecutionPlanV1,
    EvaluatorContractError,
    SnapshotBatchBindingV1,
)
from vulngym_agent.evaluator.e4_receipt import (
    E4_BATCH_SUCCESS_RECEIPT_KIND,
    E4_RUNTIME_REVERIFY_POLICY,
    E4_SCHEDULER_VERSION,
    E4_SUCCESS_RECEIPT_FILENAME,
    E4_TASK_SUCCESS_CLOSURE_KIND,
    E4BatchSuccessReceiptV1,
    E4ReceiptError,
    E4SuccessReceiptAuthorityV1,
    E4TaskSuccessClosureV1,
    claim_e4_success_receipt_authority_v1,
)


def _sha(marker: int) -> str:
    return f"{marker:064x}"


def _wire(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _contract_fixture() -> contract_fixtures.EvaluatorContractTests:
    fixture = contract_fixtures.EvaluatorContractTests(methodName="runTest")
    fixture.setUp()
    return fixture


def _success_closures(
    receipt: DiscoveryBatchExecutionReceiptV1,
) -> tuple[E4TaskSuccessClosureV1, ...]:
    return tuple(
        E4TaskSuccessClosureV1(
            task_plan_sha256=task.task_plan_sha256,
            task_id=task.task_id,
            run_sha256=task.run_sha256,
            run_wire_sha256=task.run_wire_sha256,
            discovery_result_sha256=task.discovery_result_sha256,
            runtime_evidence_sha256=task.runtime_evidence_sha256,
        )
        for task in receipt.tasks
    )


def _train_plan() -> DiscoveryBatchExecutionPlanV1:
    fixture = _contract_fixture()
    members = tuple(
        SnapshotBatchTask(
            task_id=f"VG-TRAIN-{index:020X}",
            repo_url=f"https://github.com/example/train-{index}",
            commit=f"{index + 101:040x}",
            split="train",
            instruction_id=INSTRUCTION_ID,
            snapshot_manifest_sha256=_sha(20_000 + index),
            snapshot_content_root=_sha(21_000 + index),
            file_count=1,
            node_count=1,
            total_bytes=100 + index,
        )
        for index in range(50)
    )
    original = fixture.binding
    binding = SnapshotBatchBindingV1(
        profile_id=original.profile_id,
        profile_schema_version=original.profile_schema_version,
        split="train",
        task_count=len(members),
        total_files=sum(item.file_count for item in members),
        total_nodes=sum(item.node_count for item in members),
        total_bytes=sum(item.total_bytes for item in members),
        tasks_sha256=_sha(22_001),
        public_manifest_sha256=original.public_manifest_sha256,
        source_map_sha256=_sha(22_003),
        batch_manifest_sha256=_sha(22_004),
        batch_content_root=_sha(22_005),
        attestation_key_id="e4-train-contract-test",
        snapshot_policy=original.snapshot_policy,
        tasks=members,
    )
    task_plans = []
    for position, member in enumerate(members, 1):
        task = DiscoveryTaskInputV1(
            task_id=member.task_id,
            repo_url=member.repo_url,
            commit=member.commit,
            instruction_id=member.instruction_id,
            snapshot_manifest_sha256=member.snapshot_manifest_sha256,
            snapshot_content_root=member.snapshot_content_root,
        )
        task_plans.append(
            DiscoveryTaskExecutionPlanV1(
                batch_binding_sha256=binding.binding_sha256,
                execution_policy_sha256=fixture.policy.policy_sha256,
                task_id=task.task_id,
                snapshot_id=task.snapshot_id,
                snapshot_manifest_sha256=task.snapshot_manifest_sha256,
                snapshot_content_root=task.snapshot_content_root,
                handoff_sha256=_sha(23_000 + position),
                handoff_wire_sha256=_sha(24_000 + position),
                d2_replay_sha256=_sha(25_000 + position),
                d2_replay_wire_sha256=_sha(26_000 + position),
                d3_replay_sha256=_sha(27_000 + position),
                d3_replay_wire_sha256=_sha(28_000 + position),
            )
        )
    return DiscoveryBatchExecutionPlanV1(
        batch=binding,
        execution_policy=fixture.policy,
        tasks=tuple(task_plans),
    )


def _plan_only_closures(
    plan: DiscoveryBatchExecutionPlanV1,
) -> tuple[E4TaskSuccessClosureV1, ...]:
    return tuple(
        E4TaskSuccessClosureV1(
            task_plan_sha256=task.plan_sha256,
            task_id=task.task_id,
            run_sha256=_sha(30_000 + index),
            run_wire_sha256=_sha(31_000 + index),
            discovery_result_sha256=_sha(32_000 + index),
            runtime_evidence_sha256=_sha(33_000 + index),
        )
        for index, task in enumerate(plan.tasks)
    )


class E4ReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = _contract_fixture()
        self.plan = fixture.plan
        self.execution_receipt = fixture.receipt
        self.closures = _success_closures(self.execution_receipt)

    def _claim(self) -> E4BatchSuccessReceiptV1:
        authority = e4_receipt_module._issue_e4_success_receipt_authority_v1(
            self.plan,
            self.closures,
        )
        return claim_e4_success_receipt_authority_v1(
            authority,
            self.execution_receipt,
        )

    def test_authority_claim_builds_fixed_receipt_and_roundtrips(self) -> None:
        authority = e4_receipt_module._issue_e4_success_receipt_authority_v1(
            self.plan,
            self.closures,
        )
        self.assertIs(type(authority), E4SuccessReceiptAuthorityV1)
        receipt = claim_e4_success_receipt_authority_v1(
            authority,
            self.execution_receipt,
        )

        self.assertEqual(receipt.kind, E4_BATCH_SUCCESS_RECEIPT_KIND)
        self.assertEqual(receipt.scheduler_version, E4_SCHEDULER_VERSION)
        self.assertEqual(receipt.max_parallelism, 1)
        self.assertEqual(receipt.max_attempts, 1)
        self.assertEqual(
            receipt.runtime_reverify_policy,
            E4_RUNTIME_REVERIFY_POLICY,
        )
        self.assertIs(receipt.snapshot_reverified, True)
        self.assertEqual(receipt.status, "succeeded")
        self.assertEqual(receipt.execution_receipt, self.execution_receipt)
        self.assertEqual(receipt.success_closures, self.closures)
        self.assertEqual(
            tuple(item.task_id for item in receipt.success_closures),
            tuple(item.task_id for item in self.plan.tasks),
        )
        self.assertEqual(E4_SUCCESS_RECEIPT_FILENAME, "e4-success-receipt.json")

        closure = receipt.success_closures[0]
        closure_payload = closure.to_bytes()
        self.assertEqual(
            E4TaskSuccessClosureV1.from_bytes(
                closure_payload,
                expected_closure_sha256=closure.closure_sha256,
                expected_wire_sha256=closure.wire_sha256,
            ),
            closure,
        )

        payload = receipt.to_bytes()
        self.assertEqual(
            receipt.execution_receipt_sha256,
            self.execution_receipt.receipt_sha256,
        )
        self.assertEqual(
            receipt.execution_receipt_wire_sha256,
            self.execution_receipt.wire_sha256,
        )
        self.assertEqual(receipt.wire_sha256, hashlib.sha256(payload).hexdigest())
        parsed = E4BatchSuccessReceiptV1.from_bytes(
            payload,
            expected_receipt_sha256=receipt.receipt_sha256,
            expected_wire_sha256=receipt.wire_sha256,
        )
        self.assertEqual(parsed, receipt)
        self.assertEqual(parsed.to_bytes(), payload)

    def test_authority_is_opaque_exact_type_nonserializable_and_one_shot(
        self,
    ) -> None:
        with self.assertRaises(TypeError):
            E4SuccessReceiptAuthorityV1(
                object(),
                plan=self.plan,
                success_closures=self.closures,
            )

        authority = e4_receipt_module._issue_e4_success_receipt_authority_v1(
            self.plan,
            self.closures,
        )
        with self.assertRaises(TypeError):
            pickle.dumps(authority)
        with self.assertRaises(E4ReceiptError) as captured:
            claim_e4_success_receipt_authority_v1(
                object(),
                self.execution_receipt,
            )
        self.assertEqual(captured.exception.code, "invalid_argument")

        claim_e4_success_receipt_authority_v1(
            authority,
            self.execution_receipt,
        )
        with self.assertRaises(E4ReceiptError) as captured:
            claim_e4_success_receipt_authority_v1(
                authority,
                self.execution_receipt,
            )
        self.assertEqual(captured.exception.code, "authority_reused")

    def test_authority_allows_only_one_concurrent_claim(self) -> None:
        authority = e4_receipt_module._issue_e4_success_receipt_authority_v1(
            self.plan,
            self.closures,
        )

        def claim() -> object:
            try:
                return claim_e4_success_receipt_authority_v1(
                    authority,
                    self.execution_receipt,
                )
            except E4ReceiptError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(lambda _: claim(), range(2)))
        self.assertEqual(
            sum(type(item) is E4BatchSuccessReceiptV1 for item in results),
            1,
        )
        self.assertEqual(results.count("authority_reused"), 1)

    def test_issuer_rejects_missing_reordered_and_failure_closures(self) -> None:
        for closures in (
            self.closures[:-1],
            (self.closures[1], self.closures[0], *self.closures[2:]),
        ):
            with self.subTest(count=len(closures)):
                with self.assertRaises(E4ReceiptError) as captured:
                    e4_receipt_module._issue_e4_success_receipt_authority_v1(
                        self.plan,
                        closures,
                    )
                self.assertEqual(captured.exception.code, "invalid_binding")

        invalid_values = (
            {"status": "failed"},
            {"cleanup_complete": False},
            {"runtime_reverified": False},
        )
        for changes in invalid_values:
            with self.subTest(changes=changes):
                with self.assertRaises(E4ReceiptError) as captured:
                    replace(self.closures[0], **changes)
                self.assertEqual(captured.exception.code, "invalid_contract")

    def test_exact_train_and_test_counts_are_required(self) -> None:
        test_authority = e4_receipt_module._issue_e4_success_receipt_authority_v1(
            self.plan,
            self.closures,
        )
        self.assertIs(type(test_authority), E4SuccessReceiptAuthorityV1)

        train_plan = _train_plan()
        train_closures = _plan_only_closures(train_plan)
        train_authority = e4_receipt_module._issue_e4_success_receipt_authority_v1(
            train_plan,
            train_closures,
        )
        self.assertIs(type(train_authority), E4SuccessReceiptAuthorityV1)
        for shortened in (self.closures[:-1], train_closures[:-1]):
            plan = self.plan if len(shortened) == 19 else train_plan
            with self.subTest(split=plan.batch.split):
                with self.assertRaises(E4ReceiptError) as captured:
                    e4_receipt_module._issue_e4_success_receipt_authority_v1(
                        plan,
                        shortened,
                    )
                self.assertEqual(captured.exception.code, "invalid_binding")

    def test_detached_closure_cannot_forge_success_and_consumes_claim(
        self,
    ) -> None:
        detached = (
            replace(self.closures[0], run_sha256="f" * 64),
            *self.closures[1:],
        )
        authority = e4_receipt_module._issue_e4_success_receipt_authority_v1(
            self.plan,
            detached,
        )
        with self.assertRaises(E4ReceiptError) as captured:
            claim_e4_success_receipt_authority_v1(
                authority,
                self.execution_receipt,
            )
        self.assertEqual(captured.exception.code, "detached_receipt")
        with self.assertRaises(E4ReceiptError) as captured:
            claim_e4_success_receipt_authority_v1(
                authority,
                self.execution_receipt,
            )
        self.assertEqual(captured.exception.code, "authority_reused")

    def test_receipt_rejects_fixed_field_and_result_hash_drift(self) -> None:
        receipt = self._claim()
        invalid_values = (
            {"scheduler_version": "discovery-e4-batch-runner-v2"},
            {"max_parallelism": 2},
            {"max_attempts": 2},
            {"runtime_reverify_policy": "only_at_end"},
            {"snapshot_reverified": False},
            {"status": "failed"},
        )
        for changes in invalid_values:
            with self.subTest(changes=changes):
                with self.assertRaises(E4ReceiptError) as captured:
                    replace(receipt, **changes)
                self.assertEqual(captured.exception.code, "invalid_contract")

        for field_name, digest in (
            ("run_sha256", "b" * 64),
            ("run_wire_sha256", "c" * 64),
            ("discovery_result_sha256", "d" * 64),
            ("runtime_evidence_sha256", "e" * 64),
        ):
            with self.subTest(field_name=field_name):
                detached = (
                    replace(self.closures[0], **{field_name: digest}),
                    *self.closures[1:],
                )
                with self.assertRaises(E4ReceiptError) as captured:
                    E4BatchSuccessReceiptV1(
                        execution_receipt=self.execution_receipt,
                        success_closures=detached,
                    )
                self.assertEqual(captured.exception.code, "invalid_binding")

    def test_strict_parsers_reject_extra_reordered_and_noncanonical_wire(
        self,
    ) -> None:
        receipt = self._claim()
        raw = receipt.to_dict()

        with_extra = dict(raw)
        with_extra["extra"] = True
        extra_payload = _wire(with_extra)
        with self.assertRaises(E4ReceiptError) as captured:
            E4BatchSuccessReceiptV1.from_bytes(
                extra_payload,
                expected_receipt_sha256=receipt.receipt_sha256,
                expected_wire_sha256=hashlib.sha256(extra_payload).hexdigest(),
            )
        self.assertEqual(captured.exception.code, "invalid_contract")

        reordered = dict(raw)
        reordered["success_closures"] = [
            raw["success_closures"][1],
            raw["success_closures"][0],
            *raw["success_closures"][2:],
        ]
        reordered_payload = _wire(reordered)
        with self.assertRaises(E4ReceiptError) as captured:
            E4BatchSuccessReceiptV1.from_bytes(
                reordered_payload,
                expected_receipt_sha256=receipt.receipt_sha256,
                expected_wire_sha256=hashlib.sha256(reordered_payload).hexdigest(),
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

        noncanonical_payload = (
            json.dumps(raw, ensure_ascii=False, indent=1).encode("utf-8") + b"\n"
        )
        with self.assertRaises(E4ReceiptError) as captured:
            E4BatchSuccessReceiptV1.from_bytes(
                noncanonical_payload,
                expected_receipt_sha256=receipt.receipt_sha256,
                expected_wire_sha256=hashlib.sha256(
                    noncanonical_payload
                ).hexdigest(),
            )
        self.assertEqual(captured.exception.code, "noncanonical_json")

        closure = self.closures[0]
        closure_raw = closure.to_dict()
        closure_raw["extra"] = True
        closure_payload = _wire(closure_raw)
        with self.assertRaises(E4ReceiptError) as captured:
            E4TaskSuccessClosureV1.from_bytes(
                closure_payload,
                expected_closure_sha256=closure.closure_sha256,
                expected_wire_sha256=hashlib.sha256(closure_payload).hexdigest(),
            )
        self.assertEqual(captured.exception.code, "invalid_contract")

    def test_semantic_and_wire_pins_are_independently_enforced(self) -> None:
        receipt = self._claim()
        payload = receipt.to_bytes()
        for semantic, wire, expected_code in (
            ("f" * 64, receipt.wire_sha256, "digest_mismatch"),
            (receipt.receipt_sha256, "f" * 64, "digest_mismatch"),
        ):
            with self.subTest(expected_code=expected_code, semantic=semantic):
                with self.assertRaises(E4ReceiptError) as captured:
                    E4BatchSuccessReceiptV1.from_bytes(
                        payload,
                        expected_receipt_sha256=semantic,
                        expected_wire_sha256=wire,
                    )
                self.assertEqual(captured.exception.code, expected_code)

    def test_parser_rejects_bad_types_limits_and_duplicates_fail_closed(
        self,
    ) -> None:
        receipt = self._claim()
        payload = receipt.to_bytes()
        with self.assertRaises(E4ReceiptError) as captured:
            E4BatchSuccessReceiptV1.from_bytes(
                "not-bytes",
                expected_receipt_sha256=receipt.receipt_sha256,
                expected_wire_sha256=receipt.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "invalid_argument")

        oversized = b"x" * (e4_receipt_module.E4_SUCCESS_RECEIPT_MAX_BYTES + 1)
        with self.assertRaises(E4ReceiptError) as captured:
            E4BatchSuccessReceiptV1.from_bytes(
                oversized,
                expected_receipt_sha256=receipt.receipt_sha256,
                expected_wire_sha256=hashlib.sha256(oversized).hexdigest(),
            )
        self.assertEqual(captured.exception.code, "limit_exceeded")

        with mock.patch.object(
            e4_receipt_module.json,
            "loads",
            side_effect=AssertionError("wire pin must precede parsing"),
        ) as parser:
            with self.assertRaises(E4ReceiptError) as captured:
                E4BatchSuccessReceiptV1.from_bytes(
                    payload,
                    expected_receipt_sha256=receipt.receipt_sha256,
                    expected_wire_sha256="f" * 64,
                )
        self.assertEqual(captured.exception.code, "digest_mismatch")
        parser.assert_not_called()

        duplicate = b'{"status":"succeeded",' + payload[1:]
        with self.assertRaises(E4ReceiptError) as captured:
            E4BatchSuccessReceiptV1.from_bytes(
                duplicate,
                expected_receipt_sha256=receipt.receipt_sha256,
                expected_wire_sha256=hashlib.sha256(duplicate).hexdigest(),
            )
        self.assertEqual(captured.exception.code, "invalid_contract")

    def test_direct_e3_and_e4_receipts_are_unambiguously_distinct(self) -> None:
        e3 = self.execution_receipt
        e4 = self._claim()
        self.assertIs(type(e3), DiscoveryBatchExecutionReceiptV1)
        self.assertIs(type(e4), E4BatchSuccessReceiptV1)
        self.assertNotEqual(e3.kind, e4.kind)
        self.assertEqual(self.closures[0].kind, E4_TASK_SUCCESS_CLOSURE_KIND)

        with self.assertRaises(E4ReceiptError) as captured:
            E4BatchSuccessReceiptV1.from_bytes(
                e3.to_bytes(),
                expected_receipt_sha256=e3.receipt_sha256,
                expected_wire_sha256=e3.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "invalid_contract")
        with self.assertRaises(EvaluatorContractError) as captured:
            DiscoveryBatchExecutionReceiptV1.from_bytes(
                e4.to_bytes(),
                expected_receipt_sha256=e4.receipt_sha256,
                expected_wire_sha256=e4.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "invalid_contract")
if __name__ == "__main__":
    unittest.main()
