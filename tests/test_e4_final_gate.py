from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import unittest
from unittest import mock

from vulngym_agent.benchmark.harness import (
    MAX_DISCOVERY_TOP_K,
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    PROFILE_SCHEMA_VERSION,
    PROFILE_TEST_TASKS,
    PROFILE_TRAIN_TASKS,
)
import vulngym_agent.evaluator.final_gate as final_gate
from vulngym_agent.evaluator.final_gate import (
    FINAL_GATE_STAGE_ORDER,
    FINAL_GATE_STATUS,
    FinalGateContractError,
    FinalGatePlanV1,
    FinalGateReceiptV1,
    FinalGateSplitPlanV1,
    FinalGateSplitReceiptClosureV1,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _wire_sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class FinalGateContractTests(unittest.TestCase):
    def _split_plan(self, split: str) -> FinalGateSplitPlanV1:
        count = PROFILE_TEST_TASKS if split == "test" else PROFILE_TRAIN_TASKS
        return FinalGateSplitPlanV1(
            split=split,
            task_count=count,
            sealed_batch_manifest_sha256=_sha(f"{split}:sealed"),
            replay_manifest_sha256=_sha(f"{split}:replay:semantic"),
            replay_manifest_wire_sha256=_sha(f"{split}:replay:wire"),
            snapshot_key_id=f"snapshot-key-{split}",
        )

    def _plan(self) -> FinalGatePlanV1:
        return FinalGatePlanV1(
            execution_policy_sha256=_sha("policy:semantic"),
            execution_policy_wire_sha256=_sha("policy:wire"),
            test=self._split_plan("test"),
            train=self._split_plan("train"),
        )

    def _closure(
        self,
        split: str,
        plan: FinalGatePlanV1,
        **overrides: object,
    ) -> FinalGateSplitReceiptClosureV1:
        split_plan = plan.test if split == "test" else plan.train
        count = split_plan.task_count
        arguments: dict[str, object] = {
            "split": split,
            "split_plan_sha256": split_plan.split_plan_sha256,
            "split_plan_wire_sha256": split_plan.wire_sha256,
            "e4_receipt_sha256": _sha(f"{split}:e4:semantic"),
            "e4_receipt_wire_sha256": _sha(f"{split}:e4:wire"),
            "execution_policy_sha256": plan.execution_policy_sha256,
            "execution_policy_wire_sha256": plan.execution_policy_wire_sha256,
            "execution_plan_sha256": _sha(f"{split}:execution-plan:semantic"),
            "execution_plan_wire_sha256": _sha(f"{split}:execution-plan:wire"),
            "artifact_index_sha256": _sha(f"{split}:artifact-index"),
            "projection_manifest_sha256": _sha(f"{split}:projection-manifest"),
            "task_count": count,
            "finalized_task_count": count - 1,
            "deferred_task_count": 1,
            "candidate_count": count * 3,
            "finding_count": count * 2,
            "aggregate_file_sha256": (
                None if split == "test" else _sha("train:aggregate-file")
            ),
        }
        arguments.update(overrides)
        return FinalGateSplitReceiptClosureV1(**arguments)

    def _receipt(self) -> FinalGateReceiptV1:
        plan = self._plan()
        return FinalGateReceiptV1(
            plan=plan,
            test=self._closure("test", plan),
            train=self._closure("train", plan),
        )

    def test_plan_round_trip_binds_fixed_profile_policy_inputs_and_order(self) -> None:
        plan = self._plan()
        wire = plan.to_bytes()
        parsed = FinalGatePlanV1.from_bytes(
            wire,
            expected_plan_sha256=plan.plan_sha256,
            expected_wire_sha256=_wire_sha(wire),
        )

        self.assertEqual(parsed, plan)
        self.assertEqual(parsed.profile_id, PROFILE_ID)
        self.assertEqual(parsed.profile_schema_version, PROFILE_SCHEMA_VERSION)
        self.assertEqual(parsed.public_manifest_sha256, PROFILE_MANIFEST_SHA256)
        self.assertEqual(parsed.stage_order, FINAL_GATE_STAGE_ORDER)
        self.assertEqual(
            parsed.stage_order,
            (
                "test_execution",
                "test_projection",
                "train_execution",
                "train_projection",
            ),
        )
        self.assertEqual(parsed.top_k, MAX_DISCOVERY_TOP_K)
        self.assertEqual(parsed.test.task_count, 20)
        self.assertEqual(parsed.train.task_count, 50)
        self.assertTrue(wire.endswith(b"\n"))
        self.assertEqual(wire.count(b"\n"), 1)

    def test_receipt_round_trip_closes_two_exact_split_unions(self) -> None:
        receipt = self._receipt()
        wire = receipt.to_bytes()
        parsed = FinalGateReceiptV1.from_bytes(
            wire,
            expected_receipt_sha256=receipt.receipt_sha256,
            expected_wire_sha256=_wire_sha(wire),
        )

        self.assertEqual(parsed, receipt)
        self.assertEqual(parsed.status, FINAL_GATE_STATUS)
        self.assertEqual(parsed.plan_sha256, parsed.plan.plan_sha256)
        self.assertEqual(parsed.plan_wire_sha256, parsed.plan.wire_sha256)
        self.assertIsNone(parsed.test.aggregate_file_sha256)
        self.assertRegex(parsed.train.aggregate_file_sha256 or "", r"^[0-9a-f]{64}$")
        self.assertEqual(parsed.test.finalized_task_count + parsed.test.deferred_task_count, 20)
        self.assertEqual(parsed.train.finalized_task_count + parsed.train.deferred_task_count, 50)

    def test_wire_contains_no_paths_secrets_gold_or_quality_claim(self) -> None:
        payload = self._receipt().to_bytes().decode("utf-8")
        lowered = payload.casefold()
        for forbidden in (
            "absolute_path",
            "benchmark_root",
            "output_dir",
            "secret",
            "gold",
            "accepted",
            "quality",
            "score",
        ):
            self.assertNotIn(forbidden, lowered)
        self.assertIn('"status":"closed"', payload)
        self.assertNotIn('"status":"passed"', payload)

    def test_fixed_plan_header_cannot_be_relaxed(self) -> None:
        base = {
            "execution_policy_sha256": _sha("policy"),
            "execution_policy_wire_sha256": _sha("policy-wire"),
            "test": self._split_plan("test"),
            "train": self._split_plan("train"),
        }
        invalid = (
            {"profile_id": "other-profile"},
            {"profile_schema_version": "9.9.9"},
            {"public_manifest_sha256": _sha("other-public")},
            {"stage_order": tuple(reversed(FINAL_GATE_STAGE_ORDER))},
            {"stage_order": list(FINAL_GATE_STAGE_ORDER)},
            {"top_k": 63},
            {"top_k": True},
            {"contract_version": True},
        )
        for overrides in invalid:
            with self.subTest(overrides=overrides):
                with self.assertRaises(FinalGateContractError):
                    FinalGatePlanV1(**base, **overrides)

    def test_split_plan_requires_exact_count_split_and_safe_key_id(self) -> None:
        cases = (
            {"split": "test", "task_count": 50, "snapshot_key_id": "key"},
            {"split": "train", "task_count": 20, "snapshot_key_id": "key"},
            {"split": "test", "task_count": True, "snapshot_key_id": "key"},
            {"split": "invalid", "task_count": 20, "snapshot_key_id": "key"},
            {"split": [], "task_count": 20, "snapshot_key_id": "key"},
            {"split": "test", "task_count": 20, "snapshot_key_id": "bad/key"},
            {"split": "test", "task_count": 20, "snapshot_key_id": "bad\\key"},
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(FinalGateContractError):
                    FinalGateSplitPlanV1(
                        sealed_batch_manifest_sha256=_sha("sealed"),
                        replay_manifest_sha256=_sha("replay"),
                        replay_manifest_wire_sha256=_sha("replay-wire"),
                        **case,
                    )

    def test_test_and_train_plan_inputs_cannot_reuse_an_identity(self) -> None:
        test = self._split_plan("test")
        for field_name in (
            "sealed_batch_manifest_sha256",
            "replay_manifest_sha256",
            "replay_manifest_wire_sha256",
        ):
            train = replace(
                self._split_plan("train"),
                **{field_name: getattr(test, field_name)},
            )
            with self.subTest(field=field_name):
                with self.assertRaises(FinalGateContractError) as captured:
                    FinalGatePlanV1(
                        execution_policy_sha256=_sha("policy"),
                        execution_policy_wire_sha256=_sha("policy-wire"),
                        test=test,
                        train=train,
                    )
                self.assertEqual(captured.exception.code, "invalid_binding")

    def test_split_closure_enforces_counts_closed_status_and_train_only_aggregate(self) -> None:
        plan = self._plan()
        cases = (
            ("test", {"aggregate_file_sha256": _sha("not-allowed")}),
            ("train", {"aggregate_file_sha256": None}),
            ("test", {"task_count": True}),
            ("test", {"finalized_task_count": 20, "deferred_task_count": 1}),
            ("test", {"candidate_count": 1, "finding_count": 2}),
            ("test", {"status": "passed"}),
            ("test", {"top_k": 63}),
            ([], {}),
        )
        for split, overrides in cases:
            with self.subTest(split=split, overrides=overrides):
                with self.assertRaises(FinalGateContractError):
                    self._closure(split, plan, **overrides)

    def test_top_receipt_rejects_detached_or_reused_split_outputs(self) -> None:
        plan = self._plan()
        test = self._closure("test", plan)
        train = self._closure("train", plan)

        detached = replace(test, split_plan_sha256=_sha("detached"))
        with self.assertRaises(FinalGateContractError) as captured:
            FinalGateReceiptV1(plan=plan, test=detached, train=train)
        self.assertEqual(captured.exception.code, "invalid_binding")

        reused = replace(train, e4_receipt_sha256=test.e4_receipt_sha256)
        with self.assertRaises(FinalGateContractError) as captured:
            FinalGateReceiptV1(plan=plan, test=test, train=reused)
        self.assertEqual(captured.exception.code, "invalid_binding")

        wrong_policy = replace(
            test, execution_policy_sha256=_sha("detached-policy")
        )
        with self.assertRaises(FinalGateContractError) as captured:
            FinalGateReceiptV1(plan=plan, test=wrong_policy, train=train)
        self.assertEqual(captured.exception.code, "invalid_binding")

    def test_parsers_reject_extra_keys_duplicate_keys_and_noncanonical_wire(self) -> None:
        plan = self._plan()
        raw = plan.to_dict()
        raw["unexpected"] = 1
        extra = json.dumps(
            raw, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        with self.assertRaises(FinalGateContractError) as captured:
            FinalGatePlanV1.from_bytes(
                extra,
                expected_plan_sha256=plan.plan_sha256,
                expected_wire_sha256=_wire_sha(extra),
            )
        self.assertEqual(captured.exception.code, "invalid_contract")

        duplicate = b'{"kind":"one","kind":"two"}\n'
        with self.assertRaises(FinalGateContractError) as captured:
            FinalGatePlanV1.from_bytes(
                duplicate,
                expected_plan_sha256=_sha("semantic"),
                expected_wire_sha256=_wire_sha(duplicate),
            )
        self.assertEqual(captured.exception.code, "noncanonical_json")

        pretty = json.dumps(plan.to_dict(), indent=2).encode("utf-8") + b"\n"
        with self.assertRaises(FinalGateContractError) as captured:
            FinalGatePlanV1.from_bytes(
                pretty,
                expected_plan_sha256=plan.plan_sha256,
                expected_wire_sha256=_wire_sha(pretty),
            )
        self.assertEqual(captured.exception.code, "noncanonical_json")

    def test_parser_rejects_float_bool_and_invalid_exact_types(self) -> None:
        plan = self._plan()
        raw = plan.to_dict()
        raw["top_k"] = 64.0
        payload = json.dumps(
            raw, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        with self.assertRaises(FinalGateContractError) as captured:
            FinalGatePlanV1.from_bytes(
                payload,
                expected_plan_sha256=plan.plan_sha256,
                expected_wire_sha256=_wire_sha(payload),
            )
        self.assertEqual(captured.exception.code, "invalid_contract")

        with self.assertRaises(FinalGateContractError):
            FinalGatePlanV1.from_bytes(
                bytearray(plan.to_bytes()),
                expected_plan_sha256=plan.plan_sha256,
                expected_wire_sha256=plan.wire_sha256,
            )

    def test_parser_enforces_wire_shape_and_byte_limits(self) -> None:
        plan = self._plan()
        wire = plan.to_bytes()
        with mock.patch.object(final_gate, "FINAL_GATE_MAX_WIRE_BYTES", len(wire) - 1):
            with self.assertRaises(FinalGateContractError) as captured:
                FinalGatePlanV1.from_bytes(
                    wire,
                    expected_plan_sha256=plan.plan_sha256,
                    expected_wire_sha256=_wire_sha(wire),
                )
            self.assertEqual(captured.exception.code, "limit_exceeded")

        with mock.patch.object(final_gate, "FINAL_GATE_MAX_JSON_NODES", 1):
            with self.assertRaises(FinalGateContractError) as captured:
                FinalGatePlanV1.from_bytes(
                    wire,
                    expected_plan_sha256=plan.plan_sha256,
                    expected_wire_sha256=_wire_sha(wire),
                )
            self.assertEqual(captured.exception.code, "limit_exceeded")

        with mock.patch.object(final_gate, "FINAL_GATE_MAX_JSON_DEPTH", 0):
            with self.assertRaises(FinalGateContractError) as captured:
                FinalGatePlanV1.from_bytes(
                    wire,
                    expected_plan_sha256=plan.plan_sha256,
                    expected_wire_sha256=_wire_sha(wire),
                )
            self.assertEqual(captured.exception.code, "limit_exceeded")

    def test_semantic_and_wire_pins_are_both_required(self) -> None:
        receipt = self._receipt()
        wire = receipt.to_bytes()
        with self.assertRaises(FinalGateContractError) as captured:
            FinalGateReceiptV1.from_bytes(
                wire,
                expected_receipt_sha256=_sha("wrong-semantic"),
                expected_wire_sha256=_wire_sha(wire),
            )
        self.assertEqual(captured.exception.code, "digest_mismatch")

        with self.assertRaises(FinalGateContractError) as captured:
            FinalGateReceiptV1.from_bytes(
                wire,
                expected_receipt_sha256=receipt.receipt_sha256,
                expected_wire_sha256=_sha("wrong-wire"),
            )
        self.assertEqual(captured.exception.code, "digest_mismatch")

        with self.assertRaises(FinalGateContractError) as captured:
            FinalGateReceiptV1.from_bytes(
                wire,
                expected_receipt_sha256="not-a-digest",
                expected_wire_sha256=_wire_sha(wire),
            )
        self.assertEqual(captured.exception.code, "invalid_argument")

    def test_contract_digests_are_deterministic_and_mutation_is_detected(self) -> None:
        first = self._receipt()
        second = self._receipt()
        self.assertEqual(first.to_bytes(), second.to_bytes())
        self.assertEqual(first.receipt_sha256, second.receipt_sha256)
        self.assertEqual(first.wire_sha256, second.wire_sha256)

        object.__setattr__(first, "receipt_sha256", _sha("mutated"))
        with self.assertRaises(FinalGateContractError) as captured:
            first.to_dict()
        self.assertEqual(captured.exception.code, "invalid_binding")


if __name__ == "__main__":
    unittest.main()
