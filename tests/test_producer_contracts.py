from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
import hashlib
import json
import unittest

import vulngym_agent.benchmark as benchmark_api
from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import (
    DEFAULT_DISCOVERY_LIMITS,
    DiscoveryCandidate,
    DiscoveryLocation,
    DiscoveryTaskInputV1,
)
from vulngym_agent.benchmark.producer_contracts import (
    DEFAULT_PRODUCER_LIMITS,
    PRODUCER_ERROR_TAXONOMY_VERSION,
    PRODUCER_POLICY_VERSION,
    PRODUCER_SELECTION_DIGEST_DOMAIN,
    ProducerArtifactDigestRefV1,
    ProducerContractError,
    ProducerContractLimits,
    ProducerDeferredV1,
    ProducerDraftV1,
    ProducerValidationReceiptV1,
    ValidationReceiptV1,
    parse_producer_result_v1,
)


TASK_ID = "VG-TEST-0123456789ABCDEF0123"
REPO_URL = "https://github.com/example/producer-contract"
COMMIT = "1" * 40
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def _task(*, content_root: str = DIGEST_B) -> DiscoveryTaskInputV1:
    return DiscoveryTaskInputV1(
        task_id=TASK_ID,
        repo_url=REPO_URL,
        commit=COMMIT,
        instruction_id=INSTRUCTION_ID,
        snapshot_manifest_sha256=DIGEST_A,
        snapshot_content_root=content_root,
    )


def _artifact(kind: str, index: int) -> str:
    return f"ART-{kind}-{index:024x}"


def _candidate(
    task: DiscoveryTaskInputV1,
    index: int = 1,
    *,
    trace: tuple[DiscoveryLocation, ...] = (),
    source_refs: tuple[str, ...] | None = None,
    relationship_refs: tuple[str, ...] | None = None,
) -> DiscoveryCandidate:
    source = (
        (_artifact("source", index),) if source_refs is None else source_refs
    )
    relationships = (
        (_artifact("link", index),)
        if relationship_refs is None
        else relationship_refs
    )
    return DiscoveryCandidate(
        task_id=task.task_id,
        snapshot_id=task.snapshot_id,
        repo_url=task.repo_url,
        commit=task.commit,
        entry_point=DiscoveryLocation(
            file="src/entry.py",
            line_start=index,
            line_end=index,
            code_sha256=DIGEST_C,
        ),
        critical_operation=DiscoveryLocation(
            file="src/sink.py",
            line_start=100 + index,
            line_end=100 + index,
            code_sha256=DIGEST_C,
        ),
        trace=trace,
        relationship_evidence_refs=relationships,
        source_evidence_refs=source,
    )


def _receipt(candidate: DiscoveryCandidate, index: int = 1) -> ValidationReceiptV1:
    evidence = tuple(
        sorted(
            set(candidate.source_evidence_refs)
            | set(candidate.relationship_evidence_refs)
        )
    )
    return ValidationReceiptV1(
        candidate_id=candidate.candidate_id,
        candidate_sha256=candidate.candidate_sha256,
        validation_artifact_id=_artifact("validation", index),
        validation_artifact_sha256=hashlib.sha256(
            f"validation:{index}".encode("ascii")
        ).hexdigest(),
        selection_digest=hashlib.sha256(
            f"selection:{index}".encode("ascii")
        ).hexdigest(),
        dependencies=tuple(
            ProducerArtifactDigestRefV1(
                artifact_id=artifact_id,
                artifact_sha256=hashlib.sha256(
                    f"dependency:{artifact_id}".encode("ascii")
                ).hexdigest(),
            )
            for artifact_id in evidence
        ),
    )


def _draft(count: int = 1) -> ProducerDraftV1:
    task = _task()
    candidates = tuple(
        _candidate(
            task,
            index + 1,
            source_refs=(_artifact("source-shared", 0),),
            relationship_refs=(_artifact("link-shared", 0),),
        )
        for index in range(count)
    )
    receipts = tuple(
        _receipt(candidate, index + 1)
        for index, candidate in enumerate(candidates)
    )
    return ProducerDraftV1(
        task=task,
        candidates=candidates,
        validation_receipts=receipts,
    )


class ProducerContractTests(unittest.TestCase):
    def test_public_benchmark_package_exports_d2_contracts(self) -> None:
        self.assertIs(benchmark_api.ProducerDraftV1, ProducerDraftV1)
        self.assertIs(benchmark_api.ProducerDeferredV1, ProducerDeferredV1)
        self.assertIs(benchmark_api.ValidationReceiptV1, ValidationReceiptV1)
        self.assertIs(
            benchmark_api.parse_producer_result_v1,
            parse_producer_result_v1,
        )

    def test_draft_round_trip_is_canonical_and_union_parser_is_deterministic(self) -> None:
        draft = _draft(2)
        wire = draft.to_wire()
        self.assertEqual(
            wire,
            json.dumps(
                draft.to_dict(),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        self.assertEqual(draft, ProducerDraftV1.from_wire(wire))
        self.assertEqual(draft, ProducerDraftV1.from_dict(draft.to_dict()))
        self.assertEqual(draft, parse_producer_result_v1(wire))
        self.assertEqual(draft, parse_producer_result_v1(draft.to_dict()))
        self.assertIs(draft, parse_producer_result_v1(draft))

    def test_draft_exposes_exact_authenticated_task_binding(self) -> None:
        draft = _draft()
        self.assertEqual(draft.task.task_id, draft.task_id)
        self.assertEqual(draft.task.snapshot_id, draft.snapshot_id)
        self.assertEqual(
            draft.task.snapshot_manifest_sha256, draft.manifest_sha256
        )
        self.assertEqual(draft.task.snapshot_content_root, draft.content_root)

        other_task = _task(content_root="d" * 64)
        candidate = draft.candidates[0]
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=other_task,
                candidates=(candidate,),
                validation_receipts=draft.validation_receipts,
            )
        self.assertEqual("invalid_binding", captured.exception.code)

    def test_validation_receipt_exactly_closes_candidate_and_evidence_digests(self) -> None:
        draft = _draft()
        candidate = draft.candidates[0]
        receipt = draft.validation_receipts[0]
        receipt.assert_candidate(candidate)
        self.assertEqual(
            set(candidate.source_evidence_refs)
            | set(candidate.relationship_evidence_refs),
            {item.artifact_id for item in receipt.dependencies},
        )
        self.assertIs(ValidationReceiptV1, ProducerValidationReceiptV1)
        self.assertEqual(receipt, ValidationReceiptV1.from_dict(receipt.to_dict()))

    def test_missing_extra_or_tampered_receipts_fail_closed(self) -> None:
        draft = _draft(2)
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=draft.task,
                candidates=draft.candidates,
                validation_receipts=draft.validation_receipts[:1],
            )
        self.assertEqual("receipt_coverage_mismatch", captured.exception.code)

        first = draft.validation_receipts[0]
        tampered = ValidationReceiptV1(
            candidate_id=first.candidate_id,
            candidate_sha256="f" * 64,
            validation_artifact_id=first.validation_artifact_id,
            validation_artifact_sha256=first.validation_artifact_sha256,
            selection_digest=first.selection_digest,
            dependencies=first.dependencies,
        )
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=draft.task,
                candidates=draft.candidates,
                validation_receipts=(tampered, draft.validation_receipts[1]),
            )
        self.assertEqual("invalid_binding", captured.exception.code)

        extra_dependency = ProducerArtifactDigestRefV1(
            _artifact("extra", 1), "e" * 64
        )
        invalid_closure = ValidationReceiptV1(
            candidate_id=first.candidate_id,
            candidate_sha256=first.candidate_sha256,
            validation_artifact_id=first.validation_artifact_id,
            validation_artifact_sha256=first.validation_artifact_sha256,
            selection_digest=first.selection_digest,
            dependencies=(*first.dependencies, extra_dependency),
        )
        with self.assertRaises(ProducerContractError) as captured:
            invalid_closure.assert_candidate(draft.candidates[0])
        self.assertEqual("receipt_coverage_mismatch", captured.exception.code)

    def test_receipts_reject_duplicate_dependencies_and_validation_artifact_reuse(self) -> None:
        draft = _draft(2)
        first = draft.validation_receipts[0]
        with self.assertRaises(ProducerContractError):
            ValidationReceiptV1(
                candidate_id=first.candidate_id,
                candidate_sha256=first.candidate_sha256,
                validation_artifact_id=first.validation_artifact_id,
                validation_artifact_sha256=first.validation_artifact_sha256,
                selection_digest=first.selection_digest,
                dependencies=(first.dependencies[0], first.dependencies[0]),
            )

        second = draft.validation_receipts[1]
        reused = ValidationReceiptV1(
            candidate_id=second.candidate_id,
            candidate_sha256=second.candidate_sha256,
            validation_artifact_id=first.validation_artifact_id,
            validation_artifact_sha256=second.validation_artifact_sha256,
            selection_digest=second.selection_digest,
            dependencies=second.dependencies,
        )
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=draft.task,
                candidates=draft.candidates,
                validation_receipts=(first, reused),
            )
        self.assertEqual("receipt_coverage_mismatch", captured.exception.code)

    def test_validation_artifacts_cannot_enter_any_candidate_closure(self) -> None:
        task = _task()
        first_candidate = _candidate(task, 1)
        second_candidate = _candidate(task, 2)
        first = _receipt(first_candidate, 1)
        second = _receipt(second_candidate, 2)
        cross_cycle = ValidationReceiptV1(
            candidate_id=first.candidate_id,
            candidate_sha256=first.candidate_sha256,
            validation_artifact_id=second_candidate.source_evidence_refs[0],
            validation_artifact_sha256=first.validation_artifact_sha256,
            selection_digest=first.selection_digest,
            dependencies=first.dependencies,
        )
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=task,
                candidates=(first_candidate, second_candidate),
                validation_receipts=(cross_cycle, second),
            )
        self.assertEqual("receipt_coverage_mismatch", captured.exception.code)

    def test_shared_dependency_ids_require_one_digest_across_all_receipts(self) -> None:
        task = _task()
        shared = _artifact("source", 99)
        first_candidate = _candidate(task, 1, source_refs=(shared,))
        second_candidate = _candidate(task, 2, source_refs=(shared,))
        first = _receipt(first_candidate, 1)
        second_base = _receipt(second_candidate, 2)
        second_dependencies = tuple(
            ProducerArtifactDigestRefV1(
                dependency.artifact_id,
                "f" * 64 if dependency.artifact_id == shared else dependency.artifact_sha256,
            )
            for dependency in second_base.dependencies
        )
        second = ValidationReceiptV1(
            candidate_id=second_base.candidate_id,
            candidate_sha256=second_base.candidate_sha256,
            validation_artifact_id=second_base.validation_artifact_id,
            validation_artifact_sha256=second_base.validation_artifact_sha256,
            selection_digest=second_base.selection_digest,
            dependencies=second_dependencies,
        )
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=task,
                candidates=(first_candidate, second_candidate),
                validation_receipts=(first, second),
            )
        self.assertEqual("invalid_binding", captured.exception.code)

    def test_selection_digest_domain_is_per_candidate_and_versioned(self) -> None:
        self.assertEqual(
            b"VulnGym D2 per-candidate selection v1\0",
            PRODUCER_SELECTION_DIGEST_DOMAIN,
        )

        draft = _draft(2)
        first, second = draft.validation_receipts
        repeated_selection = ValidationReceiptV1(
            candidate_id=second.candidate_id,
            candidate_sha256=second.candidate_sha256,
            validation_artifact_id=second.validation_artifact_id,
            validation_artifact_sha256=second.validation_artifact_sha256,
            selection_digest=first.selection_digest,
            dependencies=second.dependencies,
        )
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=draft.task,
                candidates=draft.candidates,
                validation_receipts=(first, repeated_selection),
            )
        self.assertEqual("receipt_coverage_mismatch", captured.exception.code)

    def test_candidates_require_disjoint_runtime_artifact_evidence(self) -> None:
        task = _task()
        shared = _artifact("shared", 1)
        candidate = _candidate(
            task,
            source_refs=(shared,),
            relationship_refs=(shared,),
        )
        receipt = _receipt(candidate)
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=task,
                candidates=(candidate,),
                validation_receipts=(receipt,),
            )
        self.assertEqual("invalid_binding", captured.exception.code)

        candidate = _candidate(task, source_refs=("SRC-not-runtime-issued",))
        receipt = ValidationReceiptV1(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            validation_artifact_id=_artifact("validation", 2),
            validation_artifact_sha256="d" * 64,
            selection_digest="e" * 64,
            dependencies=(
                ProducerArtifactDigestRefV1(_artifact("source", 2), "f" * 64),
            ),
        )
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=task,
                candidates=(candidate,),
                validation_receipts=(receipt,),
            )
        self.assertEqual("invalid_binding", captured.exception.code)

    def test_artifact_evidence_roles_are_consistent_across_candidates(self) -> None:
        task = _task()
        shared = _artifact("shared", 7)
        first = _candidate(task, 1, source_refs=(shared,))
        second = _candidate(task, 2, relationship_refs=(shared,))
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=task,
                candidates=(first, second),
                validation_receipts=(_receipt(first, 1), _receipt(second, 2)),
            )
        self.assertEqual("invalid_binding", captured.exception.code)

    def test_candidate_evidence_references_require_canonical_order(self) -> None:
        task = _task()
        source_refs = (_artifact("source", 2), _artifact("source", 1))
        relationship_refs = (_artifact("link", 2), _artifact("link", 1))
        for field in ("source", "relationship"):
            with self.subTest(field=field):
                candidate = _candidate(
                    task,
                    source_refs=(
                        source_refs if field == "source" else (_artifact("source", 1),)
                    ),
                    relationship_refs=(
                        relationship_refs
                        if field == "relationship"
                        else (_artifact("link", 1),)
                    ),
                )
                with self.assertRaises(ProducerContractError) as captured:
                    ProducerDraftV1(
                        task=task,
                        candidates=(candidate,),
                        validation_receipts=(_receipt(candidate),),
                    )
                self.assertEqual("invalid_binding", captured.exception.code)

    def test_zero_and_32_candidates_are_allowed_but_33_is_rejected(self) -> None:
        empty = _draft(0)
        self.assertEqual((), empty.candidates)
        self.assertEqual((), empty.validation_receipts)
        maximum = _draft(32)
        self.assertEqual(32, len(maximum.candidates))
        self.assertEqual(32, DEFAULT_PRODUCER_LIMITS.max_candidates)
        self.assertEqual(64, DEFAULT_DISCOVERY_LIMITS.max_candidates_per_task)
        with self.assertRaises(ProducerContractError) as captured:
            _draft(33)
        self.assertEqual("limit_exceeded", captured.exception.code)

    def test_draft_references_at_most_64_attempt_artifacts(self) -> None:
        task = _task()
        allowed_refs = tuple(_artifact("source", index) for index in range(62))
        allowed_candidate = _candidate(
            task,
            source_refs=allowed_refs,
            relationship_refs=(_artifact("link", 0),),
        )
        allowed = ProducerDraftV1(
            task=task,
            candidates=(allowed_candidate,),
            validation_receipts=(_receipt(allowed_candidate),),
        )
        self.assertEqual(64, DEFAULT_PRODUCER_LIMITS.max_artifacts_per_draft)
        self.assertEqual(63, len(allowed.validation_receipts[0].dependencies))

        excessive_refs = tuple(_artifact("source", index) for index in range(63))
        excessive_candidate = _candidate(
            task,
            source_refs=excessive_refs,
            relationship_refs=(_artifact("link", 0),),
        )
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=task,
                candidates=(excessive_candidate,),
                validation_receipts=(_receipt(excessive_candidate),),
            )
        self.assertEqual("limit_exceeded", captured.exception.code)

    def test_duplicate_endpoints_are_rejected_even_if_trace_differs(self) -> None:
        task = _task()
        baseline = _candidate(task)
        traced = _candidate(
            task,
            trace=(
                DiscoveryLocation("src/trace.py", 5, 5, DIGEST_C),
            ),
        )
        self.assertEqual(baseline.candidate_id, traced.candidate_id)
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=task,
                candidates=(baseline, traced),
                validation_receipts=(_receipt(baseline, 1), _receipt(traced, 2)),
            )
        self.assertEqual("duplicate_candidate", captured.exception.code)

    def test_candidate_and_receipt_order_is_canonical(self) -> None:
        draft = _draft(3)
        reverse = ProducerDraftV1(
            task=draft.task,
            candidates=tuple(reversed(draft.candidates)),
            validation_receipts=tuple(reversed(draft.validation_receipts)),
        )
        self.assertEqual(draft, reverse)
        self.assertEqual(draft.to_wire(), reverse.to_wire())

    def test_deferred_round_trip_is_fail_closed_for_all_fixed_stages(self) -> None:
        for stage in ("SCOUT", "ANALYZE", "VALIDATE", "FINALIZE"):
            with self.subTest(stage=stage):
                deferred = ProducerDeferredV1(
                    task=_task(),
                    stage=stage,
                    reason_code="evidence.insufficient",
                    missing_information=("one more source relationship is required",),
                )
                self.assertEqual(deferred, ProducerDeferredV1.from_wire(deferred.to_wire()))
                self.assertEqual(deferred, parse_producer_result_v1(deferred.to_dict()))
                self.assertEqual("unknown", deferred.coverage_status)
                self.assertEqual(_task().snapshot_id, deferred.snapshot_id)

        value = ProducerDeferredV1(
            task=_task(),
            stage="SCOUT",
            reason_code="evidence.insufficient",
            missing_information=("missing",),
        ).to_dict()
        value["candidates"] = []
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDeferredV1.from_dict(value)
        self.assertEqual("invalid_keys", captured.exception.code)

    def test_deferred_rejects_invalid_state_and_missing_information(self) -> None:
        for stage in ("scout", "REVIEW", [], None):
            with self.subTest(stage=stage), self.assertRaises(ProducerContractError):
                ProducerDeferredV1(
                    task=_task(),
                    stage=stage,  # type: ignore[arg-type]
                    reason_code="blocked",
                    missing_information=("missing",),
                )
        for missing in ((), None, "missing", ("duplicate", "duplicate")):
            with self.subTest(missing=missing), self.assertRaises(
                ProducerContractError
            ):
                ProducerDeferredV1(
                    task=_task(),
                    stage="SCOUT",
                    reason_code="blocked",
                    missing_information=missing,  # type: ignore[arg-type]
                )

    def test_coverage_policy_and_fixed_limits_cannot_be_expanded(self) -> None:
        with self.assertRaises(ProducerContractError):
            ProducerDraftV1(
                task=_task(),
                candidates=(),
                validation_receipts=(),
                coverage_status="complete",  # type: ignore[arg-type]
            )
        with self.assertRaises(ProducerContractError):
            ProducerDeferredV1(
                task=_task(),
                stage="SCOUT",
                reason_code="blocked",
                missing_information=("missing",),
                coverage_status=[],  # type: ignore[arg-type]
            )
        with self.assertRaises(ProducerContractError):
            ProducerContractLimits(max_candidates=33)
        with self.assertRaises(ProducerContractError):
            ProducerContractLimits(max_artifacts_per_draft=65)
        with self.assertRaises(ProducerContractError):
            ProducerContractLimits(limits_version=[])  # type: ignore[arg-type]
        self.assertEqual(
            PRODUCER_ERROR_TAXONOMY_VERSION,
            ProducerContractError.taxonomy_version,
        )

    def test_wire_rejects_noncanonical_duplicate_invalid_and_oversized_input(self) -> None:
        wire = _draft().to_wire()
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1.from_wire(b" " + wire)
        self.assertEqual("wire_invalid", captured.exception.code)
        with self.assertRaises(ProducerContractError):
            parse_producer_result_v1(b'{"result_type":"draft","result_type":"draft"}')
        with self.assertRaises(ProducerContractError):
            parse_producer_result_v1(b"\xff")
        with self.assertRaises(ProducerContractError) as captured:
            parse_producer_result_v1(
                b'"' + b"a" * (DEFAULT_PRODUCER_LIMITS.max_wire_bytes + 1) + b'"'
            )
        self.assertEqual("limit_exceeded", captured.exception.code)

        cyclic: dict[str, object] = {"result_type": "draft"}
        cyclic["cycle"] = cyclic
        with self.assertRaises(ProducerContractError):
            parse_producer_result_v1(cyclic)

    def test_wire_arrays_and_public_constructors_normalize_malformed_inputs(self) -> None:
        draft_value = _draft().to_dict()
        draft_value["candidates"] = tuple(draft_value["candidates"])
        with self.assertRaises(ProducerContractError):
            ProducerDraftV1.from_dict(draft_value)

        candidate = _draft().candidates[0]
        receipt = _draft().validation_receipts[0]
        malformed = (
            {"candidates": None, "validation_receipts": ()},
            {"candidates": "candidate", "validation_receipts": ()},
            {"candidates": (), "validation_receipts": None},
            {"candidates": {}, "validation_receipts": ()},
        )
        for values in malformed:
            with self.subTest(values=values), self.assertRaises(ProducerContractError):
                ProducerDraftV1(
                    task=_task(),
                    candidates=values["candidates"],  # type: ignore[arg-type]
                    validation_receipts=values["validation_receipts"],  # type: ignore[arg-type]
                )
        with self.assertRaises(ProducerContractError):
            ValidationReceiptV1(
                candidate_id=candidate.candidate_id,
                candidate_sha256=candidate.candidate_sha256,
                validation_artifact_id=receipt.validation_artifact_id,
                validation_artifact_sha256=receipt.validation_artifact_sha256,
                selection_digest=receipt.selection_digest,
                dependencies=None,  # type: ignore[arg-type]
            )
        with self.assertRaises(ProducerContractError):
            ProducerArtifactDigestRefV1([], DIGEST_A)  # type: ignore[arg-type]

        class BrokenMapping(Mapping[str, object]):
            def __getitem__(self, key: str) -> object:
                raise OSError("mapping trap")

            def __iter__(self):
                raise OSError("mapping trap")

            def __len__(self) -> int:
                raise OSError("mapping trap")

        class BrokenSequence(Sequence[object]):
            def __getitem__(self, index: int) -> object:
                raise OSError("sequence trap")

            def __len__(self) -> int:
                raise OSError("sequence trap")

        with self.assertRaises(ProducerContractError):
            parse_producer_result_v1(BrokenMapping())
        with self.assertRaises(ProducerContractError):
            ProducerDraftV1(
                task=_task(),
                candidates=BrokenSequence(),  # type: ignore[arg-type]
                validation_receipts=(),
            )
        released = memoryview(b"{}")
        released.release()
        with self.assertRaises(ProducerContractError):
            parse_producer_result_v1(released)

        class EvilStr(str):
            touched = False

            def encode(self, *args, **kwargs):
                self.touched = True
                return object()

        evil = EvilStr(_draft().to_wire().decode("utf-8"))
        for parser in (
            parse_producer_result_v1,
            ProducerDraftV1.from_wire,
            ProducerDeferredV1.from_wire,
        ):
            with self.subTest(parser=parser.__qualname__), self.assertRaises(
                ProducerContractError
            ):
                parser(evil)
        self.assertFalse(evil.touched)

    def test_direct_container_limits_do_not_consume_hostile_sequences(self) -> None:
        class TrapSequence(Sequence[object]):
            touched = False

            def __getitem__(self, index: int) -> object:
                self.touched = True
                raise AssertionError("must not consume a custom sequence")

            def __len__(self) -> int:
                self.touched = True
                raise AssertionError("must not inspect a custom sequence")

        trap = TrapSequence()
        with self.assertRaises(ProducerContractError):
            ProducerDraftV1(
                task=_task(),
                candidates=trap,  # type: ignore[arg-type]
                validation_receipts=(),
            )
        self.assertFalse(trap.touched)

        with self.assertRaises(ProducerContractError):
            ProducerDraftV1(
                task=_task(),
                candidates=range(10**12),  # type: ignore[arg-type]
                validation_receipts=(),
            )

        draft = _draft()
        receipt = draft.validation_receipts[0]
        with self.assertRaises(ProducerContractError):
            ValidationReceiptV1(
                candidate_id=receipt.candidate_id,
                candidate_sha256=receipt.candidate_sha256,
                validation_artifact_id=receipt.validation_artifact_id,
                validation_artifact_sha256=receipt.validation_artifact_sha256,
                selection_digest=receipt.selection_digest,
                dependencies=range(10**12),  # type: ignore[arg-type]
            )
        too_many_dependencies = tuple(
            ProducerArtifactDigestRefV1(_artifact("dep", index), DIGEST_A)
            for index in range(65)
        )
        with self.assertRaises(ProducerContractError) as captured:
            ValidationReceiptV1(
                candidate_id=receipt.candidate_id,
                candidate_sha256=receipt.candidate_sha256,
                validation_artifact_id=receipt.validation_artifact_id,
                validation_artifact_sha256=receipt.validation_artifact_sha256,
                selection_digest=receipt.selection_digest,
                dependencies=too_many_dependencies,
            )
        self.assertEqual("limit_exceeded", captured.exception.code)

        for missing in (range(10**12), tuple(str(index) for index in range(33))):
            with self.subTest(missing=type(missing).__name__), self.assertRaises(
                ProducerContractError
            ):
                ProducerDeferredV1(
                    task=_task(),
                    stage="SCOUT",
                    reason_code="blocked",
                    missing_information=missing,  # type: ignore[arg-type]
                )

    def test_custom_mapping_is_detached_once_and_bounded_by_nodes(self) -> None:
        payload = ProducerDeferredV1(
            task=_task(),
            stage="SCOUT",
            reason_code="blocked",
            missing_information=("missing",),
        ).to_dict()

        class SinglePassMapping(Mapping[str, object]):
            def __init__(self, values: dict[str, object]) -> None:
                self.values = values
                self.iterations = 0

            def __getitem__(self, key: str) -> object:
                return self.values[key]

            def __iter__(self):
                self.iterations += 1
                if self.iterations > 1:
                    raise AssertionError("mapping was traversed twice")
                return iter(self.values)

            def __len__(self) -> int:
                raise AssertionError("custom mapping length must not be trusted")

            def items(self):
                raise AssertionError("items() must not be materialized")

        single_pass = SinglePassMapping(payload)
        parsed = parse_producer_result_v1(single_pass)
        self.assertIsInstance(parsed, ProducerDeferredV1)
        self.assertEqual(1, single_pass.iterations)

        class LazyHugeMapping(Mapping[str, object]):
            def __init__(self) -> None:
                self.lookups = 0

            def __getitem__(self, key: str) -> object:
                self.lookups += 1
                return 0

            def __iter__(self):
                index = 0
                while True:
                    yield f"key-{index}"
                    index += 1

            def __len__(self) -> int:
                raise AssertionError("custom mapping length must not be trusted")

        lazy = LazyHugeMapping()
        with self.assertRaises(ProducerContractError) as captured:
            parse_producer_result_v1(lazy)
        self.assertEqual("limit_exceeded", captured.exception.code)
        self.assertLessEqual(
            lazy.lookups, DEFAULT_PRODUCER_LIMITS.max_json_nodes // 2
        )

        class DuplicateKeyMapping(Mapping[str, object]):
            def __getitem__(self, key: str) -> object:
                return "draft"

            def __iter__(self):
                return iter(("result_type", "result_type"))

            def __len__(self) -> int:
                return 2

        with self.assertRaises(ProducerContractError) as captured:
            parse_producer_result_v1(DuplicateKeyMapping())
        self.assertEqual("invalid_keys", captured.exception.code)

    def test_direct_draft_construction_enforces_final_wire_byte_limit(self) -> None:
        task = _task()
        long_path = "/".join(
            ("a" * 250, "b" * 250, "c" * 250, "d" * 240)
        )
        trace = tuple(
            DiscoveryLocation(long_path, line, line, DIGEST_C)
            for line in range(1, 65)
        )
        candidates = tuple(
            _candidate(
                task,
                index + 1,
                trace=trace,
                source_refs=(_artifact("source-shared", 0),),
                relationship_refs=(_artifact("link-shared", 0),),
            )
            for index in range(32)
        )
        receipts = tuple(
            _receipt(candidate, index + 1)
            for index, candidate in enumerate(candidates)
        )
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1(
                task=task,
                candidates=candidates,
                validation_receipts=receipts,
            )
        self.assertEqual("limit_exceeded", captured.exception.code)

    def test_to_dict_is_detached_and_nested_wire_errors_are_translated(self) -> None:
        draft = _draft()
        value = draft.to_dict()
        detached = copy.deepcopy(value)
        value["candidates"][0]["trace"].append({"bad": "value"})
        value["validation_receipts"][0]["dependencies"].clear()
        self.assertEqual(detached, draft.to_dict())

        malformed = draft.to_dict()
        malformed["task"]["snapshot_id"] = "VGS-" + "0" * 32
        with self.assertRaises(ProducerContractError) as captured:
            ProducerDraftV1.from_dict(malformed)
        self.assertEqual("invalid_binding", captured.exception.code)

    def test_contract_does_not_import_legacy_task_entry_review_or_finding_types(self) -> None:
        import inspect
        import vulngym_agent.benchmark.producer_contracts as module

        source = inspect.getsource(module)
        for forbidden in (
            "RunTask",
            "ProductionOutcome",
            "from vulngym_agent.orchestrator",
            "import Entry",
            "DiscoveryReview",
            "DiscoveryTaskResult",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIn(PRODUCER_POLICY_VERSION, source)


if __name__ == "__main__":
    unittest.main()
