from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from dataclasses import replace
import hashlib
import json
import unittest

import vulngym_agent.benchmark as benchmark_api
from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryCandidate,
    DiscoveryLocation,
    DiscoveryTaskInputV1,
)
from vulngym_agent.benchmark.producer_contracts import (
    DEFAULT_PRODUCER_LIMITS,
    ProducerArtifactDigestRefV1,
    ProducerDraftV1,
    ValidationReceiptV1,
)
from vulngym_agent.benchmark.reviewer_contracts import (
    DEFAULT_REVIEWER_LIMITS,
    REVIEWER_CRITERIA,
    REVIEWER_ERROR_TAXONOMY_VERSION,
    REVIEWER_INPUT_DIGEST_DOMAIN,
    REVIEWER_INSTRUCTION_ID,
    REVIEWER_POLICY_VERSION,
    REVIEWER_SCOPE,
    ReviewerArtifactDigestRefV1,
    ReviewerAttemptSealV1,
    ReviewerCandidateVerdictV1,
    ReviewerContractError,
    ReviewerContractLimits,
    ReviewerCriterionV1,
    ReviewerDeferredV1,
    ReviewerEvidenceSelectionV1,
    ReviewerFinalizedV1,
    ReviewerInputV1,
    parse_reviewer_result_v1,
)


TASK_ID = "VG-TEST-0123456789ABCDEF0123"
REPO_URL = "https://github.com/example/reviewer-contract"
COMMIT = "1" * 40
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _artifact(kind: str, index: int) -> str:
    return f"ART-{kind}-{index:024x}"


def _task(*, content_root: str = DIGEST_B) -> DiscoveryTaskInputV1:
    return DiscoveryTaskInputV1(
        task_id=TASK_ID,
        repo_url=REPO_URL,
        commit=COMMIT,
        instruction_id=INSTRUCTION_ID,
        snapshot_manifest_sha256=DIGEST_A,
        snapshot_content_root=content_root,
    )


def _candidate(task: DiscoveryTaskInputV1, index: int) -> DiscoveryCandidate:
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
            file="src/service.py",
            line_start=100 + index,
            line_end=100 + index,
            code_sha256=DIGEST_C,
        ),
        trace=(
            DiscoveryLocation(
                file="src/flow.py",
                line_start=200 + index,
                line_end=200 + index,
                code_sha256=DIGEST_C,
            ),
        ),
        relationship_evidence_refs=(_artifact("d2-link", 0),),
        source_evidence_refs=(_artifact("d2-source", 0),),
    )


def _receipt(candidate: DiscoveryCandidate, index: int) -> ValidationReceiptV1:
    dependencies = tuple(
        ProducerArtifactDigestRefV1(
            artifact_id=artifact_id,
            artifact_sha256=_sha(f"d2:{artifact_id}"),
        )
        for artifact_id in sorted(
            set(candidate.relationship_evidence_refs)
            | set(candidate.source_evidence_refs)
        )
    )
    return ValidationReceiptV1(
        candidate_id=candidate.candidate_id,
        candidate_sha256=candidate.candidate_sha256,
        validation_artifact_id=_artifact("d2-validation", index),
        validation_artifact_sha256=_sha(f"d2-validation:{index}"),
        selection_digest=_sha(f"d2-selection:{index}"),
        dependencies=dependencies,
    )


def _draft(count: int = 1) -> ProducerDraftV1:
    task = _task()
    candidates = tuple(_candidate(task, index + 1) for index in range(count))
    return ProducerDraftV1(
        task=task,
        candidates=candidates,
        validation_receipts=tuple(
            _receipt(candidate, index + 1)
            for index, candidate in enumerate(candidates)
        ),
    )


def _review_input(count: int = 1) -> ReviewerInputV1:
    return ReviewerInputV1(producer_draft=_draft(count))


def _criteria(
    index: int,
    assessments: tuple[str, str, str, str] = (
        "supported",
        "supported",
        "supported",
        "supported",
    ),
) -> tuple[ReviewerCriterionV1, ...]:
    artifact_id = _artifact("d3-source", index)
    artifact_sha256 = _sha(f"d3-source:{index}")
    prefixes = ("LOC", "LEX", "REL", "MAT")
    result = []
    for criterion, assessment, prefix in zip(
        REVIEWER_CRITERIA, assessments, prefixes, strict=True
    ):
        selections = (
            ()
            if assessment == "insufficient"
            else (
                ReviewerEvidenceSelectionV1(
                    artifact_id=artifact_id,
                    artifact_sha256=artifact_sha256,
                    node_id=f"{prefix}-node-{index:024x}",
                ),
            )
        )
        result.append(
            ReviewerCriterionV1(
                criterion=criterion,
                assessment=assessment,
                selections=selections,
            )
        )
    return tuple(result)


def _verdict(
    review_input: ReviewerInputV1,
    index: int,
    assessments: tuple[str, str, str, str] = (
        "supported",
        "supported",
        "supported",
        "supported",
    ),
) -> ReviewerCandidateVerdictV1:
    candidate = review_input.producer_draft.candidates[index - 1]
    model_record_sha256 = (
        None
        if all(item == "insufficient" for item in assessments)
        else _sha("d3-model-record:batch")
    )
    return ReviewerCandidateVerdictV1(
        candidate_id=candidate.candidate_id,
        candidate_sha256=candidate.candidate_sha256,
        review_input_sha256=review_input.review_input_sha256,
        criteria=_criteria(index, assessments),
        context_sha256=_sha(f"d3-context:{index}"),
        validation_artifact_id=_artifact("d3-validation", index),
        validation_artifact_sha256=_sha(f"d3-validation:{index}"),
        model_record_sha256=model_record_sha256,
    )


def _used_artifacts(
    verdicts: tuple[ReviewerCandidateVerdictV1, ...],
) -> tuple[ReviewerArtifactDigestRefV1, ...]:
    digests: dict[str, str] = {}
    for verdict in verdicts:
        for criterion in verdict.criteria:
            for selection in criterion.selections:
                digests[selection.artifact_id] = selection.artifact_sha256
        digests[verdict.validation_artifact_id] = verdict.validation_artifact_sha256
    return tuple(
        ReviewerArtifactDigestRefV1(artifact_id=item, artifact_sha256=digests[item])
        for item in sorted(digests)
    )


def _seal(
    review_input: ReviewerInputV1,
    verdicts: tuple[ReviewerCandidateVerdictV1, ...],
    *,
    used_artifacts: tuple[ReviewerArtifactDigestRefV1, ...] | None = None,
    model_record_count: int | None = None,
) -> ReviewerAttemptSealV1:
    used = _used_artifacts(verdicts) if used_artifacts is None else used_artifacts
    used_model_records = tuple(
        sorted(
            {
                verdict.model_record_sha256
                for verdict in verdicts
                if verdict.model_record_sha256 is not None
            }
        )
    )
    return ReviewerAttemptSealV1(
        review_input_sha256=review_input.review_input_sha256,
        task_id=review_input.task_id,
        snapshot_id=review_input.snapshot_id,
        manifest_sha256=review_input.manifest_sha256,
        content_root=review_input.content_root,
        tool_transcript_sha256=_sha("tool-transcript"),
        tool_record_count=0 if not verdicts else len(verdicts),
        model_transcript_sha256=_sha("model-transcript"),
        model_record_count=(
            (0 if not used_model_records else 1)
            if model_record_count is None
            else model_record_count
        ),
        source_ledger_sha256=_sha("source-ledger"),
        source_read_count=0 if not verdicts else len(verdicts),
        artifact_catalog_root_sha256=_sha("artifact-catalog"),
        artifact_count=len(used),
        budget_ledger_sha256=_sha("budget-ledger"),
        budget_event_count=0 if not verdicts else len(verdicts) + 1,
        used_artifacts=used,
        used_model_records=used_model_records,
    )


def _finalized(
    count: int = 1,
    *,
    assessments: tuple[tuple[str, str, str, str], ...] | None = None,
) -> ReviewerFinalizedV1:
    review_input = _review_input(count)
    choices = assessments or tuple(
        ("supported", "supported", "supported", "supported")
        for _ in range(count)
    )
    verdicts = tuple(
        _verdict(review_input, index + 1, choices[index])
        for index in range(count)
    )
    return ReviewerFinalizedV1(
        review_input=review_input,
        verdicts=verdicts,
        attempt_seal=_seal(review_input, verdicts),
    )


class ReviewerContractTests(unittest.TestCase):
    def test_public_benchmark_package_exports_d3_contracts(self) -> None:
        import vulngym_agent.benchmark.reviewer_contracts as reviewer_module

        self.assertIs(benchmark_api.ReviewerInputV1, ReviewerInputV1)
        self.assertIs(benchmark_api.ReviewerFinalizedV1, ReviewerFinalizedV1)
        self.assertIs(benchmark_api.ReviewerDeferredV1, ReviewerDeferredV1)
        self.assertIs(
            benchmark_api.parse_reviewer_result_v1, parse_reviewer_result_v1
        )
        for name in reviewer_module.__all__:
            with self.subTest(name=name):
                self.assertIs(getattr(benchmark_api, name), getattr(reviewer_module, name))

    def test_reviewer_input_round_trip_is_canonical_and_domain_bound(self) -> None:
        review_input = _review_input(2)
        wire = review_input.to_wire()
        self.assertEqual(
            wire,
            json.dumps(
                review_input.to_dict(),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        self.assertEqual(review_input, ReviewerInputV1.from_wire(wire))
        self.assertEqual(review_input, ReviewerInputV1.from_dict(review_input.to_dict()))
        expected = hashlib.sha256(
            REVIEWER_INPUT_DIGEST_DOMAIN
            + json.dumps(
                review_input._digest_dict(),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(expected, review_input.review_input_sha256)
        self.assertEqual(REVIEWER_INSTRUCTION_ID, review_input.instruction_id)

        tampered = review_input.to_dict()
        tampered["producer_draft"]["task"]["snapshot_content_root"] = "d" * 64
        with self.assertRaises(ReviewerContractError):
            ReviewerInputV1.from_dict(tampered)

    def test_reviewer_input_rejects_polymorphic_nested_d2_values(self) -> None:
        draft = _draft()
        candidate = draft.candidates[0]

        class CountingLocation(DiscoveryLocation):
            calls = 0

            def to_dict(self):
                type(self).calls += 1
                return super().to_dict()

        rewritten = DiscoveryCandidate(
            task_id=candidate.task_id,
            snapshot_id=candidate.snapshot_id,
            repo_url=candidate.repo_url,
            commit=candidate.commit,
            entry_point=CountingLocation(**candidate.entry_point.to_dict()),
            critical_operation=candidate.critical_operation,
            trace=candidate.trace,
            relationship_evidence_refs=candidate.relationship_evidence_refs,
            source_evidence_refs=candidate.source_evidence_refs,
        )
        rewritten_draft = ProducerDraftV1(
            task=draft.task,
            candidates=(rewritten,),
            validation_receipts=(_receipt(rewritten, 1),),
        )
        CountingLocation.calls = 0
        with self.assertRaises(ReviewerContractError) as captured:
            ReviewerInputV1(producer_draft=rewritten_draft)
        self.assertEqual("invalid_type", captured.exception.code)
        self.assertEqual(0, CountingLocation.calls)

    def test_reviewer_input_enforces_local_d3_bounds_before_serialization(self) -> None:
        original_candidates = DEFAULT_PRODUCER_LIMITS.max_candidates
        original_receipts = DEFAULT_PRODUCER_LIMITS.max_validation_receipts
        object.__setattr__(DEFAULT_PRODUCER_LIMITS, "max_candidates", 33)
        object.__setattr__(DEFAULT_PRODUCER_LIMITS, "max_validation_receipts", 33)
        try:
            oversized = _draft(33)
            self.assertEqual(33, len(oversized.candidates))
            with self.assertRaises(ReviewerContractError) as captured:
                ReviewerInputV1(producer_draft=oversized)
            self.assertEqual("invalid_type", captured.exception.code)
        finally:
            object.__setattr__(
                DEFAULT_PRODUCER_LIMITS, "max_candidates", original_candidates
            )
            object.__setattr__(
                DEFAULT_PRODUCER_LIMITS,
                "max_validation_receipts",
                original_receipts,
            )

        draft = _draft()
        object.__setattr__(draft, "coverage_status", "x" * 5_000)
        with self.assertRaises(ReviewerContractError):
            ReviewerInputV1(producer_draft=draft)

    def test_fixed_criteria_are_canonical_and_require_evidence_when_conclusive(self) -> None:
        criteria = tuple(reversed(_criteria(1)))
        verdict = ReviewerCandidateVerdictV1(
            candidate_id=_review_input().producer_draft.candidates[0].candidate_id,
            candidate_sha256=_review_input().producer_draft.candidates[0].candidate_sha256,
            review_input_sha256=_review_input().review_input_sha256,
            criteria=criteria,
            context_sha256=_sha("d3-context:1"),
            validation_artifact_id=_artifact("d3-validation", 1),
            validation_artifact_sha256=_sha("d3-validation:1"),
            model_record_sha256=_sha("d3-model-record:batch"),
        )
        self.assertEqual(REVIEWER_CRITERIA, tuple(item.criterion for item in verdict.criteria))

        with self.assertRaises(ReviewerContractError):
            ReviewerCriterionV1(
                criterion="entry_role",
                assessment="supported",
                selections=(),
            )
        insufficient = ReviewerCriterionV1(
            criterion="entry_role",
            assessment="insufficient",
            selections=(),
        )
        self.assertEqual((), insufficient.selections)

    def test_decision_is_mechanically_derived_from_three_value_assessments(self) -> None:
        review_input = _review_input()
        cases = (
            (("supported",) * 4, "accept"),
            (("supported", "insufficient", "supported", "supported"), "defer"),
            (("supported", "insufficient", "contradicted", "supported"), "reject"),
        )
        for assessments, expected in cases:
            with self.subTest(expected=expected):
                verdict = _verdict(review_input, 1, assessments)
                self.assertEqual(expected, verdict.decision)
                self.assertIn(f"review.decision.{expected}", verdict.reason_codes)
                value = verdict.to_dict()
                value["decision"] = "accept" if expected != "accept" else "reject"
                with self.assertRaises(ReviewerContractError):
                    ReviewerCandidateVerdictV1.from_dict(value)

    def test_verdict_binds_candidate_input_selections_and_validation_artifact(self) -> None:
        review_input = _review_input()
        verdict = _verdict(review_input, 1)
        candidate = review_input.producer_draft.candidates[0]
        verdict.assert_candidate(
            candidate, review_input_sha256=review_input.review_input_sha256
        )
        self.assertEqual(verdict, ReviewerCandidateVerdictV1.from_dict(verdict.to_dict()))
        for field_name in (
            "candidate_sha256",
            "context_sha256",
            "model_record_sha256",
            "review_input_sha256",
            "selection_digest",
            "validation_artifact_sha256",
            "verdict_sha256",
        ):
            value = verdict.to_dict()
            value[field_name] = "f" * 64
            with self.subTest(field=field_name), self.assertRaises(
                ReviewerContractError
            ):
                ReviewerCandidateVerdictV1.from_dict(value)

    def test_finalized_round_trip_has_exact_candidate_and_artifact_closure(self) -> None:
        finalized = _finalized(
            3,
            assessments=(
                ("supported", "supported", "supported", "supported"),
                ("supported", "contradicted", "insufficient", "supported"),
                ("supported", "insufficient", "supported", "supported"),
            ),
        )
        self.assertEqual(1, len(finalized.accepted_candidates))
        self.assertEqual(1, len(finalized.rejected_candidates))
        self.assertEqual(1, len(finalized.deferred_candidates))
        self.assertEqual(finalized, ReviewerFinalizedV1.from_wire(finalized.to_wire()))
        self.assertEqual(finalized, parse_reviewer_result_v1(finalized.to_dict()))
        self.assertEqual(finalized, parse_reviewer_result_v1(finalized))
        self.assertIsNot(finalized, parse_reviewer_result_v1(finalized))
        self.assertEqual(
            _used_artifacts(finalized.verdicts), finalized.attempt_seal.used_artifacts
        )

    def test_finalized_rejects_missing_extra_duplicate_or_wrong_input_verdicts(self) -> None:
        finalized = _finalized(2)
        with self.assertRaises(ReviewerContractError) as captured:
            ReviewerFinalizedV1(
                review_input=finalized.review_input,
                verdicts=finalized.verdicts[:1],
                attempt_seal=finalized.attempt_seal,
            )
        self.assertEqual("verdict_coverage_mismatch", captured.exception.code)

        with self.assertRaises(ReviewerContractError):
            ReviewerFinalizedV1(
                review_input=finalized.review_input,
                verdicts=(finalized.verdicts[0], finalized.verdicts[0]),
                attempt_seal=finalized.attempt_seal,
            )

        other_input = ReviewerInputV1(
            producer_draft=_draft(2),
            instruction_id=REVIEWER_INSTRUCTION_ID,
        )
        self.assertEqual(finalized.review_input, other_input)
        wrong = ReviewerCandidateVerdictV1(
            candidate_id=finalized.verdicts[0].candidate_id,
            candidate_sha256=finalized.verdicts[0].candidate_sha256,
            review_input_sha256="f" * 64,
            criteria=finalized.verdicts[0].criteria,
            context_sha256=finalized.verdicts[0].context_sha256,
            validation_artifact_id=finalized.verdicts[0].validation_artifact_id,
            validation_artifact_sha256=finalized.verdicts[0].validation_artifact_sha256,
            model_record_sha256=finalized.verdicts[0].model_record_sha256,
        )
        with self.assertRaises(ReviewerContractError):
            ReviewerFinalizedV1(
                review_input=finalized.review_input,
                verdicts=(wrong, finalized.verdicts[1]),
                attempt_seal=finalized.attempt_seal,
            )

    def test_attempt_seal_exactly_closes_artifacts_and_input(self) -> None:
        finalized = _finalized()
        missing = finalized.attempt_seal.used_artifacts[:-1]
        short_seal = _seal(
            finalized.review_input,
            finalized.verdicts,
            used_artifacts=missing,
        )
        with self.assertRaises(ReviewerContractError) as captured:
            ReviewerFinalizedV1(
                review_input=finalized.review_input,
                verdicts=finalized.verdicts,
                attempt_seal=short_seal,
            )
        self.assertEqual("artifact_coverage_mismatch", captured.exception.code)

        value = finalized.attempt_seal.to_dict()
        value["tool_transcript_sha256"] = "f" * 64
        with self.assertRaises(ReviewerContractError):
            ReviewerAttemptSealV1.from_dict(value)

        with self.assertRaises(ReviewerContractError):
            replace(finalized.attempt_seal, attempt=1)
        with self.assertRaises(ReviewerContractError):
            replace(finalized.attempt_seal, policy_scope="d3.review.extra")
        shared_digest = _sha("impossible-artifact-alias")
        with self.assertRaises(ReviewerContractError) as captured:
            _seal(
                finalized.review_input,
                finalized.verdicts,
                used_artifacts=(
                    ReviewerArtifactDigestRefV1(
                        artifact_id=_artifact("d3-alias-a", 1),
                        artifact_sha256=shared_digest,
                    ),
                    ReviewerArtifactDigestRefV1(
                        artifact_id=_artifact("d3-alias-b", 1),
                        artifact_sha256=shared_digest,
                    ),
                ),
            )
        self.assertEqual("artifact_coverage_mismatch", captured.exception.code)
        wrong_model_closure = replace(
            finalized.attempt_seal, used_model_records=("f" * 64,)
        )
        with self.assertRaises(ReviewerContractError) as captured:
            ReviewerFinalizedV1(
                review_input=finalized.review_input,
                verdicts=finalized.verdicts,
                attempt_seal=wrong_model_closure,
            )
        self.assertEqual("invalid_binding", captured.exception.code)

        with self.assertRaises(ReviewerContractError):
            replace(
                finalized.verdicts[0],
                validation_contract_id="review.validation@2",
            )

    def test_in_memory_values_are_rebuilt_and_derived_fields_rechecked(self) -> None:
        criterion = ReviewerCriterionV1(
            criterion="entry_role",
            assessment="insufficient",
            selections=(),
        )
        object.__setattr__(criterion, "assessment", "supported")
        review_input = _review_input()
        other = _criteria(1)[1:]
        with self.assertRaises(ReviewerContractError):
            ReviewerCandidateVerdictV1(
                candidate_id=review_input.producer_draft.candidates[0].candidate_id,
                candidate_sha256=review_input.producer_draft.candidates[0].candidate_sha256,
                review_input_sha256=review_input.review_input_sha256,
                criteria=(criterion, *other),
                context_sha256=_sha("d3-context:1"),
                validation_artifact_id=_artifact("d3-validation", 1),
                validation_artifact_sha256=_sha("d3-validation:1"),
                model_record_sha256=_sha("d3-model-record:batch"),
            )

        finalized = _finalized(
            1,
            assessments=(("insufficient",) * 4,),
        )
        object.__setattr__(finalized.verdicts[0], "decision", "accept")
        with self.assertRaises(ReviewerContractError):
            parse_reviewer_result_v1(finalized)

    def test_validation_artifacts_cannot_be_evidence_for_other_candidates(self) -> None:
        review_input = _review_input(2)
        first = _verdict(review_input, 1)
        aliased_criteria = tuple(
            ReviewerCriterionV1(
                criterion=criterion,
                assessment="supported",
                selections=(
                    ReviewerEvidenceSelectionV1(
                        artifact_id=first.validation_artifact_id,
                        artifact_sha256=first.validation_artifact_sha256,
                        node_id=f"{prefix}-alias-{index:024x}",
                    ),
                ),
            )
            for index, (criterion, prefix) in enumerate(
                zip(REVIEWER_CRITERIA, ("LOC", "LEX", "REL", "MAT"), strict=True),
                start=1,
            )
        )
        second_candidate = review_input.producer_draft.candidates[1]
        second = ReviewerCandidateVerdictV1(
            candidate_id=second_candidate.candidate_id,
            candidate_sha256=second_candidate.candidate_sha256,
            review_input_sha256=review_input.review_input_sha256,
            criteria=aliased_criteria,
            context_sha256=_sha("d3-context:2"),
            validation_artifact_id=_artifact("d3-validation", 2),
            validation_artifact_sha256=_sha("d3-validation:2"),
            model_record_sha256=_sha("d3-model-record:batch"),
        )
        verdicts = (first, second)
        with self.assertRaises(ReviewerContractError) as captured:
            ReviewerFinalizedV1(
                review_input=review_input,
                verdicts=verdicts,
                attempt_seal=_seal(review_input, verdicts),
            )
        self.assertEqual("artifact_coverage_mismatch", captured.exception.code)

    def test_validation_artifact_digests_are_unique_and_not_evidence(self) -> None:
        review_input = _review_input(2)
        first = _verdict(review_input, 1)
        second = _verdict(review_input, 2)
        duplicate_validation_digest = replace(
            second,
            validation_artifact_sha256=first.validation_artifact_sha256,
        )
        with self.assertRaises(ReviewerContractError) as captured:
            ReviewerFinalizedV1(
                review_input=review_input,
                verdicts=(first, duplicate_validation_digest),
                attempt_seal=_seal(
                    review_input, (first, duplicate_validation_digest)
                ),
            )
        self.assertEqual("artifact_coverage_mismatch", captured.exception.code)

        candidate = review_input.producer_draft.candidates[1]
        digest_alias_criteria = tuple(
            ReviewerCriterionV1(
                criterion=criterion,
                assessment="supported",
                selections=(
                    ReviewerEvidenceSelectionV1(
                        artifact_id=_artifact("d3-fresh-evidence", 2),
                        artifact_sha256=first.validation_artifact_sha256,
                        node_id=f"{prefix}-digest-alias-{index:016x}",
                    ),
                ),
            )
            for index, (criterion, prefix) in enumerate(
                zip(REVIEWER_CRITERIA, ("LOC", "LEX", "REL", "MAT"), strict=True),
                start=1,
            )
        )
        evidence_digest_alias = ReviewerCandidateVerdictV1(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            review_input_sha256=review_input.review_input_sha256,
            criteria=digest_alias_criteria,
            context_sha256=_sha("d3-context:digest-alias"),
            validation_artifact_id=second.validation_artifact_id,
            validation_artifact_sha256=second.validation_artifact_sha256,
            model_record_sha256=_sha("d3-model-record:batch"),
        )
        with self.assertRaises(ReviewerContractError) as captured:
            ReviewerFinalizedV1(
                review_input=review_input,
                verdicts=(first, evidence_digest_alias),
                attempt_seal=_seal(review_input, (first, evidence_digest_alias)),
            )
        self.assertEqual("artifact_coverage_mismatch", captured.exception.code)

    def test_d3_artifact_closure_cannot_reuse_any_d2_artifact_id(self) -> None:
        review_input = _review_input(1)
        candidate = review_input.producer_draft.candidates[0]
        receipt = review_input.producer_draft.validation_receipts[0]
        dependency = receipt.dependencies[0]
        aliased_criteria = tuple(
            ReviewerCriterionV1(
                criterion=criterion,
                assessment="supported",
                selections=(
                    ReviewerEvidenceSelectionV1(
                        artifact_id=dependency.artifact_id,
                        artifact_sha256=dependency.artifact_sha256,
                        node_id=f"{prefix}-d2-{index:024x}",
                    ),
                ),
            )
            for index, (criterion, prefix) in enumerate(
                zip(REVIEWER_CRITERIA, ("LOC", "LEX", "REL", "MAT"), strict=True),
                start=1,
            )
        )
        evidence_alias = ReviewerCandidateVerdictV1(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            review_input_sha256=review_input.review_input_sha256,
            criteria=aliased_criteria,
            context_sha256=_sha("d3-context:1"),
            validation_artifact_id=_artifact("d3-validation", 1),
            validation_artifact_sha256=_sha("d3-validation:1"),
            model_record_sha256=_sha("d3-model-record:batch"),
        )
        validation_alias = ReviewerCandidateVerdictV1(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            review_input_sha256=review_input.review_input_sha256,
            criteria=_criteria(1),
            context_sha256=_sha("d3-context:1"),
            validation_artifact_id=receipt.validation_artifact_id,
            validation_artifact_sha256=receipt.validation_artifact_sha256,
            model_record_sha256=_sha("d3-model-record:batch"),
        )
        for verdict in (evidence_alias, validation_alias):
            with self.subTest(alias=verdict.validation_artifact_id), self.assertRaises(
                ReviewerContractError
            ) as captured:
                ReviewerFinalizedV1(
                    review_input=review_input,
                    verdicts=(verdict,),
                    attempt_seal=_seal(review_input, (verdict,)),
                )
            self.assertEqual("artifact_coverage_mismatch", captured.exception.code)

    def test_d3_artifact_closure_cannot_reuse_a_d2_digest_under_a_new_id(self) -> None:
        review_input = _review_input(1)
        candidate = review_input.producer_draft.candidates[0]
        receipt = review_input.producer_draft.validation_receipts[0]
        dependency = receipt.dependencies[0]
        aliased_criteria = tuple(
            ReviewerCriterionV1(
                criterion=criterion,
                assessment="supported",
                selections=(
                    ReviewerEvidenceSelectionV1(
                        artifact_id=_artifact("d3-renamed", 1),
                        artifact_sha256=dependency.artifact_sha256,
                        node_id=f"{prefix}-d2-digest-{index:016x}",
                    ),
                ),
            )
            for index, (criterion, prefix) in enumerate(
                zip(REVIEWER_CRITERIA, ("LOC", "LEX", "REL", "MAT"), strict=True),
                start=1,
            )
        )
        verdict = ReviewerCandidateVerdictV1(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            review_input_sha256=review_input.review_input_sha256,
            criteria=aliased_criteria,
            context_sha256=_sha("d3-context:d2-digest-alias"),
            validation_artifact_id=_artifact("d3-validation-fresh", 1),
            validation_artifact_sha256=_sha("d3-validation:fresh"),
            model_record_sha256=_sha("d3-model-record:batch"),
        )
        with self.assertRaises(ReviewerContractError) as captured:
            ReviewerFinalizedV1(
                review_input=review_input,
                verdicts=(verdict,),
                attempt_seal=_seal(review_input, (verdict,)),
            )
        self.assertEqual("artifact_coverage_mismatch", captured.exception.code)

    def test_zero_and_32_candidate_results_are_allowed(self) -> None:
        empty = _finalized(0)
        self.assertEqual((), empty.verdicts)
        self.assertEqual(0, empty.attempt_seal.model_record_count)
        self.assertEqual(empty, ReviewerFinalizedV1.from_wire(empty.to_wire()))

        maximum = _finalized(32)
        self.assertEqual(32, len(maximum.verdicts))
        self.assertEqual(64, len(maximum.attempt_seal.used_artifacts))
        self.assertLessEqual(len(maximum.to_wire()), DEFAULT_REVIEWER_LIMITS.max_wire_bytes)

    def test_model_call_count_matches_zero_and_conclusive_review_semantics(self) -> None:
        review_input = _review_input(0)
        seal = _seal(review_input, (), model_record_count=1)
        with self.assertRaises(ReviewerContractError):
            ReviewerFinalizedV1(
                review_input=review_input,
                verdicts=(),
                attempt_seal=seal,
            )

        insufficient_input = _review_input(1)
        insufficient_verdicts = (
            _verdict(insufficient_input, 1, ("insufficient",) * 4),
        )
        insufficient = ReviewerFinalizedV1(
            review_input=insufficient_input,
            verdicts=insufficient_verdicts,
            attempt_seal=_seal(
                insufficient_input,
                insufficient_verdicts,
                model_record_count=0,
            ),
        )
        self.assertEqual("defer", insufficient.verdicts[0].decision)
        self.assertEqual(0, insufficient.attempt_seal.model_record_count)

        review_input = _review_input(1)
        verdicts = (_verdict(review_input, 1),)
        with self.assertRaises(ReviewerContractError):
            _seal(review_input, verdicts, model_record_count=0)

    def test_deferred_is_fail_closed_and_uses_fixed_taxonomies(self) -> None:
        review_input = _review_input()
        seal = _seal(review_input, ())
        deferred = ReviewerDeferredV1(
            review_input=review_input,
            stage="REVIEW",
            reason_code="runtime.model_failed",
            missing_information=("model_response",),
            attempt_seal=seal,
        )
        self.assertEqual(deferred, ReviewerDeferredV1.from_wire(deferred.to_wire()))
        self.assertEqual(deferred, parse_reviewer_result_v1(deferred.to_dict()))
        self.assertNotIn("verdicts", deferred.to_dict())

        seal_failed = ReviewerDeferredV1(
            review_input=review_input,
            stage="FINALIZE",
            reason_code="runtime.seal_failed",
            missing_information=("attempt_seal",),
            attempt_seal=None,
        )
        self.assertIsNone(seal_failed.attempt_seal)
        for reason, missing, attempt_seal in (
            ("unknown", ("model_response",), seal),
            ("runtime.model_failed", ("free text",), seal),
            ("runtime.model_failed", ("model_response",), None),
            ("runtime.seal_failed", ("attempt_seal",), seal),
            ("runtime.seal_failed", ("model_response",), None),
        ):
            with self.subTest(reason=reason, missing=missing), self.assertRaises(
                ReviewerContractError
            ):
                ReviewerDeferredV1(
                    review_input=review_input,
                    stage="FINALIZE",
                    reason_code=reason,
                    missing_information=missing,
                    attempt_seal=attempt_seal,
                )
        with self.assertRaises(ReviewerContractError):
            ReviewerDeferredV1(
                review_input=review_input,
                stage="REVIEW",
                reason_code="runtime.seal_failed",
                missing_information=("attempt_seal",),
                attempt_seal=None,
            )

        upstream = review_input.producer_draft.validation_receipts[0].dependencies[0]
        aliased_seal = _seal(
            review_input,
            (),
            used_artifacts=(
                ReviewerArtifactDigestRefV1(
                    artifact_id=upstream.artifact_id,
                    artifact_sha256=upstream.artifact_sha256,
                ),
            ),
        )
        with self.assertRaises(ReviewerContractError) as captured:
            ReviewerDeferredV1(
                review_input=review_input,
                stage="REVIEW",
                reason_code="runtime.model_failed",
                missing_information=("model_response",),
                attempt_seal=aliased_seal,
            )
        self.assertEqual("artifact_coverage_mismatch", captured.exception.code)

    def test_fixed_limits_and_scope_cannot_be_expanded(self) -> None:
        self.assertEqual("d3.review", REVIEWER_SCOPE)
        self.assertEqual("unknown", _finalized().coverage_status)
        with self.assertRaises(ReviewerContractError):
            ReviewerContractLimits(max_candidates=33)
        with self.assertRaises(ReviewerContractError):
            ReviewerContractLimits(max_wire_bytes=2_000_000)
        with self.assertRaises(ReviewerContractError):
            ReviewerInputV1(
                producer_draft=_draft(), instruction_id="f" * 64
            )
        self.assertEqual(
            REVIEWER_ERROR_TAXONOMY_VERSION,
            ReviewerContractError.taxonomy_version,
        )

        original = DEFAULT_REVIEWER_LIMITS.max_selections_per_criterion
        object.__setattr__(
            DEFAULT_REVIEWER_LIMITS, "max_selections_per_criterion", original + 1
        )
        try:
            selections = tuple(
                ReviewerEvidenceSelectionV1(
                    artifact_id=_artifact("limit", index),
                    artifact_sha256=_sha(f"limit:{index}"),
                    node_id=f"LOC-limit-{index:024x}",
                )
                for index in range(original + 1)
            )
            with self.assertRaises(ReviewerContractError) as captured:
                ReviewerCriterionV1(
                    criterion="entry_role",
                    assessment="supported",
                    selections=selections,
                )
            self.assertEqual("limit_exceeded", captured.exception.code)
        finally:
            object.__setattr__(
                DEFAULT_REVIEWER_LIMITS,
                "max_selections_per_criterion",
                original,
            )

    def test_wire_rejects_noncanonical_duplicate_invalid_and_oversized_input(self) -> None:
        wire = _finalized().to_wire()
        with self.assertRaises(ReviewerContractError) as captured:
            ReviewerFinalizedV1.from_wire(b" " + wire)
        self.assertEqual("wire_invalid", captured.exception.code)
        with self.assertRaises(ReviewerContractError):
            parse_reviewer_result_v1(
                b'{"result_type":"finalized","result_type":"finalized"}'
            )
        with self.assertRaises(ReviewerContractError):
            parse_reviewer_result_v1(b"\xff")
        with self.assertRaises(ReviewerContractError) as captured:
            parse_reviewer_result_v1(
                b'"'
                + b"a" * (DEFAULT_REVIEWER_LIMITS.max_wire_bytes + 1)
                + b'"'
            )
        self.assertEqual("limit_exceeded", captured.exception.code)

        cyclic: dict[str, object] = {"result_type": "finalized"}
        cyclic["cycle"] = cyclic
        with self.assertRaises(ReviewerContractError):
            parse_reviewer_result_v1(cyclic)

    def test_public_constructors_do_not_consume_hostile_sequences(self) -> None:
        class Endless(Sequence[object]):
            def __len__(self) -> int:
                return 1

            def __getitem__(self, index: int) -> object:
                return self

        with self.assertRaises(ReviewerContractError) as captured:
            ReviewerCriterionV1(
                criterion="entry_role",
                assessment="insufficient",
                selections=Endless(),  # type: ignore[arg-type]
            )
        self.assertEqual("invalid_type", captured.exception.code)

        class StatefulMapping(Mapping[str, object]):
            def __init__(self) -> None:
                self.reads = 0

            def __iter__(self):
                return iter(("result_type",))

            def __len__(self) -> int:
                return 1

            def __getitem__(self, key: str) -> object:
                self.reads += 1
                return "finalized"

        mapping = StatefulMapping()
        with self.assertRaises(ReviewerContractError):
            parse_reviewer_result_v1(mapping)
        self.assertEqual(1, mapping.reads)

    def test_to_dict_is_detached_and_contract_avoids_legacy_review_types(self) -> None:
        finalized = _finalized()
        value = finalized.to_dict()
        detached = copy.deepcopy(value)
        value["verdicts"][0]["criteria"][0]["selections"].clear()
        value["review_input"]["producer_draft"]["candidates"].clear()
        self.assertEqual(detached, finalized.to_dict())

        import inspect
        import vulngym_agent.benchmark.reviewer_contracts as module

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
        self.assertIn(REVIEWER_POLICY_VERSION, source)


if __name__ == "__main__":
    unittest.main()
