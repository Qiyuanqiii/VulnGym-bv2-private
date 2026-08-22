from __future__ import annotations

import unittest

import vulngym_agent.benchmark as benchmark_api
from tests.test_reviewer_contracts import _finalized, _review_input, _seal
from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryLocation,
    DiscoveryTaskInputV1,
    DiscoveryTaskResult,
)
from vulngym_agent.benchmark.producer_contracts import (
    ProducerDeferredV1,
    ProducerDraftV1,
)
from vulngym_agent.benchmark.reviewer_contracts import (
    ReviewerDeferredV1,
    ReviewerFinalizedV1,
)
from vulngym_agent.benchmark.reviewer_projection import (
    ReviewerProjectionError,
    project_discovery_run_v1,
    project_reviewer_result_v1,
)


class ReviewerProjectionTests(unittest.TestCase):
    def test_public_package_exports_d4_adapter(self) -> None:
        self.assertIs(
            benchmark_api.project_reviewer_result_v1,
            project_reviewer_result_v1,
        )
        self.assertIs(
            benchmark_api.ReviewerProjectionError,
            ReviewerProjectionError,
        )

    def test_finalized_maps_accept_reject_and_defer_mechanically(self) -> None:
        result = _finalized(
            3,
            assessments=(
                ("supported",) * 4,
                ("supported", "contradicted", "supported", "supported"),
                ("supported", "supported", "insufficient", "supported"),
            ),
        )
        projected = project_reviewer_result_v1(result)

        self.assertIs(type(projected), DiscoveryTaskResult)
        self.assertEqual("finalized", projected.status)
        self.assertEqual("unknown", projected.coverage_status)
        self.assertEqual(result.review_input.producer_draft.candidates, projected.candidates)
        by_id = {item.candidate_id: item for item in projected.reviews}
        self.assertEqual(
            ["emit", "reject", "defer"],
            [
                by_id[item.candidate_id].decision
                for item in result.review_input.producer_draft.candidates
            ],
        )
        for verdict in result.verdicts:
            self.assertEqual(verdict.reason_codes, by_id[verdict.candidate_id].reason_codes)
        self.assertEqual(projected, DiscoveryTaskResult.from_dict(projected.to_dict()))

    def test_deferred_erases_candidates_and_maps_stage(self) -> None:
        review_input = _review_input(1)
        seal = _seal(review_input, ())
        for source_stage, target_stage in (
            ("REVIEW", "d3.review"),
            ("FINALIZE", "d3.finalize"),
        ):
            with self.subTest(stage=source_stage):
                result = ReviewerDeferredV1(
                    review_input=review_input,
                    stage=source_stage,
                    reason_code="runtime.model_failed",
                    missing_information=("model_response",),
                    attempt_seal=seal,
                )
                projected = project_reviewer_result_v1(result)
                self.assertEqual("deferred", projected.status)
                self.assertEqual((), projected.candidates)
                self.assertEqual((), projected.reviews)
                self.assertIsNotNone(projected.deferred)
                assert projected.deferred is not None
                self.assertEqual(target_stage, projected.deferred.stage)
                self.assertEqual(result.reason_code, projected.deferred.reason_code)

    def test_discovery_run_maps_every_d2_deferred_stage_without_d3(self) -> None:
        task = _review_input(0).producer_draft.task
        for source_stage, target_stage in (
            ("SCOUT", "d2.scout"),
            ("ANALYZE", "d2.analyze"),
            ("VALIDATE", "d2.validate"),
            ("FINALIZE", "d2.finalize"),
        ):
            with self.subTest(stage=source_stage):
                producer = ProducerDeferredV1(
                    task=task,
                    stage=source_stage,
                    reason_code="model_error",
                    missing_information=("source evidence is incomplete",),
                )
                projected = project_discovery_run_v1(producer, None)
                self.assertEqual("deferred", projected.status)
                self.assertEqual("unknown", projected.coverage_status)
                self.assertEqual((), projected.candidates)
                self.assertEqual((), projected.reviews)
                self.assertIsNotNone(projected.deferred)
                assert projected.deferred is not None
                self.assertEqual(target_stage, projected.deferred.stage)
                self.assertEqual(producer.reason_code, projected.deferred.reason_code)
                self.assertEqual(
                    producer.missing_information,
                    projected.deferred.missing_information,
                )
                self.assertEqual(
                    projected, DiscoveryTaskResult.from_dict(projected.to_dict())
                )

    def test_discovery_run_requires_exact_d2_d3_branch_closure(self) -> None:
        reviewer = _finalized()
        producer = reviewer.review_input.producer_draft
        self.assertEqual(
            project_reviewer_result_v1(reviewer),
            project_discovery_run_v1(producer, reviewer),
        )

        review_input = _review_input(0)
        reviewer_deferred = ReviewerDeferredV1(
            review_input=review_input,
            stage="REVIEW",
            reason_code="runtime.model_failed",
            missing_information=("model_response",),
            attempt_seal=_seal(review_input, ()),
        )
        self.assertEqual(
            project_reviewer_result_v1(reviewer_deferred),
            project_discovery_run_v1(
                review_input.producer_draft,
                reviewer_deferred,
            ),
        )

        with self.assertRaises(ReviewerProjectionError) as captured:
            project_discovery_run_v1(producer, None)
        self.assertEqual("invalid_result", captured.exception.code)

        deferred = ProducerDeferredV1(
            task=producer.task,
            stage="SCOUT",
            reason_code="model_error",
            missing_information=("source evidence is incomplete",),
        )
        with self.assertRaises(ReviewerProjectionError) as captured:
            project_discovery_run_v1(deferred, reviewer)
        self.assertEqual("invalid_result", captured.exception.code)

        mismatched = _finalized(2)
        with self.assertRaises(ReviewerProjectionError) as captured:
            project_discovery_run_v1(
                mismatched.review_input.producer_draft,
                reviewer,
            )
        self.assertEqual("invalid_result", captured.exception.code)

    def test_discovery_run_strictly_reparses_d2_and_rejects_polymorphism(self) -> None:
        reviewer = _finalized()
        producer = reviewer.review_input.producer_draft
        object.__setattr__(producer, "candidates", ())
        with self.assertRaises(ReviewerProjectionError) as captured:
            project_discovery_run_v1(producer, reviewer)
        self.assertEqual("invalid_result", captured.exception.code)

        fresh = _finalized().review_input.producer_draft

        class DraftSubclass(ProducerDraftV1):
            pass

        subclass = DraftSubclass(
            task=fresh.task,
            candidates=fresh.candidates,
            validation_receipts=fresh.validation_receipts,
        )
        with self.assertRaises(ReviewerProjectionError) as captured:
            project_discovery_run_v1(subclass, _finalized())
        self.assertEqual("invalid_result", captured.exception.code)

        with self.assertRaises(ReviewerProjectionError) as captured:
            project_discovery_run_v1({}, None)  # type: ignore[arg-type]
        self.assertEqual("invalid_result", captured.exception.code)

    def test_discovery_run_rejects_nested_d2_subclasses_without_callbacks(self) -> None:
        serializer_calls: list[str] = []

        class CountingLocation(DiscoveryLocation):
            def to_dict(self):
                serializer_calls.append("draft-location")
                raise AssertionError("nested draft serializer was invoked")

        draft = _finalized().review_input.producer_draft
        entry = draft.candidates[0].entry_point
        object.__setattr__(
            draft.candidates[0],
            "entry_point",
            CountingLocation(
                file=entry.file,
                line_start=entry.line_start,
                line_end=entry.line_end,
                code_sha256=entry.code_sha256,
            ),
        )
        with self.assertRaises(ReviewerProjectionError) as captured:
            project_discovery_run_v1(draft, None)
        self.assertEqual("invalid_result", captured.exception.code)

        class CountingTask(DiscoveryTaskInputV1):
            def to_dict(self):
                serializer_calls.append("deferred-task")
                raise AssertionError("nested deferred serializer was invoked")

        task = _review_input(0).producer_draft.task
        nested_task = CountingTask(
            task_id=task.task_id,
            repo_url=task.repo_url,
            commit=task.commit,
            instruction_id=task.instruction_id,
            snapshot_manifest_sha256=task.snapshot_manifest_sha256,
            snapshot_content_root=task.snapshot_content_root,
        )
        deferred = ProducerDeferredV1(
            task=task,
            stage="SCOUT",
            reason_code="model_error",
            missing_information=("source evidence is incomplete",),
        )
        object.__setattr__(deferred, "task", nested_task)
        with self.assertRaises(ReviewerProjectionError) as captured:
            project_discovery_run_v1(deferred, None)
        self.assertEqual("invalid_result", captured.exception.code)
        self.assertEqual(serializer_calls, [])

    def test_projection_strictly_rechecks_input_and_derived_fields(self) -> None:
        result = _finalized()
        object.__setattr__(result.verdicts[0], "decision", "reject")
        with self.assertRaises(ReviewerProjectionError) as captured:
            project_reviewer_result_v1(result)
        self.assertEqual("invalid_result", captured.exception.code)

        class FinalizedSubclass(ReviewerFinalizedV1):
            pass

        fresh = _finalized()
        subclass = FinalizedSubclass(
            review_input=fresh.review_input,
            verdicts=fresh.verdicts,
            attempt_seal=fresh.attempt_seal,
        )
        with self.assertRaises(ReviewerProjectionError):
            project_reviewer_result_v1(subclass)

    def test_projection_rejects_wrong_top_level_type(self) -> None:
        with self.assertRaises(ReviewerProjectionError):
            project_reviewer_result_v1({})  # type: ignore[arg-type]

    def test_projection_normalizes_missing_nested_fields(self) -> None:
        finalized = _finalized()
        object.__delattr__(finalized.verdicts[0], "decision")
        with self.assertRaises(ReviewerProjectionError) as captured:
            project_reviewer_result_v1(finalized)
        self.assertEqual("invalid_result", captured.exception.code)

        review_input = _review_input(0)
        deferred = ReviewerDeferredV1(
            review_input=review_input,
            stage="REVIEW",
            reason_code="runtime.model_failed",
            missing_information=("model_response",),
            attempt_seal=_seal(review_input, ()),
        )
        object.__delattr__(deferred, "stage")
        with self.assertRaises(ReviewerProjectionError) as captured:
            project_reviewer_result_v1(deferred)
        self.assertEqual("invalid_result", captured.exception.code)


if __name__ == "__main__":
    unittest.main()
