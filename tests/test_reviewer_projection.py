from __future__ import annotations

import unittest

import vulngym_agent.benchmark as benchmark_api
from tests.test_reviewer_contracts import _finalized, _review_input, _seal
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskResult
from vulngym_agent.benchmark.reviewer_contracts import (
    ReviewerDeferredV1,
    ReviewerFinalizedV1,
)
from vulngym_agent.benchmark.reviewer_projection import (
    ReviewerProjectionError,
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
