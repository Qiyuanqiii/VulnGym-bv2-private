"""Strict D4 adapter from closed D3 review results to the public D0 result."""

from __future__ import annotations

from typing import Final

from .discovery_contracts import (
    DiscoveryContractError,
    DiscoveryDeferred,
    DiscoveryReview,
    DiscoveryTaskResult,
)
from .reviewer_contracts import (
    ReviewerContractError,
    ReviewerDeferredV1,
    ReviewerFinalizedV1,
    ReviewerResultV1,
    parse_reviewer_result_v1,
)


REVIEWER_PROJECTION_VERSION: Final[str] = "source-discovery-reviewer-d4-v1"
REVIEWER_PROJECTION_ERROR_TAXONOMY_VERSION: Final[str] = (
    "source-discovery-reviewer-projection-errors-v1"
)

_ERROR_CODES: Final[frozenset[str]] = frozenset({"invalid_result"})
_DECISION_MAP: Final[dict[str, str]] = {
    "accept": "emit",
    "reject": "reject",
    "defer": "defer",
}
_DEFERRED_STAGE_MAP: Final[dict[str, str]] = {
    "REVIEW": "d3.review",
    "FINALIZE": "d3.finalize",
}


class ReviewerProjectionError(ValueError):
    """Stable D4 failure that never exposes implementation details."""

    taxonomy_version = REVIEWER_PROJECTION_ERROR_TAXONOMY_VERSION

    def __init__(self, code: str, message: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            code = "invalid_result"
            message = "reviewer projection error code is invalid"
        self.code = code
        super().__init__(message)


def _canonical_result(value: object) -> ReviewerResultV1:
    if type(value) not in (ReviewerFinalizedV1, ReviewerDeferredV1):
        raise ReviewerProjectionError(
            "invalid_result", "result must be an exact D3 reviewer result"
        )
    try:
        return parse_reviewer_result_v1(value)
    except (
        AttributeError,
        KeyError,
        RecursionError,
        ReviewerContractError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        raise ReviewerProjectionError(
            "invalid_result", "result did not pass strict D3 normalization"
        ) from None


def project_reviewer_result_v1(result: ReviewerResultV1) -> DiscoveryTaskResult:
    """Erase private D3 sidecars and return one strictly reparsed D0 result.

    D3 ``accept`` is the sole decision that becomes D0 ``emit``.  A whole-task
    D3 deferral remains fail closed and carries no candidates or reviews.
    """

    canonical = _canonical_result(result)
    task = canonical.review_input.producer_draft.task
    try:
        if type(canonical) is ReviewerFinalizedV1:
            projected = DiscoveryTaskResult(
                task=task,
                status="finalized",
                coverage_status="unknown",
                candidates=canonical.review_input.producer_draft.candidates,
                reviews=tuple(
                    DiscoveryReview(
                        task_id=task.task_id,
                        snapshot_id=task.snapshot_id,
                        candidate_id=verdict.candidate_id,
                        candidate_sha256=verdict.candidate_sha256,
                        decision=_DECISION_MAP[verdict.decision],
                        reason_codes=verdict.reason_codes,
                    )
                    for verdict in canonical.verdicts
                ),
            )
        else:
            projected = DiscoveryTaskResult(
                task=task,
                status="deferred",
                coverage_status="unknown",
                candidates=(),
                reviews=(),
                deferred=DiscoveryDeferred(
                    task_id=task.task_id,
                    snapshot_id=task.snapshot_id,
                    stage=_DEFERRED_STAGE_MAP[canonical.stage],
                    reason_code=canonical.reason_code,
                    missing_information=canonical.missing_information,
                ),
            )
        # Reparse the full D0 wire shape before it crosses the adapter boundary.
        return DiscoveryTaskResult.from_dict(projected.to_dict())
    except (
        AttributeError,
        DiscoveryContractError,
        KeyError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        raise ReviewerProjectionError(
            "invalid_result", "D3 result could not be projected into strict D0"
        ) from None


__all__ = [
    "REVIEWER_PROJECTION_ERROR_TAXONOMY_VERSION",
    "REVIEWER_PROJECTION_VERSION",
    "ReviewerProjectionError",
    "project_reviewer_result_v1",
]
