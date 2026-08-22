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
from .producer_contracts import (
    ProducerDeferredV1,
    ProducerDraftV1,
    ProducerResultV1,
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
_PRODUCER_DEFERRED_STAGE_MAP: Final[dict[str, str]] = {
    "SCOUT": "d2.scout",
    "ANALYZE": "d2.analyze",
    "VALIDATE": "d2.validate",
    "FINALIZE": "d2.finalize",
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


def _canonical_producer_result(value: object) -> ProducerResultV1:
    if type(value) is ProducerDraftV1:
        parser = ProducerDraftV1.from_dict
    elif type(value) is ProducerDeferredV1:
        parser = ProducerDeferredV1.from_dict
    else:
        raise ReviewerProjectionError(
            "invalid_result", "producer result must be an exact D2 result"
        )
    try:
        return parser(value.to_dict())
    except (
        AttributeError,
        KeyError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        raise ReviewerProjectionError(
            "invalid_result", "producer result did not pass strict D2 normalization"
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


def project_discovery_run_v1(
    producer_result: ProducerResultV1,
    reviewer_result_or_none: ReviewerResultV1 | None,
) -> DiscoveryTaskResult:
    """Project one exact D2 -> optional D3 run into a strict D0 result.

    A whole-task D2 deferral never enters D3.  A D2 draft, conversely, must
    have one exact D3 result whose embedded producer draft is byte-equivalent
    after both values have independently passed their full wire parsers.
    """

    producer = _canonical_producer_result(producer_result)
    if type(producer) is ProducerDeferredV1:
        if reviewer_result_or_none is not None:
            raise ReviewerProjectionError(
                "invalid_result", "a deferred D2 result cannot have a D3 result"
            )
        try:
            projected = DiscoveryTaskResult(
                task=producer.task,
                status="deferred",
                coverage_status="unknown",
                candidates=(),
                reviews=(),
                deferred=DiscoveryDeferred(
                    task_id=producer.task.task_id,
                    snapshot_id=producer.task.snapshot_id,
                    stage=_PRODUCER_DEFERRED_STAGE_MAP[producer.stage],
                    reason_code=producer.reason_code,
                    missing_information=producer.missing_information,
                ),
            )
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
                "invalid_result", "D2 deferral could not be projected into strict D0"
            ) from None

    if reviewer_result_or_none is None:
        raise ReviewerProjectionError(
            "invalid_result", "a D2 draft requires one exact D3 result"
        )
    reviewer = _canonical_result(reviewer_result_or_none)
    if reviewer.review_input.producer_draft != producer:
        raise ReviewerProjectionError(
            "invalid_result", "D3 result does not bind the exact D2 draft"
        )
    return project_reviewer_result_v1(reviewer)


__all__ = [
    "REVIEWER_PROJECTION_ERROR_TAXONOMY_VERSION",
    "REVIEWER_PROJECTION_VERSION",
    "ReviewerProjectionError",
    "project_discovery_run_v1",
    "project_reviewer_result_v1",
]
