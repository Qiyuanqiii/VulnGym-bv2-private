"""Bounded projection from reviewed discovery candidates to evaluator findings."""

from __future__ import annotations

import hashlib
import json
from types import MappingProxyType
from typing import Any, Final, Mapping

from .discovery_contracts import (
    DEFAULT_DISCOVERY_LIMITS,
    DiscoveryCandidate,
    DiscoveryContractError,
    DiscoveryDeferred,
    DiscoveryLocation,
    DiscoveryReview,
    DiscoveryTaskInputV1,
    DiscoveryTaskResult,
)


DISCOVERY_PROJECTION_VERSION: Final[str] = "source-discovery-projection-v1"
DISCOVERY_PROJECTION_ERROR_TAXONOMY_VERSION: Final[str] = (
    "source-discovery-projection-errors-v1"
)

_PROJECTION_ERROR_CODES = frozenset(
    {"invalid_limit", "invalid_result", "projection_limit_exceeded"}
)


class DiscoveryProjectionError(ValueError):
    """A stable D0 projection failure."""

    taxonomy_version = DISCOVERY_PROJECTION_ERROR_TAXONOMY_VERSION

    def __init__(self, code: str, message: str) -> None:
        if code not in _PROJECTION_ERROR_CODES:
            raise ValueError("unknown discovery projection error code")
        self.code = code
        super().__init__(message)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _finding(candidate: DiscoveryCandidate) -> dict[str, Any]:
    identity = {
        "commit": candidate.commit,
        "critical_operation": candidate.critical_operation.evaluator_location(),
        "entry_point": candidate.entry_point.evaluator_location(),
        "repo_url": candidate.repo_url,
        "task_id": candidate.task_id,
    }
    digest = hashlib.sha256(_canonical_json(identity)).hexdigest()
    finding: dict[str, Any] = {
        "task_id": candidate.task_id,
        "finding_id": "VGF-" + digest[:32].upper(),
        "repo_url": candidate.repo_url,
        "commit": candidate.commit,
        "entry_point": candidate.entry_point.evaluator_location(),
        "critical_operation": candidate.critical_operation.evaluator_location(),
    }
    if candidate.trace:
        finding["trace"] = [item.evaluator_location() for item in candidate.trace]
    return finding


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze_json(child) for key, child in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child) for child in value)
    return value


def _has_exact_contract_types(result: DiscoveryTaskResult) -> bool:
    """Reject polymorphic contract nodes before invoking serialization methods.

    D0 constructors historically accepted subclasses for nested values.  The
    projection boundary must not call an overridable ``to_dict`` or location
    helper on such a value, so exact-type verification deliberately precedes
    strict wire normalization.
    """

    def exact_text(*values: object) -> bool:
        return all(type(value) is str for value in values)

    def exact_location(location: object) -> bool:
        return (
            type(location) is DiscoveryLocation
            and exact_text(location.file, location.code_sha256)
            and type(location.line_start) is int
            and type(location.line_end) is int
        )

    def exact_task(task: object) -> bool:
        return (
            type(task) is DiscoveryTaskInputV1
            and exact_text(
                task.task_id,
                task.repo_url,
                task.commit,
                task.instruction_id,
                task.snapshot_manifest_sha256,
                task.snapshot_content_root,
                task.snapshot_id,
            )
            and type(task.contract_version) is int
        )

    def exact_candidate(candidate: object) -> bool:
        return (
            type(candidate) is DiscoveryCandidate
            and exact_text(
                candidate.task_id,
                candidate.snapshot_id,
                candidate.repo_url,
                candidate.commit,
                candidate.candidate_id,
            )
            and type(candidate.contract_version) is int
            and exact_location(candidate.entry_point)
            and exact_location(candidate.critical_operation)
            and type(candidate.trace) is tuple
            and all(exact_location(item) for item in candidate.trace)
            and type(candidate.relationship_evidence_refs) is tuple
            and type(candidate.source_evidence_refs) is tuple
            and exact_text(*candidate.relationship_evidence_refs)
            and exact_text(*candidate.source_evidence_refs)
        )

    def exact_review(review: object) -> bool:
        return (
            type(review) is DiscoveryReview
            and exact_text(
                review.task_id,
                review.snapshot_id,
                review.candidate_id,
                review.candidate_sha256,
                review.decision,
            )
            and type(review.contract_version) is int
            and type(review.reason_codes) is tuple
            and exact_text(*review.reason_codes)
        )

    def exact_deferred(deferred: object) -> bool:
        return (
            type(deferred) is DiscoveryDeferred
            and exact_text(
                deferred.task_id,
                deferred.snapshot_id,
                deferred.stage,
                deferred.reason_code,
            )
            and type(deferred.contract_version) is int
            and type(deferred.missing_information) is tuple
            and exact_text(*deferred.missing_information)
        )

    return (
        exact_task(result.task)
        and type(result.status) is str
        and type(result.coverage_status) is str
        and type(result.contract_version) is int
        and type(result.candidates) is tuple
        and type(result.reviews) is tuple
        and all(exact_candidate(item) for item in result.candidates)
        and all(exact_review(item) for item in result.reviews)
        and (
            result.deferred is None
            or exact_deferred(result.deferred)
        )
    )


def project_discovery_result(
    result: DiscoveryTaskResult,
    *,
    max_findings: int = DEFAULT_DISCOVERY_LIMITS.max_candidates_per_task,
) -> tuple[Mapping[str, Any], ...]:
    """Project one fully reviewed task without exposing discovery sidecars.

    Endpoint identity deliberately excludes trace, matching the benchmark
    evaluator.  Equivalent endpoint pairs are emitted once, retaining the
    canonical-minimum trace representation independently of input order.
    """

    if type(result) is not DiscoveryTaskResult:
        raise DiscoveryProjectionError(
            "invalid_result", "result must be a DiscoveryTaskResult"
        )
    if not _has_exact_contract_types(result):
        raise DiscoveryProjectionError(
            "invalid_result", "result contains a polymorphic contract value"
        )
    try:
        canonical_result = DiscoveryTaskResult.from_dict(result.to_dict())
    except (DiscoveryContractError, TypeError, ValueError):
        raise DiscoveryProjectionError(
            "invalid_result", "result did not pass strict contract normalization"
        ) from None
    if (
        type(max_findings) is not int
        or not 0 <= max_findings <= DEFAULT_DISCOVERY_LIMITS.max_candidates_per_task
    ):
        raise DiscoveryProjectionError(
            "invalid_limit", "max_findings must be an integer from 0 through 64"
        )
    if canonical_result.status == "deferred":
        return ()

    unique: dict[str, dict[str, Any]] = {}
    for candidate in canonical_result.emitted_candidates:
        candidate.assert_task(canonical_result.task)
        finding = _finding(candidate)
        identity = _canonical_json(
            {
                "commit": finding["commit"],
                "critical_operation": finding["critical_operation"],
                "entry_point": finding["entry_point"],
                "repo_url": finding["repo_url"],
                "task_id": finding["task_id"],
            }
        ).decode("utf-8")
        previous = unique.get(identity)
        if previous is None or _canonical_json(finding) < _canonical_json(previous):
            unique[identity] = finding

    ordered = tuple(unique[key] for key in sorted(unique))
    if len(ordered) > max_findings:
        raise DiscoveryProjectionError(
            "projection_limit_exceeded",
            "reviewed task emits more findings than the requested limit",
        )
    return tuple(_freeze_json(item) for item in ordered)


__all__ = [
    "DISCOVERY_PROJECTION_ERROR_TAXONOMY_VERSION",
    "DISCOVERY_PROJECTION_VERSION",
    "DiscoveryProjectionError",
    "project_discovery_result",
]
