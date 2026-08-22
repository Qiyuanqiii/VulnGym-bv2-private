"""Bounded projection from reviewed discovery candidates to evaluator findings."""

from __future__ import annotations

import hashlib
import json
from types import MappingProxyType
from typing import Any, Final, Mapping

from .discovery_contracts import (
    DEFAULT_DISCOVERY_LIMITS,
    DiscoveryCandidate,
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

    if not isinstance(result, DiscoveryTaskResult):
        raise DiscoveryProjectionError(
            "invalid_result", "result must be a DiscoveryTaskResult"
        )
    if (
        type(max_findings) is not int
        or not 0 <= max_findings <= DEFAULT_DISCOVERY_LIMITS.max_candidates_per_task
    ):
        raise DiscoveryProjectionError(
            "invalid_limit", "max_findings must be an integer from 0 through 64"
        )
    if result.status == "deferred":
        return ()

    unique: dict[str, dict[str, Any]] = {}
    for candidate in result.emitted_candidates:
        candidate.assert_task(result.task)
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
