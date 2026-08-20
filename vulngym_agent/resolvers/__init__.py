"""Conservative candidate resolvers for VulnGym fields."""

from .critical_resolver import (
    CandidateContractError,
    CriticalCandidateAssessment,
    CriticalLocation,
    CriticalOperationResolver,
    CriticalPatchCandidate,
    CriticalResolutionResult,
    PatchAnalysisProtocol,
    PatchCandidateProtocol,
    resolve_critical_operation,
)

__all__ = [
    "CandidateContractError",
    "CriticalCandidateAssessment",
    "CriticalLocation",
    "CriticalOperationResolver",
    "CriticalPatchCandidate",
    "CriticalResolutionResult",
    "PatchAnalysisProtocol",
    "PatchCandidateProtocol",
    "resolve_critical_operation",
]
