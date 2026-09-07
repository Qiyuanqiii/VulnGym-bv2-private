"""Bounded old-side location nominations for new T2 production.

This is a recall-oriented review pool, not a sink/guard classifier. The requested
mode is only a hypothesis. Every nomination must still pass the existing Git,
transition, diff-side and exact-location checks before semantic review.
"""
from __future__ import annotations

from vulngym_agent.analyzers.patch_analyzer import PatchAnalysis
from vulngym_agent.resolvers.critical_resolver import CriticalPatchCandidate

REVIEW_POOL_POLICY = "old-side-review-pool-v1"


class ReviewPoolLimitError(ValueError):
    """The whole declared candidate pool cannot fit; do not silently prune it."""


def old_side_review_pool(
    analysis: PatchAnalysis, mode: str, *, max_candidates: int = 128,
    max_code_chars: int = 2000,
) -> tuple[CriticalPatchCandidate, ...]:
    if type(analysis) is not PatchAnalysis or mode not in {"sink", "guard"}:
        raise ValueError("invalid_review_pool_input")
    if (type(max_candidates) is not int or not 1 <= max_candidates <= 128
            or type(max_code_chars) is not int or not 1 <= max_code_chars <= 2000):
        raise ValueError("invalid_review_pool_limits")
    if analysis.conflicts:
        raise ValueError("conflicting_patch_not_a_review_pool")
    candidates = [CriticalPatchCandidate(
        c.candidate_id, c.mode, c.file, c.change_kind, c.old_line, c.new_line, c.code, c.reason,
    ) for c in analysis.candidates]
    if len(candidates) > max_candidates:
        raise ReviewPoolLimitError("review_pool_candidate_limit")
    # Preserve old lexical IDs/order. Do not duplicate an already nominated
    # removed line for this hypothesis; a different mode is not a duplicate.
    aliases = {"sink", "dangerous_call"} if mode == "sink" else {"guard", "early_return"}
    seen = {(c.file, c.old_line, c.code) for c in candidates
            if c.change_kind == "removed" and c.mode in aliases}
    added = 0
    for changed in analysis.files:
        if changed.binary or changed.old_path is None:
            continue
        for hunk in changed.hunks:
            for line in hunk.lines:
                if line.change_kind != "removed" or line.old_line is None or not line.code.strip():
                    continue
                identity = (changed.old_path, line.old_line, line.code)
                if identity in seen:
                    continue
                if len(line.code) > max_code_chars:
                    raise ReviewPoolLimitError("review_pool_line_limit")
                if len(candidates) >= max_candidates:
                    raise ReviewPoolLimitError("review_pool_candidate_limit")
                seen.add(identity)
                added += 1
                candidates.append(CriticalPatchCandidate(
                    candidate_id=f"review-old-{added:06d}", mode=mode, file=changed.old_path,
                    change_kind="removed", old_line=line.old_line, new_line=None, code=line.code,
                    reason="Old-side changed-line nomination; requested mode is an unverified hypothesis, not a semantic classification.",
                ))
    return tuple(candidates)
