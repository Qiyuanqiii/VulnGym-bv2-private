"""Closed runtime lane registry shared by model, tool, and audit records."""

from __future__ import annotations

from typing import Final


T2_RUNTIME_SCOPE_PAIRS: Final[frozenset[tuple[int, str]]] = frozenset(
    {
        (0, "t2.initial"),
        (1, "t2.repair-1"),
        (2, "t2.repair-2"),
    }
)
D3_RUNTIME_SCOPE_PAIRS: Final[frozenset[tuple[int, str]]] = frozenset(
    {(0, "d3.review")}
)
RUNTIME_SCOPE_PAIRS: Final[frozenset[tuple[int, str]]] = (
    T2_RUNTIME_SCOPE_PAIRS | D3_RUNTIME_SCOPE_PAIRS
)


def validate_runtime_scope(attempt: object, policy_scope: object) -> tuple[int, str]:
    """Return one exact allowlisted pair or raise a stable ``ValueError``."""

    if (
        type(attempt) is not int
        or type(policy_scope) is not str
        or (attempt, policy_scope) not in RUNTIME_SCOPE_PAIRS
    ):
        raise ValueError("policy_scope does not match attempt")
    return attempt, policy_scope


def is_t2_runtime_scope(attempt: object, policy_scope: object) -> bool:
    """Whether a value is one exact legacy T2 lane pair."""

    return (
        type(attempt) is int
        and type(policy_scope) is str
        and (attempt, policy_scope) in T2_RUNTIME_SCOPE_PAIRS
    )


__all__ = [
    "D3_RUNTIME_SCOPE_PAIRS",
    "RUNTIME_SCOPE_PAIRS",
    "T2_RUNTIME_SCOPE_PAIRS",
    "is_t2_runtime_scope",
    "validate_runtime_scope",
]
