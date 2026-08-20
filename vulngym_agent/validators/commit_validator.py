"""Deterministic validation for a candidate VulnGym commit field."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Literal

from vulngym_agent.tools.git import (
    GitFactError,
    GitRepository,
    InvalidCommitSha,
    validate_commit_sha,
)


ValidationStatus = Literal["correct", "incorrect", "uncertain"]


@dataclass(frozen=True, slots=True)
class CommitValidationResult:
    """Both the proven object facts and the still-unproven semantic role.

    ``fact_status == "correct"`` means Git proved that the exact SHA exists and
    has type ``commit``.  ``status`` remains ``uncertain`` because that fact
    alone cannot establish that it is the vulnerable (rather than fix or
    unrelated) commit.
    """

    status: ValidationStatus
    fact_status: ValidationStatus
    commit: str | None
    exists: bool | None
    is_commit: bool | None
    object_type: str | None
    semantic_role_verified: bool
    evidence: str
    error_code: str | None = None

    @property
    def deterministic_valid(self) -> bool | None:
        if self.fact_status == "correct":
            return True
        if self.fact_status == "incorrect":
            return False
        return None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class CommitValidator:
    """Validate exact commit object identity without modifying a repository."""

    def __init__(
        self,
        repository: GitRepository | str | os.PathLike[str],
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._repository: GitRepository | None
        self._repository_error: GitFactError | None
        if isinstance(repository, GitRepository):
            self._repository = repository
            self._repository_error = None
        else:
            try:
                self._repository = GitRepository(
                    repository, timeout_seconds=timeout_seconds
                )
                self._repository_error = None
            except GitFactError as error:
                self._repository = None
                self._repository_error = error

    def validate(self, commit: object) -> CommitValidationResult:
        submitted_commit = commit if isinstance(commit, str) else None
        try:
            canonical_commit = validate_commit_sha(commit)
        except InvalidCommitSha as error:
            return CommitValidationResult(
                status="incorrect",
                fact_status="incorrect",
                commit=submitted_commit,
                exists=None,
                is_commit=None,
                object_type=None,
                semantic_role_verified=False,
                evidence=f"Commit syntax is invalid: {error}.",
                error_code="invalid_commit_sha",
            )

        if self._repository is None:
            assert self._repository_error is not None
            return CommitValidationResult(
                status="uncertain",
                fact_status="uncertain",
                commit=canonical_commit,
                exists=None,
                is_commit=None,
                object_type=None,
                semantic_role_verified=False,
                evidence=(
                    "The local repository could not be inspected, so commit "
                    f"existence is unverified: {self._repository_error}."
                ),
                error_code="repository_unavailable",
            )

        try:
            object_type = self._repository.object_type(canonical_commit)
        except GitFactError as error:
            return CommitValidationResult(
                status="uncertain",
                fact_status="uncertain",
                commit=canonical_commit,
                exists=None,
                is_commit=None,
                object_type=None,
                semantic_role_verified=False,
                evidence=f"Git could not inspect commit {canonical_commit}: {error}.",
                error_code="git_read_failed",
            )

        if object_type is None:
            try:
                incomplete_history = self._repository.history_may_be_incomplete()
            except GitFactError as error:
                return CommitValidationResult(
                    status="uncertain",
                    fact_status="uncertain",
                    commit=canonical_commit,
                    exists=None,
                    is_commit=None,
                    object_type=None,
                    semantic_role_verified=False,
                    evidence=(
                        "Git could not determine whether missing local history is "
                        f"complete: {error}."
                    ),
                    error_code="history_completeness_read_failed",
                )
            if incomplete_history:
                return CommitValidationResult(
                    status="uncertain",
                    fact_status="uncertain",
                    commit=canonical_commit,
                    exists=None,
                    is_commit=None,
                    object_type=None,
                    semantic_role_verified=False,
                    evidence=(
                        f"Object {canonical_commit} is absent from the local shallow "
                        "repository, but incomplete history cannot prove that the "
                        "commit is absent from the target repository."
                    ),
                    error_code="commit_missing_from_incomplete_history",
                )
            return CommitValidationResult(
                status="incorrect",
                fact_status="incorrect",
                commit=canonical_commit,
                exists=False,
                is_commit=False,
                object_type=None,
                semantic_role_verified=False,
                evidence=(
                    f"Git cat-file could not find object {canonical_commit} in the "
                    "specified local repository."
                ),
                error_code="commit_not_found",
            )

        if object_type != "commit":
            return CommitValidationResult(
                status="incorrect",
                fact_status="incorrect",
                commit=canonical_commit,
                exists=True,
                is_commit=False,
                object_type=object_type,
                semantic_role_verified=False,
                evidence=(
                    f"Git cat-file found {canonical_commit}, but its object type is "
                    f"{object_type!r}, not 'commit'."
                ),
                error_code="object_is_not_commit",
            )

        return CommitValidationResult(
            status="uncertain",
            fact_status="correct",
            commit=canonical_commit,
            exists=True,
            is_commit=True,
            object_type="commit",
            semantic_role_verified=False,
            evidence=(
                f"Git cat-file proves {canonical_commit} exists and is a commit "
                "object. This check does not prove that it is the vulnerable "
                "commit rather than a fix or unrelated commit."
            ),
        )


def validate_commit(
    repository: GitRepository | str | os.PathLike[str],
    commit: object,
    *,
    timeout_seconds: float = 10.0,
) -> CommitValidationResult:
    """Convenience wrapper around :class:`CommitValidator`."""

    return CommitValidator(
        repository, timeout_seconds=timeout_seconds
    ).validate(commit)
