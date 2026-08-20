"""Offline validation of a candidate-to-fix commit transition."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Literal

from vulngym_agent.tools.git.repository import (
    GitDiffTooLarge,
    GitFactError,
    GitHistoryIncomplete,
    GitRepository,
    GitTextDecodeError,
    InvalidCommitSha,
    InvalidRepositoryPath,
    TextFileDiff,
    validate_commit_sha,
    validate_repo_relative_path,
)


ValidationStatus = Literal["correct", "incorrect", "uncertain"]


@dataclass(frozen=True, slots=True)
class CommitTransitionValidationResult:
    """Topology/patch facts and their deliberately conservative conclusion."""

    status: ValidationStatus
    fact_status: ValidationStatus
    candidate_commit: str | None
    fix_commit: str | None
    candidate_is_ancestor: bool | None
    candidate_is_direct_parent: bool | None
    path: str | None
    file_changed: bool | None
    before_blob_id: str | None
    after_blob_id: str | None
    added_lines: int | None
    deleted_lines: int | None
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


class CommitTransitionValidator:
    """Check local history facts without inferring vulnerability semantics.

    ``fix_commit`` is treated as caller-supplied context, not as a fact proved
    by this validator.  A direct-parent relation and a changed source path are
    strong transition facts, but they still cannot establish that the older
    commit is vulnerable or that the newer commit fixes the vulnerability.
    """

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

    def validate(
        self,
        candidate_commit: object,
        fix_commit: object,
        *,
        path: object | None = None,
    ) -> CommitTransitionValidationResult:
        candidate_text = candidate_commit if isinstance(candidate_commit, str) else None
        fix_text = fix_commit if isinstance(fix_commit, str) else None
        try:
            candidate = validate_commit_sha(candidate_commit)
        except InvalidCommitSha as error:
            return self._result(
                "incorrect",
                "incorrect",
                candidate_text,
                fix_text,
                evidence=f"Candidate commit syntax is invalid: {error}.",
                error_code="invalid_candidate_commit_sha",
            )
        try:
            fix = validate_commit_sha(fix_commit)
        except InvalidCommitSha as error:
            return self._result(
                "incorrect",
                "incorrect",
                candidate,
                fix_text,
                evidence=f"Fix commit syntax is invalid: {error}.",
                error_code="invalid_fix_commit_sha",
            )

        canonical_path: str | None = None
        if path is not None:
            try:
                canonical_path = validate_repo_relative_path(path)
            except InvalidRepositoryPath as error:
                return self._result(
                    "incorrect",
                    "incorrect",
                    candidate,
                    fix,
                    path=path if isinstance(path, str) else None,
                    evidence=f"Diff path is invalid: {error}.",
                    error_code="invalid_diff_path",
                )

        if candidate == fix:
            return self._result(
                "incorrect",
                "incorrect",
                candidate,
                fix,
                candidate_is_direct_parent=False,
                path=canonical_path,
                evidence=(
                    "Candidate and fix are the same commit. Git regards a commit "
                    "as its own ancestor, but it cannot be an earlier vulnerable "
                    "snapshot in this transition claim."
                ),
                error_code="candidate_equals_fix",
            )

        if self._repository is None:
            assert self._repository_error is not None
            return self._result(
                "uncertain",
                "uncertain",
                candidate,
                fix,
                path=canonical_path,
                evidence=(
                    "The local repository could not be inspected, so commit "
                    f"history is unverified: {self._repository_error}."
                ),
                error_code="repository_unavailable",
            )

        try:
            candidate_type = self._repository.object_type(candidate)
            fix_type = self._repository.object_type(fix)
        except GitFactError as error:
            return self._result(
                "uncertain",
                "uncertain",
                candidate,
                fix,
                path=canonical_path,
                evidence=f"Git could not inspect transition endpoints: {error}.",
                error_code="git_read_failed",
            )
        for role, commit, object_type in (
            ("candidate", candidate, candidate_type),
            ("fix", fix, fix_type),
        ):
            if object_type is None:
                try:
                    incomplete_history = self._repository.history_may_be_incomplete()
                except GitFactError as error:
                    return self._result(
                        "uncertain",
                        "uncertain",
                        candidate,
                        fix,
                        path=canonical_path,
                        evidence=(
                            "Git could not determine whether the local history is "
                            f"complete while checking the {role} endpoint: {error}."
                        ),
                        error_code="history_completeness_read_failed",
                    )
                if incomplete_history:
                    return self._result(
                        "uncertain",
                        "uncertain",
                        candidate,
                        fix,
                        path=canonical_path,
                        evidence=(
                            f"The {role} endpoint {commit} is absent from the local "
                            "shallow repository, but incomplete history cannot prove "
                            "that it is absent from the target repository."
                        ),
                        error_code=f"{role}_missing_from_incomplete_history",
                    )
            if object_type != "commit":
                detail = "absent" if object_type is None else f"type {object_type!r}"
                return self._result(
                    "incorrect",
                    "incorrect",
                    candidate,
                    fix,
                    path=canonical_path,
                    evidence=(
                        f"The {role} endpoint {commit} is not a commit object "
                        f"in the local repository ({detail})."
                    ),
                    error_code=f"{role}_commit_not_found_or_not_commit",
                )

        try:
            fix_parents = self._repository.commit_parents(fix)
            direct_parent = candidate in fix_parents
            ancestor = direct_parent or self._repository.is_ancestor(candidate, fix)
        except GitHistoryIncomplete as error:
            return self._result(
                "uncertain",
                "uncertain",
                candidate,
                fix,
                path=canonical_path,
                evidence=(
                    "The local repository has incomplete shallow history, so "
                    f"negative ancestry cannot be proven: {error}."
                ),
                error_code="history_incomplete",
            )
        except GitFactError as error:
            return self._result(
                "uncertain",
                "uncertain",
                candidate,
                fix,
                path=canonical_path,
                evidence=f"Git could not inspect commit ancestry: {error}.",
                error_code="history_read_failed",
            )

        if not ancestor:
            return self._result(
                "incorrect",
                "incorrect",
                candidate,
                fix,
                candidate_is_ancestor=False,
                candidate_is_direct_parent=False,
                path=canonical_path,
                evidence=(
                    f"Git proves candidate {candidate} is not an ancestor of the "
                    f"caller-supplied fix {fix}."
                ),
                error_code="candidate_not_ancestor_of_fix",
            )

        file_diff: TextFileDiff | None = None
        if canonical_path is not None:
            try:
                file_diff = self._repository.diff_text_file(
                    candidate, fix, canonical_path
                )
            except (GitTextDecodeError, GitDiffTooLarge, GitFactError) as error:
                return self._result(
                    "uncertain",
                    "uncertain",
                    candidate,
                    fix,
                    candidate_is_ancestor=True,
                    candidate_is_direct_parent=direct_parent,
                    path=canonical_path,
                    evidence=(
                        "Git proved the ancestry relation, but the requested "
                        f"source diff could not be verified: {error}."
                    ),
                    error_code="diff_read_failed",
                )
            if not file_diff.changed:
                return self._result(
                    "incorrect",
                    "incorrect",
                    candidate,
                    fix,
                    candidate_is_ancestor=True,
                    candidate_is_direct_parent=direct_parent,
                    path=canonical_path,
                    file_diff=file_diff,
                    evidence=(
                        f"Git proves {canonical_path} has the same blob at the "
                        "candidate and caller-supplied fix commits, contradicting "
                        "the requested changed-path transition fact."
                    ),
                    error_code="path_unchanged",
                )

        relation = "is a direct parent of" if direct_parent else "is an ancestor of"
        patch_fact = (
            f" The exact path {canonical_path} changed by "
            f"+{file_diff.added_lines}/-{file_diff.deleted_lines} lines."
            if file_diff is not None
            else ""
        )
        return self._result(
            "uncertain",
            "correct",
            candidate,
            fix,
            candidate_is_ancestor=True,
            candidate_is_direct_parent=direct_parent,
            path=canonical_path,
            file_diff=file_diff,
            evidence=(
                f"Git proves candidate {candidate} {relation} the caller-supplied "
                f"fix {fix}.{patch_fact} These topology and patch facts do not "
                "prove either commit's vulnerability semantic role."
            ),
        )

    @staticmethod
    def _result(
        status: ValidationStatus,
        fact_status: ValidationStatus,
        candidate_commit: str | None,
        fix_commit: str | None,
        *,
        candidate_is_ancestor: bool | None = None,
        candidate_is_direct_parent: bool | None = None,
        path: str | None = None,
        file_diff: TextFileDiff | None = None,
        evidence: str,
        error_code: str | None = None,
    ) -> CommitTransitionValidationResult:
        return CommitTransitionValidationResult(
            status=status,
            fact_status=fact_status,
            candidate_commit=candidate_commit,
            fix_commit=fix_commit,
            candidate_is_ancestor=candidate_is_ancestor,
            candidate_is_direct_parent=candidate_is_direct_parent,
            path=path,
            file_changed=file_diff.changed if file_diff is not None else None,
            before_blob_id=(
                file_diff.before_blob_id if file_diff is not None else None
            ),
            after_blob_id=(
                file_diff.after_blob_id if file_diff is not None else None
            ),
            added_lines=file_diff.added_lines if file_diff is not None else None,
            deleted_lines=(
                file_diff.deleted_lines if file_diff is not None else None
            ),
            semantic_role_verified=False,
            evidence=evidence,
            error_code=error_code,
        )


def validate_commit_transition(
    repository: GitRepository | str | os.PathLike[str],
    candidate_commit: object,
    fix_commit: object,
    *,
    path: object | None = None,
    timeout_seconds: float = 10.0,
) -> CommitTransitionValidationResult:
    """Convenience wrapper around :class:`CommitTransitionValidator`."""

    return CommitTransitionValidator(
        repository, timeout_seconds=timeout_seconds
    ).validate(candidate_commit, fix_commit, path=path)
