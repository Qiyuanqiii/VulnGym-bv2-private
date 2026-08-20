"""Safe, read-only access to immutable Git objects."""

from .repository import (
    GitBlobTooLarge,
    GitCommandError,
    GitDiffTooLarge,
    GitFactError,
    GitHistoryIncomplete,
    GitRepository,
    GitTextDecodeError,
    GitTimeoutError,
    InvalidCommitSha,
    InvalidRepositoryPath,
    RepositoryUnavailable,
    TextFileDiff,
    TreeEntry,
    validate_commit_sha,
    validate_repo_relative_path,
)

__all__ = [
    "GitBlobTooLarge",
    "GitCommandError",
    "GitDiffTooLarge",
    "GitFactError",
    "GitHistoryIncomplete",
    "GitRepository",
    "GitTextDecodeError",
    "GitTimeoutError",
    "InvalidCommitSha",
    "InvalidRepositoryPath",
    "RepositoryUnavailable",
    "TextFileDiff",
    "TreeEntry",
    "validate_commit_sha",
    "validate_repo_relative_path",
]
