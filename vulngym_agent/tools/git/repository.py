"""Small, defensive wrappers around read-only Git object commands.

The wrapper deliberately does not expose an arbitrary-command escape hatch.  It
uses immutable object reads only and never checks out, fetches, runs hooks, or
executes code from the inspected repository.
"""

from __future__ import annotations

import hashlib
import ntpath
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from difflib import unified_diff
from pathlib import Path
from typing import Final, Sequence


_SHA_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}\Z")
_MAX_ERROR_CHARS: Final[int] = 2_000
DEFAULT_MAX_BLOB_BYTES: Final[int] = 8 * 1024 * 1024
DEFAULT_MAX_COMMIT_BYTES: Final[int] = 1024 * 1024
DEFAULT_MAX_TREE_BYTES: Final[int] = 8 * 1024 * 1024
DEFAULT_MAX_TREE_ENTRIES: Final[int] = 100_000
MAX_TREE_DEPTH: Final[int] = 256
DEFAULT_MAX_DIFF_INPUT_BYTES: Final[int] = 2 * 1024 * 1024
DEFAULT_MAX_DIFF_OUTPUT_BYTES: Final[int] = 2 * 1024 * 1024
DEFAULT_MAX_DIFF_LINES: Final[int] = 10_000
MAX_DIFF_CONTEXT_LINES: Final[int] = 100
MAX_STORAGE_SCAN_ENTRIES: Final[int] = 1_000_000
_PROMISOR_CONFIG_RE: Final[re.Pattern[str]] = re.compile(
    r"remote\..+\.promisor\Z", re.IGNORECASE
)


class GitFactError(RuntimeError):
    """Base class for failures while reading deterministic Git facts."""


class InvalidCommitSha(ValueError, GitFactError):
    """The caller supplied something other than a canonical full SHA-1."""


class InvalidRepositoryPath(ValueError, GitFactError):
    """A repository-relative path is unsafe or non-canonical."""


class RepositoryUnavailable(GitFactError):
    """The requested directory cannot be inspected as a Git repository."""


class GitTimeoutError(GitFactError):
    """A bounded read-only Git operation exceeded its timeout."""


class GitBlobTooLarge(GitFactError):
    """A blob exceeds the configured source-read size limit."""


class GitDiffTooLarge(GitFactError):
    """A generated text diff exceeds the deterministic output limit."""


class GitTextDecodeError(GitFactError):
    """A source blob is not valid UTF-8 text."""


class GitCommandError(GitFactError):
    """A fixed read-only Git command failed unexpectedly."""

    def __init__(self, operation: str, returncode: int, stderr: str) -> None:
        self.operation = operation
        self.returncode = returncode
        self.stderr = stderr[:_MAX_ERROR_CHARS]
        detail = self.stderr.strip() or "no diagnostic output"
        super().__init__(f"git {operation} failed ({returncode}): {detail}")


class GitHistoryIncomplete(GitFactError):
    """A negative history result is inconclusive because history is shallow."""


@dataclass(frozen=True, slots=True)
class TreeEntry:
    """One exact entry from a commit tree."""

    mode: str
    object_type: str
    object_id: str
    path: str

    @property
    def is_blob(self) -> bool:
        return self.object_type == "blob"


@dataclass(frozen=True, slots=True)
class TextFileDiff:
    """A bounded, in-process text diff between two immutable commit trees."""

    before_commit: str
    after_commit: str
    path: str
    before_exists: bool
    after_exists: bool
    before_blob_id: str | None
    after_blob_id: str | None
    added_lines: int
    deleted_lines: int
    unified_diff: str

    @property
    def changed(self) -> bool:
        return self.before_blob_id != self.after_blob_id


def validate_commit_sha(commit: object) -> str:
    """Return *commit* if it is exactly 40 lowercase hexadecimal characters."""

    if not isinstance(commit, str) or _SHA_RE.fullmatch(commit) is None:
        raise InvalidCommitSha(
            "commit must be exactly 40 lowercase hexadecimal characters"
        )
    return commit


def validate_repo_relative_path(path: object) -> str:
    """Validate a canonical Git tree path and reject path/option injection.

    Git tree paths use forward slashes on every host.  Requiring the canonical
    spelling also makes exact path evidence stable across Windows and POSIX.
    """

    if not isinstance(path, str) or not path:
        raise InvalidRepositoryPath("file path must be a non-empty string")
    if "\x00" in path:
        raise InvalidRepositoryPath("file path must not contain NUL")
    if any(ord(character) < 32 for character in path):
        raise InvalidRepositoryPath("file path must not contain control characters")
    if "\\" in path:
        raise InvalidRepositoryPath(
            "file path must use repository-style forward slashes"
        )
    drive, _ = ntpath.splitdrive(path)
    if path.startswith(("/", "-", ":")) or drive or ntpath.isabs(path):
        raise InvalidRepositoryPath(
            "file path must be repository-relative and must not look like an option"
        )

    components = path.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise InvalidRepositoryPath(
            "file path must be canonical and must not contain '.', '..', or empty segments"
        )
    return path


def _find_git_executable(disallowed_root: Path) -> str:
    """Find Git only in absolute PATH entries outside the target repository."""

    executable_names = ("git.exe",) if os.name == "nt" else ("git",)
    search_path = os.environ.get("PATH") or os.defpath
    for raw_directory in search_path.split(os.pathsep):
        if not raw_directory:
            continue
        directory = Path(raw_directory).expanduser()
        if not directory.is_absolute():
            continue
        for executable_name in executable_names:
            candidate = directory / executable_name
            try:
                resolved = candidate.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if not resolved.is_file() or not os.access(resolved, os.X_OK):
                continue
            try:
                resolved.relative_to(disallowed_root)
            except ValueError:
                return str(resolved)
    raise RepositoryUnavailable(
        "git executable was not found in an absolute PATH directory outside "
        "the target repository"
    )


def _diagnostic_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")[:_MAX_ERROR_CHARS]


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_reparse(result: os.stat_result) -> bool:
    attributes = getattr(result, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


class GitRepository:
    """Read immutable facts from one local Git repository.

    All subprocess calls use argument arrays with fixed command shapes.  The
    target repository is never used as a subprocess working directory, so a
    repository-local executable named ``git`` cannot take precedence.
    """

    def __init__(
        self,
        repo_path: str | os.PathLike[str],
        *,
        timeout_seconds: float = 10.0,
        max_blob_bytes: int = DEFAULT_MAX_BLOB_BYTES,
        max_diff_input_bytes: int = DEFAULT_MAX_DIFF_INPUT_BYTES,
        max_diff_output_bytes: int = DEFAULT_MAX_DIFF_OUTPUT_BYTES,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")
        if (
            isinstance(max_blob_bytes, bool)
            or not isinstance(max_blob_bytes, int)
            or max_blob_bytes < 0
        ):
            raise ValueError("max_blob_bytes must be a non-negative integer")
        if (
            isinstance(max_diff_input_bytes, bool)
            or not isinstance(max_diff_input_bytes, int)
            or max_diff_input_bytes < 0
        ):
            raise ValueError(
                "max_diff_input_bytes must be a non-negative integer"
            )
        if (
            isinstance(max_diff_output_bytes, bool)
            or not isinstance(max_diff_output_bytes, int)
            or max_diff_output_bytes < 0
        ):
            raise ValueError(
                "max_diff_output_bytes must be a non-negative integer"
            )

        try:
            resolved = Path(repo_path).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, TypeError) as error:
            raise RepositoryUnavailable(
                f"repository path cannot be resolved: {repo_path!r}"
            ) from error
        if not resolved.is_dir():
            raise RepositoryUnavailable(f"repository path is not a directory: {resolved}")
        dot_git = resolved / ".git"
        try:
            dot_git_state = os.lstat(dot_git)
        except FileNotFoundError:
            dot_git_state = None
        except OSError as error:
            raise RepositoryUnavailable("repository metadata cannot be inspected") from error
        if dot_git_state is not None and (
            stat.S_ISLNK(dot_git_state.st_mode) or _is_reparse(dot_git_state)
        ):
            raise RepositoryUnavailable(
                "repository metadata must not be a link or reparse point"
            )
        if dot_git.is_file():
            raise RepositoryUnavailable(
                "linked worktrees and submodules with an external gitdir are not "
                "accepted by the read-only fact gate"
            )
        is_worktree_root = dot_git.is_dir()
        is_bare_root = (resolved / "HEAD").is_file() and (resolved / "objects").is_dir()
        if not is_worktree_root and not is_bare_root:
            raise RepositoryUnavailable(
                "repository path must identify a worktree or bare repository root: "
                f"{resolved}"
            )

        try:
            git_directory = (dot_git if is_worktree_root else resolved).resolve(strict=True)
            raw_object_directory = git_directory / "objects"
            raw_object_state = os.lstat(raw_object_directory)
            if stat.S_ISLNK(raw_object_state.st_mode) or _is_reparse(raw_object_state):
                raise RepositoryUnavailable(
                    "Git object storage must not be a link or reparse point"
                )
            object_directory = raw_object_directory.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise RepositoryUnavailable(
                "repository metadata/object directory cannot be resolved"
            ) from error
        if not _is_within(git_directory, resolved) or not _is_within(
            object_directory, git_directory
        ):
            raise RepositoryUnavailable(
                "repository metadata and object storage must remain inside the "
                "authorized repository root"
            )
        common_directory_file = git_directory / "commondir"
        if common_directory_file.exists() or common_directory_file.is_symlink():
            raise RepositoryUnavailable(
                "Git common-directory indirection is not allowed by the "
                f"read-only boundary: {common_directory_file}"
            )
        for alternate_name in ("alternates", "http-alternates"):
            alternate_file = object_directory / "info" / alternate_name
            if alternate_file.exists() or alternate_file.is_symlink():
                raise RepositoryUnavailable(
                    "Git alternate object databases are not allowed by the "
                    f"read-only boundary: {alternate_file}"
                )
        grafts_file = git_directory / "info" / "grafts"
        if grafts_file.exists() or grafts_file.is_symlink():
            raise RepositoryUnavailable(
                "Git graft history overrides are not allowed by the read-only "
                f"fact boundary: {grafts_file}"
            )

        self.path = resolved
        self.git_directory = git_directory
        self.object_directory = object_directory
        try:
            git_state = os.stat(git_directory)
            object_state = os.stat(object_directory)
        except OSError as error:
            raise RepositoryUnavailable(
                "repository metadata/object storage cannot be inspected"
            ) from error
        self._git_directory_identity = (git_state.st_dev, git_state.st_ino)
        self._object_directory_identity = (object_state.st_dev, object_state.st_ino)
        self.timeout_seconds = float(timeout_seconds)
        self.max_blob_bytes = max_blob_bytes
        self.max_diff_input_bytes = max_diff_input_bytes
        self.max_diff_output_bytes = max_diff_output_bytes
        self._git_executable = _find_git_executable(resolved)
        self._subprocess_directory = str(Path(self._git_executable).parent)
        self._assert_repository()
        self._assert_history_storage()

    def _environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        # Prevent ambient Git variables from redirecting the object database,
        # repository, config source, trace output, or helper executable path.
        for key in tuple(environment):
            if key.startswith("GIT_"):
                environment.pop(key)
        environment.update(
            {
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_EXTERNAL_DIFF": "",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_PAGER": "cat",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        return environment

    def _base_command(self) -> tuple[str, ...]:
        return (
            self._git_executable,
            "--no-pager",
            "--literal-pathspecs",
            "-c",
            "core.commitGraph=false",
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-C",
            str(self.path),
        )

    def _run(
        self,
        arguments: Sequence[str],
        *,
        operation: str,
        check: bool = True,
        input_data: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        command = (*self._base_command(), *arguments)
        try:
            result = subprocess.run(
                command,
                input=input_data,
                stdin=subprocess.DEVNULL if input_data is None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                cwd=self._subprocess_directory,
                env=self._environment(),
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            raise GitTimeoutError(
                f"git {operation} exceeded {self.timeout_seconds:g} seconds"
            ) from error
        except OSError as error:
            raise RepositoryUnavailable(f"could not start git: {error}") from error

        if check and result.returncode != 0:
            raise GitCommandError(
                operation,
                result.returncode,
                _diagnostic_text(result.stderr),
            )
        return result

    def _assert_repository(self) -> None:
        result = self._run(
            ("rev-list", "--max-count=0", "--all"),
            operation="rev-list",
            check=False,
        )
        if result.returncode != 0:
            detail = _diagnostic_text(result.stderr).strip()
            raise RepositoryUnavailable(
                f"not an inspectable Git repository: {self.path}"
                + (f" ({detail})" if detail else "")
            )

    def _assert_history_storage(self) -> None:
        """Reject local configuration that can redirect object reads."""

        result = self._run(
            (
                "config",
                "--no-includes",
                "--local",
                "--get-regexp",
                r"^extensions\.objectformat$|^extensions\.worktreeconfig$|"
                r"^core\.repositoryformatversion$|^remote\..*\.promisor$|"
                r"^extensions\.partialclone$",
            ),
            operation="config",
            check=False,
        )
        if result.returncode == 1 and not result.stdout and not result.stderr:
            return
        if result.returncode != 0 or result.stderr:
            raise RepositoryUnavailable(
                "local Git storage configuration could not be inspected: "
                + _diagnostic_text(result.stderr or result.stdout).strip()
            )
        try:
            records = result.stdout.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError as error:
            raise RepositoryUnavailable(
                "local Git storage configuration is not valid UTF-8"
            ) from error
        for record in records:
            key, separator, value = record.partition(" ")
            if not separator:
                raise RepositoryUnavailable(
                    "local Git storage configuration is malformed"
                )
            lowered_key = key.casefold()
            lowered_value = value.strip().casefold()
            if lowered_key == "extensions.objectformat":
                if lowered_value != "sha1":
                    raise RepositoryUnavailable(
                        "only SHA-1 object-format repositories are supported"
                    )
            elif lowered_key == "extensions.worktreeconfig":
                if lowered_value in {"true", "yes", "on", "1"}:
                    raise RepositoryUnavailable(
                        "worktree-specific configuration is not accepted by the "
                        "read-only fact gate"
                    )
            elif lowered_key == "core.repositoryformatversion":
                if lowered_value not in {"0", "1"}:
                    raise RepositoryUnavailable(
                        "unsupported Git repository format version"
                    )
            elif (
                lowered_key == "extensions.partialclone"
                or _PROMISOR_CONFIG_RE.fullmatch(lowered_key) is not None
            ):
                raise RepositoryUnavailable(
                    "partial/promisor repositories are not accepted by the "
                    "offline read-only fact gate"
                )

    def assert_storage_safe(self) -> None:
        """Re-check the local object-store containment and redirection policy.

        Snapshot preparation calls this both before and after a raw object
        traversal.  It detects metadata-directory replacement and storage
        redirections introduced after this wrapper was constructed.
        """

        for path, expected in (
            (self.git_directory, self._git_directory_identity),
            (self.object_directory, self._object_directory_identity),
        ):
            try:
                state = os.lstat(path)
            except OSError as error:
                raise RepositoryUnavailable(
                    "repository metadata/object storage changed"
                ) from error
            if (
                not stat.S_ISDIR(state.st_mode)
                or stat.S_ISLNK(state.st_mode)
                or _is_reparse(state)
                or (state.st_dev, state.st_ino) != expected
            ):
                raise RepositoryUnavailable(
                    "repository metadata/object storage changed"
                )
        markers = (
            self.git_directory / "commondir",
            self.object_directory / "info" / "alternates",
            self.object_directory / "info" / "http-alternates",
            self.git_directory / "info" / "grafts",
        )
        for marker in markers:
            try:
                os.lstat(marker)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise RepositoryUnavailable(
                    "Git storage redirection state cannot be inspected"
                ) from error
            raise RepositoryUnavailable(
                "Git storage redirection appeared after repository validation"
            )
        pending = [self.object_directory]
        scanned = 0
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as iterator:
                    for entry in iterator:
                        scanned += 1
                        if scanned > MAX_STORAGE_SCAN_ENTRIES:
                            raise RepositoryUnavailable(
                                "Git object storage exceeds the metadata scan limit"
                            )
                        try:
                            # Direct lstat is required on Windows: directory
                            # enumeration may report a zero/one link count for
                            # a hard-linked file even when the path itself has
                            # multiple names.
                            state = os.lstat(entry.path)
                        except OSError as error:
                            raise RepositoryUnavailable(
                                "Git object storage changed during scanning"
                            ) from error
                        if entry.is_symlink() or _is_reparse(state):
                            raise RepositoryUnavailable(
                                "Git object storage must not contain links or reparse points"
                            )
                        if stat.S_ISDIR(state.st_mode):
                            pending.append(Path(entry.path))
                        elif not stat.S_ISREG(state.st_mode) or state.st_nlink > 1:
                            raise RepositoryUnavailable(
                                "Git object storage contains an unsafe object file"
                            )
            except OSError as error:
                raise RepositoryUnavailable(
                    "Git object storage cannot be scanned safely"
                ) from error
        self._assert_history_storage()

    def _read_object_bytes(
        self,
        object_id: object,
        *,
        expected_type: str,
        max_bytes: int,
        operation: str,
    ) -> bytes:
        object_id = validate_commit_sha(object_id)
        if expected_type not in {"blob", "commit", "tree"}:
            raise ValueError("expected_type is not a supported raw Git object type")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes < 0
        ):
            raise ValueError("max_bytes must be a non-negative integer")
        object_type = self.object_type(object_id)
        if object_type != expected_type:
            detail = (
                "object is absent"
                if object_type is None
                else f"object has type {object_type!r}"
            )
            raise GitCommandError(
                operation,
                128,
                f"{object_id} is not a {expected_type}: {detail}",
            )
        size_result = self._run(
            ("cat-file", "-s", object_id), operation=operation
        )
        try:
            object_size = int(size_result.stdout.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise GitCommandError(
                operation, 0, "git returned an invalid object size"
            ) from error
        if object_size < 0:
            raise GitCommandError(operation, 0, "git returned a negative object size")
        if object_size > max_bytes:
            raise GitBlobTooLarge(
                f"{expected_type} object is {object_size} bytes; limit is {max_bytes}"
            )
        value_result = self._run(
            ("cat-file", expected_type, object_id), operation=operation
        )
        data = value_result.stdout
        if len(data) != object_size:
            raise GitCommandError(operation, 0, "Git object size changed while reading")
        header = f"{expected_type} {len(data)}\0".encode("ascii")
        actual_id = hashlib.sha1(header + data, usedforsecurity=False).hexdigest()
        if actual_id != object_id:
            raise GitCommandError(
                operation, 0, "Git object content does not match its object ID"
            )
        return data

    def commit_tree(self, commit: object) -> str:
        """Return the unique root-tree ID from one exact raw commit object."""

        canonical_commit = self._require_commit(commit, operation="cat-file")
        data = self._read_object_bytes(
            canonical_commit,
            expected_type="commit",
            max_bytes=DEFAULT_MAX_COMMIT_BYTES,
            operation="cat-file",
        )
        header, separator, _ = data.partition(b"\n\n")
        if not separator:
            raise GitCommandError(
                "cat-file", 0, "commit object has no header terminator"
            )
        tree_lines = [
            line[5:] for line in header.splitlines() if line.startswith(b"tree ")
        ]
        if len(tree_lines) != 1:
            raise GitCommandError(
                "cat-file", 0, "commit object must contain exactly one tree header"
            )
        try:
            return validate_commit_sha(tree_lines[0].decode("ascii"))
        except (UnicodeDecodeError, InvalidCommitSha) as error:
            raise GitCommandError(
                "cat-file", 0, "commit object contains an invalid tree ID"
            ) from error

    @staticmethod
    def _parse_raw_tree(data: bytes) -> tuple[tuple[str, str, str, bytes], ...]:
        records: list[tuple[str, str, str, bytes]] = []
        seen_names: set[bytes] = set()
        position = 0
        while position < len(data):
            space = data.find(b" ", position)
            nul = data.find(b"\0", space + 1) if space >= 0 else -1
            if space <= position or nul <= space + 1 or nul + 21 > len(data):
                raise GitCommandError("cat-file", 0, "Git tree object is malformed")
            raw_mode = data[position:space]
            raw_name = data[space + 1 : nul]
            raw_object_id = data[nul + 1 : nul + 21]
            position = nul + 21
            try:
                mode = raw_mode.decode("ascii")
            except UnicodeDecodeError as error:
                raise GitCommandError(
                    "cat-file", 0, "Git tree mode is not ASCII"
                ) from error
            if mode not in {"40000", "100644", "100755", "120000", "160000"}:
                raise GitCommandError("cat-file", 0, "Git tree mode is unsupported")
            if not raw_name or b"/" in raw_name or raw_name in seen_names:
                raise GitCommandError("cat-file", 0, "Git tree entry name is invalid")
            seen_names.add(raw_name)
            object_type = (
                "tree"
                if mode == "40000"
                else "commit"
                if mode == "160000"
                else "blob"
            )
            records.append((mode, object_type, raw_object_id.hex(), raw_name))
        return tuple(records)

    def list_tree_entries(
        self,
        commit: object,
        *,
        max_entries: int = DEFAULT_MAX_TREE_ENTRIES,
        max_output_bytes: int = DEFAULT_MAX_TREE_BYTES,
        include_trees: bool = False,
    ) -> tuple[TreeEntry, ...]:
        """Return bounded entries from one exact commit's raw tree.

        Tree objects are read one at a time after a size check, so an enormous
        ``ls-tree`` response is never accumulated.  ``max_entries`` counts
        both directory and leaf nodes even when directory entries are omitted
        from the result.  Reused tree objects are parsed once but every path
        occurrence still consumes that node budget.
        """

        for name, value in (
            ("max_entries", max_entries),
            ("max_output_bytes", max_output_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if not isinstance(include_trees, bool):
            raise ValueError("include_trees must be a boolean")
        root_tree = self.commit_tree(commit)
        remaining = max_output_bytes
        output: list[TreeEntry] = []
        seen_paths: set[bytes] = set()
        tree_cache: dict[str, tuple[tuple[str, str, str, bytes], ...]] = {}
        entry_count = 0

        def walk(
            tree_id: str,
            prefix: bytes,
            depth: int,
            ancestors: frozenset[str],
        ) -> None:
            nonlocal remaining, entry_count
            if depth > MAX_TREE_DEPTH:
                raise GitBlobTooLarge(
                    f"Git tree nesting exceeds the limit of {MAX_TREE_DEPTH}"
                )
            if tree_id in ancestors:
                raise GitCommandError("cat-file", 0, "Git tree contains a cycle")
            records = tree_cache.get(tree_id)
            if records is None:
                data = self._read_object_bytes(
                    tree_id,
                    expected_type="tree",
                    max_bytes=remaining,
                    operation="cat-file",
                )
                remaining -= len(data)
                records = self._parse_raw_tree(data)
                tree_cache[tree_id] = records
            next_ancestors = ancestors | {tree_id}
            for mode, object_type, object_id, name in records:
                entry_count += 1
                if entry_count > max_entries:
                    raise GitBlobTooLarge(
                        f"Git tree contains more than {max_entries} entries"
                    )
                path_bytes = prefix + name
                if path_bytes in seen_paths:
                    raise GitCommandError(
                        "cat-file", 0, "Git tree contains a duplicate path"
                    )
                seen_paths.add(path_bytes)
                if object_type == "tree":
                    if include_trees:
                        output.append(
                            TreeEntry(
                                mode=mode,
                                object_type=object_type,
                                object_id=object_id,
                                path=path_bytes.decode(
                                    "utf-8", errors="surrogateescape"
                                ),
                            )
                        )
                    walk(
                        object_id,
                        path_bytes + b"/",
                        depth + 1,
                        next_ancestors,
                    )
                    continue
                output.append(
                    TreeEntry(
                        mode=mode,
                        object_type=object_type,
                        object_id=object_id,
                        path=path_bytes.decode("utf-8", errors="surrogateescape"),
                    )
                )

        walk(root_tree, b"", 0, frozenset())
        return tuple(output)

    def read_blob_object(
        self, object_id: object, *, max_bytes: int | None = None
    ) -> bytes:
        """Read and hash-verify one exact blob object by its canonical ID."""

        limit = self.max_blob_bytes if max_bytes is None else max_bytes
        return self._read_object_bytes(
            object_id,
            expected_type="blob",
            max_bytes=limit,
            operation="cat-file",
        )

    def object_type(self, object_id: str) -> str | None:
        """Return the exact object's Git type, or ``None`` if it is absent."""

        object_id = validate_commit_sha(object_id)
        result = self._run(
            ("cat-file", "--batch-check=%(objecttype)"),
            operation="cat-file",
            input_data=f"{object_id}\n".encode("ascii"),
        )
        if result.stderr:
            raise GitCommandError(
                "cat-file",
                result.returncode,
                _diagnostic_text(result.stderr),
            )
        output = result.stdout.decode("ascii", errors="strict").strip()
        if output == f"{object_id} missing":
            return None
        if output not in {"blob", "commit", "tag", "tree"}:
            raise GitCommandError(
                "cat-file", 0, f"git returned an invalid object type: {output!r}"
            )
        return output

    def is_commit(self, commit: str) -> bool:
        """Return whether *commit* exists and is a commit object (not a tag)."""

        return self.object_type(commit) == "commit"

    def _require_commit(self, commit: object, *, operation: str) -> str:
        canonical_commit = validate_commit_sha(commit)
        object_type = self.object_type(canonical_commit)
        if object_type != "commit":
            detail = (
                "object is absent"
                if object_type is None
                else f"object has type {object_type!r}"
            )
            raise GitCommandError(
                operation,
                128,
                f"{canonical_commit} is not a commit: {detail}",
            )
        return canonical_commit

    def commit_parents(self, commit: object) -> tuple[str, ...]:
        """Return all parents recorded by an immutable commit object.

        The raw commit object is size-checked before it is read.  This avoids
        revision-name expansion and preserves every parent of merge commits.
        """

        canonical_commit = self._require_commit(commit, operation="cat-file")
        result = self._run(
            ("cat-file", "-s", canonical_commit),
            operation="cat-file",
        )
        try:
            object_size = int(result.stdout.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise GitCommandError(
                "cat-file", 0, "git returned an invalid commit object size"
            ) from error
        if object_size > DEFAULT_MAX_COMMIT_BYTES:
            raise GitBlobTooLarge(
                f"commit object is {object_size} bytes; limit is "
                f"{DEFAULT_MAX_COMMIT_BYTES}"
            )

        result = self._run(
            ("cat-file", "commit", canonical_commit),
            operation="cat-file",
        )
        if len(result.stdout) != object_size:
            raise GitCommandError(
                "cat-file", 0, "commit object size changed while reading"
            )

        header, separator, _ = result.stdout.partition(b"\n\n")
        if not separator:
            raise GitCommandError(
                "cat-file", 0, "commit object has no header terminator"
            )
        parents: list[str] = []
        for line in header.splitlines():
            if not line.startswith(b"parent "):
                continue
            try:
                parent = validate_commit_sha(line[7:].decode("ascii"))
            except (UnicodeDecodeError, InvalidCommitSha) as error:
                raise GitCommandError(
                    "cat-file", 0, "commit object contains an invalid parent"
                ) from error
            parents.append(parent)
        return tuple(parents)

    def history_is_shallow(self) -> bool:
        """Return whether Git marks this repository's local history as shallow.

        The marker itself must be a regular file located directly inside the
        already-authorized Git metadata directory.  Symlink indirection is
        rejected instead of followed.
        """

        shallow_file = self.git_directory / "shallow"
        if shallow_file.is_symlink():
            raise RepositoryUnavailable(
                f"Git shallow marker must not be a symlink: {shallow_file}"
            )
        if not shallow_file.exists():
            return False
        if not shallow_file.is_file():
            raise RepositoryUnavailable(
                f"Git shallow marker must be a regular file: {shallow_file}"
            )
        try:
            resolved = shallow_file.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise RepositoryUnavailable(
                f"Git shallow marker cannot be resolved: {shallow_file}"
            ) from error
        if resolved.parent != self.git_directory:
            raise RepositoryUnavailable(
                "Git shallow marker resolves outside the authorized metadata "
                f"directory: {resolved}"
            )
        return True

    def history_may_be_incomplete(self) -> bool:
        """Return whether local topology may be incomplete for negative facts.

        Besides the standard shallow marker, promisor/partial-clone settings
        indicate that absent objects may live remotely.  Configuration is read
        only from the authorized local repository with fixed arguments and all
        inherited/global/system config sources disabled by ``_environment``.
        """

        if self.history_is_shallow():
            return True
        result = self._run(
            (
                "config",
                "--no-includes",
                "--local",
                "--get-regexp",
                r"^remote\..*\.promisor$|^extensions\.partialclone$",
            ),
            operation="config",
            check=False,
        )
        if result.returncode == 1 and not result.stdout and not result.stderr:
            return False
        if result.returncode != 0 or result.stderr:
            raise GitCommandError(
                "config", result.returncode, _diagnostic_text(result.stderr)
            )
        return bool(result.stdout.strip())

    def is_ancestor(self, ancestor: object, descendant: object) -> bool:
        """Return whether *ancestor* reaches *descendant* through parent links."""

        ancestor = validate_commit_sha(ancestor)
        descendant = validate_commit_sha(descendant)
        canonical_ancestor = self._require_commit(
            ancestor, operation="merge-base"
        )
        canonical_descendant = self._require_commit(
            descendant, operation="merge-base"
        )
        if canonical_ancestor == canonical_descendant:
            return True
        result = self._run(
            (
                "merge-base",
                "--is-ancestor",
                canonical_ancestor,
                canonical_descendant,
            ),
            operation="merge-base",
            check=False,
        )
        if result.stderr or result.stdout or result.returncode not in {0, 1}:
            diagnostic = _diagnostic_text(result.stderr or result.stdout)
            raise GitCommandError("merge-base", result.returncode, diagnostic)
        if result.returncode == 1 and self.history_may_be_incomplete():
            raise GitHistoryIncomplete(
                "negative ancestry is inconclusive with incomplete local history"
            )
        return result.returncode == 0

    def tree_entry(self, commit: str, path: str) -> TreeEntry | None:
        """Return an exact tree entry at *commit*, without recursive guessing."""

        commit = validate_commit_sha(commit)
        path = validate_repo_relative_path(path)
        result = self._run(
            ("ls-tree", "-z", commit, "--", path),
            operation="ls-tree",
        )
        for raw_record in result.stdout.split(b"\x00"):
            if not raw_record:
                continue
            try:
                raw_metadata, raw_path = raw_record.split(b"\t", 1)
                mode, object_type, object_id = raw_metadata.decode("ascii").split()
                entry_path = raw_path.decode("utf-8", errors="surrogateescape")
            except (UnicodeDecodeError, ValueError) as error:
                raise GitCommandError(
                    "ls-tree",
                    0,
                    "git returned an unparseable tree record",
                ) from error
            if entry_path == path:
                return TreeEntry(mode, object_type, object_id, entry_path)
        return None

    def file_exists(self, commit: str, path: str) -> bool:
        """Return whether the exact path names a blob in the commit tree."""

        entry = self.tree_entry(commit, path)
        return entry is not None and entry.is_blob

    def _blob_size(self, commit: str, path: str) -> int:
        specification = f"{commit}:{path}"
        result = self._run(
            ("cat-file", "-s", specification),
            operation="cat-file",
        )
        try:
            return int(result.stdout.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise GitCommandError(
                "cat-file", 0, "git returned an invalid blob size"
            ) from error

    def read_file(self, commit: str, path: str) -> bytes:
        """Read a bounded blob from one commit without touching the worktree."""

        commit = validate_commit_sha(commit)
        path = validate_repo_relative_path(path)
        entry = self.tree_entry(commit, path)
        if entry is None or not entry.is_blob:
            raise GitCommandError(
                "show", 128, f"path does not name a file at {commit}: {path}"
            )

        size = self._blob_size(commit, path)
        if size > self.max_blob_bytes:
            raise GitBlobTooLarge(
                f"blob {path!r} is {size} bytes; limit is {self.max_blob_bytes}"
            )

        specification = f"{commit}:{path}"
        result = self._run(
            (
                "show",
                "--no-ext-diff",
                "--no-textconv",
                "--format=",
                specification,
            ),
            operation="show",
        )
        if len(result.stdout) != size:
            raise GitCommandError(
                "show",
                0,
                f"blob size changed while reading {path!r}",
            )
        return result.stdout

    def read_text(self, commit: str, path: str) -> str:
        """Read a UTF-8 (optionally BOM-prefixed) source file at one commit."""

        data = self.read_file(commit, path)
        try:
            return data.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as error:
            raise GitTextDecodeError(
                f"source file is not valid UTF-8 at {commit}: {path}"
            ) from error

    def diff_text_file(
        self,
        before: object,
        after: object,
        path: object,
        *,
        context_lines: int = 3,
    ) -> TextFileDiff:
        """Diff one exact UTF-8 path across two immutable commits.

        Source bytes are read through ``cat-file``/``show`` with textconv and
        external diff disabled.  The actual diff is generated in-process, so
        repository configuration and executable diff drivers are never run.
        Both source bytes combined and the UTF-8 encoded output have explicit
        limits.
        """

        before = validate_commit_sha(before)
        after = validate_commit_sha(after)
        canonical_path = validate_repo_relative_path(path)
        if (
            isinstance(context_lines, bool)
            or not isinstance(context_lines, int)
            or not 0 <= context_lines <= MAX_DIFF_CONTEXT_LINES
        ):
            raise ValueError(
                f"context_lines must be an integer from 0 to "
                f"{MAX_DIFF_CONTEXT_LINES}"
            )
        before_commit = self._require_commit(before, operation="diff")
        after_commit = self._require_commit(after, operation="diff")

        before_entry = self.tree_entry(before_commit, canonical_path)
        after_entry = self.tree_entry(after_commit, canonical_path)
        if before_entry is not None and not before_entry.is_blob:
            raise GitCommandError(
                "diff", 128, f"path is not a blob at {before_commit}: {canonical_path}"
            )
        if after_entry is not None and not after_entry.is_blob:
            raise GitCommandError(
                "diff", 128, f"path is not a blob at {after_commit}: {canonical_path}"
            )
        before_blob = (
            before_entry
            if before_entry is not None and before_entry.is_blob
            else None
        )
        after_blob = (
            after_entry
            if after_entry is not None and after_entry.is_blob
            else None
        )

        before_size = (
            self._blob_size(before_commit, canonical_path)
            if before_blob is not None
            else 0
        )
        after_size = (
            self._blob_size(after_commit, canonical_path)
            if after_blob is not None
            else 0
        )
        total_size = before_size + after_size
        if total_size > self.max_diff_input_bytes:
            raise GitDiffTooLarge(
                f"combined diff input is {total_size} bytes; limit is "
                f"{self.max_diff_input_bytes}"
            )

        before_data = (
            self.read_file(before_commit, canonical_path)
            if before_blob is not None
            else b""
        )
        after_data = (
            self.read_file(after_commit, canonical_path)
            if after_blob is not None
            else b""
        )
        try:
            # Preserve a UTF-8 BOM as text here: unlike ``read_text``, a diff
            # must expose even a BOM-only blob change instead of hiding it.
            before_text = before_data.decode("utf-8", errors="strict")
            after_text = after_data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise GitTextDecodeError(
                f"source file is not valid UTF-8 while diffing {canonical_path}"
            ) from error

        before_lines = before_text.splitlines(keepends=True)
        after_lines = after_text.splitlines(keepends=True)
        total_lines = len(before_lines) + len(after_lines)
        if total_lines > DEFAULT_MAX_DIFF_LINES:
            raise GitDiffTooLarge(
                f"combined diff input has {total_lines} lines; limit is "
                f"{DEFAULT_MAX_DIFF_LINES}"
            )
        added_lines = 0
        deleted_lines = 0
        diff_parts: list[str] = []
        output_size = 0
        in_hunk = False
        diff_lines = unified_diff(
            before_lines,
            after_lines,
            fromfile=f"a/{canonical_path}",
            tofile=f"b/{canonical_path}",
            n=context_lines,
        )
        for diff_line in diff_lines:
            output_size += len(diff_line.encode("utf-8"))
            if output_size > self.max_diff_output_bytes:
                raise GitDiffTooLarge(
                    f"generated diff exceeds limit of "
                    f"{self.max_diff_output_bytes} bytes"
                )
            if diff_line.startswith("@@"):
                in_hunk = True
            elif in_hunk and diff_line.startswith("+"):
                added_lines += 1
            elif in_hunk and diff_line.startswith("-"):
                deleted_lines += 1
            diff_parts.append(diff_line)
        diff = "".join(diff_parts)
        return TextFileDiff(
            before_commit=before_commit,
            after_commit=after_commit,
            path=canonical_path,
            before_exists=before_blob is not None,
            after_exists=after_blob is not None,
            before_blob_id=before_blob.object_id if before_blob is not None else None,
            after_blob_id=after_blob.object_id if after_blob is not None else None,
            added_lines=added_lines,
            deleted_lines=deleted_lines,
            unified_diff=diff,
        )
