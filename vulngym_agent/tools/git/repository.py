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
from typing import Final, Mapping, Sequence

from vulngym_agent.evaluator.bounded_process import (
    BoundedProcessError,
    run_bounded_process_v1,
)


_SHA_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}\Z")
_HEAD_REF_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"ref: refs/[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}\n\Z"
)
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
MAX_STORAGE_SCAN_BYTES: Final[int] = 64 * 1024 * 1024 * 1024
MAX_CRITICAL_CONFIG_BYTES: Final[int] = 1024 * 1024
MAX_HEAD_BYTES: Final[int] = 4 * 1024
MAX_PACKED_REFS_BYTES: Final[int] = 64 * 1024 * 1024
MAX_SHALLOW_BYTES: Final[int] = 16 * 1024 * 1024
DEFAULT_MAX_PROCESS_STDOUT_BYTES: Final[int] = 64 * 1024 * 1024
DEFAULT_MAX_PROCESS_STDERR_BYTES: Final[int] = 256 * 1024
DEFAULT_MAX_PROCESS_STDIN_BYTES: Final[int] = 16 * 1024 * 1024
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


class GitOutputTooLarge(GitFactError):
    """A Git subprocess exceeded its fixed stdout or stderr byte budget."""


class BoundedProcessOutputTooLarge(RuntimeError):
    """A generic bounded subprocess exceeded one of its capture budgets."""

    def __init__(self, stream_name: str) -> None:
        self.stream_name = stream_name
        super().__init__(f"subprocess {stream_name} exceeded its byte budget")


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
class GitStorageSeal:
    """Path-free identities and bounded inventory facts for Git metadata."""

    git_directory_identity: tuple[int, int]
    object_directory_identity: tuple[int, int]
    refs_directory_identity: tuple[int, int]
    pack_directory_identity: tuple[int, int]
    config_identity: tuple[int, int, int, int | None]
    head_identity: tuple[int, int, int, int | None]
    packed_refs_identity: tuple[int, int, int, int | None] | None
    object_entry_count: int
    object_total_bytes: int
    object_inventory_sha256: str
    refs_entry_count: int
    refs_total_bytes: int
    refs_inventory_sha256: str
    shallow_sha256: str | None


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


def _resolve_git_executable(
    executable: str | os.PathLike[str], disallowed_root: Path
) -> str:
    """Resolve one explicitly trusted Git executable outside the repository."""

    try:
        spelling = os.fspath(executable)
    except TypeError as error:
        raise RepositoryUnavailable("git executable path is invalid") from error
    if (
        not isinstance(spelling, str)
        or not spelling
        or "\x00" in spelling
        or any(ord(character) < 32 for character in spelling)
        or not os.path.isabs(spelling)
    ):
        raise RepositoryUnavailable("git executable path is not canonical")
    try:
        resolved = Path(spelling).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RepositoryUnavailable("git executable path is unavailable") from error
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise RepositoryUnavailable("git executable is not executable")
    try:
        resolved.relative_to(disallowed_root)
    except ValueError:
        return str(resolved)
    raise RepositoryUnavailable("git executable must remain outside the repository")


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


def sanitized_git_environment(
    base: Mapping[str, str],
    *,
    deny_askpass_executable: str | os.PathLike[str],
) -> dict[str, str]:
    """Remove ambient prompt/config controls and install a fixed deny helper."""

    environment = dict(base)
    explicit = {
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "SUDO_ASKPASS",
    }
    for key in tuple(environment):
        upper = key.upper()
        if upper.startswith("GIT_") or upper.startswith("GCM_") or upper in explicit:
            environment.pop(key)
    deny = os.fspath(deny_askpass_executable)
    if not isinstance(deny, str) or not os.path.isabs(deny):
        raise ValueError("deny askpass executable must be absolute")
    environment.update(
        {
            "GCM_GUI_PROMPT": "0",
            "GCM_INTERACTIVE": "never",
            "GIT_ASKPASS": deny,
            "GIT_TERMINAL_PROMPT": "0",
            "SSH_ASKPASS": deny,
            "SSH_ASKPASS_REQUIRE": "never",
        }
    )
    return environment


def run_bounded_process(
    command: Sequence[str],
    *,
    cwd: str | os.PathLike[str],
    environment: Mapping[str, str],
    timeout_seconds: float,
    input_data: bytes | None = None,
    max_stdout_bytes: int = DEFAULT_MAX_PROCESS_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_PROCESS_STDERR_BYTES,
    max_stdin_bytes: int = DEFAULT_MAX_PROCESS_STDIN_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    """Run one process while streaming both outputs into strict byte budgets.

    ``subprocess.run(..., PIPE)`` buffers without a caller-controlled ceiling.
    This helper drains stdout and stderr concurrently, kills the process as
    soon as either budget is crossed, tears down the complete descendant tree,
    and never retains more than the configured bytes for either stream.  A
    timeout is reported with the bounded partial captures attached to
    ``TimeoutExpired``.
    """

    if (
        not isinstance(command, Sequence)
        or isinstance(command, (str, bytes, bytearray))
        or not command
        or any(type(item) is not str or not item for item in command)
    ):
        raise ValueError("command must be a non-empty sequence of strings")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be positive")
    for name, value in (
        ("max_stdout_bytes", max_stdout_bytes),
        ("max_stderr_bytes", max_stderr_bytes),
        ("max_stdin_bytes", max_stdin_bytes),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    if input_data is not None and type(input_data) is not bytes:
        raise ValueError("input_data must be exact bytes or None")
    if input_data is not None and len(input_data) > max_stdin_bytes:
        raise BoundedProcessOutputTooLarge("stdin")

    try:
        result = run_bounded_process_v1(
            tuple(command),
            input_data or b"",
            stdout_max_bytes=max_stdout_bytes,
            stderr_max_bytes=max_stderr_bytes,
            timeout_seconds=float(timeout_seconds),
            env=dict(environment),
            cwd=os.fspath(cwd),
        )
    except BoundedProcessError as error:
        if error.code == "invalid_argument":
            raise ValueError("bounded subprocess arguments are invalid") from error
        raise OSError("bounded subprocess could not be contained") from error
    if result.stdout_overflow or result.stderr_overflow:
        raise BoundedProcessOutputTooLarge(
            "stdout" if result.stdout_overflow else "stderr"
        )
    if result.timed_out:
        raise subprocess.TimeoutExpired(
            tuple(command),
            timeout_seconds,
            output=result.stdout,
            stderr=result.stderr,
        )
    return subprocess.CompletedProcess(
        tuple(command),
        result.exit_code,
        result.stdout,
        result.stderr,
    )


def _regular_identity(
    state: os.stat_result,
) -> tuple[int, int, int, int | None]:
    return (
        state.st_dev,
        state.st_ino,
        state.st_size,
        getattr(state, "st_mtime_ns", None),
    )


def _read_safe_regular_file(
    path: Path,
    *,
    max_bytes: int,
    required: bool,
) -> tuple[tuple[int, int, int, int | None], bytes] | None:
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if required:
            raise RepositoryUnavailable("required Git metadata is absent")
        return None
    except OSError as error:
        raise RepositoryUnavailable("Git metadata cannot be inspected") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or before.st_size > max_bytes
    ):
        raise RepositoryUnavailable("Git metadata is not a bounded direct file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RepositoryUnavailable("Git metadata cannot be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink != 1
            or _regular_identity(opened) != _regular_identity(before)
        ):
            raise RepositoryUnavailable("Git metadata changed while opening")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(payload) > max_bytes
        or _regular_identity(finished) != _regular_identity(opened)
    ):
        raise RepositoryUnavailable("Git metadata changed while reading")
    try:
        after = os.lstat(path)
    except OSError as error:
        raise RepositoryUnavailable("Git metadata changed after reading") from error
    if (
        not stat.S_ISREG(after.st_mode)
        or stat.S_ISLNK(after.st_mode)
        or _is_reparse(after)
        or after.st_nlink != 1
        or _regular_identity(after) != _regular_identity(opened)
    ):
        raise RepositoryUnavailable("Git metadata changed after reading")
    return _regular_identity(opened), payload


def _safe_directory_identity(path: Path) -> tuple[int, int]:
    try:
        state = os.lstat(path)
    except OSError as error:
        raise RepositoryUnavailable("required Git metadata directory is absent") from error
    if (
        not stat.S_ISDIR(state.st_mode)
        or stat.S_ISLNK(state.st_mode)
        or _is_reparse(state)
    ):
        raise RepositoryUnavailable("Git metadata directory is not direct")
    return state.st_dev, state.st_ino


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
        git_executable: str | os.PathLike[str] | None = None,
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
        self.refs_directory = git_directory / "refs"
        self.pack_directory = object_directory / "pack"
        self.config_path = git_directory / "config"
        self.head_path = git_directory / "HEAD"
        self.packed_refs_path = git_directory / "packed-refs"
        self._git_directory_identity = _safe_directory_identity(git_directory)
        self._object_directory_identity = _safe_directory_identity(object_directory)
        self._refs_directory_identity = _safe_directory_identity(self.refs_directory)
        self._pack_directory_identity = _safe_directory_identity(self.pack_directory)
        config = _read_safe_regular_file(
            self.config_path,
            max_bytes=MAX_CRITICAL_CONFIG_BYTES,
            required=True,
        )
        head = _read_safe_regular_file(
            self.head_path,
            max_bytes=MAX_HEAD_BYTES,
            required=True,
        )
        packed_refs = _read_safe_regular_file(
            self.packed_refs_path,
            max_bytes=MAX_PACKED_REFS_BYTES,
            required=False,
        )
        if config is None or head is None:
            raise RepositoryUnavailable("required Git metadata is absent")
        head_value = head[1]
        try:
            detached_head = head_value.rstrip(b"\r\n").decode(
                "ascii", errors="strict"
            )
        except UnicodeDecodeError:
            detached_head = ""
        if not (
            _SHA_RE.fullmatch(detached_head)
            or (
                _HEAD_REF_RE.fullmatch(head_value) is not None
                and b".." not in head_value
                and b"//" not in head_value
                and b"/." not in head_value
                and not head_value.rstrip(b"\n").endswith((b"/", b"."))
            )
        ):
            raise RepositoryUnavailable("Git HEAD is not canonical")
        self._config_identity = config[0]
        self._head_identity = head[0]
        self._packed_refs_identity = packed_refs[0] if packed_refs is not None else None
        self._config_sha256 = hashlib.sha256(config[1]).hexdigest()
        self._head_sha256 = hashlib.sha256(head[1]).hexdigest()
        self._packed_refs_sha256 = (
            hashlib.sha256(packed_refs[1]).hexdigest()
            if packed_refs is not None
            else None
        )
        self.is_bare_repository = is_bare_root
        self.timeout_seconds = float(timeout_seconds)
        self.max_blob_bytes = max_blob_bytes
        self.max_diff_input_bytes = max_diff_input_bytes
        self.max_diff_output_bytes = max_diff_output_bytes
        self._git_executable = (
            _find_git_executable(resolved)
            if git_executable is None
            else _resolve_git_executable(git_executable, resolved)
        )
        self._subprocess_directory = str(Path(self._git_executable).parent)
        self._assert_repository()
        self._assert_history_storage()
        self._assert_critical_metadata_stable()

    @property
    def git_executable(self) -> Path:
        """Return the absolute executable selected for immutable fact reads."""

        return Path(self._git_executable)

    def _environment(self) -> dict[str, str]:
        environment = sanitized_git_environment(
            os.environ,
            deny_askpass_executable=self._git_executable,
        )
        # Prevent ambient Git variables from redirecting the object database,
        # repository, config source, trace output, or helper executable path.
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
        max_stdout_bytes: int = DEFAULT_MAX_PROCESS_STDOUT_BYTES,
        max_stderr_bytes: int = DEFAULT_MAX_PROCESS_STDERR_BYTES,
    ) -> subprocess.CompletedProcess[bytes]:
        command = (*self._base_command(), *arguments)
        try:
            result = run_bounded_process(
                command,
                cwd=self._subprocess_directory,
                environment=self._environment(),
                timeout_seconds=self.timeout_seconds,
                input_data=input_data,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=max_stderr_bytes,
            )
        except BoundedProcessOutputTooLarge as error:
            raise GitOutputTooLarge(
                f"git {operation} exceeded its {error.stream_name} byte budget"
            ) from error
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

    def _assert_critical_metadata_stable(self) -> None:
        if _safe_directory_identity(self.git_directory) != self._git_directory_identity:
            raise RepositoryUnavailable("Git metadata directory identity changed")
        if _safe_directory_identity(self.object_directory) != self._object_directory_identity:
            raise RepositoryUnavailable("Git object directory identity changed")
        if _safe_directory_identity(self.refs_directory) != self._refs_directory_identity:
            raise RepositoryUnavailable("Git refs directory identity changed")
        if _safe_directory_identity(self.pack_directory) != self._pack_directory_identity:
            raise RepositoryUnavailable("Git pack directory identity changed")
        config = _read_safe_regular_file(
            self.config_path,
            max_bytes=MAX_CRITICAL_CONFIG_BYTES,
            required=True,
        )
        head = _read_safe_regular_file(
            self.head_path,
            max_bytes=MAX_HEAD_BYTES,
            required=True,
        )
        packed_refs = _read_safe_regular_file(
            self.packed_refs_path,
            max_bytes=MAX_PACKED_REFS_BYTES,
            required=False,
        )
        if (
            config is None
            or head is None
            or config[0] != self._config_identity
            or head[0] != self._head_identity
            or hashlib.sha256(config[1]).hexdigest() != self._config_sha256
            or hashlib.sha256(head[1]).hexdigest() != self._head_sha256
            or (
                packed_refs[0] if packed_refs is not None else None
            )
            != self._packed_refs_identity
            or (
                hashlib.sha256(packed_refs[1]).hexdigest()
                if packed_refs is not None
                else None
            )
            != self._packed_refs_sha256
        ):
            raise RepositoryUnavailable("critical Git metadata identity changed")

    def _scan_metadata_tree(
        self,
        root: Path,
        *,
        object_storage: bool,
    ) -> tuple[int, int, str]:
        pending = [root]
        scanned = 0
        total_bytes = 0
        record_hashes: list[bytes] = []
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as iterator:
                    entries = tuple(iterator)
            except OSError as error:
                raise RepositoryUnavailable(
                    "Git metadata cannot be scanned safely"
                ) from error
            for entry in entries:
                scanned += 1
                if scanned > MAX_STORAGE_SCAN_ENTRIES:
                    raise RepositoryUnavailable(
                        "Git metadata exceeds the entry scan limit"
                    )
                try:
                    state = os.lstat(entry.path)
                    relative = Path(entry.path).relative_to(root)
                except (OSError, ValueError) as error:
                    raise RepositoryUnavailable(
                        "Git metadata changed during scanning"
                    ) from error
                if entry.is_symlink() or stat.S_ISLNK(state.st_mode) or _is_reparse(state):
                    raise RepositoryUnavailable(
                        "Git metadata must not contain links or reparse points"
                    )
                relative_bytes = os.fsencode(os.fspath(relative)).replace(
                    os.fsencode(os.sep), b"/"
                )
                if stat.S_ISDIR(state.st_mode):
                    pending.append(Path(entry.path))
                    kind = b"d"
                    size = 0
                elif stat.S_ISREG(state.st_mode) and state.st_nlink == 1:
                    kind = b"f"
                    size = state.st_size
                    total_bytes += size
                    if total_bytes > MAX_STORAGE_SCAN_BYTES:
                        raise RepositoryUnavailable(
                            "Git metadata exceeds the byte scan limit"
                        )
                    name = entry.name
                    parts = relative.parts
                    if object_storage and parts and parts[0] == "pack":
                        if name.endswith(".promisor"):
                            raise RepositoryUnavailable(
                                "Git promisor pack metadata is forbidden"
                            )
                        if name.startswith("tmp_pack_") or name.endswith(".lock"):
                            raise RepositoryUnavailable(
                                "Git pack transaction cleanup is required"
                            )
                    if not object_storage and name.endswith(".lock"):
                        raise RepositoryUnavailable(
                            "Git ref transaction cleanup is required"
                        )
                else:
                    raise RepositoryUnavailable(
                        "Git metadata contains an unsafe file"
                    )
                identity = (
                    state.st_dev,
                    state.st_ino,
                    size,
                    getattr(state, "st_mtime_ns", None),
                )
                record_hashes.append(
                    hashlib.sha256(
                        kind
                        + b"\0"
                        + relative_bytes
                        + b"\0"
                        + b":".join(
                            str(value).encode("ascii") for value in identity
                        )
                    ).digest()
                )
        inventory = hashlib.sha256(b"".join(sorted(record_hashes))).hexdigest()
        return scanned, total_bytes, inventory

    def capture_storage_seal(self) -> GitStorageSeal:
        """Return bounded storage facts while closing critical identities."""

        self._assert_critical_metadata_stable()
        for marker in (
            self.git_directory / "commondir",
            self.object_directory / "info" / "alternates",
            self.object_directory / "info" / "http-alternates",
            self.git_directory / "info" / "grafts",
        ):
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
        object_count, object_bytes, object_digest = self._scan_metadata_tree(
            self.object_directory,
            object_storage=True,
        )
        refs_count, refs_bytes, refs_digest = self._scan_metadata_tree(
            self.refs_directory,
            object_storage=False,
        )
        shallow = _read_safe_regular_file(
            self.git_directory / "shallow",
            max_bytes=MAX_SHALLOW_BYTES,
            required=False,
        )
        shallow_sha256: str | None = None
        if shallow is not None:
            payload = shallow[1]
            try:
                lines = payload.decode("ascii", errors="strict").splitlines()
            except UnicodeDecodeError as error:
                raise RepositoryUnavailable("Git shallow boundary is malformed") from error
            if not lines or any(_SHA_RE.fullmatch(line) is None for line in lines):
                raise RepositoryUnavailable("Git shallow boundary is malformed")
            shallow_sha256 = hashlib.sha256(payload).hexdigest()
        self._assert_critical_metadata_stable()
        return GitStorageSeal(
            git_directory_identity=self._git_directory_identity,
            object_directory_identity=self._object_directory_identity,
            refs_directory_identity=self._refs_directory_identity,
            pack_directory_identity=self._pack_directory_identity,
            config_identity=self._config_identity,
            head_identity=self._head_identity,
            packed_refs_identity=self._packed_refs_identity,
            object_entry_count=object_count,
            object_total_bytes=object_bytes,
            object_inventory_sha256=object_digest,
            refs_entry_count=refs_count,
            refs_total_bytes=refs_bytes,
            refs_inventory_sha256=refs_digest,
            shallow_sha256=shallow_sha256,
        )

    def assert_bare_storage_safe(self) -> GitStorageSeal:
        """Verify this is the same bounded, direct bare Git object store."""

        if not self.is_bare_repository:
            raise RepositoryUnavailable("source acquisition requires a bare repository")
        before = self.capture_storage_seal()
        result = self._run(
            ("rev-parse", "--is-bare-repository"),
            operation="rev-parse",
            max_stdout_bytes=16,
        )
        if result.stderr or result.stdout != b"true\n":
            raise RepositoryUnavailable("source repository is not exactly bare")
        after = self.capture_storage_seal()
        if before != after:
            raise RepositoryUnavailable("Git storage changed during bare verification")
        return after

    def assert_storage_safe(self) -> None:
        """Re-check the local object-store containment and redirection policy.

        Snapshot preparation calls this both before and after a raw object
        traversal.  It detects metadata-directory replacement and storage
        redirections introduced after this wrapper was constructed.
        """

        self.capture_storage_seal()

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
        object_size = self.object_size(
            object_id,
            expected_type=expected_type,
            operation=operation,
        )
        if object_size > max_bytes:
            raise GitBlobTooLarge(
                f"{expected_type} object is {object_size} bytes; limit is {max_bytes}"
            )
        value_result = self._run(
            ("cat-file", expected_type, object_id),
            operation=operation,
            max_stdout_bytes=object_size,
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

    def object_size(
        self,
        object_id: object,
        *,
        expected_type: str | None = None,
        operation: str = "cat-file",
    ) -> int:
        """Return the exact non-negative size of one verified local object."""

        object_id = validate_commit_sha(object_id)
        if expected_type is not None and expected_type not in {
            "blob",
            "commit",
            "tree",
        }:
            raise ValueError("expected_type is not a supported raw Git object type")
        object_type = self.object_type(object_id)
        if object_type is None or (
            expected_type is not None and object_type != expected_type
        ):
            wanted = expected_type or "Git"
            detail = (
                "object is absent"
                if object_type is None
                else f"object has type {object_type!r}"
            )
            raise GitCommandError(
                operation,
                128,
                f"{object_id} is not a {wanted} object: {detail}",
            )
        size_result = self._run(("cat-file", "-s", object_id), operation=operation)
        try:
            object_size = int(size_result.stdout.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise GitCommandError(
                operation, 0, "git returned an invalid object size"
            ) from error
        if object_size < 0:
            raise GitCommandError(operation, 0, "git returned a negative object size")
        return object_size

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
            max_stdout_bytes=object_size,
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

        shallow = _read_safe_regular_file(
            self.git_directory / "shallow",
            max_bytes=MAX_SHALLOW_BYTES,
            required=False,
        )
        if shallow is None:
            return False
        try:
            lines = shallow[1].decode("ascii", errors="strict").splitlines()
        except UnicodeDecodeError as error:
            raise RepositoryUnavailable("Git shallow marker is malformed") from error
        if not lines or any(_SHA_RE.fullmatch(line) is None for line in lines):
            raise RepositoryUnavailable("Git shallow marker is malformed")
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
            max_stdout_bytes=size,
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
