"""Trusted Git source acquisition and canonical source-map preparation.

This module is deliberately outside every agent sandbox.  It accepts only
digest-pinned answer-free task exports, derives GitHub transports from their
canonical repository identities, and stores fetched objects in independent
bare repositories.  Local paths appear only in the host-specific source maps;
the acquisition report contains repository/commit/tree facts but no paths.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Iterable, Literal, Mapping, Sequence

from vulngym_agent.benchmark.contracts import (
    BenchmarkContractError,
    BenchmarkTask,
)
from vulngym_agent.benchmark.harness import (
    BenchmarkHarnessError,
    _publish_directory,
)
from vulngym_agent.benchmark.sealed_snapshot import (
    SealedSnapshotError,
    SealedSnapshotSourceAudit,
    audit_sealed_snapshot_source,
)
from vulngym_agent.benchmark.snapshot_batch import (
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    SnapshotBatchError,
    SnapshotSourceMapDocument,
    VerifiedTaskExport,
    _assert_directory_chain,
    _canonical_existing_path,
    _canonical_json,
    _checked_directory_chain,
    _fixed_names,
    _read_stable_file,
    build_snapshot_source_map_document,
    load_verified_snapshot_source_map,
    load_verified_task_export,
)
from vulngym_agent.tools.git.repository import (
    BoundedProcessOutputTooLarge,
    GitFactError,
    GitRepository,
    GitStorageSeal,
    run_bounded_process,
    sanitized_git_environment,
)
from vulngym_agent.trusted_inputs import paths_overlap_v1


SOURCE_ACQUISITION_CONTRACT_VERSION: Final[str] = (
    "vulngym.source-acquisition.v4"
)
SOURCE_ACQUISITION_REPORT_NAME: Final[str] = "acquisition-report.json"
SOURCE_NOT_READY_EXIT_STATUS: Final[int] = 10
SOURCE_MAP_FILE_NAMES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "test": "test-source-map.json",
        "train": "train-source-map.json",
    }
)
GITHUB_TRANSPORTS: Final[tuple[str, str]] = ("https", "ssh")

_SHA1_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_GIT_VERSION_RE: Final[re.Pattern[bytes]] = re.compile(
    rb"git version ([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9A-Za-z-]+)*)\n\Z"
)
_GITHUB_PREFIX: Final[str] = "https://github.com/"
_MAX_OUTPUT_FILE_BYTES: Final[int] = 8 * 1024 * 1024
_GIT_SHORT_TIMEOUT_SECONDS: Final[float] = 120.0
_GIT_NETWORK_TIMEOUT_SECONDS: Final[float] = 2.0 * 60.0 * 60.0
_GIT_FSCK_TIMEOUT_SECONDS: Final[float] = 60.0 * 60.0
_GIT_MAX_STDOUT_BYTES: Final[int] = 16 * 1024 * 1024
_GIT_MAX_STDERR_BYTES: Final[int] = 4 * 1024 * 1024
_FETCH_DEPTH_STEP: Final[int] = 32
_MAX_DEEPEN_ROUNDS: Final[int] = 2_048
_MAX_TOTAL_NETWORK_SECONDS: Final[float] = 6.0 * 60.0 * 60.0
_MAX_TRANSIENT_FETCH_RETRIES_PER_REPOSITORY: Final[int] = 1
_MAX_RECOVERY_ARTIFACTS: Final[int] = 256
_MAX_RECOVERY_ARTIFACT_BYTES: Final[int] = 4 * 1024 * 1024 * 1024
_MULTI_PACK_INDEX_NAME: Final[str] = "multi-pack-index"
_ALLOWED_LOCAL_CONFIG_KEYS: Final[frozenset[str]] = frozenset(
    {
        "core.bare",
        "core.filemode",
        "core.ignorecase",
        "core.logallrefupdates",
        "core.precomposeunicode",
        "core.repositoryformatversion",
        "core.symlinks",
        "extensions.objectformat",
    }
)
_COUNT_OBJECT_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "count",
        "size",
        "in-pack",
        "packs",
        "size-pack",
        "prune-packable",
        "garbage",
        "size-garbage",
    }
)
_FSCK_NOTICE_PREFIXES: Final[tuple[bytes, ...]] = (
    b"notice: HEAD points to an unborn branch ",
    b"notice: No default references",
)


class SourceAcquisitionError(RuntimeError):
    """A path-sanitized acquisition, verification, or publication failure."""

    def __init__(self, code: str, message: str, *, exit_status: int) -> None:
        if not isinstance(code, str) or not code:
            raise ValueError("code must be a non-empty string")
        if exit_status not in {2, 3, 4, 5}:
            raise ValueError("exit_status must be one of 2, 3, 4, or 5")
        self.code = code
        self.exit_status = exit_status
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class SourceAcquisitionInput:
    """One expected digest pin and its answer-free task-export directory."""

    task_export_dir: Path
    expected_tasks_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.task_export_dir, Path):
            raise ValueError("task_export_dir must be a Path")
        if (
            not isinstance(self.expected_tasks_sha256, str)
            or _SHA256_RE.fullmatch(self.expected_tasks_sha256) is None
        ):
            raise ValueError(
                "expected_tasks_sha256 must be a lower-case SHA-256 digest"
            )


@dataclass(frozen=True, slots=True)
class AcquiredSourceMapSummary:
    """One path-free description of a host-specific source-map artifact."""

    split: str
    task_count: int
    tasks_sha256: str
    source_map_sha256: str

    def __post_init__(self) -> None:
        if self.split not in SOURCE_MAP_FILE_NAMES:
            raise ValueError("split is not supported")
        if (
            isinstance(self.task_count, bool)
            or not isinstance(self.task_count, int)
            or self.task_count < 1
        ):
            raise ValueError("task_count must be positive")
        for value, name in (
            (self.tasks_sha256, "tasks_sha256"),
            (self.source_map_sha256, "source_map_sha256"),
        ):
            if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lower-case SHA-256 digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "source_map_sha256": self.source_map_sha256,
            "split": self.split,
            "task_count": self.task_count,
            "tasks_sha256": self.tasks_sha256,
        }


@dataclass(frozen=True, slots=True)
class SourceAcquisitionSummary:
    """Path-free completion summary for a trusted acquisition run."""

    github_transport: Literal["https", "ssh"]
    repository_count: int
    task_count: int
    ready: bool
    ready_task_count: int
    blocked_task_count: int
    acquisition_report_sha256: str
    source_maps: tuple[AcquiredSourceMapSummary, ...]

    def __post_init__(self) -> None:
        maps = tuple(self.source_maps)
        object.__setattr__(self, "source_maps", maps)
        if (
            type(self.github_transport) is not str
            or self.github_transport not in GITHUB_TRANSPORTS
        ):
            raise ValueError("github_transport is invalid")
        if (
            isinstance(self.repository_count, bool)
            or not isinstance(self.repository_count, int)
            or self.repository_count < 1
        ):
            raise ValueError("repository_count must be positive")
        if (
            isinstance(self.task_count, bool)
            or not isinstance(self.task_count, int)
            or self.task_count != sum(item.task_count for item in maps)
        ):
            raise ValueError("task_count does not close over source maps")
        if not isinstance(self.ready, bool):
            raise ValueError("ready must be a boolean")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.ready_task_count, self.blocked_task_count)
        ) or self.task_count != self.ready_task_count + self.blocked_task_count:
            raise ValueError("readiness counts do not close over task_count")
        if self.ready != (self.blocked_task_count == 0):
            raise ValueError("ready does not close over blocked_task_count")
        if not 1 <= len(maps) <= 2 or len({item.split for item in maps}) != len(maps):
            raise ValueError("source_maps must contain one or two distinct splits")
        if (
            not isinstance(self.acquisition_report_sha256, str)
            or _SHA256_RE.fullmatch(self.acquisition_report_sha256) is None
        ):
            raise ValueError("report digest must be a lower-case SHA-256 digest")

    def to_dict(self) -> dict[str, object]:
        return {
            "acquisition_report_sha256": self.acquisition_report_sha256,
            "github_transport": self.github_transport,
            "blocked_task_count": self.blocked_task_count,
            "profile_id": PROFILE_ID,
            "public_manifest_sha256": PROFILE_MANIFEST_SHA256,
            "ready": self.ready,
            "ready_task_count": self.ready_task_count,
            "repository_count": self.repository_count,
            "source_maps": [item.to_dict() for item in self.source_maps],
            "task_count": self.task_count,
        }


@dataclass(frozen=True, slots=True)
class _RepositoryClosureV2:
    """Exact path-free state retained for later all-repository rechecks."""

    storage_seal: GitStorageSeal
    refs: tuple[tuple[str, str], ...]
    counts: tuple[tuple[str, int], ...]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _split_order(split: str) -> int:
    return 0 if split == "test" else 1


def github_fetch_url_v1(repo_url: object, transport: object) -> str:
    """Map one canonical GitHub HTTPS identity to a fixed fetch transport."""

    if type(transport) is not str or transport not in GITHUB_TRANSPORTS:
        raise ValueError("github transport must be https or ssh")
    try:
        probe = BenchmarkTask(
            task_id="VG-TRAIN-00000000000000000000",
            repo_url=repo_url,  # type: ignore[arg-type]
            commit="0" * 40,
            split="train",
        )
    except BenchmarkContractError as error:
        raise ValueError("repository URL is not a canonical GitHub identity") from error
    owner, repository = probe.repo_url[len(_GITHUB_PREFIX) :].split("/", 1)
    if transport == "https":
        return f"{probe.repo_url}.git"
    return f"git@github.com:{owner}/{repository}.git"


def _canonical_executable(path: Path, *, name: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise SourceAcquisitionError(
            "invalid_executable", f"{name} executable must be absolute", exit_status=2
        )
    try:
        executable = path.resolve(strict=True)
        state = os.lstat(executable)
        checked = _checked_directory_chain(executable.parent, status=2)
    except (OSError, RuntimeError, SnapshotBatchError) as error:
        raise SourceAcquisitionError(
            "invalid_executable", f"{name} executable is unavailable", exit_status=2
        ) from error
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(state.st_mode)
        or stat.S_ISLNK(state.st_mode)
        or bool(getattr(state, "st_file_attributes", 0) & reparse_flag)
        or (os.name == "posix" and not os.access(executable, os.X_OK))
    ):
        raise SourceAcquisitionError(
            "invalid_executable", f"{name} executable is not executable", exit_status=2
        )
    try:
        _assert_directory_chain(checked, status=2)
    except SnapshotBatchError as error:
        raise SourceAcquisitionError(
            "invalid_executable", f"{name} executable changed", exit_status=2
        ) from error
    return executable


def _git_environment(
    *,
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
) -> dict[str, str]:
    environment = sanitized_git_environment(
        os.environ,
        deny_askpass_executable=git_executable,
    )
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    if github_transport == "ssh":
        if ssh_executable is None:
            raise SourceAcquisitionError(
                "ssh_executable_required",
                "SSH transport requires an explicit SSH executable",
                exit_status=2,
            )
        ssh_command = str(ssh_executable)
        if os.name == "nt":
            # Git for Windows evaluates GIT_SSH_COMMAND with its POSIX shell.
            # Backslashes from list2cmdline would therefore be consumed as
            # escapes before a native or bundled OpenSSH binary can start.
            ssh_command = ssh_command.replace("\\", "/")
        command = [
            ssh_command,
            "-F",
            "none",
            "-o",
            "BatchMode=yes",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ProxyJump=none",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=30",
            "-o",
            "HostName=ssh.github.com",
            "-p",
            "443",
        ]
        environment["GIT_SSH_COMMAND"] = shlex.join(command)
        environment["GIT_SSH_VARIANT"] = "ssh"
    return environment


def _run_git(
    git_executable: Path,
    repository: Path | None,
    arguments: Sequence[str],
    *,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
    timeout_seconds: float,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    command: list[str] = [
        str(git_executable),
        "--no-pager",
        "--literal-pathspecs",
        "-c",
        "advice.detachedHead=false",
        "-c",
        "core.commitGraph=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "credential.helper=",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
    ]
    if repository is not None:
        command.extend(("-C", str(repository)))
    command.extend(arguments)
    try:
        result = run_bounded_process(
            command,
            cwd=str(git_executable.parent),
            environment=_git_environment(
                git_executable=git_executable,
                github_transport=github_transport,
                ssh_executable=ssh_executable,
            ),
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=_GIT_MAX_STDOUT_BYTES,
            max_stderr_bytes=_GIT_MAX_STDERR_BYTES,
        )
    except BoundedProcessOutputTooLarge as error:
        raise SourceAcquisitionError(
            "git_output_limit",
            "a Git subprocess exceeded its fixed output budget",
            exit_status=3,
        ) from error
    except subprocess.TimeoutExpired as error:
        raise SourceAcquisitionError(
            "git_timeout", "a bounded Git operation timed out", exit_status=3
        ) from error
    except OSError as error:
        raise SourceAcquisitionError(
            "git_unavailable", "a Git subprocess could not start", exit_status=3
        ) from error
    if check and result.returncode != 0:
        raise SourceAcquisitionError(
            "git_command_failed", "a trusted Git command failed", exit_status=3
        )
    return result


def _read_git_version(
    git_executable: Path,
    *,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
) -> str:
    """Return one fail-closed Git implementation version for the report."""

    result = _run_git(
        git_executable,
        None,
        ("version",),
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        timeout_seconds=_GIT_SHORT_TIMEOUT_SECONDS,
        check=False,
    )
    match = _GIT_VERSION_RE.fullmatch(result.stdout)
    if result.returncode != 0 or result.stderr or match is None:
        raise SourceAcquisitionError(
            "git_version_rejected",
            "Git version output does not match the supported strict contract",
            exit_status=2,
        )
    return match.group(1).decode("ascii")


def _load_exports(
    inputs: Iterable[SourceAcquisitionInput],
) -> tuple[VerifiedTaskExport, ...]:
    snapshotted = tuple(inputs)
    if not 1 <= len(snapshotted) <= 2 or any(
        type(item) is not SourceAcquisitionInput for item in snapshotted
    ):
        raise SourceAcquisitionError(
            "invalid_exports",
            "one or two exact acquisition inputs are required",
            exit_status=2,
        )
    exports: list[VerifiedTaskExport] = []
    try:
        for item in snapshotted:
            exports.append(
                load_verified_task_export(
                    item.task_export_dir,
                    expected_tasks_sha256=item.expected_tasks_sha256,
                    expected_public_manifest_sha256=PROFILE_MANIFEST_SHA256,
                )
            )
    except SnapshotBatchError as error:
        raise SourceAcquisitionError(
            "task_export_rejected",
            "an answer-free task export failed verification",
            exit_status=2,
        ) from error
    exports.sort(key=lambda item: _split_order(item.split))
    if len({item.split for item in exports}) != len(exports):
        raise SourceAcquisitionError(
            "duplicate_split", "task exports repeat a split", exit_status=2
        )
    task_ids: set[str] = set()
    snapshots: set[tuple[str, str]] = set()
    repository_spellings: dict[str, str] = {}
    for export in exports:
        for task in export.tasks:
            snapshot = (task.repo_url.casefold(), task.commit)
            canonical_url = repository_spellings.setdefault(
                task.repo_url.casefold(), task.repo_url
            )
            if (
                canonical_url != task.repo_url
                or task.task_id in task_ids
                or snapshot in snapshots
            ):
                raise SourceAcquisitionError(
                    "cross_export_collision",
                    "task exports collide across trusted identities",
                    exit_status=2,
                )
            task_ids.add(task.task_id)
            snapshots.add(snapshot)
    return tuple(exports)


def _repository_groups(
    exports: Sequence[VerifiedTaskExport],
) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, set[str]] = {}
    for export in exports:
        for task in export.tasks:
            grouped.setdefault(task.repo_url, set()).add(task.commit)
    return {
        repo_url: tuple(sorted(commits))
        for repo_url, commits in sorted(
            grouped.items(), key=lambda item: item[0].encode("utf-8")
        )
    }


def _repository_path(repository_store: Path, repo_url: str) -> tuple[Path, str, str]:
    owner, repository = repo_url[len(_GITHUB_PREFIX) :].split("/", 1)
    return repository_store / owner / f"{repository}.git", owner, repository


def _ensure_directory_child(parent: Path, name: str, *, create: bool) -> Path:
    target = parent / name
    try:
        state = os.lstat(target)
    except FileNotFoundError:
        if not create:
            raise SourceAcquisitionError(
                "repository_missing", "a required repository is absent", exit_status=4
            )
        try:
            os.mkdir(target, 0o700)
        except OSError as error:
            raise SourceAcquisitionError(
                "repository_store_failed",
                "a repository directory could not be created",
                exit_status=3,
            ) from error
    except OSError as error:
        raise SourceAcquisitionError(
            "repository_store_failed",
            "a repository directory cannot be inspected",
            exit_status=3 if create else 4,
        ) from error
    else:
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or bool(getattr(state, "st_file_attributes", 0) & reparse_flag)
        ):
            raise SourceAcquisitionError(
                "unsafe_repository_path",
                "a repository path is not a direct directory",
                exit_status=3 if create else 4,
            )
    try:
        return _canonical_existing_path(
            target, directory=True, status=3 if create else 4
        )
    except SnapshotBatchError as error:
        raise SourceAcquisitionError(
            "unsafe_repository_path",
            "a repository path failed canonicalization",
            exit_status=3 if create else 4,
        ) from error


def _directory_is_empty(path: Path) -> bool:
    try:
        with os.scandir(path) as entries:
            return next(entries, None) is None
    except OSError as error:
        raise SourceAcquisitionError(
            "repository_store_failed",
            "a repository directory cannot be inspected",
            exit_status=3,
        ) from error


def _assert_recovery_state_clean(repository_root: Path, *, status: int) -> None:
    """Reject unresolved Git transaction artifacts without deleting by name."""

    candidates: list[Path] = []
    for name in ("config.lock", "HEAD.lock", "packed-refs.lock", "shallow.lock"):
        candidates.append(repository_root / name)
    pack = repository_root / "objects" / "pack"
    refs = repository_root / "refs"
    scanned = 0
    try:
        with os.scandir(pack) as entries:
            for entry in entries:
                scanned += 1
                if scanned > _MAX_RECOVERY_ARTIFACTS * 16:
                    raise SourceAcquisitionError(
                        "cleanup_scan_limit",
                        "Git recovery state exceeds its scan budget",
                        exit_status=status,
                    )
                if entry.name.endswith(".promisor"):
                    raise SourceAcquisitionError(
                        "promisor_pack_rejected",
                        "promisor pack metadata is forbidden",
                        exit_status=status,
                    )
                if entry.name.startswith("tmp_pack_") or entry.name.endswith(".lock"):
                    candidates.append(Path(entry.path))
        pending = [refs]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    scanned += 1
                    if scanned > _MAX_RECOVERY_ARTIFACTS * 1024:
                        raise SourceAcquisitionError(
                            "cleanup_scan_limit",
                            "Git recovery state exceeds its scan budget",
                            exit_status=status,
                        )
                    state = os.lstat(entry.path)
                    reparse_flag = getattr(
                        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
                    )
                    if (
                        stat.S_ISLNK(state.st_mode)
                        or bool(
                            getattr(state, "st_file_attributes", 0)
                            & reparse_flag
                        )
                    ):
                        raise SourceAcquisitionError(
                            "cleanup_required",
                            "Git transaction state is not safe to recover automatically",
                            exit_status=status,
                        )
                    if stat.S_ISDIR(state.st_mode):
                        pending.append(Path(entry.path))
                    elif entry.name.endswith(".lock"):
                        candidates.append(Path(entry.path))
    except SourceAcquisitionError:
        raise
    except OSError as error:
        raise SourceAcquisitionError(
            "cleanup_required",
            "Git transaction state cannot be verified for recovery",
            exit_status=status,
        ) from error

    count = 0
    total_bytes = 0
    for candidate in candidates:
        try:
            state = os.lstat(candidate)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise SourceAcquisitionError(
                "cleanup_required",
                "Git transaction state cannot be verified for recovery",
                exit_status=status,
            ) from error
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        try:
            candidate.relative_to(repository_root)
        except ValueError as error:
            raise SourceAcquisitionError(
                "cleanup_required",
                "Git transaction state escaped its repository",
                exit_status=status,
            ) from error
        if (
            not stat.S_ISREG(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or bool(getattr(state, "st_file_attributes", 0) & reparse_flag)
            or state.st_nlink != 1
        ):
            raise SourceAcquisitionError(
                "cleanup_required",
                "Git transaction state is not safe to recover automatically",
                exit_status=status,
            )
        count += 1
        total_bytes += state.st_size
        if (
            count > _MAX_RECOVERY_ARTIFACTS
            or total_bytes > _MAX_RECOVERY_ARTIFACT_BYTES
        ):
            raise SourceAcquisitionError(
                "cleanup_scan_limit",
                "Git recovery artifacts exceed their fixed budget",
                exit_status=status,
            )
    if count:
        # A portable conditional unlink-by-inode primitive is unavailable.
        # Never risk deleting a concurrently replaced name; require explicit
        # operator isolation and recovery instead.
        raise SourceAcquisitionError(
            "cleanup_required",
            "verified Git transaction garbage requires isolated cleanup",
            exit_status=status,
        )


def _initialize_or_open_repository(
    repository_store: Path,
    repo_url: str,
    *,
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
    acquire: bool,
) -> tuple[Path, GitRepository]:
    target, owner, repository_name = _repository_path(repository_store, repo_url)
    owner_root = _ensure_directory_child(repository_store, owner, create=acquire)
    target = owner_root / f"{repository_name}.git"
    repository_root = _ensure_directory_child(owner_root, target.name, create=acquire)
    needs_initialization = _directory_is_empty(repository_root)
    if needs_initialization:
        if not acquire:
            raise SourceAcquisitionError(
                "repository_missing",
                "a required repository has not been initialized",
                exit_status=4,
            )
        _run_git(
            git_executable,
            None,
            (
                "init",
                "--bare",
                "--object-format=sha1",
                str(repository_root),
            ),
            github_transport=github_transport,
            ssh_executable=ssh_executable,
            timeout_seconds=_GIT_SHORT_TIMEOUT_SECONDS,
        )
    _assert_recovery_state_clean(
        repository_root,
        status=3 if acquire else 4,
    )
    try:
        repository = GitRepository(
            repository_root,
            timeout_seconds=_GIT_SHORT_TIMEOUT_SECONDS,
            git_executable=git_executable,
        )
        repository.assert_bare_storage_safe()
    except GitFactError as error:
        raise SourceAcquisitionError(
            "repository_rejected",
            "a bare repository failed the Git fact boundary",
            exit_status=3 if acquire else 4,
        ) from error
    return repository_root, repository


def _assert_acquisition_config(
    repository_root: Path,
    *,
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
    status: int,
) -> None:
    result = _run_git(
        git_executable,
        repository_root,
        ("config", "--local", "--no-includes", "--name-only", "--null", "--list"),
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        timeout_seconds=_GIT_SHORT_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0 or result.stderr:
        raise SourceAcquisitionError(
            "repository_config_rejected",
            "local repository configuration cannot be verified",
            exit_status=status,
        )
    try:
        names = [
            item.decode("utf-8", errors="strict").casefold()
            for item in result.stdout.split(b"\0")
            if item
        ]
    except UnicodeDecodeError as error:
        raise SourceAcquisitionError(
            "repository_config_rejected",
            "local repository configuration is not UTF-8",
            exit_status=status,
        ) from error
    if (
        len(names) != len(set(names))
        or not set(names).issubset(_ALLOWED_LOCAL_CONFIG_KEYS)
        or "core.bare" not in names
    ):
        raise SourceAcquisitionError(
            "repository_config_rejected",
            "local repository configuration exceeds the fixed contract",
            exit_status=status,
        )
    bare = _run_git(
        git_executable,
        repository_root,
        ("config", "--local", "--no-includes", "--get", "core.bare"),
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        timeout_seconds=_GIT_SHORT_TIMEOUT_SECONDS,
        check=False,
    )
    if bare.returncode != 0 or bare.stderr or bare.stdout != b"true\n":
        raise SourceAcquisitionError(
            "repository_config_rejected",
            "source repositories must be bare",
            exit_status=status,
        )


def _read_vulngym_refs(
    repository_root: Path,
    *,
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
    status: int,
) -> dict[str, str]:
    result = _run_git(
        git_executable,
        repository_root,
        ("show-ref",),
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        timeout_seconds=_GIT_SHORT_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode == 1 and not result.stdout and not result.stderr:
        return {}
    if result.returncode != 0 or result.stderr:
        raise SourceAcquisitionError(
            "repository_refs_rejected",
            "repository refs cannot be verified",
            exit_status=status,
        )
    refs: dict[str, str] = {}
    try:
        lines = result.stdout.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise SourceAcquisitionError(
            "repository_refs_rejected",
            "repository refs are not canonical ASCII",
            exit_status=status,
        ) from error
    for line in lines:
        object_id, separator, ref_name = line.partition(" ")
        prefix = "refs/vulngym/"
        suffix = ref_name[len(prefix) :] if ref_name.startswith(prefix) else ""
        if (
            not separator
            or _SHA1_RE.fullmatch(object_id) is None
            or _SHA1_RE.fullmatch(suffix) is None
            or object_id != suffix
            or ref_name in refs
        ):
            raise SourceAcquisitionError(
                "repository_refs_rejected",
                "repository refs exceed the fixed acquisition namespace",
                exit_status=status,
            )
        refs[ref_name] = object_id
    return refs


def _expected_vulngym_refs(commits: Sequence[str]) -> dict[str, str]:
    return {f"refs/vulngym/{commit}": commit for commit in sorted(commits)}


def _assert_exact_vulngym_refs(
    refs: Mapping[str, str], commits: Sequence[str], *, status: int
) -> str:
    expected = _expected_vulngym_refs(commits)
    if dict(refs) != expected:
        raise SourceAcquisitionError(
            "ref_closure_mismatch",
            "repository refs do not exactly match the required commit set",
            exit_status=status,
        )
    payload = b"vulngym.source-acquisition.ref-inventory.v1\0" + b"".join(
        ref_name.encode("ascii")
        + b"\0"
        + object_id.encode("ascii")
        + b"\n"
        for ref_name, object_id in sorted(expected.items())
    )
    return _sha256(payload)


def _read_count_objects(
    repository_root: Path,
    *,
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
    status: int,
) -> dict[str, int]:
    result = _run_git(
        git_executable,
        repository_root,
        ("count-objects", "-v"),
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        timeout_seconds=_GIT_SHORT_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        raise SourceAcquisitionError(
            "count_objects_failed",
            "Git object storage counters could not be verified",
            exit_status=status,
        )
    try:
        lines = result.stdout.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise SourceAcquisitionError(
            "count_objects_failed",
            "Git object storage counters are not canonical ASCII",
            exit_status=status,
        ) from error
    values: dict[str, int] = {}
    for line in lines:
        name, separator, raw_value = line.partition(": ")
        if (
            not separator
            or name not in _COUNT_OBJECT_FIELDS
            or name in values
            or not raw_value.isascii()
            or not raw_value.isdecimal()
        ):
            raise SourceAcquisitionError(
                "count_objects_failed",
                "Git object storage counters exceed the fixed contract",
                exit_status=status,
            )
        values[name] = int(raw_value)
    if set(values) != _COUNT_OBJECT_FIELDS:
        raise SourceAcquisitionError(
            "count_objects_failed",
            "Git object storage counters are incomplete",
            exit_status=status,
        )
    if values["garbage"] != 0 or values["size-garbage"] != 0:
        raise SourceAcquisitionError(
            "object_storage_garbage",
            "Git object storage contains garbage",
            exit_status=status,
        )
    if values["prune-packable"] != 0:
        raise SourceAcquisitionError(
            "prune_packable_objects_rejected",
            "Git object storage contains redundant loose objects",
            exit_status=status,
        )
    if result.stderr:
        raise SourceAcquisitionError(
            "count_objects_failed",
            "Git object storage counters emitted unexpected diagnostics",
            exit_status=status,
        )
    return values


def _assert_packed_storage(
    counts: Mapping[str, int], *, status: int
) -> None:
    if counts["packs"] < 1 or counts["in-pack"] < 1:
        raise SourceAcquisitionError(
            "packed_storage_required",
            "source acquisition v4 requires packed storage for its verified MIDX",
            exit_status=status,
        )


def _run_full_reachability_fsck(
    repository_root: Path,
    *,
    commits: Sequence[str],
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
    status: int,
) -> None:
    result = _run_git(
        git_executable,
        repository_root,
        (
            "fsck",
            "--full",
            "--strict",
            "--unreachable",
            "--no-reflogs",
            "--no-progress",
            *sorted(commits),
        ),
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        timeout_seconds=_GIT_FSCK_TIMEOUT_SECONDS,
        check=False,
    )
    if result.returncode != 0:
        raise SourceAcquisitionError(
            "repository_fsck_failed",
            "Git fsck rejected a source object store",
            exit_status=status,
        )
    stdout_lines = result.stdout.splitlines()
    stderr_lines = result.stderr.splitlines()
    if any(
        line.startswith((b"unreachable ", b"dangling "))
        for line in (*stdout_lines, *stderr_lines)
    ):
        raise SourceAcquisitionError(
            "unreachable_objects_rejected",
            "Git object storage contains objects unreachable from allowed refs",
            exit_status=status,
        )
    if stdout_lines or any(
        not line.startswith(_FSCK_NOTICE_PREFIXES) for line in stderr_lines
    ):
        raise SourceAcquisitionError(
            "repository_fsck_output_rejected",
            "Git fsck emitted unexpected diagnostics",
            exit_status=status,
        )


def _object_hygiene_report(
    *,
    counts: Mapping[str, int],
    refs: Mapping[str, str],
    commits: Sequence[str],
    ref_inventory_sha256: str,
    storage_seal: GitStorageSeal,
) -> dict[str, object]:
    return {
        "all_objects_reachable": True,
        "alternates_absent": True,
        "bare_repository": True,
        "full_fsck": True,
        "garbage_count": counts["garbage"],
        "garbage_size_kib": counts["size-garbage"],
        "loose_object_count": counts["count"],
        "loose_object_size_kib": counts["size"],
        "multi_pack_index_present": True,
        "multi_pack_index_verified": True,
        "non_shallow": storage_seal.shallow_sha256 is None,
        "observed_ref_count": len(refs),
        "pack_count": counts["packs"],
        "pack_size_kib": counts["size-pack"],
        "packed_object_count": counts["in-pack"],
        "prune_packable_count": counts["prune-packable"],
        "promisor_absent": True,
        "stored_object_count": counts["count"] + counts["in-pack"],
        "ref_inventory_sha256": ref_inventory_sha256,
        "refs_closed": True,
        "replace_refs_absent": True,
        "required_ref_count": len(commits),
        "storage_inventory_sha256": storage_seal.object_inventory_sha256,
        "storage_object_entry_count": storage_seal.object_entry_count,
        "storage_object_total_bytes": storage_seal.object_total_bytes,
        "sha1_object_format": True,
        "unreachable_object_count": 0,
    }


def _repository_closure_v2(
    *,
    storage_seal: GitStorageSeal,
    refs: Mapping[str, str],
    counts: Mapping[str, int],
) -> _RepositoryClosureV2:
    return _RepositoryClosureV2(
        storage_seal=storage_seal,
        refs=tuple(sorted(refs.items())),
        counts=tuple(sorted(counts.items())),
    )


def _assert_all_repository_closures_unchanged(
    repository_roots: Mapping[str, Path],
    repositories: Mapping[str, GitRepository],
    groups: Mapping[str, Sequence[str]],
    expected: Mapping[str, _RepositoryClosureV2],
    *,
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
    status: int,
) -> None:
    """Recheck the complete authorized repository union without deletion."""

    if (
        set(repository_roots) != set(groups)
        or set(repositories) != set(groups)
        or set(expected) != set(groups)
    ):
        raise SourceAcquisitionError(
            "repository_closure_incomplete",
            "the all-repository closure set is incomplete",
            exit_status=status,
        )
    for repo_url in sorted(groups, key=lambda value: value.encode("utf-8")):
        repository_root = repository_roots[repo_url]
        repository = repositories[repo_url]
        commits = groups[repo_url]
        _assert_recovery_state_clean(repository_root, status=status)
        _assert_acquisition_config(
            repository_root,
            git_executable=git_executable,
            github_transport=github_transport,
            ssh_executable=ssh_executable,
            status=status,
        )
        _verify_multi_pack_index(
            repository_root,
            repository,
            git_executable=git_executable,
            github_transport=github_transport,
            ssh_executable=ssh_executable,
            status=status,
        )
        try:
            before = repository.assert_bare_storage_safe()
            if repository.history_is_shallow():
                raise SourceAcquisitionError(
                    "shallow_repository_rejected",
                    "source repositories must not be shallow",
                    exit_status=status,
                )
        except GitFactError as error:
            raise SourceAcquisitionError(
                "repository_rejected",
                "a repository failed its global closure recheck",
                exit_status=status,
            ) from error
        refs = _read_vulngym_refs(
            repository_root,
            git_executable=git_executable,
            github_transport=github_transport,
            ssh_executable=ssh_executable,
            status=status,
        )
        _assert_exact_vulngym_refs(refs, commits, status=status)
        counts = _read_count_objects(
            repository_root,
            git_executable=git_executable,
            github_transport=github_transport,
            ssh_executable=ssh_executable,
            status=status,
        )
        try:
            after = repository.assert_bare_storage_safe()
        except GitFactError as error:
            raise SourceAcquisitionError(
                "repository_rejected",
                "a repository changed during its global closure recheck",
                exit_status=status,
            ) from error
        current = _repository_closure_v2(
            storage_seal=after,
            refs=refs,
            counts=counts,
        )
        if before != after or current != expected[repo_url]:
            raise SourceAcquisitionError(
                "repository_changed",
                "a repository changed after its individual verification",
                exit_status=status,
            )


def _fetch_missing_commits(
    repository_root: Path,
    repository: GitRepository,
    *,
    repo_url: str,
    commits: Sequence[str],
    refs: Mapping[str, str],
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
) -> None:
    required = tuple(sorted(commits))
    missing = tuple(
        commit
        for commit in required
        if refs.get(f"refs/vulngym/{commit}") != commit
    )
    fetch_url = github_fetch_url_v1(repo_url, github_transport)
    all_refspecs = tuple(
        f"+{commit}:refs/vulngym/{commit}" for commit in required
    )
    started = time.monotonic()

    def retry_repository_state_unchanged(
        before: GitStorageSeal,
        before_refs: Mapping[str, str],
        after: GitStorageSeal,
        after_refs: Mapping[str, str],
    ) -> bool:
        # Aggregate object counts cannot prove append-only growth: a concurrent
        # replacement plus a larger new pack could otherwise look monotonic.
        # Spend the single retry token only when the complete path-free storage
        # seal and the independently parsed logical refs are byte-for-byte stable.
        # A failed command that persisted any repository mutation is resumable by
        # a later full invocation, but is never retried in place.
        return before == after and dict(before_refs) == dict(after_refs)

    def verify_segment(
        *, verify_commit_objects: bool = False
    ) -> tuple[GitStorageSeal, dict[str, str]]:
        _assert_recovery_state_clean(repository_root, status=3)
        try:
            # The constructor and initialization gate already proved that the
            # repository is bare.  A segment seal rechecks every protected
            # directory, critical metadata file, ref and object-store entry
            # without spawning redundant rev-parse/config processes.
            seal = repository.capture_storage_seal()
        except GitFactError as error:
            raise SourceAcquisitionError(
                "repository_rejected",
                "a fetch segment failed its storage seal",
                exit_status=3,
            ) from error
        observed = _read_vulngym_refs(
            repository_root,
            git_executable=git_executable,
            github_transport=github_transport,
            ssh_executable=ssh_executable,
            status=3,
        )
        try:
            if verify_commit_objects:
                for commit in required:
                    if observed.get(f"refs/vulngym/{commit}") != commit:
                        continue
                    repository.commit_tree(commit)
            closed = repository.capture_storage_seal()
        except GitFactError as error:
            raise SourceAcquisitionError(
                "segment_object_verification_failed",
                "a completed fetch segment failed object verification",
                exit_status=3,
            ) from error
        if closed != seal:
            raise SourceAcquisitionError(
                "repository_changed",
                "repository storage changed during segment verification",
                exit_status=3,
            )
        return seal, observed

    transient_retries_remaining = _MAX_TRANSIENT_FETCH_RETRIES_PER_REPOSITORY

    def run_segment(
        arguments: tuple[str, ...],
        *,
        before: GitStorageSeal,
        before_refs: Mapping[str, str],
    ) -> None:
        nonlocal transient_retries_remaining
        while True:
            remaining = _MAX_TOTAL_NETWORK_SECONDS - (time.monotonic() - started)
            if remaining <= 0:
                raise SourceAcquisitionError(
                    "fetch_budget_exhausted",
                    "segmented fetch exceeded its total network time budget",
                    exit_status=3,
                )
            _assert_recovery_state_clean(repository_root, status=3)
            try:
                _run_git(
                    git_executable,
                    repository_root,
                    arguments,
                    github_transport=github_transport,
                    ssh_executable=ssh_executable,
                    timeout_seconds=min(_GIT_NETWORK_TIMEOUT_SECONDS, remaining),
                )
            except BaseException as error:
                # The bounded runner has reaped the Git parent. If Git left any
                # transaction name, portable conditional cleanup cannot prove
                # the name still denotes that inode; cleanup_required therefore
                # takes precedence even for an interrupt or non-retryable error.
                try:
                    _assert_recovery_state_clean(repository_root, status=3)
                except SourceAcquisitionError as cleanup_error:
                    raise cleanup_error from error
                if (
                    not isinstance(error, SourceAcquisitionError)
                    or error.code != "git_command_failed"
                    or transient_retries_remaining == 0
                ):
                    raise
                failed, failed_refs = verify_segment()
                if not retry_repository_state_unchanged(
                    before, before_refs, failed, failed_refs
                ):
                    raise SourceAcquisitionError(
                        "repository_changed",
                        "a failed fetch changed the sealed repository state",
                        exit_status=3,
                    ) from error
                transient_retries_remaining -= 1
                continue
            if time.monotonic() - started > _MAX_TOTAL_NETWORK_SECONDS:
                raise SourceAcquisitionError(
                    "fetch_budget_exhausted",
                    "segmented fetch exceeded its total network time budget",
                    exit_status=3,
                )
            _assert_recovery_state_clean(repository_root, status=3)
            return

    if missing:
        before, baseline_refs = verify_segment()
        if dict(baseline_refs) != dict(refs):
            raise SourceAcquisitionError(
                "repository_changed",
                "repository refs changed before the initial fetch",
                exit_status=3,
            )
        initial_refspecs = tuple(
            f"+{commit}:refs/vulngym/{commit}" for commit in missing
        )
        run_segment(
            (
                "fetch",
                "--atomic",
                f"--depth={_FETCH_DEPTH_STEP}",
                "--force",
                "--no-progress",
                "--no-recurse-submodules",
                "--no-tags",
                "--no-write-fetch-head",
                fetch_url,
                *initial_refspecs,
            ),
            before=before,
            before_refs=baseline_refs,
        )
        _, refs = verify_segment()
        if any(
            refs.get(f"refs/vulngym/{commit}") != commit for commit in required
        ):
            raise SourceAcquisitionError(
                "ref_binding_mismatch",
                "the initial fetch did not atomically bind all required refs",
                exit_status=3,
            )

    rounds = 0
    while repository.history_is_shallow():
        if rounds >= _MAX_DEEPEN_ROUNDS:
            raise SourceAcquisitionError(
                "fetch_round_limit",
                "segmented fetch exceeded its fixed deepen-round limit",
                exit_status=3,
            )
        before, refs = verify_segment()
        if any(
            refs.get(f"refs/vulngym/{commit}") != commit for commit in required
        ):
            raise SourceAcquisitionError(
                "ref_binding_mismatch",
                "a required ref was absent before deepening",
                exit_status=3,
            )
        run_segment(
            (
                "fetch",
                "--atomic",
                f"--deepen={_FETCH_DEPTH_STEP}",
                "--force",
                "--no-progress",
                "--no-recurse-submodules",
                "--no-tags",
                "--no-write-fetch-head",
                fetch_url,
                *all_refspecs,
            ),
            before=before,
            before_refs=refs,
        )
        after, after_refs = verify_segment()
        rounds += 1
        boundary_advanced = after.shallow_sha256 != before.shallow_sha256
        refs_advanced = after_refs != refs
        objects_advanced = (
            after.object_entry_count,
            after.object_total_bytes,
            after.object_inventory_sha256,
        ) != (
            before.object_entry_count,
            before.object_total_bytes,
            before.object_inventory_sha256,
        )
        # Exact vulngym refs must remain fixed while the shallow boundary and
        # object inventory advance.  A still-shallow repository with the same
        # boundary is not progress even if Git merely repacked identical data.
        if after.shallow_sha256 is not None and not boundary_advanced:
            raise SourceAcquisitionError(
                "fetch_no_progress",
                "remote history did not advance the shallow/ref/object state",
                exit_status=3,
            )
        if refs_advanced:
            raise SourceAcquisitionError(
                "ref_binding_mismatch",
                "a required ref changed while deepening",
                exit_status=3,
            )
        if after.shallow_sha256 is not None and not objects_advanced:
            # Changing only the shallow marker can expose already-present
            # objects and is valid.  This branch is intentionally documentary:
            # the fixed boundary comparison above is the progress authority.
            pass

    _write_verified_multi_pack_index(
        repository_root,
        repository,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
    )
    _, final_refs = verify_segment(verify_commit_objects=True)
    if any(
        final_refs.get(f"refs/vulngym/{commit}") != commit for commit in required
    ):
        raise SourceAcquisitionError(
            "ref_binding_mismatch",
            "segmented fetch did not close every exact ref",
            exit_status=3,
        )


def _write_verified_multi_pack_index(
    repository_root: Path,
    repository: GitRepository,
    *,
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
) -> None:
    """Write only derived pack lookup metadata after full history is present."""

    _assert_recovery_state_clean(repository_root, status=3)
    if repository.history_is_shallow():
        raise SourceAcquisitionError(
            "shallow_repository_rejected",
            "multi-pack indexing requires complete repository history",
            exit_status=3,
        )
    refs_before = _read_vulngym_refs(
        repository_root,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=3,
    )
    counts_before = _read_count_objects(
        repository_root,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=3,
    )
    _assert_packed_storage(counts_before, status=3)
    pack_payload_before = _capture_pack_payload_inventory(
        repository_root, status=3
    )
    _run_multi_pack_index_command(
        repository_root,
        ("multi-pack-index", "write"),
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=3,
        error_code="multi_pack_index_write_failed",
    )
    _assert_multi_pack_index_file(repository_root, status=3)

    refs_after = _read_vulngym_refs(
        repository_root,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=3,
    )
    counts_after = _read_count_objects(
        repository_root,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=3,
    )
    pack_payload_after = _capture_pack_payload_inventory(
        repository_root, status=3
    )
    if (
        repository.history_is_shallow()
        or refs_after != refs_before
        or counts_after != counts_before
        or pack_payload_after != pack_payload_before
    ):
        raise SourceAcquisitionError(
            "repository_changed",
            "multi-pack indexing changed repository facts",
            exit_status=3,
        )
    _verify_multi_pack_index(
        repository_root,
        repository,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=3,
    )


def _capture_pack_payload_inventory(
    repository_root: Path, *, status: int
) -> tuple[int, int, str]:
    """Seal pack payload metadata while excluding the derived MIDX file."""

    pack_root = repository_root / "objects" / "pack"
    records: list[bytes] = []
    total_bytes = 0
    try:
        with os.scandir(pack_root) as entries:
            for entry in entries:
                name = entry.name
                if name == _MULTI_PACK_INDEX_NAME:
                    continue
                if name.startswith(_MULTI_PACK_INDEX_NAME):
                    raise SourceAcquisitionError(
                        "multi_pack_index_layout_rejected",
                        "incremental or bitmap multi-pack indexes are forbidden",
                        exit_status=status,
                    )
                state = os.lstat(entry.path)
                reparse_flag = getattr(
                    stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
                )
                if (
                    not stat.S_ISREG(state.st_mode)
                    or stat.S_ISLNK(state.st_mode)
                    or bool(
                        getattr(state, "st_file_attributes", 0)
                        & reparse_flag
                    )
                    or state.st_nlink != 1
                ):
                    raise SourceAcquisitionError(
                        "pack_payload_rejected",
                        "pack payload metadata is not a direct regular file",
                        exit_status=status,
                    )
                if len(records) >= _MAX_RECOVERY_ARTIFACTS * 16:
                    raise SourceAcquisitionError(
                        "pack_inventory_limit",
                        "pack payload inventory exceeds its fixed entry budget",
                        exit_status=status,
                    )
                total_bytes += state.st_size
                identity = (
                    state.st_dev,
                    state.st_ino,
                    state.st_size,
                    getattr(state, "st_mtime_ns", None),
                )
                records.append(
                    name.encode("utf-8", errors="strict")
                    + b"\0"
                    + b":".join(
                        str(value).encode("ascii") for value in identity
                    )
                )
    except SourceAcquisitionError:
        raise
    except (OSError, UnicodeError) as error:
        raise SourceAcquisitionError(
            "pack_payload_rejected",
            "pack payload metadata cannot be inspected safely",
            exit_status=status,
        ) from error
    return (
        len(records),
        total_bytes,
        hashlib.sha256(b"\0".join(sorted(records))).hexdigest(),
    )


def _assert_multi_pack_index_file(
    repository_root: Path, *, status: int
) -> tuple[int, int, int, int | None]:
    path = repository_root / "objects" / "pack" / _MULTI_PACK_INDEX_NAME
    try:
        state = os.lstat(path)
    except FileNotFoundError as error:
        raise SourceAcquisitionError(
            "multi_pack_index_missing",
            "the verified multi-pack index is absent",
            exit_status=status,
        ) from error
    except OSError as error:
        raise SourceAcquisitionError(
            "multi_pack_index_rejected",
            "the multi-pack index cannot be inspected",
            exit_status=status,
        ) from error
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(state.st_mode)
        or stat.S_ISLNK(state.st_mode)
        or bool(getattr(state, "st_file_attributes", 0) & reparse_flag)
        or state.st_nlink != 1
    ):
        raise SourceAcquisitionError(
            "multi_pack_index_rejected",
            "the multi-pack index is not a direct single-link regular file",
            exit_status=status,
        )
    return (
        state.st_dev,
        state.st_ino,
        state.st_size,
        getattr(state, "st_mtime_ns", None),
    )


def _run_multi_pack_index_command(
    repository_root: Path,
    arguments: tuple[str, ...],
    *,
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
    status: int,
    error_code: str,
) -> None:
    _assert_recovery_state_clean(repository_root, status=status)
    try:
        result = _run_git(
            git_executable,
            repository_root,
            arguments,
            github_transport=github_transport,
            ssh_executable=ssh_executable,
            timeout_seconds=_GIT_FSCK_TIMEOUT_SECONDS,
            check=False,
        )
    except BaseException as error:
        try:
            _assert_recovery_state_clean(repository_root, status=status)
        except SourceAcquisitionError as cleanup_error:
            raise cleanup_error from error
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise SourceAcquisitionError(
            error_code,
            "a bounded multi-pack index operation failed",
            exit_status=status,
        ) from error
    command_error: SourceAcquisitionError | None = None
    if result.returncode != 0 or result.stdout or result.stderr:
        command_error = SourceAcquisitionError(
            error_code,
            "Git rejected a multi-pack index operation",
            exit_status=status,
        )
    try:
        _assert_recovery_state_clean(repository_root, status=status)
    except SourceAcquisitionError as cleanup_error:
        if command_error is not None:
            raise cleanup_error from command_error
        raise
    if command_error is not None:
        raise command_error


def _verify_multi_pack_index(
    repository_root: Path,
    repository: GitRepository,
    *,
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
    status: int,
) -> None:
    """Verify the required MIDX without mutating a prepared repository."""

    _assert_recovery_state_clean(repository_root, status=status)
    pack_payload_before = _capture_pack_payload_inventory(
        repository_root, status=status
    )
    index_before = _assert_multi_pack_index_file(
        repository_root, status=status
    )
    try:
        storage_before = repository.capture_storage_seal()
    except GitFactError as error:
        raise SourceAcquisitionError(
            "repository_rejected",
            "repository storage failed its multi-pack index seal",
            exit_status=status,
        ) from error
    _run_multi_pack_index_command(
        repository_root,
        ("multi-pack-index", "verify"),
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=status,
        error_code="multi_pack_index_verify_failed",
    )
    index_after = _assert_multi_pack_index_file(repository_root, status=status)
    pack_payload_after = _capture_pack_payload_inventory(
        repository_root, status=status
    )
    try:
        storage_after = repository.capture_storage_seal()
    except GitFactError as error:
        raise SourceAcquisitionError(
            "repository_rejected",
            "repository storage changed during multi-pack index verification",
            exit_status=status,
        ) from error
    if (
        index_after != index_before
        or pack_payload_after != pack_payload_before
        or storage_after != storage_before
    ):
        raise SourceAcquisitionError(
            "repository_changed",
            "repository storage changed during multi-pack index verification",
            exit_status=status,
        )


def _verify_repository(
    repository_root: Path,
    repository: GitRepository,
    commits: Sequence[str],
    *,
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
    status: int,
) -> tuple[
    dict[str, SealedSnapshotSourceAudit],
    dict[str, object],
    _RepositoryClosureV2,
]:
    try:
        _assert_recovery_state_clean(repository_root, status=status)
        before_verification = repository.assert_bare_storage_safe()
        if repository.history_is_shallow():
            raise SourceAcquisitionError(
                "shallow_repository_rejected",
                "source repositories must not be shallow",
                exit_status=status,
            )
    except GitFactError as error:
        raise SourceAcquisitionError(
            "repository_rejected",
            "a repository failed its storage verification",
            exit_status=status,
        ) from error
    refs_before = _read_vulngym_refs(
        repository_root,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=status,
    )
    ref_inventory_sha256 = _assert_exact_vulngym_refs(
        refs_before,
        commits,
        status=status,
    )
    counts_before = _read_count_objects(
        repository_root,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=status,
    )
    _assert_packed_storage(counts_before, status=status)
    _verify_multi_pack_index(
        repository_root,
        repository,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=status,
    )
    _run_full_reachability_fsck(
        repository_root,
        commits=commits,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=status,
    )
    audits: dict[str, SealedSnapshotSourceAudit] = {}
    blob_cache: dict[str, tuple[int, bool | None]] = {}
    try:
        for commit in commits:
            audits[commit] = audit_sealed_snapshot_source(
                repository,
                commit,
                blob_cache=blob_cache,
            )
    except (GitFactError, SealedSnapshotError) as error:
        raise SourceAcquisitionError(
            "commit_verification_failed",
            "an exact commit failed cat-file verification",
            exit_status=status,
        ) from error
    refs_after = _read_vulngym_refs(
        repository_root,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=status,
    )
    after_ref_inventory_sha256 = _assert_exact_vulngym_refs(
        refs_after,
        commits,
        status=status,
    )
    counts_after = _read_count_objects(
        repository_root,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=status,
    )
    try:
        after_verification = repository.assert_bare_storage_safe()
    except GitFactError as error:
        raise SourceAcquisitionError(
            "repository_rejected",
            "repository storage changed during object verification",
            exit_status=status,
        ) from error
    if (
        after_verification != before_verification
        or refs_after != refs_before
        or after_ref_inventory_sha256 != ref_inventory_sha256
        or counts_after != counts_before
    ):
        raise SourceAcquisitionError(
            "repository_changed",
            "repository storage changed during object verification",
            exit_status=status,
        )
    return (
        audits,
        _object_hygiene_report(
            counts=counts_after,
            refs=refs_after,
            commits=commits,
            ref_inventory_sha256=after_ref_inventory_sha256,
            storage_seal=after_verification,
        ),
        _repository_closure_v2(
            storage_seal=after_verification,
            refs=refs_after,
            counts=counts_after,
        ),
    )


def _acquisition_report_payload(
    exports: Sequence[VerifiedTaskExport],
    source_maps: Sequence[SnapshotSourceMapDocument],
    repository_audits: Mapping[
        str, Mapping[str, SealedSnapshotSourceAudit]
    ],
    repository_hygiene: Mapping[str, Mapping[str, object]],
    *,
    github_transport: Literal["https", "ssh"],
    git_version: str,
) -> bytes:
    source_maps_by_split = {document.split: document for document in source_maps}
    if set(source_maps_by_split) != {export.split for export in exports}:
        raise SourceAcquisitionError(
            "source_map_rejected",
            "source-map documents do not close over task exports",
            exit_status=3,
        )
    export_records = [
        {
            "source_map_sha256": source_maps_by_split[export.split].sha256,
            "split": export.split,
            "task_count": len(export.tasks),
            "tasks_sha256": export.tasks_sha256,
        }
        for export in exports
    ]
    repository_records = [
        {
            "commits": [
                audit.to_dict()
                for _, audit in sorted(commits.items())
            ],
            "object_hygiene": dict(repository_hygiene[repo_url]),
            "repo_url": repo_url,
        }
        for repo_url, commits in sorted(
            repository_audits.items(), key=lambda item: item[0].encode("utf-8")
        )
    ]
    audits = [
        audit
        for commits in repository_audits.values()
        for audit in commits.values()
    ]
    ready_task_count = sum(audit.ready for audit in audits)
    blocked_task_count = len(audits) - ready_task_count
    return _canonical_json(
        {
            "contract_version": SOURCE_ACQUISITION_CONTRACT_VERSION,
            "blocked_task_count": blocked_task_count,
            "exports": export_records,
            "fetch_protocol": {
                "deepen_by": _FETCH_DEPTH_STEP,
                "initial_depth": _FETCH_DEPTH_STEP,
                "max_deepen_rounds": _MAX_DEEPEN_ROUNDS,
                "max_total_network_seconds": int(_MAX_TOTAL_NETWORK_SECONDS),
                "max_transient_fetch_retries_per_repository": (
                    _MAX_TRANSIENT_FETCH_RETRIES_PER_REPOSITORY
                ),
                "requires_exact_ref_closure": True,
                "requires_final_full_fsck": True,
                "requires_final_non_shallow": True,
                "requires_strict_git_output": True,
                "requires_zero_garbage": True,
                "requires_zero_prune_packable": True,
                "requires_zero_unreachable_objects": True,
                "requires_final_verified_multi_pack_index": True,
                "retry_requires_unchanged_repository_seal": True,
                "writes_verified_multi_pack_index": True,
            },
            "github_transport": github_transport,
            "git_version": git_version,
            "kind": "source_acquisition_report",
            "profile_id": PROFILE_ID,
            "public_manifest_sha256": PROFILE_MANIFEST_SHA256,
            "ready": blocked_task_count == 0,
            "ready_task_count": ready_task_count,
            "repositories": repository_records,
            "repository_count": len(repository_records),
            "task_count": sum(len(export.tasks) for export in exports),
        }
    ) + b"\n"


def _output_is_stably_absent(
    output_dir: Path,
    checked_parent: Sequence[tuple[Path, tuple[int, int]]],
) -> bool:
    try:
        _assert_directory_chain(checked_parent, status=5)
        os.lstat(output_dir)
    except FileNotFoundError:
        try:
            _assert_directory_chain(checked_parent, status=5)
            os.lstat(output_dir)
        except FileNotFoundError:
            return True
        except (OSError, SnapshotBatchError):
            return False
    except (OSError, SnapshotBatchError):
        return False
    return False


def _verify_or_publish_output(
    output_dir: Path,
    files: Mapping[str, bytes],
    *,
    protected_roots: Sequence[Path],
    publish: bool,
) -> Path:
    publication_error: BaseException | None = None
    published_now = False
    checked_parent: tuple[tuple[Path, tuple[int, int]], ...] | None = None
    try:
        os.lstat(output_dir)
    except FileNotFoundError:
        if not publish:
            raise SourceAcquisitionError(
                "output_missing", "acquisition output is absent", exit_status=4
            )
        try:
            checked_parent = _checked_directory_chain(output_dir.parent, status=5)
        except SnapshotBatchError as error:
            raise SourceAcquisitionError(
                "output_publication_failed",
                "acquisition output parent cannot be trusted",
                exit_status=5,
            ) from error
        try:
            _publish_directory(
                output_dir,
                files,
                protected_roots=protected_roots,
            )
            published_now = True
        except BaseException as error:
            publication_error = error
    except OSError as error:
        raise SourceAcquisitionError(
            "output_verification_failed",
            "acquisition output cannot be inspected",
            exit_status=4,
        ) from error

    try:
        output = _canonical_existing_path(output_dir, directory=True, status=4)
        checked = _checked_directory_chain(output, status=4)
        _fixed_names(output, set(files), status=4)
        for name, expected in files.items():
            observed = _read_stable_file(
                output / name,
                max(_MAX_OUTPUT_FILE_BYTES, len(expected)),
                status=4,
            )
            if not hmac.compare_digest(observed, expected):
                raise SourceAcquisitionError(
                    "output_binding_mismatch",
                    "acquisition output does not match verified source facts",
                    exit_status=4,
                )
        _assert_directory_chain(checked, status=4)
        return output
    except BaseException as error:
        if publication_error is not None or published_now:
            if (
                isinstance(publication_error, KeyboardInterrupt)
                and not bool(getattr(publication_error, "committed", False))
                and checked_parent is not None
                and _output_is_stably_absent(output_dir, checked_parent)
            ):
                raise publication_error
            raise SourceAcquisitionError(
                "publication_uncertain",
                "acquisition output may be committed but is not verified",
                exit_status=5,
            ) from (
                publication_error if publication_error is not None else error
            )
        if isinstance(error, SourceAcquisitionError):
            raise
        if isinstance(error, SnapshotBatchError):
            raise SourceAcquisitionError(
                "output_verification_failed",
                "acquisition output failed independent readback",
                exit_status=4,
            ) from error
        raise


def _prepare_or_verify_source_acquisition(
    inputs: Iterable[SourceAcquisitionInput],
    *,
    repository_store: Path,
    output_dir: Path,
    git_executable: Path,
    github_transport: Literal["https", "ssh"],
    ssh_executable: Path | None,
    acquire: bool,
) -> SourceAcquisitionSummary:
    exports = _load_exports(inputs)
    if (
        type(github_transport) is not str
        or github_transport not in GITHUB_TRANSPORTS
    ):
        raise SourceAcquisitionError(
            "invalid_transport", "GitHub transport must be https or ssh", exit_status=2
        )
    git = _canonical_executable(git_executable, name="Git")
    if github_transport == "ssh":
        if ssh_executable is None:
            raise SourceAcquisitionError(
                "ssh_executable_required",
                "SSH transport requires an explicit SSH executable",
                exit_status=2,
            )
        ssh = _canonical_executable(ssh_executable, name="SSH")
    elif ssh_executable is not None:
        raise SourceAcquisitionError(
            "unused_ssh_executable",
            "HTTPS transport does not accept an SSH executable",
            exit_status=2,
        )
    else:
        ssh = None
    git_version = _read_git_version(
        git,
        github_transport=github_transport,
        ssh_executable=ssh,
    )
    try:
        store = _canonical_existing_path(repository_store, directory=True, status=2)
    except SnapshotBatchError as error:
        raise SourceAcquisitionError(
            "repository_store_rejected",
            "repository store must be an existing canonical directory",
            exit_status=2,
        ) from error
    output_exists = False
    try:
        os.lstat(output_dir)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise SourceAcquisitionError(
            "output_rejected", "output path cannot be inspected", exit_status=2
        ) from error
    else:
        output_exists = True
    try:
        for export in exports:
            if paths_overlap_v1(
                store,
                export.root,
                left_exists=True,
                right_directory=True,
            ):
                raise SourceAcquisitionError(
                    "path_overlap",
                    "repository store overlaps a task export",
                    exit_status=2,
                )
            if paths_overlap_v1(
                output_dir,
                export.root,
                left_exists=output_exists,
                right_directory=True,
            ):
                raise SourceAcquisitionError(
                    "path_overlap", "output overlaps a task export", exit_status=2
                )
        if paths_overlap_v1(
            output_dir,
            store,
            left_exists=output_exists,
            right_directory=True,
        ):
            raise SourceAcquisitionError(
                "path_overlap", "output overlaps the repository store", exit_status=2
            )
    except SnapshotBatchError as error:
        raise SourceAcquisitionError(
            "path_rejected", "trusted paths failed canonicalization", exit_status=2
        ) from error

    groups = _repository_groups(exports)
    # Different URL spellings must never alias the same owner/repository path
    # on case-insensitive hosts.
    derived_paths: dict[str, str] = {}
    for repo_url in groups:
        relative = str(_repository_path(store, repo_url)[0].relative_to(store))
        prior = derived_paths.setdefault(os.path.normcase(relative), repo_url)
        if prior != repo_url:
            raise SourceAcquisitionError(
                "repository_path_collision",
                "repository identities collide on the local filesystem",
                exit_status=2,
            )

    source_paths: dict[str, Path] = {}
    source_repositories: dict[str, GitRepository] = {}
    source_audits: dict[str, dict[str, SealedSnapshotSourceAudit]] = {}
    source_hygiene: dict[str, dict[str, object]] = {}
    source_closures: dict[str, _RepositoryClosureV2] = {}
    for repo_url, commits in groups.items():
        repository_root, repository = _initialize_or_open_repository(
            store,
            repo_url,
            git_executable=git,
            github_transport=github_transport,
            ssh_executable=ssh,
            acquire=acquire,
        )
        _assert_acquisition_config(
            repository_root,
            git_executable=git,
            github_transport=github_transport,
            ssh_executable=ssh,
            status=3 if acquire else 4,
        )
        refs = _read_vulngym_refs(
            repository_root,
            git_executable=git,
            github_transport=github_transport,
            ssh_executable=ssh,
            status=3 if acquire else 4,
        )
        if acquire:
            _fetch_missing_commits(
                repository_root,
                repository,
                repo_url=repo_url,
                commits=commits,
                refs=refs,
                git_executable=git,
                github_transport=github_transport,
                ssh_executable=ssh,
            )
        _assert_acquisition_config(
            repository_root,
            git_executable=git,
            github_transport=github_transport,
            ssh_executable=ssh,
            status=3 if acquire else 4,
        )
        (
            source_audits[repo_url],
            source_hygiene[repo_url],
            source_closures[repo_url],
        ) = _verify_repository(
            repository_root,
            repository,
            commits,
            git_executable=git,
            github_transport=github_transport,
            ssh_executable=ssh,
            status=3 if acquire else 4,
        )
        source_paths[repo_url] = repository_root
        source_repositories[repo_url] = repository

    documents: list[SnapshotSourceMapDocument] = []
    try:
        for export in exports:
            documents.append(
                build_snapshot_source_map_document(
                    export,
                    {
                        (task.repo_url, task.commit): source_paths[task.repo_url]
                        for task in export.tasks
                    },
                )
            )
    except SnapshotBatchError as error:
        raise SourceAcquisitionError(
            "source_map_rejected",
            "source-map construction failed its shared contract",
            exit_status=3 if acquire else 4,
        ) from error
    _assert_all_repository_closures_unchanged(
        source_paths,
        source_repositories,
        groups,
        source_closures,
        git_executable=git,
        github_transport=github_transport,
        ssh_executable=ssh,
        status=3 if acquire else 4,
    )
    report_payload = _acquisition_report_payload(
        exports,
        documents,
        source_audits,
        source_hygiene,
        github_transport=github_transport,
        git_version=git_version,
    )
    files = {
        SOURCE_MAP_FILE_NAMES[document.split]: document.payload
        for document in documents
    }
    files[SOURCE_ACQUISITION_REPORT_NAME] = report_payload
    summaries = tuple(
        AcquiredSourceMapSummary(
            split=document.split,
            task_count=document.task_count,
            tasks_sha256=document.tasks_sha256,
            source_map_sha256=document.sha256,
        )
        for document in documents
    )
    audits = [
        audit
        for commits in source_audits.values()
        for audit in commits.values()
    ]
    ready_task_count = sum(audit.ready for audit in audits)
    blocked_task_count = len(audits) - ready_task_count
    summary = SourceAcquisitionSummary(
        github_transport=github_transport,
        repository_count=len(groups),
        task_count=sum(len(export.tasks) for export in exports),
        ready=blocked_task_count == 0,
        ready_task_count=ready_task_count,
        blocked_task_count=blocked_task_count,
        acquisition_report_sha256=_sha256(report_payload),
        source_maps=summaries,
    )
    output = _verify_or_publish_output(
        output_dir,
        files,
        protected_roots=(store, *(export.root for export in exports)),
        publish=acquire,
    )
    try:
        try:
            for export, document in zip(exports, documents):
                load_verified_snapshot_source_map(
                    output / SOURCE_MAP_FILE_NAMES[export.split],
                    expected_source_map_sha256=document.sha256,
                    task_export=export,
                )
        except SnapshotBatchError as error:
            raise SourceAcquisitionError(
                "source_map_readback_failed",
                "a published source map failed shared-contract readback",
                exit_status=4,
            ) from error

        _assert_all_repository_closures_unchanged(
            source_paths,
            source_repositories,
            groups,
            source_closures,
            git_executable=git,
            github_transport=github_transport,
            ssh_executable=ssh,
            status=4,
        )
    except BaseException as error:
        if acquire and not output_exists:
            raise SourceAcquisitionError(
                "publication_uncertain",
                (
                    "acquisition output may be committed but repository closure "
                    "is not verified"
                ),
                exit_status=5,
            ) from error
        raise
    return summary


def prepare_source_acquisition(
    inputs: Iterable[SourceAcquisitionInput],
    *,
    repository_store: Path,
    output_dir: Path,
    git_executable: Path,
    github_transport: Literal["https", "ssh"] = "https",
    ssh_executable: Path | None = None,
) -> SourceAcquisitionSummary:
    """Acquire and publish one complete authorized input union.

    ``inputs`` is the complete authorization for ``repository_store`` in this
    run.  Reusing one store with a disjoint test-only or train-only input is
    unsupported; exact ref closure will reject objects authorized only by an
    omitted split.  The official 70-task operation supplies both splits once.
    """

    return _prepare_or_verify_source_acquisition(
        inputs,
        repository_store=repository_store,
        output_dir=output_dir,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        acquire=True,
    )


def verify_source_acquisition(
    inputs: Iterable[SourceAcquisitionInput],
    *,
    repository_store: Path,
    output_dir: Path,
    git_executable: Path,
    github_transport: Literal["https", "ssh"] = "https",
    ssh_executable: Path | None = None,
) -> SourceAcquisitionSummary:
    """Verify one complete authorized input union without fetching.

    As with preparation, callers must supply the full test+train authorization
    union for a combined store; split-by-split reuse of that store is rejected.
    """

    return _prepare_or_verify_source_acquisition(
        inputs,
        repository_store=repository_store,
        output_dir=output_dir,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        acquire=False,
    )


__all__ = [
    "AcquiredSourceMapSummary",
    "GITHUB_TRANSPORTS",
    "SOURCE_ACQUISITION_CONTRACT_VERSION",
    "SOURCE_ACQUISITION_REPORT_NAME",
    "SOURCE_NOT_READY_EXIT_STATUS",
    "SOURCE_MAP_FILE_NAMES",
    "SourceAcquisitionError",
    "SourceAcquisitionInput",
    "SourceAcquisitionSummary",
    "github_fetch_url_v1",
    "prepare_source_acquisition",
    "verify_source_acquisition",
]
