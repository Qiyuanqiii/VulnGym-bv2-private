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
    "vulngym.source-acquisition.v1"
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
_GITHUB_PREFIX: Final[str] = "https://github.com/"
_MAX_OUTPUT_FILE_BYTES: Final[int] = 8 * 1024 * 1024
_GIT_SHORT_TIMEOUT_SECONDS: Final[float] = 120.0
_GIT_NETWORK_TIMEOUT_SECONDS: Final[float] = 60.0 * 60.0
_GIT_FSCK_TIMEOUT_SECONDS: Final[float] = 60.0 * 60.0
_GIT_MAX_STDOUT_BYTES: Final[int] = 16 * 1024 * 1024
_GIT_MAX_STDERR_BYTES: Final[int] = 4 * 1024 * 1024
_FETCH_DEPTH_STEP: Final[int] = 32
_MAX_DEEPEN_ROUNDS: Final[int] = 2_048
_MAX_TOTAL_NETWORK_SECONDS: Final[float] = 6.0 * 60.0 * 60.0
_MAX_RECOVERY_ARTIFACTS: Final[int] = 256
_MAX_RECOVERY_ARTIFACT_BYTES: Final[int] = 4 * 1024 * 1024 * 1024
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
        command = [
            str(ssh_executable),
            "-F",
            os.devnull,
            "-oBatchMode=yes",
            "-oNumberOfPasswordPrompts=0",
            "-oProxyCommand=none",
            "-oProxyJump=none",
            "-oStrictHostKeyChecking=yes",
            "-oConnectTimeout=30",
        ]
        environment["GIT_SSH_COMMAND"] = (
            subprocess.list2cmdline(command) if os.name == "nt" else shlex.join(command)
        )
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

    def run_segment(arguments: tuple[str, ...]) -> None:
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
        except SourceAcquisitionError as error:
            # The bounded runner has reaped the Git parent. If Git left any
            # transaction name, portable conditional cleanup cannot prove the
            # name still denotes that inode; report cleanup_required instead.
            try:
                _assert_recovery_state_clean(repository_root, status=3)
            except SourceAcquisitionError as cleanup_error:
                raise cleanup_error from error
            raise
        if time.monotonic() - started > _MAX_TOTAL_NETWORK_SECONDS:
            raise SourceAcquisitionError(
                "fetch_budget_exhausted",
                "segmented fetch exceeded its total network time budget",
                exit_status=3,
            )
        _assert_recovery_state_clean(repository_root, status=3)

    if missing:
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
            )
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
            )
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

    _, final_refs = verify_segment(verify_commit_objects=True)
    if any(
        final_refs.get(f"refs/vulngym/{commit}") != commit for commit in required
    ):
        raise SourceAcquisitionError(
            "ref_binding_mismatch",
            "segmented fetch did not close every exact ref",
            exit_status=3,
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
) -> dict[str, SealedSnapshotSourceAudit]:
    try:
        _assert_recovery_state_clean(repository_root, status=status)
        before_fsck = repository.assert_bare_storage_safe()
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
    fsck = _run_git(
        git_executable,
        repository_root,
        ("fsck", "--full", "--strict", "--no-progress"),
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        timeout_seconds=_GIT_FSCK_TIMEOUT_SECONDS,
        check=False,
    )
    if fsck.returncode != 0:
        raise SourceAcquisitionError(
            "repository_fsck_failed",
            "Git fsck rejected a source object store",
            exit_status=status,
        )
    try:
        after_fsck = repository.assert_bare_storage_safe()
    except GitFactError as error:
        raise SourceAcquisitionError(
            "repository_rejected",
            "repository storage changed during full fsck",
            exit_status=status,
        ) from error
    if after_fsck != before_fsck:
        raise SourceAcquisitionError(
            "repository_changed",
            "repository storage changed during full fsck",
            exit_status=status,
        )
    refs = _read_vulngym_refs(
        repository_root,
        git_executable=git_executable,
        github_transport=github_transport,
        ssh_executable=ssh_executable,
        status=status,
    )
    audits: dict[str, SealedSnapshotSourceAudit] = {}
    blob_cache: dict[str, tuple[int, bool | None]] = {}
    try:
        for commit in commits:
            if refs.get(f"refs/vulngym/{commit}") != commit:
                raise SourceAcquisitionError(
                    "ref_binding_mismatch",
                    "a required commit ref is absent or rebound",
                    exit_status=status,
                )
            audits[commit] = audit_sealed_snapshot_source(
                repository,
                commit,
                blob_cache=blob_cache,
            )
        repository.assert_bare_storage_safe()
    except (GitFactError, SealedSnapshotError) as error:
        raise SourceAcquisitionError(
            "commit_verification_failed",
            "an exact commit failed cat-file verification",
            exit_status=status,
        ) from error
    return audits


def _acquisition_report_payload(
    exports: Sequence[VerifiedTaskExport],
    repository_audits: Mapping[
        str, Mapping[str, SealedSnapshotSourceAudit]
    ],
    *,
    github_transport: Literal["https", "ssh"],
) -> bytes:
    export_records = [
        {
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
                "requires_final_full_fsck": True,
                "requires_final_non_shallow": True,
            },
            "github_transport": github_transport,
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
    source_audits: dict[str, dict[str, SealedSnapshotSourceAudit]] = {}
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
        source_audits[repo_url] = _verify_repository(
            repository_root,
            repository,
            commits,
            git_executable=git,
            github_transport=github_transport,
            ssh_executable=ssh,
            status=3 if acquire else 4,
        )
        source_paths[repo_url] = repository_root

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
    report_payload = _acquisition_report_payload(
        exports,
        source_audits,
        github_transport=github_transport,
    )
    files = {
        SOURCE_MAP_FILE_NAMES[document.split]: document.payload
        for document in documents
    }
    files[SOURCE_ACQUISITION_REPORT_NAME] = report_payload
    output = _verify_or_publish_output(
        output_dir,
        files,
        protected_roots=(store, *(export.root for export in exports)),
        publish=acquire,
    )
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
    return SourceAcquisitionSummary(
        github_transport=github_transport,
        repository_count=len(groups),
        task_count=sum(len(export.tasks) for export in exports),
        ready=blocked_task_count == 0,
        ready_task_count=ready_task_count,
        blocked_task_count=blocked_task_count,
        acquisition_report_sha256=_sha256(report_payload),
        source_maps=summaries,
    )


def prepare_source_acquisition(
    inputs: Iterable[SourceAcquisitionInput],
    *,
    repository_store: Path,
    output_dir: Path,
    git_executable: Path,
    github_transport: Literal["https", "ssh"] = "https",
    ssh_executable: Path | None = None,
) -> SourceAcquisitionSummary:
    """Acquire missing objects, verify them, and publish source-map controls."""

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
    """Verify repositories and controls without initializing or fetching."""

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
