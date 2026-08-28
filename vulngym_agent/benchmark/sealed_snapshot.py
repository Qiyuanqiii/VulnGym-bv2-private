"""Prepare and verify sealed, source-only Git snapshots.

This module belongs to the trusted evaluator boundary.  It reads immutable Git
objects through :class:`~vulngym_agent.tools.git.repository.GitRepository`,
materializes their exact bytes without checkout/filter/hook execution, and
publishes a new directory transactionally.  The resulting ``tree/`` directory
is the *only* path that may be mounted into an agent sandbox.  ``control/``
must remain evaluator-only because it contains the authenticated manifest.

An HMAC authenticates provenance inside one evaluator deployment.  It is not a
public signature and the secret key is never serialized into the snapshot.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import errno
import hashlib
import hmac
import json
import ntpath
import os
import re
import secrets
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Iterable, Mapping, MutableMapping, Sequence

from vulngym_agent.tools.git.repository import (
    GitBlobTooLarge,
    GitFactError,
    GitRepository,
    TreeEntry,
    validate_commit_sha,
)


SNAPSHOT_CONTRACT_VERSION: Final[str] = "vulngym.sealed-source-snapshot.v3"
SNAPSHOT_POLICY_VERSION: Final[str] = "vulngym.portable-source-tree.v3"
GIT_SYMLINK_REPRESENTATION: Final[str] = "regular-file-raw-target-bytes"
GITLINK_REPRESENTATION: Final[str] = "regular-file-gitlink-commit-oid-lf"
ATTESTATION_ALGORITHM: Final[str] = "HMAC-SHA256"

_CONTENT_DOMAIN: Final[bytes] = b"VulnGym sealed source content root v3\0"
_ATTESTATION_DOMAIN: Final[bytes] = b"VulnGym sealed source attestation v3\0"
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_REPO_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z"
)
_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z"
)
_SHA1_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_WINDOWS_FORBIDDEN: Final[frozenset[str]] = frozenset('<>:"\\|?*')
_WINDOWS_RESERVED: Final[frozenset[str]] = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
)

_HARD_MAX_FILES: Final[int] = 200_000
_HARD_MAX_FILE_BYTES: Final[int] = 64 * 1024 * 1024
_HARD_MAX_TOTAL_BYTES: Final[int] = 2 * 1024 * 1024 * 1024
_HARD_MAX_PATH_BYTES: Final[int] = 4_096
_HARD_MAX_COMPONENT_BYTES: Final[int] = 255
_HARD_MAX_DEPTH: Final[int] = 128
_HARD_MAX_TREE_OBJECT_BYTES: Final[int] = 128 * 1024 * 1024
_HARD_MAX_MANIFEST_BYTES: Final[int] = 128 * 1024 * 1024
_MAX_ATTESTATION_BYTES: Final[int] = 4_096
_MIN_KEY_BYTES: Final[int] = 32
_MAX_KEY_BYTES: Final[int] = 4_096


class SealedSnapshotError(RuntimeError):
    """A sealed snapshot violated its trusted preparation contract."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class SnapshotPolicy:
    """Strict resource and cross-platform path limits for one snapshot."""

    max_files: int = 100_000
    max_file_bytes: int = 16 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_path_bytes: int = 1_024
    max_component_bytes: int = 255
    max_depth: int = 64
    max_tree_object_bytes: int = 16 * 1024 * 1024
    max_manifest_bytes: int = 64 * 1024 * 1024
    git_symlink_representation: str = GIT_SYMLINK_REPRESENTATION
    gitlink_representation: str = GITLINK_REPRESENTATION

    def __post_init__(self) -> None:
        limits = (
            ("max_files", self.max_files, _HARD_MAX_FILES),
            ("max_file_bytes", self.max_file_bytes, _HARD_MAX_FILE_BYTES),
            ("max_total_bytes", self.max_total_bytes, _HARD_MAX_TOTAL_BYTES),
            ("max_path_bytes", self.max_path_bytes, _HARD_MAX_PATH_BYTES),
            (
                "max_component_bytes",
                self.max_component_bytes,
                _HARD_MAX_COMPONENT_BYTES,
            ),
            ("max_depth", self.max_depth, _HARD_MAX_DEPTH),
            (
                "max_tree_object_bytes",
                self.max_tree_object_bytes,
                _HARD_MAX_TREE_OBJECT_BYTES,
            ),
            (
                "max_manifest_bytes",
                self.max_manifest_bytes,
                _HARD_MAX_MANIFEST_BYTES,
            ),
        )
        for name, value, hard_limit in limits:
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= hard_limit
            ):
                raise ValueError(
                    f"{name} must be an integer from 1 through {hard_limit}"
                )
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("max_file_bytes must not exceed max_total_bytes")
        if self.max_component_bytes > self.max_path_bytes:
            raise ValueError("max_component_bytes must not exceed max_path_bytes")
        if (
            type(self.git_symlink_representation) is not str
            or self.git_symlink_representation != GIT_SYMLINK_REPRESENTATION
        ):
            raise ValueError(
                "git_symlink_representation must name the fixed safe representation"
            )
        if (
            type(self.gitlink_representation) is not str
            or self.gitlink_representation != GITLINK_REPRESENTATION
        ):
            raise ValueError(
                "gitlink_representation must name the fixed safe representation"
            )

    def to_dict(self) -> dict[str, int | str]:
        return {
            "max_component_bytes": self.max_component_bytes,
            "max_depth": self.max_depth,
            "max_file_bytes": self.max_file_bytes,
            "max_files": self.max_files,
            "max_manifest_bytes": self.max_manifest_bytes,
            "max_path_bytes": self.max_path_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_tree_object_bytes": self.max_tree_object_bytes,
            "git_symlink_representation": self.git_symlink_representation,
            "gitlink_representation": self.gitlink_representation,
            "policy_version": SNAPSHOT_POLICY_VERSION,
        }


DEFAULT_SNAPSHOT_POLICY: Final[SnapshotPolicy] = SnapshotPolicy()


@dataclass(frozen=True, slots=True)
class SealedSnapshotSourceAudit:
    """Path-free readiness facts for one exact commit under a snapshot policy."""

    commit: str
    root_tree: str
    ready: bool
    scan_complete: bool
    lfs_scan_complete: bool
    status_codes: tuple[str, ...]
    tree_entry_count: int | None
    tree_count: int | None
    regular_file_count: int | None
    total_regular_bytes: int | None
    symlink_count: int | None
    gitlink_count: int | None
    lfs_pointer_count: int | None
    oversized_blob_count: int | None
    unsupported_entry_count: int | None
    mode_counts: tuple[tuple[str, int], ...]
    policy: SnapshotPolicy = DEFAULT_SNAPSHOT_POLICY

    def __post_init__(self) -> None:
        validate_commit_sha(self.commit)
        validate_commit_sha(self.root_tree)
        if not isinstance(self.ready, bool) or not isinstance(self.scan_complete, bool):
            raise ValueError("audit readiness flags must be booleans")
        if not isinstance(self.lfs_scan_complete, bool):
            raise ValueError("lfs_scan_complete must be a boolean")
        codes = tuple(self.status_codes)
        modes = tuple(self.mode_counts)
        object.__setattr__(self, "status_codes", codes)
        object.__setattr__(self, "mode_counts", modes)
        if len(set(codes)) != len(codes) or any(
            not isinstance(code, str) or not code for code in codes
        ):
            raise ValueError("status_codes must be unique non-empty strings")
        if self.ready != (
            self.scan_complete and self.lfs_scan_complete and not codes
        ):
            raise ValueError("ready does not close over audit state")
        counters = (
            self.tree_entry_count,
            self.tree_count,
            self.regular_file_count,
            self.total_regular_bytes,
            self.symlink_count,
            self.gitlink_count,
            self.lfs_pointer_count,
            self.oversized_blob_count,
            self.unsupported_entry_count,
        )
        if self.scan_complete:
            if any(
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for value in counters
            ):
                raise ValueError("complete audit counters must be non-negative integers")
        elif any(value is not None for value in counters):
            raise ValueError("incomplete audit counters must be unavailable")
        if any(
            not isinstance(mode, str)
            or not mode
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 1
            for mode, count in modes
        ):
            raise ValueError("mode_counts are invalid")
        if tuple(sorted(modes)) != modes:
            raise ValueError("mode_counts must be sorted")
        if not isinstance(self.policy, SnapshotPolicy):
            raise ValueError("policy must be a SnapshotPolicy")

    def to_dict(self) -> dict[str, object]:
        return {
            "commit": self.commit,
            "gitlink_count": self.gitlink_count,
            "lfs_pointer_count": self.lfs_pointer_count,
            "lfs_scan_complete": self.lfs_scan_complete,
            "mode_counts": {mode: count for mode, count in self.mode_counts},
            "oversized_blob_count": self.oversized_blob_count,
            "policy": self.policy.to_dict(),
            "ready": self.ready,
            "regular_file_count": self.regular_file_count,
            "root_tree": self.root_tree,
            "scan_complete": self.scan_complete,
            "status_codes": list(self.status_codes),
            "symlink_count": self.symlink_count,
            "total_regular_bytes": self.total_regular_bytes,
            "tree_count": self.tree_count,
            "tree_entry_count": self.tree_entry_count,
            "unsupported_entry_count": self.unsupported_entry_count,
        }


@dataclass(frozen=True, slots=True)
class SealedSnapshotFile:
    """One deeply immutable file record from the sealed manifest."""

    path: str
    git_mode: str
    blob_oid: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "blob_oid": self.blob_oid,
            "git_mode": self.git_mode,
            "path": self.path,
            "record_type": "file",
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class SealedSnapshotGitlink:
    """One metadata-only Git link; no child repository content is included."""

    path: str
    target_commit_oid: str
    materialized_sha256: str
    size: int = 49
    git_mode: str = "160000"
    representation: str = GITLINK_REPRESENTATION

    def __post_init__(self) -> None:
        if (
            type(self.path) is not str
            or type(self.target_commit_oid) is not str
            or _SHA1_RE.fullmatch(self.target_commit_oid) is None
            or type(self.materialized_sha256) is not str
            or _SHA256_RE.fullmatch(self.materialized_sha256) is None
            or type(self.size) is not int
            or self.size != 49
            or self.git_mode != "160000"
            or self.representation != GITLINK_REPRESENTATION
        ):
            raise ValueError("gitlink metadata is invalid")
        marker = b"gitlink " + self.target_commit_oid.encode("ascii") + b"\n"
        if hashlib.sha256(marker).hexdigest() != self.materialized_sha256:
            raise ValueError("gitlink marker digest is detached")

    @property
    def sha256(self) -> str:
        return self.materialized_sha256

    def to_dict(self) -> dict[str, object]:
        return {
            "git_mode": self.git_mode,
            "materialized_sha256": self.materialized_sha256,
            "path": self.path,
            "record_type": "gitlink",
            "representation": self.representation,
            "size": self.size,
            "target_commit_oid": self.target_commit_oid,
        }


SealedSnapshotEntry = SealedSnapshotFile | SealedSnapshotGitlink


@dataclass(frozen=True, slots=True)
class SealedSnapshotSummary:
    """Immutable result returned by the trusted snapshot preparer."""

    snapshot_root: Path
    task_id: str
    repo_url: str
    commit: str
    root_tree: str
    content_root: str
    manifest_sha256: str
    file_count: int
    total_bytes: int
    entry_count: int
    regular_file_count: int
    gitlink_count: int
    regular_file_bytes: int
    materialized_bytes: int
    files: tuple[SealedSnapshotEntry, ...]

    @property
    def agent_tree(self) -> Path:
        """Return the sole directory permitted as an agent source mount."""

        return self.snapshot_root / "tree"


@dataclass(frozen=True, slots=True)
class VerifiedSealedSnapshot:
    """Deeply immutable summary produced only after full verification."""

    snapshot_root: Path
    task_id: str
    repo_url: str
    commit: str
    root_tree: str
    content_root: str
    manifest_sha256: str
    key_id: str
    file_count: int
    total_bytes: int
    entry_count: int
    regular_file_count: int
    gitlink_count: int
    regular_file_bytes: int
    materialized_bytes: int
    files: tuple[SealedSnapshotEntry, ...]

    @property
    def agent_tree(self) -> Path:
        """Return the sole path an evaluator may mount into the agent sandbox.

        The caller must mount this path read-only and must not expose its
        parent or the sibling ``control/`` directory to the agent.
        """

        return self.snapshot_root / "tree"


@dataclass(slots=True)
class _StagingState:
    output: Path
    parent: Path
    checked_parent: tuple[tuple[Path, tuple[int, int]], ...]
    staging: Path
    staging_name: str
    staging_identity: tuple[int, int]
    parent_fd: int | None
    staging_fd: int | None
    created_dirs: dict[str, tuple[int, int]]
    created_files: dict[str, tuple[int, int]]
    windows_parent_identity: tuple[int, int] | None = None
    windows_staging_identity: tuple[int, int] | None = None
    published: bool = False


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _is_reparse(result: os.stat_result) -> bool:
    attributes = getattr(result, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _identity(result: os.stat_result) -> tuple[int, int, int, int | None, int | None]:
    return (
        result.st_dev,
        result.st_ino,
        result.st_size,
        getattr(result, "st_mtime_ns", None),
        getattr(result, "st_ctime_ns", None),
    )


def _directory_identity(result: os.stat_result) -> tuple[int, int]:
    return (result.st_dev, result.st_ino)


def _require_safe_directory(path: Path) -> os.stat_result:
    try:
        result = os.lstat(path)
    except OSError as error:
        raise SealedSnapshotError(
            "snapshot_unavailable", "a required directory is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(result.st_mode)
        or stat.S_ISLNK(result.st_mode)
        or _is_reparse(result)
    ):
        raise SealedSnapshotError(
            "unsafe_snapshot_path", "snapshot paths must not traverse links"
        )
    return result


def _require_safe_regular(path: Path) -> os.stat_result:
    try:
        result = os.lstat(path)
    except OSError as error:
        raise SealedSnapshotError(
            "snapshot_unavailable", "a required snapshot file is unavailable"
        ) from error
    if (
        not stat.S_ISREG(result.st_mode)
        or stat.S_ISLNK(result.st_mode)
        or _is_reparse(result)
        or result.st_nlink > 1
    ):
        raise SealedSnapshotError(
            "unsafe_snapshot_path", "snapshot files must be unlinked regular files"
        )
    return result


def _root_chain(path: Path) -> tuple[Path, ...]:
    return tuple(reversed(path.parents)) + (path,)


def _checked_parent_chain(path: Path) -> tuple[tuple[Path, tuple[int, int]], ...]:
    checked: list[tuple[Path, tuple[int, int]]] = []
    for component in _root_chain(path):
        state = _require_safe_directory(component)
        checked.append((component, _directory_identity(state)))
    return tuple(checked)


def _assert_parent_chain(
    checked: Sequence[tuple[Path, tuple[int, int]]],
) -> None:
    for path, expected in checked:
        current = _require_safe_directory(path)
        if _directory_identity(current) != expected:
            raise SealedSnapshotError(
                "snapshot_parent_changed",
                "snapshot parent changed during the trusted operation",
            )


def _path_relation(left: Path, right: Path) -> bool:
    try:
        common = os.path.commonpath(
            (os.path.normcase(str(left)), os.path.normcase(str(right)))
        )
    except ValueError:
        return False
    return common in {os.path.normcase(str(left)), os.path.normcase(str(right))}


class _WindowsFileTime(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]


class _WindowsHandleInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("creation_time", _WindowsFileTime),
        ("last_access_time", _WindowsFileTime),
        ("last_write_time", _WindowsFileTime),
        ("volume_serial_number", wintypes.DWORD),
        ("file_size_high", wintypes.DWORD),
        ("file_size_low", wintypes.DWORD),
        ("number_of_links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    ]


class _WindowsFindStreamData(ctypes.Structure):
    _fields_ = [
        ("stream_size", ctypes.c_longlong),
        ("stream_name", wintypes.WCHAR * (260 + 36)),
    ]


def _windows_assert_no_named_streams(path: Path) -> None:
    if os.name != "nt":
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    find_first = kernel32.FindFirstStreamW
    find_first.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        ctypes.POINTER(_WindowsFindStreamData),
        wintypes.DWORD,
    ]
    find_first.restype = wintypes.HANDLE
    find_next = kernel32.FindNextStreamW
    find_next.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_WindowsFindStreamData),
    ]
    find_next.restype = wintypes.BOOL
    find_close = kernel32.FindClose
    find_close.argtypes = [wintypes.HANDLE]
    find_close.restype = wintypes.BOOL
    data = _WindowsFindStreamData()
    handle = find_first(str(path), 0, ctypes.byref(data), 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, 0, invalid_handle}:
        error_number = ctypes.get_last_error()
        if error_number == 38:
            return
        raise SealedSnapshotError(
            "snapshot_unavailable", "snapshot streams cannot be enumerated"
        )
    try:
        while True:
            if data.stream_name != "::$DATA":
                raise SealedSnapshotError(
                    "unsafe_snapshot_path",
                    "snapshot paths must not contain named data streams",
                )
            if find_next(handle, ctypes.byref(data)):
                continue
            error_number = ctypes.get_last_error()
            if error_number != 38:
                raise SealedSnapshotError(
                    "snapshot_unavailable", "snapshot streams changed during enumeration"
                )
            break
    finally:
        find_close(handle)


def _windows_open_directory(
    path: Path,
    *,
    delete_access: bool,
    share_delete: bool,
) -> tuple[int, tuple[int, int]]:
    if os.name != "nt":
        raise OSError(errno.ENOTSUP, "Windows directory handles are unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    desired_access = 0x0080 | (0x00010000 if delete_access else 0)
    share_mode = 0x00000001 | 0x00000002
    if share_delete:
        share_mode |= 0x00000004
    handle = create_file(
        str(path),
        desired_access,
        share_mode,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, 0, invalid_handle}:
        error_number = ctypes.get_last_error()
        raise OSError(error_number, "trusted directory handle could not be opened")
    information = _WindowsHandleInformation()
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    get_information.restype = wintypes.BOOL
    if not get_information(handle, ctypes.byref(information)):
        error_number = ctypes.get_last_error()
        _windows_close_handle(int(handle))
        raise OSError(error_number, "trusted directory identity could not be read")
    if not (information.attributes & 0x00000010) or (
        information.attributes & 0x00000400
    ):
        _windows_close_handle(int(handle))
        raise SealedSnapshotError(
            "unsafe_output", "snapshot transaction paths must be plain directories"
        )
    identity = (
        information.volume_serial_number,
        (information.file_index_high << 32) | information.file_index_low,
    )
    return int(handle), identity


def _windows_close_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(handle)


def _windows_rename_directory_handle(handle: int, destination: Path) -> None:
    """Rename the directory represented by *handle* without replacement."""

    destination_text = str(destination)

    class _WindowsRenameInformation(ctypes.Structure):
        _fields_ = [
            ("replace_if_exists", ctypes.c_ubyte),
            ("root_directory", wintypes.HANDLE),
            ("file_name_length", wintypes.DWORD),
            ("file_name", wintypes.WCHAR * (len(destination_text) + 1)),
        ]

    information = _WindowsRenameInformation()
    information.replace_if_exists = 0
    information.root_directory = None
    information.file_name_length = len(destination_text.encode("utf-16-le"))
    information.file_name = destination_text
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    buffer_size = (
        _WindowsRenameInformation.file_name.offset + information.file_name_length
    )
    if not set_information(
        handle,
        3,
        ctypes.byref(information),
        buffer_size,
    ):
        error_number = ctypes.get_last_error()
        if error_number in {80, 183}:
            raise FileExistsError(str(destination))
        raise OSError(error_number, "atomic snapshot publication failed")


def _validate_binding(
    task_id: object, repo_url: object, commit: object, key_id: object
) -> tuple[str, str, str, str]:
    if not isinstance(task_id, str) or _TASK_ID_RE.fullmatch(task_id) is None:
        raise ValueError("task_id is not a canonical VulnGym task identifier")
    if (
        not isinstance(repo_url, str)
        or _REPO_URL_RE.fullmatch(repo_url) is None
        or repo_url.casefold().endswith(".git")
    ):
        raise ValueError("repo_url must be a canonical GitHub repository URL")
    canonical_commit = validate_commit_sha(commit)
    if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
        raise ValueError("key_id is not a canonical public key identifier")
    return task_id, repo_url, canonical_commit, key_id


def _copy_key(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError("attestation_key must be bytes-like")
    key = bytes(value)
    if not _MIN_KEY_BYTES <= len(key) <= _MAX_KEY_BYTES:
        raise ValueError(
            f"attestation_key must contain {_MIN_KEY_BYTES} through "
            f"{_MAX_KEY_BYTES} bytes"
        )
    return key


def _validate_portable_path(
    path: object,
    policy: SnapshotPolicy,
) -> tuple[tuple[str, ...], bytes, str]:
    if not isinstance(path, str) or not path:
        raise SealedSnapshotError(
            "unsafe_source_path", "Git paths must be non-empty UTF-8 strings"
        )
    try:
        raw_path = path.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise SealedSnapshotError(
            "unsafe_source_path", "Git paths must be valid UTF-8"
        ) from error
    if unicodedata.normalize("NFC", path) != path:
        raise SealedSnapshotError(
            "unsafe_source_path", "Git paths must use canonical NFC Unicode"
        )
    if len(raw_path) > policy.max_path_bytes:
        raise SealedSnapshotError(
            "source_limit_exceeded", "a Git path exceeds the path byte budget"
        )
    drive, _ = ntpath.splitdrive(path)
    if path.startswith(("/", "-", ":")) or drive or "\\" in path:
        raise SealedSnapshotError(
            "unsafe_source_path", "Git paths must be canonical relative paths"
        )
    components = tuple(path.split("/"))
    if len(components) > policy.max_depth:
        raise SealedSnapshotError(
            "source_limit_exceeded", "a Git path exceeds the depth budget"
        )
    for component in components:
        if component in {"", ".", ".."}:
            raise SealedSnapshotError(
                "unsafe_source_path", "Git paths contain a non-canonical component"
            )
        component_bytes = component.encode("utf-8", errors="strict")
        if len(component_bytes) > policy.max_component_bytes:
            raise SealedSnapshotError(
                "source_limit_exceeded",
                "a Git path component exceeds the byte budget",
            )
        if component.endswith((" ", ".")):
            raise SealedSnapshotError(
                "unsafe_source_path", "Git paths are not Windows-portable"
            )
        if (
            component.casefold() == ".git"
            or unicodedata.normalize("NFKC", component).casefold() == ".git"
        ):
            raise SealedSnapshotError(
                "unsafe_source_path", "Git administrative path names are forbidden"
            )
        if any(
            character in _WINDOWS_FORBIDDEN
            or unicodedata.category(character).startswith("C")
            for character in component
        ):
            raise SealedSnapshotError(
                "unsafe_source_path", "Git paths are not portable text paths"
            )
        windows_stem = component.split(".", 1)[0].upper()
        if windows_stem in _WINDOWS_RESERVED:
            raise SealedSnapshotError(
                "unsafe_source_path", "Git paths contain a reserved device name"
            )
    collision_key = "/".join(component.casefold() for component in components)
    return components, raw_path, collision_key


def _validate_entries(
    entries: Iterable[TreeEntry], policy: SnapshotPolicy
) -> tuple[tuple[TreeEntry, tuple[str, ...], bytes], ...]:
    validated: list[tuple[TreeEntry, tuple[str, ...], bytes, str]] = []
    tree_paths: list[bytes] = []
    all_paths: list[tuple[bytes, bool]] = []
    seen_exact: set[bytes] = set()
    seen_portable: set[str] = set()
    for number, entry in enumerate(entries, 1):
        if number > policy.max_files:
            raise SealedSnapshotError(
                "source_limit_exceeded", "Git tree exceeds the file-count budget"
            )
        if not isinstance(entry, TreeEntry):
            raise SealedSnapshotError(
                "invalid_source_tree", "Git tree returned an invalid entry"
            )
        components, raw_path, collision_key = _validate_portable_path(
            entry.path, policy
        )
        if raw_path in seen_exact or collision_key in seen_portable:
            raise SealedSnapshotError(
                "source_path_collision",
                "Git paths collide under the portable snapshot policy",
            )
        seen_exact.add(raw_path)
        seen_portable.add(collision_key)
        if entry.mode == "40000" and entry.object_type == "tree":
            tree_paths.append(raw_path)
            all_paths.append((raw_path, True))
            continue
        if entry.mode == "160000" or entry.object_type == "commit":
            if (
                entry.mode != "160000"
                or entry.object_type != "commit"
                or _SHA1_RE.fullmatch(entry.object_id) is None
            ):
                raise SealedSnapshotError(
                    "invalid_source_tree", "Git link metadata is invalid"
                )
            validated.append((entry, components, raw_path, collision_key))
            all_paths.append((raw_path, False))
            continue
        if (
            entry.mode not in {"100644", "100755", "120000"}
            or entry.object_type != "blob"
        ):
            raise SealedSnapshotError(
                "invalid_source_tree", "Git tree contains an unsupported entry"
            )
        if _SHA1_RE.fullmatch(entry.object_id) is None:
            raise SealedSnapshotError(
                "invalid_source_tree", "Git tree contains an invalid object ID"
            )
        validated.append((entry, components, raw_path, collision_key))
        all_paths.append((raw_path, False))

    leaf_paths = tuple(item[2] for item in validated)
    for tree_path in tree_paths:
        if not any(path.startswith(tree_path + b"/") for path in leaf_paths):
            raise SealedSnapshotError(
                "invalid_source_tree", "Git tree contains an empty directory"
            )
    if not validated:
        raise SealedSnapshotError(
            "invalid_source_tree", "sealed source trees must contain a regular file"
        )
    all_paths.sort(key=lambda item: item[0])
    previous_path: bytes | None = None
    previous_is_tree = False
    for raw_path, is_tree in all_paths:
        if (
            previous_path is not None
            and raw_path.startswith(previous_path + b"/")
            and not previous_is_tree
        ):
            raise SealedSnapshotError(
                "source_path_collision",
                "Git tree contains a file/directory prefix collision",
            )
        previous_path = raw_path
        previous_is_tree = is_tree
    validated.sort(key=lambda item: item[2])
    return tuple((entry, components, raw_path) for entry, components, raw_path, _ in validated)


def _is_lfs_pointer(data: bytes) -> bool:
    first_line = data.split(b"\n", 1)[0].rstrip(b"\r")
    return first_line == b"version https://git-lfs.github.com/spec/v1"


_SOURCE_AUDIT_STATUS_ORDER: Final[tuple[str, ...]] = (
    "source_limit_exceeded",
    "unsafe_source_path",
    "source_path_collision",
    "source_gitlink_rejected",
    "source_lfs_rejected",
    "invalid_source_tree",
)


def audit_sealed_snapshot_source(
    repository: GitRepository,
    commit: str,
    *,
    policy: SnapshotPolicy = DEFAULT_SNAPSHOT_POLICY,
    blob_cache: MutableMapping[str, tuple[int, bool | None]] | None = None,
) -> SealedSnapshotSourceAudit:
    """Inspect one commit for sealed-snapshot readiness without materializing it.

    The audit deliberately uses hard traversal bounds before applying the active
    policy.  This lets a trusted acquisition report distinguish a completely
    scanned but policy-blocked tree from a tree whose facts could not be
    enumerated safely.  ``blob_cache`` is an optional evaluator-owned cache of
    ``blob_oid -> (size, is_lfs_pointer)`` facts; ``None`` means that an
    oversized blob was not read and its LFS status is therefore unknown.
    """

    if not isinstance(repository, GitRepository):
        raise ValueError("repository must be a GitRepository")
    if not isinstance(policy, SnapshotPolicy):
        raise ValueError("policy must be a SnapshotPolicy")
    commit = validate_commit_sha(commit)
    cache = {} if blob_cache is None else blob_cache

    repository.assert_storage_safe()
    if repository.history_is_shallow():
        raise SealedSnapshotError(
            "shallow_repository_rejected",
            "sealed snapshots require a complete local repository",
        )
    root_tree = repository.commit_tree(commit)
    try:
        entries = repository.list_tree_entries(
            commit,
            max_entries=_HARD_MAX_FILES,
            max_output_bytes=_HARD_MAX_TREE_OBJECT_BYTES,
            include_trees=True,
        )
    except GitBlobTooLarge:
        return SealedSnapshotSourceAudit(
            commit=commit,
            root_tree=root_tree,
            ready=False,
            scan_complete=False,
            lfs_scan_complete=False,
            status_codes=("source_limit_exceeded",),
            tree_entry_count=None,
            tree_count=None,
            regular_file_count=None,
            total_regular_bytes=None,
            symlink_count=None,
            gitlink_count=None,
            lfs_pointer_count=None,
            oversized_blob_count=None,
            unsupported_entry_count=None,
            mode_counts=(),
            policy=policy,
        )

    statuses: set[str] = set()
    mode_counts: dict[str, int] = {}
    tree_paths: list[bytes] = []
    leaf_paths: list[bytes] = []
    all_paths: list[tuple[bytes, bool]] = []
    seen_exact: set[bytes] = set()
    seen_portable: set[str] = set()
    tree_count = 0
    regular_file_count = 0
    total_regular_bytes = 0
    symlink_count = 0
    gitlink_count = 0
    lfs_pointer_count = 0
    oversized_blob_count = 0
    unsupported_entry_count = 0
    lfs_scan_complete = True

    if len(entries) > policy.max_files:
        statuses.add("source_limit_exceeded")
    for entry in entries:
        if not isinstance(entry, TreeEntry):
            statuses.add("invalid_source_tree")
            unsupported_entry_count += 1
            continue
        mode_counts[entry.mode] = mode_counts.get(entry.mode, 0) + 1
        raw_path: bytes | None = None
        try:
            _, raw_path, collision_key = _validate_portable_path(entry.path, policy)
        except SealedSnapshotError as error:
            statuses.add(error.code)
        else:
            if raw_path in seen_exact or collision_key in seen_portable:
                statuses.add("source_path_collision")
            seen_exact.add(raw_path)
            seen_portable.add(collision_key)

        is_tree = entry.mode == "40000" and entry.object_type == "tree"
        if raw_path is not None:
            all_paths.append((raw_path, is_tree))
            if is_tree:
                tree_paths.append(raw_path)
            else:
                leaf_paths.append(raw_path)
        if is_tree:
            tree_count += 1
            continue
        if entry.mode == "120000":
            symlink_count += 1
            if entry.object_type != "blob":
                unsupported_entry_count += 1
                statuses.add("invalid_source_tree")
                continue
        if entry.mode == "160000" or entry.object_type == "commit":
            if (
                entry.mode != "160000"
                or entry.object_type != "commit"
                or _SHA1_RE.fullmatch(entry.object_id) is None
            ):
                unsupported_entry_count += 1
                statuses.add("invalid_source_tree")
                continue
            gitlink_count += 1
            if 49 > policy.max_file_bytes:
                statuses.add("source_limit_exceeded")
            continue
        if (
            entry.mode not in {"100644", "100755", "120000"}
            or entry.object_type != "blob"
        ):
            unsupported_entry_count += 1
            statuses.add("invalid_source_tree")
            continue
        if _SHA1_RE.fullmatch(entry.object_id) is None:
            unsupported_entry_count += 1
            statuses.add("invalid_source_tree")
            continue

        regular_file_count += 1
        cached = cache.get(entry.object_id)
        if cached is None:
            try:
                data = repository.read_blob_object(
                    entry.object_id, max_bytes=policy.max_file_bytes
                )
            except GitBlobTooLarge:
                # The bounded reader already performed the type/size gate. A
                # second size query is needed only for the exceptional blob so
                # the complete audit can report aggregate policy facts.
                size = repository.object_size(
                    entry.object_id,
                    expected_type="blob",
                    operation="cat-file",
                )
                is_lfs: bool | None = None
            else:
                size = len(data)
                is_lfs = _is_lfs_pointer(data)
            cache[entry.object_id] = (size, is_lfs)
        else:
            size, is_lfs = cached
            if (
                isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
                or (is_lfs is not None and not isinstance(is_lfs, bool))
            ):
                raise ValueError("blob_cache contains an invalid fact")
        total_regular_bytes += size
        if size > policy.max_file_bytes:
            oversized_blob_count += 1
            lfs_scan_complete = False
            statuses.add("source_limit_exceeded")
        elif is_lfs is None:
            # A cache entry produced under a tighter policy may carry only a
            # size fact. Unknown pointer status must never become readiness.
            lfs_scan_complete = False
        elif is_lfs:
            lfs_pointer_count += 1
            statuses.add("source_lfs_rejected")

    materialized_bytes = total_regular_bytes + (gitlink_count * 49)
    if materialized_bytes > policy.max_total_bytes:
        statuses.add("source_limit_exceeded")
    if not regular_file_count:
        statuses.add("invalid_source_tree")
    for tree_path in tree_paths:
        if not any(path.startswith(tree_path + b"/") for path in leaf_paths):
            statuses.add("invalid_source_tree")
    all_paths.sort(key=lambda item: item[0])
    previous_path: bytes | None = None
    previous_is_tree = False
    for raw_path, is_tree in all_paths:
        if (
            previous_path is not None
            and raw_path.startswith(previous_path + b"/")
            and not previous_is_tree
        ):
            statuses.add("source_path_collision")
        previous_path = raw_path
        previous_is_tree = is_tree

    repository.assert_storage_safe()
    if repository.history_is_shallow():
        raise SealedSnapshotError(
            "shallow_repository_rejected",
            "repository became shallow during source audit",
        )
    status_codes = tuple(
        code for code in _SOURCE_AUDIT_STATUS_ORDER if code in statuses
    )
    return SealedSnapshotSourceAudit(
        commit=commit,
        root_tree=root_tree,
        ready=lfs_scan_complete and not status_codes,
        scan_complete=True,
        lfs_scan_complete=lfs_scan_complete,
        status_codes=status_codes,
        tree_entry_count=len(entries),
        tree_count=tree_count,
        regular_file_count=regular_file_count,
        total_regular_bytes=total_regular_bytes,
        symlink_count=symlink_count,
        gitlink_count=gitlink_count,
        lfs_pointer_count=lfs_pointer_count,
        oversized_blob_count=oversized_blob_count,
        unsupported_entry_count=unsupported_entry_count,
        mode_counts=tuple(sorted(mode_counts.items())),
        policy=policy,
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    position = 0
    while position < len(view):
        written = os.write(descriptor, view[position:])
        if written < 1:
            raise OSError(errno.EIO, "short snapshot write")
        position += written


def _begin_staging(output_dir: str | os.PathLike[str], repository: GitRepository) -> _StagingState:
    output = Path(os.path.abspath(os.fspath(output_dir)))
    if output.name in {"", ".", ".."}:
        raise ValueError("output_dir must name a new child directory")
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise SealedSnapshotError(
            "unsafe_output", "output state cannot be inspected"
        ) from error
    else:
        raise SealedSnapshotError(
            "output_exists", "output directory already exists; overwrite is forbidden"
        )
    repository_root = Path(os.path.abspath(os.fspath(repository.path)))
    if _path_relation(output, repository_root):
        raise SealedSnapshotError(
            "unsafe_output", "snapshot output must not overlap its source repository"
        )
    parent = output.parent
    checked_parent = _checked_parent_chain(parent)
    parent_fd: int | None = None
    staging_fd: int | None = None
    staging: Path | None = None
    staging_name: str | None = None
    created_staging_identity: tuple[int, int] | None = None
    try:
        if os.name == "posix":
            parent_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            parent_fd = os.open(parent, parent_flags)
            opened_parent = os.fstat(parent_fd)
            if (
                not stat.S_ISDIR(opened_parent.st_mode)
                or _is_reparse(opened_parent)
                or _directory_identity(opened_parent) != checked_parent[-1][1]
            ):
                raise SealedSnapshotError(
                    "snapshot_parent_changed", "output parent changed during staging"
                )
            _assert_parent_chain(checked_parent)
            for _ in range(128):
                candidate = f".{output.name}.{secrets.token_hex(16)}.staging"
                try:
                    os.mkdir(candidate, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    continue
                staging_name = candidate
                break
            if staging_name is None:
                raise OSError(errno.EEXIST, "could not allocate staging directory")
            staging = parent / staging_name
            staging_fd = os.open(
                staging_name, parent_flags, dir_fd=parent_fd
            )
            state = os.fstat(staging_fd)
        else:
            for _ in range(128):
                candidate_path = parent / (
                    f".{output.name}.{secrets.token_hex(16)}.staging"
                )
                try:
                    candidate_path.mkdir(mode=0o700)
                except FileExistsError:
                    continue
                staging = candidate_path
                staging_name = candidate_path.name
                break
            if staging is None or staging_name is None:
                raise OSError(errno.EEXIST, "could not allocate staging directory")
            state = _require_safe_directory(staging)
        if not stat.S_ISDIR(state.st_mode) or _is_reparse(state):
            raise SealedSnapshotError(
                "unsafe_output", "snapshot staging directory is unsafe"
            )
        created_staging_identity = _directory_identity(state)
        windows_parent_identity: tuple[int, int] | None = None
        windows_staging_identity: tuple[int, int] | None = None
        if os.name == "nt":
            parent_handle, windows_parent_identity = _windows_open_directory(
                parent, delete_access=False, share_delete=True
            )
            try:
                staging_handle, windows_staging_identity = _windows_open_directory(
                    staging, delete_access=False, share_delete=True
                )
                _windows_close_handle(staging_handle)
            finally:
                _windows_close_handle(parent_handle)
            if (
                windows_parent_identity[1] != checked_parent[-1][1][1]
                or windows_staging_identity[1] != state.st_ino
            ):
                raise SealedSnapshotError(
                    "snapshot_parent_changed",
                    "output transaction changed while opening trusted handles",
                )
        return _StagingState(
            output=output,
            parent=parent,
            checked_parent=checked_parent,
            staging=staging,
            staging_name=staging_name,
            staging_identity=_directory_identity(state),
            parent_fd=parent_fd,
            staging_fd=staging_fd,
            created_dirs={},
            created_files={},
            windows_parent_identity=windows_parent_identity,
            windows_staging_identity=windows_staging_identity,
        )
    except Exception:
        if staging_fd is not None:
            os.close(staging_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        if staging is not None:
            try:
                current = _require_safe_directory(staging)
                if (
                    created_staging_identity is not None
                    and _directory_identity(current) == created_staging_identity
                ):
                    staging.rmdir()
            except (OSError, SealedSnapshotError):
                pass
        raise


def _state_relative_path(state: _StagingState, relative: str) -> Path:
    return state.staging.joinpath(*relative.split("/"))


def _create_staging_dir(state: _StagingState, relative: str) -> None:
    if relative in state.created_dirs:
        current = _require_safe_directory(_state_relative_path(state, relative))
        if _directory_identity(current) != state.created_dirs[relative]:
            raise SealedSnapshotError(
                "output_transaction_changed", "staging directory changed"
            )
        return
    parent_relative, _, name = relative.rpartition("/")
    if parent_relative:
        _create_staging_dir(state, parent_relative)
    parent_path = (
        _state_relative_path(state, parent_relative)
        if parent_relative
        else state.staging
    )
    parent_state = _require_safe_directory(parent_path)
    expected_parent = (
        state.created_dirs[parent_relative]
        if parent_relative
        else state.staging_identity
    )
    if _directory_identity(parent_state) != expected_parent:
        raise SealedSnapshotError(
            "output_transaction_changed", "staging parent changed"
        )
    target = parent_path / name
    try:
        target.mkdir(mode=0o700)
    except FileExistsError as error:
        raise SealedSnapshotError(
            "output_transaction_changed", "unexpected staging entry exists"
        ) from error
    created = _require_safe_directory(target)
    state.created_dirs[relative] = _directory_identity(created)


def _write_staging_file(
    state: _StagingState, relative: str, payload: bytes
) -> None:
    if relative in state.created_files:
        raise SealedSnapshotError(
            "output_transaction_changed", "duplicate staging file"
        )
    parent_relative, _, name = relative.rpartition("/")
    if not parent_relative or not name:
        raise ValueError("staging files must have a directory and simple file name")
    _create_staging_dir(state, parent_relative)
    parent_path = _state_relative_path(state, parent_relative)
    parent_state = _require_safe_directory(parent_path)
    if _directory_identity(parent_state) != state.created_dirs[parent_relative]:
        raise SealedSnapshotError(
            "output_transaction_changed", "staging parent changed"
        )
    target = parent_path / name
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(target, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse(opened):
            raise SealedSnapshotError(
                "output_transaction_changed", "staging file is unsafe"
            )
        state.created_files[relative] = _directory_identity(opened)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        finished = os.fstat(descriptor)
        if (
            _directory_identity(finished) != state.created_files[relative]
            or finished.st_size != len(payload)
        ):
            raise SealedSnapshotError(
                "output_transaction_changed", "staging file changed while writing"
            )
    finally:
        os.close(descriptor)


def _fsync_staging_directories(state: _StagingState) -> None:
    paths = [
        _state_relative_path(state, relative)
        for relative in sorted(
            state.created_dirs, key=lambda item: (item.count("/"), item), reverse=True
        )
    ] + [state.staging]
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    for path in paths:
        try:
            descriptor = os.open(path, flags)
        except OSError:
            if os.name == "posix":
                raise
            return
        try:
            try:
                os.fsync(descriptor)
            except OSError as error:
                if error.errno not in {errno.EINVAL, errno.ENOTSUP, errno.EBADF}:
                    raise
        finally:
            os.close(descriptor)


def _rename_noreplace(state: _StagingState) -> None:
    if os.name == "posix":
        if state.parent_fd is None:
            raise OSError(errno.EBADF, "missing trusted parent descriptor")
        try:
            renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
        except (AttributeError, OSError) as error:
            raise OSError(
                errno.ENOTSUP, "atomic no-replace rename is unavailable"
            ) from error
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            state.parent_fd,
            os.fsencode(state.staging_name),
            state.parent_fd,
            os.fsencode(state.output.name),
            1,
        )
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise FileExistsError(str(state.output))
            raise OSError(error_number, "atomic snapshot publication failed")
        # The no-replace rename is the POSIX commit point.  After this point a
        # hostile concurrent namespace change can make the destination name
        # refer to a different inode.  There is no portable fd-relative rename
        # of an already-open directory, so a path-based rollback could move an
        # attacker's replacement.  Mark the transaction published before all
        # post-commit checks and fail without touching either name if certainty
        # is lost.
        state.published = True
        try:
            destination = os.stat(
                state.output.name,
                dir_fd=state.parent_fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(destination.st_mode)
                or _is_reparse(destination)
                or _directory_identity(destination) != state.staging_identity
            ):
                raise SealedSnapshotError(
                    "output_transaction_changed", "published snapshot identity changed"
                )
            _assert_parent_chain(state.checked_parent)
            os.fsync(state.parent_fd)
        except Exception as error:
            raise SealedSnapshotError(
                "snapshot_publication_uncertain",
                "snapshot publication completed but its identity is uncertain",
            ) from error
    else:
        parent_handle: int | None = None
        staging_handle: int | None = None
        try:
            parent_handle, parent_identity = _windows_open_directory(
                state.parent, delete_access=False, share_delete=False
            )
            staging_handle, staging_identity = _windows_open_directory(
                state.staging, delete_access=True, share_delete=False
            )
            if (
                parent_identity != state.windows_parent_identity
                or staging_identity != state.windows_staging_identity
            ):
                raise SealedSnapshotError(
                    "output_transaction_changed", "snapshot transaction identity changed"
                )
            try:
                os.lstat(state.output)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(str(state.output))
            _assert_parent_chain(state.checked_parent)
            current = _require_safe_directory(state.staging)
            if _directory_identity(current) != state.staging_identity:
                raise SealedSnapshotError(
                    "output_transaction_changed", "staging identity changed"
                )
            _windows_rename_directory_handle(staging_handle, state.output)
            try:
                destination = _require_safe_directory(state.output)
                if _directory_identity(destination) != state.staging_identity:
                    raise SealedSnapshotError(
                        "output_transaction_changed", "published snapshot identity changed"
                    )
                _assert_parent_chain(state.checked_parent)
            except Exception:
                for _ in range(128):
                    rollback_path = state.parent / (
                        f".{state.output.name}.{secrets.token_hex(16)}.rollback"
                    )
                    try:
                        _windows_rename_directory_handle(
                            staging_handle, rollback_path
                        )
                    except FileExistsError:
                        continue
                    except OSError:
                        state.staging = state.output
                        state.staging_name = state.output.name
                    else:
                        state.staging = rollback_path
                        state.staging_name = rollback_path.name
                    break
                else:
                    state.staging = state.output
                    state.staging_name = state.output.name
                raise
        finally:
            if staging_handle is not None:
                _windows_close_handle(staging_handle)
            if parent_handle is not None:
                _windows_close_handle(parent_handle)
    state.published = True


def _cleanup_staging(state: _StagingState) -> None:
    if state.published:
        return
    try:
        _assert_parent_chain(state.checked_parent)
        current = _require_safe_directory(state.staging)
        if _directory_identity(current) != state.staging_identity:
            return
        for relative in sorted(
            state.created_files,
            key=lambda item: (item.count("/"), item),
            reverse=True,
        ):
            target = _state_relative_path(state, relative)
            try:
                item = os.lstat(target)
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(item.st_mode)
                or stat.S_ISLNK(item.st_mode)
                or _is_reparse(item)
                or _directory_identity(item) != state.created_files[relative]
            ):
                return
            target.unlink()
        for relative in sorted(
            state.created_dirs,
            key=lambda item: (item.count("/"), item),
            reverse=True,
        ):
            target = _state_relative_path(state, relative)
            try:
                item = os.lstat(target)
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISDIR(item.st_mode)
                or stat.S_ISLNK(item.st_mode)
                or _is_reparse(item)
                or _directory_identity(item) != state.created_dirs[relative]
            ):
                return
            target.rmdir()
        final = _require_safe_directory(state.staging)
        if _directory_identity(final) == state.staging_identity:
            state.staging.rmdir()
    except (OSError, SealedSnapshotError):
        # Fail-safe cleanup leaks a private staging directory instead of ever
        # deleting a path whose identity is no longer proven.
        return


def _close_staging(state: _StagingState) -> None:
    if state.staging_fd is not None:
        os.close(state.staging_fd)
        state.staging_fd = None
    if state.parent_fd is not None:
        os.close(state.parent_fd)
        state.parent_fd = None


def _content_root(file_lines: Iterable[bytes]) -> str:
    digest = hashlib.sha256()
    digest.update(_CONTENT_DOMAIN)
    for line in file_lines:
        digest.update(line)
    return digest.hexdigest()


def _attestation_mac(key: bytes, key_id: str, manifest: bytes) -> str:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    digest.update(_ATTESTATION_DOMAIN)
    digest.update(key_id.encode("ascii"))
    digest.update(b"\0")
    digest.update(manifest)
    return digest.hexdigest()


def _manifest_bytes(
    *,
    task_id: str,
    repo_url: str,
    commit: str,
    root_tree: str,
    files: Sequence[SealedSnapshotEntry],
    total_bytes: int,
    policy: SnapshotPolicy,
) -> tuple[bytes, str]:
    header = {
        "commit": commit,
        "contract_version": SNAPSHOT_CONTRACT_VERSION,
        "policy": policy.to_dict(),
        "record_type": "header",
        "repo_url": repo_url,
        "root_tree": root_tree,
        "task_id": task_id,
    }
    file_lines = tuple(_canonical_json(value.to_dict()) + b"\n" for value in files)
    content_root = _content_root(file_lines)
    regular_file_count = sum(type(value) is SealedSnapshotFile for value in files)
    gitlink_count = sum(type(value) is SealedSnapshotGitlink for value in files)
    regular_file_bytes = sum(
        value.size for value in files if type(value) is SealedSnapshotFile
    )
    footer = {
        "content_root": content_root,
        "entry_count": len(files),
        "file_count": len(files),
        "gitlink_count": gitlink_count,
        "materialized_bytes": total_bytes,
        "record_type": "footer",
        "regular_file_bytes": regular_file_bytes,
        "regular_file_count": regular_file_count,
        "total_bytes": total_bytes,
    }
    payload = (
        _canonical_json(header)
        + b"\n"
        + b"".join(file_lines)
        + _canonical_json(footer)
        + b"\n"
    )
    if len(payload) > policy.max_manifest_bytes:
        raise SealedSnapshotError(
            "source_limit_exceeded", "sealed manifest exceeds its byte budget"
        )
    return payload, content_root


def prepare_sealed_snapshot(
    repository: GitRepository,
    *,
    task_id: str,
    repo_url: str,
    commit: str,
    output_dir: str | os.PathLike[str],
    attestation_key: bytes | bytearray | memoryview,
    key_id: str,
    policy: SnapshotPolicy = DEFAULT_SNAPSHOT_POLICY,
) -> SealedSnapshotSummary:
    """Export one exact commit as an authenticated source-only snapshot.

    The output directory must not already exist and is never overwritten.  Git
    content is read only by raw object ID; checkout, attributes, filters,
    hooks, submodule recursion, and Git LFS hydration are deliberately absent. Git mode
    ``120000`` blobs are never resolved or created as host links: their target
    bytes are materialized as ordinary files under the fixed v3 policy.
    """

    if not isinstance(repository, GitRepository):
        raise ValueError("repository must be a GitRepository")
    if not isinstance(policy, SnapshotPolicy):
        raise ValueError("policy must be a SnapshotPolicy")
    task_id, repo_url, commit, key_id = _validate_binding(
        task_id, repo_url, commit, key_id
    )
    key = _copy_key(attestation_key)
    repository.assert_storage_safe()
    if repository.history_is_shallow():
        raise SealedSnapshotError(
            "shallow_repository_rejected",
            "sealed snapshots require a complete local repository",
        )
    root_tree = repository.commit_tree(commit)
    try:
        raw_entries = repository.list_tree_entries(
            commit,
            max_entries=policy.max_files,
            max_output_bytes=policy.max_tree_object_bytes,
            include_trees=True,
        )
    except GitBlobTooLarge as error:
        raise SealedSnapshotError(
            "source_limit_exceeded", "Git tree exceeds the snapshot policy"
        ) from error
    entries = _validate_entries(raw_entries, policy)
    staging = _begin_staging(output_dir, repository)
    file_records: list[SealedSnapshotEntry] = []
    total_bytes = 0
    regular_file_bytes = 0
    try:
        _create_staging_dir(staging, "tree")
        _create_staging_dir(staging, "control")
        for entry, components, _ in entries:
            if entry.mode == "160000":
                data = b"gitlink " + entry.object_id.encode("ascii") + b"\n"
                if len(data) > policy.max_file_bytes:
                    raise SealedSnapshotError(
                        "source_limit_exceeded",
                        "a materialized gitlink marker exceeds its byte budget",
                    )
            else:
                try:
                    data = repository.read_blob_object(
                        entry.object_id, max_bytes=policy.max_file_bytes
                    )
                except GitBlobTooLarge as error:
                    raise SealedSnapshotError(
                        "source_limit_exceeded", "a source blob exceeds its byte budget"
                    ) from error
            total_bytes += len(data)
            if entry.mode != "160000":
                regular_file_bytes += len(data)
            if total_bytes > policy.max_total_bytes:
                raise SealedSnapshotError(
                    "source_limit_exceeded", "source tree exceeds its total byte budget"
                )
            if entry.mode != "160000" and _is_lfs_pointer(data):
                raise SealedSnapshotError(
                    "source_lfs_rejected", "Git LFS pointer blobs are forbidden"
                )
            if entry.mode == "160000":
                record: SealedSnapshotEntry = SealedSnapshotGitlink(
                    path=entry.path,
                    target_commit_oid=entry.object_id,
                    materialized_sha256=hashlib.sha256(data).hexdigest(),
                )
            else:
                record = SealedSnapshotFile(
                    path=entry.path,
                    git_mode=entry.mode,
                    blob_oid=entry.object_id,
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                )
            # `_write_staging_file` always creates a no-follow regular 0600
            # node. This is intentional for every entry and is the complete
            # representation transform for Git mode 120000: `data` remains
            # the raw target blob and is never interpreted as a path.
            _write_staging_file(staging, "tree/" + "/".join(components), data)
            file_records.append(record)

        repository.assert_storage_safe()
        if repository.history_is_shallow():
            raise SealedSnapshotError(
                "shallow_repository_rejected",
                "repository became shallow during snapshot preparation",
            )
        files = tuple(file_records)
        manifest, content_root = _manifest_bytes(
            task_id=task_id,
            repo_url=repo_url,
            commit=commit,
            root_tree=root_tree,
            files=files,
            total_bytes=total_bytes,
            policy=policy,
        )
        manifest_sha256 = hashlib.sha256(manifest).hexdigest()
        attestation = {
            "algorithm": ATTESTATION_ALGORITHM,
            "contract_version": SNAPSHOT_CONTRACT_VERSION,
            "key_id": key_id,
            "mac": _attestation_mac(key, key_id, manifest),
            "manifest_sha256": manifest_sha256,
        }
        attestation_bytes = _canonical_json(attestation) + b"\n"
        if len(attestation_bytes) > _MAX_ATTESTATION_BYTES:
            raise SealedSnapshotError(
                "source_limit_exceeded", "attestation exceeds its fixed byte budget"
            )
        _write_staging_file(staging, "control/manifest.jsonl", manifest)
        _write_staging_file(
            staging, "control/attestation.json", attestation_bytes
        )
        _fsync_staging_directories(staging)
        _rename_noreplace(staging)
        return SealedSnapshotSummary(
            snapshot_root=staging.output,
            task_id=task_id,
            repo_url=repo_url,
            commit=commit,
            root_tree=root_tree,
            content_root=content_root,
            manifest_sha256=manifest_sha256,
            file_count=len(files),
            total_bytes=total_bytes,
            entry_count=len(files),
            regular_file_count=sum(type(item) is SealedSnapshotFile for item in files),
            gitlink_count=sum(type(item) is SealedSnapshotGitlink for item in files),
            regular_file_bytes=regular_file_bytes,
            materialized_bytes=total_bytes,
            files=files,
        )
    except FileExistsError as error:
        raise SealedSnapshotError(
            "output_exists", "output directory already exists; overwrite is forbidden"
        ) from error
    except SealedSnapshotError:
        raise
    except (GitFactError, OSError) as error:
        raise SealedSnapshotError(
            "snapshot_preparation_failed", "sealed snapshot preparation failed"
        ) from error
    finally:
        _cleanup_staging(staging)
        _close_staging(staging)


class _DuplicateJsonKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _parse_canonical_json(payload: bytes, *, code: str) -> dict[str, Any]:
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise SealedSnapshotError(code, "control JSON is not one canonical line")
    try:
        text = payload[:-1].decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SealedSnapshotError(code, "control JSON is malformed") from error
    if not isinstance(value, dict):
        raise SealedSnapshotError(code, "control JSON is not canonical")
    try:
        canonical = _canonical_json(value)
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise SealedSnapshotError(code, "control JSON is malformed") from error
    if canonical != payload[:-1]:
        raise SealedSnapshotError(code, "control JSON is not canonical")
    return value


def _policy_matches_exactly(value: object, policy: SnapshotPolicy) -> bool:
    expected = policy.to_dict()
    if not isinstance(value, dict) or set(value) != set(expected):
        return False
    for key, expected_value in expected.items():
        supplied = value.get(key)
        if type(supplied) is not type(expected_value) or supplied != expected_value:
            return False
    return True


def _read_stable_file(path: Path, maximum: int) -> tuple[bytes, tuple[int, int, int, int | None, int | None]]:
    before = _require_safe_regular(path)
    _windows_assert_no_named_streams(path)
    if before.st_size > maximum:
        raise SealedSnapshotError(
            "snapshot_limit_exceeded", "snapshot file exceeds its byte budget"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SealedSnapshotError(
            "snapshot_unavailable", "snapshot file cannot be opened"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink > 1
            or _directory_identity(opened) != _directory_identity(before)
        ):
            raise SealedSnapshotError(
                "snapshot_changed", "snapshot file changed while opening"
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise SealedSnapshotError(
                "snapshot_limit_exceeded", "snapshot file exceeds its byte budget"
            )
        finished = os.fstat(descriptor)
        if _identity(opened) != _identity(finished) or len(data) != opened.st_size:
            raise SealedSnapshotError(
                "snapshot_changed", "snapshot file changed while reading"
            )
    finally:
        os.close(descriptor)
    after = _require_safe_regular(path)
    _windows_assert_no_named_streams(path)
    if _identity(before) != _identity(after):
        raise SealedSnapshotError(
            "snapshot_changed", "snapshot file identity changed while reading"
        )
    return data, _identity(after)


def _fixed_snapshot_layout(root: Path) -> tuple[Path, Path]:
    root_state = _require_safe_directory(root)
    if root_state.st_nlink < 1:
        raise SealedSnapshotError("unsafe_snapshot_path", "invalid snapshot root")
    root_names = _bounded_directory_names(root, maximum=3)
    if root_names != {"control", "tree"}:
        raise SealedSnapshotError(
            "snapshot_layout_mismatch", "snapshot root has unexpected entries"
        )
    tree = root / "tree"
    control = root / "control"
    _require_safe_directory(tree)
    _require_safe_directory(control)
    control_names = _bounded_directory_names(control, maximum=3)
    if control_names != {"attestation.json", "manifest.jsonl"}:
        raise SealedSnapshotError(
            "snapshot_layout_mismatch", "snapshot control set is not fixed"
        )
    return tree, control


def _bounded_directory_names(path: Path, *, maximum: int) -> set[str]:
    names: set[str] = set()
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                if len(names) >= maximum:
                    raise SealedSnapshotError(
                        "snapshot_layout_mismatch",
                        "snapshot directory contains too many entries",
                    )
                names.add(entry.name)
    except SealedSnapshotError:
        raise
    except OSError as error:
        raise SealedSnapshotError(
            "snapshot_unavailable", "snapshot directory cannot be enumerated"
        ) from error
    return names


def _parse_manifest(
    payload: bytes,
    *,
    expected_task_id: str,
    expected_repo_url: str,
    expected_commit: str,
    policy: SnapshotPolicy,
) -> tuple[str, tuple[SealedSnapshotEntry, ...], int, str]:
    if not payload.endswith(b"\n") or len(payload) > policy.max_manifest_bytes:
        raise SealedSnapshotError(
            "manifest_invalid", "sealed manifest violates its byte framing"
        )
    raw_lines = payload.splitlines(keepends=True)
    if not 2 <= len(raw_lines) <= policy.max_files + 2:
        raise SealedSnapshotError(
            "manifest_invalid", "sealed manifest has an invalid record count"
        )
    records: list[dict[str, Any]] = []
    for raw_line in raw_lines:
        records.append(_parse_canonical_json(raw_line, code="manifest_invalid"))
    header = records[0]
    expected_header_keys = {
        "commit",
        "contract_version",
        "policy",
        "record_type",
        "repo_url",
        "root_tree",
        "task_id",
    }
    if set(header) != expected_header_keys or header.get("record_type") != "header":
        raise SealedSnapshotError("manifest_invalid", "manifest header is invalid")
    if (
        header["contract_version"] != SNAPSHOT_CONTRACT_VERSION
        or not _policy_matches_exactly(header["policy"], policy)
        or header["task_id"] != expected_task_id
        or header["repo_url"] != expected_repo_url
        or header["commit"] != expected_commit
        or not isinstance(header["root_tree"], str)
        or _SHA1_RE.fullmatch(header["root_tree"]) is None
    ):
        raise SealedSnapshotError(
            "manifest_binding_mismatch", "manifest trusted binding does not match"
        )

    files: list[SealedSnapshotEntry] = []
    seen_exact: set[bytes] = set()
    seen_portable: set[str] = set()
    previous_path: bytes | None = None
    total_bytes = 0
    regular_file_bytes = 0
    regular_file_count = 0
    gitlink_count = 0
    file_lines: list[bytes] = []
    file_keys = {"blob_oid", "git_mode", "path", "record_type", "sha256", "size"}
    gitlink_keys = {"git_mode", "materialized_sha256", "path", "record_type", "representation", "size", "target_commit_oid"}
    for record, raw_line in zip(records[1:-1], raw_lines[1:-1]):
        record_type = record.get("record_type")
        if not (
            (record_type == "file" and set(record) == file_keys)
            or (record_type == "gitlink" and set(record) == gitlink_keys)
        ):
            raise SealedSnapshotError("manifest_invalid", "manifest file record is invalid")
        components, raw_path, collision = _validate_portable_path(
            record.get("path"), policy
        )
        del components
        if raw_path in seen_exact or collision in seen_portable:
            raise SealedSnapshotError(
                "manifest_invalid", "manifest contains colliding paths"
            )
        if previous_path is not None and raw_path <= previous_path:
            raise SealedSnapshotError(
                "manifest_invalid", "manifest file records are not strictly sorted"
            )
        if previous_path is not None and raw_path.startswith(previous_path + b"/"):
            raise SealedSnapshotError(
                "manifest_invalid", "manifest contains a path prefix collision"
            )
        previous_path = raw_path
        seen_exact.add(raw_path)
        seen_portable.add(collision)
        size = record.get("size")
        digest_field = "sha256" if record_type == "file" else "materialized_sha256"
        oid_field = "blob_oid" if record_type == "file" else "target_commit_oid"
        if (
            (record_type == "file" and record.get("git_mode") not in {"100644", "100755", "120000"})
            or (record_type == "gitlink" and (
                record.get("git_mode") != "160000"
                or record.get("representation") != GITLINK_REPRESENTATION
                or size != 49
            ))
            or not isinstance(record.get(oid_field), str)
            or _SHA1_RE.fullmatch(record[oid_field]) is None
            or not isinstance(record.get(digest_field), str)
            or _SHA256_RE.fullmatch(record[digest_field]) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= policy.max_file_bytes
        ):
            raise SealedSnapshotError("manifest_invalid", "manifest file metadata is invalid")
        total_bytes += size
        if record_type == "file":
            regular_file_count += 1
            regular_file_bytes += size
        else:
            gitlink_count += 1
        if total_bytes > policy.max_total_bytes:
            raise SealedSnapshotError(
                "manifest_invalid", "manifest exceeds the total byte budget"
            )
        files.append(
            SealedSnapshotFile(
                path=record["path"],
                git_mode=record["git_mode"],
                blob_oid=record["blob_oid"],
                size=size,
                sha256=record["sha256"],
            )
            if record_type == "file"
            else SealedSnapshotGitlink(
                path=record["path"],
                target_commit_oid=record["target_commit_oid"],
                materialized_sha256=record["materialized_sha256"],
                size=size,
                git_mode=record["git_mode"],
                representation=record["representation"],
            )
        )
        file_lines.append(raw_line)

    if not files:
        raise SealedSnapshotError(
            "manifest_invalid", "sealed manifests must contain at least one file"
        )

    footer = records[-1]
    footer_keys = {
        "content_root",
        "entry_count",
        "file_count",
        "gitlink_count",
        "materialized_bytes",
        "record_type",
        "regular_file_bytes",
        "regular_file_count",
        "total_bytes",
    }
    if set(footer) != footer_keys:
        raise SealedSnapshotError("manifest_invalid", "manifest footer is invalid")
    content_root = _content_root(file_lines)
    integer_totals = {
        "entry_count": len(files),
        "file_count": len(files),
        "gitlink_count": gitlink_count,
        "materialized_bytes": total_bytes,
        "regular_file_bytes": regular_file_bytes,
        "regular_file_count": regular_file_count,
        "total_bytes": total_bytes,
    }
    if (
        footer.get("record_type") != "footer"
        or any(
            isinstance(footer.get(name), bool)
            or not isinstance(footer.get(name), int)
            or footer.get(name) != expected
            for name, expected in integer_totals.items()
        )
        or footer.get("content_root") != content_root
    ):
        raise SealedSnapshotError("manifest_invalid", "manifest footer does not match")
    return header["root_tree"], tuple(files), total_bytes, content_root


def _scan_tree(
    tree: Path,
    policy: SnapshotPolicy,
    *,
    expected_files: frozenset[str],
    expected_directories: frozenset[str],
) -> tuple[
    dict[str, tuple[int, int, int, int | None, int | None]],
    dict[str, tuple[int, int, int, int | None, int | None]],
]:
    files: dict[str, tuple[int, int, int, int | None, int | None]] = {}
    directories: dict[str, tuple[int, int, int, int | None, int | None]] = {}
    collision_keys: set[str] = set()
    total_bytes = 0
    stack: list[tuple[Path, tuple[str, ...]]] = [(tree, ())]
    while stack:
        directory, prefix = stack.pop()
        state = _require_safe_directory(directory)
        _windows_assert_no_named_streams(directory)
        relative_directory = "/".join(prefix)
        if relative_directory:
            if len(files) + len(directories) >= policy.max_files:
                raise SealedSnapshotError(
                    "snapshot_limit_exceeded", "snapshot tree exceeds its node budget"
                )
            directories[relative_directory] = _identity(state)
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if len(files) + len(directories) >= policy.max_files:
                        raise SealedSnapshotError(
                            "snapshot_limit_exceeded",
                            "snapshot tree exceeds its node budget",
                        )
                    relative = "/".join((*prefix, entry.name))
                    components, _, collision = _validate_portable_path(
                        relative, policy
                    )
                    if collision in collision_keys:
                        raise SealedSnapshotError(
                            "snapshot_path_collision",
                            "snapshot contains colliding paths",
                        )
                    collision_keys.add(collision)
                    try:
                        # Direct lstat supplies stable volume/file identities on
                        # Windows; DirEntry.stat may report zero device/inode values.
                        item = os.lstat(entry.path)
                    except OSError as error:
                        raise SealedSnapshotError(
                            "snapshot_unavailable",
                            "snapshot tree entry is unavailable",
                        ) from error
                    if stat.S_ISLNK(item.st_mode) or _is_reparse(item):
                        raise SealedSnapshotError(
                            "unsafe_snapshot_path", "snapshot tree contains a link"
                        )
                    if stat.S_ISDIR(item.st_mode):
                        _windows_assert_no_named_streams(Path(entry.path))
                        if relative not in expected_directories:
                            raise SealedSnapshotError(
                                "snapshot_tree_mismatch",
                                "snapshot tree contains an unexpected directory",
                            )
                        stack.append((Path(entry.path), components))
                        continue
                    # Some Windows directory enumeration APIs report zero links
                    # even though direct lstat/open reports one.  Values above
                    # one remain an unambiguous hard-link rejection.
                    if not stat.S_ISREG(item.st_mode) or item.st_nlink > 1:
                        raise SealedSnapshotError(
                            "unsafe_snapshot_path",
                            "snapshot tree contains a non-regular file",
                        )
                    _windows_assert_no_named_streams(Path(entry.path))
                    if relative not in expected_files:
                        raise SealedSnapshotError(
                            "snapshot_tree_mismatch",
                            "snapshot tree contains an unexpected file",
                        )
                    if item.st_size > policy.max_file_bytes:
                        raise SealedSnapshotError(
                            "snapshot_limit_exceeded",
                            "snapshot tree exceeds a resource budget",
                        )
                    total_bytes += item.st_size
                    if total_bytes > policy.max_total_bytes:
                        raise SealedSnapshotError(
                            "snapshot_limit_exceeded",
                            "snapshot tree exceeds its byte budget",
                        )
                    files[relative] = _identity(item)
        except SealedSnapshotError:
            raise
        except OSError as error:
            raise SealedSnapshotError(
                "snapshot_unavailable", "snapshot tree cannot be enumerated"
            ) from error
    return files, directories


def verify_sealed_snapshot(
    snapshot_root: str | os.PathLike[str],
    *,
    expected_task_id: str,
    expected_repo_url: str,
    expected_commit: str,
    attestation_key: bytes | bytearray | memoryview,
    expected_key_id: str,
    policy: SnapshotPolicy = DEFAULT_SNAPSHOT_POLICY,
) -> VerifiedSealedSnapshot:
    """Authenticate and fully re-verify a materialized sealed snapshot.

    Verification checks the trusted binding, detached HMAC, canonical manifest,
    exact tree set, raw bytes, Git blob IDs, SHA-256 digests, resource limits,
    and link/reparse/hard-link exclusion.  The returned ``agent_tree`` must be
    mounted read-only and without exposing the snapshot parent or ``control``.
    """

    if not isinstance(policy, SnapshotPolicy):
        raise ValueError("policy must be a SnapshotPolicy")
    expected_task_id, expected_repo_url, expected_commit, expected_key_id = (
        _validate_binding(
            expected_task_id,
            expected_repo_url,
            expected_commit,
            expected_key_id,
        )
    )
    key = _copy_key(attestation_key)
    root = Path(os.path.abspath(os.fspath(snapshot_root)))
    checked_parent = _checked_parent_chain(root.parent)
    tree, control = _fixed_snapshot_layout(root)
    root_identity = _directory_identity(_require_safe_directory(root))
    tree_identity = _directory_identity(_require_safe_directory(tree))
    control_identity = _directory_identity(_require_safe_directory(control))

    manifest, manifest_identity = _read_stable_file(
        control / "manifest.jsonl", policy.max_manifest_bytes
    )
    attestation_payload, attestation_identity = _read_stable_file(
        control / "attestation.json", _MAX_ATTESTATION_BYTES
    )
    attestation = _parse_canonical_json(
        attestation_payload, code="attestation_invalid"
    )
    if set(attestation) != {
        "algorithm",
        "contract_version",
        "key_id",
        "mac",
        "manifest_sha256",
    }:
        raise SealedSnapshotError(
            "attestation_invalid", "attestation fields are invalid"
        )
    manifest_sha256 = hashlib.sha256(manifest).hexdigest()
    supplied_mac = attestation.get("mac")
    if (
        attestation.get("algorithm") != ATTESTATION_ALGORITHM
        or attestation.get("contract_version") != SNAPSHOT_CONTRACT_VERSION
        or attestation.get("key_id") != expected_key_id
        or attestation.get("manifest_sha256") != manifest_sha256
        or not isinstance(supplied_mac, str)
        or _SHA256_RE.fullmatch(supplied_mac) is None
        or not hmac.compare_digest(
            supplied_mac, _attestation_mac(key, expected_key_id, manifest)
        )
    ):
        raise SealedSnapshotError(
            "attestation_invalid", "snapshot attestation did not verify"
        )

    root_tree, files, total_bytes, content_root = _parse_manifest(
        manifest,
        expected_task_id=expected_task_id,
        expected_repo_url=expected_repo_url,
        expected_commit=expected_commit,
        policy=policy,
    )
    expected_paths = frozenset(record.path for record in files)
    expected_directory_set: set[str] = set()
    for record in files:
        parts = record.path.split("/")
        for depth in range(1, len(parts)):
            expected_directory_set.add("/".join(parts[:depth]))
            if len(expected_paths) + len(expected_directory_set) > policy.max_files:
                raise SealedSnapshotError(
                    "snapshot_limit_exceeded",
                    "snapshot manifest exceeds its node budget",
                )
    expected_dirs = frozenset(expected_directory_set)
    before_files, before_dirs = _scan_tree(
        tree,
        policy,
        expected_files=expected_paths,
        expected_directories=expected_dirs,
    )
    if set(before_files) != expected_paths or set(before_dirs) != expected_dirs:
        raise SealedSnapshotError(
            "snapshot_tree_mismatch", "snapshot tree fixed set differs from manifest"
        )
    for record in files:
        data, file_identity = _read_stable_file(tree.joinpath(*record.path.split("/")), record.size)
        if file_identity != before_files[record.path]:
            raise SealedSnapshotError(
                "snapshot_changed", "snapshot tree changed during verification"
            )
        if type(record) is SealedSnapshotGitlink:
            expected_marker = b"gitlink " + record.target_commit_oid.encode("ascii") + b"\n"
            object_matches = data == expected_marker
        else:
            object_matches = hashlib.sha1(
                f"blob {len(data)}\0".encode("ascii") + data,
                usedforsecurity=False,
            ).hexdigest() == record.blob_oid
        if (
            len(data) != record.size
            or hashlib.sha256(data).hexdigest() != record.sha256
            or not object_matches
            or (type(record) is SealedSnapshotFile and _is_lfs_pointer(data))
        ):
            raise SealedSnapshotError(
                "snapshot_tree_mismatch", "snapshot bytes differ from the manifest"
            )

    after_files, after_dirs = _scan_tree(
        tree,
        policy,
        expected_files=expected_paths,
        expected_directories=expected_dirs,
    )
    if before_files != after_files or before_dirs != after_dirs:
        raise SealedSnapshotError(
            "snapshot_changed", "snapshot tree changed during verification"
        )
    _assert_parent_chain(checked_parent)
    if (
        _directory_identity(_require_safe_directory(root)) != root_identity
        or _directory_identity(_require_safe_directory(tree)) != tree_identity
        or _directory_identity(_require_safe_directory(control)) != control_identity
        or _identity(_require_safe_regular(control / "manifest.jsonl"))
        != manifest_identity
        or _identity(_require_safe_regular(control / "attestation.json"))
        != attestation_identity
    ):
        raise SealedSnapshotError(
            "snapshot_changed", "snapshot identity changed during verification"
        )
    _fixed_snapshot_layout(root)
    return VerifiedSealedSnapshot(
        snapshot_root=root,
        task_id=expected_task_id,
        repo_url=expected_repo_url,
        commit=expected_commit,
        root_tree=root_tree,
        content_root=content_root,
        manifest_sha256=manifest_sha256,
        key_id=expected_key_id,
        file_count=len(files),
        total_bytes=total_bytes,
        entry_count=len(files),
        regular_file_count=sum(type(item) is SealedSnapshotFile for item in files),
        gitlink_count=sum(type(item) is SealedSnapshotGitlink for item in files),
        regular_file_bytes=sum(item.size for item in files if type(item) is SealedSnapshotFile),
        materialized_bytes=total_bytes,
        files=files,
    )


__all__ = [
    "ATTESTATION_ALGORITHM",
    "DEFAULT_SNAPSHOT_POLICY",
    "GIT_SYMLINK_REPRESENTATION",
    "GITLINK_REPRESENTATION",
    "SNAPSHOT_CONTRACT_VERSION",
    "SNAPSHOT_POLICY_VERSION",
    "SealedSnapshotError",
    "SealedSnapshotFile",
    "SealedSnapshotGitlink",
    "SealedSnapshotEntry",
    "SealedSnapshotSourceAudit",
    "SealedSnapshotSummary",
    "SnapshotPolicy",
    "VerifiedSealedSnapshot",
    "audit_sealed_snapshot_source",
    "prepare_sealed_snapshot",
    "verify_sealed_snapshot",
]
