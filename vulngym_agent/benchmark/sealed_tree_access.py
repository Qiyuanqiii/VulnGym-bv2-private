"""Trusted, bounded read access to an authenticated sealed source tree.

The discovery agents receive :class:`BoundSealedTree`, never a filesystem
path, an attestation key, or the authenticated control directory.  Binding is
performed only after the complete sealed-snapshot verifier succeeds and the
snapshot-native D0 task identifiers match exactly.

Every successful read is constrained to one exact manifest member, checks the
original directory and file identities, performs a stable descriptor read,
and revalidates both SHA-256 and the raw Git blob object id.  ``finalize()``
performs one more complete authenticated verification and permanently closes
the capability.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import threading
from typing import Callable, Final, Mapping, Protocol

from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.sealed_snapshot import (
    DEFAULT_SNAPSHOT_POLICY,
    SealedSnapshotError,
    SealedSnapshotFile,
    SealedSnapshotGitlink,
    SnapshotPolicy,
    VerifiedSealedSnapshot,
    _scan_tree,
    _windows_assert_no_named_streams,
    verify_sealed_snapshot,
)
from vulngym_agent.benchmark.worker_handoff import WorkerHandoffError, WorkerHandoffV2


SEALED_TREE_ACCESS_VERSION: Final[str] = "source-discovery-sealed-tree-v2"

_HARD_MAX_INVENTORY_CALLS: Final[int] = 64
_HARD_MAX_READ_CALLS: Final[int] = 8_192
_HARD_MAX_BYTES_PER_READ: Final[int] = 16 * 1024 * 1024
_HARD_MAX_TOTAL_BYTES_READ: Final[int] = 256 * 1024 * 1024
_READ_CHUNK_BYTES: Final[int] = 1024 * 1024
_MIN_ATTESTATION_KEY_BYTES: Final[int] = 16
_MAX_ATTESTATION_KEY_BYTES: Final[int] = 4_096

_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "access_claimed",
        "access_finalized",
        "invalid_argument",
        "invalid_binding",
        "source_changed",
        "source_limit_exceeded",
        "source_not_found",
        "snapshot_verification_failed",
        "unsafe_source_path",
    }
)


class SealedTreeAccessError(RuntimeError):
    """Stable, host-path-free failure at the sealed-tree capability boundary."""

    def __init__(self, code: str, message: str) -> None:
        if not isinstance(code, str) or code not in _ERROR_CODES:
            raise ValueError("unknown sealed-tree access error code")
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class SealedTreeAccessLimits:
    """Bounded resource policy for one source-discovery capability."""

    max_inventory_calls: int = 8
    max_read_calls: int = 4_096
    max_bytes_per_read: int = 4 * 1024 * 1024
    max_total_bytes_read: int = 64 * 1024 * 1024
    version: str = SEALED_TREE_ACCESS_VERSION

    def __post_init__(self) -> None:
        limits = (
            ("max_inventory_calls", self.max_inventory_calls, _HARD_MAX_INVENTORY_CALLS),
            ("max_read_calls", self.max_read_calls, _HARD_MAX_READ_CALLS),
            (
                "max_bytes_per_read",
                self.max_bytes_per_read,
                _HARD_MAX_BYTES_PER_READ,
            ),
            (
                "max_total_bytes_read",
                self.max_total_bytes_read,
                _HARD_MAX_TOTAL_BYTES_READ,
            ),
        )
        if self.version != SEALED_TREE_ACCESS_VERSION:
            raise ValueError("sealed-tree access policy version is invalid")
        for name, value, maximum in limits:
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be within its fixed hard limit")
        if self.max_bytes_per_read > self.max_total_bytes_read:
            raise ValueError("per-read bytes must not exceed aggregate bytes")


DEFAULT_SEALED_TREE_ACCESS_LIMITS: Final[SealedTreeAccessLimits] = (
    SealedTreeAccessLimits()
)


def _canonical_access_limits(value: object) -> SealedTreeAccessLimits:
    if type(value) is not SealedTreeAccessLimits:
        raise SealedTreeAccessError(
            "invalid_argument", "sealed-tree limits must have an exact type"
        )
    try:
        fields = (
            value.max_inventory_calls,
            value.max_read_calls,
            value.max_bytes_per_read,
            value.max_total_bytes_read,
            value.version,
        )
    except (AttributeError, TypeError):
        raise SealedTreeAccessError(
            "invalid_argument", "sealed-tree limits are incomplete"
        ) from None
    if any(
        type(item) is not expected
        for item, expected in zip(fields, (int, int, int, int, str), strict=True)
    ):
        raise SealedTreeAccessError(
            "invalid_argument", "sealed-tree limit fields have invalid types"
        )
    try:
        return SealedTreeAccessLimits(
            max_inventory_calls=fields[0],
            max_read_calls=fields[1],
            max_bytes_per_read=fields[2],
            max_total_bytes_read=fields[3],
            version=fields[4],
        )
    except (AttributeError, TypeError, ValueError):
        raise SealedTreeAccessError(
            "invalid_argument", "sealed-tree limits are invalid"
        ) from None


def _canonical_snapshot_policy(value: object) -> SnapshotPolicy:
    if type(value) is not SnapshotPolicy:
        raise SealedTreeAccessError(
            "invalid_argument", "snapshot policy must have an exact type"
        )
    try:
        fields = (
            value.max_files,
            value.max_file_bytes,
            value.max_total_bytes,
            value.max_path_bytes,
            value.max_component_bytes,
            value.max_depth,
            value.max_tree_object_bytes,
            value.max_manifest_bytes,
            value.git_symlink_representation,
            value.gitlink_representation,
        )
    except (AttributeError, TypeError):
        raise SealedTreeAccessError(
            "invalid_argument", "snapshot policy is incomplete"
        ) from None
    if (
        any(type(item) is not int for item in fields[:-2])
        or any(type(item) is not str for item in fields[-2:])
    ):
        raise SealedTreeAccessError(
            "invalid_argument", "snapshot policy fields have invalid exact types"
        )
    try:
        return SnapshotPolicy(
            max_files=fields[0],
            max_file_bytes=fields[1],
            max_total_bytes=fields[2],
            max_path_bytes=fields[3],
            max_component_bytes=fields[4],
            max_depth=fields[5],
            max_tree_object_bytes=fields[6],
            max_manifest_bytes=fields[7],
            git_symlink_representation=fields[8],
            gitlink_representation=fields[9],
        )
    except (AttributeError, TypeError, ValueError):
        raise SealedTreeAccessError(
            "invalid_argument", "snapshot policy is invalid"
        ) from None


@dataclass(frozen=True, slots=True)
class SealedTreeFile:
    """One path-free-of-host-state file record from the verified manifest."""

    path: str
    git_mode: str
    blob_oid: str
    size: int
    sha256: str

    @classmethod
    def _from_verified(cls, value: SealedSnapshotFile) -> "SealedTreeFile":
        return cls(
            path=value.path,
            git_mode=value.git_mode,
            blob_oid=value.blob_oid,
            size=value.size,
            sha256=value.sha256,
        )

    def to_dict(self) -> dict[str, str | int]:
        return {
            "blob_oid": self.blob_oid,
            "git_mode": self.git_mode,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True, slots=True)
class SourceReadUsage:
    """One immutable, content-bound successful read receipt."""

    sequence: int
    path: str
    bytes_read: int
    sha256: str
    blob_oid: str

    def to_dict(self) -> dict[str, str | int]:
        return {
            "blob_oid": self.blob_oid,
            "bytes_read": self.bytes_read,
            "path": self.path,
            "sequence": self.sequence,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class SourceUsageLedger:
    """Bounded snapshot of source access, suitable for trusted artifacts."""

    task_id: str
    snapshot_id: str
    inventory_calls: int
    read_calls: int
    bytes_read: int
    reads: tuple[SourceReadUsage, ...]
    finalized: bool
    verification_succeeded: bool
    access_version: str = SEALED_TREE_ACCESS_VERSION

    def to_dict(self) -> dict[str, object]:
        return {
            "access_version": self.access_version,
            "bytes_read": self.bytes_read,
            "finalized": self.finalized,
            "inventory_calls": self.inventory_calls,
            "read_calls": self.read_calls,
            "reads": [item.to_dict() for item in self.reads],
            "snapshot_id": self.snapshot_id,
            "task_id": self.task_id,
            "verification_succeeded": self.verification_succeeded,
        }


_DirectoryIdentity = tuple[int, int]
_FileIdentity = tuple[int, int, int, int | None, int | None]


class _TreeAuthority(Protocol):
    """Private structural interface shared by authenticated and mounted trees."""

    def read(self, record: SealedTreeFile) -> bytes: ...

    def reverify(self, task: DiscoveryTaskInputV1) -> None: ...

    def close(self) -> None: ...


def _best_effort_close(authority: _TreeAuthority | None) -> None:
    if authority is None:
        return
    try:
        authority.close()
    except BaseException:
        pass


def _is_reparse(result: os.stat_result) -> bool:
    attributes = getattr(result, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _safe_directory(path: Path) -> tuple[os.stat_result, _DirectoryIdentity]:
    try:
        result = os.lstat(path)
    except OSError:
        raise SealedTreeAccessError(
            "source_changed", "a trusted source directory is unavailable"
        ) from None
    if (
        not stat.S_ISDIR(result.st_mode)
        or stat.S_ISLNK(result.st_mode)
        or _is_reparse(result)
    ):
        raise SealedTreeAccessError(
            "unsafe_source_path", "trusted source paths must remain plain directories"
        )
    return result, (result.st_dev, result.st_ino)


def _file_identity(result: os.stat_result) -> _FileIdentity:
    return (
        result.st_dev,
        result.st_ino,
        result.st_size,
        getattr(result, "st_mtime_ns", None),
        getattr(result, "st_ctime_ns", None),
    )


def _safe_regular(path: Path) -> tuple[os.stat_result, _FileIdentity]:
    try:
        result = os.lstat(path)
    except OSError:
        raise SealedTreeAccessError(
            "source_changed", "a trusted source file is unavailable"
        ) from None
    if (
        not stat.S_ISREG(result.st_mode)
        or stat.S_ISLNK(result.st_mode)
        or _is_reparse(result)
        or result.st_nlink > 1
    ):
        raise SealedTreeAccessError(
            "unsafe_source_path", "trusted source entries must remain plain files"
        )
    return result, _file_identity(result)


def _root_chain(path: Path) -> tuple[Path, ...]:
    return tuple(reversed(path.parents)) + (path,)


def _assert_safe_open_directory(
    result: os.stat_result,
    *,
    expected: _DirectoryIdentity,
) -> None:
    if (
        not stat.S_ISDIR(result.st_mode)
        or stat.S_ISLNK(result.st_mode)
        or _is_reparse(result)
        or (result.st_dev, result.st_ino) != expected
    ):
        raise SealedTreeAccessError(
            "source_changed", "an opened source directory identity did not match"
        )


def _assert_safe_open_file(
    result: os.stat_result,
    *,
    expected: _FileIdentity,
    expected_size: int,
) -> None:
    if (
        not stat.S_ISREG(result.st_mode)
        or stat.S_ISLNK(result.st_mode)
        or _is_reparse(result)
        or result.st_nlink > 1
        or (result.st_dev, result.st_ino) != expected[:2]
        or result.st_size != expected_size
    ):
        raise SealedTreeAccessError(
            "source_changed", "an opened source file identity did not match"
        )


def _posix_open_tree_descriptor(
    tree: Path,
    *,
    expected: _DirectoryIdentity,
) -> int:
    if (
        os.name == "nt"
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
    ):
        raise SealedTreeAccessError(
            "unsafe_source_path",
            "this platform cannot provide handle-relative source traversal",
        )
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(tree, flags)
        _assert_safe_open_directory(os.fstat(descriptor), expected=expected)
        return descriptor
    except SealedTreeAccessError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise SealedTreeAccessError(
            "source_changed", "the authenticated source root could not be pinned"
        ) from None


def _posix_open_relative_file(
    tree_descriptor: int,
    parts: tuple[str, ...],
    *,
    directories: Mapping[str, _DirectoryIdentity],
    expected_file: _FileIdentity,
    expected_size: int,
) -> tuple[int, os.stat_result]:
    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    current: int | None = None
    result_descriptor: int | None = None
    try:
        current = os.dup(tree_descriptor)
        _assert_safe_open_directory(os.fstat(current), expected=directories[""])
        for depth, component in enumerate(parts[:-1], start=1):
            next_descriptor = os.open(component, directory_flags, dir_fd=current)
            try:
                relative = "/".join(parts[:depth])
                _assert_safe_open_directory(
                    os.fstat(next_descriptor), expected=directories[relative]
                )
            except BaseException:
                os.close(next_descriptor)
                raise
            os.close(current)
            current = next_descriptor
        result_descriptor = os.open(parts[-1], file_flags, dir_fd=current)
        opened = os.fstat(result_descriptor)
        _assert_safe_open_file(
            opened, expected=expected_file, expected_size=expected_size
        )
        return result_descriptor, opened
    except SealedTreeAccessError:
        if result_descriptor is not None:
            os.close(result_descriptor)
        raise
    except OSError:
        if result_descriptor is not None:
            try:
                os.close(result_descriptor)
            except OSError:
                pass
        raise SealedTreeAccessError(
            "source_changed", "handle-relative source traversal failed"
        ) from None
    finally:
        if current is not None:
            try:
                os.close(current)
            except OSError:
                pass


def _windows_normalized_final_path(handle: int) -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_final = kernel32.GetFinalPathNameByHandleW
    get_final.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    get_final.restype = wintypes.DWORD
    required = get_final(handle, None, 0, 0)
    if required < 1:
        raise OSError(ctypes.get_last_error(), "final source identity is unavailable")
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = get_final(handle, buffer, len(buffer), 0)
    if written < 1 or written >= len(buffer):
        raise OSError(ctypes.get_last_error(), "final source identity is unavailable")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.normpath(value))


def _windows_open_source_handle(path: Path, *, read_data: bool) -> tuple[int, str]:
    if os.name != "nt":
        raise OSError("Windows source handles are unavailable")
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
    desired_access = 0x0080 | (0x80000000 if read_data else 0)
    handle = create_file(
        str(path),
        desired_access,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00200000 | (0x08000000 if read_data else 0),
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, 0, invalid_handle}:
        raise OSError(ctypes.get_last_error(), "source handle could not be opened")
    numeric_handle = int(handle)
    try:
        final_path = _windows_normalized_final_path(numeric_handle)
        return numeric_handle, final_path
    except BaseException:
        _windows_close_handle(numeric_handle)
        raise


def _windows_close_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(handle)


def _windows_expected_final_path(
    path: Path,
    *,
    expected_file: _FileIdentity,
    expected_size: int,
) -> str:
    import msvcrt

    handle: int | None = None
    descriptor: int | None = None
    try:
        handle, final_path = _windows_open_source_handle(path, read_data=True)
        descriptor = msvcrt.open_osfhandle(
            handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
        handle = None
        _assert_safe_open_file(
            os.fstat(descriptor),
            expected=expected_file,
            expected_size=expected_size,
        )
        return final_path
    except SealedTreeAccessError:
        raise
    except (OSError, ValueError):
        raise SealedTreeAccessError(
            "source_changed", "a source file final identity is unavailable"
        ) from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if handle is not None:
            _windows_close_handle(handle)


def _windows_open_source_descriptor(
    path: Path,
    *,
    expected_final_path: str,
    expected_file: _FileIdentity,
    expected_size: int,
) -> tuple[int, os.stat_result]:
    import msvcrt

    handle: int | None = None
    descriptor: int | None = None
    try:
        handle, final_path = _windows_open_source_handle(path, read_data=True)
        if final_path != expected_final_path:
            raise SealedTreeAccessError(
                "source_changed", "a source file resolved outside its sealed identity"
            )
        descriptor = msvcrt.open_osfhandle(
            handle, os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
        handle = None  # ownership transferred to the CRT descriptor
        opened = os.fstat(descriptor)
        _assert_safe_open_file(
            opened, expected=expected_file, expected_size=expected_size
        )
        return descriptor, opened
    except SealedTreeAccessError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except (OSError, ValueError):
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise SealedTreeAccessError(
            "source_changed", "a trusted Windows source handle could not be opened"
        ) from None
    finally:
        if handle is not None:
            _windows_close_handle(handle)


def _assert_no_named_streams(path: Path) -> None:
    if os.name != "nt":
        return
    try:
        _windows_assert_no_named_streams(path)
    except (SealedSnapshotError, OSError):
        raise SealedTreeAccessError(
            "unsafe_source_path", "trusted source paths must not contain named streams"
        ) from None


def _read_stable_descriptor(
    descriptor: int,
    opened: os.stat_result,
    record: SealedTreeFile,
) -> bytes:
    chunks: list[bytes] = []
    remaining = record.size + 1
    try:
        while remaining:
            chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        finished = os.fstat(descriptor)
    except OSError:
        raise SealedTreeAccessError(
            "source_changed", "a trusted source file could not be read"
        ) from None
    if _file_identity(finished) != _file_identity(opened) or len(data) != opened.st_size:
        raise SealedTreeAccessError(
            "source_changed", "a trusted source file changed while reading"
        )
    return data


def _capture_identity_state(
    tree: Path,
    files: tuple[SealedTreeFile, ...],
) -> tuple[
    tuple[tuple[Path, _DirectoryIdentity], ...],
    dict[str, _DirectoryIdentity],
    dict[str, _FileIdentity],
]:
    base_chain: list[tuple[Path, _DirectoryIdentity]] = []
    for component in _root_chain(tree):
        _, identity = _safe_directory(component)
        base_chain.append((component, identity))

    directories: dict[str, _DirectoryIdentity] = {"": base_chain[-1][1]}
    file_identities: dict[str, _FileIdentity] = {}
    for record in files:
        parts = record.path.split("/")
        for depth in range(1, len(parts)):
            relative = "/".join(parts[:depth])
            if relative in directories:
                continue
            _, identity = _safe_directory(tree.joinpath(*parts[:depth]))
            directories[relative] = identity
        _, identity = _safe_regular(tree.joinpath(*parts))
        file_identities[record.path] = identity
    return tuple(base_chain), directories, file_identities


def _assert_identity_state(
    tree: Path,
    files: tuple[SealedTreeFile, ...],
    base_chain: tuple[tuple[Path, _DirectoryIdentity], ...],
    directories: Mapping[str, _DirectoryIdentity],
    file_identities: Mapping[str, _FileIdentity],
) -> None:
    for component, expected in base_chain:
        _, current = _safe_directory(component)
        if current != expected:
            raise SealedTreeAccessError(
                "source_changed", "a trusted source directory identity changed"
            )
    for relative, expected in directories.items():
        if not relative:
            continue
        _, current = _safe_directory(tree.joinpath(*relative.split("/")))
        if current != expected:
            raise SealedTreeAccessError(
                "source_changed", "a trusted source directory identity changed"
            )
    for record in files:
        _, current = _safe_regular(tree.joinpath(*record.path.split("/")))
        if current != file_identities[record.path]:
            raise SealedTreeAccessError(
                "source_changed", "a trusted source file identity changed"
            )


def _snapshot_fingerprint(snapshot: VerifiedSealedSnapshot) -> tuple[object, ...]:
    return (
        snapshot.task_id,
        snapshot.repo_url,
        snapshot.commit,
        snapshot.root_tree,
        snapshot.content_root,
        snapshot.manifest_sha256,
        snapshot.key_id,
        snapshot.file_count,
        snapshot.total_bytes,
        snapshot.files,
    )


class _TrustedTreeAuthority:
    """Private holder of evaluator-only path and authentication material."""

    __slots__ = (
        "_base_chain",
        "_directories",
        "_expected_fingerprint",
        "_file_identities",
        "_files",
        "_key_material",
        "_key_id",
        "_policy",
        "_snapshot_root",
        "_tree",
        "_tree_descriptor",
        "_windows_final_paths",
    )

    def __init__(
        self,
        *,
        snapshot_root: Path,
        key_material: bytearray,
        key_id: str,
        policy: SnapshotPolicy,
        verified: VerifiedSealedSnapshot,
        files: tuple[SealedTreeFile, ...],
    ) -> None:
        self._snapshot_root = snapshot_root
        self._tree = verified.agent_tree
        self._key_material = key_material
        self._key_id = key_id
        self._policy = policy
        self._expected_fingerprint = _snapshot_fingerprint(verified)
        self._files = files
        (
            self._base_chain,
            self._directories,
            self._file_identities,
        ) = _capture_identity_state(self._tree, files)
        self._tree_descriptor: int | None = None
        self._windows_final_paths: dict[str, str] = {}
        if os.name == "nt":
            for record in files:
                path = self._tree.joinpath(*record.path.split("/"))
                _assert_no_named_streams(path)
                self._windows_final_paths[record.path] = (
                    _windows_expected_final_path(
                        path,
                        expected_file=self._file_identities[record.path],
                        expected_size=record.size,
                    )
                )
        else:
            self._tree_descriptor = _posix_open_tree_descriptor(
                self._tree, expected=self._directories[""]
            )

    def close(self) -> None:
        if self._tree_descriptor is not None:
            try:
                os.close(self._tree_descriptor)
            except OSError:
                pass
            self._tree_descriptor = None
        for index in range(len(self._key_material)):
            self._key_material[index] = 0
        self._snapshot_root = Path()
        self._tree = Path()
        self._base_chain = ()
        self._directories = {}
        self._file_identities = {}
        self._windows_final_paths = {}

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            # Best-effort cleanup only; trusted callers must still finalize.
            pass

    def assert_identity_state(self) -> None:
        _assert_identity_state(
            self._tree,
            self._files,
            self._base_chain,
            self._directories,
            self._file_identities,
        )
        if os.name == "nt":
            for record in self._files:
                path = self._tree.joinpath(*record.path.split("/"))
                _assert_no_named_streams(path)
                current = _windows_expected_final_path(
                    path,
                    expected_file=self._file_identities[record.path],
                    expected_size=record.size,
                )
                if current != self._windows_final_paths[record.path]:
                    raise SealedTreeAccessError(
                        "source_changed", "a source file final identity changed"
                    )
        else:
            if self._tree_descriptor is None:
                raise SealedTreeAccessError(
                    "source_changed", "the authenticated source root is not pinned"
                )
            try:
                opened_tree = os.fstat(self._tree_descriptor)
            except OSError:
                raise SealedTreeAccessError(
                    "source_changed", "the authenticated source root is unavailable"
                ) from None
            _assert_safe_open_directory(
                opened_tree, expected=self._directories[""]
            )

    def reverify(self, task: DiscoveryTaskInputV1) -> None:
        try:
            verified = verify_sealed_snapshot(
                self._snapshot_root,
                expected_task_id=task.task_id,
                expected_repo_url=task.repo_url,
                expected_commit=task.commit,
                attestation_key=self._key_material,
                expected_key_id=self._key_id,
                policy=self._policy,
            )
        except (SealedSnapshotError, OSError, ValueError, TypeError):
            raise SealedTreeAccessError(
                "snapshot_verification_failed",
                "the authenticated source snapshot did not verify",
            ) from None
        if _snapshot_fingerprint(verified) != self._expected_fingerprint:
            raise SealedTreeAccessError(
                "invalid_binding", "the authenticated source binding changed"
            )
        self.assert_identity_state()

    def read(self, record: SealedTreeFile) -> bytes:
        parts = record.path.split("/")
        for component, expected in self._base_chain:
            _, current = _safe_directory(component)
            if current != expected:
                raise SealedTreeAccessError(
                    "source_changed", "a trusted source directory identity changed"
                )
        for depth in range(1, len(parts)):
            relative = "/".join(parts[:depth])
            _, current = _safe_directory(self._tree.joinpath(*parts[:depth]))
            if current != self._directories[relative]:
                raise SealedTreeAccessError(
                    "source_changed", "a trusted source directory identity changed"
                )

        path = self._tree.joinpath(*parts)
        _, before_identity = _safe_regular(path)
        if before_identity != self._file_identities[record.path]:
            raise SealedTreeAccessError(
                "source_changed", "a trusted source file identity changed"
            )
        _assert_no_named_streams(path)

        descriptor: int | None = None
        try:
            if os.name == "nt":
                descriptor, opened = _windows_open_source_descriptor(
                    path,
                    expected_final_path=self._windows_final_paths[record.path],
                    expected_file=before_identity,
                    expected_size=record.size,
                )
            else:
                if self._tree_descriptor is None:
                    raise SealedTreeAccessError(
                        "source_changed", "the authenticated source root is not pinned"
                    )
                descriptor, opened = _posix_open_relative_file(
                    self._tree_descriptor,
                    tuple(parts),
                    directories=self._directories,
                    expected_file=before_identity,
                    expected_size=record.size,
                )
            data = _read_stable_descriptor(descriptor, opened, record)
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

        _, after_identity = _safe_regular(path)
        if after_identity != before_identity:
            raise SealedTreeAccessError(
                "source_changed", "a trusted source file identity changed"
            )
        _assert_no_named_streams(path)
        for component, expected in self._base_chain:
            _, current = _safe_directory(component)
            if current != expected:
                raise SealedTreeAccessError(
                    "source_changed", "a trusted source directory identity changed"
                )
        for depth in range(1, len(parts)):
            relative = "/".join(parts[:depth])
            _, current = _safe_directory(self._tree.joinpath(*parts[:depth]))
            if current != self._directories[relative]:
                raise SealedTreeAccessError(
                    "source_changed", "a trusted source directory identity changed"
                )

        git_header = f"blob {len(data)}\0".encode("ascii")
        git_oid = hashlib.sha1(
            git_header + data, usedforsecurity=False
        ).hexdigest()
        if (
            len(data) != record.size
            or hashlib.sha256(data).hexdigest() != record.sha256
            or git_oid != record.blob_oid
        ):
            raise SealedTreeAccessError(
                "source_changed", "trusted source bytes no longer match the manifest"
            )
        return data


def _task_authority_fingerprint(task: DiscoveryTaskInputV1) -> tuple[str, ...]:
    return (
        task.task_id,
        task.repo_url,
        task.commit,
        task.instruction_id,
        task.snapshot_manifest_sha256,
        task.snapshot_content_root,
        task.snapshot_id,
    )


def _canonical_exact_task(task: object) -> DiscoveryTaskInputV1:
    if type(task) is not DiscoveryTaskInputV1:
        raise SealedTreeAccessError(
            "invalid_argument", "task must be an exact DiscoveryTaskInputV1"
        )
    try:
        values = (
            task.task_id,
            task.repo_url,
            task.commit,
            task.instruction_id,
            task.snapshot_manifest_sha256,
            task.snapshot_content_root,
            task.snapshot_id,
            task.contract_version,
        )
    except (AttributeError, TypeError):
        raise SealedTreeAccessError(
            "invalid_binding", "task fields are incomplete"
        ) from None
    if any(
        type(value) is not expected
        for value, expected in zip(
            values,
            (str, str, str, str, str, str, str, int),
            strict=True,
        )
    ):
        raise SealedTreeAccessError(
            "invalid_binding", "task fields must have exact scalar types"
        )
    try:
        canonical = DiscoveryTaskInputV1(
            task_id=values[0],
            repo_url=values[1],
            commit=values[2],
            instruction_id=values[3],
            snapshot_manifest_sha256=values[4],
            snapshot_content_root=values[5],
            contract_version=values[7],
        )
    except (AttributeError, TypeError, ValueError):
        raise SealedTreeAccessError(
            "invalid_binding", "task did not pass strict reconstruction"
        ) from None
    if canonical.snapshot_id != values[6]:
        raise SealedTreeAccessError(
            "invalid_binding", "task snapshot identity is invalid"
        )
    return canonical


def _manifest_directories(files: tuple[SealedTreeFile, ...]) -> frozenset[str]:
    directories: set[str] = set()
    for record in files:
        parts = record.path.split("/")
        for depth in range(1, len(parts)):
            directories.add("/".join(parts[:depth]))
    return frozenset(directories)


class _MountedTreeAuthority(_TrustedTreeAuthority):
    """Key-free authority over one evaluator-verified read-only mount.

    The handoff digest is an internal closure value, not an authentication
    primitive.  Authenticity is established by the trusted evaluator before
    launch; this authority independently checks the exact mounted bytes at
    bind and finalize time.
    """

    __slots__ = ("_handoff_sha256", "_task_binding")

    def __init__(
        self,
        *,
        tree_root: Path,
        handoff: WorkerHandoffV2,
        files: tuple[SealedTreeFile, ...],
    ) -> None:
        self._snapshot_root = Path()
        self._tree = tree_root
        self._key_material = bytearray()
        self._key_id = ""
        self._policy = handoff.policy
        self._expected_fingerprint = ()
        self._files = files
        self._base_chain = ()
        self._directories = {}
        self._file_identities = {}
        self._tree_descriptor = None
        self._windows_final_paths = {}
        self._handoff_sha256 = handoff.handoff_sha256
        self._task_binding = _task_authority_fingerprint(handoff.task)
        try:
            (
                self._base_chain,
                self._directories,
                self._file_identities,
            ) = _capture_identity_state(self._tree, files)
            if os.name == "nt":
                for record in files:
                    path = self._tree.joinpath(*record.path.split("/"))
                    _assert_no_named_streams(path)
                    self._windows_final_paths[record.path] = (
                        _windows_expected_final_path(
                            path,
                            expected_file=self._file_identities[record.path],
                            expected_size=record.size,
                        )
                    )
            else:
                self._tree_descriptor = _posix_open_tree_descriptor(
                    self._tree, expected=self._directories[""]
                )
            self.reverify(handoff.task)
        except BaseException:
            _best_effort_close(self)
            raise

    def close(self) -> None:
        super().close()
        self._handoff_sha256 = ""
        self._task_binding = ()

    def _assert_mounted_layout(self) -> None:
        expected_files = frozenset(record.path for record in self._files)
        expected_directories = _manifest_directories(self._files)
        try:
            files, directories = _scan_tree(
                self._tree,
                self._policy,
                expected_files=expected_files,
                expected_directories=expected_directories,
            )
        except SealedSnapshotError as error:
            code = (
                "unsafe_source_path"
                if error.code
                in {"unsafe_snapshot_path", "snapshot_path_collision"}
                else "source_changed"
            )
            raise SealedTreeAccessError(
                code, "the mounted source tree does not match its verified handoff"
            ) from None
        if set(files) != set(expected_files) or set(directories) != set(
            expected_directories
        ):
            raise SealedTreeAccessError(
                "source_changed", "the mounted source layout changed"
            )
        for path, identity in files.items():
            if identity != self._file_identities[path]:
                raise SealedTreeAccessError(
                    "source_changed", "a mounted source file identity changed"
                )
        for path, identity in directories.items():
            if (identity[0], identity[1]) != self._directories[path]:
                raise SealedTreeAccessError(
                    "source_changed", "a mounted source directory identity changed"
                )
        self.assert_identity_state()

    def reverify(self, task: DiscoveryTaskInputV1) -> None:
        if (
            type(task) is not DiscoveryTaskInputV1
            or _task_authority_fingerprint(task) != self._task_binding
            or not self._handoff_sha256
        ):
            raise SealedTreeAccessError(
                "invalid_binding", "mounted source task binding is invalid"
            )
        self._assert_mounted_layout()
        for record in self._files:
            self.read(record)
        self._assert_mounted_layout()


_CONSTRUCTION_TOKEN: Final[object] = object()


class BoundSealedTree:
    """Path-hidden, read-only capability bound to one D0 discovery task."""

    __slots__ = (
        "__authority",
        "__by_path",
        "__bytes_read",
        "__claim_token",
        "__files",
        "__finalized",
        "__inventory_calls",
        "__limits",
        "__lock",
        "__reads",
        "__task",
        "__verification_succeeded",
    )

    def __init__(
        self,
        token: object,
        *,
        task: DiscoveryTaskInputV1,
        authority: _TreeAuthority,
        files: tuple[SealedTreeFile, ...],
        limits: SealedTreeAccessLimits,
    ) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise TypeError("BoundSealedTree values must be created by the trusted binder")
        self.__task = task
        self.__authority: _TreeAuthority | None = authority
        self.__files = files
        self.__by_path = {item.path: item for item in files}
        self.__limits = limits
        self.__claim_token: object | None = None
        self.__inventory_calls = 0
        self.__bytes_read = 0
        self.__reads: list[SourceReadUsage] = []
        self.__finalized = False
        self.__verification_succeeded = False
        self.__lock = threading.RLock()

    def __repr__(self) -> str:
        return (
            "BoundSealedTree("
            f"task_id={self.task_id!r}, snapshot_id={self.snapshot_id!r}, "
            f"file_count={self.file_count}, finalized={self.__finalized})"
        )

    def __reduce__(self) -> object:
        raise TypeError("BoundSealedTree capabilities cannot be serialized")

    @property
    def task_id(self) -> str:
        return self.__task.task_id

    @property
    def snapshot_id(self) -> str:
        return self.__task.snapshot_id

    @property
    def repo_url(self) -> str:
        return self.__task.repo_url

    @property
    def commit(self) -> str:
        return self.__task.commit

    @property
    def manifest_sha256(self) -> str:
        return self.__task.snapshot_manifest_sha256

    @property
    def content_root(self) -> str:
        return self.__task.snapshot_content_root

    @property
    def file_count(self) -> int:
        return len(self.__files)

    @property
    def total_bytes(self) -> int:
        return sum(item.size for item in self.__files)

    def _require_active(
        self, claim_token: object | None = None
    ) -> _TreeAuthority:
        if self.__finalized or self.__authority is None:
            raise SealedTreeAccessError(
                "access_finalized", "the sealed source capability is finalized"
            )
        if self.__claim_token is not None and claim_token is not self.__claim_token:
            raise SealedTreeAccessError(
                "access_claimed", "the sealed source capability has another owner"
            )
        return self.__authority

    def _claim_for_discovery(self, claim_token: object) -> None:
        """Atomically transfer all mutable access to one discovery toolbox."""

        if claim_token is None:
            raise SealedTreeAccessError(
                "invalid_binding", "a discovery owner token is required"
            )
        with self.__lock:
            self._require_active()
            if (
                self.__inventory_calls != 0
                or self.__bytes_read != 0
                or self.__reads
            ):
                raise SealedTreeAccessError(
                    "invalid_binding",
                    "a discovery owner requires a fresh sealed source capability",
                )
            self.__claim_token = claim_token

    def _invalidate(self, authority: _TreeAuthority | None = None) -> None:
        authority = self.__authority if authority is None else authority
        self.__authority = None
        self.__finalized = True
        self.__verification_succeeded = False
        # State is already one-way closed.  Cleanup must preserve the
        # triggering interruption or verification failure.
        _best_effort_close(authority)

    def inventory(
        self, *, _claim_token: object | None = None
    ) -> tuple[SealedTreeFile, ...]:
        """Return the canonical verified-manifest inventory, never host paths."""

        with self.__lock:
            self._require_active(_claim_token)
            if self.__inventory_calls >= self.__limits.max_inventory_calls:
                raise SealedTreeAccessError(
                    "source_limit_exceeded", "source inventory call budget is exhausted"
                )
            self.__inventory_calls += 1
            return self.__files

    def read_bytes(
        self,
        path: str,
        *,
        maximum_bytes: int,
        _claim_token: object | None = None,
    ) -> bytes:
        """Read one exact manifest member within the caller and run budgets."""

        with self.__lock:
            authority = self._require_active(_claim_token)
            if not isinstance(path, str):
                raise SealedTreeAccessError(
                    "invalid_argument", "source path must be a string"
                )
            if type(maximum_bytes) is not int or not (
                0 <= maximum_bytes <= self.__limits.max_bytes_per_read
            ):
                raise SealedTreeAccessError(
                    "invalid_argument", "maximum_bytes is outside the read policy"
                )
            record = self.__by_path.get(path)
            if record is None:
                raise SealedTreeAccessError(
                    "source_not_found", "source path is not in the verified manifest"
                )
            if record.size > maximum_bytes:
                raise SealedTreeAccessError(
                    "source_limit_exceeded", "source file exceeds the requested byte limit"
                )
            if len(self.__reads) >= self.__limits.max_read_calls:
                raise SealedTreeAccessError(
                    "source_limit_exceeded", "source read call budget is exhausted"
                )
            if (
                self.__bytes_read + record.size
                > self.__limits.max_total_bytes_read
            ):
                raise SealedTreeAccessError(
                    "source_limit_exceeded", "aggregate source byte budget is exhausted"
                )
            previous_bytes = self.__bytes_read
            previous_reads = self.__reads
            try:
                data = authority.read(record)
                receipt = SourceReadUsage(
                    sequence=len(self.__reads) + 1,
                    path=record.path,
                    bytes_read=len(data),
                    sha256=record.sha256,
                    blob_oid=record.blob_oid,
                )
                self.__reads = [*self.__reads, receipt]
                self.__bytes_read = previous_bytes + len(data)
                return data
            except BaseException:
                self.__reads = previous_reads
                self.__bytes_read = previous_bytes
                self._invalidate(authority)
                raise

    def usage_snapshot(self) -> SourceUsageLedger:
        """Return a deeply immutable point-in-time usage ledger."""

        with self.__lock:
            return SourceUsageLedger(
                task_id=self.task_id,
                snapshot_id=self.snapshot_id,
                inventory_calls=self.__inventory_calls,
                read_calls=len(self.__reads),
                bytes_read=self.__bytes_read,
                reads=tuple(self.__reads),
                finalized=self.__finalized,
                verification_succeeded=self.__verification_succeeded,
            )

    def finalize(
        self, *, _claim_token: object | None = None
    ) -> SourceUsageLedger:
        """Reverify the authenticated tree, close the capability, and seal usage."""

        with self.__lock:
            authority = self._require_active(_claim_token)
            try:
                authority.reverify(self.__task)
                authority.close()
                self.__authority = None
                self.__finalized = True
                self.__verification_succeeded = True
                return self.usage_snapshot()
            except BaseException:
                self._invalidate(authority)
                raise

    def _abort(self, *, _claim_token: object | None = None) -> SourceUsageLedger:
        """Irreversibly close without claiming successful re-verification."""

        with self.__lock:
            if self.__finalized:
                return self.usage_snapshot()
            self._require_active(_claim_token)
            self._invalidate()
            return self.usage_snapshot()


def bind_sealed_tree(
    task: DiscoveryTaskInputV1,
    snapshot_root: str | os.PathLike[str],
    *,
    attestation_key: bytes | bytearray | memoryview,
    expected_key_id: str,
    policy: SnapshotPolicy = DEFAULT_SNAPSHOT_POLICY,
    limits: SealedTreeAccessLimits = DEFAULT_SEALED_TREE_ACCESS_LIMITS,
) -> BoundSealedTree:
    """Verify, identity-bind, and hide one sealed snapshot behind a capability."""

    canonical_task = _canonical_exact_task(task)
    canonical_policy = _canonical_snapshot_policy(policy)
    canonical_limits = _canonical_access_limits(limits)
    if not isinstance(attestation_key, (bytes, bytearray, memoryview)):
        raise SealedTreeAccessError(
            "invalid_argument", "attestation material must be bytes-like"
        )
    try:
        key_size = (
            attestation_key.nbytes
            if isinstance(attestation_key, memoryview)
            else len(attestation_key)
        )
    except (TypeError, ValueError):
        raise SealedTreeAccessError(
            "invalid_argument", "attestation material must be readable bytes"
        ) from None
    if not _MIN_ATTESTATION_KEY_BYTES <= key_size <= _MAX_ATTESTATION_KEY_BYTES:
        raise SealedTreeAccessError(
            "invalid_argument", "attestation material is outside its byte limit"
        )
    try:
        key_material = bytearray(attestation_key)
    except (TypeError, ValueError, BufferError):
        raise SealedTreeAccessError(
            "invalid_argument", "attestation material must be contiguous bytes"
        ) from None
    try:
        root = Path(os.path.abspath(os.fspath(snapshot_root)))
        verified = verify_sealed_snapshot(
            root,
            expected_task_id=canonical_task.task_id,
            expected_repo_url=canonical_task.repo_url,
            expected_commit=canonical_task.commit,
            attestation_key=key_material,
            expected_key_id=expected_key_id,
            policy=canonical_policy,
        )
    except (SealedSnapshotError, OSError, ValueError, TypeError):
        for index in range(len(key_material)):
            key_material[index] = 0
        raise SealedTreeAccessError(
            "snapshot_verification_failed",
            "the authenticated source snapshot did not verify",
        ) from None

    if (
        verified.task_id != canonical_task.task_id
        or verified.repo_url != canonical_task.repo_url
        or verified.commit != canonical_task.commit
        or verified.manifest_sha256 != canonical_task.snapshot_manifest_sha256
        or verified.content_root != canonical_task.snapshot_content_root
    ):
        for index in range(len(key_material)):
            key_material[index] = 0
        raise SealedTreeAccessError(
            "invalid_binding", "snapshot metadata does not match the discovery task"
        )

    if any(type(item) is SealedSnapshotGitlink for item in verified.files):
        raise SealedTreeAccessError(
            "invalid_binding",
            "metadata-only gitlinks are sealed but not accessible to workers",
        )
    files = tuple(SealedTreeFile._from_verified(item) for item in verified.files)
    authority: _TrustedTreeAuthority | None = None
    try:
        authority = _TrustedTreeAuthority(
            snapshot_root=root,
            key_material=key_material,
            key_id=expected_key_id,
            policy=canonical_policy,
            verified=verified,
            files=files,
        )
        # Bracket identity capture with another complete authenticated verify.
        authority.reverify(canonical_task)
    except SealedTreeAccessError:
        if authority is None:
            for index in range(len(key_material)):
                key_material[index] = 0
        else:
            _best_effort_close(authority)
        raise
    except BaseException:
        if authority is None:
            for index in range(len(key_material)):
                key_material[index] = 0
        else:
            _best_effort_close(authority)
        raise

    try:
        return BoundSealedTree(
            _CONSTRUCTION_TOKEN,
            task=canonical_task,
            authority=authority,
            files=files,
            limits=canonical_limits,
        )
    except BaseException:
        _best_effort_close(authority)
        raise


def bind_worker_tree(
    task: DiscoveryTaskInputV1,
    tree_root: str | os.PathLike[str],
    handoff_payload: bytes,
    *,
    expected_handoff_sha256: str,
    expected_handoff_wire_sha256: str,
    limits: SealedTreeAccessLimits = DEFAULT_SEALED_TREE_ACCESS_LIMITS,
) -> BoundSealedTree:
    """Bind an evaluator-verified, read-only worker mount without secret state.

    The caller is responsible for delivering ``handoff_payload`` and ``tree_root``
    through an operating-system-enforced read-only boundary.  The handoff
    semantic and wire digests close that delivery but are not an
    authentication substitute.
    """

    canonical_task = _canonical_exact_task(task)
    canonical_limits = _canonical_access_limits(limits)
    if type(handoff_payload) is not bytes:
        raise SealedTreeAccessError(
            "invalid_argument", "worker tree inputs have invalid types"
        )
    try:
        canonical_handoff = WorkerHandoffV2.from_bytes(
            handoff_payload,
            expected_sha256=expected_handoff_sha256,
            expected_wire_sha256=expected_handoff_wire_sha256,
        )
    except (AttributeError, TypeError, ValueError, WorkerHandoffError):
        raise SealedTreeAccessError(
            "invalid_binding", "worker handoff did not pass strict verification"
        ) from None
    if _task_authority_fingerprint(canonical_task) != _task_authority_fingerprint(
        canonical_handoff.task
    ):
        raise SealedTreeAccessError(
            "invalid_binding", "worker handoff does not match the requested task"
        )
    try:
        root = Path(os.path.abspath(os.fspath(tree_root)))
    except (OSError, TypeError, ValueError):
        raise SealedTreeAccessError(
            "invalid_argument", "worker tree root is invalid"
        ) from None
    files = tuple(
        SealedTreeFile._from_verified(item) for item in canonical_handoff.files
    )
    authority: _MountedTreeAuthority | None = None
    try:
        authority = _MountedTreeAuthority(
            tree_root=root,
            handoff=canonical_handoff,
            files=files,
        )
        return BoundSealedTree(
            _CONSTRUCTION_TOKEN,
            task=canonical_handoff.task,
            authority=authority,
            files=files,
            limits=canonical_limits,
        )
    except SealedTreeAccessError:
        _best_effort_close(authority)
        raise
    except (OSError, TypeError, ValueError):
        _best_effort_close(authority)
        raise SealedTreeAccessError(
            "source_changed", "worker tree mount did not pass verification"
        ) from None
    except BaseException:
        _best_effort_close(authority)
        raise


__all__ = [
    "BoundSealedTree",
    "DEFAULT_SEALED_TREE_ACCESS_LIMITS",
    "SEALED_TREE_ACCESS_VERSION",
    "SealedTreeAccessError",
    "SealedTreeAccessLimits",
    "SealedTreeFile",
    "SourceReadUsage",
    "SourceUsageLedger",
    "bind_sealed_tree",
    "bind_worker_tree",
]
