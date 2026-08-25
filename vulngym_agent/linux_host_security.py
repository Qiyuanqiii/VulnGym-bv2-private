"""Native-Linux namespace bindings used by the formal evaluator boundary."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import posixpath
import re
import stat
import sys
from typing import Final


_MOUNTINFO_PATH: Final[Path] = Path("/proc/self/mountinfo")
_MOUNTINFO_MAX_BYTES: Final[int] = 4 * 1024 * 1024
_DEVICE_RE: Final[re.Pattern[str]] = re.compile(r"[0-9]+:[0-9]+\Z")
_MOUNT_ESCAPE_RE: Final[re.Pattern[str]] = re.compile(r"\\([0-7]{3})")


class LinuxHostSecurityError(RuntimeError):
    """Path-free failure while binding a native-Linux host namespace."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "linux_host_unsafe"
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class LinuxMountEntryV1:
    mount_id: int
    device: str
    root: str
    mount_point: str


@dataclass(frozen=True, slots=True)
class LinuxMountTableV1:
    payload: bytes
    entries: tuple[LinuxMountEntryV1, ...]


_DirectoryIdentityV1 = tuple[str, int, int, int, int, int]
_SocketIdentityV1 = tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class LinuxDirectoryGuardV1:
    path: Path
    chain: tuple[_DirectoryIdentityV1, ...]


@dataclass(frozen=True, slots=True)
class DockerSocketGuardV1:
    path: Path
    directory_guard: LinuxDirectoryGuardV1
    directory_members: tuple[str, ...]
    socket_identity: _SocketIdentityV1


def _require_native_linux() -> None:
    if os.name != "posix" or sys.platform != "linux":
        raise LinuxHostSecurityError(
            "native_linux_required", "native Linux host evidence is required"
        )


def _read_mountinfo_v1() -> bytes:
    _require_native_linux()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(_MOUNTINFO_PATH, flags)
    except OSError as error:
        raise LinuxHostSecurityError(
            "mountinfo_unavailable", "Linux mount evidence is unavailable"
        ) from error
    try:
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, _MOUNTINFO_MAX_BYTES + 1 - consumed),
            )
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > _MOUNTINFO_MAX_BYTES:
                raise LinuxHostSecurityError(
                    "mountinfo_invalid", "Linux mount evidence exceeds its limit"
                )
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if not payload or not payload.endswith(b"\n"):
        raise LinuxHostSecurityError(
            "mountinfo_invalid", "Linux mount evidence is incomplete"
        )
    return payload


def _decode_mount_field_v1(value: str) -> str:
    return _MOUNT_ESCAPE_RE.sub(
        lambda match: chr(int(match.group(1), 8)), value
    )


def _has_control_characters_v1(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _canonical_posix_path_v1(value: object) -> str:
    try:
        raw = os.fspath(value)
    except (OSError, TypeError, ValueError):
        raise LinuxHostSecurityError(
            "path_invalid", "Linux host path is invalid"
        ) from None
    if (
        type(raw) is not str
        or not raw.startswith("/")
        or _has_control_characters_v1(raw)
        or posixpath.normpath(raw) != raw
    ):
        raise LinuxHostSecurityError(
            "path_invalid", "Linux host path is not canonical"
        )
    return raw


def parse_linux_mountinfo_v1(payload: bytes) -> LinuxMountTableV1:
    if type(payload) is not bytes or not payload or not payload.endswith(b"\n"):
        raise LinuxHostSecurityError(
            "mountinfo_invalid", "Linux mount evidence is incomplete"
        )
    try:
        lines = payload.decode("utf-8", errors="strict").splitlines()
    except UnicodeError:
        raise LinuxHostSecurityError(
            "mountinfo_invalid", "Linux mount evidence is not UTF-8"
        ) from None
    entries: list[LinuxMountEntryV1] = []
    for line in lines:
        if " - " not in line:
            raise LinuxHostSecurityError(
                "mountinfo_invalid", "Linux mount evidence is malformed"
            )
        left, right = line.split(" - ", 1)
        left_fields = left.split(" ")
        right_fields = right.split(" ")
        if len(left_fields) < 6 or len(right_fields) < 3:
            raise LinuxHostSecurityError(
                "mountinfo_invalid", "Linux mount evidence is malformed"
            )
        try:
            mount_id = int(left_fields[0], 10)
        except ValueError:
            raise LinuxHostSecurityError(
                "mountinfo_invalid", "Linux mount evidence is malformed"
            ) from None
        device = left_fields[2]
        root = _decode_mount_field_v1(left_fields[3])
        mount_point = _decode_mount_field_v1(left_fields[4])
        if (
            mount_id <= 0
            or _DEVICE_RE.fullmatch(device) is None
            or _has_control_characters_v1(root)
            or _has_control_characters_v1(mount_point)
            or not root.startswith("/")
            or posixpath.normpath(root) != root
            or not mount_point.startswith("/")
            or posixpath.normpath(mount_point) != mount_point
        ):
            raise LinuxHostSecurityError(
                "mountinfo_invalid", "Linux mount evidence is malformed"
            )
        entries.append(
            LinuxMountEntryV1(
                mount_id=mount_id,
                device=device,
                root=root,
                mount_point=mount_point,
            )
        )
    if not entries:
        raise LinuxHostSecurityError(
            "mountinfo_invalid", "Linux mount evidence has no entries"
        )
    return LinuxMountTableV1(payload=payload, entries=tuple(entries))


def capture_linux_mount_table_v1() -> LinuxMountTableV1:
    return parse_linux_mountinfo_v1(_read_mountinfo_v1())


def assert_linux_mount_table_stable_v1(table: LinuxMountTableV1) -> None:
    if type(table) is not LinuxMountTableV1:
        raise LinuxHostSecurityError(
            "mountinfo_invalid", "Linux mount binding has an invalid type"
        )
    if _read_mountinfo_v1() != table.payload:
        raise LinuxHostSecurityError(
            "mountinfo_changed", "Linux mount namespace changed during validation"
        )


def linux_physical_path_v1(
    table: LinuxMountTableV1, path: str | Path
) -> tuple[str, str]:
    if type(table) is not LinuxMountTableV1:
        raise LinuxHostSecurityError(
            "mountinfo_invalid", "Linux mount binding has an invalid type"
        )
    target = _canonical_posix_path_v1(path)
    matches: list[LinuxMountEntryV1] = []
    for entry in table.entries:
        try:
            contains = (
                posixpath.commonpath((target, entry.mount_point))
                == entry.mount_point
            )
        except ValueError:
            contains = False
        if contains:
            matches.append(entry)
    if not matches:
        raise LinuxHostSecurityError(
            "mountinfo_invalid", "Linux path has no covering mount"
        )
    longest = max((item.mount_point.count("/"), len(item.mount_point)) for item in matches)
    covering = tuple(
        item
        for item in matches
        if (item.mount_point.count("/"), len(item.mount_point)) == longest
    )
    mappings = {(item.device, item.root, item.mount_point) for item in covering}
    if len(mappings) != 1:
        raise LinuxHostSecurityError(
            "mountinfo_invalid", "Linux path has an ambiguous covering mount"
        )
    mount = max(covering, key=lambda item: item.mount_id)
    relative = posixpath.relpath(target, mount.mount_point)
    physical = (
        mount.root
        if relative == "."
        else posixpath.normpath(posixpath.join(mount.root, relative))
    )
    if not physical.startswith("/"):
        raise LinuxHostSecurityError(
            "mountinfo_invalid", "Linux physical path did not normalize"
        )
    return mount.device, physical


def linux_paths_overlap_v1(
    table: LinuxMountTableV1, left: str | Path, right: str | Path
) -> bool:
    left_device, left_physical = linux_physical_path_v1(table, left)
    right_device, right_physical = linux_physical_path_v1(table, right)
    if left_device != right_device:
        return False
    try:
        common = posixpath.commonpath((left_physical, right_physical))
    except ValueError:
        return False
    return common in {left_physical, right_physical}


def _directory_chain_v1(path: Path) -> tuple[tuple[Path, os.stat_result], ...]:
    raw = _canonical_posix_path_v1(path)
    absolute = Path(raw)
    result: list[tuple[Path, os.stat_result]] = []
    try:
        for component in reversed((absolute, *absolute.parents)):
            value = os.lstat(component)
            if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
                raise OSError("unsafe directory chain")
            result.append((component, value))
        if absolute.resolve(strict=True) != absolute:
            raise OSError("directory chain contains a symbolic link")
    except (OSError, RuntimeError) as error:
        raise LinuxHostSecurityError(
            "directory_chain_unsafe", "Linux directory chain is unsafe"
        ) from error
    return tuple(result)


def _directory_identity_v1(
    path: Path, value: os.stat_result
) -> _DirectoryIdentityV1:
    return (
        os.fspath(path),
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_uid),
        int(value.st_gid),
        stat.S_IMODE(value.st_mode),
    )


def _directory_members_v1(path: Path) -> tuple[str, ...]:
    try:
        with os.scandir(path) as entries:
            members = tuple(sorted(entry.name for entry in entries))
    except OSError as error:
        raise LinuxHostSecurityError(
            "docker_socket_unsafe", "Docker socket directory is unsafe"
        ) from error
    if any(
        type(member) is not str
        or not member
        or member in {".", ".."}
        or "/" in member
        or "\x00" in member
        for member in members
    ):
        raise LinuxHostSecurityError(
            "docker_socket_unsafe", "Docker socket directory is unsafe"
        )
    return members


def bind_root_owned_directory_chain_v1(path: str | Path) -> LinuxDirectoryGuardV1:
    _require_native_linux()
    absolute = Path(_canonical_posix_path_v1(path))
    chain = _directory_chain_v1(absolute)
    if any(
        value.st_uid != 0 or stat.S_IMODE(value.st_mode) & 0o022
        for _component, value in chain
    ):
        raise LinuxHostSecurityError(
            "directory_permissions_unsafe",
            "root-owned Linux directory chain has unsafe permissions",
        )
    return LinuxDirectoryGuardV1(
        path=absolute,
        chain=tuple(_directory_identity_v1(component, value) for component, value in chain),
    )


def assert_root_owned_directory_guard_stable_v1(
    guard: LinuxDirectoryGuardV1,
) -> None:
    if type(guard) is not LinuxDirectoryGuardV1:
        raise LinuxHostSecurityError(
            "directory_chain_unsafe", "Linux directory guard has an invalid type"
        )
    if bind_root_owned_directory_chain_v1(guard.path) != guard:
        raise LinuxHostSecurityError(
            "directory_chain_changed", "Linux directory chain changed"
        )


def bind_docker_socket_guard_v1(path: str | Path) -> DockerSocketGuardV1:
    _require_native_linux()
    absolute = Path(_canonical_posix_path_v1(path))
    chain = _directory_chain_v1(absolute.parent)
    parent_component, parent_state = chain[-1]
    allowed_socket_owners = {0, os.geteuid()}
    if (
        stat.S_IMODE(parent_state.st_mode) != 0o700
        or parent_state.st_uid not in allowed_socket_owners
        or any(
            value.st_uid != 0 or stat.S_IMODE(value.st_mode) & 0o022
            for _component, value in chain[:-1]
        )
    ):
        raise LinuxHostSecurityError(
            "docker_socket_unsafe",
            "Docker socket directory chain has unsafe ownership or permissions",
        )
    expected_members = (absolute.name,)
    if _directory_members_v1(absolute.parent) != expected_members:
        raise LinuxHostSecurityError(
            "docker_socket_unsafe",
            "Docker socket directory is not dedicated to the bound socket",
        )
    try:
        socket_state = os.lstat(absolute)
        if absolute.resolve(strict=True) != absolute:
            raise OSError("socket path contains a symbolic link")
    except (OSError, RuntimeError) as error:
        raise LinuxHostSecurityError(
            "docker_socket_unavailable", "Docker socket is unavailable"
        ) from error
    socket_mode = stat.S_IMODE(socket_state.st_mode)
    if (
        not stat.S_ISSOCK(socket_state.st_mode)
        or stat.S_ISLNK(socket_state.st_mode)
        or socket_mode != 0o600
        or socket_state.st_uid != parent_state.st_uid
        or socket_state.st_gid != parent_state.st_gid
    ):
        raise LinuxHostSecurityError(
            "docker_socket_unsafe", "Docker socket ownership or permissions are unsafe"
        )
    rebound_chain = _directory_chain_v1(absolute.parent)
    if (
        tuple(
            _directory_identity_v1(component, value)
            for component, value in rebound_chain
        )
        != tuple(
            _directory_identity_v1(component, value) for component, value in chain
        )
        or _directory_members_v1(absolute.parent) != expected_members
    ):
        raise LinuxHostSecurityError(
            "docker_socket_changed", "Docker socket binding changed during validation"
        )
    directory_guard = LinuxDirectoryGuardV1(
        path=parent_component,
        chain=tuple(_directory_identity_v1(component, value) for component, value in chain),
    )
    return DockerSocketGuardV1(
        path=absolute,
        directory_guard=directory_guard,
        directory_members=expected_members,
        socket_identity=(
            int(socket_state.st_dev),
            int(socket_state.st_ino),
            int(socket_state.st_uid),
            int(socket_state.st_gid),
            socket_mode,
            int(getattr(socket_state, "st_mtime_ns", 0)),
            int(getattr(socket_state, "st_ctime_ns", 0)),
        ),
    )


def assert_docker_socket_guard_stable_v1(guard: DockerSocketGuardV1) -> None:
    if type(guard) is not DockerSocketGuardV1:
        raise LinuxHostSecurityError(
            "docker_socket_unsafe", "Docker socket guard has an invalid type"
        )
    if bind_docker_socket_guard_v1(guard.path) != guard:
        raise LinuxHostSecurityError(
            "docker_socket_changed", "Docker socket binding changed"
        )


__all__ = [
    "DockerSocketGuardV1",
    "LinuxDirectoryGuardV1",
    "LinuxHostSecurityError",
    "LinuxMountEntryV1",
    "LinuxMountTableV1",
    "assert_docker_socket_guard_stable_v1",
    "assert_linux_mount_table_stable_v1",
    "assert_root_owned_directory_guard_stable_v1",
    "bind_docker_socket_guard_v1",
    "bind_root_owned_directory_chain_v1",
    "capture_linux_mount_table_v1",
    "linux_paths_overlap_v1",
    "linux_physical_path_v1",
    "parse_linux_mountinfo_v1",
]
