"""Pinned Linux OCI runtime verification and fixed Docker command grammar.

Only the trusted evaluator calls this module.  Task data never supplies an
image, command, entrypoint, mount destination, provider option, or resource
limit.  The execution lifecycle is intentionally split from these pure
verification/building primitives so every daemon observation can be checked
before a container is started.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import secrets
import stat
import sys
import tempfile
import threading
from typing import Any, Final

from vulngym_agent.evaluator.bounded_process import (
    BoundedProcessError,
    run_bounded_process_v1,
)
from vulngym_agent.evaluator.contracts import (
    EvaluatorContractError,
    ExecutionPolicyBindingV1,
)
from vulngym_agent.evaluator.oci_worker_entry import (
    D2_REPLAY_FILENAME,
    D3_REPLAY_FILENAME,
    HANDOFF_FILENAME,
    PROTOCOL_VERSION,
    REQUEST_FILENAME,
    WORKER_ERROR_KIND,
    GenerationReceiptV1,
    OciReplayConfigV1,
    OciWorkerEntryError,
    OciWorkerRequestV1,
    _inventory_source,
    _load_runtime_bundle,
    _manifest_directories,
    _read_source_record,
    _runtime_set_sha256,
)
from vulngym_agent.benchmark.worker_handoff import WorkerHandoffV1
from vulngym_agent.evaluator.runtime_evidence import (
    DockerServerIdentityV1,
    RuntimeEvidenceError,
    RuntimeEvidenceV1,
    RuntimeIsolationV1,
    RuntimeResourceLimitsV1,
    docker_endpoint_sha256_v1,
)
from vulngym_agent.evaluator.worker_completion import (
    CompletedWorkerExecutionV1,
    WorkerCompletionError,
    _issue_completed_worker_execution_v1,
)
from vulngym_agent.orchestrator.discovery_pipeline import SourceDiscoveryRunV1


LINUX_OCI_PROVIDER_VERSION: Final[str] = "linux-oci-provider-v1"
OCI_WORKER_MODULE: Final[str] = "vulngym_agent.evaluator.oci_worker_entry"
OCI_PYTHON: Final[str] = "/usr/local/bin/python3"
OCI_SOURCE_ROOT: Final[str] = "/vulngym/source"
OCI_RUNTIME_ROOT: Final[str] = "/vulngym/runtime"
OCI_GENERATION_ROOT: Final[str] = "/vulngym"
OCI_INPUT_SOURCE_ROOT: Final[str] = "/input-source"
OCI_INPUT_RUNTIME_ROOT: Final[str] = "/input-runtime"

_MASKED_PATHS_V1: Final[tuple[str, ...]] = (
    "/proc/acpi",
    "/proc/asound",
    "/proc/interrupts",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/sys/devices/virtual/powercap",
    "/sys/firmware",
)
_READONLY_PATHS_V1: Final[tuple[str, ...]] = (
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
)
_NONE_NETWORK_KEYS_V1: Final[frozenset[str]] = frozenset(
    {
        "Aliases",
        "DNSNames",
        "DriverOpts",
        "EndpointID",
        "Gateway",
        "GlobalIPv6Address",
        "GlobalIPv6PrefixLen",
        "GwPriority",
        "IPAMConfig",
        "IPAddress",
        "IPPrefixLen",
        "IPv6Gateway",
        "Links",
        "MacAddress",
        "NetworkID",
    }
)
_LEGACY_NONE_NETWORK_ROOT_KEYS_V1: Final[frozenset[str]] = frozenset(
    {
        "Bridge",
        "EndpointID",
        "Gateway",
        "GlobalIPv6Address",
        "GlobalIPv6PrefixLen",
        "HairpinMode",
        "IPAddress",
        "IPPrefixLen",
        "IPv6Gateway",
        "LinkLocalIPv6Address",
        "LinkLocalIPv6PrefixLen",
        "MacAddress",
        "Networks",
        "Ports",
        "SandboxID",
        "SandboxKey",
        "SecondaryIPAddresses",
        "SecondaryIPv6Addresses",
    }
)

_RUNTIME_TOKEN: Final[object] = object()
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_WORKER_ERROR_CODE_RE: Final[re.Pattern[str]] = re.compile(
    r"[a-z][a-z0-9_]{0,63}\Z"
)
_IMAGE_ID_RE: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_ID_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_NAME_RE: Final[re.Pattern[str]] = re.compile(r"vulngym-e3-[0-9a-f]{32}\Z")
_NPIPE_ENDPOINT_RE: Final[re.Pattern[str]] = re.compile(
    r"npipe:////\./pipe/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z"
)
_UNIX_ENDPOINT_RE: Final[re.Pattern[str]] = re.compile(
    r"unix:///[A-Za-z0-9_@+./-]{1,240}\Z"
)
_MAX_DOCKER_EXECUTABLE_BYTES: Final[int] = 256 * 1024 * 1024
_PROBE_STDOUT_BYTES: Final[int] = 4 * 1024 * 1024
_PROBE_STDERR_BYTES: Final[int] = 64 * 1024
_PROBE_TIMEOUT_SECONDS: Final[float] = 30.0
_CONTAINER_CREATE_SPEC_DOMAIN: Final[bytes] = (
    b"VulnGym Linux OCI container create spec v1\0"
)
_CONTAINER_IDENTITY_DOMAIN: Final[bytes] = (
    b"VulnGym Linux OCI container identity v1\0"
)
_SCRUBBED_DERIVED_IMAGE_LABELS: Final[dict[str, str]] = {
    "desktop.docker.io/mounts/0/Source": "",
    "desktop.docker.io/mounts/0/SourceKind": "",
    "desktop.docker.io/mounts/0/Target": "",
    "desktop.docker.io/mounts/1/Source": "",
    "desktop.docker.io/mounts/1/SourceKind": "",
    "desktop.docker.io/mounts/1/Target": "",
    "desktop.docker.io/ports.scheme": "",
}


class LinuxOciProviderError(RuntimeError):
    """Stable, path-free failure at the trusted Linux OCI boundary."""

    def __init__(
        self, code: str, message: str, *, runtime_uncertain: bool = False
    ) -> None:
        self.code = code if type(code) is str and code else "provider_failed"
        self.runtime_uncertain = runtime_uncertain is True
        super().__init__(message)


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise LinuxOciProviderError(
            "invalid_runtime", "OCI runtime response is not canonicalizable"
        ) from None


def _reject_constant(_value: str) -> None:
    raise LinuxOciProviderError(
        "invalid_runtime", "OCI runtime response contains a forbidden constant"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LinuxOciProviderError(
                "invalid_runtime", "OCI runtime response repeats a field"
            )
        result[key] = value
    return result


def _strict_json_document(payload: bytes, *, name: str) -> object:
    if type(payload) is not bytes or not payload or len(payload) > _PROBE_STDOUT_BYTES:
        raise LinuxOciProviderError(
            "invalid_runtime", f"{name} response has an invalid size"
        )
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except LinuxOciProviderError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError):
        raise LinuxOciProviderError(
            "invalid_runtime", f"{name} response is not strict JSON"
        ) from None
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 100_000 or depth > 16:
            raise LinuxOciProviderError(
                "invalid_runtime", f"{name} response exceeds its shape limit"
            )
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif item is not None and type(item) not in {str, int, float, bool}:
            raise LinuxOciProviderError(
                "invalid_runtime", f"{name} response has an invalid value"
            )
    return value


def _clean_runtime_environment(docker_executable: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in ("SYSTEMROOT", "WINDIR"):
        value = os.environ.get(name)
        if type(value) is str and value and "\x00" not in value:
            result[name] = value
    path_entries = [os.fspath(docker_executable.parent)]
    system_root = result.get("SYSTEMROOT") or result.get("WINDIR")
    if system_root:
        path_entries.append(os.path.join(system_root, "System32"))
    else:
        path_entries.extend(("/usr/local/bin", "/usr/bin", "/bin"))
    result["PATH"] = os.pathsep.join(path_entries)
    result["LANG"] = "C"
    result["LC_ALL"] = "C"
    result["PYTHONHASHSEED"] = "0"
    return result


def _bootstrap_runtime_environment(docker_executable: Path) -> dict[str, str]:
    """Allow Docker context inputs for one local-endpoint discovery command."""

    result = _clean_runtime_environment(docker_executable)
    for name in (
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "HOME",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    ):
        value = os.environ.get(name)
        if type(value) is str and value and "\x00" not in value:
            result[name] = value
    return result


def _local_docker_endpoint(value: object) -> str:
    if type(value) is not str or not value or len(value) > 256:
        raise LinuxOciProviderError(
            "unsupported_runtime", "OCI endpoint is not a supported local endpoint"
        )
    if _NPIPE_ENDPOINT_RE.fullmatch(value) is not None:
        return value
    if _UNIX_ENDPOINT_RE.fullmatch(value) is not None:
        socket_path = value[len("unix://") :]
        if (
            not socket_path.startswith("/")
            or posixpath.normpath(socket_path) != socket_path
            or any(part in {"", ".", ".."} for part in socket_path.split("/")[1:])
        ):
            raise LinuxOciProviderError(
                "unsupported_runtime",
                "OCI endpoint is not a supported local endpoint",
            )
        return value
    raise LinuxOciProviderError(
        "unsupported_runtime", "OCI endpoint is not a supported local endpoint"
    )


_ExecutableIdentity = tuple[int, int, int, int | None, int | None]


def _stat_identity(value: os.stat_result) -> _ExecutableIdentity:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        getattr(value, "st_mtime_ns", None),
        None if os.name == "nt" else getattr(value, "st_ctime_ns", None),
    )


def _digest_descriptor(descriptor: int, expected_size: int) -> str:
    digest = hashlib.sha256()
    consumed = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        consumed += len(chunk)
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    if consumed != expected_size:
        raise OSError("OCI executable size changed while hashing")
    return digest.hexdigest()


def _open_windows_locked_executable(path: Path) -> int:
    """Open one Windows file while denying every writer and path replacement."""

    import ctypes
    from ctypes import wintypes
    import msvcrt

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    generic_read = 0x80000000
    file_share_read = 0x00000001
    open_existing = 3
    file_attribute_normal = 0x00000080
    file_flag_sequential_scan = 0x08000000
    file_flag_open_reparse_point = 0x00200000
    handle = create_file(
        os.fspath(path),
        generic_read,
        file_share_read,
        None,
        open_existing,
        file_attribute_normal
        | file_flag_sequential_scan
        | file_flag_open_reparse_point,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if ctypes.c_void_p(handle).value == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    try:
        return msvcrt.open_osfhandle(int(handle), flags)
    except (OSError, OverflowError):
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
        raise


def _open_windows_namespace_guards(
    path: Path,
) -> tuple[tuple[int, tuple[int, int]], ...]:
    """Deny rename/delete on every directory used to resolve an executable."""

    import ctypes
    from ctypes import wintypes
    import msvcrt

    if not path.is_absolute() or re.fullmatch(r"[A-Za-z]:", path.drive) is None:
        raise OSError("OCI executable must be on a local fixed Windows volume")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_drive_type = kernel32.GetDriveTypeW
    get_drive_type.argtypes = (wintypes.LPCWSTR,)
    get_drive_type.restype = wintypes.UINT
    if get_drive_type(path.anchor) != 3:
        raise OSError("OCI executable must be on a local fixed Windows volume")
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    file_read_attributes = 0x00000080
    file_share_read_write = 0x00000003
    open_existing = 3
    file_flag_backup_semantics = 0x02000000
    file_flag_open_reparse_point = 0x00200000
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    result: list[tuple[int, tuple[int, int]]] = []
    try:
        for ancestor in reversed(path.parents):
            before = os.lstat(ancestor)
            if (
                not stat.S_ISDIR(before.st_mode)
                or stat.S_ISLNK(before.st_mode)
                or bool(getattr(before, "st_file_attributes", 0) & reparse)
            ):
                raise OSError("OCI executable namespace contains a reparse point")
            handle = create_file(
                os.fspath(ancestor),
                file_read_attributes,
                file_share_read_write,
                None,
                open_existing,
                file_flag_backup_semantics | file_flag_open_reparse_point,
                None,
            )
            if ctypes.c_void_p(handle).value == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                descriptor = msvcrt.open_osfhandle(
                    int(handle),
                    os.O_RDONLY | getattr(os, "O_NOINHERIT", 0),
                )
            except (OSError, OverflowError):
                kernel32.CloseHandle(handle)
                raise
            try:
                opened = os.fstat(descriptor)
                after = os.lstat(ancestor)
                expected = (before.st_dev, before.st_ino)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != expected
                    or (after.st_dev, after.st_ino) != expected
                ):
                    raise OSError("OCI executable namespace changed while binding")
            except BaseException:
                os.close(descriptor)
                raise
            result.append((descriptor, expected))
        return tuple(result)
    except BaseException:
        for descriptor, _identity in reversed(result):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


class _ExecutableLease:
    """Own the OS primitive that makes the hashed bytes the executed bytes."""

    __slots__ = (
        "_config_descriptor",
        "_config_path",
        "_descriptor",
        "_execution_path",
        "_identity",
        "_kind",
        "_lock",
        "_namespace_guards",
        "_required_seals",
    )

    def __init__(
        self,
        *,
        descriptor: int,
        execution_path: str | None,
        config_descriptor: int,
        config_path: str,
        identity: _ExecutableIdentity,
        kind: str,
        namespace_guards: tuple[tuple[int, tuple[int, int]], ...] = (),
        required_seals: int = 0,
    ) -> None:
        self._descriptor = descriptor
        self._execution_path = execution_path
        self._config_descriptor = config_descriptor
        self._config_path = config_path
        self._identity = identity
        self._kind = kind
        self._namespace_guards = namespace_guards
        self._required_seals = required_seals
        self._lock = threading.Lock()

    def close(self) -> None:
        with self._lock:
            descriptor = self._descriptor
            config_descriptor = self._config_descriptor
            namespace_guards = self._namespace_guards
            self._descriptor = -1
            self._config_descriptor = -1
            self._namespace_guards = ()
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if config_descriptor >= 0:
            try:
                os.close(config_descriptor)
            except OSError:
                pass
        for guard, _identity in reversed(namespace_guards):
            try:
                os.close(guard)
            except OSError:
                pass

    def execution_spec(
        self, *, path: str, identity: _ExecutableIdentity
    ) -> tuple[str | None, tuple[int, ...], str]:
        with self._lock:
            descriptor = self._descriptor
            if descriptor < 0 or identity != self._identity:
                raise OSError("OCI executable lease is unavailable")
            opened = os.fstat(descriptor)
            if self._kind == "windows":
                for guard, expected in self._namespace_guards:
                    guarded = os.fstat(guard)
                    if (
                        not stat.S_ISDIR(guarded.st_mode)
                        or (guarded.st_dev, guarded.st_ino) != expected
                    ):
                        raise OSError("OCI executable namespace guard changed")
                if _stat_identity(opened) != identity:
                    raise OSError("OCI executable handle identity changed")
                current = os.lstat(path)
                if _stat_identity(current) != identity:
                    raise OSError("OCI executable path identity changed")
                if self._config_descriptor != -1 or self._config_path != "NUL":
                    raise OSError("OCI client config isolation changed")
                return None, (), self._config_path
            if self._kind != "linux-memfd" or sys.platform != "linux":
                raise OSError("OCI executable lease kind is unsupported")
            if opened.st_size != identity[2] or not stat.S_ISREG(opened.st_mode):
                raise OSError("OCI executable snapshot identity changed")
            try:
                import fcntl

                actual_seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
            except (AttributeError, OSError):
                raise OSError("OCI executable snapshot seals are unavailable") from None
            if actual_seals & self._required_seals != self._required_seals:
                raise OSError("OCI executable snapshot is no longer immutable")
            if (
                self._execution_path is None
                or not os.path.exists(self._execution_path)
            ):
                raise OSError("OCI executable descriptor path is unavailable")
            config_descriptor = self._config_descriptor
            if config_descriptor < 0:
                raise OSError("OCI client config descriptor is unavailable")
            config = os.fstat(config_descriptor)
            if (
                not stat.S_ISDIR(config.st_mode)
                or config.st_mode & 0o222
                or self._config_path != f"/proc/self/fd/{config_descriptor}"
            ):
                raise OSError("OCI client config isolation changed")
            return (
                self._execution_path,
                (descriptor, config_descriptor),
                self._config_path,
            )

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass


@dataclass(frozen=True, slots=True)
class _ExecutableBinding:
    path: str
    content_sha256: str
    identity: _ExecutableIdentity
    lease: _ExecutableLease | None = field(
        default=None, compare=False, repr=False
    )

    def execution_spec(self) -> tuple[str | None, tuple[int, ...], str]:
        if self.lease is None:
            raise LinuxOciProviderError(
                "runtime_changed", "OCI executable lease is unavailable"
            )
        try:
            return self.lease.execution_spec(path=self.path, identity=self.identity)
        except OSError as error:
            raise LinuxOciProviderError(
                "runtime_changed", "OCI executable binding is no longer valid"
            ) from error


def _copy_to_sealed_linux_memfd(
    source_descriptor: int, *, expected_size: int
) -> tuple[int, str, int]:
    try:
        import fcntl

        required_seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | getattr(os, "MFD_EXEC", 0)
        snapshot = os.memfd_create("vulngym-docker-cli-v1", flags)
    except (AttributeError, OSError):
        raise OSError("sealed executable snapshots are unavailable") from None
    digest = hashlib.sha256()
    consumed = 0
    try:
        os.lseek(source_descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            consumed += len(chunk)
            digest.update(chunk)
            pending = memoryview(chunk)
            while pending:
                written = os.write(snapshot, pending)
                if written < 1:
                    raise OSError("short executable snapshot write")
                pending = pending[written:]
        if consumed != expected_size:
            raise OSError("OCI executable changed while snapshotting")
        os.fchmod(snapshot, stat.S_IRUSR | stat.S_IXUSR)
        fcntl.fcntl(snapshot, fcntl.F_ADD_SEALS, required_seals)
        actual_seals = fcntl.fcntl(snapshot, fcntl.F_GET_SEALS)
        if actual_seals & required_seals != required_seals:
            raise OSError("OCI executable snapshot sealing failed")
        if _digest_descriptor(snapshot, expected_size) != digest.hexdigest():
            raise OSError("OCI executable snapshot digest changed")
        return snapshot, digest.hexdigest(), required_seals
    except BaseException:
        os.close(snapshot)
        raise


def _create_unlinked_linux_config_directory() -> tuple[int, str]:
    directory = tempfile.mkdtemp(prefix="vulngym-docker-config-v1-")
    descriptor = -1
    try:
        os.chmod(directory, stat.S_IRUSR | stat.S_IXUSR)
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode) or opened.st_mode & 0o222:
            raise OSError("isolated OCI client config is not read-only")
        os.rmdir(directory)
        return descriptor, f"/proc/self/fd/{descriptor}"
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            os.rmdir(directory)
        except OSError:
            pass
        raise


def _bind_executable(value: object) -> _ExecutableBinding:
    if type(value) not in {str, type(Path())}:
        raise LinuxOciProviderError(
            "invalid_argument", "OCI executable path has an invalid exact type"
        )
    try:
        path = Path(os.path.abspath(os.fspath(value)))
        before = os.lstat(path)
    except (OSError, TypeError, ValueError):
        raise LinuxOciProviderError(
            "runtime_unavailable", "OCI executable is unavailable"
        ) from None
    attributes = getattr(before, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or bool(attributes & reparse)
        or before.st_size < 1
        or before.st_size > _MAX_DOCKER_EXECUTABLE_BYTES
    ):
        raise LinuxOciProviderError(
            "runtime_unavailable", "OCI executable identity is unsafe"
        )
    if os.name == "posix" and not before.st_mode & 0o111:
        raise LinuxOciProviderError(
            "runtime_unavailable", "OCI executable identity is unsafe"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    lease: _ExecutableLease | None = None
    namespace_guards: tuple[tuple[int, tuple[int, int]], ...] = ()
    try:
        if os.name == "nt":
            namespace_guards = _open_windows_namespace_guards(path)
            descriptor = _open_windows_locked_executable(path)
        elif os.name == "posix" and sys.platform == "linux":
            descriptor = os.open(path, flags)
        else:
            raise OSError("host cannot provide a strict executable binding")
        try:
            opened = os.fstat(descriptor)
            identity = _stat_identity(before)
            if _stat_identity(opened) != identity:
                raise OSError("OCI executable changed while opening")
            if os.name == "nt":
                digest = _digest_descriptor(descriptor, before.st_size)
                lease = _ExecutableLease(
                    descriptor=descriptor,
                    execution_path=None,
                    config_descriptor=-1,
                    config_path="NUL",
                    identity=identity,
                    kind="windows",
                    namespace_guards=namespace_guards,
                )
                namespace_guards = ()
                descriptor = -1
            else:
                snapshot, digest, required_seals = _copy_to_sealed_linux_memfd(
                    descriptor, expected_size=before.st_size
                )
                try:
                    config_descriptor, config_path = (
                        _create_unlinked_linux_config_directory()
                    )
                except BaseException:
                    os.close(snapshot)
                    raise
                lease = _ExecutableLease(
                    descriptor=snapshot,
                    execution_path=f"/proc/self/fd/{snapshot}",
                    config_descriptor=config_descriptor,
                    config_path=config_path,
                    identity=identity,
                    kind="linux-memfd",
                    required_seals=required_seals,
                )
            finished = os.fstat(
                lease._descriptor if os.name == "nt" else descriptor
            )
            if os.name != "nt" and _stat_identity(finished) != identity:
                raise OSError("OCI executable changed while hashing")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        after = os.lstat(path)
    except OSError as error:
        if lease is not None:
            lease.close()
        for guard, _identity in reversed(namespace_guards):
            try:
                os.close(guard)
            except OSError:
                pass
        raise LinuxOciProviderError(
            "runtime_unavailable", "OCI executable could not be bound"
        ) from error
    if _stat_identity(after) != identity:
        if lease is not None:
            lease.close()
        raise LinuxOciProviderError(
            "runtime_unavailable", "OCI executable changed while hashing"
        )
    return _ExecutableBinding(os.fspath(path), digest, identity, lease)


def _run_probe(
    executable: _ExecutableBinding,
    env: dict[str, str],
    arguments: tuple[str, ...],
    *,
    endpoint: str,
) -> bytes:
    bound_endpoint = _local_docker_endpoint(endpoint)
    execution_path, inherited_fds, config_path = executable.execution_spec()
    try:
        result = run_bounded_process_v1(
            (
                executable.path,
                f"--host={bound_endpoint}",
                f"--config={config_path}",
                *arguments,
            ),
            stdout_max_bytes=_PROBE_STDOUT_BYTES,
            stderr_max_bytes=_PROBE_STDERR_BYTES,
            timeout_seconds=_PROBE_TIMEOUT_SECONDS,
            env=env,
            executable=execution_path,
            inherited_fds=inherited_fds,
        )
    except BoundedProcessError as error:
        raise LinuxOciProviderError(
            "runtime_unavailable", "OCI runtime probe could not be completed"
        ) from error
    if (
        result.exit_code != 0
        or result.timed_out
        or result.stdout_overflow
        or result.stderr_overflow
        or result.stderr
    ):
        raise LinuxOciProviderError(
            "runtime_unavailable", "OCI runtime probe was not clean"
        )
    return result.stdout


def _resolve_local_docker_endpoint(
    executable: _ExecutableBinding,
    env: dict[str, str],
) -> str:
    configured = env.get("DOCKER_HOST")
    if configured is not None:
        return _local_docker_endpoint(configured)
    execution_path, inherited_fds, _config_path = executable.execution_spec()
    try:
        result = run_bounded_process_v1(
            (
                executable.path,
                "context",
                "inspect",
                "--format",
                "{{json .Endpoints.docker.Host}}",
            ),
            stdout_max_bytes=4096,
            stderr_max_bytes=_PROBE_STDERR_BYTES,
            timeout_seconds=_PROBE_TIMEOUT_SECONDS,
            env=env,
            executable=execution_path,
            inherited_fds=inherited_fds,
        )
    except BoundedProcessError as error:
        raise LinuxOciProviderError(
            "runtime_unavailable", "OCI endpoint discovery could not be completed"
        ) from error
    if (
        result.exit_code != 0
        or result.timed_out
        or result.stdout_overflow
        or result.stderr_overflow
        or result.stderr
    ):
        raise LinuxOciProviderError(
            "runtime_unavailable", "OCI endpoint discovery was not clean"
        )
    endpoint = _strict_json_document(result.stdout, name="OCI endpoint")
    return _local_docker_endpoint(endpoint)


class VerifiedLinuxOciRuntimeV1:
    """Opaque binding to one CLI binary, daemon observation, image, and policy."""

    __slots__ = (
        "__arch",
        "__env",
        "__endpoint",
        "__executable",
        "__image_config_payload",
        "__image_inspect_sha256",
        "__policy_payload",
        "__policy_sha256",
        "__server_api_version",
        "__server_sha256",
        "__server_version",
    )

    def __init__(
        self,
        token: object,
        *,
        executable: _ExecutableBinding,
        env: dict[str, str],
        endpoint: str,
        server: dict[str, object],
        server_sha256: str,
        image_config: dict[str, object],
        image_inspect_sha256: str,
        policy: ExecutionPolicyBindingV1,
    ) -> None:
        if token is not _RUNTIME_TOKEN:
            raise TypeError("verified OCI runtimes are provider-created")
        self.__executable = executable
        self.__env = dict(env)
        self.__endpoint = _local_docker_endpoint(endpoint)
        self.__server_version = str(server["Version"])
        self.__server_api_version = str(server["ApiVersion"])
        self.__arch = str(server["Arch"])
        self.__server_sha256 = server_sha256
        self.__image_config_payload = _canonical_json(image_config)
        self.__image_inspect_sha256 = image_inspect_sha256
        self.__policy_payload = policy.to_bytes()
        self.__policy_sha256 = policy.policy_sha256

    @property
    def docker_executable(self) -> str:
        return self.__executable.path

    @property
    def docker_executable_sha256(self) -> str:
        return self.__executable.content_sha256

    @property
    def docker_endpoint(self) -> str:
        return self.__endpoint

    @property
    def server_version(self) -> str:
        return self.__server_version

    @property
    def server_api_version(self) -> str:
        return self.__server_api_version

    @property
    def server_arch(self) -> str:
        return self.__arch

    @property
    def server_sha256(self) -> str:
        return self.__server_sha256

    @property
    def image_inspect_sha256(self) -> str:
        return self.__image_inspect_sha256

    def _base_image_config(self) -> dict[str, object]:
        try:
            value = json.loads(
                self.__image_config_payload.decode("utf-8", errors="strict"),
                parse_constant=_reject_constant,
                object_pairs_hook=_unique_object,
            )
        except (UnicodeError, json.JSONDecodeError, ValueError):
            raise LinuxOciProviderError(
                "runtime_changed", "pinned image configuration changed"
            ) from None
        if type(value) is not dict or _canonical_json(value) != self.__image_config_payload:
            raise LinuxOciProviderError(
                "runtime_changed", "pinned image configuration changed"
            )
        return value

    @property
    def execution_policy(self) -> ExecutionPolicyBindingV1:
        return ExecutionPolicyBindingV1.from_bytes(
            self.__policy_payload,
            expected_policy_sha256=self.__policy_sha256,
            expected_wire_sha256=hashlib.sha256(self.__policy_payload).hexdigest(),
        )

    def _command_context(
        self,
    ) -> tuple[_ExecutableBinding, dict[str, str], str]:
        self.__executable.execution_spec()
        return self.__executable, dict(self.__env), self.__endpoint

    def __reduce__(self):
        raise TypeError("verified OCI runtimes are not serializable")


def verify_linux_oci_runtime_v1(
    docker_executable: str | Path,
    *,
    execution_policy: ExecutionPolicyBindingV1,
) -> VerifiedLinuxOciRuntimeV1:
    """Bind an exact Docker CLI, Linux daemon, image ID, and execution policy."""

    if type(execution_policy) is not ExecutionPolicyBindingV1:
        raise LinuxOciProviderError(
            "invalid_argument", "execution policy must have an exact type"
        )
    try:
        policy_wire = execution_policy.to_bytes()
        policy = ExecutionPolicyBindingV1.from_bytes(
            policy_wire,
            expected_policy_sha256=execution_policy.policy_sha256,
            expected_wire_sha256=hashlib.sha256(policy_wire).hexdigest(),
        )
    except (AttributeError, EvaluatorContractError, TypeError, ValueError):
        raise LinuxOciProviderError(
            "invalid_argument", "execution policy did not pass strict normalization"
        ) from None
    executable = _bind_executable(docker_executable)
    endpoint = _resolve_local_docker_endpoint(
        executable,
        _bootstrap_runtime_environment(Path(executable.path)),
    )
    env = _clean_runtime_environment(Path(executable.path))
    server_payload = _run_probe(
        executable,
        env,
        ("version", "--format", "{{json .Server}}"),
        endpoint=endpoint,
    )
    server = _strict_json_document(server_payload, name="OCI server")
    if type(server) is not dict:
        raise LinuxOciProviderError(
            "invalid_runtime", "OCI server response must be an object"
        )
    required = ("Version", "ApiVersion", "Os", "Arch")
    if (
        any(type(server.get(name)) is not str or not server[name] for name in required)
        or server["Os"] != "linux"
        or server["Arch"] not in {"amd64", "arm64"}
    ):
        raise LinuxOciProviderError(
            "unsupported_runtime", "OCI server is not a supported Linux runtime"
        )
    server_sha256 = hashlib.sha256(_canonical_json(server)).hexdigest()
    image_payload = _run_probe(
        executable,
        env,
        (
            "image",
            "inspect",
            policy.runtime_image_id,
            "--format",
            "{{json .}}",
        ),
        endpoint=endpoint,
    )
    image = _strict_json_document(image_payload, name="OCI image")
    if (
        type(image) is not dict
        or image.get("Id") != policy.runtime_image_id
        or image.get("Os") != "linux"
        or image.get("Architecture") != server["Arch"]
        or type(image.get("Config")) is not dict
    ):
        raise LinuxOciProviderError(
            "image_mismatch", "OCI image does not match the pinned Linux image"
        )
    return VerifiedLinuxOciRuntimeV1(
        _RUNTIME_TOKEN,
        executable=executable,
        env=env,
        endpoint=endpoint,
        server=server,
        server_sha256=server_sha256,
        image_config=image["Config"],
        image_inspect_sha256=hashlib.sha256(_canonical_json(image)).hexdigest(),
        policy=policy,
    )


def _generated_name(value: object, *, name: str) -> str:
    if type(value) is not str or _NAME_RE.fullmatch(value) is None:
        raise LinuxOciProviderError("invalid_argument", f"{name} is invalid")
    return value


def _safe_source_path(value: object) -> str:
    if type(value) not in {str, type(Path())}:
        raise LinuxOciProviderError(
            "invalid_argument", "source generation path is invalid"
        )
    try:
        path = os.path.abspath(os.fspath(value))
    except (OSError, TypeError, ValueError):
        raise LinuxOciProviderError(
            "invalid_argument", "source generation path is invalid"
        ) from None
    if not path or any(character in path for character in ("\x00", ",", "\r", "\n")):
        raise LinuxOciProviderError(
            "invalid_argument", "source generation path cannot form a fixed mount"
        )
    return path


def build_worker_container_create_argv_v1(
    runtime: VerifiedLinuxOciRuntimeV1,
    *,
    container_name: str,
    mode: str,
    execution_image_id: str | None = None,
    source_root: str | Path | None = None,
    runtime_input_root: str | Path | None = None,
) -> tuple[str, ...]:
    """Return the complete fixed container-create grammar for one provider step."""

    if type(runtime) is not VerifiedLinuxOciRuntimeV1:
        raise LinuxOciProviderError(
            "invalid_argument", "runtime must have an exact verified type"
    )
    container = _generated_name(container_name, name="container_name")
    if type(mode) is not str or mode not in {"materialize", "execute"}:
        raise LinuxOciProviderError("invalid_argument", "worker mode is invalid")
    if (mode == "materialize") != (
        source_root is not None and runtime_input_root is not None
    ) or (mode == "execute" and (source_root is not None or runtime_input_root is not None)):
        raise LinuxOciProviderError(
            "invalid_argument", "worker source mount does not match its mode"
        )
    policy = runtime.execution_policy
    if mode == "materialize":
        if execution_image_id is not None:
            raise LinuxOciProviderError(
                "invalid_argument", "materializer image must be the pinned base image"
            )
        image_id = policy.runtime_image_id
    else:
        if (
            type(execution_image_id) is not str
            or _IMAGE_ID_RE.fullmatch(execution_image_id) is None
            or execution_image_id == policy.runtime_image_id
        ):
            raise LinuxOciProviderError(
                "invalid_argument", "worker generation image identity is invalid"
            )
        image_id = execution_image_id
    cpu_quota = policy.cpu_millis * 100
    user = "65532:65532"
    hostname = "vulngym-materializer" if mode == "materialize" else "vulngym-worker"
    arguments: list[str] = [
        runtime.docker_executable,
        "container",
        "create",
        "--pull=never",
        f"--name={container}",
        f"--label=vulngym.e3.container={container}",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        f"--user={user}",
        f"--pids-limit={policy.pids_limit}",
        f"--memory={policy.memory_bytes}",
        f"--memory-swap={policy.memory_bytes}",
        "--cpu-period=100000",
        f"--cpu-quota={cpu_quota}",
        f"--ulimit=nofile={policy.open_files_limit}:{policy.open_files_limit}",
        "--ipc=none",
        "--cgroupns=private",
        "--restart=no",
        "--no-healthcheck",
        "--log-driver=none",
        "--runtime=runc",
        f"--hostname={hostname}",
        f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={policy.tmpfs_bytes},mode=0700,uid={user.split(':')[0]},gid={user.split(':')[1]}",
        "--workdir=/tmp",
    ]
    if mode == "execute":
        arguments.append("--read-only")
    if mode == "materialize":
        source = _safe_source_path(source_root)
        runtime_input = _safe_source_path(runtime_input_root)
        arguments.extend(
            (
                "--mount",
                f"type=bind,src={source},dst={OCI_INPUT_SOURCE_ROOT},readonly,bind-propagation=rprivate,bind-recursive=readonly",
                "--mount",
                f"type=bind,src={runtime_input},dst={OCI_INPUT_RUNTIME_ROOT},readonly,bind-propagation=rprivate,bind-recursive=readonly",
            )
        )
    arguments.extend((image_id, mode))
    return tuple(arguments)


def _none_network_settings_valid_v1(value: object) -> bool:
    if type(value) is not dict:
        return False
    keys = frozenset(value)
    modern_keys = frozenset({"SandboxID", "SandboxKey", "Ports", "Networks"})
    if keys == modern_keys:
        legacy_valid = True
    elif keys == _LEGACY_NONE_NETWORK_ROOT_KEYS_V1:
        legacy_valid = (
            value.get("Bridge") == ""
            and value.get("EndpointID") == ""
            and value.get("Gateway") == ""
            and value.get("GlobalIPv6Address") == ""
            and type(value.get("GlobalIPv6PrefixLen")) is int
            and value.get("GlobalIPv6PrefixLen") == 0
            and value.get("HairpinMode") is False
            and value.get("IPAddress") == ""
            and type(value.get("IPPrefixLen")) is int
            and value.get("IPPrefixLen") == 0
            and value.get("IPv6Gateway") == ""
            and value.get("LinkLocalIPv6Address") == ""
            and type(value.get("LinkLocalIPv6PrefixLen")) is int
            and value.get("LinkLocalIPv6PrefixLen") == 0
            and value.get("MacAddress") == ""
            and value.get("SecondaryIPAddresses") is None
            and value.get("SecondaryIPv6Addresses") is None
        )
    else:
        return False
    networks = value.get("Networks")
    if (
        not legacy_valid
        or value.get("SandboxID") != ""
        or value.get("SandboxKey") != ""
        or value.get("Ports") != {}
        or type(networks) is not dict
        or set(networks) != {"none"}
        or type(networks.get("none")) is not dict
    ):
        return False
    none = networks["none"]
    network_id = none.get("NetworkID")
    return (
        set(none) == _NONE_NETWORK_KEYS_V1
        and none.get("IPAMConfig") is None
        and none.get("Links") is None
        and none.get("Aliases") is None
        and none.get("DriverOpts") is None
        and type(none.get("GwPriority")) is int
        and none.get("GwPriority") == 0
        and type(network_id) is str
        and (network_id == "" or _CONTAINER_ID_RE.fullmatch(network_id) is not None)
        and none.get("EndpointID") == ""
        and none.get("Gateway") == ""
        and none.get("IPAddress") == ""
        and none.get("MacAddress") == ""
        and type(none.get("IPPrefixLen")) is int
        and none.get("IPPrefixLen") == 0
        and none.get("IPv6Gateway") == ""
        and none.get("GlobalIPv6Address") == ""
        and type(none.get("GlobalIPv6PrefixLen")) is int
        and none.get("GlobalIPv6PrefixLen") == 0
        and none.get("DNSNames") is None
    )


def _exact_path_members_v1(value: object, expected: tuple[str, ...]) -> bool:
    return (
        type(value) is list
        and len(value) == len(expected)
        and all(type(item) is str for item in value)
        and frozenset(value) == frozenset(expected)
    )


def normalized_container_inspect_v1(
    payload: bytes,
    *,
    runtime: VerifiedLinuxOciRuntimeV1,
    container_name: str,
    mode: str,
    execution_image_id: str | None = None,
    execution_image_label: str | None = None,
    source_root: str | Path | None = None,
    runtime_input_root: str | Path | None = None,
) -> dict[str, object]:
    """Validate and path-normalize a pre-start Docker inspect observation."""

    if type(runtime) is not VerifiedLinuxOciRuntimeV1:
        raise LinuxOciProviderError(
            "invalid_argument", "runtime must have an exact verified type"
    )
    container = _generated_name(container_name, name="container_name")
    if mode not in {"materialize", "execute"}:
        raise LinuxOciProviderError("invalid_argument", "worker mode is invalid")
    if (mode == "materialize") != (
        source_root is not None and runtime_input_root is not None
    ) or (
        mode == "execute"
        and (source_root is not None or runtime_input_root is not None)
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "container source binding does not match its mode"
        )
    expected_sources = (
        {
            OCI_INPUT_SOURCE_ROOT: _safe_source_path(source_root),
            OCI_INPUT_RUNTIME_ROOT: _safe_source_path(runtime_input_root),
        }
        if mode == "materialize"
        else {}
    )
    policy = runtime.execution_policy
    expected_image_id = (
        policy.runtime_image_id if mode == "materialize" else execution_image_id
    )
    if (
        type(expected_image_id) is not str
        or _IMAGE_ID_RE.fullmatch(expected_image_id) is None
        or (mode == "execute" and expected_image_id == policy.runtime_image_id)
        or (mode == "materialize" and execution_image_label is not None)
        or (
            mode == "execute"
            and (
                type(execution_image_label) is not str
                or _NAME_RE.fullmatch(execution_image_label) is None
            )
        )
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "container image identity is invalid"
        )
    value = _strict_json_document(payload, name="container inspect")
    if type(value) is list and len(value) == 1:
        value = value[0]
    if type(value) is not dict:
        raise LinuxOciProviderError(
            "invalid_container", "container inspect must identify one object"
        )
    config = value.get("Config")
    host = value.get("HostConfig")
    mounts = value.get("Mounts")
    network_settings = value.get("NetworkSettings")
    name = value.get("Name")
    container_id = value.get("Id")
    if (
        type(config) is not dict
        or type(host) is not dict
        or type(mounts) is not list
        or type(network_settings) is not dict
        or type(name) is not str
        or name != "/" + container
        or type(container_id) is not str
        or _CONTAINER_ID_RE.fullmatch(container_id) is None
        or value.get("Image") != expected_image_id
    ):
        raise LinuxOciProviderError(
            "invalid_container", "container identity is detached from its launch"
        )
    expected_user = "65532:65532"
    expected_hostname = (
        "vulngym-materializer" if mode == "materialize" else "vulngym-worker"
    )
    expected_labels = {
        "org.opencontainers.image.title": "VulnGym isolated evaluator worker",
        "org.opencontainers.image.version": "source-discovery-isolated-worker-v1",
        "vulngym.e3.container": container,
    }
    if mode == "execute":
        expected_labels["vulngym.e3.execution"] = execution_image_label
    base_config = runtime._base_image_config()
    expected_env = base_config.get("Env")
    if expected_env is not None and (
        type(expected_env) is not list
        or any(type(item) is not str for item in expected_env)
        or len(expected_env) != len(set(expected_env))
    ):
        raise LinuxOciProviderError(
            "invalid_runtime", "pinned image environment is invalid"
        )
    if (
        config.get("Image") != expected_image_id
        or config.get("User") != expected_user
        or config.get("Hostname") != expected_hostname
        or config.get("WorkingDir") != "/tmp"
        or config.get("Entrypoint")
        != [OCI_PYTHON, "-I", "-B", "-m", OCI_WORKER_MODULE]
        or config.get("Cmd") != [mode]
        or config.get("Labels") != expected_labels
        or config.get("Env") != expected_env
        or config.get("AttachStdin") is not False
        or config.get("AttachStdout") is not True
        or config.get("AttachStderr") is not True
        or config.get("Tty") is not False
        or config.get("OpenStdin") is not False
        or config.get("StdinOnce") is not False
        or config.get("Healthcheck") != {"Test": ["NONE"]}
        or config.get("Volumes") not in (None, {})
        or config.get("ExposedPorts") not in (None, {})
    ):
        raise LinuxOciProviderError(
            "invalid_container", "container command or image configuration drifted"
        )
    security_options = host.get("SecurityOpt")
    cap_drop = host.get("CapDrop")
    restart_policy = host.get("RestartPolicy")
    log_config = host.get("LogConfig")
    ulimits = host.get("Ulimits")
    host_mounts = host.get("Mounts")
    tmpfs = host.get("Tmpfs")
    expected_tmpfs_options = {
        "rw",
        "noexec",
        "nosuid",
        "nodev",
        f"size={policy.tmpfs_bytes}",
        "mode=0700",
        "uid=65532",
        "gid=65532",
    }
    tmpfs_valid = False
    if type(tmpfs) is dict and set(tmpfs) == {"/tmp"} and type(tmpfs["/tmp"]) is str:
        tmpfs_parts = tmpfs["/tmp"].split(",")
        tmpfs_valid = (
            len(tmpfs_parts) == len(expected_tmpfs_options)
            and set(tmpfs_parts) == expected_tmpfs_options
        )
    expected_host_mount_targets = set(expected_sources)
    observed_host_mount_targets: set[str] = set()
    host_mounts_valid = (
        host_mounts in (None, [], ())
        if mode == "execute"
        else type(host_mounts) is list
    )
    if host_mounts_valid and type(host_mounts) is list:
        for mount in host_mounts:
            if type(mount) is not dict:
                host_mounts_valid = False
                break
            target = mount.get("Target")
            options = mount.get("BindOptions")
            if (
                set(mount)
                != {"Type", "Source", "Target", "ReadOnly", "BindOptions"}
                or mount.get("Type") != "bind"
                or mount.get("Source") != expected_sources.get(target)
                or type(target) is not str
                or target not in expected_host_mount_targets
                or target in observed_host_mount_targets
                or mount.get("ReadOnly") is not True
                or options
                != {
                    "Propagation": "rprivate",
                    "ReadOnlyForceRecursive": True,
                }
            ):
                host_mounts_valid = False
                break
            observed_host_mount_targets.add(target)
    host_mounts_valid = (
        host_mounts_valid
        and observed_host_mount_targets == expected_host_mount_targets
    )
    if not host_mounts_valid:
        raise LinuxOciProviderError(
            "invalid_container", "container mount policy drifted"
        )
    if not (
        _exact_path_members_v1(host.get("MaskedPaths"), _MASKED_PATHS_V1)
        and _exact_path_members_v1(host.get("ReadonlyPaths"), _READONLY_PATHS_V1)
    ):
        raise LinuxOciProviderError(
            "invalid_container", "container procfs protection policy drifted"
        )
    if not _none_network_settings_valid_v1(network_settings):
        raise LinuxOciProviderError(
            "invalid_container", "container network policy drifted"
        )
    expected_quota = policy.cpu_millis * 100
    if (
        host.get("NetworkMode") != "none"
        or host.get("ReadonlyRootfs") is not (mode == "execute")
        or host.get("Privileged") is not False
        or host.get("PublishAllPorts") is not False
        or host.get("AutoRemove") is not False
        or cap_drop != ["ALL"]
        or host.get("CapAdd") not in (None, [], ())
        or host.get("GroupAdd") not in (None, [], ())
        or host.get("PidMode") not in {"", "private"}
        or host.get("UsernsMode") != ""
        or host.get("Binds") not in (None, [], ())
        or host.get("PortBindings") not in (None, {})
        or host.get("Links") not in (None, [], ())
        or host.get("Dns") not in (None, [], ())
        or host.get("DnsOptions") not in (None, [], ())
        or host.get("DnsSearch") not in (None, [], ())
        or host.get("ExtraHosts") not in (None, [], ())
        or host.get("DeviceCgroupRules") not in (None, [], ())
        or host.get("DeviceRequests") not in (None, [], ())
        or host.get("OomKillDisable") not in (None, False)
        or host.get("Init") not in (None, False)
        or host.get("CgroupParent") not in (None, "")
        or security_options != ["no-new-privileges=true"]
        or host.get("PidsLimit") != policy.pids_limit
        or host.get("Memory") != policy.memory_bytes
        or host.get("MemorySwap") != policy.memory_bytes
        or host.get("CpuPeriod") != 100000
        or host.get("CpuQuota") != expected_quota
        or host.get("IpcMode") != "none"
        or host.get("CgroupnsMode") != "private"
        or host.get("UTSMode") not in {"", "private"}
        or host.get("Runtime") != "runc"
        or type(restart_policy) is not dict
        or restart_policy.get("Name") not in {"", "no"}
        or type(log_config) is not dict
        or log_config.get("Type") != "none"
        or type(ulimits) is not list
        or ulimits
        != [
            {
                "Name": "nofile",
                "Hard": policy.open_files_limit,
                "Soft": policy.open_files_limit,
            }
        ]
        or host.get("Devices") not in (None, (), [])
        or not tmpfs_valid
    ):
        raise LinuxOciProviderError(
            "invalid_container", "container isolation or resource policy drifted"
        )
    normalized_mounts: list[dict[str, object]] = []
    for mount in mounts:
        if type(mount) is not dict:
            raise LinuxOciProviderError(
                "invalid_container", "container mount record is invalid"
            )
        destination = mount.get("Destination")
        mount_type = mount.get("Type")
        rw = mount.get("RW")
        source = mount.get("Source")
        if mode == "materialize" and destination == OCI_INPUT_SOURCE_ROOT:
            if (
                set(mount)
                != {"Type", "Source", "Destination", "Mode", "RW", "Propagation"}
                or mount_type != "bind"
                or rw is not False
                or source != expected_sources.get(destination)
                or mount.get("Mode") != ""
                or mount.get("Propagation") != "rprivate"
            ):
                raise LinuxOciProviderError(
                    "invalid_container", "materializer source mount is invalid"
                )
            normalized_mounts.append(
                {"destination": destination, "source": "source-input", "rw": False}
            )
        elif mode == "materialize" and destination == OCI_INPUT_RUNTIME_ROOT:
            if (
                set(mount)
                != {"Type", "Source", "Destination", "Mode", "RW", "Propagation"}
                or mount_type != "bind"
                or rw is not False
                or source != expected_sources.get(destination)
                or mount.get("Mode") != ""
                or mount.get("Propagation") != "rprivate"
            ):
                raise LinuxOciProviderError(
                    "invalid_container", "materializer runtime input mount is invalid"
                )
            normalized_mounts.append(
                {"destination": destination, "source": "runtime-input", "rw": False}
            )
        else:
            raise LinuxOciProviderError(
                "invalid_container", "container has an unexpected mount"
            )
    expected_mount_count = 2 if mode == "materialize" else 0
    if len(normalized_mounts) != expected_mount_count:
        raise LinuxOciProviderError(
            "invalid_container", "container mount set is incomplete"
        )
    normalized_mounts.sort(key=lambda item: str(item["destination"]))
    return {
        "container_id": container_id,
        "image_id": expected_image_id,
        "mode": mode,
        "mounts": normalized_mounts,
        "masked_paths": list(_MASKED_PATHS_V1),
        "network_mode": "none",
        "none_network_content": True,
        "read_only_rootfs": mode == "execute",
        "readonly_paths": list(_READONLY_PATHS_V1),
        "recursive_readonly_bind": mode == "materialize",
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "user": expected_user,
        "pids_limit": policy.pids_limit,
        "memory_bytes": policy.memory_bytes,
        "memory_swap_bytes": policy.memory_bytes,
        "cpu_period": 100000,
        "cpu_quota": expected_quota,
        "open_files_limit": policy.open_files_limit,
        "ipc_mode": "none",
        "cgroupns_mode": "private",
        "uts_mode": "private-default",
        "runtime": "runc",
        "log_driver": "none",
    }


def container_inspect_sha256_v1(normalized: dict[str, object]) -> str:
    if type(normalized) is not dict:
        raise LinuxOciProviderError(
            "invalid_argument", "normalized inspect must be an exact object"
        )
    return hashlib.sha256(_canonical_json(normalized)).hexdigest()


def container_create_spec_sha256_v1(
    runtime: VerifiedLinuxOciRuntimeV1,
    *,
    mode: str,
    execution_image_id: str | None = None,
) -> str:
    """Digest the path/name-free fixed create grammar for evidence."""

    if type(runtime) is not VerifiedLinuxOciRuntimeV1 or mode not in {
        "materialize",
        "execute",
    }:
        raise LinuxOciProviderError(
            "invalid_argument", "container create specification is invalid"
        )
    policy = runtime.execution_policy
    if mode == "materialize":
        if execution_image_id is not None:
            raise LinuxOciProviderError(
                "invalid_argument", "materializer create specification is invalid"
            )
        image_id = policy.runtime_image_id
    else:
        if (
            type(execution_image_id) is not str
            or _IMAGE_ID_RE.fullmatch(execution_image_id) is None
            or execution_image_id == policy.runtime_image_id
        ):
            raise LinuxOciProviderError(
                "invalid_argument", "execution create specification is invalid"
            )
        image_id = execution_image_id
    record = {
        "cap_drop": "ALL",
        "cgroupns": "private",
        "command": [mode],
        "cpu_period": 100000,
        "cpu_quota": policy.cpu_millis * 100,
        "entrypoint": [OCI_PYTHON, "-I", "-B", "-m", OCI_WORKER_MODULE],
        "hostname": (
            "vulngym-materializer" if mode == "materialize" else "vulngym-worker"
        ),
        "image_id": image_id,
        "ipc": "none",
        "log_driver": "none",
        "memory_bytes": policy.memory_bytes,
        "memory_swap_bytes": policy.memory_bytes,
        "mounts": (
            [
                ["bind", "source-input", OCI_INPUT_SOURCE_ROOT, "read-only-recursive"],
                ["bind", "runtime-input", OCI_INPUT_RUNTIME_ROOT, "read-only-recursive"],
            ]
            if mode == "materialize"
            else []
        ),
        "network": "none",
        "no_healthcheck": True,
        "no_new_privileges": True,
        "nofile": policy.open_files_limit,
        "pids_limit": policy.pids_limit,
        "pid_mode": "private-default",
        "provider_version": LINUX_OCI_PROVIDER_VERSION,
        "pull": "never",
        "restart": "no",
        "rootfs": "read-write" if mode == "materialize" else "read-only",
        "runtime": "runc",
        "tmpfs": {
            "destination": "/tmp",
            "gid": 65532,
            "mode": "0700",
            "options": "rw,noexec,nosuid,nodev",
            "size": policy.tmpfs_bytes,
            "uid": 65532,
        },
        "user": "65532:65532",
        "uts": "private-default",
        "workdir": "/tmp",
    }
    return hashlib.sha256(
        _CONTAINER_CREATE_SPEC_DOMAIN + _canonical_json(record)
    ).hexdigest()


def normalized_terminal_container_inspect_v1(
    payload: bytes,
    *,
    runtime: VerifiedLinuxOciRuntimeV1,
    container_name: str,
    mode: str,
    execution_image_id: str | None = None,
    execution_image_label: str | None = None,
    source_root: str | Path | None = None,
    runtime_input_root: str | Path | None = None,
) -> dict[str, object]:
    """Validate the unchanged create config plus a clean terminal state."""

    pre = normalized_container_inspect_v1(
        payload,
        runtime=runtime,
        container_name=container_name,
        mode=mode,
        execution_image_id=execution_image_id,
        execution_image_label=execution_image_label,
        source_root=source_root,
        runtime_input_root=runtime_input_root,
    )
    value = _strict_json_document(payload, name="terminal container inspect")
    if type(value) is list and len(value) == 1:
        value = value[0]
    if type(value) is not dict or type(value.get("State")) is not dict:
        raise LinuxOciProviderError(
            "invalid_container", "terminal container state is unavailable"
        )
    state = value["State"]
    restart_count = value.get("RestartCount")
    if (
        state.get("Status") != "exited"
        or state.get("Running") is not False
        or state.get("Paused") is not False
        or state.get("Restarting") is not False
        or state.get("OOMKilled") is not False
        or state.get("Dead") is not False
        or state.get("Pid") != 0
        or state.get("ExitCode") != 0
        or state.get("Error") != ""
        or type(restart_count) is not int
        or restart_count != 0
    ):
        raise LinuxOciProviderError(
            "worker_failed", "container did not reach a clean terminal state"
        )
    return {
        "create": pre,
        "state": {
            "dead": False,
            "error": "",
            "exit_code": 0,
            "oom_killed": False,
            "paused": False,
            "pid": 0,
            "restart_count": 0,
            "restarting": False,
            "running": False,
            "status": "exited",
        },
    }


def container_identity_sha256_v1(
    container_id: str, *, image_id: str, mode: str
) -> str:
    if (
        type(container_id) is not str
        or _CONTAINER_ID_RE.fullmatch(container_id) is None
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "container identity is invalid"
        )
    if (
        type(image_id) is not str
        or _IMAGE_ID_RE.fullmatch(image_id) is None
        or type(mode) is not str
        or mode not in {"materialize", "execute"}
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "container image binding is invalid"
        )
    return hashlib.sha256(
        _CONTAINER_IDENTITY_DOMAIN
        + _canonical_json(
            {"container_id": container_id, "image_id": image_id, "mode": mode}
        )
    ).hexdigest()


def _runtime_command(
    runtime: VerifiedLinuxOciRuntimeV1,
    arguments: tuple[str, ...],
    *,
    stdin: bytes = b"",
    stdout_max_bytes: int = _PROBE_STDOUT_BYTES,
    stderr_max_bytes: int = _PROBE_STDERR_BYTES,
    timeout_seconds: float = _PROBE_TIMEOUT_SECONDS,
):
    if (
        type(runtime) is not VerifiedLinuxOciRuntimeV1
        or type(arguments) is not tuple
        or not arguments
        or any(type(item) is not str or not item for item in arguments)
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "OCI runtime command is invalid"
        )
    executable, env, endpoint = runtime._command_context()
    execution_path, inherited_fds, config_path = executable.execution_spec()
    try:
        return run_bounded_process_v1(
            (
                executable.path,
                f"--host={endpoint}",
                f"--config={config_path}",
                *arguments,
            ),
            stdin,
            stdout_max_bytes=stdout_max_bytes,
            stderr_max_bytes=stderr_max_bytes,
            timeout_seconds=timeout_seconds,
            env=env,
            executable=execution_path,
            inherited_fds=inherited_fds,
        )
    except BoundedProcessError as error:
        raise LinuxOciProviderError(
            "runtime_command_failed", "OCI runtime command transport failed"
        ) from error


def _clean_command_output(result: object, *, code: str, message: str) -> bytes:
    try:
        invalid = (
            result.exit_code != 0
            or result.timed_out
            or result.stdout_overflow
            or result.stderr_overflow
            or bool(result.stderr)
        )
        stdout = result.stdout
    except (AttributeError, TypeError):
        invalid = True
        stdout = b""
    if invalid or type(stdout) is not bytes:
        raise LinuxOciProviderError(code, message)
    return stdout


class _DerivedExecutionImageV1:
    __slots__ = (
        "__active",
        "__image_id",
        "__inspect_sha256",
        "__label",
        "__lock",
        "__materializer_container_id",
        "__materializer_name",
        "__runtime",
    )

    def __init__(
        self,
        token: object,
        *,
        runtime: VerifiedLinuxOciRuntimeV1,
        image_id: str,
        label: str,
        inspect_sha256: str,
        materializer_container_id: str,
        materializer_name: str,
    ) -> None:
        if token is not _RUNTIME_TOKEN:
            raise TypeError("derived execution images are provider-created")
        if (
            type(runtime) is not VerifiedLinuxOciRuntimeV1
            or type(image_id) is not str
            or _IMAGE_ID_RE.fullmatch(image_id) is None
            or image_id == runtime.execution_policy.runtime_image_id
            or type(inspect_sha256) is not str
            or _SHA256_RE.fullmatch(inspect_sha256) is None
            or type(materializer_container_id) is not str
            or _CONTAINER_ID_RE.fullmatch(materializer_container_id) is None
        ):
            raise LinuxOciProviderError(
                "invalid_image", "derived execution image identity is invalid"
            )
        self.__runtime = runtime
        self.__image_id = image_id
        self.__label = _generated_name(label, name="execution_image_label")
        self.__inspect_sha256 = inspect_sha256
        self.__materializer_container_id = materializer_container_id
        self.__materializer_name = _generated_name(
            materializer_name, name="materializer_container_name"
        )
        self.__active = True
        self.__lock = threading.Lock()

    @property
    def image_id(self) -> str:
        return self.__image_id

    @property
    def label(self) -> str:
        return self.__label

    @property
    def inspect_sha256(self) -> str:
        return self.__inspect_sha256

    @property
    def materializer_container_id(self) -> str:
        return self.__materializer_container_id

    @property
    def materializer_name(self) -> str:
        return self.__materializer_name

    @property
    def runtime(self) -> VerifiedLinuxOciRuntimeV1:
        return self.__runtime

    def _assert_active(self) -> None:
        with self.__lock:
            if not self.__active:
                raise LinuxOciProviderError(
                    "invalid_state", "derived execution image is no longer active"
                )

    def _claim_cleanup(self) -> None:
        with self.__lock:
            if not self.__active:
                raise LinuxOciProviderError(
                    "invalid_state", "derived execution image is no longer active"
                )
            self.__active = False

    def __reduce__(self):
        raise TypeError("derived execution images are not serializable")


def _strict_text_line(payload: bytes, *, pattern: re.Pattern[str], name: str) -> str:
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise LinuxOciProviderError(
            "invalid_runtime", f"{name} response is not ASCII"
        ) from None
    normalized = text.replace("\r\n", "\n")
    if "\r" in normalized:
        raise LinuxOciProviderError(
            "invalid_runtime", f"{name} response is not one line"
        )
    values = [line for line in normalized.split("\n") if line]
    if len(values) != 1:
        raise LinuxOciProviderError(
            "invalid_runtime", f"{name} response is not one line"
        )
    value = values[0]
    if pattern.fullmatch(value) is None:
        raise LinuxOciProviderError(
            "invalid_runtime", f"{name} response has an invalid identity"
        )
    return value


def _image_inspect_payload_v1(
    runtime: VerifiedLinuxOciRuntimeV1, image_id: str
) -> bytes:
    if (
        type(runtime) is not VerifiedLinuxOciRuntimeV1
        or type(image_id) is not str
        or _IMAGE_ID_RE.fullmatch(image_id) is None
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "execution image inspection identity is invalid"
        )
    result = _runtime_command(
        runtime,
        ("image", "inspect", image_id, "--format", "{{json .}}"),
    )
    return _clean_command_output(
        result,
        code="image_inspect_failed",
        message="execution image could not be inspected",
    )


def _single_image_inspect_v1(payload: bytes, *, name: str) -> dict[str, object]:
    value = _strict_json_document(payload, name=name)
    if type(value) is list and len(value) == 1:
        value = value[0]
    if type(value) is not dict:
        raise LinuxOciProviderError(
            "invalid_image", "image inspect must identify one object"
        )
    return value


def _current_base_image_v1(
    runtime: VerifiedLinuxOciRuntimeV1,
) -> dict[str, object]:
    payload = _image_inspect_payload_v1(
        runtime, runtime.execution_policy.runtime_image_id
    )
    value = _single_image_inspect_v1(payload, name="base image inspect")
    if (
        value.get("Id") != runtime.execution_policy.runtime_image_id
        or value.get("Os") != "linux"
        or value.get("Architecture") != runtime.server_arch
        or hashlib.sha256(_canonical_json(value)).hexdigest()
        != runtime.image_inspect_sha256
    ):
        raise LinuxOciProviderError(
            "runtime_changed", "pinned base image changed during worker execution"
        )
    return value


def _rootfs_layers_v1(value: dict[str, object], *, name: str) -> list[str]:
    rootfs = value.get("RootFS")
    layers = rootfs.get("Layers") if type(rootfs) is dict else None
    if (
        type(rootfs) is not dict
        or rootfs.get("Type") != "layers"
        or type(layers) is not list
        or not layers
        or any(
            type(layer) is not str or _IMAGE_ID_RE.fullmatch(layer) is None
            for layer in layers
        )
    ):
        raise LinuxOciProviderError(
            "invalid_image", f"{name} root filesystem layers are invalid"
        )
    return list(layers)


def _normalized_execution_image_inspect_v1(
    payload: bytes,
    *,
    runtime: VerifiedLinuxOciRuntimeV1,
    image_id: str,
    label: str,
    materializer_container_id: str,
    materializer_name: str,
    base_image: dict[str, object],
) -> dict[str, object]:
    if (
        type(runtime) is not VerifiedLinuxOciRuntimeV1
        or type(image_id) is not str
        or _IMAGE_ID_RE.fullmatch(image_id) is None
        or image_id == runtime.execution_policy.runtime_image_id
        or type(materializer_container_id) is not str
        or _CONTAINER_ID_RE.fullmatch(materializer_container_id) is None
        or type(base_image) is not dict
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "execution image verification input is invalid"
        )
    execution_label = _generated_name(label, name="execution_image_label")
    container_name = _generated_name(
        materializer_name, name="materializer_container_name"
    )
    value = _single_image_inspect_v1(payload, name="execution image inspect")
    config = value.get("Config")
    base_config = base_image.get("Config")
    labels = config.get("Labels") if type(config) is dict else None
    base_labels = base_config.get("Labels") if type(base_config) is dict else None
    if base_labels is None:
        base_labels = {}
    if (
        type(base_labels) is not dict
        or any(type(key) is not str or type(item) is not str for key, item in base_labels.items())
        or "vulngym.e3.container" in base_labels
        or "vulngym.e3.execution" in base_labels
    ):
        raise LinuxOciProviderError(
            "invalid_image", "base image labels cannot bind a derived execution"
        )
    expected_labels = dict(base_labels)
    expected_labels.update(
        {
            "vulngym.e3.container": container_name,
            "vulngym.e3.execution": execution_label,
        }
    )
    expected_labels.update(_SCRUBBED_DERIVED_IMAGE_LABELS)
    base_layers = _rootfs_layers_v1(base_image, name="base image")
    derived_layers = _rootfs_layers_v1(value, name="execution image")
    repo_tags = value.get("RepoTags")
    repo_digests = value.get("RepoDigests")
    if (
        value.get("Id") != image_id
        or value.get("Id") == runtime.execution_policy.runtime_image_id
        or value.get("Os") != "linux"
        or value.get("Architecture") != runtime.server_arch
        or repo_tags not in (None, [])
        or repo_digests not in (None, [])
        or (
            value.get("Parent") not in (None, "", runtime.execution_policy.runtime_image_id)
        )
        or (
            value.get("Container") not in (None, "", materializer_container_id)
        )
        or type(config) is not dict
        or labels != expected_labels
        or config.get("Entrypoint")
        != [OCI_PYTHON, "-I", "-B", "-m", OCI_WORKER_MODULE]
        or config.get("Cmd") != ["materialize"]
        or config.get("User") != "65532:65532"
        or config.get("WorkingDir") != "/tmp"
        or config.get("Hostname") not in (None, "", "vulngym-materializer")
        or config.get("Volumes") not in (None, {})
        or config.get("ExposedPorts") not in (None, {})
        or len(derived_layers) != len(base_layers) + 1
        or derived_layers[:-1] != base_layers
    ):
        raise LinuxOciProviderError(
            "invalid_image", "derived execution image binding is invalid"
        )
    return {
        "architecture": runtime.server_arch,
        "base_image_id": runtime.execution_policy.runtime_image_id,
        "base_layer_count": len(base_layers),
        "container_id": materializer_container_id,
        "execution_image_id": image_id,
        "execution_label_sha256": hashlib.sha256(
            execution_label.encode("ascii")
        ).hexdigest(),
        "new_layer": derived_layers[-1],
        "os": "linux",
        "repo_digests": [],
        "repo_tags": [],
    }


def _find_owned_execution_image_ids_v1(
    runtime: VerifiedLinuxOciRuntimeV1, *, label: str
) -> tuple[str, ...]:
    execution_label = _generated_name(label, name="execution_image_label")
    result = _runtime_command(
        runtime,
        (
            "image",
            "ls",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"label=vulngym.e3.execution={execution_label}",
        ),
        stdout_max_bytes=1024,
    )
    stdout = _clean_command_output(
        result,
        code="cleanup_uncertain",
        message="execution image presence is uncertain",
    )
    if not stdout:
        return ()
    try:
        text = stdout.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "execution image presence is uncertain",
            runtime_uncertain=True,
        ) from None
    if not text.endswith("\n") or "\r" in text:
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "execution image presence is uncertain",
            runtime_uncertain=True,
        )
    identities = tuple(text[:-1].split("\n"))
    if (
        not identities
        or len(identities) != len(set(identities))
        or any(_IMAGE_ID_RE.fullmatch(item) is None for item in identities)
    ):
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "execution image presence is uncertain",
            runtime_uncertain=True,
        )
    return identities


def _force_remove_execution_image_id_v1(
    runtime: VerifiedLinuxOciRuntimeV1,
    *,
    image_id: str,
    label: str,
    confirm_label_absent: bool = True,
) -> None:
    if (
        type(runtime) is not VerifiedLinuxOciRuntimeV1
        or type(image_id) is not str
        or _IMAGE_ID_RE.fullmatch(image_id) is None
        or image_id == runtime.execution_policy.runtime_image_id
        or type(confirm_label_absent) is not bool
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "execution image cleanup identity is invalid"
        )
    execution_label = _generated_name(label, name="execution_image_label")
    result = _runtime_command(
        runtime,
        ("image", "rm", "--force", image_id),
        stdout_max_bytes=1024 * 1024,
        timeout_seconds=60.0,
    )
    try:
        stdout = _clean_command_output(
            result,
            code="cleanup_uncertain",
            message="execution image cleanup is uncertain",
        )
        stdout.decode("ascii", errors="strict")
    except (LinuxOciProviderError, UnicodeDecodeError) as error:
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "execution image cleanup is uncertain",
            runtime_uncertain=True,
        ) from error
    if confirm_label_absent and _find_owned_execution_image_ids_v1(
        runtime, label=execution_label
    ):
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "execution image removal could not be confirmed",
            runtime_uncertain=True,
        )


def _remove_execution_image_v1(image: _DerivedExecutionImageV1) -> None:
    if type(image) is not _DerivedExecutionImageV1:
        raise LinuxOciProviderError(
            "invalid_argument", "derived execution image handle is invalid"
        )
    image._claim_cleanup()
    _force_remove_execution_image_id_v1(
        image.runtime, image_id=image.image_id, label=image.label
    )


def _verify_execution_image_v1(image: _DerivedExecutionImageV1) -> None:
    if type(image) is not _DerivedExecutionImageV1:
        raise LinuxOciProviderError(
            "invalid_argument", "derived execution image handle is invalid"
        )
    image._assert_active()
    base = _current_base_image_v1(image.runtime)
    payload = _image_inspect_payload_v1(image.runtime, image.image_id)
    _normalized_execution_image_inspect_v1(
        payload,
        runtime=image.runtime,
        image_id=image.image_id,
        label=image.label,
        materializer_container_id=image.materializer_container_id,
        materializer_name=image.materializer_name,
        base_image=base,
    )
    value = _single_image_inspect_v1(payload, name="execution image inspect")
    if hashlib.sha256(_canonical_json(value)).hexdigest() != image.inspect_sha256:
        raise LinuxOciProviderError(
            "runtime_changed", "derived execution image changed before execution"
        )


def _commit_execution_image_v1(
    container: _WorkerContainerV1,
) -> _DerivedExecutionImageV1:
    if type(container) is not _WorkerContainerV1 or container.mode != "materialize":
        raise LinuxOciProviderError(
            "invalid_argument", "materializer container handle is invalid"
        )
    container._assert_active()
    runtime = container.runtime
    base = _current_base_image_v1(runtime)
    label = f"vulngym-e3-{secrets.token_hex(16)}"
    candidate_id: str | None = None
    command_attempted = False
    try:
        command_attempted = True
        commit_changes: list[str] = [
            "--change",
            f"LABEL vulngym.e3.execution={label}",
        ]
        for key in sorted(_SCRUBBED_DERIVED_IMAGE_LABELS):
            commit_changes.extend(("--change", f"LABEL {key}="))
        result = _runtime_command(
            runtime,
            (
                "container",
                "commit",
                *commit_changes,
                container.container_id,
            ),
            stdout_max_bytes=256,
            timeout_seconds=60.0,
        )
        stdout = _clean_command_output(
            result,
            code="image_commit_failed",
            message="derived execution image was not committed",
        )
        candidate_id = _strict_text_line(
            stdout, pattern=_IMAGE_ID_RE, name="image commit"
        )
        payload = _image_inspect_payload_v1(runtime, candidate_id)
        _normalized_execution_image_inspect_v1(
            payload,
            runtime=runtime,
            image_id=candidate_id,
            label=label,
            materializer_container_id=container.container_id,
            materializer_name=container.name,
            base_image=base,
        )
        value = _single_image_inspect_v1(payload, name="execution image inspect")
        return _DerivedExecutionImageV1(
            _RUNTIME_TOKEN,
            runtime=runtime,
            image_id=candidate_id,
            label=label,
            inspect_sha256=hashlib.sha256(_canonical_json(value)).hexdigest(),
            materializer_container_id=container.container_id,
            materializer_name=container.name,
        )
    except BaseException as primary:
        try:
            found = list(_find_owned_execution_image_ids_v1(runtime, label=label))
            if candidate_id is not None and candidate_id not in found:
                found.append(candidate_id)
            if command_attempted and not found:
                raise LinuxOciProviderError(
                    "cleanup_uncertain",
                    "derived execution image creation could not be reconciled",
                    runtime_uncertain=True,
                )
            for image_id in found:
                _force_remove_execution_image_id_v1(
                    runtime,
                    image_id=image_id,
                    label=label,
                    confirm_label_absent=False,
                )
            if _find_owned_execution_image_ids_v1(runtime, label=label):
                raise LinuxOciProviderError(
                    "cleanup_uncertain",
                    "derived execution image creation cleanup is uncertain",
                    runtime_uncertain=True,
                )
        except BaseException as cleanup_error:
            raise LinuxOciProviderError(
                "cleanup_uncertain",
                "derived execution image creation cleanup is uncertain",
                runtime_uncertain=True,
            ) from primary
        raise primary


class _WorkerContainerV1:
    __slots__ = (
        "__active",
        "__container_id",
        "__execution_image_id",
        "__execution_image_label",
        "__lock",
        "__mode",
        "__name",
        "__pre_inspect",
        "__pre_inspect_sha256",
        "__runtime",
        "__runtime_input_root",
        "__source_root",
    )

    def __init__(
        self,
        token: object,
        *,
        runtime: VerifiedLinuxOciRuntimeV1,
        container_id: str,
        name: str,
        mode: str,
        execution_image_id: str,
        execution_image_label: str | None,
        source_root: str | Path | None,
        runtime_input_root: str | Path | None,
        pre_inspect: dict[str, object],
    ) -> None:
        if token is not _RUNTIME_TOKEN:
            raise TypeError("worker containers are provider-created")
        if mode == "materialize":
            normalized_source_root = _safe_source_path(source_root)
            normalized_runtime_input_root = _safe_source_path(runtime_input_root)
        elif source_root is None and runtime_input_root is None:
            normalized_source_root = None
            normalized_runtime_input_root = None
        else:
            raise LinuxOciProviderError(
                "invalid_container", "worker container source binding is invalid"
            )
        if (
            type(container_id) is not str
            or _CONTAINER_ID_RE.fullmatch(container_id) is None
            or type(runtime) is not VerifiedLinuxOciRuntimeV1
            or type(mode) is not str
            or mode not in {"materialize", "execute"}
            or type(execution_image_id) is not str
            or _IMAGE_ID_RE.fullmatch(execution_image_id) is None
            or (
                mode == "materialize"
                and (
                    execution_image_id != runtime.execution_policy.runtime_image_id
                    or execution_image_label is not None
                )
            )
            or (
                mode == "execute"
                and (
                    execution_image_id == runtime.execution_policy.runtime_image_id
                    or type(execution_image_label) is not str
                    or _NAME_RE.fullmatch(execution_image_label) is None
                )
            )
            or type(pre_inspect) is not dict
            or pre_inspect.get("container_id") != container_id
            or pre_inspect.get("image_id") != execution_image_id
            or pre_inspect.get("mode") != mode
        ):
            raise LinuxOciProviderError(
                "invalid_container", "worker container identity is invalid"
            )
        self.__runtime = runtime
        self.__container_id = container_id
        self.__name = _generated_name(name, name="container_name")
        self.__mode = mode
        self.__execution_image_id = execution_image_id
        self.__execution_image_label = execution_image_label
        self.__source_root = normalized_source_root
        self.__runtime_input_root = normalized_runtime_input_root
        self.__pre_inspect = json.loads(_canonical_json(pre_inspect))
        self.__pre_inspect_sha256 = container_inspect_sha256_v1(pre_inspect)
        self.__active = True
        self.__lock = threading.Lock()

    @property
    def runtime(self) -> VerifiedLinuxOciRuntimeV1:
        return self.__runtime

    @property
    def container_id(self) -> str:
        return self.__container_id

    @property
    def name(self) -> str:
        return self.__name

    @property
    def execution_image_id(self) -> str:
        return self.__execution_image_id

    @property
    def execution_image_label(self) -> str | None:
        return self.__execution_image_label

    @property
    def source_root(self) -> str | None:
        return self.__source_root

    @property
    def runtime_input_root(self) -> str | None:
        return self.__runtime_input_root

    @property
    def mode(self) -> str:
        return self.__mode

    @property
    def pre_inspect_sha256(self) -> str:
        return self.__pre_inspect_sha256

    @property
    def pre_inspect(self) -> dict[str, object]:
        return json.loads(_canonical_json(self.__pre_inspect))

    def _assert_active(self) -> None:
        with self.__lock:
            if not self.__active:
                raise LinuxOciProviderError(
                    "invalid_state", "worker container is no longer active"
                )

    def _claim_cleanup(self) -> None:
        with self.__lock:
            if not self.__active:
                raise LinuxOciProviderError(
                    "invalid_state", "worker container is no longer active"
                )
            self.__active = False

    def __reduce__(self):
        raise TypeError("worker containers are not serializable")


def _container_inspect_payload_v1(
    runtime: VerifiedLinuxOciRuntimeV1, identity: str
) -> bytes:
    result = _runtime_command(
        runtime,
        ("container", "inspect", identity, "--format", "{{json .}}"),
    )
    return _clean_command_output(
        result,
        code="container_inspect_failed",
        message="worker container could not be inspected",
    )


def _create_worker_container_v1(
    runtime: VerifiedLinuxOciRuntimeV1,
    *,
    mode: str,
    execution_image: _DerivedExecutionImageV1 | None = None,
    source_root: str | Path | None = None,
    runtime_input_root: str | Path | None = None,
) -> _WorkerContainerV1:
    if (
        type(runtime) is not VerifiedLinuxOciRuntimeV1
        or type(mode) is not str
        or mode not in {"materialize", "execute"}
        or (mode == "materialize" and execution_image is not None)
        or (mode == "execute" and type(execution_image) is not _DerivedExecutionImageV1)
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "worker container creation input is invalid"
        )
    if execution_image is not None:
        execution_image._assert_active()
        if execution_image.runtime is not runtime:
            raise LinuxOciProviderError(
                "invalid_argument", "execution image belongs to another runtime"
            )
        execution_image_id = execution_image.image_id
        execution_image_label = execution_image.label
    else:
        execution_image_id = None
        execution_image_label = None
    if mode == "materialize":
        source_root = _safe_source_path(source_root)
        runtime_input_root = _safe_source_path(runtime_input_root)
    name = f"vulngym-e3-{secrets.token_hex(16)}"
    argv = build_worker_container_create_argv_v1(
        runtime,
        container_name=name,
        mode=mode,
        execution_image_id=execution_image_id,
        source_root=source_root,
        runtime_input_root=runtime_input_root,
    )
    try:
        result = _runtime_command(
            runtime, argv[1:], stdout_max_bytes=256, timeout_seconds=60.0
        )
        stdout = _clean_command_output(
            result,
            code="container_create_failed",
            message="worker container was not created cleanly",
        )
        container_id = _strict_text_line(
            stdout, pattern=_CONTAINER_ID_RE, name="container create"
        )
        inspect_payload = _container_inspect_payload_v1(runtime, container_id)
        normalized = normalized_container_inspect_v1(
            inspect_payload,
            runtime=runtime,
            container_name=name,
            mode=mode,
            execution_image_id=execution_image_id,
            execution_image_label=execution_image_label,
            source_root=source_root,
            runtime_input_root=runtime_input_root,
        )
        if normalized["container_id"] != container_id:
            raise LinuxOciProviderError(
                "invalid_container", "created container identity changed"
            )
    except BaseException as primary:
        try:
            found = _find_owned_container_id_v1(runtime, name=name)
            if found is not None:
                _force_remove_container_id_v1(runtime, found)
        except BaseException as cleanup_error:
            raise LinuxOciProviderError(
                "cleanup_uncertain",
                "worker container creation cleanup is uncertain",
                runtime_uncertain=True,
            ) from primary
        raise primary
    return _WorkerContainerV1(
        _RUNTIME_TOKEN,
        runtime=runtime,
        container_id=container_id,
        name=name,
        mode=mode,
        execution_image_id=(
            runtime.execution_policy.runtime_image_id
            if execution_image_id is None
            else execution_image_id
        ),
        execution_image_label=execution_image_label,
        source_root=source_root,
        runtime_input_root=runtime_input_root,
        pre_inspect=normalized,
    )


def _find_owned_container_id_v1(
    runtime: VerifiedLinuxOciRuntimeV1, *, name: str
) -> str | None:
    container = _generated_name(name, name="container_name")
    result = _runtime_command(
        runtime,
        (
            "container",
            "ls",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"name=^/{container}$",
        ),
        stdout_max_bytes=256,
    )
    stdout = _clean_command_output(
        result,
        code="cleanup_uncertain",
        message="worker container presence is uncertain",
    )
    if not stdout:
        return None
    return _strict_text_line(stdout, pattern=_CONTAINER_ID_RE, name="container lookup")


def _start_worker_container_v1(container: _WorkerContainerV1):
    if type(container) is not _WorkerContainerV1:
        raise LinuxOciProviderError(
            "invalid_argument", "worker container handle is invalid"
        )
    container._assert_active()
    policy = container.runtime.execution_policy
    return _runtime_command(
        container.runtime,
        ("container", "start", "--attach", container.container_id),
        stdout_max_bytes=policy.stdout_max_bytes,
        stderr_max_bytes=policy.stderr_max_bytes,
        timeout_seconds=float(policy.wall_time_seconds),
    )


def _terminal_worker_container_v1(
    container: _WorkerContainerV1,
) -> tuple[dict[str, object], str]:
    if type(container) is not _WorkerContainerV1:
        raise LinuxOciProviderError(
            "invalid_argument", "worker container handle is invalid"
        )
    container._assert_active()
    payload = _container_inspect_payload_v1(
        container.runtime, container.container_id
    )
    terminal = normalized_terminal_container_inspect_v1(
        payload,
        runtime=container.runtime,
        container_name=container.name,
        mode=container.mode,
        execution_image_id=(
            None if container.mode == "materialize" else container.execution_image_id
        ),
        execution_image_label=container.execution_image_label,
        source_root=container.source_root,
        runtime_input_root=container.runtime_input_root,
    )
    if terminal["create"] != container.pre_inspect:
        raise LinuxOciProviderError(
            "container_changed", "worker container configuration changed after launch"
        )
    return terminal, hashlib.sha256(_canonical_json(terminal)).hexdigest()


def _container_diff_v1(container: _WorkerContainerV1) -> tuple[str, bool]:
    if type(container) is not _WorkerContainerV1:
        raise LinuxOciProviderError(
            "invalid_argument", "worker container handle is invalid"
        )
    container._assert_active()
    result = _runtime_command(
        container.runtime,
        ("container", "diff", container.container_id),
        stdout_max_bytes=1024 * 1024,
    )
    stdout = _clean_command_output(
        result,
        code="container_diff_failed",
        message="worker container filesystem diff could not be verified",
    )
    if container.mode == "execute":
        if stdout != b"":
            raise LinuxOciProviderError(
                "container_changed", "execution container changed its image filesystem"
            )
        return hashlib.sha256(b"").hexdigest(), True
    try:
        text = stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise LinuxOciProviderError(
            "container_changed", "materializer container diff is not canonical"
        ) from None
    if not text or not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise LinuxOciProviderError(
            "container_changed", "materializer container diff is not canonical"
        )
    raw_lines = text[:-1].split("\n")
    if len(raw_lines) != len(set(raw_lines)):
        raise LinuxOciProviderError(
            "container_changed", "materializer container diff repeats a path"
        )
    mount_markers = {"A /input-runtime", "A /input-source"}
    generation_lines: list[str] = []
    for line in raw_lines:
        if line in mount_markers:
            continue
        if (
            len(line) < 4
            or line[0] not in {"A", "C"}
            or line[1] != " "
            or not (line[2:] == OCI_GENERATION_ROOT or line[2:].startswith(OCI_GENERATION_ROOT + "/"))
        ):
            raise LinuxOciProviderError(
                "container_changed",
                "materializer changed a path outside the generation root",
            )
        generation_lines.append(line)
    if not generation_lines:
        raise LinuxOciProviderError(
            "container_changed", "materializer did not create a generation layer"
        )
    normalized = {
        "generation_changes": sorted(generation_lines),
        "mount_markers": sorted(set(raw_lines).intersection(mount_markers)),
    }
    return hashlib.sha256(
        b"VulnGym materializer container diff v1\0" + _canonical_json(normalized)
    ).hexdigest(), False


def _force_remove_container_id_v1(
    runtime: VerifiedLinuxOciRuntimeV1, container_id: str
) -> None:
    if (
        type(runtime) is not VerifiedLinuxOciRuntimeV1
        or type(container_id) is not str
        or _CONTAINER_ID_RE.fullmatch(container_id) is None
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "container cleanup identity is invalid"
        )
    result = _runtime_command(
        runtime,
        ("container", "rm", "--force", container_id),
        stdout_max_bytes=256,
    )
    try:
        stdout = _clean_command_output(
            result,
            code="cleanup_uncertain",
            message="worker container cleanup is uncertain",
        )
        removed = _strict_text_line(
            stdout, pattern=_CONTAINER_ID_RE, name="container cleanup"
        )
    except LinuxOciProviderError as error:
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "worker container cleanup is uncertain",
            runtime_uncertain=True,
        ) from error
    if removed != container_id:
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "worker container cleanup identity is uncertain",
            runtime_uncertain=True,
        )
    check = _runtime_command(
        runtime,
        (
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"id={container_id}",
        ),
        stdout_max_bytes=256,
    )
    try:
        invalid = (
            check.exit_code != 0
            or check.timed_out
            or check.stdout_overflow
            or check.stderr_overflow
            or bool(check.stderr)
            or bool(check.stdout)
        )
    except (AttributeError, TypeError):
        invalid = True
    if invalid:
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "worker container removal could not be confirmed",
            runtime_uncertain=True,
        )


def _remove_worker_container_v1(container: _WorkerContainerV1) -> None:
    if type(container) is not _WorkerContainerV1:
        raise LinuxOciProviderError(
            "invalid_argument", "worker container handle is invalid"
        )
    container._claim_cleanup()
    _force_remove_container_id_v1(container.runtime, container.container_id)


@dataclass(frozen=True, slots=True)
class _CompletedContainerStepV1:
    stdout: bytes
    stderr: bytes
    pre_inspect_sha256: str
    post_inspect_sha256: str
    container_identity_sha256: str
    diff_sha256: str
    diff_empty: bool


def _worker_protocol_error_code_v1(result: object, *, mode: str) -> str | None:
    try:
        if (
            type(mode) is not str
            or mode not in {"materialize", "execute"}
            or result.exit_code != 2
            or result.timed_out
            or result.stdout_overflow
            or result.stderr_overflow
            or result.stdout != b""
            or type(result.stderr) is not bytes
        ):
            return None
        value = _strict_json_document(result.stderr, name="worker error")
    except (AttributeError, LinuxOciProviderError, TypeError, ValueError):
        return None
    if (
        type(value) is not dict
        or set(value) != {"code", "contract_version", "kind", "mode"}
        or type(value.get("contract_version")) is not int
        or value.get("contract_version") != PROTOCOL_VERSION
        or type(value.get("kind")) is not str
        or value.get("kind") != WORKER_ERROR_KIND
        or type(value.get("mode")) is not str
        or value.get("mode") != mode
        or type(value.get("code")) is not str
        or _WORKER_ERROR_CODE_RE.fullmatch(value["code"]) is None
        or result.stderr != _canonical_json(value) + b"\n"
    ):
        return None
    return value["code"]


def _run_container_step_v1(
    container: _WorkerContainerV1,
) -> _CompletedContainerStepV1:
    """Start and verify one container while retaining it for explicit cleanup."""

    result = _start_worker_container_v1(container)
    worker_error_code = _worker_protocol_error_code_v1(
        result, mode=container.mode
    )
    if worker_error_code is not None:
        raise LinuxOciProviderError(
            "worker_failed",
            f"worker container rejected its {container.mode} boundary "
            f"({worker_error_code})",
        )
    if (
        result.exit_code != 0
        or result.timed_out
        or result.stdout_overflow
        or result.stderr_overflow
        or result.stderr
    ):
        raise LinuxOciProviderError(
            "worker_failed",
            "worker container did not produce a clean result",
        )
    _terminal, terminal_sha256 = _terminal_worker_container_v1(container)
    diff_sha256, diff_empty = _container_diff_v1(container)
    return _CompletedContainerStepV1(
        stdout=result.stdout,
        stderr=result.stderr,
        pre_inspect_sha256=container.pre_inspect_sha256,
        post_inspect_sha256=terminal_sha256,
        container_identity_sha256=container_identity_sha256_v1(
            container.container_id,
            image_id=container.execution_image_id,
            mode=container.mode,
        ),
        diff_sha256=diff_sha256,
        diff_empty=diff_empty,
    )


def _run_clean_container_step_v1(
    container: _WorkerContainerV1,
) -> _CompletedContainerStepV1:
    """Start, verify, and remove one container; removal closes before return."""

    primary: BaseException | None = None
    completed: _CompletedContainerStepV1 | None = None
    try:
        completed = _run_container_step_v1(container)
    except BaseException as error:
        primary = error
    try:
        _remove_worker_container_v1(container)
    except BaseException as cleanup_error:
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "worker container cleanup did not close",
            runtime_uncertain=True,
        ) from (primary if primary is not None else cleanup_error)
    if primary is not None:
        raise primary
    if completed is None:
        raise LinuxOciProviderError(
            "provider_failed", "worker container result is unavailable"
        )
    return completed


def _write_runtime_input_file_v1(path: Path, payload: bytes) -> None:
    if type(path) is not type(Path()) or type(payload) is not bytes:
        raise LinuxOciProviderError(
            "invalid_argument", "runtime input file is invalid"
        )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            offset = 0
            while offset < len(payload):
                count = os.write(descriptor, payload[offset:])
                if count < 1:
                    raise OSError("short runtime input write")
                offset += count
            os.fsync(descriptor)
            state = os.fstat(descriptor)
            if (
                not stat.S_ISREG(state.st_mode)
                or state.st_size != len(payload)
                or state.st_nlink != 1
            ):
                raise OSError("runtime input identity changed")
        finally:
            os.close(descriptor)
        if path.read_bytes() != payload:
            raise OSError("runtime input readback changed")
    except OSError as error:
        raise LinuxOciProviderError(
            "runtime_input_failed", "runtime input could not be materialized"
        ) from error


def _build_runtime_input_v1(
    launch: object,
    policy: ExecutionPolicyBindingV1,
    d2_replay: OciReplayConfigV1,
    d3_replay: OciReplayConfigV1,
) -> tuple[OciWorkerRequestV1, dict[str, bytes]]:
    try:
        task_plan = launch.task_plan
        task = launch.task
        handoff_wire = launch.handoff_payload
        handoff_sha256 = launch.handoff_sha256
        handoff_wire_sha256 = launch.handoff_wire_sha256
    except (AttributeError, TypeError):
        raise LinuxOciProviderError(
            "invalid_launch", "worker launch is incomplete"
        ) from None
    if (
        type(d2_replay) is not OciReplayConfigV1
        or type(d3_replay) is not OciReplayConfigV1
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "replay configurations must have exact types"
        )
    try:
        d2_wire = d2_replay.to_bytes()
        d2 = OciReplayConfigV1.from_bytes(d2_wire)
        d3_wire = d3_replay.to_bytes()
        d3 = OciReplayConfigV1.from_bytes(d3_wire)
    except (AttributeError, OciWorkerEntryError, TypeError, ValueError):
        raise LinuxOciProviderError(
            "invalid_config", "replay configurations did not normalize"
        ) from None
    if (
        task_plan.execution_policy_sha256 != policy.policy_sha256
        or task_plan.task_id != task.task_id
        or task_plan.snapshot_id != task.snapshot_id
        or task_plan.snapshot_manifest_sha256 != task.snapshot_manifest_sha256
        or task_plan.snapshot_content_root != task.snapshot_content_root
        or task_plan.handoff_sha256 != handoff_sha256
        or task_plan.handoff_wire_sha256 != handoff_wire_sha256
        or hashlib.sha256(handoff_wire).hexdigest() != handoff_wire_sha256
        or d2.task_id != task.task_id
        or d2.role != "d2"
        or d2.backend_id != policy.d2_backend_id
        or d2.model_id != policy.d2_model_id
        or d2.config_sha256 != policy.d2_config_sha256
        or d3.task_id != task.task_id
        or d3.role != "d3"
        or d3.backend_id != policy.d3_backend_id
        or d3.model_id != policy.d3_model_id
        or d3.config_sha256 != policy.d3_config_sha256
    ):
        raise LinuxOciProviderError(
            "policy_mismatch", "worker runtime input is detached from its policy"
        )
    request = OciWorkerRequestV1(
        task_id=task.task_id,
        snapshot_id=task.snapshot_id,
        snapshot_manifest_sha256=task.snapshot_manifest_sha256,
        snapshot_content_root=task.snapshot_content_root,
        handoff_sha256=handoff_sha256,
        handoff_wire_sha256=handoff_wire_sha256,
        d2_replay_sha256=d2.config_sha256,
        d2_replay_wire_sha256=d2.wire_sha256,
        d3_replay_sha256=d3.config_sha256,
        d3_replay_wire_sha256=d3.wire_sha256,
    )
    return request, {
        REQUEST_FILENAME: request.to_bytes(),
        HANDOFF_FILENAME: handoff_wire,
        D2_REPLAY_FILENAME: d2_wire,
        D3_REPLAY_FILENAME: d3_wire,
    }


def _write_runtime_input_directory_v1(
    root: Path, wires: dict[str, bytes]
) -> None:
    if type(root) is not type(Path()) or type(wires) is not dict:
        raise LinuxOciProviderError(
            "invalid_argument", "runtime input directory is invalid"
        )
    before = os.lstat(root)
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise LinuxOciProviderError(
            "runtime_input_failed", "runtime input root is unsafe"
        )
    expected = {
        REQUEST_FILENAME,
        HANDOFF_FILENAME,
        D2_REPLAY_FILENAME,
        D3_REPLAY_FILENAME,
    }
    if set(wires) != expected:
        raise LinuxOciProviderError(
            "invalid_argument", "runtime input set is incomplete"
        )
    for name in sorted(expected):
        _write_runtime_input_file_v1(root / name, wires[name])
    try:
        bundle = _load_runtime_bundle(root)
    except (OciWorkerEntryError, OSError, TypeError, ValueError) as error:
        raise LinuxOciProviderError(
            "runtime_input_failed", "runtime input readback did not close"
        ) from error
    if bundle.request.to_bytes() != wires[REQUEST_FILENAME]:
        raise LinuxOciProviderError(
            "runtime_input_failed", "runtime input request changed during readback"
        )
    after = os.lstat(root)
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
        raise LinuxOciProviderError(
            "runtime_input_failed", "runtime input root changed during creation"
        )


def _plain_input_node_v1(path: Path, *, directory: bool) -> os.stat_result:
    if type(path) is not type(Path()):
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input path is invalid"
        )
    try:
        value = os.lstat(path)
    except OSError:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input is unavailable"
        ) from None
    attributes = getattr(value, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    invalid = (
        stat.S_ISLNK(value.st_mode)
        or bool(attributes & reparse)
        or (directory and not stat.S_ISDIR(value.st_mode))
        or (
            not directory
            and (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1)
        )
    )
    if invalid:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input identity is unsafe"
        )
    return value


def _stable_input_identity_v1(value: os.stat_result) -> tuple[object, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        getattr(value, "st_mtime_ns", None),
        getattr(value, "st_ctime_ns", None),
        stat.S_IMODE(value.st_mode),
    )


def _make_private_input_directory_v1(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except OSError as error:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input directory could not be created"
        ) from error
    state = _plain_input_node_v1(path, directory=True)
    if os.name == "posix" and stat.S_IMODE(state.st_mode) != 0o700:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input directory is not private"
        )


def _chmod_input_node_v1(path: Path, mode: int, *, directory: bool) -> None:
    before = _plain_input_node_v1(path, directory=directory)
    expected_identity = (before.st_dev, before.st_ino)
    if os.name == "posix":
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        if directory:
            flags |= getattr(os, "O_DIRECTORY", 0)
        descriptor = -1
        try:
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            if (
                (opened.st_dev, opened.st_ino) != expected_identity
                or (directory and not stat.S_ISDIR(opened.st_mode))
                or (
                    not directory
                    and (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1)
                )
            ):
                raise OSError("materializer input changed before chmod")
            os.fchmod(descriptor, mode)
            finished = os.fstat(descriptor)
            if (
                (finished.st_dev, finished.st_ino) != expected_identity
                or stat.S_IMODE(finished.st_mode) != mode
            ):
                raise OSError("materializer input chmod did not close")
        except OSError as error:
            raise LinuxOciProviderError(
                "runtime_input_failed", "materializer input mode could not be fixed"
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    else:
        try:
            os.chmod(path, mode)
        except OSError as error:
            raise LinuxOciProviderError(
                "runtime_input_failed", "materializer input mode could not be fixed"
            ) from error
    after = _plain_input_node_v1(path, directory=directory)
    if (after.st_dev, after.st_ino) != expected_identity:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input changed during chmod"
        )


def _sync_input_directory_v1(path: Path) -> None:
    if os.name != "posix":
        return
    before = _plain_input_node_v1(path, directory=True)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
        )
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise OSError("materializer input directory changed before sync")
        os.fsync(descriptor)
        finished = os.fstat(descriptor)
        if (finished.st_dev, finished.st_ino) != (before.st_dev, before.st_ino):
            raise OSError("materializer input directory changed during sync")
    except OSError as error:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input directory did not sync"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _source_tree_identity_v1(
    root: Path,
    handoff: WorkerHandoffV1,
    *,
    require_container_readable: bool,
) -> tuple[tuple[object, ...], ...]:
    if type(root) is not type(Path()) or type(handoff) is not WorkerHandoffV1:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer source binding is invalid"
        )
    try:
        _inventory_source(root, handoff)
    except (OciWorkerEntryError, OSError, TypeError, ValueError) as error:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer source inventory did not verify"
        ) from error
    records: list[tuple[object, ...]] = []
    directories = tuple(
        sorted(_manifest_directories(handoff), key=lambda item: (item.count("/"), item))
    )
    for relative in ("", *directories):
        path = root if not relative else root.joinpath(*relative.split("/"))
        state = _plain_input_node_v1(path, directory=True)
        if (
            require_container_readable
            and os.name == "posix"
            and stat.S_IMODE(state.st_mode) != 0o555
        ):
            raise LinuxOciProviderError(
                "runtime_input_failed", "materializer source directory is not read-only"
            )
        records.append(("D", relative, *_stable_input_identity_v1(state)))
    for record in handoff.files:
        path = root.joinpath(*record.path.split("/"))
        state = _plain_input_node_v1(path, directory=False)
        if (
            state.st_size != record.size
            or (
                require_container_readable
                and os.name == "posix"
                and stat.S_IMODE(state.st_mode) != 0o444
            )
        ):
            raise LinuxOciProviderError(
                "runtime_input_failed", "materializer source file state is invalid"
            )
        records.append(("F", record.path, *_stable_input_identity_v1(state)))
    return tuple(records)


def _open_posix_directory_chain_v1(
    root: Path, components: tuple[str, ...]
) -> tuple[int, ...]:
    if os.name != "posix" or type(root) is not type(Path()):
        raise LinuxOciProviderError(
            "runtime_input_failed", "descriptor-relative source access is unavailable"
        )
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise LinuxOciProviderError(
            "runtime_input_failed", "descriptor-relative source access is unavailable"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow | directory
    guards: list[int] = []
    try:
        root_before = _plain_input_node_v1(root, directory=True)
        root_descriptor = os.open(root, flags)
        guards.append(root_descriptor)
        root_opened = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_opened.st_mode)
            or (root_opened.st_dev, root_opened.st_ino)
            != (root_before.st_dev, root_before.st_ino)
        ):
            raise OSError("materializer input root changed before binding")
        for component in components:
            if (
                type(component) is not str
                or not component
                or component in {".", ".."}
                or "/" in component
                or "\\" in component
            ):
                raise OSError("materializer input path component is invalid")
            descriptor = -1
            try:
                descriptor = os.open(component, flags, dir_fd=guards[-1])
                opened = os.fstat(descriptor)
                if not stat.S_ISDIR(opened.st_mode):
                    raise OSError("materializer input ancestor is not a directory")
                guards.append(descriptor)
                descriptor = -1
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        return tuple(guards)
    except (LinuxOciProviderError, OSError) as error:
        for descriptor in reversed(guards):
            os.close(descriptor)
        if isinstance(error, LinuxOciProviderError):
            raise
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input directory chain is unsafe"
        ) from error


def _copy_source_record_v1(source_root: Path, target_root: Path, record) -> None:
    relative = record.path
    source_root_before = _plain_input_node_v1(source_root, directory=True)
    source_directories: list[tuple[Path, tuple[object, ...]]] = []
    current = source_root
    for component in relative.split("/")[:-1]:
        current = current / component
        source_directories.append(
            (
                current,
                _stable_input_identity_v1(
                    _plain_input_node_v1(current, directory=True)
                ),
            )
        )
    source = source_root.joinpath(*relative.split("/"))
    target = target_root.joinpath(*relative.split("/"))
    source_before = _plain_input_node_v1(source, directory=False)
    if source_before.st_size != record.size:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer source file size changed"
        )
    source_descriptor = -1
    target_descriptor = -1
    source_guards: tuple[int, ...] = ()
    target_guards: tuple[int, ...] = ()
    digest = hashlib.sha256()
    consumed = 0
    try:
        source_flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        target_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        components = tuple(relative.split("/"))
        if os.name == "posix":
            source_guards = _open_posix_directory_chain_v1(
                source_root, components[:-1]
            )
            target_guards = _open_posix_directory_chain_v1(
                target_root, components[:-1]
            )
            source_descriptor = os.open(
                components[-1], source_flags, dir_fd=source_guards[-1]
            )
            target_descriptor = os.open(
                components[-1],
                target_flags,
                0o600,
                dir_fd=target_guards[-1],
            )
        else:
            source_descriptor = os.open(source, source_flags)
            target_descriptor = os.open(target, target_flags, 0o600)
        source_opened = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(source_opened.st_mode)
            or source_opened.st_nlink != 1
            or (source_opened.st_dev, source_opened.st_ino)
            != (source_before.st_dev, source_before.st_ino)
            or source_opened.st_size != record.size
        ):
            raise OSError("materializer source changed before copy")
        target_opened = os.fstat(target_descriptor)
        if not stat.S_ISREG(target_opened.st_mode) or target_opened.st_nlink != 1:
            raise OSError("materializer source copy target is unsafe")
        while consumed < record.size:
            chunk = os.read(
                source_descriptor, min(64 * 1024, record.size - consumed)
            )
            if not chunk:
                raise OSError("materializer source ended before its pinned size")
            digest.update(chunk)
            pending = memoryview(chunk)
            while pending:
                written = os.write(target_descriptor, pending)
                if written < 1:
                    raise OSError("materializer source copy write was incomplete")
                pending = pending[written:]
            consumed += len(chunk)
        if os.read(source_descriptor, 1):
            raise OSError("materializer source exceeds its pinned size")
        os.fsync(target_descriptor)
        source_finished = os.fstat(source_descriptor)
        target_finished = os.fstat(target_descriptor)
        if (
            _stable_input_identity_v1(source_finished)
            != _stable_input_identity_v1(source_opened)
            or (target_finished.st_dev, target_finished.st_ino)
            != (target_opened.st_dev, target_opened.st_ino)
            or target_finished.st_size != record.size
            or digest.hexdigest() != record.sha256
        ):
            raise OSError("materializer source copy did not verify")
    except OSError as error:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer source could not be copied"
        ) from error
    finally:
        if target_descriptor >= 0:
            os.close(target_descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)
        for descriptor in reversed(target_guards):
            os.close(descriptor)
        for descriptor in reversed(source_guards):
            os.close(descriptor)
    source_after = _plain_input_node_v1(source, directory=False)
    target_after = _plain_input_node_v1(target, directory=False)
    if (
        _stable_input_identity_v1(source_after)
        != _stable_input_identity_v1(source_before)
        or (target_after.st_dev, target_after.st_ino)
        != (target_opened.st_dev, target_opened.st_ino)
        or target_after.st_size != record.size
        or _stable_input_identity_v1(
            _plain_input_node_v1(source_root, directory=True)
        )
        != _stable_input_identity_v1(source_root_before)
        or any(
            _stable_input_identity_v1(_plain_input_node_v1(path, directory=True))
            != identity
            for path, identity in source_directories
        )
    ):
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer source changed during copy"
        )


def _runtime_wires_from_bundle_v1(bundle) -> dict[str, bytes]:
    return {
        REQUEST_FILENAME: bundle.request_wire,
        HANDOFF_FILENAME: bundle.handoff_wire,
        D2_REPLAY_FILENAME: bundle.d2_wire,
        D3_REPLAY_FILENAME: bundle.d3_wire,
    }


def _materializer_input_identity_v1(
    source_root: Path,
    runtime_root: Path,
    handoff: WorkerHandoffV1,
) -> tuple[tuple[object, ...], ...]:
    records = list(
        _source_tree_identity_v1(
            source_root, handoff, require_container_readable=True
        )
    )
    runtime_state = _plain_input_node_v1(runtime_root, directory=True)
    if os.name == "posix" and stat.S_IMODE(runtime_state.st_mode) != 0o555:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer runtime directory is not read-only"
        )
    records.append(("R", "", *_stable_input_identity_v1(runtime_state)))
    for name in sorted(
        {REQUEST_FILENAME, HANDOFF_FILENAME, D2_REPLAY_FILENAME, D3_REPLAY_FILENAME}
    ):
        state = _plain_input_node_v1(runtime_root / name, directory=False)
        if os.name == "posix" and stat.S_IMODE(state.st_mode) != 0o444:
            raise LinuxOciProviderError(
                "runtime_input_failed", "materializer runtime file is not read-only"
            )
        records.append(("W", name, *_stable_input_identity_v1(state)))
    return tuple(records)


def _materializer_input_inodes_v1(
    source_root: Path,
    runtime_root: Path,
    handoff: WorkerHandoffV1,
) -> tuple[tuple[str, str, int, int], ...]:
    source_identity = _source_tree_identity_v1(
        source_root, handoff, require_container_readable=False
    )
    records = tuple(
        (str(item[0]), str(item[1]), int(item[2]), int(item[3]))
        for item in source_identity
    )
    runtime_records: list[tuple[str, str, int, int]] = []
    runtime_state = _plain_input_node_v1(runtime_root, directory=True)
    runtime_records.append(("R", "", runtime_state.st_dev, runtime_state.st_ino))
    for name in sorted(
        {REQUEST_FILENAME, HANDOFF_FILENAME, D2_REPLAY_FILENAME, D3_REPLAY_FILENAME}
    ):
        state = _plain_input_node_v1(runtime_root / name, directory=False)
        runtime_records.append(("W", name, state.st_dev, state.st_ino))
    return records + tuple(runtime_records)


@dataclass(frozen=True, slots=True)
class _MaterializerInputsV1:
    source_root: Path
    runtime_root: Path
    handoff: WorkerHandoffV1
    inodes: tuple[tuple[str, str, int, int], ...]
    identity: tuple[tuple[object, ...], ...]


def _verify_materializer_inputs_v1(
    inputs: _MaterializerInputsV1, wires: dict[str, bytes]
) -> None:
    if type(inputs) is not _MaterializerInputsV1 or type(wires) is not dict:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input verification is invalid"
        )
    if (
        _materializer_input_inodes_v1(
            inputs.source_root, inputs.runtime_root, inputs.handoff
        )
        != inputs.inodes
    ):
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input inode binding changed"
        )
    before = _materializer_input_identity_v1(
        inputs.source_root, inputs.runtime_root, inputs.handoff
    )
    if before != inputs.identity:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input identity changed"
        )
    try:
        bundle = _load_runtime_bundle(inputs.runtime_root)
        for record in inputs.handoff.files:
            _read_source_record(
                inputs.source_root,
                record.path,
                size=record.size,
                sha256=record.sha256,
            )
    except (OciWorkerEntryError, OSError, TypeError, ValueError) as error:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input content changed"
        ) from error
    if bundle.handoff != inputs.handoff or _runtime_wires_from_bundle_v1(bundle) != wires:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer runtime binding changed"
        )
    after = _materializer_input_identity_v1(
        inputs.source_root, inputs.runtime_root, inputs.handoff
    )
    if after != before:
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer input changed during verification"
        )


def _restore_materializer_input_permissions_v1(
    inputs: _MaterializerInputsV1,
) -> None:
    if type(inputs) is not _MaterializerInputsV1:
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "materializer input cleanup identity is invalid",
            runtime_uncertain=True,
        )
    expected_inodes = {
        (kind, name): (device, inode)
        for kind, name, device, inode in inputs.inodes
    }
    if len(expected_inodes) != len(inputs.inodes):
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "materializer input cleanup binding is invalid",
            runtime_uncertain=True,
        )

    def restore(
        path: Path, mode: int, *, directory: bool, kind: str, name: str
    ) -> None:
        state = _plain_input_node_v1(path, directory=directory)
        if (state.st_dev, state.st_ino) != expected_inodes.get((kind, name)):
            raise LinuxOciProviderError(
                "cleanup_uncertain",
                "materializer input changed before cleanup",
                runtime_uncertain=True,
            )
        _chmod_input_node_v1(path, mode, directory=directory)

    directories = tuple(
        sorted(
            _manifest_directories(inputs.handoff),
            key=lambda item: (item.count("/"), item),
        )
    )
    try:
        restore(
            inputs.source_root,
            0o700,
            directory=True,
            kind="D",
            name="",
        )
        for relative in directories:
            restore(
                inputs.source_root.joinpath(*relative.split("/")),
                0o700,
                directory=True,
                kind="D",
                name=relative,
            )
        restore(
            inputs.runtime_root,
            0o700,
            directory=True,
            kind="R",
            name="",
        )
        for record in inputs.handoff.files:
            restore(
                inputs.source_root.joinpath(*record.path.split("/")),
                0o600,
                directory=False,
                kind="F",
                name=record.path,
            )
        for name in (REQUEST_FILENAME, HANDOFF_FILENAME, D2_REPLAY_FILENAME, D3_REPLAY_FILENAME):
            restore(
                inputs.runtime_root / name,
                0o600,
                directory=False,
                kind="W",
                name=name,
            )
    except LinuxOciProviderError as error:
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "materializer input permissions could not be restored",
            runtime_uncertain=True,
        ) from error


def _stage_materializer_inputs_v1(
    private_root: Path,
    source_root: Path,
    wires: dict[str, bytes],
) -> _MaterializerInputsV1:
    if (
        type(private_root) is not type(Path())
        or type(source_root) is not type(Path())
        or type(wires) is not dict
    ):
        raise LinuxOciProviderError(
            "invalid_argument", "materializer staging input is invalid"
        )
    private_state = _plain_input_node_v1(private_root, directory=True)
    if os.name == "posix" and (
        stat.S_IMODE(private_state.st_mode) != 0o700
        or private_state.st_uid != os.getuid()
    ):
        raise LinuxOciProviderError(
            "runtime_input_failed", "materializer staging parent is not private"
        )
    staged_source = private_root / "source"
    staged_runtime = private_root / "runtime"
    handoff: WorkerHandoffV1 | None = None
    input_inodes: tuple[tuple[str, str, int, int], ...] = ()
    sealing_started = False
    try:
        _make_private_input_directory_v1(staged_source)
        _make_private_input_directory_v1(staged_runtime)
        _write_runtime_input_directory_v1(staged_runtime, wires)
        try:
            bundle = _load_runtime_bundle(staged_runtime)
        except (OciWorkerEntryError, OSError, TypeError, ValueError) as error:
            raise LinuxOciProviderError(
                "runtime_input_failed", "materializer runtime input did not verify"
            ) from error
        handoff = bundle.handoff
        if _runtime_wires_from_bundle_v1(bundle) != wires:
            raise LinuxOciProviderError(
                "runtime_input_failed", "materializer runtime input changed"
            )
        source_identity = _source_tree_identity_v1(
            source_root, handoff, require_container_readable=False
        )
        directories = tuple(
            sorted(
                _manifest_directories(handoff),
                key=lambda item: (item.count("/"), item),
            )
        )
        for relative in directories:
            _make_private_input_directory_v1(
                staged_source.joinpath(*relative.split("/"))
            )
        for record in handoff.files:
            _copy_source_record_v1(source_root, staged_source, record)
        if (
            _source_tree_identity_v1(
                source_root, handoff, require_container_readable=False
            )
            != source_identity
        ):
            raise LinuxOciProviderError(
                "runtime_input_failed", "sealed source changed while staging"
            )
        try:
            _inventory_source(staged_source, handoff)
            for record in handoff.files:
                _read_source_record(
                    staged_source,
                    record.path,
                    size=record.size,
                    sha256=record.sha256,
                )
        except (OciWorkerEntryError, OSError, TypeError, ValueError) as error:
            raise LinuxOciProviderError(
                "runtime_input_failed", "staged source input did not verify"
            ) from error
        for relative in sorted(
            directories, key=lambda item: (-item.count("/"), item)
        ):
            _sync_input_directory_v1(
                staged_source.joinpath(*relative.split("/"))
            )
        _sync_input_directory_v1(staged_source)
        _sync_input_directory_v1(staged_runtime)
        _sync_input_directory_v1(private_root)

        input_inodes = _materializer_input_inodes_v1(
            staged_source, staged_runtime, handoff
        )
        sealing_started = True
        for record in handoff.files:
            _chmod_input_node_v1(
                staged_source.joinpath(*record.path.split("/")),
                0o444,
                directory=False,
            )
        for name in (REQUEST_FILENAME, HANDOFF_FILENAME, D2_REPLAY_FILENAME, D3_REPLAY_FILENAME):
            _chmod_input_node_v1(staged_runtime / name, 0o444, directory=False)
        for relative in sorted(
            directories, key=lambda item: (-item.count("/"), item)
        ):
            _chmod_input_node_v1(
                staged_source.joinpath(*relative.split("/")),
                0o555,
                directory=True,
            )
        _chmod_input_node_v1(staged_source, 0o555, directory=True)
        _chmod_input_node_v1(staged_runtime, 0o555, directory=True)
        inputs = _MaterializerInputsV1(
            source_root=staged_source,
            runtime_root=staged_runtime,
            handoff=handoff,
            inodes=input_inodes,
            identity=_materializer_input_identity_v1(
                staged_source, staged_runtime, handoff
            ),
        )
        _verify_materializer_inputs_v1(inputs, wires)
        return inputs
    except BaseException as primary:
        if sealing_started and handoff is not None:
            partial = _MaterializerInputsV1(
                source_root=staged_source,
                runtime_root=staged_runtime,
                handoff=handoff,
                inodes=input_inodes,
                identity=(),
            )
            try:
                _restore_materializer_input_permissions_v1(partial)
            except BaseException:
                raise LinuxOciProviderError(
                    "cleanup_uncertain",
                    "materializer staging cleanup did not close",
                    runtime_uncertain=True,
                ) from primary
        raise


def _close_materializer_staging_v1(
    temporary_context: object, primary: BaseException | None
) -> None:
    try:
        temporary_context.cleanup()
    except BaseException as cleanup_error:
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "materializer staging deletion did not close",
            runtime_uncertain=True,
        ) from (primary if primary is not None else cleanup_error)
    if primary is not None:
        raise primary


def _validate_generation_receipt_v1(
    payload: bytes,
    *,
    request: OciWorkerRequestV1,
    launch: object,
    handoff: WorkerHandoffV1,
    wires: dict[str, bytes],
    d2_replay: OciReplayConfigV1,
    d3_replay: OciReplayConfigV1,
) -> GenerationReceiptV1:
    if type(handoff) is not WorkerHandoffV1 or type(wires) is not dict:
        raise LinuxOciProviderError(
            "invalid_argument", "source generation receipt binding is invalid"
        )
    try:
        receipt = GenerationReceiptV1.from_bytes(payload)
        task = launch.task
    except (AttributeError, OciWorkerEntryError, TypeError, ValueError):
        raise LinuxOciProviderError(
            "generation_failed", "source generation receipt is invalid"
        ) from None
    if (
        receipt.to_bytes() != payload
        or receipt.task_id != task.task_id
        or receipt.snapshot_id != task.snapshot_id
        or receipt.snapshot_manifest_sha256 != task.snapshot_manifest_sha256
        or receipt.snapshot_content_root != task.snapshot_content_root
        or receipt.request_sha256 != request.request_sha256
        or receipt.request_wire_sha256 != request.wire_sha256
        or receipt.handoff_sha256 != launch.handoff_sha256
        or receipt.handoff_wire_sha256 != launch.handoff_wire_sha256
        or receipt.d2_replay_sha256 != d2_replay.config_sha256
        or receipt.d2_replay_wire_sha256 != d2_replay.wire_sha256
        or receipt.d3_replay_sha256 != d3_replay.config_sha256
        or receipt.d3_replay_wire_sha256 != d3_replay.wire_sha256
        or receipt.runtime_set_sha256 != _runtime_set_sha256(wires)
        or receipt.file_count != handoff.file_count
        or receipt.total_bytes != handoff.total_bytes
    ):
        raise LinuxOciProviderError(
            "generation_failed", "source generation receipt is detached"
        )
    return receipt


def _reverify_linux_oci_runtime_v1(
    runtime: VerifiedLinuxOciRuntimeV1,
    execution_image: _DerivedExecutionImageV1 | None = None,
) -> None:
    executable, env, endpoint = runtime._command_context()
    server = _strict_json_document(
        _run_probe(
            executable,
            env,
            ("version", "--format", "{{json .Server}}"),
            endpoint=endpoint,
        ),
        name="OCI server",
    )
    image = _strict_json_document(
        _run_probe(
            executable,
            env,
            (
                "image",
                "inspect",
                runtime.execution_policy.runtime_image_id,
                "--format",
                "{{json .}}",
            ),
            endpoint=endpoint,
        ),
        name="OCI image",
    )
    if (
        type(server) is not dict
        or type(image) is not dict
        or hashlib.sha256(_canonical_json(server)).hexdigest()
        != runtime.server_sha256
        or hashlib.sha256(_canonical_json(image)).hexdigest()
        != runtime.image_inspect_sha256
    ):
        raise LinuxOciProviderError(
            "runtime_changed", "OCI runtime changed during worker execution"
        )
    if execution_image is not None:
        if (
            type(execution_image) is not _DerivedExecutionImageV1
            or execution_image.runtime is not runtime
        ):
            raise LinuxOciProviderError(
                "invalid_argument", "execution image belongs to another runtime"
            )
        _verify_execution_image_v1(execution_image)


def _cleanup_execution_image_or_raise_v1(
    image: _DerivedExecutionImageV1, primary: BaseException | None
) -> None:
    try:
        _remove_execution_image_v1(image)
    except BaseException as cleanup_error:
        raise LinuxOciProviderError(
            "cleanup_uncertain",
            "derived execution image cleanup did not close",
            runtime_uncertain=True,
        ) from (primary if primary is not None else cleanup_error)


def run_discovery_worker_linux_oci_v1(
    runtime: VerifiedLinuxOciRuntimeV1,
    launch: object,
    *,
    d2_replay: OciReplayConfigV1,
    d3_replay: OciReplayConfigV1,
) -> CompletedWorkerExecutionV1:
    """Execute one fixed offline task through an immutable derived image."""

    if type(runtime) is not VerifiedLinuxOciRuntimeV1:
        raise LinuxOciProviderError(
            "invalid_argument", "runtime must have an exact verified type"
        )
    # Local import avoids a module cycle while retaining an exact supervisor type gate.
    from vulngym_agent.evaluator.supervisor import WorkerTaskLaunchV1

    if type(launch) is not WorkerTaskLaunchV1:
        raise LinuxOciProviderError(
            "invalid_argument", "launch must have an exact supervisor type"
        )
    policy = runtime.execution_policy
    request, wires = _build_runtime_input_v1(
        launch, policy, d2_replay, d3_replay
    )
    primary: BaseException | None = None
    execution_image: _DerivedExecutionImageV1 | None = None
    materializer_step: _CompletedContainerStepV1 | None = None
    worker_step: _CompletedContainerStepV1 | None = None
    generation: GenerationReceiptV1 | None = None
    run_wire = b""
    run: SourceDiscoveryRunV1 | None = None
    try:
        try:
            temporary_context = tempfile.TemporaryDirectory(
                prefix="vulngym-e3-input-"
            )
        except OSError as error:
            raise LinuxOciProviderError(
                "runtime_input_failed", "materializer staging could not be allocated"
            ) from error
        staging_primary: BaseException | None = None
        try:
            inputs = _stage_materializer_inputs_v1(
                Path(temporary_context.name), launch.tree_root, wires
            )
            input_primary: BaseException | None = None
            try:
                materializer = _create_worker_container_v1(
                    runtime,
                    mode="materialize",
                    source_root=inputs.source_root,
                    runtime_input_root=inputs.runtime_root,
                )
                materializer_primary: BaseException | None = None
                try:
                    materializer_step = _run_container_step_v1(materializer)
                    _verify_materializer_inputs_v1(inputs, wires)
                    generation = _validate_generation_receipt_v1(
                        materializer_step.stdout,
                        request=request,
                        launch=launch,
                        handoff=inputs.handoff,
                        wires=wires,
                        d2_replay=d2_replay,
                        d3_replay=d3_replay,
                    )
                    execution_image = _commit_execution_image_v1(materializer)
                except BaseException as error:
                    materializer_primary = error
                try:
                    _remove_worker_container_v1(materializer)
                except BaseException as cleanup_error:
                    raise LinuxOciProviderError(
                        "cleanup_uncertain",
                        "materializer container cleanup did not close",
                        runtime_uncertain=True,
                    ) from (
                        materializer_primary
                        if materializer_primary is not None
                        else cleanup_error
                    )
                if materializer_primary is not None:
                    raise materializer_primary
            except BaseException as error:
                input_primary = error
            try:
                _restore_materializer_input_permissions_v1(inputs)
            except BaseException as cleanup_error:
                raise LinuxOciProviderError(
                    "cleanup_uncertain",
                    "materializer input cleanup did not close",
                    runtime_uncertain=True,
                ) from (
                    input_primary if input_primary is not None else cleanup_error
                )
            if input_primary is not None:
                raise input_primary
        except BaseException as error:
            staging_primary = error
        _close_materializer_staging_v1(temporary_context, staging_primary)
        if execution_image is None:
            raise LinuxOciProviderError(
                "provider_failed", "derived execution image is unavailable"
            )
        _verify_execution_image_v1(execution_image)
        worker = _create_worker_container_v1(
            runtime, mode="execute", execution_image=execution_image
        )
        worker_step = _run_clean_container_step_v1(worker)
        run_wire = worker_step.stdout
        try:
            run = SourceDiscoveryRunV1.from_wire(run_wire)
        except (AttributeError, RecursionError, RuntimeError, TypeError, ValueError):
            raise LinuxOciProviderError(
                "invalid_output", "worker output is not a canonical discovery run"
            ) from None
        if run.to_wire() != run_wire or run.task != launch.task:
            raise LinuxOciProviderError(
                "invalid_output", "worker output is detached from its launch"
            )
        _reverify_linux_oci_runtime_v1(runtime, execution_image)
    except BaseException as error:
        primary = error
    if execution_image is not None:
        _cleanup_execution_image_or_raise_v1(execution_image, primary)
    if primary is not None:
        raise primary
    if (
        execution_image is None
        or materializer_step is None
        or worker_step is None
        or generation is None
        or run is None
    ):
        raise LinuxOciProviderError(
            "provider_failed", "worker execution did not reach a closed state"
        )
    try:
        evidence = RuntimeEvidenceV1(
            docker_server=DockerServerIdentityV1(
                operating_system="linux",
                architecture=runtime.server_arch,
                engine_version=runtime.server_version,
                api_version=runtime.server_api_version,
                docker_executable_sha256=runtime.docker_executable_sha256,
                daemon_endpoint_sha256=docker_endpoint_sha256_v1(
                    runtime.docker_endpoint
                ),
                server_observation_sha256=runtime.server_sha256,
            ),
            isolation=RuntimeIsolationV1(),
            resources=RuntimeResourceLimitsV1(
                wall_time_seconds=policy.wall_time_seconds,
                memory_bytes=policy.memory_bytes,
                cpu_millis=policy.cpu_millis,
                pids_limit=policy.pids_limit,
                open_files_limit=policy.open_files_limit,
                stdout_max_bytes=policy.stdout_max_bytes,
                stderr_max_bytes=policy.stderr_max_bytes,
                tmpfs_bytes=policy.tmpfs_bytes,
            ),
            runtime_image_id=policy.runtime_image_id,
            runtime_image_inspect_sha256=runtime.image_inspect_sha256,
            execution_image_id=execution_image.image_id,
            execution_image_inspect_sha256=execution_image.inspect_sha256,
            execution_policy_sha256=policy.policy_sha256,
            task_plan_sha256=launch.task_plan.plan_sha256,
            task_id=launch.task_plan.task_id,
            snapshot_id=launch.task_plan.snapshot_id,
            snapshot_manifest_sha256=launch.task_plan.snapshot_manifest_sha256,
            snapshot_content_root=launch.task_plan.snapshot_content_root,
            handoff_sha256=launch.handoff_sha256,
            handoff_wire_sha256=launch.handoff_wire_sha256,
            source_generation_sha256=generation.generation_sha256,
            runtime_config_sha256=generation.runtime_set_sha256,
            materializer_container_create_spec_sha256=container_create_spec_sha256_v1(
                runtime, mode="materialize"
            ),
            materializer_container_pre_inspect_sha256=(
                materializer_step.pre_inspect_sha256
            ),
            materializer_container_post_inspect_sha256=(
                materializer_step.post_inspect_sha256
            ),
            materializer_container_diff_sha256=materializer_step.diff_sha256,
            materializer_container_identity_sha256=(
                materializer_step.container_identity_sha256
            ),
            container_create_spec_sha256=container_create_spec_sha256_v1(
                runtime,
                mode="execute",
                execution_image_id=execution_image.image_id,
            ),
            container_pre_inspect_sha256=worker_step.pre_inspect_sha256,
            container_post_inspect_sha256=worker_step.post_inspect_sha256,
            container_identity_sha256=worker_step.container_identity_sha256,
            run_sha256=run.run_sha256,
            run_wire_sha256=hashlib.sha256(run_wire).hexdigest(),
            run_wire_size=len(run_wire),
            stderr_sha256=hashlib.sha256(worker_step.stderr).hexdigest(),
            stderr_size=len(worker_step.stderr),
            exit_code=0,
            timed_out=False,
            oom_killed=False,
            restart_count=0,
            container_diff_empty=worker_step.diff_empty,
            cleanup_complete=True,
        )
        return _issue_completed_worker_execution_v1(run_wire, evidence)
    except (RuntimeEvidenceError, WorkerCompletionError) as error:
        raise LinuxOciProviderError(
            "evidence_failed", "worker runtime evidence did not close"
        ) from error


__all__ = [
    "LINUX_OCI_PROVIDER_VERSION",
    "LinuxOciProviderError",
    "OCI_GENERATION_ROOT",
    "OCI_INPUT_RUNTIME_ROOT",
    "OCI_INPUT_SOURCE_ROOT",
    "OCI_RUNTIME_ROOT",
    "OCI_SOURCE_ROOT",
    "VerifiedLinuxOciRuntimeV1",
    "build_worker_container_create_argv_v1",
    "container_create_spec_sha256_v1",
    "container_identity_sha256_v1",
    "container_inspect_sha256_v1",
    "normalized_container_inspect_v1",
    "normalized_terminal_container_inspect_v1",
    "run_discovery_worker_linux_oci_v1",
    "verify_linux_oci_runtime_v1",
]
