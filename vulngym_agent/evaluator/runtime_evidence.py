"""Canonical, path-free evidence for one successful Linux OCI worker run.

The trusted runtime provider constructs this record only after it has checked
the Docker daemon, the fixed container configuration, and the terminal
container state.  The contract is deliberately success-only: a timeout,
non-zero exit, OOM termination, stderr output, or weakened isolation cannot be
represented as :class:`RuntimeEvidenceV1`.

The embedded ``evidence_sha256`` authenticates the canonical content with a
contract-specific domain.  ``wire_sha256`` independently authenticates the
exact one-line JSON wire (including the embedded content digest).  Neither
digest is a signature; trust comes from the provider that performed the checks
and supplied the pinned observation digests.  The current contract does not
claim that the raw Docker inspect/diff responses are retained for offline
audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Final


RUNTIME_EVIDENCE_CONTRACT_VERSION: Final[int] = 1
RUNTIME_EVIDENCE_KIND: Final[str] = "vulngym.runtime-evidence.v1"
RUNTIME_EVIDENCE_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator runtime evidence content v1\0"
)
DOCKER_ENDPOINT_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator Docker endpoint v1\0"
)
DOCKER_SOCKET_IDENTITY_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator Docker socket identity v1\0"
)
DOCKER_INFO_IDENTITY_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator Docker info identity v1\0"
)
RUNTIME_EVIDENCE_MAX_WIRE_BYTES: Final[int] = 4 * 1024 * 1024
RUNTIME_EVIDENCE_MAX_JSON_NODES: Final[int] = 200_000
RUNTIME_EVIDENCE_MAX_JSON_DEPTH: Final[int] = 16

_EMPTY_SHA256: Final[str] = hashlib.sha256(b"").hexdigest()
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID_RE: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_SNAPSHOT_ID_RE: Final[re.Pattern[str]] = re.compile(r"VGS-[0-9A-F]{32}\Z")
_RUNTIME_COMPONENT_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z"
)
_ARCHITECTURE_RE: Final[re.Pattern[str]] = re.compile(
    r"[a-z0-9][a-z0-9._-]{0,31}\Z"
)
_DOCKER_INFO_IDENTITY_FIELDS: Final[tuple[str, ...]] = (
    "Architecture",
    "CgroupDriver",
    "CgroupVersion",
    "ContainerdCommit",
    "DefaultRuntime",
    "DockerRootDir",
    "Driver",
    "ID",
    "InitBinary",
    "InitCommit",
    "KernelVersion",
    "LiveRestoreEnabled",
    "MemTotal",
    "NCPU",
    "Name",
    "OSType",
    "OSVersion",
    "OperatingSystem",
    "RuncCommit",
    "Runtimes",
    "SecurityOptions",
    "ServerVersion",
)

_DOCKER_SERVER_KEYS: Final[frozenset[str]] = frozenset(
    {
        "api_version",
        "architecture",
        "daemon_endpoint_sha256",
        "docker_executable_sha256",
        "engine_version",
        "operating_system",
        "server_observation_sha256",
    }
)
_ISOLATION_KEYS: Final[frozenset[str]] = frozenset(
    {
        "capabilities_mode",
        "cgroupns_mode",
        "group_id",
        "ipc_mode",
        "log_driver_mode",
        "network_mode",
        "no_new_privileges",
        "rootfs_mode",
        "runtime_input_delivery_mode",
        "seccomp_mode",
        "source_delivery_mode",
        "tmpfs_mode",
        "user_id",
        "user_mode",
    }
)
_RESOURCE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "cpu_millis",
        "memory_bytes",
        "open_files_limit",
        "pids_limit",
        "stderr_max_bytes",
        "stdout_max_bytes",
        "tmpfs_bytes",
        "wall_time_seconds",
    }
)
_EVIDENCE_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "container_create_spec_sha256",
        "container_diff_empty",
        "container_identity_sha256",
        "container_post_inspect_sha256",
        "container_pre_inspect_sha256",
        "contract_version",
        "docker_server",
        "execution_image_id",
        "execution_image_inspect_sha256",
        "execution_policy_sha256",
        "exit_code",
        "handoff_sha256",
        "handoff_wire_sha256",
        "isolation",
        "kind",
        "materializer_container_create_spec_sha256",
        "materializer_container_diff_sha256",
        "materializer_container_identity_sha256",
        "materializer_container_post_inspect_sha256",
        "materializer_container_pre_inspect_sha256",
        "oom_killed",
        "provider",
        "provider_version",
        "resources",
        "restart_count",
        "run_sha256",
        "run_wire_sha256",
        "run_wire_size",
        "runtime_config_sha256",
        "runtime_image_id",
        "runtime_image_inspect_sha256",
        "snapshot_content_root",
        "snapshot_id",
        "snapshot_manifest_sha256",
        "source_generation_sha256",
        "status",
        "stderr_sha256",
        "stderr_size",
        "task_id",
        "task_plan_sha256",
        "timed_out",
        "cleanup_complete",
        "worker_version",
    }
)
_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "digest_mismatch",
        "invalid_argument",
        "invalid_binding",
        "invalid_contract",
        "limit_exceeded",
        "noncanonical_json",
    }
)


class RuntimeEvidenceError(ValueError):
    """Stable, path-free failure for runtime-evidence operations."""

    def __init__(self, code: str, message: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            code = "invalid_contract"
            message = "runtime evidence is invalid"
        self.code = code
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
        raise RuntimeEvidenceError(
            "invalid_contract", "runtime evidence is not canonical JSON"
        ) from None


def runtime_evidence_wire_sha256_v1(payload: bytes) -> str:
    """Return the transport digest of an exact evidence wire."""

    if type(payload) is not bytes:
        raise RuntimeEvidenceError(
            "invalid_argument", "runtime evidence wire must be exact bytes"
        )
    return hashlib.sha256(payload).hexdigest()


def docker_endpoint_sha256_v1(endpoint: str) -> str:
    """Return a path-free, domain-separated binding for one local endpoint."""

    if (
        type(endpoint) is not str
        or not endpoint
        or len(endpoint) > 2048
        or "\x00" in endpoint
    ):
        raise RuntimeEvidenceError(
            "invalid_argument", "Docker endpoint must be a bounded exact string"
        )
    try:
        payload = endpoint.encode("utf-8", errors="strict")
    except UnicodeError:
        raise RuntimeEvidenceError(
            "invalid_argument", "Docker endpoint is not valid UTF-8"
        ) from None
    return hashlib.sha256(DOCKER_ENDPOINT_DIGEST_DOMAIN + payload).hexdigest()


def docker_info_identity_sha256_v1(value: object) -> str:
    """Digest the stable daemon/cgroup/runtime subset of ``docker info``."""

    if type(value) is not dict or any(
        name not in value for name in _DOCKER_INFO_IDENTITY_FIELDS
    ):
        raise RuntimeEvidenceError(
            "invalid_contract", "Docker info identity is incomplete"
        )
    identity = {name: value[name] for name in _DOCKER_INFO_IDENTITY_FIELDS}
    _validate_json_shape(identity, count=[0])
    return hashlib.sha256(
        DOCKER_INFO_IDENTITY_DIGEST_DOMAIN + _canonical_json(identity)
    ).hexdigest()


def docker_socket_identity_sha256_v1(
    *, device: int, inode: int, uid: int, gid: int, mode: int
) -> str:
    """Return a path-free binding for one exact local Unix socket inode."""

    values = (device, inode, uid, gid, mode)
    if any(type(item) is not int or item < 0 for item in values):
        raise RuntimeEvidenceError(
            "invalid_argument", "Docker socket identity is invalid"
        )
    return hashlib.sha256(
        DOCKER_SOCKET_IDENTITY_DIGEST_DOMAIN
        + _canonical_json(
            {
                "device": device,
                "gid": gid,
                "inode": inode,
                "mode": mode,
                "uid": uid,
            }
        )
    ).hexdigest()


def _reject_constant(value: str) -> None:
    _ = value
    raise RuntimeEvidenceError(
        "noncanonical_json", "JSON constants outside the contract are forbidden"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeEvidenceError(
                "noncanonical_json", "JSON objects must not repeat keys"
            )
        result[key] = value
    return result


def _validate_json_shape(value: object, *, depth: int = 0, count: list[int]) -> None:
    count[0] += 1
    if (
        count[0] > RUNTIME_EVIDENCE_MAX_JSON_NODES
        or depth > RUNTIME_EVIDENCE_MAX_JSON_DEPTH
    ):
        raise RuntimeEvidenceError(
            "limit_exceeded", "runtime evidence JSON exceeds its shape limit"
        )
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise RuntimeEvidenceError(
                    "invalid_contract", "runtime evidence keys must be strings"
                )
            _validate_json_shape(child, depth=depth + 1, count=count)
    elif type(value) is list:
        for child in value:
            _validate_json_shape(child, depth=depth + 1, count=count)
    elif value is not None and type(value) not in {str, int, bool}:
        raise RuntimeEvidenceError(
            "invalid_contract", "runtime evidence has an invalid JSON value"
        )


def _strict_object(
    value: object, *, keys: frozenset[str], name: str
) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != keys:
        raise RuntimeEvidenceError(
            "invalid_contract", f"{name} has an invalid object shape"
        )
    return value


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise RuntimeEvidenceError(
            "invalid_contract", f"{name} must be a lower-case SHA-256 digest"
        )
    return value


def _require_expected_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise RuntimeEvidenceError(
            "invalid_argument", f"{name} must be a lower-case SHA-256 digest"
        )
    return value


def _parse_pinned_line(payload: bytes, *, expected_wire_sha256: str) -> dict[str, Any]:
    if type(payload) is not bytes:
        raise RuntimeEvidenceError(
            "invalid_argument", "runtime evidence payload must be exact bytes"
        )
    _require_expected_sha256(
        expected_wire_sha256, name="expected runtime evidence wire digest"
    )
    if not payload or len(payload) > RUNTIME_EVIDENCE_MAX_WIRE_BYTES:
        raise RuntimeEvidenceError(
            "limit_exceeded", "runtime evidence payload exceeds its byte limit"
        )
    if runtime_evidence_wire_sha256_v1(payload) != expected_wire_sha256:
        raise RuntimeEvidenceError(
            "digest_mismatch", "runtime evidence wire does not match its pin"
        )
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise RuntimeEvidenceError(
            "noncanonical_json", "runtime evidence must be one JSON line"
        )
    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except RuntimeEvidenceError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise RuntimeEvidenceError(
            "noncanonical_json", "runtime evidence is not strict JSON"
        ) from None
    _validate_json_shape(value, count=[0])
    if type(value) is not dict:
        raise RuntimeEvidenceError(
            "invalid_contract", "runtime evidence root must be an object"
        )
    return value


@dataclass(frozen=True, slots=True)
class RuntimeBindingPinsV1:
    """Unsigned expected runtime observations carried from readiness to OCI.

    This value is deliberately not a self-authenticating wire contract. The
    caller obtains it only by double-pin parsing the canonical readiness
    artifact, then the provider compares every field against fresh local
    observations at initial binding and each existing runtime reverify point.
    """

    daemon_endpoint_sha256: str
    docker_executable_sha256: str
    docker_socket_identity_sha256: str
    server_observation_sha256: str
    daemon_info_sha256: str
    runtime_image_id: str
    runtime_image_inspect_sha256: str

    def __post_init__(self) -> None:
        for value, name in (
            (self.daemon_endpoint_sha256, "daemon_endpoint_sha256"),
            (self.docker_executable_sha256, "docker_executable_sha256"),
            (
                self.docker_socket_identity_sha256,
                "docker_socket_identity_sha256",
            ),
            (self.server_observation_sha256, "server_observation_sha256"),
            (self.daemon_info_sha256, "daemon_info_sha256"),
            (
                self.runtime_image_inspect_sha256,
                "runtime_image_inspect_sha256",
            ),
        ):
            _require_sha256(value, name=name)
        if (
            type(self.runtime_image_id) is not str
            or _IMAGE_ID_RE.fullmatch(self.runtime_image_id) is None
        ):
            raise RuntimeEvidenceError(
                "invalid_contract", "runtime binding image ID is invalid"
            )

    def to_dict(self) -> dict[str, str]:
        self.__post_init__()
        return {
            "daemon_endpoint_sha256": self.daemon_endpoint_sha256,
            "daemon_info_sha256": self.daemon_info_sha256,
            "docker_executable_sha256": self.docker_executable_sha256,
            "docker_socket_identity_sha256": (
                self.docker_socket_identity_sha256
            ),
            "runtime_image_id": self.runtime_image_id,
            "runtime_image_inspect_sha256": self.runtime_image_inspect_sha256,
            "server_observation_sha256": self.server_observation_sha256,
        }


@dataclass(frozen=True, slots=True)
class DockerServerIdentityV1:
    """Normalized Docker daemon and executable identity."""

    operating_system: str
    architecture: str
    engine_version: str
    api_version: str
    docker_executable_sha256: str
    daemon_endpoint_sha256: str
    server_observation_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.operating_system) is not str
            or self.operating_system != "linux"
            or type(self.architecture) is not str
            or _ARCHITECTURE_RE.fullmatch(self.architecture) is None
            or type(self.engine_version) is not str
            or _RUNTIME_COMPONENT_RE.fullmatch(self.engine_version) is None
            or type(self.api_version) is not str
            or _RUNTIME_COMPONENT_RE.fullmatch(self.api_version) is None
        ):
            raise RuntimeEvidenceError(
                "invalid_contract", "Docker server identity is invalid"
            )
        _require_sha256(
            self.docker_executable_sha256, name="docker_executable_sha256"
        )
        _require_sha256(
            self.daemon_endpoint_sha256, name="daemon_endpoint_sha256"
        )
        _require_sha256(
            self.server_observation_sha256, name="server_observation_sha256"
        )

    def to_dict(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "api_version": self.api_version,
            "architecture": self.architecture,
            "daemon_endpoint_sha256": self.daemon_endpoint_sha256,
            "docker_executable_sha256": self.docker_executable_sha256,
            "engine_version": self.engine_version,
            "operating_system": self.operating_system,
            "server_observation_sha256": self.server_observation_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> "DockerServerIdentityV1":
        raw = _strict_object(
            value, keys=_DOCKER_SERVER_KEYS, name="Docker server identity"
        )
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class RuntimeIsolationV1:
    """The complete fixed isolation posture of the successful container."""

    user_id: int = 65532
    group_id: int = 65532
    network_mode: str = "none"
    rootfs_mode: str = "read-only"
    source_delivery_mode: str = "content-addressed-image-read-only"
    runtime_input_delivery_mode: str = "content-addressed-image-read-only"
    capabilities_mode: str = "drop-all"
    no_new_privileges: bool = True
    user_mode: str = "non-root"
    ipc_mode: str = "none"
    cgroupns_mode: str = "private"
    seccomp_mode: str = "filter"
    log_driver_mode: str = "none"
    tmpfs_mode: str = "rw,nosuid,nodev,noexec"

    def __post_init__(self) -> None:
        if (
            type(self.user_id) is not int
            or self.user_id != 65532
            or type(self.group_id) is not int
            or self.group_id != 65532
            or type(self.network_mode) is not str
            or self.network_mode != "none"
            or type(self.rootfs_mode) is not str
            or self.rootfs_mode != "read-only"
            or type(self.source_delivery_mode) is not str
            or self.source_delivery_mode != "content-addressed-image-read-only"
            or type(self.runtime_input_delivery_mode) is not str
            or self.runtime_input_delivery_mode
            != "content-addressed-image-read-only"
            or type(self.capabilities_mode) is not str
            or self.capabilities_mode != "drop-all"
            or type(self.no_new_privileges) is not bool
            or self.no_new_privileges is not True
            or type(self.user_mode) is not str
            or self.user_mode != "non-root"
            or type(self.ipc_mode) is not str
            or self.ipc_mode != "none"
            or type(self.cgroupns_mode) is not str
            or self.cgroupns_mode != "private"
            or type(self.seccomp_mode) is not str
            or self.seccomp_mode != "filter"
            or type(self.log_driver_mode) is not str
            or self.log_driver_mode != "none"
            or type(self.tmpfs_mode) is not str
            or self.tmpfs_mode != "rw,nosuid,nodev,noexec"
        ):
            raise RuntimeEvidenceError(
                "invalid_contract", "runtime isolation properties are invalid"
            )

    def to_dict(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "capabilities_mode": self.capabilities_mode,
            "cgroupns_mode": self.cgroupns_mode,
            "group_id": self.group_id,
            "ipc_mode": self.ipc_mode,
            "log_driver_mode": self.log_driver_mode,
            "network_mode": self.network_mode,
            "no_new_privileges": self.no_new_privileges,
            "rootfs_mode": self.rootfs_mode,
            "runtime_input_delivery_mode": self.runtime_input_delivery_mode,
            "seccomp_mode": self.seccomp_mode,
            "source_delivery_mode": self.source_delivery_mode,
            "tmpfs_mode": self.tmpfs_mode,
            "user_id": self.user_id,
            "user_mode": self.user_mode,
        }

    @classmethod
    def from_dict(cls, value: object) -> "RuntimeIsolationV1":
        raw = _strict_object(value, keys=_ISOLATION_KEYS, name="runtime isolation")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class RuntimeResourceLimitsV1:
    """Limits verified in daemon config or enforced by the provider transport."""

    wall_time_seconds: int = 1800
    memory_bytes: int = 2 * 1024 * 1024 * 1024
    cpu_millis: int = 2000
    pids_limit: int = 64
    open_files_limit: int = 256
    stdout_max_bytes: int = 6 * 1024 * 1024
    stderr_max_bytes: int = 1024 * 1024
    tmpfs_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        values = (
            self.wall_time_seconds,
            self.memory_bytes,
            self.cpu_millis,
            self.pids_limit,
            self.open_files_limit,
            self.stdout_max_bytes,
            self.stderr_max_bytes,
            self.tmpfs_bytes,
        )
        if any(type(item) is not int for item in values) or not (
            1 <= values[0] <= 3600
            and 256 * 1024 * 1024 <= values[1] <= 8 * 1024 * 1024 * 1024
            and 100 <= values[2] <= 8000
            and 8 <= values[3] <= 256
            and 32 <= values[4] <= 1024
            and 1 <= values[5] <= 6 * 1024 * 1024
            and 1 <= values[6] <= 4 * 1024 * 1024
            and 1024 * 1024 <= values[7] <= 512 * 1024 * 1024
        ):
            raise RuntimeEvidenceError(
                "limit_exceeded", "runtime resources exceed fixed bounds"
            )

    def to_dict(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "cpu_millis": self.cpu_millis,
            "memory_bytes": self.memory_bytes,
            "open_files_limit": self.open_files_limit,
            "pids_limit": self.pids_limit,
            "stderr_max_bytes": self.stderr_max_bytes,
            "stdout_max_bytes": self.stdout_max_bytes,
            "tmpfs_bytes": self.tmpfs_bytes,
            "wall_time_seconds": self.wall_time_seconds,
        }

    @classmethod
    def from_dict(cls, value: object) -> "RuntimeResourceLimitsV1":
        raw = _strict_object(value, keys=_RESOURCE_KEYS, name="runtime resources")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class RuntimeEvidenceV1:
    """Closed evidence for one successful, isolated worker execution."""

    docker_server: DockerServerIdentityV1
    isolation: RuntimeIsolationV1
    resources: RuntimeResourceLimitsV1
    runtime_image_id: str
    runtime_image_inspect_sha256: str
    execution_image_id: str
    execution_image_inspect_sha256: str
    execution_policy_sha256: str
    task_plan_sha256: str
    task_id: str
    snapshot_id: str
    snapshot_manifest_sha256: str
    snapshot_content_root: str
    handoff_sha256: str
    handoff_wire_sha256: str
    source_generation_sha256: str
    runtime_config_sha256: str
    materializer_container_create_spec_sha256: str
    materializer_container_pre_inspect_sha256: str
    materializer_container_post_inspect_sha256: str
    materializer_container_diff_sha256: str
    materializer_container_identity_sha256: str
    container_create_spec_sha256: str
    container_pre_inspect_sha256: str
    container_post_inspect_sha256: str
    container_identity_sha256: str
    run_sha256: str
    run_wire_sha256: str
    run_wire_size: int
    stderr_sha256: str
    stderr_size: int
    exit_code: int
    timed_out: bool
    oom_killed: bool
    restart_count: int
    container_diff_empty: bool
    cleanup_complete: bool
    provider: str = "linux-oci-v1"
    provider_version: str = "linux-oci-provider-v1"
    worker_version: str = "source-discovery-isolated-worker-v1"
    status: str = "succeeded"
    contract_version: int = RUNTIME_EVIDENCE_CONTRACT_VERSION
    kind: str = RUNTIME_EVIDENCE_KIND
    evidence_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != RUNTIME_EVIDENCE_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != RUNTIME_EVIDENCE_KIND
            or type(self.status) is not str
            or self.status != "succeeded"
            or type(self.provider) is not str
            or self.provider != "linux-oci-v1"
            or type(self.provider_version) is not str
            or self.provider_version != "linux-oci-provider-v1"
            or type(self.worker_version) is not str
            or self.worker_version != "source-discovery-isolated-worker-v1"
            or type(self.runtime_image_id) is not str
            or _IMAGE_ID_RE.fullmatch(self.runtime_image_id) is None
            or type(self.execution_image_id) is not str
            or _IMAGE_ID_RE.fullmatch(self.execution_image_id) is None
            or self.execution_image_id == self.runtime_image_id
            or type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.snapshot_id) is not str
            or _SNAPSHOT_ID_RE.fullmatch(self.snapshot_id) is None
        ):
            raise RuntimeEvidenceError(
                "invalid_contract", "runtime evidence identity is invalid"
            )
        if type(self.docker_server) is not DockerServerIdentityV1:
            raise RuntimeEvidenceError(
                "invalid_argument", "Docker server identity must have an exact type"
            )
        if type(self.isolation) is not RuntimeIsolationV1:
            raise RuntimeEvidenceError(
                "invalid_argument", "runtime isolation must have an exact type"
            )
        if type(self.resources) is not RuntimeResourceLimitsV1:
            raise RuntimeEvidenceError(
                "invalid_argument", "runtime resources must have an exact type"
            )
        docker_server = DockerServerIdentityV1.from_dict(self.docker_server.to_dict())
        isolation = RuntimeIsolationV1.from_dict(self.isolation.to_dict())
        resources = RuntimeResourceLimitsV1.from_dict(self.resources.to_dict())
        for value, name in (
            (self.execution_policy_sha256, "execution_policy_sha256"),
            (self.runtime_image_inspect_sha256, "runtime_image_inspect_sha256"),
            (self.execution_image_inspect_sha256, "execution_image_inspect_sha256"),
            (self.task_plan_sha256, "task_plan_sha256"),
            (self.snapshot_manifest_sha256, "snapshot_manifest_sha256"),
            (self.snapshot_content_root, "snapshot_content_root"),
            (self.handoff_sha256, "handoff_sha256"),
            (self.handoff_wire_sha256, "handoff_wire_sha256"),
            (self.source_generation_sha256, "source_generation_sha256"),
            (self.runtime_config_sha256, "runtime_config_sha256"),
            (
                self.materializer_container_create_spec_sha256,
                "materializer_container_create_spec_sha256",
            ),
            (
                self.materializer_container_pre_inspect_sha256,
                "materializer_container_pre_inspect_sha256",
            ),
            (
                self.materializer_container_post_inspect_sha256,
                "materializer_container_post_inspect_sha256",
            ),
            (
                self.materializer_container_diff_sha256,
                "materializer_container_diff_sha256",
            ),
            (
                self.materializer_container_identity_sha256,
                "materializer_container_identity_sha256",
            ),
            (self.container_create_spec_sha256, "container_create_spec_sha256"),
            (self.container_pre_inspect_sha256, "container_pre_inspect_sha256"),
            (self.container_post_inspect_sha256, "container_post_inspect_sha256"),
            (self.container_identity_sha256, "container_identity_sha256"),
            (self.run_sha256, "run_sha256"),
            (self.run_wire_sha256, "run_wire_sha256"),
            (self.stderr_sha256, "stderr_sha256"),
        ):
            _require_sha256(value, name=name)
        if (
            type(self.run_wire_size) is not int
            or not 1 <= self.run_wire_size <= resources.stdout_max_bytes
            or type(self.stderr_size) is not int
            or self.stderr_size != 0
            or self.stderr_sha256 != _EMPTY_SHA256
            or type(self.exit_code) is not int
            or self.exit_code != 0
            or type(self.timed_out) is not bool
            or self.timed_out is not False
            or type(self.oom_killed) is not bool
            or self.oom_killed is not False
            or type(self.restart_count) is not int
            or self.restart_count != 0
            or type(self.container_diff_empty) is not bool
            or self.container_diff_empty is not True
            or type(self.cleanup_complete) is not bool
            or self.cleanup_complete is not True
        ):
            raise RuntimeEvidenceError(
                "invalid_binding", "runtime evidence does not prove clean success"
            )
        object.__setattr__(self, "docker_server", docker_server)
        object.__setattr__(self, "isolation", isolation)
        object.__setattr__(self, "resources", resources)
        object.__setattr__(
            self,
            "evidence_sha256",
            hashlib.sha256(
                RUNTIME_EVIDENCE_DIGEST_DOMAIN + _canonical_json(self._core_dict())
            ).hexdigest(),
        )
        if len(self.to_bytes()) > RUNTIME_EVIDENCE_MAX_WIRE_BYTES:
            raise RuntimeEvidenceError(
                "limit_exceeded", "runtime evidence exceeds its wire limit"
            )

    def _core_dict(self) -> dict[str, object]:
        return {
            "container_create_spec_sha256": self.container_create_spec_sha256,
            "container_diff_empty": self.container_diff_empty,
            "container_identity_sha256": self.container_identity_sha256,
            "container_post_inspect_sha256": self.container_post_inspect_sha256,
            "container_pre_inspect_sha256": self.container_pre_inspect_sha256,
            "contract_version": self.contract_version,
            "docker_server": self.docker_server.to_dict(),
            "execution_image_id": self.execution_image_id,
            "execution_image_inspect_sha256": self.execution_image_inspect_sha256,
            "execution_policy_sha256": self.execution_policy_sha256,
            "exit_code": self.exit_code,
            "handoff_sha256": self.handoff_sha256,
            "handoff_wire_sha256": self.handoff_wire_sha256,
            "isolation": self.isolation.to_dict(),
            "kind": self.kind,
            "materializer_container_create_spec_sha256": self.materializer_container_create_spec_sha256,
            "materializer_container_diff_sha256": self.materializer_container_diff_sha256,
            "materializer_container_identity_sha256": self.materializer_container_identity_sha256,
            "materializer_container_post_inspect_sha256": self.materializer_container_post_inspect_sha256,
            "materializer_container_pre_inspect_sha256": self.materializer_container_pre_inspect_sha256,
            "oom_killed": self.oom_killed,
            "provider": self.provider,
            "provider_version": self.provider_version,
            "resources": self.resources.to_dict(),
            "restart_count": self.restart_count,
            "run_sha256": self.run_sha256,
            "run_wire_sha256": self.run_wire_sha256,
            "run_wire_size": self.run_wire_size,
            "runtime_config_sha256": self.runtime_config_sha256,
            "runtime_image_id": self.runtime_image_id,
            "runtime_image_inspect_sha256": self.runtime_image_inspect_sha256,
            "snapshot_content_root": self.snapshot_content_root,
            "snapshot_id": self.snapshot_id,
            "snapshot_manifest_sha256": self.snapshot_manifest_sha256,
            "source_generation_sha256": self.source_generation_sha256,
            "status": self.status,
            "stderr_sha256": self.stderr_sha256,
            "stderr_size": self.stderr_size,
            "task_id": self.task_id,
            "task_plan_sha256": self.task_plan_sha256,
            "timed_out": self.timed_out,
            "cleanup_complete": self.cleanup_complete,
            "worker_version": self.worker_version,
        }

    def to_dict(self) -> dict[str, object]:
        core = self._core_dict()
        expected = hashlib.sha256(
            RUNTIME_EVIDENCE_DIGEST_DOMAIN + _canonical_json(core)
        ).hexdigest()
        if type(self.evidence_sha256) is not str or self.evidence_sha256 != expected:
            raise RuntimeEvidenceError(
                "invalid_binding", "runtime evidence digest no longer matches"
            )
        return {**core, "evidence_sha256": self.evidence_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > RUNTIME_EVIDENCE_MAX_WIRE_BYTES:
            raise RuntimeEvidenceError(
                "limit_exceeded", "runtime evidence exceeds its wire limit"
            )
        return payload

    @property
    def wire_sha256(self) -> str:
        return runtime_evidence_wire_sha256_v1(self.to_bytes())

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_evidence_sha256: str,
        expected_wire_sha256: str,
    ) -> "RuntimeEvidenceV1":
        _require_expected_sha256(
            expected_evidence_sha256,
            name="expected runtime evidence content digest",
        )
        value = _strict_object(
            _parse_pinned_line(
                payload, expected_wire_sha256=expected_wire_sha256
            ),
            keys=_EVIDENCE_CORE_KEYS | {"evidence_sha256"},
            name="runtime evidence",
        )
        if value["evidence_sha256"] != expected_evidence_sha256:
            raise RuntimeEvidenceError(
                "digest_mismatch", "runtime evidence content does not match its pin"
            )
        result = cls(
            docker_server=DockerServerIdentityV1.from_dict(value["docker_server"]),
            isolation=RuntimeIsolationV1.from_dict(value["isolation"]),
            resources=RuntimeResourceLimitsV1.from_dict(value["resources"]),
            runtime_image_id=value["runtime_image_id"],
            runtime_image_inspect_sha256=value["runtime_image_inspect_sha256"],
            execution_image_id=value["execution_image_id"],
            execution_image_inspect_sha256=value["execution_image_inspect_sha256"],
            execution_policy_sha256=value["execution_policy_sha256"],
            task_plan_sha256=value["task_plan_sha256"],
            task_id=value["task_id"],
            snapshot_id=value["snapshot_id"],
            snapshot_manifest_sha256=value["snapshot_manifest_sha256"],
            snapshot_content_root=value["snapshot_content_root"],
            handoff_sha256=value["handoff_sha256"],
            handoff_wire_sha256=value["handoff_wire_sha256"],
            source_generation_sha256=value["source_generation_sha256"],
            runtime_config_sha256=value["runtime_config_sha256"],
            materializer_container_create_spec_sha256=value[
                "materializer_container_create_spec_sha256"
            ],
            materializer_container_pre_inspect_sha256=value[
                "materializer_container_pre_inspect_sha256"
            ],
            materializer_container_post_inspect_sha256=value[
                "materializer_container_post_inspect_sha256"
            ],
            materializer_container_diff_sha256=value[
                "materializer_container_diff_sha256"
            ],
            materializer_container_identity_sha256=value[
                "materializer_container_identity_sha256"
            ],
            container_create_spec_sha256=value["container_create_spec_sha256"],
            container_pre_inspect_sha256=value["container_pre_inspect_sha256"],
            container_post_inspect_sha256=value["container_post_inspect_sha256"],
            container_identity_sha256=value["container_identity_sha256"],
            run_sha256=value["run_sha256"],
            run_wire_sha256=value["run_wire_sha256"],
            run_wire_size=value["run_wire_size"],
            stderr_sha256=value["stderr_sha256"],
            stderr_size=value["stderr_size"],
            exit_code=value["exit_code"],
            timed_out=value["timed_out"],
            oom_killed=value["oom_killed"],
            restart_count=value["restart_count"],
            container_diff_empty=value["container_diff_empty"],
            cleanup_complete=value["cleanup_complete"],
            provider=value["provider"],
            provider_version=value["provider_version"],
            worker_version=value["worker_version"],
            status=value["status"],
            contract_version=value["contract_version"],
            kind=value["kind"],
        )
        if (
            result.evidence_sha256 != expected_evidence_sha256
            or result.wire_sha256 != expected_wire_sha256
            or result.to_bytes() != payload
        ):
            raise RuntimeEvidenceError(
                "noncanonical_json", "runtime evidence is not canonical"
            )
        return result


__all__ = [
    "DOCKER_ENDPOINT_DIGEST_DOMAIN",
    "DOCKER_INFO_IDENTITY_DIGEST_DOMAIN",
    "DOCKER_SOCKET_IDENTITY_DIGEST_DOMAIN",
    "DockerServerIdentityV1",
    "RUNTIME_EVIDENCE_CONTRACT_VERSION",
    "RUNTIME_EVIDENCE_DIGEST_DOMAIN",
    "RUNTIME_EVIDENCE_KIND",
    "RUNTIME_EVIDENCE_MAX_JSON_DEPTH",
    "RUNTIME_EVIDENCE_MAX_JSON_NODES",
    "RUNTIME_EVIDENCE_MAX_WIRE_BYTES",
    "RuntimeEvidenceError",
    "RuntimeEvidenceV1",
    "RuntimeBindingPinsV1",
    "RuntimeIsolationV1",
    "RuntimeResourceLimitsV1",
    "docker_endpoint_sha256_v1",
    "docker_info_identity_sha256_v1",
    "docker_socket_identity_sha256_v1",
    "runtime_evidence_wire_sha256_v1",
]
