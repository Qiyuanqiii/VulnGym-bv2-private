"""Fixed, offline OCI worker entry for evaluator stage E3.

The command line intentionally has exactly two forms::

    python -m vulngym_agent.evaluator.oci_worker_entry materialize
    python -m vulngym_agent.evaluator.oci_worker_entry execute

No path, module, command, backend, or provider is caller-selectable.  The
trusted launcher supplies fixed mounts.  ``materialize`` copies one verified
handoff generation from ``/input-*`` into the container layer at ``/vulngym``;
the launcher commits that layer as a content-addressed image.  ``execute``
reads the generation from that image under a read-only root filesystem and
emits only the canonical discovery-run wire on stdout.

This module uses only the Python standard library plus existing VulnGym
contracts.  It does not start processes, import target code, or access the
network.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import sys
from types import MappingProxyType
from typing import Any, BinaryIO, Final

from vulngym_agent.agents.model_runtime import (
    ReplayResponse,
    ReplayStructuredModelBackend,
)
from vulngym_agent.benchmark.sealed_tree_access import (
    SealedTreeAccessError,
    bind_worker_tree,
)
from vulngym_agent.benchmark.worker_handoff import (
    WORKER_HANDOFF_MAX_BYTES,
    WorkerHandoffError,
    WorkerHandoffV1,
)
from vulngym_agent.evaluator.worker import (
    IsolatedWorkerError,
    execute_discovery_worker_v1,
)


OCI_WORKER_ENTRY_VERSION: Final[str] = "vulngym-oci-worker-entry-v1"

WORKER_REQUEST_KIND: Final[str] = "vulngym.oci-worker-request.v1"
REPLAY_CONFIG_KIND: Final[str] = "vulngym.oci-replay-config.v1"
GENERATION_RECEIPT_KIND: Final[str] = "vulngym.oci-generation-receipt.v1"
WORKER_ERROR_KIND: Final[str] = "vulngym.oci-worker-error.v1"
PROTOCOL_VERSION: Final[int] = 1

WORKER_REQUEST_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym OCI worker request v1\0"
)
REPLAY_CONFIG_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym OCI replay config v1\0"
)
GENERATION_RECEIPT_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym OCI generation receipt v1\0"
)
RUNTIME_SET_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym OCI runtime input set v1\0"
)

REQUEST_MAX_BYTES: Final[int] = 16 * 1024
REPLAY_CONFIG_MAX_BYTES: Final[int] = 8 * 1024 * 1024
GENERATION_RECEIPT_MAX_BYTES: Final[int] = 32 * 1024
ERROR_MAX_BYTES: Final[int] = 512
MAX_REPLAY_RESPONSES: Final[int] = 16
MAX_JSON_DEPTH: Final[int] = 18
MAX_JSON_NODES: Final[int] = 40_000

REPLAY_BACKEND_ID: Final[str] = "replay"
REPLAY_MODEL_ID: Final[str] = "offline-v1"

REQUEST_FILENAME: Final[str] = "request.json"
HANDOFF_FILENAME: Final[str] = "handoff.json"
D2_REPLAY_FILENAME: Final[str] = "d2-replay.json"
D3_REPLAY_FILENAME: Final[str] = "d3-replay.json"
RUNTIME_FILENAMES: Final[tuple[str, ...]] = (
    REQUEST_FILENAME,
    HANDOFF_FILENAME,
    D2_REPLAY_FILENAME,
    D3_REPLAY_FILENAME,
)

MATERIALIZE_SOURCE_ROOT: Final[Path] = Path("/input-source")
MATERIALIZE_RUNTIME_ROOT: Final[Path] = Path("/input-runtime")
GENERATION_ROOT: Final[Path] = Path("/vulngym")
EXECUTE_SOURCE_ROOT: Final[Path] = Path("/vulngym/source")
EXECUTE_RUNTIME_ROOT: Final[Path] = Path("/vulngym/runtime")

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_SNAPSHOT_ID_RE: Final[re.Pattern[str]] = re.compile(r"VGS-[0-9A-F]{32}\Z")
_ERROR_CODE_RE: Final[re.Pattern[str]] = re.compile(
    r"[a-z][a-z0-9_]{0,63}\Z"
)
_BLOCKED_WRITE_ERRNOS: Final[frozenset[int]] = frozenset(
    {errno.EACCES, errno.EPERM, errno.EROFS}
)
_BLOCKED_NETWORK_ERRNOS: Final[frozenset[int]] = frozenset(
    {
        errno.EACCES,
        errno.EADDRNOTAVAIL,
        errno.EAFNOSUPPORT,
        errno.EHOSTUNREACH,
        errno.ENETDOWN,
        errno.ENETUNREACH,
        errno.EPERM,
    }
)
_FORBIDDEN_RUNTIME_PATHS: Final[tuple[str, ...]] = (
    "/benchmark",
    "/benchmarks",
    "/generation",
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/vulngym/control",
    "/workspace",
)
_EMPTY_INPUT_MOUNTPOINTS: Final[tuple[str, ...]] = (
    "/input-runtime",
    "/input-source",
)


class OciWorkerEntryError(RuntimeError):
    """Stable, path-free failure at the fixed OCI entry boundary."""

    def __init__(self, code: str) -> None:
        if type(code) is not str or _ERROR_CODE_RE.fullmatch(code) is None:
            code = "internal_error"
        self.code = code
        super().__init__(code)


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        _thaw_json(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _reject_constant(_value: str) -> None:
    raise OciWorkerEntryError("noncanonical_json")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OciWorkerEntryError("noncanonical_json")
        result[key] = value
    return result


def _validate_json_shape(value: object, *, depth: int = 0, count: list[int]) -> None:
    count[0] += 1
    if count[0] > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
        raise OciWorkerEntryError("limit_exceeded")
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise OciWorkerEntryError("noncanonical_json")
        return
    if type(value) is list:
        for child in value:
            _validate_json_shape(child, depth=depth + 1, count=count)
        return
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise OciWorkerEntryError("noncanonical_json")
            _validate_json_shape(child, depth=depth + 1, count=count)
        return
    raise OciWorkerEntryError("noncanonical_json")


def _parse_canonical_line(payload: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if type(payload) is not bytes or not payload or len(payload) > maximum_bytes:
        raise OciWorkerEntryError("limit_exceeded")
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise OciWorkerEntryError("noncanonical_json")
    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except OciWorkerEntryError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise OciWorkerEntryError("noncanonical_json") from None
    _validate_json_shape(value, count=[0])
    if type(value) is not dict:
        raise OciWorkerEntryError("invalid_contract")
    return value


def _strict_object(
    value: object, *, keys: frozenset[str], name: str
) -> dict[str, Any]:
    del name  # Messages never cross this boundary; retain the argument for callers.
    if type(value) is not dict or frozenset(value) != keys:
        raise OciWorkerEntryError("invalid_contract")
    return value


def _require_sha256(value: object) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise OciWorkerEntryError("invalid_contract")
    return value


@dataclass(frozen=True, slots=True)
class OciWorkerRequestV1:
    """One path-free binding for the exact handoff and replay inputs."""

    task_id: str
    snapshot_id: str
    snapshot_manifest_sha256: str
    snapshot_content_root: str
    handoff_sha256: str
    handoff_wire_sha256: str
    d2_replay_sha256: str
    d2_replay_wire_sha256: str
    d3_replay_sha256: str
    d3_replay_wire_sha256: str
    contract_version: int = PROTOCOL_VERSION
    kind: str = WORKER_REQUEST_KIND
    request_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != PROTOCOL_VERSION
            or type(self.kind) is not str
            or self.kind != WORKER_REQUEST_KIND
            or type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.snapshot_id) is not str
            or _SNAPSHOT_ID_RE.fullmatch(self.snapshot_id) is None
        ):
            raise OciWorkerEntryError("invalid_contract")
        for value in (
            self.snapshot_manifest_sha256,
            self.snapshot_content_root,
            self.handoff_sha256,
            self.handoff_wire_sha256,
            self.d2_replay_sha256,
            self.d2_replay_wire_sha256,
            self.d3_replay_sha256,
            self.d3_replay_wire_sha256,
        ):
            _require_sha256(value)
        object.__setattr__(
            self,
            "request_sha256",
            hashlib.sha256(
                WORKER_REQUEST_DIGEST_DOMAIN + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "d2_replay_sha256": self.d2_replay_sha256,
            "d2_replay_wire_sha256": self.d2_replay_wire_sha256,
            "d3_replay_sha256": self.d3_replay_sha256,
            "d3_replay_wire_sha256": self.d3_replay_wire_sha256,
            "handoff_sha256": self.handoff_sha256,
            "handoff_wire_sha256": self.handoff_wire_sha256,
            "kind": self.kind,
            "snapshot_content_root": self.snapshot_content_root,
            "snapshot_id": self.snapshot_id,
            "snapshot_manifest_sha256": self.snapshot_manifest_sha256,
            "task_id": self.task_id,
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            WORKER_REQUEST_DIGEST_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.request_sha256 != expected:
            raise OciWorkerEntryError("digest_mismatch")
        return {**self._core_dict(), "request_sha256": self.request_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > REQUEST_MAX_BYTES:
            raise OciWorkerEntryError("limit_exceeded")
        return payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(cls, payload: bytes) -> "OciWorkerRequestV1":
        value = _strict_object(
            _parse_canonical_line(payload, maximum_bytes=REQUEST_MAX_BYTES),
            keys=frozenset(
                {
                    "contract_version",
                    "d2_replay_sha256",
                    "d2_replay_wire_sha256",
                    "d3_replay_sha256",
                    "d3_replay_wire_sha256",
                    "handoff_sha256",
                    "handoff_wire_sha256",
                    "kind",
                    "request_sha256",
                    "snapshot_content_root",
                    "snapshot_id",
                    "snapshot_manifest_sha256",
                    "task_id",
                }
            ),
            name="worker request",
        )
        supplied = _require_sha256(value["request_sha256"])
        result = cls(
            task_id=value["task_id"],
            snapshot_id=value["snapshot_id"],
            snapshot_manifest_sha256=value["snapshot_manifest_sha256"],
            snapshot_content_root=value["snapshot_content_root"],
            handoff_sha256=value["handoff_sha256"],
            handoff_wire_sha256=value["handoff_wire_sha256"],
            d2_replay_sha256=value["d2_replay_sha256"],
            d2_replay_wire_sha256=value["d2_replay_wire_sha256"],
            d3_replay_sha256=value["d3_replay_sha256"],
            d3_replay_wire_sha256=value["d3_replay_wire_sha256"],
            contract_version=value["contract_version"],
            kind=value["kind"],
        )
        if result.request_sha256 != supplied or result.to_bytes() != payload:
            raise OciWorkerEntryError("digest_mismatch")
        return result


@dataclass(frozen=True, slots=True)
class OciReplayConfigV1:
    """Canonical per-task input for the sole offline backend factory."""

    task_id: str
    role: str
    responses: tuple[ReplayResponse, ...]
    backend_id: str = REPLAY_BACKEND_ID
    model_id: str = REPLAY_MODEL_ID
    contract_version: int = PROTOCOL_VERSION
    kind: str = REPLAY_CONFIG_KIND
    config_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != PROTOCOL_VERSION
            or type(self.kind) is not str
            or self.kind != REPLAY_CONFIG_KIND
            or type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.role) is not str
            or self.role not in {"d2", "d3"}
            or type(self.backend_id) is not str
            or self.backend_id != REPLAY_BACKEND_ID
            or type(self.model_id) is not str
            or self.model_id != REPLAY_MODEL_ID
            or type(self.responses) is not tuple
            or len(self.responses) > MAX_REPLAY_RESPONSES
            or any(type(item) is not ReplayResponse for item in self.responses)
        ):
            raise OciWorkerEntryError("invalid_contract")
        try:
            detached = tuple(
                ReplayResponse(
                    stage=item.stage,
                    request=_thaw_json(item.request),
                    response=_thaw_json(item.response),
                )
                for item in self.responses
            )
            # Construction also rejects duplicate (stage, request digest) keys.
            ReplayStructuredModelBackend(
                detached,
                backend_id=REPLAY_BACKEND_ID,
                model_id=REPLAY_MODEL_ID,
            )
        except (AttributeError, RecursionError, TypeError, ValueError):
            raise OciWorkerEntryError("invalid_contract") from None
        object.__setattr__(self, "responses", detached)
        object.__setattr__(
            self,
            "config_sha256",
            hashlib.sha256(
                REPLAY_CONFIG_DIGEST_DOMAIN + _canonical_json(self._core_dict())
            ).hexdigest(),
        )
        if len(self.to_bytes()) > REPLAY_CONFIG_MAX_BYTES:
            raise OciWorkerEntryError("limit_exceeded")

    def _response_dict(self, value: ReplayResponse) -> dict[str, object]:
        return {
            "request": _thaw_json(value.request),
            "response": _thaw_json(value.response),
            "stage": value.stage,
        }

    def _core_dict(self) -> dict[str, object]:
        return {
            "backend_id": self.backend_id,
            "contract_version": self.contract_version,
            "kind": self.kind,
            "model_id": self.model_id,
            "responses": [self._response_dict(item) for item in self.responses],
            "role": self.role,
            "task_id": self.task_id,
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            REPLAY_CONFIG_DIGEST_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.config_sha256 != expected:
            raise OciWorkerEntryError("digest_mismatch")
        return {**self._core_dict(), "config_sha256": self.config_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > REPLAY_CONFIG_MAX_BYTES:
            raise OciWorkerEntryError("limit_exceeded")
        return payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(cls, payload: bytes) -> "OciReplayConfigV1":
        value = _strict_object(
            _parse_canonical_line(payload, maximum_bytes=REPLAY_CONFIG_MAX_BYTES),
            keys=frozenset(
                {
                    "backend_id",
                    "config_sha256",
                    "contract_version",
                    "kind",
                    "model_id",
                    "responses",
                    "role",
                    "task_id",
                }
            ),
            name="replay config",
        )
        raw_responses = value["responses"]
        if type(raw_responses) is not list or len(raw_responses) > MAX_REPLAY_RESPONSES:
            raise OciWorkerEntryError("limit_exceeded")
        responses: list[ReplayResponse] = []
        for raw in raw_responses:
            item = _strict_object(
                raw,
                keys=frozenset({"request", "response", "stage"}),
                name="replay response",
            )
            if type(item["request"]) is not dict or type(item["response"]) is not dict:
                raise OciWorkerEntryError("invalid_contract")
            try:
                responses.append(
                    ReplayResponse(
                        stage=item["stage"],
                        request=item["request"],
                        response=item["response"],
                    )
                )
            except (AttributeError, RecursionError, TypeError, ValueError):
                raise OciWorkerEntryError("invalid_contract") from None
        supplied = _require_sha256(value["config_sha256"])
        result = cls(
            task_id=value["task_id"],
            role=value["role"],
            responses=tuple(responses),
            backend_id=value["backend_id"],
            model_id=value["model_id"],
            contract_version=value["contract_version"],
            kind=value["kind"],
        )
        if result.config_sha256 != supplied or result.to_bytes() != payload:
            raise OciWorkerEntryError("digest_mismatch")
        return result

    def build_backend(self) -> ReplayStructuredModelBackend:
        """Build the only permitted backend without dynamic resolution."""

        try:
            return ReplayStructuredModelBackend(
                self.responses,
                backend_id=REPLAY_BACKEND_ID,
                model_id=REPLAY_MODEL_ID,
            )
        except (AttributeError, RecursionError, TypeError, ValueError):
            raise OciWorkerEntryError("invalid_backend") from None


@dataclass(frozen=True, slots=True)
class GenerationReceiptV1:
    """Path-free receipt for one exact copied source/runtime generation."""

    task_id: str
    snapshot_id: str
    snapshot_manifest_sha256: str
    snapshot_content_root: str
    request_sha256: str
    request_wire_sha256: str
    handoff_sha256: str
    handoff_wire_sha256: str
    d2_replay_sha256: str
    d2_replay_wire_sha256: str
    d3_replay_sha256: str
    d3_replay_wire_sha256: str
    runtime_set_sha256: str
    file_count: int
    total_bytes: int
    contract_version: int = PROTOCOL_VERSION
    kind: str = GENERATION_RECEIPT_KIND
    generation_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != PROTOCOL_VERSION
            or type(self.kind) is not str
            or self.kind != GENERATION_RECEIPT_KIND
            or type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.snapshot_id) is not str
            or _SNAPSHOT_ID_RE.fullmatch(self.snapshot_id) is None
            or type(self.file_count) is not int
            or self.file_count < 1
            or type(self.total_bytes) is not int
            or self.total_bytes < 0
        ):
            raise OciWorkerEntryError("invalid_contract")
        for value in (
            self.snapshot_manifest_sha256,
            self.snapshot_content_root,
            self.request_sha256,
            self.request_wire_sha256,
            self.handoff_sha256,
            self.handoff_wire_sha256,
            self.d2_replay_sha256,
            self.d2_replay_wire_sha256,
            self.d3_replay_sha256,
            self.d3_replay_wire_sha256,
            self.runtime_set_sha256,
        ):
            _require_sha256(value)
        object.__setattr__(
            self,
            "generation_sha256",
            hashlib.sha256(
                GENERATION_RECEIPT_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "d2_replay_sha256": self.d2_replay_sha256,
            "d2_replay_wire_sha256": self.d2_replay_wire_sha256,
            "d3_replay_sha256": self.d3_replay_sha256,
            "d3_replay_wire_sha256": self.d3_replay_wire_sha256,
            "file_count": self.file_count,
            "handoff_sha256": self.handoff_sha256,
            "handoff_wire_sha256": self.handoff_wire_sha256,
            "kind": self.kind,
            "request_sha256": self.request_sha256,
            "request_wire_sha256": self.request_wire_sha256,
            "runtime_set_sha256": self.runtime_set_sha256,
            "snapshot_content_root": self.snapshot_content_root,
            "snapshot_id": self.snapshot_id,
            "snapshot_manifest_sha256": self.snapshot_manifest_sha256,
            "task_id": self.task_id,
            "total_bytes": self.total_bytes,
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            GENERATION_RECEIPT_DIGEST_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.generation_sha256 != expected:
            raise OciWorkerEntryError("digest_mismatch")
        return {**self._core_dict(), "generation_sha256": self.generation_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > GENERATION_RECEIPT_MAX_BYTES:
            raise OciWorkerEntryError("limit_exceeded")
        return payload

    @classmethod
    def from_bytes(cls, payload: bytes) -> "GenerationReceiptV1":
        value = _strict_object(
            _parse_canonical_line(
                payload, maximum_bytes=GENERATION_RECEIPT_MAX_BYTES
            ),
            keys=frozenset(
                {
                    "contract_version",
                    "d2_replay_sha256",
                    "d2_replay_wire_sha256",
                    "d3_replay_sha256",
                    "d3_replay_wire_sha256",
                    "file_count",
                    "generation_sha256",
                    "handoff_sha256",
                    "handoff_wire_sha256",
                    "kind",
                    "request_sha256",
                    "request_wire_sha256",
                    "runtime_set_sha256",
                    "snapshot_content_root",
                    "snapshot_id",
                    "snapshot_manifest_sha256",
                    "task_id",
                    "total_bytes",
                }
            ),
            name="generation receipt",
        )
        supplied = _require_sha256(value["generation_sha256"])
        result = cls(
            task_id=value["task_id"],
            snapshot_id=value["snapshot_id"],
            snapshot_manifest_sha256=value["snapshot_manifest_sha256"],
            snapshot_content_root=value["snapshot_content_root"],
            request_sha256=value["request_sha256"],
            request_wire_sha256=value["request_wire_sha256"],
            handoff_sha256=value["handoff_sha256"],
            handoff_wire_sha256=value["handoff_wire_sha256"],
            d2_replay_sha256=value["d2_replay_sha256"],
            d2_replay_wire_sha256=value["d2_replay_wire_sha256"],
            d3_replay_sha256=value["d3_replay_sha256"],
            d3_replay_wire_sha256=value["d3_replay_wire_sha256"],
            runtime_set_sha256=value["runtime_set_sha256"],
            file_count=value["file_count"],
            total_bytes=value["total_bytes"],
            contract_version=value["contract_version"],
            kind=value["kind"],
        )
        if result.generation_sha256 != supplied or result.to_bytes() != payload:
            raise OciWorkerEntryError("digest_mismatch")
        return result


@dataclass(frozen=True, slots=True)
class _RuntimeBundle:
    request: OciWorkerRequestV1
    request_wire: bytes
    handoff: WorkerHandoffV1
    handoff_wire: bytes
    d2_config: OciReplayConfigV1
    d2_wire: bytes
    d3_config: OciReplayConfigV1
    d3_wire: bytes


def _is_reparse(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _identity(value: os.stat_result) -> tuple[int, int, int, int | None, int | None]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        getattr(value, "st_mtime_ns", None),
        getattr(value, "st_ctime_ns", None),
    )


def _directory_identity(value: os.stat_result) -> tuple[int, int]:
    return (value.st_dev, value.st_ino)


def _require_directory(path: Path) -> os.stat_result:
    if type(path) is not type(Path()):
        raise OciWorkerEntryError("unsafe_input")
    try:
        value = os.lstat(path)
    except OSError:
        raise OciWorkerEntryError("input_unavailable") from None
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
    ):
        raise OciWorkerEntryError("unsafe_input")
    return value


def _read_bounded_regular(root: Path, name: str, *, maximum_bytes: int) -> bytes:
    if type(name) is not str or name not in RUNTIME_FILENAMES:
        raise OciWorkerEntryError("unsafe_input")
    root_before = _require_directory(root)
    target = root / name
    try:
        before = os.lstat(target)
    except OSError:
        raise OciWorkerEntryError("input_unavailable") from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
    ):
        raise OciWorkerEntryError("unsafe_input")
    if before.st_size < 1 or before.st_size > maximum_bytes:
        raise OciWorkerEntryError("limit_exceeded")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError:
        raise OciWorkerEntryError("input_unavailable") from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size > maximum_bytes
        ):
            raise OciWorkerEntryError("unsafe_input")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise OciWorkerEntryError("limit_exceeded")
        finished = os.fstat(descriptor)
        if _identity(finished) != _identity(opened) or consumed != opened.st_size:
            raise OciWorkerEntryError("input_changed")
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    root_after = _require_directory(root)
    try:
        after = os.lstat(target)
    except OSError:
        raise OciWorkerEntryError("input_changed") from None
    if _identity(root_after) != _identity(root_before) or _identity(after) != _identity(before):
        raise OciWorkerEntryError("input_changed")
    return payload


def _assert_exact_runtime_members(root: Path) -> None:
    _require_directory(root)
    try:
        names = {entry.name for entry in os.scandir(root)}
    except OSError:
        raise OciWorkerEntryError("input_unavailable") from None
    if names != set(RUNTIME_FILENAMES):
        raise OciWorkerEntryError("invalid_contract")


def _runtime_set_sha256(wires: Mapping[str, bytes]) -> str:
    if type(wires) not in (dict, MappingProxyType) or set(wires) != set(
        RUNTIME_FILENAMES
    ):
        raise OciWorkerEntryError("invalid_contract")
    digest = hashlib.sha256()
    digest.update(RUNTIME_SET_DIGEST_DOMAIN)
    for name in RUNTIME_FILENAMES:
        payload = wires[name]
        if type(payload) is not bytes:
            raise OciWorkerEntryError("invalid_contract")
        digest.update(b"F\0")
        digest.update(name.encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()


def _load_runtime_bundle(root: Path) -> _RuntimeBundle:
    _assert_exact_runtime_members(root)
    request_wire = _read_bounded_regular(
        root, REQUEST_FILENAME, maximum_bytes=REQUEST_MAX_BYTES
    )
    request = OciWorkerRequestV1.from_bytes(request_wire)
    handoff_wire = _read_bounded_regular(
        root, HANDOFF_FILENAME, maximum_bytes=WORKER_HANDOFF_MAX_BYTES
    )
    try:
        handoff = WorkerHandoffV1.from_bytes(
            handoff_wire,
            expected_sha256=request.handoff_sha256,
            expected_wire_sha256=request.handoff_wire_sha256,
        )
    except (AttributeError, TypeError, ValueError, WorkerHandoffError):
        raise OciWorkerEntryError("invalid_handoff") from None
    d2_wire = _read_bounded_regular(
        root, D2_REPLAY_FILENAME, maximum_bytes=REPLAY_CONFIG_MAX_BYTES
    )
    d3_wire = _read_bounded_regular(
        root, D3_REPLAY_FILENAME, maximum_bytes=REPLAY_CONFIG_MAX_BYTES
    )
    d2_config = OciReplayConfigV1.from_bytes(d2_wire)
    d3_config = OciReplayConfigV1.from_bytes(d3_wire)
    if (
        handoff.task.task_id != request.task_id
        or handoff.task.snapshot_id != request.snapshot_id
        or handoff.task.snapshot_manifest_sha256
        != request.snapshot_manifest_sha256
        or handoff.task.snapshot_content_root != request.snapshot_content_root
        or d2_config.task_id != request.task_id
        or d2_config.role != "d2"
        or d2_config.config_sha256 != request.d2_replay_sha256
        or d2_config.wire_sha256 != request.d2_replay_wire_sha256
        or d3_config.task_id != request.task_id
        or d3_config.role != "d3"
        or d3_config.config_sha256 != request.d3_replay_sha256
        or d3_config.wire_sha256 != request.d3_replay_wire_sha256
    ):
        raise OciWorkerEntryError("digest_mismatch")
    _assert_exact_runtime_members(root)
    return _RuntimeBundle(
        request=request,
        request_wire=request_wire,
        handoff=handoff,
        handoff_wire=handoff_wire,
        d2_config=d2_config,
        d2_wire=d2_wire,
        d3_config=d3_config,
        d3_wire=d3_wire,
    )


def _manifest_directories(handoff: WorkerHandoffV1) -> frozenset[str]:
    result: set[str] = set()
    for record in handoff.files:
        parts = record.path.split("/")
        for depth in range(1, len(parts)):
            result.add("/".join(parts[:depth]))
    return frozenset(result)


def _inventory_source(root: Path, handoff: WorkerHandoffV1) -> None:
    _require_directory(root)
    expected_files = frozenset(item.path for item in handoff.files)
    expected_directories = _manifest_directories(handoff)
    found_files: set[str] = set()
    found_directories: set[str] = set()
    stack: list[tuple[Path, str]] = [(root, "")]
    nodes = 0
    maximum_nodes = len(expected_files) + len(expected_directories) + 1
    while stack:
        directory, relative = stack.pop()
        _require_directory(directory)
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError:
            raise OciWorkerEntryError("source_rejected") from None
        for entry in entries:
            nodes += 1
            if nodes > maximum_nodes:
                raise OciWorkerEntryError("source_rejected")
            if not entry.name or entry.name in {".", ".."} or "\\" in entry.name:
                raise OciWorkerEntryError("source_rejected")
            child_relative = entry.name if not relative else f"{relative}/{entry.name}"
            try:
                # ``DirEntry.stat(...).st_nlink`` is reported as zero by some
                # supported Windows Python builds.  ``lstat`` supplies the
                # stable link count used by the rest of this module.
                value = os.lstat(entry.path)
            except OSError:
                raise OciWorkerEntryError("source_rejected") from None
            if entry.is_symlink() or stat.S_ISLNK(value.st_mode) or _is_reparse(value):
                raise OciWorkerEntryError("source_rejected")
            if stat.S_ISDIR(value.st_mode):
                found_directories.add(child_relative)
                stack.append((Path(entry.path), child_relative))
            elif stat.S_ISREG(value.st_mode) and value.st_nlink == 1:
                found_files.add(child_relative)
            else:
                raise OciWorkerEntryError("source_rejected")
    if found_files != set(expected_files) or found_directories != set(
        expected_directories
    ):
        raise OciWorkerEntryError("source_rejected")


def _verify_worker_tree(root: Path, bundle: _RuntimeBundle) -> None:
    try:
        tree = bind_worker_tree(
            bundle.handoff.task,
            root,
            bundle.handoff_wire,
            expected_handoff_sha256=bundle.handoff.handoff_sha256,
            expected_handoff_wire_sha256=bundle.handoff.wire_sha256,
        )
        tree.finalize()
    except (AttributeError, OSError, TypeError, ValueError, SealedTreeAccessError):
        raise OciWorkerEntryError("source_rejected") from None
    _inventory_source(root, bundle.handoff)


def _read_source_record(root: Path, relative: str, *, size: int, sha256: str) -> bytes:
    if (
        type(relative) is not str
        or not relative
        or relative.startswith("/")
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
        or type(size) is not int
        or size < 0
        or _SHA256_RE.fullmatch(sha256) is None
    ):
        raise OciWorkerEntryError("source_rejected")
    root_before = _require_directory(root)
    current = root
    for part in relative.split("/")[:-1]:
        current = current / part
        _require_directory(current)
    target = root.joinpath(*relative.split("/"))
    try:
        before = os.lstat(target)
    except OSError:
        raise OciWorkerEntryError("source_rejected") from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or before.st_size != size
    ):
        raise OciWorkerEntryError("source_rejected")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError:
        raise OciWorkerEntryError("source_rejected") from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size != size
        ):
            raise OciWorkerEntryError("source_rejected")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        consumed = 0
        while consumed < size:
            chunk = os.read(descriptor, min(64 * 1024, size - consumed))
            if not chunk:
                raise OciWorkerEntryError("source_rejected")
            chunks.append(chunk)
            digest.update(chunk)
            consumed += len(chunk)
        if os.read(descriptor, 1):
            raise OciWorkerEntryError("source_rejected")
        finished = os.fstat(descriptor)
        if (
            _identity(finished) != _identity(opened)
            or digest.hexdigest() != sha256
        ):
            raise OciWorkerEntryError("source_rejected")
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    if _identity(_require_directory(root)) != _identity(root_before):
        raise OciWorkerEntryError("source_rejected")
    return payload


def _write_exclusive(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    if type(path) is not type(Path()) or type(payload) is not bytes:
        raise OciWorkerEntryError("generation_failed")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, mode)
    except OSError:
        raise OciWorkerEntryError("generation_failed") from None
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OciWorkerEntryError("generation_failed")
            offset += written
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size != len(payload):
            raise OciWorkerEntryError("generation_failed")
    finally:
        os.close(descriptor)


def _create_directory(path: Path) -> None:
    try:
        os.mkdir(path, 0o700)
    except OSError:
        raise OciWorkerEntryError("generation_failed") from None
    _require_directory(path)


def _materialize_generation_at(
    input_source_root: Path,
    input_runtime_root: Path,
    generation_root: Path,
) -> bytes:
    """Materialize one generation; production callers use only fixed roots."""

    bundle = _load_runtime_bundle(input_runtime_root)
    _verify_worker_tree(input_source_root, bundle)
    generation_state = _require_directory(generation_root)
    try:
        if next(os.scandir(generation_root), None) is not None:
            raise OciWorkerEntryError("generation_not_empty")
    except OciWorkerEntryError:
        raise
    except OSError:
        raise OciWorkerEntryError("generation_unavailable") from None

    source_output = generation_root / "source"
    runtime_output = generation_root / "runtime"
    _create_directory(source_output)
    _create_directory(runtime_output)

    directories = sorted(
        _manifest_directories(bundle.handoff),
        key=lambda value: (value.count("/"), value),
    )
    for relative in directories:
        _create_directory(source_output.joinpath(*relative.split("/")))
    for record in bundle.handoff.files:
        payload = _read_source_record(
            input_source_root,
            record.path,
            size=record.size,
            sha256=record.sha256,
        )
        target = source_output.joinpath(*record.path.split("/"))
        _write_exclusive(target, payload)
        try:
            os.chmod(target, 0o444)
        except OSError:
            raise OciWorkerEntryError("generation_failed") from None

    wires = {
        REQUEST_FILENAME: bundle.request_wire,
        HANDOFF_FILENAME: bundle.handoff_wire,
        D2_REPLAY_FILENAME: bundle.d2_wire,
        D3_REPLAY_FILENAME: bundle.d3_wire,
    }
    for name in RUNTIME_FILENAMES:
        target = runtime_output / name
        _write_exclusive(target, wires[name])
        try:
            os.chmod(target, 0o444)
        except OSError:
            raise OciWorkerEntryError("generation_failed") from None

    generated_bundle = _load_runtime_bundle(runtime_output)
    if generated_bundle != bundle:
        raise OciWorkerEntryError("generation_failed")
    _verify_worker_tree(source_output, generated_bundle)
    for relative in sorted(directories, key=lambda value: (-value.count("/"), value)):
        try:
            os.chmod(source_output.joinpath(*relative.split("/")), 0o555)
        except OSError:
            raise OciWorkerEntryError("generation_failed") from None
    try:
        os.chmod(source_output, 0o555)
        os.chmod(runtime_output, 0o555)
    except OSError:
        raise OciWorkerEntryError("generation_failed") from None

    try:
        members = {entry.name for entry in os.scandir(generation_root)}
    except OSError:
        raise OciWorkerEntryError("generation_failed") from None
    if members != {"runtime", "source"}:
        raise OciWorkerEntryError("generation_failed")
    if _directory_identity(_require_directory(generation_root)) != _directory_identity(
        generation_state
    ):
        raise OciWorkerEntryError("generation_failed")
    _assert_exact_runtime_members(runtime_output)
    _inventory_source(source_output, bundle.handoff)

    receipt = GenerationReceiptV1(
        task_id=bundle.request.task_id,
        snapshot_id=bundle.request.snapshot_id,
        snapshot_manifest_sha256=bundle.request.snapshot_manifest_sha256,
        snapshot_content_root=bundle.request.snapshot_content_root,
        request_sha256=bundle.request.request_sha256,
        request_wire_sha256=bundle.request.wire_sha256,
        handoff_sha256=bundle.handoff.handoff_sha256,
        handoff_wire_sha256=bundle.handoff.wire_sha256,
        d2_replay_sha256=bundle.d2_config.config_sha256,
        d2_replay_wire_sha256=bundle.d2_config.wire_sha256,
        d3_replay_sha256=bundle.d3_config.config_sha256,
        d3_replay_wire_sha256=bundle.d3_config.wire_sha256,
        runtime_set_sha256=_runtime_set_sha256(wires),
        file_count=bundle.handoff.file_count,
        total_bytes=bundle.handoff.total_bytes,
    )
    return receipt.to_bytes()


def _read_fixed_kernel_file(path: str, *, maximum_bytes: int) -> bytes:
    if type(path) is not str or path not in {
        "/proc/self/mountinfo",
        "/proc/self/status",
    }:
        raise OciWorkerEntryError("runtime_probe_failed")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise OciWorkerEntryError("runtime_probe_failed") from None
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > maximum_bytes:
            raise OciWorkerEntryError("runtime_probe_failed")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise OciWorkerEntryError("runtime_probe_failed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _decode_mount_component(value: str) -> str:
    # mountinfo uses these four octal escapes; accepting anything else would
    # make an exact destination comparison ambiguous.
    result = value
    for encoded, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        result = result.replace(encoded, decoded)
    if "\\" in result:
        raise OciWorkerEntryError("runtime_probe_failed")
    return result


def _mount_options() -> dict[str, frozenset[str]]:
    try:
        text = _read_fixed_kernel_file(
            "/proc/self/mountinfo", maximum_bytes=1024 * 1024
        ).decode("utf-8", errors="strict")
    except UnicodeError:
        raise OciWorkerEntryError("runtime_probe_failed") from None
    mounts: dict[str, frozenset[str]] = {}
    for line in text.splitlines():
        fields = line.split(" ")
        if len(fields) < 10 or "-" not in fields:
            raise OciWorkerEntryError("runtime_probe_failed")
        mountpoint = _decode_mount_component(fields[4])
        options = frozenset(fields[5].split(","))
        if mountpoint in mounts:
            raise OciWorkerEntryError("runtime_probe_failed")
        mounts[mountpoint] = options
    return mounts


def _assert_write_blocked(path: Path, *, existing: bool) -> None:
    flags = os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not existing:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        if error.errno in _BLOCKED_WRITE_ERRNOS:
            return
        raise OciWorkerEntryError("runtime_probe_failed") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not existing:
        try:
            os.unlink(path)
        except OSError:
            pass
    raise OciWorkerEntryError("runtime_probe_failed")


def _assert_path_absent(path: str) -> None:
    try:
        os.lstat(path)
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ENOTDIR}:
            return
        raise OciWorkerEntryError("runtime_probe_failed") from None
    raise OciWorkerEntryError("runtime_probe_failed")


def _assert_empty_root_owned_directory(path: str) -> None:
    """Verify a detached bind target without following or reopening its path."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise OciWorkerEntryError("runtime_probe_failed") from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or stat.S_IMODE(before.st_mode) & 0o022
            or os.listdir(descriptor)
        ):
            raise OciWorkerEntryError("runtime_probe_failed")
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mode != after.st_mode
            or before.st_uid != after.st_uid
            or before.st_gid != after.st_gid
        ):
            raise OciWorkerEntryError("runtime_probe_failed")
    except OSError:
        raise OciWorkerEntryError("runtime_probe_failed") from None
    finally:
        os.close(descriptor)


def _assert_literal_network_blocked() -> None:
    probes = (
        (socket.AF_INET, ("192.0.2.1", 9)),
        (socket.AF_INET6, ("2001:db8::1", 9, 0, 0)),
    )
    for family, address in probes:
        try:
            channel = socket.socket(family, socket.SOCK_STREAM)
        except OSError as error:
            if error.errno in _BLOCKED_NETWORK_ERRNOS:
                continue
            raise OciWorkerEntryError("runtime_probe_failed") from None
        try:
            channel.settimeout(0.1)
            result = channel.connect_ex(address)
        except OSError as error:
            if error.errno in _BLOCKED_NETWORK_ERRNOS:
                continue
            raise OciWorkerEntryError("runtime_probe_failed") from None
        finally:
            channel.close()
        if result not in _BLOCKED_NETWORK_ERRNOS:
            raise OciWorkerEntryError("runtime_probe_failed")


def _runtime_self_check(
    source_root: Path,
    runtime_root: Path,
    handoff: WorkerHandoffV1,
) -> None:
    if os.name != "posix":
        raise OciWorkerEntryError("runtime_platform_probe_failed")
    if (
        os.fspath(source_root) != "/vulngym/source"
        or os.fspath(runtime_root) != "/vulngym/runtime"
    ):
        raise OciWorkerEntryError("runtime_identity_probe_failed")
    try:
        status = _read_fixed_kernel_file(
            "/proc/self/status", maximum_bytes=64 * 1024
        ).decode("ascii", errors="strict")
    except (OciWorkerEntryError, UnicodeError):
        raise OciWorkerEntryError("runtime_status_probe_failed") from None
    observed: dict[str, str] = {}
    for line in status.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in {"CapEff", "Gid", "NoNewPrivs", "NSpid", "Seccomp", "Uid"}:
            if key in observed:
                raise OciWorkerEntryError("runtime_status_probe_failed")
            observed[key] = value.strip()
    try:
        capabilities = int(observed["CapEff"], 16)
    except (KeyError, ValueError):
        raise OciWorkerEntryError("runtime_status_probe_failed") from None
    uid_fields = observed.get("Uid", "").split()
    gid_fields = observed.get("Gid", "").split()
    nspid_fields = observed.get("NSpid", "").split()
    getuid = getattr(os, "getuid", None)
    geteuid = getattr(os, "geteuid", None)
    getgid = getattr(os, "getgid", None)
    getegid = getattr(os, "getegid", None)
    if (
        capabilities != 0
        or observed.get("NoNewPrivs") != "1"
        or observed.get("Seccomp") != "2"
        or uid_fields != ["65532", "65532", "65532", "65532"]
        or gid_fields != ["65532", "65532", "65532", "65532"]
        or not nspid_fields
        or nspid_fields[-1] != "1"
        or not callable(getuid)
        or not callable(geteuid)
        or not callable(getgid)
        or not callable(getegid)
        or getuid() != 65532
        or geteuid() != 65532
        or getgid() != 65532
        or getegid() != 65532
    ):
        raise OciWorkerEntryError("runtime_identity_probe_failed")

    try:
        mounts = _mount_options()
    except OciWorkerEntryError:
        raise OciWorkerEntryError("runtime_mount_probe_failed") from None
    root_options = mounts.get("/")
    tmp_options = mounts.get("/tmp")
    if (
        root_options is None
        or "ro" not in root_options
        or "rw" in root_options
        or "/vulngym" in mounts
        or any(path in mounts for path in _EMPTY_INPUT_MOUNTPOINTS)
        or tmp_options is None
        or "rw" not in tmp_options
        or "ro" in tmp_options
        or not {"nodev", "noexec", "nosuid"}.issubset(tmp_options)
    ):
        raise OciWorkerEntryError("runtime_mount_probe_failed")

    first_source = source_root.joinpath(*handoff.files[0].path.split("/"))
    try:
        _assert_write_blocked(first_source, existing=True)
        _assert_write_blocked(runtime_root / REQUEST_FILENAME, existing=True)
        _assert_write_blocked(source_root / ".vulngym-write-probe", existing=False)
        _assert_write_blocked(runtime_root / ".vulngym-write-probe", existing=False)
        _assert_write_blocked(Path("/.vulngym-rootfs-write-probe"), existing=False)
    except OciWorkerEntryError:
        raise OciWorkerEntryError("runtime_write_probe_failed") from None
    try:
        for path in _FORBIDDEN_RUNTIME_PATHS:
            _assert_path_absent(path)
        for path in _EMPTY_INPUT_MOUNTPOINTS:
            _assert_empty_root_owned_directory(path)
    except OciWorkerEntryError:
        raise OciWorkerEntryError("runtime_boundary_probe_failed") from None
    try:
        _assert_literal_network_blocked()
    except OciWorkerEntryError:
        raise OciWorkerEntryError("runtime_network_probe_failed") from None


def _execute_at(runtime_root: Path, source_root: Path) -> bytes:
    """Execute one fixed offline replay run from already materialized roots."""

    bundle = _load_runtime_bundle(runtime_root)
    _runtime_self_check(source_root, runtime_root, bundle.handoff)
    try:
        wire = execute_discovery_worker_v1(
            bundle.handoff_wire,
            expected_handoff_sha256=bundle.handoff.handoff_sha256,
            expected_handoff_wire_sha256=bundle.handoff.wire_sha256,
            tree_root=source_root,
            d2_backend=bundle.d2_config.build_backend(),
            d3_backend=bundle.d3_config.build_backend(),
        )
    except IsolatedWorkerError as error:
        raise OciWorkerEntryError(error.code) from None
    except (AttributeError, OSError, RecursionError, RuntimeError, TypeError, ValueError):
        raise OciWorkerEntryError("run_failed") from None
    if type(wire) is not bytes or not wire:
        raise OciWorkerEntryError("invalid_output")
    return wire


def _error_payload(mode: str, code: str) -> bytes:
    mode_value = mode if mode in {"execute", "materialize"} else "cli"
    code_value = code if _ERROR_CODE_RE.fullmatch(code) else "internal_error"
    payload = _canonical_json(
        {
            "code": code_value,
            "contract_version": PROTOCOL_VERSION,
            "kind": WORKER_ERROR_KIND,
            "mode": mode_value,
        }
    ) + b"\n"
    if len(payload) > ERROR_MAX_BYTES:
        return (
            b'{"code":"internal_error","contract_version":1,'
            b'"kind":"vulngym.oci-worker-error.v1","mode":"cli"}\n'
        )
    return payload


def _write_stream(stream: BinaryIO, payload: bytes) -> None:
    written = stream.write(payload)
    if written is not None and written != len(payload):
        raise OciWorkerEntryError("output_failed")
    stream.flush()


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: BinaryIO | None = None,
    stderr: BinaryIO | None = None,
) -> int:
    """Run exactly one fixed mode; no caller-provided paths are accepted."""

    raw_arguments: object = sys.argv[1:] if argv is None else argv
    if type(raw_arguments) not in (list, tuple) or any(
        type(item) is not str for item in raw_arguments
    ):
        arguments: tuple[str, ...] = ()
    else:
        arguments = tuple(raw_arguments)
    mode = arguments[0] if len(arguments) == 1 else "cli"
    out = stdout if stdout is not None else sys.stdout.buffer
    err = stderr if stderr is not None else sys.stderr.buffer
    try:
        if arguments == ("materialize",):
            payload = _materialize_generation_at(
                MATERIALIZE_SOURCE_ROOT,
                MATERIALIZE_RUNTIME_ROOT,
                GENERATION_ROOT,
            )
        elif arguments == ("execute",):
            payload = _execute_at(EXECUTE_RUNTIME_ROOT, EXECUTE_SOURCE_ROOT)
        else:
            raise OciWorkerEntryError("invalid_arguments")
        _write_stream(out, payload)
        return 0
    except OciWorkerEntryError as error:
        code = error.code
    except BaseException:
        code = "internal_error"
    try:
        _write_stream(err, _error_payload(mode, code))
    except BaseException:
        return 3
    return 2


__all__ = [
    "D2_REPLAY_FILENAME",
    "D3_REPLAY_FILENAME",
    "GENERATION_RECEIPT_KIND",
    "GenerationReceiptV1",
    "HANDOFF_FILENAME",
    "MATERIALIZE_RUNTIME_ROOT",
    "MATERIALIZE_SOURCE_ROOT",
    "OCI_WORKER_ENTRY_VERSION",
    "OciReplayConfigV1",
    "OciWorkerEntryError",
    "OciWorkerRequestV1",
    "PROTOCOL_VERSION",
    "REPLAY_CONFIG_KIND",
    "REQUEST_FILENAME",
    "WORKER_REQUEST_KIND",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
