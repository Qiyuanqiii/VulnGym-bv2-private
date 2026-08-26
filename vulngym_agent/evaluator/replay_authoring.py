"""Trusted, credential-free preparation of one ordered D2/D3 replay pair.

This module is intentionally outside the OCI worker.  It authenticates one
already sealed source bundle, deterministically replays an in-progress prefix,
and exposes only the first missing structured model request.  A human or an AI
agent can bind one response to that request and resume from the beginning.

The draft itself is always two canonical :class:`OciReplayConfigV1` files.
Updates use a same-directory atomic replacement.  Finalization performs a
second, pure offline replay through the production backend and publishes the
pair into a new directory; it never accepts a provider, command, network
credential, or caller-selected Python implementation.
"""

from __future__ import annotations

from collections.abc import Mapping
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Final, Literal
import uuid

from vulngym_agent.agents.model_runtime import (
    ModelBlocked,
    ModelRequest,
    ReplayClosureError,
    ReplayResponse,
    ReplayStructuredModelBackend,
)
from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryContractError,
    DiscoveryTaskInputV1,
)
from vulngym_agent.benchmark.producer_contracts import ProducerDeferredV1
from vulngym_agent.benchmark.reviewer_contracts import (
    ReviewerDeferredV1,
    ReviewerFinalizedV1,
)
from vulngym_agent.benchmark.worker_handoff import (
    WorkerHandoffError,
    build_worker_handoff,
)
from vulngym_agent.evaluator.oci_worker_entry import (
    MAX_REPLAY_RESPONSES,
    OciReplayConfigV1,
    OciWorkerEntryError,
    REPLAY_BACKEND_ID,
    REPLAY_CONFIG_MAX_BYTES,
    REPLAY_MODEL_ID,
)
from vulngym_agent.evaluator.worker import (
    IsolatedWorkerError,
    execute_discovery_worker_v1,
)
from vulngym_agent.orchestrator.discovery_pipeline import SourceDiscoveryRunV1


REPLAY_AUTHORING_CONTRACT_VERSION: Final[int] = 1
REPLAY_AUTHORING_PENDING_KIND: Final[str] = (
    "vulngym.replay-authoring-pending-request.v1"
)
REPLAY_AUTHORING_RESPONSE_KIND: Final[str] = (
    "vulngym.replay-authoring-response.v1"
)
REPLAY_AUTHORING_SUMMARY_KIND: Final[str] = "vulngym.replay-authoring-summary.v1"
REPLAY_AUTHORING_D2_FILENAME: Final[str] = "d2.json"
REPLAY_AUTHORING_D3_FILENAME: Final[str] = "d3.json"
REPLAY_AUTHORING_MAX_TASK_BYTES: Final[int] = 32 * 1024
# A model object is bounded at 1 MiB before the request/response authoring
# envelope adds its binding fields.
REPLAY_AUTHORING_MAX_RESPONSE_BYTES: Final[int] = 2 * 1024 * 1024

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z"
)
_DRAFT_NAMES: Final[frozenset[str]] = frozenset(
    {REPLAY_AUTHORING_D2_FILENAME, REPLAY_AUTHORING_D3_FILENAME}
)
_BAD_D2_RESPONSE_REASONS: Final[frozenset[str]] = frozenset(
    {
        "duplicate_candidate",
        "invalid_model_action",
        "invalid_phase_transition",
        "invalid_selection",
        "model_binding_invalid",
    }
)
_BAD_D3_RESPONSE_REASONS: Final[frozenset[str]] = frozenset(
    {"contract.invalid", "runtime.model_failed"}
)


class ReplayAuthoringError(RuntimeError):
    """Stable failure at the trusted replay-authoring boundary."""

    def __init__(
        self, code: str, message: str, *, committed: bool = False
    ) -> None:
        self.code = code if type(code) is str and code else "authoring_failed"
        self.committed = committed is True
        super().__init__(message)


def _canonical_json(value: object) -> bytes:
    def thaw(item: object) -> object:
        if isinstance(item, Mapping):
            return {key: thaw(child) for key, child in item.items()}
        if isinstance(item, tuple):
            return [thaw(child) for child in item]
        return item

    try:
        return json.dumps(
            thaw(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise ReplayAuthoringError(
            "noncanonical_json", "authoring value is not canonical JSON"
        ) from None


def _thaw(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        result = json.loads(_canonical_json(value).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ReplayAuthoringError(
            "noncanonical_json", "authoring object did not normalize"
        ) from None
    if type(result) is not dict:
        raise ReplayAuthoringError(
            "noncanonical_json", "authoring object did not normalize"
        )
    return result


def _reject_constant(_value: str) -> None:
    raise ReplayAuthoringError(
        "noncanonical_json", "authoring JSON contains a non-finite number"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReplayAuthoringError(
                "noncanonical_json", "authoring JSON repeats an object key"
            )
        result[key] = value
    return result


def _parse_canonical_line(payload: bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > maximum_bytes
        or not payload.endswith(b"\n")
        or payload.count(b"\n") != 1
    ):
        raise ReplayAuthoringError(
            "noncanonical_json", "authoring input must be one bounded JSON line"
        )
    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ReplayAuthoringError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise ReplayAuthoringError(
            "noncanonical_json", "authoring input is not strict JSON"
        ) from None
    if type(value) is not dict or _canonical_json(value) + b"\n" != payload:
        raise ReplayAuthoringError(
            "noncanonical_json", "authoring input is not canonical JSON"
        )
    return value


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ReplayAuthoringError(
            "invalid_argument", f"{name} must be lower-case SHA-256"
        )
    return value


def _is_reparse(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", 0),
    )


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        getattr(value, "st_mtime_ns", 0),
    )


def _require_private_directory(path: Path) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError:
        raise ReplayAuthoringError(
            "input_unavailable", "authoring directory is unavailable"
        ) from None
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
        or (os.name == "posix" and value.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    ):
        raise ReplayAuthoringError(
            "unsafe_path", "authoring directory is not private and regular"
        )
    return value


def _canonical_existing_directory(value: object) -> Path:
    if type(value) not in (str, type(Path())):
        raise ReplayAuthoringError(
            "invalid_argument", "authoring root must be an exact path value"
        )
    try:
        path = Path(os.path.abspath(os.fspath(value)))
    except (OSError, TypeError, ValueError):
        raise ReplayAuthoringError(
            "invalid_argument", "authoring root path is invalid"
        ) from None
    _require_private_directory(path)
    return path


def _canonical_new_directory(value: object) -> tuple[Path, Path]:
    if type(value) not in (str, type(Path())):
        raise ReplayAuthoringError(
            "invalid_argument", "authoring output must be an exact path value"
        )
    try:
        path = Path(os.path.abspath(os.fspath(value)))
    except (OSError, TypeError, ValueError):
        raise ReplayAuthoringError(
            "invalid_argument", "authoring output path is invalid"
        ) from None
    if path.parent == path or path.name in {"", ".", ".."}:
        raise ReplayAuthoringError(
            "invalid_argument", "authoring output must be a named child"
        )
    _require_private_directory(path.parent)
    try:
        os.lstat(path)
    except FileNotFoundError:
        return path, path.parent
    except OSError:
        raise ReplayAuthoringError(
            "output_unavailable", "authoring output state is unavailable"
        ) from None
    raise ReplayAuthoringError(
        "output_exists", "authoring output already exists"
    )


@dataclass(frozen=True, slots=True)
class _DirectoryGuard:
    path: Path
    object_identity: tuple[int, int, int]
    chain: tuple[tuple[Path, tuple[int, int]], ...]


def _directory_chain(path: Path) -> tuple[Path, ...]:
    return tuple(reversed(path.parents)) + (path,)


def _guard_existing_directory(path: Path) -> _DirectoryGuard:
    checked: list[tuple[Path, tuple[int, int]]] = []
    for component in _directory_chain(path):
        try:
            state = os.lstat(component)
        except OSError:
            raise ReplayAuthoringError(
                "input_unavailable", "authoring directory chain is unavailable"
            ) from None
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
        ):
            raise ReplayAuthoringError(
                "unsafe_path", "authoring directory chain is unsafe"
            )
        checked.append((component, (state.st_dev, state.st_ino)))
    final = _require_private_directory(path)
    return _DirectoryGuard(
        path=path,
        object_identity=(final.st_dev, final.st_ino, final.st_mode),
        chain=tuple(checked),
    )


def _assert_directory_guard(guard: _DirectoryGuard) -> None:
    if type(guard) is not _DirectoryGuard:
        raise ReplayAuthoringError(
            "invalid_argument", "authoring directory guard is invalid"
        )
    for component, expected in guard.chain:
        try:
            state = os.lstat(component)
        except OSError:
            raise ReplayAuthoringError(
                "input_changed", "authoring directory chain changed"
            ) from None
        if (
            not stat.S_ISDIR(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
            or (state.st_dev, state.st_ino) != expected
        ):
            raise ReplayAuthoringError(
                "input_changed", "authoring directory chain changed"
            )
    final = _require_private_directory(guard.path)
    if (final.st_dev, final.st_ino, final.st_mode) != guard.object_identity:
        raise ReplayAuthoringError(
            "input_changed", "authoring directory identity changed"
        )


def _normalized_path(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _assert_disjoint_domains(
    left: Path,
    right: Path,
    *,
    left_guard: _DirectoryGuard | None = None,
    right_guard: _DirectoryGuard | None = None,
) -> None:
    left_text = _normalized_path(left)
    right_text = _normalized_path(right)
    try:
        common = os.path.commonpath((left_text, right_text))
    except ValueError:
        common = ""
    aliases = False
    if left_guard is not None and right_guard is not None:
        left_final = left_guard.object_identity[:2]
        right_final = right_guard.object_identity[:2]
        left_chain = frozenset(identity for _path, identity in left_guard.chain)
        right_chain = frozenset(identity for _path, identity in right_guard.chain)
        # A bind mount or other filesystem alias can give two lexically
        # unrelated paths the identity of the other domain or one of its
        # ancestors.  Comparing only the two final objects would miss that
        # ancestor/descendant alias.
        aliases = left_final in right_chain or right_final in left_chain
    if common in {left_text, right_text} or aliases:
        raise ReplayAuthoringError(
            "path_overlap", "authoring control domains overlap"
        )


def _assert_new_child_disjoint(
    output: Path,
    *,
    output_parent_guard: _DirectoryGuard,
    protected_guard: _DirectoryGuard,
) -> None:
    """Reject a not-yet-created output that is physically under a domain."""

    _assert_disjoint_domains(output, protected_guard.path)
    parent_chain = frozenset(
        identity for _path, identity in output_parent_guard.chain
    )
    if protected_guard.object_identity[:2] in parent_chain:
        raise ReplayAuthoringError(
            "path_overlap", "authoring control domains overlap"
        )


def _execution_domain_guards(
    sealed_bundle_root: str | os.PathLike[str], draft_root: Path
) -> tuple[_DirectoryGuard, _DirectoryGuard]:
    sealed = _canonical_existing_directory(sealed_bundle_root)
    sealed_guard = _guard_existing_directory(sealed)
    draft_guard = _guard_existing_directory(draft_root)
    _assert_disjoint_domains(
        sealed,
        draft_root,
        left_guard=sealed_guard,
        right_guard=draft_guard,
    )
    return sealed_guard, draft_guard


def _read_private_regular(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        before = os.lstat(path)
    except OSError:
        raise ReplayAuthoringError(
            "input_unavailable", "authoring input file is unavailable"
        ) from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > maximum_bytes
        or (os.name == "posix" and before.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    ):
        raise ReplayAuthoringError(
            "unsafe_path", "authoring input is not a bounded private regular file"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ReplayAuthoringError(
            "input_unavailable", "authoring input could not be opened"
        ) from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink != 1
            or _file_identity(opened) != _file_identity(before)
        ):
            raise ReplayAuthoringError(
                "input_changed", "authoring input changed before opening"
            )
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(
                descriptor, min(64 * 1024, maximum_bytes + 1 - consumed)
            )
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise ReplayAuthoringError(
                    "limit_exceeded", "authoring input exceeds its byte limit"
                )
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if _file_identity(after) != _file_identity(opened) or consumed != opened.st_size:
            raise ReplayAuthoringError(
                "input_changed", "authoring input changed while reading"
            )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        raise ReplayAuthoringError(
            "publication_failed", "authoring output member could not be created"
        ) from None
    failure: BaseException | None = None
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except BaseException as error:
        failure = error
    try:
        os.close(descriptor)
    except BaseException as error:
        if failure is None:
            failure = error
    if failure is not None:
        try:
            state = os.lstat(path)
            if (
                stat.S_ISREG(state.st_mode)
                and not stat.S_ISLNK(state.st_mode)
                and not _is_reparse(state)
                and state.st_nlink == 1
            ):
                os.unlink(path)
        except OSError:
            pass
        raise failure


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish one directory without replacing a raced target."""

    if os.name == "posix":
        try:
            renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
        except (AttributeError, OSError):
            renameat2 = None
        if renameat2 is None:
            raise OSError(errno.ENOTSUP, "atomic no-replace rename is unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,
            os.fsencode(source),
            -100,
            os.fsencode(destination),
            1,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise FileExistsError(str(destination))
        raise OSError(error_number, "atomic replay publication failed")
    try:
        os.lstat(destination)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(str(destination))
    os.rename(source, destination)


def _scan_draft_root(root: Path) -> tuple[int, ...]:
    before = _require_private_directory(root)
    try:
        with os.scandir(root) as entries:
            names = frozenset(entry.name for entry in entries)
    except OSError:
        raise ReplayAuthoringError(
            "input_unavailable", "authoring draft could not be enumerated"
        ) from None
    after = _require_private_directory(root)
    if _directory_identity(before) != _directory_identity(after):
        raise ReplayAuthoringError(
            "input_changed", "authoring draft changed while enumerating"
        )
    if names != _DRAFT_NAMES:
        raise ReplayAuthoringError(
            "layout_invalid", "authoring draft membership is invalid"
        )
    return _directory_identity(after)


@dataclass(frozen=True, slots=True)
class ReplayAuthoringPendingRequestV1:
    """The sole next request authorized by the current replay prefix."""

    task_id: str
    role: Literal["d2", "d3"]
    stage: str
    payload: Mapping[str, Any]
    request_sha256: str
    occurrence: int
    prefix_config_sha256: str
    contract_version: int = REPLAY_AUTHORING_CONTRACT_VERSION
    kind: str = REPLAY_AUTHORING_PENDING_KIND

    def __post_init__(self) -> None:
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.role) is not str
            or self.role not in {"d2", "d3"}
            or type(self.stage) is not str
            or type(self.occurrence) is not int
            or not 1 <= self.occurrence <= MAX_REPLAY_RESPONSES + 1
            or type(self.contract_version) is not int
            or self.contract_version != REPLAY_AUTHORING_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != REPLAY_AUTHORING_PENDING_KIND
        ):
            raise ReplayAuthoringError(
                "invalid_contract", "pending authoring request header is invalid"
            )
        try:
            frozen = ReplayResponse(
                stage=self.stage, request=self.payload, response={}
            )
        except (AttributeError, RecursionError, TypeError, ValueError):
            raise ReplayAuthoringError(
                "invalid_contract", "pending authoring request is invalid"
            ) from None
        if (
            type(self.request_sha256) is not str
            or self.request_sha256 != frozen.request_sha256
        ):
            raise ReplayAuthoringError(
                "invalid_binding", "pending request digest does not bind its payload"
            )
        _require_sha256(
            self.prefix_config_sha256, name="prefix_config_sha256"
        )
        object.__setattr__(self, "payload", frozen.request)

    @classmethod
    def from_model_request(
        cls,
        request: ModelRequest,
        *,
        role: Literal["d2", "d3"],
        occurrence: int,
        prefix_config_sha256: str,
    ) -> "ReplayAuthoringPendingRequestV1":
        if type(request) is not ModelRequest:
            raise ReplayAuthoringError(
                "invalid_contract", "authoring backend captured an invalid request"
            )
        if request.backend_id != REPLAY_BACKEND_ID or request.model_id != REPLAY_MODEL_ID:
            raise ReplayAuthoringError(
                "invalid_binding", "captured request uses an invalid replay identity"
            )
        return cls(
            task_id=request.task_id,
            role=role,
            stage=request.stage,
            payload=request.payload,
            request_sha256=request.request_sha256,
            occurrence=occurrence,
            prefix_config_sha256=prefix_config_sha256,
        )

    @classmethod
    def from_bytes(cls, payload: bytes) -> "ReplayAuthoringPendingRequestV1":
        raw = _parse_canonical_line(
            payload, maximum_bytes=REPLAY_AUTHORING_MAX_RESPONSE_BYTES
        )
        if frozenset(raw) != frozenset(
            {
                "contract_version",
                "kind",
                "occurrence",
                "payload",
                "prefix_config_sha256",
                "request_sha256",
                "role",
                "stage",
                "status",
                "task_id",
            }
        ) or raw["status"] != "pending":
            raise ReplayAuthoringError(
                "invalid_contract", "pending authoring request fields are invalid"
            )
        result = cls(
            task_id=raw["task_id"],
            role=raw["role"],
            stage=raw["stage"],
            payload=raw["payload"],
            request_sha256=raw["request_sha256"],
            occurrence=raw["occurrence"],
            prefix_config_sha256=raw["prefix_config_sha256"],
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if result.to_bytes() != payload:
            raise ReplayAuthoringError(
                "noncanonical_json", "pending authoring request did not round trip"
            )
        return result

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "kind": self.kind,
            "occurrence": self.occurrence,
            "payload": _thaw(self.payload),
            "prefix_config_sha256": self.prefix_config_sha256,
            "request_sha256": self.request_sha256,
            "role": self.role,
            "stage": self.stage,
            "status": "pending",
            "task_id": self.task_id,
        }

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"


@dataclass(frozen=True, slots=True)
class ReplayAuthoringResponseV1:
    """One externally authored response bound to an exact pending request."""

    task_id: str
    role: Literal["d2", "d3"]
    stage: str
    request_sha256: str
    occurrence: int
    prefix_config_sha256: str
    response: Mapping[str, Any]
    response_sha256: str
    contract_version: int = REPLAY_AUTHORING_CONTRACT_VERSION
    kind: str = REPLAY_AUTHORING_RESPONSE_KIND

    def __post_init__(self) -> None:
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.role) is not str
            or self.role not in {"d2", "d3"}
            or type(self.stage) is not str
            or type(self.occurrence) is not int
            or not 1 <= self.occurrence <= MAX_REPLAY_RESPONSES + 1
            or type(self.contract_version) is not int
            or self.contract_version != REPLAY_AUTHORING_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != REPLAY_AUTHORING_RESPONSE_KIND
        ):
            raise ReplayAuthoringError(
                "invalid_contract", "authoring response header is invalid"
            )
        _require_sha256(self.request_sha256, name="request_sha256")
        _require_sha256(
            self.prefix_config_sha256, name="prefix_config_sha256"
        )
        try:
            frozen = ReplayResponse(
                stage=self.stage, request={}, response=self.response
            )
        except (AttributeError, RecursionError, TypeError, ValueError):
            raise ReplayAuthoringError(
                "invalid_contract", "authoring response body is invalid"
            ) from None
        if (
            type(self.response_sha256) is not str
            or self.response_sha256 != frozen.response_sha256
        ):
            raise ReplayAuthoringError(
                "invalid_binding", "authoring response digest is invalid"
            )
        object.__setattr__(self, "response", frozen.response)

    @classmethod
    def from_pending(
        cls,
        pending: ReplayAuthoringPendingRequestV1,
        response: Mapping[str, Any],
    ) -> "ReplayAuthoringResponseV1":
        """Bind one structured response to an exact emitted request."""

        if type(pending) is not ReplayAuthoringPendingRequestV1:
            raise ReplayAuthoringError(
                "invalid_argument", "pending request has an invalid contract type"
            )
        try:
            frozen = ReplayResponse(
                stage=pending.stage,
                request=pending.payload,
                response=response,
            )
        except (AttributeError, RecursionError, TypeError, ValueError):
            raise ReplayAuthoringError(
                "invalid_contract", "authoring response body is invalid"
            ) from None
        return cls(
            task_id=pending.task_id,
            role=pending.role,
            stage=pending.stage,
            request_sha256=pending.request_sha256,
            occurrence=pending.occurrence,
            prefix_config_sha256=pending.prefix_config_sha256,
            response=frozen.response,
            response_sha256=frozen.response_sha256,
        )

    @classmethod
    def from_bytes(cls, payload: bytes) -> "ReplayAuthoringResponseV1":
        raw = _parse_canonical_line(
            payload, maximum_bytes=REPLAY_AUTHORING_MAX_RESPONSE_BYTES
        )
        if frozenset(raw) != frozenset(
            {
                "contract_version",
                "kind",
                "occurrence",
                "prefix_config_sha256",
                "request_sha256",
                "response",
                "response_sha256",
                "role",
                "stage",
                "task_id",
            }
        ):
            raise ReplayAuthoringError(
                "invalid_contract", "authoring response fields are invalid"
            )
        result = cls(
            task_id=raw["task_id"],
            role=raw["role"],
            stage=raw["stage"],
            request_sha256=raw["request_sha256"],
            occurrence=raw["occurrence"],
            prefix_config_sha256=raw["prefix_config_sha256"],
            response=raw["response"],
            response_sha256=raw["response_sha256"],
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if result.to_bytes() != payload:
            raise ReplayAuthoringError(
                "noncanonical_json", "authoring response did not round trip"
            )
        return result

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "kind": self.kind,
            "occurrence": self.occurrence,
            "prefix_config_sha256": self.prefix_config_sha256,
            "request_sha256": self.request_sha256,
            "response": _thaw(self.response),
            "response_sha256": self.response_sha256,
            "role": self.role,
            "stage": self.stage,
            "task_id": self.task_id,
        }

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"


@dataclass(frozen=True, slots=True)
class ReplayAuthoringSummaryV1:
    """Path-free state after initialization, update, closure, or publication."""

    task_id: str
    status: Literal["initialized", "updated", "closed", "published"]
    d2_response_count: int
    d3_response_count: int
    d2_config_sha256: str
    d2_wire_sha256: str
    d3_config_sha256: str
    d3_wire_sha256: str
    run_outcome: Literal[
        "not_run", "d2_deferred", "d3_deferred", "finalized"
    ]
    candidate_count: int
    finding_count: int
    reviewer_verdict_count: int
    reviewer_accept_count: int
    reviewer_reject_count: int
    reviewer_defer_count: int
    run_sha256: str | None = None
    run_wire_sha256: str | None = None
    contract_version: int = REPLAY_AUTHORING_CONTRACT_VERSION
    kind: str = REPLAY_AUTHORING_SUMMARY_KIND

    def __post_init__(self) -> None:
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.status) is not str
            or self.status not in {"initialized", "updated", "closed", "published"}
            or type(self.d2_response_count) is not int
            or type(self.d3_response_count) is not int
            or not 0 <= self.d2_response_count <= MAX_REPLAY_RESPONSES
            or not 0 <= self.d3_response_count <= MAX_REPLAY_RESPONSES
            or type(self.run_outcome) is not str
            or self.run_outcome
            not in {"not_run", "d2_deferred", "d3_deferred", "finalized"}
            or type(self.contract_version) is not int
            or self.contract_version != REPLAY_AUTHORING_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != REPLAY_AUTHORING_SUMMARY_KIND
        ):
            raise ReplayAuthoringError(
                "invalid_contract", "authoring summary header is invalid"
            )
        counts = (
            self.candidate_count,
            self.finding_count,
            self.reviewer_verdict_count,
            self.reviewer_accept_count,
            self.reviewer_reject_count,
            self.reviewer_defer_count,
        )
        if any(type(value) is not int or not 0 <= value <= 64 for value in counts):
            raise ReplayAuthoringError(
                "invalid_contract", "authoring outcome counts are invalid"
            )
        if (
            self.reviewer_accept_count
            + self.reviewer_reject_count
            + self.reviewer_defer_count
            != self.reviewer_verdict_count
            or self.finding_count != self.reviewer_accept_count
            or self.finding_count > self.candidate_count
        ):
            raise ReplayAuthoringError(
                "invalid_contract", "authoring outcome counts do not close"
            )
        for value, name in (
            (self.d2_config_sha256, "d2_config_sha256"),
            (self.d2_wire_sha256, "d2_wire_sha256"),
            (self.d3_config_sha256, "d3_config_sha256"),
            (self.d3_wire_sha256, "d3_wire_sha256"),
        ):
            _require_sha256(value, name=name)
        closed = self.status in {"closed", "published"}
        if closed:
            _require_sha256(self.run_sha256, name="run_sha256")
            _require_sha256(self.run_wire_sha256, name="run_wire_sha256")
            if self.run_outcome == "not_run":
                raise ReplayAuthoringError(
                    "invalid_contract", "closed summary must expose a run outcome"
                )
        elif self.run_sha256 is not None or self.run_wire_sha256 is not None:
            raise ReplayAuthoringError(
                "invalid_contract", "open authoring summary cannot bind a run"
            )
        elif self.run_outcome != "not_run" or any(counts):
            raise ReplayAuthoringError(
                "invalid_contract", "open summary cannot expose run outcomes"
            )
        if self.run_outcome == "d2_deferred" and (
            any(counts) or self.d3_response_count != 0
        ):
            raise ReplayAuthoringError(
                "invalid_contract", "D2 deferral outcome is inconsistent"
            )
        if self.run_outcome == "d3_deferred" and self.reviewer_verdict_count != 0:
            raise ReplayAuthoringError(
                "invalid_contract", "D3 deferral cannot expose partial verdicts"
            )
        if self.run_outcome == "finalized" and (
            self.candidate_count != self.reviewer_verdict_count
        ):
            raise ReplayAuthoringError(
                "invalid_contract", "finalized reviewer coverage is incomplete"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "candidate_count": self.candidate_count,
            "d2_config_sha256": self.d2_config_sha256,
            "d2_response_count": self.d2_response_count,
            "d2_wire_sha256": self.d2_wire_sha256,
            "d3_config_sha256": self.d3_config_sha256,
            "d3_response_count": self.d3_response_count,
            "d3_wire_sha256": self.d3_wire_sha256,
            "finding_count": self.finding_count,
            "kind": self.kind,
            "run_sha256": self.run_sha256,
            "run_outcome": self.run_outcome,
            "run_wire_sha256": self.run_wire_sha256,
            "reviewer_accept_count": self.reviewer_accept_count,
            "reviewer_defer_count": self.reviewer_defer_count,
            "reviewer_reject_count": self.reviewer_reject_count,
            "reviewer_verdict_count": self.reviewer_verdict_count,
            "status": self.status,
            "task_id": self.task_id,
        }

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"


ReplayAuthoringStepV1 = ReplayAuthoringPendingRequestV1 | ReplayAuthoringSummaryV1


class _PrefixCaptureBackend:
    """Trusted wrapper that retains only the first request past a valid prefix."""

    __slots__ = (
        "_backend",
        "_occurrences",
        "_pending",
        "_prefix_config_sha256",
        "_role",
    )

    def __init__(
        self, config: OciReplayConfigV1, *, role: Literal["d2", "d3"]
    ) -> None:
        if type(config) is not OciReplayConfigV1 or config.role != role:
            raise ReplayAuthoringError(
                "draft_invalid", "authoring prefix has an invalid role"
            )
        self._backend = config.build_backend()
        occurrences: dict[tuple[str, str], int] = {}
        for item in config.responses:
            key = (item.stage, item.request_sha256)
            occurrences[key] = occurrences.get(key, 0) + 1
        self._occurrences = occurrences
        self._pending: ReplayAuthoringPendingRequestV1 | None = None
        self._prefix_config_sha256 = config.config_sha256
        self._role = role

    @property
    def backend_id(self) -> str:
        return self._backend.backend_id

    @property
    def model_id(self) -> str:
        return self._backend.model_id

    @property
    def pending(self) -> ReplayAuthoringPendingRequestV1 | None:
        return self._pending

    @property
    def invocation_count(self) -> int:
        return self._backend.invocation_count

    def invoke(self, request: ModelRequest) -> Mapping[str, Any]:
        try:
            return self._backend.invoke(request)
        except ModelBlocked as error:
            if error.error_code == "replay_miss":
                if self._pending is not None:
                    raise ReplayAuthoringError(
                        "draft_invalid", "authoring run produced multiple pending requests"
                    ) from None
                self._pending = ReplayAuthoringPendingRequestV1.from_model_request(
                    request,
                    role=self._role,
                    occurrence=(
                        self._occurrences.get(
                            (request.stage, request.request_sha256), 0
                        )
                        + 1
                    ),
                    prefix_config_sha256=self._prefix_config_sha256,
                )
            raise

    def assert_prefix_closed(self) -> None:
        if self._pending is None:
            self._backend.assert_exact_closure()
            return
        if (
            self._backend.remaining_sequence
            or self._backend.consumed_sequence != self._backend.registered_sequence
            or self._backend.invocation_count
            != len(self._backend.registered_sequence) + 1
        ):
            raise ReplayAuthoringError(
                "draft_invalid", "authoring responses are not an exact runtime prefix"
            )


def _summary(
    d2: OciReplayConfigV1,
    d3: OciReplayConfigV1,
    *,
    status: Literal["initialized", "updated", "closed", "published"],
    run: SourceDiscoveryRunV1 | None = None,
) -> ReplayAuthoringSummaryV1:
    if d2.task_id != d3.task_id:
        raise ReplayAuthoringError(
            "draft_invalid", "authoring pair does not bind one task"
        )
    wire = None if run is None else run.to_wire()
    run_outcome: Literal[
        "not_run", "d2_deferred", "d3_deferred", "finalized"
    ] = "not_run"
    candidate_count = 0
    finding_count = 0
    reviewer_verdict_count = 0
    reviewer_accept_count = 0
    reviewer_reject_count = 0
    reviewer_defer_count = 0
    if run is not None:
        if type(run.producer_result) is ProducerDeferredV1:
            run_outcome = "d2_deferred"
        else:
            candidate_count = len(run.producer_result.candidates)
            reviewer = run.reviewer_result
            if type(reviewer) is ReviewerDeferredV1:
                run_outcome = "d3_deferred"
            elif type(reviewer) is ReviewerFinalizedV1:
                run_outcome = "finalized"
                reviewer_verdict_count = len(reviewer.verdicts)
                reviewer_accept_count = sum(
                    item.decision == "accept" for item in reviewer.verdicts
                )
                reviewer_reject_count = sum(
                    item.decision == "reject" for item in reviewer.verdicts
                )
                reviewer_defer_count = sum(
                    item.decision == "defer" for item in reviewer.verdicts
                )
                finding_count = len(run.discovery_result.emitted_candidates)
            else:
                raise ReplayAuthoringError(
                    "execution_failed", "authoring run reviewer outcome is invalid"
                )
    return ReplayAuthoringSummaryV1(
        task_id=d2.task_id,
        status=status,
        d2_response_count=len(d2.responses),
        d3_response_count=len(d3.responses),
        d2_config_sha256=d2.config_sha256,
        d2_wire_sha256=d2.wire_sha256,
        d3_config_sha256=d3.config_sha256,
        d3_wire_sha256=d3.wire_sha256,
        run_outcome=run_outcome,
        candidate_count=candidate_count,
        finding_count=finding_count,
        reviewer_verdict_count=reviewer_verdict_count,
        reviewer_accept_count=reviewer_accept_count,
        reviewer_reject_count=reviewer_reject_count,
        reviewer_defer_count=reviewer_defer_count,
        run_sha256=None if run is None else run.run_sha256,
        run_wire_sha256=None if wire is None else hashlib.sha256(wire).hexdigest(),
    )


def _validated_static_pair(
    d2: OciReplayConfigV1, d3: OciReplayConfigV1
) -> tuple[OciReplayConfigV1, OciReplayConfigV1]:
    if type(d2) is not OciReplayConfigV1 or type(d3) is not OciReplayConfigV1:
        raise ReplayAuthoringError(
            "invalid_argument", "replay pair must use exact OCI config contracts"
        )
    try:
        canonical_d2 = OciReplayConfigV1.from_bytes(d2.to_bytes())
        canonical_d3 = OciReplayConfigV1.from_bytes(d3.to_bytes())
    except (AttributeError, OciWorkerEntryError, TypeError, ValueError):
        raise ReplayAuthoringError(
            "draft_invalid", "replay pair did not pass static normalization"
        ) from None
    if (
        canonical_d2 != d2
        or canonical_d3 != d3
        or d2.task_id != d3.task_id
        or d2.role != "d2"
        or d3.role != "d3"
        or d2.backend_id != REPLAY_BACKEND_ID
        or d3.backend_id != REPLAY_BACKEND_ID
        or d2.model_id != REPLAY_MODEL_ID
        or d3.model_id != REPLAY_MODEL_ID
    ):
        raise ReplayAuthoringError(
            "draft_invalid", "replay pair has inconsistent static bindings"
        )
    return canonical_d2, canonical_d3


def validate_formal_replay_pair_v1(
    d2: OciReplayConfigV1, d3: OciReplayConfigV1
) -> None:
    """Require the minimum static shape for a non-smoke D2 -> D3 replay.

    This is deliberately not a quality assertion.  Runtime outcome counts and
    evaluator receipts still decide whether the pair deferred, emitted zero
    findings, or finalized useful candidates.
    """

    canonical_d2, canonical_d3 = _validated_static_pair(d2, d3)
    if not canonical_d2.responses or not canonical_d3.responses:
        raise ReplayAuthoringError(
            "formal_replay_incomplete",
            "formal replay requires non-empty D2 and D3 transcripts",
        )


def validate_empty_smoke_replay_pair_v1(
    d2: OciReplayConfigV1, d3: OciReplayConfigV1
) -> None:
    """Accept only the explicit legacy two-empty-config smoke fixture."""

    canonical_d2, canonical_d3 = _validated_static_pair(d2, d3)
    if canonical_d2.responses or canonical_d3.responses:
        raise ReplayAuthoringError(
            "smoke_replay_invalid", "empty smoke replay must contain no responses"
        )


def _load_draft_pair(
    draft_root: str | os.PathLike[str], *, expected_task_id: str
) -> tuple[Path, OciReplayConfigV1, OciReplayConfigV1]:
    if type(expected_task_id) is not str or _TASK_ID_RE.fullmatch(expected_task_id) is None:
        raise ReplayAuthoringError(
            "invalid_argument", "expected task ID is invalid"
        )
    root = _canonical_existing_directory(draft_root)
    identity = _scan_draft_root(root)
    try:
        d2_wire = _read_private_regular(
            root / REPLAY_AUTHORING_D2_FILENAME,
            maximum_bytes=REPLAY_CONFIG_MAX_BYTES,
        )
        d3_wire = _read_private_regular(
            root / REPLAY_AUTHORING_D3_FILENAME,
            maximum_bytes=REPLAY_CONFIG_MAX_BYTES,
        )
        d2 = OciReplayConfigV1.from_bytes(d2_wire)
        d3 = OciReplayConfigV1.from_bytes(d3_wire)
    except ReplayAuthoringError:
        raise
    except (OciWorkerEntryError, TypeError, ValueError):
        raise ReplayAuthoringError(
            "draft_invalid", "authoring draft contains an invalid replay pair"
        ) from None
    if (
        d2.task_id != expected_task_id
        or d3.task_id != expected_task_id
        or d2.role != "d2"
        or d3.role != "d3"
        or d2.backend_id != REPLAY_BACKEND_ID
        or d3.backend_id != REPLAY_BACKEND_ID
        or d2.model_id != REPLAY_MODEL_ID
        or d3.model_id != REPLAY_MODEL_ID
    ):
        raise ReplayAuthoringError(
            "draft_invalid", "authoring draft binding is invalid"
        )
    if _scan_draft_root(root) != identity:
        raise ReplayAuthoringError(
            "input_changed", "authoring draft changed while loading"
        )
    return root, d2, d3


def _assert_draft_snapshot(
    root: Path,
    *,
    expected_task_id: str,
    expected_d2: OciReplayConfigV1,
    expected_d3: OciReplayConfigV1,
    guard: _DirectoryGuard,
) -> None:
    _assert_directory_guard(guard)
    observed_root, observed_d2, observed_d3 = _load_draft_pair(
        root, expected_task_id=expected_task_id
    )
    if (
        observed_root != root
        or observed_d2 != expected_d2
        or observed_d3 != expected_d3
    ):
        raise ReplayAuthoringError(
            "input_changed", "authoring draft changed during execution"
        )
    _assert_directory_guard(guard)


def _cleanup_pair_staging(
    staging: Path, *, expected_identity: tuple[int, int]
) -> None:
    try:
        root = os.lstat(staging)
    except FileNotFoundError:
        return
    except OSError:
        raise ReplayAuthoringError(
            "publication_failed", "authoring staging cleanup failed"
        ) from None
    if (
        not stat.S_ISDIR(root.st_mode)
        or stat.S_ISLNK(root.st_mode)
        or _is_reparse(root)
        or (root.st_dev, root.st_ino) != expected_identity
    ):
        raise ReplayAuthoringError(
            "publication_failed", "authoring staging identity changed"
        )
    try:
        names = frozenset(item.name for item in os.scandir(staging))
    except OSError:
        raise ReplayAuthoringError(
            "publication_failed", "authoring staging cleanup failed"
        ) from None
    if not names.issubset(_DRAFT_NAMES):
        raise ReplayAuthoringError(
            "publication_failed", "authoring staging membership changed"
        )
    for name in sorted(names):
        target = staging / name
        try:
            state = os.lstat(target)
            if (
                not stat.S_ISREG(state.st_mode)
                or stat.S_ISLNK(state.st_mode)
                or _is_reparse(state)
                or state.st_nlink != 1
            ):
                raise OSError("unsafe staging member")
            os.unlink(target)
        except OSError:
            raise ReplayAuthoringError(
                "publication_failed", "authoring staging cleanup failed"
            ) from None
    try:
        os.rmdir(staging)
    except OSError:
        raise ReplayAuthoringError(
            "publication_failed", "authoring staging cleanup failed"
        ) from None


def _pair_publication_state_after_error(
    staging: Path,
    output: Path,
    *,
    parent: Path,
    expected_parent_identity: tuple[int, ...],
    expected_staging_identity: tuple[int, int],
    expected_d2: OciReplayConfigV1,
    expected_d3: OciReplayConfigV1,
) -> Literal["committed", "not_committed", "unknown"]:
    """Read back a failed rename without guessing whether it took effect."""

    try:
        if (
            _directory_identity(_require_private_directory(parent))[:3]
            != expected_parent_identity[:3]
        ):
            return "unknown"
        try:
            staging_state = os.lstat(staging)
        except FileNotFoundError:
            staging_state = None
        try:
            output_state = os.lstat(output)
        except FileNotFoundError:
            output_state = None
    except (OSError, ReplayAuthoringError):
        return "unknown"

    staging_matches = (
        staging_state is not None
        and stat.S_ISDIR(staging_state.st_mode)
        and not stat.S_ISLNK(staging_state.st_mode)
        and not _is_reparse(staging_state)
        and (staging_state.st_dev, staging_state.st_ino)
        == expected_staging_identity
    )
    output_matches = (
        output_state is not None
        and stat.S_ISDIR(output_state.st_mode)
        and not stat.S_ISLNK(output_state.st_mode)
        and not _is_reparse(output_state)
        and (output_state.st_dev, output_state.st_ino)
        == expected_staging_identity
    )
    if staging_matches and not output_matches:
        try:
            _root, observed_d2, observed_d3 = _load_draft_pair(
                staging, expected_task_id=expected_d2.task_id
            )
        except ReplayAuthoringError:
            return "unknown"
        return (
            "not_committed"
            if observed_d2 == expected_d2 and observed_d3 == expected_d3
            else "unknown"
        )
    if staging_state is None and output_matches:
        try:
            _root, observed_d2, observed_d3 = _load_draft_pair(
                output, expected_task_id=expected_d2.task_id
            )
        except ReplayAuthoringError:
            return "unknown"
        return (
            "committed"
            if observed_d2 == expected_d2 and observed_d3 == expected_d3
            else "unknown"
        )
    return "unknown"


def _publish_pair_directory(
    output_root: str | os.PathLike[str],
    d2: OciReplayConfigV1,
    d3: OciReplayConfigV1,
    *,
    expected_parent_guard: _DirectoryGuard | None = None,
) -> Path:
    output, parent = _canonical_new_directory(output_root)
    if expected_parent_guard is None:
        parent_guard = _guard_existing_directory(parent)
    else:
        if (
            type(expected_parent_guard) is not _DirectoryGuard
            or expected_parent_guard.path != parent
        ):
            raise ReplayAuthoringError(
                "output_changed", "authoring output parent binding changed"
            )
        _assert_directory_guard(expected_parent_guard)
        parent_guard = expected_parent_guard
    parent_before = _directory_identity(_require_private_directory(parent))
    staging = parent / f".{output.name}.replay-authoring-{uuid.uuid4().hex}"
    committed = False
    staging_identity: tuple[int, int] | None = None
    try:
        os.mkdir(staging, 0o700)
        created = os.lstat(staging)
        if (
            not stat.S_ISDIR(created.st_mode)
            or stat.S_ISLNK(created.st_mode)
            or _is_reparse(created)
        ):
            raise ReplayAuthoringError(
                "publication_failed", "authoring staging is unsafe"
            )
        staging_identity = (created.st_dev, created.st_ino)
        if os.name == "posix":
            os.chmod(staging, 0o700)
        _write_exclusive(staging / REPLAY_AUTHORING_D2_FILENAME, d2.to_bytes())
        _write_exclusive(staging / REPLAY_AUTHORING_D3_FILENAME, d3.to_bytes())
        _fsync_directory(staging)
        _assert_directory_guard(parent_guard)
        if (
            _directory_identity(_require_private_directory(parent))[:3]
            != parent_before[:3]
        ):
            raise ReplayAuthoringError(
                "output_changed", "authoring output parent changed before publication"
            )
        try:
            _rename_directory_noreplace(staging, output)
        except BaseException as error:
            try:
                publication_state = _pair_publication_state_after_error(
                    staging,
                    output,
                    parent=parent,
                    expected_parent_identity=parent_before,
                    expected_staging_identity=staging_identity,
                    expected_d2=d2,
                    expected_d3=d3,
                )
            except BaseException as readback_error:
                committed = True
                raise ReplayAuthoringError(
                    "publication_uncertain",
                    "authoring output publication readback was interrupted",
                    committed=True,
                ) from readback_error
            if publication_state == "committed":
                committed = True
            elif publication_state == "unknown":
                committed = True
                raise ReplayAuthoringError(
                    "publication_uncertain",
                    "authoring output publication requires committed readback",
                    committed=True,
                ) from error
            else:
                if isinstance(error, OSError):
                    raise ReplayAuthoringError(
                        "publication_failed", "authoring output could not be published"
                    ) from None
                raise
        committed = True
        _fsync_directory(parent)
        _loaded_root, observed_d2, observed_d3 = _load_draft_pair(
            output, expected_task_id=d2.task_id
        )
        if observed_d2 != d2 or observed_d3 != d3:
            raise ReplayAuthoringError(
                "publication_uncertain",
                "published authoring pair failed readback",
                committed=True,
            )
        _assert_directory_guard(parent_guard)
        return output
    except ReplayAuthoringError as error:
        if committed and not error.committed:
            raise ReplayAuthoringError(
                "publication_uncertain",
                "authoring publication may already be committed",
                committed=True,
            ) from error
        raise
    except BaseException as error:
        if not committed and not isinstance(error, Exception):
            raise
        raise ReplayAuthoringError(
            "publication_uncertain" if committed else "publication_failed",
            "authoring publication did not close",
            committed=committed,
        ) from error
    finally:
        if not committed and staging_identity is not None:
            _cleanup_pair_staging(
                staging, expected_identity=staging_identity
            )


def _draft_replacement_state_after_error(
    root: Path,
    *,
    root_identity: tuple[int, ...],
    target: Path,
    temporary: Path,
    temporary_identity: tuple[int, ...],
    expected_wire: bytes,
    replacement_wire: bytes,
) -> Literal["committed", "not_committed", "unknown"]:
    """Classify an interrupted replace only from exact on-disk state."""

    try:
        current = _directory_identity(_require_private_directory(root))
        if current[:3] != root_identity[:3]:
            return "unknown"
        with os.scandir(root) as entries:
            names = frozenset(entry.name for entry in entries)
        target_wire = _read_private_regular(
            target, maximum_bytes=REPLAY_CONFIG_MAX_BYTES
        )
        try:
            temporary_state = os.lstat(temporary)
        except FileNotFoundError:
            temporary_state = None
    except (OSError, ReplayAuthoringError):
        return "unknown"

    if (
        names == _DRAFT_NAMES
        and temporary_state is None
        and target_wire == replacement_wire
    ):
        return "committed"
    if (
        names == _DRAFT_NAMES.union({temporary.name})
        and temporary_state is not None
        and _file_identity(temporary_state) == temporary_identity
        and target_wire == expected_wire
    ):
        try:
            temporary_wire = _read_private_regular(
                temporary, maximum_bytes=REPLAY_CONFIG_MAX_BYTES
            )
        except ReplayAuthoringError:
            return "unknown"
        if temporary_wire == replacement_wire:
            return "not_committed"
    return "unknown"


def _replace_draft_member(
    root: Path,
    *,
    filename: str,
    expected_wire: bytes,
    replacement_wire: bytes,
) -> None:
    if filename not in _DRAFT_NAMES:
        raise ReplayAuthoringError(
            "invalid_argument", "authoring draft member name is invalid"
        )
    root_identity = _scan_draft_root(root)
    target = root / filename
    if _read_private_regular(target, maximum_bytes=REPLAY_CONFIG_MAX_BYTES) != expected_wire:
        raise ReplayAuthoringError(
            "input_changed", "authoring draft changed before update"
    )
    temporary = root / f".{filename}.update-{uuid.uuid4().hex}"
    committed = False
    try:
        _write_exclusive(temporary, replacement_wire)
    except ReplayAuthoringError as error:
        raise ReplayAuthoringError(
            "update_failed", "authoring draft temporary write failed"
        ) from error
    except OSError:
        raise ReplayAuthoringError(
            "update_failed", "authoring draft temporary write failed"
        ) from None
    try:
        temporary_identity = _file_identity(os.lstat(temporary))
    except OSError:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise ReplayAuthoringError(
            "update_failed", "authoring draft temporary write failed"
        ) from None
    try:
        current = _directory_identity(_require_private_directory(root))
        try:
            with os.scandir(root) as entries:
                names = frozenset(entry.name for entry in entries)
        except OSError:
            raise ReplayAuthoringError(
                "input_changed", "authoring draft could not be rechecked"
            ) from None
        if (
            current[:3] != root_identity[:3]
            or names != _DRAFT_NAMES.union({temporary.name})
        ):
            raise ReplayAuthoringError(
                "input_changed", "authoring draft root changed before update"
            )
        if _read_private_regular(target, maximum_bytes=REPLAY_CONFIG_MAX_BYTES) != expected_wire:
            raise ReplayAuthoringError(
                "input_changed", "authoring draft changed before update"
            )
        try:
            os.replace(temporary, target)
        except BaseException as error:
            try:
                replacement_state = _draft_replacement_state_after_error(
                    root,
                    root_identity=root_identity,
                    target=target,
                    temporary=temporary,
                    temporary_identity=temporary_identity,
                    expected_wire=expected_wire,
                    replacement_wire=replacement_wire,
                )
            except BaseException as readback_error:
                committed = True
                raise ReplayAuthoringError(
                    "update_uncertain",
                    "authoring draft update readback was interrupted",
                    committed=True,
                ) from readback_error
            if replacement_state == "committed":
                committed = True
            elif replacement_state == "unknown":
                committed = True
                raise ReplayAuthoringError(
                    "update_uncertain",
                    "authoring draft update requires committed readback",
                    committed=True,
                ) from error
            else:
                if isinstance(error, OSError):
                    raise ReplayAuthoringError(
                        "update_failed",
                        "authoring draft could not be atomically updated",
                    ) from None
                raise
        committed = True
        _fsync_directory(root)
        observed = _read_private_regular(target, maximum_bytes=REPLAY_CONFIG_MAX_BYTES)
        if observed != replacement_wire:
            raise ReplayAuthoringError(
                "update_uncertain",
                "authoring draft update failed readback",
                committed=True,
            )
        _scan_draft_root(root)
    except ReplayAuthoringError as error:
        if committed and not error.committed:
            raise ReplayAuthoringError(
                "update_uncertain",
                "authoring draft update may already be committed",
                committed=True,
            ) from error
        raise
    except BaseException as error:
        if not committed and not isinstance(error, Exception):
            raise
        raise ReplayAuthoringError(
            "update_uncertain" if committed else "update_failed",
            "authoring draft update did not close",
            committed=committed,
        ) from error
    finally:
        if not committed:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def initialize_replay_authoring_v1(
    task_id: str, draft_root: str | os.PathLike[str]
) -> ReplayAuthoringSummaryV1:
    """Publish a new two-file empty prefix for one exact task."""

    if type(task_id) is not str or _TASK_ID_RE.fullmatch(task_id) is None:
        raise ReplayAuthoringError("invalid_argument", "task ID is invalid")
    try:
        d2 = OciReplayConfigV1(task_id=task_id, role="d2", responses=())
        d3 = OciReplayConfigV1(task_id=task_id, role="d3", responses=())
    except (OciWorkerEntryError, TypeError, ValueError):
        raise ReplayAuthoringError(
            "invalid_argument", "empty authoring pair could not be constructed"
        ) from None
    initialized = _summary(d2, d3, status="initialized")
    _publish_pair_directory(draft_root, d2, d3)
    return initialized


def _validate_task_and_key(
    task: object, attestation_key: object, expected_key_id: object
) -> DiscoveryTaskInputV1:
    if type(task) is not DiscoveryTaskInputV1:
        raise ReplayAuthoringError(
            "invalid_argument", "authoring task must have an exact contract type"
        )
    try:
        frozen = DiscoveryTaskInputV1.from_dict(task.to_dict())
    except (AttributeError, DiscoveryContractError, TypeError, ValueError):
        raise ReplayAuthoringError(
            "invalid_argument", "authoring task did not normalize"
        ) from None
    if frozen != task:
        raise ReplayAuthoringError(
            "invalid_argument", "authoring task changed while normalizing"
        )
    if (
        type(attestation_key) not in (bytes, bytearray)
        or not 32 <= len(attestation_key) <= 4096
        or type(expected_key_id) is not str
        or _KEY_ID_RE.fullmatch(expected_key_id) is None
    ):
        raise ReplayAuthoringError(
            "invalid_argument", "authoring attestation input is invalid"
        )
    return frozen


def _execute_prefix(
    task: DiscoveryTaskInputV1,
    sealed_bundle_root: str | os.PathLike[str],
    *,
    attestation_key: bytes | bytearray,
    expected_key_id: str,
    d2: OciReplayConfigV1,
    d3: OciReplayConfigV1,
) -> ReplayAuthoringStepV1:
    sealed_root = _canonical_existing_directory(sealed_bundle_root)
    sealed_guard = _guard_existing_directory(sealed_root)
    try:
        handoff = build_worker_handoff(
            task,
            sealed_root,
            attestation_key=attestation_key,
            expected_key_id=expected_key_id,
        )
        handoff_wire = handoff.to_bytes()
        d2_backend = _PrefixCaptureBackend(d2, role="d2")
        d3_backend = _PrefixCaptureBackend(d3, role="d3")
        prefix_wire = execute_discovery_worker_v1(
            handoff_wire,
            expected_handoff_sha256=handoff.handoff_sha256,
            expected_handoff_wire_sha256=handoff.wire_sha256,
            tree_root=sealed_root / "tree",
            d2_backend=d2_backend,
            d3_backend=d3_backend,
        )
        prefix_run = SourceDiscoveryRunV1.from_wire(prefix_wire)
        _assert_directory_guard(sealed_guard)
    except ReplayAuthoringError:
        raise
    except (
        AttributeError,
        IsolatedWorkerError,
        OSError,
        OciWorkerEntryError,
        ReplayClosureError,
        TypeError,
        ValueError,
        WorkerHandoffError,
    ):
        raise ReplayAuthoringError(
            "execution_failed", "authoring prefix could not be executed"
        ) from None

    pending = tuple(
        item for item in (d2_backend.pending, d3_backend.pending) if item is not None
    )
    if len(pending) > 1:
        raise ReplayAuthoringError(
            "draft_invalid", "authoring run exposed more than one pending request"
        )
    try:
        d2_backend.assert_prefix_closed()
        if d2_backend.pending is not None:
            if d3.responses or d3_backend.invocation_count != 0:
                raise ReplayAuthoringError(
                    "draft_invalid", "D3 responses exist before D2 closed"
                )
        else:
            d3_backend.assert_prefix_closed()
    except ReplayClosureError:
        raise ReplayAuthoringError(
            "draft_invalid", "authoring responses are unused or out of order"
        ) from None
    if pending:
        return pending[0]

    if type(prefix_run.producer_result) is ProducerDeferredV1 and d3.responses:
        raise ReplayAuthoringError(
            "draft_invalid", "D2 defer requires an empty D3 replay"
        )
    try:
        replay_wire = execute_discovery_worker_v1(
            handoff_wire,
            expected_handoff_sha256=handoff.handoff_sha256,
            expected_handoff_wire_sha256=handoff.wire_sha256,
            tree_root=sealed_root / "tree",
            d2_backend=d2.build_backend(),
            d3_backend=d3.build_backend(),
        )
        replay_run = SourceDiscoveryRunV1.from_wire(replay_wire)
        _assert_directory_guard(sealed_guard)
    except (
        AttributeError,
        IsolatedWorkerError,
        OciWorkerEntryError,
        ReplayClosureError,
        TypeError,
        ValueError,
    ):
        raise ReplayAuthoringError(
            "offline_replay_failed", "completed authoring pair did not replay"
        ) from None
    if replay_wire != prefix_wire or replay_run != prefix_run:
        raise ReplayAuthoringError(
            "offline_replay_mismatch", "completed replay differs from authoring run"
        )
    return _summary(d2, d3, status="closed", run=replay_run)


def inspect_replay_authoring_v1(
    task: DiscoveryTaskInputV1,
    sealed_bundle_root: str | os.PathLike[str],
    draft_root: str | os.PathLike[str],
    *,
    attestation_key: bytes | bytearray,
    expected_key_id: str,
) -> ReplayAuthoringStepV1:
    """Replay the current prefix and return its sole next request or closure."""

    frozen_task = _validate_task_and_key(task, attestation_key, expected_key_id)
    root, d2, d3 = _load_draft_pair(
        draft_root, expected_task_id=frozen_task.task_id
    )
    sealed_guard, draft_guard = _execution_domain_guards(
        sealed_bundle_root, root
    )
    result = _execute_prefix(
        frozen_task,
        sealed_guard.path,
        attestation_key=attestation_key,
        expected_key_id=expected_key_id,
        d2=d2,
        d3=d3,
    )
    _assert_directory_guard(sealed_guard)
    _assert_draft_snapshot(
        root,
        expected_task_id=frozen_task.task_id,
        expected_d2=d2,
        expected_d3=d3,
        guard=draft_guard,
    )
    return result


def _assert_response_matches_pending(
    response: ReplayAuthoringResponseV1,
    pending: ReplayAuthoringPendingRequestV1,
) -> None:
    if (
        type(response) is not ReplayAuthoringResponseV1
        or response.task_id != pending.task_id
        or response.role != pending.role
        or response.stage != pending.stage
        or response.request_sha256 != pending.request_sha256
        or response.occurrence != pending.occurrence
        or response.prefix_config_sha256 != pending.prefix_config_sha256
    ):
        raise ReplayAuthoringError(
            "response_binding_mismatch",
            "authoring response does not bind the current pending request",
        )


def _assert_authored_response_was_structurally_accepted(
    run: SourceDiscoveryRunV1, *, role: Literal["d2", "d3"]
) -> None:
    if type(run) is not SourceDiscoveryRunV1:
        raise ReplayAuthoringError(
            "execution_failed", "authoring run has an invalid contract type"
        )
    if (
        role == "d2"
        and type(run.producer_result) is ProducerDeferredV1
        and run.producer_result.reason_code in _BAD_D2_RESPONSE_REASONS
    ):
        raise ReplayAuthoringError(
            "response_rejected", "D2 rejected the authored response structure"
        )
    if role == "d3":
        reviewer = run.reviewer_result
        if type(reviewer) is not ReviewerDeferredV1:
            return
        if reviewer.reason_code in _BAD_D3_RESPONSE_REASONS:
            raise ReplayAuthoringError(
                "response_rejected", "D3 rejected the authored response structure"
            )


def append_replay_authoring_response_v1(
    task: DiscoveryTaskInputV1,
    sealed_bundle_root: str | os.PathLike[str],
    draft_root: str | os.PathLike[str],
    response: ReplayAuthoringResponseV1,
    *,
    attestation_key: bytes | bytearray,
    expected_key_id: str,
) -> ReplayAuthoringStepV1:
    """Validate one response prospectively, then atomically extend its prefix."""

    frozen_task = _validate_task_and_key(task, attestation_key, expected_key_id)
    root, d2, d3 = _load_draft_pair(
        draft_root, expected_task_id=frozen_task.task_id
    )
    sealed_guard, draft_guard = _execution_domain_guards(
        sealed_bundle_root, root
    )
    current = _execute_prefix(
        frozen_task,
        sealed_guard.path,
        attestation_key=attestation_key,
        expected_key_id=expected_key_id,
        d2=d2,
        d3=d3,
    )
    _assert_directory_guard(sealed_guard)
    _assert_draft_snapshot(
        root,
        expected_task_id=frozen_task.task_id,
        expected_d2=d2,
        expected_d3=d3,
        guard=draft_guard,
    )
    if type(current) is not ReplayAuthoringPendingRequestV1:
        raise ReplayAuthoringError(
            "already_closed", "authoring draft has no pending request"
        )
    _assert_response_matches_pending(response, current)
    try:
        entry = ReplayResponse(
            stage=current.stage,
            request=current.payload,
            response=response.response,
        )
        if current.role == "d2":
            replacement = OciReplayConfigV1(
                task_id=d2.task_id,
                role="d2",
                responses=(*d2.responses, entry),
            )
            prospective_d2, prospective_d3 = replacement, d3
            filename = REPLAY_AUTHORING_D2_FILENAME
            expected_wire = d2.to_bytes()
        else:
            replacement = OciReplayConfigV1(
                task_id=d3.task_id,
                role="d3",
                responses=(*d3.responses, entry),
            )
            prospective_d2, prospective_d3 = d2, replacement
            filename = REPLAY_AUTHORING_D3_FILENAME
            expected_wire = d3.to_bytes()
    except (OciWorkerEntryError, RecursionError, TypeError, ValueError):
        raise ReplayAuthoringError(
            "response_rejected", "authoring response exceeds the replay contract"
        ) from None

    prospective = _execute_prefix(
        frozen_task,
        sealed_guard.path,
        attestation_key=attestation_key,
        expected_key_id=expected_key_id,
        d2=prospective_d2,
        d3=prospective_d3,
    )
    _assert_directory_guard(sealed_guard)
    _assert_draft_snapshot(
        root,
        expected_task_id=frozen_task.task_id,
        expected_d2=d2,
        expected_d3=d3,
        guard=draft_guard,
    )
    prospective_run: SourceDiscoveryRunV1 | None = None
    if type(prospective) is ReplayAuthoringSummaryV1:
        prospective_run = _rerun_for_summary(
            frozen_task,
            sealed_guard.path,
            attestation_key=attestation_key,
            expected_key_id=expected_key_id,
            d2=prospective_d2,
            d3=prospective_d3,
        )
        _assert_authored_response_was_structurally_accepted(
            prospective_run, role=current.role
        )
        accepted_step: ReplayAuthoringStepV1 = _summary(
            prospective_d2,
            prospective_d3,
            status="closed",
            run=prospective_run,
        )
    else:
        accepted_step = prospective
    _replace_draft_member(
        root,
        filename=filename,
        expected_wire=expected_wire,
        replacement_wire=replacement.to_bytes(),
    )
    try:
        _assert_directory_guard(draft_guard)
        _loaded_root, observed_d2, observed_d3 = _load_draft_pair(
            root, expected_task_id=frozen_task.task_id
        )
        if observed_d2 != prospective_d2 or observed_d3 != prospective_d3:
            raise ReplayAuthoringError(
                "update_uncertain",
                "authoring draft differs after atomic update",
                committed=True,
            )
        _assert_directory_guard(sealed_guard)
    except ReplayAuthoringError as error:
        if error.committed:
            raise
        raise ReplayAuthoringError(
            "update_uncertain",
            "authoring draft update failed final verification",
            committed=True,
        ) from error
    except BaseException as error:
        raise ReplayAuthoringError(
            "update_uncertain",
            "authoring draft update failed final verification",
            committed=True,
        ) from error
    return accepted_step


def _rerun_for_summary(
    task: DiscoveryTaskInputV1,
    sealed_bundle_root: str | os.PathLike[str],
    *,
    attestation_key: bytes | bytearray,
    expected_key_id: str,
    d2: OciReplayConfigV1,
    d3: OciReplayConfigV1,
) -> SourceDiscoveryRunV1:
    result = _execute_prefix(
        task,
        sealed_bundle_root,
        attestation_key=attestation_key,
        expected_key_id=expected_key_id,
        d2=d2,
        d3=d3,
    )
    if type(result) is not ReplayAuthoringSummaryV1 or result.status != "closed":
        raise ReplayAuthoringError(
            "offline_replay_failed", "closed authoring pair did not remain closed"
        )
    # Reconstruct once more so callers that need the in-memory run can compare
    # exact wire.  This helper is intentionally private and only used after the
    # pair already passed both prefix and production-backend executions.
    sealed_root = _canonical_existing_directory(sealed_bundle_root)
    sealed_guard = _guard_existing_directory(sealed_root)
    handoff = build_worker_handoff(
        task,
        sealed_root,
        attestation_key=attestation_key,
        expected_key_id=expected_key_id,
    )
    wire = execute_discovery_worker_v1(
        handoff.to_bytes(),
        expected_handoff_sha256=handoff.handoff_sha256,
        expected_handoff_wire_sha256=handoff.wire_sha256,
        tree_root=sealed_root / "tree",
        d2_backend=d2.build_backend(),
        d3_backend=d3.build_backend(),
    )
    _assert_directory_guard(sealed_guard)
    return SourceDiscoveryRunV1.from_wire(wire)


def publish_replay_authoring_v1(
    task: DiscoveryTaskInputV1,
    sealed_bundle_root: str | os.PathLike[str],
    draft_root: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    *,
    attestation_key: bytes | bytearray,
    expected_key_id: str,
) -> ReplayAuthoringSummaryV1:
    """Require exact offline closure and publish the canonical pair once."""

    frozen_task = _validate_task_and_key(task, attestation_key, expected_key_id)
    root, d2, d3 = _load_draft_pair(
        draft_root, expected_task_id=frozen_task.task_id
    )
    sealed_guard, draft_guard = _execution_domain_guards(
        sealed_bundle_root, root
    )
    output, output_parent = _canonical_new_directory(output_root)
    output_parent_guard = _guard_existing_directory(output_parent)
    _assert_new_child_disjoint(
        output,
        output_parent_guard=output_parent_guard,
        protected_guard=sealed_guard,
    )
    _assert_new_child_disjoint(
        output,
        output_parent_guard=output_parent_guard,
        protected_guard=draft_guard,
    )
    step = _execute_prefix(
        frozen_task,
        sealed_guard.path,
        attestation_key=attestation_key,
        expected_key_id=expected_key_id,
        d2=d2,
        d3=d3,
    )
    if type(step) is ReplayAuthoringPendingRequestV1:
        raise ReplayAuthoringError(
            "authoring_incomplete", "authoring draft still has a pending request"
        )
    run = _rerun_for_summary(
        frozen_task,
        sealed_guard.path,
        attestation_key=attestation_key,
        expected_key_id=expected_key_id,
        d2=d2,
        d3=d3,
    )
    _assert_directory_guard(sealed_guard)
    _assert_draft_snapshot(
        root,
        expected_task_id=frozen_task.task_id,
        expected_d2=d2,
        expected_d3=d3,
        guard=draft_guard,
    )
    published_summary = _summary(d2, d3, status="published", run=run)
    _publish_pair_directory(
        output,
        d2,
        d3,
        expected_parent_guard=output_parent_guard,
    )
    return published_summary


def read_pinned_authoring_task_v1(
    path: str | os.PathLike[str], *, expected_wire_sha256: str
) -> DiscoveryTaskInputV1:
    """Read one canonical, caller-pinned DiscoveryTaskInputV1 file."""

    expected = _require_sha256(
        expected_wire_sha256, name="expected_task_wire_sha256"
    )
    if type(path) not in (str, type(Path())):
        raise ReplayAuthoringError("invalid_argument", "task path is invalid")
    canonical = Path(os.path.abspath(os.fspath(path)))
    payload = _read_private_regular(
        canonical, maximum_bytes=REPLAY_AUTHORING_MAX_TASK_BYTES
    )
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ReplayAuthoringError(
            "task_wire_mismatch", "authoring task differs from its trusted pin"
        )
    raw = _parse_canonical_line(
        payload, maximum_bytes=REPLAY_AUTHORING_MAX_TASK_BYTES
    )
    try:
        task = DiscoveryTaskInputV1.from_dict(raw)
    except (DiscoveryContractError, TypeError, ValueError):
        raise ReplayAuthoringError(
            "task_invalid", "authoring task contract is invalid"
        ) from None
    if _canonical_json(task.to_dict()) + b"\n" != payload:
        raise ReplayAuthoringError(
            "task_invalid", "authoring task did not round trip"
        )
    return task


def read_authoring_response_file_v1(
    path: str | os.PathLike[str],
) -> ReplayAuthoringResponseV1:
    """Read one bounded canonical response envelope from a private file."""

    if type(path) not in (str, type(Path())):
        raise ReplayAuthoringError("invalid_argument", "response path is invalid")
    canonical = Path(os.path.abspath(os.fspath(path)))
    return ReplayAuthoringResponseV1.from_bytes(
        _read_private_regular(
            canonical, maximum_bytes=REPLAY_AUTHORING_MAX_RESPONSE_BYTES
        )
    )


__all__ = [
    "REPLAY_AUTHORING_CONTRACT_VERSION",
    "REPLAY_AUTHORING_D2_FILENAME",
    "REPLAY_AUTHORING_D3_FILENAME",
    "REPLAY_AUTHORING_MAX_RESPONSE_BYTES",
    "REPLAY_AUTHORING_MAX_TASK_BYTES",
    "REPLAY_AUTHORING_PENDING_KIND",
    "REPLAY_AUTHORING_RESPONSE_KIND",
    "REPLAY_AUTHORING_SUMMARY_KIND",
    "ReplayAuthoringError",
    "ReplayAuthoringPendingRequestV1",
    "ReplayAuthoringResponseV1",
    "ReplayAuthoringStepV1",
    "ReplayAuthoringSummaryV1",
    "append_replay_authoring_response_v1",
    "initialize_replay_authoring_v1",
    "inspect_replay_authoring_v1",
    "publish_replay_authoring_v1",
    "read_authoring_response_file_v1",
    "read_pinned_authoring_task_v1",
    "validate_empty_smoke_replay_pair_v1",
    "validate_formal_replay_pair_v1",
]
