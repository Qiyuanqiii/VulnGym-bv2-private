"""Prepare pinned discovery tasks and exact replay response envelopes.

This credential-free control plane fills the two input/output gaps immediately
before :mod:`vulngym_agent.replay_authoring_cli`:

* ``export-split`` authenticates one sealed snapshot batch and its answer-free
  public task export, then publishes one canonical ``DiscoveryTaskInputV1``
  file per task.  A canonical index binds the public order and every task wire
  digest; the index semantic and wire digests are returned on stdout for
  out-of-band retention.
* ``bind-response`` combines one externally wire-pinned pending request with
  one externally wire-pinned canonical model response body.  It publishes the
  existing strict ``ReplayAuthoringResponseV1`` envelope without replacing an
  earlier result.

The module has no source-map argument and never opens a source-map file.  It
also contains no provider, SDK, network, or credential integration.  Every
publication is a same-parent, no-replace directory transaction and every
success record is canonical, path-free JSON.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from types import MappingProxyType
from typing import Any, Callable, Final, Literal, Mapping, Sequence
import uuid

from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryContractError,
    DiscoveryTaskInputV1,
)
from vulngym_agent.benchmark.snapshot_batch import (
    PROFILE_ID,
    SnapshotBatchError,
    SnapshotBatchSummary,
    SnapshotBatchTask,
    VerifiedTaskExport,
    _canonical_existing_path,
    _canonical_new_child,
    _windows_extended_path,
    load_verified_task_export,
    verify_snapshot_batch,
)
from vulngym_agent.evaluator.replay_authoring import (
    REPLAY_AUTHORING_MAX_RESPONSE_BYTES,
    ReplayAuthoringError,
    ReplayAuthoringPendingRequestV1,
    ReplayAuthoringResponseV1,
)
from vulngym_agent.trusted_inputs import (
    TrustedInputError,
    paths_overlap_v1,
    read_attestation_key_file_v1,
    zero_secret_buffer_v1,
)


REPLAY_TASK_RESPONSE_CLI_VERSION: Final[str] = "replay-task-response-cli-v1"
DISCOVERY_TASK_SPLIT_EXPORT_KIND: Final[str] = (
    "vulngym.discovery-task-split-export.v1"
)
DISCOVERY_TASK_SPLIT_EXPORT_DOMAIN: Final[bytes] = (
    b"VulnGym discovery task split export v1\0"
)
REPLAY_TASK_RESPONSE_SUMMARY_KIND: Final[str] = (
    "vulngym.replay-task-response-summary.v1"
)
RESPONSE_FILENAME: Final[str] = "response.json"
INDEX_FILENAME: Final[str] = "index.json"
TASK_DIRECTORY: Final[str] = "tasks"

EXIT_SUCCESS: Final[int] = 0
EXIT_REJECTED: Final[int] = 2
EXIT_COMMITTED_UNCERTAIN: Final[int] = 11
EXIT_INTERRUPTED: Final[int] = 130

_SPLIT_COUNTS: Final[dict[str, int]] = {"test": 20, "train": 50}
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_SNAPSHOT_ID_RE: Final[re.Pattern[str]] = re.compile(r"VGS-[0-9A-F]{32}\Z")
_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z"
)
_MAX_INDEX_BYTES: Final[int] = 512 * 1024
_MAX_TASK_BYTES: Final[int] = 64 * 1024
_MAX_SUMMARY_BYTES: Final[int] = 64 * 1024


class ReplayTaskResponseError(RuntimeError):
    """Stable, path-free failure at this control-plane boundary."""

    def __init__(
        self, code: str, message: str, *, committed: bool = False
    ) -> None:
        self.code = code if type(code) is str and code else "operation_failed"
        self.committed = committed is True
        super().__init__(message)


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        _ = message
        self.exit(EXIT_REJECTED, "error: replay task/response arguments rejected\n")


def _sha256_argument(value: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "digest must be 64 lower-case hexadecimal characters"
        )
    return value


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="python -m vulngym_agent.replay_task_response_cli",
        description=(
            "Export authenticated discovery tasks and bind exact offline "
            "authoring responses."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    export = commands.add_parser(
        "export-split",
        help="publish one pinned task file per member of an authenticated split",
        allow_abbrev=False,
    )
    export.add_argument("--task-export-dir", type=Path, required=True)
    export.add_argument(
        "--expected-tasks-sha256", type=_sha256_argument, required=True
    )
    export.add_argument(
        "--expected-public-manifest-sha256",
        type=_sha256_argument,
        required=True,
    )
    export.add_argument("--sealed-batch-root", type=Path, required=True)
    export.add_argument(
        "--expected-batch-manifest-sha256",
        type=_sha256_argument,
        required=True,
    )
    export.add_argument("--key-file", type=Path, required=True)
    export.add_argument("--key-id", required=True)
    export.add_argument("--output-root", type=Path, required=True)

    verify_export = commands.add_parser(
        "verify-export",
        help="independently read a task split export under external index pins",
        allow_abbrev=False,
    )
    verify_export.add_argument("--export-root", type=Path, required=True)
    verify_export.add_argument(
        "--expected-index-sha256", type=_sha256_argument, required=True
    )
    verify_export.add_argument(
        "--expected-index-wire-sha256",
        type=_sha256_argument,
        required=True,
    )

    bind = commands.add_parser(
        "bind-response",
        help="bind a pinned pending request to a pinned canonical response body",
        allow_abbrev=False,
    )
    bind.add_argument("--pending-file", type=Path, required=True)
    bind.add_argument(
        "--expected-pending-wire-sha256",
        type=_sha256_argument,
        required=True,
    )
    bind.add_argument("--response-body-file", type=Path, required=True)
    bind.add_argument(
        "--expected-response-body-wire-sha256",
        type=_sha256_argument,
        required=True,
    )
    bind.add_argument("--output-root", type=Path, required=True)

    verify_response = commands.add_parser(
        "verify-response",
        help="independently read one response envelope under its external pin",
        allow_abbrev=False,
    )
    verify_response.add_argument("--response-root", type=Path, required=True)
    verify_response.add_argument(
        "--expected-response-wire-sha256",
        type=_sha256_argument,
        required=True,
    )
    return parser


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
        raise ReplayTaskResponseError(
            "output_invalid", "control-plane output did not normalize"
        ) from None


def _canonical_line(value: object) -> bytes:
    return _canonical_json(value) + b"\n"


def _freeze_json(value: object, *, depth: int = 0) -> object:
    if depth > 20:
        raise ValueError("JSON nesting is too deep")
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("JSON number is not finite")
        return value
    if type(value) is list:
        return tuple(_freeze_json(item, depth=depth + 1) for item in value)
    if type(value) is dict:
        return MappingProxyType(
            {
                key: _freeze_json(item, depth=depth + 1)
                for key, item in value.items()
            }
        )
    raise ValueError("unsupported JSON value")


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw_json(item) for item in value]
    return value


class _DuplicateJsonKey(ValueError):
    pass


def _strict_json_object_line(payload: bytes) -> Mapping[str, object]:
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise ReplayTaskResponseError(
            "noncanonical_json", "control JSON must be one canonical line"
        )

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if type(key) is not str or key in result:
                raise _DuplicateJsonKey(key)
            result[key] = value
        return result

    try:
        parsed = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")
            ),
        )
        frozen = _freeze_json(parsed)
        canonical = _canonical_line(_thaw_json(frozen))
    except (
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        RecursionError,
        TypeError,
        ValueError,
    ):
        raise ReplayTaskResponseError(
            "invalid_json", "control JSON is invalid"
        ) from None
    if not isinstance(frozen, Mapping) or canonical != payload:
        raise ReplayTaskResponseError(
            "noncanonical_json", "control JSON is not canonical"
        )
    return frozen


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ReplayTaskResponseError(
            "invalid_contract", f"{name} is not a lower-case SHA-256 digest"
        )
    return value


def _require_key_id(value: object) -> str:
    if type(value) is not str or _KEY_ID_RE.fullmatch(value) is None:
        raise ReplayTaskResponseError(
            "invalid_contract", "sealed batch key ID is invalid"
        )
    return value


@dataclass(frozen=True, slots=True)
class DiscoveryTaskFilePinV1:
    """One task filename and exact wire binding in public split order."""

    ordinal: int
    task_id: str
    snapshot_id: str
    task_file: str
    task_wire_sha256: str

    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or self.ordinal < 1:
            raise ReplayTaskResponseError(
                "invalid_contract", "task ordinal is invalid"
            )
        _require_sha256(self.task_wire_sha256, name="task_wire_sha256")
        expected_file = f"{TASK_DIRECTORY}/{self.task_id}.json"
        if (
            type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.snapshot_id) is not str
            or _SNAPSHOT_ID_RE.fullmatch(self.snapshot_id) is None
            or type(self.task_file) is not str
            or self.task_file != expected_file
        ):
            raise ReplayTaskResponseError(
                "invalid_contract", "task file binding is invalid"
            )

    @classmethod
    def from_dict(cls, value: object) -> "DiscoveryTaskFilePinV1":
        if type(value) is not dict or frozenset(value) != frozenset(
            {
                "ordinal",
                "snapshot_id",
                "task_file",
                "task_id",
                "task_wire_sha256",
            }
        ):
            raise ReplayTaskResponseError(
                "invalid_contract", "task file pin fields are invalid"
            )
        return cls(
            ordinal=value["ordinal"],
            task_id=value["task_id"],
            snapshot_id=value["snapshot_id"],
            task_file=value["task_file"],
            task_wire_sha256=value["task_wire_sha256"],
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "ordinal": self.ordinal,
            "snapshot_id": self.snapshot_id,
            "task_file": self.task_file,
            "task_id": self.task_id,
            "task_wire_sha256": self.task_wire_sha256,
        }


@dataclass(frozen=True, slots=True)
class DiscoveryTaskSplitExportIndexV1:
    """Canonical split index whose external pin closes all task wires."""

    split: Literal["test", "train"]
    tasks_sha256: str
    public_manifest_sha256: str
    sealed_batch_manifest_sha256: str
    sealed_batch_content_root: str
    sealed_batch_key_id: str
    tasks: tuple[DiscoveryTaskFilePinV1, ...]
    contract_version: int = 1
    kind: str = DISCOVERY_TASK_SPLIT_EXPORT_KIND
    profile_id: str = PROFILE_ID
    index_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != 1
            or type(self.kind) is not str
            or self.kind != DISCOVERY_TASK_SPLIT_EXPORT_KIND
            or type(self.profile_id) is not str
            or self.profile_id != PROFILE_ID
            or type(self.split) is not str
            or self.split not in _SPLIT_COUNTS
        ):
            raise ReplayTaskResponseError(
                "invalid_contract", "task split export header is invalid"
            )
        for value, name in (
            (self.tasks_sha256, "tasks_sha256"),
            (self.public_manifest_sha256, "public_manifest_sha256"),
            (
                self.sealed_batch_manifest_sha256,
                "sealed_batch_manifest_sha256",
            ),
            (self.sealed_batch_content_root, "sealed_batch_content_root"),
        ):
            _require_sha256(value, name=name)
        _require_key_id(self.sealed_batch_key_id)
        normalized = tuple(self.tasks)
        if (
            len(normalized) != _SPLIT_COUNTS[self.split]
            or any(type(item) is not DiscoveryTaskFilePinV1 for item in normalized)
            or tuple(item.ordinal for item in normalized)
            != tuple(range(1, len(normalized) + 1))
            or any(
                not item.task_id.startswith(f"VG-{self.split.upper()}-")
                for item in normalized
            )
            or len({item.task_id for item in normalized}) != len(normalized)
            or len({item.snapshot_id for item in normalized}) != len(normalized)
            or len({item.task_file for item in normalized}) != len(normalized)
        ):
            raise ReplayTaskResponseError(
                "invalid_contract", "task split export membership is invalid"
            )
        object.__setattr__(self, "tasks", normalized)
        semantic = hashlib.sha256(
            DISCOVERY_TASK_SPLIT_EXPORT_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        object.__setattr__(self, "index_sha256", semantic)

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "kind": self.kind,
            "profile_id": self.profile_id,
            "public_manifest_sha256": self.public_manifest_sha256,
            "sealed_batch_content_root": self.sealed_batch_content_root,
            "sealed_batch_key_id": self.sealed_batch_key_id,
            "sealed_batch_manifest_sha256": self.sealed_batch_manifest_sha256,
            "split": self.split,
            "task_count": len(self.tasks),
            "tasks": [item.to_dict() for item in self.tasks],
            "tasks_sha256": self.tasks_sha256,
        }

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_index_sha256: str,
        expected_wire_sha256: str,
    ) -> "DiscoveryTaskSplitExportIndexV1":
        expected_semantic = _require_sha256(
            expected_index_sha256, name="expected_index_sha256"
        )
        expected_wire = _require_sha256(
            expected_wire_sha256, name="expected_index_wire_sha256"
        )
        if hashlib.sha256(payload).hexdigest() != expected_wire:
            raise ReplayTaskResponseError(
                "index_wire_mismatch", "task split index wire pin differs"
            )
        raw = dict(_strict_json_object_line(payload))
        if frozenset(raw) != frozenset(
            {
                "contract_version",
                "index_sha256",
                "kind",
                "profile_id",
                "public_manifest_sha256",
                "sealed_batch_content_root",
                "sealed_batch_key_id",
                "sealed_batch_manifest_sha256",
                "split",
                "task_count",
                "tasks",
                "tasks_sha256",
            }
        ):
            raise ReplayTaskResponseError(
                "invalid_contract", "task split index fields are invalid"
            )
        raw_tasks = raw["tasks"]
        if type(raw_tasks) is not tuple:
            raise ReplayTaskResponseError(
                "invalid_contract", "task split index tasks are invalid"
            )
        result = cls(
            split=raw["split"],
            tasks_sha256=raw["tasks_sha256"],
            public_manifest_sha256=raw["public_manifest_sha256"],
            sealed_batch_manifest_sha256=raw[
                "sealed_batch_manifest_sha256"
            ],
            sealed_batch_content_root=raw["sealed_batch_content_root"],
            sealed_batch_key_id=raw["sealed_batch_key_id"],
            tasks=tuple(
                DiscoveryTaskFilePinV1.from_dict(_thaw_json(item))
                for item in raw_tasks
            ),
            contract_version=raw["contract_version"],
            kind=raw["kind"],
            profile_id=raw["profile_id"],
        )
        if (
            type(raw["task_count"]) is not int
            or raw["task_count"] != len(result.tasks)
            or raw["index_sha256"] != result.index_sha256
            or result.index_sha256 != expected_semantic
            or result.to_bytes() != payload
        ):
            raise ReplayTaskResponseError(
                "index_binding_mismatch", "task split index binding differs"
            )
        return result

    def to_dict(self) -> dict[str, object]:
        return {**self._core_dict(), "index_sha256": self.index_sha256}

    def to_bytes(self) -> bytes:
        return _canonical_line(self.to_dict())

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifiedDiscoveryTaskSplitExportV1:
    index: DiscoveryTaskSplitExportIndexV1
    tasks: tuple[DiscoveryTaskInputV1, ...]

    def __post_init__(self) -> None:
        if (
            type(self.index) is not DiscoveryTaskSplitExportIndexV1
            or type(self.tasks) is not tuple
            or len(self.tasks) != len(self.index.tasks)
            or any(type(task) is not DiscoveryTaskInputV1 for task in self.tasks)
        ):
            raise ReplayTaskResponseError(
                "invalid_contract", "verified task split export is invalid"
            )


def _is_reparse(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", 0),
        getattr(value, "st_ctime_ns", 0),
    )


def _binding_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", 0),
    )


def _directory_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _require_safe_directory(path: Path, *, private: bool = False) -> os.stat_result:
    try:
        state = os.lstat(_windows_extended_path(path))
    except OSError:
        raise ReplayTaskResponseError(
            "input_unavailable", "required directory is unavailable"
        ) from None
    if (
        not stat.S_ISDIR(state.st_mode)
        or stat.S_ISLNK(state.st_mode)
        or _is_reparse(state)
        or (
            private
            and os.name == "posix"
            and state.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        )
    ):
        raise ReplayTaskResponseError(
            "unsafe_path", "required directory is unsafe"
        )
    return state


def _root_chain(path: Path) -> tuple[Path, ...]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    result: list[Path] = []
    current = absolute
    while True:
        result.append(current)
        if current.parent == current:
            break
        current = current.parent
    result.reverse()
    return tuple(result)


def _guard_directory_chain(
    path: Path, *, final_private: bool = False
) -> tuple[tuple[Path, tuple[int, int]], ...]:
    chain = _root_chain(path)
    return tuple(
        (
            component,
            _directory_identity(
                _require_safe_directory(
                    component,
                    private=final_private and index == len(chain) - 1,
                )
            ),
        )
        for index, component in enumerate(chain)
    )


def _assert_directory_chain(
    guard: tuple[tuple[Path, tuple[int, int]], ...],
    *,
    final_private: bool = False,
) -> None:
    for index, (component, expected) in enumerate(guard):
        state = _require_safe_directory(
            component,
            private=final_private and index == len(guard) - 1,
        )
        if _directory_identity(state) != expected:
            raise ReplayTaskResponseError(
                "input_changed", "directory identity changed"
            )


def _read_regular(
    path: str | os.PathLike[str], *, maximum_bytes: int
) -> bytes:
    try:
        canonical = _canonical_existing_path(path, directory=False, status=2)
    except SnapshotBatchError as error:
        raise ReplayTaskResponseError(
            "unsafe_path", "control file path is unavailable"
        ) from error
    parent_guard = _guard_directory_chain(canonical.parent)
    try:
        before = os.lstat(_windows_extended_path(canonical))
    except OSError:
        raise ReplayTaskResponseError(
            "input_unavailable", "required file is unavailable"
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
        raise ReplayTaskResponseError(
            "unsafe_path", "required file is unsafe or exceeds its limit"
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(_windows_extended_path(canonical), flags)
    except OSError:
        raise ReplayTaskResponseError(
            "input_unavailable", "required file could not be opened"
        ) from None
    try:
        opened = os.fstat(descriptor)
        if _binding_identity(opened) != _binding_identity(before):
            raise ReplayTaskResponseError(
                "input_changed", "required file changed while opening"
            )
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(
                descriptor, min(64 * 1024, maximum_bytes + 1 - consumed)
            )
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > maximum_bytes:
                raise ReplayTaskResponseError(
                    "limit_exceeded", "required file exceeds its byte limit"
                )
        finished = os.fstat(descriptor)
        if _identity(finished) != _identity(opened) or consumed != opened.st_size:
            raise ReplayTaskResponseError(
                "input_changed", "required file changed while reading"
            )
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(_windows_extended_path(canonical))
    except OSError:
        raise ReplayTaskResponseError(
            "input_changed", "required file changed after reading"
        ) from None
    _assert_directory_chain(parent_guard)
    if _identity(after) != _identity(before):
        raise ReplayTaskResponseError(
            "input_changed", "required file changed after reading"
        )
    return b"".join(chunks)


def _scan_exact_directory(
    path: Path, expected_names: frozenset[str]
) -> tuple[int, int]:
    before = _require_safe_directory(path, private=True)
    try:
        with os.scandir(_windows_extended_path(path)) as entries:
            names = frozenset(entry.name for entry in entries)
    except OSError:
        raise ReplayTaskResponseError(
            "input_unavailable", "directory could not be enumerated"
        ) from None
    after = _require_safe_directory(path, private=True)
    if _directory_identity(after) != _directory_identity(before):
        raise ReplayTaskResponseError(
            "input_changed", "directory changed while enumerating"
        )
    if names != expected_names:
        raise ReplayTaskResponseError(
            "layout_invalid", "directory membership is invalid"
        )
    return _directory_identity(after)


def _task_wire(task: DiscoveryTaskInputV1) -> bytes:
    try:
        payload = _canonical_line(task.to_dict())
        parsed = DiscoveryTaskInputV1.from_dict(
            _thaw_json(_strict_json_object_line(payload))
        )
    except (DiscoveryContractError, ReplayTaskResponseError, TypeError, ValueError):
        raise ReplayTaskResponseError(
            "task_invalid", "discovery task did not normalize"
        ) from None
    if parsed != task or len(payload) > _MAX_TASK_BYTES:
        raise ReplayTaskResponseError(
            "task_invalid", "discovery task wire is invalid"
        )
    return payload


def read_discovery_task_split_export_v1(
    root: str | os.PathLike[str],
    *,
    expected_index_sha256: str,
    expected_index_wire_sha256: str,
) -> VerifiedDiscoveryTaskSplitExportV1:
    """Read one exact task split export using only its external index pins."""

    try:
        canonical = _canonical_existing_path(root, directory=True, status=2)
    except SnapshotBatchError as error:
        raise ReplayTaskResponseError(
            "unsafe_path", "task split export root is unavailable"
        ) from error
    parent_guard = _guard_directory_chain(canonical.parent)
    root_identity = _scan_exact_directory(
        canonical, frozenset({INDEX_FILENAME, TASK_DIRECTORY})
    )
    task_root = canonical / TASK_DIRECTORY
    task_root_state = _require_safe_directory(task_root, private=True)
    task_root_identity = _directory_identity(task_root_state)
    index_payload = _read_regular(
        canonical / INDEX_FILENAME, maximum_bytes=_MAX_INDEX_BYTES
    )
    index = DiscoveryTaskSplitExportIndexV1.from_bytes(
        index_payload,
        expected_index_sha256=expected_index_sha256,
        expected_wire_sha256=expected_index_wire_sha256,
    )
    expected_names = frozenset(f"{item.task_id}.json" for item in index.tasks)
    _scan_exact_directory(task_root, expected_names)
    tasks: list[DiscoveryTaskInputV1] = []
    first_wires: list[bytes] = []
    for binding in index.tasks:
        payload = _read_regular(
            canonical.joinpath(*binding.task_file.split("/")),
            maximum_bytes=_MAX_TASK_BYTES,
        )
        if hashlib.sha256(payload).hexdigest() != binding.task_wire_sha256:
            raise ReplayTaskResponseError(
                "task_wire_mismatch", "discovery task wire pin differs"
            )
        raw = _strict_json_object_line(payload)
        try:
            task = DiscoveryTaskInputV1.from_dict(_thaw_json(raw))
        except (DiscoveryContractError, TypeError, ValueError):
            raise ReplayTaskResponseError(
                "task_invalid", "exported discovery task is invalid"
            ) from None
        if (
            _task_wire(task) != payload
            or task.task_id != binding.task_id
            or task.snapshot_id != binding.snapshot_id
        ):
            raise ReplayTaskResponseError(
                "task_binding_mismatch", "exported discovery task binding differs"
            )
        tasks.append(task)
        first_wires.append(payload)
    if len({(task.repo_url.casefold(), task.commit) for task in tasks}) != len(tasks):
        raise ReplayTaskResponseError(
            "task_binding_mismatch", "exported discovery snapshots repeat"
        )

    # Close the finite read window: all names, identities, index bytes, and
    # task bytes must still be exactly what this result represents.
    if (
        _scan_exact_directory(
            canonical, frozenset({INDEX_FILENAME, TASK_DIRECTORY})
        )
        != root_identity
        or _scan_exact_directory(task_root, expected_names) != task_root_identity
        or _read_regular(canonical / INDEX_FILENAME, maximum_bytes=_MAX_INDEX_BYTES)
        != index_payload
    ):
        raise ReplayTaskResponseError(
            "input_changed", "task split export changed during readback"
        )
    for binding, expected_payload in zip(index.tasks, first_wires):
        if (
            _read_regular(
                canonical.joinpath(*binding.task_file.split("/")),
                maximum_bytes=_MAX_TASK_BYTES,
            )
            != expected_payload
        ):
            raise ReplayTaskResponseError(
                "input_changed", "task split export changed during readback"
            )
    _assert_directory_chain(parent_guard)
    return VerifiedDiscoveryTaskSplitExportV1(index=index, tasks=tuple(tasks))


def read_pinned_authoring_response_root_v1(
    root: str | os.PathLike[str], *, expected_wire_sha256: str
) -> ReplayAuthoringResponseV1:
    """Read one fixed response directory using an external envelope pin."""

    expected = _require_sha256(
        expected_wire_sha256, name="expected_response_wire_sha256"
    )
    try:
        canonical = _canonical_existing_path(root, directory=True, status=2)
    except SnapshotBatchError as error:
        raise ReplayTaskResponseError(
            "unsafe_path", "response root is unavailable"
        ) from error
    parent_guard = _guard_directory_chain(canonical.parent)
    root_identity = _scan_exact_directory(
        canonical, frozenset({RESPONSE_FILENAME})
    )
    payload = _read_regular(
        canonical / RESPONSE_FILENAME,
        maximum_bytes=REPLAY_AUTHORING_MAX_RESPONSE_BYTES,
    )
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ReplayTaskResponseError(
            "response_wire_mismatch", "response envelope wire pin differs"
        )
    try:
        response = ReplayAuthoringResponseV1.from_bytes(payload)
    except ReplayAuthoringError as error:
        raise ReplayTaskResponseError(
            "response_invalid", "response envelope is invalid"
        ) from error
    if (
        _scan_exact_directory(canonical, frozenset({RESPONSE_FILENAME}))
        != root_identity
        or _read_regular(
            canonical / RESPONSE_FILENAME,
            maximum_bytes=REPLAY_AUTHORING_MAX_RESPONSE_BYTES,
        )
        != payload
    ):
        raise ReplayTaskResponseError(
            "input_changed", "response envelope changed during readback"
        )
    _assert_directory_chain(parent_guard)
    return response


@dataclass(slots=True)
class _TrackedStaging:
    root: Path
    root_identity: tuple[int, int]
    nodes: dict[str, tuple[bool, tuple[int, ...]]]

    def mkdir(self, relative: str) -> Path:
        path = self.root / relative
        try:
            os.mkdir(_windows_extended_path(path), 0o700)
            if os.name == "posix":
                os.chmod(path, 0o700)
            state = os.lstat(_windows_extended_path(path))
        except OSError as error:
            raise ReplayTaskResponseError(
                "publication_failed", "staging directory creation failed"
            ) from error
        if not stat.S_ISDIR(state.st_mode) or _is_reparse(state):
            raise ReplayTaskResponseError(
                "publication_failed", "staging directory is unsafe"
            )
        self.nodes[relative] = (True, _directory_identity(state))
        return path

    def write(self, relative: str, payload: bytes) -> None:
        path = self.root.joinpath(*relative.split("/"))
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(_windows_extended_path(path), flags, 0o600)
        except OSError as error:
            raise ReplayTaskResponseError(
                "publication_failed", "staging file creation failed"
            ) from error
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink != 1
        ):
            os.close(descriptor)
            raise ReplayTaskResponseError(
                "publication_failed", "staging file is unsafe"
            )
        self.nodes[relative] = (False, _identity(opened))
        failure: BaseException | None = None
        finished = opened
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written < 1:
                    raise OSError(errno.EIO, "short write")
                view = view[written:]
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        except BaseException as error:
            failure = error
        try:
            finished = os.fstat(descriptor)
            self.nodes[relative] = (False, _identity(finished))
        except BaseException as error:
            if failure is None:
                failure = error
        try:
            os.close(descriptor)
        except BaseException as error:
            if failure is None:
                failure = error
        if failure is not None:
            if isinstance(failure, KeyboardInterrupt):
                raise failure
            raise ReplayTaskResponseError(
                "publication_failed", "staging file write failed"
            ) from failure
        try:
            state = os.lstat(_windows_extended_path(path))
        except OSError as error:
            raise ReplayTaskResponseError(
                "publication_failed", "staging file identity is unavailable"
            ) from error
        if (
            not stat.S_ISREG(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
            or state.st_nlink != 1
            or _binding_identity(state) != _binding_identity(finished)
            or state.st_size != len(payload)
        ):
            raise ReplayTaskResponseError(
                "publication_failed", "staging file identity changed"
            )
        self.nodes[relative] = (False, _identity(state))


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_noreplace(
    source: Path,
    destination: Path,
    *,
    source_dir_fd: int | None = None,
    destination_dir_fd: int | None = None,
) -> None:
    if os.name == "posix":
        try:
            renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
        except (AttributeError, OSError):
            renameat2 = None
        if renameat2 is None:
            raise OSError(errno.ENOTSUP, "atomic no-replace rename unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100 if source_dir_fd is None else source_dir_fd,
            os.fsencode(source),
            -100 if destination_dir_fd is None else destination_dir_fd,
            os.fsencode(destination),
            1,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise FileExistsError(str(destination))
        raise OSError(error_number, "atomic no-replace rename failed")
    if source_dir_fd is not None or destination_dir_fd is not None:
        raise OSError(errno.ENOTSUP, "relative no-replace rename unavailable")
    try:
        os.lstat(_windows_extended_path(destination))
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(str(destination))
    os.rename(_windows_extended_path(source), _windows_extended_path(destination))


def _safe_cleanup_staging(staging: _TrackedStaging) -> None:
    """Remove only identities created by this transaction, never recursively."""

    try:
        root_state = os.lstat(_windows_extended_path(staging.root))
    except OSError:
        return
    if (
        not stat.S_ISDIR(root_state.st_mode)
        or _is_reparse(root_state)
        or _directory_identity(root_state) != staging.root_identity
    ):
        return
    files = sorted(
        (
            (relative, identity)
            for relative, (directory, identity) in staging.nodes.items()
            if not directory
        ),
        reverse=True,
    )
    directories = sorted(
        (
            (relative, identity)
            for relative, (directory, identity) in staging.nodes.items()
            if directory
        ),
        key=lambda item: item[0].count("/"),
        reverse=True,
    )
    for relative, expected in files:
        path = staging.root.joinpath(*relative.split("/"))
        try:
            state = os.lstat(_windows_extended_path(path))
            if (
                stat.S_ISREG(state.st_mode)
                and not stat.S_ISLNK(state.st_mode)
                and not _is_reparse(state)
                and state.st_nlink == 1
                and _identity(state) == expected
            ):
                os.unlink(_windows_extended_path(path))
        except OSError:
            pass
    for relative, expected in directories:
        path = staging.root.joinpath(*relative.split("/"))
        try:
            state = os.lstat(_windows_extended_path(path))
            if (
                stat.S_ISDIR(state.st_mode)
                and not stat.S_ISLNK(state.st_mode)
                and not _is_reparse(state)
                and _directory_identity(state) == expected
            ):
                os.rmdir(_windows_extended_path(path))
        except OSError:
            pass
    try:
        state = os.lstat(_windows_extended_path(staging.root))
        if (
            stat.S_ISDIR(state.st_mode)
            and not stat.S_ISLNK(state.st_mode)
            and not _is_reparse(state)
            and _directory_identity(state) == staging.root_identity
        ):
            os.rmdir(_windows_extended_path(staging.root))
    except OSError:
        pass


def _publish_directory(
    output_root: Path,
    *,
    populate: Callable[[_TrackedStaging], None],
    verify: Callable[[Path], object],
    mutation_state: list[bool] | None = None,
) -> object:
    if mutation_state is not None:
        mutation_state[0] = False
    try:
        output = _canonical_new_child(output_root, status=2)
    except SnapshotBatchError as error:
        raise ReplayTaskResponseError(
            "invalid_output", "output root is invalid"
        ) from error
    parent_guard = _guard_directory_chain(output.parent, final_private=True)
    try:
        os.lstat(_windows_extended_path(output))
    except FileNotFoundError:
        pass
    except OSError:
        raise ReplayTaskResponseError(
            "output_unavailable", "output state is unavailable"
        ) from None
    else:
        raise ReplayTaskResponseError("output_exists", "output already exists")

    staging_path = output.parent / (
        f".{output.name}.replay-task-response-{uuid.uuid4().hex}"
    )
    try:
        os.mkdir(_windows_extended_path(staging_path), 0o700)
        if os.name == "posix":
            os.chmod(staging_path, 0o700)
        state = os.lstat(_windows_extended_path(staging_path))
    except OSError as error:
        raise ReplayTaskResponseError(
            "publication_failed", "staging root creation failed"
        ) from error
    if not stat.S_ISDIR(state.st_mode) or _is_reparse(state):
        raise ReplayTaskResponseError(
            "publication_failed", "staging root is unsafe"
        )
    staging = _TrackedStaging(
        root=staging_path,
        root_identity=_directory_identity(state),
        nodes={},
    )
    committed = False
    parent_descriptor: int | None = None
    staging_descriptor: int | None = None
    try:
        if os.name == "posix":
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            parent_descriptor = os.open(output.parent, directory_flags)
            opened_parent = os.fstat(parent_descriptor)
            if _directory_identity(opened_parent) != parent_guard[-1][1]:
                raise ReplayTaskResponseError(
                    "input_changed", "output parent changed before opening"
                )
            staging_descriptor = os.open(
                staging.root.name,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            opened_staging = os.fstat(staging_descriptor)
            if _directory_identity(opened_staging) != staging.root_identity:
                raise ReplayTaskResponseError(
                    "publication_changed", "staging root changed before opening"
                )
        populate(staging)
        before = verify(staging.root)
        for relative, (directory, _identity_value) in sorted(
            staging.nodes.items(),
            key=lambda item: item[0].count("/"),
            reverse=True,
        ):
            if directory:
                _fsync_directory(staging.root.joinpath(*relative.split("/")))
        _fsync_directory(staging.root)
        _assert_directory_chain(parent_guard, final_private=True)
        current = _require_safe_directory(staging.root, private=True)
        if _directory_identity(current) != staging.root_identity:
            raise ReplayTaskResponseError(
                "publication_changed", "staging root identity changed"
            )
        try:
            if mutation_state is not None:
                # From this point until an exact post-failure classification,
                # an interrupt may have raced with the no-replace rename.
                mutation_state[0] = True
            if parent_descriptor is not None:
                _rename_directory_noreplace(
                    Path(staging.root.name),
                    Path(output.name),
                    source_dir_fd=parent_descriptor,
                    destination_dir_fd=parent_descriptor,
                )
            else:
                _rename_directory_noreplace(staging.root, output)
            committed = True
        except BaseException as error:
            def relative_state(name: str, absolute: Path) -> os.stat_result | None:
                try:
                    if parent_descriptor is not None:
                        return os.stat(
                            name,
                            dir_fd=parent_descriptor,
                            follow_symlinks=False,
                        )
                    return os.lstat(_windows_extended_path(absolute))
                except FileNotFoundError:
                    return None
                except OSError:
                    raise ReplayTaskResponseError(
                        "publication_uncertain",
                        "publication state could not be classified",
                        committed=True,
                    ) from None

            staging_after = relative_state(staging.root.name, staging.root)
            output_after = relative_state(output.name, output)
            staging_identity = (
                None
                if staging_after is None
                else _directory_identity(staging_after)
            )
            output_identity = (
                None if output_after is None else _directory_identity(output_after)
            )
            if (
                staging_identity == staging.root_identity
                and output_identity != staging.root_identity
            ):
                if mutation_state is not None:
                    mutation_state[0] = False
                if isinstance(error, FileExistsError):
                    raise ReplayTaskResponseError(
                        "output_exists", "output was created concurrently"
                    ) from None
                if isinstance(error, KeyboardInterrupt):
                    raise
                raise ReplayTaskResponseError(
                    "publication_failed", "no-replace publication failed"
                ) from error
            if staging_identity is None and output_identity == staging.root_identity:
                committed = True
            else:
                raise ReplayTaskResponseError(
                    "publication_uncertain",
                    "publication state could not be classified",
                    committed=True,
                ) from None
        if parent_descriptor is not None:
            os.fsync(parent_descriptor)
        else:
            _fsync_directory(output.parent)
        _assert_directory_chain(parent_guard, final_private=True)
        published = _require_safe_directory(output, private=True)
        if _directory_identity(published) != staging.root_identity:
            raise ReplayTaskResponseError(
                "publication_uncertain",
                "published output identity changed",
                committed=True,
            )
        after = verify(output)
        if after != before:
            raise ReplayTaskResponseError(
                "publication_uncertain",
                "published output changed during readback",
                committed=True,
            )
        _assert_directory_chain(parent_guard, final_private=True)
        if _directory_identity(_require_safe_directory(output, private=True)) != (
            staging.root_identity
        ):
            raise ReplayTaskResponseError(
                "publication_uncertain",
                "published output identity changed after readback",
                committed=True,
            )
        return after
    except ReplayTaskResponseError as error:
        if committed and not error.committed:
            raise ReplayTaskResponseError(
                "publication_uncertain",
                "published output could not be confirmed",
                committed=True,
            ) from None
        raise
    except BaseException as error:
        if committed:
            raise ReplayTaskResponseError(
                "publication_uncertain",
                "published output could not be confirmed",
                committed=True,
            ) from None
        if isinstance(error, KeyboardInterrupt):
            raise
        raise ReplayTaskResponseError(
            "publication_failed", "output transaction failed"
        ) from error
    finally:
        if not committed:
            _safe_cleanup_staging(staging)
        if staging_descriptor is not None:
            try:
                os.close(staging_descriptor)
            except OSError:
                pass
        if parent_descriptor is not None:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass


def _assert_output_disjoint(
    output_root: Path,
    protected: tuple[tuple[Path, bool], ...],
) -> None:
    try:
        output = _canonical_new_child(output_root, status=2)
    except SnapshotBatchError as error:
        raise ReplayTaskResponseError(
            "invalid_output", "output root is invalid"
        ) from error
    output_parent_chain = frozenset(
        identity for _path, identity in _guard_directory_chain(output.parent)
    )
    for path, is_directory in protected:
        if paths_overlap_v1(
            output_root,
            path,
            left_exists=False,
            right_directory=is_directory,
        ):
            raise ReplayTaskResponseError(
                "path_overlap", "output overlaps a trusted input"
            )
        if is_directory:
            try:
                canonical = _canonical_existing_path(
                    path, directory=True, status=2
                )
            except SnapshotBatchError as error:
                raise ReplayTaskResponseError(
                    "unsafe_path", "trusted input root is unavailable"
                ) from error
            protected_identity = _directory_identity(
                _require_safe_directory(canonical)
            )
            if protected_identity in output_parent_chain:
                raise ReplayTaskResponseError(
                    "path_overlap", "output aliases a trusted input root"
                )


def _public_task_identity(task: object) -> tuple[object, ...]:
    return (
        getattr(task, "task_id", None),
        getattr(task, "repo_url", None),
        getattr(task, "commit", None),
        getattr(task, "split", None),
        getattr(task, "instruction_id", None),
    )


def _batch_task_identity(task: SnapshotBatchTask) -> tuple[object, ...]:
    return (
        task.task_id,
        task.repo_url,
        task.commit,
        task.split,
        task.instruction_id,
    )


def _assert_batch_export_binding(
    public: VerifiedTaskExport, batch: SnapshotBatchSummary
) -> None:
    if (
        type(public) is not VerifiedTaskExport
        or type(batch) is not SnapshotBatchSummary
        or public.profile_id != batch.profile_id
        or public.profile_id != PROFILE_ID
        or public.split != batch.split
        or public.tasks_sha256 != batch.tasks_sha256
        or public.public_manifest_sha256 != batch.public_manifest_sha256
        or len(public.tasks) != batch.task_count
        or tuple(_public_task_identity(task) for task in public.tasks)
        != tuple(_batch_task_identity(task) for task in batch.tasks)
    ):
        raise ReplayTaskResponseError(
            "batch_binding_mismatch",
            "sealed batch does not match the pinned public task export",
        )


def _discovery_tasks(
    public: VerifiedTaskExport, batch: SnapshotBatchSummary
) -> tuple[DiscoveryTaskInputV1, ...]:
    _assert_batch_export_binding(public, batch)
    result: list[DiscoveryTaskInputV1] = []
    for member in batch.tasks:
        try:
            task = DiscoveryTaskInputV1(
                task_id=member.task_id,
                repo_url=member.repo_url,
                commit=member.commit,
                instruction_id=member.instruction_id,
                snapshot_manifest_sha256=member.snapshot_manifest_sha256,
                snapshot_content_root=member.snapshot_content_root,
            )
        except (DiscoveryContractError, TypeError, ValueError):
            raise ReplayTaskResponseError(
                "task_invalid", "sealed batch member cannot form a discovery task"
            ) from None
        result.append(task)
    return tuple(result)


def _build_index(
    public: VerifiedTaskExport,
    batch: SnapshotBatchSummary,
    tasks: tuple[DiscoveryTaskInputV1, ...],
) -> tuple[DiscoveryTaskSplitExportIndexV1, tuple[bytes, ...]]:
    wires = tuple(_task_wire(task) for task in tasks)
    index = DiscoveryTaskSplitExportIndexV1(
        split=public.split,
        tasks_sha256=public.tasks_sha256,
        public_manifest_sha256=public.public_manifest_sha256,
        sealed_batch_manifest_sha256=batch.manifest_sha256,
        sealed_batch_content_root=batch.batch_content_root,
        sealed_batch_key_id=batch.key_id,
        tasks=tuple(
            DiscoveryTaskFilePinV1(
                ordinal=index,
                task_id=task.task_id,
                snapshot_id=task.snapshot_id,
                task_file=f"{TASK_DIRECTORY}/{task.task_id}.json",
                task_wire_sha256=hashlib.sha256(wire).hexdigest(),
            )
            for index, (task, wire) in enumerate(zip(tasks, wires), 1)
        ),
    )
    return index, wires


def _export_split(
    args: argparse.Namespace, *, mutation_state: list[bool] | None = None
) -> DiscoveryTaskSplitExportIndexV1:
    _require_key_id(args.key_id)
    try:
        first_public = load_verified_task_export(
            args.task_export_dir,
            expected_tasks_sha256=args.expected_tasks_sha256,
            expected_public_manifest_sha256=(
                args.expected_public_manifest_sha256
            ),
        )
    except SnapshotBatchError as error:
        raise ReplayTaskResponseError(
            "task_export_rejected", "public task export was rejected"
        ) from error
    key: bytearray | None = None
    try:
        key = read_attestation_key_file_v1(args.key_file)
        batch = verify_snapshot_batch(
            args.sealed_batch_root,
            expected_manifest_sha256=args.expected_batch_manifest_sha256,
            attestation_key=key,
            expected_key_id=args.key_id,
        )
    except (SnapshotBatchError, TrustedInputError) as error:
        raise ReplayTaskResponseError(
            "sealed_batch_rejected", "sealed snapshot batch was rejected"
        ) from error
    finally:
        zero_secret_buffer_v1(key)
    try:
        second_public = load_verified_task_export(
            args.task_export_dir,
            expected_tasks_sha256=args.expected_tasks_sha256,
            expected_public_manifest_sha256=(
                args.expected_public_manifest_sha256
            ),
        )
    except SnapshotBatchError as error:
        raise ReplayTaskResponseError(
            "task_export_rejected", "public task export changed"
        ) from error
    if first_public != second_public:
        raise ReplayTaskResponseError(
            "task_export_changed", "public task export changed during authentication"
        )
    tasks = _discovery_tasks(second_public, batch)
    index, wires = _build_index(second_public, batch, tasks)
    output_root = Path(args.output_root)
    _assert_output_disjoint(
        output_root,
        (
            (second_public.root, True),
            (batch.batch_root, True),
            (Path(args.key_file), False),
        ),
    )

    def populate(staging: _TrackedStaging) -> None:
        staging.mkdir(TASK_DIRECTORY)
        for binding, wire in zip(index.tasks, wires):
            staging.write(binding.task_file, wire)
        staging.write(INDEX_FILENAME, index.to_bytes())

    def verify(root: Path) -> VerifiedDiscoveryTaskSplitExportV1:
        return read_discovery_task_split_export_v1(
            root,
            expected_index_sha256=index.index_sha256,
            expected_index_wire_sha256=index.wire_sha256,
        )

    published = _publish_directory(
        output_root,
        populate=populate,
        verify=verify,
        mutation_state=mutation_state,
    )
    if (
        type(published) is not VerifiedDiscoveryTaskSplitExportV1
        or published.index != index
        or published.tasks != tasks
    ):
        raise ReplayTaskResponseError(
            "publication_uncertain",
            "published task split export differs",
            committed=True,
        )
    return index


def _read_pinned_pending(
    path: Path, expected_wire_sha256: str
) -> tuple[ReplayAuthoringPendingRequestV1, bytes]:
    payload = _read_regular(
        path, maximum_bytes=REPLAY_AUTHORING_MAX_RESPONSE_BYTES
    )
    if hashlib.sha256(payload).hexdigest() != expected_wire_sha256:
        raise ReplayTaskResponseError(
            "pending_wire_mismatch", "pending request wire pin differs"
        )
    try:
        return ReplayAuthoringPendingRequestV1.from_bytes(payload), payload
    except ReplayAuthoringError as error:
        raise ReplayTaskResponseError(
            "pending_invalid", "pending request is invalid"
        ) from error


def _read_pinned_response_body(
    path: Path, expected_wire_sha256: str
) -> tuple[Mapping[str, object], bytes]:
    payload = _read_regular(
        path, maximum_bytes=REPLAY_AUTHORING_MAX_RESPONSE_BYTES
    )
    if hashlib.sha256(payload).hexdigest() != expected_wire_sha256:
        raise ReplayTaskResponseError(
            "response_body_wire_mismatch", "response body wire pin differs"
        )
    return _strict_json_object_line(payload), payload


def _bind_response(
    args: argparse.Namespace, *, mutation_state: list[bool] | None = None
) -> tuple[
    ReplayAuthoringResponseV1, str, str
]:
    pending, pending_wire = _read_pinned_pending(
        args.pending_file, args.expected_pending_wire_sha256
    )
    response_body, body_wire = _read_pinned_response_body(
        args.response_body_file, args.expected_response_body_wire_sha256
    )
    try:
        envelope = ReplayAuthoringResponseV1.from_pending(
            pending, _thaw_json(response_body)
        )
    except ReplayAuthoringError as error:
        raise ReplayTaskResponseError(
            "response_invalid", "response body cannot form an authoring envelope"
        ) from error
    envelope_wire = envelope.to_bytes()
    if len(envelope_wire) > REPLAY_AUTHORING_MAX_RESPONSE_BYTES:
        raise ReplayTaskResponseError(
            "response_invalid", "response envelope exceeds its byte limit"
        )
    output_root = Path(args.output_root)
    _assert_output_disjoint(
        output_root,
        (
            (Path(args.pending_file), False),
            (Path(args.response_body_file), False),
        ),
    )
    wire_sha256 = hashlib.sha256(envelope_wire).hexdigest()

    def populate(staging: _TrackedStaging) -> None:
        staging.write(RESPONSE_FILENAME, envelope_wire)

    def verify(root: Path) -> ReplayAuthoringResponseV1:
        return read_pinned_authoring_response_root_v1(
            root, expected_wire_sha256=wire_sha256
        )

    published = _publish_directory(
        output_root,
        populate=populate,
        verify=verify,
        mutation_state=mutation_state,
    )
    if type(published) is not ReplayAuthoringResponseV1 or published != envelope:
        raise ReplayTaskResponseError(
            "publication_uncertain",
            "published response envelope differs",
            committed=True,
        )
    return (
        envelope,
        hashlib.sha256(pending_wire).hexdigest(),
        hashlib.sha256(body_wire).hexdigest(),
    )


def _export_summary(
    operation: str,
    status: str,
    index: DiscoveryTaskSplitExportIndexV1,
) -> dict[str, object]:
    return {
        "batch_content_root": index.sealed_batch_content_root,
        "batch_manifest_sha256": index.sealed_batch_manifest_sha256,
        "cli_version": REPLAY_TASK_RESPONSE_CLI_VERSION,
        "contract_version": 1,
        "index_sha256": index.index_sha256,
        "index_wire_sha256": index.wire_sha256,
        "kind": REPLAY_TASK_RESPONSE_SUMMARY_KIND,
        "operation": operation,
        "public_manifest_sha256": index.public_manifest_sha256,
        "split": index.split,
        "status": status,
        "task_count": len(index.tasks),
        "tasks_sha256": index.tasks_sha256,
    }


def _response_summary(
    operation: str,
    status: str,
    response: ReplayAuthoringResponseV1,
    *,
    pending_wire_sha256: str | None = None,
    response_body_wire_sha256: str | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "cli_version": REPLAY_TASK_RESPONSE_CLI_VERSION,
        "contract_version": 1,
        "kind": REPLAY_TASK_RESPONSE_SUMMARY_KIND,
        "occurrence": response.occurrence,
        "operation": operation,
        "prefix_config_sha256": response.prefix_config_sha256,
        "request_sha256": response.request_sha256,
        "response_sha256": response.response_sha256,
        "response_wire_sha256": hashlib.sha256(response.to_bytes()).hexdigest(),
        "role": response.role,
        "stage": response.stage,
        "status": status,
        "task_id": response.task_id,
    }
    if pending_wire_sha256 is not None:
        value["pending_wire_sha256"] = pending_wire_sha256
    if response_body_wire_sha256 is not None:
        value["response_body_wire_sha256"] = response_body_wire_sha256
    return value


def _write_stdout(value: object) -> None:
    payload = _canonical_line(value)
    if len(payload) > _MAX_SUMMARY_BYTES:
        raise ReplayTaskResponseError(
            "output_invalid", "control-plane summary exceeds its byte limit"
        )
    binary = getattr(sys.stdout, "buffer", None)
    if binary is not None:
        binary.write(payload)
        binary.flush()
    else:
        sys.stdout.write(payload.decode("utf-8", errors="strict"))
        sys.stdout.flush()


def _write_error(code: str) -> None:
    try:
        sys.stderr.write(f"error[{code}]: replay task/response operation failed\n")
        sys.stderr.flush()
    except BaseException:
        pass


def main(argv: Sequence[str] | None = None) -> int:
    mutation_state = [False]
    try:
        args = _parser().parse_args(argv)
        if args.command == "export-split":
            index = _export_split(args, mutation_state=mutation_state)
            result = _export_summary("export-split", "published", index)
        elif args.command == "verify-export":
            verified = read_discovery_task_split_export_v1(
                args.export_root,
                expected_index_sha256=args.expected_index_sha256,
                expected_index_wire_sha256=args.expected_index_wire_sha256,
            )
            result = _export_summary("verify-export", "verified", verified.index)
        elif args.command == "bind-response":
            response, pending_wire, body_wire = _bind_response(
                args, mutation_state=mutation_state
            )
            result = _response_summary(
                "bind-response",
                "published",
                response,
                pending_wire_sha256=pending_wire,
                response_body_wire_sha256=body_wire,
            )
        else:
            response = read_pinned_authoring_response_root_v1(
                args.response_root,
                expected_wire_sha256=args.expected_response_wire_sha256,
            )
            result = _response_summary(
                "verify-response", "verified", response
            )
        _write_stdout(result)
    except KeyboardInterrupt:
        _write_error(
            "committed_uncertain" if mutation_state[0] else "interrupted"
        )
        return (
            EXIT_COMMITTED_UNCERTAIN
            if mutation_state[0]
            else EXIT_INTERRUPTED
        )
    except ReplayTaskResponseError as error:
        publication_may_exist = error.committed or mutation_state[0]
        _write_error(
            error.code
            if error.committed or not mutation_state[0]
            else "committed_uncertain"
        )
        return (
            EXIT_COMMITTED_UNCERTAIN
            if publication_may_exist
            else EXIT_REJECTED
        )
    except (SnapshotBatchError, TrustedInputError, OSError, TypeError, ValueError):
        _write_error(
            "committed_uncertain" if mutation_state[0] else "input_rejected"
        )
        return (
            EXIT_COMMITTED_UNCERTAIN
            if mutation_state[0]
            else EXIT_REJECTED
        )
    except Exception:
        _write_error(
            "committed_uncertain" if mutation_state[0] else "internal_error"
        )
        return (
            EXIT_COMMITTED_UNCERTAIN
            if mutation_state[0]
            else EXIT_REJECTED
        )
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DISCOVERY_TASK_SPLIT_EXPORT_DOMAIN",
    "DISCOVERY_TASK_SPLIT_EXPORT_KIND",
    "DiscoveryTaskFilePinV1",
    "DiscoveryTaskSplitExportIndexV1",
    "ReplayTaskResponseError",
    "VerifiedDiscoveryTaskSplitExportV1",
    "main",
    "read_discovery_task_split_export_v1",
    "read_pinned_authoring_response_root_v1",
]
