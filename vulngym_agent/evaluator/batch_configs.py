"""Strict, read-only replay configuration input for evaluator batches.

The manifest is an attested-by-digest description of the exact canonical
configuration bytes supplied by a trusted evaluator.  It does not authorize
execution on its own: the supervisor copies the four per-task digests from the
returned canonical configurations into each task execution plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Final, Literal

from vulngym_agent.evaluator.oci_worker_entry import (
    OciReplayConfigV1,
    OciWorkerEntryError,
    REPLAY_BACKEND_ID,
    REPLAY_CONFIG_MAX_BYTES,
    REPLAY_MODEL_ID,
)


BATCH_REPLAY_CONFIG_CONTRACT_VERSION: Final[int] = 1
BATCH_REPLAY_CONFIG_MANIFEST_KIND: Final[str] = (
    "vulngym.evaluator.batch-replay-config-manifest.v1"
)
BATCH_REPLAY_CONFIG_MANIFEST_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator batch replay config manifest v1\0"
)
BATCH_REPLAY_CONFIG_MANIFEST_FILENAME: Final[str] = "manifest.json"
BATCH_REPLAY_CONFIG_DIRECTORY: Final[str] = "configs"
BATCH_REPLAY_D2_FILENAME: Final[str] = "d2.json"
BATCH_REPLAY_D3_FILENAME: Final[str] = "d3.json"

MAX_BATCH_REPLAY_MANIFEST_BYTES: Final[int] = 512 * 1024
MAX_BATCH_REPLAY_WIRE_BYTES: Final[int] = 512 * 1024 * 1024
MAX_BATCH_REPLAY_TASKS: Final[int] = 50
MAX_MANIFEST_JSON_DEPTH: Final[int] = 8
MAX_MANIFEST_JSON_NODES: Final[int] = 1024

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_EXPECTED_COUNTS: Final[dict[str, int]] = {"train": 50, "test": 20}
_MANIFEST_KEYS: Final[frozenset[str]] = frozenset(
    {"contract_version", "kind", "manifest_sha256", "split", "tasks"}
)
_TASK_KEYS: Final[frozenset[str]] = frozenset(
    {
        "d2_replay_sha256",
        "d2_replay_wire_sha256",
        "d3_replay_sha256",
        "d3_replay_wire_sha256",
        "task_id",
    }
)


class BatchReplayConfigError(RuntimeError):
    """Stable, path-free rejection at the trusted replay input boundary."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _reject_constant(_value: str) -> None:
    raise BatchReplayConfigError(
        "noncanonical_json", "replay manifest contains a non-finite number"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BatchReplayConfigError(
                "noncanonical_json", "replay manifest repeats an object key"
            )
        result[key] = value
    return result


def _validate_json_shape(
    value: object, *, depth: int = 0, count: list[int]
) -> None:
    count[0] += 1
    if count[0] > MAX_MANIFEST_JSON_NODES or depth > MAX_MANIFEST_JSON_DEPTH:
        raise BatchReplayConfigError(
            "limit_exceeded", "replay manifest exceeds its structural limit"
        )
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise BatchReplayConfigError(
                "noncanonical_json", "replay manifest contains a non-finite number"
            )
        return
    if type(value) is list:
        for child in value:
            _validate_json_shape(child, depth=depth + 1, count=count)
        return
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise BatchReplayConfigError(
                    "noncanonical_json", "replay manifest has a non-string key"
                )
            _validate_json_shape(child, depth=depth + 1, count=count)
        return
    raise BatchReplayConfigError(
        "noncanonical_json", "replay manifest has an unsupported JSON value"
    )


def _parse_canonical_manifest(payload: bytes) -> dict[str, Any]:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > MAX_BATCH_REPLAY_MANIFEST_BYTES
    ):
        raise BatchReplayConfigError(
            "limit_exceeded", "replay manifest exceeds its byte limit"
        )
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise BatchReplayConfigError(
            "noncanonical_json", "replay manifest must be one canonical JSON line"
        )
    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except BatchReplayConfigError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise BatchReplayConfigError(
            "noncanonical_json", "replay manifest is not strict JSON"
        ) from None
    _validate_json_shape(value, count=[0])
    if type(value) is not dict or _canonical_json(value) + b"\n" != payload:
        raise BatchReplayConfigError(
            "noncanonical_json", "replay manifest is not canonical JSON"
        )
    return value


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise BatchReplayConfigError(
            "invalid_manifest", f"replay manifest {name} is invalid"
        )
    return value


@dataclass(frozen=True, slots=True)
class TaskReplayConfigBindingV1:
    """The four canonical replay pins for one exact task."""

    task_id: str
    d2_replay_sha256: str
    d2_replay_wire_sha256: str
    d3_replay_sha256: str
    d3_replay_wire_sha256: str

    def __post_init__(self) -> None:
        if type(self.task_id) is not str or _TASK_ID_RE.fullmatch(self.task_id) is None:
            raise BatchReplayConfigError(
                "invalid_manifest", "replay manifest task ID is invalid"
            )
        for value, name in (
            (self.d2_replay_sha256, "d2_replay_sha256"),
            (self.d2_replay_wire_sha256, "d2_replay_wire_sha256"),
            (self.d3_replay_sha256, "d3_replay_sha256"),
            (self.d3_replay_wire_sha256, "d3_replay_wire_sha256"),
        ):
            _require_sha256(value, name=name)

    @classmethod
    def from_configs(
        cls, d2: OciReplayConfigV1, d3: OciReplayConfigV1
    ) -> "TaskReplayConfigBindingV1":
        if type(d2) is not OciReplayConfigV1 or type(d3) is not OciReplayConfigV1:
            raise BatchReplayConfigError(
                "invalid_argument", "replay binding requires exact configuration types"
            )
        try:
            d2_wire = d2.to_bytes()
            d3_wire = d3.to_bytes()
            frozen_d2 = OciReplayConfigV1.from_bytes(d2_wire)
            frozen_d3 = OciReplayConfigV1.from_bytes(d3_wire)
        except (AttributeError, OciWorkerEntryError, TypeError, ValueError):
            raise BatchReplayConfigError(
                "invalid_argument", "replay configurations did not normalize"
            ) from None
        if (
            frozen_d2.task_id != frozen_d3.task_id
            or frozen_d2.role != "d2"
            or frozen_d3.role != "d3"
            or frozen_d2.backend_id != REPLAY_BACKEND_ID
            or frozen_d3.backend_id != REPLAY_BACKEND_ID
            or frozen_d2.model_id != REPLAY_MODEL_ID
            or frozen_d3.model_id != REPLAY_MODEL_ID
        ):
            raise BatchReplayConfigError(
                "binding_mismatch", "replay pair does not bind one fixed task"
            )
        return cls(
            task_id=frozen_d2.task_id,
            d2_replay_sha256=frozen_d2.config_sha256,
            d2_replay_wire_sha256=hashlib.sha256(d2_wire).hexdigest(),
            d3_replay_sha256=frozen_d3.config_sha256,
            d3_replay_wire_sha256=hashlib.sha256(d3_wire).hexdigest(),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "d2_replay_sha256": self.d2_replay_sha256,
            "d2_replay_wire_sha256": self.d2_replay_wire_sha256,
            "d3_replay_sha256": self.d3_replay_sha256,
            "d3_replay_wire_sha256": self.d3_replay_wire_sha256,
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class BatchReplayConfigManifestV1:
    """Canonical ordered manifest for one fixed 50- or 20-task split."""

    split: Literal["train", "test"]
    tasks: tuple[TaskReplayConfigBindingV1, ...]
    contract_version: int = BATCH_REPLAY_CONFIG_CONTRACT_VERSION
    kind: str = BATCH_REPLAY_CONFIG_MANIFEST_KIND
    manifest_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != BATCH_REPLAY_CONFIG_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != BATCH_REPLAY_CONFIG_MANIFEST_KIND
            or type(self.split) is not str
            or self.split not in _EXPECTED_COUNTS
            or type(self.tasks) is not tuple
            or len(self.tasks) != _EXPECTED_COUNTS.get(self.split, -1)
        ):
            raise BatchReplayConfigError(
                "invalid_manifest", "replay manifest header or task count is invalid"
            )
        frozen: list[TaskReplayConfigBindingV1] = []
        try:
            for item in self.tasks:
                if type(item) is not TaskReplayConfigBindingV1:
                    raise BatchReplayConfigError(
                        "invalid_manifest", "replay manifest task has an invalid exact type"
                    )
                frozen.append(
                    TaskReplayConfigBindingV1(
                        task_id=item.task_id,
                        d2_replay_sha256=item.d2_replay_sha256,
                        d2_replay_wire_sha256=item.d2_replay_wire_sha256,
                        d3_replay_sha256=item.d3_replay_sha256,
                        d3_replay_wire_sha256=item.d3_replay_wire_sha256,
                    )
                )
        except BatchReplayConfigError:
            raise
        except (AttributeError, TypeError, ValueError):
            raise BatchReplayConfigError(
                "invalid_manifest", "replay manifest task is malformed"
            ) from None
        task_ids = tuple(item.task_id for item in frozen)
        prefix = "VG-TRAIN-" if self.split == "train" else "VG-TEST-"
        if (
            len(set(task_ids)) != len(task_ids)
            or any(not task_id.startswith(prefix) for task_id in task_ids)
            or len({item.d2_replay_sha256 for item in frozen}) != len(frozen)
            or len({item.d2_replay_wire_sha256 for item in frozen}) != len(frozen)
            or len({item.d3_replay_sha256 for item in frozen}) != len(frozen)
            or len({item.d3_replay_wire_sha256 for item in frozen}) != len(frozen)
        ):
            raise BatchReplayConfigError(
                "invalid_manifest", "replay manifest repeats or misclassifies a task"
            )
        object.__setattr__(self, "tasks", tuple(frozen))
        object.__setattr__(
            self,
            "manifest_sha256",
            hashlib.sha256(
                BATCH_REPLAY_CONFIG_MANIFEST_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )
        if len(self.to_bytes()) > MAX_BATCH_REPLAY_MANIFEST_BYTES:
            raise BatchReplayConfigError(
                "limit_exceeded", "replay manifest exceeds its byte limit"
            )

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "kind": self.kind,
            "split": self.split,
            "tasks": [item.to_dict() for item in self.tasks],
        }

    def to_dict(self) -> dict[str, object]:
        core = self._core_dict()
        expected = hashlib.sha256(
            BATCH_REPLAY_CONFIG_MANIFEST_DIGEST_DOMAIN + _canonical_json(core)
        ).hexdigest()
        if type(self.manifest_sha256) is not str or self.manifest_sha256 != expected:
            raise BatchReplayConfigError(
                "manifest_digest_mismatch", "replay manifest digest changed"
            )
        return {**core, "manifest_sha256": self.manifest_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > MAX_BATCH_REPLAY_MANIFEST_BYTES:
            raise BatchReplayConfigError(
                "limit_exceeded", "replay manifest exceeds its byte limit"
            )
        return payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_manifest_sha256: str,
        expected_manifest_wire_sha256: str,
    ) -> "BatchReplayConfigManifestV1":
        for value, name in (
            (expected_manifest_sha256, "expected_manifest_sha256"),
            (expected_manifest_wire_sha256, "expected_manifest_wire_sha256"),
        ):
            if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
                raise BatchReplayConfigError(
                    "invalid_argument", f"{name} must be lower-case SHA-256"
                )
        if type(payload) is not bytes:
            raise BatchReplayConfigError(
                "invalid_argument", "replay manifest payload must be exact bytes"
            )
        if hashlib.sha256(payload).hexdigest() != expected_manifest_wire_sha256:
            raise BatchReplayConfigError(
                "manifest_wire_mismatch", "replay manifest wire does not match its pin"
            )
        value = _parse_canonical_manifest(payload)
        if frozenset(value) != _MANIFEST_KEYS:
            raise BatchReplayConfigError(
                "invalid_manifest", "replay manifest root contract is invalid"
            )
        raw_tasks = value["tasks"]
        if type(raw_tasks) is not list or len(raw_tasks) > MAX_BATCH_REPLAY_TASKS:
            raise BatchReplayConfigError(
                "invalid_manifest", "replay manifest task list is invalid"
            )
        tasks: list[TaskReplayConfigBindingV1] = []
        for raw in raw_tasks:
            if type(raw) is not dict or frozenset(raw) != _TASK_KEYS:
                raise BatchReplayConfigError(
                    "invalid_manifest", "replay manifest task contract is invalid"
                )
            tasks.append(
                TaskReplayConfigBindingV1(
                    task_id=raw["task_id"],
                    d2_replay_sha256=raw["d2_replay_sha256"],
                    d2_replay_wire_sha256=raw["d2_replay_wire_sha256"],
                    d3_replay_sha256=raw["d3_replay_sha256"],
                    d3_replay_wire_sha256=raw["d3_replay_wire_sha256"],
                )
            )
        supplied_manifest_sha256 = _require_sha256(
            value["manifest_sha256"], name="manifest_sha256"
        )
        if supplied_manifest_sha256 != expected_manifest_sha256:
            raise BatchReplayConfigError(
                "manifest_digest_mismatch", "replay manifest content does not match its pin"
            )
        result = cls(
            split=value["split"],
            tasks=tuple(tasks),
            contract_version=value["contract_version"],
            kind=value["kind"],
        )
        if (
            result.manifest_sha256 != supplied_manifest_sha256
            or result.to_bytes() != payload
        ):
            raise BatchReplayConfigError(
                "manifest_digest_mismatch", "replay manifest content digest is invalid"
            )
        return result


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
    """Compare a named file with its handle across platform stat APIs.

    Windows can expose slightly different creation-time rounding through
    ``lstat`` and ``fstat`` for the same file, so creation time remains in
    same-API change checks but is excluded from this cross-API identity.
    """

    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", 0),
    )


def _require_directory(
    path: Path, *, require_private: bool = True
) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError:
        raise BatchReplayConfigError(
            "input_unavailable", "replay input directory is unavailable"
        ) from None
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
        or (
            require_private
            and os.name == "posix"
            and value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        )
    ):
        raise BatchReplayConfigError(
            "unsafe_path", "replay input traverses an unsafe directory"
        )
    return value


def _canonical_input_root(
    root: object,
) -> tuple[Path, tuple[tuple[Path, tuple[int, int]], ...]]:
    if type(root) not in (str, type(Path())):
        raise BatchReplayConfigError(
            "invalid_argument", "replay input root must be an exact path value"
        )
    try:
        result = Path(os.path.abspath(os.fspath(root)))
    except (OSError, TypeError, ValueError):
        raise BatchReplayConfigError(
            "invalid_argument", "replay input root is invalid"
        ) from None
    chain: list[Path] = []
    current = result
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    parent_chain: list[tuple[Path, tuple[int, int]]] = []
    for item in reversed(chain):
        value = _require_directory(
            item, require_private=item == result
        )
        if item != result:
            parent_chain.append(
                (item, (value.st_dev, value.st_ino))
            )
    return result, tuple(parent_chain)


def _assert_input_parent_chain(
    chain: tuple[tuple[Path, tuple[int, int]], ...]
) -> None:
    for path, identity in chain:
        value = _require_directory(path, require_private=False)
        if (value.st_dev, value.st_ino) != identity:
            raise BatchReplayConfigError(
                "input_changed", "replay input parent chain changed"
            )


def _scan_exact_directory(
    path: Path, expected_names: frozenset[str]
) -> tuple[int, ...]:
    before = _require_directory(path)
    try:
        with os.scandir(path) as entries:
            names = frozenset(entry.name for entry in entries)
    except OSError:
        raise BatchReplayConfigError(
            "input_unavailable", "replay input directory could not be read"
        ) from None
    after = _require_directory(path)
    if _identity(before) != _identity(after):
        raise BatchReplayConfigError(
            "input_changed", "replay input directory changed while reading"
        )
    if names != expected_names:
        raise BatchReplayConfigError(
            "layout_invalid", "replay input directory membership is invalid"
        )
    return _identity(after)


@dataclass(slots=True)
class _OpenedRegular:
    path: Path
    descriptor: int
    identity: tuple[int, ...]
    named_identity: tuple[int, ...]
    payload: bytes


def _open_bounded_regular(path: Path, *, maximum_bytes: int) -> _OpenedRegular:
    try:
        before = os.lstat(path)
    except OSError:
        raise BatchReplayConfigError(
            "input_unavailable", "replay input file is unavailable"
        ) from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or (os.name == "posix" and before.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    ):
        raise BatchReplayConfigError(
            "unsafe_path", "replay input member is not a private regular file"
        )
    if before.st_size < 1 or before.st_size > maximum_bytes:
        raise BatchReplayConfigError(
            "limit_exceeded", "replay input file exceeds its byte limit"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise BatchReplayConfigError(
            "input_unavailable", "replay input file could not be opened"
        ) from None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink != 1
            or _binding_identity(opened) != _binding_identity(before)
        ):
            raise BatchReplayConfigError(
                "unsafe_path", "replay input file changed before it was opened"
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
                raise BatchReplayConfigError(
                    "limit_exceeded", "replay input file exceeds its byte limit"
                )
        finished = os.fstat(descriptor)
        if _identity(finished) != _identity(opened) or consumed != opened.st_size:
            raise BatchReplayConfigError(
                "input_changed", "replay input file changed while reading"
            )
        return _OpenedRegular(
            path=path,
            descriptor=descriptor,
            identity=_identity(opened),
            named_identity=_identity(before),
            payload=b"".join(chunks),
        )
    except BaseException:
        try:
            os.close(descriptor)
        except BaseException:
            pass
        raise


def _reverify_opened(value: _OpenedRegular) -> None:
    try:
        opened = os.fstat(value.descriptor)
        named = os.lstat(value.path)
    except OSError:
        raise BatchReplayConfigError(
            "input_changed", "replay input file changed after reading"
        ) from None
    if (
        _identity(opened) != value.identity
        or _identity(named) != value.named_identity
        or _binding_identity(named) != _binding_identity(opened)
        or stat.S_ISLNK(named.st_mode)
        or _is_reparse(named)
    ):
        raise BatchReplayConfigError(
            "input_changed", "replay input file changed after reading"
        )


def _validate_loader_arguments(
    *,
    expected_manifest_sha256: object,
    expected_manifest_wire_sha256: object,
    expected_split: object,
    expected_task_ids: object,
) -> tuple[str, tuple[str, ...]]:
    for value, name in (
        (expected_manifest_sha256, "expected_manifest_sha256"),
        (expected_manifest_wire_sha256, "expected_manifest_wire_sha256"),
    ):
        if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
            raise BatchReplayConfigError(
                "invalid_argument", f"{name} must be lower-case SHA-256"
            )
    if type(expected_split) is not str or expected_split not in _EXPECTED_COUNTS:
        raise BatchReplayConfigError(
            "invalid_argument", "expected split must be train or test"
        )
    if type(expected_task_ids) is not tuple:
        raise BatchReplayConfigError(
            "invalid_argument", "expected task IDs must be an exact tuple"
        )
    task_ids = expected_task_ids
    prefix = "VG-TRAIN-" if expected_split == "train" else "VG-TEST-"
    if (
        len(task_ids) != _EXPECTED_COUNTS[expected_split]
        or any(
            type(task_id) is not str
            or _TASK_ID_RE.fullmatch(task_id) is None
            or not task_id.startswith(prefix)
            for task_id in task_ids
        )
        or len(set(task_ids)) != len(task_ids)
    ):
        raise BatchReplayConfigError(
            "invalid_argument", "expected task IDs do not define the fixed split"
        )
    return expected_split, task_ids


def load_batch_replay_configs_v1(
    root: str | os.PathLike[str],
    *,
    expected_manifest_sha256: str,
    expected_manifest_wire_sha256: str,
    expected_split: Literal["train", "test"],
    expected_task_ids: tuple[str, ...],
) -> tuple[tuple[OciReplayConfigV1, OciReplayConfigV1], ...]:
    """Load and freeze one exact, ordered replay pair for every split task."""

    split, task_ids = _validate_loader_arguments(
        expected_manifest_sha256=expected_manifest_sha256,
        expected_manifest_wire_sha256=expected_manifest_wire_sha256,
        expected_split=expected_split,
        expected_task_ids=expected_task_ids,
    )
    input_root, parent_chain = _canonical_input_root(root)
    root_identity = _scan_exact_directory(
        input_root,
        frozenset(
            {BATCH_REPLAY_CONFIG_MANIFEST_FILENAME, BATCH_REPLAY_CONFIG_DIRECTORY}
        ),
    )
    opened_files: list[_OpenedRegular] = []
    directory_identities: dict[Path, tuple[int, ...]] = {input_root: root_identity}
    result: tuple[tuple[OciReplayConfigV1, OciReplayConfigV1], ...]
    close_failed = False
    primary: BaseException | None = None
    try:
        manifest_file = _open_bounded_regular(
            input_root / BATCH_REPLAY_CONFIG_MANIFEST_FILENAME,
            maximum_bytes=MAX_BATCH_REPLAY_MANIFEST_BYTES,
        )
        opened_files.append(manifest_file)
        manifest = BatchReplayConfigManifestV1.from_bytes(
            manifest_file.payload,
            expected_manifest_sha256=expected_manifest_sha256,
            expected_manifest_wire_sha256=expected_manifest_wire_sha256,
        )
        manifest_task_ids = tuple(item.task_id for item in manifest.tasks)
        if manifest.split != split or manifest_task_ids != task_ids:
            raise BatchReplayConfigError(
                "binding_mismatch", "replay manifest does not match requested split order"
            )

        configs_root = input_root / BATCH_REPLAY_CONFIG_DIRECTORY
        directory_identities[configs_root] = _scan_exact_directory(
            configs_root, frozenset(task_ids)
        )
        pairs: list[tuple[OciReplayConfigV1, OciReplayConfigV1]] = []
        total_wire_bytes = 0
        for task_id, binding in zip(task_ids, manifest.tasks, strict=True):
            task_root = configs_root / task_id
            directory_identities[task_root] = _scan_exact_directory(
                task_root,
                frozenset({BATCH_REPLAY_D2_FILENAME, BATCH_REPLAY_D3_FILENAME}),
            )
            d2_file = _open_bounded_regular(
                task_root / BATCH_REPLAY_D2_FILENAME,
                maximum_bytes=REPLAY_CONFIG_MAX_BYTES,
            )
            opened_files.append(d2_file)
            d3_file = _open_bounded_regular(
                task_root / BATCH_REPLAY_D3_FILENAME,
                maximum_bytes=REPLAY_CONFIG_MAX_BYTES,
            )
            opened_files.append(d3_file)
            total_wire_bytes += len(d2_file.payload) + len(d3_file.payload)
            if total_wire_bytes > MAX_BATCH_REPLAY_WIRE_BYTES:
                raise BatchReplayConfigError(
                    "limit_exceeded", "replay configurations exceed the batch byte limit"
                )
            if (
                hashlib.sha256(d2_file.payload).hexdigest()
                != binding.d2_replay_wire_sha256
                or hashlib.sha256(d3_file.payload).hexdigest()
                != binding.d3_replay_wire_sha256
            ):
                raise BatchReplayConfigError(
                    "config_wire_mismatch", "replay configuration wire does not match manifest"
                )
            try:
                d2 = OciReplayConfigV1.from_bytes(d2_file.payload)
                d3 = OciReplayConfigV1.from_bytes(d3_file.payload)
            except OciWorkerEntryError as error:
                raise BatchReplayConfigError(
                    "limit_exceeded"
                    if error.code == "limit_exceeded"
                    else "config_contract_mismatch",
                    "replay configuration is not a canonical fixed-backend contract",
                ) from None
            if (
                d2.config_sha256 != binding.d2_replay_sha256
                or d3.config_sha256 != binding.d3_replay_sha256
            ):
                raise BatchReplayConfigError(
                    "config_digest_mismatch",
                    "replay configuration content does not match manifest",
                )
            if (
                d2.task_id != task_id
                or d3.task_id != task_id
                or d2.role != "d2"
                or d3.role != "d3"
                or d2.backend_id != REPLAY_BACKEND_ID
                or d3.backend_id != REPLAY_BACKEND_ID
                or d2.model_id != REPLAY_MODEL_ID
                or d3.model_id != REPLAY_MODEL_ID
            ):
                raise BatchReplayConfigError(
                    "config_binding_mismatch",
                    "replay configuration does not bind task, role, backend, and model",
                )
            pairs.append((d2, d3))

        for opened in opened_files:
            _reverify_opened(opened)
        for directory, expected_identity in directory_identities.items():
            if directory == input_root:
                expected_names = frozenset(
                    {
                        BATCH_REPLAY_CONFIG_MANIFEST_FILENAME,
                        BATCH_REPLAY_CONFIG_DIRECTORY,
                    }
                )
            elif directory == configs_root:
                expected_names = frozenset(task_ids)
            else:
                expected_names = frozenset(
                    {BATCH_REPLAY_D2_FILENAME, BATCH_REPLAY_D3_FILENAME}
                )
            if _scan_exact_directory(directory, expected_names) != expected_identity:
                raise BatchReplayConfigError(
                    "input_changed", "replay input layout changed while loading"
                )
        for opened in opened_files:
            _reverify_opened(opened)
        _assert_input_parent_chain(parent_chain)
        result = tuple(pairs)
    except BaseException as error:
        primary = error
    finally:
        for opened in reversed(opened_files):
            try:
                os.close(opened.descriptor)
            except OSError:
                close_failed = True
    if close_failed:
        raise BatchReplayConfigError(
            "input_changed", "replay input handles did not close cleanly"
        ) from primary
    if primary is not None:
        raise primary
    return result


__all__ = [
    "BATCH_REPLAY_CONFIG_CONTRACT_VERSION",
    "BATCH_REPLAY_CONFIG_DIRECTORY",
    "BATCH_REPLAY_CONFIG_MANIFEST_DIGEST_DOMAIN",
    "BATCH_REPLAY_CONFIG_MANIFEST_FILENAME",
    "BATCH_REPLAY_CONFIG_MANIFEST_KIND",
    "BATCH_REPLAY_D2_FILENAME",
    "BATCH_REPLAY_D3_FILENAME",
    "BatchReplayConfigError",
    "BatchReplayConfigManifestV1",
    "MAX_BATCH_REPLAY_MANIFEST_BYTES",
    "MAX_BATCH_REPLAY_TASKS",
    "MAX_BATCH_REPLAY_WIRE_BYTES",
    "TaskReplayConfigBindingV1",
    "load_batch_replay_configs_v1",
]
