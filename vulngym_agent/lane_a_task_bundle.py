"""Prepare pinned public Lane A tasks for the existing T2 RunTask v2 API.

The public benchmark task file owns source identity.  A separately reviewed
assignment file contributes only correlation anchors, relative evidence-package
paths, and bounded search hints.  Neither input may override the other's trust
domain.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Any, Final
import uuid

from vulngym_agent.agents.t2_inputs import T2Hints, T2TaskInputV2
from vulngym_agent.benchmark.contracts import BenchmarkContractError, BenchmarkTask
from vulngym_agent.benchmark.snapshot_batch import (
    SnapshotBatchError,
    _canonical_existing_path,
    _canonical_new_child,
    _windows_extended_path,
)
from vulngym_agent.evidence import PackageSpec
from vulngym_agent.orchestrator.contracts import RunTask, canonical_json, canonical_sha256
from vulngym_agent.trusted_inputs import paths_overlap_v1


LANE_A_TASK_BUNDLE_CONTRACT_VERSION: Final[int] = 1
LANE_A_TASK_BUNDLE_KIND: Final[str] = "vulngym.lane-a-task-bundle.v1"
LANE_A_PUBLIC_TASKS_DOMAIN: Final[bytes] = b"VulnGym Lane A public tasks v1\0"
LANE_A_ASSIGNMENTS_DOMAIN: Final[bytes] = b"VulnGym Lane A assignments v1\0"
LANE_A_PUBLIC_TASK_DOMAIN: Final[bytes] = b"VulnGym Lane A public task v1\0"
LANE_A_ASSIGNMENT_DOMAIN: Final[bytes] = b"VulnGym Lane A assignment v1\0"
LANE_A_BUNDLE_DOMAIN: Final[bytes] = b"VulnGym Lane A task bundle v1\0"
LANE_A_RUN_TASKS_FILENAME: Final[str] = "run_tasks.jsonl"
LANE_A_MANIFEST_FILENAME: Final[str] = "manifest.json"
LANE_A_BUNDLE_FILES: Final[frozenset[str]] = frozenset(
    {LANE_A_RUN_TASKS_FILENAME, LANE_A_MANIFEST_FILENAME}
)

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_ABSOLUTE_DRIVE_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z]:[\\/]")
_ASSIGNMENT_KEYS: Final[frozenset[str]] = frozenset(
    {"task_id", "report_id", "entry_id", "package", "hints"}
)
_PACKAGE_KEYS: Final[frozenset[str]] = frozenset(
    {"advisory", "references", "patches"}
)
_HINT_KEYS: Final[frozenset[str]] = frozenset(
    {"project", "fix_commits", "source_paths", "entry_symbols", "critical_mode"}
)
_FORBIDDEN_SEGMENTS: Final[frozenset[str]] = frozenset(
    {"gold", "private", "selection_lock", "source-map", "source_map"}
)
_MAX_INPUT_BYTES: Final[int] = 64 * 1024 * 1024
_MAX_LINE_BYTES: Final[int] = 1024 * 1024
_MAX_TASKS: Final[int] = 100_000


class LaneATaskBundleError(RuntimeError):
    """Path-free failure at the Lane A task preparation boundary."""

    def __init__(self, code: str, message: str, *, committed: bool = False) -> None:
        self.code = code if type(code) is str and code else "operation_failed"
        self.committed = committed is True
        super().__init__(message)


def _require_sha256(value: object, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise LaneATaskBundleError("invalid_digest", f"{name} is not SHA-256")
    return value


def _canonical_bytes(value: object) -> bytes:
    try:
        return canonical_json(value).encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise LaneATaskBundleError(
            "noncanonical_json", "control data could not be canonicalized"
        ) from None


def _line(value: object) -> bytes:
    return _canonical_bytes(value) + b"\n"


class _DuplicateKey(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _validate_json(value: object, *, depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("JSON nesting is too deep")
    if value is None or type(value) in {bool, int, str}:
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("non-finite number")
        raise ValueError("floating-point values are forbidden")
    if type(value) is list:
        for item in value:
            _validate_json(item, depth=depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON key is not a string")
            _validate_json(item, depth=depth + 1)
        return
    raise ValueError("unsupported JSON value")


def _parse_line(payload: bytes, label: str) -> dict[str, object]:
    if (
        not payload.endswith(b"\n")
        or payload.count(b"\n") != 1
        or len(payload) > _MAX_LINE_BYTES
        or payload.endswith(b"\r\n")
    ):
        raise LaneATaskBundleError("invalid_json", f"{label} framing is invalid")
    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _item: (_ for _ in ()).throw(ValueError()),
        )
        _validate_json(value)
    except (
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateKey,
        RecursionError,
        TypeError,
        ValueError,
    ):
        raise LaneATaskBundleError("invalid_json", f"{label} is invalid JSON") from None
    if type(value) is not dict or _line(value) != payload:
        raise LaneATaskBundleError(
            "noncanonical_json", f"{label} is not canonical JSON"
        )
    return value


def _is_reparse(value: os.stat_result) -> bool:
    return bool(
        getattr(value, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _directory_identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", 0),
    )


def _root_chain(path: Path) -> tuple[Path, ...]:
    result: list[Path] = []
    current = Path(os.path.abspath(os.fspath(path)))
    while True:
        result.append(current)
        if current.parent == current:
            break
        current = current.parent
    result.reverse()
    return tuple(result)


def _require_directory(path: Path, *, private: bool = False) -> os.stat_result:
    try:
        value = os.lstat(_windows_extended_path(path))
    except OSError:
        raise LaneATaskBundleError("directory_unavailable", "directory is unavailable") from None
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
        or (private and os.name == "posix" and value.st_mode & 0o022)
    ):
        raise LaneATaskBundleError("unsafe_path", "directory is unsafe")
    return value


def _guard_chain(path: Path, *, final_private: bool = False) -> tuple[tuple[Path, tuple[int, int]], ...]:
    chain = _root_chain(path)
    return tuple(
        (
            item,
            _directory_identity(
                _require_directory(
                    item, private=final_private and index == len(chain) - 1
                )
            ),
        )
        for index, item in enumerate(chain)
    )


def _assert_chain(
    guard: tuple[tuple[Path, tuple[int, int]], ...], *, final_private: bool = False
) -> None:
    for index, (path, expected) in enumerate(guard):
        current = _require_directory(
            path, private=final_private and index == len(guard) - 1
        )
        if _directory_identity(current) != expected:
            raise LaneATaskBundleError("input_changed", "directory chain changed")


def _read_regular(path: str | os.PathLike[str], *, maximum: int) -> tuple[Path, bytes]:
    try:
        canonical = _canonical_existing_path(path, directory=False, status=2)
    except SnapshotBatchError as error:
        raise LaneATaskBundleError("unsafe_path", "input path is unavailable") from error
    guard = _guard_chain(canonical.parent)
    try:
        before = os.lstat(_windows_extended_path(canonical))
    except OSError:
        raise LaneATaskBundleError("input_unavailable", "input file is unavailable") from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > maximum
        or (os.name == "posix" and before.st_mode & 0o022)
    ):
        raise LaneATaskBundleError("unsafe_path", "input file is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(_windows_extended_path(canonical), flags)
    except OSError:
        raise LaneATaskBundleError("input_unavailable", "input file could not be opened") from None
    try:
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(before):
            raise LaneATaskBundleError("input_changed", "input changed during open")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - consumed))
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > maximum:
                raise LaneATaskBundleError("input_limit", "input exceeds byte limit")
        finished = os.fstat(descriptor)
        if _file_identity(finished) != _file_identity(opened) or consumed != opened.st_size:
            raise LaneATaskBundleError("input_changed", "input changed while reading")
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(_windows_extended_path(canonical))
    except OSError:
        raise LaneATaskBundleError("input_changed", "input changed after reading") from None
    _assert_chain(guard)
    if _file_identity(after) != _file_identity(before):
        raise LaneATaskBundleError("input_changed", "input changed after reading")
    return canonical, b"".join(chunks)


def _read_regular_at(root_descriptor: int, name: str, *, maximum: int) -> bytes:
    try:
        before = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
                or _is_reparse(before) or before.st_nlink != 1
                or before.st_size < 1 or before.st_size > maximum):
            raise LaneATaskBundleError("unsafe_path", "bundle file is unsafe")
        descriptor = os.open(name, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                             | getattr(os, "O_NOFOLLOW", 0), dir_fd=root_descriptor)
        try:
            opened = os.fstat(descriptor)
            if _file_identity(opened) != _file_identity(before):
                raise LaneATaskBundleError("input_changed", "bundle file changed during open")
            payload = bytearray()
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(payload)))
                if not chunk: break
                payload.extend(chunk)
                if len(payload) > maximum:
                    raise LaneATaskBundleError("input_limit", "bundle file exceeds byte limit")
            if _file_identity(os.fstat(descriptor)) != _file_identity(opened):
                raise LaneATaskBundleError("input_changed", "bundle file changed while reading")
        finally:
            os.close(descriptor)
        after = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
        if _file_identity(after) != _file_identity(before):
            raise LaneATaskBundleError("input_changed", "bundle file changed after reading")
        return bytes(payload)
    except LaneATaskBundleError:
        raise
    except OSError:
        raise LaneATaskBundleError("input_unavailable", "bundle file is unavailable") from None


def _semantic(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + _canonical_bytes(value)).hexdigest()


def _public_task_core(task: BenchmarkTask) -> dict[str, object]:
    return task.to_dict()


@dataclass(frozen=True, slots=True)
class LaneAAssignmentV1:
    task_id: str
    report_id: str
    entry_id: str
    package: PackageSpec
    hints: T2Hints

    @classmethod
    def from_dict(cls, value: object) -> "LaneAAssignmentV1":
        if type(value) is not dict or frozenset(value) != _ASSIGNMENT_KEYS:
            raise LaneATaskBundleError(
                "assignment_fields", "assignment fields are not allowed"
            )
        package_value = value["package"]
        hints_value = value["hints"]
        if (
            type(package_value) is not dict
            or frozenset(package_value) != _PACKAGE_KEYS
            or type(hints_value) is not dict
            or frozenset(hints_value) != _HINT_KEYS
        ):
            raise LaneATaskBundleError(
                "assignment_fields", "assignment package or hints fields differ"
            )
        try:
            package = PackageSpec(
                advisory=package_value["advisory"],
                references=package_value["references"],
                patches=package_value["patches"],
            )
            hints = T2Hints.from_dict(hints_value)
            # Reuse the exact public RunTask anchor validators.
            RunTask(
                task_id=value["task_id"],
                report_id=value["report_id"],
                entry_id=value["entry_id"],
            )
        except (TypeError, ValueError):
            raise LaneATaskBundleError(
                "assignment_invalid", "assignment values are invalid"
            ) from None
        result = cls(
            task_id=value["task_id"],
            report_id=value["report_id"],
            entry_id=value["entry_id"],
            package=package,
            hints=hints,
        )
        _reject_sensitive_strings(result.to_dict())
        return result

    def to_dict(self) -> dict[str, object]:
        return {
            "entry_id": self.entry_id,
            "hints": self.hints.to_dict(),
            "package": self.package.to_dict(),
            "report_id": self.report_id,
            "task_id": self.task_id,
        }


def _reject_sensitive_strings(value: object) -> None:
    if isinstance(value, Mapping):
        for item in value.values():
            _reject_sensitive_strings(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _reject_sensitive_strings(item)
        return
    if type(value) is not str:
        return
    folded = value.casefold()
    segments = {
        item for item in re.split(r"[\\/]", folded) if item not in {"", "."}
    }
    if (
        value.startswith(("/", "\\", "file:"))
        or _ABSOLUTE_DRIVE_RE.match(value) is not None
        or segments & _FORBIDDEN_SEGMENTS
    ):
        raise LaneATaskBundleError(
            "sensitive_value", "assignment contains a private or absolute path"
        )


@dataclass(frozen=True, slots=True)
class _Inputs:
    public_path: Path
    assignment_path: Path
    public_wire: bytes
    assignment_wire: bytes
    tasks: tuple[BenchmarkTask, ...]
    assignments: tuple[LaneAAssignmentV1, ...]
    public_semantic_sha256: str
    assignment_semantic_sha256: str


def _parse_jsonl(payload: bytes, label: str) -> tuple[dict[str, object], ...]:
    if not payload.endswith(b"\n") or payload.endswith(b"\r\n"):
        raise LaneATaskBundleError("invalid_json", f"{label} framing is invalid")
    lines = payload.splitlines(keepends=True)
    if not 1 <= len(lines) <= _MAX_TASKS:
        raise LaneATaskBundleError("invalid_count", f"{label} count is invalid")
    return tuple(_parse_line(item, label) for item in lines)


def _load_inputs(
    public_tasks_file: str | os.PathLike[str],
    assignments_file: str | os.PathLike[str],
    *,
    expected_public_tasks_sha256: str,
    expected_public_tasks_wire_sha256: str,
    expected_assignments_sha256: str,
    expected_assignments_wire_sha256: str,
    expected_task_count: int,
) -> _Inputs:
    if (
        isinstance(expected_task_count, bool)
        or not isinstance(expected_task_count, int)
        or not 1 <= expected_task_count <= _MAX_TASKS
    ):
        raise LaneATaskBundleError("invalid_count", "expected task count is invalid")
    expected_public = _require_sha256(
        expected_public_tasks_sha256, "expected_public_tasks_sha256"
    )
    expected_public_wire = _require_sha256(
        expected_public_tasks_wire_sha256, "expected_public_tasks_wire_sha256"
    )
    expected_assignments = _require_sha256(
        expected_assignments_sha256, "expected_assignments_sha256"
    )
    expected_assignment_wire = _require_sha256(
        expected_assignments_wire_sha256, "expected_assignments_wire_sha256"
    )
    public_path, public_wire = _read_regular(public_tasks_file, maximum=_MAX_INPUT_BYTES)
    assignment_path, assignment_wire = _read_regular(
        assignments_file, maximum=_MAX_INPUT_BYTES
    )
    if public_path == assignment_path:
        raise LaneATaskBundleError("path_overlap", "the two inputs overlap")
    if hashlib.sha256(public_wire).hexdigest() != expected_public_wire:
        raise LaneATaskBundleError("public_wire_mismatch", "public task wire pin differs")
    if hashlib.sha256(assignment_wire).hexdigest() != expected_assignment_wire:
        raise LaneATaskBundleError(
            "assignment_wire_mismatch", "assignment wire pin differs"
        )
    public_values = _parse_jsonl(public_wire, "public task")
    assignment_values = _parse_jsonl(assignment_wire, "assignment")
    if len(public_values) != expected_task_count or len(assignment_values) != expected_task_count:
        raise LaneATaskBundleError("count_mismatch", "input task count differs from the external count")
    tasks: list[BenchmarkTask] = []
    for value in public_values:
        try:
            tasks.append(BenchmarkTask.from_dict(value))
        except (BenchmarkContractError, TypeError, ValueError):
            raise LaneATaskBundleError(
                "public_task_invalid", "public task contract is invalid"
            ) from None
    assignments = tuple(LaneAAssignmentV1.from_dict(value) for value in assignment_values)
    if len(tasks) != len(assignments):
        raise LaneATaskBundleError("count_mismatch", "input row counts differ")
    if len({task.task_id for task in tasks}) != len(tasks) or len(
        {(task.repo_url.casefold(), task.commit) for task in tasks}
    ) != len(tasks):
        raise LaneATaskBundleError("public_task_duplicate", "public tasks repeat")
    if len({item.task_id for item in assignments}) != len(assignments):
        raise LaneATaskBundleError("assignment_duplicate", "assignment tasks repeat")
    if len({item.report_id for item in assignments}) != len(assignments) or len(
        {item.entry_id for item in assignments}
    ) != len(assignments):
        raise LaneATaskBundleError("assignment_duplicate", "assignment anchors repeat")
    for task, assignment in zip(tasks, assignments, strict=True):
        if assignment.task_id != task.task_id:
            raise LaneATaskBundleError(
                "assignment_order_mismatch", "assignment task order differs"
            )
    splits = {task.split for task in tasks}
    if len(splits) != 1:
        raise LaneATaskBundleError("split_mismatch", "public task file mixes splits")
    public_core = [_public_task_core(task) for task in tasks]
    assignment_core = [item.to_dict() for item in assignments]
    public_semantic = _semantic(LANE_A_PUBLIC_TASKS_DOMAIN, public_core)
    assignment_semantic = _semantic(LANE_A_ASSIGNMENTS_DOMAIN, assignment_core)
    if public_semantic != expected_public:
        raise LaneATaskBundleError(
            "public_semantic_mismatch", "public task semantic pin differs"
        )
    if assignment_semantic != expected_assignments:
        raise LaneATaskBundleError(
            "assignment_semantic_mismatch", "assignment semantic pin differs"
        )
    return _Inputs(
        public_path=public_path,
        assignment_path=assignment_path,
        public_wire=public_wire,
        assignment_wire=assignment_wire,
        tasks=tuple(tasks),
        assignments=assignments,
        public_semantic_sha256=public_semantic,
        assignment_semantic_sha256=assignment_semantic,
    )


@dataclass(frozen=True, slots=True)
class LaneATaskBundleManifestV1:
    split: str
    task_count: int
    public_tasks_sha256: str
    public_tasks_wire_sha256: str
    assignments_sha256: str
    assignments_wire_sha256: str
    run_tasks_wire_sha256: str
    run_tasks_byte_count: int
    tasks: tuple[Mapping[str, object], ...]
    bundle_sha256: str

    def core_dict(self) -> dict[str, object]:
        return {
            "assignments_sha256": self.assignments_sha256,
            "assignments_wire_sha256": self.assignments_wire_sha256,
            "contract_version": LANE_A_TASK_BUNDLE_CONTRACT_VERSION,
            "kind": LANE_A_TASK_BUNDLE_KIND,
            "public_tasks_sha256": self.public_tasks_sha256,
            "public_tasks_wire_sha256": self.public_tasks_wire_sha256,
            "run_tasks": {
                "byte_count": self.run_tasks_byte_count,
                "content_sha256": self.run_tasks_wire_sha256,
                "line_count": self.task_count,
            },
            "split": self.split,
            "task_count": self.task_count,
            "tasks": [dict(item) for item in self.tasks],
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.core_dict(), "bundle_sha256": self.bundle_sha256}

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(_line(self.to_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class LaneATaskBundleV1:
    manifest: LaneATaskBundleManifestV1
    run_tasks: tuple[RunTask, ...]


def _build_payloads(inputs: _Inputs) -> tuple[dict[str, bytes], LaneATaskBundleV1]:
    run_tasks: list[RunTask] = []
    task_bindings: list[dict[str, object]] = []
    lines: list[bytes] = []
    for ordinal, (task, assignment) in enumerate(
        zip(inputs.tasks, inputs.assignments, strict=True), 1
    ):
        task_input = T2TaskInputV2(
            input_line=ordinal,
            repo_url=task.repo_url,
            expected_vulnerable_commit=task.commit,
            package=assignment.package,
            hints=assignment.hints,
        )
        run_task = RunTask(
            task_id=task.task_id,
            report_id=assignment.report_id,
            entry_id=assignment.entry_id,
            inputs=task_input.to_dict(),
        )
        # Parse through the production contract, not merely the dataclass used above.
        parsed = RunTask.from_dict(run_task.to_dict())
        reparsed_input = T2TaskInputV2.from_task(parsed)
        if reparsed_input.expected_vulnerable_commit != task.commit:
            raise LaneATaskBundleError(
                "commit_binding_mismatch", "RunTask vulnerable commit differs"
            )
        wire = _line(parsed.to_dict())
        lines.append(wire)
        run_tasks.append(parsed)
        public_task_sha256 = _semantic(
            LANE_A_PUBLIC_TASK_DOMAIN, _public_task_core(task)
        )
        assignment_sha256 = _semantic(
            LANE_A_ASSIGNMENT_DOMAIN, assignment.to_dict()
        )
        task_bindings.append(
            {
                "assignment_sha256": assignment_sha256,
                "ordinal": ordinal,
                "public_task_sha256": public_task_sha256,
                "run_task_sha256": canonical_sha256(parsed.to_dict()),
                "task_id": task.task_id,
            }
        )
    run_wire = b"".join(lines)
    core = {
        "assignments_sha256": inputs.assignment_semantic_sha256,
        "assignments_wire_sha256": hashlib.sha256(inputs.assignment_wire).hexdigest(),
        "contract_version": LANE_A_TASK_BUNDLE_CONTRACT_VERSION,
        "kind": LANE_A_TASK_BUNDLE_KIND,
        "public_tasks_sha256": inputs.public_semantic_sha256,
        "public_tasks_wire_sha256": hashlib.sha256(inputs.public_wire).hexdigest(),
        "run_tasks": {
            "byte_count": len(run_wire),
            "content_sha256": hashlib.sha256(run_wire).hexdigest(),
            "line_count": len(run_tasks),
        },
        "split": inputs.tasks[0].split,
        "task_count": len(run_tasks),
        "tasks": task_bindings,
    }
    bundle_sha256 = _semantic(LANE_A_BUNDLE_DOMAIN, core)
    manifest = LaneATaskBundleManifestV1(
        split=inputs.tasks[0].split,
        task_count=len(run_tasks),
        public_tasks_sha256=inputs.public_semantic_sha256,
        public_tasks_wire_sha256=hashlib.sha256(inputs.public_wire).hexdigest(),
        assignments_sha256=inputs.assignment_semantic_sha256,
        assignments_wire_sha256=hashlib.sha256(inputs.assignment_wire).hexdigest(),
        run_tasks_wire_sha256=hashlib.sha256(run_wire).hexdigest(),
        run_tasks_byte_count=len(run_wire),
        tasks=tuple(MappingProxyType(item) for item in task_bindings),
        bundle_sha256=bundle_sha256,
    )
    payloads = {
        LANE_A_RUN_TASKS_FILENAME: run_wire,
        LANE_A_MANIFEST_FILENAME: _line(manifest.to_dict()),
    }
    _reject_forbidden_payload(payloads)
    return payloads, LaneATaskBundleV1(manifest=manifest, run_tasks=tuple(run_tasks))


def _reject_forbidden_payload(payloads: Mapping[str, bytes]) -> None:
    combined = b"".join(payloads.values()).lower()
    for marker in (b"source_map", b"source-map", b"selection_lock"):
        if marker in combined:
            raise LaneATaskBundleError(
                "private_marker", "bundle contains a private control marker"
            )


def _read_bundle_payloads(root: Path) -> tuple[dict[str, bytes], tuple[int, int]]:
    state = _require_directory(root, private=True)
    identity = _directory_identity(state)
    descriptor: int | None = None
    try:
        if os.name == "posix":
            descriptor = _open_bound_directory(root, identity)
            names = frozenset(item.name for item in os.scandir(descriptor))
        else:
            names = frozenset(item.name for item in os.scandir(_windows_extended_path(root)))
    except OSError:
        raise LaneATaskBundleError("directory_unavailable", "bundle cannot be scanned") from None
    if names != LANE_A_BUNDLE_FILES:
        if descriptor is not None: os.close(descriptor)
        raise LaneATaskBundleError("layout_mismatch", "bundle file set differs")
    try:
        payloads = {
            name: (_read_regular_at(descriptor, name, maximum=_MAX_INPUT_BYTES)
                   if descriptor is not None else
                   _read_regular(root / name, maximum=_MAX_INPUT_BYTES)[1])
            for name in sorted(LANE_A_BUNDLE_FILES)
        }
        names_after = frozenset(item.name for item in
            os.scandir(descriptor if descriptor is not None else _windows_extended_path(root)))
    finally:
        if descriptor is not None: os.close(descriptor)
    try:
        current_identity = _directory_identity(_require_directory(root, private=True))
    except OSError:
        raise LaneATaskBundleError("input_changed", "bundle changed during read") from None
    if (
        names_after != names
        or current_identity != identity
    ):
        raise LaneATaskBundleError("input_changed", "bundle changed during read")
    return payloads, identity


def _parse_bundle(
    payloads: Mapping[str, bytes],
    *,
    expected_bundle_sha256: str,
    expected_manifest_wire_sha256: str,
) -> LaneATaskBundleV1:
    expected_bundle = _require_sha256(expected_bundle_sha256, "expected_bundle_sha256")
    expected_wire = _require_sha256(
        expected_manifest_wire_sha256, "expected_manifest_wire_sha256"
    )
    manifest_wire = payloads[LANE_A_MANIFEST_FILENAME]
    if hashlib.sha256(manifest_wire).hexdigest() != expected_wire:
        raise LaneATaskBundleError("manifest_wire_mismatch", "manifest wire pin differs")
    raw = _parse_line(manifest_wire, "bundle manifest")
    keys = {
        "assignments_sha256",
        "assignments_wire_sha256",
        "bundle_sha256",
        "contract_version",
        "kind",
        "public_tasks_sha256",
        "public_tasks_wire_sha256",
        "run_tasks",
        "split",
        "task_count",
        "tasks",
    }
    if set(raw) != keys:
        raise LaneATaskBundleError("manifest_invalid", "manifest fields differ")
    count = raw["task_count"]
    task_bindings = raw["tasks"]
    run_summary = raw["run_tasks"]
    if (
        raw["contract_version"] != LANE_A_TASK_BUNDLE_CONTRACT_VERSION
        or raw["kind"] != LANE_A_TASK_BUNDLE_KIND
        or raw["split"] not in {"train", "test"}
        or type(count) is not int
        or not 1 <= count <= _MAX_TASKS
        or type(task_bindings) is not list
        or len(task_bindings) != count
        or type(run_summary) is not dict
        or set(run_summary) != {"byte_count", "content_sha256", "line_count"}
    ):
        raise LaneATaskBundleError("manifest_invalid", "manifest header is invalid")
    for name in (
        "assignments_sha256",
        "assignments_wire_sha256",
        "public_tasks_sha256",
        "public_tasks_wire_sha256",
        "bundle_sha256",
    ):
        _require_sha256(raw[name], name)
    run_wire = payloads[LANE_A_RUN_TASKS_FILENAME]
    if run_summary != {
        "byte_count": len(run_wire),
        "content_sha256": hashlib.sha256(run_wire).hexdigest(),
        "line_count": count,
    }:
        raise LaneATaskBundleError("run_tasks_mismatch", "RunTask file summary differs")
    run_values = _parse_jsonl(run_wire, "RunTask")
    if len(run_values) != count:
        raise LaneATaskBundleError("count_mismatch", "RunTask count differs")
    run_tasks: list[RunTask] = []
    seen_task_ids: set[str] = set()
    expected_binding_keys = {
        "assignment_sha256",
        "ordinal",
        "public_task_sha256",
        "run_task_sha256",
        "task_id",
    }
    for ordinal, (value, binding) in enumerate(zip(run_values, task_bindings, strict=True), 1):
        if type(binding) is not dict or set(binding) != expected_binding_keys:
            raise LaneATaskBundleError("manifest_invalid", "task binding fields differ")
        for name in ("assignment_sha256", "public_task_sha256", "run_task_sha256"):
            _require_sha256(binding[name], name)
        try:
            task = RunTask.from_dict(value)
            task_input = T2TaskInputV2.from_task(task)
        except (TypeError, ValueError):
            raise LaneATaskBundleError("run_task_invalid", "RunTask v2 is invalid") from None
        if (
            binding["ordinal"] != ordinal
            or binding["task_id"] != task.task_id
            or binding["run_task_sha256"] != canonical_sha256(task.to_dict())
            or task_input.input_line != ordinal
            or task.task_id in seen_task_ids
        ):
            raise LaneATaskBundleError("task_binding_mismatch", "RunTask binding differs")
        seen_task_ids.add(task.task_id)
        run_tasks.append(task)
    core = {key: raw[key] for key in keys - {"bundle_sha256"}}
    actual_bundle = _semantic(LANE_A_BUNDLE_DOMAIN, core)
    if raw["bundle_sha256"] != actual_bundle or actual_bundle != expected_bundle:
        raise LaneATaskBundleError("bundle_pin_mismatch", "bundle semantic pin differs")
    manifest = LaneATaskBundleManifestV1(
        split=raw["split"],
        task_count=count,
        public_tasks_sha256=raw["public_tasks_sha256"],
        public_tasks_wire_sha256=raw["public_tasks_wire_sha256"],
        assignments_sha256=raw["assignments_sha256"],
        assignments_wire_sha256=raw["assignments_wire_sha256"],
        run_tasks_wire_sha256=run_summary["content_sha256"],
        run_tasks_byte_count=run_summary["byte_count"],
        tasks=tuple(MappingProxyType(dict(item)) for item in task_bindings),
        bundle_sha256=actual_bundle,
    )
    if _line(manifest.to_dict()) != manifest_wire:
        raise LaneATaskBundleError("manifest_invalid", "manifest did not round trip")
    _reject_forbidden_payload(payloads)
    return LaneATaskBundleV1(manifest=manifest, run_tasks=tuple(run_tasks))


def read_lane_a_task_bundle(
    bundle_dir: str | os.PathLike[str],
    *,
    expected_bundle_sha256: str,
    expected_manifest_wire_sha256: str,
) -> LaneATaskBundleV1:
    try:
        root = _canonical_existing_path(bundle_dir, directory=True, status=2)
    except SnapshotBatchError as error:
        raise LaneATaskBundleError("unsafe_path", "bundle path is unavailable") from error
    guard = _guard_chain(root.parent)
    payloads, identity = _read_bundle_payloads(root)
    result = _parse_bundle(
        payloads,
        expected_bundle_sha256=expected_bundle_sha256,
        expected_manifest_wire_sha256=expected_manifest_wire_sha256,
    )
    second, second_identity = _read_bundle_payloads(root)
    _assert_chain(guard)
    if second != payloads or second_identity != identity:
        raise LaneATaskBundleError("input_changed", "bundle changed during readback")
    return result


def _rename_noreplace(source: Path, destination: Path, *,
                      source_dir_fd: int | None = None,
                      destination_dir_fd: int | None = None) -> None:
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
        result = renameat2(-100 if source_dir_fd is None else source_dir_fd,
                           os.fsencode(source),
                           -100 if destination_dir_fd is None else destination_dir_fd,
                           os.fsencode(destination), 1)
        if result == 0:
            return
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise FileExistsError(str(destination))
        raise OSError(number, "atomic no-replace rename failed")
    if source_dir_fd is not None or destination_dir_fd is not None:
        raise OSError(errno.ENOTSUP, "relative directory rename unavailable")
    try:
        os.lstat(_windows_extended_path(destination))
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(str(destination))
    os.rename(_windows_extended_path(source), _windows_extended_path(destination))


def _named_directory_identity(path: Path) -> tuple[int, int] | None:
    try:
        value = os.lstat(_windows_extended_path(path))
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or _is_reparse(value):
        return None
    return _directory_identity(value)


def _directory_flags() -> int:
    return (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
            getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))


def _open_bound_directory(path: Path | str, expected: tuple[int, int], *, dir_fd: int | None = None) -> int:
    try:
        descriptor = os.open(path, _directory_flags(), dir_fd=dir_fd)
    except OSError:
        raise LaneATaskBundleError("directory_unavailable", "directory could not be opened") from None
    try:
        value = os.fstat(descriptor)
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode)
                or _is_reparse(value) or _directory_identity(value) != expected):
            raise LaneATaskBundleError("input_changed", "directory changed during open")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_windows_directory_lock(path: Path) -> int:
    """Hold a directory handle without FILE_SHARE_DELETE, preventing name swaps."""
    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    create_file.restype = ctypes.c_void_p
    handle = create_file(str(_windows_extended_path(path)), 0x0001, 0x1 | 0x2, None, 3, 0x02000000, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise LaneATaskBundleError("directory_unavailable", "directory could not be locked")
    return int(handle)


def _close_windows_handle(handle: int) -> None:
    close_handle = ctypes.windll.kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    if not close_handle(ctypes.c_void_p(handle)):
        raise OSError("directory handle close failed")


def _close_publication_descriptor(descriptor: int) -> None:
    os.close(descriptor)


def _write_file(path: Path | str, payload: bytes, *, dir_fd: int | None = None) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    target = path if dir_fd is not None else _windows_extended_path(Path(path))
    descriptor = os.open(target, flags | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dir_fd)
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
        identity = _file_identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)
    named = (os.stat(path, dir_fd=dir_fd, follow_symlinks=False) if dir_fd is not None
             else os.lstat(_windows_extended_path(Path(path))))
    if _file_identity(named) != identity or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
        raise LaneATaskBundleError("publication_changed", "created file identity changed")


def _identity_at(parent_fd: int, name: str) -> tuple[int, int] | None:
    try:
        value = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or _is_reparse(value):
        return None
    return _directory_identity(value)


def _publish(
    output_dir: str | os.PathLike[str],
    payloads: Mapping[str, bytes],
    expected: LaneATaskBundleV1,
    *,
    expected_output: Path,
    expected_parent_guard: tuple[tuple[Path, tuple[int, int]], ...],
) -> LaneATaskBundleManifestV1:
    try:
        output = _canonical_new_child(output_dir, status=2)
    except SnapshotBatchError as error:
        raise LaneATaskBundleError("invalid_output", "output path is invalid") from error
    if output != expected_output:
        raise LaneATaskBundleError("input_changed", "output identity changed before publication")
    _assert_chain(expected_parent_guard, final_private=True)
    parent_guard = expected_parent_guard
    try:
        os.lstat(_windows_extended_path(output))
    except FileNotFoundError:
        pass
    except OSError:
        raise LaneATaskBundleError("output_unavailable", "output state is unavailable") from None
    else:
        raise LaneATaskBundleError("output_exists", "output already exists")
    staging = output.parent / f".{output.name}.lane-a-{uuid.uuid4().hex}"
    parent_descriptor: int | None = None
    staging_descriptor: int | None = None
    output_descriptor: int | None = None
    windows_parent_handle: int | None = None
    staging_identity: tuple[int, int] | None = None
    committed = False
    try:
        if os.name == "posix":
            parent_descriptor = _open_bound_directory(output.parent, parent_guard[-1][1])
            if _identity_at(parent_descriptor, output.name) is not None:
                raise LaneATaskBundleError("output_exists", "output already exists")
            os.mkdir(staging.name, 0o700, dir_fd=parent_descriptor)
            created = os.stat(staging.name, dir_fd=parent_descriptor, follow_symlinks=False)
            staging_identity = _directory_identity(created)
            staging_descriptor = _open_bound_directory(staging.name, staging_identity, dir_fd=parent_descriptor)
            for name in sorted(LANE_A_BUNDLE_FILES):
                _write_file(name, payloads[name], dir_fd=staging_descriptor)
            os.fsync(staging_descriptor)
            before_payloads = {
                name: _read_regular_at(staging_descriptor, name, maximum=_MAX_INPUT_BYTES)
                for name in sorted(LANE_A_BUNDLE_FILES)
            }
        else:
            windows_parent_handle = _open_windows_directory_lock(output.parent)
            _assert_chain(parent_guard, final_private=True)
            os.mkdir(_windows_extended_path(staging), 0o700)
            staging_identity = _directory_identity(_require_directory(staging, private=True))
            for name in sorted(LANE_A_BUNDLE_FILES):
                _write_file(staging / name, payloads[name])
            before_payloads, before_identity = _read_bundle_payloads(staging)
            if before_identity != staging_identity:
                raise LaneATaskBundleError("publication_changed", "staging identity changed")
        if before_payloads != dict(payloads):
            raise LaneATaskBundleError("publication_failed", "staging readback differs")
        before = _parse_bundle(before_payloads,
            expected_bundle_sha256=expected.manifest.bundle_sha256,
            expected_manifest_wire_sha256=expected.manifest.wire_sha256)
        if before != expected:
            raise LaneATaskBundleError("publication_failed", "staging contract differs")
        _assert_chain(parent_guard, final_private=True)
        observed = (_identity_at(parent_descriptor, staging.name) if parent_descriptor is not None
                    else _directory_identity(_require_directory(staging, private=True)))
        if observed != staging_identity:
            raise LaneATaskBundleError("publication_changed", "staging identity changed")
        try:
            if parent_descriptor is not None:
                _rename_noreplace(Path(staging.name), Path(output.name),
                                  source_dir_fd=parent_descriptor,
                                  destination_dir_fd=parent_descriptor)
            else:
                _rename_noreplace(staging, output)
            committed = True
        except BaseException as error:
            try:
                if parent_descriptor is not None:
                    staging_after = _identity_at(parent_descriptor, staging.name)
                    output_after = _identity_at(parent_descriptor, output.name)
                else:
                    staging_after = _named_directory_identity(staging)
                    output_after = _named_directory_identity(output)
            except BaseException:
                raise LaneATaskBundleError(
                    "publication_uncertain", "publication state is uncertain", committed=True
                ) from None
            if staging_after == staging_identity and output_after != staging_identity:
                if isinstance(error, FileExistsError):
                    raise LaneATaskBundleError("output_exists", "output appeared concurrently") from None
                if isinstance(error, KeyboardInterrupt):
                    raise
                raise LaneATaskBundleError("publication_failed", "no-replace rename failed") from error
            if staging_after is None and output_after == staging_identity:
                committed = True
            else:
                raise LaneATaskBundleError(
                    "publication_uncertain", "publication state is uncertain", committed=True
                ) from None
        if parent_descriptor is not None:
            os.fsync(parent_descriptor)
        elif os.name == "posix":
            descriptor = os.open(output.parent, _directory_flags())
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
        _assert_chain(parent_guard, final_private=True)
        if parent_descriptor is not None:
            if _identity_at(parent_descriptor, output.name) != staging_identity:
                raise LaneATaskBundleError("publication_uncertain", "published identity differs", committed=True)
            output_descriptor = _open_bound_directory(output.name, staging_identity, dir_fd=parent_descriptor)
            after_payloads = {name: _read_regular_at(output_descriptor, name, maximum=_MAX_INPUT_BYTES)
                              for name in sorted(LANE_A_BUNDLE_FILES)}
            after_identity = staging_identity
        else:
            after_payloads, after_identity = _read_bundle_payloads(output)
        if after_identity != staging_identity or after_payloads != before_payloads:
            raise LaneATaskBundleError(
                "publication_uncertain", "published bytes differ", committed=True
            )
        after = _parse_bundle(
            after_payloads,
            expected_bundle_sha256=expected.manifest.bundle_sha256,
            expected_manifest_wire_sha256=expected.manifest.wire_sha256,
        )
        if after != expected:
            raise LaneATaskBundleError(
                "publication_uncertain", "published contract differs", committed=True
            )
        return after.manifest
    except LaneATaskBundleError as error:
        if committed and not error.committed:
            raise LaneATaskBundleError(
                "publication_uncertain", "published output could not be confirmed", committed=True
            ) from None
        raise
    except KeyboardInterrupt:
        if committed:
            raise LaneATaskBundleError(
                "publication_uncertain", "published output could not be confirmed", committed=True
            ) from None
        raise
    except BaseException:
        raise LaneATaskBundleError(
            "publication_uncertain" if committed else "publication_failed",
            "publication failed",
            committed=committed,
        ) from None
    finally:
        active = __import__('sys').exc_info()[0] is not None
        close_failed = False
        for descriptor in (output_descriptor, staging_descriptor, parent_descriptor):
            if descriptor is not None:
                try:
                    _close_publication_descriptor(descriptor)
                except BaseException:
                    close_failed = True
        if os.name == "nt":
            for handle in (windows_parent_handle,):
                if handle is not None:
                    try:
                        _close_windows_handle(handle)
                    except BaseException:
                        close_failed = True
        if close_failed and not active:
            raise LaneATaskBundleError(
                "publication_uncertain" if committed else "publication_failed",
                "publication resource close failed",
                committed=committed,
            ) from None


def _assert_output_disjoint(
    output_dir: str | os.PathLike[str],
    inputs: _Inputs,
    protected_paths: Sequence[str | os.PathLike[str]],
) -> tuple[Path, tuple[tuple[Path, tuple[int, int]], ...]]:
    try:
        output = _canonical_new_child(output_dir, status=2)
    except SnapshotBatchError as error:
        raise LaneATaskBundleError("invalid_output", "output path is invalid") from error
    output_guard = _guard_chain(output.parent, final_private=True)
    output_ids = tuple(identity for _path, identity in output_guard)
    paths = (inputs.public_path, inputs.assignment_path, *(Path(item) for item in protected_paths))
    for path in paths:
        try:
            initial = os.lstat(_windows_extended_path(path))
            canonical = _canonical_existing_path(path, directory=stat.S_ISDIR(initial.st_mode), status=2)
            state = os.lstat(_windows_extended_path(canonical))
            is_directory = stat.S_ISDIR(state.st_mode)
            if paths_overlap_v1(
                output, canonical, left_exists=False, right_directory=is_directory
            ):
                raise LaneATaskBundleError("path_overlap", "output overlaps a trusted input")
            if is_directory:
                protected_identity = _directory_identity(_require_directory(canonical))
                protected_chain = _guard_chain(canonical)
                protected_ids = tuple(identity for _item, identity in protected_chain)
                if protected_identity in output_ids or output_ids[-1] in protected_ids:
                    raise LaneATaskBundleError("path_overlap", "output aliases a trusted directory")
        except LaneATaskBundleError:
            raise
        except Exception:
            raise LaneATaskBundleError("path_check_failed", "trusted path could not be checked") from None
    _assert_chain(output_guard, final_private=True)
    return output, output_guard


def write_lane_a_task_bundle(
    output_dir: str | os.PathLike[str],
    public_tasks_file: str | os.PathLike[str],
    assignments_file: str | os.PathLike[str],
    *,
    expected_public_tasks_sha256: str,
    expected_public_tasks_wire_sha256: str,
    expected_assignments_sha256: str,
    expected_assignments_wire_sha256: str,
    expected_task_count: int,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
) -> LaneATaskBundleManifestV1:
    inputs = _load_inputs(
        public_tasks_file,
        assignments_file,
        expected_public_tasks_sha256=expected_public_tasks_sha256,
        expected_public_tasks_wire_sha256=expected_public_tasks_wire_sha256,
        expected_assignments_sha256=expected_assignments_sha256,
        expected_assignments_wire_sha256=expected_assignments_wire_sha256,
        expected_task_count=expected_task_count,
    )
    _assert_output_disjoint(output_dir, inputs, protected_paths)
    payloads, expected = _build_payloads(inputs)
    # A second pinned read closes changes between initial parsing and publication.
    repeated = _load_inputs(
        public_tasks_file,
        assignments_file,
        expected_public_tasks_sha256=expected_public_tasks_sha256,
        expected_public_tasks_wire_sha256=expected_public_tasks_wire_sha256,
        expected_assignments_sha256=expected_assignments_sha256,
        expected_assignments_wire_sha256=expected_assignments_wire_sha256,
        expected_task_count=expected_task_count,
    )
    repeated_payloads, repeated_expected = _build_payloads(repeated)
    if repeated_payloads != payloads or repeated_expected != expected:
        raise LaneATaskBundleError("input_changed", "pinned inputs changed")
    expected_output, expected_parent_guard = _assert_output_disjoint(
        output_dir, repeated, protected_paths
    )
    return _publish(
        output_dir,
        payloads,
        expected,
        expected_output=expected_output,
        expected_parent_guard=expected_parent_guard,
    )


def verify_lane_a_task_bundle(
    bundle_dir: str | os.PathLike[str],
    public_tasks_file: str | os.PathLike[str],
    assignments_file: str | os.PathLike[str],
    *,
    expected_public_tasks_sha256: str,
    expected_public_tasks_wire_sha256: str,
    expected_assignments_sha256: str,
    expected_assignments_wire_sha256: str,
    expected_task_count: int,
    expected_bundle_sha256: str,
    expected_manifest_wire_sha256: str,
) -> LaneATaskBundleV1:
    inputs = _load_inputs(
        public_tasks_file,
        assignments_file,
        expected_public_tasks_sha256=expected_public_tasks_sha256,
        expected_public_tasks_wire_sha256=expected_public_tasks_wire_sha256,
        expected_assignments_sha256=expected_assignments_sha256,
        expected_assignments_wire_sha256=expected_assignments_wire_sha256,
        expected_task_count=expected_task_count,
    )
    expected_payloads, expected = _build_payloads(inputs)
    actual = read_lane_a_task_bundle(
        bundle_dir,
        expected_bundle_sha256=expected_bundle_sha256,
        expected_manifest_wire_sha256=expected_manifest_wire_sha256,
    )
    root = _canonical_existing_path(bundle_dir, directory=True, status=2)
    actual_payloads, _identity_value = _read_bundle_payloads(root)
    if actual_payloads != expected_payloads or actual != expected:
        raise LaneATaskBundleError(
            "source_binding_mismatch", "bundle bytes differ from pinned inputs"
        )
    return actual


def compute_lane_a_input_pins(
    public_tasks_file: str | os.PathLike[str],
    assignments_file: str | os.PathLike[str],
) -> dict[str, object]:
    """Compute review-time pins; production build still requires them externally."""

    public_path, public_wire = _read_regular(public_tasks_file, maximum=_MAX_INPUT_BYTES)
    assignment_path, assignment_wire = _read_regular(assignments_file, maximum=_MAX_INPUT_BYTES)
    if public_path == assignment_path:
        raise LaneATaskBundleError("path_overlap", "the two inputs overlap")
    tasks = tuple(BenchmarkTask.from_dict(value) for value in _parse_jsonl(public_wire, "public task"))
    assignments = tuple(
        LaneAAssignmentV1.from_dict(value)
        for value in _parse_jsonl(assignment_wire, "assignment")
    )
    if len(tasks) != len(assignments) or any(
        task.task_id != assignment.task_id
        for task, assignment in zip(tasks, assignments, strict=True)
    ):
        raise LaneATaskBundleError("assignment_order_mismatch", "input rows differ")
    return {
        "assignments_sha256": _semantic(
            LANE_A_ASSIGNMENTS_DOMAIN, [item.to_dict() for item in assignments]
        ),
        "assignments_wire_sha256": hashlib.sha256(assignment_wire).hexdigest(),
        "public_tasks_sha256": _semantic(
            LANE_A_PUBLIC_TASKS_DOMAIN, [task.to_dict() for task in tasks]
        ),
        "public_tasks_wire_sha256": hashlib.sha256(public_wire).hexdigest(),
        "task_count": len(tasks),
    }


__all__ = [
    "LANE_A_TASK_BUNDLE_CONTRACT_VERSION",
    "LANE_A_TASK_BUNDLE_FILES",
    "LaneAAssignmentV1",
    "LaneATaskBundleError",
    "LaneATaskBundleManifestV1",
    "LaneATaskBundleV1",
    "compute_lane_a_input_pins",
    "read_lane_a_task_bundle",
    "verify_lane_a_task_bundle",
    "write_lane_a_task_bundle",
]
