"""Independent, pinned reader for committed discovery projection outputs.

The projection writer in :mod:`vulngym_agent.benchmark.harness` publishes a
small final-name interface.  This module is deliberately read-only and does
not discover any benchmark data: callers supply the exact ordered public task,
snapshot, and dataset bindings plus the artifact-index and projection-manifest
digests.  A successful return therefore describes only the bytes read during
this invocation and never exposes a host path.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Final, Literal, Mapping

from .contracts import BenchmarkContractError, SnapshotTaskSpec
from .discovery_contracts import DEFAULT_DISCOVERY_LIMITS
from .discovery_projection import DISCOVERY_PROJECTION_VERSION
from .harness import (
    ARTIFACT_INDEX_CONTRACT_VERSION,
    DEFAULT_DISCOVERY_TOP_K,
    MAX_DISCOVERY_TOP_K,
    MAX_FINDING_BYTES,
    MAX_TASK_FINDING_BYTES,
    MAX_TOTAL_OUTPUT_BYTES,
    MAX_TRACE_NODES_PER_BATCH,
    MAX_TRACE_NODES_PER_TASK,
    OFFICIAL_TOLERANCE,
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    PROFILE_SCHEMA_VERSION,
    PROFILE_TEST_TASKS,
    PROFILE_TRAIN_ADVISORIES,
    PROFILE_TRAIN_ENTRIES,
    PROFILE_TRAIN_TASKS,
    BenchmarkHarnessError,
    DiscoveryProjectionStats,
    DiscoveryProjectionSummary,
    TrainingAggregate,
    _validate_published_finding,
    evaluate_training_aggregate,
)
from .sealed_snapshot import SealedSnapshotError, _windows_assert_no_named_streams


PROJECTION_READER_VERSION: Final[str] = "discovery-projection-reader-v1"
MAX_PROJECTION_MANIFEST_BYTES: Final[int] = 2 * 1024 * 1024
MAX_PROJECTION_TASK_RESULTS_BYTES: Final[int] = 8 * 1024 * 1024
MAX_PROJECTION_AGGREGATE_BYTES: Final[int] = 64 * 1024
MAX_PROJECTION_JSON_DEPTH: Final[int] = 64
MAX_PROJECTION_JSON_NODES: Final[int] = 300_000

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_SNAPSHOT_ID_RE: Final[re.Pattern[str]] = re.compile(r"VGS-[0-9A-F]{32}\Z")
_EXPECTED_COUNTS: Final[dict[str, int]] = {
    "train": PROFILE_TRAIN_TASKS,
    "test": PROFILE_TEST_TASKS,
}
_BASE_MEMBERS: Final[frozenset[str]] = frozenset(
    {"findings.jsonl", "manifest.json", "task_results.jsonl"}
)
_TRAIN_MEMBERS: Final[frozenset[str]] = _BASE_MEMBERS | {"aggregate.json"}
_STAT_NAMES: Final[tuple[str, ...]] = tuple(
    DiscoveryProjectionStats.__dataclass_fields__
)
_TASK_RESULT_KEYS: Final[frozenset[str]] = frozenset(
    {"dataset_sha256", "snapshot_id", "status", "task_id", *_STAT_NAMES}
)
_AGGREGATE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "advisory_recall",
        "covered_advisories",
        "entry_recall",
        "matched_entries",
        "submitted_findings",
        "total_advisories",
        "total_entries",
    }
)
_MANIFEST_BASE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "bundle_datasets",
        "bundle_datasets_sha256",
        "bundle_index_sha256",
        "contract_version",
        "discovery_projection_version",
        "files",
        "kind",
        "manifest_sha256",
        "max_d0_findings",
        "profile_id",
        "schema_version",
        "split",
        "task_count",
        "top_k",
        *_STAT_NAMES,
    }
)


class DiscoveryProjectionReaderError(RuntimeError):
    """Stable, path-free rejection from the committed projection boundary."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "projection_invalid"
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class DiscoveryProjectionTaskBindingV1:
    """One trusted ordered public-task, snapshot, and result-dataset binding."""

    task: SnapshotTaskSpec
    snapshot_id: str
    dataset_sha256: str

    def __post_init__(self) -> None:
        if type(self.task) is not SnapshotTaskSpec:
            raise DiscoveryProjectionReaderError(
                "invalid_argument", "expected projection task has an invalid exact type"
            )
        try:
            frozen_task = SnapshotTaskSpec(
                task_id=self.task.task_id,
                repo_url=self.task.repo_url,
                commit=self.task.commit,
                split=self.task.split,
                instruction_id=self.task.instruction_id,
            )
        except (AttributeError, BenchmarkContractError, TypeError, ValueError):
            raise DiscoveryProjectionReaderError(
                "invalid_argument", "expected projection task is invalid"
            ) from None
        if (
            type(self.snapshot_id) is not str
            or _SNAPSHOT_ID_RE.fullmatch(self.snapshot_id) is None
            or type(self.dataset_sha256) is not str
            or _SHA256_RE.fullmatch(self.dataset_sha256) is None
        ):
            raise DiscoveryProjectionReaderError(
                "invalid_argument", "expected projection result binding is invalid"
            )
        object.__setattr__(self, "task", frozen_task)


@dataclass(frozen=True, slots=True)
class VerifiedDiscoveryProjectionV1:
    """Path-free closure of one committed discovery projection byte snapshot."""

    summary: DiscoveryProjectionSummary
    aggregate_file_sha256: str | None
    reader_version: str = PROJECTION_READER_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.summary) is not DiscoveryProjectionSummary
            or type(self.reader_version) is not str
            or self.reader_version != PROJECTION_READER_VERSION
            or (self.summary.split == "train")
            != (
                type(self.aggregate_file_sha256) is str
                and _SHA256_RE.fullmatch(self.aggregate_file_sha256) is not None
            )
        ):
            raise DiscoveryProjectionReaderError(
                "invalid_state", "verified projection closure is invalid"
            )

    def to_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "reader_version": self.reader_version,
            "summary": self.summary.to_dict(),
        }
        if self.aggregate_file_sha256 is not None:
            value["aggregate_file_sha256"] = self.aggregate_file_sha256
        return value


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
        raise DiscoveryProjectionReaderError(
            "noncanonical_json", "projection JSON is not canonicalizable"
        ) from None


def _reject_constant(_value: str) -> None:
    raise DiscoveryProjectionReaderError(
        "noncanonical_json", "projection JSON contains a forbidden numeric constant"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DiscoveryProjectionReaderError(
                "noncanonical_json", "projection JSON repeats an object key"
            )
        result[key] = value
    return result


def _validate_json_shape(
    value: object, *, depth: int = 0, count: list[int]
) -> None:
    count[0] += 1
    if count[0] > MAX_PROJECTION_JSON_NODES or depth > MAX_PROJECTION_JSON_DEPTH:
        raise DiscoveryProjectionReaderError(
            "limit_exceeded", "projection JSON exceeds its shape limits"
        )
    if type(value) is str:
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise DiscoveryProjectionReaderError(
                "noncanonical_json", "projection JSON contains an invalid Unicode scalar"
            )
    elif type(value) is list:
        for child in value:
            _validate_json_shape(child, depth=depth + 1, count=count)
    elif type(value) is dict:
        for key, child in value.items():
            _validate_json_shape(key, depth=depth + 1, count=count)
            _validate_json_shape(child, depth=depth + 1, count=count)
    elif value is not None and type(value) not in {bool, int, float}:
        raise DiscoveryProjectionReaderError(
            "noncanonical_json", "projection JSON contains an invalid value"
        )
    if type(value) is float and not math.isfinite(value):
        raise DiscoveryProjectionReaderError(
            "noncanonical_json", "projection JSON contains a non-finite number"
        )


def _parse_canonical_line(payload: bytes, *, name: str) -> dict[str, Any]:
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise DiscoveryProjectionReaderError(
            "noncanonical_json", f"{name} must be one canonical JSON line"
        )
    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except DiscoveryProjectionReaderError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise DiscoveryProjectionReaderError(
            "noncanonical_json", f"{name} is not strict JSON"
        ) from None
    _validate_json_shape(value, count=[0])
    if type(value) is not dict or _canonical_json(value) + b"\n" != payload:
        raise DiscoveryProjectionReaderError(
            "noncanonical_json", f"{name} is not canonical JSON"
        )
    return value


def _parse_canonical_jsonl(
    payload: bytes,
    *,
    name: str,
    maximum_records: int,
    allow_empty: bool,
) -> tuple[dict[str, Any], ...]:
    if not payload:
        if allow_empty:
            return ()
        raise DiscoveryProjectionReaderError(
            "projection_invalid", f"{name} must not be empty"
        )
    if not payload.endswith(b"\n"):
        raise DiscoveryProjectionReaderError(
            "noncanonical_json", f"{name} has invalid JSONL framing"
        )
    lines = payload.splitlines(keepends=True)
    if not 1 <= len(lines) <= maximum_records:
        raise DiscoveryProjectionReaderError(
            "limit_exceeded", f"{name} exceeds its record limit"
        )
    result: list[dict[str, Any]] = []
    for line in lines:
        if len(line) > MAX_FINDING_BYTES:
            raise DiscoveryProjectionReaderError(
                "limit_exceeded", f"{name} contains an oversized record"
            )
        result.append(_parse_canonical_line(line, name=name))
    return tuple(result)


def _is_reparse(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _directory_identity(value: os.stat_result) -> tuple[int, int, int | None, int | None]:
    return (
        value.st_dev,
        value.st_ino,
        getattr(value, "st_mtime_ns", None),
        getattr(value, "st_ctime_ns", None),
    )


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int | None]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        getattr(value, "st_mtime_ns", None),
    )


def _checked_root(
    value: str | os.PathLike[str],
) -> tuple[
    Path,
    tuple[tuple[Path, tuple[int, int]], ...],
    tuple[int, int, int | None, int | None],
]:
    if type(value) not in {str, type(Path())}:
        raise DiscoveryProjectionReaderError(
            "invalid_argument", "projection root must be an exact path value"
        )
    try:
        raw = os.fspath(value)
        if type(raw) is not str or not raw:
            raise ValueError("empty path")
        root = Path(os.path.abspath(raw))
    except (OSError, TypeError, ValueError):
        raise DiscoveryProjectionReaderError(
            "invalid_argument", "projection root path is invalid"
        ) from None
    if not root.name or root.name in {".", ".."}:
        raise DiscoveryProjectionReaderError(
            "invalid_argument", "projection root name is invalid"
        )
    chain: list[tuple[Path, tuple[int, int]]] = []
    try:
        for component in reversed((root.parent, *root.parent.parents)):
            state = os.lstat(component)
            if (
                not stat.S_ISDIR(state.st_mode)
                or stat.S_ISLNK(state.st_mode)
                or _is_reparse(state)
            ):
                raise DiscoveryProjectionReaderError(
                    "unsafe_path", "projection parent chain is unsafe"
                )
            chain.append((component, (state.st_dev, state.st_ino)))
        root_state = os.lstat(root)
        if (
            not stat.S_ISDIR(root_state.st_mode)
            or stat.S_ISLNK(root_state.st_mode)
            or _is_reparse(root_state)
        ):
            raise DiscoveryProjectionReaderError(
                "unsafe_path", "projection root is unsafe"
            )
        resolved = root.resolve(strict=True)
        resolved_state = os.lstat(resolved)
        if (
            not stat.S_ISDIR(resolved_state.st_mode)
            or stat.S_ISLNK(resolved_state.st_mode)
            or _is_reparse(resolved_state)
            or (resolved_state.st_dev, resolved_state.st_ino)
            != (root_state.st_dev, root_state.st_ino)
        ):
            raise DiscoveryProjectionReaderError(
                "unsafe_path", "projection root resolution changed"
            )
    except DiscoveryProjectionReaderError:
        raise
    except OSError as error:
        raise DiscoveryProjectionReaderError(
            "unsafe_path", "projection root is unavailable"
        ) from error
    return root, tuple(chain), _directory_identity(root_state)


def _assert_parent_chain(
    chain: tuple[tuple[Path, tuple[int, int]], ...]
) -> None:
    try:
        for component, expected in chain:
            state = os.lstat(component)
            if (
                not stat.S_ISDIR(state.st_mode)
                or stat.S_ISLNK(state.st_mode)
                or _is_reparse(state)
                or (state.st_dev, state.st_ino) != expected
            ):
                raise DiscoveryProjectionReaderError(
                    "input_changed", "projection parent chain changed while reading"
                )
    except DiscoveryProjectionReaderError:
        raise
    except OSError as error:
        raise DiscoveryProjectionReaderError(
            "input_changed", "projection parent chain changed while reading"
        ) from error


def _member_names(root: Path) -> frozenset[str]:
    try:
        with os.scandir(root) as entries:
            return frozenset(item.name for item in entries)
    except OSError as error:
        raise DiscoveryProjectionReaderError(
            "input_changed", "projection membership is unavailable"
        ) from error


def _read_member_once(
    root: Path, name: str, *, maximum_bytes: int
) -> tuple[bytes, tuple[int, int, int, int | None]]:
    path = root / name
    try:
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum_bytes
        ):
            raise DiscoveryProjectionReaderError(
                "unsafe_member", "projection member is unsafe or oversized"
            )
        if os.name == "nt":
            _windows_assert_no_named_streams(path)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse(opened)
                or opened.st_nlink != 1
                or _file_identity(opened) != _file_identity(before)
            ):
                raise DiscoveryProjectionReaderError(
                    "input_changed", "projection member changed while opening"
                )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(
                    descriptor, min(1024 * 1024, maximum_bytes + 1 - total)
                )
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum_bytes:
                    raise DiscoveryProjectionReaderError(
                        "limit_exceeded", "projection member exceeds its byte limit"
                    )
            finished = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = os.lstat(path)
        identity = _file_identity(opened)
        if (
            not stat.S_ISREG(finished.st_mode)
            or _is_reparse(finished)
            or finished.st_nlink != 1
            or not stat.S_ISREG(after.st_mode)
            or stat.S_ISLNK(after.st_mode)
            or _is_reparse(after)
            or after.st_nlink != 1
            or _file_identity(finished) != identity
            or _file_identity(after) != identity
            or total != opened.st_size
        ):
            raise DiscoveryProjectionReaderError(
                "input_changed", "projection member changed while reading"
            )
        return b"".join(chunks), identity
    except DiscoveryProjectionReaderError:
        raise
    except (OSError, SealedSnapshotError) as error:
        raise DiscoveryProjectionReaderError(
            "unsafe_member", "projection member could not be read safely"
        ) from error


def _read_stable_files(
    root: Path,
    *,
    expected_names: frozenset[str],
    root_identity: tuple[int, int, int | None, int | None],
    parent_chain: tuple[tuple[Path, tuple[int, int]], ...],
) -> dict[str, bytes]:
    if _member_names(root) != expected_names:
        raise DiscoveryProjectionReaderError(
            "projection_invalid", "projection membership is not exact"
        )
    limits = {
        "aggregate.json": MAX_PROJECTION_AGGREGATE_BYTES,
        "findings.jsonl": MAX_TOTAL_OUTPUT_BYTES,
        "manifest.json": MAX_PROJECTION_MANIFEST_BYTES,
        "task_results.jsonl": MAX_PROJECTION_TASK_RESULTS_BYTES,
    }
    first: dict[str, tuple[bytes, tuple[int, int, int, int | None]]] = {}
    second: dict[str, tuple[bytes, tuple[int, int, int, int | None]]] = {}
    for name in sorted(expected_names):
        first[name] = _read_member_once(root, name, maximum_bytes=limits[name])
    if sum(len(value[0]) for value in first.values()) > MAX_TOTAL_OUTPUT_BYTES:
        raise DiscoveryProjectionReaderError(
            "limit_exceeded", "projection output exceeds its total byte limit"
        )
    for name in sorted(expected_names):
        second[name] = _read_member_once(root, name, maximum_bytes=limits[name])
        if second[name] != first[name]:
            raise DiscoveryProjectionReaderError(
                "input_changed", "projection member changed between read passes"
            )
    try:
        for name in sorted(expected_names):
            state = os.lstat(root / name)
            if (
                not stat.S_ISREG(state.st_mode)
                or stat.S_ISLNK(state.st_mode)
                or _is_reparse(state)
                or state.st_nlink != 1
                or _file_identity(state) != second[name][1]
            ):
                raise DiscoveryProjectionReaderError(
                    "input_changed", "projection member changed before read closure"
                )
        final_root = os.lstat(root)
        if (
            not stat.S_ISDIR(final_root.st_mode)
            or stat.S_ISLNK(final_root.st_mode)
            or _is_reparse(final_root)
            or _directory_identity(final_root) != root_identity
            or _member_names(root) != expected_names
        ):
            raise DiscoveryProjectionReaderError(
                "input_changed", "projection root changed while reading"
            )
    except DiscoveryProjectionReaderError:
        raise
    except OSError as error:
        raise DiscoveryProjectionReaderError(
            "input_changed", "projection output changed while reading"
        ) from error
    _assert_parent_chain(parent_chain)
    return {name: second[name][0] for name in expected_names}


def _validate_expected_bindings(
    *,
    expected_split: object,
    expected_manifest_sha256: object,
    expected_artifact_index_sha256: object,
    expected_tasks: object,
) -> tuple[
    Literal["train", "test"],
    str,
    str,
    tuple[DiscoveryProjectionTaskBindingV1, ...],
]:
    if type(expected_split) is not str or expected_split not in _EXPECTED_COUNTS:
        raise DiscoveryProjectionReaderError(
            "invalid_argument", "expected projection split must be train or test"
        )
    for value, name in (
        (expected_manifest_sha256, "projection manifest digest"),
        (expected_artifact_index_sha256, "artifact index digest"),
    ):
        if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
            raise DiscoveryProjectionReaderError(
                "invalid_argument", f"expected {name} is invalid"
            )
    if type(expected_tasks) is not tuple:
        raise DiscoveryProjectionReaderError(
            "invalid_argument", "expected projection tasks must be an exact tuple"
        )
    bindings: list[DiscoveryProjectionTaskBindingV1] = []
    for item in expected_tasks:
        if type(item) is not DiscoveryProjectionTaskBindingV1:
            raise DiscoveryProjectionReaderError(
                "invalid_argument", "expected projection binding has an invalid exact type"
            )
        bindings.append(
            DiscoveryProjectionTaskBindingV1(
                task=item.task,
                snapshot_id=item.snapshot_id,
                dataset_sha256=item.dataset_sha256,
            )
        )
    if (
        len(bindings) != _EXPECTED_COUNTS[expected_split]
        or any(item.task.split != expected_split for item in bindings)
        or len({item.task.task_id for item in bindings}) != len(bindings)
        or len({item.snapshot_id for item in bindings}) != len(bindings)
        or len({item.dataset_sha256 for item in bindings}) != len(bindings)
    ):
        raise DiscoveryProjectionReaderError(
            "invalid_argument", "expected projection bindings do not define the fixed split"
        )
    return (
        expected_split,
        expected_manifest_sha256,
        expected_artifact_index_sha256,
        tuple(bindings),
    )


def _expected_dataset_records(
    bindings: tuple[DiscoveryProjectionTaskBindingV1, ...]
) -> list[dict[str, str]]:
    return [
        {
            "dataset_sha256": item.dataset_sha256,
            "snapshot_id": item.snapshot_id,
            "task_id": item.task.task_id,
        }
        for item in bindings
    ]


def _validate_manifest(
    value: dict[str, Any],
    *,
    split: Literal["train", "test"],
    artifact_index_sha256: str,
    bindings: tuple[DiscoveryProjectionTaskBindingV1, ...],
    payloads: Mapping[str, bytes],
) -> None:
    expected_keys = _MANIFEST_BASE_KEYS | (
        {"official_tolerance"} if split == "train" else set()
    )
    expected_files = (
        {"aggregate.json", "findings.jsonl", "task_results.jsonl"}
        if split == "train"
        else {"findings.jsonl", "task_results.jsonl"}
    )
    if frozenset(value) != frozenset(expected_keys):
        raise DiscoveryProjectionReaderError(
            "projection_invalid", "projection manifest shape is invalid"
        )
    if (
        type(value["contract_version"]) is not int
        or value["contract_version"] != ARTIFACT_INDEX_CONTRACT_VERSION
        or value["kind"] != "verified_discovery_benchmark_projection"
        or value["profile_id"] != PROFILE_ID
        or value["schema_version"] != PROFILE_SCHEMA_VERSION
        or value["manifest_sha256"] != PROFILE_MANIFEST_SHA256
        or value["discovery_projection_version"] != DISCOVERY_PROJECTION_VERSION
        or value["split"] != split
        or type(value["task_count"]) is not int
        or value["task_count"] != len(bindings)
        or type(value["top_k"]) is not int
        or value["top_k"] != DEFAULT_DISCOVERY_TOP_K
        or type(value["max_d0_findings"]) is not int
        or value["max_d0_findings"] != MAX_DISCOVERY_TOP_K
        or value["bundle_index_sha256"] != artifact_index_sha256
        or (split == "train" and value["official_tolerance"] != OFFICIAL_TOLERANCE)
    ):
        raise DiscoveryProjectionReaderError(
            "binding_mismatch", "projection manifest fixed bindings are invalid"
        )
    datasets = _expected_dataset_records(bindings)
    if (
        value["bundle_datasets"] != datasets
        or value["bundle_datasets_sha256"]
        != hashlib.sha256(_canonical_json(datasets)).hexdigest()
    ):
        raise DiscoveryProjectionReaderError(
            "binding_mismatch", "projection dataset bindings differ from expectations"
        )
    raw_files = value["files"]
    if type(raw_files) is not dict or set(raw_files) != expected_files:
        raise DiscoveryProjectionReaderError(
            "projection_invalid", "projection file bindings are invalid"
        )
    for name in sorted(expected_files):
        binding = raw_files[name]
        payload = payloads[name]
        if (
            type(binding) is not dict
            or frozenset(binding) != frozenset({"bytes", "sha256"})
            or type(binding["bytes"]) is not int
            or binding["bytes"] != len(payload)
            or type(binding["sha256"]) is not str
            or binding["sha256"] != hashlib.sha256(payload).hexdigest()
        ):
            raise DiscoveryProjectionReaderError(
                "digest_mismatch", "projection file binding does not match its bytes"
            )


def _validate_task_results(
    records: tuple[dict[str, Any], ...],
    *,
    bindings: tuple[DiscoveryProjectionTaskBindingV1, ...],
) -> tuple[tuple[DiscoveryProjectionStats, ...], tuple[str, ...]]:
    if len(records) != len(bindings):
        raise DiscoveryProjectionReaderError(
            "projection_invalid", "projection task result count is invalid"
        )
    stats: list[DiscoveryProjectionStats] = []
    statuses: list[str] = []
    for record, binding in zip(records, bindings, strict=True):
        if frozenset(record) != _TASK_RESULT_KEYS:
            raise DiscoveryProjectionReaderError(
                "projection_invalid", "projection task result shape is invalid"
            )
        status = record["status"]
        if (
            record["task_id"] != binding.task.task_id
            or record["snapshot_id"] != binding.snapshot_id
            or record["dataset_sha256"] != binding.dataset_sha256
            or type(status) is not str
            or status not in {"finalized", "deferred"}
        ):
            raise DiscoveryProjectionReaderError(
                "binding_mismatch", "projection task result order or binding is invalid"
            )
        try:
            item = DiscoveryProjectionStats(
                **{name: record[name] for name in _STAT_NAMES}
            )
        except (TypeError, ValueError):
            raise DiscoveryProjectionReaderError(
                "projection_invalid", "projection task counters are invalid"
            ) from None
        if (
            (status == "deferred") != (item.task_deferred == 1)
            or item.candidate_count > MAX_DISCOVERY_TOP_K
            or item.emit_review_count > MAX_DISCOVERY_TOP_K
            or item.reject_review_count > MAX_DISCOVERY_TOP_K
            or item.defer_review_count > MAX_DISCOVERY_TOP_K
            or item.trace_node_count > MAX_TRACE_NODES_PER_TASK
            or item.trace_node_count
            > (
                item.candidate_count
                * DEFAULT_DISCOVERY_LIMITS.max_trace_nodes_per_candidate
            )
            or item.unique_findings > MAX_DISCOVERY_TOP_K
            or item.emitted_findings > MAX_DISCOVERY_TOP_K
            or item.truncated_findings > MAX_DISCOVERY_TOP_K
            or item.truncated_findings != 0
            or item.emitted_findings != item.unique_findings
            or item.unique_findings > item.emit_review_count
        ):
            raise DiscoveryProjectionReaderError(
                "projection_invalid",
                "projection task counters violate fixed closure or limits",
            )
        stats.append(item)
        statuses.append(status)
    if sum(item.trace_node_count for item in stats) > MAX_TRACE_NODES_PER_BATCH:
        raise DiscoveryProjectionReaderError(
            "limit_exceeded", "projection trace counters exceed the batch limit"
        )
    return tuple(stats), tuple(statuses)


def _validate_findings(
    records: tuple[dict[str, Any], ...],
    *,
    bindings: tuple[DiscoveryProjectionTaskBindingV1, ...],
    stats: tuple[DiscoveryProjectionStats, ...],
) -> None:
    tasks = {item.task.task_id: item.task for item in bindings}
    positions = {item.task.task_id: index for index, item in enumerate(bindings)}
    counts = {item.task.task_id: 0 for item in bindings}
    byte_counts = {item.task.task_id: 0 for item in bindings}
    trace_counts = {item.task.task_id: 0 for item in bindings}
    previous_endpoint_identities: dict[str, str] = {}
    seen_finding_ids: set[str] = set()
    previous_position = -1
    for record in records:
        try:
            finding = _validate_published_finding(record, tasks)
        except (BenchmarkHarnessError, BenchmarkContractError, StopIteration, TypeError, ValueError):
            raise DiscoveryProjectionReaderError(
                "projection_invalid", "projected finding is not canonical"
            ) from None
        task_id = finding["task_id"]
        position = positions[task_id]
        finding_id = finding["finding_id"]
        endpoint_identity = _canonical_json(
            {
                "commit": finding["commit"],
                "critical_operation": finding["critical_operation"],
                "entry_point": finding["entry_point"],
                "repo_url": finding["repo_url"],
                "task_id": finding["task_id"],
            }
        ).decode("utf-8")
        previous_endpoint_identity = previous_endpoint_identities.get(task_id)
        if (
            position < previous_position
            or finding_id in seen_finding_ids
            or counts[task_id] >= MAX_DISCOVERY_TOP_K
            or (
                previous_endpoint_identity is not None
                and endpoint_identity <= previous_endpoint_identity
            )
        ):
            raise DiscoveryProjectionReaderError(
                "projection_invalid", "projected finding order or identity is invalid"
            )
        previous_position = position
        previous_endpoint_identities[task_id] = endpoint_identity
        seen_finding_ids.add(finding_id)
        counts[task_id] += 1
        trace_counts[task_id] += len(finding.get("trace", ()))
        byte_counts[task_id] += len(_canonical_json(record)) + 1
        if byte_counts[task_id] > MAX_TASK_FINDING_BYTES:
            raise DiscoveryProjectionReaderError(
                "limit_exceeded", "one task's projected findings exceed their byte limit"
            )
    for binding, item in zip(bindings, stats, strict=True):
        task_id = binding.task.task_id
        if (
            counts[task_id] != item.emitted_findings
            or trace_counts[task_id] > item.trace_node_count
        ):
            raise DiscoveryProjectionReaderError(
                "binding_mismatch",
                "projected findings differ from task result counters",
            )


def _validate_aggregate(
    value: dict[str, Any], *, finding_count: int
) -> TrainingAggregate:
    if frozenset(value) != _AGGREGATE_KEYS:
        raise DiscoveryProjectionReaderError(
            "projection_invalid", "training aggregate shape is invalid"
        )
    integer_names = (
        "covered_advisories",
        "matched_entries",
        "submitted_findings",
        "total_advisories",
        "total_entries",
    )
    if any(type(value[name]) is not int or value[name] < 0 for name in integer_names):
        raise DiscoveryProjectionReaderError(
            "projection_invalid", "training aggregate counts are invalid"
        )
    if (
        type(value["advisory_recall"]) is not float
        or type(value["entry_recall"]) is not float
        or not math.isfinite(value["advisory_recall"])
        or not math.isfinite(value["entry_recall"])
        or value["total_advisories"] != PROFILE_TRAIN_ADVISORIES
        or value["total_entries"] != PROFILE_TRAIN_ENTRIES
        or value["covered_advisories"] > value["total_advisories"]
        or value["matched_entries"] > value["total_entries"]
        or value["submitted_findings"] != finding_count
        or value["advisory_recall"]
        != value["covered_advisories"] / value["total_advisories"]
        or value["entry_recall"]
        != value["matched_entries"] / value["total_entries"]
    ):
        raise DiscoveryProjectionReaderError(
            "projection_invalid", "training aggregate does not close"
        )
    return TrainingAggregate(
        total_advisories=value["total_advisories"],
        covered_advisories=value["covered_advisories"],
        advisory_recall=value["advisory_recall"],
        total_entries=value["total_entries"],
        matched_entries=value["matched_entries"],
        entry_recall=value["entry_recall"],
        submitted_findings=value["submitted_findings"],
    )


def read_committed_discovery_projection_v1(
    output_root: str | os.PathLike[str],
    *,
    expected_split: Literal["train", "test"],
    expected_manifest_sha256: str,
    expected_artifact_index_sha256: str,
    expected_tasks: tuple[DiscoveryProjectionTaskBindingV1, ...],
    benchmark_root: str | os.PathLike[str] | None = None,
) -> VerifiedDiscoveryProjectionV1:
    """Verify one stable committed projection from external pins.

    Training verification additionally requires a caller-trusted benchmark
    root so the aggregate can be recomputed.  Test verification rejects that
    root and never enters the training oracle surface.
    """

    split, manifest_pin, index_pin, bindings = _validate_expected_bindings(
        expected_split=expected_split,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_artifact_index_sha256=expected_artifact_index_sha256,
        expected_tasks=expected_tasks,
    )
    if split == "train":
        if type(benchmark_root) not in {str, type(Path())}:
            raise DiscoveryProjectionReaderError(
                "invalid_argument",
                "training projection verification requires a trusted benchmark root",
            )
        try:
            if type(os.fspath(benchmark_root)) is not str or not os.fspath(benchmark_root):
                raise ValueError("empty benchmark root")
        except (OSError, TypeError, ValueError):
            raise DiscoveryProjectionReaderError(
                "invalid_argument", "trusted benchmark root is invalid"
            ) from None
    elif benchmark_root is not None:
        raise DiscoveryProjectionReaderError(
            "invalid_argument",
            "test projection verification forbids a benchmark root",
        )
    expected_names = _TRAIN_MEMBERS if split == "train" else _BASE_MEMBERS
    root, parent_chain, root_identity = _checked_root(output_root)
    payloads = _read_stable_files(
        root,
        expected_names=expected_names,
        root_identity=root_identity,
        parent_chain=parent_chain,
    )
    if hashlib.sha256(payloads["manifest.json"]).hexdigest() != manifest_pin:
        raise DiscoveryProjectionReaderError(
            "digest_mismatch", "projection manifest does not match its external pin"
        )
    try:
        manifest = _parse_canonical_line(
            payloads["manifest.json"], name="projection manifest"
        )
        _validate_manifest(
            manifest,
            split=split,
            artifact_index_sha256=index_pin,
            bindings=bindings,
            payloads=payloads,
        )
        task_results = _parse_canonical_jsonl(
            payloads["task_results.jsonl"],
            name="projection task results",
            maximum_records=len(bindings),
            allow_empty=False,
        )
        stats, statuses = _validate_task_results(task_results, bindings=bindings)
        findings = _parse_canonical_jsonl(
            payloads["findings.jsonl"],
            name="projection findings",
            maximum_records=len(bindings) * MAX_DISCOVERY_TOP_K,
            allow_empty=True,
        )
        _validate_findings(findings, bindings=bindings, stats=stats)
        totals = {name: sum(getattr(item, name) for item in stats) for name in _STAT_NAMES}
        if any(
            type(manifest[name]) is not int or manifest[name] != totals[name]
            for name in _STAT_NAMES
        ):
            raise DiscoveryProjectionReaderError(
                "binding_mismatch", "projection manifest totals do not match task results"
            )
        aggregate = None
        aggregate_sha256 = None
        if split == "train":
            aggregate = _validate_aggregate(
                _parse_canonical_line(
                    payloads["aggregate.json"], name="training aggregate"
                ),
                finding_count=len(findings),
            )
            try:
                recomputed_aggregate = evaluate_training_aggregate(
                    benchmark_root, findings
                )
            except (
                AttributeError,
                BenchmarkHarnessError,
                KeyError,
                OSError,
                RecursionError,
                RuntimeError,
                TypeError,
                UnicodeError,
                ValueError,
            ):
                raise DiscoveryProjectionReaderError(
                    "projection_invalid",
                    "trusted training aggregate could not be recomputed",
                ) from None
            if (
                type(recomputed_aggregate) is not TrainingAggregate
                or _canonical_json(recomputed_aggregate.to_dict())
                != _canonical_json(aggregate.to_dict())
            ):
                raise DiscoveryProjectionReaderError(
                    "binding_mismatch",
                    "training aggregate differs from trusted recomputation",
                )
            aggregate_sha256 = hashlib.sha256(payloads["aggregate.json"]).hexdigest()
        summary = DiscoveryProjectionSummary(
            split=split,
            task_count=len(bindings),
            finalized_task_count=sum(status == "finalized" for status in statuses),
            deferred_task_count=sum(status == "deferred" for status in statuses),
            candidate_count=totals["candidate_count"],
            finding_count=len(findings),
            bundle_index_sha256=index_pin,
            output_manifest_sha256=manifest_pin,
            aggregate=aggregate,
        )
        return VerifiedDiscoveryProjectionV1(
            summary=summary,
            aggregate_file_sha256=aggregate_sha256,
        )
    except DiscoveryProjectionReaderError:
        raise
    except (BenchmarkHarnessError, BenchmarkContractError, KeyError, TypeError, ValueError):
        raise DiscoveryProjectionReaderError(
            "projection_invalid", "committed discovery projection did not verify"
        ) from None


__all__ = [
    "DiscoveryProjectionReaderError",
    "DiscoveryProjectionTaskBindingV1",
    "MAX_PROJECTION_AGGREGATE_BYTES",
    "MAX_PROJECTION_MANIFEST_BYTES",
    "MAX_PROJECTION_TASK_RESULTS_BYTES",
    "PROJECTION_READER_VERSION",
    "VerifiedDiscoveryProjectionV1",
    "read_committed_discovery_projection_v1",
]
