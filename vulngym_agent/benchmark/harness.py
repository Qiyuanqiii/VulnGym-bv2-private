"""Leak-resistant public benchmark validation and projection helpers.

The fixed ``vulngym-50-20-v1`` profile has an intentionally tiny read
surface.  Only the signed public manifest, its two schemas, and the public
train/test JSONL files are ever opened.  In particular, this module neither
discovers files below the benchmark root nor accepts caller-selected relative
paths.

The producer boundary is answer-free.  Public training gold is used only by
the aggregate oracle after findings have already crossed the projection
boundary; it is never returned as a task input.  Blind-test projection needs
only answer-free task specs and verified formal Entries, so it can run in a
sandbox in which no gold exists.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
from types import MappingProxyType
from typing import Any, Iterable, Literal, Mapping, Sequence

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from vulngym_agent.adapters import SchemaAdapter
from vulngym_agent.orchestrator.replay import (
    ReplayArtifactError,
    ReplayLimits,
    VerifiedFormalEntries,
    read_verified_formal_entries,
)

from .contracts import (
    BenchmarkContractError,
    BenchmarkReadLimits,
    EvaluationTaskSpec,
    PublicTestRecord,
    PublicTrainingRecord,
    SnapshotTaskSpec,
    iter_evaluator_findings,
    iter_public_benchmark_jsonl,
)


PROFILE_ID = "vulngym-50-20-v1"
PROFILE_SCHEMA_VERSION = "1.0.0"
PROFILE_SOURCE_REVISION = "cd69f7e163e08485ab5496115ae03439cda6e27e"
PROFILE_MANIFEST_SHA256 = (
    "d4ef4a663a30a39d2ccd89dc89f70d19a06686ae86179c537cd5139b8ff00a73"
)

PROFILE_TRAIN_TASKS = 50
PROFILE_TEST_TASKS = 20
PROFILE_TRAIN_ADVISORIES = 51
PROFILE_TRAIN_ENTRIES = 125

DEFAULT_TOP_K = 64
MAX_TOP_K = 256
MAX_RAW_ENTRIES_PER_TASK = 4096
OFFICIAL_TOLERANCE = 5
ARTIFACT_INDEX_CONTRACT_VERSION = 1
MAX_ARTIFACT_INDEX_BYTES = 1 * 1024 * 1024
MAX_TOTAL_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_FINDING_BYTES = 256 * 1024
MAX_TASK_FINDING_BYTES = 8 * 1024 * 1024
MAX_TRACE_NODES_PER_TASK = 4096
MAX_TRACE_NODES_PER_BATCH = 65_536

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BENCHMARK_TASK_ID_RE = re.compile(r"^VG-(TRAIN|TEST)-[0-9A-F]{20}$")
_BENCHMARK_REPLAY_LIMITS = ReplayLimits(
    max_input_records=MAX_TOP_K,
    max_records_per_file=4096,
    max_line_bytes=1_048_576,
    max_total_bytes=64 * 1024 * 1024,
)

_MANIFEST_PATH = "manifests/source_and_hash_manifest.json"
_RECORD_SCHEMA_PATH = "schemas/benchmark-record.schema.json"
_MANIFEST_SCHEMA_PATH = "schemas/public-manifest.schema.json"
_TRAIN_PATH = "public/train.jsonl"
_TEST_PATH = "public/test.jsonl"

# These are the only names accepted by the reader.  The manifest includes
# additional reproducibility artifacts, but validating this runtime profile
# must not open them (notably the repository .gitignore).
_PROFILE_FILES: Mapping[str, tuple[str, int]] = {
    "manifest": (_MANIFEST_PATH, 2 * 1024 * 1024),
    "record_schema": (_RECORD_SCHEMA_PATH, 2 * 1024 * 1024),
    "manifest_schema": (_MANIFEST_SCHEMA_PATH, 2 * 1024 * 1024),
    "train": (_TRAIN_PATH, 64 * 1024 * 1024),
    "test": (_TEST_PATH, 16 * 1024 * 1024),
}
_MANIFEST_ARTIFACT_PREFIX = "benchmarks/vulngym_50_20_v1/"

_ENTRY_ADAPTER = SchemaAdapter()
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 300_000


class BenchmarkHarnessError(ValueError):
    """A deterministic, local-path-free harness failure."""

    def __init__(self, code: str, message: str) -> None:
        if not isinstance(code, str) or not code:
            raise ValueError("error code must be a non-empty string")
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class PublicBundleSummary:
    profile_id: str
    schema_version: str
    source_revision: str
    manifest_sha256: str
    train_tasks: int
    test_tasks: int
    train_advisories: int
    train_entries: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_sha256": self.manifest_sha256,
            "profile_id": self.profile_id,
            "schema_version": self.schema_version,
            "source_revision": self.source_revision,
            "test_tasks": self.test_tasks,
            "train_advisories": self.train_advisories,
            "train_entries": self.train_entries,
            "train_tasks": self.train_tasks,
        }


@dataclass(frozen=True, slots=True)
class TaskExportSummary:
    split: Literal["train", "test"]
    task_count: int
    tasks_sha256: str
    manifest_sha256: str = PROFILE_MANIFEST_SHA256

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_sha256": self.manifest_sha256,
            "split": self.split,
            "task_count": self.task_count,
            "tasks_sha256": self.tasks_sha256,
        }


@dataclass(frozen=True, slots=True)
class ProjectionStats:
    raw_entries: int
    raw_trace_nodes: int
    unique_findings: int
    deduplicated_findings: int
    emitted_findings: int
    truncated_findings: int

    def to_dict(self) -> dict[str, int]:
        return {
            "deduplicated_findings": self.deduplicated_findings,
            "emitted_findings": self.emitted_findings,
            "raw_entries": self.raw_entries,
            "raw_trace_nodes": self.raw_trace_nodes,
            "truncated_findings": self.truncated_findings,
            "unique_findings": self.unique_findings,
        }


@dataclass(frozen=True, slots=True)
class ProjectedTask:
    """One answer-free task's evaluator findings and non-semantic counters."""

    task_id: str
    findings: tuple[Mapping[str, Any], ...]
    stats: ProjectionStats

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "findings",
            tuple(_freeze_json(finding) for finding in self.findings),
        )


@dataclass(frozen=True, slots=True)
class TrainingAggregate:
    total_advisories: int
    covered_advisories: int
    advisory_recall: float
    total_entries: int
    matched_entries: int
    entry_recall: float
    submitted_findings: int

    def to_dict(self) -> dict[str, Any]:
        # This intentionally has no task, advisory, Entry, or finding IDs.
        return {
            "advisory_recall": self.advisory_recall,
            "covered_advisories": self.covered_advisories,
            "entry_recall": self.entry_recall,
            "matched_entries": self.matched_entries,
            "submitted_findings": self.submitted_findings,
            "total_advisories": self.total_advisories,
            "total_entries": self.total_entries,
        }


@dataclass(frozen=True, slots=True)
class ArtifactBundleDigest:
    task_id: str
    dataset_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not _BENCHMARK_TASK_ID_RE.fullmatch(
            self.task_id
        ):
            raise ValueError("task_id must be a fixed-profile benchmark task ID")
        if not isinstance(self.dataset_sha256, str) or not _SHA256_RE.fullmatch(
            self.dataset_sha256
        ):
            raise ValueError("dataset_sha256 must be lower-case SHA-256")


@dataclass(frozen=True, slots=True)
class ArtifactBundleIndex:
    contract_version: int
    profile_id: str
    manifest_sha256: str
    split: Literal["train", "test"]
    bundles: tuple[ArtifactBundleDigest, ...]

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ValueError("artifact index contract_version must be 1")
        if self.profile_id != PROFILE_ID or self.manifest_sha256 != PROFILE_MANIFEST_SHA256:
            raise ValueError("artifact index profile binding is invalid")
        if self.split not in {"train", "test"}:
            raise ValueError("artifact index split must be train or test")
        bundles = tuple(self.bundles)
        if any(not isinstance(item, ArtifactBundleDigest) for item in bundles):
            raise ValueError("artifact index bundles have an invalid type")
        expected_prefix = "VG-TRAIN-" if self.split == "train" else "VG-TEST-"
        if any(not item.task_id.startswith(expected_prefix) for item in bundles):
            raise ValueError("artifact index task IDs do not match split")
        task_ids = [item.task_id for item in bundles]
        digests = [item.dataset_sha256 for item in bundles]
        if len(task_ids) != len(set(task_ids)) or len(digests) != len(set(digests)):
            raise ValueError("artifact index bundle identities must be unique")
        object.__setattr__(self, "bundles", bundles)


@dataclass(frozen=True, slots=True)
class ReplayProjectionSummary:
    split: Literal["train", "test"]
    task_count: int
    finding_count: int
    bundle_index_sha256: str
    output_manifest_sha256: str
    aggregate: TrainingAggregate | None = None

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "bundle_index_sha256": self.bundle_index_sha256,
            "finding_count": self.finding_count,
            "output_manifest_sha256": self.output_manifest_sha256,
            "split": self.split,
            "task_count": self.task_count,
        }
        if self.aggregate is not None:
            value["aggregate"] = self.aggregate.to_dict()
        return value


@dataclass(frozen=True, slots=True)
class _LoadedBundle:
    summary: PublicBundleSummary
    train: tuple[PublicTrainingRecord, ...]
    test: tuple[PublicTestRecord, ...]


def _is_reparse(result: os.stat_result) -> bool:
    attributes = getattr(result, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _identity(result: os.stat_result) -> tuple[int, int, int, int | None]:
    return (
        result.st_dev,
        result.st_ino,
        result.st_size,
        getattr(result, "st_mtime_ns", None),
    )


def _checked_lstat(path: Path, *, directory: bool | None = None) -> os.stat_result:
    try:
        result = os.lstat(path)
    except OSError as error:
        raise BenchmarkHarnessError(
            "public_file_unavailable", "a required public profile file is unavailable"
        ) from error
    if stat.S_ISLNK(result.st_mode) or _is_reparse(result):
        raise BenchmarkHarnessError(
            "unsafe_public_path",
            "public profile paths must not traverse links or reparse points",
        )
    if directory is True and not stat.S_ISDIR(result.st_mode):
        raise BenchmarkHarnessError(
            "unsafe_public_path", "public profile parent must be a directory"
        )
    if directory is False and not stat.S_ISREG(result.st_mode):
        raise BenchmarkHarnessError(
            "unsafe_public_path", "public profile input must be a regular file"
        )
    return result


def _root_chain(root: Path) -> tuple[Path, ...]:
    return tuple(reversed(root.parents)) + (root,)


def _profile_path(root: Path, logical_name: str) -> tuple[Path, int]:
    try:
        relative, maximum = _PROFILE_FILES[logical_name]
    except KeyError:
        raise ValueError("logical_name is not in the fixed public profile") from None
    return root.joinpath(*relative.split("/")), maximum


def _read_profile_file(
    benchmark_root: str | os.PathLike[str], logical_name: str
) -> bytes:
    """Read exactly one fixed-profile public file without directory discovery."""

    root = Path(os.path.abspath(os.fspath(benchmark_root)))
    target, maximum = _profile_path(root, logical_name)

    # Record every traversed directory and re-check it after the descriptor is
    # consumed.  Relative names are constants, never supplied by the caller.
    checked: list[tuple[Path, tuple[int, int, int, int | None]]] = []
    for component in _root_chain(root):
        result = _checked_lstat(component, directory=True)
        checked.append((component, _identity(result)))
    current = root
    relative_parts = _PROFILE_FILES[logical_name][0].split("/")
    for part in relative_parts[:-1]:
        current = current / part
        result = _checked_lstat(current, directory=True)
        checked.append((current, _identity(result)))
    before = _checked_lstat(target, directory=False)
    checked.append((target, _identity(before)))
    if before.st_size > maximum:
        raise BenchmarkHarnessError(
            "public_file_too_large", "a public profile file exceeds its size limit"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise BenchmarkHarnessError(
            "public_file_unavailable", "a required public profile file is unavailable"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise BenchmarkHarnessError(
                "public_file_changed", "a public profile file changed while opening"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(maximum + 1)
        if len(payload) > maximum:
            raise BenchmarkHarnessError(
                "public_file_too_large", "a public profile file exceeds its size limit"
            )
        finished = os.fstat(descriptor)
        if _identity(opened) != _identity(finished) or len(payload) != opened.st_size:
            raise BenchmarkHarnessError(
                "public_file_changed", "a public profile file changed while reading"
            )
    finally:
        os.close(descriptor)

    for component, expected in checked:
        actual = _checked_lstat(
            component, directory=component != target
        )
        if _identity(actual) != expected:
            raise BenchmarkHarnessError(
                "public_file_changed", "a public profile path changed while reading"
            )
    return payload


def _reject_constant(value: str) -> None:
    raise BenchmarkHarnessError(
        "invalid_json_number", f"JSON constant {value} is not permitted"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkHarnessError(
                "duplicate_json_key", "a public JSON object repeats a key"
            )
        result[key] = value
    return result


def _validate_json_shape(value: Any) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise BenchmarkHarnessError("json_too_large", "public JSON is too large")
        if depth > _MAX_JSON_DEPTH:
            raise BenchmarkHarnessError("json_too_deep", "public JSON is too deep")
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise BenchmarkHarnessError(
                    "invalid_unicode", "public JSON contains a Unicode surrogate"
                )
            return
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise BenchmarkHarnessError(
                    "invalid_json_number", "public JSON numbers must be finite"
                )
            return
        if isinstance(item, dict):
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
            return
        if isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
            return
        raise BenchmarkHarnessError("invalid_json", "public JSON has an invalid type")

    visit(value, 0)


def _strict_json(payload: bytes) -> Any:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise BenchmarkHarnessError("invalid_utf8", "public JSON must be UTF-8") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except BenchmarkHarnessError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise BenchmarkHarnessError("invalid_json", "public file is not strict JSON") from None
    _validate_json_shape(value)
    return value


def _freeze_json(value: Any) -> Any:
    """Recursively freeze a JSON-compatible value without retaining aliases."""

    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_json(child) for key, child in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child) for child in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_json(child) for child in value]
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _schema_validator(schema: Any, *, name: str) -> Draft202012Validator:
    if not isinstance(schema, dict):
        raise BenchmarkHarnessError("invalid_schema", f"{name} must be an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise BenchmarkHarnessError(
            "invalid_schema_draft", f"{name} must declare Draft 2020-12"
        )
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as error:
        raise BenchmarkHarnessError(
            "invalid_schema", f"{name} is not a valid Draft 2020-12 schema"
        ) from error
    return Draft202012Validator(schema)


def _validate_schema_instance(
    validator: Draft202012Validator, value: Any, *, name: str
) -> None:
    error = next(validator.iter_errors(value), None)
    if error is not None:
        raise BenchmarkHarnessError(
            "schema_validation_failed", f"{name} does not satisfy its public schema"
        )


def _manifest_artifacts(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise BenchmarkHarnessError("invalid_manifest", "manifest artifacts are invalid")
    indexed: dict[str, Mapping[str, Any]] = {}
    for item in artifacts:
        if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
            raise BenchmarkHarnessError("invalid_manifest", "manifest artifact is invalid")
        path = item["path"]
        if path in indexed:
            raise BenchmarkHarnessError(
                "duplicate_manifest_path", "manifest repeats an artifact path"
            )
        indexed[path] = item
    return indexed


def _validate_artifact(
    artifacts: Mapping[str, Mapping[str, Any]],
    *,
    logical_name: str,
    payload: bytes,
    rows: int | None = None,
) -> None:
    relative = _PROFILE_FILES[logical_name][0]
    manifest_path = _MANIFEST_ARTIFACT_PREFIX + relative
    item = artifacts.get(manifest_path)
    if item is None:
        raise BenchmarkHarnessError(
            "missing_manifest_artifact", "manifest omits a required public artifact"
        )
    if item.get("bytes") != len(payload) or item.get("sha256") != _sha256(payload):
        raise BenchmarkHarnessError(
            "artifact_digest_mismatch", "a public artifact does not match its manifest"
        )
    if rows is None:
        if "rows" in item:
            raise BenchmarkHarnessError(
                "artifact_rows_mismatch", "a non-JSONL public artifact declares rows"
            )
    elif item.get("rows") != rows:
        raise BenchmarkHarnessError(
            "artifact_rows_mismatch", "a public JSONL row count differs from its manifest"
        )


def _load_and_validate_bundle(
    benchmark_root: str | os.PathLike[str],
) -> _LoadedBundle:
    # The manifest is authenticated before any path or hash inside it is
    # trusted.  Subsequent reads still use only the compile-time allowlist.
    manifest_payload = _read_profile_file(benchmark_root, "manifest")
    if _sha256(manifest_payload) != PROFILE_MANIFEST_SHA256:
        raise BenchmarkHarnessError(
            "manifest_digest_mismatch", "public manifest does not match the fixed profile"
        )
    manifest = _strict_json(manifest_payload)

    record_schema_payload = _read_profile_file(benchmark_root, "record_schema")
    manifest_schema_payload = _read_profile_file(benchmark_root, "manifest_schema")
    record_schema = _strict_json(record_schema_payload)
    manifest_schema = _strict_json(manifest_schema_payload)
    record_validator = _schema_validator(record_schema, name="benchmark record schema")
    manifest_validator = _schema_validator(manifest_schema, name="public manifest schema")
    _validate_schema_instance(manifest_validator, manifest, name="public manifest")

    if not isinstance(manifest, Mapping):
        raise BenchmarkHarnessError("invalid_manifest", "public manifest must be an object")
    source = manifest.get("source")
    build = manifest.get("build")
    if not isinstance(source, Mapping) or not isinstance(build, Mapping):
        raise BenchmarkHarnessError("invalid_manifest", "public manifest profile is invalid")
    if source.get("revision") != PROFILE_SOURCE_REVISION:
        raise BenchmarkHarnessError(
            "source_revision_mismatch", "source revision does not match the fixed profile"
        )
    if (
        manifest.get("schema_version") != PROFILE_SCHEMA_VERSION
        or build.get("dataset_id") != PROFILE_ID
        or build.get("train_tasks") != PROFILE_TRAIN_TASKS
        or build.get("test_tasks") != PROFILE_TEST_TASKS
    ):
        raise BenchmarkHarnessError(
            "profile_mismatch", "public manifest does not match the fixed benchmark profile"
        )

    artifacts = _manifest_artifacts(manifest)
    _validate_artifact(
        artifacts,
        logical_name="record_schema",
        payload=record_schema_payload,
    )
    _validate_artifact(
        artifacts,
        logical_name="manifest_schema",
        payload=manifest_schema_payload,
    )

    train_payload = _read_profile_file(benchmark_root, "train")
    test_payload = _read_profile_file(benchmark_root, "test")
    train_records = tuple(
        iter_public_benchmark_jsonl(
            _BytesReader(train_payload),
            expected_split="train",
            limits=BenchmarkReadLimits(
                max_total_bytes=_PROFILE_FILES["train"][1],
                max_records=PROFILE_TRAIN_TASKS,
            ),
        )
    )
    test_records = tuple(
        iter_public_benchmark_jsonl(
            _BytesReader(test_payload),
            expected_split="test",
            limits=BenchmarkReadLimits(
                max_total_bytes=_PROFILE_FILES["test"][1],
                max_records=PROFILE_TEST_TASKS,
            ),
        )
    )
    if not all(isinstance(record, PublicTrainingRecord) for record in train_records):
        raise BenchmarkHarnessError("split_mismatch", "train file contains a non-train record")
    if not all(isinstance(record, PublicTestRecord) for record in test_records):
        raise BenchmarkHarnessError("split_mismatch", "test file contains a non-test record")
    typed_train = tuple(record for record in train_records if isinstance(record, PublicTrainingRecord))
    typed_test = tuple(record for record in test_records if isinstance(record, PublicTestRecord))

    _validate_artifact(
        artifacts,
        logical_name="train",
        payload=train_payload,
        rows=len(typed_train),
    )
    _validate_artifact(
        artifacts,
        logical_name="test",
        payload=test_payload,
        rows=len(typed_test),
    )
    if len(typed_train) != PROFILE_TRAIN_TASKS or len(typed_test) != PROFILE_TEST_TASKS:
        raise BenchmarkHarnessError(
            "task_count_mismatch", "public task counts do not match the fixed profile"
        )

    for record in typed_train:
        _validate_schema_instance(
            record_validator, record.to_dict(), name="public training record"
        )
    for record in typed_test:
        _validate_schema_instance(
            record_validator, record.to_dict(), name="public test record"
        )

    train_ids = {record.task.task_id for record in typed_train}
    test_ids = {record.task.task_id for record in typed_test}
    train_snapshots = {
        (record.task.repo_url.casefold(), record.task.commit) for record in typed_train
    }
    test_snapshots = {
        (record.task.repo_url.casefold(), record.task.commit) for record in typed_test
    }
    if train_ids.intersection(test_ids) or train_snapshots.intersection(test_snapshots):
        raise BenchmarkHarnessError(
            "cross_split_overlap", "train and test identities must be disjoint"
        )

    report_ids: set[str] = set()
    entry_ids: set[str] = set()
    advisory_count = 0
    entry_count = 0
    for record in typed_train:
        for advisory in record.gold.advisories:
            advisory_count += 1
            if advisory.report_id in report_ids:
                raise BenchmarkHarnessError(
                    "duplicate_report_id", "training split repeats an advisory ID"
                )
            report_ids.add(advisory.report_id)
            for entry in advisory.verified_entries:
                entry_count += 1
                entry_id = entry["entry_id"]
                if entry_id in entry_ids:
                    raise BenchmarkHarnessError(
                        "duplicate_entry_id", "training split repeats an Entry ID"
                    )
                entry_ids.add(entry_id)
    if advisory_count != PROFILE_TRAIN_ADVISORIES or entry_count != PROFILE_TRAIN_ENTRIES:
        raise BenchmarkHarnessError(
            "gold_count_mismatch",
            "public training advisory/Entry counts do not match the fixed profile",
        )

    summary = PublicBundleSummary(
        profile_id=PROFILE_ID,
        schema_version=PROFILE_SCHEMA_VERSION,
        source_revision=PROFILE_SOURCE_REVISION,
        manifest_sha256=PROFILE_MANIFEST_SHA256,
        train_tasks=len(typed_train),
        test_tasks=len(typed_test),
        train_advisories=advisory_count,
        train_entries=entry_count,
    )
    return _LoadedBundle(summary=summary, train=typed_train, test=typed_test)


def _load_test_records_without_gold(
    benchmark_root: str | os.PathLike[str],
) -> tuple[PublicTestRecord, ...]:
    """Load the pinned blind split without opening the public training file.

    The authenticated manifest fixes the test artifact and the two schemas.
    Keeping this reader separate is intentional: a blind projection sandbox
    does not need an evaluator or any training answers in its read surface.
    """

    manifest_payload = _read_profile_file(benchmark_root, "manifest")
    if _sha256(manifest_payload) != PROFILE_MANIFEST_SHA256:
        raise BenchmarkHarnessError(
            "manifest_digest_mismatch", "public manifest does not match the fixed profile"
        )
    manifest = _strict_json(manifest_payload)
    record_schema_payload = _read_profile_file(benchmark_root, "record_schema")
    manifest_schema_payload = _read_profile_file(benchmark_root, "manifest_schema")
    record_schema = _strict_json(record_schema_payload)
    manifest_schema = _strict_json(manifest_schema_payload)
    record_validator = _schema_validator(record_schema, name="benchmark record schema")
    manifest_validator = _schema_validator(manifest_schema, name="public manifest schema")
    _validate_schema_instance(manifest_validator, manifest, name="public manifest")
    if not isinstance(manifest, Mapping):
        raise BenchmarkHarnessError("invalid_manifest", "public manifest must be an object")
    source = manifest.get("source")
    build = manifest.get("build")
    if not isinstance(source, Mapping) or not isinstance(build, Mapping):
        raise BenchmarkHarnessError("invalid_manifest", "public manifest profile is invalid")
    if (
        manifest.get("schema_version") != PROFILE_SCHEMA_VERSION
        or source.get("revision") != PROFILE_SOURCE_REVISION
        or build.get("dataset_id") != PROFILE_ID
        or build.get("train_tasks") != PROFILE_TRAIN_TASKS
        or build.get("test_tasks") != PROFILE_TEST_TASKS
    ):
        raise BenchmarkHarnessError(
            "profile_mismatch", "public manifest does not match the fixed benchmark profile"
        )
    artifacts = _manifest_artifacts(manifest)
    _validate_artifact(
        artifacts, logical_name="record_schema", payload=record_schema_payload
    )
    _validate_artifact(
        artifacts, logical_name="manifest_schema", payload=manifest_schema_payload
    )
    test_payload = _read_profile_file(benchmark_root, "test")
    records = tuple(
        iter_public_benchmark_jsonl(
            _BytesReader(test_payload),
            expected_split="test",
            limits=BenchmarkReadLimits(
                max_total_bytes=_PROFILE_FILES["test"][1],
                max_records=PROFILE_TEST_TASKS,
            ),
        )
    )
    if (
        len(records) != PROFILE_TEST_TASKS
        or not all(isinstance(record, PublicTestRecord) for record in records)
    ):
        raise BenchmarkHarnessError(
            "task_count_mismatch", "public test tasks do not match the fixed profile"
        )
    typed = tuple(record for record in records if isinstance(record, PublicTestRecord))
    _validate_artifact(
        artifacts, logical_name="test", payload=test_payload, rows=len(typed)
    )
    for record in typed:
        _validate_schema_instance(
            record_validator, record.to_dict(), name="public test record"
        )
    return typed


class _BytesReader:
    """Minimal binary reader avoiding a second filesystem open."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._position = 0

    def readline(self, size: int = -1) -> bytes:
        if self._position >= len(self._payload):
            return b""
        end = self._payload.find(b"\n", self._position)
        end = len(self._payload) if end < 0 else end + 1
        if size >= 0:
            end = min(end, self._position + size)
        value = self._payload[self._position:end]
        self._position = end
        return value


def validate_public_bundle(
    benchmark_root: str | os.PathLike[str],
) -> PublicBundleSummary:
    """Validate the complete pinned public profile and return counts only."""

    return _load_and_validate_bundle(benchmark_root).summary


def load_answer_free_tasks(
    benchmark_root: str | os.PathLike[str],
    *,
    split: Literal["train", "test"],
) -> tuple[SnapshotTaskSpec, ...]:
    """Return immutable snapshot tasks without advisory or Entry gold."""

    if split not in {"train", "test"}:
        raise ValueError("split must be train or test")
    records: Sequence[PublicTrainingRecord | PublicTestRecord]
    if split == "train":
        records = _load_and_validate_bundle(benchmark_root).train
    else:
        records = _load_test_records_without_gold(benchmark_root)
    return tuple(record.snapshot_spec() for record in records)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _thaw_json(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _jsonl(
    values: Iterable[Mapping[str, Any]],
    *,
    max_bytes: int = MAX_TOTAL_OUTPUT_BYTES,
) -> bytes:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    payload = bytearray()
    for value in values:
        line = _canonical_json(dict(value)).encode("utf-8") + b"\n"
        if len(line) > MAX_FINDING_BYTES or len(payload) + len(line) > max_bytes:
            raise BenchmarkHarnessError(
                "output_limit_exceeded", "projected output exceeds its byte budget"
            )
        payload.extend(line)
    return bytes(payload)


def _path_relation(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((os.path.normcase(str(path)), os.path.normcase(str(root))))
    except ValueError:
        return False
    return common == os.path.normcase(str(root))


def _rename_directory_noreplace(
    source: Path,
    destination: Path,
    *,
    source_dir_fd: int | None = None,
    destination_dir_fd: int | None = None,
) -> None:
    """Publish a directory without replacing a concurrently-created target."""

    if os.name == "posix":
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            renameat2 = libc.renameat2
        except (AttributeError, OSError):
            renameat2 = None
        if renameat2 is not None:
            renameat2.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameat2.restype = ctypes.c_int
            source_fd = -100 if source_dir_fd is None else source_dir_fd
            destination_fd = -100 if destination_dir_fd is None else destination_dir_fd
            result = renameat2(
                source_fd,
                os.fsencode(source),
                destination_fd,
                os.fsencode(destination),
                1,  # RENAME_NOREPLACE
            )
            if result == 0:
                return
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise FileExistsError(str(destination))
            raise OSError(error_number, "atomic directory publication failed")
        # A check-then-rename fallback could replace an empty directory on
        # POSIX.  Unsupported platforms therefore fail closed.
        raise OSError(errno.ENOTSUP, "no atomic no-replace rename is available")
    if source_dir_fd is not None or destination_dir_fd is not None:
        raise OSError(errno.ENOTSUP, "relative directory rename is unavailable")
    # Windows rename is no-replace.
    try:
        os.lstat(destination)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(str(destination))
    os.rename(source, destination)


def _parent_chain_unchanged(
    checked_parent: Sequence[tuple[Path, tuple[int, int]]],
) -> None:
    for component, expected in checked_parent:
        current = _checked_lstat(component, directory=True)
        if (current.st_dev, current.st_ino) != expected:
            raise BenchmarkHarnessError(
                "output_parent_changed", "output parent changed during publication"
            )


def _random_staging_name(output_name: str) -> str:
    return f".{output_name}.{secrets.token_hex(16)}.staging"


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count < 1:
            raise OSError(errno.EIO, "short transaction write")
        written += count


def _cleanup_relative_staging(
    parent_descriptor: int,
    staging_descriptor: int,
    staging_name: str,
    staging_identity: tuple[int, int],
    file_names: Iterable[str],
) -> None:
    """Best-effort cleanup anchored to trusted descriptors.

    Any identity mismatch leaves the temporary directory behind.  Leaking a
    private staging directory is safer than deleting a concurrently replaced
    object.
    """

    try:
        current = os.stat(
            staging_name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (
            not stat.S_ISDIR(current.st_mode)
            or _is_reparse(current)
            or (current.st_dev, current.st_ino) != staging_identity
        ):
            return
        opened = os.fstat(staging_descriptor)
        if (opened.st_dev, opened.st_ino) != staging_identity:
            return
        for name in file_names:
            try:
                item = os.stat(name, dir_fd=staging_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(item.st_mode) or _is_reparse(item):
                return
            os.unlink(name, dir_fd=staging_descriptor)
        current = os.stat(
            staging_name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (current.st_dev, current.st_ino) != staging_identity:
            return
        os.rmdir(staging_name, dir_fd=parent_descriptor)
    except (OSError, NotImplementedError):
        return


def _cleanup_path_staging(
    staging: Path,
    staging_identity: tuple[int, int],
    checked_parent: Sequence[tuple[Path, tuple[int, int]]],
    file_names: Iterable[str],
) -> None:
    """Best-effort non-recursive cleanup for platforms without dirfd I/O."""

    try:
        _parent_chain_unchanged(checked_parent)
        current = _checked_lstat(staging, directory=True)
        if (current.st_dev, current.st_ino) != staging_identity:
            return
        for name in file_names:
            target = staging / name
            try:
                item = os.lstat(target)
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(item.st_mode)
                or stat.S_ISLNK(item.st_mode)
                or _is_reparse(item)
            ):
                return
            target.unlink()
        _parent_chain_unchanged(checked_parent)
        current = _checked_lstat(staging, directory=True)
        if (current.st_dev, current.st_ino) == staging_identity:
            staging.rmdir()
    except (BenchmarkHarnessError, FileNotFoundError, OSError):
        return


def _publish_directory(
    output_dir: str | os.PathLike[str],
    files: Mapping[str, bytes],
    *,
    protected_roots: Iterable[str | os.PathLike[str]] = (),
) -> None:
    output = Path(os.path.abspath(os.fspath(output_dir)))
    if not files or any(
        not isinstance(name, str)
        or not name
        or "/" in name
        or "\\" in name
        or name in {".", ".."}
        for name in files
    ):
        raise ValueError("transaction files must use simple non-empty names")
    if any(not isinstance(payload, bytes) for payload in files.values()):
        raise ValueError("transaction payloads must be bytes")
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise BenchmarkHarnessError(
            "unsafe_output", "output directory state is unavailable"
        ) from error
    else:
        raise BenchmarkHarnessError(
            "output_exists", "output directory already exists; overwrite is forbidden"
        )

    for raw_root in protected_roots:
        protected = Path(os.path.abspath(os.fspath(raw_root)))
        if _path_relation(output, protected) or _path_relation(protected, output):
            raise BenchmarkHarnessError(
                "protected_output",
                "output directory must not overlap protected inputs",
            )

    parent = output.parent
    checked_parent: list[tuple[Path, tuple[int, int]]] = []
    for component in _root_chain(parent):
        result = _checked_lstat(component, directory=True)
        checked_parent.append((component, (result.st_dev, result.st_ino)))

    total_bytes = sum(len(payload) for payload in files.values())
    if total_bytes > MAX_TOTAL_OUTPUT_BYTES:
        raise BenchmarkHarnessError(
            "output_limit_exceeded", "projected output exceeds its byte budget"
        )

    staging: Path | None = None
    staging_name: str | None = None
    staging_identity: tuple[int, int] | None = None
    parent_descriptor: int | None = None
    staging_descriptor: int | None = None
    renamed = False
    try:
        if os.name == "posix":
            parent_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            parent_descriptor = os.open(parent, parent_flags)
            opened_parent = os.fstat(parent_descriptor)
            expected_parent = checked_parent[-1][1]
            if (
                not stat.S_ISDIR(opened_parent.st_mode)
                or _is_reparse(opened_parent)
                or (opened_parent.st_dev, opened_parent.st_ino) != expected_parent
            ):
                raise BenchmarkHarnessError(
                    "output_parent_changed", "output parent changed during publication"
                )
            _parent_chain_unchanged(checked_parent)
            for _ in range(128):
                candidate = _random_staging_name(output.name)
                try:
                    os.mkdir(candidate, 0o700, dir_fd=parent_descriptor)
                except FileExistsError:
                    continue
                staging_name = candidate
                break
            if staging_name is None:
                raise OSError(errno.EEXIST, "could not allocate transaction directory")
            staging_flags = parent_flags
            staging_descriptor = os.open(
                staging_name, staging_flags, dir_fd=parent_descriptor
            )
            staging_state = os.fstat(staging_descriptor)
            if not stat.S_ISDIR(staging_state.st_mode) or _is_reparse(staging_state):
                raise BenchmarkHarnessError(
                    "output_transaction_failed", "transaction staging is unsafe"
                )
            staging_identity = (staging_state.st_dev, staging_state.st_ino)
            for name, payload in files.items():
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                descriptor = os.open(name, flags, 0o600, dir_fd=staging_descriptor)
                try:
                    _write_all(descriptor, payload)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            os.fsync(staging_descriptor)
            _parent_chain_unchanged(checked_parent)
            named_staging = os.stat(
                staging_name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            if (
                not stat.S_ISDIR(named_staging.st_mode)
                or _is_reparse(named_staging)
                or (named_staging.st_dev, named_staging.st_ino) != staging_identity
            ):
                raise BenchmarkHarnessError(
                    "output_staging_changed", "transaction staging changed before publication"
                )
            _rename_directory_noreplace(
                Path(staging_name),
                Path(output.name),
                source_dir_fd=parent_descriptor,
                destination_dir_fd=parent_descriptor,
            )
            renamed = True
            destination = os.stat(
                output.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            if (
                not stat.S_ISDIR(destination.st_mode)
                or _is_reparse(destination)
                or (destination.st_dev, destination.st_ino) != staging_identity
            ):
                raise BenchmarkHarnessError(
                    "output_publication_changed",
                    "published output does not match transaction staging",
                )
            _parent_chain_unchanged(checked_parent)
            os.fsync(parent_descriptor)
        else:
            for _ in range(128):
                candidate = parent / _random_staging_name(output.name)
                try:
                    candidate.mkdir(mode=0o700)
                except FileExistsError:
                    continue
                staging = candidate
                break
            if staging is None:
                raise OSError(errno.EEXIST, "could not allocate transaction directory")
            staging_state = _checked_lstat(staging, directory=True)
            staging_identity = (staging_state.st_dev, staging_state.st_ino)
            for name, payload in files.items():
                target = staging / name
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                descriptor = os.open(target, flags, 0o600)
                try:
                    _write_all(descriptor, payload)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            _parent_chain_unchanged(checked_parent)
            current_staging = _checked_lstat(staging, directory=True)
            if (current_staging.st_dev, current_staging.st_ino) != staging_identity:
                raise BenchmarkHarnessError(
                    "output_staging_changed", "transaction staging changed before publication"
                )
            _rename_directory_noreplace(staging, output)
            renamed = True
            destination = _checked_lstat(output, directory=True)
            if (destination.st_dev, destination.st_ino) != staging_identity:
                raise BenchmarkHarnessError(
                    "output_publication_changed",
                    "published output does not match transaction staging",
                )
            _parent_chain_unchanged(checked_parent)
    except FileExistsError as error:
        raise BenchmarkHarnessError(
            "output_exists", "output directory already exists; overwrite is forbidden"
        ) from error
    except BenchmarkHarnessError:
        raise
    except OSError as error:
        raise BenchmarkHarnessError(
            "output_transaction_failed", "output directory transaction failed"
        ) from error
    finally:
        if not renamed and staging_identity is not None:
            if (
                parent_descriptor is not None
                and staging_descriptor is not None
                and staging_name is not None
            ):
                _cleanup_relative_staging(
                    parent_descriptor,
                    staging_descriptor,
                    staging_name,
                    staging_identity,
                    files,
                )
            elif staging is not None:
                _cleanup_path_staging(
                    staging, staging_identity, checked_parent, files
                )
        if staging_descriptor is not None:
            os.close(staging_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def export_answer_free_tasks(
    benchmark_root: str | os.PathLike[str],
    *,
    split: Literal["train", "test"],
    output_dir: str | os.PathLike[str],
) -> TaskExportSummary:
    """Validate and transactionally publish answer-free snapshot tasks."""

    tasks = load_answer_free_tasks(benchmark_root, split=split)
    task_payload = _jsonl(task.to_dict() for task in tasks)
    summary = TaskExportSummary(
        split=split,
        task_count=len(tasks),
        tasks_sha256=_sha256(task_payload),
    )
    manifest = {
        "kind": "answer_free_task_export",
        "profile_id": PROFILE_ID,
        "schema_version": PROFILE_SCHEMA_VERSION,
        **summary.to_dict(),
    }
    _publish_directory(
        output_dir,
        {
            "manifest.json": (_canonical_json(manifest) + "\n").encode("utf-8"),
            "tasks.jsonl": task_payload,
        },
        protected_roots=(benchmark_root,),
    )
    return summary


def _positive_top_k(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_TOP_K:
        raise ValueError(f"top_k must be an integer from 1 to {MAX_TOP_K}")
    return value


def _finding_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(dict(value)).encode("utf-8")).hexdigest()


def project_verified_entries(
    task: SnapshotTaskSpec | EvaluationTaskSpec,
    entries: Iterable[Mapping[str, Any]],
    *,
    top_k: int = DEFAULT_TOP_K,
) -> ProjectedTask:
    """Project verified formal Entries to bounded, stable evaluator findings.

    Verification provenance remains the caller's responsibility until the
    replay reader exposes an attested Entry API.  This function nonetheless
    enforces the exact 15-field Entry schema and the trusted task snapshot.
    Duplicate semantic findings are emitted once, independent of input order.
    """

    if not isinstance(task, (SnapshotTaskSpec, EvaluationTaskSpec)):
        raise ValueError("task must be an answer-free snapshot specification")
    limit = _positive_top_k(top_k)
    try:
        iterator = iter(entries)
    except TypeError:
        raise ValueError("entries must be iterable") from None

    unique: dict[str, dict[str, Any]] = {}
    seen_entry_ids: set[str] = set()
    raw_count = 0
    raw_trace_nodes = 0
    for raw_count, entry in enumerate(iterator, 1):
        if raw_count > MAX_RAW_ENTRIES_PER_TASK:
            raise BenchmarkHarnessError(
                "raw_entry_limit_exceeded", "task supplies too many verified Entries"
            )
        # Only formal T2 candidates (integer verify == 0) may cross the
        # producer projection boundary.  Public training gold has verify == 1
        # and therefore cannot be replayed as if it were producer output.
        plain_entry = _thaw_json(entry)
        validation = _ENTRY_ADAPTER.validate(plain_entry, formal_t2=True)
        if not validation.valid:
            first = validation.issues[0]
            raise BenchmarkHarnessError(
                "invalid_formal_entry",
                f"verified Entry is invalid at {first.path}: {first.code}",
            )
        raw_trace_nodes += len(plain_entry["trace"])
        if raw_trace_nodes > MAX_TRACE_NODES_PER_TASK:
            raise BenchmarkHarnessError(
                "trace_node_limit_exceeded",
                "one task exceeds its aggregate trace-node budget",
            )
        if plain_entry["repo_url"] != task.repo_url or plain_entry["commit"] != task.commit:
            raise BenchmarkHarnessError(
                "entry_binding_mismatch", "verified Entry does not match its task snapshot"
            )
        entry_id = plain_entry["entry_id"]
        if entry_id in seen_entry_ids:
            raise BenchmarkHarnessError(
                "duplicate_entry_id", "verified task batch repeats an Entry ID"
            )
        seen_entry_ids.add(entry_id)

        projected = next(
            iter_evaluator_findings(task, (plain_entry,), max_findings=1)
        )
        if projected.get("trace") == []:
            projected.pop("trace")
        identity: dict[str, Any] = {
            "task_id": task.task_id,
            "repo_url": projected["repo_url"],
            "commit": projected["commit"],
            "entry_point": projected["entry_point"],
            "critical_operation": projected["critical_operation"],
        }
        semantic = dict(identity)
        if "trace" in projected:
            semantic["trace"] = projected["trace"]
        # Trace is ignored by the benchmark matcher, so it cannot distinguish
        # findings for deduplication or ID purposes.  When duplicate endpoints
        # carry different traces, retain the canonical-minimum representation
        # to keep the output independent of input order.
        digest = _finding_digest(identity)
        candidate = {
            "task_id": task.task_id,
            "finding_id": "VGF-" + digest[:32].upper(),
            "repo_url": task.repo_url,
            "commit": task.commit,
            "entry_point": semantic["entry_point"],
            "critical_operation": semantic["critical_operation"],
            **({"trace": semantic["trace"]} if "trace" in semantic else {}),
        }
        if len(_canonical_json(candidate).encode("utf-8")) + 1 > MAX_FINDING_BYTES:
            raise BenchmarkHarnessError(
                "finding_limit_exceeded", "one projected finding exceeds its byte budget"
            )
        previous = unique.get(digest)
        if previous is None or _canonical_json(candidate) < _canonical_json(previous):
            unique[digest] = candidate

    ordered = tuple(unique[digest] for digest in sorted(unique))
    if sum(len(_canonical_json(item).encode("utf-8")) + 1 for item in ordered) > MAX_TASK_FINDING_BYTES:
        raise BenchmarkHarnessError(
            "task_output_limit_exceeded",
            "one task's projected findings exceed their byte budget",
        )
    emitted = ordered[:limit]
    stats = ProjectionStats(
        raw_entries=raw_count,
        raw_trace_nodes=raw_trace_nodes,
        unique_findings=len(ordered),
        deduplicated_findings=raw_count - len(ordered),
        emitted_findings=len(emitted),
        truncated_findings=max(0, len(ordered) - len(emitted)),
    )
    return ProjectedTask(task_id=task.task_id, findings=emitted, stats=stats)


def project_verified_entry_batches(
    tasks: Sequence[SnapshotTaskSpec | EvaluationTaskSpec],
    entries_by_task: Mapping[str, Iterable[Mapping[str, Any]]],
    *,
    top_k: int = DEFAULT_TOP_K,
) -> tuple[ProjectedTask, ...]:
    """Project complete task-bound batches; absent tasks produce zero findings."""

    limit = _positive_top_k(top_k)
    if not isinstance(entries_by_task, Mapping):
        raise ValueError("entries_by_task must be a task_id mapping")
    try:
        task_snapshot = tuple(tasks)
    except TypeError:
        raise ValueError("tasks must be iterable") from None
    task_ids: set[str] = set()
    snapshots: set[tuple[str, str]] = set()
    for task in task_snapshot:
        if not isinstance(task, (SnapshotTaskSpec, EvaluationTaskSpec)):
            raise ValueError("tasks must contain answer-free snapshot specifications")
        if task.task_id in task_ids:
            raise BenchmarkHarnessError("duplicate_task_id", "task list repeats a task ID")
        snapshot = (task.repo_url.casefold(), task.commit)
        if snapshot in snapshots:
            raise BenchmarkHarnessError("duplicate_snapshot", "task list repeats a snapshot")
        task_ids.add(task.task_id)
        snapshots.add(snapshot)
    unknown = sorted(set(entries_by_task) - task_ids, key=str)
    if unknown:
        raise BenchmarkHarnessError(
            "unknown_task_batch", "verified Entry batches contain an unknown task ID"
        )
    projected = tuple(
        project_verified_entries(
            task, entries_by_task.get(task.task_id, ()), top_k=limit
        )
        for task in task_snapshot
    )
    if sum(item.stats.raw_trace_nodes for item in projected) > MAX_TRACE_NODES_PER_BATCH:
        raise BenchmarkHarnessError(
            "trace_node_limit_exceeded",
            "projected batch exceeds its aggregate trace-node budget",
        )
    return projected


def publish_projected_entries(
    tasks: Sequence[SnapshotTaskSpec | EvaluationTaskSpec],
    entries_by_task: Mapping[str, Iterable[Mapping[str, Any]]],
    *,
    split: Literal["train", "test"],
    output_dir: str | os.PathLike[str],
    top_k: int = DEFAULT_TOP_K,
    protected_roots: Iterable[str | os.PathLike[str]] = (),
) -> tuple[ProjectedTask, ...]:
    """Transactionally publish findings without loading any benchmark gold."""

    if split not in {"train", "test"}:
        raise ValueError("split must be train or test")
    try:
        task_snapshot = tuple(tasks)
    except TypeError:
        raise ValueError("tasks must be iterable") from None
    for task in task_snapshot:
        task_split = task.split if isinstance(task, SnapshotTaskSpec) else "test"
        if task_split != split:
            raise BenchmarkHarnessError("split_mismatch", "task does not match output split")
    projected = project_verified_entry_batches(
        task_snapshot, entries_by_task, top_k=top_k
    )
    findings = tuple(finding for result in projected for finding in result.findings)
    finding_payload = _jsonl(findings)
    task_results = tuple(
        {"task_id": result.task_id, **result.stats.to_dict()} for result in projected
    )
    task_result_payload = _jsonl(task_results)
    totals = {
        key: sum(getattr(result.stats, key) for result in projected)
        for key in (
            "raw_entries",
            "raw_trace_nodes",
            "unique_findings",
            "deduplicated_findings",
            "emitted_findings",
            "truncated_findings",
        )
    }
    manifest = {
        "findings_sha256": _sha256(finding_payload),
        "kind": "unattested_projected_findings",
        "schema_version": PROFILE_SCHEMA_VERSION,
        "split": split,
        "task_count": len(projected),
        "task_results_sha256": _sha256(task_result_payload),
        "top_k": top_k,
        **totals,
    }
    _publish_directory(
        output_dir,
        {
            "findings.jsonl": finding_payload,
            "manifest.json": (_canonical_json(manifest) + "\n").encode("utf-8"),
            "task_results.jsonl": task_result_payload,
        },
        protected_roots=protected_roots,
    )
    return projected


def _checked_input_path(
    raw_path: str | os.PathLike[str], *, directory: bool
) -> Path:
    try:
        path = Path(os.path.abspath(os.fspath(raw_path)))
    except (TypeError, ValueError, OSError):
        raise BenchmarkHarnessError(
            "invalid_path", "a benchmark projection path is invalid"
        ) from None
    target_parent = path if directory else path.parent
    for component in _root_chain(target_parent):
        _checked_lstat(component, directory=True)
    if not directory:
        _checked_lstat(path, directory=False)
    return path


def _preflight_projection_paths(
    benchmark_root: str | os.PathLike[str],
    artifact_root: str | os.PathLike[str],
    bundle_index: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
) -> tuple[Path, Path, Path, Path]:
    benchmark = _checked_input_path(benchmark_root, directory=True)
    artifacts = _checked_input_path(artifact_root, directory=True)
    index = _checked_input_path(bundle_index, directory=False)
    try:
        output = Path(os.path.abspath(os.fspath(output_dir)))
    except (TypeError, ValueError, OSError):
        raise BenchmarkHarnessError(
            "invalid_path", "a benchmark projection path is invalid"
        ) from None
    for component in _root_chain(output.parent):
        _checked_lstat(component, directory=True)
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise BenchmarkHarnessError(
            "unsafe_output", "output directory state is unavailable"
        ) from error
    else:
        raise BenchmarkHarnessError(
            "output_exists", "output directory already exists; overwrite is forbidden"
        )

    lexical = (benchmark, artifacts, index, output)
    try:
        resolved = (
            benchmark.resolve(strict=True),
            artifacts.resolve(strict=True),
            index.resolve(strict=True),
            output.parent.resolve(strict=True) / output.name,
        )
    except OSError as error:
        raise BenchmarkHarnessError(
            "path_changed", "a benchmark projection path changed during validation"
        ) from error
    for candidates in (lexical, resolved):
        for position, left in enumerate(candidates):
            for right in candidates[position + 1 :]:
                if _path_relation(left, right) or _path_relation(right, left):
                    raise BenchmarkHarnessError(
                        "path_overlap",
                        "benchmark, artifacts, index, and output paths must not overlap",
                    )
    return benchmark, artifacts, index, output


def _read_bounded_index_file(path: Path) -> bytes:
    checked: list[tuple[Path, tuple[int, int, int, int | None]]] = []
    try:
        for component in _root_chain(path.parent):
            result = _checked_lstat(component, directory=True)
            checked.append((component, _identity(result)))
        before = _checked_lstat(path, directory=False)
        checked.append((path, _identity(before)))
    except BenchmarkHarnessError as error:
        raise BenchmarkHarnessError(
            "unsafe_artifact_index", "artifact index path is unsafe"
        ) from error
    if before.st_size > MAX_ARTIFACT_INDEX_BYTES:
        raise BenchmarkHarnessError(
            "artifact_index_too_large", "artifact index exceeds its byte budget"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BenchmarkHarnessError(
            "artifact_index_unavailable", "artifact index is unavailable"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise BenchmarkHarnessError(
                "artifact_index_changed", "artifact index changed while opening"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_ARTIFACT_INDEX_BYTES + 1)
        finished = os.fstat(descriptor)
        if len(payload) > MAX_ARTIFACT_INDEX_BYTES:
            raise BenchmarkHarnessError(
                "artifact_index_too_large", "artifact index exceeds its byte budget"
            )
        if _identity(opened) != _identity(finished) or len(payload) != opened.st_size:
            raise BenchmarkHarnessError(
                "artifact_index_changed", "artifact index changed while reading"
            )
    finally:
        os.close(descriptor)
    try:
        for component, expected in checked:
            actual = _checked_lstat(component, directory=component != path)
            if _identity(actual) != expected:
                raise BenchmarkHarnessError(
                    "artifact_index_changed", "artifact index changed while reading"
                )
    except BenchmarkHarnessError:
        raise
    return payload


def load_artifact_bundle_index(
    bundle_index: str | os.PathLike[str],
    *,
    expected_sha256: str,
    split: Literal["train", "test"],
    tasks: Sequence[SnapshotTaskSpec],
) -> ArtifactBundleIndex:
    """Read one attested, bounded, exact-membership replay bundle index."""

    if not isinstance(expected_sha256, str) or not _SHA256_RE.fullmatch(
        expected_sha256
    ):
        raise BenchmarkHarnessError(
            "invalid_index_digest",
            "bundle index digest must be lower-case SHA-256",
        )
    if split not in {"train", "test"}:
        raise ValueError("split must be train or test")
    task_snapshot = tuple(tasks)
    task_ids = tuple(task.task_id for task in task_snapshot)
    if len(task_ids) != len(set(task_ids)):
        raise BenchmarkHarnessError("duplicate_task_id", "task list repeats a task ID")
    path = _checked_input_path(bundle_index, directory=False)
    payload = _read_bounded_index_file(path)
    if _sha256(payload) != expected_sha256:
        raise BenchmarkHarnessError(
            "artifact_index_digest_mismatch",
            "artifact index does not match its trusted digest",
        )
    value = _strict_json(payload)
    if not isinstance(value, dict) or set(value) != {
        "contract_version",
        "profile_id",
        "manifest_sha256",
        "split",
        "bundles",
    }:
        raise BenchmarkHarnessError(
            "invalid_artifact_index", "artifact index has an invalid root contract"
        )
    if (
        type(value["contract_version"]) is not int
        or value["contract_version"] != ARTIFACT_INDEX_CONTRACT_VERSION
        or value["profile_id"] != PROFILE_ID
        or value["manifest_sha256"] != PROFILE_MANIFEST_SHA256
        or value["split"] != split
    ):
        raise BenchmarkHarnessError(
            "artifact_index_profile_mismatch",
            "artifact index does not match the requested fixed profile",
        )
    raw_bundles = value["bundles"]
    if not isinstance(raw_bundles, list) or len(raw_bundles) > (
        PROFILE_TRAIN_TASKS + PROFILE_TEST_TASKS
    ):
        raise BenchmarkHarnessError(
            "invalid_artifact_index", "artifact index bundles are invalid"
        )
    parsed: list[ArtifactBundleDigest] = []
    seen_tasks: set[str] = set()
    seen_digests: set[str] = set()
    for item in raw_bundles:
        if not isinstance(item, dict) or set(item) != {"task_id", "dataset_sha256"}:
            raise BenchmarkHarnessError(
                "invalid_artifact_index", "artifact index bundle entry is invalid"
            )
        task_id = item["task_id"]
        digest = item["dataset_sha256"]
        if not isinstance(task_id, str) or not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise BenchmarkHarnessError(
                "invalid_artifact_index", "artifact index bundle entry is invalid"
            )
        if task_id in seen_tasks:
            raise BenchmarkHarnessError(
                "duplicate_index_task", "artifact index repeats a task ID"
            )
        if digest in seen_digests:
            raise BenchmarkHarnessError(
                "duplicate_dataset_digest", "artifact index repeats a dataset digest"
            )
        seen_tasks.add(task_id)
        seen_digests.add(digest)
        parsed.append(ArtifactBundleDigest(task_id=task_id, dataset_sha256=digest))
    if seen_tasks != set(task_ids):
        raise BenchmarkHarnessError(
            "artifact_index_membership_mismatch",
            "artifact index has missing or extra benchmark tasks",
        )
    return ArtifactBundleIndex(
        contract_version=ARTIFACT_INDEX_CONTRACT_VERSION,
        profile_id=PROFILE_ID,
        manifest_sha256=PROFILE_MANIFEST_SHA256,
        split=split,
        bundles=tuple(parsed),
    )


def _output_files(
    *,
    split: Literal["train", "test"],
    projected: Sequence[ProjectedTask],
    bundle_records: Sequence[Mapping[str, Any]],
    bundle_index_sha256: str,
    top_k: int,
    aggregate: TrainingAggregate | None,
) -> tuple[dict[str, bytes], str]:
    findings = tuple(
        finding for result in projected for finding in result.findings
    )
    finding_payload = _jsonl(findings)
    task_result_payload = _jsonl(bundle_records)
    files: dict[str, bytes] = {
        "findings.jsonl": finding_payload,
        "task_results.jsonl": task_result_payload,
    }
    if split == "train":
        if aggregate is None:
            raise ValueError("training projection requires an aggregate")
        files["aggregate.json"] = (
            _canonical_json(aggregate.to_dict()) + "\n"
        ).encode("utf-8")
    elif aggregate is not None:
        raise ValueError("test projection must not include an aggregate")

    totals = {
        key: sum(getattr(result.stats, key) for result in projected)
        for key in (
            "raw_entries",
            "raw_trace_nodes",
            "unique_findings",
            "deduplicated_findings",
            "emitted_findings",
            "truncated_findings",
        )
    }
    dataset_bindings = [
        {
            "dataset_sha256": record["dataset_sha256"],
            "task_id": record["task_id"],
        }
        for record in bundle_records
    ]
    root_totals = {
        key: sum(int(record[key]) for record in bundle_records)
        for key in (
            "root_task_count",
            "finalized_root_count",
            "manual_review_root_count",
            "failed_root_count",
        )
    }
    file_bindings = {
        name: {"bytes": len(payload), "sha256": _sha256(payload)}
        for name, payload in sorted(files.items())
    }
    manifest: dict[str, Any] = {
        "bundle_datasets": dataset_bindings,
        "bundle_datasets_sha256": _sha256(
            _canonical_json(dataset_bindings).encode("utf-8")
        ),
        "bundle_index_sha256": bundle_index_sha256,
        "contract_version": ARTIFACT_INDEX_CONTRACT_VERSION,
        "files": file_bindings,
        "kind": "verified_replay_benchmark_projection",
        "manifest_sha256": PROFILE_MANIFEST_SHA256,
        "profile_id": PROFILE_ID,
        "schema_version": PROFILE_SCHEMA_VERSION,
        "split": split,
        "task_count": len(projected),
        "top_k": top_k,
        **root_totals,
        **totals,
    }
    if split == "train":
        manifest["official_tolerance"] = OFFICIAL_TOLERANCE
    manifest_payload = (_canonical_json(manifest) + "\n").encode("utf-8")
    files["manifest.json"] = manifest_payload
    if sum(len(payload) for payload in files.values()) > MAX_TOTAL_OUTPUT_BYTES:
        raise BenchmarkHarnessError(
            "output_limit_exceeded", "projected output exceeds its byte budget"
        )
    return files, _sha256(manifest_payload)


def project_verified_replay_bundles(
    benchmark_root: str | os.PathLike[str],
    *,
    artifact_root: str | os.PathLike[str],
    bundle_index: str | os.PathLike[str],
    bundle_index_sha256: str,
    output_dir: str | os.PathLike[str],
    split: Literal["train", "test"],
    top_k: int = DEFAULT_TOP_K,
) -> ReplayProjectionSummary:
    """Verify every attested replay bundle, then project and publish once."""

    if split not in {"train", "test"}:
        raise ValueError("split must be train or test")
    limit = _positive_top_k(top_k)
    benchmark, artifacts, index_path, output = _preflight_projection_paths(
        benchmark_root, artifact_root, bundle_index, output_dir
    )
    tasks = load_answer_free_tasks(benchmark, split=split)
    index = load_artifact_bundle_index(
        index_path,
        expected_sha256=bundle_index_sha256,
        split=split,
        tasks=tasks,
    )
    indexed = {item.task_id: item.dataset_sha256 for item in index.bundles}
    artifact_state = _checked_lstat(artifacts, directory=True)
    artifact_identity = (artifact_state.st_dev, artifact_state.st_ino)
    replay_scan_paths = (benchmark, artifacts, index_path, output)
    projected: list[ProjectedTask] = []
    bundle_records: list[dict[str, Any]] = []
    projected_output_bytes = 0

    # Complete every replay read and projection before invoking the train-only
    # oracle or making the output directory visible.
    for task in tasks:
        current_root = _checked_lstat(artifacts, directory=True)
        if (current_root.st_dev, current_root.st_ino) != artifact_identity:
            raise BenchmarkHarnessError(
                "artifact_root_changed",
                "artifact root changed during replay verification",
            )
        dataset_sha256 = indexed[task.task_id]
        try:
            verified = read_verified_formal_entries(
                artifacts / task.task_id,
                expected_dataset_sha256=dataset_sha256,
                protected_paths=replay_scan_paths,
                limits=_BENCHMARK_REPLAY_LIMITS,
            )
        except (ReplayArtifactError, ValueError, OSError) as error:
            raise BenchmarkHarnessError(
                "replay_artifact_rejected",
                "a replay bundle failed complete verification",
            ) from error
        if not isinstance(verified, VerifiedFormalEntries):
            raise BenchmarkHarnessError(
                "replay_artifact_rejected", "replay reader returned an invalid result"
            )
        if verified.dataset_sha256 != dataset_sha256:
            raise BenchmarkHarnessError(
                "replay_digest_mismatch", "replay bundle digest does not match its index"
            )
        if verified.input_failure_count != 0:
            raise BenchmarkHarnessError(
                "incomplete_replay_bundle",
                "indexed replay bundles must not contain input failures",
            )
        if not verified.tasks:
            raise BenchmarkHarnessError(
                "empty_replay_bundle", "indexed replay bundle has no state roots"
            )
        if len(verified.tasks) > MAX_TOP_K:
            raise BenchmarkHarnessError(
                "replay_root_limit_exceeded",
                "indexed replay bundle has too many state roots",
            )
        statuses = {"finalized": 0, "manual_review": 0, "failed": 0}
        entries: list[Mapping[str, Any]] = []
        for verified_task in verified.tasks:
            if verified_task.status not in statuses:
                raise BenchmarkHarnessError(
                    "invalid_replay_status", "replay bundle has an invalid terminal status"
                )
            statuses[verified_task.status] += 1
            entries.extend(verified_task.entries)
        task_projection = project_verified_entries(task, entries, top_k=limit)
        task_finding_bytes = sum(
            len(_canonical_json(finding).encode("utf-8")) + 1
            for finding in task_projection.findings
        )
        bundle_record = {
            "dataset_sha256": dataset_sha256,
            "failed_root_count": statuses["failed"],
            "finalized_root_count": statuses["finalized"],
            "manual_review_root_count": statuses["manual_review"],
            "root_task_count": len(verified.tasks),
            "task_id": task.task_id,
            **task_projection.stats.to_dict(),
        }
        projected_output_bytes += task_finding_bytes
        projected_output_bytes += len(
            _canonical_json(bundle_record).encode("utf-8")
        ) + 1
        if projected_output_bytes > MAX_TOTAL_OUTPUT_BYTES:
            raise BenchmarkHarnessError(
                "output_limit_exceeded", "projected output exceeds its byte budget"
            )
        projected.append(task_projection)
        if (
            sum(item.stats.raw_trace_nodes for item in projected)
            > MAX_TRACE_NODES_PER_BATCH
        ):
            raise BenchmarkHarnessError(
                "trace_node_limit_exceeded",
                "projected batch exceeds its aggregate trace-node budget",
            )
        bundle_records.append(bundle_record)

    current_artifact_state = _checked_lstat(artifacts, directory=True)
    if (current_artifact_state.st_dev, current_artifact_state.st_ino) != artifact_identity:
        raise BenchmarkHarnessError(
            "artifact_root_changed", "artifact root changed during replay verification"
        )

    aggregate: TrainingAggregate | None = None
    if split == "train":
        aggregate = evaluate_training_aggregate(
            benchmark,
            (
                finding
                for task_projection in projected
                for finding in task_projection.findings
            ),
        )
    files, manifest_digest = _output_files(
        split=split,
        projected=projected,
        bundle_records=bundle_records,
        bundle_index_sha256=bundle_index_sha256,
        top_k=limit,
        aggregate=aggregate,
    )
    _publish_directory(
        output, files, protected_roots=(benchmark, artifacts, index_path)
    )
    return ReplayProjectionSummary(
        split=split,
        task_count=len(projected),
        finding_count=sum(len(item.findings) for item in projected),
        bundle_index_sha256=bundle_index_sha256,
        output_manifest_sha256=manifest_digest,
        aggregate=aggregate,
    )


def _line_span(value: Any) -> tuple[int, int] | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return (value, value) if value > 0 else None
    if not isinstance(value, str) or "-" not in value:
        return None
    left, separator, right = value.partition("-")
    if not separator or not left.isdigit() or not right.isdigit():
        return None
    start, end = int(left), int(right)
    return (start, end) if 0 < start <= end else None


def _location_matches(
    finding: Mapping[str, Any], gold: Mapping[str, Any], tolerance: int
) -> bool:
    if finding.get("file") != gold.get("file"):
        return False
    finding_span = _line_span(finding.get("line"))
    gold_span = _line_span(gold.get("line"))
    if finding_span is None or gold_span is None:
        return False
    finding_width = finding_span[1] - finding_span[0] + 1
    gold_width = gold_span[1] - gold_span[0] + 1
    if finding_width > gold_width + (2 * tolerance):
        return False
    if finding_span[1] < gold_span[0]:
        distance = gold_span[0] - finding_span[1]
    elif gold_span[1] < finding_span[0]:
        distance = finding_span[0] - gold_span[1]
    else:
        distance = 0
    return distance <= tolerance


def _validate_published_finding(
    finding: Any, tasks: Mapping[str, SnapshotTaskSpec]
) -> Mapping[str, Any]:
    if not isinstance(finding, Mapping):
        raise BenchmarkHarnessError("invalid_finding", "finding must be an object")
    required = {
        "task_id",
        "finding_id",
        "repo_url",
        "commit",
        "entry_point",
        "critical_operation",
    }
    optional = {"trace"}
    if not required.issubset(finding) or set(finding) - required - optional:
        raise BenchmarkHarnessError(
            "invalid_finding", "finding does not match the published boundary"
        )
    task = tasks.get(finding["task_id"])
    if task is None or finding["repo_url"] != task.repo_url or finding["commit"] != task.commit:
        raise BenchmarkHarnessError(
            "finding_binding_mismatch", "finding does not match a training task"
        )
    semantic = {
        "task_id": task.task_id,
        "repo_url": task.repo_url,
        "commit": task.commit,
        "entry_point": finding["entry_point"],
        "critical_operation": finding["critical_operation"],
        **({"trace": finding["trace"]} if "trace" in finding else {}),
    }
    checked = next(iter_evaluator_findings(task, (semantic,), max_findings=1))
    if checked.get("trace") == []:
        checked.pop("trace")
        semantic.pop("trace", None)
    canonical_semantic = {
        "task_id": task.task_id,
        "repo_url": task.repo_url,
        "commit": task.commit,
        "entry_point": checked["entry_point"],
        "critical_operation": checked["critical_operation"],
        **({"trace": checked["trace"]} if "trace" in checked else {}),
    }
    if _thaw_json(semantic) != canonical_semantic:
        raise BenchmarkHarnessError(
            "invalid_finding", "finding locations contain non-evaluator fields"
        )
    identity = {
        "task_id": task.task_id,
        "repo_url": task.repo_url,
        "commit": task.commit,
        "entry_point": checked["entry_point"],
        "critical_operation": checked["critical_operation"],
    }
    expected_id = "VGF-" + _finding_digest(identity)[:32].upper()
    if finding["finding_id"] != expected_id:
        raise BenchmarkHarnessError("finding_id_mismatch", "finding ID is not canonical")
    return finding


def evaluate_training_aggregate(
    benchmark_root: str | os.PathLike[str],
    findings: Iterable[Mapping[str, Any]],
) -> TrainingAggregate:
    """Evaluate already-projected training findings and return aggregate only."""

    loaded = _load_and_validate_bundle(benchmark_root)
    tasks = {record.task.task_id: record.snapshot_spec() for record in loaded.train}

    submitted: list[Mapping[str, Any]] = []
    seen_finding_ids: set[str] = set()
    per_task: dict[str, int] = {}
    for raw in findings:
        finding = _validate_published_finding(raw, tasks)
        finding_id = finding["finding_id"]
        if finding_id in seen_finding_ids:
            raise BenchmarkHarnessError("duplicate_finding", "findings repeat a finding ID")
        seen_finding_ids.add(finding_id)
        task_id = finding["task_id"]
        per_task[task_id] = per_task.get(task_id, 0) + 1
        if per_task[task_id] > MAX_TOP_K:
            raise BenchmarkHarnessError("finding_limit_exceeded", "task has too many findings")
        submitted.append(finding)

    gold_entries: list[tuple[str, Mapping[str, Any]]] = []
    for record in loaded.train:
        for advisory in record.gold.advisories:
            for entry in advisory.verified_entries:
                gold_entries.append((advisory.report_id, entry))

    matched_entry_ids: set[str] = set()
    covered_reports: set[str] = set()
    for finding in submitted:
        for report_id, entry in gold_entries:
            if entry["repo_url"] != finding["repo_url"] or entry["commit"] != finding["commit"]:
                continue
            if _location_matches(
                finding["entry_point"], entry["entry_point"], OFFICIAL_TOLERANCE
            ) and _location_matches(
                finding["critical_operation"],
                entry["critical_operation"],
                OFFICIAL_TOLERANCE,
            ):
                matched_entry_ids.add(entry["entry_id"])
                covered_reports.add(report_id)

    total_advisories = loaded.summary.train_advisories
    total_entries = loaded.summary.train_entries
    return TrainingAggregate(
        total_advisories=total_advisories,
        covered_advisories=len(covered_reports),
        advisory_recall=(len(covered_reports) / total_advisories),
        total_entries=total_entries,
        matched_entries=len(matched_entry_ids),
        entry_recall=(len(matched_entry_ids) / total_entries),
        submitted_findings=len(submitted),
    )


__all__ = [
    "ARTIFACT_INDEX_CONTRACT_VERSION",
    "ArtifactBundleDigest",
    "ArtifactBundleIndex",
    "BenchmarkHarnessError",
    "DEFAULT_TOP_K",
    "MAX_TOP_K",
    "PROFILE_MANIFEST_SHA256",
    "PROFILE_SOURCE_REVISION",
    "ProjectedTask",
    "ProjectionStats",
    "PublicBundleSummary",
    "ReplayProjectionSummary",
    "TaskExportSummary",
    "TrainingAggregate",
    "export_answer_free_tasks",
    "load_artifact_bundle_index",
    "load_answer_free_tasks",
    "project_verified_replay_bundles",
    "validate_public_bundle",
]
