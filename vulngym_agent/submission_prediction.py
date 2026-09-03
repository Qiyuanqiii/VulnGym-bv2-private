"""Verified export of terminal T2 candidates and their honest T1 reports.

The closed-loop replay intentionally publishes ``entries.jsonl`` only for
``finalized``/``correct`` outcomes.  A competition submission has a different
job: it must contain every complete prediction, while preserving T1's actual
three-state verdict.  This module provides that separate projection without
changing the internal acceptance rule.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import MappingProxyType
from typing import Any, Final
import uuid

from vulngym_agent.models import ValidationReport
from vulngym_agent.orchestrator.contracts import (
    ProductionOutcome,
    canonical_json,
    canonical_sha256,
)
from vulngym_agent.orchestrator.replay import (
    ReplayArtifactError,
    VerifiedSubmissionPredictions,
    _validation_report_from_dict,
    read_verified_submission_predictions,
)
from vulngym_agent.trusted_inputs import paths_overlap_v1


SUBMISSION_PREDICTION_CONTRACT_VERSION: Final[int] = 1
SUBMISSION_REVIEW_EVIDENCE_CONTRACT_VERSION: Final[int] = 1
SUBMISSION_PREDICTION_FILES: Final[tuple[str, ...]] = (
    "entries.jsonl",
    "validation.jsonl",
    "submission_manifest.json",
)
_DATA_FILES: Final[tuple[str, ...]] = SUBMISSION_PREDICTION_FILES[:2]
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_MAX_FILE_BYTES: Final[int] = 64 * 1024 * 1024
_MAX_LINE_BYTES: Final[int] = 1 * 1024 * 1024
_MAX_TASKS: Final[int] = 100_000


class SubmissionPredictionError(RuntimeError):
    """Stable failure at the prediction projection boundary."""

    def __init__(
        self, code: str, message: str, *, committed: bool = False
    ) -> None:
        self.code = code if isinstance(code, str) and code else "operation_failed"
        self.committed = committed is True
        super().__init__(message)


def _require_sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise SubmissionPredictionError(
            "invalid_digest", f"{name} must be a lower-case SHA-256 digest"
        )
    return value


def _require_count(value: Any, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= _MAX_TASKS
    ):
        raise SubmissionPredictionError(
            "invalid_count", f"{name} must be between 1 and {_MAX_TASKS}"
        )
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_plain(child) for child in value]
    return value


def _line(value: Mapping[str, Any]) -> bytes:
    return canonical_json(_plain(value)).encode("utf-8") + b"\n"


def _summary(payload: bytes) -> dict[str, Any]:
    return {
        "content_sha256": hashlib.sha256(payload).hexdigest(),
        "byte_count": len(payload),
        "line_count": payload.count(b"\n"),
    }


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    def freeze(item: Any) -> Any:
        if isinstance(item, Mapping):
            return MappingProxyType(
                {str(key): freeze(child) for key, child in item.items()}
            )
        if isinstance(item, list):
            return tuple(freeze(child) for child in item)
        if isinstance(item, tuple):
            return tuple(freeze(child) for child in item)
        return item

    result = freeze(value)
    assert isinstance(result, Mapping)
    return result


@dataclass(frozen=True, slots=True)
class SubmissionPredictionManifest:
    source_replay_dataset_sha256: str
    task_count: int
    status_counts: Mapping[str, int]
    verdict_counts: Mapping[str, int]
    files: Mapping[str, Mapping[str, Any]]
    tasks: tuple[Mapping[str, Any], ...]
    submission_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(
            self.source_replay_dataset_sha256, "source_replay_dataset_sha256"
        )
        _require_sha256(self.submission_sha256, "submission_sha256")
        _require_count(self.task_count, "task_count")
        if len(self.tasks) != self.task_count:
            raise ValueError("manifest task_count does not match tasks")
        object.__setattr__(
            self, "status_counts", MappingProxyType(dict(self.status_counts))
        )
        object.__setattr__(
            self, "verdict_counts", MappingProxyType(dict(self.verdict_counts))
        )
        object.__setattr__(
            self,
            "files",
            MappingProxyType(
                {
                    str(name): MappingProxyType(dict(value))
                    for name, value in self.files.items()
                }
            ),
        )
        object.__setattr__(
            self,
            "tasks",
            tuple(_freeze_mapping(task) for task in self.tasks),
        )

    def core_dict(self) -> dict[str, Any]:
        return {
            "contract_version": SUBMISSION_PREDICTION_CONTRACT_VERSION,
            "kind": "vulngym.submission-predictions.v1",
            "source_replay_dataset_sha256": self.source_replay_dataset_sha256,
            "task_count": self.task_count,
            "status_counts": dict(self.status_counts),
            "verdict_counts": dict(self.verdict_counts),
            "files": {
                name: dict(value) for name, value in self.files.items()
            },
            "tasks": [_plain(task) for task in self.tasks],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.core_dict(), "submission_sha256": self.submission_sha256}


@dataclass(frozen=True, slots=True)
class SubmissionPredictionBundle:
    manifest: SubmissionPredictionManifest
    entries: tuple[Mapping[str, Any], ...]
    validations: tuple[ValidationReport, ...]

    def __post_init__(self) -> None:
        entries = tuple(
            ProductionOutcome(candidate=entry).candidate for entry in self.entries
        )
        validations = tuple(self.validations)
        if any(not isinstance(item, ValidationReport) for item in validations):
            raise ValueError("validations must contain ValidationReport values")
        if len(entries) != len(validations) or len(entries) != self.manifest.task_count:
            raise ValueError("submission files do not match manifest task_count")
        object.__setattr__(self, "entries", entries)
        object.__setattr__(self, "validations", validations)


@dataclass(frozen=True, slots=True)
class _TrustedPathGuard:
    path: Path
    is_directory: bool
    directory_chain: tuple[
        tuple[Path, tuple[int, int, int, int]], ...
    ]
    object_identity: tuple[int, ...]


def _build_payloads(
    predictions: VerifiedSubmissionPredictions,
    *,
    expected_task_count: int,
) -> tuple[dict[str, bytes], SubmissionPredictionManifest]:
    if not isinstance(predictions, VerifiedSubmissionPredictions):
        raise SubmissionPredictionError(
            "invalid_predictions", "predictions contract is invalid"
        )
    expected = _require_count(expected_task_count, "expected_task_count")
    if predictions.input_failure_count:
        raise SubmissionPredictionError(
            "input_failures", "source replay contains input failures"
        )
    if len(predictions.tasks) != expected:
        raise SubmissionPredictionError(
            "task_count_mismatch", "source replay task count differs"
        )
    incomplete = [task.task_id for task in predictions.tasks if not task.complete]
    if incomplete:
        raise SubmissionPredictionError(
            "incomplete_predictions",
            "source replay has terminal tasks without a candidate/report pair",
        )

    entry_lines: list[bytes] = []
    validation_lines: list[bytes] = []
    task_bindings: list[dict[str, Any]] = []
    statuses: Counter[str] = Counter()
    verdicts: Counter[str] = Counter()
    for task in predictions.tasks:
        assert task.entry is not None
        assert task.validation is not None
        if task.status not in {"finalized", "manual_review"}:
            raise SubmissionPredictionError(
                "non_submittable_status",
                "complete predictions must end finalized or manual_review",
            )
        entry = ProductionOutcome(candidate=task.entry).candidate
        report = task.validation
        if entry["verify"] != 0:
            raise SubmissionPredictionError(
                "verify_not_zero", "prediction Entry verify must remain 0"
            )
        if (
            report.report_id != entry["report_id"]
            or report.entry_id != entry["entry_id"]
            or report.input_line != task.input_line
        ):
            raise SubmissionPredictionError(
                "identity_mismatch", "prediction Entry and validation differ"
            )
        entry_sha256 = canonical_sha256(entry)
        validation_sha256 = canonical_sha256(report)
        entry_lines.append(_line(entry))
        validation_lines.append(_line(report.to_dict()))
        statuses[task.status] += 1
        verdicts[report.verdict] += 1
        task_bindings.append(
            {
                "task_id": task.task_id,
                "input_line": task.input_line,
                "status": task.status,
                "verdict": report.verdict,
                "entry_id": entry["entry_id"],
                "report_id": entry["report_id"],
                "entry_sha256": entry_sha256,
                "validation_sha256": validation_sha256,
            }
        )
    entries_payload = b"".join(entry_lines)
    validations_payload = b"".join(validation_lines)
    payloads = {
        "entries.jsonl": entries_payload,
        "validation.jsonl": validations_payload,
    }
    files = {name: _summary(payload) for name, payload in payloads.items()}
    core = {
        "contract_version": SUBMISSION_PREDICTION_CONTRACT_VERSION,
        "kind": "vulngym.submission-predictions.v1",
        "source_replay_dataset_sha256": predictions.dataset_sha256,
        "task_count": expected,
        "status_counts": dict(sorted(statuses.items())),
        "verdict_counts": dict(sorted(verdicts.items())),
        "files": files,
        "tasks": task_bindings,
    }
    submission_sha256 = canonical_sha256(core)
    manifest = SubmissionPredictionManifest(
        source_replay_dataset_sha256=predictions.dataset_sha256,
        task_count=expected,
        status_counts=core["status_counts"],
        verdict_counts=core["verdict_counts"],
        files=files,
        tasks=tuple(task_bindings),
        submission_sha256=submission_sha256,
    )
    payloads["submission_manifest.json"] = _line(manifest.to_dict())
    return payloads, manifest


def _missing_category(value: str) -> str:
    text = value.casefold()
    if any(
        marker in text
        for marker in (
            "entry",
            "route",
            "reachab",
            "runtime",
            "call",
            "data flow",
            "data-flow",
        )
    ):
        return "entry_reachability"
    if any(marker in text for marker in ("critical", "operation", "guard", "sink")):
        return "operation_proof"
    if "trace" in text:
        return "trace_completeness"
    if any(marker in text for marker in ("title", "category", "cwe", "class")):
        return "classification"
    if any(marker in text for marker in ("advisory", "patch", "source", "evidence")):
        return "source_context"
    if any(
        marker in text
        for marker in ("schema", "report", "commit", "repo", "identifier", "verify")
    ):
        return "identity_or_schema"
    return "other"


def _count_missing_categories(values: Sequence[str]) -> dict[str, int]:
    return dict(sorted(Counter(_missing_category(item) for item in values).items()))


def _field_review_summary(field: Any) -> dict[str, Any]:
    suggested_fix = getattr(field, "suggested_fix", None)
    return {
        "status": field.status,
        "confidence": field.confidence,
        "evidence_sha256": hashlib.sha256(field.evidence.encode("utf-8")).hexdigest(),
        "evidence_ref_count": len(field.evidence_refs),
        "has_suggested_fix": suggested_fix is not None,
        "suggested_fix_sha256": (
            None if suggested_fix is None else canonical_sha256(suggested_fix)
        ),
    }


def _read_replay_sidecar(path: Path) -> bytes:
    try:
        before = os.lstat(path)
    except OSError:
        raise SubmissionPredictionError(
            "source_replay_rejected", "replay sidecar is unavailable"
        ) from None
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or before.st_nlink != 1
        or before.st_size > _MAX_FILE_BYTES
    ):
        raise SubmissionPredictionError(
            "source_replay_rejected", "replay sidecar is unsafe"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise SubmissionPredictionError(
            "source_replay_rejected", "replay sidecar could not be opened"
        ) from None
    try:
        opened = os.fstat(descriptor)
        if _file_state(opened) != _file_state(before):
            raise SubmissionPredictionError(
                "source_replay_rejected", "replay sidecar changed during open"
            )
        return _read_descriptor(descriptor, before)
    finally:
        os.close(descriptor)


def _review_deferred_index(source_replay: Path) -> dict[str, Mapping[str, Any]]:
    payload = _read_replay_sidecar(source_replay / "deferred.jsonl")
    records = _parse_lines(payload, "deferred.jsonl")
    deferred_by_task: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if record.get("kind") != "deferred":
            raise SubmissionPredictionError(
                "source_replay_rejected", "deferred evidence has invalid kind"
            )
        payload_value = record.get("payload")
        if not isinstance(payload_value, Mapping):
            raise SubmissionPredictionError(
                "source_replay_rejected", "deferred evidence has invalid payload"
            )
        core = payload_value.get("deferred")
        if not isinstance(core, Mapping):
            raise SubmissionPredictionError(
                "source_replay_rejected", "deferred evidence has invalid core"
            )
        task_id = core.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise SubmissionPredictionError(
                "source_replay_rejected", "deferred evidence has invalid task"
            )
        missing = core.get("missing_information")
        if not isinstance(missing, list) or any(
            not isinstance(item, str) for item in missing
        ):
            raise SubmissionPredictionError(
                "source_replay_rejected", "deferred evidence has invalid missing set"
            )
        for name in (
            "deferred_core_sha256",
            "deferred_sha256",
            "projection_sha256",
        ):
            _require_sha256(payload_value.get(name), name)
        deferred_by_task[task_id] = {
            "attempt": core.get("attempt"),
            "mode": core.get("mode"),
            "stage": core.get("stage"),
            "reason_code": core.get("reason_code"),
            "missing_information_count": len(missing),
            "missing_category_counts": _count_missing_categories(missing),
            "deferred_core_sha256": payload_value["deferred_core_sha256"],
            "deferred_sha256": payload_value["deferred_sha256"],
            "projection_sha256": payload_value["projection_sha256"],
        }
    return deferred_by_task


def build_submission_review_evidence(
    source_replay_dir: str | os.PathLike[str],
    *,
    expected_source_replay_dataset_sha256: str,
    expected_task_count: int,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
) -> Mapping[str, Any]:
    """Build a compact reviewer index for terminal prediction readback.

    The result is intentionally a digest-and-status index.  It does not copy
    field evidence text, source snippets, prompts, model responses, or local
    paths.  Reviewers can use it to see which records need human attention and
    then inspect the already-pinned replay artifacts if a full report is needed.
    """

    source_digest = _require_sha256(
        expected_source_replay_dataset_sha256,
        "expected_source_replay_dataset_sha256",
    )
    expected = _require_count(expected_task_count, "expected_task_count")
    source_replay = _absolute_path(source_replay_dir, "source replay directory")
    protected = _normalize_protected_paths(protected_paths)
    predictions = _read_source_predictions(
        source_replay,
        expected_source_replay_dataset_sha256=source_digest,
        protected=protected,
    )
    if len(predictions.tasks) != expected:
        raise SubmissionPredictionError(
            "task_count_mismatch", "source replay task count differs"
        )
    deferred_by_task = _review_deferred_index(source_replay)

    statuses: Counter[str] = Counter()
    verdicts: Counter[str] = Counter()
    field_statuses: dict[str, Counter[str]] = {}
    missing_categories: Counter[str] = Counter()
    complete_count = 0
    tasks: list[dict[str, Any]] = []
    for task in predictions.tasks:
        statuses[task.status] += 1
        deferred = dict(deferred_by_task.get(task.task_id, {}))
        task_missing_categories = Counter()
        report = task.validation
        entry = task.entry
        fields: dict[str, Any] = {}
        incorrect_fields: list[str] = []
        uncertain_fields: list[str] = []
        report_missing_count = 0
        report_missing_category_counts: dict[str, int] = {}
        if task.complete:
            assert entry is not None and report is not None
            complete_count += 1
            verdicts[report.verdict] += 1
            report_missing_count = len(report.missing_information)
            report_missing_category_counts = _count_missing_categories(
                report.missing_information
            )
            task_missing_categories.update(report_missing_category_counts)
            for name, field in sorted(report.fields.items()):
                fields[name] = _field_review_summary(field)
                field_statuses.setdefault(name, Counter())[field.status] += 1
                if field.status == "incorrect":
                    incorrect_fields.append(name)
                elif field.status == "uncertain":
                    uncertain_fields.append(name)
        task_missing_categories.update(deferred.get("missing_category_counts", {}))
        missing_categories.update(task_missing_categories)
        tasks.append(
            {
                "task_id": task.task_id,
                "input_line": task.input_line,
                "status": task.status,
                "complete": task.complete,
                "review_posture": (
                    "ready_for_submission"
                    if task.status == "finalized"
                    else (
                        "producer_deferred"
                        if not task.complete and deferred
                        else "t1_manual_review"
                    )
                ),
                "report_id": None if entry is None else entry["report_id"],
                "entry_id": None if entry is None else entry["entry_id"],
                "entry_sha256": None if entry is None else canonical_sha256(entry),
                "validation_sha256": (
                    None if report is None else canonical_sha256(report)
                ),
                "verdict": None if report is None else report.verdict,
                "field_status_counts": (
                    {}
                    if report is None
                    else dict(
                        sorted(
                            Counter(
                                field.status for field in report.fields.values()
                            ).items()
                        )
                    )
                ),
                "incorrect_fields": incorrect_fields,
                "uncertain_fields": uncertain_fields,
                "report_missing_information_count": report_missing_count,
                "report_missing_category_counts": report_missing_category_counts,
                "deferred": deferred or None,
                "combined_missing_category_counts": dict(
                    sorted(task_missing_categories.items())
                ),
                "fields": fields,
            }
        )

    field_status_counts = {
        name: dict(sorted(counter.items()))
        for name, counter in sorted(field_statuses.items())
    }
    core = {
        "contract_version": SUBMISSION_REVIEW_EVIDENCE_CONTRACT_VERSION,
        "kind": "vulngym.submission-review-evidence.v1",
        "source_replay_dataset_sha256": predictions.dataset_sha256,
        "task_count": expected,
        "complete_count": complete_count,
        "incomplete_count": expected - complete_count,
        "input_failure_count": predictions.input_failure_count,
        "status_counts": dict(sorted(statuses.items())),
        "verdict_counts": dict(sorted(verdicts.items())),
        "field_status_counts": field_status_counts,
        "missing_category_counts": dict(sorted(missing_categories.items())),
        "tasks": tasks,
    }
    return {**core, "review_evidence_sha256": canonical_sha256(core)}


def _is_reparse(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _absolute_path(value: str | os.PathLike[str], name: str) -> Path:
    try:
        result = Path(os.path.abspath(os.fspath(value)))
    except (OSError, TypeError, ValueError):
        raise SubmissionPredictionError(
            "invalid_argument", f"{name} is invalid"
        ) from None
    return result


def _directory_binding(value: os.stat_result) -> tuple[int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        getattr(value, "st_file_attributes", 0),
    )


def _directory_state(value: os.stat_result) -> tuple[int, ...]:
    return (
        *_directory_binding(value),
        value.st_nlink,
        getattr(value, "st_mtime_ns", 0),
    )


def _file_state(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", 0),
    )


def _cleanup_file_identity(value: os.stat_result) -> tuple[int, ...]:
    """Full identity used to guard one externally trusted regular file."""

    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        getattr(value, "st_mtime_ns", 0),
        getattr(value, "st_ctime_ns", 0),
        getattr(value, "st_file_attributes", 0),
    )


def _require_safe_directory(path: Path, *, private: bool) -> os.stat_result:
    try:
        value = os.lstat(path)
    except OSError:
        raise SubmissionPredictionError(
            "directory_unavailable", "required directory is unavailable"
        ) from None
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
        or (
            private
            and os.name == "posix"
            and value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        )
    ):
        raise SubmissionPredictionError(
            "unsafe_directory", "required directory is unsafe"
        )
    return value


def _root_chain(path: Path) -> tuple[Path, ...]:
    chain: list[Path] = []
    current = path
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    chain.reverse()
    return tuple(chain)


def _guard_directory_chain(
    path: Path,
) -> tuple[tuple[Path, tuple[int, int, int, int]], ...]:
    chain = _root_chain(path)
    result: list[tuple[Path, tuple[int, int, int, int]]] = []
    for index, component in enumerate(chain):
        value = _require_safe_directory(
            component, private=index == len(chain) - 1
        )
        result.append((component, _directory_binding(value)))
    return tuple(result)


def _assert_directory_chain(
    guard: tuple[tuple[Path, tuple[int, int, int, int]], ...]
) -> None:
    for index, (component, expected) in enumerate(guard):
        value = _require_safe_directory(
            component, private=index == len(guard) - 1
        )
        if _directory_binding(value) != expected:
            raise SubmissionPredictionError(
                "directory_changed", "required directory chain changed"
            )


def _validate_directory_stat(value: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
    ):
        raise SubmissionPredictionError(
            "unsafe_directory", "required directory is unsafe"
        )


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )


def _open_bound_directory(
    path: Path | str,
    expected: tuple[int, int, int, int],
    *,
    dir_fd: int | None = None,
) -> int:
    try:
        descriptor = os.open(path, _directory_flags(), dir_fd=dir_fd)
    except OSError:
        raise SubmissionPredictionError(
            "directory_unavailable", "required directory could not be opened"
        ) from None
    try:
        opened = os.fstat(descriptor)
        _validate_directory_stat(opened)
        if _directory_binding(opened) != expected:
            raise SubmissionPredictionError(
                "directory_changed", "required directory changed during open"
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_regular(value: os.stat_result) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
        or value.st_nlink != 1
        or (
            os.name == "posix"
            and value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        )
    ):
        raise SubmissionPredictionError(
            "unsafe_file", "submission file is unsafe"
        )
    if value.st_size < 1 or value.st_size > _MAX_FILE_BYTES:
        raise SubmissionPredictionError(
            "file_too_large", "submission file exceeds the byte limit"
        )


def _validate_trusted_regular(value: os.stat_result) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
        or value.st_nlink != 1
    ):
        raise SubmissionPredictionError(
            "path_check_failed", "trusted file is unsafe"
        )


def _read_descriptor(descriptor: int, before: os.stat_result) -> bytes:
    chunks: list[bytes] = []
    consumed = 0
    while True:
        chunk = os.read(
            descriptor, min(1024 * 1024, _MAX_FILE_BYTES + 1 - consumed)
        )
        if not chunk:
            break
        chunks.append(chunk)
        consumed += len(chunk)
        if consumed > _MAX_FILE_BYTES:
            raise SubmissionPredictionError(
                "file_too_large", "submission file exceeds the byte limit"
            )
    finished = os.fstat(descriptor)
    if _file_state(finished) != _file_state(before) or consumed != before.st_size:
        raise SubmissionPredictionError(
            "file_changed", "submission file changed while being read"
        )
    return b"".join(chunks)


def _read_regular_at(root_descriptor: int, name: str) -> bytes:
    try:
        before = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    except OSError:
        raise SubmissionPredictionError(
            "file_unavailable", "submission file is unavailable"
        ) from None
    _validate_regular(before)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=root_descriptor)
    except OSError:
        raise SubmissionPredictionError(
            "file_unavailable", "submission file could not be opened"
        ) from None
    try:
        opened = os.fstat(descriptor)
        _validate_regular(opened)
        if _file_state(opened) != _file_state(before):
            raise SubmissionPredictionError(
                "file_changed", "submission file changed during open"
            )
        payload = _read_descriptor(descriptor, opened)
    finally:
        os.close(descriptor)
    try:
        after = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
    except OSError:
        raise SubmissionPredictionError(
            "file_changed", "submission file changed after reading"
        ) from None
    if _file_state(after) != _file_state(before):
        raise SubmissionPredictionError(
            "file_changed", "submission file changed after reading"
        )
    return payload


def _read_regular_path(path: Path) -> bytes:
    try:
        before = os.lstat(path)
    except OSError:
        raise SubmissionPredictionError(
            "file_unavailable", "submission file is unavailable"
        ) from None
    _validate_regular(before)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise SubmissionPredictionError(
            "file_unavailable", "submission file could not be opened"
        ) from None
    try:
        opened = os.fstat(descriptor)
        _validate_regular(opened)
        if _file_state(opened) != _file_state(before):
            raise SubmissionPredictionError(
                "file_changed", "submission file changed during open"
            )
        payload = _read_descriptor(descriptor, opened)
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError:
        raise SubmissionPredictionError(
            "file_changed", "submission file changed after reading"
        ) from None
    if _file_state(after) != _file_state(before):
        raise SubmissionPredictionError(
            "file_changed", "submission file changed after reading"
        )
    return payload


def _read_payloads_from_descriptor(
    root_descriptor: int,
    expected_root: tuple[int, int, int, int],
) -> dict[str, bytes]:
    before = os.fstat(root_descriptor)
    _validate_directory_stat(before)
    if _directory_binding(before) != expected_root:
        raise SubmissionPredictionError(
            "directory_changed", "submission directory binding differs"
        )
    try:
        names = set(os.listdir(root_descriptor))
    except OSError:
        raise SubmissionPredictionError(
            "directory_unavailable", "submission directory cannot be scanned"
        ) from None
    if names != set(SUBMISSION_PREDICTION_FILES):
        raise SubmissionPredictionError(
            "file_set_mismatch", "submission directory has missing or extra files"
        )
    payloads = {
        name: _read_regular_at(root_descriptor, name)
        for name in SUBMISSION_PREDICTION_FILES
    }
    try:
        names_after = set(os.listdir(root_descriptor))
        after = os.fstat(root_descriptor)
    except OSError:
        raise SubmissionPredictionError(
            "directory_changed", "submission directory changed while being read"
        ) from None
    if names_after != names or _directory_state(after) != _directory_state(before):
        raise SubmissionPredictionError(
            "directory_changed", "submission directory changed while being read"
        )
    return payloads


def _read_payloads_from_path(
    root: Path,
    expected_root: tuple[int, int, int, int],
) -> dict[str, bytes]:
    before = _require_safe_directory(root, private=True)
    if _directory_binding(before) != expected_root:
        raise SubmissionPredictionError(
            "directory_changed", "submission directory binding differs"
        )
    try:
        names = {item.name for item in os.scandir(root)}
    except OSError:
        raise SubmissionPredictionError(
            "directory_unavailable", "submission directory cannot be scanned"
        ) from None
    if names != set(SUBMISSION_PREDICTION_FILES):
        raise SubmissionPredictionError(
            "file_set_mismatch", "submission directory has missing or extra files"
        )
    payloads = {
        name: _read_regular_path(root / name)
        for name in SUBMISSION_PREDICTION_FILES
    }
    try:
        names_after = {item.name for item in os.scandir(root)}
    except OSError:
        raise SubmissionPredictionError(
            "directory_changed", "submission directory changed while being read"
        ) from None
    after = _require_safe_directory(root, private=True)
    if names_after != names or _directory_state(after) != _directory_state(before):
        raise SubmissionPredictionError(
            "directory_changed", "submission directory changed while being read"
        )
    return payloads


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SubmissionPredictionError(
                "duplicate_key", "submission JSON contains a duplicate key"
            )
        result[key] = value
    return result


def _parse_lines(payload: bytes, filename: str) -> tuple[dict[str, Any], ...]:
    if payload and not payload.endswith(b"\n"):
        raise SubmissionPredictionError(
            "noncanonical_json", f"{filename} lacks its final LF"
        )
    values: list[dict[str, Any]] = []
    for raw in payload.splitlines(keepends=True):
        if len(raw) > _MAX_LINE_BYTES or raw.endswith(b"\r\n"):
            raise SubmissionPredictionError(
                "noncanonical_json", f"{filename} has an invalid line"
            )
        try:
            value = json.loads(
                raw[:-1].decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SubmissionPredictionError(
                "invalid_json", f"{filename} contains invalid JSON"
            ) from None
        if not isinstance(value, dict) or _line(value) != raw:
            raise SubmissionPredictionError(
                "noncanonical_json", f"{filename} is not canonical JSON"
            )
        values.append(value)
        if len(values) > _MAX_TASKS:
            raise SubmissionPredictionError(
                "task_limit", "submission exceeds the task limit"
            )
    return tuple(values)


def _parse_submission_payloads(
    payloads: Mapping[str, bytes],
    *,
    source_digest: str,
    expected: int,
    expected_submission_sha256: str | None = None,
) -> SubmissionPredictionBundle:
    _require_sha256(source_digest, "source_digest")
    _require_count(expected, "expected")
    entries_raw = _parse_lines(payloads["entries.jsonl"], "entries.jsonl")
    validations_raw = _parse_lines(
        payloads["validation.jsonl"], "validation.jsonl"
    )
    manifest_lines = _parse_lines(
        payloads["submission_manifest.json"], "submission_manifest.json"
    )
    if len(manifest_lines) != 1:
        raise SubmissionPredictionError(
            "manifest_invalid", "submission manifest must contain one object"
        )
    raw_manifest = manifest_lines[0]
    expected_manifest_keys = {
        "contract_version",
        "kind",
        "source_replay_dataset_sha256",
        "task_count",
        "status_counts",
        "verdict_counts",
        "files",
        "tasks",
        "submission_sha256",
    }
    if set(raw_manifest) != expected_manifest_keys:
        raise SubmissionPredictionError(
            "manifest_invalid", "submission manifest fields differ"
        )
    if (
        raw_manifest["contract_version"] != SUBMISSION_PREDICTION_CONTRACT_VERSION
        or raw_manifest["kind"] != "vulngym.submission-predictions.v1"
        or raw_manifest["source_replay_dataset_sha256"] != source_digest
        or raw_manifest["task_count"] != expected
    ):
        raise SubmissionPredictionError(
            "manifest_mismatch", "submission manifest binding differs"
        )
    files = {
        name: _summary(payloads[name])
        for name in _DATA_FILES
    }
    if raw_manifest["files"] != files:
        raise SubmissionPredictionError(
            "file_digest_mismatch", "submission file summaries differ"
        )
    if len(entries_raw) != expected or len(validations_raw) != expected:
        raise SubmissionPredictionError(
            "task_count_mismatch", "submission row count differs"
        )
    tasks_raw = raw_manifest["tasks"]
    if not isinstance(tasks_raw, list) or len(tasks_raw) != expected:
        raise SubmissionPredictionError(
            "manifest_invalid", "manifest tasks are invalid"
        )
    entries: list[Mapping[str, Any]] = []
    validations: list[ValidationReport] = []
    statuses: Counter[str] = Counter()
    verdicts: Counter[str] = Counter()
    seen_task_ids: set[str] = set()
    seen_entry_ids: set[str] = set()
    previous_line = 0
    task_keys = {
        "task_id",
        "input_line",
        "status",
        "verdict",
        "entry_id",
        "report_id",
        "entry_sha256",
        "validation_sha256",
    }
    for entry_value, report_value, binding in zip(
        entries_raw, validations_raw, tasks_raw
    ):
        if not isinstance(binding, dict) or set(binding) != task_keys:
            raise SubmissionPredictionError(
                "manifest_invalid", "manifest task binding is invalid"
            )
        try:
            entry = ProductionOutcome(candidate=entry_value).candidate
            report = _validation_report_from_dict(report_value)
        except (TypeError, ValueError):
            raise SubmissionPredictionError(
                "schema_invalid", "submission Entry or validation is invalid"
            ) from None
        input_line = binding["input_line"]
        task_id = binding["task_id"]
        status = binding["status"]
        if (
            not isinstance(task_id, str)
            or not task_id
            or task_id in seen_task_ids
            or isinstance(input_line, bool)
            or not isinstance(input_line, int)
            or input_line <= previous_line
            or status not in {"finalized", "manual_review"}
        ):
            raise SubmissionPredictionError(
                "manifest_invalid", "manifest task identity is invalid"
            )
        previous_line = input_line
        seen_task_ids.add(task_id)
        if entry["entry_id"] in seen_entry_ids or entry["verify"] != 0:
            raise SubmissionPredictionError(
                "entry_invalid", "submission Entry ID or verify is invalid"
            )
        seen_entry_ids.add(entry["entry_id"])
        if (
            binding["entry_id"] != entry["entry_id"]
            or binding["report_id"] != entry["report_id"]
            or binding["verdict"] != report.verdict
            or binding["entry_sha256"] != canonical_sha256(entry)
            or binding["validation_sha256"] != canonical_sha256(report)
            or report.entry_id != entry["entry_id"]
            or report.report_id != entry["report_id"]
            or report.input_line != input_line
            or (status == "finalized" and report.verdict != "correct")
        ):
            raise SubmissionPredictionError(
                "identity_mismatch", "submission task binding differs"
            )
        statuses[status] += 1
        verdicts[report.verdict] += 1
        entries.append(entry)
        validations.append(report)
    if (
        raw_manifest["status_counts"] != dict(sorted(statuses.items()))
        or raw_manifest["verdict_counts"] != dict(sorted(verdicts.items()))
    ):
        raise SubmissionPredictionError(
            "count_mismatch", "submission status/verdict counts differ"
        )
    core = {
        key: raw_manifest[key]
        for key in expected_manifest_keys - {"submission_sha256"}
    }
    submission_sha256 = canonical_sha256(core)
    if raw_manifest["submission_sha256"] != submission_sha256:
        raise SubmissionPredictionError(
            "manifest_digest_mismatch", "submission manifest digest differs"
        )
    if (
        expected_submission_sha256 is not None
        and submission_sha256 != expected_submission_sha256
    ):
        raise SubmissionPredictionError(
            "submission_pin_mismatch", "submission digest does not match its pin"
        )
    manifest = SubmissionPredictionManifest(
        source_replay_dataset_sha256=source_digest,
        task_count=expected,
        status_counts=raw_manifest["status_counts"],
        verdict_counts=raw_manifest["verdict_counts"],
        files=files,
        tasks=tuple(tasks_raw),
        submission_sha256=submission_sha256,
    )
    return SubmissionPredictionBundle(
        manifest=manifest,
        entries=tuple(entries),
        validations=tuple(validations),
    )


def read_submission_predictions(
    directory: str | os.PathLike[str],
    *,
    expected_source_replay_dataset_sha256: str,
    expected_task_count: int,
    expected_submission_sha256: str | None = None,
) -> SubmissionPredictionBundle:
    """Verify submission integrity against explicit digest pins.

    This reader deliberately does not authenticate that the submission was
    derived from a replay.  Formal source verification is provided by
    :func:`verify_submission_predictions`, which re-reads the pinned replay
    and compares every task binding.
    """

    source_digest = _require_sha256(
        expected_source_replay_dataset_sha256,
        "expected_source_replay_dataset_sha256",
    )
    expected = _require_count(expected_task_count, "expected_task_count")
    if expected_submission_sha256 is not None:
        _require_sha256(expected_submission_sha256, "expected_submission_sha256")
    root = _absolute_path(directory, "submission directory")
    root_guard = _guard_directory_chain(root)
    root_identity = root_guard[-1][1]
    if os.name == "posix":
        root_descriptor = _open_bound_directory(root, root_identity)
        try:
            payloads = _read_payloads_from_descriptor(
                root_descriptor, root_identity
            )
        finally:
            os.close(root_descriptor)
    else:
        payloads = _read_payloads_from_path(root, root_identity)
    _assert_directory_chain(root_guard)
    bundle = _parse_submission_payloads(
        payloads,
        source_digest=source_digest,
        expected=expected,
        expected_submission_sha256=expected_submission_sha256,
    )
    if _directory_binding(_require_safe_directory(root, private=True)) != root_identity:
        raise SubmissionPredictionError(
            "directory_changed", "submission directory changed during readback"
        )
    return bundle


def _write_regular(
    path: Path | str,
    payload: bytes,
    *,
    dir_fd: int | None = None,
) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags, 0o600, dir_fd=dir_fd)
    failure: BaseException | None = None
    handle_state: tuple[int, ...] | None = None
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
        created = os.fstat(descriptor)
        _validate_regular(created)
        handle_state = _file_state(created)
    except BaseException as error:
        failure = error
    try:
        os.close(descriptor)
    except BaseException as error:
        if failure is None:
            failure = error
    if failure is not None:
        raise failure
    if handle_state is None:
        raise SubmissionPredictionError(
            "publication_failed", "created file identity was not recorded"
        )
    try:
        named = (
            os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
            if dir_fd is not None
            else os.lstat(path)
        )
    except OSError:
        raise SubmissionPredictionError(
            "file_changed", "created submission file is unavailable"
        ) from None
    _validate_regular(named)
    if _file_state(named) != handle_state:
        raise SubmissionPredictionError(
            "file_changed", "created submission file identity changed"
        )


def _fsync_directory(
    *, path: Path | None = None, descriptor: int | None = None
) -> None:
    if os.name != "posix":
        return
    if descriptor is not None:
        os.fsync(descriptor)
        return
    if path is None:
        raise ValueError("directory path or descriptor is required")
    opened = os.open(path, _directory_flags())
    try:
        os.fsync(opened)
    finally:
        os.close(opened)


def _rename_noreplace(
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
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise FileExistsError(str(destination))
        raise OSError(number, "atomic no-replace rename failed")
    if source_dir_fd is not None or destination_dir_fd is not None:
        raise OSError(errno.ENOTSUP, "relative directory rename unavailable")
    try:
        os.lstat(destination)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(str(destination))
    os.rename(source, destination)


def _named_directory_identity(path: Path) -> tuple[int, int, int, int] | None:
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise SubmissionPredictionError(
            "publication_uncertain",
            "publication identity is unavailable",
            committed=True,
        ) from None
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
    ):
        return None
    return _directory_binding(value)


def _named_directory_identity_at(
    parent_descriptor: int, name: str
) -> tuple[int, int, int, int] | None:
    try:
        value = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise SubmissionPredictionError(
            "publication_uncertain",
            "publication identity is unavailable",
            committed=True,
        ) from None
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or _is_reparse(value)
    ):
        return None
    return _directory_binding(value)


def _path_exists(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        raise SubmissionPredictionError(
            "output_unavailable", "submission output state is unavailable"
        ) from None
    return True


def _name_exists_at(parent_descriptor: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        raise SubmissionPredictionError(
            "output_unavailable", "submission output state is unavailable"
        ) from None
    return True


def _close_directory_descriptors(
    descriptors: Sequence[int | None],
    *,
    committed: bool,
    preserve_active_failure: bool,
) -> None:
    failure: BaseException | None = None
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is None or preserve_active_failure:
        return
    if committed:
        raise SubmissionPredictionError(
            "publication_uncertain",
            "published submission directory handle could not be closed",
            committed=True,
        ) from None
    if isinstance(failure, KeyboardInterrupt):
        raise failure
    raise SubmissionPredictionError(
        "publication_failed",
        "submission directory handle could not be closed",
    ) from None


def _protected_path_kind(path: Path) -> bool:
    try:
        value = os.lstat(path)
    except OSError:
        raise SubmissionPredictionError(
            "path_check_failed", "protected path could not be classified"
        ) from None
    if stat.S_ISLNK(value.st_mode) or _is_reparse(value):
        raise SubmissionPredictionError(
            "path_check_failed", "protected path could not be classified"
        )
    return stat.S_ISDIR(value.st_mode)


def _normalize_protected_paths(
    protected_paths: Sequence[str | os.PathLike[str]],
) -> tuple[Path, ...]:
    return tuple(
        _absolute_path(path, "protected path") for path in protected_paths
    )


def _capture_trusted_path_guard(
    path: Path, *, require_directory: bool
) -> _TrustedPathGuard:
    try:
        value = os.lstat(path)
    except OSError:
        raise SubmissionPredictionError(
            "path_check_failed", "trusted path is unavailable"
        ) from None
    if stat.S_ISLNK(value.st_mode) or _is_reparse(value):
        raise SubmissionPredictionError(
            "path_check_failed", "trusted path is unsafe"
        )
    is_directory = stat.S_ISDIR(value.st_mode)
    if require_directory and not is_directory:
        raise SubmissionPredictionError(
            "path_check_failed", "source replay must be a directory"
        )
    if is_directory:
        chain = _guard_directory_chain(path)
        current = _require_safe_directory(path, private=True)
        identity = _directory_state(current)
    else:
        _validate_trusted_regular(value)
        chain = _guard_directory_chain(path.parent)
        identity = _cleanup_file_identity(value)
    return _TrustedPathGuard(
        path=path,
        is_directory=is_directory,
        directory_chain=chain,
        object_identity=identity,
    )


def _capture_trusted_path_guards(
    source_replay: Path, protected: tuple[Path, ...]
) -> tuple[_TrustedPathGuard, ...]:
    return (
        _capture_trusted_path_guard(source_replay, require_directory=True),
        *(
            _capture_trusted_path_guard(path, require_directory=False)
            for path in protected
        ),
    )


def _assert_trusted_path_guards(
    guards: tuple[_TrustedPathGuard, ...]
) -> None:
    for guard in guards:
        _assert_directory_chain(guard.directory_chain)
        try:
            value = os.lstat(guard.path)
        except OSError:
            raise SubmissionPredictionError(
                "trusted_path_changed", "trusted path changed"
            ) from None
        if stat.S_ISLNK(value.st_mode) or _is_reparse(value):
            raise SubmissionPredictionError(
                "trusted_path_changed", "trusted path changed"
            )
        if guard.is_directory:
            _validate_directory_stat(value)
            observed = _directory_state(value)
        else:
            _validate_trusted_regular(value)
            observed = _cleanup_file_identity(value)
        if observed != guard.object_identity:
            raise SubmissionPredictionError(
                "trusted_path_changed", "trusted path identity changed"
            )


def _inode_identity(value: Sequence[int]) -> tuple[int, int]:
    return int(value[0]), int(value[1])


def _assert_semantic_path_disjoint(
    submission_chain: tuple[
        tuple[Path, tuple[int, int, int, int]], ...
    ],
    trusted_guards: tuple[_TrustedPathGuard, ...],
    *,
    submission_exists: bool,
) -> None:
    submission_ancestors = {
        _inode_identity(identity) for _, identity in submission_chain
    }
    for guard in trusted_guards:
        if (
            guard.is_directory
            and _inode_identity(guard.object_identity)
            in submission_ancestors
        ):
            raise SubmissionPredictionError(
                "path_overlap",
                "submission is contained by a trusted directory object",
            )
    if not submission_exists:
        return
    submission_root = _inode_identity(submission_chain[-1][1])
    for guard in trusted_guards:
        trusted_ancestors = {
            _inode_identity(identity)
            for _, identity in guard.directory_chain
        }
        if submission_root in trusted_ancestors:
            raise SubmissionPredictionError(
                "path_overlap",
                "submission contains a trusted path object",
            )


def _assert_no_path_overlap(
    submission: Path,
    source_replay: Path,
    protected: tuple[Path, ...],
    *,
    submission_exists: bool,
) -> None:
    targets = ((source_replay, True),) + tuple(
        (path, _protected_path_kind(path)) for path in protected
    )
    for path, is_directory in targets:
        try:
            overlap = paths_overlap_v1(
                submission,
                path,
                left_exists=submission_exists,
                right_directory=is_directory,
            )
        except Exception:
            raise SubmissionPredictionError(
                "path_check_failed", "protected path could not be classified"
            ) from None
        if overlap:
            raise SubmissionPredictionError(
                "path_overlap", "submission and trusted inputs overlap"
            )


def _read_source_predictions(
    source_replay: Path,
    *,
    expected_source_replay_dataset_sha256: str,
    protected: tuple[Path, ...],
) -> VerifiedSubmissionPredictions:
    try:
        return read_verified_submission_predictions(
            source_replay,
            expected_dataset_sha256=expected_source_replay_dataset_sha256,
            protected_paths=(source_replay, *protected),
        )
    except (ReplayArtifactError, OSError, TypeError, ValueError):
        raise SubmissionPredictionError(
            "source_replay_rejected", "source replay could not be verified"
        ) from None


def _assert_bundle_matches_source(
    bundle: SubmissionPredictionBundle,
    predictions: VerifiedSubmissionPredictions,
    *,
    expected_task_count: int,
) -> None:
    _, expected_manifest = _build_payloads(
        predictions, expected_task_count=expected_task_count
    )
    if bundle.manifest.to_dict() != expected_manifest.to_dict():
        raise SubmissionPredictionError(
            "source_binding_mismatch",
            "submission manifest differs from the pinned source replay",
        )
    for binding, entry, report, source in zip(
        bundle.manifest.tasks,
        bundle.entries,
        bundle.validations,
        predictions.tasks,
        strict=True,
    ):
        if (
            not source.complete
            or source.entry is None
            or source.validation is None
            or binding["task_id"] != source.task_id
            or binding["input_line"] != source.input_line
            or binding["status"] != source.status
            or canonical_sha256(entry) != canonical_sha256(source.entry)
            or canonical_sha256(report) != canonical_sha256(source.validation)
        ):
            raise SubmissionPredictionError(
                "source_binding_mismatch",
                "submission task differs from the pinned source replay",
            )


def verify_submission_predictions(
    submission_dir: str | os.PathLike[str],
    source_replay_dir: str | os.PathLike[str],
    *,
    expected_source_replay_dataset_sha256: str,
    expected_task_count: int,
    expected_submission_sha256: str,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
) -> SubmissionPredictionBundle:
    """Formally verify a submission by re-reading its pinned source replay."""

    source_digest = _require_sha256(
        expected_source_replay_dataset_sha256,
        "expected_source_replay_dataset_sha256",
    )
    expected = _require_count(expected_task_count, "expected_task_count")
    submission_digest = _require_sha256(
        expected_submission_sha256, "expected_submission_sha256"
    )
    submission = _absolute_path(submission_dir, "submission directory")
    source_replay = _absolute_path(source_replay_dir, "source replay directory")
    protected = _normalize_protected_paths(protected_paths)
    _assert_no_path_overlap(
        submission,
        source_replay,
        protected,
        submission_exists=True,
    )
    trusted_guards = _capture_trusted_path_guards(source_replay, protected)
    submission_guard = _guard_directory_chain(submission)
    _assert_semantic_path_disjoint(
        submission_guard, trusted_guards, submission_exists=True
    )
    predictions = _read_source_predictions(
        source_replay,
        expected_source_replay_dataset_sha256=source_digest,
        protected=protected,
    )
    _assert_trusted_path_guards(trusted_guards)
    bundle = read_submission_predictions(
        submission,
        expected_source_replay_dataset_sha256=source_digest,
        expected_task_count=expected,
        expected_submission_sha256=submission_digest,
    )
    _assert_bundle_matches_source(
        bundle, predictions, expected_task_count=expected
    )
    _assert_trusted_path_guards(trusted_guards)
    _assert_directory_chain(submission_guard)
    _assert_semantic_path_disjoint(
        submission_guard, trusted_guards, submission_exists=True
    )
    return bundle


def _publish_payloads(
    output: Path,
    payloads: Mapping[str, bytes],
    expected_manifest: SubmissionPredictionManifest,
    predictions: VerifiedSubmissionPredictions,
    *,
    parent_guard: tuple[
        tuple[Path, tuple[int, int, int, int]], ...
    ],
    trusted_guards: tuple[_TrustedPathGuard, ...],
) -> SubmissionPredictionManifest:
    parent = output.parent
    if output == parent:
        raise SubmissionPredictionError(
            "invalid_argument", "submission output cannot be a filesystem root"
        )
    _assert_directory_chain(parent_guard)
    _assert_trusted_path_guards(trusted_guards)
    _assert_semantic_path_disjoint(
        parent_guard, trusted_guards, submission_exists=False
    )
    if _path_exists(output):
        raise SubmissionPredictionError(
            "output_exists", "submission output already exists"
        )
    staging = parent / f".submission-predictions-{uuid.uuid4().hex}"
    parent_descriptor: int | None = None
    staging_descriptor: int | None = None
    output_descriptor: int | None = None
    staging_identity: tuple[int, int, int, int] | None = None
    committed = False
    try:
        if os.name == "posix":
            parent_descriptor = _open_bound_directory(
                parent, parent_guard[-1][1]
            )
            if _name_exists_at(parent_descriptor, output.name):
                raise SubmissionPredictionError(
                    "output_exists", "submission output already exists"
                )
            os.mkdir(staging.name, 0o700, dir_fd=parent_descriptor)
            created = os.stat(
                staging.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            _validate_directory_stat(created)
            staging_identity = _directory_binding(created)
            staging_descriptor = _open_bound_directory(
                staging.name,
                staging_identity,
                dir_fd=parent_descriptor,
            )
            for name in SUBMISSION_PREDICTION_FILES:
                _write_regular(name, payloads[name], dir_fd=staging_descriptor)
            _fsync_directory(descriptor=staging_descriptor)
            before_payloads = _read_payloads_from_descriptor(
                staging_descriptor, staging_identity
            )
        else:
            os.mkdir(staging, 0o700)
            created = _require_safe_directory(staging, private=True)
            staging_identity = _directory_binding(created)
            for name in SUBMISSION_PREDICTION_FILES:
                _write_regular(staging / name, payloads[name])
            before_payloads = _read_payloads_from_path(
                staging, staging_identity
            )
        before = _parse_submission_payloads(
            before_payloads,
            source_digest=expected_manifest.source_replay_dataset_sha256,
            expected=expected_manifest.task_count,
            expected_submission_sha256=expected_manifest.submission_sha256,
        )
        _assert_bundle_matches_source(
            before,
            predictions,
            expected_task_count=expected_manifest.task_count,
        )
        _assert_directory_chain(parent_guard)
        _assert_trusted_path_guards(trusted_guards)
        _assert_semantic_path_disjoint(
            parent_guard, trusted_guards, submission_exists=False
        )
        observed_staging = (
            _named_directory_identity_at(parent_descriptor, staging.name)
            if parent_descriptor is not None
            else _named_directory_identity(staging)
        )
        if observed_staging != staging_identity:
            raise SubmissionPredictionError(
                "staging_changed", "submission staging directory changed"
            )
        try:
            if parent_descriptor is not None:
                _rename_noreplace(
                    Path(staging.name),
                    Path(output.name),
                    source_dir_fd=parent_descriptor,
                    destination_dir_fd=parent_descriptor,
                )
            else:
                _rename_noreplace(staging, output)
            committed = True
        except BaseException as error:
            try:
                _assert_directory_chain(parent_guard)
                staging_after = (
                    _named_directory_identity_at(parent_descriptor, staging.name)
                    if parent_descriptor is not None
                    else _named_directory_identity(staging)
                )
                output_after = (
                    _named_directory_identity_at(parent_descriptor, output.name)
                    if parent_descriptor is not None
                    else _named_directory_identity(output)
                )
            except BaseException:
                raise SubmissionPredictionError(
                    "publication_uncertain",
                    "submission publication state could not be classified",
                    committed=True,
                ) from None
            if staging_after == staging_identity and output_after != staging_identity:
                if isinstance(error, FileExistsError):
                    raise SubmissionPredictionError(
                        "output_exists", "submission output was created concurrently"
                    ) from None
                raise error
            if staging_after is None and output_after == staging_identity:
                committed = True
            else:
                raise SubmissionPredictionError(
                    "publication_uncertain",
                    "submission publication state could not be classified",
                    committed=True,
                ) from None
        if parent_descriptor is not None:
            _fsync_directory(descriptor=parent_descriptor)
        else:
            _fsync_directory(path=parent)
        _assert_directory_chain(parent_guard)
        published_identity = (
            _named_directory_identity_at(parent_descriptor, output.name)
            if parent_descriptor is not None
            else _named_directory_identity(output)
        )
        if published_identity != staging_identity:
            raise SubmissionPredictionError(
                "publication_uncertain",
                "published submission identity changed",
                committed=True,
            )
        if parent_descriptor is not None:
            output_descriptor = _open_bound_directory(
                output.name,
                staging_identity,
                dir_fd=parent_descriptor,
            )
            after_payloads = _read_payloads_from_descriptor(
                output_descriptor, staging_identity
            )
        else:
            after_payloads = _read_payloads_from_path(output, staging_identity)
        after = _parse_submission_payloads(
            after_payloads,
            source_digest=expected_manifest.source_replay_dataset_sha256,
            expected=expected_manifest.task_count,
            expected_submission_sha256=expected_manifest.submission_sha256,
        )
        _assert_bundle_matches_source(
            after,
            predictions,
            expected_task_count=expected_manifest.task_count,
        )
        if after.manifest.to_dict() != before.manifest.to_dict():
            raise SubmissionPredictionError(
                "publication_uncertain",
                "published submission changed during readback",
                committed=True,
            )
        _assert_directory_chain(parent_guard)
        final_identity = (
            _named_directory_identity_at(parent_descriptor, output.name)
            if parent_descriptor is not None
            else _named_directory_identity(output)
        )
        if final_identity != staging_identity:
            raise SubmissionPredictionError(
                "publication_uncertain",
                "published submission identity changed after readback",
                committed=True,
            )
        return after.manifest
    except SubmissionPredictionError as error:
        if committed and not error.committed:
            raise SubmissionPredictionError(
                "publication_uncertain",
                "published submission could not be confirmed",
                committed=True,
            ) from None
        raise
    except KeyboardInterrupt:
        if committed:
            raise SubmissionPredictionError(
                "publication_uncertain",
                "published submission could not be confirmed",
                committed=True,
            ) from None
        raise
    except Exception:
        if committed:
            raise SubmissionPredictionError(
                "publication_uncertain",
                "published submission could not be confirmed",
                committed=True,
            ) from None
        raise SubmissionPredictionError(
            "publication_failed", "submission publication failed"
        ) from None
    except BaseException:
        if committed:
            raise SubmissionPredictionError(
                "publication_uncertain",
                "published submission could not be confirmed",
                committed=True,
            ) from None
        raise
    finally:
        # A populated staging tree is intentionally retained on every failure.
        # Name-based cleanup cannot prove that a same-user replacement did not
        # win between the final identity check and unlink.
        _close_directory_descriptors(
            (output_descriptor, staging_descriptor, parent_descriptor),
            committed=committed,
            preserve_active_failure=sys.exc_info()[0] is not None,
        )


def write_submission_predictions(
    output_dir: str | os.PathLike[str],
    source_replay_dir: str | os.PathLike[str],
    *,
    expected_source_replay_dataset_sha256: str,
    expected_task_count: int,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
) -> SubmissionPredictionManifest:
    """Re-read a pinned replay and atomically publish its submission view.

    A caller-provided projection object is intentionally not accepted: the
    replay directory plus a separately trusted digest are the source of truth.
    """

    source_digest = _require_sha256(
        expected_source_replay_dataset_sha256,
        "expected_source_replay_dataset_sha256",
    )
    expected = _require_count(expected_task_count, "expected_task_count")
    output = _absolute_path(output_dir, "submission output directory")
    source_replay = _absolute_path(source_replay_dir, "source replay directory")
    protected = _normalize_protected_paths(protected_paths)
    _assert_no_path_overlap(
        output,
        source_replay,
        protected,
        submission_exists=False,
    )
    parent_guard = _guard_directory_chain(output.parent)
    trusted_guards = _capture_trusted_path_guards(source_replay, protected)
    _assert_semantic_path_disjoint(
        parent_guard, trusted_guards, submission_exists=False
    )
    predictions = _read_source_predictions(
        source_replay,
        expected_source_replay_dataset_sha256=source_digest,
        protected=protected,
    )
    _assert_trusted_path_guards(trusted_guards)
    _assert_directory_chain(parent_guard)
    _assert_semantic_path_disjoint(
        parent_guard, trusted_guards, submission_exists=False
    )
    payloads, expected_manifest = _build_payloads(
        predictions, expected_task_count=expected
    )
    return _publish_payloads(
        output,
        payloads,
        expected_manifest,
        predictions,
        parent_guard=parent_guard,
        trusted_guards=trusted_guards,
    )


__all__ = [
    "SUBMISSION_PREDICTION_CONTRACT_VERSION",
    "SUBMISSION_PREDICTION_FILES",
    "SUBMISSION_REVIEW_EVIDENCE_CONTRACT_VERSION",
    "SubmissionPredictionBundle",
    "SubmissionPredictionError",
    "SubmissionPredictionManifest",
    "build_submission_review_evidence",
    "read_submission_predictions",
    "verify_submission_predictions",
    "write_submission_predictions",
]
