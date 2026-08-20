"""Strict public benchmark contracts for the VulnGym 50/20 split.

This module deliberately does not adapt benchmark tasks into orchestrator
``RunTask`` objects.  A public test task identifies only an immutable source
snapshot; the existing T2 contract additionally requires advisory and entry
anchors plus an evidence package.  Inventing those values would either leak
answers or silently change a blind-discovery benchmark into an anchored task.

Training gold is parsed for offline calibration and evaluator use.  It never
participates in :class:`EvaluationTaskSpec` and the finding projection emits
only the fields consumed by ``examples/evaluate.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Any, BinaryIO, Iterable, Iterator, Literal, Mapping, TypeAlias

from vulngym_agent.adapters import SchemaAdapter


SCHEMA_VERSION = "1.0.0"
INSTRUCTION_ID = "vulngym-whitebox-locate-v1"
ORIGIN = "GitHub Advisory Database (reviewed)"

DEFAULT_MAX_LINE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_RECORDS = 10_000
MAX_FINDINGS_PER_TASK = 4_096

_HARD_MAX_LINE_BYTES = 64 * 1024 * 1024
_HARD_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
_HARD_MAX_RECORDS = 1_000_000
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 250_000
_MAX_TRACE_NODES = 256

_TASK_ID_RE = re.compile(r"^VG-(TRAIN|TEST)-[0-9A-F]{20}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REPORT_ID_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")
_ENTRY_ID_RE = re.compile(r"^entry-[0-9]{5}$")
_REPO_URL_RE = re.compile(
    r"^https://github\.com/"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"
)
_ADVISORY_URL_RE = re.compile(
    r"^https://github\.com/advisories/"
    r"(GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4})/?$"
)
_LINE_RANGE_RE = re.compile(r"^([1-9][0-9]*)-([1-9][0-9]*)$")

_TASK_KEYS = frozenset(
    {"task_id", "repo_url", "commit", "split", "instruction_id"}
)
_TRAIN_RECORD_KEYS = frozenset({"schema_version", "kind", "task", "gold"})
_TEST_RECORD_KEYS = frozenset({"schema_version", "kind", "task"})
_GOLD_KEYS = frozenset({"advisories"})
_ADVISORY_KEYS = frozenset(
    {
        "commit",
        "origin",
        "project",
        "repo_url",
        "report_id",
        "source_link",
        "verified_entries",
        "vuln_category_l1",
        "vuln_category_l2",
        "vuln_ids",
        "vuln_title",
    }
)

_ENTRY_ADVISORY_FIELDS = (
    "commit",
    "origin",
    "project",
    "repo_url",
    "report_id",
    "source_link",
    "vuln_category_l1",
    "vuln_category_l2",
    "vuln_ids",
)

_SCHEMA_ADAPTER = SchemaAdapter()


class BenchmarkContractError(ValueError):
    """A deterministic, path-free public benchmark contract failure."""

    def __init__(
        self, code: str, message: str, *, input_line: int | None = None
    ) -> None:
        if not isinstance(code, str) or not code:
            raise ValueError("error code must be a non-empty string")
        self.code = code
        self.input_line = input_line
        prefix = f"input line {input_line}: " if input_line is not None else ""
        super().__init__(f"{prefix}{message}")


def _positive_limit(name: str, value: Any, hard_limit: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > hard_limit
    ):
        raise ValueError(f"{name} must be an integer from 1 to {hard_limit}")
    return value


@dataclass(frozen=True, slots=True)
class BenchmarkReadLimits:
    """Resource limits for fail-fast public JSONL parsing."""

    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_records: int = DEFAULT_MAX_RECORDS

    def __post_init__(self) -> None:
        _positive_limit(
            "max_line_bytes", self.max_line_bytes, _HARD_MAX_LINE_BYTES
        )
        _positive_limit(
            "max_total_bytes", self.max_total_bytes, _HARD_MAX_TOTAL_BYTES
        )
        _positive_limit("max_records", self.max_records, _HARD_MAX_RECORDS)


def _strict_object(
    value: Any, *, keys: frozenset[str], name: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkContractError("invalid_type", f"{name} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        extra = sorted(actual - keys, key=str)
        raise BenchmarkContractError(
            "invalid_keys",
            f"{name} keys differ; missing={missing}, extra={extra}",
        )
    return value


def _string(value: Any, *, name: str, nonempty: bool = False) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        qualifier = "non-empty " if nonempty else ""
        raise BenchmarkContractError(
            "invalid_type", f"{name} must be a {qualifier}string"
        )
    return value


def _string_tuple(
    value: Any, *, name: str, unique: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise BenchmarkContractError("invalid_type", f"{name} must be an array")
    result = tuple(_string(item, name=f"{name} item") for item in value)
    if unique and len(set(result)) != len(result):
        raise BenchmarkContractError(
            "duplicate_value", f"{name} items must be unique"
        )
    return result


def _freeze_json(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_JSON_DEPTH:
        raise BenchmarkContractError(
            "json_too_deep", f"JSON exceeds depth {_MAX_JSON_DEPTH}"
        )
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise BenchmarkContractError(
                "invalid_json_number", "JSON numbers must be finite"
            )
        return value
    if isinstance(value, Mapping):
        return MappingProxyType(
            {
                key: _freeze_json(child, depth=depth + 1)
                for key, child in value.items()
            }
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child, depth=depth + 1) for child in value)
    raise BenchmarkContractError(
        "invalid_json_type", f"unsupported JSON type {type(value).__name__}"
    )


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


def _validate_json_shape(value: Any) -> None:
    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise BenchmarkContractError(
                "json_too_large", f"JSON exceeds {_MAX_JSON_NODES} nodes"
            )
        if depth > _MAX_JSON_DEPTH:
            raise BenchmarkContractError(
                "json_too_deep", f"JSON exceeds depth {_MAX_JSON_DEPTH}"
            )
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise BenchmarkContractError(
                    "invalid_unicode", "JSON contains a Unicode surrogate"
                )
            return
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise BenchmarkContractError(
                    "invalid_json_number", "JSON numbers must be finite"
                )
            return
        if isinstance(item, Mapping):
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
            return
        if isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
            return
        raise BenchmarkContractError(
            "invalid_json_type", f"unsupported JSON type {type(item).__name__}"
        )

    visit(value, 0)


def _reject_constant(value: str) -> None:
    raise BenchmarkContractError(
        "invalid_json_number", f"JSON constant {value} is not permitted"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkContractError(
                "duplicate_json_key", "JSON object contains a duplicate key"
            )
        result[key] = value
    return result


def _parse_json_line(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise BenchmarkContractError(
            "invalid_utf8", "JSONL input must be valid UTF-8"
        ) from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except BenchmarkContractError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise BenchmarkContractError("invalid_json", "line is not strict JSON") from None
    _validate_json_shape(value)
    return value


@dataclass(frozen=True, slots=True)
class BenchmarkTask:
    """The immutable public task identity shared by train and test records."""

    task_id: str
    repo_url: str
    commit: str
    split: Literal["train", "test"]
    instruction_id: str = INSTRUCTION_ID

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not _TASK_ID_RE.fullmatch(
            self.task_id
        ):
            raise BenchmarkContractError(
                "invalid_task_id", "task_id has an invalid format"
            )
        expected_prefix = "VG-TRAIN-" if self.split == "train" else "VG-TEST-"
        if self.split not in {"train", "test"} or not self.task_id.startswith(
            expected_prefix
        ):
            raise BenchmarkContractError(
                "split_mismatch", "task_id prefix does not match split"
            )
        if (
            not isinstance(self.repo_url, str)
            or not _REPO_URL_RE.fullmatch(self.repo_url)
            or self.repo_url.casefold().endswith(".git")
        ):
            raise BenchmarkContractError(
                "invalid_repo_url",
                "repo_url must be a canonical https://github.com/owner/repo URL",
            )
        if not isinstance(self.commit, str) or not _COMMIT_RE.fullmatch(self.commit):
            raise BenchmarkContractError(
                "invalid_commit", "commit must be 40 lower-case hex characters"
            )
        if self.instruction_id != INSTRUCTION_ID:
            raise BenchmarkContractError(
                "invalid_instruction", f"instruction_id must be {INSTRUCTION_ID}"
            )

    @classmethod
    def from_dict(cls, value: Any) -> "BenchmarkTask":
        task = _strict_object(value, keys=_TASK_KEYS, name="task")
        return cls(
            task_id=task["task_id"],
            repo_url=task["repo_url"],
            commit=task["commit"],
            split=task["split"],
            instruction_id=task["instruction_id"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "instruction_id": self.instruction_id,
            "repo_url": self.repo_url,
            "split": self.split,
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class EvaluationTaskSpec:
    """Answer-free blind-discovery specification for one public test task."""

    task_id: str
    repo_url: str
    commit: str
    instruction_id: str = INSTRUCTION_ID

    def __post_init__(self) -> None:
        # Reuse the complete public identity validation without storing split.
        BenchmarkTask(
            task_id=self.task_id,
            repo_url=self.repo_url,
            commit=self.commit,
            split="test",
            instruction_id=self.instruction_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "instruction_id": self.instruction_id,
            "repo_url": self.repo_url,
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class SnapshotTaskSpec:
    """Answer-free snapshot input usable for train calibration or blind test."""

    task_id: str
    repo_url: str
    commit: str
    split: Literal["train", "test"]
    instruction_id: str = INSTRUCTION_ID

    def __post_init__(self) -> None:
        BenchmarkTask(
            task_id=self.task_id,
            repo_url=self.repo_url,
            commit=self.commit,
            split=self.split,
            instruction_id=self.instruction_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "instruction_id": self.instruction_id,
            "repo_url": self.repo_url,
            "split": self.split,
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class TrainingAdvisory:
    """One immutable, public training advisory and its verified entries."""

    commit: str
    origin: str
    project: str
    repo_url: str
    report_id: str
    source_link: str
    verified_entries: tuple[Mapping[str, Any], ...]
    vuln_category_l1: str
    vuln_category_l2: str
    vuln_ids: tuple[str, ...]
    vuln_title: str

    def __post_init__(self) -> None:
        if not isinstance(self.commit, str) or not _COMMIT_RE.fullmatch(self.commit):
            raise BenchmarkContractError(
                "invalid_commit", "advisory commit has an invalid format"
            )
        if self.origin != ORIGIN:
            raise BenchmarkContractError(
                "invalid_origin", f"advisory origin must be {ORIGIN}"
            )
        if (
            not isinstance(self.repo_url, str)
            or not _REPO_URL_RE.fullmatch(self.repo_url)
            or self.repo_url.casefold().endswith(".git")
        ):
            raise BenchmarkContractError(
                "invalid_repo_url", "advisory repo_url has an invalid format"
            )
        for name, value in (
            ("project", self.project),
            ("vuln_category_l1", self.vuln_category_l1),
            ("vuln_category_l2", self.vuln_category_l2),
            ("vuln_title", self.vuln_title),
        ):
            _string(value, name=f"advisory {name}", nonempty=True)
        if not isinstance(self.report_id, str) or not _REPORT_ID_RE.fullmatch(
            self.report_id
        ):
            raise BenchmarkContractError(
                "invalid_report_id", "advisory report_id has an invalid format"
            )
        source_match = (
            _ADVISORY_URL_RE.fullmatch(self.source_link)
            if isinstance(self.source_link, str)
            else None
        )
        if source_match is None or source_match.group(1).upper() != self.report_id:
            raise BenchmarkContractError(
                "source_link_mismatch",
                "source_link does not bind the advisory report_id",
            )
        if (
            not isinstance(self.vuln_ids, tuple)
            or not all(isinstance(item, str) for item in self.vuln_ids)
            or len(set(self.vuln_ids)) != len(self.vuln_ids)
        ):
            raise BenchmarkContractError(
                "invalid_vuln_ids", "advisory vuln_ids must be a unique string tuple"
            )
        if not isinstance(self.verified_entries, tuple) or not self.verified_entries:
            raise BenchmarkContractError(
                "invalid_entries", "verified_entries must be a non-empty tuple"
            )
        seen_entry_ids: set[str] = set()
        frozen_entries: list[Mapping[str, Any]] = []
        advisory_values = {
            field_name: getattr(self, field_name)
            for field_name in _ENTRY_ADVISORY_FIELDS
        }
        advisory_values["vuln_ids"] = list(self.vuln_ids)
        for entry in self.verified_entries:
            validation = _SCHEMA_ADAPTER.validate(entry, formal_t2=False)
            if not validation.valid:
                first = validation.issues[0]
                raise BenchmarkContractError(
                    "invalid_training_entry",
                    f"verified entry is invalid at {first.path}: {first.code}",
                )
            if entry["verify"] != 1 or isinstance(entry["verify"], bool):
                raise BenchmarkContractError(
                    "unverified_training_entry", "training entry verify must equal 1"
                )
            entry_id = entry["entry_id"]
            if entry_id in seen_entry_ids:
                raise BenchmarkContractError(
                    "duplicate_entry_id", "advisory repeats a training entry_id"
                )
            seen_entry_ids.add(entry_id)
            for field_name, advisory_value in advisory_values.items():
                if entry[field_name] != advisory_value:
                    raise BenchmarkContractError(
                        "entry_advisory_mismatch",
                        f"training entry {field_name} does not match its advisory",
                    )
            frozen = _freeze_json(entry)
            assert isinstance(frozen, Mapping)
            frozen_entries.append(frozen)
        object.__setattr__(self, "verified_entries", tuple(frozen_entries))

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "origin": self.origin,
            "project": self.project,
            "repo_url": self.repo_url,
            "report_id": self.report_id,
            "source_link": self.source_link,
            "verified_entries": [
                _thaw_json(entry) for entry in self.verified_entries
            ],
            "vuln_category_l1": self.vuln_category_l1,
            "vuln_category_l2": self.vuln_category_l2,
            "vuln_ids": list(self.vuln_ids),
            "vuln_title": self.vuln_title,
        }


@dataclass(frozen=True, slots=True)
class TrainingGold:
    """Public calibration gold.  This type has no T2 conversion API."""

    advisories: tuple[TrainingAdvisory, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.advisories, tuple) or not self.advisories:
            raise BenchmarkContractError(
                "empty_gold", "training gold requires at least one advisory"
            )
        if not all(isinstance(item, TrainingAdvisory) for item in self.advisories):
            raise BenchmarkContractError(
                "invalid_gold", "training gold contains an invalid advisory"
            )
        report_ids: set[str] = set()
        entry_ids: set[str] = set()
        for advisory in self.advisories:
            if advisory.report_id in report_ids:
                raise BenchmarkContractError(
                    "duplicate_report_id", "training gold repeats an advisory report_id"
                )
            report_ids.add(advisory.report_id)
            for entry in advisory.verified_entries:
                entry_id = entry["entry_id"]
                if entry_id in entry_ids:
                    raise BenchmarkContractError(
                        "duplicate_entry_id", "training gold repeats an entry_id"
                    )
                entry_ids.add(entry_id)

    def iter_entries(self) -> Iterator[Mapping[str, Any]]:
        for advisory in self.advisories:
            yield from advisory.verified_entries

    def to_dict(self) -> dict[str, Any]:
        return {"advisories": [item.to_dict() for item in self.advisories]}


@dataclass(frozen=True, slots=True)
class PublicTrainingRecord:
    task: BenchmarkTask
    gold: TrainingGold
    schema_version: str = SCHEMA_VERSION
    kind: str = "training_example"

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION or self.kind != "training_example":
            raise BenchmarkContractError(
                "invalid_record_tag", "training record tags are invalid"
            )
        if not isinstance(self.task, BenchmarkTask) or self.task.split != "train":
            raise BenchmarkContractError(
                "split_mismatch", "training record requires a train task"
            )
        if not isinstance(self.gold, TrainingGold):
            raise BenchmarkContractError(
                "invalid_gold", "training record requires training gold"
            )
        for advisory in self.gold.advisories:
            if (
                advisory.repo_url != self.task.repo_url
                or advisory.commit != self.task.commit
            ):
                raise BenchmarkContractError(
                    "snapshot_mismatch",
                    "training gold advisory snapshot does not match its task",
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "gold": self.gold.to_dict(),
            "kind": self.kind,
            "schema_version": self.schema_version,
            "task": self.task.to_dict(),
        }

    def snapshot_spec(self) -> SnapshotTaskSpec:
        """Return only the answer-free side of a public training example."""

        return SnapshotTaskSpec(
            task_id=self.task.task_id,
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            split="train",
            instruction_id=self.task.instruction_id,
        )


@dataclass(frozen=True, slots=True)
class PublicTestRecord:
    """One public test record.  Its shape cannot carry a ``gold`` member."""

    task: BenchmarkTask
    schema_version: str = SCHEMA_VERSION
    kind: str = "test_task"

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION or self.kind != "test_task":
            raise BenchmarkContractError(
                "invalid_record_tag", "test record tags are invalid"
            )
        if not isinstance(self.task, BenchmarkTask) or self.task.split != "test":
            raise BenchmarkContractError(
                "split_mismatch", "test record requires a test task"
            )

    def evaluation_spec(self) -> EvaluationTaskSpec:
        return EvaluationTaskSpec(
            task_id=self.task.task_id,
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            instruction_id=self.task.instruction_id,
        )

    def snapshot_spec(self) -> SnapshotTaskSpec:
        return SnapshotTaskSpec(
            task_id=self.task.task_id,
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            split="test",
            instruction_id=self.task.instruction_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "schema_version": self.schema_version,
            "task": self.task.to_dict(),
        }


PublicBenchmarkRecord: TypeAlias = PublicTrainingRecord | PublicTestRecord


def _validate_advisory(
    value: Any,
    *,
    task: BenchmarkTask,
    seen_report_ids: set[str],
    seen_entry_ids: set[str],
) -> TrainingAdvisory:
    advisory = _strict_object(value, keys=_ADVISORY_KEYS, name="gold advisory")
    report_id = advisory["report_id"]
    if not isinstance(report_id, str) or not _REPORT_ID_RE.fullmatch(report_id):
        raise BenchmarkContractError(
            "invalid_report_id", "advisory report_id has an invalid format"
        )
    if report_id in seen_report_ids:
        raise BenchmarkContractError(
            "duplicate_report_id", "training task repeats an advisory report_id"
        )
    seen_report_ids.add(report_id)

    commit = advisory["commit"]
    repo_url = advisory["repo_url"]
    if commit != task.commit or repo_url != task.repo_url:
        raise BenchmarkContractError(
            "snapshot_mismatch", "advisory snapshot does not match its task"
        )
    if advisory["origin"] != ORIGIN:
        raise BenchmarkContractError(
            "invalid_origin", f"advisory origin must be {ORIGIN}"
        )
    project = _string(advisory["project"], name="advisory project", nonempty=True)
    category_l1 = _string(
        advisory["vuln_category_l1"],
        name="advisory vuln_category_l1",
        nonempty=True,
    )
    category_l2 = _string(
        advisory["vuln_category_l2"],
        name="advisory vuln_category_l2",
        nonempty=True,
    )
    title = _string(
        advisory["vuln_title"], name="advisory vuln_title", nonempty=True
    )
    source_link = _string(
        advisory["source_link"], name="advisory source_link"
    )
    source_match = _ADVISORY_URL_RE.fullmatch(source_link)
    if source_match is None or source_match.group(1).upper() != report_id:
        raise BenchmarkContractError(
            "source_link_mismatch", "source_link does not bind the advisory report_id"
        )
    vuln_ids = _string_tuple(
        advisory["vuln_ids"], name="advisory vuln_ids", unique=True
    )

    entries_value = advisory["verified_entries"]
    if not isinstance(entries_value, list) or not entries_value:
        raise BenchmarkContractError(
            "invalid_entries", "verified_entries must be a non-empty array"
        )
    checked_entries: list[Mapping[str, Any]] = []
    for entry in entries_value:
        validation = _SCHEMA_ADAPTER.validate(entry, formal_t2=False)
        if not validation.valid:
            first = validation.issues[0]
            raise BenchmarkContractError(
                "invalid_training_entry",
                f"verified entry is invalid at {first.path}: {first.code}",
            )
        if entry["verify"] != 1 or isinstance(entry["verify"], bool):
            raise BenchmarkContractError(
                "unverified_training_entry", "training entry verify must equal 1"
            )
        entry_id = entry["entry_id"]
        if not isinstance(entry_id, str) or not _ENTRY_ID_RE.fullmatch(entry_id):
            raise BenchmarkContractError(
                "invalid_entry_id", "training entry_id has an invalid format"
            )
        if entry_id in seen_entry_ids:
            raise BenchmarkContractError(
                "duplicate_entry_id", "training gold repeats an entry_id"
            )
        seen_entry_ids.add(entry_id)
        for field_name in _ENTRY_ADVISORY_FIELDS:
            advisory_value = advisory[field_name]
            if entry[field_name] != advisory_value:
                raise BenchmarkContractError(
                    "entry_advisory_mismatch",
                    f"training entry {field_name} does not match its advisory",
                )
        checked_entries.append(entry)

    return TrainingAdvisory(
        commit=commit,
        origin=ORIGIN,
        project=project,
        repo_url=repo_url,
        report_id=report_id,
        source_link=source_link,
        verified_entries=tuple(checked_entries),
        vuln_category_l1=category_l1,
        vuln_category_l2=category_l2,
        vuln_ids=vuln_ids,
        vuln_title=title,
    )


def parse_public_benchmark_record(value: Any) -> PublicBenchmarkRecord:
    """Parse one decoded public record with exact train/test shapes."""

    _validate_json_shape(value)
    if not isinstance(value, Mapping):
        raise BenchmarkContractError(
            "invalid_type", "benchmark record must be an object"
        )
    kind = value.get("kind")
    if kind == "test_gold":
        raise BenchmarkContractError(
            "private_gold_forbidden", "test gold is not a public benchmark record"
        )
    if kind == "test_task":
        record = _strict_object(value, keys=_TEST_RECORD_KEYS, name="test record")
        if record["schema_version"] != SCHEMA_VERSION:
            raise BenchmarkContractError(
                "unsupported_schema", "unsupported benchmark schema_version"
            )
        task = BenchmarkTask.from_dict(record["task"])
        return PublicTestRecord(task=task)
    if kind == "training_example":
        record = _strict_object(value, keys=_TRAIN_RECORD_KEYS, name="training record")
        if record["schema_version"] != SCHEMA_VERSION:
            raise BenchmarkContractError(
                "unsupported_schema", "unsupported benchmark schema_version"
            )
        task = BenchmarkTask.from_dict(record["task"])
        if task.split != "train":
            raise BenchmarkContractError(
                "split_mismatch", "training record task split must be train"
            )
        gold_value = _strict_object(record["gold"], keys=_GOLD_KEYS, name="gold")
        advisories_value = gold_value["advisories"]
        if not isinstance(advisories_value, list) or not advisories_value:
            raise BenchmarkContractError(
                "empty_gold", "training gold requires at least one advisory"
            )
        seen_report_ids: set[str] = set()
        seen_entry_ids: set[str] = set()
        advisories = tuple(
            _validate_advisory(
                item,
                task=task,
                seen_report_ids=seen_report_ids,
                seen_entry_ids=seen_entry_ids,
            )
            for item in advisories_value
        )
        return PublicTrainingRecord(task=task, gold=TrainingGold(advisories))
    raise BenchmarkContractError(
        "invalid_kind", "public benchmark kind must be training_example or test_task"
    )


def iter_public_benchmark_jsonl(
    stream: BinaryIO,
    *,
    expected_split: Literal["train", "test"],
    limits: BenchmarkReadLimits | None = None,
) -> Iterator[PublicBenchmarkRecord]:
    """Stream, bound, and strictly parse one public train or test JSONL file.

    Task IDs and ``(repo_url, commit)`` snapshots are unique across the whole
    stream.  Training entry IDs are also unique across the parsed file.
    """

    if expected_split not in {"train", "test"}:
        raise ValueError("expected_split must be train or test")
    configured = limits or BenchmarkReadLimits()
    if not isinstance(configured, BenchmarkReadLimits):
        raise ValueError("limits must be a BenchmarkReadLimits")
    if not hasattr(stream, "readline"):
        raise ValueError("stream must be a binary file-like object")

    seen_task_ids: set[str] = set()
    seen_snapshots: set[tuple[str, str]] = set()
    seen_training_entry_ids: set[str] = set()
    seen_training_report_ids: set[str] = set()
    total_bytes = 0
    input_line = 0

    while True:
        remaining = configured.max_total_bytes - total_bytes
        raw = stream.readline(min(configured.max_line_bytes + 1, remaining + 1))
        if not isinstance(raw, bytes):
            raise ValueError("stream must return bytes")
        if not raw:
            break
        total_bytes += len(raw)
        input_line += 1
        if total_bytes > configured.max_total_bytes:
            raise BenchmarkContractError(
                "total_bytes_exceeded",
                "benchmark input exceeds max_total_bytes",
                input_line=input_line,
            )
        if len(raw) > configured.max_line_bytes or not raw.endswith(b"\n"):
            code = (
                "line_bytes_exceeded"
                if len(raw) > configured.max_line_bytes
                else "unterminated_line"
            )
            message = (
                "benchmark line exceeds max_line_bytes"
                if code == "line_bytes_exceeded"
                else "every benchmark JSONL record must end with LF"
            )
            raise BenchmarkContractError(code, message, input_line=input_line)
        if input_line > configured.max_records:
            raise BenchmarkContractError(
                "record_limit_exceeded",
                "benchmark input exceeds max_records",
                input_line=input_line,
            )
        payload = raw[:-1]
        if payload.endswith(b"\r"):
            payload = payload[:-1]
        if not payload.strip():
            raise BenchmarkContractError(
                "blank_line", "blank JSONL records are not allowed", input_line=input_line
            )
        try:
            record = parse_public_benchmark_record(_parse_json_line(payload))
        except BenchmarkContractError as error:
            if error.input_line is not None:
                raise
            raise BenchmarkContractError(
                error.code, str(error), input_line=input_line
            ) from None
        if record.task.split != expected_split:
            raise BenchmarkContractError(
                "split_mismatch",
                f"record split does not match expected {expected_split} file",
                input_line=input_line,
            )
        if record.task.task_id in seen_task_ids:
            raise BenchmarkContractError(
                "duplicate_task_id",
                "benchmark input repeats a task_id",
                input_line=input_line,
            )
        # GitHub owner and repository path aliases are operationally
        # case-insensitive.  Preserve the published spelling but close that
        # alias when enforcing snapshot uniqueness.
        snapshot = (record.task.repo_url.casefold(), record.task.commit)
        if snapshot in seen_snapshots:
            raise BenchmarkContractError(
                "duplicate_snapshot",
                "benchmark input repeats a (repo_url, commit) snapshot",
                input_line=input_line,
            )
        seen_task_ids.add(record.task.task_id)
        seen_snapshots.add(snapshot)
        if isinstance(record, PublicTrainingRecord):
            current_report_ids = {
                advisory.report_id for advisory in record.gold.advisories
            }
            repeated_reports = seen_training_report_ids.intersection(
                current_report_ids
            )
            if repeated_reports:
                raise BenchmarkContractError(
                    "duplicate_report_id",
                    "benchmark input repeats a training report_id across tasks",
                    input_line=input_line,
                )
            seen_training_report_ids.update(current_report_ids)
            current_entry_ids = {
                entry["entry_id"] for entry in record.gold.iter_entries()
            }
            repeated = seen_training_entry_ids.intersection(current_entry_ids)
            if repeated:
                raise BenchmarkContractError(
                    "duplicate_entry_id",
                    "benchmark input repeats a training entry_id across tasks",
                    input_line=input_line,
                )
            seen_training_entry_ids.update(current_entry_ids)
        yield record


def load_public_benchmark_jsonl(
    path: str | os.PathLike[str],
    *,
    expected_split: Literal["train", "test"],
    limits: BenchmarkReadLimits | None = None,
) -> tuple[PublicBenchmarkRecord, ...]:
    """Open and parse a bounded public benchmark artifact."""

    configured = limits or BenchmarkReadLimits()
    if not isinstance(configured, BenchmarkReadLimits):
        raise ValueError("limits must be a BenchmarkReadLimits")
    input_path = Path(os.path.abspath(os.fspath(path)))

    def is_reparse_point(status: os.stat_result) -> bool:
        attributes = getattr(status, "st_file_attributes", 0)
        flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return bool(attributes & flag)

    def checked_lstat(candidate: Path) -> os.stat_result:
        try:
            status = os.lstat(candidate)
        except OSError as error:
            raise BenchmarkContractError(
                "input_unavailable", "public benchmark input is unavailable"
            ) from error
        if stat.S_ISLNK(status.st_mode) or is_reparse_point(status):
            raise BenchmarkContractError(
                "unsafe_input_path",
                "public benchmark path must not traverse links or reparse points",
            )
        return status

    try:
        # Reject a linked final component and linked ancestors.  ``absolute``
        # normalizes dot segments without resolving links first.
        chain = tuple(reversed(input_path.parents)) + (input_path,)
        before = None
        for component in chain:
            before = checked_lstat(component)
        assert before is not None
    except BenchmarkContractError:
        raise
    if not stat.S_ISREG(before.st_mode):
        raise BenchmarkContractError(
            "unsafe_input_path", "public benchmark input must be a regular file"
        )
    if before.st_size > configured.max_total_bytes:
        raise BenchmarkContractError(
            "total_bytes_exceeded", "benchmark input exceeds max_total_bytes"
        )
    try:
        with input_path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or is_reparse_point(opened):
                raise BenchmarkContractError(
                    "unsafe_input_path", "public benchmark input must be a regular file"
                )
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise BenchmarkContractError(
                    "input_changed", "public benchmark input changed while opening"
                )
            if opened.st_size > configured.max_total_bytes:
                raise BenchmarkContractError(
                    "total_bytes_exceeded",
                    "benchmark input exceeds max_total_bytes",
                )
            records = tuple(
                iter_public_benchmark_jsonl(
                    stream, expected_split=expected_split, limits=configured
                )
            )
            finished = os.fstat(stream.fileno())
            opened_identity = (opened.st_dev, opened.st_ino)
            finished_identity = (finished.st_dev, finished.st_ino)
            opened_state = (
                opened.st_size,
                getattr(opened, "st_mtime_ns", None),
            )
            finished_state = (
                finished.st_size,
                getattr(finished, "st_mtime_ns", None),
            )
            if opened_identity != finished_identity or opened_state != finished_state:
                raise BenchmarkContractError(
                    "input_changed", "public benchmark input changed while reading"
                )
            return records
    except BenchmarkContractError:
        raise
    except OSError as error:
        raise BenchmarkContractError(
            "input_unavailable", "public benchmark input is unavailable"
        ) from error


def _project_location(value: Any, *, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BenchmarkContractError(
            "invalid_finding", f"{name} must be an object"
        )
    file_name = value.get("file")
    if (
        not isinstance(file_name, str)
        or not file_name
        or len(file_name) > 4096
        or file_name.startswith("/")
        or "\\" in file_name
        or ":" in file_name
        or "//" in file_name
        or any(part in {"", ".", ".."} for part in file_name.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in file_name)
    ):
        raise BenchmarkContractError(
            "invalid_finding_path", f"{name}.file must be a safe repository path"
        )
    line = value.get("line")
    if isinstance(line, bool):
        valid_line = False
    elif isinstance(line, int):
        valid_line = line > 0
    elif isinstance(line, str) and len(line) <= 41:
        match = _LINE_RANGE_RE.fullmatch(line)
        valid_line = match is not None and int(match.group(1)) <= int(match.group(2))
    else:
        valid_line = False
    if not valid_line:
        raise BenchmarkContractError(
            "invalid_finding_line", f"{name}.line must be a positive line or range"
        )
    return {"file": file_name, "line": line}


def iter_evaluator_findings(
    task: EvaluationTaskSpec | SnapshotTaskSpec,
    findings: Iterable[Mapping[str, Any]],
    *,
    max_findings: int = MAX_FINDINGS_PER_TASK,
) -> Iterator[dict[str, Any]]:
    """Project zero or more task findings into the external evaluator format.

    Top-level and location-level metadata not consumed by the evaluator is
    deliberately removed.  When a producer includes task/snapshot binders,
    they must exactly match the trusted evaluation specification.
    """

    if not isinstance(task, (EvaluationTaskSpec, SnapshotTaskSpec)):
        raise ValueError("task must be an answer-free snapshot specification")
    limit = _positive_limit("max_findings", max_findings, MAX_FINDINGS_PER_TASK)
    try:
        iterator = iter(findings)
    except TypeError:
        raise ValueError("findings must be iterable") from None

    for index, finding in enumerate(iterator, 1):
        if index > limit:
            raise BenchmarkContractError(
                "finding_limit_exceeded", "task produces too many findings"
            )
        if not isinstance(finding, Mapping):
            raise BenchmarkContractError(
                "invalid_finding", "each finding must be an object"
            )
        optional_binders = {
            "task_id": task.task_id,
            "repo_url": task.repo_url,
            "commit": task.commit,
        }
        for field_name, expected in optional_binders.items():
            if field_name in finding and finding[field_name] != expected:
                raise BenchmarkContractError(
                    "finding_binding_mismatch",
                    f"finding {field_name} does not match its evaluation task",
                )
        projected: dict[str, Any] = {
            "repo_url": task.repo_url,
            "commit": task.commit,
            "entry_point": _project_location(
                finding.get("entry_point"), name="entry_point"
            ),
            "critical_operation": _project_location(
                finding.get("critical_operation"), name="critical_operation"
            ),
        }
        if "trace" in finding:
            trace = finding["trace"]
            if not isinstance(trace, (list, tuple)) or len(trace) > _MAX_TRACE_NODES:
                raise BenchmarkContractError(
                    "invalid_finding_trace",
                    f"trace must contain at most {_MAX_TRACE_NODES} locations",
                )
            projected["trace"] = [
                _project_location(item, name=f"trace[{position}]")
                for position, item in enumerate(trace)
            ]
        yield projected


__all__ = [
    "BenchmarkContractError",
    "BenchmarkReadLimits",
    "BenchmarkTask",
    "EvaluationTaskSpec",
    "PublicBenchmarkRecord",
    "PublicTestRecord",
    "PublicTrainingRecord",
    "SnapshotTaskSpec",
    "TrainingAdvisory",
    "TrainingGold",
    "iter_evaluator_findings",
    "iter_public_benchmark_jsonl",
    "load_public_benchmark_jsonl",
    "parse_public_benchmark_record",
]
