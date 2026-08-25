#!/usr/bin/env python3
"""Build and audit the reproducible VulnGym 50-train / 20-test split.

The script is intentionally independent of ``vulngym_agent``.  It pins the
public VulnGym v0.1.4 inputs by SHA-256, admits only complete human-verified
advisories, coalesces advisories that share a repository snapshot, performs a
deterministic marginally stratified split, and writes public tasks separately
from evaluator-only test gold.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
INSTRUCTION_ID = "vulngym-whitebox-locate-v1"
SOURCE_REPOSITORY = "https://github.com/Tencent/VulnGym"
SOURCE_REVISION = "cd69f7e163e08485ab5496115ae03439cda6e27e"
SOURCE_TAG = "v0.1.4"
BENCHMARK_RELATIVE = Path("benchmarks/vulngym_50_20_v1")
SCRIPT_RELATIVE = Path("scripts/build_vulngym_50_20.py")

SOURCE_FILES: dict[str, dict[str, Any]] = {
    "data/entries.jsonl": {
        "sha256": "2158b6bfef0be1812e7a6a77b32ad32b65964c2546c83018ff20a9a6f706c7b1",
        "git_blob_sha1": "43f86b3155635053253acfea0e1bdb87b1a8b773",
        "rows": 408,
    },
    "data/reports.jsonl": {
        "sha256": "5d29ce523441eb1739bddca3e4550514171b1b2b1f9d38bd922933408d25fbb9",
        "git_blob_sha1": "6c6d23449e702b3fc4920817ea512c5243ac3997",
        "rows": 184,
    },
    "LICENSE": {
        "sha256": "8c566172d3cd40ac7dbc8c1dc4d5babe4b485e1947252ccff26b59f5a2d27679",
        "git_blob_sha1": "32707e2bd4fe5229fc3960c27b8a8500c5d5d596",
    },
    "SCHEMA.md": {
        "sha256": "ad3a35029bebbc9be197b0ff325d4b49d9ed5c64d9c755a6b652cbf4b619624a",
        "git_blob_sha1": "f6066edae1130ef8f2453459b1ae135a63e5c925",
    },
}

PUBLIC_STATIC_FILES = (
    ".gitignore",
    "benchmarks/vulngym_50_20_v1/README.md",
    "benchmarks/vulngym_50_20_v1/NOTICE.md",
    "benchmarks/vulngym_50_20_v1/config/language_extensions.json",
    "benchmarks/vulngym_50_20_v1/config/sampling.json",
    "benchmarks/vulngym_50_20_v1/requirements.txt",
    "benchmarks/vulngym_50_20_v1/schemas/benchmark-record.schema.json",
    "benchmarks/vulngym_50_20_v1/schemas/public-manifest.schema.json",
    "scripts/build_vulngym_50_20.py",
)

FORBIDDEN_TEST_KEYS = frozenset(
    {
        "answer",
        "answers",
        "code",
        "critical_operation",
        "desc",
        "entry_id",
        "entry_point",
        "gold",
        "origin",
        "report_id",
        "source_link",
        "trace",
        "verify",
        "vuln_category_l1",
        "vuln_category_l2",
        "vuln_ids",
        "vuln_title",
    }
)

_LINE_RANGE = re.compile(r"^([1-9][0-9]*)-([1-9][0-9]*)$")


class BuildError(RuntimeError):
    """Raised when a fail-closed source, schema, or leakage check fails."""


@dataclass(frozen=True)
class SnapshotTask:
    key: str
    repo_url: str
    commit: str
    advisories: tuple[dict[str, Any], ...]
    languages: tuple[str, ...]
    primary_language: str
    sampling_language: str
    categories_l1: tuple[str, ...]

    @property
    def report_ids(self) -> tuple[str, ...]:
        return tuple(item["report_id"] for item in self.advisories)

    @property
    def entry_count(self) -> int:
        return sum(len(item["verified_entries"]) for item in self.advisories)


@dataclass(frozen=True)
class SourcePopulation:
    total_entries: int
    verified_entries: int
    total_advisories: int
    fully_verified_advisories: int
    partially_verified_advisories: int
    unverified_advisories: int
    eligible_snapshot_tasks: int
    eligible_advisories: int
    eligible_entries: int
    excluded_incomplete_snapshot_tasks: int


@dataclass(frozen=True)
class Selection:
    train_keys: tuple[str, ...]
    test_keys: tuple[str, ...]
    objective: float
    restart: int
    iterations: int


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def canonical_jsonl_bytes(rows: Iterable[Mapping[str, Any]]) -> bytes:
    return "".join(
        json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
        for row in rows
    ).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BuildError(f"cannot load JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise BuildError(f"{path} must contain a JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise BuildError(f"cannot read JSONL {path}: {exc}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            raise BuildError(f"{path}:{line_number}: blank JSONL rows are forbidden")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BuildError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise BuildError(f"{path}:{line_number}: row must be a JSON object")
        rows.append(value)
    return rows


def verify_pinned_sources(repo_root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for relative, expected in SOURCE_FILES.items():
        path = repo_root / Path(relative)
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise BuildError(f"cannot read pinned source {path}: {exc}") from exc
        actual = sha256_bytes(payload)
        if actual != expected["sha256"]:
            raise BuildError(
                f"pinned source hash mismatch for {relative}: "
                f"expected {expected['sha256']}, got {actual}"
            )
        item = {
            "bytes": len(payload),
            "git_blob_sha1": expected["git_blob_sha1"],
            "path": relative,
            "sha256": actual,
            "url": f"{SOURCE_REPOSITORY}/blob/{SOURCE_REVISION}/{relative}",
        }
        if "rows" in expected:
            rows = len(payload.decode("utf-8").splitlines())
            if rows != expected["rows"]:
                raise BuildError(
                    f"pinned source row mismatch for {relative}: "
                    f"expected {expected['rows']}, got {rows}"
                )
            item["rows"] = rows
        result[relative] = item
    try:
        tag_revision = subprocess.run(
            ["git", "rev-parse", f"{SOURCE_TAG}^{{commit}}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            encoding="utf-8",
            errors="strict",
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise BuildError(f"cannot verify pinned source tag {SOURCE_TAG}: {exc}") from exc
    if tag_revision != SOURCE_REVISION:
        raise BuildError(
            f"source tag {SOURCE_TAG} resolves to {tag_revision}, expected {SOURCE_REVISION}"
        )
    for relative, expected in SOURCE_FILES.items():
        try:
            working_blob = subprocess.run(
                ["git", "hash-object", f"--path={relative}", relative],
                cwd=repo_root,
                check=True,
                capture_output=True,
                encoding="utf-8",
                errors="strict",
            ).stdout.strip()
            tree_line = subprocess.run(
                ["git", "ls-tree", SOURCE_REVISION, "--", relative],
                cwd=repo_root,
                check=True,
                capture_output=True,
                encoding="utf-8",
                errors="strict",
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise BuildError(
                f"cannot verify {relative} in source revision {SOURCE_REVISION}: {exc}"
            ) from exc
        if working_blob != expected["git_blob_sha1"]:
            raise BuildError(
                f"filtered working-tree Git blob mismatch for {relative}: "
                f"expected {expected['git_blob_sha1']}, got {working_blob}"
            )
        fields = tree_line.split(None, 3)
        if len(fields) != 4 or fields[1] != "blob" or fields[2] != expected["git_blob_sha1"]:
            raise BuildError(
                f"source revision {SOURCE_REVISION} does not bind {relative} "
                f"to blob {expected['git_blob_sha1']}"
            )
    return result


def _validate_line(value: Any, context: str) -> None:
    if isinstance(value, bool):
        raise BuildError(f"{context}: boolean is not a valid line")
    if isinstance(value, int):
        if value < 1:
            raise BuildError(f"{context}: line must be positive")
        return
    if not isinstance(value, str):
        raise BuildError(f"{context}: line must be an integer or range")
    match = _LINE_RANGE.fullmatch(value)
    if not match or int(match.group(1)) > int(match.group(2)):
        raise BuildError(f"{context}: invalid inclusive line range {value!r}")


def _validate_location(value: Any, context: str) -> None:
    if not isinstance(value, dict):
        raise BuildError(f"{context}: location must be an object")
    required = {"file", "line", "code"}
    optional = {"desc"}
    if not required <= value.keys() or not value.keys() <= required | optional:
        raise BuildError(f"{context}: invalid location fields")
    if not isinstance(value["file"], str) or not value["file"]:
        raise BuildError(f"{context}: file must be a non-empty string")
    pure_path = PurePosixPath(value["file"])
    if (
        pure_path.is_absolute()
        or "\\" in value["file"]
        or ".." in pure_path.parts
    ):
        raise BuildError(f"{context}: file must be a relative POSIX path")
    if not isinstance(value["code"], str):
        raise BuildError(f"{context}: code must be a string")
    if "desc" in value and not isinstance(value["desc"], str):
        raise BuildError(f"{context}: desc must be a string")
    _validate_line(value["line"], f"{context}.line")


def validate_source_entry(entry: Mapping[str, Any], context: str) -> None:
    required = {
        "commit",
        "critical_operation",
        "entry_id",
        "entry_point",
        "origin",
        "project",
        "repo_url",
        "report_id",
        "source_link",
        "trace",
        "verify",
        "vuln_category_l1",
        "vuln_category_l2",
        "vuln_ids",
        "vuln_title",
    }
    if set(entry) != required:
        raise BuildError(f"{context}: entry fields differ from the v0.1.4 contract")
    if entry["verify"] not in (0, 1) or isinstance(entry["verify"], bool):
        raise BuildError(f"{context}: verify must be integer 0 or 1")
    if not re.fullmatch(r"entry-[0-9]{5}", str(entry["entry_id"])):
        raise BuildError(f"{context}: invalid entry_id")
    if not re.fullmatch(r"GHSA-[0-9A-Z]{4}(?:-[0-9A-Z]{4}){2}", str(entry["report_id"])):
        raise BuildError(f"{context}: invalid report_id")
    if not re.fullmatch(r"[0-9a-f]{40}", str(entry["commit"])):
        raise BuildError(f"{context}: invalid commit")
    if not str(entry["repo_url"]).startswith("https://github.com/"):
        raise BuildError(f"{context}: invalid repo_url")
    _validate_location(entry["entry_point"], f"{context}.entry_point")
    _validate_location(entry["critical_operation"], f"{context}.critical_operation")
    if not isinstance(entry["trace"], list):
        raise BuildError(f"{context}: trace must be an array")
    for index, node in enumerate(entry["trace"]):
        _validate_location(node, f"{context}.trace[{index}]")


def language_for_path(path: str, language_config: Mapping[str, Any]) -> str:
    extension = PurePosixPath(path).suffix.lower()
    mapping = language_config["extensions"]
    return str(mapping.get(extension, language_config["unknown_label"]))


def _snapshot_key(repo_url: str, commit: str) -> str:
    return f"{repo_url}\0{commit}"


def build_source_universe(
    entries: Sequence[dict[str, Any]],
    reports: Sequence[dict[str, Any]],
    language_config: Mapping[str, Any],
) -> tuple[list[SnapshotTask], SourcePopulation, dict[str, list[dict[str, Any]]]]:
    if not isinstance(language_config.get("extensions"), dict):
        raise BuildError("language config extensions must be an object")
    if language_config.get("sources") != [
        "entry_point.file",
        "critical_operation.file",
    ]:
        raise BuildError("language config sources changed unexpectedly")

    entry_ids: set[str] = set()
    entries_by_report: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, entry in enumerate(entries, 1):
        validate_source_entry(entry, f"entries.jsonl:{index}")
        entry_id = entry["entry_id"]
        if entry_id in entry_ids:
            raise BuildError(f"duplicate entry_id {entry_id}")
        entry_ids.add(entry_id)
        entries_by_report[entry["report_id"]].append(entry)

    reports_by_id: dict[str, dict[str, Any]] = {}
    reports_by_snapshot: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, report in enumerate(reports, 1):
        report_id = report.get("report_id")
        if not isinstance(report_id, str) or report_id in reports_by_id:
            raise BuildError(f"reports.jsonl:{index}: invalid or duplicate report_id")
        if report_id not in entries_by_report:
            raise BuildError(f"report {report_id} has no entries")
        grouped_ids = sorted(item["entry_id"] for item in entries_by_report[report_id])
        if report.get("entry_ids") != grouped_ids or report.get("num_entries") != len(grouped_ids):
            raise BuildError(f"report {report_id} entry membership is inconsistent")
        repo_url = report.get("repo_url")
        commit = report.get("commit")
        if not isinstance(repo_url, str) or not isinstance(commit, str):
            raise BuildError(f"report {report_id} lacks repository coordinates")
        for entry in entries_by_report[report_id]:
            for field in ("repo_url", "commit", "origin", "source_link"):
                if entry[field] != report.get(field):
                    raise BuildError(f"report {report_id} disagrees with entry on {field}")
        reports_by_id[report_id] = report
        reports_by_snapshot[_snapshot_key(repo_url, commit)].append(report)

    if set(entries_by_report) != set(reports_by_id):
        raise BuildError("entries/reports report_id sets differ")

    fully_verified = {
        report_id
        for report_id, grouped in entries_by_report.items()
        if grouped and all(item["verify"] == 1 for item in grouped)
    }
    partially_verified = {
        report_id
        for report_id, grouped in entries_by_report.items()
        if any(item["verify"] == 1 for item in grouped)
        and not all(item["verify"] == 1 for item in grouped)
    }
    unverified = set(entries_by_report) - fully_verified - partially_verified

    tasks: list[SnapshotTask] = []
    excluded_snapshot_count = 0
    for key, grouped_reports in sorted(reports_by_snapshot.items()):
        report_ids = {item["report_id"] for item in grouped_reports}
        if not report_ids <= fully_verified:
            excluded_snapshot_count += 1
            continue
        repo_url = grouped_reports[0]["repo_url"]
        commit = grouped_reports[0]["commit"]
        advisory_gold: list[dict[str, Any]] = []
        language_counts: Counter[str] = Counter()
        categories: set[str] = set()
        for report in sorted(grouped_reports, key=lambda item: item["report_id"]):
            grouped_entries = sorted(
                entries_by_report[report["report_id"]], key=lambda item: item["entry_id"]
            )
            category_l1 = {item["vuln_category_l1"] for item in grouped_entries}
            category_l2 = {item["vuln_category_l2"] for item in grouped_entries}
            if len(category_l1) != 1 or len(category_l2) != 1:
                raise BuildError(f"report {report['report_id']} has inconsistent categories")
            categories.update(category_l1)
            for entry in grouped_entries:
                if entry["verify"] != 1:
                    raise BuildError("internal eligibility error: unverified gold entry")
                for field in ("entry_point", "critical_operation"):
                    language_counts[
                        language_for_path(entry[field]["file"], language_config)
                    ] += 1
            advisory_gold.append(
                {
                    "commit": report["commit"],
                    "origin": report["origin"],
                    "project": report["project"],
                    "repo_url": report["repo_url"],
                    "report_id": report["report_id"],
                    "source_link": report["source_link"],
                    "verified_entries": grouped_entries,
                    "vuln_category_l1": next(iter(category_l1)),
                    "vuln_category_l2": next(iter(category_l2)),
                    "vuln_ids": report["vuln_ids"],
                    "vuln_title": report["vuln_title"],
                }
            )
        if not language_counts:
            language_counts[str(language_config["unknown_label"])] = 1
        primary_language = sorted(language_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
        sampling_primary_languages = set(language_config["sampling_primary_languages"])
        sampling_language = (
            primary_language
            if primary_language in sampling_primary_languages
            else str(language_config["sampling_other_label"])
        )
        tasks.append(
            SnapshotTask(
                key=key,
                repo_url=repo_url,
                commit=commit,
                advisories=tuple(advisory_gold),
                languages=tuple(sorted(language_counts)),
                primary_language=primary_language,
                sampling_language=sampling_language,
                categories_l1=tuple(sorted(categories)),
            )
        )

    population = SourcePopulation(
        total_entries=len(entries),
        verified_entries=sum(item["verify"] == 1 for item in entries),
        total_advisories=len(reports),
        fully_verified_advisories=len(fully_verified),
        partially_verified_advisories=len(partially_verified),
        unverified_advisories=len(unverified),
        eligible_snapshot_tasks=len(tasks),
        eligible_advisories=sum(len(item.advisories) for item in tasks),
        eligible_entries=sum(item.entry_count for item in tasks),
        excluded_incomplete_snapshot_tasks=excluded_snapshot_count,
    )
    return tasks, population, entries_by_report


def task_features(task: SnapshotTask) -> set[tuple[str, str]]:
    features = {("repository", task.repo_url)}
    features.add(("language", task.sampling_language))
    features.update(("vuln_category_l1", value) for value in task.categories_l1)
    return features


def task_answer_signatures(
    task: SnapshotTask, minimum_code_characters: int
) -> tuple[set[tuple[str, str, str, str]], set[tuple[str, str, str]]]:
    """Return commit-independent location and normalized-code signatures."""
    locations: set[tuple[str, str, str, str]] = set()
    code: set[tuple[str, str, str]] = set()
    for advisory in task.advisories:
        for entry in advisory["verified_entries"]:
            nodes = [
                ("entry_point", entry["entry_point"]),
                ("critical_operation", entry["critical_operation"]),
                *(("trace", node) for node in entry["trace"]),
            ]
            for role, node in nodes:
                locations.add(
                    (
                        entry["repo_url"],
                        role,
                        _normalize_path(node["file"]),
                        str(node["line"]),
                    )
                )
                normalized_code = " ".join(node["code"].split())
                if len(normalized_code) >= minimum_code_characters:
                    code.add((entry["repo_url"], role, normalized_code))
    return locations, code


def selection_signature_overlaps(
    tasks: Sequence[SnapshotTask],
    selection: Selection,
    minimum_code_characters: int,
) -> tuple[int, int]:
    by_key = {task.key: task for task in tasks}

    def collect(keys: Iterable[str]) -> tuple[set[Any], set[Any]]:
        locations: set[Any] = set()
        code: set[Any] = set()
        for key in keys:
            task_locations, task_code = task_answer_signatures(
                by_key[key], minimum_code_characters
            )
            locations.update(task_locations)
            code.update(task_code)
        return locations, code

    train_locations, train_code = collect(selection.train_keys)
    test_locations, test_code = collect(selection.test_keys)
    return len(train_locations & test_locations), len(train_code & test_code)


def stable_rank(seed: str, value: str) -> bytes:
    key = hashlib.sha256(seed.encode("utf-8")).digest()
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()


def opaque_task_id(dataset_id: str, seed: str, split: str, task_key: str) -> str:
    material = f"{dataset_id}\0{seed}\0{split}\0{task_key}".encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:20].upper()
    return f"VG-{split.upper()}-{digest}"


class MarginalObjective:
    """Incremental equal-dimension marginal distribution objective."""

    def __init__(
        self,
        tasks: Sequence[SnapshotTask],
        train_size: int,
        test_size: int,
        coverage_threshold: float,
    ) -> None:
        all_features = sorted({feature for task in tasks for feature in task_features(task)})
        self.feature_index = {feature: index for index, feature in enumerate(all_features)}
        self.features = tuple(all_features)
        self.task_indices = {
            task.key: frozenset(self.feature_index[item] for item in task_features(task))
            for task in tasks
        }
        self.population = [0] * len(all_features)
        for indices in self.task_indices.values():
            for index in indices:
                self.population[index] += 1
        labels_per_dimension = Counter(dimension for dimension, _ in all_features)
        self.weights = [
            1.0 / labels_per_dimension[dimension] for dimension, _ in all_features
        ]
        self.universe_size = len(tasks)
        self.train_size = train_size
        self.test_size = test_size
        self.selected_size = train_size + test_size
        self.coverage_threshold = coverage_threshold

    def counts(self, keys: Iterable[str]) -> list[int]:
        counts = [0] * len(self.features)
        for key in keys:
            for index in self.task_indices[key]:
                counts[index] += 1
        return counts

    def _term(self, index: int, count: int, size: int) -> float:
        target = self.population[index] * size / self.universe_size
        loss = self.weights[index] * ((count - target) ** 2 / max(target, 1.0))
        if target >= self.coverage_threshold and count == 0:
            loss += self.weights[index] * 100.0
        return loss

    def loss(self, counts: Sequence[int], size: int) -> float:
        return sum(self._term(index, count, size) for index, count in enumerate(counts))

    def delta(
        self,
        counts: Sequence[int],
        remove_key: str,
        add_key: str,
        size: int,
    ) -> float:
        remove = self.task_indices[remove_key]
        add = self.task_indices[add_key]
        changed = remove ^ add
        result = 0.0
        for index in changed:
            before = counts[index]
            after = before - (index in remove) + (index in add)
            result += self._term(index, after, size) - self._term(index, before, size)
        return result

    def update_counts(
        self,
        counts: list[int],
        remove_key: str,
        add_key: str,
    ) -> None:
        for index in self.task_indices[remove_key] - self.task_indices[add_key]:
            counts[index] -= 1
        for index in self.task_indices[add_key] - self.task_indices[remove_key]:
            counts[index] += 1

    def objective(
        self,
        train_counts: Sequence[int],
        test_counts: Sequence[int],
        selected_counts: Sequence[int],
    ) -> float:
        return (
            self.loss(train_counts, self.train_size)
            + self.loss(test_counts, self.test_size)
            + 0.5 * self.loss(selected_counts, self.selected_size)
        )

    def missing_required_coverage(
        self, counts: Sequence[int], size: int
    ) -> list[tuple[str, str]]:
        missing: list[tuple[str, str]] = []
        for index, feature in enumerate(self.features):
            target = self.population[index] * size / self.universe_size
            if target >= self.coverage_threshold and counts[index] == 0:
                missing.append(feature)
        return missing


def _apply_swap(
    source: set[str], destination: set[str], remove_key: str, add_key: str
) -> None:
    source.remove(remove_key)
    source.add(add_key)
    destination.remove(add_key)
    destination.add(remove_key)


def _optimize_restart(
    tasks: Sequence[SnapshotTask],
    objective: MarginalObjective,
    seed: str,
    restart: int,
    max_iterations: int,
) -> Selection:
    order = sorted(
        (task.key for task in tasks),
        key=lambda key: (stable_rank(seed, f"restart:{restart}:{key}"), key),
    )
    train = set(order[: objective.train_size])
    test = set(order[objective.train_size : objective.selected_size])
    unused = set(order[objective.selected_size :])
    train_counts = objective.counts(train)
    test_counts = objective.counts(test)
    selected_counts = [left + right for left, right in zip(train_counts, test_counts)]

    epsilon = 1e-12
    completed_iterations = 0
    for iteration in range(max_iterations):
        best_delta = 0.0
        best_move: tuple[str, str, str] | None = None

        def consider(delta: float, move: tuple[str, str, str]) -> None:
            nonlocal best_delta, best_move
            if delta < best_delta - epsilon or (
                delta < -epsilon
                and abs(delta - best_delta) <= epsilon
                and (best_move is None or move < best_move)
            ):
                best_delta = delta
                best_move = move

        for train_key in sorted(train):
            for test_key in sorted(test):
                delta = objective.delta(
                    train_counts, train_key, test_key, objective.train_size
                ) + objective.delta(test_counts, test_key, train_key, objective.test_size)
                consider(delta, ("train_test", train_key, test_key))
        for train_key in sorted(train):
            for unused_key in sorted(unused):
                delta = objective.delta(
                    train_counts, train_key, unused_key, objective.train_size
                ) + 0.5 * objective.delta(
                    selected_counts, train_key, unused_key, objective.selected_size
                )
                consider(delta, ("train_unused", train_key, unused_key))
        for test_key in sorted(test):
            for unused_key in sorted(unused):
                delta = objective.delta(
                    test_counts, test_key, unused_key, objective.test_size
                ) + 0.5 * objective.delta(
                    selected_counts, test_key, unused_key, objective.selected_size
                )
                consider(delta, ("test_unused", test_key, unused_key))

        if best_move is None:
            break
        kind, left, right = best_move
        if kind == "train_test":
            objective.update_counts(train_counts, left, right)
            objective.update_counts(test_counts, right, left)
            _apply_swap(train, test, left, right)
        elif kind == "train_unused":
            objective.update_counts(train_counts, left, right)
            objective.update_counts(selected_counts, left, right)
            _apply_swap(train, unused, left, right)
        else:
            objective.update_counts(test_counts, left, right)
            objective.update_counts(selected_counts, left, right)
            _apply_swap(test, unused, left, right)
        completed_iterations = iteration + 1

    final_score = objective.objective(train_counts, test_counts, selected_counts)
    return Selection(
        train_keys=tuple(sorted(train)),
        test_keys=tuple(sorted(test)),
        objective=final_score,
        restart=restart,
        iterations=completed_iterations,
    )


def select_tasks(
    tasks: Sequence[SnapshotTask], sampling: Mapping[str, Any]
) -> tuple[Selection, MarginalObjective]:
    train_size = int(sampling["train_tasks"])
    test_size = int(sampling["test_tasks"])
    if train_size < 1 or test_size < 1 or train_size + test_size > len(tasks):
        raise BuildError("invalid requested split sizes")
    objective = MarginalObjective(
        tasks,
        train_size,
        test_size,
        float(sampling["coverage_expected_count_threshold"]),
    )
    candidates = [
        _optimize_restart(
            tasks,
            objective,
            str(sampling["sampling_seed"]),
            restart,
            int(sampling["max_local_search_iterations"]),
        )
        for restart in range(int(sampling["restarts"]))
    ]
    minimum_code_characters = int(sampling["leakage_code_min_normalized_chars"])
    safe_candidates = [
        candidate
        for candidate in candidates
        if selection_signature_overlaps(
            tasks, candidate, minimum_code_characters
        )
        == (0, 0)
    ]
    if not safe_candidates:
        raise BuildError(
            "no deterministic restart satisfied the cross-version location/code "
            "leakage constraints"
        )
    best = min(
        safe_candidates,
        key=lambda item: (
            round(item.objective, 14),
            item.train_keys,
            item.test_keys,
            item.restart,
        ),
    )
    train_counts = objective.counts(best.train_keys)
    test_counts = objective.counts(best.test_keys)
    selected_counts = objective.counts((*best.train_keys, *best.test_keys))
    missing = {
        "train": objective.missing_required_coverage(train_counts, train_size),
        "test": objective.missing_required_coverage(test_counts, test_size),
        "selected": objective.missing_required_coverage(
            selected_counts, train_size + test_size
        ),
    }
    if any(missing.values()):
        raise BuildError(f"stratified selection missed required coverage: {missing}")
    return best, objective


def public_task(task: SnapshotTask, split: str, sampling: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "commit": task.commit,
        "instruction_id": INSTRUCTION_ID,
        "repo_url": task.repo_url,
        "split": split,
        "task_id": opaque_task_id(
            str(sampling["dataset_id"]),
            str(sampling["sampling_seed"]),
            split,
            task.key,
        ),
    }


def build_records(
    tasks: Sequence[SnapshotTask],
    selection: Selection,
    sampling: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    by_key = {task.key: task for task in tasks}
    train_rows: list[dict[str, Any]] = []
    test_rows: list[dict[str, Any]] = []
    test_gold_rows: list[dict[str, Any]] = []
    lock_train: list[dict[str, Any]] = []
    lock_test: list[dict[str, Any]] = []

    for key in selection.train_keys:
        task = by_key[key]
        task_value = public_task(task, "train", sampling)
        train_rows.append(
            {
                "gold": {"advisories": list(task.advisories)},
                "kind": "training_example",
                "schema_version": SCHEMA_VERSION,
                "task": task_value,
            }
        )
        lock_train.append(
            {
                "commit": task.commit,
                "report_ids": list(task.report_ids),
                "repo_url": task.repo_url,
                "task_id": task_value["task_id"],
            }
        )

    for key in selection.test_keys:
        task = by_key[key]
        task_value = public_task(task, "test", sampling)
        test_rows.append(
            {
                "kind": "test_task",
                "schema_version": SCHEMA_VERSION,
                "task": task_value,
            }
        )
        test_gold_rows.append(
            {
                "gold": {"advisories": list(task.advisories)},
                "kind": "test_gold",
                "schema_version": SCHEMA_VERSION,
                "task_id": task_value["task_id"],
            }
        )
        lock_test.append(
            {
                "commit": task.commit,
                "report_ids": list(task.report_ids),
                "repo_url": task.repo_url,
                "task_id": task_value["task_id"],
            }
        )

    train_rows.sort(key=lambda row: row["task"]["task_id"])
    test_rows.sort(key=lambda row: row["task"]["task_id"])
    test_gold_rows.sort(key=lambda row: row["task_id"])
    lock_train.sort(key=lambda row: row["task_id"])
    lock_test.sort(key=lambda row: row["task_id"])
    selection_lock = {
        "algorithm": sampling["algorithm"],
        "dataset_id": sampling["dataset_id"],
        "objective": round(selection.objective, 12),
        "sampling_seed": sampling["sampling_seed"],
        "schema_version": SCHEMA_VERSION,
        "selected_restart": selection.restart,
        "test": lock_test,
        "train": lock_train,
    }
    return train_rows, test_rows, test_gold_rows, selection_lock


def _gold_advisories(rows: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for row in rows:
        gold = row.get("gold")
        if isinstance(gold, Mapping):
            advisories = gold.get("advisories")
            if isinstance(advisories, list):
                result.extend(item for item in advisories if isinstance(item, Mapping))
    return result


def _gold_entries(rows: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for advisory in _gold_advisories(rows):
        entries = advisory.get("verified_entries")
        if isinstance(entries, list):
            result.extend(item for item in entries if isinstance(item, Mapping))
    return result


def _recursive_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, Mapping):
        for key, child in value.items():
            keys.add(str(key))
            keys.update(_recursive_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_recursive_keys(child))
    return keys


def _normalize_path(path: Any) -> str:
    if not isinstance(path, str):
        return ""
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return re.sub(r"/+", "/", normalized)


def _endpoint_fingerprint(entry: Mapping[str, Any], include_commit: bool) -> str:
    parts = [str(entry.get("repo_url", ""))]
    if include_commit:
        parts.append(str(entry.get("commit", "")))
    for field in ("entry_point", "critical_operation"):
        location = entry.get(field)
        if not isinstance(location, Mapping):
            parts.extend(("", ""))
        else:
            parts.extend((_normalize_path(location.get("file")), str(location.get("line", ""))))
    return sha256_bytes("\0".join(parts).encode("utf-8"))


def _all_node_signatures(
    entries: Iterable[Mapping[str, Any]], minimum_code_characters: int
) -> tuple[set[str], set[str]]:
    location_fingerprints: set[str] = set()
    code_fingerprints: set[str] = set()
    for entry in entries:
        nodes: list[tuple[str, Any]] = [
            ("entry_point", entry.get("entry_point")),
            ("critical_operation", entry.get("critical_operation")),
        ]
        trace = entry.get("trace")
        if isinstance(trace, list):
            nodes.extend(("trace", node) for node in trace)
        for role, node in nodes:
            if not isinstance(node, Mapping):
                continue
            location_material = "\0".join(
                (
                    str(entry.get("repo_url", "")),
                    role,
                    _normalize_path(node.get("file")),
                    str(node.get("line", "")),
                )
            )
            location_fingerprints.add(
                sha256_bytes(location_material.encode("utf-8"))
            )
            normalized_code = " ".join(str(node.get("code", "")).split())
            if len(normalized_code) >= minimum_code_characters:
                code_material = "\0".join(
                    (str(entry.get("repo_url", "")), role, normalized_code)
                )
                code_fingerprints.add(sha256_bytes(code_material.encode("utf-8")))
    return location_fingerprints, code_fingerprints


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"check": name, "detail": detail, "status": "pass" if passed else "fail"}


def build_leakage_report(
    train_rows: Sequence[dict[str, Any]],
    test_rows: Sequence[dict[str, Any]],
    test_gold_rows: Sequence[dict[str, Any]],
    repo_root: Path,
    output_root: Path,
    private_root: Path,
    minimum_code_characters: int,
) -> dict[str, Any]:
    train_advisories = _gold_advisories(train_rows)
    test_advisories = _gold_advisories(test_gold_rows)
    train_entries = _gold_entries(train_rows)
    test_entries = _gold_entries(test_gold_rows)

    train_report_ids = {str(item["report_id"]) for item in train_advisories}
    test_report_ids = {str(item["report_id"]) for item in test_advisories}
    train_entry_ids = {str(item["entry_id"]) for item in train_entries}
    test_entry_ids = {str(item["entry_id"]) for item in test_entries}
    train_vuln_ids = {
        str(identifier)
        for item in train_advisories
        for identifier in item.get("vuln_ids", [])
    }
    test_vuln_ids = {
        str(identifier)
        for item in test_advisories
        for identifier in item.get("vuln_ids", [])
    }
    train_sources = {str(item["source_link"]) for item in train_advisories}
    test_sources = {str(item["source_link"]) for item in test_advisories}
    train_snapshots = {
        (str(row["task"]["repo_url"]), str(row["task"]["commit"])) for row in train_rows
    }
    test_snapshots = {
        (str(row["task"]["repo_url"]), str(row["task"]["commit"])) for row in test_rows
    }
    train_location_fingerprints = {
        _endpoint_fingerprint(item, include_commit=False) for item in train_entries
    }
    test_location_fingerprints = {
        _endpoint_fingerprint(item, include_commit=False) for item in test_entries
    }
    train_exact_fingerprints = {
        _endpoint_fingerprint(item, include_commit=True) for item in train_entries
    }
    test_exact_fingerprints = {
        _endpoint_fingerprint(item, include_commit=True) for item in test_entries
    }
    train_node_locations, train_node_code = _all_node_signatures(
        train_entries, minimum_code_characters
    )
    test_node_locations, test_node_code = _all_node_signatures(
        test_entries, minimum_code_characters
    )
    public_test_keys = set().union(*(_recursive_keys(row) for row in test_rows))
    test_task_ids = {str(row["task"]["task_id"]) for row in test_rows}
    gold_task_ids = {str(row["task_id"]) for row in test_gold_rows}

    public_payload = canonical_jsonl_bytes([*train_rows, *test_rows]).decode("utf-8")
    sensitive_tokens = sorted(
        test_report_ids
        | test_entry_ids
        | test_vuln_ids
        | test_sources
        | {str(item["vuln_title"]) for item in test_advisories},
        key=lambda value: (-len(value), value),
    )
    exposed_tokens = [token for token in sensitive_tokens if token and token in public_payload]

    checks = [
        _check("exact_train_task_count", len(train_rows) == 50, f"count={len(train_rows)}"),
        _check("exact_test_task_count", len(test_rows) == 20, f"count={len(test_rows)}"),
        _check(
            "test_gold_task_count",
            len(test_gold_rows) == 20,
            f"count={len(test_gold_rows)}",
        ),
        _check(
            "test_task_gold_bijection",
            test_task_ids == gold_task_ids and len(test_task_ids) == len(test_rows),
            "public test task IDs equal private gold task IDs one-to-one",
        ),
        _check(
            "advisory_disjoint",
            not (train_report_ids & test_report_ids),
            f"train={len(train_report_ids)}, test={len(test_report_ids)}, overlap={len(train_report_ids & test_report_ids)}",
        ),
        _check(
            "entry_disjoint",
            not (train_entry_ids & test_entry_ids),
            f"train={len(train_entry_ids)}, test={len(test_entry_ids)}, overlap={len(train_entry_ids & test_entry_ids)}",
        ),
        _check(
            "vulnerability_identifier_disjoint",
            not (train_vuln_ids & test_vuln_ids),
            f"overlap={len(train_vuln_ids & test_vuln_ids)}",
        ),
        _check(
            "source_link_disjoint",
            not (train_sources & test_sources),
            f"overlap={len(train_sources & test_sources)}",
        ),
        _check(
            "repository_commit_snapshot_disjoint",
            not (train_snapshots & test_snapshots),
            f"overlap={len(train_snapshots & test_snapshots)}",
        ),
        _check(
            "role_aware_endpoint_disjoint_without_commit",
            not (train_location_fingerprints & test_location_fingerprints),
            f"overlap={len(train_location_fingerprints & test_location_fingerprints)}",
        ),
        _check(
            "role_aware_endpoint_disjoint_exact_snapshot",
            not (train_exact_fingerprints & test_exact_fingerprints),
            f"overlap={len(train_exact_fingerprints & test_exact_fingerprints)}",
        ),
        _check(
            "all_gold_node_locations_disjoint_without_commit",
            not (train_node_locations & test_node_locations),
            f"overlap={len(train_node_locations & test_node_locations)}",
        ),
        _check(
            "normalized_gold_code_disjoint",
            not (train_node_code & test_node_code),
            f"minimum_normalized_characters={minimum_code_characters}, overlap={len(train_node_code & test_node_code)}",
        ),
        _check(
            "public_test_forbidden_fields_absent",
            not (public_test_keys & FORBIDDEN_TEST_KEYS),
            f"forbidden_key_count={len(public_test_keys & FORBIDDEN_TEST_KEYS)}",
        ),
        _check(
            "test_gold_tokens_absent_from_public_datasets",
            not exposed_tokens,
            f"exposed_token_count={len(exposed_tokens)}",
        ),
        _check(
            "all_gold_entries_human_verified",
            all(item.get("verify") == 1 for item in [*train_entries, *test_entries]),
            f"gold_entries={len(train_entries) + len(test_entries)}",
        ),
        _check(
            "private_output_outside_public_root",
            not private_root.resolve().is_relative_to(
                (output_root / "public").resolve()
            )
            and not (output_root / "public").resolve().is_relative_to(
                private_root.resolve()
            ),
            "private output is not contained by the public output and vice versa",
        ),
        _check(
            "private_gold_gitignore_rule_present",
            "/benchmarks/vulngym_50_20_v1/private/*"
            in (repo_root / ".gitignore").read_text(encoding="utf-8"),
            "repository .gitignore contains the evaluator-only path rule",
        ),
    ]
    status = "pass" if all(item["status"] == "pass" for item in checks) else "fail"
    return {
        "checks": checks,
        "dataset_id": "vulngym-50-20-v1",
        "isolation_scope": "artifact-and-runtime",
        "limitations": [
            "The upstream VulnGym annotations and GitHub advisories are public; this split cannot make those facts information-theoretically secret.",
            "A closed-book evaluation must deny the agent access to this checkout, data/, private/, evaluator logs, and the Internet.",
            "Directory separation in one readable checkout is not an access-control boundary; mount or copy only public/test.jsonl and the target source snapshot.",
        ],
        "schema_version": SCHEMA_VERSION,
        "status": status,
    }


def _split_summary(keys: Iterable[str], by_key: Mapping[str, SnapshotTask]) -> dict[str, int]:
    selected = [by_key[key] for key in keys]
    return {
        "advisories": sum(len(item.advisories) for item in selected),
        "entries": sum(item.entry_count for item in selected),
        "repositories": len({item.repo_url for item in selected}),
        "snapshot_tasks": len(selected),
    }


def _mean_absolute_rate_error(
    actual: Mapping[str, int], population: Mapping[str, int], size: int, universe_size: int
) -> float:
    if not population:
        return 0.0
    return sum(
        abs(actual.get(label, 0) / size - count / universe_size)
        for label, count in population.items()
    ) / len(population)


def build_stratification_report(
    tasks: Sequence[SnapshotTask],
    selection: Selection,
    objective: MarginalObjective,
    sampling: Mapping[str, Any],
    population: SourcePopulation,
) -> dict[str, Any]:
    by_key = {task.key: task for task in tasks}
    train_set = set(selection.train_keys)
    test_set = set(selection.test_keys)
    selected_set = train_set | test_set
    dimensions: dict[str, list[dict[str, Any]]] = {}
    dimension_metrics: dict[str, dict[str, float]] = {}
    for dimension in ("language", "vuln_category_l1", "repository"):
        labels = sorted(label for dim, label in objective.features if dim == dimension)
        population_counts: Counter[str] = Counter()
        train_counts: Counter[str] = Counter()
        test_counts: Counter[str] = Counter()
        selected_counts: Counter[str] = Counter()
        for task in tasks:
            values = {
                label
                for dim, label in task_features(task)
                if dim == dimension
            }
            population_counts.update(values)
            if task.key in train_set:
                train_counts.update(values)
            if task.key in test_set:
                test_counts.update(values)
            if task.key in selected_set:
                selected_counts.update(values)
        rows: list[dict[str, Any]] = []
        for label in labels:
            pop_count = population_counts[label]
            rows.append(
                {
                    "label": label,
                    "selected": selected_counts[label],
                    "selected_target": round(
                        pop_count * (len(selected_set) / len(tasks)), 6
                    ),
                    "test": test_counts[label],
                    "test_target": round(pop_count * (len(test_set) / len(tasks)), 6),
                    "train": train_counts[label],
                    "train_target": round(pop_count * (len(train_set) / len(tasks)), 6),
                    "universe": pop_count,
                }
            )
        dimensions[dimension] = rows
        dimension_metrics[dimension] = {
            "selected_mean_absolute_rate_error": round(
                _mean_absolute_rate_error(
                    selected_counts, population_counts, len(selected_set), len(tasks)
                ),
                8,
            ),
            "test_mean_absolute_rate_error": round(
                _mean_absolute_rate_error(
                    test_counts, population_counts, len(test_set), len(tasks)
                ),
                8,
            ),
            "train_mean_absolute_rate_error": round(
                _mean_absolute_rate_error(
                    train_counts, population_counts, len(train_set), len(tasks)
                ),
                8,
            ),
        }

    primary_population = Counter(task.primary_language for task in tasks)
    primary_train = Counter(by_key[key].primary_language for key in train_set)
    primary_test = Counter(by_key[key].primary_language for key in test_set)
    primary_language = [
        {
            "label": label,
            "test": primary_test[label],
            "train": primary_train[label],
            "universe": primary_population[label],
        }
        for label in sorted(primary_population)
    ]

    selected_counts_vector = objective.counts(selected_set)
    train_counts_vector = objective.counts(train_set)
    test_counts_vector = objective.counts(test_set)
    coverage = {
        "selected_missing_required_labels": len(
            objective.missing_required_coverage(
                selected_counts_vector, len(selected_set)
            )
        ),
        "test_missing_required_labels": len(
            objective.missing_required_coverage(test_counts_vector, len(test_set))
        ),
        "train_missing_required_labels": len(
            objective.missing_required_coverage(train_counts_vector, len(train_set))
        ),
    }
    return {
        "coverage": coverage,
        "dataset_id": sampling["dataset_id"],
        "dimensions": dimensions,
        "language_derivation": {
            "detailed_endpoint_labels_are_available_in_primary_language_audit": True,
            "sampling_groups": ["Go", "Python", "TypeScript", "Other"],
            "sampling_uses_primary_language": True,
            "source_fields": ["entry_point.file", "critical_operation.file"],
            "unknown_extensions": "Other",
        },
        "metrics": dimension_metrics,
        "objective": {
            "algorithm": sampling["algorithm"],
            "coverage_expected_count_threshold": sampling[
                "coverage_expected_count_threshold"
            ],
            "iterations": selection.iterations,
            "restarts": sampling["restarts"],
            "score": round(selection.objective, 12),
            "selected_restart": selection.restart,
        },
        "primary_language": primary_language,
        "schema_version": SCHEMA_VERSION,
        "splits": {
            "selected": _split_summary(selected_set, by_key),
            "test": _split_summary(test_set, by_key),
            "train": _split_summary(train_set, by_key),
            "universe": {
                "advisories": population.eligible_advisories,
                "entries": population.eligible_entries,
                "repositories": len({task.repo_url for task in tasks}),
                "snapshot_tasks": population.eligible_snapshot_tasks,
            },
        },
        "stratification_axes": [
            "language (multi-label task incidence)",
            "vuln_category_l1 (multi-label task incidence)",
            "repository (repo_url task incidence)",
        ],
    }


def validate_json_schema(
    schema: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    expected_kind: str,
    path: str,
) -> dict[str, Any]:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise BuildError(
            "jsonschema is required for formal validation; install "
            "benchmarks/vulngym_50_20_v1/requirements.txt"
        ) from exc
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    errors: list[str] = []
    for line_number, row in enumerate(rows, 1):
        if row.get("kind") != expected_kind:
            errors.append(
                f"line {line_number}: expected kind {expected_kind!r}, got {row.get('kind')!r}"
            )
            continue
        for error in sorted(validator.iter_errors(row), key=lambda item: list(item.path)):
            location = ".".join(str(part) for part in error.path) or "$"
            errors.append(f"line {line_number} {location}: {error.message}")
    return {
        "errors": errors,
        "expected_kind": expected_kind,
        "path": path,
        "rows": len(rows),
        "status": "pass" if not errors else "fail",
    }


def validate_manifest_schema(
    schema: Mapping[str, Any], manifest: Mapping[str, Any], path: str
) -> dict[str, Any]:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise BuildError(
            "jsonschema is required for formal validation; install "
            "benchmarks/vulngym_50_20_v1/requirements.txt"
        ) from exc
    Draft202012Validator.check_schema(schema)
    errors = [
        f"{'.'.join(str(part) for part in error.path) or '$'}: {error.message}"
        for error in sorted(
            Draft202012Validator(schema).iter_errors(manifest),
            key=lambda item: list(item.path),
        )
    ]
    return {
        "errors": errors,
        "path": path,
        "rows": 1,
        "status": "pass" if not errors else "fail",
    }


def build_cross_record_checks(
    train_rows: Sequence[dict[str, Any]],
    test_rows: Sequence[dict[str, Any]],
    test_gold_rows: Sequence[dict[str, Any]],
    entries_by_report: Mapping[str, Sequence[dict[str, Any]]],
) -> list[dict[str, Any]]:
    all_gold_rows = [*train_rows, *test_gold_rows]
    all_advisories = _gold_advisories(all_gold_rows)
    all_entries = _gold_entries(all_gold_rows)
    report_counts = Counter(str(item["report_id"]) for item in all_advisories)
    task_ids = [
        *(str(row["task"]["task_id"]) for row in train_rows),
        *(str(row["task"]["task_id"]) for row in test_rows),
    ]
    complete = True
    for advisory in all_advisories:
        report_id = str(advisory["report_id"])
        expected = canonical_jsonl_bytes(
            sorted(entries_by_report[report_id], key=lambda item: item["entry_id"])
        )
        actual = canonical_jsonl_bytes(advisory["verified_entries"])
        if expected != actual:
            complete = False
            break
    checks = [
        _check("train_rows", len(train_rows) == 50, f"count={len(train_rows)}"),
        _check("test_rows", len(test_rows) == 20, f"count={len(test_rows)}"),
        _check(
            "private_gold_rows",
            len(test_gold_rows) == 20,
            f"count={len(test_gold_rows)}",
        ),
        _check(
            "task_ids_unique",
            len(task_ids) == len(set(task_ids)),
            f"count={len(task_ids)}, unique={len(set(task_ids))}",
        ),
        _check(
            "selected_advisories_unique",
            all(count == 1 for count in report_counts.values()),
            f"advisories={len(report_counts)}",
        ),
        _check(
            "selected_advisories_complete",
            complete,
            "every selected advisory contains exactly all of its source entries",
        ),
        _check(
            "all_selected_entries_verify_1",
            all(item.get("verify") == 1 for item in all_entries),
            f"entries={len(all_entries)}",
        ),
    ]
    return checks


def artifact_descriptor(path: str, payload: bytes, rows: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "bytes": len(payload),
        "path": path,
        "sha256": sha256_bytes(payload),
    }
    if rows is not None:
        result["rows"] = rows
    return result


def build_public_manifest(
    repo_root: Path,
    definition_root: Path,
    pinned_sources: Mapping[str, dict[str, Any]],
    population: SourcePopulation,
    sampling: Mapping[str, Any],
    train_bytes: bytes,
    test_bytes: bytes,
) -> dict[str, Any]:
    artifacts = [
        artifact_descriptor(
            "benchmarks/vulngym_50_20_v1/public/train.jsonl", train_bytes, 50
        ),
        artifact_descriptor(
            "benchmarks/vulngym_50_20_v1/public/test.jsonl", test_bytes, 20
        ),
    ]
    for relative in PUBLIC_STATIC_FILES:
        path = repo_root / Path(relative)
        if relative.startswith("benchmarks/vulngym_50_20_v1/"):
            suffix = Path(relative).relative_to(BENCHMARK_RELATIVE)
            path = definition_root / suffix
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise BuildError(f"cannot hash build material {path}: {exc}") from exc
        artifacts.append(artifact_descriptor(relative, payload))
    artifacts.sort(key=lambda item: item["path"])
    return {
        "artifacts": artifacts,
        "build": {
            "algorithm": sampling["algorithm"],
            "dataset_id": sampling["dataset_id"],
            "eligibility_policy": "advisory-complete verify=1 and snapshot-complete; task unit is repo_url+commit",
            "sampling_seed": sampling["sampling_seed"],
            "task_unit": "repo_url+commit snapshot",
            "test_tasks": sampling["test_tasks"],
            "train_tasks": sampling["train_tasks"],
        },
        "license": {
            "name": "CC-BY-4.0",
            "notice": "See benchmarks/vulngym_50_20_v1/NOTICE.md; upstream source snippets may carry separate project licenses.",
            "path": "LICENSE",
        },
        "schema_version": SCHEMA_VERSION,
        "source": {
            "files": [pinned_sources[key] for key in sorted(pinned_sources)],
            "repository": SOURCE_REPOSITORY,
            "revision": SOURCE_REVISION,
            "tag": SOURCE_TAG,
            "visibility": "public",
        },
        "source_population": {
            "eligible_advisories": population.eligible_advisories,
            "eligible_entries": population.eligible_entries,
            "eligible_snapshot_tasks": population.eligible_snapshot_tasks,
            "fully_verified_advisories": population.fully_verified_advisories,
            "verified_entries": population.verified_entries,
        },
    }


def build_schema_report(
    record_results: Sequence[dict[str, Any]],
    manifest_result: dict[str, Any],
    cross_checks: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    passed = all(item["status"] == "pass" for item in record_results)
    passed = passed and manifest_result["status"] == "pass"
    passed = passed and all(item["status"] == "pass" for item in cross_checks)
    return {
        "cross_record_checks": list(cross_checks),
        "dataset_id": "vulngym-50-20-v1",
        "engine": {
            "draft": "2020-12",
            "name": "jsonschema",
            "requirements": "benchmarks/vulngym_50_20_v1/requirements.txt",
        },
        "files": [*record_results, manifest_result],
        "schema_version": SCHEMA_VERSION,
        "status": "pass" if passed else "fail",
    }


def checksum_lines(
    repo_root: Path,
    definition_root: Path,
    generated_public: Mapping[str, bytes],
) -> bytes:
    items: dict[str, bytes] = dict(generated_public)
    for relative in PUBLIC_STATIC_FILES:
        path = repo_root / Path(relative)
        if relative.startswith("benchmarks/vulngym_50_20_v1/"):
            path = definition_root / Path(relative).relative_to(BENCHMARK_RELATIVE)
        items[relative] = path.read_bytes()
    lines = [f"{sha256_bytes(payload)}  {path}" for path, payload in sorted(items.items())]
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_private_manifest(
    private_payloads: Mapping[str, bytes], public_checksums: bytes
) -> dict[str, Any]:
    return {
        "artifacts": [
            artifact_descriptor(path, payload, 20 if path.endswith("test_gold.jsonl") else None)
            for path, payload in sorted(private_payloads.items())
        ],
        "dataset_id": "vulngym-50-20-v1",
        "public_sha256s_sha256": sha256_bytes(public_checksums),
        "schema_version": SCHEMA_VERSION,
        "visibility": "evaluator-only",
        "warning": "Never mount private artifacts or the source VulnGym checkout into an evaluated agent sandbox.",
    }


def _format_jsonschema_failures(results: Sequence[Mapping[str, Any]]) -> str:
    failures: list[str] = []
    for result in results:
        for error in result.get("errors", []):
            failures.append(f"{result.get('path')}: {error}")
    return "\n".join(failures)


def build_all_artifacts(
    repo_root: Path,
    definition_root: Path,
    output_root: Path,
    private_root: Path,
) -> dict[Path, bytes]:
    pinned_sources = verify_pinned_sources(repo_root)
    language_config = load_json(definition_root / "config/language_extensions.json")
    sampling = load_json(definition_root / "config/sampling.json")
    if sampling.get("schema_version") != SCHEMA_VERSION:
        raise BuildError("unsupported sampling config schema_version")
    if sampling.get("algorithm") != "deterministic-marginal-local-search-v1":
        raise BuildError("unsupported sampling algorithm")

    entries = load_jsonl(repo_root / "data/entries.jsonl")
    reports = load_jsonl(repo_root / "data/reports.jsonl")
    tasks, population, entries_by_report = build_source_universe(
        entries, reports, language_config
    )
    selection, objective = select_tasks(tasks, sampling)
    train_rows, test_rows, test_gold_rows, selection_lock = build_records(
        tasks, selection, sampling
    )

    train_bytes = canonical_jsonl_bytes(train_rows)
    test_bytes = canonical_jsonl_bytes(test_rows)
    test_gold_bytes = canonical_jsonl_bytes(test_gold_rows)
    selection_lock_bytes = canonical_json_bytes(selection_lock)

    record_schema = load_json(definition_root / "schemas/benchmark-record.schema.json")
    manifest_schema = load_json(definition_root / "schemas/public-manifest.schema.json")
    record_results = [
        validate_json_schema(
            record_schema,
            train_rows,
            "training_example",
            "benchmarks/vulngym_50_20_v1/public/train.jsonl",
        ),
        validate_json_schema(
            record_schema,
            test_rows,
            "test_task",
            "benchmarks/vulngym_50_20_v1/public/test.jsonl",
        ),
        validate_json_schema(
            record_schema,
            test_gold_rows,
            "test_gold",
            "benchmarks/vulngym_50_20_v1/private/test_gold.jsonl",
        ),
    ]
    cross_checks = build_cross_record_checks(
        train_rows, test_rows, test_gold_rows, entries_by_report
    )
    schema_failures = _format_jsonschema_failures(record_results)
    if schema_failures:
        raise BuildError(f"record schema validation failed:\n{schema_failures}")
    failed_cross = [item for item in cross_checks if item["status"] != "pass"]
    if failed_cross:
        raise BuildError(f"cross-record validation failed: {failed_cross}")

    leakage_report = build_leakage_report(
        train_rows,
        test_rows,
        test_gold_rows,
        repo_root,
        output_root,
        private_root,
        int(sampling["leakage_code_min_normalized_chars"]),
    )
    if leakage_report["status"] != "pass":
        failed = [
            item for item in leakage_report["checks"] if item["status"] != "pass"
        ]
        raise BuildError(f"leakage checks failed: {failed}")
    stratification_report = build_stratification_report(
        tasks, selection, objective, sampling, population
    )
    public_manifest = build_public_manifest(
        repo_root,
        definition_root,
        pinned_sources,
        population,
        sampling,
        train_bytes,
        test_bytes,
    )
    manifest_result = validate_manifest_schema(
        manifest_schema,
        public_manifest,
        "benchmarks/vulngym_50_20_v1/manifests/source_and_hash_manifest.json",
    )
    if manifest_result["status"] != "pass":
        raise BuildError(
            "manifest schema validation failed:\n"
            + _format_jsonschema_failures([manifest_result])
        )
    schema_report = build_schema_report(record_results, manifest_result, cross_checks)

    public_generated: dict[str, bytes] = {
        "benchmarks/vulngym_50_20_v1/manifests/source_and_hash_manifest.json": canonical_json_bytes(
            public_manifest
        ),
        "benchmarks/vulngym_50_20_v1/public/test.jsonl": test_bytes,
        "benchmarks/vulngym_50_20_v1/public/train.jsonl": train_bytes,
        "benchmarks/vulngym_50_20_v1/reports/leakage_check.json": canonical_json_bytes(
            leakage_report
        ),
        "benchmarks/vulngym_50_20_v1/reports/schema_validation.json": canonical_json_bytes(
            schema_report
        ),
        "benchmarks/vulngym_50_20_v1/reports/stratification.json": canonical_json_bytes(
            stratification_report
        ),
    }
    public_checksums = checksum_lines(repo_root, definition_root, public_generated)
    public_generated[
        "benchmarks/vulngym_50_20_v1/manifests/SHA256SUMS"
    ] = public_checksums

    private_payloads = {
        "benchmarks/vulngym_50_20_v1/private/selection_lock.json": selection_lock_bytes,
        "benchmarks/vulngym_50_20_v1/private/test_gold.jsonl": test_gold_bytes,
    }
    private_manifest = build_private_manifest(private_payloads, public_checksums)
    private_payloads[
        "benchmarks/vulngym_50_20_v1/private/private_manifest.json"
    ] = canonical_json_bytes(private_manifest)

    outputs: dict[Path, bytes] = {}
    for relative, payload in public_generated.items():
        relative_to_benchmark = Path(relative).relative_to(BENCHMARK_RELATIVE)
        outputs[output_root / relative_to_benchmark] = payload
    for relative, payload in private_payloads.items():
        outputs[private_root / Path(relative).name] = payload
    return outputs


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def write_artifacts(outputs: Mapping[Path, bytes]) -> None:
    for path, payload in sorted(outputs.items(), key=lambda item: item[0].as_posix()):
        _atomic_write(path, payload)


def verify_artifacts(outputs: Mapping[Path, bytes]) -> list[str]:
    mismatches: list[str] = []
    for path, expected in sorted(outputs.items(), key=lambda item: item[0].as_posix()):
        try:
            actual = path.read_bytes()
        except OSError as exc:
            mismatches.append(f"{path}: cannot read: {exc}")
            continue
        if actual != expected:
            mismatches.append(
                f"{path}: expected sha256={sha256_bytes(expected)}, "
                f"got sha256={sha256_bytes(actual)}"
            )
    return mismatches


def _verify_directory_allowlist(
    root: Path, allowed: set[str], label: str
) -> list[str]:
    if not root.exists():
        return [f"{label} directory is missing: {root}"]
    actual = {
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
    }
    errors = [
        f"unexpected {label} file: {item}" for item in sorted(actual - allowed)
    ]
    errors.extend(f"missing {label} file: {item}" for item in sorted(allowed - actual))
    return errors


def verify_output_allowlists(
    output_root: Path, definition_root: Path, private_root: Path
) -> list[str]:
    errors: list[str] = []
    errors.extend(
        _verify_directory_allowlist(
            output_root / "public", {"test.jsonl", "train.jsonl"}, "public dataset"
        )
    )
    errors.extend(
        _verify_directory_allowlist(
            output_root / "manifests",
            {"SHA256SUMS", "source_and_hash_manifest.json"},
            "manifest",
        )
    )
    errors.extend(
        _verify_directory_allowlist(
            output_root / "reports",
            {"leakage_check.json", "schema_validation.json", "stratification.json"},
            "report",
        )
    )
    default_private_root = output_root / "private"
    private_allowed = {"private_manifest.json", "selection_lock.json", "test_gold.jsonl"}
    if private_root.resolve() == default_private_root.resolve():
        if definition_root.resolve() == output_root.resolve():
            private_allowed.add("README.md")
        errors.extend(
            _verify_directory_allowlist(private_root, private_allowed, "private artifact")
        )
    else:
        errors.extend(
            _verify_directory_allowlist(private_root, private_allowed, "private artifact")
        )
        if default_private_root.exists():
            errors.extend(
                _verify_directory_allowlist(
                    default_private_root,
                    {"README.md"} if definition_root.resolve() == output_root.resolve() else set(),
                    "default private staging",
                )
            )
    return errors


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=repo_root,
        help="VulnGym checkout containing pinned data/ (default: script parent)",
    )
    parser.add_argument(
        "--definition-root",
        type=Path,
        default=repo_root / BENCHMARK_RELATIVE,
        help="directory containing config/ and schemas/",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=repo_root / BENCHMARK_RELATIVE,
        help="destination benchmark directory",
    )
    parser.add_argument(
        "--private-output-root",
        type=Path,
        help="evaluator-only destination (default: <output-root>/private)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="rebuild in memory and verify byte-for-byte outputs without writing",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = args.repo_root.resolve()
    definition_root = args.definition_root.resolve()
    output_root = args.output_root.resolve()
    private_root = (
        args.private_output_root.resolve()
        if args.private_output_root is not None
        else output_root / "private"
    )
    try:
        outputs = build_all_artifacts(
            repo_root, definition_root, output_root, private_root
        )
        if args.check:
            mismatches = verify_artifacts(outputs)
            mismatches.extend(
                verify_output_allowlists(output_root, definition_root, private_root)
            )
            if mismatches:
                for item in mismatches:
                    print(f"ERROR: {item}", file=sys.stderr)
                return 1
            print(f"PASS: {len(outputs)} generated artifacts are byte-for-byte reproducible")
            return 0
        write_artifacts(outputs)
        allowlist_errors = verify_output_allowlists(
            output_root, definition_root, private_root
        )
        if allowlist_errors:
            for item in allowlist_errors:
                print(f"ERROR: {item}", file=sys.stderr)
            return 1
        print(
            "Built VulnGym 50/20 split: "
            f"{output_root / 'public/train.jsonl'} (50), "
            f"{output_root / 'public/test.jsonl'} (20)"
        )
        print(f"Evaluator-only gold: {private_root / 'test_gold.jsonl'}")
        return 0
    except BuildError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
