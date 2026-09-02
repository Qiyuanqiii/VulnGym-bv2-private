"""Prepare a small, cleared public-input batch for the Lane A materializer.

This is the explicit network pre-step described by
``docs/lane_a_assignment_materializer_runbook.md``.  It reads answer-free
public task identities and the ten-field public report index, fetches only the
requested GitHub advisories with ``gh api``, and immediately reduces every
response to the materializer's five-field cache contract.  Raw API responses
are never written to disk.

The output is a new directory containing exactly ``tasks.jsonl``,
``reports.jsonl``, ``ghsa-cache.jsonl``, and ``repos.json``.  Publication is a
same-parent atomic no-replace rename.  The canonical input pins and a compact
summary are emitted as one JSON object on stdout.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any, Callable, Final, Mapping, Sequence
import uuid


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vulngym_agent.benchmark.contracts import BenchmarkContractError, BenchmarkTask
from vulngym_agent.benchmark.snapshot_batch import (
    SnapshotBatchError,
    _canonical_existing_path,
    _canonical_new_child,
    _windows_extended_path,
)
from vulngym_agent.lane_a_assignment_materializer import (
    _parse_advisory,
    _parse_report,
    compute_lane_a_assignment_input_pins,
)
from vulngym_agent.lane_a_task_bundle import (
    LaneATaskBundleError,
    _assert_chain,
    _directory_identity,
    _guard_chain,
    _is_reparse,
    _line,
    _read_regular,
    _rename_noreplace,
)
from vulngym_agent.tools.git import GitFactError, GitRepository, GitStorageSeal
from vulngym_agent.trusted_inputs import paths_overlap_v1


CONTRACT_VERSION: Final[int] = 1
KIND: Final[str] = "vulngym.lane-a-public-batch-preparation.v1"
TASKS_FILENAME: Final[str] = "tasks.jsonl"
REPORTS_FILENAME: Final[str] = "reports.jsonl"
GHSA_CACHE_FILENAME: Final[str] = "ghsa-cache.jsonl"
REPOS_FILENAME: Final[str] = "repos.json"
OUTPUT_FILENAMES: Final[frozenset[str]] = frozenset(
    {TASKS_FILENAME, REPORTS_FILENAME, GHSA_CACHE_FILENAME, REPOS_FILENAME}
)

_MAX_INPUT_BYTES: Final[int] = 64 * 1024 * 1024
_MAX_LINE_BYTES: Final[int] = 2 * 1024 * 1024
_MAX_RECORDS: Final[int] = 100_000
_MAX_API_BYTES: Final[int] = 2 * 1024 * 1024
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_COMMIT_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"https://github\.com/"
    r"([A-Za-z0-9][A-Za-z0-9_.-]{0,99})/"
    r"([A-Za-z0-9][A-Za-z0-9_.-]{0,99})/commit/([0-9A-Fa-f]{40})\Z"
)
_FORBIDDEN_PATH_MARKERS: Final[frozenset[str]] = frozenset(
    {"gold", "private", "selection_lock", "selection-lock", "source-map", "source_map"}
)


class LaneAPublicBatchError(RuntimeError):
    """Stable, path-free failure raised by this preparation boundary."""

    def __init__(self, code: str, message: str, *, committed: bool = False) -> None:
        self.code = code if isinstance(code, str) and code else "operation_failed"
        self.committed = committed is True
        super().__init__(message)


class _DuplicateKey(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _RepositoryState:
    repo_url: str
    path: Path
    repository: GitRepository
    seal: GitStorageSeal


AdvisoryFetcher = Callable[[str], Mapping[str, Any]]


def _error(code: str, message: str, *, committed: bool = False) -> LaneAPublicBatchError:
    return LaneAPublicBatchError(code, message, committed=committed)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _validate_json(value: Any, *, depth: int = 0, allow_floats: bool = False) -> None:
    if depth > 32:
        raise ValueError("JSON nesting is too deep")
    if value is None or type(value) in {bool, int, str}:
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON number is not finite")
        if not allow_floats:
            raise ValueError("floating-point JSON values are not accepted")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json(item, depth=depth + 1, allow_floats=allow_floats)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON key is not a string")
            _validate_json(item, depth=depth + 1, allow_floats=allow_floats)
        return
    raise ValueError("JSON value has an unsupported type")


def _parse_json_bytes(
    payload: bytes, *, label: str, allow_floats: bool = False
) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _item: (_ for _ in ()).throw(ValueError()),
        )
        _validate_json(value, allow_floats=allow_floats)
    except (
        UnicodeError,
        json.JSONDecodeError,
        _DuplicateKey,
        RecursionError,
        TypeError,
        ValueError,
    ):
        raise _error("invalid_json", f"{label} is not strict JSON") from None
    if not isinstance(value, dict):
        raise _error("invalid_json", f"{label} is not a JSON object")
    return value


def _read_jsonl(path: Path, *, label: str) -> tuple[Path, bytes, tuple[dict[str, Any], ...]]:
    _reject_forbidden_path(path)
    try:
        canonical, payload = _read_regular(path, maximum=_MAX_INPUT_BYTES)
    except LaneATaskBundleError as exc:
        raise _error(exc.code, f"{label} input is unavailable or unsafe") from None
    if not payload.endswith(b"\n") or payload.endswith(b"\r\n"):
        raise _error("invalid_framing", f"{label} must use LF-terminated JSONL")
    lines = payload.splitlines(keepends=True)
    if not 1 <= len(lines) <= _MAX_RECORDS:
        raise _error("invalid_count", f"{label} record count is invalid")
    values: list[dict[str, Any]] = []
    for line in lines:
        if len(line) > _MAX_LINE_BYTES or not line.endswith(b"\n") or line == b"\n":
            raise _error("invalid_framing", f"{label} contains an invalid line")
        values.append(_parse_json_bytes(line[:-1], label=label))
    return canonical, payload, tuple(values)


def _reject_forbidden_path(path: Path) -> None:
    parts = {
        part.casefold()
        for part in re.split(r"[\\/]", os.path.abspath(os.fspath(path)))
        if part not in {"", "."}
    }
    if any(
        part == "private"
        or any(
            marker in part
            for marker in _FORBIDDEN_PATH_MARKERS - {"private"}
        )
        for part in parts
    ):
        raise _error("forbidden_input", "a forbidden data/control path was supplied")


def _load_public_tasks(
    path: Path, task_ids: Sequence[str]
) -> tuple[Path, bytes, tuple[BenchmarkTask, ...]]:
    if (
        not task_ids
        or len(task_ids) > _MAX_RECORDS
        or len(set(task_ids)) != len(task_ids)
        or any(not isinstance(item, str) or _TASK_ID_RE.fullmatch(item) is None for item in task_ids)
    ):
        raise _error("task_ids_invalid", "explicit task identifiers are invalid or repeat")
    canonical, wire, values = _read_jsonl(path, label="public tasks")
    parsed: list[BenchmarkTask] = []
    try:
        parsed = [BenchmarkTask.from_dict(value) for value in values]
    except (BenchmarkContractError, TypeError, ValueError):
        raise _error("public_task_invalid", "the public task file is invalid") from None
    by_id: dict[str, BenchmarkTask] = {}
    snapshots: set[tuple[str, str]] = set()
    for task in parsed:
        key = (task.repo_url.casefold(), task.commit)
        if task.task_id in by_id or key in snapshots:
            raise _error("public_task_duplicate", "the public task file repeats an identity")
        by_id[task.task_id] = task
        snapshots.add(key)
    missing = sorted(set(task_ids) - set(by_id))
    if missing:
        raise _error("task_missing", "an explicitly requested task is absent")
    selected = tuple(sorted((by_id[item] for item in task_ids), key=lambda item: item.task_id))
    if len({task.split for task in selected}) != 1:
        raise _error("split_mismatch", "the selected tasks mix benchmark splits")
    return canonical, wire, selected


def _load_public_reports(
    path: Path, tasks: Sequence[BenchmarkTask]
) -> tuple[Path, bytes, tuple[dict[str, Any], ...], dict[str, tuple[dict[str, Any], ...]]]:
    canonical, wire, values = _read_jsonl(path, label="public reports")
    reports: list[dict[str, Any]] = []
    try:
        for value in values:
            reports.append(_parse_report(value).to_dict())
    except LaneATaskBundleError as exc:
        raise _error(exc.code, "the public report file is invalid") from None
    if len({item["report_id"] for item in reports}) != len(reports):
        raise _error("report_duplicate", "the public report file repeats a report")
    all_entries = [entry for report in reports for entry in report["entry_ids"]]
    if len(all_entries) != len(set(all_entries)):
        raise _error("report_duplicate", "public entry identifiers repeat")

    selected: list[dict[str, Any]] = []
    by_task: dict[str, tuple[dict[str, Any], ...]] = {}
    for task in tasks:
        matches = tuple(
            sorted(
                (
                    report
                    for report in reports
                    if report["repo_url"].casefold() == task.repo_url.casefold()
                    and report["commit"] == task.commit
                ),
                key=lambda item: item["report_id"],
            )
        )
        if not matches:
            raise _error("report_missing", "a requested task has no exact public report match")
        by_task[task.task_id] = matches
        selected.extend(matches)
    if len({item["report_id"] for item in selected}) != len(selected):
        raise _error("report_binding_invalid", "selected tasks share an advisory report")
    selected.sort(key=lambda item: item["report_id"])
    return canonical, wire, tuple(selected), by_task


def _gh_executable() -> str:
    candidate = shutil.which("gh")
    if not candidate:
        raise _error("gh_unavailable", "the GitHub CLI is unavailable")
    try:
        return str(Path(candidate).resolve(strict=True))
    except (OSError, RuntimeError):
        raise _error("gh_unavailable", "the GitHub CLI cannot be resolved") from None


def _fetch_advisory(ghsa_id: str) -> Mapping[str, Any]:
    command = [
        _gh_executable(),
        "api",
        "--hostname",
        "github.com",
        "-H",
        "Accept: application/vnd.github+json",
        f"/advisories/{ghsa_id}",
    ]
    environment = dict(os.environ)
    environment.update({"GH_PAGER": "cat", "NO_COLOR": "1"})
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise _error("gh_failed", "the public advisory request failed") from None
    if result.returncode != 0:
        raise _error("gh_failed", "the public advisory request failed")
    if not 1 <= len(result.stdout) <= _MAX_API_BYTES:
        raise _error("gh_response_invalid", "the public advisory response size is invalid")
    return _parse_json_bytes(
        result.stdout, label="public advisory response", allow_floats=True
    )


def _reference_url(value: Any) -> str:
    if isinstance(value, str):
        result = value
    elif isinstance(value, dict) and isinstance(value.get("url"), str):
        result = value["url"]
    else:
        raise _error("gh_response_invalid", "a public advisory reference is invalid")
    if (
        not result.startswith("https://")
        or len(result) > 2048
        or result != result.strip()
        or "\x00" in result
        or any(ord(character) < 32 for character in result)
    ):
        raise _error("gh_response_invalid", "a public advisory reference is invalid")
    return result


def _sanitize_advisory(raw: Mapping[str, Any], expected_ghsa: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise _error("gh_response_invalid", "the public advisory response is invalid")
    raw_ghsa = raw.get("ghsa_id")
    description = raw.get("description")
    summary = raw.get("summary")
    identifiers = raw.get("identifiers")
    references = raw.get("references")
    if (
        not isinstance(raw_ghsa, str)
        or raw_ghsa.upper() != expected_ghsa
        or not isinstance(description, str)
        or not isinstance(summary, str)
        or not isinstance(identifiers, list)
        or not isinstance(references, list)
    ):
        raise _error("gh_response_invalid", "the public advisory response fields are invalid")

    identifier_pairs: set[tuple[str, str]] = set()
    for item in identifiers:
        if not isinstance(item, Mapping):
            raise _error("gh_response_invalid", "a public advisory identifier is invalid")
        kind = item.get("type")
        value = item.get("value")
        if not isinstance(kind, str) or not isinstance(value, str):
            raise _error("gh_response_invalid", "a public advisory identifier is invalid")
        kind = kind.upper()
        if kind not in {"GHSA", "CVE"}:
            continue
        identifier_pairs.add((kind, value.upper()))

    sanitized = {
        "description": description.strip(),
        "ghsa_id": expected_ghsa,
        "identifiers": [
            {"type": kind, "value": value}
            for kind, value in sorted(identifier_pairs)
        ],
        "references": sorted({_reference_url(item) for item in references}),
        "summary": summary.strip(),
    }
    try:
        return _parse_advisory(sanitized).to_dict()
    except LaneATaskBundleError as exc:
        raise _error(exc.code, "the sanitized public advisory is invalid") from None


def _load_repositories(
    local_repo_root: Path, tasks: Sequence[BenchmarkTask]
) -> tuple[Path, dict[str, _RepositoryState]]:
    _reject_forbidden_path(local_repo_root)
    try:
        root = _canonical_existing_path(local_repo_root, directory=True, status=2)
    except SnapshotBatchError:
        raise _error("repository_root_unsafe", "the local repository root is unsafe") from None
    states: dict[str, _RepositoryState] = {}
    for task in tasks:
        key = task.repo_url.casefold()
        if key in states:
            continue
        owner, name = task.repo_url.removeprefix("https://github.com/").split("/", 1)
        candidate = root / owner / f"{name}.git"
        try:
            path = _canonical_existing_path(candidate, directory=True, status=2)
            repository = GitRepository(path)
            seal = repository.assert_bare_storage_safe()
        except (SnapshotBatchError, GitFactError, OSError, ValueError):
            raise _error("repository_unsafe", "a required local bare repository is unsafe") from None
        states[key] = _RepositoryState(task.repo_url, path, repository, seal)
    for task in tasks:
        try:
            states[task.repo_url.casefold()].repository.commit_tree(task.commit)
        except GitFactError:
            raise _error("vulnerable_commit_missing", "a vulnerable commit is unavailable") from None
    return root, states


def _same_repo_candidates(advisory: Mapping[str, Any], repo_url: str) -> tuple[str, ...]:
    expected = repo_url.casefold()
    candidates: set[str] = set()
    for reference in advisory["references"]:
        match = _COMMIT_URL_RE.fullmatch(reference)
        if match is None:
            continue
        actual = f"https://github.com/{match.group(1)}/{match.group(2)}".casefold()
        if actual == expected:
            candidates.add(match.group(3).lower())
    return tuple(sorted(candidates))


def _validate_materializer_anchor(
    task: BenchmarkTask,
    report: Mapping[str, Any],
    advisory: Mapping[str, Any],
    repository: GitRepository,
) -> str:
    actual_identifiers = {item["value"] for item in advisory["identifiers"]}
    if actual_identifiers != set(report["vuln_ids"]):
        raise _error(
            "advisory_identifier_mismatch",
            "public advisory identifiers differ from the selected public report",
        )
    candidates = _same_repo_candidates(advisory, task.repo_url)
    if not candidates:
        raise _error(
            "fix_candidate_missing",
            "the selected advisory has no same-repository 40-hex commit reference",
        )
    matching: list[str] = []
    for candidate in candidates:
        try:
            parents = repository.commit_parents(candidate)
        except GitFactError:
            raise _error(
                "fix_candidate_unavailable",
                "a referenced fix commit is absent from the local bare repository",
            ) from None
        if parents == (task.commit,):
            matching.append(candidate)
    if len(matching) != 1:
        raise _error(
            "ambiguous_fix_candidate" if len(matching) > 1 else "fix_parent_mismatch",
            "the selected advisory has no unique single-parent fix for the vulnerable commit",
        )
    return matching[0]


def _canonical_wires(
    tasks: Sequence[BenchmarkTask],
    reports: Sequence[Mapping[str, Any]],
    advisories: Sequence[Mapping[str, Any]],
    repositories: Sequence[Mapping[str, str]],
) -> dict[str, bytes]:
    return {
        TASKS_FILENAME: b"".join(_line(task.to_dict()) for task in tasks),
        REPORTS_FILENAME: b"".join(_line(dict(report)) for report in reports),
        GHSA_CACHE_FILENAME: b"".join(_line(dict(advisory)) for advisory in advisories),
        REPOS_FILENAME: _line(
            {"contract_version": 1, "repositories": [dict(item) for item in repositories]}
        ),
    }


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(_windows_extended_path(path), flags, 0o600)
    try:
        consumed = 0
        while consumed < len(payload):
            written = os.write(descriptor, payload[consumed:])
            if written <= 0:
                raise OSError("short write")
            consumed += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_output_payloads(root: Path, *, committed: bool) -> dict[str, bytes]:
    code = "publication_uncertain" if committed else "publication_failed"
    try:
        entries = tuple(os.scandir(_windows_extended_path(root)))
    except OSError:
        raise _error(code, "publication output cannot be enumerated", committed=committed) from None
    if frozenset(entry.name for entry in entries) != OUTPUT_FILENAMES:
        raise _error(code, "publication output layout differs", committed=committed)
    result: dict[str, bytes] = {}
    for entry in entries:
        try:
            state = os.lstat(entry.path)
        except OSError:
            raise _error(code, "publication output changed", committed=committed) from None
        if (
            not stat.S_ISREG(state.st_mode)
            or stat.S_ISLNK(state.st_mode)
            or _is_reparse(state)
            or state.st_nlink != 1
        ):
            raise _error(code, "publication output contains an unsafe member", committed=committed)
        try:
            _path, payload = _read_regular(Path(entry.path), maximum=_MAX_INPUT_BYTES)
        except LaneATaskBundleError:
            raise _error(code, "publication output cannot be read", committed=committed) from None
        result[entry.name] = payload
    return result


def _preflight_output(
    output_dir: Path,
    *,
    protected_files: Sequence[Path],
    repository_root: Path,
) -> tuple[Path, tuple[tuple[Path, tuple[int, int]], ...]]:
    _reject_forbidden_path(output_dir)
    try:
        output = _canonical_new_child(output_dir, status=2)
    except SnapshotBatchError:
        raise _error("invalid_output", "the output path is invalid") from None
    try:
        os.lstat(_windows_extended_path(output))
    except FileNotFoundError:
        pass
    except OSError:
        raise _error("output_unavailable", "the output state is unavailable") from None
    else:
        raise _error("output_exists", "the output directory already exists")
    try:
        if paths_overlap_v1(output, repository_root, left_exists=False, right_directory=True):
            raise _error("path_overlap", "the output overlaps the repository store")
        for path in protected_files:
            if paths_overlap_v1(output, path, left_exists=False):
                raise _error("path_overlap", "the output overlaps a public input")
        guard = _guard_chain(output.parent, final_private=True)
    except (LaneATaskBundleError, SnapshotBatchError):
        raise _error("path_check_failed", "the output boundary cannot be verified") from None
    return output, guard


def _publish(
    output: Path,
    guard: tuple[tuple[Path, tuple[int, int]], ...],
    payloads: Mapping[str, bytes],
) -> dict[str, object]:
    staging = output.parent / f".{output.name}.lane-a-public-{uuid.uuid4().hex}"
    committed = False
    try:
        _assert_chain(guard, final_private=True)
        os.mkdir(_windows_extended_path(staging), 0o700)
        staging_identity = _directory_identity(os.lstat(_windows_extended_path(staging)))
        for name in sorted(OUTPUT_FILENAMES):
            _write_exclusive(staging / name, payloads[name])
        before = _read_output_payloads(staging, committed=False)
        if before != dict(payloads):
            raise _error("publication_failed", "staging readback differs")
        pins = compute_lane_a_assignment_input_pins(
            staging / TASKS_FILENAME,
            staging / REPORTS_FILENAME,
            staging / GHSA_CACHE_FILENAME,
            staging / REPOS_FILENAME,
        )
        _assert_chain(guard, final_private=True)
        if _directory_identity(os.lstat(_windows_extended_path(staging))) != staging_identity:
            raise _error("publication_failed", "staging identity changed")
        _rename_noreplace(staging, output)
        committed = True
        first = _read_output_payloads(output, committed=True)
        second = _read_output_payloads(output, committed=True)
        _assert_chain(guard, final_private=True)
        if first != before or second != before:
            raise _error("publication_uncertain", "published readback differs", committed=True)
        return dict(pins)
    except LaneAPublicBatchError as exc:
        if committed and not exc.committed:
            raise _error("publication_uncertain", "publication could not be confirmed", committed=True) from None
        raise
    except FileExistsError:
        if committed:
            raise _error("publication_uncertain", "publication could not be confirmed", committed=True) from None
        raise _error("output_exists", "the output directory appeared concurrently") from None
    except (LaneATaskBundleError, OSError, SnapshotBatchError, ValueError):
        raise _error(
            "publication_uncertain" if committed else "publication_failed",
            "atomic publication failed",
            committed=committed,
        ) from None


def prepare_lane_a_public_batch(
    *,
    public_tasks_file: Path,
    public_reports_file: Path,
    local_repo_root: Path,
    task_ids: Sequence[str],
    output_dir: Path,
    advisory_fetcher: AdvisoryFetcher | None = None,
) -> dict[str, object]:
    """Prepare and atomically publish one explicit public Lane A batch."""

    task_path, task_input_wire, tasks = _load_public_tasks(public_tasks_file, task_ids)
    report_path, report_input_wire, reports, reports_by_task = _load_public_reports(
        public_reports_file, tasks
    )
    repo_root, repositories = _load_repositories(local_repo_root, tasks)
    output, output_guard = _preflight_output(
        output_dir,
        protected_files=(task_path, report_path),
        repository_root=repo_root,
    )

    fetcher = advisory_fetcher or _fetch_advisory
    advisories: list[dict[str, Any]] = []
    by_ghsa: dict[str, dict[str, Any]] = {}
    for report in reports:
        ghsa_id = report["report_id"]
        try:
            raw = fetcher(ghsa_id)
        except LaneAPublicBatchError:
            raise
        except BaseException:
            raise _error("gh_failed", "the public advisory request failed") from None
        advisory = _sanitize_advisory(raw, ghsa_id)
        advisories.append(advisory)
        by_ghsa[ghsa_id] = advisory
    advisories.sort(key=lambda item: item["ghsa_id"])

    fix_commits: dict[str, str] = {}
    for task in tasks:
        selected_report = reports_by_task[task.task_id][0]
        fix_commits[task.task_id] = _validate_materializer_anchor(
            task,
            selected_report,
            by_ghsa[selected_report["report_id"]],
            repositories[task.repo_url.casefold()].repository,
        )

    try:
        if _read_regular(task_path, maximum=_MAX_INPUT_BYTES)[1] != task_input_wire:
            raise _error("input_changed", "the public task file changed during preparation")
        if _read_regular(report_path, maximum=_MAX_INPUT_BYTES)[1] != report_input_wire:
            raise _error("input_changed", "the public report file changed during preparation")
    except LaneATaskBundleError:
        raise _error("input_changed", "a public input changed during preparation") from None
    for state in repositories.values():
        try:
            if state.repository.assert_bare_storage_safe() != state.seal:
                raise _error("input_changed", "a local bare repository changed during preparation")
        except GitFactError:
            raise _error("input_changed", "a local bare repository changed during preparation") from None

    repository_rows = [
        {"path": str(state.path), "repo_url": state.repo_url}
        for state in sorted(repositories.values(), key=lambda item: item.repo_url.casefold())
    ]
    payloads = _canonical_wires(tasks, reports, advisories, repository_rows)
    pins = _publish(output, output_guard, payloads)
    return {
        "contract_version": CONTRACT_VERSION,
        "kind": KIND,
        "pins": pins,
        "summary": {
            "advisory_count": len(advisories),
            "fix_commits": [
                {"fix_commit": fix_commits[task.task_id], "task_id": task.task_id}
                for task in tasks
            ],
            "report_count": len(reports),
            "repository_count": len(repositories),
            "split": tasks[0].split,
            "task_count": len(tasks),
            "task_ids": [task.task_id for task in tasks],
            "wire_sha256": {
                name: hashlib.sha256(payload).hexdigest()
                for name, payload in sorted(payloads.items())
            },
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-tasks-file", required=True, type=Path)
    parser.add_argument("--public-reports-file", required=True, type=Path)
    parser.add_argument("--local-repo-root", required=True, type=Path)
    parser.add_argument("--task-id", action="append", required=True, dest="task_ids")
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        result = prepare_lane_a_public_batch(
            public_tasks_file=args.public_tasks_file,
            public_reports_file=args.public_reports_file,
            local_repo_root=args.local_repo_root,
            task_ids=args.task_ids,
            output_dir=args.output_dir,
        )
    except LaneAPublicBatchError as exc:
        payload = {
            "code": exc.code,
            "committed": exc.committed,
            "status": "failed",
        }
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 11 if exc.committed else 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
