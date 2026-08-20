"""Batch JSONL entry point for the first B-v2 T1 fact-gate slice."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Final, Iterable, Mapping, Sequence

from vulngym_agent.adapters import MAX_TRACE_NODES
from vulngym_agent.agents import T1DeterministicValidator, T1ValidationOutcome
from vulngym_agent.evidence import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_PACKAGE_BYTES,
    DEFAULT_MAX_PACKAGE_FILES,
    HARD_MAX_PACKAGE_FILES,
    PackageLoadResult,
    load_evidence_package,
)
from vulngym_agent.models import FieldValidation, ValidationReport
from vulngym_agent.tools.git import GitFactError, GitRepository


DEFAULT_MAX_INPUT_LINE_BYTES: Final[int] = 1024 * 1024
HARD_MAX_INPUT_LINE_BYTES: Final[int] = 32 * 1024 * 1024
DEFAULT_MAX_RECORDS: Final[int] = 10_000
HARD_MAX_RECORDS: Final[int] = 100_000
DEFAULT_MAX_TRACE_NODES: Final[int] = 64
HARD_MAX_TRACE_NODES: Final[int] = MAX_TRACE_NODES
_DRAIN_CHUNK_BYTES: Final[int] = 64 * 1024
_REPORT_ID_RE = re.compile(r"GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}\Z")
_ENTRY_ID_RE = re.compile(r"entry-[0-9]{5}\Z")


@dataclass(frozen=True, slots=True)
class InputRecord:
    line_number: int
    value: Any | None
    error: str | None = None


class RepositoryResolver:
    """Resolve exact ``repo_url`` keys to cached, read-only Git handles."""

    def __init__(
        self,
        *,
        repo_root: Path | None = None,
        repo_map: Mapping[str, Path] | None = None,
    ) -> None:
        self._repo_root = repo_root
        self._repo_map = dict(repo_map or {})
        self._cache: dict[Path, tuple[GitRepository | None, str | None]] = {}

    def resolve(self, candidate: Any) -> tuple[GitRepository | None, str | None]:
        if self._repo_root is not None:
            return self._open(self._repo_root)
        if not isinstance(candidate, Mapping):
            return None, "输入行不是 JSON 对象"
        repo_url = candidate.get("repo_url")
        if not isinstance(repo_url, str):
            return None, "候选记录没有可用的 repo_url"
        path = self._repo_map.get(repo_url)
        if path is None:
            return None, f"repo map 中没有 {repo_url!r}"
        return self._open(path)

    def _open(self, path: Path) -> tuple[GitRepository | None, str | None]:
        canonical = path.expanduser().resolve()
        cached = self._cache.get(canonical)
        if cached is not None:
            return cached
        try:
            result: tuple[GitRepository | None, str | None] = (
                GitRepository(canonical),
                None,
            )
        except (GitFactError, OSError, RuntimeError) as error:
            result = None, str(error)
        self._cache[canonical] = result
        return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant {value!r} is not allowed")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key {key!r} is not allowed")
        value[key] = item
    return value


def _validate_unicode_scalars(value: Any) -> None:
    """Reject unpaired UTF-16 surrogates without recursively walking JSON."""

    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise ValueError("unpaired UTF-16 surrogate is not allowed")
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())


def _bounded_positive_integer(name: str, value: Any, hard_limit: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= hard_limit
    ):
        raise ValueError(f"{name} must be an integer from 1 to {hard_limit}")
    return value


def iter_jsonl(
    path: Path,
    *,
    max_input_line_bytes: int = DEFAULT_MAX_INPUT_LINE_BYTES,
) -> Iterable[InputRecord]:
    """Decode and parse physical lines with a strict binary read bound.

    An oversized line is drained in fixed-size chunks without retaining its
    payload.  This preserves physical line correlation and lets the next line
    be processed while keeping peak input-buffer memory bounded.
    """

    max_input_line_bytes = _bounded_positive_integer(
        "max_input_line_bytes",
        max_input_line_bytes,
        HARD_MAX_INPUT_LINE_BYTES,
    )
    with path.open("rb") as stream:
        line_number = 0
        while True:
            raw_line = stream.readline(max_input_line_bytes + 1)
            if not raw_line:
                break
            line_number += 1
            if len(raw_line) > max_input_line_bytes:
                while raw_line and not raw_line.endswith(b"\n"):
                    raw_line = stream.readline(_DRAIN_CHUNK_BYTES)
                yield InputRecord(
                    line_number,
                    None,
                    "physical JSONL line exceeds the configured byte limit "
                    f"of {max_input_line_bytes}",
                )
                continue
            try:
                text = raw_line.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                yield InputRecord(
                    line_number,
                    None,
                    f"line {line_number} is not valid UTF-8: {error}",
                )
                continue
            if not text.strip():
                yield InputRecord(line_number, None, "blank JSONL line is not allowed")
                continue
            try:
                value = json.loads(
                    text,
                    parse_constant=_reject_json_constant,
                    object_pairs_hook=_unique_json_object,
                )
            except json.JSONDecodeError as error:
                yield InputRecord(
                    line_number,
                    None,
                    f"invalid JSON at column {error.colno}: {error.msg}",
                )
                continue
            except (ValueError, RecursionError) as error:
                yield InputRecord(
                    line_number,
                    None,
                    f"invalid JSON value: {error}",
                )
                continue
            try:
                _validate_unicode_scalars(value)
            except ValueError as error:
                yield InputRecord(
                    line_number,
                    None,
                    f"invalid JSON value: {error}",
                )
                continue
            yield InputRecord(line_number, value)


def _unwrap_candidate(value: Any) -> tuple[Any, Any, bool, str | None]:
    if isinstance(value, Mapping) and ("entry" in value or "package" in value):
        if set(value) != {"entry", "package"}:
            return (
                None,
                None,
                True,
                "package wrapper must contain exactly 'package' and 'entry'",
            )
        return value.get("entry"), value.get("package"), True, None
    return value, None, False, None


def _candidate_correlation(candidate: Any) -> tuple[str | None, str | None]:
    if not isinstance(candidate, Mapping):
        return None, None
    report_id = candidate.get("report_id")
    if not isinstance(report_id, str) or not _REPORT_ID_RE.fullmatch(report_id):
        report_id = None
    entry_id = candidate.get("entry_id")
    if not isinstance(entry_id, str) or not _ENTRY_ID_RE.fullmatch(entry_id):
        entry_id = None
    return report_id, entry_id


def _resource_limit_outcome(
    record: InputRecord,
    candidate: Any,
    *,
    field_name: str,
    detail: str,
    stopped: bool,
) -> T1ValidationOutcome:
    report_id, entry_id = _candidate_correlation(candidate)
    field = FieldValidation(
        status="incorrect",
        confidence=1.0,
        evidence=(
            f"输入 JSONL 第 {record.line_number} 行触发资源限额：{detail}。"
        ),
    )
    report = ValidationReport(
        report_id=report_id,
        entry_id=entry_id,
        verdict="incorrect",
        fields={field_name: field},
        summary=(
            "输入记录超过批处理资源契约；已发出可关联错误并停止后续记录。"
            if stopped
            else "输入记录超过批处理资源契约；未进入 Evidence Package 或 Git 验证。"
        ),
        missing_information=("缩小输入以满足已配置的资源限额",),
        input_line=record.line_number,
    )
    return T1ValidationOutcome(report, ())


def _input_error_outcome(record: InputRecord) -> T1ValidationOutcome:
    assert record.error is not None
    field = FieldValidation(
        status="incorrect",
        confidence=1.0,
        evidence=f"输入 JSONL 第 {record.line_number} 行无法形成候选记录：{record.error}。",
    )
    report = ValidationReport(
        report_id=None,
        verdict="incorrect",
        fields={"schema": field},
        summary="输入行存在确定性的编码或 JSON 格式错误；该行已隔离，后续记录继续处理。",
        missing_information=("修复该行的 UTF-8/JSON 格式后重新验证",),
        input_line=record.line_number,
    )
    return T1ValidationOutcome(report, ())


def run_batch(
    records: Iterable[InputRecord],
    resolver: RepositoryResolver,
    *,
    line_tolerance: int = 5,
    package_root: Path | None = None,
    max_evidence_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_package_bytes: int = DEFAULT_MAX_PACKAGE_BYTES,
    max_package_files: int = DEFAULT_MAX_PACKAGE_FILES,
    max_records: int = DEFAULT_MAX_RECORDS,
    max_trace_nodes: int = DEFAULT_MAX_TRACE_NODES,
) -> tuple[list[T1ValidationOutcome], Counter[str]]:
    if (
        isinstance(line_tolerance, bool)
        or not isinstance(line_tolerance, int)
        or line_tolerance < 0
    ):
        raise ValueError("line_tolerance must be a non-negative integer")
    for name, value in (
        ("max_evidence_file_bytes", max_evidence_file_bytes),
        ("max_package_bytes", max_package_bytes),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    max_records = _bounded_positive_integer(
        "max_records", max_records, HARD_MAX_RECORDS
    )
    max_package_files = _bounded_positive_integer(
        "max_package_files", max_package_files, HARD_MAX_PACKAGE_FILES
    )
    max_trace_nodes = _bounded_positive_integer(
        "max_trace_nodes", max_trace_nodes, HARD_MAX_TRACE_NODES
    )
    outcomes: list[T1ValidationOutcome] = []
    counts: Counter[str] = Counter()
    for record_index, record in enumerate(records):
        if record_index >= max_records:
            candidate, _, _, _ = _unwrap_candidate(record.value)
            outcome = _resource_limit_outcome(
                record,
                candidate,
                field_name="schema",
                detail=(
                    f"input contains more than the configured {max_records} records"
                ),
                stopped=True,
            )
            outcomes.append(outcome)
            counts[outcome.report.verdict] += 1
            break
        if record.error is not None:
            outcome = _input_error_outcome(record)
        else:
            try:
                candidate, package_reference, wrapped, wrapper_error = (
                    _unwrap_candidate(record.value)
                )
                package_result: PackageLoadResult | None = None
                if wrapper_error is not None:
                    outcome = _input_error_outcome(
                        InputRecord(record.line_number, None, wrapper_error)
                    )
                elif (
                    isinstance(candidate, Mapping)
                    and isinstance(candidate.get("trace"), list)
                    and len(candidate["trace"]) > max_trace_nodes
                ):
                    outcome = _resource_limit_outcome(
                        record,
                        candidate,
                        field_name="trace",
                        detail=(
                            f"trace contains {len(candidate['trace'])} nodes; "
                            f"configured maximum is {max_trace_nodes}"
                        ),
                        stopped=False,
                    )
                else:
                    if wrapped:
                        assert isinstance(record.value, Mapping)
                        entry_id = (
                            candidate.get("entry_id")
                            if isinstance(candidate, Mapping)
                            else None
                        )
                        report_id = (
                            candidate.get("report_id")
                            if isinstance(candidate, Mapping)
                            else None
                        )
                        if package_root is None:
                            package_result = PackageLoadResult(
                                status="uncertain",
                                package=None,
                                issues=(),
                                input_line=record.line_number,
                                entry_id=entry_id if isinstance(entry_id, str) else None,
                                report_id=report_id if isinstance(report_id, str) else None,
                            )
                        else:
                            package_result = load_evidence_package(
                                package_root,
                                package_reference,
                                max_file_bytes=max_evidence_file_bytes,
                                max_package_bytes=max_package_bytes,
                                max_package_files=max_package_files,
                                input_line=record.line_number,
                                entry_id=entry_id if isinstance(entry_id, str) else None,
                                report_id=report_id if isinstance(report_id, str) else None,
                            )
                    repository, note = resolver.resolve(candidate)
                    outcome = T1DeterministicValidator(
                        repository,
                        line_tolerance=line_tolerance,
                        repository_note=note,
                        package_result=package_result,
                    ).validate(candidate, input_line=record.line_number)
            except Exception as error:
                # A single untrusted record must not abort the remaining JSONL
                # batch.  Process-control exceptions are BaseException and are
                # deliberately not intercepted here.
                outcome = _input_error_outcome(
                    InputRecord(
                        record.line_number,
                        None,
                        "validator isolated an unexpected per-record failure: "
                        f"{type(error).__name__}: {error}",
                    )
                )
        outcomes.append(outcome)
        counts[outcome.report.verdict] += 1
    return outcomes, counts


def _jsonl_text(values: Iterable[Mapping[str, Any]]) -> str:
    return "".join(
        json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n"
        for value in values
    )


def _stage_text(path: Path, text: str) -> Path:
    if path.exists() and not path.is_file():
        raise ValueError(f"output path is not a regular file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _atomic_write_many(outputs: Mapping[Path, str]) -> None:
    """Replace a related output set and restore the old set on failure.

    Individual ``os.replace`` calls are atomic, but the three B-v2 artifacts
    form one logical run.  Staging every file first and keeping same-directory
    backups lets ordinary write/rename failures roll back the whole set.
    """

    if len(set(outputs)) != len(outputs):
        raise ValueError("transaction output paths must be distinct")
    stages: dict[Path, Path] = {}
    backups: dict[Path, Path | None] = {}
    committed: set[Path] = set()
    transaction_succeeded = False
    try:
        for path, text in outputs.items():
            stages[path] = _stage_text(path, text)

        for path in outputs:
            if not path.exists():
                backups[path] = None
                continue
            handle, backup_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".backup", dir=path.parent
            )
            os.close(handle)
            backup = Path(backup_name)
            try:
                os.replace(path, backup)
            except BaseException:
                backup.unlink(missing_ok=True)
                raise
            backups[path] = backup

        for path in outputs:
            os.replace(stages[path], path)
            committed.add(path)
        transaction_succeeded = True
    except BaseException as write_error:
        rollback_errors: list[str] = []
        for path in reversed(tuple(outputs)):
            backup = backups.get(path)
            try:
                if path in committed:
                    path.unlink(missing_ok=True)
                if backup is not None and backup.exists():
                    os.replace(backup, path)
            except BaseException as rollback_error:
                rollback_errors.append(f"{path}: {rollback_error}")
        if rollback_errors:
            raise RuntimeError(
                "output transaction failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from write_error
        raise
    finally:
        cleanup = list(stages.values())
        if transaction_succeeded:
            cleanup.extend(backup for backup in backups.values() if backup)
        for temporary in cleanup:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                # The primary transaction result is more important than a
                # best-effort cleanup diagnostic for a hidden temp file.
                pass


def _load_repo_map(path: Path) -> dict[str, Path]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("repo map must be a JSON object of repo_url -> local path")
    result: dict[str, Path] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.startswith("https://github.com/"):
            raise ValueError(f"invalid repo map key: {key!r}")
        if not isinstance(item, str) or not item:
            raise ValueError(f"repo map value for {key!r} must be a path string")
        local_path = Path(item).expanduser()
        if not local_path.is_absolute():
            local_path = path.parent / local_path
        result[key] = local_path
    return result


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the offline B-v2 deterministic T1 fact gate over candidate JSONL."
        )
    )
    parser.add_argument("input", type=Path, help="candidate entries JSONL")
    repositories = parser.add_mutually_exclusive_group()
    repositories.add_argument(
        "--repo-root",
        type=Path,
        help="one local Git repository used for every input row",
    )
    repositories.add_argument(
        "--repo-map",
        type=Path,
        help="JSON object mapping exact repo_url strings to local repository roots",
    )
    parser.add_argument(
        "--validation-output",
        type=Path,
        default=Path("outputs/validation.jsonl"),
    )
    parser.add_argument(
        "--evidence-output",
        type=Path,
        default=Path("artifacts/evidence.jsonl"),
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        default=Path("artifacts/run_manifest.jsonl"),
    )
    parser.add_argument("--line-tolerance", type=int, default=5)
    parser.add_argument(
        "--package-root",
        type=Path,
        help="authorized root for per-line local advisory/reference/patch packages",
    )
    parser.add_argument(
        "--max-evidence-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
    )
    parser.add_argument(
        "--max-package-bytes",
        type=int,
        default=DEFAULT_MAX_PACKAGE_BYTES,
    )
    parser.add_argument(
        "--max-package-files",
        type=int,
        default=DEFAULT_MAX_PACKAGE_FILES,
    )
    parser.add_argument(
        "--max-input-line-bytes",
        type=int,
        default=DEFAULT_MAX_INPUT_LINE_BYTES,
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=DEFAULT_MAX_RECORDS,
    )
    parser.add_argument(
        "--max-trace-nodes",
        type=int,
        default=DEFAULT_MAX_TRACE_NODES,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.line_tolerance < 0:
        print("error: --line-tolerance must be non-negative", file=os.sys.stderr)
        return 2
    if args.max_evidence_file_bytes < 0 or args.max_package_bytes < 0:
        print("error: evidence byte limits must be non-negative", file=os.sys.stderr)
        return 2
    try:
        _bounded_positive_integer(
            "--max-input-line-bytes",
            args.max_input_line_bytes,
            HARD_MAX_INPUT_LINE_BYTES,
        )
        _bounded_positive_integer(
            "--max-records", args.max_records, HARD_MAX_RECORDS
        )
        _bounded_positive_integer(
            "--max-package-files",
            args.max_package_files,
            HARD_MAX_PACKAGE_FILES,
        )
        _bounded_positive_integer(
            "--max-trace-nodes", args.max_trace_nodes, HARD_MAX_TRACE_NODES
        )
    except ValueError as error:
        print(f"error: {error}", file=os.sys.stderr)
        return 2

    try:
        input_path = args.input.expanduser().resolve(strict=True)
        repo_map_path = (
            args.repo_map.expanduser().resolve(strict=True)
            if args.repo_map
            else None
        )
        package_root = (
            args.package_root.expanduser().resolve(strict=True)
            if args.package_root
            else None
        )
        if package_root is not None and not package_root.is_dir():
            raise ValueError(f"package root is not a directory: {package_root}")
        output_paths = [
            args.validation_output.expanduser().resolve(),
            args.evidence_output.expanduser().resolve(),
            args.manifest_output.expanduser().resolve(),
        ]
        protected_inputs = {input_path}
        if repo_map_path is not None:
            protected_inputs.add(repo_map_path)
        if any(path in protected_inputs for path in output_paths):
            raise ValueError(
                "an output path must not overwrite the input JSONL or repo map"
            )
        if len(set(output_paths)) != len(output_paths):
            raise ValueError("validation, evidence, and manifest outputs must be distinct")
        repo_map = _load_repo_map(repo_map_path) if repo_map_path else None
        repository_roots: list[Path] = []
        if args.repo_root is not None:
            repository_roots.append(args.repo_root.expanduser().resolve())
        if repo_map is not None:
            repository_roots.extend(
                path.expanduser().resolve() for path in repo_map.values()
            )
        if any(
            _path_is_within(output, root)
            for output in output_paths
            for root in repository_roots
        ):
            raise ValueError(
                "validation, evidence, and manifest outputs must stay outside "
                "read-only target repositories"
            )
        if package_root is not None and any(
            _path_is_within(output, package_root) for output in output_paths
        ):
            raise ValueError(
                "validation, evidence, and manifest outputs must stay outside "
                "the read-only Evidence Package root"
            )
        resolver = RepositoryResolver(repo_root=args.repo_root, repo_map=repo_map)
        outcomes, counts = run_batch(
            iter_jsonl(
                input_path,
                max_input_line_bytes=args.max_input_line_bytes,
            ),
            resolver,
            line_tolerance=args.line_tolerance,
            package_root=package_root,
            max_evidence_file_bytes=args.max_evidence_file_bytes,
            max_package_bytes=args.max_package_bytes,
            max_package_files=args.max_package_files,
            max_records=args.max_records,
            max_trace_nodes=args.max_trace_nodes,
        )
        validations = [outcome.report.to_dict() for outcome in outcomes]
        evidence_by_id: dict[str, dict[str, Any]] = {}
        for outcome in outcomes:
            for item in outcome.evidence:
                payload = item.to_dict()
                existing = evidence_by_id.setdefault(item.evidence_id, payload)
                if existing != payload:
                    raise ValueError(
                        f"evidence ID collision for {item.evidence_id}"
                    )
        evidence = list(evidence_by_id.values())
        timestamp = datetime.now(timezone.utc).isoformat()
        manifest = {
            # Keep run manifests portable and avoid leaking workstation paths.
            "input": input_path.name,
            "completed_at": timestamp,
            "record_count": len(outcomes),
            "evidence_count": len(evidence),
            "verdict_counts": {
                status: counts.get(status, 0)
                for status in ("correct", "incorrect", "uncertain")
            },
            "line_tolerance": args.line_tolerance,
            "evidence_package_root_configured": package_root is not None,
            "max_evidence_file_bytes": args.max_evidence_file_bytes,
            "max_package_bytes": args.max_package_bytes,
            "max_package_files": args.max_package_files,
            "max_input_line_bytes": args.max_input_line_bytes,
            "max_records": args.max_records,
            "max_trace_nodes": args.max_trace_nodes,
            "policy": {
                "offline_evidence": True,
                "repository_read_only": True,
                "checkout": False,
                "semantic_positive_claims": False,
            },
        }
        _atomic_write_many(
            {
                output_paths[0]: _jsonl_text(validations),
                output_paths[1]: _jsonl_text(evidence),
                output_paths[2]: _jsonl_text([manifest]),
            }
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=os.sys.stderr)
        return 2

    print(
        "processed="
        f"{len(outcomes)} correct={counts.get('correct', 0)} "
        f"incorrect={counts.get('incorrect', 0)} "
        f"uncertain={counts.get('uncertain', 0)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
