"""Deterministic single-task result bundles for the D2 -> D3 -> D4 lane.

This contract is deliberately separate from :mod:`orchestrator.replay`.  The
legacy replay v1 file set describes formal Entry production and must remain
byte-for-byte compatible.  A discovery bundle instead retains one canonical
D2 result, an optional canonical D3 result, and a manifest that binds the D4
result digest.  Readers always recompute D4; no persisted derived decision is
trusted.

The reader returns an in-memory result bound to the exact bytes it verified. It
does not acquire an operating-system writer lease or promise that a caller with
concurrent write authority cannot alter the pathname after verification; the
trusted evaluator must provide an exclusive or read-only consumption phase.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import TYPE_CHECKING, Any, Final, Mapping, Sequence

from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskResult
from vulngym_agent.benchmark.discovery_projection import project_discovery_result
from vulngym_agent.benchmark.producer_contracts import (
    ProducerDeferredV1,
    ProducerDraftV1,
    ProducerResultV1,
    parse_producer_result_v1,
)
from vulngym_agent.benchmark.reviewer_contracts import (
    ReviewerDeferredV1,
    ReviewerFinalizedV1,
    ReviewerResultV1,
    parse_reviewer_result_v1,
)
from vulngym_agent.benchmark.reviewer_projection import (
    REVIEWER_PROJECTION_VERSION,
    ReviewerProjectionError,
    project_discovery_run_v1,
)

if TYPE_CHECKING:
    from .discovery_pipeline import SourceDiscoveryRunV1


DISCOVERY_REPLAY_SCHEMA_VERSION: Final[int] = 1
DISCOVERY_REPLAY_VERSION: Final[str] = "source-discovery-result-bundle-v1"
DISCOVERY_REPLAY_ERROR_TAXONOMY_VERSION: Final[str] = (
    "source-discovery-result-bundle-errors-v1"
)
DISCOVERY_REPLAY_FILES: Final[tuple[str, str, str]] = (
    "producer.jsonl",
    "reviewer.jsonl",
    "manifest.jsonl",
)

_PRODUCER_FILE: Final[str] = "producer.jsonl"
_REVIEWER_FILE: Final[str] = "reviewer.jsonl"
_MANIFEST_FILE: Final[str] = "manifest.jsonl"
_DATASET_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym source discovery result bundle dataset v1\0"
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
)
_MAX_LINE_BYTES: Final[int] = 2 * 1024 * 1024
_MAX_TOTAL_BYTES: Final[int] = 8 * 1024 * 1024
_MAX_PROTECTED_PATHS: Final[int] = 256
_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "binding_mismatch",
        "bundle_changed",
        "bundle_unavailable",
        "digest_mismatch",
        "invalid_argument",
        "invalid_result",
        "layout_invalid",
        "limit_exceeded",
        "noncanonical_json",
        "output_exists",
        "protected_path",
        "publication_failed",
        "publication_uncertain",
        "unsafe_path",
        "unsupported_version",
    }
)


class DiscoveryReplayError(RuntimeError):
    """Stable, path-free discovery result-bundle failure."""

    taxonomy_version = DISCOVERY_REPLAY_ERROR_TAXONOMY_VERSION

    def __init__(
        self,
        code: str,
        message: str,
        *,
        committed: bool = False,
    ) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            code = "invalid_argument"
            message = "discovery replay error code is invalid"
        self.code = code
        self.committed = committed is True
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class DiscoveryReplayLimits:
    """Caller-narrowable fixed byte ceilings for one task bundle."""

    max_line_bytes: int = _MAX_LINE_BYTES
    max_total_bytes: int = _MAX_TOTAL_BYTES

    def __post_init__(self) -> None:
        if (
            type(self.max_line_bytes) is not int
            or type(self.max_total_bytes) is not int
            or not 1 <= self.max_line_bytes <= _MAX_LINE_BYTES
            or not 1 <= self.max_total_bytes <= _MAX_TOTAL_BYTES
            or self.max_line_bytes > self.max_total_bytes
        ):
            raise DiscoveryReplayError(
                "invalid_argument", "discovery replay limits are invalid"
            )


DEFAULT_DISCOVERY_REPLAY_LIMITS: Final[DiscoveryReplayLimits] = (
    DiscoveryReplayLimits()
)


@dataclass(frozen=True, slots=True)
class VerifiedDiscoveryResult:
    """Narrow result returned only after a complete bundle verification."""

    dataset_sha256: str
    result: DiscoveryTaskResult

    def __post_init__(self) -> None:
        if (
            type(self.dataset_sha256) is not str
            or _SHA256_RE.fullmatch(self.dataset_sha256) is None
            or type(self.result) is not DiscoveryTaskResult
        ):
            raise ValueError("verified discovery result is invalid")
        try:
            # Reject polymorphic nested D0 nodes before any nested serializer is
            # allowed to execute.
            project_discovery_result(self.result)
            canonical = DiscoveryTaskResult.from_dict(self.result.to_dict())
        except (AttributeError, RecursionError, RuntimeError, TypeError, ValueError):
            raise ValueError("verified discovery result is invalid") from None
        object.__setattr__(self, "result", canonical)


@dataclass(frozen=True, slots=True)
class VerifiedDiscoveryRun:
    """Canonical closed run returned from one verified bundle byte snapshot."""

    dataset_sha256: str
    run: "SourceDiscoveryRunV1"

    def __post_init__(self) -> None:
        from .discovery_pipeline import SourceDiscoveryRunV1

        if (
            type(self.dataset_sha256) is not str
            or _SHA256_RE.fullmatch(self.dataset_sha256) is None
            or type(self.run) is not SourceDiscoveryRunV1
        ):
            raise ValueError("verified discovery run is invalid")
        try:
            supplied_run_sha256 = self.run.run_sha256
            # Reconstruct from exact top-level fields.  SourceDiscoveryRunV1
            # performs the complete nested preflight before any serializer is
            # invoked, so a mutated frozen input cannot execute polymorphic
            # nested methods here.
            canonical = SourceDiscoveryRunV1(
                producer_result=self.run.producer_result,
                reviewer_result=self.run.reviewer_result,
                discovery_result=self.run.discovery_result,
                contract_version=self.run.contract_version,
            )
        except (AttributeError, RecursionError, RuntimeError, TypeError, ValueError):
            raise ValueError("verified discovery run is invalid") from None
        if (
            type(supplied_run_sha256) is not str
            or supplied_run_sha256 != canonical.run_sha256
        ):
            raise ValueError("verified discovery run is invalid")
        object.__setattr__(self, "run", canonical)

    @property
    def result(self) -> DiscoveryTaskResult:
        """Compatibility-friendly access to the run's canonical D0 result."""

        return self.run.discovery_result


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeError):
        raise DiscoveryReplayError(
            "invalid_result", "result cannot be encoded as canonical JSON"
        ) from None


def _canonical_line(value: object) -> bytes:
    return _canonical_json(value) + b"\n"


def _reject_constant(value: str) -> None:
    raise DiscoveryReplayError(
        "noncanonical_json", "JSON constants outside the strict contract are forbidden"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DiscoveryReplayError(
                "noncanonical_json", "JSON objects must not contain duplicate keys"
            )
        result[key] = value
    return result


def _parse_jsonl(
    payload: bytes,
    *,
    name: str,
    allow_empty: bool,
) -> Mapping[str, Any] | None:
    if not payload:
        if allow_empty:
            return None
        raise DiscoveryReplayError("layout_invalid", f"{name} must contain one record")
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise DiscoveryReplayError(
            "noncanonical_json", f"{name} must be one terminated canonical JSON line"
        )
    try:
        text = payload[:-1].decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except DiscoveryReplayError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise DiscoveryReplayError(
            "noncanonical_json", f"{name} is not strict JSON"
        ) from None
    if type(value) is not dict or _canonical_line(value) != payload:
        raise DiscoveryReplayError(
            "noncanonical_json", f"{name} is not canonical JSON"
        )
    return value


def _canonical_producer(value: object) -> tuple[ProducerResultV1, bytes]:
    if type(value) not in (ProducerDraftV1, ProducerDeferredV1):
        raise DiscoveryReplayError(
            "invalid_result", "producer_result must be an exact D2 result"
        )
    try:
        wire = _canonical_json(value.to_dict())
        canonical = parse_producer_result_v1(wire)
    except (
        AttributeError,
        KeyError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        raise DiscoveryReplayError(
            "invalid_result", "producer_result did not pass strict D2 parsing"
        ) from None
    return canonical, wire


def _canonical_reviewer(
    value: object | None,
) -> tuple[ReviewerResultV1 | None, bytes]:
    if value is None:
        return None, b""
    if type(value) not in (ReviewerFinalizedV1, ReviewerDeferredV1):
        raise DiscoveryReplayError(
            "invalid_result", "reviewer_result must be an exact D3 result or null"
        )
    try:
        wire = _canonical_json(value.to_dict())
        canonical = parse_reviewer_result_v1(wire)
    except (
        AttributeError,
        KeyError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        raise DiscoveryReplayError(
            "invalid_result", "reviewer_result did not pass strict D3 parsing"
        ) from None
    return canonical, wire


def _canonical_discovery(value: object) -> tuple[DiscoveryTaskResult, bytes]:
    if type(value) is not DiscoveryTaskResult:
        raise DiscoveryReplayError(
            "invalid_result", "discovery_result must be an exact D0 result"
        )
    try:
        project_discovery_result(value)
        canonical = DiscoveryTaskResult.from_dict(value.to_dict())
        wire = _canonical_json(canonical.to_dict())
    except (
        AttributeError,
        KeyError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        raise DiscoveryReplayError(
            "invalid_result", "discovery_result did not pass strict D0 parsing"
        ) from None
    return canonical, wire


def _project(
    producer: ProducerResultV1,
    reviewer: ReviewerResultV1 | None,
) -> DiscoveryTaskResult:
    try:
        return project_discovery_run_v1(producer, reviewer)
    except (ReviewerProjectionError, RecursionError, RuntimeError, TypeError, ValueError):
        raise DiscoveryReplayError(
            "invalid_result", "D2 and D3 results do not form one exact D4 run"
        ) from None


def _normalize_run(
    run: "SourceDiscoveryRunV1",
) -> tuple[ProducerResultV1, ReviewerResultV1 | None, DiscoveryTaskResult, bytes, bytes]:
    try:
        from .discovery_pipeline import SourceDiscoveryRunV1
    except (ImportError, RuntimeError):
        raise DiscoveryReplayError(
            "invalid_argument", "source discovery pipeline contract is unavailable"
        ) from None
    if type(run) is not SourceDiscoveryRunV1:
        raise DiscoveryReplayError(
            "invalid_argument", "run must be an exact SourceDiscoveryRunV1"
        )
    try:
        canonical_run = SourceDiscoveryRunV1(
            producer_result=run.producer_result,
            reviewer_result=run.reviewer_result,
            discovery_result=run.discovery_result,
            contract_version=run.contract_version,
        )
        supplied_run_sha256 = run.run_sha256
    except (
        AttributeError,
        KeyError,
        RecursionError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        raise DiscoveryReplayError(
            "invalid_result", "source discovery run did not pass strict normalization"
        ) from None
    if (
        type(supplied_run_sha256) is not str
        or supplied_run_sha256 != canonical_run.run_sha256
    ):
        raise DiscoveryReplayError(
            "binding_mismatch", "source discovery run digest does not match its fields"
        )
    producer, producer_wire = _canonical_producer(canonical_run.producer_result)
    reviewer, reviewer_wire = _canonical_reviewer(canonical_run.reviewer_result)
    supplied, _ = _canonical_discovery(canonical_run.discovery_result)
    derived = _project(producer, reviewer)
    if supplied != derived:
        raise DiscoveryReplayError(
            "binding_mismatch", "stored D0 result differs from deterministic D4"
        )
    return producer, reviewer, derived, producer_wire, reviewer_wire


def _file_summary(payload: bytes, *, line_count: int) -> dict[str, Any]:
    return {
        "bytes": len(payload),
        "line_count": line_count,
        "sha256": _sha256(payload),
    }


def _manifest_core(
    *,
    result: DiscoveryTaskResult,
    producer_wire: bytes,
    reviewer_wire: bytes,
    producer_file: bytes,
    reviewer_file: bytes,
) -> dict[str, Any]:
    task = result.task
    discovery_wire = _canonical_json(result.to_dict())
    return {
        "bundle_version": DISCOVERY_REPLAY_VERSION,
        "commit": task.commit,
        "discovery_result_sha256": _sha256(discovery_wire),
        "files": {
            _PRODUCER_FILE: _file_summary(producer_file, line_count=1),
            _REVIEWER_FILE: _file_summary(
                reviewer_file, line_count=0 if not reviewer_file else 1
            ),
        },
        "instruction_id": task.instruction_id,
        "kind": "source_discovery_result_bundle",
        "manifest_line_count": 1,
        "producer_result_sha256": _sha256(producer_wire),
        "projection_version": REVIEWER_PROJECTION_VERSION,
        "repo_url": task.repo_url,
        "reviewer_result_sha256": (
            None if not reviewer_wire else _sha256(reviewer_wire)
        ),
        "schema_version": DISCOVERY_REPLAY_SCHEMA_VERSION,
        "snapshot_id": task.snapshot_id,
        "task_id": task.task_id,
    }


def _dataset_sha256(core: Mapping[str, Any]) -> str:
    return _sha256(_DATASET_DIGEST_DOMAIN + _canonical_json(dict(core)))


def _manifest_payload(core: Mapping[str, Any]) -> tuple[bytes, str]:
    dataset_sha256 = _dataset_sha256(core)
    return _canonical_line({**dict(core), "dataset_sha256": dataset_sha256}), dataset_sha256


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


def _directory_identity(result: os.stat_result) -> tuple[int, int]:
    return (result.st_dev, result.st_ino)


def _checked_lstat(path: Path, *, directory: bool | None) -> os.stat_result:
    try:
        result = os.lstat(path)
    except OSError as error:
        raise DiscoveryReplayError(
            "bundle_unavailable", "a required discovery bundle path is unavailable"
        ) from error
    if stat.S_ISLNK(result.st_mode) or _is_reparse(result):
        raise DiscoveryReplayError(
            "unsafe_path", "discovery bundle paths must not traverse links"
        )
    if directory is True and not stat.S_ISDIR(result.st_mode):
        raise DiscoveryReplayError(
            "unsafe_path", "a discovery bundle parent is not a directory"
        )
    if directory is False and not stat.S_ISREG(result.st_mode):
        raise DiscoveryReplayError(
            "unsafe_path", "a discovery bundle member is not a regular file"
        )
    return result


def _root_chain(path: Path) -> tuple[Path, ...]:
    return tuple(reversed(path.parents)) + (path,)


def _checked_chain(path: Path) -> tuple[tuple[Path, tuple[int, int]], ...]:
    return tuple(
        (component, _directory_identity(_checked_lstat(component, directory=True)))
        for component in _root_chain(path)
    )


def _assert_chain(
    checked: Sequence[tuple[Path, tuple[int, int]]],
) -> None:
    for component, expected in checked:
        if _directory_identity(_checked_lstat(component, directory=True)) != expected:
            raise DiscoveryReplayError(
                "bundle_changed", "a discovery bundle parent changed during use"
            )


def _fixed_names(root: Path) -> None:
    try:
        with os.scandir(root) as iterator:
            names = {entry.name for entry in iterator}
    except OSError as error:
        raise DiscoveryReplayError(
            "bundle_unavailable", "discovery bundle membership is unavailable"
        ) from error
    if names != set(DISCOVERY_REPLAY_FILES):
        raise DiscoveryReplayError(
            "layout_invalid", "discovery bundle has missing or extra files"
        )


def _read_stable_file(
    path: Path,
    *,
    maximum_bytes: int,
) -> tuple[bytes, tuple[int, int, int, int | None]]:
    before = _checked_lstat(path, directory=False)
    if before.st_size > maximum_bytes:
        raise DiscoveryReplayError(
            "limit_exceeded", "a discovery bundle file exceeds its byte limit"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DiscoveryReplayError(
            "bundle_unavailable", "a discovery bundle file could not be opened"
        ) from error
    try:
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse(opened)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise DiscoveryReplayError(
                    "bundle_changed", "a discovery bundle file changed while opening"
                )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum_bytes:
                    raise DiscoveryReplayError(
                        "limit_exceeded",
                        "a discovery bundle file exceeds its byte limit",
                    )
            finished = os.fstat(descriptor)
        except DiscoveryReplayError:
            raise
        except OSError as error:
            raise DiscoveryReplayError(
                "bundle_unavailable",
                "a discovery bundle file could not be read",
            ) from error
    finally:
        active_error = sys.exc_info()[0] is not None
        try:
            os.close(descriptor)
        except OSError as error:
            if not active_error:
                raise DiscoveryReplayError(
                    "bundle_unavailable",
                    "a discovery bundle file could not be closed",
                ) from error
    payload = b"".join(chunks)
    if (
        _identity(opened) != _identity(finished)
        or len(payload) != opened.st_size
        or _identity(_checked_lstat(path, directory=False)) != _identity(before)
    ):
        raise DiscoveryReplayError(
            "bundle_changed", "a discovery bundle file changed while reading"
        )
    return payload, _identity(before)


def _absolute_path(value: str | os.PathLike[str], *, name: str) -> Path:
    try:
        return Path(os.path.abspath(os.fspath(value)))
    except (AttributeError, RecursionError, RuntimeError, TypeError, ValueError, OSError):
        raise DiscoveryReplayError(
            "invalid_argument", f"{name} is not a valid filesystem path"
        ) from None


def _protected_tokens(
    paths: Sequence[Path],
) -> tuple[str, ...]:
    tokens: set[str] = set()
    for path in paths:
        try:
            resolved = path.resolve(strict=False)
        except (OSError, RuntimeError):
            resolved = path
        for candidate in (path, resolved):
            text = str(candidate)
            if text:
                tokens.add(text.casefold())
                tokens.add(text.replace("\\", "/").casefold())
                tokens.add(text.replace("/", "\\").casefold())
    return tuple(sorted(tokens, key=lambda item: (-len(item), item)))


def _ensure_payload_safe(value: Any, protected_tokens: Sequence[str]) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            _ensure_payload_safe(key, protected_tokens)
            _ensure_payload_safe(child, protected_tokens)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _ensure_payload_safe(child, protected_tokens)
        return
    if not isinstance(value, str):
        return
    candidates = (
        value.casefold(),
        value.replace("\\", "/").casefold(),
        value.replace("/", "\\").casefold(),
    )
    if any(token in candidate for token in protected_tokens for candidate in candidates):
        raise DiscoveryReplayError(
            "protected_path", "discovery bundle payload contains a protected path"
        )


def _paths_overlap(
    output: Path,
    protected_paths: Sequence[Path],
) -> bool:
    try:
        target = output.resolve(strict=False)
    except (OSError, RuntimeError):
        target = output
    for candidate in protected_paths:
        try:
            candidate = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            pass
        try:
            common = os.path.commonpath(
                (os.path.normcase(str(target)), os.path.normcase(str(candidate)))
            )
        except ValueError:
            continue
        if common in {os.path.normcase(str(target)), os.path.normcase(str(candidate))}:
            return True
    return False


def _validate_expected_sha256(value: object) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise DiscoveryReplayError(
            "invalid_argument", "expected_dataset_sha256 must be lower-case SHA-256"
        )
    return value


def _validate_expected_task_id(value: object) -> str:
    if type(value) is not str or _TASK_ID_RE.fullmatch(value) is None:
        raise DiscoveryReplayError(
            "invalid_argument", "expected_task_id is invalid"
        )
    return value


def _active_limits(value: DiscoveryReplayLimits | None) -> DiscoveryReplayLimits:
    if value is None:
        # ``frozen=True`` is an API guard, not an integrity boundary:
        # ``object.__setattr__`` can still mutate the exported singleton.  Build
        # the fixed defaults afresh so one corrupted reference cannot widen or
        # narrow every subsequent reader/writer invocation.
        return DiscoveryReplayLimits()
    if type(value) is not DiscoveryReplayLimits:
        raise DiscoveryReplayError(
            "invalid_argument", "limits must be exact DiscoveryReplayLimits"
        )
    try:
        return DiscoveryReplayLimits(
            max_line_bytes=value.max_line_bytes,
            max_total_bytes=value.max_total_bytes,
        )
    except (AttributeError, DiscoveryReplayError, TypeError, ValueError):
        raise DiscoveryReplayError(
            "invalid_argument", "limits did not pass strict normalization"
        ) from None


def _normalize_protected_paths(
    value: Sequence[str | os.PathLike[str]],
) -> tuple[Path, ...]:
    if isinstance(value, (str, bytes, bytearray, os.PathLike, Mapping, set, frozenset)):
        raise DiscoveryReplayError(
            "invalid_argument", "protected_paths must be an ordered path collection"
        )
    normalized: list[Path] = []
    try:
        for item in value:
            if len(normalized) >= _MAX_PROTECTED_PATHS:
                raise DiscoveryReplayError(
                    "invalid_argument", "protected_paths exceeds its fixed count limit"
                )
            if not isinstance(item, (str, bytes, os.PathLike)):
                raise DiscoveryReplayError(
                    "invalid_argument", "protected_paths contains an invalid path"
                )
            normalized.append(_absolute_path(item, name="protected path"))
    except DiscoveryReplayError:
        raise
    except Exception:
        raise DiscoveryReplayError(
            "invalid_argument", "protected_paths must be an ordered path collection"
        ) from None
    return tuple(normalized)


def _validate_manifest(
    manifest: Mapping[str, Any],
    *,
    producer: ProducerResultV1,
    reviewer: ReviewerResultV1 | None,
    result: DiscoveryTaskResult,
    producer_wire: bytes,
    reviewer_wire: bytes,
    producer_file: bytes,
    reviewer_file: bytes,
    expected_dataset_sha256: str,
    expected_task_id: str,
) -> str:
    expected_core = _manifest_core(
        result=result,
        producer_wire=producer_wire,
        reviewer_wire=reviewer_wire,
        producer_file=producer_file,
        reviewer_file=reviewer_file,
    )
    expected_keys = set(expected_core) | {"dataset_sha256"}
    if set(manifest) != expected_keys:
        raise DiscoveryReplayError(
            "layout_invalid", "discovery manifest fields are invalid"
        )
    if manifest.get("schema_version") != DISCOVERY_REPLAY_SCHEMA_VERSION or manifest.get(
        "bundle_version"
    ) != DISCOVERY_REPLAY_VERSION:
        raise DiscoveryReplayError(
            "unsupported_version", "discovery bundle version is unsupported"
        )
    if manifest.get("task_id") != expected_task_id:
        raise DiscoveryReplayError(
            "binding_mismatch", "discovery bundle does not match the expected task"
        )
    if dict(manifest) != {**expected_core, "dataset_sha256": manifest.get("dataset_sha256")}:
        raise DiscoveryReplayError(
            "binding_mismatch", "discovery manifest does not bind the parsed run"
        )
    dataset_sha256 = _dataset_sha256(expected_core)
    if (
        type(manifest.get("dataset_sha256")) is not str
        or manifest["dataset_sha256"] != dataset_sha256
        or dataset_sha256 != expected_dataset_sha256
    ):
        raise DiscoveryReplayError(
            "digest_mismatch", "discovery bundle dataset digest does not match"
        )
    # Branch shape is independently closed instead of inferred from manifest.
    if (type(producer) is ProducerDeferredV1) != (reviewer is None):
        raise DiscoveryReplayError(
            "binding_mismatch", "D2 and D3 result files have an invalid branch shape"
        )
    return dataset_sha256


def read_discovery_run_bundle(
    root: str | os.PathLike[str],
    *,
    expected_dataset_sha256: str,
    expected_task_id: str,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
    limits: DiscoveryReplayLimits | None = None,
) -> VerifiedDiscoveryRun:
    """Verify one byte snapshot and return its complete canonical closed run."""

    expected_digest = _validate_expected_sha256(expected_dataset_sha256)
    expected_task = _validate_expected_task_id(expected_task_id)
    active_limits = _active_limits(limits)
    protected_path_snapshot = _normalize_protected_paths(protected_paths)
    bundle = _absolute_path(root, name="bundle root")
    protected = _protected_tokens((*protected_path_snapshot, bundle))
    parent_chain = _checked_chain(bundle.parent)
    root_state = _checked_lstat(bundle, directory=True)
    root_identity = _directory_identity(root_state)
    _fixed_names(bundle)

    payloads: dict[str, bytes] = {}
    identities: dict[str, tuple[int, int, int, int | None]] = {}
    total_bytes = 0
    for name in DISCOVERY_REPLAY_FILES:
        payload, identity = _read_stable_file(
            bundle / name,
            maximum_bytes=active_limits.max_line_bytes,
        )
        payloads[name] = payload
        identities[name] = identity
        total_bytes += len(payload)
        if total_bytes > active_limits.max_total_bytes:
            raise DiscoveryReplayError(
                "limit_exceeded", "discovery bundle exceeds its total byte limit"
            )

    producer_value = _parse_jsonl(
        payloads[_PRODUCER_FILE], name=_PRODUCER_FILE, allow_empty=False
    )
    assert producer_value is not None
    try:
        parsed_producer = parse_producer_result_v1(producer_value)
    except (AttributeError, KeyError, RecursionError, RuntimeError, TypeError, ValueError):
        raise DiscoveryReplayError(
            "invalid_result", "producer.jsonl did not pass strict D2 parsing"
        ) from None
    producer, producer_wire = _canonical_producer(parsed_producer)
    reviewer_value = _parse_jsonl(
        payloads[_REVIEWER_FILE], name=_REVIEWER_FILE, allow_empty=True
    )
    reviewer: ReviewerResultV1 | None
    reviewer_wire: bytes
    if reviewer_value is None:
        reviewer, reviewer_wire = None, b""
    else:
        try:
            parsed_reviewer = parse_reviewer_result_v1(reviewer_value)
        except (
            AttributeError,
            KeyError,
            RecursionError,
            RuntimeError,
            TypeError,
            ValueError,
        ):
            raise DiscoveryReplayError(
                "invalid_result", "reviewer.jsonl did not pass strict D3 parsing"
            ) from None
        reviewer, reviewer_wire = _canonical_reviewer(parsed_reviewer)
    result = _project(producer, reviewer)
    try:
        from .discovery_pipeline import SourceDiscoveryRunV1

        run = SourceDiscoveryRunV1(
            producer_result=producer,
            reviewer_result=reviewer,
            discovery_result=result,
        )
    except (AttributeError, KeyError, RecursionError, RuntimeError, TypeError, ValueError):
        raise DiscoveryReplayError(
            "invalid_result", "bundle sidecars did not form one canonical closed run"
        ) from None
    manifest = _parse_jsonl(
        payloads[_MANIFEST_FILE], name=_MANIFEST_FILE, allow_empty=False
    )
    assert manifest is not None
    for value in (producer_value, reviewer_value, result.to_dict(), manifest):
        _ensure_payload_safe(value, protected)
    dataset_sha256 = _validate_manifest(
        manifest,
        producer=producer,
        reviewer=reviewer,
        result=result,
        producer_wire=producer_wire,
        reviewer_wire=reviewer_wire,
        producer_file=payloads[_PRODUCER_FILE],
        reviewer_file=payloads[_REVIEWER_FILE],
        expected_dataset_sha256=expected_digest,
        expected_task_id=expected_task,
    )

    _fixed_names(bundle)
    for name, expected in identities.items():
        if _identity(_checked_lstat(bundle / name, directory=False)) != expected:
            raise DiscoveryReplayError(
                "bundle_changed", "discovery bundle changed during verification"
            )
    if _directory_identity(_checked_lstat(bundle, directory=True)) != root_identity:
        raise DiscoveryReplayError(
            "bundle_changed", "discovery bundle root changed during verification"
        )
    _assert_chain(parent_chain)
    return VerifiedDiscoveryRun(dataset_sha256=dataset_sha256, run=run)


def read_discovery_result_bundle(
    root: str | os.PathLike[str],
    *,
    expected_dataset_sha256: str,
    expected_task_id: str,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
    limits: DiscoveryReplayLimits | None = None,
) -> VerifiedDiscoveryResult:
    """Compatibility wrapper returning D0 from one richer verified read."""

    verified = read_discovery_run_bundle(
        root,
        expected_dataset_sha256=expected_dataset_sha256,
        expected_task_id=expected_task_id,
        protected_paths=protected_paths,
        limits=limits,
    )
    return VerifiedDiscoveryResult(
        dataset_sha256=verified.dataset_sha256,
        result=verified.run.discovery_result,
    )


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        count = os.write(descriptor, view[offset:])
        if count < 1:
            raise OSError(errno.EIO, "short discovery bundle write")
        offset += count


def _rename_directory_noreplace(source: Path, destination: Path) -> None:
    if os.name == "posix":
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            renameat2 = libc.renameat2
        except (AttributeError, OSError):
            renameat2 = None
        if renameat2 is None:
            raise OSError(errno.ENOTSUP, "atomic no-replace rename is unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,
            os.fsencode(source),
            -100,
            os.fsencode(destination),
            1,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise FileExistsError(str(destination))
        raise OSError(error_number, "atomic discovery bundle publication failed")
    try:
        os.lstat(destination)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError(str(destination))
    os.rename(source, destination)


def _sync_staging_directory(
    staging: Path,
    *,
    expected_identity: tuple[int, int],
) -> None:
    """Persist staged directory entries before the publication commit point."""

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(staging, flags)
    except OSError:
        if os.name == "posix":
            raise
        return
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _is_reparse(opened)
            or _directory_identity(opened) != expected_identity
        ):
            raise DiscoveryReplayError(
                "bundle_changed", "discovery staging changed before directory sync"
            )
        try:
            os.fsync(descriptor)
        except OSError as error:
            if os.name == "posix" or error.errno not in {
                errno.EBADF,
                errno.EINVAL,
                errno.ENOTSUP,
            }:
                raise
    finally:
        os.close(descriptor)


def _safe_cleanup_staging(
    staging: Path,
    *,
    expected_identity: tuple[int, int],
    expected_members: Mapping[str, tuple[int, int, int, int | None]],
    parent_chain: Sequence[tuple[Path, tuple[int, int]]],
) -> None:
    """Conservatively retain an unpublished private staging directory.

    Even descriptor-relative ``stat`` followed by ``unlink(name, dir_fd=...)``
    leaves a name-replacement window inside the opened directory.  No supported
    Python primitive atomically says "unlink this name only if it still denotes
    this inode", so cleanup never removes names after an interrupted publish.
    The caller reports a pre-commit failure and an operator may inspect and
    remove the private staging area through a separately trusted procedure.
    """

    _ = (staging, expected_identity, expected_members, parent_chain)


def write_discovery_result_bundle(
    output_dir: str | os.PathLike[str],
    run: "SourceDiscoveryRunV1",
    *,
    protected_paths: Sequence[str | os.PathLike[str]] = (),
    limits: DiscoveryReplayLimits | None = None,
) -> VerifiedDiscoveryResult:
    """Publish one verified result bundle in a sibling no-replace transaction."""

    active_limits = _active_limits(limits)
    protected_path_snapshot = _normalize_protected_paths(protected_paths)
    producer, reviewer, result, producer_wire, reviewer_wire = _normalize_run(run)
    producer_file = producer_wire + b"\n"
    reviewer_file = b"" if reviewer is None else reviewer_wire + b"\n"
    core = _manifest_core(
        result=result,
        producer_wire=producer_wire,
        reviewer_wire=reviewer_wire,
        producer_file=producer_file,
        reviewer_file=reviewer_file,
    )
    manifest_file, dataset_sha256 = _manifest_payload(core)
    files = {
        _PRODUCER_FILE: producer_file,
        _REVIEWER_FILE: reviewer_file,
        _MANIFEST_FILE: manifest_file,
    }
    if any(len(payload) > active_limits.max_line_bytes for payload in files.values()):
        raise DiscoveryReplayError(
            "limit_exceeded", "a discovery bundle file exceeds its byte limit"
        )
    if sum(len(payload) for payload in files.values()) > active_limits.max_total_bytes:
        raise DiscoveryReplayError(
            "limit_exceeded", "discovery bundle exceeds its total byte limit"
        )

    output = _absolute_path(output_dir, name="output directory")
    parent_chain = _checked_chain(output.parent)
    if _paths_overlap(output, protected_path_snapshot):
        raise DiscoveryReplayError(
            "protected_path", "output directory overlaps a protected path"
        )
    try:
        os.lstat(output)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise DiscoveryReplayError(
            "unsafe_path", "output directory state is unavailable"
        ) from error
    else:
        raise DiscoveryReplayError(
            "output_exists", "output directory already exists"
        )

    tokens = _protected_tokens((*protected_path_snapshot, output))
    for value in (
        producer.to_dict(),
        None if reviewer is None else reviewer.to_dict(),
        result.to_dict(),
        {**core, "dataset_sha256": dataset_sha256},
    ):
        _ensure_payload_safe(value, tokens)

    staging = output.parent / (
        f".{output.name}.{secrets.token_hex(16)}.discovery-staging"
    )
    try:
        staging.mkdir(mode=0o700)
        staging_state = _checked_lstat(staging, directory=True)
    except (DiscoveryReplayError, OSError) as error:
        if isinstance(error, DiscoveryReplayError):
            raise
        raise DiscoveryReplayError(
            "publication_failed", "discovery staging could not be created"
        ) from error
    staging_identity = _directory_identity(staging_state)
    created_member_identities: dict[str, tuple[int, int, int, int | None]] = {}
    committed = False
    try:
        for name in DISCOVERY_REPLAY_FILES:
            target = staging / name
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(target, flags, 0o600)
            try:
                _write_all(descriptor, files[name])
                os.fsync(descriptor)
            finally:
                try:
                    opened = os.fstat(descriptor)
                    if stat.S_ISREG(opened.st_mode) and not _is_reparse(opened):
                        created_member_identities[name] = _identity(opened)
                finally:
                    os.close(descriptor)
            if (
                name not in created_member_identities
                or _identity(_checked_lstat(target, directory=False))
                != created_member_identities[name]
            ):
                raise DiscoveryReplayError(
                    "bundle_changed", "a discovery staging member changed after write"
                )
        read_discovery_result_bundle(
            staging,
            expected_dataset_sha256=dataset_sha256,
            expected_task_id=result.task.task_id,
            protected_paths=protected_path_snapshot,
            limits=active_limits,
        )
        if _directory_identity(_checked_lstat(staging, directory=True)) != staging_identity:
            raise DiscoveryReplayError(
                "bundle_changed", "discovery staging changed before publication"
            )
        _sync_staging_directory(
            staging,
            expected_identity=staging_identity,
        )
        _assert_chain(parent_chain)
        try:
            os.lstat(output)
        except FileNotFoundError:
            pass
        else:
            raise DiscoveryReplayError(
                "output_exists", "output directory already exists"
            )
        try:
            _rename_directory_noreplace(staging, output)
        except BaseException:
            try:
                committed = (
                    _directory_identity(_checked_lstat(output, directory=True))
                    == staging_identity
                )
            except (DiscoveryReplayError, OSError):
                committed = False
            raise
        committed = True
        if _directory_identity(_checked_lstat(output, directory=True)) != staging_identity:
            raise DiscoveryReplayError(
                "publication_uncertain",
                "published discovery bundle identity is uncertain",
                committed=True,
            )
        _assert_chain(parent_chain)
        if os.name == "posix":
            descriptor = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        # The staging verification cannot bind bytes changed in the final
        # pre-rename window.  Only a strict read from the published name may be
        # returned as verified.  Any failure here is post-commit uncertainty.
        return read_discovery_result_bundle(
            output,
            expected_dataset_sha256=dataset_sha256,
            expected_task_id=result.task.task_id,
            protected_paths=protected_path_snapshot,
            limits=active_limits,
        )
    except BaseException as error:
        if committed:
            if isinstance(error, DiscoveryReplayError) and error.committed:
                raise
            if not isinstance(error, Exception):
                raise
            raise DiscoveryReplayError(
                "publication_uncertain",
                "discovery bundle may have been published",
                committed=True,
            ) from error
        _safe_cleanup_staging(
            staging,
            expected_identity=staging_identity,
            expected_members=created_member_identities,
            parent_chain=parent_chain,
        )
        if isinstance(error, DiscoveryReplayError):
            raise
        if isinstance(error, FileExistsError):
            raise DiscoveryReplayError(
                "output_exists", "output directory already exists"
            ) from error
        if not isinstance(error, Exception):
            raise
        raise DiscoveryReplayError(
            "publication_failed", "discovery bundle publication failed"
        ) from error


__all__ = [
    "DEFAULT_DISCOVERY_REPLAY_LIMITS",
    "DISCOVERY_REPLAY_ERROR_TAXONOMY_VERSION",
    "DISCOVERY_REPLAY_FILES",
    "DISCOVERY_REPLAY_SCHEMA_VERSION",
    "DISCOVERY_REPLAY_VERSION",
    "DiscoveryReplayError",
    "DiscoveryReplayLimits",
    "VerifiedDiscoveryRun",
    "VerifiedDiscoveryResult",
    "read_discovery_run_bundle",
    "read_discovery_result_bundle",
    "write_discovery_result_bundle",
]
