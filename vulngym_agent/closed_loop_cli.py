"""Offline, bounded T2 -> T1 closed-loop JSONL batch runner.

This module is intentionally a separate entry point from the existing T1-only
CLI.  It accepts exact :class:`~vulngym_agent.orchestrator.RunTask` JSONL,
binds path-free task data to trusted local package/repository configuration,
and runs the real local T2 producer followed by a fresh deterministic T1
validator for every validation round.

There is no online model/provider adapter here.  ``ExactReplayBackend`` only
serves pre-registered, one-shot responses keyed by the discrete canonical
identity fields of a ``ModelRequest``.  Delimiter-bearing identifiers are
never flattened into ``ModelRequest.operation`` for lookup, so a fixture
cannot accidentally reuse a response across task, attempt, policy scope,
stage, call ID, backend/model identity, or request digest.
"""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import sys
from threading import RLock
from types import MappingProxyType
from typing import Any, BinaryIO, Final, Protocol, TextIO, runtime_checkable

from vulngym_agent.agents.model_runtime import (
    MODEL_STAGES,
    ModelBlocked,
    ModelRequest,
    structured_json_sha256,
)
from vulngym_agent.agents.real_t2_producer import LocalStructuredT2Producer
from vulngym_agent.agents.t1_validator import T1DeterministicValidator
from vulngym_agent.agents.t2_execution import LocalT2ContextFactory
from vulngym_agent.agents.t2_inputs import T2TaskInputV1
from vulngym_agent.evidence import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_PACKAGE_BYTES,
    DEFAULT_MAX_PACKAGE_FILES,
    HARD_MAX_PACKAGE_FILES,
    PackageLoadResult,
    load_evidence_package,
)
from vulngym_agent.orchestrator import (
    ClosedLoopOrchestrator,
    ClosedLoopOutcome,
    Limits,
    RunTask,
)
from vulngym_agent.tools.git import GitFactError, GitRepository


DEFAULT_MAX_INPUT_LINE_BYTES: Final[int] = 1024 * 1024
HARD_MAX_INPUT_LINE_BYTES: Final[int] = 32 * 1024 * 1024
DEFAULT_MAX_TASK_BYTES: Final[int] = 64 * 1024 * 1024
HARD_MAX_TASK_BYTES: Final[int] = 1024 * 1024 * 1024
DEFAULT_MAX_RECORDS: Final[int] = 10_000
HARD_MAX_RECORDS: Final[int] = 100_000
DEFAULT_MAX_REPLAY_BYTES: Final[int] = 16 * 1024 * 1024
HARD_MAX_REPLAY_BYTES: Final[int] = 128 * 1024 * 1024
DEFAULT_MAX_REPLAY_RESPONSES: Final[int] = 50_000
HARD_MAX_REPLAY_RESPONSES: Final[int] = 300_000
DEFAULT_MAX_CONFIG_BYTES: Final[int] = 1024 * 1024
HARD_MAX_CONFIG_BYTES: Final[int] = 16 * 1024 * 1024
HARD_MAX_REPOSITORIES: Final[int] = 4096
HARD_MAX_T1_FILE_BYTES: Final[int] = 128 * 1024 * 1024
HARD_MAX_T1_PACKAGE_BYTES: Final[int] = 512 * 1024 * 1024
_DRAIN_CHUNK_BYTES: Final[int] = 64 * 1024

EXIT_OK: Final[int] = 0
EXIT_INCOMPLETE: Final[int] = 1
EXIT_FATAL: Final[int] = 2

_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REPO_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"
)
_COMPONENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$")
_MODEL_CALL_ID_RE = re.compile(r"^MODEL-[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ERROR_CODE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

ExactReplayIdentity = tuple[str, int, str, str, str, str, str, str]


class ClosedLoopBatchError(RuntimeError):
    """Batch-level controlled failure which must abort publication."""


class ExactReplayMismatch(ClosedLoopBatchError):
    """The consumed model-call sequence did not close the replay fixture."""


class TaskInputLimitExceeded(ClosedLoopBatchError):
    """The task JSONL exceeded its batch-level byte budget."""


class _InjectedBackendError(RuntimeError):
    """Private exception converted by AttemptModelRuntime to ``backend_error``."""


def _positive_bounded(name: str, value: Any, hard_limit: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > hard_limit
    ):
        raise ValueError(f"{name} must be an integer from 1 to {hard_limit}")
    return value


def _non_negative_bounded(name: str, value: Any, hard_limit: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > hard_limit
    ):
        raise ValueError(f"{name} must be an integer from 0 to {hard_limit}")
    return value


def _strict_keys(value: Any, expected: frozenset[str], *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{name} field names must be strings")
    actual = set(value)
    if actual != set(expected):
        raise ValueError(f"{name} must contain exactly its documented fields")
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError("non-standard JSON numeric constants are not allowed")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object keys are not allowed")
        value[key] = item
    return value


def _validate_unicode_scalars(value: Any) -> None:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise ValueError("unpaired UTF-16 surrogates are not allowed")
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, Mapping):
            pending.extend(item.keys())
            pending.extend(item.values())


def _strict_json_bytes(raw: bytes, *, name: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError(f"{name} is not valid UTF-8") from error
    try:
        value = json.loads(
            text,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_json_object,
        )
    except (json.JSONDecodeError, ValueError, RecursionError) as error:
        raise ValueError(f"{name} is not strict JSON") from error
    _validate_unicode_scalars(value)
    return value


def _read_bounded_file(path: Path, *, max_bytes: int, name: str) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"{name} exceeds its configured byte limit")
    return raw


def _freeze_json(value: Any) -> Any:
    """Deep-freeze a JSON value already checked by a bounded validator."""

    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class BatchInputRecord:
    """One physical input line, including a digest even when parsing fails."""

    input_line: int
    raw_sha256: str
    task: RunTask | None = None
    error_code: str | None = None
    error_task_id: str | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.input_line, bool)
            or not isinstance(self.input_line, int)
            or self.input_line < 1
        ):
            raise ValueError("input_line must be a positive integer")
        if not isinstance(self.raw_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.raw_sha256
        ):
            raise ValueError("raw_sha256 must be a lower-case SHA-256 digest")
        if (self.task is None) == (self.error_code is None):
            raise ValueError("record must contain exactly one task or error_code")
        if self.task is not None and not isinstance(self.task, RunTask):
            raise ValueError("task must be a RunTask")
        if self.error_code is not None and (
            not isinstance(self.error_code, str)
            or _ERROR_CODE_RE.fullmatch(self.error_code) is None
        ):
            raise ValueError("error_code has an invalid format")
        if self.error_task_id is not None and (
            self.task is not None
            or not isinstance(self.error_task_id, str)
            or _TASK_ID_RE.fullmatch(self.error_task_id) is None
        ):
            raise ValueError("error_task_id must be a valid ID on an error record")


def _parse_task_value(value: Any, *, input_line: int) -> RunTask:
    if not isinstance(value, Mapping):
        raise ValueError("task line must be a JSON object")
    task = RunTask.from_dict(value)
    task_input = T2TaskInputV1.from_task(task)
    if task_input.input_line != input_line:
        raise ValueError("task inputs.input_line does not match the physical line")
    return task


def _checked_stream_size(stream: BinaryIO) -> int | None:
    """Return an fstat size when the binary stream owns a real descriptor."""

    try:
        descriptor = stream.fileno()
    except (AttributeError, io.UnsupportedOperation):
        return None
    size = os.fstat(descriptor).st_size
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError("task input has an invalid file size")
    return size


def _iter_task_stream(
    stream: BinaryIO,
    *,
    max_input_line_bytes: int,
    max_task_bytes: int,
    declared_size: int | None = None,
) -> Iterator[BatchInputRecord]:
    """Read one already-open binary stream with a live cumulative byte gate."""

    line_limit = _positive_bounded(
        "max_input_line_bytes", max_input_line_bytes, HARD_MAX_INPUT_LINE_BYTES
    )
    task_limit = _positive_bounded(
        "max_task_bytes", max_task_bytes, HARD_MAX_TASK_BYTES
    )
    observed_sizes = (declared_size, _checked_stream_size(stream))
    for size in observed_sizes:
        if size is not None:
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise ValueError("task input has an invalid file size")
            if size > task_limit:
                raise TaskInputLimitExceeded(
                    "task input exceeds the configured total byte limit"
                )

    bytes_read = 0

    def bounded_readline(requested: int) -> bytes:
        nonlocal bytes_read
        # At the exact boundary, one byte is enough to distinguish EOF from a
        # concurrently grown file.  No read can overshoot the budget by more
        # than that sentinel byte.
        remaining = task_limit - bytes_read
        read_size = min(requested, remaining + 1)
        raw = stream.readline(max(1, read_size))
        if not isinstance(raw, bytes):
            raise ValueError("task input stream must be binary")
        bytes_read += len(raw)
        if bytes_read > task_limit:
            raise TaskInputLimitExceeded(
                "task input grew beyond the configured total byte limit"
            )
        return raw

    input_line = 0
    while True:
        raw = bounded_readline(line_limit + 1)
        if not raw:
            break
        input_line += 1
        digest = sha256()
        digest.update(raw)
        oversized = len(raw) > line_limit
        if oversized:
            tail = raw
            while tail and not tail.endswith(b"\n"):
                tail = bounded_readline(_DRAIN_CHUNK_BYTES)
                if tail:
                    digest.update(tail)
        raw_digest = digest.hexdigest()
        if oversized:
            yield BatchInputRecord(
                input_line,
                raw_digest,
                error_code="input_line_too_large",
            )
            continue

        if not raw.strip():
            yield BatchInputRecord(
                input_line, raw_digest, error_code="blank_input_line"
            )
            continue
        try:
            value = _strict_json_bytes(raw, name="task line")
        except ValueError:
            yield BatchInputRecord(
                input_line, raw_digest, error_code="invalid_json"
            )
            continue
        try:
            task = _parse_task_value(value, input_line=input_line)
        except (TypeError, ValueError):
            task_id = value.get("task_id") if isinstance(value, Mapping) else None
            safe_task_id = (
                task_id
                if isinstance(task_id, str) and _TASK_ID_RE.fullmatch(task_id)
                else None
            )
            claimed_line = (
                value["inputs"].get("input_line")
                if isinstance(value, Mapping)
                and isinstance(value.get("inputs"), Mapping)
                else None
            )
            code = (
                "input_line_mismatch"
                if isinstance(claimed_line, int)
                and not isinstance(claimed_line, bool)
                and claimed_line >= 1
                and claimed_line != input_line
                else "invalid_run_task"
            )
            yield BatchInputRecord(
                input_line,
                raw_digest,
                error_code=code,
                error_task_id=safe_task_id,
            )
            continue
        yield BatchInputRecord(input_line, raw_digest, task=task)


def iter_task_jsonl(
    path: str | os.PathLike[str],
    *,
    max_input_line_bytes: int = DEFAULT_MAX_INPUT_LINE_BYTES,
    max_task_bytes: int = DEFAULT_MAX_TASK_BYTES,
) -> Iterator[BatchInputRecord]:
    """Yield bounded strict tasks, rejecting total-size races fail-closed."""

    line_limit = _positive_bounded(
        "max_input_line_bytes", max_input_line_bytes, HARD_MAX_INPUT_LINE_BYTES
    )
    task_limit = _positive_bounded(
        "max_task_bytes", max_task_bytes, HARD_MAX_TASK_BYTES
    )
    input_path = Path(path)
    # Reject a statically oversized file before opening it.  The fstat check
    # inside ``_iter_task_stream`` closes the stat/open replacement race.
    declared_size = input_path.stat().st_size
    if declared_size > task_limit:
        raise TaskInputLimitExceeded(
            "task input exceeds the configured total byte limit"
        )
    with input_path.open("rb") as stream:
        yield from _iter_task_stream(
            stream,
            max_input_line_bytes=line_limit,
            max_task_bytes=task_limit,
            declared_size=declared_size,
        )


@dataclass(frozen=True, slots=True)
class ExactReplayFixture:
    """One one-shot result bound to every discrete ModelRequest identity field."""

    task_id: str
    attempt: int
    policy_scope: str
    stage: str
    model_call_id: str
    backend_id: str
    model_id: str
    request_sha256: str
    status: str
    response: Mapping[str, Any] | None
    error_code: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or _TASK_ID_RE.fullmatch(self.task_id) is None:
            raise ValueError("replay task_id has an invalid format")
        if (
            isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or self.attempt < 0
            or self.attempt > 2
        ):
            raise ValueError("replay attempt must be an integer from 0 to 2")
        if (
            not isinstance(self.policy_scope, str)
            or _TASK_ID_RE.fullmatch(self.policy_scope) is None
        ):
            raise ValueError("replay policy_scope has an invalid format")
        if not isinstance(self.stage, str) or self.stage not in MODEL_STAGES:
            raise ValueError("replay stage has an invalid value")
        if (
            not isinstance(self.model_call_id, str)
            or _MODEL_CALL_ID_RE.fullmatch(self.model_call_id) is None
        ):
            raise ValueError("replay model_call_id has an invalid format")
        if (
            not isinstance(self.backend_id, str)
            or _COMPONENT_ID_RE.fullmatch(self.backend_id) is None
        ):
            raise ValueError("replay backend_id has an invalid format")
        if (
            not isinstance(self.model_id, str)
            or _COMPONENT_ID_RE.fullmatch(self.model_id) is None
        ):
            raise ValueError("replay model_id has an invalid format")
        if (
            not isinstance(self.request_sha256, str)
            or _SHA256_RE.fullmatch(self.request_sha256) is None
        ):
            raise ValueError("replay request_sha256 has an invalid format")
        if not isinstance(self.status, str) or self.status not in {
            "success",
            "blocked",
            "error",
        }:
            raise ValueError("replay status must be success, blocked, or error")
        if self.status == "success":
            if not isinstance(self.response, Mapping) or self.error_code is not None:
                raise ValueError("successful replay fixtures require only a response")
            # Reuse the runtime's exact structured-response bounds, then keep a
            # detached ordinary JSON object.  No prompt/request is persisted.
            structured_json_sha256(self.response)
            object.__setattr__(self, "response", _freeze_json(self.response))
        else:
            if self.response is not None:
                raise ValueError("failed replay fixtures cannot contain a response")
            if (
                not isinstance(self.error_code, str)
                or _ERROR_CODE_RE.fullmatch(self.error_code) is None
            ):
                raise ValueError("failed replay fixtures require a stable error_code")
            if self.status == "error" and self.error_code != "backend_error":
                raise ValueError("error replay fixtures must use backend_error")

    @classmethod
    def from_request(
        cls,
        request: ModelRequest,
        *,
        status: str,
        response: Mapping[str, Any] | None,
        error_code: str | None,
    ) -> ExactReplayFixture:
        """Build a request-free fixture by copying only canonical identity fields."""

        if not isinstance(request, ModelRequest):
            raise ValueError("request must be a ModelRequest")
        return cls(
            task_id=request.task_id,
            attempt=request.attempt,
            policy_scope=request.policy_scope,
            stage=request.stage,
            model_call_id=request.model_call_id,
            backend_id=request.backend_id,
            model_id=request.model_id,
            request_sha256=request.request_sha256,
            status=status,
            response=response,
            error_code=error_code,
        )

    @property
    def identity(self) -> ExactReplayIdentity:
        """Return the collision-free lookup identity without request content."""

        return (
            self.task_id,
            self.attempt,
            self.policy_scope,
            self.stage,
            self.model_call_id,
            self.backend_id,
            self.model_id,
            self.request_sha256,
        )


def _exact_replay_identity(request: ModelRequest) -> ExactReplayIdentity:
    return (
        request.task_id,
        request.attempt,
        request.policy_scope,
        request.stage,
        request.model_call_id,
        request.backend_id,
        request.model_id,
        request.request_sha256,
    )


class ExactReplayBackend:
    """Offline backend with discrete-identity matching and exactly-once closure."""

    __slots__ = (
        "_backend_id",
        "_consumed",
        "_entries",
        "_lock",
        "_miss_count",
        "_model_id",
        "_reuse_count",
    )

    def __init__(
        self,
        entries: Iterable[ExactReplayFixture],
        *,
        backend_id: str = "exact-replay",
        model_id: str = "offline-v1",
    ) -> None:
        if not isinstance(backend_id, str) or _COMPONENT_ID_RE.fullmatch(backend_id) is None:
            raise ValueError("backend_id has an invalid format")
        if not isinstance(model_id, str) or _COMPONENT_ID_RE.fullmatch(model_id) is None:
            raise ValueError("model_id has an invalid format")
        if isinstance(entries, (str, bytes, Mapping, set, frozenset)):
            raise ValueError("entries must be an ordered fixture collection")
        try:
            fixtures = tuple(entries)
        except TypeError as error:
            raise ValueError("entries must be iterable") from error
        if any(type(item) is not ExactReplayFixture for item in fixtures):
            raise ValueError("entries must contain exact ExactReplayFixture values")
        registered: dict[ExactReplayIdentity, ExactReplayFixture] = {}
        for fixture in fixtures:
            if fixture.backend_id != backend_id or fixture.model_id != model_id:
                raise ValueError(
                    "replay fixture backend_id/model_id must match the backend"
                )
            identity = fixture.identity
            if identity in registered:
                raise ValueError("duplicate replay identity registration")
            registered[identity] = fixture
        self._backend_id = backend_id
        self._model_id = model_id
        self._entries = MappingProxyType(registered)
        self._consumed: set[ExactReplayIdentity] = set()
        self._miss_count = 0
        self._reuse_count = 0
        self._lock = RLock()

    @property
    def backend_id(self) -> str:
        return self._backend_id

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def registered_count(self) -> int:
        return len(self._entries)

    @property
    def consumed_count(self) -> int:
        with self._lock:
            return len(self._consumed)

    def invoke(self, request: ModelRequest) -> Mapping[str, Any]:
        if not isinstance(request, ModelRequest):
            raise ValueError("request must be a ModelRequest")
        identity = _exact_replay_identity(request)
        with self._lock:
            fixture = self._entries.get(identity)
            if fixture is None:
                self._miss_count += 1
                raise ExactReplayMismatch("unregistered exact replay identity")
            if identity in self._consumed:
                self._reuse_count += 1
                raise ExactReplayMismatch("reused exact replay identity")
            self._consumed.add(identity)
            if fixture.status == "blocked":
                assert fixture.error_code is not None
                raise ModelBlocked(fixture.error_code)
            if fixture.status == "error":
                raise _InjectedBackendError("backend_error")
            assert fixture.response is not None
            thawed = _thaw_json(fixture.response)
            assert isinstance(thawed, dict)
            return thawed

    def assert_complete(self) -> None:
        """Reject missing, extra, or reused fixtures without exposing requests."""

        with self._lock:
            unused = len(self._entries) - len(self._consumed)
            if unused or self._miss_count or self._reuse_count:
                raise ExactReplayMismatch(
                    "exact replay fixture did not close: "
                    f"unused={unused}, missing={self._miss_count}, "
                    f"reused={self._reuse_count}"
                )


def load_exact_replay_backend(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_REPLAY_BYTES,
    max_responses: int = DEFAULT_MAX_REPLAY_RESPONSES,
) -> ExactReplayBackend:
    """Load the strict, request-free exact replay fixture JSON document."""

    byte_limit = _positive_bounded("max_replay_bytes", max_bytes, HARD_MAX_REPLAY_BYTES)
    response_limit = _positive_bounded(
        "max_replay_responses", max_responses, HARD_MAX_REPLAY_RESPONSES
    )
    raw = _read_bounded_file(Path(path), max_bytes=byte_limit, name="replay fixture")
    value = _strict_json_bytes(raw, name="replay fixture")
    root = _strict_keys(
        value,
        frozenset({"contract_version", "backend_id", "model_id", "responses"}),
        name="replay fixture",
    )
    if type(root["contract_version"]) is not int or root["contract_version"] != 2:
        raise ValueError("replay contract_version must be integer 2")
    responses = root["responses"]
    if not isinstance(responses, list):
        raise ValueError("replay responses must be an array")
    if len(responses) > response_limit:
        raise ValueError("replay responses exceed the configured count limit")
    fixtures: list[ExactReplayFixture] = []
    for item in responses:
        record = _strict_keys(
            item,
            frozenset(
                {
                    "task_id",
                    "attempt",
                    "policy_scope",
                    "stage",
                    "model_call_id",
                    "backend_id",
                    "model_id",
                    "request_sha256",
                    "status",
                    "response",
                    "error_code",
                }
            ),
            name="replay response",
        )
        fixtures.append(
            ExactReplayFixture(
                task_id=record["task_id"],
                attempt=record["attempt"],
                policy_scope=record["policy_scope"],
                stage=record["stage"],
                model_call_id=record["model_call_id"],
                backend_id=record["backend_id"],
                model_id=record["model_id"],
                request_sha256=record["request_sha256"],
                status=record["status"],
                response=record["response"],
                error_code=record["error_code"],
            )
        )
    return ExactReplayBackend(
        fixtures,
        backend_id=root["backend_id"],
        model_id=root["model_id"],
    )


def _configured_directory(value: object, *, name: str) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise ValueError(f"{name} must identify an existing directory")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute directory path")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise ValueError(f"{name} must identify an existing directory") from None
    if not resolved.is_dir():
        raise ValueError(f"{name} must identify an existing directory")
    return resolved


def _paths_overlap(first: Path, second: Path) -> bool:
    return (
        first == second
        or first in second.parents
        or second in first.parents
    )


def _reject_package_repo_overlap(
    package_root: Path,
    repo_map: Mapping[str, Path],
) -> None:
    """Keep evidence-package and source-repository capabilities disjoint."""

    for repo_root in repo_map.values():
        checked_repo = _configured_directory(repo_root, name="repo_map path")
        if _paths_overlap(package_root, checked_repo):
            raise ValueError(
                "package_root and repository roots must be disjoint directories"
            )


def load_trusted_repo_map(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_CONFIG_BYTES,
) -> Mapping[str, Path]:
    """Load an exact canonical GitHub URL -> absolute local root trust map."""

    limit = _positive_bounded("max_config_bytes", max_bytes, HARD_MAX_CONFIG_BYTES)
    raw = _read_bounded_file(Path(path), max_bytes=limit, name="repo map")
    value = _strict_json_bytes(raw, name="repo map")
    root = _strict_keys(
        value,
        frozenset({"contract_version", "repositories"}),
        name="repo map",
    )
    if type(root["contract_version"]) is not int or root["contract_version"] != 1:
        raise ValueError("repo map contract_version must be integer 1")
    repositories = root["repositories"]
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("repo map repositories must be a non-empty array")
    if len(repositories) > HARD_MAX_REPOSITORIES:
        raise ValueError("repo map contains too many repositories")

    result: dict[str, Path] = {}
    normalized_urls: set[str] = set()
    resolved_paths: set[Path] = set()
    for item in repositories:
        record = _strict_keys(
            item, frozenset({"repo_url", "path"}), name="repo map entry"
        )
        repo_url = record["repo_url"]
        if not isinstance(repo_url, str) or _REPO_URL_RE.fullmatch(repo_url) is None:
            raise ValueError("repo map contains a non-canonical GitHub URL")
        normalized = repo_url.casefold()
        if normalized in normalized_urls:
            raise ValueError("repo map contains a duplicate normalized URL")
        normalized_urls.add(normalized)
        repo_path = _configured_directory(record["path"], name="repo map path")
        if repo_path in resolved_paths:
            raise ValueError("repo map contains a duplicate resolved repository path")
        resolved_paths.add(repo_path)
        result[repo_url] = repo_path
    return MappingProxyType(result)


class LocalT1ValidatorFactory:
    """Build a fresh T1 using only task data and trusted local roots."""

    __slots__ = (
        "_line_tolerance",
        "_max_file_bytes",
        "_max_package_bytes",
        "_max_package_files",
        "_package_root",
        "_repo_map",
    )

    def __init__(
        self,
        package_root: str | os.PathLike[str],
        repo_map: Mapping[str, Path],
        *,
        line_tolerance: int = 5,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_package_bytes: int = DEFAULT_MAX_PACKAGE_BYTES,
        max_package_files: int = DEFAULT_MAX_PACKAGE_FILES,
    ) -> None:
        self._package_root = _configured_directory(package_root, name="package_root")
        if not isinstance(repo_map, Mapping) or not repo_map:
            raise ValueError("repo_map must be a non-empty mapping")
        # The CLI loader and LocalT2ContextFactory perform the full trust-map
        # checks.  This detached exact snapshot prevents later caller mutation.
        self._repo_map = MappingProxyType(dict(repo_map))
        _reject_package_repo_overlap(self._package_root, self._repo_map)
        self._line_tolerance = _non_negative_bounded(
            "line_tolerance", line_tolerance, 1_000_000
        )
        self._max_file_bytes = _non_negative_bounded(
            "max_file_bytes", max_file_bytes, HARD_MAX_T1_FILE_BYTES
        )
        self._max_package_bytes = _non_negative_bounded(
            "max_package_bytes", max_package_bytes, HARD_MAX_T1_PACKAGE_BYTES
        )
        self._max_package_files = _positive_bounded(
            "max_package_files", max_package_files, HARD_MAX_PACKAGE_FILES
        )

    def __call__(self, task: RunTask) -> T1DeterministicValidator:
        task_input = T2TaskInputV1.from_task(task)
        repo_path = self._repo_map.get(task_input.repo_url)
        repository: GitRepository | None = None
        repository_note: str | None = None
        if repo_path is None:
            repository_note = "task repository is absent from the trusted repo map"
        else:
            try:
                repository = GitRepository(repo_path)
            except (GitFactError, OSError, RuntimeError, ValueError):
                # Do not propagate local absolute paths into ClosedLoopOutcome.
                repository_note = "trusted repository is unavailable"

        try:
            package_result = load_evidence_package(
                self._package_root,
                task_input.package,
                max_file_bytes=self._max_file_bytes,
                max_package_bytes=self._max_package_bytes,
                max_package_files=self._max_package_files,
                input_line=task_input.input_line,
                entry_id=task.entry_id,
                report_id=task.report_id,
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            # Unexpected local-read failures are facts we cannot establish,
            # never evidence that the candidate is correct.
            package_result = PackageLoadResult(
                status="uncertain",
                package=None,
                issues=(),
                input_line=task_input.input_line,
                entry_id=task.entry_id,
                report_id=task.report_id,
            )
        return T1DeterministicValidator(
            repository,
            line_tolerance=self._line_tolerance,
            repository_note=repository_note,
            package_result=package_result,
        )


@runtime_checkable
class ClosedLoopTaskRunner(Protocol):
    def run(self, task: RunTask) -> ClosedLoopOutcome: ...

    def finalize_batch(self) -> None: ...


class LocalClosedLoopTaskRunner:
    """Composition root for one offline batch; each task gets a fresh run."""

    __slots__ = ("_backend", "_limits", "_producer", "_t1_factory", "_t2_factory")

    def __init__(
        self,
        *,
        package_root: str | os.PathLike[str],
        repo_map: Mapping[str, Path],
        backend: ExactReplayBackend,
        limits: Limits | Mapping[str, Any] | None = None,
        line_tolerance: int = 5,
        t1_max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        t1_max_package_bytes: int = DEFAULT_MAX_PACKAGE_BYTES,
        t1_max_package_files: int = DEFAULT_MAX_PACKAGE_FILES,
    ) -> None:
        if not isinstance(backend, ExactReplayBackend):
            raise ValueError("backend must be an ExactReplayBackend")
        self._backend = backend
        self._limits = (
            limits
            if isinstance(limits, Limits)
            else Limits.from_dict(limits)
            if isinstance(limits, Mapping)
            else Limits()
        )
        self._producer = LocalStructuredT2Producer()
        self._t2_factory = LocalT2ContextFactory(package_root, repo_map, backend)
        self._t1_factory = LocalT1ValidatorFactory(
            package_root,
            repo_map,
            line_tolerance=line_tolerance,
            max_file_bytes=t1_max_file_bytes,
            max_package_bytes=t1_max_package_bytes,
            max_package_files=t1_max_package_files,
        )

    def run(self, task: RunTask) -> ClosedLoopOutcome:
        if not isinstance(task, RunTask):
            raise ValueError("task must be a RunTask")
        orchestrator = ClosedLoopOrchestrator(
            self._producer,
            self._t1_factory,
            self._t2_factory,
            limits=self._limits,
        )
        return orchestrator.run(task)

    def finalize_batch(self) -> None:
        self._backend.assert_complete()


@dataclass(frozen=True, slots=True)
class BatchSummary:
    records_seen: int
    tasks_run: int
    entries_written: int
    finalized: int
    manual_review: int
    failed: int
    input_failures: int
    record_limit_reached: bool
    require_all_finalized: bool = False

    @property
    def exit_code(self) -> int:
        if self.failed or self.input_failures:
            return EXIT_INCOMPLETE
        if self.require_all_finalized and self.manual_review:
            return EXIT_INCOMPLETE
        return EXIT_OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": 1,
            "status": "ok" if self.exit_code == EXIT_OK else "incomplete",
            "records_seen": self.records_seen,
            "tasks_run": self.tasks_run,
            "entries_written": self.entries_written,
            "finalized": self.finalized,
            "manual_review": self.manual_review,
            "failed": self.failed,
            "input_failures": self.input_failures,
            "record_limit_reached": self.record_limit_reached,
            "require_all_finalized": self.require_all_finalized,
        }


class _BatchCounters:
    __slots__ = ("counts", "entries", "records_seen", "record_limit", "tasks")

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.entries = 0
        self.records_seen = 0
        self.record_limit = False
        self.tasks = 0


ArtifactEvent = Any
ArtifactWriter = Callable[[Iterable[ArtifactEvent]], Any]


def _safe_task_id(record: BatchInputRecord) -> str | None:
    if record.task is None:
        return record.error_task_id
    value = record.task.task_id
    return value if _TASK_ID_RE.fullmatch(value) is not None else None


def _make_failure_event(
    record: BatchInputRecord,
    error_code: str,
    *,
    task_id: str | None,
) -> Any:
    # Imported lazily so this batch module stays independently testable while
    # the replay artifact contract evolves.  The constructor is the authority
    # for persisted failure-record validation.
    from vulngym_agent.orchestrator.replay import InputFailureRecord

    return InputFailureRecord(
        input_line=record.input_line,
        error_code=error_code,
        raw_sha256=record.raw_sha256,
        task_id=task_id,
    )


def _make_replay_event(record: BatchInputRecord, outcome: ClosedLoopOutcome) -> Any:
    from vulngym_agent.orchestrator.replay import ReplayRecord

    assert record.task is not None
    return ReplayRecord(
        input_line=record.input_line,
        task=record.task,
        outcome=outcome,
    )


def run_closed_loop_batch(
    records: Iterable[BatchInputRecord],
    runner: ClosedLoopTaskRunner,
    *,
    write_artifacts: ArtifactWriter,
    max_records: int = DEFAULT_MAX_RECORDS,
    require_all_finalized: bool = False,
) -> tuple[BatchSummary, Any]:
    """Run a bounded batch and invoke the artifact writer exactly once.

    The artifact writer receives a lazy, physical-line-ordered event stream.
    This lets the canonical replay writer persist large batches without this
    module inventing or buffering a second outcome serialization.
    """

    if not callable(getattr(runner, "run", None)):
        raise ValueError("runner must provide run(task)")
    if not callable(getattr(runner, "finalize_batch", None)):
        raise ValueError("runner must provide finalize_batch()")
    if not callable(write_artifacts):
        raise ValueError("artifact writer must be callable")
    record_limit = _positive_bounded("max_records", max_records, HARD_MAX_RECORDS)
    if type(require_all_finalized) is not bool:
        raise ValueError("require_all_finalized must be a bool")

    counters = _BatchCounters()
    stream_completed = False
    seen_task_ids: set[str] = set()
    seen_entry_ids: set[str] = set()
    emitted_task_ids: set[str] = set()

    def failure_event(record: BatchInputRecord, error_code: str) -> Any:
        task_id = _safe_task_id(record)
        if task_id in emitted_task_ids:
            task_id = None
        elif task_id is not None:
            emitted_task_ids.add(task_id)
        return _make_failure_event(record, error_code, task_id=task_id)

    def events() -> Iterator[ArtifactEvent]:
        nonlocal stream_completed
        previous_line = 0
        try:
            for record_index, record in enumerate(records):
                if type(record) is not BatchInputRecord:
                    raise ValueError("records must contain exact BatchInputRecord values")
                if record.input_line <= previous_line:
                    raise ValueError("input records must have increasing physical lines")
                previous_line = record.input_line
                counters.records_seen += 1
                if record_index >= record_limit:
                    counters.record_limit = True
                    counters.counts["input_failure"] += 1
                    yield failure_event(record, "record_limit")
                    break
                if record.error_code is not None:
                    claimed_task_id = _safe_task_id(record)
                    if claimed_task_id is not None:
                        seen_task_ids.add(claimed_task_id)
                    counters.counts["input_failure"] += 1
                    yield failure_event(record, record.error_code)
                    continue

                assert record.task is not None
                if record.task.task_id in seen_task_ids:
                    counters.counts["input_failure"] += 1
                    yield failure_event(record, "duplicate_task_id")
                    continue
                seen_task_ids.add(record.task.task_id)
                assert record.task.entry_id is not None
                if record.task.entry_id in seen_entry_ids:
                    counters.counts["input_failure"] += 1
                    yield failure_event(record, "duplicate_entry_id")
                    continue
                seen_entry_ids.add(record.task.entry_id)
                counters.tasks += 1
                try:
                    outcome = runner.run(record.task)
                except Exception:
                    counters.counts["input_failure"] += 1
                    yield failure_event(record, "task_runner_error")
                    continue
                if type(outcome) is not ClosedLoopOutcome or outcome.state.task is not record.task:
                    counters.counts["input_failure"] += 1
                    yield failure_event(record, "runner_contract_error")
                    continue

                counters.counts[outcome.status] += 1
                if outcome.status == "finalized":
                    if (
                        outcome.report is None
                        or outcome.report.verdict != "correct"
                        or outcome.entry is None
                    ):
                        raise ClosedLoopBatchError(
                            "finalized outcome is not closed by a correct T1 report"
                        )
                    counters.entries += 1
                emitted_task_ids.add(record.task.task_id)
                yield _make_replay_event(record, outcome)

            # Exact replay closure is a batch publication precondition.  It is
            # deliberately inside the writer's one-shot consumption so its
            # staging transaction is abandoned on unused/missing/reused calls.
            runner.finalize_batch()
            stream_completed = True
        finally:
            # A writer that stops consuming early violates the bulk contract;
            # the caller checks this flag after it returns.
            pass

    manifest = write_artifacts(events())
    if not stream_completed:
        raise ClosedLoopBatchError("artifact writer did not consume the full event stream")
    summary = BatchSummary(
        records_seen=counters.records_seen,
        tasks_run=counters.tasks,
        entries_written=counters.entries,
        finalized=counters.counts["finalized"],
        manual_review=counters.counts["manual_review"],
        failed=counters.counts["failed"],
        input_failures=counters.counts["input_failure"],
        record_limit_reached=counters.record_limit,
        require_all_finalized=require_all_finalized,
    )
    return summary, manifest


def _json_line(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def _run_artifact_cli_batch(
    *,
    output_dir: Path,
    protected_paths: Sequence[Path],
    records: Iterable[BatchInputRecord],
    runner: ClosedLoopTaskRunner,
    max_records: int,
    require_all_finalized: bool,
) -> BatchSummary:
    from vulngym_agent.orchestrator.replay import (
        ReplayLimits,
        write_closed_loop_artifacts,
    )

    def write_artifacts(events: Iterable[Any]) -> Any:
        return write_closed_loop_artifacts(
            output_dir,
            events,
            protected_paths=tuple(protected_paths),
            limits=ReplayLimits(max_input_records=max_records + 1),
        )

    summary, manifest = run_closed_loop_batch(
        records,
        runner,
        write_artifacts=write_artifacts,
        max_records=max_records,
        require_all_finalized=require_all_finalized,
    )
    entry_count = getattr(manifest, "entry_count", None)
    if entry_count != summary.entries_written:
        raise ClosedLoopBatchError(
            "artifact manifest entry count does not match finalized outcomes"
        )
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vulngym_agent.closed_loop_cli",
        description="Run the bounded offline VulnGym T2 -> T1 closed loop.",
    )
    parser.add_argument("--tasks", required=True, type=Path)
    parser.add_argument("--replay-responses", required=True, type=Path)
    parser.add_argument("--repo-map", required=True, type=Path)
    parser.add_argument("--package-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--max-input-line-bytes", type=int, default=DEFAULT_MAX_INPUT_LINE_BYTES
    )
    parser.add_argument(
        "--max-task-bytes",
        type=int,
        default=DEFAULT_MAX_TASK_BYTES,
        help=(
            "maximum total bytes read from the tasks JSONL; static or "
            "concurrent-growth overflow aborts publication"
        ),
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=DEFAULT_MAX_RECORDS,
        help=(
            "process at most this many tasks, then record the first overflow "
            "line and stop; replay fixtures for unprocessed lines remain unused "
            "and therefore reject publication"
        ),
    )
    parser.add_argument("--max-replay-bytes", type=int, default=DEFAULT_MAX_REPLAY_BYTES)
    parser.add_argument(
        "--max-replay-responses", type=int, default=DEFAULT_MAX_REPLAY_RESPONSES
    )
    parser.add_argument("--max-llm-calls", type=int, default=Limits().max_llm_calls)
    parser.add_argument("--max-tool-calls", type=int, default=Limits().max_tool_calls)
    parser.add_argument(
        "--max-repair-iterations",
        type=int,
        default=Limits().max_repair_iterations,
    )
    parser.add_argument("--line-tolerance", type=int, default=5)
    parser.add_argument(
        "--t1-max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES
    )
    parser.add_argument(
        "--t1-max-package-bytes", type=int, default=DEFAULT_MAX_PACKAGE_BYTES
    )
    parser.add_argument(
        "--t1-max-package-files", type=int, default=DEFAULT_MAX_PACKAGE_FILES
    )
    parser.add_argument(
        "--require-all-finalized",
        action="store_true",
        help="return 1 when any valid task is routed to manual review",
    )
    return parser


def _fatal_summary(error_code: str) -> dict[str, Any]:
    return {"contract_version": 1, "status": "fatal", "error_code": error_code}


def _print_summary(value: Mapping[str, Any], stream: TextIO) -> None:
    stream.write(_json_line(value))
    stream.flush()


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        max_input_line_bytes = _positive_bounded(
            "max_input_line_bytes",
            args.max_input_line_bytes,
            HARD_MAX_INPUT_LINE_BYTES,
        )
        max_task_bytes = _positive_bounded(
            "max_task_bytes", args.max_task_bytes, HARD_MAX_TASK_BYTES
        )
        max_records = _positive_bounded(
            "max_records", args.max_records, HARD_MAX_RECORDS
        )
        tasks_path = args.tasks.resolve(strict=True)
        replay_path = args.replay_responses.resolve(strict=True)
        repo_map_path = args.repo_map.resolve(strict=True)
        if not tasks_path.is_file() or not replay_path.is_file() or not repo_map_path.is_file():
            raise ValueError("configured input files must be regular files")
        package_root = _configured_directory(args.package_root, name="package_root")
        repo_map = load_trusted_repo_map(repo_map_path)
        backend = load_exact_replay_backend(
            replay_path,
            max_bytes=args.max_replay_bytes,
            max_responses=args.max_replay_responses,
        )
        limits = Limits(
            max_llm_calls=args.max_llm_calls,
            max_tool_calls=args.max_tool_calls,
            max_repair_iterations=args.max_repair_iterations,
        )
        runner = LocalClosedLoopTaskRunner(
            package_root=package_root,
            repo_map=repo_map,
            backend=backend,
            limits=limits,
            line_tolerance=args.line_tolerance,
            t1_max_file_bytes=args.t1_max_file_bytes,
            t1_max_package_bytes=args.t1_max_package_bytes,
            t1_max_package_files=args.t1_max_package_files,
        )
        protected = (
            tasks_path,
            replay_path,
            repo_map_path,
            package_root,
            *repo_map.values(),
        )
        summary = _run_artifact_cli_batch(
            output_dir=args.output_dir,
            protected_paths=protected,
            records=iter_task_jsonl(
                tasks_path,
                max_input_line_bytes=max_input_line_bytes,
                max_task_bytes=max_task_bytes,
            ),
            runner=runner,
            max_records=max_records,
            require_all_finalized=args.require_all_finalized,
        )
    except TaskInputLimitExceeded:
        _print_summary(
            _fatal_summary("task_input_limit_exceeded"), stream=sys.stdout
        )
        return EXIT_FATAL
    except ExactReplayMismatch:
        _print_summary(_fatal_summary("exact_replay_mismatch"), stream=sys.stdout)
        return EXIT_FATAL
    except (OSError, RuntimeError, TypeError, ValueError):
        # Do not echo exception messages: filesystem and Git errors frequently
        # contain trusted absolute paths which are outside the public contract.
        _print_summary(
            _fatal_summary("batch_configuration_or_io_error"), stream=sys.stdout
        )
        return EXIT_FATAL
    _print_summary(summary.to_dict(), stream=sys.stdout)
    return summary.exit_code


if __name__ == "__main__":  # pragma: no cover - exercised through main(argv)
    raise SystemExit(main())


__all__ = [
    "BatchInputRecord",
    "BatchSummary",
    "ClosedLoopBatchError",
    "ClosedLoopTaskRunner",
    "ExactReplayBackend",
    "ExactReplayFixture",
    "ExactReplayMismatch",
    "LocalClosedLoopTaskRunner",
    "LocalT1ValidatorFactory",
    "TaskInputLimitExceeded",
    "iter_task_jsonl",
    "load_exact_replay_backend",
    "load_trusted_repo_map",
    "main",
    "run_closed_loop_batch",
]
