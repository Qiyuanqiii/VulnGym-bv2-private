"""Attempt-scoped runtime for bounded, structured model calls.

The runtime is deliberately provider agnostic.  It accepts one fixed backend,
charges the shared budget before every invocation, and retains only the
minimal :class:`ModelCallRecord` needed to audit or replay the attempt.  Raw
requests, responses, exception messages, prompts, hidden reasoning, and
credentials are never written to the finalized transcript.

No network or model SDK is imported here.  ``ReplayStructuredModelBackend``
is the deterministic offline implementation used by tests and replay jobs.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import hashlib
import json
import math
import re
from threading import RLock
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from vulngym_agent.orchestrator.budget import Budget, BudgetEvent
    from vulngym_agent.orchestrator.contracts import ModelCallRecord


LLM_CALLS = "llm_calls"
MODEL_STAGES = frozenset({"plan", "semantic_judge", "reflection", "repair"})

_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MODEL_CALL_ID_RE = re.compile(r"^MODEL-[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MODEL_COMPONENT_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$"
)
_ERROR_CODE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_MAX_ATTEMPT = 2
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 10_000
_MAX_STRING_CHARS = 262_144
_MAX_CANONICAL_BYTES = 1_048_576
_MAX_MODEL_CALLS_PER_ATTEMPT = 256


class ModelRuntimeError(RuntimeError):
    """Base class for deterministic model-runtime policy errors."""


class ModelRuntimeFinalized(ModelRuntimeError):
    """Raised when a permanently sealed runtime is invoked again."""


class ModelLedgerMismatch(ModelRuntimeError):
    """Raised when recorded model calls do not exactly match the budget ledger."""


class ModelBlocked(RuntimeError):
    """Stable expected refusal from a structured model backend.

    Only the machine-readable code crosses the runtime boundary.  Backends
    must not attach provider text, prompts, or other sensitive details.
    """

    __slots__ = ("error_code",)

    def __init__(self, error_code: str) -> None:
        self.error_code = _identifier(
            error_code, name="error_code", pattern=_ERROR_CODE_RE
        )
        super().__init__(error_code)


def _identifier(value: Any, *, name: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{name} has an invalid format")
    return value


def _attempt(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > _MAX_ATTEMPT
    ):
        raise ValueError(f"attempt must be an integer from 0 to {_MAX_ATTEMPT}")
    return value


def _stage(value: Any) -> str:
    if not isinstance(value, str) or value not in MODEL_STAGES:
        raise ValueError(
            "stage must be plan, semantic_judge, reflection, or repair"
        )
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


def _freeze_json_object(value: Any, *, name: str) -> Mapping[str, Any]:
    """Validate, copy, and recursively freeze one bounded JSON object."""

    nodes = 0
    text_bytes = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes, text_bytes
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise ValueError(f"{name} exceeds {_MAX_JSON_NODES} JSON nodes")
        if depth > _MAX_JSON_DEPTH:
            raise ValueError(f"{name} exceeds JSON depth {_MAX_JSON_DEPTH}")
        if item is None or isinstance(item, (bool, int)):
            return item
        if isinstance(item, str):
            if len(item) > _MAX_STRING_CHARS:
                raise ValueError(
                    f"{name} contains a string longer than "
                    f"{_MAX_STRING_CHARS} characters"
                )
            text_bytes += len(item.encode("utf-8"))
            if text_bytes > _MAX_CANONICAL_BYTES:
                raise ValueError(f"{name} contains too much string data")
            return item
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError(f"{name} contains a non-finite number")
            return item
        if isinstance(item, Mapping):
            frozen: dict[str, Any] = {}
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError(f"{name} object keys must be strings")
                if len(key) > 256:
                    raise ValueError(f"{name} object key is too long")
                text_bytes += len(key.encode("utf-8"))
                if text_bytes > _MAX_CANONICAL_BYTES:
                    raise ValueError(f"{name} contains too much string data")
                frozen[key] = visit(child, depth + 1)
            return MappingProxyType(frozen)
        if isinstance(item, (list, tuple)):
            return tuple(visit(child, depth + 1) for child in item)
        raise ValueError(
            f"{name} contains unsupported JSON type {type(item).__name__}"
        )

    frozen = visit(value, 0)
    if not isinstance(frozen, Mapping):
        raise ValueError(f"{name} must be a JSON object")
    encoded = _canonical_json(frozen).encode("utf-8")
    if len(encoded) > _MAX_CANONICAL_BYTES:
        raise ValueError(
            f"{name} exceeds {_MAX_CANONICAL_BYTES} canonical JSON bytes"
        )
    return frozen


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _thaw_json(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def structured_json_sha256(value: Mapping[str, Any]) -> str:
    """Return the canonical digest used for structured requests/responses."""

    frozen = _freeze_json_object(value, name="structured JSON")
    return hashlib.sha256(_canonical_json(frozen).encode("utf-8")).hexdigest()


def _operation_for(
    *,
    task_id: str,
    attempt: int,
    policy_scope: str,
    stage: str,
    model_call_id: str,
    backend_id: str,
    model_id: str,
    request_sha256: str,
) -> str:
    """Return the sole valid ledger operation for this exact model call."""

    return (
        f"model:{task_id}:{attempt}:{policy_scope}:{stage}:{model_call_id}:"
        f"{backend_id}:{model_id}:{request_sha256}"
    )


@dataclass(frozen=True, slots=True)
class ModelRequest:
    """Canonical immutable input delivered to a structured backend."""

    task_id: str
    attempt: int
    policy_scope: str
    stage: str
    model_call_id: str
    backend_id: str
    model_id: str
    payload: Mapping[str, Any]
    request_sha256: str = field(init=False)
    operation: str = field(init=False)

    def __post_init__(self) -> None:
        _identifier(self.task_id, name="task_id", pattern=_TASK_ID_RE)
        _attempt(self.attempt)
        _identifier(self.policy_scope, name="policy_scope", pattern=_SCOPE_RE)
        _stage(self.stage)
        _identifier(
            self.model_call_id,
            name="model_call_id",
            pattern=_MODEL_CALL_ID_RE,
        )
        _identifier(self.backend_id, name="backend_id", pattern=_MODEL_COMPONENT_ID_RE)
        _identifier(self.model_id, name="model_id", pattern=_MODEL_COMPONENT_ID_RE)
        payload = _freeze_json_object(self.payload, name="model request")
        request_sha256 = hashlib.sha256(
            _canonical_json(payload).encode("utf-8")
        ).hexdigest()
        object.__setattr__(self, "payload", payload)
        object.__setattr__(self, "request_sha256", request_sha256)
        object.__setattr__(
            self,
            "operation",
            _operation_for(
                task_id=self.task_id,
                attempt=self.attempt,
                policy_scope=self.policy_scope,
                stage=self.stage,
                model_call_id=self.model_call_id,
                backend_id=self.backend_id,
                model_id=self.model_id,
                request_sha256=request_sha256,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the ephemeral request envelope; transcripts never call this."""

        return {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "stage": self.stage,
            "model_call_id": self.model_call_id,
            "backend_id": self.backend_id,
            "model_id": self.model_id,
            "payload": _thaw_json(self.payload),
            "request_sha256": self.request_sha256,
            "operation": self.operation,
        }


@runtime_checkable
class StructuredModelBackend(Protocol):
    """Provider-neutral synchronous backend for one structured JSON response."""

    @property
    def backend_id(self) -> str: ...

    @property
    def model_id(self) -> str: ...

    def invoke(self, request: ModelRequest) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ReplayResponse:
    """One immutable request/response pair pre-registered for offline replay."""

    stage: str
    request: Mapping[str, Any]
    response: Mapping[str, Any]
    request_sha256: str = field(init=False)
    response_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _stage(self.stage)
        request = _freeze_json_object(self.request, name="replay request")
        response = _freeze_json_object(self.response, name="replay response")
        object.__setattr__(self, "request", request)
        object.__setattr__(self, "response", response)
        object.__setattr__(
            self,
            "request_sha256",
            hashlib.sha256(_canonical_json(request).encode("utf-8")).hexdigest(),
        )
        object.__setattr__(
            self,
            "response_sha256",
            hashlib.sha256(_canonical_json(response).encode("utf-8")).hexdigest(),
        )


class ReplayStructuredModelBackend:
    """Offline backend that serves only constructor-registered exact matches."""

    __slots__ = ("_backend_id", "_model_id", "_responses")

    def __init__(
        self,
        entries: Iterable[ReplayResponse],
        *,
        backend_id: str = "replay",
        model_id: str = "offline-v1",
    ) -> None:
        self._backend_id = _identifier(
            backend_id, name="backend_id", pattern=_MODEL_COMPONENT_ID_RE
        )
        self._model_id = _identifier(
            model_id, name="model_id", pattern=_MODEL_COMPONENT_ID_RE
        )
        if isinstance(entries, (str, bytes, Mapping, set, frozenset)):
            raise ValueError("entries must be an ordered ReplayResponse collection")
        try:
            items = tuple(entries)
        except TypeError as exc:
            raise ValueError("entries must be an iterable") from exc
        if any(not isinstance(item, ReplayResponse) for item in items):
            raise ValueError("entries must contain only ReplayResponse values")
        responses: dict[tuple[str, str], Mapping[str, Any]] = {}
        for item in items:
            key = (item.stage, item.request_sha256)
            if key in responses:
                raise ValueError("duplicate replay request registration")
            # Copy through the bounded validator so the backend does not rely
            # on mutable caller-owned state, even if a future entry type does.
            responses[key] = _freeze_json_object(
                item.response, name="registered replay response"
            )
        self._responses = MappingProxyType(responses)

    @property
    def backend_id(self) -> str:
        return self._backend_id

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def registered_keys(self) -> frozenset[tuple[str, str]]:
        return frozenset(self._responses)

    def invoke(self, request: ModelRequest) -> Mapping[str, Any]:
        try:
            response = self._responses[(request.stage, request.request_sha256)]
        except KeyError as exc:
            raise ModelBlocked("replay_miss") from exc
        # Return another frozen copy so callers cannot mutate registry state.
        return _freeze_json_object(response, name="replay response")


@dataclass(frozen=True, slots=True)
class ModelResult:
    """Terminal result for one charged call; only its projection is persisted."""

    task_id: str
    attempt: int
    policy_scope: str
    model_call_id: str
    stage: str
    backend_id: str
    model_id: str
    request_sha256: str
    operation: str
    budget_event_sequence: int
    status: str
    response: Mapping[str, Any] | None = None
    error_code: str | None = None
    response_sha256: str | None = field(init=False)

    def __post_init__(self) -> None:
        _identifier(self.task_id, name="task_id", pattern=_TASK_ID_RE)
        _attempt(self.attempt)
        _identifier(self.policy_scope, name="policy_scope", pattern=_SCOPE_RE)
        _identifier(
            self.model_call_id,
            name="model_call_id",
            pattern=_MODEL_CALL_ID_RE,
        )
        _stage(self.stage)
        _identifier(self.backend_id, name="backend_id", pattern=_MODEL_COMPONENT_ID_RE)
        _identifier(self.model_id, name="model_id", pattern=_MODEL_COMPONENT_ID_RE)
        _identifier(self.request_sha256, name="request_sha256", pattern=_SHA256_RE)
        expected_operation = _operation_for(
            task_id=self.task_id,
            attempt=self.attempt,
            policy_scope=self.policy_scope,
            stage=self.stage,
            model_call_id=self.model_call_id,
            backend_id=self.backend_id,
            model_id=self.model_id,
            request_sha256=self.request_sha256,
        )
        if self.operation != expected_operation:
            raise ValueError("operation does not bind the exact scoped model call")
        if (
            isinstance(self.budget_event_sequence, bool)
            or not isinstance(self.budget_event_sequence, int)
            or self.budget_event_sequence < 1
        ):
            raise ValueError("budget_event_sequence must be a positive integer")
        if self.status not in {"success", "blocked", "error"}:
            raise ValueError("status must be success, blocked, or error")

        if self.status == "success":
            if self.response is None:
                raise ValueError("successful results require a response")
            if self.error_code is not None:
                raise ValueError("successful results cannot contain error_code")
            response = _freeze_json_object(self.response, name="model response")
            response_sha256 = hashlib.sha256(
                _canonical_json(response).encode("utf-8")
            ).hexdigest()
        else:
            if self.response is not None:
                raise ValueError("blocked/error results cannot contain a response")
            if self.error_code is None:
                raise ValueError("blocked/error results require error_code")
            _identifier(self.error_code, name="error_code", pattern=_ERROR_CODE_RE)
            response = None
            response_sha256 = None
        object.__setattr__(self, "response", response)
        object.__setattr__(self, "response_sha256", response_sha256)

    def to_model_call_record(self) -> ModelCallRecord:
        """Project the result into the minimal public orchestration sidecar."""

        from vulngym_agent.orchestrator.contracts import ModelCallRecord

        return ModelCallRecord(
            task_id=self.task_id,
            attempt=self.attempt,
            policy_scope=self.policy_scope,
            model_call_id=self.model_call_id,
            stage=self.stage,
            backend_id=self.backend_id,
            model_id=self.model_id,
            request_sha256=self.request_sha256,
            operation=self.operation,
            budget_event_sequence=self.budget_event_sequence,
            status=self.status,
            response_sha256=self.response_sha256,
            error_code=self.error_code,
        )

    def to_dict(self) -> dict[str, Any]:
        """Expose the immediate result; finalized transcripts use only records."""

        return {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "model_call_id": self.model_call_id,
            "stage": self.stage,
            "backend_id": self.backend_id,
            "model_id": self.model_id,
            "request_sha256": self.request_sha256,
            "operation": self.operation,
            "budget_event_sequence": self.budget_event_sequence,
            "status": self.status,
            "response": None if self.response is None else _thaw_json(self.response),
            "response_sha256": self.response_sha256,
            "error_code": self.error_code,
        }


@dataclass(frozen=True, slots=True)
class AttemptModelTranscript:
    """Sealed, replay-safe metadata for one attempt's model calls."""

    task_id: str
    attempt: int
    policy_scope: str
    backend_id: str
    model_id: str
    records: tuple[ModelCallRecord, ...]
    transcript_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        from vulngym_agent.orchestrator.contracts import ModelCallRecord

        _identifier(self.task_id, name="task_id", pattern=_TASK_ID_RE)
        _attempt(self.attempt)
        _identifier(self.policy_scope, name="policy_scope", pattern=_SCOPE_RE)
        _identifier(self.backend_id, name="backend_id", pattern=_MODEL_COMPONENT_ID_RE)
        _identifier(self.model_id, name="model_id", pattern=_MODEL_COMPONENT_ID_RE)
        if isinstance(self.records, (str, bytes, Mapping, set, frozenset)):
            raise ValueError("records must be an ordered ModelCallRecord array")
        try:
            records = tuple(self.records)
        except TypeError as exc:
            raise ValueError("records must be an ordered array") from exc
        if len(records) > _MAX_MODEL_CALLS_PER_ATTEMPT:
            raise ValueError("records exceeds the per-attempt model-call limit")
        if any(not isinstance(item, ModelCallRecord) for item in records):
            raise ValueError("records must contain only ModelCallRecord values")
        ids = [item.model_call_id for item in records]
        if len(ids) != len(set(ids)):
            raise ValueError("transcript model call IDs must be unique")
        for record in records:
            if (
                record.task_id != self.task_id
                or record.attempt != self.attempt
                or record.policy_scope != self.policy_scope
                or record.backend_id != self.backend_id
                or record.model_id != self.model_id
            ):
                raise ValueError("record identity/scope does not match transcript")
        object.__setattr__(self, "records", records)
        unsigned = {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "backend_id": self.backend_id,
            "model_id": self.model_id,
            "records": [record.to_dict() for record in records],
        }
        object.__setattr__(
            self,
            "transcript_sha256",
            hashlib.sha256(_canonical_json(unsigned).encode("utf-8")).hexdigest(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "backend_id": self.backend_id,
            "model_id": self.model_id,
            "records": [record.to_dict() for record in self.records],
            "transcript_sha256": self.transcript_sha256,
        }

    def __iter__(self):
        return iter(self.records)


class AttemptModelRuntime:
    """Budgeted, auditable runner scoped to one model backend and attempt."""

    __slots__ = (
        "_backend",
        "_backend_id",
        "_budget",
        "_executing",
        "_finalized",
        "_finalization_error",
        "_initial_budget_event_count",
        "_initial_llm_usage",
        "_lock",
        "_model_id",
        "_records",
        "_transcript",
        "attempt",
        "policy_scope",
        "task_id",
    )

    def __init__(
        self,
        *,
        task_id: str,
        attempt: int,
        policy_scope: str,
        budget: Budget,
        backend: StructuredModelBackend,
    ) -> None:
        self.task_id = _identifier(task_id, name="task_id", pattern=_TASK_ID_RE)
        self.attempt = _attempt(attempt)
        self.policy_scope = _identifier(
            policy_scope, name="policy_scope", pattern=_SCOPE_RE
        )
        expected_scope = (
            "t2.initial"
            if self.attempt == 0
            else f"t2.repair-{self.attempt}"
        )
        if self.policy_scope != expected_scope:
            raise ValueError("policy_scope does not match attempt")
        from vulngym_agent.orchestrator.budget import Budget as BudgetController

        if not isinstance(budget, BudgetController):
            raise ValueError("budget must be a Budget")
        try:
            backend_id = backend.backend_id
            model_id = backend.model_id
            invoke = backend.invoke
        except (AttributeError, TypeError) as exc:
            raise ValueError("backend must implement StructuredModelBackend") from exc
        if not callable(invoke):
            raise ValueError("backend.invoke must be callable")
        self._backend_id = _identifier(
            backend_id, name="backend_id", pattern=_MODEL_COMPONENT_ID_RE
        )
        self._model_id = _identifier(
            model_id, name="model_id", pattern=_MODEL_COMPONENT_ID_RE
        )
        self._backend = backend
        self._budget = budget
        self._initial_budget_event_count = len(budget.events)
        self._initial_llm_usage = budget.usage.llm_calls
        self._records: list[ModelCallRecord] = []
        self._executing = False
        self._finalized = False
        self._finalization_error: str | None = None
        self._transcript: AttemptModelTranscript | None = None
        self._lock = RLock()

    @property
    def backend_id(self) -> str:
        return self._backend_id

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def records(self) -> tuple[ModelCallRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def call(
        self,
        model_call_id: str,
        stage: str,
        payload: Mapping[str, Any],
    ) -> ModelResult:
        """Validate, charge, invoke, and record one structured model call."""

        with self._lock:
            if self._finalized:
                raise ModelRuntimeFinalized("model runtime is already finalized")
            if self._executing:
                raise ModelRuntimeError("re-entrant model calls are not allowed")
            call_id = _identifier(
                model_call_id,
                name="model_call_id",
                pattern=_MODEL_CALL_ID_RE,
            )
            stage_value = _stage(stage)
            if call_id in {record.model_call_id for record in self._records}:
                raise ValueError(f"duplicate model_call_id: {call_id}")
            if len(self._records) >= _MAX_MODEL_CALLS_PER_ATTEMPT:
                raise ModelRuntimeError("attempt model-call count limit exceeded")
            request = ModelRequest(
                task_id=self.task_id,
                attempt=self.attempt,
                policy_scope=self.policy_scope,
                stage=stage_value,
                model_call_id=call_id,
                backend_id=self._backend_id,
                model_id=self._model_id,
                payload=payload,
            )

            # BudgetExceeded deliberately propagates before backend execution
            # and before a synthetic record can be created.
            event = self._budget.charge_llm_call(operation=request.operation)
            self._executing = True
            try:
                try:
                    response = self._backend.invoke(request)
                    normalized_response = _freeze_json_object(
                        response, name="model response"
                    )
                    result = ModelResult(
                        task_id=self.task_id,
                        attempt=self.attempt,
                        policy_scope=self.policy_scope,
                        model_call_id=call_id,
                        stage=stage_value,
                        backend_id=self._backend_id,
                        model_id=self._model_id,
                        request_sha256=request.request_sha256,
                        operation=request.operation,
                        budget_event_sequence=event.sequence,
                        status="success",
                        response=normalized_response,
                    )
                except ModelBlocked as exc:
                    result = self._terminal_failure(
                        request=request,
                        event=event,
                        status="blocked",
                        error_code=exc.error_code,
                    )
                except Exception:
                    # Never persist the raw exception, its message, request
                    # content, prompt, hidden reasoning, or credentials.
                    result = self._terminal_failure(
                        request=request,
                        event=event,
                        status="error",
                        error_code="backend_error",
                    )
            finally:
                self._executing = False

            self._records.append(result.to_model_call_record())
            return result

    def _terminal_failure(
        self,
        *,
        request: ModelRequest,
        event: BudgetEvent,
        status: str,
        error_code: str,
    ) -> ModelResult:
        return ModelResult(
            task_id=self.task_id,
            attempt=self.attempt,
            policy_scope=self.policy_scope,
            model_call_id=request.model_call_id,
            stage=request.stage,
            backend_id=self._backend_id,
            model_id=self._model_id,
            request_sha256=request.request_sha256,
            operation=request.operation,
            budget_event_sequence=event.sequence,
            status=status,
            error_code=error_code,
        )

    def _verify_budget_ledger(self) -> None:
        events = self._budget.events
        if len(events) < self._initial_budget_event_count:
            raise ModelLedgerMismatch("budget ledger was truncated")
        attempt_events = events[self._initial_budget_event_count :]
        llm_events = tuple(
            event for event in attempt_events if event.resource == LLM_CALLS
        )
        if len(llm_events) != len(self._records):
            raise ModelLedgerMismatch(
                "attempt LLM-call budget delta does not equal recorded calls"
            )
        if (
            self._budget.usage.llm_calls - self._initial_llm_usage
            != len(self._records)
        ):
            raise ModelLedgerMismatch(
                "LLM-call usage delta does not equal recorded calls"
            )
        # Sequence numbers are globally unique within Budget's append-only
        # ledger, so exact operation order binds every record one-to-one.
        for record, event in zip(self._records, llm_events, strict=True):
            expected_operation = _operation_for(
                task_id=self.task_id,
                attempt=self.attempt,
                policy_scope=self.policy_scope,
                stage=record.stage,
                model_call_id=record.model_call_id,
                backend_id=record.backend_id,
                model_id=record.model_id,
                request_sha256=record.request_sha256,
            )
            if (
                event.resource != LLM_CALLS
                or event.amount != 1
                or event.operation != expected_operation
            ):
                raise ModelLedgerMismatch(
                    f"budget event does not bind record {record.model_call_id}"
                )

    def finalize(self) -> AttemptModelTranscript:
        """Verify the budget ledger and irreversibly seal this runtime."""

        with self._lock:
            if self._transcript is not None:
                return self._transcript
            if self._finalization_error is not None:
                raise ModelLedgerMismatch(self._finalization_error)
            if self._executing:
                raise ModelRuntimeError("cannot finalize during a model call")
            self._finalized = True
            try:
                self._verify_budget_ledger()
                transcript = AttemptModelTranscript(
                    task_id=self.task_id,
                    attempt=self.attempt,
                    policy_scope=self.policy_scope,
                    backend_id=self._backend_id,
                    model_id=self._model_id,
                    records=tuple(self._records),
                )
            except Exception as exc:
                self._finalization_error = str(exc)
                raise
            self._transcript = transcript
            return transcript


__all__ = [
    "AttemptModelRuntime",
    "AttemptModelTranscript",
    "MODEL_STAGES",
    "ModelBlocked",
    "ModelLedgerMismatch",
    "ModelRequest",
    "ModelResult",
    "ModelRuntimeError",
    "ModelRuntimeFinalized",
    "ReplayResponse",
    "ReplayStructuredModelBackend",
    "StructuredModelBackend",
    "structured_json_sha256",
]
