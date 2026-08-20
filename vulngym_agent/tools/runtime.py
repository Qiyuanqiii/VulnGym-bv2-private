"""Attempt-scoped, auditable execution boundary for trusted T2 tools.

The runtime deliberately provides no shell, network, subprocess, or arbitrary
filesystem primitive.  Callers supply a fixed registry of narrow, trusted
``ToolDefinition`` objects and an even narrower allowlist for one production
attempt.  Each definition carries a stable, publisher-assigned ``contract_id``
from a release/build manifest.  Registry replay identity is derived from those
IDs, never from Python callable metadata: a contract ID identifies the shipped
tool contract, but cannot prove that arbitrary malicious code in the same
process has not replaced its handler.  Every accepted call is charged before
its handler starts and can be reconciled against the shared
:class:`~vulngym_agent.orchestrator.budget.Budget` ledger when the attempt is
sealed.

This module is infrastructure only.  Concrete Git/advisory/package tools are
expected to expose small JSON contracts through handlers added elsewhere.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
import hashlib
import json
import math
import re
from threading import RLock
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vulngym_agent.orchestrator.budget import Budget, BudgetEvent
    from vulngym_agent.orchestrator.contracts import ToolCallRecord


TOOL_CALLS = "tool_calls"


_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TOOL_CALL_ID_RE = re.compile(r"^TOOL-[A-Za-z0-9][A-Za-z0-9._-]{0,122}$")
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TOOL_CONTRACT_ID_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,158}@[A-Za-z0-9][A-Za-z0-9._-]{0,30}$"
)
_ARTIFACT_ID_RE = re.compile(r"^ART-[A-Za-z0-9][A-Za-z0-9._-]{0,123}$")
_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_MAX_ATTEMPT = 2
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 10_000
_MAX_STRING_CHARS = 262_144
_MAX_CANONICAL_BYTES = 1_048_576
_MAX_ARTIFACTS_PER_CALL = 32
_MAX_ARTIFACTS_PER_ATTEMPT = 64
_MAX_ARTIFACT_BYTES_PER_ATTEMPT = 8 * 1_048_576
_ARTIFACT_REF_TAG = "$artifact_ref"


class ToolRuntimeError(RuntimeError):
    """Base class for deterministic runtime policy errors."""


class ToolNotAllowed(ToolRuntimeError):
    """Raised before charging when a tool is absent from the active policy."""


class ToolReferenceError(ToolRuntimeError):
    """Raised before charging for a forged or out-of-scope artifact reference."""


class ToolRuntimeFinalized(ToolRuntimeError):
    """Raised when a sealed runtime is asked to execute another call."""


class ToolLedgerMismatch(ToolRuntimeError):
    """Raised when runtime results no longer match the budget ledger."""


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


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(child) for child in value]
    return value


def _freeze_json(value: Any, *, name: str) -> Any:
    """Validate and recursively freeze one tightly bounded JSON value."""

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
                    f"{name} contains a string longer than {_MAX_STRING_CHARS} chars"
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
    encoded = json.dumps(
        _thaw_json(frozen),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
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


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _ensure_sha256(value: Any, *, name: str) -> str:
    return _identifier(value, name=name, pattern=_SHA256_RE)


def _operation_for(
    *, task_id: str, attempt: int, policy_scope: str, tool_call_id: str, tool_name: str
) -> str:
    """Return the only accepted ledger operation for this exact tool call."""

    return (
        f"tool:{task_id}:{attempt}:{policy_scope}:"
        f"{tool_call_id}:{tool_name}"
    )


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    """Opaque reference issued by exactly one attempt runtime instance.

    Scope fields are serialized for auditability.  The runtime additionally
    checks object identity against its private issuance table, so reconstructing
    an equal value does not create an accepted capability.
    """

    task_id: str
    attempt: int
    policy_scope: str
    artifact_id: str
    artifact_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.task_id, name="task_id", pattern=_TASK_ID_RE)
        _attempt(self.attempt)
        _identifier(self.policy_scope, name="policy_scope", pattern=_SCOPE_RE)
        _identifier(self.artifact_id, name="artifact_id", pattern=_ARTIFACT_ID_RE)
        _ensure_sha256(self.artifact_sha256, name="artifact_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
        }


@dataclass(frozen=True, slots=True)
class ToolArtifact:
    """One immutable, scoped, content-addressed JSON artifact."""

    task_id: str
    attempt: int
    policy_scope: str
    tool_call_id: str
    artifact_id: str
    kind: str
    payload: Any
    payload_sha256: str = field(init=False)
    artifact_sha256: str = field(init=False)
    canonical_bytes: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _identifier(self.task_id, name="task_id", pattern=_TASK_ID_RE)
        _attempt(self.attempt)
        _identifier(self.policy_scope, name="policy_scope", pattern=_SCOPE_RE)
        _identifier(
            self.tool_call_id, name="tool_call_id", pattern=_TOOL_CALL_ID_RE
        )
        _identifier(self.artifact_id, name="artifact_id", pattern=_ARTIFACT_ID_RE)
        _identifier(self.kind, name="kind", pattern=_TOOL_NAME_RE)
        payload = _freeze_json(self.payload, name="artifact payload")
        payload_json = _canonical_json(payload)
        object.__setattr__(self, "payload", payload)
        object.__setattr__(
            self,
            "payload_sha256",
            hashlib.sha256(payload_json.encode("utf-8")).hexdigest(),
        )
        metadata = {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "tool_call_id": self.tool_call_id,
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "payload": _thaw_json(payload),
        }
        object.__setattr__(self, "artifact_sha256", _sha256(metadata))
        object.__setattr__(self, "canonical_bytes", len(payload_json.encode("utf-8")))

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "tool_call_id": self.tool_call_id,
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "payload": _thaw_json(self.payload),
            "payload_sha256": self.payload_sha256,
            "artifact_sha256": self.artifact_sha256,
        }


@dataclass(frozen=True, slots=True)
class ToolCallEnvelope:
    """Canonical, immutable input delivered to a trusted tool handler."""

    task_id: str
    attempt: int
    policy_scope: str
    tool_call_id: str
    tool_name: str
    arguments: Mapping[str, Any]
    arguments_sha256: str = field(init=False)
    operation: str = field(init=False)

    def __post_init__(self) -> None:
        _identifier(self.task_id, name="task_id", pattern=_TASK_ID_RE)
        _attempt(self.attempt)
        _identifier(self.policy_scope, name="policy_scope", pattern=_SCOPE_RE)
        _identifier(
            self.tool_call_id, name="tool_call_id", pattern=_TOOL_CALL_ID_RE
        )
        _identifier(self.tool_name, name="tool_name", pattern=_TOOL_NAME_RE)
        arguments = _freeze_json(self.arguments, name="tool arguments")
        if not isinstance(arguments, Mapping):
            raise ValueError("tool arguments must be a JSON object")
        object.__setattr__(self, "arguments", arguments)
        object.__setattr__(self, "arguments_sha256", _sha256(arguments))
        object.__setattr__(
            self,
            "operation",
            _operation_for(
                task_id=self.task_id,
                attempt=self.attempt,
                policy_scope=self.policy_scope,
                tool_call_id=self.tool_call_id,
                tool_name=self.tool_name,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "tool_call_id": self.tool_call_id,
            "tool_name": self.tool_name,
            "arguments": _thaw_json(self.arguments),
            "arguments_sha256": self.arguments_sha256,
            "operation": self.operation,
        }


@dataclass(frozen=True, slots=True)
class ToolHandlerOutput:
    """Successful structured value returned by a trusted handler."""

    output: Any = None
    artifacts: tuple[ToolArtifact, ...] = ()

    def __post_init__(self) -> None:
        output = _freeze_json(self.output, name="tool output")
        if isinstance(self.artifacts, (str, bytes, Mapping, set, frozenset)):
            raise ValueError("artifacts must be an ordered array")
        try:
            artifacts = tuple(self.artifacts)
        except TypeError as exc:
            raise ValueError("artifacts must be an ordered array") from exc
        if len(artifacts) > _MAX_ARTIFACTS_PER_CALL:
            raise ValueError(
                f"one call cannot emit more than {_MAX_ARTIFACTS_PER_CALL} artifacts"
            )
        if any(not isinstance(item, ToolArtifact) for item in artifacts):
            raise ValueError("artifacts must contain only ToolArtifact values")
        object.__setattr__(self, "output", output)
        object.__setattr__(self, "artifacts", artifacts)


class ToolBlocked(RuntimeError):
    """A stable, expected policy/domain block reported by a tool handler."""

    def __init__(
        self, error_code: str, detail: Mapping[str, Any] | None = None
    ) -> None:
        self.error_code = _identifier(
            error_code, name="error_code", pattern=_ERROR_CODE_RE
        )
        frozen = _freeze_json(detail or {}, name="blocked error detail")
        if not isinstance(frozen, Mapping):
            raise ValueError("blocked error detail must be a JSON object")
        self.detail = frozen
        super().__init__(error_code)


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """One manifest-identified trusted handler in a frozen registry.

    ``contract_id`` is an explicit release/build-manifest identifier, normally
    versioned (for example ``vulngym.local-t2.git_show@1``).  It deliberately
    does not hash or introspect ``handler``: callable identity is not stable
    across builds and cannot establish the integrity of hostile in-process
    Python code.
    """

    name: str
    contract_id: str
    handler: Callable[[ToolCallEnvelope], ToolHandlerOutput]

    def __post_init__(self) -> None:
        _identifier(self.name, name="tool definition name", pattern=_TOOL_NAME_RE)
        _identifier(
            self.contract_id,
            name="tool definition contract_id",
            pattern=_TOOL_CONTRACT_ID_RE,
        )
        if not callable(self.handler):
            raise ValueError("tool definition handler must be callable")


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Replay-safe terminal record for one charged call."""

    task_id: str
    attempt: int
    policy_scope: str
    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    operation: str
    budget_event_sequence: int
    status: str
    output: Any = None
    artifact_refs: tuple[ArtifactRef, ...] = ()
    error_code: str | None = None
    error: Mapping[str, Any] | None = None
    output_sha256: str | None = field(init=False)
    artifacts_sha256: str = field(init=False)
    error_sha256: str | None = field(init=False)
    result_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _identifier(self.task_id, name="task_id", pattern=_TASK_ID_RE)
        _attempt(self.attempt)
        _identifier(self.policy_scope, name="policy_scope", pattern=_SCOPE_RE)
        _identifier(
            self.tool_call_id, name="tool_call_id", pattern=_TOOL_CALL_ID_RE
        )
        _identifier(self.tool_name, name="tool_name", pattern=_TOOL_NAME_RE)
        _ensure_sha256(self.arguments_sha256, name="arguments_sha256")
        expected_operation = _operation_for(
            task_id=self.task_id,
            attempt=self.attempt,
            policy_scope=self.policy_scope,
            tool_call_id=self.tool_call_id,
            tool_name=self.tool_name,
        )
        if self.operation != expected_operation:
            raise ValueError("operation does not bind the exact scoped tool call")
        if (
            isinstance(self.budget_event_sequence, bool)
            or not isinstance(self.budget_event_sequence, int)
            or self.budget_event_sequence < 1
        ):
            raise ValueError("budget_event_sequence must be a positive integer")
        if self.status not in {"success", "blocked", "error"}:
            raise ValueError("status must be success, blocked, or error")

        output = _freeze_json(self.output, name="recorded tool output")
        if isinstance(self.artifact_refs, (str, bytes, Mapping, set, frozenset)):
            raise ValueError("artifact_refs must be an ordered array")
        try:
            refs = tuple(self.artifact_refs)
        except TypeError as exc:
            raise ValueError("artifact_refs must be an ordered array") from exc
        if len(refs) > _MAX_ARTIFACTS_PER_CALL:
            raise ValueError("artifact_refs exceeds the per-call limit")
        if any(not isinstance(item, ArtifactRef) for item in refs):
            raise ValueError("artifact_refs must contain only ArtifactRef values")
        if len({item.artifact_id for item in refs}) != len(refs):
            raise ValueError("artifact_refs must have unique artifact IDs")
        for ref in refs:
            if (
                ref.task_id != self.task_id
                or ref.attempt != self.attempt
                or ref.policy_scope != self.policy_scope
            ):
                raise ValueError("artifact reference scope does not match result")

        if self.status == "success":
            if self.error_code is not None or self.error is not None:
                raise ValueError("successful results cannot contain an error")
            output_sha256: str | None = _sha256(output)
            error_value = None
            error_sha256: str | None = None
        else:
            if self.output is not None or refs:
                raise ValueError("blocked/error results cannot contain output/artifacts")
            if self.error_code is None:
                raise ValueError("blocked/error results require error_code")
            _identifier(self.error_code, name="error_code", pattern=_ERROR_CODE_RE)
            error_value = _freeze_json(self.error or {}, name="recorded tool error")
            if not isinstance(error_value, Mapping):
                raise ValueError("recorded tool error must be a JSON object")
            output_sha256 = None
            error_sha256 = _sha256(
                {"error_code": self.error_code, "detail": _thaw_json(error_value)}
            )

        refs_value = [ref.to_dict() for ref in refs]
        artifacts_sha256 = _sha256(refs_value)
        terminal = {
            "status": self.status,
            "output_sha256": output_sha256,
            "artifacts_sha256": artifacts_sha256,
            "error_code": self.error_code,
            "error_sha256": error_sha256,
        }
        object.__setattr__(self, "output", output)
        object.__setattr__(self, "artifact_refs", refs)
        object.__setattr__(self, "error", error_value)
        object.__setattr__(self, "output_sha256", output_sha256)
        object.__setattr__(self, "artifacts_sha256", artifacts_sha256)
        object.__setattr__(self, "error_sha256", error_sha256)
        object.__setattr__(self, "result_sha256", _sha256(terminal))

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "tool_call_id": self.tool_call_id,
            "tool_name": self.tool_name,
            "arguments_sha256": self.arguments_sha256,
            "operation": self.operation,
            "budget_event_sequence": self.budget_event_sequence,
            "status": self.status,
            "output": _thaw_json(self.output),
            "output_sha256": self.output_sha256,
            "artifact_refs": [ref.to_dict() for ref in self.artifact_refs],
            "artifacts_sha256": self.artifacts_sha256,
            "error_code": self.error_code,
            "error": None if self.error is None else _thaw_json(self.error),
            "error_sha256": self.error_sha256,
            "result_sha256": self.result_sha256,
        }

    def to_tool_call_record(self) -> ToolCallRecord:
        """Project the detailed result into the orchestrator's minimal sidecar."""

        # Lazy import keeps the low-level tools package usable while the
        # orchestrator/agent packages themselves are still being initialized.
        from vulngym_agent.orchestrator.contracts import ToolCallRecord

        return ToolCallRecord(
            task_id=self.task_id,
            attempt=self.attempt,
            policy_scope=self.policy_scope,
            tool_call_id=self.tool_call_id,
            tool_name=self.tool_name,
            arguments_sha256=self.arguments_sha256,
            operation=self.operation,
            budget_event_sequence=self.budget_event_sequence,
            status=self.status,
            result_sha256=self.result_sha256 if self.status == "success" else None,
            error_code=self.error_code if self.status != "success" else None,
        )


@dataclass(frozen=True, slots=True)
class AttemptToolTranscript:
    """Immutable ordered transcript returned when one runtime is sealed."""

    task_id: str
    attempt: int
    policy_scope: str
    registry_sha256: str
    allowlist_sha256: str
    records: tuple[ToolResult, ...]
    artifacts: tuple[ToolArtifact, ...]
    transcript_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _identifier(self.task_id, name="task_id", pattern=_TASK_ID_RE)
        _attempt(self.attempt)
        _identifier(self.policy_scope, name="policy_scope", pattern=_SCOPE_RE)
        _ensure_sha256(self.registry_sha256, name="registry_sha256")
        _ensure_sha256(self.allowlist_sha256, name="allowlist_sha256")
        records = tuple(self.records)
        artifacts = tuple(self.artifacts)
        if any(not isinstance(item, ToolResult) for item in records):
            raise ValueError("records must contain only ToolResult values")
        if any(not isinstance(item, ToolArtifact) for item in artifacts):
            raise ValueError("artifacts must contain only ToolArtifact values")
        for item in (*records, *artifacts):
            if (
                item.task_id != self.task_id
                or item.attempt != self.attempt
                or item.policy_scope != self.policy_scope
            ):
                raise ValueError("transcript item scope differs from transcript")
        call_ids = [item.tool_call_id for item in records]
        artifact_ids = [item.artifact_id for item in artifacts]
        if len(call_ids) != len(set(call_ids)):
            raise ValueError("transcript tool call IDs must be unique")
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("transcript artifact IDs must be unique")
        object.__setattr__(self, "records", records)
        object.__setattr__(self, "artifacts", artifacts)
        unsigned = {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "registry_sha256": self.registry_sha256,
            "allowlist_sha256": self.allowlist_sha256,
            "records": [item.to_dict() for item in records],
            "artifacts": [item.to_dict() for item in artifacts],
        }
        object.__setattr__(self, "transcript_sha256", _sha256(unsigned))

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "policy_scope": self.policy_scope,
            "registry_sha256": self.registry_sha256,
            "allowlist_sha256": self.allowlist_sha256,
            "records": [item.to_dict() for item in self.records],
            "artifacts": [item.to_dict() for item in self.artifacts],
            "transcript_sha256": self.transcript_sha256,
        }

    def __iter__(self):
        """Allow ``records, artifacts = runtime.finalize()`` unpacking."""

        yield self.records
        yield self.artifacts


class AttemptToolRuntime:
    """A fixed-registry tool runner scoped to exactly one T2 attempt."""

    __slots__ = (
        "_allowlist",
        "_allowlist_sha256",
        "_artifact_bytes",
        "_artifacts",
        "_budget",
        "_executing",
        "_finalized",
        "_finalization_error",
        "_initial_budget_event_count",
        "_initial_tool_usage",
        "_issued_refs",
        "_lock",
        "_records",
        "_registry",
        "_registry_sha256",
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
        registry: Mapping[str, ToolDefinition] | Iterable[ToolDefinition],
        allowlist: Iterable[str],
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
        # Import lazily to preserve the tools -> agents -> orchestrator import
        # boundary while still rejecting lookalike ledger objects at runtime.
        from vulngym_agent.orchestrator.budget import Budget as BudgetController

        if not isinstance(budget, BudgetController):
            raise ValueError("budget must be a Budget")

        if isinstance(registry, Mapping):
            definitions: list[ToolDefinition] = []
            for name, definition in registry.items():
                if not isinstance(name, str) or not isinstance(
                    definition, ToolDefinition
                ):
                    raise ValueError("registry must contain ToolDefinition values")
                if name != definition.name:
                    raise ValueError("registry key must equal ToolDefinition.name")
                definitions.append(definition)
        else:
            if isinstance(registry, (str, bytes, set, frozenset)):
                raise ValueError("registry must be an ordered ToolDefinition collection")
            try:
                definitions = list(registry)
            except TypeError as exc:
                raise ValueError("registry must be an iterable") from exc
            if any(not isinstance(item, ToolDefinition) for item in definitions):
                raise ValueError("registry must contain ToolDefinition values")
        registry_copy: dict[str, ToolDefinition] = {}
        contract_ids: set[str] = set()
        for definition in definitions:
            if definition.name in registry_copy:
                raise ValueError(f"duplicate tool definition: {definition.name}")
            if definition.contract_id in contract_ids:
                raise ValueError(
                    f"duplicate tool contract_id: {definition.contract_id}"
                )
            registry_copy[definition.name] = definition
            contract_ids.add(definition.contract_id)

        if isinstance(allowlist, (str, bytes, Mapping)):
            raise ValueError("allowlist must be a collection of tool names")
        try:
            allowed = frozenset(allowlist)
        except TypeError as exc:
            raise ValueError("allowlist must be an iterable of tool names") from exc
        if any(not isinstance(name, str) for name in allowed):
            raise ValueError("allowlist must contain only tool names")
        unknown = allowed - set(registry_copy)
        if unknown:
            raise ValueError(
                "allowlist contains unregistered tool(s): " + ", ".join(sorted(unknown))
            )

        self._budget = budget
        self._registry = MappingProxyType(registry_copy)
        self._allowlist = allowed
        self._registry_sha256 = _sha256(
            [
                [name, registry_copy[name].contract_id]
                for name in sorted(registry_copy)
            ]
        )
        self._allowlist_sha256 = _sha256(sorted(allowed))
        self._initial_budget_event_count = len(budget.events)
        self._initial_tool_usage = budget.usage.tool_calls
        self._records: list[ToolResult] = []
        self._artifacts: list[ToolArtifact] = []
        self._issued_refs: dict[str, ArtifactRef] = {}
        self._artifact_bytes = 0
        self._executing = False
        self._finalized = False
        self._finalization_error: str | None = None
        self._transcript: AttemptToolTranscript | None = None
        self._lock = RLock()

    @property
    def registry(self) -> Mapping[str, ToolDefinition]:
        return self._registry

    @property
    def allowlist(self) -> frozenset[str]:
        return self._allowlist

    @property
    def records(self) -> tuple[ToolResult, ...]:
        with self._lock:
            return tuple(self._records)

    @property
    def artifacts(self) -> tuple[ToolArtifact, ...]:
        with self._lock:
            return tuple(self._artifacts)

    def artifact_ref(self, artifact_id: str) -> ArtifactRef:
        """Return the exact opaque reference issued for an existing artifact."""

        _identifier(artifact_id, name="artifact_id", pattern=_ARTIFACT_ID_RE)
        with self._lock:
            try:
                return self._issued_refs[artifact_id]
            except KeyError as exc:
                raise ToolReferenceError("artifact was not issued by this runtime") from exc

    def resolve_artifact(self, ref: ArtifactRef) -> ToolArtifact:
        """Resolve only an exact reference object issued by this runtime."""

        with self._lock:
            self._require_issued_ref(ref)
            for artifact in self._artifacts:
                if artifact.artifact_id == ref.artifact_id:
                    return artifact
        raise ToolReferenceError("artifact reference has no matching artifact")

    def _require_issued_ref(self, ref: ArtifactRef) -> None:
        if not isinstance(ref, ArtifactRef):
            raise ToolReferenceError("artifact reference has an invalid type")
        issued = self._issued_refs.get(ref.artifact_id)
        if (
            issued is not ref
            or ref.task_id != self.task_id
            or ref.attempt != self.attempt
            or ref.policy_scope != self.policy_scope
        ):
            raise ToolReferenceError(
                "artifact reference was not issued in this runtime attempt"
            )

    def _normalize_arguments(self, value: Any) -> Mapping[str, Any]:
        nodes = 0
        text_bytes = 0

        def visit(item: Any, depth: int) -> Any:
            nonlocal nodes, text_bytes
            nodes += 1
            if nodes > _MAX_JSON_NODES:
                raise ValueError(
                    f"tool arguments exceeds {_MAX_JSON_NODES} JSON nodes"
                )
            if depth > _MAX_JSON_DEPTH:
                raise ValueError(
                    f"tool arguments exceeds JSON depth {_MAX_JSON_DEPTH}"
                )
            if isinstance(item, ArtifactRef):
                self._require_issued_ref(item)
                return {_ARTIFACT_REF_TAG: item.to_dict()}
            if item is None or isinstance(item, (bool, int)):
                return item
            if isinstance(item, str):
                if len(item) > _MAX_STRING_CHARS:
                    raise ValueError("tool arguments contains an oversized string")
                text_bytes += len(item.encode("utf-8"))
                if text_bytes > _MAX_CANONICAL_BYTES:
                    raise ValueError("tool arguments contains too much string data")
                return item
            if isinstance(item, float):
                if not math.isfinite(item):
                    raise ValueError("tool arguments contains a non-finite number")
                return item
            if isinstance(item, Mapping):
                if _ARTIFACT_REF_TAG in item:
                    raise ToolReferenceError(
                        f"raw {_ARTIFACT_REF_TAG} objects are reserved"
                    )
                normalized: dict[str, Any] = {}
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise ValueError("tool argument object keys must be strings")
                    if len(key) > 256:
                        raise ValueError("tool argument object key is too long")
                    text_bytes += len(key.encode("utf-8"))
                    if text_bytes > _MAX_CANONICAL_BYTES:
                        raise ValueError(
                            "tool arguments contains too much string data"
                        )
                    normalized[key] = visit(child, depth + 1)
                return normalized
            if isinstance(item, (list, tuple)):
                return [visit(child, depth + 1) for child in item]
            raise ValueError(
                "tool arguments contains unsupported type "
                f"{type(item).__name__}"
            )

        normalized = visit(value, 0)
        if not isinstance(normalized, Mapping):
            raise ValueError("tool arguments must be a JSON object")
        frozen = _freeze_json(normalized, name="tool arguments")
        assert isinstance(frozen, Mapping)
        return frozen

    def _make_error_result(
        self,
        *,
        envelope: ToolCallEnvelope,
        event: BudgetEvent,
        status: str,
        error_code: str,
        error: Mapping[str, Any],
    ) -> ToolResult:
        return ToolResult(
            task_id=self.task_id,
            attempt=self.attempt,
            policy_scope=self.policy_scope,
            tool_call_id=envelope.tool_call_id,
            tool_name=envelope.tool_name,
            arguments_sha256=envelope.arguments_sha256,
            operation=envelope.operation,
            budget_event_sequence=event.sequence,
            status=status,
            error_code=error_code,
            error=error,
        )

    def call(
        self,
        tool_call_id: str,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> ToolResult:
        """Charge and execute one policy-allowed trusted tool.

        Invalid policy/input/reference requests fail before charging.  Once a
        charge succeeds, handler blocks and failures are converted into stable
        terminal records; the budget is never refunded.
        """

        with self._lock:
            if self._finalized:
                raise ToolRuntimeFinalized("tool runtime is already finalized")
            if self._executing:
                raise ToolRuntimeError("re-entrant tool calls are not allowed")
            call_id = _identifier(
                tool_call_id, name="tool_call_id", pattern=_TOOL_CALL_ID_RE
            )
            name = _identifier(tool_name, name="tool_name", pattern=_TOOL_NAME_RE)
            if call_id in {record.tool_call_id for record in self._records}:
                raise ValueError(f"duplicate tool_call_id: {call_id}")
            if name not in self._registry:
                raise ToolNotAllowed(f"tool is not registered: {name}")
            if name not in self._allowlist:
                raise ToolNotAllowed(f"tool is not allowed in this attempt: {name}")

            normalized_arguments = self._normalize_arguments(
                {} if arguments is None else arguments
            )
            envelope = ToolCallEnvelope(
                task_id=self.task_id,
                attempt=self.attempt,
                policy_scope=self.policy_scope,
                tool_call_id=call_id,
                tool_name=name,
                arguments=normalized_arguments,
            )

            # BudgetExceeded intentionally propagates before handler state or a
            # synthetic result record is created.
            event = self._budget.charge_tool_call(operation=envelope.operation)
            definition = self._registry[name]
            self._executing = True
            try:
                try:
                    handler_output = definition.handler(envelope)
                    if not isinstance(handler_output, ToolHandlerOutput):
                        raise ValueError(
                            "trusted handler must return ToolHandlerOutput"
                        )
                    new_artifacts = handler_output.artifacts
                    if len(self._artifacts) + len(new_artifacts) > _MAX_ARTIFACTS_PER_ATTEMPT:
                        raise ValueError("attempt artifact count limit exceeded")
                    artifact_ids = {item.artifact_id for item in self._artifacts}
                    proposed_ids: set[str] = set()
                    proposed_bytes = 0
                    for artifact in new_artifacts:
                        if (
                            artifact.task_id != self.task_id
                            or artifact.attempt != self.attempt
                            or artifact.policy_scope != self.policy_scope
                            or artifact.tool_call_id != call_id
                        ):
                            raise ValueError(
                                "handler artifact does not match exact call scope"
                            )
                        if (
                            artifact.artifact_id in artifact_ids
                            or artifact.artifact_id in proposed_ids
                        ):
                            raise ValueError(
                                f"duplicate artifact_id: {artifact.artifact_id}"
                            )
                        proposed_ids.add(artifact.artifact_id)
                        proposed_bytes += artifact.canonical_bytes
                    if (
                        self._artifact_bytes + proposed_bytes
                        > _MAX_ARTIFACT_BYTES_PER_ATTEMPT
                    ):
                        raise ValueError("attempt artifact byte limit exceeded")

                    refs = tuple(
                        ArtifactRef(
                            task_id=self.task_id,
                            attempt=self.attempt,
                            policy_scope=self.policy_scope,
                            artifact_id=artifact.artifact_id,
                            artifact_sha256=artifact.artifact_sha256,
                        )
                        for artifact in new_artifacts
                    )
                    result = ToolResult(
                        task_id=self.task_id,
                        attempt=self.attempt,
                        policy_scope=self.policy_scope,
                        tool_call_id=call_id,
                        tool_name=name,
                        arguments_sha256=envelope.arguments_sha256,
                        operation=envelope.operation,
                        budget_event_sequence=event.sequence,
                        status="success",
                        output=handler_output.output,
                        artifact_refs=refs,
                    )
                except ToolBlocked as exc:
                    new_artifacts = ()
                    refs = ()
                    proposed_bytes = 0
                    result = self._make_error_result(
                        envelope=envelope,
                        event=event,
                        status="blocked",
                        error_code=exc.error_code,
                        error=exc.detail,
                    )
                except Exception as exc:  # trusted boundary: record, never refund
                    new_artifacts = ()
                    refs = ()
                    proposed_bytes = 0
                    exception_type = (
                        f"{type(exc).__module__}.{type(exc).__qualname__}"
                    )
                    result = self._make_error_result(
                        envelope=envelope,
                        event=event,
                        status="error",
                        error_code="handler_error",
                        error={"exception_type": exception_type},
                    )
            finally:
                self._executing = False

            self._artifacts.extend(new_artifacts)
            self._artifact_bytes += proposed_bytes
            for ref in refs:
                self._issued_refs[ref.artifact_id] = ref
            self._records.append(result)
            return result

    def _verify_budget_ledger(self) -> None:
        events = self._budget.events
        if len(events) < self._initial_budget_event_count:
            raise ToolLedgerMismatch("budget ledger was truncated")
        attempt_events = events[self._initial_budget_event_count :]
        tool_events = tuple(
            event for event in attempt_events if event.resource == TOOL_CALLS
        )
        if len(tool_events) != len(self._records):
            raise ToolLedgerMismatch(
                "attempt tool-call budget delta does not equal recorded calls"
            )
        if (
            self._budget.usage.tool_calls - self._initial_tool_usage
            != len(self._records)
        ):
            raise ToolLedgerMismatch(
                "tool-call usage delta does not equal recorded calls"
            )
        event_by_sequence = {event.sequence: event for event in tool_events}
        for record in self._records:
            event = event_by_sequence.get(record.budget_event_sequence)
            if event is None:
                raise ToolLedgerMismatch(
                    f"record {record.tool_call_id} has no budget event"
                )
            if (
                event.resource != TOOL_CALLS
                or event.amount != 1
                or event.operation != record.operation
            ):
                raise ToolLedgerMismatch(
                    f"budget event does not bind record {record.tool_call_id}"
                )

    def finalize(self) -> AttemptToolTranscript:
        """Verify the ledger and irreversibly seal this attempt runtime."""

        with self._lock:
            if self._transcript is not None:
                return self._transcript
            if self._finalization_error is not None:
                raise ToolLedgerMismatch(self._finalization_error)
            if self._executing:
                raise ToolRuntimeError("cannot finalize during a tool call")
            # A finalize attempt is a one-way seal even when reconciliation
            # discovers corruption.  Further calls could only obscure the
            # original mismatch.
            self._finalized = True
            try:
                self._verify_budget_ledger()
            except Exception as exc:
                self._finalization_error = str(exc)
                raise

            artifact_by_id = {item.artifact_id: item for item in self._artifacts}
            for record in self._records:
                for ref in record.artifact_refs:
                    artifact = artifact_by_id.get(ref.artifact_id)
                    if artifact is None or artifact.artifact_sha256 != ref.artifact_sha256:
                        raise ToolRuntimeError(
                            f"artifact reference mismatch for {ref.artifact_id}"
                        )
                    if artifact.tool_call_id != record.tool_call_id:
                        raise ToolRuntimeError(
                            f"artifact call binding mismatch for {ref.artifact_id}"
                        )

            try:
                transcript = AttemptToolTranscript(
                    task_id=self.task_id,
                    attempt=self.attempt,
                    policy_scope=self.policy_scope,
                    registry_sha256=self._registry_sha256,
                    allowlist_sha256=self._allowlist_sha256,
                    records=tuple(self._records),
                    artifacts=tuple(self._artifacts),
                )
            except Exception as exc:
                self._finalization_error = str(exc)
                raise
            self._transcript = transcript
            return transcript


__all__ = [
    "ArtifactRef",
    "AttemptToolRuntime",
    "AttemptToolTranscript",
    "ToolArtifact",
    "ToolBlocked",
    "ToolCallEnvelope",
    "ToolDefinition",
    "ToolHandlerOutput",
    "ToolLedgerMismatch",
    "ToolNotAllowed",
    "ToolReferenceError",
    "ToolResult",
    "ToolRuntimeError",
    "ToolRuntimeFinalized",
]
