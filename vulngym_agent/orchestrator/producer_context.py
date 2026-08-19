"""Orchestrator-owned execution context for one T2 producer attempt.

The producer receives a narrow :class:`ProducerExecutionContext` capability
instead of receiving the shared ``Budget``, either low-level runtime, the
finalizer, or an issuance receipt.  The orchestrator retains the matching
:class:`ProducerAttemptController`.  Consequently producer code can request
trusted tool/model calls, but it cannot seal the attempt or manufacture the
corresponding public sidecar records.  Only the controller projects records
from sealed runtimes after reconciling them with the exact budget ledger slice.

This is an API capability boundary for trusted Python implementation code and
untrusted model/data inputs.  It is not a sandbox for hostile Python plugins;
such plugins require process isolation.

This module intentionally exposes no shell, network, subprocess, filesystem,
or generic callable primitive.  Concrete trusted tools remain responsible for
their own narrow input contracts.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from threading import RLock
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from vulngym_agent.agents.model_runtime import (
    AttemptModelRuntime,
    AttemptModelTranscript,
    ModelResult,
    StructuredModelBackend,
)
from vulngym_agent.orchestrator.budget import (
    LLM_CALLS,
    TOOL_CALLS,
    Budget,
    BudgetEvent,
)
from vulngym_agent.orchestrator.contracts import ModelCallRecord, ToolCallRecord
from vulngym_agent.tools.runtime import (
    ArtifactRef,
    AttemptToolRuntime,
    AttemptToolTranscript,
    ToolArtifact,
    ToolDefinition,
    ToolResult,
)

if TYPE_CHECKING:
    from vulngym_agent.orchestrator.contracts import RunTask
    from vulngym_agent.orchestrator.repair_plan import RepairPlan


_RECEIPT_FACTORY_KEY = object()
_MODES = frozenset({"generate", "repair"})
_MODEL_STAGE_GRAMMAR = {
    "generate": ("plan", "semantic_judge", "reflection"),
    "repair": ("repair", "reflection"),
}


class ProducerContextError(RuntimeError):
    """Base class for deterministic execution-context failures."""


class ProducerContextFinalized(ProducerContextError):
    """Raised when a call is attempted after finalization has begun."""


class ProducerContextLedgerMismatch(ProducerContextError):
    """Raised when runtime records do not exactly close the budget ledger."""


class ProducerContextReceipt:
    """An in-memory-only proof that a context issued a projection.

    Receipt validity is based solely on object identity.  It deliberately has
    no serializable nonce, dictionary representation, or pickle reduction.
    The receipt is excluded from :meth:`ProducerTranscriptProjection.to_dict`.
    """

    __slots__ = ()

    def __new__(cls, factory_key: object) -> "ProducerContextReceipt":
        if factory_key is not _RECEIPT_FACTORY_KEY:
            raise TypeError("receipts can only be issued by a producer context")
        return super().__new__(cls)

    def __repr__(self) -> str:
        return "<ProducerContextReceipt in-memory-only>"

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise TypeError("producer context receipts cannot be serialized")


@dataclass(frozen=True, slots=True)
class ProducerTranscriptProjection:
    """Immutable, minimal sidecar projection of one sealed producer attempt."""

    task_id: str
    attempt: int
    mode: str
    policy_scope: str
    tool_calls: tuple[ToolCallRecord, ...]
    model_calls: tuple[ModelCallRecord, ...]
    tool_transcript_sha256: str
    model_transcript_sha256: str
    receipt: ProducerContextReceipt = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.mode not in _MODES:
            raise ValueError("mode must be generate or repair")
        if not isinstance(self.receipt, ProducerContextReceipt):
            raise ValueError("receipt must be a ProducerContextReceipt")
        tool_calls = tuple(self.tool_calls)
        model_calls = tuple(self.model_calls)
        if any(not isinstance(item, ToolCallRecord) for item in tool_calls):
            raise ValueError("tool_calls must contain only ToolCallRecord values")
        if any(not isinstance(item, ModelCallRecord) for item in model_calls):
            raise ValueError("model_calls must contain only ModelCallRecord values")
        for record in (*tool_calls, *model_calls):
            if (
                record.task_id != self.task_id
                or record.attempt != self.attempt
                or record.policy_scope != self.policy_scope
            ):
                raise ValueError("record identity/scope differs from projection")
        object.__setattr__(self, "tool_calls", tool_calls)
        object.__setattr__(self, "model_calls", model_calls)

    def to_dict(self) -> dict[str, Any]:
        """Return the serializable sidecar; the receipt is never included."""

        return {
            "task_id": self.task_id,
            "attempt": self.attempt,
            "mode": self.mode,
            "policy_scope": self.policy_scope,
            "tool_calls": [record.to_dict() for record in self.tool_calls],
            "model_calls": [record.to_dict() for record in self.model_calls],
            "tool_transcript_sha256": self.tool_transcript_sha256,
            "model_transcript_sha256": self.model_transcript_sha256,
        }

    @property
    def tool_names(self) -> tuple[str, ...]:
        """Return the runtime-derived tool-name order for policy checks."""

        return tuple(record.tool_name for record in self.tool_calls)

    @property
    def model_stages(self) -> tuple[str, ...]:
        """Return the runtime-derived model-stage order for completion checks."""

        return tuple(record.stage for record in self.model_calls)

    @property
    def call_order(self) -> tuple[tuple[str, str], ...]:
        """Return the exact cross-runtime order derived from ledger sequences."""

        ordered = (
            *(
                (record.budget_event_sequence, "tool", record.tool_name)
                for record in self.tool_calls
            ),
            *(
                (record.budget_event_sequence, "model", record.stage)
                for record in self.model_calls
            ),
        )
        return tuple((kind, name) for _, kind, name in sorted(ordered))


class ProducerExecutionContext:
    """Producer-facing capability with no finalizer, receipt, ledger, or runtime."""

    __slots__ = (
        "__attempt",
        "__call_model",
        "__call_tool",
        "__mode",
        "__policy_scope",
        "__resolve_artifact",
        "__task_id",
    )

    def __init__(
        self,
        *,
        task_id: str,
        attempt: int,
        mode: str,
        policy_scope: str,
        call_tool: Any,
        call_model: Any,
        resolve_artifact: Any,
        factory_key: object,
    ) -> None:
        if factory_key is not _RECEIPT_FACTORY_KEY:
            raise TypeError("producer contexts can only be issued by a controller")
        self.__task_id = task_id
        self.__attempt = attempt
        self.__mode = mode
        self.__policy_scope = policy_scope
        self.__call_tool = call_tool
        self.__call_model = call_model
        self.__resolve_artifact = resolve_artifact

    @property
    def task_id(self) -> str:
        return self.__task_id

    @property
    def attempt(self) -> int:
        return self.__attempt

    @property
    def mode(self) -> str:
        return self.__mode

    @property
    def policy_scope(self) -> str:
        return self.__policy_scope

    def call_tool(
        self,
        tool_call_id: str,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> ToolResult:
        """Invoke one allowlisted trusted tool through the owned controller."""

        return self.__call_tool(tool_call_id, tool_name, arguments)

    def call_model(
        self,
        model_call_id: str,
        stage: str,
        payload: Mapping[str, Any],
    ) -> ModelResult:
        """Invoke the controller's fixed structured model backend."""

        return self.__call_model(model_call_id, stage, payload)

    def resolve_artifact(self, ref: ArtifactRef) -> ToolArtifact:
        """Resolve only an exact artifact capability issued in this attempt."""

        return self.__resolve_artifact(ref)


@runtime_checkable
class ProducerContextFactory(Protocol):
    """Create one orchestrator-owned controller for an active T2 attempt."""

    def create(
        self,
        task: "RunTask",
        *,
        attempt: int,
        mode: str,
        plan: "RepairPlan | None",
        budget: Budget,
    ) -> "ProducerAttemptController":
        ...


class ProducerAttemptController:
    """Orchestrator-owned constructor, ledger reconciler, and finalizer."""

    __slots__ = (
        "_budget",
        "_finalization_error",
        "_initial_budget_events",
        "_lock",
        "_model_runtime",
        "_projection",
        "_producer_context",
        "_receipt",
        "_sealed",
        "_tool_runtime",
        "attempt",
        "mode",
        "policy_scope",
        "task_id",
    )

    def __init__(
        self,
        *,
        task_id: str,
        attempt: int,
        mode: str,
        policy_scope: str,
        budget: Budget,
        tool_registry: Mapping[str, ToolDefinition] | Iterable[ToolDefinition],
        allowed_tools: Iterable[str],
        model_backend: StructuredModelBackend,
    ) -> None:
        if mode not in _MODES:
            raise ValueError("mode must be generate or repair")
        if mode == "generate" and attempt != 0:
            raise ValueError("generate context must use attempt 0")
        if mode == "repair" and attempt not in {1, 2}:
            raise ValueError("repair context must use attempt 1 or 2")
        expected_scope = "t2.initial" if attempt == 0 else f"t2.repair-{attempt}"
        if policy_scope != expected_scope:
            raise ValueError("policy_scope does not match attempt")
        if not isinstance(budget, Budget):
            raise ValueError("budget must be a Budget")

        # The two runtimes receive the same fixed identity, policy, and ledger.
        # Neither runtime nor the ledger is made available through a public
        # property on this producer-facing object.
        tool_runtime = AttemptToolRuntime(
            task_id=task_id,
            attempt=attempt,
            policy_scope=policy_scope,
            budget=budget,
            registry=tool_registry,
            allowlist=allowed_tools,
        )
        model_runtime = AttemptModelRuntime(
            task_id=task_id,
            attempt=attempt,
            policy_scope=policy_scope,
            budget=budget,
            backend=model_backend,
        )

        self.task_id = tool_runtime.task_id
        self.attempt = tool_runtime.attempt
        self.mode = mode
        self.policy_scope = tool_runtime.policy_scope
        self._budget = budget
        self._initial_budget_events = budget.events
        self._tool_runtime = tool_runtime
        self._model_runtime = model_runtime
        self._receipt = ProducerContextReceipt(_RECEIPT_FACTORY_KEY)
        self._projection: ProducerTranscriptProjection | None = None
        self._finalization_error: ProducerContextLedgerMismatch | None = None
        self._sealed = False
        self._lock = RLock()
        self._producer_context = ProducerExecutionContext(
            task_id=self.task_id,
            attempt=self.attempt,
            mode=self.mode,
            policy_scope=self.policy_scope,
            call_tool=self._call_tool,
            call_model=self._call_model,
            resolve_artifact=self._resolve_artifact,
            factory_key=_RECEIPT_FACTORY_KEY,
        )

    @property
    def producer_context(self) -> ProducerExecutionContext:
        """Return the narrow capability that may be passed to producer code."""

        return self._producer_context

    def _call_tool(
        self,
        tool_call_id: str,
        tool_name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> ToolResult:
        """Invoke one allowlisted trusted tool through the owned runtime."""

        with self._lock:
            self._require_open()
            return self._tool_runtime.call(tool_call_id, tool_name, arguments)

    def _call_model(
        self,
        model_call_id: str,
        stage: str,
        payload: Mapping[str, Any],
    ) -> ModelResult:
        """Invoke the fixed structured backend through the owned runtime."""

        with self._lock:
            self._require_open()
            grammar = _MODEL_STAGE_GRAMMAR[self.mode]
            observed = tuple(record.stage for record in self._model_runtime.records)
            if observed != grammar[: len(observed)]:
                raise ProducerContextError(
                    "owned model runtime does not contain a valid stage prefix"
                )
            if len(observed) >= len(grammar) or stage != grammar[len(observed)]:
                expected = grammar[len(observed)] if len(observed) < len(grammar) else None
                raise ValueError(
                    "model stage does not follow the context grammar; "
                    f"expected {expected!r}"
                )
            return self._model_runtime.call(model_call_id, stage, payload)

    def _resolve_artifact(self, ref: ArtifactRef) -> ToolArtifact:
        """Resolve only an exact artifact capability issued by this context."""

        with self._lock:
            return self._tool_runtime.resolve_artifact(ref)

    def issued(self, projection: object) -> bool:
        """Verify both projection identity and its in-memory receipt identity."""

        return (
            projection is self._projection
            and isinstance(projection, ProducerTranscriptProjection)
            and projection.receipt is self._receipt
        )

    def _require_open(self) -> None:
        if self._sealed:
            raise ProducerContextFinalized("producer context is already finalized")

    def _ledger_suffix(self) -> tuple[BudgetEvent, ...]:
        current = self._budget.events
        prefix_length = len(self._initial_budget_events)
        if len(current) < prefix_length or current[:prefix_length] != self._initial_budget_events:
            raise ProducerContextLedgerMismatch("budget ledger prefix was modified")
        return current[prefix_length:]

    def _verify_exact_closure(
        self,
        tool_transcript: AttemptToolTranscript,
        model_transcript: AttemptModelTranscript,
    ) -> tuple[tuple[ToolCallRecord, ...], tuple[ModelCallRecord, ...]]:
        tool_calls = tuple(record.to_tool_call_record() for record in tool_transcript.records)
        model_calls = tuple(model_transcript.records)
        stages = tuple(record.stage for record in model_calls)
        grammar = _MODEL_STAGE_GRAMMAR[self.mode]
        if stages != grammar[: len(stages)]:
            raise ProducerContextLedgerMismatch(
                "model calls do not form a valid context-stage prefix"
            )
        records: tuple[tuple[ToolCallRecord | ModelCallRecord, str], ...] = tuple(
            (record, TOOL_CALLS) for record in tool_calls
        ) + tuple((record, LLM_CALLS) for record in model_calls)

        suffix = self._ledger_suffix()
        if len(suffix) != len(records):
            raise ProducerContextLedgerMismatch(
                "budget-event delta does not equal projected call count"
            )
        events_by_sequence = {event.sequence: event for event in suffix}
        if len(events_by_sequence) != len(suffix):
            raise ProducerContextLedgerMismatch("budget event sequences are not unique")
        if {record.budget_event_sequence for record, _ in records} != set(events_by_sequence):
            raise ProducerContextLedgerMismatch(
                "projected calls do not cover the exact budget-event delta"
            )
        for record, resource in records:
            if (
                record.task_id != self.task_id
                or record.attempt != self.attempt
                or record.policy_scope != self.policy_scope
            ):
                raise ProducerContextLedgerMismatch(
                    "projected call does not match context identity/scope"
                )
            event = events_by_sequence[record.budget_event_sequence]
            if (
                event.resource != resource
                or event.amount != 1
                or event.operation != record.operation
            ):
                raise ProducerContextLedgerMismatch(
                    "projected call does not bind its exact budget event"
                )
        return tool_calls, model_calls

    def finalize(self) -> ProducerTranscriptProjection:
        """Seal both runtimes and return one immutable, receipt-bound projection.

        Successful repeated calls return the same projection object.  Any
        failed finalization also seals the context permanently and is replayed
        as the same stable context-level ledger error.
        """

        with self._lock:
            if self._projection is not None:
                return self._projection
            if self._finalization_error is not None:
                raise self._finalization_error
            self._sealed = True
            try:
                tool_transcript = self._tool_runtime.finalize()
                model_transcript = self._model_runtime.finalize()
                tool_calls, model_calls = self._verify_exact_closure(
                    tool_transcript, model_transcript
                )
                projection = ProducerTranscriptProjection(
                    task_id=self.task_id,
                    attempt=self.attempt,
                    mode=self.mode,
                    policy_scope=self.policy_scope,
                    tool_calls=tool_calls,
                    model_calls=model_calls,
                    tool_transcript_sha256=tool_transcript.transcript_sha256,
                    model_transcript_sha256=model_transcript.transcript_sha256,
                    receipt=self._receipt,
                )
            except Exception as exc:
                if isinstance(exc, ProducerContextLedgerMismatch):
                    error = exc
                else:
                    error = ProducerContextLedgerMismatch(
                        "producer runtime transcript did not close the budget ledger"
                    )
                self._finalization_error = error
                raise error from exc
            self._projection = projection
            return projection


__all__ = [
    "ProducerContextError",
    "ProducerContextFinalized",
    "ProducerContextLedgerMismatch",
    "ProducerContextReceipt",
    "ProducerContextFactory",
    "ProducerAttemptController",
    "ProducerExecutionContext",
    "ProducerTranscriptProjection",
]
