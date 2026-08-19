"""Deterministic, append-only execution budgets for the closed-loop runner.

The budget is charged *before* an external operation starts.  A failed
operation therefore remains charged, which makes replay and audit results
independent of exception handling.  Ledger events intentionally contain no
wall-clock timestamp or random identifier.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from threading import Lock
from typing import Any, Callable, Mapping, TypeVar, cast


LLM_CALLS = "llm_calls"
TOOL_CALLS = "tool_calls"
REPAIR_ITERATIONS = "repair_iterations"
BUDGET_RESOURCES = frozenset({LLM_CALLS, TOOL_CALLS, REPAIR_ITERATIONS})

_T = TypeVar("_T")


def _non_negative_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _positive_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _resource_name(resource: str) -> str:
    if not isinstance(resource, str) or resource not in BUDGET_RESOURCES:
        supported = ", ".join(sorted(BUDGET_RESOURCES))
        raise ValueError(f"resource must be one of: {supported}")
    return resource


@dataclass(frozen=True, slots=True)
class Limits:
    """Immutable ceilings for one orchestrator run."""

    max_llm_calls: int = 16
    max_tool_calls: int = 80
    max_repair_iterations: int = 2

    def __post_init__(self) -> None:
        _non_negative_int("max_llm_calls", self.max_llm_calls)
        _non_negative_int("max_tool_calls", self.max_tool_calls)
        _non_negative_int("max_repair_iterations", self.max_repair_iterations)

    @property
    def max_iterations(self) -> int:
        """Read-only compatibility alias; output always uses the new name."""

        return self.max_repair_iterations

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Limits":
        if not isinstance(value, Mapping):
            raise ValueError("limits must be a JSON object")

        allowed = {
            "max_llm_calls",
            "max_tool_calls",
            "max_repair_iterations",
            "max_iterations",
        }
        unknown = set(value) - allowed
        if unknown:
            names = ", ".join(sorted(str(name) for name in unknown))
            raise ValueError(f"unknown limit field(s): {names}")

        has_new = "max_repair_iterations" in value
        has_old = "max_iterations" in value
        if has_new and has_old:
            new_value = value["max_repair_iterations"]
            old_value = value["max_iterations"]
            if new_value != old_value or type(new_value) is not type(old_value):
                raise ValueError(
                    "max_iterations conflicts with max_repair_iterations"
                )

        defaults = cls()
        repair_limit = value.get(
            "max_repair_iterations",
            value.get("max_iterations", defaults.max_repair_iterations),
        )
        return cls(
            max_llm_calls=value.get("max_llm_calls", defaults.max_llm_calls),
            max_tool_calls=value.get("max_tool_calls", defaults.max_tool_calls),
            max_repair_iterations=repair_limit,
        )

    @classmethod
    def from_json(cls, value: str) -> "Limits":
        try:
            decoded = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("limits must be valid JSON") from exc
        return cls.from_dict(decoded)

    def to_dict(self) -> dict[str, int]:
        return {
            "max_llm_calls": self.max_llm_calls,
            "max_tool_calls": self.max_tool_calls,
            "max_repair_iterations": self.max_repair_iterations,
        }

    def to_canonical_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


@dataclass(frozen=True, slots=True)
class Usage:
    """Immutable budget usage (or remaining-capacity) snapshot."""

    llm_calls: int = 0
    tool_calls: int = 0
    repair_iterations: int = 0

    def __post_init__(self) -> None:
        _non_negative_int("llm_calls", self.llm_calls)
        _non_negative_int("tool_calls", self.tool_calls)
        _non_negative_int("repair_iterations", self.repair_iterations)

    def value_for(self, resource: str) -> int:
        return cast(int, getattr(self, _resource_name(resource)))

    def incremented(self, resource: str, amount: int = 1) -> "Usage":
        name = _resource_name(resource)
        increment = _positive_int("amount", amount)
        values = self.to_dict()
        values[name] += increment
        return Usage(**values)

    def to_dict(self) -> dict[str, int]:
        return {
            "llm_calls": self.llm_calls,
            "tool_calls": self.tool_calls,
            "repair_iterations": self.repair_iterations,
        }


@dataclass(frozen=True, slots=True)
class BudgetEvent:
    """One immutable charge in the append-only budget ledger."""

    sequence: int
    resource: str
    amount: int
    usage_after: Usage
    operation: str | None = None

    def __post_init__(self) -> None:
        _positive_int("sequence", self.sequence)
        _resource_name(self.resource)
        _positive_int("amount", self.amount)
        if not isinstance(self.usage_after, Usage):
            raise ValueError("usage_after must be a Usage snapshot")
        if self.operation is not None and (
            not isinstance(self.operation, str) or not self.operation.strip()
        ):
            raise ValueError("operation must be a non-empty string or None")

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "sequence": self.sequence,
            "resource": self.resource,
            "amount": self.amount,
            "usage_after": self.usage_after.to_dict(),
        }
        if self.operation is not None:
            value["operation"] = self.operation
        return value


class BudgetExceeded(RuntimeError):
    """Raised before an operation whose charge would exceed its limit."""

    def __init__(
        self,
        *,
        resource: str,
        requested: int,
        remaining: int,
        usage: Usage,
        limits: Limits,
    ) -> None:
        self.resource = _resource_name(resource)
        self.requested = _positive_int("requested", requested)
        self.remaining = _non_negative_int("remaining", remaining)
        self.usage = usage
        self.limits = limits
        super().__init__(
            f"budget exceeded for {resource}: requested {requested}, "
            f"remaining {remaining}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": "budget_exceeded",
            "resource": self.resource,
            "requested": self.requested,
            "remaining": self.remaining,
            "usage": self.usage.to_dict(),
            "limits": self.limits.to_dict(),
        }


class Budget:
    """Thread-safe controller with an append-only deterministic charge ledger."""

    __slots__ = ("_events", "_limits", "_lock", "_usage")

    def __init__(self, limits: Limits | Mapping[str, Any] | None = None) -> None:
        if limits is None:
            normalized = Limits()
        elif isinstance(limits, Limits):
            normalized = limits
        elif isinstance(limits, Mapping):
            normalized = Limits.from_dict(limits)
        else:
            raise ValueError("limits must be Limits, a JSON object, or None")
        self._limits = normalized
        self._usage = Usage()
        self._events: tuple[BudgetEvent, ...] = ()
        self._lock = Lock()

    @property
    def limits(self) -> Limits:
        return self._limits

    @property
    def usage(self) -> Usage:
        with self._lock:
            return self._usage

    @property
    def events(self) -> tuple[BudgetEvent, ...]:
        with self._lock:
            return self._events

    @property
    def ledger(self) -> tuple[BudgetEvent, ...]:
        """Readable alias for the immutable event tuple."""

        return self.events

    def _limit_for(self, resource: str) -> int:
        name = _resource_name(resource)
        return cast(int, getattr(self._limits, f"max_{name}"))

    def _remaining_unlocked(self, resource: str) -> int:
        return self._limit_for(resource) - self._usage.value_for(resource)

    def remaining(self, resource: str | None = None) -> Usage | int:
        """Return remaining capacity for one resource or all resources."""

        with self._lock:
            if resource is not None:
                return self._remaining_unlocked(resource)
            return Usage(
                llm_calls=self._remaining_unlocked(LLM_CALLS),
                tool_calls=self._remaining_unlocked(TOOL_CALLS),
                repair_iterations=self._remaining_unlocked(REPAIR_ITERATIONS),
            )

    def would_exceed(self, resource: str, amount: int = 1) -> bool:
        increment = _positive_int("amount", amount)
        with self._lock:
            return increment > self._remaining_unlocked(resource)

    def require(self, resource: str, amount: int = 1) -> None:
        """Raise without mutating state when the requested charge cannot fit."""

        increment = _positive_int("amount", amount)
        with self._lock:
            self._require_unlocked(resource, increment)

    def _require_unlocked(self, resource: str, amount: int) -> None:
        name = _resource_name(resource)
        available = self._remaining_unlocked(name)
        if amount > available:
            raise BudgetExceeded(
                resource=name,
                requested=amount,
                remaining=available,
                usage=self._usage,
                limits=self._limits,
            )

    def charge(
        self,
        resource: str,
        amount: int = 1,
        *,
        operation: str | None = None,
    ) -> BudgetEvent:
        """Atomically append a charge before the caller starts its operation."""

        name = _resource_name(resource)
        increment = _positive_int("amount", amount)
        if operation is not None and (
            not isinstance(operation, str) or not operation.strip()
        ):
            raise ValueError("operation must be a non-empty string or None")

        with self._lock:
            self._require_unlocked(name, increment)
            usage_after = self._usage.incremented(name, increment)
            event = BudgetEvent(
                sequence=len(self._events) + 1,
                resource=name,
                amount=increment,
                usage_after=usage_after,
                operation=operation,
            )
            self._usage = usage_after
            self._events = (*self._events, event)
            return event

    def run_charged(
        self,
        resource: str,
        function: Callable[..., _T],
        /,
        *args: Any,
        amount: int = 1,
        operation: str | None = None,
        **kwargs: Any,
    ) -> _T:
        """Charge first, then invoke ``function``; exceptions never refund."""

        if not callable(function):
            raise ValueError("function must be callable")
        self.charge(resource, amount, operation=operation)
        return function(*args, **kwargs)

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "limits": self._limits.to_dict(),
                "usage": self._usage.to_dict(),
                "events": [event.to_dict() for event in self._events],
            }

    def to_canonical_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def charge_llm_call(self, *, operation: str | None = None) -> BudgetEvent:
        return self.charge(LLM_CALLS, operation=operation)

    def charge_tool_call(self, *, operation: str | None = None) -> BudgetEvent:
        return self.charge(TOOL_CALLS, operation=operation)

    def charge_repair_iteration(
        self, *, operation: str | None = None
    ) -> BudgetEvent:
        return self.charge(REPAIR_ITERATIONS, operation=operation)
