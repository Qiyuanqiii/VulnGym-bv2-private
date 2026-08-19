"""Interface boundary for VulnGym candidate producers.

Concrete producers may be deterministic test doubles or later LLM-backed
implementations.  The orchestrator depends only on this protocol.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Mapping, Protocol, runtime_checkable

from vulngym_agent.orchestrator.contracts import ProducerResult, RunTask
from vulngym_agent.orchestrator.repair_plan import RepairPlan

if TYPE_CHECKING:
    from vulngym_agent.orchestrator.budget import Budget


@runtime_checkable
class T2Producer(Protocol):
    """Generate or narrowly repair a formal candidate, otherwise defer."""

    def generate(self, task: RunTask, budget: "Budget") -> ProducerResult:
        """Produce a candidate or explicitly defer when evidence is insufficient."""

        ...

    def repair(
        self,
        task: RunTask,
        previous_entry: Mapping[str, Any],
        plan: RepairPlan,
        budget: "Budget",
    ) -> ProducerResult:
        """Narrowly repair authorized fields or explicitly defer the attempt."""

        ...


__all__ = ["ProducerResult", "T2Producer"]
