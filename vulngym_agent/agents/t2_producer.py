"""Interface boundary for VulnGym candidate producers.

Concrete producers may be deterministic test doubles or later LLM-backed
implementations.  The orchestrator depends only on this protocol.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping, Protocol, runtime_checkable

from vulngym_agent.orchestrator.contracts import ProductionOutcome, RunTask
from vulngym_agent.orchestrator.repair_plan import RepairPlan

if TYPE_CHECKING:
    from vulngym_agent.orchestrator.budget import Budget


@runtime_checkable
class T2Producer(Protocol):
    """Generate and narrowly repair formal Entry candidates."""

    def generate(self, task: RunTask, budget: "Budget") -> ProductionOutcome:
        """Produce the initial candidate for one task."""

        ...

    def repair(
        self,
        task: RunTask,
        previous_entry: Mapping[str, Any],
        plan: RepairPlan,
        budget: "Budget",
    ) -> ProductionOutcome:
        """Repair only fields authorized by ``plan`` and return a new candidate."""

        ...


__all__ = ["T2Producer"]
