"""Small trusted-runtime fixtures shared by orchestrator unit tests."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from vulngym_agent.agents.model_runtime import ModelRequest
from vulngym_agent.orchestrator.budget import Budget
from vulngym_agent.orchestrator.contracts import RunTask
from vulngym_agent.orchestrator.producer_context import (
    ProducerAttemptController,
    ProducerExecutionContext,
)
from vulngym_agent.orchestrator.repair_plan import RepairPlan
from vulngym_agent.tools.runtime import (
    ToolCallEnvelope,
    ToolDefinition,
    ToolHandlerOutput,
)


class FixedStructuredBackend:
    backend_id = "test.fixed"
    model_id = "test-structured-v1"

    def invoke(self, request: ModelRequest) -> dict[str, Any]:
        return {
            "accepted": True,
            "attempt": request.attempt,
            "stage": request.stage,
        }


def _tool_handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
    return ToolHandlerOutput(
        output={
            "accepted": True,
            "attempt": envelope.attempt,
            "tool": envelope.tool_name,
        }
    )


class FixedProducerContextFactory:
    """Create real attempt controllers with deterministic local capabilities."""

    def __init__(self, tool_names: Iterable[str] = ()) -> None:
        names = tuple(dict.fromkeys(tool_names))
        self._registry = tuple(
            ToolDefinition(
                name=name,
                contract_id=f"vulngym.test-producer.{name}@1",
                handler=_tool_handler,
            )
            for name in names
        )
        self._allowed_tools = names
        self.created: list[ProducerAttemptController] = []
        self.calls: list[tuple[RunTask, int, str, RepairPlan | None, Budget]] = []

    def create(
        self,
        task: RunTask,
        *,
        attempt: int,
        mode: str,
        plan: RepairPlan | None,
        budget: Budget,
    ) -> ProducerAttemptController:
        self.calls.append((task, attempt, mode, plan, budget))
        controller = ProducerAttemptController(
            task_id=task.task_id,
            attempt=attempt,
            mode=mode,
            policy_scope=(
                "t2.initial" if attempt == 0 else f"t2.repair-{attempt}"
            ),
            budget=budget,
            tool_registry=self._registry,
            allowed_tools=self._allowed_tools,
            model_backend=FixedStructuredBackend(),
        )
        self.created.append(controller)
        return controller


def complete_model_stages(context: ProducerExecutionContext) -> None:
    stages = (
        ("plan", "semantic_judge", "reflection")
        if context.mode == "generate"
        else ("repair", "reflection")
    )
    for stage in stages:
        context.call_model(
            f"MODEL-fixture-{context.attempt}-{stage}",
            stage,
            {"attempt": context.attempt, "stage": stage},
        )


__all__ = [
    "FixedProducerContextFactory",
    "FixedStructuredBackend",
    "complete_model_stages",
]
