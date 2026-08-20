"""Public contracts for the VulnGym B-v2 closed-loop orchestrator."""

from .contracts import (
    ProductionOutcome,
    RunTask,
    ToolCallRecord,
    canonical_json,
    canonical_sha256,
)
from .budget import (
    BUDGET_RESOURCES,
    LLM_CALLS,
    REPAIR_ITERATIONS,
    TOOL_CALLS,
    Budget,
    BudgetEvent,
    BudgetExceeded,
    Limits,
    Usage,
)
from .repair_plan import (
    RepairInstruction,
    RepairPlan,
    build_repair_plan,
    dependent_field_closure,
)
from .state_machine import (
    CandidateValidator,
    ClosedLoopOrchestrator,
    ClosedLoopOutcome,
    ProductionAttemptSummary,
    ProductionSummary,
    RUN_STATUSES,
    RunState,
    TERMINAL_STATUSES,
    TerminationSummary,
    ValidationSummary,
)

__all__ = [
    "BUDGET_RESOURCES",
    "Budget",
    "BudgetEvent",
    "BudgetExceeded",
    "CandidateValidator",
    "ClosedLoopOrchestrator",
    "ClosedLoopOutcome",
    "LLM_CALLS",
    "Limits",
    "ProductionOutcome",
    "ProductionAttemptSummary",
    "ProductionSummary",
    "RUN_STATUSES",
    "REPAIR_ITERATIONS",
    "RepairInstruction",
    "RepairPlan",
    "RunTask",
    "RunState",
    "TERMINAL_STATUSES",
    "TerminationSummary",
    "ToolCallRecord",
    "TOOL_CALLS",
    "Usage",
    "ValidationSummary",
    "build_repair_plan",
    "canonical_json",
    "canonical_sha256",
    "dependent_field_closure",
]
