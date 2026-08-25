"""Fixed in-worker entry for one source-discovery task.

This module does not create a process or claim operating-system isolation.
The trusted launcher must execute it inside a verified provider that exposes
only one read-only source tree and the canonical non-secret handoff.  Model
backends are trusted runtime configuration; untrusted task data cannot name a
module, command, provider, model, credential, or filesystem path.

The only successful return value is one bounded canonical
``SourceDiscoveryRunV1`` wire.  Publication and benchmark projection remain in
the trusted parent after a post-run source verification.
"""

from __future__ import annotations

import os
from typing import Final

from vulngym_agent.agents.model_runtime import (
    ReplayClosureError,
    ReplayStructuredModelBackend,
    StructuredModelBackend,
)
from vulngym_agent.benchmark.sealed_tree_access import (
    DEFAULT_SEALED_TREE_ACCESS_LIMITS,
    SealedTreeAccessError,
    SealedTreeAccessLimits,
    bind_worker_tree,
)
from vulngym_agent.benchmark.worker_handoff import (
    WorkerHandoffError,
    WorkerHandoffV2,
)
from vulngym_agent.orchestrator.budget import Budget, Limits
from vulngym_agent.orchestrator.discovery_pipeline import (
    SOURCE_DISCOVERY_RUN_MAX_WIRE_BYTES,
    SourceDiscoveryRunV1,
    run_source_discovery_task_v1,
)


ISOLATED_WORKER_VERSION: Final[str] = "source-discovery-isolated-worker-v1"
ISOLATED_WORKER_ERROR_TAXONOMY_VERSION: Final[str] = (
    "source-discovery-isolated-worker-errors-v1"
)

DEFAULT_D2_WORKER_BUDGET_LIMITS: Final[Limits] = Limits(
    max_llm_calls=16,
    max_tool_calls=80,
    max_repair_iterations=0,
)
DEFAULT_D3_WORKER_BUDGET_LIMITS: Final[Limits] = Limits(
    max_llm_calls=16,
    max_tool_calls=80,
    max_repair_iterations=0,
)

_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "invalid_backend",
        "invalid_handoff",
        "invalid_limits",
        "invalid_output",
        "run_failed",
        "source_rejected",
    }
)


class IsolatedWorkerError(RuntimeError):
    """Stable, path-free error returned by the fixed worker boundary."""

    taxonomy_version = ISOLATED_WORKER_ERROR_TAXONOMY_VERSION

    def __init__(self, code: str, message: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            code = "run_failed"
            message = "isolated worker failed"
        self.code = code
        super().__init__(message)


def _narrow_budget_limits(value: object, *, ceiling: Limits) -> Limits:
    if type(value) is not Limits:
        raise IsolatedWorkerError(
            "invalid_limits", "worker budget limits must be exact Limits"
        )
    fields = (
        value.max_llm_calls,
        value.max_tool_calls,
        value.max_repair_iterations,
    )
    if any(type(item) is not int for item in fields):
        raise IsolatedWorkerError(
            "invalid_limits", "worker budget limits must be exact integers"
        )
    if (
        not 0 <= fields[0] <= ceiling.max_llm_calls
        or not 0 <= fields[1] <= ceiling.max_tool_calls
        or fields[2] != 0
    ):
        raise IsolatedWorkerError(
            "invalid_limits", "worker budget limits cannot broaden the fixed policy"
        )
    return Limits(
        max_llm_calls=fields[0],
        max_tool_calls=fields[1],
        max_repair_iterations=0,
    )


def _narrow_tree_limits(value: object) -> SealedTreeAccessLimits:
    if type(value) is not SealedTreeAccessLimits:
        raise IsolatedWorkerError(
            "invalid_limits", "worker tree limits must be exact"
        )
    fields = (
        value.max_inventory_calls,
        value.max_read_calls,
        value.max_bytes_per_read,
        value.max_total_bytes_read,
        value.version,
    )
    if any(type(item) is not int for item in fields[:4]) or type(fields[4]) is not str:
        raise IsolatedWorkerError(
            "invalid_limits", "worker tree limits must be exact integers"
        )
    ceiling = DEFAULT_SEALED_TREE_ACCESS_LIMITS
    if (
        not 1 <= fields[0] <= ceiling.max_inventory_calls
        or not 1 <= fields[1] <= ceiling.max_read_calls
        or not 1 <= fields[2] <= ceiling.max_bytes_per_read
        or not 1 <= fields[3] <= ceiling.max_total_bytes_read
        or fields[2] > fields[3]
        or fields[4] != ceiling.version
    ):
        raise IsolatedWorkerError(
            "invalid_limits", "worker tree limits cannot broaden the fixed policy"
        )
    return SealedTreeAccessLimits(
        max_inventory_calls=fields[0],
        max_read_calls=fields[1],
        max_bytes_per_read=fields[2],
        max_total_bytes_read=fields[3],
        version=fields[4],
    )


def _backend_shape(value: object, *, name: str) -> None:
    try:
        backend_id = value.backend_id
        model_id = value.model_id
        invoke = value.invoke
    except (AttributeError, TypeError):
        raise IsolatedWorkerError(
            "invalid_backend", f"{name} does not implement the fixed backend protocol"
        ) from None
    if (
        type(backend_id) is not str
        or type(model_id) is not str
        or not callable(invoke)
    ):
        raise IsolatedWorkerError(
            "invalid_backend", f"{name} does not implement the fixed backend protocol"
        )


def execute_discovery_worker_v1(
    handoff_payload: bytes,
    *,
    expected_handoff_sha256: str,
    expected_handoff_wire_sha256: str,
    tree_root: str | os.PathLike[str],
    d2_backend: StructuredModelBackend,
    d3_backend: StructuredModelBackend,
    d2_budget_limits: Limits = DEFAULT_D2_WORKER_BUDGET_LIMITS,
    d3_budget_limits: Limits = DEFAULT_D3_WORKER_BUDGET_LIMITS,
    tree_limits: SealedTreeAccessLimits = DEFAULT_SEALED_TREE_ACCESS_LIMITS,
) -> bytes:
    """Execute one closed D2/D3/D4 run over a key-free read-only mount."""

    try:
        handoff = WorkerHandoffV2.from_bytes(
            handoff_payload,
            expected_sha256=expected_handoff_sha256,
            expected_wire_sha256=expected_handoff_wire_sha256,
        )
    except (TypeError, ValueError, WorkerHandoffError):
        raise IsolatedWorkerError(
            "invalid_handoff", "worker handoff did not pass strict parsing"
        ) from None
    d2_limits = _narrow_budget_limits(
        d2_budget_limits, ceiling=DEFAULT_D2_WORKER_BUDGET_LIMITS
    )
    d3_limits = _narrow_budget_limits(
        d3_budget_limits, ceiling=DEFAULT_D3_WORKER_BUDGET_LIMITS
    )
    source_limits = _narrow_tree_limits(tree_limits)
    _backend_shape(d2_backend, name="D2 backend")

    def tree_factory():
        return bind_worker_tree(
            handoff.task,
            tree_root,
            handoff_payload,
            expected_handoff_sha256=handoff.handoff_sha256,
            expected_handoff_wire_sha256=handoff.wire_sha256,
            limits=source_limits,
        )

    try:
        run = run_source_discovery_task_v1(
            handoff.task,
            d2_tree_factory=tree_factory,
            d2_budget_factory=lambda: Budget(d2_limits),
            d2_backend=d2_backend,
            d3_tree_factory=tree_factory,
            d3_budget_factory=lambda: Budget(d3_limits),
            d3_backend=d3_backend,
        )
        for backend in (d2_backend, d3_backend):
            if isinstance(backend, ReplayStructuredModelBackend):
                # Invoke the trusted implementation directly so a subclass
                # cannot override closure and turn an unconsumed transcript
                # into a successful formal worker result.
                ReplayStructuredModelBackend.assert_exact_closure(backend)
    except SealedTreeAccessError:
        raise IsolatedWorkerError(
            "source_rejected", "worker source mount did not remain verified"
        ) from None
    except IsolatedWorkerError:
        raise
    except (
        AttributeError,
        KeyError,
        RecursionError,
        ReplayClosureError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        raise IsolatedWorkerError(
            "run_failed", "worker run did not close successfully"
        ) from None
    try:
        wire = run.to_wire()
        canonical = SourceDiscoveryRunV1.from_wire(wire)
    except (AttributeError, RecursionError, RuntimeError, TypeError, ValueError):
        raise IsolatedWorkerError(
            "invalid_output", "worker result is not a canonical closed run"
        ) from None
    if (
        len(wire) > SOURCE_DISCOVERY_RUN_MAX_WIRE_BYTES
        or canonical.task != handoff.task
        or canonical.run_sha256 != run.run_sha256
        or canonical.to_wire() != wire
    ):
        raise IsolatedWorkerError(
            "invalid_output", "worker result binding is invalid"
        )
    return wire


__all__ = [
    "DEFAULT_D2_WORKER_BUDGET_LIMITS",
    "DEFAULT_D3_WORKER_BUDGET_LIMITS",
    "ISOLATED_WORKER_ERROR_TAXONOMY_VERSION",
    "ISOLATED_WORKER_VERSION",
    "IsolatedWorkerError",
    "execute_discovery_worker_v1",
]
