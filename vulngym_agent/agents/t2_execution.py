"""Trusted local execution-context factory for the real T2 producer.

The task contract deliberately contains no workstation paths.  This module is
the single composition boundary that binds that path-free contract to trusted
local package and repository roots, then gives the orchestrator an owned
``ProducerAttemptController``.  Producer code receives only the controller's
narrow ``ProducerExecutionContext`` capability.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
import re
from types import MappingProxyType

from vulngym_agent.agents.model_runtime import StructuredModelBackend
from vulngym_agent.agents.t2_inputs import T2TaskInputV1
from vulngym_agent.agents.t2_toolbox import (
    LOCAL_T2_TOOL_NAMES,
    LocalT2Toolbox,
)
from vulngym_agent.orchestrator.budget import Budget
from vulngym_agent.orchestrator.contracts import RunTask
from vulngym_agent.orchestrator.producer_context import ProducerAttemptController
from vulngym_agent.orchestrator.repair_plan import (
    REPAIR_TOOL_POLICY_VERSION,
    RepairPlan,
)


_REPO_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"
)


def _configured_directory(value: object, *, name: str) -> Path:
    """Resolve one trusted directory without reflecting its path on failure."""

    if isinstance(value, str) and not value.strip():
        raise ValueError(f"{name} must identify an existing directory")
    if not isinstance(value, (str, Path)):
        raise ValueError(f"{name} must identify an existing directory")
    try:
        resolved = Path(value).expanduser().resolve(strict=True)
        is_directory = resolved.is_dir()
    except (OSError, RuntimeError, TypeError, ValueError):
        raise ValueError(
            f"{name} must identify an existing directory"
        ) from None
    if not is_directory:
        raise ValueError(f"{name} must identify an existing directory")
    return resolved


def _copy_repo_map(repo_map: object) -> Mapping[str, Path]:
    """Validate and detach the exact GitHub URL to local-directory mapping."""

    if not isinstance(repo_map, Mapping):
        raise ValueError("repo_map must be a non-empty URL-to-directory mapping")
    try:
        # A deep, eager snapshot prevents later mutation of either a regular
        # dictionary or a custom Mapping view from changing task routing.
        items = deepcopy(tuple(repo_map.items()))
    except Exception:
        raise ValueError(
            "repo_map must be a non-empty URL-to-directory mapping"
        ) from None
    if not items:
        raise ValueError("repo_map must be a non-empty URL-to-directory mapping")

    copied: dict[str, Path] = {}
    normalized_keys: set[str] = set()
    for item in items:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError("repo_map contains an invalid entry")
        repo_url, repo_path = item
        if not isinstance(repo_url, str) or _REPO_URL_RE.fullmatch(repo_url) is None:
            raise ValueError("repo_map contains a non-canonical GitHub URL")

        # GitHub repository URLs are case-insensitive in practice.  Retaining
        # two case variants would make an apparently exact trust binding
        # dependent on which spelling happened to arrive in task data.
        normalized = repo_url.casefold()
        if normalized in normalized_keys:
            raise ValueError("repo_map contains a duplicate normalized URL")
        normalized_keys.add(normalized)
        copied[repo_url] = _configured_directory(repo_path, name="repo_map value")

    return MappingProxyType(copied)


class LocalT2ContextFactory:
    """Bind strict T2 tasks to fixed offline tools and one model backend.

    Filesystem locations remain private trusted configuration.  They are not
    copied into a ``RunTask``, a producer execution context, a transcript
    projection, or an exception message.
    """

    __slots__ = ("_backend", "_package_root", "_repo_map")

    def __init__(
        self,
        package_root: str | Path,
        repo_map: Mapping[str, str | Path],
        backend: StructuredModelBackend,
    ) -> None:
        self._package_root = _configured_directory(
            package_root, name="package_root"
        )
        self._repo_map = _copy_repo_map(repo_map)
        if not isinstance(backend, StructuredModelBackend):
            raise ValueError("backend must implement StructuredModelBackend")
        self._backend = backend

    @staticmethod
    def _validate_attempt_plan(
        task: RunTask,
        *,
        attempt: int,
        mode: str,
        plan: RepairPlan | None,
    ) -> RepairPlan | None:
        if mode == "generate":
            if attempt != 0:
                raise ValueError("generate context must use attempt 0")
            if plan is not None:
                raise ValueError("generate context must not receive a RepairPlan")
            return None
        if mode != "repair":
            raise ValueError("mode must be generate or repair")
        if attempt not in {1, 2}:
            raise ValueError("repair context must use attempt 1 or 2")
        if type(plan) is not RepairPlan:
            raise ValueError("repair context requires an exact RepairPlan")

        # Reparse the current wire form so object.__setattr__ or another local
        # mutation cannot bypass RepairPlan's digest/policy invariants.
        try:
            checked = RepairPlan.from_dict(plan.to_dict())
        except (TypeError, ValueError):
            raise ValueError("repair context received an invalid RepairPlan") from None
        if checked != plan:
            raise ValueError("repair context received a non-canonical RepairPlan")
        if (
            checked.task_id != task.task_id
            or checked.report_id != task.report_id
            or checked.entry_id != task.entry_id
            or checked.repair_iteration != attempt
            or checked.tool_policy_version != REPAIR_TOOL_POLICY_VERSION
        ):
            raise ValueError(
                "RepairPlan does not match the active task, parent, iteration, "
                "or tool policy"
            )
        return checked

    @staticmethod
    def _repair_allowlist(
        toolbox: LocalT2Toolbox, plan: RepairPlan
    ) -> tuple[str, ...]:
        requested = {"validate_schema"}
        for field_name in plan.repair_fields:
            requested.update(plan.instructions[field_name].allowed_tools)
        selected = requested & toolbox.tool_names
        # Keep the fixed local-registry order so runtime policy digests are
        # deterministic and never depend on plan mapping iteration order.
        return tuple(name for name in LOCAL_T2_TOOL_NAMES if name in selected)

    def create(
        self,
        task: RunTask,
        *,
        attempt: int,
        mode: str,
        plan: RepairPlan | None,
        budget: Budget,
    ) -> ProducerAttemptController:
        # Parse before consulting trusted configuration.  Every real attempt
        # therefore crosses the same strict, path-free T2 input boundary.
        task_input = T2TaskInputV1.from_task(task)
        checked_plan = self._validate_attempt_plan(
            task, attempt=attempt, mode=mode, plan=plan
        )
        repo_path = self._repo_map.get(task_input.repo_url)
        if repo_path is None:
            raise ValueError("task repository is not present in the trusted repo map")

        toolbox = LocalT2Toolbox(
            task,
            task_input,
            self._package_root,
            repo_path,
        )
        allowed_tools = (
            LOCAL_T2_TOOL_NAMES
            if checked_plan is None
            else self._repair_allowlist(toolbox, checked_plan)
        )
        policy_scope = "t2.initial" if attempt == 0 else f"t2.repair-{attempt}"
        return ProducerAttemptController(
            task_id=task.task_id,
            attempt=attempt,
            mode=mode,
            policy_scope=policy_scope,
            budget=budget,
            tool_registry=toolbox.registry,
            allowed_tools=allowed_tools,
            model_backend=self._backend,
        )


__all__ = ["LocalT2ContextFactory"]
