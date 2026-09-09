"""Evidence-bound, offline T2 production and restricted repair.

``LocalStructuredT2Producer`` is deliberately an orchestrator of capabilities,
not another filesystem or Git client.  Every evidence-producing operation is
performed through the orchestrator-owned ``ProducerExecutionContext`` facade.
The injected model may choose only among runtime-issued candidate identifiers
and may supply four bounded descriptive strings; it can never supply a commit,
path, line, or code snippet.

The model wire contracts are intentionally small and exact:

* ``plan`` -> ``{"action": "analyze" | "defer", "critical_mode": ...}``
* ``semantic_judge`` -> an action, two issued candidate IDs, and bounded
  ``project``/title/category strings
  (opt-in: one ``request_context`` response before the final select/defer)
* ``repair`` -> ``{"action": "apply" | "defer", "repair_fields": [...]}``
* ``reflection`` -> ``{"action": "emit" | "defer"}``

Any malformed response, ambiguous fact, blocked/error result, or missing fact
becomes :class:`ProductionDeferredDraft`.  The producer does not invent a location
to satisfy the 15-field Entry schema.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any

from vulngym_agent.adapters import ENTRY_FIELDS
from vulngym_agent.adapters.schema_adapter import ORIGIN
from vulngym_agent.models import EvidenceItem
from vulngym_agent.orchestrator.budget import BudgetExceeded
from vulngym_agent.orchestrator.contracts import (
    ProductionDeferredDraft,
    ProductionDraft,
    ProducerDraftResult,
    RunTask,
    canonical_sha256,
    freeze_entry_candidate,
)
from vulngym_agent.orchestrator.repair_plan import (
    REPAIR_TOOL_POLICY_VERSION,
    SAFE_REPAIR_TOOL_REGISTRY,
    RepairPlan,
)
from vulngym_agent.orchestrator.producer_context import ProducerExecutionContext
from vulngym_agent.tools import ToolResult

from .model_runtime import ModelResult
from .t2_inputs import T2TaskInput, T2TaskInputV2, parse_t2_task_input
from . import t2_semantic_context as semantic_context_tools
from . import t2_context_followup as context_followup_tools


_MAX_SEMANTIC_CANDIDATES = 64
_MAX_MODEL_CODE_CHARS = 4_000
_SAFE_TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f]+$")
_GHSA_SOURCE_RE = re.compile(
    r"^https://github\.com/advisories/(GHSA-[0-9A-Za-z]{4}-"
    r"[0-9A-Za-z]{4}-[0-9A-Za-z]{4})/?$"
)

_TOOL_DEFER_STAGES = {
    "read_local_advisory": "load_advisory",
    "extract_advisory_fields": "extract_advisory",
    "read_local_patch": "analyze_patch",
    "resolve_local_repo": "resolve_repo",
    "git_parents": "resolve_commit",
    "git_show": "resolve_commit",
    "git_diff": "analyze_patch",
    "version_ancestry": "resolve_commit",
    "dataflow_candidate_search": "resolve_critical",
    "route_recognition": "resolve_entry",
    "validate_schema": "validate_schema",
}

_REPAIR_TASK_CHECKS = frozenset({"task:entry_id", "task:report_id"})
_REPAIR_ADVISORY_CHECKS = frozenset(
    {
        "advisory:id",
        "advisory:source_link",
        "advisory:title",
        "advisory:vulnerability_type",
        "advisory:vuln_ids",
    }
)
_REPAIR_SEMANTIC_CHECKS = frozenset(
    {"semantic:title", "semantic:category_l1", "semantic:category_l2"}
)
_REPAIR_ADVISORY_TOOLS = frozenset(
    {"read_local_advisory", "extract_advisory_fields"}
)


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _thaw(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _freeze_public_json(value: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return a detached, recursively immutable JSON object."""

    def freeze(item: Any) -> Any:
        if isinstance(item, Mapping):
            return MappingProxyType({str(key): freeze(child) for key, child in item.items()})
        if isinstance(item, (list, tuple)):
            return tuple(freeze(child) for child in item)
        return item

    frozen = freeze(value)
    assert isinstance(frozen, Mapping)
    return frozen


@dataclass(frozen=True, slots=True)
class _CriticalChoice:
    issued_id: str
    source_candidate_id: str
    location: Mapping[str, Any]
    mode: str
    change_kind: str
    evidence: str
    tool_call_id: str

    def model_value(self) -> dict[str, Any]:
        return {
            "candidate_id": self.issued_id,
            "source_candidate_id": self.source_candidate_id,
            "mode": self.mode,
            "change_kind": self.change_kind,
            "location": _thaw(self.location),
            "evidence": self.evidence[:2_000],
        }


@dataclass(frozen=True, slots=True)
class _EntryChoice:
    issued_id: str
    location: Mapping[str, Any]
    kind: str
    symbol: str | None
    explicit_external_binding: bool
    direct_critical_reference: bool
    evidence: str
    tool_call_id: str

    def model_value(self) -> dict[str, Any]:
        return {
            "candidate_id": self.issued_id,
            "location": _thaw(self.location),
            "kind": self.kind,
            "symbol": self.symbol,
            "explicit_external_binding": self.explicit_external_binding,
            "direct_critical_reference": self.direct_critical_reference,
            "evidence": self.evidence[:2_000],
        }


class _Stop(RuntimeError):
    """Internal, machine-readable fail-closed transition."""

    __slots__ = ("stage", "reason_code", "missing_information")

    def __init__(
        self, stage: str, reason_code: str, missing_information: Sequence[str]
    ) -> None:
        self.stage = stage
        self.reason_code = reason_code
        self.missing_information = tuple(dict.fromkeys(missing_information))
        super().__init__(reason_code)


class _Attempt:
    """Producer-facing helper over one orchestrator-owned capability facade."""

    __slots__ = (
        "attempt",
        "context",
        "digest",
        "evidence",
        "last_stage",
        "model_sequence",
        "mode",
        "policy_scope",
        "task",
        "tool_sequence",
    )

    def __init__(
        self,
        *,
        task: RunTask,
        context: ProducerExecutionContext,
    ) -> None:
        if not isinstance(context, ProducerExecutionContext):
            raise ValueError("context must be a ProducerExecutionContext")
        if context.task_id != task.task_id:
            raise ValueError("context task_id does not match task")
        self.task = task
        self.context = context
        self.attempt = context.attempt
        self.mode = context.mode
        self.digest = hashlib.sha256(
            _canonical_json(task.to_dict()).encode("utf-8")
        ).hexdigest()
        self.policy_scope = context.policy_scope
        self.tool_sequence = 0
        self.model_sequence = 0
        self.evidence: list[EvidenceItem] = []
        self.last_stage = "plan" if self.mode == "generate" else "repair"

    def _tool_stage(self, name: str) -> str:
        stage = _TOOL_DEFER_STAGES.get(name, "compose")
        if self.mode == "repair" and stage in {
            "load_advisory",
            "extract_advisory",
            "compose",
        }:
            return "repair"
        return stage

    def tool_call(
        self, name: str, arguments: Mapping[str, Any] | None = None, *, stage: str | None = None
    ) -> ToolResult:
        self.tool_sequence += 1
        call_id = (
            f"TOOL-{self.digest[:16]}-A{self.attempt}-"
            f"{self.tool_sequence:03d}-{name}"
        )
        self.last_stage = stage or self._tool_stage(name)
        result = self.context.call_tool(call_id, name, arguments or {})
        if result.status != "success":
            raise _Stop(
                self.last_stage,
                f"tool_{result.status}",
                (f"{name} did not produce trusted evidence ({result.error_code})",),
            )
        return result

    def model_call(self, stage: str, payload: Mapping[str, Any]) -> ModelResult:
        self.model_sequence += 1
        call_id = (
            f"MODEL-{self.digest[:16]}-A{self.attempt}-"
            f"{self.model_sequence:03d}-{stage}"
        )
        self.last_stage = stage
        result = self.context.call_model(call_id, stage, payload)
        if result.status != "success":
            raise _Stop(
                stage,
                f"model_{result.status}",
                (f"{stage} model call did not return a trusted structured result",),
            )
        return result

    def artifact_payload(
        self, result: ToolResult, *, expected_kind: str
    ) -> Mapping[str, Any]:
        if len(result.artifact_refs) != 1:
            raise _Stop(
                self.last_stage,
                "artifact_cardinality",
                (f"{result.tool_name} must emit exactly one artifact",),
            )
        artifact = self.context.resolve_artifact(result.artifact_refs[0])
        if artifact.kind != expected_kind or not isinstance(artifact.payload, Mapping):
            raise _Stop(
                self.last_stage,
                "artifact_kind_mismatch",
                (f"{result.tool_name} emitted an unexpected artifact",),
            )
        return artifact.payload

    def evidence_id(self, label: str) -> str:
        safe = re.sub(r"[^A-Z0-9._-]", "-", label.upper())
        return f"EV-{self.digest[:16].upper()}-A{self.attempt}-{safe}"

class LocalStructuredT2Producer:
    """Produce formal candidates through a controller-owned execution facade."""

    __slots__ = ("_include_reflection_context", "_evidence_first_planning", "_include_semantic_context", "_include_reflection_defer_details", "_context_followup")

    def __init__(
        self, *, include_reflection_context: bool = False,
        evidence_first_planning: bool = False,
        include_semantic_context: bool = False,
        include_reflection_defer_details: bool = False,
        context_followup: bool = False,
    ) -> None:
        if type(include_reflection_context) is not bool:
            raise ValueError("include_reflection_context must be boolean")
        # Opt in only for fresh production. Legacy exact-replay request bytes
        # must remain unchanged, including both reflection stages.
        self._include_reflection_context = include_reflection_context
        if type(evidence_first_planning) is not bool:
            raise ValueError("evidence_first_planning must be boolean")
        self._evidence_first_planning = evidence_first_planning
        if type(include_semantic_context) is not bool:
            raise ValueError("include_semantic_context must be boolean")
        self._include_semantic_context = include_semantic_context
        if type(include_reflection_defer_details) is not bool:
            raise ValueError("include_reflection_defer_details must be boolean")
        if include_reflection_defer_details and not (include_reflection_context and include_semantic_context):
            raise ValueError("reflection defer details require reflection and semantic context")
        self._include_reflection_defer_details = include_reflection_defer_details
        if type(context_followup) is not bool or (context_followup and not include_semantic_context):
            raise ValueError("context followup requires semantic context and a boolean option")
        self._context_followup = context_followup

    def _reflection_decision(self, result: ModelResult, evidence_ids: Sequence[str], *, repaired: bool = False) -> None:
        keys = frozenset({"action"})
        if (self._include_reflection_defer_details and isinstance(result.response, Mapping)
                and result.response.get("action") == "defer"):
            keys = keys | {"defer_details"}
        response = self._exact_response(result, keys, "reflection")
        if response["action"] == "defer":
            if self._include_reflection_defer_details:
                try:
                    details = semantic_context_tools.validate_defer_details(
                        response["defer_details"], evidence_ids, stage="reflection")
                except ValueError:
                    raise _Stop("reflection", "invalid_model_output", (
                        "reflection defer details must reference current evidence and permitted missing fields",)) from None
                raise _Stop("reflection", "model_deferred", (
                    f"Model-reported reflection defer [{details['reason_code']}]: {details['explanation']}",
                    "model_defer_details:" + _canonical_json(details),
                ))
            message = "reflection declined to emit the repaired candidate" if repaired else "reflection declined to emit the candidate"
            raise _Stop("reflection", "model_deferred", (message,))
        if response["action"] != "emit":
            raise _Stop("reflection", "invalid_model_output", ("reflection may only emit or defer",))

    @staticmethod
    def _deferred_without_attempt(
        task: RunTask, *, stage: str, reason_code: str, missing: Sequence[str]
    ) -> ProductionDeferredDraft:
        del task
        return ProductionDeferredDraft(
            stage=stage,
            reason_code=reason_code,
            missing_information=tuple(dict.fromkeys(missing)),
        )

    @staticmethod
    def _finish_deferred(
        run: _Attempt, stop: _Stop
    ) -> ProductionDeferredDraft:
        return ProductionDeferredDraft(
            stage=stop.stage,
            reason_code=stop.reason_code,
            missing_information=stop.missing_information,
            evidence=tuple(run.evidence),
        )

    @staticmethod
    def _finish_outcome(
        run: _Attempt, candidate: Mapping[str, Any]
    ) -> ProductionDraft:
        return ProductionDraft(
            candidate=candidate,
            evidence=tuple(run.evidence),
        )

    @staticmethod
    def _exact_response(
        result: ModelResult, expected: frozenset[str], stage: str
    ) -> Mapping[str, Any]:
        response = result.response
        if not isinstance(response, Mapping) or frozenset(response) != expected:
            raise _Stop(
                stage,
                "invalid_model_output",
                (f"{stage} response did not satisfy its exact JSON contract",),
            )
        return response

    @staticmethod
    def _bounded_text(value: Any, *, field: str, maximum: int) -> str:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value) > maximum
            or _SAFE_TEXT_RE.fullmatch(value) is None
        ):
            raise _Stop(
                "semantic_judge",
                "invalid_model_output",
                (f"model field {field} must be a bounded canonical string",),
            )
        return value

    @staticmethod
    def _ordered_strings(value: Any, *, field: str) -> tuple[str, ...]:
        if (
            isinstance(value, (str, bytes, Mapping, set, frozenset))
            or not isinstance(value, Sequence)
        ):
            raise _Stop(
                "compose",
                "invalid_evidence_shape",
                (f"{field} must be an ordered string array",),
            )
        items = tuple(value)
        if any(not isinstance(item, str) or not item for item in items):
            raise _Stop(
                "compose",
                "invalid_evidence_shape",
                (f"{field} contains an invalid value",),
            )
        return items

    def generate(
        self, task: RunTask, context: ProducerExecutionContext
    ) -> ProducerDraftResult:
        """Generate with legacy routing or opt-in evidence-before-plan routing."""

        if not isinstance(task, RunTask):
            raise ValueError("task must be a RunTask")
        if not isinstance(context, ProducerExecutionContext):
            raise ValueError("context must be a ProducerExecutionContext")
        if (
            context.task_id != task.task_id
            or context.attempt != 0
            or context.mode != "generate"
            or context.policy_scope != "t2.initial"
        ):
            raise ValueError("context does not identify the initial generation round")
        try:
            task_input = parse_t2_task_input(task)
        except (TypeError, ValueError):
            if task.report_id is None or task.entry_id is None:
                raise
            return self._deferred_without_attempt(
                task,
                stage="task_contract",
                reason_code="invalid_task_inputs",
                missing=("a valid strict T2 task input is required",),
            )

        run = _Attempt(task=task, context=context)
        try:
            candidate = self._generate(run, task_input)
            return self._finish_outcome(run, candidate)
        except BudgetExceeded as error:
            return self._finish_deferred(
                run,
                _Stop(
                    run.last_stage,
                    "budget_exceeded",
                    (f"additional {error.resource} budget is required",),
                ),
            )
        except _Stop as stop:
            return self._finish_deferred(run, stop)
        except Exception:
            # An unexpected trusted-component failure must not become a partly
            # assembled Entry.  Details are intentionally not persisted.
            return self._finish_deferred(
                run,
                _Stop(
                    "compose",
                    "producer_internal_error",
                    ("the offline producer could not establish a complete candidate",),
                ),
            )

    def _select_mode(
        self, run: _Attempt, plan_payload: Mapping[str, Any],
        allowed_modes: Sequence[str],
    ) -> str:
        plan = run.model_call("plan", plan_payload)
        plan_response = self._exact_response(
            plan, frozenset({"action", "critical_mode"}), "plan"
        )
        action = plan_response["action"]
        critical_mode = plan_response["critical_mode"]
        if action == "defer":
            if critical_mode is not None:
                raise _Stop(
                    "plan",
                    "invalid_model_output",
                    ("a deferred plan cannot select a critical mode",),
                )
            raise _Stop(
                "plan", "model_deferred", ("the planning stage declined analysis",)
            )
        if action != "analyze" or critical_mode not in allowed_modes:
            raise _Stop(
                "plan",
                "invalid_model_output",
                ("the plan selected an unauthorized critical mode",),
            )
        return critical_mode

    def _collect_critical_choices(
        self, run: _Attempt, resolution_result: ToolResult, *,
        source_path: str, vulnerable_commit: str, fix_commit: str,
        critical_choices: list[_CriticalChoice],
    ) -> dict[str, Any]:
        before_count = len(critical_choices)
        resolution_artifact = run.artifact_payload(
            resolution_result, expected_kind="t2.critical_candidates"
        )
        resolution = resolution_artifact.get("critical_resolution")
        if not isinstance(resolution, Mapping):
            raise _Stop(
                "resolve_critical",
                "invalid_critical_evidence",
                ("critical resolver output is incomplete",),
            )
        provisional_ids = set(
            self._ordered_strings(
                resolution.get("provisional_candidate_ids"),
                field="provisional_candidate_ids",
            )
        )
        candidates = resolution.get("candidates")
        if (
            isinstance(candidates, (str, bytes, Mapping))
            or not isinstance(candidates, Sequence)
        ):
            raise _Stop(
                "resolve_critical",
                "invalid_critical_evidence",
                ("critical candidate evidence is not an ordered array",),
            )
        for assessment in candidates:
            if not isinstance(assessment, Mapping):
                continue
            source_id = assessment.get("candidate_id")
            location = assessment.get("location")
            if source_id not in provisional_ids or not isinstance(location, Mapping):
                continue
            if (
                assessment.get("fact_status") != "correct"
                or assessment.get("in_removed_or_changed_side") is not True
                or assessment.get("change_kind") not in {"removed", "changed", "context"}
                or assessment.get("vulnerable_commit") != vulnerable_commit
                or assessment.get("fix_commit") != fix_commit
                or location.get("file") != source_path
                or not isinstance(location.get("line"), int)
                or isinstance(location.get("line"), bool)
                or location.get("line", 0) < 1
                or not isinstance(location.get("code"), str)
                or not location.get("code")
            ):
                continue
            if len(location["code"]) > _MAX_MODEL_CODE_CHARS:
                raise _Stop(
                    "resolve_critical",
                    "candidate_too_large",
                    ("a critical candidate exceeds the semantic review bound",),
                )
            issued_id = f"critical-{len(critical_choices) + 1:04d}"
            critical_choices.append(
                _CriticalChoice(
                    issued_id=issued_id,
                    source_candidate_id=str(source_id),
                    location=_freeze_public_json(
                        {
                            "file": location["file"],
                            "line": location["line"],
                            "code": location["code"],
                        }
                    ),
                    mode=str(resolution.get("mode")),
                    change_kind=str(assessment.get("change_kind")),
                    evidence=(str(assessment.get("evidence") or "fact-checked diff location") +
                              (" Review pool mode is only a hypothesis; a changed line is not a verified role."
                               if resolution_artifact.get("mode_is_unverified_hypothesis") is True else "")),
                    tool_call_id=resolution_result.tool_call_id,
                )
            )
        reason_counts: dict[str, int] = {}
        for assessment in candidates:
            reason = assessment.get("error_code") if isinstance(assessment, Mapping) else None
            if reason is None:
                reason = "none"
            elif not isinstance(reason, str) or re.fullmatch(r"[a-z0-9_]{1,64}", reason) is None:
                reason = "unclassified"
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        accepted = len(critical_choices) - before_count
        diagnostic = {
            "kind": "critical_candidate_inventory_v1",
            "mode": resolution.get("mode"), "assessed_count": len(candidates),
            "provisional_count": len(provisional_ids), "accepted_count": accepted,
            "not_accepted_count": len(candidates) - accepted,
            "resolver_reason_counts": reason_counts,
            "semantic_role_verified": False,
        }
        if resolution_artifact.get("mode_is_unverified_hypothesis") is True:
            diagnostic["candidate_policy"] = resolution_artifact["candidate_policy"]
            diagnostic["mode_is_unverified_hypothesis"] = True
        return diagnostic

    @staticmethod
    def _planning_evidence(
        *, snippet: str, vulnerable_commit: str, fix_commit: str,
        changed_paths: Sequence[str], diff_context: Sequence[Mapping[str, Any]],
        allowed_modes: Sequence[str], critical_choices: Sequence[_CriticalChoice],
        candidate_policy: str | None = None,
    ) -> dict[str, Any]:
        inventory = []
        for mode in allowed_modes:
            choices = [choice for choice in critical_choices if choice.mode == mode]
            samples = []
            for choice in choices[:4]:
                value = choice.model_value()
                code = value["location"]["code"]
                value["location"]["code"] = code[:1000]
                value["code_truncated"] = len(code) > 1000
                value["evidence"] = value["evidence"][:500]
                samples.append(value)
            inventory.append({"mode": mode, "candidate_count": len(choices), "samples": samples})
        result = {
            "contract_version": 1, "basis": "declared_diff_candidates_v1",
            "advisory_snippet": snippet[:2000], "advisory_snippet_truncated": len(snippet) > 2000,
            "vulnerable_commit": vulnerable_commit, "fix_commit": fix_commit,
            "changed_path_count": len(changed_paths), "diffs": list(diff_context),
            "omitted_diff_count": len(changed_paths) - len(diff_context),
            "mode_inventory": inventory,
            "scope": "declared_paths_and_bounded_lexical_candidates_only",
            "semantic_role_verified": False,
        }
        if candidate_policy is not None:
            result.update(
                candidate_policy=candidate_policy,
                mode_is_unverified_hypothesis=True,
                scope="declared_paths_and_bounded_old_side_review_candidates_only",
            )
        return result

    def _semantic_context(
        self, run: _Attempt, *, repo_ref: str, vulnerable_commit: str, fix_commit: str,
        advisory_text: str, choices: Sequence[_CriticalChoice | _EntryChoice],
        diff_context: Sequence[Mapping[str, Any]], diff_call_ids: Mapping[str, str],
        changed_path_count: int, advisory_call_id: str,
        blob_cache: dict[str, tuple[str, str, str]] | None = None,
    ) -> dict[str, Any]:
        """Read only pinned declared files; retain exactly the context sent to the model."""
        advisory_id = run.evidence_id("SEMANTIC-ADVISORY")
        advisory_truncated = len(advisory_text) > semantic_context_tools.MAX_ADVISORY_CHARS
        advisory_text = advisory_text[:semantic_context_tools.MAX_ADVISORY_CHARS]
        run.evidence.append(EvidenceItem(
            evidence_id=advisory_id, report_id=run.task.report_id, entry_id=run.task.entry_id,
            source_type="advisory", snippet=advisory_text, tool_call_id=advisory_call_id,
        ))
        diffs = []
        for index, diff in enumerate(diff_context):
            evidence_id = run.evidence_id(f"SEMANTIC-DIFF-{index + 1:03d}")
            row = {**_thaw(diff), "evidence_id": evidence_id,
                   "before_commit": vulnerable_commit, "after_commit": fix_commit}
            run.evidence.append(EvidenceItem(
                evidence_id=evidence_id, report_id=run.task.report_id, entry_id=run.task.entry_id,
                source_type="patch", snippet=_canonical_json(row), file=str(diff["file"]),
                commit=fix_commit, tool_call_id=diff_call_ids[str(diff["file"])],
            ))
            diffs.append(row)
        blobs: dict[str, tuple[str, str, str]] = {} if blob_cache is None else blob_cache
        blocks: list[dict[str, Any]] = []
        coverage = []
        used_chars = 0
        # Scheduling windows does not change the issued catalog or select an
        # answer. Late declarations must not lose all context to file ordering.
        context_order = semantic_context_tools.prioritize_context_candidates(
            [choice.model_value() for choice in choices if isinstance(choice, _CriticalChoice)],
            [choice.model_value() for choice in choices if isinstance(choice, _EntryChoice)],
        )
        choices_by_id = {choice.issued_id: choice for choice in choices}
        for candidate_id in context_order:
            choice = choices_by_id[candidate_id]
            path, line = str(choice.location["file"]), int(choice.location["line"])
            covered = next((block for block in blocks if block["file"] == path
                            and block["line_start"] <= line <= block["line_end"]
                            and block["anchor_line_complete"]), None)
            if covered is not None:
                covered["candidate_ids"].append(choice.issued_id)
                coverage.append({"candidate_id": choice.issued_id, "evidence_id": covered["evidence_id"], "status": "included"})
                continue
            remaining = semantic_context_tools.MAX_SOURCE_CHARS - used_chars
            if (len(blocks) >= semantic_context_tools.MAX_SOURCE_BLOCKS or remaining < 256
                    or (path not in blobs and len(blobs) >= semantic_context_tools.MAX_SOURCE_FILES)):
                coverage.append({"candidate_id": choice.issued_id, "evidence_id": None, "status": "omitted_context_budget"})
                continue
            if path not in blobs:
                result = run.tool_call("git_show", {"repo": repo_ref, "commit": vulnerable_commit, "path": path}, stage="semantic_judge")
                payload = run.artifact_payload(result, expected_kind="t2.git_blob")
                text = payload.get("text")
                if (payload.get("commit") != vulnerable_commit or payload.get("path") != path
                        or not isinstance(text, str)
                        or payload.get("text_sha256") != hashlib.sha256(text.encode("utf-8")).hexdigest()):
                    raise _Stop("semantic_judge", "invalid_context_evidence", ("source context did not match its pinned blob",))
                blobs[path] = (text, payload["text_sha256"], result.tool_call_id)
            text, digest, call_id = blobs[path]
            try:
                companions = [int(other.location["line"]) for other in choices
                              if type(other) is not type(choice) and other.location["file"] == path]
                block = semantic_context_tools.source_window(text, path, line,
                    max_chars=min(semantic_context_tools.MAX_BLOCK_CHARS, remaining),
                    companion_lines=companions)
                block = semantic_context_tools.remove_covered_lines(block, blocks)
            except ValueError:
                raise _Stop("semantic_judge", "invalid_context_anchor", ("a candidate anchor is outside the pinned source context",)) from None
            block.update(evidence_id=run.evidence_id(f"SEMANTIC-SOURCE-{len(blocks) + 1:03d}"),
                         commit=vulnerable_commit, blob_sha256=digest, tool_call_id=call_id,
                         candidate_ids=[choice.issued_id])
            blocks.append(block)
            used_chars += len(block["text"])
            coverage.append({"candidate_id": choice.issued_id, "evidence_id": block["evidence_id"],
                             "status": "included" if block["anchor_line_complete"] else "anchor_truncated"})
        for block in blocks:
            run.evidence.append(EvidenceItem(
                evidence_id=block["evidence_id"], report_id=run.task.report_id, entry_id=run.task.entry_id,
                source_type="source", snippet=_canonical_json(block), commit=vulnerable_commit,
                file=block["file"], line_start=block["line_start"], line_end=block["line_end"], tool_call_id=block["tool_call_id"],
            ))
        return {
            "contract_version": 2,
            "advisory": {"evidence_id": advisory_id, "text": advisory_text, "truncated": advisory_truncated,
                         "source": "loaded_advisory_text", "tool_call_id": advisory_call_id},
            "diffs": diffs, "omitted_diff_count": changed_path_count - len(diffs),
            "source_contexts": blocks, "candidate_context_coverage": coverage,
            "context_selection_policy": "role_path_paired_anchors_no_overlap_v2",
            "coverage_basis": "candidate_anchor_line_not_entire_candidate_span",
            "source_chars": used_chars, "source_files_read": len(blobs),
            "scope": "declared_paths_pinned_version_bounded_context_not_a_complete_call_graph",
            "semantic_relationship_verified": False,
            "collector_assessment": {
                "relationship": "not_assessed", "candidate_roles": "not_assessed",
                "false_verification_flags_mean": "collector_has_not_verified_not_a_negative_verdict",
                "pairing_is": "retrieval_proximity_not_semantic_relationship",
                "model_task": "assess_supplied_code_and_advisory_not_presence_of_prior_approval",
            },
        }

    def _followup_context(
        self, run: _Attempt, response: Mapping[str, Any], *,
        choices: Mapping[str, Mapping[str, Any]], context: Mapping[str, Any],
        repo_ref: str, vulnerable_commit: str, declared_paths: Sequence[str],
        blob_cache: dict[str, tuple[str, str, str]],
    ) -> dict[str, Any]:
        """Satisfy one explicit context request using the existing pinned reader."""
        try:
            requests = context_followup_tools.validate_requests(response, choices)
        except ValueError:
            raise _Stop("semantic_judge", "invalid_context_request", (
                "context requests must use issued candidates and the advertised limits",)) from None
        paths = list(dict.fromkeys(str(choices[row["candidate_id"]]["location"]["file"])
                                   for row in requests))
        if any(row["kind"] == "references" for row in requests):
            paths = list(dict.fromkeys((*paths, *declared_paths)))
        if any(path not in declared_paths for path in paths):
            raise _Stop("semantic_judge", "invalid_context_request", (
                "context is limited to the task's declared source paths",))
        selected_paths = paths[:context_followup_tools.MAX_FILES]
        for path in selected_paths:
            if path in blob_cache:
                continue
            result = run.tool_call("git_show", {"repo": repo_ref, "commit": vulnerable_commit,
                                   "path": path}, stage="semantic_judge")
            payload = run.artifact_payload(result, expected_kind="t2.git_blob")
            text = payload.get("text")
            if (payload.get("commit") != vulnerable_commit or payload.get("path") != path
                    or not isinstance(text, str)
                    or payload.get("text_sha256") != hashlib.sha256(text.encode("utf-8")).hexdigest()):
                raise _Stop("semantic_judge", "invalid_context_evidence", (
                    "supplementary context did not match its pinned blob",))
            blob_cache[path] = (text, payload["text_sha256"], result.tool_call_id)
        blocks = context_followup_tools.collect_blocks(
            requests, choices, {path: blob_cache[path][0] for path in selected_paths},
            context["source_contexts"],
        )
        if not blocks:
            raise _Stop("semantic_judge", "context_followup_empty", (
                "requested context yielded no new complete source lines within declared paths and limits",
                "context_requests:" + _canonical_json(requests),))
        for index, block in enumerate(blocks, 1):
            _, digest, call_id = blob_cache[block["file"]]
            block.update(evidence_id=run.evidence_id(f"FOLLOWUP-SOURCE-{index:03d}"),
                         commit=vulnerable_commit, blob_sha256=digest, tool_call_id=call_id)
            run.evidence.append(EvidenceItem(
                evidence_id=block["evidence_id"], report_id=run.task.report_id, entry_id=run.task.entry_id,
                source_type="source", snippet=_canonical_json(block), commit=vulnerable_commit,
                file=block["file"], line_start=block["line_start"], line_end=block["line_end"],
                tool_call_id=call_id,
            ))
        return {**context, "followup": {
            "round": 1, "requests": requests, "source_contexts": blocks,
            "source_chars": sum(len(block["text"]) for block in blocks),
            "source_files_considered": len(selected_paths),
            "omitted_path_count": len(paths) - len(selected_paths),
            "status": "bounded_context_added_not_exhaustive",
            "scope": "declared_paths_pinned_version_occurrences_not_proven_relationships",
        }}

    def _generate(
        self, run: _Attempt, task_input: T2TaskInput
    ) -> Mapping[str, Any]:
        allowed_modes = (
            ("sink", "guard")
            if task_input.hints.critical_mode == "auto"
            else (task_input.hints.critical_mode,)
        )
        plan_payload: dict[str, Any] = {
            "contract_version": 1,
            "task_id": run.task.task_id,
            "report_id": run.task.report_id,
            "entry_id": run.task.entry_id,
            "inputs_sha256": canonical_sha256(run.task.inputs),
            "repo_url": task_input.repo_url,
            "package": task_input.package.to_dict(),
            "hints": task_input.hints.to_dict(),
            "allowed_critical_modes": list(allowed_modes),
            "required_sequence": [
                "local_advisory",
                "advisory_facts",
                "local_repo",
                "single_fix",
                "single_parent",
                "ancestry",
                "declared_path_diffs",
                "critical_candidates",
                "entry_candidates",
                "schema_validation",
                "reflection",
            ],
        }
        if isinstance(task_input, T2TaskInputV2):
            plan_payload["expected_vulnerable_commit"] = (
                task_input.expected_vulnerable_commit
            )
        critical_mode = None
        if not self._evidence_first_planning:
            critical_mode = self._select_mode(run, plan_payload, allowed_modes)

        advisory = run.tool_call("read_local_advisory")
        advisory_ref = advisory.artifact_refs[0]
        facts_result = run.tool_call(
            "extract_advisory_fields", {"advisory": advisory_ref}
        )
        facts = run.artifact_payload(
            facts_result, expected_kind="t2.advisory_facts"
        )
        ghsa_ids = self._ordered_strings(facts.get("ghsa_ids"), field="ghsa_ids")
        if ghsa_ids != (run.task.report_id,):
            raise _Stop(
                "extract_advisory",
                "ambiguous_report_id",
                ("the advisory must contain exactly the task GHSA identifier",),
            )
        fix_commits = self._ordered_strings(
            facts.get("fix_commits"), field="fix_commits"
        )
        if len(fix_commits) != 1:
            raise _Stop(
                "extract_advisory",
                "ambiguous_fix_commit",
                ("the advisory must explicitly identify exactly one fix commit",),
            )
        fix_commit = fix_commits[0]
        source_link = facts.get("source_link")
        source_match = (
            _GHSA_SOURCE_RE.fullmatch(source_link)
            if isinstance(source_link, str)
            else None
        )
        if source_match is None or source_match.group(1).upper() != run.task.report_id:
            raise _Stop(
                "extract_advisory",
                "missing_source_link",
                ("a canonical advisory link matching report_id is required",),
            )
        source_link = f"https://github.com/advisories/{run.task.report_id}"
        snippet = facts.get("snippet")
        if not isinstance(snippet, str) or not snippet.strip():
            raise _Stop(
                "extract_advisory",
                "missing_advisory_summary",
                ("the advisory must contain bounded textual evidence",),
            )
        run.evidence.append(
            EvidenceItem(
                evidence_id=run.evidence_id("ADVISORY"),
                report_id=run.task.report_id,
                entry_id=run.task.entry_id,
                source_type="advisory",
                snippet=snippet[:2_000],
                tool_call_id=facts_result.tool_call_id,
            )
        )

        # Declared patches are capabilities/evidence, never raw parser inputs.
        for patch_path in task_input.package.patches:
            run.tool_call("read_local_patch", {"path": patch_path})

        repo_result = run.tool_call(
            "resolve_local_repo", {"repo_url": task_input.repo_url}
        )
        repo_ref = repo_result.artifact_refs[0]
        parents_result = run.tool_call(
            "git_parents", {"repo": repo_ref, "commit": fix_commit}
        )
        parents = self._ordered_strings(
            parents_result.output.get("parents")
            if isinstance(parents_result.output, Mapping)
            else None,
            field="parents",
        )
        if len(parents) != 1:
            raise _Stop(
                "resolve_commit",
                "fix_not_single_parent",
                ("the advisory fix must have exactly one vulnerable parent",),
            )
        vulnerable_commit = parents[0]
        if (
            isinstance(task_input, T2TaskInputV2)
            and vulnerable_commit != task_input.expected_vulnerable_commit
        ):
            raise _Stop(
                "resolve_commit",
                "vulnerable_commit_mismatch",
                (
                    "the advisory-derived vulnerable parent differs from the "
                    "answer-free benchmark snapshot pin",
                ),
            )
        ancestry = run.tool_call(
            "version_ancestry",
            {
                "repo": repo_ref,
                "ancestor": vulnerable_commit,
                "descendant": fix_commit,
            },
        )
        if (
            not isinstance(ancestry.output, Mapping)
            or ancestry.output.get("is_ancestor") is not True
        ):
            raise _Stop(
                "resolve_commit",
                "ancestry_not_proven",
                ("the vulnerable parent-to-fix ancestry was not proven",),
            )
        run.evidence.append(
            EvidenceItem(
                evidence_id=run.evidence_id("GIT"),
                report_id=run.task.report_id,
                entry_id=run.task.entry_id,
                source_type="git",
                snippet="The unique fix commit has one parent and the parent is its ancestor.",
                commit=vulnerable_commit,
                tool_call_id=ancestry.tool_call_id,
            )
        )

        critical_choices: list[_CriticalChoice] = []
        changed_paths: list[str] = []
        diff_context: list[dict[str, Any]] = []
        diff_call_ids: dict[str, str] = {}
        diagnostics: list[dict[str, Any]] = []
        search_modes = allowed_modes if self._evidence_first_planning else (critical_mode,)
        for source_path in task_input.hints.source_paths:
            diff = run.tool_call(
                "git_diff",
                {
                    "repo": repo_ref, "before_commit": vulnerable_commit,
                    "after_commit": fix_commit, "path": source_path,
                },
            )
            if not isinstance(diff.output, Mapping) or diff.output.get("changed") is not True:
                continue
            changed_paths.append(source_path)
            if (self._evidence_first_planning or self._include_semantic_context) and len(diff_context) < 8:
                diff_payload = run.artifact_payload(diff, expected_kind="t2.git_diff")
                text = diff_payload.get("unified_diff")
                if not isinstance(text, str):
                    raise _Stop("analyze_patch", "invalid_diff_evidence", ("a bounded textual diff is required",))
                diff_context.append({
                    "file": source_path, "added_lines": diff.output.get("added_lines"),
                    "deleted_lines": diff.output.get("deleted_lines"),
                    "excerpt": text[:2000], "truncated": len(text) > 2000,
                })
                diff_call_ids[source_path] = diff.tool_call_id
            for mode in search_modes:
                resolution_result = run.tool_call(
                    "dataflow_candidate_search",
                    {"repo": repo_ref, "diff": diff.artifact_refs[0], "mode": mode},
                )
                diagnostic = self._collect_critical_choices(
                    run, resolution_result, source_path=source_path,
                    vulnerable_commit=vulnerable_commit, fix_commit=fix_commit,
                    critical_choices=critical_choices,
                )
                if self._evidence_first_planning:
                    diagnostics.append(diagnostic)
                    run.evidence.append(EvidenceItem(
                        evidence_id=run.evidence_id(f"INVENTORY-{len(diagnostics):03d}"),
                        report_id=run.task.report_id, entry_id=run.task.entry_id,
                        source_type="patch", snippet=_canonical_json(diagnostic),
                        file=source_path, commit=vulnerable_commit,
                        tool_call_id=resolution_result.tool_call_id,
                    ))
                    if sum(choice.mode == mode for choice in critical_choices) > _MAX_SEMANTIC_CANDIDATES:
                        raise _Stop("resolve_critical", "candidate_set_too_large",
                                    ("one routing mode exceeds the bounded candidate set",))

        if not changed_paths:
            raise _Stop(
                "analyze_patch", "no_declared_source_change",
                ("none of the declared source paths changed in the unique fix",),
            )
        review_policy = next((item["candidate_policy"] for item in diagnostics
                              if item.get("mode_is_unverified_hypothesis") is True), None)
        if self._evidence_first_planning:
            available_modes = tuple(mode for mode in allowed_modes if any(
                choice.mode == mode for choice in critical_choices
            ))
            if not available_modes:
                assessed = sum(item["assessed_count"] for item in diagnostics)
                mismatched = sum(item["resolver_reason_counts"].get("candidate_mode_mismatch", 0)
                                 for item in diagnostics)
                reason = ("critical_extractor_no_candidates" if assessed == 0 else
                          "critical_mode_unsupported_by_candidates" if mismatched == assessed else
                          "critical_candidates_rejected")
                raise _Stop("resolve_critical", reason, (
                    "declared-path extraction provided no admissible candidates for the permitted modes",
                    "review the recorded candidate inventories; this does not establish that the report is unresolvable",
                ))
            plan_payload["contract_version"] = 2
            plan_payload["allowed_critical_modes"] = list(available_modes)
            plan_payload["planning_evidence"] = self._planning_evidence(
                snippet=snippet, vulnerable_commit=vulnerable_commit, fix_commit=fix_commit,
                changed_paths=changed_paths, diff_context=diff_context,
                allowed_modes=allowed_modes, critical_choices=critical_choices,
                candidate_policy=review_policy,
            )
            critical_mode = self._select_mode(run, plan_payload, available_modes)
            critical_choices = [choice for choice in critical_choices if choice.mode == critical_mode]

        if not critical_choices:
            reason = (
                "guard_only_exists_on_fix_side"
                if critical_mode == "guard"
                else "no_vulnerable_side_candidate"
            )
            missing = (
                "a guard location on the vulnerable side is required"
                if critical_mode == "guard"
                else "a fact-checked vulnerable-side critical candidate is required"
            )
            raise _Stop("resolve_critical", reason, (missing,))
        if len(critical_choices) > _MAX_SEMANTIC_CANDIDATES:
            raise _Stop(
                "resolve_critical",
                "candidate_set_too_large",
                ("critical candidates exceed the bounded semantic review set",),
            )

        critical_paths = tuple(
            dict.fromkeys(str(choice.location["file"]) for choice in critical_choices)
        )
        routes_result = run.tool_call(
            "route_recognition",
            {
                "repo": repo_ref,
                "commit": vulnerable_commit,
                "critical_paths": list(critical_paths),
                "critical_symbols": list(task_input.hints.entry_symbols),
            },
        )
        routes = run.artifact_payload(
            routes_result, expected_kind="t2.entry_candidates"
        )
        raw_entries = routes.get("candidates")
        if (
            isinstance(raw_entries, (str, bytes, Mapping))
            or not isinstance(raw_entries, Sequence)
        ):
            raise _Stop(
                "resolve_entry",
                "invalid_entry_evidence",
                ("entry candidate evidence is not an ordered array",),
            )
        entry_choices: list[_EntryChoice] = []
        for raw in raw_entries:
            if not isinstance(raw, Mapping) or raw.get("fact_status") != "correct":
                continue
            path = raw.get("path")
            line = raw.get("line")
            code = raw.get("code")
            if (
                path not in task_input.hints.source_paths
                or not isinstance(line, int)
                or isinstance(line, bool)
                or line < 1
                or not isinstance(code, str)
                or not code
            ):
                continue
            if len(code) > _MAX_MODEL_CODE_CHARS:
                raise _Stop(
                    "resolve_entry",
                    "candidate_too_large",
                    ("an entry candidate exceeds the semantic review bound",),
                )
            entry_choices.append(
                _EntryChoice(
                    issued_id=f"entry-{len(entry_choices) + 1:04d}",
                    location=_freeze_public_json(
                        {"file": path, "line": line, "code": code}
                    ),
                    kind=str(raw.get("kind")),
                    symbol=raw.get("symbol") if isinstance(raw.get("symbol"), str) else None,
                    explicit_external_binding=raw.get("explicit_external_binding") is True,
                    direct_critical_reference=raw.get("direct_critical_reference") is True,
                    evidence=str(raw.get("evidence") or "fact-checked entry construct"),
                    tool_call_id=routes_result.tool_call_id,
                )
            )
        if not entry_choices:
            raise _Stop(
                "resolve_entry",
                "no_entry_candidate",
                ("a fact-checked entry-point candidate is required",),
            )
        if len(entry_choices) > _MAX_SEMANTIC_CANDIDATES:
            raise _Stop(
                "resolve_entry",
                "candidate_set_too_large",
                ("entry candidates exceed the bounded semantic review set",),
            )

        semantic_context = None
        context_blobs: dict[str, tuple[str, str, str]] = {}
        if self._include_semantic_context:
            # Reuse the already-loaded advisory, not the extracted 2,000-character
            # summary. Each backend call is stateless and needs its own context.
            advisory_payload = run.artifact_payload(advisory, expected_kind="t2.local_advisory")
            full_advisory_text = advisory_payload.get("text")
            if not isinstance(full_advisory_text, str) or not full_advisory_text.strip():
                raise _Stop("semantic_judge", "invalid_context_evidence", ("loaded advisory text is unavailable",))
            semantic_context = self._semantic_context(
                run, repo_ref=repo_ref, vulnerable_commit=vulnerable_commit, fix_commit=fix_commit,
                advisory_text=full_advisory_text, choices=(*critical_choices, *entry_choices), diff_context=diff_context,
                diff_call_ids=diff_call_ids, changed_path_count=len(changed_paths), advisory_call_id=advisory.tool_call_id,
                blob_cache=context_blobs if self._context_followup else None,
            )
        semantic_payload = {
                "contract_version": 1,
                "task_id": run.task.task_id,
                "report_id": run.task.report_id,
                "entry_id": run.task.entry_id,
                "repo_url": task_input.repo_url,
                "vulnerable_commit": vulnerable_commit,
                "fix_commit": fix_commit,
                "advisory": {
                    "vuln_ids": list(
                        dict.fromkeys(
                            (*self._ordered_strings(facts.get("cve_ids"), field="cve_ids"),)
                            + ghsa_ids
                            + self._ordered_strings(
                                facts.get("other_vuln_ids"), field="other_vuln_ids"
                            )
                        )
                    ),
                    "snippet": snippet[:2_000],
                    "project_hint": task_input.hints.project,
                },
                "critical_candidates": [
                    choice.model_value() for choice in critical_choices
                ],
                "entry_candidates": [choice.model_value() for choice in entry_choices],
                "output_authority": {
                    "select_only_issued_candidate_ids": True,
                    "free_text_fields": [
                        "project",
                        "vuln_title",
                        "vuln_category_l1",
                        "vuln_category_l2",
                    ],
                    "trace": [],
                },
            }
        context_evidence_ids: list[str] = []
        if review_policy is not None:
            semantic_payload.update(candidate_policy=review_policy,
                                    mode_is_unverified_hypothesis=True)
        if semantic_context is not None:
            context_evidence_ids = [semantic_context["advisory"]["evidence_id"],
                                    *(item["evidence_id"] for item in semantic_context["diffs"]),
                                    *(item["evidence_id"] for item in semantic_context["source_contexts"])]
            semantic_payload.update(contract_version=2, semantic_context=semantic_context,
                                    defer_contract=semantic_context_tools.defer_contract(context_evidence_ids))
        context_choices = {choice.issued_id: choice.model_value() for choice in (*critical_choices, *entry_choices)}
        if self._context_followup:
            semantic_payload["context_request_contract"] = context_followup_tools.request_contract(list(context_choices))
        semantic_result = run.model_call("semantic_judge", semantic_payload)
        if (self._context_followup and isinstance(semantic_result.response, Mapping)
                and semantic_result.response.get("action") == "request_context"):
            semantic_context = self._followup_context(
                run, semantic_result.response, choices=context_choices, context=semantic_context,
                repo_ref=repo_ref, vulnerable_commit=vulnerable_commit,
                declared_paths=task_input.hints.source_paths, blob_cache=context_blobs,
            )
            context_evidence_ids.extend(block["evidence_id"]
                                        for block in semantic_context["followup"]["source_contexts"])
            semantic_payload.update(
                semantic_context=semantic_context,
                context_request_contract=context_followup_tools.request_contract(list(context_choices), rounds_remaining=0),
                defer_contract=semantic_context_tools.defer_contract(context_evidence_ids),
            )
            semantic_result = run.model_call("semantic_judge", semantic_payload)
            if isinstance(semantic_result.response, Mapping) and semantic_result.response.get("action") == "request_context":
                raise _Stop("semantic_judge", "context_followup_exhausted", (
                    "one supplementary read round is complete; unresolved context requires review",))
        semantic_keys = frozenset({"action", "critical_candidate_id", "entry_candidate_id", "project",
                                   "vuln_title", "vuln_category_l1", "vuln_category_l2"})
        if (semantic_context is not None and isinstance(semantic_result.response, Mapping)
                and semantic_result.response.get("action") == "defer"):
            semantic_keys = semantic_keys | {"defer_details"}
        semantic = self._exact_response(
            semantic_result,
            semantic_keys,
            "semantic_judge",
        )
        if semantic["action"] == "defer":
            if any(
                semantic[name] is not None
                for name in semantic
                if name not in {"action", "defer_details"}
            ):
                raise _Stop(
                    "semantic_judge",
                    "invalid_model_output",
                    ("a deferred semantic response cannot supply candidate content",),
                )
            if semantic_context is not None:
                try:
                    details = semantic_context_tools.validate_defer_details(semantic["defer_details"], context_evidence_ids)
                except ValueError:
                    raise _Stop("semantic_judge", "invalid_model_output", ("semantic defer details must reference current evidence and permitted missing fields",)) from None
                raise _Stop("semantic_judge", "model_deferred", (
                    f"Model-reported defer [{details['reason_code']}]: {details['explanation']}",
                    "model_defer_details:" + _canonical_json(details),
                ))
            raise _Stop(
                "semantic_judge",
                "model_deferred",
                ("semantic evidence was insufficient for a safe selection",),
            )
        if semantic["action"] != "select":
            raise _Stop(
                "semantic_judge",
                "invalid_model_output",
                ("semantic action must be select or defer",),
            )
        critical_by_id = {choice.issued_id: choice for choice in critical_choices}
        entry_by_id = {choice.issued_id: choice for choice in entry_choices}
        try:
            selected_critical = critical_by_id[semantic["critical_candidate_id"]]
            selected_entry = entry_by_id[semantic["entry_candidate_id"]]
        except (KeyError, TypeError):
            raise _Stop(
                "semantic_judge",
                "unknown_candidate_id",
                ("the model must select runtime-issued candidate identifiers",),
            ) from None

        project = self._bounded_text(semantic["project"], field="project", maximum=256)
        vuln_title = self._bounded_text(
            semantic["vuln_title"], field="vuln_title", maximum=512
        )
        category_l1 = self._bounded_text(
            semantic["vuln_category_l1"], field="vuln_category_l1", maximum=128
        )
        category_l2 = self._bounded_text(
            semantic["vuln_category_l2"], field="vuln_category_l2", maximum=128
        )
        cve_ids = self._ordered_strings(facts.get("cve_ids"), field="cve_ids")
        other_ids = self._ordered_strings(
            facts.get("other_vuln_ids"), field="other_vuln_ids"
        )
        vuln_ids = list(dict.fromkeys(cve_ids + ghsa_ids + other_ids))
        candidate = {
            "commit": vulnerable_commit,
            "critical_operation": _thaw(selected_critical.location),
            "entry_id": run.task.entry_id,
            "entry_point": _thaw(selected_entry.location),
            "origin": ORIGIN,
            "project": project,
            "repo_url": task_input.repo_url,
            "report_id": run.task.report_id,
            "source_link": source_link,
            "trace": [],
            "verify": 0,
            "vuln_category_l1": category_l1,
            "vuln_category_l2": category_l2,
            "vuln_ids": vuln_ids,
            "vuln_title": vuln_title,
        }
        if set(candidate) != set(ENTRY_FIELDS):
            raise RuntimeError("producer candidate assembly violated ENTRY_FIELDS")

        run.evidence.extend(
            (
                EvidenceItem(
                    evidence_id=run.evidence_id("CRITICAL"),
                    report_id=run.task.report_id,
                    entry_id=run.task.entry_id,
                    source_type="source",
                    snippet=str(selected_critical.location["code"])[:2_000],
                    commit=vulnerable_commit,
                    file=str(selected_critical.location["file"]),
                    line_start=int(selected_critical.location["line"]),
                    line_end=int(selected_critical.location["line"]),
                    tool_call_id=selected_critical.tool_call_id,
                ),
                EvidenceItem(
                    evidence_id=run.evidence_id("ENTRY"),
                    report_id=run.task.report_id,
                    entry_id=run.task.entry_id,
                    source_type="source",
                    snippet=str(selected_entry.location["code"])[:2_000],
                    commit=vulnerable_commit,
                    file=str(selected_entry.location["file"]),
                    line_start=int(selected_entry.location["line"]),
                    line_end=int(selected_entry.location["line"]),
                    tool_call_id=selected_entry.tool_call_id,
                ),
            )
        )
        validation = run.tool_call("validate_schema", {"candidate": candidate})
        if (
            not isinstance(validation.output, Mapping)
            or validation.output.get("valid") is not True
        ):
            raise _Stop(
                "validate_schema",
                "schema_validation_failed",
                ("the assembled 15-field candidate did not satisfy the formal schema",),
            )
        reflection_result = run.model_call(
            "reflection",
            {
                "contract_version": 1,
                "candidate_sha256": canonical_sha256(candidate),
                "schema_valid": True,
                "critical_candidate_id": selected_critical.issued_id,
                "entry_candidate_id": selected_entry.issued_id,
                "allowed_actions": ["emit", "defer"],
                **({"review_context": {
                    "candidate": _thaw(candidate),
                    "advisory_snippet": snippet[:2_000],
                    "fix_commit": fix_commit,
                    "selected_critical": selected_critical.model_value(),
                    "selected_entry": selected_entry.model_value(),
                    "review_kind": "producer_self_review_not_independent",
                    **({"semantic_context": semantic_context} if semantic_context is not None else {}),
                }} if self._include_reflection_context else {}),
                **({"contract_version": 2, "defer_contract": semantic_context_tools.defer_contract(
                    context_evidence_ids, stage="reflection")} if self._include_reflection_defer_details else {}),
            },
        )
        self._reflection_decision(reflection_result, context_evidence_ids)
        return candidate

    def repair(
        self,
        task: RunTask,
        previous_entry: Mapping[str, Any],
        plan: RepairPlan,
        context: ProducerExecutionContext,
    ) -> ProducerDraftResult:
        """Apply only selected, plan-authorized T1 ``suggested_fix`` values."""

        if not isinstance(task, RunTask):
            raise ValueError("task must be a RunTask")
        if not isinstance(plan, RepairPlan):
            raise ValueError("plan must be a RepairPlan")
        if not isinstance(context, ProducerExecutionContext):
            raise ValueError("context must be a ProducerExecutionContext")
        if (
            context.task_id != task.task_id
            or context.attempt != plan.repair_iteration
            or context.mode != "repair"
            or context.policy_scope != f"t2.repair-{plan.repair_iteration}"
        ):
            raise ValueError("context does not identify the active repair round")
        try:
            task_input = parse_t2_task_input(task)
            previous = freeze_entry_candidate(previous_entry)
        except (TypeError, ValueError):
            if task.report_id is None or task.entry_id is None:
                raise
            return self._deferred_without_attempt(
                task,
                stage="repair_contract",
                reason_code="invalid_repair_input",
                missing=("a valid current candidate and strict T2 task are required",),
            )
        run = _Attempt(task=task, context=context)
        try:
            candidate = self._repair(run, task_input, previous, plan)
            return self._finish_outcome(run, candidate)
        except BudgetExceeded as error:
            return self._finish_deferred(
                run,
                _Stop(
                    run.last_stage,
                    "budget_exceeded",
                    (f"additional {error.resource} budget is required",),
                ),
            )
        except _Stop as stop:
            return self._finish_deferred(run, stop)
        except Exception:
            return self._finish_deferred(
                run,
                _Stop(
                    "repair",
                    "producer_internal_error",
                    ("restricted repair could not establish a safe candidate",),
                ),
            )

    def _repair(
        self,
        run: _Attempt,
        task_input: T2TaskInput,
        previous: Mapping[str, Any],
        plan: RepairPlan,
    ) -> Mapping[str, Any]:
        if (
            plan.task_id != run.task.task_id
            or plan.report_id != run.task.report_id
            or plan.entry_id != run.task.entry_id
            or plan.tool_policy_version != REPAIR_TOOL_POLICY_VERSION
            or plan.tool_policy_version not in SAFE_REPAIR_TOOL_REGISTRY
            or plan.previous_candidate_sha256 != canonical_sha256(previous)
        ):
            raise _Stop(
                "repair_contract",
                "repair_plan_binding_mismatch",
                ("RepairPlan must bind the exact task and current candidate digest",),
            )
        try:
            plan.assert_locked_fields(previous)
        except ValueError:
            raise _Stop(
                "repair_contract",
                "locked_field_mismatch",
                ("current locked fields do not match the RepairPlan hashes",),
            ) from None

        check_evidence = self._prepare_repair_checks(run, plan)

        repair_result = run.model_call(
            "repair",
            {
                "contract_version": 1,
                "task_id": run.task.task_id,
                "report_id": run.task.report_id,
                "entry_id": run.task.entry_id,
                "inputs_sha256": canonical_sha256(run.task.inputs),
                "current_candidate_sha256": canonical_sha256(previous),
                "repair_plan_sha256": canonical_sha256(plan.to_dict()),
                "repair_fields": [
                    {
                        "field": field_name,
                        "failure_codes": list(
                            plan.instructions[field_name].failure_codes
                        ),
                        "required_checks": list(
                            plan.instructions[field_name].required_checks
                        ),
                        "allowed_tools": list(
                            plan.instructions[field_name].allowed_tools
                        ),
                        "suggested_fix": _thaw(
                            plan.instructions[field_name].suggested_fix
                        ),
                        "has_suggested_fix": (
                            plan.instructions[field_name].suggested_fix is not None
                        ),
                    }
                    for field_name in plan.repair_fields
                ],
                "allowed_actions": ["apply", "defer"],
                "value_authority": "t1_suggested_fix_only",
                "check_evidence": check_evidence,
            },
        )
        response = self._exact_response(
            repair_result, frozenset({"action", "repair_fields"}), "repair"
        )
        fields_value = response["repair_fields"]
        if (
            isinstance(fields_value, (str, bytes, Mapping, set, frozenset))
            or not isinstance(fields_value, Sequence)
        ):
            raise _Stop(
                "repair",
                "invalid_model_output",
                ("repair_fields must be an ordered array",),
            )
        selected = tuple(fields_value)
        if any(not isinstance(field, str) for field in selected) or len(selected) != len(
            set(selected)
        ):
            raise _Stop(
                "repair",
                "invalid_model_output",
                ("repair_fields must contain unique field names",),
            )
        if response["action"] == "defer":
            if selected:
                raise _Stop(
                    "repair",
                    "invalid_model_output",
                    ("a deferred repair cannot select fields",),
                )
            raise _Stop(
                "repair",
                "model_deferred",
                ("the repair model found no safe plan-authorized change",),
            )
        if response["action"] != "apply" or not selected:
            raise _Stop(
                "repair",
                "invalid_model_output",
                ("repair action must apply at least one authorized field or defer",),
            )
        if any(field not in plan.repair_fields for field in selected):
            raise _Stop(
                "repair",
                "unauthorized_repair_field",
                ("the model selected a field outside RepairPlan.repair_fields",),
            )
        if any(plan.instructions[field].suggested_fix is None for field in selected):
            raise _Stop(
                "repair",
                "missing_suggested_fix",
                ("every selected field requires a T1 suggested_fix value",),
            )

        candidate = _thaw(previous)
        for field_name in selected:
            candidate[field_name] = _thaw(
                plan.instructions[field_name].suggested_fix
            )
        changed = tuple(
            field_name
            for field_name in ENTRY_FIELDS
            if canonical_sha256(candidate[field_name])
            != canonical_sha256(previous[field_name])
        )
        if not changed:
            raise _Stop(
                "repair",
                "repair_no_progress",
                ("selected suggested_fix values do not change the candidate",),
            )
        if any(field not in selected for field in changed):
            raise _Stop(
                "repair",
                "unauthorized_repair_change",
                ("repair changed a field not selected by the model",),
            )
        try:
            plan.assert_locked_fields(candidate)
        except ValueError:
            raise _Stop(
                "repair",
                "locked_field_changed",
                ("restricted repair changed a locked field",),
            ) from None
        if (
            candidate.get("report_id") != run.task.report_id
            or candidate.get("entry_id") != run.task.entry_id
            or candidate.get("repo_url") != task_input.repo_url
            or (
                isinstance(task_input, T2TaskInputV2)
                and candidate.get("commit")
                != task_input.expected_vulnerable_commit
            )
            or candidate.get("origin") != ORIGIN
            or type(candidate.get("verify")) is not int
            or candidate.get("verify") != 0
        ):
            raise _Stop(
                "repair",
                "task_binding_changed",
                (
                    "repair must preserve task identity, origin, repository, "
                    "the benchmark snapshot commit, and verify=0",
                ),
            )

        validation = run.tool_call("validate_schema", {"candidate": candidate})
        if (
            not isinstance(validation.output, Mapping)
            or validation.output.get("valid") is not True
        ):
            raise _Stop(
                "validate_schema",
                "schema_validation_failed",
                ("the repaired candidate did not satisfy the formal schema",),
            )
        reflection_evidence: list[dict[str, Any]] = []
        if self._include_reflection_defer_details:
            # A current schema fact is available even if no advisory read is
            # authorized for this repair. It does not prove semantic truth.
            item = EvidenceItem(
                evidence_id=run.evidence_id("REPAIR-REFLECTION-SCHEMA"),
                report_id=run.task.report_id, entry_id=run.task.entry_id,
                source_type="schema", tool_call_id=validation.tool_call_id,
                snippet=_canonical_json({"candidate_sha256": canonical_sha256(candidate),
                                         "schema_valid": True, "semantic_verified": False}),
            )
            run.evidence.append(item)
            reflection_evidence = [e.to_dict() for e in run.evidence]
        reflection_ids = [e["evidence_id"] for e in reflection_evidence]
        reflection_result = run.model_call(
            "reflection",
            {
                "contract_version": 1,
                "candidate_sha256": canonical_sha256(candidate),
                "parent_candidate_sha256": canonical_sha256(previous),
                "repair_plan_sha256": canonical_sha256(plan.to_dict()),
                "changed_fields": list(changed),
                "schema_valid": True,
                "allowed_actions": ["emit", "defer"],
                **({"review_context": {
                    "candidate": _thaw(candidate),
                    "previous_candidate": _thaw(previous),
                    "check_evidence": check_evidence,
                    "review_kind": "bounded_repair_self_review_not_independent",
                    **({"evidence": reflection_evidence} if self._include_reflection_defer_details else {}),
                }} if self._include_reflection_context else {}),
                **({"contract_version": 2, "defer_contract": semantic_context_tools.defer_contract(
                    reflection_ids, stage="reflection")} if self._include_reflection_defer_details else {}),
            },
        )
        self._reflection_decision(reflection_result, reflection_ids, repaired=True)
        return candidate

    def _prepare_repair_checks(
        self, run: _Attempt, plan: RepairPlan
    ) -> Mapping[str, Any]:
        """Execute the supported pre-repair checks or fail closed.

        Source-location, patch-region, ancestry, and trace-continuity checks
        intentionally remain unsupported here until they have dedicated
        deterministic verifiers.  A RepairPlan that requires one of those
        checks is deferred rather than treating the check name as prompt text.
        """

        checks = tuple(
            dict.fromkeys(
                check
                for field_name in plan.repair_fields
                for check in plan.instructions[field_name].required_checks
            )
        )
        supported = tuple(
            check
            for check in checks
            if check in _REPAIR_TASK_CHECKS
            or check in _REPAIR_ADVISORY_CHECKS
            or check in _REPAIR_SEMANTIC_CHECKS
            or check.startswith("schema:")
        )
        if len(supported) != len(checks):
            unavailable = tuple(check for check in checks if check not in supported)
            raise _Stop(
                "repair",
                "required_checks_unavailable",
                (
                    "trusted repair verifiers are unavailable for: "
                    + ", ".join(unavailable),
                ),
            )

        authorized_tools = {
            tool
            for field_name in plan.repair_fields
            for tool in plan.instructions[field_name].allowed_tools
        }
        needs_advisory = any(check in _REPAIR_ADVISORY_CHECKS for check in checks)
        if needs_advisory and not _REPAIR_ADVISORY_TOOLS <= authorized_tools:
            raise _Stop(
                "repair",
                "required_checks_unavailable",
                ("RepairPlan does not authorize the required advisory checks",),
            )

        summary: dict[str, Any] = {
            "required_checks": list(checks),
            "task_checks": [
                check for check in checks if check in _REPAIR_TASK_CHECKS
            ],
            "schema_checks": [
                check for check in checks if check.startswith("schema:")
            ],
            "semantic_checks": [
                check for check in checks if check in _REPAIR_SEMANTIC_CHECKS
            ],
        }
        if not needs_advisory:
            return summary

        advisory = run.tool_call("read_local_advisory")
        facts_result = run.tool_call(
            "extract_advisory_fields", {"advisory": advisory.artifact_refs[0]}
        )
        facts = run.artifact_payload(
            facts_result, expected_kind="t2.advisory_facts"
        )
        ghsa_ids = self._ordered_strings(facts.get("ghsa_ids"), field="ghsa_ids")
        if run.task.report_id not in ghsa_ids:
            raise _Stop(
                "repair",
                "required_checks_failed",
                ("the local advisory does not bind the active report_id",),
            )
        snippet = facts.get("snippet")
        if not isinstance(snippet, str) or not snippet.strip():
            raise _Stop(
                "repair",
                "required_checks_failed",
                ("the local advisory has no bounded semantic evidence",),
            )
        run.evidence.append(
            EvidenceItem(
                evidence_id=run.evidence_id("REPAIR-ADVISORY"),
                report_id=run.task.report_id,
                entry_id=run.task.entry_id,
                source_type="advisory",
                snippet=snippet[:2_000],
                tool_call_id=facts_result.tool_call_id,
            )
        )
        summary["advisory"] = {
            "ghsa_ids": list(ghsa_ids),
            "cve_ids": list(
                self._ordered_strings(facts.get("cve_ids"), field="cve_ids")
            ),
            "other_vuln_ids": list(
                self._ordered_strings(
                    facts.get("other_vuln_ids"), field="other_vuln_ids"
                )
            ),
            "source_link": facts.get("source_link"),
            "snippet": snippet[:2_000],
        }
        return summary


__all__ = ["LocalStructuredT2Producer"]
