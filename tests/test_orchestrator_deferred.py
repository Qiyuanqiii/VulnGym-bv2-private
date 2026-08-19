from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from typing import Any, Mapping
import unittest

from jsonschema.validators import validator_for
from referencing import Registry, Resource

from vulngym_agent.agents.t1_validator import T1ValidationOutcome
from vulngym_agent.models import EvidenceItem, FieldValidation, ValidationReport
from vulngym_agent.orchestrator.budget import Budget
from vulngym_agent.orchestrator.contracts import (
    ModelCallRecord,
    ProductionDeferred,
    ProductionDeferredDraft,
    ProductionDraft,
    ProductionOutcome,
    RunTask,
    ToolCallRecord,
    canonical_sha256,
)
from vulngym_agent.orchestrator.producer_context import ProducerExecutionContext
from vulngym_agent.orchestrator.state_machine import (
    ClosedLoopOrchestrator,
    STOP_PRODUCER_DEFERRED,
    STOP_PRODUCER_ERROR,
    STOP_SIDECAR_CONFLICT,
    STOP_UNACCOUNTED_MODEL_CALL,
    STOP_UNACCOUNTED_TOOL_CALL,
)
from tests.producer_context_support import (
    FixedProducerContextFactory,
    complete_model_stages,
)


ROOT = Path(__file__).resolve().parents[1]


def _entry() -> dict[str, Any]:
    entry = json.loads(
        (ROOT / "data" / "entries.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    entry["verify"] = 0
    return entry


def _model_call(
    call_id: str,
    *,
    stage: str = "plan",
    attempt: int = 0,
    sequence: int = 1,
) -> ModelCallRecord:
    task_id = "task:deferred-001"
    scope = "t2.initial" if attempt == 0 else f"t2.repair-{attempt}"
    request_sha256 = canonical_sha256({"call": call_id, "side": "request"})
    return ModelCallRecord(
        task_id=task_id,
        attempt=attempt,
        policy_scope=scope,
        model_call_id=call_id,
        stage=stage,
        backend_id="test.replay",
        model_id="test-model",
        request_sha256=request_sha256,
        operation=(
            f"model:{task_id}:{attempt}:{scope}:{stage}:{call_id}:"
            f"test.replay:test-model:{request_sha256}"
        ),
        budget_event_sequence=sequence,
        status="success",
        response_sha256=canonical_sha256({"call": call_id, "side": "response"}),
    )


def _tool_call(
    call_id: str, *, attempt: int = 0, sequence: int = 1
) -> ToolCallRecord:
    task_id = "task:deferred-001"
    scope = "t2.initial" if attempt == 0 else f"t2.repair-{attempt}"
    return ToolCallRecord(
        task_id=task_id,
        attempt=attempt,
        policy_scope=scope,
        tool_call_id=call_id,
        tool_name="local.read_advisory",
        arguments_sha256=canonical_sha256({"call": call_id, "side": "arguments"}),
        operation=(
            f"tool:{task_id}:{attempt}:{scope}:{call_id}:local.read_advisory"
        ),
        budget_event_sequence=sequence,
        status="success",
        result_sha256=canonical_sha256({"call": call_id, "side": "result"}),
    )


class _NeverValidatorFactory:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, task: RunTask) -> object:
        self.calls += 1
        raise AssertionError("T1 must not run after initial production defers")


class _OneReportFactory:
    def __init__(self, report: ValidationReport) -> None:
        self.report = report
        self.calls = 0
        self.seen: list[dict[str, Any]] = []

    def __call__(self, task: RunTask) -> object:
        owner = self

        class Validator:
            def validate(
                self, candidate: Any, *, input_line: int | None = None
            ) -> T1ValidationOutcome:
                owner.calls += 1
                owner.seen.append(deepcopy(candidate))
                return T1ValidationOutcome(report=owner.report, evidence=())

        return Validator()


class OrchestratorDeferredTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entry = _entry()
        self.task = RunTask(
            task_id="task:deferred-001",
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            inputs={"input_line": 9, "private_path": "must-not-be-persisted"},
        )

    def test_initial_defer_is_replayable_manual_review_without_t1(self) -> None:
        task = self.task
        tool_call = _tool_call("TOOL-initial-defer")
        model_call = _model_call("MODEL-initial-defer", sequence=2)
        evidence = EvidenceItem(
            evidence_id="EV-DEFER-INITIAL",
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            source_type="advisory",
            snippet="Public advisory lacks a vulnerable source location.",
            tool_call_id=tool_call.tool_call_id,
        )

        class Producer:
            def generate(
                self, run_task: RunTask, context: ProducerExecutionContext
            ) -> ProductionDeferredDraft:
                context.call_tool(tool_call.tool_call_id, tool_call.tool_name, {})
                context.call_model(model_call.model_call_id, "plan", {})
                return ProductionDeferredDraft(
                    stage="semantic_judge",
                    reason_code="insufficient_source_evidence",
                    missing_information=("SENTINEL-MISSING-SOURCE",),
                    evidence=(evidence,),
                )

            def repair(self, *args: Any, **kwargs: Any) -> ProductionOutcome:
                raise AssertionError("repair must not run")

        factory = _NeverValidatorFactory()
        result = ClosedLoopOrchestrator(
            Producer(),
            factory,
            FixedProducerContextFactory((tool_call.tool_name,)),
        ).run(task)

        self.assertEqual(result.status, "manual_review")
        self.assertEqual(result.state.stop_reason, STOP_PRODUCER_DEFERRED)
        self.assertEqual(factory.calls, 0)
        self.assertIsNone(result.entry)
        self.assertIsNone(result.report)
        self.assertEqual(result.state.validation_count, 0)
        self.assertEqual(result.state.production_history, ())
        self.assertEqual(result.state.production_attempts, ())
        self.assertEqual(result.production_outcomes, ())
        self.assertIsInstance(result.deferred_outcome, ProductionDeferred)
        self.assertEqual(
            result.state.deferred_sha256,
            canonical_sha256(result.deferred_outcome),
        )
        self.assertEqual(result.state.budget["usage"]["tool_calls"], 1)
        self.assertEqual(result.state.budget["usage"]["llm_calls"], 1)

        replayed = ProductionDeferred.from_dict(result.deferred_outcome.to_dict())
        replace(result, deferred_outcome=replayed)
        tampered = replace(replayed, reason_code="different_reason")
        with self.assertRaisesRegex(ValueError, "persisted digest"):
            replace(result, deferred_outcome=tampered)

        serialized = result.state.to_dict()
        schemas = {
            name: json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            for name in (
                "entry.schema.json",
                "validation.schema.json",
                "repair_plan.schema.json",
                "run_state.schema.json",
            )
        }
        registry = Registry()
        for schema in schemas.values():
            registry = registry.with_resource(
                schema["$id"], Resource.from_contents(schema)
            )
        run_schema = schemas["run_state.schema.json"]
        validator_class = validator_for(run_schema)
        validator_class.check_schema(run_schema)
        self.assertEqual(
            list(validator_class(run_schema, registry=registry).iter_errors(serialized)),
            [],
        )
        encoded = json.dumps(serialized, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("must-not-be-persisted", encoded)
        self.assertNotIn("SENTINEL-MISSING-SOURCE", encoded)

    def test_initial_defer_may_use_zero_tool_and_model_calls(self) -> None:
        class Producer:
            def generate(
                self, task: RunTask, context: ProducerExecutionContext
            ) -> ProductionDeferredDraft:
                return ProductionDeferredDraft(
                    stage="load_advisory",
                    reason_code="advisory_missing",
                    missing_information=("public advisory",),
                )

        factory = _NeverValidatorFactory()
        result = ClosedLoopOrchestrator(
            Producer(), factory, FixedProducerContextFactory()
        ).run(self.task)

        self.assertEqual(result.status, "manual_review")
        self.assertEqual(result.state.stop_reason, STOP_PRODUCER_DEFERRED)
        self.assertEqual(result.state.budget["usage"]["tool_calls"], 0)
        self.assertEqual(result.state.budget["usage"]["llm_calls"], 0)
        self.assertEqual(result.deferred_outcome.tool_calls, ())
        self.assertEqual(result.deferred_outcome.model_calls, ())
        self.assertEqual(factory.calls, 0)

    def test_repair_defer_keeps_last_validated_candidate_and_charged_plan(self) -> None:
        task = self.task
        initial_call = _model_call("MODEL-repair-defer-initial")
        repair_call = _model_call(
            "MODEL-repair-defer-final",
            stage="repair",
            attempt=1,
            sequence=4,
        )
        repair_tool = _tool_call(
            "TOOL-repair-defer", attempt=1, sequence=3
        )
        report = ValidationReport(
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            input_line=9,
            verdict="incorrect",
            fields={
                "vuln_title": FieldValidation(
                    status="incorrect",
                    confidence=1.0,
                    evidence="The public title does not match the candidate.",
                    suggested_fix="Correct title",
                )
            },
            summary="One field requires repair.",
        )
        evidence = EvidenceItem(
            evidence_id="EV-DEFER-REPAIR",
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            source_type="git",
            snippet="No safe replacement could be corroborated.",
            tool_call_id=repair_tool.tool_call_id,
        )

        class Producer:
            def generate(
                self, run_task: RunTask, context: ProducerExecutionContext
            ) -> ProductionDraft:
                complete_model_stages(context)
                return ProductionDraft(candidate=self_entry)

            def repair(
                self,
                run_task: RunTask,
                previous_entry: Mapping[str, Any],
                plan: Any,
                context: ProducerExecutionContext,
            ) -> ProductionDeferredDraft:
                context.call_tool(
                    repair_tool.tool_call_id, repair_tool.tool_name, {}
                )
                context.call_model(repair_call.model_call_id, "repair", {})
                return ProductionDeferredDraft(
                    stage="repair",
                    reason_code="no_safe_replacement",
                    missing_information=("corroborated replacement title",),
                    evidence=(evidence,),
                )

        self_entry = deepcopy(self.entry)
        factory = _OneReportFactory(report)
        result = ClosedLoopOrchestrator(
            Producer(),
            factory,
            FixedProducerContextFactory((repair_tool.tool_name,)),
        ).run(task)

        self.assertEqual(result.status, "manual_review")
        self.assertEqual(result.state.stop_reason, STOP_PRODUCER_DEFERRED)
        self.assertEqual(result.state.repair_iteration, 1)
        self.assertEqual(result.state.validation_count, 1)
        self.assertEqual(len(result.repair_plans), 1)
        self.assertIs(result.state.active_repair_plan, result.repair_plans[0])
        self.assertEqual(len(result.production_outcomes), 1)
        self.assertEqual(len(result.state.production_history), 1)
        self.assertEqual(len(result.state.production_attempts), 1)
        self.assertEqual(canonical_sha256(result.entry), canonical_sha256(self.entry))
        self.assertEqual(result.report, report)
        self.assertEqual(factory.calls, 1)
        self.assertEqual(set(factory.seen[0]), set(self.entry))
        self.assertEqual(result.state.budget["usage"]["repair_iterations"], 1)
        self.assertEqual(result.state.budget["usage"]["tool_calls"], 1)
        self.assertEqual(result.state.budget["usage"]["llm_calls"], 4)

        for field_name, expected_error in (
            ("parent_candidate_sha256", "parent digest"),
            ("repair_plan_sha256", "repair-plan digest"),
        ):
            tampered_deferred = replace(
                result.deferred_outcome,
                **{field_name: "f" * 64},
            )
            tampered_state = replace(
                result.state,
                deferred_sha256=canonical_sha256(tampered_deferred),
            )
            with self.subTest(field_name=field_name), self.assertRaisesRegex(
                ValueError, expected_error
            ):
                replace(
                    result,
                    state=tampered_state,
                    deferred_outcome=tampered_deferred,
                )

    def test_completed_draft_requires_the_full_generate_model_grammar(self) -> None:
        correct = ValidationReport(
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            input_line=9,
            verdict="correct",
            fields={
                "schema": FieldValidation(
                    status="correct",
                    confidence=1.0,
                    evidence="Candidate is shaped correctly.",
                )
            },
            summary="Correct.",
        )

        class Producer:
            def __init__(self, stage_count: int) -> None:
                self.stage_count = stage_count

            def generate(
                self, task: RunTask, context: ProducerExecutionContext
            ) -> ProductionDraft:
                stages = ("plan", "semantic_judge", "reflection")
                for index, stage in enumerate(stages[: self.stage_count]):
                    context.call_model(
                        f"MODEL-accounting-{index}", stage, {"index": index}
                    )
                return ProductionDraft(candidate=entry)

        entry = self.entry
        for stage_count in range(4):
            with self.subTest(stage_count=stage_count):
                factory = _OneReportFactory(correct)
                result = ClosedLoopOrchestrator(
                    Producer(stage_count),
                    factory,
                    FixedProducerContextFactory(),
                ).run(self.task)
                if stage_count < 3:
                    self.assertEqual(result.status, "failed")
                    self.assertEqual(result.state.stop_reason, STOP_PRODUCER_ERROR)
                    self.assertEqual(factory.calls, 0)
                else:
                    self.assertEqual(result.status, "finalized")
                    self.assertEqual(factory.calls, 1)

    def test_deferred_draft_accepts_empty_or_partial_context_prefixes(self) -> None:
        class Producer:
            def __init__(
                self,
                *,
                charged_tools: int,
                recorded_tools: int,
                charged_models: int,
                recorded_models: int,
            ) -> None:
                self.charged_tools = charged_tools
                self.recorded_tools = recorded_tools
                self.charged_models = charged_models
                self.recorded_models = recorded_models

            def generate(
                self, task: RunTask, context: ProducerExecutionContext
            ) -> ProductionDeferredDraft:
                for index in range(self.charged_tools):
                    context.call_tool(
                        f"TOOL-defer-accounting-{index}",
                        "local.read_advisory",
                        {"index": index},
                    )
                stages = ("plan", "semantic_judge", "reflection")
                for index, stage in enumerate(stages[: self.charged_models]):
                    context.call_model(
                        f"MODEL-defer-accounting-{index}",
                        stage,
                        {"index": index},
                    )
                return ProductionDeferredDraft(
                    stage="reflection",
                    reason_code="insufficient_evidence",
                    missing_information=("corroboration",),
                )

        cases = (
            (0, 1, 0, 0),
            (2, 1, 0, 0),
            (0, 0, 0, 1),
            (0, 0, 2, 1),
        )
        for charged_tools, recorded_tools, charged_models, recorded_models in cases:
            with self.subTest(
                charged_tools=charged_tools,
                recorded_tools=recorded_tools,
                charged_models=charged_models,
                recorded_models=recorded_models,
            ):
                factory = _NeverValidatorFactory()
                result = ClosedLoopOrchestrator(
                    Producer(
                        charged_tools=charged_tools,
                        recorded_tools=recorded_tools,
                        charged_models=charged_models,
                        recorded_models=recorded_models,
                    ),
                    factory,
                    FixedProducerContextFactory(("local.read_advisory",)),
                ).run(self.task)
                self.assertEqual(result.status, "manual_review")
                self.assertEqual(result.state.stop_reason, STOP_PRODUCER_DEFERRED)
                self.assertIsNotNone(result.deferred_outcome)
                self.assertEqual(
                    len(result.deferred_outcome.tool_calls), charged_tools
                )
                self.assertEqual(
                    len(result.deferred_outcome.model_calls), charged_models
                )
                self.assertEqual(factory.calls, 0)

    def test_formal_deferred_cannot_inject_attempt_topology(self) -> None:
        valid = ProductionDeferred.from_task(
            self.task,
            stage="plan",
            reason_code="missing_advisory",
            missing_information=("advisory",),
        )
        mismatched = replace(valid, task_id="task:someone-else")

        class Producer:
            def generate(
                self, task: RunTask, context: ProducerExecutionContext
            ) -> ProductionDeferred:
                return mismatched

        factory = _NeverValidatorFactory()
        result = ClosedLoopOrchestrator(
            Producer(), factory, FixedProducerContextFactory()
        ).run(self.task)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_PRODUCER_ERROR)
        self.assertIn("ProducerDraftResult", result.error)
        self.assertIsNone(result.deferred_outcome)

    def test_model_call_ids_are_globally_unique_across_deferred_attempt(self) -> None:
        duplicate_id = "MODEL-duplicate-across-rounds"
        initial_call = _model_call(duplicate_id)
        repair_call = _model_call(
            duplicate_id, stage="repair", attempt=1, sequence=3
        )
        report = ValidationReport(
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            input_line=9,
            verdict="incorrect",
            fields={
                "vuln_title": FieldValidation(
                    status="incorrect",
                    confidence=1.0,
                    evidence="Needs repair.",
                    suggested_fix="A title",
                )
            },
            summary="Repair requested.",
        )

        class Producer:
            def generate(
                self, task: RunTask, context: ProducerExecutionContext
            ) -> ProductionDraft:
                context.call_model(duplicate_id, "plan", {})
                context.call_model("MODEL-initial-judge", "semantic_judge", {})
                context.call_model("MODEL-initial-reflect", "reflection", {})
                return ProductionDraft(candidate=entry)

            def repair(
                self,
                task: RunTask,
                previous_entry: Mapping[str, Any],
                plan: Any,
                context: ProducerExecutionContext,
            ) -> ProductionDeferredDraft:
                context.call_model(duplicate_id, "repair", {})
                return ProductionDeferredDraft(
                    stage="repair",
                    reason_code="no_safe_replacement",
                    missing_information=("replacement",),
                )

        entry = self.entry
        result = ClosedLoopOrchestrator(
            Producer(),
            _OneReportFactory(report),
            FixedProducerContextFactory(),
        ).run(self.task)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_SIDECAR_CONFLICT)
        self.assertIn("model call ID", result.error)
        self.assertIsNone(result.deferred_outcome)


if __name__ == "__main__":
    unittest.main()
