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
from vulngym_agent.orchestrator.budget import Budget, Limits
from vulngym_agent.orchestrator.contracts import (
    ModelCallRecord,
    ProductionDraft,
    ProductionOutcome,
    RunTask,
    ToolCallRecord,
    canonical_sha256,
)
from vulngym_agent.orchestrator.producer_context import (
    ProducerContextFinalized,
    ProducerExecutionContext,
)
from vulngym_agent.orchestrator.state_machine import (
    ClosedLoopOrchestrator,
    STOP_BUDGET_EXHAUSTED,
    STOP_INVALID_CANDIDATE,
    STOP_LOCKED_FIELD_CHANGED,
    STOP_MAX_REPAIR_ITERATIONS,
    STOP_NO_PROGRESS,
    STOP_NO_REPAIRABLE_FIELDS,
    STOP_PRODUCER_ERROR,
    STOP_REPEATED_ERROR,
    STOP_SIDECAR_CONFLICT,
    STOP_UNACCOUNTED_TOOL_CALL,
    STOP_VALIDATED_CORRECT,
    STOP_VALIDATION_REGRESSION,
    STOP_VALIDATION_UNCERTAIN,
    STOP_VALIDATOR_ERROR,
)
from tests.producer_context_support import (
    FixedProducerContextFactory,
    complete_model_stages,
)


ROOT = Path(__file__).resolve().parents[1]


def _model_call(index: int, *, sequence: int) -> ModelCallRecord:
    task_id = "task:closed-loop-001"
    scope = "t2.initial" if index == 0 else f"t2.repair-{index}"
    stage = "plan" if index == 0 else "repair"
    call_id = f"MODEL-fake-{index}"
    request_sha256 = canonical_sha256({"round": index, "kind": "request"})
    return ModelCallRecord(
        task_id=task_id,
        attempt=index,
        policy_scope=scope,
        model_call_id=call_id,
        stage=stage,
        backend_id="test.fake",
        model_id="test-model",
        request_sha256=request_sha256,
        operation=(
            f"model:{task_id}:{index}:{scope}:{stage}:{call_id}:"
            f"test.fake:test-model:{request_sha256}"
        ),
        budget_event_sequence=sequence,
        status="success",
        response_sha256=canonical_sha256({"round": index, "kind": "response"}),
    )


def _entry() -> dict[str, Any]:
    value = json.loads(
        (ROOT / "data" / "entries.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    value["verify"] = 0
    return value


def _report(
    entry: Mapping[str, Any],
    statuses: Mapping[str, str],
    *,
    label: str = "round",
    suggested_fixes: Mapping[str, Any] | None = None,
) -> ValidationReport:
    fixes = suggested_fixes or {}
    fields: dict[str, FieldValidation] = {}
    for field_name, status in statuses.items():
        fields[field_name] = FieldValidation(
            status=status,
            confidence=1.0 if status != "uncertain" else 0.5,
            evidence=f"{label}:{field_name}:{status}",
            suggested_fix=(
                fixes[field_name]
                if field_name in fixes
                else entry[field_name]
                if status == "incorrect" and field_name in entry
                else None
            ),
        )
    verdict = (
        "incorrect"
        if "incorrect" in statuses.values()
        else "uncertain"
        if "uncertain" in statuses.values()
        else "correct"
    )
    return ValidationReport(
        report_id=entry["report_id"],
        entry_id=entry["entry_id"],
        input_line=7,
        verdict=verdict,
        fields=fields,
        summary=f"Validation {label}.",
    )


class _SequenceValidatorFactory:
    def __init__(self, reports: list[ValidationReport], expected_task: RunTask) -> None:
        self.reports = reports
        self.expected_task = expected_task
        self.created: list[object] = []
        self.seen_candidates: list[dict[str, Any]] = []
        self.seen_input_lines: list[int | None] = []

    def __call__(self, task: RunTask) -> object:
        if task is not self.expected_task:
            raise AssertionError("validator factory did not receive the original task")
        index = len(self.created)
        if index >= len(self.reports):
            raise AssertionError("unexpected validation round")
        owner = self
        report = self.reports[index]

        class Validator:
            def validate(
                self, candidate: Any, *, input_line: int | None = None
            ) -> T1ValidationOutcome:
                if not isinstance(candidate, dict):
                    raise AssertionError("T1 must receive one detached plain object")
                owner.seen_candidates.append(deepcopy(candidate))
                owner.seen_input_lines.append(input_line)
                return T1ValidationOutcome(report=report, evidence=())

        instance = Validator()
        self.created.append(instance)
        return instance


class _FakeProducer:
    def __init__(
        self,
        generated: Mapping[str, Any],
        repairs: list[Mapping[str, Any]] | None = None,
        *,
        assumptions: tuple[str, ...] = (),
        evidence_by_round: list[tuple[EvidenceItem, ...]] | None = None,
        tool_calls: tuple[ToolCallRecord, ...] = (),
        charge_tools: bool = True,
        fail_generate: bool = False,
        fail_repair: int | None = None,
    ) -> None:
        self.generated = deepcopy(dict(generated))
        self.repairs = [deepcopy(dict(value)) for value in (repairs or [])]
        self.assumptions = assumptions
        self.evidence_by_round = evidence_by_round or []
        self.tool_calls = tool_calls
        self.charge_tools = charge_tools
        self.fail_generate = fail_generate
        self.fail_repair = fail_repair
        self.generate_calls = 0
        self.repair_calls = 0
        self.plans: list[Any] = []
        self.previous_entries: list[dict[str, Any]] = []

    def _sidecar_evidence(self, index: int) -> tuple[EvidenceItem, ...]:
        return self.evidence_by_round[index] if index < len(self.evidence_by_round) else ()

    def generate(
        self, task: RunTask, context: ProducerExecutionContext
    ) -> ProductionDraft:
        self.generate_calls += 1
        context.call_model("MODEL-fixture-0-plan", "plan", {"attempt": 0})
        if self.fail_generate:
            raise RuntimeError("generation failed")
        if self.charge_tools:
            for call in self.tool_calls:
                context.call_tool(call.tool_call_id, call.tool_name, {})
        context.call_model(
            "MODEL-fixture-0-semantic_judge", "semantic_judge", {"attempt": 0}
        )
        context.call_model(
            "MODEL-fixture-0-reflection", "reflection", {"attempt": 0}
        )
        return ProductionDraft(
            self.generated,
            evidence=self._sidecar_evidence(0),
            assumptions=self.assumptions,
        )

    def repair(
        self,
        task: RunTask,
        previous_entry: Mapping[str, Any],
        plan: Any,
        context: ProducerExecutionContext,
    ) -> ProductionDraft:
        self.repair_calls += 1
        self.plans.append(plan)
        self.previous_entries.append(deepcopy(dict(previous_entry)))
        context.call_model(
            f"MODEL-fixture-{context.attempt}-repair",
            "repair",
            {"attempt": context.attempt},
        )
        if self.fail_repair == self.repair_calls:
            raise RuntimeError("repair failed")
        context.call_model(
            f"MODEL-fixture-{context.attempt}-reflection",
            "reflection",
            {"attempt": context.attempt},
        )
        return ProductionDraft(
            self.repairs[self.repair_calls - 1],
            evidence=self._sidecar_evidence(self.repair_calls),
        )


class ClosedLoopOrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entry = _entry()
        self.task = RunTask(
            task_id="task:closed-loop-001",
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            inputs={"input_line": 7, "package": {"advisory": "item.json"}},
        )

    def _run(
        self,
        producer: _FakeProducer,
        reports: list[ValidationReport],
        *,
        initial_candidate: Mapping[str, Any] | ProductionOutcome | None = None,
        limits: Limits | None = None,
    ) -> tuple[Any, _SequenceValidatorFactory]:
        factory = _SequenceValidatorFactory(reports, self.task)
        context_factory = FixedProducerContextFactory(
            call.tool_name for call in producer.tool_calls
        )
        runner = ClosedLoopOrchestrator(
            producer, factory, context_factory, limits=limits or Limits()
        )
        return (
            runner.run(self.task, initial_candidate=initial_candidate),
            factory,
        )

    def test_initial_correct_finalizes_with_one_fresh_validation(self) -> None:
        producer = _FakeProducer(self.entry, assumptions=("not sent to T1",))
        result, factory = self._run(
            producer, [_report(self.entry, {"schema": "correct"})]
        )

        self.assertEqual(result.status, "finalized")
        self.assertEqual(result.state.stop_reason, STOP_VALIDATED_CORRECT)
        self.assertEqual(producer.generate_calls, 1)
        self.assertEqual(producer.repair_calls, 0)
        self.assertEqual(len(factory.created), 1)
        self.assertEqual(factory.seen_input_lines, [7])
        self.assertNotIn("assumptions", factory.seen_candidates[0])
        self.assertEqual(set(factory.seen_candidates[0]), set(self.entry))
        self.assertEqual(result.state.validation_count, 1)
        self.assertEqual(result.state.budget["usage"]["llm_calls"], 3)

    def test_one_repair_can_finalize_and_only_authorized_field_changes(self) -> None:
        repaired = deepcopy(self.entry)
        repaired["vuln_title"] = "Repaired title"
        producer = _FakeProducer(self.entry, [repaired])
        first = _report(self.entry, {"vuln_title": "incorrect"}, label="bad")
        second = _report(repaired, {"vuln_title": "correct"}, label="good")

        result, factory = self._run(producer, [first, second])

        self.assertEqual(result.status, "finalized")
        self.assertEqual(result.state.repair_iteration, 1)
        self.assertEqual(result.state.validation_count, 2)
        self.assertEqual(result.changed_fields, ("vuln_title",))
        self.assertEqual(producer.plans[0].repair_fields, ("vuln_title",))
        self.assertEqual(len(factory.created), 2)
        self.assertIsNot(factory.created[0], factory.created[1])
        self.assertEqual(result.entry["vuln_title"], "Repaired title")

    def test_two_repairs_are_allowed_but_never_a_third(self) -> None:
        first_candidate = deepcopy(self.entry)
        first_candidate["vuln_title"] = "repair-one"
        second_candidate = deepcopy(self.entry)
        second_candidate["vuln_title"] = "repair-two"
        producer = _FakeProducer(self.entry, [first_candidate, second_candidate])
        reports = [
            _report(self.entry, {"vuln_title": "incorrect"}, label="bad-0"),
            _report(first_candidate, {"vuln_title": "incorrect"}, label="bad-1"),
            _report(second_candidate, {"vuln_title": "incorrect"}, label="bad-2"),
        ]

        result, factory = self._run(producer, reports)

        self.assertEqual(result.status, "manual_review")
        self.assertEqual(result.state.stop_reason, STOP_MAX_REPAIR_ITERATIONS)
        self.assertEqual(producer.repair_calls, 2)
        self.assertEqual(len(factory.created), 3)
        self.assertEqual(result.state.validation_count, 3)

        wrong_operation_budget = result.state.to_dict()["budget"]
        repair_event = next(
            event
            for event in wrong_operation_budget["events"]
            if event["resource"] == "repair_iterations"
        )
        repair_event["operation"] = "repair:forged"
        with self.assertRaisesRegex(ValueError, "canonical repair operation"):
            replace(result.state, budget=wrong_operation_budget)

        combined_budget = {
            "limits": dict(result.state.budget["limits"]),
            "usage": dict(result.state.budget["usage"]),
            "events": [
                {
                    "sequence": 1,
                    "resource": "llm_calls",
                    "amount": 1,
                    "usage_after": {
                        "llm_calls": 1,
                        "tool_calls": 0,
                        "repair_iterations": 0,
                    },
                    "operation": result.state.budget["events"][0]["operation"],
                },
                {
                    "sequence": 2,
                    "resource": "repair_iterations",
                    "amount": 2,
                    "usage_after": {
                        "llm_calls": 1,
                        "tool_calls": 0,
                        "repair_iterations": 2,
                    },
                    "operation": "repair:1",
                },
                {
                    "sequence": 3,
                    "resource": "llm_calls",
                    "amount": 1,
                    "usage_after": {
                        "llm_calls": 2,
                        "tool_calls": 0,
                        "repair_iterations": 2,
                    },
                    "operation": result.state.budget["events"][2]["operation"],
                },
                {
                    "sequence": 4,
                    "resource": "llm_calls",
                    "amount": 1,
                    "usage_after": {
                        "llm_calls": 3,
                        "tool_calls": 0,
                        "repair_iterations": 2,
                    },
                    "operation": result.state.budget["events"][4]["operation"],
                },
            ],
        }
        with self.assertRaisesRegex(ValueError, "budget|repair round"):
            replace(result.state, budget=combined_budget)
        self.assertEqual(result.state.budget["usage"]["repair_iterations"], 2)
        self.assertEqual(len(result.repair_plans), 2)
        self.assertEqual(len(result.state.validation_history), 3)
        self.assertEqual(
            tuple(
                item.candidate_sha256
                for item in result.state.validation_history
            ),
            tuple(
                item.candidate_sha256
                for item in result.state.production_history
            ),
        )
        for summary in result.state.production_history[1:]:
            matching_plans = [
                plan
                for plan in result.repair_plans
                if canonical_sha256(plan) == summary.repair_plan_sha256
            ]
            self.assertEqual(len(matching_plans), 1)

    def test_uncertain_only_never_invokes_repair(self) -> None:
        producer = _FakeProducer(self.entry)
        uncertain = _report(self.entry, {"commit": "uncertain"})

        result, _ = self._run(producer, [uncertain])

        self.assertEqual(result.status, "manual_review")
        self.assertEqual(result.state.stop_reason, STOP_VALIDATION_UNCERTAIN)
        self.assertEqual(producer.repair_calls, 0)

    def test_no_progress_stops_before_revalidation(self) -> None:
        producer = _FakeProducer(self.entry, [self.entry])
        bad = _report(self.entry, {"vuln_title": "incorrect"})

        result, factory = self._run(producer, [bad])

        self.assertEqual(result.state.stop_reason, STOP_NO_PROGRESS)
        self.assertEqual(len(factory.created), 1)
        self.assertEqual(result.state.validation_count, 1)
        self.assertEqual(producer.repair_calls, 1)

    def test_same_structured_error_after_change_stops_repair_oscillation(self) -> None:
        changed = deepcopy(self.entry)
        changed["vuln_title"] = "different but still wrong"
        producer = _FakeProducer(self.entry, [changed])
        repeated = _report(self.entry, {"vuln_title": "incorrect"}, label="same")

        result, _ = self._run(producer, [repeated, repeated])

        self.assertEqual(result.state.stop_reason, STOP_REPEATED_ERROR)
        self.assertEqual(producer.repair_calls, 1)
        self.assertEqual(result.state.validation_count, 2)

    def test_non_adjacent_error_signature_cycle_is_detected(self) -> None:
        first_candidate = deepcopy(self.entry)
        first_candidate["vuln_title"] = "cycle-b"
        second_candidate = deepcopy(self.entry)
        second_candidate["vuln_title"] = "cycle-a-again"
        producer = _FakeProducer(
            self.entry, [first_candidate, second_candidate]
        )
        reports = [
            _report(
                self.entry,
                {"vuln_title": "incorrect"},
                label="A",
                suggested_fixes={"vuln_title": "cycle-target"},
            ),
            _report(
                first_candidate,
                {"vuln_title": "incorrect"},
                label="B",
                suggested_fixes={"vuln_title": "cycle-target"},
            ),
            _report(
                second_candidate,
                {"vuln_title": "incorrect"},
                label="A",
                suggested_fixes={"vuln_title": "cycle-target"},
            ),
        ]

        result, _ = self._run(producer, reports)

        self.assertEqual(result.state.stop_reason, STOP_REPEATED_ERROR)
        self.assertEqual(result.state.repair_iteration, 2)

    def test_unfunded_next_plan_does_not_replace_the_last_attempted_plan(self) -> None:
        changed = deepcopy(self.entry)
        changed["vuln_title"] = "still incorrect"
        producer = _FakeProducer(self.entry, [changed])
        reports = [
            _report(self.entry, {"vuln_title": "incorrect"}, label="first"),
            _report(changed, {"vuln_title": "incorrect"}, label="second"),
        ]

        result, _ = self._run(
            producer,
            reports,
            limits=Limits(max_repair_iterations=1),
        )

        self.assertEqual(result.state.stop_reason, STOP_BUDGET_EXHAUSTED)
        self.assertEqual(result.state.repair_iteration, 1)
        self.assertEqual(len(result.repair_plans), 1)
        self.assertEqual(result.state.active_repair_plan.repair_iteration, 1)

    def test_locked_field_change_is_rejected_without_validating_it(self) -> None:
        changed = deepcopy(self.entry)
        changed["commit"] = "1" * 40
        changed["vuln_title"] = "unauthorized collateral change"
        producer = _FakeProducer(self.entry, [changed])
        bad = _report(self.entry, {"commit": "incorrect"})

        result, factory = self._run(producer, [bad])

        self.assertEqual(result.state.stop_reason, STOP_LOCKED_FIELD_CHANGED)
        self.assertEqual(result.entry["vuln_title"], self.entry["vuln_title"])
        self.assertEqual(len(factory.created), 1)
        self.assertIn("vuln_title", result.error)

    def test_previously_correct_field_regression_routes_to_manual_review(self) -> None:
        changed = deepcopy(self.entry)
        changed["commit"] = "2" * 40
        producer = _FakeProducer(self.entry, [changed])
        first = _report(
            self.entry,
            {"commit": "incorrect", "critical_operation": "correct"},
            label="before",
        )
        second = _report(
            changed,
            {"commit": "correct", "critical_operation": "incorrect"},
            label="after",
        )

        result, _ = self._run(producer, [first, second])

        self.assertEqual(result.state.stop_reason, STOP_VALIDATION_REGRESSION)
        self.assertIn("critical_operation", result.error)

    def test_correct_field_becoming_uncertain_or_missing_is_a_regression(self) -> None:
        for label, second_fields in (
            ("uncertain", {"commit": "correct", "critical_operation": "uncertain"}),
            ("missing", {"commit": "correct"}),
        ):
            with self.subTest(label=label):
                changed = deepcopy(self.entry)
                changed["commit"] = "2" * 40
                producer = _FakeProducer(self.entry, [changed])
                first = _report(
                    self.entry,
                    {"commit": "incorrect", "critical_operation": "correct"},
                    label="before",
                )
                second = _report(changed, second_fields, label=f"after-{label}")

                result, _ = self._run(producer, [first, second])

                self.assertEqual(
                    result.state.stop_reason, STOP_VALIDATION_REGRESSION
                )
                self.assertIn("critical_operation", result.error)

    def test_budget_exhaustion_prevents_repair_call(self) -> None:
        producer = _FakeProducer(self.entry, [self.entry])
        bad = _report(self.entry, {"vuln_title": "incorrect"})

        result, _ = self._run(
            producer,
            [bad],
            initial_candidate=self.entry,
            limits=Limits(max_repair_iterations=0),
        )

        self.assertEqual(result.state.stop_reason, STOP_BUDGET_EXHAUSTED)
        self.assertEqual(producer.repair_calls, 0)
        self.assertEqual(result.state.budget["usage"]["repair_iterations"], 0)

    def test_failed_repair_remains_charged_and_isolated(self) -> None:
        producer = _FakeProducer(self.entry, [self.entry], fail_repair=1)
        bad = _report(self.entry, {"vuln_title": "incorrect"})

        result, _ = self._run(producer, [bad], initial_candidate=self.entry)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_PRODUCER_ERROR)
        self.assertEqual(result.state.repair_iteration, 1)
        self.assertEqual(result.state.budget["usage"]["repair_iterations"], 1)
        self.assertEqual(result.state.budget["usage"]["llm_calls"], 1)

    def test_producer_exception_permanently_seals_the_context_facade(self) -> None:
        producer = _FakeProducer(self.entry, fail_generate=True)
        validators = _SequenceValidatorFactory([], self.task)
        context_factory = FixedProducerContextFactory()
        result = ClosedLoopOrchestrator(
            producer,
            validators,
            context_factory,
        ).run(self.task)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_PRODUCER_ERROR)
        self.assertEqual(len(context_factory.created), 1)
        captured = context_factory.created[0].producer_context
        with self.assertRaises(ProducerContextFinalized):
            captured.call_model(
                "MODEL-after-failure",
                "semantic_judge",
                {"attempt": 0},
            )
        self.assertEqual(result.state.budget["usage"]["llm_calls"], 1)

    def test_validator_exception_is_a_structured_failed_outcome(self) -> None:
        class BrokenFactory:
            def __call__(self, task: RunTask) -> object:
                raise RuntimeError("validator unavailable")

        runner = ClosedLoopOrchestrator(
            _FakeProducer(self.entry),
            BrokenFactory(),
            FixedProducerContextFactory(),
        )
        result = runner.run(self.task)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_VALIDATOR_ERROR)
        self.assertIn("validator unavailable", result.error)

    def test_direct_invalid_candidate_is_rejected_before_t1(self) -> None:
        invalid = deepcopy(self.entry)
        invalid["extra"] = "must not enter the official row"
        producer = _FakeProducer(self.entry)
        factory = _SequenceValidatorFactory([], self.task)
        runner = ClosedLoopOrchestrator(
            producer, factory, FixedProducerContextFactory()
        )

        result = runner.run(self.task, initial_candidate=invalid)

        self.assertEqual(result.state.stop_reason, STOP_INVALID_CANDIDATE)
        self.assertEqual(result.state.validation_count, 0)
        self.assertEqual(producer.generate_calls, 0)

    def test_factory_errors_and_substituted_controllers_fail_per_task(self) -> None:
        class BrokenFactory:
            def __init__(self, kind: str) -> None:
                self.kind = kind

            def create(self, task: RunTask, **kwargs: Any) -> Any:
                if self.kind == "raises":
                    raise RuntimeError("context factory unavailable")
                if self.kind == "wrong-type":
                    return object()
                controller = FixedProducerContextFactory().create(
                    task, **kwargs
                )
                controller.policy_scope = "t2.repair-1"
                return controller

        for kind, error_fragment in (
            ("raises", "factory unavailable"),
            ("wrong-type", "ProducerAttemptController"),
            ("wrong-scope", "identity/scope"),
        ):
            with self.subTest(kind=kind):
                producer = _FakeProducer(self.entry)
                validators = _SequenceValidatorFactory([], self.task)
                result = ClosedLoopOrchestrator(
                    producer, validators, BrokenFactory(kind)
                ).run(self.task)

                self.assertEqual(result.status, "failed")
                self.assertEqual(result.state.stop_reason, STOP_PRODUCER_ERROR)
                self.assertIn(error_fragment, result.error)
                self.assertEqual(producer.generate_calls, 0)
                self.assertEqual(validators.created, [])

    def test_pseudo_field_incorrect_is_not_broadened_into_repairs(self) -> None:
        producer = _FakeProducer(self.entry)
        pseudo = _report(self.entry, {"schema": "incorrect"})

        result, _ = self._run(producer, [pseudo])

        self.assertEqual(result.status, "manual_review")
        self.assertEqual(result.state.stop_reason, STOP_NO_REPAIRABLE_FIELDS)
        self.assertEqual(producer.repair_calls, 0)

    def test_unaccounted_tool_call_is_rejected(self) -> None:
        producer = _FakeProducer(self.entry)
        factory = _SequenceValidatorFactory([], self.task)

        class RogueFactory(FixedProducerContextFactory):
            def create(self, task: RunTask, **kwargs: Any) -> Any:
                budget = kwargs["budget"]
                budget.charge_tool_call(operation="rogue:outside-context")
                return super().create(task, **kwargs)

        result = ClosedLoopOrchestrator(
            producer, factory, RogueFactory()
        ).run(self.task)

        self.assertEqual(result.state.stop_reason, STOP_UNACCOUNTED_TOOL_CALL)
        self.assertEqual(result.state.validation_count, 0)

    def test_conflicting_evidence_ids_across_rounds_stop_the_run(self) -> None:
        changed = deepcopy(self.entry)
        changed["vuln_title"] = "changed"
        first_evidence = EvidenceItem(
            evidence_id="EV-CONFLICT",
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            source_type="advisory",
            snippet="first payload",
        )
        second_evidence = EvidenceItem(
            evidence_id="EV-CONFLICT",
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            source_type="advisory",
            snippet="different payload",
        )
        producer = _FakeProducer(
            self.entry,
            [changed],
            evidence_by_round=[(first_evidence,), (second_evidence,)],
        )
        bad = _report(self.entry, {"vuln_title": "incorrect"})

        result, _ = self._run(producer, [bad])

        self.assertEqual(result.state.stop_reason, STOP_SIDECAR_CONFLICT)
        self.assertIn("EV-CONFLICT", result.error)

    def test_run_state_is_schema_valid_sanitized_and_replayable(self) -> None:
        producer = _FakeProducer(
            self.entry, assumptions=("producer-only assumption",)
        )
        result, _ = self._run(
            producer, [_report(self.entry, {"schema": "correct"})]
        )
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
        errors = list(
            validator_class(run_schema, registry=registry).iter_errors(serialized)
        )

        self.assertEqual(errors, [])
        encoded = json.dumps(serialized, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("producer-only assumption", encoded)
        self.assertNotIn("item.json", encoded)
        self.assertNotIn("inputs", serialized["task"])
        self.assertNotIn("input_line", serialized["task"])
        self.assertEqual(
            serialized["candidate_sha256"],
            canonical_sha256(serialized["candidate"]),
        )
        self.assertEqual(
            serialized["production_history"][-1]["candidate_sha256"],
            serialized["candidate_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
