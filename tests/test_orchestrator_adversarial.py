from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from typing import Any, Mapping
import unittest

from vulngym_agent.adapters import ENTRY_FIELDS
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
from vulngym_agent.orchestrator.producer_context import ProducerExecutionContext
from vulngym_agent.orchestrator.repair_plan import RepairPlan
from vulngym_agent.orchestrator.state_machine import (
    ClosedLoopOutcome,
    ClosedLoopOrchestrator,
    ProductionSummary,
    STOP_BUDGET_EXHAUSTED,
    STOP_PRODUCER_ERROR,
    STOP_SIDECAR_CONFLICT,
    STOP_UNACCOUNTED_TOOL_CALL,
    STOP_VALIDATED_CORRECT,
    STOP_VALIDATOR_ERROR,
)
from tests.producer_context_support import FixedProducerContextFactory


ROOT = Path(__file__).resolve().parents[1]
_UNSET = object()


def _first_entry() -> dict[str, Any]:
    entry = json.loads(
        (ROOT / "data" / "entries.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    entry["verify"] = 0
    return entry


def _report(
    candidate: Mapping[str, Any],
    statuses: Mapping[str, str],
    *,
    label: str,
    verdict: str | None = None,
    report_id: object = _UNSET,
    entry_id: object = _UNSET,
    suggested_fixes: Mapping[str, Any] | None = None,
) -> ValidationReport:
    fixes = suggested_fixes or {}
    fields: dict[str, FieldValidation] = {}
    for field_name, status in statuses.items():
        suggested_fix = fixes.get(field_name)
        if (
            field_name not in fixes
            and status == "incorrect"
            and field_name in candidate
        ):
            suggested_fix = candidate[field_name]
        fields[field_name] = FieldValidation(
            status=status,
            confidence=0.5 if status == "uncertain" else 1.0,
            evidence=f"{label}:{field_name}:{status}",
            suggested_fix=suggested_fix,
        )

    if verdict is None:
        verdict = (
            "incorrect"
            if "incorrect" in statuses.values()
            else "uncertain"
            if "uncertain" in statuses.values()
            else "correct"
        )
    resolved_report_id = (
        candidate["report_id"] if report_id is _UNSET else report_id
    )
    resolved_entry_id = candidate["entry_id"] if entry_id is _UNSET else entry_id
    return ValidationReport(
        report_id=resolved_report_id,  # type: ignore[arg-type]
        entry_id=resolved_entry_id,  # type: ignore[arg-type]
        input_line=11,
        verdict=verdict,
        fields=fields,
        summary=f"Adversarial validation: {label}.",
    )


def _evidence(entry: Mapping[str, Any], *, snippet: str) -> EvidenceItem:
    return EvidenceItem(
        evidence_id="EV-SHARED",
        report_id=entry["report_id"],
        entry_id=entry["entry_id"],
        source_type="advisory",
        snippet=snippet,
    )


def _tool_call(
    *,
    tool_call_id: str = "TOOL-shared",
    result_digest: str = "2" * 64,
    tool_name: str = "sentinel.tool",
    attempt: int = 0,
    sequence: int = 2,
) -> ToolCallRecord:
    task_id = "task:adversarial-001"
    scope = "t2.initial" if attempt == 0 else f"t2.repair-{attempt}"
    return ToolCallRecord(
        task_id=task_id,
        attempt=attempt,
        policy_scope=scope,
        tool_call_id=tool_call_id,
        tool_name=tool_name,
        arguments_sha256="1" * 64,
        operation=(
            f"tool:{task_id}:{attempt}:{scope}:{tool_call_id}:{tool_name}"
        ),
        budget_event_sequence=sequence,
        status="success",
        result_sha256=result_digest,
    )


def _model_call(index: int, *, sequence: int) -> ModelCallRecord:
    task_id = "task:adversarial-001"
    scope = "t2.initial" if index == 0 else f"t2.repair-{index}"
    stage = "plan" if index == 0 else "repair"
    call_id = f"MODEL-adversarial-{index}"
    request_sha256 = canonical_sha256({"round": index, "kind": "request"})
    return ModelCallRecord(
        task_id=task_id,
        attempt=index,
        policy_scope=scope,
        model_call_id=call_id,
        stage=stage,
        backend_id="test.adversarial",
        model_id="test-model",
        request_sha256=request_sha256,
        operation=(
            f"model:{task_id}:{index}:{scope}:{stage}:{call_id}:"
            f"test.adversarial:test-model:{request_sha256}"
        ),
        budget_event_sequence=sequence,
        status="success",
        response_sha256=canonical_sha256({"round": index, "kind": "response"}),
    )


class _ValidatorFactory:
    """Factory spy whose products expose exactly the validator call surface."""

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.factory_tasks: list[RunTask] = []
        self.instances: list[object] = []
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def __call__(self, task: RunTask) -> object:
        index = len(self.instances)
        if index >= len(self.responses):
            raise AssertionError("unexpected validator round")
        response = self.responses[index]
        owner = self

        class OneRoundValidator:
            def validate(self, *args: Any, **kwargs: Any) -> Any:
                owner.calls.append((deepcopy(args), deepcopy(kwargs)))
                if isinstance(response, BaseException):
                    raise response
                if isinstance(response, ValidationReport):
                    return T1ValidationOutcome(report=response, evidence=())
                return response

        instance = OneRoundValidator()
        self.factory_tasks.append(task)
        self.instances.append(instance)
        return instance


class _ScriptedProducer:
    """Deterministic producer with independently configurable audit sidecars."""

    def __init__(
        self,
        candidates: list[Mapping[str, Any]],
        *,
        evidence_rounds: list[tuple[EvidenceItem, ...]] | None = None,
        tool_rounds: list[tuple[ToolCallRecord, ...]] | None = None,
        assumptions_rounds: list[tuple[str, ...]] | None = None,
        tool_charge_counts: list[int] | None = None,
        fail_repair: str | None = None,
    ) -> None:
        self.candidates = [deepcopy(dict(candidate)) for candidate in candidates]
        self.evidence_rounds = evidence_rounds or []
        self.tool_rounds = tool_rounds or []
        self.assumptions_rounds = assumptions_rounds or []
        self.tool_charge_counts = tool_charge_counts
        self.fail_repair = fail_repair
        self.generate_calls = 0
        self.repair_calls = 0
        self.plans: list[RepairPlan] = []
        self.previous_entries: list[dict[str, Any]] = []

    def _round_values(
        self, values: list[tuple[Any, ...]], index: int
    ) -> tuple[Any, ...]:
        return values[index] if index < len(values) else ()

    def _charge_tools(
        self, index: int, context: ProducerExecutionContext
    ) -> None:
        returned = self._round_values(self.tool_rounds, index)
        returned_count = len(returned)
        charge_count = (
            self.tool_charge_counts[index]
            if self.tool_charge_counts is not None
            else returned_count
        )
        for position in range(charge_count):
            record = returned[position] if position < returned_count else None
            context.call_tool(
                (
                    record.tool_call_id
                    if record is not None
                    else f"TOOL-extra-{index}-{position}"
                ),
                record.tool_name if record is not None else "sentinel.tool",
                {"round": index, "position": position},
            )

    def _outcome(self, index: int) -> ProductionDraft:
        return ProductionDraft(
            candidate=self.candidates[index],
            evidence=self._round_values(self.evidence_rounds, index),
            assumptions=self._round_values(self.assumptions_rounds, index),
        )

    def generate(
        self, task: RunTask, context: ProducerExecutionContext
    ) -> ProductionDraft:
        self.generate_calls += 1
        context.call_model("MODEL-adversarial-0-plan", "plan", {"round": 0})
        self._charge_tools(0, context)
        context.call_model(
            "MODEL-adversarial-0-semantic", "semantic_judge", {"round": 0}
        )
        context.call_model(
            "MODEL-adversarial-0-reflection", "reflection", {"round": 0}
        )
        return self._outcome(0)

    def repair(
        self,
        task: RunTask,
        previous_entry: Mapping[str, Any],
        plan: RepairPlan,
        context: ProducerExecutionContext,
    ) -> ProductionDraft:
        self.repair_calls += 1
        self.previous_entries.append(deepcopy(dict(previous_entry)))
        self.plans.append(plan)
        if self.fail_repair == "before_llm":
            raise RuntimeError("repair failed before producer LLM call")
        context.call_model(
            f"MODEL-adversarial-{context.attempt}-repair",
            "repair",
            {"round": context.attempt},
        )
        if self.fail_repair == "after_llm":
            raise RuntimeError("repair failed after producer LLM call")
        index = self.repair_calls
        self._charge_tools(index, context)
        context.call_model(
            f"MODEL-adversarial-{context.attempt}-reflection",
            "reflection",
            {"round": context.attempt},
        )
        return self._outcome(index)


class ClosedLoopOrchestratorAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entry = _first_entry()
        self.task = RunTask(
            task_id="task:adversarial-001",
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            inputs={"input_line": 11, "public_fixture": "first-entry"},
        )

    def _run(
        self,
        producer: _ScriptedProducer,
        responses: list[Any],
        *,
        initial_candidate: Mapping[str, Any] | ProductionOutcome | None = None,
        limits: Limits | None = None,
    ) -> tuple[Any, _ValidatorFactory]:
        factory = _ValidatorFactory(responses)
        tool_names = {
            record.tool_name
            for round_records in producer.tool_rounds
            for record in round_records
        }
        tool_names.add("sentinel.tool")
        runner = ClosedLoopOrchestrator(
            producer,
            factory,
            FixedProducerContextFactory(tool_names),
            limits=limits or Limits(),
        )
        result = runner.run(self.task, initial_candidate=initial_candidate)
        return result, factory

    def test_mixed_incorrect_and_uncertain_repairs_only_incorrect_field(self) -> None:
        repaired = deepcopy(self.entry)
        repaired["vuln_title"] = "A narrowly repaired title"
        producer = _ScriptedProducer([self.entry, repaired])
        mixed = _report(
            self.entry,
            {"vuln_title": "incorrect", "commit": "uncertain"},
            label="mixed",
        )
        correct = _report(repaired, {"schema": "correct"}, label="correct")

        result, _ = self._run(producer, [mixed, correct])

        self.assertEqual(result.status, "finalized")
        self.assertEqual(result.state.stop_reason, STOP_VALIDATED_CORRECT)
        self.assertEqual(producer.plans[0].repair_fields, ("vuln_title",))
        self.assertEqual(producer.plans[0].dependent_fields, ())
        self.assertIn("commit", producer.plans[0].locked_fields)
        self.assertNotIn("commit", producer.plans[0].instructions)
        self.assertEqual(result.entry["commit"], self.entry["commit"])
        self.assertEqual(result.changed_fields, ("vuln_title",))

    def test_wrong_candidate_report_id_remains_narrowly_repairable(self) -> None:
        wrong = deepcopy(self.entry)
        wrong_id = "GHSA-1111-2222-3333"
        wrong["report_id"] = wrong_id
        wrong["source_link"] = f"https://github.com/advisories/{wrong_id}"
        wrong["vuln_ids"] = [
            identifier
            for identifier in wrong["vuln_ids"]
            if not identifier.startswith("GHSA-")
        ] + [wrong_id]
        producer = _ScriptedProducer([wrong, self.entry])
        bad_id = _report(
            wrong,
            {"report_id": "incorrect"},
            label="wrong-report-id",
            report_id=wrong_id,
            suggested_fixes={"report_id": self.entry["report_id"]},
        )
        correct = _report(self.entry, {"schema": "correct"}, label="correct")

        result, _ = self._run(producer, [bad_id, correct])

        self.assertEqual(result.status, "finalized")
        plan = producer.plans[0]
        self.assertEqual(plan.report_id, self.task.report_id)
        self.assertEqual(plan.repair_fields, ("report_id",))
        self.assertEqual(set(plan.dependent_fields), {"source_link", "vuln_ids"})
        self.assertEqual(
            set(result.changed_fields), {"report_id", "source_link", "vuln_ids"}
        )
        self.assertEqual(result.entry["report_id"], self.task.report_id)

    def test_identity_gate_preserves_the_identity_t1_actually_observed(self) -> None:
        wrong = deepcopy(self.entry)
        wrong_id = "GHSA-1111-2222-3333"
        wrong["report_id"] = wrong_id
        wrong["source_link"] = f"https://github.com/advisories/{wrong_id}"
        wrong["vuln_ids"] = [wrong_id]
        producer = _ScriptedProducer([wrong])
        observed_evidence = _evidence(wrong, snippet="observed wrong identity")
        observed = ValidationReport(
            report_id=wrong_id,
            entry_id=wrong["entry_id"],
            input_line=11,
            verdict="correct",
            fields={
                "report_id": FieldValidation(
                    status="correct",
                    confidence=1.0,
                    evidence="T1 observed the candidate identifier.",
                    evidence_refs=(observed_evidence.evidence_id,),
                )
            },
            summary="Observed candidate identity.",
        )
        validation = T1ValidationOutcome(
            report=observed,
            evidence=(observed_evidence,),
        )

        result, _ = self._run(
            producer,
            [validation],
            limits=Limits(max_repair_iterations=0),
        )

        self.assertEqual(result.status, "manual_review")
        self.assertEqual(result.entry["report_id"], wrong_id)
        self.assertEqual(result.report.report_id, wrong_id)
        self.assertEqual(result.state.last_validation.report_id, wrong_id)
        identity_field = result.report.fields["report_id"]
        self.assertEqual(identity_field.status, "incorrect")
        self.assertEqual(identity_field.suggested_fix, self.task.report_id)
        self.assertEqual(
            identity_field.evidence_refs, (observed_evidence.evidence_id,)
        )

    def test_all_declared_dependents_may_change_with_the_repair_field(self) -> None:
        repaired = deepcopy(self.entry)
        repaired["commit"] = "0" * 40
        repaired["entry_point"]["desc"] += " [revalidated at repaired commit]"
        repaired["critical_operation"]["desc"] += " [revalidated at repaired commit]"
        repaired["trace"][0]["desc"] += " [revalidated at repaired commit]"
        producer = _ScriptedProducer([self.entry, repaired])
        bad_commit = _report(
            self.entry,
            {"commit": "incorrect"},
            label="bad-commit",
            suggested_fixes={"commit": repaired["commit"]},
        )
        correct = _report(repaired, {"schema": "correct"}, label="correct")

        result, _ = self._run(producer, [bad_commit, correct])

        self.assertEqual(result.status, "finalized")
        plan = producer.plans[0]
        self.assertEqual(plan.repair_fields, ("commit",))
        self.assertEqual(
            set(plan.dependent_fields),
            {"entry_point", "critical_operation", "trace"},
        )
        self.assertTrue(
            {"commit", "entry_point", "critical_operation", "trace"}
            <= set(result.changed_fields)
        )

    def test_failed_repair_keeps_attempt_state_and_budget_counts_aligned(self) -> None:
        bad = _report(
            self.entry,
            {"vuln_title": "incorrect"},
            label="repair-will-fail",
        )
        for failure_point, expected_llm_calls in (
            ("before_llm", 0),
            ("after_llm", 1),
        ):
            with self.subTest(failure_point=failure_point):
                producer = _ScriptedProducer(
                    [self.entry], fail_repair=failure_point
                )
                result, _ = self._run(
                    producer,
                    [bad],
                    initial_candidate=self.entry,
                )

                usage = result.state.budget["usage"]
                self.assertEqual(result.status, "failed")
                self.assertEqual(result.state.stop_reason, STOP_PRODUCER_ERROR)
                self.assertEqual(producer.repair_calls, 1)
                self.assertEqual(result.state.repair_iteration, 1)
                self.assertEqual(usage["repair_iterations"], 1)
                self.assertEqual(usage["llm_calls"], expected_llm_calls)
                self.assertEqual(result.state.validation_count, 1)
                self.assertEqual(len(result.state.production_history), 1)
                self.assertEqual(
                    result.state.candidate_sha256,
                    result.state.production_history[0].candidate_sha256,
                )

    def test_synchronized_failure_reason_forgery_is_rejected(self) -> None:
        bad = _report(
            self.entry,
            {"vuln_title": "incorrect"},
            label="failure-forgery",
        )
        producer = _ScriptedProducer(
            [self.entry], fail_repair="after_llm"
        )
        result, _ = self._run(producer, [bad])

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_PRODUCER_ERROR)
        termination = result.state.termination
        self.assertIsNotNone(termination)

        forged_validator = replace(
            termination,
            reason=STOP_VALIDATOR_ERROR,
            phase="validator",
        )
        with self.assertRaisesRegex(ValueError, "retained run topology"):
            forged_state = replace(
                result.state,
                stop_reason=STOP_VALIDATOR_ERROR,
                termination=forged_validator,
            )
            replace(result, state=forged_state)

        budget = result.state.budget
        remaining = (
            budget["limits"]["max_llm_calls"]
            - budget["usage"]["llm_calls"]
        )
        forged_budget = replace(
            termination,
            reason=STOP_BUDGET_EXHAUSTED,
            phase="budget",
            budget_resource="llm_calls",
            budget_requested=remaining + 1,
            budget_remaining=remaining,
        )
        with self.assertRaisesRegex(ValueError, "budget|topology"):
            forged_state = replace(
                result.state,
                stop_reason=STOP_BUDGET_EXHAUSTED,
                termination=forged_budget,
            )
            replace(result, state=forged_state)

    def test_run_state_rejects_verify_one_with_synchronized_digests(self) -> None:
        correct = _report(
            self.entry, {"schema": "correct"}, label="verify-forgery"
        )
        result, _ = self._run(_ScriptedProducer([self.entry]), [correct])
        candidate = result.state.to_dict()["candidate"]
        candidate["verify"] = 1
        forged_digest = canonical_sha256(candidate)
        forged_history = (
            replace(
                result.state.production_history[0],
                candidate_sha256=forged_digest,
            ),
        )
        forged_attempts = (
            replace(
                result.state.production_attempts[0],
                candidate_sha256=forged_digest,
            ),
        )

        with self.assertRaisesRegex(ValueError, "candidate_sha256|verify"):
            replace(
                result.state,
                candidate=candidate,
                candidate_sha256=forged_digest,
                production_history=forged_history,
                production_attempts=forged_attempts,
            )

    def test_generation_budget_exhaustion_stops_before_candidate_or_t1(self) -> None:
        producer = _ScriptedProducer([self.entry])
        result, factory = self._run(
            producer,
            [],
            limits=Limits(max_llm_calls=0),
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_BUDGET_EXHAUSTED)
        self.assertEqual(producer.generate_calls, 1)
        self.assertEqual(result.state.budget["usage"]["llm_calls"], 0)
        self.assertEqual(result.state.validation_count, 0)
        self.assertIsNone(result.state.candidate)
        self.assertIsNone(result.state.candidate_sha256)
        self.assertEqual(result.state.production_history, ())
        self.assertEqual(factory.instances, [])

    def test_validator_wrong_return_type_is_a_structured_failure(self) -> None:
        producer = _ScriptedProducer([self.entry])
        result, factory = self._run(producer, [{"not": "an outcome"}])

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_VALIDATOR_ERROR)
        self.assertIn("T1ValidationOutcome", result.error)
        self.assertEqual(result.state.validation_count, 0)
        self.assertEqual(len(factory.instances), 1)

    def test_validator_inconsistent_verdict_is_a_structured_failure(self) -> None:
        inconsistent = _report(
            self.entry,
            {"vuln_title": "incorrect"},
            label="inconsistent",
            verdict="correct",
        )
        producer = _ScriptedProducer([self.entry])

        result, _ = self._run(producer, [inconsistent])

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_VALIDATOR_ERROR)
        self.assertIn("verdict disagrees", result.error)
        self.assertEqual(result.state.validation_count, 0)

    def test_validator_report_must_bind_to_the_task_input_line(self) -> None:
        wrong_line = replace(
            _report(self.entry, {"schema": "correct"}, label="wrong-line"),
            input_line=999,
        )
        producer = _ScriptedProducer([self.entry])

        result, _ = self._run(producer, [wrong_line])

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_VALIDATOR_ERROR)
        self.assertIn("input_line", result.error)

    def test_identical_sidecar_ids_and_payloads_are_replay_safe(self) -> None:
        repaired = deepcopy(self.entry)
        repaired["vuln_title"] = "Repaired with replayed sidecars"
        shared_evidence = _evidence(self.entry, snippet="identical payload")
        first_tool = _tool_call(tool_call_id="TOOL-first")
        second_tool = _tool_call(
            tool_call_id="TOOL-second", attempt=1, sequence=5
        )
        producer = _ScriptedProducer(
            [self.entry, repaired],
            evidence_rounds=[(shared_evidence,), (shared_evidence,)],
            tool_rounds=[(first_tool,), (second_tool,)],
        )
        bad = _report(
            self.entry, {"vuln_title": "incorrect"}, label="bad-title"
        )
        correct = _report(repaired, {"schema": "correct"}, label="correct")

        result, _ = self._run(producer, [bad, correct])

        self.assertEqual(result.status, "finalized")
        self.assertEqual(result.state.stop_reason, STOP_VALIDATED_CORRECT)
        self.assertEqual(len(result.production_outcomes), 2)
        self.assertEqual(result.state.budget["usage"]["tool_calls"], 2)

        replayed_second = ProductionOutcome(
            candidate=repaired,
            evidence=(shared_evidence,),
            tool_calls=(first_tool,),
            model_calls=result.production_outcomes[1].model_calls,
        )
        replayed_attempts = (
            result.state.production_attempts[0],
            replace(
                result.state.production_attempts[1],
                outcome_sha256=canonical_sha256(replayed_second),
            ),
        )
        replayed_state = replace(
            result.state,
            production_attempts=replayed_attempts,
        )
        with self.assertRaisesRegex(ValueError, "globally unique"):
            replace(
                result,
                state=replayed_state,
                production_outcomes=(
                    result.production_outcomes[0],
                    replayed_second,
                ),
            )

    def test_same_sidecar_id_with_different_payload_is_rejected(self) -> None:
        repaired = deepcopy(self.entry)
        repaired["vuln_title"] = "Repair that must not be accepted"
        bad = _report(
            self.entry, {"vuln_title": "incorrect"}, label="bad-title"
        )
        cases = (
            (
                "evidence",
                [
                    (_evidence(self.entry, snippet="first"),),
                    (_evidence(self.entry, snippet="different"),),
                ],
                [],
            ),
            (
                "tool",
                [],
                [
                    (_tool_call(result_digest="2" * 64),),
                    (
                        _tool_call(
                            result_digest="3" * 64,
                            attempt=1,
                            sequence=5,
                        ),
                    ),
                ],
            ),
        )
        for kind, evidence_rounds, tool_rounds in cases:
            with self.subTest(kind=kind):
                producer = _ScriptedProducer(
                    [self.entry, repaired],
                    evidence_rounds=evidence_rounds,
                    tool_rounds=tool_rounds,
                )
                result, _ = self._run(producer, [bad])

                self.assertEqual(result.status, "failed")
                self.assertEqual(result.state.stop_reason, STOP_SIDECAR_CONFLICT)
                expected_error = (
                    "conflicting payloads"
                    if kind == "evidence"
                    else "reused across attempts"
                )
                self.assertIn(expected_error, result.error)
                self.assertEqual(result.state.validation_count, 1)
                self.assertEqual(len(result.production_outcomes), 1)

    def test_t1_evidence_cannot_rebind_a_producer_evidence_id(self) -> None:
        producer_evidence = _evidence(self.entry, snippet="producer payload")
        t1_evidence = _evidence(self.entry, snippet="different T1 payload")
        producer = _ScriptedProducer(
            [self.entry], evidence_rounds=[(producer_evidence,)]
        )
        report = ValidationReport(
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            input_line=11,
            verdict="correct",
            fields={
                "schema": FieldValidation(
                    status="correct",
                    confidence=1.0,
                    evidence="T1 used a colliding evidence identifier.",
                    evidence_refs=(t1_evidence.evidence_id,),
                )
            },
            summary="Adversarial T1 evidence collision.",
        )
        validation = T1ValidationOutcome(
            report=report,
            evidence=(t1_evidence,),
        )

        result, _ = self._run(producer, [validation])

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_SIDECAR_CONFLICT)
        self.assertIn("conflicts between T1", result.error)

    def test_t1_evidence_must_identify_the_candidate_it_supports(self) -> None:
        wrong_evidence = EvidenceItem(
            evidence_id="EV-WRONG-BIND",
            report_id="GHSA-1111-2222-3333",
            entry_id="entry-99999",
            source_type="advisory",
            snippet="Evidence from a different task.",
        )
        report = ValidationReport(
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            input_line=11,
            verdict="correct",
            fields={
                "schema": FieldValidation(
                    status="correct",
                    confidence=1.0,
                    evidence="Cross-task evidence must be rejected.",
                    evidence_refs=(wrong_evidence.evidence_id,),
                )
            },
            summary="Adversarial cross-task binding.",
        )
        validation = T1ValidationOutcome(
            report=report,
            evidence=(wrong_evidence,),
        )
        producer = _ScriptedProducer([self.entry])

        result, _ = self._run(producer, [validation])

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_VALIDATOR_ERROR)
        self.assertIn("does not identify its candidate", result.error)

    def test_t1_evidence_cannot_reference_an_unrecorded_tool_call(self) -> None:
        evidence = EvidenceItem(
            evidence_id="EV-T1-DANGLING-TOOL",
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            source_type="source",
            snippet="No T1 tool ledger contains this call.",
            tool_call_id="TOOL-NOT-RECORDED",
        )
        report = ValidationReport(
            report_id=self.entry["report_id"],
            entry_id=self.entry["entry_id"],
            input_line=11,
            verdict="correct",
            fields={
                "schema": FieldValidation(
                    status="correct",
                    confidence=1.0,
                    evidence="Dangling T1 tool reference must fail.",
                    evidence_refs=(evidence.evidence_id,),
                )
            },
            summary="Adversarial T1 tool binding.",
        )
        producer = _ScriptedProducer([self.entry])
        validation = T1ValidationOutcome(report=report, evidence=(evidence,))

        result, _ = self._run(producer, [validation])

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_VALIDATOR_ERROR)
        self.assertIn("unrecorded tool call", result.error)

    def test_producer_evidence_must_bind_to_candidate_and_local_tool_call(self) -> None:
        cases = (
            EvidenceItem(
                evidence_id="EV-WRONG-REPORT",
                report_id="GHSA-1111-2222-3333",
                entry_id=self.entry["entry_id"],
                source_type="source",
                snippet="Wrong report binding.",
            ),
            EvidenceItem(
                evidence_id="EV-WRONG-ENTRY",
                report_id=self.entry["report_id"],
                entry_id="entry-99999",
                source_type="source",
                snippet="Wrong entry binding.",
            ),
            EvidenceItem(
                evidence_id="EV-DANGLING-TOOL",
                report_id=self.entry["report_id"],
                entry_id=self.entry["entry_id"],
                source_type="source",
                snippet="Dangling tool binding.",
                tool_call_id="TOOL-missing",
            ),
        )
        for evidence in cases:
            with self.subTest(evidence_id=evidence.evidence_id):
                producer = _ScriptedProducer(
                    [self.entry], evidence_rounds=[(evidence,)]
                )
                result, _ = self._run(producer, [])

                self.assertEqual(result.status, "failed")
                self.assertEqual(result.state.stop_reason, STOP_PRODUCER_ERROR)
                self.assertEqual(result.state.validation_count, 0)

    def test_terminal_snapshots_do_not_alias_mutable_report_or_budget_data(self) -> None:
        producer = _ScriptedProducer([self.entry])
        report = _report(self.entry, {"schema": "correct"}, label="correct")
        mutable_evidence: list[EvidenceItem] = []
        validation = T1ValidationOutcome(
            report=report,
            evidence=mutable_evidence,  # type: ignore[arg-type]
        )

        result, _ = self._run(producer, [validation])
        mutable_evidence.append(
            _evidence(self.entry, snippet="late external mutation")
        )

        with self.assertRaises(TypeError):
            result.report.fields["schema"] = FieldValidation(
                status="incorrect",
                confidence=1.0,
                evidence="mutation must fail",
            )
        with self.assertRaises(TypeError):
            result.state.budget["usage"]["llm_calls"] = 999
        self.assertEqual(result.report.to_dict()["verdict"], "correct")
        self.assertEqual(result.state.to_dict()["budget"]["usage"]["llm_calls"], 3)
        self.assertEqual(result.validation_outcomes[0].evidence, ())

    def test_tool_call_records_must_exactly_close_the_budget_delta(self) -> None:
        tool = _tool_call()
        correct = _report(self.entry, {"schema": "correct"}, label="correct")
        cases = (
            ("exact", 1, "finalized", STOP_VALIDATED_CORRECT),
            ("zero-context-calls", 0, "finalized", STOP_VALIDATED_CORRECT),
            ("two-context-calls", 2, "finalized", STOP_VALIDATED_CORRECT),
        )
        for name, charged, expected_status, expected_reason in cases:
            with self.subTest(name=name):
                producer = _ScriptedProducer(
                    [self.entry],
                    tool_rounds=[(tool,)],
                    tool_charge_counts=[charged],
                )
                result, _ = self._run(producer, [correct])

                self.assertEqual(result.status, expected_status)
                self.assertEqual(result.state.stop_reason, expected_reason)
                self.assertEqual(
                    result.state.budget["usage"]["tool_calls"], charged
                )

    def test_producer_cannot_charge_the_budget_capability_directly(self) -> None:
        tool = _tool_call(tool_call_id="TOOL-forged-ledger")
        correct = _report(self.entry, {"schema": "correct"}, label="correct")

        class ForgedProducer(_ScriptedProducer):
            def _charge_tools(self, index: int, budget: Budget) -> None:
                budget.charge_tool_call(operation="tool:arbitrary-forged-charge")

        producer = ForgedProducer(
            [self.entry],
            tool_rounds=[(tool,)],
        )
        result, factory = self._run(producer, [correct])

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, STOP_PRODUCER_ERROR)
        self.assertEqual(result.state.budget["usage"]["tool_calls"], 0)
        self.assertIn("charge_tool_call", result.error)
        self.assertEqual(factory.instances, [])

    def test_provided_outcome_cannot_import_unaccounted_tool_calls(self) -> None:
        tool = _tool_call(tool_call_id="TOOL-imported")
        provided = ProductionOutcome(candidate=self.entry, tool_calls=(tool,))
        producer = _ScriptedProducer([self.entry])

        result, factory = self._run(
            producer,
            [],
            initial_candidate=provided,
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.state.stop_reason, "invalid_candidate")
        self.assertIn("external budget ledger", result.error)
        self.assertEqual(result.state.budget["usage"]["tool_calls"], 0)
        self.assertEqual(factory.instances, [])

    def test_a_run_cannot_inherit_charges_from_a_shared_budget(self) -> None:
        budget = Budget()
        budget.charge_tool_call(operation="prior-task.tool")
        producer = _ScriptedProducer([self.entry])
        factory = _ValidatorFactory([])
        runner = ClosedLoopOrchestrator(
            producer, factory, FixedProducerContextFactory()
        )

        with self.assertRaisesRegex(ValueError, "budget must be fresh"):
            runner.run(
                self.task,
                initial_candidate=self.entry,
                budget=budget,
            )

        self.assertEqual(factory.instances, [])

    def test_run_state_status_and_candidate_history_digests_form_a_chain(self) -> None:
        repaired = deepcopy(self.entry)
        repaired["vuln_title"] = "Digest-linked repair"
        producer = _ScriptedProducer([self.entry, repaired])
        bad = _report(
            self.entry, {"vuln_title": "incorrect"}, label="digest-bad"
        )
        correct = _report(repaired, {"schema": "correct"}, label="digest-good")

        result, _ = self._run(producer, [bad, correct])

        state = result.state
        history = state.production_history
        self.assertEqual(result.status, state.status)
        self.assertEqual(state.status, "finalized")
        self.assertEqual(state.stop_reason, STOP_VALIDATED_CORRECT)
        self.assertEqual(state.repair_iteration, 1)
        self.assertEqual(state.validation_count, 2)
        self.assertEqual(len(history), 2)
        self.assertEqual(state.candidate_sha256, canonical_sha256(state.candidate))
        self.assertEqual(state.candidate_sha256, history[-1].candidate_sha256)
        self.assertEqual(
            history[1].parent_candidate_sha256, history[0].candidate_sha256
        )
        self.assertEqual(
            history[1].repair_plan_sha256,
            canonical_sha256(state.active_repair_plan),
        )
        self.assertEqual(
            [item.candidate_sha256 for item in result.production_outcomes],
            [item.candidate_sha256 for item in history],
        )
        serialized = state.to_dict()
        self.assertEqual(
            serialized["candidate_sha256"],
            canonical_sha256(serialized["candidate"]),
        )

        with self.assertRaisesRegex(
            ValueError, "active RepairPlan|validated current candidate"
        ):
            replace(
                state,
                validation_count=0,
                last_validation=None,
                validation_history=(),
            )
        forged_history = (
            ProductionSummary(
                attempt=0,
                mode="generated",
                candidate_sha256="f" * 64,
            ),
        )
        with self.assertRaisesRegex(ValueError, "final accepted production"):
            replace(state, production_history=forged_history)

        flipped_history = (
            replace(state.production_history[0], mode="provided"),
            *state.production_history[1:],
        )
        flipped_attempts = (
            replace(state.production_attempts[0], mode="provided"),
            *state.production_attempts[1:],
        )
        with self.assertRaisesRegex(ValueError, "provided provenance"):
            replace(
                state,
                production_history=flipped_history,
                production_attempts=flipped_attempts,
            )

        forged_budget = deepcopy(state.to_dict()["budget"])
        forged_budget["usage"]["llm_calls"] += 1
        with self.assertRaisesRegex(ValueError, "does not equal its event ledger"):
            replace(state, budget=forged_budget)

        tampered_plan = replace(
            result.repair_plans[0],
            global_actions=("tampered replay payload",),
        )
        with self.assertRaisesRegex(ValueError, "latest repair plan"):
            ClosedLoopOutcome(
                status=result.status,
                state=state,
                entry=result.entry,
                report=result.report,
                production_outcomes=result.production_outcomes,
                validation_outcomes=result.validation_outcomes,
                repair_plans=(tampered_plan,),
                changed_fields=result.changed_fields,
            )

        tampered_plan_digest = canonical_sha256(tampered_plan)
        synchronized_history = (
            state.production_history[0],
            replace(
                state.production_history[1],
                repair_plan_sha256=tampered_plan_digest,
            ),
        )
        synchronized_attempts = (
            state.production_attempts[0],
            replace(
                state.production_attempts[1],
                repair_plan_sha256=tampered_plan_digest,
            ),
        )
        synchronized_state = replace(
            state,
            active_repair_plan=tampered_plan,
            production_history=synchronized_history,
            production_attempts=synchronized_attempts,
        )
        with self.assertRaisesRegex(ValueError, "parent round"):
            replace(
                result,
                state=synchronized_state,
                repair_plans=(tampered_plan,),
            )

        tampered_candidate = deepcopy(repaired)
        tampered_candidate["vuln_title"] = "tampered accepted sidecar"
        with self.assertRaisesRegex(ValueError, "production sidecars"):
            replace(
                result,
                production_outcomes=(
                    result.production_outcomes[0],
                    ProductionOutcome(candidate=tampered_candidate),
                ),
            )

        injected_evidence = _evidence(
            self.entry, snippet="unreferenced replay injection"
        )
        injected_validation = replace(
            result.validation_outcomes[0],
            evidence=(injected_evidence,),
        )
        with self.assertRaisesRegex(ValueError, "closed set"):
            replace(
                result,
                validation_outcomes=(
                    injected_validation,
                    *result.validation_outcomes[1:],
                ),
            )

    def test_t1_is_fresh_each_round_and_receives_no_producer_sidecars(self) -> None:
        repaired = deepcopy(self.entry)
        repaired["vuln_title"] = "Isolated repair"
        sentinel_assumption = "SENTINEL-ASSUMPTION-NEVER-T1"
        sentinel_evidence = "SENTINEL-EVIDENCE-NEVER-T1"
        evidence = _evidence(self.entry, snippet=sentinel_evidence)
        first_tool = _tool_call(result_digest="4" * 64)
        second_tool = _tool_call(
            tool_call_id="TOOL-second",
            tool_name="sentinel.second-tool",
            result_digest="6" * 64,
            attempt=1,
            sequence=5,
        )
        producer = _ScriptedProducer(
            [self.entry, repaired],
            evidence_rounds=[(evidence,), (evidence,)],
            tool_rounds=[(first_tool,), (second_tool,)],
            assumptions_rounds=[
                (sentinel_assumption,),
                ("SENTINEL-REPAIR-ASSUMPTION",),
            ],
        )
        bad = _report(
            self.entry, {"vuln_title": "incorrect"}, label="isolation-bad"
        )
        correct = _report(repaired, {"schema": "correct"}, label="isolation-good")

        result, factory = self._run(producer, [bad, correct])

        self.assertEqual(result.status, "finalized")
        self.assertEqual(len(factory.instances), 2)
        self.assertIsNot(factory.instances[0], factory.instances[1])
        self.assertEqual(factory.factory_tasks, [self.task, self.task])
        self.assertTrue(all(task is self.task for task in factory.factory_tasks))
        self.assertEqual(len(factory.calls), 2)
        forbidden_text = (
            sentinel_assumption,
            sentinel_evidence,
            "sentinel.tool",
            "SENTINEL-REPAIR-ASSUMPTION",
            "sentinel.second-tool",
        )
        for args, kwargs in factory.calls:
            self.assertEqual(len(args), 1)
            self.assertEqual(kwargs, {"input_line": 11})
            candidate = args[0]
            self.assertIs(type(candidate), dict)
            self.assertEqual(set(candidate), set(ENTRY_FIELDS))
            encoded = json.dumps(candidate, ensure_ascii=False, sort_keys=True)
            self.assertFalse(any(value in encoded for value in forbidden_text))
            self.assertNotIsInstance(candidate, ProductionOutcome)
            self.assertNotIsInstance(candidate, RepairPlan)
        self.assertEqual(len(producer.plans), 1)
        self.assertIsInstance(producer.plans[0], RepairPlan)


if __name__ == "__main__":
    unittest.main()
