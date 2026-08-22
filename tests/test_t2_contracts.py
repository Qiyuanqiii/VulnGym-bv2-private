from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
from typing import get_args
import unittest

from vulngym_agent.models import EvidenceItem
from vulngym_agent.orchestrator import (
    ModelCallRecord,
    ProducerDraftResult,
    ProducerResult,
    ProductionDeferred,
    ProductionDeferredDraft,
    ProductionDraft,
    ProductionOutcome,
    RunTask,
    ToolCallRecord,
    canonical_sha256,
)


ROOT = Path(__file__).resolve().parents[1]


class T2ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entry = json.loads(
            (ROOT / "data" / "entries.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()[0]
        )
        cls.entry["verify"] = 0
        cls.task = RunTask(
            task_id="task:t2-contract-001",
            report_id=cls.entry["report_id"],
            entry_id=cls.entry["entry_id"],
            inputs={
                "advisory_path": "private/advisory.json",
                "provider_hint": "must-not-cross-the-result-boundary",
            },
        )

    def _tool_call(self, *, attempt: int = 0, sequence: int = 1) -> ToolCallRecord:
        scope = "t2.initial" if attempt == 0 else f"t2.repair-{attempt}"
        return ToolCallRecord(
            task_id=self.task.task_id,
            attempt=attempt,
            policy_scope=scope,
            tool_call_id="TOOL-T2-1",
            tool_name="local.git.show",
            arguments_sha256="a" * 64,
            operation=(
                f"tool:{self.task.task_id}:{attempt}:{scope}:"
                "TOOL-T2-1:local.git.show"
            ),
            budget_event_sequence=sequence,
            status="success",
            result_sha256="b" * 64,
        )

    def _model_call(
        self,
        *,
        call_id: str = "MODEL-T2-1",
        attempt: int = 0,
        sequence: int = 2,
    ) -> ModelCallRecord:
        scope = "t2.initial" if attempt == 0 else f"t2.repair-{attempt}"
        request_sha256 = "c" * 64
        return ModelCallRecord(
            task_id=self.task.task_id,
            attempt=attempt,
            policy_scope=scope,
            model_call_id=call_id,
            stage="semantic_judge",
            backend_id="local.openai",
            model_id="gpt-5.6",
            request_sha256=request_sha256,
            operation=(
                f"model:{self.task.task_id}:{attempt}:{scope}:semantic_judge:"
                f"{call_id}:local.openai:gpt-5.6:{request_sha256}"
            ),
            budget_event_sequence=sequence,
            status="success",
            response_sha256="d" * 64,
        )

    def _evidence(self, *, entry_id: str | None = None) -> EvidenceItem:
        return EvidenceItem(
            evidence_id="EV-T2-CONTRACT-1",
            report_id=self.task.report_id,
            entry_id=self.task.entry_id if entry_id is None else entry_id,
            source_type="source",
            commit=self.entry["commit"],
            file=self.entry["critical_operation"]["file"],
            line_start=1,
            line_end=1,
            snippet="A bounded source fact used by the producer.",
            tool_call_id="TOOL-T2-1",
        )

    def test_model_call_record_is_digest_only_immutable_and_round_trips(self) -> None:
        record = self._model_call()
        serialized = record.to_dict()

        self.assertEqual(ModelCallRecord.from_dict(serialized), record)
        self.assertEqual(
            set(serialized),
            {
                "task_id",
                "attempt",
                "policy_scope",
                "model_call_id",
                "stage",
                "backend_id",
                "model_id",
                "request_sha256",
                "operation",
                "budget_event_sequence",
                "status",
                "response_sha256",
                "error_code",
            },
        )
        self.assertFalse(
            {"prompt", "messages", "reasoning", "chain_of_thought", "api_key"}
            & set(serialized)
        )
        with self.assertRaises(FrozenInstanceError):
            record.status = "error"  # type: ignore[misc]

    def test_t2_outcome_rejects_d3_review_sidecars(self) -> None:
        request_sha256 = "c" * 64
        d3_model = ModelCallRecord(
            task_id=self.task.task_id,
            attempt=0,
            policy_scope="d3.review",
            model_call_id="MODEL-D3-1",
            stage="semantic_judge",
            backend_id="local.openai",
            model_id="gpt-5.6",
            request_sha256=request_sha256,
            operation=(
                f"model:{self.task.task_id}:0:d3.review:semantic_judge:"
                f"MODEL-D3-1:local.openai:gpt-5.6:{request_sha256}"
            ),
            budget_event_sequence=1,
            status="success",
            response_sha256="d" * 64,
        )
        d3_tool = ToolCallRecord(
            task_id=self.task.task_id,
            attempt=0,
            policy_scope="d3.review",
            tool_call_id="TOOL-D3-1",
            tool_name="review.source",
            arguments_sha256="a" * 64,
            operation=(
                f"tool:{self.task.task_id}:0:d3.review:"
                "TOOL-D3-1:review.source"
            ),
            budget_event_sequence=1,
            status="success",
            result_sha256="b" * 64,
        )
        for sidecars in (
            {"model_calls": (d3_model,)},
            {"tool_calls": (d3_tool,)},
        ):
            with self.subTest(sidecars=tuple(sidecars)), self.assertRaisesRegex(
                ValueError, "T2 outcome sidecars"
            ):
                ProductionOutcome(candidate=self.entry, **sidecars)

    def test_model_call_record_rejects_invalid_lifecycle_and_extra_content(self) -> None:
        with self.assertRaisesRegex(ValueError, "stage"):
            ModelCallRecord(
                task_id=self.task.task_id,
                attempt=0,
                policy_scope="t2.initial",
                model_call_id="MODEL-BAD-1",
                stage="free_form_reasoning",
                backend_id="local",
                model_id="gpt-5.6",
                request_sha256="a" * 64,
                operation=(
                    f"model:{self.task.task_id}:0:t2.initial:free_form_reasoning:"
                    f"MODEL-BAD-1:local:gpt-5.6:{'a' * 64}"
                ),
                budget_event_sequence=1,
                status="success",
                response_sha256="b" * 64,
            )
        with self.assertRaisesRegex(ValueError, "requires response_sha256"):
            ModelCallRecord(
                task_id=self.task.task_id,
                attempt=0,
                policy_scope="t2.initial",
                model_call_id="MODEL-BAD-2",
                stage="plan",
                backend_id="local",
                model_id="gpt-5.6",
                request_sha256="a" * 64,
                operation=(
                    f"model:{self.task.task_id}:0:t2.initial:plan:"
                    f"MODEL-BAD-2:local:gpt-5.6:{'a' * 64}"
                ),
                budget_event_sequence=1,
                status="success",
            )
        with self.assertRaisesRegex(ValueError, "requires error_code"):
            ModelCallRecord(
                task_id=self.task.task_id,
                attempt=0,
                policy_scope="t2.initial",
                model_call_id="MODEL-BAD-3",
                stage="reflection",
                backend_id="local",
                model_id="gpt-5.6",
                request_sha256="a" * 64,
                operation=(
                    f"model:{self.task.task_id}:0:t2.initial:reflection:"
                    f"MODEL-BAD-3:local:gpt-5.6:{'a' * 64}"
                ),
                budget_event_sequence=1,
                status="error",
            )
        with self.assertRaisesRegex(ValueError, "cannot have response_sha256"):
            replace(
                self._model_call(),
                status="error",
                error_code="backend_error",
            )

        contaminated = self._model_call().to_dict()
        contaminated["prompt"] = "raw prompt must never cross this boundary"
        with self.assertRaisesRegex(ValueError, "keys differ"):
            ModelCallRecord.from_dict(contaminated)

    def test_call_records_bind_scope_operation_event_and_terminal_state(self) -> None:
        tool = self._tool_call()
        model = self._model_call()
        with self.assertRaisesRegex(ValueError, "requires result_sha256"):
            replace(tool, result_sha256=None)
        with self.assertRaisesRegex(ValueError, "requires error_code"):
            replace(
                tool,
                status="blocked",
                result_sha256=None,
                error_code=None,
            )
        with self.assertRaisesRegex(ValueError, "cannot have result_sha256"):
            replace(tool, status="error", error_code="handler_error")
        with self.assertRaisesRegex(ValueError, "policy_scope"):
            replace(tool, policy_scope="t2.repair-1")
        with self.assertRaisesRegex(ValueError, "operation"):
            replace(model, operation="model:forged")
        with self.assertRaisesRegex(ValueError, "budget_event_sequence"):
            replace(model, budget_event_sequence=True)

    def test_production_outcome_includes_bounded_model_audit_records(self) -> None:
        outcome = ProductionOutcome(
            candidate=deepcopy(self.entry),
            evidence=(self._evidence(),),
            tool_calls=(self._tool_call(),),
            model_calls=(self._model_call(),),
            assumptions=("The semantic role still requires independent T1 review.",),
        )
        serialized = outcome.to_dict()

        self.assertEqual(ProductionOutcome.from_dict(serialized).to_dict(), serialized)
        self.assertEqual(serialized["model_calls"][0]["stage"], "semantic_judge")
        self.assertNotIn("model_calls", serialized["candidate"])

        with self.assertRaisesRegex(ValueError, "model call IDs must be unique"):
            ProductionOutcome(
                candidate=self.entry,
                model_calls=(self._model_call(), self._model_call()),
            )

    def test_production_drafts_are_immutable_and_have_no_authority_fields(self) -> None:
        evidence = self._evidence()
        draft = ProductionDraft(
            candidate=deepcopy(self.entry),
            evidence=(evidence,),
            assumptions=("bounded assumption",),
        )
        serialized = draft.to_dict()

        self.assertEqual(ProductionDraft.from_dict(serialized), draft)
        self.assertFalse(hasattr(draft, "__dict__"))
        self.assertFalse(hasattr(draft, "budget"))
        self.assertFalse(hasattr(draft, "tool_calls"))
        self.assertFalse(hasattr(draft, "model_calls"))
        self.assertFalse(hasattr(draft, "task_id"))
        with self.assertRaises(FrozenInstanceError):
            draft.candidate = {}  # type: ignore[misc]

        contaminated = dict(serialized)
        contaminated["tool_calls"] = [self._tool_call().to_dict()]
        with self.assertRaisesRegex(ValueError, "keys differ"):
            ProductionDraft.from_dict(contaminated)

        deferred = ProductionDeferredDraft(
            stage="resolve_commit",
            reason_code="ambiguous_commit",
            missing_information=("unique fix commit",),
            evidence=(evidence,),
        )
        self.assertEqual(
            ProductionDeferredDraft.from_dict(deferred.to_dict()), deferred
        )
        for forbidden in (
            "task_id",
            "attempt",
            "mode",
            "parent_candidate_sha256",
            "repair_plan_sha256",
            "tool_calls",
            "model_calls",
        ):
            self.assertFalse(hasattr(deferred, forbidden))
        with self.assertRaisesRegex(ValueError, "limit of 256"):
            ProductionOutcome(
                candidate=self.entry,
                model_calls=(self._model_call(),) * 257,
            )

    def test_deferred_result_binds_sanitized_task_and_sidecars(self) -> None:
        missing = ["A unique vulnerable commit cannot be established."]
        deferred = ProductionDeferred.from_task(
            self.task,
            stage="resolve_commit",
            reason_code="ambiguous_commit",
            missing_information=missing,
            evidence=(self._evidence(),),
            tool_calls=(self._tool_call(),),
            model_calls=(self._model_call(),),
        )
        missing.append("Mutation after construction must not leak into the result.")
        serialized = deferred.to_dict()

        self.assertEqual(
            deferred.inputs_sha256,
            canonical_sha256(self.task.inputs),
        )
        self.assertNotIn("inputs", serialized)
        self.assertNotIn("advisory_path", json.dumps(serialized))
        self.assertEqual(len(deferred.missing_information), 1)
        self.assertEqual(
            ProductionDeferred.from_dict(serialized).to_dict(),
            serialized,
        )
        with self.assertRaises(FrozenInstanceError):
            deferred.stage = "compose"  # type: ignore[misc]

    def test_deferred_result_rejects_unbound_evidence_and_dangling_tools(self) -> None:
        wrong_entry = EvidenceItem(
            evidence_id="EV-T2-WRONG-ENTRY",
            report_id=self.task.report_id,
            entry_id="entry-99999",
            source_type="source",
            snippet="This record belongs to a different entry.",
        )
        with self.assertRaisesRegex(ValueError, "entry_id must match"):
            ProductionDeferred.from_task(
                self.task,
                stage="resolve_entry",
                reason_code="ambiguous_entry_point",
                missing_information=("External reachability is not established.",),
                evidence=(wrong_entry,),
            )

        dangling = EvidenceItem(
            evidence_id="EV-T2-DANGLING-TOOL",
            report_id=self.task.report_id,
            entry_id=self.task.entry_id,
            source_type="git",
            snippet="This evidence references a missing tool call.",
            tool_call_id="TOOL-MISSING",
        )
        with self.assertRaisesRegex(ValueError, "must resolve"):
            ProductionDeferred.from_task(
                self.task,
                stage="resolve_commit",
                reason_code="missing_tool_result",
                missing_information=("The referenced object is unavailable.",),
                evidence=(dangling,),
            )

    def test_deferred_result_requires_complete_binding_and_bounded_arrays(self) -> None:
        incomplete_task = RunTask(
            task_id="task:t2-contract-incomplete",
            inputs={},
        )
        with self.assertRaisesRegex(ValueError, "requires task report_id and entry_id"):
            ProductionDeferred.from_task(
                incomplete_task,
                stage="plan",
                reason_code="missing_identity",
                missing_information=("The report identity is unavailable.",),
            )
        with self.assertRaisesRegex(ValueError, "non-empty strings"):
            ProductionDeferred.from_task(
                self.task,
                stage="plan",
                reason_code="insufficient_evidence",
                missing_information=(),
            )
        with self.assertRaisesRegex(ValueError, "limit of 256"):
            ProductionDeferred.from_task(
                self.task,
                stage="plan",
                reason_code="insufficient_evidence",
                missing_information=[f"missing-{index}" for index in range(257)],
            )

    def test_deferred_result_binds_generate_and_repair_topology(self) -> None:
        parent_sha256 = canonical_sha256(self.entry)
        plan_sha256 = "e" * 64
        repaired = ProductionDeferred.from_task(
            self.task,
            attempt=1,
            mode="repair",
            parent_candidate_sha256=parent_sha256,
            repair_plan_sha256=plan_sha256,
            stage="repair",
            reason_code="no_safe_replacement",
            missing_information=("replacement",),
        )
        self.assertEqual(repaired.attempt, 1)
        self.assertEqual(repaired.mode, "repair")
        self.assertEqual(repaired.parent_candidate_sha256, parent_sha256)
        self.assertEqual(repaired.repair_plan_sha256, plan_sha256)

        with self.assertRaisesRegex(ValueError, "attempt 0"):
            ProductionDeferred.from_task(
                self.task,
                attempt=1,
                stage="plan",
                reason_code="missing_advisory",
                missing_information=("advisory",),
            )
        with self.assertRaisesRegex(ValueError, "parent_candidate_sha256"):
            ProductionDeferred.from_task(
                self.task,
                attempt=1,
                mode="repair",
                stage="repair",
                reason_code="no_safe_replacement",
                missing_information=("replacement",),
            )
        with self.assertRaisesRegex(ValueError, "not allowed"):
            ProductionDeferred.from_task(
                self.task,
                attempt=1,
                mode="repair",
                parent_candidate_sha256=parent_sha256,
                repair_plan_sha256=plan_sha256,
                stage="plan",
                reason_code="no_safe_replacement",
                missing_information=("replacement",),
            )

    def test_deserializers_enforce_exact_json_object_and_array_boundaries(self) -> None:
        deferred = ProductionDeferred.from_task(
            self.task,
            stage="reflection",
            reason_code="evidence_conflict",
            missing_information=("Contradictory source evidence remains unresolved.",),
        ).to_dict()
        deferred["api_key"] = "must-not-be-accepted"
        with self.assertRaisesRegex(ValueError, "keys differ"):
            ProductionDeferred.from_dict(deferred)

        outcome = ProductionOutcome(candidate=self.entry).to_dict()
        outcome["model_calls"] = {"MODEL-BAD": self._model_call().to_dict()}
        with self.assertRaisesRegex(ValueError, "must be an array"):
            ProductionOutcome.from_dict(outcome)

    def test_producer_result_union_has_success_and_deferred_variants(self) -> None:
        self.assertEqual(
            set(get_args(ProducerResult)),
            {ProductionOutcome, ProductionDeferred},
        )
        self.assertEqual(
            set(get_args(ProducerDraftResult)),
            {ProductionDraft, ProductionDeferredDraft},
        )


if __name__ == "__main__":
    unittest.main()
