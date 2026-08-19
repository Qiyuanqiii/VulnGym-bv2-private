from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import pickle
import unittest

from vulngym_agent.agents.model_runtime import ModelRequest
from vulngym_agent.orchestrator.budget import Budget, Limits
from vulngym_agent.orchestrator.producer_context import (
    ProducerAttemptController,
    ProducerContextFinalized,
    ProducerContextLedgerMismatch,
    ProducerContextReceipt,
    ProducerExecutionContext,
    ProducerTranscriptProjection,
)
from vulngym_agent.tools.runtime import (
    ToolArtifact,
    ToolCallEnvelope,
    ToolDefinition,
    ToolHandlerOutput,
    ToolNotAllowed,
)


TASK_ID = "TASK-GHSA-AAAA-BBBB-CCCC"


class _Backend:
    backend_id = "local-replay"
    model_id = "structured-v1"

    def invoke(self, request: ModelRequest):
        return {"stage": request.stage, "accepted": True}


def _read_source(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
    artifact = ToolArtifact(
        task_id=envelope.task_id,
        attempt=envelope.attempt,
        policy_scope=envelope.policy_scope,
        tool_call_id=envelope.tool_call_id,
        artifact_id="ART-source-1",
        kind="source.snippet",
        payload={"path": "src/a.py", "line": 7},
    )
    return ToolHandlerOutput(output={"found": True}, artifacts=(artifact,))


class ProducerExecutionContextTests(unittest.TestCase):
    def _controller(
        self,
        *,
        budget: Budget | None = None,
        attempt: int = 0,
        mode: str = "generate",
    ) -> ProducerAttemptController:
        return ProducerAttemptController(
            task_id=TASK_ID,
            attempt=attempt,
            mode=mode,
            policy_scope="t2.initial" if attempt == 0 else f"t2.repair-{attempt}",
            budget=budget or Budget(Limits(max_tool_calls=8, max_llm_calls=8)),
            tool_registry=(ToolDefinition("source.read", _read_source),),
            allowed_tools=("source.read",),
            model_backend=_Backend(),
        )

    def test_calls_are_projected_only_by_finalize_and_exactly_close_budget(self) -> None:
        budget = Budget(Limits(max_tool_calls=2, max_llm_calls=2))
        controller = self._controller(budget=budget)
        context = controller.producer_context

        tool_result = context.call_tool(
            "TOOL-00001", "source.read", {"path": "src/a.py"}
        )
        artifact = context.resolve_artifact(tool_result.artifact_refs[0])
        plan_result = context.call_model("MODEL-plan", "plan", {"task": TASK_ID})
        model_result = context.call_model(
            "MODEL-00001", "semantic_judge", {"artifact": artifact.payload_sha256}
        )

        projection = controller.finalize()
        self.assertEqual(projection.tool_calls, (tool_result.to_tool_call_record(),))
        self.assertEqual(
            projection.model_calls,
            (plan_result.to_model_call_record(), model_result.to_model_call_record()),
        )
        self.assertEqual(
            {
                record.budget_event_sequence
                for record in (*projection.tool_calls, *projection.model_calls)
            },
            {event.sequence for event in budget.events},
        )
        self.assertEqual(projection.tool_names, ("source.read",))
        self.assertEqual(projection.model_stages, ("plan", "semantic_judge"))
        self.assertEqual(
            projection.call_order,
            (
                ("tool", "source.read"),
                ("model", "plan"),
                ("model", "semantic_judge"),
            ),
        )
        self.assertEqual(controller.finalize(), projection)
        self.assertIs(controller.finalize(), projection)

    def test_finalize_seals_both_call_surfaces_but_resolution_remains_read_only(self) -> None:
        controller = self._controller()
        context = controller.producer_context
        result = context.call_tool("TOOL-00001", "source.read", {})
        ref = result.artifact_refs[0]
        expected_artifact = context.resolve_artifact(ref)
        controller.finalize()

        with self.assertRaises(ProducerContextFinalized):
            context.call_tool("TOOL-00002", "source.read", {})
        with self.assertRaises(ProducerContextFinalized):
            context.call_model("MODEL-00001", "reflection", {})
        self.assertIs(context.resolve_artifact(ref), expected_artifact)

    def test_receipt_is_identity_bound_in_memory_only_and_never_in_sidecar(self) -> None:
        first = self._controller()
        second = self._controller()
        projection = first.finalize()

        self.assertTrue(first.issued(projection))
        self.assertFalse(second.issued(projection))
        forged = ProducerTranscriptProjection(
            task_id=projection.task_id,
            attempt=projection.attempt,
            mode=projection.mode,
            policy_scope=projection.policy_scope,
            tool_calls=projection.tool_calls,
            model_calls=projection.model_calls,
            tool_transcript_sha256="0" * 64,
            model_transcript_sha256="0" * 64,
            receipt=projection.receipt,
        )
        self.assertFalse(first.issued(forged))
        with self.assertRaises(TypeError):
            ProducerContextReceipt(object())
        with self.assertRaises(TypeError):
            json.dumps(projection.receipt)
        with self.assertRaises(TypeError):
            pickle.dumps(projection.receipt)
        sidecar = projection.to_dict()
        self.assertNotIn("receipt", sidecar)
        self.assertNotIn("nonce", json.dumps(sidecar, sort_keys=True))

    def test_projection_and_record_arrays_are_immutable(self) -> None:
        controller = self._controller()
        context = controller.producer_context
        context.call_model("MODEL-00001", "plan", {"task": "produce"})
        projection = controller.finalize()

        with self.assertRaises(FrozenInstanceError):
            projection.mode = "repair"  # type: ignore[misc]
        self.assertIsInstance(projection.tool_calls, tuple)
        self.assertIsInstance(projection.model_calls, tuple)
        self.assertIsInstance(context, ProducerExecutionContext)
        self.assertFalse(hasattr(context, "__dict__"))
        self.assertFalse(hasattr(context, "budget"))
        self.assertFalse(hasattr(context, "finalize"))
        self.assertFalse(hasattr(context, "issued"))
        self.assertFalse(hasattr(context, "receipt"))
        with self.assertRaises(AttributeError):
            context.task_id = "TASK-forged"  # type: ignore[misc]

    def test_unlisted_tool_is_rejected_without_charging(self) -> None:
        budget = Budget(Limits(max_tool_calls=2, max_llm_calls=2))
        controller = ProducerAttemptController(
            task_id=TASK_ID,
            attempt=0,
            mode="generate",
            policy_scope="t2.initial",
            budget=budget,
            tool_registry=(ToolDefinition("source.read", _read_source),),
            allowed_tools=(),
            model_backend=_Backend(),
        )
        context = controller.producer_context

        with self.assertRaises(ToolNotAllowed):
            context.call_tool("TOOL-00001", "source.read", {})
        self.assertEqual(budget.events, ())
        self.assertEqual(controller.finalize().tool_calls, ())

    def test_none_tool_arguments_are_normalized_to_an_empty_object(self) -> None:
        observed = []

        def handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            observed.append(envelope.arguments)
            return ToolHandlerOutput(output={"ok": True})

        controller = ProducerAttemptController(
            task_id=TASK_ID,
            attempt=0,
            mode="generate",
            policy_scope="t2.initial",
            budget=Budget(Limits(max_tool_calls=1)),
            tool_registry=(ToolDefinition("source.read", handler),),
            allowed_tools=("source.read",),
            model_backend=_Backend(),
        )
        context = controller.producer_context
        context.call_tool("TOOL-00001", "source.read")

        self.assertEqual(dict(observed[0]), {})
        controller.finalize()

    def test_generate_model_stages_must_be_a_unique_strict_prefix(self) -> None:
        budget = Budget(Limits(max_llm_calls=4))
        controller = self._controller(budget=budget)
        context = controller.producer_context

        with self.assertRaisesRegex(ValueError, "expected 'plan'"):
            context.call_model("MODEL-wrong-1", "semantic_judge", {})
        self.assertEqual(budget.usage.llm_calls, 0)
        context.call_model("MODEL-plan", "plan", {})
        with self.assertRaisesRegex(ValueError, "expected 'semantic_judge'"):
            context.call_model("MODEL-duplicate", "plan", {})
        with self.assertRaisesRegex(ValueError, "expected 'semantic_judge'"):
            context.call_model("MODEL-wrong-2", "reflection", {})
        self.assertEqual(budget.usage.llm_calls, 1)
        context.call_model("MODEL-judge", "semantic_judge", {})
        context.call_model("MODEL-reflect", "reflection", {})
        with self.assertRaisesRegex(ValueError, "expected None"):
            context.call_model("MODEL-extra", "reflection", {})

        projection = controller.finalize()
        self.assertEqual(
            projection.model_stages,
            ("plan", "semantic_judge", "reflection"),
        )

    def test_repair_model_stages_must_be_a_unique_strict_prefix(self) -> None:
        budget = Budget(Limits(max_llm_calls=3))
        controller = self._controller(budget=budget, attempt=1, mode="repair")
        context = controller.producer_context

        with self.assertRaisesRegex(ValueError, "expected 'repair'"):
            context.call_model("MODEL-wrong", "plan", {})
        context.call_model("MODEL-repair", "repair", {})
        with self.assertRaisesRegex(ValueError, "expected 'reflection'"):
            context.call_model("MODEL-duplicate", "repair", {})
        context.call_model("MODEL-reflect", "reflection", {})

        self.assertEqual(
            controller.finalize().model_stages, ("repair", "reflection")
        )

    def test_finalize_accepts_empty_and_partial_stage_prefixes_for_defer(self) -> None:
        empty = self._controller()
        self.assertEqual(empty.finalize().model_stages, ())

        partial = self._controller()
        partial.producer_context.call_model("MODEL-plan", "plan", {})
        self.assertEqual(partial.finalize().model_stages, ("plan",))

    def test_unrelated_or_fabricated_budget_event_fails_closed_permanently(self) -> None:
        budget = Budget(Limits(max_tool_calls=2, max_llm_calls=2, max_repair_iterations=2))
        controller = self._controller(budget=budget)
        context = controller.producer_context
        context.call_tool("TOOL-00001", "source.read", {})
        budget.charge_repair_iteration(operation="forged:outside-context")

        with self.assertRaises(ProducerContextLedgerMismatch) as first:
            controller.finalize()
        with self.assertRaises(ProducerContextLedgerMismatch) as second:
            controller.finalize()
        self.assertIs(first.exception, second.exception)
        with self.assertRaises(ProducerContextFinalized):
            context.call_model("MODEL-00001", "reflection", {})

    def test_same_resource_fabricated_charge_is_rejected_by_owned_runtime(self) -> None:
        budget = Budget(Limits(max_tool_calls=2, max_llm_calls=2))
        controller = self._controller(budget=budget)
        budget.charge_tool_call(operation="tool:forged")

        with self.assertRaises(ProducerContextLedgerMismatch):
            controller.finalize()

    def test_mode_attempt_and_scope_topology_is_fixed(self) -> None:
        common = {
            "task_id": TASK_ID,
            "budget": Budget(),
            "tool_registry": (ToolDefinition("source.read", _read_source),),
            "allowed_tools": ("source.read",),
            "model_backend": _Backend(),
        }
        with self.assertRaisesRegex(ValueError, "generate context"):
            ProducerAttemptController(
                attempt=1,
                mode="generate",
                policy_scope="t2.repair-1",
                **common,
            )
        with self.assertRaisesRegex(ValueError, "repair context"):
            ProducerAttemptController(
                attempt=0,
                mode="repair",
                policy_scope="t2.initial",
                **common,
            )
        with self.assertRaisesRegex(ValueError, "policy_scope"):
            ProducerAttemptController(
                attempt=0,
                mode="generate",
                policy_scope="t2.generate.custom",
                **common,
            )

    def test_repair_context_uses_fixed_repair_identity(self) -> None:
        controller = self._controller(attempt=2, mode="repair")
        context = controller.producer_context
        tool = context.call_tool("TOOL-00001", "source.read", {})
        model = context.call_model("MODEL-00001", "repair", {"fields": ["title"]})
        projection = controller.finalize()

        self.assertEqual(projection.mode, "repair")
        self.assertEqual(projection.attempt, 2)
        self.assertEqual(projection.policy_scope, "t2.repair-2")
        for record in (tool.to_tool_call_record(), model.to_model_call_record()):
            self.assertEqual(record.task_id, TASK_ID)
            self.assertEqual(record.attempt, 2)
            self.assertEqual(record.policy_scope, "t2.repair-2")


if __name__ == "__main__":
    unittest.main()
