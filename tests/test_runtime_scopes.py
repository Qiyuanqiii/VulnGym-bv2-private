from __future__ import annotations

import unittest

from vulngym_agent.agents.model_runtime import (
    AttemptModelRuntime,
    ModelRequest,
)
from vulngym_agent.orchestrator import Budget, Limits
from vulngym_agent.orchestrator.contracts import ModelCallRecord, ToolCallRecord
from vulngym_agent.runtime_scopes import (
    D3_RUNTIME_SCOPE_PAIRS,
    RUNTIME_SCOPE_PAIRS,
    T2_RUNTIME_SCOPE_PAIRS,
    is_t2_runtime_scope,
    validate_runtime_scope,
)
from vulngym_agent.tools.runtime import (
    AttemptToolRuntime,
    ToolArtifact,
    ToolCallEnvelope,
    ToolDefinition,
    ToolHandlerOutput,
    ToolReferenceError,
)


TASK_ID = "VG-TEST-0123456789ABCDEF0123"


class _Backend:
    backend_id = "reviewer-fixture"
    model_id = "structured-v1"

    def invoke(self, request: ModelRequest):
        return {"candidate_token": "CANDIDATE-0001", "complete": True}


def _handler(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
    return ToolHandlerOutput(
        output={"complete": True},
        artifacts=(
            ToolArtifact(
                task_id=envelope.task_id,
                attempt=envelope.attempt,
                policy_scope=envelope.policy_scope,
                tool_call_id=envelope.tool_call_id,
                artifact_id="ART-review-source-0001",
                kind="review.source",
                payload={"node_ids": ["LOC-node-0001"]},
            ),
        ),
    )


def _tool_runtime(*, scope: str, budget: Budget | None = None) -> AttemptToolRuntime:
    return AttemptToolRuntime(
        task_id=TASK_ID,
        attempt=0,
        policy_scope=scope,
        budget=budget or Budget(Limits(max_tool_calls=4)),
        registry=(
            ToolDefinition(
                name="review.source",
                contract_id="review.source@1",
                handler=_handler,
            ),
        ),
        allowlist=("review.source",),
    )


class RuntimeScopeTests(unittest.TestCase):
    def test_scope_registry_is_a_closed_exact_pair_matrix(self) -> None:
        self.assertEqual(
            frozenset(
                {
                    (0, "t2.initial"),
                    (1, "t2.repair-1"),
                    (2, "t2.repair-2"),
                    (0, "d3.review"),
                }
            ),
            RUNTIME_SCOPE_PAIRS,
        )
        self.assertEqual(frozenset({(0, "d3.review")}), D3_RUNTIME_SCOPE_PAIRS)
        self.assertEqual(3, len(T2_RUNTIME_SCOPE_PAIRS))
        for pair in RUNTIME_SCOPE_PAIRS:
            with self.subTest(pair=pair):
                self.assertEqual(pair, validate_runtime_scope(*pair))
        invalid = (
            (1, "d3.review"),
            (2, "d3.review"),
            (0, "d3.review.extra"),
            (0, "D3.review"),
            (0, "custom"),
            (True, "d3.review"),
        )
        for pair in invalid:
            with self.subTest(pair=pair), self.assertRaisesRegex(
                ValueError, "policy_scope does not match attempt"
            ):
                validate_runtime_scope(*pair)
        self.assertTrue(is_t2_runtime_scope(0, "t2.initial"))
        self.assertFalse(is_t2_runtime_scope(0, "d3.review"))

    def test_model_runtime_records_and_seals_d3_review_lane(self) -> None:
        budget = Budget(Limits(max_llm_calls=2))
        runtime = AttemptModelRuntime(
            task_id=TASK_ID,
            attempt=0,
            policy_scope="d3.review",
            budget=budget,
            backend=_Backend(),
        )
        result = runtime.call(
            "MODEL-REVIEW-0001",
            "semantic_judge",
            {"candidate_token": "CANDIDATE-0001"},
        )
        self.assertEqual("success", result.status)
        self.assertEqual("d3.review", result.policy_scope)
        self.assertIn(":0:d3.review:semantic_judge:", result.operation)
        self.assertEqual(1, budget.usage.llm_calls)
        record = result.to_model_call_record()
        self.assertEqual(record, ModelCallRecord.from_dict(record.to_dict()))
        transcript = runtime.finalize()
        self.assertIs(transcript, runtime.sealed_transcript)
        self.assertEqual((record,), transcript.records)

    def test_tool_runtime_records_seals_and_isolates_d3_review_lane(self) -> None:
        d3_budget = Budget(Limits(max_tool_calls=2))
        d3 = _tool_runtime(scope="d3.review", budget=d3_budget)
        result = d3.call(
            "TOOL-REVIEW-0001", "review.source", {"candidate_token": "C-1"}
        )
        self.assertEqual("success", result.status)
        self.assertEqual("d3.review", result.policy_scope)
        self.assertIn(":0:d3.review:", result.operation)
        record = result.to_tool_call_record()
        self.assertEqual(record, ToolCallRecord.from_dict(record.to_dict()))
        transcript = d3.finalize()
        self.assertIs(transcript, d3.sealed_transcript)
        self.assertEqual((result,), transcript.records)

        t2 = _tool_runtime(scope="t2.initial")
        t2_result = t2.call(
            "TOOL-REVIEW-0002", "review.source", {"candidate_token": "C-1"}
        )
        foreign_ref = t2_result.artifact_refs[0]
        before = d3_budget.usage.tool_calls
        with self.assertRaises(ToolReferenceError):
            d3.resolve_artifact(foreign_ref)
        self.assertEqual(before, d3_budget.usage.tool_calls)

    def test_runtime_constructors_reject_every_non_allowlisted_pair(self) -> None:
        invalid = ((1, "d3.review"), (0, "d3.review.extra"), (0, "custom"))
        for attempt, scope in invalid:
            with self.subTest(runtime="model", attempt=attempt, scope=scope), self.assertRaises(
                ValueError
            ):
                AttemptModelRuntime(
                    task_id=TASK_ID,
                    attempt=attempt,
                    policy_scope=scope,
                    budget=Budget(),
                    backend=_Backend(),
                )
            with self.subTest(runtime="tool", attempt=attempt, scope=scope), self.assertRaises(
                ValueError
            ):
                AttemptToolRuntime(
                    task_id=TASK_ID,
                    attempt=attempt,
                    policy_scope=scope,
                    budget=Budget(),
                    registry=(),
                    allowlist=(),
                )


if __name__ == "__main__":
    unittest.main()
