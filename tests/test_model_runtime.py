from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import math
import unittest

from vulngym_agent.agents.model_runtime import (
    AttemptModelRuntime,
    ModelBlocked,
    ModelLedgerMismatch,
    ModelRequest,
    ModelRuntimeFinalized,
    ReplayResponse,
    ReplayStructuredModelBackend,
    StructuredModelBackend,
    structured_json_sha256,
)
from vulngym_agent.orchestrator import Budget, BudgetExceeded, Limits


TASK_ID = "TASK-GHSA-AAAA-BBBB-CCCC"


class _Backend:
    backend_id = "test-backend"
    model_id = "structured-v1"

    def __init__(self, function):
        self._function = function

    def invoke(self, request: ModelRequest):
        return self._function(request)


class AttemptModelRuntimeTests(unittest.TestCase):
    def _runtime(
        self,
        backend,
        *,
        budget: Budget | None = None,
        attempt: int = 0,
    ) -> AttemptModelRuntime:
        return AttemptModelRuntime(
            task_id=TASK_ID,
            attempt=attempt,
            policy_scope="t2.initial" if attempt == 0 else f"t2.repair-{attempt}",
            budget=budget or Budget(Limits(max_llm_calls=8)),
            backend=backend,
        )

    def test_success_is_charged_first_exactly_bound_and_permanently_sealed(self) -> None:
        budget = Budget(Limits(max_llm_calls=2))
        seen: list[ModelRequest] = []

        def invoke(request: ModelRequest):
            self.assertEqual(budget.usage.llm_calls, 1)
            seen.append(request)
            return {"selected_candidate_ids": ["PATCH-0001"], "safe": True}

        runtime = self._runtime(_Backend(invoke), budget=budget)
        result = runtime.call(
            "MODEL-00001",
            "semantic_judge",
            {"candidate_ids": ["PATCH-0001"], "threshold": 0.8},
        )

        self.assertEqual(result.status, "success")
        self.assertEqual(result.response["selected_candidate_ids"], ("PATCH-0001",))
        self.assertEqual(result.request_sha256, seen[0].request_sha256)
        self.assertEqual(result.operation, seen[0].operation)
        self.assertEqual(budget.events[0].operation, result.operation)
        for component in (
            TASK_ID,
            "0",
            "t2.initial",
            "semantic_judge",
            "MODEL-00001",
            "test-backend",
            "structured-v1",
            result.request_sha256,
        ):
            self.assertIn(component, result.operation)
        record = result.to_model_call_record()
        self.assertEqual(record.task_id, TASK_ID)
        self.assertEqual(record.attempt, 0)
        self.assertEqual(record.policy_scope, "t2.initial")
        self.assertEqual(record.operation, result.operation)
        self.assertEqual(record.budget_event_sequence, budget.events[0].sequence)
        self.assertEqual(record.response_sha256, result.response_sha256)
        self.assertEqual(runtime.records, (record,))

        transcript = runtime.finalize()
        self.assertEqual(transcript.records, (record,))
        self.assertEqual(runtime.finalize(), transcript)
        self.assertRegex(transcript.transcript_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(json.loads(json.dumps(transcript.to_dict())), transcript.to_dict())
        with self.assertRaises(ModelRuntimeFinalized):
            runtime.call("MODEL-00002", "reflection", {})
        self.assertEqual(budget.usage.llm_calls, 1)

    def test_requests_responses_and_replay_entries_are_deeply_immutable(self) -> None:
        source = {"nested": {"ids": ["A"]}}
        entry = ReplayResponse(
            stage="plan",
            request=source,
            response={"steps": [{"tool": "advisory.load"}]},
        )
        source["nested"]["ids"].append("B")
        self.assertEqual(entry.request["nested"]["ids"], ("A",))
        with self.assertRaises(TypeError):
            entry.request["other"] = True
        with self.assertRaises(AttributeError):
            entry.response["steps"].append({})
        with self.assertRaises(FrozenInstanceError):
            entry.stage = "repair"  # type: ignore[misc]

        backend = ReplayStructuredModelBackend((entry,))
        result = self._runtime(backend).call("MODEL-00001", "plan", source)
        self.assertEqual(result.status, "blocked")  # source changed: exact replay miss

        matched = self._runtime(backend).call(
            "MODEL-00001", "plan", {"nested": {"ids": ["A"]}}
        )
        self.assertEqual(matched.status, "success")
        with self.assertRaises(TypeError):
            matched.response["new"] = 1
        with self.assertRaises(AttributeError):
            matched.response["steps"].append({})

    def test_replay_backend_only_serves_pre_registered_stage_and_digest(self) -> None:
        entry = ReplayResponse(
            stage="plan",
            request={"evidence_ids": ["E-1"]},
            response={"candidate_ids": ["C-1"]},
        )
        backend = ReplayStructuredModelBackend(
            (entry,), backend_id="replay-test", model_id="fixture-v2"
        )
        self.assertIsInstance(backend, StructuredModelBackend)
        self.assertEqual(
            backend.registered_keys,
            frozenset({("plan", structured_json_sha256(entry.request))}),
        )

        first = self._runtime(backend).call(
            "MODEL-00001", "plan", {"evidence_ids": ["E-1"]}
        )
        second = self._runtime(backend).call(
            "MODEL-00099", "plan", {"evidence_ids": ["E-1"]}
        )
        miss = self._runtime(backend).call(
            "MODEL-00001", "reflection", {"evidence_ids": ["E-1"]}
        )

        self.assertEqual(first.status, "success")
        self.assertEqual(first.response_sha256, second.response_sha256)
        self.assertEqual(miss.status, "blocked")
        self.assertEqual(miss.error_code, "replay_miss")
        self.assertIsNone(miss.response_sha256)

        with self.assertRaisesRegex(ValueError, "duplicate"):
            ReplayStructuredModelBackend((entry, entry))
        with self.assertRaises(TypeError):
            backend._responses[("plan", "0" * 64)] = {}  # type: ignore[attr-defined]

    def test_backend_block_and_error_are_charged_but_scrub_sensitive_content(self) -> None:
        secrets = "raw prompt api-key sk-secret hidden chain-of-thought"

        def blocked(request: ModelRequest):
            raise ModelBlocked("policy_denied")

        def failed(request: ModelRequest):
            raise OSError(secrets)

        blocked_budget = Budget(Limits(max_llm_calls=1))
        blocked_runtime = self._runtime(_Backend(blocked), budget=blocked_budget)
        blocked_result = blocked_runtime.call(
            "MODEL-00001", "repair", {"prompt": secrets}
        )
        self.assertEqual(blocked_result.status, "blocked")
        self.assertEqual(blocked_result.error_code, "policy_denied")
        self.assertEqual(blocked_budget.usage.llm_calls, 1)

        failed_budget = Budget(Limits(max_llm_calls=1))
        failed_runtime = self._runtime(_Backend(failed), budget=failed_budget)
        failed_result = failed_runtime.call(
            "MODEL-00001", "reflection", {"credentials": secrets}
        )
        self.assertEqual(failed_result.status, "error")
        self.assertEqual(failed_result.error_code, "backend_error")
        self.assertIsNone(failed_result.response)
        self.assertEqual(failed_budget.usage.llm_calls, 1)

        serialized = json.dumps(
            {
                "blocked": blocked_runtime.finalize().to_dict(),
                "failed": failed_runtime.finalize().to_dict(),
            },
            sort_keys=True,
        )
        self.assertNotIn(secrets, serialized)
        self.assertNotIn("OSError", serialized)
        self.assertNotIn("prompt", serialized)
        self.assertNotIn("credentials", serialized)

    def test_budget_exceeded_never_invokes_backend_or_creates_fake_record(self) -> None:
        invoked = False

        def invoke(request: ModelRequest):
            nonlocal invoked
            invoked = True
            return {}

        budget = Budget(Limits(max_llm_calls=0))
        runtime = self._runtime(_Backend(invoke), budget=budget)

        with self.assertRaises(BudgetExceeded):
            runtime.call("MODEL-00001", "plan", {})

        self.assertFalse(invoked)
        self.assertEqual(runtime.records, ())
        self.assertEqual(budget.events, ())
        self.assertEqual(runtime.finalize().records, ())

    def test_invalid_stage_json_and_duplicate_id_fail_before_charging(self) -> None:
        calls = 0

        def invoke(request: ModelRequest):
            nonlocal calls
            calls += 1
            return {"ok": True}

        budget = Budget(Limits(max_llm_calls=5))
        runtime = self._runtime(_Backend(invoke), budget=budget)

        for stage, payload in (
            ("freeform", {}),
            ("plan", {"bad": math.nan}),
            ("plan", {"bad": object()}),
        ):
            with self.subTest(stage=stage, payload=payload), self.assertRaises(ValueError):
                runtime.call("MODEL-00001", stage, payload)
        self.assertEqual(budget.usage.llm_calls, 0)

        runtime.call("MODEL-00001", "plan", {})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            runtime.call("MODEL-00001", "reflection", {})
        self.assertEqual(calls, 1)
        self.assertEqual(budget.usage.llm_calls, 1)

    def test_non_object_or_oversized_backend_response_becomes_charged_error(self) -> None:
        for response in ([1, 2], {"deep": math.nan}, {"value": object()}):
            with self.subTest(response=response):
                budget = Budget(Limits(max_llm_calls=1))
                runtime = self._runtime(
                    _Backend(lambda request, value=response: value), budget=budget
                )
                result = runtime.call("MODEL-00001", "plan", {})
                self.assertEqual(result.status, "error")
                self.assertEqual(result.error_code, "backend_error")
                self.assertEqual(budget.usage.llm_calls, 1)
                self.assertEqual(len(runtime.finalize().records), 1)

    def test_finalize_detects_llm_ledger_pollution_and_seals_on_failure(self) -> None:
        budget = Budget(Limits(max_llm_calls=3))
        runtime = self._runtime(_Backend(lambda request: {"ok": True}), budget=budget)
        runtime.call("MODEL-00001", "plan", {})
        budget.charge_llm_call(operation="model:unowned")

        with self.assertRaises(ModelLedgerMismatch):
            runtime.finalize()
        with self.assertRaises(ModelLedgerMismatch):
            runtime.finalize()
        with self.assertRaises(ModelRuntimeFinalized):
            runtime.call("MODEL-00002", "reflection", {})

    def test_invalid_constructor_values_and_protocol_are_rejected(self) -> None:
        budget = Budget()
        with self.assertRaises(ValueError):
            AttemptModelRuntime(
                task_id=TASK_ID,
                attempt=3,
                policy_scope="t2.repair-3",
                budget=budget,
                backend=_Backend(lambda request: {}),
            )
        with self.assertRaisesRegex(ValueError, "backend"):
            AttemptModelRuntime(
                task_id=TASK_ID,
                attempt=0,
                policy_scope="t2.initial",
                budget=budget,
                backend=object(),  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
