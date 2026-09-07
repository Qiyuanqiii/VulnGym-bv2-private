"""Synthetic, offline regressions for explicit producer self-review deferral."""
from __future__ import annotations

import json
import unittest

from tests import test_real_t2_producer as fixture
from vulngym_agent.agents import t2_semantic_context as context
from vulngym_agent.agents import deepseek_backend as ds
from vulngym_agent.agents.real_t2_producer import LocalStructuredT2Producer
from vulngym_agent.orchestrator.budget import Budget, Limits
from vulngym_agent.t2_production_cli import LocalProductionTaskRunner


def response(payload):
    return {"action": "defer", "defer_details": {
        "reason_code": "unsupported_relationship", "missing_fields": ["trace"],
        "evidence_refs": list(payload["defer_contract"]["allowed_evidence_refs"][:1]),
        "explanation": "The supplied evidence does not establish that an empty trace is complete.",
    }}


class ReflectionDeferTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.LocalStructuredT2ProducerTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()

    def backend(self, change=None):
        backend = fixture._ScriptedBackend()
        original = backend.invoke
        def invoke(request):
            if request.stage != "reflection":
                return original(request)
            backend.requests.append(request)
            answer = response(request.payload)
            if change:
                change(answer)
            return answer
        backend.invoke = invoke
        return backend

    def runner(self, backend):
        return LocalProductionTaskRunner(
            package_root=self.f.package_root, repo_map={fixture.REPO_URL: self.f.repository},
            backend=backend, limits=Limits(max_llm_calls=3, max_tool_calls=80, max_repair_iterations=0),
        )

    def test_initial_self_report_uses_current_evidence_and_never_calls_t1(self):
        backend = self.backend()
        outcome = self.runner(backend).run(self.f._task())
        result = outcome.deferred_outcome
        self.assertEqual((result.stage, result.reason_code), ("reflection", "model_deferred"))
        self.assertIsNone(outcome.entry)
        self.assertIsNone(outcome.report)
        self.assertEqual(outcome.validation_outcomes, ())
        value = json.loads(next(x.split(":", 1)[1] for x in result.missing_information if x.startswith("model_defer_details:")))
        self.assertEqual(value["kind"], "model_reflection_defer_v1")
        self.assertEqual(value["assessment_origin"], "model_self_report_not_independently_verified")
        self.assertTrue(set(value["evidence_refs"]) <= {e.evidence_id for e in result.evidence})
        payload = backend.requests[-1].payload
        self.assertEqual(payload["contract_version"], 2)
        self.assertTrue(payload["defer_contract"]["required_on_reflection_defer"])
        self.assertEqual([r.stage for r in backend.requests], ["plan", "semantic_judge", "reflection"])
        self.assertEqual(payload["defer_contract"]["allowed_evidence_refs"],
                         backend.requests[1].payload["defer_contract"]["allowed_evidence_refs"])

    def test_missing_stale_or_emit_with_details_rejected(self):
        for change in (lambda x: x.pop("defer_details"),
                       lambda x: x["defer_details"].update(evidence_refs=["EV-OTHER-TASK"]),
                       lambda x: x.update(action="emit"),
                       lambda x: x.update(extra="not-allowed")):
            with self.subTest(change=change):
                outcome = self.runner(self.backend(change)).run(self.f._task())
                self.assertEqual(outcome.deferred_outcome.reason_code, "invalid_model_output")
                self.assertEqual(outcome.validation_outcomes, ())

    def test_emit_shape_remains_action_only(self):
        backend = fixture._ScriptedBackend()
        outcome = self.runner(backend).run(self.f._task())
        self.assertIsNotNone(outcome.entry)
        self.assertEqual(outcome.entry["verify"], 0)
        self.assertIsNotNone(outcome.report)
        wire = ds.build_chat_request(backend.requests[-1], ds.DeepSeekSettings())
        self.assertIn(b'"defer_details"', wire.replace(b'\\"', b'"'))
        self.assertEqual(ds.PROMPT_VERSION, "t2-json-v4")

    def test_repair_self_report_uses_this_attempt_and_retained_schema_evidence(self):
        task = self.f._task()
        draft, _, _ = self.f._generate(fixture._ScriptedBackend(), task=task)
        previous = fixture._plain(draft.candidate)
        plan = self.f._title_plan(task, previous, "Specific replacement title")
        for stale in (False, True):
            with self.subTest(stale=stale):
                backend = self.backend(lambda x: x["defer_details"].update(evidence_refs=["EV-OLD-ATTEMPT"])) if stale else self.backend()
                controller = self.f._factory(backend).create(
                    task, attempt=1, mode="repair", plan=plan,
                    budget=Budget(Limits(max_llm_calls=4, max_tool_calls=20)))
                producer = LocalStructuredT2Producer(
                    include_reflection_context=True, include_semantic_context=True,
                    include_reflection_defer_details=True)
                result = producer.repair(task, previous, plan, controller.producer_context)
                controller.finalize()
                self.assertEqual(result.reason_code, "invalid_model_output" if stale else "model_deferred")
                payload = backend.requests[-1].payload
                self.assertEqual(payload["contract_version"], 2)
                allowed = set(payload["defer_contract"]["allowed_evidence_refs"])
                self.assertTrue(allowed <= {e.evidence_id for e in result.evidence})
                self.assertTrue(all("-A1-" in e for e in allowed))
                self.assertTrue(any(e["source_type"] == "schema" for e in payload["review_context"]["evidence"]))

    def test_legacy_initial_and_repair_keep_unstructured_defer(self):
        backend = fixture._ScriptedBackend()
        original = backend.invoke
        def invoke(request):
            if request.stage == "reflection":
                backend.requests.append(request)
                return {"action": "defer"}
            return original(request)
        backend.invoke = invoke
        result, _, _ = self.f._generate(backend)
        self.assertEqual(result.missing_information, ("reflection declined to emit the candidate",))
        self.assertEqual(backend.requests[-1].payload["contract_version"], 1)
        self.assertNotIn("defer_contract", backend.requests[-1].payload)

    def test_opt_in_requires_both_contexts_and_strict_boolean(self):
        for kwargs in ({"include_reflection_defer_details": 1},
                       {"include_reflection_defer_details": "true"},
                       {"include_reflection_defer_details": True},
                       {"include_reflection_defer_details": True, "include_reflection_context": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                LocalStructuredT2Producer(**kwargs)

    def test_reflection_details_are_bounded_and_stage_distinct(self):
        value = response({"defer_contract": {"allowed_evidence_refs": ["EV-current"]}})["defer_details"]
        self.assertEqual(context.validate_defer_details(value, ["EV-current"], stage="reflection")["kind"], "model_reflection_defer_v1")
        for patch_value in ({"reason_code": "unsupported"}, {"explanation": "x" * 401},
                            {"explanation": "x\ny"}, {"missing_fields": []},
                            {"evidence_refs": []}, {"evidence_refs": ["EV-current"] * 2}):
            with self.subTest(value=patch_value), self.assertRaises(ValueError):
                context.validate_defer_details({**value, **patch_value}, ["EV-current"], stage="reflection")
        with self.assertRaises(ValueError):
            context.validate_defer_details(value, ["EV-current"])  # trace is reflection-specific
        with self.assertRaises(ValueError):
            context.defer_contract(["EV-current"], stage="unknown")


if __name__ == "__main__":
    unittest.main()
