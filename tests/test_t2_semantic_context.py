"""Bounded context/defer regressions. All models and repositories are synthetic."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from tests import test_real_t2_producer as fixture
from tests.test_deepseek_backend import KEY, request
from vulngym_agent.agents import deepseek_backend as ds
from vulngym_agent.agents import t2_semantic_context as context
from vulngym_agent.agents.model_runtime import ModelBlocked
from vulngym_agent.agents.real_t2_producer import LocalStructuredT2Producer
from vulngym_agent.orchestrator import Limits
from vulngym_agent.t2_production_cli import LocalProductionTaskRunner


def details(refs=("EV-current",)):
    return {"reason_code": "unsupported_relationship", "missing_fields": ["relationship"],
            "evidence_refs": list(refs), "explanation": "The supplied blocks do not establish this relationship."}


def deferred(payload, *, structured=True):
    answer = {"action": "defer", "critical_candidate_id": None, "entry_candidate_id": None,
              "project": None, "vuln_title": None, "vuln_category_l1": None, "vuln_category_l2": None}
    if structured:
        answer["defer_details"] = details(payload["defer_contract"]["allowed_evidence_refs"][:1])
    return answer


class SourceWindowTests(unittest.TestCase):
    def test_complete_python_function_includes_decorators_and_exact_lines(self):
        text = "# header\n@route('/x')\ndef entry(value):\n    return helper(value)\n\n# tail\n"
        for anchor in (2, 3, 4):
            block = context.source_window(text, "src/a.py", anchor)
            self.assertEqual((block["line_start"], block["line_end"]), (2, 4))
            self.assertEqual(block["text"], "\n".join(text.splitlines()[1:4]))
            self.assertEqual(block["selection"], "python_function")
            self.assertTrue(block["complete_function"])
            self.assertFalse(block["call_relationship_verified"])

    def test_smallest_enclosing_nested_function_is_selected(self):
        text = "def outer():\n    def inner():\n        return 1\n    return inner()\n"
        block = context.source_window(text, "a.py", 3)
        self.assertEqual((block["line_start"], block["line_end"]), (2, 3))

    def test_async_python_function_is_selected_without_executing_source(self):
        text = "raise AssertionError('source must not execute')\nasync def entry():\n    return 1\n"
        block = context.source_window(text, "a.py", 3)
        self.assertEqual(block["line_start"], 2)
        self.assertTrue(block["complete_function"])

    def test_other_language_and_invalid_python_are_only_line_windows(self):
        for path in ("a.ts", "a.py"):
            block = context.source_window("function entry(v) {\n  return helper(v);\n}\n", path, 2)
            self.assertEqual(block["selection"], "line_window")
            self.assertFalse(block["complete_function"])
            self.assertIsNone(block["enclosing_python_function"])

    def test_large_function_does_not_claim_complete_context(self):
        text = "def entry():\n" + "    x = 1\n" * 150
        block = context.source_window(text, "a.py", 75)
        self.assertEqual((block["line_start"], block["line_end"]), (51, 99))
        self.assertFalse(block["complete_function"])
        self.assertTrue(block["omitted_before"] and block["omitted_after"])

    def test_character_budget_preserves_anchor_and_exact_whole_lines(self):
        lines = [str(i) * 10 for i in range(1, 100)]
        block = context.source_window("\n".join(lines), "a.ts", 50, max_chars=75)
        self.assertLessEqual(len(block["text"]), 75)
        self.assertTrue(block["line_start"] <= 50 <= block["line_end"])
        self.assertEqual(block["text"], "\n".join(lines[block["line_start"] - 1:block["line_end"]]))
        self.assertTrue(block["anchor_line_complete"] and block["trimmed_to_char_budget"])

    def test_overlong_anchor_is_explicitly_truncated(self):
        block = context.source_window("first\n" + "x" * 500 + "\nlast", "a.ts", 2, max_chars=80)
        self.assertEqual((block["line_start"], block["line_end"]), (2, 2))
        self.assertEqual(block["text"], "x" * 80)
        self.assertFalse(block["anchor_line_complete"])
        self.assertFalse(block["complete_function"])

    def test_invalid_anchors_and_budgets_rejected(self):
        for anchor in (True, 0, -1, 2, "1", None):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                context.source_window("one", "a.py", anchor)
        for size in (True, 0, -1, "2"):
            with self.subTest(size=size), self.assertRaises(ValueError):
                context.source_window("one", "a.py", 1, max_chars=size)

    def test_unicode_crlf_is_deterministic(self):
        text = "def entry():\r\n    return '中文'\r\n"
        first = context.source_window(text, "a.py", 2)
        self.assertEqual(first, context.source_window(text, "a.py", 2))
        self.assertEqual(first["text"], "def entry():\n    return '中文'")


class DeferDetailsTests(unittest.TestCase):
    def test_valid_details_remain_model_self_report_not_verified_conclusion(self):
        value = context.validate_defer_details(details(), ["EV-current"])
        self.assertEqual(value["kind"], "model_semantic_defer_v1")
        self.assertEqual(value["assessment_origin"], "model_self_report_not_independently_verified")
        self.assertEqual(value["evidence_refs"], ["EV-current"])

    def test_contract_only_offers_current_evidence_and_bounded_fields(self):
        contract = context.defer_contract(["EV-a", "EV-b"])
        self.assertEqual(contract["allowed_evidence_refs"], ["EV-a", "EV-b"])
        self.assertEqual(contract["max_explanation_chars"], 400)
        self.assertIn("relationship", contract["missing_fields"])

    def test_missing_extra_or_unknown_fields_rejected(self):
        cases = [None, [], {}, {**details(), "reason_code": "guess"},
                 {**details(), "extra": True}, {k: v for k, v in details().items() if k != "explanation"}]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                context.validate_defer_details(value, ["EV-current"])

    def test_refs_require_current_unique_nonempty_bounded_values(self):
        for value in ([], ["EV-stale"], ["EV-current", "EV-current"], "EV-current", [1], [[]],
                      [f"EV-{i}" for i in range(9)]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                context.validate_defer_details({**details(), "evidence_refs": value},
                                               ["EV-current", *(f"EV-{i}" for i in range(9))])

    def test_missing_fields_are_unique_and_from_schema(self):
        for value in ([], ["anything"], ["relationship", "relationship"], "relationship", [True]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                context.validate_defer_details({**details(), "missing_fields": value}, ["EV-current"])

    def test_explanation_empty_overlong_and_control_chars_rejected(self):
        for value in (None, "", "  ", "x" * 401, "x\ny", "x\x00y", "x\x7fy"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                context.validate_defer_details({**details(), "explanation": value}, ["EV-current"])


class SemanticContextIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.LocalStructuredT2ProducerTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def runner(self, backend, *, max_tool_calls=80):
        return LocalProductionTaskRunner(
            package_root=self.fixture.package_root,
            repo_map={fixture.REPO_URL: self.fixture.repository}, backend=backend,
            limits=Limits(max_llm_calls=3, max_tool_calls=max_tool_calls, max_repair_iterations=0),
        )

    def declining_backend(self, change=None):
        backend = fixture._ScriptedBackend()
        original = backend.invoke
        def invoke(current):
            if current.stage != "semantic_judge":
                return original(current)
            backend.requests.append(current)
            answer = deferred(current.payload)
            if change:
                change(answer)
            return answer
        backend.invoke = invoke
        return backend

    def test_context_has_pinned_blobs_diff_advisory_and_identical_reflection_copy(self):
        backend = fixture._ScriptedBackend()
        outcome = self.runner(backend).run(self.fixture._task())
        semantic = backend.requests[1].payload
        self.assertEqual(semantic["contract_version"], 2)
        ctx = semantic["semantic_context"]
        self.assertEqual(ctx, backend.requests[2].payload["review_context"]["semantic_context"])
        self.assertEqual(ctx["diffs"][0]["before_commit"], self.fixture.vulnerable_commit)
        self.assertEqual(ctx["diffs"][0]["after_commit"], self.fixture.fix_commit)
        self.assertIn("@@", ctx["diffs"][0]["excerpt"])
        self.assertFalse(ctx["semantic_relationship_verified"])
        production = outcome.production_outcomes[0]
        evidence = {item.evidence_id: item for item in production.evidence}
        self.assertTrue(set(semantic["defer_contract"]["allowed_evidence_refs"]).issubset(evidence))
        self.assertEqual(sum(call.tool_name == "git_show" for call in production.tool_calls), 1)
        self.assertEqual(ctx["source_files_read"], 1)
        for block in ctx["source_contexts"]:
            self.assertEqual(block["commit"], self.fixture.vulnerable_commit)
            self.assertEqual(block["file"], fixture.SOURCE_PATH)
            self.assertEqual(json.loads(evidence[block["evidence_id"]].snippet), fixture._plain(block))
            self.assertEqual(evidence[block["evidence_id"]].tool_call_id, block["tool_call_id"])
        self.assertIn("return dangerous(request)", "\n".join(b["text"] for b in ctx["source_contexts"]))
        self.assertEqual(ctx["coverage_basis"], "candidate_anchor_line_not_entire_candidate_span")
        self.assertEqual(outcome.entry["verify"], 0)

    def test_full_loaded_advisory_not_already_truncated_summary(self):
        path = self.fixture.package_root / "advisories/item.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["summary"] += " bounded-public-text" * 600
        raw = json.dumps(value, sort_keys=True)
        path.write_text(raw, encoding="utf-8")
        backend = self.declining_backend()
        outcome = self.runner(backend).run(self.fixture._task())
        advisory = backend.requests[1].payload["semantic_context"]["advisory"]
        self.assertEqual(advisory["text"], raw[:6000])
        self.assertTrue(advisory["truncated"])
        self.assertEqual(advisory["source"], "loaded_advisory_text")
        item = next(e for e in outcome.deferred_outcome.evidence if e.evidence_id == advisory["evidence_id"])
        self.assertEqual(item.snippet, advisory["text"])
        self.assertEqual(item.tool_call_id, advisory["tool_call_id"])
        self.assertIn("read_local_advisory", item.tool_call_id)

    def test_context_budgets_flag_omissions_without_unbounded_reads(self):
        for limits in ({"MAX_SOURCE_BLOCKS": 0}, {"MAX_SOURCE_FILES": 0}, {"MAX_SOURCE_CHARS": 100}):
            with self.subTest(limits=limits), patch.multiple(context, **limits):
                backend = self.declining_backend()
                outcome = self.runner(backend).run(self.fixture._task())
                ctx = backend.requests[1].payload["semantic_context"]
                self.assertEqual(ctx["source_contexts"], ())
                self.assertEqual(ctx["source_files_read"], 0)
                self.assertTrue(all(r["status"] == "omitted_context_budget" for r in ctx["candidate_context_coverage"]))
                self.assertIsNone(outcome.entry)

    def test_defer_is_structured_and_references_retained_evidence(self):
        backend = self.declining_backend()
        outcome = self.runner(backend).run(self.fixture._task())
        result = outcome.deferred_outcome
        self.assertEqual((result.stage, result.reason_code), ("semantic_judge", "model_deferred"))
        encoded = next(v for v in result.missing_information if v.startswith("model_defer_details:"))
        value = json.loads(encoded.partition(":")[2])
        self.assertEqual(value["missing_fields"], ["relationship"])
        self.assertTrue(set(value["evidence_refs"]).issubset(e.evidence_id for e in result.evidence))
        self.assertIn("not_independently_verified", value["assessment_origin"])
        self.assertIsNone(outcome.entry)
        self.assertIsNone(outcome.report)
        self.assertEqual(outcome.validation_outcomes, ())

    def test_missing_or_stale_defer_details_cannot_pass(self):
        for change in (lambda a: a.pop("defer_details"),
                       lambda a: a["defer_details"].update(evidence_refs=["EV-stale"]),
                       lambda a: a.update(project="invented-content")):
            with self.subTest(change=change):
                outcome = self.runner(self.declining_backend(change)).run(self.fixture._task())
                self.assertEqual(outcome.deferred_outcome.reason_code, "invalid_model_output")
                self.assertIsNone(outcome.entry)
                self.assertEqual(outcome.validation_outcomes, ())

    def test_defer_evidence_survives_artifact_write_and_two_readbacks(self):
        from vulngym_agent.orchestrator.replay import (
            ReplayRecord, read_closed_loop_artifacts, write_closed_loop_artifacts,
        )
        task = self.fixture._task()
        outcome = self.runner(self.declining_backend()).run(task)
        output = self.fixture.root / "semantic-artifacts"
        manifest = write_closed_loop_artifacts(output, [ReplayRecord(1, task, outcome)])
        first = read_closed_loop_artifacts(output)
        before = {p.name: p.read_bytes() for p in output.iterdir()}
        second = read_closed_loop_artifacts(output)
        self.assertEqual(first.manifest.dataset_sha256, manifest.dataset_sha256)
        self.assertEqual(second.manifest.dataset_sha256, manifest.dataset_sha256)
        self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})
        self.assertEqual(first.record_counts["deferred.jsonl"], 1)
        self.assertEqual(first.record_counts["entries.jsonl"], 0)
        self.assertIn(b"model_defer_details:", before["deferred.jsonl"])
        self.assertIn(b"model_self_report_not_independently_verified", before["deferred.jsonl"])

    def test_select_response_cannot_attach_defer_details(self):
        backend = fixture._ScriptedBackend()
        original = backend.invoke
        def invoke(current):
            answer = original(current)
            if current.stage == "semantic_judge":
                answer["defer_details"] = details()
            return answer
        backend.invoke = invoke
        outcome = self.runner(backend).run(self.fixture._task())
        self.assertEqual(outcome.deferred_outcome.reason_code, "invalid_model_output")
        self.assertIsNone(outcome.entry)

    def test_tool_budget_at_source_read_stops_before_semantic_model(self):
        backend = self.declining_backend()
        first = self.runner(backend).run(self.fixture._task())
        calls = first.deferred_outcome.tool_calls
        before_context = next(i for i, call in enumerate(calls) if call.tool_name == "git_show")
        backend = self.declining_backend()
        outcome = self.runner(backend, max_tool_calls=before_context).run(self.fixture._task())
        self.assertEqual([r.stage for r in backend.requests], ["plan"])
        self.assertEqual(outcome.deferred_outcome.stage, "semantic_judge")
        self.assertIsNone(outcome.entry)

    def test_invalid_window_stops_before_semantic_model(self):
        backend = self.declining_backend()
        with patch.object(context, "source_window", side_effect=ValueError("bad anchor")):
            outcome = self.runner(backend).run(self.fixture._task())
        self.assertEqual(outcome.deferred_outcome.reason_code, "invalid_context_anchor")
        self.assertEqual([r.stage for r in backend.requests], ["plan"])
        self.assertIsNone(outcome.entry)

    def test_legacy_default_keeps_original_defer_contract(self):
        backend = fixture._ScriptedBackend()
        original = backend.invoke
        def invoke(current):
            if current.stage == "semantic_judge":
                backend.requests.append(current)
                return deferred(current.payload, structured=False)
            return original(current)
        backend.invoke = invoke
        draft, _, _ = self.fixture._generate(backend)
        self.assertEqual(draft.reason_code, "model_deferred")
        self.assertEqual(backend.requests[1].payload["contract_version"], 1)
        self.assertNotIn("semantic_context", backend.requests[1].payload)
        self.assertNotIn("defer_contract", backend.requests[1].payload)

    def test_semantic_context_flag_is_strict_boolean(self):
        for value in (1, "true", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                LocalStructuredT2Producer(include_semantic_context=value)

    def test_adapter_rejects_missing_contract2_context_before_transport(self):
        backend = ds.DeepSeekV4ProBackend(api_key=KEY)
        for payload in ({"contract_version": 2}, {"contract_version": 2, "semantic_context": {}}):
            with self.subTest(payload=payload), patch.object(ds, "_post_official") as post:
                with self.assertRaises(ModelBlocked) as error:
                    backend.invoke(request(backend, stage="semantic_judge", payload=payload))
                self.assertEqual(error.exception.error_code, "deepseek_semantic_context_missing")
                post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
