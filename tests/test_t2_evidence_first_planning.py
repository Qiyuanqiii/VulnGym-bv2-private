"""Offline routing regressions; scripted models are not quality evaluations."""
from __future__ import annotations

import json
from contextlib import redirect_stdout
import io
import unittest
from unittest.mock import patch

from tests import test_real_t2_producer as fixture
from vulngym_agent.agents.real_t2_producer import LocalStructuredT2Producer, _CriticalChoice
from vulngym_agent.orchestrator import Limits, RunTask
from vulngym_agent.t2_production_cli import LocalProductionTaskRunner


class EvidenceFirstPlanningTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.LocalStructuredT2ProducerTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def runner(self, backend, **limits):
        return LocalProductionTaskRunner(
            package_root=self.fixture.package_root,
            repo_map={fixture.REPO_URL: self.fixture.repository}, backend=backend,
            limits=Limits(max_llm_calls=limits.get("max_llm_calls", 3),
                          max_tool_calls=limits.get("max_tool_calls", 80),
                          max_repair_iterations=0),
        )

    def rewrite_pair(self, before, after):
        path = self.fixture.repository / fixture.SOURCE_PATH
        for label, text in (("before", before), ("after", after)):
            path.write_text(text, encoding="utf-8")
            fixture._git(self.fixture.repository, "add", "--", fixture.SOURCE_PATH)
            fixture._git(self.fixture.repository, "commit", "--quiet", "-m", label)
            commit = fixture._git(self.fixture.repository, "rev-parse", "HEAD")
            if label == "before":
                self.fixture.vulnerable_commit = commit
            else:
                self.fixture.fix_commit = commit
        self.fixture._write_advisory((self.fixture.fix_commit,))
        diff = fixture._git(self.fixture.repository, "diff", "--no-ext-diff",
                            self.fixture.vulnerable_commit, self.fixture.fix_commit,
                            "--", fixture.SOURCE_PATH)
        (self.fixture.package_root / "patches/fix.patch").write_text(diff + "\n", encoding="utf-8")

    def guard_task(self, mode="auto"):
        before = ("@app.route('/item')\n"
                  "def public_route(request):\n"
                  "    if request.enabled:\n"
                  "        return request.value\n"
                  "    return None\n")
        after = before.replace("if request.enabled:", "if request.enabled and request.owner:")
        self.rewrite_pair(before, after)
        return self.fixture._task(critical_mode=mode)

    def test_configuration_flag_is_strict_boolean(self):
        for value in (1, "true", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                LocalStructuredT2Producer(evidence_first_planning=value)

    def test_production_cannot_silently_disable_review_profile(self):
        for value in (False, 1, "true", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                LocalProductionTaskRunner(backend=fixture._ScriptedBackend(), review_candidate_pool=value)

    def test_plan_sees_advisory_pins_and_actual_diff_before_model_call(self):
        backend = fixture._ScriptedBackend()
        outcome = self.runner(backend).run(self.fixture._task(critical_mode="auto"))
        request = backend.requests[0]
        context = request.payload["planning_evidence"]
        self.assertEqual(request.stage, "plan")
        self.assertEqual(request.payload["contract_version"], 2)
        self.assertEqual(context["vulnerable_commit"], self.fixture.vulnerable_commit)
        self.assertEqual(context["fix_commit"], self.fixture.fix_commit)
        self.assertIn("Unsafe eval", context["advisory_snippet"])
        self.assertIn("@@", context["diffs"][0]["excerpt"])
        self.assertFalse(context["semantic_role_verified"])
        production = outcome.production_outcomes[0]
        plan_sequence = production.model_calls[0].budget_event_sequence
        collections = [call for call in production.tool_calls if call.tool_name in {
            "read_local_advisory", "git_parents", "git_diff", "dataflow_candidate_search"}]
        self.assertTrue(collections)
        self.assertTrue(all(call.budget_event_sequence < plan_sequence for call in collections))
        self.assertEqual([r.stage for r in backend.requests], ["plan", "semantic_judge", "reflection"])
        self.assertEqual(production.candidate["verify"], 0)
        self.assertEqual(len(outcome.validation_outcomes), 1)

    def test_removed_guard_line_is_reviewable_under_both_unverified_hypotheses(self):
        task = self.guard_task()
        backend = fixture._ScriptedBackend(critical_mode="guard")
        outcome = self.runner(backend).run(task)
        plan = backend.requests[0]
        self.assertEqual(tuple(plan.payload["allowed_critical_modes"]), ("sink", "guard"))
        counts = {item["mode"]: item["candidate_count"]
                  for item in plan.payload["planning_evidence"]["mode_inventory"]}
        self.assertGreater(counts["sink"], 0)
        self.assertGreater(counts["guard"], 0)
        self.assertIs(plan.payload["planning_evidence"]["mode_is_unverified_hypothesis"], True)
        semantic = next(r for r in backend.requests if r.stage == "semantic_judge")
        self.assertIs(semantic.payload["mode_is_unverified_hypothesis"], True)
        self.assertTrue(all(c["mode"] == "guard" for c in semantic.payload["critical_candidates"]))
        self.assertIn("semantic_judge", [r.stage for r in backend.requests])
        self.assertIsNotNone(outcome.entry)
        self.assertEqual(outcome.entry["verify"], 0)

    def test_explicit_sink_constraint_is_not_overridden_by_guard_inventory(self):
        task = self.guard_task(mode="sink")
        backend = fixture._ScriptedBackend(critical_mode="guard")
        outcome = self.runner(backend).run(task)
        self.assertEqual([r.stage for r in backend.requests], ["plan"])
        self.assertEqual(tuple(backend.requests[0].payload["allowed_critical_modes"]), ("sink",))
        self.assertIsNone(outcome.entry)
        self.assertIsNone(outcome.report)
        self.assertEqual(outcome.deferred_outcome.reason_code, "invalid_model_output")

    def test_model_cannot_select_a_mode_with_zero_admissible_candidates(self):
        task = self.guard_task()
        backend = fixture._ScriptedBackend(critical_mode="sink")
        original = LocalStructuredT2Producer._collect_critical_choices
        def guard_only(producer, run, result, **kwargs):
            diagnostic = original(producer, run, result, **kwargs)
            if diagnostic["mode"] == "sink":
                kwargs["critical_choices"][:] = [c for c in kwargs["critical_choices"] if c.mode != "sink"]
                diagnostic["accepted_count"] = 0
            return diagnostic
        with patch.object(LocalStructuredT2Producer, "_collect_critical_choices", guard_only):
            outcome = self.runner(backend).run(task)
        self.assertEqual(tuple(backend.requests[0].payload["allowed_critical_modes"]), ("guard",))
        self.assertEqual([r.stage for r in backend.requests], ["plan"])
        self.assertEqual(outcome.deferred_outcome.reason_code, "invalid_model_output")
        self.assertIsNone(outcome.entry)
        self.assertIsNone(outcome.report)

    def test_semantic_model_can_decline_despite_available_candidate(self):
        task = self.guard_task()
        backend = fixture._ScriptedBackend(critical_mode="guard")
        original = backend.invoke
        def invoke(request):
            if request.stage == "semantic_judge":
                backend.requests.append(request)
                return {"action": "defer", "critical_candidate_id": None, "entry_candidate_id": None,
                        "project": None, "vuln_title": None, "vuln_category_l1": None, "vuln_category_l2": None,
                        "defer_details": {"reason_code": "unsupported_relationship", "missing_fields": ["relationship"],
                                          "evidence_refs": [request.payload["defer_contract"]["allowed_evidence_refs"][0]],
                                          "explanation": "The scripted fixture declines the role relationship."}}
            return original(request)
        backend.invoke = invoke
        outcome = self.runner(backend).run(task)
        self.assertEqual(outcome.deferred_outcome.stage, "semantic_judge")
        self.assertEqual(outcome.deferred_outcome.reason_code, "model_deferred")
        self.assertIsNone(outcome.entry)
        self.assertIsNone(outcome.report)

    def test_missing_entry_construct_defers_instead_of_using_file_start(self):
        self.rewrite_pair("value = source\n", "value = normalized\n")
        backend = fixture._ScriptedBackend()
        outcome = self.runner(backend).run(self.fixture._task(critical_mode="auto"))
        self.assertEqual([r.stage for r in backend.requests], ["plan"])
        self.assertEqual(outcome.deferred_outcome.stage, "resolve_entry")
        self.assertEqual(outcome.deferred_outcome.reason_code, "no_entry_candidate")
        self.assertIsNone(outcome.entry)
        self.assertFalse(outcome.validation_outcomes)

    def test_no_lexical_candidates_defer_without_model_cost(self):
        self.fixture._replace_fix_with_benign_change()
        backend = fixture._ScriptedBackend()
        outcome = self.runner(backend).run(self.fixture._task(critical_mode="auto"))
        self.assertEqual(backend.requests, [])
        self.assertEqual(outcome.deferred_outcome.reason_code, "critical_extractor_no_candidates")
        inventory = [json.loads(item.snippet) for item in outcome.deferred_outcome.evidence
                     if item.source_type == "patch"]
        self.assertEqual(len(inventory), 2)
        self.assertTrue(all(item["assessed_count"] == 0 for item in inventory))

    def test_fix_side_only_candidates_remain_rejected_and_explained(self):
        self.rewrite_pair("", "if value.enabled:\n    return value\n")
        backend = fixture._ScriptedBackend(critical_mode="guard")
        outcome = self.runner(backend).run(self.fixture._task(critical_mode="auto"))
        self.assertEqual(backend.requests, [])
        self.assertIsNone(outcome.entry)
        self.assertEqual(outcome.deferred_outcome.reason_code, "critical_candidates_rejected")
        inventory = [json.loads(item.snippet) for item in outcome.deferred_outcome.evidence
                     if item.source_type == "patch"]
        self.assertTrue(any(item["resolver_reason_counts"].get("fix_only_added_candidate", 0)
                            for item in inventory))
        self.assertTrue(all(item["accepted_count"] == 0 for item in inventory))

    def test_invalid_version_is_caught_before_paying_for_plan(self):
        value = self.fixture._task().to_dict()
        value["inputs"]["expected_vulnerable_commit"] = "f" * 40
        backend = fixture._ScriptedBackend()
        outcome = self.runner(backend).run(RunTask.from_dict(value))
        self.assertEqual(backend.requests, [])
        self.assertEqual(outcome.deferred_outcome.reason_code, "vulnerable_commit_mismatch")

    def test_tool_budget_before_planning_does_not_call_model(self):
        backend = fixture._ScriptedBackend()
        outcome = self.runner(backend, max_tool_calls=1).run(self.fixture._task())
        self.assertEqual(backend.requests, [])
        self.assertEqual(outcome.deferred_outcome.reason_code, "budget_exceeded")

    def test_oversized_candidate_set_stops_before_model(self):
        backend = fixture._ScriptedBackend()
        with patch("vulngym_agent.agents.real_t2_producer._MAX_SEMANTIC_CANDIDATES", 0):
            outcome = self.runner(backend).run(self.fixture._task())
        self.assertEqual(backend.requests, [])
        self.assertEqual(outcome.deferred_outcome.reason_code, "candidate_set_too_large")

    def test_planning_samples_are_bounded_and_not_semantically_verified(self):
        choices = [_CriticalChoice(
            issued_id=f"critical-{index:04d}", source_candidate_id=f"pc-{index}",
            location={"file": fixture.SOURCE_PATH, "line": index + 1, "code": "x" * 3000},
            mode="guard", change_kind="removed", evidence="e" * 3000, tool_call_id="tool:sample",
        ) for index in range(9)]
        context = LocalStructuredT2Producer._planning_evidence(
            snippet="a" * 3000, vulnerable_commit="a" * 40, fix_commit="b" * 40,
            changed_paths=["one", "two"], diff_context=[{"file": "one", "excerpt": "diff"}],
            allowed_modes=("sink", "guard"), critical_choices=choices,
        )
        self.assertEqual(len(context["advisory_snippet"]), 2000)
        self.assertTrue(context["advisory_snippet_truncated"])
        self.assertEqual(context["omitted_diff_count"], 1)
        samples = context["mode_inventory"][1]["samples"]
        self.assertEqual(len(samples), 4)
        self.assertTrue(all(item["code_truncated"] for item in samples))
        self.assertTrue(all(len(item["location"]["code"]) == 1000 for item in samples))
        self.assertTrue(all(len(item["evidence"]) == 500 for item in samples))
        self.assertFalse(context["semantic_role_verified"])

    def test_legacy_replay_keeps_plan_first_without_new_evidence(self):
        backend = fixture._ScriptedBackend()
        _, projection, _ = self.fixture._generate(backend)
        self.assertEqual(projection.model_calls[0].budget_event_sequence, 1)
        self.assertEqual(backend.requests[0].payload["contract_version"], 1)
        self.assertNotIn("planning_evidence", backend.requests[0].payload)

    def probe_arguments(self, task):
        tasks = self.fixture.root / "tasks.jsonl"
        tasks.write_text(json.dumps(task.to_dict()) + "\n", encoding="utf-8")
        repos = self.fixture.root / "repos.json"
        repos.write_text(json.dumps({"contract_version": 1, "repositories": [
            {"repo_url": fixture.REPO_URL, "path": str(self.fixture.repository)}]}), encoding="utf-8")
        return ["--tasks", str(tasks), "--repo-map", str(repos),
                "--package-root", str(self.fixture.package_root)]

    def test_offline_probe_never_calls_provider_or_claims_complete_entries(self):
        from scripts.probe_t2_routing_offline import main
        task = self.guard_task()
        stdout = io.StringIO()
        with patch("vulngym_agent.agents.deepseek_backend._post_official") as post, redirect_stdout(stdout):
            code = main(self.probe_arguments(task))
        post.assert_not_called()
        self.assertEqual(code, 0)
        summary = json.loads(stdout.getvalue())
        self.assertEqual(summary["model"], "offline-script-not-a-model")
        self.assertEqual(summary["network_calls"], 0)
        row = summary["results"][0]
        self.assertTrue(row["semantic_stage_reached"])
        self.assertEqual((row["complete_entries"], row["t1_calls"]), (0, 0))
        self.assertNotIn(str(self.fixture.root), stdout.getvalue())

    def test_probe_candidate_index_has_exact_metadata_not_source_or_quality_claims(self):
        from scripts.probe_t2_routing_offline import main
        stdout = io.StringIO()
        with patch("vulngym_agent.agents.deepseek_backend._post_official") as post, redirect_stdout(stdout):
            code = main(self.probe_arguments(self.guard_task()) + ["--candidate-index"])
        self.assertEqual(code, 0)
        post.assert_not_called()
        row = json.loads(stdout.getvalue())["results"][0]
        self.assertTrue(row["mode_is_unverified_hypothesis"])
        self.assertEqual(row["candidate_policy"], "old-side-review-pool-v1")
        self.assertTrue(row["candidate_index"])
        self.assertTrue(all(len(item["code_sha256"]) == 64 for item in row["candidate_index"]))
        self.assertTrue(all(not item["semantic_role_verified"] for item in row["candidate_index"]))
        self.assertNotIn("if request.enabled", stdout.getvalue())
        self.assertNotIn(str(self.fixture.root), stdout.getvalue())

    def test_offline_probe_rejects_invalid_input_before_task_execution(self):
        from scripts import probe_t2_routing_offline as probe
        task = self.fixture._task()
        value = task.to_dict()
        value["inputs"]["input_line"] = 2
        stdout = io.StringIO()
        with patch.object(probe, "LocalProductionTaskRunner") as runner, redirect_stdout(stdout):
            code = probe.main(self.probe_arguments(RunTask.from_dict(value)))
        runner.assert_not_called()
        self.assertEqual(code, 2)
        self.assertNotIn(str(self.fixture.root), stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
