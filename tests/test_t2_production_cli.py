"""Synthetic plumbing tests; these are not real-model quality measurements."""

from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
import io
import json
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

from tests import test_real_t2_producer as fixture
from vulngym_agent.agents.model_runtime import ModelBlocked, ReplayStructuredModelBackend
from vulngym_agent.closed_loop_cli import (
    ClosedLoopBatchError,
    ExactReplayBackend,
    LocalClosedLoopTaskRunner,
    iter_task_jsonl,
    run_closed_loop_batch,
)
from vulngym_agent.orchestrator import Limits, RunTask
from vulngym_agent import t2_production_cli as production


class BackendFactoryTests(unittest.TestCase):
    def test_import_is_explicit_and_factory_is_called_once(self):
        module = ModuleType("unit_t2_backend")
        calls = []
        backend = fixture._ScriptedBackend()
        module.create = lambda: (calls.append(True), backend)[1]
        with patch.dict(sys.modules, {module.__name__: module}):
            result = production.load_backend_factory("unit_t2_backend:create")
        self.assertIs(result, backend)
        self.assertEqual(calls, [True])
        self.assertEqual(backend.requests, [])

    def test_invalid_factory_syntax_does_not_import(self):
        for specification in ("x", "x:y.z", "x:y()", "./x.py:create", "x:y\n", ""):
            with self.subTest(specification=specification), patch.object(
                production.importlib, "import_module"
            ) as importing:
                with self.assertRaises(ValueError):
                    production.load_backend_factory(specification)
                importing.assert_not_called()

    def test_factory_rejects_invalid_backend_and_identifier(self):
        invalid_id = fixture._ScriptedBackend()
        invalid_id.backend_id = "C:\\sensitive\\backend"
        noncallable = fixture._ScriptedBackend()
        noncallable.invoke = None
        for backend in (None, object(), fixture._ScriptedBackend, invalid_id, noncallable):
            with self.subTest(backend=type(backend).__name__):
                with self.assertRaises(ValueError):
                    production._validate_backend(backend)

    def test_known_replay_backends_are_not_production_backends(self):
        for backend in (ExactReplayBackend([]), ReplayStructuredModelBackend([])):
            with self.subTest(backend=type(backend).__name__):
                with self.assertRaisesRegex(ValueError, "exact-replay"):
                    production._validate_backend(backend)

    def test_old_runner_still_rejects_a_non_replay_backend(self):
        with self.assertRaisesRegex(ValueError, "ExactReplayBackend"):
            LocalClosedLoopTaskRunner(backend=fixture._ScriptedBackend())

    def test_help_has_no_model_call_and_no_replay_argument(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout), patch.object(production, "load_backend_factory") as loading:
            with self.assertRaises(SystemExit) as stopped:
                production.main(["--help"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("--backend-factory", stdout.getvalue())
        self.assertNotIn("--replay-responses", stdout.getvalue())
        loading.assert_not_called()


class ProductionCompositionTests(unittest.TestCase):
    def setUp(self):
        # Reuse the small synthetic Git/advisory fixture, not benchmark answers.
        self.fixture = fixture.LocalStructuredT2ProducerTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.backend = fixture._ScriptedBackend()
        self.task = self.fixture._task()

    def runner(self, backend=None, **configuration):
        return production.LocalProductionTaskRunner(
            package_root=self.fixture.package_root,
            repo_map={fixture.REPO_URL: self.fixture.repository},
            backend=self.backend if backend is None else backend,
            limits=configuration.pop("limits", Limits(max_llm_calls=8, max_tool_calls=80)),
            **configuration,
        )

    def test_fresh_request_drives_local_t2_and_actual_t1(self):
        runner = self.runner()
        outcome = runner.run(self.task)
        self.assertEqual(outcome.status, "manual_review")
        self.assertEqual(outcome.report.verdict, "uncertain")
        self.assertIsNotNone(outcome.entry)  # Retained candidate, not auto-finalized.
        candidate = outcome.production_outcomes[-1].candidate
        self.assertEqual(candidate["verify"], 0)
        self.assertEqual(candidate["commit"], self.fixture.vulnerable_commit)
        self.assertEqual(len(outcome.validation_outcomes), 1)
        self.assertEqual([request.stage for request in self.backend.requests],
                         ["plan", "semantic_judge", "reflection"])
        self.assertEqual(len(outcome.production_outcomes[0].model_calls), 3)
        runner.finalize_batch()
        runner.finalize_batch()  # Closure is idempotent, not a second run.
        with self.assertRaises(ClosedLoopBatchError):
            runner.run(self.task)
        self.assertEqual(len(self.backend.requests), 3)

    def test_two_unregistered_tasks_share_backend_but_not_task_identity(self):
        second_value = self.task.to_dict()
        second_value.update(task_id="task:fresh-second", entry_id="entry-00002")
        second_value["inputs"]["input_line"] = 2
        second = RunTask.from_dict(second_value)
        lines = [json.dumps(task.to_dict()) for task in (self.task, second)]
        task_file = self.fixture.root / "fresh-tasks.jsonl"
        task_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        records = iter_task_jsonl(task_file)
        summary, events = run_closed_loop_batch(
            records, self.runner(), write_artifacts=tuple,
        )
        self.assertEqual((summary.tasks_run, summary.manual_review, summary.input_failures), (2, 2, 0))
        self.assertEqual(summary.entries_written, 0)
        self.assertEqual(summary.exit_code, 0)
        self.assertEqual(len(events), 2)
        self.assertEqual({r.task_id for r in self.backend.requests}, {self.task.task_id, second.task_id})
        self.assertEqual(len({r.operation for r in self.backend.requests}), 6)

    def test_insufficient_evidence_defer_keeps_a_reason_not_an_entry(self):
        self.backend.invoke = lambda request: {"action": "defer", "critical_mode": None}
        outcome = self.runner().run(self.task)
        self.assertNotEqual(outcome.status, "finalized")
        self.assertIsNone(outcome.entry)
        self.assertIsNone(outcome.report)  # No made-up T1 verdict before a candidate.
        self.assertEqual(outcome.production_outcomes, ())
        self.assertEqual(outcome.deferred_outcome.reason_code, "model_deferred")
        self.assertTrue(outcome.deferred_outcome.missing_information)

    def test_declared_patch_file_is_optional_when_git_diff_is_available(self):
        value = self.task.to_dict()
        value["inputs"]["package"]["patches"] = []
        outcome = self.runner().run(RunTask.from_dict(value))
        self.assertEqual(len(outcome.production_outcomes), 1)
        self.assertEqual(outcome.production_outcomes[0].candidate["verify"], 0)
        self.assertIsNotNone(outcome.report)
        self.assertEqual([r.stage for r in self.backend.requests],
                         ["plan", "semantic_judge", "reflection"])

    def test_unknown_candidate_cannot_be_turned_into_a_complete_entry(self):
        outcome = self.runner(fixture._ScriptedBackend(unknown_candidate=True)).run(self.task)
        self.assertNotEqual(outcome.status, "finalized")
        self.assertIsNone(outcome.entry)
        self.assertEqual(outcome.production_outcomes, ())
        self.assertEqual(outcome.deferred_outcome.reason_code, "unknown_candidate_id")

    def test_model_budget_still_limits_real_backend_invocations(self):
        outcome = self.runner(limits=Limits(max_llm_calls=1, max_tool_calls=80)).run(self.task)
        self.assertEqual(len(self.backend.requests), 1)
        self.assertIsNone(outcome.entry)
        self.assertNotEqual(outcome.status, "finalized")

    def test_backend_exception_text_is_not_in_persistable_outcome(self):
        def unavailable(request):
            raise TimeoutError("secret-token C:\\hidden\\provider-config")
        self.backend.invoke = unavailable
        outcome = self.runner().run(self.task)
        public = repr(outcome)
        self.assertNotIn("secret-token", public)
        self.assertNotIn("provider-config", public)
        self.assertIsNone(outcome.entry)
        self.assertEqual(outcome.deferred_outcome.model_calls[0].error_code, "backend_error")

    def test_backend_identity_change_aborts_batch_closure(self):
        runner = self.runner()
        self.backend.model_id = "different-model"
        with self.assertRaises(ClosedLoopBatchError):
            runner.run(self.task)
        with self.assertRaises(ClosedLoopBatchError):
            runner.finalize_batch()
        self.assertEqual(self.backend.requests, [])

    def cli_arguments(self):
        root = self.fixture.root
        tasks = root / "tasks.jsonl"
        tasks.write_text(json.dumps(self.task.to_dict()) + "\n", encoding="utf-8")
        repo_map = root / "repo-map.json"
        repo_map.write_text(json.dumps({
            "contract_version": 1,
            "repositories": [{"repo_url": fixture.REPO_URL, "path": str(self.fixture.repository)}],
        }), encoding="utf-8")
        return ["--tasks", str(tasks), "--repo-map", str(repo_map),
                "--package-root", str(self.fixture.package_root),
                "--output-dir", str(root / "output"),
                "--backend-factory", "unit_t2_backend:create", "--max-tool-calls", "80"]

    def test_cli_publishes_synthetic_review_artifacts_without_replay_fixtures(self):
        module = ModuleType("unit_t2_backend")
        module.create = lambda: self.backend
        stdout = io.StringIO()
        with patch.dict(sys.modules, {module.__name__: module}), redirect_stdout(stdout):
            code = production.main(self.cli_arguments())
        summary = json.loads(stdout.getvalue())
        self.assertEqual(code, 0, summary)
        self.assertEqual(summary["manual_review"], 1)
        self.assertEqual(summary["entries_written"], 0)
        self.assertEqual(summary["model_mode"], "configured_backend")
        self.assertEqual(summary["backend_id"], "test.offline-script")
        self.assertEqual((self.fixture.root / "output" / "entries.jsonl").read_bytes(), b"")
        self.assertNotIn(str(self.fixture.root), stdout.getvalue())

    def test_cli_factory_error_is_path_free_and_does_not_publish(self):
        stdout = io.StringIO()
        with patch.object(production, "load_backend_factory", side_effect=RuntimeError(
            "secret-token C:\\hidden\\config"
        )), redirect_stdout(stdout):
            code = production.main(self.cli_arguments())
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout.getvalue())["error_code"],
                         "production_configuration_or_io_error")
        self.assertNotIn("secret-token", stdout.getvalue())
        self.assertFalse((self.fixture.root / "output").exists())

    def test_cli_model_timeout_is_incomplete_even_with_preserved_manual_review(self):
        def blocked(request):
            raise ModelBlocked("deepseek_timeout")
        self.backend.invoke = blocked
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(production, "load_backend_factory", return_value=self.backend), redirect_stdout(stdout), redirect_stderr(stderr):
            code = production.main(self.cli_arguments() + ["--progress"])
        summary = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(summary["status"], "incomplete")
        self.assertEqual(summary["execution_status"], "model_execution_incomplete")
        self.assertEqual(summary["manual_review"], 1)
        self.assertEqual(summary["execution_counts"]["model_declared_defer_tasks"], 0)
        self.assertEqual(summary["execution_counts"]["model_problem_tasks"], 1)
        self.assertEqual(summary["execution_counts"]["complete_candidate_tasks"], 0)
        self.assertEqual(summary["model_error_counts"], {"deepseek_timeout": 1})
        self.assertFalse(summary["model_call_counts_are_http_counts"])
        self.assertTrue((self.fixture.root / "output" / "deferred.jsonl").is_file())
        self.assertEqual([json.loads(s)["event"] for s in stderr.getvalue().splitlines()],
                         ["task_started", "task_finished"])
        self.assertNotIn(str(self.fixture.root), stdout.getvalue() + stderr.getvalue())

    def test_cli_valid_defer_is_not_a_transport_failure(self):
        self.backend.invoke = lambda request: {"action": "defer", "critical_mode": None}
        stdout = io.StringIO()
        with patch.object(production, "load_backend_factory", return_value=self.backend), redirect_stdout(stdout):
            code = production.main(self.cli_arguments())
        summary = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(summary["execution_counts"]["model_declared_defer_tasks"], 1)
        self.assertEqual(summary["execution_counts"]["model_problem_tasks"], 0)
        self.assertEqual(summary["execution_status"], "processed_not_quality_verified")

    def test_cli_truncation_adds_only_metadata_and_keeps_exit_one(self):
        from tests.test_deepseek_backend import KEY, envelope, wire
        from vulngym_agent.agents import deepseek_backend as ds
        backend = ds.DeepSeekV4ProBackend(api_key=KEY,
            settings=ds.DeepSeekSettings(token_budget_profile="t2-balanced-v1"))
        plan = envelope('{"action":"analyze","critical_mode":"sink"}')
        truncated = envelope("do-not-log-answer", finish="length")
        truncated["usage"] = {"prompt_tokens": 100, "completion_tokens": 16384, "total_tokens": 16484}
        stdout = io.StringIO()
        with patch.object(production, "load_backend_factory", return_value=backend), \
                patch.object(ds, "_post_official", side_effect=[wire(plan), wire(truncated)]) as post, redirect_stdout(stdout):
            code = production.main(self.cli_arguments() + ["--max-llm-calls", "3", "--max-repair-iterations", "0"])
        summary = json.loads(stdout.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(summary["model_error_counts"], {"deepseek_output_truncated": 1})
        self.assertEqual(summary["execution_counts"]["model_declared_defer_tasks"], 0)
        self.assertEqual(summary["last_completion_failure"]["stage"], "semantic_judge")
        self.assertEqual(summary["last_completion_failure"]["configured_max_tokens"], 16384)
        self.assertNotIn("do-not-log-answer", stdout.getvalue())
        self.assertNotIn("private-provider-reasoning", stdout.getvalue())
        self.assertNotIn(KEY, stdout.getvalue())

    def test_cli_complete_candidate_count_does_not_require_finalized(self):
        stdout = io.StringIO()
        with patch.object(production, "load_backend_factory", return_value=self.backend), redirect_stdout(stdout):
            code = production.main(self.cli_arguments())
        summary = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(summary["execution_counts"]["complete_candidate_tasks"], 1)
        self.assertEqual(summary["execution_counts"]["t1_report_tasks"], 1)
        self.assertEqual(summary["finalized"], 0)

    def test_cli_manual_review_is_not_success_in_opt_in_strict_mode(self):
        stdout = io.StringIO()
        with patch.object(production, "load_backend_factory", return_value=self.backend), redirect_stdout(stdout):
            code = production.main(self.cli_arguments() + ["--require-all-finalized"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stdout.getvalue())["manual_review"], 1)

    def test_cli_refuses_identity_change_before_artifact_publication(self):
        invoke = self.backend.invoke
        def changed(request):
            response = invoke(request)
            self.backend.model_id = "changed-during-invocation"
            return response
        self.backend.invoke = changed
        stdout = io.StringIO()
        with patch.object(production, "load_backend_factory", return_value=self.backend), redirect_stdout(stdout):
            code = production.main(self.cli_arguments())
        self.assertEqual(code, 2)
        self.assertFalse((self.fixture.root / "output").exists())

    def test_cli_rejects_bad_limits_before_loading_backend(self):
        arguments = self.cli_arguments() + ["--max-llm-calls", "-1"]
        with patch.object(production, "load_backend_factory") as loading, redirect_stdout(io.StringIO()):
            code = production.main(arguments)
        self.assertEqual(code, 2)
        loading.assert_not_called()

    def test_production_cli_does_not_accept_answer_registry(self):
        with redirect_stderr(io.StringIO()), patch.object(production, "load_backend_factory") as loading:
            with self.assertRaises(SystemExit) as stopped:
                production.main(self.cli_arguments() + ["--replay-responses", "answers.json"])
        self.assertEqual(stopped.exception.code, 2)
        loading.assert_not_called()


if __name__ == "__main__":
    unittest.main()
