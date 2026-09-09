"""No credentials or HTTP: v5 diagnostic authorization and frozen plan checks."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_t2_context_retest_v3 as runner


class ContextRetestV3Tests(unittest.TestCase):
    def test_reuses_tested_guard_without_changing_historical_run_paths(self):
        self.assertNotEqual(runner.RUN, runner.previous.RUN)
        self.assertEqual(runner.BASE, runner.previous.RUN)
        self.assertEqual(runner.SETTINGS.timeout_seconds, 300)
        self.assertEqual(runner.adapter.DeepSeekSettings().timeout_seconds, 120)
        self.assertEqual(runner.TASKS, runner.previous.TASKS)
        self.assertEqual(runner.adapter.PROMPT_VERSION, "t2-json-v5")

    def test_check_has_no_credential_read_or_run(self):
        with patch.object(runner, "preflight", return_value={"provider_calls": 0}) as check, \
                patch.object(runner.getpass, "getpass") as key, patch.object(runner, "run") as run, \
                patch.object(runner, "emit"):
            self.assertEqual(runner.main(["check"]), 0)
        check.assert_called_once_with()
        key.assert_not_called()
        run.assert_not_called()

    def test_run_needs_both_current_confirmations_and_digest(self):
        variants = [[], ["--confirm-paid-retest"], ["--confirm-platform-cap"],
                    ["--confirm-paid-retest", "--confirm-platform-cap"]]
        with patch.object(runner, "run") as run, patch.object(runner.getpass, "getpass") as key, \
                patch.object(runner, "emit"):
            for flags in variants:
                self.assertEqual(runner.main(["run", *flags]), 2)
        run.assert_not_called()
        key.assert_not_called()

    def test_confirmed_run_preserves_digest_and_exit_status(self):
        with patch.object(runner, "run", return_value=1) as run:
            self.assertEqual(runner.main(["run", "--confirm-paid-retest", "--confirm-platform-cap",
                                        "--expected-manifest-sha256", "a" * 64]), 1)
        run.assert_called_once_with("a" * 64)

    def test_manifest_mismatch_precedes_intent_and_key_read(self):
        with patch.object(runner, "read_bytes", return_value=b"{}"), \
                patch.object(runner.getpass, "getpass") as key, patch.object(runner, "put_new") as write:
            with self.assertRaisesRegex(ValueError, "digest_mismatch"):
                runner.run("a" * 64)
        key.assert_not_called()
        write.assert_not_called()

    def test_existing_preparation_is_preserved_without_reading(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(runner, "RUN", Path(temp)), \
                patch.object(runner, "build_plan") as build:
            with self.assertRaisesRegex(ValueError, "existing_preparation"):
                runner.prepare()
        build.assert_not_called()

    def test_old_baseline_hash_change_is_rejected(self):
        with patch.object(runner, "read_bytes", return_value=b"{}"):
            with self.assertRaisesRegex(ValueError, "baseline_manifest_changed"):
                runner.build_plan()

    def test_any_frozen_plan_change_is_rejected_before_git(self):
        base = dict(budget_cny=20, max_total_http_requests=6, model={"timeout_seconds": 300})
        for mutation in ({"budget_cny": 21}, {"max_total_http_requests": 7},
                         {"model": {"timeout_seconds": 120}}, {"extra": "unexpected"}):
            changed = {**deepcopy(base), **mutation}
            with self.subTest(mutation=mutation), patch.object(runner, "read_bytes", return_value=runner.wire(changed)), \
                    patch.object(runner, "build_plan", return_value=base), patch.object(runner, "git") as git:
                with self.assertRaisesRegex(ValueError, "profile_changed"):
                    runner.preflight()
            git.assert_not_called()

    def test_duplicate_run_stops_before_input_reads_and_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "run-start.json").write_bytes(b"existing")
            plan = {"synthetic": "plan"}
            def git(*args):
                if args[:2] == ("branch", "--show-current"):
                    return b"codex/b-v2-source-discovery\n"
                if args[:2] == ("rev-parse", "HEAD:vulngym_agent"):
                    return runner.RUNTIME_TREE.encode()
                return runner.wire(plan)
            with patch.object(runner, "RUN", root), patch.object(runner, "read_bytes", return_value=runner.wire(plan)), \
                    patch.object(runner, "build_plan", return_value=plan), patch.object(runner, "git", side_effect=git), \
                    patch.object(runner.previous, "checked_input") as inputs, patch.object(runner.getpass, "getpass") as key:
                with self.assertRaisesRegex(ValueError, "existing_run"):
                    runner.preflight(for_run=True)
            inputs.assert_not_called()
            key.assert_not_called()

    def test_backend_factory_never_initializes_or_loads_credentials(self):
        with patch.object(runner, "_backend", None), patch.object(runner.getpass, "getpass") as key:
            with self.assertRaisesRegex(RuntimeError, "not_initialized"):
                runner.backend_factory()
        key.assert_not_called()


if __name__ == "__main__":
    unittest.main()
