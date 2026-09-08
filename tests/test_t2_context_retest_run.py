"""Wrapper routing tests; no credentials, provider, or real run directory writes."""
import unittest
from unittest.mock import patch

from scripts import run_t2_context_retest_v1 as runner


class ContextRetestWrapperTests(unittest.TestCase):
    def test_shared_configuration_restored_after_success_and_error(self):
        original = runner.engine.RUN, runner.engine.MANIFEST_SHA256
        for fail in (False, True):
            try:
                with runner.configured_engine():
                    self.assertEqual(runner.engine.RUN, runner.RUN)
                    self.assertEqual(runner.engine.MANIFEST_SHA256, runner.MANIFEST_SHA256)
                    if fail:
                        raise RuntimeError("synthetic")
            except RuntimeError:
                pass
            self.assertEqual((runner.engine.RUN, runner.engine.MANIFEST_SHA256), original)

    def test_run_without_cap_never_reaches_shared_runner(self):
        with patch.object(runner.engine, "main") as run, patch.object(runner, "verify_frozen_profile") as verify, patch.object(runner.engine, "emit"):
            self.assertEqual(runner.main(["run"]), 2)
        run.assert_not_called()
        verify.assert_not_called()

    def test_check_does_not_require_or_start_a_paid_run(self):
        with patch.object(runner.engine, "main", return_value=0) as run, patch.object(runner, "verify_frozen_profile") as verify:
            self.assertEqual(runner.main(["check"]), 0)
        verify.assert_called_once_with(for_run=False)
        run.assert_called_once_with(["check"])

    def test_confirmed_run_still_requires_frozen_wrapper_check(self):
        with patch.object(runner.engine, "main", return_value=0) as run, patch.object(runner, "verify_frozen_profile") as verify:
            self.assertEqual(runner.main(["run", "--confirm-platform-cap"]), 0)
        verify.assert_called_once_with(for_run=True)
        run.assert_called_once_with(["run"])

    def test_preflight_failure_does_not_start_shared_runner(self):
        with patch.object(runner.engine, "main") as run, patch.object(runner, "verify_frozen_profile", side_effect=ValueError("synthetic")), patch.object(runner.engine, "emit"):
            self.assertEqual(runner.main(["run", "--confirm-platform-cap"]), 2)
        run.assert_not_called()

    def test_factory_delegates_only_to_the_in_memory_backend(self):
        marker = object()
        with patch.object(runner.engine, "backend_factory", return_value=marker) as factory:
            self.assertIs(runner.backend_factory(), marker)
        factory.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
