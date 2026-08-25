from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import unittest
from unittest import mock

from vulngym_agent.benchmark.source_acquisition import (
    AcquiredSourceMapSummary,
    SOURCE_NOT_READY_EXIT_STATUS,
    SourceAcquisitionError,
    SourceAcquisitionSummary,
)
from vulngym_agent import source_acquisition_cli


DIGEST = "a" * 64
REPORT_DIGEST = "b" * 64
MAP_DIGEST = "c" * 64


def _summary(*, ready: bool) -> SourceAcquisitionSummary:
    return SourceAcquisitionSummary(
        github_transport="https",
        repository_count=1,
        task_count=20,
        ready=ready,
        ready_task_count=20 if ready else 19,
        blocked_task_count=0 if ready else 1,
        acquisition_report_sha256=REPORT_DIGEST,
        source_maps=(
            AcquiredSourceMapSummary(
                split="test",
                task_count=20,
                tasks_sha256=DIGEST,
                source_map_sha256=MAP_DIGEST,
            ),
        ),
    )


class SourceAcquisitionCliTests(unittest.TestCase):
    def _argv(self, *extra: str) -> list[str]:
        return [
            "prepare",
            "--repository-store",
            str(Path("C:/trusted/repos")),
            "--output-dir",
            str(Path("C:/trusted/controls")),
            "--git-executable",
            str(Path("C:/trusted/git.exe")),
            "--test-task-export-dir",
            str(Path("C:/trusted/test-export")),
            "--test-expected-tasks-sha256",
            DIGEST,
            *extra,
        ]

    def test_prepare_prints_canonical_summary_and_returns_ready_status(self) -> None:
        standard_output = StringIO()
        with mock.patch.object(
            source_acquisition_cli,
            "prepare_source_acquisition",
            return_value=_summary(ready=True),
        ) as operation, redirect_stdout(standard_output):
            status = source_acquisition_cli.main(self._argv())
        self.assertEqual(status, 0)
        self.assertIn('"ready":true', standard_output.getvalue())
        call = operation.call_args
        self.assertEqual(call.kwargs["github_transport"], "https")
        self.assertIsNone(call.kwargs["ssh_executable"])
        self.assertEqual(len(call.args[0]), 1)

    def test_policy_blocked_sources_publish_summary_but_return_not_ready(self) -> None:
        standard_output = StringIO()
        with mock.patch.object(
            source_acquisition_cli,
            "prepare_source_acquisition",
            return_value=_summary(ready=False),
        ), redirect_stdout(standard_output):
            status = source_acquisition_cli.main(self._argv())
        self.assertEqual(status, SOURCE_NOT_READY_EXIT_STATUS)
        self.assertIn('"blocked_task_count":1', standard_output.getvalue())
        self.assertIn('"ready":false', standard_output.getvalue())

    def test_ssh_transport_requires_explicit_executable(self) -> None:
        standard_error = StringIO()
        with redirect_stderr(standard_error):
            status = source_acquisition_cli.main(
                self._argv("--github-transport", "ssh")
            )
        self.assertEqual(status, 2)
        self.assertEqual(
            standard_error.getvalue(),
            "error[input_rejected]: source acquisition command rejected its inputs\n",
        )

    def test_task_export_path_and_digest_are_atomic_inputs(self) -> None:
        argv = self._argv()
        argv = argv[:-2]
        standard_error = StringIO()
        with redirect_stderr(standard_error):
            status = source_acquisition_cli.main(argv)
        self.assertEqual(status, 2)
        self.assertIn("input_rejected", standard_error.getvalue())

    def test_structured_failure_does_not_disclose_exception_details(self) -> None:
        standard_error = StringIO()
        error = SourceAcquisitionError(
            "git_command_failed",
            "secret path and remote diagnostic",
            exit_status=3,
        )
        with mock.patch.object(
            source_acquisition_cli,
            "prepare_source_acquisition",
            side_effect=error,
        ), redirect_stderr(standard_error):
            status = source_acquisition_cli.main(self._argv())
        self.assertEqual(status, 3)
        self.assertEqual(
            standard_error.getvalue(),
            "error[git_command_failed]: source acquisition command failed\n",
        )
        self.assertNotIn("secret", standard_error.getvalue())

    def test_prepare_stdout_failure_is_committed_uncertain(self) -> None:
        for failure in (OSError("closed stdout"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                standard_error = StringIO()
                with mock.patch.object(
                    source_acquisition_cli,
                    "prepare_source_acquisition",
                    return_value=_summary(ready=True),
                ), mock.patch.object(
                    source_acquisition_cli,
                    "_print_json",
                    side_effect=failure,
                ), redirect_stderr(standard_error):
                    status = source_acquisition_cli.main(self._argv())
                self.assertEqual(status, 5)
                self.assertEqual(
                    standard_error.getvalue(),
                    "error[publication_uncertain]: source acquisition output may be committed\n",
                )

    def test_keyboard_interrupt_before_prepare_commit_is_preserved(self) -> None:
        with mock.patch.object(
            source_acquisition_cli,
            "prepare_source_acquisition",
            side_effect=KeyboardInterrupt,
        ), self.assertRaises(KeyboardInterrupt):
            source_acquisition_cli.main(self._argv())


if __name__ == "__main__":
    unittest.main()
