from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import subprocess
import sys
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

    def test_repository_store_help_states_complete_union_contract(self) -> None:
        for command in ("prepare", "verify"):
            with self.subTest(command=command):
                standard_output = StringIO()
                with redirect_stdout(standard_output), self.assertRaises(
                    SystemExit
                ) as captured:
                    source_acquisition_cli.main([command, "--help"])
                self.assertEqual(captured.exception.code, 0)
                help_text = " ".join(standard_output.getvalue().split())
                self.assertIn(
                    "single split runs require an independent store", help_text
                )
                self.assertIn(
                    "same complete test+train union and exact digest pins",
                    help_text,
                )
                self.assertIn(
                    "cannot prove prior store-use history",
                    help_text,
                )

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

    def test_verify_stdout_control_flow_failures_are_stable_io_failures(self) -> None:
        class FatalOutput(BaseException):
            pass

        arguments = self._argv()
        arguments[0] = "verify"
        for failure in (
            BrokenPipeError("closed stdout"),
            KeyboardInterrupt(),
            FatalOutput(),
        ):
            with self.subTest(failure=type(failure).__name__):
                standard_error = StringIO()
                with (
                    mock.patch.object(
                        source_acquisition_cli,
                        "verify_source_acquisition",
                        return_value=_summary(ready=True),
                    ),
                    mock.patch.object(
                        source_acquisition_cli,
                        "_print_json",
                        side_effect=failure,
                    ),
                    redirect_stderr(standard_error),
                ):
                    status = source_acquisition_cli.main(arguments)
                self.assertEqual(5, status)
                self.assertEqual(
                    "error[io_failed]: source acquisition command failed\n",
                    standard_error.getvalue(),
                )
                self.assertNotIn("C:/trusted", standard_error.getvalue())

    def test_failed_injected_stdout_is_detached_but_not_closed(self) -> None:
        class FlushFailureStringIO(StringIO):
            def flush(self) -> None:
                raise BrokenPipeError("closed stdout")

        expected_errors = {
            "prepare": (
                "error[publication_uncertain]: "
                "source acquisition output may be committed\n"
            ),
            "verify": "error[io_failed]: source acquisition command failed\n",
        }
        for command, expected_error in expected_errors.items():
            with self.subTest(command=command):
                output = FlushFailureStringIO()
                standard_error = StringIO()
                arguments = self._argv()
                arguments[0] = command
                operation = (
                    "prepare_source_acquisition"
                    if command == "prepare"
                    else "verify_source_acquisition"
                )
                with (
                    mock.patch.object(
                        source_acquisition_cli,
                        operation,
                        return_value=_summary(ready=True),
                    ),
                    mock.patch.object(sys, "stdout", output),
                    redirect_stderr(standard_error),
                ):
                    status = source_acquisition_cli.main(arguments)
                    self.assertIsNone(sys.stdout)

                self.assertEqual(5, status)
                self.assertFalse(output.closed)
                self.assertEqual(expected_error, standard_error.getvalue())

    def test_closed_stdout_pipe_has_stable_process_exit_status(self) -> None:
        child_code = """
import sys
from unittest import mock

from vulngym_agent import source_acquisition_cli

command = sys.argv[1]
summary = type(
    "Summary",
    (),
    {"ready": True, "to_dict": lambda self: {"ok": True}},
)()
operation = (
    "prepare_source_acquisition"
    if command == "prepare"
    else "verify_source_acquisition"
)
mock.patch.object(
    source_acquisition_cli,
    operation,
    return_value=summary,
).start()
arguments = [
    command,
    "--repository-store", "sensitive-repository-store",
    "--output-dir", "sensitive-output-dir",
    "--git-executable", "sensitive-git",
    "--test-task-export-dir", "sensitive-task-export",
    "--test-expected-tasks-sha256", "a" * 64,
]

# The parent closes its stdout reader before releasing this one-byte gate.
sys.stdin.buffer.read(1)
raise SystemExit(source_acquisition_cli.main(arguments))
"""
        repository_root = Path(__file__).resolve().parents[1]
        expected_errors = {
            "prepare": (
                "error[publication_uncertain]: "
                "source acquisition output may be committed"
            ),
            "verify": "error[io_failed]: source acquisition command failed",
        }

        for command, expected_error in expected_errors.items():
            with self.subTest(command=command):
                process = subprocess.Popen(
                    [sys.executable, "-B", "-c", child_code, command],
                    cwd=repository_root,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertIsNotNone(process.stdin)
                self.assertIsNotNone(process.stdout)
                self.assertIsNotNone(process.stderr)
                assert process.stdin is not None
                assert process.stdout is not None
                assert process.stderr is not None
                process.stdout.close()
                process.stdin.write(b"1")
                process.stdin.close()
                status = process.wait(timeout=30)
                error = process.stderr.read().decode("utf-8", errors="strict")
                process.stderr.close()

                self.assertEqual(5, status)
                self.assertEqual([expected_error], error.splitlines())
                self.assertNotIn(str(repository_root), error)
                self.assertNotIn("sensitive-", error)

    def test_keyboard_interrupt_before_prepare_commit_is_preserved(self) -> None:
        with mock.patch.object(
            source_acquisition_cli,
            "prepare_source_acquisition",
            side_effect=KeyboardInterrupt,
        ), self.assertRaises(KeyboardInterrupt):
            source_acquisition_cli.main(self._argv())


if __name__ == "__main__":
    unittest.main()
