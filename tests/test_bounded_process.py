from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import vulngym_agent.evaluator.bounded_process as bounded_module
from vulngym_agent.evaluator.bounded_process import (
    BoundedProcessError,
    run_bounded_process_v1,
)


class BoundedProcessTests(unittest.TestCase):
    @staticmethod
    def _python(source: str, stdin: bytes = b"", **overrides):
        arguments = {
            "stdout_max_bytes": 1024 * 1024,
            "stderr_max_bytes": 1024 * 1024,
            "timeout_seconds": 10.0,
        }
        arguments.update(overrides)
        return run_bounded_process_v1(
            (sys.executable, "-I", "-B", "-c", source),
            stdin,
            **arguments,
        )

    def test_roundtrip_stdin_and_concurrent_streams(self) -> None:
        payload = b"x" * (512 * 1024)
        result = self._python(
            "import sys; data=sys.stdin.buffer.read(); "
            "sys.stderr.buffer.write(b'e'*400000); "
            "sys.stdout.buffer.write(data)",
            payload,
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, payload)
        self.assertEqual(result.stderr, b"e" * 400000)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.stdout_overflow)
        self.assertFalse(result.stderr_overflow)

    def test_stdout_overflow_is_bounded_and_terminates(self) -> None:
        result = self._python(
            "import os,time; os.write(1,b'x'*1000000); time.sleep(30)",
            stdout_max_bytes=4096,
        )
        self.assertEqual(len(result.stdout), 4096)
        self.assertTrue(result.stdout_overflow)
        self.assertFalse(result.timed_out)

    def test_stderr_overflow_is_bounded(self) -> None:
        result = self._python(
            "import os; os.write(2,b'y'*100000)", stderr_max_bytes=17
        )
        self.assertEqual(result.stderr, b"y" * 17)
        self.assertTrue(result.stderr_overflow)

    def test_timeout_terminates_descendant_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "late.txt"
            child_source = (
                "import pathlib,time; time.sleep(2); "
                f"pathlib.Path({str(marker)!r}).write_text('late')"
            )
            parent_source = (
                "import subprocess,sys,time; "
                f"subprocess.Popen((sys.executable,'-I','-B','-c',{child_source!r})); "
                "time.sleep(30)"
            )
            result = self._python(parent_source, timeout_seconds=0.25)
            self.assertTrue(result.timed_out)
            time.sleep(2.2)
            self.assertFalse(marker.exists())

    def test_interrupt_while_initialising_deadline_terminates_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "late.txt"
            child_source = (
                "import pathlib,time; time.sleep(1); "
                f"pathlib.Path({str(marker)!r}).write_text('late')"
            )
            parent_source = (
                "import subprocess,sys,time; "
                f"subprocess.Popen((sys.executable,'-I','-B','-c',{child_source!r})); "
                "time.sleep(30)"
            )

            def interrupt_after_child_can_start() -> float:
                time.sleep(0.25)
                raise KeyboardInterrupt

            with mock.patch.object(
                bounded_module.time,
                "monotonic",
                side_effect=interrupt_after_child_can_start,
            ), self.assertRaises(KeyboardInterrupt):
                self._python(parent_source)
            time.sleep(1.2)
            self.assertFalse(marker.exists())

    def test_exited_leader_does_not_leave_background_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "orphan.txt"
            child_source = (
                "import pathlib,time; time.sleep(1); "
                f"pathlib.Path({str(marker)!r}).write_text('orphan')"
            )
            parent_source = (
                "import subprocess,sys; "
                f"subprocess.Popen((sys.executable,'-I','-B','-c',{child_source!r}))"
            )
            result = self._python(parent_source)
            self.assertEqual(result.exit_code, 0)
            time.sleep(1.2)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "nt", "requires Windows suspended creation")
    def test_windows_child_cannot_run_before_job_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "started.txt"
            entered = threading.Event()
            release = threading.Event()
            results = []
            failures: list[BaseException] = []
            original = bounded_module._WindowsKillJob.assign_and_resume

            def delayed_assign(job, process) -> None:
                entered.set()
                if not release.wait(timeout=5):
                    raise OSError("test did not release suspended process")
                original(job, process)

            def invoke() -> None:
                try:
                    results.append(
                        self._python(
                            "import pathlib; "
                            f"pathlib.Path({str(marker)!r}).write_text('started')"
                        )
                    )
                except BaseException as error:
                    failures.append(error)

            with mock.patch.object(
                bounded_module._WindowsKillJob,
                "assign_and_resume",
                new=delayed_assign,
            ):
                thread = threading.Thread(target=invoke, daemon=True)
                thread.start()
                try:
                    self.assertTrue(entered.wait(timeout=5))
                    time.sleep(0.25)
                    self.assertFalse(marker.exists())
                finally:
                    release.set()
                    thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].exit_code, 0)
            self.assertTrue(marker.exists())

    def test_rejects_shell_like_or_unbounded_inputs(self) -> None:
        with self.assertRaises(BoundedProcessError):
            run_bounded_process_v1(
                [sys.executable],  # type: ignore[arg-type]
                stdout_max_bytes=1,
                stderr_max_bytes=1,
                timeout_seconds=1,
            )
        with self.assertRaises(BoundedProcessError):
            run_bounded_process_v1(
                (sys.executable,),
                stdout_max_bytes=-1,
                stderr_max_bytes=1,
                timeout_seconds=1,
            )
        with self.assertRaises(BoundedProcessError):
            run_bounded_process_v1(
                (sys.executable,),
                stdout_max_bytes=1,
                stderr_max_bytes=1,
                timeout_seconds=True,  # type: ignore[arg-type]
            )
        with self.assertRaises(BoundedProcessError):
            run_bounded_process_v1(
                (sys.executable,),
                stdout_max_bytes=1,
                stderr_max_bytes=1,
                timeout_seconds=1,
                executable="",
            )
        with self.assertRaises(BoundedProcessError):
            run_bounded_process_v1(
                (sys.executable,),
                stdout_max_bytes=1,
                stderr_max_bytes=1,
                timeout_seconds=1,
                inherited_fds=(0,),
            )

    @unittest.skipUnless(
        os.name == "posix" and Path("/proc/self/fd").is_dir(),
        "requires a procfd-capable POSIX host",
    )
    def test_executable_override_runs_the_inherited_descriptor(self) -> None:
        executable = Path("/bin/echo").resolve()
        descriptor = os.open(executable, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            result = run_bounded_process_v1(
                ("untrusted-path-was-not-used", "bound-by-fd"),
                stdout_max_bytes=1024,
                stderr_max_bytes=1024,
                timeout_seconds=10,
                executable=f"/proc/self/fd/{descriptor}",
                inherited_fds=(descriptor,),
            )
        finally:
            os.close(descriptor)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, b"bound-by-fd\n")
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
