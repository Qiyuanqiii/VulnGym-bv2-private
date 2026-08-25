"""Bounded subprocess transport used by the trusted OCI provider.

The helper deliberately accepts only an argv tuple and never invokes a shell.
It drains stdout and stderr concurrently, retains at most the configured byte
limits, and tears down the process tree on timeout, overflow, interruption, or
an internal pump failure.  Container cleanup is still the caller's duty: a
terminated Docker CLI process does not imply that its daemon-side container
was removed.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from typing import Final, Mapping


PROCESS_TRANSPORT_VERSION: Final[str] = "bounded-subprocess-transport-v1"
_CHUNK_BYTES: Final[int] = 64 * 1024
_MAX_STREAM_BYTES: Final[int] = 64 * 1024 * 1024
_MAX_STDIN_BYTES: Final[int] = 64 * 1024 * 1024
_MAX_TIMEOUT_SECONDS: Final[float] = 7200.0
_WINDOWS_CREATE_SUSPENDED: Final[int] = 0x00000004


class BoundedProcessError(RuntimeError):
    """Stable error raised before a bounded child can be executed safely."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "process_failed"
        super().__init__(message)


class _WindowsKillJob:
    """A non-inheritable Job Object that owns one suspended process tree."""

    __slots__ = ("_handle", "_lock")

    def __init__(self, handle: int) -> None:
        self._handle = handle
        self._lock = threading.Lock()

    @classmethod
    def create(cls) -> "_WindowsKillJob":
        if sys.platform != "win32":
            raise OSError("Windows Job Objects are unavailable")
        import ctypes
        from ctypes import wintypes

        class _IoCounters(ctypes.Structure):
            _fields_ = (
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            )

        class _BasicLimitInformation(ctypes.Structure):
            _fields_ = (
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            )

        class _ExtendedLimitInformation(ctypes.Structure):
            _fields_ = (
                ("BasicLimitInformation", _BasicLimitInformation),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            )

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_job = kernel32.CreateJobObjectW
        create_job.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        create_job.restype = wintypes.HANDLE
        set_information = kernel32.SetInformationJobObject
        set_information.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        set_information.restype = wintypes.BOOL
        handle = create_job(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        information = _ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = 0x00002000
        if not set_information(
            handle,
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            error = ctypes.get_last_error()
            kernel32.CloseHandle(handle)
            raise ctypes.WinError(error)
        return cls(int(handle))

    def assign_and_resume(self, process: subprocess.Popen[bytes]) -> None:
        import ctypes
        from ctypes import wintypes

        with self._lock:
            handle = self._handle
        if handle < 0:
            raise OSError("Windows Job Object is unavailable")
        process_handle = wintypes.HANDLE(int(process._handle))
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        assign = kernel32.AssignProcessToJobObject
        assign.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        assign.restype = wintypes.BOOL
        if not assign(wintypes.HANDLE(handle), process_handle):
            raise ctypes.WinError(ctypes.get_last_error())
        resume = ctypes.WinDLL("ntdll").NtResumeProcess
        resume.argtypes = (wintypes.HANDLE,)
        resume.restype = wintypes.LONG
        if resume(process_handle) != 0:
            raise OSError("suspended Windows process could not be resumed")

    def terminate(self) -> None:
        import ctypes
        from ctypes import wintypes

        with self._lock:
            handle = self._handle
        if handle < 0:
            return
        terminate = ctypes.WinDLL(
            "kernel32", use_last_error=True
        ).TerminateJobObject
        terminate.argtypes = (wintypes.HANDLE, wintypes.UINT)
        terminate.restype = wintypes.BOOL
        if not terminate(wintypes.HANDLE(handle), 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        import ctypes
        from ctypes import wintypes

        with self._lock:
            handle = self._handle
            self._handle = -1
        if handle >= 0:
            close_handle = ctypes.WinDLL(
                "kernel32", use_last_error=True
            ).CloseHandle
            close_handle.argtypes = (wintypes.HANDLE,)
            close_handle.restype = wintypes.BOOL
            close_handle(wintypes.HANDLE(handle))

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass


@dataclass(frozen=True, slots=True)
class BoundedProcessResultV1:
    """Terminal, size-bounded observation of one child process."""

    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_overflow: bool
    stderr_overflow: bool

    def __post_init__(self) -> None:
        if (
            type(self.exit_code) is not int
            or type(self.stdout) is not bytes
            or type(self.stderr) is not bytes
            or type(self.timed_out) is not bool
            or type(self.stdout_overflow) is not bool
            or type(self.stderr_overflow) is not bool
        ):
            raise TypeError("bounded process result fields have invalid exact types")


def _validate_arguments(
    argv: object,
    stdin: object,
    *,
    stdout_max_bytes: object,
    stderr_max_bytes: object,
    timeout_seconds: object,
    env: object,
    cwd: object,
    executable: object,
    inherited_fds: object,
) -> tuple[
    tuple[str, ...],
    bytes,
    dict[str, str] | None,
    str | None,
    str | None,
    tuple[int, ...],
]:
    if (
        type(argv) is not tuple
        or not argv
        or any(type(item) is not str or not item or "\x00" in item for item in argv)
    ):
        raise BoundedProcessError("invalid_argument", "process argv is invalid")
    if type(stdin) is not bytes or len(stdin) > _MAX_STDIN_BYTES:
        raise BoundedProcessError("invalid_argument", "process stdin is invalid")
    for value, name in (
        (stdout_max_bytes, "stdout_max_bytes"),
        (stderr_max_bytes, "stderr_max_bytes"),
    ):
        if type(value) is not int or not 0 <= value <= _MAX_STREAM_BYTES:
            raise BoundedProcessError("invalid_argument", f"{name} is invalid")
    if (
        type(timeout_seconds) not in {int, float}
        or isinstance(timeout_seconds, bool)
        or not 0 < float(timeout_seconds) <= _MAX_TIMEOUT_SECONDS
    ):
        raise BoundedProcessError("invalid_argument", "process timeout is invalid")
    normalized_env: dict[str, str] | None
    if env is None:
        normalized_env = None
    elif type(env) is dict and all(
        type(key) is str
        and key
        and "\x00" not in key
        and "=" not in key
        and type(value) is str
        and "\x00" not in value
        for key, value in env.items()
    ):
        normalized_env = dict(env)
    else:
        raise BoundedProcessError("invalid_argument", "process environment is invalid")
    normalized_cwd: str | None
    if cwd is None:
        normalized_cwd = None
    elif type(cwd) in {str, type(Path())}:
        try:
            normalized_cwd = os.fspath(cwd)
        except (TypeError, ValueError):
            raise BoundedProcessError(
                "invalid_argument", "process working directory is invalid"
            ) from None
        if not normalized_cwd or "\x00" in normalized_cwd:
            raise BoundedProcessError(
                "invalid_argument", "process working directory is invalid"
            )
    else:
        raise BoundedProcessError(
            "invalid_argument", "process working directory is invalid"
        )
    normalized_executable: str | None
    if executable is None:
        normalized_executable = None
    elif type(executable) in {str, type(Path())}:
        try:
            normalized_executable = os.fspath(executable)
        except (TypeError, ValueError):
            raise BoundedProcessError(
                "invalid_argument", "process executable override is invalid"
            ) from None
        if not normalized_executable or "\x00" in normalized_executable:
            raise BoundedProcessError(
                "invalid_argument", "process executable override is invalid"
            )
    else:
        raise BoundedProcessError(
            "invalid_argument", "process executable override is invalid"
        )
    if (
        type(inherited_fds) is not tuple
        or any(
            type(descriptor) is not int or descriptor < 0
            for descriptor in inherited_fds
        )
        or len(set(inherited_fds)) != len(inherited_fds)
        or (inherited_fds and os.name != "posix")
        or (inherited_fds and normalized_executable is None)
    ):
        raise BoundedProcessError(
            "invalid_argument", "process inherited descriptors are invalid"
        )
    for descriptor in inherited_fds:
        try:
            os.fstat(descriptor)
        except OSError:
            raise BoundedProcessError(
                "invalid_argument", "process inherited descriptor is unavailable"
            ) from None
    return (
        argv,
        stdin,
        normalized_env,
        normalized_cwd,
        normalized_executable,
        inherited_fds,
    )


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    *,
    windows_job: _WindowsKillJob | None = None,
) -> None:
    """Best-effort termination restricted to the just-created process tree."""

    if os.name == "posix":
        # The session leader may have exited while a descendant still owns an
        # output pipe.  Its original process group remains addressable by the
        # leader PID, so signal it even after Popen.poll() becomes terminal.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
        return
    if windows_job is not None:
        try:
            windows_job.terminate()
        except OSError:
            pass
    if process.poll() is not None:
        return
    # The Job Object is authoritative. taskkill remains a bounded fallback for
    # a platform failure after the process was created.
    taskkill: str | None = None
    if sys.platform == "win32":
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(32768)
            count = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
            if 0 < count < len(buffer):
                candidate = os.path.join(buffer.value, "taskkill.exe")
                if os.path.isabs(candidate):
                    taskkill = candidate
        except (AttributeError, OSError, ValueError):
            taskkill = None
    try:
        if taskkill is not None:
            subprocess.run(
                (taskkill, "/PID", str(process.pid), "/T", "/F"),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
                shell=False,
            )
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        process.kill()
    except OSError:
        pass


def run_bounded_process_v1(
    argv: tuple[str, ...],
    stdin: bytes = b"",
    *,
    stdout_max_bytes: int,
    stderr_max_bytes: int,
    timeout_seconds: float,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
    executable: str | Path | None = None,
    inherited_fds: tuple[int, ...] = (),
) -> BoundedProcessResultV1:
    """Run one shell-free child while concurrently bounding both output pipes."""

    (
        checked_argv,
        checked_stdin,
        checked_env,
        checked_cwd,
        checked_executable,
        checked_inherited_fds,
    ) = _validate_arguments(
        argv,
        stdin,
        stdout_max_bytes=stdout_max_bytes,
        stderr_max_bytes=stderr_max_bytes,
        timeout_seconds=timeout_seconds,
        env=env,
        cwd=cwd,
        executable=executable,
        inherited_fds=inherited_fds,
    )
    creationflags = 0
    popen_arguments: dict[str, object] = {}
    windows_job: _WindowsKillJob | None = None
    if os.name == "posix":
        popen_arguments["start_new_session"] = True
        if checked_inherited_fds:
            popen_arguments["pass_fds"] = checked_inherited_fds
    else:
        try:
            windows_job = _WindowsKillJob.create()
        except OSError as error:
            raise BoundedProcessError(
                "process_start_failed", "Windows process containment is unavailable"
            ) from error
        creationflags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | _WINDOWS_CREATE_SUSPENDED
        )
    if checked_executable is not None:
        popen_arguments["executable"] = checked_executable
    try:
        process = subprocess.Popen(
            checked_argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=checked_cwd,
            env=checked_env,
            shell=False,
            creationflags=creationflags,
            **popen_arguments,
        )
    except (OSError, ValueError) as error:
        if windows_job is not None:
            windows_job.close()
        raise BoundedProcessError(
            "process_start_failed", "bounded child process could not be started"
        ) from error

    if windows_job is not None:
        try:
            windows_job.assign_and_resume(process)
        except OSError as error:
            _terminate_process_tree(process, windows_job=windows_job)
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                pass
            windows_job.close()
            raise BoundedProcessError(
                "process_start_failed", "Windows process containment could not start"
            ) from error

    if process.stdin is None or process.stdout is None or process.stderr is None:
        _terminate_process_tree(process, windows_job=windows_job)
        if windows_job is not None:
            windows_job.close()
        raise BoundedProcessError(
            "process_start_failed", "bounded child pipes were not created"
        )

    overflow = threading.Event()
    pump_failed = threading.Event()
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    stdout_state = [False]
    stderr_state = [False]

    def writer() -> None:
        try:
            view = memoryview(checked_stdin)
            sent = 0
            while sent < len(view):
                count = process.stdin.write(view[sent : sent + _CHUNK_BYTES])
                if count is None or count < 1:
                    raise OSError("short subprocess stdin write")
                sent += count
            process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            if process.poll() is None:
                pump_failed.set()
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    def reader(
        stream,
        retained: bytearray,
        limit: int,
        state: list[bool],
    ) -> None:
        try:
            while True:
                chunk = stream.read(_CHUNK_BYTES)
                if not chunk:
                    break
                available = max(0, limit - len(retained))
                if available:
                    retained.extend(chunk[:available])
                if len(chunk) > available:
                    state[0] = True
                    overflow.set()
        except (OSError, ValueError):
            pump_failed.set()
        finally:
            try:
                stream.close()
            except OSError:
                pass

    threads = (
        threading.Thread(target=writer, name="bounded-stdin", daemon=True),
        threading.Thread(
            target=reader,
            args=(process.stdout, stdout_buffer, stdout_max_bytes, stdout_state),
            name="bounded-stdout",
            daemon=True,
        ),
        threading.Thread(
            target=reader,
            args=(process.stderr, stderr_buffer, stderr_max_bytes, stderr_state),
            name="bounded-stderr",
            daemon=True,
        ),
    )
    timed_out = False
    interrupted = False
    started_threads: list[threading.Thread] = []
    try:
        for thread in threads:
            thread.start()
            started_threads.append(thread)
        deadline = time.monotonic() + float(timeout_seconds)
        while process.poll() is None:
            if overflow.is_set() or pump_failed.is_set():
                _terminate_process_tree(process, windows_job=windows_job)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process_tree(process, windows_job=windows_job)
                break
            try:
                process.wait(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired:
                pass
        _terminate_process_tree(process, windows_job=windows_job)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process, windows_job=windows_job)
            process.wait(timeout=5)
    except BaseException:
        interrupted = True
        _terminate_process_tree(process, windows_job=windows_job)
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
        raise
    finally:
        for thread in started_threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in started_threads):
            _terminate_process_tree(process, windows_job=windows_job)
            if not interrupted:
                pump_failed.set()
        if windows_job is not None:
            windows_job.close()

    if pump_failed.is_set() and not (stdout_state[0] or stderr_state[0]):
        raise BoundedProcessError(
            "process_transport_failed", "bounded child pipe transport failed"
        )
    return BoundedProcessResultV1(
        exit_code=int(process.returncode if process.returncode is not None else -1),
        stdout=bytes(stdout_buffer),
        stderr=bytes(stderr_buffer),
        timed_out=timed_out,
        stdout_overflow=stdout_state[0],
        stderr_overflow=stderr_state[0],
    )


__all__ = [
    "BoundedProcessError",
    "BoundedProcessResultV1",
    "PROCESS_TRANSPORT_VERSION",
    "run_bounded_process_v1",
]
