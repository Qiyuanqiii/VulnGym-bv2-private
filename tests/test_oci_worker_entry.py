from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from vulngym_agent.agents.model_runtime import ReplayResponse
from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.sealed_snapshot import prepare_sealed_snapshot
from vulngym_agent.benchmark.worker_handoff import build_worker_handoff
import vulngym_agent.evaluator.oci_worker_entry as entry_module
from vulngym_agent.evaluator.oci_worker_entry import (
    D2_REPLAY_FILENAME,
    D3_REPLAY_FILENAME,
    GenerationReceiptV1,
    HANDOFF_FILENAME,
    OciReplayConfigV1,
    OciWorkerEntryError,
    OciWorkerRequestV1,
    REQUEST_FILENAME,
)
from vulngym_agent.evaluator.worker import execute_discovery_worker_v1
from vulngym_agent.orchestrator.discovery_pipeline import SourceDiscoveryRunV1
from vulngym_agent.tools.git.repository import GitRepository


TASK_ID = "VG-TRAIN-0123456789ABCDEF0997"
REPO_URL = "https://github.com/example/oci-worker-entry"
KEY = b"oci worker entry test attestation key 0001"
KEY_ID = "oci-worker-entry-test"
SOURCE_PATH = "src/app.py"
SOURCE = (
    b"def entry(value):\n"
    b"    return critical(value)\n"
    b"def critical(value):\n"
    b"    return value\n"
)
DEFER_RESPONSE = {
    "action": "defer",
    "missing_information": ["source evidence"],
    "reason_code": "insufficient_source_evidence",
}


class _CaptureBackend:
    backend_id = "replay"
    model_id = "offline-v1"

    def __init__(self) -> None:
        self.requests = []

    def invoke(self, request):
        self.requests.append(request)
        return DEFER_RESPONSE


class _ForbiddenBackend:
    @property
    def backend_id(self):
        raise AssertionError("D3 must not be acquired after a D2 deferral")

    @property
    def model_id(self):
        raise AssertionError("D3 must not be acquired after a D2 deferral")

    def invoke(self, _request):
        raise AssertionError("D3 must not be acquired after a D2 deferral")


class OciWorkerEntryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repo"
        self.repository.mkdir()
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.name", "VulnGym Test")
        self._git("config", "user.email", "vulngym@example.invalid")
        self._git("config", "core.autocrlf", "false")
        (self.repository / "src").mkdir()
        (self.repository / SOURCE_PATH).write_bytes(SOURCE)
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "source")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()

        self.snapshot_root = self.root / "sealed"
        prepared = prepare_sealed_snapshot(
            GitRepository(self.repository),
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=self.commit,
            output_dir=self.snapshot_root,
            attestation_key=KEY,
            key_id=KEY_ID,
        )
        self.task = DiscoveryTaskInputV1(
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=self.commit,
            instruction_id=INSTRUCTION_ID,
            snapshot_manifest_sha256=prepared.manifest_sha256,
            snapshot_content_root=prepared.content_root,
        )
        self.handoff = build_worker_handoff(
            self.task,
            self.snapshot_root,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )
        self.handoff_wire = self.handoff.to_bytes()

        capture = _CaptureBackend()
        self.expected_run_wire = execute_discovery_worker_v1(
            self.handoff_wire,
            expected_handoff_sha256=self.handoff.handoff_sha256,
            expected_handoff_wire_sha256=self.handoff.wire_sha256,
            tree_root=self.snapshot_root / "tree",
            d2_backend=capture,
            d3_backend=_ForbiddenBackend(),
        )
        self.assertEqual(len(capture.requests), 1)
        captured_request = capture.requests[0]
        self.d2_config = OciReplayConfigV1(
            task_id=TASK_ID,
            role="d2",
            responses=(
                ReplayResponse(
                    stage=captured_request.stage,
                    request=captured_request.payload,
                    response=DEFER_RESPONSE,
                ),
            ),
        )
        self.d3_config = OciReplayConfigV1(
            task_id=TASK_ID,
            role="d3",
            responses=(),
        )
        self.request = OciWorkerRequestV1(
            task_id=TASK_ID,
            snapshot_id=self.task.snapshot_id,
            snapshot_manifest_sha256=self.task.snapshot_manifest_sha256,
            snapshot_content_root=self.task.snapshot_content_root,
            handoff_sha256=self.handoff.handoff_sha256,
            handoff_wire_sha256=self.handoff.wire_sha256,
            d2_replay_sha256=self.d2_config.config_sha256,
            d2_replay_wire_sha256=self.d2_config.wire_sha256,
            d3_replay_sha256=self.d3_config.config_sha256,
            d3_replay_wire_sha256=self.d3_config.wire_sha256,
        )
        self.input_runtime = self.root / "input-runtime"
        self.input_runtime.mkdir()
        self._write_runtime(self.input_runtime)
        self.generation = self.root / "generation"
        self.generation.mkdir()

    def tearDown(self) -> None:
        # Materialization intentionally makes the generation read-only.  Reset
        # local test permissions so Windows can remove the temporary tree.
        for path in sorted(
            self.root.rglob("*"), key=lambda value: len(value.parts), reverse=True
        ):
            try:
                os.chmod(path, 0o700)
            except OSError:
                pass
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _write_runtime(self, root: Path) -> None:
        (root / REQUEST_FILENAME).write_bytes(self.request.to_bytes())
        (root / HANDOFF_FILENAME).write_bytes(self.handoff_wire)
        (root / D2_REPLAY_FILENAME).write_bytes(self.d2_config.to_bytes())
        (root / D3_REPLAY_FILENAME).write_bytes(self.d3_config.to_bytes())

    def _materialize(self) -> bytes:
        return entry_module._materialize_generation_at(
            self.snapshot_root / "tree",
            self.input_runtime,
            self.generation,
        )

    def test_request_and_replay_contracts_are_canonical_and_digest_bound(self) -> None:
        self.assertEqual(
            OciWorkerRequestV1.from_bytes(self.request.to_bytes()), self.request
        )
        self.assertEqual(
            OciReplayConfigV1.from_bytes(self.d2_config.to_bytes()), self.d2_config
        )
        self.assertEqual(
            self.d2_config.build_backend().registered_keys,
            frozenset(
                {
                    (
                        self.d2_config.responses[0].stage,
                        self.d2_config.responses[0].request_sha256,
                    )
                }
            ),
        )

        value = json.loads(self.request.to_bytes())
        value["handoff_wire_sha256"] = "f" * 64
        tampered = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        with self.assertRaises(OciWorkerEntryError) as captured:
            OciWorkerRequestV1.from_bytes(tampered)
        self.assertEqual(captured.exception.code, "digest_mismatch")

        duplicate = self.d2_config.to_bytes().replace(
            b'{"backend_id":"replay",',
            b'{"backend_id":"replay","backend_id":"replay",',
            1,
        )
        with self.assertRaises(OciWorkerEntryError) as captured:
            OciReplayConfigV1.from_bytes(duplicate)
        self.assertEqual(captured.exception.code, "noncanonical_json")

    def test_materialize_copies_only_exact_generation_and_returns_receipt(self) -> None:
        receipt_wire = self._materialize()
        receipt = GenerationReceiptV1.from_bytes(receipt_wire)
        self.assertEqual(receipt.task_id, TASK_ID)
        self.assertEqual(receipt.snapshot_id, self.task.snapshot_id)
        self.assertEqual(receipt.request_sha256, self.request.request_sha256)
        self.assertEqual(receipt.handoff_sha256, self.handoff.handoff_sha256)
        self.assertEqual(receipt.file_count, self.handoff.file_count)
        self.assertEqual(receipt.total_bytes, self.handoff.total_bytes)
        self.assertEqual(
            {item.name for item in self.generation.iterdir()},
            {"runtime", "source"},
        )
        self.assertEqual(
            {item.name for item in (self.generation / "runtime").iterdir()},
            {
                REQUEST_FILENAME,
                HANDOFF_FILENAME,
                D2_REPLAY_FILENAME,
                D3_REPLAY_FILENAME,
            },
        )
        self.assertEqual(
            (self.generation / "source" / SOURCE_PATH).read_bytes(), SOURCE
        )
        self.assertNotIn(KEY, receipt_wire)
        self.assertNotIn(str(self.root).encode("utf-8"), receipt_wire)

        # The generation is a detached copy; later changes to the original do
        # not alter the bytes already materialized.
        (self.snapshot_root / "tree" / SOURCE_PATH).write_bytes(
            SOURCE.replace(b"critical", b"changed_")
        )
        self.assertEqual(
            (self.generation / "source" / SOURCE_PATH).read_bytes(), SOURCE
        )

    def test_execute_builds_only_replay_backends_and_returns_canonical_run(self) -> None:
        self._materialize()
        with mock.patch.object(entry_module, "_runtime_self_check") as check:
            wire = entry_module._execute_at(
                self.generation / "runtime", self.generation / "source"
            )
        check.assert_called_once()
        self.assertEqual(wire, self.expected_run_wire)
        result = SourceDiscoveryRunV1.from_wire(wire)
        self.assertEqual(result.to_wire(), wire)
        self.assertEqual(result.task, self.task)
        self.assertEqual(result.discovery_result.status, "deferred")

    def test_cli_has_only_two_argument_free_modes_and_stable_error_output(self) -> None:
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        with (
            mock.patch.object(
                entry_module, "MATERIALIZE_SOURCE_ROOT", self.snapshot_root / "tree"
            ),
            mock.patch.object(
                entry_module, "MATERIALIZE_RUNTIME_ROOT", self.input_runtime
            ),
            mock.patch.object(entry_module, "GENERATION_ROOT", self.generation),
        ):
            code = entry_module.main(
                ["materialize"], stdout=stdout, stderr=stderr
            )
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), b"")
        GenerationReceiptV1.from_bytes(stdout.getvalue())

        execute_stdout = io.BytesIO()
        execute_stderr = io.BytesIO()
        with (
            mock.patch.object(
                entry_module, "EXECUTE_SOURCE_ROOT", self.generation / "source"
            ),
            mock.patch.object(
                entry_module, "EXECUTE_RUNTIME_ROOT", self.generation / "runtime"
            ),
            mock.patch.object(entry_module, "_runtime_self_check"),
        ):
            code = entry_module.main(
                ["execute"], stdout=execute_stdout, stderr=execute_stderr
            )
        self.assertEqual(code, 0)
        self.assertEqual(execute_stdout.getvalue(), self.expected_run_wire)
        self.assertEqual(execute_stderr.getvalue(), b"")

        invalid_stdout = io.BytesIO()
        invalid_stderr = io.BytesIO()
        code = entry_module.main(
            ["execute", "C:/caller/path"],
            stdout=invalid_stdout,
            stderr=invalid_stderr,
        )
        self.assertEqual(code, 2)
        self.assertEqual(invalid_stdout.getvalue(), b"")
        error = json.loads(invalid_stderr.getvalue())
        self.assertEqual(
            error,
            {
                "code": "invalid_arguments",
                "contract_version": 1,
                "kind": "vulngym.oci-worker-error.v1",
                "mode": "cli",
            },
        )
        self.assertLessEqual(len(invalid_stderr.getvalue()), 512)

        probe_stdout = io.BytesIO()
        probe_stderr = io.BytesIO()
        with mock.patch.object(
            entry_module,
            "_execute_at",
            side_effect=OciWorkerEntryError("runtime_probe_failed"),
        ):
            code = entry_module.main(
                ["execute"], stdout=probe_stdout, stderr=probe_stderr
            )
        self.assertEqual(code, 2)
        self.assertEqual(probe_stdout.getvalue(), b"")
        self.assertEqual(
            json.loads(probe_stderr.getvalue()),
            {
                "code": "runtime_probe_failed",
                "contract_version": 1,
                "kind": "vulngym.oci-worker-error.v1",
                "mode": "execute",
            },
        )

    def test_runtime_digest_mismatch_and_extra_members_fail_before_execution(self) -> None:
        value = json.loads((self.input_runtime / REQUEST_FILENAME).read_bytes())
        value["d2_replay_wire_sha256"] = "f" * 64
        # Reconstructing the outer request makes its own digest valid while
        # leaving the pinned replay wire deliberately wrong.
        changed = OciWorkerRequestV1(
            task_id=value["task_id"],
            snapshot_id=value["snapshot_id"],
            snapshot_manifest_sha256=value["snapshot_manifest_sha256"],
            snapshot_content_root=value["snapshot_content_root"],
            handoff_sha256=value["handoff_sha256"],
            handoff_wire_sha256=value["handoff_wire_sha256"],
            d2_replay_sha256=value["d2_replay_sha256"],
            d2_replay_wire_sha256=value["d2_replay_wire_sha256"],
            d3_replay_sha256=value["d3_replay_sha256"],
            d3_replay_wire_sha256=value["d3_replay_wire_sha256"],
        )
        (self.input_runtime / REQUEST_FILENAME).write_bytes(changed.to_bytes())
        with mock.patch.object(
            entry_module,
            "execute_discovery_worker_v1",
            side_effect=AssertionError("execution must remain unreachable"),
        ) as execute:
            with self.assertRaises(OciWorkerEntryError) as captured:
                entry_module._execute_at(
                    self.input_runtime, self.snapshot_root / "tree"
                )
        self.assertEqual(captured.exception.code, "digest_mismatch")
        execute.assert_not_called()

        (self.input_runtime / REQUEST_FILENAME).write_bytes(self.request.to_bytes())
        (self.input_runtime / "control.json").write_bytes(b"{}\n")
        with self.assertRaises(OciWorkerEntryError) as captured:
            entry_module._materialize_generation_at(
                self.snapshot_root / "tree",
                self.input_runtime,
                self.generation,
            )
        self.assertEqual(captured.exception.code, "invalid_contract")
        self.assertEqual(list(self.generation.iterdir()), [])

    def test_materialize_rejects_unexpected_source_and_linked_runtime_input(self) -> None:
        extra = self.snapshot_root / "tree" / "unexpected.txt"
        extra.write_bytes(b"unexpected\n")
        with self.assertRaises(OciWorkerEntryError) as captured:
            self._materialize()
        self.assertEqual(captured.exception.code, "source_rejected")
        self.assertEqual(list(self.generation.iterdir()), [])
        extra.unlink()

        request_path = self.input_runtime / REQUEST_FILENAME
        request_path.unlink()
        try:
            os.link(self.input_runtime / HANDOFF_FILENAME, request_path)
        except (NotImplementedError, OSError):
            self.skipTest("hard links are unavailable on this filesystem")
        with self.assertRaises(OciWorkerEntryError) as captured:
            self._materialize()
        self.assertEqual(captured.exception.code, "unsafe_input")
        self.assertEqual(list(self.generation.iterdir()), [])

    def test_runtime_self_check_requires_exact_kernel_status(self) -> None:
        status = (
            b"CapEff:\t0000000000000000\n"
            b"Gid:\t65532\t65532\t65532\t65532\n"
            b"NoNewPrivs:\t1\n"
            b"NSpid:\t1234\t1\n"
            b"Seccomp:\t2\n"
            b"Uid:\t65532\t65532\t65532\t65532\n"
        )
        mountinfo = (
            b"1 0 0:1 / / ro - overlay overlay ro\n"
            b"2 1 0:2 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n"
        )

        def kernel_file(path: str, *, maximum_bytes: int) -> bytes:
            del maximum_bytes
            return status if path.endswith("status") else mountinfo

        source_mount = PurePosixPath("/vulngym/source")
        runtime_mount = PurePosixPath("/vulngym/runtime")
        posix_os = SimpleNamespace(
            name="posix",
            fspath=os.fspath,
            getuid=lambda: 65532,
            geteuid=lambda: 65532,
            getgid=lambda: 65532,
            getegid=lambda: 65532,
        )
        with (
            mock.patch.object(entry_module, "os", posix_os),
            mock.patch.object(
                entry_module, "_read_fixed_kernel_file", side_effect=kernel_file
            ),
            mock.patch.object(entry_module, "_assert_write_blocked") as writes,
            mock.patch.object(entry_module, "_assert_path_absent") as absent,
            mock.patch.object(
                entry_module, "_assert_empty_root_owned_directory"
            ) as empty_mountpoint,
            mock.patch.object(entry_module, "_assert_literal_network_blocked") as network,
        ):
            entry_module._runtime_self_check(
                source_mount,
                runtime_mount,
                self.handoff,
            )
        self.assertEqual(writes.call_count, 5)
        self.assertEqual(absent.call_count, len(entry_module._FORBIDDEN_RUNTIME_PATHS))
        self.assertEqual(
            empty_mountpoint.call_count,
            len(entry_module._EMPTY_INPUT_MOUNTPOINTS),
        )
        network.assert_called_once_with()

        bad_status = status.replace(b"0000000000000000", b"0000000000000001")

        def bad_kernel_file(path: str, *, maximum_bytes: int) -> bytes:
            del maximum_bytes
            return bad_status if path.endswith("status") else mountinfo

        with (
            mock.patch.object(entry_module, "os", posix_os),
            mock.patch.object(
                entry_module,
                "_read_fixed_kernel_file",
                side_effect=bad_kernel_file,
            ),
        ):
            with self.assertRaises(OciWorkerEntryError) as captured:
                entry_module._runtime_self_check(
                    source_mount,
                    runtime_mount,
                    self.handoff,
                )
        self.assertEqual(captured.exception.code, "runtime_identity_probe_failed")

    def test_detached_input_mountpoints_must_be_empty_stable_and_root_owned(self) -> None:
        valid = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755,
            st_uid=0,
            st_gid=0,
            st_dev=7,
            st_ino=11,
        )
        with (
            mock.patch.object(entry_module.os, "open", return_value=23),
            mock.patch.object(entry_module.os, "fstat", side_effect=(valid, valid)),
            mock.patch.object(entry_module.os, "listdir", return_value=[]),
            mock.patch.object(entry_module.os, "close") as close,
        ):
            entry_module._assert_empty_root_owned_directory("/input-source")
        close.assert_called_once_with(23)

        bad_states = (
            (SimpleNamespace(**{**vars(valid), "st_uid": 65532}), [], valid),
            (
                SimpleNamespace(
                    **{**vars(valid), "st_mode": stat.S_IFDIR | 0o777}
                ),
                [],
                valid,
            ),
            (valid, ["leaked-input"], valid),
            (valid, [], SimpleNamespace(**{**vars(valid), "st_ino": 12})),
        )
        for before, members, after in bad_states:
            with self.subTest(before=before, members=members, after=after):
                with (
                    mock.patch.object(entry_module.os, "open", return_value=23),
                    mock.patch.object(
                        entry_module.os, "fstat", side_effect=(before, after)
                    ),
                    mock.patch.object(entry_module.os, "listdir", return_value=members),
                    mock.patch.object(entry_module.os, "close"),
                ):
                    with self.assertRaises(OciWorkerEntryError):
                        entry_module._assert_empty_root_owned_directory(
                            "/input-source"
                        )


if __name__ == "__main__":
    unittest.main()
