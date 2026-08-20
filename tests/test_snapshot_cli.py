from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from vulngym_agent import snapshot_cli
from vulngym_agent.benchmark import snapshot_batch
from vulngym_agent.benchmark.snapshot_batch import (
    SnapshotBatchError,
    SnapshotBatchSummary,
    SnapshotBatchTask,
)


DIGEST = "a" * 64
KEY = b"Q" * 32
KEY_ID = "cli-key-2026"


class SnapshotCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.key_file = self.root / "evaluator.key"
        self.key_file.write_bytes(KEY)
        self.key_file.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _summary(self) -> SnapshotBatchSummary:
        tasks = (
            SnapshotBatchTask(
                task_id="VG-TEST-0123456789ABCDEF0123",
                repo_url="https://github.com/example/cli-one",
                commit="1" * 40,
                split="test",
                instruction_id="vulngym-whitebox-locate-v1",
                snapshot_manifest_sha256=DIGEST,
                snapshot_content_root=DIGEST,
                file_count=1,
                node_count=1,
                total_bytes=1,
            ),
            SnapshotBatchTask(
                task_id="VG-TEST-1123456789ABCDEF0123",
                repo_url="https://github.com/example/cli-two",
                commit="2" * 40,
                split="test",
                instruction_id="vulngym-whitebox-locate-v1",
                snapshot_manifest_sha256=DIGEST,
                snapshot_content_root=DIGEST,
                file_count=2,
                node_count=2,
                total_bytes=3,
            ),
        )
        with mock.patch.object(
            snapshot_batch, "_OFFICIAL_SPLIT_COUNTS", {"train": 1, "test": 2}
        ):
            return SnapshotBatchSummary(
                batch_root=self.root / "sealed",
                profile_id="vulngym-50-20-v1",
                split="test",
                task_count=2,
                total_files=3,
                total_nodes=3,
                total_bytes=4,
                tasks_sha256=DIGEST,
                public_manifest_sha256=DIGEST,
                source_map_sha256=DIGEST,
                manifest_sha256=DIGEST,
                batch_content_root=DIGEST,
                key_id=KEY_ID,
                tasks=tasks,
            )

    def _prepare_arguments(self) -> list[str]:
        return [
            "prepare",
            "--task-export-dir",
            str(self.root / "export"),
            "--expected-tasks-sha256",
            DIGEST,
            "--expected-public-manifest-sha256",
            DIGEST,
            "--source-map",
            str(self.root / "source-map.json"),
            "--expected-source-map-sha256",
            DIGEST,
            "--output-dir",
            str(self.root / "sealed"),
            "--key-file",
            str(self.key_file),
            "--key-id",
            KEY_ID,
        ]

    def test_prepare_dispatches_secret_bytes_and_emits_path_free_json(self) -> None:
        output = StringIO()
        with mock.patch.object(
            snapshot_cli, "prepare_snapshot_batch", return_value=self._summary()
        ) as prepare, redirect_stdout(output):
            status = snapshot_cli.main(self._prepare_arguments())
        self.assertEqual(0, status)
        self.assertEqual(KEY, prepare.call_args.kwargs["attestation_key"])
        emitted = json.loads(output.getvalue())
        self.assertEqual(DIGEST, emitted["manifest_sha256"])
        self.assertNotIn("batch_root", emitted)
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertNotIn(KEY.decode("ascii"), output.getvalue())

    def test_verify_batch_requires_pinned_manifest_and_key_id(self) -> None:
        (self.root / "sealed").mkdir()
        output = StringIO()
        with mock.patch.object(
            snapshot_cli, "verify_snapshot_batch", return_value=self._summary()
        ) as verify, redirect_stdout(output):
            status = snapshot_cli.main(
                [
                    "verify-batch",
                    "--sealed-root",
                    str(self.root / "sealed"),
                    "--expected-manifest-sha256",
                    DIGEST,
                    "--key-file",
                    str(self.key_file),
                    "--expected-key-id",
                    KEY_ID,
                ]
            )
        self.assertEqual(0, status)
        self.assertEqual(DIGEST, verify.call_args.kwargs["expected_manifest_sha256"])
        self.assertEqual(KEY_ID, verify.call_args.kwargs["expected_key_id"])
        self.assertEqual(KEY, verify.call_args.kwargs["attestation_key"])

    def test_batch_error_exit_classes_and_messages_are_path_sanitized(self) -> None:
        secret = r"D:\sensitive\hidden\source"
        for expected in (2, 3, 4, 5):
            error = StringIO()
            failure = SnapshotBatchError(
                f"failure_{expected}", secret, exit_status=expected
            )
            with self.subTest(expected=expected), mock.patch.object(
                snapshot_cli, "prepare_snapshot_batch", side_effect=failure
            ), redirect_stderr(error):
                status = snapshot_cli.main(self._prepare_arguments())
            self.assertEqual(expected, status)
            self.assertNotIn(secret, error.getvalue())
            self.assertNotIn(str(self.root), error.getvalue())
            self.assertNotIn("Traceback", error.getvalue())

    def test_key_path_conflict_and_invalid_secret_file_are_input_errors(self) -> None:
        protected = self.root / "protected"
        protected.mkdir()
        nested_key = protected / "key.bin"
        nested_key.write_bytes(KEY)
        arguments = self._prepare_arguments()
        arguments[arguments.index("--output-dir") + 1] = str(protected)
        arguments[arguments.index("--key-file") + 1] = str(nested_key)
        error = StringIO()
        with mock.patch.object(snapshot_cli, "prepare_snapshot_batch") as prepare, redirect_stderr(error):
            status = snapshot_cli.main(arguments)
        self.assertEqual(2, status)
        prepare.assert_not_called()
        self.assertNotIn(str(protected), error.getvalue())

        self.key_file.write_bytes(b"too short")
        error = StringIO()
        with mock.patch.object(snapshot_cli, "prepare_snapshot_batch") as prepare, redirect_stderr(error):
            status = snapshot_cli.main(self._prepare_arguments())
        self.assertEqual(2, status)
        prepare.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX key-mode contract")
    def test_posix_key_file_rejects_group_or_other_permissions(self) -> None:
        self.key_file.chmod(0o640)
        error = StringIO()
        with mock.patch.object(
            snapshot_cli, "prepare_snapshot_batch"
        ) as prepare, redirect_stderr(error):
            status = snapshot_cli.main(self._prepare_arguments())
        self.assertEqual(2, status)
        prepare.assert_not_called()
        self.assertNotIn(str(self.key_file), error.getvalue())

    @unittest.skipUnless(os.name == "nt", "Windows device-path alias contract")
    def test_windows_device_key_alias_is_rejected(self) -> None:
        arguments = self._prepare_arguments()
        arguments[arguments.index("--key-file") + 1] = "\\\\?\\" + str(
            self.key_file
        )
        error = StringIO()
        with mock.patch.object(
            snapshot_cli, "prepare_snapshot_batch"
        ) as prepare, redirect_stderr(error):
            status = snapshot_cli.main(arguments)
        self.assertEqual(2, status)
        prepare.assert_not_called()
        self.assertNotIn(str(self.key_file), error.getvalue())


if __name__ == "__main__":
    unittest.main()
