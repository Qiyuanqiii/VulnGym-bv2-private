from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from vulngym_agent.agents.model_runtime import ModelRequest
from vulngym_agent.benchmark.contracts import INSTRUCTION_ID, SnapshotTaskSpec
from vulngym_agent.benchmark.harness import (
    PROFILE_MANIFEST_SHA256,
    PROFILE_SCHEMA_VERSION,
)
from vulngym_agent.benchmark import snapshot_batch
from vulngym_agent.benchmark.snapshot_batch import (
    PROFILE_ID,
    SOURCE_MAP_KIND,
    SOURCE_MAP_SCHEMA_VERSION,
    prepare_snapshot_batch,
)
from vulngym_agent.evaluator.oci_worker_entry import (
    REPLAY_BACKEND_ID,
    REPLAY_MODEL_ID,
)
from vulngym_agent.evaluator.replay_authoring import (
    ReplayAuthoringPendingRequestV1,
    ReplayAuthoringResponseV1,
)
import vulngym_agent.replay_task_response_cli as cli


KEY = b"task response test attestation key 0001"
KEY_ID = "task-response-test"
REPO_URL = "https://github.com/example/task-response"
TASK_ONE = "VG-TRAIN-0123456789ABCDEF0123"
TASK_TWO = "VG-TRAIN-1123456789ABCDEF0123"


def _canonical_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _private_write(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


class ReplayTaskSplitExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.repository = cls.root / "repository"
        cls.repository.mkdir(mode=0o700)
        cls._git("init", "-q", "-b", "main")
        cls._git("config", "user.name", "VulnGym Test")
        cls._git("config", "user.email", "vulngym@example.invalid")
        cls._git("config", "core.autocrlf", "false")
        (cls.repository / "app.py").write_bytes(b"print('one')\n")
        cls._git("add", "app.py")
        cls._git("commit", "-q", "-m", "one")
        first_commit = cls._git("rev-parse", "HEAD").stdout.strip()
        (cls.repository / "app.py").write_bytes(b"print('two')\n")
        cls._git("add", "app.py")
        cls._git("commit", "-q", "-m", "two")
        second_commit = cls._git("rev-parse", "HEAD").stdout.strip()
        cls.tasks = (
            SnapshotTaskSpec(
                task_id=TASK_ONE,
                repo_url=REPO_URL,
                commit=first_commit,
                split="train",
            ),
            SnapshotTaskSpec(
                task_id=TASK_TWO,
                repo_url=REPO_URL,
                commit=second_commit,
                split="train",
            ),
        )
        cls.task_export = cls.root / "public-task-export"
        cls.task_export.mkdir(mode=0o700)
        tasks_payload = b"".join(
            _canonical_line(task.to_dict()) for task in cls.tasks
        )
        cls.tasks_sha256 = _sha(tasks_payload)
        manifest = {
            "kind": "answer_free_task_export",
            "manifest_sha256": PROFILE_MANIFEST_SHA256,
            "profile_id": PROFILE_ID,
            "schema_version": PROFILE_SCHEMA_VERSION,
            "split": "train",
            "task_count": 2,
            "tasks_sha256": cls.tasks_sha256,
        }
        (cls.task_export / "tasks.jsonl").write_bytes(tasks_payload)
        (cls.task_export / "manifest.json").write_bytes(
            _canonical_line(manifest)
        )

        source_map_value = {
            "kind": SOURCE_MAP_KIND,
            "profile_id": PROFILE_ID,
            "public_manifest_sha256": PROFILE_MANIFEST_SHA256,
            "schema_version": SOURCE_MAP_SCHEMA_VERSION,
            "sources": sorted(
                (
                    {
                        "commit": task.commit,
                        "repo_root": str(cls.repository),
                        "repo_url": task.repo_url,
                    }
                    for task in cls.tasks
                ),
                key=lambda item: (
                    item["repo_url"].encode("utf-8"),
                    item["commit"].encode("ascii"),
                ),
            ),
            "tasks_sha256": cls.tasks_sha256,
        }
        cls.source_map = cls.root / "synthetic-source-map.json"
        source_map_payload = _canonical_line(source_map_value)
        cls.source_map.write_bytes(source_map_payload)
        cls.source_map_sha256 = _sha(source_map_payload)
        cls.sealed_batch = cls.root / "sealed-batch"
        with mock.patch.object(
            snapshot_batch, "_OFFICIAL_SPLIT_COUNTS", {"train": 2, "test": 1}
        ):
            prepared = prepare_snapshot_batch(
                cls.task_export,
                expected_tasks_sha256=cls.tasks_sha256,
                expected_public_manifest_sha256=PROFILE_MANIFEST_SHA256,
                source_map_path=cls.source_map,
                expected_source_map_sha256=cls.source_map_sha256,
                output_dir=cls.sealed_batch,
                attestation_key=KEY,
                key_id=KEY_ID,
            )
        cls.batch_manifest_sha256 = prepared.manifest_sha256
        cls.key_file = cls.root / "key.bin"
        _private_write(cls.key_file, KEY)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _git(cls, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=cls.repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _invoke(self, *arguments: object) -> tuple[int, dict[str, object] | None, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(cli, "_SPLIT_COUNTS", {"train": 2, "test": 1}),
            mock.patch.object(
                snapshot_batch,
                "_OFFICIAL_SPLIT_COUNTS",
                {"train": 2, "test": 1},
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = cli.main([str(item) for item in arguments])
        text = stdout.getvalue()
        return status, json.loads(text) if text else None, stderr.getvalue()

    def _export_arguments(self, output: Path) -> tuple[object, ...]:
        return (
            "export-split",
            "--task-export-dir",
            self.task_export,
            "--expected-tasks-sha256",
            self.tasks_sha256,
            "--expected-public-manifest-sha256",
            PROFILE_MANIFEST_SHA256,
            "--sealed-batch-root",
            self.sealed_batch,
            "--expected-batch-manifest-sha256",
            self.batch_manifest_sha256,
            "--key-file",
            self.key_file,
            "--key-id",
            KEY_ID,
            "--output-root",
            output,
        )

    def test_export_split_authenticates_and_preserves_public_order(self) -> None:
        output = self.root / "export-success"
        status, summary, error = self._invoke(*self._export_arguments(output))
        self.assertEqual((status, error), (0, ""))
        assert summary is not None
        self.assertEqual(summary["status"], "published")
        self.assertEqual(summary["task_count"], 2)
        self.assertEqual(summary["tasks_sha256"], self.tasks_sha256)
        self.assertEqual(
            {path.name for path in output.iterdir()}, {"index.json", "tasks"}
        )
        with mock.patch.object(
            cli, "_SPLIT_COUNTS", {"train": 2, "test": 1}
        ):
            verified = cli.read_discovery_task_split_export_v1(
                output,
                expected_index_sha256=summary["index_sha256"],
                expected_index_wire_sha256=summary["index_wire_sha256"],
            )
        self.assertEqual(
            tuple(task.task_id for task in verified.tasks),
            (TASK_ONE, TASK_TWO),
        )
        for binding, task in zip(verified.index.tasks, verified.tasks):
            task_wire = (output / binding.task_file).read_bytes()
            self.assertEqual(_sha(task_wire), binding.task_wire_sha256)
            self.assertEqual(json.loads(task_wire), task.to_dict())

        serialized = b"".join(
            path.read_bytes()
            for path in sorted(output.rglob("*"))
            if path.is_file()
        )
        self.assertNotIn(str(self.repository).encode(), serialized)
        self.assertNotIn(str(self.source_map).encode(), serialized)
        self.assertNotIn(self.source_map_sha256.encode(), serialized)

        verify_status, verify_summary, verify_error = self._invoke(
            "verify-export",
            "--export-root",
            output,
            "--expected-index-sha256",
            summary["index_sha256"],
            "--expected-index-wire-sha256",
            summary["index_wire_sha256"],
        )
        self.assertEqual((verify_status, verify_error), (0, ""))
        assert verify_summary is not None
        self.assertEqual(verify_summary["status"], "verified")
        self.assertEqual(
            verify_summary["index_wire_sha256"], summary["index_wire_sha256"]
        )

    def test_wrong_external_input_pin_creates_no_output(self) -> None:
        output = self.root / "export-wrong-pin"
        arguments = list(self._export_arguments(output))
        index = arguments.index("--expected-batch-manifest-sha256") + 1
        arguments[index] = "0" * 64
        status, summary, error = self._invoke(*arguments)
        self.assertEqual(status, 2)
        self.assertIsNone(summary)
        self.assertIn("sealed_batch_rejected", error)
        self.assertFalse(output.exists())

    def test_reordered_public_export_cannot_be_rebound_to_the_sealed_batch(self) -> None:
        reordered = self.root / "reordered-public-task-export"
        reordered.mkdir(mode=0o700)
        payload = b"".join(
            _canonical_line(task.to_dict()) for task in reversed(self.tasks)
        )
        tasks_sha256 = _sha(payload)
        (reordered / "tasks.jsonl").write_bytes(payload)
        (reordered / "manifest.json").write_bytes(
            _canonical_line(
                {
                    "kind": "answer_free_task_export",
                    "manifest_sha256": PROFILE_MANIFEST_SHA256,
                    "profile_id": PROFILE_ID,
                    "schema_version": PROFILE_SCHEMA_VERSION,
                    "split": "train",
                    "task_count": 2,
                    "tasks_sha256": tasks_sha256,
                }
            )
        )
        output = self.root / "reordered-output"
        arguments = list(self._export_arguments(output))
        arguments[arguments.index("--task-export-dir") + 1] = reordered
        arguments[arguments.index("--expected-tasks-sha256") + 1] = tasks_sha256
        status, summary, error = self._invoke(*arguments)
        self.assertEqual(status, 2)
        self.assertIsNone(summary)
        self.assertIn("batch_binding_mismatch", error)
        self.assertFalse(output.exists())

    def test_export_never_replaces_an_existing_root(self) -> None:
        output = self.root / "export-existing"
        output.mkdir(mode=0o700)
        marker = output / "owned.txt"
        marker.write_bytes(b"caller-owned")
        status, summary, error = self._invoke(*self._export_arguments(output))
        self.assertEqual(status, 2)
        self.assertIsNone(summary)
        self.assertIn("output_exists", error)
        self.assertEqual(marker.read_bytes(), b"caller-owned")

    def test_export_rejects_output_inside_sealed_batch(self) -> None:
        output = self.sealed_batch / "forbidden-output"
        status, summary, error = self._invoke(*self._export_arguments(output))
        self.assertEqual(status, 2)
        self.assertIsNone(summary)
        self.assertIn("path_overlap", error)
        self.assertFalse(output.exists())

    def test_precommit_rename_failure_cleans_only_owned_staging(self) -> None:
        output = self.root / "export-rename-failure"
        with mock.patch.object(
            cli,
            "_rename_directory_noreplace",
            side_effect=OSError("synthetic precommit failure"),
        ):
            status, summary, _error = self._invoke(
                *self._export_arguments(output)
            )
        self.assertEqual(status, 2)
        self.assertIsNone(summary)
        self.assertFalse(output.exists())
        self.assertEqual(
            list(self.root.glob(f".{output.name}.replay-task-response-*")), []
        )

    def test_task_tamper_is_rejected_under_original_external_index_pin(self) -> None:
        output = self.root / "export-tamper"
        status, summary, error = self._invoke(*self._export_arguments(output))
        self.assertEqual((status, error), (0, ""))
        assert summary is not None
        task_file = output / "tasks" / f"{TASK_ONE}.json"
        original = task_file.read_bytes()
        value = json.loads(original)
        value["snapshot_content_root"] = "0" * 64
        task_file.write_bytes(_canonical_line(value))
        verify_status, verified, verify_error = self._invoke(
            "verify-export",
            "--export-root",
            output,
            "--expected-index-sha256",
            summary["index_sha256"],
            "--expected-index-wire-sha256",
            summary["index_wire_sha256"],
        )
        self.assertEqual(verify_status, 2)
        self.assertIsNone(verified)
        self.assertIn("task_wire_mismatch", verify_error)


class ReplayResponseBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        request = ModelRequest(
            task_id=TASK_ONE,
            attempt=0,
            policy_scope="replay.task.response.test",
            stage="plan",
            model_call_id="MODEL-TASK-RESPONSE-001",
            backend_id=REPLAY_BACKEND_ID,
            model_id=REPLAY_MODEL_ID,
            payload={"task": TASK_ONE, "step": "inventory"},
        )
        self.pending = ReplayAuthoringPendingRequestV1.from_model_request(
            request,
            role="d2",
            occurrence=1,
            prefix_config_sha256=_sha(b"empty-prefix"),
        )
        self.pending_file = self.root / "pending.json"
        self.pending_wire = self.pending.to_bytes()
        _private_write(self.pending_file, self.pending_wire)
        self.body = {"action": "inventory", "cursor": 0, "limit": 8}
        self.body_file = self.root / "response-body.json"
        self.body_wire = _canonical_line(self.body)
        _private_write(self.body_file, self.body_wire)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _invoke(*arguments: object) -> tuple[int, dict[str, object] | None, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main([str(item) for item in arguments])
        text = stdout.getvalue()
        return status, json.loads(text) if text else None, stderr.getvalue()

    def _bind_arguments(self, output: Path) -> tuple[object, ...]:
        return (
            "bind-response",
            "--pending-file",
            self.pending_file,
            "--expected-pending-wire-sha256",
            _sha(self.pending_wire),
            "--response-body-file",
            self.body_file,
            "--expected-response-body-wire-sha256",
            _sha(self.body_wire),
            "--output-root",
            output,
        )

    def test_bind_response_copies_all_exact_pending_bindings(self) -> None:
        output = self.root / "bound-response"
        status, summary, error = self._invoke(*self._bind_arguments(output))
        self.assertEqual((status, error), (0, ""))
        assert summary is not None
        payload = (output / "response.json").read_bytes()
        response = ReplayAuthoringResponseV1.from_bytes(payload)
        self.assertEqual(response.task_id, self.pending.task_id)
        self.assertEqual(response.role, self.pending.role)
        self.assertEqual(response.stage, self.pending.stage)
        self.assertEqual(response.request_sha256, self.pending.request_sha256)
        self.assertEqual(response.occurrence, self.pending.occurrence)
        self.assertEqual(
            response.prefix_config_sha256, self.pending.prefix_config_sha256
        )
        self.assertEqual(dict(response.response), self.body)
        self.assertEqual(summary["pending_wire_sha256"], _sha(self.pending_wire))
        self.assertEqual(summary["response_body_wire_sha256"], _sha(self.body_wire))
        self.assertEqual(summary["response_wire_sha256"], _sha(payload))

        verify_status, verified, verify_error = self._invoke(
            "verify-response",
            "--response-root",
            output,
            "--expected-response-wire-sha256",
            summary["response_wire_sha256"],
        )
        self.assertEqual((verify_status, verify_error), (0, ""))
        assert verified is not None
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(verified["response_sha256"], response.response_sha256)

    def test_wrong_pending_or_body_pin_creates_no_output(self) -> None:
        for option, suffix in (
            ("--expected-pending-wire-sha256", "pending"),
            ("--expected-response-body-wire-sha256", "body"),
        ):
            output = self.root / f"wrong-{suffix}"
            arguments = list(self._bind_arguments(output))
            arguments[arguments.index(option) + 1] = "0" * 64
            status, summary, _error = self._invoke(*arguments)
            self.assertEqual(status, 2)
            self.assertIsNone(summary)
            self.assertFalse(output.exists())

    def test_noncanonical_model_body_is_rejected_even_when_wire_pinned(self) -> None:
        self.body_wire = json.dumps(self.body, indent=2).encode("utf-8") + b"\n"
        _private_write(self.body_file, self.body_wire)
        output = self.root / "noncanonical-body"
        status, summary, error = self._invoke(*self._bind_arguments(output))
        self.assertEqual(status, 2)
        self.assertIsNone(summary)
        self.assertIn("noncanonical_json", error)
        self.assertFalse(output.exists())

    def test_occurrence_and_prefix_prevent_cross_step_reuse(self) -> None:
        first_output = self.root / "first-occurrence"
        status, first_summary, error = self._invoke(
            *self._bind_arguments(first_output)
        )
        self.assertEqual((status, error), (0, ""))
        assert first_summary is not None

        second = ReplayAuthoringPendingRequestV1(
            task_id=self.pending.task_id,
            role=self.pending.role,
            stage=self.pending.stage,
            payload=self.pending.payload,
            request_sha256=self.pending.request_sha256,
            occurrence=2,
            prefix_config_sha256=_sha(b"one-response-prefix"),
        )
        second_wire = second.to_bytes()
        _private_write(self.pending_file, second_wire)
        self.pending_wire = second_wire
        second_output = self.root / "second-occurrence"
        status, second_summary, error = self._invoke(
            *self._bind_arguments(second_output)
        )
        self.assertEqual((status, error), (0, ""))
        assert second_summary is not None
        self.assertNotEqual(
            first_summary["response_wire_sha256"],
            second_summary["response_wire_sha256"],
        )
        second_response = ReplayAuthoringResponseV1.from_bytes(
            (second_output / "response.json").read_bytes()
        )
        self.assertEqual(second_response.occurrence, 2)
        self.assertEqual(
            second_response.prefix_config_sha256, second.prefix_config_sha256
        )

    def test_bind_never_replaces_an_existing_response_root(self) -> None:
        output = self.root / "existing-response"
        output.mkdir(mode=0o700)
        marker = output / "owned.txt"
        marker.write_bytes(b"caller-owned")
        status, summary, error = self._invoke(*self._bind_arguments(output))
        self.assertEqual(status, 2)
        self.assertIsNone(summary)
        self.assertIn("output_exists", error)
        self.assertEqual(marker.read_bytes(), b"caller-owned")

    def test_response_tamper_fails_original_external_wire_pin(self) -> None:
        output = self.root / "tampered-response"
        status, summary, error = self._invoke(*self._bind_arguments(output))
        self.assertEqual((status, error), (0, ""))
        assert summary is not None
        response_path = output / "response.json"
        raw = json.loads(response_path.read_bytes())
        raw["response"] = {"action": "defer"}
        raw["response_sha256"] = _sha(_canonical_line(raw["response"])[:-1])
        response_path.write_bytes(_canonical_line(raw))
        verify_status, verified, verify_error = self._invoke(
            "verify-response",
            "--response-root",
            output,
            "--expected-response-wire-sha256",
            summary["response_wire_sha256"],
        )
        self.assertEqual(verify_status, 2)
        self.assertIsNone(verified)
        self.assertIn("response_wire_mismatch", verify_error)


if __name__ == "__main__":
    unittest.main()
