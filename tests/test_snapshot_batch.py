from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import hmac
from io import StringIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from vulngym_agent import snapshot_cli
from vulngym_agent.benchmark.contracts import SnapshotTaskSpec
from vulngym_agent.benchmark.harness import (
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    PROFILE_SCHEMA_VERSION,
)
from vulngym_agent.benchmark import snapshot_batch
from vulngym_agent.benchmark.sealed_snapshot import (
    SealedSnapshotError,
    SnapshotPolicy,
)
from vulngym_agent.benchmark.snapshot_batch import (
    SOURCE_MAP_KIND,
    SOURCE_MAP_SCHEMA_VERSION,
    SnapshotBatchError,
    prepare_snapshot_batch,
    verify_snapshot_batch,
    verify_snapshot_batch_with_evidence,
)
from vulngym_agent.tools.git.repository import GitRepository


KEY = b"K" * 32
OTHER_KEY = b"Z" * 32
KEY_ID = "batch-evaluator-2026"
REPO_URL = "https://github.com/example/batch-source"
TASK_ONE = "VG-TRAIN-0123456789ABCDEF0123"
TASK_TWO = "VG-TRAIN-1123456789ABCDEF0123"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class SnapshotBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.name", "VulnGym Test")
        self._git("config", "user.email", "vulngym@example.invalid")
        self._git("config", "core.autocrlf", "false")
        (self.repo / "app.py").write_bytes(b"print('first')\r\n")
        self._git("add", "app.py")
        self._git("commit", "-q", "-m", "first")
        self.commit_one = self._git("rev-parse", "HEAD").stdout.strip()
        (self.repo / "app.py").write_bytes(b"print('second')\n")
        (self.repo / "data.bin").write_bytes(b"\x00\xff\x10")
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "second")
        self.commit_two = self._git("rev-parse", "HEAD").stdout.strip()
        self.tasks = (
            SnapshotTaskSpec(
                task_id=TASK_ONE,
                repo_url=REPO_URL,
                commit=self.commit_one,
                split="train",
            ),
            SnapshotTaskSpec(
                task_id=TASK_TWO,
                repo_url=REPO_URL,
                commit=self.commit_two,
                split="train",
            ),
        )
        self.export_dir = self.root / "task-export"
        self.tasks_sha256 = self._write_export(self.tasks)
        self.source_map = self.root / "source-map.json"
        self.source_map_sha256 = self._write_source_map(
            [
                {
                    "commit": task.commit,
                    "repo_root": str(self.repo),
                    "repo_url": task.repo_url,
                }
                for task in self.tasks
            ]
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repo,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def _hash_object(self, payload: bytes, *, object_type: str) -> str:
        result = subprocess.run(
            ["git", "hash-object", "-w", "-t", object_type, "--stdin"],
            cwd=self.repo,
            input=payload,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.stdout.decode("ascii").strip()

    def _nested_blob_commit(
        self, components: tuple[str, ...], payload: bytes
    ) -> str:
        blob = self._hash_object(payload, object_type="blob")
        tree = self._hash_object(
            b"100644 "
            + components[-1].encode("ascii")
            + b"\0"
            + bytes.fromhex(blob),
            object_type="tree",
        )
        for component in reversed(components[:-1]):
            tree = self._hash_object(
                b"40000 "
                + component.encode("ascii")
                + b"\0"
                + bytes.fromhex(tree),
                object_type="tree",
            )
        return self._git("commit-tree", tree, "-m", "nested tree").stdout.strip()

    def _write_export(self, tasks: tuple[SnapshotTaskSpec, ...]) -> str:
        self.export_dir.mkdir(exist_ok=True)
        payload = b"".join(_canonical(task.to_dict()) + b"\n" for task in tasks)
        digest = hashlib.sha256(payload).hexdigest()
        manifest = {
            "kind": "answer_free_task_export",
            "manifest_sha256": PROFILE_MANIFEST_SHA256,
            "profile_id": PROFILE_ID,
            "schema_version": PROFILE_SCHEMA_VERSION,
            "split": "train",
            "task_count": len(tasks),
            "tasks_sha256": digest,
        }
        (self.export_dir / "tasks.jsonl").write_bytes(payload)
        (self.export_dir / "manifest.json").write_bytes(_canonical(manifest) + b"\n")
        return digest

    def _write_source_map(self, sources: list[dict[str, str]], **extra: object) -> str:
        sources = sorted(
            sources,
            key=lambda source: (
                source["repo_url"].encode("utf-8"),
                source["commit"].encode("ascii"),
            ),
        )
        value = {
            "kind": SOURCE_MAP_KIND,
            "profile_id": PROFILE_ID,
            "public_manifest_sha256": PROFILE_MANIFEST_SHA256,
            "schema_version": SOURCE_MAP_SCHEMA_VERSION,
            "sources": sources,
            "tasks_sha256": self.tasks_sha256,
            **extra,
        }
        payload = _canonical(value) + b"\n"
        self.source_map.write_bytes(payload)
        return hashlib.sha256(payload).hexdigest()

    def _prepare(self, name: str = "sealed-batch", **overrides: object):
        arguments: dict[str, object] = {
            "expected_tasks_sha256": self.tasks_sha256,
            "expected_public_manifest_sha256": PROFILE_MANIFEST_SHA256,
            "source_map_path": self.source_map,
            "expected_source_map_sha256": self.source_map_sha256,
            "output_dir": self.root / name,
            "attestation_key": KEY,
            "key_id": KEY_ID,
        }
        arguments.update(overrides)
        with mock.patch.object(
            snapshot_batch, "_OFFICIAL_SPLIT_COUNTS", {"train": 2, "test": 1}
        ):
            return prepare_snapshot_batch(self.export_dir, **arguments)

    def _verify(
        self, name: str | Path, manifest_sha256: str, **overrides: object
    ):
        arguments: dict[str, object] = {
            "expected_manifest_sha256": manifest_sha256,
            "attestation_key": KEY,
            "expected_key_id": KEY_ID,
        }
        arguments.update(overrides)
        batch_root = Path(name)
        if not batch_root.is_absolute():
            batch_root = self.root / batch_root
        with mock.patch.object(
            snapshot_batch, "_OFFICIAL_SPLIT_COUNTS", {"train": 2, "test": 1}
        ):
            return verify_snapshot_batch(batch_root, **arguments)

    def test_prepare_and_verify_two_tasks_with_fresh_repository_gates(self) -> None:
        real_repository = GitRepository
        with mock.patch.object(
            snapshot_batch,
            "GitRepository",
            side_effect=lambda path: real_repository(path),
        ) as repository_factory:
            prepared = self._prepare()

        self.assertEqual(2, repository_factory.call_count)
        self.assertEqual({"bundles", "control"}, {p.name for p in prepared.batch_root.iterdir()})
        self.assertEqual(
            {TASK_ONE, TASK_TWO},
            {p.name for p in (prepared.batch_root / "bundles").iterdir()},
        )
        for task in self.tasks:
            self.assertEqual(
                {"tree", "control"},
                {
                    p.name
                    for p in (prepared.batch_root / "bundles" / task.task_id).iterdir()
                },
            )
        verified = self._verify("sealed-batch", prepared.manifest_sha256)
        self.assertEqual(prepared.to_dict(), verified.to_dict())
        self.assertEqual(prepared.tasks, verified.tasks)
        self.assertNotIn(str(self.repo), json.dumps(prepared.to_dict()))

    @unittest.skipUnless(os.name == "nt", "Windows extended-length path contract")
    def test_batch_prepare_and_repeated_verify_support_long_tree(self) -> None:
        components = tuple(
            f"level{index}-" + (chr(ord("a") + index) * 44)
            for index in range(6)
        ) + ("payload-" + ("z" * 44) + ".bin",)
        commit = self._nested_blob_commit(components, b"batch-long-path")
        self.tasks = (
            self.tasks[0],
            SnapshotTaskSpec(
                task_id=TASK_TWO,
                repo_url=REPO_URL,
                commit=commit,
                split="train",
            ),
        )
        self.tasks_sha256 = self._write_export(self.tasks)
        self.source_map_sha256 = self._write_source_map(
            [
                {
                    "commit": task.commit,
                    "repo_root": str(self.repo),
                    "repo_url": task.repo_url,
                }
                for task in self.tasks
            ]
        )
        first_component = self.root / ("p" * 120)
        parent = first_component / ("q" * 120)
        snapshot_batch._windows_extended_path(parent, force=True).mkdir(
            parents=True
        )
        output = parent / "long-😀😀-sealed-batch"
        failed_output = parent / "long-😀😀-batch-rollback"
        try:
            self.assertGreater(
                len(str(output).encode("utf-16-le")) // 2, 260
            )
            for unsafe_name in (
                "CON",
                "CON .txt",
                "name.",
                "name ",
                "file:stream",
            ):
                with self.subTest(unsafe_name=unsafe_name):
                    with self.assertRaises(
                        SnapshotBatchError
                    ) as captured:
                        self._prepare(
                            output_dir=parent / unsafe_name
                        )
                    self.assertEqual(
                        "path_alias_rejected", captured.exception.code
                    )
            prepared = self._prepare(output_dir=output)
            long_file = (
                prepared.batch_root
                / "bundles"
                / TASK_TWO
                / "tree"
            ).joinpath(*components)
            self.assertGreater(len(str(long_file)), 260)
            self.assertFalse(str(prepared.batch_root).startswith("\\\\?\\"))
            first = self._verify(output, prepared.manifest_sha256)
            second = self._verify(output, prepared.manifest_sha256)
            self.assertEqual(prepared.to_dict(), first.to_dict())
            self.assertEqual(first.to_dict(), second.to_dict())
            self.assertFalse(str(first.batch_root).startswith("\\\\?\\"))
            with self.assertRaises(SnapshotBatchError) as captured:
                self._prepare(output_dir=output)
            self.assertEqual("output_exists", captured.exception.code)
            with mock.patch.object(
                snapshot_batch,
                "_manifest_bytes",
                side_effect=SnapshotBatchError(
                    "transaction_failed",
                    "injected after long bundle registration",
                    exit_status=5,
                ),
            ):
                with self.assertRaises(SnapshotBatchError):
                    self._prepare(output_dir=failed_output)
            names = {
                entry.name
                for entry in os.scandir(
                    snapshot_batch._windows_extended_path(
                        parent, force=True
                    )
                )
            }
            self.assertNotIn(failed_output.name, names)
            self.assertFalse(
                any(
                    name.startswith(f".{failed_output.name}.")
                    for name in names
                )
            )
        finally:
            shutil.rmtree(
                snapshot_batch._windows_extended_path(
                    first_component, force=True
                )
            )

    def test_trusted_evidence_requires_two_actual_full_verifications(self) -> None:
        prepared = self._prepare()
        with mock.patch.object(
            snapshot_batch, "_OFFICIAL_SPLIT_COUNTS", {"train": 2, "test": 1}
        ), mock.patch.object(
            snapshot_batch,
            "verify_snapshot_batch",
            wraps=snapshot_batch.verify_snapshot_batch,
        ) as verifier:
            first = verify_snapshot_batch_with_evidence(
                prepared.batch_root,
                expected_manifest_sha256=prepared.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
            )
            second = verify_snapshot_batch_with_evidence(
                prepared.batch_root,
                expected_manifest_sha256=prepared.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
            )

        self.assertEqual(verifier.call_count, 2)
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertEqual(first.semantic_sha256, second.semantic_sha256)
        self.assertEqual(first.task_records_sha256, second.task_records_sha256)
        self.assertEqual(
            first.key_equality_tag_sha256, second.key_equality_tag_sha256
        )
        wire = json.dumps(first.to_dict(), sort_keys=True)
        self.assertNotIn(str(prepared.batch_root), wire)
        self.assertNotIn(KEY.decode("ascii"), wire)

    def test_trusted_evidence_rejects_a_nondefault_snapshot_policy(self) -> None:
        prepared = self._prepare()
        custom_policy = SnapshotPolicy(max_files=99_999)
        with mock.patch.object(snapshot_batch, "verify_snapshot_batch") as verifier:
            with self.assertRaisesRegex(SnapshotBatchError, "fixed default policy"):
                verify_snapshot_batch_with_evidence(
                    prepared.batch_root,
                    expected_manifest_sha256=prepared.manifest_sha256,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                    policy=custom_policy,
                )
        verifier.assert_not_called()

    def test_cli_prepare_output_interrupt_is_committed_uncertain_then_pinned_verify(
        self,
    ) -> None:
        class FatalOutput(BaseException):
            pass

        key_file = self.root / "snapshot.key"
        key_file.write_bytes(KEY)
        key_file.chmod(0o600)

        for index, failure in enumerate(
            (
                BrokenPipeError("closed stdout"),
                KeyboardInterrupt(),
                FatalOutput(),
            ),
            start=1,
        ):
            with self.subTest(failure=type(failure).__name__):
                sealed = self.root / f"cli-committed-{index}"
                prepare_error = StringIO()
                with (
                    mock.patch.object(
                        snapshot_batch,
                        "_OFFICIAL_SPLIT_COUNTS",
                        {"train": 2, "test": 1},
                    ),
                    mock.patch.object(
                        snapshot_cli, "_print_json", side_effect=failure
                    ),
                    redirect_stderr(prepare_error),
                ):
                    status = snapshot_cli.main(
                        [
                            "prepare",
                            "--task-export-dir",
                            str(self.export_dir),
                            "--expected-tasks-sha256",
                            self.tasks_sha256,
                            "--expected-public-manifest-sha256",
                            PROFILE_MANIFEST_SHA256,
                            "--source-map",
                            str(self.source_map),
                            "--expected-source-map-sha256",
                            self.source_map_sha256,
                            "--output-dir",
                            str(sealed),
                            "--key-file",
                            str(key_file),
                            "--key-id",
                            KEY_ID,
                        ]
                    )
                self.assertEqual(5, status)
                self.assertEqual(
                    "error[publication_uncertain]: snapshot batch output may be committed\n",
                    prepare_error.getvalue(),
                )
                self.assertNotIn(str(self.root), prepare_error.getvalue())
                self.assertEqual(
                    {"bundles", "control"},
                    {item.name for item in sealed.iterdir()},
                )

                manifest_sha256 = hashlib.sha256(
                    (sealed / "control" / "manifest.jsonl").read_bytes()
                ).hexdigest()
                wrong_pin_error = StringIO()
                with (
                    mock.patch.object(
                        snapshot_batch,
                        "_OFFICIAL_SPLIT_COUNTS",
                        {"train": 2, "test": 1},
                    ),
                    redirect_stderr(wrong_pin_error),
                ):
                    wrong_pin_status = snapshot_cli.main(
                        [
                            "verify-batch",
                            "--sealed-root",
                            str(sealed),
                            "--expected-manifest-sha256",
                            "0" * 64,
                            "--key-file",
                            str(key_file),
                            "--expected-key-id",
                            KEY_ID,
                        ]
                    )
                self.assertEqual(4, wrong_pin_status)
                self.assertIn(
                    "error[batch_manifest_digest_mismatch]",
                    wrong_pin_error.getvalue(),
                )
                self.assertTrue(sealed.is_dir())

                verify_output = StringIO()
                with (
                    mock.patch.object(
                        snapshot_batch,
                        "_OFFICIAL_SPLIT_COUNTS",
                        {"train": 2, "test": 1},
                    ),
                    redirect_stdout(verify_output),
                ):
                    verify_status = snapshot_cli.main(
                        [
                            "verify-batch",
                            "--sealed-root",
                            str(sealed),
                            "--expected-manifest-sha256",
                            manifest_sha256,
                            "--key-file",
                            str(key_file),
                            "--expected-key-id",
                            KEY_ID,
                        ]
                    )
                self.assertEqual(0, verify_status)
                self.assertEqual(
                    manifest_sha256,
                    json.loads(verify_output.getvalue())["manifest_sha256"],
                )

    def test_v3_verifier_rejects_a_self_consistent_legacy_v1_batch(self) -> None:
        prepared = self._prepare("legacy-v1-batch")
        legacy_snapshot_bindings: dict[str, tuple[str, str]] = {}

        for task in prepared.tasks:
            control = prepared.batch_root / task.bundle_path / "control"
            manifest_path = control / "manifest.jsonl"
            records = [json.loads(line) for line in manifest_path.read_bytes().splitlines()]
            records[0]["contract_version"] = "vulngym.sealed-source-snapshot.v1"
            records[0]["policy"].pop("git_symlink_representation")
            records[0]["policy"]["policy_version"] = (
                "vulngym.portable-source-tree.v1"
            )
            file_lines = tuple(_canonical(record) + b"\n" for record in records[1:-1])
            content_root = hashlib.sha256(
                b"VulnGym sealed source content root v1\0" + b"".join(file_lines)
            ).hexdigest()
            records[-1]["content_root"] = content_root
            legacy_manifest = (
                _canonical(records[0])
                + b"\n"
                + b"".join(file_lines)
                + _canonical(records[-1])
                + b"\n"
            )
            manifest_sha256 = hashlib.sha256(legacy_manifest).hexdigest()
            mac = hmac.new(KEY, digestmod=hashlib.sha256)
            mac.update(b"VulnGym sealed source attestation v1\0")
            mac.update(KEY_ID.encode("ascii"))
            mac.update(b"\0")
            mac.update(legacy_manifest)
            legacy_attestation = _canonical(
                {
                    "algorithm": "HMAC-SHA256",
                    "contract_version": "vulngym.sealed-source-snapshot.v1",
                    "key_id": KEY_ID,
                    "mac": mac.hexdigest(),
                    "manifest_sha256": manifest_sha256,
                }
            ) + b"\n"
            manifest_path.write_bytes(legacy_manifest)
            (control / "attestation.json").write_bytes(legacy_attestation)
            legacy_snapshot_bindings[task.task_id] = (
                manifest_sha256,
                content_root,
            )

        batch_control = prepared.batch_root / "control"
        batch_manifest_path = batch_control / "manifest.jsonl"
        batch_records = [
            json.loads(line) for line in batch_manifest_path.read_bytes().splitlines()
        ]
        batch_records[0]["contract_version"] = "vulngym.sealed-snapshot-batch.v1"
        batch_records[0]["snapshot_policy"].pop("git_symlink_representation")
        batch_records[0]["snapshot_policy"]["policy_version"] = (
            "vulngym.portable-source-tree.v1"
        )
        for record in batch_records[1:-1]:
            manifest_sha256, content_root = legacy_snapshot_bindings[
                record["task_id"]
            ]
            record["snapshot_manifest_sha256"] = manifest_sha256
            record["snapshot_content_root"] = content_root
        task_lines = tuple(_canonical(record) + b"\n" for record in batch_records[1:-1])
        batch_content_root = hashlib.sha256(
            b"VulnGym sealed snapshot batch content root v1\0"
            + b"".join(task_lines)
        ).hexdigest()
        batch_records[-1]["batch_content_root"] = batch_content_root
        legacy_batch_manifest = (
            _canonical(batch_records[0])
            + b"\n"
            + b"".join(task_lines)
            + _canonical(batch_records[-1])
            + b"\n"
        )
        batch_manifest_sha256 = hashlib.sha256(legacy_batch_manifest).hexdigest()
        batch_mac = hmac.new(KEY, digestmod=hashlib.sha256)
        batch_mac.update(b"VulnGym sealed snapshot batch attestation v1\0")
        batch_mac.update(KEY_ID.encode("ascii"))
        batch_mac.update(b"\0")
        batch_mac.update(legacy_batch_manifest)
        legacy_batch_attestation = _canonical(
            {
                "algorithm": "HMAC-SHA256",
                "contract_version": "vulngym.sealed-snapshot-batch.v1",
                "key_id": KEY_ID,
                "mac": batch_mac.hexdigest(),
                "manifest_sha256": batch_manifest_sha256,
            }
        ) + b"\n"
        batch_manifest_path.write_bytes(legacy_batch_manifest)
        (batch_control / "attestation.json").write_bytes(legacy_batch_attestation)

        with self.assertRaises(SnapshotBatchError) as captured:
            self._verify("legacy-v1-batch", batch_manifest_sha256)
        self.assertEqual(captured.exception.code, "batch_attestation_invalid")

    def test_batch_rejects_a_pinned_policy_v3_header(self) -> None:
        prepared = self._prepare("policy-v3-batch")
        control = prepared.batch_root / "control"
        manifest_path = control / "manifest.jsonl"
        records = [json.loads(line) for line in manifest_path.read_bytes().splitlines()]
        policy = records[0]["snapshot_policy"]
        policy["policy_version"] = "vulngym.portable-source-tree.v3"
        policy["max_file_bytes"] = 16 * 1024 * 1024
        policy["max_total_bytes"] = 512 * 1024 * 1024
        manifest = b"".join(_canonical(record) + b"\n" for record in records)
        manifest_sha256 = hashlib.sha256(manifest).hexdigest()
        mac = hmac.new(KEY, digestmod=hashlib.sha256)
        mac.update(snapshot_batch._BATCH_ATTESTATION_DOMAIN)
        mac.update(KEY_ID.encode("ascii"))
        mac.update(b"\0")
        mac.update(manifest)
        attestation = _canonical(
            {
                "algorithm": "HMAC-SHA256",
                "contract_version": snapshot_batch.BATCH_CONTRACT_VERSION,
                "key_id": KEY_ID,
                "mac": mac.hexdigest(),
                "manifest_sha256": manifest_sha256,
            }
        ) + b"\n"
        manifest_path.write_bytes(manifest)
        (control / "attestation.json").write_bytes(attestation)

        with self.assertRaises(SnapshotBatchError) as captured:
            self._verify("policy-v3-batch", manifest_sha256)
        self.assertEqual(captured.exception.code, "batch_manifest_invalid")

    def test_source_map_digest_coverage_duplicates_extras_and_schema(self) -> None:
        with self.assertRaisesRegex(SnapshotBatchError, "digest"):
            self._prepare(expected_source_map_sha256="0" * 64)

        exact_sources = [
            {
                "commit": task.commit,
                "repo_root": str(self.repo),
                "repo_url": task.repo_url,
            }
            for task in self.tasks
        ]
        self.source_map_sha256 = self._write_source_map(exact_sources[:1])
        with self.assertRaisesRegex(SnapshotBatchError, "coverage"):
            self._prepare()

        self.source_map_sha256 = self._write_source_map(exact_sources + [exact_sources[0]])
        with self.assertRaisesRegex(SnapshotBatchError, "unique"):
            self._prepare()

        extra = {
            "commit": "f" * 40,
            "repo_root": str(self.repo),
            "repo_url": "https://github.com/example/extra-source",
        }
        self.source_map_sha256 = self._write_source_map(exact_sources + [extra])
        with self.assertRaisesRegex(SnapshotBatchError, "coverage"):
            self._prepare()

        self.source_map_sha256 = self._write_source_map(exact_sources, forbidden="field")
        with self.assertRaisesRegex(SnapshotBatchError, "contract"):
            self._prepare()

    def test_duplicate_answer_free_task_is_rejected(self) -> None:
        self.tasks_sha256 = self._write_export((self.tasks[0], self.tasks[0]))
        self.source_map_sha256 = self._write_source_map(
            [
                {
                    "commit": self.tasks[0].commit,
                    "repo_root": str(self.repo),
                    "repo_url": self.tasks[0].repo_url,
                }
            ]
        )
        with self.assertRaisesRegex(SnapshotBatchError, "uniqueness"):
            self._prepare()

    def test_official_split_count_is_fixed(self) -> None:
        with self.assertRaisesRegex(SnapshotBatchError, "binding"):
            prepare_snapshot_batch(
                self.export_dir,
                expected_tasks_sha256=self.tasks_sha256,
                expected_public_manifest_sha256=PROFILE_MANIFEST_SHA256,
                source_map_path=self.source_map,
                expected_source_map_sha256=self.source_map_sha256,
                output_dir=self.root / "official-count",
                attestation_key=KEY,
                key_id=KEY_ID,
            )
        self.assertFalse((self.root / "official-count").exists())

    def test_duplicate_repository_snapshot_is_rejected(self) -> None:
        duplicate_snapshot = SnapshotTaskSpec(
            task_id=TASK_TWO,
            repo_url=REPO_URL,
            commit=self.commit_one,
            split="train",
        )
        self.tasks_sha256 = self._write_export((self.tasks[0], duplicate_snapshot))
        self.source_map_sha256 = self._write_source_map(
            [
                {
                    "commit": self.commit_one,
                    "repo_root": str(self.repo),
                    "repo_url": REPO_URL,
                }
            ]
        )
        with self.assertRaisesRegex(SnapshotBatchError, "snapshot uniqueness"):
            self._prepare()

    def test_tamper_wrong_key_and_pinned_manifest_digest_are_rejected(self) -> None:
        prepared = self._prepare("tree-tamper")
        with self.assertRaises(SnapshotBatchError):
            self._verify(
                "tree-tamper", prepared.manifest_sha256, attestation_key=OTHER_KEY
            )
        tree_file = prepared.batch_root / "bundles" / TASK_ONE / "tree" / "app.py"
        tree_file.write_bytes(b"tampered\n")
        with self.assertRaisesRegex(SnapshotBatchError, "deep verification"):
            self._verify("tree-tamper", prepared.manifest_sha256)

        second = self._prepare("manifest-tamper")
        manifest = second.batch_root / "control" / "manifest.jsonl"
        manifest.write_bytes(manifest.read_bytes() + b"\n")
        with self.assertRaisesRegex(SnapshotBatchError, "pinned digest"):
            self._verify("manifest-tamper", second.manifest_sha256)

    def test_existing_target_is_preserved_without_overwrite(self) -> None:
        target = self.root / "sealed-batch"
        target.mkdir()
        sentinel = target / "sentinel.txt"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(SnapshotBatchError, "cannot be replaced") as caught:
            self._prepare()
        self.assertEqual(5, caught.exception.exit_status)
        self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))

    def test_mid_batch_failure_rolls_back_outer_staging(self) -> None:
        real_prepare = snapshot_batch.prepare_sealed_snapshot
        calls = 0

        def fail_second(*args: object, **kwargs: object):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise SealedSnapshotError("injected_failure", "injected")
            return real_prepare(*args, **kwargs)

        with mock.patch.object(
            snapshot_batch, "prepare_sealed_snapshot", side_effect=fail_second
        ), self.assertRaises(SnapshotBatchError):
            self._prepare("rollback")
        self.assertFalse((self.root / "rollback").exists())
        self.assertEqual([], list(self.root.glob(".rollback.*.staging")))

    def test_cleanup_preserves_staging_with_unregistered_late_child(self) -> None:
        captured_staging: list[Path] = []

        def inject_unknown(state: object) -> None:
            staging = state.staging
            captured_staging.append(staging)
            unknown = staging / "bundles" / TASK_ONE / "tree" / "unregistered.txt"
            unknown.write_bytes(b"do not delete\n")
            raise SnapshotBatchError(
                "injected_publication_failure", "injected", exit_status=5
            )

        with mock.patch.object(
            snapshot_batch, "_publish_noreplace", side_effect=inject_unknown
        ), self.assertRaises(SnapshotBatchError):
            self._prepare("preserve-unknown")

        self.assertEqual(1, len(captured_staging))
        staging = captured_staging[0]
        unknown = staging / "bundles" / TASK_ONE / "tree" / "unregistered.txt"
        self.assertTrue(staging.is_dir())
        self.assertEqual(b"do not delete\n", unknown.read_bytes())
        self.assertTrue((staging / "bundles").is_dir())
        self.assertTrue(
            (staging / "bundles" / TASK_ONE / "tree" / "app.py").is_file()
        )
        self.assertTrue((staging / "control" / "manifest.jsonl").is_file())
        self.assertFalse((self.root / "preserve-unknown").exists())

    def test_canonical_parser_maps_lone_surrogate_to_batch_error(self) -> None:
        with self.assertRaises(SnapshotBatchError) as caught:
            snapshot_batch._parse_canonical_line(
                b'{"value":"\\ud800"}\n', status=2
            )
        self.assertEqual("invalid_json", caught.exception.code)
        self.assertEqual(2, caught.exception.exit_status)

    def test_batch_manifest_policy_comparison_distinguishes_bool_from_int(self) -> None:
        policy = SnapshotPolicy(max_depth=1)
        prepared = self._prepare("policy-type", policy=policy)
        manifest_path = prepared.batch_root / "control" / "manifest.jsonl"
        lines = manifest_path.read_bytes().splitlines(keepends=True)
        header = json.loads(lines[0])
        header["snapshot_policy"]["max_depth"] = True
        tampered = _canonical(header) + b"\n" + b"".join(lines[1:])

        with mock.patch.object(
            snapshot_batch, "_OFFICIAL_SPLIT_COUNTS", {"train": 2, "test": 1}
        ), self.assertRaises(SnapshotBatchError) as caught:
            snapshot_batch._parse_batch_manifest(tampered, policy=policy)
        self.assertEqual("batch_manifest_invalid", caught.exception.code)

    def test_v3_task_identity_and_counter_errors_are_stable_batch_errors(self) -> None:
        prepared = self._prepare("v3-invalid-task")
        manifest = prepared.batch_root / "control" / "manifest.jsonl"
        original = [json.loads(line) for line in manifest.read_bytes().splitlines()]
        cases = (
            ("root_tree", "x" * 40),
            ("gitlink_count", -1),
            ("materialized_bytes", original[1]["materialized_bytes"] + 1),
        )
        for field, value in cases:
            with self.subTest(field=field):
                records = copy.deepcopy(original)
                records[1][field] = value
                task_lines = tuple(_canonical(item) + b"\n" for item in records[1:-1])
                records[-1]["batch_content_root"] = snapshot_batch._batch_content_root(task_lines)
                payload = _canonical(records[0]) + b"\n" + b"".join(task_lines) + _canonical(records[-1]) + b"\n"
                with mock.patch.object(snapshot_batch, "_OFFICIAL_SPLIT_COUNTS", {"train": 2, "test": 1}), self.assertRaises(SnapshotBatchError) as caught:
                    snapshot_batch._parse_batch_manifest(payload, policy=snapshot_batch.DEFAULT_SNAPSHOT_POLICY)
                self.assertEqual(caught.exception.code, "batch_manifest_invalid")
                self.assertEqual(caught.exception.exit_status, 4)

    def test_cross_bundle_mutation_during_final_pass_is_rejected(self) -> None:
        real_verify = snapshot_batch.verify_sealed_snapshot
        calls = 0

        def mutate_first_after_last_verify(*args: object, **kwargs: object):
            nonlocal calls
            verified = real_verify(*args, **kwargs)
            calls += 1
            if calls == 4:
                first = Path(args[0]).parent / TASK_ONE / "tree" / "app.py"
                first.write_bytes(b"cross-bundle tamper\n")
            return verified

        with mock.patch.object(
            snapshot_batch,
            "verify_sealed_snapshot",
            side_effect=mutate_first_after_last_verify,
        ), self.assertRaises(SnapshotBatchError):
            self._prepare("cross-window-prepare")
        self.assertFalse((self.root / "cross-window-prepare").exists())

        prepared = self._prepare("cross-window-verify")
        calls = 0
        with mock.patch.object(
            snapshot_batch,
            "verify_sealed_snapshot",
            side_effect=mutate_first_after_last_verify,
        ), self.assertRaises(SnapshotBatchError):
            self._verify("cross-window-verify", prepared.manifest_sha256)

    def test_prepare_failure_reports_path_free_pass_and_task_ordinal(self) -> None:
        real_verify = snapshot_batch.verify_sealed_snapshot
        cases = (
            (1, "pass1_task_001_snapshot_unavailable"),
            (2, "pass1_task_002_snapshot_unavailable"),
            (3, "pass2_task_001_snapshot_unavailable"),
            (4, "pass2_task_002_snapshot_unavailable"),
        )
        for failure_call, diagnostic_code in cases:
            calls = 0

            def fail_selected_verification(*args: object, **kwargs: object):
                nonlocal calls
                calls += 1
                if calls == failure_call:
                    raise SealedSnapshotError(
                        "snapshot_unavailable", "injected path-free failure"
                    )
                return real_verify(*args, **kwargs)

            output_name = f"diagnostic-{failure_call}"
            with self.subTest(failure_call=failure_call), mock.patch.object(
                snapshot_batch,
                "verify_sealed_snapshot",
                side_effect=fail_selected_verification,
            ), self.assertRaises(SnapshotBatchError) as captured:
                self._prepare(output_name)
            self.assertEqual(
                "transaction_verification_failed", captured.exception.code
            )
            self.assertEqual(
                diagnostic_code, captured.exception.diagnostic_code
            )
            self.assertNotIn(TASK_ONE, diagnostic_code)
            self.assertNotIn(TASK_TWO, diagnostic_code)
            self.assertFalse((self.root / output_name).exists())

    def test_prepare_failure_prefers_path_free_inner_diagnostic(self) -> None:
        def fail_verification(*args: object, **kwargs: object):
            raise SealedSnapshotError(
                "snapshot_changed",
                "injected identity drift",
                diagnostic_code="tree_directory_scan_identity_changed",
            )

        with mock.patch.object(
            snapshot_batch,
            "verify_sealed_snapshot",
            side_effect=fail_verification,
        ), self.assertRaises(SnapshotBatchError) as captured:
            self._prepare("detailed-diagnostic")
        self.assertEqual(
            "pass1_task_001_tree_directory_scan_identity_changed",
            captured.exception.diagnostic_code,
        )
        self.assertLessEqual(len(captured.exception.diagnostic_code or ""), 64)
        self.assertFalse((self.root / "detailed-diagnostic").exists())

    def test_verification_diagnostic_falls_back_to_bounded_outer_code(self) -> None:
        error = SimpleNamespace(
            code="snapshot_changed",
            diagnostic_code="a" * 64,
        )
        diagnostic = snapshot_batch._verification_diagnostic_code(
            "pass1", 1, error
        )
        self.assertEqual("pass1_task_001_snapshot_changed", diagnostic)
        self.assertLessEqual(len(diagnostic), 64)

    def test_batch_error_retains_public_diagnostic_length_contract(self) -> None:
        diagnostic = "a" * 128
        error = SnapshotBatchError(
            "transaction_verification_failed",
            "bounded public diagnostic",
            exit_status=5,
            diagnostic_code=diagnostic,
        )
        self.assertEqual(diagnostic, error.diagnostic_code)
        with self.assertRaises(ValueError):
            SnapshotBatchError(
                "transaction_verification_failed",
                "oversized public diagnostic",
                exit_status=5,
                diagnostic_code="a" * 129,
            )

    @unittest.skipUnless(os.name == "nt", "Windows device-path alias contract")
    def test_windows_subst_drive_is_canonicalized_by_object_identity(self) -> None:
        drive = next(
            (
                f"{letter}:"
                for letter in reversed("PQRSTUVWXYZ")
                if not Path(f"{letter}:\\").exists()
            ),
            None,
        )
        self.assertIsNotNone(drive, "no free drive letter for SUBST regression")
        assert drive is not None
        created = subprocess.run(
            ["subst", drive, str(self.root)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(0, created.returncode, "SUBST setup failed")
        try:
            alias_root = Path(f"{drive}\\")
            canonical_directory = snapshot_batch._canonical_existing_path(
                alias_root / self.export_dir.name,
                directory=True,
                status=2,
            )
            canonical_file = snapshot_batch._canonical_existing_path(
                alias_root / self.source_map.name,
                directory=False,
                status=2,
            )
            expected_directory = snapshot_batch._windows_final_path(
                self.export_dir,
                directory=True,
            )
            expected_file = snapshot_batch._windows_final_path(
                self.source_map,
                directory=False,
            )
            self.assertEqual(
                os.path.normcase(os.path.normpath(str(expected_directory))),
                os.path.normcase(os.path.normpath(str(canonical_directory))),
            )
            self.assertEqual(
                os.path.normcase(os.path.normpath(str(expected_file))),
                os.path.normcase(os.path.normpath(str(canonical_file))),
            )
        finally:
            removed = subprocess.run(
                ["subst", drive, "/D"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(0, removed.returncode, "SUBST cleanup failed")

    @unittest.skipUnless(os.name == "nt", "Windows device-path alias contract")
    def test_windows_device_alias_cannot_bypass_output_overlap(self) -> None:
        aliased = Path("\\\\?\\" + str(self.repo / "aliased-output"))
        with self.assertRaisesRegex(SnapshotBatchError, "device-path"):
            self._prepare(output_dir=aliased)
        self.assertFalse((self.repo / "aliased-output").exists())

    def test_aggregate_file_and_byte_caps_fail_closed(self) -> None:
        for name, constant in (
            ("aggregate-files", "_MAX_BATCH_TOTAL_FILES"),
            ("aggregate-nodes", "_MAX_BATCH_TOTAL_NODES"),
            ("aggregate-bytes", "_MAX_BATCH_TOTAL_BYTES"),
        ):
            with self.subTest(constant=constant), mock.patch.object(
                snapshot_batch, constant, 0
            ), self.assertRaisesRegex(SnapshotBatchError, "aggregate") as caught:
                self._prepare(name)
            self.assertEqual(3, caught.exception.exit_status)
            self.assertFalse((self.root / name).exists())
            self.assertEqual([], list(self.root.glob(f".{name}.*.staging")))

    def test_output_path_conflict_and_absolute_path_non_disclosure(self) -> None:
        with self.assertRaisesRegex(SnapshotBatchError, "overlaps") as caught:
            self._prepare(output_dir=self.repo / "sealed-output")
        self.assertEqual(2, caught.exception.exit_status)

        prepared = self._prepare("path-free")
        secret = str(self.repo).encode("utf-8")
        control_payloads: list[bytes] = []
        for directory, _, names in os.walk(prepared.batch_root):
            for name in names:
                path = Path(directory) / name
                if path.parent.name == "control":
                    control_payloads.append(path.read_bytes())
        self.assertTrue(control_payloads)
        self.assertNotIn(secret, b"".join(control_payloads))
        lowered = b"".join(control_payloads).lower()
        for forbidden in (b'"gold"', b'"advisory"', b'"entry"'):
            self.assertNotIn(forbidden, lowered)


if __name__ == "__main__":
    unittest.main()
