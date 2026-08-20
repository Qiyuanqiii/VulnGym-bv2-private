from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

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

    def _verify(self, name: str, manifest_sha256: str, **overrides: object):
        arguments: dict[str, object] = {
            "expected_manifest_sha256": manifest_sha256,
            "attestation_key": KEY,
            "expected_key_id": KEY_ID,
        }
        arguments.update(overrides)
        with mock.patch.object(
            snapshot_batch, "_OFFICIAL_SPLIT_COUNTS", {"train": 2, "test": 1}
        ):
            return verify_snapshot_batch(self.root / name, **arguments)

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
