from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import vulngym_agent.benchmark.harness as harness


def _task(marker: str) -> harness.SnapshotTaskSpec:
    return harness.SnapshotTaskSpec(
        task_id=f"VG-TEST-{marker * 20}",
        repo_url=f"https://github.com/example/project-{marker.lower()}",
        commit=marker.lower() * 40,
        split="test",
    )


class ArtifactIndexWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tasks = (_task("A"), _task("B"))
        self.bundles = tuple(
            harness.ArtifactBundleDigest(task.task_id, str(position) * 64)
            for position, task in enumerate(self.tasks, 1)
        )

    def test_roundtrip_is_canonical_and_uses_task_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "index.json"
            with mock.patch.object(
                harness,
                "load_artifact_bundle_index",
                wraps=harness.load_artifact_bundle_index,
            ) as reader:
                digest = harness.write_artifact_bundle_index(
                    output,
                    split="test",
                    tasks=self.tasks,
                    bundles=tuple(reversed(self.bundles)),
                )

            expected = json.dumps(
                {
                    "bundles": [
                        {
                            "dataset_sha256": bundle.dataset_sha256,
                            "task_id": bundle.task_id,
                        }
                        for bundle in self.bundles
                    ],
                    "contract_version": harness.ARTIFACT_INDEX_CONTRACT_VERSION,
                    "manifest_sha256": harness.PROFILE_MANIFEST_SHA256,
                    "profile_id": harness.PROFILE_ID,
                    "split": "test",
                },
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            self.assertEqual(output.read_bytes(), expected)
            self.assertEqual(digest, hashlib.sha256(expected).hexdigest())
            self.assertLessEqual(len(expected), harness.MAX_ARTIFACT_INDEX_BYTES)
            reader.assert_called_once_with(
                output,
                expected_sha256=digest,
                split="test",
                tasks=self.tasks,
            )
            loaded = harness.load_artifact_bundle_index(
                output,
                expected_sha256=digest,
                split="test",
                tasks=self.tasks,
            )
            self.assertEqual(loaded.bundles, self.bundles)

    def test_existing_output_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "index.json"
            sentinel = b"caller-owned\n"
            output.write_bytes(sentinel)

            with self.assertRaises(harness.BenchmarkHarnessError) as captured:
                harness.write_artifact_bundle_index(
                    output,
                    split="test",
                    tasks=self.tasks,
                    bundles=self.bundles,
                )

            self.assertEqual(captured.exception.code, "output_exists")
            self.assertFalse(captured.exception.committed)
            self.assertEqual(output.read_bytes(), sentinel)

    def test_write_interrupt_and_rename_conflict_never_publish_staging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "index.json"
            with mock.patch.object(
                harness, "_write_all", side_effect=KeyboardInterrupt()
            ):
                with self.assertRaises(KeyboardInterrupt):
                    harness.write_artifact_bundle_index(
                        output,
                        split="test",
                        tasks=self.tasks,
                        bundles=self.bundles,
                    )
            self.assertFalse(output.exists())
            retained = tuple(root.iterdir())
            self.assertEqual(len(retained), 1)
            self.assertTrue(retained[0].name.startswith(".index.json."))
            self.assertTrue(retained[0].name.endswith(".staging"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "index.json"
            sentinel = b"concurrent-winner\n"
            original_rename = harness._rename_directory_noreplace

            def collide(
                source: Path,
                destination: Path,
                *,
                source_dir_fd: int | None = None,
                destination_dir_fd: int | None = None,
            ) -> None:
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_BINARY", 0)
                )
                if destination_dir_fd is None:
                    descriptor = os.open(destination, flags, 0o600)
                else:
                    descriptor = os.open(
                        destination,
                        flags,
                        0o600,
                        dir_fd=destination_dir_fd,
                    )
                try:
                    os.write(descriptor, sentinel)
                finally:
                    os.close(descriptor)
                original_rename(
                    source,
                    destination,
                    source_dir_fd=source_dir_fd,
                    destination_dir_fd=destination_dir_fd,
                )

            with mock.patch.object(
                harness, "_rename_directory_noreplace", side_effect=collide
            ):
                with self.assertRaises(harness.BenchmarkHarnessError) as captured:
                    harness.write_artifact_bundle_index(
                        output,
                        split="test",
                        tasks=self.tasks,
                        bundles=self.bundles,
                    )
            self.assertEqual(captured.exception.code, "output_exists")
            self.assertFalse(captured.exception.committed)
            self.assertEqual(output.read_bytes(), sentinel)
            retained = tuple(path for path in root.iterdir() if path != output)
            self.assertEqual(len(retained), 1)
            self.assertTrue(retained[0].name.startswith(".index.json."))
            self.assertTrue(retained[0].name.endswith(".staging"))

    def test_rename_commit_followed_by_error_is_reported_as_committed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "index.json"
            original_rename = harness._rename_directory_noreplace

            def commit_then_error(
                source: Path,
                destination: Path,
                *,
                source_dir_fd: int | None = None,
                destination_dir_fd: int | None = None,
            ) -> None:
                original_rename(
                    source,
                    destination,
                    source_dir_fd=source_dir_fd,
                    destination_dir_fd=destination_dir_fd,
                )
                raise OSError("rename completed before acknowledgement failed")

            with mock.patch.object(
                harness,
                "_rename_directory_noreplace",
                side_effect=commit_then_error,
            ):
                with self.assertRaises(harness.BenchmarkHarnessError) as captured:
                    harness.write_artifact_bundle_index(
                        output,
                        split="test",
                        tasks=self.tasks,
                        bundles=self.bundles,
                    )

            self.assertTrue(captured.exception.committed)
            self.assertTrue(output.is_file())
            payload = output.read_bytes()
            loaded = harness.load_artifact_bundle_index(
                output,
                expected_sha256=hashlib.sha256(payload).hexdigest(),
                split="test",
                tasks=self.tasks,
            )
            self.assertEqual(loaded.bundles, self.bundles)

    def test_exact_mutated_values_are_rejected_without_callbacks(self) -> None:
        callbacks: list[str] = []

        class CallbackString(str):
            def __eq__(self, other):
                callbacks.append("eq")
                return super().__eq__(other)

            def __hash__(self):
                callbacks.append("hash")
                return super().__hash__()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            malformed_task = _task("C")
            object.__setattr__(
                malformed_task,
                "repo_url",
                CallbackString(malformed_task.repo_url),
            )
            malformed_bundle = harness.ArtifactBundleDigest(
                self.tasks[0].task_id, "3" * 64
            )
            object.__setattr__(
                malformed_bundle,
                "dataset_sha256",
                CallbackString(malformed_bundle.dataset_sha256),
            )
            cases = (
                ((malformed_task,), (harness.ArtifactBundleDigest(malformed_task.task_id, "4" * 64),)),
                ((self.tasks[0],), (malformed_bundle,)),
            )
            for position, (tasks, bundles) in enumerate(cases):
                output = root / f"index-{position}.json"
                with self.subTest(position=position):
                    with self.assertRaises(harness.BenchmarkHarnessError) as captured:
                        harness.write_artifact_bundle_index(
                            output,
                            split="test",
                            tasks=tasks,
                            bundles=bundles,
                        )
                    self.assertEqual(
                        captured.exception.code, "invalid_writer_argument"
                    )
                    self.assertFalse(output.exists())
            self.assertEqual(callbacks, [])

    def test_membership_size_and_protected_path_fail_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "index.json"

            with self.assertRaises(harness.BenchmarkHarnessError) as captured:
                harness.write_artifact_bundle_index(
                    output,
                    split="test",
                    tasks=self.tasks,
                    bundles=self.bundles[:1],
                )
            self.assertEqual(
                captured.exception.code, "artifact_index_membership_mismatch"
            )
            self.assertFalse(output.exists())

            with mock.patch.object(harness, "MAX_ARTIFACT_INDEX_BYTES", 1):
                with self.assertRaises(harness.BenchmarkHarnessError) as captured:
                    harness.write_artifact_bundle_index(
                        output,
                        split="test",
                        tasks=self.tasks,
                        bundles=self.bundles,
                    )
            self.assertEqual(captured.exception.code, "artifact_index_too_large")
            self.assertFalse(output.exists())

            with self.assertRaises(harness.BenchmarkHarnessError) as captured:
                harness.write_artifact_bundle_index(
                    output,
                    split="test",
                    tasks=self.tasks,
                    bundles=self.bundles,
                    protected_paths=(root,),
                )
            self.assertEqual(captured.exception.code, "path_overlap")
            self.assertFalse(output.exists())

    def test_readback_mismatch_is_reported_as_committed(self) -> None:
        wrong = harness.ArtifactBundleIndex(
            contract_version=harness.ARTIFACT_INDEX_CONTRACT_VERSION,
            profile_id=harness.PROFILE_ID,
            manifest_sha256=harness.PROFILE_MANIFEST_SHA256,
            split="test",
            bundles=tuple(reversed(self.bundles)),
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "index.json"
            with mock.patch.object(
                harness, "load_artifact_bundle_index", return_value=wrong
            ):
                with self.assertRaises(harness.BenchmarkHarnessError) as captured:
                    harness.write_artifact_bundle_index(
                        output,
                        split="test",
                        tasks=self.tasks,
                        bundles=self.bundles,
                    )
            self.assertEqual(
                captured.exception.code, "artifact_index_readback_failed"
            )
            self.assertTrue(captured.exception.committed)
            self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
