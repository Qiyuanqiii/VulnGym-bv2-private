from __future__ import annotations

from dataclasses import FrozenInstanceError
import os
from pathlib import Path
import pickle
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
import vulngym_agent.benchmark as benchmark_api
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark import sealed_tree_access as access_module
from vulngym_agent.benchmark.sealed_snapshot import (
    SealedSnapshotError,
    prepare_sealed_snapshot,
)
from vulngym_agent.benchmark.sealed_tree_access import (
    BoundSealedTree,
    SealedTreeAccessError,
    SealedTreeAccessLimits,
    bind_sealed_tree,
)
from vulngym_agent.tools.git.repository import GitRepository


TASK_ID = "VG-TRAIN-0123456789ABCDEF0123"
REPO_URL = "https://github.com/example/discovery-source"
KEY = b"trusted discovery evaluator key!!"
OTHER_KEY = b"different discovery evaluator key!"
KEY_ID = "discovery-evaluator-2026-01"
GIT_SYMLINK_PATH = "parent-link"
GIT_SYMLINK_TARGET = b"../../outside/source.py"


class SealedTreeAccessTests(unittest.TestCase):
    def test_access_api_is_exported_from_the_benchmark_package(self) -> None:
        self.assertIs(BoundSealedTree, benchmark_api.BoundSealedTree)
        self.assertIs(bind_sealed_tree, benchmark_api.bind_sealed_tree)

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.repo_path = self.root / "repo"
        self.repo_path.mkdir()
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.name", "VulnGym Test")
        self._git("config", "user.email", "vulngym@example.invalid")
        self._git("config", "core.autocrlf", "false")
        (self.repo_path / "src").mkdir()
        (self.repo_path / "src" / "app.py").write_bytes(
            b"def entry(value):\n    return sink(value)\n"
        )
        (self.repo_path / "empty.txt").write_bytes(b"")
        (self.repo_path / "payload.bin").write_bytes(b"\x00\xff\x10\n")
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "source")
        link_blob = subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=self.repo_path,
            input=GIT_SYMLINK_TARGET,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.decode("ascii").strip()
        self._git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"120000,{link_blob},{GIT_SYMLINK_PATH}",
        )
        self._git("commit", "-q", "-m", "Git symlink bytes")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()
        self.snapshot_root = self.root / "sealed"
        prepared = prepare_sealed_snapshot(
            GitRepository(self.repo_path),
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=self.commit,
            output_dir=self.snapshot_root,
            attestation_key=KEY,
            key_id=KEY_ID,
        )
        self.prepared = prepared
        self.task = DiscoveryTaskInputV1(
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=self.commit,
            instruction_id=INSTRUCTION_ID,
            snapshot_manifest_sha256=prepared.manifest_sha256,
            snapshot_content_root=prepared.content_root,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repo_path,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _bind(
        self, *, limits: SealedTreeAccessLimits | None = None
    ) -> BoundSealedTree:
        arguments = {}
        if limits is not None:
            arguments["limits"] = limits
        return bind_sealed_tree(
            self.task,
            self.snapshot_root,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
            **arguments,
        )

    @staticmethod
    def _make_writable(path: Path) -> None:
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def test_factory_calls_complete_verifier_and_binds_exact_task_metadata(self) -> None:
        real_verify = access_module.verify_sealed_snapshot
        with mock.patch.object(
            access_module,
            "verify_sealed_snapshot",
            wraps=real_verify,
        ) as verifier:
            bound = self._bind()
        self.assertEqual(2, verifier.call_count)
        first = verifier.call_args_list[0]
        self.assertEqual(self.snapshot_root, first.args[0])
        self.assertEqual(TASK_ID, first.kwargs["expected_task_id"])
        self.assertEqual(REPO_URL, first.kwargs["expected_repo_url"])
        self.assertEqual(self.commit, first.kwargs["expected_commit"])

        self.assertEqual(self.task.snapshot_id, bound.snapshot_id)
        self.assertEqual(self.prepared.manifest_sha256, bound.manifest_sha256)
        self.assertEqual(self.prepared.content_root, bound.content_root)
        bound.finalize()

    def test_manifest_or_content_binding_mismatch_fails_closed(self) -> None:
        for field in ("snapshot_manifest_sha256", "snapshot_content_root"):
            values = {
                "task_id": TASK_ID,
                "repo_url": REPO_URL,
                "commit": self.commit,
                "instruction_id": INSTRUCTION_ID,
                "snapshot_manifest_sha256": self.prepared.manifest_sha256,
                "snapshot_content_root": self.prepared.content_root,
            }
            values[field] = "f" * 64
            task = DiscoveryTaskInputV1(**values)
            with self.subTest(field=field), self.assertRaises(
                SealedTreeAccessError
            ) as captured:
                bind_sealed_tree(
                    task,
                    self.snapshot_root,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                )
            self.assertEqual("invalid_binding", captured.exception.code)

    def test_attestation_material_is_strictly_bytes_like_and_bounded(self) -> None:
        released = memoryview(KEY)
        released.release()
        for invalid in (None, "key", [1, 2, 3], 2**31, released):
            with self.subTest(value=type(invalid).__name__), self.assertRaises(
                SealedTreeAccessError
            ) as captured:
                bind_sealed_tree(
                    self.task,
                    self.snapshot_root,
                    attestation_key=invalid,  # type: ignore[arg-type]
                    expected_key_id=KEY_ID,
                )
            self.assertEqual("invalid_argument", captured.exception.code)

        for invalid in (b"short", b"x" * 4_097):
            with self.subTest(size=len(invalid)), self.assertRaises(
                SealedTreeAccessError
            ) as captured:
                bind_sealed_tree(
                    self.task,
                    self.snapshot_root,
                    attestation_key=invalid,
                    expected_key_id=KEY_ID,
                )
            self.assertEqual("invalid_argument", captured.exception.code)

        bound = bind_sealed_tree(
            self.task,
            self.snapshot_root,
            attestation_key=memoryview(KEY),
            expected_key_id=KEY_ID,
        )
        self.assertTrue(bound.finalize().verification_succeeded)

    def test_inventory_is_canonical_immutable_and_contains_no_host_paths(self) -> None:
        bound = self._bind()
        inventory = bound.inventory()
        self.assertEqual(
            tuple(sorted(item.path for item in self.prepared.files)),
            tuple(item.path for item in inventory),
        )
        self.assertEqual(self.prepared.file_count, len(inventory))
        with self.assertRaises(FrozenInstanceError):
            inventory[0].size = 0  # type: ignore[misc]

        representation = repr(bound)
        self.assertNotIn(str(self.root), representation)
        self.assertNotIn(str(self.snapshot_root), representation)
        self.assertFalse(hasattr(bound, "snapshot_root"))
        self.assertFalse(hasattr(bound, "agent_tree"))
        self.assertFalse(hasattr(bound, "attestation_key"))
        with self.assertRaises(TypeError):
            pickle.dumps(bound)
        bound.finalize()

    def test_read_is_exact_manifest_only_and_records_content_bound_usage(self) -> None:
        bound = self._bind()
        expected = b"def entry(value):\n    return sink(value)\n"
        self.assertEqual(
            expected,
            bound.read_bytes("src/app.py", maximum_bytes=len(expected)),
        )
        self.assertEqual(b"", bound.read_bytes("empty.txt", maximum_bytes=0))
        for path in (
            "src/../src/app.py",
            "SRC/app.py",
            "/src/app.py",
            "src\\app.py",
            ".git/config",
        ):
            with self.subTest(path=path), self.assertRaises(
                SealedTreeAccessError
            ) as captured:
                bound.read_bytes(path, maximum_bytes=1024)
            self.assertEqual("source_not_found", captured.exception.code)

        usage = bound.usage_snapshot()
        self.assertEqual(2, usage.read_calls)
        self.assertEqual(len(expected), usage.bytes_read)
        self.assertEqual((1, 2), tuple(item.sequence for item in usage.reads))
        self.assertEqual(
            ("src/app.py", "empty.txt"), tuple(item.path for item in usage.reads)
        )
        self.assertFalse(usage.finalized)
        self.assertFalse(usage.verification_succeeded)

        final = bound.finalize()
        self.assertTrue(final.finalized)
        self.assertTrue(final.verification_succeeded)
        with self.assertRaises(SealedTreeAccessError) as captured:
            bound.read_bytes("src/app.py", maximum_bytes=1024)
        self.assertEqual("access_finalized", captured.exception.code)

    def test_git_symlink_record_is_read_as_regular_raw_data(self) -> None:
        materialized = self.prepared.agent_tree / GIT_SYMLINK_PATH
        value = os.lstat(materialized)
        self.assertTrue(stat.S_ISREG(value.st_mode))
        self.assertFalse(stat.S_ISLNK(value.st_mode))
        record = next(
            item for item in self.prepared.files if item.path == GIT_SYMLINK_PATH
        )
        self.assertEqual("120000", record.git_mode)

        bound = self._bind()
        inventory_record = next(
            item for item in bound.inventory() if item.path == GIT_SYMLINK_PATH
        )
        self.assertEqual("120000", inventory_record.git_mode)
        self.assertEqual(
            GIT_SYMLINK_TARGET,
            bound.read_bytes(
                GIT_SYMLINK_PATH, maximum_bytes=len(GIT_SYMLINK_TARGET)
            ),
        )
        self.assertTrue(bound.finalize().verification_succeeded)

    def test_read_and_inventory_budgets_are_hard_and_failed_reads_are_not_logged(self) -> None:
        limits = SealedTreeAccessLimits(
            max_inventory_calls=1,
            max_read_calls=1,
            max_bytes_per_read=4,
            max_total_bytes_read=4,
        )
        bound = self._bind(limits=limits)
        bound.inventory()
        with self.assertRaises(SealedTreeAccessError) as captured:
            bound.inventory()
        self.assertEqual("source_limit_exceeded", captured.exception.code)

        with self.assertRaises(SealedTreeAccessError) as captured:
            bound.read_bytes("src/app.py", maximum_bytes=4)
        self.assertEqual("source_limit_exceeded", captured.exception.code)
        self.assertEqual(b"\x00\xff\x10\n", bound.read_bytes("payload.bin", maximum_bytes=4))
        with self.assertRaises(SealedTreeAccessError) as captured:
            bound.read_bytes("empty.txt", maximum_bytes=0)
        self.assertEqual("source_limit_exceeded", captured.exception.code)
        self.assertEqual(1, bound.usage_snapshot().read_calls)
        bound.finalize()

    def test_same_byte_file_replacement_is_rejected_by_identity(self) -> None:
        bound = self._bind()
        path = self.prepared.agent_tree / "src" / "app.py"
        data = path.read_bytes()
        self._make_writable(path)
        path.unlink()
        path.write_bytes(data)

        with self.assertRaises(SealedTreeAccessError) as captured:
            bound.read_bytes("src/app.py", maximum_bytes=len(data))
        self.assertEqual("source_changed", captured.exception.code)
        self.assertNotIn(str(self.root), str(captured.exception))
        invalidated = bound.usage_snapshot()
        self.assertTrue(invalidated.finalized)
        self.assertFalse(invalidated.verification_succeeded)

    def test_byte_tamper_is_rejected_without_path_or_key_disclosure(self) -> None:
        bound = self._bind()
        path = self.prepared.agent_tree / "payload.bin"
        self._make_writable(path)
        path.write_bytes(b"evil")

        with self.assertRaises(SealedTreeAccessError) as captured:
            bound.read_bytes("payload.bin", maximum_bytes=4)
        self.assertEqual("source_changed", captured.exception.code)
        message = str(captured.exception)
        self.assertNotIn(str(self.root), message)
        self.assertNotIn(KEY.decode("ascii"), message)

    def test_finalize_reverifies_all_unread_files_and_invalidates_on_failure(self) -> None:
        bound = self._bind()
        path = self.prepared.agent_tree / "payload.bin"
        self._make_writable(path)
        path.write_bytes(b"evil")

        with self.assertRaises(SealedTreeAccessError) as captured:
            bound.finalize()
        self.assertEqual("snapshot_verification_failed", captured.exception.code)
        usage = bound.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)
        with self.assertRaises(SealedTreeAccessError) as second:
            bound.finalize()
        self.assertEqual("access_finalized", second.exception.code)

    def test_wrong_key_failure_is_generic_and_path_free(self) -> None:
        with self.assertRaises(SealedTreeAccessError) as captured:
            bind_sealed_tree(
                self.task,
                self.snapshot_root,
                attestation_key=OTHER_KEY,
                expected_key_id=KEY_ID,
            )
        self.assertEqual("snapshot_verification_failed", captured.exception.code)
        message = str(captured.exception)
        self.assertNotIn(str(self.root), message)
        self.assertNotIn(OTHER_KEY.decode("ascii"), message)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_posix_ancestor_swap_cannot_redirect_the_pinned_tree_read(self) -> None:
        bound = self._bind()
        expected = b"def entry(value):\n    return sink(value)\n"
        tree = self.prepared.agent_tree
        held_tree = tree.with_name("held-tree")
        outside = self.root / "outside"
        (outside / "src").mkdir(parents=True)
        (outside / "src" / "app.py").write_bytes(b"external secret")
        real_open = os.open
        swapped = False
        descriptor_bytes: list[bytes] = []

        def trap_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal swapped
            if path == "src" and dir_fd is not None and not swapped:
                tree.rename(held_tree)
                tree.symlink_to(outside, target_is_directory=True)
                swapped = True
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if path == "app.py" and dir_fd is not None:
                descriptor_bytes.append(os.pread(descriptor, len(expected), 0))
            return descriptor

        try:
            with mock.patch.object(access_module.os, "open", side_effect=trap_open):
                with self.assertRaises(SealedTreeAccessError) as captured:
                    bound.read_bytes("src/app.py", maximum_bytes=len(expected))
            self.assertEqual("source_changed", captured.exception.code)
            self.assertTrue(swapped)
            self.assertEqual([expected], descriptor_bytes)
        finally:
            if tree.is_symlink():
                tree.unlink()
            if held_tree.exists():
                held_tree.rename(tree)

    @unittest.skipUnless(os.name == "nt", "Windows handle regression")
    def test_windows_reads_use_same_handle_final_path_and_named_stream_guard(self) -> None:
        real_final_path = access_module._windows_normalized_final_path
        with mock.patch.object(
            access_module,
            "_windows_normalized_final_path",
            wraps=real_final_path,
        ) as final_path:
            bound = self._bind()
            before_read = final_path.call_count
            data = bound.read_bytes("src/app.py", maximum_bytes=128)
            self.assertIn(b"return sink", data)
            self.assertGreater(final_path.call_count, before_read)
            bound.finalize()

        bound = self._bind()
        with mock.patch.object(
            access_module,
            "_windows_assert_no_named_streams",
            side_effect=SealedSnapshotError(
                "unsafe_snapshot_path", "simulated named stream"
            ),
        ):
            with self.assertRaises(SealedTreeAccessError) as captured:
                bound.read_bytes("src/app.py", maximum_bytes=128)
        self.assertEqual("unsafe_source_path", captured.exception.code)

    @unittest.skipUnless(os.name == "nt", "Windows identity stability regression")
    def test_windows_repeated_bind_read_finalize_is_stable(self) -> None:
        for iteration in range(30):
            with self.subTest(iteration=iteration):
                bound = self._bind()
                self.assertIn(
                    b"return sink",
                    bound.read_bytes("src/app.py", maximum_bytes=128),
                )
                self.assertTrue(bound.finalize().verification_succeeded)

    def test_production_module_has_no_git_shell_or_network_dependency(self) -> None:
        source = Path(access_module.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "GitRepository",
            "subprocess",
            "requests",
            "urllib",
            "socket",
            "os.system",
            "Popen",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
