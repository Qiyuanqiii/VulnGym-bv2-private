from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import vulngym_agent.evaluator.bounded_process as bounded_process_module
import vulngym_agent.tools.git.repository as repository_module

from vulngym_agent.tools.git import (
    GitBlobTooLarge,
    GitCommandError,
    GitRepository,
    RepositoryUnavailable,
)
from vulngym_agent.tools.git.repository import (
    BoundedProcessOutputTooLarge,
    run_bounded_process,
)


def _git(root: Path, *arguments: str, input_data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout


class RawGitTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        _git(self.root, "init", "-q")
        _git(self.root, "config", "user.email", "test@example.invalid")
        _git(self.root, "config", "user.name", "VulnGym Test")
        (self.root / "src").mkdir()
        self.binary = b"\x00raw\xffbytes\n"
        (self.root / "src" / "data.bin").write_bytes(self.binary)
        (self.root / "script.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
        _git(self.root, "add", "--", "src/data.bin", "script.sh")
        _git(self.root, "update-index", "--chmod=+x", "script.sh")
        _git(self.root, "commit", "-q", "-m", "initial")
        self.commit = _git(self.root, "rev-parse", "HEAD").decode().strip()
        self.tree = _git(self.root, "rev-parse", "HEAD^{tree}").decode().strip()
        self.repository = GitRepository(self.root, max_blob_bytes=1024)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_commit_tree_lists_recursive_exact_modes_and_reads_raw_blob(self) -> None:
        self.assertEqual(self.repository.commit_tree(self.commit), self.tree)
        entries = self.repository.list_tree_entries(
            self.commit, max_entries=10, max_output_bytes=4096
        )
        self.assertEqual(
            [(entry.path, entry.mode, entry.object_type) for entry in entries],
            [
                ("script.sh", "100755", "blob"),
                ("src/data.bin", "100644", "blob"),
            ],
        )
        binary_entry = next(entry for entry in entries if entry.path == "src/data.bin")
        self.assertEqual(
            self.repository.read_blob_object(binary_entry.object_id, max_bytes=64),
            self.binary,
        )

    def test_batched_blob_reader_preserves_order_duplicates_and_binary_bytes(self) -> None:
        entries = self.repository.list_tree_entries(
            self.commit, max_entries=10, max_output_bytes=4096
        )
        binary_id = next(
            entry.object_id for entry in entries if entry.path == "src/data.bin"
        )
        empty_id = _git(
            self.root, "hash-object", "-w", "--stdin", input_data=b""
        ).decode("ascii").strip()
        requested = (binary_id, empty_id, binary_id)
        with mock.patch.object(
            self.repository, "_run", wraps=self.repository._run
        ) as runner:
            observed = tuple(
                self.repository.iter_blob_objects(
                    requested,
                    max_total_bytes=2 * len(self.binary),
                    max_bytes=64,
                )
            )
        self.assertEqual(
            (
                (binary_id, self.binary),
                (empty_id, b""),
                (binary_id, self.binary),
            ),
            observed,
        )
        commands = tuple(call.args[0] for call in runner.call_args_list)
        self.assertEqual(2, len(commands))
        self.assertEqual("cat-file", commands[0][0])
        self.assertTrue(commands[0][1].startswith("--batch-check="))
        self.assertEqual(("cat-file", "--batch"), commands[1])

    def test_batched_blob_reader_rejects_limits_types_and_malformed_content(self) -> None:
        with mock.patch.object(
            self.repository,
            "_run",
            side_effect=AssertionError("empty batch invoked Git"),
        ):
            self.assertEqual(
                (),
                tuple(
                    self.repository.iter_blob_objects(
                        (), max_total_bytes=0, max_bytes=0
                    )
                ),
            )

        entry = self.repository.list_tree_entries(
            self.commit, max_entries=10, max_output_bytes=4096
        )[0]
        with self.assertRaises(GitBlobTooLarge):
            tuple(
                self.repository.iter_blob_objects(
                    (entry.object_id,),
                    max_total_bytes=0,
                    max_bytes=1024,
                )
            )
        with self.assertRaises(GitCommandError):
            tuple(
                self.repository.iter_blob_objects(
                    (self.commit,),
                    max_total_bytes=1024,
                    max_bytes=1024,
                )
            )

        object_id = hashlib.sha1(
            b"blob 1\0x", usedforsecurity=False
        ).hexdigest()
        metadata = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=f"{object_id} blob 1\n".encode("ascii"),
            stderr=b"",
        )
        malformed = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=f"{object_id} blob 1\n".encode("ascii") + b"y\n",
            stderr=b"",
        )
        with mock.patch.object(
            self.repository, "_run", side_effect=(metadata, malformed)
        ), self.assertRaises(GitCommandError):
            tuple(
                self.repository.iter_blob_objects(
                    (object_id,),
                    max_total_bytes=1,
                    max_bytes=1,
                )
            )

        first_data = b"a"
        second_data = b"b"
        first_id = hashlib.sha1(
            b"blob 1\0" + first_data, usedforsecurity=False
        ).hexdigest()
        second_id = hashlib.sha1(
            b"blob 1\0" + second_data, usedforsecurity=False
        ).hexdigest()
        metadata = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=(
                f"{first_id} blob 1\n{second_id} blob 1\n".encode("ascii")
            ),
            stderr=b"",
        )
        corrupt_second_frame = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=(
                f"{first_id} blob 1\n".encode("ascii")
                + first_data
                + b"\n"
                + f"{second_id} blob 1\n".encode("ascii")
                + b"c\n"
            ),
            stderr=b"",
        )
        with mock.patch.object(
            self.repository,
            "_run",
            side_effect=(metadata, corrupt_second_frame),
        ):
            reader = self.repository.iter_blob_objects(
                (first_id, second_id), max_total_bytes=2, max_bytes=1
            )
            with self.assertRaises(GitCommandError):
                next(reader)

    def test_batched_blob_reader_chunks_content_and_uses_large_blob_fallback(self) -> None:
        entries = self.repository.list_tree_entries(
            self.commit, max_entries=10, max_output_bytes=4096
        )
        object_ids = tuple(entry.object_id for entry in entries)
        expected = tuple(
            (object_id, self.repository.read_blob_object(object_id, max_bytes=1024))
            for object_id in object_ids
        )
        with mock.patch.object(
            repository_module, "_MAX_BATCH_CONTENT_RESPONSE_BYTES", 80
        ), mock.patch.object(
            self.repository, "_run", wraps=self.repository._run
        ) as runner:
            observed = tuple(
                self.repository.iter_blob_objects(
                    object_ids,
                    max_total_bytes=1024,
                    max_bytes=1024,
                )
            )
        self.assertEqual(expected, observed)
        content_calls = tuple(
            call
            for call in runner.call_args_list
            if call.args[0] == ("cat-file", "--batch")
        )
        self.assertGreaterEqual(len(content_calls), 2)

        with mock.patch.object(
            repository_module, "_MAX_BATCH_CONTENT_RESPONSE_BYTES", 1
        ), mock.patch.object(
            self.repository,
            "_read_object_bytes",
            wraps=self.repository._read_object_bytes,
        ) as fallback:
            observed = tuple(
                self.repository.iter_blob_objects(
                    (object_ids[0],),
                    max_total_bytes=1024,
                    max_bytes=1024,
                )
            )
        self.assertEqual(expected[:1], observed)
        fallback.assert_called_once()

        with mock.patch.object(
            repository_module, "_MAX_BATCH_CONTENT_RESPONSE_BYTES", 1
        ), mock.patch.object(
            self.repository, "_read_object_bytes", return_value=b"wrong-size"
        ), self.assertRaises(GitCommandError):
            tuple(
                self.repository.iter_blob_objects(
                    (object_ids[0],),
                    max_total_bytes=1024,
                    max_bytes=1024,
                )
            )

    def test_symlink_and_gitlink_modes_are_preserved_for_policy_rejection(self) -> None:
        link_blob = _git(
            self.root, "hash-object", "-w", "--stdin", input_data=b"outside"
        ).decode().strip()
        _git(
            self.root,
            "update-index",
            "--add",
            "--cacheinfo",
            f"120000,{link_blob},link",
        )
        _git(
            self.root,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.commit},submodule",
        )
        _git(self.root, "commit", "-q", "-m", "special modes")
        commit = _git(self.root, "rev-parse", "HEAD").decode().strip()
        entries = self.repository.list_tree_entries(
            commit, max_entries=10, max_output_bytes=4096
        )
        modes = {entry.path: (entry.mode, entry.object_type) for entry in entries}
        self.assertEqual(modes["link"], ("120000", "blob"))
        self.assertEqual(modes["submodule"], ("160000", "commit"))

    def test_tree_and_blob_resource_limits_fail_before_unbounded_reads(self) -> None:
        with self.assertRaises(GitBlobTooLarge):
            self.repository.list_tree_entries(
                self.commit, max_entries=1, max_output_bytes=4096
            )
        with self.assertRaises(GitBlobTooLarge):
            self.repository.list_tree_entries(
                self.commit, max_entries=10, max_output_bytes=1
            )
        entry = self.repository.list_tree_entries(
            self.commit, max_entries=10, max_output_bytes=4096
        )[0]
        with self.assertRaises(GitBlobTooLarge):
            self.repository.read_blob_object(entry.object_id, max_bytes=1)

    def test_git_blob_larger_than_legacy_transport_limit_is_read_exactly(self) -> None:
        blob_size = (64 * 1024 * 1024) + 1
        blob_path = self.root / "large-transport.bin"
        chunk = b"V" * (1024 * 1024)
        with blob_path.open("wb") as stream:
            for _ in range(64):
                stream.write(chunk)
            stream.write(b"!")
        object_id = _git(
            self.root,
            "hash-object",
            "-w",
            "--",
            blob_path.name,
        ).decode("ascii").strip()
        repository = GitRepository(self.root, max_blob_bytes=blob_size)
        with self.assertRaises(GitBlobTooLarge):
            repository.read_blob_object(object_id, max_bytes=64 * 1024 * 1024)
        data = repository.read_blob_object(object_id, max_bytes=blob_size)
        self.assertEqual(len(data), blob_size)
        self.assertEqual(data[:1], b"V")
        self.assertEqual(data[-1:], b"!")

    def test_reused_empty_trees_consume_node_budget_and_can_be_exposed(self) -> None:
        empty_tree = _git(
            self.root, "mktree", "-z", input_data=b""
        ).decode().strip()
        root_payload = b"".join(
            b"40000 dir%03d\0" % number + bytes.fromhex(empty_tree)
            for number in range(40)
        )
        root_tree = _git(
            self.root,
            "hash-object",
            "-t",
            "tree",
            "-w",
            "--stdin",
            input_data=root_payload,
        ).decode().strip()
        commit = _git(self.root, "commit-tree", root_tree, "-m", "empty dirs").decode().strip()

        with self.assertRaises(GitBlobTooLarge):
            self.repository.list_tree_entries(
                commit, max_entries=10, max_output_bytes=4096
            )
        entries = self.repository.list_tree_entries(
            commit,
            max_entries=40,
            max_output_bytes=4096,
            include_trees=True,
        )
        self.assertEqual(40, len(entries))
        self.assertTrue(all(entry.object_type == "tree" for entry in entries))

    def test_wrong_or_missing_object_types_are_rejected(self) -> None:
        with self.assertRaises(GitCommandError):
            self.repository.read_blob_object(self.commit, max_bytes=1024)
        with self.assertRaises(GitCommandError):
            self.repository.read_blob_object("f" * 40, max_bytes=1024)

    def test_storage_redirection_created_after_open_is_rejected(self) -> None:
        self.repository.assert_storage_safe()
        alternates = self.root / ".git" / "objects" / "info" / "alternates"
        alternates.write_text("../external\n", encoding="utf-8")
        with self.assertRaises(RepositoryUnavailable):
            self.repository.assert_storage_safe()

    def test_hardlinked_object_storage_is_rejected(self) -> None:
        blob = _git(
            self.root, "hash-object", "-w", "--stdin", input_data=b"hardlink"
        ).decode().strip()
        source = self.root / ".git" / "objects" / blob[:2] / blob[2:]
        outside = self.root / "outside-object-link"
        try:
            outside.hardlink_to(source)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"hard links are unavailable: {error}")
        with self.assertRaises(RepositoryUnavailable):
            self.repository.assert_storage_safe()

    def test_critical_metadata_identity_and_hardlinks_are_rejected(self) -> None:
        config = self.root / ".git" / "config"
        outside = self.root / "outside-config-link"
        try:
            outside.hardlink_to(config)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"hard links are unavailable: {error}")
        with self.assertRaises(RepositoryUnavailable):
            self.repository.assert_storage_safe()

    def test_promisor_pack_marker_and_packed_refs_appearance_are_rejected(self) -> None:
        promisor = self.root / ".git" / "objects" / "pack" / ("a" * 40 + ".promisor")
        promisor.write_bytes(b"")
        with self.assertRaises(RepositoryUnavailable):
            self.repository.assert_storage_safe()
        promisor.unlink()

        packed_refs = self.root / ".git" / "packed-refs"
        packed_refs.write_text("# pack-refs with: peeled fully-peeled\n", encoding="ascii")
        with self.assertRaises(RepositoryUnavailable):
            self.repository.assert_storage_safe()

    def test_bounded_process_never_buffers_past_stdout_limit(self) -> None:
        with self.assertRaises(BoundedProcessOutputTooLarge) as captured:
            run_bounded_process(
                (
                    sys.executable,
                    "-c",
                    "import sys;sys.stdout.buffer.write(b'x'*65536)",
                ),
                cwd=self.root,
                environment=os.environ,
                timeout_seconds=10,
                max_stdout_bytes=64,
                max_stderr_bytes=64,
            )
        self.assertEqual(captured.exception.stream_name, "stdout")

    def test_bounded_process_timeout_terminates_real_descendant_tree(self) -> None:
        marker = self.root / "late-descendant.txt"
        child_source = (
            "import pathlib,time;time.sleep(1);"
            f"pathlib.Path({str(marker)!r}).write_text('late')"
        )
        parent_source = (
            "import subprocess,sys,time;"
            f"subprocess.Popen((sys.executable,'-I','-B','-c',{child_source!r}));"
            "time.sleep(30)"
        )
        with self.assertRaises(subprocess.TimeoutExpired):
            run_bounded_process(
                (sys.executable, "-I", "-B", "-c", parent_source),
                cwd=self.root,
                environment=os.environ,
                timeout_seconds=0.25,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        time.sleep(1.2)
        self.assertFalse(marker.exists())

    def test_bounded_process_overflow_terminates_real_descendant_tree(
        self,
    ) -> None:
        marker = self.root / "late-overflow-descendant.txt"
        child_source = (
            "import pathlib,time;time.sleep(1);"
            f"pathlib.Path({str(marker)!r}).write_text('late')"
        )
        parent_source = (
            "import os,subprocess,sys,time;"
            f"subprocess.Popen((sys.executable,'-I','-B','-c',{child_source!r}));"
            "os.write(1,b'x'*65536);time.sleep(30)"
        )
        with self.assertRaises(BoundedProcessOutputTooLarge):
            run_bounded_process(
                (sys.executable, "-I", "-B", "-c", parent_source),
                cwd=self.root,
                environment=os.environ,
                timeout_seconds=10,
                max_stdout_bytes=64,
                max_stderr_bytes=1024,
            )
        time.sleep(1.2)
        self.assertFalse(marker.exists())

    def test_bounded_process_keyboard_interrupt_terminates_real_descendant_tree(
        self,
    ) -> None:
        ready = self.root / "descendant-ready.txt"
        marker = self.root / "late-interrupted-descendant.txt"
        child_source = (
            "import pathlib,time;"
            f"pathlib.Path({str(ready)!r}).write_text('ready');"
            "time.sleep(1);"
            f"pathlib.Path({str(marker)!r}).write_text('late')"
        )
        parent_source = (
            "import subprocess,sys,time;"
            f"subprocess.Popen((sys.executable,'-I','-B','-c',{child_source!r}));"
            "time.sleep(30)"
        )
        original_monotonic = time.monotonic

        def interrupt_after_descendant_started() -> float:
            if ready.exists():
                raise KeyboardInterrupt
            return original_monotonic()

        with mock.patch.object(
            bounded_process_module.time,
            "monotonic",
            side_effect=interrupt_after_descendant_started,
        ), self.assertRaises(KeyboardInterrupt):
            run_bounded_process(
                (sys.executable, "-I", "-B", "-c", parent_source),
                cwd=self.root,
                environment=os.environ,
                timeout_seconds=10,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        self.assertTrue(ready.exists())
        time.sleep(1.2)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
