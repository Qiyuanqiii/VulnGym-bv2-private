from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from vulngym_agent.tools.git import (
    GitBlobTooLarge,
    GitCommandError,
    GitRepository,
    RepositoryUnavailable,
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


if __name__ == "__main__":
    unittest.main()
