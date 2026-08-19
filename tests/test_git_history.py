from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vulngym_agent.tools.git.repository import (
    GitCommandError,
    GitDiffTooLarge,
    GitHistoryIncomplete,
    GitRepository,
    InvalidCommitSha,
    InvalidRepositoryPath,
    RepositoryUnavailable,
)
from vulngym_agent.tools.git import (
    GitDiffTooLarge as ExportedGitDiffTooLarge,
    TextFileDiff as ExportedTextFileDiff,
)
from vulngym_agent.validators import (
    CommitTransitionValidator as ExportedCommitTransitionValidator,
    validate_commit_transition,
)
from vulngym_agent.validators.commit_transition_validator import (
    CommitTransitionValidator,
)


class GitHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_directory = tempfile.TemporaryDirectory()
        cls.repo_path = Path(cls._temporary_directory.name)
        cls.source_path = cls.repo_path / "src" / "app.py"
        cls.deleted_path = cls.repo_path / "src" / "deleted.py"
        cls.binary_path = cls.repo_path / "src" / "binary.py"
        cls.source_path.parent.mkdir(parents=True)

        cls._git("init", "-q", "-b", "main")
        cls._git("config", "user.name", "VulnGym Test")
        cls._git("config", "user.email", "vulngym@example.invalid")
        cls.source_path.write_text("def run(value):\n    return value\n", encoding="utf-8")
        cls.deleted_path.write_text("legacy = True\n", encoding="utf-8")
        cls.binary_path.write_bytes(b"\xff\n")
        cls._commit_all("candidate snapshot")
        cls.candidate = cls._head()

        cls.source_path.write_text(
            "def run(value):\n    return sanitize(value)\n", encoding="utf-8"
        )
        cls.deleted_path.unlink()
        (cls.repo_path / "src" / "added.py").write_text(
            "enabled = True\n", encoding="utf-8"
        )
        cls.binary_path.write_bytes(b"\xfe\n")
        cls._commit_all("caller supplied direct fix")
        cls.direct_fix = cls._head()

        (cls.repo_path / "notes.txt").write_text("one\n", encoding="utf-8")
        cls._commit_all("later descendant")
        cls.descendant = cls._head()

        cls._git("switch", "-q", "-c", "side", cls.direct_fix)
        (cls.repo_path / "side.txt").write_text("side\n", encoding="utf-8")
        cls._commit_all("side branch")
        cls.side = cls._head()

        cls._git("switch", "-q", "main")
        cls._git("merge", "-q", "--no-ff", "side", "-m", "merge side")
        cls.merge = cls._head()

        # Worktree changes must never affect immutable history reads.
        cls.source_path.write_text("WORKTREE_ONLY = True\n", encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary_directory.cleanup()

    @classmethod
    def _git(cls, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=cls.repo_path,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    @classmethod
    def _commit_all(cls, message: str) -> None:
        cls._git("add", "-A")
        cls._git("commit", "-q", "-m", message)

    @classmethod
    def _head(cls) -> str:
        return cls._git("rev-parse", "HEAD").stdout.strip()

    def setUp(self) -> None:
        self.repository = GitRepository(self.repo_path)
        self.validator = CommitTransitionValidator(self.repository)

    def test_history_types_and_validator_are_publicly_exported(self) -> None:
        self.assertIs(ExportedGitDiffTooLarge, GitDiffTooLarge)
        self.assertEqual(ExportedTextFileDiff.__name__, "TextFileDiff")
        self.assertIs(ExportedCommitTransitionValidator, CommitTransitionValidator)
        result = validate_commit_transition(
            self.repository, self.candidate, self.direct_fix
        )
        self.assertEqual(result.fact_status, "correct")

    def test_commit_parents_preserves_root_single_and_merge_parents(self) -> None:
        self.assertEqual(self.repository.commit_parents(self.candidate), ())
        self.assertEqual(
            self.repository.commit_parents(self.direct_fix),
            (self.candidate,),
        )
        self.assertEqual(
            self.repository.commit_parents(self.merge),
            (self.descendant, self.side),
        )

    def test_commit_parents_rejects_invalid_or_non_commit_object(self) -> None:
        blob = self._git("rev-parse", f"{self.candidate}:src/app.py").stdout.strip()
        with self.assertRaises(InvalidCommitSha):
            self.repository.commit_parents("HEAD")
        with self.assertRaises(GitCommandError):
            self.repository.commit_parents(blob)

    def test_is_ancestor_handles_true_false_and_reflexive_cases(self) -> None:
        self.assertTrue(self.repository.is_ancestor(self.candidate, self.merge))
        self.assertFalse(self.repository.is_ancestor(self.side, self.descendant))
        self.assertTrue(self.repository.is_ancestor(self.candidate, self.candidate))

    def test_is_ancestor_uses_only_fixed_full_sha_arguments(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"", stderr=b""
        )
        with (
            mock.patch.object(
                self.repository,
                "_require_commit",
                side_effect=lambda commit, *, operation: commit,
            ),
            mock.patch.object(
                self.repository, "_run", return_value=completed
            ) as run,
        ):
            result = self.repository.is_ancestor(self.candidate, self.direct_fix)

        self.assertTrue(result)
        self.assertEqual(
            run.call_args.args[0],
            (
                "merge-base",
                "--is-ancestor",
                self.candidate,
                self.direct_fix,
            ),
        )
        self.assertEqual(run.call_args.kwargs["operation"], "merge-base")
        self.assertFalse(run.call_args.kwargs["check"])

    def test_is_ancestor_rejects_unexpected_git_exit_or_output(self) -> None:
        with mock.patch.object(
            self.repository,
            "_run",
            return_value=subprocess.CompletedProcess(
                args=[], returncode=2, stdout=b"", stderr=b"fatal"
            ),
        ):
            with self.assertRaises(GitCommandError):
                self.repository.is_ancestor(self.candidate, self.direct_fix)

    def test_is_ancestor_does_not_claim_negative_in_shallow_history(self) -> None:
        shallow_file = self.repository.git_directory / "shallow"
        shallow_file.write_text(self.candidate + "\n", encoding="ascii")
        try:
            self.assertTrue(self.repository.history_is_shallow())
            with self.assertRaises(GitHistoryIncomplete):
                self.repository.is_ancestor(self.side, self.descendant)
        finally:
            shallow_file.unlink()
        self.assertFalse(self.repository.history_is_shallow())

    def test_transition_maps_shallow_negative_to_history_incomplete(self) -> None:
        shallow_file = self.repository.git_directory / "shallow"
        shallow_file.write_text(self.candidate + "\n", encoding="ascii")
        try:
            result = self.validator.validate(self.side, self.descendant)
        finally:
            shallow_file.unlink()

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "uncertain")
        self.assertEqual(result.error_code, "history_incomplete")

    def test_transition_missing_endpoint_in_shallow_history_is_uncertain(self) -> None:
        shallow_file = self.repository.git_directory / "shallow"
        shallow_file.write_text(self.candidate + "\n", encoding="ascii")
        try:
            result = self.validator.validate("0" * 40, self.descendant)
        finally:
            shallow_file.unlink()

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "uncertain")
        self.assertEqual(
            result.error_code, "candidate_missing_from_incomplete_history"
        )

    def test_equal_declared_fix_is_incorrect_even_when_missing_from_shallow_repo(self) -> None:
        missing = "0" * 40
        shallow_file = self.repository.git_directory / "shallow"
        shallow_file.write_text(self.candidate + "\n", encoding="ascii")
        try:
            result = self.validator.validate(missing, missing)
        finally:
            shallow_file.unlink()

        self.assertEqual(result.status, "incorrect")
        self.assertEqual(result.error_code, "candidate_equals_fix")

    def test_partial_clone_marker_also_makes_negative_history_inconclusive(self) -> None:
        self._git("config", "--local", "remote.origin.promisor", "true")
        try:
            self.assertTrue(self.repository.history_may_be_incomplete())
            with self.assertRaises(GitHistoryIncomplete):
                self.repository.is_ancestor(self.side, self.descendant)
            result = self.validator.validate(self.side, self.descendant)
            with self.assertRaisesRegex(
                RepositoryUnavailable, "partial/promisor repositories"
            ):
                GitRepository(self.repo_path)
        finally:
            self._git("config", "--local", "--unset", "remote.origin.promisor")

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.error_code, "history_incomplete")

    def test_shallow_marker_symlink_is_rejected(self) -> None:
        if not hasattr(Path, "symlink_to"):
            self.skipTest("symlinks are unavailable")
        shallow_file = self.repository.git_directory / "shallow"
        target = self.repo_path / "outside-shallow"
        target.write_text(self.candidate + "\n", encoding="ascii")
        try:
            try:
                shallow_file.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("creating symlinks is not permitted")
            with self.assertRaisesRegex(
                RepositoryUnavailable, "must not be a symlink"
            ):
                self.repository.history_is_shallow()
        finally:
            if shallow_file.is_symlink():
                shallow_file.unlink()
            target.unlink(missing_ok=True)

    def test_diff_text_file_reports_modified_added_and_deleted_files(self) -> None:
        modified = self.repository.diff_text_file(
            self.candidate, self.direct_fix, "src/app.py"
        )
        added = self.repository.diff_text_file(
            self.candidate, self.direct_fix, "src/added.py"
        )
        deleted = self.repository.diff_text_file(
            self.candidate, self.direct_fix, "src/deleted.py"
        )

        self.assertTrue(modified.changed)
        self.assertEqual((modified.added_lines, modified.deleted_lines), (1, 1))
        self.assertIn("-    return value", modified.unified_diff)
        self.assertIn("+    return sanitize(value)", modified.unified_diff)
        self.assertNotIn("WORKTREE_ONLY", modified.unified_diff)
        self.assertFalse(added.before_exists)
        self.assertTrue(added.after_exists)
        self.assertEqual((added.added_lines, added.deleted_lines), (1, 0))
        self.assertTrue(deleted.before_exists)
        self.assertFalse(deleted.after_exists)
        self.assertEqual((deleted.added_lines, deleted.deleted_lines), (0, 1))

    def test_diff_text_file_reports_unchanged_and_missing_paths(self) -> None:
        unchanged = self.repository.diff_text_file(
            self.direct_fix, self.descendant, "src/app.py"
        )
        missing = self.repository.diff_text_file(
            self.candidate, self.direct_fix, "src/missing.py"
        )

        self.assertFalse(unchanged.changed)
        self.assertEqual(unchanged.unified_diff, "")
        self.assertFalse(missing.changed)
        self.assertFalse(missing.before_exists)
        self.assertFalse(missing.after_exists)

    def test_diff_rejects_sha_path_context_and_size_abuse(self) -> None:
        with self.assertRaises(InvalidCommitSha):
            self.repository.diff_text_file("HEAD", self.direct_fix, "src/app.py")
        with self.assertRaises(InvalidRepositoryPath):
            self.repository.diff_text_file(
                self.candidate, self.direct_fix, "--output=/tmp/pwn"
            )
        with self.assertRaises(ValueError):
            self.repository.diff_text_file(
                self.candidate,
                self.direct_fix,
                "src/app.py",
                context_lines=101,
            )
        limited_input = GitRepository(self.repo_path, max_diff_input_bytes=1)
        with self.assertRaises(GitDiffTooLarge):
            limited_input.diff_text_file(
                self.candidate, self.direct_fix, "src/app.py"
            )
        limited_output = GitRepository(self.repo_path, max_diff_output_bytes=1)
        with self.assertRaises(GitDiffTooLarge):
            limited_output.diff_text_file(
                self.candidate, self.direct_fix, "src/app.py"
            )

    def test_transition_direct_parent_and_patch_are_facts_not_semantics(self) -> None:
        result = self.validator.validate(
            self.candidate, self.direct_fix, path="src/app.py"
        )

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "correct")
        self.assertTrue(result.candidate_is_ancestor)
        self.assertTrue(result.candidate_is_direct_parent)
        self.assertTrue(result.file_changed)
        self.assertEqual((result.added_lines, result.deleted_lines), (1, 1))
        self.assertFalse(result.semantic_role_verified)
        self.assertIn("do not prove", result.evidence)

    def test_transition_non_direct_ancestor_is_a_positive_fact(self) -> None:
        result = self.validator.validate(self.candidate, self.descendant)

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "correct")
        self.assertTrue(result.candidate_is_ancestor)
        self.assertFalse(result.candidate_is_direct_parent)

    def test_transition_rejects_equal_or_non_ancestor_claims(self) -> None:
        equal = self.validator.validate(self.candidate, self.candidate)
        divergent = self.validator.validate(self.side, self.descendant)

        self.assertEqual(equal.status, "incorrect")
        self.assertEqual(equal.error_code, "candidate_equals_fix")
        self.assertEqual(divergent.status, "incorrect")
        self.assertEqual(divergent.error_code, "candidate_not_ancestor_of_fix")

    def test_transition_rejects_unchanged_requested_path(self) -> None:
        result = self.validator.validate(
            self.direct_fix, self.descendant, path="src/app.py"
        )

        self.assertEqual(result.status, "incorrect")
        self.assertEqual(result.fact_status, "incorrect")
        self.assertFalse(result.file_changed)
        self.assertEqual(result.error_code, "path_unchanged")

    def test_transition_maps_non_utf8_diff_failure_to_uncertain(self) -> None:
        result = self.validator.validate(
            self.candidate, self.direct_fix, path="src/binary.py"
        )

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "uncertain")
        self.assertTrue(result.candidate_is_direct_parent)
        self.assertEqual(result.error_code, "diff_read_failed")

    def test_transition_maps_history_failures_to_uncertain(self) -> None:
        with mock.patch.object(
            self.repository,
            "commit_parents",
            side_effect=GitCommandError("cat-file", 128, "missing history"),
        ):
            result = self.validator.validate(self.candidate, self.direct_fix)

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "uncertain")
        self.assertEqual(result.error_code, "history_read_failed")

    def test_environment_remains_offline_and_read_only(self) -> None:
        environment = self.repository._environment()
        command = self.repository._base_command()

        self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(environment["GIT_EXTERNAL_DIFF"], "")
        self.assertIn("core.commitGraph=false", command)

    def test_worktree_config_indirection_is_rejected_at_repository_boundary(self) -> None:
        self._git("config", "--local", "extensions.worktreeConfig", "true")
        try:
            with self.assertRaisesRegex(
                RepositoryUnavailable, "worktree-specific configuration"
            ):
                GitRepository(self.repo_path)
        finally:
            self._git("config", "--local", "--unset", "extensions.worktreeConfig")

    def test_legacy_grafts_cannot_override_ancestry(self) -> None:
        grafts = self.repository.git_directory / "info" / "grafts"
        grafts.parent.mkdir(parents=True, exist_ok=True)
        grafts.write_text(f"{self.side} {self.candidate}\n", encoding="ascii")
        try:
            with self.assertRaisesRegex(RepositoryUnavailable, "graft"):
                GitRepository(self.repo_path)
        finally:
            grafts.unlink()


if __name__ == "__main__":
    unittest.main()
