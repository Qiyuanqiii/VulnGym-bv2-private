from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vulngym_agent.tools.git import (
    GitCommandError,
    GitRepository,
    InvalidRepositoryPath,
    RepositoryUnavailable,
    validate_repo_relative_path,
)
from vulngym_agent.validators import (
    CommitValidator,
    InvalidLineSpan,
    LocationValidator,
    normalize_code,
    parse_line_span,
    validate_commit,
)


SOURCE_AT_VULNERABLE_COMMIT = """def entry(value):
    prepared = value.strip()
    if not prepared:
        return None
    audited = prepared
    result = dangerous(audited)
    return result

def helper(value):
    return dangerous(value)
"""


class GitFactGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_directory = tempfile.TemporaryDirectory()
        cls.repo_path = Path(cls._temporary_directory.name)
        cls.source_path = cls.repo_path / "src" / "app.py"
        cls.non_utf8_path = cls.repo_path / "src" / "non_utf8.py"
        cls.source_path.parent.mkdir(parents=True)

        cls._git("init", "-q")
        cls._git("config", "user.name", "VulnGym Test")
        cls._git("config", "user.email", "vulngym@example.invalid")
        cls.source_path.write_text(SOURCE_AT_VULNERABLE_COMMIT, encoding="utf-8")
        cls.non_utf8_path.write_bytes(b"\xff\xfe\n")
        cls._git("add", "--", "src/app.py", "src/non_utf8.py")
        cls._git("commit", "-q", "-m", "vulnerable snapshot")
        cls.vulnerable_commit = cls._git("rev-parse", "HEAD").stdout.strip()
        cls.source_blob = cls._git(
            "rev-parse", f"{cls.vulnerable_commit}:src/app.py"
        ).stdout.strip()

        # Leave the worktree different from the immutable commit.  Object reads
        # must still return SOURCE_AT_VULNERABLE_COMMIT and must never checkout.
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

    def setUp(self) -> None:
        self.repository = GitRepository(self.repo_path)
        self.validator = LocationValidator(self.repository)

    def validate(self, *, file: object = "src/app.py", line: object, code: object):
        return self.validator.validate(
            self.vulnerable_commit,
            file=file,
            line=line,
            code=code,
        )

    def test_existing_commit_is_proven_but_semantic_role_stays_uncertain(self) -> None:
        result = validate_commit(self.repo_path, self.vulnerable_commit)

        self.assertTrue(result.deterministic_valid)
        self.assertTrue(result.exists)
        self.assertTrue(result.is_commit)
        self.assertEqual(result.object_type, "commit")
        self.assertEqual(result.fact_status, "correct")
        self.assertEqual(result.status, "uncertain")
        self.assertFalse(result.semantic_role_verified)
        self.assertIn("exists and is a commit object", result.evidence)

    def test_nonexistent_and_malformed_commits_are_incorrect(self) -> None:
        missing = validate_commit(self.repo_path, "0" * 40)
        malformed = validate_commit(self.repo_path, self.vulnerable_commit.upper())

        self.assertEqual(missing.status, "incorrect")
        self.assertFalse(missing.exists)
        self.assertEqual(missing.error_code, "commit_not_found")
        self.assertEqual(malformed.status, "incorrect")
        self.assertEqual(malformed.error_code, "invalid_commit_sha")

    def test_missing_commit_in_shallow_history_is_uncertain(self) -> None:
        shallow_file = self.repository.git_directory / "shallow"
        shallow_file.write_text(self.vulnerable_commit + "\n", encoding="ascii")
        try:
            result = CommitValidator(self.repository).validate("0" * 40)
        finally:
            shallow_file.unlink()

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "uncertain")
        self.assertIsNone(result.exists)
        self.assertEqual(
            result.error_code, "commit_missing_from_incomplete_history"
        )

    def test_git_read_failure_is_uncertain_not_commit_not_found(self) -> None:
        diagnostic = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=f"{self.vulnerable_commit} missing\n".encode("ascii"),
            stderr=b"fatal: unable to read object database",
        )
        with mock.patch.object(self.repository, "_run", return_value=diagnostic):
            result = validate_commit(self.repository, self.vulnerable_commit)

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "uncertain")
        self.assertEqual(result.error_code, "git_read_failed")

    def test_operator_token_boundaries_are_not_merged(self) -> None:
        self.assertNotEqual(normalize_code("a++b"), normalize_code("a + +b"))
        self.assertEqual(
            normalize_code("result=dangerous(value)"),
            normalize_code("result = dangerous(value)"),
        )

    def test_external_object_stores_and_common_directories_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            external = root / "external"
            target.mkdir()
            external.mkdir()
            for repository in (target, external):
                subprocess.run(
                    ["git", "init", "-q"],
                    cwd=repository,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

            alternates = target / ".git" / "objects" / "info" / "alternates"
            alternates.write_text(
                str(external / ".git" / "objects") + "\n", encoding="utf-8"
            )
            with self.assertRaises(RepositoryUnavailable):
                GitRepository(target)

            alternates.unlink()
            (target / ".git" / "commondir").write_text(
                str(external / ".git") + "\n", encoding="utf-8"
            )
            with self.assertRaises(RepositoryUnavailable):
                GitRepository(target)

    def test_git_environment_disables_lazy_fetch(self) -> None:
        self.assertEqual(self.repository._environment()["GIT_NO_LAZY_FETCH"], "1")

    def test_existing_non_commit_git_object_is_rejected(self) -> None:
        result = validate_commit(self.repo_path, self.source_blob)

        self.assertTrue(result.exists)
        self.assertFalse(result.is_commit)
        self.assertEqual(result.object_type, "blob")
        self.assertEqual(result.status, "incorrect")
        self.assertEqual(result.error_code, "object_is_not_commit")

    def test_source_is_read_from_the_requested_commit_not_the_worktree(self) -> None:
        committed = self.repository.read_text(
            self.vulnerable_commit, "src/app.py"
        )

        self.assertEqual(committed, SOURCE_AT_VULNERABLE_COMMIT)
        self.assertNotIn("WORKTREE_ONLY", committed)
        self.assertEqual(
            self.source_path.read_text(encoding="utf-8"),
            "WORKTREE_ONLY = True\n",
        )
        self.assertEqual(
            self._git("rev-parse", "HEAD").stdout.strip(),
            self.vulnerable_commit,
        )

    def test_reading_a_missing_file_reports_a_git_fact_error(self) -> None:
        with self.assertRaises(GitCommandError):
            self.repository.read_file(self.vulnerable_commit, "src/missing.py")

    def test_repository_path_must_be_the_repository_root(self) -> None:
        with self.assertRaises(RepositoryUnavailable):
            GitRepository(self.repo_path / "src")

    def test_repository_paths_reject_traversal_absolute_and_option_inputs(self) -> None:
        invalid_paths = (
            "../secret.py",
            "src/../secret.py",
            "/etc/passwd",
            "C:/Windows/system.ini",
            "C:drive-relative.py",
            "--help",
            ":(glob)**",
            "src\\app.py",
            "src//app.py",
            "src/app.py\x00ignored",
        )
        for invalid_path in invalid_paths:
            with self.subTest(path=invalid_path):
                with self.assertRaises(InvalidRepositoryPath):
                    validate_repo_relative_path(invalid_path)

    def test_location_returns_structured_path_error_without_running_git(self) -> None:
        result = self.validate(file="../src/app.py", line=6, code="dangerous()")

        self.assertEqual(result.status, "incorrect")
        self.assertEqual(result.error_code, "invalid_file_path")
        self.assertIsNone(result.file_exists)
        self.assertIn("Repository path is invalid", result.evidence)

    def test_exact_code_match_proves_facts_not_semantics(self) -> None:
        result = self.validate(line=6, code="result=dangerous(audited)")

        self.assertTrue(result.deterministic_valid)
        self.assertEqual(result.fact_status, "correct")
        self.assertEqual(result.status, "uncertain")
        self.assertTrue(result.file_exists)
        self.assertTrue(result.line_valid)
        self.assertTrue(result.code_matches)
        self.assertEqual(result.matched_start, 6)
        self.assertEqual(result.line_offset, 0)
        self.assertEqual(result.matched_code, "    result = dangerous(audited)")
        self.assertEqual(len(result.blob_id or ""), 40)
        self.assertFalse(result.semantic_role_verified)
        self.assertIn("semantics were not evaluated", result.evidence)

    def test_code_match_accepts_an_anchor_offset_within_five_lines(self) -> None:
        result = self.validate(line=1, code="result = dangerous(audited)")

        self.assertTrue(result.code_matches)
        self.assertEqual(result.matched_start, 6)
        self.assertEqual(result.line_offset, 5)

    def test_code_outside_tolerance_or_not_present_is_incorrect(self) -> None:
        outside_tolerance = self.validate(line=10, code="prepared = value.strip()")
        absent = self.validate(line=6, code="result = safe(audited)")
        merged_word_tokens = self.validate(line=3, code="ifnotprepared:")

        self.assertEqual(outside_tolerance.status, "incorrect")
        self.assertFalse(outside_tolerance.code_matches)
        self.assertEqual(outside_tolerance.error_code, "code_not_found_near_line")
        self.assertEqual(absent.status, "incorrect")
        self.assertFalse(absent.code_matches)
        self.assertFalse(merged_word_tokens.code_matches)

    def test_out_of_bounds_line_is_incorrect(self) -> None:
        result = self.validate(line=999, code="result = dangerous(audited)")

        self.assertEqual(result.status, "incorrect")
        self.assertTrue(result.file_exists)
        self.assertFalse(result.line_valid)
        self.assertEqual(result.error_code, "line_out_of_bounds")

    def test_non_utf8_source_is_uncertain_without_losing_file_fact(self) -> None:
        result = self.validate(file="src/non_utf8.py", line=1, code="anything")

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "uncertain")
        self.assertTrue(result.file_exists)
        self.assertEqual(len(result.blob_id or ""), 40)
        self.assertEqual(result.error_code, "source_read_failed")

    def test_range_and_multiline_snippet_match_as_one_contiguous_block(self) -> None:
        result = self.validate(
            line="5-6",
            code="""audited=prepared
result = dangerous(audited)""",
        )

        self.assertTrue(result.code_matches)
        self.assertEqual((result.matched_start, result.matched_end), (5, 6))
        self.assertEqual(result.line_offset, 0)

    def test_multiline_snippet_can_use_a_single_nearby_anchor(self) -> None:
        result = self.validate(
            line=1,
            code="""audited = prepared
result = dangerous(audited)""",
        )

        self.assertTrue(result.code_matches)
        self.assertEqual((result.matched_start, result.matched_end), (5, 6))
        self.assertEqual(result.line_offset, 4)

    def test_range_may_be_longer_than_a_matching_multiline_snippet(self) -> None:
        result = self.validate(
            line="4-8",
            code="""audited = prepared
result = dangerous(audited)""",
        )

        self.assertTrue(result.code_matches)
        self.assertEqual((result.matched_start, result.matched_end), (5, 6))
        self.assertEqual(result.line_offset, 1)

    def test_file_matching_is_case_sensitive_and_exact(self) -> None:
        result = self.validate(
            file="SRC/app.py",
            line=6,
            code="result = dangerous(audited)",
        )

        self.assertEqual(result.status, "incorrect")
        self.assertFalse(result.file_exists)
        self.assertEqual(result.error_code, "file_not_found")

    def test_line_parser_accepts_only_schema_forms(self) -> None:
        self.assertEqual(parse_line_span(7), (7, 7))
        self.assertEqual(parse_line_span("7-9"), (7, 9))
        self.assertEqual(parse_line_span("7-7"), (7, 7))
        huge_range = f"{'9' * 5_000}-{'9' * 5_000}"
        for invalid in (
            True,
            0,
            -1,
            "7",
            "0-1",
            "9-7",
            " 7-9",
            "x-y",
            huge_range,
            None,
        ):
            with self.subTest(line=invalid):
                with self.assertRaises(InvalidLineSpan):
                    parse_line_span(invalid)


if __name__ == "__main__":
    unittest.main()
