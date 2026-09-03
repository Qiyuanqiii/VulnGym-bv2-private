from __future__ import annotations

import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path

from vulngym_agent.resolvers import (
    CriticalOperationResolver,
    CriticalPatchCandidate,
    CriticalResolutionResult,
    resolve_critical_operation,
)
from vulngym_agent.resolvers.critical_resolver import _old_side_line_sets
from vulngym_agent.tools.git import GitRepository
from vulngym_agent.tools.git import TextFileDiff


class CriticalResolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_directory = tempfile.TemporaryDirectory()
        cls.repo_path = Path(cls._temporary_directory.name)
        source = cls.repo_path / "src" / "render.py"
        source.parent.mkdir(parents=True)

        cls._git("init", "-q", "-b", "main")
        cls._git("config", "user.name", "VulnGym Test")
        cls._git("config", "user.email", "vulngym@example.invalid")
        source.write_text(
            "def render(value):\n"
            "    prepared = value.strip()\n"
            "    return dangerous(prepared)\n"
            "\n"
            "def unchanged():\n"
            "    return 1\n",
            encoding="utf-8",
        )
        cls._commit_all("vulnerable snapshot")
        cls.vulnerable = cls._head()

        cls._git("switch", "-q", "-c", "unrelated")
        (cls.repo_path / "unrelated.txt").write_text("side\n", encoding="utf-8")
        cls._commit_all("unrelated branch")
        cls.unrelated = cls._head()

        cls._git("switch", "-q", "main")
        source.write_text(
            "def render(value):\n"
            "    prepared = sanitize(value.strip())\n"
            "    if not prepared:\n"
            "        return \"\"\n"
            "    return safe(prepared)\n"
            "\n"
            "def unchanged():\n"
            "    return 1\n",
            encoding="utf-8",
        )
        cls._commit_all("fix unsafe rendering")
        cls.fix = cls._head()

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
        self.resolver = CriticalOperationResolver(self.repository)

    @staticmethod
    def _sink(**overrides: object) -> dict[str, object]:
        candidate: dict[str, object] = {
            "candidate_id": "sink-1",
            "mode": "dangerous_call",
            "file": "src/render.py",
            "change_kind": "removed",
            "old_line": 3,
            "new_line": None,
            "code": "    return dangerous(prepared)",
            "reason": "patch analyzer labels this a dangerous call",
        }
        candidate.update(overrides)
        return candidate

    def _resolve(
        self,
        candidates: object,
        *,
        mode: str = "sink",
        vulnerable: str | None = None,
        fix: str | None = None,
    ) -> CriticalResolutionResult:
        return self.resolver.resolve(
            vulnerable or self.vulnerable,
            fix or self.fix,
            mode=mode,
            candidates=candidates,  # type: ignore[arg-type]
        )

    def test_sink_old_side_location_is_fact_correct_but_semantically_uncertain(self) -> None:
        result = self._resolve([self._sink()])

        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "correct")
        self.assertFalse(result.semantic_role_verified)
        self.assertEqual(result.provisional_candidate_ids, ("sink-1",))
        self.assertEqual(
            result.unique_provisional_location.to_dict(),
            {
                "file": "src/render.py",
                "line": 3,
                "code": "    return dangerous(prepared)",
            },
        )
        assessment = result.candidates[0]
        self.assertEqual(assessment.transition_fact_status, "correct")
        self.assertEqual(assessment.source_fact_status, "correct")
        self.assertTrue(assessment.in_removed_or_changed_side)
        self.assertIn("do not prove", assessment.counterevidence[0])

    def test_guard_mode_accepts_old_changed_condition_but_does_not_claim_semantics(self) -> None:
        candidate = CriticalPatchCandidate(
            candidate_id="guard-1",
            mode="guard",
            file="src/render.py",
            change_kind="changed",
            old_line=2,
            new_line=2,
            code="    prepared = value.strip()",
            reason="possible missing validation",
        )

        result = self._resolve([candidate], mode="guard")

        self.assertEqual((result.status, result.fact_status), ("uncertain", "correct"))
        self.assertEqual(result.provisional_candidate_ids, ("guard-1",))
        self.assertFalse(result.candidates[0].semantic_role_verified)

    def test_guard_mode_accepts_old_context_near_fix_added_guard(self) -> None:
        candidate = CriticalPatchCandidate(
            candidate_id="guard-context-1",
            mode="guard",
            file="src/render.py",
            change_kind="context",
            old_line=1,
            new_line=1,
            code="def render(value):",
            reason="old-side context beside a fix-added guard",
        )

        result = self._resolve([candidate], mode="guard")

        self.assertEqual((result.status, result.fact_status), ("uncertain", "correct"))
        self.assertEqual(result.provisional_candidate_ids, ("guard-context-1",))
        self.assertEqual(
            result.unique_provisional_location.to_dict(),
            {
                "file": "src/render.py",
                "line": 1,
                "code": "def render(value):",
            },
        )
        self.assertTrue(result.candidates[0].in_removed_or_changed_side)
        self.assertIn("fix-added guard", result.candidates[0].evidence)

    def test_guard_context_line_sets_include_sanitizer_and_assert_alias_hunks(self) -> None:
        diff = TextFileDiff(
            before_commit="1" * 40,
            after_commit="2" * 40,
            path="src/render.ts",
            before_exists=True,
            after_exists=True,
            before_blob_id="3" * 40,
            after_blob_id="4" * 40,
            added_lines=3,
            deleted_lines=0,
            unified_diff="""diff --git a/src/render.ts b/src/render.ts
index 1111111..2222222 100644
--- a/src/render.ts
+++ b/src/render.ts
@@ -1,3 +1,5 @@
+import * as a from "node:assert";
 export function render(req: Request) {
   const body = readBody(req)
+  a.ok(req.headers.get("content-type"))
   return DOMPurify.sanitize(body)
 }
""",
        )

        _removed, guard_context = _old_side_line_sets(diff)

        self.assertIn(2, guard_context)
        self.assertIn(3, guard_context)

    def test_fix_added_guard_is_refuted_without_inventing_vulnerable_line(self) -> None:
        result = self._resolve(
            [
                self._sink(
                    candidate_id="guard-added",
                    mode="early_return",
                    change_kind="added",
                    old_line=None,
                    new_line=3,
                    code="    if not prepared:",
                )
            ],
            mode="guard",
        )

        self.assertEqual((result.status, result.fact_status), ("incorrect", "incorrect"))
        assessment = result.candidates[0]
        self.assertEqual(assessment.error_code, "fix_only_added_candidate")
        self.assertIsNone(assessment.location)
        self.assertIn("fix-added", assessment.evidence)

    def test_fix_side_line_is_not_substituted_for_missing_old_line(self) -> None:
        result = self._resolve(
            [self._sink(old_line=None, new_line=5, change_kind="removed")]
        )
        self.assertEqual(result.candidates[0].error_code, "fix_only_added_candidate")
        self.assertEqual(result.status, "incorrect")

    def test_missing_vulnerable_path_is_incorrect(self) -> None:
        result = self._resolve([self._sink(file="src/not-present.py")])
        assessment = result.candidates[0]
        self.assertEqual((assessment.status, assessment.fact_status), ("incorrect", "incorrect"))
        self.assertEqual(assessment.error_code, "file_not_found")
        self.assertIn("does not name a file", assessment.evidence)

    def test_existing_context_line_not_on_removed_side_is_incorrect(self) -> None:
        result = self._resolve(
            [
                self._sink(
                    candidate_id="context-1",
                    old_line=5,
                    code="def unchanged():",
                )
            ]
        )
        assessment = result.candidates[0]
        self.assertEqual(assessment.error_code, "candidate_not_in_removed_side")
        self.assertFalse(assessment.in_removed_or_changed_side)
        self.assertEqual(result.status, "incorrect")

    def test_code_not_present_near_claimed_old_line_is_incorrect(self) -> None:
        result = self._resolve([self._sink(code="    return imaginary(value)")])
        self.assertEqual(result.candidates[0].error_code, "code_not_found_near_line")
        self.assertEqual(result.status, "incorrect")

    def test_mode_mismatch_is_explicit_counterevidence(self) -> None:
        result = self._resolve([self._sink(mode="guard")])
        self.assertEqual(result.candidates[0].error_code, "candidate_mode_mismatch")
        self.assertIn("does not match", result.counterevidence[0])

    def test_invalid_mode_and_path_are_incorrect(self) -> None:
        invalid_mode = self._resolve([self._sink()], mode="taint")
        self.assertEqual(invalid_mode.error_code, "invalid_mode")
        self.assertEqual(invalid_mode.status, "incorrect")

        invalid_path = self._resolve([self._sink(file="../src/render.py")])
        self.assertEqual(invalid_path.candidates[0].error_code, "invalid_candidate_path")

    def test_candidate_equal_to_fix_is_incorrect(self) -> None:
        result = self._resolve([self._sink()], vulnerable=self.fix)
        assessment = result.candidates[0]
        self.assertEqual(assessment.error_code, "candidate_equals_fix")
        self.assertEqual(assessment.status, "incorrect")

    def test_nonancestor_transition_is_incorrect(self) -> None:
        result = self._resolve([self._sink()], vulnerable=self.unrelated)
        assessment = result.candidates[0]
        self.assertEqual(assessment.error_code, "candidate_not_ancestor_of_fix")
        self.assertEqual(result.status, "incorrect")

    def test_no_candidates_is_uncertain_and_does_not_guess(self) -> None:
        result = self._resolve([])
        self.assertEqual((result.status, result.fact_status), ("uncertain", "uncertain"))
        self.assertEqual(result.error_code, "no_candidates")
        self.assertEqual(result.provisional_locations, ())
        self.assertIn("no location was guessed", result.evidence)

    def test_mapping_contract_errors_are_isolated_per_candidate(self) -> None:
        result = self._resolve(
            [
                self._sink(),
                self._sink(candidate_id="bad-2", old_line=True),
                self._sink(candidate_id="bad-3", code=""),
            ]
        )
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.provisional_candidate_ids, ("sink-1",))
        self.assertEqual(result.candidates[1].error_code, "invalid_old_line")
        self.assertEqual(result.candidates[2].error_code, "invalid_code")

    def test_duplicate_ids_are_not_silently_merged(self) -> None:
        result = self._resolve([self._sink(), self._sink()])
        self.assertEqual(result.candidates[1].error_code, "duplicate_candidate_id")
        self.assertEqual(result.provisional_candidate_ids, ("sink-1",))

    def test_candidate_count_and_code_size_are_bounded(self) -> None:
        resolver = CriticalOperationResolver(
            self.repository, max_candidates=1, max_candidate_code_chars=16
        )
        too_many = resolver.resolve(
            self.vulnerable,
            self.fix,
            mode="sink",
            candidates=[self._sink(), self._sink(candidate_id="sink-2")],
        )
        self.assertEqual(too_many.error_code, "candidate_limit_exceeded")
        self.assertEqual(too_many.status, "uncertain")

        oversized = resolver.resolve(
            self.vulnerable,
            self.fix,
            mode="sink",
            candidates=[self._sink(code="x" * 17)],
        )
        self.assertEqual(oversized.candidates[0].error_code, "candidate_code_too_large")

    def test_convenience_api_and_serialization_are_stable(self) -> None:
        result = resolve_critical_operation(
            self.repository,
            self.vulnerable,
            self.fix,
            mode="sink",
            candidates=[self._sink()],
        )
        serialized = result.to_dict()
        self.assertEqual(serialized["mode"], "sink")
        self.assertEqual(serialized["status"], "uncertain")
        self.assertEqual(serialized["provisional_candidate_ids"], ["sink-1"])
        self.assertEqual(
            serialized["provisional_locations"][0]["file"], "src/render.py"
        )
        self.assertEqual(
            serialized["suggested_location"],
            result.suggested_location.to_dict(),
        )
        self.assertFalse(serialized["semantic_role_verified"])

    def test_whole_patch_analysis_object_or_mapping_can_be_passed_directly(self) -> None:
        analysis = SimpleNamespace(candidates=(self._sink(),))
        object_result = self._resolve(analysis)
        mapping_result = self._resolve({"candidates": [self._sink()]})

        self.assertEqual(object_result.provisional_candidate_ids, ("sink-1",))
        self.assertEqual(mapping_result.provisional_candidate_ids, ("sink-1",))
        self.assertEqual(
            object_result.suggested_location,
            mapping_result.suggested_location,
        )

    def test_unexpected_analysis_property_failure_is_tristate_not_exception(self) -> None:
        class BrokenAnalysis:
            @property
            def candidates(self) -> object:
                raise ValueError("broken analysis")

        result = self._resolve(BrokenAnalysis())
        self.assertEqual((result.status, result.fact_status), ("uncertain", "uncertain"))
        self.assertEqual(result.error_code, "candidate_input_unreadable")


if __name__ == "__main__":
    unittest.main()
