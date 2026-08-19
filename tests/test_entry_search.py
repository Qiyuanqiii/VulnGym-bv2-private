from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from vulngym_agent.source import (
    EntryPointSearcher,
    EntryPointSearchResult,
    search_entry_points,
)
from vulngym_agent.tools.git import GitRepository


class EntryPointSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_directory = tempfile.TemporaryDirectory()
        cls.repo_path = Path(cls._temporary_directory.name)
        files: dict[str, str | bytes] = {
            "src/app.py": (
                "from src.critical import dangerous\n\n"
                "@app.post('/run')\n"
                "def submit(value):\n"
                "    return dangerous(value)\n\n"
                "def helper(value):\n"
                "    return dangerous(value)\n"
            ),
            "src/unrelated.py": (
                "from src.critical import dangerous\n\n"
                "@app.get('/health')\n"
                "def health():\n"
                "    return 'ok'\n"
            ),
            "src/critical.py": "def dangerous(value):\n    return eval(value)\n",
            "web/server.ts": (
                "export function handleRequest(value: string) {\n"
                "  return dangerous(value);\n"
                "}\n"
            ),
            "java/App.java": (
                "class App {\n"
                "  @PostMapping(\"/run\")\n"
                "  public String submit(String value) {\n"
                "    return dangerous(value);\n"
                "  }\n"
                "}\n"
            ),
            "go/server.go": (
                "package app\n"
                "func Serve(value string) string {\n"
                "  return dangerous(value)\n"
                "}\n"
            ),
            "ruby/app.rb": (
                "post '/run' do\n"
                "  dangerous(params[:value])\n"
                "end\n"
            ),
            "php/App.php": (
                "<?php\n"
                "#[Route('/run')]\n"
                "public function submit($value) {\n"
                "  return dangerous($value);\n"
                "}\n"
            ),
            "docs/readme.md": "dangerous is documented here\n",
            "src/non_utf8.py": b"def handler(x):\n    return dangerous(\xff)\n",
            "src/large.py": "@app.get('/')\ndef route():\n    return dangerous('x')\n" + "# padding\n" * 100,
        }
        for name, content in files.items():
            path = cls.repo_path / Path(*name.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
        cls._git("init", "-q")
        cls._git("config", "user.name", "VulnGym Test")
        cls._git("config", "user.email", "vulngym@example.invalid")
        cls._git("add", "-A")
        cls._git("commit", "-q", "-m", "immutable entry fixtures")
        cls.commit = cls._git("rev-parse", "HEAD").stdout.strip()
        # The search must use the commit object, not the mutable worktree.
        (cls.repo_path / "src" / "app.py").write_text(
            "WORKTREE_ONLY = True\n", encoding="utf-8"
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary_directory.cleanup()

    @classmethod
    def _git(cls, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments], cwd=cls.repo_path, check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def setUp(self) -> None:
        self.repository = GitRepository(self.repo_path)

    def search(self, paths: list[object], **kwargs: object) -> EntryPointSearchResult:
        return EntryPointSearcher(self.repository).search(
            self.commit, paths=paths, critical_symbols=["dangerous"], **kwargs
        )

    def test_python_route_direct_reference_is_structural_fact_only(self) -> None:
        result = self.search(["src/app.py"])
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "correct")
        route = next(candidate for candidate in result.candidates if candidate.kind == "route")
        self.assertTrue(route.explicit_external_binding)
        self.assertTrue(route.direct_critical_reference)
        self.assertEqual(route.status, "uncertain")
        self.assertFalse(route.runtime_reachability_verified)
        self.assertFalse(route.semantic_role_verified)
        self.assertIn("dangerous(value)", route.code)
        self.assertNotIn("WORKTREE_ONLY", route.code)

    def test_internal_helper_is_never_correct(self) -> None:
        result = self.search(["src/app.py"])
        helper = next(candidate for candidate in result.candidates if candidate.symbol == "helper")
        self.assertEqual(helper.kind, "handler")
        self.assertFalse(helper.explicit_external_binding)
        self.assertEqual(helper.status, "uncertain")

    def test_file_wide_only_reference_does_not_make_route_correct(self) -> None:
        result = self.search(["src/unrelated.py"])
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "correct")
        self.assertEqual(len(result.candidates), 1)
        self.assertFalse(result.candidates[0].direct_critical_reference)
        self.assertEqual(result.candidates[0].status, "uncertain")

    def test_supported_languages_produce_conservative_candidates(self) -> None:
        for path, kind in (
            ("web/server.ts", "export"),
            ("java/App.java", "route"),
            ("go/server.go", "export"),
            ("ruby/app.rb", "route"),
            ("php/App.php", "route"),
        ):
            with self.subTest(path=path):
                result = self.search([path])
                self.assertTrue(any(candidate.kind == kind for candidate in result.candidates))
                self.assertTrue(all(not candidate.runtime_reachability_verified for candidate in result.candidates))

    def test_critical_path_import_can_be_a_direct_clue(self) -> None:
        result = EntryPointSearcher(self.repository).search(
            self.commit,
            paths=["src/app.py"],
            critical_paths=["src/critical.py"],
        )
        # The import is outside the route function, so this remains uncertain.
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.candidates[0].matched_clue, "path:src/critical.py")
        self.assertFalse(result.candidates[0].direct_critical_reference)

    def test_non_utf8_and_unsupported_files_are_uncertain_with_reasons(self) -> None:
        result = self.search(["src/non_utf8.py", "docs/readme.md"])
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "uncertain")
        self.assertEqual(
            {issue.code for issue in result.issues},
            {"non_utf8_source", "unsupported_language"},
        )
        self.assertEqual(len(result.unsupported_reasons), 1)

    def test_unsafe_or_empty_path_list_is_rejected_before_read(self) -> None:
        empty = self.search([])
        escaped = self.search(["../src/app.py"])
        scalar = EntryPointSearcher(self.repository).search(
            self.commit, paths="src/app.py", critical_symbols=["dangerous"]
        )
        for result in (empty, escaped, scalar):
            self.assertEqual(result.status, "incorrect")
            self.assertEqual(result.bytes_read, 0)
            self.assertEqual(result.candidates, ())

    def test_max_files_is_a_strict_pre_read_gate(self) -> None:
        result = EntryPointSearcher(self.repository, max_files=1).search(
            self.commit,
            paths=["src/app.py", "src/critical.py"],
            critical_symbols=["dangerous"],
        )
        self.assertEqual(result.error_code, "max_files_exceeded")
        self.assertEqual(result.bytes_read, 0)

    def test_max_bytes_does_not_partially_read_oversized_blob(self) -> None:
        result = EntryPointSearcher(self.repository, max_bytes=64).search(
            self.commit, paths=["src/large.py"], critical_symbols=["dangerous"]
        )
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.bytes_read, 0)
        self.assertEqual(result.issues[0].code, "source_too_large_or_budget_exceeded")

    def test_max_candidates_truncates_and_marks_overall_uncertain(self) -> None:
        result = EntryPointSearcher(self.repository, max_candidates=1).search(
            self.commit, paths=["src/app.py"], critical_symbols=["dangerous"]
        )
        self.assertEqual(len(result.candidates), 1)
        self.assertTrue(result.candidates_truncated)
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.fact_status, "uncertain")

    def test_missing_file_is_uncertain_not_repository_scan(self) -> None:
        result = self.search(["src/missing.py"])
        self.assertEqual(result.status, "uncertain")
        self.assertEqual(result.searched_paths, ())
        self.assertEqual(result.issues[0].code, "source_read_failed")

    def test_convenience_api_and_serialization(self) -> None:
        result = search_entry_points(
            self.repository, self.commit,
            paths=["src/app.py"], critical_symbols=["dangerous"],
        )
        payload = result.to_dict()
        self.assertEqual(payload["commit"], self.commit)
        self.assertIsInstance(payload["candidates"], tuple)
        self.assertEqual(result.selected_paths, ("src/app.py",))

    def test_constructor_limits_are_bounded(self) -> None:
        for keyword in ("max_files", "max_bytes", "max_candidates"):
            with self.subTest(keyword=keyword):
                with self.assertRaises(ValueError):
                    EntryPointSearcher(self.repository, **{keyword: 0})
                with self.assertRaises(ValueError):
                    EntryPointSearcher(self.repository, **{keyword: True})


if __name__ == "__main__":
    unittest.main()
