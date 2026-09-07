"""Offline candidate recall/authority tests, not semantic-quality measurements."""
from __future__ import annotations

from dataclasses import replace
import difflib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.test_patch_analyzer import local_patch
from tests.test_real_t2_producer import _git
from tests import test_t2_toolbox as toolbox_fixture
from vulngym_agent.agents.t2_review_candidates import (
    REVIEW_POOL_POLICY, ReviewPoolLimitError, old_side_review_pool,
)
from vulngym_agent.agents.t2_toolbox import LocalT2Toolbox, LOCAL_T2_TOOL_CONTRACT_IDS
from vulngym_agent.analyzers.patch_analyzer import analyze_patch, PatchConflict
from vulngym_agent.orchestrator import Budget, Limits
from vulngym_agent.resolvers.critical_resolver import CriticalOperationResolver
from vulngym_agent.source.entry_search import EntryPointSearcher
from vulngym_agent.tools import AttemptToolRuntime
from vulngym_agent.tools.git import GitRepository


def analysis_for(before: str, after: str, old="src/item.py", new=None):
    text = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                       fromfile=f"a/{old}", tofile=f"b/{new or old}"))
    return analyze_patch(local_patch(text))


class OldSideReviewPoolTests(unittest.TestCase):
    def test_nonkeyword_removed_lines_are_hypotheses_not_added_side_locations(self):
        before = "record = query.first()\nObject.assign(item, body)\n"
        after = "record = query.filtered().first()\nObject.assign(item, { name })\n"
        analysis = analysis_for(before, after)
        for mode in ("sink", "guard"):
            with self.subTest(mode=mode):
                pool = old_side_review_pool(analysis, mode)
                extra = [c for c in pool if c.candidate_id.startswith("review-old-")]
                self.assertEqual([c.code for c in extra], before.splitlines())
                self.assertEqual([c.old_line for c in extra], [1, 2])
                self.assertTrue(all(c.mode == mode and c.change_kind == "removed" for c in extra))
                self.assertTrue(all(c.new_line is None for c in extra))
                self.assertTrue(all("unverified hypothesis" in c.reason for c in extra))
                self.assertEqual(pool, old_side_review_pool(analysis, mode))

    def test_lexical_ids_order_and_existing_removed_nomination_are_preserved(self):
        analysis = analysis_for("return eval(value)\n", "return parse(value)\n")
        self.assertTrue(analysis.candidates)
        pool = old_side_review_pool(analysis, "sink")
        self.assertEqual([c.candidate_id for c in pool[:len(analysis.candidates)]],
                         [c.candidate_id for c in analysis.candidates])
        self.assertEqual(len([c for c in pool if c.old_line == 1
                              and c.change_kind == "removed" and c.mode in {"sink", "dangerous_call"}]), 1)

    def test_added_only_and_blank_removed_lines_do_not_create_old_side_locations(self):
        added = analysis_for("", "result = parse(value)\n")
        blank = analysis_for("\n", "result = parse(value)\n")
        for analysis in (added, blank):
            self.assertFalse([c for c in old_side_review_pool(analysis, "sink")
                              if c.candidate_id.startswith("review-old-")])

    def test_rename_keeps_old_path_for_new_nominations(self):
        analysis = analysis_for("item = data\n", "item = clean\n", old="src/old.py", new="src/new.py")
        pool = old_side_review_pool(analysis, "sink")
        self.assertEqual([(c.file, c.old_line) for c in pool], [("src/old.py", 1)])

    def test_budget_excess_is_an_explicit_failure_not_silent_pruning(self):
        analysis = analysis_for("one = data\ntwo = data\n", "one = clean\ntwo = clean\n")
        with self.assertRaises(ReviewPoolLimitError):
            old_side_review_pool(analysis, "sink", max_candidates=1)
        long_line = analysis_for("x = " + "a" * 2000 + "\n", "x = clean\n")
        with self.assertRaises(ReviewPoolLimitError):
            old_side_review_pool(long_line, "sink")

    def test_strict_limits_and_conflicting_diff_rejected(self):
        analysis = analysis_for("x = data\n", "x = clean\n")
        for name in ("max_candidates", "max_code_chars"):
            for value in (True, 0, -1, "2", None):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    old_side_review_pool(analysis, "sink", **{name: value})
        for mode in ("auto", "other", True, None):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                old_side_review_pool(analysis, mode)
        with self.assertRaises(ValueError):
            old_side_review_pool(replace(analysis, conflicts=(PatchConflict("conflict", "test"),)), "sink")


class NamedCallableReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.files = {
            "service.ts": (
                "import { Row } from './types'\n"
                "const count = 0\n"
                "const createRow = async (body: Partial<Row>): Promise<Row> => {\n"
                "  const item = new Row()\n"
                "  Object.assign(item, body)\n"
                "  return item\n"
                "}\n"
                "function listRows(value: string) {\n"
                "  return value\n"
                "}\n"
                "export default { createRow, listRows }\n"
            ),
            "plain.ts": "import { Row } from './types'\nconst config = { enabled: true }\n",
            "handler-data.ts": "const requestHandler = { enabled: true }\n",
            "router.ts": "router.post('/rows', (req, res) => {\n  createRow(req.body)\n})\n",
            "outside.ts": "export function outside() { return 1 }\n",
        }
        _git(cls.root, "init", "-q")
        _git(cls.root, "config", "user.name", "VulnGym Test")
        _git(cls.root, "config", "user.email", "test@example.invalid")
        for name, text in cls.files.items():
            (cls.root / name).write_text(text, encoding="utf-8")
        _git(cls.root, "add", "--", *cls.files)
        _git(cls.root, "commit", "-q", "-m", "offline named callable fixture")
        cls.before = _git(cls.root, "rev-parse", "HEAD")
        (cls.root / "service.ts").write_text(cls.files["service.ts"].replace(
            "Object.assign(item, body)", "Object.assign(item, { name: body.name })"), encoding="utf-8")
        _git(cls.root, "add", "--", "service.ts")
        _git(cls.root, "commit", "-q", "-m", "offline replacement fixture")
        cls.after = _git(cls.root, "rev-parse", "HEAD")
        # Searches must use the pinned old blob, not this mutable worktree.
        (cls.root / "service.ts").write_text("WORKTREE_SENTINEL\n", encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def search(self, paths, *, profile=True, critical_paths=None, symbols=()):
        return EntryPointSearcher(self.root, review_callables=profile, whole_line_snippets=True).search(
            self.before, paths=paths, critical_paths=critical_paths or paths, critical_symbols=symbols)

    def test_named_arrow_and_function_are_review_candidates_not_external_routes(self):
        result = self.search(["service.ts"])
        self.assertEqual([(c.symbol, c.line, c.kind) for c in result.candidates],
                         [("createRow", 3, "callable"), ("listRows", 8, "callable")])
        for candidate in result.candidates:
            self.assertEqual(candidate.status, "uncertain")
            self.assertEqual(candidate.fact_status, "correct")
            self.assertFalse(candidate.explicit_external_binding)
            self.assertFalse(candidate.semantic_role_verified)
            self.assertFalse(candidate.runtime_reachability_verified)
            self.assertIn("not an external binding", candidate.evidence)
            self.assertNotIn("WORKTREE_SENTINEL", candidate.code)
            self.assertEqual(candidate.code, "\n".join(self.files["service.ts"].splitlines()[candidate.line-1:candidate.end_line]))

    def test_plain_file_and_handler_named_data_have_no_new_placeholder(self):
        for path in ("plain.ts", "handler-data.ts"):
            with self.subTest(path=path):
                result = self.search([path])
                self.assertFalse(result.candidates)
                self.assertIn("no_entry_construct_in_declared_path", [i.code for i in result.issues])
                self.assertEqual(result.status, "uncertain")
        legacy = self.search(["service.ts"], profile=False)
        self.assertEqual([(c.line, c.symbol) for c in legacy.candidates], [(1, None)])

    def test_only_explicit_paths_are_read_and_supplied_router_is_separate_candidate(self):
        original = GitRepository.read_file
        reads = []
        def read_file(repo, commit, path):
            reads.append(path)
            return original(repo, commit, path)
        with patch.object(GitRepository, "read_file", read_file):
            result = self.search(["service.ts", "router.ts"], critical_paths=["service.ts"], symbols=["createRow"])
        self.assertEqual(reads, ["service.ts", "router.ts"])
        route = next(c for c in result.candidates if c.path == "router.ts")
        self.assertEqual(route.kind, "route")
        self.assertTrue(route.explicit_external_binding)
        self.assertFalse(route.runtime_reachability_verified)
        self.assertNotIn("outside.ts", result.searched_paths)

    def test_old_removed_nomination_is_fact_checked_and_off_by_one_is_not_relocated(self):
        before = self.files["service.ts"]
        after = before.replace("Object.assign(item, body)", "Object.assign(item, { name: body.name })")
        pool = old_side_review_pool(analysis_for(before, after, old="service.ts"), "sink")
        nomination = next(c for c in pool if c.code.strip() == "Object.assign(item, body)")
        resolver = CriticalOperationResolver(self.root, line_tolerance=0)
        result = resolver.resolve(self.before, self.after, mode="sink", candidates=[nomination])
        candidate = result.candidates[0]
        self.assertEqual(candidate.fact_status, "correct")
        self.assertEqual(candidate.status, "uncertain")
        self.assertFalse(result.semantic_role_verified)
        shifted = resolver.resolve(self.before, self.after, mode="sink",
                                   candidates=[replace(nomination, old_line=nomination.old_line - 1)])
        self.assertFalse(shifted.provisional_candidate_ids)

    def test_profile_flag_is_strict_and_default_output_stays_legacy(self):
        for value in (1, "true", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                EntryPointSearcher(self.root, review_callables=value)
        kwargs = dict(paths=["service.ts"], critical_paths=["service.ts"])
        default = EntryPointSearcher(self.root).search(self.before, **kwargs).to_dict()
        explicit = EntryPointSearcher(self.root, review_callables=False).search(self.before, **kwargs).to_dict()
        self.assertEqual(default, explicit)


class ReviewToolboxTests(unittest.TestCase):
    def setUp(self):
        self.fixture = toolbox_fixture.LocalT2ToolboxTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def toolbox(self, **kwargs):
        f = self.fixture
        return LocalT2Toolbox(f.task, f.toolbox.task_input, f.package_root, f.repository, **kwargs)

    def test_only_two_tool_contract_ids_change_and_profile_is_strict(self):
        new = self.toolbox(review_candidate_pool=True)
        changed = {name for name, definition in new.registry.items()
                   if definition.contract_id != LOCAL_T2_TOOL_CONTRACT_IDS[name]}
        self.assertEqual(changed, {"dataflow_candidate_search", "route_recognition"})
        self.assertEqual(set(new.registry), set(self.fixture.toolbox.registry))
        whole = self.toolbox(review_candidate_pool=True, whole_line_entry_snippets=True)
        self.assertNotEqual(new.registry["route_recognition"].contract_id,
                            whole.registry["route_recognition"].contract_id)
        for value in (1, "true", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.toolbox(review_candidate_pool=value)

    def test_profile_artifact_is_a_hypothesis_and_scope_cannot_expand(self):
        f = self.fixture
        toolbox = self.toolbox(review_candidate_pool=True)
        runtime = AttemptToolRuntime(task_id=f.task.task_id, attempt=0, policy_scope="t2.initial",
                                     budget=Budget(Limits(max_tool_calls=20)), registry=toolbox.registry,
                                     allowlist=toolbox.tool_names)
        def call(index, name, arguments):
            return runtime.call(f"TOOL-{index:05d}", name, arguments)
        repo = call(1, "resolve_local_repo", {"repo_url": toolbox_fixture.REPO_URL}).artifact_refs[0]
        diff = call(2, "git_diff", {"repo": repo, "before_commit": f.vulnerable,
                                   "after_commit": f.fix, "path": toolbox_fixture.SOURCE_PATH})
        result = call(3, "dataflow_candidate_search", {"repo": repo, "diff": diff.artifact_refs[0], "mode": "sink"})
        self.assertEqual(result.status, "success")
        payload = runtime.resolve_artifact(result.artifact_refs[0]).payload
        self.assertEqual(payload["candidate_policy"], REVIEW_POOL_POLICY)
        self.assertIs(payload["mode_is_unverified_hypothesis"], True)
        self.assertIs(payload["critical_resolution"]["semantic_role_verified"], False)
        unknown = call(4, "dataflow_candidate_search", {"repo": repo, "diff": diff.artifact_refs[0], "mode": "auto"})
        self.assertEqual(unknown.error_code, "invalid_critical_mode")
        undeclared = call(5, "git_show", {"repo": repo, "commit": f.vulnerable, "path": "src/undeclared.py"})
        self.assertEqual(undeclared.status, "blocked")


if __name__ == "__main__":
    unittest.main()
