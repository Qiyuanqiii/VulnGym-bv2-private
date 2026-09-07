"""Whole-line excerpts fix annotation text facts, not semantic role validation."""
from __future__ import annotations

import unittest

from scripts.audit_lane_a_review_offline import check_entry_excerpt
from tests import test_real_t2_producer as fx
from vulngym_agent.agents.t2_execution import LocalT2ContextFactory
from vulngym_agent.orchestrator import Limits
from vulngym_agent.source.entry_search import EntryPointSearcher, whole_line_excerpt
from vulngym_agent.t2_production_cli import LocalProductionTaskRunner
from vulngym_agent.validators.location_validator import LocationValidator


class WholeLineExcerptTests(unittest.TestCase):
    def test_short_text_is_byte_preserving(self):
        for text in ("one", "one\ntwo", "one\ntwo\n", "中文\r\n第二行"):
            self.assertEqual(whole_line_excerpt(text), text)

    def test_partial_final_line_is_removed_not_fabricated(self):
        self.assertEqual(whole_line_excerpt("first\nsecond_long\nthird", max_chars=12), "first")

    def test_exact_line_boundary_keeps_full_line(self):
        self.assertEqual(whole_line_excerpt("first\nsecond", max_chars=5), "first")
        self.assertEqual(whole_line_excerpt("first\nsecond", max_chars=6), "first")

    def test_single_overlong_line_is_not_issued(self):
        self.assertIsNone(whole_line_excerpt("x" * 2001))
        self.assertIsNone(whole_line_excerpt("x" * 2001 + "\nshort"))

    def test_empty_or_whitespace_is_not_a_candidate(self):
        for text in ("", "  ", "\n ", "\n" + "x" * 3000):
            self.assertIsNone(whole_line_excerpt(text))

    def test_exact_cap_and_unicode_are_complete(self):
        self.assertEqual(whole_line_excerpt("x" * 2000), "x" * 2000)
        self.assertEqual(whole_line_excerpt("甲乙\n第三行", max_chars=5), "甲乙")

    def test_invalid_limits_rejected(self):
        for limit in (True, 0, -1, "2000", None):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                whole_line_excerpt("x", max_chars=limit)


class WholeLineEntryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fx = fx.LocalStructuredT2ProducerTests()
        self.addCleanup(self.fx.doCleanups)
        self.fx.setUp()

    def long_source(self):
        before = ("def dangerous(user):\n    return eval(user)\n\n"
                  "@app.route('/run')\ndef public_route(request):\n"
                  + "".join(f"    value_{i} = '" + "x" * 37 + "'\n" for i in range(80))
                  + "    return dangerous(request)\n")
        after = before.replace("eval(user)", "int(user)")
        for label, content in (("before", before), ("after", after)):
            (self.fx.repository / fx.SOURCE_PATH).write_text(content, encoding="utf-8")
            fx._git(self.fx.repository, "add", "--", fx.SOURCE_PATH)
            fx._git(self.fx.repository, "commit", "-q", "-m", label)
            setattr(self.fx, "vulnerable_commit" if label == "before" else "fix_commit",
                    fx._git(self.fx.repository, "rev-parse", "HEAD"))
        self.fx._write_advisory((self.fx.fix_commit,))
        patch = fx._git(self.fx.repository, "diff", self.fx.vulnerable_commit,
                        self.fx.fix_commit, "--", fx.SOURCE_PATH)
        (self.fx.package_root / "patches/fix.patch").write_text(patch + "\n", encoding="utf-8")

    def test_long_entry_default_stays_legacy_new_policy_passes_exact_text_check(self):
        self.long_source()
        arguments = {"paths": [fx.SOURCE_PATH], "critical_symbols": ["dangerous"]}
        old = EntryPointSearcher(self.fx.repository).search(self.fx.vulnerable_commit, **arguments)
        new = EntryPointSearcher(self.fx.repository, whole_line_snippets=True).search(self.fx.vulnerable_commit, **arguments)
        old_entry = next(c for c in old.candidates if c.symbol == "public_route")
        new_entry = next(c for c in new.candidates if c.symbol == "public_route")
        self.assertEqual(len(old_entry.code), 2000)
        self.assertLess(len(new_entry.code), 2000)
        self.assertEqual(new_entry.code, old_entry.code.rsplit("\n", 1)[0])
        self.assertEqual(new_entry.end_line, new_entry.line + len(new_entry.code.splitlines()) - 1)
        validator = LocationValidator(self.fx.repository, line_tolerance=0)
        check = lambda c: validator.validate_mapping(self.fx.vulnerable_commit, {"file": c.path, "line": c.line, "code": c.code})
        self.assertEqual(check(old_entry).fact_status, "incorrect")
        self.assertEqual(check(new_entry).fact_status, "correct")
        self.assertFalse(check(new_entry).semantic_role_verified)
        self.assertEqual(new_entry.status, "uncertain")
        self.assertIn("remaining construct text is omitted", new_entry.evidence)

    def test_production_wiring_emits_whole_lines_and_t1_remains_uncertain(self):
        self.long_source()
        backend = fx._ScriptedBackend()
        original = backend.invoke
        def invoke(request):
            answer = original(request)
            if request.stage == "semantic_judge":
                answer["entry_candidate_id"] = next(c["candidate_id"] for c in request.payload["entry_candidates"]
                                                    if c["symbol"] == "public_route")
            return answer
        backend.invoke = invoke
        runner = LocalProductionTaskRunner(
            backend=backend, package_root=self.fx.package_root,
            repo_map={fx.REPO_URL: self.fx.repository}, limits=Limits(max_llm_calls=3, max_tool_calls=80, max_repair_iterations=0),
        )
        outcome = runner.run(self.fx._task())
        self.assertIsNotNone(outcome.entry)
        self.assertEqual(outcome.report.fields["entry_point"].status, "uncertain")
        self.assertIn("File/line/code facts are verified", outcome.report.fields["entry_point"].evidence)
        self.assertEqual(outcome.status, "manual_review")
        self.assertEqual(outcome.entry["verify"], 0)
        self.assertLess(len(outcome.entry["entry_point"]["code"]), 2000)

    def test_audit_recognizes_exact_character_truncation_not_semantic_truth(self):
        self.long_source()
        result = EntryPointSearcher(self.fx.repository).search(
            self.fx.vulnerable_commit, paths=[fx.SOURCE_PATH], critical_paths=[fx.SOURCE_PATH],
        )
        candidate = next(c for c in result.candidates if c.symbol == "public_route")
        entry = {"commit": self.fx.vulnerable_commit, "entry_point": {
            "file": candidate.path, "line": candidate.line, "code": candidate.code,
        }}
        proof = check_entry_excerpt(entry, self.fx.repository)
        self.assertEqual(proof["classification"], "confirmed_producer_character_truncation")
        self.assertEqual(proof["original_fact_status"], "incorrect")
        self.assertEqual(proof["proposed_excerpt"]["fact_status"], "correct")
        self.assertFalse(proof["semantic_role_verified"])
        self.assertFalse(proof["historical_entry_modified"])
        self.assertEqual(entry["entry_point"]["code"], candidate.code)

    def test_overlong_single_line_construct_and_plain_anchor_are_unissued(self):
        for name, text in (("export.ts", "export const handler = '" + "x" * 2200 + "';\n"),
                           ("plain.ts", "const value = '" + "x" * 2200 + "';\n")):
            (self.fx.repository / name).write_text(text, encoding="utf-8")
            fx._git(self.fx.repository, "add", "--", name)
            fx._git(self.fx.repository, "commit", "-q", "-m", "overlong fixture")
            commit = fx._git(self.fx.repository, "rev-parse", "HEAD")
            result = EntryPointSearcher(self.fx.repository, whole_line_snippets=True).search(
                commit, paths=[name], critical_paths=[name],
            )
            self.assertEqual(result.candidates, ())
            self.assertEqual(result.fact_status, "uncertain")
            self.assertIn("entry_snippet_first_line_too_large", [i.code for i in result.issues])

    def test_opt_in_flag_is_strict_and_cannot_disable_new_production_policy(self):
        for value in (1, None, "true"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                EntryPointSearcher(self.fx.repository, whole_line_snippets=value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                LocalT2ContextFactory(self.fx.package_root, {fx.REPO_URL: self.fx.repository}, fx._ScriptedBackend(),
                                      whole_line_entry_snippets=value)
        with self.assertRaises(ValueError):
            LocalProductionTaskRunner(backend=fx._ScriptedBackend(), whole_line_entry_snippets=False)


if __name__ == "__main__":
    unittest.main()
