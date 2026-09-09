"""Four small offline output checks; the backend is a synthetic test script."""
from contextlib import redirect_stdout
import io
import json
import unittest
from unittest.mock import patch

from tests import test_t2_production_cli as composition
from tests.test_t2_reflection_defer import response as reflection_defer
from vulngym_agent import t2_production_cli as production


class T2UserResultTests(unittest.TestCase):
    def setUp(self):
        self.base = composition.ProductionCompositionTests()
        self.addCleanup(self.base.doCleanups)
        self.base.setUp()
        self.root = self.base.fixture.root
        self.results = self.root / "results"

    def invoke(self):
        stdout = io.StringIO()
        with patch.object(production, "load_backend_factory", return_value=self.base.backend), redirect_stdout(stdout):
            code = production.main(self.base.cli_arguments() + ["--results-dir", str(self.results)])
        return code, json.loads(stdout.getvalue())

    def read(self, name):
        return [json.loads(line) for line in (self.results / name).read_text(encoding="utf-8").splitlines()]

    def test_complete_manual_review_candidate_is_immediately_usable(self):
        code, summary = self.invoke()
        self.assertEqual(code, 0, summary)
        self.assertTrue(summary["user_results_written"])
        self.assertEqual((self.root / "output" / "entries.jsonl").read_bytes(), b"")
        entry, = self.read("entries.jsonl")
        report, = self.read("validation.jsonl")
        self.assertEqual(entry["verify"], 0)
        self.assertEqual(report["entry_id"], entry["entry_id"])
        self.assertEqual(report["verdict"], "uncertain")
        user_summary, = self.read("summary.json")
        self.assertEqual(user_summary["status"], "completed")
        self.assertEqual(user_summary["candidate_count"], 1)
        self.assertEqual(user_summary["tasks"][0]["review_status"], "t1_uncertain")
        self.assertEqual(set(p.name for p in self.results.iterdir()),
                         {"entries.jsonl", "validation.jsonl", "deferred.jsonl", "summary.json"})

    def test_reflection_defer_does_not_publish_the_unemitted_candidate(self):
        invoke = self.base.backend.invoke
        self.base.backend.invoke = lambda request: (
            reflection_defer(request.payload) if request.stage == "reflection" else invoke(request))
        code, summary = self.invoke()
        self.assertEqual(code, 0, summary)
        self.assertEqual(self.read("entries.jsonl"), [])
        self.assertEqual(self.read("validation.jsonl"), [])
        deferred, = self.read("deferred.jsonl")
        self.assertEqual(deferred["stage"], "reflection")
        self.assertEqual(deferred["reason_code"], "model_deferred")
        self.assertEqual(deferred["model_reason"]["missing_fields"], ["trace"])
        self.assertNotIn("model_defer_details", json.dumps(deferred))
        self.assertNotIn("explanation", json.dumps(deferred))

    def test_t1_error_keeps_the_complete_t2_candidate_as_unreviewed(self):
        with patch("vulngym_agent.closed_loop_cli.LocalT1ValidatorFactory.__call__",
                   side_effect=RuntimeError("do-not-copy-provider-secret")):
            code, summary = self.invoke()
        self.assertEqual(code, 1, summary)
        entry, = self.read("entries.jsonl")
        self.assertEqual(entry["verify"], 0)
        self.assertEqual(self.read("validation.jsonl"), [])
        user_summary, = self.read("summary.json")
        self.assertEqual(user_summary["unreviewed_candidate_count"], 1)
        self.assertEqual(user_summary["tasks"][0]["review_status"], "unreviewed")
        self.assertEqual(user_summary["batch_exit_code"], 1)
        for item in self.results.iterdir():
            self.assertNotIn("do-not-copy-provider-secret", item.read_text(encoding="utf-8"))

    def test_existing_or_overlapping_results_are_rejected_before_backend_loading(self):
        existing = self.root / "already-there"
        existing.mkdir()
        for target in (existing, self.base.fixture.package_root / "results",
                       self.base.fixture.repository / "results", self.root / "output"):
            with self.subTest(target=target.name), patch.object(production, "load_backend_factory") as load, redirect_stdout(io.StringIO()):
                code = production.main(self.base.cli_arguments() + ["--results-dir", str(target)])
            self.assertEqual(code, 2)
            load.assert_not_called()
        self.assertEqual(list(existing.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
