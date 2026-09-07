from __future__ import annotations

from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import audit_lane_a_review_offline as audit
from vulngym_agent.models import FieldValidation


class ReviewAuditTests(unittest.TestCase):
    def field(self, evidence, status="uncertain"):
        return FieldValidation(status=status, confidence=0.5, evidence=evidence)

    def test_explicit_checker_limitation_is_not_claimed_to_be_missing_input(self):
        field = self.field("project 通过了结构检查，但确定性事实门禁不能判断项目名。")
        self.assertEqual(audit.classify_field("project", field, {}), "checker_semantic_capability_gap")
        self.assertEqual(audit.classify_field("entry_point", field, {}), "unclassified_uncertain")

    def test_location_fact_proof_does_not_become_semantic_proof(self):
        field = self.field("File/line/code facts are verified, but entry-point reachability or critical-operation semantics were not evaluated.")
        for name in ("entry_point", "critical_operation"):
            self.assertEqual(audit.classify_field(name, field, {}), "role_semantics_unverified")

    def test_empty_trace_requires_explicit_report_limitation(self):
        field = self.field("trace 是 Schema 合法的空数组，仍无法证明完整。")
        self.assertEqual(audit.classify_field("trace", field, {"trace": []}), "trace_completeness_unverified")
        self.assertEqual(audit.classify_field("trace", field, {"trace": [{}]}), "unclassified_uncertain")
        self.assertEqual(audit.classify_field("trace", self.field("读取失败"), {"trace": []}), "unclassified_uncertain")

    def test_unknown_or_execution_failure_reason_remains_unclassified(self):
        for evidence in ("source read failed", "unsupported_check", "ambiguous", "missing inputs", "new wording"):
            self.assertEqual(audit.classify_field("entry_point", self.field(evidence), {}), "unclassified_uncertain")

    def test_incorrect_not_reclassified_as_uncertain_or_correct(self):
        self.assertEqual(audit.classify_field("entry_point", self.field("mismatch", "incorrect"), {}), "reported_incorrect_fact")
        self.assertIsNone(audit.classify_field("entry_point", self.field("good", "correct"), {}))

    def bundle(self, status="uncertain"):
        entry = {"entry_id": "entry-00001", "verify": 0, "trace": [], "repo_url": "https://github.com/example/project"}
        report = SimpleNamespace(verdict=status, report_id="GHSA-1111-2222-3333", fields={
            "entry_point": self.field("mismatch" if status == "incorrect" else "unknown", status),
            "project": self.field("确定性事实门禁不能判断项目名"),
        })
        binding = {"task_id": "task-one", "entry_sha256": "a" * 64, "validation_sha256": "b" * 64, "status": "manual_review"}
        return SimpleNamespace(entries=(entry,), validations=(report,), manifest=SimpleNamespace(
            tasks=(binding,), files={}, submission_sha256="c" * 64, source_replay_dataset_sha256="d" * 64,
        ))

    def test_uncertain_report_does_not_trigger_source_reads_or_mutate_original(self):
        bundle = self.bundle()
        before = deepcopy(bundle.entries)
        with patch.object(audit, "check_entry_excerpt") as check:
            summary, cards = audit.audit_bundle(bundle, {})
        check.assert_not_called()
        self.assertEqual(bundle.entries, before)
        self.assertEqual(cards[0]["original_verdict"], "uncertain")
        self.assertFalse(cards[0]["semantic_review_completed"])
        self.assertEqual(summary["new_finalized_entries"], 0)

    def test_confirmed_text_correction_does_not_promote_whole_record(self):
        bundle = self.bundle("incorrect")
        with patch.object(audit, "check_entry_excerpt", return_value={"classification": "confirmed_producer_character_truncation"}):
            summary, cards = audit.audit_bundle(bundle, {"https://github.com/example/project": "unused-test-path"})
        self.assertEqual(summary["confirmed_excerpt_truncations"], 1)
        self.assertEqual(cards[0]["original_verdict"], "incorrect")
        self.assertEqual(summary["historical_records_modified"], 0)
        self.assertEqual(summary["semantic_review_completed"], 0)

    def test_missing_trusted_repo_map_does_not_guess_or_access_other_repos(self):
        with patch.object(audit, "check_entry_excerpt") as check, self.assertRaises(ValueError):
            audit.audit_bundle(self.bundle("incorrect"), {})
        check.assert_not_called()


class ReviewAuditCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.repo_map = self.root / "repos.json"
        self.repo_map.write_text(json.dumps({"contract_version": 1, "repositories": [{
            "repo_url": "https://github.com/example/project", "path": str(self.repository),
        }]}), encoding="utf-8")
        self.output = self.root / "audit"
        reader = patch.object(audit, "read_submission_predictions",
                              return_value=ReviewAuditTests().bundle())
        self.reader = reader.start()
        self.addCleanup(reader.stop)

    def call(self, *extra, output=None):
        args = ["--submission-dir", str(self.source), "--repo-map", str(self.repo_map),
                "--source-set-sha256", "d" * 64, "--submission-sha256", "c" * 64,
                "--task-count", "1", "--output-dir", str(output or self.output), *extra]
        with redirect_stdout(io.StringIO()):
            return audit.main(args)

    def test_pins_pass_to_reader_and_two_checks_preserve_identical_bytes(self):
        self.assertEqual(self.call(), 0)
        self.reader.assert_called_once_with(
            self.source.resolve(), expected_source_replay_dataset_sha256="d" * 64,
            expected_task_count=1, expected_submission_sha256="c" * 64,
        )
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        self.assertEqual(set(before), {"summary.json", "review_cards.jsonl"})
        self.assertEqual(self.call("--check"), 0)
        self.assertEqual(self.call("--check"), 0)
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()}, before)
        self.assertEqual(list(self.source.iterdir()), [])

    def test_existing_output_is_not_overwritten(self):
        self.assertEqual(self.call(), 0)
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        self.assertEqual(self.call(), 2)
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()}, before)

    def test_changed_bytes_or_extra_file_fail_readback_without_repair(self):
        self.assertEqual(self.call(), 0)
        summary = self.output / "summary.json"
        original = summary.read_bytes()
        changed = original + b" "
        summary.write_bytes(changed)
        self.assertEqual(self.call("--check"), 2)
        self.assertEqual(summary.read_bytes(), changed)
        summary.write_bytes(original)
        extra = self.output / "unexpected.txt"
        extra.write_text("preserve", encoding="utf-8")
        self.assertEqual(self.call("--check"), 2)
        self.assertEqual(extra.read_text(encoding="utf-8"), "preserve")

    def test_input_overlap_or_wrong_digest_refused_before_output(self):
        self.assertEqual(self.call(output=self.source / "audit"), 2)
        self.reader.assert_not_called()
        self.assertEqual(list(self.source.iterdir()), [])
        self.reader.side_effect = ValueError("digest mismatch")
        self.assertEqual(self.call(), 2)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
