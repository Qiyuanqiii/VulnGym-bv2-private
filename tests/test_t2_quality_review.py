from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import prepare_t2_quality_review as quality
from vulngym_agent.models import FieldValidation

SYSTEM_SHA = "a" * 40


def bundle_fixture():
    entries, bindings, reports = [], [], []
    for i in range(40):
        # Five known errors from two repositories, plus six further repos.
        repo_index = (0 if i < 4 else 1) if i < 5 else ((i - 5) % 8)
        report_id = f"GHSA-0000-0000-{i:04X}"
        entries.append({
            "entry_id": f"entry-{i + 1:05d}", "report_id": report_id,
            "repo_url": f"https://github.com/example/repo-{repo_index}",
            "commit": "b" * 40, "source_link": f"https://github.com/advisories/{report_id}",
            "verify": 0, "trace": [], "entry_point": {"file": "entry.py"},
            "critical_operation": {"file": "different.py" if i % 3 == 0 else "entry.py"},
        })
        bindings.append({"task_id": f"task-{i:03d}", "entry_sha256": f"{i:064x}",
                         "validation_sha256": f"{i + 100:064x}", "status": "manual_review"})
        reports.append(SimpleNamespace(verdict="incorrect" if i < 5 else "uncertain", fields={
            "project": FieldValidation(status="uncertain", confidence=0.5,
                                       evidence="确定性事实门禁不能判断项目名"),
        }))
    return SimpleNamespace(entries=tuple(entries), validations=tuple(reports), manifest=SimpleNamespace(
        tasks=tuple(bindings), files={}, source_replay_dataset_sha256="c" * 64, submission_sha256="d" * 64,
    ))


class QualityReviewTests(unittest.TestCase):
    def setUp(self):
        self.bundle = bundle_fixture()
        self.payloads = quality.prepare(self.bundle, system_commit=SYSTEM_SHA)
        self.cohort = quality.parse(self.payloads["cohort.json"])
        self.forms = [quality.parse(line) for line in self.payloads["review_template.jsonl"].splitlines()]

    def assess(self, field="entry_role", status="supported", index=0):
        self.forms[index]["reviewer"] = {"name": "fixture reviewer", "kind": "ai_assisted_self_review",
                                         "independence": "self", "assessed_at": "2026-09-07"}
        self.forms[index]["fields"][field] = {"status": status, "evidence_refs": ["fixture:source-1"],
                                            "rationale": "Synthetic rationale; not a real assessment.",
                                            "next_action": "Check the missing source context." if status == "uncertain" else ""}

    def test_retains_all_errors_and_covers_eight_repositories(self):
        cases = self.cohort["cases"]
        self.assertEqual(len(cases), 12)
        self.assertEqual(len({c["repo_url"] for c in cases}), 8)
        self.assertEqual(sum(c["historical_t1_verdict"] == "incorrect" for c in cases), 5)
        self.assertEqual(sum(c["selection_reason"] == "retain_all_reported_errors" for c in cases), 5)

    def test_selection_and_output_are_invariant_to_source_order(self):
        reverse = deepcopy(self.bundle)
        reverse.entries = tuple(reversed(reverse.entries))
        reverse.validations = tuple(reversed(reverse.validations))
        reverse.manifest.tasks = tuple(reversed(reverse.manifest.tasks))
        self.assertEqual(quality.prepare(reverse, system_commit=SYSTEM_SHA), self.payloads)

    def test_cannot_drop_error_rows_to_fit_smaller_cohort(self):
        with self.assertRaisesRegex(ValueError, "keep_errors"):
            quality.select_records(self.bundle, size=4, min_repositories=2)

    def test_invalid_size_or_insufficient_diversity_or_duplicate_task_fails(self):
        for size, repos in ((True, 4), (41, 4), (101, 4), (12, 0), (12, 9)):
            with self.subTest(size=size, repos=repos), self.assertRaises(ValueError):
                quality.select_records(self.bundle, size, repos)
        self.bundle.manifest.tasks[1]["task_id"] = self.bundle.manifest.tasks[0]["task_id"]
        with self.assertRaises(ValueError):
            quality.select_records(self.bundle)

    def test_historical_groups_are_not_labeled_unseen_or_complete(self):
        self.assertEqual({c["sample_group"] for c in self.cohort["cases"]}, {"development_regression"})
        self.assertEqual(self.cohort["new_input_cohort"]["selected_report_ids"], [])
        self.assertEqual(self.cohort["system_for_next_production_test"]["status"], "planned_not_executed")
        self.assertIn("retrospective", self.cohort["selection_timing"])
        self.assertTrue(all(c["scenario_evaluation"] == "not_reviewed" for c in self.cohort["cases"]))

    def test_unknown_is_not_zero_or_full_accuracy_and_fact_semantic_are_separate(self):
        metrics = quality.summarize(self.cohort, self.forms)
        self.assertEqual(metrics["cases_with_any_review"], 0)
        self.assertEqual(metrics["case_count"], 12)
        for group, count in (("fact", 48), ("semantic", 60)):
            data = metrics["quality_groups"][group]
            self.assertEqual(data["field_slots"], count)
            self.assertEqual(data["field_counts"]["not_reviewed"], count)
            self.assertEqual(data["adjudicated_fields"], 0)
            self.assertEqual(data["positive_adjudicated_field_rate"], {"numerator": 0, "denominator": 0, "value": None})

    def test_supported_alternative_error_and_unresolved_denominators(self):
        self.assess("entry_role", "supported")
        self.assess("operation_role", "reasonable_alternative")
        self.assess("classification", "contradicted")
        self.assess("trace", "uncertain")
        metrics = quality.summarize(self.cohort, self.forms)
        semantic = metrics["quality_groups"]["semantic"]
        self.assertEqual(semantic["adjudicated_fields"], 3)
        self.assertEqual(semantic["positive_adjudicated_field_rate"], {"numerator": 2, "denominator": 3, "value": 2 / 3})
        self.assertEqual(semantic["unresolved_fields"], 57)
        self.assertEqual(metrics["quality_groups"]["fact"]["adjudicated_fields"], 0)
        self.assertEqual(metrics["cases_with_any_review"], 1)
        self.assertEqual(metrics["cases_all_fields_considered"], 0)
        self.assertFalse(metrics["reviewer_identity_and_independence_verified"])
        self.assertEqual(metrics["reviewer_independence_case_counts"], {"self": 1})

    def test_t1_uncertain_and_incorrect_do_not_prepopulate_quality_judgments(self):
        self.assertEqual(self.forms[0]["reviewer"], None)
        self.assertTrue(all(f["status"] == "not_reviewed" for r in self.forms for f in r["fields"].values()))
        self.assertEqual(quality.summarize(self.cohort, self.forms)["entry_verify_mutations"], 0)

    def test_assessed_field_requires_reviewer_identity(self):
        self.assess()
        self.forms[0]["reviewer"] = None
        with self.assertRaisesRegex(ValueError, "missing_reviewer"):
            quality.summarize(self.cohort, self.forms)

    def test_independence_is_declared_not_verified_and_nonhuman_not_human_review(self):
        self.assess()
        self.forms[0]["reviewer"]["independence"] = "independent_declared"
        with self.assertRaises(ValueError):
            quality.summarize(self.cohort, self.forms)
        self.forms[0]["reviewer"]["kind"] = "human"
        result = quality.summarize(self.cohort, self.forms)
        self.assertFalse(result["reviewer_identity_and_independence_verified"])
        self.assertEqual(result["reviewer_kind_case_counts"], {"human": 1})

    def test_cross_case_digest_task_or_missing_record_refused(self):
        for key, value in (("entry_sha256", "e" * 64), ("task_id", "other-task"), ("protocol_id", "old")):
            forms = deepcopy(self.forms)
            forms[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                quality.summarize(self.cohort, forms)
        with self.assertRaises(ValueError):
            quality.summarize(self.cohort, self.forms[:-1])
        with self.assertRaises(ValueError):
            quality.summarize(self.cohort, [self.forms[0]] * len(self.forms))

    def test_schema_free_extra_verify_or_missing_field_is_not_accepted(self):
        for mutate in (lambda r: r.update(verify=1), lambda r: r["fields"].pop("trace"),
                       lambda r: r["fields"].update(new_dimension={})):
            forms = deepcopy(self.forms)
            mutate(forms[0])
            with self.assertRaises(ValueError):
                quality.summarize(self.cohort, forms)

    def test_uncertain_requires_specific_rationale_and_next_action(self):
        self.assess(status="uncertain")
        for name in ("rationale", "next_action"):
            forms = deepcopy(self.forms)
            forms[0]["fields"]["entry_role"][name] = " "
            with self.subTest(name=name), self.assertRaises(ValueError):
                quality.summarize(self.cohort, forms)

    def test_decisive_assessment_needs_evidence_and_rationale(self):
        for status in ("supported", "reasonable_alternative", "contradicted"):
            self.assess(status=status)
            self.forms[0]["fields"]["entry_role"]["evidence_refs"] = []
            with self.subTest(status=status), self.assertRaises(ValueError):
                quality.summarize(self.cohort, self.forms)

    def test_unreviewed_cannot_contain_silent_decision(self):
        self.forms[0]["fields"]["entry_role"]["rationale"] = "actually checked"
        with self.assertRaises(ValueError):
            quality.summarize(self.cohort, self.forms)

    def test_text_ref_limits_duplicates_and_unknown_status_rejected(self):
        self.assess()
        for name, value in (("rationale", "x" * 1201), ("rationale", "bad\x00text"),
                            ("evidence_refs", ["duplicate", "duplicate"]), ("evidence_refs", [str(i) for i in range(9)]),
                            ("evidence_refs", "not a list"), ("status", "incorrect")):
            forms = deepcopy(self.forms)
            forms[0]["fields"]["entry_role"][name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                quality.summarize(self.cohort, forms)

    def test_protocol_rubric_change_requires_new_version_not_silent_regrade(self):
        self.cohort["rubric"]["entry_role"]["question"] = "always pass"
        with self.assertRaisesRegex(ValueError, "protocol"):
            quality.summarize(self.cohort, self.forms)

    def test_byte_manifest_covers_all_four_outputs(self):
        manifest = quality.parse(self.payloads["manifest.json"])
        self.assertEqual(set(manifest["files"]), set(self.payloads) - {"manifest.json"})
        for name, identity in manifest["files"].items():
            self.assertEqual(identity["sha256"], sha256(self.payloads[name]).hexdigest())
            self.assertEqual(identity["byte_count"], len(self.payloads[name]))

    def test_full_commit_machine_verify_and_no_network_required(self):
        for invalid in ("abc", "a" * 39, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                quality.prepare(self.bundle, system_commit=invalid)
        with patch("http.client.HTTPSConnection", side_effect=AssertionError("no network")) as network:
            quality.prepare(self.bundle, system_commit=SYSTEM_SHA)
        network.assert_not_called()
        self.bundle.entries[0]["verify"] = 1
        with self.assertRaises(ValueError):
            quality.prepare(self.bundle, system_commit=SYSTEM_SHA)

    def test_markdown_escapes_data_and_is_clearly_unsigned(self):
        self.cohort["cases"][0]["report_id"] = "<script>|`marker`"
        text = quality.render(self.cohort)
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;&#124;&#96;marker&#96;", text)
        self.assertIn("未完成实质评价", text)
        self.assertIn("不是语义判断", text)

    def test_duplicate_keys_and_nonfinite_json_are_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                quality.parse(raw)


class QualityReviewCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source, self.output = self.root / "source", self.root / "review"
        self.source.mkdir()
        reader = patch.object(quality, "read_submission_predictions", return_value=bundle_fixture())
        self.reader = reader.start()
        self.addCleanup(reader.stop)

    def call(self, *extra, output=None):
        args = ["prepare", "--submission-dir", str(self.source), "--output-dir", str(output or self.output),
                "--source-set-sha256", "c" * 64, "--submission-sha256", "d" * 64,
                "--task-count", "40", "--system-commit", SYSTEM_SHA, *extra]
        with redirect_stdout(io.StringIO()) as stdout:
            return quality.main(args), stdout.getvalue()

    def test_prepare_and_two_checks_preserve_bytes_and_forward_pins(self):
        self.assertEqual(self.call()[0], 0)
        self.reader.assert_called_once_with(self.source.resolve(), expected_source_replay_dataset_sha256="c" * 64,
                                          expected_submission_sha256="d" * 64, expected_task_count=40)
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        self.assertEqual(len(before), 5)
        self.assertEqual(self.call("--check")[0], 0)
        self.assertEqual(self.call("--check")[0], 0)
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()}, before)

    def test_existing_or_corrupt_output_not_overwritten(self):
        self.assertEqual(self.call()[0], 0)
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        self.assertEqual(self.call()[0], 2)
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()}, before)
        (self.output / "cohort.json").write_bytes(b"changed")
        self.assertEqual(self.call("--check")[0], 2)
        self.assertEqual((self.output / "cohort.json").read_bytes(), b"changed")

    def test_extra_file_or_overlap_refused_without_delete(self):
        self.assertEqual(self.call(output=self.source / "nested")[0], 2)
        self.reader.assert_not_called()
        self.assertEqual(self.call()[0], 0)
        extra = self.output / "keep.txt"
        extra.write_text("keep", encoding="utf-8")
        self.assertEqual(self.call("--check")[0], 2)
        self.assertEqual(extra.read_text(encoding="utf-8"), "keep")

    def test_summary_of_untouched_template_is_zero_reviews_not_zero_quality(self):
        self.assertEqual(self.call()[0], 0)
        cohort = self.output / "cohort.json"
        args = ["summarize", "--cohort", str(cohort), "--cohort-sha256", sha256(cohort.read_bytes()).hexdigest(),
                "--reviews", str(self.output / "review_template.jsonl")]
        with redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(quality.main(args), 0)
        metrics = json.loads(stdout.getvalue())
        self.assertEqual(metrics["cases_with_any_review"], 0)
        self.assertIsNone(metrics["quality_groups"]["semantic"]["positive_adjudicated_field_rate"]["value"])
        self.assertEqual(quality.encode(metrics), (self.output / "baseline_metrics.json").read_bytes())
        self.assertEqual(metrics["review_file_sha256"], sha256((self.output / "review_template.jsonl").read_bytes()).hexdigest())
        args[4] = "0" * 64
        with redirect_stdout(io.StringIO()):
            self.assertEqual(quality.main(args), 2)

    def test_altered_cohort_format_rejected_and_review_file_identity_preserved(self):
        self.assertEqual(self.call()[0], 0)
        cohort = self.output / "cohort.json"
        reviews = self.output / "review_template.jsonl"
        changed_review_bytes = reviews.read_bytes().replace(b'"protocol_id":', b'"protocol_id": ')
        reviews.write_bytes(changed_review_bytes)
        args = ["summarize", "--cohort", str(cohort), "--cohort-sha256", sha256(cohort.read_bytes()).hexdigest(),
                "--reviews", str(reviews)]
        with redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(quality.main(args), 0)
        metrics = json.loads(stdout.getvalue())
        self.assertEqual(metrics["review_file_sha256"], sha256(changed_review_bytes).hexdigest())
        self.assertNotEqual(metrics["canonical_reviews_sha256"], metrics["review_file_sha256"])
        cohort.write_bytes(cohort.read_bytes() + b" ")
        args[4] = sha256(cohort.read_bytes()).hexdigest()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(quality.main(args), 2)

    def test_source_digest_failure_creates_no_output(self):
        self.reader.side_effect = ValueError("wrong source digest")
        self.assertEqual(self.call()[0], 2)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
