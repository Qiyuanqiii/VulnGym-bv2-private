"""Read-only mixed-batch projections; no model or live repository calls."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import test_orchestrator as fixture
from tests.producer_context_support import FixedProducerContextFactory
from vulngym_agent.orchestrator import (
    ClosedLoopOrchestrator, ProductionDeferredDraft, ReplayRecord,
    InputFailureRecord, Limits, canonical_sha256, write_closed_loop_artifacts,
)
from vulngym_agent import submission_prediction as module
from vulngym_agent.submission_prediction_cli import main


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.ClosedLoopOrchestratorTests()
        self.f.setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def task_outcome(self, status):
        return self.f._run(fixture._FakeProducer(self.f.entry), [
            fixture._report(self.f.entry, {"trace": status}, label=status)],
            limits=Limits(max_repair_iterations=0))[0]

    def deferred_outcome(self, task):
        class Producer:
            def generate(self, task, context):
                return ProductionDeferredDraft(stage="reflection", reason_code="model_deferred",
                    missing_information=("reflection declined to emit the candidate",))
        def no_validator(task):
            raise AssertionError("T1 must not run on defer")
        return ClosedLoopOrchestrator(Producer(), no_validator, FixedProducerContextFactory()).run(task)

    def source(self, status="uncertain", *, defer_only=False, failure=False):
        second = replace(self.f.task, task_id="task-002", entry_id="entry-90002",
                         inputs={**self.f.task.inputs, "input_line": 8})
        records = [] if defer_only else [ReplayRecord(7, self.f.task, self.task_outcome(status))]
        records.append(ReplayRecord(8, second, self.deferred_outcome(second)))
        if failure:
            records.append(InputFailureRecord(input_line=9, error_code="invalid_input", raw_sha256="a" * 64))
        directory = self.root / "source"
        manifest = write_closed_loop_artifacts(directory, records)
        return directory, manifest.dataset_sha256, len(records)

    def build(self, source, digest, count):
        return module.build_submission_handoff(source, expected_source_replay_dataset_sha256=digest, expected_task_count=count)

    def test_mixed_task_bindings_and_complete_records_preserved(self):
        source, digest, count = self.source()
        before = {p.name: p.read_bytes() for p in source.iterdir()}
        result = self.build(source, digest, count)
        self.assertEqual(encoded(result), encoded(self.build(source, digest, count)))
        self.assertEqual(before, {p.name: p.read_bytes() for p in source.iterdir()})
        self.assertEqual(result["kind"], "vulngym.mixed-batch-handoff.v1")
        self.assertEqual((result["task_count"], result["complete_count"], result["incomplete_count"]), (2, 1, 1))
        self.assertEqual(result["entries"], [self.f.entry])
        self.assertEqual(result["entries"][0]["verify"], 0)
        self.assertEqual(result["validation"][0]["verdict"], "uncertain")
        self.assertEqual([t["input_line"] for t in result["tasks"]], [7, 8])
        self.assertEqual([t["pair_ordinal"] for t in result["tasks"]], [1, None])
        self.assertEqual(result["tasks"][1]["deferred"][0]["missing_information"], ["reflection declined to emit the candidate"])
        self.assertEqual(result["tasks"][0]["candidate_sha256"], canonical_sha256(result["entries"][0]))
        self.assertEqual(result["status_counts"], {"manual_review": 2})
        self.assertFalse(result["formal_submission_export"])
        self.assertFalse(result["independent_quality_review_completed"])
        self.assertNotIn("model_response", encoded(result).decode())
        self.assertNotIn("task_inputs", result)
        core = dict(result)
        digest_value = core.pop("handoff_sha256")
        self.assertEqual(digest_value, canonical_sha256(core))

    def test_all_deferred_batch_keeps_tasks_without_fake_entries(self):
        source, digest, count = self.source(defer_only=True)
        result = self.build(source, digest, count)
        self.assertEqual(result["entries"], [])
        self.assertEqual(result["validation"], [])
        self.assertEqual(result["complete_count"], 0)
        self.assertEqual(result["incomplete_count"], 1)

    def test_incorrect_verdict_not_filtered_or_upgraded(self):
        source, digest, count = self.source(status="incorrect")
        result = self.build(source, digest, count)
        self.assertEqual(result["validation"][0]["verdict"], "incorrect")
        self.assertEqual(result["verdict_counts"], {"incorrect": 1})
        self.assertEqual(result["tasks"][0]["status"], "manual_review")

    def test_finalized_candidate_keeps_correct_without_implying_whole_batch_finalized(self):
        source, digest, count = self.source(status="correct")
        result = self.build(source, digest, count)
        self.assertEqual(result["status_counts"], {"finalized": 1, "manual_review": 1})
        self.assertFalse(result["formal_submission_export"])

    def test_wrong_digest_count_and_input_failures_rejected(self):
        source, digest, count = self.source(failure=True)
        for d, n in (("a" * 64, count), (digest, count)):
            with self.subTest(d=d), self.assertRaises(module.SubmissionPredictionError):
                self.build(source, d, n)

    def test_count_mismatch_rejected(self):
        source, digest, count = self.source()
        with self.assertRaises(module.SubmissionPredictionError):
            self.build(source, digest, count + 1)

    def test_sidecar_reread_must_match_verified_file_digest(self):
        source, digest, count = self.source()
        with patch.object(module, "_read_replay_sidecar", return_value=b"changed"), self.assertRaises(module.SubmissionPredictionError):
            self.build(source, digest, count)

    def test_formal_export_still_rejects_this_mixed_batch(self):
        source, digest, count = self.source()
        with self.assertRaises(module.SubmissionPredictionError) as raised:
            module.write_submission_predictions(self.root / "must-not-publish", source,
                expected_source_replay_dataset_sha256=digest, expected_task_count=count)
        self.assertEqual(raised.exception.code, "incomplete_predictions")
        self.assertFalse((self.root / "must-not-publish").exists())

    def test_file_verification_is_byte_exact_and_checks_external_digests(self):
        source, digest, count = self.source()
        result = self.build(source, digest, count)
        output = self.root / "handoff.json"
        output.write_bytes(encoded(result))
        def verify(h=result["handoff_sha256"]):
            return module.verify_submission_handoff(output, source,
                expected_handoff_sha256=h, expected_source_replay_dataset_sha256=digest, expected_task_count=count)
        self.assertTrue(verify()["verified"])
        with self.assertRaises(module.SubmissionPredictionError):
            verify("b" * 64)
        modified = deepcopy(result)
        modified["entries"][0]["vuln_title"] = "Changed after generation"
        modified["handoff_sha256"] = canonical_sha256({k: v for k, v in modified.items() if k != "handoff_sha256"})
        output.write_bytes(encoded(modified))
        with self.assertRaises(module.SubmissionPredictionError):
            verify(modified["handoff_sha256"])  # self-rehash is not authority
        output.write_bytes(b"\xef\xbb\xbf" + encoded(result))
        with self.assertRaises(module.SubmissionPredictionError):
            verify()

    def test_cli_roundtrip_and_failure_emit_no_partial_payload(self):
        source, digest, count = self.source()
        common = ["--replay-dir", str(source), "--replay-dataset-sha256", digest,
                  "--expected-task-count", str(count)]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["handoff", *common])
        self.assertEqual(code, 0)
        result = json.loads(out.getvalue())
        output = self.root / "cli-handoff.json"
        output.write_bytes(out.getvalue().encode())
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["verify-handoff", *common, "--handoff-file", str(output),
                         "--handoff-sha256", result["handoff_sha256"]])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out.getvalue())["verified"])
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["handoff", "--replay-dir", str(source), "--replay-dataset-sha256", "c" * 64,
                         "--expected-task-count", str(count)])
        self.assertEqual(code, 2)
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
