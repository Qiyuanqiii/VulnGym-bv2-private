"""Synthetic receipt checks only; no provider requests or target execution."""
from copy import deepcopy
import json
import unittest

from scripts import collect_t2_stage_budget_retest_v1 as receipt


class StageBudgetReceiptTests(unittest.TestCase):
    def setUp(self):
        self.events, self.calls = [], []
        for n, (task, stage) in enumerate([(t, s) for t in receipt.TASKS for s in receipt.STAGES], 1):
            base = dict(attempt=n, task_id=task, stage=stage, model_call_id=f"MODEL-{n}",
                request_body_sha256=str(n) * 64, request_bytes=100, timeout_seconds=300,
                configured_max_tokens=receipt.STAGE_LIMITS[stage])
            self.events.extend([dict(base, event="started"), dict(base, event="finished",
                status="http_200", response_model_matches=True, finish_reason="stop", elapsed_seconds=1.0,
                answer_characters=10, provider_reasoning_characters=30, response_bytes=100,
                usage=dict(prompt_tokens=10, completion_tokens=2, total_tokens=12,
                           prompt_cache_hit_tokens=4, prompt_cache_miss_tokens=6))])
            self.calls.append(dict(task_id=task, stage=stage, model_call_id=f"MODEL-{n}",
                                   status="success", error_code=None))
        self.ended = dict(transport_attempts=6, transport_halt_code=None, exit_code=0,
            configured_completion_tokens_attempted=45056, credential_use_ended=True, error_code=None)
        self.cli = dict(exit_code=0, status="ok", execution_status="processed_not_quality_verified",
            tasks_run=2, manual_review=2, failed=0, input_failures=0, entries_written=0, finalized=0,
            model_error_counts={}, execution_counts=dict(complete_candidate_tasks=1, t1_report_tasks=1,
                deferred_tasks=1, model_declared_defer_tasks=1, model_problem_tasks=0, non_success_model_calls=0))
        self.candidates = [dict(task_id=receipt.TASKS[1], payload=dict(
            candidate_sha256=receipt.CANDIDATE_SHA, candidate={"verify": 0}))]
        details = dict(kind="model_reflection_defer_v1", reason_code="ambiguous_candidate_roles",
            assessment_origin="model_self_report_not_independently_verified",
            missing_fields=["critical_operation", "relationship"], evidence_refs=["A", "B", "C"],
            explanation="Synthetic candidate role lacks supporting evidence.")
        self.deferred = [dict(task_id=receipt.TASKS[0], payload=dict(deferred_sha256=receipt.DEFERRED_SHA,
            deferred=dict(stage="reflection", reason_code="model_deferred",
                          missing_information=["model_defer_details:" + json.dumps(details)])))]
        self.validations = [dict(task_id=receipt.TASKS[1], payload=dict(report_sha256=receipt.VALIDATION_SHA,
            report=dict(verdict="uncertain", fields={str(i): {"status": "correct" if i < 9 else "uncertain"}
                                                     for i in range(16)})))]

    def count(self):
        return receipt.transport_counts(self.events, self.calls, self.ended)

    def result(self):
        return receipt.reconcile(self.cli, self.ended, self.count(), self.candidates, self.deferred, self.validations)

    def test_six_complete_responses_are_distinct_from_candidate_count(self):
        counts = self.count()
        self.assertEqual(counts["actual_http_requests"], 6)
        self.assertEqual(counts["structured_results_accepted"], 6)
        self.assertEqual(counts["provider_reported_usage"]["total_tokens"], 72)
        self.assertEqual(counts["configured_completion_tokens_attempted"], 45056)
        results = self.result()
        self.assertTrue(results[0]["semantic_abstention"])
        self.assertFalse(results[0]["complete_candidate"])
        self.assertTrue(results[1]["complete_candidate"])
        self.assertEqual(results[1]["workflow_status"], "manual_review")

    def test_wrong_stage_budget_rejected_even_when_both_log_rows_agree(self):
        for row in self.events[:2]:
            row["configured_max_tokens"] = 8192
        with self.assertRaises(AssertionError):
            self.count()

    def test_changed_configured_total_rejected(self):
        self.ended["configured_completion_tokens_attempted"] = 49152
        with self.assertRaises(AssertionError):
            self.count()

    def test_stage_order_cannot_be_relabelled(self):
        for row in self.events[2:4]:
            row["stage"] = "plan"
        with self.assertRaises(AssertionError):
            self.count()

    def test_model_identity_must_match_sent_identity(self):
        self.calls[1]["model_call_id"] = "MODEL-other"
        with self.assertRaises(AssertionError):
            self.count()

    def test_missing_http_completion_rejected(self):
        self.events.pop()
        with self.assertRaises(AssertionError):
            self.count()

    def test_truncated_response_cannot_enter_success_receipt(self):
        self.events[3]["finish_reason"] = "length"
        with self.assertRaises(AssertionError):
            self.count()

    def test_unknown_or_inconsistent_usage_is_not_zero_filled(self):
        for usage in ({}, {**self.events[1]["usage"], "total_tokens": 1},
                      {**self.events[1]["usage"], "prompt_tokens": True}):
            events = deepcopy(self.events)
            events[1]["usage"] = usage
            with self.assertRaises(AssertionError):
                receipt.transport_counts(events, self.calls, self.ended)

    def test_permission_or_transport_failure_rejected(self):
        self.ended["transport_halt_code"] = "deepseek_access_denied"
        with self.assertRaises(AssertionError):
            self.count()

    def test_provider_model_mismatch_rejected(self):
        self.events[1]["response_model_matches"] = False
        with self.assertRaises(AssertionError):
            self.count()

    def test_structured_model_error_cannot_be_accepted(self):
        self.calls[1].update(status="blocked", error_code="deepseek_output_truncated")
        with self.assertRaises(AssertionError):
            self.count()

    def test_exit_boolean_or_changed_exit_is_rejected(self):
        for value in (False, 1, 2):
            self.cli["exit_code"] = self.ended["exit_code"] = value
            with self.assertRaises(AssertionError):
                self.result()

    def test_defer_is_not_relabelled_truncation(self):
        self.deferred[0]["payload"]["deferred"]["reason_code"] = "model_blocked"
        with self.assertRaises(AssertionError):
            self.result()

    def test_defer_self_report_cannot_be_called_independent_review(self):
        value = self.deferred[0]["payload"]["deferred"]
        details = json.loads(value["missing_information"][0].removeprefix("model_defer_details:"))
        details["assessment_origin"] = "independent_human_review"
        value["missing_information"] = ["model_defer_details:" + json.dumps(details)]
        with self.assertRaises(AssertionError):
            self.result()

    def test_t1_uncertainty_is_not_upgraded(self):
        self.validations[0]["payload"]["report"]["verdict"] = "correct"
        with self.assertRaises(AssertionError):
            self.result()

    def test_all_three_artifact_bindings_are_checked(self):
        for data, key in ((self.candidates, "candidate_sha256"),
                          (self.validations, "report_sha256"), (self.deferred, "deferred_sha256")):
            previous = data[0]["payload"][key]
            data[0]["payload"][key] = "f" * 64
            with self.assertRaises(AssertionError):
                self.result()
            data[0]["payload"][key] = previous

    def test_verify_boolean_and_verified_flag_rejected(self):
        for value in (False, 1):
            self.candidates[0]["payload"]["candidate"]["verify"] = value
            with self.assertRaises(AssertionError):
                self.result()

    def test_finalized_count_cannot_be_promoted(self):
        self.cli["finalized"] = 1
        with self.assertRaises(AssertionError):
            self.result()


if __name__ == "__main__":
    unittest.main()
