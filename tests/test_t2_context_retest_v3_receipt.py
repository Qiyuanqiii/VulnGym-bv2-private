"""Synthetic receipt invariants; no model calls, production runs or real inputs."""
from copy import deepcopy
import unittest

from scripts.collect_t2_context_retest_v3 import TASKS, CANDIDATE_SHA, transport_counts, reconcile


class ContextReceiptTests(unittest.TestCase):
    def setUp(self):
        self.events, self.calls = [], []
        for n, (task, stage) in enumerate([(TASKS[0], "plan"), (TASKS[0], "semantic_judge"),
                (TASKS[1], "plan"), (TASKS[1], "semantic_judge"), (TASKS[1], "reflection")], 1):
            base = dict(attempt=n, task_id=task, stage=stage, request_body_sha256=str(n) * 64, timeout_seconds=300)
            completion = 8192 if n == 2 else 2
            self.events += [dict(base, event="started"), dict(base, event="finished", status="http_200",
                elapsed_seconds=1.0, usage=dict(prompt_tokens=10, completion_tokens=completion,
                    total_tokens=10 + completion, prompt_cache_hit_tokens=4, prompt_cache_miss_tokens=6))]
            self.calls.append(dict(task_id=task, stage=stage, status="blocked" if n == 2 else "success",
                error_code="deepseek_output_truncated" if n == 2 else None))
        self.ended = dict(transport_attempts=5, transport_halt_code=None, exit_code=1,
                          credential_use_ended=True, error_code=None)
        self.cli = dict(exit_code=1, status="incomplete", execution_status="model_execution_incomplete",
            tasks_run=2, manual_review=2, failed=0, input_failures=0, entries_written=0, finalized=0,
            model_error_counts={"deepseek_output_truncated": 1}, execution_counts=dict(
                complete_candidate_tasks=1, t1_report_tasks=1, deferred_tasks=1,
                model_declared_defer_tasks=0, model_problem_tasks=1, non_success_model_calls=1))
        self.candidates = [dict(task_id=TASKS[1], payload=dict(candidate_sha256=CANDIDATE_SHA, candidate={"verify": 0}))]
        self.deferred = [dict(task_id=TASKS[0], payload=dict(deferred_sha256="a" * 64,
            deferred=dict(stage="semantic_judge", reason_code="model_blocked")))]
        self.validations = [dict(task_id=TASKS[1], payload=dict(report_sha256="b" * 64,
            report=dict(verdict="uncertain", fields={str(i): {"status": "correct" if i < 9 else "uncertain"} for i in range(16)})))]

    def count(self):
        return transport_counts(self.events, self.calls, self.ended)

    def result(self):
        return reconcile(self.cli, self.ended, self.count(), self.candidates, self.deferred, self.validations)

    def test_truncation_usage_is_counted_not_a_transport_failure(self):
        counts = self.count()
        self.assertEqual(counts["actual_http_requests"], 5)
        self.assertEqual(counts["http_successes"], 5)
        self.assertEqual(counts["structured_results_accepted"], 4)
        self.assertEqual(counts["structured_results_rejected_after_http"], 1)
        self.assertEqual(counts["provider_reported_usage"]["completion_tokens"], 8200)
        self.assertEqual(counts["locally_blocked_before_http"], 0)

    def test_partial_candidate_is_not_abstention_or_finalized(self):
        result = self.result()
        self.assertFalse(result[0]["semantic_abstention"])
        self.assertTrue(result[1]["complete_candidate"])
        self.assertEqual(result[1]["verify"], 0)
        self.assertEqual(result[1]["t1_verdict"], "uncertain")

    def test_incomplete_usage_is_rejected_not_zero_filled(self):
        for usage in ({}, {**self.events[1]["usage"], "total_tokens": 1},
                      {**self.events[1]["usage"], "prompt_tokens": True}):
            events = deepcopy(self.events)
            events[1]["usage"] = usage
            with self.assertRaises(AssertionError):
                transport_counts(events, self.calls, self.ended)

    def test_timeout_cannot_use_http_success_receipt(self):
        self.ended["transport_halt_code"] = "deepseek_timeout"
        with self.assertRaises(AssertionError):
            self.count()

    def test_missing_completion_rejected(self):
        self.events.pop()
        with self.assertRaises(AssertionError):
            self.count()

    def test_request_order_and_identity_must_match(self):
        self.calls.reverse()
        with self.assertRaises(AssertionError):
            self.count()

    def test_unknown_model_problem_rejected(self):
        self.calls[1]["error_code"] = "unknown"
        with self.assertRaises(AssertionError):
            self.count()

    def test_truncation_evidence_must_match_budget(self):
        self.events[3]["usage"].update(completion_tokens=1, total_tokens=11)
        with self.assertRaises(AssertionError):
            self.count()

    def test_production_exit_cannot_be_relabelled_zero(self):
        self.ended["exit_code"] = self.cli["exit_code"] = 0
        with self.assertRaises(AssertionError):
            self.result()

    def test_candidate_binding_cannot_be_swapped(self):
        self.candidates[0]["payload"]["candidate_sha256"] = "c" * 64
        with self.assertRaises(AssertionError):
            self.result()

    def test_verify_must_remain_machine_zero(self):
        self.candidates[0]["payload"]["candidate"]["verify"] = 1
        with self.assertRaises(AssertionError):
            self.result()

    def test_t1_uncertainty_cannot_be_promoted(self):
        self.validations[0]["payload"]["report"]["verdict"] = "correct"
        with self.assertRaises(AssertionError):
            self.result()

    def test_truncation_cannot_be_relabelled_model_defer(self):
        self.deferred[0]["payload"]["deferred"]["reason_code"] = "model_deferred"
        with self.assertRaises(AssertionError):
            self.result()


if __name__ == "__main__":
    unittest.main()
