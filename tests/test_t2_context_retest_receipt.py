"""No-network checks of diagnostic accounting, not real semantic results."""
from copy import deepcopy
import unittest

from scripts.collect_t2_context_retest_v1 import TASKS, transport_counts


class RetestReceiptTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        for n, stage in ((1, "plan"), (2, "semantic_judge")):
            base = dict(attempt=n, task_id=TASKS[0], stage=stage, request_body_sha256=str(n) * 64)
            self.events.append(dict(base, event="started"))
            self.events.append(dict(base, event="finished", status="http_200" if n == 1 else "blocked",
                reported_model_matches=True, usage={"total_tokens": 10} if n == 1 else {}, error_code="deepseek_timeout"))
        self.calls = [dict(task_id=TASKS[0], stage="plan", status="success", error_code=None),
            dict(task_id=TASKS[0], stage="semantic_judge", status="blocked", error_code="deepseek_timeout"),
            dict(task_id=TASKS[1], stage="plan", status="blocked", error_code="deepseek_timeout")]
        self.ended = dict(transport_attempts=2, transport_halt_code="deepseek_timeout")

    def test_timeout_is_not_second_task_http_or_complete_usage(self):
        value = transport_counts(self.events, self.calls, self.ended)
        self.assertEqual(value["actual_http_requests"], 2)
        self.assertEqual(value["model_invocations"], 3)
        self.assertEqual(value["locally_blocked_invocations_not_http_requests"], 1)
        self.assertEqual(value["known_provider_usage"]["total_tokens"], 10)
        self.assertFalse(value["usage_is_complete"])
        self.assertEqual(value["timed_out_request_usage_and_billing"], "unknown")

    def test_unsent_success_rejected(self):
        self.calls[-1]["status"] = "success"
        with self.assertRaises(AssertionError):
            transport_counts(self.events, self.calls, self.ended)

    def test_incomplete_telemetry_rejected(self):
        with self.assertRaises(AssertionError):
            transport_counts(self.events[:-1], self.calls, self.ended)

    def test_duplicate_stage_rejected(self):
        self.calls.append(deepcopy(self.calls[0]))
        with self.assertRaises(AssertionError):
            transport_counts(self.events, self.calls, self.ended)

    def test_changed_error_code_rejected(self):
        self.calls[1]["error_code"] = "different"
        with self.assertRaises(AssertionError):
            transport_counts(self.events, self.calls, self.ended)

    def test_request_after_terminal_failure_rejected(self):
        base = dict(attempt=3, task_id=TASKS[1], stage="plan", request_body_sha256="3" * 64)
        self.events.extend([dict(base, event="started"), dict(base, event="finished", status="http_200")])
        self.ended["transport_attempts"] = 3
        with self.assertRaises(AssertionError):
            transport_counts(self.events, self.calls, self.ended)


if __name__ == "__main__":
    unittest.main()
