"""Synthetic transport tests only; never call a provider or load a real key."""
from copy import deepcopy
import json
import unittest

from scripts.run_t2_new_input_batch_v1 import BoundedTransport, TASKS, adapter
from vulngym_agent.agents.model_runtime import ModelBlocked


def request(task=TASKS[0], call="MODEL-1", stage="plan"):
    return {"model": adapter.MODEL_ID, "max_tokens": 8192, "stream": False,
            "messages": [{"content": "synthetic"}, {"content": json.dumps({
                "task_id": task, "model_call_id": call, "stage": stage})}]}


class BoundedTransportTests(unittest.TestCase):
    def setUp(self):
        self.calls, self.events = [], []
        def send(body, key, timeout):
            self.calls.append((body, timeout))
            return json.dumps({"model": adapter.MODEL_ID, "usage": {"prompt_tokens": 10,
                "completion_tokens": 2, "total_tokens": 12, "ignored": "private-content"},
                "choices": [{"message": {"content": "not-logged", "reasoning_content": "not-logged"}}]}).encode()
        self.guard = BoundedTransport(send, self.events.append)

    def invoke(self, value=None, guard=None):
        return (guard or self.guard)(json.dumps(value or request()).encode(), "synthetic-key", 120)

    def test_six_requests_two_tasks_and_minimal_telemetry(self):
        for task in TASKS:
            for number in range(3):
                self.invoke(request(task, f"MODEL-{number}"))
        self.assertEqual(len(self.calls), 6)
        self.assertEqual(len(self.events), 12)
        self.assertNotIn("synthetic-key", repr(self.events))
        self.assertNotIn("private-content", repr(self.events))
        self.assertNotIn("not-logged", repr(self.events))
        with self.assertRaisesRegex(ModelBlocked, "budget_exceeded"):
            self.invoke(request(TASKS[1], "MODEL-4"))
        self.assertEqual(len(self.calls), 6)

    def test_per_task_cap_is_three(self):
        for number in range(3):
            self.invoke(request(call=f"MODEL-{number}"))
        with self.assertRaisesRegex(ModelBlocked, "budget_exceeded"):
            self.invoke(request(call="MODEL-4"))
        self.assertEqual(len(self.calls), 3)

    def test_duplicate_call_not_retried(self):
        self.invoke()
        with self.assertRaisesRegex(ModelBlocked, "duplicate_request"):
            self.invoke()
        self.assertEqual(len(self.calls), 1)

    def test_contract_rejects_other_tasks_repair_model_tokens_and_stream(self):
        values = [request("other"), request(stage="repair")]
        for key, value in [("model", "other"), ("max_tokens", 8193), ("max_tokens", True), ("stream", True)]:
            changed = deepcopy(request())
            changed[key] = value
            values.append(changed)
        for value in values:
            with self.subTest(value=value), self.assertRaisesRegex(ModelBlocked, "contract_invalid"):
                self.invoke(value)
        self.assertEqual(self.calls, [])

    def test_malformed_json_and_oversized_timeout_never_send(self):
        with self.assertRaisesRegex(ModelBlocked, "contract_invalid"):
            self.guard(b"not json", "synthetic-key", 120)
        with self.assertRaisesRegex(ModelBlocked, "contract_invalid"):
            self.guard(json.dumps(request()).encode(), "synthetic-key", 121)
        self.assertEqual(self.calls, [])

    def test_started_event_precedes_paid_request(self):
        order = []
        guard = BoundedTransport(lambda *a: order.append("send") or b"{}", lambda row: order.append(row["event"]))
        self.invoke(guard=guard)
        self.assertEqual(order, ["started", "send", "finished"])

    def test_failed_initial_persistence_prevents_send_and_latches(self):
        def fail(row):
            raise OSError("synthetic-full-disk")
        guard = BoundedTransport(self.guard.send, fail)
        for _ in range(2):
            with self.assertRaisesRegex(ModelBlocked, "telemetry_failed"):
                self.invoke(guard=guard)
        self.assertEqual(self.calls, [])

    def test_auth_and_timeout_failures_stop_later_requests(self):
        for code in ["deepseek_authentication_failed", "deepseek_access_denied", "deepseek_balance_insufficient", "deepseek_rate_limited", "deepseek_timeout"]:
            count = []
            def fail(*args):
                count.append(1)
                raise ModelBlocked(code)
            guard = BoundedTransport(fail, lambda row: None)
            for _ in range(2):
                with self.assertRaisesRegex(ModelBlocked, code):
                    self.invoke(guard=guard)
            self.assertEqual(len(count), 1)

    def test_unknown_exception_text_is_not_logged(self):
        def fail(*args):
            raise OSError("synthetic-secret-not-for-log")
        guard = BoundedTransport(fail, self.events.append)
        with self.assertRaisesRegex(ModelBlocked, "transport_failed"):
            self.invoke(guard=guard)
        self.assertNotIn("synthetic-secret", repr(self.events))

    def test_final_persistence_failure_stops_later_requests(self):
        def record(row):
            if row["event"] == "finished":
                raise OSError("synthetic-disk-full")
        guard = BoundedTransport(self.guard.send, record)
        for _ in range(2):
            with self.assertRaisesRegex(ModelBlocked, "telemetry_failed"):
                self.invoke(guard=guard)
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
