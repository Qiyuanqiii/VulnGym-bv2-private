"""No credentials or HTTP: stage-budget runner scope and transport contracts."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_t2_stage_budget_retest_v1 as runner
from vulngym_agent.agents.model_runtime import ModelBlocked


class StageBudgetRetestPlanTests(unittest.TestCase):
    def test_separate_guard_and_paths_preserve_historical_runs(self):
        self.assertNotEqual(runner.RUN, runner.previous.RUN)
        self.assertNotEqual(runner.BASE, runner.previous.RUN)
        self.assertEqual(runner.SETTINGS.token_budget_profile, "t2-balanced-v1")
        self.assertEqual(runner.STAGE_LIMITS, {"plan": 2048, "semantic_judge": 16384, "reflection": 4096})
        self.assertEqual(runner.SETTINGS.timeout_seconds, 300)
        self.assertEqual(runner.adapter.DeepSeekSettings().timeout_seconds, 120)
        self.assertEqual(runner.TASKS, runner.previous.TASKS)
        self.assertEqual(runner.adapter.PROMPT_VERSION, "t2-json-v5")

    def test_check_has_no_credential_read_or_run(self):
        with patch.object(runner, "preflight", return_value={"provider_calls": 0}) as check, \
                patch.object(runner.getpass, "getpass") as key, patch.object(runner, "run") as run, \
                patch.object(runner, "emit"):
            self.assertEqual(runner.main(["check"]), 0)
        check.assert_called_once_with()
        key.assert_not_called()
        run.assert_not_called()

    def test_run_needs_both_current_confirmations_and_digest(self):
        variants = [[], ["--confirm-paid-retest"], ["--confirm-platform-cap"],
                    ["--confirm-paid-retest", "--confirm-platform-cap"]]
        with patch.object(runner, "run") as run, patch.object(runner.getpass, "getpass") as key, \
                patch.object(runner, "emit"):
            for flags in variants:
                self.assertEqual(runner.main(["run", *flags]), 2)
        run.assert_not_called()
        key.assert_not_called()

    def test_confirmed_run_preserves_digest_and_exit_status(self):
        with patch.object(runner, "run", return_value=1) as run:
            self.assertEqual(runner.main(["run", "--confirm-paid-retest", "--confirm-platform-cap",
                                        "--expected-manifest-sha256", "a" * 64]), 1)
        run.assert_called_once_with("a" * 64)

    def test_manifest_mismatch_precedes_intent_and_key_read(self):
        with patch.object(runner, "read_bytes", return_value=b"{}"), \
                patch.object(runner.getpass, "getpass") as key, patch.object(runner, "put_new") as write:
            with self.assertRaisesRegex(ValueError, "digest_mismatch"):
                runner.run("a" * 64)
        key.assert_not_called()
        write.assert_not_called()

    def test_existing_preparation_is_preserved_without_reading(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(runner, "RUN", Path(temp)), \
                patch.object(runner, "build_plan") as build:
            with self.assertRaisesRegex(ValueError, "existing_preparation"):
                runner.prepare()
        build.assert_not_called()

    def test_old_baseline_hash_change_is_rejected(self):
        with patch.object(runner, "read_bytes", return_value=b"{}"):
            with self.assertRaisesRegex(ValueError, "baseline_manifest_changed"):
                runner.build_plan()

    def test_any_frozen_plan_change_is_rejected_before_git(self):
        base = dict(budget_cny=20, max_total_http_requests=6, model={"timeout_seconds": 300})
        for mutation in ({"budget_cny": 21}, {"max_total_http_requests": 7},
                         {"model": {"timeout_seconds": 120}}, {"extra": "unexpected"}):
            changed = {**deepcopy(base), **mutation}
            with self.subTest(mutation=mutation), patch.object(runner, "read_bytes", return_value=runner.wire(changed)), \
                    patch.object(runner, "build_plan", return_value=base), patch.object(runner, "git") as git:
                with self.assertRaisesRegex(ValueError, "profile_changed"):
                    runner.preflight()
            git.assert_not_called()

    def test_duplicate_run_stops_before_input_reads_and_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "run-start.json").write_bytes(b"existing")
            plan = {"synthetic": "plan"}
            def git(*args):
                if args[:2] == ("branch", "--show-current"):
                    return b"codex/b-v2-source-discovery\n"
                if args[:2] == ("rev-parse", "HEAD:vulngym_agent"):
                    return runner.RUNTIME_TREE.encode()
                return runner.wire(plan)
            with patch.object(runner, "RUN", root), patch.object(runner, "read_bytes", return_value=runner.wire(plan)), \
                    patch.object(runner, "build_plan", return_value=plan), patch.object(runner, "git", side_effect=git), \
                    patch.object(runner.previous, "checked_input") as inputs, patch.object(runner.getpass, "getpass") as key:
                with self.assertRaisesRegex(ValueError, "existing_run"):
                    runner.preflight(for_run=True)
            inputs.assert_not_called()
            key.assert_not_called()

    def test_backend_factory_never_initializes_or_loads_credentials(self):
        with patch.object(runner, "_backend", None), patch.object(runner.getpass, "getpass") as key:
            with self.assertRaisesRegex(RuntimeError, "not_initialized"):
                runner.backend_factory()
        key.assert_not_called()


def request(task=None, stage="plan", call=None):
    return {"model": runner.adapter.MODEL_ID, "max_tokens": runner.STAGE_LIMITS.get(stage, 4096),
        "stream": False, "reasoning_effort": "high",
        "messages": [{"role": "system", "content": "synthetic"},
            {"role": "user", "content": json.dumps({"task_id": task or runner.TASKS[0],
                "stage": stage, "model_call_id": call or "MODEL-" + stage})}]}


class StageBudgetRetestTransportTests(unittest.TestCase):
    def setUp(self):
        self.calls, self.events = [], []
        self.response = runner.wire({"model": runner.adapter.MODEL_ID, "usage": {
            "prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12,
            "prompt_cache_hit_tokens": 0, "prompt_cache_miss_tokens": 10,
            "raw_field": "do-not-log"}, "choices": [{"finish_reason": "stop",
                "message": {"content": "answer-must-not-log", "reasoning_content": "reasoning-must-not-log"}}]})
        def send(body, key, timeout):
            self.calls.append((body, timeout))
            return self.response
        self.guard = runner.StageBudgetTransport(send, self.events.append)

    def invoke(self, value=None, *, guard=None, timeout=300):
        return (guard or self.guard)(runner.wire(request() if value is None else value), "synthetic-key", timeout)

    def test_six_ordered_unique_stages_use_real_caps_and_body_digests(self):
        for task in runner.TASKS:
            for stage in runner.STAGES:
                self.invoke(request(task, stage))
        self.assertEqual(len(self.calls), 6)
        self.assertEqual(self.guard.configured_completion_tokens, 45056)
        self.assertEqual([row["configured_max_tokens"] for row in self.events[::2]], [2048, 16384, 4096] * 2)
        for (body, timeout), event in zip(self.calls, self.events[::2], strict=True):
            self.assertEqual(event["request_body_sha256"], sha256(body).hexdigest())
            self.assertEqual(event["configured_max_tokens"], json.loads(body)["max_tokens"])
            self.assertEqual(timeout, 300)
        with self.assertRaisesRegex(ModelBlocked, "budget_exceeded"):
            self.invoke(request(runner.TASKS[1], "reflection", "MODEL-extra"))
        self.assertEqual(len(self.calls), 6)

    def test_missing_predecessor_and_duplicate_stage_never_send(self):
        for stage in ("semantic_judge", "reflection"):
            with self.assertRaisesRegex(ModelBlocked, "stage_sequence_invalid"):
                self.invoke(request(stage=stage))
        self.invoke()
        with self.assertRaisesRegex(ModelBlocked, "stage_sequence_invalid"):
            self.invoke(request(call="MODEL-other-plan"))
        self.assertEqual(len(self.calls), 1)

    def test_duplicate_model_identity_never_resent(self):
        self.invoke()
        with self.assertRaisesRegex(ModelBlocked, "duplicate_request_rejected"):
            self.invoke(request(stage="semantic_judge", call="MODEL-plan"))
        self.assertEqual(len(self.calls), 1)

    def test_per_task_cap_cannot_borrow_from_other_task(self):
        for stage in runner.STAGES:
            self.invoke(request(stage=stage))
        with self.assertRaisesRegex(ModelBlocked, "budget_exceeded"):
            self.invoke(request(call="MODEL-extra"))
        self.assertEqual(len(self.calls), 3)

    def test_cap_model_reasoning_repair_and_other_tasks_rejected(self):
        values = [request(task="other"), request(stage="repair")]
        for key, value in (("model", "other"), ("max_tokens", 8192), ("max_tokens", True),
                           ("stream", True), ("reasoning_effort", "max")):
            item = request()
            item[key] = value
            values.append(item)
        for item in values:
            with self.subTest(item=item), self.assertRaisesRegex(ModelBlocked, "contract_invalid"):
                self.invoke(item)
        self.assertEqual(self.calls, [])

    def test_invalid_deadlines_rejected(self):
        for timeout in (120, 299, 301, True, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(ModelBlocked, "contract_invalid"):
                self.invoke(timeout=timeout)
        self.assertEqual(self.calls, [])

    def test_malformed_envelopes_do_not_send(self):
        for body in (b"invalid", b'{"a":1,"a":2}', b"{}", "not-bytes",
                     runner.wire({"messages": [{"role": "system"}]})):
            with self.assertRaisesRegex(ModelBlocked, "contract_invalid"):
                self.guard(body, "synthetic-key", 300)
        self.assertEqual(self.calls, [])

    def test_telemetry_retains_only_counters_not_content_or_key(self):
        self.invoke()
        result = self.events[-1]
        self.assertEqual(result["answer_characters"], len("answer-must-not-log"))
        self.assertEqual(result["provider_reasoning_characters"], len("reasoning-must-not-log"))
        self.assertEqual(result["finish_reason"], "stop")
        self.assertEqual(result["usage"]["total_tokens"], 12)
        for marker in ("must-not-log", "synthetic-key", "do-not-log"):
            self.assertNotIn(marker, repr(self.events))

    def test_invalid_usage_is_unknown_not_zero(self):
        self.response = runner.wire({"model": runner.adapter.MODEL_ID, "usage": {
            "prompt_tokens": True, "completion_tokens": -1, "total_tokens": 10**20},
            "choices": [{"finish_reason": "provider-private-message", "message": {"content": None}}]})
        self.invoke()
        self.assertEqual(self.events[-1]["usage"], {})
        self.assertIsNone(self.events[-1]["answer_characters"])
        self.assertEqual(self.events[-1]["finish_reason"], "unknown")
        self.assertNotIn("provider-private-message", repr(self.events))

    def test_truncated_bytes_are_passed_to_adapter_unchanged_without_retry(self):
        self.response = self.response.replace(b'"stop"', b'"length"')
        self.assertEqual(self.invoke(), self.response)
        self.assertEqual(self.events[-1]["finish_reason"], "length")
        self.assertEqual(len(self.calls), 1)

    def test_bad_response_format_does_not_trigger_retry(self):
        self.response = b"invalid-provider-payload"
        self.assertEqual(self.invoke(), self.response)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.events[-1]["usage"], {})

    def test_intent_is_durable_before_send(self):
        order = []
        guard = runner.StageBudgetTransport(lambda *a: order.append("send") or self.response,
                                           lambda e: order.append(e["event"]))
        self.invoke(guard=guard)
        self.assertEqual(order, ["started", "send", "finished"])

    def test_start_write_failure_sends_nothing_and_latches(self):
        def fail(event):
            raise OSError("synthetic-write-failure")
        guard = runner.StageBudgetTransport(self.guard.send, fail)
        for _ in range(2):
            with self.assertRaisesRegex(ModelBlocked, "telemetry_failed"):
                self.invoke(guard=guard)
        self.assertEqual(guard.attempts, 0)
        self.assertEqual(self.calls, [])

    def test_completion_write_failure_blocks_any_later_send(self):
        def record(event):
            if event["event"] == "finished":
                raise OSError("synthetic-write-failure")
        guard = runner.StageBudgetTransport(self.guard.send, record)
        for _ in range(2):
            with self.assertRaisesRegex(ModelBlocked, "telemetry_failed"):
                self.invoke(guard=guard)
        self.assertEqual(len(self.calls), 1)

    def test_permission_auth_balance_rate_limit_errors_halt_all_sends(self):
        for code in ("deepseek_authentication_failed", "deepseek_access_denied",
                     "deepseek_balance_insufficient", "deepseek_rate_limited"):
            sent = []
            def fail(*args):
                sent.append(1)
                raise ModelBlocked(code)
            guard = runner.StageBudgetTransport(fail, self.events.append)
            for _ in range(2):
                with self.assertRaisesRegex(ModelBlocked, code):
                    self.invoke(guard=guard)
            self.assertEqual(len(sent), 1)

    def test_timeout_records_only_phase_and_stops(self):
        sent = []
        def fail(*args):
            sent.append(1)
            raise runner.adapter._TransportBlocked("deepseek_timeout", {
                "phase": "wait_headers", "request_started": True, "other": "do-not-log"})
        guard = runner.StageBudgetTransport(fail, self.events.append)
        for _ in range(2):
            with self.assertRaisesRegex(ModelBlocked, "deepseek_timeout"):
                self.invoke(guard=guard)
        self.assertEqual(len(sent), 1)
        self.assertEqual(self.events[-1]["transport_failure"], {
            "phase": "wait_headers", "request_started": True, "usage_and_billing_known": False})
        self.assertNotIn("do-not-log", repr(self.events))

    def test_unclassified_error_never_logs_exception_text(self):
        def fail(*args):
            raise OSError("synthetic-secret")
        guard = runner.StageBudgetTransport(fail, self.events.append)
        with self.assertRaisesRegex(ModelBlocked, "transport_failed"):
            self.invoke(guard=guard)
        self.assertNotIn("synthetic-secret", repr(self.events))


class StageBudgetAdapterIntegrationTests(unittest.TestCase):
    def test_actual_adapter_wire_passes_guard_without_changing_bytes(self):
        from tests.test_deepseek_backend import KEY, request as model_request
        backend = runner.adapter.DeepSeekV4ProBackend(api_key=KEY, settings=runner.SETTINGS)
        bodies, events = [], []
        guard = runner.StageBudgetTransport(lambda body, *_: bodies.append(body) or b"{}", events.append)
        for stage in runner.STAGES:
            req = model_request(backend, task_id=runner.TASKS[0], stage=stage,
                                payload={"review_context": {"candidate": {"verify": 0}}})
            body = runner.adapter.build_chat_request(req, runner.SETTINGS)
            guard(body, KEY, 300)
            self.assertEqual(bodies[-1], body)
        self.assertEqual(guard.configured_completion_tokens, 22528)
        self.assertNotIn(KEY, repr(events))

    def test_adapter_truncation_after_guard_remains_blocked_without_a_retry(self):
        from tests.test_deepseek_backend import KEY, envelope, request as model_request
        backend = runner.adapter.DeepSeekV4ProBackend(api_key=KEY, settings=runner.SETTINGS)
        responses = [runner.wire(envelope('{"action":"analyze","critical_mode":"guard"}')),
                     runner.wire(envelope('{}', finish="length"))]
        sent, events = [], []
        def send(body, *_):
            sent.append(body)
            return responses[len(sent) - 1]
        guard = runner.StageBudgetTransport(send, events.append)
        with patch.object(runner.adapter, "_post_official", guard):
            backend.invoke(model_request(backend, task_id=runner.TASKS[0], stage="plan"))
            with self.assertRaisesRegex(ModelBlocked, "deepseek_output_truncated"):
                backend.invoke(model_request(backend, task_id=runner.TASKS[0], stage="semantic_judge"))
        self.assertEqual(len(sent), 2)
        self.assertEqual(backend.last_completion_failure()["configured_max_tokens"], 16384)
        self.assertEqual(events[-1]["finish_reason"], "length")
        self.assertNotIn("private-provider-reasoning", repr(events))


if __name__ == "__main__":
    unittest.main()
