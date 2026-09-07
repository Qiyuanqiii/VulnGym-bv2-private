"""Offline HTTP/protocol doubles only; no DeepSeek account or live model calls."""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_real_t2_producer as fixture
from vulngym_agent.agents import deepseek_backend as ds
from vulngym_agent.agents.model_runtime import ModelBlocked, ModelRequest
from vulngym_agent.agents.real_t2_producer import LocalStructuredT2Producer
from vulngym_agent.orchestrator import Budget, Limits
from vulngym_agent.t2_production_cli import LocalProductionTaskRunner, load_backend_factory


KEY = "synthetic-test-key-not-a-credential"


def request(backend, *, stage="plan", payload=None, task_id="task:one", attempt=0):
    return ModelRequest(task_id=task_id, attempt=attempt,
                        policy_scope="t2.initial" if attempt == 0 else "t2.repair-1",
                        stage=stage, model_call_id="MODEL-example-" + stage,
                        backend_id=backend.backend_id, model_id=backend.model_id,
                        payload={} if payload is None else payload)


def envelope(content=None, *, finish="stop", model=ds.MODEL_ID):
    return {"object": "chat.completion", "model": model, "choices": [{
        "index": 0, "finish_reason": finish,
        "message": {"role": "assistant", "content": content if content is not None else '{"action":"defer","critical_mode":null}',
                    "reasoning_content": "private-provider-reasoning-not-for-persistence"},
    }]}


def wire(value):
    return json.dumps(value, ensure_ascii=True).encode("utf-8")


class DeepSeekConfigurationTests(unittest.TestCase):
    def test_factory_loads_with_explicit_key_without_network_or_sdk(self):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": KEY}, clear=True), patch.object(ds, "_post_official") as post:
            backend = load_backend_factory("vulngym_agent.agents.deepseek_backend:create_backend")
            profile = backend.configuration()
        self.assertEqual(backend.model_id, "deepseek-v4-pro")
        self.assertEqual(profile["reasoning_effort"], "high")
        self.assertEqual(profile["max_tokens"], 8192)
        self.assertEqual(profile["automatic_retries"], 0)
        self.assertNotIn(KEY, repr(backend) + repr(profile))
        post.assert_not_called()

    def test_explicit_effort_limits_and_prompt_are_bound_to_identity(self):
        one = ds.DeepSeekV4ProBackend(api_key=KEY)
        same = ds.DeepSeekV4ProBackend(api_key="different-synthetic-key")
        maximum = ds.DeepSeekV4ProBackend(api_key=KEY, settings=ds.DeepSeekSettings(reasoning_effort="max"))
        self.assertEqual(one.backend_id, same.backend_id)
        self.assertNotEqual(one.backend_id, maximum.backend_id)
        self.assertEqual(len(one.configuration()["prompt_sha256"]), 64)
        with self.assertRaises(AttributeError):
            one.model_id = "different"

    def test_invalid_settings_fail_without_network(self):
        for settings in ({"reasoning_effort": "ultra"}, {"max_tokens": True},
                         {"max_tokens": 0}, {"max_tokens": 32769},
                         {"timeout_seconds": float("nan")}, {"timeout_seconds": float("inf")},
                         {"timeout_seconds": True}, {"timeout_seconds": 0}, {"timeout_seconds": 301}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                ds.DeepSeekSettings(**settings)

    def test_key_is_required_and_control_characters_are_rejected(self):
        for key in (None, "", "one\ntwo", "one two", "非ASCII", "x" * 4097):
            with self.subTest(key_type=type(key).__name__), self.assertRaises(ValueError):
                ds.DeepSeekV4ProBackend(api_key=key)
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            ds.create_backend()

    def test_config_check_reports_presence_not_key_or_connectivity(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": KEY}, clear=True), patch.object(ds, "_post_official") as post, redirect_stdout(output):
            code = ds.main(["--check-config"])
        value = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(value["status"], "configured_not_connected")
        self.assertEqual(value["network_calls"], 0)
        self.assertNotIn(KEY, output.getvalue())
        post.assert_not_called()

    def test_bad_environment_is_normalized_without_echo(self):
        for environment in ({}, {"DEEPSEEK_API_KEY": KEY, "VULNGYM_DEEPSEEK_MAX_TOKENS": "secret-configuration-text"}):
            output = io.StringIO()
            with patch.dict(os.environ, environment, clear=True), redirect_stdout(output):
                code = ds.main(["--check-config"])
            self.assertEqual(code, 2)
            self.assertNotIn("secret-configuration-text", output.getvalue())
            self.assertNotIn(KEY, output.getvalue())


class DeepSeekProtocolTests(unittest.TestCase):
    def setUp(self):
        self.backend = ds.DeepSeekV4ProBackend(api_key=KEY)

    def test_request_uses_official_model_json_thinking_and_only_current_context(self):
        first = request(self.backend, payload={"sample": "first-task-only"})
        second = request(self.backend, task_id="task:two", payload={"sample": "second-task-only"})
        with patch.object(ds, "_post_official", return_value=wire(envelope())) as post:
            self.backend.invoke(first)
            self.backend.invoke(second)
        self.assertEqual(post.call_count, 2)
        body = json.loads(post.call_args.args[0])
        self.assertEqual(body["model"], ds.MODEL_ID)
        self.assertEqual(body["thinking"], {"type": "enabled"})
        self.assertEqual(body["reasoning_effort"], "high")
        self.assertEqual(body["response_format"], {"type": "json_object"})
        self.assertFalse(body["stream"])
        self.assertNotIn("temperature", body)
        self.assertNotIn("tools", body)
        self.assertIn("JSON", body["messages"][0]["content"])
        self.assertEqual(json.loads(body["messages"][1]["content"]), second.to_dict())
        self.assertNotIn("first-task-only", str(body))

    def test_request_identities_must_match_and_no_fallback_is_attempted(self):
        other = ds.DeepSeekV4ProBackend(api_key=KEY, settings=ds.DeepSeekSettings(reasoning_effort="max"))
        with patch.object(ds, "_post_official") as post, self.assertRaises(ModelBlocked) as blocked:
            self.backend.invoke(request(other))
        self.assertEqual(blocked.exception.error_code, "deepseek_request_identity_mismatch")
        post.assert_not_called()

    def test_reflection_requires_actual_candidate_context_before_sending(self):
        with patch.object(ds, "_post_official") as post, self.assertRaises(ModelBlocked) as blocked:
            self.backend.invoke(request(self.backend, stage="reflection", payload={"schema_valid": True}))
        self.assertEqual(blocked.exception.error_code, "deepseek_reflection_context_missing")
        post.assert_not_called()

    def test_all_four_stages_have_explicit_json_contracts(self):
        for stage in ("plan", "semantic_judge", "reflection", "repair"):
            with self.subTest(stage=stage):
                body = json.loads(ds.build_chat_request(request(self.backend, stage=stage, payload={
                    "review_context": {"candidate": {"verify": 0}},
                }), ds.DeepSeekSettings()))
                self.assertIn('"action"', body["messages"][0]["content"])

    def test_bounded_wire_request_is_checked_before_transport(self):
        with patch.object(ds, "MAX_REQUEST_BYTES", 20), patch.object(ds, "_post_official") as post:
            with self.assertRaises(ModelBlocked) as blocked:
                self.backend.invoke(request(self.backend))
        self.assertEqual(blocked.exception.error_code, "deepseek_request_too_large")
        post.assert_not_called()

    def test_response_returns_only_content_not_provider_reasoning(self):
        parsed = ds.parse_chat_response(wire(envelope('{"action":"emit"}')))
        self.assertEqual(parsed, {"action": "emit"})
        self.assertNotIn("private-provider-reasoning", repr(parsed))

    def test_invalid_empty_nonfinite_duplicate_or_nonobject_content_is_not_repaired(self):
        for content in ("", " ", "[]", "null", "```json\n{}\n```", '{"a":1,"a":2}',
                        '{"a":NaN}', '{"a":Infinity}', '{"a":', '{"a":"\\ud800"}'):
            with self.subTest(content=content), self.assertRaises(ModelBlocked):
                ds.parse_chat_response(wire(envelope(content)))

    def test_truncation_filter_and_server_interruption_are_not_success(self):
        for finish, code in (("length", "deepseek_output_truncated"),
                             ("content_filter", "deepseek_content_filtered"),
                             ("insufficient_system_resource", "deepseek_resource_unavailable"),
                             ("tool_calls", "deepseek_completion_incomplete")):
            with self.subTest(finish=finish), self.assertRaises(ModelBlocked) as blocked:
                ds.parse_chat_response(wire(envelope('{"action":"emit"}', finish=finish)))
            self.assertEqual(blocked.exception.error_code, code)

    def test_response_envelope_and_model_are_checked(self):
        cases = [b"not json", b"[]", b'\xff', b'{"model":1,"model":2}',
                 wire(envelope(model="deepseek-v4-flash"))]
        for mutation in ({"choices": []}, {"choices": [None]}, {"object": "wrong"}):
            value = envelope()
            value.update(mutation)
            cases.append(wire(value))
        for raw in cases:
            with self.subTest(raw_size=len(raw)), self.assertRaises(ModelBlocked):
                ds.parse_chat_response(raw)
        with patch.object(ds, "MAX_RESPONSE_BYTES", 16), self.assertRaises(ModelBlocked):
            ds.parse_chat_response(wire(envelope()))

    def test_auth_balance_access_and_rate_limit_stop_later_network_calls(self):
        for code in ("deepseek_authentication_failed", "deepseek_balance_insufficient",
                     "deepseek_access_denied", "deepseek_rate_limited"):
            backend = ds.DeepSeekV4ProBackend(api_key=KEY)
            with self.subTest(code=code), patch.object(ds, "_post_official", side_effect=ModelBlocked(code)) as post:
                for task_id in ("task:one", "task:two"):
                    with self.assertRaises(ModelBlocked) as blocked:
                        backend.invoke(request(backend, task_id=task_id))
                    self.assertEqual(blocked.exception.error_code, code)
                self.assertEqual(post.call_count, 1)


class _Socket:
    def __init__(self):
        self.timeouts = []
        self.shutdowns = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def shutdown(self, how):
        self.shutdowns.append(how)


class _Response:
    def __init__(self, raw, *, status=200, headers=None):
        self.raw = io.BytesIO(raw)
        self.status = status
        self.headers = {} if headers is None else headers
        self.closed = False
        self.reads = []

    def getheader(self, key, default=None):
        return self.headers.get(key, default)

    def isclosed(self):
        return self.closed

    def read1(self, limit):
        self.reads.append(limit)
        chunk = self.raw.read(limit)
        if self.raw.tell() == len(self.raw.getvalue()):
            self.closed = True
        return chunk

    def close(self):
        self.closed = True


class _Connection:
    def __init__(self, response):
        self.sock = _Socket()
        self.response = response
        self.requests = []
        self.closed = False

    def connect(self):
        pass

    def request(self, method, path, *, body, headers):
        self.requests.append((method, path, body, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class DeepSeekTransportTests(unittest.TestCase):
    def post(self, response):
        connection = _Connection(response)
        with patch.object(ds.http.client, "HTTPSConnection", return_value=connection) as constructor:
            result = ds._post_official(b"{}", KEY, 20)
        constructor.assert_called_once_with("api.deepseek.com", timeout=20)
        self.assertTrue(connection.closed)
        return result, connection

    def test_single_official_post_and_closed_response_body(self):
        raw = wire(envelope())
        result, connection = self.post(_Response(raw, headers={"Content-Length": str(len(raw))}))
        self.assertEqual(result, raw)
        self.assertEqual(len(connection.requests), 1)
        method, path, body, headers = connection.requests[0]
        self.assertEqual((method, path, body), ("POST", "/chat/completions", b"{}"))
        self.assertEqual(headers["Authorization"], "Bearer " + KEY)
        self.assertEqual(headers["Accept-Encoding"], "identity")

    def test_error_body_is_not_read_and_redirects_are_not_followed(self):
        for status, code in ((301, "deepseek_redirect_rejected"), (307, "deepseek_redirect_rejected"),
                             (401, "deepseek_authentication_failed"), (402, "deepseek_balance_insufficient"),
                             (403, "deepseek_access_denied"), (429, "deepseek_rate_limited"),
                             (503, "deepseek_server_error")):
            response = _Response(b"provider-secret-text", status=status)
            connection = _Connection(response)
            with self.subTest(status=status), patch.object(ds.http.client, "HTTPSConnection", return_value=connection):
                with self.assertRaises(ModelBlocked) as blocked:
                    ds._post_official(b"{}", KEY, 20)
                self.assertEqual(blocked.exception.error_code, code)
                self.assertEqual(response.reads, [])
                self.assertEqual(len(connection.requests), 1)
                self.assertTrue(connection.closed)
                self.assertNotIn("provider-secret-text", str(blocked.exception))

    def test_size_encoding_and_truncated_http_body_checks(self):
        for response, code in ((
                _Response(b"x", headers={"Content-Length": str(ds.MAX_RESPONSE_BYTES + 1)}),
                "deepseek_response_too_large"), (
                _Response(b"x", headers={"Content-Encoding": "gzip"}),
                "deepseek_response_encoding_unsupported"), (
                _Response(b"x", headers={"Content-Length": "bad"}),
                "deepseek_response_invalid"), (
                _Response(b"x", headers={"Content-Length": "9"}),
                "deepseek_response_incomplete")):
            with self.subTest(code=code), self.assertRaises(ModelBlocked) as blocked:
                self.post(response)
            self.assertEqual(blocked.exception.error_code, code)
        with patch.object(ds, "MAX_RESPONSE_BYTES", 10), self.assertRaises(ModelBlocked) as blocked:
            self.post(_Response(b"x" * 11))
        self.assertEqual(blocked.exception.error_code, "deepseek_response_too_large")

    def test_socket_failure_is_normalized_and_has_no_retry(self):
        connection = _Connection(_Response(b""))
        connection.connect = lambda: (_ for _ in ()).throw(TimeoutError("private connection text"))
        with patch.object(ds.http.client, "HTTPSConnection", return_value=connection) as constructor:
            with self.assertRaises(ModelBlocked) as blocked:
                ds._post_official(b"{}", KEY, 20)
        self.assertEqual(blocked.exception.error_code, "deepseek_timeout")
        constructor.assert_called_once()
        self.assertTrue(connection.closed)
        self.assertNotIn("private connection text", str(blocked.exception))

    def test_deadline_cancels_active_read_even_with_keepalive_bytes(self):
        response = _Response(b" ")
        connection = _Connection(response)
        timers = []
        class ManualTimer:
            def __init__(self, seconds, callback):
                self.callback = callback
                self.cancelled = False
                timers.append(self)
            def start(self):
                pass
            def cancel(self):
                self.cancelled = True
        def read1(limit):
            timers[0].callback()
            return b" "
        response.read1 = read1
        with patch.object(ds, "Timer", ManualTimer), patch.object(ds.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaises(ModelBlocked) as blocked:
                ds._post_official(b"{}", KEY, 20)
        self.assertEqual(blocked.exception.error_code, "deepseek_timeout")
        self.assertEqual(connection.sock.shutdowns, [ds.socket.SHUT_RDWR])
        self.assertTrue(connection.closed)
        self.assertTrue(timers[0].cancelled)


class DeepSeekProductionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.LocalStructuredT2ProducerTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def test_adapter_to_local_producer_and_t1_with_only_http_mocked(self):
        backend = ds.DeepSeekV4ProBackend(api_key=KEY)
        runner = LocalProductionTaskRunner(
            package_root=self.fixture.package_root,
            repo_map={fixture.REPO_URL: self.fixture.repository}, backend=backend,
            limits=Limits(max_llm_calls=8, max_tool_calls=80),
        )
        staged = []
        scripted = fixture._ScriptedBackend()
        def response(body, key, timeout):
            current = json.loads(json.loads(body)["messages"][1]["content"])
            staged.append(current)
            answer = scripted.invoke(SimpleNamespace(stage=current["stage"], payload=current["payload"]))
            return wire(envelope(json.dumps(answer)))
        with patch.object(ds, "_post_official", side_effect=response) as post:
            outcome = runner.run(self.fixture._task())
            runner.finalize_batch()
        self.assertEqual(post.call_count, 3)
        self.assertEqual(outcome.status, "manual_review")
        self.assertEqual(outcome.entry["verify"], 0)
        self.assertEqual(outcome.report.verdict, "uncertain")
        self.assertEqual(staged[0]["payload"]["contract_version"], 2)
        self.assertIn("planning_evidence", staged[0]["payload"])
        self.assertIn("diffs", staged[0]["payload"]["planning_evidence"])
        context = staged[-1]["payload"]["review_context"]
        self.assertEqual(context["candidate"], fixture._plain(outcome.entry))
        self.assertIn("advisory_snippet", context)
        self.assertIn("selected_critical", context)
        self.assertEqual(staged[1]["payload"]["contract_version"], 2)
        self.assertEqual(context["semantic_context"], staged[1]["payload"]["semantic_context"])
        self.assertTrue(staged[1]["payload"]["defer_contract"]["required_on_semantic_defer"])
        self.assertNotIn(KEY, repr(outcome))
        self.assertNotIn("private-provider-reasoning", repr(outcome))

    def test_legacy_producer_does_not_change_reflection_request_shape(self):
        scripted = fixture._ScriptedBackend()
        draft, projection, _ = self.fixture._generate(scripted)
        reflection = [r for r in scripted.requests if r.stage == "reflection"][0]
        self.assertNotIn("review_context", reflection.payload)
        self.assertEqual(set(reflection.payload), {"contract_version", "candidate_sha256", "schema_valid",
                                                  "critical_candidate_id", "entry_candidate_id", "allowed_actions"})

    def test_context_flag_rejects_non_boolean_configuration(self):
        with self.assertRaises(ValueError):
            LocalStructuredT2Producer(include_reflection_context="true")

    def test_repair_review_context_is_opt_in_and_preserves_legacy_shape(self):
        task = self.fixture._task()
        generated, _, _ = self.fixture._generate(fixture._ScriptedBackend(), task=task)
        previous = fixture._plain(generated.candidate)
        plan = self.fixture._title_plan(task, previous, "A more specific test title")
        for enabled in (False, True):
            scripted = fixture._ScriptedBackend()
            controller = self.fixture._factory(scripted).create(
                task, attempt=1, mode="repair", plan=plan,
                budget=Budget(Limits(max_llm_calls=4, max_tool_calls=20)),
            )
            repaired = LocalStructuredT2Producer(include_reflection_context=enabled).repair(
                task, previous, plan, controller.producer_context,
            )
            controller.finalize()
            reflection = [r for r in scripted.requests if r.stage == "reflection"][0]
            with self.subTest(enabled=enabled):
                if enabled:
                    context = reflection.payload["review_context"]
                    self.assertEqual(fixture._plain(context["candidate"]), fixture._plain(repaired.candidate))
                    self.assertEqual(fixture._plain(context["previous_candidate"]), previous)
                    self.assertIn("check_evidence", context)
                else:
                    self.assertEqual(set(reflection.payload), {"contract_version", "candidate_sha256",
                        "parent_candidate_sha256", "repair_plan_sha256", "changed_fields", "schema_valid", "allowed_actions"})


if __name__ == "__main__":
    unittest.main()
