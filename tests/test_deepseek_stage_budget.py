"""Synthetic HTTP fixtures only; no key lookup, provider call or model score."""
from contextlib import redirect_stdout
from hashlib import sha256
import io
import json
import os
import unittest
from unittest.mock import patch

from tests.test_deepseek_backend import KEY, envelope, request, wire
from vulngym_agent.agents import deepseek_backend as ds
from vulngym_agent.agents.model_runtime import ModelBlocked


class StageBudgetTests(unittest.TestCase):
    def setUp(self):
        self.settings = ds.DeepSeekSettings(token_budget_profile="t2-balanced-v1")
        self.backend = ds.DeepSeekV4ProBackend(api_key=KEY, settings=self.settings)

    def test_actual_wire_limits_are_stage_specific(self):
        for stage, expected in (("plan", 2048), ("semantic_judge", 16384), ("reflection", 4096), ("repair", 4096)):
            with self.subTest(stage=stage):
                req = request(self.backend, stage=stage, payload={"review_context": {"candidate": {"verify": 0}}})
                body = json.loads(ds.build_chat_request(req, self.settings))
                self.assertEqual(body["max_tokens"], expected)
                self.assertFalse(body["stream"])
                self.assertEqual(body["reasoning_effort"], "high")

    def test_initial_task_budget_is_lower_not_a_currency_guarantee(self):
        profile = self.settings.profile()
        self.assertEqual(profile["initial_three_stage_output_cap"], 22528)
        self.assertEqual(profile["max_tokens"], 16384)
        self.assertEqual(2 * profile["initial_three_stage_output_cap"], 45056)
        self.assertLess(45056, 6 * 8192)
        self.assertEqual(profile["automatic_retries"], 0)
        self.assertNotIn("currency_cost", profile)

    def test_uniform_profile_and_four_requests_remain_byte_identical(self):
        # Captured before this change on a7df33b, with the same synthetic request.
        expected = {"plan": "c4bca9a1ce087c292e5c212dbceac5db8589bdbe29767394de759aa34dac7540",
            "semantic_judge": "aae2f22bbe1ee6e94c6d613e5446493de4ee94d97c80f24f8cbf4e484c808167",
            "reflection": "7097f90c44d7ee7b7eedc95443627adf95ba0719368ac10cd269399587482377",
            "repair": "e695a7beb18fb2247f9f5911f03418eb1fcb6bac8bbc9563d56b3deb68f658bd"}
        legacy = ds.DeepSeekV4ProBackend(api_key=KEY)
        self.assertEqual(legacy.backend_id, "deepseek:t2-json-v5:e51cfb6d694bbdfda1fbee0d")
        self.assertNotIn("token_budget_profile", legacy.configuration())
        for stage, digest in expected.items():
            req = request(legacy, stage=stage, payload={"review_context": {"candidate": {"verify": 0}}})
            self.assertEqual(sha256(ds.build_chat_request(req, ds.DeepSeekSettings())).hexdigest(), digest)

    def test_custom_uniform_limit_still_works(self):
        uniform = ds.DeepSeekSettings(max_tokens=1234)
        for stage in ("plan", "semantic_judge", "reflection", "repair"):
            self.assertEqual(uniform.max_tokens_for_stage(stage), 1234)

    def test_unknown_profile_and_conflicting_uniform_limit_are_rejected(self):
        for kwargs in ({"token_budget_profile": "unknown"}, {"token_budget_profile": None},
                       {"token_budget_profile": "t2-balanced-v1", "max_tokens": 16384}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ds.DeepSeekSettings(**kwargs)

    def test_unknown_stage_rejected(self):
        with self.assertRaises(ValueError):
            self.settings.max_tokens_for_stage("unlisted")

    def test_profile_identity_changes_but_prompt_does_not(self):
        legacy = ds.DeepSeekV4ProBackend(api_key=KEY)
        self.assertNotEqual(legacy.backend_id, self.backend.backend_id)
        self.assertEqual(legacy.configuration()["prompt_sha256"], self.backend.configuration()["prompt_sha256"])

    def test_mutating_returned_stage_map_cannot_change_settings(self):
        profile = self.settings.profile()
        profile["stage_max_tokens"]["semantic_judge"] = 1
        self.assertEqual(self.settings.max_tokens_for_stage("semantic_judge"), 16384)

    def test_settings_check_never_reads_key_or_connects(self):
        output = io.StringIO()
        values = {"VULNGYM_DEEPSEEK_TOKEN_BUDGET_PROFILE": "t2-balanced-v1"}
        def get(name, default=None):
            self.assertNotEqual(name, "DEEPSEEK_API_KEY")
            return values.get(name, default)
        with patch.object(ds.os.environ, "get", side_effect=get), patch.object(ds, "_post_official") as post, redirect_stdout(output):
            self.assertEqual(ds.main(["--check-settings"]), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value["status"], "settings_only_not_connected")
        self.assertEqual(value["network_calls"], 0)
        self.assertEqual(value["token_budget_profile"], "t2-balanced-v1")
        post.assert_not_called()

    def test_factory_opt_in_is_explicit_and_local(self):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": KEY,
                "VULNGYM_DEEPSEEK_TOKEN_BUDGET_PROFILE": "t2-balanced-v1"}, clear=True), patch.object(ds, "_post_official") as post:
            backend = ds.create_backend()
        self.assertEqual(backend.backend_id, self.backend.backend_id)
        post.assert_not_called()

    def test_settings_error_does_not_echo_environment(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"VULNGYM_DEEPSEEK_TOKEN_BUDGET_PROFILE": "sensitive-invalid-value"}, clear=True), redirect_stdout(output):
            code = ds.main(["--check-settings"])
        self.assertEqual(code, 2)
        self.assertNotIn("sensitive-invalid-value", output.getvalue())


class CompletionDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.settings = ds.DeepSeekSettings(token_budget_profile="t2-balanced-v1")
        self.backend = ds.DeepSeekV4ProBackend(api_key=KEY, settings=self.settings)

    def truncated(self, *, content="not-to-be-logged", reasoning="hidden-provider-text"):
        value = envelope(content, finish="length")
        value["choices"][0]["message"]["reasoning_content"] = reasoning
        value["usage"] = {"prompt_tokens": 20, "completion_tokens": 16384, "total_tokens": 16404}
        return value

    def invoke_failure(self, value):
        with patch.object(ds, "_post_official", return_value=wire(value)) as post:
            with self.assertRaises(ModelBlocked) as stopped:
                self.backend.invoke(request(self.backend, stage="semantic_judge"))
        self.assertEqual(stopped.exception.error_code, "deepseek_output_truncated")
        self.assertEqual(post.call_count, 1)
        return self.backend.last_completion_failure()

    def test_length_never_emits_even_when_partial_content_is_valid_json(self):
        value = self.invoke_failure(self.truncated(content='{"action":"emit"}'))
        self.assertEqual(value["finish_reason"], "length")
        self.assertEqual(value["configured_max_tokens"], 16384)
        self.assertEqual(value["stage"], "semantic_judge")
        self.assertEqual(value["completion_tokens"], 16384)
        self.assertTrue(value["usage_consistent"])

    def test_diagnostic_retains_counts_not_text_or_credentials(self):
        value = self.invoke_failure(self.truncated(content=KEY, reasoning="private text example"))
        self.assertEqual(value["answer_characters"], len(KEY))
        self.assertEqual(value["provider_reasoning_characters"], len("private text example"))
        self.assertNotIn(KEY, json.dumps(value))
        self.assertNotIn("private text example", json.dumps(value))
        self.assertFalse(value["currency_cost_measured"])
        self.assertIsNone(self.backend.last_transport_failure())

    def test_missing_usage_and_text_are_unknown_not_zero(self):
        response = self.truncated(content=None, reasoning=None)
        response.pop("usage")
        response["choices"][0]["message"]["content"] = None
        value = self.invoke_failure(response)
        for key in ("answer_characters", "provider_reasoning_characters", "prompt_tokens", "completion_tokens", "total_tokens"):
            self.assertIsNone(value[key])
        self.assertFalse(value["usage_consistent"])

    def test_inconsistent_usage_remains_flagged(self):
        response = self.truncated()
        response["usage"]["total_tokens"] = 1
        value = self.invoke_failure(response)
        self.assertFalse(value["usage_consistent"])

    def test_boolean_negative_and_oversized_token_counts_are_unknown(self):
        response = self.truncated()
        response["usage"] = {"prompt_tokens": True, "completion_tokens": -1, "total_tokens": 10**12}
        value = self.invoke_failure(response)
        self.assertTrue(all(value[k] is None for k in ("prompt_tokens", "completion_tokens", "total_tokens")))

    def test_diagnostic_return_is_a_copy(self):
        value = self.invoke_failure(self.truncated())
        value["configured_max_tokens"] = 1
        self.assertEqual(self.backend.last_completion_failure()["configured_max_tokens"], 16384)

    def test_later_success_does_not_reassign_failure_to_another_task(self):
        self.invoke_failure(self.truncated())
        with patch.object(ds, "_post_official", return_value=wire(envelope())):
            self.backend.invoke(request(self.backend, task_id="task:two"))
        self.assertEqual(self.backend.last_completion_failure()["task_id"], "task:one")

    def test_success_has_no_failure_metadata(self):
        with patch.object(ds, "_post_official", return_value=wire(envelope())):
            self.backend.invoke(request(self.backend))
        self.assertIsNone(self.backend.last_completion_failure())

    def test_wrong_model_cannot_supply_diagnostic_metadata(self):
        response = self.truncated()
        response["model"] = "other-model"
        with patch.object(ds, "_post_official", return_value=wire(response)), self.assertRaises(ModelBlocked):
            self.backend.invoke(request(self.backend))
        self.assertIsNone(self.backend.last_completion_failure())


if __name__ == "__main__":
    unittest.main()
