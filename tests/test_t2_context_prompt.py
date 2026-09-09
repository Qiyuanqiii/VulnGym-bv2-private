"""Synthetic wire serialization only; no model, transport or target source reads."""

from __future__ import annotations

import json
import unittest

from vulngym_agent.agents import deepseek_backend as ds
from vulngym_agent.agents.model_runtime import ModelBlocked, ModelRequest


def semantic_request(payload):
    return ModelRequest(
        task_id="task:context-prompt", attempt=0, policy_scope="t2.initial",
        stage="semantic_judge", model_call_id="MODEL-context-prompt",
        backend_id="synthetic-backend", model_id=ds.MODEL_ID, payload=payload,
    )


def wire(payload):
    return json.loads(ds.build_chat_request(semantic_request(payload), ds.DeepSeekSettings()))


class ContextPromptTests(unittest.TestCase):
    def test_default_contract_remains_select_defer_only(self):
        for payload in ({"contract_version": 1},
                        {"contract_version": 2, "semantic_context": {}, "defer_contract": {}}):
            with self.subTest(version=payload["contract_version"]):
                body = wire(payload)
                self.assertEqual(len(body["messages"]), 2)
                self.assertEqual(json.loads(body["messages"][1]["content"]),
                                 semantic_request(payload).to_dict())
                self.assertNotIn("context_request_contract", json.loads(body["messages"][1]["content"])["payload"])
                self.assertIn("Without payload.context_request_contract, select/defer are the only actions.",
                              body["messages"][0]["content"])
                self.assertIn('The exact select shape is {"action":"select"', body["messages"][0]["content"])
                self.assertIn('the base defer object is {"action":"defer"', body["messages"][0]["content"])
        self.assertEqual(ds.PROMPT_VERSION, "t2-json-v6")

    def test_opt_in_and_followup_serialize_only_current_bounded_context(self):
        payload = {
            "contract_version": 2, "semantic_context": {}, "defer_contract": {},
            "critical_candidates": [{"candidate_id": "CR-synthetic"}],
            "entry_candidates": [{"candidate_id": "EN-synthetic", "symbol": "synthetic_entry"}],
            "context_request_contract": {
                "rounds_remaining": 1, "candidate_ids": ["CR-synthetic", "EN-synthetic"],
                "max_requests": 2, "kinds": ["window", "references"], "max_reason_chars": 200,
            },
        }
        first = wire(payload)
        prompt = first["messages"][0]["content"]
        self.assertIn('"action":"request_context","requests":[{"candidate_id":"<issued ID>"', prompt)
        for phrase in ("rounds_remaining is greater than", "Use 1-2 unique requests",
                       "existing critical or entry candidate ID", "only kinds are window and references",
                       "chosen candidate supplies a usable symbol", "No other fields, paths, commands, code",
                       "1-200 characters", "Reference hits are identifier occurrences, not proven calls",
                       "could resolve a specific missing fact", "rounds_remaining is zero",
                       "request_context and repeated context requests are forbidden"):
            self.assertIn(phrase, prompt)
        self.assertEqual(json.loads(first["messages"][1]["content"])["payload"], payload)
        requested = [{"candidate_id": "EN-synthetic", "kind": "references",
                      "reason": "The supplied code does not show which callers reach this entry."}]
        followup = {
            "status": "bounded_context_added_not_exhaustive", "requests": requested,
            "source_contexts": [{"evidence_id": "EV-synthetic", "text": "synthetic_entry(value)",
                                 "call_relationship_verified": False}],
            "omitted_path_count": 1,
        }
        second_payload = {
            **payload, "semantic_context": {"followup": followup},
            "context_request_contract": {**payload["context_request_contract"], "rounds_remaining": 0},
        }
        second = wire(second_payload)
        self.assertEqual(json.loads(second["messages"][1]["content"])["payload"], second_payload)
        self.assertEqual(len(second["messages"]), 2)
        self.assertNotIn("EV-synthetic", first["messages"][1]["content"])
        self.assertIn("payload.semantic_context.followup", second["messages"][0]["content"])

    def test_advertised_contract_must_be_a_mapping(self):
        for invalid in (None, [], True, "request-context"):
            with self.subTest(contract=invalid), self.assertRaises(ModelBlocked) as blocked:
                wire({"contract_version": 2, "semantic_context": {}, "defer_contract": {},
                      "context_request_contract": invalid})
            self.assertEqual(blocked.exception.error_code, "deepseek_context_request_contract_invalid")


if __name__ == "__main__":
    unittest.main()
