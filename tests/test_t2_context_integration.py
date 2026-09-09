"""Offline integration checks for one bounded context-followup round.

All source and Git history are disposable synthetic fixtures. These tests do
not contact a model or measure vulnerability-detection quality.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
import subprocess
import unittest
from unittest.mock import patch

from tests import test_t2_production_cli as fixture
from vulngym_agent.agents import real_t2_producer as producer
from vulngym_agent.orchestrator import Limits


class _ContextBackend(fixture.fixture._ScriptedBackend):
    def __init__(self, *, repeat=False, invalid_id=False, kind="window"):
        super().__init__()
        self.repeat = repeat
        self.invalid_id = invalid_id
        self.kind = kind
        self.observe = lambda request: None

    def invoke(self, request):
        self.observe(request)
        previous = sum(item.stage == "semantic_judge" for item in self.requests)
        if request.stage == "semantic_judge" and (previous == 0 or self.repeat):
            self.requests.append(request)
            candidate_id = request.payload["critical_candidates"][0]["candidate_id"]
            return {
                "action": "request_context",
                "requests": [{
                    "candidate_id": "not-an-issued-candidate" if self.invalid_id else candidate_id,
                    "kind": self.kind,
                    "reason": "missing context",
                }],
            }
        return super().invoke(request)


class ContextFollowupIntegrationTests(unittest.TestCase):
    def setUp(self):
        # Keep the imported TestCase inside its module, avoiding duplicate discovery.
        self.composition = fixture.ProductionCompositionTests()
        self.addCleanup(self.composition.doCleanups)
        self.composition.setUp()
        self.synthetic = self.composition.fixture

    def _source_variant(self, *, no_gap=False, tail=""):
        """Create two commits only inside the fixture's temporary repository."""
        source_path = fixture.fixture.SOURCE_PATH
        revisions = (self.synthetic.vulnerable_commit, self.synthetic.fix_commit)
        contents = [fixture.fixture._git(self.synthetic.repository, "show", f"{rev}:{source_path}")
                    for rev in revisions]
        new_revisions = []
        for label, content in zip(("synthetic context vulnerable", "synthetic context fix"), contents):
            if no_gap:
                content = content.replace("\n\n@app", "\n@app")
            (self.synthetic.repository / source_path).write_text(content + "\n" + tail, encoding="utf-8")
            fixture.fixture._git(self.synthetic.repository, "add", "--", source_path)
            fixture.fixture._git(self.synthetic.repository, "commit", "--quiet", "-m", label)
            new_revisions.append(fixture.fixture._git(self.synthetic.repository, "rev-parse", "HEAD"))
        self.synthetic.vulnerable_commit, self.synthetic.fix_commit = new_revisions
        diff = fixture.fixture._git(self.synthetic.repository, "diff", "--no-ext-diff",
                                    *new_revisions, "--", source_path)
        (self.synthetic.package_root / "patches" / "fix.patch").write_text(diff + "\n", encoding="utf-8")
        self.synthetic._write_advisory((self.synthetic.fix_commit,))
        self.composition.task = self.synthetic._task()

    def _with_supplement(self):
        self._source_variant(tail=(
            "\n# Synthetic caller is outside both initial Python-function windows.\n"
            "synthetic_caller = dangerous\n"
        ))

    def _run(self, backend, **configuration):
        return self.composition.runner(backend, context_followup=True, **configuration).run(
            self.composition.task)

    def test_followup_lines_and_pinned_evidence_reach_second_judge_and_reflection(self):
        self._with_supplement()
        backend = _ContextBackend()
        read_counts = []
        original = producer._Attempt.tool_call
        with patch.object(producer._Attempt, "tool_call", autospec=True, side_effect=original) as reading:
            backend.observe = lambda request: read_counts.append(reading.call_count) if request.stage == "semantic_judge" else None
            outcome = self._run(backend)
        # The follow-up must reuse the pinned blob already read for this file.
        self.assertEqual(len(read_counts), 2)
        self.assertEqual(read_counts[0], read_counts[1])
        context_reads = [call.args[2] for call in reading.call_args_list
                         if call.args[1] == "git_show" and call.kwargs.get("stage") == "semantic_judge"]
        self.assertEqual(len(context_reads), 1)
        self.assertEqual(context_reads[0]["commit"], self.synthetic.vulnerable_commit)
        self.assertEqual(context_reads[0]["path"], fixture.fixture.SOURCE_PATH)
        self.assertEqual([item.stage for item in backend.requests],
                         ["plan", "semantic_judge", "semantic_judge", "reflection"])
        self.assertIsNotNone(outcome.entry)
        self.assertEqual(outcome.entry["verify"], 0)
        self.assertEqual(len(outcome.validation_outcomes), 1)
        initial, second, reflection = backend.requests[1:]
        self.assertEqual(initial.payload["context_request_contract"]["rounds_remaining"], 1)
        self.assertEqual(second.payload["context_request_contract"]["rounds_remaining"], 0)
        self.assertNotIn("followup", initial.payload["semantic_context"])
        context = second.payload["semantic_context"]
        self.assertEqual(context, reflection.payload["review_context"]["semantic_context"])
        blocks = context["followup"]["source_contexts"]
        self.assertTrue(blocks)
        self.assertIn("synthetic_caller = dangerous", "\n".join(block["text"] for block in blocks))

        pinned = subprocess.run(
            ["git", "-C", str(self.synthetic.repository), "show",
             f"{self.synthetic.vulnerable_commit}:{fixture.fixture.SOURCE_PATH}"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout.decode("utf-8-sig")
        digest = hashlib.sha256(pinned.encode("utf-8")).hexdigest()
        covered = {(block["file"], line)
                   for block in initial.payload["semantic_context"]["source_contexts"]
                   for line in range(block["line_start"], block["line_end"] + 1)}
        production = outcome.production_outcomes[0]
        evidence = {item.evidence_id: item for item in production.evidence}
        tool_ids = {item.tool_call_id for item in production.tool_calls}
        self.assertEqual(len(production.model_calls), 4)
        self.assertEqual(len({request.operation for request in backend.requests}), 4)
        for block in blocks:
            with self.subTest(evidence_id=block["evidence_id"]):
                self.assertEqual(block["commit"], self.synthetic.vulnerable_commit)
                self.assertEqual(block["blob_sha256"], digest)
                self.assertIn(block["tool_call_id"], tool_ids)
                self.assertEqual(block["text"], "\n".join(
                    pinned.splitlines()[block["line_start"] - 1:block["line_end"]]))
                new_lines = {(block["file"], line)
                             for line in range(block["line_start"], block["line_end"] + 1)}
                self.assertFalse(new_lines & covered)
                covered.update(new_lines)
                stored = evidence[block["evidence_id"]]
                self.assertEqual(json.loads(stored.snippet), fixture.fixture._plain(block))
                for request in (second, reflection):
                    self.assertIn(block["evidence_id"], request.payload["defer_contract"]["allowed_evidence_refs"])

    def test_opt_in_without_a_request_keeps_three_calls_and_disabled_omits_contract(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                backend = fixture.fixture._ScriptedBackend()
                outcome = self.composition.runner(backend, context_followup=enabled).run(self.composition.task)
                self.assertIsNotNone(outcome.entry)
                self.assertEqual([item.stage for item in backend.requests],
                                 ["plan", "semantic_judge", "reflection"])
                payload = backend.requests[1].payload
                self.assertEqual("context_request_contract" in payload, enabled)
                self.assertNotIn("followup", payload["semantic_context"])

    def test_invalid_candidate_is_rejected_before_additional_tool_calls(self):
        backend = _ContextBackend(invalid_id=True)
        counts = []
        original = producer._Attempt.tool_call
        with patch.object(producer._Attempt, "tool_call", autospec=True, side_effect=original) as reading:
            backend.observe = lambda request: counts.append(reading.call_count) if request.stage == "semantic_judge" else None
            outcome = self._run(backend)
            self.assertEqual(reading.call_count, counts[0])
        self.assertEqual([request.stage for request in backend.requests], ["plan", "semantic_judge"])
        self.assertEqual(outcome.deferred_outcome.reason_code, "invalid_context_request")
        self.assertIsNone(outcome.entry)
        self.assertEqual(outcome.production_outcomes, ())

    def test_repeated_request_stops_after_one_followup_without_more_reads(self):
        self._with_supplement()
        backend = _ContextBackend(repeat=True)
        counts = []
        original = producer._Attempt.tool_call
        with patch.object(producer._Attempt, "tool_call", autospec=True, side_effect=original) as reading:
            backend.observe = lambda request: counts.append(reading.call_count) if request.stage == "semantic_judge" else None
            outcome = self._run(backend)
            self.assertEqual(reading.call_count, counts[-1])
        self.assertEqual([request.stage for request in backend.requests],
                         ["plan", "semantic_judge", "semantic_judge"])
        self.assertEqual(outcome.deferred_outcome.reason_code, "context_followup_exhausted")
        self.assertIsNone(outcome.entry)
        self.assertEqual(len(outcome.deferred_outcome.model_calls), 3)

    def test_followup_cannot_exceed_existing_model_call_budget(self):
        self._with_supplement()
        for maximum in (2, 3):
            with self.subTest(maximum=maximum):
                backend = _ContextBackend()
                outcome = self._run(backend, limits=Limits(max_llm_calls=maximum, max_tool_calls=80))
                self.assertEqual(len(backend.requests), maximum)
                self.assertNotIn("reflection", [request.stage for request in backend.requests])
                self.assertIsNone(outcome.entry)
                self.assertEqual(outcome.deferred_outcome.reason_code, "budget_exceeded")
                self.assertEqual(outcome.state.budget["usage"]["llm_calls"], maximum)
                for event in outcome.state.budget["events"]:
                    self.assertLessEqual(event["usage_after"]["llm_calls"], maximum)
                    self.assertLessEqual(event["usage_after"]["tool_calls"], 80)

    def test_no_new_lines_defers_without_a_second_semantic_call(self):
        for blank_gap in (True, False):
            with self.subTest(blank_gap=blank_gap):
                if not blank_gap:
                    self._source_variant(no_gap=True)
                backend = _ContextBackend()
                outcome = self._run(backend)
                self.assertEqual([request.stage for request in backend.requests], ["plan", "semantic_judge"])
                self.assertEqual(outcome.deferred_outcome.reason_code, "context_followup_empty")
                self.assertIsNone(outcome.entry)

    def test_cli_flag_advertises_the_contract_without_adding_calls(self):
        backend = fixture.fixture._ScriptedBackend()
        stdout = io.StringIO()
        with patch.object(fixture.production, "load_backend_factory", return_value=backend), redirect_stdout(stdout):
            code = fixture.production.main(self.composition.cli_arguments() + ["--context-followup"])
        self.assertEqual(code, 0, stdout.getvalue())
        self.assertEqual(len(backend.requests), 3)
        self.assertIn("context_request_contract", backend.requests[1].payload)
        self.assertEqual(json.loads(stdout.getvalue())["entries_written"], 0)


if __name__ == "__main__":
    unittest.main()
