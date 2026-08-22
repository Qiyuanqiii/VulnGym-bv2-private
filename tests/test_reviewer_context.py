from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import vulngym_agent.orchestrator as orchestrator_api
from vulngym_agent.agents.model_runtime import ModelRequest
from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryCandidate,
    DiscoveryLocation,
    DiscoveryTaskInputV1,
)
from vulngym_agent.benchmark.producer_contracts import (
    ProducerArtifactDigestRefV1,
    ProducerDraftV1,
    ValidationReceiptV1,
)
from vulngym_agent.benchmark.reviewer_contracts import (
    REVIEWER_ARTIFACT_CATALOG_DIGEST_DOMAIN,
    REVIEWER_BUDGET_LEDGER_DIGEST_DOMAIN,
    REVIEWER_CONTEXT_DIGEST_DOMAIN,
    REVIEWER_CRITERIA,
    REVIEWER_MODEL_RECORD_DIGEST_DOMAIN,
    REVIEWER_SOURCE_LEDGER_DIGEST_DOMAIN,
    ReviewerCriterionV1,
    ReviewerEvidenceSelectionV1,
    ReviewerInputV1,
    reviewer_selection_digest_v1,
)
from vulngym_agent.benchmark.sealed_snapshot import prepare_sealed_snapshot
from vulngym_agent.benchmark.sealed_tree_access import BoundSealedTree, bind_sealed_tree
from vulngym_agent.orchestrator.budget import Budget, Limits
from vulngym_agent.orchestrator.contracts import canonical_json
from vulngym_agent.orchestrator.reviewer_context import (
    ReviewerContextBindingError,
    ReviewerContextFinalized,
    ReviewerContextLedgerMismatch,
    ReviewerContextLimitExceeded,
    ReviewerContextSession,
    reviewer_artifact_catalog_root_sha256,
    reviewer_budget_ledger_sha256,
    reviewer_context_sha256,
    reviewer_model_record_sha256,
    reviewer_source_ledger_sha256,
)
from vulngym_agent.tools.git.repository import GitRepository
from vulngym_agent.tools.runtime import ArtifactRef, AttemptToolRuntime, ToolArtifact


TASK_ID = "VG-TEST-0123456789ABCDEF0123"
REPO_URL = "https://github.com/example/reviewer-context"
KEY = b"reviewer context test attestation key 0001"
KEY_ID = "reviewer-context-test"
SOURCE_PATH = "src/app.py"
SOURCE_LINES = tuple(
    f"value_{index} = source_{index}(value_{index - 1})\n".encode("utf-8")
    for index in range(1, 41)
)
SOURCE = b"".join(SOURCE_LINES)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _domain(domain: bytes, value: object) -> str:
    return hashlib.sha256(
        domain + canonical_json(value).encode("utf-8")
    ).hexdigest()


class RecordingBackend:
    backend_id = "review-context-replay"
    model_id = "offline-review-v1"

    def __init__(self) -> None:
        self.requests: list[ModelRequest] = []

    def invoke(self, request: ModelRequest):
        self.requests.append(request)
        return {
            "reviews": [
                {
                    "candidate_id": context["candidate_id"],
                    "context_token": f"context-{index + 1}",
                    "criteria": [],
                }
                for index, context in enumerate(request.payload["contexts"])
            ]
        }


class ReviewerContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repo"
        self.repository.mkdir()
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.name", "VulnGym Test")
        self._git("config", "user.email", "vulngym@example.invalid")
        self._git("config", "core.autocrlf", "false")
        (self.repository / "src").mkdir()
        (self.repository / SOURCE_PATH).write_bytes(SOURCE)
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "source")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()
        self.snapshot_root = self.root / "sealed"
        prepared = prepare_sealed_snapshot(
            GitRepository(self.repository),
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=self.commit,
            output_dir=self.snapshot_root,
            attestation_key=KEY,
            key_id=KEY_ID,
        )
        self.task = DiscoveryTaskInputV1(
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=self.commit,
            instruction_id=INSTRUCTION_ID,
            snapshot_manifest_sha256=prepared.manifest_sha256,
            snapshot_content_root=prepared.content_root,
        )
        self.trees = []

    def tearDown(self) -> None:
        for tree in self.trees:
            try:
                if not tree.usage_snapshot().finalized:
                    tree.finalize()
            except Exception:
                pass
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _tree(self):
        tree = bind_sealed_tree(
            self.task,
            self.snapshot_root,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )
        self.trees.append(tree)
        return tree

    @staticmethod
    def _location(line: int) -> DiscoveryLocation:
        return DiscoveryLocation(
            file=SOURCE_PATH,
            line_start=line,
            line_end=line,
            code_sha256=hashlib.sha256(SOURCE_LINES[line - 1]).hexdigest(),
        )

    def _candidate(
        self,
        index: int = 1,
        *,
        trace_lines: tuple[int, ...] = (3,),
        wrong_digest: bool = False,
    ) -> DiscoveryCandidate:
        entry = self._location(1 + (index - 1) * 4)
        if wrong_digest:
            entry = DiscoveryLocation(
                file=entry.file,
                line_start=entry.line_start,
                line_end=entry.line_end,
                code_sha256="f" * 64,
            )
        critical = self._location(2 + (index - 1) * 4)
        return DiscoveryCandidate(
            task_id=self.task.task_id,
            snapshot_id=self.task.snapshot_id,
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            entry_point=entry,
            critical_operation=critical,
            trace=tuple(self._location(line) for line in trace_lines),
            relationship_evidence_refs=(
                f"ART-d2-link-{index:024x}",
            ),
            source_evidence_refs=(
                f"ART-d2-source-{index:024x}",
            ),
        )

    def _review_input(self, candidates: tuple[DiscoveryCandidate, ...]) -> ReviewerInputV1:
        receipts = []
        for index, candidate in enumerate(candidates, start=1):
            dependencies = tuple(
                ProducerArtifactDigestRefV1(
                    artifact_id=artifact_id,
                    artifact_sha256=_sha(f"dependency:{artifact_id}"),
                )
                for artifact_id in sorted(
                    (*candidate.source_evidence_refs, *candidate.relationship_evidence_refs)
                )
            )
            receipts.append(
                ValidationReceiptV1(
                    candidate_id=candidate.candidate_id,
                    candidate_sha256=candidate.candidate_sha256,
                    validation_artifact_id=f"ART-d2-validation-{index:024x}",
                    validation_artifact_sha256=_sha(f"validation:{index}"),
                    selection_digest=_sha(f"selection:{index}"),
                    dependencies=dependencies,
                )
            )
        return ReviewerInputV1(
            producer_draft=ProducerDraftV1(
                task=self.task,
                candidates=candidates,
                validation_receipts=tuple(receipts),
            )
        )

    def _session(self, review_input: ReviewerInputV1, *, tree=None, budget=None, backend=None):
        selected_tree = self._tree() if tree is None else tree
        selected_budget = (
            Budget(Limits(max_llm_calls=16, max_tool_calls=80))
            if budget is None
            else budget
        )
        selected_backend = RecordingBackend() if backend is None else backend
        session = ReviewerContextSession(
            review_input,
            selected_tree,
            selected_budget,
            selected_backend,
        )
        return session, selected_tree, selected_budget, selected_backend

    @staticmethod
    def _criteria(selection=None, *, assessment: str = "supported"):
        selections = () if selection is None else (selection,)
        return tuple(
            ReviewerCriterionV1(
                criterion=criterion,
                assessment=assessment,
                selections=selections,
            )
            for criterion in REVIEWER_CRITERIA
        )

    def test_public_api_exports_context_layer(self) -> None:
        self.assertIs(ReviewerContextSession, orchestrator_api.ReviewerContextSession)
        self.assertIs(
            REVIEWER_CONTEXT_DIGEST_DOMAIN,
            orchestrator_api.REVIEWER_CONTEXT_DIGEST_DOMAIN,
        )
        names = orchestrator_api.__all__
        self.assertEqual(len(names), len(set(names)))
        for name in (
            "ReviewerCandidateContext",
            "ReviewerContextSession",
            "ReviewerModelCall",
            "ReviewerValidationArtifact",
            "reviewer_context_sha256",
            "reviewer_model_record_sha256",
        ):
            self.assertIn(name, names)

    def test_available_context_is_fresh_complete_and_digest_bound(self) -> None:
        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        session, tree, budget, _ = self._session(review_input)
        context = session.build_candidate_context(candidate.candidate_id)
        self.assertEqual("available", context.context_status)
        self.assertIsNone(context.context_reason)
        self.assertEqual(3, len(context.nodes))
        self.assertEqual(
            {
                "candidate_location_count": 3,
                "complete": True,
                "fresh_location_count": 3,
                "unique_source_span_count": 3,
            },
            context.coverage,
        )
        unsigned = context.to_model_dict()
        observed = unsigned.pop("context_sha256")
        self.assertEqual(reviewer_context_sha256(unsigned), observed)
        self.assertEqual(_domain(REVIEWER_CONTEXT_DIGEST_DOMAIN, unsigned), observed)
        self.assertEqual(review_input.task_id, unsigned["task_id"])
        self.assertEqual(review_input.snapshot_id, unsigned["snapshot_id"])
        self.assertEqual(review_input.manifest_sha256, unsigned["manifest_sha256"])
        self.assertEqual(review_input.content_root, unsigned["content_root"])
        self.assertEqual(1, budget.usage.tool_calls)
        self.assertFalse(tree.usage_snapshot().finalized)
        self.assertIs(context, session.build_candidate_context(candidate.candidate_id))
        self.assertEqual(1, budget.usage.tool_calls)
        session.abort()

    def test_model_validation_and_attempt_seal_close_exact_runtime(self) -> None:
        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        session, tree, budget, backend = self._session(review_input)
        context = session.build_candidate_context(candidate.candidate_id)
        model_call = session.call_model(
            "MODEL-D3-REVIEW-0001",
            (context,),
            {"response_contract": "criteria-only-v1"},
        )
        self.assertEqual(1, len(backend.requests))
        self.assertEqual(
            reviewer_model_record_sha256(model_call.record),
            model_call.record_sha256,
        )
        self.assertEqual(
            _domain(
                REVIEWER_MODEL_RECORD_DIGEST_DOMAIN,
                {"record": model_call.record.to_dict()},
            ),
            model_call.record_sha256,
        )
        selection = context.nodes[0].to_selection()
        criteria = self._criteria(selection)
        validation = session.issue_validation(
            context,
            criteria,
            model_record_sha256=model_call.record_sha256,
        )
        payload = validation.artifact.payload
        self.assertEqual("accept", payload["decision"])
        self.assertEqual("available", payload["context_status"])
        self.assertEqual(context.coverage, dict(payload["coverage"]))
        self.assertEqual(
            reviewer_selection_digest_v1(
                candidate_id=candidate.candidate_id,
                candidate_sha256=candidate.candidate_sha256,
                context_sha256=context.context_sha256,
                criteria=criteria,
                review_input_sha256=review_input.review_input_sha256,
            ),
            payload["selection_digest"],
        )
        seal = session.finalize(
            used_artifacts=(
                context.nodes[0].artifact_ref,
                validation.artifact_ref,
            ),
            used_model_records=(model_call.record_sha256,),
        )
        self.assertEqual((2, 1, 3), (
            seal.tool_record_count,
            seal.model_record_count,
            seal.budget_event_count,
        ))
        self.assertEqual(2, seal.artifact_count)
        self.assertEqual(1, seal.source_read_count)
        self.assertEqual(reviewer_budget_ledger_sha256(budget), seal.budget_ledger_sha256)
        self.assertEqual(
            _domain(REVIEWER_BUDGET_LEDGER_DIGEST_DOMAIN, {"budget": budget.to_dict()}),
            seal.budget_ledger_sha256,
        )
        source_ledger = tree.usage_snapshot()
        self.assertTrue(source_ledger.finalized)
        self.assertTrue(source_ledger.verification_succeeded)
        self.assertEqual(
            reviewer_source_ledger_sha256(source_ledger),
            seal.source_ledger_sha256,
        )
        self.assertEqual(
            _domain(
                REVIEWER_SOURCE_LEDGER_DIGEST_DOMAIN,
                {"ledger": source_ledger.to_dict()},
            ),
            seal.source_ledger_sha256,
        )
        self.assertIs(seal, session.finalize(
            used_artifacts=(),
            used_model_records=(),
        ))
        with self.assertRaises(ReviewerContextFinalized):
            session.build_candidate_context(candidate.candidate_id)

    def test_local_location_limit_yields_finalizable_unavailable_context(self) -> None:
        candidate = self._candidate(trace_lines=tuple(range(3, 18)))
        review_input = self._review_input((candidate,))
        session, tree, budget, _ = self._session(review_input)
        context = session.build_candidate_context(candidate.candidate_id)
        self.assertEqual("unavailable", context.context_status)
        self.assertEqual("context.location_limit", context.context_reason)
        self.assertEqual((), context.nodes)
        self.assertFalse(context.coverage["complete"])
        self.assertEqual(0, budget.usage.tool_calls)
        criteria = self._criteria(assessment="insufficient")
        validation = session.issue_validation(
            context,
            criteria,
            model_record_sha256=None,
        )
        payload = validation.artifact.payload
        self.assertEqual("defer", payload["decision"])
        self.assertEqual("unavailable", payload["context_status"])
        self.assertEqual([], list(payload["evidence"]))
        seal = session.finalize(
            used_artifacts=(validation.artifact_ref,),
            used_model_records=(),
        )
        self.assertEqual((1, 0, 1, 0), (
            seal.tool_record_count,
            seal.model_record_count,
            seal.artifact_count,
            seal.source_read_count,
        ))
        self.assertTrue(tree.usage_snapshot().verification_succeeded)

    def test_unavailable_context_rejects_model_and_conclusive_validation(self) -> None:
        candidate = self._candidate(trace_lines=tuple(range(3, 18)))
        review_input = self._review_input((candidate,))
        session, _, budget, _ = self._session(review_input)
        context = session.build_candidate_context(candidate.candidate_id)
        with self.assertRaises(ReviewerContextBindingError):
            session.call_model("MODEL-D3-REVIEW-0001", (context,), {})
        self.assertEqual(0, budget.usage.llm_calls)
        fabricated = ReviewerEvidenceSelectionV1(
            artifact_id="ART-fabricated-000000000000000000000001",
            artifact_sha256="a" * 64,
            node_id="LOC-fabricated-000000000000000000000001",
        )
        with self.assertRaises(ReviewerContextBindingError):
            session.issue_validation(
                context,
                self._criteria(fabricated),
                model_record_sha256="b" * 64,
            )
        session.abort()

    def test_wrong_candidate_location_digest_fails_and_can_only_abort(self) -> None:
        candidate = self._candidate(wrong_digest=True)
        review_input = self._review_input((candidate,))
        session, tree, budget, _ = self._session(review_input)
        with self.assertRaises(ReviewerContextBindingError):
            session.build_candidate_context(candidate.candidate_id)
        self.assertEqual(1, budget.usage.tool_calls)
        session.abort()
        self.assertTrue(tree.usage_snapshot().finalized)
        self.assertFalse(tree.usage_snapshot().verification_succeeded)
        with self.assertRaises(ReviewerContextFinalized):
            session.build_candidate_context(candidate.candidate_id)

    def test_constructor_requires_fresh_budget_without_claiming_tree(self) -> None:
        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        tree = self._tree()
        budget = Budget(Limits(max_llm_calls=16, max_tool_calls=80))
        budget.charge_tool_call(operation="preexisting")
        with self.assertRaises(ValueError):
            ReviewerContextSession(review_input, tree, budget, RecordingBackend())
        self.assertFalse(tree.usage_snapshot().finalized)
        session, _, _, _ = self._session(review_input, tree=tree)
        session.abort()

    def test_constructor_claim_window_aborts_the_tree(self) -> None:
        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        tree = self._tree()
        budget = Budget(Limits(max_llm_calls=16, max_tool_calls=80))
        original_claim = BoundSealedTree._claim_for_discovery

        def interrupt_after_claim(bound_tree: BoundSealedTree, token: object) -> None:
            original_claim(bound_tree, token)
            raise KeyboardInterrupt()

        with mock.patch.object(
            BoundSealedTree,
            "_claim_for_discovery",
            autospec=True,
            side_effect=interrupt_after_claim,
        ):
            with self.assertRaises(KeyboardInterrupt):
                ReviewerContextSession(review_input, tree, budget, RecordingBackend())
        usage = tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)

    def test_constructor_post_claim_window_closes_every_capability(self) -> None:
        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        tree = self._tree()
        budget = Budget(Limits(max_llm_calls=16, max_tool_calls=80))
        with mock.patch(
            "vulngym_agent.orchestrator.reviewer_context.canonical_sha256",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                ReviewerContextSession(review_input, tree, budget, RecordingBackend())
        usage = tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)

    def test_same_tree_cannot_back_two_sessions(self) -> None:
        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        tree = self._tree()
        first, _, _, _ = self._session(review_input, tree=tree)
        with self.assertRaises(Exception):
            self._session(review_input, tree=tree)
        self.assertFalse(tree.usage_snapshot().finalized)
        first.abort()

    def test_reconstructed_equal_ref_is_rejected_and_failure_is_stable(self) -> None:
        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        session, tree, _, _ = self._session(review_input)
        context = session.build_candidate_context(candidate.candidate_id)
        issued = context.nodes[0].artifact_ref
        reconstructed = ArtifactRef(**issued.to_dict())
        with self.assertRaises(ReviewerContextLedgerMismatch) as first:
            session.finalize(
                used_artifacts=(reconstructed,),
                used_model_records=(),
            )
        with self.assertRaises(ReviewerContextLedgerMismatch) as second:
            session.finalize(used_artifacts=(), used_model_records=())
        self.assertIs(first.exception, second.exception)
        self.assertTrue(tree.usage_snapshot().finalized)

    def test_unowned_budget_event_breaks_exact_closure(self) -> None:
        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        session, tree, budget, _ = self._session(review_input)
        session.build_candidate_context(candidate.candidate_id)
        budget.charge_tool_call(operation="unowned")
        with self.assertRaises(ReviewerContextLedgerMismatch):
            session.finalize(used_artifacts=(), used_model_records=())
        self.assertTrue(tree.usage_snapshot().finalized)

    def test_oversized_controller_request_is_rejected_before_charge(self) -> None:
        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        session, _, budget, _ = self._session(review_input)
        context = session.build_candidate_context(candidate.candidate_id)
        before = budget.events
        with self.assertRaises(ReviewerContextLimitExceeded):
            session.call_model(
                "MODEL-D3-REVIEW-0001",
                (context,),
                {"padding": "x" * (65 * 1024)},
            )
        self.assertEqual(before, budget.events)
        session.abort()

    def test_model_response_cannot_supply_decision_or_integrity_fields(self) -> None:
        class InvalidProjectionBackend(RecordingBackend):
            def invoke(self, request: ModelRequest):
                self.requests.append(request)
                return {
                    "candidate_id": request.payload["contexts"][0]["candidate_id"],
                    "decision": "accept",
                    "selection_digest": "a" * 64,
                }

        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        backend = InvalidProjectionBackend()
        session, _, budget, _ = self._session(review_input, backend=backend)
        context = session.build_candidate_context(candidate.candidate_id)
        with self.assertRaises(ReviewerContextBindingError):
            session.call_model("MODEL-D3-REVIEW-0001", (context,), {})
        self.assertEqual(1, budget.usage.llm_calls)
        session.abort()

    def test_two_contexts_share_one_exact_model_record(self) -> None:
        first = self._candidate(index=1, trace_lines=(3,))
        second = self._candidate(index=2, trace_lines=(7,))
        review_input = self._review_input((first, second))
        session, _, _, _ = self._session(review_input)
        first_context = session.build_candidate_context(first.candidate_id)
        second_context = session.build_candidate_context(second.candidate_id)
        model_call = session.call_model(
            "MODEL-D3-REVIEW-BATCH-0001",
            (first_context, second_context),
            {"response_contract": "criteria-only-v1"},
        )
        validations = []
        for context in (first_context, second_context):
            criteria = self._criteria(context.nodes[0].to_selection())
            validations.append(
                session.issue_validation(
                    context,
                    criteria,
                    model_record_sha256=model_call.record_sha256,
                )
            )
        seal = session.finalize(
            used_artifacts=(
                first_context.nodes[0].artifact_ref,
                second_context.nodes[0].artifact_ref,
                validations[0].artifact_ref,
                validations[1].artifact_ref,
            ),
            used_model_records=(model_call.record_sha256,),
        )
        self.assertEqual((4, 1, 4, 1), (
            seal.tool_record_count,
            seal.model_record_count,
            seal.artifact_count,
            len(seal.used_model_records),
        ))

    def test_mutated_issued_context_is_rejected_before_model_charge(self) -> None:
        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        session, _, budget, _ = self._session(review_input)
        context = session.build_candidate_context(candidate.candidate_id)
        object.__setattr__(context, "candidate_sha256", "0" * 64)
        before = budget.events
        with self.assertRaises(ReviewerContextBindingError):
            session.call_model("MODEL-D3-REVIEW-0001", (context,), {})
        self.assertEqual(before, budget.events)
        session.abort()

    def test_zero_candidate_attempt_closes_without_calls(self) -> None:
        review_input = self._review_input(())
        session, tree, budget, _ = self._session(review_input)
        seal = session.finalize(used_artifacts=(), used_model_records=())
        self.assertEqual((0, 0, 0, 0, 0), (
            seal.tool_record_count,
            seal.model_record_count,
            seal.artifact_count,
            seal.budget_event_count,
            seal.source_read_count,
        ))
        self.assertEqual((), budget.events)
        usage = tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertTrue(usage.verification_succeeded)

    def test_keyboard_interrupt_one_way_aborts_every_capability(self) -> None:
        candidate = self._candidate()
        review_input = self._review_input((candidate,))
        session, tree, _, _ = self._session(review_input)
        with mock.patch.object(
            AttemptToolRuntime,
            "call",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                session.build_candidate_context(candidate.candidate_id)
        self.assertTrue(session.sealed)
        usage = tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)
        session.abort()
        with self.assertRaises(ReviewerContextFinalized):
            session.build_candidate_context(candidate.candidate_id)

    def test_catalog_digest_algorithm_is_domain_separated_and_order_independent(self) -> None:
        first = ToolArtifact(
            task_id=TASK_ID,
            attempt=0,
            policy_scope="d3.review",
            tool_call_id="TOOL-D3-CATALOG-0001",
            artifact_id="ART-review-context-000000000000000000000001",
            kind="review.context",
            payload={"value": 1},
        )
        second = ToolArtifact(
            task_id=TASK_ID,
            attempt=0,
            policy_scope="d3.review",
            tool_call_id="TOOL-D3-CATALOG-0002",
            artifact_id="ART-review-context-000000000000000000000002",
            kind="review.context",
            payload={"value": 2},
        )
        rows = [
            {
                "artifact_id": item.artifact_id,
                "artifact_sha256": item.artifact_sha256,
                "kind": item.kind,
                "payload_sha256": item.payload_sha256,
                "tool_call_id": item.tool_call_id,
            }
            for item in (first, second)
        ]
        expected = _domain(
            REVIEWER_ARTIFACT_CATALOG_DIGEST_DOMAIN,
            {"artifacts": rows},
        )
        self.assertEqual(
            expected,
            reviewer_artifact_catalog_root_sha256((second, first)),
        )


if __name__ == "__main__":
    unittest.main()
