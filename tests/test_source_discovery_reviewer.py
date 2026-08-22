from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import vulngym_agent.agents as agents_api
from vulngym_agent.agents.model_runtime import (
    AttemptModelRuntime,
    ModelBlocked,
    ModelRequest,
)
from vulngym_agent.agents.source_discovery_reviewer import (
    SourceDiscoveryReviewerController,
)
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
    REVIEWER_CRITERIA,
    ReviewerDeferredV1,
    ReviewerFinalizedV1,
    ReviewerInputV1,
)
from vulngym_agent.benchmark.reviewer_projection import project_reviewer_result_v1
from vulngym_agent.benchmark.sealed_snapshot import prepare_sealed_snapshot
from vulngym_agent.benchmark.sealed_tree_access import bind_sealed_tree
from vulngym_agent.orchestrator.budget import Budget, Limits
from vulngym_agent.orchestrator.reviewer_context import ReviewerContextSession
from vulngym_agent.tools.git.repository import GitRepository
from vulngym_agent.tools.runtime import AttemptToolRuntime


TASK_ID = "VG-TRAIN-0123456789ABCDEF0789"
REPO_URL = "https://github.com/example/source-discovery-reviewer"
KEY = b"source discovery reviewer test key 0001"
KEY_ID = "source-discovery-reviewer-test"
SOURCE_PATH = "src/app.py"
SOURCE = (
    b"def critical(value):\n"
    b"    return evaluate(value)\n"
    b"def entry(value):\n"
    b"    return critical(value)\n"
    + b"".join(
        f"context line {line:02d}\n".encode("ascii") for line in range(5, 21)
    )
)


def _sha(value: bytes | str) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _artifact(label: str, index: int) -> str:
    return f"ART-{label}-{index:024x}"


class ScriptedReviewerBackend:
    backend_id = "reviewer-scripted"
    model_id = "offline-d3-v1"

    def __init__(self, mode: str = "accept") -> None:
        self.mode = mode
        self.requests: list[ModelRequest] = []

    @staticmethod
    def _node(context, role: str):
        nodes = tuple(context["nodes"])
        if role == "trace_continuity":
            return next(
                (item for item in nodes if item["role"].startswith("trace.")),
                nodes[0],
            )
        wanted = "entry_role" if role == "entry_role" else "critical_role"
        return next(item for item in nodes if item["role"] == wanted)

    def invoke(self, request: ModelRequest):
        self.requests.append(request)
        if self.mode == "interrupt":
            raise KeyboardInterrupt()
        if self.mode == "blocked":
            raise ModelBlocked("fixture_blocked")

        reviews = []
        for context in request.payload["contexts"]:
            criteria = []
            for criterion in REVIEWER_CRITERIA:
                assessment = "supported"
                if self.mode == "reject" and criterion == "critical_role":
                    assessment = "contradicted"
                elif self.mode == "mixed" and criterion == "trace_continuity":
                    assessment = "insufficient"
                elif self.mode == "all_insufficient":
                    assessment = "insufficient"
                selections = []
                if assessment != "insufficient":
                    node = self._node(context, criterion)
                    selections = [
                        {
                            "artifact_id": node["artifact_id"],
                            "node_id": node["node_id"],
                        }
                    ]
                criteria.append(
                    {
                        "assessment": assessment,
                        "criterion": criterion,
                        "selections": selections,
                    }
                )
            reviews.append(
                {
                    "candidate_id": context["candidate_id"],
                    "criteria": criteria,
                }
            )
        if self.mode == "invalid_extra":
            reviews[0]["decision"] = "accept"
        if self.mode == "forged":
            reviews[0]["criteria"][0]["selections"][0]["node_id"] = (
                "LOC-forged-review-node"
            )
        if self.mode == "missing_reviews":
            return {}
        if self.mode == "wrong_reviews_type":
            return {"reviews": {}}
        if self.mode == "wrong_review_count":
            return {"reviews": []}
        if self.mode == "wrong_criteria_order":
            reviews[0]["criteria"].reverse()
        if self.mode == "unknown_assessment":
            reviews[0]["criteria"][0]["assessment"] = "unknown"
        if self.mode == "conclusive_without_selection":
            reviews[0]["criteria"][0]["selections"] = []
        if self.mode == "insufficient_with_selection":
            reviews[0]["criteria"][0]["assessment"] = "insufficient"
        if self.mode == "mixed_batch_provenance":
            for criterion in reviews[-1]["criteria"]:
                criterion["assessment"] = "insufficient"
                criterion["selections"] = []
        return {"reviews": reviews}


class SourceDiscoveryReviewerTests(unittest.TestCase):
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

    def tearDown(self) -> None:
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

    def _candidate(self, index: int, *, wrong_digest: bool = False) -> DiscoveryCandidate:
        lines = SOURCE.splitlines(keepends=True)
        if index == 1:
            entry_line, critical_line, trace_line = 3, 2, 4
        else:
            entry_line, critical_line, trace_line = 1, 4, 2

        def location(line: int) -> DiscoveryLocation:
            digest = "f" * 64 if wrong_digest and line == entry_line else _sha(lines[line - 1])
            return DiscoveryLocation(
                file=SOURCE_PATH,
                line_start=line,
                line_end=line,
                code_sha256=digest,
            )

        return DiscoveryCandidate(
            task_id=self.task.task_id,
            snapshot_id=self.task.snapshot_id,
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            entry_point=location(entry_line),
            critical_operation=location(critical_line),
            trace=(location(trace_line),),
            source_evidence_refs=(_artifact("d2-source", index),),
            relationship_evidence_refs=(_artifact("d2-link", index),),
        )

    @staticmethod
    def _receipt(candidate: DiscoveryCandidate, index: int) -> ValidationReceiptV1:
        dependencies = tuple(
            ProducerArtifactDigestRefV1(
                artifact_id=artifact_id,
                artifact_sha256=_sha(f"d2:{artifact_id}"),
            )
            for artifact_id in sorted(
                (*candidate.source_evidence_refs, *candidate.relationship_evidence_refs)
            )
        )
        return ValidationReceiptV1(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            validation_artifact_id=_artifact("d2-validation", index),
            validation_artifact_sha256=_sha(f"d2-validation:{index}"),
            selection_digest=_sha(f"d2-selection:{index}"),
            dependencies=dependencies,
        )

    def _input(self, count: int = 1, *, wrong_digest: bool = False) -> ReviewerInputV1:
        candidates = tuple(
            self._candidate(index + 1, wrong_digest=wrong_digest)
            for index in range(count)
        )
        draft = ProducerDraftV1(
            task=self.task,
            candidates=candidates,
            validation_receipts=tuple(
                self._receipt(candidate, index + 1)
                for index, candidate in enumerate(candidates)
            ),
        )
        return ReviewerInputV1(producer_draft=draft)

    def _overflow_input(self) -> ReviewerInputV1:
        lines = SOURCE.splitlines(keepends=True)

        def location(line: int) -> DiscoveryLocation:
            return DiscoveryLocation(
                file=SOURCE_PATH,
                line_start=line,
                line_end=line,
                code_sha256=_sha(lines[line - 1]),
            )

        candidate = DiscoveryCandidate(
            task_id=self.task.task_id,
            snapshot_id=self.task.snapshot_id,
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            entry_point=location(1),
            critical_operation=location(2),
            trace=tuple(location(line) for line in range(3, 20)),
            source_evidence_refs=(_artifact("d2-overflow-source", 1),),
            relationship_evidence_refs=(_artifact("d2-overflow-link", 1),),
        )
        return ReviewerInputV1(
            producer_draft=ProducerDraftV1(
                task=self.task,
                candidates=(candidate,),
                validation_receipts=(self._receipt(candidate, 1),),
            )
        )

    def _boundary_input(self) -> ReviewerInputV1:
        lines = SOURCE.splitlines(keepends=True)

        def location(line: int) -> DiscoveryLocation:
            return DiscoveryLocation(
                file=SOURCE_PATH,
                line_start=line,
                line_end=line,
                code_sha256=_sha(lines[line - 1]),
            )

        candidates = []
        for offset in range(32):
            entry_line = offset % 16 + 1
            critical_line = 17 + offset // 16
            trace_line = 19 + offset % 2
            candidates.append(
                DiscoveryCandidate(
                    task_id=self.task.task_id,
                    snapshot_id=self.task.snapshot_id,
                    repo_url=self.task.repo_url,
                    commit=self.task.commit,
                    entry_point=location(entry_line),
                    critical_operation=location(critical_line),
                    trace=(location(trace_line),),
                    source_evidence_refs=(
                        _artifact("d2-boundary-source", 1),
                    ),
                    relationship_evidence_refs=(
                        _artifact("d2-boundary-link", 1),
                    ),
                )
            )
        return ReviewerInputV1(
            producer_draft=ProducerDraftV1(
                task=self.task,
                candidates=tuple(candidates),
                validation_receipts=tuple(
                    self._receipt(candidate, index + 1)
                    for index, candidate in enumerate(candidates)
                ),
            )
        )

    def _tree(self):
        return bind_sealed_tree(
            self.task,
            self.snapshot_root,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )

    def _custom_task_and_tree(self, label: str, source: bytes):
        repository = self.root / f"repo-{label}"
        repository.mkdir()
        subprocess.run(
            ["git", "init", "-q", "-b", "main"],
            cwd=repository,
            check=True,
        )
        for key, value in (
            ("user.name", "VulnGym Test"),
            ("user.email", "vulngym@example.invalid"),
            ("core.autocrlf", "false"),
        ):
            subprocess.run(
                ["git", "config", key, value],
                cwd=repository,
                check=True,
            )
        path = "src/limit.py"
        (repository / "src").mkdir()
        (repository / path).write_bytes(source)
        subprocess.run(["git", "add", "-A"], cwd=repository, check=True)
        subprocess.run(
            ["git", "commit", "-q", "-m", "source"],
            cwd=repository,
            check=True,
        )
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        task_id = "VG-TEST-" + hashlib.sha256(label.encode("utf-8")).hexdigest()[:20].upper()
        repo_url = f"https://github.com/example/reviewer-{label}"
        snapshot_root = self.root / f"sealed-{label}"
        prepared = prepare_sealed_snapshot(
            GitRepository(repository),
            task_id=task_id,
            repo_url=repo_url,
            commit=commit,
            output_dir=snapshot_root,
            attestation_key=KEY,
            key_id=KEY_ID,
        )
        task = DiscoveryTaskInputV1(
            task_id=task_id,
            repo_url=repo_url,
            commit=commit,
            instruction_id=INSTRUCTION_ID,
            snapshot_manifest_sha256=prepared.manifest_sha256,
            snapshot_content_root=prepared.content_root,
        )
        tree = bind_sealed_tree(
            task,
            snapshot_root,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )
        return task, tree, path

    @staticmethod
    def _budget() -> Budget:
        return Budget(
            Limits(
                max_llm_calls=16,
                max_tool_calls=80,
                max_repair_iterations=0,
            )
        )

    def _run(self, mode: str = "accept", *, count: int = 1, wrong_digest: bool = False):
        backend = ScriptedReviewerBackend(mode)
        tree = self._tree()
        controller = SourceDiscoveryReviewerController(
            self._input(count, wrong_digest=wrong_digest),
            tree,
            self._budget(),
            backend,
        )
        return controller.run(), backend, tree, controller

    def test_public_agents_package_exports_reviewer(self) -> None:
        self.assertIs(
            agents_api.SourceDiscoveryReviewerController,
            SourceDiscoveryReviewerController,
        )

    def test_accept_path_is_fresh_closed_and_projects_to_one_finding(self) -> None:
        result, backend, tree, controller = self._run()
        self.assertIs(type(result), ReviewerFinalizedV1)
        assert isinstance(result, ReviewerFinalizedV1)
        self.assertIs(result, controller.run())
        self.assertEqual("accept", result.verdicts[0].decision)
        self.assertEqual(2, result.attempt_seal.tool_record_count)
        self.assertEqual(1, result.attempt_seal.model_record_count)
        self.assertEqual(2, result.attempt_seal.artifact_count)
        self.assertEqual(2, len(result.attempt_seal.used_artifacts))
        self.assertEqual(1, len(result.attempt_seal.used_model_records))
        self.assertTrue(tree.usage_snapshot().verification_succeeded)
        self.assertEqual(1, len(project_reviewer_result_v1(result).emitted_candidates))

        payload = json.dumps(
            backend.requests[0].to_dict()["payload"],
            ensure_ascii=False,
            sort_keys=True,
        )
        draft = result.review_input.producer_draft
        for receipt in draft.validation_receipts:
            self.assertNotIn(receipt.validation_artifact_id, payload)
            self.assertNotIn(receipt.validation_artifact_sha256, payload)
            self.assertNotIn(receipt.selection_digest, payload)
            for dependency in receipt.dependencies:
                self.assertNotIn(dependency.artifact_id, payload)
                self.assertNotIn(dependency.artifact_sha256, payload)
        for forbidden_name in (
            "relationship_evidence_refs",
            "source_evidence_refs",
            "validation_receipts",
        ):
            self.assertNotIn(forbidden_name, payload)
        self.assertNotIn("def entry", result.to_wire().decode("utf-8"))

    def test_two_candidates_share_one_batch_model_record(self) -> None:
        result, backend, _, _ = self._run(count=2)
        self.assertIs(type(result), ReviewerFinalizedV1)
        assert isinstance(result, ReviewerFinalizedV1)
        self.assertEqual(1, len(backend.requests))
        self.assertEqual(1, result.attempt_seal.model_record_count)
        self.assertEqual(4, result.attempt_seal.artifact_count)
        self.assertEqual(
            1,
            len({item.model_record_sha256 for item in result.verdicts}),
        )

    def test_decision_is_derived_for_reject_mixed_and_all_insufficient(self) -> None:
        for mode, expected in (
            ("reject", "reject"),
            ("mixed", "defer"),
            ("all_insufficient", "defer"),
        ):
            with self.subTest(mode=mode):
                result, _, _, _ = self._run(mode)
                self.assertIs(type(result), ReviewerFinalizedV1)
                assert isinstance(result, ReviewerFinalizedV1)
                verdict = result.verdicts[0]
                self.assertEqual(expected, verdict.decision)
                if mode == "all_insufficient":
                    self.assertIsNotNone(verdict.model_record_sha256)
                    self.assertEqual(
                        (verdict.model_record_sha256,),
                        result.attempt_seal.used_model_records,
                    )
                    self.assertEqual(1, result.attempt_seal.model_record_count)

    def test_mixed_batch_all_insufficient_candidate_keeps_shared_model_record(self) -> None:
        result, _, _, _ = self._run("mixed_batch_provenance", count=2)
        self.assertIs(type(result), ReviewerFinalizedV1)
        assert isinstance(result, ReviewerFinalizedV1)
        self.assertEqual(
            1,
            len({item.model_record_sha256 for item in result.verdicts}),
        )
        self.assertTrue(
            all(item.model_record_sha256 is not None for item in result.verdicts)
        )
        self.assertEqual(
            (result.verdicts[0].model_record_sha256,),
            result.attempt_seal.used_model_records,
        )

    def test_invalid_or_forged_model_response_defers_without_partial_verdicts(self) -> None:
        for mode, reason in (
            ("invalid_extra", "runtime.model_failed"),
            ("forged", "runtime.model_failed"),
            ("blocked", "runtime.model_failed"),
        ):
            with self.subTest(mode=mode):
                result, _, tree, _ = self._run(mode)
                self.assertIs(type(result), ReviewerDeferredV1)
                assert isinstance(result, ReviewerDeferredV1)
                self.assertEqual(reason, result.reason_code)
                self.assertIsNotNone(result.attempt_seal)
                self.assertTrue(tree.usage_snapshot().finalized)

    def test_malformed_model_response_taxonomy_is_consistently_model_failed(self) -> None:
        for mode in (
            "missing_reviews",
            "wrong_reviews_type",
            "wrong_review_count",
            "wrong_criteria_order",
            "unknown_assessment",
            "conclusive_without_selection",
            "insufficient_with_selection",
        ):
            with self.subTest(mode=mode):
                result, _, tree, _ = self._run(mode)
                self.assertIs(type(result), ReviewerDeferredV1)
                assert isinstance(result, ReviewerDeferredV1)
                self.assertEqual("runtime.model_failed", result.reason_code)
                self.assertEqual((), result.attempt_seal.used_artifacts)  # type: ignore[union-attr]
                self.assertTrue(tree.usage_snapshot().finalized)

    def test_fresh_source_mismatch_defers_and_closes_source(self) -> None:
        result, _, tree, _ = self._run(wrong_digest=True)
        self.assertIs(type(result), ReviewerDeferredV1)
        assert isinstance(result, ReviewerDeferredV1)
        self.assertEqual("runtime.source_failed", result.reason_code)
        self.assertEqual((), result.attempt_seal.used_artifacts)  # type: ignore[union-attr]
        self.assertTrue(tree.usage_snapshot().verification_succeeded)

    def test_zero_candidates_finalize_without_calls(self) -> None:
        result, backend, tree, _ = self._run(count=0)
        self.assertIs(type(result), ReviewerFinalizedV1)
        assert isinstance(result, ReviewerFinalizedV1)
        self.assertEqual((), result.verdicts)
        self.assertEqual(0, result.attempt_seal.tool_record_count)
        self.assertEqual(0, result.attempt_seal.model_record_count)
        self.assertEqual(0, result.attempt_seal.budget_event_count)
        self.assertEqual([], backend.requests)
        self.assertTrue(tree.usage_snapshot().verification_succeeded)

    def test_local_context_limit_becomes_candidate_level_insufficient(self) -> None:
        backend = ScriptedReviewerBackend()
        tree = self._tree()
        result = SourceDiscoveryReviewerController(
            self._overflow_input(), tree, self._budget(), backend
        ).run()
        self.assertIs(type(result), ReviewerFinalizedV1)
        assert isinstance(result, ReviewerFinalizedV1)
        self.assertEqual("defer", result.verdicts[0].decision)
        self.assertTrue(
            all(
                item.assessment == "insufficient"
                for item in result.verdicts[0].criteria
            )
        )
        self.assertEqual([], backend.requests)
        self.assertEqual(1, result.attempt_seal.tool_record_count)
        self.assertEqual(0, result.attempt_seal.model_record_count)
        self.assertEqual(0, result.attempt_seal.source_read_count)
        self.assertEqual(1, result.attempt_seal.artifact_count)

    def test_source_size_limits_become_candidate_level_unavailable(self) -> None:
        cases = (
            ("file-limit", b"ok\n" + b"x" * (1024 * 1024), 0),
            ("span-limit", b"x" * (64 * 1024) + b"\n", 1),
        )
        for label, source, expected_reads in cases:
            with self.subTest(label=label):
                task, tree, path = self._custom_task_and_tree(label, source)
                first_line = source.splitlines(keepends=True)[0]
                location = DiscoveryLocation(
                    file=path,
                    line_start=1,
                    line_end=1,
                    code_sha256=_sha(first_line),
                )
                candidate = DiscoveryCandidate(
                    task_id=task.task_id,
                    snapshot_id=task.snapshot_id,
                    repo_url=task.repo_url,
                    commit=task.commit,
                    entry_point=location,
                    critical_operation=location,
                    trace=(location,),
                    source_evidence_refs=(_artifact("d2-limit-source", 1),),
                    relationship_evidence_refs=(_artifact("d2-limit-link", 1),),
                )
                review_input = ReviewerInputV1(
                    producer_draft=ProducerDraftV1(
                        task=task,
                        candidates=(candidate,),
                        validation_receipts=(self._receipt(candidate, 1),),
                    )
                )
                backend = ScriptedReviewerBackend()
                result = SourceDiscoveryReviewerController(
                    review_input, tree, self._budget(), backend
                ).run()
                self.assertIs(type(result), ReviewerFinalizedV1)
                assert isinstance(result, ReviewerFinalizedV1)
                self.assertEqual("defer", result.verdicts[0].decision)
                self.assertIsNone(result.verdicts[0].model_record_sha256)
                self.assertEqual([], backend.requests)
                self.assertEqual(2, result.attempt_seal.tool_record_count)
                self.assertEqual(1, result.attempt_seal.artifact_count)
                self.assertEqual(expected_reads, result.attempt_seal.source_read_count)

    def test_non_capacity_source_block_remains_a_closed_task_failure(self) -> None:
        source = b"\xff\n"
        task, tree, path = self._custom_task_and_tree("non-text", source)
        location = DiscoveryLocation(
            file=path,
            line_start=1,
            line_end=1,
            code_sha256=_sha(source),
        )
        candidate = DiscoveryCandidate(
            task_id=task.task_id,
            snapshot_id=task.snapshot_id,
            repo_url=task.repo_url,
            commit=task.commit,
            entry_point=location,
            critical_operation=location,
            trace=(location,),
            source_evidence_refs=(_artifact("d2-non-text-source", 1),),
            relationship_evidence_refs=(_artifact("d2-non-text-link", 1),),
        )
        review_input = ReviewerInputV1(
            producer_draft=ProducerDraftV1(
                task=task,
                candidates=(candidate,),
                validation_receipts=(self._receipt(candidate, 1),),
            )
        )
        backend = ScriptedReviewerBackend()
        result = SourceDiscoveryReviewerController(
            review_input, tree, self._budget(), backend
        ).run()
        self.assertIs(type(result), ReviewerDeferredV1)
        assert isinstance(result, ReviewerDeferredV1)
        self.assertEqual("runtime.source_failed", result.reason_code)
        self.assertEqual([], backend.requests)
        self.assertIsNotNone(result.attempt_seal)
        self.assertEqual(1, result.attempt_seal.tool_record_count)  # type: ignore[union-attr]
        self.assertEqual(0, result.attempt_seal.artifact_count)  # type: ignore[union-attr]
        self.assertEqual(1, result.attempt_seal.source_read_count)  # type: ignore[union-attr]

    def test_cumulative_source_artifact_budget_degrades_remaining_candidates(self) -> None:
        line_bytes = 50 * 1024
        source_lines = tuple(
            bytes([65 + index]) * (line_bytes - 1) + b"\n"
            for index in range(6)
        )
        task, tree, path = self._custom_task_and_tree(
            "cumulative-limit", b"".join(source_lines)
        )

        def location(line: int) -> DiscoveryLocation:
            return DiscoveryLocation(
                file=path,
                line_start=line,
                line_end=line,
                code_sha256=_sha(source_lines[line - 1]),
            )

        endpoint_pairs = tuple(itertools.permutations(range(1, 7), 2))[:24]
        candidates = tuple(
            DiscoveryCandidate(
                task_id=task.task_id,
                snapshot_id=task.snapshot_id,
                repo_url=task.repo_url,
                commit=task.commit,
                entry_point=location(lines[0]),
                critical_operation=location(lines[1]),
                trace=(
                    location(
                        next(
                            line
                            for line in range(1, 7)
                            if line not in lines
                        )
                    ),
                ),
                source_evidence_refs=(_artifact("d2-cumulative-source", 1),),
                relationship_evidence_refs=(_artifact("d2-cumulative-link", 1),),
            )
            for lines in endpoint_pairs
        )
        review_input = ReviewerInputV1(
            producer_draft=ProducerDraftV1(
                task=task,
                candidates=candidates,
                validation_receipts=tuple(
                    self._receipt(candidate, index + 1)
                    for index, candidate in enumerate(candidates)
                ),
            )
        )
        backend = ScriptedReviewerBackend()
        result = SourceDiscoveryReviewerController(
            review_input, tree, self._budget(), backend
        ).run()
        self.assertIs(type(result), ReviewerFinalizedV1)
        assert isinstance(result, ReviewerFinalizedV1)
        model_bound = tuple(
            item for item in result.verdicts if item.model_record_sha256 is not None
        )
        locally_deferred = tuple(
            item for item in result.verdicts if item.model_record_sha256 is None
        )
        self.assertTrue(model_bound)
        self.assertTrue(locally_deferred)
        self.assertTrue(all(item.decision == "accept" for item in model_bound))
        self.assertTrue(all(item.decision == "defer" for item in locally_deferred))
        self.assertEqual(
            len(model_bound), result.attempt_seal.source_read_count
        )
        self.assertEqual(
            (len(model_bound) + 1) // 2,
            result.attempt_seal.model_record_count,
        )
        self.assertEqual(len(backend.requests), result.attempt_seal.model_record_count)

    def test_32_candidate_boundary_closes_64_artifacts_and_16_model_calls(self) -> None:
        backend = ScriptedReviewerBackend()
        result = SourceDiscoveryReviewerController(
            self._boundary_input(), self._tree(), self._budget(), backend
        ).run()
        self.assertIs(type(result), ReviewerFinalizedV1)
        assert isinstance(result, ReviewerFinalizedV1)
        self.assertEqual(32, len(result.verdicts))
        self.assertEqual(64, result.attempt_seal.tool_record_count)
        self.assertEqual(64, result.attempt_seal.artifact_count)
        self.assertEqual(16, result.attempt_seal.model_record_count)
        self.assertEqual(80, result.attempt_seal.budget_event_count)
        self.assertEqual(16, len(backend.requests))

    def test_keyboard_interrupt_aborts_source_and_propagates(self) -> None:
        backend = ScriptedReviewerBackend("interrupt")
        tree = self._tree()
        controller = SourceDiscoveryReviewerController(
            self._input(), tree, self._budget(), backend
        )
        with self.assertRaises(KeyboardInterrupt):
            controller.run()
        usage = tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)
        with self.assertRaisesRegex(RuntimeError, "irreversibly cancelled"):
            controller.run()

    def test_finalize_keyboard_interrupt_closes_then_propagates(self) -> None:
        backend = ScriptedReviewerBackend()
        tree = self._tree()
        controller = SourceDiscoveryReviewerController(
            self._input(), tree, self._budget(), backend
        )
        original_finalize = AttemptToolRuntime.finalize
        calls = 0

        def interrupt_after_finalize(runtime: AttemptToolRuntime):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise KeyboardInterrupt()
            return original_finalize(runtime)

        with mock.patch.object(
            AttemptToolRuntime,
            "finalize",
            autospec=True,
            side_effect=interrupt_after_finalize,
        ):
            with self.assertRaises(KeyboardInterrupt):
                controller.run()
        usage = tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertTrue(usage.verification_succeeded)
        self.assertEqual(2, calls)
        self.assertIsNotNone(controller._session._tool_runtime.sealed_transcript)
        with self.assertRaisesRegex(RuntimeError, "irreversibly cancelled"):
            controller.run()

    def test_constructor_post_session_interrupt_aborts_source(self) -> None:
        tree = self._tree()
        with mock.patch.object(
            ReviewerContextSession,
            "review_input",
            new_callable=mock.PropertyMock,
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                SourceDiscoveryReviewerController(
                    self._input(), tree, self._budget(), ScriptedReviewerBackend()
                )
        usage = tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)

    def test_model_finalize_interrupt_retries_closure_then_propagates(self) -> None:
        backend = ScriptedReviewerBackend()
        tree = self._tree()
        controller = SourceDiscoveryReviewerController(
            self._input(), tree, self._budget(), backend
        )
        original_finalize = AttemptModelRuntime.finalize
        calls = 0

        def interrupt_before_finalize(runtime: AttemptModelRuntime):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise KeyboardInterrupt()
            return original_finalize(runtime)

        with mock.patch.object(
            AttemptModelRuntime,
            "finalize",
            autospec=True,
            side_effect=interrupt_before_finalize,
        ):
            with self.assertRaises(KeyboardInterrupt):
                controller.run()
        usage = tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertTrue(usage.verification_succeeded)
        self.assertEqual(2, calls)
        self.assertIsNotNone(controller._session._model_runtime.sealed_transcript)
        with self.assertRaisesRegex(RuntimeError, "irreversibly cancelled"):
            controller.run()


if __name__ == "__main__":
    unittest.main()
