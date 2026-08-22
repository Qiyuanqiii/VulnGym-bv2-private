from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryCandidate,
    DiscoveryLocation,
    DiscoveryTaskInputV1,
)
from vulngym_agent.benchmark.producer_contracts import (
    ProducerArtifactDigestRefV1,
    ProducerDeferredV1,
    ProducerDraftV1,
    ValidationReceiptV1,
)
from vulngym_agent.benchmark.reviewer_contracts import (
    ReviewerDeferredV1,
    ReviewerInputV1,
)
from vulngym_agent.benchmark.reviewer_projection import project_discovery_run_v1
from vulngym_agent.benchmark.sealed_snapshot import prepare_sealed_snapshot
from vulngym_agent.benchmark.sealed_tree_access import bind_sealed_tree
from vulngym_agent.orchestrator.budget import Budget, Limits
from vulngym_agent.orchestrator.discovery_pipeline import (
    SourceDiscoveryRunV1,
    run_source_discovery_task_v1,
)
from vulngym_agent.tools.git.repository import GitRepository


TASK_ID = "VG-TRAIN-0123456789ABCDEF0789"
REPO_URL = "https://github.com/example/discovery-pipeline"
KEY = b"source discovery pipeline test key 0001"
KEY_ID = "source-discovery-pipeline-test"
SOURCE_PATH = "src/app.py"
SOURCE = b"def entry(value):\n    return critical(value)\ndef critical(value):\n    return value\n"


def _sha(value: bytes | str) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _artifact(label: str, index: int) -> str:
    return f"ART-{label}-{index:024x}"


class SourceDiscoveryPipelineTests(unittest.TestCase):
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

    def _tree(self):
        return bind_sealed_tree(
            self.task,
            self.snapshot_root,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )

    def _deferred(self, *, stage: str = "SCOUT") -> ProducerDeferredV1:
        return ProducerDeferredV1(
            task=self.task,
            stage=stage,
            reason_code="model_deferred",
            missing_information=("source evidence",),
        )

    def _draft(self) -> ProducerDraftV1:
        lines = SOURCE.splitlines(keepends=True)

        def location(line: int) -> DiscoveryLocation:
            return DiscoveryLocation(
                file=SOURCE_PATH,
                line_start=line,
                line_end=line,
                code_sha256=_sha(lines[line - 1]),
            )

        source_id = _artifact("pipeline-source", 1)
        relationship_id = _artifact("pipeline-link", 1)
        candidate = DiscoveryCandidate(
            task_id=self.task.task_id,
            snapshot_id=self.task.snapshot_id,
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            entry_point=location(1),
            critical_operation=location(3),
            trace=(location(2),),
            source_evidence_refs=(source_id,),
            relationship_evidence_refs=(relationship_id,),
        )
        receipt = ValidationReceiptV1(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            validation_artifact_id=_artifact("pipeline-validation", 1),
            validation_artifact_sha256=_sha("pipeline-validation"),
            selection_digest=_sha("pipeline-selection"),
            dependencies=tuple(
                ProducerArtifactDigestRefV1(
                    artifact_id=artifact_id,
                    artifact_sha256=_sha(f"pipeline:{artifact_id}"),
                )
                for artifact_id in sorted((source_id, relationship_id))
            ),
        )
        return ProducerDraftV1(
            task=self.task,
            candidates=(candidate,),
            validation_receipts=(receipt,),
        )

    @staticmethod
    def _reviewer_deferred(draft: ProducerDraftV1) -> ReviewerDeferredV1:
        return ReviewerDeferredV1(
            review_input=ReviewerInputV1(producer_draft=draft),
            stage="FINALIZE",
            reason_code="runtime.seal_failed",
            missing_information=("attempt_seal",),
            attempt_seal=None,
        )

    @staticmethod
    def _producer_controller(result, seen: list[tuple[object, ...]], error=None):
        class Controller:
            def __init__(self, task, tree, budget, backend) -> None:
                self.tree = tree
                seen.append((task, tree, budget, backend))

            def run(self):
                self.tree.finalize()
                if error is not None:
                    raise error
                return result

        return Controller

    @staticmethod
    def _reviewer_controller(result, seen: list[tuple[object, ...]]):
        class Controller:
            def __init__(self, review_input, tree, budget, backend) -> None:
                self.tree = tree
                seen.append((review_input, tree, budget, backend))

            def run(self):
                self.tree.finalize()
                return result

        return Controller

    def test_d2_deferred_never_acquires_or_runs_d3(self) -> None:
        producer = self._deferred()
        producer_seen: list[tuple[object, ...]] = []
        d2_trees: list[object] = []
        d2_budgets: list[Budget] = []

        def d2_tree_factory():
            value = self._tree()
            d2_trees.append(value)
            return value

        def d2_budget_factory():
            value = Budget(Limits())
            d2_budgets.append(value)
            return value

        def forbidden_d3_factory():
            self.fail("a D2 deferral must not acquire any D3 capability")

        class ForbiddenReviewerController:
            def __init__(self, *_args, **_kwargs) -> None:
                raise AssertionError("a D2 deferral must not construct D3")

        with (
            mock.patch(
                "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryAttemptController",
                self._producer_controller(producer, producer_seen),
            ),
            mock.patch(
                "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryReviewerController",
                ForbiddenReviewerController,
            ),
        ):
            result = run_source_discovery_task_v1(
                self.task,
                d2_tree_factory=d2_tree_factory,
                d2_budget_factory=d2_budget_factory,
                d2_backend=object(),
                d3_tree_factory=forbidden_d3_factory,
                d3_budget_factory=forbidden_d3_factory,
                d3_backend=object(),
            )

        self.assertIs(type(result), SourceDiscoveryRunV1)
        self.assertIsNone(result.reviewer_result)
        self.assertEqual(result.discovery_result.status, "deferred")
        self.assertEqual(result.discovery_result.deferred.stage, "d2.scout")
        self.assertEqual(len(producer_seen), 1)
        self.assertEqual(len(d2_trees), 1)
        self.assertEqual(len(d2_budgets), 1)
        self.assertTrue(d2_trees[0].usage_snapshot().finalized)

    def test_draft_lazily_runs_d3_with_independent_capabilities(self) -> None:
        producer = self._draft()
        reviewer = self._reviewer_deferred(producer)
        producer_seen: list[tuple[object, ...]] = []
        reviewer_seen: list[tuple[object, ...]] = []
        trees: list[object] = []
        budgets: list[Budget] = []

        def tree_factory():
            value = self._tree()
            trees.append(value)
            return value

        def budget_factory():
            value = Budget(Limits())
            budgets.append(value)
            return value

        with (
            mock.patch(
                "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryAttemptController",
                self._producer_controller(producer, producer_seen),
            ),
            mock.patch(
                "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryReviewerController",
                self._reviewer_controller(reviewer, reviewer_seen),
            ),
        ):
            result = run_source_discovery_task_v1(
                self.task,
                d2_tree_factory=tree_factory,
                d2_budget_factory=budget_factory,
                d2_backend=object(),
                d3_tree_factory=tree_factory,
                d3_budget_factory=budget_factory,
                d3_backend=object(),
            )

        self.assertIs(type(result.reviewer_result), ReviewerDeferredV1)
        self.assertEqual(result.discovery_result.deferred.stage, "d3.finalize")
        self.assertEqual(len(producer_seen), 1)
        self.assertEqual(len(reviewer_seen), 1)
        self.assertEqual(len(trees), 2)
        self.assertEqual(len(budgets), 2)
        self.assertIsNot(trees[0], trees[1])
        self.assertIsNot(budgets[0], budgets[1])
        self.assertEqual(reviewer_seen[0][0].producer_draft, producer)
        self.assertTrue(all(tree.usage_snapshot().finalized for tree in trees))

    def test_run_contract_round_trips_and_rejects_noncanonical_wire(self) -> None:
        producer = self._deferred()
        discovery = project_discovery_run_v1(producer, None)
        result = SourceDiscoveryRunV1(producer, None, discovery)

        self.assertEqual(SourceDiscoveryRunV1.from_wire(result.to_wire()), result)
        self.assertEqual(SourceDiscoveryRunV1.from_dict(result.to_dict()), result)
        with self.assertRaisesRegex(ValueError, "wire is invalid"):
            SourceDiscoveryRunV1.from_wire(b" " + result.to_wire())
        duplicate = result.to_wire().replace(
            b'{"contract_version":1,',
            b'{"contract_version":1,"contract_version":1,',
            1,
        )
        with self.assertRaisesRegex(ValueError, "wire is invalid"):
            SourceDiscoveryRunV1.from_wire(duplicate)

        tampered = result.to_dict()
        tampered["run_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "run_sha256"):
            SourceDiscoveryRunV1.from_dict(tampered)

    def test_run_contract_rejects_incomplete_or_inconsistent_closure(self) -> None:
        deferred = self._deferred()
        deferred_projection = project_discovery_run_v1(deferred, None)
        draft = self._draft()
        reviewer = self._reviewer_deferred(draft)

        with self.assertRaisesRegex(ValueError, "closed run"):
            SourceDiscoveryRunV1(deferred, reviewer, deferred_projection)
        with self.assertRaisesRegex(ValueError, "closed run"):
            SourceDiscoveryRunV1(draft, None, deferred_projection)

        other = self._deferred(stage="ANALYZE")
        wrong_projection = project_discovery_run_v1(other, None)
        with self.assertRaisesRegex(ValueError, "exact D2/D3 projection"):
            SourceDiscoveryRunV1(deferred, None, wrong_projection)

    def test_exact_type_checks_do_not_invoke_polymorphic_serializers(self) -> None:
        class EvilDeferred(ProducerDeferredV1):
            def to_wire(self):
                raise AssertionError("polymorphic serializer was invoked")

        evil = EvilDeferred(
            task=self.task,
            stage="SCOUT",
            reason_code="model_deferred",
            missing_information=("source evidence",),
        )
        discovery = project_discovery_run_v1(self._deferred(), None)
        with self.assertRaisesRegex(ValueError, "exact D2 result"):
            SourceDiscoveryRunV1(evil, None, discovery)

    def test_invalid_task_and_d2_failure_do_not_touch_d3_factories(self) -> None:
        factory_calls: list[str] = []

        def d2_tree_factory():
            factory_calls.append("d2-tree")
            return self._tree()

        def d2_budget_factory():
            factory_calls.append("d2-budget")
            return Budget(Limits())

        def forbidden_d3_factory():
            factory_calls.append("d3")
            self.fail("D3 must stay lazy when D2 does not return a draft")

        with self.assertRaisesRegex(ValueError, "exact DiscoveryTaskInputV1"):
            run_source_discovery_task_v1(
                object(),
                d2_tree_factory=d2_tree_factory,
                d2_budget_factory=d2_budget_factory,
                d2_backend=object(),
                d3_tree_factory=forbidden_d3_factory,
                d3_budget_factory=forbidden_d3_factory,
                d3_backend=object(),
            )
        self.assertEqual(factory_calls, [])

        producer_seen: list[tuple[object, ...]] = []
        with mock.patch(
            "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryAttemptController",
            self._producer_controller(
                self._deferred(), producer_seen, KeyboardInterrupt()
            ),
        ):
            with self.assertRaises(KeyboardInterrupt):
                run_source_discovery_task_v1(
                    self.task,
                    d2_tree_factory=d2_tree_factory,
                    d2_budget_factory=d2_budget_factory,
                    d2_backend=object(),
                    d3_tree_factory=forbidden_d3_factory,
                    d3_budget_factory=forbidden_d3_factory,
                    d3_backend=object(),
                )
        self.assertEqual(factory_calls, ["d2-tree", "d2-budget"])
        self.assertEqual(len(producer_seen), 1)

    def test_reused_d2_tree_is_rejected_before_reviewer_construction(self) -> None:
        producer = self._draft()
        producer_seen: list[tuple[object, ...]] = []
        shared_tree = self._tree()
        budgets: list[Budget] = []

        def budget_factory():
            value = Budget(Limits())
            budgets.append(value)
            return value

        with mock.patch(
            "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryAttemptController",
            self._producer_controller(producer, producer_seen),
        ):
            with self.assertRaisesRegex(ValueError, "independent tree and budget"):
                run_source_discovery_task_v1(
                    self.task,
                    d2_tree_factory=lambda: shared_tree,
                    d2_budget_factory=budget_factory,
                    d2_backend=object(),
                    d3_tree_factory=lambda: shared_tree,
                    d3_budget_factory=budget_factory,
                    d3_backend=object(),
                )
        self.assertEqual(len(budgets), 2)


if __name__ == "__main__":
    unittest.main()
