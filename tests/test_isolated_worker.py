from __future__ import annotations

import hashlib
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
from vulngym_agent.benchmark.sealed_snapshot import prepare_sealed_snapshot
from vulngym_agent.benchmark.sealed_tree_access import (
    DEFAULT_SEALED_TREE_ACCESS_LIMITS,
    SealedTreeAccessLimits,
    bind_worker_tree,
)
from vulngym_agent.benchmark.worker_handoff import build_worker_handoff
from vulngym_agent.evaluator.worker import (
    DEFAULT_D2_WORKER_BUDGET_LIMITS,
    DEFAULT_D3_WORKER_BUDGET_LIMITS,
    IsolatedWorkerError,
    execute_discovery_worker_v1,
)
from vulngym_agent.orchestrator.budget import Budget, Limits
import vulngym_agent.evaluator.worker as worker_module
from vulngym_agent.orchestrator.discovery_pipeline import SourceDiscoveryRunV1
from vulngym_agent.tools.git.repository import GitRepository


TASK_ID = "VG-TRAIN-0123456789ABCDEF0993"
REPO_URL = "https://github.com/example/isolated-worker"
KEY = b"isolated worker test attestation key 0001"
KEY_ID = "isolated-worker-test"
SOURCE_PATH = "src/app.py"
SOURCE = (
    b"def entry(value):\n"
    b"    return critical(value)\n"
    b"def critical(value):\n"
    b"    return value\n"
)


def _sha(value: bytes | str) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _artifact(label: str, index: int) -> str:
    return f"ART-{label}-{index:024x}"


class _Backend:
    backend_id = "isolated-test"
    model_id = "offline-v1"

    def invoke(self, _request):
        raise AssertionError("patched controllers must not invoke the model backend")


class IsolatedWorkerTests(unittest.TestCase):
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
        self.handoff = build_worker_handoff(
            self.task,
            self.snapshot_root,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )
        self.payload = self.handoff.to_bytes()

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

    def _execute(self, **overrides) -> bytes:
        arguments = {
            "expected_handoff_sha256": self.handoff.handoff_sha256,
            "expected_handoff_wire_sha256": self.handoff.wire_sha256,
            "tree_root": self.snapshot_root / "tree",
            "d2_backend": _Backend(),
            "d3_backend": _Backend(),
        }
        arguments.update(overrides)
        return execute_discovery_worker_v1(self.payload, **arguments)

    def _deferred(self) -> ProducerDeferredV1:
        return ProducerDeferredV1(
            task=self.task,
            stage="SCOUT",
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

        source_id = _artifact("worker-source", 1)
        relationship_id = _artifact("worker-link", 1)
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
            validation_artifact_id=_artifact("worker-validation", 1),
            validation_artifact_sha256=_sha("worker-validation"),
            selection_digest=_sha("worker-selection"),
            dependencies=tuple(
                ProducerArtifactDigestRefV1(
                    artifact_id=artifact_id,
                    artifact_sha256=_sha(f"worker:{artifact_id}"),
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
    def _producer_controller(result, seen: list[tuple[object, ...]]):
        class Controller:
            def __init__(self, task, tree, budget, backend) -> None:
                self.tree = tree
                seen.append((task, tree, budget, backend))

            def run(self):
                self.tree.finalize()
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

    def test_d2_defer_never_accesses_or_constructs_d3(self) -> None:
        producer_seen: list[tuple[object, ...]] = []
        d3_accesses: list[str] = []

        class ForbiddenD3Backend:
            @property
            def backend_id(self):
                d3_accesses.append("backend_id")
                raise AssertionError("D3 backend must remain untouched")

            @property
            def model_id(self):
                d3_accesses.append("model_id")
                raise AssertionError("D3 backend must remain untouched")

            def invoke(self, _request):
                d3_accesses.append("invoke")
                raise AssertionError("D3 backend must remain untouched")

        class ForbiddenReviewerController:
            def __init__(self, *_args, **_kwargs) -> None:
                raise AssertionError("D3 controller must not be constructed")

        with (
            mock.patch(
                "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryAttemptController",
                self._producer_controller(self._deferred(), producer_seen),
            ),
            mock.patch(
                "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryReviewerController",
                ForbiddenReviewerController,
            ),
            mock.patch.object(worker_module, "bind_worker_tree", wraps=bind_worker_tree) as binder,
            mock.patch.object(worker_module, "Budget", wraps=Budget) as budget_factory,
        ):
            wire = self._execute(d3_backend=ForbiddenD3Backend())

        result = SourceDiscoveryRunV1.from_wire(wire)
        self.assertEqual(result.to_wire(), wire)
        self.assertIsNone(result.reviewer_result)
        self.assertEqual(result.discovery_result.status, "deferred")
        self.assertEqual(len(producer_seen), 1)
        self.assertEqual(binder.call_count, 1)
        self.assertEqual(budget_factory.call_count, 1)
        self.assertEqual(d3_accesses, [])
        self.assertTrue(producer_seen[0][1].usage_snapshot().finalized)

    def test_draft_uses_two_independent_trees_and_budgets_and_returns_canonical_run(self) -> None:
        producer = self._draft()
        reviewer = self._reviewer_deferred(producer)
        producer_seen: list[tuple[object, ...]] = []
        reviewer_seen: list[tuple[object, ...]] = []

        with (
            mock.patch(
                "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryAttemptController",
                self._producer_controller(producer, producer_seen),
            ),
            mock.patch(
                "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryReviewerController",
                self._reviewer_controller(reviewer, reviewer_seen),
            ),
            mock.patch.object(worker_module, "bind_worker_tree", wraps=bind_worker_tree) as binder,
            mock.patch.object(worker_module, "Budget", wraps=Budget) as budget_factory,
        ):
            wire = self._execute()

        result = SourceDiscoveryRunV1.from_wire(wire)
        self.assertEqual(result.to_wire(), wire)
        self.assertEqual(result.task, self.task)
        self.assertEqual(result.run_sha256, SourceDiscoveryRunV1.from_wire(wire).run_sha256)
        self.assertIs(type(result.reviewer_result), ReviewerDeferredV1)
        self.assertEqual(len(producer_seen), 1)
        self.assertEqual(len(reviewer_seen), 1)
        self.assertEqual(binder.call_count, 2)
        self.assertEqual(budget_factory.call_count, 2)
        d2_tree, d2_budget = producer_seen[0][1:3]
        d3_tree, d3_budget = reviewer_seen[0][1:3]
        self.assertIsNot(d2_tree, d3_tree)
        self.assertIsNot(d2_budget, d3_budget)
        self.assertTrue(d2_tree.usage_snapshot().finalized)
        self.assertTrue(d3_tree.usage_snapshot().finalized)

    def test_wrong_wire_pin_fails_before_run(self) -> None:
        with mock.patch.object(
            worker_module,
            "run_source_discovery_task_v1",
            side_effect=AssertionError("run must remain unreachable"),
        ) as runner:
            with self.assertRaises(IsolatedWorkerError) as captured:
                self._execute(expected_handoff_wire_sha256="f" * 64)
        self.assertEqual(captured.exception.code, "invalid_handoff")
        runner.assert_not_called()

    def test_broadened_limits_fail_before_resource_acquisition(self) -> None:
        broadened = (
            {
                "d2_budget_limits": Limits(
                    max_llm_calls=DEFAULT_D2_WORKER_BUDGET_LIMITS.max_llm_calls + 1,
                    max_tool_calls=DEFAULT_D2_WORKER_BUDGET_LIMITS.max_tool_calls,
                    max_repair_iterations=0,
                )
            },
            {
                "d3_budget_limits": Limits(
                    max_llm_calls=DEFAULT_D3_WORKER_BUDGET_LIMITS.max_llm_calls + 1,
                    max_tool_calls=DEFAULT_D3_WORKER_BUDGET_LIMITS.max_tool_calls,
                    max_repair_iterations=0,
                )
            },
            {
                "tree_limits": SealedTreeAccessLimits(
                    max_inventory_calls=(
                        DEFAULT_SEALED_TREE_ACCESS_LIMITS.max_inventory_calls + 1
                    ),
                    max_read_calls=DEFAULT_SEALED_TREE_ACCESS_LIMITS.max_read_calls,
                    max_bytes_per_read=(
                        DEFAULT_SEALED_TREE_ACCESS_LIMITS.max_bytes_per_read
                    ),
                    max_total_bytes_read=(
                        DEFAULT_SEALED_TREE_ACCESS_LIMITS.max_total_bytes_read
                    ),
                )
            },
        )
        for override in broadened:
            with self.subTest(override=tuple(override)):
                with mock.patch.object(
                    worker_module,
                    "run_source_discovery_task_v1",
                    side_effect=AssertionError("run must remain unreachable"),
                ) as runner:
                    with self.assertRaises(IsolatedWorkerError) as captured:
                        self._execute(**override)
                self.assertEqual(captured.exception.code, "invalid_limits")
                runner.assert_not_called()

    def test_invalid_d2_backend_and_source_mutation_fail_closed(self) -> None:
        with mock.patch.object(
            worker_module,
            "bind_worker_tree",
            side_effect=AssertionError("source binding must remain unreachable"),
        ) as binder:
            with self.assertRaises(IsolatedWorkerError) as captured:
                self._execute(d2_backend=object())
        self.assertEqual(captured.exception.code, "invalid_backend")
        binder.assert_not_called()

        target = self.snapshot_root / "tree" / SOURCE_PATH
        target.write_bytes(SOURCE.replace(b"critical", b"changed_"))

        class ForbiddenProducerController:
            def __init__(self, *_args, **_kwargs) -> None:
                raise AssertionError("a rejected source must not construct D2")

        with mock.patch(
            "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryAttemptController",
            ForbiddenProducerController,
        ):
            with self.assertRaises(IsolatedWorkerError) as captured:
                self._execute()
        self.assertEqual(captured.exception.code, "source_rejected")


if __name__ == "__main__":
    unittest.main()
