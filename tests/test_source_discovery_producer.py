from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import vulngym_agent.agents as agents_api
from vulngym_agent.agents.discovery_toolbox import DiscoveryToolbox
from vulngym_agent.agents.model_runtime import (
    AttemptModelRuntime,
    AttemptModelTranscript,
    ModelRequest,
    ModelResult,
    structured_json_sha256,
)
from vulngym_agent.agents.source_discovery_producer import (
    SourceDiscoveryAttemptController,
)
from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.producer_contracts import (
    PRODUCER_SELECTION_DIGEST_DOMAIN,
    ProducerDeferredV1,
    ProducerDraftV1,
)
from vulngym_agent.benchmark.sealed_snapshot import prepare_sealed_snapshot
from vulngym_agent.benchmark.sealed_tree_access import (
    SealedTreeAccessError,
    bind_sealed_tree,
)
from vulngym_agent.orchestrator.budget import Budget, Limits
from vulngym_agent.tools.runtime import (
    AttemptToolRuntime,
    AttemptToolTranscript,
    ToolArtifact,
)
from vulngym_agent.tools.git.repository import GitRepository


TASK_ID = "VG-TRAIN-0123456789ABCDEF0456"
REPO_URL = "https://github.com/example/source-discovery-producer"
KEY = b"source discovery producer test key 0001"
KEY_ID = "source-discovery-producer-test"
SOURCE_PATH = "src/app.py"
SOURCE = (
    b"def sink(value):\n"
    b"    return eval(value)\n"
    b"def entry(value):\n"
    b"    return sink(value)\n"
)


class ScriptedBackend:
    backend_id = "scripted"
    model_id = "offline-d2-v1"

    def __init__(self, mode: str = "success") -> None:
        self.mode = mode
        self.step = 0
        self.fill = 0
        self.requests: list[ModelRequest] = []

    @staticmethod
    def _nodes(request: ModelRequest):
        return tuple(request.payload["catalog"]["nodes"])

    @staticmethod
    def _relationships(request: ModelRequest):
        return tuple(request.payload["catalog"]["relationships"])

    @staticmethod
    def _ref(item):
        return {
            "artifact_id": item["ref"]["artifact_id"],
            "node_id": item["ref"]["node_id"],
        }

    def _find_node(self, request: ModelRequest, node_type: str, **fields):
        for node in self._nodes(request):
            if node["type"] != node_type:
                continue
            if all(node.get(key) == value for key, value in fields.items()):
                return node
        raise AssertionError(f"missing {node_type} node: {fields}")

    def _selection(self, request: ModelRequest):
        declaration = self._find_node(
            request, "LEX", kind="function_declaration", token="sink"
        )
        call = self._find_node(request, "LEX", kind="call", token="sink")
        relationships = self._relationships(request)
        relationship = next(item for item in relationships if item["symbol"] == "sink")
        return {
            "critical": self._ref(call),
            "entry": self._ref(declaration),
            "relationships": [self._ref(relationship)],
            "trace": [],
        }

    def invoke(self, request: ModelRequest):
        self.requests.append(request)
        if self.mode == "empty":
            step = self.step
            self.step += 1
            if step == 0:
                return {"action": "advance"}
            return {"action": "select", "candidates": []}
        if self.mode == "validate_action":
            return {"action": "source_validate", "candidate": {}}
        if self.mode == "forged":
            return {
                "action": "search",
                "cursor": 0,
                "files": [{"artifact_id": "ART-forged", "node_id": "FIL-forged"}],
                "limit": 8,
                "query": "entry",
            }
        if self.mode == "reverse":
            self.step += 1
            return {"action": "advance"}
        if self.mode == "blocked":
            return {"action": "inventory", "cursor": 1_000, "limit": 8}

        step = self.step
        self.step += 1
        if step == 0:
            return {"action": "inventory", "cursor": 0, "limit": 256}
        if step == 1:
            source = self._find_node(request, "FIL", path=SOURCE_PATH)
            return {
                "action": "search",
                "cursor": 0,
                "files": [self._ref(source)],
                "limit": 32,
                "query": "entry",
            }
        if step == 2:
            match = self._find_node(request, "MAT", path=SOURCE_PATH, line=3)
            ref = self._ref(match)
            return {
                "action": "read",
                "locations": [
                    {
                        **ref,
                        "context_after": 1,
                        "context_before": 2,
                    }
                ],
            }
        if step == 3:
            return {"action": "advance"}
        if step == 4:
            location = self._find_node(request, "LOC", path=SOURCE_PATH, line=1)
            return {
                "action": "structure",
                "cursor": 0,
                "limit": 256,
                "source": self._ref(location),
            }
        if step == 5:
            lexical = self._find_node(request, "LEX", token="sink")
            return {
                "action": "link",
                "cursor": 0,
                "limit": 256,
                "structures": [self._ref(lexical)],
            }
        if self.mode == "reserve" and self.fill < 59:
            self.fill += 1
            return {"action": "inventory", "cursor": 0, "limit": 256}

        candidate = self._selection(request)
        if self.mode == "duplicate":
            return {"action": "select", "candidates": [candidate, candidate]}
        return {"action": "select", "candidates": [candidate]}


class LedgerInterferenceBackend:
    backend_id = "ledger-interference"
    model_id = "offline-d2-v1"

    def __init__(self, budget: Budget) -> None:
        self.budget = budget

    def invoke(self, request: ModelRequest):
        self.budget.charge_repair_iteration(operation="unowned-controller-event")
        return {"action": "source_validate"}


class ReentrantBackend:
    backend_id = "reentrant"
    model_id = "offline-d2-v1"

    def __init__(self) -> None:
        self.controller = None

    def invoke(self, request: ModelRequest):
        assert self.controller is not None
        return self.controller.run()


class InterruptBackend:
    backend_id = "interrupt"
    model_id = "offline-d2-v1"

    def invoke(self, request: ModelRequest):
        raise KeyboardInterrupt()


class TaskSubclass(DiscoveryTaskInputV1):
    pass


class SourceDiscoveryProducerTests(unittest.TestCase):
    def test_public_agents_package_lazily_exports_controller(self) -> None:
        self.assertIs(
            agents_api.SourceDiscoveryAttemptController,
            SourceDiscoveryAttemptController,
        )

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
        (self.repository / "README.md").write_text("public source\n", encoding="utf-8")
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

    def _controller(self, backend, *, limits=None):
        budget = Budget(limits or Limits(max_llm_calls=80, max_tool_calls=80))
        controller = SourceDiscoveryAttemptController(
            task=self.task,
            tree=self._tree(),
            budget=budget,
            backend=backend,
        )
        return controller, budget

    def test_task_subclass_is_rejected_before_tree_ownership_transfers(self) -> None:
        subclass = TaskSubclass(
            task_id=self.task.task_id,
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            instruction_id=self.task.instruction_id,
            snapshot_manifest_sha256=self.task.snapshot_manifest_sha256,
            snapshot_content_root=self.task.snapshot_content_root,
        )
        tree = self._tree()
        with self.assertRaises(ValueError):
            SourceDiscoveryAttemptController(
                subclass,
                tree,
                Budget(Limits(max_llm_calls=8, max_tool_calls=8)),
                ScriptedBackend(),
            )
        usage = tree.usage_snapshot()
        self.assertFalse(usage.finalized)
        self.assertEqual(0, usage.inventory_calls)
        self.assertEqual(0, usage.read_calls)

    def test_invalid_backend_does_not_consume_tree_or_budget(self) -> None:
        tree = self._tree()
        budget = Budget(Limits(max_llm_calls=8, max_tool_calls=8))
        with self.assertRaises(ValueError):
            SourceDiscoveryAttemptController(
                self.task,
                tree,
                budget,
                object(),  # type: ignore[arg-type]
            )
        usage = tree.usage_snapshot()
        self.assertFalse(usage.finalized)
        self.assertEqual((0, 0, 0), (usage.inventory_calls, usage.read_calls, usage.bytes_read))
        self.assertEqual((0, 0), (budget.usage.llm_calls, budget.usage.tool_calls))

        result = SourceDiscoveryAttemptController(
            self.task,
            tree,
            budget,
            ScriptedBackend(),
        ).run()
        self.assertIsInstance(result, ProducerDraftV1)
        self.assertTrue(tree.usage_snapshot().finalized)

    def test_post_claim_constructor_failure_aborts_the_tree(self) -> None:
        tree = self._tree()
        with mock.patch(
            "vulngym_agent.agents.source_discovery_producer._ArtifactCatalog",
            side_effect=RuntimeError("synthetic assembly failure"),
        ):
            with self.assertRaises(RuntimeError):
                SourceDiscoveryAttemptController(
                    self.task,
                    tree,
                    Budget(Limits(max_llm_calls=8, max_tool_calls=8)),
                    ScriptedBackend(),
                )
        usage = tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)
        with self.assertRaises(SealedTreeAccessError) as captured:
            SourceDiscoveryAttemptController(
                self.task,
                tree,
                Budget(Limits(max_llm_calls=8, max_tool_calls=8)),
                ScriptedBackend(),
            )
        self.assertEqual("access_finalized", captured.exception.code)

    def test_post_claim_base_exception_aborts_the_tree(self) -> None:
        tree = self._tree()
        with mock.patch.object(
            AttemptToolRuntime,
            "__init__",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                SourceDiscoveryAttemptController(
                    self.task,
                    tree,
                    Budget(Limits(max_llm_calls=8, max_tool_calls=8)),
                    ScriptedBackend(),
                )
        usage = tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)

    def test_interrupt_immediately_after_explicit_claim_aborts_the_tree(self) -> None:
        tree = self._tree()
        original = DiscoveryToolbox.claim_source_usage

        def claim_then_interrupt(toolbox):
            original(toolbox)
            raise KeyboardInterrupt()

        with mock.patch.object(
            DiscoveryToolbox,
            "claim_source_usage",
            autospec=True,
            side_effect=claim_then_interrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                SourceDiscoveryAttemptController(
                    self.task,
                    tree,
                    Budget(Limits(max_llm_calls=8, max_tool_calls=8)),
                    ScriptedBackend(),
                )
        usage = tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)

    def test_same_tree_cannot_back_two_attempt_controllers(self) -> None:
        tree = self._tree()
        first = SourceDiscoveryAttemptController(
            self.task,
            tree,
            Budget(Limits(max_llm_calls=8, max_tool_calls=8)),
            ScriptedBackend(),
        )
        with self.assertRaises(SealedTreeAccessError) as captured:
            SourceDiscoveryAttemptController(
                self.task,
                tree,
                Budget(Limits(max_llm_calls=8, max_tool_calls=8)),
                ScriptedBackend(),
            )
        self.assertEqual("access_claimed", captured.exception.code)
        self.assertIsInstance(first.run(), ProducerDraftV1)

    def test_minimal_success_is_validated_deterministic_and_cached(self) -> None:
        first_backend = ScriptedBackend()
        first_controller, first_budget = self._controller(first_backend)
        first = first_controller.run()
        self.assertIsInstance(first, ProducerDraftV1)
        assert isinstance(first, ProducerDraftV1)
        self.assertEqual(1, len(first.candidates))
        self.assertEqual(1, len(first.validation_receipts))
        receipt = first.validation_receipts[0]
        receipt.assert_candidate(first.candidates[0])
        raw_selection = first_backend._selection(first_backend.requests[-1])
        selection_payload = {
            "critical": raw_selection["critical"],
            "entry": raw_selection["entry"],
            "relationships": sorted(
                raw_selection["relationships"],
                key=lambda item: (item["artifact_id"], item["node_id"]),
            ),
            "task": self.task.to_dict(),
            "trace": raw_selection["trace"],
        }
        expected_selection_digest = hashlib.sha256(
            PRODUCER_SELECTION_DIGEST_DOMAIN
            + json.dumps(
                selection_payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(expected_selection_digest, receipt.selection_digest)
        self.assertEqual(7, first_budget.usage.llm_calls)
        self.assertEqual(6, first_budget.usage.tool_calls)
        self.assertIs(first, first_controller.run())

        second_controller, _ = self._controller(ScriptedBackend())
        second = second_controller.run()
        self.assertIsInstance(second, ProducerDraftV1)
        assert isinstance(second, ProducerDraftV1)
        self.assertEqual(first.to_wire(), second.to_wire())

    def test_empty_selection_releases_a_closed_empty_draft(self) -> None:
        controller, budget = self._controller(ScriptedBackend("empty"))
        result = controller.run()
        self.assertIsInstance(result, ProducerDraftV1)
        assert isinstance(result, ProducerDraftV1)
        self.assertEqual((), result.candidates)
        self.assertEqual((), result.validation_receipts)
        self.assertEqual((2, 0), (budget.usage.llm_calls, budget.usage.tool_calls))
        self.assertIsNotNone(controller._tool_runtime.sealed_transcript)
        self.assertIsNotNone(controller._model_runtime.sealed_transcript)
        usage = self.trees[-1].usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertTrue(usage.verification_succeeded)

    def test_forged_opaque_reference_fails_before_a_tool_call(self) -> None:
        controller, budget = self._controller(ScriptedBackend("forged"))
        result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(("SCOUT", "invalid_model_action"), (result.stage, result.reason_code))
        self.assertEqual(0, budget.usage.tool_calls)

    def test_phase_transition_is_irreversible(self) -> None:
        controller, budget = self._controller(ScriptedBackend("reverse"))
        result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(
            ("ANALYZE", "invalid_phase_transition"),
            (result.stage, result.reason_code),
        )
        self.assertEqual(2, budget.usage.llm_calls)
        self.assertEqual(0, budget.usage.tool_calls)

    def test_model_cannot_invoke_controller_only_validation(self) -> None:
        controller, budget = self._controller(ScriptedBackend("validate_action"))
        result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual("invalid_model_action", result.reason_code)
        self.assertEqual(0, budget.usage.tool_calls)

    def test_blocked_tool_becomes_deferred(self) -> None:
        controller, budget = self._controller(ScriptedBackend("blocked"))
        result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(("SCOUT", "tool_blocked"), (result.stage, result.reason_code))
        self.assertEqual(1, budget.usage.tool_calls)

    def test_budget_exhaustion_becomes_deferred_and_still_finalizes(self) -> None:
        controller, budget = self._controller(
            ScriptedBackend(), limits=Limits(max_llm_calls=0, max_tool_calls=8)
        )
        result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(("SCOUT", "budget_exhausted"), (result.stage, result.reason_code))
        self.assertEqual(0, budget.usage.llm_calls)
        self.assertTrue(self.trees[-1].usage_snapshot().finalized)

    def test_duplicate_candidate_batch_is_wholly_deferred(self) -> None:
        controller, budget = self._controller(ScriptedBackend("duplicate"))
        result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(("ANALYZE", "duplicate_candidate"), (result.stage, result.reason_code))
        self.assertEqual(5, budget.usage.tool_calls)

    def test_validation_artifact_capacity_is_reserved_before_batch(self) -> None:
        controller, budget = self._controller(ScriptedBackend("reserve"))
        result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(
            ("VALIDATE", "artifact_capacity_exhausted"),
            (result.stage, result.reason_code),
        )
        self.assertEqual(64, budget.usage.tool_calls)

    def test_validation_artifact_must_exactly_match_its_runtime_reference(self) -> None:
        controller, _ = self._controller(ScriptedBackend())
        original = AttemptToolRuntime.resolve_artifact

        def mismatched(runtime, ref):
            artifact = original(runtime, ref)
            if artifact.kind != "discovery.source_validation":
                return artifact
            return ToolArtifact(
                task_id=artifact.task_id,
                attempt=artifact.attempt,
                policy_scope=artifact.policy_scope,
                tool_call_id=artifact.tool_call_id,
                artifact_id="ART-rebound-validation",
                kind=artifact.kind,
                payload=artifact.payload,
            )

        with mock.patch.object(
            AttemptToolRuntime,
            "resolve_artifact",
            autospec=True,
            side_effect=mismatched,
        ):
            result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(
            ("VALIDATE", "artifact_binding_invalid"),
            (result.stage, result.reason_code),
        )
        self.assertTrue(self.trees[-1].usage_snapshot().finalized)

    def test_tool_result_must_bind_the_requested_action(self) -> None:
        controller, _ = self._controller(ScriptedBackend())
        original = AttemptToolRuntime.call

        def redirect(runtime, call_id, name, arguments):
            if name == "source_inventory":
                return original(
                    runtime,
                    call_id,
                    "source_read",
                    {
                        "spans": [
                            {"line_end": 4, "line_start": 1, "path": SOURCE_PATH}
                        ]
                    },
                )
            return original(runtime, call_id, name, arguments)

        with mock.patch.object(
            AttemptToolRuntime,
            "call",
            autospec=True,
            side_effect=redirect,
        ):
            result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(
            ("FINALIZE", "attempt_finalization_failed"),
            (result.stage, result.reason_code),
        )

    def test_unrecorded_model_result_cannot_release_a_result(self) -> None:
        controller, _ = self._controller(ScriptedBackend())

        def unrecorded(runtime, call_id, stage, payload):
            request_sha256 = structured_json_sha256(payload)
            return ModelResult(
                task_id=self.task.task_id,
                attempt=0,
                policy_scope="t2.initial",
                model_call_id=call_id,
                stage=stage,
                backend_id=runtime.backend_id,
                model_id=runtime.model_id,
                request_sha256=request_sha256,
                operation=(
                    f"model:{self.task.task_id}:0:t2.initial:{stage}:{call_id}:"
                    f"{runtime.backend_id}:{runtime.model_id}:{request_sha256}"
                ),
                budget_event_sequence=1,
                status="success",
                response={
                    "action": "defer",
                    "missing_information": ["no selection"],
                    "reason_code": "no_selection",
                },
            )

        with mock.patch.object(
            AttemptModelRuntime,
            "call",
            autospec=True,
            side_effect=unrecorded,
        ):
            result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(
            ("FINALIZE", "attempt_finalization_failed"),
            (result.stage, result.reason_code),
        )

    def test_source_finalization_failure_overrides_a_draft(self) -> None:
        controller, _ = self._controller(ScriptedBackend())
        with mock.patch.object(
            DiscoveryToolbox,
            "finalize_source_usage",
            side_effect=RuntimeError("synthetic finalization failure"),
        ):
            result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(
            ("FINALIZE", "attempt_finalization_failed"),
            (result.stage, result.reason_code),
        )
        # Earlier finalizers still ran even though source closure failed.
        self.assertIsNotNone(controller._tool_runtime._transcript)
        self.assertIsNotNone(controller._model_runtime._transcript)
        usage = self.trees[-1].usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)
        self.assertIs(result, controller.run())

    def test_tool_finalization_failure_does_not_skip_source_finalization(self) -> None:
        controller, _ = self._controller(ScriptedBackend("validate_action"))
        with mock.patch.object(
            AttemptToolRuntime,
            "finalize",
            side_effect=RuntimeError("synthetic transcript failure"),
        ):
            result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual("FINALIZE", result.stage)
        self.assertTrue(self.trees[-1].usage_snapshot().finalized)

    def test_model_finalization_failure_does_not_skip_source_finalization(self) -> None:
        controller, _ = self._controller(ScriptedBackend("validate_action"))
        with mock.patch.object(
            AttemptModelRuntime,
            "finalize",
            side_effect=RuntimeError("synthetic transcript failure"),
        ):
            result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual("FINALIZE", result.stage)
        self.assertIsNotNone(controller._tool_runtime._transcript)
        self.assertTrue(self.trees[-1].usage_snapshot().finalized)

    def test_silent_none_finalizers_cannot_release_a_result(self) -> None:
        for runtime_type in (AttemptToolRuntime, AttemptModelRuntime):
            with self.subTest(runtime=runtime_type.__name__):
                controller, _ = self._controller(ScriptedBackend("validate_action"))
                with mock.patch.object(runtime_type, "finalize", return_value=None):
                    result = controller.run()
                self.assertIsInstance(result, ProducerDeferredV1)
                assert isinstance(result, ProducerDeferredV1)
                self.assertEqual(
                    ("FINALIZE", "attempt_finalization_failed"),
                    (result.stage, result.reason_code),
                )
                self.assertTrue(self.trees[-1].usage_snapshot().finalized)

    def test_equal_transcript_from_another_runtime_cannot_be_replayed(self) -> None:
        first, _ = self._controller(ScriptedBackend())
        self.assertIsInstance(first.run(), ProducerDraftV1)
        old_tool = first._tool_runtime.sealed_transcript
        old_model = first._model_runtime.sealed_transcript
        self.assertIsInstance(old_tool, AttemptToolTranscript)
        self.assertIsInstance(old_model, AttemptModelTranscript)

        second, _ = self._controller(ScriptedBackend())
        with mock.patch.object(AttemptToolRuntime, "finalize", return_value=old_tool):
            tool_replay = second.run()
        self.assertIsInstance(tool_replay, ProducerDeferredV1)
        assert isinstance(tool_replay, ProducerDeferredV1)
        self.assertEqual(
            ("FINALIZE", "attempt_finalization_failed"),
            (tool_replay.stage, tool_replay.reason_code),
        )
        self.assertIsNone(second._tool_runtime.sealed_transcript)

        third, _ = self._controller(ScriptedBackend())
        with mock.patch.object(AttemptModelRuntime, "finalize", return_value=old_model):
            model_replay = third.run()
        self.assertIsInstance(model_replay, ProducerDeferredV1)
        assert isinstance(model_replay, ProducerDeferredV1)
        self.assertEqual(
            ("FINALIZE", "attempt_finalization_failed"),
            (model_replay.stage, model_replay.reason_code),
        )
        self.assertIsNone(third._model_runtime.sealed_transcript)

    def test_source_ledger_from_another_tree_cannot_be_replayed(self) -> None:
        first, _ = self._controller(ScriptedBackend())
        self.assertIsInstance(first.run(), ProducerDraftV1)
        old_ledger = self.trees[-1].usage_snapshot()
        self.assertTrue(old_ledger.verification_succeeded)

        second, _ = self._controller(ScriptedBackend())
        current_tree = self.trees[-1]
        with mock.patch.object(
            DiscoveryToolbox,
            "finalize_source_usage",
            return_value=old_ledger,
        ):
            result = second.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(
            ("FINALIZE", "attempt_finalization_failed"),
            (result.stage, result.reason_code),
        )
        usage = current_tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)

    def test_unowned_shared_budget_event_fails_exact_closure(self) -> None:
        budget = Budget(Limits(max_llm_calls=8, max_tool_calls=8))
        controller = SourceDiscoveryAttemptController(
            self.task,
            self._tree(),
            budget,
            LedgerInterferenceBackend(budget),
        )
        result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(
            ("FINALIZE", "attempt_finalization_failed"),
            (result.stage, result.reason_code),
        )
        self.assertEqual(1, budget.usage.repair_iterations)
        self.assertTrue(self.trees[-1].usage_snapshot().finalized)

    def test_reentrant_backend_cannot_start_a_second_run(self) -> None:
        backend = ReentrantBackend()
        controller, budget = self._controller(backend)
        backend.controller = controller
        result = controller.run()
        self.assertIsInstance(result, ProducerDeferredV1)
        assert isinstance(result, ProducerDeferredV1)
        self.assertEqual(("SCOUT", "model_error"), (result.stage, result.reason_code))
        self.assertEqual(1, budget.usage.llm_calls)
        self.assertTrue(self.trees[-1].usage_snapshot().finalized)

    def test_keyboard_interrupt_seals_capabilities_before_propagating(self) -> None:
        controller, _ = self._controller(InterruptBackend())
        with self.assertRaises(KeyboardInterrupt):
            controller.run()
        usage = self.trees[-1].usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)
        cached = controller.run()
        self.assertIsInstance(cached, ProducerDeferredV1)
        assert isinstance(cached, ProducerDeferredV1)
        self.assertEqual(
            ("FINALIZE", "attempt_cancelled"),
            (cached.stage, cached.reason_code),
        )

    def test_interrupt_immediately_after_running_store_is_cleaned_up(self) -> None:
        controller, _ = self._controller(ScriptedBackend())
        lines, first_line = inspect.getsourcelines(
            SourceDiscoveryAttemptController.run
        )
        assignment_index = next(
            index for index, line in enumerate(lines) if "self._running = True" in line
        )
        target_line = first_line + assignment_index + 1
        triggered = False

        def interrupt(frame, event, argument):
            nonlocal triggered
            if (
                event == "line"
                and frame.f_code is SourceDiscoveryAttemptController.run.__code__
                and frame.f_lineno == target_line
            ):
                triggered = True
                sys.settrace(None)
                raise KeyboardInterrupt()
            return interrupt

        sys.settrace(interrupt)
        try:
            with self.assertRaises(KeyboardInterrupt):
                controller.run()
        finally:
            sys.settrace(None)
        self.assertTrue(triggered)
        usage = self.trees[-1].usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertFalse(usage.verification_succeeded)
        self.assertFalse(controller._running)
        self.assertTrue(controller._sealed)
        cached = controller.run()
        self.assertIsInstance(cached, ProducerDeferredV1)
        assert isinstance(cached, ProducerDeferredV1)
        self.assertEqual(
            ("FINALIZE", "attempt_cancelled"),
            (cached.stage, cached.reason_code),
        )


if __name__ == "__main__":
    unittest.main()
