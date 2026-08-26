from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from types import SimpleNamespace

from vulngym_agent.agents.model_runtime import (
    ModelBlocked,
    ModelRequest,
    ReplayResponse,
)
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
from vulngym_agent.benchmark.snapshot_batch import SnapshotBatchError
from vulngym_agent.evaluator.oci_worker_entry import OciReplayConfigV1
import vulngym_agent.evaluator.replay_authoring as authoring_module
from vulngym_agent.evaluator.replay_authoring import (
    ReplayAuthoringError,
    ReplayAuthoringPendingRequestV1,
    ReplayAuthoringResponseV1,
    ReplayAuthoringSummaryV1,
    append_replay_authoring_response_v1,
    initialize_replay_authoring_v1,
    inspect_replay_authoring_v1,
    publish_replay_authoring_v1,
    validate_empty_smoke_replay_pair_v1,
    validate_formal_replay_pair_v1,
)
import vulngym_agent.replay_authoring_cli as authoring_cli
from vulngym_agent.tools.git.repository import GitRepository


TASK_ID = "VG-TRAIN-0123456789ABCDEF0998"
REPO_URL = "https://github.com/example/replay-authoring"
KEY = b"replay authoring test attestation key 0001"
KEY_ID = "replay-authoring-test"
SOURCE = b"def entry(value):\n    return critical(value)\n"
DEFER_RESPONSE = {
    "action": "defer",
    "missing_information": ["source evidence"],
    "reason_code": "insufficient_source_evidence",
}


def _sha(value: bytes | str) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _artifact(label: str, index: int) -> str:
    return f"ART-{label}-{index:024x}"


class ReplayAuthoringTests(unittest.TestCase):
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
        (self.repository / "src" / "app.py").write_bytes(SOURCE)
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "source")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()

        self.sealed = self.root / "sealed"
        prepared = prepare_sealed_snapshot(
            GitRepository(self.repository),
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=self.commit,
            output_dir=self.sealed,
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
        self.draft = self.root / "draft"
        initialized = initialize_replay_authoring_v1(TASK_ID, self.draft)
        self.assertEqual(initialized.status, "initialized")

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

    @staticmethod
    def _cli(*arguments: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "vulngym_agent.replay_authoring_cli",
                *(str(item) for item in arguments),
            ],
            cwd=Path(__file__).resolve().parents[1],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def _inspect(self):
        return inspect_replay_authoring_v1(
            self.task,
            self.sealed,
            self.draft,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )

    def _append(
        self,
        pending: ReplayAuthoringPendingRequestV1,
        response: dict[str, object],
    ):
        self.assertEqual(
            ReplayAuthoringPendingRequestV1.from_bytes(pending.to_bytes()), pending
        )
        envelope = ReplayAuthoringResponseV1.from_pending(pending, response)
        self.assertEqual(
            ReplayAuthoringResponseV1.from_bytes(envelope.to_bytes()), envelope
        )
        return append_replay_authoring_response_v1(
            self.task,
            self.sealed,
            self.draft,
            envelope,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )

    def _draft_result(self) -> ProducerDraftV1:
        lines = SOURCE.splitlines(keepends=True)
        source_id = _artifact("authoring-source", 1)
        relationship_id = _artifact("authoring-link", 1)
        candidate = DiscoveryCandidate(
            task_id=self.task.task_id,
            snapshot_id=self.task.snapshot_id,
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            entry_point=DiscoveryLocation(
                file="src/app.py",
                line_start=1,
                line_end=1,
                code_sha256=_sha(lines[0]),
            ),
            critical_operation=DiscoveryLocation(
                file="src/app.py",
                line_start=2,
                line_end=2,
                code_sha256=_sha(lines[1]),
            ),
            trace=(),
            source_evidence_refs=(source_id,),
            relationship_evidence_refs=(relationship_id,),
        )
        receipt = ValidationReceiptV1(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            validation_artifact_id=_artifact("authoring-validation", 1),
            validation_artifact_sha256=_sha("authoring-validation"),
            selection_digest=_sha("authoring-selection"),
            dependencies=tuple(
                ProducerArtifactDigestRefV1(
                    artifact_id=artifact_id,
                    artifact_sha256=_sha(f"authoring:{artifact_id}"),
                )
                for artifact_id in sorted((source_id, relationship_id))
            ),
        )
        return ProducerDraftV1(
            task=self.task,
            candidates=(candidate,),
            validation_receipts=(receipt,),
        )

    def _repeating_d2_controller(self):
        outer = self

        class Controller:
            def __init__(self, task, tree, _budget, backend) -> None:
                self.task = task
                self.tree = tree
                self.backend = backend

            def run(self):
                try:
                    try:
                        for ordinal in (1, 2):
                            self.backend.invoke(
                                ModelRequest(
                                    task_id=self.task.task_id,
                                    attempt=0,
                                    policy_scope="authoring.test.d2",
                                    stage="plan",
                                    model_call_id=f"MODEL-AUTHORING-D2-{ordinal:03d}",
                                    backend_id=self.backend.backend_id,
                                    model_id=self.backend.model_id,
                                    payload={"fixture": "repeated-d2-request"},
                                )
                            )
                    except ModelBlocked:
                        return ProducerDeferredV1(
                            task=self.task,
                            stage="SCOUT",
                            reason_code="model_blocked",
                            missing_information=("structured model response",),
                        )
                    return outer._draft_result()
                finally:
                    self.tree.finalize()

        return Controller

    @staticmethod
    def _d3_deferred_controller():
        class Controller:
            def __init__(self, review_input, tree, _budget, backend) -> None:
                self.review_input = review_input
                self.tree = tree
                self.backend = backend

            def run(self):
                try:
                    try:
                        self.backend.invoke(
                            ModelRequest(
                                task_id=self.review_input.task_id,
                                attempt=0,
                                policy_scope="authoring.test.d3",
                                stage="semantic_judge",
                                model_call_id="MODEL-AUTHORING-D3-001",
                                backend_id=self.backend.backend_id,
                                model_id=self.backend.model_id,
                                payload={"fixture": "d3-request"},
                            )
                        )
                    except ModelBlocked:
                        pass
                    return ReviewerDeferredV1(
                        review_input=ReviewerInputV1(
                            producer_draft=self.review_input.producer_draft
                        ),
                        stage="FINALIZE",
                        reason_code="runtime.seal_failed",
                        missing_information=("attempt_seal",),
                        attempt_seal=None,
                    )
                finally:
                    self.tree.finalize()

        return Controller

    def test_dynamic_multistep_recovers_and_publishes_exact_defer(self) -> None:
        first = self._inspect()
        self.assertIs(type(first), ReplayAuthoringPendingRequestV1)
        self.assertEqual((first.role, first.stage), ("d2", "plan"))

        second = self._append(
            first, {"action": "inventory", "cursor": 0, "limit": 8}
        )
        self.assertIs(type(second), ReplayAuthoringPendingRequestV1)
        self.assertNotEqual(first.request_sha256, second.request_sha256)

        recovered = self._inspect()
        self.assertEqual(recovered.to_bytes(), second.to_bytes())
        closed = self._append(recovered, DEFER_RESPONSE)
        self.assertIs(type(closed), ReplayAuthoringSummaryV1)
        self.assertEqual(closed.status, "closed")
        self.assertEqual((closed.d2_response_count, closed.d3_response_count), (2, 0))
        self.assertEqual(closed.run_outcome, "d2_deferred")
        self.assertEqual(
            (
                closed.candidate_count,
                closed.finding_count,
                closed.reviewer_verdict_count,
            ),
            (0, 0, 0),
        )

        d2 = OciReplayConfigV1.from_bytes((self.draft / "d2.json").read_bytes())
        d3 = OciReplayConfigV1.from_bytes((self.draft / "d3.json").read_bytes())
        self.assertEqual(len(d2.responses), 2)
        self.assertEqual(d3.responses, ())
        with self.assertRaises(ReplayAuthoringError) as captured:
            validate_formal_replay_pair_v1(d2, d3)
        self.assertEqual(captured.exception.code, "formal_replay_incomplete")

        output = self.root / "published"
        published = publish_replay_authoring_v1(
            self.task,
            self.sealed,
            self.draft,
            output,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )
        self.assertEqual(published.status, "published")
        self.assertEqual((output / "d2.json").read_bytes(), d2.to_bytes())
        self.assertEqual((output / "d3.json").read_bytes(), d3.to_bytes())

    def test_stale_and_structurally_invalid_responses_do_not_mutate_draft(self) -> None:
        first = self._inspect()
        second = self._append(
            first, {"action": "inventory", "cursor": 0, "limit": 8}
        )
        before = (self.draft / "d2.json").read_bytes()
        stale = ReplayAuthoringResponseV1.from_pending(first, DEFER_RESPONSE)
        with self.assertRaises(ReplayAuthoringError) as captured:
            append_replay_authoring_response_v1(
                self.task,
                self.sealed,
                self.draft,
                stale,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
            )
        self.assertEqual(captured.exception.code, "response_binding_mismatch")
        self.assertEqual((self.draft / "d2.json").read_bytes(), before)

        invalid = ReplayAuthoringResponseV1.from_pending(
            second, {"not_an_action": True}
        )
        with self.assertRaises(ReplayAuthoringError) as captured:
            append_replay_authoring_response_v1(
                self.task,
                self.sealed,
                self.draft,
                invalid,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
            )
        self.assertEqual(captured.exception.code, "response_rejected")
        self.assertEqual((self.draft / "d2.json").read_bytes(), before)

    def test_failed_atomic_replace_preserves_draft_and_exact_layout(self) -> None:
        pending = self._inspect()
        response = ReplayAuthoringResponseV1.from_pending(
            pending, {"action": "inventory", "cursor": 0, "limit": 8}
        )
        before = (self.draft / "d2.json").read_bytes()
        with mock.patch.object(authoring_module.os, "replace", side_effect=OSError):
            with self.assertRaises(ReplayAuthoringError) as captured:
                append_replay_authoring_response_v1(
                    self.task,
                    self.sealed,
                    self.draft,
                    response,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                )
        self.assertEqual(captured.exception.code, "update_failed")
        self.assertFalse(captured.exception.committed)
        self.assertEqual((self.draft / "d2.json").read_bytes(), before)
        self.assertEqual(
            {item.name for item in self.draft.iterdir()}, {"d2.json", "d3.json"}
        )
        self.assertEqual(self._inspect().to_bytes(), pending.to_bytes())

    def test_replace_side_effect_then_error_closes_from_exact_readback(self) -> None:
        target = self.draft / "d2.json"
        expected_wire = target.read_bytes()
        replacement_wire = b'{"committed":"replacement"}\n'
        original_replace = authoring_module.os.replace

        for failure in (
            OSError("late replace failure"),
            KeyboardInterrupt(),
            BaseException("late replace interruption"),
        ):
            with self.subTest(failure=type(failure).__name__):
                target.write_bytes(expected_wire)

                def replace_then_raise(source, destination):
                    original_replace(source, destination)
                    raise failure

                with mock.patch.object(
                    authoring_module.os,
                    "replace",
                    side_effect=replace_then_raise,
                ):
                    authoring_module._replace_draft_member(
                        self.draft,
                        filename="d2.json",
                        expected_wire=expected_wire,
                        replacement_wire=replacement_wire,
                    )
                self.assertEqual(target.read_bytes(), replacement_wire)
                self.assertEqual(
                    {item.name for item in self.draft.iterdir()},
                    {"d2.json", "d3.json"},
                )

    def test_precommit_replace_interrupt_is_preserved(self) -> None:
        target = self.draft / "d2.json"
        expected_wire = target.read_bytes()
        with mock.patch.object(
            authoring_module.os, "replace", side_effect=KeyboardInterrupt()
        ):
            with self.assertRaises(KeyboardInterrupt):
                authoring_module._replace_draft_member(
                    self.draft,
                    filename="d2.json",
                    expected_wire=expected_wire,
                    replacement_wire=b'{"not":"committed"}\n',
                )
        self.assertEqual(target.read_bytes(), expected_wire)
        self.assertEqual(
            {item.name for item in self.draft.iterdir()}, {"d2.json", "d3.json"}
        )

    def test_replace_error_with_interrupted_readback_is_committed_uncertain(
        self,
    ) -> None:
        target = self.draft / "d2.json"
        expected_wire = target.read_bytes()
        replacement_wire = b'{"committed":"replacement"}\n'
        original_replace = authoring_module.os.replace

        def replace_then_raise(source, destination):
            original_replace(source, destination)
            raise OSError("late replace failure")

        with (
            mock.patch.object(
                authoring_module.os, "replace", side_effect=replace_then_raise
            ),
            mock.patch.object(
                authoring_module,
                "_draft_replacement_state_after_error",
                side_effect=KeyboardInterrupt(),
            ),
            self.assertRaises(ReplayAuthoringError) as captured,
        ):
            authoring_module._replace_draft_member(
                self.draft,
                filename="d2.json",
                expected_wire=expected_wire,
                replacement_wire=replacement_wire,
            )
        self.assertEqual(captured.exception.code, "update_uncertain")
        self.assertTrue(captured.exception.committed)
        self.assertEqual(target.read_bytes(), replacement_wire)

    def test_out_of_order_unused_and_deferred_d3_drafts_fail_closed(self) -> None:
        first = self._inspect()
        second = self._append(
            first, {"action": "inventory", "cursor": 0, "limit": 8}
        )
        closed = self._append(second, DEFER_RESPONSE)
        self.assertEqual(closed.status, "closed")
        valid_d2 = OciReplayConfigV1.from_bytes(
            (self.draft / "d2.json").read_bytes()
        )
        self.assertEqual(len(valid_d2.responses), 2)

        out_of_order = OciReplayConfigV1(
            task_id=TASK_ID,
            role="d2",
            responses=tuple(reversed(valid_d2.responses)),
        )
        (self.draft / "d2.json").write_bytes(out_of_order.to_bytes())
        with self.assertRaises(ReplayAuthoringError) as captured:
            self._inspect()
        self.assertEqual(captured.exception.code, "draft_invalid")

        extra = ReplayResponse(
            stage="plan",
            request={"fixture": "unused"},
            response=DEFER_RESPONSE,
        )
        unused = OciReplayConfigV1(
            task_id=TASK_ID,
            role="d2",
            responses=(*valid_d2.responses, extra),
        )
        (self.draft / "d2.json").write_bytes(unused.to_bytes())
        with self.assertRaises(ReplayAuthoringError) as captured:
            self._inspect()
        self.assertEqual(captured.exception.code, "draft_invalid")

        (self.draft / "d2.json").write_bytes(valid_d2.to_bytes())
        invalid_d3 = OciReplayConfigV1(
            task_id=TASK_ID,
            role="d3",
            responses=(extra,),
        )
        (self.draft / "d3.json").write_bytes(invalid_d3.to_bytes())
        with self.assertRaises(ReplayAuthoringError) as captured:
            self._inspect()
        self.assertEqual(captured.exception.code, "draft_invalid")

    def test_response_digest_and_task_are_bound(self) -> None:
        pending = self._inspect()
        response = ReplayAuthoringResponseV1.from_pending(pending, DEFER_RESPONSE)
        raw = response.to_bytes()
        tampered = raw.replace(response.response_sha256.encode("ascii"), b"0" * 64)
        with self.assertRaises(ReplayAuthoringError) as captured:
            ReplayAuthoringResponseV1.from_bytes(tampered)
        self.assertEqual(captured.exception.code, "invalid_binding")

    def test_repeated_request_occurrence_and_prefix_bind_d2_to_d3_path(self) -> None:
        with (
            mock.patch(
                "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryAttemptController",
                self._repeating_d2_controller(),
            ),
            mock.patch(
                "vulngym_agent.orchestrator.discovery_pipeline.SourceDiscoveryReviewerController",
                self._d3_deferred_controller(),
            ),
        ):
            first = self._inspect()
            self.assertEqual((first.role, first.occurrence), ("d2", 1))
            first_envelope = ReplayAuthoringResponseV1.from_pending(
                first, {"fixture_response": 1}
            )
            second = self._append(first, {"fixture_response": 1})
            self.assertEqual((second.role, second.occurrence), ("d2", 2))
            self.assertEqual(second.request_sha256, first.request_sha256)
            self.assertNotEqual(
                second.prefix_config_sha256, first.prefix_config_sha256
            )

            before = (self.draft / "d2.json").read_bytes()
            with self.assertRaises(ReplayAuthoringError) as captured:
                append_replay_authoring_response_v1(
                    self.task,
                    self.sealed,
                    self.draft,
                    first_envelope,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                )
            self.assertEqual(captured.exception.code, "response_binding_mismatch")
            self.assertEqual((self.draft / "d2.json").read_bytes(), before)

            d3_pending = self._append(second, {"fixture_response": 2})
            self.assertEqual((d3_pending.role, d3_pending.occurrence), ("d3", 1))
            closed = self._append(d3_pending, {"fixture_response": "review"})
            self.assertEqual(closed.run_outcome, "d3_deferred")
            self.assertEqual(
                (
                    closed.candidate_count,
                    closed.finding_count,
                    closed.reviewer_verdict_count,
                    closed.reviewer_accept_count,
                    closed.reviewer_reject_count,
                    closed.reviewer_defer_count,
                ),
                (1, 0, 0, 0, 0, 0),
            )

        d2 = OciReplayConfigV1.from_bytes((self.draft / "d2.json").read_bytes())
        d3 = OciReplayConfigV1.from_bytes((self.draft / "d3.json").read_bytes())
        self.assertEqual(len(d2.responses), 2)
        self.assertEqual(d2.responses[0].request_sha256, d2.responses[1].request_sha256)
        self.assertEqual(len(d3.responses), 1)
        validate_formal_replay_pair_v1(d2, d3)
        with self.assertRaises(ReplayAuthoringError):
            validate_empty_smoke_replay_pair_v1(d2, d3)

    def test_api_rejects_overlapping_domains_and_detects_draft_pollution(self) -> None:
        before_d2 = (self.draft / "d2.json").read_bytes()
        before_d3 = (self.draft / "d3.json").read_bytes()
        for sealed in (self.draft, self.root):
            with self.subTest(sealed=sealed.name):
                with self.assertRaises(ReplayAuthoringError) as captured:
                    inspect_replay_authoring_v1(
                        self.task,
                        sealed,
                        self.draft,
                        attestation_key=KEY,
                        expected_key_id=KEY_ID,
                    )
                self.assertEqual(captured.exception.code, "path_overlap")
                self.assertEqual((self.draft / "d2.json").read_bytes(), before_d2)
                self.assertEqual((self.draft / "d3.json").read_bytes(), before_d3)

        sealed_guard = authoring_module._guard_existing_directory(self.sealed)
        draft_guard = authoring_module._guard_existing_directory(self.draft)
        aliased_draft_guard = authoring_module._DirectoryGuard(
            path=draft_guard.path,
            object_identity=draft_guard.object_identity,
            chain=(
                *draft_guard.chain[:-1],
                (self.sealed, sealed_guard.object_identity[:2]),
                draft_guard.chain[-1],
            ),
        )
        with (
            mock.patch.object(
                authoring_module,
                "_guard_existing_directory",
                side_effect=(sealed_guard, aliased_draft_guard),
            ),
            self.assertRaises(ReplayAuthoringError) as captured,
        ):
            self._inspect()
        self.assertEqual(captured.exception.code, "path_overlap")
        self.assertEqual((self.draft / "d2.json").read_bytes(), before_d2)
        self.assertEqual((self.draft / "d3.json").read_bytes(), before_d3)

        with self.assertRaises(ReplayAuthoringError) as captured:
            publish_replay_authoring_v1(
                self.task,
                self.sealed,
                self.draft,
                self.draft / "nested-output",
                attestation_key=KEY,
                expected_key_id=KEY_ID,
            )
        self.assertEqual(captured.exception.code, "path_overlap")
        self.assertEqual((self.draft / "d2.json").read_bytes(), before_d2)
        self.assertEqual((self.draft / "d3.json").read_bytes(), before_d3)

        original_execute = authoring_module._execute_prefix
        intruder = self.draft / "unexpected.json"

        def polluting_execute(*args, **kwargs):
            result = original_execute(*args, **kwargs)
            intruder.write_bytes(b"{}\n")
            return result

        with mock.patch.object(
            authoring_module, "_execute_prefix", side_effect=polluting_execute
        ):
            with self.assertRaises(ReplayAuthoringError):
                self._inspect()
        self.assertEqual((self.draft / "d2.json").read_bytes(), before_d2)
        self.assertEqual((self.draft / "d3.json").read_bytes(), before_d3)
        intruder.unlink()

    def test_exclusive_write_and_failed_publication_clean_precommit_files(self) -> None:
        partial = self.root / "partial.json"
        with mock.patch.object(authoring_module.os, "write", side_effect=OSError):
            with self.assertRaises(OSError):
                authoring_module._write_exclusive(partial, b"payload")
        self.assertFalse(partial.exists())

        output = self.root / "failed-publication"
        original_write = authoring_module._write_exclusive
        calls = 0

        def fail_second(path, payload):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected write failure")
            return original_write(path, payload)

        with mock.patch.object(
            authoring_module, "_write_exclusive", side_effect=fail_second
        ):
            with self.assertRaises(ReplayAuthoringError) as captured:
                initialize_replay_authoring_v1(TASK_ID, output)
        self.assertEqual(captured.exception.code, "publication_failed")
        self.assertFalse(captured.exception.committed)
        self.assertFalse(output.exists())
        self.assertFalse(
            any(
                item.name.startswith(f".{output.name}.replay-authoring-")
                for item in self.root.iterdir()
            )
        )

    def test_publication_side_effect_then_error_closes_from_exact_readback(self) -> None:
        original_rename = authoring_module._rename_directory_noreplace

        for index, failure in enumerate(
            (
                OSError("late rename failure"),
                KeyboardInterrupt(),
                BaseException("late rename interruption"),
            ),
            start=1,
        ):
            with self.subTest(failure=type(failure).__name__):
                output = self.root / f"committed-publication-{index}"

                def rename_then_raise(source, destination):
                    original_rename(source, destination)
                    raise failure

                with mock.patch.object(
                    authoring_module,
                    "_rename_directory_noreplace",
                    side_effect=rename_then_raise,
                ):
                    summary = initialize_replay_authoring_v1(TASK_ID, output)
                self.assertEqual(summary.task_id, TASK_ID)
                self.assertEqual(summary.status, "initialized")
                self.assertEqual(
                    {item.name for item in output.iterdir()},
                    {"d2.json", "d3.json"},
                )
                self.assertEqual(
                    OciReplayConfigV1.from_bytes(
                        (output / "d2.json").read_bytes()
                    ).role,
                    "d2",
                )

    def test_init_summary_control_flow_failures_are_precommit(self) -> None:
        for index, failure in enumerate(
            (KeyboardInterrupt(), BaseException("summary interrupted")),
            start=1,
        ):
            with self.subTest(failure=type(failure).__name__):
                output = self.root / f"summary-interrupted-{index}"
                with (
                    mock.patch.object(
                        authoring_module, "_summary", side_effect=failure
                    ),
                    self.assertRaises(type(failure)) as captured,
                ):
                    initialize_replay_authoring_v1(TASK_ID, output)
                self.assertIs(captured.exception, failure)
                self.assertFalse(output.exists())
                self.assertFalse(
                    any(
                        item.name.startswith(
                            f".{output.name}.replay-authoring-"
                        )
                        for item in self.root.iterdir()
                    )
                )

    def test_cli_init_summary_interrupt_is_proven_precommit(self) -> None:
        output = self.root / "cli-summary-interrupted"
        args = SimpleNamespace(
            command="init",
            draft_root=output,
            task_file=self.root / "task-input.json",
        )
        parser = SimpleNamespace(parse_args=lambda _argv: args)
        stream = io.StringIO()
        with (
            mock.patch.object(authoring_cli, "_parser", return_value=parser),
            mock.patch.object(authoring_cli, "_assert_no_overlap"),
            mock.patch.object(authoring_cli, "_task", return_value=self.task),
            mock.patch.object(
                authoring_module, "_summary", side_effect=KeyboardInterrupt()
            ),
            mock.patch.object(authoring_cli.sys, "stderr", stream),
        ):
            self.assertEqual(
                authoring_cli.main([]), authoring_cli.EXIT_INTERRUPTED
            )
        self.assertEqual(
            stream.getvalue(),
            "error[interrupted]: replay authoring failed\n",
        )
        self.assertFalse(output.exists())
        self.assertFalse(
            any(
                item.name.startswith(f".{output.name}.replay-authoring-")
                for item in self.root.iterdir()
            )
        )

    def test_precommit_publication_interrupt_is_preserved_and_cleaned(self) -> None:
        output = self.root / "interrupted-publication"
        with mock.patch.object(
            authoring_module,
            "_rename_directory_noreplace",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                initialize_replay_authoring_v1(TASK_ID, output)
        self.assertFalse(output.exists())
        self.assertFalse(
            any(
                item.name.startswith(f".{output.name}.replay-authoring-")
                for item in self.root.iterdir()
            )
        )

    def test_publication_error_with_interrupted_readback_is_committed_uncertain(
        self,
    ) -> None:
        output = self.root / "publication-readback-interrupted"
        original_rename = authoring_module._rename_directory_noreplace

        def rename_then_raise(source, destination):
            original_rename(source, destination)
            raise OSError("late rename failure")

        with (
            mock.patch.object(
                authoring_module,
                "_rename_directory_noreplace",
                side_effect=rename_then_raise,
            ),
            mock.patch.object(
                authoring_module,
                "_pair_publication_state_after_error",
                side_effect=KeyboardInterrupt(),
            ),
            self.assertRaises(ReplayAuthoringError) as captured,
        ):
            initialize_replay_authoring_v1(TASK_ID, output)
        self.assertEqual(captured.exception.code, "publication_uncertain")
        self.assertTrue(captured.exception.committed)
        self.assertEqual(
            {item.name for item in output.iterdir()}, {"d2.json", "d3.json"}
        )

    def test_post_replace_scan_and_reload_failures_are_committed_uncertain(self) -> None:
        pending = self._inspect()
        response = ReplayAuthoringResponseV1.from_pending(
            pending, {"action": "inventory", "cursor": 0, "limit": 8}
        )
        original_scan = authoring_module._scan_draft_root
        scan_calls = 0

        def fail_postcommit_scan(root):
            nonlocal scan_calls
            scan_calls += 1
            if scan_calls == 8:
                raise ReplayAuthoringError("input_changed", "injected scan failure")
            return original_scan(root)

        with mock.patch.object(
            authoring_module, "_scan_draft_root", side_effect=fail_postcommit_scan
        ):
            with self.assertRaises(ReplayAuthoringError) as captured:
                append_replay_authoring_response_v1(
                    self.task,
                    self.sealed,
                    self.draft,
                    response,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                )
        self.assertEqual(captured.exception.code, "update_uncertain")
        self.assertTrue(captured.exception.committed)
        committed = OciReplayConfigV1.from_bytes(
            (self.draft / "d2.json").read_bytes()
        )
        self.assertEqual(len(committed.responses), 1)

        second = self._inspect()
        second_response = ReplayAuthoringResponseV1.from_pending(
            second, DEFER_RESPONSE
        )
        original_load = authoring_module._load_draft_pair
        load_calls = 0

        def fail_final_reload(*args, **kwargs):
            nonlocal load_calls
            load_calls += 1
            if load_calls == 4:
                raise ReplayAuthoringError("input_changed", "injected reload failure")
            return original_load(*args, **kwargs)

        with mock.patch.object(
            authoring_module, "_load_draft_pair", side_effect=fail_final_reload
        ):
            with self.assertRaises(ReplayAuthoringError) as captured:
                append_replay_authoring_response_v1(
                    self.task,
                    self.sealed,
                    self.draft,
                    second_response,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                )
        self.assertEqual(captured.exception.code, "update_uncertain")
        self.assertTrue(captured.exception.committed)
        closed = self._inspect()
        self.assertEqual(closed.run_outcome, "d2_deferred")

    def test_empty_smoke_static_validation_is_explicit(self) -> None:
        d2 = OciReplayConfigV1.from_bytes((self.draft / "d2.json").read_bytes())
        d3 = OciReplayConfigV1.from_bytes((self.draft / "d3.json").read_bytes())
        validate_empty_smoke_replay_pair_v1(d2, d3)
        with self.assertRaises(ReplayAuthoringError) as captured:
            validate_formal_replay_pair_v1(d2, d3)
        self.assertEqual(captured.exception.code, "formal_replay_incomplete")

    def test_cli_failures_are_path_free_and_never_escape(self) -> None:
        init_args = SimpleNamespace(
            command="init",
            draft_root=self.root / "unused-output",
            task_file=self.root / "task-input.json",
        )

        def parser_for(value):
            return SimpleNamespace(parse_args=lambda _argv: value)

        for failure, expected_text in (
            (BrokenPipeError(), "error[committed_uncertain]"),
            (ValueError("flush failed"), "error[committed_uncertain]"),
            (KeyboardInterrupt(), "error[committed_uncertain]"),
            (BaseException("output interrupted"), "error[committed_uncertain]"),
        ):
            stream = io.StringIO()
            with (
                mock.patch.object(authoring_cli, "_parser", return_value=parser_for(init_args)),
                mock.patch.object(authoring_cli, "_assert_no_overlap"),
                mock.patch.object(authoring_cli, "_task", return_value=self.task),
                mock.patch.object(
                    authoring_cli,
                    "initialize_replay_authoring_v1",
                    return_value=mock.sentinel.result,
                ),
                mock.patch.object(authoring_cli, "_write_stdout", side_effect=failure),
                mock.patch.object(authoring_cli.sys, "stderr", stream),
            ):
                self.assertEqual(
                    authoring_cli.main([]),
                    authoring_cli.EXIT_COMMITTED_UNCERTAIN,
                )
            self.assertEqual(stream.getvalue(), expected_text + ": replay authoring failed\n")
            self.assertNotIn(str(self.root), stream.getvalue())

        stream = io.StringIO()
        with (
            mock.patch.object(authoring_cli, "_parser", return_value=parser_for(init_args)),
            mock.patch.object(authoring_cli, "_assert_no_overlap"),
            mock.patch.object(authoring_cli, "_task", return_value=self.task),
            mock.patch.object(
                authoring_cli,
                "initialize_replay_authoring_v1",
                side_effect=KeyboardInterrupt(),
            ),
            mock.patch.object(authoring_cli.sys, "stderr", stream),
        ):
            self.assertEqual(authoring_cli.main([]), authoring_cli.EXIT_INTERRUPTED)
        self.assertEqual(
            stream.getvalue(), "error[interrupted]: replay authoring failed\n"
        )

        respond_args = SimpleNamespace(command="respond")

        def returned_mutation(_args, _task, *, mutation_state):
            mutation_state[0] = True
            return mock.sentinel.committed_result

        stream = io.StringIO()
        with (
            mock.patch.object(
                authoring_cli, "_parser", return_value=parser_for(respond_args)
            ),
            mock.patch.object(authoring_cli, "_validate_mutating_paths"),
            mock.patch.object(authoring_cli, "_task", return_value=self.task),
            mock.patch.object(
                authoring_cli, "_run_with_key", side_effect=returned_mutation
            ),
            mock.patch.object(
                authoring_cli, "_write_stdout", side_effect=KeyboardInterrupt()
            ),
            mock.patch.object(authoring_cli.sys, "stderr", stream),
        ):
            self.assertEqual(
                authoring_cli.main([]),
                authoring_cli.EXIT_COMMITTED_UNCERTAIN,
            )
        self.assertEqual(
            stream.getvalue(),
            "error[committed_uncertain]: replay authoring failed\n",
        )

        next_args = SimpleNamespace(command="next-request")
        for failure, expected_code, expected_text in (
            (OSError("read-only output failed"), 2, "error[output_failed]"),
            (KeyboardInterrupt(), 130, "error[interrupted]"),
            (BaseException("read-only output interrupted"), 130, "error[interrupted]"),
        ):
            stream = io.StringIO()
            with (
                mock.patch.object(
                    authoring_cli, "_parser", return_value=parser_for(next_args)
                ),
                mock.patch.object(authoring_cli, "_validate_mutating_paths"),
                mock.patch.object(authoring_cli, "_task", return_value=self.task),
                mock.patch.object(
                    authoring_cli,
                    "_run_with_key",
                    return_value=mock.sentinel.read_only_result,
                ),
                mock.patch.object(
                    authoring_cli, "_write_stdout", side_effect=failure
                ),
                mock.patch.object(authoring_cli.sys, "stderr", stream),
            ):
                self.assertEqual(authoring_cli.main([]), expected_code)
            self.assertEqual(
                stream.getvalue(), expected_text + ": replay authoring failed\n"
            )

        snapshot_error = SnapshotBatchError(
            "unsafe_path",
            f"must not leak {self.root}",
            exit_status=2,
        )
        stream = io.StringIO()
        with (
            mock.patch.object(authoring_cli, "_parser", return_value=parser_for(next_args)),
            mock.patch.object(
                authoring_cli,
                "_validate_mutating_paths",
                side_effect=snapshot_error,
            ),
            mock.patch.object(authoring_cli.sys, "stderr", stream),
        ):
            self.assertEqual(authoring_cli.main([]), 2)
        self.assertEqual(
            stream.getvalue(),
            "error[input_rejected]: replay authoring failed\n",
        )
        self.assertNotIn(str(self.root), stream.getvalue())

    def test_cli_marks_mutation_before_core_call_and_resets_proven_precommit_interrupt(
        self,
    ) -> None:
        args = SimpleNamespace(
            command="respond",
            key_file=self.root / "key",
            response_file=self.root / "response",
            sealed_bundle_root=self.sealed,
            draft_root=self.draft,
            key_id=KEY_ID,
        )
        response = mock.sentinel.response
        state = [False]

        def committed_call(*_args, **_kwargs):
            self.assertTrue(state[0])
            return mock.sentinel.result

        with (
            mock.patch.object(
                authoring_cli,
                "read_attestation_key_file_v1",
                return_value=bytearray(KEY),
            ),
            mock.patch.object(
                authoring_cli,
                "read_authoring_response_file_v1",
                return_value=response,
            ),
            mock.patch.object(
                authoring_cli,
                "append_replay_authoring_response_v1",
                side_effect=committed_call,
            ),
        ):
            result = authoring_cli._run_with_key(
                args, self.task, mutation_state=state
            )
        self.assertIs(result, mock.sentinel.result)
        self.assertTrue(state[0])

        state = [False]
        with (
            mock.patch.object(
                authoring_cli,
                "read_attestation_key_file_v1",
                return_value=bytearray(KEY),
            ),
            mock.patch.object(
                authoring_cli,
                "read_authoring_response_file_v1",
                return_value=response,
            ),
            mock.patch.object(
                authoring_cli,
                "append_replay_authoring_response_v1",
                side_effect=KeyboardInterrupt(),
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            authoring_cli._run_with_key(
                args, self.task, mutation_state=state
            )
        self.assertFalse(state[0])

        state = [False]

        def initialized_call(*_args, **_kwargs):
            self.assertTrue(state[0])
            return mock.sentinel.initialized

        with mock.patch.object(
            authoring_cli,
            "initialize_replay_authoring_v1",
            side_effect=initialized_call,
        ):
            result = authoring_cli._run_init(
                self.task, self.root / "new-draft", mutation_state=state
            )
        self.assertIs(result, mock.sentinel.initialized)
        self.assertTrue(state[0])

        state = [False]
        with (
            mock.patch.object(
                authoring_cli,
                "initialize_replay_authoring_v1",
                side_effect=KeyboardInterrupt(),
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            authoring_cli._run_init(
                self.task, self.root / "new-draft", mutation_state=state
            )
        self.assertFalse(state[0])

    def test_cli_init_step_respond_and_finalize(self) -> None:
        task_file = self.root / "task.json"
        task_wire = (
            json.dumps(
                self.task.to_dict(),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        task_file.write_bytes(task_wire)
        task_file.chmod(0o600)
        key_file = self.root / "snapshot.key"
        key_file.write_bytes(KEY)
        key_file.chmod(0o600)
        task_digest = hashlib.sha256(task_wire).hexdigest()
        cli_draft = self.root / "cli-draft"

        initialized = self._cli(
            "init",
            "--task-file",
            task_file,
            "--expected-task-wire-sha256",
            task_digest,
            "--draft-root",
            cli_draft,
        )
        self.assertEqual((initialized.returncode, initialized.stderr), (0, b""))
        self.assertEqual(json.loads(initialized.stdout)["status"], "initialized")

        common = (
            "--task-file",
            task_file,
            "--expected-task-wire-sha256",
            task_digest,
            "--sealed-bundle-root",
            self.sealed,
            "--draft-root",
            cli_draft,
            "--key-file",
            key_file,
            "--key-id",
            KEY_ID,
        )
        requested = self._cli("next-request", *common)
        self.assertEqual((requested.returncode, requested.stderr), (10, b""))
        pending = ReplayAuthoringPendingRequestV1.from_bytes(requested.stdout)

        response_file = self.root / "response.json"
        response_file.write_bytes(
            ReplayAuthoringResponseV1.from_pending(
                pending, DEFER_RESPONSE
            ).to_bytes()
        )
        response_file.chmod(0o600)
        responded = self._cli(
            "respond", *common, "--response-file", response_file
        )
        self.assertEqual((responded.returncode, responded.stderr), (0, b""))
        self.assertEqual(json.loads(responded.stdout)["status"], "closed")

        output = self.root / "cli-published"
        finalized = self._cli("finalize", *common, "--output-root", output)
        self.assertEqual((finalized.returncode, finalized.stderr), (0, b""))
        self.assertEqual(json.loads(finalized.stdout)["status"], "published")
        self.assertEqual(
            {item.name for item in output.iterdir()}, {"d2.json", "d3.json"}
        )


if __name__ == "__main__":
    unittest.main()
