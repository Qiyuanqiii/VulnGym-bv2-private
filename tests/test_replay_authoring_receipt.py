from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID, SnapshotTaskSpec
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.evaluator.replay_authoring import ReplayAuthoringSummaryV1
import vulngym_agent.replay_authoring_receipt as receipt_module
from vulngym_agent.replay_authoring_receipt import (
    REPLAY_RECEIPT_FILENAME_SUFFIX,
    ReplayActorApprovalV1,
    ReplayAuthoringClosureReceiptV1,
    ReplayAuthoringReceiptError,
    ReplayClosureObservationV1,
    build_replay_authoring_index_v1,
    public_task_sha256_v1,
    read_pinned_approval_v1,
    read_pinned_observation_v1,
    readback_published_replay_v1,
    seal_replay_closure_receipt_v1,
)
import vulngym_agent.replay_authoring_receipt_cli as receipt_cli
import vulngym_agent.replay_batch_plan_cli as batch_cli


TASK_ID = "VG-TEST-0123456789ABCDEF0123"
REPO_URL = "https://github.com/example/replay-receipt"
COMMIT = "1" * 40


def _sha(label: bytes | str) -> str:
    payload = label if isinstance(label, bytes) else label.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class ReplayAuthoringReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.task = DiscoveryTaskInputV1(
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=COMMIT,
            instruction_id=INSTRUCTION_ID,
            snapshot_manifest_sha256=_sha("snapshot-manifest"),
            snapshot_content_root=_sha("snapshot-content"),
        )
        self.summary = ReplayAuthoringSummaryV1(
            task_id=TASK_ID,
            status="closed",
            d2_response_count=2,
            d3_response_count=1,
            d2_config_sha256=_sha("d2-semantic"),
            d2_wire_sha256=_sha("d2-wire"),
            d3_config_sha256=_sha("d3-semantic"),
            d3_wire_sha256=_sha("d3-wire"),
            run_outcome="finalized",
            candidate_count=2,
            finding_count=1,
            reviewer_verdict_count=2,
            reviewer_accept_count=1,
            reviewer_reject_count=1,
            reviewer_defer_count=0,
            run_sha256=_sha("run-semantic"),
            run_wire_sha256=_sha("run-wire"),
        )
        self.observation = ReplayClosureObservationV1.from_summary(
            self.task,
            self.summary,
            task_wire_sha256=_sha("task-wire"),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _private_file(path: Path, payload: bytes) -> None:
        path.write_bytes(payload)
        path.chmod(0o600)

    @staticmethod
    def _approvals(
        observation: ReplayClosureObservationV1,
    ) -> tuple[ReplayActorApprovalV1, ...]:
        return tuple(
            ReplayActorApprovalV1.from_observation(
                observation,
                actor_role=role,
                actor_id=f"independent-{role}",
            )
            for role in ("author", "critic", "reviewer")
        )

    def test_observation_three_approvals_and_receipt_round_trip(self) -> None:
        observation = ReplayClosureObservationV1.from_bytes(
            self.observation.to_bytes()
        )
        self.assertEqual(observation, self.observation)
        approvals = tuple(
            ReplayActorApprovalV1.from_bytes(item.to_bytes())
            for item in self._approvals(observation)
        )
        receipt = seal_replay_closure_receipt_v1(observation, approvals)
        parsed = ReplayAuthoringClosureReceiptV1.from_bytes(receipt.to_bytes())
        self.assertEqual(parsed, receipt)
        self.assertEqual(
            tuple(item.actor_role for item in parsed.approvals),
            ("author", "critic", "reviewer"),
        )
        self.assertEqual(len({item.actor_id for item in parsed.approvals}), 3)
        self.assertEqual(parsed.observation.run_outcome, "finalized")
        self.assertEqual(parsed.observation.finding_count, 1)
        serialized = receipt.to_bytes().decode("utf-8")
        self.assertNotIn(str(self.root), serialized)
        self.assertNotIn("published_root", serialized)
        self.assertEqual(receipt.wire_sha256, _sha(receipt.to_bytes()))

    def test_tamper_duplicate_identity_and_stale_approval_are_rejected(self) -> None:
        approvals = self._approvals(self.observation)
        receipt = seal_replay_closure_receipt_v1(self.observation, approvals)
        raw = json.loads(receipt.to_bytes())
        raw["observation"]["finding_count"] = 2
        tampered = (
            json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )
        with self.assertRaises(ReplayAuthoringReceiptError):
            ReplayAuthoringClosureReceiptV1.from_bytes(tampered)

        duplicate_actor = replace(approvals[1], actor_id=approvals[0].actor_id)
        with self.assertRaisesRegex(
            ReplayAuthoringReceiptError, "identities are not distinct"
        ):
            seal_replay_closure_receipt_v1(
                self.observation,
                (approvals[0], duplicate_actor, approvals[2]),
            )

        changed = replace(self.observation, run_sha256=_sha("new-run"))
        with self.assertRaisesRegex(
            ReplayAuthoringReceiptError, "does not bind"
        ):
            seal_replay_closure_receipt_v1(changed, approvals)

    def test_deferred_or_empty_closure_cannot_be_approved(self) -> None:
        deferred_summary = ReplayAuthoringSummaryV1(
            task_id=TASK_ID,
            status="closed",
            d2_response_count=1,
            d3_response_count=1,
            d2_config_sha256=_sha("deferred-d2-semantic"),
            d2_wire_sha256=_sha("deferred-d2-wire"),
            d3_config_sha256=_sha("deferred-d3-semantic"),
            d3_wire_sha256=_sha("deferred-d3-wire"),
            run_outcome="d3_deferred",
            candidate_count=1,
            finding_count=0,
            reviewer_verdict_count=0,
            reviewer_accept_count=0,
            reviewer_reject_count=0,
            reviewer_defer_count=0,
            run_sha256=_sha("deferred-run"),
            run_wire_sha256=_sha("deferred-run-wire"),
        )
        observation = ReplayClosureObservationV1.from_summary(
            self.task,
            deferred_summary,
            task_wire_sha256=_sha("task-wire"),
        )
        with self.assertRaisesRegex(
            ReplayAuthoringReceiptError, "non-empty finalized replay"
        ):
            ReplayActorApprovalV1.from_observation(
                observation, actor_role="author", actor_id="actor-a"
            )

        empty_finalized = replace(
            self.observation,
            candidate_count=0,
            finding_count=0,
            reviewer_verdict_count=0,
            reviewer_accept_count=0,
            reviewer_reject_count=0,
            d2_response_count=0,
        )
        with self.assertRaises(ReplayAuthoringReceiptError):
            ReplayActorApprovalV1.from_observation(
                empty_finalized, actor_role="author", actor_id="actor-a"
            )

    def test_readback_uses_pinned_task_and_closed_production_reader(self) -> None:
        with (
            mock.patch.object(
                receipt_module,
                "read_pinned_authoring_task_v1",
                return_value=self.task,
            ) as read_task,
            mock.patch.object(
                receipt_module,
                "inspect_replay_authoring_v1",
                return_value=self.summary,
            ) as inspect,
        ):
            result = readback_published_replay_v1(
                self.root / "task.json",
                self.root / "published",
                self.root / "sealed",
                expected_task_wire_sha256=_sha("task-wire"),
                attestation_key=b"x" * 32,
                expected_key_id="receipt-test-key",
            )
        self.assertEqual(result, self.observation)
        read_task.assert_called_once_with(
            self.root / "task.json", expected_wire_sha256=_sha("task-wire")
        )
        self.assertEqual(inspect.call_count, 1)
        self.assertEqual(inspect.call_args.args[0], self.task)
        self.assertEqual(inspect.call_args.args[2], self.root / "published")

        pending = mock.Mock(spec=receipt_module.ReplayAuthoringPendingRequestV1)
        with (
            mock.patch.object(
                receipt_module,
                "read_pinned_authoring_task_v1",
                return_value=self.task,
            ),
            mock.patch.object(
                receipt_module,
                "inspect_replay_authoring_v1",
                return_value=pending,
            ),
            self.assertRaises(ReplayAuthoringReceiptError),
        ):
            readback_published_replay_v1(
                self.root / "task.json",
                self.root / "published",
                self.root / "sealed",
                expected_task_wire_sha256=_sha("task-wire"),
                attestation_key=b"x" * 32,
                expected_key_id="receipt-test-key",
            )

    def test_pinned_observation_and_approval_require_semantic_and_wire_pins(self) -> None:
        observation_file = self.root / "observation.json"
        self._private_file(observation_file, self.observation.to_bytes())
        self.assertEqual(
            read_pinned_observation_v1(
                observation_file,
                expected_sha256=self.observation.observation_sha256,
                expected_wire_sha256=self.observation.wire_sha256,
            ),
            self.observation,
        )
        with self.assertRaisesRegex(
            ReplayAuthoringReceiptError, "wire pin differs"
        ):
            read_pinned_observation_v1(
                observation_file,
                expected_sha256=self.observation.observation_sha256,
                expected_wire_sha256="0" * 64,
            )

        approval = self._approvals(self.observation)[0]
        approval_file = self.root / "approval.json"
        self._private_file(approval_file, approval.to_bytes())
        self.assertEqual(
            read_pinned_approval_v1(
                approval_file,
                expected_sha256=approval.approval_sha256,
                expected_wire_sha256=approval.wire_sha256,
            ),
            approval,
        )
        with self.assertRaisesRegex(
            ReplayAuthoringReceiptError, "semantic pin differs"
        ):
            read_pinned_approval_v1(
                approval_file,
                expected_sha256="0" * 64,
                expected_wire_sha256=approval.wire_sha256,
            )


class ReplayAuthoringIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.benchmark = self.root / "benchmark"
        self.benchmark.mkdir(mode=0o700)
        self.receipts = self.root / "receipts"
        self.receipts.mkdir(mode=0o700)
        self.tasks = {
            split: self._tasks(split) for split in ("test", "train")
        }
        self._write_all_receipts()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _tasks(split: str) -> tuple[SnapshotTaskSpec, ...]:
        count = 20 if split == "test" else 50
        return tuple(
            SnapshotTaskSpec(
                task_id=f"VG-{split.upper()}-{index:020X}",
                repo_url=f"https://github.com/example/{split}-repo-{index}",
                commit=f"{index + (1 if split == 'test' else 101):040x}",
                split=split,
            )
            for index in range(count)
        )

    @staticmethod
    def _receipt(
        task: SnapshotTaskSpec, *, ordinal: int
    ) -> ReplayAuthoringClosureReceiptV1:
        observation = ReplayClosureObservationV1(
            task_id=task.task_id,
            split=task.split,
            task_wire_sha256=_sha(f"task-wire:{task.task_id}"),
            public_task_sha256=public_task_sha256_v1(
                task_id=task.task_id,
                repo_url=task.repo_url,
                commit=task.commit,
                instruction_id=task.instruction_id,
                split=task.split,
            ),
            d2_sha256=_sha(f"d2:{ordinal}:semantic"),
            d2_wire_sha256=_sha(f"d2:{ordinal}:wire"),
            d3_sha256=_sha(f"d3:{ordinal}:semantic"),
            d3_wire_sha256=_sha(f"d3:{ordinal}:wire"),
            d2_response_count=2,
            d3_response_count=1,
            run_sha256=_sha(f"run:{ordinal}:semantic"),
            run_wire_sha256=_sha(f"run:{ordinal}:wire"),
            run_outcome="finalized",
            candidate_count=1,
            finding_count=1,
            reviewer_verdict_count=1,
            reviewer_accept_count=1,
            reviewer_reject_count=0,
            reviewer_defer_count=0,
        )
        approvals = tuple(
            ReplayActorApprovalV1.from_observation(
                observation,
                actor_role=role,
                actor_id=f"{role}-agent-{ordinal}",
            )
            for role in ("author", "critic", "reviewer")
        )
        return seal_replay_closure_receipt_v1(observation, approvals)

    def _write_all_receipts(self) -> None:
        ordinal = 0
        for split in ("test", "train"):
            for task in self.tasks[split]:
                ordinal += 1
                receipt = self._receipt(task, ordinal=ordinal)
                path = self.receipts / (
                    task.task_id + REPLAY_RECEIPT_FILENAME_SUFFIX
                )
                path.write_bytes(receipt.to_bytes())
                path.chmod(0o600)

    def _load_tasks(self, _root: Path, *, split: str):
        return self.tasks[split]

    def test_builds_exact_index_accepted_by_existing_batch_plan_reader(self) -> None:
        with mock.patch.object(
            receipt_module,
            "load_answer_free_tasks",
            side_effect=self._load_tasks,
        ):
            index = build_replay_authoring_index_v1(
                self.benchmark, self.receipts
            )
        self.assertEqual(len(index.tasks), 70)
        self.assertEqual(
            tuple(item.split for item in index.tasks[:20]), ("test",) * 20
        )
        self.assertEqual(
            tuple(item.split for item in index.tasks[20:]), ("train",) * 50
        )
        index_file = self.root / "authoring-index.json"
        index_file.write_bytes(index.to_bytes())
        index_file.chmod(0o600)
        expected_tasks = tuple(
            (split, task.task_id)
            for split in ("test", "train")
            for task in self.tasks[split]
        )
        loaded = batch_cli._load_authoring_index(
            index_file,
            expected_sha256=index.index_sha256,
            expected_wire_sha256=index.wire_sha256,
            expected_tasks=expected_tasks,
        )
        self.assertEqual(len(loaded), 70)
        self.assertEqual(
            loaded[self.tasks["test"][0].task_id],
            (
                index.tasks[0].d2_sha256,
                index.tasks[0].d2_wire_sha256,
                index.tasks[0].d3_sha256,
                index.tasks[0].d3_wire_sha256,
            ),
        )

    def test_index_rejects_missing_extra_and_wrong_public_identity(self) -> None:
        first = self.tasks["test"][0]
        first_path = self.receipts / (
            first.task_id + REPLAY_RECEIPT_FILENAME_SUFFIX
        )
        original = first_path.read_bytes()
        first_path.unlink()
        with (
            mock.patch.object(
                receipt_module,
                "load_answer_free_tasks",
                side_effect=self._load_tasks,
            ),
            self.assertRaisesRegex(
                ReplayAuthoringReceiptError, "membership is invalid"
            ),
        ):
            build_replay_authoring_index_v1(self.benchmark, self.receipts)
        first_path.write_bytes(original)
        first_path.chmod(0o600)

        extra = self.receipts / "extra.json"
        extra.write_bytes(b"{}\n")
        extra.chmod(0o600)
        with (
            mock.patch.object(
                receipt_module,
                "load_answer_free_tasks",
                side_effect=self._load_tasks,
            ),
            self.assertRaises(ReplayAuthoringReceiptError),
        ):
            build_replay_authoring_index_v1(self.benchmark, self.receipts)
        extra.unlink()

        wrong_task = replace(first, repo_url="https://github.com/example/wrong")
        wrong_receipt = self._receipt(wrong_task, ordinal=1)
        first_path.write_bytes(wrong_receipt.to_bytes())
        first_path.chmod(0o600)
        with (
            mock.patch.object(
                receipt_module,
                "load_answer_free_tasks",
                side_effect=self._load_tasks,
            ),
            self.assertRaisesRegex(
                ReplayAuthoringReceiptError, "public task identity"
            ),
        ):
            build_replay_authoring_index_v1(self.benchmark, self.receipts)

    def test_cli_approve_is_canonical_and_pin_bound(self) -> None:
        first_task = self.tasks["test"][0]
        receipt = ReplayAuthoringClosureReceiptV1.from_bytes(
            (
                self.receipts
                / (first_task.task_id + REPLAY_RECEIPT_FILENAME_SUFFIX)
            ).read_bytes()
        )
        observation = receipt.observation
        path = self.root / "observation.json"
        path.write_bytes(observation.to_bytes())
        path.chmod(0o600)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = receipt_cli.main(
                [
                    "approve",
                    "--observation-file",
                    str(path),
                    "--expected-observation-sha256",
                    observation.observation_sha256,
                    "--expected-observation-wire-sha256",
                    observation.wire_sha256,
                    "--actor-role",
                    "critic",
                    "--actor-id",
                    "critic-web-agent",
                ]
            )
        self.assertEqual((status, stderr.getvalue()), (0, ""))
        approval = ReplayActorApprovalV1.from_bytes(
            stdout.getvalue().encode("utf-8")
        )
        self.assertEqual(
            (approval.actor_role, approval.actor_id),
            ("critic", "critic-web-agent"),
        )


if __name__ == "__main__":
    unittest.main()
