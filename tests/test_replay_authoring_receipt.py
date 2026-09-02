from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID, SnapshotTaskSpec
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.harness import PROFILE_ID
from vulngym_agent.benchmark.snapshot_batch import (
    SnapshotBatchSummary,
    SnapshotBatchTask,
)
from vulngym_agent.evaluator.replay_authoring import ReplayAuthoringSummaryV1
import vulngym_agent.replay_authoring_receipt as receipt_module
from vulngym_agent.replay_authoring_receipt import (
    REPLAY_RECEIPT_FILENAME_SUFFIX,
    ReplayActorApprovalV2,
    ReplayActorKeyRegistrationV2,
    ReplayAuthoringClosureReceiptV2,
    ReplayAuthoringIndexV2,
    ReplayAuthoringReceiptError,
    ReplayClosureObservationV2,
    ReplaySourceBindingV2,
    ReplayTrustKeyRegistrationV2,
    ReplayTrustRegistryV2,
    build_replay_authoring_index_v2,
    public_task_sha256_v1,
    read_pinned_approval_v2,
    read_pinned_observation_v2,
    readback_published_replay_v2,
    replay_ed25519_public_key_from_private_v2,
    replay_key_fingerprint_v2,
    seal_replay_closure_receipt_v2,
    verify_published_replay_observation_v2,
)
from vulngym_agent.replay_task_response_cli import (
    DiscoveryTaskFilePinV1,
    DiscoveryTaskSplitExportIndexV1,
    VerifiedDiscoveryTaskSplitExportV1,
)
import vulngym_agent.replay_authoring_receipt_cli as receipt_cli
import vulngym_agent.replay_batch_plan_cli as batch_cli


RUNTIME_TMP = (
    Path(r"D:\VulnGym-bv2-runtime\tmp")
    if os.name == "nt"
    else Path(tempfile.gettempdir()) / "VulnGym-bv2-runtime" / "tmp"
).resolve()
TASK_ID = "VG-TEST-0123456789ABCDEF0123"
REPO_URL = "https://github.com/example/replay-receipt"
COMMIT = "1" * 40
ROLES = ("author", "critic", "reviewer")
TRUST_SLOTS = (
    ("actor-approval", "author"),
    ("actor-approval", "critic"),
    ("actor-approval", "reviewer"),
    ("readback-attestation", "test"),
    ("readback-attestation", "train"),
    ("authoring-index", "global"),
)


def _sha(label: bytes | str) -> str:
    payload = label if isinstance(label, bytes) else label.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _key(label: str) -> bytes:
    return hashlib.sha256(("key:" + label).encode("utf-8")).digest()


def _signing_keys(prefix: str = "official") -> dict[tuple[str, str], bytes]:
    return {
        (purpose, role): _key(f"{prefix}:{purpose}:{role}")
        for purpose, role in TRUST_SLOTS
    }


def _registry(
    signing_keys: dict[tuple[str, str], bytes],
) -> ReplayTrustRegistryV2:
    return ReplayTrustRegistryV2(
        keys=tuple(
            ReplayTrustKeyRegistrationV2.from_public_key(
                purpose=purpose,  # type: ignore[arg-type]
                role=role,  # type: ignore[arg-type]
                key_id=f"{purpose}-{role}-key",
                public_key=replay_ed25519_public_key_from_private_v2(
                    signing_keys[(purpose, role)]
                ),
            )
            for purpose, role in TRUST_SLOTS
        )
    )


def _private_file(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def _temporary() -> tempfile.TemporaryDirectory[str]:
    RUNTIME_TMP.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(dir=RUNTIME_TMP)


def _summary(task_id: str, ordinal: int = 1) -> ReplayAuthoringSummaryV1:
    return ReplayAuthoringSummaryV1(
        task_id=task_id,
        status="closed",
        d2_response_count=2,
        d3_response_count=1,
        d2_config_sha256=_sha(f"d2-semantic:{ordinal}"),
        d2_wire_sha256=_sha(f"d2-wire:{ordinal}"),
        d3_config_sha256=_sha(f"d3-semantic:{ordinal}"),
        d3_wire_sha256=_sha(f"d3-wire:{ordinal}"),
        run_outcome="finalized",
        candidate_count=2,
        finding_count=1,
        reviewer_verdict_count=2,
        reviewer_accept_count=1,
        reviewer_reject_count=1,
        reviewer_defer_count=0,
        run_sha256=_sha(f"run-semantic:{ordinal}"),
        run_wire_sha256=_sha(f"run-wire:{ordinal}"),
    )


class ReplayAuthoringReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = _temporary()
        self.root = Path(self.temporary.name).resolve()
        self.snapshot_key = _key("snapshot")
        self.signing_keys = _signing_keys()
        self.trust_registry = _registry(self.signing_keys)
        self.readback_key = self.signing_keys[("readback-attestation", "test")]
        self.actor_keys = {
            role: self.signing_keys[("actor-approval", role)] for role in ROLES
        }
        self.registrations = tuple(
            ReplayActorKeyRegistrationV2.from_trust_registry(
                actor_role=role,
                trust_registry=self.trust_registry,
            )
            for role in ROLES
        )
        self.task = DiscoveryTaskInputV1(
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=COMMIT,
            instruction_id=INSTRUCTION_ID,
            snapshot_manifest_sha256=_sha("snapshot-manifest"),
            snapshot_content_root=_sha("snapshot-content"),
        )
        self.source = ReplaySourceBindingV2(
            split="test",
            task_export_index_sha256=_sha("export-index"),
            task_export_index_wire_sha256=_sha("export-index-wire"),
            tasks_sha256=_sha("tasks"),
            public_manifest_sha256=_sha("public-manifest"),
            sealed_batch_manifest_sha256=_sha("sealed-manifest"),
            sealed_batch_content_root=_sha("sealed-content"),
            sealed_batch_key_id="snapshot-key",
            snapshot_key_fingerprint=replay_key_fingerprint_v2(
                self.snapshot_key
            ),
            readback_key_id=self.trust_registry.registration(
                purpose="readback-attestation", role="test"
            ).key_id,
            readback_key_fingerprint=self.trust_registry.registration(
                purpose="readback-attestation", role="test"
            ).public_key_fingerprint,
            trust_registry_sha256=self.trust_registry.registry_sha256,
            trust_registry_wire_sha256=self.trust_registry.wire_sha256,
        )
        self.observation = ReplayClosureObservationV2.from_summary(
            self.task,
            _summary(TASK_ID),
            task_wire_sha256=_sha("task-wire"),
            source=self.source,
            readback_private_key=self.readback_key,
            trust_registry=self.trust_registry,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_temporary_root_is_absolute(self) -> None:
        self.assertTrue(self.root.is_absolute())

    def _approvals(
        self, observation: ReplayClosureObservationV2 | None = None
    ) -> tuple[ReplayActorApprovalV2, ...]:
        selected = observation or self.observation
        return tuple(
            ReplayActorApprovalV2.from_observation(
                selected,
                actor_role=role,
                actor_private_key=self.actor_keys[role],
                trust_registry=self.trust_registry,
            )
            for role in ROLES
        )

    def _seal(
        self, observation: ReplayClosureObservationV2 | None = None
    ) -> ReplayAuthoringClosureReceiptV2:
        selected = observation or self.observation
        return seal_replay_closure_receipt_v2(
            selected,
            self._approvals(selected),
            trust_registry=self.trust_registry,
        )

    def test_authenticated_round_trip_and_external_pins(self) -> None:
        observation = ReplayClosureObservationV2.from_bytes(
            self.observation.to_bytes()
        )
        observation.verify_readback(
            trust_registry=self.trust_registry,
        )
        receipt = self._seal(observation)
        parsed = ReplayAuthoringClosureReceiptV2.from_bytes(receipt.to_bytes())
        self.assertEqual(parsed, receipt)
        self.assertEqual(
            tuple(item.actor_key_id for item in parsed.approvals),
            tuple(f"actor-approval-{role}-key" for role in ROLES),
        )

        observation_file = self.root / "observation.json"
        _private_file(observation_file, observation.to_bytes())
        self.assertEqual(
            read_pinned_observation_v2(
                observation_file,
                expected_sha256=observation.observation_sha256,
                expected_wire_sha256=observation.wire_sha256,
                trust_registry=self.trust_registry,
            ),
            observation,
        )
        approval = parsed.approvals[0]
        approval_file = self.root / "approval.json"
        _private_file(approval_file, approval.to_bytes())
        self.assertEqual(
            read_pinned_approval_v2(
                approval_file,
                expected_sha256=approval.approval_sha256,
                expected_wire_sha256=approval.wire_sha256,
                trust_registry=self.trust_registry,
            ),
            approval,
        )

    def test_trust_registry_requires_exact_order_uniqueness_and_both_pins(self) -> None:
        payload = self.trust_registry.to_bytes()
        self.assertEqual(
            ReplayTrustRegistryV2.from_bytes(
                payload,
                expected_sha256=self.trust_registry.registry_sha256,
                expected_wire_sha256=self.trust_registry.wire_sha256,
            ),
            self.trust_registry,
        )
        for semantic, wire in (
            ("0" * 64, self.trust_registry.wire_sha256),
            (self.trust_registry.registry_sha256, "0" * 64),
        ):
            with self.subTest(semantic=semantic, wire=wire):
                with self.assertRaises(ReplayAuthoringReceiptError):
                    ReplayTrustRegistryV2.from_bytes(
                        payload,
                        expected_sha256=semantic,
                        expected_wire_sha256=wire,
                    )
        with self.assertRaisesRegex(ReplayAuthoringReceiptError, "reordered"):
            ReplayTrustRegistryV2(
                keys=(
                    self.trust_registry.keys[1],
                    self.trust_registry.keys[0],
                    *self.trust_registry.keys[2:],
                )
            )

    def test_self_signed_registry_wrong_key_and_key_reuse_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            ReplayAuthoringReceiptError, "registered public key"
        ):
            ReplayActorApprovalV2.from_observation(
                self.observation,
                actor_role="author",
                actor_private_key=_key("attacker"),
                trust_registry=self.trust_registry,
            )

        attacker_keys = _signing_keys("attacker")
        attacker_registry = _registry(attacker_keys)
        attacker_readback = attacker_registry.registration(
            purpose="readback-attestation", role="test"
        )
        attacker_source = replace(
            self.source,
            readback_key_id=attacker_readback.key_id,
            readback_key_fingerprint=attacker_readback.public_key_fingerprint,
            trust_registry_sha256=attacker_registry.registry_sha256,
            trust_registry_wire_sha256=attacker_registry.wire_sha256,
        )
        attacker_observation = ReplayClosureObservationV2.from_summary(
            self.task,
            _summary(TASK_ID),
            task_wire_sha256=_sha("task-wire"),
            source=attacker_source,
            readback_private_key=attacker_keys[("readback-attestation", "test")],
            trust_registry=attacker_registry,
        )
        attacker_approvals = tuple(
            ReplayActorApprovalV2.from_observation(
                attacker_observation,
                actor_role=role,
                actor_private_key=attacker_keys[("actor-approval", role)],
                trust_registry=attacker_registry,
            )
            for role in ROLES
        )
        attacker_receipt = seal_replay_closure_receipt_v2(
            attacker_observation,
            attacker_approvals,
            trust_registry=attacker_registry,
        )
        with self.assertRaises(ReplayAuthoringReceiptError):
            receipt_module.authenticate_replay_closure_receipt_v2(
                attacker_receipt, trust_registry=self.trust_registry
            )

        reused_keys = _signing_keys("reused")
        reused_keys[("actor-approval", "critic")] = reused_keys[
            ("actor-approval", "author")
        ]
        with self.assertRaisesRegex(ReplayAuthoringReceiptError, "reuses a key"):
            _registry(reused_keys)

    def test_forged_observation_and_stale_approval_are_rejected(self) -> None:
        forged = replace(
            self.observation,
            run_sha256=_sha("forged-run"),
        )
        with self.assertRaisesRegex(
            ReplayAuthoringReceiptError, "readback attestation is invalid"
        ):
            forged.verify_readback(
                trust_registry=self.trust_registry,
            )
        with self.assertRaisesRegex(ReplayAuthoringReceiptError, "does not bind"):
            seal_replay_closure_receipt_v2(
                forged,
                self._approvals(self.observation),
                trust_registry=self.trust_registry,
            )

    def test_readback_binds_verified_export_and_sealed_batch(self) -> None:
        tasks = tuple(
            DiscoveryTaskInputV1(
                task_id=f"VG-TEST-{index:020X}",
                repo_url=f"https://github.com/example/readback-{index}",
                commit=f"{index + 1:040x}",
                instruction_id=INSTRUCTION_ID,
                snapshot_manifest_sha256=_sha(f"snapshot-manifest:{index}"),
                snapshot_content_root=_sha(f"snapshot-content:{index}"),
            )
            for index in range(20)
        )
        pins = tuple(
            DiscoveryTaskFilePinV1(
                ordinal=index + 1,
                task_id=task.task_id,
                snapshot_id=task.snapshot_id,
                task_file=f"tasks/{task.task_id}.json",
                task_wire_sha256=_sha(f"task-wire:{task.task_id}"),
            )
            for index, task in enumerate(tasks)
        )
        export_index = DiscoveryTaskSplitExportIndexV1(
            split="test",
            tasks_sha256=_sha("test-tasks"),
            public_manifest_sha256=_sha("test-public"),
            sealed_batch_manifest_sha256=_sha("test-batch-manifest"),
            sealed_batch_content_root=_sha("test-batch-root"),
            sealed_batch_key_id="snapshot-key",
            tasks=pins,
        )
        export = VerifiedDiscoveryTaskSplitExportV1(export_index, tasks)
        members = tuple(
            SnapshotBatchTask(
                task_id=task.task_id,
                repo_url=task.repo_url,
                commit=task.commit,
                split="test",
                instruction_id=task.instruction_id,
                snapshot_manifest_sha256=task.snapshot_manifest_sha256,
                snapshot_content_root=task.snapshot_content_root,
                root_tree="0" * 40,
                file_count=0,
                node_count=0,
                total_bytes=0,
                entry_count=0,
                regular_file_count=0,
                gitlink_count=0,
                regular_file_bytes=0,
                materialized_bytes=0,
            )
            for task in tasks
        )
        batch = SnapshotBatchSummary(
            batch_root=self.root / "batch",
            profile_id=PROFILE_ID,
            split="test",
            task_count=20,
            total_files=0,
            total_nodes=0,
            total_bytes=0,
            tasks_sha256=export_index.tasks_sha256,
            public_manifest_sha256=export_index.public_manifest_sha256,
            source_map_sha256=_sha("opaque-source-map-pin"),
            manifest_sha256=export_index.sealed_batch_manifest_sha256,
            batch_content_root=export_index.sealed_batch_content_root,
            key_id="snapshot-key",
            tasks=members,
        )
        selected = tasks[0]
        summary = _summary(selected.task_id)
        with (
            mock.patch.object(
                receipt_module, "read_verified_task_export_v2", return_value=export
            ),
            mock.patch.object(
                receipt_module, "verify_snapshot_batch", return_value=batch
            ),
            mock.patch.object(
                receipt_module, "inspect_replay_authoring_v1", return_value=summary
            ) as inspect,
        ):
            result = readback_published_replay_v2(
                self.root / "export",
                selected.task_id,
                self.root / "published",
                self.root / "sealed-batch",
                expected_task_export_index_sha256=export_index.index_sha256,
                expected_task_export_index_wire_sha256=export_index.wire_sha256,
                snapshot_attestation_key=self.snapshot_key,
                expected_snapshot_key_id="snapshot-key",
                expected_snapshot_key_fingerprint=replay_key_fingerprint_v2(
                    self.snapshot_key
                ),
                readback_private_key=self.readback_key,
                trust_registry=self.trust_registry,
            )
        self.assertEqual(result.task_wire_sha256, pins[0].task_wire_sha256)
        self.assertEqual(result.snapshot_id, selected.snapshot_id)
        self.assertEqual(result.source.sealed_batch_content_root, batch.batch_content_root)
        self.assertEqual(inspect.call_args.args[1], batch.batch_root / members[0].bundle_path)

        changed = replace(summary, run_sha256=_sha("freshly-changed-run"))
        with (
            mock.patch.object(
                receipt_module, "read_verified_task_export_v2", return_value=export
            ),
            mock.patch.object(
                receipt_module, "verify_snapshot_batch", return_value=batch
            ),
            mock.patch.object(
                receipt_module, "inspect_replay_authoring_v1", return_value=changed
            ),
            self.assertRaisesRegex(ReplayAuthoringReceiptError, "fresh production"),
        ):
            verify_published_replay_observation_v2(
                result,
                self.root / "export",
                self.root / "published",
                self.root / "sealed-batch",
                expected_task_export_index_sha256=export_index.index_sha256,
                expected_task_export_index_wire_sha256=export_index.wire_sha256,
                snapshot_attestation_key=self.snapshot_key,
                expected_snapshot_key_id="snapshot-key",
                expected_snapshot_key_fingerprint=replay_key_fingerprint_v2(
                    self.snapshot_key
                ),
                trust_registry=self.trust_registry,
            )

    def test_cli_approve_loads_only_actor_private_and_pinned_registry(self) -> None:
        observation_file = self.root / "observation.json"
        actor_file = self.root / "actor.key"
        registry_file = self.root / "trust-registry.json"
        _private_file(observation_file, self.observation.to_bytes())
        _private_file(actor_file, self.actor_keys["critic"])
        _private_file(registry_file, self.trust_registry.to_bytes())
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = receipt_cli.main(
                [
                    "approve",
                    "--observation-file", str(observation_file),
                    "--expected-observation-sha256", self.observation.observation_sha256,
                     "--expected-observation-wire-sha256", self.observation.wire_sha256,
                     "--actor-role", "critic",
                     "--actor-private-key-file", str(actor_file),
                     "--trust-registry-file", str(registry_file),
                     "--expected-trust-registry-sha256", self.trust_registry.registry_sha256,
                     "--expected-trust-registry-wire-sha256", self.trust_registry.wire_sha256,
                ]
            )
        self.assertEqual((status, stderr.getvalue()), (0, ""))
        approval = ReplayActorApprovalV2.from_bytes(stdout.getvalue().encode())
        self.assertEqual(
            (approval.actor_role, approval.actor_key_id),
            ("critic", "actor-approval-critic-key"),
        )


class ReplayAuthoringIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = _temporary()
        self.root = Path(self.temporary.name).resolve()
        self.benchmark = self.root / "benchmark"
        self.receipts = self.root / "receipts"
        self.benchmark.mkdir(mode=0o700)
        self.receipts.mkdir(mode=0o700)
        self.snapshot_keys = {split: _key(f"snapshot:{split}") for split in ("test", "train")}
        self.signing_keys = _signing_keys()
        self.trust_registry = _registry(self.signing_keys)
        self.readback_keys = {
            split: self.signing_keys[("readback-attestation", split)]
            for split in ("test", "train")
        }
        self.actor_keys = {
            role: self.signing_keys[("actor-approval", role)] for role in ROLES
        }
        self.index_key = self.signing_keys[("authoring-index", "global")]
        self.registrations = tuple(
            ReplayActorKeyRegistrationV2.from_trust_registry(
                actor_role=role,
                trust_registry=self.trust_registry,
            )
            for role in ROLES
        )
        self.public_tasks = {split: self._public_tasks(split) for split in ("test", "train")}
        self.exports = {split: self._export(split) for split in ("test", "train")}
        self.sources = {
            split: ReplaySourceBindingV2.from_export_index(
                self.exports[split].index,
                task_export_index_wire_sha256=self.exports[split].index.wire_sha256,
                snapshot_key_fingerprint=replay_key_fingerprint_v2(self.snapshot_keys[split]),
                trust_registry=self.trust_registry,
            )
            for split in ("test", "train")
        }
        self._write_receipts()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _public_tasks(split: str) -> tuple[SnapshotTaskSpec, ...]:
        count = 20 if split == "test" else 50
        offset = 1 if split == "test" else 101
        return tuple(
            SnapshotTaskSpec(
                task_id=f"VG-{split.upper()}-{index:020X}",
                repo_url=f"https://github.com/example/{split}-repo-{index}",
                commit=f"{index + offset:040x}",
                split=split,
            )
            for index in range(count)
        )

    def _export(self, split: str) -> VerifiedDiscoveryTaskSplitExportV1:
        tasks = tuple(
            DiscoveryTaskInputV1(
                task_id=task.task_id,
                repo_url=task.repo_url,
                commit=task.commit,
                instruction_id=task.instruction_id,
                snapshot_manifest_sha256=_sha(f"snapshot-manifest:{task.task_id}"),
                snapshot_content_root=_sha(f"snapshot-content:{task.task_id}"),
            )
            for task in self.public_tasks[split]
        )
        pins = tuple(
            DiscoveryTaskFilePinV1(
                ordinal=index + 1,
                task_id=task.task_id,
                snapshot_id=task.snapshot_id,
                task_file=f"tasks/{task.task_id}.json",
                task_wire_sha256=_sha(f"task-wire:{task.task_id}"),
            )
            for index, task in enumerate(tasks)
        )
        index = DiscoveryTaskSplitExportIndexV1(
            split=split,
            tasks_sha256=_sha(f"tasks:{split}"),
            public_manifest_sha256=_sha(f"public:{split}"),
            sealed_batch_manifest_sha256=_sha(f"batch-manifest:{split}"),
            sealed_batch_content_root=_sha(f"batch-root:{split}"),
            sealed_batch_key_id=f"snapshot-{split}",
            tasks=pins,
        )
        return VerifiedDiscoveryTaskSplitExportV1(index=index, tasks=tasks)

    def _receipt(self, split: str, ordinal: int) -> ReplayAuthoringClosureReceiptV2:
        task = self.exports[split].tasks[ordinal]
        pin = self.exports[split].index.tasks[ordinal]
        observation = ReplayClosureObservationV2.from_summary(
            task,
            _summary(task.task_id, ordinal + (0 if split == "test" else 20) + 1),
            task_wire_sha256=pin.task_wire_sha256,
            source=self.sources[split],
            readback_private_key=self.readback_keys[split],
            trust_registry=self.trust_registry,
        )
        approvals = tuple(
            ReplayActorApprovalV2.from_observation(
                observation,
                actor_role=role,
                actor_private_key=self.actor_keys[role],
                trust_registry=self.trust_registry,
            )
            for role in ROLES
        )
        return seal_replay_closure_receipt_v2(
            observation,
            approvals,
            trust_registry=self.trust_registry,
        )

    def _write_receipts(self) -> None:
        for split in ("test", "train"):
            for ordinal, task in enumerate(self.public_tasks[split]):
                _private_file(
                    self.receipts / f"{task.task_id}{REPLAY_RECEIPT_FILENAME_SUFFIX}",
                    self._receipt(split, ordinal).to_bytes(),
                )

    def _load_tasks(self, _root: Path, *, split: str):
        return self.public_tasks[split]

    def _build(self) -> ReplayAuthoringIndexV2:
        with mock.patch.object(receipt_module, "load_answer_free_tasks", side_effect=self._load_tasks):
            return build_replay_authoring_index_v2(
                self.benchmark,
                self.receipts,
                task_exports=self.exports,
                snapshot_key_fingerprints={split: replay_key_fingerprint_v2(self.snapshot_keys[split]) for split in ("test", "train")},
                trust_registry=self.trust_registry,
                index_private_key=self.index_key,
            )

    def test_builds_exact_v2_index_accepted_by_formal_reader(self) -> None:
        index = self._build()
        self.assertEqual(tuple(item.split for item in index.tasks), ("test",) * 20 + ("train",) * 50)
        self.assertEqual(tuple(item.split for item in index.sources), ("test", "train"))
        index_file = self.root / "index.json"
        _private_file(index_file, index.to_bytes())
        expected_tasks = tuple((split, task.task_id) for split in ("test", "train") for task in self.public_tasks[split])
        loaded = batch_cli._load_authoring_index(
            index_file,
            expected_sha256=index.index_sha256,
            expected_wire_sha256=index.wire_sha256,
            expected_tasks=expected_tasks,
            trust_registry=self.trust_registry,
        )
        self.assertEqual(len(loaded), 70)
        with self.assertRaisesRegex(
            batch_cli.ReplayBatchPlanError, "formal v2"
        ):
            batch_cli._load_authoring_index(
                index_file,
                expected_sha256=index.index_sha256,
                expected_wire_sha256=index.wire_sha256,
                expected_tasks=expected_tasks,
                trust_registry=_registry(_signing_keys("unregistered")),
            )
        self.assertEqual(ReplayAuthoringIndexV2.from_bytes(index.to_bytes(), expected_sha256=index.index_sha256, expected_wire_sha256=index.wire_sha256), index)

    def test_mixed_source_receipt_and_wrong_external_pin_are_rejected(self) -> None:
        first = self.public_tasks["test"][0]
        path = self.receipts / f"{first.task_id}{REPLAY_RECEIPT_FILENAME_SUFFIX}"
        original = ReplayAuthoringClosureReceiptV2.from_bytes(path.read_bytes())
        mixed_observation = ReplayClosureObservationV2.from_summary(
            self.exports["test"].tasks[0],
            _summary(first.task_id, 1),
            task_wire_sha256=self.exports["test"].index.tasks[0].task_wire_sha256,
            source=replace(self.sources["test"], sealed_batch_content_root=self.sources["train"].sealed_batch_content_root),
            readback_private_key=self.readback_keys["test"],
            trust_registry=self.trust_registry,
        )
        approvals = tuple(
            ReplayActorApprovalV2.from_observation(
                mixed_observation,
                actor_role=role,
                actor_private_key=self.actor_keys[role],
                trust_registry=self.trust_registry,
            )
            for role in ROLES
        )
        mixed_receipt = seal_replay_closure_receipt_v2(
            mixed_observation,
            approvals,
            trust_registry=self.trust_registry,
        )
        _private_file(path, mixed_receipt.to_bytes())
        with self.assertRaisesRegex(ReplayAuthoringReceiptError, "authenticated public source"):
            self._build()
        _private_file(path, original.to_bytes())
        index = self._build()
        with self.assertRaisesRegex(ReplayAuthoringReceiptError, "wire pin differs"):
            ReplayAuthoringIndexV2.from_bytes(
                index.to_bytes(),
                expected_sha256=index.index_sha256,
                expected_wire_sha256="0" * 64,
            )

    def test_receipt_root_swap_cannot_substitute_preopened_member(self) -> None:
        name = next(iter(sorted(path.name for path in self.receipts.iterdir())))
        original = (self.receipts / name).read_bytes()
        replacement = self.root / "replacement"
        replacement.mkdir(mode=0o700)
        for path in self.receipts.iterdir():
            payload = b"{}\n" if path.name == name else path.read_bytes()
            _private_file(replacement / path.name, payload)
        hidden = self.root / "hidden-original"
        with receipt_module._ReceiptDirectoryReader(
            self.receipts,
            frozenset(path.name for path in self.receipts.iterdir()),
        ) as reader:
            if os.name == "nt":
                with self.assertRaises(OSError):
                    self.receipts.rename(hidden)
                self.assertEqual(reader.read(name), original)
                reader.verify()
            else:
                self.receipts.rename(hidden)
                replacement.rename(self.receipts)
                self.assertEqual(reader.read(name), original)
                self.receipts.rename(replacement)
                hidden.rename(self.receipts)
                try:
                    reader.verify()
                except ReplayAuthoringReceiptError as error:
                    self.assertEqual(error.code, "input_changed")

    def test_v1_index_is_legacy_read_only_and_rejected_by_formal_gate(self) -> None:
        tasks = [
            {
                "d2_sha256": _sha(f"legacy-d2:{index}"),
                "d2_wire_sha256": _sha(f"legacy-d2-wire:{index}"),
                "d3_sha256": _sha(f"legacy-d3:{index}"),
                "d3_wire_sha256": _sha(f"legacy-d3-wire:{index}"),
                "split": split,
                "task_id": task.task_id,
            }
            for index, (split, task) in enumerate(
                (item for split in ("test", "train") for item in ((split, task) for task in self.public_tasks[split]))
            )
        ]
        core = {"contract_version": 1, "kind": "vulngym.replay-authoring-index.v1", "tasks": tasks}
        semantic = hashlib.sha256(b"vulngym:replay-authoring-index:v1\x00" + json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        payload = json.dumps({**core, "index_sha256": semantic}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        path = self.root / "legacy-index.json"
        _private_file(path, payload)
        expected_tasks = tuple((split, task.task_id) for split in ("test", "train") for task in self.public_tasks[split])
        legacy = batch_cli._load_legacy_authoring_index_read_only(
            path,
            expected_sha256=semantic,
            expected_wire_sha256=_sha(payload),
            expected_tasks=expected_tasks,
        )
        self.assertEqual(len(legacy), 70)
        with self.assertRaisesRegex(batch_cli.ReplayBatchPlanError, "formal v2"):
            batch_cli._load_authoring_index(
                path,
                expected_sha256=semantic,
                expected_wire_sha256=_sha(payload),
                expected_tasks=expected_tasks,
                trust_registry=self.trust_registry,
            )


if __name__ == "__main__":
    unittest.main()
