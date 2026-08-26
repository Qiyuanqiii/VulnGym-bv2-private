from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from vulngym_agent.benchmark import snapshot_batch
from vulngym_agent.benchmark.snapshot_batch import (
    DEFAULT_SNAPSHOT_POLICY,
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    SNAPSHOT_BATCH_KEY_EQUALITY_TAG_DOMAIN,
    SnapshotBatchError,
    SnapshotBatchSummary,
    SnapshotBatchTask,
    SnapshotBatchVerificationEvidenceV1,
    verify_snapshot_batch_with_evidence,
)
from vulngym_agent.benchmark.source_acquisition import (
    SOURCE_ACQUISITION_CONTRACT_VERSION,
)
from vulngym_agent.benchmark.source_sealing_receipt import (
    SOURCE_SEALING_CLOSURE_DIGEST_DOMAIN,
    SourceSealingClosureError,
    SourceSealingClosureReceiptV1,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _batch_tasks(split: str) -> tuple[SnapshotBatchTask, ...]:
    count = 20 if split == "test" else 50
    return tuple(
        SnapshotBatchTask(
            task_id=f"VG-{split.upper()}-{index:020d}",
            repo_url=f"https://github.com/example/repository-{index % 22:02d}",
            commit=f"{index + 1:040x}",
            split=split,
            instruction_id="vulngym-whitebox-locate-v1",
            snapshot_manifest_sha256=_sha(f"{split}-task-manifest-{index}"),
            snapshot_content_root=_sha(f"{split}-task-root-{index}"),
            file_count=1,
            node_count=1,
            total_bytes=index + 1,
        )
        for index in range(count)
    )


def _summary(
    split: str,
    root: Path,
    *,
    key_id: str | None = None,
    tasks: tuple[SnapshotBatchTask, ...] | None = None,
) -> SnapshotBatchSummary:
    batch_tasks = tasks if tasks is not None else _batch_tasks(split)
    return SnapshotBatchSummary(
        batch_root=root.resolve(),
        profile_id=PROFILE_ID,
        split=split,
        task_count=len(batch_tasks),
        total_files=sum(task.file_count for task in batch_tasks),
        total_nodes=sum(task.node_count for task in batch_tasks),
        total_bytes=sum(task.total_bytes for task in batch_tasks),
        tasks_sha256=_sha(f"{split}-task-export"),
        public_manifest_sha256=PROFILE_MANIFEST_SHA256,
        source_map_sha256=_sha(f"{split}-source-map"),
        manifest_sha256=_sha(f"{split}-sealed-manifest"),
        batch_content_root=_sha(f"{split}-batch-content"),
        key_id=key_id or f"{split}-source-seal-2026",
        tasks=batch_tasks,
    )


def _audit(commit: str, root_tree: str) -> dict[str, object]:
    return {
        "commit": commit,
        "gitlink_count": 0,
        "lfs_pointer_count": 0,
        "lfs_scan_complete": True,
        "mode_counts": {"100644": 1},
        "oversized_blob_count": 0,
        "policy": DEFAULT_SNAPSHOT_POLICY.to_dict(),
        "ready": True,
        "regular_file_count": 1,
        "root_tree": root_tree,
        "scan_complete": True,
        "status_codes": [],
        "symlink_count": 0,
        "total_regular_bytes": 1,
        "tree_count": 0,
        "tree_entry_count": 1,
        "unsupported_entry_count": 0,
    }


def _hygiene(index: int, commit_count: int) -> dict[str, object]:
    return {
        "all_objects_reachable": True,
        "alternates_absent": True,
        "bare_repository": True,
        "full_fsck": True,
        "garbage_count": 0,
        "garbage_size_kib": 0,
        "loose_object_count": commit_count,
        "loose_object_size_kib": 1,
        "non_shallow": True,
        "observed_ref_count": commit_count,
        "pack_count": 0,
        "pack_size_kib": 0,
        "packed_object_count": 0,
        "promisor_absent": True,
        "prune_packable_count": 0,
        "ref_inventory_sha256": _sha(f"refs-{index}"),
        "refs_closed": True,
        "replace_refs_absent": True,
        "required_ref_count": commit_count,
        "sha1_object_format": True,
        "storage_inventory_sha256": _sha(f"storage-{index}"),
        "storage_object_entry_count": commit_count,
        "storage_object_total_bytes": commit_count,
        "stored_object_count": commit_count,
        "unreachable_object_count": 0,
    }


def _report_value() -> dict[str, object]:
    repositories: list[dict[str, object]] = []
    commit_index = 1
    for repository_index in range(22):
        count = 4 if repository_index < 4 else 3
        commits = []
        for _ in range(count):
            commit = f"{commit_index:040x}"
            commits.append(_audit(commit, f"{10_000 + commit_index:040x}"))
            commit_index += 1
        repositories.append(
            {
                "commits": commits,
                "object_hygiene": _hygiene(repository_index, count),
                "repo_url": (
                    "https://github.com/example/"
                    f"repository-{repository_index:02d}"
                ),
            }
        )
    return {
        "blocked_task_count": 0,
        "contract_version": SOURCE_ACQUISITION_CONTRACT_VERSION,
        "exports": [
            {
                "source_map_sha256": _sha("test-source-map"),
                "split": "test",
                "task_count": 20,
                "tasks_sha256": _sha("test-task-export"),
            },
            {
                "source_map_sha256": _sha("train-source-map"),
                "split": "train",
                "task_count": 50,
                "tasks_sha256": _sha("train-task-export"),
            },
        ],
        "fetch_protocol": {
            "deepen_by": 32,
            "initial_depth": 32,
            "max_deepen_rounds": 2_048,
            "max_total_network_seconds": 21_600,
            "requires_exact_ref_closure": True,
            "requires_final_full_fsck": True,
            "requires_final_non_shallow": True,
            "requires_strict_git_output": True,
            "requires_zero_garbage": True,
            "requires_zero_prune_packable": True,
            "requires_zero_unreachable_objects": True,
        },
        "github_transport": "https",
        "git_version": "2.51.0.windows.1",
        "kind": "source_acquisition_report",
        "profile_id": PROFILE_ID,
        "public_manifest_sha256": PROFILE_MANIFEST_SHA256,
        "ready": True,
        "ready_task_count": 70,
        "repositories": repositories,
        "repository_count": 22,
        "task_count": 70,
    }


def _report_bytes(value: dict[str, object] | None = None) -> tuple[bytes, str]:
    payload = _canonical(value if value is not None else _report_value()) + b"\n"
    return payload, hashlib.sha256(payload).hexdigest()


def _mint(
    root: Path,
    summary: SnapshotBatchSummary,
    key: bytes,
) -> SnapshotBatchVerificationEvidenceV1:
    with mock.patch(
        "vulngym_agent.benchmark.snapshot_batch.verify_snapshot_batch",
        return_value=summary,
    ) as verifier:
        evidence = verify_snapshot_batch_with_evidence(
            root,
            expected_manifest_sha256=summary.manifest_sha256,
            attestation_key=key,
            expected_key_id=summary.key_id,
        )
    verifier.assert_called_once()
    return evidence


class SourceSealingReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        base = Path(self._temporary.name)
        self.test_root = base / "test-output"
        self.train_root = base / "train-output"
        self.test_root.mkdir()
        self.train_root.mkdir()
        self.test_key = b"T" * 32
        self.train_key = b"R" * 32

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _evidence(
        self,
        *,
        test_key: bytes | None = None,
        train_key: bytes | None = None,
        test_root: Path | None = None,
        train_root: Path | None = None,
        test_key_id: str = "test-source-seal-2026",
        train_key_id: str = "train-source-seal-2026",
    ) -> tuple[
        tuple[SnapshotBatchVerificationEvidenceV1, ...],
        tuple[SnapshotBatchVerificationEvidenceV1, ...],
    ]:
        actual_test_root = test_root or self.test_root
        actual_train_root = train_root or self.train_root
        test_summary = _summary("test", actual_test_root, key_id=test_key_id)
        train_summary = _summary("train", actual_train_root, key_id=train_key_id)
        return (
            tuple(
                _mint(actual_test_root, test_summary, test_key or self.test_key)
                for _ in range(2)
            ),
            tuple(
                _mint(
                    actual_train_root,
                    train_summary,
                    train_key or self.train_key,
                )
                for _ in range(2)
            ),
        )

    def _receipt(self) -> SourceSealingClosureReceiptV1:
        report, report_sha256 = _report_bytes()
        test_evidence, train_evidence = self._evidence()
        return SourceSealingClosureReceiptV1.from_verified_evidence(
            implementation_commit="a" * 40,
            acquisition_report_bytes=report,
            expected_acquisition_report_sha256=report_sha256,
            test_evidence=test_evidence,  # type: ignore[arg-type]
            train_evidence=train_evidence,  # type: ignore[arg-type]
        )

    def test_factory_roundtrip_is_path_free_and_exactly_pinned(self) -> None:
        receipt = self._receipt()
        payload = receipt.to_bytes()
        raw = json.loads(payload)
        semantic = raw.pop("receipt_sha256")
        self.assertEqual(
            hashlib.sha256(
                SOURCE_SEALING_CLOSURE_DIGEST_DOMAIN + _canonical(raw)
            ).hexdigest(),
            semantic,
        )
        self.assertEqual(hashlib.sha256(payload).hexdigest(), receipt.wire_sha256)
        self.assertEqual(
            receipt,
            SourceSealingClosureReceiptV1.from_bytes(
                payload,
                expected_receipt_sha256=receipt.receipt_sha256,
                expected_wire_sha256=receipt.wire_sha256,
            ),
        )
        self.assertNotIn(str(self.test_root).encode(), payload)
        self.assertNotIn(str(self.train_root).encode(), payload)
        self.assertNotIn(self.test_key, payload)
        self.assertNotIn(self.train_key, payload)
        for forbidden in (
            b"batch_root",
            b"attestation_key",
            b"key_bytes",
            b"error_count",
        ):
            self.assertNotIn(forbidden, payload)
        self.assertNotEqual(
            receipt.test.verify_rounds[0].run_id,
            receipt.test.verify_rounds[1].run_id,
        )

    def test_report_pin_and_strict_fields_reject_detachment(self) -> None:
        report, report_sha256 = _report_bytes()
        test_evidence, train_evidence = self._evidence()
        with self.assertRaises(SourceSealingClosureError):
            SourceSealingClosureReceiptV1.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256="0" * 64,
                test_evidence=test_evidence,  # type: ignore[arg-type]
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )
        detached = _report_value()
        detached["report_path"] = "C:/operator/report.json"
        detached_bytes, detached_sha256 = _report_bytes(detached)
        with self.assertRaises(SourceSealingClosureError):
            SourceSealingClosureReceiptV1.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=detached_bytes,
                expected_acquisition_report_sha256=detached_sha256,
                test_evidence=test_evidence,  # type: ignore[arg-type]
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )
        self.assertEqual(hashlib.sha256(report).hexdigest(), report_sha256)

    def test_contradictory_repository_hygiene_is_rejected(self) -> None:
        raw = _report_value()
        repositories = raw["repositories"]
        assert isinstance(repositories, list)
        hygiene = repositories[0]["object_hygiene"]
        assert isinstance(hygiene, dict)
        hygiene["bare_repository"] = False
        report, report_sha256 = _report_bytes(raw)
        test_evidence, train_evidence = self._evidence()
        with self.assertRaisesRegex(SourceSealingClosureError, "hygiene"):
            SourceSealingClosureReceiptV1.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=test_evidence,  # type: ignore[arg-type]
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )

    def test_all_ready_commit_contradictions_are_rejected(self) -> None:
        test_evidence, train_evidence = self._evidence()
        for field in (
            "gitlink_count",
            "lfs_pointer_count",
            "oversized_blob_count",
            "unsupported_entry_count",
        ):
            with self.subTest(field=field):
                raw = _report_value()
                commit = raw["repositories"][0]["commits"][0]  # type: ignore[index]
                commit[field] = 1  # type: ignore[index]
                report, report_sha256 = _report_bytes(raw)
                with self.assertRaisesRegex(
                    SourceSealingClosureError, "contradictory"
                ):
                    SourceSealingClosureReceiptV1.from_verified_evidence(
                        implementation_commit="a" * 40,
                        acquisition_report_bytes=report,
                        expected_acquisition_report_sha256=report_sha256,
                        test_evidence=test_evidence,  # type: ignore[arg-type]
                        train_evidence=train_evidence,  # type: ignore[arg-type]
                    )

        for label, changes in (
            ("empty", {"mode_counts": {}, "regular_file_count": 0, "tree_entry_count": 0}),
            ("tree-mode", {"tree_count": 1}),
            ("symlink-mode", {"symlink_count": 1}),
            (
                "file-limit",
                {"tree_entry_count": DEFAULT_SNAPSHOT_POLICY.max_files + 1},
            ),
            (
                "byte-limit",
                {
                    "total_regular_bytes": (
                        DEFAULT_SNAPSHOT_POLICY.max_total_bytes + 1
                    )
                },
            ),
        ):
            with self.subTest(label=label):
                raw = _report_value()
                commit = raw["repositories"][0]["commits"][0]  # type: ignore[index]
                commit.update(changes)  # type: ignore[union-attr]
                report, report_sha256 = _report_bytes(raw)
                with self.assertRaises(SourceSealingClosureError):
                    SourceSealingClosureReceiptV1.from_verified_evidence(
                        implementation_commit="a" * 40,
                        acquisition_report_bytes=report,
                        expected_acquisition_report_sha256=report_sha256,
                        test_evidence=test_evidence,  # type: ignore[arg-type]
                        train_evidence=train_evidence,  # type: ignore[arg-type]
                    )

    def test_all_object_hygiene_contradictions_are_rejected(self) -> None:
        test_evidence, train_evidence = self._evidence()
        cases: list[tuple[str, str, object]] = [
            *((name, name, False) for name in (
                "all_objects_reachable",
                "alternates_absent",
                "bare_repository",
                "full_fsck",
                "non_shallow",
                "promisor_absent",
                "refs_closed",
                "replace_refs_absent",
                "sha1_object_format",
            )),
            *((name, name, 1) for name in (
                "garbage_count",
                "garbage_size_kib",
                "prune_packable_count",
                "unreachable_object_count",
            )),
            ("required-refs", "required_ref_count", 2),
            ("observed-refs", "observed_ref_count", 2),
            ("stored-objects", "stored_object_count", 0),
            ("storage-entries", "storage_object_entry_count", 0),
            ("storage-bytes", "storage_object_total_bytes", 0),
        ]
        for label, field, value in cases:
            with self.subTest(label=label):
                raw = _report_value()
                hygiene = raw["repositories"][0]["object_hygiene"]  # type: ignore[index]
                hygiene[field] = value  # type: ignore[index]
                report, report_sha256 = _report_bytes(raw)
                with self.assertRaises(SourceSealingClosureError):
                    SourceSealingClosureReceiptV1.from_verified_evidence(
                        implementation_commit="a" * 40,
                        acquisition_report_bytes=report,
                        expected_acquisition_report_sha256=report_sha256,
                        test_evidence=test_evidence,  # type: ignore[arg-type]
                        train_evidence=train_evidence,  # type: ignore[arg-type]
                    )

    def test_arbitrary_labels_and_reused_evidence_are_rejected(self) -> None:
        self.assertFalse(hasattr(SourceSealingClosureReceiptV1, "from_summaries"))
        report, report_sha256 = _report_bytes()
        test_evidence, train_evidence = self._evidence()
        with self.assertRaisesRegex(SourceSealingClosureError, "trusted evidence"):
            SourceSealingClosureReceiptV1.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=(
                    ("round-one", test_evidence[0]),
                    ("round-two", test_evidence[0]),
                ),  # type: ignore[arg-type]
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(SourceSealingClosureError, "does not agree"):
            SourceSealingClosureReceiptV1.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=(test_evidence[0], test_evidence[0]),
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )
        receipt = SourceSealingClosureReceiptV1.from_verified_evidence(
            implementation_commit="a" * 40,
            acquisition_report_bytes=report,
            expected_acquisition_report_sha256=report_sha256,
            test_evidence=test_evidence,  # type: ignore[arg-type]
            train_evidence=train_evidence,  # type: ignore[arg-type]
        )
        self.assertEqual("closed", receipt.status)

    def test_copied_evidence_with_forged_run_id_is_rejected(self) -> None:
        report, report_sha256 = _report_bytes()
        test_evidence, train_evidence = self._evidence()
        forged = copy.copy(test_evidence[0])
        object.__setattr__(forged, "run_id", _sha("forged-run-id"))
        with self.assertRaisesRegex(SourceSealingClosureError, "fresh trusted"):
            SourceSealingClosureReceiptV1.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=(test_evidence[0], forged),
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )
        receipt = SourceSealingClosureReceiptV1.from_verified_evidence(
            implementation_commit="a" * 40,
            acquisition_report_bytes=report,
            expected_acquisition_report_sha256=report_sha256,
            test_evidence=test_evidence,  # type: ignore[arg-type]
            train_evidence=train_evidence,  # type: ignore[arg-type]
        )
        self.assertEqual("closed", receipt.status)

    def test_tasks_only_change_between_runs_is_rejected(self) -> None:
        report, report_sha256 = _report_bytes()
        first_summary = _summary("test", self.test_root)
        changed_tasks = list(first_summary.tasks)
        changed_tasks[0] = replace(
            changed_tasks[0], snapshot_content_root=_sha("changed-task-root")
        )
        second_summary = _summary("test", self.test_root, tasks=tuple(changed_tasks))
        self.assertEqual(first_summary.to_dict(), second_summary.to_dict())
        test_evidence = (
            _mint(self.test_root, first_summary, self.test_key),
            _mint(self.test_root, second_summary, self.test_key),
        )
        _, train_evidence = self._evidence()
        with self.assertRaisesRegex(SourceSealingClosureError, "does not agree"):
            SourceSealingClosureReceiptV1.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=test_evidence,
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )

    def test_same_key_material_with_different_ids_is_rejected(self) -> None:
        report, report_sha256 = _report_bytes()
        test_evidence, train_evidence = self._evidence(
            test_key=self.test_key,
            train_key=self.test_key,
            test_key_id="test-key-id",
            train_key_id="train-key-id",
        )
        with self.assertRaisesRegex(SourceSealingClosureError, "reuse"):
            SourceSealingClosureReceiptV1.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=test_evidence,  # type: ignore[arg-type]
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )

    def test_same_output_root_across_splits_is_rejected(self) -> None:
        report, report_sha256 = _report_bytes()
        test_evidence, train_evidence = self._evidence(
            test_root=self.test_root,
            train_root=self.test_root,
        )
        with self.assertRaisesRegex(SourceSealingClosureError, "reuse"):
            SourceSealingClosureReceiptV1.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=test_evidence,  # type: ignore[arg-type]
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )

    def test_same_output_path_recreated_between_splits_is_rejected(self) -> None:
        report, report_sha256 = _report_bytes()
        shared = self.test_root
        test_summary = _summary("test", shared)
        test_evidence = tuple(
            _mint(shared, test_summary, self.test_key) for _ in range(2)
        )
        shared.rmdir()
        shared.mkdir()
        train_summary = _summary("train", shared)
        train_evidence = tuple(
            _mint(shared, train_summary, self.train_key) for _ in range(2)
        )
        with self.assertRaisesRegex(SourceSealingClosureError, "output root"):
            SourceSealingClosureReceiptV1.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=test_evidence,  # type: ignore[arg-type]
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )

    def test_replaced_root_fails_without_partially_consuming_evidence(self) -> None:
        report, report_sha256 = _report_bytes()
        test_evidence, train_evidence = self._evidence()
        preserved = self.test_root.with_name("preserved-test-output")
        self.test_root.rename(preserved)
        self.test_root.mkdir()
        with self.assertRaisesRegex(SourceSealingClosureError, "fresh trusted"):
            SourceSealingClosureReceiptV1.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=test_evidence,  # type: ignore[arg-type]
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )
        self.test_root.rmdir()
        preserved.rename(self.test_root)
        receipt = SourceSealingClosureReceiptV1.from_verified_evidence(
            implementation_commit="a" * 40,
            acquisition_report_bytes=report,
            expected_acquisition_report_sha256=report_sha256,
            test_evidence=test_evidence,  # type: ignore[arg-type]
            train_evidence=train_evidence,  # type: ignore[arg-type]
        )
        self.assertEqual("closed", receipt.status)

    def test_expired_evidence_is_rejected(self) -> None:
        report, report_sha256 = _report_bytes()
        with mock.patch.object(snapshot_batch.time, "monotonic", return_value=100.0):
            test_evidence, train_evidence = self._evidence()
        with mock.patch.object(
            snapshot_batch.time,
            "monotonic",
            return_value=(
                100.0
                + snapshot_batch._SNAPSHOT_BATCH_EVIDENCE_TTL_SECONDS
                + 1.0
            ),
        ):
            with self.assertRaisesRegex(SourceSealingClosureError, "fresh trusted"):
                SourceSealingClosureReceiptV1.from_verified_evidence(
                    implementation_commit="a" * 40,
                    acquisition_report_bytes=report,
                    expected_acquisition_report_sha256=report_sha256,
                    test_evidence=test_evidence,  # type: ignore[arg-type]
                    train_evidence=train_evidence,  # type: ignore[arg-type]
                )

    def test_direct_receipt_constructor_and_unpinned_dict_are_unavailable(self) -> None:
        receipt = self._receipt()
        self.assertFalse(hasattr(SourceSealingClosureReceiptV1, "from_dict"))
        with self.assertRaisesRegex(SourceSealingClosureError, "trusted evidence"):
            SourceSealingClosureReceiptV1(
                implementation_commit=receipt.implementation_commit,
                acquisition=receipt.acquisition,
                test=receipt.test,
                train=receipt.train,
            )

    def test_low_entropy_key_has_no_unpeppered_offline_verifier(self) -> None:
        receipt = self._receipt()
        unpeppered = hashlib.sha256(
            SNAPSHOT_BATCH_KEY_EQUALITY_TAG_DOMAIN
            + len(self.test_key).to_bytes(8, "big")
            + self.test_key
        ).hexdigest()
        self.assertNotEqual(unpeppered, receipt.test.key_equality_tag_sha256)
        self.assertNotIn(unpeppered.encode("ascii"), receipt.to_bytes())

    def test_evidence_constructor_is_not_a_public_mint(self) -> None:
        summary = _summary("test", self.test_root)
        with self.assertRaisesRegex(SnapshotBatchError, "trusted verifier"):
            SnapshotBatchVerificationEvidenceV1(
                summary=summary,
                _key_material=bytearray(self.test_key),
                _output_identity=(1, 2),
                _run_nonce=bytearray(32),
                _mint=object(),
            )


if __name__ == "__main__":
    unittest.main()
