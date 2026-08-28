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
    SnapshotBatchVerificationEvidenceV2,
    verify_snapshot_batch_with_evidence,
)
from vulngym_agent.benchmark.source_acquisition import (
    SOURCE_ACQUISITION_CONTRACT_VERSION,
)
from vulngym_agent.benchmark.source_sealing_receipt import (
    SOURCE_SEALING_CLOSURE_DIGEST_DOMAIN,
    SOURCE_SEALING_TASK_CLOSURE_DOMAIN,
    SourceSealingClosureError,
    SourceSealingClosureReceiptV2,
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
            commit=f"{index + 1 + (0 if split == 'test' else 20):040x}",
            split=split,
            instruction_id="vulngym-whitebox-locate-v1",
            snapshot_manifest_sha256=_sha(f"{split}-task-manifest-{index}"),
            snapshot_content_root=_sha(f"{split}-task-root-{index}"),
            root_tree=f"{10_001 + index + (0 if split == 'test' else 20):040x}",
                file_count=1,
                node_count=1,
                total_bytes=index + 1,
                entry_count=1,
                regular_file_count=1,
                gitlink_count=0,
                regular_file_bytes=index + 1,
                materialized_bytes=index + 1,
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
        "loose_object_count": 0,
        "loose_object_size_kib": 0,
        "multi_pack_index_present": True,
        "multi_pack_index_verified": True,
        "non_shallow": True,
        "observed_ref_count": commit_count,
        "pack_count": 1,
        "pack_size_kib": 1,
        "packed_object_count": commit_count,
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
    all_tasks = _batch_tasks("test") + _batch_tasks("train")
    for repository_index in range(22):
        repo_url = f"https://github.com/example/repository-{repository_index:02d}"
        tasks = tuple(task for task in all_tasks if task.repo_url == repo_url)
        commits = [_audit(task.commit, task.root_tree) for task in tasks]
        count = len(commits)
        repositories.append(
            {
                "commits": commits,
                "object_hygiene": _hygiene(repository_index, count),
                "repo_url": repo_url,
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
                "task_source_facts": [
                    {"task_id": task.task_id, "repo_url": task.repo_url, "commit": task.commit, "root_tree": task.root_tree, "gitlink_count": task.gitlink_count}
                    for task in _batch_tasks("test")
                ],
                "tasks_sha256": _sha("test-task-export"),
            },
            {
                "source_map_sha256": _sha("train-source-map"),
                "split": "train",
                "task_count": 50,
                "task_source_facts": [
                    {"task_id": task.task_id, "repo_url": task.repo_url, "commit": task.commit, "root_tree": task.root_tree, "gitlink_count": task.gitlink_count}
                    for task in _batch_tasks("train")
                ],
                "tasks_sha256": _sha("train-task-export"),
            },
        ],
        "fetch_protocol": {
            "deepen_by": 32,
            "initial_depth": 32,
            "max_deepen_rounds": 2_048,
            "max_total_network_seconds": 21_600,
            "max_transient_fetch_retries_per_repository": 1,
            "requires_exact_ref_closure": True,
            "requires_final_full_fsck": True,
            "requires_final_non_shallow": True,
            "requires_final_verified_multi_pack_index": True,
            "requires_strict_git_output": True,
            "requires_zero_garbage": True,
            "requires_zero_prune_packable": True,
            "requires_zero_unreachable_objects": True,
            "retry_requires_unchanged_repository_seal": True,
            "writes_verified_multi_pack_index": True,
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
) -> SnapshotBatchVerificationEvidenceV2:
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
        tuple[SnapshotBatchVerificationEvidenceV2, ...],
        tuple[SnapshotBatchVerificationEvidenceV2, ...],
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

    def _receipt(self) -> SourceSealingClosureReceiptV2:
        report, report_sha256 = _report_bytes()
        test_evidence, train_evidence = self._evidence()
        return SourceSealingClosureReceiptV2.from_verified_evidence(
            implementation_commit="a" * 40,
            acquisition_report_bytes=report,
            expected_acquisition_report_sha256=report_sha256,
            test_evidence=test_evidence,  # type: ignore[arg-type]
            train_evidence=train_evidence,  # type: ignore[arg-type]
        )

    def test_factory_roundtrip_is_path_free_and_exactly_pinned(self) -> None:
        receipt = self._receipt()
        task_records = [
            {
                "task_id": task.task_id,
                "repo_url": task.repo_url,
                "commit": task.commit,
                "root_tree": task.root_tree,
                "snapshot_manifest_sha256": task.snapshot_manifest_sha256,
                "snapshot_content_root": task.snapshot_content_root,
                "entry_count": task.entry_count,
                "regular_file_count": task.regular_file_count,
                "gitlink_count": task.gitlink_count,
                "regular_file_bytes": task.regular_file_bytes,
                "materialized_bytes": task.materialized_bytes,
            }
            for task in _batch_tasks("test")
        ]
        self.assertEqual(
            hashlib.sha256(
                SOURCE_SEALING_TASK_CLOSURE_DOMAIN
                + _canonical({"split": "test", "tasks": task_records})
            ).hexdigest(),
            receipt.test.task_closure_sha256,
        )
        self.assertNotEqual(
            receipt.test.task_closure_sha256,
            receipt.train.task_closure_sha256,
        )
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
            SourceSealingClosureReceiptV2.from_bytes(
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

        tampered = json.loads(payload)
        tampered["test"]["task_closure_sha256"] = "f" * 64
        tampered_payload = _canonical(tampered) + b"\n"
        with self.assertRaises(SourceSealingClosureError):
            SourceSealingClosureReceiptV2.from_bytes(
                tampered_payload,
                expected_receipt_sha256=receipt.receipt_sha256,
                expected_wire_sha256=hashlib.sha256(tampered_payload).hexdigest(),
            )

    def test_v2_reader_rejects_legacy_v1_wire(self) -> None:
        receipt = self._receipt()
        raw = json.loads(receipt.to_bytes())
        raw["contract_version"] = 1
        payload = _canonical(raw) + b"\n"
        with self.assertRaises(SourceSealingClosureError):
            SourceSealingClosureReceiptV2.from_bytes(
                payload,
                expected_receipt_sha256=raw["receipt_sha256"],
                expected_wire_sha256=hashlib.sha256(payload).hexdigest(),
            )

    def test_report_pin_and_strict_fields_reject_detachment(self) -> None:
        report, report_sha256 = _report_bytes()
        test_evidence, train_evidence = self._evidence()
        with self.assertRaises(SourceSealingClosureError):
            SourceSealingClosureReceiptV2.from_verified_evidence(
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
            SourceSealingClosureReceiptV2.from_verified_evidence(
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
            SourceSealingClosureReceiptV2.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=test_evidence,  # type: ignore[arg-type]
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )

    def test_verified_multi_pack_index_protocol_is_required(self) -> None:
        test_evidence, train_evidence = self._evidence()
        for field in (
            "requires_final_verified_multi_pack_index",
            "writes_verified_multi_pack_index",
        ):
            with self.subTest(field=field):
                raw = _report_value()
                protocol = raw["fetch_protocol"]
                assert isinstance(protocol, dict)
                protocol[field] = False
                report, report_sha256 = _report_bytes(raw)
                with self.assertRaisesRegex(
                    SourceSealingClosureError, "fetch protocol"
                ):
                    SourceSealingClosureReceiptV2.from_verified_evidence(
                        implementation_commit="a" * 40,
                        acquisition_report_bytes=report,
                        expected_acquisition_report_sha256=report_sha256,
                        test_evidence=test_evidence,  # type: ignore[arg-type]
                        train_evidence=train_evidence,  # type: ignore[arg-type]
                    )

    def test_bounded_fetch_retry_protocol_is_strictly_required(self) -> None:
        self.assertEqual(
            SOURCE_ACQUISITION_CONTRACT_VERSION,
            "vulngym.source-acquisition.v5",
        )
        test_evidence, train_evidence = self._evidence()
        for field, invalid in (
            ("max_transient_fetch_retries_per_repository", 0),
            ("retry_requires_unchanged_repository_seal", False),
        ):
            with self.subTest(field=field):
                raw = _report_value()
                protocol = raw["fetch_protocol"]
                assert isinstance(protocol, dict)
                protocol[field] = invalid
                report, report_sha256 = _report_bytes(raw)
                with self.assertRaisesRegex(
                    SourceSealingClosureError, "fetch protocol"
                ):
                    SourceSealingClosureReceiptV2.from_verified_evidence(
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
                    SourceSealingClosureReceiptV2.from_verified_evidence(
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
                    SourceSealingClosureReceiptV2.from_verified_evidence(
                        implementation_commit="a" * 40,
                        acquisition_report_bytes=report,
                        expected_acquisition_report_sha256=report_sha256,
                        test_evidence=test_evidence,  # type: ignore[arg-type]
                        train_evidence=train_evidence,  # type: ignore[arg-type]
                    )

    def test_gitlink_count_closes_across_audit_export_and_batch_task(self) -> None:
        test_tasks = list(_batch_tasks("test"))
        test_tasks[0] = replace(
            test_tasks[0],
            file_count=2,
            node_count=2,
            total_bytes=test_tasks[0].total_bytes + 49,
            entry_count=2,
            gitlink_count=1,
            materialized_bytes=test_tasks[0].materialized_bytes + 49,
        )
        test_summary = _summary("test", self.test_root, tasks=tuple(test_tasks))
        train_summary = _summary("train", self.train_root)
        test_evidence = tuple(
            _mint(self.test_root, test_summary, self.test_key) for _ in range(2)
        )
        train_evidence = tuple(
            _mint(self.train_root, train_summary, self.train_key) for _ in range(2)
        )

        raw = _report_value()
        test_export = raw["exports"][0]  # type: ignore[index]
        test_export["task_source_facts"][0]["gitlink_count"] = 1  # type: ignore[index]
        audit = raw["repositories"][0]["commits"][0]  # type: ignore[index]
        audit["gitlink_count"] = 1  # type: ignore[index]
        audit["mode_counts"] = {"100644": 1, "160000": 1}  # type: ignore[index]
        audit["tree_entry_count"] = 2  # type: ignore[index]
        report, report_sha256 = _report_bytes(raw)

        receipt = SourceSealingClosureReceiptV2.from_verified_evidence(
            implementation_commit="a" * 40,
            acquisition_report_bytes=report,
            expected_acquisition_report_sha256=report_sha256,
            test_evidence=test_evidence,  # type: ignore[arg-type]
            train_evidence=train_evidence,  # type: ignore[arg-type]
        )
        self.assertEqual(receipt.test.task_count, 20)

    def test_task_source_root_tree_must_match_repository_audit_and_batch(self) -> None:
        test_evidence, train_evidence = self._evidence()
        for target in ("fact", "audit"):
            with self.subTest(target=target):
                raw = _report_value()
                if target == "fact":
                    raw["exports"][0]["task_source_facts"][0]["root_tree"] = "f" * 40  # type: ignore[index]
                else:
                    raw["repositories"][0]["commits"][0]["root_tree"] = "f" * 40  # type: ignore[index]
                report, report_sha256 = _report_bytes(raw)
                with self.assertRaisesRegex(SourceSealingClosureError, "source fact"):
                    SourceSealingClosureReceiptV2.from_verified_evidence(
                        implementation_commit="a" * 40,
                        acquisition_report_bytes=report,
                        expected_acquisition_report_sha256=report_sha256,
                        test_evidence=test_evidence,  # type: ignore[arg-type]
                        train_evidence=train_evidence,  # type: ignore[arg-type]
                    )

    def test_task_source_identities_must_exactly_close_repository_audit(self) -> None:
        raw = _report_value()
        test_facts = raw["exports"][0]["task_source_facts"]  # type: ignore[index]
        assert isinstance(test_facts, list)
        first = test_facts[0]
        second = test_facts[1]
        assert isinstance(first, dict)
        assert isinstance(second, dict)
        for field in ("repo_url", "commit", "root_tree", "gitlink_count"):
            second[field] = first[field]
        report, report_sha256 = _report_bytes(raw)
        test_evidence, train_evidence = self._evidence()
        with self.assertRaisesRegex(SourceSealingClosureError, "exactly close"):
            SourceSealingClosureReceiptV2.from_verified_evidence(
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
                "multi_pack_index_present",
                "multi_pack_index_verified",
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
            ("pack-count", "pack_count", 0),
            ("packed-objects", "packed_object_count", 0),
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
                    SourceSealingClosureReceiptV2.from_verified_evidence(
                        implementation_commit="a" * 40,
                        acquisition_report_bytes=report,
                        expected_acquisition_report_sha256=report_sha256,
                        test_evidence=test_evidence,  # type: ignore[arg-type]
                        train_evidence=train_evidence,  # type: ignore[arg-type]
                    )

    def test_arbitrary_labels_and_reused_evidence_are_rejected(self) -> None:
        self.assertFalse(hasattr(SourceSealingClosureReceiptV2, "from_summaries"))
        report, report_sha256 = _report_bytes()
        test_evidence, train_evidence = self._evidence()
        with self.assertRaisesRegex(SourceSealingClosureError, "trusted evidence"):
            SourceSealingClosureReceiptV2.from_verified_evidence(
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
            SourceSealingClosureReceiptV2.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=(test_evidence[0], test_evidence[0]),
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )
        receipt = SourceSealingClosureReceiptV2.from_verified_evidence(
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
            SourceSealingClosureReceiptV2.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=(test_evidence[0], forged),
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )
        receipt = SourceSealingClosureReceiptV2.from_verified_evidence(
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
            SourceSealingClosureReceiptV2.from_verified_evidence(
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
            SourceSealingClosureReceiptV2.from_verified_evidence(
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
            SourceSealingClosureReceiptV2.from_verified_evidence(
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
            SourceSealingClosureReceiptV2.from_verified_evidence(
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
            SourceSealingClosureReceiptV2.from_verified_evidence(
                implementation_commit="a" * 40,
                acquisition_report_bytes=report,
                expected_acquisition_report_sha256=report_sha256,
                test_evidence=test_evidence,  # type: ignore[arg-type]
                train_evidence=train_evidence,  # type: ignore[arg-type]
            )
        self.test_root.rmdir()
        preserved.rename(self.test_root)
        receipt = SourceSealingClosureReceiptV2.from_verified_evidence(
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
                SourceSealingClosureReceiptV2.from_verified_evidence(
                    implementation_commit="a" * 40,
                    acquisition_report_bytes=report,
                    expected_acquisition_report_sha256=report_sha256,
                    test_evidence=test_evidence,  # type: ignore[arg-type]
                    train_evidence=train_evidence,  # type: ignore[arg-type]
                )

    def test_direct_receipt_constructor_and_unpinned_dict_are_unavailable(self) -> None:
        receipt = self._receipt()
        self.assertFalse(hasattr(SourceSealingClosureReceiptV2, "from_dict"))
        with self.assertRaisesRegex(SourceSealingClosureError, "trusted evidence"):
            SourceSealingClosureReceiptV2(
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
            SnapshotBatchVerificationEvidenceV2(
                summary=summary,
                _key_material=bytearray(self.test_key),
                _output_identity=(1, 2),
                _run_nonce=bytearray(32),
                _mint=object(),
            )


if __name__ == "__main__":
    unittest.main()
