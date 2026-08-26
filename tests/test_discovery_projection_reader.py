from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from vulngym_agent.benchmark import harness, projection_reader
from vulngym_agent.benchmark.contracts import SnapshotTaskSpec
from vulngym_agent.benchmark.projection_reader import (
    DiscoveryProjectionReaderError,
    DiscoveryProjectionTaskBindingV1,
    read_committed_discovery_projection_v1,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class DiscoveryProjectionReaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.trusted_benchmark_root = self.base / "trusted-benchmark"
        self._build_sequence = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _zero_training_aggregate() -> harness.TrainingAggregate:
        return harness.TrainingAggregate(
            total_advisories=51,
            covered_advisories=0,
            advisory_recall=0.0,
            total_entries=125,
            matched_entries=0,
            entry_recall=0.0,
            submitted_findings=0,
        )

    def _build(
        self, split: str
    ) -> tuple[
        Path,
        str,
        str,
        tuple[DiscoveryProjectionTaskBindingV1, ...],
    ]:
        count = 50 if split == "train" else 20
        prefix = "TRAIN" if split == "train" else "TEST"
        bindings: list[DiscoveryProjectionTaskBindingV1] = []
        projected: list[harness._ProjectedDiscoveryTask] = []
        records: list[dict[str, object]] = []
        for index in range(count):
            task = SnapshotTaskSpec(
                task_id=f"VG-{prefix}-{index:020X}",
                repo_url=f"https://github.com/example/repo-{index}",
                commit=f"{index + 1:040x}",
                split=split,
            )
            snapshot_id = f"VGS-{index + 1:032X}"
            dataset_sha256 = sha256(f"dataset-{split}-{index}".encode()).hexdigest()
            binding = DiscoveryProjectionTaskBindingV1(
                task=task,
                snapshot_id=snapshot_id,
                dataset_sha256=dataset_sha256,
            )
            stats = harness.DiscoveryProjectionStats(
                candidate_count=0,
                emit_review_count=0,
                reject_review_count=0,
                defer_review_count=0,
                trace_node_count=0,
                unique_findings=0,
                emitted_findings=0,
                truncated_findings=0,
                task_deferred=0,
            )
            bindings.append(binding)
            projected.append(
                harness._ProjectedDiscoveryTask(
                    task_id=task.task_id,
                    snapshot_id=snapshot_id,
                    status="finalized",
                    findings=(),
                    stats=stats,
                )
            )
            records.append(
                {
                    "dataset_sha256": dataset_sha256,
                    "snapshot_id": snapshot_id,
                    "status": "finalized",
                    "task_id": task.task_id,
                    **stats.to_dict(),
                }
            )
        index_sha256 = sha256(f"index-{split}".encode()).hexdigest()
        aggregate = self._zero_training_aggregate() if split == "train" else None
        files, manifest_sha256 = harness._discovery_output_files(
            split=split,
            projected=projected,
            bundle_records=records,
            bundle_index_sha256=index_sha256,
            top_k=64,
            aggregate=aggregate,
        )
        self._build_sequence += 1
        root = self.base / f"projection-{split}-{self._build_sequence}"
        root.mkdir()
        for name, payload in files.items():
            (root / name).write_bytes(payload)
        return root, manifest_sha256, index_sha256, tuple(bindings)

    def _read(
        self,
        root: Path,
        manifest_sha256: str,
        index_sha256: str,
        bindings: tuple[DiscoveryProjectionTaskBindingV1, ...],
        *,
        split: str,
    ):
        return read_committed_discovery_projection_v1(
            root,
            expected_split=split,
            expected_manifest_sha256=manifest_sha256,
            expected_artifact_index_sha256=index_sha256,
            expected_tasks=bindings,
            benchmark_root=(
                self.trusted_benchmark_root if split == "train" else None
            ),
        )

    def _manifest(self, root: Path) -> dict[str, object]:
        return json.loads((root / "manifest.json").read_text(encoding="utf-8"))

    def _refresh_manifest(
        self, root: Path, manifest: dict[str, object] | None = None
    ) -> str:
        value = self._manifest(root) if manifest is None else manifest
        files = value["files"]
        assert isinstance(files, dict)
        for name in tuple(files):
            payload = (root / name).read_bytes()
            files[name] = {"bytes": len(payload), "sha256": sha256(payload).hexdigest()}
        payload = _canonical(value) + b"\n"
        (root / "manifest.json").write_bytes(payload)
        return sha256(payload).hexdigest()

    def _finding(
        self,
        binding: DiscoveryProjectionTaskBindingV1,
        *,
        entry_line: int = 10,
        critical_line: int | str = "20-21",
        trace: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        entry = {"file": "src/entry.py", "line": entry_line}
        critical = {"file": "src/sink.py", "line": critical_line}
        identity = {
            "commit": binding.task.commit,
            "critical_operation": critical,
            "entry_point": entry,
            "repo_url": binding.task.repo_url,
            "task_id": binding.task.task_id,
        }
        finding = {
            "commit": binding.task.commit,
            "critical_operation": critical,
            "entry_point": entry,
            "finding_id": "VGF-" + sha256(_canonical(identity)).hexdigest()[:32].upper(),
            "repo_url": binding.task.repo_url,
            "task_id": binding.task.task_id,
        }
        if trace is not None:
            finding["trace"] = trace
        return finding

    def _rewrite_first_task_counters(
        self, root: Path, **counters: int
    ) -> str:
        task_records = [
            json.loads(line)
            for line in (root / "task_results.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        task_records[0].update(counters)
        (root / "task_results.jsonl").write_bytes(
            b"".join(_canonical(record) + b"\n" for record in task_records)
        )
        manifest = self._manifest(root)
        manifest.update(counters)
        return self._refresh_manifest(root, manifest)

    def _install_one_finding(self, root: Path, binding) -> tuple[str, dict[str, object]]:
        finding = self._finding(binding)
        (root / "findings.jsonl").write_bytes(_canonical(finding) + b"\n")
        manifest_sha256 = self._rewrite_first_task_counters(
            root,
            candidate_count=1,
            emit_review_count=1,
            emitted_findings=1,
            unique_findings=1,
        )
        return manifest_sha256, finding

    def test_test_and_train_success_return_path_free_verified_closures(self) -> None:
        for split in ("test", "train"):
            with self.subTest(split=split):
                root, manifest, index, bindings = self._build(split)
                if split == "train":
                    with mock.patch.object(
                        projection_reader,
                        "evaluate_training_aggregate",
                        return_value=self._zero_training_aggregate(),
                    ) as oracle:
                        result = self._read(
                            root, manifest, index, bindings, split=split
                        )
                    oracle.assert_called_once_with(self.trusted_benchmark_root, ())
                else:
                    result = self._read(
                        root, manifest, index, bindings, split=split
                    )
                self.assertEqual(split, result.summary.split)
                self.assertEqual(len(bindings), result.summary.task_count)
                self.assertEqual(0, result.summary.finding_count)
                self.assertEqual(manifest, result.summary.output_manifest_sha256)
                self.assertEqual(index, result.summary.bundle_index_sha256)
                self.assertEqual(
                    split == "train", result.aggregate_file_sha256 is not None
                )
                serialized = json.dumps(result.to_dict(), sort_keys=True)
                self.assertNotIn(str(root), serialized)

    def test_formal_outcome_gate_rejects_deferred_and_zero_finding_tasks(self) -> None:
        one_finding = harness.DiscoveryProjectionStats(
            candidate_count=1,
            emit_review_count=1,
            reject_review_count=0,
            defer_review_count=0,
            trace_node_count=0,
            unique_findings=1,
            emitted_findings=1,
            truncated_findings=0,
            task_deferred=0,
        )
        zero_finding = harness.DiscoveryProjectionStats(
            candidate_count=0,
            emit_review_count=0,
            reject_review_count=0,
            defer_review_count=0,
            trace_node_count=0,
            unique_findings=0,
            emitted_findings=0,
            truncated_findings=0,
            task_deferred=0,
        )
        two_findings = harness.DiscoveryProjectionStats(
            candidate_count=2,
            emit_review_count=2,
            reject_review_count=0,
            defer_review_count=0,
            trace_node_count=0,
            unique_findings=2,
            emitted_findings=2,
            truncated_findings=0,
            task_deferred=0,
        )
        deferred = harness.DiscoveryProjectionStats(
            candidate_count=0,
            emit_review_count=0,
            reject_review_count=0,
            defer_review_count=0,
            trace_node_count=0,
            unique_findings=0,
            emitted_findings=0,
            truncated_findings=0,
            task_deferred=1,
        )

        projection_reader._validate_formal_projection_outcomes_v1(
            (one_finding,), ("finalized",)
        )
        for stats, statuses in (
            ((zero_finding,), ("finalized",)),
            (
                (zero_finding, two_findings),
                ("finalized", "finalized"),
            ),
            ((deferred,), ("deferred",)),
        ):
            if len(stats) == 2:
                self.assertEqual(
                    len(stats), sum(item.unique_findings for item in stats)
                )
            with self.subTest(statuses=statuses), self.assertRaises(
                DiscoveryProjectionReaderError
            ) as captured:
                projection_reader._validate_formal_projection_outcomes_v1(
                    stats, statuses
                )
            self.assertEqual("formal_outcome_incomplete", captured.exception.code)

        root, manifest, index, bindings = self._build("test")
        with self.assertRaises(DiscoveryProjectionReaderError) as captured:
            read_committed_discovery_projection_v1(
                root,
                expected_split="test",
                expected_manifest_sha256=manifest,
                expected_artifact_index_sha256=index,
                expected_tasks=bindings,
                require_formal_outcomes=True,
            )
        self.assertEqual("formal_outcome_incomplete", captured.exception.code)

    def test_train_requires_trusted_root_and_test_never_calls_oracle(self) -> None:
        train_root, train_manifest, train_index, train_bindings = self._build("train")
        with mock.patch.object(
            projection_reader, "evaluate_training_aggregate"
        ) as oracle, self.assertRaises(DiscoveryProjectionReaderError) as captured:
            read_committed_discovery_projection_v1(
                train_root,
                expected_split="train",
                expected_manifest_sha256=train_manifest,
                expected_artifact_index_sha256=train_index,
                expected_tasks=train_bindings,
            )
        self.assertEqual("invalid_argument", captured.exception.code)
        oracle.assert_not_called()

        test_root, test_manifest, test_index, test_bindings = self._build("test")
        with mock.patch.object(
            projection_reader,
            "evaluate_training_aggregate",
            side_effect=AssertionError("test split reached oracle"),
        ) as oracle:
            result = self._read(
                test_root,
                test_manifest,
                test_index,
                test_bindings,
                split="test",
            )
            self.assertEqual("test", result.summary.split)
            with self.assertRaises(DiscoveryProjectionReaderError) as captured:
                read_committed_discovery_projection_v1(
                    test_root,
                    expected_split="test",
                    expected_manifest_sha256=test_manifest,
                    expected_artifact_index_sha256=test_index,
                    expected_tasks=test_bindings,
                    benchmark_root=self.trusted_benchmark_root,
                )
        self.assertEqual("invalid_argument", captured.exception.code)
        oracle.assert_not_called()

    def test_external_manifest_index_and_dataset_pins_are_mandatory(self) -> None:
        root, manifest, index, bindings = self._build("test")
        for kwargs in (
            {"manifest_sha256": "f" * 64, "index_sha256": index, "bindings": bindings},
            {"manifest_sha256": manifest, "index_sha256": "e" * 64, "bindings": bindings},
            {
                "manifest_sha256": manifest,
                "index_sha256": index,
                "bindings": (
                    DiscoveryProjectionTaskBindingV1(
                        task=bindings[0].task,
                        snapshot_id=bindings[0].snapshot_id,
                        dataset_sha256="d" * 64,
                    ),
                    *bindings[1:],
                ),
            },
        ):
            with self.subTest(kwargs=tuple(kwargs)):
                with self.assertRaises(DiscoveryProjectionReaderError):
                    self._read(root, split="test", **kwargs)

    def test_exact_test_train_member_union_rejects_extra_and_missing_aggregate(self) -> None:
        test_root, test_manifest, test_index, test_bindings = self._build("test")
        (test_root / "aggregate.json").write_bytes(b"{}\n")
        with self.assertRaises(DiscoveryProjectionReaderError):
            self._read(
                test_root,
                test_manifest,
                test_index,
                test_bindings,
                split="test",
            )

        train_root, train_manifest, train_index, train_bindings = self._build("train")
        (train_root / "aggregate.json").unlink()
        with self.assertRaises(DiscoveryProjectionReaderError):
            self._read(
                train_root,
                train_manifest,
                train_index,
                train_bindings,
                split="train",
            )

    def test_bound_file_tamper_and_duplicate_key_jsonl_are_rejected(self) -> None:
        root, manifest, index, bindings = self._build("test")
        (root / "findings.jsonl").write_bytes(b"{}\n")
        with self.assertRaises(DiscoveryProjectionReaderError):
            self._read(root, manifest, index, bindings, split="test")

        duplicate_root, _, duplicate_index, duplicate_bindings = self._build("test")
        path = duplicate_root / "task_results.jsonl"
        payload = path.read_bytes()
        payload = payload.replace(
            b'{"candidate_count":0,',
            b'{"candidate_count":0,"candidate_count":0,',
            1,
        )
        path.write_bytes(payload)
        duplicate_manifest = self._refresh_manifest(duplicate_root)
        with self.assertRaises(DiscoveryProjectionReaderError) as captured:
            self._read(
                duplicate_root,
                duplicate_manifest,
                duplicate_index,
                duplicate_bindings,
                split="test",
            )
        self.assertEqual("noncanonical_json", captured.exception.code)

    def test_finding_schema_id_order_and_per_task_counts_are_reverified(self) -> None:
        root, _, index, bindings = self._build("test")
        manifest, finding = self._install_one_finding(root, bindings[0])
        result = self._read(root, manifest, index, bindings, split="test")
        self.assertEqual(1, result.summary.finding_count)

        finding["finding_id"] = "VGF-" + "0" * 32
        (root / "findings.jsonl").write_bytes(_canonical(finding) + b"\n")
        invalid_manifest = self._refresh_manifest(root)
        with self.assertRaises(DiscoveryProjectionReaderError):
            self._read(root, invalid_manifest, index, bindings, split="test")

    def test_same_task_findings_require_canonical_endpoint_order(self) -> None:
        root, _, index, bindings = self._build("test")
        findings = [
            self._finding(bindings[0], entry_line=10, critical_line=20),
            self._finding(bindings[0], entry_line=11, critical_line=21),
        ]

        def endpoint_identity(finding: dict[str, object]) -> bytes:
            return _canonical(
                {
                    "commit": finding["commit"],
                    "critical_operation": finding["critical_operation"],
                    "entry_point": finding["entry_point"],
                    "repo_url": finding["repo_url"],
                    "task_id": finding["task_id"],
                }
            )

        ordered = sorted(findings, key=endpoint_identity)
        (root / "findings.jsonl").write_bytes(
            b"".join(_canonical(finding) + b"\n" for finding in reversed(ordered))
        )
        manifest = self._rewrite_first_task_counters(
            root,
            candidate_count=2,
            emit_review_count=2,
            emitted_findings=2,
            unique_findings=2,
        )
        with self.assertRaises(DiscoveryProjectionReaderError) as captured:
            self._read(root, manifest, index, bindings, split="test")
        self.assertEqual("projection_invalid", captured.exception.code)

    def test_fixed_top_k_counter_closure_rejects_impossible_findings(self) -> None:
        zero_candidate_root, _, zero_index, zero_bindings = self._build("test")
        _, _finding = self._install_one_finding(
            zero_candidate_root, zero_bindings[0]
        )
        zero_manifest = self._rewrite_first_task_counters(
            zero_candidate_root,
            candidate_count=0,
            emit_review_count=0,
            emitted_findings=1,
            truncated_findings=0,
            unique_findings=1,
        )
        with self.assertRaises(DiscoveryProjectionReaderError):
            self._read(
                zero_candidate_root,
                zero_manifest,
                zero_index,
                zero_bindings,
                split="test",
            )

        truncated_root, _, truncated_index, truncated_bindings = self._build("test")
        _, _finding = self._install_one_finding(
            truncated_root, truncated_bindings[0]
        )
        truncated_manifest = self._rewrite_first_task_counters(
            truncated_root,
            candidate_count=2,
            emit_review_count=2,
            emitted_findings=1,
            truncated_findings=1,
            unique_findings=2,
        )
        with self.assertRaises(DiscoveryProjectionReaderError):
            self._read(
                truncated_root,
                truncated_manifest,
                truncated_index,
                truncated_bindings,
                split="test",
            )

    def test_trace_counters_have_writer_upper_and_emitted_lower_bounds(self) -> None:
        impossible_root, _, impossible_index, impossible_bindings = self._build("test")
        impossible_manifest = self._rewrite_first_task_counters(
            impossible_root,
            candidate_count=0,
            trace_node_count=1,
        )
        with self.assertRaises(DiscoveryProjectionReaderError):
            self._read(
                impossible_root,
                impossible_manifest,
                impossible_index,
                impossible_bindings,
                split="test",
            )

        emitted_root, _, emitted_index, emitted_bindings = self._build("test")
        finding = self._finding(
            emitted_bindings[0],
            trace=[{"file": "src/middle.py", "line": 15}],
        )
        (emitted_root / "findings.jsonl").write_bytes(
            _canonical(finding) + b"\n"
        )
        emitted_manifest = self._rewrite_first_task_counters(
            emitted_root,
            candidate_count=1,
            emit_review_count=1,
            emitted_findings=1,
            trace_node_count=0,
            unique_findings=1,
        )
        with self.assertRaises(DiscoveryProjectionReaderError) as captured:
            self._read(
                emitted_root,
                emitted_manifest,
                emitted_index,
                emitted_bindings,
                split="test",
            )
        self.assertEqual("binding_mismatch", captured.exception.code)

    def test_train_aggregate_is_canonical_bounded_and_closed(self) -> None:
        root, _, index, bindings = self._build("train")
        aggregate = json.loads((root / "aggregate.json").read_text(encoding="utf-8"))
        aggregate["covered_advisories"] = 52
        aggregate["advisory_recall"] = 1.0
        (root / "aggregate.json").write_bytes(_canonical(aggregate) + b"\n")
        manifest = self._refresh_manifest(root)
        with self.assertRaises(DiscoveryProjectionReaderError):
            self._read(root, manifest, index, bindings, split="train")

    def test_train_aggregate_must_equal_trusted_recomputation(self) -> None:
        root, _, index, bindings = self._build("train")
        aggregate = json.loads((root / "aggregate.json").read_text(encoding="utf-8"))
        aggregate.update(
            {
                "advisory_recall": 1 / 51,
                "covered_advisories": 1,
                "entry_recall": 1 / 125,
                "matched_entries": 1,
            }
        )
        (root / "aggregate.json").write_bytes(_canonical(aggregate) + b"\n")
        manifest = self._refresh_manifest(root)
        with mock.patch.object(
            projection_reader,
            "evaluate_training_aggregate",
            return_value=self._zero_training_aggregate(),
        ) as oracle, self.assertRaises(DiscoveryProjectionReaderError) as captured:
            self._read(root, manifest, index, bindings, split="train")
        self.assertEqual("binding_mismatch", captured.exception.code)
        oracle.assert_called_once_with(self.trusted_benchmark_root, ())

    def test_hardlinked_member_is_rejected_without_following_it(self) -> None:
        root, manifest, index, bindings = self._build("test")
        os.link(root / "findings.jsonl", self.base / "outside-hardlink")
        with self.assertRaises(DiscoveryProjectionReaderError) as captured:
            self._read(root, manifest, index, bindings, split="test")
        self.assertEqual("unsafe_member", captured.exception.code)

    def test_second_pass_identity_change_is_detected_via_injected_reader(self) -> None:
        root, manifest, index, bindings = self._build("test")
        real_read = projection_reader._read_member_once
        calls: dict[str, int] = {}

        def changed(root_value, name, *, maximum_bytes):
            value = real_read(root_value, name, maximum_bytes=maximum_bytes)
            calls[name] = calls.get(name, 0) + 1
            if name == "manifest.json" and calls[name] == 2:
                payload, identity = value
                return payload, (*identity[:-1], int(identity[-1] or 0) ^ 1)
            return value

        with mock.patch.object(
            projection_reader, "_read_member_once", side_effect=changed
        ), self.assertRaises(DiscoveryProjectionReaderError) as captured:
            self._read(root, manifest, index, bindings, split="test")
        self.assertEqual("input_changed", captured.exception.code)


if __name__ == "__main__":
    unittest.main()
