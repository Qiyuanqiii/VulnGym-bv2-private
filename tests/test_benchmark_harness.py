from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from vulngym_agent.benchmark import (
    BenchmarkHarnessError,
    SnapshotTaskSpec,
    export_answer_free_tasks,
    validate_public_bundle,
)
from vulngym_agent.benchmark import harness
from vulngym_agent.benchmark.harness import (
    evaluate_training_aggregate,
    project_verified_entry_batches,
    project_verified_entries,
    publish_projected_entries,
)
from vulngym_agent.orchestrator import VerifiedFormalEntries, VerifiedTaskEntries


SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _jsonl(values: list[dict]) -> bytes:
    return b"".join(_canonical(value) + b"\n" for value in values)


def _bundle_index_payload(
    split: str, task_ids: list[str], *, manifest_sha256: str | None = None
) -> tuple[bytes, dict[str, str]]:
    digests = {
        task_id: hashlib.sha256(f"{split}:{position}".encode()).hexdigest()
        for position, task_id in enumerate(task_ids)
    }
    payload = _canonical(
        {
            "bundles": [
                {"dataset_sha256": digests[task_id], "task_id": task_id}
                for task_id in reversed(task_ids)
            ],
            "contract_version": 1,
            "manifest_sha256": manifest_sha256 or harness.PROFILE_MANIFEST_SHA256,
            "profile_id": harness.PROFILE_ID,
            "split": split,
        }
    )
    return payload, digests


def _location(file_name: str, line: int) -> dict:
    return {
        "code": "dangerous(value)",
        "desc": "annotation that must be stripped",
        "file": file_name,
        "line": line,
    }


def _entry(
    *,
    repo_url: str,
    commit: str,
    report_id: str,
    entry_id: str,
    verify: int,
    line: int = 10,
) -> dict:
    return {
        "commit": commit,
        "critical_operation": _location("src/sink.py", line + 10),
        "entry_id": entry_id,
        "entry_point": _location("src/input.py", line),
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "project",
        "repo_url": repo_url,
        "report_id": report_id,
        "source_link": f"https://github.com/advisories/{report_id}",
        "trace": [_location("src/middle.py", line + 5)],
        "verify": verify,
        "vuln_category_l1": "Injection",
        "vuln_category_l2": "Command injection",
        "vuln_ids": [report_id],
        "vuln_title": "Example vulnerability",
    }


def _profile_payloads(*, overlap: bool = False) -> dict[str, bytes]:
    record_schema = _canonical({"$schema": SCHEMA_URI, "type": "object"})
    manifest_schema = _canonical({"$schema": SCHEMA_URI, "type": "object"})

    train: list[dict] = []
    entry_number = 0
    for task_number in range(50):
        repo_url = f"https://github.com/example/repo{task_number:03d}"
        commit = f"{task_number + 1:040x}"
        advisory_numbers = (1, 2) if task_number == 0 else (task_number + 2,)
        advisories = []
        for advisory_number in advisory_numbers:
            report_id = (
                f"GHSA-{advisory_number:04X}-{advisory_number + 100:04X}-"
                f"{advisory_number + 200:04X}"
            )
            entries = []
            entry_total = 3 if advisory_number <= 23 else 2
            for offset in range(entry_total):
                entry_number += 1
                entries.append(
                    _entry(
                        repo_url=repo_url,
                        commit=commit,
                        report_id=report_id,
                        entry_id=f"entry-{entry_number:05d}",
                        verify=1,
                        line=10 + offset,
                    )
                )
            sample = entries[0]
            advisories.append(
                {
                    "commit": commit,
                    "origin": sample["origin"],
                    "project": sample["project"],
                    "repo_url": repo_url,
                    "report_id": report_id,
                    "source_link": sample["source_link"],
                    "verified_entries": entries,
                    "vuln_category_l1": sample["vuln_category_l1"],
                    "vuln_category_l2": sample["vuln_category_l2"],
                    "vuln_ids": sample["vuln_ids"],
                    "vuln_title": sample["vuln_title"],
                }
            )
        train.append(
            {
                "gold": {"advisories": advisories},
                "kind": "training_example",
                "schema_version": "1.0.0",
                "task": {
                    "commit": commit,
                    "instruction_id": "vulngym-whitebox-locate-v1",
                    "repo_url": repo_url,
                    "split": "train",
                    "task_id": f"VG-TRAIN-{task_number:020X}",
                },
            }
        )
    assert entry_number == 125

    test: list[dict] = []
    for task_number in range(20):
        repo_url = f"https://github.com/example/test{task_number:03d}"
        commit = f"{task_number + 1001:040x}"
        if overlap and task_number == 0:
            repo_url = train[0]["task"]["repo_url"]
            commit = train[0]["task"]["commit"]
        test.append(
            {
                "kind": "test_task",
                "schema_version": "1.0.0",
                "task": {
                    "commit": commit,
                    "instruction_id": "vulngym-whitebox-locate-v1",
                    "repo_url": repo_url,
                    "split": "test",
                    "task_id": f"VG-TEST-{task_number:020X}",
                },
            }
        )
    train_payload = _jsonl(train)
    test_payload = _jsonl(test)

    def artifact(path: str, payload: bytes, rows: int | None = None) -> dict:
        result = {
            "bytes": len(payload),
            "path": "benchmarks/vulngym_50_20_v1/" + path,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        if rows is not None:
            result["rows"] = rows
        return result

    manifest = {
        "artifacts": [
            artifact("schemas/benchmark-record.schema.json", record_schema),
            artifact("schemas/public-manifest.schema.json", manifest_schema),
            artifact("public/train.jsonl", train_payload, 50),
            artifact("public/test.jsonl", test_payload, 20),
        ],
        "build": {
            "dataset_id": "vulngym-50-20-v1",
            "test_tasks": 20,
            "train_tasks": 50,
        },
        "schema_version": "1.0.0",
        "source": {"revision": harness.PROFILE_SOURCE_REVISION},
    }
    return {
        "manifest": _canonical(manifest),
        "record_schema": record_schema,
        "manifest_schema": manifest_schema,
        "train": train_payload,
        "test": test_payload,
    }


class FixedProfileTests(unittest.TestCase):
    def test_validates_fixed_counts_and_opens_only_five_public_names(self) -> None:
        payloads = _profile_payloads()
        digest = hashlib.sha256(payloads["manifest"]).hexdigest()
        opened: list[str] = []

        def read(_root: object, logical_name: str) -> bytes:
            opened.append(logical_name)
            return payloads[logical_name]

        with mock.patch.object(harness, "_read_profile_file", side_effect=read), mock.patch.object(
            harness, "PROFILE_MANIFEST_SHA256", digest
        ):
            summary = validate_public_bundle("ignored")
        self.assertEqual(opened, ["manifest", "record_schema", "manifest_schema", "train", "test"])
        self.assertEqual(summary.train_tasks, 50)
        self.assertEqual(summary.test_tasks, 20)
        self.assertEqual(summary.train_advisories, 51)
        self.assertEqual(summary.train_entries, 125)

    def test_rejects_cross_split_snapshot_overlap(self) -> None:
        payloads = _profile_payloads(overlap=True)
        digest = hashlib.sha256(payloads["manifest"]).hexdigest()
        with mock.patch.object(
            harness,
            "_read_profile_file",
            side_effect=lambda _root, name: payloads[name],
        ), mock.patch.object(harness, "PROFILE_MANIFEST_SHA256", digest):
            with self.assertRaises(BenchmarkHarnessError) as ctx:
                validate_public_bundle("ignored")
        self.assertEqual(ctx.exception.code, "cross_split_overlap")

    def test_bad_manifest_digest_fails_before_other_public_reads(self) -> None:
        opened: list[str] = []

        def read(_root: object, name: str) -> bytes:
            opened.append(name)
            return b"{}"

        with mock.patch.object(harness, "_read_profile_file", side_effect=read):
            with self.assertRaises(BenchmarkHarnessError) as ctx:
                validate_public_bundle("ignored")
        self.assertEqual(ctx.exception.code, "manifest_digest_mismatch")
        self.assertEqual(opened, ["manifest"])

    def test_train_oracle_returns_only_perfect_aggregate_after_projection(self) -> None:
        payloads = _profile_payloads()
        digest = hashlib.sha256(payloads["manifest"]).hexdigest()
        with mock.patch.object(
            harness,
            "_read_profile_file",
            side_effect=lambda _root, name: payloads[name],
        ), mock.patch.object(harness, "PROFILE_MANIFEST_SHA256", digest):
            loaded = harness._load_and_validate_bundle("ignored")
            tasks = tuple(record.snapshot_spec() for record in loaded.train)
            batches: dict[str, list[dict]] = {}
            for record in loaded.train:
                entries: list[dict] = []
                for advisory in record.gold.advisories:
                    for entry in advisory.to_dict()["verified_entries"]:
                        entry["verify"] = 0
                        entries.append(entry)
                batches[record.task.task_id] = entries
            projected = project_verified_entry_batches(tasks, batches)
            findings = [
                finding for task_result in projected for finding in task_result.findings
            ]
            aggregate = evaluate_training_aggregate("ignored", findings)
        self.assertEqual(aggregate.covered_advisories, 51)
        self.assertEqual(aggregate.matched_entries, 125)
        self.assertEqual(aggregate.advisory_recall, 1.0)
        self.assertEqual(aggregate.entry_recall, 1.0)
        self.assertFalse(
            set(aggregate.to_dict())
            & {"task_id", "report_id", "entry_id", "finding_id", "details"}
        )

    def test_official_tolerance_is_fixed_and_distant_locations_do_not_match(self) -> None:
        payloads = _profile_payloads()
        digest = hashlib.sha256(payloads["manifest"]).hexdigest()
        with mock.patch.object(
            harness,
            "_read_profile_file",
            side_effect=lambda _root, name: payloads[name],
        ), mock.patch.object(harness, "PROFILE_MANIFEST_SHA256", digest):
            loaded = harness._load_and_validate_bundle("ignored")
            task = loaded.train[0].snapshot_spec()
            distant = _entry(
                repo_url=task.repo_url,
                commit=task.commit,
                report_id="GHSA-9999-AAAA-BBBB",
                entry_id="entry-99999",
                verify=0,
                line=500,
            )
            finding = project_verified_entries(task, [distant]).findings[0]
            aggregate = evaluate_training_aggregate("ignored", [finding])
        self.assertEqual(aggregate.covered_advisories, 0)
        self.assertEqual(aggregate.matched_entries, 0)


class ProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.task = SnapshotTaskSpec(
            task_id="VG-TEST-" + "A" * 20,
            repo_url="https://github.com/example/project",
            commit="a" * 40,
            split="test",
        )
        self.entry = _entry(
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            report_id="GHSA-1234-ABCD-5678",
            entry_id="entry-00001",
            verify=0,
        )

    def test_projects_exact_boundary_with_stable_semantic_deduplication(self) -> None:
        duplicate = deepcopy(self.entry)
        duplicate["entry_id"] = "entry-00002"
        duplicate["trace"][0]["line"] = 16
        result = project_verified_entries(self.task, [duplicate, self.entry])
        self.assertEqual(result.stats.raw_entries, 2)
        self.assertEqual(result.stats.deduplicated_findings, 1)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(
            set(finding),
            {
                "task_id",
                "finding_id",
                "repo_url",
                "commit",
                "entry_point",
                "critical_operation",
                "trace",
            },
        )
        self.assertEqual(set(finding["entry_point"]), {"file", "line"})
        self.assertNotIn("report_id", finding)
        reverse = project_verified_entries(self.task, [self.entry, duplicate])
        self.assertEqual(result.findings, reverse.findings)
        with self.assertRaises(TypeError):
            result.findings[0]["entry_point"]["line"] = 999  # type: ignore[index]
        with self.assertRaises(FrozenInstanceError):
            result.task_id = "VG-TEST-" + "B" * 20  # type: ignore[misc]

    def test_task_generator_is_snapshotted_before_multi_pass_projection(self) -> None:
        projected = project_verified_entry_batches(
            (task for task in (self.task,)),
            {self.task.task_id: (entry for entry in (self.entry,))},
        )
        self.assertEqual(len(projected), 1)
        self.assertEqual(len(projected[0].findings), 1)

    def test_aggregate_trace_node_budget_is_enforced(self) -> None:
        entries = []
        for number in range(17):
            entry = deepcopy(self.entry)
            entry["entry_id"] = f"entry-{10000 + number:05d}"
            entry["trace"] = [
                _location("src/middle.py", position + 1)
                for position in range(256)
            ]
            entries.append(entry)
        with self.assertRaises(BenchmarkHarnessError) as ctx:
            project_verified_entries(self.task, entries, top_k=64)
        self.assertEqual(ctx.exception.code, "trace_node_limit_exceeded")

    def test_rejects_gold_and_cross_snapshot_entries(self) -> None:
        gold = deepcopy(self.entry)
        gold["verify"] = 1
        with self.assertRaises(BenchmarkHarnessError) as ctx:
            project_verified_entries(self.task, [gold])
        self.assertEqual(ctx.exception.code, "invalid_formal_entry")

        wrong = deepcopy(self.entry)
        wrong["commit"] = "b" * 40
        with self.assertRaises(BenchmarkHarnessError) as ctx:
            project_verified_entries(self.task, [wrong])
        self.assertEqual(ctx.exception.code, "entry_binding_mismatch")

    def test_projection_publish_is_transactional_bounded_and_no_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "submission"
            projected = publish_projected_entries(
                [self.task],
                {self.task.task_id: [self.entry]},
                split="test",
                output_dir=output,
            )
            self.assertEqual(len(projected[0].findings), 1)
            rows = [json.loads(line) for line in (output / "findings.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["top_k"], 64)
            self.assertEqual(manifest["raw_entries"], 1)
            with self.assertRaises(BenchmarkHarnessError) as ctx:
                publish_projected_entries(
                    [self.task],
                    {self.task.task_id: [self.entry]},
                    split="test",
                    output_dir=output,
                )
            self.assertEqual(ctx.exception.code, "output_exists")

    @unittest.skipUnless(os.name == "nt", "Windows path-swap fallback regression")
    def test_parent_swap_cannot_publish_or_delete_replacement_staging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "parent"
            parent.mkdir()
            moved_parent = root / "moved-parent"
            output = parent / "submission"
            original_rename = harness._rename_directory_noreplace

            def swap_parent(source: Path, destination: Path, **kwargs: object) -> None:
                parent.rename(moved_parent)
                parent.mkdir()
                replacement = parent / source.name
                replacement.mkdir()
                (replacement / "evil.txt").write_text("replacement", encoding="utf-8")
                original_rename(source, destination, **kwargs)

            with mock.patch.object(
                harness, "_rename_directory_noreplace", side_effect=swap_parent
            ):
                with self.assertRaises(BenchmarkHarnessError) as ctx:
                    harness._publish_directory(output, {"safe.txt": b"safe\n"})

            self.assertIn(
                ctx.exception.code,
                {"output_parent_changed", "output_publication_changed"},
            )
            self.assertEqual((output / "evil.txt").read_text(encoding="utf-8"), "replacement")
            self.assertTrue(any(path.name.endswith(".staging") for path in moved_parent.iterdir()))


class VerifiedReplayHarnessTests(unittest.TestCase):
    def test_index_rejects_duplicate_extra_and_missing_membership(self) -> None:
        task = harness.SnapshotTaskSpec(
            task_id="VG-TEST-" + "A" * 20,
            repo_url="https://github.com/example/project",
            commit="a" * 40,
            split="test",
        )
        digest = "1" * 64
        cases = (
            [],
            [
                {"task_id": task.task_id, "dataset_sha256": digest},
                {"task_id": task.task_id, "dataset_sha256": "2" * 64},
            ],
            [
                {"task_id": task.task_id, "dataset_sha256": digest},
                {"task_id": "VG-TEST-" + "B" * 20, "dataset_sha256": "2" * 64},
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "index.json"
            for bundles in cases:
                payload = _canonical(
                    {
                        "bundles": bundles,
                        "contract_version": 1,
                        "manifest_sha256": harness.PROFILE_MANIFEST_SHA256,
                        "profile_id": harness.PROFILE_ID,
                        "split": "test",
                    }
                )
                path.write_bytes(payload)
                with self.assertRaises(BenchmarkHarnessError):
                    harness.load_artifact_bundle_index(
                        path,
                        expected_sha256=hashlib.sha256(payload).hexdigest(),
                        split="test",
                        tasks=(task,),
                    )

    def test_test_projection_reads_no_train_gold_and_supports_two_roots(self) -> None:
        payloads = _profile_payloads()
        profile_digest = hashlib.sha256(payloads["manifest"]).hexdigest()
        task_ids = [
            f"VG-TEST-{number:020X}" for number in range(20)
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            benchmark = root / "benchmark"
            artifacts = root / "artifacts"
            index_path = root / "index.json"
            output = root / "output"
            benchmark.mkdir()
            artifacts.mkdir()
            index_payload, dataset_digests = _bundle_index_payload(
                "test", task_ids, manifest_sha256=profile_digest
            )
            index_path.write_bytes(index_payload)
            opened: list[str] = []

            def read_profile(_root: object, name: str) -> bytes:
                opened.append(name)
                return payloads[name]

            def read_replay(bundle: Path, **kwargs: object) -> VerifiedFormalEntries:
                task_id = Path(bundle).name
                number = int(task_id.removeprefix("VG-TEST-"), 16)
                repo_url = f"https://github.com/example/test{number:03d}"
                commit = f"{number + 1001:040x}"
                tasks: tuple[VerifiedTaskEntries, ...]
                if number == 0:
                    first = _entry(
                        repo_url=repo_url,
                        commit=commit,
                        report_id="GHSA-1111-AAAA-BBBB",
                        entry_id="entry-90001",
                        verify=0,
                        line=10,
                    )
                    second = _entry(
                        repo_url=repo_url,
                        commit=commit,
                        report_id="GHSA-2222-AAAA-BBBB",
                        entry_id="entry-90002",
                        verify=0,
                        line=100,
                    )
                    tasks = (
                        VerifiedTaskEntries("internal:one", "finalized", (first,)),
                        VerifiedTaskEntries("internal:two", "finalized", (second,)),
                    )
                else:
                    tasks = (
                        VerifiedTaskEntries(
                            f"internal:manual:{number}", "manual_review"
                        ),
                    )
                self.assertEqual(
                    kwargs["expected_dataset_sha256"], dataset_digests[task_id]
                )
                self.assertEqual(kwargs["limits"].max_input_records, 256)
                return VerifiedFormalEntries(dataset_digests[task_id], tasks)

            with mock.patch.object(
                harness, "PROFILE_MANIFEST_SHA256", profile_digest
            ), mock.patch.object(
                harness, "_read_profile_file", side_effect=read_profile
            ), mock.patch.object(
                harness, "read_verified_formal_entries", side_effect=read_replay
            ) as replay, mock.patch.object(
                harness, "evaluate_training_aggregate"
            ) as oracle:
                summary = harness.project_verified_replay_bundles(
                    benchmark,
                    artifact_root=artifacts,
                    bundle_index=index_path,
                    bundle_index_sha256=hashlib.sha256(index_payload).hexdigest(),
                    output_dir=output,
                    split="test",
                )

            self.assertEqual(replay.call_count, 20)
            oracle.assert_not_called()
            self.assertNotIn("train", opened)
            self.assertEqual(summary.finding_count, 2)
            self.assertFalse((output / "aggregate.json").exists())
            findings = (output / "findings.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(findings), 2)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["root_task_count"], 21)
            self.assertEqual(manifest["finalized_root_count"], 2)
            self.assertEqual(manifest["manual_review_root_count"], 19)
            self.assertEqual(len(manifest["bundle_datasets"]), 20)

    def test_train_oracle_runs_only_after_all_replays_and_publishes_aggregate(self) -> None:
        payloads = _profile_payloads()
        profile_digest = hashlib.sha256(payloads["manifest"]).hexdigest()
        task_ids = [f"VG-TRAIN-{number:020X}" for number in range(50)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            benchmark = root / "benchmark"
            artifacts = root / "artifacts"
            index_path = root / "index.json"
            output = root / "output"
            benchmark.mkdir()
            artifacts.mkdir()
            index_payload, dataset_digests = _bundle_index_payload(
                "train", task_ids, manifest_sha256=profile_digest
            )
            index_path.write_bytes(index_payload)
            reads: list[str] = []

            def read_replay(bundle: Path, **_kwargs: object) -> VerifiedFormalEntries:
                task_id = Path(bundle).name
                reads.append(task_id)
                return VerifiedFormalEntries(
                    dataset_digests[task_id],
                    (VerifiedTaskEntries(f"internal:failed:{len(reads)}", "failed"),),
                )

            aggregate = harness.TrainingAggregate(51, 0, 0.0, 125, 0, 0.0, 0)

            def oracle(_root: object, findings: object) -> object:
                self.assertEqual(len(reads), 50)
                self.assertEqual(tuple(findings), ())
                return aggregate

            with mock.patch.object(
                harness, "PROFILE_MANIFEST_SHA256", profile_digest
            ), mock.patch.object(
                harness,
                "_read_profile_file",
                side_effect=lambda _root, name: payloads[name],
            ), mock.patch.object(
                harness, "read_verified_formal_entries", side_effect=read_replay
            ), mock.patch.object(
                harness, "evaluate_training_aggregate", side_effect=oracle
            ) as evaluate:
                summary = harness.project_verified_replay_bundles(
                    benchmark,
                    artifact_root=artifacts,
                    bundle_index=index_path,
                    bundle_index_sha256=hashlib.sha256(index_payload).hexdigest(),
                    output_dir=output,
                    split="train",
                )
            evaluate.assert_called_once()
            self.assertEqual(summary.aggregate, aggregate)
            self.assertEqual(
                json.loads((output / "aggregate.json").read_text(encoding="utf-8")),
                aggregate.to_dict(),
            )

    def test_total_output_budget_stops_before_later_replays_or_train_oracle(self) -> None:
        tasks = tuple(
            harness.SnapshotTaskSpec(
                task_id=f"VG-TRAIN-{number:020X}",
                repo_url=f"https://github.com/example/project-{number}",
                commit=f"{number + 1:040x}",
                split="train",
            )
            for number in range(2)
        )
        digests = tuple(f"{number + 1:064x}" for number in range(2))
        index = harness.ArtifactBundleIndex(
            contract_version=1,
            profile_id=harness.PROFILE_ID,
            manifest_sha256=harness.PROFILE_MANIFEST_SHA256,
            split="train",
            bundles=tuple(
                harness.ArtifactBundleDigest(task.task_id, digest)
                for task, digest in zip(tasks, digests, strict=True)
            ),
        )
        entries = {
            task.task_id: _entry(
                repo_url=task.repo_url,
                commit=task.commit,
                report_id=f"GHSA-{number + 1:04X}-ABCD-5678",
                entry_id=f"entry-{number + 1:05d}",
                verify=0,
            )
            for number, task in enumerate(tasks)
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            benchmark = root / "benchmark"
            artifacts = root / "artifacts"
            index_path = root / "index.json"
            benchmark.mkdir()
            artifacts.mkdir()
            index_path.write_text("{}", encoding="utf-8")

            def read_replay(bundle: Path, **_kwargs: object) -> VerifiedFormalEntries:
                task = next(item for item in tasks if item.task_id == bundle.name)
                position = tasks.index(task)
                return VerifiedFormalEntries(
                    digests[position],
                    (
                        VerifiedTaskEntries(
                            f"internal:{position}",
                            "finalized",
                            (entries[task.task_id],),
                        ),
                    ),
                )

            with mock.patch.object(
                harness, "load_answer_free_tasks", return_value=tasks
            ), mock.patch.object(
                harness, "load_artifact_bundle_index", return_value=index
            ), mock.patch.object(
                harness, "read_verified_formal_entries", side_effect=read_replay
            ) as replay, mock.patch.object(
                harness, "evaluate_training_aggregate"
            ) as oracle, mock.patch.object(
                harness, "MAX_TOTAL_OUTPUT_BYTES", 1
            ):
                with self.assertRaises(BenchmarkHarnessError) as ctx:
                    harness.project_verified_replay_bundles(
                        benchmark,
                        artifact_root=artifacts,
                        bundle_index=index_path,
                        bundle_index_sha256="0" * 64,
                        output_dir=root / "output",
                        split="train",
                    )

            self.assertEqual(ctx.exception.code, "output_limit_exceeded")
            self.assertEqual(replay.call_count, 1)
            oracle.assert_not_called()

    def test_projection_rejects_overlapping_paths_before_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            benchmark = root / "benchmark"
            benchmark.mkdir()
            artifacts = benchmark / "artifacts"
            artifacts.mkdir()
            index = root / "index.json"
            index.write_text("{}", encoding="utf-8")
            with self.assertRaises(BenchmarkHarnessError) as ctx:
                harness.project_verified_replay_bundles(
                    benchmark,
                    artifact_root=artifacts,
                    bundle_index=index,
                    bundle_index_sha256="0" * 64,
                    output_dir=root / "output",
                    split="test",
                )
        self.assertEqual(ctx.exception.code, "path_overlap")
        self.assertNotIn(str(root), str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
