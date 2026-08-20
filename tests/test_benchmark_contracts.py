from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from vulngym_agent.benchmark import (
    BenchmarkContractError,
    BenchmarkReadLimits,
    EvaluationTaskSpec,
    PublicTestRecord,
    PublicTrainingRecord,
    TrainingGold,
    iter_evaluator_findings,
    iter_public_benchmark_jsonl,
    load_public_benchmark_jsonl,
    parse_public_benchmark_record,
)


REPO_URL = "https://github.com/example/project"
COMMIT = "a" * 40
REPORT_ID = "GHSA-1234-ABCD-5678"


def _task(*, split: str, suffix: str = "0" * 20) -> dict:
    return {
        "commit": COMMIT,
        "instruction_id": "vulngym-whitebox-locate-v1",
        "repo_url": REPO_URL,
        "split": split,
        "task_id": f"VG-{split.upper()}-{suffix}",
    }


def _location(file_name: str, line: int | str) -> dict:
    return {
        "code": "dangerous(value)",
        "desc": "public training annotation",
        "file": file_name,
        "line": line,
    }


def _entry(*, entry_id: str = "entry-00001") -> dict:
    return {
        "commit": COMMIT,
        "critical_operation": _location("src/sink.py", "20-21"),
        "entry_id": entry_id,
        "entry_point": _location("src/input.py", 10),
        "origin": "GitHub Advisory Database (reviewed)",
        "project": "project",
        "repo_url": REPO_URL,
        "report_id": REPORT_ID,
        "source_link": "https://github.com/advisories/GHSA-1234-abcd-5678",
        "trace": [_location("src/middle.py", 15)],
        "verify": 1,
        "vuln_category_l1": "Injection",
        "vuln_category_l2": "Command injection",
        "vuln_ids": ["CVE-2026-12345", REPORT_ID],
        "vuln_title": "Example vulnerability",
    }


def _advisory(*, entry_id: str = "entry-00001") -> dict:
    entry = _entry(entry_id=entry_id)
    return {
        "commit": COMMIT,
        "origin": entry["origin"],
        "project": entry["project"],
        "repo_url": REPO_URL,
        "report_id": REPORT_ID,
        "source_link": entry["source_link"],
        "verified_entries": [entry],
        "vuln_category_l1": entry["vuln_category_l1"],
        "vuln_category_l2": entry["vuln_category_l2"],
        "vuln_ids": entry["vuln_ids"],
        "vuln_title": entry["vuln_title"],
    }


def _test_record(*, suffix: str = "0" * 20) -> dict:
    return {
        "kind": "test_task",
        "schema_version": "1.0.0",
        "task": _task(split="test", suffix=suffix),
    }


def _training_record(*, suffix: str = "0" * 20) -> dict:
    return {
        "gold": {"advisories": [_advisory()]},
        "kind": "training_example",
        "schema_version": "1.0.0",
        "task": _task(split="train", suffix=suffix),
    }


def _jsonl(*values: dict) -> bytes:
    return b"".join(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        + b"\n"
        for value in values
    )


class PublicRecordContractTests(unittest.TestCase):
    def test_test_record_becomes_answer_free_evaluation_spec(self) -> None:
        record = parse_public_benchmark_record(_test_record())

        self.assertIsInstance(record, PublicTestRecord)
        spec = record.evaluation_spec()
        self.assertEqual(
            spec.to_dict(),
            {
                "commit": COMMIT,
                "instruction_id": "vulngym-whitebox-locate-v1",
                "repo_url": REPO_URL,
                "task_id": "VG-TEST-" + "0" * 20,
            },
        )
        self.assertNotIn("gold", record.to_dict())
        self.assertFalse(hasattr(record, "to_run_task"))
        self.assertFalse(hasattr(spec, "to_run_task"))
        with self.assertRaises(FrozenInstanceError):
            spec.commit = "b" * 40  # type: ignore[misc]

    def test_test_record_rejects_any_gold_member(self) -> None:
        value = _test_record()
        value["gold"] = {"advisories": []}
        with self.assertRaisesRegex(BenchmarkContractError, "keys differ"):
            parse_public_benchmark_record(value)

        with self.assertRaisesRegex(BenchmarkContractError, "not a public") as ctx:
            parse_public_benchmark_record(
                {
                    "kind": "test_gold",
                    "schema_version": "1.0.0",
                    "task_id": "VG-TEST-" + "0" * 20,
                    "gold": {"advisories": []},
                }
            )
        self.assertEqual(ctx.exception.code, "private_gold_forbidden")

    def test_training_gold_is_strict_immutable_calibration_data(self) -> None:
        source = _training_record()
        record = parse_public_benchmark_record(source)

        self.assertIsInstance(record, PublicTrainingRecord)
        self.assertEqual(record.to_dict(), source)
        entries = tuple(record.gold.iter_entries())
        self.assertEqual(len(entries), 1)
        with self.assertRaises(TypeError):
            entries[0]["verify"] = 0  # type: ignore[index]
        self.assertFalse(hasattr(record, "to_run_task"))
        self.assertFalse(hasattr(record.gold, "to_run_task"))
        snapshot = record.snapshot_spec()
        self.assertEqual(snapshot.split, "train")
        self.assertNotIn("gold", snapshot.to_dict())
        self.assertFalse(hasattr(snapshot, "to_run_task"))

    def test_training_record_requires_gold_and_exact_cross_bindings(self) -> None:
        missing = _training_record()
        del missing["gold"]
        with self.assertRaisesRegex(BenchmarkContractError, "keys differ"):
            parse_public_benchmark_record(missing)

        mismatched = _training_record()
        mismatched["gold"]["advisories"][0]["verified_entries"][0][
            "vuln_category_l1"
        ] = "different"
        with self.assertRaisesRegex(BenchmarkContractError, "does not match"):
            parse_public_benchmark_record(mismatched)

        unverified = _training_record()
        unverified["gold"]["advisories"][0]["verified_entries"][0]["verify"] = 0
        with self.assertRaisesRegex(BenchmarkContractError, "verify must equal 1"):
            parse_public_benchmark_record(unverified)

    def test_task_contract_rejects_noncanonical_identity(self) -> None:
        wrong_prefix = _test_record()
        wrong_prefix["task"]["task_id"] = "VG-TRAIN-" + "0" * 20
        with self.assertRaisesRegex(BenchmarkContractError, "prefix"):
            parse_public_benchmark_record(wrong_prefix)

        dot_git = _test_record()
        dot_git["task"]["repo_url"] += ".git"
        with self.assertRaisesRegex(BenchmarkContractError, "canonical"):
            parse_public_benchmark_record(dot_git)

        upper_dot_git = _test_record()
        upper_dot_git["task"]["repo_url"] += ".GIT"
        with self.assertRaisesRegex(BenchmarkContractError, "canonical"):
            parse_public_benchmark_record(upper_dot_git)

    def test_direct_construction_preserves_task_gold_and_uniqueness_invariants(self) -> None:
        record = parse_public_benchmark_record(_training_record())
        assert isinstance(record, PublicTrainingRecord)
        with self.assertRaises(BenchmarkContractError) as ctx:
            PublicTrainingRecord(
                task=replace(record.task, commit="b" * 40), gold=record.gold
            )
        self.assertEqual(ctx.exception.code, "snapshot_mismatch")

        with self.assertRaises(BenchmarkContractError) as ctx:
            TrainingGold(record.gold.advisories + record.gold.advisories)
        self.assertEqual(ctx.exception.code, "duplicate_report_id")


class StreamingParserTests(unittest.TestCase):
    def test_streams_records_and_enforces_global_task_snapshot_uniqueness(self) -> None:
        first = _test_record(suffix="0" * 20)
        second = _test_record(suffix="1" * 20)
        second["task"]["repo_url"] = "https://github.com/example/other"
        records = tuple(
            iter_public_benchmark_jsonl(
                BytesIO(_jsonl(first, second)), expected_split="test"
            )
        )
        self.assertEqual([item.task.task_id for item in records], [
            "VG-TEST-" + "0" * 20,
            "VG-TEST-" + "1" * 20,
        ])

        duplicate_id = _test_record(suffix="0" * 20)
        duplicate_id["task"]["repo_url"] = "https://github.com/example/other"
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(_jsonl(first, duplicate_id)), expected_split="test"
                )
            )
        self.assertEqual(ctx.exception.code, "duplicate_task_id")

        duplicate_snapshot = _test_record(suffix="1" * 20)
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(_jsonl(first, duplicate_snapshot)), expected_split="test"
                )
            )
        self.assertEqual(ctx.exception.code, "duplicate_snapshot")

        case_alias = _test_record(suffix="1" * 20)
        case_alias["task"]["repo_url"] = "https://github.com/Example/Project"
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(_jsonl(first, case_alias)), expected_split="test"
                )
            )
        self.assertEqual(ctx.exception.code, "duplicate_snapshot")

    def test_stream_rejects_report_ids_repeated_across_training_tasks(self) -> None:
        first = _training_record(suffix="0" * 20)
        second = _training_record(suffix="1" * 20)
        second_repo = "https://github.com/example/other"
        second["task"]["repo_url"] = second_repo
        second["gold"]["advisories"][0]["repo_url"] = second_repo
        second["gold"]["advisories"][0]["verified_entries"][0][
            "repo_url"
        ] = second_repo
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(_jsonl(first, second)), expected_split="train"
                )
            )
        self.assertEqual(ctx.exception.code, "duplicate_report_id")

    def test_expected_split_is_not_inferred_from_filename(self) -> None:
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(_jsonl(_test_record())), expected_split="train"
                )
            )
        self.assertEqual(ctx.exception.code, "split_mismatch")

    def test_rejects_duplicate_keys_nonfinite_numbers_and_surrogates(self) -> None:
        valid = json.dumps(_test_record(), separators=(",", ":"))
        duplicate = valid.replace(
            '"kind":"test_task"',
            '"kind":"test_task","kind":"test_task"',
            1,
        ).encode("utf-8") + b"\n"
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(duplicate), expected_split="test"
                )
            )
        self.assertEqual(ctx.exception.code, "duplicate_json_key")

        nonfinite = valid.replace(
            '"schema_version":"1.0.0"', '"schema_version":NaN', 1
        ).encode("utf-8") + b"\n"
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(nonfinite), expected_split="test"
                )
            )
        self.assertEqual(ctx.exception.code, "invalid_json_number")

        surrogate = valid.replace("test_task", "test_\\ud800task", 1).encode(
            "ascii"
        ) + b"\n"
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(surrogate), expected_split="test"
                )
            )
        self.assertEqual(ctx.exception.code, "invalid_unicode")

    def test_enforces_line_total_record_and_termination_limits(self) -> None:
        payload = _jsonl(_test_record())
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(payload),
                    expected_split="test",
                    limits=BenchmarkReadLimits(max_line_bytes=32),
                )
            )
        self.assertEqual(ctx.exception.code, "line_bytes_exceeded")

        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(payload),
                    expected_split="test",
                    limits=BenchmarkReadLimits(max_total_bytes=32),
                )
            )
        self.assertEqual(ctx.exception.code, "total_bytes_exceeded")

        second = _test_record(suffix="1" * 20)
        second["task"]["repo_url"] = "https://github.com/example/other"
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(_jsonl(_test_record(), second)),
                    expected_split="test",
                    limits=BenchmarkReadLimits(max_records=1),
                )
            )
        self.assertEqual(ctx.exception.code, "record_limit_exceeded")

        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_public_benchmark_jsonl(
                    BytesIO(payload.rstrip(b"\n")), expected_split="test"
                )
            )
        self.assertEqual(ctx.exception.code, "unterminated_line")

    def test_path_loader_checks_the_same_bounded_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.jsonl"
            path.write_bytes(_jsonl(_test_record()))
            records = load_public_benchmark_jsonl(path, expected_split="test")
            self.assertEqual(len(records), 1)
            with self.assertRaises(BenchmarkContractError) as ctx:
                load_public_benchmark_jsonl(
                    path,
                    expected_split="test",
                    limits=BenchmarkReadLimits(max_total_bytes=32),
                )
            self.assertEqual(ctx.exception.code, "total_bytes_exceeded")

            with self.assertRaises(BenchmarkContractError) as ctx:
                load_public_benchmark_jsonl(
                    Path(directory), expected_split="test"
                )
            self.assertEqual(ctx.exception.code, "unsafe_input_path")

            linked = Path(directory) / "linked.jsonl"
            try:
                linked.symlink_to(path)
            except OSError as error:
                self.skipTest(f"file symlinks are unavailable: {error}")
            with self.assertRaises(BenchmarkContractError) as ctx:
                load_public_benchmark_jsonl(linked, expected_split="test")
            self.assertEqual(ctx.exception.code, "unsafe_input_path")

    def test_path_loader_detects_file_identity_swap_during_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory) / "expected.jsonl"
            replacement = Path(directory) / "replacement.jsonl"
            expected.write_bytes(_jsonl(_test_record()))
            alternate = _test_record(suffix="1" * 20)
            alternate["task"]["repo_url"] = "https://github.com/example/other"
            replacement.write_bytes(_jsonl(alternate))
            replacement_stream = replacement.open("rb")
            try:
                with mock.patch.object(
                    Path, "open", return_value=replacement_stream
                ):
                    with self.assertRaises(BenchmarkContractError) as ctx:
                        load_public_benchmark_jsonl(
                            expected, expected_split="test"
                        )
            finally:
                replacement_stream.close()
            self.assertEqual(ctx.exception.code, "input_changed")


class FindingProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.task = EvaluationTaskSpec(
            task_id="VG-TEST-" + "0" * 20,
            repo_url=REPO_URL,
            commit=COMMIT,
        )

    def test_projects_multiple_findings_and_strips_non_evaluator_metadata(self) -> None:
        findings = [
            {
                "repo_url": REPO_URL,
                "commit": COMMIT,
                "report_id": REPORT_ID,
                "entry_id": "entry-00001",
                "entry_point": _location("src/input.py", 10),
                "critical_operation": _location("src/sink.py", "20-21"),
                "trace": [_location("src/middle.py", 15)],
                "vuln_title": "must not cross evaluator boundary",
            },
            {
                "entry_point": {"file": "src/other.py", "line": 30},
                "critical_operation": {"file": "src/final.py", "line": 40},
            },
        ]

        projected = tuple(iter_evaluator_findings(self.task, findings))

        self.assertEqual(len(projected), 2)
        self.assertEqual(
            set(projected[0]),
            {"repo_url", "commit", "entry_point", "critical_operation", "trace"},
        )
        self.assertEqual(projected[0]["entry_point"], {
            "file": "src/input.py",
            "line": 10,
        })
        self.assertNotIn("report_id", projected[0])
        self.assertNotIn("code", projected[0]["critical_operation"])
        self.assertEqual(
            set(projected[1]),
            {"repo_url", "commit", "entry_point", "critical_operation"},
        )

        training = parse_public_benchmark_record(_training_record())
        calibration = tuple(
            iter_evaluator_findings(training.snapshot_spec(), findings[:1])
        )
        self.assertEqual(len(calibration), 1)

    def test_projection_rejects_cross_task_or_unsafe_findings(self) -> None:
        mismatched = {
            "repo_url": "https://github.com/example/other",
            "entry_point": {"file": "src/input.py", "line": 10},
            "critical_operation": {"file": "src/sink.py", "line": 20},
        }
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(iter_evaluator_findings(self.task, [mismatched]))
        self.assertEqual(ctx.exception.code, "finding_binding_mismatch")

        unsafe = {
            "entry_point": {"file": "../secret", "line": 10},
            "critical_operation": {"file": "src/sink.py", "line": 20},
        }
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(iter_evaluator_findings(self.task, [unsafe]))
        self.assertEqual(ctx.exception.code, "invalid_finding_path")

        reversed_range = {
            "entry_point": {"file": "src/input.py", "line": "12-10"},
            "critical_operation": {"file": "src/sink.py", "line": 20},
        }
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(iter_evaluator_findings(self.task, [reversed_range]))
        self.assertEqual(ctx.exception.code, "invalid_finding_line")

    def test_projection_is_bounded_and_accepts_zero_findings(self) -> None:
        self.assertEqual(tuple(iter_evaluator_findings(self.task, [])), ())
        finding = {
            "entry_point": {"file": "src/input.py", "line": 10},
            "critical_operation": {"file": "src/sink.py", "line": 20},
        }
        with self.assertRaises(BenchmarkContractError) as ctx:
            tuple(
                iter_evaluator_findings(
                    self.task, [finding, finding], max_findings=1
                )
            )
        self.assertEqual(ctx.exception.code, "finding_limit_exceeded")


if __name__ == "__main__":
    unittest.main()
