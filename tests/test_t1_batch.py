from __future__ import annotations

from contextlib import redirect_stderr
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from vulngym_agent.adapters import ENTRY_FIELDS, SchemaAdapter
from vulngym_agent.agents import T1DeterministicValidator
from vulngym_agent.cli import (
    DEFAULT_MAX_INPUT_LINE_BYTES,
    DEFAULT_MAX_PACKAGE_FILES,
    DEFAULT_MAX_RECORDS,
    DEFAULT_MAX_TRACE_NODES,
    HARD_MAX_INPUT_LINE_BYTES,
    HARD_MAX_PACKAGE_FILES,
    HARD_MAX_RECORDS,
    HARD_MAX_TRACE_NODES,
    InputRecord,
    RepositoryResolver,
    _atomic_write_many,
    iter_jsonl,
    main,
    run_batch,
)
from vulngym_agent.tools.git import GitRepository


ROOT = Path(__file__).resolve().parents[1]
SOURCE = """def entry(value):
    prepared = value.strip()
    return sink(prepared)

def sink(value):
    return dangerous(value)
"""
EVIDENCE_ID_RE = re.compile(r"EV-[A-Z0-9][A-Z0-9._-]*\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
SIDECAR_NAMES = {
    "alternatives",
    "assumptions",
    "confidence",
    "evidence_id",
    "evidence_ids",
    "evidence_refs",
    "status",
    "suggested_fix",
    "tool_calls",
}


class T1BatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_directory = tempfile.TemporaryDirectory()
        cls.repo_path = Path(cls._temporary_directory.name)
        cls.source_path = cls.repo_path / "src" / "app.py"
        cls.source_path.parent.mkdir(parents=True)

        cls._git("init", "-q")
        cls._git("config", "user.name", "VulnGym T1 Test")
        cls._git("config", "user.email", "vulngym-t1@example.invalid")
        cls.source_path.write_text(SOURCE, encoding="utf-8")
        (cls.repo_path / "src" / "non_utf8.py").write_bytes(b"\xff\xfe\n")
        cls._git("add", "--", "src/app.py", "src/non_utf8.py")
        cls._git("commit", "-q", "-m", "candidate snapshot")
        cls.commit = cls._git("rev-parse", "HEAD").stdout.strip()
        cls.repo_url = "https://github.com/example/vulngym-t1-fixture"

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary_directory.cleanup()

    @classmethod
    def _git(cls, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=cls.repo_path,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def candidate(self) -> dict[str, object]:
        report_id = "GHSA-ABCD-1234-EFGH"
        return {
            "commit": self.commit,
            "critical_operation": {
                "code": "return dangerous(value)",
                "file": "src/app.py",
                "line": 6,
            },
            "entry_id": "entry-00001",
            "entry_point": {
                "code": "def entry(value):",
                "file": "src/app.py",
                "line": 1,
            },
            "origin": "GitHub Advisory Database (reviewed)",
            "project": "vulngym-t1-fixture",
            "repo_url": self.repo_url,
            "report_id": report_id,
            "source_link": f"https://github.com/advisories/{report_id}",
            "trace": [],
            "verify": 0,
            "vuln_category_l1": "Injection",
            "vuln_category_l2": "Command Injection",
            "vuln_ids": ["CVE-2026-12345", report_id],
            "vuln_title": "Fixture command injection",
        }

    def validator(self) -> T1DeterministicValidator:
        return T1DeterministicValidator(GitRepository(self.repo_path))

    def assert_evidence_contract(self, evidence: dict[str, object]) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "evidence.schema.json").read_text(encoding="utf-8")
        )
        self.assertLessEqual(set(evidence), set(schema["properties"]))
        self.assertTrue(set(schema["required"]).issubset(evidence))
        self.assertRegex(str(evidence["evidence_id"]), EVIDENCE_ID_RE)
        self.assertIn(evidence["source_type"], schema["properties"]["source_type"]["enum"])
        self.assertIsInstance(evidence["snippet"], str)
        self.assertTrue(str(evidence["snippet"]).strip())
        if "commit" in evidence:
            self.assertRegex(str(evidence["commit"]), COMMIT_RE)
        self.assertEqual("line_start" in evidence, "line_end" in evidence)
        if "line_start" in evidence:
            self.assertLessEqual(evidence["line_start"], evidence["line_end"])

    def test_schema_valid_candidate_is_uncertain_with_readable_sidecars(self) -> None:
        candidate = self.candidate()
        original = deepcopy(candidate)
        self.assertTrue(SchemaAdapter().validate(candidate).valid)

        outcome = self.validator().validate(candidate)

        self.assertEqual(outcome.report.verdict, "uncertain")
        for name in ("commit", "entry_point", "critical_operation"):
            with self.subTest(field=name):
                field = outcome.report.fields[name]
                self.assertEqual(field.status, "uncertain")
                self.assertTrue(field.evidence.strip())
                self.assertEqual(len(field.evidence_refs), 1)
        self.assertIn("Git source proves", outcome.report.fields["entry_point"].evidence)
        self.assertIn("Git source proves", outcome.report.fields["critical_operation"].evidence)

        by_id = {item.evidence_id: item.to_dict() for item in outcome.evidence}
        self.assertEqual(len(by_id), len(outcome.evidence))
        referenced = {
            evidence_id
            for field in outcome.report.fields.values()
            for evidence_id in field.evidence_refs
        }
        self.assertEqual(referenced, set(by_id))
        for item in by_id.values():
            self.assert_evidence_contract(item)

        entry_item = by_id[outcome.report.fields["entry_point"].evidence_refs[0]]
        self.assertEqual(entry_item["commit"], self.commit)
        self.assertEqual(entry_item["file"], "src/app.py")
        self.assertEqual((entry_item["line_start"], entry_item["line_end"]), (1, 1))
        self.assertEqual(entry_item["snippet"], "def entry(value):")

        # Validation and evidence are sidecars; validating must not inject them
        # into the official Entry object or any nested location.
        self.assertEqual(candidate, original)
        self.assertEqual(set(candidate), set(ENTRY_FIELDS))
        self.assertFalse(set(candidate) & SIDECAR_NAMES)
        self.assertFalse(set(candidate["entry_point"]) & SIDECAR_NAMES)
        self.assertFalse(set(candidate["critical_operation"]) & SIDECAR_NAMES)

    def test_missing_file_and_wrong_code_are_deterministically_incorrect(self) -> None:
        mutations = (
            ("entry_point", "file", "src/missing.py", "does not name a file"),
            (
                "critical_operation",
                "code",
                "return harmless(value)",
                "was not found",
            ),
        )
        for field_name, member, value, evidence_fragment in mutations:
            with self.subTest(field=field_name, member=member):
                candidate = self.candidate()
                candidate[field_name][member] = value
                self.assertTrue(SchemaAdapter().validate(candidate).valid)

                outcome = self.validator().validate(candidate)

                self.assertEqual(outcome.report.verdict, "incorrect")
                self.assertEqual(outcome.report.fields[field_name].status, "incorrect")
                self.assertIn(
                    evidence_fragment,
                    outcome.report.fields[field_name].evidence,
                )

    def test_empty_trace_is_legal_but_semantically_uncertain(self) -> None:
        outcome = self.validator().validate(self.candidate())

        trace = outcome.report.fields["trace"]
        self.assertEqual(trace.status, "uncertain")
        self.assertIn("合法", trace.evidence)
        self.assertIn("空数组", trace.evidence)
        self.assertTrue(
            any("trace" in item.casefold() for item in outcome.report.missing_information)
        )

    def test_unreadable_trace_node_is_not_claimed_as_factually_verified(self) -> None:
        candidate = self.candidate()
        candidate["trace"] = [
            {"file": "src/non_utf8.py", "line": 1, "code": "placeholder"}
        ]

        outcome = self.validator().validate(candidate)

        trace = outcome.report.fields["trace"]
        self.assertEqual(trace.status, "uncertain")
        self.assertIn("无法核实", trace.evidence)
        self.assertNotIn("均通过本地 file/line/code", trace.evidence)

    def test_bad_json_blank_and_non_utf8_lines_are_isolated(self) -> None:
        candidate_line = json.dumps(self.candidate(), ensure_ascii=False).encode("utf-8")
        payload = b"\n".join(
            (
                candidate_line,
                b'{"broken":',
                b"",
                b"\xff",
                candidate_line,
            )
        ) + b"\n"

        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "candidates.jsonl"
            input_path.write_bytes(payload)
            records = list(iter_jsonl(input_path))

        self.assertEqual([record.line_number for record in records], [1, 2, 3, 4, 5])
        self.assertIsNone(records[0].error)
        self.assertIn("invalid JSON", records[1].error or "")
        self.assertIn("blank JSONL line", records[2].error or "")
        self.assertIn("not valid UTF-8", records[3].error or "")
        self.assertIsNone(records[4].error)

        outcomes, counts = run_batch(
            records,
            RepositoryResolver(repo_root=self.repo_path),
        )

        self.assertEqual(
            [outcome.report.verdict for outcome in outcomes],
            ["uncertain", "incorrect", "incorrect", "incorrect", "uncertain"],
        )
        self.assertEqual(outcomes[-1].report.report_id, self.candidate()["report_id"])
        self.assertEqual(counts, {"uncertain": 2, "incorrect": 3})
        for line_number, outcome in zip((2, 3, 4), outcomes[1:4]):
            self.assertIn(f"第 {line_number} 行", outcome.report.fields["schema"].evidence)
            self.assertEqual(outcome.evidence, ())

    def test_oversized_jsonl_line_is_bounded_and_next_line_survives(self) -> None:
        payload = b'{"pad":"' + (b"x" * 150_000) + b'"}\n{}\n'
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "candidates.jsonl"
            input_path.write_bytes(payload)

            records = list(iter_jsonl(input_path, max_input_line_bytes=64))

        self.assertEqual([record.line_number for record in records], [1, 2])
        self.assertIn("configured byte limit of 64", records[0].error or "")
        self.assertIsNone(records[0].value)
        self.assertEqual(records[1].value, {})
        self.assertIsNone(records[1].error)

    def test_record_limit_emits_correlated_error_then_stops(self) -> None:
        candidates = []
        for index in range(1, 5):
            candidate = self.candidate()
            candidate["entry_id"] = f"entry-{index:05d}"
            candidates.append(candidate)
        consumed: list[int] = []

        def records():
            for line_number, candidate in zip((4, 9, 15, 22), candidates):
                consumed.append(line_number)
                yield InputRecord(line_number, candidate)

        resolver = mock.Mock(spec=RepositoryResolver)
        resolver.resolve.return_value = (None, "test has no repository")
        outcomes, counts = run_batch(records(), resolver, max_records=2)

        self.assertEqual(consumed, [4, 9, 15])
        self.assertEqual(resolver.resolve.call_count, 2)
        self.assertEqual(len(outcomes), 3)
        limit_report = outcomes[-1].report
        self.assertEqual(limit_report.verdict, "incorrect")
        self.assertEqual(limit_report.input_line, 15)
        self.assertEqual(limit_report.entry_id, "entry-00003")
        self.assertEqual(limit_report.report_id, candidates[2]["report_id"])
        self.assertIn("configured 2 records", limit_report.fields["schema"].evidence)
        self.assertIn("停止", limit_report.summary)
        self.assertEqual(counts, {"uncertain": 2, "incorrect": 1})

    def test_oversized_trace_is_rejected_before_repository_resolution(self) -> None:
        candidate = self.candidate()
        candidate["trace"] = [
            deepcopy(candidate["entry_point"]),
            deepcopy(candidate["entry_point"]),
            deepcopy(candidate["entry_point"]),
        ]
        resolver = mock.Mock(spec=RepositoryResolver)

        outcomes, counts = run_batch(
            [InputRecord(7, candidate)],
            resolver,
            max_trace_nodes=2,
        )

        resolver.resolve.assert_not_called()
        self.assertEqual(counts, {"incorrect": 1})
        report = outcomes[0].report
        self.assertEqual(report.input_line, 7)
        self.assertEqual(report.entry_id, candidate["entry_id"])
        self.assertEqual(report.fields["trace"].status, "incorrect")
        self.assertIn("3 nodes", report.fields["trace"].evidence)
        self.assertIn("maximum is 2", report.fields["trace"].evidence)

    def test_nonstandard_constants_and_duplicate_keys_are_isolated(self) -> None:
        payload = (
            b'{"value": NaN}\n'
            b'{"value": 1, "value": 2}\n'
            b'{"\\ud800": 1}\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "candidates.jsonl"
            input_path.write_bytes(payload)
            records = list(iter_jsonl(input_path))

        self.assertEqual(len(records), 3)
        self.assertIn("non-standard JSON numeric constant", records[0].error or "")
        self.assertIn("duplicate JSON object key", records[1].error or "")
        self.assertIn("unpaired UTF-16 surrogate", records[2].error or "")

        outcomes, _ = run_batch(records, RepositoryResolver())
        serialized = "".join(
            json.dumps(outcome.report.to_dict(), ensure_ascii=False) + "\n"
            for outcome in outcomes
        )
        serialized.encode("utf-8")

    def test_dotted_extra_key_does_not_poison_commit_field_attribution(self) -> None:
        candidate = self.candidate()
        candidate["commit.injected"] = "not a real field"

        outcome = self.validator().validate(candidate)

        self.assertEqual(outcome.report.fields["schema"].status, "incorrect")
        self.assertEqual(outcome.report.fields["commit"].status, "uncertain")
        self.assertIn(
            "exists and is a commit object",
            outcome.report.fields["commit"].evidence,
        )

    def test_repository_resolver_supports_root_and_exact_url_map(self) -> None:
        candidate = self.candidate()
        root_resolver = RepositoryResolver(repo_root=self.repo_path)
        map_resolver = RepositoryResolver(repo_map={self.repo_url: self.repo_path})

        for name, resolver in (("root", root_resolver), ("map", map_resolver)):
            with self.subTest(resolver=name):
                outcomes, _ = run_batch([InputRecord(1, candidate)], resolver)
                self.assertEqual(outcomes[0].report.verdict, "uncertain")
                self.assertIn(
                    "Git source proves",
                    outcomes[0].report.fields["entry_point"].evidence,
                )

        unmapped = deepcopy(candidate)
        unmapped["repo_url"] = "https://github.com/example/not-in-map"
        repository, note = map_resolver.resolve(unmapped)
        self.assertIsNone(repository)
        self.assertIn("repo map", note or "")

    def test_reports_retain_entry_and_physical_line_correlation(self) -> None:
        first = self.candidate()
        second = self.candidate()
        second["entry_id"] = "entry-00002"
        outcomes, _ = run_batch(
            [InputRecord(4, first), InputRecord(9, second)],
            RepositoryResolver(repo_root=self.repo_path),
        )

        self.assertEqual(
            [(item.report.entry_id, item.report.input_line) for item in outcomes],
            [("entry-00001", 4), ("entry-00002", 9)],
        )
        self.assertEqual(outcomes[0].report.report_id, outcomes[1].report.report_id)
        self.assertTrue(
            all(item.entry_id == outcome.report.entry_id for outcome in outcomes for item in outcome.evidence)
        )

    def test_evidence_ids_are_unique_when_fields_share_the_same_fact(self) -> None:
        candidate = self.candidate()
        candidate["critical_operation"] = deepcopy(candidate["entry_point"])

        first = self.validator().validate(candidate)
        second = self.validator().validate(candidate)
        first_ids = [item.evidence_id for item in first.evidence]
        second_ids = [item.evidence_id for item in second.evidence]

        self.assertEqual(len(first_ids), len(set(first_ids)))
        self.assertEqual(first_ids, second_ids)
        for evidence_id in first_ids:
            self.assertRegex(evidence_id, EVIDENCE_ID_RE)

    def test_invalid_candidate_commit_never_leaks_into_evidence_commit(self) -> None:
        candidate = self.candidate()
        candidate["commit"] = "NOT-A-COMMIT"
        candidate["trace"] = [deepcopy(candidate["entry_point"])]

        outcome = self.validator().validate(candidate)

        self.assertEqual(outcome.report.verdict, "incorrect")
        self.assertEqual(outcome.report.fields["commit"].status, "incorrect")
        for item in outcome.evidence:
            payload = item.to_dict()
            self.assert_evidence_contract(payload)
            self.assertNotEqual(payload.get("commit"), candidate["commit"])

    def test_module_cli_writes_validation_evidence_and_manifest_jsonl(self) -> None:
        candidate = self.candidate()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            input_path = work / "candidates.jsonl"
            repo_map_path = work / "repo-map.json"
            validation_path = work / "outputs" / "validation.jsonl"
            evidence_path = work / "artifacts" / "evidence.jsonl"
            manifest_path = work / "artifacts" / "run_manifest.jsonl"
            input_path.write_text(
                json.dumps(candidate, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            original_input = input_path.read_bytes()
            repo_map_path.write_text(
                json.dumps({self.repo_url: str(self.repo_path)}),
                encoding="utf-8",
            )

            environment = os.environ.copy()
            environment["PYTHONIOENCODING"] = "utf-8"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "vulngym_agent",
                    str(input_path),
                    "--repo-map",
                    str(repo_map_path),
                    "--validation-output",
                    str(validation_path),
                    "--evidence-output",
                    str(evidence_path),
                    "--manifest-output",
                    str(manifest_path),
                    "--max-input-line-bytes",
                    "65536",
                    "--max-records",
                    "7",
                    "--max-package-files",
                    "11",
                    "--max-trace-nodes",
                    "9",
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("processed=1", completed.stdout)
            self.assertEqual(input_path.read_bytes(), original_input)
            validations = self._load_jsonl(validation_path)
            evidence = self._load_jsonl(evidence_path)
            manifests = self._load_jsonl(manifest_path)

        self.assertEqual(len(validations), 1)
        self.assertEqual(validations[0]["verdict"], "uncertain")
        validation_schema = json.loads(
            (ROOT / "schemas" / "validation.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(set(validations[0]), set(validation_schema["required"]))
        allowed_fields = set(
            validation_schema["properties"]["fields"]["properties"]
        )
        self.assertLessEqual(set(validations[0]["fields"]), allowed_fields)
        for field in validations[0]["fields"].values():
            self.assertTrue(field["evidence"].strip())

        self.assertGreater(len(evidence), 0)
        evidence_ids = [item["evidence_id"] for item in evidence]
        self.assertEqual(len(evidence_ids), len(set(evidence_ids)))
        for item in evidence:
            self.assert_evidence_contract(item)
        refs = {
            evidence_id
            for field in validations[0]["fields"].values()
            for evidence_id in field.get("evidence_refs", [])
        }
        self.assertEqual(refs, set(evidence_ids))

        self.assertEqual(len(manifests), 1)
        manifest = manifests[0]
        self.assertEqual(manifest["input"], "candidates.jsonl")
        self.assertNotIn(str(input_path.parent), manifest["input"])
        self.assertEqual(manifest["record_count"], 1)
        self.assertEqual(manifest["evidence_count"], len(evidence))
        self.assertEqual(
            manifest["verdict_counts"],
            {"correct": 0, "incorrect": 0, "uncertain": 1},
        )
        self.assertTrue(manifest["policy"]["offline_evidence"])
        self.assertTrue(manifest["policy"]["repository_read_only"])
        self.assertFalse(manifest["policy"]["checkout"])
        self.assertEqual(manifest["max_input_line_bytes"], 65536)
        self.assertEqual(manifest["max_records"], 7)
        self.assertEqual(manifest["max_package_files"], 11)
        self.assertEqual(manifest["max_trace_nodes"], 9)

        persisted_entry = json.loads(original_input.decode("utf-8"))
        self.assertEqual(persisted_entry, candidate)
        self.assertEqual(set(persisted_entry), set(ENTRY_FIELDS))
        self.assertFalse(set(persisted_entry) & SIDECAR_NAMES)

    def test_resource_limit_parameters_reject_zero_negative_bool_and_hard_overflow(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "candidates.jsonl"
            input_path.write_text("{}\n", encoding="utf-8")
            invalid_cli_values = (
                ("--max-input-line-bytes", "0"),
                ("--max-input-line-bytes", str(HARD_MAX_INPUT_LINE_BYTES + 1)),
                ("--max-records", "-1"),
                ("--max-records", str(HARD_MAX_RECORDS + 1)),
                ("--max-package-files", "0"),
                ("--max-package-files", str(HARD_MAX_PACKAGE_FILES + 1)),
                ("--max-trace-nodes", "0"),
                ("--max-trace-nodes", str(HARD_MAX_TRACE_NODES + 1)),
            )
            for option, value in invalid_cli_values:
                with self.subTest(option=option, value=value):
                    errors = io.StringIO()
                    with redirect_stderr(errors):
                        result = main([str(input_path), option, value])
                    self.assertEqual(result, 2)
                    self.assertIn(option, errors.getvalue())

            with self.assertRaises(ValueError):
                list(iter_jsonl(input_path, max_input_line_bytes=True))
            with self.assertRaises(ValueError):
                run_batch([], RepositoryResolver(), max_records=False)
            with self.assertRaises(ValueError):
                run_batch([], RepositoryResolver(), max_package_files=True)
            with self.assertRaises(ValueError):
                run_batch([], RepositoryResolver(), max_trace_nodes=True)

        self.assertEqual(DEFAULT_MAX_INPUT_LINE_BYTES, 1024 * 1024)
        self.assertEqual(DEFAULT_MAX_RECORDS, 10_000)
        self.assertEqual(DEFAULT_MAX_PACKAGE_FILES, 64)
        self.assertEqual(HARD_MAX_PACKAGE_FILES, 256)
        self.assertEqual(DEFAULT_MAX_TRACE_NODES, 64)

    def test_cli_protects_repo_map_and_read_only_repository_paths(self) -> None:
        candidate = self.candidate()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            input_path = work / "candidates.jsonl"
            repo_map_path = work / "repo-map.json"
            evidence_path = work / "evidence.jsonl"
            manifest_path = work / "manifest.jsonl"
            input_path.write_text(json.dumps(candidate) + "\n", encoding="utf-8")
            repo_map_path.write_text(
                json.dumps({self.repo_url: str(self.repo_path)}),
                encoding="utf-8",
            )
            original_map = repo_map_path.read_bytes()

            with redirect_stderr(io.StringIO()):
                overwrite_map = main(
                    [
                        str(input_path),
                        "--repo-map",
                        str(repo_map_path),
                        "--validation-output",
                        str(repo_map_path),
                        "--evidence-output",
                        str(evidence_path),
                        "--manifest-output",
                        str(manifest_path),
                    ]
                )
            self.assertEqual(overwrite_map, 2)
            self.assertEqual(repo_map_path.read_bytes(), original_map)

            repository_output = self.repo_path / "must-not-write.jsonl"
            with redirect_stderr(io.StringIO()):
                overwrite_repository = main(
                    [
                        str(input_path),
                        "--repo-root",
                        str(self.repo_path),
                        "--validation-output",
                        str(repository_output),
                        "--evidence-output",
                        str(evidence_path),
                        "--manifest-output",
                        str(manifest_path),
                    ]
                )
            self.assertEqual(overwrite_repository, 2)
            self.assertFalse(repository_output.exists())

            with redirect_stderr(io.StringIO()):
                overwrite_directory = main(
                    [
                        str(input_path),
                        "--validation-output",
                        str(work),
                        "--evidence-output",
                        str(evidence_path),
                        "--manifest-output",
                        str(manifest_path),
                    ]
                )
            self.assertEqual(overwrite_directory, 2)
            self.assertTrue(work.is_dir())

    def test_related_outputs_roll_back_as_a_set_when_replace_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = {
                root / "validation.jsonl": "new validation\n",
                root / "evidence.jsonl": "new evidence\n",
                root / "manifest.jsonl": "new manifest\n",
            }
            for index, path in enumerate(outputs, 1):
                path.write_text(f"old {index}\n", encoding="utf-8")
            original_replace = os.replace
            call_count = 0

            def fail_last_commit(source: object, destination: object) -> None:
                nonlocal call_count
                call_count += 1
                if call_count == 6:
                    raise OSError("simulated final replace failure")
                original_replace(source, destination)

            with mock.patch("vulngym_agent.cli.os.replace", side_effect=fail_last_commit):
                with self.assertRaises(OSError):
                    _atomic_write_many(outputs)

            self.assertEqual(
                [path.read_text(encoding="utf-8") for path in outputs],
                ["old 1\n", "old 2\n", "old 3\n"],
            )

    @staticmethod
    def _load_jsonl(path: Path) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
        ]


if __name__ == "__main__":
    unittest.main()
