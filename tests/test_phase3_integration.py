from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from vulngym_agent.adapters import SchemaAdapter
from vulngym_agent.cli import InputRecord, RepositoryResolver, main, run_batch


ROOT = Path(__file__).resolve().parents[1]
REPORT_ID = "GHSA-P3AA-1234-TEST"
CVE_ID = "CVE-2026-31415"
SOURCE_LINK = f"https://github.com/advisories/{REPORT_ID}"
EVIDENCE_ID_RE = re.compile(r"EV-[A-Z0-9][A-Z0-9._-]*\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")

VULNERABLE_SOURCE = """from flask import Flask, request

app = Flask(__name__)

@app.post("/run")
def run_route():
    payload = request.get_json()["payload"]
    return eval(payload)
"""

FIXED_SOURCE = """from flask import Flask, request

app = Flask(__name__)

@app.post("/run")
def run_route():
    payload = request.get_json()["payload"]
    if not isinstance(payload, str):
        return {"error": "invalid payload"}, 400
    return safe_eval(payload)
"""


class Phase3IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls._temporary_directory.name)
        cls.repo_path = cls.root / "repository"
        cls.package_root = cls.root / "packages"
        cls.source_path = cls.repo_path / "src" / "app.py"
        cls.source_path.parent.mkdir(parents=True)
        (cls.package_root / "advisories").mkdir(parents=True)
        (cls.package_root / "patches").mkdir(parents=True)

        cls._git("init", "-q", "-b", "main")
        cls._git("config", "user.name", "VulnGym Phase 3 Test")
        cls._git("config", "user.email", "phase3@example.invalid")

        cls.source_path.write_text(VULNERABLE_SOURCE, encoding="utf-8")
        cls._commit_all("vulnerable route and sink")
        cls.vulnerable_commit = cls._head()

        cls.source_path.write_text(FIXED_SOURCE, encoding="utf-8")
        cls._commit_all("add guard and replace sink")
        cls.fix_commit = cls._head()
        cls.repo_url = "https://github.com/example/vulngym-phase3-fixture"

        advisory = {
            "ghsa_id": REPORT_ID,
            "cve_id": CVE_ID,
            "source_link": SOURCE_LINK,
            "fix_commit": cls.fix_commit,
            "summary": "Untrusted route input reaches dynamic evaluation.",
        }
        (cls.package_root / "advisories" / "fixture.json").write_text(
            json.dumps(advisory), encoding="utf-8"
        )
        patch_text = cls._git(
            "diff", cls.vulnerable_commit, cls.fix_commit, "--", "src/app.py"
        ).stdout
        (cls.package_root / "patches" / "fix.patch").write_text(
            patch_text, encoding="utf-8"
        )
        (cls.package_root / "patches" / "malformed.patch").write_text(
            "diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -8,1 +8,1 @@\n"
            "-    return eval(payload)\n",
            encoding="utf-8",
        )

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

    @classmethod
    def _commit_all(cls, message: str) -> None:
        cls._git("add", "-A")
        cls._git("commit", "-q", "-m", message)

    @classmethod
    def _head(cls) -> str:
        return cls._git("rev-parse", "HEAD").stdout.strip()

    def candidate(self, *, entry_id: str = "entry-00301") -> dict[str, object]:
        return {
            "commit": self.vulnerable_commit,
            "critical_operation": {
                "code": "return eval(payload)",
                "file": "src/app.py",
                "line": 8,
            },
            "entry_id": entry_id,
            "entry_point": {
                "code": '@app.post("/run")',
                "file": "src/app.py",
                "line": 5,
            },
            "origin": "GitHub Advisory Database (reviewed)",
            "project": "vulngym-phase3-fixture",
            "repo_url": self.repo_url,
            "report_id": REPORT_ID,
            "source_link": SOURCE_LINK,
            "trace": [],
            "verify": 0,
            "vuln_category_l1": "Injection",
            "vuln_category_l2": "Code Injection",
            "vuln_ids": [CVE_ID, REPORT_ID],
            "vuln_title": "Route input reaches dynamic evaluation",
        }

    @staticmethod
    def package(patch: str = "patches/fix.patch") -> dict[str, object]:
        return {
            "advisory": "advisories/fixture.json",
            "patches": [patch],
        }

    def validate_wrapper(self, candidate: dict[str, object]):
        outcomes, counts = run_batch(
            [InputRecord(1, {"entry": candidate, "package": self.package()})],
            RepositoryResolver(repo_root=self.repo_path),
            package_root=self.package_root,
        )
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(counts, {"uncertain": 1})
        return outcomes[0]

    def assert_strict_sidecar_contract(self, outcome) -> None:
        validation_schema = json.loads(
            (ROOT / "schemas" / "validation.schema.json").read_text(
                encoding="utf-8"
            )
        )
        evidence_schema = json.loads(
            (ROOT / "schemas" / "evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        report = outcome.report.to_dict()
        self.assertEqual(set(report), set(validation_schema["required"]))
        self.assertIn(report["verdict"], ("correct", "incorrect", "uncertain"))
        self.assertIsInstance(report["summary"], str)
        self.assertTrue(report["summary"].strip())
        self.assertIsInstance(report["missing_information"], list)
        self.assertEqual(
            len(report["missing_information"]),
            len(set(report["missing_information"])),
        )

        allowed_fields = set(
            validation_schema["properties"]["fields"]["properties"]
        )
        field_schema = validation_schema["$defs"]["fieldValidation"]
        allowed_field_members = set(field_schema["properties"])
        required_field_members = set(field_schema["required"])
        refs: list[str] = []
        for name, field in report["fields"].items():
            with self.subTest(sidecar_field=name):
                self.assertIn(name, allowed_fields)
                self.assertLessEqual(set(field), allowed_field_members)
                self.assertTrue(required_field_members.issubset(field))
                self.assertIn(field["status"], ("correct", "incorrect", "uncertain"))
                self.assertIsInstance(field["confidence"], (int, float))
                self.assertNotIsInstance(field["confidence"], bool)
                self.assertGreaterEqual(field["confidence"], 0)
                self.assertLessEqual(field["confidence"], 1)
                self.assertIsInstance(field["evidence"], str)
                self.assertTrue(field["evidence"].strip())
                field_refs = field.get("evidence_refs", [])
                self.assertEqual(len(field_refs), len(set(field_refs)))
                for evidence_id in field_refs:
                    self.assertRegex(evidence_id, EVIDENCE_ID_RE)
                refs.extend(field_refs)

        allowed_evidence_members = set(evidence_schema["properties"])
        required_evidence_members = set(evidence_schema["required"])
        evidence_payloads = [item.to_dict() for item in outcome.evidence]
        evidence_ids = [item["evidence_id"] for item in evidence_payloads]
        self.assertEqual(len(evidence_ids), len(set(evidence_ids)))
        self.assertEqual(set(refs), set(evidence_ids))
        for item in evidence_payloads:
            with self.subTest(evidence_id=item["evidence_id"]):
                self.assertLessEqual(set(item), allowed_evidence_members)
                self.assertTrue(required_evidence_members.issubset(item))
                self.assertRegex(item["evidence_id"], EVIDENCE_ID_RE)
                self.assertEqual(item["report_id"], REPORT_ID)
                self.assertIn(
                    item["source_type"],
                    evidence_schema["properties"]["source_type"]["enum"],
                )
                self.assertIsInstance(item["snippet"], str)
                self.assertTrue(item["snippet"].strip())
                if "commit" in item:
                    self.assertRegex(item["commit"], COMMIT_RE)
                self.assertEqual("line_start" in item, "line_end" in item)
                if "line_start" in item:
                    self.assertLessEqual(item["line_start"], item["line_end"])

    def test_patch_resolver_and_t1_keep_critical_semantics_uncertain(self) -> None:
        candidate = self.candidate()
        original = deepcopy(candidate)

        outcome = self.validate_wrapper(candidate)

        critical = outcome.report.fields["critical_operation"]
        self.assertEqual(outcome.report.verdict, "uncertain")
        self.assertEqual(critical.status, "uncertain")
        self.assertIsNone(critical.suggested_fix)
        self.assertIn("临时候选", critical.evidence)
        self.assertIn("控制流缺口线索", critical.evidence)
        self.assertIn("绝不转换成漏洞版本位置", critical.evidence)
        self.assertNotIn("safe_eval(payload)", str(critical.suggested_fix))
        self.assertEqual(candidate, original)

        evidence_by_id = {item.evidence_id: item for item in outcome.evidence}
        critical_evidence = [evidence_by_id[item] for item in critical.evidence_refs]
        self.assertTrue(
            any(item.source_type == "patch" for item in critical_evidence)
        )
        self.assert_strict_sidecar_contract(outcome)

    def test_explicit_route_and_critical_clue_remain_entry_hints(self) -> None:
        outcome = self.validate_wrapper(self.candidate())

        entry = outcome.report.fields["entry_point"]
        self.assertEqual(entry.status, "uncertain")
        self.assertIn("Entry 反向搜索", entry.evidence)
        self.assertIn("explicit entry/export construct", entry.evidence)
        self.assertIn("Runtime reachability", entry.evidence)
        self.assertTrue(
            any("运行时路由注册" in item for item in outcome.report.missing_information)
        )

    def test_malformed_patch_is_isolated_and_next_raw_entry_continues(self) -> None:
        wrapped = {
            "entry": self.candidate(entry_id="entry-00302"),
            "package": self.package("patches/malformed.patch"),
        }
        raw = self.candidate(entry_id="entry-00303")

        outcomes, counts = run_batch(
            [InputRecord(17, wrapped), InputRecord(18, raw)],
            RepositoryResolver(repo_root=self.repo_path),
            package_root=self.package_root,
        )

        self.assertEqual(len(outcomes), 2)
        self.assertEqual(counts, {"uncertain": 2})
        self.assertEqual(
            [(item.report.entry_id, item.report.input_line) for item in outcomes],
            [("entry-00302", 17), ("entry-00303", 18)],
        )
        self.assertEqual(outcomes[0].report.fields["schema"].status, "correct")
        self.assertEqual(
            outcomes[0].report.fields["critical_operation"].status, "uncertain"
        )
        self.assertIn(
            "不可解析资料",
            outcomes[0].report.fields["critical_operation"].evidence,
        )
        self.assertEqual(outcomes[1].report.report_id, REPORT_ID)

    def test_raw_entry_without_package_remains_backward_compatible(self) -> None:
        candidate = self.candidate(entry_id="entry-00304")
        self.assertTrue(SchemaAdapter().validate(candidate).valid)

        outcomes, counts = run_batch(
            [InputRecord(9, candidate)],
            RepositoryResolver(repo_root=self.repo_path),
            package_root=self.package_root,
        )

        self.assertEqual(len(outcomes), 1)
        self.assertEqual(counts, {"uncertain": 1})
        outcome = outcomes[0]
        self.assertEqual(outcome.report.entry_id, "entry-00304")
        self.assertEqual(outcome.report.input_line, 9)
        self.assertEqual(outcome.report.fields["schema"].status, "correct")
        self.assertEqual(outcome.report.fields["entry_point"].status, "uncertain")
        self.assertEqual(
            outcome.report.fields["critical_operation"].status, "uncertain"
        )
        self.assertFalse(any(item.source_type == "patch" for item in outcome.evidence))

    def test_cli_outputs_validate_against_draft_2020_12_schemas(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError:  # pragma: no cover - optional developer dependency
            self.skipTest("jsonschema is not installed")

        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory)
            input_path = output_root / "candidates.jsonl"
            validation_path = output_root / "validation.jsonl"
            evidence_path = output_root / "evidence.jsonl"
            manifest_path = output_root / "manifest.jsonl"
            input_path.write_text(
                json.dumps(
                    {
                        "entry": self.candidate(entry_id="entry-00305"),
                        "package": self.package(),
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            exit_code = main(
                [
                    str(input_path),
                    "--repo-root",
                    str(self.repo_path),
                    "--package-root",
                    str(self.package_root),
                    "--validation-output",
                    str(validation_path),
                    "--evidence-output",
                    str(evidence_path),
                    "--manifest-output",
                    str(manifest_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            validation_schema = json.loads(
                (ROOT / "schemas" / "validation.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            evidence_schema = json.loads(
                (ROOT / "schemas" / "evidence.schema.json").read_text(
                    encoding="utf-8"
                )
            )
            validation_validator = Draft202012Validator(validation_schema)
            evidence_validator = Draft202012Validator(evidence_schema)
            validations = [
                json.loads(line)
                for line in validation_path.read_text(encoding="utf-8").splitlines()
            ]
            evidence = [
                json.loads(line)
                for line in evidence_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(validations), 1)
            self.assertTrue(evidence)
            for value in validations:
                validation_validator.validate(value)
            for value in evidence:
                evidence_validator.validate(value)


if __name__ == "__main__":
    unittest.main()
