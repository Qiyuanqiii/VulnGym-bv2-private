from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from vulngym_agent.agents import T1DeterministicValidator
from vulngym_agent.cli import InputRecord, RepositoryResolver, run_batch
from vulngym_agent.evidence import (
    LoadedEvidenceFile,
    extract_advisory_facts,
    load_evidence_package,
)
from vulngym_agent.tools.git import GitRepository
from vulngym_agent.validators import validate_advisory_fields


REPORT_ID = "GHSA-ABCD-1234-EFGH"
OTHER_REPORT_ID = "GHSA-WXYZ-9876-IJKL"
CVE_ID = "CVE-2026-12345"
SOURCE_LINK = f"https://github.com/advisories/{REPORT_ID}"


class Phase2AdvisoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls._temporary_directory.name)
        cls.repo_path = cls.root / "repository"
        cls.package_root = cls.root / "packages"
        cls.repo_path.mkdir()
        (cls.repo_path / "src").mkdir()
        cls.package_root.mkdir()

        cls._git("init", "-q", "-b", "main")
        cls._git("config", "user.name", "VulnGym Phase 2 Test")
        cls._git("config", "user.email", "phase2@example.invalid")
        (cls.repo_path / "src" / "app.py").write_text(
            "def entry(value):\n"
            "    return sink(value)\n"
            "\n"
            "def sink(value):\n"
            "    return dangerous(value)\n",
            encoding="utf-8",
        )
        cls._commit_all("vulnerable snapshot")
        cls.vulnerable_commit = cls._head()

        (cls.repo_path / "src" / "app.py").write_text(
            "def entry(value):\n"
            "    return sink(value)\n"
            "\n"
            "def sink(value):\n"
            "    return sanitize(value)\n",
            encoding="utf-8",
        )
        cls._commit_all("fix unsafe sink")
        cls.fix_commit = cls._head()
        cls.repo_url = "https://github.com/example/vulngym-phase2-fixture"

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

    @staticmethod
    def _document(text: str) -> LoadedEvidenceFile:
        payload = text.encode("utf-8")
        return LoadedEvidenceFile(
            kind="advisory",
            relative_path="advisory.json",
            text=text,
            byte_size=len(payload),
            sha256=sha256(payload).hexdigest(),
        )

    def _candidate(
        self,
        commit: str | None = None,
        *,
        entry_id: str = "entry-00001",
    ) -> dict[str, object]:
        selected_commit = commit or self.vulnerable_commit
        critical_code = (
            "return sanitize(value)"
            if selected_commit == self.fix_commit
            else "return dangerous(value)"
        )
        return {
            "commit": selected_commit,
            "critical_operation": {
                "code": critical_code,
                "file": "src/app.py",
                "line": 5,
            },
            "entry_id": entry_id,
            "entry_point": {
                "code": "def entry(value):",
                "file": "src/app.py",
                "line": 1,
            },
            "origin": "GitHub Advisory Database (reviewed)",
            "project": "vulngym-phase2-fixture",
            "repo_url": self.repo_url,
            "report_id": REPORT_ID,
            "source_link": SOURCE_LINK,
            "trace": [],
            "verify": 0,
            "vuln_category_l1": "Injection",
            "vuln_category_l2": "Command Injection",
            "vuln_ids": [CVE_ID, REPORT_ID],
            "vuln_title": "Fixture command injection",
        }

    def _advisory_text(
        self,
        *,
        fix_commit: str | None = None,
        extra_ghsa: str | None = None,
    ) -> str:
        value: dict[str, object] = {
            "ghsa_id": REPORT_ID,
            "cve_id": CVE_ID,
            "source_link": SOURCE_LINK,
            "summary": "Unsafe input reaches a command sink.",
        }
        if extra_ghsa is not None:
            value["related_advisory"] = extra_ghsa
        if fix_commit is not None:
            value["fix_commit"] = fix_commit
        return json.dumps(value, ensure_ascii=False)

    def _write_advisory(self, relative_path: str, text: str) -> None:
        path = self.package_root.joinpath(*relative_path.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _load_package(
        self,
        relative_path: str,
        *,
        input_line: int = 1,
        entry_id: str = "entry-00001",
    ):
        return load_evidence_package(
            self.package_root,
            {"advisory": relative_path},
            input_line=input_line,
            entry_id=entry_id,
            report_id=REPORT_ID,
        )

    def test_extracts_unique_ghsa_cve_source_and_explicit_fix_commit(self) -> None:
        facts = extract_advisory_facts(
            self._document(self._advisory_text(fix_commit=self.fix_commit))
        )

        self.assertEqual(facts.ghsa_ids, (REPORT_ID,))
        self.assertEqual(facts.cve_ids, (CVE_ID,))
        self.assertEqual(facts.vuln_ids, (CVE_ID, REPORT_ID))
        self.assertEqual(facts.fix_commits, (self.fix_commit,))
        self.assertEqual(facts.source_link, SOURCE_LINK)
        self.assertIn(REPORT_ID, facts.snippet)

    def test_bare_sha_is_not_inferred_to_be_a_fix_commit(self) -> None:
        document = self._document(
            f"Advisory {REPORT_ID} ({CVE_ID}).\n"
            f"Observed commit: {self.fix_commit}\n"
            f"Vulnerable commit {self.vulnerable_commit}\n"
        )

        facts = extract_advisory_facts(document)

        self.assertEqual(facts.fix_commits, ())
        self.assertEqual(facts.ghsa_ids, (REPORT_ID,))
        self.assertEqual(facts.cve_ids, (CVE_ID,))

    def test_explicit_fix_url_extracts_one_canonical_commit(self) -> None:
        upper_fix = self.fix_commit.upper()
        document = self._document(
            json.dumps(
                {
                    "ghsa_id": REPORT_ID,
                    "fix_commit": (
                        "https://github.com/example/project/commit/" + upper_fix
                    ),
                }
            )
        )

        facts = extract_advisory_facts(document)

        self.assertEqual(facts.fix_commits, (self.fix_commit,))

    def test_matching_advisory_fields_are_correct(self) -> None:
        relative_path = "matching/advisory.json"
        self._write_advisory(relative_path, self._advisory_text())
        package_result = self._load_package(relative_path)
        assert package_result.package is not None
        assert package_result.package.advisory is not None
        facts = extract_advisory_facts(package_result.package.advisory)

        validation = validate_advisory_fields(
            self._candidate(), package_result, facts
        )

        self.assertEqual(validation.status, "correct")
        self.assertEqual(
            validation.field_statuses,
            {"report_id": "correct", "source_link": "correct", "vuln_ids": "correct"},
        )
        self.assertEqual(validation.suggested_fixes, {})

    def test_literal_non_cve_identifier_is_preserved(self) -> None:
        external_id = "ZDI-CAN-28762"
        relative_path = "matching/other-id.json"
        advisory = json.loads(self._advisory_text())
        advisory["external_id"] = external_id
        self._write_advisory(relative_path, json.dumps(advisory))
        package_result = self._load_package(relative_path)
        assert package_result.package is not None
        assert package_result.package.advisory is not None
        facts = extract_advisory_facts(package_result.package.advisory)
        candidate = self._candidate()
        candidate["vuln_ids"] = [CVE_ID, REPORT_ID, external_id]

        validation = validate_advisory_fields(candidate, package_result, facts)

        self.assertEqual(facts.other_vuln_ids, (external_id,))
        self.assertEqual(validation.field_statuses["vuln_ids"], "correct")
        self.assertNotIn("vuln_ids", validation.suggested_fixes)

    def test_advisory_mismatch_is_incorrect_with_literal_suggestions(self) -> None:
        relative_path = "mismatch/advisory.json"
        self._write_advisory(relative_path, self._advisory_text())
        package_result = self._load_package(relative_path)
        assert package_result.package is not None
        assert package_result.package.advisory is not None
        facts = extract_advisory_facts(package_result.package.advisory)
        candidate = self._candidate()
        candidate["report_id"] = OTHER_REPORT_ID
        candidate["source_link"] = (
            f"https://github.com/advisories/{OTHER_REPORT_ID}"
        )
        candidate["vuln_ids"] = [OTHER_REPORT_ID]

        validation = validate_advisory_fields(candidate, package_result, facts)

        self.assertEqual(validation.status, "incorrect")
        self.assertEqual(set(validation.field_statuses.values()), {"incorrect"})
        self.assertEqual(validation.suggested_fixes["report_id"], REPORT_ID)
        self.assertEqual(validation.suggested_fixes["source_link"], SOURCE_LINK)
        self.assertEqual(
            validation.suggested_fixes["vuln_ids"], [CVE_ID, REPORT_ID]
        )

    def test_multiple_ghsa_ids_remain_uncertain_instead_of_guessing(self) -> None:
        facts = extract_advisory_facts(
            self._document(self._advisory_text(extra_ghsa=OTHER_REPORT_ID))
        )
        candidate = self._candidate()
        candidate["vuln_ids"] = [CVE_ID, REPORT_ID, OTHER_REPORT_ID]
        self._write_advisory(
            "multiple/advisory.json",
            self._advisory_text(extra_ghsa=OTHER_REPORT_ID),
        )
        package_result = self._load_package("multiple/advisory.json")

        validation = validate_advisory_fields(candidate, package_result, facts)

        self.assertEqual(validation.status, "uncertain")
        self.assertEqual(validation.field_statuses["report_id"], "uncertain")
        self.assertEqual(validation.field_statuses["source_link"], "uncertain")
        self.assertEqual(validation.field_statuses["vuln_ids"], "correct")
        self.assertNotIn("report_id", validation.suggested_fixes)

    def test_missing_advisory_stays_uncertain_and_retains_correlation(self) -> None:
        package_result = self._load_package(
            "missing/advisory.json", input_line=7, entry_id="entry-00007"
        )

        validation = validate_advisory_fields(
            self._candidate(entry_id="entry-00007"), package_result, None
        )

        self.assertEqual(package_result.status, "uncertain")
        self.assertFalse(package_result.usable)
        self.assertEqual(package_result.input_line, 7)
        self.assertEqual(package_result.entry_id, "entry-00007")
        self.assertEqual(package_result.report_id, REPORT_ID)
        self.assertEqual(validation.status, "uncertain")
        self.assertEqual(set(validation.field_statuses.values()), {"uncertain"})
        self.assertEqual(validation.error_code, "advisory_unavailable")
        self.assertTrue(validation.missing_information)

    def test_missing_optional_patch_is_visible_in_report_and_evidence(self) -> None:
        relative_path = "incomplete/advisory.json"
        self._write_advisory(relative_path, self._advisory_text())
        package_result = load_evidence_package(
            self.package_root,
            {
                "advisory": relative_path,
                "patches": ["incomplete/missing.patch"],
            },
            input_line=8,
            entry_id="entry-00008",
            report_id=REPORT_ID,
        )

        outcome = T1DeterministicValidator(
            GitRepository(self.repo_path), package_result=package_result
        ).validate(self._candidate(entry_id="entry-00008"), input_line=8)

        package_field = outcome.report.fields["evidence_package"]
        self.assertEqual(package_result.status, "uncertain")
        self.assertEqual(package_field.status, "uncertain")
        self.assertIn("incomplete/missing.patch", package_field.evidence)
        self.assertIn("file_missing", package_field.evidence)
        self.assertTrue(package_field.evidence_refs)
        self.assertTrue(
            any(
                "Evidence Package" in item
                for item in outcome.report.missing_information
            )
        )
        evidence_ids = {item.evidence_id for item in outcome.evidence}
        referenced_ids = {
            evidence_id
            for field in outcome.report.fields.values()
            for evidence_id in field.evidence_refs
        }
        self.assertEqual(evidence_ids, referenced_ids)

    def test_candidate_equal_to_fix_is_incorrect_and_suggests_unique_parent(self) -> None:
        relative_path = "transition/fix.json"
        self._write_advisory(
            relative_path, self._advisory_text(fix_commit=self.fix_commit)
        )
        package_result = self._load_package(relative_path)

        outcome = T1DeterministicValidator(
            GitRepository(self.repo_path), package_result=package_result
        ).validate(self._candidate(self.fix_commit))

        commit_field = outcome.report.fields["commit"]
        self.assertEqual(commit_field.status, "incorrect")
        self.assertEqual(commit_field.suggested_fix, self.vulnerable_commit)
        self.assertIn("same commit", commit_field.evidence)
        self.assertEqual(outcome.report.verdict, "incorrect")

    def test_candidate_equal_to_one_of_multiple_fixes_is_still_incorrect(self) -> None:
        relative_path = "transition/multiple-fixes.json"
        advisory = json.loads(self._advisory_text())
        advisory["fix_commits"] = [self.fix_commit, self.vulnerable_commit]
        self._write_advisory(relative_path, json.dumps(advisory))
        package_result = self._load_package(relative_path)

        outcome = T1DeterministicValidator(
            GitRepository(self.repo_path), package_result=package_result
        ).validate(self._candidate(self.fix_commit))

        commit_field = outcome.report.fields["commit"]
        self.assertEqual(commit_field.status, "incorrect")
        self.assertEqual(commit_field.suggested_fix, self.vulnerable_commit)

    def test_declared_fix_equality_does_not_require_local_object_presence(self) -> None:
        missing_fix = "0" * 40
        relative_path = "transition/missing-fix.json"
        self._write_advisory(
            relative_path, self._advisory_text(fix_commit=missing_fix)
        )
        package_result = self._load_package(relative_path)

        outcome = T1DeterministicValidator(
            GitRepository(self.repo_path), package_result=package_result
        ).validate(self._candidate(missing_fix))

        commit_field = outcome.report.fields["commit"]
        self.assertEqual(commit_field.status, "incorrect")
        self.assertIsNone(commit_field.suggested_fix)
        self.assertIn("same commit", commit_field.evidence)

    def test_ancestor_of_fix_is_a_fact_but_semantic_role_remains_uncertain(self) -> None:
        relative_path = "transition/ancestor.json"
        self._write_advisory(
            relative_path, self._advisory_text(fix_commit=self.fix_commit)
        )
        package_result = self._load_package(relative_path)

        outcome = T1DeterministicValidator(
            GitRepository(self.repo_path), package_result=package_result
        ).validate(self._candidate(self.vulnerable_commit))

        commit_field = outcome.report.fields["commit"]
        self.assertEqual(commit_field.status, "uncertain")
        self.assertIsNone(commit_field.suggested_fix)
        self.assertIn("direct parent", commit_field.evidence)
        self.assertIn("do not prove", commit_field.evidence)
        self.assertTrue(
            any("semantic" in item.casefold() or "语义" in item for item in outcome.report.missing_information)
        )

    def test_wrapper_batch_isolates_unsafe_package_and_keeps_sidecars_correlated(self) -> None:
        relative_path = "batch/advisory.json"
        self._write_advisory(
            relative_path, self._advisory_text(fix_commit=self.fix_commit)
        )
        first_entry = self._candidate(entry_id="entry-00001")
        unsafe_entry = self._candidate(entry_id="entry-00002")
        last_entry = self._candidate(entry_id="entry-00003")
        original_entries = deepcopy((first_entry, unsafe_entry, last_entry))
        records = [
            InputRecord(
                4,
                {"package": {"advisory": relative_path}, "entry": first_entry},
            ),
            InputRecord(
                9,
                {"package": {"advisory": "../outside.json"}, "entry": unsafe_entry},
            ),
            InputRecord(
                12,
                {"package": {"advisory": relative_path}, "entry": last_entry},
            ),
        ]

        outcomes, counts = run_batch(
            records,
            RepositoryResolver(repo_root=self.repo_path),
            package_root=self.package_root,
        )

        self.assertEqual(len(outcomes), 3)
        self.assertEqual(
            [outcome.report.input_line for outcome in outcomes], [4, 9, 12]
        )
        self.assertEqual(
            [outcome.report.entry_id for outcome in outcomes],
            ["entry-00001", "entry-00002", "entry-00003"],
        )
        self.assertEqual(
            [outcome.report.verdict for outcome in outcomes],
            ["uncertain", "incorrect", "uncertain"],
        )
        self.assertEqual(counts["incorrect"], 1)
        for outcome in outcomes:
            evidence_ids = {item.evidence_id for item in outcome.evidence}
            references = {
                reference
                for field in outcome.report.fields.values()
                for reference in field.evidence_refs
            }
            self.assertEqual(references, evidence_ids)
            self.assertTrue(outcome.evidence)
            self.assertTrue(
                all(
                    item.entry_id == outcome.report.entry_id
                    and item.report_id == outcome.report.report_id
                    for item in outcome.evidence
                )
            )
        self.assertEqual((first_entry, unsafe_entry, last_entry), original_entries)

    def test_raw_entry_remains_a_supported_backward_compatible_input(self) -> None:
        candidate = self._candidate(entry_id="entry-00017")
        original = deepcopy(candidate)

        outcomes, counts = run_batch(
            [InputRecord(17, candidate)],
            RepositoryResolver(repo_root=self.repo_path),
            package_root=self.package_root,
        )

        self.assertEqual(len(outcomes), 1)
        outcome = outcomes[0]
        self.assertEqual(outcome.report.input_line, 17)
        self.assertEqual(outcome.report.entry_id, "entry-00017")
        self.assertEqual(outcome.report.report_id, REPORT_ID)
        self.assertEqual(outcome.report.fields["schema"].status, "correct")
        self.assertEqual(outcome.report.fields["report_id"].status, "uncertain")
        self.assertEqual(outcome.report.fields["commit"].status, "uncertain")
        self.assertEqual(outcome.report.verdict, "uncertain")
        self.assertEqual(counts["uncertain"], 1)
        self.assertEqual(candidate, original)

    def test_same_entry_with_different_advisories_has_distinct_evidence_ids(self) -> None:
        first_path = "collision/first.json"
        second_path = "collision/second.json"
        first_text = self._advisory_text()
        second = json.loads(first_text)
        second["summary"] = "A different local advisory body for replay."
        self._write_advisory(first_path, first_text)
        self._write_advisory(second_path, json.dumps(second))
        candidate = self._candidate(entry_id="entry-00041")

        outcomes, _ = run_batch(
            [
                InputRecord(
                    1,
                    {"package": {"advisory": first_path}, "entry": deepcopy(candidate)},
                ),
                InputRecord(
                    2,
                    {"package": {"advisory": second_path}, "entry": deepcopy(candidate)},
                ),
            ],
            RepositoryResolver(repo_root=self.repo_path),
            package_root=self.package_root,
        )

        first_evidence = {item.evidence_id: item.to_dict() for item in outcomes[0].evidence}
        second_evidence = {item.evidence_id: item.to_dict() for item in outcomes[1].evidence}
        shared = set(first_evidence) & set(second_evidence)
        self.assertTrue(shared)
        self.assertTrue(
            all(first_evidence[item] == second_evidence[item] for item in shared)
        )
        self.assertNotEqual(set(first_evidence), set(second_evidence))


if __name__ == "__main__":
    unittest.main()
