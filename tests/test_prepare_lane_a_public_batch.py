from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import prepare_lane_a_public_batch as prep
from vulngym_agent.lane_a_assignment_materializer import (
    compute_lane_a_assignment_input_pins,
)


def _canonical_line(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


class PrepareLaneAPublicBatchTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.repo_root = self.root / "repositories"
        self.repo_root.mkdir()
        self.outputs = self.root / "outputs"
        self.outputs.mkdir()

        self.repo_url = "https://github.com/example/repo"
        self.vulnerable, self.fix = self._make_bare_repository("example", "repo")
        self.task_id = "VG-TEST-00000000000000000001"
        self.other_task_id = "VG-TEST-00000000000000000002"
        self.report_id = "GHSA-1111-1111-1111"
        self.cve_id = "CVE-2026-10001"
        self.tasks_file = self.inputs / "tasks.jsonl"
        self.reports_file = self.inputs / "reports.jsonl"
        self.tasks = [
            self._task(self.task_id, self.vulnerable),
            self._task(self.other_task_id, "1" * 40, repo_url="https://github.com/other/repo"),
        ]
        self.reports = [
            self._report(self.report_id, self.vulnerable),
            self._report(
                "GHSA-2222-2222-2222",
                "1" * 40,
                repo_url="https://github.com/other/repo",
                entry_id="entry-00002",
                vuln_ids=["GHSA-2222-2222-2222"],
            ),
        ]
        self.tasks_file.write_bytes(b"".join(_canonical_line(item) for item in self.tasks))
        # The checked-in public report index is valid JSONL but not itself in
        # canonical compact form.  The preparer must canonicalize selected rows.
        self.reports_file.write_bytes(
            b"".join((json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8") for item in self.reports)
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _git(*arguments: str, cwd: Path) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            env={
                **os.environ,
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
            },
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr + result.stdout)
        return result.stdout.strip()

    def _make_bare_repository(self, owner: str, name: str) -> tuple[str, str]:
        work = self.root / f"work-{owner}-{name}"
        work.mkdir()
        self._git("init", cwd=work)
        self._git("config", "user.name", "Fixture", cwd=work)
        self._git("config", "user.email", "fixture@example.invalid", cwd=work)
        source = work / "app.py"
        source.write_text("def run(value):\n    return value\n", encoding="utf-8")
        self._git("add", "app.py", cwd=work)
        self._git("-c", "commit.gpgsign=false", "commit", "-m", "vulnerable", cwd=work)
        vulnerable = self._git("rev-parse", "HEAD", cwd=work)
        source.write_text("def run(value):\n    return bool(value)\n", encoding="utf-8")
        self._git("add", "app.py", cwd=work)
        self._git("-c", "commit.gpgsign=false", "commit", "-m", "fix", cwd=work)
        fix = self._git("rev-parse", "HEAD", cwd=work)
        owner_dir = self.repo_root / owner
        owner_dir.mkdir(parents=True, exist_ok=True)
        self._git(
            "clone",
            "--bare",
            "--no-hardlinks",
            str(work),
            str(owner_dir / f"{name}.git"),
            cwd=self.root,
        )
        return vulnerable, fix

    def _task(self, task_id: str, commit: str, *, repo_url: str | None = None) -> dict[str, object]:
        return {
            "commit": commit,
            "instruction_id": "vulngym-whitebox-locate-v1",
            "repo_url": repo_url or self.repo_url,
            "split": "test",
            "task_id": task_id,
        }

    def _report(
        self,
        report_id: str,
        commit: str,
        *,
        repo_url: str | None = None,
        entry_id: str = "entry-00001",
        vuln_ids: list[str] | None = None,
    ) -> dict[str, object]:
        selected_ids = vuln_ids or [self.cve_id, report_id]
        return {
            "commit": commit,
            "entry_ids": [entry_id],
            "num_entries": 1,
            "origin": "GitHub Advisory Database (reviewed)",
            "project": "repo",
            "repo_url": repo_url or self.repo_url,
            "report_id": report_id,
            "source_link": (
                "https://github.com/advisories/GHSA-"
                + report_id.removeprefix("GHSA-").lower()
            ),
            "vuln_ids": selected_ids,
            "vuln_title": "Fixture vulnerability",
        }

    def _advisory(self, ghsa_id: str | None = None, *, references: list[str] | None = None) -> dict[str, object]:
        report_id = ghsa_id or self.report_id
        identifiers = (
            [
                {"type": "GHSA", "value": report_id.lower()},
                {"type": "CVE", "value": self.cve_id.lower()},
                {"type": "INTERNAL", "value": "must-not-persist"},
            ]
            if report_id == self.report_id
            else [{"type": "GHSA", "value": report_id}]
        )
        return {
            "cvss": {"score": 9.8},
            "description": "  Public description.  ",
            "ghsa_id": report_id.lower(),
            "identifiers": identifiers,
            "references": references
            or [
                {"url": f"{self.repo_url}/commit/{self.fix}"},
                "https://example.invalid/context",
            ],
            "secret_control": "must-not-persist",
            "summary": "  Public summary  ",
        }

    def _prepare(self, *, output_name: str = "prepared", fetcher=None):
        return prep.prepare_lane_a_public_batch(
            public_tasks_file=self.tasks_file,
            public_reports_file=self.reports_file,
            local_repo_root=self.repo_root,
            task_ids=[self.task_id],
            output_dir=self.outputs / output_name,
            advisory_fetcher=fetcher or (lambda _ghsa: self._advisory()),
        )

    def test_prepares_exact_canonical_public_inputs_and_real_pins(self) -> None:
        requested: list[str] = []
        result = self._prepare(fetcher=lambda ghsa: requested.append(ghsa) or self._advisory())
        output = self.outputs / "prepared"

        self.assertEqual(requested, [self.report_id])
        self.assertEqual(
            {item.name for item in output.iterdir()},
            {
                prep.TASKS_FILENAME,
                prep.REPORTS_FILENAME,
                prep.GHSA_CACHE_FILENAME,
                prep.REPOS_FILENAME,
            },
        )
        task = json.loads((output / prep.TASKS_FILENAME).read_bytes())
        report = json.loads((output / prep.REPORTS_FILENAME).read_bytes())
        advisory_wire = (output / prep.GHSA_CACHE_FILENAME).read_bytes()
        advisory = json.loads(advisory_wire)
        repo_map = json.loads((output / prep.REPOS_FILENAME).read_bytes())

        self.assertEqual(task["task_id"], self.task_id)
        self.assertEqual(report["report_id"], self.report_id)
        self.assertEqual(
            set(advisory),
            {"description", "ghsa_id", "identifiers", "references", "summary"},
        )
        self.assertEqual(advisory["description"], "Public description.")
        self.assertEqual(advisory["summary"], "Public summary")
        self.assertEqual(
            advisory["identifiers"],
            [
                {"type": "CVE", "value": self.cve_id},
                {"type": "GHSA", "value": self.report_id},
            ],
        )
        self.assertNotIn(b"must-not-persist", advisory_wire)
        self.assertEqual(repo_map["contract_version"], 1)
        self.assertEqual(repo_map["repositories"][0]["repo_url"], self.repo_url)
        self.assertTrue(repo_map["repositories"][0]["path"].endswith("repo.git"))

        for name in prep.OUTPUT_FILENAMES:
            payload = (output / name).read_bytes()
            self.assertTrue(payload.endswith(b"\n"))
            self.assertNotIn(b"\r\n", payload)
            for line in payload.splitlines(keepends=True):
                self.assertEqual(line, _canonical_line(json.loads(line)))

        expected_pins = compute_lane_a_assignment_input_pins(
            output / prep.TASKS_FILENAME,
            output / prep.REPORTS_FILENAME,
            output / prep.GHSA_CACHE_FILENAME,
            output / prep.REPOS_FILENAME,
        )
        self.assertEqual(result["pins"], expected_pins)
        self.assertEqual(result["summary"]["task_ids"], [self.task_id])
        self.assertEqual(
            result["summary"]["fix_commits"],
            [{"fix_commit": self.fix, "task_id": self.task_id}],
        )

    def test_rejects_existing_output_before_fetch(self) -> None:
        output = self.outputs / "occupied"
        output.mkdir()
        fetcher = mock.Mock(side_effect=AssertionError("must not fetch"))
        with self.assertRaises(prep.LaneAPublicBatchError) as captured:
            self._prepare(output_name="occupied", fetcher=fetcher)
        self.assertEqual(captured.exception.code, "output_exists")
        fetcher.assert_not_called()

    def test_unknown_explicit_task_fails_without_network_or_output(self) -> None:
        fetcher = mock.Mock(side_effect=AssertionError("must not fetch"))
        with self.assertRaises(prep.LaneAPublicBatchError) as captured:
            prep.prepare_lane_a_public_batch(
                public_tasks_file=self.tasks_file,
                public_reports_file=self.reports_file,
                local_repo_root=self.repo_root,
                task_ids=["VG-TEST-FFFFFFFFFFFFFFFFFFFF"],
                output_dir=self.outputs / "missing",
                advisory_fetcher=fetcher,
            )
        self.assertEqual(captured.exception.code, "task_missing")
        self.assertFalse((self.outputs / "missing").exists())
        fetcher.assert_not_called()

    def test_missing_vulnerable_commit_fails_before_network(self) -> None:
        missing = "f" * 40
        self.tasks_file.write_bytes(_canonical_line(self._task(self.task_id, missing)))
        self.reports_file.write_bytes(
            (json.dumps(self._report(self.report_id, missing)) + "\n").encode("utf-8")
        )
        fetcher = mock.Mock(side_effect=AssertionError("must not fetch"))
        with self.assertRaises(prep.LaneAPublicBatchError) as captured:
            self._prepare(output_name="missing-commit", fetcher=fetcher)
        self.assertEqual(captured.exception.code, "vulnerable_commit_missing")
        fetcher.assert_not_called()

    def test_advisory_without_direct_fix_reference_is_not_published(self) -> None:
        with self.assertRaises(prep.LaneAPublicBatchError) as captured:
            self._prepare(
                output_name="no-fix",
                fetcher=lambda _ghsa: self._advisory(
                    references=["https://github.com/example/repo/issues/1"]
                ),
            )
        self.assertEqual(captured.exception.code, "fix_candidate_missing")
        self.assertFalse((self.outputs / "no-fix").exists())

    def test_forbidden_input_name_is_rejected_without_reading_it(self) -> None:
        forbidden = self.inputs / "test_gold.jsonl"
        forbidden.write_bytes(self.tasks_file.read_bytes())
        with self.assertRaises(prep.LaneAPublicBatchError) as captured:
            prep.prepare_lane_a_public_batch(
                public_tasks_file=forbidden,
                public_reports_file=self.reports_file,
                local_repo_root=self.repo_root,
                task_ids=[self.task_id],
                output_dir=self.outputs / "forbidden",
                advisory_fetcher=lambda _ghsa: self._advisory(),
            )
        self.assertEqual(captured.exception.code, "forbidden_input")

    def test_fetch_uses_fixed_github_api_shape_and_accepts_ignored_float(self) -> None:
        raw = self._advisory()
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(raw).encode("utf-8"), stderr=b""
        )
        with mock.patch.object(prep, "_gh_executable", return_value="C:\\tools\\gh.exe"), mock.patch.object(
            prep.subprocess, "run", return_value=completed
        ) as run:
            observed = prep._fetch_advisory(self.report_id)
        self.assertEqual(observed["cvss"]["score"], 9.8)
        command = run.call_args.args[0]
        self.assertEqual(
            command,
            [
                "C:\\tools\\gh.exe",
                "api",
                "--hostname",
                "github.com",
                "-H",
                "Accept: application/vnd.github+json",
                f"/advisories/{self.report_id}",
            ],
        )
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
