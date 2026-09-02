from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import vulngym_agent.lane_a_assignment_materializer as materializer
import vulngym_agent.lane_a_task_bundle as lane_bundle
from vulngym_agent.agents.t2_toolbox import MAX_LOCAL_FILE_BYTES
from vulngym_agent.evidence import load_evidence_package
from vulngym_agent.lane_a_assignment_materializer import (
    ASSIGNMENTS_FILENAME,
    COVERAGE_AUDIT_FILENAME,
    LaneAAssignmentMaterializerError,
    compute_lane_a_assignment_input_pins,
    verify_lane_a_assignment_materialization,
    write_lane_a_assignment_materialization,
)
from vulngym_agent.lane_a_task_bundle import (
    compute_lane_a_input_pins,
    write_lane_a_task_bundle,
)


def _wire(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _jsonl(values: list[object]) -> bytes:
    return b"".join(_wire(value) for value in values)


class LaneAAssignmentMaterializerTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output_root = self.root / "outputs"
        self.output_root.mkdir()
        self.bundle_root = self.root / "bundles"
        self.bundle_root.mkdir()
        self.repo = self.root / "repo"
        self._git("init", str(self.repo), cwd=self.root)
        self._git("config", "user.name", "Fixture", cwd=self.repo)
        self._git("config", "user.email", "fixture@example.invalid", cwd=self.repo)
        (self.repo / "src").mkdir()
        (self.repo / "src" / "app.py").write_text(
            "def check(value):\n    return value\n", encoding="utf-8"
        )
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        self._git("add", "--all", cwd=self.repo)
        self._git("-c", "commit.gpgsign=false", "commit", "-m", "vulnerable", cwd=self.repo)
        self.vulnerable = self._git("rev-parse", "HEAD", cwd=self.repo).strip()

        (self.repo / "src" / "app.py").write_text(
            "def check(value):\n    return bool(value)\n", encoding="utf-8"
        )
        self._git("add", "--all", cwd=self.repo)
        self._git("-c", "commit.gpgsign=false", "commit", "-m", "fix", cwd=self.repo)
        self.fix = self._git("rev-parse", "HEAD", cwd=self.repo).strip()
        self.main_branch = self._git("branch", "--show-current", cwd=self.repo).strip()

        self._git("checkout", "-b", "alternate", self.vulnerable, cwd=self.repo)
        (self.repo / "src" / "app.py").write_text(
            "def check(value):\n    return value is not None\n", encoding="utf-8"
        )
        self._git("add", "--all", cwd=self.repo)
        self._git("-c", "commit.gpgsign=false", "commit", "-m", "alternate fix", cwd=self.repo)
        self.alternate_fix = self._git("rev-parse", "HEAD", cwd=self.repo).strip()

        self._git("checkout", self.main_branch, cwd=self.repo)
        (self.repo / "src" / "app.py").write_text(
            "def check(value):\n    return bool(value and value.strip())\n", encoding="utf-8"
        )
        self._git("add", "--all", cwd=self.repo)
        self._git("-c", "commit.gpgsign=false", "commit", "-m", "later", cwd=self.repo)
        self.descendant = self._git("rev-parse", "HEAD", cwd=self.repo).strip()

        self.repo_url = "https://github.com/example/repo"
        self.tasks_path = self.root / "tasks.jsonl"
        self.reports_path = self.root / "reports.jsonl"
        self.cache_path = self.root / "advisories.jsonl"
        self.repo_map_path = self.root / "repos.json"
        self.task = {
            "commit": self.vulnerable,
            "instruction_id": "vulngym-whitebox-locate-v1",
            "repo_url": self.repo_url,
            "split": "test",
            "task_id": "VG-TEST-00000000000000000001",
        }
        self.reports = [
            self._report("GHSA-1111-1111-1111", ["entry-00001", "entry-00002"]),
            self._report("GHSA-2222-2222-2222", ["entry-00003"]),
        ]
        self.cache = [
            self._advisory("GHSA-1111-1111-1111", [self._commit_url(self.fix)]),
            self._advisory(
                "GHSA-2222-2222-2222",
                ["https://github.com/example/repo/issues/2"],
            ),
        ]
        self._write_inputs()

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
            env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
        )
        if result.returncode != 0:
            raise AssertionError(result.stderr + result.stdout)
        return result.stdout

    def _report(self, report_id: str, entry_ids: list[str]) -> dict[str, object]:
        return {
            "commit": self.vulnerable,
            "entry_ids": entry_ids,
            "num_entries": len(entry_ids),
            "origin": "GitHub Advisory Database (reviewed)",
            "project": "repo",
            "repo_url": self.repo_url,
            "report_id": report_id,
            "source_link": f"https://github.com/advisories/{report_id}",
            "vuln_ids": [report_id],
            "vuln_title": f"Fixture {report_id}",
        }

    @staticmethod
    def _advisory(report_id: str, references: list[str]) -> dict[str, object]:
        return {
            "description": "A public advisory fixture.",
            "ghsa_id": report_id,
            "identifiers": [{"type": "GHSA", "value": report_id}],
            "references": sorted(references),
            "summary": "Fixture vulnerability",
        }

    def _commit_url(self, commit: str, repo_url: str | None = None) -> str:
        return f"{repo_url or self.repo_url}/commit/{commit}"

    def _write_inputs(self) -> None:
        self.tasks_path.write_bytes(_jsonl([self.task]))
        self.reports_path.write_bytes(_jsonl(self.reports))
        self.cache_path.write_bytes(_jsonl(self.cache))
        self.repo_map_path.write_bytes(
            _wire(
                {
                    "contract_version": 1,
                    "repositories": [{"path": str(self.repo), "repo_url": self.repo_url}],
                }
            )
        )

    def _pins(self) -> dict[str, object]:
        pins = compute_lane_a_assignment_input_pins(
            self.tasks_path, self.reports_path, self.cache_path, self.repo_map_path
        )
        return {
            "expected_advisory_cache_sha256": pins["advisory_cache_sha256"],
            "expected_advisory_cache_wire_sha256": pins["advisory_cache_wire_sha256"],
            "expected_public_tasks_sha256": pins["public_tasks_sha256"],
            "expected_public_tasks_wire_sha256": pins["public_tasks_wire_sha256"],
            "expected_reports_sha256": pins["reports_sha256"],
            "expected_reports_wire_sha256": pins["reports_wire_sha256"],
            "expected_repo_map_sha256": pins["repo_map_sha256"],
            "expected_repo_map_wire_sha256": pins["repo_map_wire_sha256"],
            "expected_task_count": pins["task_count"],
        }

    def _build(self, name: str = "output"):
        return write_lane_a_assignment_materialization(
            self.output_root / name,
            self.tasks_path,
            self.reports_path,
            self.cache_path,
            self.repo_map_path,
            **self._pins(),
        )

    def _cli_args(self, output: Path) -> list[str]:
        pins = self._pins()
        arguments = [
            "build",
            "--public-tasks-file", str(self.tasks_path),
            "--reports-file", str(self.reports_path),
            "--advisory-cache-file", str(self.cache_path),
            "--repo-map-file", str(self.repo_map_path),
        ]
        for name, value in pins.items():
            arguments.extend(["--" + name.replace("expected_", "expected-").replace("_", "-"), str(value)])
        arguments.extend(["--output-dir", str(output)])
        return arguments

    def test_build_selects_one_anchor_and_audits_every_extra(self) -> None:
        manifest = self._build()
        output = self.output_root / "output"
        assignment = json.loads((output / ASSIGNMENTS_FILENAME).read_bytes())
        self.assertEqual(assignment["report_id"], "GHSA-1111-1111-1111")
        self.assertEqual(assignment["entry_id"], "entry-00001")
        self.assertEqual(assignment["hints"]["fix_commits"], [self.fix])
        self.assertEqual(assignment["hints"]["source_paths"], ["src/app.py"])
        audit = json.loads((output / COVERAGE_AUDIT_FILENAME).read_bytes())
        self.assertEqual(audit["anchor_policy"], "lexicographic-report-entry-v1")
        self.assertEqual(
            audit["anchor_semantics"],
            "deterministic_evaluation_anchor_not_finding_provenance",
        )
        self.assertEqual(
            audit["not_run"],
            [
                {"entry_ids": ["entry-00002"], "report_id": "GHSA-1111-1111-1111"},
                {"entry_ids": ["entry-00003"], "report_id": "GHSA-2222-2222-2222"},
            ],
        )
        patch = (output / f"patch-GHSA-1111-1111-1111.diff").read_text(encoding="utf-8")
        self.assertIn("diff --git a/src/app.py b/src/app.py", patch)
        self.assertNotIn(str(self.root), (output / "manifest.json").read_text(encoding="utf-8"))
        verify_lane_a_assignment_materialization(
            output,
            self.tasks_path,
            self.reports_path,
            self.cache_path,
            self.repo_map_path,
            expected_materialization_sha256=manifest.materialization_sha256,
            expected_manifest_wire_sha256=manifest.manifest_wire_sha256,
            **self._pins(),
        )

    def test_output_feeds_task_bundle_and_evidence_loader(self) -> None:
        materialized = self.output_root / "materialized"
        self._build("materialized")
        assignment_path = materialized / ASSIGNMENTS_FILENAME
        bundle_pins = compute_lane_a_input_pins(self.tasks_path, assignment_path)
        write_lane_a_task_bundle(
            self.bundle_root / "task-bundle",
            self.tasks_path,
            assignment_path,
            expected_public_tasks_sha256=bundle_pins["public_tasks_sha256"],
            expected_public_tasks_wire_sha256=bundle_pins["public_tasks_wire_sha256"],
            expected_assignments_sha256=bundle_pins["assignments_sha256"],
            expected_assignments_wire_sha256=bundle_pins["assignments_wire_sha256"],
            expected_task_count=bundle_pins["task_count"],
            protected_paths=[materialized],
        )
        run_task = json.loads(
            (self.bundle_root / "task-bundle" / "run_tasks.jsonl").read_bytes()
        )
        package_result = load_evidence_package(
            materialized,
            run_task["inputs"]["package"],
            input_line=1,
            entry_id=run_task["entry_id"],
            report_id=run_task["report_id"],
        )
        self.assertEqual(package_result.status, "correct")
        self.assertIsNotNone(package_result.package)

    def test_ambiguous_direct_children_fail_closed(self) -> None:
        self.cache[0]["references"] = sorted(
            [self._commit_url(self.fix), self._commit_url(self.alternate_fix)]
        )
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "ambiguous_fix_candidate")

    def test_wrong_parent_fails_closed(self) -> None:
        self.cache[0]["references"] = [self._commit_url(self.descendant)]
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "fix_parent_mismatch")

    def test_cross_repo_and_traversal_like_commit_references_are_not_candidates(self) -> None:
        self.cache[0]["references"] = sorted(
            [
                self._commit_url(self.fix, "https://github.com/other/repo"),
                f"{self.repo_url}/commit/../{self.fix}",
            ]
        )
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "fix_candidate_missing")

    def test_answer_fields_and_leak_markers_are_rejected(self) -> None:
        self.cache[0]["trace"] = []
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            compute_lane_a_assignment_input_pins(
                self.tasks_path, self.reports_path, self.cache_path, self.repo_map_path
            )
        self.assertEqual(caught.exception.code, "advisory_fields")
        del self.cache[0]["trace"]
        self.cache[0]["description"] = "selection_lock must never cross this boundary"
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "private_marker")

    def test_advisory_prose_cannot_smuggle_an_extra_ghsa_or_fix(self) -> None:
        self.cache[0]["description"] = "Related GHSA-3333-3333-3333"
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "advisory_identifier_mismatch")

        self.cache[0]["description"] = "Fix commit " + self.alternate_fix
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "advisory_ambiguous")

    def test_advisory_identifiers_must_equal_public_report(self) -> None:
        self.cache[0]["identifiers"] = [
            {"type": "CVE", "value": "CVE-2026-12345"},
            {"type": "GHSA", "value": "GHSA-1111-1111-1111"},
        ]
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "advisory_identifier_mismatch")

    def test_advisory_cannot_omit_a_public_report_identifier(self) -> None:
        self.reports[0]["vuln_ids"] = [
            "CVE-2026-12345",
            "GHSA-1111-1111-1111",
        ]
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "advisory_identifier_mismatch")

    def test_advisory_must_fit_downstream_t2_file_budget(self) -> None:
        self.cache[0]["description"] = "x" * MAX_LOCAL_FILE_BYTES
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "advisory_limit")

    def test_source_diff_must_fit_downstream_t2_git_budget(self) -> None:
        self._git("checkout", "-b", "oversized-diff", self.vulnerable, cwd=self.repo)
        large_source = "\n".join(f"value_{index} = '{'x' * 1000}'" for index in range(160))
        (self.repo / "src" / "app.py").write_text(large_source + "\n", encoding="utf-8")
        self._git("add", "--all", cwd=self.repo)
        self._git(
            "-c", "commit.gpgsign=false", "commit", "-m", "oversized diff", cwd=self.repo
        )
        oversized_fix = self._git("rev-parse", "HEAD", cwd=self.repo).strip()
        self.cache[0]["references"] = [self._commit_url(oversized_fix)]
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "non_source_diff")

    def test_non_source_only_fix_is_rejected(self) -> None:
        self._git("checkout", "-b", "docs-only", self.vulnerable, cwd=self.repo)
        (self.repo / "README.md").write_text("changed\n", encoding="utf-8")
        self._git("add", "--all", cwd=self.repo)
        self._git("-c", "commit.gpgsign=false", "commit", "-m", "docs only", cwd=self.repo)
        docs_fix = self._git("rev-parse", "HEAD", cwd=self.repo).strip()
        self.cache[0]["references"] = [self._commit_url(docs_fix)]
        self._write_inputs()
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "non_source_diff")

    def test_no_overwrite_and_deterministic_readback(self) -> None:
        first_manifest = self._build("first")
        second_manifest = self._build("second")
        first = self.output_root / "first"
        second = self.output_root / "second"
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(
            {item.name: item.read_bytes() for item in first.iterdir()},
            {item.name: item.read_bytes() for item in second.iterdir()},
        )
        marker = self.output_root / "occupied"
        marker.mkdir()
        (marker / "owner.txt").write_text("owner", encoding="utf-8")
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            write_lane_a_assignment_materialization(
                marker,
                self.tasks_path,
                self.reports_path,
                self.cache_path,
                self.repo_map_path,
                **self._pins(),
            )
        self.assertEqual(caught.exception.code, "output_exists")
        self.assertEqual((marker / "owner.txt").read_text(encoding="utf-8"), "owner")

    def test_hardlinked_input_is_rejected(self) -> None:
        alias = self.root / "tasks-hardlink.jsonl"
        try:
            os.link(self.tasks_path, alias)
        except OSError:
            self.skipTest("hardlinks are unavailable")
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            compute_lane_a_assignment_input_pins(
                self.tasks_path, self.reports_path, self.cache_path, self.repo_map_path
            )
        self.assertEqual(caught.exception.code, "unsafe_path")

    def test_reparse_marked_input_is_rejected(self) -> None:
        target_inode = os.lstat(self.cache_path).st_ino
        actual = lane_bundle._is_reparse

        def marked(state):
            return state.st_ino == target_inode or actual(state)

        with mock.patch.object(lane_bundle, "_is_reparse", side_effect=marked):
            with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
                compute_lane_a_assignment_input_pins(
                    self.tasks_path,
                    self.reports_path,
                    self.cache_path,
                    self.repo_map_path,
                )
        self.assertEqual(caught.exception.code, "unsafe_path")

    def test_repository_alias_and_hardlinked_metadata_are_rejected(self) -> None:
        self.repo_map_path.write_bytes(
            _wire(
                {
                    "contract_version": 1,
                    "repositories": [
                        {"path": str(self.repo), "repo_url": self.repo_url},
                        {
                            "path": str(self.repo),
                            "repo_url": "https://github.com/example/repo2",
                        },
                    ],
                }
            )
        )
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            compute_lane_a_assignment_input_pins(
                self.tasks_path, self.reports_path, self.cache_path, self.repo_map_path
            )
        self.assertEqual(caught.exception.code, "repo_map_duplicate")

        self._write_inputs()
        head_alias = self.root / "head-hardlink"
        try:
            os.link(self.repo / ".git" / "HEAD", head_alias)
        except OSError:
            self.skipTest("repository metadata hardlinks are unavailable")
        with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
            self._build()
        self.assertEqual(caught.exception.code, "repository_unsafe")

    def test_input_mutation_between_passes_is_rejected(self) -> None:
        pins = self._pins()
        original = materializer._build_payloads
        calls = 0

        def mutate_after_first(inputs):
            nonlocal calls
            result = original(inputs)
            calls += 1
            if calls == 1:
                self.cache[0]["summary"] = "Changed after the first pass"
                self.cache_path.write_bytes(_jsonl(self.cache))
            return result

        with mock.patch.object(materializer, "_build_payloads", side_effect=mutate_after_first):
            with self.assertRaises(LaneAAssignmentMaterializerError) as caught:
                write_lane_a_assignment_materialization(
                    self.output_root / "mutating",
                    self.tasks_path,
                    self.reports_path,
                    self.cache_path,
                    self.repo_map_path,
                    **pins,
                )
        self.assertEqual(caught.exception.code, "input_changed")
        self.assertFalse((self.output_root / "mutating").exists())

    def test_optimized_cli_build_and_verify(self) -> None:
        output = self.output_root / "optimized"
        command = [
            sys.executable,
            "-O",
            "-m",
            "vulngym_agent.lane_a_assignment_materializer_cli",
            *self._cli_args(output),
        ]
        result = subprocess.run(
            command,
            cwd=Path(__file__).parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["status"], "ok")
        verify_arguments = self._cli_args(self.output_root / "unused")[1:-2]
        verify_command = [
            sys.executable,
            "-O",
            "-m",
            "vulngym_agent.lane_a_assignment_materializer_cli",
            "verify",
            *verify_arguments,
            "--materialization-dir", str(output),
            "--expected-materialization-sha256", summary["materialization_sha256"],
            "--expected-manifest-wire-sha256", summary["manifest_wire_sha256"],
        ]
        verified = subprocess.run(
            verify_command,
            cwd=Path(__file__).parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr + verified.stdout)
        self.assertEqual(json.loads(verified.stdout)["operation"], "verify")

    def test_precommit_failure_keeps_staging_for_inspection(self) -> None:
        output = self.output_root / "retained"
        with mock.patch.object(
            materializer, "_rename_noreplace", side_effect=OSError("synthetic")
        ):
            with self.assertRaises(LaneAAssignmentMaterializerError):
                self._build("retained")
        self.assertFalse(output.exists())
        stages = list(self.output_root.glob(".retained.lane-a-assignment-*"))
        self.assertEqual(len(stages), 1)
        self.assertIn("manifest.json", {item.name for item in stages[0].iterdir()})


if __name__ == "__main__":
    unittest.main()
