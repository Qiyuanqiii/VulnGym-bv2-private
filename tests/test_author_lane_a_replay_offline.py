from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any
import unittest
from unittest.mock import patch

from scripts.author_lane_a_replay_offline import (
    DecisionAuthoringBackend,
    LaneAReplayAuthoringError,
    RepairDecision,
    TaskDecision,
    author_lane_a_replay,
    main as authoring_main,
)
from vulngym_agent.agents.model_runtime import ModelRequest
from vulngym_agent.closed_loop_cli import main as closed_loop_main


REPORT_ID = "GHSA-1111-2222-3333"
ENTRY_ID = "entry-00001"
TASK_ID = "VG-TEST-00000000000000000001"
REPO_URL = "https://github.com/example/project"
SOURCE_PATH = "src/app.py"


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


class LaneAReplayAuthoringTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = self.root / "repository"
        self.package = self.root / "package"
        (self.repository / "src").mkdir(parents=True)
        (self.package / "advisories").mkdir(parents=True)
        (self.package / "patches").mkdir(parents=True)
        _git(self.repository, "init", "--quiet")
        _git(self.repository, "config", "user.name", "VulGym Test")
        _git(
            self.repository,
            "config",
            "user.email",
            "vulngym-test@example.invalid",
        )
        vulnerable = (
            "def dangerous(user):\n"
            "    return eval(user)\n"
            "\n"
            "@app.route('/run')\n"
            "def public_route(request):\n"
            "    return dangerous(request)\n"
        )
        (self.repository / SOURCE_PATH).write_text(vulnerable, encoding="utf-8")
        _git(self.repository, "add", "--", SOURCE_PATH)
        _git(self.repository, "commit", "--quiet", "-m", "vulnerable")
        self.vulnerable_commit = _git(self.repository, "rev-parse", "HEAD")
        fixed = (
            "def dangerous(user):\n"
            "    if not user.isdigit():\n"
            "        return None\n"
            "    return int(user)\n"
            "\n"
            "@app.route('/run')\n"
            "def public_route(request):\n"
            "    return dangerous(request)\n"
        )
        (self.repository / SOURCE_PATH).write_text(fixed, encoding="utf-8")
        _git(self.repository, "add", "--", SOURCE_PATH)
        _git(self.repository, "commit", "--quiet", "-m", "fix")
        self.fix_commit = _git(self.repository, "rev-parse", "HEAD")
        patch_text = _git(
            self.repository,
            "diff",
            "--no-ext-diff",
            self.vulnerable_commit,
            self.fix_commit,
            "--",
            SOURCE_PATH,
        )
        (self.package / "patches" / "fix.patch").write_text(
            patch_text + "\n", encoding="utf-8", newline="\n"
        )
        _write_json(
            self.package / "advisories" / "item.json",
            {
                "cve": "CVE-2026-12345",
                "fix_commits": [self.fix_commit],
                "ghsa_id": REPORT_ID,
                "source_link": f"https://github.com/advisories/{REPORT_ID}",
                "summary": "Unsafe eval permits code execution from a public route.",
            },
        )
        self.tasks = self.root / "run_tasks.jsonl"
        _write_json(
            self.tasks,
            {
                "entry_id": ENTRY_ID,
                "inputs": {
                    "contract_version": 2,
                    "expected_vulnerable_commit": self.vulnerable_commit,
                    "hints": {
                        "critical_mode": "sink",
                        "entry_symbols": ["public_route", "dangerous"],
                        "fix_commits": [self.fix_commit],
                        "project": "example-project",
                        "source_paths": [SOURCE_PATH],
                    },
                    "input_line": 1,
                    "package": {
                        "advisory": "advisories/item.json",
                        "patches": ["patches/fix.patch"],
                        "references": [],
                    },
                    "repo_url": REPO_URL,
                },
                "report_id": REPORT_ID,
                "task_id": TASK_ID,
            },
        )
        self.repo_map = self.root / "repo-map.json"
        _write_json(
            self.repo_map,
            {
                "contract_version": 1,
                "repositories": [
                    {"path": str(self.repository.resolve()), "repo_url": REPO_URL}
                ],
            },
        )
        self.decisions = self.root / "decisions.json"
        _write_json(
            self.decisions,
            {
                "contract_version": 1,
                "tasks": [
                    {
                        "plan": {"critical_mode": "sink"},
                        "reflection": {"action": "emit"},
                        "repairs": [],
                        "semantic_judge": {
                            "critical_candidate_ordinal": 1,
                            "entry_candidate_ordinal": 1,
                            "project": "example-project",
                            "vuln_category_l1": "Injection",
                            "vuln_category_l2": "Code Injection",
                            "vuln_title": "Unsafe evaluation of an untrusted route value",
                        },
                        "task_id": TASK_ID,
                    }
                ],
            },
        )

    def test_authors_request_bound_replay_and_formal_cli_replays_it(self) -> None:
        replay = self.root / "exact-replay.json"
        summary = author_lane_a_replay(
            tasks_path=self.tasks,
            decisions_path=self.decisions,
            repo_map_path=self.repo_map,
            package_root=self.package,
            output_replay=replay,
        )

        document = json.loads(replay.read_text(encoding="utf-8"))
        self.assertEqual(document["contract_version"], 2)
        self.assertEqual(document["backend_id"], "exact-replay")
        self.assertEqual(
            [item["stage"] for item in document["responses"]],
            ["plan", "semantic_judge", "reflection"],
        )
        self.assertTrue(
            all(len(item["request_sha256"]) == 64 for item in document["responses"])
        )
        self.assertTrue(summary["exact_replay_verified"])
        self.assertEqual(summary["task_count"], 1)
        self.assertEqual(summary["status_counts"], {"manual_review": 1})
        self.assertEqual(summary["verdict_counts"], {"uncertain": 1})
        serialized_summary = json.dumps(summary, ensure_ascii=False)
        self.assertNotIn(str(self.root), serialized_summary)
        self.assertNotIn("return eval(user)", serialized_summary)

        output = self.root / "closed-loop-output"
        stdout = io.StringIO()
        with patch("sys.stdout", stdout):
            code = closed_loop_main(
                [
                    "--tasks",
                    str(self.tasks),
                    "--replay-responses",
                    str(replay),
                    "--repo-map",
                    str(self.repo_map),
                    "--package-root",
                    str(self.package),
                    "--output-dir",
                    str(output),
                ]
            )
        batch = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(batch["tasks_run"], 1)
        self.assertEqual(batch["manual_review"], 1)
        self.assertEqual(batch["entries_written"], 0)
        self.assertEqual(
            len(
                (output / "validation.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ),
            1,
        )

    def test_out_of_range_candidate_ordinal_publishes_nothing(self) -> None:
        decision = json.loads(self.decisions.read_text(encoding="utf-8"))
        decision["tasks"][0]["semantic_judge"]["critical_candidate_ordinal"] = 999
        _write_json(self.decisions, decision)
        replay = self.root / "must-not-exist.json"

        with self.assertRaisesRegex(
            LaneAReplayAuthoringError, "candidate ordinal"
        ) as raised:
            author_lane_a_replay(
                tasks_path=self.tasks,
                decisions_path=self.decisions,
                repo_map_path=self.repo_map,
                package_root=self.package,
                output_replay=replay,
            )

        self.assertEqual(raised.exception.code, "candidate_ordinal_invalid")
        self.assertFalse(replay.exists())

    def test_contract_version_rejects_boolean_type_confusion(self) -> None:
        decision = json.loads(self.decisions.read_text(encoding="utf-8"))
        decision["contract_version"] = True
        _write_json(self.decisions, decision)

        with self.assertRaises(LaneAReplayAuthoringError) as raised:
            author_lane_a_replay(
                tasks_path=self.tasks,
                decisions_path=self.decisions,
                repo_map_path=self.repo_map,
                package_root=self.package,
                output_replay=self.root / "must-not-exist.json",
            )

        self.assertEqual(raised.exception.code, "decision_invalid")

    def test_all_configured_paths_are_gated_before_reading(self) -> None:
        baseline = {
            "tasks_path": self.tasks,
            "decisions_path": self.decisions,
            "repo_map_path": self.repo_map,
            "package_root": self.package,
            "output_replay": self.root / "safe-output.json",
        }
        for argument in baseline:
            configured = dict(baseline)
            configured[argument] = self.root / "PrIvAtE" / "does-not-exist"
            with self.subTest(argument=argument):
                with self.assertRaises(LaneAReplayAuthoringError) as raised:
                    author_lane_a_replay(**configured)
                self.assertEqual(raised.exception.code, "sensitive_path")

        for component in ("GOLD.json", "selection-lock", "source_map.json"):
            with self.subTest(component=component):
                with self.assertRaises(LaneAReplayAuthoringError) as raised:
                    author_lane_a_replay(
                        **{
                            **baseline,
                            "tasks_path": self.root / component / "missing.jsonl",
                        }
                    )
                self.assertEqual(raised.exception.code, "sensitive_path")

    def test_decision_free_text_rejects_paths_uris_and_private_markers(self) -> None:
        cases = (
            ("project", r"C:\secret\project"),
            ("vuln_title", "/etc/passwd"),
            ("vuln_category_l1", "file:///tmp/input"),
            ("vuln_category_l2", r"\\server\share\input"),
            ("project", "private metadata"),
            ("vuln_title", "gold answer"),
            ("vuln_category_l1", "selection-lock material"),
            ("vuln_category_l2", "source_map material"),
        )
        original = json.loads(self.decisions.read_text(encoding="utf-8"))
        for ordinal, (field, value) in enumerate(cases, 1):
            decision = json.loads(json.dumps(original))
            decision["tasks"][0]["semantic_judge"][field] = value
            _write_json(self.decisions, decision)
            output = self.root / f"sensitive-{ordinal}.json"
            with self.subTest(field=field, value=value):
                with self.assertRaises(LaneAReplayAuthoringError) as raised:
                    author_lane_a_replay(
                        tasks_path=self.tasks,
                        decisions_path=self.decisions,
                        repo_map_path=self.repo_map,
                        package_root=self.package,
                        output_replay=output,
                    )
                self.assertEqual(raised.exception.code, "decision_sensitive")
                self.assertFalse(output.exists())

    def test_committed_interruption_is_uncertain_then_same_bytes_recover(self) -> None:
        replay = self.root / "recoverable-replay.json"
        stderr = io.StringIO()
        real_link = os.link

        def link_then_interrupt(source: Path, target: Path) -> None:
            real_link(source, target)
            raise KeyboardInterrupt

        arguments = [
            "--tasks",
            str(self.tasks),
            "--decisions",
            str(self.decisions),
            "--repo-map",
            str(self.repo_map),
            "--package-root",
            str(self.package),
            "--output-replay",
            str(replay),
        ]
        with (
            patch(
                "scripts.author_lane_a_replay_offline.os.link",
                side_effect=link_then_interrupt,
            ),
            patch("sys.stderr", stderr),
        ):
            code = authoring_main(arguments)

        self.assertEqual(code, 11)
        self.assertEqual(json.loads(stderr.getvalue())["error_code"], "publication_uncertain")
        self.assertTrue(replay.is_file())
        committed = replay.read_bytes()

        summary = author_lane_a_replay(
            tasks_path=self.tasks,
            decisions_path=self.decisions,
            repo_map_path=self.repo_map,
            package_root=self.package,
            output_replay=replay,
        )

        self.assertEqual(summary["status"], "recovered")
        self.assertEqual(replay.read_bytes(), committed)
        self.assertTrue(summary["exact_replay_verified"])

    def test_existing_different_output_is_not_replaced(self) -> None:
        replay = self.root / "existing-replay.json"
        original = b"not-the-requested-replay\n"
        replay.write_bytes(original)

        with self.assertRaises(LaneAReplayAuthoringError) as raised:
            author_lane_a_replay(
                tasks_path=self.tasks,
                decisions_path=self.decisions,
                repo_map_path=self.repo_map,
                package_root=self.package,
                output_replay=replay,
            )

        self.assertEqual(raised.exception.code, "output_exists")
        self.assertEqual(replay.read_bytes(), original)

    def test_repair_requires_a_t1_suggested_fix(self) -> None:
        decision = TaskDecision(
            task_id=TASK_ID,
            critical_mode="sink",
            critical_candidate_ordinal=1,
            entry_candidate_ordinal=1,
            project="example-project",
            vuln_title="Unsafe evaluation",
            vuln_category_l1="Injection",
            vuln_category_l2="Code Injection",
            reflection_action="emit",
            repairs=(RepairDecision(1, ("vuln_title",), "emit"),),
        )
        backend = DecisionAuthoringBackend({TASK_ID: decision})
        request = ModelRequest(
            task_id=TASK_ID,
            attempt=1,
            policy_scope="t2.repair-1",
            stage="repair",
            model_call_id="MODEL-repair",
            backend_id="exact-replay",
            model_id="offline-v1",
            payload={
                "repair_fields": [
                    {
                        "field": "vuln_title",
                        "has_suggested_fix": False,
                        "suggested_fix": None,
                    }
                ]
            },
        )

        with self.assertRaises(LaneAReplayAuthoringError) as raised:
            backend.invoke(request)
        self.assertEqual(raised.exception.code, "repair_not_authorized")
        self.assertEqual(backend.fixtures, ())


if __name__ == "__main__":
    unittest.main()
