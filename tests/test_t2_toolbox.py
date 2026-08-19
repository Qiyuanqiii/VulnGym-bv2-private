from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from vulngym_agent.adapters.schema_adapter import ORIGIN
from vulngym_agent.agents.t2_inputs import T2TaskInputV1
from vulngym_agent.agents.t2_toolbox import LOCAL_T2_TOOL_NAMES, LocalT2Toolbox
from vulngym_agent.orchestrator import Budget, Limits, RunTask
from vulngym_agent.orchestrator.repair_plan import (
    REPAIR_TOOL_POLICY_VERSION,
    SAFE_REPAIR_TOOL_REGISTRY,
)
from vulngym_agent.tools import ArtifactRef, AttemptToolRuntime, ToolReferenceError
from vulngym_agent.tools.git import TextFileDiff


REPORT_ID = "GHSA-1111-2222-3333"
REPO_URL = "https://github.com/example/project"
SOURCE_PATH = "src/app.py"


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


class LocalT2ToolboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repo"
        self.package_root = self.root / "package"
        (self.repository / "src").mkdir(parents=True)
        (self.package_root / "advisories").mkdir(parents=True)
        (self.package_root / "patches").mkdir(parents=True)
        _git(self.repository, "init", "--quiet")
        _git(self.repository, "config", "user.name", "VulnGym Test")
        _git(self.repository, "config", "user.email", "test@example.invalid")

        vulnerable_text = (
            "def dangerous(user):\n"
            "    return eval(user)\n"
            "\n"
            "@app.route('/run')\n"
            "def public_route(request):\n"
            "    return dangerous(request)\n"
        )
        (self.repository / SOURCE_PATH).write_text(vulnerable_text, encoding="utf-8")
        _git(self.repository, "add", "--", SOURCE_PATH)
        _git(self.repository, "commit", "--quiet", "-m", "vulnerable")
        self.vulnerable = _git(self.repository, "rev-parse", "HEAD")

        fixed_text = (
            "def dangerous(user):\n"
            "    if not user.isdigit():\n"
            "        return None\n"
            "    return int(user)\n"
            "\n"
            "@app.route('/run')\n"
            "def public_route(request):\n"
            "    return dangerous(request)\n"
        )
        (self.repository / SOURCE_PATH).write_text(fixed_text, encoding="utf-8")
        _git(self.repository, "add", "--", SOURCE_PATH)
        _git(self.repository, "commit", "--quiet", "-m", "fix")
        self.fix = _git(self.repository, "rev-parse", "HEAD")

        patch = _git(
            self.repository, "diff", "--no-ext-diff", self.vulnerable, self.fix, "--", SOURCE_PATH
        )
        (self.package_root / "patches" / "fix.patch").write_text(
            patch + "\n", encoding="utf-8"
        )
        advisory = {
            "ghsa_id": REPORT_ID,
            "cve": "CVE-2026-12345",
            "fix_commit": self.fix,
            "source_link": f"https://github.com/advisories/{REPORT_ID}",
        }
        (self.package_root / "advisories" / "item.json").write_text(
            json.dumps(advisory), encoding="utf-8"
        )

        inputs = {
            "contract_version": 1,
            "input_line": 1,
            "repo_url": REPO_URL,
            "package": {
                "advisory": "advisories/item.json",
                "references": [],
                "patches": ["patches/fix.patch"],
            },
            "hints": {
                "project": "project",
                "fix_commits": [self.fix],
                "source_paths": [SOURCE_PATH],
                "entry_symbols": ["public_route", "dangerous"],
                "critical_mode": "sink",
            },
        }
        self.task = RunTask(
            task_id="task:t2-toolbox",
            report_id=REPORT_ID,
            entry_id="entry-00001",
            inputs=inputs,
        )
        parsed = T2TaskInputV1.from_task(self.task)
        self.toolbox = LocalT2Toolbox(
            self.task, parsed, self.package_root, self.repository
        )
        self.runtime = AttemptToolRuntime(
            task_id=self.task.task_id,
            attempt=0,
            policy_scope="t2.initial",
            budget=Budget(Limits(max_tool_calls=40)),
            registry=self.toolbox.registry,
            allowlist=self.toolbox.tool_names,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def call(self, number: int, name: str, arguments=None):
        return self.runtime.call(f"TOOL-{number:05d}", name, arguments or {})

    def test_registry_is_fixed_and_only_contains_policy_tools(self) -> None:
        self.assertEqual(tuple(self.toolbox.registry), LOCAL_T2_TOOL_NAMES)
        self.assertLessEqual(
            self.toolbox.tool_names,
            SAFE_REPAIR_TOOL_REGISTRY[REPAIR_TOOL_POLICY_VERSION],
        )
        with self.assertRaises(TypeError):
            self.toolbox.registry["shell"] = object()  # type: ignore[index]

    def test_true_offline_chain_and_portable_artifacts(self) -> None:
        advisory = self.call(1, "read_local_advisory")
        self.assertEqual(advisory.status, "success")
        facts = self.call(
            2,
            "extract_advisory_fields",
            {"advisory": advisory.artifact_refs[0]},
        )
        self.assertEqual(facts.status, "success")
        self.assertIn(self.fix, facts.output["fix_commits"])

        local_patch = self.call(
            3, "read_local_patch", {"path": "patches/fix.patch"}
        )
        self.assertEqual(local_patch.status, "success")

        repo = self.call(4, "resolve_local_repo", {"repo_url": REPO_URL})
        repo_ref = repo.artifact_refs[0]
        parents = self.call(
            5, "git_parents", {"repo": repo_ref, "commit": self.fix}
        )
        self.assertEqual(parents.output["parents"], (self.vulnerable,))
        blob = self.call(
            6,
            "git_show",
            {"repo": repo_ref, "commit": self.vulnerable, "path": SOURCE_PATH},
        )
        self.assertEqual(blob.status, "success")
        ancestry = self.call(
            7,
            "version_ancestry",
            {
                "repo": repo_ref,
                "ancestor": self.vulnerable,
                "descendant": self.fix,
            },
        )
        self.assertIs(ancestry.output["is_ancestor"], True)
        diff = self.call(
            8,
            "git_diff",
            {
                "repo": repo_ref,
                "before_commit": self.vulnerable,
                "after_commit": self.fix,
                "path": SOURCE_PATH,
            },
        )
        self.assertIs(diff.output["changed"], True)
        critical = self.call(
            9,
            "dataflow_candidate_search",
            {"repo": repo_ref, "diff": diff.artifact_refs[0], "mode": "sink"},
        )
        self.assertEqual(critical.status, "success")
        self.assertGreaterEqual(critical.output["candidate_count"], 1)
        self.assertTrue(critical.output["provisional_candidate_ids"])
        self.assertIs(critical.output["semantic_role_verified"], False)

        routes = self.call(
            10,
            "route_recognition",
            {
                "repo": repo_ref,
                "commit": self.vulnerable,
                "critical_paths": [SOURCE_PATH],
                "critical_symbols": ["dangerous"],
            },
        )
        self.assertEqual(routes.status, "success")
        self.assertEqual(routes.output["selected_paths"], (SOURCE_PATH,))
        self.assertGreaterEqual(routes.output["candidate_count"], 1)

        candidate = {
            "commit": self.vulnerable,
            "critical_operation": {
                "code": "return eval(user)",
                "file": SOURCE_PATH,
                "line": 2,
            },
            "entry_id": "entry-00001",
            "entry_point": {
                "code": "def public_route(request):",
                "file": SOURCE_PATH,
                "line": 5,
            },
            "origin": ORIGIN,
            "project": "project",
            "repo_url": REPO_URL,
            "report_id": REPORT_ID,
            "source_link": f"https://github.com/advisories/{REPORT_ID}",
            "trace": [],
            "verify": 0,
            "vuln_category_l1": "Injection",
            "vuln_category_l2": "Code Injection",
            "vuln_ids": ["CVE-2026-12345", REPORT_ID],
            "vuln_title": "Unsafe evaluation",
        }
        schema = self.call(11, "validate_schema", {"candidate": candidate})
        self.assertEqual(schema.status, "success")
        self.assertIs(schema.output["valid"], True)

        transcript = self.runtime.finalize()
        encoded = json.dumps(transcript.to_dict(), ensure_ascii=False)
        self.assertNotIn(str(self.package_root), encoded)
        self.assertNotIn(str(self.repository), encoded)
        self.assertNotIn("package_root", encoded)
        self.assertNotIn("repo_path", encoded)

    def test_extract_requires_a_runtime_issued_loaded_advisory(self) -> None:
        result = self.call(
            1, "extract_advisory_fields", {"advisory": "ART-not-loaded"}
        )
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.error_code, "invalid_artifact_reference")

        advisory = self.call(2, "read_local_advisory")
        issued = advisory.artifact_refs[0]
        equal_but_forged = ArtifactRef(**issued.to_dict())
        calls_before = len(self.runtime.records)
        with self.assertRaises(ToolReferenceError):
            self.runtime.call(
                "TOOL-00003",
                "extract_advisory_fields",
                {"advisory": equal_but_forged},
            )
        self.assertEqual(len(self.runtime.records), calls_before)

    def test_evidence_text_is_not_rewritten_behind_its_digest(self) -> None:
        advisory_path = self.package_root / "advisories" / "item.json"
        advisory_text = json.dumps(
            {
                "ghsa_id": REPORT_ID,
                "fix_commit": self.fix,
                "source_link": f"https://github.com/advisories/{REPORT_ID}",
                "description": f"literal source text: {self.repository}",
            }
        )
        advisory_path.write_text(advisory_text, encoding="utf-8")

        result = self.call(1, "read_local_advisory")
        artifact = self.runtime.resolve_artifact(result.artifact_refs[0])
        self.assertEqual(artifact.payload["text"], advisory_text)
        self.assertEqual(
            artifact.payload["sha256"],
            hashlib.sha256(advisory_text.encode("utf-8")).hexdigest(),
        )

    def test_patch_and_source_authority_cannot_be_expanded(self) -> None:
        undeclared = self.call(
            1, "read_local_patch", {"path": "patches/not-declared.patch"}
        )
        self.assertEqual(undeclared.status, "blocked")
        self.assertEqual(undeclared.error_code, "patch_not_declared")

        repo = self.call(2, "resolve_local_repo", {"repo_url": REPO_URL})
        escaped = self.call(
            3,
            "git_show",
            {"repo": repo.artifact_refs[0], "commit": self.fix, "path": "../secret"},
        )
        self.assertEqual(escaped.status, "blocked")
        self.assertEqual(escaped.error_code, "invalid_source_path")
        not_allowed = self.call(
            4,
            "git_diff",
            {
                "repo": repo.artifact_refs[0],
                "before_commit": self.vulnerable,
                "after_commit": self.fix,
                "path": "README.md",
            },
        )
        self.assertEqual(not_allowed.status, "blocked")
        self.assertEqual(not_allowed.error_code, "source_path_not_allowed")
        encoded = json.dumps(
            [record.to_dict() for record in self.runtime.records],
            ensure_ascii=False,
        )
        self.assertNotIn(str(self.package_root), encoded)
        self.assertNotIn(str(self.repository), encoded)

    def test_dataflow_has_no_forged_diff_or_candidate_input(self) -> None:
        repo = self.call(1, "resolve_local_repo", {"repo_url": REPO_URL})
        forged = TextFileDiff(
            before_commit=self.vulnerable,
            after_commit=self.fix,
            path=SOURCE_PATH,
            before_exists=True,
            after_exists=True,
            before_blob_id="a" * 40,
            after_blob_id="b" * 40,
            added_lines=0,
            deleted_lines=1,
            unified_diff="-    return eval(user)\n",
        )
        with self.assertRaisesRegex(ValueError, "unsupported type"):
            self.runtime.call(
                "TOOL-00002",
                "dataflow_candidate_search",
                {"repo": repo.artifact_refs[0], "diff": forged, "mode": "sink"},
            )
        result = self.call(
            3,
            "dataflow_candidate_search",
            {
                "repo": repo.artifact_refs[0],
                "unified_diff": "- return eval(user)",
                "candidates": [{"file": SOURCE_PATH, "line": 2}],
                "mode": "sink",
            },
        )
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.error_code, "invalid_arguments")


if __name__ == "__main__":
    unittest.main()
