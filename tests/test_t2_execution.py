from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from vulngym_agent.adapters import ENTRY_FIELDS
from vulngym_agent.agents.model_runtime import ModelRequest
from vulngym_agent.agents.t2_execution import LocalT2ContextFactory
from vulngym_agent.orchestrator.budget import Budget, Limits
from vulngym_agent.orchestrator.contracts import RunTask
from vulngym_agent.orchestrator.repair_plan import (
    DEFAULT_FIELD_REPAIR_POLICY,
    REPAIR_TOOL_POLICY_VERSION,
    RepairInstruction,
    RepairPlan,
)
from vulngym_agent.tools.runtime import ToolNotAllowed


REPORT_ID = "GHSA-1111-2222-3333"
ENTRY_ID = "entry-00001"
REPO_URL = "https://github.com/example/project"


class _Backend:
    backend_id = "test.local"
    model_id = "test-structured-v1"

    def invoke(self, request: ModelRequest):
        return {"accepted": True, "stage": request.stage}


def _inputs(repo_url: str = REPO_URL) -> dict[str, object]:
    return {
        "contract_version": 1,
        "input_line": 7,
        "repo_url": repo_url,
        "package": {
            "advisory": "advisories/item.json",
            "references": [],
            "patches": [],
        },
        "hints": {
            "project": "project",
            "fix_commits": ["a" * 40],
            "source_paths": ["src/app.py"],
            "entry_symbols": ["public_route"],
            "critical_mode": "sink",
        },
    }


def _task(
    repo_url: str = REPO_URL,
    *,
    task_id: str = "task:t2-execution",
    report_id: str = REPORT_ID,
    entry_id: str = ENTRY_ID,
) -> RunTask:
    return RunTask(
        task_id=task_id,
        report_id=report_id,
        entry_id=entry_id,
        inputs=_inputs(repo_url),
    )


def _candidate() -> dict[str, object]:
    return {name: None for name in ENTRY_FIELDS}


def _repair_plan(task: RunTask, *, iteration: int = 1) -> RepairPlan:
    policy = DEFAULT_FIELD_REPAIR_POLICY["vuln_title"]
    instruction = RepairInstruction(
        failure_codes=("title_mismatch",),
        evidence="The title must follow the advisory.",
        evidence_refs=(),
        suggested_fix="Correct title",
        required_checks=policy.required_checks,
        # ripgrep belongs to the versioned field policy but is intentionally
        # absent from LocalT2Toolbox.  The factory must intersect it away.
        allowed_tools=("read_local_advisory", "git_show", "ripgrep"),
    )
    return RepairPlan.create(
        task_id=task.task_id,
        report_id=task.report_id,
        entry_id=task.entry_id,
        previous_candidate=_candidate(),
        validation={"report_id": task.report_id, "entry_id": task.entry_id},
        repair_iteration=iteration,
        repair_fields=("vuln_title",),
        instructions={"vuln_title": instruction},
    )


class LocalT2ContextFactoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.package_root = self.root / "PRIVATE-PACKAGE-ROOT"
        self.repository = self.root / "PRIVATE-REPOSITORY-ROOT"
        (self.package_root / "advisories").mkdir(parents=True)
        self.repository.mkdir()
        (self.package_root / "advisories" / "item.json").write_text(
            json.dumps({"ghsa_id": REPORT_ID}), encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def factory(self, repo_map=None) -> LocalT2ContextFactory:
        return LocalT2ContextFactory(
            self.package_root,
            {REPO_URL: self.repository} if repo_map is None else repo_map,
            _Backend(),
        )

    def test_constructor_snapshots_and_strictly_validates_trusted_paths(self) -> None:
        mutable_map = {REPO_URL: self.repository}
        factory = self.factory(mutable_map)
        mutable_map.clear()
        controller = factory.create(
            _task(),
            attempt=0,
            mode="generate",
            plan=None,
            budget=Budget(),
        )
        self.assertEqual(controller.task_id, "task:t2-execution")

        invalid_maps = (
            {},
            {"https://github.com/example/project/tree/main": self.repository},
            {REPO_URL: ""},
            {REPO_URL: self.package_root / "missing"},
            {
                "https://github.com/Example/Project": self.repository,
                "https://github.com/example/project": self.repository,
            },
        )
        for repo_map in invalid_maps:
            with self.subTest(repo_map=tuple(repo_map)):
                with self.assertRaises(ValueError):
                    self.factory(repo_map)

        secret_missing = self.root / "DO-NOT-LEAK-MISSING-ROOT"
        with self.assertRaises(ValueError) as raised:
            LocalT2ContextFactory(
                secret_missing,
                {REPO_URL: self.repository},
                _Backend(),
            )
        self.assertNotIn(str(secret_missing), str(raised.exception))

    def test_exact_repo_mapping_blocks_unmapped_task_without_path_leakage(self) -> None:
        factory = self.factory()
        with self.assertRaisesRegex(ValueError, "not present") as raised:
            factory.create(
                _task("https://github.com/example/another-project"),
                attempt=0,
                mode="generate",
                plan=None,
                budget=Budget(),
            )
        message = str(raised.exception)
        self.assertNotIn(str(self.package_root), message)
        self.assertNotIn(str(self.repository), message)

    def test_repair_allowlist_is_plan_union_intersected_with_local_registry(self) -> None:
        task = _task()
        controller = self.factory().create(
            task,
            attempt=1,
            mode="repair",
            plan=_repair_plan(task),
            budget=Budget(Limits(max_tool_calls=6, max_llm_calls=2)),
        )
        context = controller.producer_context

        advisory = context.call_tool("TOOL-advisory", "read_local_advisory", {})
        schema = context.call_tool(
            "TOOL-schema", "validate_schema", {"candidate": _candidate()}
        )
        self.assertEqual(advisory.status, "success")
        self.assertEqual(schema.status, "success")
        for number, disallowed in enumerate(("version_ancestry", "ripgrep"), 1):
            with self.subTest(tool=disallowed):
                with self.assertRaises(ToolNotAllowed):
                    context.call_tool(f"TOOL-denied-{number}", disallowed, {})

        projection = controller.finalize()
        self.assertEqual(
            projection.tool_names,
            ("read_local_advisory", "validate_schema"),
        )
        self.assertEqual(len(projection.tool_calls), 2)

    def test_attempt_scope_plan_binding_and_producer_capability_are_fixed(self) -> None:
        task = _task()
        controller = self.factory().create(
            task,
            attempt=2,
            mode="repair",
            plan=_repair_plan(task, iteration=2),
            budget=Budget(),
        )
        context = controller.producer_context
        self.assertEqual((context.attempt, context.mode), (2, "repair"))
        self.assertEqual(context.policy_scope, "t2.repair-2")
        self.assertFalse(hasattr(context, "budget"))
        self.assertFalse(hasattr(context, "package_root"))
        self.assertFalse(hasattr(context, "repo_path"))

        mismatches = (
            (0, "generate", _repair_plan(task)),
            (1, "repair", None),
            (2, "repair", _repair_plan(task, iteration=1)),
            (
                1,
                "repair",
                replace(_repair_plan(task), task_id="task:other"),
            ),
            (
                1,
                "repair",
                replace(_repair_plan(task), report_id="GHSA-AAAA-BBBB-CCCC"),
            ),
        )
        for attempt, mode, plan in mismatches:
            with self.subTest(attempt=attempt, mode=mode, plan=plan):
                with self.assertRaises(ValueError):
                    self.factory().create(
                        task,
                        attempt=attempt,
                        mode=mode,
                        plan=plan,
                        budget=Budget(),
                    )

        forged_policy = _repair_plan(task)
        object.__setattr__(
            forged_policy, "tool_policy_version", "repair-tools-unknown"
        )
        with self.assertRaisesRegex(ValueError, "invalid RepairPlan"):
            self.factory().create(
                task,
                attempt=1,
                mode="repair",
                plan=forged_policy,
                budget=Budget(),
            )

    def test_task_and_projection_never_contain_trusted_local_paths(self) -> None:
        task = _task()
        controller = self.factory().create(
            task,
            attempt=0,
            mode="generate",
            plan=None,
            budget=Budget(),
        )
        projection = controller.finalize()
        serialized = json.dumps(
            {"task": task.to_dict(), "projection": projection.to_dict()},
            sort_keys=True,
        )
        for secret in (str(self.package_root), str(self.repository)):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("package_root", serialized)
        self.assertNotIn("repo_path", serialized)


if __name__ == "__main__":
    unittest.main()
