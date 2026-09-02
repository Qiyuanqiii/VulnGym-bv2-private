from __future__ import annotations

from collections import Counter
from pathlib import Path
import tempfile
import unittest

from scripts.author_replay_batch_offline import (
    _build_d2_response,
    _build_d3_response,
    _nodes,
    _scan_tree_for_plan,
    TaskPlan,
)


class OfflineAuthoringHelperTests(unittest.TestCase):
    def test_catalog_tuple_nodes_are_visible_to_d2_builder(self) -> None:
        plan = TaskPlan(
            task_id="VG-TEST-0123456789ABCDEF0123",
            split="test",
            target_path="src/app.ts",
            target_index=0,
            inventory_cursor=0,
            critical_line=2,
            critical_query="execPromise",
            critical_token="execPromise",
            entry_line=1,
            entry_token="run",
            relation_line=2,
            relation_token="run",
            score=1,
        )
        payload = {
            "allowed_actions": ("inventory", "search", "read", "advance"),
            "phase": "SCOUT",
            "catalog": {
                "nodes": (
                    {
                        "type": "FIL",
                        "path": "src/app.ts",
                        "ref": {"artifact_id": "ART-inv", "node_id": "FIL-1"},
                    },
                )
            },
        }

        self.assertEqual(1, len(_nodes(payload, "FIL")))
        self.assertEqual(
            {
                "action": "search",
                "cursor": 0,
                "files": [{"artifact_id": "ART-inv", "node_id": "FIL-1"}],
                "limit": 8,
                "query": "execPromise",
            },
            _build_d2_response(payload, plan),
        )

    def test_d3_builder_accepts_tuple_contexts_and_nodes(self) -> None:
        payload = {
            "contexts": (
                {
                    "candidate_id": "VGC-1",
                    "nodes": (
                        {"role": "entry_role", "artifact_id": "ART", "node_id": "LOC-entry"},
                        {"role": "critical_role", "artifact_id": "ART", "node_id": "LOC-critical"},
                        {"role": "trace.001", "artifact_id": "ART", "node_id": "LOC-trace"},
                    ),
                },
            ),
            "request": {
                "criteria": (
                    "entry_role",
                    "critical_role",
                    "trace_continuity",
                    "counterevidence_status",
                )
            },
        }

        response = _build_d3_response(payload)
        self.assertEqual("VGC-1", response["reviews"][0]["candidate_id"])
        self.assertTrue(
            all(item["assessment"] == "supported" for item in response["reviews"][0]["criteria"])
        )

    def test_scan_prefers_actual_call_over_import_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            path = tree / "packages" / "nodes-base" / "nodes" / "ExecuteCommand" / "ExecuteCommand.node.ts"
            path.parent.mkdir(parents=True)
            path.write_text(
                "\n".join(
                    [
                        "import { exec } from 'child_process';",
                        "const execPromise = promisify(exec);",
                        "export async function run(command: string) {",
                        "  return execPromise(command);",
                        "}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            inventory = [path.relative_to(tree).as_posix()]

            plan = _scan_tree_for_plan(
                task_id="VG-TEST-0123456789ABCDEF0123",
                split="test",
                repo_url="https://github.com/n8n-io/n8n",
                tree=tree,
                inventory=inventory,
                training_hints={"https://github.com/n8n-io/n8n": Counter()},
            )

        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertNotEqual(1, plan.critical_line)
        self.assertEqual("execPromise", plan.critical_query)


if __name__ == "__main__":
    unittest.main()
