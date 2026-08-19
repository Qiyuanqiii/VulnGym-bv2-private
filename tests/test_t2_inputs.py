from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from jsonschema.validators import validator_for

from vulngym_agent.agents.t2_inputs import T2TaskInputV1
from vulngym_agent.orchestrator import RunTask


ROOT = Path(__file__).resolve().parents[1]


def _inputs() -> dict[str, object]:
    return {
        "contract_version": 1,
        "input_line": 7,
        "repo_url": "https://github.com/example/project",
        "package": {
            "advisory": "advisories/GHSA-1111-2222-3333.json",
            "references": ["references/pr-1.md"],
            "patches": ["patches/fix.patch"],
        },
        "hints": {
            "project": "project",
            "fix_commits": ["a" * 40],
            "source_paths": ["src/route.py", "src/service.py"],
            "entry_symbols": ["public_route"],
            "critical_mode": "sink",
        },
    }


def _task(inputs: dict[str, object] | None = None) -> RunTask:
    return RunTask(
        task_id="task:t2-input-1",
        report_id="GHSA-1111-2222-3333",
        entry_id="entry-00001",
        inputs=_inputs() if inputs is None else inputs,
    )


class T2TaskInputTests(unittest.TestCase):
    def test_round_trip_is_strict_json_and_contains_no_local_roots(self) -> None:
        parsed = T2TaskInputV1.from_task(_task())

        self.assertEqual(parsed.to_dict(), _inputs())
        encoded = repr(parsed.to_dict())
        self.assertNotIn("package_root", encoded)
        self.assertNotIn("repo_path", encoded)
        self.assertNotIn("model_path", encoded)

    def test_task_requires_correlation_anchors_and_exact_top_level_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "require report_id and entry_id"):
            T2TaskInputV1.from_task(
                RunTask(task_id="task:no-anchor", inputs=_inputs())
            )

        value = _inputs()
        value["repo_path"] = "C:/untrusted"
        with self.assertRaisesRegex(ValueError, "extra=.*repo_path"):
            T2TaskInputV1.from_task(_task(value))

    def test_package_and_source_paths_reuse_safe_relative_contracts(self) -> None:
        cases = (
            ("package", "../outside.json"),
            ("source", "../outside.py"),
            ("source", "-c"),
            ("source", "C:/outside.py"),
        )
        for kind, malicious in cases:
            with self.subTest(kind=kind, malicious=malicious):
                value = _inputs()
                if kind == "package":
                    value["package"]["advisory"] = malicious  # type: ignore[index]
                else:
                    value["hints"]["source_paths"] = [malicious]  # type: ignore[index]
                with self.assertRaises(ValueError):
                    T2TaskInputV1.from_task(_task(value))

    def test_fix_commits_symbols_and_mode_are_bounded_and_canonical(self) -> None:
        mutations = (
            ("fix_commits", ["A" * 40]),
            ("entry_symbols", ["bad symbol"]),
            ("entry_symbols", ["x"] * 65),
            ("critical_mode", "shell"),
            ("source_paths", []),
        )
        for field, replacement in mutations:
            with self.subTest(field=field):
                value = deepcopy(_inputs())
                value["hints"][field] = replacement  # type: ignore[index]
                with self.assertRaises(ValueError):
                    T2TaskInputV1.from_task(_task(value))

        for project in (" project", "project ", "bad\x00project", "\t"):
            with self.subTest(project=project):
                value = deepcopy(_inputs())
                value["hints"]["project"] = project  # type: ignore[index]
                with self.assertRaisesRegex(ValueError, "canonical"):
                    T2TaskInputV1.from_task(_task(value))

    def test_repo_url_and_integer_types_are_canonical(self) -> None:
        for field, replacement in (
            ("repo_url", "https://github.com/example/project.git"),
            ("repo_url", "https://github.com/example/project/"),
            ("repo_url", "https://evil.example/example/project"),
            ("input_line", True),
            ("contract_version", True),
        ):
            with self.subTest(field=field):
                value = _inputs()
                value[field] = replacement
                with self.assertRaises(ValueError):
                    T2TaskInputV1.from_task(_task(value))

    def test_package_declaration_has_a_hard_file_count_bound(self) -> None:
        value = _inputs()
        value["package"]["references"] = [  # type: ignore[index]
            f"references/{index}.txt" for index in range(256)
        ]
        with self.assertRaisesRegex(ValueError, "at most 256 files"):
            T2TaskInputV1.from_task(_task(value))

        value = _inputs()
        value["package"]["advisory"] = "a" * 1025  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "1024 characters"):
            T2TaskInputV1.from_task(_task(value))

        value = _inputs()
        value["hints"]["source_paths"] = [  # type: ignore[index]
            "a" * 4097
        ]
        with self.assertRaisesRegex(ValueError, "4096 characters"):
            T2TaskInputV1.from_task(_task(value))

    def test_json_schema_matches_the_python_contract(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "t2_task.schema.json").read_text(encoding="utf-8")
        )
        validator_type = validator_for(schema)
        validator_type.check_schema(schema)
        validator = validator_type(schema)

        canonical = T2TaskInputV1.from_task(_task()).to_dict()
        self.assertEqual(list(validator.iter_errors(canonical)), [])

        for mutation in (
            {**canonical, "repo_path": "C:/untrusted"},
            {**canonical, "contract_version": True},
            {
                **canonical,
                "hints": {**canonical["hints"], "source_paths": ["../escape.py"]},
            },
        ):
            with self.subTest(mutation=mutation):
                self.assertTrue(list(validator.iter_errors(mutation)))


if __name__ == "__main__":
    unittest.main()
