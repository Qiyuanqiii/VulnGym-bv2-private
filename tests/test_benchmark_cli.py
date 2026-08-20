from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import unittest
from unittest import mock

from vulngym_agent import benchmark_cli
from vulngym_agent.benchmark.harness import PublicBundleSummary


class BenchmarkCliTests(unittest.TestCase):
    def test_validate_emits_machine_readable_summary(self) -> None:
        summary = PublicBundleSummary(
            profile_id="vulngym-50-20-v1",
            schema_version="1.0.0",
            source_revision="c" * 40,
            manifest_sha256="d" * 64,
            train_tasks=50,
            test_tasks=20,
            train_advisories=51,
            train_entries=125,
        )
        output = StringIO()
        with mock.patch.object(
            benchmark_cli, "validate_public_bundle", return_value=summary
        ) as validate, redirect_stdout(output):
            status = benchmark_cli.main(
                ["validate", "--benchmark-root", "public-bundle"]
            )
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue()), summary.to_dict())
        validate.assert_called_once()

    def test_project_commands_require_attested_index_and_dispatch_split(self) -> None:
        for command, split in (("project-train", "train"), ("project-test", "test")):
            summary = mock.Mock()
            summary.to_dict.return_value = {"split": split}
            output = StringIO()
            with mock.patch.object(
                benchmark_cli,
                "project_verified_replay_bundles",
                return_value=summary,
            ) as project, redirect_stdout(output):
                status = benchmark_cli.main(
                    [
                        command,
                        "--benchmark-root",
                        "benchmark",
                        "--artifact-root",
                        "artifacts",
                        "--bundle-index",
                        "index.json",
                        "--bundle-index-sha256",
                        "a" * 64,
                        "--output-dir",
                        "output",
                    ]
                )
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(output.getvalue()), {"split": split})
            self.assertEqual(project.call_args.kwargs["split"], split)
            self.assertEqual(project.call_args.kwargs["top_k"], 64)

    def test_os_errors_do_not_echo_absolute_paths(self) -> None:
        secret = r"D:\sensitive\private\gold.jsonl"
        error = StringIO()
        with mock.patch.object(
            benchmark_cli,
            "project_verified_replay_bundles",
            side_effect=OSError(secret),
        ), redirect_stderr(error):
            status = benchmark_cli.main(
                [
                    "project-test",
                    "--benchmark-root",
                    "benchmark",
                    "--artifact-root",
                    "artifacts",
                    "--bundle-index",
                    "index.json",
                    "--bundle-index-sha256",
                    "a" * 64,
                    "--output-dir",
                    "output",
                ]
            )
        self.assertEqual(status, 2)
        self.assertNotIn(secret, error.getvalue())
        self.assertNotIn("Traceback", error.getvalue())


if __name__ == "__main__":
    unittest.main()
