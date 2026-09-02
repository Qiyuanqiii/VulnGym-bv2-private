from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import vulngym_agent.lane_a_task_bundle as lane
import vulngym_agent.lane_a_task_bundle_cli as lane_cli

from vulngym_agent.agents.t2_inputs import T2TaskInputV2
from vulngym_agent.lane_a_task_bundle import (
    LaneATaskBundleError,
    compute_lane_a_input_pins,
    verify_lane_a_task_bundle,
    write_lane_a_task_bundle,
)


def _line(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


class LaneATaskBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.public = self.root / "public.jsonl"
        self.assignments = self.root / "assignments.jsonl"
        self.tasks = [
            {
                "commit": character * 40,
                "instruction_id": "vulngym-whitebox-locate-v1",
                "repo_url": f"https://github.com/example/repo{index}",
                "split": "test",
                "task_id": f"VG-TEST-{index:020X}",
            }
            for index, character in ((1, "a"), (2, "b"))
        ]
        self.rows = [
            {
                "entry_id": f"entry-{index:05d}",
                "hints": {
                    "critical_mode": "auto",
                    "entry_symbols": [f"handler{index}"],
                    "fix_commits": [],
                    "project": f"project{index}",
                    "source_paths": [f"src/file{index}.py"],
                },
                "package": {
                    "advisory": f"advisory/item{index}.json",
                    "patches": [f"patches/item{index}.patch"],
                    "references": [],
                },
                "report_id": f"GHSA-AAAA-BBBB-{index:04d}",
                "task_id": self.tasks[index - 1]["task_id"],
            }
            for index in (1, 2)
        ]
        self._write_inputs()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_inputs(self) -> None:
        self.public.write_bytes(b"".join(_line(item) for item in self.tasks))
        self.assignments.write_bytes(b"".join(_line(item) for item in self.rows))

    def _kwargs(self) -> dict[str, object]:
        pins = compute_lane_a_input_pins(self.public, self.assignments)
        return {
            "expected_public_tasks_sha256": pins["public_tasks_sha256"],
            "expected_public_tasks_wire_sha256": pins["public_tasks_wire_sha256"],
            "expected_assignments_sha256": pins["assignments_sha256"],
            "expected_assignments_wire_sha256": pins["assignments_wire_sha256"],
            "expected_task_count": pins["task_count"],
        }

    def _cli_build_argv(self, output: Path) -> list[str]:
        kwargs = self._kwargs()
        return [
            "build",
            "--public-tasks-file", str(self.public),
            "--assignments-file", str(self.assignments),
            "--expected-public-tasks-sha256", str(kwargs["expected_public_tasks_sha256"]),
            "--expected-public-tasks-wire-sha256", str(kwargs["expected_public_tasks_wire_sha256"]),
            "--expected-assignments-sha256", str(kwargs["expected_assignments_sha256"]),
            "--expected-assignments-wire-sha256", str(kwargs["expected_assignments_wire_sha256"]),
            "--expected-task-count", "2",
            "--output-dir", str(output),
        ]

    def test_build_and_independent_verify(self) -> None:
        output = self.root / "bundle"
        kwargs = self._kwargs()
        manifest = write_lane_a_task_bundle(output, self.public, self.assignments, **kwargs)
        lines = (output / "run_tasks.jsonl").read_bytes().splitlines()
        self.assertEqual(len(lines), 2)
        for task, payload in zip(self.tasks, lines, strict=True):
            value = json.loads(payload)
            parsed = T2TaskInputV2.from_task(__import__(
                "vulngym_agent.orchestrator.contracts", fromlist=["RunTask"]
            ).RunTask.from_dict(value))
            self.assertEqual(parsed.expected_vulnerable_commit, task["commit"])
        result = verify_lane_a_task_bundle(
            output,
            self.public,
            self.assignments,
            expected_bundle_sha256=manifest.bundle_sha256,
            expected_manifest_wire_sha256=manifest.wire_sha256,
            **kwargs,
        )
        self.assertEqual(result.manifest.task_count, 2)
        data = json.loads((output / "manifest.json").read_bytes())
        self.assertEqual([item["task_id"] for item in data["tasks"]], [item["task_id"] for item in self.tasks])
        self.assertTrue(all("public_task_sha256" in item for item in data["tasks"]))

    def test_assignment_must_match_same_public_row(self) -> None:
        self.rows.reverse()
        self._write_inputs()
        pins = compute_lane_a_input_pins
        with self.assertRaises(LaneATaskBundleError) as caught:
            pins(self.public, self.assignments)
        self.assertEqual(caught.exception.code, "assignment_order_mismatch")

    def test_external_count_and_pins_fail_closed(self) -> None:
        kwargs = self._kwargs()
        kwargs["expected_task_count"] = 1
        with self.assertRaises(LaneATaskBundleError) as caught:
            write_lane_a_task_bundle(self.root / "bundle", self.public, self.assignments, **kwargs)
        self.assertEqual(caught.exception.code, "count_mismatch")
        self.assertFalse((self.root / "bundle").exists())

    def test_assignment_cannot_override_source_or_contain_private_path(self) -> None:
        kwargs = self._kwargs()
        self.rows[0]["repo_url"] = self.tasks[0]["repo_url"]
        self._write_inputs()
        with self.assertRaises(LaneATaskBundleError) as caught:
            write_lane_a_task_bundle(self.root / "bundle", self.public, self.assignments, **kwargs)
        self.assertIn(caught.exception.code, {"assignment_wire_mismatch", "assignment_fields", "input_changed"})

        del self.rows[0]["repo_url"]
        self.rows[0]["package"]["advisory"] = "private/item.json"
        self._write_inputs()
        with self.assertRaises(LaneATaskBundleError) as caught:
            compute_lane_a_input_pins(self.public, self.assignments)
        self.assertEqual(caught.exception.code, "sensitive_value")

    def test_no_replace_and_tamper_detection(self) -> None:
        output = self.root / "bundle"
        output.mkdir()
        marker = output / "owner.txt"
        marker.write_text("owner", encoding="utf-8")
        with self.assertRaises(LaneATaskBundleError):
            write_lane_a_task_bundle(output, self.public, self.assignments, **self._kwargs())
        self.assertEqual(marker.read_text(encoding="utf-8"), "owner")

        output2 = self.root / "bundle2"
        kwargs = self._kwargs()
        manifest = write_lane_a_task_bundle(output2, self.public, self.assignments, **kwargs)
        data = bytearray((output2 / "run_tasks.jsonl").read_bytes())
        data[data.index(b"repo1")] = ord("x")
        (output2 / "run_tasks.jsonl").write_bytes(data)
        with self.assertRaises(LaneATaskBundleError):
            verify_lane_a_task_bundle(
                output2, self.public, self.assignments,
                expected_bundle_sha256=manifest.bundle_sha256,
                expected_manifest_wire_sha256=manifest.wire_sha256,
                **kwargs,
            )

    def test_cli_success_is_path_free(self) -> None:
        kwargs = self._kwargs()
        command = [
            sys.executable, "-m", "vulngym_agent.lane_a_task_bundle_cli", "build",
            "--public-tasks-file", str(self.public), "--assignments-file", str(self.assignments),
            "--expected-public-tasks-sha256", str(kwargs["expected_public_tasks_sha256"]),
            "--expected-public-tasks-wire-sha256", str(kwargs["expected_public_tasks_wire_sha256"]),
            "--expected-assignments-sha256", str(kwargs["expected_assignments_sha256"]),
            "--expected-assignments-wire-sha256", str(kwargs["expected_assignments_wire_sha256"]),
            "--expected-task-count", "2", "--output-dir", str(self.root / "cli-bundle"),
        ]
        result = subprocess.run(command, cwd=Path(__file__).parents[1], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertNotIn(str(self.root), result.stdout)
        self.assertEqual(json.loads(result.stdout)["task_count"], 2)

    def test_committed_rename_confirmation_exception_is_recovered(self) -> None:
        output = self.root / "bundle"
        original = lane._rename_noreplace
        def committed_then_raise(source, destination, **kwargs):
            original(source, destination, **kwargs)
            raise OSError("synthetic confirmation loss")
        with mock.patch.object(lane, "_rename_noreplace", committed_then_raise):
            manifest = write_lane_a_task_bundle(output, self.public, self.assignments, **self._kwargs())
        self.assertEqual(manifest.task_count, 2)

    def test_precommit_failure_preserves_owned_staging(self) -> None:
        output = self.root / "bundle"
        with mock.patch.object(lane, "_parse_bundle", side_effect=LaneATaskBundleError("synthetic", "failure")):
            with self.assertRaises(LaneATaskBundleError) as caught:
                write_lane_a_task_bundle(output, self.public, self.assignments, **self._kwargs())
        self.assertEqual(caught.exception.code, "synthetic")
        stages = list(self.root.glob(".bundle.lane-a-*"))
        self.assertEqual(len(stages), 1)
        self.assertEqual({item.name for item in stages[0].iterdir()}, lane.LANE_A_BUNDLE_FILES)

    def test_failure_preserves_replaced_file_and_original_error(self) -> None:
        output = self.root / "bundle"
        original = lane._parse_bundle
        changed = False
        def replace_then_fail(payloads, **kwargs):
            nonlocal changed
            stages = list(self.root.glob(".bundle.lane-a-*"))
            if stages and not changed:
                changed = True
                target = stages[0] / lane.LANE_A_RUN_TASKS_FILENAME
                target.unlink()
                target.write_bytes(b"caller-owned\n")
                raise LaneATaskBundleError("synthetic", "failure")
            return original(payloads, **kwargs)
        with mock.patch.object(lane, "_parse_bundle", side_effect=replace_then_fail):
            with self.assertRaises(LaneATaskBundleError) as caught:
                write_lane_a_task_bundle(output, self.public, self.assignments, **self._kwargs())
        self.assertEqual(caught.exception.code, "synthetic")
        stages = list(self.root.glob(".bundle.lane-a-*"))
        self.assertEqual(len(stages), 1)
        self.assertEqual((stages[0] / lane.LANE_A_RUN_TASKS_FILENAME).read_bytes(), b"caller-owned\n")

    def test_precommit_interrupt_is_not_masked_and_staging_is_preserved(self) -> None:
        output = self.root / "bundle"
        changed = False

        def replace_then_interrupt(_payloads, **_kwargs):
            nonlocal changed
            stages = list(self.root.glob(".bundle.lane-a-*"))
            if stages and not changed:
                changed = True
                target = stages[0] / lane.LANE_A_RUN_TASKS_FILENAME
                target.unlink()
                target.write_bytes(b"caller-owned\n")
                raise KeyboardInterrupt()
            raise AssertionError("unexpected parse retry")

        with mock.patch.object(lane, "_parse_bundle", side_effect=replace_then_interrupt):
            with self.assertRaises(KeyboardInterrupt):
                write_lane_a_task_bundle(
                    output, self.public, self.assignments, **self._kwargs()
                )
        stages = list(self.root.glob(".bundle.lane-a-*"))
        self.assertEqual(len(stages), 1)
        self.assertEqual(
            (stages[0] / lane.LANE_A_RUN_TASKS_FILENAME).read_bytes(),
            b"caller-owned\n",
        )

    def test_identity_containment_catches_text_alias_bypass(self) -> None:
        inputs = lane._load_inputs(self.public, self.assignments, **self._kwargs())
        output = self.root / "bundle"
        with mock.patch.object(lane, "paths_overlap_v1", return_value=False):
            with self.assertRaises(LaneATaskBundleError) as caught:
                lane._assert_output_disjoint(output, inputs, [self.root])
        self.assertEqual(caught.exception.code, "path_overlap")

    def test_parent_swap_after_disjoint_check_cannot_pollute_protected_object(self) -> None:
        parent = self.root / "safe-parent"
        parent.mkdir()
        output = parent / "bundle"
        protected = self.root / "protected"
        protected.mkdir()
        protected_identity = lane._directory_identity(os.lstat(protected))
        moved = self.root / "moved-safe-parent"
        original = lane._publish

        def swap_then_publish(output_dir, payloads, expected, **kwargs):
            os.rename(parent, moved)
            os.rename(protected, parent)
            return original(output_dir, payloads, expected, **kwargs)

        with mock.patch.object(lane, "_publish", side_effect=swap_then_publish):
            with self.assertRaises(LaneATaskBundleError) as caught:
                write_lane_a_task_bundle(
                    output,
                    self.public,
                    self.assignments,
                    protected_paths=[protected],
                    **self._kwargs(),
                )
        self.assertEqual(caught.exception.code, "input_changed")
        self.assertEqual(
            lane._directory_identity(os.lstat(parent)), protected_identity
        )
        self.assertFalse(output.exists())

    def test_cli_postpublication_output_failures_are_committed_uncertain(self) -> None:
        failures = (KeyboardInterrupt(), SystemExit(7), BrokenPipeError("closed"))
        for index, failure in enumerate(failures, 1):
            with self.subTest(failure=type(failure).__name__):
                output = self.root / f"post-publication-{index}"
                with (
                    mock.patch.object(lane_cli, "_write_stdout", side_effect=failure),
                    mock.patch.object(lane_cli, "_write_error") as write_error,
                ):
                    status = lane_cli.main(self._cli_build_argv(output))
                self.assertEqual(status, lane_cli.EXIT_COMMITTED_UNCERTAIN)
                self.assertTrue((output / lane.LANE_A_MANIFEST_FILENAME).is_file())
                self.assertTrue(write_error.call_args.kwargs["committed"])

    def test_cli_precommit_interrupt_is_rejected(self) -> None:
        output = self.root / "precommit-interrupt"
        with (
            mock.patch.object(
                lane_cli, "write_lane_a_task_bundle", side_effect=KeyboardInterrupt()
            ),
            mock.patch.object(lane_cli, "_write_error") as write_error,
        ):
            status = lane_cli.main(self._cli_build_argv(output))
        self.assertEqual(status, lane_cli.EXIT_REJECTED)
        self.assertFalse(output.exists())
        self.assertFalse(write_error.call_args.kwargs["committed"])

    def test_postcommit_resource_close_interrupt_is_committed_uncertain(self) -> None:
        output = self.root / "close-interrupt"
        if os.name == "nt":
            original = lane._close_windows_handle

            def close_then_interrupt(handle):
                original(handle)
                raise KeyboardInterrupt()

            target = "_close_windows_handle"
        else:
            original = lane._close_publication_descriptor
            interrupted = False

            def close_then_interrupt(descriptor):
                nonlocal interrupted
                original(descriptor)
                if not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt()

            target = "_close_publication_descriptor"
        with mock.patch.object(lane, target, side_effect=close_then_interrupt):
            with self.assertRaises(LaneATaskBundleError) as caught:
                write_lane_a_task_bundle(
                    output, self.public, self.assignments, **self._kwargs()
                )
        self.assertEqual(caught.exception.code, "publication_uncertain")
        self.assertTrue(caught.exception.committed)
        self.assertTrue((output / lane.LANE_A_MANIFEST_FILENAME).is_file())

    @unittest.skipUnless(os.name == "posix", "descriptor-relative parent race is POSIX-specific")
    def test_parent_swap_cannot_redirect_publication(self) -> None:
        parent = self.root / "parent"
        parent.mkdir()
        output = parent / "bundle"
        moved = self.root / "moved-parent"
        original = lane._rename_noreplace
        def swap_parent(source, destination, **kwargs):
            os.rename(parent, moved)
            parent.mkdir()
            original(source, destination, **kwargs)
        with mock.patch.object(lane, "_rename_noreplace", side_effect=swap_parent):
            with self.assertRaises(LaneATaskBundleError) as caught:
                write_lane_a_task_bundle(output, self.public, self.assignments, **self._kwargs())
        self.assertTrue(caught.exception.committed)
        self.assertFalse(output.exists())
        self.assertTrue((moved / "bundle").exists())

    @unittest.skipUnless(os.name == "nt", "Windows directory-lock regression")
    def test_windows_parent_swap_is_blocked_before_rename(self) -> None:
        parent = self.root / "parent"
        parent.mkdir()
        output = parent / "bundle"
        moved = self.root / "moved-parent"
        def swap_parent(_source, _destination, **_kwargs):
            os.rename(parent, moved)
        with mock.patch.object(lane, "_rename_noreplace", side_effect=swap_parent):
            with self.assertRaises(LaneATaskBundleError):
                write_lane_a_task_bundle(output, self.public, self.assignments, **self._kwargs())
        self.assertTrue(parent.exists())
        self.assertFalse(moved.exists())
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
