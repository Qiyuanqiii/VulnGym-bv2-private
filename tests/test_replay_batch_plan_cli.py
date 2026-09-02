from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from vulngym_agent.agents.model_runtime import ReplayResponse
from vulngym_agent.benchmark.contracts import SnapshotTaskSpec
from vulngym_agent.evaluator.final_gate import (
    FINAL_GATE_PLAN_FILENAME,
    FinalGatePlanV1,
)
from vulngym_agent.evaluator.oci_worker_entry import OciReplayConfigV1
import vulngym_agent.replay_batch_plan_cli as cli


class ReplayBatchPlanCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.benchmark = self.root / "benchmark"
        self.benchmark.mkdir(mode=0o700)
        self.tasks = {
            split: self._tasks(split)
            for split in ("test", "train")
        }
        self.authoring = {
            split: self._authoring_root(split, suffix="baseline")
            for split in ("test", "train")
        }
        self.authoring_index, self.authoring_index_sha, self.authoring_index_wire_sha = (
            self._authoring_index(self.authoring)
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _tasks(split: str) -> tuple[SnapshotTaskSpec, ...]:
        count = 20 if split == "test" else 50
        prefix = split.upper()
        return tuple(
            SnapshotTaskSpec(
                task_id=f"VG-{prefix}-{index:020X}",
                repo_url=f"https://github.com/example/repo-{index}",
                commit=f"{index + 1:040x}",
                split=split,
            )
            for index in range(count)
        )

    @staticmethod
    def _pair(task_id: str) -> tuple[OciReplayConfigV1, OciReplayConfigV1]:
        result = []
        for role in ("d2", "d3"):
            result.append(
                OciReplayConfigV1(
                    task_id=task_id,
                    role=role,
                    responses=(
                        ReplayResponse(
                            stage="plan",
                            request={"role": role, "task_id": task_id},
                            response={"action": "fixture", "role": role},
                        ),
                    ),
                )
            )
        return result[0], result[1]

    @staticmethod
    def _private_file(path: Path, payload: bytes) -> None:
        path.write_bytes(payload)
        path.chmod(0o600)

    def _authoring_root(
        self, split: str, *, empty_first: bool = False, suffix: str = "fixture"
    ) -> Path:
        root = self.root / f"{split}-authoring-{suffix}-{int(empty_first)}"
        root.mkdir(mode=0o700)
        for index, task in enumerate(self.tasks[split]):
            task_root = root / task.task_id
            task_root.mkdir(mode=0o700)
            d2, d3 = self._pair(task.task_id)
            if empty_first and index == 0:
                d2 = OciReplayConfigV1(
                    task_id=task.task_id, role="d2", responses=()
                )
                d3 = OciReplayConfigV1(
                    task_id=task.task_id, role="d3", responses=()
                )
            self._private_file(task_root / "d2.json", d2.to_bytes())
            self._private_file(task_root / "d3.json", d3.to_bytes())
        return root

    def _authoring_index(
        self, roots: dict[str, Path], *, suffix: str = "baseline"
    ) -> tuple[Path, str, str]:
        tasks: list[dict[str, object]] = []
        for split in ("test", "train"):
            for task in self.tasks[split]:
                task_root = roots[split] / task.task_id
                d2 = OciReplayConfigV1.from_bytes((task_root / "d2.json").read_bytes())
                d3 = OciReplayConfigV1.from_bytes((task_root / "d3.json").read_bytes())
                tasks.append(
                    {
                        "d2_sha256": d2.config_sha256,
                        "d2_wire_sha256": d2.wire_sha256,
                        "d3_sha256": d3.config_sha256,
                        "d3_wire_sha256": d3.wire_sha256,
                        "split": split,
                        "task_id": task.task_id,
                    }
                )
        core = {
            "contract_version": 1,
            "kind": "vulngym.replay-authoring-index.v1",
            "tasks": tasks,
        }
        canonical_core = json.dumps(
            core, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        semantic = hashlib.sha256(
            b"vulngym:replay-authoring-index:v1\x00" + canonical_core
        ).hexdigest()
        value = {**core, "index_sha256": semantic}
        payload = (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        path = self.root / f"authoring-index-{suffix}.json"
        self._private_file(path, payload)
        return path, semantic, hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _index_arguments(path: Path, semantic: str, wire: str) -> tuple[object, ...]:
        return (
            "--authoring-index-file",
            path,
            "--expected-authoring-index-sha256",
            semantic,
            "--expected-authoring-index-wire-sha256",
            wire,
        )

    def _load_tasks(self, _root: Path, *, split: str):
        return self.tasks[split]

    def _invoke(self, *arguments: object) -> tuple[int, dict[str, object] | None, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                cli, "load_answer_free_tasks", side_effect=self._load_tasks
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = cli.main([str(item) for item in arguments])
        payload = stdout.getvalue()
        value = json.loads(payload) if payload else None
        return status, value, stderr.getvalue()

    @staticmethod
    def _tree_bytes(root: Path) -> dict[str, bytes]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def _build_split(self, split: str, suffix: str = "one"):
        authoring = self.authoring[split]
        output = self.root / f"{split}-batch-{suffix}"
        status, summary, error = self._invoke(
            "build-split",
            "--benchmark-root",
            self.benchmark,
            "--split",
            split,
            "--authoring-output-root",
            authoring,
            *self._index_arguments(
                self.authoring_index,
                self.authoring_index_sha,
                self.authoring_index_wire_sha,
            ),
            "--output-root",
            output,
        )
        self.assertEqual((status, error), (0, ""))
        assert summary is not None
        return output, summary

    def test_build_and_verify_split_are_reproducible_and_formal(self) -> None:
        authoring = self.authoring["test"]
        first = self.root / "test-batch-one"
        status, summary, error = self._invoke(
            "build-split",
            "--benchmark-root",
            self.benchmark,
            "--split",
            "test",
            "--authoring-output-root",
            authoring,
            *self._index_arguments(
                self.authoring_index,
                self.authoring_index_sha,
                self.authoring_index_wire_sha,
            ),
            "--output-root",
            first,
        )
        self.assertEqual((status, error), (0, ""))
        assert summary is not None
        self.assertEqual(summary["status"], "published")
        self.assertEqual(summary["formal_replay_count"], 20)
        self.assertEqual(summary["authoring_index_sha256"], self.authoring_index_sha)
        self.assertEqual(
            summary["authoring_index_wire_sha256"], self.authoring_index_wire_sha
        )
        self.assertNotIn(str(self.root), json.dumps(summary))

        verified_status, verified, verified_error = self._invoke(
            "verify-split",
            "--benchmark-root",
            self.benchmark,
            "--split",
            "test",
            "--replay-root",
            first,
            "--expected-manifest-sha256",
            summary["replay_manifest_sha256"],
            "--expected-manifest-wire-sha256",
            summary["replay_manifest_wire_sha256"],
        )
        self.assertEqual((verified_status, verified_error), (0, ""))
        assert verified is not None
        self.assertEqual(verified["status"], "verified")

        second = self.root / "test-batch-two"
        second_status, second_summary, second_error = self._invoke(
            "build-split",
            "--benchmark-root",
            self.benchmark,
            "--split",
            "test",
            "--authoring-output-root",
            authoring,
            *self._index_arguments(
                self.authoring_index,
                self.authoring_index_sha,
                self.authoring_index_wire_sha,
            ),
            "--output-root",
            second,
        )
        self.assertEqual((second_status, second_error), (0, ""))
        self.assertEqual(second_summary, summary)
        self.assertEqual(self._tree_bytes(first), self._tree_bytes(second))

    def test_empty_smoke_pair_and_extra_member_are_not_formal_inputs(self) -> None:
        empty = self._authoring_root("test", empty_first=True, suffix="empty")
        empty_index, empty_index_sha, empty_index_wire = self._authoring_index(
            {"test": empty, "train": self.authoring["train"]}, suffix="empty"
        )
        output = self.root / "rejected-empty"
        status, summary, error = self._invoke(
            "build-split",
            "--benchmark-root",
            self.benchmark,
            "--split",
            "test",
            "--authoring-output-root",
            empty,
            *self._index_arguments(empty_index, empty_index_sha, empty_index_wire),
            "--output-root",
            output,
        )
        self.assertEqual((status, summary), (2, None))
        self.assertEqual(
            error,
            "error[formal_replay_rejected]: replay batch/plan operation failed\n",
        )
        self.assertFalse(output.exists())
        self.assertNotIn(str(self.root), error)

        complete = self._authoring_root("train", suffix="extra")
        extra_index, extra_index_sha, extra_index_wire = self._authoring_index(
            {"test": self.authoring["test"], "train": complete}, suffix="extra"
        )
        (complete / "unexpected").mkdir(mode=0o700)
        extra_output = self.root / "rejected-extra"
        status, summary, error = self._invoke(
            "build-split",
            "--benchmark-root",
            self.benchmark,
            "--split",
            "train",
            "--authoring-output-root",
            complete,
            *self._index_arguments(extra_index, extra_index_sha, extra_index_wire),
            "--output-root",
            extra_output,
        )
        self.assertEqual((status, summary), (2, None))
        self.assertEqual(
            error,
            "error[layout_invalid]: replay batch/plan operation failed\n",
        )
        self.assertFalse(extra_output.exists())

    def test_build_and_verify_plan_bind_all_seventy_replays(self) -> None:
        test_root, test_summary = self._build_split("test")
        train_root, train_summary = self._build_split("train")
        image_id = "sha256:" + "c" * 64
        plan_root = self.root / "plan-one"
        arguments = (
            "--benchmark-root",
            self.benchmark,
            "--test-replay-root",
            test_root,
            "--test-replay-manifest-sha256",
            test_summary["replay_manifest_sha256"],
            "--test-replay-manifest-wire-sha256",
            test_summary["replay_manifest_wire_sha256"],
            "--train-replay-root",
            train_root,
            "--train-replay-manifest-sha256",
            train_summary["replay_manifest_sha256"],
            "--train-replay-manifest-wire-sha256",
            train_summary["replay_manifest_wire_sha256"],
            "--test-sealed-batch-manifest-sha256",
            "a" * 64,
            "--train-sealed-batch-manifest-sha256",
            "b" * 64,
            "--test-key-id",
            "test-key-v1",
            "--train-key-id",
            "train-key-v1",
            "--runtime-image-id",
            image_id,
        )
        status, summary, error = self._invoke(
            "build-plan", *arguments, "--output-root", plan_root
        )
        self.assertEqual((status, error), (0, ""))
        assert summary is not None
        self.assertEqual(summary["status"], "published")
        self.assertEqual(summary["total_task_count"], 70)
        payload = (plan_root / FINAL_GATE_PLAN_FILENAME).read_bytes()
        parsed = FinalGatePlanV1.from_bytes(
            payload,
            expected_plan_sha256=summary["plan_sha256"],
            expected_wire_sha256=summary["plan_wire_sha256"],
        )
        self.assertEqual((parsed.test.task_count, parsed.train.task_count), (20, 50))

        verify_status, verified, verify_error = self._invoke(
            "verify-plan",
            "--benchmark-root",
            self.benchmark,
            "--test-replay-root",
            test_root,
            "--train-replay-root",
            train_root,
            "--plan-root",
            plan_root,
            "--expected-plan-sha256",
            summary["plan_sha256"],
            "--expected-plan-wire-sha256",
            summary["plan_wire_sha256"],
            "--runtime-image-id",
            image_id,
        )
        self.assertEqual((verify_status, verify_error), (0, ""))
        assert verified is not None
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(verified["plan_sha256"], summary["plan_sha256"])

        second = self.root / "plan-two"
        second_status, second_summary, second_error = self._invoke(
            "build-plan", *arguments, "--output-root", second
        )
        self.assertEqual((second_status, second_error), (0, ""))
        self.assertEqual(second_summary, summary)
        self.assertEqual(self._tree_bytes(second), self._tree_bytes(plan_root))

        wrong_status, wrong_value, wrong_error = self._invoke(
            "verify-plan",
            "--benchmark-root",
            self.benchmark,
            "--test-replay-root",
            test_root,
            "--train-replay-root",
            train_root,
            "--plan-root",
            plan_root,
            "--expected-plan-sha256",
            summary["plan_sha256"],
            "--expected-plan-wire-sha256",
            summary["plan_wire_sha256"],
            "--runtime-image-id",
            "sha256:" + "d" * 64,
        )
        self.assertEqual((wrong_status, wrong_value), (2, None))
        self.assertEqual(
            wrong_error,
            "error[policy_mismatch]: replay batch/plan operation failed\n",
        )

    def test_verify_rejects_tamper_without_paths(self) -> None:
        replay_root, summary = self._build_split("test")
        first = self.tasks["test"][0].task_id
        with (replay_root / "configs" / first / "d2.json").open("ab") as stream:
            stream.write(b"x")
        status, value, error = self._invoke(
            "verify-split",
            "--benchmark-root",
            self.benchmark,
            "--split",
            "test",
            "--replay-root",
            replay_root,
            "--expected-manifest-sha256",
            summary["replay_manifest_sha256"],
            "--expected-manifest-wire-sha256",
            summary["replay_manifest_wire_sha256"],
        )
        self.assertEqual((status, value), (2, None))
        self.assertEqual(
            error,
            "error[formal_replay_rejected]: replay batch/plan operation failed\n",
        )
        self.assertNotIn(str(self.root), error)

    def test_build_split_requires_exact_frozen_authoring_binding(self) -> None:
        task = self.tasks["test"][0]
        target = self.authoring["test"] / task.task_id / "d2.json"
        replacement = OciReplayConfigV1(
            task_id=task.task_id,
            role="d2",
            responses=(
                ReplayResponse(
                    stage="plan",
                    request={"role": "d2", "task_id": task.task_id},
                    response={"action": "different-valid-fixture", "role": "d2"},
                ),
            ),
        )
        target.write_bytes(replacement.to_bytes())
        target.chmod(0o600)
        output = self.root / "substituted-batch"
        status, value, error = self._invoke(
            "build-split",
            "--benchmark-root",
            self.benchmark,
            "--split",
            "test",
            "--authoring-output-root",
            self.authoring["test"],
            *self._index_arguments(
                self.authoring_index,
                self.authoring_index_sha,
                self.authoring_index_wire_sha,
            ),
            "--output-root",
            output,
        )
        self.assertEqual((status, value), (2, None))
        self.assertEqual(
            error,
            "error[authoring_binding_mismatch]: replay batch/plan operation failed\n",
        )
        self.assertFalse(output.exists())

    def test_authoring_index_requires_both_external_pins(self) -> None:
        for semantic, wire in (
            ("0" * 64, self.authoring_index_wire_sha),
            (self.authoring_index_sha, "0" * 64),
        ):
            with self.subTest(semantic=semantic, wire=wire):
                output = self.root / f"bad-index-{semantic[:1]}-{wire[:1]}"
                status, value, error = self._invoke(
                    "build-split",
                    "--benchmark-root",
                    self.benchmark,
                    "--split",
                    "test",
                    "--authoring-output-root",
                    self.authoring["test"],
                    *self._index_arguments(self.authoring_index, semantic, wire),
                    "--output-root",
                    output,
                )
                self.assertEqual((status, value), (2, None))
                self.assertEqual(
                    error,
                    "error[authoring_index_rejected]: replay batch/plan operation failed\n",
                )
                self.assertFalse(output.exists())

    def test_authoring_index_rejects_wrong_split_reorder_and_duplicate(self) -> None:
        baseline = json.loads(self.authoring_index.read_text(encoding="utf-8"))

        def write_variant(tasks: list[dict[str, object]], suffix: str):
            core = {
                "contract_version": 1,
                "kind": "vulngym.replay-authoring-index.v1",
                "tasks": tasks,
            }
            core_wire = json.dumps(
                core,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            semantic = hashlib.sha256(
                b"vulngym:replay-authoring-index:v1\x00" + core_wire
            ).hexdigest()
            payload = (
                json.dumps(
                    {**core, "index_sha256": semantic},
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
            path = self.root / f"invalid-authoring-index-{suffix}.json"
            self._private_file(path, payload)
            return path, semantic, hashlib.sha256(payload).hexdigest()

        variants: dict[str, list[dict[str, object]]] = {}
        wrong_split = [dict(item) for item in baseline["tasks"]]
        wrong_split[0]["split"] = "train"
        variants["wrong-split"] = wrong_split
        reordered = [dict(item) for item in baseline["tasks"]]
        reordered[0], reordered[1] = reordered[1], reordered[0]
        variants["reordered"] = reordered
        duplicate = [dict(item) for item in baseline["tasks"]]
        duplicate[1]["task_id"] = duplicate[0]["task_id"]
        variants["duplicate"] = duplicate

        for suffix, tasks in variants.items():
            with self.subTest(case=suffix):
                path, semantic, wire = write_variant(tasks, suffix)
                output = self.root / f"invalid-index-output-{suffix}"
                status, value, error = self._invoke(
                    "build-split",
                    "--benchmark-root",
                    self.benchmark,
                    "--split",
                    "test",
                    "--authoring-output-root",
                    self.authoring["test"],
                    *self._index_arguments(path, semantic, wire),
                    "--output-root",
                    output,
                )
                self.assertEqual((status, value), (2, None))
                self.assertEqual(
                    error,
                    "error[authoring_index_rejected]: replay batch/plan operation failed\n",
                )
                self.assertFalse(output.exists())

    def test_staging_swap_is_rejected_and_replacement_is_retained(self) -> None:
        output = self.root / "staging-swap-output"
        moved = self.root / "moved-staging"

        def populate(staging: Path) -> None:
            cli._write_private_regular(staging / "safe.txt", b"safe\n")

        def verify(staging: Path) -> bytes:
            payload = (staging / "safe.txt").read_bytes()
            staging.rename(moved)
            staging.mkdir(mode=0o700)
            (staging / "replacement.txt").write_bytes(b"replacement\n")
            return payload

        with self.assertRaises(cli.ReplayBatchPlanError) as captured:
            cli._publish_directory(output, populate=populate, verify=verify)
        self.assertEqual(captured.exception.code, "output_staging_changed")
        self.assertFalse(output.exists())
        self.assertEqual((moved / "safe.txt").read_bytes(), b"safe\n")
        replacements = list(self.root.glob(".staging-swap-output.replay-batch-plan-*"))
        self.assertEqual(len(replacements), 1)
        self.assertEqual(
            (replacements[0] / "replacement.txt").read_bytes(), b"replacement\n"
        )

    def test_failure_never_deletes_replacement_staging(self) -> None:
        output = self.root / "cleanup-replacement-output"
        moved = self.root / "cleanup-original-staging"

        def populate(staging: Path) -> None:
            cli._write_private_regular(staging / "safe.txt", b"safe\n")
            staging.rename(moved)
            staging.mkdir(mode=0o700)
            (staging / "do-not-delete.txt").write_bytes(b"retained\n")
            raise RuntimeError("injected failure")

        with self.assertRaises(RuntimeError):
            cli._publish_directory(output, populate=populate, verify=lambda _root: None)
        replacements = list(
            self.root.glob(".cleanup-replacement-output.replay-batch-plan-*")
        )
        self.assertEqual(len(replacements), 1)
        self.assertEqual(
            (replacements[0] / "do-not-delete.txt").read_bytes(), b"retained\n"
        )
        self.assertEqual((moved / "safe.txt").read_bytes(), b"safe\n")

    def test_no_replace_conflict_retains_both_target_and_staging(self) -> None:
        output = self.root / "no-replace-output"
        original = cli._rename_directory_noreplace

        def conflict(source: Path, destination: Path, **kwargs: object) -> None:
            output.mkdir(mode=0o700)
            (output / "winner.txt").write_bytes(b"winner\n")
            original(source, destination, **kwargs)

        with (
            mock.patch.object(cli, "_rename_directory_noreplace", side_effect=conflict),
            self.assertRaises(cli.ReplayBatchPlanError) as captured,
        ):
            cli._publish_directory(
                output,
                populate=lambda root: cli._write_private_regular(
                    root / "safe.txt", b"safe\n"
                ),
                verify=lambda root: (root / "safe.txt").read_bytes(),
            )
        self.assertEqual(captured.exception.code, "output_exists")
        self.assertEqual((output / "winner.txt").read_bytes(), b"winner\n")
        staging = list(self.root.glob(".no-replace-output.replay-batch-plan-*"))
        self.assertEqual(len(staging), 1)
        self.assertEqual((staging[0] / "safe.txt").read_bytes(), b"safe\n")

    def test_parent_swap_is_uncertain_and_never_deletes_replacements(self) -> None:
        parent = self.root / "parent"
        parent.mkdir(mode=0o700)
        moved_parent = self.root / "moved-parent"
        output = parent / "batch"
        original = cli._rename_directory_noreplace

        def swap_parent(source: Path, destination: Path, **kwargs: object) -> None:
            parent.rename(moved_parent)
            parent.mkdir(mode=0o700)
            replacement = parent / source.name
            replacement.mkdir(mode=0o700)
            (replacement / "replacement.txt").write_bytes(b"replacement\n")
            original(source, destination, **kwargs)

        with (
            mock.patch.object(cli, "_rename_directory_noreplace", side_effect=swap_parent),
            self.assertRaises(cli.ReplayBatchPlanError) as captured,
        ):
            cli._publish_directory(
                output,
                populate=lambda root: cli._write_private_regular(
                    root / "safe.txt", b"safe\n"
                ),
                verify=lambda root: (root / "safe.txt").read_bytes(),
            )
        self.assertEqual(captured.exception.code, "publication_uncertain")
        if os.name == "posix":
            self.assertEqual((moved_parent / "batch" / "safe.txt").read_bytes(), b"safe\n")
            replacement_roots = list(parent.glob(".batch.replay-batch-plan-*"))
            self.assertEqual(len(replacement_roots), 1)
            self.assertEqual(
                (replacement_roots[0] / "replacement.txt").read_bytes(),
                b"replacement\n",
            )
        else:
            self.assertEqual((parent / "batch" / "replacement.txt").read_bytes(), b"replacement\n")
            retained = list(moved_parent.glob(".batch.replay-batch-plan-*"))
            self.assertEqual(len(retained), 1)
            self.assertEqual((retained[0] / "safe.txt").read_bytes(), b"safe\n")

    def test_postcommit_same_bytes_replacement_is_publication_uncertain(self) -> None:
        output = self.root / "postcommit-replacement-output"
        moved = self.root / "postcommit-original-tree"
        calls = 0

        def verify(root: Path) -> bytes:
            nonlocal calls
            calls += 1
            payload = (root / "safe.txt").read_bytes()
            if calls == 2:
                root.rename(moved)
                root.mkdir(mode=0o700)
                cli._write_private_regular(root / "safe.txt", payload)
            return payload

        with self.assertRaises(cli.ReplayBatchPlanError) as captured:
            cli._publish_directory(
                output,
                populate=lambda root: cli._write_private_regular(
                    root / "safe.txt", b"same-bytes\n"
                ),
                verify=verify,
            )
        self.assertEqual(captured.exception.code, "publication_uncertain")
        self.assertTrue(captured.exception.committed)
        self.assertEqual((moved / "safe.txt").read_bytes(), b"same-bytes\n")
        self.assertEqual((output / "safe.txt").read_bytes(), b"same-bytes\n")


if __name__ == "__main__":
    unittest.main()
