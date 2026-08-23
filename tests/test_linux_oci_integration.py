"""Opt-in real Docker gate for the E3 immutable-generation execution path."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.sealed_snapshot import (
    DEFAULT_SNAPSHOT_POLICY,
    prepare_sealed_snapshot,
)
from vulngym_agent.benchmark.sealed_tree_access import (
    DEFAULT_SEALED_TREE_ACCESS_LIMITS,
)
from vulngym_agent.benchmark.worker_handoff import build_worker_handoff
from vulngym_agent.evaluator.contracts import (
    DiscoveryTaskExecutionPlanV1,
    ExecutionPolicyBindingV1,
    snapshot_policy_sha256_v1,
)
from vulngym_agent.evaluator.linux_oci import (
    run_discovery_worker_linux_oci_v1,
    verify_linux_oci_runtime_v1,
)
from vulngym_agent.evaluator.oci_worker_entry import OciReplayConfigV1
import vulngym_agent.evaluator.supervisor as supervisor_module
from vulngym_agent.evaluator.supervisor import (
    WorkerTaskLaunchV1,
    budget_limits_sha256_v1,
    tree_limits_sha256_v1,
)
from vulngym_agent.evaluator.worker import (
    DEFAULT_D2_WORKER_BUDGET_LIMITS,
    DEFAULT_D3_WORKER_BUDGET_LIMITS,
)
from vulngym_agent.tools.git.repository import GitRepository


_ENABLED = os.environ.get("VULNGYM_E3_DOCKER_INTEGRATION") == "1"
_IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


@unittest.skipUnless(_ENABLED, "set VULNGYM_E3_DOCKER_INTEGRATION=1")
class LinuxOciIntegrationTests(unittest.TestCase):
    def test_one_offline_task_closes_through_real_linux_oci(self) -> None:
        if (
            os.environ.get("VULNGYM_E3_REQUIRE_NATIVE_LINUX") == "1"
            and platform.system() != "Linux"
        ):
            self.fail("the release E3 gate requires a native Linux host")
        image_id = os.environ.get("VULNGYM_E3_WORKER_IMAGE_ID", "")
        if _IMAGE_RE.fullmatch(image_id) is None:
            self.fail("VULNGYM_E3_WORKER_IMAGE_ID must be an exact image ID")
        docker_value = os.environ.get("VULNGYM_E3_DOCKER_EXECUTABLE")
        docker_executable = docker_value or shutil.which("docker")
        if not docker_executable:
            self.fail("a Docker CLI executable is required")

        key = b"VulnGym E3 integration attestation key 0001"
        key_id = "e3-integration"
        task_id = "VG-TEST-EEEEEEEEEEEEEEEEEEEE"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository_root = root / "repository"
            repository_root.mkdir()
            self._git(repository_root, "init", "-q", "-b", "main")
            self._git(repository_root, "config", "user.name", "VulnGym Test")
            self._git(
                repository_root,
                "config",
                "user.email",
                "vulngym@example.invalid",
            )
            (repository_root / "app.py").write_bytes(
                b"def identity(value):\n    return value\n"
            )
            self._git(repository_root, "add", "app.py")
            self._git(repository_root, "commit", "-q", "-m", "source")
            commit = self._git(
                repository_root, "rev-parse", "HEAD"
            ).stdout.strip()

            snapshot_root = root / "snapshot"
            prepared = prepare_sealed_snapshot(
                GitRepository(repository_root),
                task_id=task_id,
                repo_url="https://github.com/example/e3-integration",
                commit=commit,
                output_dir=snapshot_root,
                attestation_key=key,
                key_id=key_id,
            )
            task = DiscoveryTaskInputV1(
                task_id=task_id,
                repo_url="https://github.com/example/e3-integration",
                commit=commit,
                instruction_id=INSTRUCTION_ID,
                snapshot_manifest_sha256=prepared.manifest_sha256,
                snapshot_content_root=prepared.content_root,
            )
            handoff = build_worker_handoff(
                task,
                snapshot_root,
                attestation_key=key,
                expected_key_id=key_id,
            )
            source_before = self._tree_observation(snapshot_root / "tree")
            if os.name == "posix":
                self.assertEqual(
                    stat.S_IMODE(os.lstat(snapshot_root / "tree").st_mode),
                    0o700,
                )
                self.assertEqual(
                    stat.S_IMODE(
                        os.lstat(snapshot_root / "tree" / "app.py").st_mode
                    ),
                    0o600,
                )
            d2_replay = OciReplayConfigV1(
                task_id=task_id, role="d2", responses=()
            )
            d3_replay = OciReplayConfigV1(
                task_id=task_id, role="d3", responses=()
            )
            policy = ExecutionPolicyBindingV1(
                runtime_image_id=image_id,
                d2_backend_id=d2_replay.backend_id,
                d2_model_id=d2_replay.model_id,
                d3_backend_id=d3_replay.backend_id,
                d3_model_id=d3_replay.model_id,
                snapshot_policy_sha256=snapshot_policy_sha256_v1(
                    DEFAULT_SNAPSHOT_POLICY
                ),
                d2_budget_sha256=budget_limits_sha256_v1(
                    DEFAULT_D2_WORKER_BUDGET_LIMITS
                ),
                d3_budget_sha256=budget_limits_sha256_v1(
                    DEFAULT_D3_WORKER_BUDGET_LIMITS
                ),
                tree_limits_sha256=tree_limits_sha256_v1(
                    DEFAULT_SEALED_TREE_ACCESS_LIMITS
                ),
                wall_time_seconds=60,
                memory_bytes=256 * 1024 * 1024,
                cpu_millis=100,
                pids_limit=16,
                open_files_limit=64,
                stdout_max_bytes=1024 * 1024,
                stderr_max_bytes=64 * 1024,
                tmpfs_bytes=1024 * 1024,
            )
            task_plan = DiscoveryTaskExecutionPlanV1(
                batch_binding_sha256="1" * 64,
                execution_policy_sha256=policy.policy_sha256,
                task_id=task.task_id,
                snapshot_id=task.snapshot_id,
                snapshot_manifest_sha256=task.snapshot_manifest_sha256,
                snapshot_content_root=task.snapshot_content_root,
                handoff_sha256=handoff.handoff_sha256,
                handoff_wire_sha256=handoff.wire_sha256,
                d2_replay_sha256=d2_replay.config_sha256,
                d2_replay_wire_sha256=d2_replay.wire_sha256,
                d3_replay_sha256=d3_replay.config_sha256,
                d3_replay_wire_sha256=d3_replay.wire_sha256,
            )
            launch = WorkerTaskLaunchV1(
                supervisor_module._SESSION_TOKEN,
                task_plan=task_plan,
                handoff=handoff,
                tree_root=snapshot_root / "tree",
            )
            runtime = verify_linux_oci_runtime_v1(
                Path(docker_executable), execution_policy=policy
            )
            completion = run_discovery_worker_linux_oci_v1(
                runtime,
                launch,
                d2_replay=d2_replay,
                d3_replay=d3_replay,
            )
            self.assertEqual(
                self._tree_observation(snapshot_root / "tree"), source_before
            )
            claimed = completion._claim_for_plan(task_plan)
            evidence = claimed.runtime_evidence
            self.assertEqual(claimed.run.task, task)
            self.assertEqual(evidence.runtime_image_id, image_id)
            self.assertNotEqual(evidence.execution_image_id, image_id)
            self.assertRegex(
                evidence.execution_image_inspect_sha256, r"^[0-9a-f]{64}$"
            )
            self.assertRegex(
                evidence.materializer_container_diff_sha256, r"^[0-9a-f]{64}$"
            )
            self.assertTrue(evidence.container_diff_empty)
            self.assertTrue(evidence.cleanup_complete)
            removed_image = subprocess.run(
                (docker_executable, "image", "inspect", evidence.execution_image_id),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(removed_image.returncode, 0)

    @staticmethod
    def _tree_observation(root: Path) -> tuple[tuple[object, ...], ...]:
        records: list[tuple[object, ...]] = []
        for path in (root, *sorted(root.rglob("*"))):
            value = os.lstat(path)
            records.append(
                (
                    "." if path == root else path.relative_to(root).as_posix(),
                    value.st_dev,
                    value.st_ino,
                    value.st_size,
                    stat.S_IMODE(value.st_mode),
                    getattr(value, "st_mtime_ns", None),
                    getattr(value, "st_ctime_ns", None),
                    (
                        hashlib.sha256(path.read_bytes()).hexdigest()
                        if stat.S_ISREG(value.st_mode)
                        else None
                    ),
                )
            )
        return tuple(records)

    @staticmethod
    def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ("git", *arguments),
            cwd=root,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
