from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import pickle
import subprocess
import tempfile
import unittest
from unittest import mock

import vulngym_agent.evaluator.supervisor as supervisor_module
from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.producer_contracts import ProducerDeferredV1
from vulngym_agent.benchmark.reviewer_projection import project_discovery_run_v1
from vulngym_agent.benchmark.sealed_snapshot import (
    DEFAULT_SNAPSHOT_POLICY,
    prepare_sealed_snapshot,
)
from vulngym_agent.benchmark.snapshot_batch import (
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    SnapshotBatchSummary,
    SnapshotBatchTask,
)
from vulngym_agent.benchmark.worker_handoff import build_worker_handoff
from vulngym_agent.evaluator.contracts import (
    ExecutionPolicyBindingV1,
    snapshot_policy_sha256_v2,
)
from vulngym_agent.evaluator.oci_worker_entry import (
    OciReplayConfigV1,
    REPLAY_BACKEND_ID,
    REPLAY_MODEL_ID,
)
from vulngym_agent.evaluator.supervisor import (
    EvaluatorSupervisorError,
    accept_discovery_worker_output_v1,
    budget_limits_sha256_v1,
    postverify_discovery_execution_v1,
    prepare_discovery_execution_plan_v1,
    publish_postverified_discovery_execution_v1,
    tree_limits_sha256_v1,
)
from vulngym_agent.evaluator.worker import (
    DEFAULT_D2_WORKER_BUDGET_LIMITS,
    DEFAULT_D3_WORKER_BUDGET_LIMITS,
)
from vulngym_agent.evaluator.runtime_evidence import (
    DockerServerIdentityV1,
    RuntimeEvidenceV1,
    RuntimeIsolationV1,
    RuntimeResourceLimitsV1,
)
from vulngym_agent.evaluator.worker_completion import (
    WorkerCompletionError,
    _issue_completed_worker_execution_v1,
)
from vulngym_agent.orchestrator.discovery_pipeline import SourceDiscoveryRunV1
from vulngym_agent.benchmark.sealed_tree_access import (
    DEFAULT_SEALED_TREE_ACCESS_LIMITS,
)
from vulngym_agent.tools.git.repository import GitRepository


KEY = b"evaluator supervisor integration test key 0001"
KEY_ID = "evaluator-supervisor-test"
REPO_URL = "https://github.com/example/evaluator-supervisor"
SOURCE = b"def entry(value):\n    return value\n"


def _sha(marker: int) -> str:
    return f"{marker:064x}"


class EvaluatorSupervisorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.repository = cls.root / "repo"
        cls.repository.mkdir()
        cls._git("init", "-q", "-b", "main")
        cls._git("config", "user.name", "VulnGym Test")
        cls._git("config", "user.email", "vulngym@example.invalid")
        cls._git("config", "core.autocrlf", "false")
        (cls.repository / "src").mkdir()
        (cls.repository / "src" / "app.py").write_bytes(SOURCE)
        cls._git("add", "-A")
        cls._git("commit", "-q", "-m", "source")
        cls.commit = cls._git("rev-parse", "HEAD").stdout.strip()
        cls.batch_root = cls.root / "batch"
        (cls.batch_root / "bundles").mkdir(parents=True)

        members: list[SnapshotBatchTask] = []
        handoffs = {}
        repository = GitRepository(cls.repository)
        for index in range(20):
            task_id = f"VG-TEST-{index:020X}"
            snapshot_root = cls.batch_root / "bundles" / task_id
            prepared = prepare_sealed_snapshot(
                repository,
                task_id=task_id,
                repo_url=REPO_URL,
                commit=cls.commit,
                output_dir=snapshot_root,
                attestation_key=KEY,
                key_id=KEY_ID,
            )
            directories = {
                "/".join(item.path.split("/")[:depth])
                for item in prepared.files
                for depth in range(1, len(item.path.split("/")))
            }
            member = SnapshotBatchTask(
                task_id=task_id,
                repo_url=REPO_URL,
                commit=cls.commit,
                split="test",
                instruction_id=INSTRUCTION_ID,
                snapshot_manifest_sha256=prepared.manifest_sha256,
                snapshot_content_root=prepared.content_root,
                root_tree=prepared.root_tree,
                file_count=prepared.file_count,
                node_count=prepared.file_count + len(directories),
                total_bytes=prepared.total_bytes,
                entry_count=prepared.entry_count,
                regular_file_count=prepared.regular_file_count,
                gitlink_count=prepared.gitlink_count,
                regular_file_bytes=prepared.regular_file_bytes,
                materialized_bytes=prepared.materialized_bytes,
            )
            members.append(member)
            from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1

            task = DiscoveryTaskInputV1(
                task_id=member.task_id,
                repo_url=member.repo_url,
                commit=member.commit,
                instruction_id=member.instruction_id,
                snapshot_manifest_sha256=member.snapshot_manifest_sha256,
                snapshot_content_root=member.snapshot_content_root,
            )
            handoffs[task_id] = build_worker_handoff(
                task,
                snapshot_root,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
            )
        cls.members = tuple(members)
        cls.handoffs = handoffs
        cls.replay_configs = tuple(
            (
                OciReplayConfigV1(
                    task_id=member.task_id,
                    role="d2",
                    responses=(),
                ),
                OciReplayConfigV1(
                    task_id=member.task_id,
                    role="d3",
                    responses=(),
                ),
            )
            for member in cls.members
        )
        cls.summary = SnapshotBatchSummary(
            batch_root=cls.batch_root.resolve(),
            profile_id=PROFILE_ID,
            split="test",
            task_count=len(cls.members),
            total_files=sum(item.file_count for item in cls.members),
            total_nodes=sum(item.node_count for item in cls.members),
            total_bytes=sum(item.total_bytes for item in cls.members),
            tasks_sha256=_sha(1),
            public_manifest_sha256=PROFILE_MANIFEST_SHA256,
            source_map_sha256=_sha(3),
            manifest_sha256=_sha(4),
            batch_content_root=_sha(5),
            key_id=KEY_ID,
            tasks=cls.members,
        )
        cls.execution_policy = ExecutionPolicyBindingV1(
            runtime_image_id="sha256:" + "a" * 64,
            d2_backend_id=REPLAY_BACKEND_ID,
            d2_model_id=REPLAY_MODEL_ID,
            d3_backend_id=REPLAY_BACKEND_ID,
            d3_model_id=REPLAY_MODEL_ID,
            snapshot_policy_sha256=snapshot_policy_sha256_v2(
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
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def _git(cls, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=cls.repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    @classmethod
    def _handoff_builder(cls, task, *_args, **_kwargs):
        return cls.handoffs[task.task_id]

    def _prepare(self, *summaries: SnapshotBatchSummary):
        sequence = summaries or (self.summary,)
        verifier = mock.patch(
            "vulngym_agent.evaluator.supervisor.verify_snapshot_batch",
            side_effect=sequence,
        )
        builder = mock.patch(
            "vulngym_agent.evaluator.supervisor.build_worker_handoff",
            side_effect=self._handoff_builder,
        )
        return verifier, builder

    @staticmethod
    def _run_for(task) -> bytes:
        producer = ProducerDeferredV1(
            task=task,
            stage="SCOUT",
            reason_code="model_deferred",
            missing_information=("source evidence",),
        )
        discovery = project_discovery_run_v1(producer, None)
        return SourceDiscoveryRunV1(producer, None, discovery).to_wire()

    def _completion_for(self, launch, run_wire: bytes, marker: int):
        run = SourceDiscoveryRunV1.from_wire(run_wire)
        task_plan = launch.task_plan
        evidence = RuntimeEvidenceV1(
            docker_server=DockerServerIdentityV1(
                operating_system="linux",
                architecture="amd64",
                engine_version="29.6.2",
                api_version="1.55",
                docker_executable_sha256=_sha(9001),
                daemon_endpoint_sha256=_sha(9002),
                server_observation_sha256=_sha(9003),
            ),
            isolation=RuntimeIsolationV1(),
            resources=RuntimeResourceLimitsV1(
                wall_time_seconds=self.execution_policy.wall_time_seconds,
                memory_bytes=self.execution_policy.memory_bytes,
                cpu_millis=self.execution_policy.cpu_millis,
                pids_limit=self.execution_policy.pids_limit,
                open_files_limit=self.execution_policy.open_files_limit,
                stdout_max_bytes=self.execution_policy.stdout_max_bytes,
                stderr_max_bytes=self.execution_policy.stderr_max_bytes,
                tmpfs_bytes=self.execution_policy.tmpfs_bytes,
            ),
            runtime_image_id=self.execution_policy.runtime_image_id,
            runtime_image_inspect_sha256=_sha(9004),
            execution_image_id="sha256:" + _sha(marker + 17),
            execution_image_inspect_sha256=_sha(marker + 8),
            execution_policy_sha256=self.execution_policy.policy_sha256,
            task_plan_sha256=task_plan.plan_sha256,
            task_id=task_plan.task_id,
            snapshot_id=task_plan.snapshot_id,
            snapshot_manifest_sha256=task_plan.snapshot_manifest_sha256,
            snapshot_content_root=task_plan.snapshot_content_root,
            handoff_sha256=task_plan.handoff_sha256,
            handoff_wire_sha256=task_plan.handoff_wire_sha256,
            source_generation_sha256=_sha(marker + 2),
            runtime_config_sha256=_sha(marker + 3),
            materializer_container_create_spec_sha256=_sha(marker + 9),
            materializer_container_pre_inspect_sha256=_sha(marker + 10),
            materializer_container_post_inspect_sha256=_sha(marker + 11),
            materializer_container_diff_sha256=_sha(marker + 12),
            materializer_container_identity_sha256=_sha(marker + 13),
            container_create_spec_sha256=_sha(marker + 4),
            container_pre_inspect_sha256=_sha(marker + 5),
            container_post_inspect_sha256=_sha(marker + 6),
            container_identity_sha256=_sha(marker + 7),
            run_sha256=run.run_sha256,
            run_wire_sha256=hashlib.sha256(run_wire).hexdigest(),
            run_wire_size=len(run_wire),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            stderr_size=0,
            exit_code=0,
            timed_out=False,
            oom_killed=False,
            restart_count=0,
            container_diff_empty=True,
            cleanup_complete=True,
        )
        return _issue_completed_worker_execution_v1(run_wire, evidence)

    def _postverified_token(self):
        verifier, builder = self._prepare(self.summary, self.summary)
        with verifier, builder:
            session = prepare_discovery_execution_plan_v1(
                self.batch_root,
                expected_batch_manifest_sha256=self.summary.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
                execution_policy=self.execution_policy,
                task_replay_configs=self.replay_configs,
            )
            for index, member in enumerate(self.members):
                launch = session.launch_for(member.task_id)
                accept_discovery_worker_output_v1(
                    session,
                    completion=self._completion_for(
                        launch, self._run_for(launch.task), 5000 + index * 10
                    ),
                )
            return postverify_discovery_execution_v1(session)

    def test_prepare_derives_full_plan_and_narrow_launches(self) -> None:
        verifier, builder = self._prepare(self.summary)
        with verifier as verify_call, builder as build_call:
            session = prepare_discovery_execution_plan_v1(
                self.batch_root,
                expected_batch_manifest_sha256=self.summary.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
                execution_policy=self.execution_policy,
                task_replay_configs=self.replay_configs,
            )
        self.assertEqual(verify_call.call_count, 1)
        self.assertEqual(build_call.call_count, 20)
        self.assertEqual(len(session.plan.tasks), 20)
        self.assertEqual(
            tuple(task.task_id for task in session.plan.tasks),
            tuple(member.task_id for member in self.members),
        )
        for task_plan, (d2_replay, d3_replay) in zip(
            session.plan.tasks, self.replay_configs, strict=True
        ):
            self.assertEqual(task_plan.d2_replay_sha256, d2_replay.config_sha256)
            self.assertEqual(task_plan.d2_replay_wire_sha256, d2_replay.wire_sha256)
            self.assertEqual(task_plan.d3_replay_sha256, d3_replay.config_sha256)
            self.assertEqual(task_plan.d3_replay_wire_sha256, d3_replay.wire_sha256)
        launch = session.launch_for(self.members[0].task_id)
        self.assertEqual(launch.task_plan.task_id, self.members[0].task_id)
        self.assertEqual(launch.tree_root.name, "tree")
        self.assertEqual(launch.tree_root.parent.name, self.members[0].task_id)
        self.assertNotIn(KEY, launch.handoff_payload)
        self.assertNotIn(b"control/", launch.handoff_payload)
        with self.assertRaises(TypeError):
            pickle.dumps(launch)
        session.abort()

    def test_prepare_rejects_missing_replay_pair(self) -> None:
        verifier, builder = self._prepare(self.summary)
        with verifier, builder as build_call:
            with self.assertRaises(EvaluatorSupervisorError) as captured:
                prepare_discovery_execution_plan_v1(
                    self.batch_root,
                    expected_batch_manifest_sha256=self.summary.manifest_sha256,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                    execution_policy=self.execution_policy,
                    task_replay_configs=self.replay_configs[:-1],
                )
        self.assertEqual(captured.exception.code, "invalid_binding")
        self.assertEqual(build_call.call_count, 0)

    def test_prepare_rejects_duplicate_replay_pair(self) -> None:
        duplicate = self.replay_configs[:-1] + (self.replay_configs[0],)
        verifier, builder = self._prepare(self.summary)
        with verifier as verify_call, builder as build_call:
            with self.assertRaises(EvaluatorSupervisorError) as captured:
                prepare_discovery_execution_plan_v1(
                    self.batch_root,
                    expected_batch_manifest_sha256=self.summary.manifest_sha256,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                    execution_policy=self.execution_policy,
                    task_replay_configs=duplicate,
                )
        self.assertEqual(captured.exception.code, "invalid_binding")
        self.assertEqual(verify_call.call_count, 0)
        self.assertEqual(build_call.call_count, 0)

    def test_prepare_rejects_reordered_replay_pairs(self) -> None:
        reordered = (
            self.replay_configs[1],
            self.replay_configs[0],
            *self.replay_configs[2:],
        )
        verifier, builder = self._prepare(self.summary)
        with verifier, builder as build_call:
            with self.assertRaises(EvaluatorSupervisorError) as captured:
                prepare_discovery_execution_plan_v1(
                    self.batch_root,
                    expected_batch_manifest_sha256=self.summary.manifest_sha256,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                    execution_policy=self.execution_policy,
                    task_replay_configs=reordered,
                )
        self.assertEqual(captured.exception.code, "invalid_binding")
        self.assertEqual(build_call.call_count, 0)

    def test_prepare_rejects_cross_task_replay_exchange(self) -> None:
        first_d2, first_d3 = self.replay_configs[0]
        second_d2, second_d3 = self.replay_configs[1]
        exchanged = (
            (first_d2, second_d3),
            (second_d2, first_d3),
            *self.replay_configs[2:],
        )
        verifier, builder = self._prepare(self.summary)
        with verifier as verify_call, builder as build_call:
            with self.assertRaises(EvaluatorSupervisorError) as captured:
                prepare_discovery_execution_plan_v1(
                    self.batch_root,
                    expected_batch_manifest_sha256=self.summary.manifest_sha256,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                    execution_policy=self.execution_policy,
                    task_replay_configs=exchanged,
                )
        self.assertEqual(captured.exception.code, "policy_mismatch")
        self.assertEqual(verify_call.call_count, 0)
        self.assertEqual(build_call.call_count, 0)

    def test_session_replay_for_returns_frozen_detached_copies(self) -> None:
        verifier, builder = self._prepare(self.summary)
        with verifier, builder:
            session = prepare_discovery_execution_plan_v1(
                self.batch_root,
                expected_batch_manifest_sha256=self.summary.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
                execution_policy=self.execution_policy,
                task_replay_configs=self.replay_configs,
            )
        task_id = self.members[0].task_id
        supplied_d2, supplied_d3 = self.replay_configs[0]
        expected_d2_wire = supplied_d2.to_bytes()
        expected_d3_wire = supplied_d3.to_bytes()
        saved_d2_task_id = supplied_d2.task_id
        saved_d3_task_id = supplied_d3.task_id
        try:
            object.__setattr__(supplied_d2, "task_id", self.members[1].task_id)
            object.__setattr__(supplied_d3, "task_id", self.members[1].task_id)
            first_d2, first_d3 = session.replay_for(task_id)
            second_d2, second_d3 = session.replay_for(task_id)
            self.assertEqual(first_d2.to_bytes(), expected_d2_wire)
            self.assertEqual(first_d3.to_bytes(), expected_d3_wire)
            self.assertEqual(second_d2.to_bytes(), expected_d2_wire)
            self.assertEqual(second_d3.to_bytes(), expected_d3_wire)
            self.assertIsNot(first_d2, supplied_d2)
            self.assertIsNot(first_d3, supplied_d3)
            self.assertIsNot(first_d2, second_d2)
            self.assertIsNot(first_d3, second_d3)
        finally:
            object.__setattr__(supplied_d2, "task_id", saved_d2_task_id)
            object.__setattr__(supplied_d3, "task_id", saved_d3_task_id)
            session.abort()

    def test_prepare_binds_the_verifiers_canonical_root(self) -> None:
        supplied_alias = self.root / "batch-alias-spelling"
        verifier, builder = self._prepare(self.summary)
        with mock.patch.object(
            supervisor_module,
            "_canonical_existing_path",
            return_value=self.summary.batch_root,
        ) as canonicalize, verifier as verify_call, builder:
            session = prepare_discovery_execution_plan_v1(
                supplied_alias,
                expected_batch_manifest_sha256=self.summary.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
                execution_policy=self.execution_policy,
                task_replay_configs=self.replay_configs,
            )
        canonicalize.assert_called_once_with(
            Path(os.path.abspath(os.fspath(supplied_alias))),
            directory=True,
            status=4,
        )
        self.assertEqual(
            verify_call.call_args.args[0],
            Path(os.path.abspath(os.fspath(supplied_alias))),
        )
        session.abort()

        forged = replace(
            self.summary,
            batch_root=self.root / "forged-different-batch-root",
        )
        verifier, builder = self._prepare(forged)
        with mock.patch.object(
            supervisor_module,
            "_canonical_existing_path",
            return_value=self.summary.batch_root,
        ), verifier, builder:
            with self.assertRaises(EvaluatorSupervisorError) as captured:
                prepare_discovery_execution_plan_v1(
                    supplied_alias,
                    expected_batch_manifest_sha256=self.summary.manifest_sha256,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                    execution_policy=self.execution_policy,
                    task_replay_configs=self.replay_configs,
                )
        self.assertEqual(captured.exception.code, "batch_binding_mismatch")

    def test_handoff_swap_is_rejected_during_prepare(self) -> None:
        wrong = self.handoffs[self.members[1].task_id]

        def swapped_builder(task, *_args, **_kwargs):
            if task.task_id == self.members[0].task_id:
                return wrong
            return self.handoffs[task.task_id]

        with mock.patch(
            "vulngym_agent.evaluator.supervisor.verify_snapshot_batch",
            return_value=self.summary,
        ), mock.patch(
            "vulngym_agent.evaluator.supervisor.build_worker_handoff",
            side_effect=swapped_builder,
        ):
            with self.assertRaises(EvaluatorSupervisorError) as captured:
                prepare_discovery_execution_plan_v1(
                    self.batch_root,
                    expected_batch_manifest_sha256=self.summary.manifest_sha256,
                    attestation_key=KEY,
                    expected_key_id=KEY_ID,
                    execution_policy=self.execution_policy,
                    task_replay_configs=self.replay_configs,
                )
        self.assertEqual(captured.exception.code, "batch_verification_failed")

    def test_session_detaches_handoff_before_launch(self) -> None:
        verifier, builder = self._prepare(self.summary)
        with verifier, builder:
            session = prepare_discovery_execution_plan_v1(
                self.batch_root,
                expected_batch_manifest_sha256=self.summary.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
                execution_policy=self.execution_policy,
                task_replay_configs=self.replay_configs,
            )
        first_id = self.members[0].task_id
        original = self.handoffs[first_id]
        replacement = self.handoffs[self.members[1].task_id]
        fields = (
            "task",
            "policy",
            "root_tree",
            "files",
            "handoff_sha256",
            "wire_sha256",
        )
        saved = tuple(getattr(original, field) for field in fields)
        try:
            for field in fields:
                object.__setattr__(original, field, getattr(replacement, field))
            launch = session.launch_for(first_id)
            self.assertEqual(launch.task.task_id, first_id)
            self.assertEqual(launch.task_plan.task_id, first_id)
            self.assertNotEqual(
                launch.handoff_sha256, replacement.handoff_sha256
            )
        finally:
            for field, value in zip(fields, saved, strict=True):
                object.__setattr__(original, field, value)
            session.abort()

    def test_out_of_order_outputs_close_only_after_fresh_postverify(self) -> None:
        verifier, builder = self._prepare(self.summary, self.summary)
        with verifier as verify_call, builder:
            session = prepare_discovery_execution_plan_v1(
                self.batch_root,
                expected_batch_manifest_sha256=self.summary.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
                execution_policy=self.execution_policy,
                task_replay_configs=self.replay_configs,
            )
            for index, member in reversed(tuple(enumerate(self.members))):
                launch = session.launch_for(member.task_id)
                accept_discovery_worker_output_v1(
                    session,
                    completion=self._completion_for(
                        launch, self._run_for(launch.task), 1000 + index * 10
                    ),
                )
            token = postverify_discovery_execution_v1(session)
        self.assertEqual(verify_call.call_count, 2)
        self.assertEqual(session.state, "postverified")
        self.assertEqual(
            tuple(item.task_plan.task_id for item in token.pending),
            tuple(item.task_id for item in self.members),
        )
        self.assertTrue(all(value == 0 for value in session._DiscoveryExecutionSession__key))
        with self.assertRaises(TypeError):
            pickle.dumps(token)

    def test_changed_post_binding_aborts_before_publication(self) -> None:
        changed = replace(self.summary, batch_content_root=_sha(9999))
        verifier, builder = self._prepare(self.summary, changed)
        with verifier, builder:
            session = prepare_discovery_execution_plan_v1(
                self.batch_root,
                expected_batch_manifest_sha256=self.summary.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
                execution_policy=self.execution_policy,
                task_replay_configs=self.replay_configs,
            )
            for index, member in enumerate(self.members):
                launch = session.launch_for(member.task_id)
                accept_discovery_worker_output_v1(
                    session,
                    completion=self._completion_for(
                        launch, self._run_for(launch.task), 2000 + index * 10
                    ),
                )
            with self.assertRaises(EvaluatorSupervisorError) as captured:
                postverify_discovery_execution_v1(session)
        self.assertEqual(captured.exception.code, "postverify_mismatch")
        self.assertEqual(session.state, "failed")
        self.assertTrue(all(value == 0 for value in session._DiscoveryExecutionSession__key))

    def test_postverify_io_failure_fails_session_and_clears_key(self) -> None:
        verifier, builder = self._prepare(
            self.summary, OSError("injected postverify failure")
        )
        with verifier, builder:
            session = prepare_discovery_execution_plan_v1(
                self.batch_root,
                expected_batch_manifest_sha256=self.summary.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
                execution_policy=self.execution_policy,
                task_replay_configs=self.replay_configs,
            )
            for index, member in enumerate(self.members):
                launch = session.launch_for(member.task_id)
                accept_discovery_worker_output_v1(
                    session,
                    completion=self._completion_for(
                        launch, self._run_for(launch.task), 8000 + index * 10
                    ),
                )
            with self.assertRaises(EvaluatorSupervisorError) as captured:
                postverify_discovery_execution_v1(session)
        self.assertEqual(captured.exception.code, "postverify_failed")
        self.assertEqual(session.state, "failed")
        self.assertTrue(
            all(value == 0 for value in session._DiscoveryExecutionSession__key)
        )

    def test_cross_task_output_cannot_form_a_provider_completion(self) -> None:
        verifier, builder = self._prepare(self.summary)
        with verifier, builder:
            session = prepare_discovery_execution_plan_v1(
                self.batch_root,
                expected_batch_manifest_sha256=self.summary.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
                execution_policy=self.execution_policy,
                task_replay_configs=self.replay_configs,
            )
        first = session.launch_for(self.members[0].task_id)
        second = session.launch_for(self.members[1].task_id)
        valid_for_first = self._completion_for(
            first, self._run_for(first.task), 3000
        )
        evidence = valid_for_first._CompletedWorkerExecutionV1__evidence
        with self.assertRaises(WorkerCompletionError) as captured:
            _issue_completed_worker_execution_v1(
                self._run_for(second.task), evidence
            )
        self.assertEqual(captured.exception.code, "detached_completion")
        self.assertEqual(session.state, "prepared")
        session.abort()

    def test_malformed_exact_completion_fails_session_and_clears_key(self) -> None:
        verifier, builder = self._prepare(self.summary)
        with verifier, builder:
            session = prepare_discovery_execution_plan_v1(
                self.batch_root,
                expected_batch_manifest_sha256=self.summary.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
                execution_policy=self.execution_policy,
                task_replay_configs=self.replay_configs,
            )
        launch = session.launch_for(self.members[0].task_id)
        completion = self._completion_for(
            launch, self._run_for(launch.task), 3500
        )
        object.__setattr__(
            completion,
            "_CompletedWorkerExecutionV1__evidence",
            object(),
        )
        with self.assertRaises(EvaluatorSupervisorError) as captured:
            accept_discovery_worker_output_v1(session, completion=completion)
        self.assertEqual(captured.exception.code, "invalid_output")
        self.assertEqual(session.state, "failed")
        self.assertTrue(
            all(value == 0 for value in session._DiscoveryExecutionSession__key)
        )

    def test_postverified_batch_publishes_one_complete_outer_transaction(self) -> None:
        verifier, builder = self._prepare(self.summary, self.summary)
        with verifier, builder:
            session = prepare_discovery_execution_plan_v1(
                self.batch_root,
                expected_batch_manifest_sha256=self.summary.manifest_sha256,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
                execution_policy=self.execution_policy,
                task_replay_configs=self.replay_configs,
            )
            for index, member in enumerate(self.members):
                launch = session.launch_for(member.task_id)
                accept_discovery_worker_output_v1(
                    session,
                    completion=self._completion_for(
                        launch, self._run_for(launch.task), 4000 + index * 10
                    ),
                )
            token = postverify_discovery_execution_v1(session)

        output = self.root / "published-evaluator-results"
        receipt = publish_postverified_discovery_execution_v1(token, output)
        self.assertEqual(receipt.plan.plan_sha256, session.plan.plan_sha256)
        self.assertEqual(len(receipt.tasks), 20)
        self.assertEqual(
            {item.name for item in output.iterdir()},
            {
                "artifact-index.json",
                "bundles",
                "execution-plan.json",
                "execution-receipt.json",
            },
        )
        self.assertEqual(
            {item.name for item in (output / "bundles").iterdir()},
            {member.task_id for member in self.members},
        )
        self.assertEqual(
            hashlib.sha256((output / "execution-receipt.json").read_bytes()).hexdigest(),
            receipt.wire_sha256,
        )
        with self.assertRaises(EvaluatorSupervisorError) as captured:
            publish_postverified_discovery_execution_v1(
                token, self.root / "second-publication"
            )
        self.assertEqual(captured.exception.code, "invalid_state")

    def test_plan_corruption_at_rename_cannot_return_publication_success(self) -> None:
        token = self._postverified_token()
        output = self.root / "published-corrupt-plan-at-commit"
        original_rename = supervisor_module._rename_directory_noreplace

        def corrupt_plan_then_rename(source: Path, destination: Path) -> None:
            (source / "execution-plan.json").write_bytes(b"corrupted-plan\n")
            original_rename(source, destination)

        with mock.patch.object(
            supervisor_module,
            "_rename_directory_noreplace",
            side_effect=corrupt_plan_then_rename,
        ):
            with self.assertRaises(EvaluatorSupervisorError) as captured:
                publish_postverified_discovery_execution_v1(token, output)

        self.assertTrue(captured.exception.committed)
        self.assertTrue(output.is_dir())

    def test_rename_commit_followed_by_error_is_reported_as_committed(self) -> None:
        token = self._postverified_token()
        output = self.root / "published-rename-error-after-commit"
        original_rename = supervisor_module._rename_directory_noreplace

        def commit_then_error(source: Path, destination: Path) -> None:
            original_rename(source, destination)
            raise OSError("rename completed before acknowledgement failed")

        with mock.patch.object(
            supervisor_module,
            "_rename_directory_noreplace",
            side_effect=commit_then_error,
        ):
            with self.assertRaises(EvaluatorSupervisorError) as captured:
                publish_postverified_discovery_execution_v1(token, output)

        self.assertTrue(captured.exception.committed)
        self.assertTrue(output.is_dir())


if __name__ == "__main__":
    unittest.main()
