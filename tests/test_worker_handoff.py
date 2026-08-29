from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import vulngym_agent.benchmark as benchmark_api
import vulngym_agent.benchmark.snapshot_batch as snapshot_batch_module
import vulngym_agent.benchmark.sealed_tree_access as sealed_tree_access_module
import vulngym_agent.benchmark.worker_handoff as worker_handoff_module
from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.sealed_snapshot import (
    SealedSnapshotFile,
    SealedSnapshotGitlink,
    SnapshotPolicy,
    prepare_sealed_snapshot,
)
from vulngym_agent.benchmark.sealed_tree_access import (
    DEFAULT_SEALED_TREE_ACCESS_LIMITS,
    SealedTreeAccessError,
    SealedTreeAccessLimits,
    bind_worker_tree,
)
from vulngym_agent.benchmark.worker_handoff import (
    WORKER_HANDOFF_DIGEST_DOMAIN,
    WORKER_HANDOFF_CONTRACT_VERSION,
    WORKER_HANDOFF_MAX_BYTES,
    WORKER_HANDOFF_MAX_FILES,
    WorkerHandoffError,
    WorkerHandoffV2,
    build_worker_handoff,
)
from vulngym_agent.tools.git.repository import GitRepository


TASK_ID = "VG-TRAIN-0123456789ABCDEF0991"
REPO_URL = "https://github.com/example/worker-handoff"
KEY = b"worker handoff test attestation key 0001"
KEY_ID = "worker-handoff-test"
SOURCE_PATH = "src/app.py"
SOURCE = b"def entry(value):\n    return critical(value)\n"
GIT_SYMLINK_PATH = "absolute-link"
GIT_SYMLINK_TARGET = b"/opt/vulngym/outside"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class WorkerHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repo"
        self.repository.mkdir()
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.name", "VulnGym Test")
        self._git("config", "user.email", "vulngym@example.invalid")
        self._git("config", "core.autocrlf", "false")
        (self.repository / "src").mkdir()
        (self.repository / SOURCE_PATH).write_bytes(SOURCE)
        (self.repository / "README.md").write_text(
            "source-only fixture\n", encoding="utf-8"
        )
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "source")
        link_blob = subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=self.repository,
            input=GIT_SYMLINK_TARGET,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.decode("ascii").strip()
        self._git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"120000,{link_blob},{GIT_SYMLINK_PATH}",
        )
        self._git("commit", "-q", "-m", "Git symlink bytes")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()
        self.snapshot_root = self.root / "sealed"
        prepared = prepare_sealed_snapshot(
            GitRepository(self.repository),
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=self.commit,
            output_dir=self.snapshot_root,
            attestation_key=KEY,
            key_id=KEY_ID,
        )
        self.task = DiscoveryTaskInputV1(
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=self.commit,
            instruction_id=INSTRUCTION_ID,
            snapshot_manifest_sha256=prepared.manifest_sha256,
            snapshot_content_root=prepared.content_root,
        )
        self.handoff = build_worker_handoff(
            self.task,
            self.snapshot_root,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _bind(self):
        return bind_worker_tree(
            self.task,
            self.snapshot_root / "tree",
            self.handoff.to_bytes(),
            expected_handoff_sha256=self.handoff.handoff_sha256,
            expected_handoff_wire_sha256=self.handoff.wire_sha256,
        )

    def test_gitlink_snapshot_fails_closed_before_worker_handoff(self) -> None:
        target = self.commit
        self._git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{target},vendor/dependency",
        )
        self._git("commit", "-q", "-m", "metadata-only gitlink")
        commit = self._git("rev-parse", "HEAD").stdout.strip()
        root = self.root / "sealed-gitlink"
        prepared = prepare_sealed_snapshot(
            GitRepository(self.repository),
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=commit,
            output_dir=root,
            attestation_key=KEY,
            key_id=KEY_ID,
        )
        task = DiscoveryTaskInputV1(
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=commit,
            instruction_id=INSTRUCTION_ID,
            snapshot_manifest_sha256=prepared.manifest_sha256,
            snapshot_content_root=prepared.content_root,
        )
        with (
            mock.patch.object(
                worker_handoff_module,
                "WorkerHandoffV2",
                side_effect=AssertionError(
                    "worker handoff must not be constructed for gitlinks"
                ),
            ) as constructor,
            self.assertRaises(WorkerHandoffError) as captured,
        ):
            build_worker_handoff(
                task, root, attestation_key=KEY, expected_key_id=KEY_ID
            )
        self.assertEqual("snapshot_verification_failed", captured.exception.code)
        constructor.assert_not_called()

    def test_public_contract_is_canonical_nonsecret_and_exported(self) -> None:
        payload = self.handoff.to_bytes()
        parsed = WorkerHandoffV2.from_bytes(
            payload,
            expected_sha256=self.handoff.handoff_sha256,
            expected_wire_sha256=self.handoff.wire_sha256,
        )
        self.assertEqual(parsed, self.handoff)
        self.assertEqual(parsed.to_bytes(), payload)
        self.assertLessEqual(len(payload), WORKER_HANDOFF_MAX_BYTES)
        self.assertNotIn(KEY, payload)
        self.assertNotIn(KEY_ID.encode("ascii"), payload)
        self.assertNotIn(str(self.snapshot_root).encode("utf-8"), payload)
        self.assertNotIn(b"attestation", payload)
        self.assertNotIn(b"control/", payload)
        self.assertIs(benchmark_api.WorkerHandoffV2, WorkerHandoffV2)
        self.assertIs(benchmark_api.bind_worker_tree, bind_worker_tree)
        self.assertIn("build_worker_handoff", benchmark_api.__all__)
        self.assertEqual(len(benchmark_api.__all__), len(set(benchmark_api.__all__)))

    def test_constructor_detaches_task_and_recomputes_original_manifest(self) -> None:
        original_task = self.task
        handoff = WorkerHandoffV2(
            task=original_task,
            policy=self.handoff.policy,
            root_tree=self.handoff.root_tree,
            files=self.handoff.files,
        )
        object.__setattr__(original_task, "repo_url", "https://github.com/example/changed")
        self.assertEqual(handoff.task.repo_url, REPO_URL)
        self.assertEqual(handoff.task.snapshot_manifest_sha256, self.handoff.task.snapshot_manifest_sha256)
        self.task = handoff.task

    def test_constructor_detaches_every_file_record(self) -> None:
        caller_files = tuple(
            SealedSnapshotFile(
                path=item.path,
                git_mode=item.git_mode,
                blob_oid=item.blob_oid,
                size=item.size,
                sha256=item.sha256,
            )
            for item in self.handoff.files
        )
        handoff = WorkerHandoffV2(
            task=self.task,
            policy=self.handoff.policy,
            root_tree=self.handoff.root_tree,
            files=caller_files,
        )
        original_sha256 = handoff.files[0].sha256
        object.__setattr__(caller_files[0], "sha256", "f" * 64)
        self.assertEqual(handoff.files[0].sha256, original_sha256)
        self.assertEqual(
            WorkerHandoffV2.from_bytes(
                handoff.to_bytes(),
                expected_sha256=handoff.handoff_sha256,
                expected_wire_sha256=handoff.wire_sha256,
            ),
            handoff,
        )

    def test_wrong_wire_pin_is_rejected_before_json_parsing(self) -> None:
        payload = self.handoff.to_bytes()
        with mock.patch(
            "vulngym_agent.benchmark.worker_handoff.json.loads",
            side_effect=AssertionError("JSON parsing must remain unreachable"),
        ) as parser:
            with self.assertRaises(WorkerHandoffError) as captured:
                WorkerHandoffV2.from_bytes(
                    payload,
                    expected_sha256=self.handoff.handoff_sha256,
                    expected_wire_sha256="f" * 64,
                )
        self.assertEqual(captured.exception.code, "digest_mismatch")
        parser.assert_not_called()

    def test_pinned_policy_v3_handoff_is_rejected(self) -> None:
        raw = json.loads(self.handoff.to_bytes())
        raw["policy"]["policy_version"] = "vulngym.portable-source-tree.v3"
        raw["policy"]["max_file_bytes"] = 16 * 1024 * 1024
        raw["policy"]["max_total_bytes"] = 512 * 1024 * 1024
        core = dict(raw)
        core.pop("handoff_sha256")
        handoff_sha256 = hashlib.sha256(
            WORKER_HANDOFF_DIGEST_DOMAIN + _canonical(core)
        ).hexdigest()
        raw["handoff_sha256"] = handoff_sha256
        payload = _canonical(raw) + b"\n"

        with self.assertRaises(WorkerHandoffError) as captured:
            WorkerHandoffV2.from_bytes(
                payload,
                expected_sha256=handoff_sha256,
                expected_wire_sha256=hashlib.sha256(payload).hexdigest(),
            )
        self.assertEqual(captured.exception.code, "invalid_contract")

    def test_snapshot_policy_does_not_expand_downstream_budgets(self) -> None:
        self.assertEqual(snapshot_batch_module._MAX_BATCH_TOTAL_BYTES, 16 * 1024**3)
        self.assertEqual(WORKER_HANDOFF_CONTRACT_VERSION, 2)
        self.assertEqual(WORKER_HANDOFF_MAX_BYTES, 72 * 1024 * 1024)
        self.assertEqual(WORKER_HANDOFF_MAX_FILES, 100_000)
        self.assertEqual(
            DEFAULT_SEALED_TREE_ACCESS_LIMITS.max_bytes_per_read,
            4 * 1024 * 1024,
        )
        self.assertEqual(
            DEFAULT_SEALED_TREE_ACCESS_LIMITS.max_total_bytes_read,
            64 * 1024 * 1024,
        )
        SealedTreeAccessLimits(
            max_bytes_per_read=16 * 1024 * 1024,
            max_total_bytes_read=256 * 1024 * 1024,
        )
        with self.assertRaises(ValueError):
            SealedTreeAccessLimits(
                max_bytes_per_read=(16 * 1024 * 1024) + 1,
                max_total_bytes_read=256 * 1024 * 1024,
            )
        with self.assertRaises(ValueError):
            SealedTreeAccessLimits(
                max_bytes_per_read=1,
                max_total_bytes_read=(256 * 1024 * 1024) + 1,
            )

    def test_strict_parser_rejects_duplicate_noncanonical_and_wrong_digest(self) -> None:
        payload = self.handoff.to_bytes()
        with self.assertRaises(WorkerHandoffError) as captured:
            WorkerHandoffV2.from_bytes(
                payload,
                expected_sha256="f" * 64,
                expected_wire_sha256=self.handoff.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "digest_mismatch")

        legacy = json.loads(payload)
        legacy["contract_version"] = 1
        legacy["kind"] = "vulngym.source-discovery-worker-handoff.v1"
        legacy["policy"].pop("git_symlink_representation")
        legacy["policy"]["policy_version"] = "vulngym.portable-source-tree.v1"
        file_lines = tuple(
            json.dumps(
                record,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
            for record in legacy["files"]
        )
        content_root = hashlib.sha256(
            b"VulnGym sealed source content root v1\0" + b"".join(file_lines)
        ).hexdigest()
        legacy["task"]["snapshot_content_root"] = content_root
        legacy_manifest = (
            json.dumps(
                {
                    "commit": legacy["task"]["commit"],
                    "contract_version": "vulngym.sealed-source-snapshot.v1",
                    "policy": legacy["policy"],
                    "record_type": "header",
                    "repo_url": legacy["task"]["repo_url"],
                    "root_tree": legacy["root_tree"],
                    "task_id": legacy["task"]["task_id"],
                },
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
            + b"".join(file_lines)
            + json.dumps(
                {
                    "content_root": content_root,
                    "file_count": len(legacy["files"]),
                    "record_type": "footer",
                    "total_bytes": sum(item["size"] for item in legacy["files"]),
                },
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        legacy["task"]["snapshot_manifest_sha256"] = hashlib.sha256(
            legacy_manifest
        ).hexdigest()
        legacy_core = dict(legacy)
        legacy_core.pop("handoff_sha256")
        legacy["handoff_sha256"] = hashlib.sha256(
            b"VulnGym source discovery worker handoff v1\0"
            + json.dumps(
                legacy_core,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        legacy_payload = (
            json.dumps(
                legacy,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        with self.assertRaises(WorkerHandoffError) as captured:
            WorkerHandoffV2.from_bytes(
                legacy_payload,
                expected_sha256=legacy["handoff_sha256"],
                expected_wire_sha256=hashlib.sha256(legacy_payload).hexdigest(),
            )
        self.assertEqual(captured.exception.code, "invalid_contract")

        version_prefix = (
            f'{{"contract_version":{WORKER_HANDOFF_CONTRACT_VERSION},'.encode("ascii")
        )
        duplicate = payload.replace(
            version_prefix,
            version_prefix
            + f'"contract_version":{WORKER_HANDOFF_CONTRACT_VERSION},'.encode(
                "ascii"
            ),
            1,
        )
        self.assertNotEqual(duplicate, payload)
        with self.assertRaises(WorkerHandoffError) as captured:
            WorkerHandoffV2.from_bytes(
                duplicate,
                expected_sha256=self.handoff.handoff_sha256,
                expected_wire_sha256=hashlib.sha256(duplicate).hexdigest(),
            )
        self.assertEqual(captured.exception.code, "noncanonical_json")

        value = json.loads(payload)
        noncanonical = json.dumps(value, indent=2).encode("utf-8") + b"\n"
        with self.assertRaises(WorkerHandoffError):
            WorkerHandoffV2.from_bytes(
                noncanonical,
                expected_sha256=self.handoff.handoff_sha256,
                expected_wire_sha256=hashlib.sha256(noncanonical).hexdigest(),
            )

    def test_manifest_or_task_tamper_cannot_form_a_new_handoff(self) -> None:
        file_record = self.handoff.files[0]
        object.__setattr__(file_record, "sha256", "f" * 64)
        with self.assertRaises(WorkerHandoffError) as captured:
            WorkerHandoffV2(
                task=self.handoff.task,
                policy=self.handoff.policy,
                root_tree=self.handoff.root_tree,
                files=self.handoff.files,
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

    def test_builder_rejects_wrong_attestation_and_task_binding(self) -> None:
        with self.assertRaises(WorkerHandoffError) as captured:
            build_worker_handoff(
                self.task,
                self.snapshot_root,
                attestation_key=b"wrong worker handoff key material 0000",
                expected_key_id=KEY_ID,
            )
        self.assertEqual(captured.exception.code, "snapshot_verification_failed")

        wrong = DiscoveryTaskInputV1(
            task_id=self.task.task_id,
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            instruction_id=self.task.instruction_id,
            snapshot_manifest_sha256="f" * 64,
            snapshot_content_root=self.task.snapshot_content_root,
        )
        with self.assertRaises(WorkerHandoffError):
            build_worker_handoff(
                wrong,
                self.snapshot_root,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
            )

    def test_mounted_binder_reads_and_finalizes_without_control_or_key(self) -> None:
        tree = self._bind()
        inventory = tree.inventory()
        self.assertEqual(
            tuple(item.path for item in inventory),
            tuple(item.path for item in self.handoff.files),
        )
        source = tree.read_bytes(SOURCE_PATH, maximum_bytes=len(SOURCE))
        self.assertEqual(source, SOURCE)
        ledger = tree.finalize()
        self.assertTrue(ledger.finalized)
        self.assertTrue(ledger.verification_succeeded)
        self.assertEqual(ledger.read_calls, 1)
        self.assertEqual(ledger.reads[0].sha256, hashlib.sha256(SOURCE).hexdigest())

    def test_handoff_and_worker_preserve_git_symlink_mode_but_read_plain_bytes(self) -> None:
        record = next(
            item for item in self.handoff.files if item.path == GIT_SYMLINK_PATH
        )
        self.assertEqual("120000", record.git_mode)
        materialized = self.snapshot_root / "tree" / GIT_SYMLINK_PATH
        self.assertTrue(materialized.is_file())
        self.assertFalse(materialized.is_symlink())

        tree = self._bind()
        inventory_record = next(
            item for item in tree.inventory() if item.path == GIT_SYMLINK_PATH
        )
        self.assertEqual("120000", inventory_record.git_mode)
        self.assertEqual(
            GIT_SYMLINK_TARGET,
            tree.read_bytes(
                GIT_SYMLINK_PATH, maximum_bytes=len(GIT_SYMLINK_TARGET)
            ),
        )
        self.assertTrue(tree.finalize().verification_succeeded)

    def test_mounted_binder_rejects_wrong_pin_task_and_extra_member(self) -> None:
        with self.assertRaises(SealedTreeAccessError) as captured:
            bind_worker_tree(
                self.task,
                self.snapshot_root / "tree",
                self.handoff.to_bytes(),
                expected_handoff_sha256="f" * 64,
                expected_handoff_wire_sha256=self.handoff.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

        wrong_task = DiscoveryTaskInputV1(
            task_id="VG-TRAIN-0123456789ABCDEF0992",
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            instruction_id=self.task.instruction_id,
            snapshot_manifest_sha256=self.task.snapshot_manifest_sha256,
            snapshot_content_root=self.task.snapshot_content_root,
        )
        with self.assertRaises(SealedTreeAccessError) as captured:
            bind_worker_tree(
                wrong_task,
                self.snapshot_root / "tree",
                self.handoff.to_bytes(),
                expected_handoff_sha256=self.handoff.handoff_sha256,
                expected_handoff_wire_sha256=self.handoff.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

        (self.snapshot_root / "tree" / "extra.txt").write_text(
            "extra\n", encoding="utf-8"
        )
        with self.assertRaises(SealedTreeAccessError) as captured:
            self._bind()
        self.assertEqual(captured.exception.code, "source_changed")

    def test_binder_rejects_mutated_graph_without_running_callbacks(self) -> None:
        callbacks = 0

        class CallbackString(str):
            def __eq__(self, other):
                nonlocal callbacks
                callbacks += 1
                return super().__eq__(other)

        mutated_task = DiscoveryTaskInputV1.from_dict(self.task.to_dict())
        object.__setattr__(mutated_task, "repo_url", CallbackString(mutated_task.repo_url))
        with self.assertRaises(SealedTreeAccessError) as captured:
            bind_worker_tree(
                mutated_task,
                self.snapshot_root / "tree",
                self.handoff.to_bytes(),
                expected_handoff_sha256=self.handoff.handoff_sha256,
                expected_handoff_wire_sha256=self.handoff.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

    def test_binder_detaches_limits_and_rejects_malformed_limit_graphs(self) -> None:
        limits = SealedTreeAccessLimits(max_read_calls=1)
        tree = bind_worker_tree(
            self.task,
            self.snapshot_root / "tree",
            self.handoff.to_bytes(),
            expected_handoff_sha256=self.handoff.handoff_sha256,
            expected_handoff_wire_sha256=self.handoff.wire_sha256,
            limits=limits,
        )
        object.__setattr__(limits, "max_read_calls", 2)
        self.assertEqual(tree.read_bytes(SOURCE_PATH, maximum_bytes=len(SOURCE)), SOURCE)
        with self.assertRaises(SealedTreeAccessError) as captured:
            tree.read_bytes("README.md", maximum_bytes=1024)
        self.assertEqual(captured.exception.code, "source_limit_exceeded")
        tree.finalize()

        malformed = object.__new__(SealedTreeAccessLimits)
        with self.assertRaises(SealedTreeAccessError) as captured:
            bind_worker_tree(
                self.task,
                self.snapshot_root / "tree",
                self.handoff.to_bytes(),
                expected_handoff_sha256=self.handoff.handoff_sha256,
                expected_handoff_wire_sha256=self.handoff.wire_sha256,
                limits=malformed,
            )
        self.assertEqual(captured.exception.code, "invalid_argument")

        callbacks = 0

        class CallbackInt(int):
            def __index__(self):
                nonlocal callbacks
                callbacks += 1
                return super().__index__()

        polymorphic = SealedTreeAccessLimits()
        object.__setattr__(polymorphic, "max_read_calls", CallbackInt(1))
        with self.assertRaises(SealedTreeAccessError) as captured:
            bind_worker_tree(
                self.task,
                self.snapshot_root / "tree",
                self.handoff.to_bytes(),
                expected_handoff_sha256=self.handoff.handoff_sha256,
                expected_handoff_wire_sha256=self.handoff.wire_sha256,
                limits=polymorphic,
            )
        self.assertEqual(captured.exception.code, "invalid_argument")
        self.assertEqual(callbacks, 0)
        self.assertEqual(callbacks, 0)

        class CallbackHandoff(WorkerHandoffV2):
            def to_bytes(self):
                nonlocal callbacks
                callbacks += 1
                return b""

        with self.assertRaises(SealedTreeAccessError) as captured:
            bind_worker_tree(
                self.task,
                self.snapshot_root / "tree",
                object.__new__(CallbackHandoff),  # type: ignore[arg-type]
                expected_handoff_sha256=self.handoff.handoff_sha256,
                expected_handoff_wire_sha256=self.handoff.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "invalid_argument")
        self.assertEqual(callbacks, 0)

        malformed_task = object.__new__(DiscoveryTaskInputV1)
        with self.assertRaises(SealedTreeAccessError) as captured:
            bind_worker_tree(
                malformed_task,
                self.snapshot_root / "tree",
                self.handoff.to_bytes(),
                expected_handoff_sha256=self.handoff.handoff_sha256,
                expected_handoff_wire_sha256=self.handoff.wire_sha256,
            )
        self.assertEqual(captured.exception.code, "invalid_binding")

    def test_malformed_exact_handoff_nodes_have_stable_contract_errors(self) -> None:
        with self.assertRaises(WorkerHandoffError):
            WorkerHandoffV2(
                task=object.__new__(DiscoveryTaskInputV1),
                policy=self.handoff.policy,
                root_tree=self.handoff.root_tree,
                files=self.handoff.files,
            )
        with self.assertRaises(WorkerHandoffError):
            WorkerHandoffV2(
                task=self.task,
                policy=object.__new__(SnapshotPolicy),
                root_tree=self.handoff.root_tree,
                files=self.handoff.files,
            )
        with self.assertRaises(WorkerHandoffError):
            WorkerHandoffV2(
                task=self.task,
                policy=self.handoff.policy,
                root_tree=self.handoff.root_tree,
                files=(object.__new__(SealedSnapshotFile),),
            )
        with self.assertRaises(WorkerHandoffError):
            build_worker_handoff(
                object.__new__(DiscoveryTaskInputV1),
                self.snapshot_root,
                attestation_key=KEY,
                expected_key_id=KEY_ID,
            )

    def test_finalize_detects_content_change_and_permanently_closes(self) -> None:
        tree = self._bind()
        target = self.snapshot_root / "tree" / SOURCE_PATH
        target.write_bytes(SOURCE.replace(b"critical", b"changed_"))
        with self.assertRaises(SealedTreeAccessError) as captured:
            tree.finalize()
        self.assertIn(
            captured.exception.code,
            {"source_changed", "snapshot_verification_failed"},
        )
        ledger = tree.usage_snapshot()
        self.assertTrue(ledger.finalized)
        self.assertFalse(ledger.verification_succeeded)
        with self.assertRaises(SealedTreeAccessError) as second:
            tree.inventory()
        self.assertEqual(second.exception.code, "access_finalized")

    def test_finalize_interrupt_is_one_way_and_closes_the_authority(self) -> None:
        tree = self._bind()
        with mock.patch.object(
            sealed_tree_access_module._MountedTreeAuthority,
            "reverify",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                tree.finalize()
        ledger = tree.usage_snapshot()
        self.assertTrue(ledger.finalized)
        self.assertFalse(ledger.verification_succeeded)
        with self.assertRaises(SealedTreeAccessError) as captured:
            tree.inventory()
        self.assertEqual(captured.exception.code, "access_finalized")

    def test_close_interrupt_after_reverify_is_one_way(self) -> None:
        tree = self._bind()
        with mock.patch.object(
            sealed_tree_access_module._MountedTreeAuthority,
            "close",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                tree.finalize()
        ledger = tree.usage_snapshot()
        self.assertTrue(ledger.finalized)
        self.assertFalse(ledger.verification_succeeded)

    def test_post_read_ledger_interrupt_rolls_back_and_closes(self) -> None:
        tree = self._bind()
        with mock.patch.object(
            sealed_tree_access_module,
            "SourceReadUsage",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                tree.read_bytes(SOURCE_PATH, maximum_bytes=len(SOURCE))
        ledger = tree.usage_snapshot()
        self.assertTrue(ledger.finalized)
        self.assertFalse(ledger.verification_succeeded)
        self.assertEqual(ledger.read_calls, 0)
        self.assertEqual(ledger.bytes_read, 0)

    def test_read_interrupt_is_one_way_and_closes_the_authority(self) -> None:
        tree = self._bind()
        with mock.patch.object(
            sealed_tree_access_module._MountedTreeAuthority,
            "read",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                tree.read_bytes(SOURCE_PATH, maximum_bytes=len(SOURCE))
        ledger = tree.usage_snapshot()
        self.assertTrue(ledger.finalized)
        self.assertFalse(ledger.verification_succeeded)
        self.assertEqual(ledger.read_calls, 0)

    def test_capability_construction_interrupt_closes_mounted_authority(self) -> None:
        original_close = sealed_tree_access_module._MountedTreeAuthority.close
        closed: list[object] = []

        def recording_close(authority):
            closed.append(authority)
            return original_close(authority)

        with mock.patch.object(
            sealed_tree_access_module._MountedTreeAuthority,
            "close",
            recording_close,
        ), mock.patch.object(
            sealed_tree_access_module,
            "BoundSealedTree",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                bind_worker_tree(
                    self.task,
                    self.snapshot_root / "tree",
                    self.handoff.to_bytes(),
                    expected_handoff_sha256=self.handoff.handoff_sha256,
                    expected_handoff_wire_sha256=self.handoff.wire_sha256,
                )
        self.assertEqual(len(closed), 1)

        with mock.patch.object(
            sealed_tree_access_module._MountedTreeAuthority,
            "close",
            side_effect=(SystemExit(), None),
        ), mock.patch.object(
            sealed_tree_access_module,
            "BoundSealedTree",
            side_effect=KeyboardInterrupt(),
        ):
            with self.assertRaises(KeyboardInterrupt):
                bind_worker_tree(
                    self.task,
                    self.snapshot_root / "tree",
                    self.handoff.to_bytes(),
                    expected_handoff_sha256=self.handoff.handoff_sha256,
                    expected_handoff_wire_sha256=self.handoff.wire_sha256,
                )


if __name__ == "__main__":
    unittest.main()
