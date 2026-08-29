from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from vulngym_agent.benchmark import sealed_snapshot as sealed_snapshot_module
from vulngym_agent.benchmark.sealed_snapshot import (
    GIT_SYMLINK_REPRESENTATION,
    GITLINK_REPRESENTATION,
    SealedSnapshotError,
    SnapshotPolicy,
    audit_sealed_snapshot_source,
    prepare_sealed_snapshot,
    verify_sealed_snapshot,
)
from vulngym_agent.tools.git.repository import GitFactError, GitRepository


TASK_ID = "VG-TRAIN-0123456789ABCDEF0123"
OTHER_TASK_ID = "VG-TRAIN-1123456789ABCDEF0123"
REPO_URL = "https://github.com/example/sealed-source"
KEY = b"trusted evaluator key material!!"
OTHER_KEY = b"another trusted evaluator key!!!"
KEY_ID = "evaluator-key-2026-01"


class SealedSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.repo_path = self.root / "repo"
        self.repo_path.mkdir()
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.name", "VulnGym Test")
        self._git("config", "user.email", "vulngym@example.invalid")
        self._git("config", "core.autocrlf", "false")
        (self.repo_path / "src").mkdir()
        (self.repo_path / "src" / "app.py").write_bytes(
            b"print('exact bytes')\r\n"
        )
        (self.repo_path / "binary.dat").write_bytes(b"\x00\xff\x10\n")
        (self.repo_path / "run.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
        self._git("add", "-A")
        self._git("update-index", "--chmod=+x", "run.sh")
        self._git("commit", "-q", "-m", "sealed source")
        self.commit = self._git("rev-parse", "HEAD").stdout.strip()
        self.repository = GitRepository(self.repo_path)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _git(
        self,
        *arguments: str,
        input_data: bytes | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repo_path,
            input=input_data,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=input_data is None,
        )

    def _hash_object(
        self, data: bytes, *, object_type: str = "blob", literally: bool = False
    ) -> str:
        arguments = ["git", "hash-object"]
        if literally:
            arguments.append("--literally")
        arguments.extend(["-t", object_type, "-w", "--stdin"])
        result = subprocess.run(
            arguments,
            cwd=self.repo_path,
            input=data,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.stdout.decode("ascii").strip()

    def _raw_commit(self, tree_data: bytes) -> str:
        tree = self._hash_object(tree_data, object_type="tree")
        return self._git("commit-tree", tree, "-m", "crafted tree").stdout.strip()

    def _commit_git_symlinks(
        self, entries: tuple[tuple[str, bytes], ...], *, message: str
    ) -> str:
        """Create only Git 120000 entries; never create host symlinks."""

        for path, target_bytes in entries:
            blob = self._hash_object(target_bytes)
            self._git(
                "update-index", "--add", "--cacheinfo", f"120000,{blob},{path}"
            )
        self._git("commit", "-q", "-m", message)
        return self._git("rev-parse", "HEAD").stdout.strip()

    def _prepare(
        self,
        name: str = "snapshot",
        *,
        repository: GitRepository | None = None,
        commit: str | None = None,
        policy: SnapshotPolicy | None = None,
    ):
        arguments = {}
        if policy is not None:
            arguments["policy"] = policy
        return prepare_sealed_snapshot(
            repository or self.repository,
            task_id=TASK_ID,
            repo_url=REPO_URL,
            commit=commit or self.commit,
            output_dir=self.root / name,
            attestation_key=KEY,
            key_id=KEY_ID,
            **arguments,
        )

    def _verify(self, name: str = "snapshot", **overrides):
        arguments = {
            "expected_task_id": TASK_ID,
            "expected_repo_url": REPO_URL,
            "expected_commit": self.commit,
            "attestation_key": KEY,
            "expected_key_id": KEY_ID,
        }
        arguments.update(overrides)
        return verify_sealed_snapshot(self.root / name, **arguments)

    def test_prepare_and_verify_preserve_exact_raw_blob_bytes(self) -> None:
        prepared = self._prepare()

        self.assertEqual(3, prepared.file_count)
        self.assertEqual(
            b"print('exact bytes')\r\n",
            (prepared.agent_tree / "src" / "app.py").read_bytes(),
        )
        self.assertEqual(b"\x00\xff\x10\n", (prepared.agent_tree / "binary.dat").read_bytes())
        self.assertFalse((prepared.snapshot_root / ".git").exists())
        self.assertFalse((prepared.agent_tree / ".git").exists())
        verified = self._verify()
        self.assertEqual(prepared.content_root, verified.content_root)
        self.assertEqual(prepared.manifest_sha256, verified.manifest_sha256)
        self.assertEqual(prepared.files, verified.files)
        self.assertEqual(prepared.agent_tree, verified.agent_tree)
        with self.assertRaises(FrozenInstanceError):
            verified.file_count = 0  # type: ignore[misc]

    def test_manifest_and_attestation_are_deterministic(self) -> None:
        first = self._prepare("first")
        second = self._prepare("second")

        self.assertEqual(first.files, second.files)
        self.assertEqual(first.content_root, second.content_root)
        self.assertEqual(first.manifest_sha256, second.manifest_sha256)
        for relative in ("control/manifest.jsonl", "control/attestation.json"):
            self.assertEqual(
                (first.snapshot_root / relative).read_bytes(),
                (second.snapshot_root / relative).read_bytes(),
            )
        manifest_lines = (first.snapshot_root / "control" / "manifest.jsonl").read_bytes().splitlines()
        paths = [json.loads(line)["path"] for line in manifest_lines[1:-1]]
        self.assertEqual(
            sorted(paths, key=lambda path: path.encode("utf-8")), paths
        )
        policy = SnapshotPolicy().to_dict()
        self.assertEqual(
            "vulngym.sealed-source-snapshot.v3",
            sealed_snapshot_module.SNAPSHOT_CONTRACT_VERSION,
        )
        self.assertEqual("vulngym.portable-source-tree.v4", policy["policy_version"])
        self.assertEqual(80 * 1024 * 1024, policy["max_file_bytes"])
        self.assertEqual(640 * 1024 * 1024, policy["max_total_bytes"])
        self.assertEqual(
            GIT_SYMLINK_REPRESENTATION,
            policy["git_symlink_representation"],
        )
        self.assertEqual(GITLINK_REPRESENTATION, policy["gitlink_representation"])
        self.assertEqual(
            b"VulnGym sealed source content root v3\0",
            sealed_snapshot_module._CONTENT_DOMAIN,
        )
        self.assertEqual(
            b"VulnGym sealed source attestation v3\0",
            sealed_snapshot_module._ATTESTATION_DOMAIN,
        )
        with self.assertRaises(ValueError):
            SnapshotPolicy(git_symlink_representation="host-symlink")
        with self.assertRaises(ValueError):
            SnapshotPolicy(gitlink_representation="recursive-checkout")
        SnapshotPolicy(
            max_file_bytes=96 * 1024 * 1024,
            max_total_bytes=2 * 1024 * 1024 * 1024,
        )
        with self.assertRaises(ValueError):
            SnapshotPolicy(max_file_bytes=(96 * 1024 * 1024) + 1)
        with self.assertRaises(ValueError):
            SnapshotPolicy(max_total_bytes=(2 * 1024 * 1024 * 1024) + 1)

    def test_v4_policy_rejects_a_self_consistent_policy_v3_bundle(self) -> None:
        prepared = self._prepare("legacy-policy-v3")
        manifest_path = prepared.snapshot_root / "control" / "manifest.jsonl"
        records = [json.loads(line) for line in manifest_path.read_bytes().splitlines()]
        records[0]["policy"]["policy_version"] = "vulngym.portable-source-tree.v3"
        records[0]["policy"]["max_file_bytes"] = 16 * 1024 * 1024
        records[0]["policy"]["max_total_bytes"] = 512 * 1024 * 1024
        manifest = b"".join(
            sealed_snapshot_module._canonical_json(record) + b"\n"
            for record in records
        )
        manifest_sha256 = hashlib.sha256(manifest).hexdigest()
        mac = hmac.new(KEY, digestmod=hashlib.sha256)
        mac.update(sealed_snapshot_module._ATTESTATION_DOMAIN)
        mac.update(KEY_ID.encode("ascii"))
        mac.update(b"\0")
        mac.update(manifest)
        attestation = {
            "algorithm": "HMAC-SHA256",
            "contract_version": "vulngym.sealed-source-snapshot.v3",
            "key_id": KEY_ID,
            "mac": mac.hexdigest(),
            "manifest_sha256": manifest_sha256,
        }
        manifest_path.write_bytes(manifest)
        (prepared.snapshot_root / "control" / "attestation.json").write_bytes(
            sealed_snapshot_module._canonical_json(attestation) + b"\n"
        )

        with self.assertRaises(SealedSnapshotError) as captured:
            self._verify("legacy-policy-v3")
        self.assertEqual(captured.exception.code, "manifest_binding_mismatch")

    def test_v3_verifier_rejects_a_self_consistent_legacy_v1_bundle(self) -> None:
        prepared = self._prepare("legacy-v1")
        manifest_path = prepared.snapshot_root / "control" / "manifest.jsonl"
        records = [json.loads(line) for line in manifest_path.read_bytes().splitlines()]
        records[0]["contract_version"] = "vulngym.sealed-source-snapshot.v1"
        records[0]["policy"].pop("git_symlink_representation")
        records[0]["policy"]["policy_version"] = "vulngym.portable-source-tree.v1"
        file_lines = tuple(
            sealed_snapshot_module._canonical_json(record) + b"\n"
            for record in records[1:-1]
        )
        content = hashlib.sha256(
            b"VulnGym sealed source content root v1\0" + b"".join(file_lines)
        ).hexdigest()
        records[-1]["content_root"] = content
        legacy_manifest = (
            sealed_snapshot_module._canonical_json(records[0])
            + b"\n"
            + b"".join(file_lines)
            + sealed_snapshot_module._canonical_json(records[-1])
            + b"\n"
        )
        manifest_sha256 = hashlib.sha256(legacy_manifest).hexdigest()
        legacy_mac = hmac.new(KEY, digestmod=hashlib.sha256)
        legacy_mac.update(b"VulnGym sealed source attestation v1\0")
        legacy_mac.update(KEY_ID.encode("ascii"))
        legacy_mac.update(b"\0")
        legacy_mac.update(legacy_manifest)
        legacy_attestation = sealed_snapshot_module._canonical_json(
            {
                "algorithm": "HMAC-SHA256",
                "contract_version": "vulngym.sealed-source-snapshot.v1",
                "key_id": KEY_ID,
                "mac": legacy_mac.hexdigest(),
                "manifest_sha256": manifest_sha256,
            }
        ) + b"\n"
        manifest_path.write_bytes(legacy_manifest)
        (prepared.snapshot_root / "control" / "attestation.json").write_bytes(
            legacy_attestation
        )

        with self.assertRaises(SealedSnapshotError) as captured:
            self._verify("legacy-v1")
        self.assertEqual(captured.exception.code, "attestation_invalid")

    def test_verifier_rejects_wrong_key_key_id_and_trusted_binding(self) -> None:
        self._prepare()
        cases = (
            {"attestation_key": OTHER_KEY},
            {"expected_key_id": "different-key"},
            {"expected_task_id": OTHER_TASK_ID},
            {"expected_repo_url": "https://github.com/example/other"},
            {"expected_commit": "f" * 40},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(SealedSnapshotError):
                self._verify(**overrides)

    def test_manifest_parser_rejects_empty_and_boolean_counts(self) -> None:
        policy = SnapshotPolicy()
        header = {
            "commit": self.commit,
            "contract_version": sealed_snapshot_module.SNAPSHOT_CONTRACT_VERSION,
            "policy": policy.to_dict(),
            "record_type": "header",
            "repo_url": REPO_URL,
            "root_tree": "0" * 40,
            "task_id": TASK_ID,
        }
        empty_footer = {
            "content_root": sealed_snapshot_module._content_root(()),
            "file_count": 0,
            "record_type": "footer",
            "total_bytes": 0,
        }
        empty_manifest = (
            sealed_snapshot_module._canonical_json(header)
            + b"\n"
            + sealed_snapshot_module._canonical_json(empty_footer)
            + b"\n"
        )
        with self.assertRaisesRegex(SealedSnapshotError, "at least one file"):
            sealed_snapshot_module._parse_manifest(
                empty_manifest,
                expected_task_id=TASK_ID,
                expected_repo_url=REPO_URL,
                expected_commit=self.commit,
                policy=policy,
            )

        file_record = {
            "blob_oid": "1" * 40,
            "git_mode": "100644",
            "path": "one.txt",
            "record_type": "file",
            "sha256": "2" * 64,
            "size": 1,
        }
        file_line = sealed_snapshot_module._canonical_json(file_record) + b"\n"
        boolean_footer = {
            "content_root": sealed_snapshot_module._content_root((file_line,)),
            "file_count": True,
            "record_type": "footer",
            "total_bytes": True,
        }
        boolean_manifest = (
            sealed_snapshot_module._canonical_json(header)
            + b"\n"
            + file_line
            + sealed_snapshot_module._canonical_json(boolean_footer)
            + b"\n"
        )
        with self.assertRaisesRegex(SealedSnapshotError, "footer"):
            sealed_snapshot_module._parse_manifest(
                boolean_manifest,
                expected_task_id=TASK_ID,
                expected_repo_url=REPO_URL,
                expected_commit=self.commit,
                policy=policy,
            )

        float_header = dict(header)
        float_header["policy"] = {
            key: (float(value) if type(value) is int else value)
            for key, value in policy.to_dict().items()
        }
        float_manifest = (
            sealed_snapshot_module._canonical_json(float_header)
            + b"\n"
            + file_line
            + sealed_snapshot_module._canonical_json(
                {
                    "content_root": sealed_snapshot_module._content_root((file_line,)),
                    "file_count": 1,
                    "record_type": "footer",
                    "total_bytes": 1,
                }
            )
            + b"\n"
        )
        with self.assertRaisesRegex(SealedSnapshotError, "trusted binding"):
            sealed_snapshot_module._parse_manifest(
                float_manifest,
                expected_task_id=TASK_ID,
                expected_repo_url=REPO_URL,
                expected_commit=self.commit,
                policy=policy,
            )

    def test_manifest_footer_rejects_each_detached_count(self) -> None:
        prepared = self._prepare("footer-counts")
        manifest_path = prepared.snapshot_root / "control" / "manifest.jsonl"
        records = [json.loads(line) for line in manifest_path.read_bytes().splitlines()]
        expected = {
            "entry_count": 3,
            "file_count": 3,
            "gitlink_count": 0,
            "materialized_bytes": prepared.total_bytes,
            "regular_file_bytes": prepared.total_bytes,
            "regular_file_count": 3,
            "total_bytes": prepared.total_bytes,
        }
        for field, value in expected.items():
            self.assertEqual(value, records[-1][field])
            changed = [dict(record) for record in records]
            changed[-1][field] = value + 1
            payload = b"".join(
                sealed_snapshot_module._canonical_json(record) + b"\n"
                for record in changed
            )
            with self.subTest(field=field), self.assertRaisesRegex(
                SealedSnapshotError, "footer"
            ):
                sealed_snapshot_module._parse_manifest(
                    payload,
                    expected_task_id=TASK_ID,
                    expected_repo_url=REPO_URL,
                    expected_commit=self.commit,
                    policy=SnapshotPolicy(),
                )

    def test_canonical_json_rejects_lone_surrogate_as_structured_error(self) -> None:
        with self.assertRaisesRegex(SealedSnapshotError, "malformed"):
            sealed_snapshot_module._parse_canonical_json(
                b'{"value":"\\ud800"}\n', code="attestation_invalid"
            )

    def test_verifier_rejects_tree_tampering_extras_and_control_links(self) -> None:
        first = self._prepare("tampered")
        (first.agent_tree / "src" / "app.py").write_bytes(b"tampered\n")
        with self.assertRaises(SealedSnapshotError):
            self._verify("tampered")

        second = self._prepare("extra")
        (second.agent_tree / "extra.txt").write_text("extra", encoding="utf-8")
        with self.assertRaises(SealedSnapshotError):
            self._verify("extra")

        if hasattr(os, "symlink"):
            third = self._prepare("linked-control")
            manifest = third.snapshot_root / "control" / "manifest.jsonl"
            saved = third.snapshot_root / "saved-manifest.jsonl"
            manifest.replace(saved)
            try:
                os.symlink(saved, manifest)
            except (OSError, NotImplementedError):
                self.skipTest("creating symlinks is not permitted on this host")
            with self.assertRaises(SealedSnapshotError):
                self._verify("linked-control")

    def test_prepare_and_verify_materialize_git_symlinks_as_raw_regular_files(self) -> None:
        targets = (
            ("absolute-link", b"/etc/passwd"),
            ("parent-link", b"../../outside/source.py"),
        )
        symlink_commit = self._commit_git_symlinks(
            targets, message="Git symlink byte fixtures"
        )

        prepared = self._prepare("symlink-v2", commit=symlink_commit)
        records = {item.path: item for item in prepared.files}
        for path, target_bytes in targets:
            with self.subTest(path=path):
                materialized = prepared.agent_tree / path
                value = os.lstat(materialized)
                self.assertTrue(stat.S_ISREG(value.st_mode))
                self.assertFalse(stat.S_ISLNK(value.st_mode))
                self.assertEqual(target_bytes, materialized.read_bytes())
                self.assertEqual("120000", records[path].git_mode)
                if os.name == "posix":
                    self.assertEqual(0o600, stat.S_IMODE(value.st_mode))

        verified = self._verify(
            "symlink-v2", expected_commit=symlink_commit
        )
        self.assertEqual(prepared.files, verified.files)
        self.assertEqual(prepared.content_root, verified.content_root)
        self.assertEqual(prepared.manifest_sha256, verified.manifest_sha256)

    def test_verifier_rejects_tampered_materialized_git_symlink_bytes(self) -> None:
        symlink_commit = self._commit_git_symlinks(
            (("link", b"../src/app.py"),), message="Git symlink tamper fixture"
        )
        prepared = self._prepare("symlink-tamper", commit=symlink_commit)
        materialized = prepared.agent_tree / "link"
        self.assertFalse(materialized.is_symlink())
        materialized.write_bytes(b"changed-target")

        with self.assertRaises(SealedSnapshotError):
            self._verify("symlink-tamper", expected_commit=symlink_commit)

    def test_verifier_rejects_host_symlink_substitution_for_git_symlink_record(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("host has no symlink API")
        symlink_commit = self._commit_git_symlinks(
            (("link", b"../src/app.py"),), message="Git symlink substitution fixture"
        )
        prepared = self._prepare("symlink-substitution", commit=symlink_commit)
        materialized = prepared.agent_tree / "link"
        outside = self.root / "outside-target"
        outside.write_bytes(b"../src/app.py")
        materialized.unlink()
        try:
            os.symlink(outside, materialized)
        except (OSError, NotImplementedError):
            self.skipTest("creating host symlinks is not permitted")

        with self.assertRaises(SealedSnapshotError):
            self._verify("symlink-substitution", expected_commit=symlink_commit)

    def test_source_audit_accepts_git_symlink_representation_and_blocks_others(self) -> None:
        symlink_commit = self._commit_git_symlinks(
            (("link", b"../src/app.py"),), message="Git symlink audit fixture"
        )
        ready = audit_sealed_snapshot_source(self.repository, symlink_commit)
        self.assertTrue(ready.ready)
        self.assertEqual((), ready.status_codes)
        self.assertEqual(1, ready.symlink_count)
        self.assertEqual(0, ready.gitlink_count)
        self.assertEqual(0, ready.lfs_pointer_count)
        self.assertEqual(4, ready.regular_file_count)
        self.assertIn(("120000", 1), ready.mode_counts)

        size_only_cache: dict[str, tuple[int, bool | None]] = {}
        limited = audit_sealed_snapshot_source(
            self.repository,
            symlink_commit,
            policy=SnapshotPolicy(max_file_bytes=1),
            blob_cache=size_only_cache,
        )
        self.assertFalse(limited.ready)
        self.assertFalse(limited.lfs_scan_complete)
        self.assertIn("source_limit_exceeded", limited.status_codes)
        reused_unknown = audit_sealed_snapshot_source(
            self.repository, symlink_commit, blob_cache=size_only_cache
        )
        self.assertFalse(reused_unknown.ready)
        self.assertFalse(reused_unknown.lfs_scan_complete)

        self._git("rm", "-q", "--cached", "link")
        parent = self._git("rev-parse", "HEAD").stdout.strip()
        self._git(
            "update-index", "--add", "--cacheinfo", f"160000,{parent},submodule"
        )
        self._git("commit", "-q", "-m", "gitlink entry")
        gitlink_commit = self._git("rev-parse", "HEAD").stdout.strip()
        blocked_gitlink = audit_sealed_snapshot_source(
            self.repository, gitlink_commit
        )
        self.assertTrue(blocked_gitlink.ready)
        self.assertEqual(1, blocked_gitlink.gitlink_count)
        self.assertEqual((), blocked_gitlink.status_codes)

        self._git("rm", "-q", "--cached", "submodule")
        lfs_pointer = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:" + b"0" * 64 + b"\nsize 999\n"
        )
        lfs_commit = self._commit_git_symlinks(
            (("lfs-link", lfs_pointer),), message="Git symlink LFS pointer"
        )
        blocked_lfs = audit_sealed_snapshot_source(self.repository, lfs_commit)
        self.assertFalse(blocked_lfs.ready)
        self.assertEqual(1, blocked_lfs.lfs_pointer_count)
        self.assertEqual(1, blocked_lfs.symlink_count)
        self.assertIn("source_lfs_rejected", blocked_lfs.status_codes)
        with self.assertRaisesRegex(SealedSnapshotError, "LFS"):
            self._prepare("symlink-lfs", commit=lfs_commit)

    def test_prepare_materializes_gitlink_marker_and_still_rejects_lfs_pointer(self) -> None:
        parent = self._git("rev-parse", "HEAD").stdout.strip()
        self._git(
            "update-index", "--add", "--cacheinfo", f"160000,{parent},submodule"
        )
        self._git("commit", "-q", "-m", "gitlink entry")
        gitlink_commit = self._git("rev-parse", "HEAD").stdout.strip()
        prepared = self._prepare("gitlink", commit=gitlink_commit)
        marker = prepared.agent_tree / "submodule"
        self.assertEqual(b"gitlink " + parent.encode("ascii") + b"\n", marker.read_bytes())
        record = next(item for item in prepared.files if item.path == "submodule")
        self.assertEqual("gitlink", record.to_dict()["record_type"])
        self.assertEqual(parent, record.target_commit_oid)
        verified = self._verify("gitlink", expected_commit=gitlink_commit)
        self.assertEqual(prepared.files, verified.files)

        marker.write_bytes(b"gitlink " + ("f" * 40).encode("ascii") + b"\n")
        with self.assertRaises(SealedSnapshotError):
            self._verify("gitlink", expected_commit=gitlink_commit)

        self._git("rm", "-q", "--cached", "submodule")
        (self.repo_path / "large.bin").write_bytes(
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:" + b"0" * 64 + b"\nsize 999\n"
        )
        self._git("add", "large.bin")
        self._git("commit", "-q", "-m", "lfs pointer")
        lfs_commit = self._git("rev-parse", "HEAD").stdout.strip()
        with self.assertRaisesRegex(SealedSnapshotError, "LFS"):
            self._prepare("lfs", commit=lfs_commit)

    def test_gitlink_materialization_never_reads_child_as_blob(self) -> None:
        child = self._git("rev-parse", "HEAD").stdout.strip()
        self._git("update-index", "--add", "--cacheinfo", f"160000,{child},Peekaboo")
        self._git("commit", "-q", "-m", "metadata-only gitlink")
        commit = self._git("rev-parse", "HEAD").stdout.strip()
        with mock.patch.object(
            self.repository, "read_blob_object", wraps=self.repository.read_blob_object
        ) as reader:
            prepared = self._prepare("gitlink-no-child-read", commit=commit)
        self.assertNotIn(child, [call.args[0] for call in reader.call_args_list])
        self.assertEqual(
            b"gitlink " + child.encode("ascii") + b"\n",
            (prepared.agent_tree / "Peekaboo").read_bytes(),
        )

    def test_gitlink_marker_is_subject_to_file_and_materialized_budgets(self) -> None:
        child = self._git("rev-parse", "HEAD").stdout.strip()
        gitlink_tree = b"160000 submodule\0" + bytes.fromhex(child)
        gitlink_only = self._raw_commit(gitlink_tree)
        tight_file = SnapshotPolicy(max_file_bytes=48, max_total_bytes=48)
        audited = audit_sealed_snapshot_source(
            self.repository, gitlink_only, policy=tight_file
        )
        self.assertIn("source_limit_exceeded", audited.status_codes)
        with self.assertRaisesRegex(SealedSnapshotError, "byte budget"):
            self._prepare("gitlink-file-budget", commit=gitlink_only, policy=tight_file)

        blob = self._hash_object(b"x")
        mixed_tree = (
            b"100644 one.txt\0"
            + bytes.fromhex(blob)
            + b"160000 submodule\0"
            + bytes.fromhex(child)
        )
        mixed_commit = self._raw_commit(mixed_tree)
        tight_total = SnapshotPolicy(max_file_bytes=49, max_total_bytes=49)
        audited = audit_sealed_snapshot_source(
            self.repository, mixed_commit, policy=tight_total
        )
        self.assertIn("source_limit_exceeded", audited.status_codes)
        with self.assertRaisesRegex(SealedSnapshotError, "total byte budget"):
            self._prepare("gitlink-total-budget", commit=mixed_commit, policy=tight_total)

    def test_regular_blob_that_looks_like_gitlink_marker_remains_a_file(self) -> None:
        child = self._git("rev-parse", "HEAD").stdout.strip()
        marker = b"gitlink " + child.encode("ascii") + b"\n"
        blob = self._hash_object(marker)
        commit = self._raw_commit(b"100644 marker.txt\0" + bytes.fromhex(blob))
        prepared = self._prepare("marker-like-file", commit=commit)
        record = prepared.files[0]
        self.assertEqual("file", record.to_dict()["record_type"])
        self.assertEqual(marker, (prepared.agent_tree / "marker.txt").read_bytes())

    def test_prepare_rejects_non_nfc_reserved_and_casefold_collisions(self) -> None:
        blob = self._hash_object(b"unsafe")
        decomposed_name = "e\u0301.txt".encode("utf-8")
        decomposed_tree = b"100644 " + decomposed_name + b"\0" + bytes.fromhex(blob)
        decomposed_commit = self._raw_commit(decomposed_tree)
        with self.assertRaises(SealedSnapshotError):
            self._prepare("non-nfc", commit=decomposed_commit)

        reserved_tree = b"100644 CON.txt\0" + bytes.fromhex(blob)
        reserved_commit = self._raw_commit(reserved_tree)
        with self.assertRaises(SealedSnapshotError):
            self._prepare("reserved", commit=reserved_commit)

        first = b"100644 README\0" + bytes.fromhex(blob)
        second = b"100644 Readme\0" + bytes.fromhex(blob)
        collision_commit = self._raw_commit(first + second)
        with self.assertRaisesRegex(SealedSnapshotError, "collide"):
            self._prepare("collision", commit=collision_commit)

    def test_prepare_rejects_unsafe_or_empty_directory_nodes(self) -> None:
        empty_tree = self._hash_object(b"", object_type="tree")
        empty_directory = b"40000 empty\0" + bytes.fromhex(empty_tree)
        empty_commit = self._raw_commit(empty_directory)
        with self.assertRaisesRegex(SealedSnapshotError, "empty directory"):
            self._prepare("empty-directory", commit=empty_commit)

        administrative = b"40000 .GIT\0" + bytes.fromhex(empty_tree)
        administrative_tree = self._hash_object(
            administrative, object_type="tree", literally=True
        )
        administrative_commit = self._git(
            "commit-tree", administrative_tree, "-m", "administrative tree"
        ).stdout.strip()
        with self.assertRaisesRegex(SealedSnapshotError, "administrative"):
            self._prepare("administrative-directory", commit=administrative_commit)

    def test_policy_limits_fail_closed_and_rollback(self) -> None:
        policies = (
            SnapshotPolicy(max_files=1),
            SnapshotPolicy(max_file_bytes=4, max_total_bytes=100),
            SnapshotPolicy(max_file_bytes=32, max_total_bytes=32),
            SnapshotPolicy(
                max_path_bytes=5,
                max_component_bytes=5,
            ),
            SnapshotPolicy(max_manifest_bytes=8),
        )
        for number, policy in enumerate(policies):
            name = f"limited-{number}"
            with self.subTest(policy=policy), self.assertRaises(SealedSnapshotError):
                self._prepare(name, policy=policy)
            self.assertFalse((self.root / name).exists())
            self.assertEqual(
                [], list(self.root.glob(f".{name}.*.staging"))
            )

        failing = self.root / "read-failure"
        with mock.patch.object(
            self.repository,
            "read_blob_object",
            side_effect=GitFactError("injected read failure"),
        ), self.assertRaises(SealedSnapshotError):
            self._prepare("read-failure")
        self.assertFalse(failing.exists())
        self.assertEqual([], list(self.root.glob(".read-failure.*.staging")))

    def test_output_is_no_overwrite(self) -> None:
        output = self.root / "snapshot"
        output.mkdir()
        sentinel = output / "sentinel.txt"
        sentinel.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(SealedSnapshotError, "overwrite"):
            self._prepare()
        self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))

    def test_post_publish_check_failure_preserves_identity_safe_result(self) -> None:
        output = self.root / "post-publish-failure"
        original = sealed_snapshot_module._assert_parent_chain

        def fail_only_after_publication(checked) -> None:
            if output.exists():
                raise SealedSnapshotError(
                    "snapshot_parent_changed", "injected post-publication failure"
                )
            original(checked)

        with mock.patch.object(
            sealed_snapshot_module,
            "_assert_parent_chain",
            side_effect=fail_only_after_publication,
        ), self.assertRaises(SealedSnapshotError):
            self._prepare("post-publish-failure")

        if os.name == "posix":
            # POSIX has no portable rename-by-open-directory-handle.  Once the
            # no-replace rename commits, an uncertain post-check must leave the
            # published identity untouched instead of attempting a name-based
            # rollback.
            self.assertTrue(output.is_dir())
            self.assertEqual(3, self._verify("post-publish-failure").file_count)
        else:
            # Windows retains a delete-capable handle to the exact staging
            # directory, so it can safely roll back that identity.
            self.assertFalse(output.exists())
        self.assertEqual([], list(self.root.glob(".post-publish-failure.*.rollback")))

    @unittest.skipUnless(os.name == "posix", "POSIX publication identity test")
    def test_posix_post_publish_swap_never_moves_unknown_output(self) -> None:
        output = self.root / "posix-publish-swap"
        stolen = self.root / "stolen-legal-snapshot"
        original_stat = sealed_snapshot_module.os.stat
        swapped = False

        def swap_before_identity_check(path, *args, **kwargs):
            nonlocal swapped
            if (
                not swapped
                and path == output.name
                and kwargs.get("dir_fd") is not None
            ):
                os.rename(output, stolen)
                output.mkdir()
                (output / "evil.txt").write_text("evil", encoding="utf-8")
                swapped = True
            return original_stat(path, *args, **kwargs)

        with mock.patch.object(
            sealed_snapshot_module.os,
            "stat",
            side_effect=swap_before_identity_check,
        ), self.assertRaisesRegex(SealedSnapshotError, "publication"):
            self._prepare("posix-publish-swap")

        self.assertTrue(swapped)
        self.assertEqual("evil", (output / "evil.txt").read_text(encoding="utf-8"))
        self.assertTrue((stolen / "tree" / "src" / "app.py").is_file())
        self.assertEqual([], list(self.root.glob(".posix-publish-swap.*.rollback")))

    @unittest.skipUnless(os.name == "nt", "Windows handle publication test")
    def test_windows_publication_handle_blocks_staging_swap(self) -> None:
        original = sealed_snapshot_module._windows_rename_directory_handle
        attempts: list[OSError] = []

        def attempt_swap(handle: int, destination: Path) -> None:
            staging = next(self.root.glob(".handle-publish.*.staging"))
            try:
                staging.rename(self.root / "stolen-legal-staging")
            except OSError as error:
                attempts.append(error)
            else:  # pragma: no cover - this is the regression being prevented
                staging.mkdir()
                (staging / "evil.txt").write_text("evil", encoding="utf-8")
            original(handle, destination)

        with mock.patch.object(
            sealed_snapshot_module,
            "_windows_rename_directory_handle",
            side_effect=attempt_swap,
        ):
            prepared = self._prepare("handle-publish")

        self.assertTrue(attempts)
        self.assertFalse((prepared.snapshot_root / "evil.txt").exists())
        self.assertEqual(3, self._verify("handle-publish").file_count)

    @unittest.skipUnless(os.name == "nt", "NTFS stream verification test")
    def test_windows_verifier_rejects_named_data_streams(self) -> None:
        prepared = self._prepare("named-stream")
        stream = Path(str(prepared.agent_tree / "binary.dat") + ":hidden")
        try:
            stream.write_bytes(b"not part of the Git blob")
        except OSError as error:
            self.skipTest(f"named data streams are unavailable: {error}")
        with self.assertRaisesRegex(SealedSnapshotError, "named data streams"):
            self._verify("named-stream")

    def test_prepare_rechecks_alternates_and_rejects_shallow_repository(self) -> None:
        alternates = self.repo_path / ".git" / "objects" / "info" / "alternates"
        alternates.write_text(str(self.repo_path / ".git" / "objects"), encoding="utf-8")
        try:
            with self.assertRaises(GitFactError):
                self._prepare("alternates")
        finally:
            alternates.unlink()

        shallow_root = self.root / "shallow"
        subprocess.run(
            [
                "git",
                "clone",
                "-q",
                "--depth=1",
                self.repo_path.as_uri(),
                str(shallow_root),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        shallow_repository = GitRepository(shallow_root)
        shallow_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=shallow_root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()
        with self.assertRaisesRegex(SealedSnapshotError, "complete local"):
            self._prepare(
                "shallow-output",
                repository=shallow_repository,
                commit=shallow_commit,
            )


if __name__ == "__main__":
    unittest.main()
