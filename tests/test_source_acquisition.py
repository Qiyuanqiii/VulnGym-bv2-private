from __future__ import annotations

from dataclasses import replace
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock
import zlib

from vulngym_agent.benchmark.contracts import SnapshotTaskSpec
from vulngym_agent.benchmark.snapshot_batch import (
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    PROFILE_SCHEMA_VERSION,
)
from vulngym_agent.benchmark import source_acquisition
from vulngym_agent.benchmark.source_acquisition import (
    SOURCE_ACQUISITION_CONTRACT_VERSION,
    SourceAcquisitionError,
    SourceAcquisitionInput,
    github_fetch_url_v1,
    prepare_source_acquisition,
    verify_source_acquisition,
)


REPO_URL = "https://github.com/example/project"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _fetch_storage_seal(
    *,
    object_entry_count: int = 3,
    object_total_bytes: int = 300,
    object_inventory_sha256: str = "a" * 64,
    refs_entry_count: int = 0,
    refs_total_bytes: int = 0,
    refs_inventory_sha256: str = "b" * 64,
    shallow_sha256: str | None = None,
) -> source_acquisition.GitStorageSeal:
    return source_acquisition.GitStorageSeal(
        git_directory_identity=(1, 1),
        object_directory_identity=(1, 2),
        refs_directory_identity=(1, 3),
        pack_directory_identity=(1, 4),
        config_identity=(1, 5, 10, 100),
        head_identity=(1, 6, 10, 100),
        packed_refs_identity=None,
        object_entry_count=object_entry_count,
        object_total_bytes=object_total_bytes,
        object_inventory_sha256=object_inventory_sha256,
        refs_entry_count=refs_entry_count,
        refs_total_bytes=refs_total_bytes,
        refs_inventory_sha256=refs_inventory_sha256,
        shallow_sha256=shallow_sha256,
    )


class SourceAcquisitionIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        found = shutil.which("git")
        if found is None:
            raise unittest.SkipTest("Git is unavailable")
        cls.git = Path(found).resolve()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.origin = self.root / "origin"
        self.repository_store = self.root / "repositories"
        self.repository_store.mkdir()
        self.output = self.root / "controls"
        self.all_commits = self._make_origin(200)
        self.commits = self.all_commits[-70:]
        self.test_export, self.test_sha = self._write_export(
            "test", self.commits[:20]
        )
        self.train_export, self.train_sha = self._write_export(
            "train", self.commits[20:]
        )
        self.inputs = (
            SourceAcquisitionInput(self.test_export, self.test_sha),
            SourceAcquisitionInput(self.train_export, self.train_sha),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(
        self,
        *arguments: str,
        cwd: Path | None = None,
        input_data: bytes | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(
            (str(self.git), *arguments),
            cwd=str(cwd or self.root),
            input=input_data,
            stdin=subprocess.DEVNULL if input_data is None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        if check and result.returncode != 0:
            self.fail(
                f"fixture Git failed: {arguments!r}: "
                f"{result.stderr.decode(errors='replace')}"
            )
        return result

    def _make_origin(self, count: int) -> tuple[str, ...]:
        self._git("init", "--quiet", str(self.origin))
        self._git("config", "user.name", "VulnGym Test", cwd=self.origin)
        self._git("config", "user.email", "test@example.invalid", cwd=self.origin)
        stream = bytearray()
        timestamp = 1_700_000_000
        for index in range(count):
            blob_mark = (index * 2) + 1
            commit_mark = blob_mark + 1
            content = f"source revision {index}\n".encode("ascii")
            message = f"revision {index}".encode("ascii")
            stream.extend(b"blob\n")
            stream.extend(f"mark :{blob_mark}\n".encode("ascii"))
            stream.extend(f"data {len(content)}\n".encode("ascii"))
            stream.extend(content)
            stream.extend(b"commit refs/heads/main\n")
            stream.extend(f"mark :{commit_mark}\n".encode("ascii"))
            stream.extend(
                (
                    "committer VulnGym Test <test@example.invalid> "
                    f"{timestamp + index} +0000\n"
                ).encode("ascii")
            )
            stream.extend(f"data {len(message)}\n".encode("ascii"))
            stream.extend(message + b"\n")
            stream.extend(f"M 100644 :{blob_mark} source.txt\n\n".encode("ascii"))
        stream.extend(b"done\n")
        self._git("fast-import", "--quiet", cwd=self.origin, input_data=bytes(stream))
        revisions = self._git(
            "rev-list", "--reverse", "refs/heads/main", cwd=self.origin
        ).stdout.decode("ascii").splitlines()
        self.assertEqual(len(revisions), count)
        return tuple(revisions)

    def _write_export(
        self,
        split: str,
        commits: tuple[str, ...],
        *,
        directory_name: str | None = None,
    ) -> tuple[Path, str]:
        export = self.root / (directory_name or f"{split}-export")
        export.mkdir()
        tasks = [
            SnapshotTaskSpec(
                task_id=f"VG-{split.upper()}-{index:020X}",
                repo_url=REPO_URL,
                commit=commit,
                split=split,
            ).to_dict()
            for index, commit in enumerate(commits)
        ]
        payload = b"".join(_canonical(task) + b"\n" for task in tasks)
        digest = hashlib.sha256(payload).hexdigest()
        manifest = {
            "kind": "answer_free_task_export",
            "manifest_sha256": PROFILE_MANIFEST_SHA256,
            "profile_id": PROFILE_ID,
            "schema_version": PROFILE_SCHEMA_VERSION,
            "split": split,
            "task_count": len(tasks),
            "tasks_sha256": digest,
        }
        (export / "tasks.jsonl").write_bytes(payload)
        (export / "manifest.json").write_bytes(_canonical(manifest) + b"\n")
        return export, digest

    def _local_origin(self, repo_url: object, transport: object) -> str:
        self.assertEqual(repo_url, REPO_URL)
        self.assertIn(transport, {"https", "ssh"})
        return self.origin.as_uri()

    def _prepare(self):
        with mock.patch.object(
            source_acquisition,
            "github_fetch_url_v1",
            side_effect=self._local_origin,
        ):
            return prepare_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )

    def test_acquires_70_refs_writes_path_free_report_and_is_resumable(self) -> None:
        summary = self._prepare()
        self.assertEqual(summary.repository_count, 1)
        self.assertEqual(summary.task_count, 70)
        self.assertTrue(summary.ready)
        self.assertEqual(summary.ready_task_count, 70)
        self.assertEqual(summary.blocked_task_count, 0)
        self.assertEqual(
            [item.split for item in summary.source_maps], ["test", "train"]
        )
        self.assertEqual(
            set(item.name for item in self.output.iterdir()),
            {
                "acquisition-report.json",
                "test-source-map.json",
                "train-source-map.json",
            },
        )
        report_payload = (self.output / "acquisition-report.json").read_bytes()
        report = json.loads(report_payload)
        self.assertEqual(
            report["contract_version"], SOURCE_ACQUISITION_CONTRACT_VERSION
        )
        self.assertEqual(
            report["contract_version"], "vulngym.source-acquisition.v4"
        )
        self.assertEqual(report["github_transport"], "https")
        self.assertEqual(report["task_count"], 70)
        self.assertEqual(report["repository_count"], 1)
        self.assertRegex(
            report["git_version"], r"[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9A-Za-z-]+)*"
        )
        self.assertEqual(
            [item["source_map_sha256"] for item in report["exports"]],
            [item.source_map_sha256 for item in summary.source_maps],
        )
        self.assertEqual(report["fetch_protocol"]["initial_depth"], 32)
        self.assertEqual(report["fetch_protocol"]["deepen_by"], 32)
        self.assertEqual(
            report["fetch_protocol"][
                "max_transient_fetch_retries_per_repository"
            ],
            1,
        )
        self.assertTrue(report["fetch_protocol"]["requires_exact_ref_closure"])
        self.assertTrue(report["fetch_protocol"]["requires_final_full_fsck"])
        self.assertTrue(report["fetch_protocol"]["requires_final_non_shallow"])
        self.assertTrue(report["fetch_protocol"]["requires_strict_git_output"])
        self.assertTrue(report["fetch_protocol"]["requires_zero_garbage"])
        self.assertTrue(
            report["fetch_protocol"]["requires_zero_prune_packable"]
        )
        self.assertTrue(
            report["fetch_protocol"]["requires_zero_unreachable_objects"]
        )
        self.assertTrue(
            report["fetch_protocol"]["writes_verified_multi_pack_index"]
        )
        self.assertTrue(
            report["fetch_protocol"][
                "requires_final_verified_multi_pack_index"
            ]
        )
        self.assertTrue(
            report["fetch_protocol"][
                "retry_requires_unchanged_repository_seal"
            ]
        )
        self.assertTrue(report["ready"])
        self.assertEqual(report["ready_task_count"], 70)
        self.assertEqual(report["blocked_task_count"], 0)
        repository_report = report["repositories"][0]
        hygiene = repository_report["object_hygiene"]
        self.assertTrue(hygiene["all_objects_reachable"])
        self.assertTrue(hygiene["alternates_absent"])
        self.assertTrue(hygiene["bare_repository"])
        self.assertTrue(hygiene["full_fsck"])
        self.assertEqual(hygiene["garbage_count"], 0)
        self.assertEqual(hygiene["garbage_size_kib"], 0)
        self.assertTrue(hygiene["multi_pack_index_present"])
        self.assertTrue(hygiene["multi_pack_index_verified"])
        self.assertTrue(hygiene["non_shallow"])
        self.assertTrue(hygiene["promisor_absent"])
        self.assertEqual(hygiene["observed_ref_count"], 70)
        self.assertEqual(hygiene["prune_packable_count"], 0)
        self.assertEqual(hygiene["required_ref_count"], 70)
        self.assertTrue(hygiene["refs_closed"])
        self.assertTrue(hygiene["replace_refs_absent"])
        self.assertTrue(hygiene["sha1_object_format"])
        self.assertEqual(hygiene["unreachable_object_count"], 0)
        self.assertRegex(hygiene["ref_inventory_sha256"], r"[0-9a-f]{64}")
        self.assertRegex(hygiene["storage_inventory_sha256"], r"[0-9a-f]{64}")
        self.assertGreater(hygiene["storage_object_entry_count"], 0)
        self.assertGreater(hygiene["storage_object_total_bytes"], 0)
        self.assertEqual(
            hygiene["loose_object_count"] + hygiene["packed_object_count"],
            hygiene["stored_object_count"],
        )
        self.assertGreater(hygiene["pack_count"], 0)
        commit_audits = repository_report["commits"]
        self.assertEqual(len(commit_audits), 70)
        self.assertEqual(
            {audit["commit"] for audit in commit_audits}, set(self.commits)
        )
        for audit in commit_audits:
            self.assertTrue(audit["ready"])
            self.assertTrue(audit["scan_complete"])
            self.assertTrue(audit["lfs_scan_complete"])
            self.assertEqual(audit["mode_counts"], {"100644": 1})
            self.assertEqual(audit["regular_file_count"], 1)
            self.assertEqual(audit["symlink_count"], 0)
            self.assertEqual(audit["gitlink_count"], 0)
            self.assertEqual(audit["lfs_pointer_count"], 0)
            self.assertEqual(audit["status_codes"], [])

        def string_values(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, list):
                for item in value:
                    yield from string_values(item)
            elif isinstance(value, dict):
                for key, item in value.items():
                    yield key
                    yield from string_values(item)

        for value in string_values(report):
            self.assertNotIn(str(self.root).casefold(), value.casefold())
            self.assertNotIn(self.root.as_posix().casefold(), value.casefold())
        self.assertEqual(
            hashlib.sha256(report_payload).hexdigest(),
            summary.acquisition_report_sha256,
        )
        repository = self.repository_store / "example" / "project.git"
        refs = self._git("show-ref", cwd=repository).stdout.decode("ascii").splitlines()
        self.assertEqual(len(refs), 70)
        self.assertTrue(
            all(
                ref.split(" ", 1)[1]
                == f"refs/vulngym/{ref.split(' ', 1)[0]}"
                for ref in refs
            )
        )
        self.assertEqual(
            self._git(
                "rev-parse", "--is-shallow-repository", cwd=repository
            ).stdout,
            b"false\n",
        )
        self.assertFalse((repository / "objects" / "info" / "alternates").exists())
        self.assertFalse((repository / "shallow").exists())
        multi_pack_index = repository / "objects" / "pack" / "multi-pack-index"
        self.assertTrue(multi_pack_index.is_file())
        self._git(
            "multi-pack-index", "verify", cwd=repository
        )
        test_map = json.loads(
            (self.output / "test-source-map.json").read_bytes()
        )
        self.assertEqual(
            {record["repo_root"] for record in test_map["sources"]},
            {str(repository)},
        )

        real_run = source_acquisition._run_git
        fetches: list[tuple[str, ...]] = []
        multi_pack_operations: list[tuple[str, ...]] = []

        def traced_run(*args, **kwargs):
            arguments = tuple(args[2])
            if arguments and arguments[0] == "fetch":
                fetches.append(arguments)
            if arguments and arguments[0] == "multi-pack-index":
                multi_pack_operations.append(arguments)
            return real_run(*args, **kwargs)

        with mock.patch.object(source_acquisition, "_run_git", side_effect=traced_run):
            second = prepare_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertEqual(second, summary)
        self.assertEqual(fetches, [])
        self.assertIn(
            ("multi-pack-index", "write"),
            multi_pack_operations,
        )

        multi_pack_operations.clear()
        with mock.patch.object(source_acquisition, "_run_git", side_effect=traced_run):
            verified = verify_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertEqual(verified, summary)
        self.assertEqual(fetches, [])
        self.assertTrue(multi_pack_operations)
        self.assertFalse(
            any("write" in arguments for arguments in multi_pack_operations)
        )

    def test_single_pack_midx_is_verified_and_corruption_is_read_only(self) -> None:
        repository_root = self.root / "single-pack.git"
        self._git("init", "--quiet", "--bare", str(repository_root))
        commit = self.all_commits[-1]
        self._git(
            "fetch",
            "--atomic",
            "--force",
            "--no-progress",
            "--no-recurse-submodules",
            "--no-tags",
            "--no-write-fetch-head",
            self.origin.as_uri(),
            f"+{commit}:refs/vulngym/{commit}",
            cwd=repository_root,
        )
        self._git("repack", "-ad", cwd=repository_root)
        pack_root = repository_root / "objects" / "pack"
        self.assertEqual(len(tuple(pack_root.glob("*.pack"))), 1)
        repository = source_acquisition.GitRepository(
            repository_root,
            timeout_seconds=30,
            git_executable=self.git,
        )
        source_acquisition._write_verified_multi_pack_index(
            repository_root,
            repository,
            git_executable=self.git,
            github_transport="https",
            ssh_executable=None,
        )
        multi_pack_index = pack_root / "multi-pack-index"
        self.assertTrue(multi_pack_index.is_file())
        self._git("multi-pack-index", "verify", cwd=repository_root)

        corrupted = bytearray(multi_pack_index.read_bytes())
        self.assertGreater(len(corrupted), 12)
        corrupted[-1] ^= 1
        multi_pack_index.write_bytes(corrupted)
        with self.assertRaises(SourceAcquisitionError) as captured:
            source_acquisition._verify_multi_pack_index(
                repository_root,
                repository,
                git_executable=self.git,
                github_transport="https",
                ssh_executable=None,
                status=4,
            )
        self.assertEqual(
            captured.exception.code, "multi_pack_index_verify_failed"
        )
        self.assertEqual(captured.exception.exit_status, 4)
        self.assertEqual(multi_pack_index.read_bytes(), corrupted)

    def test_post_publish_global_closure_failure_is_uncertain(self) -> None:
        failure = SourceAcquisitionError(
            "repository_changed",
            "simulated post-publication repository change",
            exit_status=4,
        )
        with mock.patch.object(
            source_acquisition,
            "_assert_all_repository_closures_unchanged",
            side_effect=(None, failure),
        ), self.assertRaises(SourceAcquisitionError) as captured:
            self._prepare()

        self.assertEqual(captured.exception.code, "publication_uncertain")
        self.assertEqual(captured.exception.exit_status, 5)
        self.assertIs(captured.exception.__cause__, failure)
        self.assertTrue(self.output.is_dir())
        self.assertTrue((self.output / "acquisition-report.json").is_file())

    def test_summary_construction_failure_precedes_publication(self) -> None:
        failure = RuntimeError("simulated summary construction failure")
        with mock.patch.object(
            source_acquisition,
            "SourceAcquisitionSummary",
            side_effect=failure,
        ), self.assertRaises(RuntimeError) as captured:
            self._prepare()

        self.assertIs(captured.exception, failure)
        self.assertFalse(self.output.exists())

    def test_ref_rebinding_is_rejected(self) -> None:
        self._prepare()
        repository = self.repository_store / "example" / "project.git"
        self._git(
            "update-ref",
            f"refs/vulngym/{self.commits[0]}",
            self.commits[1],
            cwd=repository,
        )
        with self.assertRaises(SourceAcquisitionError) as captured:
            verify_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertEqual(captured.exception.code, "repository_refs_rejected")

    def test_extra_well_formed_vulngym_ref_is_rejected(self) -> None:
        self._prepare()
        repository = self.repository_store / "example" / "project.git"
        extra = self.all_commits[0]
        self.assertNotIn(extra, self.commits)
        self._git(
            "update-ref",
            f"refs/vulngym/{extra}",
            extra,
            cwd=repository,
        )
        with self.assertRaises(SourceAcquisitionError) as captured:
            verify_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertEqual(captured.exception.code, "ref_closure_mismatch")

    def test_git_count_objects_garbage_is_rejected(self) -> None:
        self._prepare()
        repository = self.repository_store / "example" / "project.git"
        garbage = repository / "objects" / "pack" / "unexpected-garbage"
        garbage.write_bytes(b"not a Git pack artifact")
        with self.assertRaises(SourceAcquisitionError) as captured:
            verify_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertEqual(captured.exception.code, "object_storage_garbage")

    def test_prune_packable_loose_duplicate_is_rejected(self) -> None:
        self._prepare()
        repository = self.repository_store / "example" / "project.git"
        object_id = self.commits[-1]
        object_type = self._git(
            "cat-file", "-t", object_id, cwd=repository
        ).stdout.strip()
        body = self._git(
            "cat-file", object_type.decode("ascii"), object_id, cwd=repository
        ).stdout
        loose_payload = (
            object_type
            + b" "
            + str(len(body)).encode("ascii")
            + b"\0"
            + body
        )
        self.assertEqual(
            hashlib.sha1(loose_payload, usedforsecurity=False).hexdigest(),
            object_id,
        )
        loose = repository / "objects" / object_id[:2] / object_id[2:]
        loose.parent.mkdir(exist_ok=True)
        loose.write_bytes(zlib.compress(loose_payload))
        count = self._git("count-objects", "-v", cwd=repository).stdout
        self.assertIn(b"prune-packable: 1\n", count)

        with self.assertRaises(SourceAcquisitionError) as captured:
            verify_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertEqual(captured.exception.code, "prune_packable_objects_rejected")

    def test_unreachable_object_is_rejected(self) -> None:
        self._prepare()
        repository = self.repository_store / "example" / "project.git"
        unreachable = self._git(
            "hash-object",
            "-w",
            "--stdin",
            cwd=repository,
            input_data=b"unreachable source-acquisition test object\n",
        ).stdout.decode("ascii").strip()
        self.assertRegex(unreachable, r"[0-9a-f]{40}")

        with self.assertRaises(SourceAcquisitionError) as captured:
            verify_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertEqual(captured.exception.code, "unreachable_objects_rejected")

    def test_interrupted_deepen_preserves_completed_segments_and_resumes(self) -> None:
        real_run = source_acquisition._run_git
        deepen_calls = 0

        def interrupted_run(*args, **kwargs):
            nonlocal deepen_calls
            arguments = tuple(args[2])
            if arguments and arguments[0] == "fetch" and any(
                value == "--deepen=32" for value in arguments
            ):
                deepen_calls += 1
                if deepen_calls in {2, 3}:
                    raise SourceAcquisitionError(
                        "git_command_failed",
                        "simulated connection interruption",
                        exit_status=3,
                    )
            return real_run(*args, **kwargs)

        with mock.patch.object(
            source_acquisition,
            "github_fetch_url_v1",
            side_effect=self._local_origin,
        ), mock.patch.object(
            source_acquisition, "_run_git", side_effect=interrupted_run
        ), self.assertRaises(SourceAcquisitionError) as captured:
            prepare_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertEqual(captured.exception.code, "git_command_failed")
        self.assertFalse(self.output.exists())
        repository = self.repository_store / "example" / "project.git"
        shallow = repository / "shallow"
        self.assertTrue(shallow.is_file())
        completed_boundary = hashlib.sha256(shallow.read_bytes()).hexdigest()
        # The second segment consumes the one repository-wide retry token and
        # then fails closed, preserving the first completed deepen for resume.
        self.assertEqual(deepen_calls, 3)

        resumed_fetches: list[tuple[str, ...]] = []

        def resumed_run(*args, **kwargs):
            arguments = tuple(args[2])
            if arguments and arguments[0] == "fetch":
                resumed_fetches.append(arguments)
            return real_run(*args, **kwargs)

        with mock.patch.object(
            source_acquisition,
            "github_fetch_url_v1",
            side_effect=self._local_origin,
        ), mock.patch.object(
            source_acquisition, "_run_git", side_effect=resumed_run
        ):
            summary = prepare_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertTrue(summary.ready)
        self.assertTrue(resumed_fetches)
        self.assertTrue(
            all("--depth=32" not in arguments for arguments in resumed_fetches)
        )
        self.assertTrue(
            all("--deepen=32" in arguments for arguments in resumed_fetches)
        )
        self.assertRegex(completed_boundary, r"[0-9a-f]{64}")
        self.assertFalse(shallow.exists())
        self.assertEqual(
            self._git(
                "rev-parse", "--is-shallow-repository", cwd=repository
            ).stdout,
            b"false\n",
        )

    def test_local_config_transport_rewrite_is_rejected(self) -> None:
        self._prepare()
        repository = self.repository_store / "example" / "project.git"
        self._git(
            "config",
            "url.file:///unexpected.insteadOf",
            "https://github.com/",
            cwd=repository,
        )
        with self.assertRaises(SourceAcquisitionError) as captured:
            verify_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertEqual(captured.exception.code, "repository_config_rejected")

    def test_output_tampering_is_rejected_without_fetch(self) -> None:
        self._prepare()
        report = self.output / "acquisition-report.json"
        report.write_bytes(report.read_bytes() + b" ")
        with self.assertRaises(SourceAcquisitionError) as captured:
            verify_source_acquisition(
                self.inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertEqual(captured.exception.code, "output_binding_mismatch")

    def test_cross_split_snapshot_collision_fails_before_repository_creation(self) -> None:
        duplicate_train, duplicate_sha = self._write_export(
            "train",
            (self.commits[0], *self.commits[21:70]),
            directory_name="duplicate-train-export",
        )
        inputs = (
            SourceAcquisitionInput(self.test_export, self.test_sha),
            SourceAcquisitionInput(duplicate_train, duplicate_sha),
        )
        with self.assertRaises(SourceAcquisitionError) as captured:
            prepare_source_acquisition(
                inputs,
                repository_store=self.repository_store,
                output_dir=self.output,
                git_executable=self.git,
            )
        self.assertEqual(captured.exception.code, "cross_export_collision")
        self.assertEqual(list(self.repository_store.iterdir()), [])


class SourceAcquisitionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        found = shutil.which("git")
        if found is None:
            raise unittest.SkipTest("Git is unavailable")
        cls.git = Path(found).resolve()

    def test_git_version_output_is_strict_and_reportable(self) -> None:
        completed = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=b"git version 2.51.0.windows.1\n",
            stderr=b"",
        )
        with mock.patch.object(
            source_acquisition, "_run_git", return_value=completed
        ):
            self.assertEqual(
                source_acquisition._read_git_version(
                    self.git,
                    github_transport="https",
                    ssh_executable=None,
                ),
                "2.51.0.windows.1",
            )

        for stdout, stderr in (
            (b"git version 2.51\n", b""),
            (b"git version 2.51.0\nextra\n", b""),
            (b"git version 2.51.0\n", b"warning\n"),
        ):
            with self.subTest(stdout=stdout, stderr=stderr), mock.patch.object(
                source_acquisition,
                "_run_git",
                return_value=subprocess.CompletedProcess(
                    args=(), returncode=0, stdout=stdout, stderr=stderr
                ),
            ), self.assertRaises(SourceAcquisitionError) as captured:
                source_acquisition._read_git_version(
                    self.git,
                    github_transport="https",
                    ssh_executable=None,
                )
            self.assertEqual(captured.exception.code, "git_version_rejected")

    def test_show_ref_rejects_foreign_loose_replace_and_packed_refs(self) -> None:
        allowed = "1" * 40
        allowed_line = f"{allowed} refs/vulngym/{allowed}\n"
        cases = {
            "loose branch": f"{allowed} refs/heads/main\n",
            "replace ref": f"{allowed} refs/replace/{'2' * 40}\n",
            # show-ref flattens loose and packed storage to the same wire form;
            # this case represents a foreign name read from packed-refs.
            "packed tag": f"{allowed} refs/tags/packed-only\n",
        }
        for label, foreign_line in cases.items():
            completed = subprocess.CompletedProcess(
                args=(),
                returncode=0,
                stdout=(allowed_line + foreign_line).encode("ascii"),
                stderr=b"",
            )
            with self.subTest(label=label), mock.patch.object(
                source_acquisition,
                "_run_git",
                return_value=completed,
            ) as runner, self.assertRaises(SourceAcquisitionError) as captured:
                source_acquisition._read_vulngym_refs(
                    Path("C:/trusted/repository.git"),
                    git_executable=Path("C:/trusted/git.exe"),
                    github_transport="https",
                    ssh_executable=None,
                    status=4,
                )
            self.assertEqual(captured.exception.code, "repository_refs_rejected")
            self.assertEqual(captured.exception.exit_status, 4)
            self.assertEqual(runner.call_args.args[2], ("show-ref",))

    def test_global_union_recheck_detects_earlier_repository_mutation(self) -> None:
        first_url = "https://github.com/example/project-a"
        second_url = "https://github.com/example/project-b"
        first_commit = "1" * 40
        second_commit = "2" * 40
        first_refs = {f"refs/vulngym/{first_commit}": first_commit}
        second_refs = {f"refs/vulngym/{second_commit}": second_commit}
        counts = {"count": 1}
        first_captured_seal = object()
        first_mutated_seal = object()
        second_seal = object()
        first_repository = mock.Mock(spec=source_acquisition.GitRepository)
        first_repository.assert_bare_storage_safe.return_value = (
            first_mutated_seal
        )
        first_repository.history_is_shallow.return_value = False
        second_repository = mock.Mock(spec=source_acquisition.GitRepository)
        second_repository.assert_bare_storage_safe.return_value = second_seal
        second_repository.history_is_shallow.return_value = False
        roots = {
            first_url: Path("C:/trusted/project-a.git"),
            second_url: Path("C:/trusted/project-b.git"),
        }
        repositories = {
            first_url: first_repository,
            second_url: second_repository,
        }
        groups = {
            first_url: (first_commit,),
            second_url: (second_commit,),
        }
        expected = {
            first_url: source_acquisition._repository_closure_v2(
                storage_seal=first_captured_seal,
                refs=first_refs,
                counts=counts,
            ),
            second_url: source_acquisition._repository_closure_v2(
                storage_seal=second_seal,
                refs=second_refs,
                counts=counts,
            ),
        }

        def refs_for_root(root, **_kwargs):
            return first_refs if root == roots[first_url] else second_refs

        with mock.patch.object(
            source_acquisition, "_assert_recovery_state_clean"
        ), mock.patch.object(
            source_acquisition, "_assert_acquisition_config"
        ), mock.patch.object(
            source_acquisition, "_verify_multi_pack_index"
        ), mock.patch.object(
            source_acquisition, "_read_vulngym_refs", side_effect=refs_for_root
        ), mock.patch.object(
            source_acquisition, "_read_count_objects", return_value=counts
        ), self.assertRaises(SourceAcquisitionError) as captured:
            source_acquisition._assert_all_repository_closures_unchanged(
                roots,
                repositories,
                groups,
                expected,
                git_executable=self.git,
                github_transport="https",
                ssh_executable=None,
                status=4,
            )
        self.assertEqual(captured.exception.code, "repository_changed")
        self.assertEqual(captured.exception.exit_status, 4)
        second_repository.assert_bare_storage_safe.assert_not_called()

    def test_fetch_is_exact_atomic_segmented_and_has_no_checkout_surface(self) -> None:
        commit = "1" * 40
        repository = mock.Mock(spec=source_acquisition.GitRepository)
        repository.capture_storage_seal.return_value = _fetch_storage_seal()
        failure = SourceAcquisitionError(
            "git_command_failed", "simulated network failure", exit_status=3
        )
        with mock.patch.object(
            source_acquisition, "_run_git", side_effect=failure
        ) as runner, mock.patch.object(
            source_acquisition, "_assert_recovery_state_clean"
        ), mock.patch.object(
            source_acquisition, "_read_vulngym_refs", return_value={}
        ), self.assertRaises(SourceAcquisitionError):
            source_acquisition._fetch_missing_commits(
                Path("C:/trusted/repository.git"),
                repository,
                repo_url=REPO_URL,
                commits=(commit,),
                refs={},
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="ssh",
                ssh_executable=Path("C:/trusted/ssh.exe"),
            )
        self.assertEqual(runner.call_count, 2)
        first_arguments = runner.call_args_list[0].args[2]
        arguments = runner.call_args_list[1].args[2]
        self.assertEqual(arguments, first_arguments)
        self.assertEqual(arguments[0], "fetch")
        for required in (
            "--atomic",
            "--depth=32",
            "--force",
            "--no-recurse-submodules",
            "--no-tags",
            "--no-write-fetch-head",
        ):
            self.assertIn(required, arguments)
        self.assertIn("git@github.com:example/project.git", arguments)
        self.assertIn(f"+{commit}:refs/vulngym/{commit}", arguments)
        self.assertFalse(
            any(
                argument.startswith(("--filter", "--shallow"))
                for argument in arguments
            )
        )

    def test_one_transient_fetch_failure_retries_with_same_arguments(self) -> None:
        commit = "1" * 40
        ref_name = f"refs/vulngym/{commit}"
        refs = {ref_name: commit}
        before = _fetch_storage_seal()
        repository = mock.Mock(spec=source_acquisition.GitRepository)
        repository.capture_storage_seal.side_effect = (
            before,
            before,
            before,
            before,
            before,
            before,
            before,
            before,
        )
        repository.history_is_shallow.return_value = False
        failure = SourceAcquisitionError(
            "git_command_failed", "simulated transient failure", exit_status=3
        )
        completed = subprocess.CompletedProcess(
            args=(), returncode=0, stdout=b"", stderr=b""
        )
        with mock.patch.object(
            source_acquisition, "_run_git", side_effect=(failure, completed)
        ) as runner, mock.patch.object(
            source_acquisition, "_assert_recovery_state_clean"
        ), mock.patch.object(
            source_acquisition,
            "_read_vulngym_refs",
            side_effect=({}, {}, refs, refs),
        ), mock.patch.object(
            source_acquisition, "_write_verified_multi_pack_index"
        ):
            source_acquisition._fetch_missing_commits(
                Path("C:/trusted/repository.git"),
                repository,
                repo_url=REPO_URL,
                commits=(commit,),
                refs={},
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="https",
                ssh_executable=None,
            )
        self.assertEqual(runner.call_count, 2)
        self.assertEqual(
            runner.call_args_list[0].args[2], runner.call_args_list[1].args[2]
        )
        repository.commit_tree.assert_called_once_with(commit)

    def test_transient_retry_token_is_shared_across_fetch_segments(self) -> None:
        commit = "1" * 40
        refs = {f"refs/vulngym/{commit}": commit}
        before = _fetch_storage_seal()
        shallow = replace(before, shallow_sha256="c" * 64)
        repository = mock.Mock(spec=source_acquisition.GitRepository)
        repository.capture_storage_seal.side_effect = (
            before,
            before,
            before,
            before,
            shallow,
            shallow,
            shallow,
            shallow,
        )
        repository.history_is_shallow.return_value = True
        first_failure = SourceAcquisitionError(
            "git_command_failed", "initial transient failure", exit_status=3
        )
        deepen_failure = SourceAcquisitionError(
            "git_command_failed", "deepen transient failure", exit_status=3
        )
        completed = subprocess.CompletedProcess(
            args=(), returncode=0, stdout=b"", stderr=b""
        )
        with mock.patch.object(
            source_acquisition,
            "_run_git",
            side_effect=(first_failure, completed, deepen_failure),
        ) as runner, mock.patch.object(
            source_acquisition, "_assert_recovery_state_clean"
        ), mock.patch.object(
            source_acquisition,
            "_read_vulngym_refs",
            side_effect=({}, {}, refs, refs),
        ), self.assertRaises(SourceAcquisitionError) as captured:
            source_acquisition._fetch_missing_commits(
                Path("C:/trusted/repository.git"),
                repository,
                repo_url=REPO_URL,
                commits=(commit,),
                refs={},
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="https",
                ssh_executable=None,
            )
        self.assertIs(captured.exception, deepen_failure)
        self.assertEqual(runner.call_count, 3)
        self.assertEqual(
            runner.call_args_list[0].args[2], runner.call_args_list[1].args[2]
        )
        self.assertIn("--deepen=32", runner.call_args_list[2].args[2])

    def test_transient_fetch_retry_uses_the_original_network_budget(self) -> None:
        commit = "1" * 40
        refs = {f"refs/vulngym/{commit}": commit}
        seal = _fetch_storage_seal()
        repository = mock.Mock(spec=source_acquisition.GitRepository)
        repository.capture_storage_seal.return_value = seal
        repository.history_is_shallow.return_value = False
        failure = SourceAcquisitionError(
            "git_command_failed", "simulated transient failure", exit_status=3
        )
        completed = subprocess.CompletedProcess(
            args=(), returncode=0, stdout=b"", stderr=b""
        )
        with mock.patch.object(
            source_acquisition, "_run_git", side_effect=(failure, completed)
        ) as runner, mock.patch.object(
            source_acquisition, "_assert_recovery_state_clean"
        ), mock.patch.object(
            source_acquisition,
            "_read_vulngym_refs",
            side_effect=({}, {}, refs, refs),
        ), mock.patch.object(
            source_acquisition, "_write_verified_multi_pack_index"
        ), mock.patch.object(
            source_acquisition.time,
            "monotonic",
            side_effect=(0.0, 19_000.0, 21_000.0, 21_001.0),
        ):
            source_acquisition._fetch_missing_commits(
                Path("C:/trusted/repository.git"),
                repository,
                repo_url=REPO_URL,
                commits=(commit,),
                refs={},
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="https",
                ssh_executable=None,
            )
        self.assertEqual(
            [call.kwargs["timeout_seconds"] for call in runner.call_args_list],
            [2_600.0, 600.0],
        )

    def test_fetch_retry_rejects_changed_control_plane(self) -> None:
        commit = "1" * 40
        before = _fetch_storage_seal()
        cases = {
            "logical-refs": (
                before,
                {f"refs/vulngym/{'2' * 40}": "2" * 40},
            ),
            "refs-storage": (
                replace(
                    before,
                    refs_entry_count=1,
                    refs_total_bytes=41,
                    refs_inventory_sha256="9" * 64,
                ),
                {},
            ),
            "shallow": (replace(before, shallow_sha256="d" * 64), {}),
            "identity": (
                replace(before, config_identity=(1, 50, 10, 100)),
                {},
            ),
            "object-shrink": (
                replace(
                    before,
                    object_entry_count=before.object_entry_count - 1,
                    object_total_bytes=before.object_total_bytes - 1,
                    object_inventory_sha256="e" * 64,
                ),
                {},
            ),
            "object-replacement-without-growth": (
                replace(before, object_inventory_sha256="f" * 64),
                {},
            ),
            "object-replacement-with-aggregate-growth": (
                replace(
                    before,
                    object_entry_count=before.object_entry_count + 2,
                    object_total_bytes=before.object_total_bytes + 500,
                    object_inventory_sha256="7" * 64,
                ),
                {},
            ),
        }
        for label, (changed, changed_refs) in cases.items():
            with self.subTest(label=label):
                repository = mock.Mock(spec=source_acquisition.GitRepository)
                repository.capture_storage_seal.side_effect = (
                    before,
                    before,
                    changed,
                    changed,
                )
                failure = SourceAcquisitionError(
                    "git_command_failed",
                    "simulated transient failure",
                    exit_status=3,
                )
                with mock.patch.object(
                    source_acquisition, "_run_git", side_effect=failure
                ) as runner, mock.patch.object(
                    source_acquisition, "_assert_recovery_state_clean"
                ), mock.patch.object(
                    source_acquisition,
                    "_read_vulngym_refs",
                    side_effect=({}, changed_refs),
                ), self.assertRaises(SourceAcquisitionError) as captured:
                    source_acquisition._fetch_missing_commits(
                        Path("C:/trusted/repository.git"),
                        repository,
                        repo_url=REPO_URL,
                        commits=(commit,),
                        refs={},
                        git_executable=Path("C:/trusted/git.exe"),
                        github_transport="https",
                        ssh_executable=None,
                    )
                self.assertEqual(captured.exception.code, "repository_changed")
                self.assertEqual(runner.call_count, 1)

    def test_nontransient_fetch_failures_and_interrupts_are_not_retried(self) -> None:
        commit = "1" * 40
        failures: tuple[BaseException, ...] = (
            SourceAcquisitionError("git_timeout", "timeout", exit_status=3),
            SourceAcquisitionError(
                "git_output_limit", "output limit", exit_status=3
            ),
            SourceAcquisitionError(
                "git_unavailable", "unavailable", exit_status=3
            ),
            KeyboardInterrupt(),
            SystemExit(7),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                repository = mock.Mock(spec=source_acquisition.GitRepository)
                repository.capture_storage_seal.return_value = _fetch_storage_seal()
                with mock.patch.object(
                    source_acquisition, "_run_git", side_effect=failure
                ) as runner, mock.patch.object(
                    source_acquisition, "_assert_recovery_state_clean"
                ), mock.patch.object(
                    source_acquisition, "_read_vulngym_refs", return_value={}
                ), self.assertRaises(type(failure)) as captured:
                    source_acquisition._fetch_missing_commits(
                        Path("C:/trusted/repository.git"),
                        repository,
                        repo_url=REPO_URL,
                        commits=(commit,),
                        refs={},
                        git_executable=Path("C:/trusted/git.exe"),
                        github_transport="https",
                        ssh_executable=None,
                    )
                self.assertIs(captured.exception, failure)
                self.assertEqual(runner.call_count, 1)

    def test_fetch_failure_preserves_cleanup_required(self) -> None:
        commit = "1" * 40
        for failure in (
            SourceAcquisitionError(
                "git_command_failed", "simulated transient failure", exit_status=3
            ),
            KeyboardInterrupt(),
        ):
            with self.subTest(failure=type(failure).__name__):
                repository = mock.Mock(spec=source_acquisition.GitRepository)
                repository.capture_storage_seal.return_value = (
                    _fetch_storage_seal()
                )
                cleanup = SourceAcquisitionError(
                    "cleanup_required", "simulated lock residue", exit_status=3
                )
                with mock.patch.object(
                    source_acquisition, "_run_git", side_effect=failure
                ) as runner, mock.patch.object(
                    source_acquisition,
                    "_assert_recovery_state_clean",
                    side_effect=(None, None, cleanup),
                ), mock.patch.object(
                    source_acquisition, "_read_vulngym_refs", return_value={}
                ), self.assertRaises(SourceAcquisitionError) as captured:
                    source_acquisition._fetch_missing_commits(
                        Path("C:/trusted/repository.git"),
                        repository,
                        repo_url=REPO_URL,
                        commits=(commit,),
                        refs={},
                        git_executable=Path("C:/trusted/git.exe"),
                        github_transport="https",
                        ssh_executable=None,
                    )
                self.assertIs(captured.exception, cleanup)
                self.assertIs(captured.exception.__cause__, failure)
                self.assertEqual(runner.call_count, 1)

    def test_multi_pack_index_is_verified_and_preserves_repository_facts(self) -> None:
        commit = "1" * 40
        refs = {f"refs/vulngym/{commit}": commit}
        counts = {
            "count": 0,
            "size": 0,
            "in-pack": 10,
            "packs": 2,
            "size-pack": 1,
            "prune-packable": 0,
            "garbage": 0,
            "size-garbage": 0,
        }
        repository = mock.Mock(spec=source_acquisition.GitRepository)
        repository.history_is_shallow.side_effect = (False, False)
        storage_seal = object()
        repository.capture_storage_seal.return_value = storage_seal
        completed = subprocess.CompletedProcess(
            args=(), returncode=0, stdout=b"", stderr=b""
        )
        with mock.patch.object(
            source_acquisition, "_assert_recovery_state_clean"
        ) as recovery, mock.patch.object(
            source_acquisition, "_read_vulngym_refs", return_value=refs
        ) as read_refs, mock.patch.object(
            source_acquisition, "_read_count_objects", return_value=counts
        ) as read_counts, mock.patch.object(
            source_acquisition,
            "_capture_pack_payload_inventory",
            return_value=(4, 100, "a" * 64),
        ) as pack_inventory, mock.patch.object(
            source_acquisition,
            "_assert_multi_pack_index_file",
            return_value=(1, 2, 3, 4),
        ) as index_file, mock.patch.object(
            source_acquisition, "_run_git", return_value=completed
        ) as runner:
            source_acquisition._write_verified_multi_pack_index(
                Path("C:/trusted/repository.git"),
                repository,
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="https",
                ssh_executable=None,
            )
        self.assertEqual(
            [call.args[2] for call in runner.call_args_list],
            [
                ("multi-pack-index", "write"),
                ("multi-pack-index", "verify"),
            ],
        )
        self.assertGreaterEqual(recovery.call_count, 6)
        self.assertEqual(read_refs.call_count, 2)
        self.assertEqual(read_counts.call_count, 2)
        self.assertEqual(pack_inventory.call_count, 4)
        self.assertEqual(index_file.call_count, 3)
        self.assertEqual(repository.history_is_shallow.call_count, 2)
        self.assertEqual(repository.capture_storage_seal.call_count, 2)

    def test_multi_pack_index_rejects_changed_object_counts(self) -> None:
        refs = {"refs/vulngym/" + "1" * 40: "1" * 40}
        before = {
            "count": 0,
            "size": 0,
            "in-pack": 10,
            "packs": 2,
            "size-pack": 1,
            "prune-packable": 0,
            "garbage": 0,
            "size-garbage": 0,
        }
        after = dict(before, packs=3)
        repository = mock.Mock(spec=source_acquisition.GitRepository)
        repository.history_is_shallow.side_effect = (False, False)
        completed = subprocess.CompletedProcess(
            args=(), returncode=0, stdout=b"", stderr=b""
        )
        with mock.patch.object(
            source_acquisition, "_assert_recovery_state_clean"
        ), mock.patch.object(
            source_acquisition, "_read_vulngym_refs", return_value=refs
        ), mock.patch.object(
            source_acquisition, "_read_count_objects", side_effect=(before, after)
        ), mock.patch.object(
            source_acquisition,
            "_capture_pack_payload_inventory",
            return_value=(4, 100, "a" * 64),
        ), mock.patch.object(
            source_acquisition,
            "_assert_multi_pack_index_file",
            return_value=(1, 2, 3, 4),
        ), mock.patch.object(
            source_acquisition, "_run_git", return_value=completed
        ), self.assertRaises(SourceAcquisitionError) as captured:
            source_acquisition._write_verified_multi_pack_index(
                Path("C:/trusted/repository.git"),
                repository,
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="https",
                ssh_executable=None,
            )
        self.assertEqual(captured.exception.code, "repository_changed")

    def test_multi_pack_index_requires_at_least_one_pack(self) -> None:
        counts = {
            "count": 3,
            "size": 1,
            "in-pack": 0,
            "packs": 0,
            "size-pack": 0,
            "prune-packable": 0,
            "garbage": 0,
            "size-garbage": 0,
        }
        repository = mock.Mock(spec=source_acquisition.GitRepository)
        repository.history_is_shallow.return_value = False
        with mock.patch.object(
            source_acquisition, "_assert_recovery_state_clean"
        ), mock.patch.object(
            source_acquisition, "_read_vulngym_refs", return_value={}
        ), mock.patch.object(
            source_acquisition, "_read_count_objects", return_value=counts
        ), mock.patch.object(
            source_acquisition, "_run_git"
        ) as runner, self.assertRaises(SourceAcquisitionError) as captured:
            source_acquisition._write_verified_multi_pack_index(
                Path("C:/trusted/repository.git"),
                repository,
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="https",
                ssh_executable=None,
            )
        self.assertEqual(captured.exception.code, "packed_storage_required")
        self.assertEqual(captured.exception.exit_status, 3)
        runner.assert_not_called()
        with self.assertRaises(SourceAcquisitionError) as verify_captured:
            source_acquisition._assert_packed_storage(counts, status=4)
        self.assertEqual(
            verify_captured.exception.code, "packed_storage_required"
        )
        self.assertEqual(verify_captured.exception.exit_status, 4)

    def test_multi_pack_index_failure_preserves_cleanup_required(self) -> None:
        failed = subprocess.CompletedProcess(
            args=(), returncode=3, stdout=b"", stderr=b"simulated failure"
        )
        cleanup = SourceAcquisitionError(
            "cleanup_required", "simulated lock residue", exit_status=3
        )
        with mock.patch.object(
            source_acquisition,
            "_assert_recovery_state_clean",
            side_effect=(None, cleanup),
        ), mock.patch.object(
            source_acquisition, "_run_git", return_value=failed
        ), self.assertRaises(SourceAcquisitionError) as captured:
            source_acquisition._run_multi_pack_index_command(
                Path("C:/trusted/repository.git"),
                ("multi-pack-index", "write"),
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="https",
                ssh_executable=None,
                status=3,
                error_code="multi_pack_index_write_failed",
            )
        self.assertIs(captured.exception, cleanup)
        self.assertIsInstance(
            captured.exception.__cause__, SourceAcquisitionError
        )
        self.assertEqual(
            captured.exception.__cause__.code,
            "multi_pack_index_write_failed",
        )

    def test_multi_pack_index_interrupt_is_preserved_unless_cleanup_is_required(
        self,
    ) -> None:
        for interruption in (KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(interruption=type(interruption).__name__), (
                mock.patch.object(
                    source_acquisition,
                    "_assert_recovery_state_clean",
                    side_effect=(None, None),
                )
            ), mock.patch.object(
                source_acquisition, "_run_git", side_effect=interruption
            ), self.assertRaises(type(interruption)) as captured:
                source_acquisition._run_multi_pack_index_command(
                    Path("C:/trusted/repository.git"),
                    ("multi-pack-index", "write"),
                    git_executable=Path("C:/trusted/git.exe"),
                    github_transport="https",
                    ssh_executable=None,
                    status=3,
                    error_code="multi_pack_index_write_failed",
                )
            self.assertIs(captured.exception, interruption)

        interruption = KeyboardInterrupt()
        cleanup = SourceAcquisitionError(
            "cleanup_required", "simulated MIDX lock residue", exit_status=3
        )
        with mock.patch.object(
            source_acquisition,
            "_assert_recovery_state_clean",
            side_effect=(None, cleanup),
        ), mock.patch.object(
            source_acquisition, "_run_git", side_effect=interruption
        ), self.assertRaises(SourceAcquisitionError) as captured:
            source_acquisition._run_multi_pack_index_command(
                Path("C:/trusted/repository.git"),
                ("multi-pack-index", "write"),
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="https",
                ssh_executable=None,
                status=3,
                error_code="multi_pack_index_write_failed",
            )
        self.assertIs(captured.exception, cleanup)
        self.assertIs(captured.exception.__cause__, interruption)

    def test_multi_pack_index_verify_is_read_only_and_requires_stable_storage(
        self,
    ) -> None:
        repository = mock.Mock(spec=source_acquisition.GitRepository)
        repository.capture_storage_seal.side_effect = (object(), object())
        completed = subprocess.CompletedProcess(
            args=(), returncode=0, stdout=b"", stderr=b""
        )
        with mock.patch.object(
            source_acquisition, "_assert_recovery_state_clean"
        ), mock.patch.object(
            source_acquisition,
            "_capture_pack_payload_inventory",
            return_value=(4, 100, "a" * 64),
        ), mock.patch.object(
            source_acquisition,
            "_assert_multi_pack_index_file",
            return_value=(1, 2, 3, 4),
        ), mock.patch.object(
            source_acquisition, "_run_git", return_value=completed
        ) as runner, self.assertRaises(SourceAcquisitionError) as captured:
            source_acquisition._verify_multi_pack_index(
                Path("C:/trusted/repository.git"),
                repository,
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="https",
                ssh_executable=None,
                status=4,
            )
        self.assertEqual(captured.exception.code, "repository_changed")
        self.assertEqual(captured.exception.exit_status, 4)
        self.assertEqual(
            runner.call_args.args[2],
            ("multi-pack-index", "verify"),
        )

    def test_multi_pack_index_verify_rejects_missing_file_without_git(self) -> None:
        repository = mock.Mock(spec=source_acquisition.GitRepository)
        missing = SourceAcquisitionError(
            "multi_pack_index_missing", "simulated missing MIDX", exit_status=4
        )
        with mock.patch.object(
            source_acquisition, "_assert_recovery_state_clean"
        ), mock.patch.object(
            source_acquisition,
            "_capture_pack_payload_inventory",
            return_value=(4, 100, "a" * 64),
        ), mock.patch.object(
            source_acquisition,
            "_assert_multi_pack_index_file",
            side_effect=missing,
        ), mock.patch.object(
            source_acquisition, "_run_git"
        ) as runner, self.assertRaises(SourceAcquisitionError) as captured:
            source_acquisition._verify_multi_pack_index(
                Path("C:/trusted/repository.git"),
                repository,
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="https",
                ssh_executable=None,
                status=4,
            )
        self.assertIs(captured.exception, missing)
        runner.assert_not_called()

    def test_reachability_fsck_uses_only_explicit_commit_roots(self) -> None:
        commits = ("2" * 40, "1" * 40)
        completed = subprocess.CompletedProcess(
            args=(), returncode=0, stdout=b"", stderr=b""
        )
        with mock.patch.object(
            source_acquisition,
            "_run_git",
            return_value=completed,
        ) as runner:
            source_acquisition._run_full_reachability_fsck(
                Path("C:/trusted/repository.git"),
                commits=commits,
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="https",
                ssh_executable=None,
                status=4,
            )
        self.assertEqual(
            runner.call_args.args[2],
            (
                "fsck",
                "--full",
                "--strict",
                "--unreachable",
                "--no-reflogs",
                "--no-progress",
                "1" * 40,
                "2" * 40,
            ),
        )

    def test_github_transport_mapping_is_derived_not_caller_supplied(self) -> None:
        self.assertEqual(
            github_fetch_url_v1(REPO_URL, "https"),
            "https://github.com/example/project.git",
        )
        self.assertEqual(
            github_fetch_url_v1(REPO_URL, "ssh"),
            "git@github.com:example/project.git",
        )
        for value in (
            "git@github.com:example/project.git",
            "ssh://github.com/example/project",
            "https://evil.example/example/project",
            "https://github.com/example/project.git",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    github_fetch_url_v1(value, "ssh")
        with self.assertRaises(ValueError):
            github_fetch_url_v1(REPO_URL, "file")

    def test_git_output_overflow_has_one_stable_error_code(self) -> None:
        with mock.patch.object(
            source_acquisition,
            "run_bounded_process",
            side_effect=source_acquisition.BoundedProcessOutputTooLarge("stderr"),
        ), self.assertRaises(SourceAcquisitionError) as captured:
            source_acquisition._run_git(
                self.git,
                None,
                ("version",),
                github_transport="https",
                ssh_executable=None,
                timeout_seconds=10,
            )
        self.assertEqual(captured.exception.code, "git_output_limit")

    def test_ssh_environment_is_noninteractive_and_caller_cannot_supply_command(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {
                "GIT_SSH_COMMAND": "attacker-controlled",
                "GIT_CONFIG_GLOBAL": "attacker-controlled",
            },
            clear=False,
        ):
            environment = source_acquisition._git_environment(
                git_executable=Path("C:/trusted/git.exe"),
                github_transport="ssh",
                ssh_executable=Path("C:/trusted/ssh.exe"),
            )
        self.assertNotIn("attacker-controlled", environment["GIT_SSH_COMMAND"])
        expected_ssh = str(Path("C:/trusted/ssh.exe"))
        if os.name == "nt":
            expected_ssh = expected_ssh.replace("\\", "/")
        self.assertEqual(
            shlex.split(environment["GIT_SSH_COMMAND"]),
            [
                expected_ssh,
                "-F",
                "none",
                "-o",
                "BatchMode=yes",
                "-o",
                "NumberOfPasswordPrompts=0",
                "-o",
                "ProxyCommand=none",
                "-o",
                "ProxyJump=none",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=30",
                "-o",
                "HostName=ssh.github.com",
                "-p",
                "443",
            ],
        )
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")

    def test_http_401_cannot_invoke_ambient_askpass(self) -> None:
        class Unauthorized(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="VulnGym"')
                self.end_headers()

            def log_message(self, *args):
                del args

        server = ThreadingHTTPServer(("127.0.0.1", 0), Unauthorized)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                marker = root / "ambient-askpass-invoked"
                if os.name == "nt":
                    spy = root / "ambient-askpass.cmd"
                    spy.write_text(
                        f"@echo invoked>\"{marker}\"\r\n@exit /b 1\r\n",
                        encoding="utf-8",
                    )
                else:
                    spy = root / "ambient-askpass.sh"
                    spy.write_text(
                        f"#!/bin/sh\nprintf invoked > '{marker}'\nexit 1\n",
                        encoding="utf-8",
                    )
                    spy.chmod(0o700)
                ambient = {
                    "DISPLAY": ":99",
                    "GCM_INTERACTIVE": "always",
                    "GIT_ASKPASS": str(spy),
                    "SSH_ASKPASS": str(spy),
                    "SSH_ASKPASS_REQUIRE": "force",
                }
                with mock.patch.dict(os.environ, ambient, clear=False):
                    result = source_acquisition._run_git(
                        self.git,
                        None,
                        (
                            "ls-remote",
                            f"http://127.0.0.1:{server.server_port}/repository.git",
                        ),
                        github_transport="https",
                        ssh_executable=None,
                        timeout_seconds=10,
                        check=False,
                    )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_publication_failure_never_rolls_back_an_uncertain_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "controls"

            def uncertain_publish(target, files, **kwargs):
                del files, kwargs
                Path(target).mkdir()
                (Path(target) / "report.json").write_bytes(b"not expected\n")
                raise source_acquisition.BenchmarkHarnessError(
                    "output_publication_changed",
                    "simulated post-commit uncertainty",
                )

            with mock.patch.object(
                source_acquisition,
                "_publish_directory",
                side_effect=uncertain_publish,
            ), self.assertRaises(SourceAcquisitionError) as captured:
                source_acquisition._verify_or_publish_output(
                    output,
                    {"report.json": b"expected\n"},
                    protected_roots=(),
                    publish=True,
                )
            self.assertEqual(captured.exception.code, "publication_uncertain")
            self.assertEqual(
                (output / "report.json").read_bytes(), b"not expected\n"
            )

    def test_post_commit_base_exceptions_are_resolved_by_exact_readback(self) -> None:
        class FatalPublication(BaseException):
            pass

        for exception in (
            OSError("simulated post-commit I/O failure"),
            KeyboardInterrupt(),
            FatalPublication(),
        ):
            with (
                self.subTest(exception=type(exception).__name__),
                tempfile.TemporaryDirectory() as temporary,
            ):
                output = Path(temporary) / "controls"

                def committed_then_raised(target, files, **kwargs):
                    del kwargs
                    Path(target).mkdir()
                    for name, payload in files.items():
                        (Path(target) / name).write_bytes(payload)
                    raise exception

                with mock.patch.object(
                    source_acquisition,
                    "_publish_directory",
                    side_effect=committed_then_raised,
                ):
                    observed = source_acquisition._verify_or_publish_output(
                        output,
                        {"report.json": b"expected\n"},
                        protected_roots=(),
                        publish=True,
                    )
                self.assertEqual(observed, output.resolve(strict=True))
                self.assertEqual(
                    (output / "report.json").read_bytes(), b"expected\n"
                )

    def test_unprovable_post_publication_base_exception_is_uncertain(self) -> None:
        class FatalPublication(BaseException):
            def __bool__(self) -> bool:
                raise AssertionError("publication errors must not be truth-tested")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "controls"

            def committed_mismatch(target, files, **kwargs):
                del files, kwargs
                Path(target).mkdir()
                (Path(target) / "report.json").write_bytes(b"not expected\n")
                raise FatalPublication()

            with mock.patch.object(
                source_acquisition,
                "_publish_directory",
                side_effect=committed_mismatch,
            ), self.assertRaises(SourceAcquisitionError) as captured:
                source_acquisition._verify_or_publish_output(
                    output,
                    {"report.json": b"expected\n"},
                    protected_roots=(),
                    publish=True,
                )
            self.assertEqual(captured.exception.code, "publication_uncertain")
            self.assertEqual(captured.exception.exit_status, 5)

    def test_unprovable_io_failure_without_destination_is_uncertain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "controls"
            with mock.patch.object(
                source_acquisition,
                "_publish_directory",
                side_effect=OSError("simulated unknown publication state"),
            ), self.assertRaises(SourceAcquisitionError) as captured:
                source_acquisition._verify_or_publish_output(
                    output,
                    {"report.json": b"expected\n"},
                    protected_roots=(),
                    publish=True,
                )
            self.assertEqual(captured.exception.code, "publication_uncertain")
            self.assertEqual(captured.exception.exit_status, 5)
            self.assertFalse(output.exists())

    def test_keyboard_interrupt_before_publication_remains_an_interrupt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "controls"
            with mock.patch.object(
                source_acquisition,
                "_publish_directory",
                side_effect=KeyboardInterrupt,
            ), self.assertRaises(KeyboardInterrupt):
                source_acquisition._verify_or_publish_output(
                    output,
                    {"report.json": b"expected\n"},
                    protected_roots=(),
                    publish=True,
                )
            self.assertFalse(output.exists())

    def test_recovery_artifacts_fail_closed_and_are_never_deleted_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository.git"
            pack = repository / "objects" / "pack"
            refs = repository / "refs"
            pack.mkdir(parents=True)
            refs.mkdir()
            artifact = pack / "tmp_pack_interrupted"
            artifact.write_bytes(b"bounded Git transaction bytes")
            with self.assertRaises(SourceAcquisitionError) as captured:
                source_acquisition._assert_recovery_state_clean(
                    repository, status=3
                )
            self.assertEqual(captured.exception.code, "cleanup_required")
            self.assertEqual(
                artifact.read_bytes(), b"bounded Git transaction bytes"
            )

            artifact.unlink()
            multi_pack_lock = pack / "multi-pack-index.lock"
            multi_pack_lock.write_bytes(b"unresolved MIDX transaction")
            with self.assertRaises(SourceAcquisitionError) as captured:
                source_acquisition._assert_recovery_state_clean(
                    repository, status=3
                )
            self.assertEqual(captured.exception.code, "cleanup_required")
            self.assertEqual(
                multi_pack_lock.read_bytes(), b"unresolved MIDX transaction"
            )

            multi_pack_lock.unlink()
            promisor = pack / ("a" * 40 + ".promisor")
            promisor.write_bytes(b"")
            with self.assertRaises(SourceAcquisitionError) as captured:
                source_acquisition._assert_recovery_state_clean(
                    repository, status=3
                )
            self.assertEqual(captured.exception.code, "promisor_pack_rejected")
            self.assertTrue(promisor.exists())


if __name__ == "__main__":
    unittest.main()
