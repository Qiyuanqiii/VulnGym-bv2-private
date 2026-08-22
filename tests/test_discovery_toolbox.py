from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from threading import Barrier, Event, Lock, Thread
import unittest
from unittest import mock

import vulngym_agent.agents as agents_api
from vulngym_agent.agents.discovery_toolbox import (
    DISCOVERY_TOOL_CONTRACT_IDS,
    DISCOVERY_TOOL_NAMES,
    DiscoveryToolbox,
    MAX_INVENTORY_BATCH_FILES,
    MAX_LINK_RESULTS,
    MAX_READ_SPANS,
    MAX_SEARCH_RESULTS,
    MAX_STRUCTURE_RESULTS,
)
from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryCandidate,
    DiscoveryLocation,
    DiscoveryTaskInputV1,
)
from vulngym_agent.benchmark.sealed_snapshot import prepare_sealed_snapshot
from vulngym_agent.benchmark.sealed_tree_access import (
    SealedTreeAccessError,
    bind_sealed_tree,
)
from vulngym_agent.orchestrator import Budget, Limits
from vulngym_agent.tools import ArtifactRef, AttemptToolRuntime, ToolReferenceError
from vulngym_agent.tools.git.repository import GitRepository


TASK_ID = "VG-TRAIN-0123456789ABCDEF0123"
REPO_URL = "https://github.com/example/discovery-toolbox"
KEY = b"trusted discovery toolbox key 0001"
KEY_ID = "discovery-toolbox-test"
SOURCE_PATH = "src/app.py"
SOURCE = (
    b"def sink(value):\n"
    b"    return eval(value)\n"
    b"def entry(value):\n"
    b"    return sink(value)\n"
)
DENSE_SOURCE = (b"def repeated():\n" * 128) + (b"repeated()\n" * 128)


class DiscoveryToolboxTests(unittest.TestCase):
    def test_toolbox_api_is_lazily_exported_from_the_agents_package(self) -> None:
        self.assertIs(DiscoveryToolbox, agents_api.DiscoveryToolbox)
        self.assertEqual(DISCOVERY_TOOL_NAMES, agents_api.DISCOVERY_TOOL_NAMES)

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
        (self.repository / "src" / "dense.py").write_bytes(DENSE_SOURCE)
        (self.repository / "README.md").write_text(
            "literal needle and public documentation\n", encoding="utf-8"
        )
        (self.repository / "payload.bin").write_bytes(b"\x00\xffneedle\n")
        self._git("add", "-A")
        self._git("commit", "-q", "-m", "source")
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
        self.tree = bind_sealed_tree(
            self.task,
            self.snapshot_root,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )
        self.toolbox = DiscoveryToolbox(self.task, self.tree)
        self.toolbox.claim_source_usage()
        self.runtime = AttemptToolRuntime(
            task_id=self.task.task_id,
            attempt=0,
            policy_scope="t2.initial",
            budget=Budget(Limits(max_tool_calls=40)),
            registry=self.toolbox.registry,
            allowlist=self.toolbox.tool_names,
        )

    def tearDown(self) -> None:
        try:
            if not self.tree.usage_snapshot().finalized:
                self.toolbox.abort_source_usage()
        finally:
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

    def call(self, number: int, name: str, arguments=None):
        return self.runtime.call(
            f"TOOL-{number:05d}", name, {} if arguments is None else arguments
        )

    def _read_source(self, number: int = 1):
        return self.call(
            number,
            "source_read",
            {
                "spans": [
                    {"path": SOURCE_PATH, "line_start": line, "line_end": line}
                    for line in range(1, 5)
                ]
            },
        )

    def _structure(self, source_result, number: int = 2):
        return self.call(
            number,
            "source_structure",
            {
                "source": source_result.artifact_refs[0],
                "cursor": 0,
                "limit": MAX_STRUCTURE_RESULTS,
            },
        )

    def _candidate(
        self,
        source_artifact_id: str,
        structure_artifact_id: str,
        relationship_artifact_id: str,
    ) -> DiscoveryCandidate:
        lines = SOURCE.splitlines(keepends=True)
        return DiscoveryCandidate(
            task_id=self.task.task_id,
            snapshot_id=self.task.snapshot_id,
            repo_url=self.task.repo_url,
            commit=self.task.commit,
            entry_point=DiscoveryLocation(
                SOURCE_PATH,
                3,
                3,
                hashlib.sha256(lines[2]).hexdigest(),
            ),
            critical_operation=DiscoveryLocation(
                SOURCE_PATH,
                2,
                2,
                hashlib.sha256(lines[1]).hexdigest(),
            ),
            trace=(
                DiscoveryLocation(
                    SOURCE_PATH,
                    4,
                    4,
                    hashlib.sha256(lines[3]).hexdigest(),
                ),
            ),
            source_evidence_refs=(source_artifact_id, structure_artifact_id),
            relationship_evidence_refs=(relationship_artifact_id,),
        )

    def test_fixed_registry_has_replay_stable_contract_ids(self) -> None:
        self.assertEqual(DISCOVERY_TOOL_NAMES, tuple(self.toolbox.registry))
        self.assertEqual(DISCOVERY_TOOL_NAMES, tuple(DISCOVERY_TOOL_CONTRACT_IDS))
        self.assertEqual(
            dict(DISCOVERY_TOOL_CONTRACT_IDS),
            {
                name: definition.contract_id
                for name, definition in self.toolbox.registry.items()
            },
        )
        self.assertEqual(6, len(set(DISCOVERY_TOOL_CONTRACT_IDS.values())))
        with self.assertRaises(TypeError):
            self.toolbox.registry["shell"] = object()  # type: ignore[index]

        second_tree = bind_sealed_tree(
            self.task,
            self.snapshot_root,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )
        second = DiscoveryToolbox(self.task, second_tree)
        second.claim_source_usage()
        replay = AttemptToolRuntime(
            task_id=self.task.task_id,
            attempt=0,
            policy_scope="t2.initial",
            budget=Budget(),
            registry=second.registry,
            allowlist=(),
        )
        self.assertEqual(
            self.runtime.finalize().registry_sha256,
            replay.finalize().registry_sha256,
        )
        second.abort_source_usage()

    def test_inventory_is_batched_canonical_and_snapshot_bound(self) -> None:
        result = self.call(
            1,
            "source_inventory",
            {"cursor": 0, "limit": MAX_INVENTORY_BATCH_FILES},
        )
        self.assertEqual("success", result.status)
        artifact = self.runtime.resolve_artifact(result.artifact_refs[0])
        paths = tuple(item["path"] for item in artifact.payload["files"])
        self.assertEqual(tuple(sorted(paths)), paths)
        self.assertEqual(4, result.output["total_file_count"])
        self.assertIs(result.output["complete"], True)
        self.assertEqual(self.task.snapshot_id, artifact.payload["snapshot"]["snapshot_id"])
        self.assertEqual(
            self.task.snapshot_manifest_sha256,
            artifact.payload["snapshot"]["snapshot_manifest_sha256"],
        )

    def test_literal_search_is_bounded_case_sensitive_and_skips_binary(self) -> None:
        result = self.call(
            1,
            "source_search",
            {
                "query": "needle",
                "paths": ["payload.bin", "README.md"],
                "cursor": 0,
                "limit": MAX_SEARCH_RESULTS,
            },
        )
        self.assertEqual("success", result.status)
        artifact = self.runtime.resolve_artifact(result.artifact_refs[0])
        self.assertEqual(1, result.output["match_count"])
        self.assertEqual("README.md", artifact.payload["matches"][0]["path"])
        self.assertEqual(
            ({"path": "payload.bin", "reason": "not_utf8_text"},),
            artifact.payload["skipped"],
        )

        upper = self.call(
            2,
            "source_search",
            {
                "query": "Needle",
                "paths": ["README.md"],
                "cursor": 0,
                "limit": 1,
            },
        )
        self.assertEqual(0, upper.output["match_count"])

        first_page = self.call(
            3,
            "source_search",
            {
                "query": "sink",
                "paths": [SOURCE_PATH],
                "cursor": 0,
                "limit": 1,
            },
        )
        second_page = self.call(
            4,
            "source_search",
            {
                "query": "sink",
                "paths": [SOURCE_PATH],
                "cursor": first_page.output["next_cursor"],
                "limit": 1,
            },
        )
        self.assertIs(first_page.output["complete"], False)
        self.assertIs(second_page.output["complete"], True)
        self.assertEqual(1, first_page.output["match_count"])
        self.assertEqual(1, second_page.output["match_count"])

    def test_source_read_emits_exact_line_bytes_and_digests(self) -> None:
        result = self._read_source()
        self.assertEqual("success", result.status)
        artifact = self.runtime.resolve_artifact(result.artifact_refs[0])
        records = artifact.payload["spans"]
        self.assertEqual(4, len(records))
        lines = SOURCE.splitlines(keepends=True)
        self.assertEqual(lines[1].decode("utf-8"), records[1]["text"])
        self.assertEqual(
            hashlib.sha256(lines[1]).hexdigest(), records[1]["code_sha256"]
        )
        self.assertEqual(
            hashlib.sha256(SOURCE).hexdigest(), records[1]["file_sha256"]
        )

    def test_structure_and_link_are_lexical_only_and_digest_chained(self) -> None:
        source = self._read_source()
        structure = self._structure(source)
        structure_artifact = self.runtime.resolve_artifact(structure.artifact_refs[0])
        nodes = structure_artifact.payload["lexical_nodes"]
        self.assertEqual("unverified", structure.output["semantic_status"])
        self.assertIn("sink", {item["token"] for item in nodes})
        self.assertIn("entry", {item["token"] for item in nodes})
        self.assertIn("eval", {item["token"] for item in nodes})
        entry_node = next(
            item
            for item in nodes
            if item["token"] == "entry" and item["kind"] == "function_declaration"
        )
        self.assertEqual(
            hashlib.sha256(SOURCE.splitlines(keepends=True)[2]).hexdigest(),
            entry_node["code_sha256"],
        )
        self.assertEqual(
            source.artifact_refs[0].artifact_sha256,
            structure_artifact.payload["upstream_artifacts"][0]["artifact_sha256"],
        )

        linked = self.call(
            3,
            "source_link",
            {
                "structures": [structure.artifact_refs[0]],
                "cursor": 0,
                "limit": MAX_LINK_RESULTS,
            },
        )
        linked_artifact = self.runtime.resolve_artifact(linked.artifact_refs[0])
        relationships = linked_artifact.payload["mechanical_relationships"]
        self.assertEqual("unverified", linked.output["semantic_status"])
        self.assertEqual(1, linked.output["relationship_count"])
        self.assertEqual("sink", relationships[0]["symbol"])
        self.assertEqual("literal_symbol_match", relationships[0]["relation"])
        self.assertNotIn("vulnerable", json.dumps(linked_artifact.to_dict()))

    def test_validate_checks_source_bytes_and_exact_transitive_evidence_closure(self) -> None:
        source = self._read_source()
        structure = self._structure(source)
        linked = self.call(
            3,
            "source_link",
            {
                "structures": [structure.artifact_refs[0]],
                "cursor": 0,
                "limit": MAX_LINK_RESULTS,
            },
        )
        candidate = self._candidate(
            source.artifact_refs[0].artifact_id,
            structure.artifact_refs[0].artifact_id,
            linked.artifact_refs[0].artifact_id,
        )
        validated = self.call(
            4,
            "source_validate",
            {
                "candidate": candidate.to_dict(),
                "evidence": [
                    source.artifact_refs[0],
                    structure.artifact_refs[0],
                    linked.artifact_refs[0],
                ],
            },
        )
        self.assertEqual("success", validated.status)
        self.assertIs(validated.output["source_facts_valid"], True)
        self.assertIs(validated.output["artifact_refs_closed"], True)
        self.assertEqual("unreviewed", validated.output["semantic_status"])
        self.assertEqual("unverified", validated.output["relationship_status"])
        artifact = self.runtime.resolve_artifact(validated.artifact_refs[0])
        self.assertEqual(candidate.candidate_sha256, artifact.payload["candidate_sha256"])
        self.assertEqual(3, len(artifact.payload["upstream_artifacts"]))

    def test_mechanical_link_generation_short_circuits_at_aggregate_limit(self) -> None:
        structures = []
        call_number = 1
        for _ in range(16):
            source = self.call(
                call_number,
                "source_read",
                {
                    "spans": [
                        {
                            "path": "src/dense.py",
                            "line_start": 1,
                            "line_end": 256,
                        }
                    ]
                },
            )
            self.assertEqual("success", source.status)
            call_number += 1
            structure = self.call(
                call_number,
                "source_structure",
                {
                    "source": source.artifact_refs[0],
                    "cursor": 0,
                    "limit": MAX_STRUCTURE_RESULTS,
                },
            )
            self.assertEqual("success", structure.status)
            self.assertEqual(256, structure.output["node_count"])
            structures.append(structure.artifact_refs[0])
            call_number += 1

        linked = self.call(
            call_number,
            "source_link",
            {
                "structures": structures,
                "cursor": 0,
                "limit": MAX_LINK_RESULTS,
            },
        )
        self.assertEqual("blocked", linked.status)
        self.assertEqual("relationship_result_limit_exceeded", linked.error_code)

    def test_validate_rejects_missing_dependency_and_wrong_source_digest(self) -> None:
        source = self._read_source()
        structure = self._structure(source)
        linked = self.call(
            3,
            "source_link",
            {
                "structures": [structure.artifact_refs[0]],
                "cursor": 0,
                "limit": MAX_LINK_RESULTS,
            },
        )
        candidate = self._candidate(
            source.artifact_refs[0].artifact_id,
            structure.artifact_refs[0].artifact_id,
            linked.artifact_refs[0].artifact_id,
        )
        missing = self.call(
            4,
            "source_validate",
            {
                "candidate": candidate.to_dict(),
                "evidence": [source.artifact_refs[0], linked.artifact_refs[0]],
            },
        )
        self.assertEqual("blocked", missing.status)
        self.assertEqual("candidate_evidence_closure_mismatch", missing.error_code)

        tampered_value = candidate.to_dict()
        tampered_value["entry_point"]["code_sha256"] = "f" * 64
        tampered = DiscoveryCandidate.from_dict(tampered_value)
        digest = self.call(
            5,
            "source_validate",
            {
                "candidate": tampered.to_dict(),
                "evidence": [
                    source.artifact_refs[0],
                    structure.artifact_refs[0],
                    linked.artifact_refs[0],
                ],
            },
        )
        self.assertEqual("blocked", digest.status)
        self.assertEqual("candidate_source_digest_mismatch", digest.error_code)

    def test_runtime_rejects_forged_refs_and_handler_blocks_wrong_shape(self) -> None:
        source = self._read_source()
        issued = source.artifact_refs[0]
        forged = ArtifactRef(**issued.to_dict())
        before = len(self.runtime.records)
        with self.assertRaises(ToolReferenceError):
            self.runtime.call(
                "TOOL-00002",
                "source_structure",
                {"source": forged, "cursor": 0, "limit": 1},
            )
        self.assertEqual(before, len(self.runtime.records))

        wrong = self.call(
            3,
            "source_read",
            {"spans": [], "path": SOURCE_PATH},
        )
        self.assertEqual("blocked", wrong.status)
        self.assertEqual("invalid_arguments", wrong.error_code)

    def test_public_outputs_do_not_expose_host_paths_keys_git_or_semantic_answers(self) -> None:
        inventory = self.call(
            1,
            "source_inventory",
            {"cursor": 0, "limit": MAX_INVENTORY_BATCH_FILES},
        )
        source = self._read_source(2)
        structure = self._structure(source, 3)
        linked = self.call(
            4,
            "source_link",
            {
                "structures": [structure.artifact_refs[0]],
                "cursor": 0,
                "limit": MAX_LINK_RESULTS,
            },
        )
        transcript = self.runtime.finalize().to_dict()
        encoded = json.dumps(transcript, ensure_ascii=False)
        for forbidden in (
            str(self.root),
            str(self.snapshot_root),
            KEY.decode("ascii"),
            "attestation_key",
            "snapshot_root",
            "selection_lock",
            "git_diff",
            "git_history",
            "shell",
            "network",
            "semantic_status\":\"verified",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, encoded)
        self.assertEqual("success", inventory.status)
        self.assertEqual("success", linked.status)

    def test_limits_and_manifest_membership_fail_closed(self) -> None:
        cases = (
            (
                "source_inventory",
                {"cursor": 0, "limit": MAX_INVENTORY_BATCH_FILES + 1},
                "invalid_arguments",
            ),
            (
                "source_search",
                {
                    "query": "sink",
                    "paths": ["../secret"],
                    "cursor": 0,
                    "limit": MAX_SEARCH_RESULTS,
                },
                "source_path_not_allowed",
            ),
            (
                "source_read",
                {
                    "spans": [
                        {"path": SOURCE_PATH, "line_start": 1, "line_end": 1}
                        for _ in range(MAX_READ_SPANS + 1)
                    ]
                },
                "invalid_arguments",
            ),
        )
        for number, (name, arguments, error_code) in enumerate(cases, start=1):
            with self.subTest(name=name):
                result = self.call(number, name, arguments)
                self.assertEqual("blocked", result.status)
                self.assertEqual(error_code, result.error_code)

    def test_cached_inventory_cannot_bypass_finalized_tree_capability(self) -> None:
        first = self.call(
            1,
            "source_inventory",
            {"cursor": 0, "limit": MAX_INVENTORY_BATCH_FILES},
        )
        self.assertEqual("success", first.status)
        before = self.toolbox.usage_snapshot()
        self.assertFalse(before.finalized)
        final = self.toolbox.finalize_source_usage()
        self.assertTrue(final.finalized)
        self.assertTrue(final.verification_succeeded)
        blocked = self.call(
            2,
            "source_inventory",
            {"cursor": 0, "limit": MAX_INVENTORY_BATCH_FILES},
        )
        self.assertEqual("blocked", blocked.status)
        self.assertEqual("sealed_tree_access_failed", blocked.error_code)
        self.assertEqual("access_finalized", blocked.error["access_code"])
        self.assertNotIn("finalize_source_usage", self.toolbox.registry)
        self.assertNotIn("abort_source_usage", self.toolbox.registry)
        self.assertNotIn("claim_source_usage", self.toolbox.registry)
        self.assertNotIn("usage_snapshot", self.toolbox.registry)

    def test_tree_claim_is_atomic_and_direct_mutation_is_denied(self) -> None:
        second = DiscoveryToolbox(self.task, self.tree)
        with self.assertRaises(SealedTreeAccessError) as captured:
            second.claim_source_usage()
        self.assertEqual("access_claimed", captured.exception.code)
        with self.assertRaises(SealedTreeAccessError) as captured:
            self.tree.inventory()
        self.assertEqual("access_claimed", captured.exception.code)
        with self.assertRaises(SealedTreeAccessError) as captured:
            self.tree.finalize()
        self.assertEqual("access_claimed", captured.exception.code)

        result = self.call(
            1,
            "source_inventory",
            {"cursor": 0, "limit": MAX_INVENTORY_BATCH_FILES},
        )
        self.assertEqual("success", result.status)

    def test_concurrent_tree_claim_has_exactly_one_owner(self) -> None:
        tree = bind_sealed_tree(
            self.task,
            self.snapshot_root,
            attestation_key=KEY,
            expected_key_id=KEY_ID,
        )
        barrier = Barrier(2)
        lock = Lock()
        owners = []
        errors = []

        def claim() -> None:
            toolbox = DiscoveryToolbox(self.task, tree)
            barrier.wait()
            try:
                toolbox.claim_source_usage()
            except SealedTreeAccessError as error:
                with lock:
                    errors.append(error.code)
            else:
                with lock:
                    owners.append(toolbox)

        workers = [Thread(target=claim) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(5)
        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(1, len(owners))
        self.assertEqual(["access_claimed"], errors)
        owners[0].abort_source_usage()
        self.assertTrue(tree.usage_snapshot().finalized)

    def test_final_usage_rejects_calls_outside_the_toolbox_ledger(self) -> None:
        self.tree.inventory(_claim_token=self.toolbox._tree_claim_token)
        with self.assertRaises(SealedTreeAccessError) as captured:
            self.toolbox.finalize_source_usage()
        self.assertEqual("invalid_binding", captured.exception.code)
        usage = self.tree.usage_snapshot()
        self.assertTrue(usage.finalized)
        self.assertTrue(usage.verification_succeeded)

    def test_controller_finalize_is_serialized_after_an_inflight_tool(self) -> None:
        source = self._read_source()
        entered = Event()
        release = Event()
        finalized = Event()
        call_result = []
        final_result = []
        original = DiscoveryToolbox._lexical_nodes

        def blocked_lexical(toolbox, binding):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test did not release lexical analysis")
            return original(toolbox, binding)

        def run_structure() -> None:
            call_result.append(
                self.call(
                    2,
                    "source_structure",
                    {
                        "source": source.artifact_refs[0],
                        "cursor": 0,
                        "limit": MAX_STRUCTURE_RESULTS,
                    },
                )
            )

        def run_finalize() -> None:
            final_result.append(self.toolbox.finalize_source_usage())
            finalized.set()

        with mock.patch.object(
            DiscoveryToolbox,
            "_lexical_nodes",
            autospec=True,
            side_effect=blocked_lexical,
        ):
            worker = Thread(target=run_structure)
            worker.start()
            self.assertTrue(entered.wait(5))
            closer = Thread(target=run_finalize)
            closer.start()
            self.assertFalse(finalized.wait(0.05))
            release.set()
            worker.join(5)
            closer.join(5)

        self.assertFalse(worker.is_alive())
        self.assertFalse(closer.is_alive())
        self.assertEqual("success", call_result[0].status)
        self.assertTrue(final_result[0].finalized)
        self.assertTrue(final_result[0].verification_succeeded)


if __name__ == "__main__":
    unittest.main()
