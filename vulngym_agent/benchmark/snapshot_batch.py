"""Strict batch preparation and verification for sealed source snapshots.

The batch layer consumes only the answer-free ``tasks.jsonl`` export and an
operator-authored source map.  Repository roots remain input-only: neither
they nor any other absolute path is serialized into the published batch.

Each task is prepared through a fresh :class:`GitRepository` and the narrow
public sealed-snapshot API.  The complete batch is assembled in a sibling
staging directory and published once, without replacement, only after every
task and both batch control files are durable.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Any, Final, Iterable, Mapping, Sequence

from vulngym_agent.benchmark.contracts import (
    BenchmarkContractError,
    BenchmarkTask,
    SnapshotTaskSpec,
)
from vulngym_agent.benchmark.sealed_snapshot import (
    ATTESTATION_ALGORITHM,
    DEFAULT_SNAPSHOT_POLICY,
    SealedSnapshotError,
    SealedSnapshotSummary,
    SnapshotPolicy,
    _windows_logical_path_is_safe,
    _windows_extended_path,
    prepare_sealed_snapshot,
    verify_sealed_snapshot,
)
from vulngym_agent.tools.git.repository import GitFactError, GitRepository


BATCH_CONTRACT_VERSION: Final[str] = "vulngym.sealed-snapshot-batch.v3"
SOURCE_MAP_KIND: Final[str] = "sealed_snapshot_source_map"
SOURCE_MAP_SCHEMA_VERSION: Final[str] = "1.0.0"

# These three values are part of the fixed answer-free export wire contract.
# Keeping them local avoids importing the full benchmark evaluator (and its
# schema/orchestrator dependencies) into the source-snapshot trust boundary.
PROFILE_ID: Final[str] = "vulngym-50-20-v1"
PROFILE_SCHEMA_VERSION: Final[str] = "1.0.0"
PROFILE_MANIFEST_SHA256: Final[str] = (
    "d4ef4a663a30a39d2ccd89dc89f70d19a06686ae86179c537cd5139b8ff00a73"
)

_BATCH_CONTENT_DOMAIN: Final[bytes] = (
    b"VulnGym sealed snapshot batch content root v3\0"
)
_BATCH_ATTESTATION_DOMAIN: Final[bytes] = (
    b"VulnGym sealed snapshot batch attestation v3\0"
)
_BATCH_MATERIALIZED_DOMAIN: Final[bytes] = (
    b"VulnGym sealed snapshot batch materialized state v3\0"
)
SNAPSHOT_BATCH_EVIDENCE_CONTRACT_VERSION: Final[int] = 2
SNAPSHOT_BATCH_EVIDENCE_KIND: Final[str] = (
    "vulngym.sealed-snapshot-verification-evidence.v2"
)
SNAPSHOT_BATCH_EVIDENCE_SEMANTIC_DOMAIN: Final[bytes] = (
    b"VulnGym sealed snapshot verification evidence v2\0"
)
SNAPSHOT_BATCH_EVIDENCE_RUN_ID_DOMAIN: Final[bytes] = (
    b"VulnGym sealed snapshot verification run id v2\0"
)
SNAPSHOT_BATCH_KEY_EQUALITY_TAG_DOMAIN: Final[bytes] = (
    b"VulnGym sealed snapshot key equality tag v2\0"
)
SNAPSHOT_BATCH_OUTPUT_IDENTITY_DOMAIN: Final[bytes] = (
    b"VulnGym sealed snapshot output filesystem identity v2\0"
)
SNAPSHOT_BATCH_TASK_RECORDS_DOMAIN: Final[bytes] = (
    b"VulnGym sealed snapshot batch task records v2\0"
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_SHA1_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}\Z")
_DIAGNOSTIC_CODE_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9_]{1,128}\Z")
_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z"
)
_MAX_TASK_EXPORT_BYTES: Final[int] = 8 * 1024 * 1024
_MAX_TASK_LINE_BYTES: Final[int] = 64 * 1024
_MAX_SOURCE_MAP_BYTES: Final[int] = 8 * 1024 * 1024
_MAX_BATCH_MANIFEST_BYTES: Final[int] = 16 * 1024 * 1024
_MAX_BATCH_ATTESTATION_BYTES: Final[int] = 4 * 1024
_MAX_BATCH_TASKS: Final[int] = 100
_MAX_BATCH_TOTAL_FILES: Final[int] = 1_000_000
_MAX_BATCH_TOTAL_NODES: Final[int] = 1_000_000
_MAX_BATCH_TOTAL_BYTES: Final[int] = 16 * 1024 * 1024 * 1024
# Tree nodes plus five fixed nodes per task (bundle/tree/control and two
# controls), and the four fixed batch-level nodes.
_MAX_BATCH_CLEANUP_NODES: Final[int] = (
    _MAX_BATCH_TOTAL_NODES + (5 * _MAX_BATCH_TASKS) + 4
)
_MIN_KEY_BYTES: Final[int] = 32
_MAX_KEY_BYTES: Final[int] = 4_096
_OFFICIAL_SPLIT_COUNTS: Final[Mapping[str, int]] = {"train": 50, "test": 20}
_SNAPSHOT_BATCH_EVIDENCE_MINT: Final[object] = object()
_SNAPSHOT_BATCH_RUN_NONCE_BYTES: Final[int] = 32
_SNAPSHOT_BATCH_KEY_EQUALITY_PEPPER: Final[bytes] = secrets.token_bytes(32)
_SNAPSHOT_BATCH_EVIDENCE_REGISTRY_MAX: Final[int] = 64
_SNAPSHOT_BATCH_EVIDENCE_TTL_SECONDS: Final[float] = 24 * 60 * 60


class SnapshotBatchError(RuntimeError):
    """A strict batch contract, source, verification, or transaction failed."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_status: int,
        committed: bool = False,
        diagnostic_code: str | None = None,
    ) -> None:
        if exit_status not in {2, 3, 4, 5}:
            raise ValueError("exit_status must be one of 2, 3, 4, or 5")
        if (
            diagnostic_code is not None
            and (
                type(diagnostic_code) is not str
                or _DIAGNOSTIC_CODE_RE.fullmatch(diagnostic_code) is None
            )
        ):
            raise ValueError("diagnostic_code must be a bounded lowercase token")
        self.code = code
        self.exit_status = exit_status
        self.committed = bool(committed)
        self.diagnostic_code = diagnostic_code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class SnapshotBatchTask:
    """One path-free task result authenticated by the batch manifest."""

    task_id: str
    repo_url: str
    commit: str
    split: str
    instruction_id: str
    snapshot_manifest_sha256: str
    snapshot_content_root: str
    root_tree: str
    file_count: int
    node_count: int
    total_bytes: int
    entry_count: int
    regular_file_count: int
    gitlink_count: int
    regular_file_bytes: int
    materialized_bytes: int

    def __post_init__(self) -> None:
        SnapshotTaskSpec(
            task_id=self.task_id,
            repo_url=self.repo_url,
            commit=self.commit,
            split=self.split,
            instruction_id=self.instruction_id,
        )
        for value, name in (
            (self.snapshot_manifest_sha256, "snapshot_manifest_sha256"),
            (self.snapshot_content_root, "snapshot_content_root"),
        ):
            if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lower-case SHA-256 digest")
        if type(self.root_tree) is not str or _SHA1_RE.fullmatch(self.root_tree) is None:
            raise ValueError("root_tree must be a lower-case SHA-1 object id")
        if any(type(value) is not int or value < 0 for value in (
            self.entry_count, self.regular_file_count, self.gitlink_count,
            self.regular_file_bytes, self.materialized_bytes,
        )):
            raise ValueError("entry and byte counters must be integers")
        if (
            isinstance(self.file_count, bool)
            or not isinstance(self.file_count, int)
            or not 0 <= self.file_count <= _MAX_BATCH_TOTAL_FILES
        ):
            raise ValueError("file_count violates the fixed batch budget")
        if (
            isinstance(self.node_count, bool)
            or not isinstance(self.node_count, int)
            or not self.file_count <= self.node_count <= _MAX_BATCH_TOTAL_NODES
        ):
            raise ValueError("node_count violates the fixed batch budget")
        if (
            isinstance(self.total_bytes, bool)
            or not isinstance(self.total_bytes, int)
            or not 0 <= self.total_bytes <= _MAX_BATCH_TOTAL_BYTES
        ):
            raise ValueError("total_bytes violates the fixed batch budget")
        if (
            self.entry_count != self.file_count
            or self.entry_count != self.regular_file_count + self.gitlink_count
            or self.materialized_bytes != self.total_bytes
            or self.materialized_bytes
            != self.regular_file_bytes + 49 * self.gitlink_count
        ):
            raise ValueError("entry and byte counters do not close")

    @property
    def bundle_path(self) -> str:
        return f"bundles/{self.task_id}"

    def to_record(self) -> dict[str, object]:
        return {
            "bundle_path": self.bundle_path,
            "commit": self.commit,
            "file_count": self.file_count,
            "entry_count": self.entry_count,
            "regular_file_count": self.regular_file_count,
            "gitlink_count": self.gitlink_count,
            "regular_file_bytes": self.regular_file_bytes,
            "materialized_bytes": self.materialized_bytes,
            "instruction_id": self.instruction_id,
            "node_count": self.node_count,
            "record_type": "task",
            "repo_url": self.repo_url,
            "root_tree": self.root_tree,
            "snapshot_content_root": self.snapshot_content_root,
            "snapshot_manifest_sha256": self.snapshot_manifest_sha256,
            "split": self.split,
            "task_id": self.task_id,
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True, slots=True)
class SnapshotBatchSummary:
    """Immutable batch result; ``to_dict`` deliberately omits local paths."""

    batch_root: Path
    profile_id: str
    split: str
    task_count: int
    total_files: int
    total_nodes: int
    total_bytes: int
    tasks_sha256: str
    public_manifest_sha256: str
    source_map_sha256: str
    manifest_sha256: str
    batch_content_root: str
    key_id: str
    tasks: tuple[SnapshotBatchTask, ...]

    @property
    def total_entries(self) -> int:
        return sum(task.entry_count for task in self.tasks)

    @property
    def total_regular_files(self) -> int:
        return sum(task.regular_file_count for task in self.tasks)

    @property
    def total_gitlinks(self) -> int:
        return sum(task.gitlink_count for task in self.tasks)

    @property
    def total_regular_file_bytes(self) -> int:
        return sum(task.regular_file_bytes for task in self.tasks)

    @property
    def total_materialized_bytes(self) -> int:
        return sum(task.materialized_bytes for task in self.tasks)

    def __post_init__(self) -> None:
        if not isinstance(self.batch_root, Path) or not self.batch_root.is_absolute():
            raise ValueError("batch_root must be an absolute Path")
        frozen_tasks = tuple(self.tasks)
        if any(not isinstance(task, SnapshotBatchTask) for task in frozen_tasks):
            raise ValueError("tasks must contain SnapshotBatchTask values")
        object.__setattr__(self, "tasks", frozen_tasks)
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (
                self.task_count,
                self.total_files,
                self.total_nodes,
                self.total_bytes,
            )
        ):
            raise ValueError("batch summary counters must be integers")
        if (
            self.profile_id != PROFILE_ID
            or not isinstance(self.split, str)
            or self.split not in _OFFICIAL_SPLIT_COUNTS
            or self.task_count != len(frozen_tasks)
            or self.task_count != _OFFICIAL_SPLIT_COUNTS[self.split]
            or self.total_files != sum(task.file_count for task in frozen_tasks)
            or self.total_nodes != sum(task.node_count for task in frozen_tasks)
            or self.total_bytes != sum(task.total_bytes for task in frozen_tasks)
            or len({task.task_id for task in frozen_tasks}) != len(frozen_tasks)
            or any(task.split != self.split for task in frozen_tasks)
        ):
            raise ValueError("batch summary counters or task bindings are invalid")
        if not 0 <= self.total_files <= _MAX_BATCH_TOTAL_FILES:
            raise ValueError("batch total_files violates the fixed aggregate budget")
        if not 0 <= self.total_nodes <= _MAX_BATCH_TOTAL_NODES:
            raise ValueError("batch total_nodes violates the fixed aggregate budget")
        if not 0 <= self.total_bytes <= _MAX_BATCH_TOTAL_BYTES:
            raise ValueError("batch total_bytes violates the fixed aggregate budget")
        for value, name in (
            (self.tasks_sha256, "tasks_sha256"),
            (self.public_manifest_sha256, "public_manifest_sha256"),
            (self.source_map_sha256, "source_map_sha256"),
            (self.manifest_sha256, "manifest_sha256"),
            (self.batch_content_root, "batch_content_root"),
        ):
            if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lower-case SHA-256 digest")
        if not isinstance(self.key_id, str) or _KEY_ID_RE.fullmatch(self.key_id) is None:
            raise ValueError("key_id is not canonical")

    def to_dict(self) -> dict[str, object]:
        return {
            "batch_content_root": self.batch_content_root,
            "key_id": self.key_id,
            "manifest_sha256": self.manifest_sha256,
            "profile_id": self.profile_id,
            "public_manifest_sha256": self.public_manifest_sha256,
            "source_map_sha256": self.source_map_sha256,
            "split": self.split,
            "task_count": self.task_count,
            "tasks_sha256": self.tasks_sha256,
            "total_bytes": self.total_bytes,
            "total_files": self.total_files,
            "total_nodes": self.total_nodes,
            "total_entries": self.total_entries,
            "total_regular_files": self.total_regular_files,
            "total_gitlinks": self.total_gitlinks,
            "total_regular_file_bytes": self.total_regular_file_bytes,
            "total_materialized_bytes": self.total_materialized_bytes,
        }


def _snapshot_batch_key_equality_tag(key_material: bytearray) -> str:
    return hmac.new(
        _SNAPSHOT_BATCH_KEY_EQUALITY_PEPPER,
        SNAPSHOT_BATCH_KEY_EQUALITY_TAG_DOMAIN
        + len(key_material).to_bytes(8, "big")
        + key_material,
        hashlib.sha256,
    ).hexdigest()


def _snapshot_batch_output_identity_sha256(
    output_identity: tuple[int, int],
) -> str:
    return _sha256(
        SNAPSHOT_BATCH_OUTPUT_IDENTITY_DOMAIN
        + _canonical_json(
            {"device": output_identity[0], "file_id": output_identity[1]}
        )
    )


@dataclass(frozen=True, slots=True)
class SnapshotBatchVerificationEvidenceV2:
    """Mint-only, path-free evidence from one complete batch verification."""

    summary: SnapshotBatchSummary
    _key_material: InitVar[bytearray]
    _output_identity: InitVar[tuple[int, int]]
    _run_nonce: InitVar[bytearray]
    _mint: InitVar[object]
    summary_wire_sha256: str = field(init=False)
    task_records_sha256: str = field(init=False)
    key_equality_tag_sha256: str = field(init=False)
    output_identity_sha256: str = field(init=False)
    semantic_sha256: str = field(init=False)
    run_id: str = field(init=False)

    def __post_init__(
        self,
        _key_material: bytearray,
        _output_identity: tuple[int, int],
        _run_nonce: bytearray,
        _mint: object,
    ) -> None:
        if _mint is not _SNAPSHOT_BATCH_EVIDENCE_MINT:
            raise SnapshotBatchError(
                "untrusted_evidence",
                "verification evidence must be minted by the trusted verifier",
                exit_status=2,
            )
        if type(self.summary) is not SnapshotBatchSummary:
            raise SnapshotBatchError(
                "untrusted_evidence",
                "verification evidence requires an exact verified summary",
                exit_status=2,
            )
        if (
            type(_key_material) is not bytearray
            or not _MIN_KEY_BYTES <= len(_key_material) <= _MAX_KEY_BYTES
            or type(_run_nonce) is not bytearray
            or len(_run_nonce) != _SNAPSHOT_BATCH_RUN_NONCE_BYTES
            or type(_output_identity) is not tuple
            or len(_output_identity) != 2
            or any(type(value) is not int or value < 0 for value in _output_identity)
            or type(self.summary.tasks) is not tuple
            or any(type(task) is not SnapshotBatchTask for task in self.summary.tasks)
        ):
            raise SnapshotBatchError(
                "untrusted_evidence",
                "verification evidence inputs violate the fixed contract",
                exit_status=2,
            )
        summary_wire = _canonical_json(self.summary.to_dict()) + b"\n"
        task_records = b"".join(
            _canonical_json(task.to_record()) + b"\n"
            for task in self.summary.tasks
        )
        summary_wire_sha256 = _sha256(summary_wire)
        task_records_sha256 = _sha256(
            SNAPSHOT_BATCH_TASK_RECORDS_DOMAIN + task_records
        )
        key_equality_tag_sha256 = _snapshot_batch_key_equality_tag(_key_material)
        output_identity_sha256 = _snapshot_batch_output_identity_sha256(
            _output_identity
        )
        core = {
            "contract_version": SNAPSHOT_BATCH_EVIDENCE_CONTRACT_VERSION,
            "key_equality_tag_sha256": key_equality_tag_sha256,
            "kind": SNAPSHOT_BATCH_EVIDENCE_KIND,
            "output_identity_sha256": output_identity_sha256,
            "summary": self.summary.to_dict(),
            "summary_wire_sha256": summary_wire_sha256,
            "task_records_sha256": task_records_sha256,
        }
        semantic_sha256 = _sha256(
            SNAPSHOT_BATCH_EVIDENCE_SEMANTIC_DOMAIN + _canonical_json(core)
        )
        run_id = _sha256(
            SNAPSHOT_BATCH_EVIDENCE_RUN_ID_DOMAIN
            + _run_nonce
            + bytes.fromhex(semantic_sha256)
        )
        object.__setattr__(self, "summary_wire_sha256", summary_wire_sha256)
        object.__setattr__(self, "task_records_sha256", task_records_sha256)
        object.__setattr__(self, "key_equality_tag_sha256", key_equality_tag_sha256)
        object.__setattr__(self, "output_identity_sha256", output_identity_sha256)
        object.__setattr__(self, "semantic_sha256", semantic_sha256)
        object.__setattr__(self, "run_id", run_id)

    def _core_dict(self) -> dict[str, object]:
        return {
            "contract_version": SNAPSHOT_BATCH_EVIDENCE_CONTRACT_VERSION,
            "key_equality_tag_sha256": self.key_equality_tag_sha256,
            "kind": SNAPSHOT_BATCH_EVIDENCE_KIND,
            "output_identity_sha256": self.output_identity_sha256,
            "summary": self.summary.to_dict(),
            "summary_wire_sha256": self.summary_wire_sha256,
            "task_records_sha256": self.task_records_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        expected = _sha256(
            SNAPSHOT_BATCH_EVIDENCE_SEMANTIC_DOMAIN
            + _canonical_json(self._core_dict())
        )
        if expected != self.semantic_sha256:
            raise SnapshotBatchError(
                "untrusted_evidence",
                "verification evidence changed after trusted minting",
                exit_status=4,
            )
        return {
            **self._core_dict(),
            "run_id": self.run_id,
            "semantic_sha256": self.semantic_sha256,
        }


_SNAPSHOT_BATCH_EVIDENCE_LOCK: Final[threading.Lock] = threading.Lock()


@dataclass(frozen=True, slots=True)
class _SnapshotBatchEvidenceRegistration:
    evidence: SnapshotBatchVerificationEvidenceV2
    wire_sha256: str
    batch_root: Path
    output_identity: tuple[int, int]
    minted_monotonic: float


_SNAPSHOT_BATCH_EVIDENCE_REGISTRY: Final[
    dict[int, _SnapshotBatchEvidenceRegistration]
] = {}


def _purge_expired_snapshot_batch_evidence_locked(now: float) -> None:
    expired = tuple(
        evidence_id
        for evidence_id, registration in _SNAPSHOT_BATCH_EVIDENCE_REGISTRY.items()
        if now < registration.minted_monotonic
        or now - registration.minted_monotonic
        > _SNAPSHOT_BATCH_EVIDENCE_TTL_SECONDS
    )
    for evidence_id in expired:
        _SNAPSHOT_BATCH_EVIDENCE_REGISTRY.pop(evidence_id, None)


def _register_snapshot_batch_verification_evidence(
    evidence: SnapshotBatchVerificationEvidenceV2,
    *,
    batch_root: Path,
    output_identity: tuple[int, int],
) -> None:
    wire_sha256 = _sha256(_canonical_json(evidence.to_dict()))
    minted_monotonic = time.monotonic()
    with _SNAPSHOT_BATCH_EVIDENCE_LOCK:
        _purge_expired_snapshot_batch_evidence_locked(minted_monotonic)
        if len(_SNAPSHOT_BATCH_EVIDENCE_REGISTRY) >= (
            _SNAPSHOT_BATCH_EVIDENCE_REGISTRY_MAX
        ):
            raise SnapshotBatchError(
                "evidence_registry_full",
                "verification evidence registry reached its fixed capacity",
                exit_status=4,
            )
        if id(evidence) in _SNAPSHOT_BATCH_EVIDENCE_REGISTRY:
            raise SnapshotBatchError(
                "untrusted_evidence",
                "verification evidence identity is already registered",
                exit_status=4,
            )
        _SNAPSHOT_BATCH_EVIDENCE_REGISTRY[id(evidence)] = (
            _SnapshotBatchEvidenceRegistration(
                evidence=evidence,
                wire_sha256=wire_sha256,
                batch_root=batch_root,
                output_identity=output_identity,
                minted_monotonic=minted_monotonic,
            )
        )


def _claim_snapshot_batch_verification_evidence_batch(
    *,
    test_evidence: tuple[
        SnapshotBatchVerificationEvidenceV2,
        SnapshotBatchVerificationEvidenceV2,
    ],
    train_evidence: tuple[
        SnapshotBatchVerificationEvidenceV2,
        SnapshotBatchVerificationEvidenceV2,
    ],
) -> None:
    """Atomically consume four fresh, unchanged trusted verifier mints.

    The final root checks close deletion, replacement, rename, and same-path
    split reuse between verification and receipt creation.  They cannot make
    mutable filesystem contents transactionally immutable: the formal caller
    must isolate both roots read-only and exclude concurrent writers after the
    verification runs.
    """

    if (
        type(test_evidence) is not tuple
        or type(train_evidence) is not tuple
        or len(test_evidence) != 2
        or len(train_evidence) != 2
    ):
        raise SnapshotBatchError(
            "untrusted_evidence",
            "verification evidence must be an exact two-round split pair",
            exit_status=2,
        )
    evidence_values = (*test_evidence, *train_evidence)
    if any(
        type(evidence) is not SnapshotBatchVerificationEvidenceV2
        for evidence in evidence_values
    ) or len({id(evidence) for evidence in evidence_values}) != len(
        evidence_values
    ):
        raise SnapshotBatchError(
            "untrusted_evidence",
            "verification evidence was forged, copied, or reused",
            exit_status=2,
        )

    with _SNAPSHOT_BATCH_EVIDENCE_LOCK:
        now = time.monotonic()
        registrations: list[_SnapshotBatchEvidenceRegistration] = []
        for evidence in evidence_values:
            registration = _SNAPSHOT_BATCH_EVIDENCE_REGISTRY.get(id(evidence))
            if (
                registration is None
                or registration.evidence is not evidence
                or now < registration.minted_monotonic
                or now - registration.minted_monotonic
                > _SNAPSHOT_BATCH_EVIDENCE_TTL_SECONDS
                or registration.wire_sha256
                != _sha256(_canonical_json(evidence.to_dict()))
                or evidence.summary.batch_root != registration.batch_root
                or evidence.output_identity_sha256
                != _snapshot_batch_output_identity_sha256(
                    registration.output_identity
                )
            ):
                raise SnapshotBatchError(
                    "untrusted_evidence",
                    "verification evidence was forged, changed, stale, or reused",
                    exit_status=2,
                )
            current_root = _canonical_existing_path(
                registration.batch_root,
                directory=True,
                status=4,
            )
            current_identity = _directory_identity(
                _require_safe_directory(current_root, status=4)
            )
            if (
                current_root != registration.batch_root
                or current_identity != registration.output_identity
            ):
                raise SnapshotBatchError(
                    "stale_evidence",
                    "verified snapshot output changed before evidence claim",
                    exit_status=4,
                )
            registrations.append(registration)

        test_first, test_second, train_first, train_second = registrations
        if (
            test_first.batch_root != test_second.batch_root
            or test_first.output_identity != test_second.output_identity
            or train_first.batch_root != train_second.batch_root
            or train_first.output_identity != train_second.output_identity
            or test_first.batch_root == train_first.batch_root
            or test_first.output_identity == train_first.output_identity
        ):
            raise SnapshotBatchError(
                "untrusted_evidence",
                "verification evidence reuses or changes a split output root",
                exit_status=2,
            )

        # No passed registration is consumed until every registry, wire, TTL,
        # path, and current-identity check has succeeded for all four values.
        for evidence in evidence_values:
            del _SNAPSHOT_BATCH_EVIDENCE_REGISTRY[id(evidence)]


@dataclass(frozen=True, slots=True)
class VerifiedTaskExport:
    """One fully authenticated answer-free task export.

    The local root is retained for trusted preparation code, while callers
    that serialize results must deliberately select the path-free fields.
    """

    root: Path
    profile_id: str
    schema_version: str
    public_manifest_sha256: str
    split: str
    tasks_sha256: str
    tasks: tuple[SnapshotTaskSpec, ...]


@dataclass(frozen=True, slots=True)
class VerifiedSnapshotSourceMap:
    """A strict source map whose repositories have canonical local roots."""

    path: Path
    sha256: str
    sources: Mapping[tuple[str, str], Path]
    source_chains: Mapping[
        tuple[str, str], tuple[tuple[Path, tuple[int, int]], ...]
    ]


@dataclass(frozen=True, slots=True)
class SnapshotSourceMapDocument:
    """Canonical source-map bytes prepared from a verified task export."""

    split: str
    task_count: int
    tasks_sha256: str
    payload: bytes
    sha256: str

    def __post_init__(self) -> None:
        if self.split not in _OFFICIAL_SPLIT_COUNTS:
            raise ValueError("split is not an official benchmark split")
        if self.task_count != _OFFICIAL_SPLIT_COUNTS[self.split]:
            raise ValueError("task_count does not match the official split")
        if not isinstance(self.payload, bytes) or not self.payload.endswith(b"\n"):
            raise ValueError("payload must be newline-terminated bytes")
        if len(self.payload) > _MAX_SOURCE_MAP_BYTES:
            raise ValueError("payload exceeds the source-map byte budget")
        for value, name in (
            (self.tasks_sha256, "tasks_sha256"),
            (self.sha256, "sha256"),
        ):
            if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lower-case SHA-256 digest")
        if _sha256(self.payload) != self.sha256:
            raise ValueError("payload does not match its SHA-256 digest")


@dataclass(slots=True)
class _BatchStaging:
    output: Path
    parent: Path
    parent_identity: tuple[int, int]
    parent_chain: tuple[tuple[Path, tuple[int, int]], ...]
    staging: Path
    staging_identity: tuple[int, int]
    parent_fd: int | None = None
    staging_fd: int | None = None
    windows_parent_identity: tuple[int, int] | None = None
    windows_staging_identity: tuple[int, int] | None = None
    published: bool = False
    cleanup_nodes: dict[str, _CleanupNode] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _CleanupNode:
    """One transaction-created node that cleanup is permitted to remove."""

    directory: bool
    identity: tuple[object, ...]


class _DuplicateJsonKey(ValueError):
    pass


def _is_reparse(result: os.stat_result) -> bool:
    attributes = getattr(result, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _directory_identity(result: os.stat_result) -> tuple[int, int]:
    return result.st_dev, result.st_ino


def _file_identity(
    result: os.stat_result,
) -> tuple[int, int, int, int | None, int | None]:
    return (
        result.st_dev,
        result.st_ino,
        result.st_size,
        getattr(result, "st_mtime_ns", None),
        getattr(result, "st_ctime_ns", None),
    )


def _stable_path_identity(
    result: os.stat_result,
) -> tuple[int, int, int, int | None]:
    """Identity comparable across Windows path and handle stat calls.

    NTFS may advance change-time metadata when a newly created file is first
    opened.  Device, file ID, size, and last-write time remain the stable
    cross-API identity, while the opened handle is still checked with the full
    identity before and after reading.
    """

    return (
        result.st_dev,
        result.st_ino,
        result.st_size,
        getattr(result, "st_mtime_ns", None),
    )


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_sha256(value: object, *, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise SnapshotBatchError(
            "invalid_digest", f"{name} must be a lower-case SHA-256 digest", exit_status=2
        )
    return value


def _copy_key(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SnapshotBatchError(
            "invalid_key", "attestation key must be bytes-like", exit_status=2
        )
    key = bytes(value)
    if not _MIN_KEY_BYTES <= len(key) <= _MAX_KEY_BYTES:
        raise SnapshotBatchError(
            "invalid_key",
            "attestation key violates its fixed byte budget",
            exit_status=2,
        )
    return key


def _copy_key_buffer(value: object) -> bytearray:
    """Copy key material into a mutable buffer that callers can zero."""

    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SnapshotBatchError(
            "invalid_key", "attestation key must be bytes-like", exit_status=2
        )
    try:
        key = bytearray(value)
    except (BufferError, TypeError, ValueError):
        raise SnapshotBatchError(
            "invalid_key", "attestation key must be a flat byte buffer", exit_status=2
        ) from None
    if not _MIN_KEY_BYTES <= len(key) <= _MAX_KEY_BYTES:
        _zero_buffer(key)
        raise SnapshotBatchError(
            "invalid_key",
            "attestation key violates its fixed byte budget",
            exit_status=2,
        )
    return key


def _zero_buffer(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _validate_key_id(value: object) -> str:
    if not isinstance(value, str) or _KEY_ID_RE.fullmatch(value) is None:
        raise SnapshotBatchError(
            "invalid_key_id", "key identifier is not canonical", exit_status=2
        )
    return value


def _require_safe_directory(path: Path, *, status: int) -> os.stat_result:
    try:
        result = os.lstat(_windows_extended_path(path))
    except OSError as error:
        raise SnapshotBatchError(
            "directory_unavailable", "a required directory is unavailable", exit_status=status
        ) from error
    if (
        not stat.S_ISDIR(result.st_mode)
        or stat.S_ISLNK(result.st_mode)
        or _is_reparse(result)
    ):
        raise SnapshotBatchError(
            "unsafe_directory", "a required directory is unsafe", exit_status=status
        )
    return result


def _require_safe_regular(path: Path, *, status: int) -> os.stat_result:
    try:
        result = os.lstat(_windows_extended_path(path))
    except OSError as error:
        raise SnapshotBatchError(
            "file_unavailable", "a required input file is unavailable", exit_status=status
        ) from error
    if (
        not stat.S_ISREG(result.st_mode)
        or stat.S_ISLNK(result.st_mode)
        or _is_reparse(result)
        or result.st_nlink > 1
    ):
        raise SnapshotBatchError(
            "unsafe_file", "a required input file is unsafe", exit_status=status
        )
    return result


def _root_chain(path: Path) -> tuple[Path, ...]:
    return tuple(reversed(path.parents)) + (path,)


def _checked_directory_chain(
    path: Path, *, status: int
) -> tuple[tuple[Path, tuple[int, int]], ...]:
    return tuple(
        (component, _directory_identity(_require_safe_directory(component, status=status)))
        for component in _root_chain(path)
    )


def _assert_directory_chain(
    checked: Sequence[tuple[Path, tuple[int, int]]], *, status: int
) -> None:
    for component, expected in checked:
        current = _require_safe_directory(component, status=status)
        if _directory_identity(current) != expected:
            raise SnapshotBatchError(
                "directory_changed",
                "a trusted directory changed during the operation",
                exit_status=status,
            )


def _read_stable_file(path: Path, maximum: int, *, status: int) -> bytes:
    _windows_assert_no_named_streams(path, status=status)
    before = _require_safe_regular(path, status=status)
    if before.st_size > maximum:
        raise SnapshotBatchError(
            "input_limit_exceeded", "an input file exceeds its byte budget", exit_status=status
        )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(_windows_extended_path(path), flags)
    except OSError as error:
        raise SnapshotBatchError(
            "file_unavailable", "an input file cannot be opened", exit_status=status
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink > 1
            or _stable_path_identity(opened) != _stable_path_identity(before)
        ):
            raise SnapshotBatchError(
                "input_changed", "an input changed while opening", exit_status=status
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        finished = os.fstat(descriptor)
        if (
            len(payload) > maximum
            or len(payload) != opened.st_size
            or _file_identity(finished) != _file_identity(opened)
        ):
            raise SnapshotBatchError(
                "input_changed", "an input changed while reading", exit_status=status
            )
    finally:
        os.close(descriptor)
    after = _require_safe_regular(path, status=status)
    _windows_assert_no_named_streams(path, status=status)
    if _stable_path_identity(after) != _stable_path_identity(before):
        raise SnapshotBatchError(
            "input_changed", "an input changed during validation", exit_status=status
        )
    return payload


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _validate_json_shape(value: Any, *, depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("JSON nesting is too deep")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        raise ValueError("floating-point values are forbidden")
    if isinstance(value, list):
        for item in value:
            _validate_json_shape(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("object keys must be strings")
            _validate_json_shape(item, depth=depth + 1)
        return
    raise ValueError("unsupported JSON value")


def _parse_canonical_line(payload: bytes, *, status: int) -> dict[str, Any]:
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise SnapshotBatchError(
            "invalid_json", "JSON records must use one-line framing", exit_status=status
        )
    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _validate_json_shape(value)
        canonical = _canonical_json(value)
    except (
        UnicodeDecodeError,
        UnicodeEncodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        RecursionError,
        ValueError,
    ) as error:
        raise SnapshotBatchError(
            "invalid_json", "JSON input is malformed", exit_status=status
        ) from error
    if not isinstance(value, dict) or canonical + b"\n" != payload:
        raise SnapshotBatchError(
            "noncanonical_json", "JSON input is not canonical", exit_status=status
        )
    return value


def _strict_json_equal(left: object, right: object) -> bool:
    """Compare decoded JSON without Python's ``bool == int`` coercion."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        if set(left) != set(right):
            return False
        return all(_strict_json_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _strict_json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return left == right


def _fixed_names(path: Path, expected: set[str], *, status: int) -> None:
    _require_safe_directory(path, status=status)
    _windows_assert_no_named_streams(path, status=status)
    seen: set[str] = set()
    try:
        with os.scandir(_windows_extended_path(path)) as entries:
            for entry in entries:
                if entry.name not in expected or len(seen) >= len(expected):
                    raise SnapshotBatchError(
                        "layout_mismatch",
                        "a fixed directory layout does not match",
                        exit_status=status,
                    )
                seen.add(entry.name)
                if len(seen) > len(expected):
                    raise SnapshotBatchError(
                        "layout_mismatch",
                        "a fixed directory layout does not match",
                        exit_status=status,
                    )
    except SnapshotBatchError:
        raise
    except OSError as error:
        raise SnapshotBatchError(
            "directory_unavailable", "a directory cannot be enumerated", exit_status=status
        ) from error
    if seen != expected:
        raise SnapshotBatchError(
            "layout_mismatch", "a fixed directory layout does not match", exit_status=status
        )
    _windows_assert_no_named_streams(path, status=status)


def load_verified_task_export(
    task_export_dir: str | os.PathLike[str],
    *,
    expected_tasks_sha256: str,
    expected_public_manifest_sha256: str,
) -> VerifiedTaskExport:
    """Load one exact, digest-pinned answer-free task export."""

    expected_tasks_sha256 = _validate_sha256(
        expected_tasks_sha256, name="expected_tasks_sha256"
    )
    expected_public_manifest_sha256 = _validate_sha256(
        expected_public_manifest_sha256,
        name="expected_public_manifest_sha256",
    )
    root = _canonical_existing_path(
        task_export_dir, directory=True, status=2
    )
    checked_root = _checked_directory_chain(root, status=2)
    _fixed_names(root, {"manifest.json", "tasks.jsonl"}, status=2)
    manifest_payload = _read_stable_file(
        root / "manifest.json", _MAX_TASK_LINE_BYTES, status=2
    )
    tasks_payload = _read_stable_file(
        root / "tasks.jsonl", _MAX_TASK_EXPORT_BYTES, status=2
    )
    manifest = _parse_canonical_line(manifest_payload, status=2)
    manifest_keys = {
        "kind",
        "manifest_sha256",
        "profile_id",
        "schema_version",
        "split",
        "task_count",
        "tasks_sha256",
    }
    task_count = manifest.get("task_count")
    split = manifest.get("split")
    tasks_sha256 = _sha256(tasks_payload)
    if (
        set(manifest) != manifest_keys
        or manifest.get("kind") != "answer_free_task_export"
        or manifest.get("profile_id") != PROFILE_ID
        or manifest.get("schema_version") != PROFILE_SCHEMA_VERSION
        or manifest.get("manifest_sha256") != PROFILE_MANIFEST_SHA256
        or manifest.get("manifest_sha256") != expected_public_manifest_sha256
        or not isinstance(split, str)
        or split not in _OFFICIAL_SPLIT_COUNTS
        or isinstance(task_count, bool)
        or not isinstance(task_count, int)
        or task_count != _OFFICIAL_SPLIT_COUNTS.get(split)
        or manifest.get("tasks_sha256") != tasks_sha256
        or tasks_sha256 != expected_tasks_sha256
    ):
        raise SnapshotBatchError(
            "task_export_binding_mismatch",
            "answer-free task export binding does not match",
            exit_status=2,
        )
    if not tasks_payload.endswith(b"\n"):
        raise SnapshotBatchError(
            "invalid_task_export", "task JSONL framing is invalid", exit_status=2
        )
    raw_lines = tasks_payload.splitlines(keepends=True)
    if len(raw_lines) != task_count:
        raise SnapshotBatchError(
            "invalid_task_export", "task count does not match its manifest", exit_status=2
        )
    tasks: list[SnapshotTaskSpec] = []
    seen_task_ids: set[str] = set()
    seen_snapshots: set[tuple[str, str]] = set()
    for raw_line in raw_lines:
        if len(raw_line) > _MAX_TASK_LINE_BYTES:
            raise SnapshotBatchError(
                "input_limit_exceeded", "a task record exceeds its byte budget", exit_status=2
            )
        record = _parse_canonical_line(raw_line, status=2)
        try:
            task = BenchmarkTask.from_dict(record)
        except BenchmarkContractError as error:
            raise SnapshotBatchError(
                "invalid_task_export", "an answer-free task is invalid", exit_status=2
            ) from error
        snapshot_identity = (task.repo_url.casefold(), task.commit)
        if (
            task.split != manifest["split"]
            or task.task_id in seen_task_ids
            or snapshot_identity in seen_snapshots
        ):
            raise SnapshotBatchError(
                "invalid_task_export",
                "task split or task/snapshot uniqueness binding does not match",
                exit_status=2,
            )
        seen_task_ids.add(task.task_id)
        seen_snapshots.add(snapshot_identity)
        tasks.append(
            SnapshotTaskSpec(
                task_id=task.task_id,
                repo_url=task.repo_url,
                commit=task.commit,
                split=task.split,
                instruction_id=task.instruction_id,
            )
        )
    _assert_directory_chain(checked_root, status=2)
    _fixed_names(root, {"manifest.json", "tasks.jsonl"}, status=2)
    return VerifiedTaskExport(
        root=root,
        profile_id=manifest["profile_id"],
        schema_version=manifest["schema_version"],
        public_manifest_sha256=manifest["manifest_sha256"],
        split=manifest["split"],
        tasks_sha256=tasks_sha256,
        tasks=tuple(tasks),
    )


def _canonical_repo_root(
    value: object,
) -> tuple[Path, tuple[tuple[Path, tuple[int, int]], ...]]:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SnapshotBatchError(
            "invalid_source_map", "source roots must be absolute paths", exit_status=2
        )
    if any(ord(character) < 32 for character in value):
        raise SnapshotBatchError(
            "invalid_source_map", "source roots contain control characters", exit_status=2
        )
    if not os.path.isabs(value) or os.path.normpath(value) != value:
        raise SnapshotBatchError(
            "invalid_source_map",
            "source roots must use canonical absolute spelling",
            exit_status=2,
        )
    root = _canonical_existing_path(value, directory=True, status=2)
    checked = _checked_directory_chain(root, status=2)
    _assert_directory_chain(checked, status=2)
    return root, checked


def build_snapshot_source_map_document(
    task_export: VerifiedTaskExport,
    source_roots: Mapping[tuple[str, str], str | os.PathLike[str]],
) -> SnapshotSourceMapDocument:
    """Build canonical source-map bytes using the batch contract itself.

    Repository roots are resolved and checked before their absolute canonical
    spelling is serialized.  This intentionally makes the source-map wire
    digest host/path specific while leaving acquisition receipts free of
    local paths.
    """

    if type(task_export) is not VerifiedTaskExport:
        raise SnapshotBatchError(
            "invalid_task_export",
            "verified task-export input has an invalid type",
            exit_status=2,
        )
    if not isinstance(source_roots, Mapping):
        raise SnapshotBatchError(
            "invalid_source_map",
            "source roots must be a mapping",
            exit_status=2,
        )
    try:
        supplied = dict(source_roots)
    except (TypeError, ValueError) as error:
        raise SnapshotBatchError(
            "invalid_source_map",
            "source roots cannot be snapshotted",
            exit_status=2,
        ) from error
    required = {(task.repo_url, task.commit) for task in task_export.tasks}
    if set(supplied) != required:
        raise SnapshotBatchError(
            "source_map_coverage_mismatch",
            "source-map coverage must be exact with no missing or extra sources",
            exit_status=2,
        )

    records: list[dict[str, str]] = []
    checked_roots: list[tuple[tuple[Path, tuple[int, int]], ...]] = []
    order = sorted(
        required,
        key=lambda identity: (
            identity[0].encode("utf-8"),
            identity[1].encode("ascii"),
        ),
    )
    for repo_url, commit in order:
        raw_root = supplied[(repo_url, commit)]
        try:
            root_text = os.fspath(raw_root)
        except TypeError as error:
            raise SnapshotBatchError(
                "invalid_source_map",
                "a source root has an invalid type",
                exit_status=2,
            ) from error
        root, checked = _canonical_repo_root(root_text)
        checked_roots.append(checked)
        records.append(
            {
                "commit": commit,
                "repo_root": str(root),
                "repo_url": repo_url,
            }
        )

    value = {
        "kind": SOURCE_MAP_KIND,
        "profile_id": task_export.profile_id,
        "public_manifest_sha256": task_export.public_manifest_sha256,
        "schema_version": SOURCE_MAP_SCHEMA_VERSION,
        "sources": records,
        "tasks_sha256": task_export.tasks_sha256,
    }
    payload = _canonical_json(value) + b"\n"
    if len(payload) > _MAX_SOURCE_MAP_BYTES:
        raise SnapshotBatchError(
            "input_limit_exceeded",
            "source-map output exceeds its byte budget",
            exit_status=2,
        )
    for checked in checked_roots:
        _assert_directory_chain(checked, status=2)
    return SnapshotSourceMapDocument(
        split=task_export.split,
        task_count=len(task_export.tasks),
        tasks_sha256=task_export.tasks_sha256,
        payload=payload,
        sha256=_sha256(payload),
    )


def load_verified_snapshot_source_map(
    source_map_path: str | os.PathLike[str],
    *,
    expected_source_map_sha256: str,
    task_export: VerifiedTaskExport,
) -> VerifiedSnapshotSourceMap:
    """Load one canonical source map against a verified task export."""

    if type(task_export) is not VerifiedTaskExport:
        raise SnapshotBatchError(
            "invalid_task_export",
            "verified task-export input has an invalid type",
            exit_status=2,
        )
    expected_source_map_sha256 = _validate_sha256(
        expected_source_map_sha256, name="expected_source_map_sha256"
    )
    path = _canonical_existing_path(
        source_map_path, directory=False, status=2
    )
    checked_parent = _checked_directory_chain(path.parent, status=2)
    payload = _read_stable_file(path, _MAX_SOURCE_MAP_BYTES, status=2)
    _assert_directory_chain(checked_parent, status=2)
    actual_sha256 = _sha256(payload)
    if actual_sha256 != expected_source_map_sha256:
        raise SnapshotBatchError(
            "source_map_digest_mismatch",
            "source-map digest does not match",
            exit_status=2,
        )
    value = _parse_canonical_line(payload, status=2)
    expected_keys = {
        "kind",
        "profile_id",
        "public_manifest_sha256",
        "schema_version",
        "sources",
        "tasks_sha256",
    }
    raw_sources = value.get("sources")
    if (
        set(value) != expected_keys
        or value.get("kind") != SOURCE_MAP_KIND
        or value.get("schema_version") != SOURCE_MAP_SCHEMA_VERSION
        or value.get("profile_id") != task_export.profile_id
        or value.get("public_manifest_sha256")
        != task_export.public_manifest_sha256
        or value.get("tasks_sha256") != task_export.tasks_sha256
        or not isinstance(raw_sources, list)
        or not 1 <= len(raw_sources) <= _MAX_BATCH_TASKS
    ):
        raise SnapshotBatchError(
            "invalid_source_map", "source-map contract does not match", exit_status=2
        )
    sources: dict[tuple[str, str], Path] = {}
    source_chains: dict[
        tuple[str, str], tuple[tuple[Path, tuple[int, int]], ...]
    ] = {}
    order: list[tuple[bytes, bytes]] = []
    for raw_source in raw_sources:
        if not isinstance(raw_source, dict) or set(raw_source) != {
            "commit",
            "repo_root",
            "repo_url",
        }:
            raise SnapshotBatchError(
                "invalid_source_map", "a source-map record is invalid", exit_status=2
            )
        repo_url = raw_source.get("repo_url")
        commit = raw_source.get("commit")
        try:
            # The task contract supplies the exact canonical URL/SHA validation.
            probe = SnapshotTaskSpec(
                task_id="VG-TRAIN-00000000000000000000",
                repo_url=repo_url,
                commit=commit,
                split="train",
            )
        except (BenchmarkContractError, ValueError) as error:
            raise SnapshotBatchError(
                "invalid_source_map", "a source identity is invalid", exit_status=2
            ) from error
        identity = (probe.repo_url, probe.commit)
        if identity in sources:
            raise SnapshotBatchError(
                "duplicate_source", "source-map identities must be unique", exit_status=2
            )
        root, checked = _canonical_repo_root(raw_source.get("repo_root"))
        sources[identity] = root
        source_chains[identity] = checked
        order.append((identity[0].encode("utf-8"), identity[1].encode("ascii")))
    if order != sorted(order):
        raise SnapshotBatchError(
            "invalid_source_map", "source-map records are not sorted", exit_status=2
        )
    required = {(task.repo_url, task.commit) for task in task_export.tasks}
    if set(sources) != required:
        raise SnapshotBatchError(
            "source_map_coverage_mismatch",
            "source-map coverage must be exact with no missing or extra sources",
            exit_status=2,
        )
    _assert_directory_chain(checked_parent, status=2)
    for checked in source_chains.values():
        _assert_directory_chain(checked, status=2)
    return VerifiedSnapshotSourceMap(
        path=path,
        sha256=actual_sha256,
        sources=sources,
        source_chains=source_chains,
    )


def _paths_overlap(left: Path, right: Path) -> bool:
    left_text = os.path.normcase(os.path.abspath(os.fspath(left)))
    right_text = os.path.normcase(os.path.abspath(os.fspath(right)))
    try:
        common = os.path.commonpath((left_text, right_text))
    except ValueError:
        return False
    return common in {left_text, right_text}


class _WindowsFileTime(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]


class _WindowsHandleInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("creation_time", _WindowsFileTime),
        ("last_access_time", _WindowsFileTime),
        ("last_write_time", _WindowsFileTime),
        ("volume_serial_number", wintypes.DWORD),
        ("file_size_high", wintypes.DWORD),
        ("file_size_low", wintypes.DWORD),
        ("number_of_links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    ]


class _WindowsFindStreamData(ctypes.Structure):
    _fields_ = [
        ("stream_size", ctypes.c_longlong),
        ("stream_name", wintypes.WCHAR * (260 + 36)),
    ]


def _windows_assert_no_named_streams(path: Path, *, status: int) -> None:
    if os.name != "nt":
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    find_first = kernel32.FindFirstStreamW
    find_first.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        ctypes.POINTER(_WindowsFindStreamData),
        wintypes.DWORD,
    ]
    find_first.restype = wintypes.HANDLE
    find_next = kernel32.FindNextStreamW
    find_next.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_WindowsFindStreamData),
    ]
    find_next.restype = wintypes.BOOL
    find_close = kernel32.FindClose
    find_close.argtypes = [wintypes.HANDLE]
    find_close.restype = wintypes.BOOL
    data = _WindowsFindStreamData()
    handle = find_first(str(_windows_extended_path(path)), 0, ctypes.byref(data), 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, 0, invalid_handle}:
        error_number = ctypes.get_last_error()
        if error_number == 38:
            return
        raise SnapshotBatchError(
            "path_unavailable", "path streams cannot be enumerated", exit_status=status
        )
    try:
        while True:
            if data.stream_name != "::$DATA":
                raise SnapshotBatchError(
                    "unsafe_file",
                    "named data streams are forbidden",
                    exit_status=status,
                )
            if find_next(handle, ctypes.byref(data)):
                continue
            error_number = ctypes.get_last_error()
            if error_number != 38:
                raise SnapshotBatchError(
                    "path_unavailable",
                    "path streams changed during enumeration",
                    exit_status=status,
                )
            break
    finally:
        find_close(handle)


def _windows_open_directory(
    path: Path,
    *,
    delete_access: bool,
    share_delete: bool,
) -> tuple[int, tuple[int, int]]:
    if os.name != "nt":
        raise OSError(errno.ENOTSUP, "Windows directory handles are unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    desired_access = 0x0080 | (0x00010000 if delete_access else 0)
    share_mode = 0x00000001 | 0x00000002
    if share_delete:
        share_mode |= 0x00000004
    handle = create_file(
        str(_windows_extended_path(path)),
        desired_access,
        share_mode,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, 0, invalid_handle}:
        raise OSError(
            ctypes.get_last_error(), "trusted batch directory handle could not be opened"
        )
    information = _WindowsHandleInformation()
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    get_information.restype = wintypes.BOOL
    if not get_information(handle, ctypes.byref(information)):
        error_number = ctypes.get_last_error()
        kernel32.CloseHandle(handle)
        raise OSError(error_number, "trusted batch directory identity could not be read")
    if not (information.attributes & 0x00000010) or (
        information.attributes & 0x00000400
    ):
        kernel32.CloseHandle(handle)
        raise SnapshotBatchError(
            "unsafe_directory", "batch transaction paths must be plain directories", exit_status=5
        )
    identity = (
        information.volume_serial_number,
        (information.file_index_high << 32) | information.file_index_low,
    )
    return int(handle), identity


def _windows_close_handle(handle: int) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(handle)


def _windows_rename_directory_handle(handle: int, destination: Path) -> None:
    destination_text = str(_windows_extended_path(destination))
    destination_utf16 = destination_text.encode("utf-16-le")
    destination_utf16_units = len(destination_utf16) // 2

    class _WindowsRenameInformation(ctypes.Structure):
        _fields_ = [
            ("replace_if_exists", ctypes.c_ubyte),
            ("root_directory", wintypes.HANDLE),
            ("file_name_length", wintypes.DWORD),
            (
                "file_name",
                wintypes.WCHAR * (destination_utf16_units + 1),
            ),
        ]

    information = _WindowsRenameInformation()
    information.replace_if_exists = 0
    information.root_directory = None
    information.file_name_length = len(destination_utf16)
    information.file_name = destination_text
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_information = kernel32.SetFileInformationByHandle
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    buffer_size = (
        _WindowsRenameInformation.file_name.offset + information.file_name_length
    )
    if not set_information(handle, 3, ctypes.byref(information), buffer_size):
        error_number = ctypes.get_last_error()
        if error_number in {80, 183}:
            raise SnapshotBatchError(
                "output_exists", "output appeared during publication", exit_status=5
            )
        raise OSError(error_number, "atomic batch publication failed")


def _windows_final_path(path: Path, *, directory: bool) -> Path:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    flags = 0x00200000 | (0x02000000 if directory else 0)
    handle = create_file(
        str(_windows_extended_path(path)),
        0x0080,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        flags,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in {None, 0, invalid_handle}:
        raise OSError(ctypes.get_last_error(), "canonical path handle could not be opened")
    try:
        get_final = kernel32.GetFinalPathNameByHandleW
        get_final.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        get_final.restype = wintypes.DWORD
        required = get_final(handle, None, 0, 0)
        if required < 1:
            raise OSError(
                ctypes.get_last_error(), "canonical path identity could not be read"
            )
        buffer = ctypes.create_unicode_buffer(required + 1)
        written = get_final(handle, buffer, len(buffer), 0)
        if written < 1 or written >= len(buffer):
            raise OSError(
                ctypes.get_last_error(), "canonical path identity could not be read"
            )
        value = buffer.value
    finally:
        kernel32.CloseHandle(handle)
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _reject_device_path(path: str | os.PathLike[str], *, status: int) -> None:
    if os.name != "nt":
        return
    spelling = os.fspath(path).replace("/", "\\")
    if spelling.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        raise SnapshotBatchError(
            "path_alias_rejected",
            "Windows device-path spellings are forbidden",
            exit_status=status,
        )
    logical = Path(os.fspath(path))
    if not _windows_logical_path_is_safe(logical):
        raise SnapshotBatchError(
            "path_alias_rejected",
            "Windows logical path components are unsafe",
            exit_status=status,
        )
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not _windows_logical_path_is_safe(absolute):
        raise SnapshotBatchError(
            "path_alias_rejected",
            "Windows logical path components are unsafe",
            exit_status=status,
        )


def _canonical_existing_path(
    path: str | os.PathLike[str],
    *,
    directory: bool,
    status: int,
) -> Path:
    _reject_device_path(path, status=status)
    absolute = Path(os.path.abspath(os.fspath(path)))
    if os.name == "nt":
        # Hosted Windows runners commonly expose trusted roots through SUBST
        # drives and 8.3 path spellings. GetFinalPathNameByHandleW expands
        # those aliases, so spelling equality would reject the same object.
        # Validate both complete chains and their object identity before
        # accepting that normalization; junctions/reparse points still fail.
        supplied_parent = absolute if directory else absolute.parent
        supplied_chain = _checked_directory_chain(supplied_parent, status=status)
        supplied_state = (
            _require_safe_directory(absolute, status=status)
            if directory
            else _require_safe_regular(absolute, status=status)
        )
        try:
            resolved = _windows_final_path(absolute, directory=directory)
        except (OSError, RuntimeError) as error:
            raise SnapshotBatchError(
                "path_unavailable",
                "a trusted path cannot be canonicalized",
                exit_status=status,
            ) from error
        supplied_text = os.path.normcase(os.path.normpath(str(absolute)))
        canonical_text = os.path.normcase(os.path.normpath(str(resolved)))
        local_drive_alias = (
            absolute.is_absolute()
            and resolved.is_absolute()
            and re.fullmatch(r"[A-Za-z]:", absolute.drive) is not None
            and re.fullmatch(r"[A-Za-z]:", resolved.drive) is not None
        )
        if supplied_text != canonical_text and not local_drive_alias:
            raise SnapshotBatchError(
                "path_alias_rejected",
                "trusted paths must use their canonical identity spelling",
                exit_status=status,
            )
        canonical_parent = resolved if directory else resolved.parent
        canonical_chain = _checked_directory_chain(canonical_parent, status=status)
        canonical_state = (
            _require_safe_directory(resolved, status=status)
            if directory
            else _require_safe_regular(resolved, status=status)
        )
        supplied_identity = (
            _directory_identity(supplied_state)
            if directory
            else _stable_path_identity(supplied_state)
        )
        canonical_identity = (
            _directory_identity(canonical_state)
            if directory
            else _stable_path_identity(canonical_state)
        )
        if supplied_identity != canonical_identity:
            raise SnapshotBatchError(
                "path_alias_rejected",
                "trusted path aliases must resolve to the same object",
                exit_status=status,
            )
        _assert_directory_chain(supplied_chain, status=status)
        _assert_directory_chain(canonical_chain, status=status)
        try:
            confirmed = _windows_final_path(absolute, directory=directory)
        except (OSError, RuntimeError) as error:
            raise SnapshotBatchError(
                "path_unavailable",
                "a trusted path cannot be canonicalized",
                exit_status=status,
            ) from error
        if os.path.normcase(os.path.normpath(str(confirmed))) != canonical_text:
            raise SnapshotBatchError(
                "path_changed",
                "trusted path identity changed during canonicalization",
                exit_status=status,
            )
        current_supplied = (
            _require_safe_directory(absolute, status=status)
            if directory
            else _require_safe_regular(absolute, status=status)
        )
        current_canonical = (
            _require_safe_directory(resolved, status=status)
            if directory
            else _require_safe_regular(resolved, status=status)
        )
        current_supplied_identity = (
            _directory_identity(current_supplied)
            if directory
            else _stable_path_identity(current_supplied)
        )
        current_canonical_identity = (
            _directory_identity(current_canonical)
            if directory
            else _stable_path_identity(current_canonical)
        )
        if (
            current_supplied_identity != supplied_identity
            or current_canonical_identity != canonical_identity
        ):
            raise SnapshotBatchError(
                "path_changed",
                "trusted path identity changed during canonicalization",
                exit_status=status,
            )
        _assert_directory_chain(supplied_chain, status=status)
        _assert_directory_chain(canonical_chain, status=status)
        return resolved
    try:
        resolved = absolute.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise SnapshotBatchError(
            "path_unavailable", "a trusted path cannot be canonicalized", exit_status=status
        ) from error
    supplied = os.path.normcase(os.path.normpath(str(absolute)))
    canonical = os.path.normcase(os.path.normpath(str(resolved)))
    if supplied != canonical:
        raise SnapshotBatchError(
            "path_alias_rejected",
            "trusted paths must use their canonical identity spelling",
            exit_status=status,
        )
    return resolved


def _canonical_new_child(
    path: str | os.PathLike[str], *, status: int
) -> Path:
    _reject_device_path(path, status=status)
    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute.name in {"", ".", ".."}:
        raise SnapshotBatchError(
            "invalid_output", "output must name a new child directory", exit_status=status
        )
    parent = _canonical_existing_path(
        absolute.parent, directory=True, status=status
    )
    return parent / absolute.name


def _preflight_output(
    output_dir: str | os.PathLike[str],
    *,
    task_export: VerifiedTaskExport,
    source_map: VerifiedSnapshotSourceMap,
) -> Path:
    output = _canonical_new_child(output_dir, status=2)
    try:
        os.lstat(_windows_extended_path(output))
    except FileNotFoundError:
        pass
    except OSError as error:
        raise SnapshotBatchError(
            "output_unavailable", "output state cannot be inspected", exit_status=5
        ) from error
    else:
        raise SnapshotBatchError(
            "output_exists", "output already exists and cannot be replaced", exit_status=5
        )
    protected = (task_export.root, source_map.path, *source_map.sources.values())
    if any(_paths_overlap(output, path) for path in protected):
        raise SnapshotBatchError(
            "output_path_conflict", "output overlaps a trusted input", exit_status=2
        )
    _require_safe_directory(output.parent, status=5)
    return output


def _begin_staging(output: Path) -> _BatchStaging:
    parent_chain = _checked_directory_chain(output.parent, status=5)
    parent_state = _require_safe_directory(output.parent, status=5)
    parent_identity = _directory_identity(parent_state)
    if os.name == "posix":
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        parent_fd: int | None = None
        staging_fd: int | None = None
        staging: Path | None = None
        staging_name: str | None = None
        try:
            parent_fd = os.open(output.parent, flags)
            opened_parent = os.fstat(parent_fd)
            if (
                not stat.S_ISDIR(opened_parent.st_mode)
                or _is_reparse(opened_parent)
                or _directory_identity(opened_parent) != parent_identity
            ):
                raise SnapshotBatchError(
                    "transaction_changed", "batch output parent changed", exit_status=5
                )
            _assert_directory_chain(parent_chain, status=5)
            for _ in range(128):
                candidate = f".{output.name}.{secrets.token_hex(16)}.staging"
                try:
                    os.mkdir(candidate, 0o700, dir_fd=parent_fd)
                except FileExistsError:
                    continue
                staging_name = candidate
                staging = output.parent / candidate
                break
            if staging is None or staging_name is None:
                raise SnapshotBatchError(
                    "transaction_failed", "batch staging allocation failed", exit_status=5
                )
            staging_fd = os.open(staging_name, flags, dir_fd=parent_fd)
            state = os.fstat(staging_fd)
            named_state = os.stat(
                staging_name, dir_fd=parent_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISDIR(state.st_mode)
                or _is_reparse(state)
                or _directory_identity(named_state) != _directory_identity(state)
            ):
                raise SnapshotBatchError(
                    "transaction_changed", "batch staging identity changed", exit_status=5
                )
            return _BatchStaging(
                output=output,
                parent=output.parent,
                parent_identity=parent_identity,
                parent_chain=parent_chain,
                staging=staging,
                staging_identity=_directory_identity(state),
                parent_fd=parent_fd,
                staging_fd=staging_fd,
            )
        except Exception:
            if staging_fd is not None:
                os.close(staging_fd)
            if staging is not None and staging_name is not None and parent_fd is not None:
                try:
                    named = os.stat(
                        staging_name, dir_fd=parent_fd, follow_symlinks=False
                    )
                    if _directory_identity(named) == _directory_identity(
                        os.lstat(_windows_extended_path(staging))
                    ):
                        os.rmdir(staging_name, dir_fd=parent_fd)
                except OSError:
                    pass
            if parent_fd is not None:
                os.close(parent_fd)
            raise

    for _ in range(128):
        staging = output.parent / f".{output.name}.{secrets.token_hex(16)}.staging"
        try:
            _windows_extended_path(staging).mkdir(mode=0o700)
        except FileExistsError:
            continue
        except OSError as error:
            raise SnapshotBatchError(
                "transaction_failed", "batch staging could not be created", exit_status=5
            ) from error
        state = _require_safe_directory(staging, status=5)
        windows_parent_identity: tuple[int, int] | None = None
        windows_staging_identity: tuple[int, int] | None = None
        if os.name == "nt":
            parent_handle: int | None = None
            staging_handle: int | None = None
            try:
                parent_handle, windows_parent_identity = _windows_open_directory(
                    output.parent, delete_access=False, share_delete=True
                )
                staging_handle, windows_staging_identity = _windows_open_directory(
                    staging, delete_access=False, share_delete=True
                )
                if (
                    windows_parent_identity[1] != parent_identity[1]
                    or windows_staging_identity[1] != state.st_ino
                ):
                    raise SnapshotBatchError(
                        "transaction_changed",
                        "batch transaction changed while opening trusted handles",
                        exit_status=5,
                    )
            except Exception:
                try:
                    current = os.lstat(_windows_extended_path(staging))
                    if _directory_identity(current) == _directory_identity(state):
                        _windows_extended_path(staging).rmdir()
                except OSError:
                    pass
                raise
            finally:
                if staging_handle is not None:
                    _windows_close_handle(staging_handle)
                if parent_handle is not None:
                    _windows_close_handle(parent_handle)
        return _BatchStaging(
            output=output,
            parent=output.parent,
            parent_identity=parent_identity,
            parent_chain=parent_chain,
            staging=staging,
            staging_identity=_directory_identity(state),
            windows_parent_identity=windows_parent_identity,
            windows_staging_identity=windows_staging_identity,
        )
    raise SnapshotBatchError(
        "transaction_failed", "batch staging allocation failed", exit_status=5
    )


def _close_staging(state: _BatchStaging) -> None:
    if state.staging_fd is not None:
        try:
            os.close(state.staging_fd)
        except OSError:
            # Closing a directory descriptor is cleanup only: surfacing this
            # from ``finally`` would hide the transaction's real result (and,
            # after rename, falsely make a committed publication look failed).
            pass
        state.staging_fd = None
    if state.parent_fd is not None:
        try:
            os.close(state.parent_fd)
        except OSError:
            pass
        state.parent_fd = None


def _cleanup_parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str):
        raise SnapshotBatchError(
            "transaction_failed", "cleanup layout path is invalid", exit_status=5
        )
    parts = tuple(relative.split("/"))
    if (
        not parts
        or any(
            not part
            or part in {".", ".."}
            or "\\" in part
            or "\x00" in part
            for part in parts
        )
    ):
        raise SnapshotBatchError(
            "transaction_failed", "cleanup layout path is invalid", exit_status=5
        )
    return parts


def _snapshot_cleanup_node(path: Path, *, directory: bool) -> _CleanupNode:
    _windows_assert_no_named_streams(path, status=5)
    if directory:
        current = _require_safe_directory(path, status=5)
        identity: tuple[object, ...] = _directory_identity(current)
    else:
        current = _require_safe_regular(path, status=5)
        identity = _stable_path_identity(current)
    _windows_assert_no_named_streams(path, status=5)
    return _CleanupNode(directory=directory, identity=identity)


def _register_cleanup_record(
    state: _BatchStaging,
    relative: str,
    record: _CleanupNode,
) -> None:
    parts = _cleanup_parts(relative)
    current = _snapshot_cleanup_node(
        state.staging.joinpath(*parts), directory=record.directory
    )
    if current != record:
        raise SnapshotBatchError(
            "transaction_changed",
            "a transaction-created node changed before registration",
            exit_status=5,
        )
    previous = state.cleanup_nodes.get(relative)
    if previous is not None and previous != record:
        raise SnapshotBatchError(
            "transaction_changed",
            "cleanup layout identity changed",
            exit_status=5,
        )
    if previous is None and len(state.cleanup_nodes) >= _MAX_BATCH_CLEANUP_NODES:
        raise SnapshotBatchError(
            "batch_limit_exceeded",
            "cleanup layout exceeds its fixed node budget",
            exit_status=3,
        )
    state.cleanup_nodes[relative] = record


def _register_cleanup_node(
    state: _BatchStaging, relative: str, *, directory: bool
) -> None:
    parts = _cleanup_parts(relative)
    record = _snapshot_cleanup_node(
        state.staging.joinpath(*parts), directory=directory
    )
    _register_cleanup_record(state, relative, record)


def _create_tracked_directory(state: _BatchStaging, relative: str) -> Path:
    path = state.staging.joinpath(*_cleanup_parts(relative))
    try:
        _windows_extended_path(path).mkdir(mode=0o700)
    except OSError as error:
        raise SnapshotBatchError(
            "transaction_failed",
            "batch directory creation failed",
            exit_status=5,
        ) from error
    _register_cleanup_node(state, relative, directory=True)
    return path


def _register_core_bundle(
    state: _BatchStaging,
    summary: SealedSnapshotSummary,
    task: SnapshotTaskSpec,
    *,
    policy: SnapshotPolicy,
) -> None:
    """Pin the exact successful core output as cleanup-owned nodes."""

    bundle_relative = f"bundles/{task.task_id}"
    tree_relative = f"{bundle_relative}/tree"
    control_relative = f"{bundle_relative}/control"
    bundle = state.staging.joinpath(*_cleanup_parts(bundle_relative))
    if (
        not isinstance(summary, SealedSnapshotSummary)
        or summary.snapshot_root != bundle
        or summary.task_id != task.task_id
        or summary.repo_url != task.repo_url
        or summary.commit != task.commit
        or isinstance(summary.file_count, bool)
        or not isinstance(summary.file_count, int)
        or summary.file_count != len(summary.files)
        or not 0 <= summary.file_count <= policy.max_files
    ):
        raise SnapshotBatchError(
            "transaction_changed",
            "core snapshot summary does not identify its expected bundle",
            exit_status=5,
        )

    directories = {bundle_relative, tree_relative, control_relative}
    files = {
        f"{control_relative}/attestation.json",
        f"{control_relative}/manifest.jsonl",
    }
    tree_children: dict[str, set[str]] = {"": set()}
    seen_paths: set[str] = set()
    for record in summary.files:
        if not isinstance(record.path, str):
            raise SnapshotBatchError(
                "transaction_changed",
                "core snapshot summary contains an invalid path",
                exit_status=5,
            )
        components = tuple(record.path.split("/"))
        if (
            not components
            or len(components) > policy.max_depth
            or record.path in seen_paths
            or any(
                not component
                or component in {".", ".."}
                or "\\" in component
                or "\x00" in component
                for component in components
            )
        ):
            raise SnapshotBatchError(
                "transaction_changed",
                "core snapshot summary contains an invalid path",
                exit_status=5,
            )
        seen_paths.add(record.path)
        files.add(f"{tree_relative}/{record.path}")
        for index, component in enumerate(components):
            parent = "/".join(components[:index])
            tree_children.setdefault(parent, set()).add(component)
            if index < len(components) - 1:
                child = "/".join(components[: index + 1])
                tree_children.setdefault(child, set())
                directories.add(f"{tree_relative}/{child}")

    if len(directories) + len(files) > _MAX_BATCH_CLEANUP_NODES:
        raise SnapshotBatchError(
            "batch_limit_exceeded",
            "core cleanup layout exceeds its fixed node budget",
            exit_status=3,
        )
    _fixed_names(bundle, {"tree", "control"}, status=5)
    _fixed_names(
        bundle / "control", {"attestation.json", "manifest.jsonl"}, status=5
    )
    for relative, names in tree_children.items():
        directory = bundle / "tree"
        if relative:
            directory = directory.joinpath(*relative.split("/"))
        _fixed_names(directory, names, status=5)

    for relative in sorted(directories, key=lambda value: (value.count("/"), value)):
        _register_cleanup_node(state, relative, directory=True)
    for relative in sorted(files):
        _register_cleanup_node(state, relative, directory=False)


def _exclusive_write(path: Path, payload: bytes) -> _CleanupNode:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(_windows_extended_path(path), flags, 0o600)
    except OSError as error:
        raise SnapshotBatchError(
            "transaction_failed", "batch control file creation failed", exit_status=5
        ) from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse(opened):
            raise SnapshotBatchError(
                "transaction_failed", "batch control file is unsafe", exit_status=5
            )
        view = memoryview(payload)
        position = 0
        while position < len(view):
            written = os.write(descriptor, view[position:])
            if written < 1:
                raise OSError(errno.EIO, "short write")
            position += written
        os.fsync(descriptor)
        finished = os.fstat(descriptor)
        if (
            (finished.st_dev, finished.st_ino) != (opened.st_dev, opened.st_ino)
            or finished.st_size != len(payload)
        ):
            raise SnapshotBatchError(
                "transaction_failed", "batch control write was incomplete", exit_status=5
            )
    except OSError as error:
        raise SnapshotBatchError(
            "transaction_failed", "batch control write failed", exit_status=5
        ) from error
    finally:
        os.close(descriptor)
    published = _require_safe_regular(path, status=5)
    if (
        (published.st_dev, published.st_ino) != (opened.st_dev, opened.st_ino)
        or published.st_size != len(payload)
    ):
        raise SnapshotBatchError(
            "transaction_changed", "batch control file changed after writing", exit_status=5
        )
    return _CleanupNode(directory=False, identity=_stable_path_identity(published))


def _fsync_directory(path: Path) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(_windows_extended_path(path), flags)
    except OSError as error:
        if os.name == "posix":
            raise SnapshotBatchError(
                "transaction_failed", "batch directory cannot be opened", exit_status=5
            ) from error
        return
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno not in {errno.EINVAL, errno.ENOTSUP, errno.EBADF}:
                raise SnapshotBatchError(
                    "transaction_failed", "batch directory sync failed", exit_status=5
                ) from error
    finally:
        os.close(descriptor)


def _publish_noreplace(state: _BatchStaging) -> None:
    _assert_directory_chain(state.parent_chain, status=5)
    parent = _require_safe_directory(state.parent, status=5)
    if _directory_identity(parent) != state.parent_identity:
        raise SnapshotBatchError(
            "transaction_changed", "batch output parent changed", exit_status=5
        )
    if os.name == "posix":
        if state.parent_fd is None or state.staging_fd is None:
            raise SnapshotBatchError(
                "transaction_failed", "trusted publication handles are missing", exit_status=5
            )
        opened_parent = os.fstat(state.parent_fd)
        opened_staging = os.fstat(state.staging_fd)
        named_staging = os.stat(
            state.staging.name,
            dir_fd=state.parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(opened_parent.st_mode)
            or not stat.S_ISDIR(opened_staging.st_mode)
            or _is_reparse(opened_parent)
            or _is_reparse(opened_staging)
            or _directory_identity(opened_parent) != state.parent_identity
            or _directory_identity(opened_staging) != state.staging_identity
            or _directory_identity(named_staging) != state.staging_identity
        ):
            raise SnapshotBatchError(
                "transaction_changed", "batch publication identity changed", exit_status=5
            )
        try:
            renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
        except (AttributeError, OSError) as error:
            raise SnapshotBatchError(
                "transaction_unsupported",
                "atomic no-replace publication is unavailable",
                exit_status=5,
            ) from error
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            state.parent_fd,
            os.fsencode(state.staging.name),
            state.parent_fd,
            os.fsencode(state.output.name),
            1,
        )
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise SnapshotBatchError(
                    "output_exists", "output appeared during publication", exit_status=5
                )
            raise SnapshotBatchError(
                "transaction_failed", "atomic batch publication failed", exit_status=5
            )
        state.published = True
        try:
            destination = os.stat(
                state.output.name,
                dir_fd=state.parent_fd,
                follow_symlinks=False,
            )
            if _directory_identity(destination) != state.staging_identity:
                raise SnapshotBatchError(
                    "publication_commit_uncertain",
                    "published batch identity is not the verified staging identity",
                    exit_status=5,
                    committed=True,
                )
            _assert_directory_chain(state.parent_chain, status=5)
            os.fsync(state.parent_fd)
        except SnapshotBatchError as error:
            if error.committed:
                raise
            raise SnapshotBatchError(
                "publication_commit_uncertain",
                "batch rename committed but its parent identity changed",
                exit_status=5,
                committed=True,
            ) from error
        except OSError as error:
            raise SnapshotBatchError(
                "publication_commit_uncertain",
                "batch rename committed but durability could not be confirmed",
                exit_status=5,
                committed=True,
            ) from error
    else:
        parent_handle: int | None = None
        staging_handle: int | None = None
        try:
            parent_handle, parent_identity = _windows_open_directory(
                state.parent, delete_access=False, share_delete=False
            )
            staging_handle, staging_identity = _windows_open_directory(
                state.staging, delete_access=True, share_delete=False
            )
            if (
                parent_identity != state.windows_parent_identity
                or staging_identity != state.windows_staging_identity
            ):
                raise SnapshotBatchError(
                    "transaction_changed", "batch transaction identity changed", exit_status=5
                )
            try:
                os.lstat(_windows_extended_path(state.output))
            except FileNotFoundError:
                pass
            else:
                raise SnapshotBatchError(
                    "output_exists", "output appeared during publication", exit_status=5
                )
            _assert_directory_chain(state.parent_chain, status=5)
            _windows_rename_directory_handle(staging_handle, state.output)
            # SetFileInformationByHandle success is the commit point.  The
            # trusted staging handle identifies exactly the directory moved.
            state.published = True
            try:
                destination = _require_safe_directory(state.output, status=5)
                if _directory_identity(destination) != state.staging_identity:
                    raise SnapshotBatchError(
                        "publication_commit_uncertain",
                        "published batch identity is not the verified staging identity",
                        exit_status=5,
                        committed=True,
                    )
                _assert_directory_chain(state.parent_chain, status=5)
            except SnapshotBatchError as error:
                if error.committed:
                    raise
                raise SnapshotBatchError(
                    "publication_commit_uncertain",
                    "batch rename committed but its parent identity changed",
                    exit_status=5,
                    committed=True,
                ) from error
        finally:
            if staging_handle is not None:
                _windows_close_handle(staging_handle)
            if parent_handle is not None:
                _windows_close_handle(parent_handle)
    if not state.published:
        raise SnapshotBatchError(
            "transaction_failed", "batch publication did not commit", exit_status=5
        )


def _cleanup_node_matches(path: Path, expected: _CleanupNode) -> bool:
    try:
        _windows_assert_no_named_streams(path, status=5)
        current = os.lstat(_windows_extended_path(path))
        if expected.directory:
            identity: tuple[object, ...] = _directory_identity(current)
            safe_type = (
                stat.S_ISDIR(current.st_mode)
                and not stat.S_ISLNK(current.st_mode)
                and not _is_reparse(current)
            )
        else:
            identity = _stable_path_identity(current)
            safe_type = (
                stat.S_ISREG(current.st_mode)
                and not stat.S_ISLNK(current.st_mode)
                and not _is_reparse(current)
                and current.st_nlink <= 1
            )
        _windows_assert_no_named_streams(path, status=5)
    except (OSError, SnapshotBatchError):
        return False
    return safe_type and identity == expected.identity


def _cleanup_layout_is_exact(
    path: Path,
    expected_identity: tuple[int, int],
    allowed: Mapping[str, _CleanupNode],
) -> bool:
    """Validate the entire bounded allowlist before deleting any node."""

    if len(allowed) > _MAX_BATCH_CLEANUP_NODES:
        return False
    try:
        root = os.lstat(_windows_extended_path(path))
        if (
            not stat.S_ISDIR(root.st_mode)
            or stat.S_ISLNK(root.st_mode)
            or _is_reparse(root)
            or _directory_identity(root) != expected_identity
        ):
            return False
        _windows_assert_no_named_streams(path, status=5)
        stack: list[tuple[str, Path]] = [("", path)]
        seen: set[str] = set()
        while stack:
            parent_relative, directory = stack.pop()
            with os.scandir(_windows_extended_path(directory)) as entries:
                for entry in entries:
                    relative = (
                        entry.name
                        if not parent_relative
                        else f"{parent_relative}/{entry.name}"
                    )
                    expected = allowed.get(relative)
                    if (
                        expected is None
                        or relative in seen
                        or len(seen) >= _MAX_BATCH_CLEANUP_NODES
                    ):
                        return False
                    child = directory / entry.name
                    if not _cleanup_node_matches(child, expected):
                        return False
                    seen.add(relative)
                    if expected.directory:
                        stack.append((relative, child))
        final_root = os.lstat(_windows_extended_path(path))
        _windows_assert_no_named_streams(path, status=5)
        return (
            _directory_identity(final_root) == expected_identity
            and seen == set(allowed)
        )
    except (OSError, SnapshotBatchError):
        return False


def _cleanup_tree(
    path: Path,
    expected_identity: tuple[int, int],
    allowed: Mapping[str, _CleanupNode],
) -> None:
    """Delete only a fully prevalidated transaction-owned staging layout."""

    if not _cleanup_layout_is_exact(path, expected_identity, allowed):
        # Unknown, missing, or replaced nodes make the whole tree ineligible.
        return
    ordered = sorted(
        allowed.items(),
        key=lambda item: (
            item[0].count("/"),
            1 if not item[1].directory else 0,
            item[0],
        ),
        reverse=True,
    )
    try:
        for relative, expected in ordered:
            child = path.joinpath(*_cleanup_parts(relative))
            if not _cleanup_node_matches(child, expected):
                return
            if expected.directory:
                _windows_extended_path(child).rmdir()
            else:
                _windows_extended_path(child).unlink()
            try:
                os.lstat(_windows_extended_path(child))
            except FileNotFoundError:
                pass
            else:
                return
        final = os.lstat(_windows_extended_path(path))
        if (
            stat.S_ISDIR(final.st_mode)
            and not stat.S_ISLNK(final.st_mode)
            and not _is_reparse(final)
            and _directory_identity(final) == expected_identity
        ):
            _windows_assert_no_named_streams(path, status=5)
            _windows_extended_path(path).rmdir()
    except (OSError, SnapshotBatchError):
        # Preserving a remainder is safer than deleting an unproven object.
        return


def _batch_content_root(task_lines: Iterable[bytes]) -> str:
    digest = hashlib.sha256()
    digest.update(_BATCH_CONTENT_DOMAIN)
    for line in task_lines:
        digest.update(line)
    return digest.hexdigest()


def _batch_mac(key: bytes, key_id: str, manifest: bytes) -> str:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    digest.update(_BATCH_ATTESTATION_DOMAIN)
    digest.update(key_id.encode("ascii"))
    digest.update(b"\0")
    digest.update(manifest)
    return digest.hexdigest()


def _snapshot_node_count(files: Sequence[Any]) -> int:
    directories: set[str] = set()
    for record in files:
        components = record.path.split("/")
        for depth in range(1, len(components)):
            directories.add("/".join(components[:depth]))
    return len(files) + len(directories)


def _verification_diagnostic_code(
    stage: str,
    task_ordinal: int,
    error: BaseException,
) -> str:
    """Return bounded, path-free context for a failed verification pass."""

    inner_code = getattr(error, "code", None)
    if (
        type(inner_code) is not str
        or len(inner_code) > 80
        or _DIAGNOSTIC_CODE_RE.fullmatch(inner_code) is None
    ):
        inner_code = "value_error" if isinstance(error, ValueError) else "inner_error"
    diagnostic_code = f"{stage}_task_{task_ordinal:03d}_{inner_code}"
    if _DIAGNOSTIC_CODE_RE.fullmatch(diagnostic_code) is None:
        return f"{stage}_task_{task_ordinal:03d}_inner_error"
    return diagnostic_code


def _materialized_batch_digest(
    bundles: Path,
    verified_snapshots: Sequence[Any],
    *,
    policy: SnapshotPolicy,
    status: int,
) -> str:
    """Hash the exact fixed bundle set around a full verification pass.

    This closes the practical cross-bundle window in which an earlier bundle
    could change while a later bundle is being deeply verified.  Callers take
    one digest after the first complete pass and another after the second.
    """

    expected_tasks = {verified.task_id for verified in verified_snapshots}
    _fixed_names(bundles, expected_tasks, status=status)
    digest = hashlib.sha256()
    digest.update(_BATCH_MATERIALIZED_DOMAIN)
    aggregate_files = 0
    aggregate_nodes = 0
    aggregate_bytes = 0
    for verified in verified_snapshots:
        bundle = bundles / verified.task_id
        tree = bundle / "tree"
        control = bundle / "control"
        _fixed_names(bundle, {"tree", "control"}, status=status)
        _fixed_names(
            control, {"attestation.json", "manifest.jsonl"}, status=status
        )
        children: dict[str, set[str]] = {"": set()}
        for record in verified.files:
            components = record.path.split("/")
            for index, component in enumerate(components):
                parent = "/".join(components[:index])
                children.setdefault(parent, set()).add(component)
                if index < len(components) - 1:
                    children.setdefault("/".join(components[: index + 1]), set())
        aggregate_files += verified.file_count
        aggregate_nodes += verified.file_count + max(0, len(children) - 1)
        aggregate_bytes += verified.total_bytes
        if (
            aggregate_files > _MAX_BATCH_TOTAL_FILES
            or aggregate_nodes > _MAX_BATCH_TOTAL_NODES
            or aggregate_bytes > _MAX_BATCH_TOTAL_BYTES
        ):
            raise SnapshotBatchError(
                "batch_limit_exceeded",
                "materialized batch exceeds its aggregate budget",
                exit_status=status,
            )
        digest.update(verified.task_id.encode("ascii"))
        digest.update(b"\0")
        for relative, names in sorted(children.items()):
            directory = tree if not relative else tree.joinpath(*relative.split("/"))
            _fixed_names(directory, names, status=status)
            digest.update(b"D\0")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
        for record in verified.files:
            data = _read_stable_file(
                tree.joinpath(*record.path.split("/")), record.size, status=status
            )
            if (
                len(data) != record.size
                or hashlib.sha256(data).hexdigest() != record.sha256
            ):
                raise SnapshotBatchError(
                    "batch_changed",
                    "materialized task bytes changed around verification",
                    exit_status=status,
                )
            digest.update(b"F\0")
            digest.update(record.path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(data).digest())
        for name, maximum in (
            ("manifest.jsonl", policy.max_manifest_bytes),
            ("attestation.json", _MAX_BATCH_ATTESTATION_BYTES),
        ):
            payload = _read_stable_file(control / name, maximum, status=status)
            digest.update(b"C\0")
            digest.update(name.encode("ascii"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()


def _manifest_bytes(
    task_export: VerifiedTaskExport,
    source_map_sha256: str,
    tasks: Sequence[SnapshotBatchTask],
    policy: SnapshotPolicy,
) -> tuple[bytes, str, int, int, int]:
    header = {
        "contract_version": BATCH_CONTRACT_VERSION,
        "profile_id": task_export.profile_id,
        "public_manifest_sha256": task_export.public_manifest_sha256,
        "record_type": "header",
        "schema_version": task_export.schema_version,
        "snapshot_policy": policy.to_dict(),
        "source_map_sha256": source_map_sha256,
        "split": task_export.split,
        "task_count": len(tasks),
        "tasks_sha256": task_export.tasks_sha256,
    }
    task_lines = tuple(_canonical_json(task.to_record()) + b"\n" for task in tasks)
    content_root = _batch_content_root(task_lines)
    total_files = sum(task.file_count for task in tasks)
    total_nodes = sum(task.node_count for task in tasks)
    total_bytes = sum(task.total_bytes for task in tasks)
    if (
        len(tasks) > _MAX_BATCH_TASKS
        or total_files > _MAX_BATCH_TOTAL_FILES
        or total_nodes > _MAX_BATCH_TOTAL_NODES
        or total_bytes > _MAX_BATCH_TOTAL_BYTES
    ):
        raise SnapshotBatchError(
            "batch_limit_exceeded",
            "batch aggregate exceeds its fixed resource budget",
            exit_status=3,
        )
    footer = {
        "batch_content_root": content_root,
        "record_type": "footer",
        "task_count": len(tasks),
        "total_bytes": total_bytes,
        "total_files": total_files,
        "total_nodes": total_nodes,
        "total_entries": sum(task.entry_count for task in tasks),
        "total_regular_files": sum(task.regular_file_count for task in tasks),
        "total_gitlinks": sum(task.gitlink_count for task in tasks),
        "total_regular_file_bytes": sum(task.regular_file_bytes for task in tasks),
        "total_materialized_bytes": sum(task.materialized_bytes for task in tasks),
    }
    payload = _canonical_json(header) + b"\n" + b"".join(task_lines) + _canonical_json(footer) + b"\n"
    if len(payload) > _MAX_BATCH_MANIFEST_BYTES:
        raise SnapshotBatchError(
            "batch_limit_exceeded", "batch manifest exceeds its byte budget", exit_status=3
        )
    return payload, content_root, total_files, total_nodes, total_bytes


def prepare_snapshot_batch(
    task_export_dir: str | os.PathLike[str],
    *,
    expected_tasks_sha256: str,
    expected_public_manifest_sha256: str,
    source_map_path: str | os.PathLike[str],
    expected_source_map_sha256: str,
    output_dir: str | os.PathLike[str],
    attestation_key: bytes | bytearray | memoryview,
    key_id: str,
    policy: SnapshotPolicy = DEFAULT_SNAPSHOT_POLICY,
) -> SnapshotBatchSummary:
    """Prepare and transactionally publish one strict sealed-snapshot batch."""

    if not isinstance(policy, SnapshotPolicy):
        raise SnapshotBatchError(
            "invalid_policy", "snapshot policy is invalid", exit_status=2
        )
    key = _copy_key(attestation_key)
    key_id = _validate_key_id(key_id)
    task_export = load_verified_task_export(
        task_export_dir,
        expected_tasks_sha256=expected_tasks_sha256,
        expected_public_manifest_sha256=expected_public_manifest_sha256,
    )
    source_map = load_verified_snapshot_source_map(
        source_map_path,
        expected_source_map_sha256=expected_source_map_sha256,
        task_export=task_export,
    )
    output = _preflight_output(
        output_dir, task_export=task_export, source_map=source_map
    )
    staging = _begin_staging(output)
    try:
        bundles = _create_tracked_directory(staging, "bundles")
        control = _create_tracked_directory(staging, "control")
        for task in task_export.tasks:
            source_identity = (task.repo_url, task.commit)
            repository_root = source_map.sources[source_identity]
            _assert_directory_chain(
                source_map.source_chains[source_identity], status=3
            )
            try:
                repository = GitRepository(repository_root)
                prepared = prepare_sealed_snapshot(
                    repository,
                    task_id=task.task_id,
                    repo_url=task.repo_url,
                    commit=task.commit,
                    output_dir=bundles / task.task_id,
                    attestation_key=key,
                    key_id=key_id,
                    policy=policy,
                )
                _register_core_bundle(
                    staging, prepared, task, policy=policy
                )
            except GitFactError as error:
                raise SnapshotBatchError(
                    "source_repository_rejected",
                    "a source repository failed the Git fact gate",
                    exit_status=3,
                ) from error
            except SealedSnapshotError as error:
                source_codes = {
                    "invalid_source_tree",
                    "shallow_repository_rejected",
                    "source_gitlink_rejected",
                    "source_lfs_rejected",
                    "source_limit_exceeded",
                    "source_link_rejected",
                    "source_path_collision",
                    "unsafe_source_path",
                }
                status = 3 if (
                    error.code in source_codes
                    or isinstance(error.__cause__, GitFactError)
                ) else 5
                raise SnapshotBatchError(
                    "snapshot_preparation_failed",
                    "a task snapshot could not be prepared",
                    exit_status=status,
                ) from error
            _assert_directory_chain(
                source_map.source_chains[source_identity], status=3
            )
        _fixed_names(
            bundles, {task.task_id for task in task_export.tasks}, status=5
        )
        task_results: list[SnapshotBatchTask] = []
        aggregate_files = 0
        aggregate_nodes = 0
        aggregate_bytes = 0
        first_verified: list[Any] = []
        for task_ordinal, task in enumerate(task_export.tasks, start=1):
            try:
                verified = verify_sealed_snapshot(
                    bundles / task.task_id,
                    expected_task_id=task.task_id,
                    expected_repo_url=task.repo_url,
                    expected_commit=task.commit,
                    attestation_key=key,
                    expected_key_id=key_id,
                    policy=policy,
                )
            except (SealedSnapshotError, ValueError) as error:
                raise SnapshotBatchError(
                    "transaction_verification_failed",
                    "a prepared task failed verification before batch binding",
                    exit_status=5,
                    diagnostic_code=_verification_diagnostic_code(
                        "pass1", task_ordinal, error
                    ),
                ) from error
            aggregate_files += verified.file_count
            verified_node_count = _snapshot_node_count(verified.files)
            if verified_node_count > policy.max_files:
                raise SnapshotBatchError(
                    "batch_limit_exceeded",
                    "a task node set exceeds the fixed snapshot policy",
                    exit_status=3,
                )
            aggregate_nodes += verified_node_count
            aggregate_bytes += verified.total_bytes
            if (
                aggregate_files > _MAX_BATCH_TOTAL_FILES
                or aggregate_nodes > _MAX_BATCH_TOTAL_NODES
                or aggregate_bytes > _MAX_BATCH_TOTAL_BYTES
            ):
                raise SnapshotBatchError(
                    "batch_limit_exceeded",
                    "batch aggregate exceeds its fixed resource budget",
                    exit_status=3,
                )
            task_results.append(
                SnapshotBatchTask(
                    task_id=task.task_id,
                    repo_url=task.repo_url,
                    commit=task.commit,
                    split=task.split,
                    instruction_id=task.instruction_id,
                    snapshot_manifest_sha256=verified.manifest_sha256,
                    snapshot_content_root=verified.content_root,
                    root_tree=verified.root_tree,
                    file_count=verified.file_count,
                    node_count=verified_node_count,
                    total_bytes=verified.total_bytes,
                    entry_count=verified.entry_count,
                    regular_file_count=verified.regular_file_count,
                    gitlink_count=verified.gitlink_count,
                    regular_file_bytes=verified.regular_file_bytes,
                    materialized_bytes=verified.materialized_bytes,
                )
            )
            first_verified.append(verified)
        baseline_materialized = _materialized_batch_digest(
            bundles, first_verified, policy=policy, status=5
        )
        manifest, content_root, total_files, total_nodes, total_bytes = _manifest_bytes(
            task_export, source_map.sha256, task_results, policy
        )
        manifest_sha256 = _sha256(manifest)
        attestation = {
            "algorithm": ATTESTATION_ALGORITHM,
            "contract_version": BATCH_CONTRACT_VERSION,
            "key_id": key_id,
            "mac": _batch_mac(key, key_id, manifest),
            "manifest_sha256": manifest_sha256,
        }
        attestation_payload = _canonical_json(attestation) + b"\n"
        if len(attestation_payload) > _MAX_BATCH_ATTESTATION_BYTES:
            raise SnapshotBatchError(
                "batch_limit_exceeded", "batch attestation exceeds its byte budget", exit_status=3
            )
        manifest_node = _exclusive_write(control / "manifest.jsonl", manifest)
        _register_cleanup_record(
            staging, "control/manifest.jsonl", manifest_node
        )
        attestation_node = _exclusive_write(
            control / "attestation.json", attestation_payload
        )
        _register_cleanup_record(
            staging, "control/attestation.json", attestation_node
        )
        for task in task_results:
            _fsync_directory(bundles / task.task_id / "tree")
            _fsync_directory(bundles / task.task_id / "control")
            _fsync_directory(bundles / task.task_id)
        _fsync_directory(control)
        _fsync_directory(bundles)
        _fsync_directory(staging.staging)
        _fixed_names(staging.staging, {"bundles", "control"}, status=5)
        _fixed_names(
            control, {"attestation.json", "manifest.jsonl"}, status=5
        )
        _fixed_names(bundles, {task.task_id for task in task_results}, status=5)
        second_verified: list[Any] = []
        for task_ordinal, task in enumerate(task_results, start=1):
            try:
                verified = verify_sealed_snapshot(
                    bundles / task.task_id,
                    expected_task_id=task.task_id,
                    expected_repo_url=task.repo_url,
                    expected_commit=task.commit,
                    attestation_key=key,
                    expected_key_id=key_id,
                    policy=policy,
                )
            except (SealedSnapshotError, ValueError) as error:
                raise SnapshotBatchError(
                    "transaction_verification_failed",
                    "a staged task changed before batch publication",
                    exit_status=5,
                    diagnostic_code=_verification_diagnostic_code(
                        "pass2", task_ordinal, error
                    ),
                ) from error
            if (
                verified.manifest_sha256 != task.snapshot_manifest_sha256
                or verified.content_root != task.snapshot_content_root
                or verified.root_tree != task.root_tree
                or verified.file_count != task.file_count
                or _snapshot_node_count(verified.files) != task.node_count
                or verified.total_bytes != task.total_bytes
                or verified.entry_count != task.entry_count
                or verified.regular_file_count != task.regular_file_count
                or verified.gitlink_count != task.gitlink_count
                or verified.regular_file_bytes != task.regular_file_bytes
                or verified.materialized_bytes != task.materialized_bytes
            ):
                raise SnapshotBatchError(
                    "transaction_verification_failed",
                    "a staged task no longer matches its batch record",
                    exit_status=5,
                    diagnostic_code=f"record_match_task_{task_ordinal:03d}",
                )
            second_verified.append(verified)
        final_materialized = _materialized_batch_digest(
            bundles, second_verified, policy=policy, status=5
        )
        if final_materialized != baseline_materialized:
            raise SnapshotBatchError(
                "transaction_verification_failed",
                "batch materialized state changed across full verification passes",
                exit_status=5,
                diagnostic_code="materialized_match",
            )
        if not _cleanup_layout_is_exact(
            staging.staging,
            staging.staging_identity,
            staging.cleanup_nodes,
        ):
            raise SnapshotBatchError(
                "transaction_changed",
                "staged batch no longer matches its registered fixed layout",
                exit_status=5,
            )
        result = SnapshotBatchSummary(
            batch_root=output,
            profile_id=task_export.profile_id,
            split=task_export.split,
            task_count=len(task_results),
            total_files=total_files,
            total_nodes=total_nodes,
            total_bytes=total_bytes,
            tasks_sha256=task_export.tasks_sha256,
            public_manifest_sha256=task_export.public_manifest_sha256,
            source_map_sha256=source_map.sha256,
            manifest_sha256=manifest_sha256,
            batch_content_root=content_root,
            key_id=key_id,
            tasks=tuple(task_results),
        )
        _publish_noreplace(staging)
        return result
    except SnapshotBatchError:
        raise
    except OSError as error:
        raise SnapshotBatchError(
            "transaction_failed", "batch transaction failed", exit_status=5
        ) from error
    finally:
        if not staging.published:
            _cleanup_tree(
                staging.staging,
                staging.staging_identity,
                staging.cleanup_nodes,
            )
        _close_staging(staging)


def _parse_batch_manifest(
    payload: bytes,
    *,
    policy: SnapshotPolicy,
) -> tuple[
    dict[str, Any], tuple[SnapshotBatchTask, ...], str, int, int, int
]:
    if not payload.endswith(b"\n") or len(payload) > _MAX_BATCH_MANIFEST_BYTES:
        raise SnapshotBatchError(
            "batch_manifest_invalid", "batch manifest framing is invalid", exit_status=4
        )
    raw_lines = payload.splitlines(keepends=True)
    if not 3 <= len(raw_lines) <= _MAX_BATCH_TASKS + 2:
        raise SnapshotBatchError(
            "batch_manifest_invalid", "batch manifest record count is invalid", exit_status=4
        )
    records = tuple(_parse_canonical_line(line, status=4) for line in raw_lines)
    header = records[0]
    header_keys = {
        "contract_version",
        "profile_id",
        "public_manifest_sha256",
        "record_type",
        "schema_version",
        "snapshot_policy",
        "source_map_sha256",
        "split",
        "task_count",
        "tasks_sha256",
    }
    task_count = header.get("task_count")
    split = header.get("split")
    tasks_sha256 = header.get("tasks_sha256")
    source_map_sha256 = header.get("source_map_sha256")
    if (
        set(header) != header_keys
        or header.get("record_type") != "header"
        or header.get("contract_version") != BATCH_CONTRACT_VERSION
        or header.get("profile_id") != PROFILE_ID
        or header.get("schema_version") != PROFILE_SCHEMA_VERSION
        or header.get("public_manifest_sha256") != PROFILE_MANIFEST_SHA256
        or not isinstance(tasks_sha256, str)
        or _SHA256_RE.fullmatch(tasks_sha256) is None
        or not isinstance(source_map_sha256, str)
        or _SHA256_RE.fullmatch(source_map_sha256) is None
        or not isinstance(split, str)
        or split not in _OFFICIAL_SPLIT_COUNTS
        or not _strict_json_equal(
            header.get("snapshot_policy"), policy.to_dict()
        )
        or isinstance(task_count, bool)
        or not isinstance(task_count, int)
        or task_count != _OFFICIAL_SPLIT_COUNTS.get(split)
        or len(records) != task_count + 2
    ):
        raise SnapshotBatchError(
            "batch_manifest_invalid", "batch manifest header is invalid", exit_status=4
        )
    task_keys = {
        "bundle_path",
        "commit",
        "file_count",
        "entry_count",
        "regular_file_count",
        "gitlink_count",
        "regular_file_bytes",
        "materialized_bytes",
        "instruction_id",
        "node_count",
        "record_type",
        "repo_url",
        "snapshot_content_root",
        "root_tree",
        "snapshot_manifest_sha256",
        "split",
        "task_id",
        "total_bytes",
    }
    tasks: list[SnapshotBatchTask] = []
    seen: set[str] = set()
    seen_snapshots: set[tuple[str, str]] = set()
    task_lines: list[bytes] = []
    aggregate_files = 0
    aggregate_nodes = 0
    aggregate_bytes = 0
    for record, raw_line in zip(records[1:-1], raw_lines[1:-1]):
        file_count = record.get("file_count")
        node_count = record.get("node_count")
        total_bytes = record.get("total_bytes")
        try:
            spec = SnapshotTaskSpec(
                task_id=record.get("task_id"),
                repo_url=record.get("repo_url"),
                commit=record.get("commit"),
                split=record.get("split"),
                instruction_id=record.get("instruction_id"),
            )
        except (BenchmarkContractError, ValueError) as error:
            raise SnapshotBatchError(
                "batch_manifest_invalid", "a batch task binding is invalid", exit_status=4
            ) from error
        snapshot_identity = (spec.repo_url.casefold(), spec.commit)
        if (
            set(record) != task_keys
            or record.get("record_type") != "task"
            or spec.split != header["split"]
            or record.get("bundle_path") != f"bundles/{spec.task_id}"
            or spec.task_id in seen
            or snapshot_identity in seen_snapshots
            or not isinstance(record.get("snapshot_manifest_sha256"), str)
            or _SHA256_RE.fullmatch(record["snapshot_manifest_sha256"]) is None
            or not isinstance(record.get("snapshot_content_root"), str)
            or _SHA256_RE.fullmatch(record["snapshot_content_root"]) is None
            or type(record.get("root_tree")) is not str
            or _SHA1_RE.fullmatch(record["root_tree"]) is None
            or isinstance(file_count, bool)
            or not isinstance(file_count, int)
            or not 0 <= file_count <= policy.max_files
            or isinstance(node_count, bool)
            or not isinstance(node_count, int)
            or not file_count <= node_count <= policy.max_files
            or isinstance(total_bytes, bool)
            or not isinstance(total_bytes, int)
            or not 0 <= total_bytes <= policy.max_total_bytes
        ):
            raise SnapshotBatchError(
                "batch_manifest_invalid", "a batch task record is invalid", exit_status=4
            )
        seen.add(spec.task_id)
        seen_snapshots.add(snapshot_identity)
        aggregate_files += file_count
        aggregate_nodes += node_count
        aggregate_bytes += total_bytes
        if (
            aggregate_files > _MAX_BATCH_TOTAL_FILES
            or aggregate_nodes > _MAX_BATCH_TOTAL_NODES
            or aggregate_bytes > _MAX_BATCH_TOTAL_BYTES
        ):
            raise SnapshotBatchError(
                "batch_manifest_invalid",
                "batch manifest exceeds its aggregate resource budget",
                exit_status=4,
            )
        try:
            parsed_task = SnapshotBatchTask(
                task_id=spec.task_id,
                repo_url=spec.repo_url,
                commit=spec.commit,
                split=spec.split,
                instruction_id=spec.instruction_id,
                snapshot_manifest_sha256=record["snapshot_manifest_sha256"],
                snapshot_content_root=record["snapshot_content_root"],
                root_tree=record["root_tree"],
                file_count=file_count,
                node_count=node_count,
                total_bytes=total_bytes,
                entry_count=record["entry_count"],
                regular_file_count=record["regular_file_count"],
                gitlink_count=record["gitlink_count"],
                regular_file_bytes=record["regular_file_bytes"],
                materialized_bytes=record["materialized_bytes"],
            )
        except (TypeError, ValueError) as error:
            raise SnapshotBatchError(
                "batch_manifest_invalid",
                "a batch task record violates the v3 counter or source identity contract",
                exit_status=4,
            ) from error
        tasks.append(parsed_task)
        task_lines.append(raw_line)
    content_root = _batch_content_root(task_lines)
    total_files = aggregate_files
    total_nodes = aggregate_nodes
    total_bytes = aggregate_bytes
    footer = records[-1]
    if (
        set(footer)
        != {
            "batch_content_root",
            "record_type",
            "task_count",
            "total_bytes",
            "total_files",
            "total_nodes",
            "total_entries",
            "total_regular_files",
            "total_gitlinks",
            "total_regular_file_bytes",
            "total_materialized_bytes",
        }
        or footer.get("record_type") != "footer"
        or footer.get("batch_content_root") != content_root
        or footer.get("task_count") != len(tasks)
        or footer.get("total_files") != total_files
        or footer.get("total_nodes") != total_nodes
        or footer.get("total_bytes") != total_bytes
        or footer.get("total_entries") != sum(task.entry_count for task in tasks)
        or footer.get("total_regular_files") != sum(task.regular_file_count for task in tasks)
        or footer.get("total_gitlinks") != sum(task.gitlink_count for task in tasks)
        or footer.get("total_regular_file_bytes") != sum(task.regular_file_bytes for task in tasks)
        or footer.get("total_materialized_bytes") != sum(task.materialized_bytes for task in tasks)
    ):
        raise SnapshotBatchError(
            "batch_manifest_invalid", "batch manifest footer is invalid", exit_status=4
        )
    return header, tuple(tasks), content_root, total_files, total_nodes, total_bytes


def verify_snapshot_batch(
    batch_root: str | os.PathLike[str],
    *,
    expected_manifest_sha256: str,
    attestation_key: bytes | bytearray | memoryview,
    expected_key_id: str,
    policy: SnapshotPolicy = DEFAULT_SNAPSHOT_POLICY,
) -> SnapshotBatchSummary:
    """Authenticate a batch and deeply verify every sealed task snapshot."""

    if not isinstance(policy, SnapshotPolicy):
        raise SnapshotBatchError(
            "invalid_policy", "snapshot policy is invalid", exit_status=2
        )
    expected_manifest_sha256 = _validate_sha256(
        expected_manifest_sha256, name="expected_manifest_sha256"
    )
    expected_key_id = _validate_key_id(expected_key_id)
    key = _copy_key(attestation_key)
    root = _canonical_existing_path(batch_root, directory=True, status=4)
    checked_parent = _checked_directory_chain(root.parent, status=4)
    _fixed_names(root, {"bundles", "control"}, status=4)
    _fixed_names(
        root / "control", {"attestation.json", "manifest.jsonl"}, status=4
    )
    root_identity = _directory_identity(_require_safe_directory(root, status=4))
    bundles = root / "bundles"
    control = root / "control"
    bundles_identity = _directory_identity(_require_safe_directory(bundles, status=4))
    control_identity = _directory_identity(_require_safe_directory(control, status=4))
    manifest = _read_stable_file(
        control / "manifest.jsonl", _MAX_BATCH_MANIFEST_BYTES, status=4
    )
    attestation_payload = _read_stable_file(
        control / "attestation.json", _MAX_BATCH_ATTESTATION_BYTES, status=4
    )
    manifest_sha256 = _sha256(manifest)
    if manifest_sha256 != expected_manifest_sha256:
        raise SnapshotBatchError(
            "batch_manifest_digest_mismatch",
            "batch manifest digest does not match the pinned digest",
            exit_status=4,
        )
    attestation = _parse_canonical_line(attestation_payload, status=4)
    if set(attestation) != {
        "algorithm",
        "contract_version",
        "key_id",
        "mac",
        "manifest_sha256",
    }:
        raise SnapshotBatchError(
            "batch_attestation_invalid", "batch attestation fields are invalid", exit_status=4
        )
    supplied_mac = attestation.get("mac")
    if (
        attestation.get("algorithm") != ATTESTATION_ALGORITHM
        or attestation.get("contract_version") != BATCH_CONTRACT_VERSION
        or attestation.get("key_id") != expected_key_id
        or attestation.get("manifest_sha256") != manifest_sha256
        or not isinstance(supplied_mac, str)
        or _SHA256_RE.fullmatch(supplied_mac) is None
        or not hmac.compare_digest(
            supplied_mac, _batch_mac(key, expected_key_id, manifest)
        )
    ):
        raise SnapshotBatchError(
            "batch_attestation_invalid", "batch attestation did not verify", exit_status=4
        )
    (
        header,
        tasks,
        content_root,
        total_files,
        total_nodes,
        total_bytes,
    ) = _parse_batch_manifest(manifest, policy=policy)
    expected_bundle_names = {task.task_id for task in tasks}
    _fixed_names(bundles, expected_bundle_names, status=4)
    first_verified: list[Any] = []
    for task in tasks:
        try:
            verified = verify_sealed_snapshot(
                bundles / task.task_id,
                expected_task_id=task.task_id,
                expected_repo_url=task.repo_url,
                expected_commit=task.commit,
                attestation_key=key,
                expected_key_id=expected_key_id,
                policy=policy,
            )
        except (SealedSnapshotError, ValueError) as error:
            raise SnapshotBatchError(
                "task_snapshot_verification_failed",
                "a task snapshot failed deep verification",
                exit_status=4,
            ) from error
        if (
            verified.manifest_sha256 != task.snapshot_manifest_sha256
            or verified.content_root != task.snapshot_content_root
            or verified.root_tree != task.root_tree
            or verified.file_count != task.file_count
            or _snapshot_node_count(verified.files) != task.node_count
            or verified.total_bytes != task.total_bytes
            or verified.entry_count != task.entry_count
            or verified.regular_file_count != task.regular_file_count
            or verified.gitlink_count != task.gitlink_count
            or verified.regular_file_bytes != task.regular_file_bytes
            or verified.materialized_bytes != task.materialized_bytes
        ):
            raise SnapshotBatchError(
                "task_snapshot_binding_mismatch",
                "a task snapshot differs from its batch record",
                exit_status=4,
            )
        first_verified.append(verified)
    baseline_materialized = _materialized_batch_digest(
        bundles, first_verified, policy=policy, status=4
    )
    second_verified: list[Any] = []
    for task in tasks:
        try:
            verified = verify_sealed_snapshot(
                bundles / task.task_id,
                expected_task_id=task.task_id,
                expected_repo_url=task.repo_url,
                expected_commit=task.commit,
                attestation_key=key,
                expected_key_id=expected_key_id,
                policy=policy,
            )
        except (SealedSnapshotError, ValueError) as error:
            raise SnapshotBatchError(
                "task_snapshot_verification_failed",
                "a task snapshot failed the final deep-verification pass",
                exit_status=4,
            ) from error
        if (
            verified.manifest_sha256 != task.snapshot_manifest_sha256
            or verified.content_root != task.snapshot_content_root
            or verified.root_tree != task.root_tree
            or verified.file_count != task.file_count
            or _snapshot_node_count(verified.files) != task.node_count
            or verified.total_bytes != task.total_bytes
            or verified.entry_count != task.entry_count
            or verified.regular_file_count != task.regular_file_count
            or verified.gitlink_count != task.gitlink_count
            or verified.regular_file_bytes != task.regular_file_bytes
            or verified.materialized_bytes != task.materialized_bytes
        ):
            raise SnapshotBatchError(
                "task_snapshot_binding_mismatch",
                "a task snapshot differs from its batch record",
                exit_status=4,
            )
        second_verified.append(verified)
    final_materialized = _materialized_batch_digest(
        bundles, second_verified, policy=policy, status=4
    )
    if final_materialized != baseline_materialized:
        raise SnapshotBatchError(
            "batch_changed",
            "batch materialized state changed across full verification passes",
            exit_status=4,
        )
    _fixed_names(root, {"bundles", "control"}, status=4)
    _fixed_names(
        control, {"attestation.json", "manifest.jsonl"}, status=4
    )
    _fixed_names(bundles, expected_bundle_names, status=4)
    final_manifest = _read_stable_file(
        control / "manifest.jsonl", _MAX_BATCH_MANIFEST_BYTES, status=4
    )
    final_attestation = _read_stable_file(
        control / "attestation.json", _MAX_BATCH_ATTESTATION_BYTES, status=4
    )
    if final_manifest != manifest or final_attestation != attestation_payload:
        raise SnapshotBatchError(
            "batch_changed", "batch control changed during verification", exit_status=4
        )
    _assert_directory_chain(checked_parent, status=4)
    if (
        _directory_identity(_require_safe_directory(root, status=4)) != root_identity
        or _directory_identity(_require_safe_directory(bundles, status=4))
        != bundles_identity
        or _directory_identity(_require_safe_directory(control, status=4))
        != control_identity
    ):
        raise SnapshotBatchError(
            "batch_changed", "batch identity changed during verification", exit_status=4
        )
    return SnapshotBatchSummary(
        batch_root=root,
        profile_id=header["profile_id"],
        split=header["split"],
        task_count=len(tasks),
        total_files=total_files,
        total_nodes=total_nodes,
        total_bytes=total_bytes,
        tasks_sha256=header["tasks_sha256"],
        public_manifest_sha256=header["public_manifest_sha256"],
        source_map_sha256=header["source_map_sha256"],
        manifest_sha256=manifest_sha256,
        batch_content_root=content_root,
        key_id=expected_key_id,
        tasks=tasks,
    )


def verify_snapshot_batch_with_evidence(
    batch_root: str | os.PathLike[str],
    *,
    expected_manifest_sha256: str,
    attestation_key: bytes | bytearray | memoryview,
    expected_key_id: str,
    policy: SnapshotPolicy = DEFAULT_SNAPSHOT_POLICY,
) -> SnapshotBatchVerificationEvidenceV2:
    """Run full verification and mint non-replayable path-free evidence."""

    if type(policy) is not SnapshotPolicy or policy != DEFAULT_SNAPSHOT_POLICY:
        raise SnapshotBatchError(
            "invalid_policy",
            "trusted verification evidence requires the fixed default policy",
            exit_status=2,
        )
    root = _canonical_existing_path(batch_root, directory=True, status=4)
    before_identity = _directory_identity(_require_safe_directory(root, status=4))
    key_buffer = _copy_key_buffer(attestation_key)
    run_nonce = bytearray(_SNAPSHOT_BATCH_RUN_NONCE_BYTES)
    try:
        run_nonce[:] = secrets.token_bytes(_SNAPSHOT_BATCH_RUN_NONCE_BYTES)
        summary = verify_snapshot_batch(
            root,
            expected_manifest_sha256=expected_manifest_sha256,
            attestation_key=key_buffer,
            expected_key_id=expected_key_id,
            policy=policy,
        )
        after_identity = _directory_identity(
            _require_safe_directory(root, status=4)
        )
        if summary.batch_root != root or after_identity != before_identity:
            raise SnapshotBatchError(
                "batch_changed",
                "batch root identity changed across evidence minting",
                exit_status=4,
            )
        evidence = SnapshotBatchVerificationEvidenceV2(
            summary=summary,
            _key_material=key_buffer,
            _output_identity=after_identity,
            _run_nonce=run_nonce,
            _mint=_SNAPSHOT_BATCH_EVIDENCE_MINT,
        )
        _register_snapshot_batch_verification_evidence(
            evidence,
            batch_root=root,
            output_identity=after_identity,
        )
        return evidence
    finally:
        _zero_buffer(run_nonce)
        _zero_buffer(key_buffer)


__all__ = [
    "BATCH_CONTRACT_VERSION",
    "SOURCE_MAP_KIND",
    "SOURCE_MAP_SCHEMA_VERSION",
    "SNAPSHOT_BATCH_EVIDENCE_CONTRACT_VERSION",
    "SNAPSHOT_BATCH_EVIDENCE_KIND",
    "SNAPSHOT_BATCH_EVIDENCE_RUN_ID_DOMAIN",
    "SNAPSHOT_BATCH_EVIDENCE_SEMANTIC_DOMAIN",
    "SNAPSHOT_BATCH_KEY_EQUALITY_TAG_DOMAIN",
    "SNAPSHOT_BATCH_OUTPUT_IDENTITY_DOMAIN",
    "SNAPSHOT_BATCH_TASK_RECORDS_DOMAIN",
    "SnapshotSourceMapDocument",
    "SnapshotBatchError",
    "SnapshotBatchSummary",
    "SnapshotBatchTask",
    "SnapshotBatchVerificationEvidenceV2",
    "VerifiedSnapshotSourceMap",
    "VerifiedTaskExport",
    "build_snapshot_source_map_document",
    "load_verified_snapshot_source_map",
    "load_verified_task_export",
    "prepare_snapshot_batch",
    "verify_snapshot_batch",
    "verify_snapshot_batch_with_evidence",
]
