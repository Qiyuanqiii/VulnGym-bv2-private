"""Non-secret handoff from the trusted snapshot verifier to one worker.

The evaluator authenticates a sealed snapshot before constructing this value.
The resulting canonical record contains only one answer-free discovery task,
the portable snapshot policy, the root-tree identifier, and the exact file
manifest.  It deliberately contains no host path, attestation key, key ID, or
``control/`` material.

Inside an isolated worker, :func:`bind_worker_tree` consumes the handoff and a
read-only mount of the corresponding ``tree/`` directory.  The handoff is not
a replacement signature: its trust comes from the evaluator-authenticated
construction step and an operating-system-enforced read-only mount.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Final, Mapping

from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.sealed_snapshot import (
    DEFAULT_SNAPSHOT_POLICY,
    SNAPSHOT_POLICY_VERSION,
    SealedSnapshotError,
    SealedSnapshotFile,
    SealedSnapshotGitlink,
    SnapshotPolicy,
    _manifest_bytes,
    _parse_manifest,
    verify_sealed_snapshot,
)


WORKER_HANDOFF_CONTRACT_VERSION: Final[int] = 2
WORKER_HANDOFF_KIND: Final[str] = "vulngym.source-discovery-worker-handoff.v2"
WORKER_HANDOFF_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym source discovery worker handoff v2\0"
)
WORKER_HANDOFF_MAX_BYTES: Final[int] = 72 * 1024 * 1024
WORKER_HANDOFF_MAX_FILES: Final[int] = 100_000

_SHA1_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_POLICY_KEYS: Final[frozenset[str]] = frozenset(
    {
        "max_component_bytes",
        "max_depth",
        "max_file_bytes",
        "max_files",
        "max_manifest_bytes",
        "max_path_bytes",
        "max_total_bytes",
        "max_tree_object_bytes",
        "git_symlink_representation",
        "gitlink_representation",
        "policy_version",
    }
)
_FILE_KEYS: Final[frozenset[str]] = frozenset(
    {"blob_oid", "git_mode", "path", "record_type", "sha256", "size"}
)
_ROOT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "contract_version",
        "files",
        "handoff_sha256",
        "kind",
        "policy",
        "root_tree",
        "task",
    }
)
_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "digest_mismatch",
        "invalid_argument",
        "invalid_binding",
        "invalid_contract",
        "limit_exceeded",
        "noncanonical_json",
        "snapshot_verification_failed",
    }
)


class WorkerHandoffError(ValueError):
    """Stable, path-free failure at the trusted-to-worker boundary."""

    def __init__(self, code: str, message: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES:
            code = "invalid_argument"
            message = "worker handoff error code is invalid"
        self.code = code
        super().__init__(message)


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeError):
        raise WorkerHandoffError(
            "invalid_contract", "worker handoff is not canonical JSON"
        ) from None


def _reject_constant(value: str) -> None:
    _ = value
    raise WorkerHandoffError(
        "noncanonical_json", "JSON constants outside the contract are forbidden"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise WorkerHandoffError(
                "noncanonical_json", "JSON objects must not repeat keys"
            )
        value[key] = item
    return value


def _strict_object(value: object, *, keys: frozenset[str], name: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise WorkerHandoffError(
            "invalid_contract", f"{name} has an invalid object shape"
        )
    return value


def _policy_from_dict(value: object) -> SnapshotPolicy:
    raw = _strict_object(value, keys=_POLICY_KEYS, name="policy")
    if raw["policy_version"] != SNAPSHOT_POLICY_VERSION:
        raise WorkerHandoffError(
            "invalid_contract", "worker handoff policy version is invalid"
        )
    try:
        policy = SnapshotPolicy(
            max_files=raw["max_files"],
            max_file_bytes=raw["max_file_bytes"],
            max_total_bytes=raw["max_total_bytes"],
            max_path_bytes=raw["max_path_bytes"],
            max_component_bytes=raw["max_component_bytes"],
            max_depth=raw["max_depth"],
            max_tree_object_bytes=raw["max_tree_object_bytes"],
            max_manifest_bytes=raw["max_manifest_bytes"],
            git_symlink_representation=raw["git_symlink_representation"],
            gitlink_representation=raw["gitlink_representation"],
        )
    except (TypeError, ValueError):
        raise WorkerHandoffError(
            "invalid_contract", "worker handoff policy is invalid"
        ) from None
    if policy.to_dict() != raw:
        raise WorkerHandoffError(
            "invalid_contract", "worker handoff policy is not canonical"
        )
    return policy


def _file_from_dict(value: object) -> SealedSnapshotFile:
    raw = _strict_object(value, keys=_FILE_KEYS, name="file")
    if raw["record_type"] != "file":
        raise WorkerHandoffError(
            "invalid_contract", "worker handoff file record is invalid"
        )
    return SealedSnapshotFile(
        path=raw["path"],
        git_mode=raw["git_mode"],
        blob_oid=raw["blob_oid"],
        size=raw["size"],
        sha256=raw["sha256"],
    )


def _canonical_task(value: object) -> DiscoveryTaskInputV1:
    if type(value) is not DiscoveryTaskInputV1:
        raise WorkerHandoffError(
            "invalid_argument", "worker handoff task must be an exact task"
        )
    try:
        fields = (
            value.task_id,
            value.repo_url,
            value.commit,
            value.instruction_id,
            value.snapshot_manifest_sha256,
            value.snapshot_content_root,
            value.snapshot_id,
            value.contract_version,
        )
    except (AttributeError, TypeError):
        raise WorkerHandoffError(
            "invalid_contract", "worker handoff task fields are incomplete"
        ) from None
    if any(
        type(item) is not expected
        for item, expected in zip(
            fields, (str, str, str, str, str, str, str, int), strict=True
        )
    ):
        raise WorkerHandoffError(
            "invalid_argument", "worker handoff task fields must have exact types"
        )
    try:
        task = DiscoveryTaskInputV1(
            task_id=fields[0],
            repo_url=fields[1],
            commit=fields[2],
            instruction_id=fields[3],
            snapshot_manifest_sha256=fields[4],
            snapshot_content_root=fields[5],
            contract_version=fields[7],
        )
    except (AttributeError, TypeError, ValueError):
        raise WorkerHandoffError(
            "invalid_contract", "worker handoff task is invalid"
        ) from None
    if task.snapshot_id != fields[6]:
        raise WorkerHandoffError(
            "invalid_binding", "worker handoff task identity is invalid"
        )
    return task


def _canonical_policy(value: object) -> SnapshotPolicy:
    if type(value) is not SnapshotPolicy:
        raise WorkerHandoffError(
            "invalid_argument", "worker handoff policy must be exact"
        )
    try:
        fields = (
            value.max_files,
            value.max_file_bytes,
            value.max_total_bytes,
            value.max_path_bytes,
            value.max_component_bytes,
            value.max_depth,
            value.max_tree_object_bytes,
            value.max_manifest_bytes,
            value.git_symlink_representation,
            value.gitlink_representation,
        )
    except (AttributeError, TypeError):
        raise WorkerHandoffError(
            "invalid_contract", "worker handoff policy fields are incomplete"
        ) from None
    if (
        any(type(item) is not int for item in fields[:-2])
        or any(type(item) is not str for item in fields[-2:])
    ):
        raise WorkerHandoffError(
            "invalid_argument", "worker handoff policy fields have invalid exact types"
        )
    try:
        policy = SnapshotPolicy(
            max_files=fields[0],
            max_file_bytes=fields[1],
            max_total_bytes=fields[2],
            max_path_bytes=fields[3],
            max_component_bytes=fields[4],
            max_depth=fields[5],
            max_tree_object_bytes=fields[6],
            max_manifest_bytes=fields[7],
            git_symlink_representation=fields[8],
            gitlink_representation=fields[9],
        )
    except (AttributeError, TypeError, ValueError):
        raise WorkerHandoffError(
            "invalid_contract", "worker handoff policy is invalid"
        ) from None
    ceiling = DEFAULT_SNAPSHOT_POLICY
    if any(
        current > maximum
        for current, maximum in zip(
            fields[:-2],
            (
                ceiling.max_files,
                ceiling.max_file_bytes,
                ceiling.max_total_bytes,
                ceiling.max_path_bytes,
                ceiling.max_component_bytes,
                ceiling.max_depth,
                ceiling.max_tree_object_bytes,
                ceiling.max_manifest_bytes,
            ),
            strict=True,
        )
    ):
        raise WorkerHandoffError(
            "limit_exceeded", "worker handoff policy exceeds the fixed E ceiling"
        )
    return policy


def _task_dict(task: DiscoveryTaskInputV1) -> dict[str, object]:
    canonical = _canonical_task(task)
    return {
        "commit": canonical.commit,
        "contract_version": canonical.contract_version,
        "instruction_id": canonical.instruction_id,
        "repo_url": canonical.repo_url,
        "snapshot_content_root": canonical.snapshot_content_root,
        "snapshot_id": canonical.snapshot_id,
        "snapshot_manifest_sha256": canonical.snapshot_manifest_sha256,
        "task_id": canonical.task_id,
    }


def _policy_dict(policy: SnapshotPolicy) -> dict[str, object]:
    canonical = _canonical_policy(policy)
    return canonical.to_dict()


def _file_dict(value: SealedSnapshotFile) -> dict[str, object]:
    if type(value) is not SealedSnapshotFile:
        raise WorkerHandoffError(
            "invalid_argument", "worker handoff file must have an exact type"
        )
    try:
        fields = (value.path, value.git_mode, value.blob_oid, value.size, value.sha256)
    except (AttributeError, TypeError):
        raise WorkerHandoffError(
            "invalid_contract", "worker handoff file fields are incomplete"
        ) from None
    if any(
        type(item) is not expected
        for item, expected in zip(fields, (str, str, str, int, str), strict=True)
    ):
        raise WorkerHandoffError(
            "invalid_contract", "worker handoff file fields have invalid types"
        )
    return {
        "blob_oid": fields[2],
        "git_mode": fields[1],
        "path": fields[0],
        "record_type": "file",
        "sha256": fields[4],
        "size": fields[3],
    }


@dataclass(frozen=True, slots=True)
class WorkerHandoffV2:
    """Canonical, non-secret description of one preverified source mount."""

    task: DiscoveryTaskInputV1
    policy: SnapshotPolicy
    root_tree: str
    files: tuple[SealedSnapshotFile, ...]
    contract_version: int = WORKER_HANDOFF_CONTRACT_VERSION
    kind: str = WORKER_HANDOFF_KIND
    handoff_sha256: str = field(init=False)
    wire_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != WORKER_HANDOFF_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != WORKER_HANDOFF_KIND
        ):
            raise WorkerHandoffError(
                "invalid_contract", "worker handoff version is invalid"
            )
        canonical_task = _canonical_task(self.task)
        canonical_policy = _canonical_policy(self.policy)
        object.__setattr__(self, "task", canonical_task)
        object.__setattr__(self, "policy", canonical_policy)
        if type(self.root_tree) is not str or _SHA1_RE.fullmatch(self.root_tree) is None:
            raise WorkerHandoffError(
                "invalid_contract", "worker handoff root tree is invalid"
            )
        if type(self.files) is not tuple:
            raise WorkerHandoffError(
                "invalid_argument", "worker handoff files must be an exact tuple"
            )
        if not self.files or len(self.files) > min(
            self.policy.max_files, WORKER_HANDOFF_MAX_FILES
        ):
            raise WorkerHandoffError(
                "limit_exceeded", "worker handoff file count is invalid"
            )
        if any(type(item) is not SealedSnapshotFile for item in self.files):
            raise WorkerHandoffError(
                "invalid_argument", "worker handoff files have invalid types"
            )
        file_dicts = tuple(_file_dict(item) for item in self.files)
        # Detach every manifest member from the caller-owned object graph before
        # any helper observes it.  Frozen dataclasses can still be modified via
        # ``object.__setattr__`` by a concurrent caller, so validation alone is
        # not a sufficient ownership boundary.
        canonical_files = tuple(_file_from_dict(item) for item in file_dicts)
        object.__setattr__(self, "files", canonical_files)
        total_bytes = sum(item["size"] for item in file_dicts)
        if not 0 <= total_bytes <= self.policy.max_total_bytes:
            raise WorkerHandoffError(
                "limit_exceeded", "worker handoff byte count is invalid"
            )
        try:
            manifest, content_root = _manifest_bytes(
                task_id=self.task.task_id,
                repo_url=self.task.repo_url,
                commit=self.task.commit,
                root_tree=self.root_tree,
                files=canonical_files,
                total_bytes=total_bytes,
                policy=self.policy,
            )
            (
                parsed_root,
                parsed_files,
                parsed_total,
                parsed_content_root,
            ) = _parse_manifest(
                manifest,
                expected_task_id=self.task.task_id,
                expected_repo_url=self.task.repo_url,
                expected_commit=self.task.commit,
                policy=self.policy,
            )
        except (AttributeError, SealedSnapshotError, TypeError, ValueError):
            raise WorkerHandoffError(
                "invalid_contract", "worker handoff manifest records are invalid"
            ) from None
        if (
            parsed_root != self.root_tree
            or parsed_files != canonical_files
            or parsed_total != total_bytes
            or parsed_content_root != content_root
            or content_root != self.task.snapshot_content_root
            or hashlib.sha256(manifest).hexdigest()
            != self.task.snapshot_manifest_sha256
        ):
            raise WorkerHandoffError(
                "invalid_binding", "worker handoff does not match the discovery task"
            )
        object.__setattr__(self, "files", parsed_files)
        digest = hashlib.sha256(
            WORKER_HANDOFF_DIGEST_DOMAIN + _canonical_json(self._core_dict())
        ).hexdigest()
        object.__setattr__(self, "handoff_sha256", digest)
        payload = self._wire_bytes()
        if len(payload) > WORKER_HANDOFF_MAX_BYTES:
            raise WorkerHandoffError(
                "limit_exceeded", "worker handoff exceeds its byte limit"
            )
        object.__setattr__(self, "wire_sha256", hashlib.sha256(payload).hexdigest())

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(item.size for item in self.files)

    def _core_dict(self) -> dict[str, object]:
        try:
            contract_version = self.contract_version
            kind = self.kind
            root_tree = self.root_tree
            files = self.files
            policy = self.policy
            task = self.task
        except (AttributeError, TypeError):
            raise WorkerHandoffError(
                "invalid_contract", "worker handoff root fields are incomplete"
            ) from None
        if (
            type(contract_version) is not int
            or contract_version != WORKER_HANDOFF_CONTRACT_VERSION
            or type(kind) is not str
            or kind != WORKER_HANDOFF_KIND
            or type(root_tree) is not str
            or _SHA1_RE.fullmatch(root_tree) is None
        ):
            raise WorkerHandoffError(
                "invalid_contract", "worker handoff root fields are invalid"
            )
        return {
            "contract_version": contract_version,
            "files": [_file_dict(item) for item in files],
            "kind": kind,
            "policy": _policy_dict(policy),
            "root_tree": root_tree,
            "task": _task_dict(task),
        }

    def to_dict(self) -> dict[str, object]:
        core = self._core_dict()
        try:
            supplied = self.handoff_sha256
        except (AttributeError, TypeError):
            raise WorkerHandoffError(
                "invalid_binding", "worker handoff digest is unavailable"
            ) from None
        expected = hashlib.sha256(
            WORKER_HANDOFF_DIGEST_DOMAIN + _canonical_json(core)
        ).hexdigest()
        if type(supplied) is not str or supplied != expected:
            raise WorkerHandoffError(
                "invalid_binding", "worker handoff digest no longer matches"
            )
        return {**core, "handoff_sha256": supplied}

    def _wire_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"

    def to_bytes(self) -> bytes:
        payload = self._wire_bytes()
        try:
            supplied = self.wire_sha256
        except (AttributeError, TypeError):
            raise WorkerHandoffError(
                "invalid_binding", "worker handoff wire digest is unavailable"
            ) from None
        if type(supplied) is not str or hashlib.sha256(payload).hexdigest() != supplied:
            raise WorkerHandoffError(
                "invalid_binding", "worker handoff wire digest no longer matches"
            )
        return payload

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_sha256: str,
        expected_wire_sha256: str,
    ) -> "WorkerHandoffV2":
        if type(payload) is not bytes:
            raise WorkerHandoffError(
                "invalid_argument", "worker handoff payload must be exact bytes"
            )
        if (
            type(expected_sha256) is not str
            or _SHA256_RE.fullmatch(expected_sha256) is None
            or type(expected_wire_sha256) is not str
            or _SHA256_RE.fullmatch(expected_wire_sha256) is None
        ):
            raise WorkerHandoffError(
                "invalid_argument", "expected worker handoff digest is invalid"
            )
        if not payload or len(payload) > WORKER_HANDOFF_MAX_BYTES:
            raise WorkerHandoffError(
                "limit_exceeded", "worker handoff payload exceeds its byte limit"
            )
        if hashlib.sha256(payload).hexdigest() != expected_wire_sha256:
            raise WorkerHandoffError(
                "digest_mismatch", "worker handoff wire does not match its pin"
            )
        if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
            raise WorkerHandoffError(
                "noncanonical_json", "worker handoff must be one canonical JSON line"
            )
        try:
            decoded = payload[:-1].decode("utf-8", errors="strict")
            value = json.loads(
                decoded,
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except WorkerHandoffError:
            raise
        except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
            raise WorkerHandoffError(
                "noncanonical_json", "worker handoff is not strict JSON"
            ) from None
        raw = _strict_object(value, keys=_ROOT_KEYS, name="worker handoff")
        supplied_digest = raw["handoff_sha256"]
        if (
            type(supplied_digest) is not str
            or _SHA256_RE.fullmatch(supplied_digest) is None
            or supplied_digest != expected_sha256
        ):
            raise WorkerHandoffError(
                "digest_mismatch", "worker handoff digest does not match its pin"
            )
        try:
            task = DiscoveryTaskInputV1.from_dict(raw["task"])
        except (AttributeError, TypeError, ValueError):
            raise WorkerHandoffError(
                "invalid_contract", "worker handoff task is invalid"
            ) from None
        policy = _policy_from_dict(raw["policy"])
        raw_files = raw["files"]
        if type(raw_files) is not list or not raw_files or len(raw_files) > min(
            policy.max_files, WORKER_HANDOFF_MAX_FILES
        ):
            raise WorkerHandoffError(
                "limit_exceeded", "worker handoff file array is invalid"
            )
        files = tuple(_file_from_dict(item) for item in raw_files)
        result = cls(
            task=task,
            policy=policy,
            root_tree=raw["root_tree"],
            files=files,
            contract_version=raw["contract_version"],
            kind=raw["kind"],
        )
        if result.handoff_sha256 != supplied_digest:
            raise WorkerHandoffError(
                "digest_mismatch", "worker handoff content digest is invalid"
            )
        if result.wire_sha256 != expected_wire_sha256:
            raise WorkerHandoffError(
                "digest_mismatch", "worker handoff transport digest is invalid"
            )
        if result.to_bytes() != payload:
            raise WorkerHandoffError(
                "noncanonical_json", "worker handoff JSON is not canonical"
            )
        return result


def build_worker_handoff(
    task: DiscoveryTaskInputV1,
    snapshot_root: str | os.PathLike[str],
    *,
    attestation_key: bytes | bytearray | memoryview,
    expected_key_id: str,
    policy: SnapshotPolicy = DEFAULT_SNAPSHOT_POLICY,
) -> WorkerHandoffV2:
    """Authenticate one sealed snapshot and derive a non-secret worker record."""

    canonical_task = _canonical_task(task)
    canonical_policy = _canonical_policy(policy)
    try:
        root = Path(os.path.abspath(os.fspath(snapshot_root)))
        verified = verify_sealed_snapshot(
            root,
            expected_task_id=canonical_task.task_id,
            expected_repo_url=canonical_task.repo_url,
            expected_commit=canonical_task.commit,
            attestation_key=attestation_key,
            expected_key_id=expected_key_id,
            policy=canonical_policy,
        )
    except (AttributeError, OSError, SealedSnapshotError, TypeError, ValueError):
        raise WorkerHandoffError(
            "snapshot_verification_failed", "sealed snapshot did not verify"
        ) from None
    if (
        verified.task_id != canonical_task.task_id
        or verified.repo_url != canonical_task.repo_url
        or verified.commit != canonical_task.commit
        or verified.manifest_sha256 != canonical_task.snapshot_manifest_sha256
        or verified.content_root != canonical_task.snapshot_content_root
    ):
        raise WorkerHandoffError(
            "invalid_binding", "sealed snapshot does not match the worker task"
        )
    if any(type(item) is SealedSnapshotGitlink for item in verified.files):
        raise WorkerHandoffError(
            "snapshot_verification_failed",
            "metadata-only gitlinks are sealed but not worker-readable",
        )
    result = WorkerHandoffV2(
        task=canonical_task,
        policy=canonical_policy,
        root_tree=verified.root_tree,
        files=verified.files,
    )
    return result


__all__ = [
    "WORKER_HANDOFF_CONTRACT_VERSION",
    "WORKER_HANDOFF_DIGEST_DOMAIN",
    "WORKER_HANDOFF_KIND",
    "WORKER_HANDOFF_MAX_BYTES",
    "WORKER_HANDOFF_MAX_FILES",
    "WorkerHandoffError",
    "WorkerHandoffV2",
    "build_worker_handoff",
]
