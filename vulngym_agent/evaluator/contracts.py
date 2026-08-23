"""Canonical execution-plan and receipt contracts for evaluator stage E.

The values in this module are path-free and secret-free.  They bind a freshly
verified snapshot batch, a fixed Linux OCI execution policy, per-task worker
handoffs, closed discovery runs, and the published result index.  Authenticity
still comes from the trusted supervisor performing the pre/post verification;
the domain-separated digests make substitutions and incomplete closure
detectable after that trusted construction step.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Final

from vulngym_agent.benchmark.discovery_contracts import DiscoveryTaskInputV1
from vulngym_agent.benchmark.harness import (
    ARTIFACT_INDEX_CONTRACT_VERSION,
    ArtifactBundleDigest,
    ArtifactBundleIndex,
    artifact_bundle_index_payload_v1,
)
from vulngym_agent.benchmark.sealed_snapshot import SnapshotPolicy
from vulngym_agent.benchmark.snapshot_batch import (
    BATCH_CONTRACT_VERSION,
    PROFILE_ID,
    PROFILE_SCHEMA_VERSION,
    SnapshotBatchSummary,
    SnapshotBatchTask,
)
from vulngym_agent.benchmark.worker_handoff import WorkerHandoffV1
from vulngym_agent.evaluator.runtime_evidence import (
    RuntimeEvidenceError,
    RuntimeEvidenceV1,
)


EVALUATOR_CONTRACT_VERSION: Final[int] = 1
SNAPSHOT_BATCH_BINDING_KIND: Final[str] = (
    "vulngym.snapshot-batch-binding.v1"
)
EXECUTION_POLICY_BINDING_KIND: Final[str] = (
    "vulngym.discovery-execution-policy.v1"
)
DISCOVERY_TASK_EXECUTION_PLAN_KIND: Final[str] = (
    "vulngym.discovery-task-execution-plan.v1"
)
DISCOVERY_BATCH_EXECUTION_PLAN_KIND: Final[str] = (
    "vulngym.discovery-batch-execution-plan.v1"
)
DISCOVERY_TASK_EXECUTION_RECEIPT_KIND: Final[str] = (
    "vulngym.discovery-task-execution-receipt.v1"
)
DISCOVERY_BATCH_EXECUTION_RECEIPT_KIND: Final[str] = (
    "vulngym.discovery-batch-execution-receipt.v1"
)

SNAPSHOT_BATCH_BINDING_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator snapshot batch binding v1\0"
)
EXECUTION_POLICY_BINDING_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator execution policy binding v1\0"
)
SNAPSHOT_POLICY_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator snapshot policy v1\0"
)
DISCOVERY_TASK_EXECUTION_PLAN_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator discovery task plan v1\0"
)
DISCOVERY_BATCH_EXECUTION_PLAN_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator discovery batch plan v1\0"
)
DISCOVERY_TASK_EXECUTION_RECEIPT_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator discovery task receipt v1\0"
)
DISCOVERY_BATCH_EXECUTION_RECEIPT_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym evaluator discovery batch receipt v1\0"
)

EVALUATOR_CONTRACT_MAX_WIRE_BYTES: Final[int] = 4 * 1024 * 1024
EVALUATOR_CONTRACT_MAX_JSON_NODES: Final[int] = 200_000
EVALUATOR_CONTRACT_MAX_JSON_DEPTH: Final[int] = 16

_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID_RE: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEY_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z"
)
_COMPONENT_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}\Z"
)
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"VG-(?:TRAIN|TEST)-[0-9A-F]{20}\Z"
)
_SNAPSHOT_ID_RE: Final[re.Pattern[str]] = re.compile(r"VGS-[0-9A-F]{32}\Z")
_SPLIT_COUNTS: Final[dict[str, int]] = {"train": 50, "test": 20}

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
        "policy_version",
    }
)
_BATCH_TASK_KEYS: Final[frozenset[str]] = frozenset(
    {
        "bundle_path",
        "commit",
        "file_count",
        "instruction_id",
        "node_count",
        "record_type",
        "repo_url",
        "snapshot_content_root",
        "snapshot_manifest_sha256",
        "split",
        "task_id",
        "total_bytes",
    }
)
_EXECUTION_POLICY_CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "capabilities_mode",
        "contract_version",
        "cpu_millis",
        "d2_backend_id",
        "d2_budget_sha256",
        "d2_model_id",
        "d3_backend_id",
        "d3_budget_sha256",
        "d3_model_id",
        "kind",
        "memory_bytes",
        "network_mode",
        "no_new_privileges",
        "open_files_limit",
        "pids_limit",
        "provider",
        "rootfs_mode",
        "runtime_image_id",
        "snapshot_policy_sha256",
        "source_mount_mode",
        "stderr_max_bytes",
        "stdout_max_bytes",
        "tmpfs_bytes",
        "tree_limits_sha256",
        "wall_time_seconds",
        "worker_version",
    }
)


class EvaluatorContractError(ValueError):
    """Stable, path-free failure for E-stage canonical contracts."""

    def __init__(self, code: str, message: str) -> None:
        if type(code) is not str or not code:
            code = "invalid_contract"
            message = "evaluator contract is invalid"
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
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise EvaluatorContractError(
            "invalid_contract", "evaluator contract is not canonical JSON"
        ) from None


def _reject_constant(value: str) -> None:
    _ = value
    raise EvaluatorContractError(
        "noncanonical_json", "JSON constants outside the contract are forbidden"
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvaluatorContractError(
                "noncanonical_json", "JSON objects must not repeat keys"
            )
        result[key] = value
    return result


def _validate_json_shape(value: object, *, depth: int = 0, count: list[int]) -> None:
    count[0] += 1
    if (
        count[0] > EVALUATOR_CONTRACT_MAX_JSON_NODES
        or depth > EVALUATOR_CONTRACT_MAX_JSON_DEPTH
    ):
        raise EvaluatorContractError(
            "limit_exceeded", "evaluator contract JSON exceeds its shape limit"
        )
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise EvaluatorContractError(
                    "invalid_contract", "evaluator contract keys must be strings"
                )
            _validate_json_shape(child, depth=depth + 1, count=count)
    elif type(value) is list:
        for child in value:
            _validate_json_shape(child, depth=depth + 1, count=count)
    elif value is not None and type(value) not in {str, int, bool}:
        raise EvaluatorContractError(
            "invalid_contract", "evaluator contract has an invalid JSON value"
        )


def _strict_object(
    value: object, *, keys: frozenset[str], name: str
) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != keys:
        raise EvaluatorContractError(
            "invalid_contract", f"{name} has an invalid object shape"
        )
    return value


def _parse_pinned_line(
    payload: bytes,
    *,
    expected_wire_sha256: str,
) -> dict[str, Any]:
    if type(payload) is not bytes:
        raise EvaluatorContractError(
            "invalid_argument", "evaluator contract payload must be exact bytes"
        )
    if (
        type(expected_wire_sha256) is not str
        or _SHA256_RE.fullmatch(expected_wire_sha256) is None
    ):
        raise EvaluatorContractError(
            "invalid_argument", "expected evaluator wire digest is invalid"
        )
    if not payload or len(payload) > EVALUATOR_CONTRACT_MAX_WIRE_BYTES:
        raise EvaluatorContractError(
            "limit_exceeded", "evaluator contract payload exceeds its byte limit"
        )
    if hashlib.sha256(payload).hexdigest() != expected_wire_sha256:
        raise EvaluatorContractError(
            "digest_mismatch", "evaluator contract wire does not match its pin"
        )
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise EvaluatorContractError(
            "noncanonical_json", "evaluator contract must be one JSON line"
        )
    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except EvaluatorContractError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EvaluatorContractError(
            "noncanonical_json", "evaluator contract is not strict JSON"
        ) from None
    _validate_json_shape(value, count=[0])
    if type(value) is not dict:
        raise EvaluatorContractError(
            "invalid_contract", "evaluator contract root must be an object"
        )
    return value


def _embedded_sha256_from_canonical_wire(payload: bytes, *, field: str) -> str:
    """Read a self-pin from bytes already emitted by an exact contract value."""

    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except EvaluatorContractError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise EvaluatorContractError(
            "noncanonical_json", "contract self-serialization is not strict JSON"
        ) from None
    if type(value) is not dict or field not in value:
        raise EvaluatorContractError(
            "invalid_contract", "contract self-serialization has no digest pin"
        )
    pin = value[field]
    _require_sha256(pin, name=field)
    return pin


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise EvaluatorContractError(
            "invalid_contract", f"{name} must be a lower-case SHA-256 digest"
        )
    return value


def _canonical_policy(value: object) -> SnapshotPolicy:
    if type(value) is not SnapshotPolicy:
        raise EvaluatorContractError(
            "invalid_argument", "snapshot policy must have an exact type"
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
        )
    except (AttributeError, TypeError):
        raise EvaluatorContractError(
            "invalid_contract", "snapshot policy fields are incomplete"
        ) from None
    if any(type(item) is not int for item in fields):
        raise EvaluatorContractError(
            "invalid_contract", "snapshot policy fields must be exact integers"
        )
    try:
        return SnapshotPolicy(
            max_files=fields[0],
            max_file_bytes=fields[1],
            max_total_bytes=fields[2],
            max_path_bytes=fields[3],
            max_component_bytes=fields[4],
            max_depth=fields[5],
            max_tree_object_bytes=fields[6],
            max_manifest_bytes=fields[7],
        )
    except (AttributeError, TypeError, ValueError):
        raise EvaluatorContractError(
            "invalid_contract", "snapshot policy is invalid"
        ) from None


def snapshot_policy_sha256_v1(value: SnapshotPolicy) -> str:
    """Return the domain-separated digest of one exact snapshot policy."""

    policy = _canonical_policy(value)
    return hashlib.sha256(
        SNAPSHOT_POLICY_DIGEST_DOMAIN + _canonical_json(policy.to_dict())
    ).hexdigest()


def _policy_from_dict(value: object) -> SnapshotPolicy:
    raw = _strict_object(value, keys=_POLICY_KEYS, name="snapshot policy")
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
        )
    except (AttributeError, TypeError, ValueError):
        raise EvaluatorContractError(
            "invalid_contract", "snapshot policy is invalid"
        ) from None
    if policy.to_dict() != raw:
        raise EvaluatorContractError(
            "noncanonical_json", "snapshot policy is not canonical"
        )
    return policy


def _canonical_batch_task(value: object) -> SnapshotBatchTask:
    if type(value) is not SnapshotBatchTask:
        raise EvaluatorContractError(
            "invalid_argument", "batch task must have an exact type"
        )
    try:
        fields = (
            value.task_id,
            value.repo_url,
            value.commit,
            value.split,
            value.instruction_id,
            value.snapshot_manifest_sha256,
            value.snapshot_content_root,
            value.file_count,
            value.node_count,
            value.total_bytes,
            value.bundle_path,
        )
    except (AttributeError, TypeError):
        raise EvaluatorContractError(
            "invalid_contract", "batch task fields are incomplete"
        ) from None
    if any(type(item) is not str for item in fields[:7]) or any(
        type(item) is not int for item in fields[7:10]
    ) or type(fields[10]) is not str:
        raise EvaluatorContractError(
            "invalid_contract", "batch task fields have invalid exact types"
        )
    try:
        result = SnapshotBatchTask(
            task_id=fields[0],
            repo_url=fields[1],
            commit=fields[2],
            split=fields[3],
            instruction_id=fields[4],
            snapshot_manifest_sha256=fields[5],
            snapshot_content_root=fields[6],
            file_count=fields[7],
            node_count=fields[8],
            total_bytes=fields[9],
        )
    except (AttributeError, TypeError, ValueError):
        raise EvaluatorContractError(
            "invalid_contract", "batch task is invalid"
        ) from None
    if result.bundle_path != fields[10]:
        raise EvaluatorContractError(
            "invalid_binding", "batch task bundle identity is invalid"
        )
    return result


def _batch_task_from_record(value: object) -> SnapshotBatchTask:
    raw = _strict_object(value, keys=_BATCH_TASK_KEYS, name="batch task")
    if raw["record_type"] != "task":
        raise EvaluatorContractError(
            "invalid_contract", "batch task record type is invalid"
        )
    try:
        result = SnapshotBatchTask(
            task_id=raw["task_id"],
            repo_url=raw["repo_url"],
            commit=raw["commit"],
            split=raw["split"],
            instruction_id=raw["instruction_id"],
            snapshot_manifest_sha256=raw["snapshot_manifest_sha256"],
            snapshot_content_root=raw["snapshot_content_root"],
            file_count=raw["file_count"],
            node_count=raw["node_count"],
            total_bytes=raw["total_bytes"],
        )
    except (AttributeError, TypeError, ValueError):
        raise EvaluatorContractError(
            "invalid_contract", "batch task record is invalid"
        ) from None
    if result.to_record() != raw:
        raise EvaluatorContractError(
            "noncanonical_json", "batch task record is not canonical"
        )
    return result


@dataclass(frozen=True, slots=True)
class SnapshotBatchBindingV1:
    """Path-free closure of one fresh, complete batch verification."""

    profile_id: str
    profile_schema_version: str
    split: str
    task_count: int
    total_files: int
    total_nodes: int
    total_bytes: int
    tasks_sha256: str
    public_manifest_sha256: str
    source_map_sha256: str
    batch_manifest_sha256: str
    batch_content_root: str
    attestation_key_id: str
    snapshot_policy: SnapshotPolicy
    tasks: tuple[SnapshotBatchTask, ...]
    batch_contract_version: str = BATCH_CONTRACT_VERSION
    contract_version: int = EVALUATOR_CONTRACT_VERSION
    kind: str = SNAPSHOT_BATCH_BINDING_KIND
    binding_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != EVALUATOR_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != SNAPSHOT_BATCH_BINDING_KIND
            or type(self.batch_contract_version) is not str
            or self.batch_contract_version != BATCH_CONTRACT_VERSION
            or type(self.profile_id) is not str
            or self.profile_id != PROFILE_ID
            or type(self.profile_schema_version) is not str
            or self.profile_schema_version != PROFILE_SCHEMA_VERSION
            or type(self.split) is not str
            or self.split not in _SPLIT_COUNTS
        ):
            raise EvaluatorContractError(
                "invalid_contract", "snapshot batch binding header is invalid"
            )
        counters = (
            self.task_count,
            self.total_files,
            self.total_nodes,
            self.total_bytes,
        )
        if any(type(item) is not int or item < 0 for item in counters):
            raise EvaluatorContractError(
                "invalid_contract", "snapshot batch counters are invalid"
            )
        for value, name in (
            (self.tasks_sha256, "tasks_sha256"),
            (self.public_manifest_sha256, "public_manifest_sha256"),
            (self.source_map_sha256, "source_map_sha256"),
            (self.batch_manifest_sha256, "batch_manifest_sha256"),
            (self.batch_content_root, "batch_content_root"),
        ):
            _require_sha256(value, name=name)
        if (
            type(self.attestation_key_id) is not str
            or _KEY_ID_RE.fullmatch(self.attestation_key_id) is None
        ):
            raise EvaluatorContractError(
                "invalid_contract", "snapshot batch key identifier is invalid"
            )
        policy = _canonical_policy(self.snapshot_policy)
        if type(self.tasks) is not tuple:
            raise EvaluatorContractError(
                "invalid_argument", "snapshot batch tasks must be an exact tuple"
            )
        tasks = tuple(_canonical_batch_task(task) for task in self.tasks)
        if (
            self.task_count != _SPLIT_COUNTS[self.split]
            or self.task_count != len(tasks)
            or any(task.split != self.split for task in tasks)
            or len({task.task_id for task in tasks}) != len(tasks)
            or self.total_files != sum(task.file_count for task in tasks)
            or self.total_nodes != sum(task.node_count for task in tasks)
            or self.total_bytes != sum(task.total_bytes for task in tasks)
        ):
            raise EvaluatorContractError(
                "invalid_binding", "snapshot batch members or counters do not close"
            )
        object.__setattr__(self, "snapshot_policy", policy)
        object.__setattr__(self, "tasks", tasks)
        object.__setattr__(
            self,
            "binding_sha256",
            hashlib.sha256(
                SNAPSHOT_BATCH_BINDING_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )
        if len(self.to_bytes()) > EVALUATOR_CONTRACT_MAX_WIRE_BYTES:
            raise EvaluatorContractError(
                "limit_exceeded", "snapshot batch binding exceeds its wire limit"
            )

    def _core_dict(self) -> dict[str, object]:
        policy = _canonical_policy(self.snapshot_policy)
        tasks = tuple(_canonical_batch_task(task) for task in self.tasks)
        return {
            "attestation_key_id": self.attestation_key_id,
            "batch_content_root": self.batch_content_root,
            "batch_contract_version": self.batch_contract_version,
            "batch_manifest_sha256": self.batch_manifest_sha256,
            "contract_version": self.contract_version,
            "kind": self.kind,
            "profile_id": self.profile_id,
            "profile_schema_version": self.profile_schema_version,
            "public_manifest_sha256": self.public_manifest_sha256,
            "snapshot_policy": policy.to_dict(),
            "source_map_sha256": self.source_map_sha256,
            "split": self.split,
            "task_count": self.task_count,
            "tasks": [task.to_record() for task in tasks],
            "tasks_sha256": self.tasks_sha256,
            "total_bytes": self.total_bytes,
            "total_files": self.total_files,
            "total_nodes": self.total_nodes,
        }

    def to_dict(self) -> dict[str, object]:
        core = self._core_dict()
        expected = hashlib.sha256(
            SNAPSHOT_BATCH_BINDING_DIGEST_DOMAIN + _canonical_json(core)
        ).hexdigest()
        if type(self.binding_sha256) is not str or self.binding_sha256 != expected:
            raise EvaluatorContractError(
                "invalid_binding", "snapshot batch binding digest no longer matches"
            )
        return {**core, "binding_sha256": self.binding_sha256}

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_verified_summary(
        cls,
        summary: SnapshotBatchSummary,
        *,
        snapshot_policy: SnapshotPolicy,
    ) -> "SnapshotBatchBindingV1":
        if type(summary) is not SnapshotBatchSummary:
            raise EvaluatorContractError(
                "invalid_argument", "verified batch summary must have an exact type"
            )
        try:
            fields = (
                summary.profile_id,
                summary.split,
                summary.task_count,
                summary.total_files,
                summary.total_nodes,
                summary.total_bytes,
                summary.tasks_sha256,
                summary.public_manifest_sha256,
                summary.source_map_sha256,
                summary.manifest_sha256,
                summary.batch_content_root,
                summary.key_id,
                summary.tasks,
            )
        except (AttributeError, TypeError):
            raise EvaluatorContractError(
                "invalid_contract", "verified batch summary is incomplete"
            ) from None
        if type(fields[12]) is not tuple:
            raise EvaluatorContractError(
                "invalid_contract", "verified batch task collection is invalid"
            )
        return cls(
            profile_id=fields[0],
            profile_schema_version=PROFILE_SCHEMA_VERSION,
            split=fields[1],
            task_count=fields[2],
            total_files=fields[3],
            total_nodes=fields[4],
            total_bytes=fields[5],
            tasks_sha256=fields[6],
            public_manifest_sha256=fields[7],
            source_map_sha256=fields[8],
            batch_manifest_sha256=fields[9],
            batch_content_root=fields[10],
            attestation_key_id=fields[11],
            snapshot_policy=snapshot_policy,
            tasks=fields[12],
        )

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_binding_sha256: str,
        expected_wire_sha256: str,
    ) -> "SnapshotBatchBindingV1":
        _require_sha256(expected_binding_sha256, name="expected_binding_sha256")
        raw = _parse_pinned_line(
            payload, expected_wire_sha256=expected_wire_sha256
        )
        keys = frozenset(
            {
                "attestation_key_id",
                "batch_content_root",
                "batch_contract_version",
                "batch_manifest_sha256",
                "binding_sha256",
                "contract_version",
                "kind",
                "profile_id",
                "profile_schema_version",
                "public_manifest_sha256",
                "snapshot_policy",
                "source_map_sha256",
                "split",
                "task_count",
                "tasks",
                "tasks_sha256",
                "total_bytes",
                "total_files",
                "total_nodes",
            }
        )
        value = _strict_object(raw, keys=keys, name="snapshot batch binding")
        if (
            type(value["binding_sha256"]) is not str
            or value["binding_sha256"] != expected_binding_sha256
            or type(value["tasks"]) is not list
        ):
            raise EvaluatorContractError(
                "digest_mismatch", "snapshot batch binding does not match its pin"
            )
        result = cls(
            profile_id=value["profile_id"],
            profile_schema_version=value["profile_schema_version"],
            split=value["split"],
            task_count=value["task_count"],
            total_files=value["total_files"],
            total_nodes=value["total_nodes"],
            total_bytes=value["total_bytes"],
            tasks_sha256=value["tasks_sha256"],
            public_manifest_sha256=value["public_manifest_sha256"],
            source_map_sha256=value["source_map_sha256"],
            batch_manifest_sha256=value["batch_manifest_sha256"],
            batch_content_root=value["batch_content_root"],
            attestation_key_id=value["attestation_key_id"],
            snapshot_policy=_policy_from_dict(value["snapshot_policy"]),
            tasks=tuple(_batch_task_from_record(item) for item in value["tasks"]),
            batch_contract_version=value["batch_contract_version"],
            contract_version=value["contract_version"],
            kind=value["kind"],
        )
        if (
            result.binding_sha256 != expected_binding_sha256
            or result.wire_sha256 != expected_wire_sha256
            or result.to_bytes() != payload
        ):
            raise EvaluatorContractError(
                "noncanonical_json", "snapshot batch binding is not canonical"
            )
        return result


@dataclass(frozen=True, slots=True)
class ExecutionPolicyBindingV1:
    """Fixed Linux OCI and shared model/runtime policy for one batch."""

    runtime_image_id: str
    d2_backend_id: str
    d2_model_id: str
    d3_backend_id: str
    d3_model_id: str
    snapshot_policy_sha256: str
    d2_budget_sha256: str
    d3_budget_sha256: str
    tree_limits_sha256: str
    wall_time_seconds: int = 1800
    memory_bytes: int = 2 * 1024 * 1024 * 1024
    cpu_millis: int = 2000
    pids_limit: int = 64
    open_files_limit: int = 256
    stdout_max_bytes: int = 6 * 1024 * 1024
    stderr_max_bytes: int = 1024 * 1024
    tmpfs_bytes: int = 64 * 1024 * 1024
    provider: str = "linux-oci-v1"
    worker_version: str = "source-discovery-isolated-worker-v1"
    network_mode: str = "none"
    rootfs_mode: str = "read-only"
    source_mount_mode: str = "read-only"
    capabilities_mode: str = "drop-all"
    no_new_privileges: bool = True
    contract_version: int = EVALUATOR_CONTRACT_VERSION
    kind: str = EXECUTION_POLICY_BINDING_KIND
    policy_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != EVALUATOR_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != EXECUTION_POLICY_BINDING_KIND
            or type(self.provider) is not str
            or self.provider != "linux-oci-v1"
            or type(self.worker_version) is not str
            or self.worker_version != "source-discovery-isolated-worker-v1"
            or type(self.runtime_image_id) is not str
            or _IMAGE_ID_RE.fullmatch(self.runtime_image_id) is None
            or type(self.network_mode) is not str
            or self.network_mode != "none"
            or type(self.rootfs_mode) is not str
            or self.rootfs_mode != "read-only"
            or type(self.source_mount_mode) is not str
            or self.source_mount_mode != "read-only"
            or type(self.capabilities_mode) is not str
            or self.capabilities_mode != "drop-all"
            or type(self.no_new_privileges) is not bool
            or self.no_new_privileges is not True
        ):
            raise EvaluatorContractError(
                "invalid_contract", "execution policy fixed properties are invalid"
            )
        for value, name in (
            (self.d2_backend_id, "d2_backend_id"),
            (self.d2_model_id, "d2_model_id"),
            (self.d3_backend_id, "d3_backend_id"),
            (self.d3_model_id, "d3_model_id"),
        ):
            if type(value) is not str or _COMPONENT_ID_RE.fullmatch(value) is None:
                raise EvaluatorContractError(
                    "invalid_contract", f"{name} is invalid"
                )
        for value, name in (
            (self.snapshot_policy_sha256, "snapshot_policy_sha256"),
            (self.d2_budget_sha256, "d2_budget_sha256"),
            (self.d3_budget_sha256, "d3_budget_sha256"),
            (self.tree_limits_sha256, "tree_limits_sha256"),
        ):
            _require_sha256(value, name=name)
        resources = (
            self.wall_time_seconds,
            self.memory_bytes,
            self.cpu_millis,
            self.pids_limit,
            self.open_files_limit,
            self.stdout_max_bytes,
            self.stderr_max_bytes,
            self.tmpfs_bytes,
        )
        if any(type(item) is not int for item in resources) or not (
            1 <= resources[0] <= 3600
            and 256 * 1024 * 1024 <= resources[1] <= 8 * 1024 * 1024 * 1024
            and 100 <= resources[2] <= 8000
            and 8 <= resources[3] <= 256
            and 32 <= resources[4] <= 1024
            and 1 <= resources[5] <= 6 * 1024 * 1024
            and 1 <= resources[6] <= 4 * 1024 * 1024
            and 1024 * 1024 <= resources[7] <= 512 * 1024 * 1024
        ):
            raise EvaluatorContractError(
                "limit_exceeded", "execution policy resources exceed fixed bounds"
            )
        object.__setattr__(
            self,
            "policy_sha256",
            hashlib.sha256(
                EXECUTION_POLICY_BINDING_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "capabilities_mode": self.capabilities_mode,
            "contract_version": self.contract_version,
            "cpu_millis": self.cpu_millis,
            "d2_backend_id": self.d2_backend_id,
            "d2_budget_sha256": self.d2_budget_sha256,
            "d2_model_id": self.d2_model_id,
            "d3_backend_id": self.d3_backend_id,
            "d3_budget_sha256": self.d3_budget_sha256,
            "d3_model_id": self.d3_model_id,
            "kind": self.kind,
            "memory_bytes": self.memory_bytes,
            "network_mode": self.network_mode,
            "no_new_privileges": self.no_new_privileges,
            "open_files_limit": self.open_files_limit,
            "pids_limit": self.pids_limit,
            "provider": self.provider,
            "rootfs_mode": self.rootfs_mode,
            "runtime_image_id": self.runtime_image_id,
            "snapshot_policy_sha256": self.snapshot_policy_sha256,
            "source_mount_mode": self.source_mount_mode,
            "stderr_max_bytes": self.stderr_max_bytes,
            "stdout_max_bytes": self.stdout_max_bytes,
            "tmpfs_bytes": self.tmpfs_bytes,
            "tree_limits_sha256": self.tree_limits_sha256,
            "wall_time_seconds": self.wall_time_seconds,
            "worker_version": self.worker_version,
        }

    def to_dict(self) -> dict[str, object]:
        core = self._core_dict()
        expected = hashlib.sha256(
            EXECUTION_POLICY_BINDING_DIGEST_DOMAIN + _canonical_json(core)
        ).hexdigest()
        if type(self.policy_sha256) is not str or self.policy_sha256 != expected:
            raise EvaluatorContractError(
                "invalid_binding", "execution policy digest no longer matches"
            )
        return {**core, "policy_sha256": self.policy_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > EVALUATOR_CONTRACT_MAX_WIRE_BYTES:
            raise EvaluatorContractError(
                "limit_exceeded", "execution policy exceeds its wire limit"
            )
        return payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_policy_sha256: str,
        expected_wire_sha256: str,
    ) -> "ExecutionPolicyBindingV1":
        _require_sha256(expected_policy_sha256, name="expected_policy_sha256")
        raw = _parse_pinned_line(
            payload, expected_wire_sha256=expected_wire_sha256
        )
        value = _strict_object(
            raw,
            keys=_EXECUTION_POLICY_CORE_KEYS | {"policy_sha256"},
            name="execution policy",
        )
        if (
            type(value["policy_sha256"]) is not str
            or value["policy_sha256"] != expected_policy_sha256
        ):
            raise EvaluatorContractError(
                "digest_mismatch", "execution policy does not match its pin"
            )
        arguments = {key: value[key] for key in _EXECUTION_POLICY_CORE_KEYS}
        result = cls(**arguments)
        if (
            result.policy_sha256 != expected_policy_sha256
            or result.wire_sha256 != expected_wire_sha256
            or result.to_bytes() != payload
        ):
            raise EvaluatorContractError(
                "noncanonical_json", "execution policy is not canonical"
            )
        return result


@dataclass(frozen=True, slots=True)
class DiscoveryTaskExecutionPlanV1:
    """Pre-launch binding for one member, handoff, and exact D2/D3 replay wires."""

    batch_binding_sha256: str
    execution_policy_sha256: str
    task_id: str
    snapshot_id: str
    snapshot_manifest_sha256: str
    snapshot_content_root: str
    handoff_sha256: str
    handoff_wire_sha256: str
    d2_replay_sha256: str
    d2_replay_wire_sha256: str
    d3_replay_sha256: str
    d3_replay_wire_sha256: str
    contract_version: int = EVALUATOR_CONTRACT_VERSION
    kind: str = DISCOVERY_TASK_EXECUTION_PLAN_KIND
    plan_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != EVALUATOR_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != DISCOVERY_TASK_EXECUTION_PLAN_KIND
            or type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.snapshot_id) is not str
            or _SNAPSHOT_ID_RE.fullmatch(self.snapshot_id) is None
        ):
            raise EvaluatorContractError(
                "invalid_contract", "task execution plan identity is invalid"
            )
        for value, name in (
            (self.batch_binding_sha256, "batch_binding_sha256"),
            (self.execution_policy_sha256, "execution_policy_sha256"),
            (self.snapshot_manifest_sha256, "snapshot_manifest_sha256"),
            (self.snapshot_content_root, "snapshot_content_root"),
            (self.handoff_sha256, "handoff_sha256"),
            (self.handoff_wire_sha256, "handoff_wire_sha256"),
            (self.d2_replay_sha256, "d2_replay_sha256"),
            (self.d2_replay_wire_sha256, "d2_replay_wire_sha256"),
            (self.d3_replay_sha256, "d3_replay_sha256"),
            (self.d3_replay_wire_sha256, "d3_replay_wire_sha256"),
        ):
            _require_sha256(value, name=name)
        object.__setattr__(
            self,
            "plan_sha256",
            hashlib.sha256(
                DISCOVERY_TASK_EXECUTION_PLAN_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "batch_binding_sha256": self.batch_binding_sha256,
            "contract_version": self.contract_version,
            "d2_replay_sha256": self.d2_replay_sha256,
            "d2_replay_wire_sha256": self.d2_replay_wire_sha256,
            "d3_replay_sha256": self.d3_replay_sha256,
            "d3_replay_wire_sha256": self.d3_replay_wire_sha256,
            "execution_policy_sha256": self.execution_policy_sha256,
            "handoff_sha256": self.handoff_sha256,
            "handoff_wire_sha256": self.handoff_wire_sha256,
            "kind": self.kind,
            "snapshot_content_root": self.snapshot_content_root,
            "snapshot_id": self.snapshot_id,
            "snapshot_manifest_sha256": self.snapshot_manifest_sha256,
            "task_id": self.task_id,
        }

    def to_dict(self) -> dict[str, object]:
        core = self._core_dict()
        expected = hashlib.sha256(
            DISCOVERY_TASK_EXECUTION_PLAN_DIGEST_DOMAIN + _canonical_json(core)
        ).hexdigest()
        if type(self.plan_sha256) is not str or self.plan_sha256 != expected:
            raise EvaluatorContractError(
                "invalid_binding", "task execution plan digest no longer matches"
            )
        return {**core, "plan_sha256": self.plan_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > EVALUATOR_CONTRACT_MAX_WIRE_BYTES:
            raise EvaluatorContractError(
                "limit_exceeded", "task execution plan exceeds its wire limit"
            )
        return payload

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_handoff(
        cls,
        batch: SnapshotBatchBindingV1,
        execution_policy: ExecutionPolicyBindingV1,
        handoff: WorkerHandoffV1,
        *,
        d2_replay_sha256: str,
        d2_replay_wire_sha256: str,
        d3_replay_sha256: str,
        d3_replay_wire_sha256: str,
    ) -> "DiscoveryTaskExecutionPlanV1":
        if (
            type(batch) is not SnapshotBatchBindingV1
            or type(execution_policy) is not ExecutionPolicyBindingV1
            or type(handoff) is not WorkerHandoffV1
        ):
            raise EvaluatorContractError(
                "invalid_argument", "task plan inputs must have exact types"
            )
        # Freeze each nested value to one canonical wire before reading any of
        # its scalar bindings.  This avoids retaining caller-owned references
        # across the plan-construction boundary.
        batch_wire = batch.to_bytes()
        batch = SnapshotBatchBindingV1.from_bytes(
            batch_wire,
            expected_binding_sha256=_embedded_sha256_from_canonical_wire(
                batch_wire, field="binding_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(batch_wire).hexdigest(),
        )
        policy_wire = execution_policy.to_bytes()
        execution_policy = ExecutionPolicyBindingV1.from_bytes(
            policy_wire,
            expected_policy_sha256=_embedded_sha256_from_canonical_wire(
                policy_wire, field="policy_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(policy_wire).hexdigest(),
        )
        handoff_wire = handoff.to_bytes()
        handoff = WorkerHandoffV1.from_bytes(
            handoff_wire,
            expected_sha256=_embedded_sha256_from_canonical_wire(
                handoff_wire, field="handoff_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(handoff_wire).hexdigest(),
        )
        matches = tuple(
            task for task in batch.tasks if task.task_id == handoff.task.task_id
        )
        if len(matches) != 1:
            raise EvaluatorContractError(
                "invalid_binding", "worker handoff is not a unique batch member"
            )
        member = matches[0]
        try:
            expected_task = DiscoveryTaskInputV1(
                task_id=member.task_id,
                repo_url=member.repo_url,
                commit=member.commit,
                instruction_id=member.instruction_id,
                snapshot_manifest_sha256=member.snapshot_manifest_sha256,
                snapshot_content_root=member.snapshot_content_root,
            )
        except (AttributeError, TypeError, ValueError):
            raise EvaluatorContractError(
                "invalid_binding", "batch member cannot form a discovery task"
            ) from None
        if handoff.task != expected_task:
            raise EvaluatorContractError(
                "invalid_binding", "worker handoff does not match its batch member"
            )
        return cls(
            batch_binding_sha256=batch.binding_sha256,
            execution_policy_sha256=execution_policy.policy_sha256,
            task_id=expected_task.task_id,
            snapshot_id=expected_task.snapshot_id,
            snapshot_manifest_sha256=expected_task.snapshot_manifest_sha256,
            snapshot_content_root=expected_task.snapshot_content_root,
            handoff_sha256=handoff.handoff_sha256,
            handoff_wire_sha256=handoff.wire_sha256,
            d2_replay_sha256=d2_replay_sha256,
            d2_replay_wire_sha256=d2_replay_wire_sha256,
            d3_replay_sha256=d3_replay_sha256,
            d3_replay_wire_sha256=d3_replay_wire_sha256,
        )

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_plan_sha256: str,
        expected_wire_sha256: str,
    ) -> "DiscoveryTaskExecutionPlanV1":
        _require_sha256(expected_plan_sha256, name="expected_plan_sha256")
        value = _strict_object(
            _parse_pinned_line(
                payload, expected_wire_sha256=expected_wire_sha256
            ),
            keys=frozenset(
                {
                    "batch_binding_sha256",
                    "contract_version",
                    "d2_replay_sha256",
                    "d2_replay_wire_sha256",
                    "d3_replay_sha256",
                    "d3_replay_wire_sha256",
                    "execution_policy_sha256",
                    "handoff_sha256",
                    "handoff_wire_sha256",
                    "kind",
                    "plan_sha256",
                    "snapshot_content_root",
                    "snapshot_id",
                    "snapshot_manifest_sha256",
                    "task_id",
                }
            ),
            name="task execution plan",
        )
        if value["plan_sha256"] != expected_plan_sha256:
            raise EvaluatorContractError(
                "digest_mismatch", "task execution plan does not match its pin"
            )
        result = cls(
            batch_binding_sha256=value["batch_binding_sha256"],
            execution_policy_sha256=value["execution_policy_sha256"],
            d2_replay_sha256=value["d2_replay_sha256"],
            d2_replay_wire_sha256=value["d2_replay_wire_sha256"],
            d3_replay_sha256=value["d3_replay_sha256"],
            d3_replay_wire_sha256=value["d3_replay_wire_sha256"],
            task_id=value["task_id"],
            snapshot_id=value["snapshot_id"],
            snapshot_manifest_sha256=value["snapshot_manifest_sha256"],
            snapshot_content_root=value["snapshot_content_root"],
            handoff_sha256=value["handoff_sha256"],
            handoff_wire_sha256=value["handoff_wire_sha256"],
            contract_version=value["contract_version"],
            kind=value["kind"],
        )
        if (
            result.plan_sha256 != expected_plan_sha256
            or result.wire_sha256 != expected_wire_sha256
            or result.to_bytes() != payload
        ):
            raise EvaluatorContractError(
                "noncanonical_json", "task execution plan is not canonical"
            )
        return result


def _nested_payload(value: object, *, name: str) -> bytes:
    if type(value) is not dict:
        raise EvaluatorContractError(
            "invalid_contract", f"{name} must be an exact object"
        )
    return _canonical_json(value) + b"\n"


@dataclass(frozen=True, slots=True)
class DiscoveryBatchExecutionPlanV1:
    """Complete pre-launch plan covering every task in one batch exactly once."""

    batch: SnapshotBatchBindingV1
    execution_policy: ExecutionPolicyBindingV1
    tasks: tuple[DiscoveryTaskExecutionPlanV1, ...]
    contract_version: int = EVALUATOR_CONTRACT_VERSION
    kind: str = DISCOVERY_BATCH_EXECUTION_PLAN_KIND
    plan_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != EVALUATOR_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != DISCOVERY_BATCH_EXECUTION_PLAN_KIND
            or type(self.batch) is not SnapshotBatchBindingV1
            or type(self.execution_policy) is not ExecutionPolicyBindingV1
            or type(self.tasks) is not tuple
        ):
            raise EvaluatorContractError(
                "invalid_contract", "batch execution plan root is invalid"
            )
        batch_wire = self.batch.to_bytes()
        batch = SnapshotBatchBindingV1.from_bytes(
            batch_wire,
            expected_binding_sha256=_embedded_sha256_from_canonical_wire(
                batch_wire, field="binding_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(batch_wire).hexdigest(),
        )
        policy_wire = self.execution_policy.to_bytes()
        policy = ExecutionPolicyBindingV1.from_bytes(
            policy_wire,
            expected_policy_sha256=_embedded_sha256_from_canonical_wire(
                policy_wire, field="policy_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(policy_wire).hexdigest(),
        )
        task_plans: list[DiscoveryTaskExecutionPlanV1] = []
        for task in self.tasks:
            if type(task) is not DiscoveryTaskExecutionPlanV1:
                raise EvaluatorContractError(
                    "invalid_argument", "batch plan tasks must have exact types"
                )
            wire = task.to_bytes()
            task_plans.append(
                DiscoveryTaskExecutionPlanV1.from_bytes(
                    wire,
                    expected_plan_sha256=_embedded_sha256_from_canonical_wire(
                        wire, field="plan_sha256"
                    ),
                    expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
                )
            )
        tasks = tuple(task_plans)
        if policy.snapshot_policy_sha256 != snapshot_policy_sha256_v1(
            batch.snapshot_policy
        ):
            raise EvaluatorContractError(
                "invalid_binding", "execution policy does not bind the batch policy"
            )
        if len(tasks) != len(batch.tasks):
            raise EvaluatorContractError(
                "invalid_binding", "batch plan does not cover every batch task"
            )
        for member, task_plan in zip(batch.tasks, tasks, strict=True):
            try:
                expected_task = DiscoveryTaskInputV1(
                    task_id=member.task_id,
                    repo_url=member.repo_url,
                    commit=member.commit,
                    instruction_id=member.instruction_id,
                    snapshot_manifest_sha256=member.snapshot_manifest_sha256,
                    snapshot_content_root=member.snapshot_content_root,
                )
            except (AttributeError, TypeError, ValueError):
                raise EvaluatorContractError(
                    "invalid_binding", "batch member cannot form a discovery task"
                ) from None
            if (
                task_plan.batch_binding_sha256 != batch.binding_sha256
                or task_plan.execution_policy_sha256 != policy.policy_sha256
                or task_plan.task_id != expected_task.task_id
                or task_plan.snapshot_id != expected_task.snapshot_id
                or task_plan.snapshot_manifest_sha256
                != expected_task.snapshot_manifest_sha256
                or task_plan.snapshot_content_root
                != expected_task.snapshot_content_root
            ):
                raise EvaluatorContractError(
                    "invalid_binding", "batch plan task order or identity is invalid"
                )
        if (
            len({task.task_id for task in tasks}) != len(tasks)
            or len({task.plan_sha256 for task in tasks}) != len(tasks)
            or len({task.handoff_sha256 for task in tasks}) != len(tasks)
            or len({task.handoff_wire_sha256 for task in tasks}) != len(tasks)
            or len({task.d2_replay_sha256 for task in tasks}) != len(tasks)
            or len({task.d2_replay_wire_sha256 for task in tasks}) != len(tasks)
            or len({task.d3_replay_sha256 for task in tasks}) != len(tasks)
            or len({task.d3_replay_wire_sha256 for task in tasks}) != len(tasks)
        ):
            raise EvaluatorContractError(
                "invalid_binding", "batch plan repeats a task, handoff, or replay identity"
            )
        object.__setattr__(self, "batch", batch)
        object.__setattr__(self, "execution_policy", policy)
        object.__setattr__(self, "tasks", tasks)
        object.__setattr__(
            self,
            "plan_sha256",
            hashlib.sha256(
                DISCOVERY_BATCH_EXECUTION_PLAN_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )
        if len(self.to_bytes()) > EVALUATOR_CONTRACT_MAX_WIRE_BYTES:
            raise EvaluatorContractError(
                "limit_exceeded", "batch execution plan exceeds its wire limit"
            )

    def _core_dict(self) -> dict[str, object]:
        return {
            "batch": self.batch.to_dict(),
            "contract_version": self.contract_version,
            "execution_policy": self.execution_policy.to_dict(),
            "kind": self.kind,
            "tasks": [task.to_dict() for task in self.tasks],
        }

    def to_dict(self) -> dict[str, object]:
        core = self._core_dict()
        expected = hashlib.sha256(
            DISCOVERY_BATCH_EXECUTION_PLAN_DIGEST_DOMAIN + _canonical_json(core)
        ).hexdigest()
        if type(self.plan_sha256) is not str or self.plan_sha256 != expected:
            raise EvaluatorContractError(
                "invalid_binding", "batch execution plan digest no longer matches"
            )
        return {**core, "plan_sha256": self.plan_sha256}

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_plan_sha256: str,
        expected_wire_sha256: str,
    ) -> "DiscoveryBatchExecutionPlanV1":
        _require_sha256(expected_plan_sha256, name="expected_plan_sha256")
        value = _strict_object(
            _parse_pinned_line(
                payload, expected_wire_sha256=expected_wire_sha256
            ),
            keys=frozenset(
                {
                    "batch",
                    "contract_version",
                    "execution_policy",
                    "kind",
                    "plan_sha256",
                    "tasks",
                }
            ),
            name="batch execution plan",
        )
        if (
            value["plan_sha256"] != expected_plan_sha256
            or type(value["tasks"]) is not list
        ):
            raise EvaluatorContractError(
                "digest_mismatch", "batch execution plan does not match its pin"
            )
        raw_batch = value["batch"]
        raw_policy = value["execution_policy"]
        if type(raw_batch) is not dict or type(raw_policy) is not dict:
            raise EvaluatorContractError(
                "invalid_contract", "batch execution plan nested roots are invalid"
            )
        batch_payload = _nested_payload(raw_batch, name="batch binding")
        batch = SnapshotBatchBindingV1.from_bytes(
            batch_payload,
            expected_binding_sha256=_require_sha256(
                raw_batch.get("binding_sha256"), name="binding_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(batch_payload).hexdigest(),
        )
        policy_payload = _nested_payload(raw_policy, name="execution policy")
        policy = ExecutionPolicyBindingV1.from_bytes(
            policy_payload,
            expected_policy_sha256=_require_sha256(
                raw_policy.get("policy_sha256"), name="policy_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(policy_payload).hexdigest(),
        )
        task_plans: list[DiscoveryTaskExecutionPlanV1] = []
        for raw_task in value["tasks"]:
            task_payload = _nested_payload(raw_task, name="task plan")
            if type(raw_task) is not dict:
                raise EvaluatorContractError(
                    "invalid_contract", "task plan must be an object"
                )
            task_plans.append(
                DiscoveryTaskExecutionPlanV1.from_bytes(
                    task_payload,
                    expected_plan_sha256=_require_sha256(
                        raw_task.get("plan_sha256"), name="task plan digest"
                    ),
                    expected_wire_sha256=hashlib.sha256(task_payload).hexdigest(),
                )
            )
        result = cls(
            batch=batch,
            execution_policy=policy,
            tasks=tuple(task_plans),
            contract_version=value["contract_version"],
            kind=value["kind"],
        )
        if (
            result.plan_sha256 != expected_plan_sha256
            or result.wire_sha256 != expected_wire_sha256
            or result.to_bytes() != payload
        ):
            raise EvaluatorContractError(
                "noncanonical_json", "batch execution plan is not canonical"
            )
        return result


@dataclass(frozen=True, slots=True)
class DiscoveryTaskExecutionReceiptV1:
    """Terminal success receipt for one exact task plan and result bundle."""

    task_plan_sha256: str
    execution_policy_sha256: str
    task_id: str
    snapshot_id: str
    run_sha256: str
    run_wire_sha256: str
    discovery_result_sha256: str
    dataset_sha256: str
    artifact_index_sha256: str
    runtime_evidence: RuntimeEvidenceV1
    status: str = "succeeded"
    contract_version: int = EVALUATOR_CONTRACT_VERSION
    kind: str = DISCOVERY_TASK_EXECUTION_RECEIPT_KIND
    receipt_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != EVALUATOR_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != DISCOVERY_TASK_EXECUTION_RECEIPT_KIND
            or type(self.status) is not str
            or self.status != "succeeded"
            or type(self.task_id) is not str
            or _TASK_ID_RE.fullmatch(self.task_id) is None
            or type(self.snapshot_id) is not str
            or _SNAPSHOT_ID_RE.fullmatch(self.snapshot_id) is None
        ):
            raise EvaluatorContractError(
                "invalid_contract", "task execution receipt identity is invalid"
            )
        for value, name in (
            (self.task_plan_sha256, "task_plan_sha256"),
            (self.execution_policy_sha256, "execution_policy_sha256"),
            (self.run_sha256, "run_sha256"),
            (self.run_wire_sha256, "run_wire_sha256"),
            (self.discovery_result_sha256, "discovery_result_sha256"),
            (self.dataset_sha256, "dataset_sha256"),
            (self.artifact_index_sha256, "artifact_index_sha256"),
        ):
            _require_sha256(value, name=name)
        if type(self.runtime_evidence) is not RuntimeEvidenceV1:
            raise EvaluatorContractError(
                "invalid_argument", "runtime evidence must have an exact type"
            )
        try:
            evidence_wire = self.runtime_evidence.to_bytes()
            evidence = RuntimeEvidenceV1.from_bytes(
                evidence_wire,
                expected_evidence_sha256=self.runtime_evidence.evidence_sha256,
                expected_wire_sha256=hashlib.sha256(evidence_wire).hexdigest(),
            )
        except (AttributeError, RuntimeEvidenceError, TypeError, ValueError):
            raise EvaluatorContractError(
                "invalid_binding", "runtime evidence did not pass strict normalization"
            ) from None
        if (
            evidence.task_plan_sha256 != self.task_plan_sha256
            or evidence.execution_policy_sha256 != self.execution_policy_sha256
            or evidence.task_id != self.task_id
            or evidence.snapshot_id != self.snapshot_id
            or evidence.run_sha256 != self.run_sha256
            or evidence.run_wire_sha256 != self.run_wire_sha256
        ):
            raise EvaluatorContractError(
                "invalid_binding", "runtime evidence is detached from the task receipt"
            )
        object.__setattr__(self, "runtime_evidence", evidence)
        object.__setattr__(
            self,
            "receipt_sha256",
            hashlib.sha256(
                DISCOVERY_TASK_EXECUTION_RECEIPT_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )

    def _core_dict(self) -> dict[str, object]:
        return {
            "artifact_index_sha256": self.artifact_index_sha256,
            "contract_version": self.contract_version,
            "dataset_sha256": self.dataset_sha256,
            "discovery_result_sha256": self.discovery_result_sha256,
            "execution_policy_sha256": self.execution_policy_sha256,
            "kind": self.kind,
            "run_sha256": self.run_sha256,
            "run_wire_sha256": self.run_wire_sha256,
            "runtime_evidence": self.runtime_evidence.to_dict(),
            "runtime_evidence_sha256": self.runtime_evidence.evidence_sha256,
            "snapshot_id": self.snapshot_id,
            "status": self.status,
            "task_id": self.task_id,
            "task_plan_sha256": self.task_plan_sha256,
        }

    def to_dict(self) -> dict[str, object]:
        core = self._core_dict()
        expected = hashlib.sha256(
            DISCOVERY_TASK_EXECUTION_RECEIPT_DIGEST_DOMAIN
            + _canonical_json(core)
        ).hexdigest()
        if type(self.receipt_sha256) is not str or self.receipt_sha256 != expected:
            raise EvaluatorContractError(
                "invalid_binding", "task execution receipt digest no longer matches"
            )
        return {**core, "receipt_sha256": self.receipt_sha256}

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @property
    def runtime_evidence_sha256(self) -> str:
        return self.runtime_evidence.evidence_sha256

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_receipt_sha256: str,
        expected_wire_sha256: str,
    ) -> "DiscoveryTaskExecutionReceiptV1":
        _require_sha256(expected_receipt_sha256, name="expected_receipt_sha256")
        keys = frozenset(
            {
                "artifact_index_sha256",
                "contract_version",
                "dataset_sha256",
                "discovery_result_sha256",
                "execution_policy_sha256",
                "kind",
                "receipt_sha256",
                "run_sha256",
                "run_wire_sha256",
                "runtime_evidence",
                "runtime_evidence_sha256",
                "snapshot_id",
                "status",
                "task_id",
                "task_plan_sha256",
            }
        )
        value = _strict_object(
            _parse_pinned_line(
                payload, expected_wire_sha256=expected_wire_sha256
            ),
            keys=keys,
            name="task execution receipt",
        )
        if value["receipt_sha256"] != expected_receipt_sha256:
            raise EvaluatorContractError(
                "digest_mismatch", "task execution receipt does not match its pin"
            )
        raw_evidence = value["runtime_evidence"]
        evidence_payload = _nested_payload(raw_evidence, name="runtime evidence")
        if type(raw_evidence) is not dict:
            raise EvaluatorContractError(
                "invalid_contract", "runtime evidence must be an object"
            )
        try:
            evidence = RuntimeEvidenceV1.from_bytes(
                evidence_payload,
                expected_evidence_sha256=_require_sha256(
                    raw_evidence.get("evidence_sha256"),
                    name="runtime evidence digest",
                ),
                expected_wire_sha256=hashlib.sha256(evidence_payload).hexdigest(),
            )
        except RuntimeEvidenceError:
            raise EvaluatorContractError(
                "invalid_contract", "runtime evidence did not pass strict parsing"
            ) from None
        if value["runtime_evidence_sha256"] != evidence.evidence_sha256:
            raise EvaluatorContractError(
                "invalid_binding", "runtime evidence digest is detached"
            )
        result = cls(
            task_plan_sha256=value["task_plan_sha256"],
            execution_policy_sha256=value["execution_policy_sha256"],
            task_id=value["task_id"],
            snapshot_id=value["snapshot_id"],
            run_sha256=value["run_sha256"],
            run_wire_sha256=value["run_wire_sha256"],
            discovery_result_sha256=value["discovery_result_sha256"],
            dataset_sha256=value["dataset_sha256"],
            artifact_index_sha256=value["artifact_index_sha256"],
            runtime_evidence=evidence,
            status=value["status"],
            contract_version=value["contract_version"],
            kind=value["kind"],
        )
        if (
            result.receipt_sha256 != expected_receipt_sha256
            or result.wire_sha256 != expected_wire_sha256
            or result.to_bytes() != payload
        ):
            raise EvaluatorContractError(
                "noncanonical_json", "task execution receipt is not canonical"
            )
        return result


@dataclass(frozen=True, slots=True)
class DiscoveryBatchExecutionReceiptV1:
    """Self-contained closure of pre/post batch verification and publication."""

    plan: DiscoveryBatchExecutionPlanV1
    pre_batch_binding_sha256: str
    post_batch_binding_sha256: str
    artifact_index_sha256: str
    tasks: tuple[DiscoveryTaskExecutionReceiptV1, ...]
    result_bundle_version: str = "source-discovery-result-bundle-v1"
    artifact_index_contract_version: int = 1
    contract_version: int = EVALUATOR_CONTRACT_VERSION
    kind: str = DISCOVERY_BATCH_EXECUTION_RECEIPT_KIND
    receipt_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.contract_version) is not int
            or self.contract_version != EVALUATOR_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != DISCOVERY_BATCH_EXECUTION_RECEIPT_KIND
            or type(self.result_bundle_version) is not str
            or self.result_bundle_version != "source-discovery-result-bundle-v1"
            or type(self.artifact_index_contract_version) is not int
            or self.artifact_index_contract_version != 1
            or type(self.plan) is not DiscoveryBatchExecutionPlanV1
            or type(self.tasks) is not tuple
        ):
            raise EvaluatorContractError(
                "invalid_contract", "batch execution receipt root is invalid"
            )
        for value, name in (
            (self.pre_batch_binding_sha256, "pre_batch_binding_sha256"),
            (self.post_batch_binding_sha256, "post_batch_binding_sha256"),
            (self.artifact_index_sha256, "artifact_index_sha256"),
        ):
            _require_sha256(value, name=name)
        plan_wire = self.plan.to_bytes()
        plan = DiscoveryBatchExecutionPlanV1.from_bytes(
            plan_wire,
            expected_plan_sha256=_embedded_sha256_from_canonical_wire(
                plan_wire, field="plan_sha256"
            ),
            expected_wire_sha256=hashlib.sha256(plan_wire).hexdigest(),
        )
        receipts: list[DiscoveryTaskExecutionReceiptV1] = []
        for receipt in self.tasks:
            if type(receipt) is not DiscoveryTaskExecutionReceiptV1:
                raise EvaluatorContractError(
                    "invalid_argument", "batch receipt tasks must have exact types"
                )
            wire = receipt.to_bytes()
            receipts.append(
                DiscoveryTaskExecutionReceiptV1.from_bytes(
                    wire,
                    expected_receipt_sha256=_embedded_sha256_from_canonical_wire(
                        wire, field="receipt_sha256"
                    ),
                    expected_wire_sha256=hashlib.sha256(wire).hexdigest(),
                )
            )
        tasks = tuple(receipts)
        if (
            self.pre_batch_binding_sha256 != plan.batch.binding_sha256
            or self.post_batch_binding_sha256 != plan.batch.binding_sha256
            or len(tasks) != len(plan.tasks)
        ):
            raise EvaluatorContractError(
                "invalid_binding", "batch receipt pre/post or membership is invalid"
            )
        for task_plan, receipt in zip(plan.tasks, tasks, strict=True):
            evidence = receipt.runtime_evidence
            resources = evidence.resources
            policy = plan.execution_policy
            if (
                receipt.task_plan_sha256 != task_plan.plan_sha256
                or receipt.execution_policy_sha256
                != policy.policy_sha256
                or receipt.task_id != task_plan.task_id
                or receipt.snapshot_id != task_plan.snapshot_id
                or receipt.artifact_index_sha256 != self.artifact_index_sha256
                or evidence.snapshot_manifest_sha256
                != task_plan.snapshot_manifest_sha256
                or evidence.snapshot_content_root
                != task_plan.snapshot_content_root
                or evidence.handoff_sha256 != task_plan.handoff_sha256
                or evidence.handoff_wire_sha256
                != task_plan.handoff_wire_sha256
                or evidence.runtime_image_id != policy.runtime_image_id
                or resources.wall_time_seconds != policy.wall_time_seconds
                or resources.memory_bytes != policy.memory_bytes
                or resources.cpu_millis != policy.cpu_millis
                or resources.pids_limit != policy.pids_limit
                or resources.open_files_limit != policy.open_files_limit
                or resources.stdout_max_bytes != policy.stdout_max_bytes
                or resources.stderr_max_bytes != policy.stderr_max_bytes
                or resources.tmpfs_bytes != policy.tmpfs_bytes
            ):
                raise EvaluatorContractError(
                    "invalid_binding", "batch receipt task order or identity is invalid"
                )
        if (
            len({receipt.task_id for receipt in tasks}) != len(tasks)
            or len({receipt.receipt_sha256 for receipt in tasks}) != len(tasks)
            or len({receipt.dataset_sha256 for receipt in tasks}) != len(tasks)
        ):
            raise EvaluatorContractError(
                "invalid_binding", "batch receipt repeats a task or result identity"
            )
        evidence_values = tuple(receipt.runtime_evidence for receipt in tasks)
        if (
            len(
                {
                    _canonical_json(evidence.docker_server.to_dict())
                    for evidence in evidence_values
                }
            )
            != 1
            or len(
                {evidence.runtime_image_inspect_sha256 for evidence in evidence_values}
            )
            != 1
            or len({evidence.execution_image_id for evidence in evidence_values})
            != len(evidence_values)
            or len(
                {
                    evidence.execution_image_inspect_sha256
                    for evidence in evidence_values
                }
            )
            != len(evidence_values)
            or len(
                {
                    evidence.materializer_container_identity_sha256
                    for evidence in evidence_values
                }
            )
            != len(evidence_values)
            or len(
                {
                    evidence.container_identity_sha256
                    for evidence in evidence_values
                }
            )
            != len(evidence_values)
            or len({evidence.source_generation_sha256 for evidence in evidence_values})
            != len(evidence_values)
            or len({evidence.runtime_config_sha256 for evidence in evidence_values})
            != len(evidence_values)
        ):
            raise EvaluatorContractError(
                "invalid_binding",
                "batch receipt runtime identities are inconsistent or reused",
            )
        try:
            index = ArtifactBundleIndex(
                contract_version=ARTIFACT_INDEX_CONTRACT_VERSION,
                profile_id=plan.batch.profile_id,
                manifest_sha256=plan.batch.public_manifest_sha256,
                split=plan.batch.split,
                bundles=tuple(
                    ArtifactBundleDigest(
                        task_id=receipt.task_id,
                        dataset_sha256=receipt.dataset_sha256,
                    )
                    for receipt in tasks
                ),
            )
            expected_index_sha256 = hashlib.sha256(
                artifact_bundle_index_payload_v1(index)
            ).hexdigest()
        except (AttributeError, TypeError, ValueError):
            raise EvaluatorContractError(
                "invalid_binding", "batch receipt cannot form its artifact index"
            ) from None
        if self.artifact_index_sha256 != expected_index_sha256:
            raise EvaluatorContractError(
                "invalid_binding", "batch receipt artifact index digest is detached"
            )
        object.__setattr__(self, "plan", plan)
        object.__setattr__(self, "tasks", tasks)
        object.__setattr__(
            self,
            "receipt_sha256",
            hashlib.sha256(
                DISCOVERY_BATCH_EXECUTION_RECEIPT_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )
        if len(self.to_bytes()) > EVALUATOR_CONTRACT_MAX_WIRE_BYTES:
            raise EvaluatorContractError(
                "limit_exceeded", "batch execution receipt exceeds its wire limit"
            )

    def _core_dict(self) -> dict[str, object]:
        return {
            "artifact_index_contract_version": self.artifact_index_contract_version,
            "artifact_index_sha256": self.artifact_index_sha256,
            "contract_version": self.contract_version,
            "kind": self.kind,
            "plan": self.plan.to_dict(),
            "post_batch_binding_sha256": self.post_batch_binding_sha256,
            "pre_batch_binding_sha256": self.pre_batch_binding_sha256,
            "result_bundle_version": self.result_bundle_version,
            "tasks": [receipt.to_dict() for receipt in self.tasks],
        }

    def to_dict(self) -> dict[str, object]:
        core = self._core_dict()
        expected = hashlib.sha256(
            DISCOVERY_BATCH_EXECUTION_RECEIPT_DIGEST_DOMAIN
            + _canonical_json(core)
        ).hexdigest()
        if type(self.receipt_sha256) is not str or self.receipt_sha256 != expected:
            raise EvaluatorContractError(
                "invalid_binding", "batch execution receipt digest no longer matches"
            )
        return {**core, "receipt_sha256": self.receipt_sha256}

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"

    @property
    def wire_sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_receipt_sha256: str,
        expected_wire_sha256: str,
    ) -> "DiscoveryBatchExecutionReceiptV1":
        _require_sha256(expected_receipt_sha256, name="expected_receipt_sha256")
        value = _strict_object(
            _parse_pinned_line(
                payload, expected_wire_sha256=expected_wire_sha256
            ),
            keys=frozenset(
                {
                    "artifact_index_contract_version",
                    "artifact_index_sha256",
                    "contract_version",
                    "kind",
                    "plan",
                    "post_batch_binding_sha256",
                    "pre_batch_binding_sha256",
                    "receipt_sha256",
                    "result_bundle_version",
                    "tasks",
                }
            ),
            name="batch execution receipt",
        )
        if (
            value["receipt_sha256"] != expected_receipt_sha256
            or type(value["tasks"]) is not list
        ):
            raise EvaluatorContractError(
                "digest_mismatch", "batch execution receipt does not match its pin"
            )
        raw_plan = value["plan"]
        if type(raw_plan) is not dict:
            raise EvaluatorContractError(
                "invalid_contract", "batch receipt plan must be an object"
            )
        plan_payload = _nested_payload(raw_plan, name="batch plan")
        plan = DiscoveryBatchExecutionPlanV1.from_bytes(
            plan_payload,
            expected_plan_sha256=_require_sha256(
                raw_plan.get("plan_sha256"), name="batch plan digest"
            ),
            expected_wire_sha256=hashlib.sha256(plan_payload).hexdigest(),
        )
        task_receipts: list[DiscoveryTaskExecutionReceiptV1] = []
        for raw_receipt in value["tasks"]:
            receipt_payload = _nested_payload(raw_receipt, name="task receipt")
            if type(raw_receipt) is not dict:
                raise EvaluatorContractError(
                    "invalid_contract", "task receipt must be an object"
                )
            task_receipts.append(
                DiscoveryTaskExecutionReceiptV1.from_bytes(
                    receipt_payload,
                    expected_receipt_sha256=_require_sha256(
                        raw_receipt.get("receipt_sha256"),
                        name="task receipt digest",
                    ),
                    expected_wire_sha256=hashlib.sha256(
                        receipt_payload
                    ).hexdigest(),
                )
            )
        result = cls(
            plan=plan,
            pre_batch_binding_sha256=value["pre_batch_binding_sha256"],
            post_batch_binding_sha256=value["post_batch_binding_sha256"],
            artifact_index_sha256=value["artifact_index_sha256"],
            tasks=tuple(task_receipts),
            result_bundle_version=value["result_bundle_version"],
            artifact_index_contract_version=value[
                "artifact_index_contract_version"
            ],
            contract_version=value["contract_version"],
            kind=value["kind"],
        )
        if (
            result.receipt_sha256 != expected_receipt_sha256
            or result.wire_sha256 != expected_wire_sha256
            or result.to_bytes() != payload
        ):
            raise EvaluatorContractError(
                "noncanonical_json", "batch execution receipt is not canonical"
            )
        return result


__all__ = [
    "DISCOVERY_BATCH_EXECUTION_PLAN_DIGEST_DOMAIN",
    "DISCOVERY_BATCH_EXECUTION_PLAN_KIND",
    "DISCOVERY_BATCH_EXECUTION_RECEIPT_DIGEST_DOMAIN",
    "DISCOVERY_BATCH_EXECUTION_RECEIPT_KIND",
    "DISCOVERY_TASK_EXECUTION_PLAN_DIGEST_DOMAIN",
    "DISCOVERY_TASK_EXECUTION_PLAN_KIND",
    "DISCOVERY_TASK_EXECUTION_RECEIPT_DIGEST_DOMAIN",
    "DISCOVERY_TASK_EXECUTION_RECEIPT_KIND",
    "DiscoveryBatchExecutionPlanV1",
    "DiscoveryBatchExecutionReceiptV1",
    "DiscoveryTaskExecutionPlanV1",
    "DiscoveryTaskExecutionReceiptV1",
    "EVALUATOR_CONTRACT_MAX_WIRE_BYTES",
    "EVALUATOR_CONTRACT_VERSION",
    "EXECUTION_POLICY_BINDING_DIGEST_DOMAIN",
    "EXECUTION_POLICY_BINDING_KIND",
    "EvaluatorContractError",
    "ExecutionPolicyBindingV1",
    "SNAPSHOT_BATCH_BINDING_DIGEST_DOMAIN",
    "SNAPSHOT_BATCH_BINDING_KIND",
    "SNAPSHOT_POLICY_DIGEST_DOMAIN",
    "SnapshotBatchBindingV1",
    "snapshot_policy_sha256_v1",
]
