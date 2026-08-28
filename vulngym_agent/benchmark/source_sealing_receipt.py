"""Strict, path-free closure receipt for the fixed 22-repository source seal.

The receipt is a mechanical binding of already verified, path-free evidence.
It deliberately has no filesystem, process, network, key-material, or publication
interface.  The trusted snapshot verifier performs each independent verification
run and mints its non-reusable ``run_id``.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field
import hashlib
import json
import re
from typing import Final, Literal

from vulngym_agent.benchmark.contracts import (
    BenchmarkContractError,
    BenchmarkTask,
)
from vulngym_agent.benchmark.snapshot_batch import (
    DEFAULT_SNAPSHOT_POLICY,
    PROFILE_ID,
    PROFILE_MANIFEST_SHA256,
    SnapshotBatchError,
    SnapshotBatchVerificationEvidenceV2,
    _claim_snapshot_batch_verification_evidence_batch,
)
from vulngym_agent.benchmark.source_acquisition import (
    SOURCE_ACQUISITION_CONTRACT_VERSION,
)


SOURCE_SEALING_CLOSURE_CONTRACT_VERSION: Final[int] = 2
SOURCE_SEALING_CLOSURE_KIND: Final[str] = (
    "vulngym.source-sealing-closure-receipt.v2"
)
SOURCE_SEALING_CLOSURE_STATUS: Final[str] = "closed"
SOURCE_SEALING_CLOSURE_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym source sealing closure receipt v2\0"
)
SOURCE_SEALING_TASK_CLOSURE_DOMAIN: Final[bytes] = b"vulngym.source-sealing.task-closure.v2\0"
SOURCE_SEALING_CLOSURE_MAX_WIRE_BYTES: Final[int] = 64 * 1024
SOURCE_SEALING_CLOSURE_MAX_JSON_NODES: Final[int] = 512
SOURCE_SEALING_CLOSURE_MAX_JSON_DEPTH: Final[int] = 12
SOURCE_SEALING_REPOSITORY_COUNT: Final[int] = 22
SOURCE_SEALING_TASK_COUNT: Final[int] = 70
SOURCE_SEALING_VERIFY_ROUNDS_PER_SPLIT: Final[int] = 2
SOURCE_SEALING_ACQUISITION_REPORT_MAX_WIRE_BYTES: Final[int] = 16 * 1024 * 1024
SOURCE_SEALING_ACQUISITION_REPORT_MAX_JSON_NODES: Final[int] = 250_000
SOURCE_SEALING_ACQUISITION_REPORT_MAX_JSON_DEPTH: Final[int] = 32

_SHA1_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}\Z")
_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z"
)
_SPLIT_COUNTS: Final[dict[str, int]] = {"test": 20, "train": 50}
_GIT_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9A-Za-z-]+)*\Z"
)
_SOURCE_SEALING_VERIFIED_MINT: Final[object] = object()
_SOURCE_SEALING_PARSED_MINT: Final[object] = object()

_OBJECT_HYGIENE_SUCCESS_FIELDS: Final[tuple[str, ...]] = (
    "bare_repository_count",
    "sha1_object_format_repository_count",
    "non_shallow_repository_count",
    "full_fsck_repository_count",
    "exact_ref_set_repository_count",
    "exact_object_closure_repository_count",
)
_OBJECT_HYGIENE_ZERO_FIELDS: Final[tuple[str, ...]] = (
    "garbage_file_count",
    "prune_packable_object_count",
    "unreachable_object_count",
    "extra_ref_count",
    "promisor_repository_count",
    "alternate_repository_count",
    "replace_ref_count",
)


class SourceSealingClosureError(ValueError):
    """Stable rejection for a malformed or detached source-sealing closure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code if type(code) is str and code else "invalid_contract"
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
        raise SourceSealingClosureError(
            "invalid_contract", "source-sealing value is not canonical JSON"
        ) from None


def _require_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise SourceSealingClosureError(
            "invalid_contract", f"{name} must be lower-case SHA-256"
        )
    return value


def _require_expected_sha256(value: object, *, name: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise SourceSealingClosureError(
            "invalid_argument", f"{name} must be lower-case SHA-256"
        )
    return value


def _require_id(value: object, *, name: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise SourceSealingClosureError(
            "invalid_contract", f"{name} must be a canonical path-free identifier"
        )
    return value


def _strict_object(
    value: object, *, keys: frozenset[str], name: str
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise SourceSealingClosureError(
            "invalid_contract", f"{name} has invalid exact keys"
        )
    return value


def _validate_json_shape(
    value: object,
    *,
    max_nodes: int = SOURCE_SEALING_CLOSURE_MAX_JSON_NODES,
    max_depth: int = SOURCE_SEALING_CLOSURE_MAX_JSON_DEPTH,
) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if (
            count > max_nodes
            or depth > max_depth
        ):
            raise SourceSealingClosureError(
                "limit_exceeded", "source-sealing JSON exceeds its shape limit"
            )
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) not in {str, int, bool}:
            raise SourceSealingClosureError(
                "invalid_contract", "source-sealing JSON contains an invalid value"
            )


def _parse_pinned_canonical_line(
    payload: bytes,
    *,
    expected_wire_sha256: str,
    max_wire_bytes: int = SOURCE_SEALING_CLOSURE_MAX_WIRE_BYTES,
    max_json_nodes: int = SOURCE_SEALING_CLOSURE_MAX_JSON_NODES,
    max_json_depth: int = SOURCE_SEALING_CLOSURE_MAX_JSON_DEPTH,
) -> dict[str, object]:
    if type(payload) is not bytes:
        raise SourceSealingClosureError(
            "invalid_argument", "source-sealing wire must be exact bytes"
        )
    wire_sha256 = _require_expected_sha256(
        expected_wire_sha256, name="expected_wire_sha256"
    )
    if not payload or len(payload) > max_wire_bytes:
        raise SourceSealingClosureError(
            "limit_exceeded", "source-sealing wire exceeds its byte limit"
        )
    if hashlib.sha256(payload).hexdigest() != wire_sha256:
        raise SourceSealingClosureError(
            "digest_mismatch", "source-sealing wire differs from its pin"
        )
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise SourceSealingClosureError(
            "noncanonical_json", "source-sealing wire must be one JSON line"
        )

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise SourceSealingClosureError(
                    "noncanonical_json", "source-sealing JSON repeats an object key"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            payload[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                SourceSealingClosureError(
                    "noncanonical_json",
                    "source-sealing JSON contains a non-finite number",
                )
            ),
        )
    except SourceSealingClosureError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
        raise SourceSealingClosureError(
            "noncanonical_json", "source-sealing wire is not strict JSON"
        ) from None
    _validate_json_shape(
        value,
        max_nodes=max_json_nodes,
        max_depth=max_json_depth,
    )
    if type(value) is not dict or _canonical_json(value) + b"\n" != payload:
        raise SourceSealingClosureError(
            "noncanonical_json", "source-sealing wire is not canonical"
        )
    return value


@dataclass(frozen=True, slots=True)
class SourceObjectHygieneClosureV1:
    """Path-free aggregate proof that all 22 bare repositories are clean."""

    repository_count: int
    bare_repository_count: int
    sha1_object_format_repository_count: int
    non_shallow_repository_count: int
    full_fsck_repository_count: int
    exact_ref_set_repository_count: int
    exact_object_closure_repository_count: int
    garbage_file_count: int
    prune_packable_object_count: int
    unreachable_object_count: int
    extra_ref_count: int
    promisor_repository_count: int
    alternate_repository_count: int
    replace_ref_count: int

    def __post_init__(self) -> None:
        values = self.to_dict()
        if any(type(value) is not int for value in values.values()):
            raise SourceSealingClosureError(
                "invalid_contract", "object-hygiene counters must be exact integers"
            )
        if self.repository_count != SOURCE_SEALING_REPOSITORY_COUNT:
            raise SourceSealingClosureError(
                "invalid_closure", "object hygiene must close exactly 22 repositories"
            )
        if any(
            values[name] != SOURCE_SEALING_REPOSITORY_COUNT
            for name in _OBJECT_HYGIENE_SUCCESS_FIELDS
        ):
            raise SourceSealingClosureError(
                "invalid_closure", "every repository must pass every hygiene check"
            )
        if any(values[name] != 0 for name in _OBJECT_HYGIENE_ZERO_FIELDS):
            raise SourceSealingClosureError(
                "invalid_closure", "object hygiene must contain no residue"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "alternate_repository_count": self.alternate_repository_count,
            "bare_repository_count": self.bare_repository_count,
            "exact_object_closure_repository_count": (
                self.exact_object_closure_repository_count
            ),
            "exact_ref_set_repository_count": self.exact_ref_set_repository_count,
            "extra_ref_count": self.extra_ref_count,
            "full_fsck_repository_count": self.full_fsck_repository_count,
            "garbage_file_count": self.garbage_file_count,
            "non_shallow_repository_count": self.non_shallow_repository_count,
            "promisor_repository_count": self.promisor_repository_count,
            "prune_packable_object_count": self.prune_packable_object_count,
            "replace_ref_count": self.replace_ref_count,
            "repository_count": self.repository_count,
            "sha1_object_format_repository_count": (
                self.sha1_object_format_repository_count
            ),
            "unreachable_object_count": self.unreachable_object_count,
        }

    @classmethod
    def from_dict(cls, value: object) -> "SourceObjectHygieneClosureV1":
        keys = frozenset(
            {
                "repository_count",
                *_OBJECT_HYGIENE_SUCCESS_FIELDS,
                *_OBJECT_HYGIENE_ZERO_FIELDS,
            }
        )
        raw = _strict_object(value, keys=keys, name="object-hygiene closure")
        return cls(**raw)  # type: ignore[arg-type]


def _freeze_hygiene(value: object) -> SourceObjectHygieneClosureV1:
    if type(value) is not SourceObjectHygieneClosureV1:
        raise SourceSealingClosureError(
            "invalid_argument", "object hygiene must have an exact contract type"
        )
    return SourceObjectHygieneClosureV1.from_dict(value.to_dict())


@dataclass(frozen=True, slots=True)
class SourceAcquisitionClosureV1:
    """Combined acquisition report pin plus exact readiness/hygiene closure."""

    acquisition_report_sha256: str
    repository_count: int
    task_count: int
    ready: bool
    ready_task_count: int
    blocked_task_count: int
    object_hygiene: SourceObjectHygieneClosureV1

    def __post_init__(self) -> None:
        _require_sha256(
            self.acquisition_report_sha256, name="acquisition_report_sha256"
        )
        if (
            type(self.repository_count) is not int
            or self.repository_count != SOURCE_SEALING_REPOSITORY_COUNT
            or type(self.task_count) is not int
            or self.task_count != SOURCE_SEALING_TASK_COUNT
            or type(self.ready) is not bool
            or self.ready is not True
            or type(self.ready_task_count) is not int
            or self.ready_task_count != SOURCE_SEALING_TASK_COUNT
            or type(self.blocked_task_count) is not int
            or self.blocked_task_count != 0
        ):
            raise SourceSealingClosureError(
                "invalid_closure", "source acquisition does not close 22/70 ready"
            )
        hygiene = _freeze_hygiene(self.object_hygiene)
        if hygiene.repository_count != self.repository_count:
            raise SourceSealingClosureError(
                "invalid_binding", "object hygiene is detached from acquisition"
            )
        object.__setattr__(self, "object_hygiene", hygiene)

    def to_dict(self) -> dict[str, object]:
        return {
            "acquisition_report_sha256": self.acquisition_report_sha256,
            "blocked_task_count": self.blocked_task_count,
            "object_hygiene": self.object_hygiene.to_dict(),
            "ready": self.ready,
            "ready_task_count": self.ready_task_count,
            "repository_count": self.repository_count,
            "task_count": self.task_count,
        }

    @classmethod
    def from_dict(cls, value: object) -> "SourceAcquisitionClosureV1":
        raw = _strict_object(
            value,
            keys=frozenset(
                {
                    "acquisition_report_sha256",
                    "blocked_task_count",
                    "object_hygiene",
                    "ready",
                    "ready_task_count",
                    "repository_count",
                    "task_count",
                }
            ),
            name="source-acquisition closure",
        )
        return cls(
            acquisition_report_sha256=raw[
                "acquisition_report_sha256"
            ],  # type: ignore[arg-type]
            repository_count=raw["repository_count"],  # type: ignore[arg-type]
            task_count=raw["task_count"],  # type: ignore[arg-type]
            ready=raw["ready"],  # type: ignore[arg-type]
            ready_task_count=raw["ready_task_count"],  # type: ignore[arg-type]
            blocked_task_count=raw["blocked_task_count"],  # type: ignore[arg-type]
            object_hygiene=SourceObjectHygieneClosureV1.from_dict(
                raw["object_hygiene"]
            ),
        )


def _freeze_acquisition(value: object) -> SourceAcquisitionClosureV1:
    if type(value) is not SourceAcquisitionClosureV1:
        raise SourceSealingClosureError(
            "invalid_argument", "acquisition must have an exact contract type"
        )
    return SourceAcquisitionClosureV1.from_dict(value.to_dict())


@dataclass(frozen=True, slots=True)
class _AcquisitionSplitPinV5:
    split: Literal["test", "train"]
    task_count: int
    task_export_sha256: str
    source_map_sha256: str
    task_source_facts: tuple[tuple[str, str, str, str, int], ...]


@dataclass(frozen=True, slots=True)
class _AcquisitionReportClosureV5:
    acquisition: SourceAcquisitionClosureV1
    split_pins: tuple[_AcquisitionSplitPinV5, _AcquisitionSplitPinV5]

    def split_pin(self, split: Literal["test", "train"]) -> _AcquisitionSplitPinV5:
        for pin in self.split_pins:
            if pin.split == split:
                return pin
        raise SourceSealingClosureError(
            "invalid_closure", "acquisition report omits a fixed split"
        )


def _parse_ready_commit_v4(value: object) -> str:
    raw = _strict_object(
        value,
        keys=frozenset(
            {
                "commit",
                "gitlink_count",
                "lfs_pointer_count",
                "lfs_scan_complete",
                "mode_counts",
                "oversized_blob_count",
                "policy",
                "ready",
                "regular_file_count",
                "root_tree",
                "scan_complete",
                "status_codes",
                "symlink_count",
                "total_regular_bytes",
                "tree_count",
                "tree_entry_count",
                "unsupported_entry_count",
            }
        ),
        name="source-acquisition commit audit",
    )
    if (
        type(raw["commit"]) is not str
        or _SHA1_RE.fullmatch(raw["commit"]) is None  # type: ignore[arg-type]
        or type(raw["root_tree"]) is not str
        or _SHA1_RE.fullmatch(raw["root_tree"]) is None  # type: ignore[arg-type]
        or raw["ready"] is not True
        or raw["scan_complete"] is not True
        or raw["lfs_scan_complete"] is not True
        or type(raw["status_codes"]) is not list
        or raw["status_codes"] != []
        or raw["policy"] != DEFAULT_SNAPSHOT_POLICY.to_dict()
    ):
        raise SourceSealingClosureError(
            "invalid_closure", "source-acquisition commit is not fully ready"
        )
    counter_names = (
        "gitlink_count",
        "lfs_pointer_count",
        "oversized_blob_count",
        "regular_file_count",
        "symlink_count",
        "total_regular_bytes",
        "tree_count",
        "tree_entry_count",
        "unsupported_entry_count",
    )
    if any(
        type(raw[name]) is not int or raw[name] < 0  # type: ignore[operator]
        for name in counter_names
    ):
        raise SourceSealingClosureError(
            "invalid_contract", "source-acquisition commit counters are invalid"
        )
    modes = raw["mode_counts"]
    allowed_modes = frozenset({"100644", "100755", "120000", "160000", "40000"})
    if (
        type(modes) is not dict
        or any(
            type(mode) is not str
            or mode not in allowed_modes
            or type(count) is not int
            or count < 1
            for mode, count in modes.items()
        )
        or sum(modes.values()) != raw["tree_entry_count"]
    ):
        raise SourceSealingClosureError(
            "invalid_contract", "source-acquisition commit mode counts are invalid"
        )
    regular_mode_count = sum(
        modes.get(mode, 0) for mode in ("100644", "100755", "120000")
    )
    if (
        raw["lfs_pointer_count"] != 0
        or raw["oversized_blob_count"] != 0
        or raw["unsupported_entry_count"] != 0
        or raw["regular_file_count"] < 1
        or raw["tree_entry_count"] > DEFAULT_SNAPSHOT_POLICY.max_files
        or raw["total_regular_bytes"] > DEFAULT_SNAPSHOT_POLICY.max_total_bytes
        or raw["tree_count"] != modes.get("40000", 0)
        or raw["symlink_count"] != modes.get("120000", 0)
        or raw["gitlink_count"] != modes.get("160000", 0)
        or raw["regular_file_count"] != regular_mode_count
        or raw["tree_entry_count"]
        != raw["tree_count"] + raw["regular_file_count"] + raw["gitlink_count"]
    ):
        raise SourceSealingClosureError(
            "invalid_closure",
            "source-acquisition ready commit facts are contradictory",
        )
    return raw["commit"]  # type: ignore[return-value]


def _parse_repository_hygiene_v4(
    value: object,
    *,
    commit_count: int,
) -> tuple[dict[str, object], bool]:
    raw = _strict_object(
        value,
        keys=frozenset(
            {
                "all_objects_reachable",
                "alternates_absent",
                "bare_repository",
                "full_fsck",
                "garbage_count",
                "garbage_size_kib",
                "loose_object_count",
                "loose_object_size_kib",
                "multi_pack_index_present",
                "multi_pack_index_verified",
                "non_shallow",
                "observed_ref_count",
                "pack_count",
                "pack_size_kib",
                "packed_object_count",
                "promisor_absent",
                "prune_packable_count",
                "ref_inventory_sha256",
                "refs_closed",
                "replace_refs_absent",
                "required_ref_count",
                "sha1_object_format",
                "storage_inventory_sha256",
                "storage_object_entry_count",
                "storage_object_total_bytes",
                "stored_object_count",
                "unreachable_object_count",
            }
        ),
        name="source-acquisition object hygiene",
    )
    boolean_names = (
        "all_objects_reachable",
        "alternates_absent",
        "bare_repository",
        "full_fsck",
        "multi_pack_index_present",
        "multi_pack_index_verified",
        "non_shallow",
        "promisor_absent",
        "refs_closed",
        "replace_refs_absent",
        "sha1_object_format",
    )
    if any(type(raw[name]) is not bool for name in boolean_names):
        raise SourceSealingClosureError(
            "invalid_contract", "object-hygiene facts must be exact booleans"
        )
    counter_names = (
        "garbage_count",
        "garbage_size_kib",
        "loose_object_count",
        "loose_object_size_kib",
        "observed_ref_count",
        "pack_count",
        "pack_size_kib",
        "packed_object_count",
        "prune_packable_count",
        "required_ref_count",
        "storage_object_entry_count",
        "storage_object_total_bytes",
        "stored_object_count",
        "unreachable_object_count",
    )
    if any(
        type(raw[name]) is not int or raw[name] < 0  # type: ignore[operator]
        for name in counter_names
    ):
        raise SourceSealingClosureError(
            "invalid_contract", "object-hygiene counters are invalid"
        )
    _require_sha256(raw["ref_inventory_sha256"], name="ref_inventory_sha256")
    _require_sha256(
        raw["storage_inventory_sha256"], name="storage_inventory_sha256"
    )
    if (
        commit_count < 1
        or raw["required_ref_count"] != commit_count
        or raw["observed_ref_count"] != commit_count
        or raw["stored_object_count"]
        != raw["loose_object_count"] + raw["packed_object_count"]
        or raw["stored_object_count"] < 1
        or raw["pack_count"] < 1
        or raw["packed_object_count"] < 1
        or raw["storage_object_entry_count"] < 1
        or raw["storage_object_total_bytes"] < 1
    ):
        raise SourceSealingClosureError(
            "invalid_binding", "object hygiene is detached from repository commits"
        )
    if any(raw[name] is not True for name in boolean_names) or any(
        raw[name] != 0
        for name in (
            "garbage_count",
            "garbage_size_kib",
            "prune_packable_count",
            "unreachable_object_count",
        )
    ):
        raise SourceSealingClosureError(
            "invalid_closure", "repository object hygiene is not fully closed"
        )
    return raw, True


def _parse_acquisition_report_v5(
    payload: bytes,
    *,
    expected_acquisition_report_sha256: str,
) -> _AcquisitionReportClosureV5:
    report_sha256 = _require_expected_sha256(
        expected_acquisition_report_sha256,
        name="expected_acquisition_report_sha256",
    )
    raw = _strict_object(
        _parse_pinned_canonical_line(
            payload,
            expected_wire_sha256=report_sha256,
            max_wire_bytes=SOURCE_SEALING_ACQUISITION_REPORT_MAX_WIRE_BYTES,
            max_json_nodes=SOURCE_SEALING_ACQUISITION_REPORT_MAX_JSON_NODES,
            max_json_depth=SOURCE_SEALING_ACQUISITION_REPORT_MAX_JSON_DEPTH,
        ),
        keys=frozenset(
            {
                "blocked_task_count",
                "contract_version",
                "exports",
                "fetch_protocol",
                "github_transport",
                "git_version",
                "kind",
                "profile_id",
                "public_manifest_sha256",
                "ready",
                "ready_task_count",
                "repositories",
                "repository_count",
                "task_count",
            }
        ),
        name="source-acquisition report v5",
    )
    if (
        raw["contract_version"] != SOURCE_ACQUISITION_CONTRACT_VERSION
        or raw["kind"] != "source_acquisition_report"
        or raw["profile_id"] != PROFILE_ID
        or raw["public_manifest_sha256"] != PROFILE_MANIFEST_SHA256
        or raw["github_transport"] not in {"https", "ssh"}
        or type(raw["git_version"]) is not str
        or _GIT_VERSION_RE.fullmatch(raw["git_version"]) is None  # type: ignore[arg-type]
    ):
        raise SourceSealingClosureError(
            "invalid_contract", "source-acquisition report header is invalid"
        )
    expected_protocol = {
        "deepen_by": 32,
        "initial_depth": 32,
        "max_deepen_rounds": 2_048,
        "max_total_network_seconds": 21_600,
        "max_transient_fetch_retries_per_repository": 1,
        "requires_exact_ref_closure": True,
        "requires_final_full_fsck": True,
        "requires_final_non_shallow": True,
        "requires_final_verified_multi_pack_index": True,
        "requires_strict_git_output": True,
        "requires_zero_garbage": True,
        "requires_zero_prune_packable": True,
        "requires_zero_unreachable_objects": True,
        "retry_requires_unchanged_repository_seal": True,
        "writes_verified_multi_pack_index": True,
    }
    if raw["fetch_protocol"] != expected_protocol:
        raise SourceSealingClosureError(
            "invalid_contract", "source-acquisition fetch protocol is invalid"
        )
    exports = raw["exports"]
    if type(exports) is not list or len(exports) != 2:
        raise SourceSealingClosureError(
            "invalid_closure", "source-acquisition report requires two exports"
        )
    split_pins: list[_AcquisitionSplitPinV5] = []
    for expected_split, export_value in zip(("test", "train"), exports):
        export = _strict_object(
            export_value,
            keys=frozenset(
                {
                    "source_map_sha256",
                    "split",
                    "task_count",
                    "task_source_facts",
                    "tasks_sha256",
                }
            ),
            name="source-acquisition export",
        )
        if (
            export["split"] != expected_split
            or type(export["task_count"]) is not int
            or export["task_count"] != _SPLIT_COUNTS[expected_split]
        ):
            raise SourceSealingClosureError(
                "invalid_closure", "source-acquisition export split/count is invalid"
            )
        task_source_facts_value = export["task_source_facts"]
        if type(task_source_facts_value) is not list or len(task_source_facts_value) != export["task_count"]:
            raise SourceSealingClosureError("invalid_closure", "task source facts are incomplete")
        task_source_facts: list[tuple[str, str, str, str, int]] = []
        for fact_value in task_source_facts_value:
            fact = _strict_object(fact_value, keys=frozenset({"task_id", "repo_url", "commit", "root_tree", "gitlink_count"}), name="task source fact")
            try:
                task = BenchmarkTask(task_id=fact["task_id"], repo_url=fact["repo_url"], commit=fact["commit"], split=expected_split)
            except (BenchmarkContractError, TypeError, ValueError) as error:
                raise SourceSealingClosureError("invalid_contract", "task source identity is invalid") from error
            if (type(fact["root_tree"]) is not str or _SHA1_RE.fullmatch(fact["root_tree"]) is None
                or type(fact["gitlink_count"]) is not int or fact["gitlink_count"] < 0):
                raise SourceSealingClosureError("invalid_contract", "task source fact is invalid")
            task_source_facts.append((task.task_id, task.repo_url, task.commit, fact["root_tree"], fact["gitlink_count"]))
        if tuple(task_source_facts) != tuple(sorted(task_source_facts)) or len({item[0] for item in task_source_facts}) != len(task_source_facts):
            raise SourceSealingClosureError("invalid_contract", "task source facts are not canonical")
        split_pins.append(
            _AcquisitionSplitPinV5(
                split=expected_split,  # type: ignore[arg-type]
                task_count=export["task_count"],  # type: ignore[arg-type]
                task_export_sha256=_require_sha256(
                    export["tasks_sha256"], name="tasks_sha256"
                ),
                source_map_sha256=_require_sha256(
                    export["source_map_sha256"], name="source_map_sha256"
                ),
                task_source_facts=tuple(task_source_facts),
            )
        )
    repositories = raw["repositories"]
    if type(repositories) is not list or len(repositories) != 22:
        raise SourceSealingClosureError(
            "invalid_closure", "source-acquisition report requires 22 repositories"
        )
    repository_urls: list[str] = []
    audit_source_facts: dict[tuple[str, str], tuple[str, int]] = {}
    commit_total = 0
    success_counts = {name: 0 for name in _OBJECT_HYGIENE_SUCCESS_FIELDS}
    residue_counts = {name: 0 for name in _OBJECT_HYGIENE_ZERO_FIELDS}
    for repository_value in repositories:
        repository = _strict_object(
            repository_value,
            keys=frozenset({"commits", "object_hygiene", "repo_url"}),
            name="source-acquisition repository",
        )
        commits_value = repository["commits"]
        if type(commits_value) is not list or not commits_value:
            raise SourceSealingClosureError(
                "invalid_closure", "each source repository requires commits"
            )
        commits = tuple(_parse_ready_commit_v4(item) for item in commits_value)
        if tuple(sorted(commits)) != commits or len(set(commits)) != len(commits):
            raise SourceSealingClosureError(
                "invalid_contract", "repository commits are not canonical"
            )
        repo_url = repository["repo_url"]
        try:
            BenchmarkTask(
                task_id="VG-TEST-00000000000000000000",
                repo_url=repo_url,  # type: ignore[arg-type]
                commit=commits[0],
                split="test",
            )
        except BenchmarkContractError as error:
            raise SourceSealingClosureError(
                "invalid_contract", "repository URL is not canonical"
            ) from error
        repository_urls.append(repo_url)  # type: ignore[arg-type]
        for commit_value in commits_value:
            assert type(commit_value) is dict
            identity = (repo_url, commit_value["commit"])
            fact = (commit_value["root_tree"], commit_value["gitlink_count"])
            if identity in audit_source_facts and audit_source_facts[identity] != fact:
                raise SourceSealingClosureError(
                    "invalid_binding", "repository audit source identity is contradictory"
                )
            audit_source_facts[identity] = fact  # type: ignore[index]
        hygiene, exact_object_closure = _parse_repository_hygiene_v4(
            repository["object_hygiene"], commit_count=len(commits)
        )
        success_counts["bare_repository_count"] += int(
            hygiene["bare_repository"] is True
        )
        success_counts["sha1_object_format_repository_count"] += int(
            hygiene["sha1_object_format"] is True
        )
        success_counts["non_shallow_repository_count"] += int(
            hygiene["non_shallow"] is True
        )
        success_counts["full_fsck_repository_count"] += int(
            hygiene["full_fsck"] is True
        )
        success_counts["exact_ref_set_repository_count"] += int(
            hygiene["refs_closed"] is True
            and hygiene["observed_ref_count"] == hygiene["required_ref_count"]
        )
        success_counts["exact_object_closure_repository_count"] += int(
            exact_object_closure
        )
        residue_counts["garbage_file_count"] += hygiene["garbage_count"]  # type: ignore[operator]
        residue_counts["prune_packable_object_count"] += hygiene[
            "prune_packable_count"
        ]  # type: ignore[operator]
        residue_counts["unreachable_object_count"] += hygiene[
            "unreachable_object_count"
        ]  # type: ignore[operator]
        residue_counts["extra_ref_count"] += max(
            0,
            hygiene["observed_ref_count"]  # type: ignore[operator]
            - hygiene["required_ref_count"],  # type: ignore[operator]
        )
        residue_counts["promisor_repository_count"] += int(
            hygiene["promisor_absent"] is not True
        )
        residue_counts["alternate_repository_count"] += int(
            hygiene["alternates_absent"] is not True
        )
        residue_counts["replace_ref_count"] += int(
            hygiene["replace_refs_absent"] is not True
        )
        commit_total += len(commits)
    if (
        repository_urls != sorted(repository_urls, key=lambda value: value.encode("utf-8"))
        or len(set(repository_urls)) != len(repository_urls)
    ):
        raise SourceSealingClosureError(
            "invalid_contract", "source repositories are not canonical and unique"
        )
    if (
        type(raw["repository_count"]) is not int
        or raw["repository_count"] != len(repositories)
        or type(raw["task_count"]) is not int
        or raw["task_count"] != SOURCE_SEALING_TASK_COUNT
        or commit_total != SOURCE_SEALING_TASK_COUNT
        or sum(pin.task_count for pin in split_pins) != SOURCE_SEALING_TASK_COUNT
        or raw["ready"] is not True
        or type(raw["ready_task_count"]) is not int
        or raw["ready_task_count"] != SOURCE_SEALING_TASK_COUNT
        or type(raw["blocked_task_count"]) is not int
        or raw["blocked_task_count"] != 0
    ):
        raise SourceSealingClosureError(
            "invalid_closure", "source-acquisition report does not close 22/70 ready"
        )
    for pin in split_pins:
        for _, repo_url, commit, root_tree, gitlink_count in pin.task_source_facts:
            if audit_source_facts.get((repo_url, commit)) != (root_tree, gitlink_count):
                raise SourceSealingClosureError(
                    "invalid_binding", "task source fact is detached from repository audit"
                )
    exported_source_identities = tuple(
        (repo_url, commit)
        for pin in split_pins
        for _, repo_url, commit, _, _ in pin.task_source_facts
    )
    if (
        len(set(exported_source_identities)) != SOURCE_SEALING_TASK_COUNT
        or set(exported_source_identities) != set(audit_source_facts)
    ):
        raise SourceSealingClosureError(
            "invalid_binding",
            "task source identities do not exactly close the repository audit",
        )
    hygiene_closure = SourceObjectHygieneClosureV1(
        repository_count=len(repositories),
        **success_counts,
        **residue_counts,
    )
    return _AcquisitionReportClosureV5(
        acquisition=SourceAcquisitionClosureV1(
            acquisition_report_sha256=report_sha256,
            repository_count=len(repositories),
            task_count=SOURCE_SEALING_TASK_COUNT,
            ready=True,
            ready_task_count=SOURCE_SEALING_TASK_COUNT,
            blocked_task_count=0,
            object_hygiene=hygiene_closure,
        ),
        split_pins=(split_pins[0], split_pins[1]),
    )


@dataclass(frozen=True, slots=True)
class SourceSealingVerifyRoundV1:
    """One trusted re-verification run and its path-free semantic pins."""

    run_id: str
    evidence_semantic_sha256: str
    summary_wire_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(self.run_id, name="run_id")
        _require_sha256(
            self.evidence_semantic_sha256, name="evidence_semantic_sha256"
        )
        _require_sha256(self.summary_wire_sha256, name="summary_wire_sha256")

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_semantic_sha256": self.evidence_semantic_sha256,
            "run_id": self.run_id,
            "summary_wire_sha256": self.summary_wire_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> "SourceSealingVerifyRoundV1":
        raw = _strict_object(
            value,
            keys=frozenset(
                {"evidence_semantic_sha256", "run_id", "summary_wire_sha256"}
            ),
            name="source-sealing verify round",
        )
        return cls(
            run_id=raw["run_id"],  # type: ignore[arg-type]
            evidence_semantic_sha256=raw[
                "evidence_semantic_sha256"
            ],  # type: ignore[arg-type]
            summary_wire_sha256=raw["summary_wire_sha256"],  # type: ignore[arg-type]
        )


def _freeze_round(value: object) -> SourceSealingVerifyRoundV1:
    if type(value) is not SourceSealingVerifyRoundV1:
        raise SourceSealingClosureError(
            "invalid_argument", "verify round must have an exact contract type"
        )
    return SourceSealingVerifyRoundV1.from_dict(value.to_dict())


@dataclass(frozen=True, slots=True)
class SourceSealingSplitClosureV2:
    """Fixed split pins and exactly two content-identical verification runs."""

    split: Literal["test", "train"]
    task_count: int
    task_export_sha256: str
    source_map_sha256: str
    sealed_manifest_sha256: str
    batch_content_root: str
    key_id: str
    key_equality_tag_sha256: str
    output_identity_sha256: str
    task_records_sha256: str
    task_closure_sha256: str
    entry_count: int
    regular_file_count: int
    gitlink_count: int
    regular_file_bytes: int
    materialized_bytes: int
    verify_rounds: tuple[
        SourceSealingVerifyRoundV1, SourceSealingVerifyRoundV1
    ]

    def __post_init__(self) -> None:
        expected_count = (
            _SPLIT_COUNTS.get(self.split) if type(self.split) is str else None
        )
        if (
            expected_count is None
            or type(self.task_count) is not int
            or self.task_count != expected_count
        ):
            raise SourceSealingClosureError(
                "invalid_closure", "source-sealing split/count is invalid"
            )
        for value, name in (
            (self.task_export_sha256, "task_export_sha256"),
            (self.source_map_sha256, "source_map_sha256"),
            (self.sealed_manifest_sha256, "sealed_manifest_sha256"),
            (self.batch_content_root, "batch_content_root"),
            (self.key_equality_tag_sha256, "key_equality_tag_sha256"),
            (self.output_identity_sha256, "output_identity_sha256"),
            (self.task_records_sha256, "task_records_sha256"),
            (self.task_closure_sha256, "task_closure_sha256"),
        ):
            _require_sha256(value, name=name)
        counters = (
            self.entry_count, self.regular_file_count, self.gitlink_count,
            self.regular_file_bytes, self.materialized_bytes,
        )
        if any(type(value) is not int or value < 0 for value in counters):
            raise SourceSealingClosureError("invalid_contract", "split aggregate counters are invalid")
        if (self.entry_count != self.regular_file_count + self.gitlink_count
            or self.materialized_bytes != self.regular_file_bytes + 49 * self.gitlink_count):
            raise SourceSealingClosureError("invalid_closure", "split aggregate counters do not close")
        _require_id(self.key_id, name="key_id")
        if (
            type(self.verify_rounds) is not tuple
            or len(self.verify_rounds) != SOURCE_SEALING_VERIFY_ROUNDS_PER_SPLIT
        ):
            raise SourceSealingClosureError(
                "invalid_closure", "each split requires exactly two verify rounds"
            )
        rounds = tuple(_freeze_round(item) for item in self.verify_rounds)
        if rounds[0].run_id == rounds[1].run_id:
            raise SourceSealingClosureError(
                "invalid_binding", "verify run_id values must be distinct"
            )
        if (
            rounds[0].summary_wire_sha256 != rounds[1].summary_wire_sha256
            or rounds[0].evidence_semantic_sha256
            != rounds[1].evidence_semantic_sha256
        ):
            raise SourceSealingClosureError(
                "invalid_binding", "verify evidence semantics must be identical"
            )
        object.__setattr__(self, "verify_rounds", rounds)

    def to_dict(self) -> dict[str, object]:
        return {
            "batch_content_root": self.batch_content_root,
            "key_equality_tag_sha256": self.key_equality_tag_sha256,
            "key_id": self.key_id,
            "output_identity_sha256": self.output_identity_sha256,
            "sealed_manifest_sha256": self.sealed_manifest_sha256,
            "source_map_sha256": self.source_map_sha256,
            "split": self.split,
            "task_count": self.task_count,
            "task_export_sha256": self.task_export_sha256,
            "task_records_sha256": self.task_records_sha256,
            "task_closure_sha256": self.task_closure_sha256,
            "entry_count": self.entry_count,
            "regular_file_count": self.regular_file_count,
            "gitlink_count": self.gitlink_count,
            "regular_file_bytes": self.regular_file_bytes,
            "materialized_bytes": self.materialized_bytes,
            "verify_rounds": [item.to_dict() for item in self.verify_rounds],
        }

    @classmethod
    def from_dict(cls, value: object) -> "SourceSealingSplitClosureV2":
        raw = _strict_object(
            value,
            keys=frozenset(
                {
                    "batch_content_root",
                    "key_equality_tag_sha256",
                    "key_id",
                    "output_identity_sha256",
                    "sealed_manifest_sha256",
                    "source_map_sha256",
                    "split",
                    "task_count",
                    "task_export_sha256",
                    "task_records_sha256",
                    "task_closure_sha256",
                    "entry_count",
                    "regular_file_count",
                    "gitlink_count",
                    "regular_file_bytes",
                    "materialized_bytes",
                    "verify_rounds",
                }
            ),
            name="source-sealing split closure",
        )
        raw_rounds = raw["verify_rounds"]
        if type(raw_rounds) is not list or len(raw_rounds) != 2:
            raise SourceSealingClosureError(
                "invalid_contract", "verify_rounds must be an exact two-item array"
            )
        return cls(
            split=raw["split"],  # type: ignore[arg-type]
            task_count=raw["task_count"],  # type: ignore[arg-type]
            task_export_sha256=raw["task_export_sha256"],  # type: ignore[arg-type]
            source_map_sha256=raw["source_map_sha256"],  # type: ignore[arg-type]
            sealed_manifest_sha256=raw[
                "sealed_manifest_sha256"
            ],  # type: ignore[arg-type]
            batch_content_root=raw["batch_content_root"],  # type: ignore[arg-type]
            key_id=raw["key_id"],  # type: ignore[arg-type]
            key_equality_tag_sha256=raw[
                "key_equality_tag_sha256"
            ],  # type: ignore[arg-type]
            output_identity_sha256=raw[
                "output_identity_sha256"
            ],  # type: ignore[arg-type]
            task_records_sha256=raw[
                "task_records_sha256"
            ],  # type: ignore[arg-type]
            task_closure_sha256=raw["task_closure_sha256"],  # type: ignore[arg-type]
            entry_count=raw["entry_count"],  # type: ignore[arg-type]
            regular_file_count=raw["regular_file_count"],  # type: ignore[arg-type]
            gitlink_count=raw["gitlink_count"],  # type: ignore[arg-type]
            regular_file_bytes=raw["regular_file_bytes"],  # type: ignore[arg-type]
            materialized_bytes=raw["materialized_bytes"],  # type: ignore[arg-type]
            verify_rounds=(
                SourceSealingVerifyRoundV1.from_dict(raw_rounds[0]),
                SourceSealingVerifyRoundV1.from_dict(raw_rounds[1]),
            ),
        )


def _freeze_split(value: object) -> SourceSealingSplitClosureV2:
    if type(value) is not SourceSealingSplitClosureV2:
        raise SourceSealingClosureError(
            "invalid_argument", "split closure must have an exact contract type"
        )
    return SourceSealingSplitClosureV2.from_dict(value.to_dict())


def _split_from_evidence(
    *,
    split: Literal["test", "train"],
    acquisition_pin: _AcquisitionSplitPinV5,
    evidence: tuple[
        SnapshotBatchVerificationEvidenceV2,
        SnapshotBatchVerificationEvidenceV2,
    ],
) -> SourceSealingSplitClosureV2:
    if (
        type(acquisition_pin) is not _AcquisitionSplitPinV5
        or acquisition_pin.split != split
        or acquisition_pin.task_count != _SPLIT_COUNTS[split]
    ):
        raise SourceSealingClosureError(
            "invalid_binding", "acquisition pin is detached from its fixed split"
        )
    if type(evidence) is not tuple or len(evidence) != 2 or any(
        type(item) is not SnapshotBatchVerificationEvidenceV2 for item in evidence
    ):
        raise SourceSealingClosureError(
            "invalid_argument", "each split requires two trusted evidence values"
        )
    for item in evidence:
        try:
            item.to_dict()
        except SnapshotBatchError as error:
            raise SourceSealingClosureError(
                "invalid_argument",
                "verification evidence has an invalid semantic contract",
            ) from error
        summary = item.summary
        if (
            summary.split != split
            or summary.task_count != acquisition_pin.task_count
            or summary.profile_id != PROFILE_ID
            or summary.public_manifest_sha256 != PROFILE_MANIFEST_SHA256
            or summary.tasks_sha256 != acquisition_pin.task_export_sha256
            or summary.source_map_sha256 != acquisition_pin.source_map_sha256
        ):
            raise SourceSealingClosureError(
                "invalid_binding", "verification evidence is detached from acquisition"
            )
        observed_source_facts = tuple(
            sorted((task.task_id, task.repo_url, task.commit, task.root_tree, task.gitlink_count) for task in summary.tasks)
        )
        if observed_source_facts != acquisition_pin.task_source_facts:
            raise SourceSealingClosureError(
                "invalid_binding", "snapshot task source facts are detached from acquisition"
            )
    if (
        evidence[0].run_id == evidence[1].run_id
        or evidence[0].semantic_sha256 != evidence[1].semantic_sha256
        or evidence[0].summary_wire_sha256 != evidence[1].summary_wire_sha256
        or evidence[0].task_records_sha256 != evidence[1].task_records_sha256
        or evidence[0].key_equality_tag_sha256
        != evidence[1].key_equality_tag_sha256
        or evidence[0].output_identity_sha256
        != evidence[1].output_identity_sha256
        or evidence[0].summary.to_dict() != evidence[1].summary.to_dict()
        or evidence[0].summary.batch_root != evidence[1].summary.batch_root
    ):
        raise SourceSealingClosureError(
            "invalid_binding", "independent verification evidence does not agree"
        )
    summary = evidence[0].summary
    task_closure_records = [
        {
            "task_id": task.task_id, "repo_url": task.repo_url, "commit": task.commit,
            "root_tree": task.root_tree,
            "snapshot_manifest_sha256": task.snapshot_manifest_sha256,
            "snapshot_content_root": task.snapshot_content_root,
            "entry_count": task.entry_count, "regular_file_count": task.regular_file_count,
            "gitlink_count": task.gitlink_count, "regular_file_bytes": task.regular_file_bytes,
            "materialized_bytes": task.materialized_bytes,
        }
        for task in summary.tasks
    ]
    task_closure_sha256 = hashlib.sha256(
        SOURCE_SEALING_TASK_CLOSURE_DOMAIN
        + _canonical_json({"split": split, "tasks": task_closure_records})
    ).hexdigest()
    return SourceSealingSplitClosureV2(
        split=split,
        task_count=summary.task_count,
        task_export_sha256=summary.tasks_sha256,
        source_map_sha256=summary.source_map_sha256,
        sealed_manifest_sha256=summary.manifest_sha256,
        batch_content_root=summary.batch_content_root,
        key_id=summary.key_id,
        key_equality_tag_sha256=evidence[0].key_equality_tag_sha256,
        output_identity_sha256=evidence[0].output_identity_sha256,
        task_records_sha256=evidence[0].task_records_sha256,
        task_closure_sha256=task_closure_sha256,
        entry_count=sum(task.entry_count for task in summary.tasks),
        regular_file_count=sum(task.regular_file_count for task in summary.tasks),
        gitlink_count=sum(task.gitlink_count for task in summary.tasks),
        regular_file_bytes=sum(task.regular_file_bytes for task in summary.tasks),
        materialized_bytes=sum(task.materialized_bytes for task in summary.tasks),
        verify_rounds=(
            SourceSealingVerifyRoundV1(
                run_id=evidence[0].run_id,
                evidence_semantic_sha256=evidence[0].semantic_sha256,
                summary_wire_sha256=evidence[0].summary_wire_sha256,
            ),
            SourceSealingVerifyRoundV1(
                run_id=evidence[1].run_id,
                evidence_semantic_sha256=evidence[1].semantic_sha256,
                summary_wire_sha256=evidence[1].summary_wire_sha256,
            ),
        ),
    )


@dataclass(frozen=True, slots=True)
class SourceSealingClosureReceiptV2:
    """Exact source-acquisition and two-split sealed-snapshot closure."""

    implementation_commit: str
    acquisition: SourceAcquisitionClosureV1
    test: SourceSealingSplitClosureV2
    train: SourceSealingSplitClosureV2
    _mint: InitVar[object | None] = None
    profile_id: str = PROFILE_ID
    public_manifest_sha256: str = PROFILE_MANIFEST_SHA256
    status: str = SOURCE_SEALING_CLOSURE_STATUS
    contract_version: int = SOURCE_SEALING_CLOSURE_CONTRACT_VERSION
    kind: str = SOURCE_SEALING_CLOSURE_KIND
    receipt_sha256: str = field(init=False)

    def __post_init__(self, _mint: object | None) -> None:
        if (
            _mint is not _SOURCE_SEALING_VERIFIED_MINT
            and _mint is not _SOURCE_SEALING_PARSED_MINT
        ):
            raise SourceSealingClosureError(
                "untrusted_receipt",
                "source-sealing receipt requires trusted evidence or external pins",
            )
        if (
            type(self.implementation_commit) is not str
            or _SHA1_RE.fullmatch(self.implementation_commit) is None
            or type(self.profile_id) is not str
            or self.profile_id != PROFILE_ID
            or type(self.public_manifest_sha256) is not str
            or self.public_manifest_sha256 != PROFILE_MANIFEST_SHA256
            or type(self.status) is not str
            or self.status != SOURCE_SEALING_CLOSURE_STATUS
            or type(self.contract_version) is not int
            or self.contract_version != SOURCE_SEALING_CLOSURE_CONTRACT_VERSION
            or type(self.kind) is not str
            or self.kind != SOURCE_SEALING_CLOSURE_KIND
        ):
            raise SourceSealingClosureError(
                "invalid_contract", "source-sealing receipt header is invalid"
            )
        acquisition = _freeze_acquisition(self.acquisition)
        test = _freeze_split(self.test)
        train = _freeze_split(self.train)
        if test.split != "test" or train.split != "train":
            raise SourceSealingClosureError(
                "invalid_binding", "source-sealing split union is invalid"
            )
        if test.task_count + train.task_count != acquisition.task_count:
            raise SourceSealingClosureError(
                "invalid_binding", "split task counts do not close acquisition"
            )
        run_ids = tuple(
            item.run_id for split in (test, train) for item in split.verify_rounds
        )
        if len(set(run_ids)) != len(run_ids):
            raise SourceSealingClosureError(
                "invalid_binding", "run_id values must be globally distinct"
            )
        identity_pairs = (
            (test.key_id, train.key_id),
            (test.key_equality_tag_sha256, train.key_equality_tag_sha256),
            (test.output_identity_sha256, train.output_identity_sha256),
            (test.task_export_sha256, train.task_export_sha256),
            (test.task_records_sha256, train.task_records_sha256),
            (test.task_closure_sha256, train.task_closure_sha256),
            (test.source_map_sha256, train.source_map_sha256),
            (test.sealed_manifest_sha256, train.sealed_manifest_sha256),
            (test.batch_content_root, train.batch_content_root),
            (
                test.verify_rounds[0].summary_wire_sha256,
                train.verify_rounds[0].summary_wire_sha256,
            ),
        )
        if any(left == right for left, right in identity_pairs):
            raise SourceSealingClosureError(
                "invalid_binding", "test and train reuse a split or key identity"
            )
        object.__setattr__(self, "acquisition", acquisition)
        object.__setattr__(self, "test", test)
        object.__setattr__(self, "train", train)
        object.__setattr__(
            self,
            "receipt_sha256",
            hashlib.sha256(
                SOURCE_SEALING_CLOSURE_DIGEST_DOMAIN
                + _canonical_json(self._core_dict())
            ).hexdigest(),
        )
        if len(self.to_bytes()) > SOURCE_SEALING_CLOSURE_MAX_WIRE_BYTES:
            raise SourceSealingClosureError(
                "limit_exceeded", "source-sealing receipt exceeds its wire limit"
            )

    def _core_dict(self) -> dict[str, object]:
        return {
            "acquisition": self.acquisition.to_dict(),
            "contract_version": self.contract_version,
            "implementation_commit": self.implementation_commit,
            "kind": self.kind,
            "profile_id": self.profile_id,
            "public_manifest_sha256": self.public_manifest_sha256,
            "status": self.status,
            "test": self.test.to_dict(),
            "train": self.train.to_dict(),
        }

    def to_dict(self) -> dict[str, object]:
        expected = hashlib.sha256(
            SOURCE_SEALING_CLOSURE_DIGEST_DOMAIN
            + _canonical_json(self._core_dict())
        ).hexdigest()
        if self.receipt_sha256 != expected:
            raise SourceSealingClosureError(
                "invalid_binding", "source-sealing receipt digest changed"
            )
        return {**self._core_dict(), "receipt_sha256": self.receipt_sha256}

    def to_bytes(self) -> bytes:
        payload = _canonical_json(self.to_dict()) + b"\n"
        if len(payload) > SOURCE_SEALING_CLOSURE_MAX_WIRE_BYTES:
            raise SourceSealingClosureError(
                "limit_exceeded", "source-sealing receipt exceeds its wire limit"
            )
        return payload

    @property
    def wire_sha256(self) -> str:
        """Exact SHA-256 pin for ``to_bytes`` (kept external to avoid recursion)."""

        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def _from_pinned_dict(cls, value: object) -> "SourceSealingClosureReceiptV2":
        raw = _strict_object(
            value,
            keys=frozenset(
                {
                    "acquisition",
                    "contract_version",
                    "implementation_commit",
                    "kind",
                    "profile_id",
                    "public_manifest_sha256",
                    "receipt_sha256",
                    "status",
                    "test",
                    "train",
                }
            ),
            name="source-sealing closure receipt",
        )
        expected_receipt = _require_sha256(
            raw["receipt_sha256"], name="receipt_sha256"
        )
        result = cls(
            implementation_commit=raw[
                "implementation_commit"
            ],  # type: ignore[arg-type]
            acquisition=SourceAcquisitionClosureV1.from_dict(raw["acquisition"]),
            test=SourceSealingSplitClosureV2.from_dict(raw["test"]),
            train=SourceSealingSplitClosureV2.from_dict(raw["train"]),
            profile_id=raw["profile_id"],  # type: ignore[arg-type]
            public_manifest_sha256=raw[
                "public_manifest_sha256"
            ],  # type: ignore[arg-type]
            status=raw["status"],  # type: ignore[arg-type]
            contract_version=raw["contract_version"],  # type: ignore[arg-type]
            kind=raw["kind"],  # type: ignore[arg-type]
            _mint=_SOURCE_SEALING_PARSED_MINT,
        )
        if result.receipt_sha256 != expected_receipt or result.to_dict() != raw:
            raise SourceSealingClosureError(
                "digest_mismatch", "source-sealing receipt differs from its digest"
            )
        return result

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        expected_receipt_sha256: str,
        expected_wire_sha256: str,
    ) -> "SourceSealingClosureReceiptV2":
        semantic = _require_expected_sha256(
            expected_receipt_sha256, name="expected_receipt_sha256"
        )
        result = cls._from_pinned_dict(
            _parse_pinned_canonical_line(
                payload, expected_wire_sha256=expected_wire_sha256
            )
        )
        if result.receipt_sha256 != semantic or result.to_bytes() != payload:
            raise SourceSealingClosureError(
                "digest_mismatch", "source-sealing receipt differs from its pin"
            )
        return result

    @classmethod
    def from_verified_evidence(
        cls,
        *,
        implementation_commit: str,
        acquisition_report_bytes: bytes,
        expected_acquisition_report_sha256: str,
        test_evidence: tuple[
            SnapshotBatchVerificationEvidenceV2,
            SnapshotBatchVerificationEvidenceV2,
        ],
        train_evidence: tuple[
            SnapshotBatchVerificationEvidenceV2,
            SnapshotBatchVerificationEvidenceV2,
        ],
    ) -> "SourceSealingClosureReceiptV2":
        """Bind a pinned v5 acquisition report and trusted verifier evidence."""

        report = _parse_acquisition_report_v5(
            acquisition_report_bytes,
            expected_acquisition_report_sha256=(
                expected_acquisition_report_sha256
            ),
        )
        test = _split_from_evidence(
            split="test",
            acquisition_pin=report.split_pin("test"),
            evidence=test_evidence,
        )
        train = _split_from_evidence(
            split="train",
            acquisition_pin=report.split_pin("train"),
            evidence=train_evidence,
        )
        test_ids = tuple(task.task_id for task in test_evidence[0].summary.tasks)
        train_ids = tuple(task.task_id for task in train_evidence[0].summary.tasks)
        if (len(set(test_ids)) != 20 or len(set(train_ids)) != 50
            or set(test_ids).intersection(train_ids)
            or len(set(test_ids).union(train_ids)) != SOURCE_SEALING_TASK_COUNT):
            raise SourceSealingClosureError(
                "invalid_binding", "test/train task identities do not form an exact disjoint 70-task set"
            )
        if test_evidence[0].summary.batch_root == train_evidence[0].summary.batch_root:
            raise SourceSealingClosureError(
                "invalid_binding", "test and train reuse an output root"
            )
        result = cls(
            implementation_commit=implementation_commit,
            acquisition=report.acquisition,
            test=test,
            train=train,
            _mint=_SOURCE_SEALING_VERIFIED_MINT,
        )
        try:
            _claim_snapshot_batch_verification_evidence_batch(
                test_evidence=test_evidence,
                train_evidence=train_evidence,
            )
        except SnapshotBatchError as error:
            raise SourceSealingClosureError(
                "invalid_argument",
                "verification evidence is not a fresh trusted verifier mint",
            ) from error
        return result


__all__ = [
    "SOURCE_SEALING_CLOSURE_CONTRACT_VERSION",
    "SOURCE_SEALING_CLOSURE_DIGEST_DOMAIN",
    "SOURCE_SEALING_TASK_CLOSURE_DOMAIN",
    "SOURCE_SEALING_CLOSURE_KIND",
    "SOURCE_SEALING_CLOSURE_MAX_JSON_DEPTH",
    "SOURCE_SEALING_CLOSURE_MAX_JSON_NODES",
    "SOURCE_SEALING_CLOSURE_MAX_WIRE_BYTES",
    "SOURCE_SEALING_ACQUISITION_REPORT_MAX_JSON_DEPTH",
    "SOURCE_SEALING_ACQUISITION_REPORT_MAX_JSON_NODES",
    "SOURCE_SEALING_ACQUISITION_REPORT_MAX_WIRE_BYTES",
    "SOURCE_SEALING_CLOSURE_STATUS",
    "SOURCE_SEALING_REPOSITORY_COUNT",
    "SOURCE_SEALING_TASK_COUNT",
    "SOURCE_SEALING_VERIFY_ROUNDS_PER_SPLIT",
    "SourceAcquisitionClosureV1",
    "SourceObjectHygieneClosureV1",
    "SourceSealingClosureError",
    "SourceSealingClosureReceiptV2",
    "SourceSealingSplitClosureV2",
    "SourceSealingVerifyRoundV1",
]
