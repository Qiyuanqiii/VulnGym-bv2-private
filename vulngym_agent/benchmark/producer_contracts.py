"""Strict D2 producer result contracts for authenticated source discovery.

``ProducerDraftV1`` is the trusted, post-validation hand-off to D3.  It is
not the model-facing selection request: the controller first resolves only
runtime-issued artifact/node selections, constructs complete D0 candidates,
and attaches one validation receipt per candidate.  This module validates the
resulting immutable data and its exact receipt closure; runtime issuance and
artifact graph authority remain controller responsibilities.

The D2 candidate cap is deliberately 32, below D0's fixed cap of 64.  The
smaller first-version policy leaves room under the attempt runtime's 64
artifact ceiling for navigation and validation artifacts.  Runtime budgeting
may reduce the effective cap further but this contract can never raise it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import re
from typing import Any, Final, Literal, TypeAlias

from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryCandidate,
    DiscoveryContractError,
    DiscoveryTaskInputV1,
)


PRODUCER_CONTRACT_VERSION: Final[int] = 1
PRODUCER_POLICY_VERSION: Final[str] = "source-discovery-producer-d2-v1"
PRODUCER_LIMITS_VERSION: Final[str] = "source-discovery-producer-limits-v1"
PRODUCER_ERROR_TAXONOMY_VERSION: Final[str] = (
    "source-discovery-producer-errors-v1"
)
PRODUCER_SELECTION_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym D2 per-candidate selection v1\0"
)

_MAX_CANDIDATES: Final[int] = 32
_MAX_VALIDATION_RECEIPTS: Final[int] = 32
_MAX_DEPENDENCIES_PER_RECEIPT: Final[int] = 64
_MAX_ARTIFACTS_PER_DRAFT: Final[int] = 64
_MAX_MISSING_INFORMATION: Final[int] = 32
_MAX_MISSING_INFORMATION_CHARS: Final[int] = 2_048
_MAX_JSON_DEPTH: Final[int] = 8
_MAX_JSON_NODES: Final[int] = 20_000
_MAX_STRING_CHARS: Final[int] = 4_096
_MAX_WIRE_BYTES: Final[int] = 1_048_576

_ARTIFACT_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^ART-[A-Za-z0-9][A-Za-z0-9._-]{0,123}$"
)
_CANDIDATE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^VGC-[0-9A-F]{32}$")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_REASON_CODE_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-z][a-z0-9._:-]{0,127}$"
)
_DEFERRED_STAGES: Final[frozenset[str]] = frozenset(
    {"SCOUT", "ANALYZE", "VALIDATE", "FINALIZE"}
)

_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "duplicate_candidate",
        "invalid_binding",
        "invalid_identifier",
        "invalid_keys",
        "invalid_state",
        "invalid_type",
        "invalid_value",
        "limit_exceeded",
        "receipt_coverage_mismatch",
        "wire_invalid",
    }
)


class ProducerContractError(ValueError):
    """Stable, path-free failure for all public D2 contract boundaries."""

    taxonomy_version = PRODUCER_ERROR_TAXONOMY_VERSION

    def __init__(self, code: str, message: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES or type(message) is not str:
            code = "invalid_value"
            message = "producer contract error code is invalid"
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ProducerContractLimits:
    """Versioned fixed limits; callers may not expand the D2 policy."""

    max_candidates: int = _MAX_CANDIDATES
    max_validation_receipts: int = _MAX_VALIDATION_RECEIPTS
    max_dependencies_per_receipt: int = _MAX_DEPENDENCIES_PER_RECEIPT
    max_artifacts_per_draft: int = _MAX_ARTIFACTS_PER_DRAFT
    max_missing_information: int = _MAX_MISSING_INFORMATION
    max_missing_information_chars: int = _MAX_MISSING_INFORMATION_CHARS
    max_json_depth: int = _MAX_JSON_DEPTH
    max_json_nodes: int = _MAX_JSON_NODES
    max_string_chars: int = _MAX_STRING_CHARS
    max_wire_bytes: int = _MAX_WIRE_BYTES
    limits_version: str = PRODUCER_LIMITS_VERSION

    def __post_init__(self) -> None:
        expected = {
            "max_candidates": _MAX_CANDIDATES,
            "max_validation_receipts": _MAX_VALIDATION_RECEIPTS,
            "max_dependencies_per_receipt": _MAX_DEPENDENCIES_PER_RECEIPT,
            "max_artifacts_per_draft": _MAX_ARTIFACTS_PER_DRAFT,
            "max_missing_information": _MAX_MISSING_INFORMATION,
            "max_missing_information_chars": _MAX_MISSING_INFORMATION_CHARS,
            "max_json_depth": _MAX_JSON_DEPTH,
            "max_json_nodes": _MAX_JSON_NODES,
            "max_string_chars": _MAX_STRING_CHARS,
            "max_wire_bytes": _MAX_WIRE_BYTES,
        }
        if (
            type(self.limits_version) is not str
            or self.limits_version != PRODUCER_LIMITS_VERSION
        ):
            raise ProducerContractError(
                "invalid_value", "limits_version does not match the D2 policy"
            )
        for name, fixed in expected.items():
            value = getattr(self, name)
            if type(value) is not int or value != fixed:
                raise ProducerContractError(
                    "invalid_value", f"{name} must equal the D2 fixed limit {fixed}"
                )

    def to_dict(self) -> dict[str, int | str]:
        return {
            "limits_version": self.limits_version,
            "max_artifacts_per_draft": self.max_artifacts_per_draft,
            "max_candidates": self.max_candidates,
            "max_dependencies_per_receipt": self.max_dependencies_per_receipt,
            "max_json_depth": self.max_json_depth,
            "max_json_nodes": self.max_json_nodes,
            "max_missing_information": self.max_missing_information,
            "max_missing_information_chars": self.max_missing_information_chars,
            "max_string_chars": self.max_string_chars,
            "max_validation_receipts": self.max_validation_receipts,
            "max_wire_bytes": self.max_wire_bytes,
        }


DEFAULT_PRODUCER_LIMITS: Final[ProducerContractLimits] = ProducerContractLimits()


def _identifier(value: Any, *, pattern: re.Pattern[str], name: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ProducerContractError(
            "invalid_identifier", f"{name} has an invalid format"
        )
    return value


def _ordered_values(
    value: Any, *, name: str, maximum: int
) -> tuple[Any, ...]:
    # Direct constructors accept only already-materialized bounded containers.
    # This avoids consuming hostile/infinite Sequence implementations before a
    # cardinality check can run.
    if type(value) not in (tuple, list):
        raise ProducerContractError(
            "invalid_type", f"{name} must be an ordered collection"
        )
    # Exact tuples are immutable.  For lists, take an explicitly bounded slice
    # so concurrent growth between length inspection and copying cannot make
    # materialization exceed the policy by an arbitrary amount.
    snapshot = value if type(value) is tuple else tuple(value[: maximum + 1])
    if len(snapshot) > maximum:
        raise ProducerContractError("limit_exceeded", f"{name} exceeds its limit")
    return snapshot


def _strict_object(
    value: Any, *, expected: frozenset[str], name: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProducerContractError("invalid_type", f"{name} must be an object")
    try:
        keys = tuple(value)
    except Exception:
        raise ProducerContractError("invalid_type", f"{name} must be an object") from None
    if any(not isinstance(key, str) for key in keys):
        raise ProducerContractError("invalid_keys", f"{name} keys must be strings")
    if frozenset(keys) != expected or len(keys) != len(expected):
        raise ProducerContractError(
            "invalid_keys", f"{name} must contain its exact contract keys"
        )
    return value


def _canonical_bytes(value: Any) -> bytes:
    encoder = json.JSONEncoder(
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    encoded = bytearray()
    try:
        for chunk in encoder.iterencode(value):
            encoded_chunk = chunk.encode("utf-8")
            if len(encoded) + len(encoded_chunk) > DEFAULT_PRODUCER_LIMITS.max_wire_bytes:
                raise ProducerContractError(
                    "limit_exceeded", "producer wire value exceeds its byte limit"
                )
            encoded.extend(encoded_chunk)
    except ProducerContractError:
        raise
    except Exception:
        raise ProducerContractError(
            "wire_invalid", "producer value is not canonical JSON"
        ) from None
    return bytes(encoded)


def _detach_bounded_json(value: Any) -> Any:
    """Validate and detach JSON in one bounded traversal.

    In particular, custom ``Mapping`` implementations are consumed through a
    single key iterator.  We never materialize ``items()`` or revisit the
    caller-owned object, so a lazy or stateful mapping cannot bypass the node
    budget between validation and canonicalization.
    """

    nodes = 0

    def claim(depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > DEFAULT_PRODUCER_LIMITS.max_json_nodes:
            raise ProducerContractError(
                "limit_exceeded", "producer wire value exceeds its node limit"
            )
        if depth > DEFAULT_PRODUCER_LIMITS.max_json_depth:
            raise ProducerContractError(
                "limit_exceeded", "producer wire value exceeds its depth limit"
            )

    def checked_text(item: str) -> str:
        if len(item) > DEFAULT_PRODUCER_LIMITS.max_string_chars:
            raise ProducerContractError(
                "limit_exceeded", "producer wire string exceeds its length limit"
            )
        try:
            item.encode("utf-8")
        except UnicodeError:
            raise ProducerContractError(
                "wire_invalid", "producer wire text is not valid Unicode"
            ) from None
        return item

    def visit(item: Any, depth: int) -> Any:
        claim(depth)
        if item is None or type(item) in (bool, int):
            if type(item) is int and item.bit_length() > (
                DEFAULT_PRODUCER_LIMITS.max_wire_bytes * 4
            ):
                raise ProducerContractError(
                    "limit_exceeded", "producer wire integer exceeds its byte limit"
                )
            return item
        if type(item) is str:
            return checked_text(item)
        if isinstance(item, Mapping):
            detached: dict[str, Any] = {}
            # ``len`` is only an optimization for exact dictionaries.  A
            # custom Mapping may lie, allocate, or fail in ``__len__`` and is
            # therefore governed solely by the iterator/node budget.
            if type(item) is dict and len(item) > (
                DEFAULT_PRODUCER_LIMITS.max_json_nodes - nodes
            ) // 2:
                raise ProducerContractError(
                    "limit_exceeded", "producer wire object exceeds its node limit"
                )
            try:
                iterator = iter(item)
            except Exception:
                raise ProducerContractError(
                    "wire_invalid", "producer wire object cannot be inspected"
                ) from None
            while True:
                try:
                    key = next(iterator)
                except StopIteration:
                    break
                except Exception:
                    raise ProducerContractError(
                        "wire_invalid", "producer wire object cannot be inspected"
                    ) from None
                claim(depth + 1)
                if type(key) is not str:
                    raise ProducerContractError(
                        "invalid_keys", "producer wire object keys must be strings"
                    )
                checked_text(key)
                if key in detached:
                    raise ProducerContractError(
                        "invalid_keys", "producer wire object keys must be unique"
                    )
                if nodes >= DEFAULT_PRODUCER_LIMITS.max_json_nodes:
                    raise ProducerContractError(
                        "limit_exceeded", "producer wire value exceeds its node limit"
                    )
                try:
                    child = item[key]
                except Exception:
                    raise ProducerContractError(
                        "wire_invalid", "producer wire object cannot be inspected"
                    ) from None
                detached[key] = visit(child, depth + 1)
            return detached
        if type(item) is list:
            if len(item) > DEFAULT_PRODUCER_LIMITS.max_json_nodes - nodes:
                raise ProducerContractError(
                    "limit_exceeded", "producer wire value exceeds its node limit"
                )
            detached_list: list[Any] = []
            for child in item:
                detached_list.append(visit(child, depth + 1))
            return detached_list
        raise ProducerContractError(
            "invalid_type", "producer wire contains a non-JSON value"
        )

    try:
        return visit(value, 0)
    except ProducerContractError:
        raise
    except Exception:
        raise ProducerContractError(
            "wire_invalid", "producer wire value cannot be inspected"
        ) from None


def _validate_json_shape(value: Any) -> None:
    _detach_bounded_json(value)


def _bounded_wire_object(value: Any, *, name: str) -> Mapping[str, Any]:
    detached = _detach_bounded_json(value)
    _canonical_bytes(detached)
    if type(detached) is not dict:
        raise ProducerContractError("invalid_type", f"{name} must be an object")
    return detached


class _DuplicateWireKey(ValueError):
    pass


def _decode_wire(value: Any) -> Mapping[str, Any]:
    if type(value) is str:
        if not value or len(value) > DEFAULT_PRODUCER_LIMITS.max_wire_bytes:
            raise ProducerContractError(
                "limit_exceeded", "producer wire bytes are empty or exceed their limit"
            )
        try:
            raw = str.encode(value, "utf-8")
        except Exception:
            raise ProducerContractError(
                "wire_invalid", "producer wire text is not valid UTF-8"
            ) from None
    elif type(value) is bytes:
        raw = value
    elif type(value) is bytearray:
        if not value or len(value) > DEFAULT_PRODUCER_LIMITS.max_wire_bytes:
            raise ProducerContractError(
                "limit_exceeded", "producer wire bytes are empty or exceed their limit"
            )
        raw = bytes(value)
    elif type(value) is memoryview:
        try:
            if value.nbytes > DEFAULT_PRODUCER_LIMITS.max_wire_bytes:
                raise ProducerContractError(
                    "limit_exceeded",
                    "producer wire bytes are empty or exceed their limit",
                )
            raw = bytes(value)
        except ProducerContractError:
            raise
        except Exception:
            raise ProducerContractError(
                "wire_invalid", "producer wire bytes are unavailable"
            ) from None
    else:
        raise ProducerContractError(
            "invalid_type", "producer wire must be UTF-8 text or bytes"
        )
    if not raw or len(raw) > DEFAULT_PRODUCER_LIMITS.max_wire_bytes:
        raise ProducerContractError(
            "limit_exceeded", "producer wire bytes are empty or exceed their limit"
        )
    try:
        text = raw.decode("utf-8")

        def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, child in pairs:
                if key in result:
                    raise _DuplicateWireKey("duplicate producer wire key")
                result[key] = child
            return result

        def invalid_constant(_: str) -> Any:
            raise ValueError("non-finite producer number")

        decoded = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=invalid_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError):
        raise ProducerContractError(
            "wire_invalid", "producer wire is not strict JSON"
        ) from None
    decoded = _detach_bounded_json(decoded)
    if _canonical_bytes(decoded) != raw:
        raise ProducerContractError(
            "wire_invalid", "producer wire is not in canonical form"
        )
    if type(decoded) is not dict:
        raise ProducerContractError(
            "invalid_type", "producer wire root must be an object"
        )
    return decoded


@dataclass(frozen=True, slots=True)
class ProducerArtifactDigestRefV1:
    """Portable ID+digest reference; runtime issuance is checked by controller."""

    artifact_id: str
    artifact_sha256: str
    contract_version: int = PRODUCER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ProducerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        _identifier(self.artifact_id, pattern=_ARTIFACT_ID_RE, name="artifact_id")
        _identifier(
            self.artifact_sha256,
            pattern=_SHA256_RE,
            name="artifact_sha256",
        )
        _validate_json_shape(self.to_dict())
        _canonical_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "ProducerArtifactDigestRefV1":
        ref = _strict_object(
            _bounded_wire_object(value, name="ProducerArtifactDigestRefV1"),
            expected=frozenset(
                {"artifact_id", "artifact_sha256", "contract_version"}
            ),
            name="ProducerArtifactDigestRefV1",
        )
        return cls(
            artifact_id=ref["artifact_id"],
            artifact_sha256=ref["artifact_sha256"],
            contract_version=ref["contract_version"],
        )

    def to_dict(self) -> dict[str, str | int]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "contract_version": self.contract_version,
        }


@dataclass(frozen=True, slots=True)
class ValidationReceiptV1:
    """Controller-issued proof binding one exact candidate to source validation.

    ``selection_digest`` is per candidate, never a digest of the complete model
    response.  Under :data:`PRODUCER_SELECTION_DIGEST_DOMAIN`, the controller
    hashes canonical JSON containing the task/snapshot binding, entry and
    critical owner-artifact/node references, ordered trace references, and
    canonically sorted relationship owner-artifact/link references.  This
    data-only contract deliberately does not accept that model-facing object.
    """

    candidate_id: str
    candidate_sha256: str
    validation_artifact_id: str
    validation_artifact_sha256: str
    selection_digest: str
    dependencies: tuple[ProducerArtifactDigestRefV1, ...]
    contract_version: int = PRODUCER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ProducerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        _identifier(self.candidate_id, pattern=_CANDIDATE_ID_RE, name="candidate_id")
        for name, value in (
            ("candidate_sha256", self.candidate_sha256),
            ("validation_artifact_sha256", self.validation_artifact_sha256),
            ("selection_digest", self.selection_digest),
        ):
            _identifier(value, pattern=_SHA256_RE, name=name)
        _identifier(
            self.validation_artifact_id,
            pattern=_ARTIFACT_ID_RE,
            name="validation_artifact_id",
        )
        dependencies = _ordered_values(
            self.dependencies,
            name="dependencies",
            maximum=DEFAULT_PRODUCER_LIMITS.max_dependencies_per_receipt,
        )
        if len(dependencies) > DEFAULT_PRODUCER_LIMITS.max_dependencies_per_receipt:
            raise ProducerContractError(
                "limit_exceeded", "validation dependencies exceed their limit"
            )
        if any(type(item) is not ProducerArtifactDigestRefV1 for item in dependencies):
            raise ProducerContractError(
                "invalid_type", "dependencies must contain artifact digest references"
            )
        dependencies = tuple(sorted(dependencies, key=lambda item: item.artifact_id))
        dependency_ids = [item.artifact_id for item in dependencies]
        if len(dependency_ids) != len(set(dependency_ids)):
            raise ProducerContractError(
                "invalid_value", "validation dependencies repeat an artifact"
            )
        if self.validation_artifact_id in set(dependency_ids):
            raise ProducerContractError(
                "invalid_value", "a validation artifact cannot depend on itself"
            )
        object.__setattr__(self, "dependencies", dependencies)
        _validate_json_shape(self.to_dict())
        _canonical_bytes(self.to_dict())

    def assert_candidate(self, candidate: DiscoveryCandidate) -> None:
        if type(candidate) is not DiscoveryCandidate or (
            self.candidate_id,
            self.candidate_sha256,
        ) != (candidate.candidate_id, candidate.candidate_sha256):
            raise ProducerContractError(
                "invalid_binding", "validation receipt does not match its candidate"
            )
        evidence_ids = set(candidate.source_evidence_refs) | set(
            candidate.relationship_evidence_refs
        )
        dependency_ids = {item.artifact_id for item in self.dependencies}
        if dependency_ids != evidence_ids:
            raise ProducerContractError(
                "receipt_coverage_mismatch",
                "validation dependencies do not close candidate evidence",
            )

    @classmethod
    def from_dict(cls, value: Any) -> "ValidationReceiptV1":
        receipt = _strict_object(
            _bounded_wire_object(value, name="ValidationReceiptV1"),
            expected=frozenset(
                {
                    "candidate_id",
                    "candidate_sha256",
                    "contract_version",
                    "dependencies",
                    "selection_digest",
                    "validation_artifact_id",
                    "validation_artifact_sha256",
                }
            ),
            name="ValidationReceiptV1",
        )
        dependencies = receipt["dependencies"]
        if not isinstance(dependencies, list):
            raise ProducerContractError(
                "invalid_type", "validation dependencies must be an array"
            )
        return cls(
            candidate_id=receipt["candidate_id"],
            candidate_sha256=receipt["candidate_sha256"],
            validation_artifact_id=receipt["validation_artifact_id"],
            validation_artifact_sha256=receipt["validation_artifact_sha256"],
            selection_digest=receipt["selection_digest"],
            dependencies=tuple(
                ProducerArtifactDigestRefV1.from_dict(item) for item in dependencies
            ),
            contract_version=receipt["contract_version"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_sha256": self.candidate_sha256,
            "contract_version": self.contract_version,
            "dependencies": [item.to_dict() for item in self.dependencies],
            "selection_digest": self.selection_digest,
            "validation_artifact_id": self.validation_artifact_id,
            "validation_artifact_sha256": self.validation_artifact_sha256,
        }


ProducerValidationReceiptV1 = ValidationReceiptV1


def _validate_task(value: Any) -> DiscoveryTaskInputV1:
    if type(value) is not DiscoveryTaskInputV1:
        raise ProducerContractError(
            "invalid_type", "task must be a DiscoveryTaskInputV1 value"
        )
    return value


def _translate_discovery_error(error: DiscoveryContractError) -> ProducerContractError:
    code = "invalid_binding" if error.code == "invalid_binding" else "invalid_value"
    return ProducerContractError(code, "nested discovery contract is invalid")


@dataclass(frozen=True, slots=True)
class ProducerDraftV1:
    """Trusted post-validation producer draft containing complete D0 candidates."""

    task: DiscoveryTaskInputV1
    candidates: tuple[DiscoveryCandidate, ...]
    validation_receipts: tuple[ValidationReceiptV1, ...]
    coverage_status: Literal["unknown"] = "unknown"
    policy_version: str = PRODUCER_POLICY_VERSION
    contract_version: int = PRODUCER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        task = _validate_task(self.task)
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ProducerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        if (
            type(self.policy_version) is not str
            or self.policy_version != PRODUCER_POLICY_VERSION
        ):
            raise ProducerContractError(
                "invalid_value", "policy_version does not match D2"
            )
        if type(self.coverage_status) is not str or self.coverage_status != "unknown":
            raise ProducerContractError(
                "invalid_state", "coverage_status must remain unknown"
            )
        candidates = _ordered_values(
            self.candidates,
            name="candidates",
            maximum=DEFAULT_PRODUCER_LIMITS.max_candidates,
        )
        receipts = _ordered_values(
            self.validation_receipts,
            name="validation_receipts",
            maximum=DEFAULT_PRODUCER_LIMITS.max_validation_receipts,
        )
        if len(candidates) > DEFAULT_PRODUCER_LIMITS.max_candidates:
            raise ProducerContractError(
                "limit_exceeded", "producer draft exceeds its 32-candidate cap"
            )
        if len(receipts) > DEFAULT_PRODUCER_LIMITS.max_validation_receipts:
            raise ProducerContractError(
                "limit_exceeded", "producer draft has too many validation receipts"
            )
        if any(type(item) is not DiscoveryCandidate for item in candidates):
            raise ProducerContractError(
                "invalid_type", "candidates must contain DiscoveryCandidate values"
            )
        if any(type(item) is not ValidationReceiptV1 for item in receipts):
            raise ProducerContractError(
                "invalid_type", "validation_receipts contain an invalid value"
            )
        candidates = tuple(sorted(candidates, key=lambda item: item.candidate_id))
        receipts = tuple(sorted(receipts, key=lambda item: item.candidate_id))
        candidate_ids = [item.candidate_id for item in candidates]
        receipt_ids = [item.candidate_id for item in receipts]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ProducerContractError(
                "duplicate_candidate", "producer draft repeats an endpoint candidate"
            )
        if len(receipt_ids) != len(set(receipt_ids)):
            raise ProducerContractError(
                "receipt_coverage_mismatch", "producer draft repeats a receipt"
            )
        if set(candidate_ids) != set(receipt_ids):
            raise ProducerContractError(
                "receipt_coverage_mismatch",
                "producer draft requires exactly one receipt per candidate",
            )
        validation_ids = [item.validation_artifact_id for item in receipts]
        if len(validation_ids) != len(set(validation_ids)):
            raise ProducerContractError(
                "receipt_coverage_mismatch",
                "validation artifacts must be unique per candidate",
            )
        selection_digests = [item.selection_digest for item in receipts]
        if len(selection_digests) != len(set(selection_digests)):
            raise ProducerContractError(
                "receipt_coverage_mismatch",
                "per-candidate selection digests must be unique",
            )
        validation_id_set = set(validation_ids)
        evidence_id_set = {
            artifact_id
            for candidate in candidates
            for artifact_id in (
                *candidate.source_evidence_refs,
                *candidate.relationship_evidence_refs,
            )
        }
        dependency_digests: dict[str, str] = {}
        for receipt in receipts:
            for dependency in receipt.dependencies:
                previous = dependency_digests.setdefault(
                    dependency.artifact_id, dependency.artifact_sha256
                )
                if previous != dependency.artifact_sha256:
                    raise ProducerContractError(
                        "invalid_binding",
                        "shared validation dependencies disagree on their digest",
                    )
        if validation_id_set & (evidence_id_set | set(dependency_digests)):
            raise ProducerContractError(
                "receipt_coverage_mismatch",
                "validation artifacts cannot enter candidate evidence closure",
            )
        represented_artifact_ids = validation_id_set | evidence_id_set | set(
            dependency_digests
        )
        if len(represented_artifact_ids) > DEFAULT_PRODUCER_LIMITS.max_artifacts_per_draft:
            raise ProducerContractError(
                "limit_exceeded",
                "producer draft exceeds the attempt artifact ceiling",
            )
        by_id = {item.candidate_id: item for item in candidates}
        all_source_ids: set[str] = set()
        all_relationship_ids: set[str] = set()
        for candidate in candidates:
            try:
                candidate.assert_task(task)
            except DiscoveryContractError as error:
                raise _translate_discovery_error(error) from None
            source_ids = tuple(candidate.source_evidence_refs)
            relationship_ids = tuple(candidate.relationship_evidence_refs)
            if source_ids != tuple(sorted(source_ids)) or relationship_ids != tuple(
                sorted(relationship_ids)
            ):
                raise ProducerContractError(
                    "invalid_binding",
                    "candidate evidence references must use canonical order",
                )
            if set(source_ids) & set(relationship_ids) or any(
                _ARTIFACT_ID_RE.fullmatch(item) is None
                for item in (*source_ids, *relationship_ids)
            ):
                raise ProducerContractError(
                    "invalid_binding",
                    "candidate evidence must be disjoint runtime artifact IDs",
                )
            all_source_ids.update(source_ids)
            all_relationship_ids.update(relationship_ids)
        if all_source_ids & all_relationship_ids:
            raise ProducerContractError(
                "invalid_binding",
                "artifact evidence roles must be consistent across the draft",
            )
        for receipt in receipts:
            receipt.assert_candidate(by_id[receipt.candidate_id])
        object.__setattr__(self, "candidates", candidates)
        object.__setattr__(self, "validation_receipts", receipts)
        _validate_json_shape(self.to_dict())
        _canonical_bytes(self.to_dict())

    @property
    def result_type(self) -> Literal["draft"]:
        return "draft"

    @property
    def task_id(self) -> str:
        return self.task.task_id

    @property
    def snapshot_id(self) -> str:
        return self.task.snapshot_id

    @property
    def manifest_sha256(self) -> str:
        return self.task.snapshot_manifest_sha256

    @property
    def content_root(self) -> str:
        return self.task.snapshot_content_root

    @classmethod
    def from_dict(cls, value: Any) -> "ProducerDraftV1":
        draft = _strict_object(
            _bounded_wire_object(value, name="ProducerDraftV1"),
            expected=frozenset(
                {
                    "candidates",
                    "contract_version",
                    "coverage_status",
                    "policy_version",
                    "result_type",
                    "task",
                    "validation_receipts",
                }
            ),
            name="ProducerDraftV1",
        )
        if draft["result_type"] != "draft":
            raise ProducerContractError(
                "invalid_state", "producer result_type must be draft"
            )
        candidates = draft["candidates"]
        receipts = draft["validation_receipts"]
        if not isinstance(candidates, list) or not isinstance(receipts, list):
            raise ProducerContractError(
                "invalid_type", "draft candidates and receipts must be arrays"
            )
        try:
            task = DiscoveryTaskInputV1.from_dict(draft["task"])
            parsed_candidates = tuple(
                DiscoveryCandidate.from_dict(item) for item in candidates
            )
        except DiscoveryContractError as error:
            raise _translate_discovery_error(error) from None
        return cls(
            task=task,
            candidates=parsed_candidates,
            validation_receipts=tuple(
                ValidationReceiptV1.from_dict(item) for item in receipts
            ),
            coverage_status=draft["coverage_status"],
            policy_version=draft["policy_version"],
            contract_version=draft["contract_version"],
        )

    @classmethod
    def from_wire(cls, value: Any) -> "ProducerDraftV1":
        return cls.from_dict(_decode_wire(value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidates": [item.to_dict() for item in self.candidates],
            "contract_version": self.contract_version,
            "coverage_status": self.coverage_status,
            "policy_version": self.policy_version,
            "result_type": self.result_type,
            "task": self.task.to_dict(),
            "validation_receipts": [
                item.to_dict() for item in self.validation_receipts
            ],
        }

    def to_wire(self) -> bytes:
        return _canonical_bytes(self.to_dict())


@dataclass(frozen=True, slots=True)
class ProducerDeferredV1:
    """Fail-closed D2 outcome containing no partial candidate material."""

    task: DiscoveryTaskInputV1
    stage: Literal["SCOUT", "ANALYZE", "VALIDATE", "FINALIZE"]
    reason_code: str
    missing_information: tuple[str, ...]
    coverage_status: Literal["unknown"] = "unknown"
    policy_version: str = PRODUCER_POLICY_VERSION
    contract_version: int = PRODUCER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        _validate_task(self.task)
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ProducerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        if (
            type(self.policy_version) is not str
            or self.policy_version != PRODUCER_POLICY_VERSION
        ):
            raise ProducerContractError(
                "invalid_value", "policy_version does not match D2"
            )
        if type(self.coverage_status) is not str or self.coverage_status != "unknown":
            raise ProducerContractError(
                "invalid_state", "coverage_status must remain unknown"
            )
        if type(self.stage) is not str or self.stage not in _DEFERRED_STAGES:
            raise ProducerContractError(
                "invalid_state", "deferred stage is not a D2 stage"
            )
        _identifier(self.reason_code, pattern=_REASON_CODE_RE, name="reason_code")
        missing = _ordered_values(
            self.missing_information,
            name="missing_information",
            maximum=DEFAULT_PRODUCER_LIMITS.max_missing_information,
        )
        if not missing or len(missing) > DEFAULT_PRODUCER_LIMITS.max_missing_information:
            raise ProducerContractError(
                "limit_exceeded", "missing_information has an invalid count"
            )
        for item in missing:
            if (
                type(item) is not str
                or not item
                or len(item) > DEFAULT_PRODUCER_LIMITS.max_missing_information_chars
                or any(ord(character) < 32 or ord(character) == 127 for character in item)
            ):
                raise ProducerContractError(
                    "invalid_value", "missing_information contains invalid text"
                )
            try:
                item.encode("utf-8")
            except UnicodeError:
                raise ProducerContractError(
                    "invalid_value", "missing_information is not valid Unicode"
                ) from None
        if len(missing) != len(set(missing)):
            raise ProducerContractError(
                "invalid_value", "missing_information must not contain duplicates"
            )
        object.__setattr__(self, "missing_information", missing)
        _validate_json_shape(self.to_dict())
        _canonical_bytes(self.to_dict())

    @property
    def result_type(self) -> Literal["deferred"]:
        return "deferred"

    @property
    def task_id(self) -> str:
        return self.task.task_id

    @property
    def snapshot_id(self) -> str:
        return self.task.snapshot_id

    @property
    def manifest_sha256(self) -> str:
        return self.task.snapshot_manifest_sha256

    @property
    def content_root(self) -> str:
        return self.task.snapshot_content_root

    @classmethod
    def from_dict(cls, value: Any) -> "ProducerDeferredV1":
        deferred = _strict_object(
            _bounded_wire_object(value, name="ProducerDeferredV1"),
            expected=frozenset(
                {
                    "contract_version",
                    "coverage_status",
                    "missing_information",
                    "policy_version",
                    "reason_code",
                    "result_type",
                    "stage",
                    "task",
                }
            ),
            name="ProducerDeferredV1",
        )
        if deferred["result_type"] != "deferred":
            raise ProducerContractError(
                "invalid_state", "producer result_type must be deferred"
            )
        missing = deferred["missing_information"]
        if not isinstance(missing, list):
            raise ProducerContractError(
                "invalid_type", "missing_information must be an array"
            )
        try:
            task = DiscoveryTaskInputV1.from_dict(deferred["task"])
        except DiscoveryContractError as error:
            raise _translate_discovery_error(error) from None
        return cls(
            task=task,
            stage=deferred["stage"],
            reason_code=deferred["reason_code"],
            missing_information=tuple(missing),
            coverage_status=deferred["coverage_status"],
            policy_version=deferred["policy_version"],
            contract_version=deferred["contract_version"],
        )

    @classmethod
    def from_wire(cls, value: Any) -> "ProducerDeferredV1":
        return cls.from_dict(_decode_wire(value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "coverage_status": self.coverage_status,
            "missing_information": list(self.missing_information),
            "policy_version": self.policy_version,
            "reason_code": self.reason_code,
            "result_type": self.result_type,
            "stage": self.stage,
            "task": self.task.to_dict(),
        }

    def to_wire(self) -> bytes:
        return _canonical_bytes(self.to_dict())


ProducerResultV1: TypeAlias = ProducerDraftV1 | ProducerDeferredV1


def parse_producer_result_v1(value: Any) -> ProducerResultV1:
    """Parse a canonical wire value or strict JSON object into the D2 union."""

    if type(value) in (ProducerDraftV1, ProducerDeferredV1):
        return value
    if isinstance(value, (str, bytes, bytearray, memoryview)):
        payload = _decode_wire(value)
    else:
        payload = _bounded_wire_object(value, name="ProducerResultV1")
    try:
        result_type = payload.get("result_type")
    except (TypeError, ValueError, RuntimeError):
        raise ProducerContractError(
            "wire_invalid", "producer result discriminator is unavailable"
        ) from None
    if result_type == "draft":
        return ProducerDraftV1.from_dict(payload)
    if result_type == "deferred":
        return ProducerDeferredV1.from_dict(payload)
    raise ProducerContractError(
        "invalid_state", "producer result_type must be draft or deferred"
    )


__all__ = [
    "DEFAULT_PRODUCER_LIMITS",
    "PRODUCER_CONTRACT_VERSION",
    "PRODUCER_ERROR_TAXONOMY_VERSION",
    "PRODUCER_LIMITS_VERSION",
    "PRODUCER_POLICY_VERSION",
    "PRODUCER_SELECTION_DIGEST_DOMAIN",
    "ProducerArtifactDigestRefV1",
    "ProducerContractError",
    "ProducerContractLimits",
    "ProducerDeferredV1",
    "ProducerDraftV1",
    "ProducerResultV1",
    "ProducerValidationReceiptV1",
    "ValidationReceiptV1",
    "parse_producer_result_v1",
]
