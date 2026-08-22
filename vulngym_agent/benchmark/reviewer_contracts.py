"""Strict D3 contracts for independent source-discovery review.

The reviewer receives one complete :class:`ProducerDraftV1`, reacquires its
own source evidence from a fresh sealed-tree runtime, and emits one mechanical
three-way verdict per candidate.  The contracts in this module bind that work
without treating a model judgment as a source fact: artifact issuance,
transcript identity, ledger closure, and catalog authority remain controller
responsibilities.

Every digest is domain separated.  Public results contain only bounded
portable references and closure digests; source excerpts and complete runtime
sidecars are deliberately excluded.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Final, Literal, TypeAlias

from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryCandidate,
    DiscoveryLocation,
    DiscoveryTaskInputV1,
)
from vulngym_agent.benchmark.producer_contracts import (
    ProducerArtifactDigestRefV1,
    ProducerContractError,
    ProducerDraftV1,
    ValidationReceiptV1,
)


REVIEWER_CONTRACT_VERSION: Final[int] = 1
REVIEWER_POLICY_VERSION: Final[str] = "source-discovery-reviewer-d3-v1"
REVIEWER_SCOPE: Final[str] = "d3.review"
REVIEWER_VALIDATION_ARTIFACT_KIND: Final[str] = "review.validation"
REVIEWER_VALIDATION_CONTRACT_ID: Final[str] = (
    "source-discovery-review-validate@1"
)
REVIEWER_LIMITS_VERSION: Final[str] = "source-discovery-reviewer-limits-v1"
REVIEWER_ERROR_TAXONOMY_VERSION: Final[str] = (
    "source-discovery-reviewer-errors-v1"
)
REVIEWER_INSTRUCTION_V1: Final[str] = (
    "Independently assess each source-discovery candidate against only the "
    "fresh D3 source context. Return the fixed four criteria as supported, "
    "contradicted, or insufficient, with runtime-issued evidence selections. "
    "For counterevidence_status, supported means the bounded context supports "
    "absence of a contradiction, contradicted means contradictory source is "
    "present, and insufficient means the bounded context cannot decide."
)
REVIEWER_INSTRUCTION_ID: Final[str] = hashlib.sha256(
    REVIEWER_INSTRUCTION_V1.encode("utf-8")
).hexdigest()

REVIEWER_INPUT_DIGEST_DOMAIN: Final[bytes] = b"VulnGym D3 reviewer input v1\0"
REVIEWER_SELECTION_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym D3 reviewer candidate selections v1\0"
)
REVIEWER_VERDICT_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym D3 reviewer candidate verdict v1\0"
)
REVIEWER_ATTEMPT_SEAL_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym D3 reviewer attempt seal v1\0"
)
REVIEWER_RESULT_DIGEST_DOMAIN: Final[bytes] = (
    b"VulnGym D3 reviewer result v1\0"
)

REVIEWER_CRITERIA: Final[tuple[str, ...]] = (
    "entry_role",
    "critical_role",
    "trace_continuity",
    "counterevidence_status",
)
REVIEWER_ASSESSMENTS: Final[frozenset[str]] = frozenset(
    {"supported", "contradicted", "insufficient"}
)
REVIEWER_DECISIONS: Final[frozenset[str]] = frozenset(
    {"accept", "reject", "defer"}
)

_MAX_CANDIDATES: Final[int] = 32
_MAX_SELECTIONS_PER_CRITERION: Final[int] = 8
_MAX_SELECTIONS_PER_VERDICT: Final[int] = 32
_MAX_SELECTIONS_PER_BATCH: Final[int] = 256
_MAX_ARTIFACTS_PER_ATTEMPT: Final[int] = 64
_MAX_MODEL_RECORDS: Final[int] = 16
_MAX_TOOL_RECORDS: Final[int] = 80
_MAX_SOURCE_READS: Final[int] = 4_096
_MAX_BUDGET_EVENTS: Final[int] = 96
_MAX_MISSING_INFORMATION: Final[int] = 8
_MAX_JSON_DEPTH: Final[int] = 12
_MAX_JSON_NODES: Final[int] = 32_000
_MAX_STRING_CHARS: Final[int] = 4_096
_MAX_WIRE_BYTES: Final[int] = 1_572_864
_MAX_UPSTREAM_TRACE_NODES: Final[int] = 64
_MAX_UPSTREAM_EVIDENCE_REFS: Final[int] = 256
_MAX_UPSTREAM_RECEIPT_DEPENDENCIES: Final[int] = 64
_MAX_UPSTREAM_ARTIFACT_IDS: Final[int] = 64
_MAX_UPSTREAM_LINE: Final[int] = 2_147_483_647
_MAX_UPSTREAM_LOCATION_SPAN: Final[int] = 256
_MAX_UPSTREAM_WIRE_BYTES: Final[int] = 1_048_576

_ARTIFACT_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^ART-[A-Za-z0-9][A-Za-z0-9._-]{0,123}$"
)
_NODE_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:LOC|LEX|MAT|REL)-[A-Za-z0-9][A-Za-z0-9._-]{0,123}$"
)
_CANDIDATE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^VGC-[0-9A-F]{32}$")
_TASK_ID_RE: Final[re.Pattern[str]] = re.compile(r"^VG-(?:TRAIN|TEST)-[0-9A-F]{20}$")
_SNAPSHOT_ID_RE: Final[re.Pattern[str]] = re.compile(r"^VGS-[0-9A-F]{32}$")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

_DEFERRED_STAGES: Final[frozenset[str]] = frozenset({"REVIEW", "FINALIZE"})
_DEFERRED_REASON_CODES: Final[frozenset[str]] = frozenset(
    {
        "contract.invalid",
        "review.incomplete",
        "runtime.budget_exhausted",
        "runtime.cancelled",
        "runtime.model_failed",
        "runtime.seal_failed",
        "runtime.source_failed",
        "runtime.tool_failed",
    }
)
_MISSING_INFORMATION_CODES: Final[frozenset[str]] = frozenset(
    {
        "artifact_catalog",
        "attempt_seal",
        "budget_ledger",
        "candidate_coverage",
        "model_response",
        "model_transcript",
        "review_evidence",
        "source_ledger",
        "tool_transcript",
    }
)

_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "artifact_coverage_mismatch",
        "duplicate_candidate",
        "invalid_binding",
        "invalid_identifier",
        "invalid_keys",
        "invalid_state",
        "invalid_type",
        "invalid_value",
        "limit_exceeded",
        "verdict_coverage_mismatch",
        "wire_invalid",
    }
)


class ReviewerContractError(ValueError):
    """Stable, path-free failure for every public D3 contract boundary."""

    taxonomy_version = REVIEWER_ERROR_TAXONOMY_VERSION

    def __init__(self, code: str, message: str) -> None:
        if type(code) is not str or code not in _ERROR_CODES or type(message) is not str:
            code = "invalid_value"
            message = "reviewer contract error code is invalid"
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ReviewerContractLimits:
    """Fixed D3 resource and wire limits; callers cannot expand them."""

    max_candidates: int = _MAX_CANDIDATES
    max_selections_per_criterion: int = _MAX_SELECTIONS_PER_CRITERION
    max_selections_per_verdict: int = _MAX_SELECTIONS_PER_VERDICT
    max_selections_per_batch: int = _MAX_SELECTIONS_PER_BATCH
    max_artifacts_per_attempt: int = _MAX_ARTIFACTS_PER_ATTEMPT
    max_model_records: int = _MAX_MODEL_RECORDS
    max_tool_records: int = _MAX_TOOL_RECORDS
    max_source_reads: int = _MAX_SOURCE_READS
    max_budget_events: int = _MAX_BUDGET_EVENTS
    max_missing_information: int = _MAX_MISSING_INFORMATION
    max_json_depth: int = _MAX_JSON_DEPTH
    max_json_nodes: int = _MAX_JSON_NODES
    max_string_chars: int = _MAX_STRING_CHARS
    max_wire_bytes: int = _MAX_WIRE_BYTES
    limits_version: str = REVIEWER_LIMITS_VERSION

    def __post_init__(self) -> None:
        expected = {
            "max_candidates": _MAX_CANDIDATES,
            "max_selections_per_criterion": _MAX_SELECTIONS_PER_CRITERION,
            "max_selections_per_verdict": _MAX_SELECTIONS_PER_VERDICT,
            "max_selections_per_batch": _MAX_SELECTIONS_PER_BATCH,
            "max_artifacts_per_attempt": _MAX_ARTIFACTS_PER_ATTEMPT,
            "max_model_records": _MAX_MODEL_RECORDS,
            "max_tool_records": _MAX_TOOL_RECORDS,
            "max_source_reads": _MAX_SOURCE_READS,
            "max_budget_events": _MAX_BUDGET_EVENTS,
            "max_missing_information": _MAX_MISSING_INFORMATION,
            "max_json_depth": _MAX_JSON_DEPTH,
            "max_json_nodes": _MAX_JSON_NODES,
            "max_string_chars": _MAX_STRING_CHARS,
            "max_wire_bytes": _MAX_WIRE_BYTES,
        }
        if type(self.limits_version) is not str or self.limits_version != REVIEWER_LIMITS_VERSION:
            raise ReviewerContractError(
                "invalid_value", "limits_version does not match the D3 policy"
            )
        for name, fixed in expected.items():
            value = getattr(self, name)
            if type(value) is not int or value != fixed:
                raise ReviewerContractError(
                    "invalid_value", f"{name} must equal the D3 fixed limit {fixed}"
                )

    def to_dict(self) -> dict[str, int | str]:
        return {
            "limits_version": self.limits_version,
            "max_artifacts_per_attempt": self.max_artifacts_per_attempt,
            "max_budget_events": self.max_budget_events,
            "max_candidates": self.max_candidates,
            "max_json_depth": self.max_json_depth,
            "max_json_nodes": self.max_json_nodes,
            "max_missing_information": self.max_missing_information,
            "max_model_records": self.max_model_records,
            "max_selections_per_batch": self.max_selections_per_batch,
            "max_selections_per_criterion": self.max_selections_per_criterion,
            "max_selections_per_verdict": self.max_selections_per_verdict,
            "max_source_reads": self.max_source_reads,
            "max_string_chars": self.max_string_chars,
            "max_tool_records": self.max_tool_records,
            "max_wire_bytes": self.max_wire_bytes,
        }


DEFAULT_REVIEWER_LIMITS: Final[ReviewerContractLimits] = ReviewerContractLimits()


def _identifier(value: Any, *, pattern: re.Pattern[str], name: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ReviewerContractError(
            "invalid_identifier", f"{name} has an invalid format"
        )
    return value


def _ordered_values(value: Any, *, name: str, maximum: int) -> tuple[Any, ...]:
    if type(value) not in (tuple, list):
        raise ReviewerContractError(
            "invalid_type", f"{name} must be an ordered collection"
        )
    snapshot = value if type(value) is tuple else tuple(value[: maximum + 1])
    if len(snapshot) > maximum:
        raise ReviewerContractError("limit_exceeded", f"{name} exceeds its limit")
    return snapshot


def _strict_object(
    value: Any, *, expected: frozenset[str], name: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReviewerContractError("invalid_type", f"{name} must be an object")
    try:
        keys = tuple(value)
    except Exception:
        raise ReviewerContractError("invalid_type", f"{name} must be an object") from None
    if any(type(key) is not str for key in keys):
        raise ReviewerContractError("invalid_keys", f"{name} keys must be strings")
    if frozenset(keys) != expected or len(keys) != len(expected):
        raise ReviewerContractError(
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
            raw = chunk.encode("utf-8")
            if len(encoded) + len(raw) > _MAX_WIRE_BYTES:
                raise ReviewerContractError(
                    "limit_exceeded", "reviewer wire value exceeds its byte limit"
                )
            encoded.extend(raw)
    except ReviewerContractError:
        raise
    except Exception:
        raise ReviewerContractError(
            "wire_invalid", "reviewer value is not canonical JSON"
        ) from None
    return bytes(encoded)


def _digest(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + _canonical_bytes(value)).hexdigest()


def _detach_bounded_json(value: Any) -> Any:
    nodes = 0

    def claim(depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise ReviewerContractError(
                "limit_exceeded", "reviewer wire value exceeds its node limit"
            )
        if depth > _MAX_JSON_DEPTH:
            raise ReviewerContractError(
                "limit_exceeded", "reviewer wire value exceeds its depth limit"
            )

    def checked_text(item: str) -> str:
        if len(item) > _MAX_STRING_CHARS:
            raise ReviewerContractError(
                "limit_exceeded", "reviewer wire string exceeds its length limit"
            )
        try:
            item.encode("utf-8")
        except UnicodeError:
            raise ReviewerContractError(
                "wire_invalid", "reviewer wire text is not valid Unicode"
            ) from None
        return item

    def visit(item: Any, depth: int) -> Any:
        claim(depth)
        if item is None or type(item) in (bool, int):
            if type(item) is int and item.bit_length() > (
                _MAX_WIRE_BYTES * 4
            ):
                raise ReviewerContractError(
                    "limit_exceeded", "reviewer wire integer exceeds its byte limit"
                )
            return item
        if type(item) is str:
            return checked_text(item)
        if isinstance(item, Mapping):
            detached: dict[str, Any] = {}
            if type(item) is dict and len(item) > (
                _MAX_JSON_NODES - nodes
            ) // 2:
                raise ReviewerContractError(
                    "limit_exceeded", "reviewer wire object exceeds its node limit"
                )
            try:
                iterator = iter(item)
            except Exception:
                raise ReviewerContractError(
                    "wire_invalid", "reviewer wire object cannot be inspected"
                ) from None
            while True:
                try:
                    key = next(iterator)
                except StopIteration:
                    break
                except Exception:
                    raise ReviewerContractError(
                        "wire_invalid", "reviewer wire object cannot be inspected"
                    ) from None
                claim(depth + 1)
                if type(key) is not str:
                    raise ReviewerContractError(
                        "invalid_keys", "reviewer wire object keys must be strings"
                    )
                checked_text(key)
                if key in detached:
                    raise ReviewerContractError(
                        "invalid_keys", "reviewer wire object keys must be unique"
                    )
                if nodes >= _MAX_JSON_NODES:
                    raise ReviewerContractError(
                        "limit_exceeded", "reviewer wire value exceeds its node limit"
                    )
                try:
                    child = item[key]
                except Exception:
                    raise ReviewerContractError(
                        "wire_invalid", "reviewer wire object cannot be inspected"
                    ) from None
                detached[key] = visit(child, depth + 1)
            return detached
        if type(item) is list:
            if len(item) > _MAX_JSON_NODES - nodes:
                raise ReviewerContractError(
                    "limit_exceeded", "reviewer wire value exceeds its node limit"
                )
            return [visit(child, depth + 1) for child in item]
        raise ReviewerContractError(
            "invalid_type", "reviewer wire contains a non-JSON value"
        )

    try:
        return visit(value, 0)
    except ReviewerContractError:
        raise
    except Exception:
        raise ReviewerContractError(
            "wire_invalid", "reviewer wire value cannot be inspected"
        ) from None


def _bounded_wire_object(value: Any, *, name: str) -> Mapping[str, Any]:
    detached = _detach_bounded_json(value)
    _canonical_bytes(detached)
    if type(detached) is not dict:
        raise ReviewerContractError("invalid_type", f"{name} must be an object")
    return detached


class _DuplicateWireKey(ValueError):
    pass


def _decode_wire(value: Any) -> Mapping[str, Any]:
    if type(value) is str:
        if not value or len(value) > _MAX_WIRE_BYTES:
            raise ReviewerContractError(
                "limit_exceeded", "reviewer wire bytes are empty or exceed their limit"
            )
        try:
            raw = str.encode(value, "utf-8")
        except Exception:
            raise ReviewerContractError(
                "wire_invalid", "reviewer wire text is not valid UTF-8"
            ) from None
    elif type(value) is bytes:
        raw = value
    elif type(value) is bytearray:
        if not value or len(value) > _MAX_WIRE_BYTES:
            raise ReviewerContractError(
                "limit_exceeded", "reviewer wire bytes are empty or exceed their limit"
            )
        raw = bytes(value)
    elif type(value) is memoryview:
        try:
            if value.nbytes > _MAX_WIRE_BYTES:
                raise ReviewerContractError(
                    "limit_exceeded",
                    "reviewer wire bytes are empty or exceed their limit",
                )
            raw = bytes(value)
        except ReviewerContractError:
            raise
        except Exception:
            raise ReviewerContractError(
                "wire_invalid", "reviewer wire bytes are unavailable"
            ) from None
    else:
        raise ReviewerContractError(
            "invalid_type", "reviewer wire must be UTF-8 text or bytes"
        )
    if not raw or len(raw) > _MAX_WIRE_BYTES:
        raise ReviewerContractError(
            "limit_exceeded", "reviewer wire bytes are empty or exceed their limit"
        )
    try:
        text = raw.decode("utf-8")

        def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, child in pairs:
                if key in result:
                    raise _DuplicateWireKey("duplicate reviewer wire key")
                result[key] = child
            return result

        def invalid_constant(_: str) -> Any:
            raise ValueError("non-finite reviewer number")

        decoded = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=invalid_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError):
        raise ReviewerContractError(
            "wire_invalid", "reviewer wire is not strict JSON"
        ) from None
    decoded = _detach_bounded_json(decoded)
    if _canonical_bytes(decoded) != raw:
        raise ReviewerContractError(
            "wire_invalid", "reviewer wire is not in canonical form"
        )
    if type(decoded) is not dict:
        raise ReviewerContractError(
            "invalid_type", "reviewer wire root must be an object"
        )
    return decoded


def _exact_text(*values: object) -> bool:
    for value in values:
        if type(value) is not str or len(value) > _MAX_STRING_CHARS:
            return False
        try:
            value.encode("utf-8")
        except UnicodeError:
            return False
    return True


def _producer_draft_has_exact_types(draft: object) -> bool:
    def exact_location(location: object) -> bool:
        return (
            type(location) is DiscoveryLocation
            and _exact_text(location.file, location.code_sha256)
            and type(location.line_start) is int
            and type(location.line_end) is int
            and 1
            <= location.line_start
            <= location.line_end
            <= _MAX_UPSTREAM_LINE
            and location.line_end - location.line_start + 1
            <= _MAX_UPSTREAM_LOCATION_SPAN
        )

    def exact_task(task: object) -> bool:
        return (
            type(task) is DiscoveryTaskInputV1
            and _exact_text(
                task.task_id,
                task.repo_url,
                task.commit,
                task.instruction_id,
                task.snapshot_manifest_sha256,
                task.snapshot_content_root,
                task.snapshot_id,
            )
            and type(task.contract_version) is int
            and task.contract_version == 1
        )

    def exact_candidate(candidate: object) -> bool:
        return (
            type(candidate) is DiscoveryCandidate
            and _exact_text(
                candidate.task_id,
                candidate.snapshot_id,
                candidate.repo_url,
                candidate.commit,
                candidate.candidate_id,
            )
            and type(candidate.contract_version) is int
            and candidate.contract_version == 1
            and exact_location(candidate.entry_point)
            and exact_location(candidate.critical_operation)
            and type(candidate.trace) is tuple
            and len(candidate.trace) <= _MAX_UPSTREAM_TRACE_NODES
            and all(exact_location(item) for item in candidate.trace)
            and type(candidate.relationship_evidence_refs) is tuple
            and type(candidate.source_evidence_refs) is tuple
            and len(candidate.relationship_evidence_refs)
            <= _MAX_UPSTREAM_EVIDENCE_REFS
            and len(candidate.source_evidence_refs)
            <= _MAX_UPSTREAM_EVIDENCE_REFS
            and _exact_text(*candidate.relationship_evidence_refs)
            and _exact_text(*candidate.source_evidence_refs)
        )

    def exact_artifact(ref: object) -> bool:
        return (
            type(ref) is ProducerArtifactDigestRefV1
            and _exact_text(ref.artifact_id, ref.artifact_sha256)
            and type(ref.contract_version) is int
            and ref.contract_version == 1
        )

    def exact_receipt(receipt: object) -> bool:
        return (
            type(receipt) is ValidationReceiptV1
            and _exact_text(
                receipt.candidate_id,
                receipt.candidate_sha256,
                receipt.validation_artifact_id,
                receipt.validation_artifact_sha256,
                receipt.selection_digest,
            )
            and type(receipt.contract_version) is int
            and receipt.contract_version == 1
            and type(receipt.dependencies) is tuple
            and len(receipt.dependencies) <= _MAX_UPSTREAM_RECEIPT_DEPENDENCIES
            and all(exact_artifact(item) for item in receipt.dependencies)
        )

    exact = (
        type(draft) is ProducerDraftV1
        and exact_task(draft.task)
        and _exact_text(draft.coverage_status, draft.policy_version)
        and type(draft.contract_version) is int
        and draft.contract_version == 1
        and type(draft.candidates) is tuple
        and type(draft.validation_receipts) is tuple
        and len(draft.candidates) <= _MAX_CANDIDATES
        and len(draft.validation_receipts) <= _MAX_CANDIDATES
        and all(exact_candidate(item) for item in draft.candidates)
        and all(exact_receipt(item) for item in draft.validation_receipts)
    )
    if not exact:
        return False
    artifact_ids = {
        artifact_id
        for candidate in draft.candidates
        for artifact_id in (
            *candidate.source_evidence_refs,
            *candidate.relationship_evidence_refs,
        )
    }
    artifact_ids.update(
        receipt.validation_artifact_id for receipt in draft.validation_receipts
    )
    artifact_ids.update(
        dependency.artifact_id
        for receipt in draft.validation_receipts
        for dependency in receipt.dependencies
    )
    return len(artifact_ids) <= _MAX_UPSTREAM_ARTIFACT_IDS


def _canonical_producer_draft(value: Any) -> ProducerDraftV1:
    if not _producer_draft_has_exact_types(value):
        raise ReviewerContractError(
            "invalid_type", "producer_draft contains a polymorphic contract value"
        )
    try:
        wire = _canonical_bytes(value.to_dict())
        if len(wire) > _MAX_UPSTREAM_WIRE_BYTES:
            raise ReviewerContractError(
                "limit_exceeded", "producer_draft exceeds the D2 wire limit"
            )
        return ProducerDraftV1.from_wire(wire)
    except ReviewerContractError:
        raise
    except (ProducerContractError, TypeError, ValueError):
        raise ReviewerContractError(
            "invalid_binding", "producer_draft did not pass strict normalization"
        ) from None


def _count(value: Any, *, name: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ReviewerContractError(
            "invalid_value", f"{name} must be a bounded non-negative integer"
        )
    return value


@dataclass(frozen=True, slots=True)
class ReviewerInputV1:
    """Self-contained, digest-bound D2 draft accepted by the D3 reviewer."""

    producer_draft: ProducerDraftV1
    instruction_id: str = REVIEWER_INSTRUCTION_ID
    policy_version: str = REVIEWER_POLICY_VERSION
    contract_version: int = REVIEWER_CONTRACT_VERSION
    review_input_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ReviewerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        if type(self.instruction_id) is not str or self.instruction_id != REVIEWER_INSTRUCTION_ID:
            raise ReviewerContractError(
                "invalid_value", "instruction_id does not match the D3 reviewer"
            )
        if type(self.policy_version) is not str or self.policy_version != REVIEWER_POLICY_VERSION:
            raise ReviewerContractError(
                "invalid_value", "policy_version does not match D3"
            )
        draft = _canonical_producer_draft(self.producer_draft)
        object.__setattr__(self, "producer_draft", draft)
        object.__setattr__(
            self,
            "review_input_sha256",
            _digest(REVIEWER_INPUT_DIGEST_DOMAIN, self._digest_dict()),
        )
        _canonical_bytes(self.to_dict())

    @property
    def input_type(self) -> Literal["review_input"]:
        return "review_input"

    @property
    def task_id(self) -> str:
        return self.producer_draft.task_id

    @property
    def snapshot_id(self) -> str:
        return self.producer_draft.snapshot_id

    @property
    def manifest_sha256(self) -> str:
        return self.producer_draft.manifest_sha256

    @property
    def content_root(self) -> str:
        return self.producer_draft.content_root

    def _digest_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "input_type": self.input_type,
            "instruction_id": self.instruction_id,
            "policy_version": self.policy_version,
            "producer_draft": self.producer_draft.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ReviewerInputV1":
        item = _strict_object(
            _bounded_wire_object(value, name="ReviewerInputV1"),
            expected=frozenset(
                {
                    "contract_version",
                    "input_type",
                    "instruction_id",
                    "policy_version",
                    "producer_draft",
                    "review_input_sha256",
                }
            ),
            name="ReviewerInputV1",
        )
        if item["input_type"] != "review_input":
            raise ReviewerContractError(
                "invalid_state", "reviewer input_type must be review_input"
            )
        try:
            draft = ProducerDraftV1.from_dict(item["producer_draft"])
        except ProducerContractError:
            raise ReviewerContractError(
                "invalid_binding", "nested producer draft is invalid"
            ) from None
        result = cls(
            producer_draft=draft,
            instruction_id=item["instruction_id"],
            policy_version=item["policy_version"],
            contract_version=item["contract_version"],
        )
        if type(item["review_input_sha256"]) is not str or item["review_input_sha256"] != result.review_input_sha256:
            raise ReviewerContractError(
                "invalid_binding", "review_input_sha256 does not match its input"
            )
        return result

    @classmethod
    def from_wire(cls, value: Any) -> "ReviewerInputV1":
        return cls.from_dict(_decode_wire(value))

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._digest_dict(),
            "review_input_sha256": self.review_input_sha256,
        }

    def to_wire(self) -> bytes:
        return _canonical_bytes(self.to_dict())


def _canonical_reviewer_input(value: Any) -> ReviewerInputV1:
    if type(value) is not ReviewerInputV1:
        raise ReviewerContractError(
            "invalid_type", "review_input must be ReviewerInputV1"
        )
    canonical = ReviewerInputV1(
        producer_draft=value.producer_draft,
        instruction_id=value.instruction_id,
        policy_version=value.policy_version,
        contract_version=value.contract_version,
    )
    if (
        type(value.review_input_sha256) is not str
        or value.review_input_sha256 != canonical.review_input_sha256
    ):
        raise ReviewerContractError(
            "invalid_binding", "review_input_sha256 does not match its input"
        )
    return canonical


@dataclass(frozen=True, slots=True)
class ReviewerEvidenceSelectionV1:
    """One D3-issued artifact/node capability selected for a criterion."""

    artifact_id: str
    artifact_sha256: str
    node_id: str
    contract_version: int = REVIEWER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ReviewerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        _identifier(self.artifact_id, pattern=_ARTIFACT_ID_RE, name="artifact_id")
        _identifier(
            self.artifact_sha256, pattern=_SHA256_RE, name="artifact_sha256"
        )
        _identifier(self.node_id, pattern=_NODE_ID_RE, name="node_id")
        _canonical_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "ReviewerEvidenceSelectionV1":
        item = _strict_object(
            _bounded_wire_object(value, name="ReviewerEvidenceSelectionV1"),
            expected=frozenset(
                {"artifact_id", "artifact_sha256", "contract_version", "node_id"}
            ),
            name="ReviewerEvidenceSelectionV1",
        )
        return cls(
            artifact_id=item["artifact_id"],
            artifact_sha256=item["artifact_sha256"],
            node_id=item["node_id"],
            contract_version=item["contract_version"],
        )

    def to_dict(self) -> dict[str, str | int]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "contract_version": self.contract_version,
            "node_id": self.node_id,
        }


@dataclass(frozen=True, slots=True)
class ReviewerCriterionV1:
    """One fixed reviewer criterion with a bounded three-valued assessment."""

    criterion: Literal[
        "entry_role",
        "critical_role",
        "trace_continuity",
        "counterevidence_status",
    ]
    assessment: Literal["supported", "contradicted", "insufficient"]
    selections: tuple[ReviewerEvidenceSelectionV1, ...]
    contract_version: int = REVIEWER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ReviewerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        if type(self.criterion) is not str or self.criterion not in REVIEWER_CRITERIA:
            raise ReviewerContractError(
                "invalid_value", "criterion is not part of the D3 policy"
            )
        if type(self.assessment) is not str or self.assessment not in REVIEWER_ASSESSMENTS:
            raise ReviewerContractError(
                "invalid_value", "assessment must use the D3 three-value policy"
            )
        selections = _ordered_values(
            self.selections,
            name="selections",
            maximum=_MAX_SELECTIONS_PER_CRITERION,
        )
        canonical_selections: list[ReviewerEvidenceSelectionV1] = []
        for item in selections:
            if type(item) is not ReviewerEvidenceSelectionV1:
                raise ReviewerContractError(
                    "invalid_type", "selections contain an invalid value"
                )
            canonical_selections.append(
                ReviewerEvidenceSelectionV1(
                    artifact_id=item.artifact_id,
                    artifact_sha256=item.artifact_sha256,
                    node_id=item.node_id,
                    contract_version=item.contract_version,
                )
            )
        selections = tuple(canonical_selections)
        selections = tuple(
            sorted(selections, key=lambda item: (item.artifact_id, item.node_id))
        )
        identities = [(item.artifact_id, item.node_id) for item in selections]
        if len(identities) != len(set(identities)):
            raise ReviewerContractError(
                "invalid_value", "criterion selections must not repeat a node"
            )
        digests: dict[str, str] = {}
        for selection in selections:
            previous = digests.setdefault(
                selection.artifact_id, selection.artifact_sha256
            )
            if previous != selection.artifact_sha256:
                raise ReviewerContractError(
                    "invalid_binding", "one artifact ID has conflicting digests"
                )
        if self.assessment in {"supported", "contradicted"} and not selections:
            raise ReviewerContractError(
                "invalid_state", "conclusive criteria require fresh D3 evidence"
            )
        object.__setattr__(self, "selections", selections)
        _canonical_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "ReviewerCriterionV1":
        item = _strict_object(
            _bounded_wire_object(value, name="ReviewerCriterionV1"),
            expected=frozenset(
                {"assessment", "contract_version", "criterion", "selections"}
            ),
            name="ReviewerCriterionV1",
        )
        selections = item["selections"]
        if type(selections) is not list:
            raise ReviewerContractError(
                "invalid_type", "criterion selections must be an array"
            )
        return cls(
            criterion=item["criterion"],
            assessment=item["assessment"],
            selections=tuple(
                ReviewerEvidenceSelectionV1.from_dict(child) for child in selections
            ),
            contract_version=item["contract_version"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment": self.assessment,
            "contract_version": self.contract_version,
            "criterion": self.criterion,
            "selections": [item.to_dict() for item in self.selections],
        }


def _canonical_criterion(value: Any) -> ReviewerCriterionV1:
    if type(value) is not ReviewerCriterionV1:
        raise ReviewerContractError(
            "invalid_type", "criteria contain an invalid value"
        )
    return ReviewerCriterionV1(
        criterion=value.criterion,
        assessment=value.assessment,
        selections=value.selections,
        contract_version=value.contract_version,
    )


def _derive_decision(criteria: tuple[ReviewerCriterionV1, ...]) -> str:
    assessments = tuple(item.assessment for item in criteria)
    if "contradicted" in assessments:
        return "reject"
    if assessments and all(item == "supported" for item in assessments):
        return "accept"
    return "defer"


@dataclass(frozen=True, slots=True)
class ReviewerCandidateVerdictV1:
    """Controller-derived verdict for one exact producer candidate."""

    candidate_id: str
    candidate_sha256: str
    review_input_sha256: str
    criteria: tuple[ReviewerCriterionV1, ...]
    context_sha256: str
    validation_artifact_id: str
    validation_artifact_sha256: str
    model_record_sha256: str | None = None
    validation_contract_id: str = REVIEWER_VALIDATION_CONTRACT_ID
    contract_version: int = REVIEWER_CONTRACT_VERSION
    decision: Literal["accept", "reject", "defer"] = field(init=False)
    selection_digest: str = field(init=False)
    verdict_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ReviewerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        _identifier(self.candidate_id, pattern=_CANDIDATE_ID_RE, name="candidate_id")
        _identifier(
            self.candidate_sha256, pattern=_SHA256_RE, name="candidate_sha256"
        )
        _identifier(
            self.review_input_sha256,
            pattern=_SHA256_RE,
            name="review_input_sha256",
        )
        _identifier(self.context_sha256, pattern=_SHA256_RE, name="context_sha256")
        _identifier(
            self.validation_artifact_id,
            pattern=_ARTIFACT_ID_RE,
            name="validation_artifact_id",
        )
        _identifier(
            self.validation_artifact_sha256,
            pattern=_SHA256_RE,
            name="validation_artifact_sha256",
        )
        if (
            type(self.validation_contract_id) is not str
            or self.validation_contract_id != REVIEWER_VALIDATION_CONTRACT_ID
        ):
            raise ReviewerContractError(
                "invalid_value", "validation_contract_id does not match D3"
            )
        if self.model_record_sha256 is not None:
            _identifier(
                self.model_record_sha256,
                pattern=_SHA256_RE,
                name="model_record_sha256",
            )
        criteria = _ordered_values(
            self.criteria, name="criteria", maximum=len(REVIEWER_CRITERIA)
        )
        criteria = tuple(_canonical_criterion(item) for item in criteria)
        rank = {name: index for index, name in enumerate(REVIEWER_CRITERIA)}
        criteria = tuple(sorted(criteria, key=lambda item: rank[item.criterion]))
        if tuple(item.criterion for item in criteria) != REVIEWER_CRITERIA:
            raise ReviewerContractError(
                "invalid_state", "verdict requires each fixed criterion exactly once"
            )
        selection_count = sum(len(item.selections) for item in criteria)
        if selection_count > _MAX_SELECTIONS_PER_VERDICT:
            raise ReviewerContractError(
                "limit_exceeded", "verdict has too many evidence selections"
            )
        digests: dict[str, str] = {}
        for criterion in criteria:
            for selection in criterion.selections:
                previous = digests.setdefault(
                    selection.artifact_id, selection.artifact_sha256
                )
                if previous != selection.artifact_sha256:
                    raise ReviewerContractError(
                        "invalid_binding", "one artifact ID has conflicting digests"
                    )
        if self.validation_artifact_id in digests:
            raise ReviewerContractError(
                "artifact_coverage_mismatch",
                "validation artifacts cannot be criterion evidence",
            )
        object.__setattr__(self, "criteria", criteria)
        decision = _derive_decision(criteria)
        if (
            any(item.assessment != "insufficient" for item in criteria)
            and self.model_record_sha256 is None
        ):
            raise ReviewerContractError(
                "invalid_state", "conclusive criteria require a model record binding"
            )
        object.__setattr__(self, "decision", decision)
        selection_digest = _digest(
            REVIEWER_SELECTION_DIGEST_DOMAIN,
            {
                "candidate_id": self.candidate_id,
                "candidate_sha256": self.candidate_sha256,
                "context_sha256": self.context_sha256,
                "criteria": [item.to_dict() for item in criteria],
                "review_input_sha256": self.review_input_sha256,
            },
        )
        object.__setattr__(self, "selection_digest", selection_digest)
        object.__setattr__(
            self,
            "verdict_sha256",
            _digest(REVIEWER_VERDICT_DIGEST_DOMAIN, self._digest_dict()),
        )
        _canonical_bytes(self.to_dict())

    @property
    def reason_codes(self) -> tuple[str, ...]:
        return tuple(
            f"review.{item.criterion}.{item.assessment}" for item in self.criteria
        ) + (f"review.decision.{self.decision}",)

    def assert_candidate(
        self, candidate: DiscoveryCandidate, *, review_input_sha256: str
    ) -> None:
        if type(candidate) is not DiscoveryCandidate or (
            self.candidate_id,
            self.candidate_sha256,
            self.review_input_sha256,
        ) != (
            candidate.candidate_id,
            candidate.candidate_sha256,
            review_input_sha256,
        ):
            raise ReviewerContractError(
                "invalid_binding", "reviewer verdict does not match its candidate"
            )

    def _digest_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_sha256": self.candidate_sha256,
            "contract_version": self.contract_version,
            "context_sha256": self.context_sha256,
            "criteria": [item.to_dict() for item in self.criteria],
            "decision": self.decision,
            "model_record_sha256": self.model_record_sha256,
            "review_input_sha256": self.review_input_sha256,
            "selection_digest": self.selection_digest,
            "validation_artifact_id": self.validation_artifact_id,
            "validation_artifact_sha256": self.validation_artifact_sha256,
            "validation_contract_id": self.validation_contract_id,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ReviewerCandidateVerdictV1":
        item = _strict_object(
            _bounded_wire_object(value, name="ReviewerCandidateVerdictV1"),
            expected=frozenset(
                {
                    "candidate_id",
                    "candidate_sha256",
                    "contract_version",
                    "context_sha256",
                    "criteria",
                    "decision",
                    "model_record_sha256",
                    "review_input_sha256",
                    "selection_digest",
                    "validation_artifact_id",
                    "validation_artifact_sha256",
                    "validation_contract_id",
                    "verdict_sha256",
                }
            ),
            name="ReviewerCandidateVerdictV1",
        )
        criteria = item["criteria"]
        if type(criteria) is not list:
            raise ReviewerContractError("invalid_type", "criteria must be an array")
        result = cls(
            candidate_id=item["candidate_id"],
            candidate_sha256=item["candidate_sha256"],
            review_input_sha256=item["review_input_sha256"],
            criteria=tuple(ReviewerCriterionV1.from_dict(child) for child in criteria),
            context_sha256=item["context_sha256"],
            validation_artifact_id=item["validation_artifact_id"],
            validation_artifact_sha256=item["validation_artifact_sha256"],
            model_record_sha256=item["model_record_sha256"],
            validation_contract_id=item["validation_contract_id"],
            contract_version=item["contract_version"],
        )
        for name in ("decision", "selection_digest", "verdict_sha256"):
            if type(item[name]) is not str or item[name] != getattr(result, name):
                raise ReviewerContractError(
                    "invalid_binding", f"{name} does not match the reviewer verdict"
                )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {**self._digest_dict(), "verdict_sha256": self.verdict_sha256}


def _canonical_verdict(value: Any) -> ReviewerCandidateVerdictV1:
    if type(value) is not ReviewerCandidateVerdictV1:
        raise ReviewerContractError(
            "invalid_type", "verdicts contain an invalid value"
        )
    canonical = ReviewerCandidateVerdictV1(
        candidate_id=value.candidate_id,
        candidate_sha256=value.candidate_sha256,
        review_input_sha256=value.review_input_sha256,
        criteria=value.criteria,
        context_sha256=value.context_sha256,
        validation_artifact_id=value.validation_artifact_id,
        validation_artifact_sha256=value.validation_artifact_sha256,
        model_record_sha256=value.model_record_sha256,
        validation_contract_id=value.validation_contract_id,
        contract_version=value.contract_version,
    )
    for name in ("decision", "selection_digest", "verdict_sha256"):
        if type(getattr(value, name)) is not str or getattr(value, name) != getattr(
            canonical, name
        ):
            raise ReviewerContractError(
                "invalid_binding", f"{name} does not match the reviewer verdict"
            )
    return canonical


@dataclass(frozen=True, slots=True)
class ReviewerArtifactDigestRefV1:
    """Portable D3 artifact ID+digest pair used by an attempt seal."""

    artifact_id: str
    artifact_sha256: str
    contract_version: int = REVIEWER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ReviewerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        _identifier(self.artifact_id, pattern=_ARTIFACT_ID_RE, name="artifact_id")
        _identifier(
            self.artifact_sha256, pattern=_SHA256_RE, name="artifact_sha256"
        )
        _canonical_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Any) -> "ReviewerArtifactDigestRefV1":
        item = _strict_object(
            _bounded_wire_object(value, name="ReviewerArtifactDigestRefV1"),
            expected=frozenset(
                {"artifact_id", "artifact_sha256", "contract_version"}
            ),
            name="ReviewerArtifactDigestRefV1",
        )
        return cls(
            artifact_id=item["artifact_id"],
            artifact_sha256=item["artifact_sha256"],
            contract_version=item["contract_version"],
        )

    def to_dict(self) -> dict[str, str | int]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "contract_version": self.contract_version,
        }


@dataclass(frozen=True, slots=True)
class ReviewerAttemptSealV1:
    """Digest-only closure of one independently owned D3 runtime attempt."""

    review_input_sha256: str
    task_id: str
    snapshot_id: str
    manifest_sha256: str
    content_root: str
    tool_transcript_sha256: str
    tool_record_count: int
    model_transcript_sha256: str
    model_record_count: int
    source_ledger_sha256: str
    source_read_count: int
    artifact_catalog_root_sha256: str
    artifact_count: int
    budget_ledger_sha256: str
    budget_event_count: int
    used_artifacts: tuple[ReviewerArtifactDigestRefV1, ...]
    used_model_records: tuple[str, ...]
    attempt: int = 0
    policy_scope: str = REVIEWER_SCOPE
    contract_version: int = REVIEWER_CONTRACT_VERSION
    seal_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ReviewerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        if type(self.attempt) is not int or self.attempt != 0:
            raise ReviewerContractError(
                "invalid_state", "D3 reviewer attempt must be integer 0"
            )
        if type(self.policy_scope) is not str or self.policy_scope != REVIEWER_SCOPE:
            raise ReviewerContractError(
                "invalid_state", "policy_scope must be d3.review"
            )
        _identifier(
            self.review_input_sha256,
            pattern=_SHA256_RE,
            name="review_input_sha256",
        )
        _identifier(self.task_id, pattern=_TASK_ID_RE, name="task_id")
        _identifier(self.snapshot_id, pattern=_SNAPSHOT_ID_RE, name="snapshot_id")
        for name, value in (
            ("manifest_sha256", self.manifest_sha256),
            ("content_root", self.content_root),
            ("tool_transcript_sha256", self.tool_transcript_sha256),
            ("model_transcript_sha256", self.model_transcript_sha256),
            ("source_ledger_sha256", self.source_ledger_sha256),
            ("artifact_catalog_root_sha256", self.artifact_catalog_root_sha256),
            ("budget_ledger_sha256", self.budget_ledger_sha256),
        ):
            _identifier(value, pattern=_SHA256_RE, name=name)
        _count(
            self.tool_record_count,
            name="tool_record_count",
            maximum=_MAX_TOOL_RECORDS,
        )
        _count(
            self.model_record_count,
            name="model_record_count",
            maximum=_MAX_MODEL_RECORDS,
        )
        _count(
            self.source_read_count,
            name="source_read_count",
            maximum=_MAX_SOURCE_READS,
        )
        _count(
            self.artifact_count,
            name="artifact_count",
            maximum=_MAX_ARTIFACTS_PER_ATTEMPT,
        )
        _count(
            self.budget_event_count,
            name="budget_event_count",
            maximum=_MAX_BUDGET_EVENTS,
        )
        artifacts = _ordered_values(
            self.used_artifacts,
            name="used_artifacts",
            maximum=_MAX_ARTIFACTS_PER_ATTEMPT,
        )
        canonical_artifacts: list[ReviewerArtifactDigestRefV1] = []
        for item in artifacts:
            if type(item) is not ReviewerArtifactDigestRefV1:
                raise ReviewerContractError(
                    "invalid_type", "used_artifacts contain an invalid value"
                )
            canonical_artifacts.append(
                ReviewerArtifactDigestRefV1(
                    artifact_id=item.artifact_id,
                    artifact_sha256=item.artifact_sha256,
                    contract_version=item.contract_version,
                )
            )
        artifacts = tuple(canonical_artifacts)
        artifacts = tuple(sorted(artifacts, key=lambda item: item.artifact_id))
        artifact_ids = [item.artifact_id for item in artifacts]
        if len(artifact_ids) != len(set(artifact_ids)):
            raise ReviewerContractError(
                "artifact_coverage_mismatch", "used_artifacts repeat an artifact ID"
            )
        artifact_digests = [item.artifact_sha256 for item in artifacts]
        if len(artifact_digests) != len(set(artifact_digests)):
            raise ReviewerContractError(
                "artifact_coverage_mismatch",
                "used_artifacts repeat an artifact digest under a different ID",
            )
        if self.artifact_count < len(artifacts):
            raise ReviewerContractError(
                "artifact_coverage_mismatch",
                "artifact_count cannot be smaller than used_artifacts",
            )
        object.__setattr__(self, "used_artifacts", artifacts)
        model_records = _ordered_values(
            self.used_model_records,
            name="used_model_records",
            maximum=_MAX_MODEL_RECORDS,
        )
        if any(
            type(item) is not str or _SHA256_RE.fullmatch(item) is None
            for item in model_records
        ):
            raise ReviewerContractError(
                "invalid_identifier", "used_model_records contain an invalid digest"
            )
        model_records = tuple(sorted(model_records))
        if len(model_records) != len(set(model_records)):
            raise ReviewerContractError(
                "invalid_value", "used_model_records must not contain duplicates"
            )
        if self.model_record_count < len(model_records):
            raise ReviewerContractError(
                "invalid_binding",
                "model_record_count cannot be smaller than used_model_records",
            )
        object.__setattr__(self, "used_model_records", model_records)
        object.__setattr__(
            self,
            "seal_sha256",
            _digest(REVIEWER_ATTEMPT_SEAL_DIGEST_DOMAIN, self._digest_dict()),
        )
        _canonical_bytes(self.to_dict())

    def assert_input(self, review_input: ReviewerInputV1) -> None:
        if type(review_input) is not ReviewerInputV1 or (
            self.review_input_sha256,
            self.task_id,
            self.snapshot_id,
            self.manifest_sha256,
            self.content_root,
        ) != (
            review_input.review_input_sha256,
            review_input.task_id,
            review_input.snapshot_id,
            review_input.manifest_sha256,
            review_input.content_root,
        ):
            raise ReviewerContractError(
                "invalid_binding", "attempt seal does not match reviewer input"
            )

    def _digest_dict(self) -> dict[str, Any]:
        return {
            "artifact_catalog_root_sha256": self.artifact_catalog_root_sha256,
            "artifact_count": self.artifact_count,
            "attempt": self.attempt,
            "budget_event_count": self.budget_event_count,
            "budget_ledger_sha256": self.budget_ledger_sha256,
            "content_root": self.content_root,
            "contract_version": self.contract_version,
            "manifest_sha256": self.manifest_sha256,
            "model_record_count": self.model_record_count,
            "model_transcript_sha256": self.model_transcript_sha256,
            "policy_scope": self.policy_scope,
            "review_input_sha256": self.review_input_sha256,
            "snapshot_id": self.snapshot_id,
            "source_ledger_sha256": self.source_ledger_sha256,
            "source_read_count": self.source_read_count,
            "task_id": self.task_id,
            "tool_record_count": self.tool_record_count,
            "tool_transcript_sha256": self.tool_transcript_sha256,
            "used_artifacts": [item.to_dict() for item in self.used_artifacts],
            "used_model_records": list(self.used_model_records),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ReviewerAttemptSealV1":
        item = _strict_object(
            _bounded_wire_object(value, name="ReviewerAttemptSealV1"),
            expected=frozenset(
                {
                    "artifact_catalog_root_sha256",
                    "artifact_count",
                    "attempt",
                    "budget_event_count",
                    "budget_ledger_sha256",
                    "content_root",
                    "contract_version",
                    "manifest_sha256",
                    "model_record_count",
                    "model_transcript_sha256",
                    "policy_scope",
                    "review_input_sha256",
                    "seal_sha256",
                    "snapshot_id",
                    "source_ledger_sha256",
                    "source_read_count",
                    "task_id",
                    "tool_record_count",
                    "tool_transcript_sha256",
                    "used_artifacts",
                    "used_model_records",
                }
            ),
            name="ReviewerAttemptSealV1",
        )
        artifacts = item["used_artifacts"]
        if type(artifacts) is not list:
            raise ReviewerContractError(
                "invalid_type", "used_artifacts must be an array"
            )
        model_records = item["used_model_records"]
        if type(model_records) is not list:
            raise ReviewerContractError(
                "invalid_type", "used_model_records must be an array"
            )
        result = cls(
            review_input_sha256=item["review_input_sha256"],
            task_id=item["task_id"],
            snapshot_id=item["snapshot_id"],
            manifest_sha256=item["manifest_sha256"],
            content_root=item["content_root"],
            tool_transcript_sha256=item["tool_transcript_sha256"],
            tool_record_count=item["tool_record_count"],
            model_transcript_sha256=item["model_transcript_sha256"],
            model_record_count=item["model_record_count"],
            source_ledger_sha256=item["source_ledger_sha256"],
            source_read_count=item["source_read_count"],
            artifact_catalog_root_sha256=item["artifact_catalog_root_sha256"],
            artifact_count=item["artifact_count"],
            budget_ledger_sha256=item["budget_ledger_sha256"],
            budget_event_count=item["budget_event_count"],
            used_artifacts=tuple(
                ReviewerArtifactDigestRefV1.from_dict(child) for child in artifacts
            ),
            used_model_records=tuple(model_records),
            attempt=item["attempt"],
            policy_scope=item["policy_scope"],
            contract_version=item["contract_version"],
        )
        if type(item["seal_sha256"]) is not str or item["seal_sha256"] != result.seal_sha256:
            raise ReviewerContractError(
                "invalid_binding", "seal_sha256 does not match the attempt seal"
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {**self._digest_dict(), "seal_sha256": self.seal_sha256}


def _canonical_attempt_seal(value: Any) -> ReviewerAttemptSealV1:
    if type(value) is not ReviewerAttemptSealV1:
        raise ReviewerContractError(
            "invalid_type", "attempt_seal must be ReviewerAttemptSealV1"
        )
    canonical = ReviewerAttemptSealV1(
        review_input_sha256=value.review_input_sha256,
        task_id=value.task_id,
        snapshot_id=value.snapshot_id,
        manifest_sha256=value.manifest_sha256,
        content_root=value.content_root,
        tool_transcript_sha256=value.tool_transcript_sha256,
        tool_record_count=value.tool_record_count,
        model_transcript_sha256=value.model_transcript_sha256,
        model_record_count=value.model_record_count,
        source_ledger_sha256=value.source_ledger_sha256,
        source_read_count=value.source_read_count,
        artifact_catalog_root_sha256=value.artifact_catalog_root_sha256,
        artifact_count=value.artifact_count,
        budget_ledger_sha256=value.budget_ledger_sha256,
        budget_event_count=value.budget_event_count,
        used_artifacts=value.used_artifacts,
        used_model_records=value.used_model_records,
        attempt=value.attempt,
        policy_scope=value.policy_scope,
        contract_version=value.contract_version,
    )
    if type(value.seal_sha256) is not str or value.seal_sha256 != canonical.seal_sha256:
        raise ReviewerContractError(
            "invalid_binding", "seal_sha256 does not match the attempt seal"
        )
    return canonical


def _artifact_closure(
    verdicts: tuple[ReviewerCandidateVerdictV1, ...],
) -> tuple[ReviewerArtifactDigestRefV1, ...]:
    digests: dict[str, str] = {}
    for verdict in verdicts:
        for criterion in verdict.criteria:
            for selection in criterion.selections:
                previous = digests.setdefault(
                    selection.artifact_id, selection.artifact_sha256
                )
                if previous != selection.artifact_sha256:
                    raise ReviewerContractError(
                        "invalid_binding", "one artifact ID has conflicting digests"
                    )
        previous = digests.setdefault(
            verdict.validation_artifact_id, verdict.validation_artifact_sha256
        )
        if previous != verdict.validation_artifact_sha256:
            raise ReviewerContractError(
                "invalid_binding", "one artifact ID has conflicting digests"
            )
    return tuple(
        ReviewerArtifactDigestRefV1(artifact_id=item, artifact_sha256=digests[item])
        for item in sorted(digests)
    )


def _producer_artifact_ids(draft: ProducerDraftV1) -> frozenset[str]:
    return frozenset(
        {
            artifact_id
            for candidate in draft.candidates
            for artifact_id in (
                *candidate.source_evidence_refs,
                *candidate.relationship_evidence_refs,
            )
        }
        | {
            receipt.validation_artifact_id
            for receipt in draft.validation_receipts
        }
        | {
            dependency.artifact_id
            for receipt in draft.validation_receipts
            for dependency in receipt.dependencies
        }
    )


def _producer_artifact_digests(draft: ProducerDraftV1) -> frozenset[str]:
    """Return every artifact digest carried by the embedded D2 draft."""

    return frozenset(
        {
            receipt.validation_artifact_sha256
            for receipt in draft.validation_receipts
        }
        | {
            dependency.artifact_sha256
            for receipt in draft.validation_receipts
            for dependency in receipt.dependencies
        }
    )


def _assert_fresh_artifact_ids(
    review_input: ReviewerInputV1,
    artifacts: tuple[ReviewerArtifactDigestRefV1, ...],
) -> None:
    if _producer_artifact_ids(review_input.producer_draft) & {
        item.artifact_id for item in artifacts
    }:
        raise ReviewerContractError(
            "artifact_coverage_mismatch",
            "D3 artifacts must be disjoint from producer artifact IDs",
        )
    if _producer_artifact_digests(review_input.producer_draft) & {
        item.artifact_sha256 for item in artifacts
    }:
        raise ReviewerContractError(
            "artifact_coverage_mismatch",
            "D3 artifacts must be disjoint from producer artifact digests",
        )


@dataclass(frozen=True, slots=True)
class ReviewerFinalizedV1:
    """Atomic D3 batch with exact candidate/verdict and artifact closure."""

    review_input: ReviewerInputV1
    verdicts: tuple[ReviewerCandidateVerdictV1, ...]
    attempt_seal: ReviewerAttemptSealV1
    coverage_status: Literal["unknown"] = "unknown"
    policy_version: str = REVIEWER_POLICY_VERSION
    contract_version: int = REVIEWER_CONTRACT_VERSION
    result_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ReviewerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        if type(self.policy_version) is not str or self.policy_version != REVIEWER_POLICY_VERSION:
            raise ReviewerContractError(
                "invalid_value", "policy_version does not match D3"
            )
        if type(self.coverage_status) is not str or self.coverage_status != "unknown":
            raise ReviewerContractError(
                "invalid_state", "coverage_status must remain unknown"
            )
        canonical_input = _canonical_reviewer_input(self.review_input)
        object.__setattr__(self, "review_input", canonical_input)
        verdicts = _ordered_values(
            self.verdicts,
            name="verdicts",
            maximum=_MAX_CANDIDATES,
        )
        verdicts = tuple(_canonical_verdict(item) for item in verdicts)
        verdicts = tuple(sorted(verdicts, key=lambda item: item.candidate_id))
        verdict_ids = [item.candidate_id for item in verdicts]
        if len(verdict_ids) != len(set(verdict_ids)):
            raise ReviewerContractError(
                "duplicate_candidate", "reviewer result repeats a candidate verdict"
            )
        candidates = canonical_input.producer_draft.candidates
        by_id = {item.candidate_id: item for item in candidates}
        if set(verdict_ids) != set(by_id):
            raise ReviewerContractError(
                "verdict_coverage_mismatch",
                "finalized reviewer result requires one verdict per candidate",
            )
        for verdict in verdicts:
            verdict.assert_candidate(
                by_id[verdict.candidate_id],
                review_input_sha256=canonical_input.review_input_sha256,
            )
        validation_ids = [item.validation_artifact_id for item in verdicts]
        if len(validation_ids) != len(set(validation_ids)):
            raise ReviewerContractError(
                "artifact_coverage_mismatch",
                "validation artifacts must be unique per candidate",
            )
        validation_digests = [item.validation_artifact_sha256 for item in verdicts]
        if len(validation_digests) != len(set(validation_digests)):
            raise ReviewerContractError(
                "artifact_coverage_mismatch",
                "validation artifact digests must be unique per candidate",
            )
        evidence_ids = {
            selection.artifact_id
            for verdict in verdicts
            for criterion in verdict.criteria
            for selection in criterion.selections
        }
        evidence_digests = {
            selection.artifact_sha256
            for verdict in verdicts
            for criterion in verdict.criteria
            for selection in criterion.selections
        }
        if set(validation_ids) & evidence_ids:
            raise ReviewerContractError(
                "artifact_coverage_mismatch",
                "validation artifacts cannot be evidence for any candidate",
            )
        if set(validation_digests) & evidence_digests:
            raise ReviewerContractError(
                "artifact_coverage_mismatch",
                "validation artifact digests cannot be evidence for any candidate",
            )
        total_selections = sum(
            len(criterion.selections)
            for verdict in verdicts
            for criterion in verdict.criteria
        )
        if total_selections > _MAX_SELECTIONS_PER_BATCH:
            raise ReviewerContractError(
                "limit_exceeded", "reviewer result has too many evidence selections"
            )
        seal = _canonical_attempt_seal(self.attempt_seal)
        seal.assert_input(canonical_input)
        closure = _artifact_closure(verdicts)
        _assert_fresh_artifact_ids(canonical_input, closure)
        if seal.used_artifacts != closure:
            raise ReviewerContractError(
                "artifact_coverage_mismatch",
                "attempt seal must exactly close verdict artifacts",
            )
        model_record_closure = tuple(
            sorted(
                {
                    verdict.model_record_sha256
                    for verdict in verdicts
                    if verdict.model_record_sha256 is not None
                }
            )
        )
        if seal.used_model_records != model_record_closure:
            raise ReviewerContractError(
                "invalid_binding",
                "attempt seal must exactly close verdict model records",
            )
        if not verdicts and seal.model_record_count != 0:
            raise ReviewerContractError(
                "invalid_state", "zero-candidate review cannot contain model calls"
            )
        has_conclusive_assessment = any(
            criterion.assessment != "insufficient"
            for verdict in verdicts
            for criterion in verdict.criteria
        )
        if has_conclusive_assessment and seal.model_record_count == 0:
            raise ReviewerContractError(
                "invalid_state", "conclusive review criteria require a model call"
            )
        object.__setattr__(self, "verdicts", verdicts)
        object.__setattr__(self, "attempt_seal", seal)
        object.__setattr__(
            self,
            "result_sha256",
            _digest(REVIEWER_RESULT_DIGEST_DOMAIN, self._digest_dict()),
        )
        _canonical_bytes(self.to_dict())

    @property
    def result_type(self) -> Literal["finalized"]:
        return "finalized"

    @property
    def accepted_candidates(self) -> tuple[DiscoveryCandidate, ...]:
        return self._candidates_for("accept")

    @property
    def rejected_candidates(self) -> tuple[DiscoveryCandidate, ...]:
        return self._candidates_for("reject")

    @property
    def deferred_candidates(self) -> tuple[DiscoveryCandidate, ...]:
        return self._candidates_for("defer")

    def _candidates_for(self, decision: str) -> tuple[DiscoveryCandidate, ...]:
        by_id = {
            item.candidate_id: item
            for item in self.review_input.producer_draft.candidates
        }
        return tuple(
            by_id[item.candidate_id]
            for item in self.verdicts
            if item.decision == decision
        )

    def _digest_dict(self) -> dict[str, Any]:
        return {
            "attempt_seal": self.attempt_seal.to_dict(),
            "contract_version": self.contract_version,
            "coverage_status": self.coverage_status,
            "policy_version": self.policy_version,
            "result_type": self.result_type,
            "review_input": self.review_input.to_dict(),
            "verdicts": [item.to_dict() for item in self.verdicts],
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ReviewerFinalizedV1":
        item = _strict_object(
            _bounded_wire_object(value, name="ReviewerFinalizedV1"),
            expected=frozenset(
                {
                    "attempt_seal",
                    "contract_version",
                    "coverage_status",
                    "policy_version",
                    "result_sha256",
                    "result_type",
                    "review_input",
                    "verdicts",
                }
            ),
            name="ReviewerFinalizedV1",
        )
        if item["result_type"] != "finalized":
            raise ReviewerContractError(
                "invalid_state", "reviewer result_type must be finalized"
            )
        verdicts = item["verdicts"]
        if type(verdicts) is not list:
            raise ReviewerContractError("invalid_type", "verdicts must be an array")
        result = cls(
            review_input=ReviewerInputV1.from_dict(item["review_input"]),
            verdicts=tuple(
                ReviewerCandidateVerdictV1.from_dict(child) for child in verdicts
            ),
            attempt_seal=ReviewerAttemptSealV1.from_dict(item["attempt_seal"]),
            coverage_status=item["coverage_status"],
            policy_version=item["policy_version"],
            contract_version=item["contract_version"],
        )
        if type(item["result_sha256"]) is not str or item["result_sha256"] != result.result_sha256:
            raise ReviewerContractError(
                "invalid_binding", "result_sha256 does not match finalized result"
            )
        return result

    @classmethod
    def from_wire(cls, value: Any) -> "ReviewerFinalizedV1":
        return cls.from_dict(_decode_wire(value))

    def to_dict(self) -> dict[str, Any]:
        return {**self._digest_dict(), "result_sha256": self.result_sha256}

    def to_wire(self) -> bytes:
        return _canonical_bytes(self.to_dict())


@dataclass(frozen=True, slots=True)
class ReviewerDeferredV1:
    """Whole-task D3 deferral with no partial candidate verdicts."""

    review_input: ReviewerInputV1
    stage: Literal["REVIEW", "FINALIZE"]
    reason_code: str
    missing_information: tuple[str, ...]
    attempt_seal: ReviewerAttemptSealV1 | None
    coverage_status: Literal["unknown"] = "unknown"
    policy_version: str = REVIEWER_POLICY_VERSION
    contract_version: int = REVIEWER_CONTRACT_VERSION
    result_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ReviewerContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        if type(self.policy_version) is not str or self.policy_version != REVIEWER_POLICY_VERSION:
            raise ReviewerContractError(
                "invalid_value", "policy_version does not match D3"
            )
        if type(self.coverage_status) is not str or self.coverage_status != "unknown":
            raise ReviewerContractError(
                "invalid_state", "coverage_status must remain unknown"
            )
        canonical_input = _canonical_reviewer_input(self.review_input)
        object.__setattr__(self, "review_input", canonical_input)
        if type(self.stage) is not str or self.stage not in _DEFERRED_STAGES:
            raise ReviewerContractError(
                "invalid_state", "deferred stage is not a D3 stage"
            )
        if type(self.reason_code) is not str or self.reason_code not in _DEFERRED_REASON_CODES:
            raise ReviewerContractError(
                "invalid_value", "reason_code is not part of the D3 taxonomy"
            )
        missing = _ordered_values(
            self.missing_information,
            name="missing_information",
            maximum=_MAX_MISSING_INFORMATION,
        )
        if not missing or any(
            type(item) is not str or item not in _MISSING_INFORMATION_CODES
            for item in missing
        ):
            raise ReviewerContractError(
                "invalid_value",
                "missing_information must use non-empty D3 taxonomy tokens",
            )
        missing = tuple(sorted(missing))
        if len(missing) != len(set(missing)):
            raise ReviewerContractError(
                "invalid_value", "missing_information must not contain duplicates"
            )
        object.__setattr__(self, "missing_information", missing)
        if self.reason_code == "runtime.seal_failed":
            if (
                self.stage != "FINALIZE"
                or self.attempt_seal is not None
                or "attempt_seal" not in missing
            ):
                raise ReviewerContractError(
                    "invalid_state",
                    "seal failure requires FINALIZE and no partial attempt seal",
                )
        else:
            if type(self.attempt_seal) is not ReviewerAttemptSealV1:
                raise ReviewerContractError(
                    "invalid_state", "non-seal deferrals require a closed attempt seal"
                )
            seal = _canonical_attempt_seal(self.attempt_seal)
            seal.assert_input(canonical_input)
            _assert_fresh_artifact_ids(canonical_input, seal.used_artifacts)
            object.__setattr__(self, "attempt_seal", seal)
        object.__setattr__(
            self,
            "result_sha256",
            _digest(REVIEWER_RESULT_DIGEST_DOMAIN, self._digest_dict()),
        )
        _canonical_bytes(self.to_dict())

    @property
    def result_type(self) -> Literal["deferred"]:
        return "deferred"

    def _digest_dict(self) -> dict[str, Any]:
        return {
            "attempt_seal": (
                None if self.attempt_seal is None else self.attempt_seal.to_dict()
            ),
            "contract_version": self.contract_version,
            "coverage_status": self.coverage_status,
            "missing_information": list(self.missing_information),
            "policy_version": self.policy_version,
            "reason_code": self.reason_code,
            "result_type": self.result_type,
            "review_input": self.review_input.to_dict(),
            "stage": self.stage,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "ReviewerDeferredV1":
        item = _strict_object(
            _bounded_wire_object(value, name="ReviewerDeferredV1"),
            expected=frozenset(
                {
                    "attempt_seal",
                    "contract_version",
                    "coverage_status",
                    "missing_information",
                    "policy_version",
                    "reason_code",
                    "result_sha256",
                    "result_type",
                    "review_input",
                    "stage",
                }
            ),
            name="ReviewerDeferredV1",
        )
        if item["result_type"] != "deferred":
            raise ReviewerContractError(
                "invalid_state", "reviewer result_type must be deferred"
            )
        missing = item["missing_information"]
        if type(missing) is not list:
            raise ReviewerContractError(
                "invalid_type", "missing_information must be an array"
            )
        seal_value = item["attempt_seal"]
        if seal_value is not None and type(seal_value) is not dict:
            raise ReviewerContractError(
                "invalid_type", "attempt_seal must be an object or null"
            )
        result = cls(
            review_input=ReviewerInputV1.from_dict(item["review_input"]),
            stage=item["stage"],
            reason_code=item["reason_code"],
            missing_information=tuple(missing),
            attempt_seal=(
                None
                if seal_value is None
                else ReviewerAttemptSealV1.from_dict(seal_value)
            ),
            coverage_status=item["coverage_status"],
            policy_version=item["policy_version"],
            contract_version=item["contract_version"],
        )
        if type(item["result_sha256"]) is not str or item["result_sha256"] != result.result_sha256:
            raise ReviewerContractError(
                "invalid_binding", "result_sha256 does not match deferred result"
            )
        return result

    @classmethod
    def from_wire(cls, value: Any) -> "ReviewerDeferredV1":
        return cls.from_dict(_decode_wire(value))

    def to_dict(self) -> dict[str, Any]:
        return {**self._digest_dict(), "result_sha256": self.result_sha256}

    def to_wire(self) -> bytes:
        return _canonical_bytes(self.to_dict())


def _canonical_finalized_result(value: Any) -> ReviewerFinalizedV1:
    if type(value) is not ReviewerFinalizedV1:
        raise ReviewerContractError(
            "invalid_type", "reviewer result must be a D3 result value"
        )
    canonical = ReviewerFinalizedV1(
        review_input=value.review_input,
        verdicts=value.verdicts,
        attempt_seal=value.attempt_seal,
        coverage_status=value.coverage_status,
        policy_version=value.policy_version,
        contract_version=value.contract_version,
    )
    if type(value.result_sha256) is not str or value.result_sha256 != canonical.result_sha256:
        raise ReviewerContractError(
            "invalid_binding", "result_sha256 does not match finalized result"
        )
    return canonical


def _canonical_deferred_result(value: Any) -> ReviewerDeferredV1:
    if type(value) is not ReviewerDeferredV1:
        raise ReviewerContractError(
            "invalid_type", "reviewer result must be a D3 result value"
        )
    canonical = ReviewerDeferredV1(
        review_input=value.review_input,
        stage=value.stage,
        reason_code=value.reason_code,
        missing_information=value.missing_information,
        attempt_seal=value.attempt_seal,
        coverage_status=value.coverage_status,
        policy_version=value.policy_version,
        contract_version=value.contract_version,
    )
    if type(value.result_sha256) is not str or value.result_sha256 != canonical.result_sha256:
        raise ReviewerContractError(
            "invalid_binding", "result_sha256 does not match deferred result"
        )
    return canonical


ReviewerResultV1: TypeAlias = ReviewerFinalizedV1 | ReviewerDeferredV1


def parse_reviewer_result_v1(value: Any) -> ReviewerResultV1:
    """Parse one canonical D3 result wire or strict JSON object."""

    if type(value) is ReviewerFinalizedV1:
        return _canonical_finalized_result(value)
    if type(value) is ReviewerDeferredV1:
        return _canonical_deferred_result(value)
    if isinstance(value, (str, bytes, bytearray, memoryview)):
        payload = _decode_wire(value)
    else:
        payload = _bounded_wire_object(value, name="ReviewerResultV1")
    try:
        result_type = payload.get("result_type")
    except (TypeError, ValueError, RuntimeError):
        raise ReviewerContractError(
            "wire_invalid", "reviewer result discriminator is unavailable"
        ) from None
    if result_type == "finalized":
        return ReviewerFinalizedV1.from_dict(payload)
    if result_type == "deferred":
        return ReviewerDeferredV1.from_dict(payload)
    raise ReviewerContractError(
        "invalid_state", "reviewer result_type must be finalized or deferred"
    )


__all__ = [
    "DEFAULT_REVIEWER_LIMITS",
    "REVIEWER_ASSESSMENTS",
    "REVIEWER_ATTEMPT_SEAL_DIGEST_DOMAIN",
    "REVIEWER_CONTRACT_VERSION",
    "REVIEWER_CRITERIA",
    "REVIEWER_DECISIONS",
    "REVIEWER_ERROR_TAXONOMY_VERSION",
    "REVIEWER_INPUT_DIGEST_DOMAIN",
    "REVIEWER_INSTRUCTION_ID",
    "REVIEWER_INSTRUCTION_V1",
    "REVIEWER_LIMITS_VERSION",
    "REVIEWER_POLICY_VERSION",
    "REVIEWER_RESULT_DIGEST_DOMAIN",
    "REVIEWER_SCOPE",
    "REVIEWER_SELECTION_DIGEST_DOMAIN",
    "REVIEWER_VERDICT_DIGEST_DOMAIN",
    "REVIEWER_VALIDATION_ARTIFACT_KIND",
    "REVIEWER_VALIDATION_CONTRACT_ID",
    "ReviewerArtifactDigestRefV1",
    "ReviewerAttemptSealV1",
    "ReviewerCandidateVerdictV1",
    "ReviewerContractError",
    "ReviewerContractLimits",
    "ReviewerCriterionV1",
    "ReviewerDeferredV1",
    "ReviewerEvidenceSelectionV1",
    "ReviewerFinalizedV1",
    "ReviewerInputV1",
    "ReviewerResultV1",
    "parse_reviewer_result_v1",
]
