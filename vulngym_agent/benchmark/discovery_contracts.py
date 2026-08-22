"""Strict source-only discovery contracts for sealed benchmark snapshots.

These contracts intentionally stop at snapshot-native endpoint candidates.
They contain no advisory, report, Entry, title, category, or verification
fields and provide no conversion from a raw formal Entry.  Semantic review is
represented as a separate bounded decision and never changes source facts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Final, Literal, Mapping, Sequence
import unicodedata

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID


DISCOVERY_CONTRACT_VERSION: Final[int] = 1
DISCOVERY_LIMITS_VERSION: Final[str] = "source-discovery-d0-v1"
DISCOVERY_ERROR_TAXONOMY_VERSION: Final[str] = "source-discovery-errors-v1"

_MAX_PATH_BYTES: Final[int] = 1_024
_MAX_COMPONENT_BYTES: Final[int] = 255
_MAX_PATH_DEPTH: Final[int] = 64
_MAX_LINE: Final[int] = 2_147_483_647
_MAX_LOCATION_SPAN: Final[int] = 256
_MAX_CANDIDATES_PER_TASK: Final[int] = 64
_MAX_TRACE_NODES_PER_CANDIDATE: Final[int] = 64
_MAX_TRACE_NODES_PER_TASK: Final[int] = 4_096
_MAX_EVIDENCE_REFS_PER_CANDIDATE: Final[int] = 256
_MAX_REVIEWS_PER_TASK: Final[int] = 64
_MAX_REASON_CODES_PER_REVIEW: Final[int] = 32
_MAX_MISSING_INFORMATION: Final[int] = 64
_MAX_SIDECAR_TEXT_CHARS: Final[int] = 4_096

_TASK_ID_RE = re.compile(r"^VG-(TRAIN|TEST)-[0-9A-F]{20}$")
_REPO_URL_RE = re.compile(
    r"^https://github\.com/"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/"
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$"
)
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SNAPSHOT_ID_RE = re.compile(r"^VGS-[0-9A-F]{32}$")
_CANDIDATE_ID_RE = re.compile(r"^VGC-[0-9A-F]{32}$")
_EVIDENCE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_STAGE_RE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_WINDOWS_FORBIDDEN = frozenset('<>:"\\|?*')
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
)

_ERROR_CODES = frozenset(
    {
        "duplicate_candidate",
        "invalid_binding",
        "invalid_identifier",
        "invalid_keys",
        "invalid_state",
        "invalid_type",
        "invalid_value",
        "limit_exceeded",
        "review_coverage_mismatch",
    }
)
_REVIEW_DECISIONS = frozenset({"emit", "reject", "defer"})
_RESULT_STATUSES = frozenset({"finalized", "deferred"})
_COVERAGE_STATUSES = frozenset({"unknown"})


class DiscoveryContractError(ValueError):
    """A stable, path-free D0 contract failure."""

    taxonomy_version = DISCOVERY_ERROR_TAXONOMY_VERSION

    def __init__(self, code: str, message: str) -> None:
        if code not in _ERROR_CODES:
            raise ValueError("unknown discovery contract error code")
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class DiscoveryContractLimits:
    """Versioned hard limits shared by D0 readers and projection."""

    max_candidates_per_task: int = _MAX_CANDIDATES_PER_TASK
    max_location_span: int = _MAX_LOCATION_SPAN
    max_path_depth: int = _MAX_PATH_DEPTH
    max_trace_nodes_per_candidate: int = _MAX_TRACE_NODES_PER_CANDIDATE
    max_trace_nodes_per_task: int = _MAX_TRACE_NODES_PER_TASK
    max_evidence_refs_per_candidate: int = _MAX_EVIDENCE_REFS_PER_CANDIDATE
    max_reviews_per_task: int = _MAX_REVIEWS_PER_TASK
    max_reason_codes_per_review: int = _MAX_REASON_CODES_PER_REVIEW
    max_missing_information: int = _MAX_MISSING_INFORMATION
    limits_version: str = DISCOVERY_LIMITS_VERSION

    def __post_init__(self) -> None:
        expected = {
            "max_candidates_per_task": _MAX_CANDIDATES_PER_TASK,
            "max_location_span": _MAX_LOCATION_SPAN,
            "max_path_depth": _MAX_PATH_DEPTH,
            "max_trace_nodes_per_candidate": _MAX_TRACE_NODES_PER_CANDIDATE,
            "max_trace_nodes_per_task": _MAX_TRACE_NODES_PER_TASK,
            "max_evidence_refs_per_candidate": _MAX_EVIDENCE_REFS_PER_CANDIDATE,
            "max_reviews_per_task": _MAX_REVIEWS_PER_TASK,
            "max_reason_codes_per_review": _MAX_REASON_CODES_PER_REVIEW,
            "max_missing_information": _MAX_MISSING_INFORMATION,
        }
        if self.limits_version != DISCOVERY_LIMITS_VERSION:
            raise DiscoveryContractError(
                "invalid_value", "limits_version does not match the D0 policy"
            )
        for name, fixed in expected.items():
            value = getattr(self, name)
            if type(value) is not int or value != fixed:
                raise DiscoveryContractError(
                    "invalid_value", f"{name} must equal the D0 fixed limit {fixed}"
                )

    def to_dict(self) -> dict[str, int | str]:
        return {
            "limits_version": self.limits_version,
            "max_candidates_per_task": self.max_candidates_per_task,
            "max_evidence_refs_per_candidate": self.max_evidence_refs_per_candidate,
            "max_location_span": self.max_location_span,
            "max_missing_information": self.max_missing_information,
            "max_path_depth": self.max_path_depth,
            "max_reason_codes_per_review": self.max_reason_codes_per_review,
            "max_reviews_per_task": self.max_reviews_per_task,
            "max_trace_nodes_per_candidate": self.max_trace_nodes_per_candidate,
            "max_trace_nodes_per_task": self.max_trace_nodes_per_task,
        }


DEFAULT_DISCOVERY_LIMITS: Final[DiscoveryContractLimits] = DiscoveryContractLimits()


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise DiscoveryContractError(
            "invalid_value", "discovery value is not canonical JSON"
        ) from None


def _digest_id(prefix: str, value: object) -> str:
    return prefix + hashlib.sha256(_canonical_json(value)).hexdigest()[:32].upper()


def _strict_object(
    value: Any, *, expected: frozenset[str], name: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DiscoveryContractError("invalid_type", f"{name} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise DiscoveryContractError(
            "invalid_keys", f"{name} keys must be strings"
        )
    actual = frozenset(value)
    if actual != expected:
        raise DiscoveryContractError(
            "invalid_keys", f"{name} must contain its exact contract keys"
        )
    return value


def _bounded_identifier(
    value: Any, *, pattern: re.Pattern[str], name: str
) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DiscoveryContractError(
            "invalid_identifier", f"{name} has an invalid format"
        )
    return value


def _string_tuple(
    value: Any,
    *,
    name: str,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
    allow_empty: bool,
) -> tuple[str, ...]:
    if isinstance(value, (str, bytes, Mapping, set, frozenset)) or not isinstance(
        value, Sequence
    ):
        raise DiscoveryContractError(
            "invalid_type", f"{name} must be an ordered array"
        )
    result = tuple(value)
    if len(result) > maximum:
        raise DiscoveryContractError("limit_exceeded", f"{name} exceeds its limit")
    if not allow_empty and not result:
        raise DiscoveryContractError(
            "invalid_value", f"{name} must not be empty"
        )
    if any(
        not isinstance(item, str)
        or not item
        or len(item) > _MAX_SIDECAR_TEXT_CHARS
        or any(ord(character) < 32 or ord(character) == 127 for character in item)
        or (pattern is not None and pattern.fullmatch(item) is None)
        for item in result
    ):
        raise DiscoveryContractError(
            "invalid_value", f"{name} contains an invalid value"
        )
    if len(result) != len(set(result)):
        raise DiscoveryContractError(
            "invalid_value", f"{name} must not contain duplicates"
        )
    return result


def _repo_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise DiscoveryContractError(
            "invalid_value", "location.file must be a non-empty string"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise DiscoveryContractError(
            "invalid_value", "location.file must be valid Unicode"
        ) from None
    components = value.split("/")
    if (
        len(encoded) > _MAX_PATH_BYTES
        or len(components) > _MAX_PATH_DEPTH
        or value != unicodedata.normalize("NFC", value)
        or value.startswith(("/", "-", ":"))
        or "\\" in value
        or ":" in value
        or any(component in {"", ".", ".."} for component in components)
        or any(len(component.encode("utf-8")) > _MAX_COMPONENT_BYTES for component in components)
        or any(component.endswith((" ", ".")) for component in components)
        or any(
            component.casefold() == ".git"
            or unicodedata.normalize("NFKC", component).casefold() == ".git"
            for component in components
        )
        or any(
            component.split(".", 1)[0].upper() in _WINDOWS_RESERVED
            for component in components
        )
        or any(
            character in _WINDOWS_FORBIDDEN
            or unicodedata.category(character).startswith("C")
            for character in value
        )
    ):
        raise DiscoveryContractError(
            "invalid_value", "location.file is not a canonical repository path"
        )
    return value


@dataclass(frozen=True, slots=True)
class DiscoveryTaskInputV1:
    """One answer-free task bound to one authenticated source snapshot."""

    task_id: str
    repo_url: str
    commit: str
    instruction_id: str
    snapshot_manifest_sha256: str
    snapshot_content_root: str
    contract_version: int = DISCOVERY_CONTRACT_VERSION
    snapshot_id: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise DiscoveryContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        _bounded_identifier(self.task_id, pattern=_TASK_ID_RE, name="task_id")
        _bounded_identifier(self.repo_url, pattern=_REPO_URL_RE, name="repo_url")
        if self.repo_url.casefold().endswith(".git"):
            raise DiscoveryContractError(
                "invalid_identifier", "repo_url must not end with .git"
            )
        _bounded_identifier(self.commit, pattern=_COMMIT_RE, name="commit")
        if self.instruction_id != INSTRUCTION_ID:
            raise DiscoveryContractError(
                "invalid_value", "instruction_id does not match the benchmark"
            )
        _bounded_identifier(
            self.snapshot_manifest_sha256,
            pattern=_SHA256_RE,
            name="snapshot_manifest_sha256",
        )
        _bounded_identifier(
            self.snapshot_content_root,
            pattern=_SHA256_RE,
            name="snapshot_content_root",
        )
        snapshot_id = _digest_id(
            "VGS-",
            {
                "commit": self.commit,
                "repo_url": self.repo_url,
                "snapshot_content_root": self.snapshot_content_root,
                "snapshot_manifest_sha256": self.snapshot_manifest_sha256,
            },
        )
        object.__setattr__(self, "snapshot_id", snapshot_id)

    @classmethod
    def from_dict(cls, value: Any) -> "DiscoveryTaskInputV1":
        task = _strict_object(
            value,
            expected=frozenset(
                {
                    "commit",
                    "contract_version",
                    "instruction_id",
                    "repo_url",
                    "snapshot_content_root",
                    "snapshot_id",
                    "snapshot_manifest_sha256",
                    "task_id",
                }
            ),
            name="DiscoveryTaskInputV1",
        )
        result = cls(
            task_id=task["task_id"],
            repo_url=task["repo_url"],
            commit=task["commit"],
            instruction_id=task["instruction_id"],
            snapshot_manifest_sha256=task["snapshot_manifest_sha256"],
            snapshot_content_root=task["snapshot_content_root"],
            contract_version=task["contract_version"],
        )
        if task["snapshot_id"] != result.snapshot_id:
            raise DiscoveryContractError(
                "invalid_binding", "snapshot_id does not match the task snapshot"
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "contract_version": self.contract_version,
            "instruction_id": self.instruction_id,
            "repo_url": self.repo_url,
            "snapshot_content_root": self.snapshot_content_root,
            "snapshot_id": self.snapshot_id,
            "snapshot_manifest_sha256": self.snapshot_manifest_sha256,
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class DiscoveryLocation:
    """One exact, source-byte-bound location inside a sealed tree."""

    file: str
    line_start: int
    line_end: int
    code_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "file", _repo_path(self.file))
        if (
            type(self.line_start) is not int
            or type(self.line_end) is not int
            or not 1 <= self.line_start <= self.line_end <= _MAX_LINE
            or self.line_end - self.line_start + 1
            > DEFAULT_DISCOVERY_LIMITS.max_location_span
        ):
            raise DiscoveryContractError(
                "invalid_value",
                "location lines must be a positive ordered range within the span limit",
            )
        _bounded_identifier(
            self.code_sha256, pattern=_SHA256_RE, name="location.code_sha256"
        )

    @classmethod
    def from_dict(cls, value: Any) -> "DiscoveryLocation":
        location = _strict_object(
            value,
            expected=frozenset({"code_sha256", "file", "line_end", "line_start"}),
            name="DiscoveryLocation",
        )
        return cls(
            file=location["file"],
            line_start=location["line_start"],
            line_end=location["line_end"],
            code_sha256=location["code_sha256"],
        )

    def evaluator_location(self) -> dict[str, str | int]:
        line: str | int = (
            self.line_start
            if self.line_start == self.line_end
            else f"{self.line_start}-{self.line_end}"
        )
        return {"file": self.file, "line": line}

    def identity_dict(self) -> dict[str, str | int]:
        return {
            "file": self.file,
            "line_end": self.line_end,
            "line_start": self.line_start,
        }

    def to_dict(self) -> dict[str, str | int]:
        return {
            "code_sha256": self.code_sha256,
            "file": self.file,
            "line_end": self.line_end,
            "line_start": self.line_start,
        }


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    """One fact-bound endpoint hypothesis; semantic authority is separate."""

    task_id: str
    snapshot_id: str
    repo_url: str
    commit: str
    entry_point: DiscoveryLocation
    critical_operation: DiscoveryLocation
    trace: tuple[DiscoveryLocation, ...]
    relationship_evidence_refs: tuple[str, ...]
    source_evidence_refs: tuple[str, ...]
    contract_version: int = DISCOVERY_CONTRACT_VERSION
    candidate_id: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise DiscoveryContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        _bounded_identifier(self.task_id, pattern=_TASK_ID_RE, name="task_id")
        _bounded_identifier(
            self.snapshot_id, pattern=_SNAPSHOT_ID_RE, name="snapshot_id"
        )
        _bounded_identifier(self.repo_url, pattern=_REPO_URL_RE, name="repo_url")
        _bounded_identifier(self.commit, pattern=_COMMIT_RE, name="commit")
        if not isinstance(self.entry_point, DiscoveryLocation) or not isinstance(
            self.critical_operation, DiscoveryLocation
        ):
            raise DiscoveryContractError(
                "invalid_type", "candidate endpoints must be DiscoveryLocation values"
            )
        if isinstance(self.trace, (str, bytes, bytearray, Mapping, set, frozenset)):
            raise DiscoveryContractError(
                "invalid_type", "trace must be an ordered collection"
            )
        try:
            trace = tuple(self.trace)
        except TypeError:
            raise DiscoveryContractError(
                "invalid_type", "trace must be an ordered collection"
            ) from None
        if any(not isinstance(item, DiscoveryLocation) for item in trace):
            raise DiscoveryContractError(
                "invalid_type", "trace must contain DiscoveryLocation values"
            )
        if len(trace) > DEFAULT_DISCOVERY_LIMITS.max_trace_nodes_per_candidate:
            raise DiscoveryContractError(
                "limit_exceeded", "candidate trace exceeds its node limit"
            )
        object.__setattr__(self, "trace", trace)
        object.__setattr__(
            self,
            "relationship_evidence_refs",
            _string_tuple(
                self.relationship_evidence_refs,
                name="relationship_evidence_refs",
                maximum=DEFAULT_DISCOVERY_LIMITS.max_evidence_refs_per_candidate,
                pattern=_EVIDENCE_REF_RE,
                allow_empty=False,
            ),
        )
        object.__setattr__(
            self,
            "source_evidence_refs",
            _string_tuple(
                self.source_evidence_refs,
                name="source_evidence_refs",
                maximum=DEFAULT_DISCOVERY_LIMITS.max_evidence_refs_per_candidate,
                pattern=_EVIDENCE_REF_RE,
                allow_empty=False,
            ),
        )
        candidate_id = _digest_id(
            "VGC-",
            {
                "critical_operation": self.critical_operation.identity_dict(),
                "entry_point": self.entry_point.identity_dict(),
                "snapshot_id": self.snapshot_id,
                "task_id": self.task_id,
            },
        )
        object.__setattr__(self, "candidate_id", candidate_id)

    def assert_task(self, task: DiscoveryTaskInputV1) -> None:
        if not isinstance(task, DiscoveryTaskInputV1) or (
            self.task_id,
            self.snapshot_id,
            self.repo_url,
            self.commit,
        ) != (task.task_id, task.snapshot_id, task.repo_url, task.commit):
            raise DiscoveryContractError(
                "invalid_binding", "candidate does not match its task snapshot"
            )

    @property
    def candidate_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_dict())).hexdigest()

    @classmethod
    def from_dict(cls, value: Any) -> "DiscoveryCandidate":
        candidate = _strict_object(
            value,
            expected=frozenset(
                {
                    "candidate_id",
                    "commit",
                    "contract_version",
                    "critical_operation",
                    "entry_point",
                    "relationship_evidence_refs",
                    "repo_url",
                    "snapshot_id",
                    "source_evidence_refs",
                    "task_id",
                    "trace",
                }
            ),
            name="DiscoveryCandidate",
        )
        trace_value = candidate["trace"]
        if not isinstance(trace_value, list):
            raise DiscoveryContractError("invalid_type", "trace must be an array")
        for name in ("relationship_evidence_refs", "source_evidence_refs"):
            if not isinstance(candidate[name], list):
                raise DiscoveryContractError(
                    "invalid_type", f"{name} must be an array"
                )
        result = cls(
            task_id=candidate["task_id"],
            snapshot_id=candidate["snapshot_id"],
            repo_url=candidate["repo_url"],
            commit=candidate["commit"],
            entry_point=DiscoveryLocation.from_dict(candidate["entry_point"]),
            critical_operation=DiscoveryLocation.from_dict(
                candidate["critical_operation"]
            ),
            trace=tuple(DiscoveryLocation.from_dict(item) for item in trace_value),
            relationship_evidence_refs=tuple(candidate["relationship_evidence_refs"]),
            source_evidence_refs=tuple(candidate["source_evidence_refs"]),
            contract_version=candidate["contract_version"],
        )
        if candidate["candidate_id"] != result.candidate_id:
            raise DiscoveryContractError(
                "invalid_binding", "candidate_id does not match candidate endpoints"
            )
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "commit": self.commit,
            "contract_version": self.contract_version,
            "critical_operation": self.critical_operation.to_dict(),
            "entry_point": self.entry_point.to_dict(),
            "relationship_evidence_refs": list(self.relationship_evidence_refs),
            "repo_url": self.repo_url,
            "snapshot_id": self.snapshot_id,
            "source_evidence_refs": list(self.source_evidence_refs),
            "task_id": self.task_id,
            "trace": [item.to_dict() for item in self.trace],
        }


@dataclass(frozen=True, slots=True)
class DiscoveryReview:
    """Independent policy decision for one immutable discovery candidate."""

    task_id: str
    snapshot_id: str
    candidate_id: str
    candidate_sha256: str
    decision: Literal["emit", "reject", "defer"]
    reason_codes: tuple[str, ...]
    contract_version: int = DISCOVERY_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise DiscoveryContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        _bounded_identifier(self.task_id, pattern=_TASK_ID_RE, name="task_id")
        _bounded_identifier(
            self.snapshot_id, pattern=_SNAPSHOT_ID_RE, name="snapshot_id"
        )
        _bounded_identifier(
            self.candidate_id, pattern=_CANDIDATE_ID_RE, name="candidate_id"
        )
        _bounded_identifier(
            self.candidate_sha256,
            pattern=_SHA256_RE,
            name="candidate_sha256",
        )
        if not isinstance(self.decision, str) or self.decision not in _REVIEW_DECISIONS:
            raise DiscoveryContractError(
                "invalid_value", "review decision must be emit, reject, or defer"
            )
        object.__setattr__(
            self,
            "reason_codes",
            _string_tuple(
                self.reason_codes,
                name="reason_codes",
                maximum=DEFAULT_DISCOVERY_LIMITS.max_reason_codes_per_review,
                pattern=_REASON_CODE_RE,
                allow_empty=False,
            ),
        )

    def assert_candidate(self, candidate: DiscoveryCandidate) -> None:
        if not isinstance(candidate, DiscoveryCandidate) or (
            self.task_id,
            self.snapshot_id,
            self.candidate_id,
            self.candidate_sha256,
        ) != (
            candidate.task_id,
            candidate.snapshot_id,
            candidate.candidate_id,
            candidate.candidate_sha256,
        ):
            raise DiscoveryContractError(
                "invalid_binding", "review does not match its candidate"
            )

    @classmethod
    def from_dict(cls, value: Any) -> "DiscoveryReview":
        review = _strict_object(
            value,
            expected=frozenset(
                {
                    "candidate_id",
                    "candidate_sha256",
                    "contract_version",
                    "decision",
                    "reason_codes",
                    "snapshot_id",
                    "task_id",
                }
            ),
            name="DiscoveryReview",
        )
        if not isinstance(review["reason_codes"], list):
            raise DiscoveryContractError(
                "invalid_type", "reason_codes must be an array"
            )
        return cls(
            task_id=review["task_id"],
            snapshot_id=review["snapshot_id"],
            candidate_id=review["candidate_id"],
            candidate_sha256=review["candidate_sha256"],
            decision=review["decision"],
            reason_codes=tuple(review["reason_codes"]),
            contract_version=review["contract_version"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_sha256": self.candidate_sha256,
            "contract_version": self.contract_version,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "snapshot_id": self.snapshot_id,
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class DiscoveryDeferred:
    """Fail-closed task outcome that makes no clean-source claim."""

    task_id: str
    snapshot_id: str
    stage: str
    reason_code: str
    missing_information: tuple[str, ...]
    contract_version: int = DISCOVERY_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise DiscoveryContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        _bounded_identifier(self.task_id, pattern=_TASK_ID_RE, name="task_id")
        _bounded_identifier(
            self.snapshot_id, pattern=_SNAPSHOT_ID_RE, name="snapshot_id"
        )
        _bounded_identifier(self.stage, pattern=_STAGE_RE, name="stage")
        _bounded_identifier(
            self.reason_code, pattern=_REASON_CODE_RE, name="reason_code"
        )
        object.__setattr__(
            self,
            "missing_information",
            _string_tuple(
                self.missing_information,
                name="missing_information",
                maximum=DEFAULT_DISCOVERY_LIMITS.max_missing_information,
                allow_empty=False,
            ),
        )

    @classmethod
    def from_dict(cls, value: Any) -> "DiscoveryDeferred":
        deferred = _strict_object(
            value,
            expected=frozenset(
                {
                    "contract_version",
                    "missing_information",
                    "reason_code",
                    "snapshot_id",
                    "stage",
                    "task_id",
                }
            ),
            name="DiscoveryDeferred",
        )
        if not isinstance(deferred["missing_information"], list):
            raise DiscoveryContractError(
                "invalid_type", "missing_information must be an array"
            )
        return cls(
            task_id=deferred["task_id"],
            snapshot_id=deferred["snapshot_id"],
            stage=deferred["stage"],
            reason_code=deferred["reason_code"],
            missing_information=tuple(deferred["missing_information"]),
            contract_version=deferred["contract_version"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "missing_information": list(self.missing_information),
            "reason_code": self.reason_code,
            "snapshot_id": self.snapshot_id,
            "stage": self.stage,
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class DiscoveryTaskResult:
    """Atomic per-task D0 result with complete candidate-review closure."""

    task: DiscoveryTaskInputV1
    status: Literal["finalized", "deferred"]
    coverage_status: Literal["unknown"]
    candidates: tuple[DiscoveryCandidate, ...]
    reviews: tuple[DiscoveryReview, ...]
    deferred: DiscoveryDeferred | None = None
    contract_version: int = DISCOVERY_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise DiscoveryContractError(
                "invalid_value", "contract_version must be integer 1"
            )
        if not isinstance(self.task, DiscoveryTaskInputV1):
            raise DiscoveryContractError(
                "invalid_type", "task must be DiscoveryTaskInputV1"
            )
        if not isinstance(self.status, str) or self.status not in _RESULT_STATUSES:
            raise DiscoveryContractError("invalid_state", "result status is invalid")
        if (
            not isinstance(self.coverage_status, str)
            or self.coverage_status not in _COVERAGE_STATUSES
        ):
            raise DiscoveryContractError(
                "invalid_state", "coverage_status must remain unknown"
            )
        if isinstance(
            self.candidates, (str, bytes, bytearray, Mapping, set, frozenset)
        ) or isinstance(
            self.reviews, (str, bytes, bytearray, Mapping, set, frozenset)
        ):
            raise DiscoveryContractError(
                "invalid_type", "candidates and reviews must be ordered collections"
            )
        try:
            candidates = tuple(self.candidates)
            reviews = tuple(self.reviews)
        except TypeError:
            raise DiscoveryContractError(
                "invalid_type", "candidates and reviews must be ordered collections"
            ) from None
        if any(not isinstance(item, DiscoveryCandidate) for item in candidates):
            raise DiscoveryContractError(
                "invalid_type", "candidates contain an invalid value"
            )
        if any(not isinstance(item, DiscoveryReview) for item in reviews):
            raise DiscoveryContractError(
                "invalid_type", "reviews contain an invalid value"
            )
        if len(candidates) > DEFAULT_DISCOVERY_LIMITS.max_candidates_per_task:
            raise DiscoveryContractError(
                "limit_exceeded", "task contains too many candidates"
            )
        if len(reviews) > DEFAULT_DISCOVERY_LIMITS.max_reviews_per_task:
            raise DiscoveryContractError(
                "limit_exceeded", "task contains too many reviews"
            )
        if sum(len(item.trace) for item in candidates) > DEFAULT_DISCOVERY_LIMITS.max_trace_nodes_per_task:
            raise DiscoveryContractError(
                "limit_exceeded", "task exceeds its aggregate trace-node limit"
            )
        candidates = tuple(sorted(candidates, key=lambda item: item.candidate_id))
        reviews = tuple(sorted(reviews, key=lambda item: item.candidate_id))
        for candidate in candidates:
            candidate.assert_task(self.task)
        candidate_ids = [item.candidate_id for item in candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise DiscoveryContractError(
                "duplicate_candidate", "task repeats an endpoint candidate"
            )
        review_ids = [item.candidate_id for item in reviews]
        if len(review_ids) != len(set(review_ids)):
            raise DiscoveryContractError(
                "review_coverage_mismatch", "task repeats a candidate review"
            )
        by_id = {item.candidate_id: item for item in candidates}
        if self.status == "finalized":
            if self.deferred is not None or set(review_ids) != set(candidate_ids):
                raise DiscoveryContractError(
                    "review_coverage_mismatch",
                    "finalized tasks require exactly one review per candidate",
                )
            for review in reviews:
                review.assert_candidate(by_id[review.candidate_id])
        else:
            if candidates or reviews or not isinstance(self.deferred, DiscoveryDeferred):
                raise DiscoveryContractError(
                    "invalid_state",
                    "deferred tasks contain no candidates or reviews and require a reason",
                )
            if (
                self.deferred.task_id != self.task.task_id
                or self.deferred.snapshot_id != self.task.snapshot_id
            ):
                raise DiscoveryContractError(
                    "invalid_binding", "deferred outcome does not match its task"
                )
        object.__setattr__(self, "candidates", candidates)
        object.__setattr__(self, "reviews", reviews)

    @property
    def emitted_candidates(self) -> tuple[DiscoveryCandidate, ...]:
        if self.status != "finalized":
            return ()
        by_id = {item.candidate_id: item for item in self.candidates}
        return tuple(
            by_id[review.candidate_id]
            for review in self.reviews
            if review.decision == "emit"
        )

    @classmethod
    def from_dict(cls, value: Any) -> "DiscoveryTaskResult":
        result = _strict_object(
            value,
            expected=frozenset(
                {
                    "candidates",
                    "contract_version",
                    "coverage_status",
                    "deferred",
                    "reviews",
                    "status",
                    "task",
                }
            ),
            name="DiscoveryTaskResult",
        )
        candidates = result["candidates"]
        reviews = result["reviews"]
        if not isinstance(candidates, list) or not isinstance(reviews, list):
            raise DiscoveryContractError(
                "invalid_type", "result candidates and reviews must be arrays"
            )
        deferred_value = result["deferred"]
        if deferred_value is not None and not isinstance(deferred_value, Mapping):
            raise DiscoveryContractError(
                "invalid_type", "result deferred must be an object or null"
            )
        return cls(
            task=DiscoveryTaskInputV1.from_dict(result["task"]),
            status=result["status"],
            coverage_status=result["coverage_status"],
            candidates=tuple(DiscoveryCandidate.from_dict(item) for item in candidates),
            reviews=tuple(DiscoveryReview.from_dict(item) for item in reviews),
            deferred=(
                None
                if deferred_value is None
                else DiscoveryDeferred.from_dict(deferred_value)
            ),
            contract_version=result["contract_version"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidates": [item.to_dict() for item in self.candidates],
            "contract_version": self.contract_version,
            "coverage_status": self.coverage_status,
            "deferred": None if self.deferred is None else self.deferred.to_dict(),
            "reviews": [item.to_dict() for item in self.reviews],
            "status": self.status,
            "task": self.task.to_dict(),
        }


__all__ = [
    "DEFAULT_DISCOVERY_LIMITS",
    "DISCOVERY_CONTRACT_VERSION",
    "DISCOVERY_ERROR_TAXONOMY_VERSION",
    "DISCOVERY_LIMITS_VERSION",
    "DiscoveryCandidate",
    "DiscoveryContractError",
    "DiscoveryContractLimits",
    "DiscoveryDeferred",
    "DiscoveryLocation",
    "DiscoveryReview",
    "DiscoveryTaskInputV1",
    "DiscoveryTaskResult",
]
