"""Independent D3 source-review execution context.

The context in this module owns one fresh sealed-source capability, one fresh
budget, and one tool/model runtime pair in the ``d3.review`` lane.  It exposes
only bounded candidate contexts and controller-facing issuance operations;
the underlying tree, toolbox, runtimes, ledger, and artifact catalog remain
private.

This is a trusted in-process capability boundary, not a sandbox for arbitrary
Python extensions.  Model input and output still cross the structured runtime
and every released seal is rebuilt from closed runtime state.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import re
from threading import RLock
from typing import Any, Final

from vulngym_agent.agents.discovery_toolbox import (
    MAX_READ_SPANS,
    MAX_TOOL_ARTIFACT_CANONICAL_BYTES,
    DiscoveryToolbox,
)
from vulngym_agent.agents.model_runtime import (
    AttemptModelRuntime,
    AttemptModelTranscript,
    ModelResult,
    StructuredModelBackend,
    structured_json_sha256,
)
from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryCandidate,
    DiscoveryLocation,
)
from vulngym_agent.benchmark.reviewer_contracts import (
    REVIEWER_ARTIFACT_CATALOG_DIGEST_DOMAIN,
    REVIEWER_BUDGET_LEDGER_DIGEST_DOMAIN,
    REVIEWER_CRITERIA,
    REVIEWER_CONTEXT_DIGEST_DOMAIN,
    REVIEWER_INSTRUCTION_ID,
    REVIEWER_INSTRUCTION_V1,
    REVIEWER_MODEL_RECORD_DIGEST_DOMAIN,
    REVIEWER_POLICY_VERSION,
    REVIEWER_SCOPE,
    REVIEWER_SOURCE_LEDGER_DIGEST_DOMAIN,
    REVIEWER_VALIDATION_ARTIFACT_KIND,
    REVIEWER_VALIDATION_CONTRACT_ID,
    ReviewerArtifactDigestRefV1,
    ReviewerAttemptSealV1,
    ReviewerCriterionV1,
    ReviewerEvidenceSelectionV1,
    ReviewerInputV1,
    reviewer_selection_digest_v1,
)
from vulngym_agent.benchmark.sealed_tree_access import (
    SEALED_TREE_ACCESS_VERSION,
    BoundSealedTree,
    SourceReadUsage,
    SourceUsageLedger,
)
from vulngym_agent.orchestrator.budget import (
    LLM_CALLS,
    REPAIR_ITERATIONS,
    TOOL_CALLS,
    Budget,
)
from vulngym_agent.orchestrator.contracts import (
    ModelCallRecord,
    canonical_json,
    canonical_sha256,
)
from vulngym_agent.tools.runtime import (
    ArtifactRef,
    AttemptToolRuntime,
    AttemptToolTranscript,
    ToolArtifact,
    ToolCallEnvelope,
    ToolDefinition,
    ToolHandlerOutput,
    ToolResult,
)


REVIEWER_MODEL_REQUEST_CONTRACT_ID: Final[str] = (
    "source-discovery-review-model@1"
)

_ATTEMPT: Final[int] = 0
_MODEL_STAGE: Final[str] = "semantic_judge"
_SOURCE_TOOL: Final[str] = "source_read"
_VALIDATION_TOOL: Final[str] = "review_validate"
_MAX_ARTIFACTS: Final[int] = 64
_MAX_MODEL_RECORDS: Final[int] = 16
_MAX_TOOL_RECORDS: Final[int] = 80
_MAX_BUDGET_EVENTS: Final[int] = 96
_MAX_CONTEXT_NODES: Final[int] = 66
_MAX_CONTEXT_MODEL_BYTES: Final[int] = 384 * 1024
_MAX_CONTEXT_MODEL_JSON_NODES: Final[int] = 4_000
_MAX_CONTROLLER_REQUEST_BYTES: Final[int] = 64 * 1024
_MAX_CONTROLLER_REQUEST_JSON_NODES: Final[int] = 1_000
_MAX_SOURCE_ARTIFACT_RESERVATION_BYTES: Final[int] = (
    MAX_TOOL_ARTIFACT_CANONICAL_BYTES
)
_MAX_SOURCE_CATALOG_BYTES: Final[int] = 4 * 1024 * 1024
_UNAVAILABLE_SOURCE_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "source_batch_too_large",
        "source_file_too_large",
        "source_span_batch_too_large",
        "source_span_too_large",
    }
)
_ARTIFACT_REF_TAG: Final[str] = "$artifact_ref"
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_GIT_OID_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
_REASON_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-z][a-z0-9._:-]{0,127}$"
)


class ReviewerContextError(RuntimeError):
    """Base class for deterministic D3 context failures."""


class ReviewerContextFinalized(ReviewerContextError):
    """Raised when an operation is attempted after one-way closure."""


class ReviewerContextLimitExceeded(ReviewerContextError):
    """Raised before a candidate operation that cannot fit fixed D3 limits."""


class ReviewerContextBindingError(ReviewerContextError):
    """Raised when runtime state does not bind the exact D3 input."""


class ReviewerContextLedgerMismatch(ReviewerContextError):
    """Raised when the tool/model/budget/source closure is not exact."""


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw(child) for child in value]
    return value


def _runtime_argument_wire(value: Any) -> Any:
    """Mirror the tool runtime's ArtifactRef-to-tag normalization."""

    if type(value) is ArtifactRef:
        return {_ARTIFACT_REF_TAG: value.to_dict()}
    if isinstance(value, Mapping):
        return {str(key): _runtime_argument_wire(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_runtime_argument_wire(child) for child in value]
    return value


def _domain_sha256(domain: bytes, value: Any) -> str:
    return hashlib.sha256(
        domain + canonical_json(value).encode("utf-8")
    ).hexdigest()


def _json_metrics(value: Any) -> tuple[int, int]:
    """Return canonical bytes and runtime-compatible recursive node count."""

    nodes = 0

    def visit(item: Any) -> None:
        nonlocal nodes
        nodes += 1
        if isinstance(item, Mapping):
            for key, child in item.items():
                visit(key)
                visit(child)
        elif isinstance(item, (tuple, list)):
            for child in item:
                visit(child)

    visit(value)
    return len(canonical_json(value).encode("utf-8")), nodes


def _assert_model_response_boundary(value: Mapping[str, Any]) -> None:
    """Keep derived decisions and all integrity digests controller-owned."""

    forbidden = {
        "decision",
        "result_digest",
        "selection_digest",
        "verdict_digest",
    }

    def visit(item: Any) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ReviewerContextBindingError(
                        "model response keys must be strings"
                    )
                if key in forbidden or key.endswith("_sha256"):
                    raise ReviewerContextBindingError(
                        "model response contains a controller-owned field"
                    )
                visit(child)
        elif isinstance(item, (tuple, list)):
            for child in item:
                visit(child)

    visit(value)


def reviewer_context_sha256(value: Mapping[str, Any]) -> str:
    """Digest one unsigned, bounded D3 model-context object."""

    if not isinstance(value, Mapping):
        raise ValueError("reviewer context digest input must be an object")
    return _domain_sha256(REVIEWER_CONTEXT_DIGEST_DOMAIN, value)


def reviewer_model_record_sha256(record: ModelCallRecord) -> str:
    """Digest one exact runtime model record with the fixed D3 domain."""

    if type(record) is not ModelCallRecord:
        raise ValueError("record must be an exact ModelCallRecord")
    canonical = ModelCallRecord.from_dict(record.to_dict())
    if canonical != record:
        raise ValueError("model record did not pass strict normalization")
    return _domain_sha256(
        REVIEWER_MODEL_RECORD_DIGEST_DOMAIN,
        {"record": canonical.to_dict()},
    )


def _canonical_artifact(artifact: ToolArtifact) -> ToolArtifact:
    if type(artifact) is not ToolArtifact:
        raise ValueError("artifacts must contain exact ToolArtifact values")
    canonical = ToolArtifact(
        task_id=artifact.task_id,
        attempt=artifact.attempt,
        policy_scope=artifact.policy_scope,
        tool_call_id=artifact.tool_call_id,
        artifact_id=artifact.artifact_id,
        kind=artifact.kind,
        payload=artifact.payload,
    )
    if canonical != artifact:
        raise ValueError("artifact did not pass strict normalization")
    return canonical


def reviewer_artifact_catalog_root_sha256(
    artifacts: Sequence[ToolArtifact],
) -> str:
    """Digest the complete D3 artifact catalog without embedding payloads."""

    if isinstance(artifacts, (str, bytes, Mapping, set, frozenset)):
        raise ValueError("artifacts must be an ordered collection")
    items = tuple(_canonical_artifact(item) for item in artifacts)
    if len(items) > _MAX_ARTIFACTS:
        raise ValueError("artifact catalog exceeds the D3 limit")
    ids = [item.artifact_id for item in items]
    if len(ids) != len(set(ids)):
        raise ValueError("artifact catalog contains duplicate IDs")
    rows = [
        {
            "artifact_id": item.artifact_id,
            "artifact_sha256": item.artifact_sha256,
            "kind": item.kind,
            "payload_sha256": item.payload_sha256,
            "tool_call_id": item.tool_call_id,
        }
        for item in sorted(items, key=lambda item: item.artifact_id)
    ]
    return _domain_sha256(
        REVIEWER_ARTIFACT_CATALOG_DIGEST_DOMAIN,
        {"artifacts": rows},
    )


def reviewer_source_ledger_sha256(ledger: SourceUsageLedger) -> str:
    """Digest one exact, finalized source-usage ledger."""

    if type(ledger) is not SourceUsageLedger or (
        type(ledger.inventory_calls) is not int
        or ledger.inventory_calls < 0
        or type(ledger.read_calls) is not int
        or ledger.read_calls < 0
        or type(ledger.bytes_read) is not int
        or ledger.bytes_read < 0
        or type(ledger.finalized) is not bool
        or type(ledger.verification_succeeded) is not bool
        or ledger.finalized is not True
        or ledger.verification_succeeded is not True
        or ledger.access_version != SEALED_TREE_ACCESS_VERSION
    ):
        raise ValueError("ledger must be an exact SourceUsageLedger")
    reads = tuple(ledger.reads)
    if any(
        type(item) is not SourceReadUsage
        or type(item.bytes_read) is not int
        or item.bytes_read < 0
        for item in reads
    ):
        raise ValueError("source ledger reads do not close")
    if (
        ledger.read_calls != len(reads)
        or ledger.bytes_read != sum(item.bytes_read for item in reads)
        or any(
            type(item.sequence) is not int
            or item.sequence != index
            or type(item.path) is not str
            or not item.path
            or type(item.sha256) is not str
            or _SHA256_RE.fullmatch(item.sha256) is None
            or type(item.blob_oid) is not str
            or _GIT_OID_RE.fullmatch(item.blob_oid) is None
            for index, item in enumerate(reads, start=1)
        )
    ):
        raise ValueError("source ledger reads do not close")
    return _domain_sha256(
        REVIEWER_SOURCE_LEDGER_DIGEST_DOMAIN,
        {"ledger": ledger.to_dict()},
    )


def reviewer_budget_ledger_sha256(budget: Budget) -> str:
    """Digest one atomic snapshot of the fresh D3 budget ledger."""

    if type(budget) is not Budget:
        raise ValueError("budget must be an exact Budget")
    return _domain_sha256(
        REVIEWER_BUDGET_LEDGER_DIGEST_DOMAIN,
        {"budget": budget.to_dict()},
    )


@dataclass(frozen=True, slots=True)
class ReviewerContextNode:
    """One fresh source location issued inside a candidate context."""

    candidate_id: str
    role: str
    artifact_ref: ArtifactRef = field(repr=False)
    node_id: str
    file: str
    line_start: int
    line_end: int
    code_sha256: str
    text: str

    def __post_init__(self) -> None:
        if type(self.artifact_ref) is not ArtifactRef:
            raise ValueError("artifact_ref must be an exact ArtifactRef")
        if not isinstance(self.role, str) or not self.role:
            raise ValueError("role must be a non-empty string")
        if not self.node_id.startswith("LOC-"):
            raise ValueError("reviewer context nodes must use LOC IDs")
        if hashlib.sha256(self.text.encode("utf-8")).hexdigest() != self.code_sha256:
            raise ValueError("context text does not match code_sha256")

    @property
    def artifact_id(self) -> str:
        return self.artifact_ref.artifact_id

    @property
    def artifact_sha256(self) -> str:
        return self.artifact_ref.artifact_sha256

    def to_model_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "code_sha256": self.code_sha256,
            "file": self.file,
            "line_end": self.line_end,
            "line_start": self.line_start,
            "node_id": self.node_id,
            "role": self.role,
            "text": self.text,
        }

    def to_selection(self) -> ReviewerEvidenceSelectionV1:
        return ReviewerEvidenceSelectionV1(
            artifact_id=self.artifact_id,
            artifact_sha256=self.artifact_sha256,
            node_id=self.node_id,
        )


@dataclass(frozen=True, slots=True)
class ReviewerCandidateContext:
    """Ephemeral, fresh-source-only model context for one D2 candidate."""

    review_input_sha256: str
    task_id: str
    snapshot_id: str
    manifest_sha256: str
    content_root: str
    instruction_id: str
    policy_version: str
    candidate_id: str
    candidate_sha256: str
    nodes: tuple[ReviewerContextNode, ...]
    context_status: str = "available"
    context_reason: str | None = None
    candidate_location_count: int = 0
    unique_source_span_count: int = 0
    context_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if _SHA256_RE.fullmatch(self.review_input_sha256) is None:
            raise ValueError("review_input_sha256 is invalid")
        if _SHA256_RE.fullmatch(self.candidate_sha256) is None:
            raise ValueError("candidate_sha256 is invalid")
        for value, name in (
            (self.manifest_sha256, "manifest_sha256"),
            (self.content_root, "content_root"),
        ):
            if _SHA256_RE.fullmatch(value) is None:
                raise ValueError(f"{name} is invalid")
        if self.instruction_id != REVIEWER_INSTRUCTION_ID:
            raise ValueError("instruction_id differs from the D3 instruction")
        if self.policy_version != REVIEWER_POLICY_VERSION:
            raise ValueError("policy_version differs from the D3 policy")
        if self.context_status not in {"available", "unavailable"}:
            raise ValueError("context_status is invalid")
        if type(self.candidate_location_count) is not int or not (
            2 <= self.candidate_location_count <= _MAX_CONTEXT_NODES
        ):
            raise ValueError("candidate_location_count is invalid")
        if type(self.unique_source_span_count) is not int or not (
            1 <= self.unique_source_span_count <= _MAX_CONTEXT_NODES
        ):
            raise ValueError("unique_source_span_count is invalid")
        nodes = tuple(self.nodes)
        if len(nodes) > _MAX_CONTEXT_NODES:
            raise ValueError("candidate context exceeds the fixed node limit")
        if any(
            type(item) is not ReviewerContextNode
            or item.candidate_id != self.candidate_id
            for item in nodes
        ):
            raise ValueError("candidate context contains an invalid node")
        identities = [(item.artifact_id, item.node_id) for item in nodes]
        if len(identities) != len(set(identities)):
            raise ValueError("candidate context repeats a node")
        if self.context_status == "available":
            if (
                self.context_reason is not None
                or len(nodes) != self.candidate_location_count
                or self.unique_source_span_count > MAX_READ_SPANS
            ):
                raise ValueError("available context coverage is invalid")
        else:
            if (
                type(self.context_reason) is not str
                or _REASON_RE.fullmatch(self.context_reason) is None
                or nodes
            ):
                raise ValueError("unavailable context must have one reason and no nodes")
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(
            self,
            "context_sha256",
            reviewer_context_sha256(self._digest_dict()),
        )
        if self.context_status == "available":
            canonical_bytes, json_nodes = _json_metrics(self.to_model_dict())
            if (
                canonical_bytes > _MAX_CONTEXT_MODEL_BYTES
                or json_nodes > _MAX_CONTEXT_MODEL_JSON_NODES
            ):
                raise ReviewerContextLimitExceeded(
                    "candidate model context exceeds the fixed D3 envelope"
                )

    def _digest_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_sha256": self.candidate_sha256,
            "content_root": self.content_root,
            "context_reason": self.context_reason,
            "context_status": self.context_status,
            "coverage": self.coverage,
            "instruction_id": self.instruction_id,
            "manifest_sha256": self.manifest_sha256,
            "nodes": [item.to_model_dict() for item in self.nodes],
            "policy_version": self.policy_version,
            "review_input_sha256": self.review_input_sha256,
            "snapshot_id": self.snapshot_id,
            "task_id": self.task_id,
        }

    @property
    def coverage(self) -> dict[str, Any]:
        return {
            "candidate_location_count": self.candidate_location_count,
            "complete": self.context_status == "available",
            "fresh_location_count": len(self.nodes),
            "unique_source_span_count": self.unique_source_span_count,
        }

    def to_model_dict(self) -> dict[str, Any]:
        return {**self._digest_dict(), "context_sha256": self.context_sha256}


@dataclass(frozen=True, slots=True)
class ReviewerModelCall:
    """Immediate model result plus its fixed D3 record digest."""

    result: ModelResult
    record: ModelCallRecord
    record_sha256: str
    context_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.result) is not ModelResult or type(self.record) is not ModelCallRecord:
            raise ValueError("reviewer model call contains invalid runtime values")
        if self.result.to_model_call_record() != self.record:
            raise ValueError("reviewer model call record differs from its result")
        if reviewer_model_record_sha256(self.record) != self.record_sha256:
            raise ValueError("reviewer model record digest is invalid")
        contexts = tuple(self.context_sha256s)
        if not contexts or len(contexts) != len(set(contexts)):
            raise ValueError("reviewer model call requires unique contexts")
        if any(_SHA256_RE.fullmatch(item) is None for item in contexts):
            raise ValueError("reviewer model call contains an invalid context digest")
        object.__setattr__(self, "context_sha256s", contexts)


@dataclass(frozen=True, slots=True)
class ReviewerValidationArtifact:
    """Exact current-runtime validation artifact for one candidate."""

    candidate_id: str
    context_sha256: str
    artifact_ref: ArtifactRef
    artifact: ToolArtifact

    def __post_init__(self) -> None:
        if type(self.artifact_ref) is not ArtifactRef or type(self.artifact) is not ToolArtifact:
            raise ValueError("validation artifact values have invalid types")
        if (
            self.artifact_ref.artifact_id != self.artifact.artifact_id
            or self.artifact_ref.artifact_sha256 != self.artifact.artifact_sha256
            or self.artifact.kind != REVIEWER_VALIDATION_ARTIFACT_KIND
        ):
            raise ValueError("validation artifact reference does not bind its artifact")


class _ReviewerContextCatalog:
    """Attempt-local authority over fresh D3 artifacts and model bindings."""

    __slots__ = (
        "_artifacts",
        "_contexts",
        "_model_bindings",
        "_nodes",
        "_refs",
        "_review_input",
    )

    def __init__(self, review_input: ReviewerInputV1) -> None:
        self._review_input = review_input
        self._artifacts: dict[str, ToolArtifact] = {}
        self._refs: dict[str, ArtifactRef] = {}
        self._contexts: dict[str, ReviewerCandidateContext] = {}
        self._nodes: dict[tuple[str, str, str, str], ReviewerContextNode] = {}
        self._model_bindings: dict[str, tuple[str, ...]] = {}

    @property
    def artifacts(self) -> tuple[ToolArtifact, ...]:
        return tuple(self._artifacts.values())

    @property
    def artifact_count(self) -> int:
        return len(self._artifacts)

    @property
    def artifact_bytes(self) -> int:
        return sum(item.canonical_bytes for item in self._artifacts.values())

    def _add_artifact(self, ref: ArtifactRef, artifact: ToolArtifact) -> None:
        if type(ref) is not ArtifactRef or type(artifact) is not ToolArtifact:
            raise ReviewerContextBindingError("artifact values have invalid types")
        if (
            ref.task_id != self._review_input.task_id
            or ref.attempt != _ATTEMPT
            or ref.policy_scope != REVIEWER_SCOPE
            or artifact.task_id != ref.task_id
            or artifact.attempt != ref.attempt
            or artifact.policy_scope != ref.policy_scope
            or artifact.artifact_id != ref.artifact_id
            or artifact.artifact_sha256 != ref.artifact_sha256
        ):
            raise ReviewerContextBindingError("artifact scope or digest differs")
        if ref.artifact_id in self._artifacts:
            raise ReviewerContextBindingError("artifact ID is already cataloged")
        if len(self._artifacts) >= _MAX_ARTIFACTS:
            raise ReviewerContextLimitExceeded("D3 artifact catalog is full")
        self._refs[ref.artifact_id] = ref
        self._artifacts[ref.artifact_id] = artifact

    def add_source_context(
        self,
        *,
        candidate: DiscoveryCandidate,
        roles: tuple[tuple[str, DiscoveryLocation], ...],
        ref: ArtifactRef,
        artifact: ToolArtifact,
    ) -> ReviewerCandidateContext:
        if candidate.candidate_id in {
            item.candidate_id for item in self._contexts.values()
        }:
            raise ReviewerContextBindingError("candidate context already exists")
        if artifact.kind != "discovery.source_spans":
            raise ReviewerContextBindingError("source context artifact kind differs")
        self._add_artifact(ref, artifact)
        payload = artifact.payload
        if not isinstance(payload, Mapping) or frozenset(payload) != {
            "snapshot",
            "spans",
            "upstream_artifacts",
        }:
            raise ReviewerContextBindingError("source context payload is invalid")
        if _thaw(payload.get("snapshot")) != {
            "commit": self._review_input.producer_draft.task.commit,
            "repo_url": self._review_input.producer_draft.task.repo_url,
            "snapshot_content_root": self._review_input.content_root,
            "snapshot_id": self._review_input.snapshot_id,
            "snapshot_manifest_sha256": self._review_input.manifest_sha256,
            "task_id": self._review_input.task_id,
        } or _thaw(payload.get("upstream_artifacts")) != []:
            raise ReviewerContextBindingError("source context snapshot binding differs")
        raw_spans = payload.get("spans")
        if not isinstance(raw_spans, tuple):
            raise ReviewerContextBindingError("source spans must be an array")
        spans: dict[tuple[str, int, int], Mapping[str, Any]] = {}
        for raw in raw_spans:
            if not isinstance(raw, Mapping) or frozenset(raw) != {
                "code_sha256",
                "file_sha256",
                "line_end",
                "line_start",
                "path",
                "text",
            }:
                raise ReviewerContextBindingError("source span row is invalid")
            key = (raw["path"], raw["line_start"], raw["line_end"])
            if key in spans:
                raise ReviewerContextBindingError("source span row is duplicated")
            text = raw["text"]
            if type(text) is not str or hashlib.sha256(text.encode("utf-8")).hexdigest() != raw["code_sha256"]:
                raise ReviewerContextBindingError("source span digest differs")
            spans[key] = raw
        expected_locations = {
            (location.file, location.line_start, location.line_end): location
            for _, location in roles
        }
        if set(spans) != set(expected_locations):
            raise ReviewerContextBindingError("source spans do not exactly cover candidate context")
        for key, location in expected_locations.items():
            if spans[key]["code_sha256"] != location.code_sha256:
                raise ReviewerContextBindingError("fresh source differs from candidate location")

        nodes: list[ReviewerContextNode] = []
        for role, location in roles:
            row = spans[(location.file, location.line_start, location.line_end)]
            node_id = "LOC-" + hashlib.sha256(
                canonical_json(
                    {
                        "artifact_id": ref.artifact_id,
                        "candidate_id": candidate.candidate_id,
                        "location": location.to_dict(),
                        "role": role,
                    }
                ).encode("utf-8")
            ).hexdigest()[:32].upper()
            node = ReviewerContextNode(
                candidate_id=candidate.candidate_id,
                role=role,
                artifact_ref=ref,
                node_id=node_id,
                file=location.file,
                line_start=location.line_start,
                line_end=location.line_end,
                code_sha256=location.code_sha256,
                text=row["text"],
            )
            nodes.append(node)
        try:
            context = ReviewerCandidateContext(
                review_input_sha256=self._review_input.review_input_sha256,
                task_id=self._review_input.task_id,
                snapshot_id=self._review_input.snapshot_id,
                manifest_sha256=self._review_input.manifest_sha256,
                content_root=self._review_input.content_root,
                instruction_id=REVIEWER_INSTRUCTION_ID,
                policy_version=REVIEWER_POLICY_VERSION,
                candidate_id=candidate.candidate_id,
                candidate_sha256=candidate.candidate_sha256,
                nodes=tuple(nodes),
                context_status="available",
                context_reason=None,
                candidate_location_count=len(roles),
                unique_source_span_count=len(expected_locations),
            )
        except ReviewerContextLimitExceeded:
            return self.add_unavailable_context(
                candidate=candidate,
                reason="context.model_limit",
                candidate_location_count=len(roles),
                unique_source_span_count=len(expected_locations),
            )
        self._contexts[context.context_sha256] = context
        for node in nodes:
            self._nodes[
                (
                    candidate.candidate_id,
                    context.context_sha256,
                    node.artifact_id,
                    node.node_id,
                )
            ] = node
        return context

    def add_unavailable_context(
        self,
        *,
        candidate: DiscoveryCandidate,
        reason: str,
        candidate_location_count: int,
        unique_source_span_count: int,
    ) -> ReviewerCandidateContext:
        if candidate.candidate_id in {
            item.candidate_id for item in self._contexts.values()
        }:
            raise ReviewerContextBindingError("candidate context already exists")
        context = ReviewerCandidateContext(
            review_input_sha256=self._review_input.review_input_sha256,
            task_id=self._review_input.task_id,
            snapshot_id=self._review_input.snapshot_id,
            manifest_sha256=self._review_input.manifest_sha256,
            content_root=self._review_input.content_root,
            instruction_id=REVIEWER_INSTRUCTION_ID,
            policy_version=REVIEWER_POLICY_VERSION,
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            nodes=(),
            context_status="unavailable",
            context_reason=reason,
            candidate_location_count=candidate_location_count,
            unique_source_span_count=unique_source_span_count,
        )
        self._contexts[context.context_sha256] = context
        return context

    def context_is_issued(self, context: object) -> bool:
        if type(context) is not ReviewerCandidateContext:
            return False
        try:
            if self._contexts.get(context.context_sha256) is not context:
                return False
            if reviewer_context_sha256(context._digest_dict()) != context.context_sha256:
                return False
            for node in context.nodes:
                if type(node) is not ReviewerContextNode:
                    return False
                canonical = ReviewerContextNode(
                    candidate_id=node.candidate_id,
                    role=node.role,
                    artifact_ref=node.artifact_ref,
                    node_id=node.node_id,
                    file=node.file,
                    line_start=node.line_start,
                    line_end=node.line_end,
                    code_sha256=node.code_sha256,
                    text=node.text,
                )
                if canonical != node:
                    return False
        except (AttributeError, TypeError, ValueError):
            return False
        return True

    def register_model_record(
        self,
        record_sha256: str,
        contexts: tuple[ReviewerCandidateContext, ...],
    ) -> None:
        if record_sha256 in self._model_bindings:
            raise ReviewerContextBindingError("model record digest is duplicated")
        if any(not self.context_is_issued(item) for item in contexts):
            raise ReviewerContextBindingError("model record references an unissued context")
        self._model_bindings[record_sha256] = tuple(
            item.context_sha256 for item in contexts
        )

    def model_record_is_bound(
        self,
        record_sha256: str,
        context_sha256: str,
    ) -> bool:
        return context_sha256 in self._model_bindings.get(record_sha256, ())

    def require_selection(
        self,
        *,
        candidate_id: str,
        context_sha256: str,
        selection: ReviewerEvidenceSelectionV1,
    ) -> ReviewerContextNode:
        node = self._nodes.get(
            (
                candidate_id,
                context_sha256,
                selection.artifact_id,
                selection.node_id,
            )
        )
        if node is None or node.artifact_sha256 != selection.artifact_sha256:
            raise ReviewerContextBindingError("criterion selection is not fresh D3 evidence")
        return node

    def artifact_ref(self, artifact_id: str) -> ArtifactRef:
        try:
            return self._refs[artifact_id]
        except KeyError as exc:
            raise ReviewerContextBindingError("artifact is not in the D3 catalog") from exc

    def review_validate(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        if (
            type(envelope) is not ToolCallEnvelope
            or envelope.task_id != self._review_input.task_id
            or envelope.attempt != _ATTEMPT
            or envelope.policy_scope != REVIEWER_SCOPE
            or envelope.tool_name != _VALIDATION_TOOL
        ):
            raise ReviewerContextBindingError("review validation scope differs")
        arguments = envelope.arguments
        expected_keys = {
            "candidate",
            "context_sha256",
            "criteria",
            "evidence",
            "model_record_sha256",
            "review_input_sha256",
            "validation_contract_id",
        }
        if not isinstance(arguments, Mapping) or frozenset(arguments) != expected_keys:
            raise ReviewerContextBindingError("review validation arguments are invalid")
        if (
            arguments["review_input_sha256"] != self._review_input.review_input_sha256
            or arguments["validation_contract_id"] != REVIEWER_VALIDATION_CONTRACT_ID
        ):
            raise ReviewerContextBindingError("review validation input binding differs")
        candidate = DiscoveryCandidate.from_dict(_thaw(arguments["candidate"]))
        by_id = {
            item.candidate_id: item
            for item in self._review_input.producer_draft.candidates
        }
        expected_candidate = by_id.get(candidate.candidate_id)
        if expected_candidate is None or candidate != expected_candidate:
            raise ReviewerContextBindingError("review validation candidate differs")
        context_sha256 = arguments["context_sha256"]
        context = self._contexts.get(context_sha256)
        if context is None or context.candidate_id != candidate.candidate_id:
            raise ReviewerContextBindingError("review validation context differs")
        raw_criteria = arguments["criteria"]
        if not isinstance(raw_criteria, tuple):
            raise ReviewerContextBindingError("review criteria must be an array")
        criteria = tuple(
            ReviewerCriterionV1.from_dict(_thaw(item)) for item in raw_criteria
        )
        if tuple(item.criterion for item in criteria) != REVIEWER_CRITERIA:
            raise ReviewerContextBindingError("review criteria coverage differs")

        selected: dict[str, str] = {}
        for criterion in criteria:
            for selection in criterion.selections:
                self.require_selection(
                    candidate_id=candidate.candidate_id,
                    context_sha256=context_sha256,
                    selection=selection,
                )
                previous = selected.setdefault(
                    selection.artifact_id, selection.artifact_sha256
                )
                if previous != selection.artifact_sha256:
                    raise ReviewerContextBindingError("evidence digest conflicts")
        raw_evidence = arguments["evidence"]
        if not isinstance(raw_evidence, tuple):
            raise ReviewerContextBindingError("review evidence must be an array")
        evidence: dict[str, str] = {}
        for item in raw_evidence:
            if not isinstance(item, Mapping) or frozenset(item) != {_ARTIFACT_REF_TAG}:
                raise ReviewerContextBindingError("review evidence reference is invalid")
            wire = item[_ARTIFACT_REF_TAG]
            if not isinstance(wire, Mapping) or frozenset(wire) != {
                "artifact_id",
                "artifact_sha256",
                "attempt",
                "policy_scope",
                "task_id",
            }:
                raise ReviewerContextBindingError("review evidence reference is invalid")
            if (
                wire["task_id"] != self._review_input.task_id
                or wire["attempt"] != _ATTEMPT
                or wire["policy_scope"] != REVIEWER_SCOPE
            ):
                raise ReviewerContextBindingError("review evidence scope differs")
            artifact_id = wire["artifact_id"]
            issued = self._refs.get(artifact_id)
            if issued is None or issued.artifact_sha256 != wire["artifact_sha256"]:
                raise ReviewerContextBindingError("review evidence is not cataloged")
            if artifact_id in evidence:
                raise ReviewerContextBindingError("review evidence repeats an artifact")
            evidence[artifact_id] = wire["artifact_sha256"]
        if evidence != selected:
            raise ReviewerContextBindingError("review evidence closure differs")

        model_record_sha256 = arguments["model_record_sha256"]
        conclusive = any(item.assessment != "insufficient" for item in criteria)
        if context.context_status == "available":
            if (
                type(model_record_sha256) is not str
                or not self.model_record_is_bound(model_record_sha256, context_sha256)
            ):
                raise ReviewerContextBindingError("review model record binding differs")
        elif (
            conclusive or selected or model_record_sha256 is not None
        ):
            raise ReviewerContextBindingError(
                "unavailable context requires all-insufficient criteria"
            )

        assessments = tuple(item.assessment for item in criteria)
        decision = (
            "reject"
            if "contradicted" in assessments
            else "accept"
            if all(item == "supported" for item in assessments)
            else "defer"
        )
        selection_digest = reviewer_selection_digest_v1(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            context_sha256=context_sha256,
            criteria=criteria,
            review_input_sha256=self._review_input.review_input_sha256,
        )

        evidence_rows = [
            {
                "artifact_id": artifact_id,
                "artifact_sha256": selected[artifact_id],
            }
            for artifact_id in sorted(selected)
        ]
        payload = {
            "candidate_id": candidate.candidate_id,
            "candidate_sha256": candidate.candidate_sha256,
            "context_sha256": context_sha256,
            "context_reason": context.context_reason,
            "context_status": context.context_status,
            "coverage": context.coverage,
            "criteria": [item.to_dict() for item in criteria],
            "decision": decision,
            "evidence": evidence_rows,
            "evidence_closed": True,
            "model_record_sha256": model_record_sha256,
            "review_input_sha256": self._review_input.review_input_sha256,
            "selection_digest": selection_digest,
            "snapshot": {
                "content_root": self._review_input.content_root,
                "manifest_sha256": self._review_input.manifest_sha256,
                "snapshot_id": self._review_input.snapshot_id,
                "task_id": self._review_input.task_id,
            },
            "validation_contract_id": REVIEWER_VALIDATION_CONTRACT_ID,
        }
        artifact_id = "ART-review-validation-" + hashlib.sha256(
            canonical_json(
                {
                    "attempt": envelope.attempt,
                    "payload": payload,
                    "policy_scope": envelope.policy_scope,
                    "task_id": envelope.task_id,
                    "tool_call_id": envelope.tool_call_id,
                }
            ).encode("utf-8")
        ).hexdigest()[:24]
        artifact = ToolArtifact(
            task_id=envelope.task_id,
            attempt=envelope.attempt,
            policy_scope=envelope.policy_scope,
            tool_call_id=envelope.tool_call_id,
            artifact_id=artifact_id,
            kind=REVIEWER_VALIDATION_ARTIFACT_KIND,
            payload=payload,
        )
        return ToolHandlerOutput(
            output={
                "candidate_id": candidate.candidate_id,
                "context_sha256": context_sha256,
                "evidence_closed": True,
            },
            artifacts=(artifact,),
        )

    def add_validation(
        self,
        *,
        candidate_id: str,
        context_sha256: str,
        ref: ArtifactRef,
        artifact: ToolArtifact,
        criteria: tuple[ReviewerCriterionV1, ...],
        model_record_sha256: str | None,
    ) -> ReviewerValidationArtifact:
        if artifact.kind != REVIEWER_VALIDATION_ARTIFACT_KIND:
            raise ReviewerContextBindingError("validation artifact kind differs")
        payload = artifact.payload
        context = self._contexts.get(context_sha256)
        candidate = next(
            (
                item
                for item in self._review_input.producer_draft.candidates
                if item.candidate_id == candidate_id
            ),
            None,
        )
        if context is None or candidate is None:
            raise ReviewerContextBindingError("validation context is not cataloged")
        assessments = tuple(item.assessment for item in criteria)
        decision = (
            "reject"
            if "contradicted" in assessments
            else "accept"
            if all(item == "supported" for item in assessments)
            else "defer"
        )
        selection_digest = reviewer_selection_digest_v1(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.candidate_sha256,
            context_sha256=context_sha256,
            criteria=criteria,
            review_input_sha256=self._review_input.review_input_sha256,
        )
        evidence: dict[str, str] = {}
        for criterion in criteria:
            for selection in criterion.selections:
                evidence[selection.artifact_id] = selection.artifact_sha256
        expected_payload = {
            "candidate_id": candidate.candidate_id,
            "candidate_sha256": candidate.candidate_sha256,
            "context_reason": context.context_reason,
            "context_sha256": context_sha256,
            "context_status": context.context_status,
            "coverage": context.coverage,
            "criteria": [item.to_dict() for item in criteria],
            "decision": decision,
            "evidence": [
                {
                    "artifact_id": artifact_id,
                    "artifact_sha256": evidence[artifact_id],
                }
                for artifact_id in sorted(evidence)
            ],
            "evidence_closed": True,
            "model_record_sha256": model_record_sha256,
            "review_input_sha256": self._review_input.review_input_sha256,
            "selection_digest": selection_digest,
            "snapshot": {
                "content_root": self._review_input.content_root,
                "manifest_sha256": self._review_input.manifest_sha256,
                "snapshot_id": self._review_input.snapshot_id,
                "task_id": self._review_input.task_id,
            },
            "validation_contract_id": REVIEWER_VALIDATION_CONTRACT_ID,
        }
        if not isinstance(payload, Mapping) or _thaw(payload) != expected_payload:
            raise ReviewerContextBindingError("validation artifact payload differs")
        self._add_artifact(ref, artifact)
        return ReviewerValidationArtifact(
            candidate_id=candidate_id,
            context_sha256=context_sha256,
            artifact_ref=ref,
            artifact=artifact,
        )


class ReviewerContextSession:
    """Own and close one independent D3 review attempt."""

    __slots__ = (
        "_budget",
        "_catalog",
        "_expected_model_records",
        "_expected_tool_artifacts",
        "_expected_tool_records",
        "_finalization_error",
        "_lock",
        "_model_runtime",
        "_review_input",
        "_seal",
        "_sealed",
        "_tool_runtime",
        "_toolbox",
        "_validation_by_candidate",
        "_attempt_digest",
    )

    def __init__(
        self,
        review_input: ReviewerInputV1,
        tree: BoundSealedTree,
        budget: Budget,
        backend: StructuredModelBackend,
    ) -> None:
        if type(review_input) is not ReviewerInputV1:
            raise ValueError("review_input must be an exact ReviewerInputV1")
        canonical_input = ReviewerInputV1.from_dict(review_input.to_dict())
        if canonical_input != review_input:
            raise ValueError("review_input did not pass strict normalization")
        if type(tree) is not BoundSealedTree:
            raise ValueError("tree must be an exact BoundSealedTree")
        if type(budget) is not Budget:
            raise ValueError("budget must be an exact Budget")
        if budget.events or budget.usage.to_dict() != {
            "llm_calls": 0,
            "repair_iterations": 0,
            "tool_calls": 0,
        }:
            raise ValueError("D3 reviewer requires a fresh budget")
        if (
            tree.task_id,
            tree.snapshot_id,
            tree.repo_url,
            tree.commit,
            tree.manifest_sha256,
            tree.content_root,
        ) != (
            canonical_input.task_id,
            canonical_input.snapshot_id,
            canonical_input.producer_draft.task.repo_url,
            canonical_input.producer_draft.task.commit,
            canonical_input.manifest_sha256,
            canonical_input.content_root,
        ):
            raise ValueError("tree does not match reviewer input")
        initial_source = tree.usage_snapshot()
        if (
            type(initial_source) is not SourceUsageLedger
            or initial_source.finalized
            or initial_source.inventory_calls != 0
            or initial_source.read_calls != 0
            or initial_source.bytes_read != 0
            or initial_source.reads
        ):
            raise ValueError("D3 reviewer requires a fresh source capability")

        model_runtime = AttemptModelRuntime(
            task_id=canonical_input.task_id,
            attempt=_ATTEMPT,
            policy_scope=REVIEWER_SCOPE,
            budget=budget,
            backend=backend,
        )
        toolbox = DiscoveryToolbox(canonical_input.producer_draft.task, tree)
        tool_runtime: AttemptToolRuntime | None = None
        try:
            toolbox.claim_source_usage()
            claimed_source = toolbox.usage_snapshot()
            if claimed_source != initial_source:
                raise ValueError("source capability changed while it was claimed")
            catalog = _ReviewerContextCatalog(canonical_input)
            registry = dict(toolbox.registry)
            registry[_VALIDATION_TOOL] = ToolDefinition(
                name=_VALIDATION_TOOL,
                contract_id=REVIEWER_VALIDATION_CONTRACT_ID,
                handler=catalog.review_validate,
            )
            tool_runtime = AttemptToolRuntime(
                task_id=canonical_input.task_id,
                attempt=_ATTEMPT,
                policy_scope=REVIEWER_SCOPE,
                budget=budget,
                registry=registry,
                allowlist=(_SOURCE_TOOL, _VALIDATION_TOOL),
            )
            self._review_input = canonical_input
            self._budget = budget
            self._toolbox = toolbox
            self._tool_runtime = tool_runtime
            self._model_runtime = model_runtime
            self._catalog = catalog
            self._expected_tool_records: list[ToolResult] = []
            self._expected_tool_artifacts: list[ToolArtifact] = []
            self._expected_model_records: list[ModelCallRecord] = []
            self._validation_by_candidate: dict[str, ReviewerValidationArtifact] = {}
            self._attempt_digest = canonical_sha256(
                {
                    "policy_scope": REVIEWER_SCOPE,
                    "review_input_sha256": canonical_input.review_input_sha256,
                    "task_id": canonical_input.task_id,
                }
            )[:16].upper()
            self._sealed = False
            self._seal: ReviewerAttemptSealV1 | None = None
            self._finalization_error: ReviewerContextLedgerMismatch | None = None
            self._lock = RLock()
            return
        except BaseException:
            if tool_runtime is not None:
                try:
                    tool_runtime.finalize()
                except BaseException:
                    pass
            try:
                model_runtime.finalize()
            except BaseException:
                pass
            try:
                toolbox.abort_source_usage()
            except BaseException:
                pass
            raise

    @property
    def review_input(self) -> ReviewerInputV1:
        return self._review_input

    @property
    def sealed(self) -> bool:
        return self._sealed

    def _require_open(self) -> None:
        if self._sealed:
            raise ReviewerContextFinalized("reviewer context is already closed")

    def _candidate(self, candidate_id: str) -> DiscoveryCandidate:
        matches = tuple(
            item
            for item in self._review_input.producer_draft.candidates
            if item.candidate_id == candidate_id
        )
        if len(matches) != 1:
            raise ReviewerContextBindingError("candidate is not in reviewer input")
        return matches[0]

    def _tool_call_id(self, action: str, candidate_id: str) -> str:
        token = candidate_id.removeprefix("VGC-")
        return f"TOOL-D3-{self._attempt_digest}-{action}-{token}"

    def _record_tool_result(
        self,
        result: ToolResult,
        *,
        call_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        artifact_kind: str,
    ) -> tuple[ArtifactRef, ToolArtifact]:
        expected_arguments_sha256 = ToolCallEnvelope(
            task_id=self._review_input.task_id,
            attempt=_ATTEMPT,
            policy_scope=REVIEWER_SCOPE,
            tool_call_id=call_id,
            tool_name=tool_name,
            arguments=_runtime_argument_wire(arguments),
        ).arguments_sha256
        if (
            type(result) is not ToolResult
            or result.task_id != self._review_input.task_id
            or result.attempt != _ATTEMPT
            or result.policy_scope != REVIEWER_SCOPE
            or result.tool_call_id != call_id
            or result.tool_name != tool_name
            or result.arguments_sha256 != expected_arguments_sha256
            or result.operation
            != f"tool:{self._review_input.task_id}:0:{REVIEWER_SCOPE}:{call_id}:{tool_name}"
        ):
            raise ReviewerContextBindingError("tool result binding differs")
        self._expected_tool_records.append(result)
        if result.status != "success" or len(result.artifact_refs) != 1:
            raise ReviewerContextBindingError("D3 tool call did not issue one artifact")
        ref = result.artifact_refs[0]
        if type(ref) is not ArtifactRef or self._tool_runtime.artifact_ref(ref.artifact_id) is not ref:
            raise ReviewerContextBindingError("tool artifact reference was not issued here")
        artifact = self._tool_runtime.resolve_artifact(ref)
        if (
            type(artifact) is not ToolArtifact
            or artifact.kind != artifact_kind
            or artifact.tool_call_id != call_id
        ):
            raise ReviewerContextBindingError("tool artifact binding differs")
        self._expected_tool_artifacts.append(artifact)
        return ref, artifact

    def _record_unavailable_source_result(
        self,
        result: ToolResult,
        *,
        call_id: str,
        arguments: Mapping[str, Any],
    ) -> bool:
        expected_arguments_sha256 = ToolCallEnvelope(
            task_id=self._review_input.task_id,
            attempt=_ATTEMPT,
            policy_scope=REVIEWER_SCOPE,
            tool_call_id=call_id,
            tool_name=_SOURCE_TOOL,
            arguments=_runtime_argument_wire(arguments),
        ).arguments_sha256
        expected_operation = (
            f"tool:{self._review_input.task_id}:0:{REVIEWER_SCOPE}:"
            f"{call_id}:{_SOURCE_TOOL}"
        )
        if (
            type(result) is not ToolResult
            or result.task_id != self._review_input.task_id
            or result.attempt != _ATTEMPT
            or result.policy_scope != REVIEWER_SCOPE
            or result.tool_call_id != call_id
            or result.tool_name != _SOURCE_TOOL
            or result.arguments_sha256 != expected_arguments_sha256
            or result.operation != expected_operation
        ):
            raise ReviewerContextBindingError("tool result binding differs")
        if (
            result.status != "blocked"
            or result.error_code not in _UNAVAILABLE_SOURCE_ERROR_CODES
            or result.artifact_refs
        ):
            return False
        self._expected_tool_records.append(result)
        return True

    def build_candidate_context(self, candidate_id: str) -> ReviewerCandidateContext:
        """Read and bind at most sixteen unique exact candidate locations."""

        with self._lock:
            self._require_open()
            try:
                candidate = self._candidate(candidate_id)
                existing = tuple(
                    item
                    for item in self._catalog._contexts.values()
                    if item.candidate_id == candidate_id
                )
                if existing:
                    return existing[0]
                roles: list[tuple[str, DiscoveryLocation]] = [
                    ("entry_role", candidate.entry_point),
                    ("critical_role", candidate.critical_operation),
                ]
                roles.extend(
                    (f"trace.{index:03d}", location)
                    for index, location in enumerate(candidate.trace, start=1)
                )
                unique: dict[tuple[str, int, int], DiscoveryLocation] = {}
                for _, location in roles:
                    key = (location.file, location.line_start, location.line_end)
                    previous = unique.setdefault(key, location)
                    if previous.code_sha256 != location.code_sha256:
                        raise ReviewerContextBindingError(
                            "one source location has conflicting candidate digests"
                        )
                if len(unique) > MAX_READ_SPANS:
                    return self._catalog.add_unavailable_context(
                        candidate=candidate,
                        reason="context.location_limit",
                        candidate_location_count=len(roles),
                        unique_source_span_count=len(unique),
                    )
                if self._catalog.artifact_count >= _MAX_ARTIFACTS:
                    raise ReviewerContextLimitExceeded("D3 artifact catalog is full")
                if (
                    self._catalog.artifact_bytes
                    + _MAX_SOURCE_ARTIFACT_RESERVATION_BYTES
                    > _MAX_SOURCE_CATALOG_BYTES
                ):
                    return self._catalog.add_unavailable_context(
                        candidate=candidate,
                        reason="context.artifact_byte_budget",
                        candidate_location_count=len(roles),
                        unique_source_span_count=len(unique),
                    )
                arguments = {
                    "spans": [
                        {
                            "line_end": location.line_end,
                            "line_start": location.line_start,
                            "path": location.file,
                        }
                        for _, location in sorted(unique.items())
                    ]
                }
                call_id = self._tool_call_id("READ", candidate.candidate_id)
                result = self._tool_runtime.call(call_id, _SOURCE_TOOL, arguments)
                if self._record_unavailable_source_result(
                    result,
                    call_id=call_id,
                    arguments=arguments,
                ):
                    return self._catalog.add_unavailable_context(
                        candidate=candidate,
                        reason=f"context.{result.error_code}",
                        candidate_location_count=len(roles),
                        unique_source_span_count=len(unique),
                    )
                ref, artifact = self._record_tool_result(
                    result,
                    call_id=call_id,
                    tool_name=_SOURCE_TOOL,
                    arguments=arguments,
                    artifact_kind="discovery.source_spans",
                )
                return self._catalog.add_source_context(
                    candidate=candidate,
                    roles=tuple(roles),
                    ref=ref,
                    artifact=artifact,
                )
            except BaseException as exc:
                if not isinstance(exc, Exception):
                    self._abort_locked()
                raise

    def resolve_selection(
        self,
        context: ReviewerCandidateContext,
        *,
        artifact_id: str,
        node_id: str,
    ) -> ReviewerEvidenceSelectionV1:
        """Resolve an opaque model choice against an exact issued context."""

        with self._lock:
            self._require_open()
            if not self._catalog.context_is_issued(context):
                raise ReviewerContextBindingError("context was not issued here")
            candidates = tuple(
                node
                for node in context.nodes
                if node.artifact_id == artifact_id and node.node_id == node_id
            )
            if len(candidates) != 1:
                raise ReviewerContextBindingError("model selection is not in the context")
            return candidates[0].to_selection()

    def call_model(
        self,
        model_call_id: str,
        contexts: Sequence[ReviewerCandidateContext],
        request: Mapping[str, Any],
    ) -> ReviewerModelCall:
        """Call the fixed structured model with only fresh D3 contexts."""

        with self._lock:
            self._require_open()
            try:
                if isinstance(contexts, (str, bytes, Mapping, set, frozenset)):
                    raise ValueError("contexts must be an ordered collection")
                issued = tuple(contexts)
                if (
                    not issued
                    or len(issued) > 2
                    or len({item.context_sha256 for item in issued}) != len(issued)
                    or any(not self._catalog.context_is_issued(item) for item in issued)
                ):
                    raise ReviewerContextBindingError("model contexts are invalid")
                if any(item.context_status != "available" for item in issued):
                    raise ReviewerContextBindingError(
                        "unavailable contexts cannot be sent to the model"
                    )
                if len(self._expected_model_records) >= _MAX_MODEL_RECORDS:
                    raise ReviewerContextLimitExceeded("D3 model record limit is exhausted")
                if not isinstance(request, Mapping):
                    raise ValueError("request must be an object")
                request_bytes, request_nodes = _json_metrics(request)
                if (
                    request_bytes > _MAX_CONTROLLER_REQUEST_BYTES
                    or request_nodes > _MAX_CONTROLLER_REQUEST_JSON_NODES
                ):
                    raise ReviewerContextLimitExceeded(
                        "controller model request exceeds the fixed D3 envelope"
                    )
                payload = {
                    "contexts": [item.to_model_dict() for item in issued],
                    "instruction": REVIEWER_INSTRUCTION_V1,
                    "instruction_id": REVIEWER_INSTRUCTION_ID,
                    "policy_version": REVIEWER_POLICY_VERSION,
                    "request": _thaw(request),
                    "request_contract_id": REVIEWER_MODEL_REQUEST_CONTRACT_ID,
                    "review_input_sha256": self._review_input.review_input_sha256,
                }
                request_sha256 = structured_json_sha256(payload)
                backend_id = self._model_runtime.backend_id
                model_id = self._model_runtime.model_id
                result = self._model_runtime.call(
                    model_call_id,
                    _MODEL_STAGE,
                    payload,
                )
                if (
                    type(result) is not ModelResult
                    or result.task_id != self._review_input.task_id
                    or result.attempt != _ATTEMPT
                    or result.policy_scope != REVIEWER_SCOPE
                    or result.model_call_id != model_call_id
                    or result.stage != _MODEL_STAGE
                    or result.backend_id != backend_id
                    or result.model_id != model_id
                    or result.request_sha256 != request_sha256
                    or result.operation
                    != (
                        f"model:{self._review_input.task_id}:0:{REVIEWER_SCOPE}:"
                        f"{_MODEL_STAGE}:{model_call_id}:{backend_id}:{model_id}:"
                        f"{request_sha256}"
                    )
                ):
                    raise ReviewerContextBindingError("model result binding differs")
                record = result.to_model_call_record()
                self._expected_model_records.append(record)
                digest = reviewer_model_record_sha256(record)
                call = ReviewerModelCall(
                    result=result,
                    record=record,
                    record_sha256=digest,
                    context_sha256s=tuple(item.context_sha256 for item in issued),
                )
                if result.status == "success":
                    assert result.response is not None
                    _assert_model_response_boundary(result.response)
                    self._catalog.register_model_record(digest, issued)
                return call
            except BaseException as exc:
                if not isinstance(exc, Exception):
                    self._abort_locked()
                raise

    def issue_validation(
        self,
        context: ReviewerCandidateContext,
        criteria: Sequence[ReviewerCriterionV1],
        *,
        model_record_sha256: str | None,
    ) -> ReviewerValidationArtifact:
        """Issue one candidate-unique validation artifact from closed selections."""

        with self._lock:
            self._require_open()
            try:
                if not self._catalog.context_is_issued(context):
                    raise ReviewerContextBindingError("context was not issued here")
                if context.candidate_id in self._validation_by_candidate:
                    raise ReviewerContextBindingError("candidate validation already exists")
                if isinstance(criteria, (str, bytes, Mapping, set, frozenset)):
                    raise ValueError("criteria must be an ordered collection")
                canonical_criteria = tuple(
                    ReviewerCriterionV1.from_dict(item.to_dict())
                    if type(item) is ReviewerCriterionV1
                    else (_ for _ in ()).throw(
                        ValueError("criteria must contain exact ReviewerCriterionV1 values")
                    )
                    for item in criteria
                )
                rank = {name: index for index, name in enumerate(REVIEWER_CRITERIA)}
                canonical_criteria = tuple(
                    sorted(canonical_criteria, key=lambda item: rank.get(item.criterion, 99))
                )
                if tuple(item.criterion for item in canonical_criteria) != REVIEWER_CRITERIA:
                    raise ReviewerContextBindingError("criteria coverage differs")
                evidence: dict[str, ArtifactRef] = {}
                for criterion in canonical_criteria:
                    for selection in criterion.selections:
                        self._catalog.require_selection(
                            candidate_id=context.candidate_id,
                            context_sha256=context.context_sha256,
                            selection=selection,
                        )
                        evidence.setdefault(
                            selection.artifact_id,
                            self._catalog.artifact_ref(selection.artifact_id),
                        )
                conclusive = any(
                    item.assessment != "insufficient" for item in canonical_criteria
                )
                if context.context_status == "available":
                    if (
                        type(model_record_sha256) is not str
                        or not self._catalog.model_record_is_bound(
                            model_record_sha256, context.context_sha256
                        )
                    ):
                        raise ReviewerContextBindingError("model record is not bound to context")
                elif conclusive or evidence or model_record_sha256 is not None:
                    raise ReviewerContextBindingError(
                        "unavailable context requires all-insufficient validation"
                    )
                if self._catalog.artifact_count >= _MAX_ARTIFACTS:
                    raise ReviewerContextLimitExceeded("D3 artifact catalog is full")
                candidate = self._candidate(context.candidate_id)
                arguments = {
                    "candidate": candidate.to_dict(),
                    "context_sha256": context.context_sha256,
                    "criteria": [item.to_dict() for item in canonical_criteria],
                    "evidence": [evidence[item] for item in sorted(evidence)],
                    "model_record_sha256": model_record_sha256,
                    "review_input_sha256": self._review_input.review_input_sha256,
                    "validation_contract_id": REVIEWER_VALIDATION_CONTRACT_ID,
                }
                call_id = self._tool_call_id("VALIDATE", candidate.candidate_id)
                result = self._tool_runtime.call(call_id, _VALIDATION_TOOL, arguments)
                ref, artifact = self._record_tool_result(
                    result,
                    call_id=call_id,
                    tool_name=_VALIDATION_TOOL,
                    arguments=arguments,
                    artifact_kind=REVIEWER_VALIDATION_ARTIFACT_KIND,
                )
                validation = self._catalog.add_validation(
                    candidate_id=candidate.candidate_id,
                    context_sha256=context.context_sha256,
                    ref=ref,
                    artifact=artifact,
                    criteria=canonical_criteria,
                    model_record_sha256=model_record_sha256,
                )
                self._validation_by_candidate[candidate.candidate_id] = validation
                return validation
            except BaseException as exc:
                if not isinstance(exc, Exception):
                    self._abort_locked()
                raise

    def _finalize_tool_transcript(self) -> AttemptToolTranscript:
        transcript = self._tool_runtime.finalize()
        registry = self._tool_runtime.registry
        expected = AttemptToolTranscript(
            task_id=self._review_input.task_id,
            attempt=_ATTEMPT,
            policy_scope=REVIEWER_SCOPE,
            registry_sha256=canonical_sha256(
                [[name, registry[name].contract_id] for name in sorted(registry)]
            ),
            allowlist_sha256=canonical_sha256(sorted(self._tool_runtime.allowlist)),
            records=tuple(self._expected_tool_records),
            artifacts=tuple(self._expected_tool_artifacts),
        )
        if (
            type(transcript) is not AttemptToolTranscript
            or transcript != expected
            or self._tool_runtime.records != expected.records
            or self._tool_runtime.artifacts != expected.artifacts
            or self._tool_runtime.sealed_transcript is not transcript
            or self._tool_runtime.finalize() is not transcript
        ):
            raise ReviewerContextLedgerMismatch("tool transcript did not close")
        return transcript

    def _finalize_model_transcript(self) -> AttemptModelTranscript:
        transcript = self._model_runtime.finalize()
        expected = AttemptModelTranscript(
            task_id=self._review_input.task_id,
            attempt=_ATTEMPT,
            policy_scope=REVIEWER_SCOPE,
            backend_id=self._model_runtime.backend_id,
            model_id=self._model_runtime.model_id,
            records=tuple(self._expected_model_records),
        )
        if (
            type(transcript) is not AttemptModelTranscript
            or transcript != expected
            or self._model_runtime.records != expected.records
            or self._model_runtime.sealed_transcript is not transcript
            or self._model_runtime.finalize() is not transcript
        ):
            raise ReviewerContextLedgerMismatch("model transcript did not close")
        return transcript

    def _verify_budget(
        self,
        tool_transcript: AttemptToolTranscript,
        model_transcript: AttemptModelTranscript,
    ) -> None:
        state = self._budget.to_dict()
        events = self._budget.events
        if state.get("events") != [item.to_dict() for item in events]:
            raise ReviewerContextLedgerMismatch("budget snapshot is inconsistent")
        records = tuple(
            (item.budget_event_sequence, TOOL_CALLS, item.operation)
            for item in tool_transcript.records
        ) + tuple(
            (item.budget_event_sequence, LLM_CALLS, item.operation)
            for item in model_transcript.records
        )
        if len(events) != len(records) or len(events) > _MAX_BUDGET_EVENTS:
            raise ReviewerContextLedgerMismatch("budget event coverage differs")
        by_sequence = {sequence: (resource, operation) for sequence, resource, operation in records}
        if len(by_sequence) != len(records):
            raise ReviewerContextLedgerMismatch("budget event sequence is ambiguous")
        for event in events:
            if (
                event.amount != 1
                or event.resource == REPAIR_ITERATIONS
                or by_sequence.get(event.sequence) != (event.resource, event.operation)
            ):
                raise ReviewerContextLedgerMismatch("budget event binding differs")
        usage = state.get("usage")
        if usage != {
            "llm_calls": len(model_transcript.records),
            "repair_iterations": 0,
            "tool_calls": len(tool_transcript.records),
        }:
            raise ReviewerContextLedgerMismatch("budget usage does not close")

    def _used_artifact_closure(
        self, refs: Sequence[ArtifactRef]
    ) -> tuple[ReviewerArtifactDigestRefV1, ...]:
        if isinstance(refs, (str, bytes, Mapping, set, frozenset)):
            raise ReviewerContextBindingError("used artifacts must be ordered")
        values = tuple(refs)
        if len(values) > _MAX_ARTIFACTS:
            raise ReviewerContextLimitExceeded("used artifacts exceed the D3 limit")
        result: dict[str, str] = {}
        for ref in values:
            if type(ref) is not ArtifactRef:
                raise ReviewerContextBindingError("used artifact reference is invalid")
            if self._tool_runtime.artifact_ref(ref.artifact_id) is not ref:
                raise ReviewerContextBindingError("used artifact was not issued here")
            artifact = self._tool_runtime.resolve_artifact(ref)
            cataloged = self._catalog._artifacts.get(ref.artifact_id)
            if cataloged is not artifact:
                raise ReviewerContextBindingError("used artifact is not cataloged")
            previous = result.setdefault(ref.artifact_id, ref.artifact_sha256)
            if previous != ref.artifact_sha256:
                raise ReviewerContextBindingError("used artifact digest conflicts")
        return tuple(
            ReviewerArtifactDigestRefV1(
                artifact_id=artifact_id,
                artifact_sha256=result[artifact_id],
            )
            for artifact_id in sorted(result)
        )

    def _used_model_closure(self, values: Sequence[str]) -> tuple[str, ...]:
        if isinstance(values, (str, bytes, Mapping, set, frozenset)):
            raise ReviewerContextBindingError("used model records must be ordered")
        result = tuple(values)
        if len(result) > _MAX_MODEL_RECORDS or len(result) != len(set(result)):
            raise ReviewerContextBindingError("used model record closure is invalid")
        if any(item not in self._catalog._model_bindings for item in result):
            raise ReviewerContextBindingError("used model record was not issued here")
        return tuple(sorted(result))

    def finalize(
        self,
        *,
        used_artifacts: Sequence[ArtifactRef],
        used_model_records: Sequence[str],
    ) -> ReviewerAttemptSealV1:
        """Seal every owned capability and return one strict D3 attempt seal."""

        with self._lock:
            if self._seal is not None:
                return self._seal
            if self._finalization_error is not None:
                raise self._finalization_error
            self._require_open()
            self._sealed = True
            failures: list[BaseException] = []
            control_flow: BaseException | None = None
            tool_transcript: AttemptToolTranscript | None = None
            model_transcript: AttemptModelTranscript | None = None
            source_ledger: SourceUsageLedger | None = None
            try:
                tool_transcript = self._finalize_tool_transcript()
            except BaseException as exc:
                failures.append(exc)
                if not isinstance(exc, Exception) and control_flow is None:
                    control_flow = exc
            try:
                model_transcript = self._finalize_model_transcript()
            except BaseException as exc:
                failures.append(exc)
                if not isinstance(exc, Exception) and control_flow is None:
                    control_flow = exc
            if tool_transcript is not None and model_transcript is not None:
                try:
                    self._verify_budget(tool_transcript, model_transcript)
                except BaseException as exc:
                    failures.append(exc)
                    if not isinstance(exc, Exception) and control_flow is None:
                        control_flow = exc
            try:
                source_ledger = self._toolbox.finalize_source_usage()
                readback = self._toolbox.usage_snapshot()
                if (
                    type(source_ledger) is not SourceUsageLedger
                    or type(readback) is not SourceUsageLedger
                    or source_ledger != readback
                    or source_ledger.task_id != self._review_input.task_id
                    or source_ledger.snapshot_id != self._review_input.snapshot_id
                    or source_ledger.finalized is not True
                    or source_ledger.verification_succeeded is not True
                ):
                    raise ReviewerContextLedgerMismatch("source ledger did not close")
            except BaseException as exc:
                failures.append(exc)
                if not isinstance(exc, Exception) and control_flow is None:
                    control_flow = exc
                try:
                    self._toolbox.abort_source_usage()
                except BaseException as abort_exc:
                    failures.append(abort_exc)
                    if (
                        not isinstance(abort_exc, Exception)
                        and control_flow is None
                    ):
                        control_flow = abort_exc
            if control_flow is not None:
                self._best_effort_close_capabilities()
                raise control_flow
            if failures or tool_transcript is None or model_transcript is None or source_ledger is None:
                error = ReviewerContextLedgerMismatch(
                    "reviewer runtime did not close into an attempt seal"
                )
                self._finalization_error = error
                raise error from failures[0] if failures else None
            try:
                if len(tool_transcript.records) > _MAX_TOOL_RECORDS:
                    raise ReviewerContextLimitExceeded("D3 tool record limit exceeded")
                artifacts = self._used_artifact_closure(used_artifacts)
                model_records = self._used_model_closure(used_model_records)
                if tuple(self._catalog.artifacts) != tool_transcript.artifacts:
                    raise ReviewerContextLedgerMismatch("artifact catalog differs from transcript")
                seal = ReviewerAttemptSealV1(
                    review_input_sha256=self._review_input.review_input_sha256,
                    task_id=self._review_input.task_id,
                    snapshot_id=self._review_input.snapshot_id,
                    manifest_sha256=self._review_input.manifest_sha256,
                    content_root=self._review_input.content_root,
                    tool_transcript_sha256=tool_transcript.transcript_sha256,
                    tool_record_count=len(tool_transcript.records),
                    model_transcript_sha256=model_transcript.transcript_sha256,
                    model_record_count=len(model_transcript.records),
                    source_ledger_sha256=reviewer_source_ledger_sha256(source_ledger),
                    source_read_count=source_ledger.read_calls,
                    artifact_catalog_root_sha256=reviewer_artifact_catalog_root_sha256(
                        tool_transcript.artifacts
                    ),
                    artifact_count=len(tool_transcript.artifacts),
                    budget_ledger_sha256=reviewer_budget_ledger_sha256(self._budget),
                    budget_event_count=len(self._budget.events),
                    used_artifacts=artifacts,
                    used_model_records=model_records,
                )
                canonical = ReviewerAttemptSealV1.from_dict(seal.to_dict())
                if canonical != seal:
                    raise ReviewerContextLedgerMismatch("attempt seal normalization differs")
            except BaseException as exc:
                if not isinstance(exc, Exception):
                    self._best_effort_close_capabilities()
                    raise
                error = ReviewerContextLedgerMismatch(
                    "reviewer runtime did not close into an attempt seal"
                )
                self._finalization_error = error
                raise error from exc
            self._seal = canonical
            return canonical

    def _best_effort_close_capabilities(self) -> None:
        for operation in (
            self._tool_runtime.finalize,
            self._model_runtime.finalize,
            self._toolbox.abort_source_usage,
        ):
            try:
                operation()
            except BaseException:
                pass

    def _abort_locked(self) -> None:
        if self._sealed:
            return
        self._sealed = True
        self._best_effort_close_capabilities()

    def abort(self) -> None:
        """Best-effort, idempotent, one-way closure without issuing a seal."""

        with self._lock:
            self._abort_locked()


__all__ = [
    "REVIEWER_ARTIFACT_CATALOG_DIGEST_DOMAIN",
    "REVIEWER_BUDGET_LEDGER_DIGEST_DOMAIN",
    "REVIEWER_CONTEXT_DIGEST_DOMAIN",
    "REVIEWER_MODEL_RECORD_DIGEST_DOMAIN",
    "REVIEWER_MODEL_REQUEST_CONTRACT_ID",
    "REVIEWER_SOURCE_LEDGER_DIGEST_DOMAIN",
    "ReviewerCandidateContext",
    "ReviewerContextBindingError",
    "ReviewerContextError",
    "ReviewerContextFinalized",
    "ReviewerContextLedgerMismatch",
    "ReviewerContextLimitExceeded",
    "ReviewerContextNode",
    "ReviewerContextSession",
    "ReviewerModelCall",
    "ReviewerValidationArtifact",
    "reviewer_artifact_catalog_root_sha256",
    "reviewer_budget_ledger_sha256",
    "reviewer_context_sha256",
    "reviewer_model_record_sha256",
    "reviewer_source_ledger_sha256",
]
