"""Source-native D2 discovery producer.

The model in this module never constructs a D0 candidate and never receives a
source capability.  It can only navigate a controller-issued, attempt-local
catalog and return opaque ``artifact_id``/``node_id`` pairs.  The controller
resolves those pairs against exact runtime objects, closes their artifact
graph, constructs candidates mechanically, and performs source validation
before releasing a draft.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import re
from threading import RLock
from typing import Any, Final, Literal

from vulngym_agent.agents.discovery_toolbox import (
    MAX_INVENTORY_BATCH_FILES,
    MAX_LINK_INPUTS,
    MAX_LINK_RESULTS,
    MAX_READ_SPANS,
    MAX_SEARCH_PATHS,
    MAX_SEARCH_RESULTS,
    MAX_STRUCTURE_RESULTS,
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
    DiscoveryTaskInputV1,
)
from vulngym_agent.benchmark.producer_contracts import (
    DEFAULT_PRODUCER_LIMITS,
    PRODUCER_SELECTION_DIGEST_DOMAIN,
    ProducerArtifactDigestRefV1,
    ProducerDeferredV1,
    ProducerDraftV1,
    ProducerResultV1,
    ValidationReceiptV1,
)
from vulngym_agent.benchmark.sealed_tree_access import (
    BoundSealedTree,
    SourceUsageLedger,
)
from vulngym_agent.orchestrator.budget import (
    LLM_CALLS,
    REPAIR_ITERATIONS,
    TOOL_CALLS,
    Budget,
    BudgetExceeded,
)
from vulngym_agent.tools.runtime import (
    ArtifactRef,
    AttemptToolRuntime,
    AttemptToolTranscript,
    ToolArtifact,
    ToolResult,
)


_ATTEMPT: Final[int] = 0
_POLICY_SCOPE: Final[str] = "t2.initial"
_MAX_RUNTIME_ARTIFACTS: Final[int] = 64
_MAX_CATALOG_ITEMS: Final[int] = 1_024
_MAX_MODEL_PAYLOAD_BYTES: Final[int] = 900 * 1_024
_MAX_CONTEXT_LINES: Final[int] = 127
_MAX_TRACE_NODES: Final[int] = 64
_MAX_MODEL_MISSING_ITEMS: Final[int] = 32
_MAX_MODEL_MISSING_CHARS: Final[int] = 2_048
_MAX_MODEL_JSON_NODES: Final[int] = 9_500

_NODE_REF_KEYS: Final[frozenset[str]] = frozenset({"artifact_id", "node_id"})
_REASON_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_ARTIFACT_KINDS: Final[frozenset[str]] = frozenset(
    {
        "discovery.source_inventory",
        "discovery.source_search",
        "discovery.source_spans",
        "discovery.source_structure",
        "discovery.source_relationships",
    }
)
_TOOL_ARTIFACT_KINDS: Final[Mapping[str, str]] = {
    "source_inventory": "discovery.source_inventory",
    "source_link": "discovery.source_relationships",
    "source_read": "discovery.source_spans",
    "source_search": "discovery.source_search",
    "source_structure": "discovery.source_structure",
    "source_validate": "discovery.source_validation",
}


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw(child) for child in value]
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _thaw(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _tool_arguments_sha256(value: Any) -> str:
    """Mirror the runtime's public ArtifactRef wire encoding for one call."""

    def wire(item: Any) -> Any:
        if type(item) is ArtifactRef:
            return {"$artifact_ref": item.to_dict()}
        if isinstance(item, Mapping):
            return {str(key): wire(child) for key, child in item.items()}
        if isinstance(item, (tuple, list)):
            return [wire(child) for child in item]
        return item

    return _sha256(wire(value))


def _node_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{_sha256(value)[:32].upper()}"


def _selection_digest_v1(
    task: DiscoveryTaskInputV1, selection: Mapping[str, Any]
) -> str:
    """Bind one normalized opaque selection under the public D2 domain."""

    payload = {
        "critical": _thaw(selection["critical"]),
        "entry": _thaw(selection["entry"]),
        "relationships": _thaw(selection["relationships"]),
        "task": task.to_dict(),
        "trace": _thaw(selection["trace"]),
    }
    return hashlib.sha256(
        PRODUCER_SELECTION_DIGEST_DOMAIN + _canonical_bytes(payload)
    ).hexdigest()


def _ordered(value: Any, *, maximum: int, allow_empty: bool = False) -> tuple[Any, ...]:
    if (
        isinstance(value, (str, bytes, bytearray, Mapping, set, frozenset))
        or not isinstance(value, Sequence)
    ):
        raise ValueError("ordered collection required")
    result = tuple(value)
    if len(result) > maximum or (not allow_empty and not result):
        raise ValueError("ordered collection has an invalid count")
    return result


def _exact(value: Any, keys: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("object required")
    try:
        actual = tuple(value)
    except (TypeError, ValueError, RuntimeError):
        raise ValueError("object cannot be inspected") from None
    if any(type(key) is not str for key in actual):
        raise ValueError("object keys must be strings")
    if frozenset(actual) != keys or len(actual) != len(keys):
        raise ValueError("object has unexpected keys")
    return value


def _integer(value: Any, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("integer is outside its fixed bounds")
    return value


@dataclass(frozen=True, slots=True)
class _CatalogNode:
    artifact_id: str
    node_id: str
    node_type: Literal["FIL", "MAT", "LOC", "LEX"]
    path: str
    line: int | None
    code_sha256: str | None
    view: Mapping[str, Any]

    @property
    def key(self) -> tuple[str, str]:
        return (self.artifact_id, self.node_id)


@dataclass(frozen=True, slots=True)
class _CatalogRelationship:
    artifact_id: str
    node_id: str
    call_node_id: str
    declaration_node_id: str
    view: Mapping[str, Any]

    @property
    def key(self) -> tuple[str, str]:
        return (self.artifact_id, self.node_id)


@dataclass(frozen=True, slots=True)
class _Selection:
    entry: _CatalogNode
    critical: _CatalogNode
    trace: tuple[_CatalogNode, ...]
    relationships: tuple[_CatalogRelationship, ...]
    wire: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _BuiltCandidate:
    candidate: DiscoveryCandidate
    selection_digest: str


class _Deferred(Exception):
    __slots__ = ("stage", "reason_code", "missing")

    def __init__(
        self,
        stage: Literal["SCOUT", "ANALYZE", "VALIDATE", "FINALIZE"],
        reason_code: str,
        missing: tuple[str, ...],
    ) -> None:
        self.stage = stage
        self.reason_code = reason_code
        self.missing = missing
        super().__init__(reason_code)


class _CatalogLimit(ValueError):
    """The complete catalog cannot cross a fixed controller boundary."""


class _ArtifactCatalog:
    """Controller-private exact artifact graph and model-facing projection."""

    __slots__ = (
        "_artifacts",
        "_direct_upstream",
        "_nodes",
        "_refs",
        "_relationships",
        "_task",
    )

    def __init__(self, task: DiscoveryTaskInputV1) -> None:
        self._task = task
        self._refs: dict[str, ArtifactRef] = {}
        self._artifacts: dict[str, ToolArtifact] = {}
        self._direct_upstream: dict[str, tuple[str, ...]] = {}
        self._nodes: dict[tuple[str, str], _CatalogNode] = {}
        self._relationships: dict[
            tuple[str, str], _CatalogRelationship
        ] = {}

    @property
    def artifact_count(self) -> int:
        return len(self._artifacts)

    def ref(self, artifact_id: str) -> ArtifactRef:
        return self._refs[artifact_id]

    def artifact(self, artifact_id: str) -> ToolArtifact:
        return self._artifacts[artifact_id]

    def node(self, value: Any, *, types: frozenset[str]) -> _CatalogNode:
        ref = _exact(value, _NODE_REF_KEYS)
        artifact_id = ref.get("artifact_id")
        node_id = ref.get("node_id")
        if type(artifact_id) is not str or type(node_id) is not str:
            raise ValueError("opaque node reference is invalid")
        try:
            node = self._nodes[(artifact_id, node_id)]
        except KeyError:
            raise ValueError("opaque node reference was not issued") from None
        if node.node_type not in types:
            raise ValueError("opaque node has the wrong type")
        return node

    def relationship(self, value: Any) -> _CatalogRelationship:
        ref = _exact(value, _NODE_REF_KEYS)
        artifact_id = ref.get("artifact_id")
        node_id = ref.get("node_id")
        if type(artifact_id) is not str or type(node_id) is not str:
            raise ValueError("opaque relationship reference is invalid")
        try:
            return self._relationships[(artifact_id, node_id)]
        except KeyError:
            raise ValueError("opaque relationship reference was not issued") from None

    def _snapshot(self) -> dict[str, Any]:
        return {
            "commit": self._task.commit,
            "repo_url": self._task.repo_url,
            "snapshot_content_root": self._task.snapshot_content_root,
            "snapshot_id": self._task.snapshot_id,
            "snapshot_manifest_sha256": self._task.snapshot_manifest_sha256,
            "task_id": self._task.task_id,
        }

    @staticmethod
    def _array(value: Any, *, maximum: int = 4_097) -> tuple[Any, ...]:
        return _ordered(value, maximum=maximum, allow_empty=True)

    def add(self, ref: ArtifactRef, artifact: ToolArtifact) -> None:
        if (
            not isinstance(ref, ArtifactRef)
            or not isinstance(artifact, ToolArtifact)
            or artifact.artifact_id != ref.artifact_id
            or artifact.artifact_sha256 != ref.artifact_sha256
            or artifact.kind not in _ARTIFACT_KINDS
            or ref.artifact_id in self._refs
        ):
            raise ValueError("runtime artifact binding is invalid")
        payload = artifact.payload
        if not isinstance(payload, Mapping) or _thaw(payload.get("snapshot")) != self._snapshot():
            raise ValueError("artifact snapshot binding is invalid")
        upstream_raw = self._array(payload.get("upstream_artifacts"), maximum=64)
        upstream: list[str] = []
        for item in upstream_raw:
            pair = _exact(item, frozenset({"artifact_id", "artifact_sha256"}))
            artifact_id = pair.get("artifact_id")
            digest = pair.get("artifact_sha256")
            if (
                not isinstance(artifact_id, str)
                or not isinstance(digest, str)
                or artifact_id not in self._refs
                or self._refs[artifact_id].artifact_sha256 != digest
                or artifact_id in upstream
            ):
                raise ValueError("artifact upstream closure is invalid")
            upstream.append(artifact_id)

        self._refs[ref.artifact_id] = ref
        self._artifacts[ref.artifact_id] = artifact
        self._direct_upstream[ref.artifact_id] = tuple(upstream)
        try:
            if artifact.kind == "discovery.source_inventory":
                self._add_inventory(artifact)
            elif artifact.kind == "discovery.source_search":
                self._add_search(artifact)
            elif artifact.kind == "discovery.source_spans":
                self._add_spans(artifact)
            elif artifact.kind == "discovery.source_structure":
                self._add_structure(artifact)
            elif artifact.kind == "discovery.source_relationships":
                self._add_relationships(artifact)
            self._check_limits()
        except Exception:
            self._refs.pop(ref.artifact_id, None)
            self._artifacts.pop(ref.artifact_id, None)
            self._direct_upstream.pop(ref.artifact_id, None)
            for key in tuple(self._nodes):
                if key[0] == ref.artifact_id:
                    self._nodes.pop(key)
            for key in tuple(self._relationships):
                if key[0] == ref.artifact_id:
                    self._relationships.pop(key)
            raise

    def _check_limits(self) -> None:
        if len(self._nodes) + len(self._relationships) > _MAX_CATALOG_ITEMS:
            raise _CatalogLimit("catalog item limit exceeded")

    def _put_node(self, node: _CatalogNode) -> None:
        if node.key in self._nodes:
            raise ValueError("catalog node repeats an opaque reference")
        self._nodes[node.key] = node

    def _add_inventory(self, artifact: ToolArtifact) -> None:
        files = self._array(artifact.payload.get("files"), maximum=MAX_INVENTORY_BATCH_FILES)
        for raw in files:
            item = _exact(raw, frozenset({"blob_oid", "git_mode", "path", "sha256", "size"}))
            path, digest, size = item.get("path"), item.get("sha256"), item.get("size")
            if not isinstance(path, str) or not isinstance(digest, str) or type(size) is not int:
                raise ValueError("inventory record is invalid")
            node_id = _node_id(
                "FIL",
                {
                    "artifact_sha256": artifact.artifact_sha256,
                    "path": path,
                    "sha256": digest,
                    "snapshot_id": self._task.snapshot_id,
                },
            )
            self._put_node(
                _CatalogNode(
                    artifact_id=artifact.artifact_id,
                    node_id=node_id,
                    node_type="FIL",
                    path=path,
                    line=None,
                    code_sha256=digest,
                    view={"path": path, "size": size},
                )
            )

    def _add_search(self, artifact: ToolArtifact) -> None:
        matches = self._array(artifact.payload.get("matches"), maximum=MAX_SEARCH_RESULTS)
        required = frozenset(
            {
                "column_end",
                "column_start",
                "excerpt",
                "excerpt_start_column",
                "line",
                "line_code_sha256",
                "match_sha256",
                "path",
            }
        )
        for index, raw in enumerate(matches):
            item = _exact(raw, required)
            path, line, digest = item.get("path"), item.get("line"), item.get("line_code_sha256")
            if not isinstance(path, str) or type(line) is not int or not isinstance(digest, str):
                raise ValueError("search match is invalid")
            node_id = _node_id(
                "MAT",
                {
                    "artifact_sha256": artifact.artifact_sha256,
                    "index": index,
                    "line": line,
                    "path": path,
                    "snapshot_id": self._task.snapshot_id,
                },
            )
            self._put_node(
                _CatalogNode(
                    artifact_id=artifact.artifact_id,
                    node_id=node_id,
                    node_type="MAT",
                    path=path,
                    line=line,
                    code_sha256=digest,
                    view={
                        "column_end": item.get("column_end"),
                        "column_start": item.get("column_start"),
                        "excerpt": item.get("excerpt"),
                        "line": line,
                        "path": path,
                    },
                )
            )

    def _add_spans(self, artifact: ToolArtifact) -> None:
        spans = self._array(artifact.payload.get("spans"), maximum=MAX_READ_SPANS)
        required = frozenset(
            {"code_sha256", "file_sha256", "line_end", "line_start", "path", "text"}
        )
        for span_index, raw in enumerate(spans):
            span = _exact(raw, required)
            path, start, end, text = (
                span.get("path"),
                span.get("line_start"),
                span.get("line_end"),
                span.get("text"),
            )
            if (
                not isinstance(path, str)
                or type(start) is not int
                or type(end) is not int
                or not isinstance(text, str)
                or not 1 <= start <= end
            ):
                raise ValueError("source span is invalid")
            encoded = text.encode("utf-8")
            # Match the sealed reader's byte-oriented keepends semantics.  In
            # particular, Unicode line-separator code points are source bytes,
            # not repository line boundaries.
            lines = encoded.splitlines(keepends=True)
            if len(lines) != end - start + 1:
                raise ValueError("source span line count is invalid")
            if hashlib.sha256(encoded).hexdigest() != span.get("code_sha256"):
                raise ValueError("source span digest is invalid")
            for offset, line_bytes in enumerate(lines):
                line = start + offset
                digest = hashlib.sha256(line_bytes).hexdigest()
                line_text = line_bytes.decode("utf-8")
                node_id = _node_id(
                    "LOC",
                    {
                        "artifact_sha256": artifact.artifact_sha256,
                        "code_sha256": digest,
                        "line": line,
                        "path": path,
                        "snapshot_id": self._task.snapshot_id,
                        "span_index": span_index,
                    },
                )
                self._put_node(
                    _CatalogNode(
                        artifact_id=artifact.artifact_id,
                        node_id=node_id,
                        node_type="LOC",
                        path=path,
                        line=line,
                        code_sha256=digest,
                        view={"line": line, "path": path, "text": line_text},
                    )
                )

    def _add_structure(self, artifact: ToolArtifact) -> None:
        nodes = self._array(artifact.payload.get("lexical_nodes"), maximum=MAX_STRUCTURE_RESULTS)
        required = frozenset(
            {
                "code_sha256",
                "column_end",
                "column_start",
                "kind",
                "line",
                "node_id",
                "path",
                "source_artifact_id",
                "token",
            }
        )
        upstream = self._direct_upstream[artifact.artifact_id]
        for raw in nodes:
            item = _exact(raw, required)
            node_id, path, line, digest, source_id = (
                item.get("node_id"),
                item.get("path"),
                item.get("line"),
                item.get("code_sha256"),
                item.get("source_artifact_id"),
            )
            if (
                not isinstance(node_id, str)
                or not node_id.startswith("LEX-")
                or not isinstance(path, str)
                or type(line) is not int
                or not isinstance(digest, str)
                or source_id not in upstream
                or self._artifacts[source_id].kind != "discovery.source_spans"
            ):
                raise ValueError("lexical node is invalid")
            self._put_node(
                _CatalogNode(
                    artifact_id=artifact.artifact_id,
                    node_id=node_id,
                    node_type="LEX",
                    path=path,
                    line=line,
                    code_sha256=digest,
                    view={
                        "column_end": item.get("column_end"),
                        "column_start": item.get("column_start"),
                        "kind": item.get("kind"),
                        "line": line,
                        "path": path,
                        "token": item.get("token"),
                    },
                )
            )

    def _upstream_lexical_node(self, relationship_artifact_id: str, node_id: str) -> _CatalogNode:
        matches = [
            self._nodes[(artifact_id, node_id)]
            for artifact_id in self._direct_upstream[relationship_artifact_id]
            if (artifact_id, node_id) in self._nodes
            and self._nodes[(artifact_id, node_id)].node_type == "LEX"
        ]
        if len(matches) != 1:
            raise ValueError("relationship endpoint is not exactly closed")
        return matches[0]

    def _add_relationships(self, artifact: ToolArtifact) -> None:
        upstream = self._direct_upstream[artifact.artifact_id]
        if not upstream or any(
            self._artifacts[item].kind != "discovery.source_structure" for item in upstream
        ):
            raise ValueError("relationship upstream is invalid")
        relationships = self._array(
            artifact.payload.get("mechanical_relationships"), maximum=MAX_LINK_RESULTS
        )
        required = frozenset(
            {
                "call_node_id",
                "declaration_node_id",
                "link_id",
                "relation",
                "semantic_status",
                "symbol",
            }
        )
        for raw in relationships:
            item = _exact(raw, required)
            link_id = item.get("link_id")
            call_id = item.get("call_node_id")
            declaration_id = item.get("declaration_node_id")
            if (
                not isinstance(link_id, str)
                or not link_id.startswith("REL-")
                or not isinstance(call_id, str)
                or not isinstance(declaration_id, str)
                or item.get("relation") != "literal_symbol_match"
                or item.get("semantic_status") != "unverified"
            ):
                raise ValueError("mechanical relationship is invalid")
            call = self._upstream_lexical_node(artifact.artifact_id, call_id)
            declaration = self._upstream_lexical_node(
                artifact.artifact_id, declaration_id
            )
            if (
                call.view.get("kind") != "call"
                or not str(declaration.view.get("kind", "")).endswith("_declaration")
                or call.view.get("token") != item.get("symbol")
                or declaration.view.get("token") != item.get("symbol")
            ):
                raise ValueError("mechanical relationship endpoints do not match")
            relationship = _CatalogRelationship(
                artifact_id=artifact.artifact_id,
                node_id=link_id,
                call_node_id=call_id,
                declaration_node_id=declaration_id,
                view={
                    "call_ref": {
                        "artifact_id": call.artifact_id,
                        "node_id": call.node_id,
                    },
                    "declaration_ref": {
                        "artifact_id": declaration.artifact_id,
                        "node_id": declaration.node_id,
                    },
                    "relation": "literal_symbol_match",
                    "semantic_status": "unverified",
                    "symbol": item.get("symbol"),
                },
            )
            if relationship.key in self._relationships:
                raise ValueError("catalog relationship repeats an opaque reference")
            self._relationships[relationship.key] = relationship

    def closure(self, artifact_ids: Sequence[str]) -> tuple[str, ...]:
        seen: set[str] = set()

        def visit(artifact_id: str) -> None:
            if artifact_id in seen:
                return
            if artifact_id not in self._artifacts:
                raise ValueError("artifact closure references an unknown artifact")
            seen.add(artifact_id)
            for upstream in self._direct_upstream[artifact_id]:
                visit(upstream)

        for artifact_id in artifact_ids:
            visit(artifact_id)
        return tuple(sorted(seen))

    def covering_span(self, node: _CatalogNode) -> str:
        if node.line is None or node.code_sha256 is None:
            raise ValueError("candidate node is not a source location")
        matches: list[str] = []
        for candidate in self._nodes.values():
            if (
                candidate.node_type == "LOC"
                and candidate.path == node.path
                and candidate.line == node.line
                and candidate.code_sha256 == node.code_sha256
            ):
                matches.append(candidate.artifact_id)
        if not matches:
            raise ValueError("candidate location lacks a source span")
        return sorted(set(matches))[0]

    def relationship_endpoints(self, relationship: _CatalogRelationship) -> tuple[_CatalogNode, _CatalogNode]:
        return (
            self._upstream_lexical_node(relationship.artifact_id, relationship.call_node_id),
            self._upstream_lexical_node(
                relationship.artifact_id, relationship.declaration_node_id
            ),
        )

    def model_view(self) -> Mapping[str, Any]:
        nodes = [
            {
                "ref": {"artifact_id": item.artifact_id, "node_id": item.node_id},
                "type": item.node_type,
                **_thaw(item.view),
            }
            for item in sorted(
                self._nodes.values(),
                key=lambda value: (value.node_type, value.artifact_id, value.node_id),
            )
        ]
        relationships = [
            {
                "ref": {"artifact_id": item.artifact_id, "node_id": item.node_id},
                **_thaw(item.view),
            }
            for item in sorted(
                self._relationships.values(),
                key=lambda value: (value.artifact_id, value.node_id),
            )
        ]
        if len(nodes) + len(relationships) > _MAX_CATALOG_ITEMS:
            raise ValueError("catalog item limit exceeded")
        return {"nodes": nodes, "relationships": relationships}


class SourceDiscoveryAttemptController:
    """Run one fail-closed, source-only D2 producer attempt.

    Invalid public inputs are rejected before ``tree`` is claimed.  Once the
    atomic claim succeeds, an unexpected assembly failure closes the source
    capability rather than returning a second usable owner.
    """

    __slots__ = (
        "_attempt_digest",
        "_budget",
        "_catalog",
        "_expected_model_records",
        "_expected_tool_artifacts",
        "_expected_tool_records",
        "_initial_events",
        "_initial_usage",
        "_lock",
        "_model_calls",
        "_model_runtime",
        "_result",
        "_running",
        "_sealed",
        "_stage",
        "_task",
        "_tool_calls",
        "_tool_runtime",
        "_toolbox",
    )

    def __init__(
        self,
        task: DiscoveryTaskInputV1,
        tree: BoundSealedTree,
        budget: Budget,
        backend: StructuredModelBackend,
    ) -> None:
        if type(task) is not DiscoveryTaskInputV1:
            raise ValueError("task must be DiscoveryTaskInputV1")
        if not isinstance(budget, Budget):
            raise ValueError("budget must be Budget")
        self._task = task
        self._budget = budget
        self._initial_events = budget.events
        self._initial_usage = budget.usage
        model_runtime = AttemptModelRuntime(
            task_id=task.task_id,
            attempt=_ATTEMPT,
            policy_scope=_POLICY_SCOPE,
            budget=budget,
            backend=backend,
        )
        toolbox = DiscoveryToolbox(task, tree)
        tool_runtime: AttemptToolRuntime | None = None
        try:
            toolbox.claim_source_usage()
            source_usage = toolbox.usage_snapshot()
            if (
                type(source_usage) is not SourceUsageLedger
                or source_usage.task_id != task.task_id
                or source_usage.snapshot_id != task.snapshot_id
                or source_usage.finalized
                or source_usage.verification_succeeded
                or source_usage.inventory_calls != 0
                or source_usage.read_calls != 0
                or source_usage.bytes_read != 0
                or source_usage.reads
            ):
                raise ValueError("tree must be a fresh source capability")
            tool_runtime = AttemptToolRuntime(
                task_id=task.task_id,
                attempt=_ATTEMPT,
                policy_scope=_POLICY_SCOPE,
                budget=budget,
                registry=toolbox.definitions,
                allowlist=toolbox.tool_names,
            )
            self._toolbox = toolbox
            self._tool_runtime = tool_runtime
            self._model_runtime = model_runtime
            self._expected_model_records: list[Any] = []
            self._expected_tool_records: list[ToolResult] = []
            self._expected_tool_artifacts: list[ToolArtifact] = []
            self._catalog = _ArtifactCatalog(task)
            self._attempt_digest = _sha256(
                {
                    "policy_scope": _POLICY_SCOPE,
                    "snapshot_id": task.snapshot_id,
                    "task_id": task.task_id,
                }
            )[:16]
            self._model_calls = 0
            self._tool_calls = 0
            self._sealed = False
            self._stage: Literal["SCOUT", "ANALYZE", "VALIDATE", "FINALIZE"] = "SCOUT"
            self._result: ProducerResultV1 | None = None
            self._running = False
            self._lock = RLock()
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

    def _deferred(
        self,
        stage: Literal["SCOUT", "ANALYZE", "VALIDATE", "FINALIZE"],
        reason: str,
        *missing: str,
    ) -> ProducerDeferredV1:
        return ProducerDeferredV1(
            task=self._task,
            stage=stage,
            reason_code=reason,
            missing_information=tuple(missing) or ("producer evidence is incomplete",),
        )

    def _model_id(self, phase: str) -> str:
        self._model_calls += 1
        return f"MODEL-{self._attempt_digest}-{self._model_calls:03d}-{phase}"

    def _tool_id(self, name: str) -> str:
        self._tool_calls += 1
        return f"TOOL-{self._attempt_digest}-{self._tool_calls:03d}-{name}"

    def _model_payload(self, phase: Literal["SCOUT", "ANALYZE"], last: Mapping[str, Any]) -> Mapping[str, Any]:
        catalog = self._catalog.model_view()
        payload = {
            "action_contracts": {
                "advance": {"exact_keys": ["action"]},
                "defer": {
                    "exact_keys": [
                        "action",
                        "missing_information",
                        "reason_code",
                    ]
                },
                "inventory": {
                    "exact_keys": ["action", "cursor", "limit"],
                    "limit_range": [1, MAX_INVENTORY_BATCH_FILES],
                },
                "link": {
                    "exact_keys": [
                        "action",
                        "cursor",
                        "limit",
                        "structures",
                    ],
                    "structures": "1..16 LEX opaque refs with distinct owners",
                },
                "read": {
                    "exact_keys": ["action", "locations"],
                    "location_exact_keys": [
                        "artifact_id",
                        "context_after",
                        "context_before",
                        "node_id",
                    ],
                    "locations": "1..16 FIL/MAT/LOC/LEX opaque refs",
                    "context_range": [0, _MAX_CONTEXT_LINES],
                },
                "search": {
                    "exact_keys": [
                        "action",
                        "cursor",
                        "files",
                        "limit",
                        "query",
                    ],
                    "files": "1..64 FIL opaque refs",
                    "query": "non-empty case-sensitive literal, at most 128 characters",
                },
                "select": {
                    "candidate_exact_keys": [
                        "critical",
                        "entry",
                        "relationships",
                        "trace",
                    ],
                    "exact_keys": ["action", "candidates"],
                    "relationships": "non-empty REL opaque refs",
                },
                "structure": {
                    "exact_keys": ["action", "cursor", "limit", "source"],
                    "source": "one LOC opaque ref",
                },
            },
            "allowed_actions": (
                ["inventory", "search", "read", "structure", "link", "defer", "advance"]
                if phase == "SCOUT"
                else ["inventory", "search", "read", "structure", "link", "defer", "select"]
            ),
            "catalog": catalog,
            "last_result": _thaw(last),
            "phase": phase,
            "selection_contract": {
                "candidate": {
                    "critical": "opaque node ref",
                    "entry": "opaque node ref",
                    "relationships": "non-empty opaque relationship refs",
                    "trace": "ordered opaque node refs",
                },
                "opaque_ref_keys": ["artifact_id", "node_id"],
                "raw_locations_or_hashes_forbidden": True,
            },
            "task": self._task.to_dict(),
        }
        nodes = 0

        def count(value: Any) -> None:
            nonlocal nodes
            nodes += 1
            if nodes > _MAX_MODEL_JSON_NODES:
                raise _CatalogLimit("model request JSON-node limit exceeded")
            if isinstance(value, Mapping):
                for key, child in value.items():
                    count(key)
                    count(child)
            elif isinstance(value, (tuple, list)):
                for child in value:
                    count(child)

        try:
            count(payload)
            too_large = len(_canonical_bytes(payload)) > _MAX_MODEL_PAYLOAD_BYTES
        except _CatalogLimit:
            too_large = True
        if too_large:
            raise _Deferred(
                phase,
                "catalog_limit_exceeded",
                ("complete catalog exceeds the model request byte limit",),
            )
        return payload

    def _call_model(self, phase: Literal["SCOUT", "ANALYZE"], last: Mapping[str, Any]) -> Mapping[str, Any]:
        if self._sealed:
            raise _Deferred(phase, "invalid_state", ("attempt is already sealed",))
        runtime_stage = "plan" if phase == "SCOUT" else "semantic_judge"
        call_id = self._model_id(phase)
        payload = self._model_payload(phase, last)
        request_sha256 = structured_json_sha256(payload)
        backend_id = self._model_runtime.backend_id
        model_id = self._model_runtime.model_id
        expected_operation = (
            f"model:{self._task.task_id}:{_ATTEMPT}:{_POLICY_SCOPE}:"
            f"{runtime_stage}:{call_id}:{backend_id}:{model_id}:{request_sha256}"
        )
        result = self._model_runtime.call(call_id, runtime_stage, payload)
        if (
            type(result) is not ModelResult
            or result.task_id != self._task.task_id
            or result.attempt != _ATTEMPT
            or result.policy_scope != _POLICY_SCOPE
            or result.model_call_id != call_id
            or result.stage != runtime_stage
            or result.backend_id != backend_id
            or result.model_id != model_id
            or result.request_sha256 != request_sha256
            or result.operation != expected_operation
        ):
            raise _Deferred(
                phase,
                "model_binding_invalid",
                ("model result did not bind the exact controller call",),
            )
        self._expected_model_records.append(result.to_model_call_record())
        if result.status == "blocked":
            raise _Deferred(phase, "model_blocked", ("structured model call was blocked",))
        if result.status != "success" or result.response is None:
            raise _Deferred(phase, "model_error", ("structured model call failed",))
        return result.response

    def _resolve_bound_artifact(
        self,
        result: ToolResult,
        ref: ArtifactRef,
        *,
        expected_kind: str,
        record_artifact: bool = False,
    ) -> ToolArtifact:
        if (
            type(ref) is not ArtifactRef
            or ref.task_id != self._task.task_id
            or ref.attempt != _ATTEMPT
            or ref.policy_scope != _POLICY_SCOPE
        ):
            raise ValueError("artifact reference scope differs from the controller call")
        if self._tool_runtime.artifact_ref(ref.artifact_id) is not ref:
            raise ValueError("artifact reference was not issued by this runtime")
        matches = tuple(
            item
            for item in self._tool_runtime.artifacts
            if item.artifact_id == ref.artifact_id
        )
        if len(matches) != 1:
            raise ValueError("artifact is absent from the runtime ledger")
        artifact = matches[0]
        if (
            type(artifact) is not ToolArtifact
            or artifact.task_id != self._task.task_id
            or artifact.attempt != _ATTEMPT
            or artifact.policy_scope != _POLICY_SCOPE
            or artifact.tool_call_id != result.tool_call_id
            or artifact.artifact_id != ref.artifact_id
            or artifact.artifact_sha256 != ref.artifact_sha256
            or artifact.kind != expected_kind
        ):
            raise ValueError("artifact did not bind the exact result and reference")
        if record_artifact:
            if any(
                existing.artifact_id == artifact.artifact_id
                for existing in self._expected_tool_artifacts
            ):
                raise ValueError("controller observed a duplicate artifact ID")
            self._expected_tool_artifacts.append(artifact)
        if self._tool_runtime.resolve_artifact(ref) is not artifact:
            raise ValueError("artifact resolution differs from the runtime ledger")
        return artifact

    def _call_tool(
        self,
        phase: Literal["SCOUT", "ANALYZE", "VALIDATE"],
        name: str,
        arguments: Mapping[str, Any],
        *,
        catalog: bool = True,
    ) -> ToolResult:
        if self._sealed:
            raise _Deferred(phase, "invalid_state", ("attempt is already sealed",))
        call_id = self._tool_id(name)
        arguments_sha256 = _tool_arguments_sha256(arguments)
        expected_operation = (
            f"tool:{self._task.task_id}:{_ATTEMPT}:{_POLICY_SCOPE}:{call_id}:{name}"
        )
        result = self._tool_runtime.call(call_id, name, arguments)
        if (
            type(result) is not ToolResult
            or result.task_id != self._task.task_id
            or result.attempt != _ATTEMPT
            or result.policy_scope != _POLICY_SCOPE
            or result.tool_call_id != call_id
            or result.tool_name != name
            or result.arguments_sha256 != arguments_sha256
            or result.operation != expected_operation
        ):
            raise _Deferred(
                phase,
                "tool_binding_invalid",
                ("tool result did not bind the exact controller call",),
            )
        self._expected_tool_records.append(result)
        if result.status == "blocked":
            raise _Deferred(
                phase,
                "tool_blocked",
                (f"{name} was blocked with {result.error_code or 'unknown'}",),
            )
        if result.status != "success":
            raise _Deferred(phase, "tool_error", (f"{name} failed",))
        if len(result.artifact_refs) != 1:
            raise _Deferred(
                phase,
                "artifact_binding_invalid",
                ("tool did not issue exactly one artifact",),
            )
        ref = result.artifact_refs[0]
        try:
            artifact = self._resolve_bound_artifact(
                result,
                ref,
                expected_kind=_TOOL_ARTIFACT_KINDS[name],
                record_artifact=True,
            )
            if catalog:
                self._catalog.add(ref, artifact)
        except _CatalogLimit:
            raise _Deferred(
                phase,
                "catalog_limit_exceeded",
                ("complete catalog exceeds its fixed item limit",),
            ) from None
        except Exception:
            raise _Deferred(
                phase,
                "artifact_binding_invalid",
                ("tool artifact did not close against the exact controller call",),
            ) from None
        return result

    def _ref(self, value: Any, *, types: frozenset[str]) -> _CatalogNode:
        return self._catalog.node(value, types=types)

    def _tool_action(
        self,
        phase: Literal["SCOUT", "ANALYZE"],
        action: str,
        response: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if action == "inventory":
            value = _exact(response, frozenset({"action", "cursor", "limit"}))
            arguments = {
                "cursor": _integer(value.get("cursor"), minimum=0, maximum=1_000_000),
                "limit": _integer(value.get("limit"), minimum=1, maximum=MAX_INVENTORY_BATCH_FILES),
            }
            result = self._call_tool(phase, "source_inventory", arguments)
        elif action == "search":
            value = _exact(response, frozenset({"action", "cursor", "files", "limit", "query"}))
            files = _ordered(value.get("files"), maximum=MAX_SEARCH_PATHS)
            paths = [self._ref(item, types=frozenset({"FIL"})).path for item in files]
            query = value.get("query")
            if (
                type(query) is not str
                or not query
                or len(query) > 128
                or "\n" in query
                or "\r" in query
            ):
                raise ValueError("literal query is invalid")
            if len(paths) != len(set(paths)):
                raise ValueError("search file selection repeats a path")
            arguments = {
                "cursor": _integer(value.get("cursor"), minimum=0, maximum=4_096),
                "limit": _integer(value.get("limit"), minimum=1, maximum=MAX_SEARCH_RESULTS),
                "paths": sorted(paths),
                "query": query,
            }
            result = self._call_tool(phase, "source_search", arguments)
        elif action == "read":
            value = _exact(response, frozenset({"action", "locations"}))
            selected = _ordered(value.get("locations"), maximum=MAX_READ_SPANS)
            spans: list[dict[str, Any]] = []
            for raw in selected:
                item = _exact(
                    raw,
                    frozenset({"artifact_id", "context_after", "context_before", "node_id"}),
                )
                node = self._ref(
                    {"artifact_id": item.get("artifact_id"), "node_id": item.get("node_id")},
                    types=frozenset({"FIL", "MAT", "LOC", "LEX"}),
                )
                before = _integer(item.get("context_before"), minimum=0, maximum=_MAX_CONTEXT_LINES)
                after = _integer(item.get("context_after"), minimum=0, maximum=_MAX_CONTEXT_LINES)
                line = 1 if node.line is None else node.line
                spans.append(
                    {
                        "line_end": line + after,
                        "line_start": max(1, line - before),
                        "path": node.path,
                    }
                )
            identities = [(item["path"], item["line_start"], item["line_end"]) for item in spans]
            if len(identities) != len(set(identities)):
                raise ValueError("read selection repeats a span")
            result = self._call_tool(phase, "source_read", {"spans": spans})
        elif action == "structure":
            value = _exact(response, frozenset({"action", "cursor", "limit", "source"}))
            node = self._ref(value.get("source"), types=frozenset({"LOC"}))
            arguments = {
                "cursor": _integer(value.get("cursor"), minimum=0, maximum=4_096),
                "limit": _integer(value.get("limit"), minimum=1, maximum=MAX_STRUCTURE_RESULTS),
                "source": self._catalog.ref(node.artifact_id),
            }
            result = self._call_tool(phase, "source_structure", arguments)
        elif action == "link":
            value = _exact(response, frozenset({"action", "cursor", "limit", "structures"}))
            selected = _ordered(value.get("structures"), maximum=MAX_LINK_INPUTS)
            owners = [self._ref(item, types=frozenset({"LEX"})).artifact_id for item in selected]
            if len(owners) != len(set(owners)):
                raise ValueError("link selection repeats a structure artifact")
            arguments = {
                "cursor": _integer(value.get("cursor"), minimum=0, maximum=4_096),
                "limit": _integer(value.get("limit"), minimum=1, maximum=MAX_LINK_RESULTS),
                "structures": [self._catalog.ref(item) for item in sorted(owners)],
            }
            result = self._call_tool(phase, "source_link", arguments)
        else:
            raise ValueError("unknown tool action")
        return {
            "action": action,
            "artifact_ids": [item.artifact_id for item in result.artifact_refs],
            "status": result.status,
            "summary": _thaw(result.output),
        }

    @staticmethod
    def _wire_ref(node: _CatalogNode | _CatalogRelationship) -> dict[str, str]:
        return {"artifact_id": node.artifact_id, "node_id": node.node_id}

    def _parse_selections(self, response: Mapping[str, Any]) -> tuple[_Selection, ...]:
        value = _exact(response, frozenset({"action", "candidates"}))
        raw_candidates = _ordered(
            value.get("candidates"),
            maximum=DEFAULT_PRODUCER_LIMITS.max_candidates,
            allow_empty=True,
        )
        selections: list[_Selection] = []
        for raw in raw_candidates:
            item = _exact(raw, frozenset({"critical", "entry", "relationships", "trace"}))
            entry = self._ref(item.get("entry"), types=frozenset({"MAT", "LOC", "LEX"}))
            critical = self._ref(item.get("critical"), types=frozenset({"MAT", "LOC", "LEX"}))
            trace = tuple(
                self._ref(node, types=frozenset({"MAT", "LOC", "LEX"}))
                for node in _ordered(item.get("trace"), maximum=_MAX_TRACE_NODES, allow_empty=True)
            )
            relationships = tuple(
                self._catalog.relationship(rel)
                for rel in _ordered(item.get("relationships"), maximum=64)
            )
            relationship_keys = [relationship.key for relationship in relationships]
            if len(relationship_keys) != len(set(relationship_keys)):
                raise ValueError("candidate repeats a relationship reference")
            relationships = tuple(
                sorted(relationships, key=lambda value: value.key)
            )
            node_keys = {node.key for node in (entry, critical, *trace)}
            for relationship in relationships:
                endpoints = self._catalog.relationship_endpoints(relationship)
                if {endpoints[0].key, endpoints[1].key} - node_keys:
                    raise ValueError("selected relationship is unrelated to candidate locations")
            wire = {
                "critical": self._wire_ref(critical),
                "entry": self._wire_ref(entry),
                "relationships": [self._wire_ref(item) for item in relationships],
                "trace": [self._wire_ref(item) for item in trace],
            }
            selections.append(
                _Selection(
                    entry=entry,
                    critical=critical,
                    trace=trace,
                    relationships=relationships,
                    wire=wire,
                )
            )
        return tuple(selections)

    @staticmethod
    def _location(node: _CatalogNode) -> DiscoveryLocation:
        if node.line is None or node.code_sha256 is None:
            raise ValueError("selected node is not an exact source location")
        return DiscoveryLocation(
            file=node.path,
            line_start=node.line,
            line_end=node.line,
            code_sha256=node.code_sha256,
        )

    def _build_candidate(self, selection: _Selection) -> _BuiltCandidate:
        source_roots: set[str] = set()
        location_nodes = (selection.entry, selection.critical, *selection.trace)
        for node in location_nodes:
            source_roots.add(node.artifact_id)
            source_roots.add(self._catalog.covering_span(node))
        relationship_ids = {item.artifact_id for item in selection.relationships}
        for relationship in selection.relationships:
            source_roots.update(self._catalog.closure((relationship.artifact_id,)))
        source_roots.difference_update(relationship_ids)
        source_ids = self._catalog.closure(tuple(source_roots))
        source_ids = tuple(item for item in source_ids if item not in relationship_ids)
        candidate = DiscoveryCandidate(
            task_id=self._task.task_id,
            snapshot_id=self._task.snapshot_id,
            repo_url=self._task.repo_url,
            commit=self._task.commit,
            entry_point=self._location(selection.entry),
            critical_operation=self._location(selection.critical),
            trace=tuple(self._location(item) for item in selection.trace),
            relationship_evidence_refs=tuple(sorted(relationship_ids)),
            source_evidence_refs=source_ids,
        )
        selection_digest = _selection_digest_v1(self._task, selection.wire)
        return _BuiltCandidate(candidate=candidate, selection_digest=selection_digest)

    def _validate(self, built: Sequence[_BuiltCandidate]) -> ProducerDraftV1:
        self._stage = "VALIDATE"
        candidates = tuple(sorted(built, key=lambda item: item.candidate.candidate_id))
        count = len(candidates)
        if count > DEFAULT_PRODUCER_LIMITS.max_candidates:
            raise _Deferred("VALIDATE", "candidate_limit_exceeded", ("candidate batch exceeds 32",))
        if len(self._tool_runtime.artifacts) + count > _MAX_RUNTIME_ARTIFACTS:
            raise _Deferred(
                "VALIDATE",
                "artifact_capacity_exhausted",
                ("attempt cannot reserve one validation artifact per candidate",),
            )
        if self._budget.remaining(TOOL_CALLS) < count:
            raise _Deferred(
                "VALIDATE",
                "budget_exhausted",
                ("tool-call budget cannot cover the validation batch",),
            )
        receipts: list[ValidationReceiptV1] = []
        for item in candidates:
            candidate = item.candidate
            evidence_ids = tuple(
                sorted((*candidate.source_evidence_refs, *candidate.relationship_evidence_refs))
            )
            refs = tuple(self._catalog.ref(artifact_id) for artifact_id in evidence_ids)
            try:
                result = self._call_tool(
                    "VALIDATE",
                    "source_validate",
                    {"candidate": candidate.to_dict(), "evidence": refs},
                    catalog=False,
                )
            except BudgetExceeded:
                raise _Deferred(
                    "VALIDATE",
                    "budget_exhausted",
                    ("tool-call budget changed during validation",),
                ) from None
            if len(result.artifact_refs) != 1:
                raise _Deferred(
                    "VALIDATE", "validation_failed", ("validation artifact is missing",)
                )
            validation_ref = result.artifact_refs[0]
            try:
                artifact = self._resolve_bound_artifact(
                    result,
                    validation_ref,
                    expected_kind="discovery.source_validation",
                )
                payload = artifact.payload
                dependency_rows = _ordered(payload.get("dependencies"), maximum=64)
                upstream_rows = _ordered(
                    payload.get("upstream_artifacts"), maximum=64
                )
                actual_dependencies = {
                    (row.get("artifact_id"), row.get("artifact_sha256"))
                    for row in dependency_rows
                    if isinstance(row, Mapping)
                }
                actual_upstream = {
                    (row.get("artifact_id"), row.get("artifact_sha256"))
                    for row in upstream_rows
                    if isinstance(row, Mapping)
                }
                expected_dependencies = {
                    (ref.artifact_id, ref.artifact_sha256) for ref in refs
                }
                if (
                    artifact.kind != "discovery.source_validation"
                    or _thaw(payload.get("snapshot")) != self._catalog._snapshot()
                    or payload.get("candidate_id") != candidate.candidate_id
                    or payload.get("candidate_sha256") != candidate.candidate_sha256
                    or payload.get("location_count") != 2 + len(candidate.trace)
                    or payload.get("source_facts_valid") is not True
                    or payload.get("artifact_refs_closed") is not True
                    or payload.get("relationship_status") != "unverified"
                    or payload.get("semantic_status") != "unreviewed"
                    or actual_dependencies != expected_dependencies
                    or actual_upstream != expected_dependencies
                    or len(dependency_rows) != len(expected_dependencies)
                    or len(upstream_rows) != len(expected_dependencies)
                ):
                    raise ValueError("validation payload mismatch")
            except Exception:
                raise _Deferred(
                    "VALIDATE",
                    "validation_failed",
                    ("validation artifact did not bind the exact candidate",),
                ) from None
            dependencies = tuple(
                ProducerArtifactDigestRefV1(
                    artifact_id=ref.artifact_id,
                    artifact_sha256=ref.artifact_sha256,
                )
                for ref in refs
            )
            receipts.append(
                ValidationReceiptV1(
                    candidate_id=candidate.candidate_id,
                    candidate_sha256=candidate.candidate_sha256,
                    validation_artifact_id=validation_ref.artifact_id,
                    validation_artifact_sha256=validation_ref.artifact_sha256,
                    selection_digest=item.selection_digest,
                    dependencies=dependencies,
                )
            )
        return ProducerDraftV1(
            task=self._task,
            candidates=tuple(item.candidate for item in candidates),
            validation_receipts=tuple(receipts),
        )

    def _run_body(self) -> ProducerResultV1:
        phase: Literal["SCOUT", "ANALYZE"] = "SCOUT"
        last: Mapping[str, Any] = {"action": "start", "status": "ready"}
        while True:
            try:
                response = self._call_model(phase, last)
            except BudgetExceeded:
                raise _Deferred(
                    phase,
                    "budget_exhausted",
                    ("model-call budget is exhausted",),
                ) from None
            action = response.get("action") if isinstance(response, Mapping) else None
            if type(action) is not str:
                raise _Deferred(phase, "invalid_model_action", ("model action is missing",))
            if action == "defer":
                try:
                    value = _exact(response, frozenset({"action", "missing_information", "reason_code"}))
                    reason = value.get("reason_code")
                    missing = _ordered(
                        value.get("missing_information"), maximum=_MAX_MODEL_MISSING_ITEMS
                    )
                    if (
                        type(reason) is not str
                        or _REASON_RE.fullmatch(reason) is None
                        or any(
                            type(item) is not str
                            or not item
                            or len(item) > _MAX_MODEL_MISSING_CHARS
                            for item in missing
                        )
                    ):
                        raise ValueError("model defer is invalid")
                except ValueError:
                    raise _Deferred(
                        phase, "invalid_model_action", ("model defer action is invalid",)
                    ) from None
                raise _Deferred(
                    phase,
                    "model_deferred",
                    ("model did not have enough source evidence",),
                )
            if action == "advance":
                try:
                    _exact(response, frozenset({"action"}))
                except ValueError:
                    raise _Deferred(
                        phase, "invalid_model_action", ("advance action is invalid",)
                    ) from None
                if phase != "SCOUT":
                    raise _Deferred(
                        "ANALYZE",
                        "invalid_phase_transition",
                        ("ANALYZE cannot transition back to SCOUT",),
                    )
                phase = "ANALYZE"
                self._stage = "ANALYZE"
                last = {"action": "advance", "status": "success"}
                continue
            if action == "select":
                if phase != "ANALYZE":
                    raise _Deferred(
                        phase,
                        "invalid_phase_transition",
                        ("selection is allowed only after SCOUT",),
                    )
                try:
                    selections = self._parse_selections(response)
                    built = tuple(self._build_candidate(item) for item in selections)
                except Exception:
                    raise _Deferred(
                        "ANALYZE",
                        "invalid_selection",
                        ("opaque selection did not resolve to a closed candidate",),
                    ) from None
                candidate_ids = [item.candidate.candidate_id for item in built]
                if len(candidate_ids) != len(set(candidate_ids)):
                    raise _Deferred(
                        "ANALYZE",
                        "duplicate_candidate",
                        ("selection repeats an endpoint candidate",),
                    )
                return self._validate(built)
            if action not in {"inventory", "search", "read", "structure", "link"}:
                raise _Deferred(
                    phase,
                    "invalid_model_action",
                    ("model requested an action outside the D2 allowlist",),
                )
            try:
                last = self._tool_action(phase, action, response)
            except _Deferred:
                raise
            except BudgetExceeded:
                raise _Deferred(
                    phase,
                    "budget_exhausted",
                    ("tool-call budget is exhausted",),
                ) from None
            except Exception:
                raise _Deferred(
                    phase,
                    "invalid_model_action",
                    ("model tool action did not use valid opaque references",),
                ) from None

    def _verify_shared_budget(self) -> None:
        events = self._budget.events
        if events[: len(self._initial_events)] != self._initial_events:
            raise ValueError("shared budget prefix changed")
        suffix = events[len(self._initial_events) :]
        records: dict[int, tuple[str, str]] = {}
        for record in self._tool_runtime.records:
            records[record.budget_event_sequence] = (TOOL_CALLS, record.operation)
        for record in self._model_runtime.records:
            if record.budget_event_sequence in records:
                raise ValueError("shared budget sequence is ambiguous")
            records[record.budget_event_sequence] = (LLM_CALLS, record.operation)
        if len(records) != len(suffix):
            raise ValueError("shared budget has unowned attempt events")
        for event in suffix:
            expected = records.get(event.sequence)
            if (
                expected is None
                or event.amount != 1
                or (event.resource, event.operation) != expected
                or event.resource == REPAIR_ITERATIONS
            ):
                raise ValueError("shared budget event does not close")
        usage = self._budget.usage
        if (
            usage.llm_calls - self._initial_usage.llm_calls
            != len(self._model_runtime.records)
            or usage.tool_calls - self._initial_usage.tool_calls
            != len(self._tool_runtime.records)
            or usage.repair_iterations != self._initial_usage.repair_iterations
        ):
            raise ValueError("shared budget usage does not close")

    def _finalize_tool_transcript(self) -> AttemptToolTranscript:
        transcript = self._tool_runtime.finalize()
        if type(transcript) is not AttemptToolTranscript:
            raise ValueError("tool finalizer returned an invalid transcript type")
        registry = self._tool_runtime.registry
        expected = AttemptToolTranscript(
            task_id=self._task.task_id,
            attempt=_ATTEMPT,
            policy_scope=_POLICY_SCOPE,
            registry_sha256=_sha256(
                [
                    [name, registry[name].contract_id]
                    for name in sorted(registry)
                ]
            ),
            allowlist_sha256=_sha256(sorted(self._tool_runtime.allowlist)),
            records=tuple(self._expected_tool_records),
            artifacts=tuple(self._expected_tool_artifacts),
        )
        if (
            transcript != expected
            or self._tool_runtime.records != expected.records
            or self._tool_runtime.artifacts != expected.artifacts
            or self._tool_runtime.sealed_transcript is not transcript
            or self._tool_runtime.finalize() is not transcript
        ):
            raise ValueError("tool transcript did not close the controller action ledger")
        return transcript

    def _finalize_model_transcript(self) -> AttemptModelTranscript:
        transcript = self._model_runtime.finalize()
        if type(transcript) is not AttemptModelTranscript:
            raise ValueError("model finalizer returned an invalid transcript type")
        expected = AttemptModelTranscript(
            task_id=self._task.task_id,
            attempt=_ATTEMPT,
            policy_scope=_POLICY_SCOPE,
            backend_id=self._model_runtime.backend_id,
            model_id=self._model_runtime.model_id,
            records=tuple(self._expected_model_records),
        )
        if (
            transcript != expected
            or self._model_runtime.records != expected.records
            or self._model_runtime.sealed_transcript is not transcript
            or self._model_runtime.finalize() is not transcript
        ):
            raise ValueError("model transcript did not close the controller action ledger")
        return transcript

    def _finalize(self, provisional: ProducerResultV1) -> ProducerResultV1:
        self._sealed = True
        self._stage = "FINALIZE"
        failures = 0
        try:
            self._finalize_tool_transcript()
        except Exception:
            failures += 1
        try:
            self._finalize_model_transcript()
        except Exception:
            failures += 1
        try:
            self._verify_shared_budget()
        except Exception:
            failures += 1
        try:
            source_usage = self._toolbox.finalize_source_usage()
            source_readback = self._toolbox.usage_snapshot()
            if (
                type(source_usage) is not SourceUsageLedger
                or type(source_readback) is not SourceUsageLedger
                or source_usage != source_readback
                or source_usage.task_id != self._task.task_id
                or source_usage.snapshot_id != self._task.snapshot_id
                or source_usage.finalized is not True
                or source_usage.verification_succeeded is not True
            ):
                raise ValueError("source usage ledger did not close")
        except Exception:
            failures += 1
            try:
                closed = self._toolbox.abort_source_usage()
                if not isinstance(closed, SourceUsageLedger) or not closed.finalized:
                    failures += 1
            except Exception:
                failures += 1
        if failures:
            return self._deferred(
                "FINALIZE",
                "attempt_finalization_failed",
                "attempt transcripts or source usage did not close",
            )
        return provisional

    def _cleanup_after_cancellation(self) -> None:
        """Best-effort one-way sealing before propagating ``BaseException``."""

        self._sealed = True
        self._stage = "FINALIZE"
        for operation in (
            self._tool_runtime.finalize,
            self._model_runtime.finalize,
            self._verify_shared_budget,
            self._toolbox.abort_source_usage,
        ):
            try:
                operation()
            except BaseException:
                pass
        try:
            self._result = self._deferred(
                "FINALIZE",
                "attempt_cancelled",
                "attempt was cancelled after its capabilities were sealed",
            )
        except BaseException:
            self._result = None

    def _provisional_result(self) -> ProducerResultV1:
        """Convert ordinary attempt stops into a contract result.

        Keeping this exception translation outside ``run`` leaves no nested
        ``try`` line-event gap after ``_running`` is set.  Base exceptions still
        propagate to the single owner-level cleanup boundary in ``run``.
        """

        try:
            return self._run_body()
        except _Deferred as stopped:
            return self._deferred(
                stopped.stage, stopped.reason_code, *stopped.missing
            )
        except BudgetExceeded:
            return self._deferred(
                self._stage,
                "budget_exhausted",
                "attempt execution budget is exhausted",
            )
        except Exception:
            return self._deferred(
                self._stage,
                "attempt_error",
                "attempt failed before producing a closed draft",
            )

    def run(self) -> ProducerResultV1:
        """Run once, seal all capabilities, and return only a finalized result."""

        with self._lock:
            if self._result is not None:
                return self._result
            if self._running:
                raise RuntimeError("re-entrant producer runs are not allowed")
            try:
                self._running = True
                provisional = self._provisional_result()
                self._result = self._finalize(provisional)
                return self._result
            except BaseException:
                self._cleanup_after_cancellation()
                raise
            finally:
                self._running = False


__all__ = ["SourceDiscoveryAttemptController"]
