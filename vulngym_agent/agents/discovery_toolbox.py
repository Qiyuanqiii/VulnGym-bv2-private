"""Bounded source-only tools for one authenticated discovery snapshot.

The toolbox is a narrow composition layer over :class:`BoundSealedTree`.
It never receives or exposes the snapshot's host path, attestation key, Git
repository, history, or network/shell capabilities.  Every source path must
be an exact member of the authenticated manifest and all derived artifacts
are bound to the task, snapshot, and upstream artifact digests.

The structural and relationship tools deliberately make lexical/mechanical
claims only.  ``source_validate`` authenticates source facts and evidence
closure, but leaves semantic disposition to an independent reviewer.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import re
from threading import RLock
from types import MappingProxyType
from typing import Any, Final

from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryCandidate,
    DiscoveryContractError,
    DiscoveryLocation,
    DiscoveryTaskInputV1,
)
from vulngym_agent.benchmark.sealed_tree_access import (
    BoundSealedTree,
    SealedTreeAccessError,
    SealedTreeFile,
    SourceUsageLedger,
)
from vulngym_agent.tools import (
    ToolArtifact,
    ToolBlocked,
    ToolCallEnvelope,
    ToolDefinition,
    ToolHandlerOutput,
)


DISCOVERY_TOOL_NAMES: Final[tuple[str, ...]] = (
    "source_inventory",
    "source_search",
    "source_read",
    "source_structure",
    "source_link",
    "source_validate",
)

DISCOVERY_TOOL_CONTRACT_IDS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "source_inventory": "vulngym.source-discovery.inventory@1",
        "source_search": "vulngym.source-discovery.literal-search@1",
        "source_read": "vulngym.source-discovery.span-read@1",
        "source_structure": "vulngym.source-discovery.lexical-structure@1",
        "source_link": "vulngym.source-discovery.mechanical-link@1",
        "source_validate": "vulngym.source-discovery.source-validate@1",
    }
)

MAX_INVENTORY_BATCH_FILES: Final[int] = 256
MAX_SEARCH_PATHS: Final[int] = 64
MAX_SEARCH_QUERY_CHARS: Final[int] = 128
MAX_SEARCH_RESULTS: Final[int] = 256
MAX_SEARCH_CURSOR: Final[int] = 4_096
MAX_SEARCH_FILE_BYTES: Final[int] = 512 * 1024
MAX_SEARCH_TOTAL_BYTES: Final[int] = 4 * 1024 * 1024
MAX_SEARCH_EXCERPT_CHARS: Final[int] = 512
MAX_READ_SPANS: Final[int] = 16
MAX_READ_LINES_PER_SPAN: Final[int] = 256
MAX_READ_FILE_BYTES: Final[int] = 1024 * 1024
MAX_READ_TOTAL_BYTES: Final[int] = 8 * 1024 * 1024
MAX_READ_SPAN_BYTES: Final[int] = 64 * 1024
MAX_READ_ARTIFACT_BYTES: Final[int] = 512 * 1024
MAX_STRUCTURE_RESULTS: Final[int] = 256
MAX_STRUCTURE_CURSOR: Final[int] = 4_096
MAX_LINK_INPUTS: Final[int] = 16
MAX_LINK_RESULTS: Final[int] = 256
MAX_LINK_CURSOR: Final[int] = 4_096
MAX_VALIDATION_EVIDENCE: Final[int] = 64
MAX_VALIDATION_TOTAL_BYTES: Final[int] = 16 * 1024 * 1024
MAX_TOOL_ARTIFACT_CANONICAL_BYTES: Final[int] = 900 * 1024

_ARTIFACT_REF_TAG: Final[str] = "$artifact_ref"
_ARTIFACT_REF_FIELDS: Final[frozenset[str]] = frozenset(
    {"task_id", "attempt", "policy_scope", "artifact_id", "artifact_sha256"}
)
_CALL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9_$])([A-Za-z_$][A-Za-z0-9_$]*)\s*\("
)
_DECLARATION_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "function_declaration",
        re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\b"),
    ),
    (
        "class_declaration",
        re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b"),
    ),
    (
        "function_declaration",
        re.compile(r"\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\("),
    ),
    (
        "function_declaration",
        re.compile(
            r"^\s*(?:export\s+)?(?:const|let|var)\s+"
            r"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
            r"(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>"
        ),
    ),
    (
        "function_declaration",
        re.compile(
            r"^\s*func\s+(?:\([^)]*\)\s*)?"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*\("
        ),
    ),
)
_CALL_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "catch",
        "class",
        "def",
        "elif",
        "except",
        "for",
        "foreach",
        "function",
        "if",
        "match",
        "return",
        "sizeof",
        "switch",
        "while",
        "with",
    }
)


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        _thaw(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest_identifier(prefix: str, value: Any, *, length: int = 24) -> str:
    return prefix + hashlib.sha256(_canonical_json(value)).hexdigest()[:length].upper()


def _stable_artifact_id(
    envelope: ToolCallEnvelope, *, kind: str, payload: Mapping[str, Any]
) -> str:
    digest = hashlib.sha256(
        _canonical_json(
            {
                "attempt": envelope.attempt,
                "kind": kind,
                "payload": payload,
                "policy_scope": envelope.policy_scope,
                "task_id": envelope.task_id,
                "tool_call_id": envelope.tool_call_id,
            }
        )
    ).hexdigest()
    safe_kind = re.sub(r"[^A-Za-z0-9._-]", "-", kind)[:32]
    return f"ART-{safe_kind}-{digest[:24]}"


@dataclass(frozen=True, slots=True)
class _SourceSpan:
    path: str
    line_start: int
    line_end: int
    code_sha256: str
    text: str


@dataclass(frozen=True, slots=True)
class _LexicalNode:
    node_id: str
    path: str
    line: int
    column_start: int
    column_end: int
    code_sha256: str
    kind: str
    token: str
    source_artifact_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "column_end": self.column_end,
            "column_start": self.column_start,
            "code_sha256": self.code_sha256,
            "kind": self.kind,
            "line": self.line,
            "node_id": self.node_id,
            "path": self.path,
            "source_artifact_id": self.source_artifact_id,
            "token": self.token,
        }


@dataclass(frozen=True, slots=True)
class _MechanicalLink:
    link_id: str
    call_node_id: str
    declaration_node_id: str
    symbol: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_node_id": self.call_node_id,
            "declaration_node_id": self.declaration_node_id,
            "link_id": self.link_id,
            "relation": "literal_symbol_match",
            "semantic_status": "unverified",
            "symbol": self.symbol,
        }


@dataclass(frozen=True, slots=True)
class _ArtifactBinding:
    artifact: ToolArtifact
    tag: str
    value: object
    upstream_ids: tuple[str, ...] = ()


class DiscoveryToolbox:
    """Fixed source-only tool registry for one D0 discovery task."""

    __slots__ = (
        "_artifacts",
        "_file_by_path",
        "_files",
        "_lifecycle_lock",
        "_registry",
        "_tree",
        "task",
    )

    def __init__(self, task: DiscoveryTaskInputV1, tree: BoundSealedTree) -> None:
        if not isinstance(task, DiscoveryTaskInputV1):
            raise ValueError("task must be DiscoveryTaskInputV1")
        if not isinstance(tree, BoundSealedTree):
            raise ValueError("tree must be BoundSealedTree")
        tree_binding = (
            tree.task_id,
            tree.snapshot_id,
            tree.repo_url,
            tree.commit,
            tree.manifest_sha256,
            tree.content_root,
        )
        task_binding = (
            task.task_id,
            task.snapshot_id,
            task.repo_url,
            task.commit,
            task.snapshot_manifest_sha256,
            task.snapshot_content_root,
        )
        if tree_binding != task_binding:
            raise ValueError("tree must exactly match the discovery task snapshot")

        self.task = task
        self._tree = tree
        self._files: tuple[SealedTreeFile, ...] | None = None
        self._file_by_path: Mapping[str, SealedTreeFile] | None = None
        self._artifacts: dict[str, _ArtifactBinding] = {}
        self._lifecycle_lock = RLock()
        handlers = {
            "source_inventory": self._source_inventory,
            "source_search": self._source_search,
            "source_read": self._source_read,
            "source_structure": self._source_structure,
            "source_link": self._source_link,
            "source_validate": self._source_validate,
        }
        self._registry = MappingProxyType(
            {
                name: ToolDefinition(
                    name=name,
                    contract_id=DISCOVERY_TOOL_CONTRACT_IDS[name],
                    handler=self._serialized_handler(handlers[name]),
                )
                for name in DISCOVERY_TOOL_NAMES
            }
        )

    @property
    def registry(self) -> Mapping[str, ToolDefinition]:
        return self._registry

    @property
    def definitions(self) -> tuple[ToolDefinition, ...]:
        return tuple(self._registry.values())

    @property
    def tool_names(self) -> frozenset[str]:
        return frozenset(self._registry)

    def usage_snapshot(self) -> SourceUsageLedger:
        """Return the host-path-free source ledger to the trusted controller.

        This method is intentionally absent from ``registry`` and therefore
        cannot be invoked through the model-facing tool runtime.
        """

        with self._lifecycle_lock:
            return self._tree.usage_snapshot()

    def finalize_source_usage(self) -> SourceUsageLedger:
        """Reverify and close the source capability for the trusted controller.

        The controller must call this exactly once before releasing a draft.
        This lifecycle operation is not a model tool and exposes neither the
        sealed tree's path nor its attestation material.
        """

        with self._lifecycle_lock:
            return self._tree.finalize()

    def _serialized_handler(
        self,
        handler: Callable[[ToolCallEnvelope], ToolHandlerOutput],
    ) -> Callable[[ToolCallEnvelope], ToolHandlerOutput]:
        def invoke(envelope: ToolCallEnvelope) -> ToolHandlerOutput:
            with self._lifecycle_lock:
                return handler(envelope)

        return invoke

    def _snapshot_binding(self) -> dict[str, Any]:
        return {
            "commit": self.task.commit,
            "repo_url": self.task.repo_url,
            "snapshot_content_root": self.task.snapshot_content_root,
            "snapshot_id": self.task.snapshot_id,
            "snapshot_manifest_sha256": self.task.snapshot_manifest_sha256,
            "task_id": self.task.task_id,
        }

    def _inventory(self) -> tuple[SealedTreeFile, ...]:
        if self._files is None:
            try:
                files = self._tree.inventory()
            except SealedTreeAccessError as error:
                raise ToolBlocked(
                    "sealed_tree_access_failed", {"access_code": error.code}
                ) from error
            if (
                not isinstance(files, tuple)
                or any(not isinstance(item, SealedTreeFile) for item in files)
                or tuple(sorted(files, key=lambda item: item.path)) != files
                or len(files) != self._tree.file_count
            ):
                raise ToolBlocked("sealed_tree_contract_mismatch")
            by_path = {item.path: item for item in files}
            if len(by_path) != len(files):
                raise ToolBlocked("sealed_tree_contract_mismatch")
            self._files = files
            self._file_by_path = MappingProxyType(by_path)
        return self._files

    def _files_by_path(self) -> Mapping[str, SealedTreeFile]:
        self._inventory()
        assert self._file_by_path is not None
        return self._file_by_path

    def _read_bytes(self, path: str, *, maximum_bytes: int) -> bytes:
        try:
            return self._tree.read_bytes(path, maximum_bytes=maximum_bytes)
        except SealedTreeAccessError as error:
            raise ToolBlocked(
                "sealed_tree_access_failed", {"access_code": error.code}
            ) from error

    def _check_scope(self, envelope: ToolCallEnvelope, expected_tool: str) -> None:
        if envelope.task_id != self.task.task_id:
            raise ToolBlocked("task_scope_mismatch")
        if envelope.tool_name != expected_tool:
            raise ToolBlocked("tool_binding_mismatch")
        usage = self._tree.usage_snapshot()
        if usage.task_id != self.task.task_id or usage.snapshot_id != self.task.snapshot_id:
            raise ToolBlocked("sealed_tree_contract_mismatch")
        if usage.finalized:
            raise ToolBlocked(
                "sealed_tree_access_failed", {"access_code": "access_finalized"}
            )

    @staticmethod
    def _exact_arguments(
        envelope: ToolCallEnvelope, expected: frozenset[str]
    ) -> Mapping[str, Any]:
        actual = frozenset(envelope.arguments)
        if actual != expected:
            raise ToolBlocked(
                "invalid_arguments",
                {"actual": sorted(actual), "expected": sorted(expected)},
            )
        return envelope.arguments

    @staticmethod
    def _integer(
        arguments: Mapping[str, Any],
        key: str,
        *,
        minimum: int,
        maximum: int,
    ) -> int:
        value = arguments.get(key)
        if type(value) is not int or not minimum <= value <= maximum:
            raise ToolBlocked(
                "invalid_arguments",
                {"field": key, "maximum": maximum, "minimum": minimum},
            )
        return value

    @staticmethod
    def _ordered_array(
        value: Any, *, field: str, maximum: int, allow_empty: bool = False
    ) -> tuple[Any, ...]:
        if isinstance(value, (str, bytes, Mapping, set, frozenset)) or not isinstance(
            value, Sequence
        ):
            raise ToolBlocked("invalid_arguments", {"field": field})
        result = tuple(value)
        if len(result) > maximum or (not allow_empty and not result):
            raise ToolBlocked(
                "invalid_arguments", {"field": field, "maximum": maximum}
            )
        return result

    def _path(self, value: Any, *, field: str) -> str:
        if not isinstance(value, str) or value not in self._files_by_path():
            raise ToolBlocked("source_path_not_allowed", {"field": field})
        return value

    def _emit(
        self,
        envelope: ToolCallEnvelope,
        *,
        tag: str,
        kind: str,
        payload: Mapping[str, Any],
        value: object,
        upstream: Sequence[_ArtifactBinding] = (),
        output: Mapping[str, Any] | None = None,
    ) -> ToolHandlerOutput:
        upstream_bindings = tuple(upstream)
        upstream_payload = [
            {
                "artifact_id": binding.artifact.artifact_id,
                "artifact_sha256": binding.artifact.artifact_sha256,
            }
            for binding in sorted(
                upstream_bindings, key=lambda item: item.artifact.artifact_id
            )
        ]
        portable_payload = {
            "snapshot": self._snapshot_binding(),
            "upstream_artifacts": upstream_payload,
            **_thaw(payload),
        }
        if (
            len(_canonical_json(portable_payload))
            > MAX_TOOL_ARTIFACT_CANONICAL_BYTES
        ):
            raise ToolBlocked(
                "artifact_payload_too_large",
                {"maximum_bytes": MAX_TOOL_ARTIFACT_CANONICAL_BYTES},
            )
        artifact = ToolArtifact(
            task_id=envelope.task_id,
            attempt=envelope.attempt,
            policy_scope=envelope.policy_scope,
            tool_call_id=envelope.tool_call_id,
            artifact_id=_stable_artifact_id(
                envelope, kind=kind, payload=portable_payload
            ),
            kind=kind,
            payload=portable_payload,
        )
        upstream_ids = tuple(
            item["artifact_id"] for item in upstream_payload
        )
        self._artifacts[artifact.artifact_id] = _ArtifactBinding(
            artifact=artifact,
            tag=tag,
            value=value,
            upstream_ids=upstream_ids,
        )
        summary = {"artifact_id": artifact.artifact_id}
        if output is not None:
            summary.update(_thaw(output))
        return ToolHandlerOutput(output=summary, artifacts=(artifact,))

    def _require_artifact_value(
        self,
        envelope: ToolCallEnvelope,
        value: Any,
        *,
        field: str,
        tags: frozenset[str] | None = None,
    ) -> _ArtifactBinding:
        if not isinstance(value, Mapping) or frozenset(value) != {
            _ARTIFACT_REF_TAG
        }:
            raise ToolBlocked("invalid_artifact_reference", {"field": field})
        reference = value[_ARTIFACT_REF_TAG]
        if (
            not isinstance(reference, Mapping)
            or frozenset(reference) != _ARTIFACT_REF_FIELDS
        ):
            raise ToolBlocked("invalid_artifact_reference", {"field": field})
        if (
            reference.get("task_id") != envelope.task_id
            or reference.get("attempt") != envelope.attempt
            or reference.get("policy_scope") != envelope.policy_scope
        ):
            raise ToolBlocked("artifact_scope_mismatch", {"field": field})
        artifact_id = reference.get("artifact_id")
        if not isinstance(artifact_id, str):
            raise ToolBlocked("invalid_artifact_reference", {"field": field})
        binding = self._artifacts.get(artifact_id)
        if binding is None or (tags is not None and binding.tag not in tags):
            raise ToolBlocked("artifact_kind_mismatch", {"field": field})
        if reference.get("artifact_sha256") != binding.artifact.artifact_sha256:
            raise ToolBlocked("artifact_digest_mismatch", {"field": field})
        return binding

    def _source_inventory(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "source_inventory")
        arguments = self._exact_arguments(envelope, frozenset({"cursor", "limit"}))
        files = self._inventory()
        cursor = self._integer(
            arguments, "cursor", minimum=0, maximum=len(files)
        )
        limit = self._integer(
            arguments,
            "limit",
            minimum=1,
            maximum=MAX_INVENTORY_BATCH_FILES,
        )
        selected = files[cursor : cursor + limit]
        next_cursor = cursor + len(selected)
        complete = next_cursor >= len(files)
        records = [
            {
                "blob_oid": item.blob_oid,
                "git_mode": item.git_mode,
                "path": item.path,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in selected
        ]
        payload = {
            "complete": complete,
            "cursor": cursor,
            "files": records,
            "limit": limit,
            "next_cursor": None if complete else next_cursor,
            "total_file_count": len(files),
            "total_source_bytes": self._tree.total_bytes,
        }
        return self._emit(
            envelope,
            tag="inventory",
            kind="discovery.source_inventory",
            payload=payload,
            value=selected,
            output={
                "complete": complete,
                "file_count": len(selected),
                "next_cursor": None if complete else next_cursor,
                "total_file_count": len(files),
            },
        )

    def _search_paths(self, value: Any) -> tuple[str, ...]:
        raw = self._ordered_array(value, field="paths", maximum=MAX_SEARCH_PATHS)
        paths = tuple(self._path(item, field="paths") for item in raw)
        if len(set(paths)) != len(paths):
            raise ToolBlocked("invalid_arguments", {"field": "paths"})
        return tuple(sorted(paths))

    def _source_search(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "source_search")
        arguments = self._exact_arguments(
            envelope, frozenset({"cursor", "limit", "paths", "query"})
        )
        query = arguments.get("query")
        if (
            not isinstance(query, str)
            or not query
            or len(query) > MAX_SEARCH_QUERY_CHARS
            or "\n" in query
            or "\r" in query
            or any(ord(character) < 32 or ord(character) == 127 for character in query)
        ):
            raise ToolBlocked("invalid_literal_query")
        paths = self._search_paths(arguments.get("paths"))
        cursor = self._integer(
            arguments, "cursor", minimum=0, maximum=MAX_SEARCH_CURSOR
        )
        limit = self._integer(
            arguments, "limit", minimum=1, maximum=MAX_SEARCH_RESULTS
        )

        file_by_path = self._files_by_path()
        eligible = [path for path in paths if file_by_path[path].size <= MAX_SEARCH_FILE_BYTES]
        skipped = [
            {"path": path, "reason": "file_too_large"}
            for path in paths
            if file_by_path[path].size > MAX_SEARCH_FILE_BYTES
        ]
        if sum(file_by_path[path].size for path in eligible) > MAX_SEARCH_TOTAL_BYTES:
            raise ToolBlocked(
                "search_batch_too_large",
                {
                    "maximum_bytes": MAX_SEARCH_TOTAL_BYTES,
                    "path_count": len(eligible),
                },
            )

        wanted_end = cursor + limit
        encountered = 0
        matches: list[dict[str, Any]] = []
        for path in eligible:
            raw = self._read_bytes(path, maximum_bytes=MAX_SEARCH_FILE_BYTES)
            if b"\0" in raw:
                skipped.append({"path": path, "reason": "not_utf8_text"})
                continue
            try:
                text = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                skipped.append({"path": path, "reason": "not_utf8_text"})
                continue
            for line_number, line_with_ending in enumerate(
                text.splitlines(keepends=True), start=1
            ):
                line = line_with_ending.removesuffix("\n").removesuffix("\r")
                line_code_sha256 = hashlib.sha256(
                    line_with_ending.encode("utf-8")
                ).hexdigest()
                offset = 0
                while True:
                    index = line.find(query, offset)
                    if index < 0:
                        break
                    if encountered > MAX_SEARCH_CURSOR:
                        raise ToolBlocked(
                            "search_result_limit_exceeded",
                            {"maximum": MAX_SEARCH_CURSOR + 1},
                        )
                    if cursor <= encountered < wanted_end:
                        left = max(0, index - MAX_SEARCH_EXCERPT_CHARS // 2)
                        right = min(
                            len(line),
                            left + MAX_SEARCH_EXCERPT_CHARS,
                        )
                        excerpt = line[left:right]
                        matches.append(
                            {
                                "column_end": index + len(query),
                                "column_start": index + 1,
                                "excerpt": excerpt,
                                "excerpt_start_column": left + 1,
                                "line": line_number,
                                "line_code_sha256": line_code_sha256,
                                "match_sha256": hashlib.sha256(
                                    query.encode("utf-8")
                                ).hexdigest(),
                                "path": path,
                            }
                        )
                    encountered += 1
                    offset = index + max(1, len(query))

        skipped.sort(key=lambda item: item["path"])
        next_cursor = cursor + len(matches)
        has_more = encountered > next_cursor
        complete = not has_more
        payload = {
            "complete": complete,
            "cursor": cursor,
            "case_sensitive": True,
            "literal_query": query,
            "matches": matches,
            "next_cursor": None if complete else next_cursor,
            "overlap_policy": "non_overlapping",
            "paths": list(paths),
            "skipped": skipped,
        }
        return self._emit(
            envelope,
            tag="search",
            kind="discovery.source_search",
            payload=payload,
            value=tuple(matches),
            output={
                "complete": complete,
                "match_count": len(matches),
                "next_cursor": None if complete else next_cursor,
                "skipped_count": len(skipped),
            },
        )

    def _parse_spans(self, value: Any) -> tuple[tuple[str, int, int], ...]:
        raw_spans = self._ordered_array(
            value, field="spans", maximum=MAX_READ_SPANS
        )
        spans: list[tuple[str, int, int]] = []
        for index, item in enumerate(raw_spans):
            if not isinstance(item, Mapping) or frozenset(item) != {
                "line_end",
                "line_start",
                "path",
            }:
                raise ToolBlocked("invalid_arguments", {"field": f"spans[{index}]"})
            path = self._path(item.get("path"), field=f"spans[{index}].path")
            line_start = item.get("line_start")
            line_end = item.get("line_end")
            if (
                type(line_start) is not int
                or type(line_end) is not int
                or not 1 <= line_start <= line_end
                or line_end - line_start + 1 > MAX_READ_LINES_PER_SPAN
            ):
                raise ToolBlocked(
                    "invalid_source_span", {"field": f"spans[{index}]"}
                )
            spans.append((path, line_start, line_end))
        if len(set(spans)) != len(spans):
            raise ToolBlocked("invalid_arguments", {"field": "spans"})
        return tuple(sorted(spans))

    def _load_text_files(
        self, paths: Sequence[str], *, total_limit: int
    ) -> dict[str, tuple[bytes, tuple[bytes, ...]]]:
        file_by_path = self._files_by_path()
        unique_paths = tuple(sorted(set(paths)))
        if any(file_by_path[path].size > MAX_READ_FILE_BYTES for path in unique_paths):
            raise ToolBlocked(
                "source_file_too_large", {"maximum_bytes": MAX_READ_FILE_BYTES}
            )
        if sum(file_by_path[path].size for path in unique_paths) > total_limit:
            raise ToolBlocked(
                "source_batch_too_large", {"maximum_bytes": total_limit}
            )
        loaded: dict[str, tuple[bytes, tuple[bytes, ...]]] = {}
        for path in unique_paths:
            raw = self._read_bytes(path, maximum_bytes=MAX_READ_FILE_BYTES)
            if b"\0" in raw:
                raise ToolBlocked("source_not_utf8_text", {"path": path})
            try:
                raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise ToolBlocked("source_not_utf8_text", {"path": path}) from None
            loaded[path] = (raw, tuple(raw.splitlines(keepends=True)))
        return loaded

    def _source_read(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "source_read")
        arguments = self._exact_arguments(envelope, frozenset({"spans"}))
        requested = self._parse_spans(arguments.get("spans"))
        loaded = self._load_text_files(
            [item[0] for item in requested], total_limit=MAX_READ_TOTAL_BYTES
        )
        file_by_path = self._files_by_path()
        spans: list[_SourceSpan] = []
        total_span_bytes = 0
        for path, line_start, line_end in requested:
            lines = loaded[path][1]
            if line_end > len(lines):
                raise ToolBlocked(
                    "source_span_out_of_range",
                    {"line_count": len(lines), "path": path},
                )
            selected = b"".join(lines[line_start - 1 : line_end])
            if len(selected) > MAX_READ_SPAN_BYTES:
                raise ToolBlocked(
                    "source_span_too_large",
                    {"maximum_bytes": MAX_READ_SPAN_BYTES, "path": path},
                )
            total_span_bytes += len(selected)
            if total_span_bytes > MAX_READ_ARTIFACT_BYTES:
                raise ToolBlocked(
                    "source_span_batch_too_large",
                    {"maximum_bytes": MAX_READ_ARTIFACT_BYTES},
                )
            spans.append(
                _SourceSpan(
                    path=path,
                    line_start=line_start,
                    line_end=line_end,
                    code_sha256=hashlib.sha256(selected).hexdigest(),
                    text=selected.decode("utf-8"),
                )
            )
        records = [
            {
                "code_sha256": span.code_sha256,
                "file_sha256": file_by_path[span.path].sha256,
                "line_end": span.line_end,
                "line_start": span.line_start,
                "path": span.path,
                "text": span.text,
            }
            for span in spans
        ]
        return self._emit(
            envelope,
            tag="spans",
            kind="discovery.source_spans",
            payload={"spans": records},
            value=tuple(spans),
            output={"span_count": len(spans)},
        )

    def _lexical_nodes(
        self, binding: _ArtifactBinding
    ) -> tuple[_LexicalNode, ...]:
        if binding.tag != "spans" or not isinstance(binding.value, tuple):
            raise ToolBlocked("artifact_kind_mismatch", {"field": "source"})
        nodes: dict[str, _LexicalNode] = {}
        for span in binding.value:
            if not isinstance(span, _SourceSpan):
                raise ToolBlocked("artifact_capability_invalid")
            for offset, line_with_ending in enumerate(
                span.text.splitlines(keepends=True), start=0
            ):
                line = line_with_ending.removesuffix("\n").removesuffix("\r")
                line_number = span.line_start + offset
                code_sha256 = hashlib.sha256(
                    line_with_ending.encode("utf-8")
                ).hexdigest()
                declaration_ranges: set[tuple[int, int, str]] = set()
                for kind, pattern in _DECLARATION_PATTERNS:
                    match = pattern.search(line)
                    if match is None:
                        continue
                    start, end = match.span(1)
                    token = match.group(1)
                    declaration_ranges.add((start, end, token))
                    node = self._make_node(
                        binding,
                        path=span.path,
                        line=line_number,
                        column_start=start + 1,
                        column_end=end,
                        code_sha256=code_sha256,
                        kind=kind,
                        token=token,
                    )
                    nodes[node.node_id] = node
                    if len(nodes) > MAX_STRUCTURE_CURSOR + 1:
                        raise ToolBlocked(
                            "structure_result_limit_exceeded",
                            {"maximum": MAX_STRUCTURE_CURSOR + 1},
                        )
                for match in _CALL_RE.finditer(line):
                    token = match.group(1)
                    start, end = match.span(1)
                    if token in _CALL_KEYWORDS or (start, end, token) in declaration_ranges:
                        continue
                    node = self._make_node(
                        binding,
                        path=span.path,
                        line=line_number,
                        column_start=start + 1,
                        column_end=end,
                        code_sha256=code_sha256,
                        kind="call",
                        token=token,
                    )
                    nodes[node.node_id] = node
                    if len(nodes) > MAX_STRUCTURE_CURSOR + 1:
                        raise ToolBlocked(
                            "structure_result_limit_exceeded",
                            {"maximum": MAX_STRUCTURE_CURSOR + 1},
                        )
        return tuple(
            sorted(
                nodes.values(),
                key=lambda item: (
                    item.path,
                    item.line,
                    item.column_start,
                    item.kind,
                    item.token,
                    item.node_id,
                ),
            )
        )

    def _make_node(
        self,
        source: _ArtifactBinding,
        *,
        path: str,
        line: int,
        column_start: int,
        column_end: int,
        code_sha256: str,
        kind: str,
        token: str,
    ) -> _LexicalNode:
        identity = {
            "column_end": column_end,
            "column_start": column_start,
            "code_sha256": code_sha256,
            "kind": kind,
            "line": line,
            "path": path,
            "snapshot_id": self.task.snapshot_id,
            "source_artifact_sha256": source.artifact.artifact_sha256,
            "token": token,
        }
        return _LexicalNode(
            node_id=_digest_identifier("LEX-", identity),
            path=path,
            line=line,
            column_start=column_start,
            column_end=column_end,
            code_sha256=code_sha256,
            kind=kind,
            token=token,
            source_artifact_id=source.artifact.artifact_id,
        )

    def _source_structure(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "source_structure")
        arguments = self._exact_arguments(
            envelope, frozenset({"cursor", "limit", "source"})
        )
        source = self._require_artifact_value(
            envelope,
            arguments.get("source"),
            field="source",
            tags=frozenset({"spans"}),
        )
        cursor = self._integer(
            arguments, "cursor", minimum=0, maximum=MAX_STRUCTURE_CURSOR
        )
        limit = self._integer(
            arguments, "limit", minimum=1, maximum=MAX_STRUCTURE_RESULTS
        )
        nodes = self._lexical_nodes(source)
        if len(nodes) > MAX_STRUCTURE_CURSOR + 1:
            raise ToolBlocked(
                "structure_result_limit_exceeded",
                {"maximum": MAX_STRUCTURE_CURSOR + 1},
            )
        selected = nodes[cursor : cursor + limit]
        next_cursor = cursor + len(selected)
        complete = next_cursor >= len(nodes)
        payload = {
            "complete": complete,
            "cursor": cursor,
            "lexical_nodes": [item.to_dict() for item in selected],
            "next_cursor": None if complete else next_cursor,
            "semantic_status": "unverified",
        }
        return self._emit(
            envelope,
            tag="structure",
            kind="discovery.source_structure",
            payload=payload,
            value=selected,
            upstream=(source,),
            output={
                "complete": complete,
                "next_cursor": None if complete else next_cursor,
                "node_count": len(selected),
                "semantic_status": "unverified",
            },
        )

    def _structure_inputs(
        self, envelope: ToolCallEnvelope, value: Any
    ) -> tuple[_ArtifactBinding, ...]:
        raw = self._ordered_array(
            value, field="structures", maximum=MAX_LINK_INPUTS
        )
        bindings = tuple(
            self._require_artifact_value(
                envelope,
                item,
                field=f"structures[{index}]",
                tags=frozenset({"structure"}),
            )
            for index, item in enumerate(raw)
        )
        ids = [item.artifact.artifact_id for item in bindings]
        if len(ids) != len(set(ids)):
            raise ToolBlocked("invalid_arguments", {"field": "structures"})
        return tuple(sorted(bindings, key=lambda item: item.artifact.artifact_id))

    def _mechanical_links(
        self, structures: Sequence[_ArtifactBinding]
    ) -> tuple[_MechanicalLink, ...]:
        nodes: dict[str, _LexicalNode] = {}
        for binding in structures:
            if binding.tag != "structure" or not isinstance(binding.value, tuple):
                raise ToolBlocked("artifact_capability_invalid")
            for node in binding.value:
                if not isinstance(node, _LexicalNode):
                    raise ToolBlocked("artifact_capability_invalid")
                nodes[node.node_id] = node
        declarations: dict[str, list[_LexicalNode]] = {}
        calls: list[_LexicalNode] = []
        for node in nodes.values():
            if node.kind.endswith("_declaration"):
                declarations.setdefault(node.token, []).append(node)
            elif node.kind == "call":
                calls.append(node)
        links: dict[str, _MechanicalLink] = {}
        for call in calls:
            for declaration in declarations.get(call.token, ()):
                identity = {
                    "call_node_id": call.node_id,
                    "declaration_node_id": declaration.node_id,
                    "relation": "literal_symbol_match",
                    "snapshot_id": self.task.snapshot_id,
                    "symbol": call.token,
                }
                link = _MechanicalLink(
                    link_id=_digest_identifier("REL-", identity),
                    call_node_id=call.node_id,
                    declaration_node_id=declaration.node_id,
                    symbol=call.token,
                )
                links[link.link_id] = link
                if len(links) > MAX_LINK_CURSOR + 1:
                    raise ToolBlocked(
                        "relationship_result_limit_exceeded",
                        {"maximum": MAX_LINK_CURSOR + 1},
                    )
        return tuple(
            sorted(
                links.values(),
                key=lambda item: (
                    item.symbol,
                    item.call_node_id,
                    item.declaration_node_id,
                ),
            )
        )

    def _source_link(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "source_link")
        arguments = self._exact_arguments(
            envelope, frozenset({"cursor", "limit", "structures"})
        )
        structures = self._structure_inputs(envelope, arguments.get("structures"))
        cursor = self._integer(
            arguments, "cursor", minimum=0, maximum=MAX_LINK_CURSOR
        )
        limit = self._integer(
            arguments, "limit", minimum=1, maximum=MAX_LINK_RESULTS
        )
        links = self._mechanical_links(structures)
        if len(links) > MAX_LINK_CURSOR + 1:
            raise ToolBlocked(
                "relationship_result_limit_exceeded",
                {"maximum": MAX_LINK_CURSOR + 1},
            )
        selected = links[cursor : cursor + limit]
        next_cursor = cursor + len(selected)
        complete = next_cursor >= len(links)
        payload = {
            "complete": complete,
            "cursor": cursor,
            "mechanical_relationships": [item.to_dict() for item in selected],
            "next_cursor": None if complete else next_cursor,
            "semantic_status": "unverified",
        }
        return self._emit(
            envelope,
            tag="relationships",
            kind="discovery.source_relationships",
            payload=payload,
            value=selected,
            upstream=structures,
            output={
                "complete": complete,
                "next_cursor": None if complete else next_cursor,
                "relationship_count": len(selected),
                "semantic_status": "unverified",
            },
        )

    def _validation_evidence(
        self, envelope: ToolCallEnvelope, value: Any
    ) -> tuple[_ArtifactBinding, ...]:
        raw = self._ordered_array(
            value,
            field="evidence",
            maximum=MAX_VALIDATION_EVIDENCE,
        )
        bindings = tuple(
            self._require_artifact_value(
                envelope, item, field=f"evidence[{index}]"
            )
            for index, item in enumerate(raw)
        )
        ids = [item.artifact.artifact_id for item in bindings]
        if len(ids) != len(set(ids)):
            raise ToolBlocked("invalid_arguments", {"field": "evidence"})
        return tuple(sorted(bindings, key=lambda item: item.artifact.artifact_id))

    @staticmethod
    def _span_covers(span: _SourceSpan, location: DiscoveryLocation) -> bool:
        return (
            span.path == location.file
            and span.line_start <= location.line_start
            and span.line_end >= location.line_end
        )

    def _validate_location_bytes(
        self,
        location: DiscoveryLocation,
        loaded: Mapping[str, tuple[bytes, tuple[bytes, ...]]],
    ) -> None:
        lines = loaded[location.file][1]
        if location.line_end > len(lines):
            raise ToolBlocked("candidate_location_out_of_range")
        selected = b"".join(lines[location.line_start - 1 : location.line_end])
        if hashlib.sha256(selected).hexdigest() != location.code_sha256:
            raise ToolBlocked("candidate_source_digest_mismatch")

    def _source_validate(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "source_validate")
        arguments = self._exact_arguments(
            envelope, frozenset({"candidate", "evidence"})
        )
        try:
            # AttemptToolRuntime recursively freezes JSON arrays to tuples;
            # reconstruct the detached wire value before applying the D0
            # contract, whose JSON decoder correctly requires arrays.
            candidate = DiscoveryCandidate.from_dict(
                _thaw(arguments.get("candidate"))
            )
            candidate.assert_task(self.task)
        except DiscoveryContractError as error:
            raise ToolBlocked(
                "invalid_discovery_candidate", {"contract_code": error.code}
            ) from error
        evidence = self._validation_evidence(envelope, arguments.get("evidence"))
        evidence_by_id = {item.artifact.artifact_id: item for item in evidence}
        declared_source = set(candidate.source_evidence_refs)
        declared_relationship = set(candidate.relationship_evidence_refs)
        if declared_source & declared_relationship:
            raise ToolBlocked("candidate_evidence_partition_invalid")
        if set(evidence_by_id) != declared_source | declared_relationship:
            raise ToolBlocked("candidate_evidence_closure_mismatch")
        if any(
            evidence_by_id[artifact_id].tag != "relationships"
            for artifact_id in declared_relationship
        ):
            raise ToolBlocked("candidate_relationship_evidence_invalid")
        if any(
            evidence_by_id[artifact_id].tag == "relationships"
            for artifact_id in declared_source
        ):
            raise ToolBlocked("candidate_source_evidence_invalid")
        if any(
            evidence_by_id[artifact_id].tag
            not in {"inventory", "search", "spans", "structure"}
            for artifact_id in declared_source
        ):
            raise ToolBlocked("candidate_source_evidence_invalid")
        if any(
            not isinstance(evidence_by_id[artifact_id].value, tuple)
            or not evidence_by_id[artifact_id].value
            for artifact_id in declared_relationship
        ):
            raise ToolBlocked("candidate_relationship_evidence_invalid")

        for binding in evidence:
            if any(upstream_id not in evidence_by_id for upstream_id in binding.upstream_ids):
                raise ToolBlocked("candidate_evidence_closure_mismatch")

        spans = tuple(
            span
            for binding in evidence
            if binding.tag == "spans" and isinstance(binding.value, tuple)
            for span in binding.value
            if isinstance(span, _SourceSpan)
        )
        locations = (
            candidate.entry_point,
            candidate.critical_operation,
            *candidate.trace,
        )
        if any(
            not any(self._span_covers(span, location) for span in spans)
            for location in locations
        ):
            raise ToolBlocked("candidate_location_evidence_missing")
        file_by_path = self._files_by_path()
        if any(location.file not in file_by_path for location in locations):
            raise ToolBlocked("candidate_source_path_not_found")

        loaded = self._load_text_files(
            [location.file for location in locations],
            total_limit=MAX_VALIDATION_TOTAL_BYTES,
        )
        for location in locations:
            self._validate_location_bytes(location, loaded)

        dependencies = [
            {
                "artifact_id": binding.artifact.artifact_id,
                "artifact_sha256": binding.artifact.artifact_sha256,
            }
            for binding in evidence
        ]
        payload = {
            "artifact_refs_closed": True,
            "candidate_id": candidate.candidate_id,
            "candidate_sha256": candidate.candidate_sha256,
            "dependencies": dependencies,
            "location_count": len(locations),
            "relationship_status": "unverified",
            "semantic_status": "unreviewed",
            "source_facts_valid": True,
        }
        return self._emit(
            envelope,
            tag="validation",
            kind="discovery.source_validation",
            payload=payload,
            value=candidate,
            upstream=evidence,
            output={
                "artifact_refs_closed": True,
                "candidate_id": candidate.candidate_id,
                "candidate_sha256": candidate.candidate_sha256,
                "relationship_status": "unverified",
                "semantic_status": "unreviewed",
                "source_facts_valid": True,
            },
        )


__all__ = [
    "DISCOVERY_TOOL_CONTRACT_IDS",
    "DISCOVERY_TOOL_NAMES",
    "DiscoveryToolbox",
    "MAX_INVENTORY_BATCH_FILES",
    "MAX_LINK_INPUTS",
    "MAX_LINK_RESULTS",
    "MAX_READ_SPANS",
    "MAX_SEARCH_PATHS",
    "MAX_SEARCH_RESULTS",
    "MAX_STRUCTURE_RESULTS",
    "MAX_TOOL_ARTIFACT_CANONICAL_BYTES",
    "MAX_VALIDATION_EVIDENCE",
]
