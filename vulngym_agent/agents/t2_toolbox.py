"""Trusted, offline-only tools used by the real T2 producer.

The toolbox is intentionally a composition layer rather than a general tool
API.  Filesystem roots are trusted constructor configuration, while every
runtime call has a small exact JSON contract.  Source and patch objects passed
between tools are capabilities issued by :class:`AttemptToolRuntime`; callers
cannot submit a ``LoadedEvidenceFile`` or ``TextFileDiff`` of their own.

No handler checks out a worktree, enumerates a repository, fetches data, opens
the network, runs target code, or exposes an arbitrary path/command primitive.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any

from vulngym_agent.adapters import SchemaAdapter
from vulngym_agent.analyzers import PatchAnalysisError, analyze_patch
from vulngym_agent.evidence import (
    LoadedEvidenceFile,
    PackageLoadResult,
    extract_advisory_facts,
    load_evidence_package,
)
from vulngym_agent.orchestrator.contracts import RunTask
from vulngym_agent.orchestrator.repair_plan import (
    REPAIR_TOOL_POLICY_VERSION,
    SAFE_REPAIR_TOOL_REGISTRY,
)
from vulngym_agent.resolvers import CriticalOperationResolver
from vulngym_agent.source import EntryPointSearcher
from vulngym_agent.tools import (
    ToolArtifact,
    ToolBlocked,
    ToolCallEnvelope,
    ToolDefinition,
    ToolHandlerOutput,
)
from vulngym_agent.tools.git import (
    GitFactError,
    GitHistoryIncomplete,
    GitRepository,
    InvalidCommitSha,
    InvalidRepositoryPath,
    TextFileDiff,
    validate_commit_sha,
    validate_repo_relative_path,
)

from .t2_inputs import T2TaskInput, parse_t2_task_input


# Keep single strings below ToolArtifact's per-string bound and leave ample
# room for canonical JSON metadata.  These are producer bounds, deliberately
# narrower than the lower-level readers' hard limits.
MAX_LOCAL_FILE_BYTES = 256 * 1024
MAX_LOCAL_PACKAGE_BYTES = 2 * 1024 * 1024
MAX_GIT_BLOB_BYTES = 256 * 1024
MAX_GIT_DIFF_BYTES = 96 * 1024
MAX_ROUTE_BYTES = 1024 * 1024
MAX_CRITICAL_CANDIDATES = 128

_ARTIFACT_REF_TAG = "$artifact_ref"
_ARTIFACT_REF_FIELDS = frozenset(
    {"task_id", "attempt", "policy_scope", "artifact_id", "artifact_sha256"}
)
_SYMBOL_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_.$:/-]{0,127}$")

LOCAL_T2_TOOL_NAMES = (
    "read_local_advisory",
    "extract_advisory_fields",
    "read_local_patch",
    "resolve_local_repo",
    "git_parents",
    "git_show",
    "git_diff",
    "version_ancestry",
    "dataflow_candidate_search",
    "route_recognition",
    "validate_schema",
)

# These identities are release/build-manifest data.  Bump the relevant value
# whenever that tool's accepted inputs, emitted outputs, or security semantics
# change.  AttemptToolRuntime intentionally does not derive identity from the
# bound Python method, because callable introspection is neither replay-stable
# nor proof against malicious code already executing in this process.
LOCAL_T2_TOOL_CONTRACT_IDS = MappingProxyType(
    {
        "read_local_advisory": "vulngym.local-t2.read_local_advisory@1",
        "extract_advisory_fields": "vulngym.local-t2.extract_advisory_fields@1",
        "read_local_patch": "vulngym.local-t2.read_local_patch@1",
        "resolve_local_repo": "vulngym.local-t2.resolve_local_repo@1",
        "git_parents": "vulngym.local-t2.git_parents@1",
        "git_show": "vulngym.local-t2.git_show@1",
        "git_diff": "vulngym.local-t2.git_diff@1",
        "version_ancestry": "vulngym.local-t2.version_ancestry@1",
        "dataflow_candidate_search": (
            "vulngym.local-t2.dataflow_candidate_search@2"
        ),
        "route_recognition": "vulngym.local-t2.route_recognition@1",
        "validate_schema": "vulngym.local-t2.validate_schema@1",
    }
)


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _thaw(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _stable_artifact_id(
    envelope: ToolCallEnvelope, *, kind: str, payload: Mapping[str, Any]
) -> str:
    digest = hashlib.sha256(
        _canonical_json(
            {
                "task_id": envelope.task_id,
                "attempt": envelope.attempt,
                "policy_scope": envelope.policy_scope,
                "tool_call_id": envelope.tool_call_id,
                "kind": kind,
                "payload": payload,
            }
        ).encode("utf-8")
    ).hexdigest()
    safe_kind = re.sub(r"[^A-Za-z0-9._-]", "-", kind)[:32]
    return f"ART-{safe_kind}-{digest[:24]}"


@dataclass(frozen=True, slots=True)
class _ArtifactBinding:
    artifact: ToolArtifact
    tag: str
    value: object
    repository: GitRepository | None = None


@dataclass(frozen=True, slots=True)
class _TrustedDiff:
    repository: GitRepository
    diff: TextFileDiff


class LocalT2Toolbox:
    """Build the fixed trusted registry for one correlated T2 task.

    ``package_root`` and ``repo_path`` are trusted process configuration and
    are never included in an output or artifact.  ``task_input`` must be the
    exact parsed representation of ``task.inputs`` so a caller cannot mix
    correlation anchors with a different package or repository URL.
    """

    __slots__ = (
        "_artifacts",
        "_package",
        "_package_loaded",
        "_package_root",
        "_registry",
        "_repository",
        "_repo_path",
        "_schema_adapter",
        "_whole_line_entry_snippets",
        "task",
        "task_input",
    )

    def __init__(
        self,
        task: RunTask,
        task_input: T2TaskInput,
        package_root: str | Path,
        repo_path: str | Path,
        *, whole_line_entry_snippets: bool = False,
    ) -> None:
        if type(whole_line_entry_snippets) is not bool:
            raise ValueError("whole_line_entry_snippets must be boolean")
        self._whole_line_entry_snippets = whole_line_entry_snippets
        if not isinstance(task, RunTask):
            raise ValueError("task must be a RunTask")
        if parse_t2_task_input(task) != task_input:
            raise ValueError("task_input must exactly match task.inputs")

        self.task = task
        self.task_input = task_input
        self._package_root = self._configured_directory(
            package_root, name="package_root"
        )
        self._repo_path = self._configured_directory(repo_path, name="repo_path")
        self._package_loaded = False
        self._package: PackageLoadResult | None = None
        self._repository: GitRepository | None = None
        self._artifacts: dict[str, _ArtifactBinding] = {}
        self._schema_adapter = SchemaAdapter()

        handlers = {
            "read_local_advisory": self._read_local_advisory,
            "extract_advisory_fields": self._extract_advisory_fields,
            "read_local_patch": self._read_local_patch,
            "resolve_local_repo": self._resolve_local_repo,
            "git_parents": self._git_parents,
            "git_show": self._git_show,
            "git_diff": self._git_diff,
            "version_ancestry": self._version_ancestry,
            "dataflow_candidate_search": self._dataflow_candidate_search,
            "route_recognition": self._route_recognition,
            "validate_schema": self._validate_schema,
        }
        safe = SAFE_REPAIR_TOOL_REGISTRY[REPAIR_TOOL_POLICY_VERSION]
        if set(handlers) - safe:
            raise RuntimeError("Local T2 registry contains a non-policy tool")
        self._registry = MappingProxyType(
            {
                name: ToolDefinition(
                    name=name,
                    contract_id=LOCAL_T2_TOOL_CONTRACT_IDS[name],
                    handler=handlers[name],
                )
                for name in LOCAL_T2_TOOL_NAMES
            }
        )

    @staticmethod
    def _configured_directory(value: str | Path, *, name: str) -> Path:
        try:
            resolved = Path(value).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, TypeError) as error:
            raise ValueError(f"{name} must identify an existing directory") from error
        if not resolved.is_dir():
            raise ValueError(f"{name} must identify an existing directory")
        return resolved

    @property
    def registry(self) -> Mapping[str, ToolDefinition]:
        """The fixed registry accepted directly by ``AttemptToolRuntime``."""

        return self._registry

    @property
    def definitions(self) -> tuple[ToolDefinition, ...]:
        return tuple(self._registry.values())

    @property
    def tool_names(self) -> frozenset[str]:
        return frozenset(self._registry)

    def _check_scope(self, envelope: ToolCallEnvelope, expected_tool: str) -> None:
        if envelope.task_id != self.task.task_id:
            raise ToolBlocked("task_scope_mismatch")
        if envelope.tool_name != expected_tool:
            raise ToolBlocked("tool_binding_mismatch")

    @staticmethod
    def _exact_arguments(
        envelope: ToolCallEnvelope, expected: frozenset[str]
    ) -> Mapping[str, Any]:
        actual = frozenset(envelope.arguments)
        if actual != expected:
            raise ToolBlocked(
                "invalid_arguments",
                {"expected": sorted(expected), "actual": sorted(actual)},
            )
        return envelope.arguments

    def _portable(self, value: Any) -> Any:
        """Copy public JSON without rewriting evidence content.

        Handler payloads are assembled from an explicit field allowlist and do
        not contain the configured package/repository roots.  Replacing root
        looking substrings recursively would also rewrite legitimate advisory
        or source text while leaving its content digest unchanged.
        """

        if isinstance(value, Mapping):
            return {str(key): self._portable(child) for key, child in value.items()}
        if isinstance(value, (tuple, list)):
            return [self._portable(child) for child in value]
        return value

    def _emit(
        self,
        envelope: ToolCallEnvelope,
        *,
        tag: str,
        kind: str,
        payload: Mapping[str, Any],
        value: object,
        repository: GitRepository | None = None,
        output: Mapping[str, Any] | None = None,
    ) -> ToolHandlerOutput:
        portable_payload = self._portable(payload)
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
        self._artifacts[artifact.artifact_id] = _ArtifactBinding(
            artifact=artifact,
            tag=tag,
            value=value,
            repository=repository,
        )
        summary = {"artifact_id": artifact.artifact_id}
        if output is not None:
            summary.update(self._portable(output))
        return ToolHandlerOutput(output=summary, artifacts=(artifact,))

    def _require_artifact(
        self,
        envelope: ToolCallEnvelope,
        arguments: Mapping[str, Any],
        *,
        key: str,
        tag: str,
    ) -> _ArtifactBinding:
        wrapped = arguments.get(key)
        if not isinstance(wrapped, Mapping) or frozenset(wrapped) != {
            _ARTIFACT_REF_TAG
        }:
            raise ToolBlocked("invalid_artifact_reference", {"field": key})
        reference = wrapped[_ARTIFACT_REF_TAG]
        if not isinstance(reference, Mapping) or frozenset(reference) != _ARTIFACT_REF_FIELDS:
            raise ToolBlocked("invalid_artifact_reference", {"field": key})
        if (
            reference.get("task_id") != envelope.task_id
            or reference.get("attempt") != envelope.attempt
            or reference.get("policy_scope") != envelope.policy_scope
        ):
            raise ToolBlocked("artifact_scope_mismatch", {"field": key})
        artifact_id = reference.get("artifact_id")
        if not isinstance(artifact_id, str):
            raise ToolBlocked("invalid_artifact_reference", {"field": key})
        binding = self._artifacts.get(artifact_id)
        if binding is None or binding.tag != tag:
            raise ToolBlocked("artifact_kind_mismatch", {"field": key})
        artifact = binding.artifact
        if (
            reference.get("artifact_sha256") != artifact.artifact_sha256
            or artifact.task_id != envelope.task_id
            or artifact.attempt != envelope.attempt
            or artifact.policy_scope != envelope.policy_scope
        ):
            raise ToolBlocked("artifact_digest_mismatch", {"field": key})
        return binding

    @staticmethod
    def _string(
        arguments: Mapping[str, Any], key: str, *, error_code: str
    ) -> str:
        value = arguments.get(key)
        if not isinstance(value, str) or not value:
            raise ToolBlocked(error_code, {"field": key})
        return value

    @staticmethod
    def _commit(arguments: Mapping[str, Any], key: str) -> str:
        try:
            return validate_commit_sha(arguments.get(key))
        except InvalidCommitSha as error:
            raise ToolBlocked("invalid_commit", {"field": key}) from error

    def _source_path(self, arguments: Mapping[str, Any], key: str) -> str:
        try:
            path = validate_repo_relative_path(arguments.get(key))
        except InvalidRepositoryPath as error:
            raise ToolBlocked("invalid_source_path", {"field": key}) from error
        if path not in self.task_input.hints.source_paths:
            raise ToolBlocked("source_path_not_allowed", {"path": path})
        return path

    def _repository_binding(
        self,
        envelope: ToolCallEnvelope,
        arguments: Mapping[str, Any],
    ) -> GitRepository:
        binding = self._require_artifact(
            envelope, arguments, key="repo", tag="repository"
        )
        if not isinstance(binding.value, GitRepository):
            raise ToolBlocked("repository_capability_invalid")
        return binding.value

    @staticmethod
    def _package_issues(result: PackageLoadResult) -> list[dict[str, Any]]:
        # Messages can contain host diagnostics.  Stable codes and declared
        # relative paths are sufficient for policy/retry decisions.
        return [
            {
                "status": issue.status,
                "code": issue.code,
                "field": issue.field,
                "relative_path": issue.relative_path,
            }
            for issue in result.issues
        ]

    def _load_package_once(self) -> PackageLoadResult:
        if not self._package_loaded:
            self._package = load_evidence_package(
                self._package_root,
                self.task_input.package,
                max_file_bytes=MAX_LOCAL_FILE_BYTES,
                max_package_bytes=MAX_LOCAL_PACKAGE_BYTES,
                max_package_files=(
                    1
                    + len(self.task_input.package.references)
                    + len(self.task_input.package.patches)
                ),
                input_line=self.task_input.input_line,
                entry_id=self.task.entry_id,
                report_id=self.task.report_id,
            )
            self._package_loaded = True
        assert self._package is not None
        return self._package

    def _read_local_advisory(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "read_local_advisory")
        self._exact_arguments(envelope, frozenset())
        result = self._load_package_once()
        package = result.package
        advisory = package.advisory if package is not None else None
        if advisory is None:
            raise ToolBlocked(
                "local_advisory_unavailable",
                {"status": result.status, "issues": self._package_issues(result)},
            )
        payload = {
            "kind": advisory.kind,
            "relative_path": advisory.relative_path,
            "byte_size": advisory.byte_size,
            "sha256": advisory.sha256,
            "text": advisory.text,
            "package_status": result.status,
            "issues": self._package_issues(result),
        }
        return self._emit(
            envelope,
            tag="advisory",
            kind="t2.local_advisory",
            payload=payload,
            value=advisory,
            output={
                "status": result.status,
                "relative_path": advisory.relative_path,
                "sha256": advisory.sha256,
                "issues": self._package_issues(result),
            },
        )

    def _extract_advisory_fields(
        self, envelope: ToolCallEnvelope
    ) -> ToolHandlerOutput:
        self._check_scope(envelope, "extract_advisory_fields")
        arguments = self._exact_arguments(envelope, frozenset({"advisory"}))
        binding = self._require_artifact(
            envelope, arguments, key="advisory", tag="advisory"
        )
        if not isinstance(binding.value, LoadedEvidenceFile):
            raise ToolBlocked("advisory_capability_invalid")
        facts = extract_advisory_facts(binding.value)
        payload = {
            "source_artifact_id": binding.artifact.artifact_id,
            **asdict(facts),
        }
        return self._emit(
            envelope,
            tag="advisory_facts",
            kind="t2.advisory_facts",
            payload=payload,
            value=facts,
            output={
                "ghsa_ids": list(facts.ghsa_ids),
                "cve_ids": list(facts.cve_ids),
                "fix_commits": list(facts.fix_commits),
            },
        )

    def _read_local_patch(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "read_local_patch")
        arguments = self._exact_arguments(envelope, frozenset({"path"}))
        path = self._string(arguments, "path", error_code="invalid_patch_path")
        if path not in self.task_input.package.patches:
            raise ToolBlocked("patch_not_declared", {"path": path})
        if not self._package_loaded:
            raise ToolBlocked("package_not_loaded")
        assert self._package is not None
        package = self._package.package
        document = (
            next((item for item in package.patches if item.relative_path == path), None)
            if package is not None
            else None
        )
        if document is None:
            raise ToolBlocked("local_patch_unavailable", {"path": path})
        payload = {
            "kind": document.kind,
            "relative_path": document.relative_path,
            "byte_size": document.byte_size,
            "sha256": document.sha256,
            "text": document.text,
        }
        return self._emit(
            envelope,
            tag="local_patch",
            kind="t2.local_patch",
            payload=payload,
            value=document,
            output={
                "relative_path": document.relative_path,
                "byte_size": document.byte_size,
                "sha256": document.sha256,
            },
        )

    def _resolve_local_repo(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "resolve_local_repo")
        arguments = self._exact_arguments(envelope, frozenset({"repo_url"}))
        repo_url = self._string(arguments, "repo_url", error_code="invalid_repo_url")
        if repo_url != self.task_input.repo_url:
            raise ToolBlocked("repo_url_not_bound")
        if self._repository is None:
            try:
                self._repository = GitRepository(
                    self._repo_path,
                    max_blob_bytes=MAX_GIT_BLOB_BYTES,
                    max_diff_input_bytes=2 * MAX_GIT_BLOB_BYTES,
                    max_diff_output_bytes=MAX_GIT_DIFF_BYTES,
                )
            except GitFactError as error:
                raise ToolBlocked("local_repo_unavailable") from error
        payload = {
            "repo_url": repo_url,
            "object_format": "sha1",
            "source_paths": list(self.task_input.hints.source_paths),
        }
        return self._emit(
            envelope,
            tag="repository",
            kind="t2.local_repository",
            payload=payload,
            value=self._repository,
            repository=self._repository,
            output={"repo_url": repo_url},
        )

    def _git_parents(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "git_parents")
        arguments = self._exact_arguments(
            envelope, frozenset({"repo", "commit"})
        )
        repository = self._repository_binding(envelope, arguments)
        commit = self._commit(arguments, "commit")
        try:
            parents = repository.commit_parents(commit)
        except GitFactError as error:
            raise ToolBlocked("git_parents_unavailable", {"commit": commit}) from error
        payload = {"commit": commit, "parents": list(parents)}
        return self._emit(
            envelope,
            tag="git_parents",
            kind="t2.git_parents",
            payload=payload,
            value=parents,
            repository=repository,
            output=payload,
        )

    def _git_show(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "git_show")
        arguments = self._exact_arguments(
            envelope, frozenset({"repo", "commit", "path"})
        )
        repository = self._repository_binding(envelope, arguments)
        commit = self._commit(arguments, "commit")
        path = self._source_path(arguments, "path")
        try:
            text = repository.read_text(commit, path)
        except GitFactError as error:
            raise ToolBlocked(
                "git_blob_unavailable", {"commit": commit, "path": path}
            ) from error
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        payload = {
            "commit": commit,
            "path": path,
            "text": text,
            "text_sha256": digest,
            "utf8_bytes": len(text.encode("utf-8")),
        }
        return self._emit(
            envelope,
            tag="git_blob",
            kind="t2.git_blob",
            payload=payload,
            value=text,
            repository=repository,
            output={
                "commit": commit,
                "path": path,
                "text_sha256": digest,
                "utf8_bytes": len(text.encode("utf-8")),
            },
        )

    def _git_diff(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "git_diff")
        arguments = self._exact_arguments(
            envelope,
            frozenset({"repo", "before_commit", "after_commit", "path"}),
        )
        repository = self._repository_binding(envelope, arguments)
        before = self._commit(arguments, "before_commit")
        after = self._commit(arguments, "after_commit")
        path = self._source_path(arguments, "path")
        try:
            diff = repository.diff_text_file(before, after, path)
        except GitFactError as error:
            raise ToolBlocked(
                "git_diff_unavailable",
                {"before_commit": before, "after_commit": after, "path": path},
            ) from error
        payload = asdict(diff)
        payload["changed"] = diff.changed
        return self._emit(
            envelope,
            tag="git_diff",
            kind="t2.git_diff",
            payload=payload,
            value=_TrustedDiff(repository, diff),
            repository=repository,
            output={
                "before_commit": before,
                "after_commit": after,
                "path": path,
                "changed": diff.changed,
                "added_lines": diff.added_lines,
                "deleted_lines": diff.deleted_lines,
            },
        )

    def _version_ancestry(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "version_ancestry")
        arguments = self._exact_arguments(
            envelope, frozenset({"repo", "ancestor", "descendant"})
        )
        repository = self._repository_binding(envelope, arguments)
        ancestor = self._commit(arguments, "ancestor")
        descendant = self._commit(arguments, "descendant")
        try:
            is_ancestor = repository.is_ancestor(ancestor, descendant)
        except GitHistoryIncomplete as error:
            raise ToolBlocked(
                "git_history_incomplete",
                {"ancestor": ancestor, "descendant": descendant},
            ) from error
        except GitFactError as error:
            raise ToolBlocked(
                "version_ancestry_unavailable",
                {"ancestor": ancestor, "descendant": descendant},
            ) from error
        payload = {
            "ancestor": ancestor,
            "descendant": descendant,
            "is_ancestor": is_ancestor,
        }
        return self._emit(
            envelope,
            tag="version_ancestry",
            kind="t2.version_ancestry",
            payload=payload,
            value=is_ancestor,
            repository=repository,
            output=payload,
        )

    def _dataflow_candidate_search(
        self, envelope: ToolCallEnvelope
    ) -> ToolHandlerOutput:
        self._check_scope(envelope, "dataflow_candidate_search")
        arguments = self._exact_arguments(
            envelope, frozenset({"repo", "diff", "mode"})
        )
        repository = self._repository_binding(envelope, arguments)
        diff_binding = self._require_artifact(
            envelope, arguments, key="diff", tag="git_diff"
        )
        trusted = diff_binding.value
        if not isinstance(trusted, _TrustedDiff) or trusted.repository is not repository:
            raise ToolBlocked("diff_repository_mismatch")
        mode = self._string(arguments, "mode", error_code="invalid_critical_mode")
        if mode not in {"sink", "guard"}:
            raise ToolBlocked("invalid_critical_mode")
        try:
            analysis = analyze_patch(
                trusted.diff,
                max_files=1,
                max_candidates=MAX_CRITICAL_CANDIDATES,
            )
        except PatchAnalysisError as error:
            raise ToolBlocked("patch_analysis_failed") from error
        resolution = CriticalOperationResolver(
            repository, max_candidates=MAX_CRITICAL_CANDIDATES
        ).resolve(
            trusted.diff.before_commit,
            trusted.diff.after_commit,
            mode=mode,
            candidates=analysis,
        )
        payload = {
            "source_diff_artifact_id": diff_binding.artifact.artifact_id,
            "patch_analysis": asdict(analysis),
            "critical_resolution": resolution.to_dict(),
        }
        return self._emit(
            envelope,
            tag="critical_candidates",
            kind="t2.critical_candidates",
            payload=payload,
            value=resolution,
            repository=repository,
            output={
                "mode": mode,
                "fact_status": resolution.fact_status,
                "status": resolution.status,
                "candidate_count": len(resolution.candidates),
                "provisional_candidate_ids": list(
                    resolution.provisional_candidate_ids
                ),
                "semantic_role_verified": resolution.semantic_role_verified,
            },
        )

    @staticmethod
    def _clue_array(
        arguments: Mapping[str, Any], key: str, *, maximum: int
    ) -> tuple[str, ...]:
        value = arguments.get(key)
        if (
            isinstance(value, (str, bytes, Mapping))
            or not isinstance(value, Sequence)
            or len(value) > maximum
        ):
            raise ToolBlocked("invalid_route_clues", {"field": key})
        items = tuple(value)
        if any(not isinstance(item, str) or not item for item in items):
            raise ToolBlocked("invalid_route_clues", {"field": key})
        if len(items) != len(set(items)):
            raise ToolBlocked("invalid_route_clues", {"field": key})
        return items

    def _route_recognition(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "route_recognition")
        arguments = self._exact_arguments(
            envelope,
            frozenset({"repo", "commit", "critical_paths", "critical_symbols"}),
        )
        repository = self._repository_binding(envelope, arguments)
        commit = self._commit(arguments, "commit")
        critical_paths = self._clue_array(arguments, "critical_paths", maximum=64)
        critical_symbols = self._clue_array(
            arguments, "critical_symbols", maximum=64
        )
        if not critical_paths and not critical_symbols:
            raise ToolBlocked("missing_route_clue")
        try:
            canonical_critical_paths = tuple(
                validate_repo_relative_path(path) for path in critical_paths
            )
        except InvalidRepositoryPath as error:
            raise ToolBlocked("invalid_route_clues", {"field": "critical_paths"}) from error
        if any(
            path not in self.task_input.hints.source_paths
            for path in canonical_critical_paths
        ):
            raise ToolBlocked("source_path_not_allowed")
        if any(_SYMBOL_RE.fullmatch(symbol) is None for symbol in critical_symbols):
            raise ToolBlocked("invalid_route_clues", {"field": "critical_symbols"})
        result = EntryPointSearcher(
            repository,
            max_files=len(self.task_input.hints.source_paths),
            max_bytes=MAX_ROUTE_BYTES,
            whole_line_snippets=self._whole_line_entry_snippets,
        ).search(
            commit,
            paths=self.task_input.hints.source_paths,
            critical_paths=canonical_critical_paths,
            critical_symbols=critical_symbols,
        )
        payload = result.to_dict()
        return self._emit(
            envelope,
            tag="entry_candidates",
            kind="t2.entry_candidates",
            payload=payload,
            value=result,
            repository=repository,
            output={
                "status": result.status,
                "fact_status": result.fact_status,
                "selected_paths": list(result.selected_paths),
                "searched_paths": list(result.searched_paths),
                "candidate_count": len(result.candidates),
                "runtime_reachability_verified": (
                    result.runtime_reachability_verified
                ),
                "semantic_role_verified": result.semantic_role_verified,
            },
        )

    def _validate_schema(self, envelope: ToolCallEnvelope) -> ToolHandlerOutput:
        self._check_scope(envelope, "validate_schema")
        arguments = self._exact_arguments(envelope, frozenset({"candidate"}))
        candidate = arguments.get("candidate")
        if not isinstance(candidate, Mapping):
            raise ToolBlocked("invalid_candidate_shape")
        thawed = _thaw(candidate)
        result = self._schema_adapter.validate(thawed, formal_t2=True)
        payload = {
            "candidate_sha256": hashlib.sha256(
                _canonical_json(thawed).encode("utf-8")
            ).hexdigest(),
            **result.to_dict(),
        }
        return self._emit(
            envelope,
            tag="schema_validation",
            kind="t2.schema_validation",
            payload=payload,
            value=result,
            output=result.to_dict(),
        )


__all__ = [
    "LOCAL_T2_TOOL_CONTRACT_IDS",
    "LOCAL_T2_TOOL_NAMES",
    "LocalT2Toolbox",
    "MAX_CRITICAL_CANDIDATES",
    "MAX_GIT_BLOB_BYTES",
    "MAX_GIT_DIFF_BYTES",
    "MAX_LOCAL_FILE_BYTES",
    "MAX_LOCAL_PACKAGE_BYTES",
    "MAX_ROUTE_BYTES",
]
