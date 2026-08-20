"""Bounded, read-only discovery of textual entry-point candidates.

Only immutable blobs at caller-supplied paths are inspected.  This module
never enumerates a repository, checks out a worktree, imports inspected code,
or invokes a language runtime.  It is a conservative text fact layer, not a
call-graph engine.
"""

from __future__ import annotations

import os
import posixpath
import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Final, Literal, Sequence

from vulngym_agent.tools.git import (
    GitBlobTooLarge,
    GitFactError,
    GitRepository,
    InvalidCommitSha,
    InvalidRepositoryPath,
    validate_commit_sha,
    validate_repo_relative_path,
)


ValidationStatus = Literal["correct", "incorrect", "uncertain"]
EntryPointKind = Literal["route", "rpc", "cli", "handler", "export"]

DEFAULT_MAX_FILES: Final[int] = 64
DEFAULT_MAX_BYTES: Final[int] = 4 * 1024 * 1024
DEFAULT_MAX_CANDIDATES: Final[int] = 100
HARD_MAX_FILES: Final[int] = 512
HARD_MAX_BYTES: Final[int] = 32 * 1024 * 1024
HARD_MAX_CANDIDATES: Final[int] = 1_000
_MAX_CLUES: Final[int] = 64
_MAX_CLUE_CHARS: Final[int] = 256
_MAX_SCOPE_LINES: Final[int] = 200
_MAX_SNIPPET_CHARS: Final[int] = 2_000

_LANGUAGES: Final[dict[str, str]] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".go": "go", ".rb": "ruby",
    ".php": "php", ".phtml": "php",
}
_HANDLER_NAME_RE = re.compile(
    r"(?:handler|handle|controller|endpoint|command|execute|serve|main|helper)\Z",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class EntryPointCandidate:
    """One supported textual construct related to a supplied critical clue."""

    status: ValidationStatus
    fact_status: ValidationStatus
    path: str
    line: int
    end_line: int
    language: str
    kind: EntryPointKind
    symbol: str | None
    explicit_external_binding: bool
    direct_critical_reference: bool
    matched_clue: str
    runtime_reachability_verified: bool
    semantic_role_verified: bool
    code: str
    evidence: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EntryPointSearchIssue:
    status: Literal["incorrect", "uncertain"]
    code: str
    path: str | None
    evidence: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EntryPointSearchResult:
    status: ValidationStatus
    fact_status: ValidationStatus
    commit: str | None
    selected_paths: tuple[str, ...]
    searched_paths: tuple[str, ...]
    critical_paths: tuple[str, ...]
    critical_symbols: tuple[str, ...]
    candidates: tuple[EntryPointCandidate, ...]
    issues: tuple[EntryPointSearchIssue, ...]
    unsupported_reasons: tuple[str, ...]
    bytes_read: int
    max_files: int
    max_bytes: int
    max_candidates: int
    candidates_truncated: bool
    runtime_reachability_verified: bool
    semantic_role_verified: bool
    evidence: str
    error_code: str | None = None

    @property
    def deterministic_valid(self) -> bool | None:
        if self.fact_status == "correct":
            return True
        if self.fact_status == "incorrect":
            return False
        return None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _Marker:
    line: int
    declaration_line: int
    kind: EntryPointKind
    symbol: str | None
    explicit: bool
    scope: Literal["line", "python", "brace", "ruby"]


def _positive_limit(name: str, value: object, hard_limit: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= hard_limit:
        raise ValueError(f"{name} must be an integer from 1 to {hard_limit}")
    return value


def _as_sequence(value: object, name: str) -> tuple[object, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError(f"{name} must be a sequence, not a scalar string")
    return tuple(value)


def _validate_symbol(symbol: object) -> str:
    if not isinstance(symbol, str) or not symbol:
        raise ValueError("critical symbols must be non-empty strings")
    if len(symbol) > _MAX_CLUE_CHARS:
        raise ValueError(f"critical symbols must not exceed {_MAX_CLUE_CHARS} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in symbol):
        raise ValueError("critical symbols must not contain control characters")
    return symbol


def _language(path: str) -> str | None:
    return _LANGUAGES.get(PurePosixPath(path).suffix.casefold())


def _next_declaration(
    lines: Sequence[str], start: int, pattern: re.Pattern[str], limit: int = 8
) -> tuple[int, re.Match[str]] | None:
    for index in range(start + 1, min(len(lines), start + limit + 1)):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith(("@", "#[")):
            continue
        match = pattern.match(lines[index])
        return (index, match) if match is not None else None
    return None


_PY_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
_PY_DECORATOR_RE = re.compile(
    r"^\s*@[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\."
    r"(?P<method>route|get|post|put|delete|patch|options|head|websocket|rpc|method|command|group)\s*\(",
    re.IGNORECASE,
)
_PY_MAIN_RE = re.compile(r"^\s*if\s+__name__\s*==\s*([\"'])__main__\1\s*:")
_JS_ROUTE_RE = re.compile(
    r"^\s*[A-Za-z_$][\w$.[\]]*\s*\.\s*(?P<method>get|post|put|delete|patch|options|head|all|use)\s*\(",
    re.IGNORECASE,
)
_JS_RPC_RE = re.compile(
    r"^\s*(?:[A-Za-z_$][\w$]*\.)*(?:rpc|grpc|server|service)[\w$]*\s*\.\s*"
    r"(?:addService|registerService|register|handle|on)\s*\(", re.IGNORECASE
)
_JS_CLI_RE = re.compile(
    r"^\s*(?:program|cli|yargs|commander)\s*\.\s*(?:command|action|handler)\s*\(",
    re.IGNORECASE,
)
_JS_EXPORT_RE = re.compile(
    r"^\s*export\s+(?:default\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+"
    r"([A-Za-z_$][\w$]*)\b"
)
_JS_COMMON_EXPORT_RE = re.compile(r"^\s*(?:module\.)?exports(?:\.([A-Za-z_$][\w$]*))?\s*=")
_JS_FUNCTION_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("
)
_JS_CONST_FUNCTION_RE = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*="
)
_JAVA_ANNOTATION_RE = re.compile(
    r"^\s*@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|"
    r"Path|GET|POST|PUT|DELETE|PATCH|Command|RpcMethod|GrpcService)\b", re.IGNORECASE
)
_JAVA_METHOD_RE = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|synchronized|abstract|native|default)\s+)*"
    r"(?:[A-Za-z_$][\w$<>,.?\[\]]*\s+)+([A-Za-z_$][\w$]*)\s*\("
)
_JAVA_MAIN_RE = re.compile(r"^\s*public\s+static\s+void\s+(main)\s*\(", re.IGNORECASE)
_GO_FUNC_RE = re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(")
_GO_ROUTE_RE = re.compile(
    r"^\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.(?:HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|Methods)\s*\(",
    re.IGNORECASE,
)
_GO_RPC_RE = re.compile(r"^\s*(?:[A-Za-z_]\w*\.)?Register\w+Server\s*\(")
_GO_CLI_RE = re.compile(r"^\s*(?:Use|Run|RunE)\s*:")
_RUBY_ROUTE_RE = re.compile(r"^\s*(?:get|post|put|patch|delete|options|head)\s+", re.IGNORECASE)
_RUBY_CLI_RE = re.compile(r"^\s*(?:desc|command)\s+", re.IGNORECASE)
_RUBY_DEF_RE = re.compile(r"^\s*def\s+(?:self\.)?([A-Za-z_]\w*[!?=]?)")
_PHP_ROUTE_RE = re.compile(
    r"^\s*(?:\\?[A-Za-z_]\w*\\)*Route::(?:get|post|put|patch|delete|options|any|match)\s*\(",
    re.IGNORECASE,
)
_PHP_ATTRIBUTE_RE = re.compile(r"^\s*#\[\s*(?:\\?[A-Za-z_]\w*\\)*Route\s*\(", re.IGNORECASE)
_PHP_COMMAND_RE = re.compile(r"^\s*#\[\s*(?:\\?[A-Za-z_]\w*\\)*AsCommand\s*\(", re.IGNORECASE)
_PHP_FUNCTION_RE = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|abstract)\s+)*"
    r"function\s+&?\s*([A-Za-z_]\w*)\s*\(", re.IGNORECASE
)


def _markers(language: str, lines: Sequence[str]) -> list[_Marker]:
    markers: list[_Marker] = []
    declared: set[int] = set()
    if language == "python":
        for index, line in enumerate(lines):
            decorator = _PY_DECORATOR_RE.match(line)
            if decorator:
                declaration = _next_declaration(lines, index, _PY_DEF_RE)
                if declaration:
                    declaration_line, match = declaration
                    method = decorator.group("method").casefold()
                    kind: EntryPointKind = "cli" if method in {"command", "group"} else "rpc" if method in {"rpc", "method"} else "route"
                    markers.append(_Marker(index, declaration_line, kind, match.group(1), True, "python"))
                    declared.add(declaration_line)
            if _PY_MAIN_RE.match(line):
                markers.append(_Marker(index, index, "cli", "__main__", True, "python"))
            if re.match(r"^\s*__all__\s*=", line):
                markers.append(_Marker(index, index, "export", "__all__", True, "line"))
        for index, line in enumerate(lines):
            match = _PY_DEF_RE.match(line)
            if match and index not in declared and _HANDLER_NAME_RE.search(match.group(1)):
                markers.append(_Marker(index, index, "handler", match.group(1), False, "python"))
    elif language in {"javascript", "typescript"}:
        for index, line in enumerate(lines):
            export = _JS_EXPORT_RE.match(line)
            if export:
                markers.append(_Marker(index, index, "export", export.group(1), True, "brace")); declared.add(index)
            common = _JS_COMMON_EXPORT_RE.match(line)
            if common:
                markers.append(_Marker(index, index, "export", common.group(1) or "module.exports", True, "line"))
            if _JS_ROUTE_RE.match(line):
                markers.append(_Marker(index, index, "route", None, True, "brace"))
            elif _JS_RPC_RE.match(line):
                markers.append(_Marker(index, index, "rpc", None, True, "brace"))
            elif _JS_CLI_RE.match(line):
                markers.append(_Marker(index, index, "cli", None, True, "brace"))
        for index, line in enumerate(lines):
            function = _JS_FUNCTION_RE.match(line) or _JS_CONST_FUNCTION_RE.match(line)
            if function and index not in declared and _HANDLER_NAME_RE.search(function.group(1)):
                markers.append(_Marker(index, index, "handler", function.group(1), False, "brace"))
    elif language == "java":
        for index, line in enumerate(lines):
            if _JAVA_ANNOTATION_RE.match(line):
                declaration = _next_declaration(lines, index, _JAVA_METHOD_RE)
                if declaration:
                    declaration_line, match = declaration
                    annotation = line.casefold()
                    kind = "rpc" if "rpc" in annotation or "grpc" in annotation else "cli" if "command" in annotation else "route"
                    markers.append(_Marker(index, declaration_line, kind, match.group(1), True, "brace")); declared.add(declaration_line)
            main = _JAVA_MAIN_RE.match(line)
            if main:
                markers.append(_Marker(index, index, "cli", main.group(1), True, "brace")); declared.add(index)
        for index, line in enumerate(lines):
            method = _JAVA_METHOD_RE.match(line)
            if method and index not in declared and _HANDLER_NAME_RE.search(method.group(1)):
                markers.append(_Marker(index, index, "handler", method.group(1), False, "brace"))
    elif language == "go":
        for index, line in enumerate(lines):
            function = _GO_FUNC_RE.match(line)
            if function:
                name = function.group(1)
                if name[:1].isupper():
                    markers.append(_Marker(index, index, "export", name, True, "brace")); declared.add(index)
                elif _HANDLER_NAME_RE.search(name):
                    markers.append(_Marker(index, index, "handler", name, False, "brace"))
            if _GO_ROUTE_RE.match(line):
                markers.append(_Marker(index, index, "route", None, True, "line"))
            elif _GO_RPC_RE.match(line):
                markers.append(_Marker(index, index, "rpc", None, True, "line"))
            elif _GO_CLI_RE.match(line):
                markers.append(_Marker(index, index, "cli", None, True, "brace"))
    elif language == "ruby":
        pending_cli: int | None = None
        for index, line in enumerate(lines):
            if _RUBY_ROUTE_RE.match(line):
                markers.append(_Marker(index, index, "route", None, True, "ruby"))
            if _RUBY_CLI_RE.match(line):
                pending_cli = index
            method = _RUBY_DEF_RE.match(line)
            if method:
                if pending_cli is not None and index - pending_cli <= 8:
                    markers.append(_Marker(pending_cli, index, "cli", method.group(1), True, "ruby")); declared.add(index); pending_cli = None
                elif _HANDLER_NAME_RE.search(method.group(1)):
                    markers.append(_Marker(index, index, "handler", method.group(1), False, "ruby"))
    elif language == "php":
        for index, line in enumerate(lines):
            if _PHP_ROUTE_RE.match(line):
                markers.append(_Marker(index, index, "route", None, True, "brace"))
            kind: EntryPointKind | None = "route" if _PHP_ATTRIBUTE_RE.match(line) else "cli" if _PHP_COMMAND_RE.match(line) else None
            if kind:
                declaration = _next_declaration(lines, index, _PHP_FUNCTION_RE)
                if declaration:
                    declaration_line, match = declaration
                    markers.append(_Marker(index, declaration_line, kind, match.group(1), True, "brace")); declared.add(declaration_line)
        for index, line in enumerate(lines):
            function = _PHP_FUNCTION_RE.match(line)
            if function and index not in declared and _HANDLER_NAME_RE.search(function.group(1)):
                markers.append(_Marker(index, index, "handler", function.group(1), False, "brace"))

    markers.sort(key=lambda marker: (marker.line, not marker.explicit, marker.kind))
    result: list[_Marker] = []
    explicit_declarations = {(marker.declaration_line, marker.symbol) for marker in markers if marker.explicit}
    for marker in markers:
        if not marker.explicit and (marker.declaration_line, marker.symbol) in explicit_declarations:
            continue
        result.append(marker)
    return result


def _python_scope_end(lines: Sequence[str], declaration: int) -> int:
    indent = len(lines[declaration]) - len(lines[declaration].lstrip(" \t"))
    end = declaration
    for index in range(declaration + 1, min(len(lines), declaration + _MAX_SCOPE_LINES)):
        if not lines[index].strip():
            end = index; continue
        if len(lines[index]) - len(lines[index].lstrip(" \t")) <= indent:
            break
        end = index
    return end


def _brace_scope_end(lines: Sequence[str], start: int) -> int:
    stop = min(len(lines), start + _MAX_SCOPE_LINES)
    depth = 0; found = False; quote: str | None = None; escaped = False
    for index in range(start, stop):
        for character in lines[index]:
            if escaped:
                escaped = False; continue
            if quote is not None:
                if character == "\\": escaped = True
                elif character == quote: quote = None
                continue
            if character in {"'", '"', "`"}: quote = character
            elif character == "{": depth += 1; found = True
            elif character == "}" and found:
                depth -= 1
                if depth <= 0: return index
        if not found and index - start >= 8: break
    return start if not found else min(stop - 1, len(lines) - 1)


def _ruby_scope_end(lines: Sequence[str], start: int) -> int:
    stop = min(len(lines), start + _MAX_SCOPE_LINES)
    depth = 0; found = False
    opener = re.compile(r"\b(?:do|def|class|module|begin|case)\b")
    for index in range(start, stop):
        text = lines[index].split("#", 1)[0]
        depth += len(opener.findall(text)); found = found or depth > 0
        if re.match(r"^\s*end\b", text):
            depth -= 1
            if found and depth <= 0: return index
    return start if not found else min(stop - 1, len(lines) - 1)


def _scope(lines: Sequence[str], marker: _Marker) -> tuple[int, str]:
    if marker.scope == "python": end = _python_scope_end(lines, marker.declaration_line)
    elif marker.scope == "brace": end = _brace_scope_end(lines, marker.line)
    elif marker.scope == "ruby": end = _ruby_scope_end(lines, marker.line)
    else: end = marker.line
    return end, "\n".join(lines[marker.line:end + 1])


def _contains_symbol(text: str, symbol: str) -> bool:
    return re.search(r"(?<![A-Za-z0-9_$])" + re.escape(symbol) + r"(?![A-Za-z0-9_$])", text) is not None


def _path_forms(candidate_path: str, critical_path: str) -> tuple[str, ...]:
    critical_stem = str(PurePosixPath(critical_path).with_suffix(""))
    relative = posixpath.relpath(critical_path, posixpath.dirname(candidate_path) or ".")
    relative_stem = str(PurePosixPath(relative).with_suffix(""))
    forms = {critical_path, critical_stem, critical_stem.replace("/", "."), relative, relative_stem}
    if not relative.startswith("."):
        forms.update({f"./{relative}", f"./{relative_stem}"})
    return tuple(sorted((value for value in forms if len(value) > 1), key=len, reverse=True))


def _relation(
    path: str, scope_text: str, file_text: str,
    critical_paths: Sequence[str], critical_symbols: Sequence[str],
) -> tuple[bool, bool, str | None]:
    for symbol in critical_symbols:
        if _contains_symbol(scope_text, symbol): return True, True, f"symbol:{symbol}"
    for critical_path in critical_paths:
        if any(form in scope_text for form in _path_forms(path, critical_path)):
            return True, True, f"path:{critical_path}"
    for symbol in critical_symbols:
        if _contains_symbol(file_text, symbol): return True, False, f"symbol:{symbol}"
    for critical_path in critical_paths:
        if path == critical_path or any(form in file_text for form in _path_forms(path, critical_path)):
            return True, False, f"path:{critical_path}"
    return False, False, None


class EntryPointSearcher:
    """Search an explicit path allow-list at one immutable commit."""

    def __init__(
        self, repository: GitRepository | str | os.PathLike[str], *,
        timeout_seconds: float = 10.0,
        max_files: int = DEFAULT_MAX_FILES,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_candidates: int = DEFAULT_MAX_CANDIDATES,
    ) -> None:
        self.max_files = _positive_limit("max_files", max_files, HARD_MAX_FILES)
        self.max_bytes = _positive_limit("max_bytes", max_bytes, HARD_MAX_BYTES)
        self.max_candidates = _positive_limit("max_candidates", max_candidates, HARD_MAX_CANDIDATES)
        self._repository: GitRepository | None
        self._repository_error: GitFactError | None
        if isinstance(repository, GitRepository):
            self._repository = repository; self._repository_error = None
        else:
            try:
                self._repository = GitRepository(repository, timeout_seconds=timeout_seconds, max_blob_bytes=max_bytes)
                self._repository_error = None
            except GitFactError as error:
                self._repository = None; self._repository_error = error

    def _result(
        self, status: ValidationStatus, fact_status: ValidationStatus,
        commit: str | None, selected: tuple[str, ...], critical_paths: tuple[str, ...],
        symbols: tuple[str, ...], candidates: tuple[EntryPointCandidate, ...],
        issues: tuple[EntryPointSearchIssue, ...], unsupported: tuple[str, ...],
        searched: tuple[str, ...], bytes_read: int, truncated: bool,
        evidence: str, error_code: str | None = None,
    ) -> EntryPointSearchResult:
        return EntryPointSearchResult(
            status, fact_status, commit, selected, searched, critical_paths, symbols,
            candidates, issues, unsupported, bytes_read, self.max_files, self.max_bytes,
            self.max_candidates, truncated, False, False, evidence, error_code,
        )

    def _invalid(self, evidence: str, code: str, commit: str | None = None) -> EntryPointSearchResult:
        issue = EntryPointSearchIssue("incorrect", code, None, evidence)
        return self._result("incorrect", "incorrect", commit, (), (), (), (), (issue,), (), (), 0, False, evidence, code)

    def search(
        self, commit: object, *, paths: Sequence[object],
        critical_paths: Sequence[object] = (), critical_symbols: Sequence[object] = (),
    ) -> EntryPointSearchResult:
        try:
            canonical_commit = validate_commit_sha(commit)
        except InvalidCommitSha as error:
            return self._invalid(f"Commit syntax is invalid: {error}.", "invalid_commit_sha", commit if isinstance(commit, str) else None)
        try:
            raw_paths = _as_sequence(paths, "paths")
            raw_critical_paths = _as_sequence(critical_paths, "critical_paths")
            raw_symbols = _as_sequence(critical_symbols, "critical_symbols")
        except TypeError as error:
            return self._invalid(str(error), "invalid_sequence", canonical_commit)
        if not raw_paths:
            return self._invalid("At least one explicit source path is required; repository-wide enumeration is unsupported.", "empty_path_allow_list", canonical_commit)
        if len(raw_paths) > self.max_files:
            return self._invalid(f"Selected path count exceeds max_files={self.max_files}; no files were read.", "max_files_exceeded", canonical_commit)
        if not raw_critical_paths and not raw_symbols:
            return self._invalid("At least one critical path or symbol clue is required.", "missing_critical_clue", canonical_commit)
        if len(raw_critical_paths) + len(raw_symbols) > _MAX_CLUES:
            return self._invalid(f"Critical clue count exceeds {_MAX_CLUES}.", "too_many_critical_clues", canonical_commit)
        try:
            selected = tuple(validate_repo_relative_path(path) for path in raw_paths)
            critical_path_values = tuple(validate_repo_relative_path(path) for path in raw_critical_paths)
            symbol_values = tuple(_validate_symbol(symbol) for symbol in raw_symbols)
        except (InvalidRepositoryPath, ValueError) as error:
            return self._invalid(f"A path or symbol clue is invalid: {error}.", "invalid_path_or_clue", canonical_commit)
        if len(set(selected)) != len(selected):
            return self._invalid("Selected paths must be unique.", "duplicate_selected_path", canonical_commit)
        if self._repository is None:
            assert self._repository_error is not None
            evidence = f"The local repository could not be inspected; no blobs were read: {self._repository_error}."
            issue = EntryPointSearchIssue("uncertain", "repository_unavailable", None, evidence)
            return self._result("uncertain", "uncertain", canonical_commit, selected, critical_path_values, symbol_values, (), (issue,), (), (), 0, False, evidence, issue.code)

        candidates: list[EntryPointCandidate] = []
        issues: list[EntryPointSearchIssue] = []
        unsupported: list[str] = []
        searched: list[str] = []
        bytes_read = 0; truncated = False
        for path in selected:
            language = _language(path)
            if language is None:
                reason = f"{path}: unsupported source extension"
                unsupported.append(reason); issues.append(EntryPointSearchIssue("uncertain", "unsupported_language", path, reason)); continue
            remaining = self.max_bytes - bytes_read
            if remaining <= 0:
                issues.append(EntryPointSearchIssue("uncertain", "max_bytes_exhausted", path, f"No byte budget remains for {path}.")); continue
            try:
                # Strict total budget even when the injected repository has a larger per-blob cap.
                bounded = GitRepository(self._repository.path, timeout_seconds=self._repository.timeout_seconds, max_blob_bytes=min(self._repository.max_blob_bytes, remaining))
                data = bounded.read_file(canonical_commit, path)
            except GitBlobTooLarge as error:
                issues.append(EntryPointSearchIssue("uncertain", "source_too_large_or_budget_exceeded", path, f"Source was not read within the remaining byte budget: {error}.")); continue
            except GitFactError as error:
                issues.append(EntryPointSearchIssue("uncertain", "source_read_failed", path, f"Immutable source blob could not be read: {error}.")); continue
            bytes_read += len(data)
            try:
                text = data.decode("utf-8-sig", errors="strict")
            except UnicodeDecodeError:
                issues.append(EntryPointSearchIssue("uncertain", "non_utf8_source", path, "Immutable source blob is not valid UTF-8 text.")); continue
            searched.append(path); lines = text.splitlines()
            for marker in _markers(language, lines):
                end, scope_text = _scope(lines, marker)
                related, direct, matched = _relation(path, scope_text, text, critical_path_values, symbol_values)
                if not related or matched is None: continue
                if len(candidates) >= self.max_candidates:
                    truncated = True; break
                # Even a same-scope explicit binding is only a lexical/structural
                # fact.  It must not establish runtime reachability by itself.
                status: ValidationStatus = "uncertain"
                construct = "explicit entry/export construct" if marker.explicit else "handler/helper naming heuristic"
                relation = "same bounded construct directly references" if direct else "selected file, outside that construct, references"
                caveat = (
                    "Runtime reachability and vulnerability semantics remain unproved."
                    if marker.explicit and direct
                    else "The heuristic candidate must not be promoted to a verified entry point."
                )
                candidates.append(EntryPointCandidate(
                    status, "correct", path, marker.line + 1, end + 1, language, marker.kind,
                    marker.symbol, marker.explicit, direct, matched, False, False,
                    scope_text[:_MAX_SNIPPET_CHARS],
                    f"Observed {construct}; the {relation} {matched}. {caveat}",
                ))
            if truncated:
                issues.append(EntryPointSearchIssue("uncertain", "max_candidates_exceeded", path, f"Candidate output was truncated at {self.max_candidates}.")); break

        incomplete = bool(issues) or truncated
        if incomplete: status, fact_status = "uncertain", "uncertain"
        else: status, fact_status = "uncertain", "correct"
        evidence = f"Read {bytes_read} bytes from {len(searched)} explicitly selected files and retained {len(candidates)} clue-related candidates. Runtime reachability and vulnerability semantics were not verified."
        if not candidates: evidence += " Bounded absence is not proof that the repository has no entry point."
        if issues: evidence += f" {len(issues)} issue(s) made the search incomplete."
        return self._result(status, fact_status, canonical_commit, selected, critical_path_values, symbol_values, tuple(candidates), tuple(issues), tuple(unsupported), tuple(searched), bytes_read, truncated, evidence, issues[0].code if issues else None)


def search_entry_points(
    repository: GitRepository | str | os.PathLike[str], commit: object, *,
    paths: Sequence[object], critical_paths: Sequence[object] = (),
    critical_symbols: Sequence[object] = (), timeout_seconds: float = 10.0,
    max_files: int = DEFAULT_MAX_FILES, max_bytes: int = DEFAULT_MAX_BYTES,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> EntryPointSearchResult:
    return EntryPointSearcher(
        repository, timeout_seconds=timeout_seconds, max_files=max_files,
        max_bytes=max_bytes, max_candidates=max_candidates,
    ).search(commit, paths=paths, critical_paths=critical_paths, critical_symbols=critical_symbols)


__all__ = [
    "DEFAULT_MAX_BYTES", "DEFAULT_MAX_CANDIDATES", "DEFAULT_MAX_FILES",
    "EntryPointCandidate", "EntryPointSearchIssue", "EntryPointSearchResult",
    "EntryPointSearcher", "search_entry_points",
]
