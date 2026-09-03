"""Offline, low-noise authoring helper for B-v2 replay D2/D3 pairs.

This script deliberately stays inside the replay-authoring contract:

* inputs come from the public authoring export index and one sealed source tree;
* the private benchmark gold / selection lock / source-map files are never read;
* every committed D2/D3 response is bound through ``ReplayAuthoringResponseV1``;
* final publication is still performed by the trusted replay-authoring API.

The only heuristic part is choosing the next structured response body.  It first
scans the sealed source tree itself to pick a likely source-discovery anchor,
then drives the normal inventory/search/read/structure/link/select contract so
the final artifacts remain replayable and auditable.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
from typing import Any, Iterable, Literal, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vulngym_agent.evaluator.replay_authoring import (
    ReplayAuthoringError,
    ReplayAuthoringPendingRequestV1,
    ReplayAuthoringResponseV1,
    ReplayAuthoringSummaryV1,
    append_replay_authoring_response_v1,
    initialize_replay_authoring_v1,
    inspect_replay_authoring_v1,
    publish_replay_authoring_v1,
    read_pinned_authoring_task_v1,
)
from vulngym_agent.evaluator.oci_worker_entry import OciReplayConfigV1
from vulngym_agent.agents.model_runtime import ReplayResponse
from vulngym_agent.trusted_inputs import (
    read_attestation_key_file_v1,
    zero_secret_buffer_v1,
)


DEFAULT_RUNTIME_ROOT = Path(os.environ.get("VULNGYM_BV2_RUNTIME", r"D:\VulnGym-bv2-runtime"))
DEFAULT_PUBLIC_DATASET_ROOT = Path(
    os.environ.get(
        "VULNGYM_PUBLIC_DATASET_ROOT",
        r"D:\GitProjects\VulnGym\benchmarks\vulngym_50_20_v1\public",
    )
)

MAX_INVENTORY_BATCH = 64
MAX_SEARCH_PATHS = 64
MAX_SEARCH_RESULTS = 8
MAX_READ_SPANS = 16
MAX_STRUCTURE_RESULTS = 80
MAX_LINK_RESULTS = 80
MAX_LOCAL_SCAN_BYTES = 512 * 1024
MAX_LOCAL_SCAN_FILES = 12_000

TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".svelte",
    ".swift",
    ".ts",
    ".tsx",
    ".vue",
}

SKIP_PARTS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
    "build",
    "target",
    "coverage",
    ".next",
    ".venv",
    "venv",
}

SOFT_SKIP_PARTS = {
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "fixtures",
    "fixture",
    "docs",
    "doc",
    "examples",
    "example",
    "mock",
    "mocks",
}

PATH_KEYWORDS = {
    "auth": 22,
    "authorization": 22,
    "permission": 20,
    "policy": 12,
    "route": 18,
    "routes": 18,
    "controller": 18,
    "controllers": 18,
    "api": 15,
    "server": 14,
    "gateway": 18,
    "webhook": 18,
    "socket": 12,
    "session": 16,
    "sandbox": 22,
    "exec": 24,
    "invoke": 18,
    "command": 18,
    "plugin": 14,
    "install": 12,
    "file": 12,
    "fs": 12,
    "path": 10,
    "upload": 12,
    "import": 8,
    "loader": 10,
    "export": 8,
    "admin": 12,
    "tenant": 12,
    "organization": 14,
}

CONTEXT_KEYWORDS = {
    "req": 8,
    "request": 8,
    "params": 8,
    "query": 8,
    "body": 8,
    "header": 8,
    "headers": 8,
    "token": 8,
    "cookie": 8,
    "user": 6,
    "owner": 8,
    "admin": 8,
    "organization": 10,
    "organizationid": 10,
    "tenant": 8,
    "path": 7,
    "url": 7,
    "cmd": 8,
    "command": 8,
    "clipath": 10,
    "filename": 7,
}


@dataclass(frozen=True, slots=True)
class Pattern:
    query: str
    token: str
    weight: int


PATTERNS: tuple[Pattern, ...] = (
    Pattern("pickle.load", "load", 120),
    Pattern("pickle.loads", "loads", 120),
    Pattern("torch.load", "load", 112),
    Pattern("yaml.load", "load", 105),
    Pattern("marshal.loads", "loads", 105),
    Pattern("joblib.load", "load", 100),
    Pattern("cloudpickle.load", "load", 100),
    Pattern("ObjectInputStream", "ObjectInputStream", 96),
    Pattern("readObject", "readObject", 96),
    Pattern("Runtime.getRuntime().exec", "exec", 112),
    Pattern("ProcessBuilder", "ProcessBuilder", 100),
    Pattern("child_process", "child_process", 100),
    Pattern("execPromise", "execPromise", 92),
    Pattern("execCommand", "execCommand", 88),
    Pattern("execSync", "execSync", 105),
    Pattern("spawnSync", "spawnSync", 92),
    Pattern("spawn(", "spawn", 88),
    Pattern("exec(", "exec", 90),
    Pattern("os.system", "system", 100),
    Pattern("subprocess.", "subprocess", 92),
    Pattern("shell=True", "shell", 88),
    Pattern("eval(", "eval", 95),
    Pattern("new Function", "Function", 90),
    Pattern("vm.runIn", "runIn", 88),
    Pattern("innerHTML", "innerHTML", 88),
    Pattern("dangerouslySetInnerHTML", "dangerouslySetInnerHTML", 88),
    Pattern("res.json", "json", 68),
    Pattern("res.send", "send", 66),
    Pattern("response.json", "json", 62),
    Pattern("router.get", "get", 62),
    Pattern("router.post", "post", 62),
    Pattern("router.put", "put", 64),
    Pattern("router.delete", "delete", 64),
    Pattern("app.get", "get", 62),
    Pattern("app.post", "post", 62),
    Pattern("app.put", "put", 64),
    Pattern("app.delete", "delete", 64),
    Pattern("FastAPI", "FastAPI", 58),
    Pattern("@router.get", "get", 62),
    Pattern("@router.post", "post", 62),
    Pattern("@router.put", "put", 64),
    Pattern("@router.delete", "delete", 64),
    Pattern("readFile", "readFile", 78),
    Pattern("writeFile", "writeFile", 78),
    Pattern("open(", "open", 52),
    Pattern("send_file", "send_file", 82),
    Pattern("FileResponse", "FileResponse", 78),
    Pattern("tar.extract", "extract", 88),
    Pattern("extractall", "extractall", 88),
    Pattern("path.join", "join", 60),
    Pattern("resolve(", "resolve", 54),
    Pattern("sql`", "sql", 72),
    Pattern("query(", "query", 62),
    Pattern("execute(", "execute", 62),
    Pattern("raw(", "raw", 58),
    Pattern("ORDER BY", "ORDER", 58),
    Pattern("organizationId", "organizationId", 62),
    Pattern("tenantId", "tenantId", 58),
    Pattern("checkPermission", "checkPermission", 58),
    Pattern("authenticateRequest", "authenticateRequest", 58),
    Pattern("removeSession", "removeSession", 56),
    Pattern("handleRequest", "handleRequest", 56),
    Pattern("websocket", "websocket", 52),
    Pattern("WebSocket", "WebSocket", 52),
    Pattern("http.Get", "Get", 72),
    Pattern("exec.Command", "Command", 100),
    Pattern("template.HTML", "HTML", 84),
)


DECLARATION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("function_declaration", re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\b")),
    ("class_declaration", re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b")),
    ("function_declaration", re.compile(r"\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")),
    (
        "function_declaration",
        re.compile(
            r"^\s*(?:export\s+)?(?:const|let|var)\s+"
            r"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
            r"(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>"
        ),
    ),
    ("function_declaration", re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")),
)

CALL_RE = re.compile(r"(?<![A-Za-z0-9_$])([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
CALL_KEYWORDS = {
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


@dataclass(frozen=True, slots=True)
class LocalHit:
    path: str
    line: int
    query: str
    token: str
    score: int
    declaration_line: int | None
    declaration_token: str | None
    relation_line: int | None
    relation_token: str | None
    entry_line: int | None


@dataclass(frozen=True, slots=True)
class TaskPlan:
    task_id: str
    split: Literal["test", "train"]
    target_path: str
    target_index: int
    inventory_cursor: int
    critical_line: int
    critical_query: str
    critical_token: str
    entry_line: int
    entry_token: str | None
    relation_line: int | None
    relation_token: str | None
    score: int

    @property
    def relation_query(self) -> str | None:
        return self.relation_token


def _json_line(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_line(value))


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _path_parts(rel: str) -> set[str]:
    chunks: set[str] = set()
    for part in rel.replace("\\", "/").split("/"):
        stem = part.rsplit(".", 1)[0]
        for chunk in re.split(r"[^A-Za-z0-9]+", stem):
            if chunk:
                chunks.add(chunk.lower())
        if part:
            chunks.add(part.lower())
    return chunks


def _should_skip_file(rel: str, size: int) -> bool:
    parts = _path_parts(rel)
    if parts & SKIP_PARTS:
        return True
    suffix = Path(rel).suffix.lower()
    if suffix not in TEXT_EXTENSIONS:
        return True
    return size <= 0 or size > MAX_LOCAL_SCAN_BYTES


def _soft_penalty(rel: str) -> int:
    parts = _path_parts(rel)
    return -35 if parts & SOFT_SKIP_PARTS else 0


def _path_score(rel: str, repo_hint_paths: Counter[str]) -> int:
    lower = rel.lower()
    score = _soft_penalty(rel)
    for keyword, weight in PATH_KEYWORDS.items():
        if keyword in lower:
            score += weight
    if rel in repo_hint_paths:
        score += min(120, 30 + repo_hint_paths[rel] * 12)
    else:
        for hinted, count in repo_hint_paths.items():
            hinted_parts = set(hinted.lower().split("/"))
            rel_parts = set(lower.split("/"))
            if hinted_parts and len(hinted_parts & rel_parts) >= 2:
                score += min(40, 8 + count * 4)
    return score


def _context_score(line: str) -> int:
    lower = line.lower()
    return sum(weight for keyword, weight in CONTEXT_KEYWORDS.items() if keyword in lower)


def _read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _iter_regular_files(tree: Path) -> list[str]:
    files: list[str] = []
    for path in tree.rglob("*"):
        if path.is_file():
            files.append(path.relative_to(tree).as_posix())
    files.sort()
    return files


def _iter_scannable_files(tree: Path, inventory: Sequence[str]) -> Iterable[tuple[str, Path, int]]:
    emitted = 0
    for rel in inventory:
        path = tree / Path(*rel.split("/"))
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if _should_skip_file(rel, size):
            continue
        emitted += 1
        if emitted > MAX_LOCAL_SCAN_FILES:
            break
        yield rel, path, size


def _declarations(lines: Sequence[str]) -> list[tuple[int, int, str]]:
    result: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines, start=1):
        for _kind, pattern in DECLARATION_PATTERNS:
            match = pattern.search(line)
            if match is None:
                continue
            indent = len(line) - len(line.lstrip(" \t"))
            result.append((index, indent, match.group(1)))
            break
    return result


def _nearest_declaration(
    lines: Sequence[str], declarations: Sequence[tuple[int, int, str]], line_number: int
) -> tuple[int, str] | None:
    if not declarations:
        return None
    target_line = lines[line_number - 1] if 1 <= line_number <= len(lines) else ""
    target_indent = len(target_line) - len(target_line.lstrip(" \t"))
    before = [
        (line, indent, token)
        for line, indent, token in declarations
        if line <= line_number and (indent <= target_indent or target_indent == 0)
    ]
    if before:
        line, _indent, token = before[-1]
        return line, token
    line, _indent, token = declarations[0]
    return line, token


def _find_relation_line(
    lines: Sequence[str], token: str | None, declaration_line: int | None
) -> int | None:
    if not token:
        return None
    call_pattern = re.compile(rf"(?<![A-Za-z0-9_$]){re.escape(token)}\s*\(")
    best: int | None = None
    best_distance = 10**9
    anchor = declaration_line or 1
    for index, line in enumerate(lines, start=1):
        if index == declaration_line:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue
        if call_pattern.search(line) is None:
            continue
        distance = abs(index - anchor)
        if distance < best_distance:
            best = index
            best_distance = distance
    return best


def _find_any_relation(
    lines: Sequence[str], declarations: Sequence[tuple[int, int, str]], anchor_line: int
) -> tuple[int, str] | None:
    by_token = {token: line for line, _indent, token in declarations}
    if not by_token:
        return None
    best: tuple[int, str] | None = None
    best_score = 10**9
    for index, line in enumerate(lines, start=1):
        for match in CALL_RE.finditer(line):
            token = match.group(1)
            if token in CALL_KEYWORDS or token not in by_token or by_token[token] == index:
                continue
            distance = abs(index - anchor_line) + abs(by_token[token] - anchor_line)
            if distance < best_score:
                best = (index, token)
                best_score = distance
    return best


def _route_entry_line(lines: Sequence[str], critical_line: int) -> int | None:
    route_re = re.compile(
        r"\b(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|all)\s*\(|@(?:router|app)\.(?:get|post|put|delete|patch)"
    )
    best: int | None = None
    for index, line in enumerate(lines, start=1):
        if index > critical_line:
            break
        if route_re.search(line):
            best = index
    return best


def _load_training_path_hints(public_dataset_root: Path) -> dict[str, Counter[str]]:
    train_path = public_dataset_root / "train.jsonl"
    result: dict[str, Counter[str]] = {}
    if not train_path.exists():
        return result
    with train_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            repo = item.get("task", {}).get("repo_url")
            if not isinstance(repo, str):
                continue
            counter = result.setdefault(repo, Counter())
            for advisory in item.get("gold", {}).get("advisories", []):
                if not isinstance(advisory, Mapping):
                    continue
                for entry in advisory.get("verified_entries", []):
                    if not isinstance(entry, Mapping):
                        continue
                    for key in ("entry_point", "critical_operation"):
                        node = entry.get(key)
                        if isinstance(node, Mapping):
                            path = node.get("file")
                            if isinstance(path, str) and path:
                                counter[path] += 1
    return result


def _scan_tree_for_plan(
    *,
    task_id: str,
    split: Literal["test", "train"],
    repo_url: str,
    tree: Path,
    inventory: Sequence[str],
    training_hints: Mapping[str, Counter[str]],
) -> TaskPlan | None:
    repo_hint_paths = training_hints.get(repo_url, Counter())
    hits: list[LocalHit] = []
    for rel, path, _size in _iter_scannable_files(tree, inventory):
        text = _read_text(path)
        if text is None:
            continue
        lines = text.splitlines()
        declarations = _declarations(lines)
        pscore = _path_score(rel, repo_hint_paths)
        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "*")):
                continue
            import_like = (
                stripped.startswith("import ")
                or stripped.startswith("from ")
                or stripped.startswith("const ")
                and "require(" in stripped
            )
            for pattern in PATTERNS:
                if pattern.query not in line:
                    continue
                declaration = _nearest_declaration(lines, declarations, line_number)
                declaration_line: int | None = None
                declaration_token: str | None = None
                if declaration is not None:
                    declaration_line, declaration_token = declaration
                relation_line = _find_relation_line(lines, declaration_token, declaration_line)
                relation_token = declaration_token if relation_line is not None else None
                if relation_line is None:
                    fallback = _find_any_relation(lines, declarations, line_number)
                    if fallback is not None:
                        relation_line, relation_token = fallback
                route_line = _route_entry_line(lines, line_number)
                entry_line = route_line or declaration_line
                score = pattern.weight + pscore + _context_score(line)
                if relation_line is not None:
                    score += 45
                if entry_line is not None:
                    score += 25
                if route_line is not None:
                    score += 25
                if rel in repo_hint_paths:
                    score += 30
                if import_like:
                    score -= 120
                if pattern.query in {"open(", "query(", "execute(", "resolve("} and pscore < 20:
                    score -= 35
                hits.append(
                    LocalHit(
                        path=rel,
                        line=line_number,
                        query=pattern.query,
                        token=pattern.token,
                        score=score,
                        declaration_line=declaration_line,
                        declaration_token=declaration_token,
                        relation_line=relation_line,
                        relation_token=relation_token,
                        entry_line=entry_line,
                    )
                )
    if not hits:
        return None
    hits.sort(
        key=lambda item: (
            item.score,
            item.relation_line is not None,
            item.entry_line is not None,
            -item.line,
            item.path,
        ),
        reverse=True,
    )
    selected = hits[0]
    try:
        target_index = list(inventory).index(selected.path)
    except ValueError:
        return None
    inventory_cursor = (target_index // MAX_INVENTORY_BATCH) * MAX_INVENTORY_BATCH
    entry_line = selected.entry_line or selected.declaration_line or selected.line
    return TaskPlan(
        task_id=task_id,
        split=split,
        target_path=selected.path,
        target_index=target_index,
        inventory_cursor=inventory_cursor,
        critical_line=selected.line,
        critical_query=selected.query,
        critical_token=selected.token,
        entry_line=entry_line,
        entry_token=selected.declaration_token,
        relation_line=selected.relation_line,
        relation_token=selected.relation_token,
        score=selected.score,
    )


def _nodes(payload: Mapping[str, Any], type_name: str | None = None) -> list[Mapping[str, Any]]:
    catalog = payload.get("catalog", {})
    if not isinstance(catalog, Mapping):
        return []
    raw = catalog.get("nodes", [])
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return []
    result = [item for item in raw if isinstance(item, Mapping)]
    if type_name is not None:
        result = [item for item in result if item.get("type") == type_name]
    return result


def _relationships(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    catalog = payload.get("catalog", {})
    if not isinstance(catalog, Mapping):
        return []
    raw = catalog.get("relationships", [])
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return []
    return [item for item in raw if isinstance(item, Mapping)]


def _ref(node: Mapping[str, Any]) -> dict[str, str] | None:
    value = node.get("ref")
    if (
        isinstance(value, Mapping)
        and isinstance(value.get("artifact_id"), str)
        and isinstance(value.get("node_id"), str)
    ):
        return {"artifact_id": value["artifact_id"], "node_id": value["node_id"]}
    return None


def _same_ref(left: Mapping[str, str], right: Mapping[str, str]) -> bool:
    return (
        left.get("artifact_id") == right.get("artifact_id")
        and left.get("node_id") == right.get("node_id")
    )


def _fileref_for_path(payload: Mapping[str, Any], path: str) -> dict[str, str] | None:
    for node in _nodes(payload, "FIL"):
        if node.get("path") == path:
            return _ref(node)
    return None


def _mat_nodes_for(
    payload: Mapping[str, Any], *, path: str, query: str | None = None
) -> list[Mapping[str, Any]]:
    result = []
    for node in _nodes(payload, "MAT"):
        if node.get("path") != path:
            continue
        if query is not None and query not in str(node.get("excerpt", "")):
            continue
        result.append(node)
    return result


def _loc_nodes_for_line(
    payload: Mapping[str, Any], *, path: str, line: int
) -> list[Mapping[str, Any]]:
    return [
        node
        for node in _nodes(payload, "LOC")
        if node.get("path") == path and node.get("line") == line
    ]


def _loc_nodes_near_line(
    payload: Mapping[str, Any], *, path: str, line: int, radius: int = 6
) -> list[Mapping[str, Any]]:
    return [
        node
        for node in _nodes(payload, "LOC")
        if node.get("path") == path
        and isinstance(node.get("line"), int)
        and abs(int(node["line"]) - line) <= radius
    ]


def _lex_nodes_for_line(
    payload: Mapping[str, Any], *, path: str, line: int
) -> list[Mapping[str, Any]]:
    return [
        node
        for node in _nodes(payload, "LEX")
        if node.get("path") == path and node.get("line") == line
    ]


def _best_lex_ref(
    payload: Mapping[str, Any],
    *,
    path: str,
    line: int,
    token: str | None = None,
    kind_suffix: str | None = None,
) -> dict[str, str] | None:
    candidates = _lex_nodes_for_line(payload, path=path, line=line)
    if token is not None:
        exact = [node for node in candidates if node.get("token") == token]
        if exact:
            candidates = exact
    if kind_suffix is not None:
        kinded = [
            node
            for node in candidates
            if isinstance(node.get("kind"), str) and str(node["kind"]).endswith(kind_suffix)
        ]
        if kinded:
            candidates = kinded
    for node in candidates:
        ref = _ref(node)
        if ref is not None:
            return ref
    return None


def _best_source_ref(
    payload: Mapping[str, Any],
    *,
    path: str,
    line: int,
    token: str | None = None,
    prefer_declaration: bool = False,
) -> dict[str, str] | None:
    lex = _best_lex_ref(
        payload,
        path=path,
        line=line,
        token=token,
        kind_suffix="declaration" if prefer_declaration else None,
    )
    if lex is not None:
        return lex
    for node in _mat_nodes_for(payload, path=path):
        if node.get("line") == line:
            ref = _ref(node)
            if ref is not None:
                return ref
    for node in _loc_nodes_for_line(payload, path=path, line=line):
        ref = _ref(node)
        if ref is not None:
            return ref
    for node in _loc_nodes_near_line(payload, path=path, line=line):
        ref = _ref(node)
        if ref is not None:
            return ref
    return None


def _has_structure_near(payload: Mapping[str, Any], *, path: str, line: int, token: str | None = None) -> bool:
    for node in _nodes(payload, "LEX"):
        if node.get("path") != path or not isinstance(node.get("line"), int):
            continue
        if abs(int(node["line"]) - line) > 8:
            continue
        if token is None or node.get("token") == token:
            return True
    return False


def _read_locations_from_matches(
    matches: Sequence[Mapping[str, Any]],
    *,
    preferred_lines: Sequence[int],
    max_items: int = 2,
) -> list[dict[str, Any]]:
    selected: list[Mapping[str, Any]] = []
    used: set[tuple[str, str]] = set()
    line_set = set(preferred_lines)
    for node in matches:
        if node.get("line") in line_set:
            ref = _ref(node)
            if ref is None:
                continue
            key = (ref["artifact_id"], ref["node_id"])
            if key not in used:
                selected.append(node)
                used.add(key)
    for node in matches:
        if len(selected) >= max_items:
            break
        ref = _ref(node)
        if ref is None:
            continue
        key = (ref["artifact_id"], ref["node_id"])
        if key in used:
            continue
        selected.append(node)
        used.add(key)
    result: list[dict[str, Any]] = []
    for node in selected[:max_items]:
        ref = _ref(node)
        if ref is None:
            continue
        result.append(
            {
                **ref,
                "context_before": 12,
                "context_after": 12,
            }
        )
    return result


def _structure_source_for_line(
    payload: Mapping[str, Any], *, path: str, line: int
) -> dict[str, str] | None:
    for node in _loc_nodes_for_line(payload, path=path, line=line):
        ref = _ref(node)
        if ref is not None:
            return ref
    near = _loc_nodes_near_line(payload, path=path, line=line, radius=12)
    for node in near:
        ref = _ref(node)
        if ref is not None:
            return ref
    return None


def _structure_inputs(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    seen: set[str] = set()
    for node in _nodes(payload, "LEX"):
        ref = _ref(node)
        if ref is None:
            continue
        artifact_id = ref["artifact_id"]
        if artifact_id in seen:
            continue
        seen.add(artifact_id)
        refs.append(ref)
        if len(refs) >= 16:
            break
    return refs


def _relationship_ref(rel: Mapping[str, Any]) -> dict[str, str] | None:
    value = rel.get("ref")
    if (
        isinstance(value, Mapping)
        and isinstance(value.get("artifact_id"), str)
        and isinstance(value.get("node_id"), str)
    ):
        return {"artifact_id": value["artifact_id"], "node_id": value["node_id"]}
    return None


def _select_relationship(payload: Mapping[str, Any], relation_token: str | None) -> Mapping[str, Any] | None:
    relationships = _relationships(payload)
    if relation_token is not None:
        for rel in relationships:
            if rel.get("symbol") == relation_token and _relationship_ref(rel) is not None:
                return rel
    for rel in relationships:
        if _relationship_ref(rel) is not None:
            return rel
    return None


def _link_result_is_exhausted(payload: Mapping[str, Any]) -> bool:
    last_result = payload.get("last_result")
    if not isinstance(last_result, Mapping) or last_result.get("action") != "link":
        return False
    summary = last_result.get("summary")
    return (
        isinstance(summary, Mapping)
        and summary.get("complete") is True
        and summary.get("next_cursor") is None
    )


def _next_link_cursor(payload: Mapping[str, Any]) -> int | None:
    last_result = payload.get("last_result")
    if not isinstance(last_result, Mapping) or last_result.get("action") != "link":
        return None
    summary = last_result.get("summary")
    if not isinstance(summary, Mapping):
        return None
    cursor = summary.get("next_cursor")
    if type(cursor) is int and cursor >= 0:
        return cursor
    return None


def _last_result_action(payload: Mapping[str, Any]) -> str | None:
    last_result = payload.get("last_result")
    if not isinstance(last_result, Mapping):
        return None
    action = last_result.get("action")
    return action if isinstance(action, str) else None


def _dedupe_refs(refs: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for ref in refs:
        if not any(_same_ref(ref, existing) for existing in result):
            result.append(ref)
    return result


def _build_select_response(payload: Mapping[str, Any], plan: TaskPlan) -> dict[str, Any] | None:
    relationship = _select_relationship(payload, plan.relation_token)
    if relationship is None:
        return None
    rel_ref = _relationship_ref(relationship)
    if rel_ref is None:
        return None
    entry_ref = _best_source_ref(
        payload,
        path=plan.target_path,
        line=plan.entry_line,
        token=plan.entry_token,
        prefer_declaration=True,
    )
    critical_ref = _best_source_ref(
        payload,
        path=plan.target_path,
        line=plan.critical_line,
        token=plan.critical_token,
    )
    if entry_ref is None or critical_ref is None:
        return None
    trace_refs: list[dict[str, str]] = []
    for key in ("call_ref", "declaration_ref"):
        value = relationship.get(key)
        if (
            isinstance(value, Mapping)
            and isinstance(value.get("artifact_id"), str)
            and isinstance(value.get("node_id"), str)
        ):
            trace_refs.append({"artifact_id": value["artifact_id"], "node_id": value["node_id"]})
    if plan.relation_line is not None:
        rel_line_ref = _best_source_ref(
            payload,
            path=plan.target_path,
            line=plan.relation_line,
            token=plan.relation_token,
        )
        if rel_line_ref is not None:
            trace_refs.append(rel_line_ref)
    if not trace_refs:
        trace_refs.append(entry_ref)
    return {
        "action": "select",
        "candidates": [
            {
                "entry": entry_ref,
                "critical": critical_ref,
                "trace": _dedupe_refs(trace_refs),
                "relationships": [rel_ref],
            }
        ],
    }


def _build_d3_response(payload: Mapping[str, Any]) -> dict[str, Any]:
    contexts = payload.get("contexts", [])
    reviews: list[dict[str, Any]] = []
    criteria = payload.get("request", {}).get("criteria", [])
    if (
        not isinstance(criteria, Sequence)
        or isinstance(criteria, (str, bytes))
        or not criteria
    ):
        criteria = [
            "entry_role",
            "critical_role",
            "trace_continuity",
            "counterevidence_status",
        ]
    iterable_contexts = (
        contexts
        if isinstance(contexts, Sequence) and not isinstance(contexts, (str, bytes))
        else []
    )
    for context in iterable_contexts:
        if not isinstance(context, Mapping):
            continue
        nodes = [node for node in context.get("nodes", []) if isinstance(node, Mapping)]
        by_role: dict[str, list[dict[str, str]]] = {}
        trace_refs: list[dict[str, str]] = []
        for node in nodes:
            role = node.get("role")
            ref = {
                "artifact_id": node.get("artifact_id"),
                "node_id": node.get("node_id"),
            }
            if not isinstance(ref["artifact_id"], str) or not isinstance(ref["node_id"], str):
                continue
            if isinstance(role, str):
                by_role.setdefault(role, []).append(ref)
                if role.startswith("trace."):
                    trace_refs.append(ref)
        criterion_items: list[dict[str, Any]] = []
        for criterion in criteria:
            if criterion == "entry_role":
                selections = by_role.get("entry_role", [])
            elif criterion == "critical_role":
                selections = by_role.get("critical_role", [])
            elif criterion == "trace_continuity":
                selections = trace_refs or by_role.get("entry_role", []) + by_role.get("critical_role", [])
            elif criterion == "counterevidence_status":
                selections = by_role.get("critical_role", []) or by_role.get("entry_role", [])
            else:
                selections = []
            criterion_items.append(
                {
                    "criterion": criterion,
                    "assessment": "supported" if selections else "insufficient",
                    "selections": _dedupe_refs(selections),
                }
            )
        candidate_id = context.get("candidate_id")
        if isinstance(candidate_id, str):
            reviews.append({"candidate_id": candidate_id, "criteria": criterion_items})
    return {"reviews": reviews}


def _build_d2_response(payload: Mapping[str, Any], plan: TaskPlan) -> dict[str, Any] | None:
    allowed = payload.get("allowed_actions", [])
    phase = payload.get("phase")
    if not isinstance(allowed, Sequence) or isinstance(allowed, (str, bytes)):
        return None
    allowed_set = set(str(item) for item in allowed if isinstance(item, str))
    last_action = _last_result_action(payload)

    target_ref = _fileref_for_path(payload, plan.target_path)
    if target_ref is None and "inventory" in allowed_set:
        inventory_nodes = _nodes(payload, "FIL")
        if inventory_nodes:
            available_paths = [
                str(node.get("path"))
                for node in inventory_nodes
                if isinstance(node.get("path"), str)
            ]
            if available_paths:
                after_target = sum(1 for path in available_paths if path < plan.target_path)
                if after_target == len(available_paths):
                    cursor = plan.inventory_cursor + MAX_INVENTORY_BATCH
                else:
                    cursor = max(0, plan.inventory_cursor - MAX_INVENTORY_BATCH)
                if cursor == plan.inventory_cursor:
                    return None
                return {
                    "action": "inventory",
                    "cursor": cursor,
                    "limit": MAX_INVENTORY_BATCH,
                }
        return {
            "action": "inventory",
            "cursor": plan.inventory_cursor,
            "limit": MAX_INVENTORY_BATCH,
        }

    if target_ref is not None:
        critical_matches = _mat_nodes_for(
            payload, path=plan.target_path, query=plan.critical_query
        )
        if not critical_matches and "search" in allowed_set:
            return {
                "action": "search",
                "cursor": 0,
                "files": [target_ref],
                "limit": MAX_SEARCH_RESULTS,
                "query": plan.critical_query,
            }
        if critical_matches and not _loc_nodes_near_line(
            payload, path=plan.target_path, line=plan.critical_line, radius=4
        ) and last_action != "read" and "read" in allowed_set:
            locations = _read_locations_from_matches(
                critical_matches,
                preferred_lines=[plan.critical_line, plan.entry_line],
                max_items=2,
            )
            if locations:
                return {"action": "read", "locations": locations[:MAX_READ_SPANS]}

    if phase == "SCOUT" and "advance" in allowed_set:
        if (
            last_action == "read"
            or _loc_nodes_near_line(
                payload, path=plan.target_path, line=plan.critical_line, radius=8
            )
        ):
            return {"action": "advance"}

    if phase == "ANALYZE":
        if plan.relation_query and target_ref is not None:
            relation_matches = _mat_nodes_for(
                payload, path=plan.target_path, query=plan.relation_query
            )
            preferred_relation_lines = [
                line
                for line in (plan.relation_line, plan.entry_line)
                if line is not None
            ]
            if not relation_matches and "search" in allowed_set:
                return {
                    "action": "search",
                    "cursor": 0,
                    "files": [target_ref],
                    "limit": MAX_SEARCH_RESULTS,
                    "query": plan.relation_query,
                }
            if relation_matches and last_action != "read" and "read" in allowed_set:
                missing_relation_context = any(
                    not _loc_nodes_near_line(
                        payload, path=plan.target_path, line=line, radius=4
                    )
                    for line in preferred_relation_lines
                )
                if missing_relation_context:
                    locations = _read_locations_from_matches(
                        relation_matches,
                        preferred_lines=preferred_relation_lines,
                        max_items=2,
                    )
                    if locations:
                        return {"action": "read", "locations": locations[:MAX_READ_SPANS]}

        structure_targets: list[tuple[int, str | None]] = [
            (plan.critical_line, plan.critical_token),
            (plan.entry_line, plan.entry_token),
        ]
        if plan.relation_line is not None:
            structure_targets.append((plan.relation_line, plan.relation_token))
        for line, token in structure_targets:
            if line is None:
                continue
            if _has_structure_near(payload, path=plan.target_path, line=line):
                continue
            source = _structure_source_for_line(payload, path=plan.target_path, line=line)
            if source is not None and "structure" in allowed_set:
                return {
                    "action": "structure",
                    "cursor": 0,
                    "limit": MAX_STRUCTURE_RESULTS,
                    "source": source,
                }

        selected_relationship = _select_relationship(payload, plan.relation_token)
        if selected_relationship is None and _link_result_is_exhausted(payload) and "defer" in allowed_set:
            return {
                "action": "defer",
                "missing_information": [
                    "source relationship search returned no selectable relationship for the planned entry and critical refs"
                ],
                "reason_code": "no_selectable_relationship",
            }
        if selected_relationship is None and "link" in allowed_set:
            next_cursor = _next_link_cursor(payload)
            structures = _structure_inputs(payload)
            if structures:
                return {
                    "action": "link",
                    "cursor": 0 if next_cursor is None else next_cursor,
                    "limit": MAX_LINK_RESULTS,
                    "structures": structures,
                }

        select_response = _build_select_response(payload, plan)
        if select_response is not None and "select" in allowed_set:
            return select_response

        if "defer" in allowed_set:
            return {
                "action": "defer",
                "missing_information": [
                    "offline replay helper could not assemble selectable structure and relationship evidence"
                ],
                "reason_code": "insufficient_offline_evidence",
            }

    return None


def _next_response(pending: ReplayAuthoringPendingRequestV1, plan: TaskPlan) -> dict[str, Any]:
    payload = pending.payload
    if pending.role == "d3":
        return _build_d3_response(payload)
    response = _build_d2_response(payload, plan)
    if response is None:
        raise RuntimeError(
            f"no_offline_response: task={plan.task_id} phase={payload.get('phase')} "
            f"allowed={payload.get('allowed_actions')}"
        )
    return response


def _copy_final_if_needed(src: Path, dst: Path) -> None:
    if dst.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def _fast_append_response(
    *,
    draft_root: Path,
    pending: ReplayAuthoringPendingRequestV1,
    body: Mapping[str, Any],
) -> None:
    filename = "d2.json" if pending.role == "d2" else "d3.json"
    target = draft_root / filename
    current = OciReplayConfigV1.from_bytes(target.read_bytes())
    entry = ReplayResponse(
        stage=pending.stage,
        request=pending.payload,
        response=body,
    )
    replacement = OciReplayConfigV1(
        task_id=current.task_id,
        role=current.role,
        responses=(*current.responses, entry),
    )
    _atomic_write(target, replacement.to_bytes())


def _run_one_task(
    *,
    split: Literal["test", "train"],
    task_entry: Mapping[str, Any],
    index_root: Path,
    runtime_root: Path,
    training_hints: Mapping[str, Counter[str]],
    attempt_suffix: str,
    max_steps: int,
    overwrite_draft: bool,
    publish: bool,
    trusted_append: bool,
) -> dict[str, Any]:
    task_id = str(task_entry["task_id"])
    final_root = runtime_root / "authoring" / "final" / split / task_id
    if final_root.exists():
        return {"task_id": task_id, "status": "skipped_final_exists", "final_root": str(final_root)}

    task_file = index_root / str(task_entry["task_file"])
    sealed_bundle = runtime_root / "sealed" / split / "bundles" / task_id
    tree = sealed_bundle / "tree"
    if not tree.is_dir():
        return {"task_id": task_id, "status": "failed", "code": "sealed_tree_missing"}
    inventory = _iter_regular_files(tree)
    task_json = _load_json(task_file)
    plan = _scan_tree_for_plan(
        task_id=task_id,
        split=split,
        repo_url=str(task_json.get("repo_url", "")),
        tree=tree,
        inventory=inventory,
        training_hints=training_hints,
    )
    if plan is None:
        return {"task_id": task_id, "status": "failed", "code": "no_local_plan"}
    plan_record = {
        "path": plan.target_path,
        "target_index": plan.target_index,
        "inventory_cursor": plan.inventory_cursor,
        "critical_line": plan.critical_line,
        "critical_query": plan.critical_query,
        "entry_line": plan.entry_line,
        "relation_line": plan.relation_line,
        "relation_token": plan.relation_token,
        "score": plan.score,
    }

    draft_root = runtime_root / "authoring" / "drafts" / split / f"{task_id}-{attempt_suffix}"
    pending_dir = runtime_root / "authoring" / "pending" / split / f"{task_id}-{attempt_suffix}"
    bodies_dir = runtime_root / "authoring" / "bodies" / split / f"{task_id}-{attempt_suffix}"
    summary_dir = runtime_root / "authoring" / "summaries" / split / f"{task_id}-{attempt_suffix}"
    _write_json(summary_dir / "plan.json", plan_record)
    print(
        json.dumps(
            {"task_id": task_id, "status": "plan", **plan_record},
            ensure_ascii=False,
            sort_keys=True,
        ),
        flush=True,
    )
    if overwrite_draft and draft_root.exists():
        raise RuntimeError(f"refusing destructive overwrite of existing draft: {draft_root}")
    if not draft_root.exists():
        initialize_replay_authoring_v1(task_id, draft_root)

    split_index = _load_json(index_root / "index.json")
    key_id = str(split_index["sealed_batch_key_id"])
    key_file = (
        runtime_root
        / "control"
        / "secrets"
        / ("issue60-test-source-seal.key" if split == "test" else "issue60-train-source-seal.key")
    )
    key = read_attestation_key_file_v1(key_file)
    try:
        task = read_pinned_authoring_task_v1(
            task_file,
            expected_wire_sha256=str(task_entry["task_wire_sha256"]),
        )
        steps = 0
        while steps < max_steps:
            step = inspect_replay_authoring_v1(
                task,
                sealed_bundle,
                draft_root,
                attestation_key=key,
                expected_key_id=key_id,
            )
            if isinstance(step, ReplayAuthoringSummaryV1):
                if step.status == "closed" and publish:
                    published = publish_replay_authoring_v1(
                        task,
                        sealed_bundle,
                        draft_root,
                        final_root,
                        attestation_key=key,
                        expected_key_id=key_id,
                    )
                    _write_json(summary_dir / "published.json", published.to_dict())
                    return {
                        "task_id": task_id,
                        "status": "published",
                        "steps": steps,
                        "final_root": str(final_root),
                        "candidate_count": published.candidate_count,
                        "finding_count": published.finding_count,
                        "d2_response_count": published.d2_response_count,
                        "d3_response_count": published.d3_response_count,
                        "plan": {
                            "path": plan.target_path,
                            "line": plan.critical_line,
                            "query": plan.critical_query,
                            "score": plan.score,
                        },
                    }
                _write_json(summary_dir / f"{step.status}.json", step.to_dict())
                return {"task_id": task_id, "status": step.status, "steps": steps}

            if not isinstance(step, ReplayAuthoringPendingRequestV1):
                return {"task_id": task_id, "status": "failed", "code": "unexpected_step_type"}
            steps += 1
            _write_json(pending_dir / f"{steps:04d}.json", step.to_dict())
            body = _next_response(step, plan)
            _write_json(bodies_dir / f"{steps:04d}.json", body)
            print(
                json.dumps(
                    {
                        "task_id": task_id,
                        "status": "step",
                        "step": steps,
                        "role": step.role,
                        "stage": step.stage,
                        "phase": step.payload.get("phase"),
                        "action": body.get("action"),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                flush=True,
            )
            response = ReplayAuthoringResponseV1.from_pending(step, body)
            if trusted_append:
                next_step = append_replay_authoring_response_v1(
                    task,
                    sealed_bundle,
                    draft_root,
                    response,
                    attestation_key=key,
                    expected_key_id=key_id,
                )
                if isinstance(next_step, ReplayAuthoringSummaryV1) and next_step.status == "closed":
                    if publish:
                        published = publish_replay_authoring_v1(
                            task,
                            sealed_bundle,
                            draft_root,
                            final_root,
                            attestation_key=key,
                            expected_key_id=key_id,
                        )
                        _write_json(summary_dir / "published.json", published.to_dict())
                        return {
                            "task_id": task_id,
                            "status": "published",
                            "steps": steps,
                            "final_root": str(final_root),
                            "candidate_count": published.candidate_count,
                            "finding_count": published.finding_count,
                            "d2_response_count": published.d2_response_count,
                            "d3_response_count": published.d3_response_count,
                            "plan": {
                                "path": plan.target_path,
                                "line": plan.critical_line,
                                "query": plan.critical_query,
                                "score": plan.score,
                            },
                        }
            else:
                _fast_append_response(draft_root=draft_root, pending=step, body=response.response)
        return {
            "task_id": task_id,
            "status": "failed",
            "code": "step_limit_exceeded",
            "steps": steps,
        }
    except ReplayAuthoringError as error:
        return {
            "task_id": task_id,
            "status": "failed",
            "code": error.code,
            "message": str(error),
            "committed": error.committed,
        }
    except Exception as error:
        return {
            "task_id": task_id,
            "status": "failed",
            "code": error.__class__.__name__,
            "message": str(error),
        }
    finally:
        zero_secret_buffer_v1(key)


def _select_tasks(index: Mapping[str, Any], *, start_after: str | None, limit: int | None) -> list[Mapping[str, Any]]:
    raw = index.get("tasks", [])
    if not isinstance(raw, list):
        raise RuntimeError("index tasks field is invalid")
    tasks = [item for item in raw if isinstance(item, Mapping)]
    if start_after:
        seen = False
        selected: list[Mapping[str, Any]] = []
        for item in tasks:
            if seen:
                selected.append(item)
            elif item.get("task_id") == start_after:
                seen = True
        tasks = selected
    if limit is not None:
        tasks = tasks[:limit]
    return tasks


def run(args: argparse.Namespace) -> int:
    runtime_root = Path(args.runtime_root)
    public_dataset_root = Path(args.public_dataset_root)
    split = args.split
    index_root = runtime_root / "authoring-inputs" / split
    index = _load_json(index_root / "index.json")
    training_hints = _load_training_path_hints(public_dataset_root)
    tasks = _select_tasks(index, start_after=args.start_after, limit=args.limit)
    started = time.time()
    results = []
    for task_entry in tasks:
        result = _run_one_task(
            split=split,
            task_entry=task_entry,
            index_root=index_root,
            runtime_root=runtime_root,
            training_hints=training_hints,
            attempt_suffix=args.attempt_suffix,
            max_steps=args.max_steps,
            overwrite_draft=args.overwrite_draft,
            publish=not args.no_publish,
            trusted_append=args.trusted_append,
        )
        results.append(result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
        if result.get("status") == "failed" and args.stop_on_failure:
            break
    summary = {
        "kind": "vulngym.offline-authoring-batch-summary.v1",
        "split": split,
        "requested": len(tasks),
        "published": sum(1 for item in results if item.get("status") == "published"),
        "skipped_final_exists": sum(1 for item in results if item.get("status") == "skipped_final_exists"),
        "failed": sum(1 for item in results if item.get("status") == "failed"),
        "elapsed_seconds": round(time.time() - started, 3),
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True), flush=True)
    return 0 if summary["failed"] == 0 else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", default=str(DEFAULT_RUNTIME_ROOT))
    parser.add_argument("--public-dataset-root", default=str(DEFAULT_PUBLIC_DATASET_ROOT))
    parser.add_argument("--split", choices=("test", "train"), default="test")
    parser.add_argument("--limit", type=int, default=1)
    parser.add_argument("--start-after")
    parser.add_argument("--attempt-suffix", default="auto1")
    parser.add_argument("--max-steps", type=int, default=24)
    parser.add_argument("--stop-on-failure", action="store_true", default=True)
    parser.add_argument("--keep-going", dest="stop_on_failure", action="store_false")
    parser.add_argument("--overwrite-draft", action="store_true")
    parser.add_argument("--no-publish", action="store_true")
    parser.add_argument(
        "--trusted-append",
        action="store_true",
        help="Use the slower prospective append API for every response instead of fast transcript writes.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    os.environ.setdefault("TEMP", str(DEFAULT_RUNTIME_ROOT / "tmp"))
    os.environ.setdefault("TMP", str(DEFAULT_RUNTIME_ROOT / "tmp"))
    parser = build_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
