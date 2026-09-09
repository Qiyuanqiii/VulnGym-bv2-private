"""Pure, bounded follow-up source selection; no file access or semantic claims.

The controller supplies issued choices and already-authorized source blobs.
Literal occurrences are retrieval hints, never proof of a call relationship.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from itertools import islice
import re
from typing import Any

MAX_FILES = 8
MAX_CHARS = 8_000
MAX_BLOCKS = 4

_MAX_REQUESTS = 2
_MAX_REASON_CHARS = 200
_MAX_ID_CHARS = 256
_MAX_CONTRACT_IDS = 1_024
_MAX_EXISTING_BLOCKS = 256
_MAX_PATH_CHARS = 4_096
_MAX_SYMBOL_CHARS = 200
_MAX_SOURCE_CHARS = 256 * 1_024
_MAX_SOURCE_LINES = 20_000
_MAX_MATCH_LINES = 16
_WINDOW_RADIUS = 60
_REFERENCE_RADIUS = 12
_KINDS = ("window", "references")
_LINE_ENDINGS = ("\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")


def _sequence(value: Any, maximum: int, label: str) -> Sequence[Any]:
    if (not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray))
            or len(value) > maximum):
        raise ValueError(label)
    return value


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= _MAX_ID_CHARS and bool(value.strip())


def request_contract(candidate_ids: Sequence[str], rounds_remaining: int = 1) -> dict[str, Any]:
    """Describe the optional exact model response, with one follow-up round."""
    ids = _sequence(candidate_ids, _MAX_CONTRACT_IDS, "invalid_context_candidate_ids")
    if any(not _identifier(item) for item in ids) or len(set(ids)) != len(ids):
        raise ValueError("invalid_context_candidate_ids")
    if type(rounds_remaining) is not int or rounds_remaining not in (0, 1):
        raise ValueError("invalid_context_rounds_remaining")
    return {
        "contract_version": 1,
        "optional": True,
        "action": "request_context",
        "rounds_remaining": rounds_remaining,
        "candidate_ids": list(ids),
        "allowed_kinds": list(_KINDS),
        "min_requests": 1,
        "max_requests": _MAX_REQUESTS,
        "unique_by": ["candidate_id", "kind"],
        "max_reason_chars": _MAX_REASON_CHARS,
        "reason_must_be_nonempty": True,
        "extra_fields_allowed": False,
        "response_shape": {
            "action": "request_context",
            "requests": [{"candidate_id": "<issued candidate ID>",
                          "kind": "window|references", "reason": "<nonempty reason>"}],
        },
        "limits": {
            "max_files": MAX_FILES, "max_new_chars": MAX_CHARS, "max_new_blocks": MAX_BLOCKS,
            "window_radius_lines": _WINDOW_RADIUS,
            "reference_radius_lines": _REFERENCE_RADIUS,
            "max_scanned_chars_per_file": _MAX_SOURCE_CHARS,
            "max_scanned_lines_per_file": _MAX_SOURCE_LINES,
            "max_matching_lines_per_request": _MAX_MATCH_LINES,
        },
        "scope": "supplied_declared_path_blobs_only; no arbitrary paths or tools",
        "references_mean": "literal_symbol_token_occurrences_not_verified_relationships",
        "coverage": "new_complete_lines_only; bounded_selection_not_exhaustive",
    }


def validate_requests(
    response: Any, choices: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, str]]:
    """Accept only the exact request shape and already-issued candidate IDs."""
    if (not isinstance(response, Mapping) or len(response) != 2
            or set(response) != {"action", "requests"}
            or response["action"] != "request_context" or not isinstance(choices, Mapping)):
        raise ValueError("invalid_context_request")
    requests = _sequence(response["requests"], _MAX_REQUESTS, "invalid_context_requests_count")
    if not requests:
        raise ValueError("invalid_context_requests_count")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for request in requests:
        if (not isinstance(request, Mapping) or len(request) != 3
                or set(request) != {"candidate_id", "kind", "reason"}):
            raise ValueError("invalid_context_request_fields")
        identifier, kind, reason = request["candidate_id"], request["kind"], request["reason"]
        if not _identifier(identifier) or identifier not in choices:
            raise ValueError("unknown_context_candidate")
        if not isinstance(kind, str) or kind not in _KINDS:
            raise ValueError("invalid_context_request_kind")
        if (not isinstance(reason, str) or not 0 < len(reason) <= _MAX_REASON_CHARS
                or not reason.strip()):
            raise ValueError("invalid_context_request_reason")
        identity = (identifier, kind)
        if identity in seen:
            raise ValueError("duplicate_context_request")
        seen.add(identity)
        choice = choices[identifier]
        location = choice.get("location") if isinstance(choice, Mapping) else None
        if (not isinstance(location, Mapping)
                or not isinstance(location.get("file"), str)
                or not 0 < len(location["file"]) <= _MAX_PATH_CHARS
                or type(location.get("line")) is not int or location["line"] < 1
                or not isinstance(location.get("code"), str)):
            raise ValueError("invalid_context_candidate_location")
        result.append({"candidate_id": identifier, "kind": kind, "reason": reason})
    return result


def _source_lines(text: str) -> list[str]:
    """Read a bounded prefix without mistaking its cut-off tail for a full line."""
    prefix = text[:_MAX_SOURCE_CHARS]
    lines = prefix.splitlines()
    if len(text) > len(prefix) and prefix and not prefix.endswith(_LINE_ENDINGS):
        lines.pop()
    return lines[:_MAX_SOURCE_LINES]


def _covered_lines(
    existing: Sequence[Mapping[str, Any]], sources: Mapping[str, list[str]],
) -> dict[str, set[int]]:
    covered: dict[str, set[int]] = {path: set() for path in sources}
    for block in existing:
        if not isinstance(block, Mapping):
            raise ValueError("invalid_existing_context_block")
        path, first, last, text = (block.get(key) for key in ("file", "line_start", "line_end", "text"))
        if (not isinstance(path, str) or not 0 < len(path) <= _MAX_PATH_CHARS
                or type(first) is not int or type(last) is not int
                or not 1 <= first <= last or not isinstance(text, str)):
            raise ValueError("invalid_existing_context_block")
        if path not in sources or block.get("anchor_line_complete") is False:
            continue
        lines = sources[path]
        # Metadata alone cannot establish coverage: the complete source lines
        # must match the supplied block, including any blank final source line.
        if last <= len(lines) and text == "\n".join(lines[first - 1:last]):
            covered[path].update(range(first, last + 1))
    return covered


def collect_blocks(
    requests: Sequence[Mapping[str, Any]], choices: Mapping[str, Mapping[str, Any]],
    blobs: Mapping[str, str], existing_blocks: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return up to four new whole-line blocks from bounded supplied blobs.

    Windows cover the candidate anchor +/-60 lines. References search escaped
    literal symbol tokens, candidate file first, with +/-12 lines per matching
    line. Neither operation parses, executes, or establishes source semantics.
    Scans consider at most eight files and a bounded complete-line prefix each.
    Lines exceeding the remaining character budget are skipped, never cut.
    """
    requests = _sequence(requests, _MAX_REQUESTS, "invalid_context_requests_count")
    rows = validate_requests({"action": "request_context", "requests": list(requests)}, choices)
    existing = _sequence(existing_blocks, _MAX_EXISTING_BLOCKS, "invalid_existing_context_blocks")
    if not isinstance(blobs, Mapping):
        raise ValueError("invalid_context_blobs")

    # Candidate files get priority even when supplied after many other paths.
    paths = list(dict.fromkeys(choices[row["candidate_id"]]["location"]["file"] for row in rows))
    if any(row["kind"] == "references" for row in rows):
        for path in islice(blobs, MAX_FILES):
            if not isinstance(path, str) or not 0 < len(path) <= _MAX_PATH_CHARS:
                raise ValueError("invalid_context_blob_path")
            if path not in paths and len(paths) < MAX_FILES:
                paths.append(path)
    sources: dict[str, list[str]] = {}
    for path in paths[:MAX_FILES]:
        if path not in blobs:
            continue
        text = blobs[path]
        if not isinstance(text, str):
            raise ValueError("invalid_context_blob_text")
        sources[path] = _source_lines(text)
    covered = _covered_lines(existing, sources)
    blocks: list[dict[str, Any]] = []
    used_chars = 0

    def append_window(path: str, anchor: int, radius: int, row: Mapping[str, str]) -> None:
        nonlocal used_chars
        lines = sources.get(path, [])
        if not 1 <= anchor <= len(lines):
            return
        first, last = max(1, anchor - radius), min(len(lines), anchor + radius)
        pending: list[str] = []
        pending_start = first

        def flush() -> None:
            nonlocal used_chars
            if not pending:
                return
            if not any(line.strip() for line in pending):
                used_chars -= len("\n".join(pending))
                pending.clear()
                return
            blocks.append({
                "file": path, "line_start": pending_start,
                "line_end": pending_start + len(pending) - 1,
                "text": "\n".join(pending), "candidate_ids": [row["candidate_id"]],
                "kind": row["kind"], "relationship_verified": False,
            })
            pending.clear()

        for number in range(first, last + 1):
            if len(blocks) >= MAX_BLOCKS:
                break
            if number in covered[path]:
                flush()
                continue
            line = lines[number - 1]
            added = len(line) + bool(pending)
            if used_chars + added > MAX_CHARS:
                flush()
                # A preceding block needs no newline separator in the next
                # block. Retry this complete line against the true remainder.
                if len(blocks) >= MAX_BLOCKS or used_chars + len(line) > MAX_CHARS:
                    continue
            if not pending:
                pending_start = number
            used_chars += len(line) + bool(pending)
            pending.append(line)
            covered[path].add(number)
        flush()

    for row in rows:
        if len(blocks) >= MAX_BLOCKS:
            break
        choice = choices[row["candidate_id"]]
        path = choice["location"]["file"]
        if row["kind"] == "window":
            append_window(path, choice["location"]["line"], _WINDOW_RADIUS, row)
            continue
        symbol = choice.get("symbol")
        if not isinstance(symbol, str) or not 0 < len(symbol) <= _MAX_SYMBOL_CHARS or not symbol.strip():
            continue
        # Dollar signs count as identifier characters for common source
        # languages. Escape symbols so punctuation has no regex semantics.
        token = re.compile(r"(?<![\w$])" + re.escape(symbol) + r"(?![\w$])")
        reference_paths = [path] if path in sources else []
        reference_paths.extend(other for other in sources if other != path)
        matches = 0
        for source_path in reference_paths:
            for number, line in enumerate(sources[source_path], 1):
                if len(blocks) >= MAX_BLOCKS or matches >= _MAX_MATCH_LINES:
                    break
                if token.search(line) is not None:
                    matches += 1
                    append_window(source_path, number, _REFERENCE_RADIUS, row)
            if len(blocks) >= MAX_BLOCKS or matches >= _MAX_MATCH_LINES:
                break
    return blocks
