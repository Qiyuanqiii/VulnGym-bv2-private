"""Pure bounded context selection and model self-reported defer validation.

No file access, model calls, candidate issuance or semantic verdicts live here.
Source text must come from the controller's pinned, declared-path Git reader.
"""
from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
import re
from typing import Any

MAX_SOURCE_FILES = 8
MAX_SOURCE_BLOCKS = 12
MAX_SOURCE_CHARS = 16_000
MAX_BLOCK_CHARS = 3_000
MAX_ADVISORY_CHARS = 6_000
DEFER_REASONS = (
    "insufficient_context", "ambiguous_candidate_roles", "unsupported_relationship",
    "conflicting_evidence", "insufficient_advisory", "no_supported_candidate",
)
MISSING_FIELDS = ("entry_point", "critical_operation", "relationship", "version", "classification", "title")


def prioritize_context_candidates(
    critical: Sequence[Mapping[str, Any]], entries: Sequence[Mapping[str, Any]],
) -> list[str]:
    """Schedule bounded windows fairly; never choose an answer or prove a role.

    Round-robin declared paths and both candidate roles, instead of exhausting
    the budget on all criticals followed by entries in source-file order.
    Within each path, existing binding clues and proximity to issued critical
    anchors are retrieval hints only. All candidate IDs are retained exactly.
    """
    paths: list[str] = []
    by_path: dict[str, tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]] = {}
    seen: set[str] = set()
    for role, pool in enumerate((critical, entries)):
        for candidate in pool:
            location = candidate.get("location")
            identifier = candidate.get("candidate_id")
            if (not isinstance(location, Mapping) or not isinstance(identifier, str)
                    or not identifier or identifier in seen
                    or not isinstance(location.get("file"), str) or not location["file"]
                    or type(location.get("line")) is not int or location["line"] < 1):
                raise ValueError("invalid_context_candidate_identity_or_location")
            seen.add(identifier)
            path = location["file"]
            if path not in by_path:
                paths.append(path)
                by_path[path] = ([], [])
            by_path[path][role].append(candidate)
    for criticals, entry_list in by_path.values():
        anchors = [c["location"]["line"] for c in criticals]
        entry_list.sort(key=lambda c: (
            c.get("explicit_external_binding") is not True,
            c.get("direct_critical_reference") is not True,
            min((abs(c["location"]["line"] - line) for line in anchors), default=0),
        ))
    order = []
    depth = max((len(pool) for pair in by_path.values() for pool in pair), default=0)
    for index in range(depth):
        for path in paths:
            for pool in by_path[path]:
                if index < len(pool):
                    order.append(pool[index]["candidate_id"])
    return order


def source_window(
    text: str, path: str, line: int, *, max_chars: int = MAX_BLOCK_CHARS,
    companion_lines: Sequence[int] = (),
) -> dict[str, Any]:
    """Select a complete small Python function or a clearly labelled line window.

    Other languages, invalid Python and large functions start with +/-24 lines;
    no regex-based claim of complete function or call-graph reconstruction.
    A nearby opposite-role anchor may extend that window, if its entire interval
    fits the same budget. Proximity is a retrieval hint, never a semantic edge.
    Whole-line trimming keeps the anchor visible, except an overlong anchor is
    explicitly character-truncated. All returned line numbers are exact.
    """
    if not isinstance(text, str) or type(line) is not int or type(max_chars) is not int or max_chars < 1:
        raise ValueError("invalid_source_window")
    lines = text.splitlines()
    if not 1 <= line <= len(lines):
        raise ValueError("source_anchor_out_of_range")
    if (isinstance(companion_lines, (str, bytes, Mapping))
            or not isinstance(companion_lines, Sequence)
            or any(type(n) is not int or not 1 <= n <= len(lines) for n in companion_lines)):
        raise ValueError("invalid_companion_anchors")
    start, end = max(1, line - 24), min(len(lines), line + 24)
    function = None
    if path.endswith(".py") and len(text) <= 256 * 1024:
        try:
            tree = ast.parse(text)
            candidates = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    first = min([node.lineno, *(item.lineno for item in node.decorator_list)])
                    last = node.end_lineno or node.lineno
                    if first <= line <= last:
                        candidates.append((first, last))
            if candidates:
                first, last = min(candidates, key=lambda item: (item[1] - item[0], -item[0]))
                function = {"line_start": first, "line_end": last}
                if last - first < 120:
                    start, end = first, last
        except (SyntaxError, ValueError, RecursionError):
            pass  # Source is data; unavailable parsing retains labelled windows.
    companion = None
    nearby = sorted(set(companion_lines) - {line}, key=lambda n: (abs(n - line), n))
    # When a real parser gives us a function boundary, do not cross it merely
    # to join two nearby anchors. Other languages retain explicit line windows.
    nearby = [n for n in nearby if abs(n - line) < 120 and
              (function is None or function["line_start"] <= n <= function["line_end"])]
    if nearby:
        low, high = sorted((line, nearby[0]))
        if len("\n".join(lines[low - 1:high])) <= max_chars:
            companion = nearby[0]
            start, end = min(start, low), max(end, high)
    required_start, required_end = sorted((line, companion if companion is not None else line))
    original_start, original_end = start, end
    # Include a candidate line even if decorators or unusual source put it at an edge.
    selected = "\n".join(lines[start - 1:end])
    while len(selected) > max_chars and start < end:
        if end - required_end >= required_start - start and end > required_end:
            end -= 1
        elif start < required_start:
            start += 1
        elif end > required_end:
            end -= 1
        else:
            break
        selected = "\n".join(lines[start - 1:end])
    anchor_complete = len(selected) <= max_chars
    selected = selected[:max_chars]
    complete_function = bool(function and start == function["line_start"]
                             and end == function["line_end"] and anchor_complete)
    return {
        "file": path, "line_start": start, "line_end": end, "text": selected,
        "anchor_line_complete": anchor_complete,
        "selection": "python_function" if complete_function else
                     "paired_anchor_window" if companion is not None else "line_window",
        "anchor_line": line, "companion_anchor_line": companion,
        "companion_basis": "nearby_opposite_role_anchor_not_a_verified_edge" if companion is not None else None,
        "enclosing_python_function": function, "complete_function": complete_function,
        "source_lines": len(lines), "omitted_before": start > 1, "omitted_after": end < len(lines),
        "trimmed_to_char_budget": (start, end) != (original_start, original_end) or not anchor_complete,
        "call_relationship_verified": False,
        "relationship_assessment": "not_assessed_by_context_collector",
    }


def remove_covered_lines(block: Mapping[str, Any], existing: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Trim overlap with complete prior windows, without synthesizing source.

    The caller already reuses an existing block when it contains the new anchor.
    This function only trims window edges; the primary anchor cannot disappear.
    An incomplete overlong line cannot serve as coverage for another window.
    """
    result = dict(block)
    start, end, anchor = block["line_start"], block["line_end"], block["anchor_line"]
    for prior in existing:
        if prior["file"] != block["file"] or not prior["anchor_line_complete"]:
            continue
        first, last = prior["line_start"], prior["line_end"]
        if first <= anchor <= last:
            raise ValueError("source_anchor_already_covered")
        if last < anchor:
            start = max(start, last + 1)
        elif first > anchor:
            end = min(end, first - 1)
    if (start, end) == (block["line_start"], block["line_end"]):
        return result
    lines = block["text"].split("\n")
    result.update(line_start=start, line_end=end,
        text="\n".join(lines[start - block["line_start"]:end - block["line_start"] + 1]),
        selection="deduplicated_line_window", complete_function=False,
        omitted_before=start > 1, omitted_after=end < block["source_lines"],
        overlap_trimmed=True)
    companion = result["companion_anchor_line"]
    if companion is not None and not start <= companion <= end:
        result.update(companion_anchor_line=None, companion_basis=None)
    return result


def defer_contract(evidence_ids: Sequence[str], *, stage: str = "semantic_judge") -> dict[str, Any]:
    if stage not in ("semantic_judge", "reflection"):
        raise ValueError("invalid_defer_stage")
    return {
        "contract_version": 1, ("required_on_semantic_defer" if stage == "semantic_judge" else "required_on_reflection_defer"): True,
        "reason_codes": list(DEFER_REASONS),
        "missing_fields": list(MISSING_FIELDS if stage == "semantic_judge" else (*MISSING_FIELDS, "project", "trace")),
        "allowed_evidence_refs": list(evidence_ids), "max_evidence_refs": 8,
        "max_explanation_chars": 400,
        "assessment_origin": "model_self_report_not_independently_verified",
    }


def validate_defer_details(value: Any, evidence_ids: Sequence[str], *, stage: str = "semantic_judge") -> dict[str, Any]:
    """Validate a small reason object, without endorsing its semantic claims."""
    if stage not in ("semantic_judge", "reflection"):
        raise ValueError("invalid_defer_stage")
    if not isinstance(value, Mapping) or set(value) != {"reason_code", "missing_fields", "evidence_refs", "explanation"}:
        raise ValueError("invalid_semantic_defer_details")
    reason = value["reason_code"]
    if not isinstance(reason, str) or reason not in DEFER_REASONS:
        raise ValueError("invalid_semantic_defer_reason")
    normalized = {}
    fields = MISSING_FIELDS if stage == "semantic_judge" else (*MISSING_FIELDS, "project", "trace")
    for name, allowed, maximum in (("missing_fields", fields, 6), ("evidence_refs", evidence_ids, 8)):
        items = value[name]
        if (isinstance(items, (str, bytes, Mapping)) or not isinstance(items, Sequence)
                or not 1 <= len(items) <= maximum
                or any(not isinstance(item, str) or item not in allowed for item in items)
                or len(set(items)) != len(items)):
            raise ValueError("invalid_semantic_defer_refs_or_fields")
        normalized[name] = list(items)
    explanation = value["explanation"]
    if (not isinstance(explanation, str) or not explanation.strip() or len(explanation) > 400
            or re.search(r"[\x00-\x1f\x7f]", explanation)):
        raise ValueError("invalid_semantic_defer_explanation")
    return {"kind": "model_semantic_defer_v1" if stage == "semantic_judge" else "model_reflection_defer_v1", "reason_code": reason, **normalized,
            "explanation": explanation,
            "assessment_origin": "model_self_report_not_independently_verified"}
