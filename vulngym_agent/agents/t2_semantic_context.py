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


def source_window(text: str, path: str, line: int, *, max_chars: int = MAX_BLOCK_CHARS) -> dict[str, Any]:
    """Select a complete small Python function or a clearly labelled line window.

    Other languages, invalid Python and large functions use +/-24 source lines;
    no regex-based claim of complete function or call-graph reconstruction.
    Whole-line trimming keeps the anchor visible, except an overlong anchor is
    explicitly character-truncated. All returned line numbers are exact.
    """
    if not isinstance(text, str) or type(line) is not int or type(max_chars) is not int or max_chars < 1:
        raise ValueError("invalid_source_window")
    lines = text.splitlines()
    if not 1 <= line <= len(lines):
        raise ValueError("source_anchor_out_of_range")
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
    original_start, original_end = start, end
    # Include a candidate line even if decorators or unusual source put it at an edge.
    selected = "\n".join(lines[start - 1:end])
    while len(selected) > max_chars and start < end:
        if end - line >= line - start and end > line:
            end -= 1
        elif start < line:
            start += 1
        else:
            end -= 1
        selected = "\n".join(lines[start - 1:end])
    anchor_complete = len(selected) <= max_chars
    selected = selected[:max_chars]
    complete_function = bool(function and start == function["line_start"]
                             and end == function["line_end"] and anchor_complete)
    return {
        "file": path, "line_start": start, "line_end": end, "text": selected,
        "anchor_line_complete": anchor_complete,
        "selection": "python_function" if complete_function else "line_window",
        "enclosing_python_function": function, "complete_function": complete_function,
        "source_lines": len(lines), "omitted_before": start > 1, "omitted_after": end < len(lines),
        "trimmed_to_char_budget": (start, end) != (original_start, original_end) or not anchor_complete,
        "call_relationship_verified": False,
    }


def defer_contract(evidence_ids: Sequence[str]) -> dict[str, Any]:
    return {
        "contract_version": 1, "required_on_semantic_defer": True,
        "reason_codes": list(DEFER_REASONS), "missing_fields": list(MISSING_FIELDS),
        "allowed_evidence_refs": list(evidence_ids), "max_evidence_refs": 8,
        "max_explanation_chars": 400,
        "assessment_origin": "model_self_report_not_independently_verified",
    }


def validate_defer_details(value: Any, evidence_ids: Sequence[str]) -> dict[str, Any]:
    """Validate a small reason object, without endorsing its semantic claims."""
    if not isinstance(value, Mapping) or set(value) != {"reason_code", "missing_fields", "evidence_refs", "explanation"}:
        raise ValueError("invalid_semantic_defer_details")
    reason = value["reason_code"]
    if not isinstance(reason, str) or reason not in DEFER_REASONS:
        raise ValueError("invalid_semantic_defer_reason")
    normalized = {}
    for name, allowed, maximum in (("missing_fields", MISSING_FIELDS, 6), ("evidence_refs", evidence_ids, 8)):
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
    return {"kind": "model_semantic_defer_v1", "reason_code": reason, **normalized,
            "explanation": explanation,
            "assessment_origin": "model_self_report_not_independently_verified"}
