"""Conservative extraction of machine-checkable facts from local advisories."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Iterable, Mapping

from .package import LoadedEvidenceFile


_GHSA_RE = re.compile(r"\bGHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}\b")
_CVE_RE = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,}\b", re.IGNORECASE)
_COMMIT_RE = re.compile(
    r"(?<![0-9a-fA-F])([0-9a-f]{40})(?![0-9a-fA-F])", re.IGNORECASE
)
_FIX_KEYS = frozenset(
    {
        "fix_commit",
        "fix_commits",
        "fixed_commit",
        "fixed_commits",
        "patched_commit",
        "patched_commits",
    }
)


@dataclass(frozen=True, slots=True)
class AdvisoryFacts:
    """Literal identifiers and explicitly labelled fix commits."""

    ghsa_ids: tuple[str, ...]
    cve_ids: tuple[str, ...]
    fix_commits: tuple[str, ...]
    source_link: str | None
    snippet: str
    other_vuln_ids: tuple[str, ...] = ()

    @property
    def vuln_ids(self) -> tuple[str, ...]:
        return self.cve_ids + self.ghsa_ids + self.other_vuln_ids


def _stable_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _json_values(value: Any, keys: frozenset[str]) -> Iterable[str]:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if isinstance(key, str) and key.casefold() in keys:
                    candidates = nested if isinstance(nested, list) else [nested]
                    for candidate in candidates:
                        if isinstance(candidate, str):
                            yield candidate
                pending.append(nested)
        elif isinstance(item, list):
            pending.extend(item)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant {value!r}")


def extract_advisory_facts(document: LoadedEvidenceFile) -> AdvisoryFacts:
    """Extract only unambiguous literal facts; never infer from arbitrary SHA text."""

    text = document.text
    ghsa_ids = _stable_unique(match.upper() for match in _GHSA_RE.findall(text))
    cve_ids = _stable_unique(match.upper() for match in _CVE_RE.findall(text))
    supported_ids = frozenset((*ghsa_ids, *cve_ids))
    # SCHEMA.md allows identifier families beyond CVE/GHSA (for example ZDI).
    # Preserve literal candidate-style tokens as advisory facts instead of
    # silently recommending their deletion.  This generic extractor is used
    # for completeness only; GHSA/CVE retain their stricter validators above.
    other_vuln_ids = _stable_unique(
        token.upper()
        for token in re.findall(
            r"(?<![0-9A-Za-z])([A-Za-z][A-Za-z0-9]*-[A-Za-z0-9][A-Za-z0-9._-]*)",
            text,
        )
        if token == token.upper()
        if token.upper() not in supported_ids
        and not token.upper().startswith(("CWE-", "CVSS-", "HTTP-", "HTTPS-"))
    )
    source_link = None
    parsed: Any = None
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError, RecursionError):
        pass

    fix_values: list[str] = []
    if parsed is not None:
        fix_values.extend(_json_values(parsed, _FIX_KEYS))
        if isinstance(parsed, Mapping):
            for key in ("source_link", "advisory_url", "ghsa_url"):
                value = parsed.get(key)
                if isinstance(value, str):
                    source_link = value
                    break

    # Plain-text advisories must explicitly label the commit as a fix.  A bare
    # 40-hex value could be a vulnerable, fix, merge, or unrelated commit.
    labelled_fix = re.compile(
        r"(?im)\b(?:fix(?:ed)?|patch(?:ed)?)\s+commit\s*[:=#-]?\s*"
        r"([0-9a-f]{40})\b"
    )
    fix_values.extend(labelled_fix.findall(text))
    extracted_fix_commits: list[str] = []
    for value in fix_values:
        matches = _COMMIT_RE.findall(value)
        if len(matches) == 1:
            extracted_fix_commits.append(matches[0].lower())
    fix_commits = _stable_unique(extracted_fix_commits)

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    snippet = "\n".join(lines[:8])[:2000] or "本地公告文件为空。"
    return AdvisoryFacts(
        ghsa_ids,
        cve_ids,
        fix_commits,
        source_link,
        snippet,
        other_vuln_ids,
    )
