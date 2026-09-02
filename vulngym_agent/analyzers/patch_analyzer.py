"""Parse bounded unified diffs without executing repository-controlled code.

The analyzer reports syntax and deliberately conservative lexical candidates.
It does not claim that a changed line is a vulnerability, guard, sink, or fix
in the semantic sense.  Such claims require a later source-aware resolver.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import re
import shlex
from typing import Final, Iterable, Literal

from vulngym_agent.evidence import LoadedEvidenceFile
from vulngym_agent.tools.git import (
    InvalidRepositoryPath,
    TextFileDiff,
    validate_repo_relative_path,
)


DEFAULT_MAX_PATCH_CHARS: Final[int] = 2 * 1024 * 1024
DEFAULT_MAX_PATCH_LINES: Final[int] = 20_000
DEFAULT_MAX_FILES: Final[int] = 512
DEFAULT_MAX_HUNKS: Final[int] = 4_096
DEFAULT_MAX_HUNK_LINES: Final[int] = 10_000
DEFAULT_MAX_CANDIDATES: Final[int] = 4_096

_HUNK_RE: Final[re.Pattern[str]] = re.compile(
    r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: ?(.*))?\Z"
)
_MAX_SOURCE_LINE_NUMBER: Final[int] = 2_147_483_647
_DANGEROUS_CALL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9_])(?:eval|exec|system|popen|shell_exec|unserialize|"
    r"pickle\.loads|yaml\.load|strcpy|strcat|sprintf|memcpy)\s*\(",
    re.IGNORECASE,
)
_GUARD_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:if\b|unless\b|assert\b|require\s*\(|(?:validate|verify|"
    r"check|authorize|authorise|deny|reject)[A-Za-z0-9_]*\s*\()",
    re.IGNORECASE,
)
_EARLY_RETURN_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:return\b|raise\b|throw\b|break\s*;?\s*$|continue\s*;?\s*$|"
    r"goto\s+(?:fail|error|cleanup)\b|abort\s*\()",
    re.IGNORECASE,
)

ChangeKind = Literal["context", "added", "removed"]
FileChangeKind = Literal["added", "deleted", "modified", "renamed", "binary"]
CandidateMode = Literal["guard", "early_return", "dangerous_call"]


class PatchAnalysisError(ValueError):
    """Base class for deterministic patch-analysis failures."""


class PatchLimitExceeded(PatchAnalysisError):
    """The patch exceeds a configured resource bound."""


class PatchFormatError(PatchAnalysisError):
    """The patch is not structurally valid unified diff text."""


class UnsafePatchPath(PatchFormatError):
    """A patch header names a non-canonical or unsafe repository path."""


@dataclass(frozen=True, slots=True)
class PatchLine:
    """One context, added, or removed source line with both coordinates."""

    change_kind: ChangeKind
    old_line: int | None
    new_line: int | None
    code: str


@dataclass(frozen=True, slots=True)
class PatchHunk:
    """One validated unified-diff hunk."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    section: str
    lines: tuple[PatchLine, ...]


@dataclass(frozen=True, slots=True)
class ChangedFile:
    """One changed path pair and its bounded text hunks."""

    old_path: str | None
    new_path: str | None
    change_kind: FileChangeKind
    hunks: tuple[PatchHunk, ...]
    added_lines: int
    removed_lines: int
    binary: bool = False

    @property
    def path(self) -> str:
        """Prefer the post-change path while retaining deletion support."""

        path = self.new_path or self.old_path
        assert path is not None
        return path


@dataclass(frozen=True, slots=True)
class PatchCandidate:
    """A lexical review candidate, never a verified vulnerability semantic."""

    candidate_id: str
    mode: CandidateMode
    file: str
    change_kind: Literal["context", "added", "removed"]
    old_line: int | None
    new_line: int | None
    code: str
    reason: str
    semantic_verified: bool = False


@dataclass(frozen=True, slots=True)
class PatchConflict:
    """A deterministic contradiction within or between supplied sources."""

    code: str
    message: str
    file: str | None = None


@dataclass(frozen=True, slots=True)
class PatchUncertainty:
    """A fact the bounded text parser intentionally could not establish."""

    code: str
    message: str
    file: str | None = None


@dataclass(frozen=True, slots=True)
class PatchAnalysis:
    """Structured patch syntax, candidates, and explicit epistemic limits."""

    source_kind: Literal["git", "local"]
    files: tuple[ChangedFile, ...]
    candidates: tuple[PatchCandidate, ...]
    conflicts: tuple[PatchConflict, ...] = ()
    uncertainties: tuple[PatchUncertainty, ...] = ()
    corroborated_files: tuple[str, ...] = ()
    semantic_verified: bool = False

    @property
    def fact_status(self) -> Literal["correct", "incorrect", "uncertain"]:
        """Classify parsed patch facts separately from vulnerability semantics."""

        if self.conflicts:
            return "incorrect"
        if self.uncertainties:
            return "uncertain"
        return "correct"

    @property
    def semantic_status(self) -> Literal["uncertain"]:
        """Lexical patch analysis alone never proves a vulnerability role."""

        return "uncertain"

    @property
    def guard_candidates(self) -> tuple[PatchCandidate, ...]:
        return tuple(item for item in self.candidates if item.mode == "guard")

    @property
    def early_return_candidates(self) -> tuple[PatchCandidate, ...]:
        return tuple(item for item in self.candidates if item.mode == "early_return")

    @property
    def removed_dangerous_calls(self) -> tuple[PatchCandidate, ...]:
        return tuple(
            item
            for item in self.candidates
            if item.mode == "dangerous_call" and item.change_kind == "removed"
        )


@dataclass(slots=True)
class _FileBuilder:
    declared_old: str | None = None
    declared_new: str | None = None
    old_path: str | None = None
    new_path: str | None = None
    rename_from: str | None = None
    rename_to: str | None = None
    saw_old_header: bool = False
    saw_new_header: bool = False
    binary: bool = False
    hunks: list[PatchHunk] | None = None

    def __post_init__(self) -> None:
        if self.hunks is None:
            self.hunks = []


@dataclass(slots=True)
class _HunkBuilder:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    section: str
    lines: list[PatchLine]
    old_consumed: int = 0
    new_consumed: int = 0

    @property
    def complete(self) -> bool:
        return (
            self.old_consumed == self.old_count
            and self.new_consumed == self.new_count
        )


def _bound(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _shell_words(value: str, *, context: str) -> list[str]:
    try:
        return shlex.split(value, posix=True)
    except ValueError as error:
        raise PatchFormatError(f"malformed quoted path in {context}") from error


def _path_token(value: str, *, context: str, prefix: str | None = None) -> str | None:
    value = value.split("\t", 1)[0]
    if "\\" in value:
        raise UnsafePatchPath(
            f"backslash/escape syntax is not accepted in {context}"
        )
    if value.startswith(('"', "'")):
        words = _shell_words(value, context=context)
        if len(words) != 1:
            raise PatchFormatError(f"expected one path in {context}")
        value = words[0]
    if value == "/dev/null":
        return None
    if prefix is not None and value.startswith(prefix):
        value = value[len(prefix) :]
    if any(ord(character) == 127 for character in value):
        raise UnsafePatchPath(f"DEL control character is not accepted in {context}")
    try:
        return validate_repo_relative_path(value)
    except InvalidRepositoryPath as error:
        raise UnsafePatchPath(f"unsafe path in {context}: {value!r}") from error


def _diff_git_paths(line: str) -> tuple[str, str]:
    raw_paths = line[len("diff --git ") :]
    if "\\" in raw_paths:
        raise UnsafePatchPath("backslash/escape syntax is not accepted in diff --git")
    words = _shell_words(raw_paths, context="diff --git")
    if len(words) != 2:
        raise PatchFormatError("diff --git must contain exactly two quoted path tokens")
    old_path = _path_token(words[0], context="diff --git old path", prefix="a/")
    new_path = _path_token(words[1], context="diff --git new path", prefix="b/")
    if old_path is None or new_path is None:
        raise PatchFormatError("diff --git paths must not use /dev/null")
    return old_path, new_path


def _hunk_header(line: str) -> _HunkBuilder:
    match = _HUNK_RE.fullmatch(line)
    if match is None:
        raise PatchFormatError(f"malformed unified-diff hunk header: {line!r}")
    raw_numbers = (
        match.group(1),
        match.group(2) or "1",
        match.group(3),
        match.group(4) or "1",
    )
    if any(len(value) > 10 for value in raw_numbers):
        raise PatchFormatError("hunk line coordinates exceed the supported range")
    old_start, old_count, new_start, new_count = map(int, raw_numbers)
    if any(
        value > _MAX_SOURCE_LINE_NUMBER
        for value in (old_start, old_count, new_start, new_count)
    ):
        raise PatchFormatError("hunk line coordinates exceed the supported range")
    if (old_count and old_start == 0) or (new_count and new_start == 0):
        raise PatchFormatError("non-empty hunk ranges must start at line 1 or later")
    return _HunkBuilder(
        old_start,
        old_count,
        new_start,
        new_count,
        match.group(5) or "",
        [],
    )


def _finish_hunk(builder: _HunkBuilder) -> PatchHunk:
    if not builder.complete:
        raise PatchFormatError(
            "hunk body does not match its declared old/new line counts"
        )
    return PatchHunk(
        builder.old_start,
        builder.old_count,
        builder.new_start,
        builder.new_count,
        builder.section,
        tuple(builder.lines),
    )


def _file_kind(builder: _FileBuilder) -> FileChangeKind:
    if builder.binary:
        return "binary"
    if builder.rename_from is not None or builder.rename_to is not None:
        return "renamed"
    if builder.old_path is None:
        return "added"
    if builder.new_path is None:
        return "deleted"
    return "modified"


def _finish_file(
    builder: _FileBuilder,
    conflicts: list[PatchConflict],
    uncertainties: list[PatchUncertainty],
) -> ChangedFile:
    if builder.saw_old_header != builder.saw_new_header:
        raise PatchFormatError("--- and +++ file headers must appear as a pair")
    old_path = (
        builder.rename_from
        if builder.rename_from is not None
        else builder.old_path
        if builder.saw_old_header
        else builder.declared_old
    )
    new_path = (
        builder.rename_to
        if builder.rename_to is not None
        else builder.new_path
        if builder.saw_new_header
        else builder.declared_new
    )
    if old_path is None and new_path is None:
        raise PatchFormatError("changed file has neither an old nor a new path")

    for declared, observed, label in (
        (builder.declared_old, old_path, "old"),
        (builder.declared_new, new_path, "new"),
    ):
        if declared is not None and observed is not None and declared != observed:
            conflicts.append(
                PatchConflict(
                    "path_headers_disagree",
                    f"diff --git and file headers disagree on the {label} path",
                    observed,
                )
            )
    if (builder.rename_from is None) != (builder.rename_to is None):
        uncertainties.append(
            PatchUncertainty(
                "incomplete_rename_metadata",
                "only one side of the rename metadata was present",
                new_path or old_path,
            )
        )
    if builder.binary:
        uncertainties.append(
            PatchUncertainty(
                "binary_content_not_analyzed",
                "binary patch payloads have no source lines for lexical analysis",
                new_path or old_path,
            )
        )

    hunks = tuple(builder.hunks or ())
    added = sum(
        1 for hunk in hunks for line in hunk.lines if line.change_kind == "added"
    )
    removed = sum(
        1 for hunk in hunks for line in hunk.lines if line.change_kind == "removed"
    )
    return ChangedFile(
        old_path,
        new_path,
        _file_kind(builder),
        hunks,
        added,
        removed,
        builder.binary,
    )


def _append_hunk_line(builder: _HunkBuilder, line: str, max_hunk_lines: int) -> None:
    if line == r"\ No newline at end of file":
        if not builder.lines:
            raise PatchFormatError("newline marker appears before any hunk content")
        return
    if not line or line[0] not in " +-":
        raise PatchFormatError(f"invalid unified-diff hunk body line: {line!r}")
    prefix, code = line[0], line[1:]
    if prefix == " ":
        change_kind: ChangeKind = "context"
        old_line = builder.old_start + builder.old_consumed
        new_line = builder.new_start + builder.new_consumed
        builder.old_consumed += 1
        builder.new_consumed += 1
    elif prefix == "-":
        change_kind = "removed"
        old_line = builder.old_start + builder.old_consumed
        new_line = None
        builder.old_consumed += 1
    else:
        change_kind = "added"
        old_line = None
        new_line = builder.new_start + builder.new_consumed
        builder.new_consumed += 1
    if (
        builder.old_consumed > builder.old_count
        or builder.new_consumed > builder.new_count
    ):
        raise PatchFormatError("hunk body exceeds its declared line counts")
    builder.lines.append(PatchLine(change_kind, old_line, new_line, code))
    if len(builder.lines) > max_hunk_lines:
        raise PatchLimitExceeded(
            f"hunk exceeds configured line limit of {max_hunk_lines}"
        )


def _parse_text(
    text: str,
    *,
    source_kind: Literal["git", "local"],
    max_chars: int,
    max_lines: int,
    max_files: int,
    max_hunks: int,
    max_hunk_lines: int,
) -> PatchAnalysis:
    if not isinstance(text, str):
        raise TypeError("patch text must be a string")
    if len(text) > max_chars:
        raise PatchLimitExceeded(
            f"patch has {len(text)} characters; limit is {max_chars}"
        )
    lines = text.splitlines()
    if len(lines) > max_lines:
        raise PatchLimitExceeded(
            f"patch has {len(lines)} lines; limit is {max_lines}"
        )

    files: list[ChangedFile] = []
    conflicts: list[PatchConflict] = []
    uncertainties: list[PatchUncertainty] = []
    current: _FileBuilder | None = None
    hunk: _HunkBuilder | None = None
    hunk_count = 0
    binary_payload = False

    def finish_active_hunk() -> None:
        nonlocal hunk
        if hunk is not None:
            assert current is not None and current.hunks is not None
            current.hunks.append(_finish_hunk(hunk))
            hunk = None

    def finish_active_file() -> None:
        nonlocal current, binary_payload
        if current is not None:
            finish_active_hunk()
            files.append(_finish_file(current, conflicts, uncertainties))
            if len(files) > max_files:
                raise PatchLimitExceeded(
                    f"patch exceeds configured file limit of {max_files}"
                )
        current = None
        binary_payload = False

    for line in lines:
        if hunk is not None:
            if hunk.complete:
                if line == r"\ No newline at end of file":
                    continue
                finish_active_hunk()
            else:
                _append_hunk_line(hunk, line, max_hunk_lines)
                continue

        if line.startswith("diff --git "):
            finish_active_file()
            old_path, new_path = _diff_git_paths(line)
            current = _FileBuilder(declared_old=old_path, declared_new=new_path)
            continue

        if binary_payload:
            continue

        if line.startswith("--- "):
            if current is None:
                current = _FileBuilder()
            elif current.saw_old_header and not current.saw_new_header:
                raise PatchFormatError("a second --- header appeared before +++")
            elif current.saw_old_header or current.hunks:
                finish_active_file()
                current = _FileBuilder()
            current.old_path = _path_token(
                line[4:], context="--- header", prefix="a/"
            )
            current.saw_old_header = True
            continue

        if line.startswith("+++ "):
            if current is None or not current.saw_old_header:
                raise PatchFormatError("+++ header must follow a --- header")
            current.new_path = _path_token(
                line[4:], context="+++ header", prefix="b/"
            )
            current.saw_new_header = True
            continue

        if line.startswith("@@"):
            if current is None or not (
                current.saw_old_header and current.saw_new_header
            ):
                raise PatchFormatError("hunk must follow matching ---/+++ headers")
            hunk = _hunk_header(line)
            hunk_count += 1
            if hunk_count > max_hunks:
                raise PatchLimitExceeded(
                    f"patch exceeds configured hunk limit of {max_hunks}"
                )
            continue

        if line.startswith("rename from "):
            if current is None:
                raise PatchFormatError("rename metadata must follow diff --git")
            current.rename_from = _path_token(
                line[len("rename from ") :], context="rename from"
            )
            continue
        if line.startswith("rename to "):
            if current is None:
                raise PatchFormatError("rename metadata must follow diff --git")
            current.rename_to = _path_token(
                line[len("rename to ") :], context="rename to"
            )
            continue
        if line.startswith("Binary files ") and line.endswith(" differ"):
            if current is None:
                current = _FileBuilder()
            payload = line[len("Binary files ") : -len(" differ")]
            parts = payload.split(" and ", 1)
            if len(parts) != 2:
                raise PatchFormatError("malformed binary-files marker")
            current.old_path = _path_token(
                parts[0], context="binary old path", prefix="a/"
            )
            current.new_path = _path_token(
                parts[1], context="binary new path", prefix="b/"
            )
            current.saw_old_header = True
            current.saw_new_header = True
            current.binary = True
            continue
        if line == "GIT binary patch":
            if current is None:
                raise PatchFormatError("binary payload must follow a file header")
            current.binary = True
            binary_payload = True
            continue

        if current is not None and line.startswith(
            (
                "index ",
                "new file mode ",
                "deleted file mode ",
                "old mode ",
                "new mode ",
                "similarity index ",
                "dissimilarity index ",
            )
        ):
            continue
        if line == r"\ No newline at end of file":
            raise PatchFormatError("newline marker appears outside a hunk")
        if (
            current is not None
            and current.saw_old_header
            and current.saw_new_header
            and line.startswith((" ", "+", "-"))
        ):
            raise PatchFormatError("source-like content appears outside a hunk")
        # Mail headers/preamble and unknown non-hunk metadata are inert.  They
        # are never interpreted as source code or paths.

    finish_active_file()
    if not files:
        uncertainties.append(
            PatchUncertainty(
                "no_unified_diff",
                "the supplied text contained no parseable changed file",
            )
        )
    return PatchAnalysis(
        source_kind,
        tuple(files),
        (),
        tuple(conflicts),
        tuple(uncertainties),
    )


def _nearest_context_line(hunk: PatchHunk, line_index: int) -> PatchLine | None:
    candidates = [
        (abs(index - line_index), 0 if index < line_index else 1, index, line)
        for index, line in enumerate(hunk.lines)
        if line.change_kind == "context" and line.old_line is not None and line.code.strip()
    ]
    if not candidates:
        return None
    return min(candidates)[3]


def _candidates(files: Iterable[ChangedFile], max_candidates: int) -> tuple[PatchCandidate, ...]:
    candidates: list[PatchCandidate] = []
    context_keys: set[tuple[str, int, str]] = set()

    def append_candidate(
        mode: CandidateMode,
        changed_file: ChangedFile,
        line: PatchLine,
        reason: str,
    ) -> None:
        candidates.append(
            PatchCandidate(
                f"patch-candidate-{len(candidates) + 1:06d}",
                mode,
                changed_file.path,
                line.change_kind,  # type: ignore[arg-type]
                line.old_line,
                line.new_line,
                line.code,
                reason,
            )
        )
        if len(candidates) > max_candidates:
            raise PatchLimitExceeded(
                "patch exceeds configured lexical-candidate limit of "
                f"{max_candidates}"
            )

    for changed_file in files:
        for hunk in changed_file.hunks:
            for index, line in enumerate(hunk.lines):
                modes: list[tuple[CandidateMode, str]] = []
                if line.change_kind == "added" and _GUARD_RE.search(line.code):
                    modes.append(
                        (
                            "guard",
                            "lexical conditional/validation-like pattern; semantic role unverified",
                        )
                    )
                if line.change_kind == "added" and _EARLY_RETURN_RE.search(line.code):
                    modes.append(
                        (
                            "early_return",
                            "lexical early-exit-like pattern; semantic role unverified",
                        )
                    )
                if line.change_kind == "removed" and _DANGEROUS_CALL_RE.search(line.code):
                    modes.append(
                        (
                            "dangerous_call",
                            "lexical call-name list match; semantic role unverified",
                        )
                    )
                for mode, reason in modes:
                    append_candidate(mode, changed_file, line, reason)
                if (
                    line.change_kind == "added"
                    and (
                        _GUARD_RE.search(line.code) is not None
                        or _EARLY_RETURN_RE.search(line.code) is not None
                    )
                ):
                    context = _nearest_context_line(hunk, index)
                    if context is not None:
                        assert context.old_line is not None
                        key = (changed_file.path, context.old_line, context.code)
                        if key not in context_keys:
                            context_keys.add(key)
                            append_candidate(
                                "guard",
                                changed_file,
                                context,
                                (
                                    "old-side context in a hunk containing a "
                                    "fix-added guard-like line; semantic role "
                                    "unverified"
                                ),
                            )
    return tuple(candidates)


def _git_consistency(
    analysis: PatchAnalysis, source: TextFileDiff
) -> PatchAnalysis:
    path = _path_token(source.path, context="TextFileDiff.path")
    assert path is not None
    conflicts = list(analysis.conflicts)
    uncertainties = list(analysis.uncertainties)
    files = list(analysis.files)
    if source.before_exists != (source.before_blob_id is not None):
        conflicts.append(
            PatchConflict(
                "git_before_blob_fact_disagrees",
                "TextFileDiff before_exists disagrees with before_blob_id",
                path,
            )
        )
    if source.after_exists != (source.after_blob_id is not None):
        conflicts.append(
            PatchConflict(
                "git_after_blob_fact_disagrees",
                "TextFileDiff after_exists disagrees with after_blob_id",
                path,
            )
        )
    if not source.before_exists and not source.after_exists:
        conflicts.append(
            PatchConflict(
                "git_diff_no_endpoints",
                "TextFileDiff says the path exists at neither endpoint",
                path,
            )
        )
    if len(files) == 1:
        item = files[0]
        if item.path != path:
            conflicts.append(
                PatchConflict(
                    "git_diff_path_disagrees",
                    "TextFileDiff.path disagrees with its unified-diff headers",
                    path,
                )
            )
        if (item.old_path is not None) != source.before_exists:
            conflicts.append(
                PatchConflict(
                    "git_before_endpoint_disagrees",
                    "TextFileDiff before_exists disagrees with the patch file headers",
                    path,
                )
            )
        if (item.new_path is not None) != source.after_exists:
            conflicts.append(
                PatchConflict(
                    "git_after_endpoint_disagrees",
                    "TextFileDiff after_exists disagrees with the patch file headers",
                    path,
                )
            )
        item = replace(
            item,
            old_path=path if source.before_exists else None,
            new_path=path if source.after_exists else None,
            change_kind=(
                "added"
                if not source.before_exists and source.after_exists
                else "deleted"
                if source.before_exists and not source.after_exists
                else "modified"
            ),
        )
        files[0] = item
        if (
            item.added_lines != source.added_lines
            or item.removed_lines != source.deleted_lines
        ):
            conflicts.append(
                PatchConflict(
                    "git_diff_counts_disagree",
                    "TextFileDiff line counts disagree with its unified-diff body",
                    path,
                )
            )
        if not source.changed and source.unified_diff:
            conflicts.append(
                PatchConflict(
                    "git_unchanged_with_patch",
                    "TextFileDiff blob identities say unchanged but include a patch body",
                    path,
                )
            )
    elif source.changed or source.unified_diff:
        conflicts.append(
            PatchConflict(
                "git_diff_file_count",
                "TextFileDiff must describe exactly one changed path",
                path,
            )
        )
    else:
        uncertainties.append(
            PatchUncertainty(
                "unchanged_git_file",
                "the Git blobs are identical, so there is no patch to analyze",
                path,
            )
        )
    return replace(
        analysis,
        files=tuple(files),
        conflicts=tuple(conflicts),
        uncertainties=tuple(uncertainties),
    )


def _changed_line_fingerprint(changed_file: ChangedFile) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            line.change_kind,
            line.old_line,
            line.new_line,
            line.code,
        )
        for hunk in changed_file.hunks
        for line in hunk.lines
        if line.change_kind != "context"
    )


def _corroborate(primary: PatchAnalysis, secondary: PatchAnalysis) -> PatchAnalysis:
    conflicts = list(primary.conflicts)
    uncertainties = list(primary.uncertainties)
    uncertainties.extend(secondary.uncertainties)
    conflicts.extend(secondary.conflicts)
    corroborated = list(primary.corroborated_files)

    secondary_by_path = {item.path: item for item in secondary.files}
    primary_paths = {item.path for item in primary.files}
    for item in primary.files:
        other = secondary_by_path.get(item.path)
        if other is None:
            conflicts.append(
                PatchConflict(
                    "patch_source_file_missing",
                    "the corroborating patch source does not contain this changed path",
                    item.path,
                )
            )
            continue
        if (
            item.old_path != other.old_path
            or item.new_path != other.new_path
            or item.change_kind != other.change_kind
            or _changed_line_fingerprint(item) != _changed_line_fingerprint(other)
        ):
            conflicts.append(
                PatchConflict(
                    "patch_sources_disagree",
                    "local and Git patch facts disagree for this path",
                    item.path,
                )
            )
        else:
            corroborated.append(item.path)
    for item in secondary.files:
        if item.path not in primary_paths:
            conflicts.append(
                PatchConflict(
                    "patch_source_file_extra",
                    "the corroborating patch source contains an additional changed path",
                    item.path,
                )
            )
    return replace(
        primary,
        conflicts=tuple(conflicts),
        uncertainties=tuple(uncertainties),
        corroborated_files=tuple(dict.fromkeys(corroborated)),
    )


def _single_source(
    source: TextFileDiff | LoadedEvidenceFile,
    *,
    max_chars: int,
    max_lines: int,
    max_files: int,
    max_hunks: int,
    max_hunk_lines: int,
    max_candidates: int,
) -> PatchAnalysis:
    if isinstance(source, TextFileDiff):
        kind: Literal["git", "local"] = "git"
        text = source.unified_diff
    elif isinstance(source, LoadedEvidenceFile):
        if source.kind != "patch":
            raise TypeError("LoadedEvidenceFile.kind must be 'patch'")
        kind = "local"
        text = source.text
    else:
        raise TypeError("source must be TextFileDiff or LoadedEvidenceFile")

    analysis = _parse_text(
        text,
        source_kind=kind,
        max_chars=max_chars,
        max_lines=max_lines,
        max_files=max_files,
        max_hunks=max_hunks,
        max_hunk_lines=max_hunk_lines,
    )
    if isinstance(source, TextFileDiff):
        analysis = _git_consistency(analysis, source)
    return replace(
        analysis,
        candidates=_candidates(analysis.files, max_candidates),
    )


def analyze_patch(
    source: TextFileDiff | LoadedEvidenceFile,
    *,
    corroborating: TextFileDiff | LoadedEvidenceFile | None = None,
    git_diff: TextFileDiff | None = None,
    max_chars: int = DEFAULT_MAX_PATCH_CHARS,
    max_lines: int = DEFAULT_MAX_PATCH_LINES,
    max_files: int = DEFAULT_MAX_FILES,
    max_hunks: int = DEFAULT_MAX_HUNKS,
    max_hunk_lines: int = DEFAULT_MAX_HUNK_LINES,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> PatchAnalysis:
    """Analyze one patch and optionally compare it with another trusted view.

    ``git_diff`` is a readable convenience for the common local-evidence plus
    Git-fact comparison.  ``corroborating`` supports either source direction;
    callers must not provide both.  A mismatch is returned as a conflict and
    never silently selects one source as the vulnerability truth.
    """

    if corroborating is not None and git_diff is not None:
        raise ValueError("provide corroborating or git_diff, not both")
    if git_diff is not None:
        corroborating = git_diff
    bounds = {
        "max_chars": _bound("max_chars", max_chars),
        "max_lines": _bound("max_lines", max_lines),
        "max_files": _bound("max_files", max_files),
        "max_hunks": _bound("max_hunks", max_hunks),
        "max_hunk_lines": _bound("max_hunk_lines", max_hunk_lines),
        "max_candidates": _bound("max_candidates", max_candidates),
    }
    analysis = _single_source(source, **bounds)
    if corroborating is None:
        return analysis
    second = _single_source(corroborating, **bounds)
    return _corroborate(analysis, second)


def compare_patch_sources(
    local_patch: LoadedEvidenceFile,
    git_diff: TextFileDiff,
    **bounds: int,
) -> PatchAnalysis:
    """Compare local patch evidence with an exact Git text-file diff."""

    return analyze_patch(local_patch, git_diff=git_diff, **bounds)
