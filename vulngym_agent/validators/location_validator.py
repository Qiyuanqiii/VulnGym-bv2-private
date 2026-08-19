"""Deterministic file, line, and source-snippet validation at one commit."""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from typing import Literal, Mapping

from vulngym_agent.tools.git import (
    GitFactError,
    GitRepository,
    InvalidCommitSha,
    InvalidRepositoryPath,
    validate_commit_sha,
    validate_repo_relative_path,
)


ValidationStatus = Literal["correct", "incorrect", "uncertain"]
_LINE_RANGE_RE = re.compile(r"([1-9][0-9]*)-([1-9][0-9]*)\Z")
_MAX_CANDIDATE_CODE_CHARS = 100_000


class InvalidLineSpan(ValueError):
    """A location line is not an int or canonical ``a-b`` range."""


@dataclass(frozen=True, slots=True)
class LocationValidationResult:
    """Structured deterministic facts plus explicit semantic uncertainty."""

    status: ValidationStatus
    fact_status: ValidationStatus
    commit: str | None
    file: str | None
    requested_line: int | str | None
    requested_start: int | None
    requested_end: int | None
    file_exists: bool | None
    blob_id: str | None
    line_valid: bool | None
    code_matches: bool | None
    matched_start: int | None
    matched_end: int | None
    matched_code: str | None
    line_offset: int | None
    all_match_starts: tuple[int, ...]
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


def parse_line_span(line: object) -> tuple[int, int]:
    """Parse the VulnGym ``int | 'a-b'`` line contract."""

    if isinstance(line, bool):
        raise InvalidLineSpan("line must not be a boolean")
    if isinstance(line, int):
        if line < 1:
            raise InvalidLineSpan("line integer must be at least 1")
        return line, line
    if isinstance(line, str):
        match = _LINE_RANGE_RE.fullmatch(line)
        if match is None:
            raise InvalidLineSpan("line range must use canonical 'a-b' syntax")
        try:
            start, end = (int(value) for value in match.groups())
        except ValueError as error:
            raise InvalidLineSpan("line range integers are too large") from error
        if end < start:
            raise InvalidLineSpan("line range end must not precede its start")
        return start, end
    raise InvalidLineSpan("line must be a positive integer or an 'a-b' range")


def _normalized_line(line: str) -> str:
    """Tokenize one line while ignoring formatting-only whitespace.

    Token separators preserve lexical boundaries, so ``if not`` cannot match
    ``ifnot`` and ``a + +b`` cannot match ``a++b``.  A small cross-language
    maximal-operator set still lets spacing around punctuation vary.
    """

    multi_operators = (
        ">>>=",
        "<<=",
        ">>=",
        "===",
        "!==",
        "**=",
        "//=",
        "...",
        "&&=",
        "||=",
        "??=",
        ">>>",
        "++",
        "--",
        "&&",
        "||",
        "??",
        "?.",
        "**",
        "//",
        "==",
        "!=",
        "<=",
        ">=",
        "+=",
        "-=",
        "*=",
        "/=",
        "%=",
        "&=",
        "|=",
        "^=",
        "<<",
        ">>",
        "=>",
        "->",
        "::",
        ":=",
        "<-",
        "|>",
        "..",
    )
    tokens: list[str] = []
    index = 0
    while index < len(line):
        character = line[index]
        if character.isspace():
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
            end = index + 1
            escaped = False
            while end < len(line):
                current = line[end]
                end += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    break
            tokens.append(line[index:end])
            index = end
            continue
        if character.isalnum() or character in {"_", "$"}:
            end = index + 1
            while end < len(line) and (
                line[end].isalnum() or line[end] in {"_", "$"}
            ):
                end += 1
            tokens.append(line[index:end])
            index = end
            continue
        operator = next(
            (value for value in multi_operators if line.startswith(value, index)),
            None,
        )
        if operator is not None:
            tokens.append(operator)
            index += len(operator)
        else:
            tokens.append(character)
            index += 1
    return "\x1f".join(tokens)


def normalize_code(code: str) -> tuple[str, ...]:
    """Return a conservative, line-preserving code representation."""

    if not isinstance(code, str):
        raise ValueError("code must be a string")
    lines = code.splitlines()
    first = 0
    last = len(lines)
    while first < last and not lines[first].strip():
        first += 1
    while last > first and not lines[last - 1].strip():
        last -= 1
    return tuple(_normalized_line(line) for line in lines[first:last])


def _snippet_line_count(code: object) -> tuple[str, ...]:
    if not isinstance(code, str):
        raise ValueError("code must be a string")
    if "\x00" in code:
        raise ValueError("code must not contain NUL")
    if len(code) > _MAX_CANDIDATE_CODE_CHARS:
        raise ValueError(
            f"code exceeds the {_MAX_CANDIDATE_CODE_CHARS}-character safety limit"
        )
    normalized = normalize_code(code)
    if not normalized or not any(normalized_line for normalized_line in normalized):
        raise ValueError("code must contain at least one non-whitespace character")
    return normalized


def _closed_interval_distance(
    first_start: int,
    first_end: int,
    second_start: int,
    second_end: int,
) -> int:
    """Return zero for overlapping closed intervals, otherwise their gap."""

    if first_end < second_start:
        return second_start - first_end
    if second_end < first_start:
        return first_start - second_end
    return 0


def _result(
    *,
    status: ValidationStatus,
    fact_status: ValidationStatus,
    commit: str | None,
    file: str | None,
    requested_line: int | str | None,
    requested_start: int | None = None,
    requested_end: int | None = None,
    file_exists: bool | None = None,
    blob_id: str | None = None,
    line_valid: bool | None = None,
    code_matches: bool | None = None,
    matched_start: int | None = None,
    matched_end: int | None = None,
    matched_code: str | None = None,
    line_offset: int | None = None,
    all_match_starts: tuple[int, ...] = (),
    evidence: str,
    error_code: str | None = None,
) -> LocationValidationResult:
    return LocationValidationResult(
        status=status,
        fact_status=fact_status,
        commit=commit,
        file=file,
        requested_line=requested_line,
        requested_start=requested_start,
        requested_end=requested_end,
        file_exists=file_exists,
        blob_id=blob_id,
        line_valid=line_valid,
        code_matches=code_matches,
        matched_start=matched_start,
        matched_end=matched_end,
        matched_code=matched_code,
        line_offset=line_offset,
        all_match_starts=all_match_starts,
        semantic_role_verified=False,
        evidence=evidence,
        error_code=error_code,
    )


class LocationValidator:
    """Validate exact path and nearby code without checking out the commit."""

    def __init__(
        self,
        repository: GitRepository | str | os.PathLike[str],
        *,
        line_tolerance: int = 5,
        timeout_seconds: float = 10.0,
    ) -> None:
        if isinstance(line_tolerance, bool) or not isinstance(line_tolerance, int):
            raise ValueError("line_tolerance must be a non-negative integer")
        if line_tolerance < 0:
            raise ValueError("line_tolerance must be a non-negative integer")
        self.line_tolerance = line_tolerance
        self._repository: GitRepository | None
        self._repository_error: GitFactError | None
        if isinstance(repository, GitRepository):
            self._repository = repository
            self._repository_error = None
        else:
            try:
                self._repository = GitRepository(
                    repository, timeout_seconds=timeout_seconds
                )
                self._repository_error = None
            except GitFactError as error:
                self._repository = None
                self._repository_error = error

    def validate(
        self,
        commit: object,
        *,
        file: object,
        line: object,
        code: object,
    ) -> LocationValidationResult:
        submitted_commit = commit if isinstance(commit, str) else None
        submitted_file = file if isinstance(file, str) else None
        submitted_line = (
            line
            if isinstance(line, (int, str)) and not isinstance(line, bool)
            else None
        )

        try:
            canonical_commit = validate_commit_sha(commit)
        except InvalidCommitSha as error:
            return _result(
                status="incorrect",
                fact_status="incorrect",
                commit=submitted_commit,
                file=submitted_file,
                requested_line=submitted_line,
                evidence=f"Commit syntax is invalid: {error}.",
                error_code="invalid_commit_sha",
            )
        try:
            canonical_file = validate_repo_relative_path(file)
        except InvalidRepositoryPath as error:
            return _result(
                status="incorrect",
                fact_status="incorrect",
                commit=canonical_commit,
                file=submitted_file,
                requested_line=submitted_line,
                evidence=f"Repository path is invalid: {error}.",
                error_code="invalid_file_path",
            )
        try:
            requested_start, requested_end = parse_line_span(line)
        except InvalidLineSpan as error:
            return _result(
                status="incorrect",
                fact_status="incorrect",
                commit=canonical_commit,
                file=canonical_file,
                requested_line=submitted_line,
                evidence=f"Line location is invalid: {error}.",
                error_code="invalid_line",
            )
        try:
            normalized_candidate = _snippet_line_count(code)
        except ValueError as error:
            return _result(
                status="incorrect",
                fact_status="incorrect",
                commit=canonical_commit,
                file=canonical_file,
                requested_line=submitted_line,
                requested_start=requested_start,
                requested_end=requested_end,
                evidence=f"Code snippet is invalid: {error}.",
                error_code="invalid_code",
            )

        if self._repository is None:
            assert self._repository_error is not None
            return _result(
                status="uncertain",
                fact_status="uncertain",
                commit=canonical_commit,
                file=canonical_file,
                requested_line=submitted_line,
                requested_start=requested_start,
                requested_end=requested_end,
                evidence=(
                    "The local repository could not be inspected, so this location "
                    f"is unverified: {self._repository_error}."
                ),
                error_code="repository_unavailable",
            )

        try:
            object_type = self._repository.object_type(canonical_commit)
            if object_type != "commit":
                reason = (
                    "does not exist"
                    if object_type is None
                    else f"has Git object type {object_type!r}"
                )
                return _result(
                    status="incorrect",
                    fact_status="incorrect",
                    commit=canonical_commit,
                    file=canonical_file,
                    requested_line=submitted_line,
                    requested_start=requested_start,
                    requested_end=requested_end,
                    evidence=f"Commit {canonical_commit} {reason}; source cannot be read.",
                    error_code="commit_not_found_or_not_commit",
                )

            entry = self._repository.tree_entry(canonical_commit, canonical_file)
            if entry is None or not entry.is_blob:
                return _result(
                    status="incorrect",
                    fact_status="incorrect",
                    commit=canonical_commit,
                    file=canonical_file,
                    requested_line=submitted_line,
                    requested_start=requested_start,
                    requested_end=requested_end,
                    file_exists=False,
                    evidence=(
                        f"Exact path {canonical_file!r} does not name a file in "
                        f"commit {canonical_commit}."
                    ),
                    error_code="file_not_found",
                )

        except GitFactError as error:
            return _result(
                status="uncertain",
                fact_status="uncertain",
                commit=canonical_commit,
                file=canonical_file,
                requested_line=submitted_line,
                requested_start=requested_start,
                requested_end=requested_end,
                evidence=f"Git could not read the source location: {error}.",
                error_code="source_read_failed",
            )

        try:
            source = self._repository.read_text(canonical_commit, canonical_file)
        except GitFactError as error:
            return _result(
                status="uncertain",
                fact_status="uncertain",
                commit=canonical_commit,
                file=canonical_file,
                requested_line=submitted_line,
                requested_start=requested_start,
                requested_end=requested_end,
                file_exists=True,
                blob_id=entry.object_id,
                evidence=(
                    f"Exact path {canonical_file!r} exists at {canonical_commit}, but "
                    f"its source text could not be read safely: {error}."
                ),
                error_code="source_read_failed",
            )

        source_lines = source.splitlines()
        total_lines = len(source_lines)
        if requested_start > total_lines or requested_end > total_lines:
            return _result(
                status="incorrect",
                fact_status="incorrect",
                commit=canonical_commit,
                file=canonical_file,
                requested_line=submitted_line,
                requested_start=requested_start,
                requested_end=requested_end,
                file_exists=True,
                blob_id=entry.object_id,
                line_valid=False,
                evidence=(
                    f"{canonical_file!r} has {total_lines} lines at {canonical_commit}; "
                    f"requested lines {requested_start}-{requested_end} are out of bounds."
                ),
                error_code="line_out_of_bounds",
            )

        candidate_span = len(normalized_candidate)
        normalized_source = tuple(_normalized_line(item) for item in source_lines)
        latest_start = total_lines - candidate_span + 1
        # A multi-line code block may begin before the declared range while
        # still overlapping it.  Include every possible start whose resulting
        # closed interval can be within the configured distance.
        search_start = max(
            1,
            requested_start - self.line_tolerance - candidate_span + 1,
        )
        search_end = min(latest_start, requested_end + self.line_tolerance)
        match_starts = tuple(
            candidate_start
            for candidate_start in range(search_start, search_end + 1)
            if normalized_source[
                candidate_start - 1 : candidate_start - 1 + candidate_span
            ]
            == normalized_candidate
            and _closed_interval_distance(
                candidate_start,
                candidate_start + candidate_span - 1,
                requested_start,
                requested_end,
            )
            <= self.line_tolerance
        )

        if not match_starts:
            return _result(
                status="incorrect",
                fact_status="incorrect",
                commit=canonical_commit,
                file=canonical_file,
                requested_line=submitted_line,
                requested_start=requested_start,
                requested_end=requested_end,
                file_exists=True,
                blob_id=entry.object_id,
                line_valid=True,
                code_matches=False,
                evidence=(
                    f"Whitespace-normalized code was not found in exact path "
                    f"{canonical_file!r} within closed-interval distance "
                    f"{self.line_tolerance} of requested lines "
                    f"{requested_start}-{requested_end} at commit {canonical_commit}."
                ),
                error_code="code_not_found_near_line",
            )

        matched_start = min(
            match_starts,
            key=lambda candidate_start: (
                _closed_interval_distance(
                    candidate_start,
                    candidate_start + candidate_span - 1,
                    requested_start,
                    requested_end,
                ),
                abs(candidate_start - requested_start),
                candidate_start,
            ),
        )
        matched_end = matched_start + candidate_span - 1
        matched_code = "\n".join(source_lines[matched_start - 1 : matched_end])
        offset = matched_start - requested_start
        interval_distance = _closed_interval_distance(
            matched_start,
            matched_end,
            requested_start,
            requested_end,
        )
        ambiguity = (
            f" There are {len(match_starts)} matches in the tolerance window; "
            f"the nearest begins at line {matched_start}."
            if len(match_starts) > 1
            else ""
        )
        return _result(
            status="uncertain",
            fact_status="correct",
            commit=canonical_commit,
            file=canonical_file,
            requested_line=submitted_line,
            requested_start=requested_start,
            requested_end=requested_end,
            file_exists=True,
            blob_id=entry.object_id,
            line_valid=True,
            code_matches=True,
            matched_start=matched_start,
            matched_end=matched_end,
            matched_code=matched_code,
            line_offset=offset,
            all_match_starts=match_starts,
            evidence=(
                f"Git source proves the whitespace-normalized snippet exists in exact "
                f"path {canonical_file!r} at lines {matched_start}-{matched_end} "
                f"(start offset {offset:+d}, closed-interval distance "
                f"{interval_distance}, allowed {self.line_tolerance}) in commit "
                f"{canonical_commit}; blob {entry.object_id}. Matched committed code: "
                f"{matched_code[:240]!r}.{ambiguity} File/line/code facts are verified, "
                "but entry-point reachability or critical-operation semantics were not evaluated."
            ),
        )

    def validate_mapping(
        self, commit: object, location: Mapping[str, object]
    ) -> LocationValidationResult:
        """Validate one schema-shaped ``{file, line, code}`` mapping."""

        return self.validate(
            commit,
            file=location.get("file"),
            line=location.get("line"),
            code=location.get("code"),
        )


def validate_location(
    repository: GitRepository | str | os.PathLike[str],
    commit: object,
    *,
    file: object,
    line: object,
    code: object,
    line_tolerance: int = 5,
    timeout_seconds: float = 10.0,
) -> LocationValidationResult:
    """Convenience wrapper around :class:`LocationValidator`."""

    return LocationValidator(
        repository,
        line_tolerance=line_tolerance,
        timeout_seconds=timeout_seconds,
    ).validate(commit, file=file, line=line, code=code)
