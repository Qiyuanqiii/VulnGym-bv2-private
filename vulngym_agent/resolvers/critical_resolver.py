"""Conservative Sink/Guard resolution for ``critical_operation`` candidates.

The resolver consumes a small, stable candidate shape instead of importing a
particular patch parser.  It proves only immutable Git, diff-side, and source
location facts.  Even a fully corroborated candidate remains ``uncertain`` at
the vulnerability-semantic layer until a separate semantic judge establishes
that it is the actual sink or defective guard.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import re
from typing import Literal, Protocol

from vulngym_agent.tools.git import (
    GitFactError,
    GitRepository,
    InvalidRepositoryPath,
    TextFileDiff,
    validate_repo_relative_path,
)
from vulngym_agent.validators.commit_transition_validator import (
    CommitTransitionValidationResult,
    CommitTransitionValidator,
)
from vulngym_agent.validators.location_validator import LocationValidator


ValidationStatus = Literal["correct", "incorrect", "uncertain"]
CriticalMode = Literal["sink", "guard"]

DEFAULT_MAX_CANDIDATES = 128
MAX_MAX_CANDIDATES = 256
DEFAULT_MAX_CANDIDATE_CODE_CHARS = 100_000
MAX_REASON_CHARS = 2_000
MAX_MAPPING_FIELDS = 32

_HUNK_RE = re.compile(
    r"^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@"
)
_CANDIDATE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MISSING = object()


class PatchCandidateProtocol(Protocol):
    """Structural input accepted from a patch analyzer.

    ``mode`` may be the resolver modes (``sink``/``guard``) or the patch
    analyzer labels ``dangerous_call``/``early_return``.  ``change_kind`` must
    describe which side supplied ``code``; only ``removed`` and ``changed`` can
    become a vulnerable-version location.
    """

    candidate_id: str
    mode: str
    file: str
    change_kind: str
    old_line: int | None
    new_line: int | None
    code: str
    reason: str


class PatchAnalysisProtocol(Protocol):
    """Duck-typed bridge to a patch analyzer without importing its module."""

    candidates: Iterable[PatchCandidateProtocol]


@dataclass(frozen=True, slots=True)
class CriticalPatchCandidate:
    """Dependency-free input contract for one patch-derived candidate."""

    candidate_id: str
    mode: str
    file: str
    change_kind: str
    old_line: int | None
    new_line: int | None
    code: str
    reason: str = ""


@dataclass(frozen=True, slots=True)
class CriticalLocation:
    """A provisional, schema-shaped location in the vulnerable commit."""

    file: str
    line: int | str
    code: str

    def to_dict(self) -> dict[str, object]:
        return {"file": self.file, "line": self.line, "code": self.code}


@dataclass(frozen=True, slots=True)
class CriticalCandidateAssessment:
    """Facts, conclusion, and counterevidence for one candidate."""

    candidate_id: str
    requested_mode: str
    candidate_mode: str | None
    change_kind: str | None
    vulnerable_commit: str | None
    fix_commit: str | None
    file: str | None
    requested_old_line: int | None
    requested_new_line: int | None
    status: ValidationStatus
    fact_status: ValidationStatus
    transition_fact_status: ValidationStatus | None
    source_fact_status: ValidationStatus | None
    in_removed_or_changed_side: bool | None
    semantic_role_verified: bool
    location: CriticalLocation | None
    claimed_reason: str
    evidence: str
    counterevidence: tuple[str, ...]
    error_code: str | None = None

    @property
    def is_provisional(self) -> bool:
        return self.fact_status == "correct" and self.location is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "requested_mode": self.requested_mode,
            "candidate_mode": self.candidate_mode,
            "change_kind": self.change_kind,
            "vulnerable_commit": self.vulnerable_commit,
            "fix_commit": self.fix_commit,
            "file": self.file,
            "requested_old_line": self.requested_old_line,
            "requested_new_line": self.requested_new_line,
            "status": self.status,
            "fact_status": self.fact_status,
            "transition_fact_status": self.transition_fact_status,
            "source_fact_status": self.source_fact_status,
            "in_removed_or_changed_side": self.in_removed_or_changed_side,
            "semantic_role_verified": self.semantic_role_verified,
            "location": self.location.to_dict() if self.location else None,
            "claimed_reason": self.claimed_reason,
            "evidence": self.evidence,
            "counterevidence": list(self.counterevidence),
            "error_code": self.error_code,
        }


@dataclass(frozen=True, slots=True)
class CriticalResolutionResult:
    """Batch result suitable for a candidate/evidence sidecar."""

    mode: str
    status: ValidationStatus
    fact_status: ValidationStatus
    vulnerable_commit: str | None
    fix_commit: str | None
    candidates: tuple[CriticalCandidateAssessment, ...]
    provisional_candidate_ids: tuple[str, ...]
    semantic_role_verified: bool
    evidence: str
    counterevidence: tuple[str, ...]
    missing_information: tuple[str, ...]
    error_code: str | None = None

    @property
    def provisional_locations(self) -> tuple[CriticalLocation, ...]:
        return tuple(
            assessment.location
            for assessment in self.candidates
            if assessment.is_provisional and assessment.location is not None
        )

    @property
    def unique_provisional_location(self) -> CriticalLocation | None:
        locations = self.provisional_locations
        return locations[0] if len(locations) == 1 else None

    @property
    def suggested_location(self) -> CriticalLocation | None:
        """Return a suggestion only when immutable facts leave one candidate.

        The name is intentionally provisional: ``semantic_role_verified``
        remains false, so callers must not turn it into a final Entry merely
        because the location is unique.
        """

        return self.unique_provisional_location

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "status": self.status,
            "fact_status": self.fact_status,
            "vulnerable_commit": self.vulnerable_commit,
            "fix_commit": self.fix_commit,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "provisional_candidate_ids": list(self.provisional_candidate_ids),
            "provisional_locations": [
                location.to_dict() for location in self.provisional_locations
            ],
            "suggested_location": (
                self.suggested_location.to_dict()
                if self.suggested_location is not None
                else None
            ),
            "semantic_role_verified": self.semantic_role_verified,
            "evidence": self.evidence,
            "counterevidence": list(self.counterevidence),
            "missing_information": list(self.missing_information),
            "error_code": self.error_code,
        }


class CandidateContractError(ValueError):
    """One patch candidate violates the bounded input contract."""

    def __init__(self, code: str, message: str, candidate_id: str) -> None:
        self.code = code
        self.candidate_id = candidate_id
        super().__init__(message)


def _candidate_value(value: object, name: str) -> object:
    if isinstance(value, Mapping):
        return value.get(name, _MISSING)
    try:
        return getattr(value, name)
    except (AttributeError, RuntimeError):
        return _MISSING


def _candidate_hint(value: object, fallback: str) -> str:
    raw = _candidate_value(value, "candidate_id")
    if isinstance(raw, str) and _CANDIDATE_ID_RE.fullmatch(raw):
        return raw
    return fallback


def _positive_optional_line(
    value: object, *, name: str, candidate_id: str
) -> int | None:
    if value is _MISSING or value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise CandidateContractError(
            f"invalid_{name}",
            f"{name} must be a positive integer or null",
            candidate_id,
        )
    return value


def _coerce_candidate(value: object, index: int) -> CriticalPatchCandidate:
    fallback_id = f"candidate-{index:04d}"
    candidate_id = _candidate_hint(value, fallback_id)
    if isinstance(value, Mapping) and len(value) > MAX_MAPPING_FIELDS:
        raise CandidateContractError(
            "candidate_mapping_too_wide",
            f"candidate mapping exceeds {MAX_MAPPING_FIELDS} fields",
            candidate_id,
        )

    raw_id = _candidate_value(value, "candidate_id")
    if not isinstance(raw_id, str) or _CANDIDATE_ID_RE.fullmatch(raw_id) is None:
        raise CandidateContractError(
            "invalid_candidate_id",
            "candidate_id must be 1-128 safe ASCII identifier characters",
            fallback_id,
        )
    candidate_id = raw_id

    values: dict[str, str] = {}
    for name in ("mode", "file", "change_kind", "code"):
        raw = _candidate_value(value, name)
        if not isinstance(raw, str):
            raise CandidateContractError(
                f"invalid_{name}", f"{name} must be a string", candidate_id
            )
        values[name] = raw

    code = values["code"]
    if not code.strip() or "\x00" in code:
        raise CandidateContractError(
            "invalid_code", "code must contain non-NUL source text", candidate_id
        )

    raw_reason = _candidate_value(value, "reason")
    if raw_reason is _MISSING:
        reason = ""
    elif not isinstance(raw_reason, str) or "\x00" in raw_reason:
        raise CandidateContractError(
            "invalid_reason", "reason must be a non-NUL string", candidate_id
        )
    elif len(raw_reason) > MAX_REASON_CHARS:
        raise CandidateContractError(
            "reason_too_large",
            f"reason exceeds {MAX_REASON_CHARS} characters",
            candidate_id,
        )
    else:
        reason = raw_reason

    return CriticalPatchCandidate(
        candidate_id=candidate_id,
        mode=values["mode"],
        file=values["file"],
        change_kind=values["change_kind"],
        old_line=_positive_optional_line(
            _candidate_value(value, "old_line"),
            name="old_line",
            candidate_id=candidate_id,
        ),
        new_line=_positive_optional_line(
            _candidate_value(value, "new_line"),
            name="new_line",
            candidate_id=candidate_id,
        ),
        code=code,
        reason=reason,
    )


def _canonical_candidate_mode(mode: str) -> CriticalMode | None:
    if mode in {"sink", "dangerous_call"}:
        return "sink"
    if mode in {"guard", "early_return"}:
        return "guard"
    return None


def _removed_line_numbers(diff: TextFileDiff) -> frozenset[int]:
    """Extract old-side removed line numbers from our in-process unified diff."""

    removed: set[int] = set()
    old_line: int | None = None
    in_hunk = False
    for line in diff.unified_diff.splitlines():
        match = _HUNK_RE.match(line)
        if match is not None:
            old_line = int(match.group(1))
            in_hunk = True
            continue
        if not in_hunk or old_line is None:
            continue
        if line.startswith("-"):
            removed.add(old_line)
            old_line += 1
        elif line.startswith(" "):
            old_line += 1
        elif line.startswith("+") or line.startswith("\\"):
            continue
        else:
            # Only headers may occur outside a hunk.  Unexpected content after
            # a hunk means the generated diff cannot safely support line facts.
            raise ValueError("generated unified diff contains an invalid hunk line")
    return frozenset(removed)


class CriticalOperationResolver:
    """Resolve patch candidates into conservative Sink/Guard location facts."""

    def __init__(
        self,
        repository: GitRepository | str,
        *,
        line_tolerance: int = 5,
        timeout_seconds: float = 10.0,
        max_candidates: int = DEFAULT_MAX_CANDIDATES,
        max_candidate_code_chars: int = DEFAULT_MAX_CANDIDATE_CODE_CHARS,
    ) -> None:
        if (
            isinstance(max_candidates, bool)
            or not isinstance(max_candidates, int)
            or not 1 <= max_candidates <= MAX_MAX_CANDIDATES
        ):
            raise ValueError(
                f"max_candidates must be an integer from 1 to {MAX_MAX_CANDIDATES}"
            )
        if (
            isinstance(max_candidate_code_chars, bool)
            or not isinstance(max_candidate_code_chars, int)
            or not 1 <= max_candidate_code_chars <= DEFAULT_MAX_CANDIDATE_CODE_CHARS
        ):
            raise ValueError(
                "max_candidate_code_chars must be an integer from 1 to "
                f"{DEFAULT_MAX_CANDIDATE_CODE_CHARS}"
            )
        if (
            isinstance(line_tolerance, bool)
            or not isinstance(line_tolerance, int)
            or not 0 <= line_tolerance <= 100
        ):
            raise ValueError("line_tolerance must be an integer from 0 to 100")

        self.max_candidates = max_candidates
        self.max_candidate_code_chars = max_candidate_code_chars
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

        validator_source: GitRepository | str = (
            self._repository if self._repository is not None else repository
        )
        self._transition_validator = CommitTransitionValidator(
            validator_source, timeout_seconds=timeout_seconds
        )
        self._location_validator = LocationValidator(
            validator_source,
            line_tolerance=line_tolerance,
            timeout_seconds=timeout_seconds,
        )

    def resolve(
        self,
        vulnerable_commit: object,
        fix_commit: object,
        *,
        mode: object,
        candidates: (
            Iterable[
                CriticalPatchCandidate | PatchCandidateProtocol | Mapping[str, object]
            ]
            | PatchAnalysisProtocol
            | Mapping[str, object]
        ),
    ) -> CriticalResolutionResult:
        vulnerable_text = vulnerable_commit if isinstance(vulnerable_commit, str) else None
        fix_text = fix_commit if isinstance(fix_commit, str) else None
        if mode not in {"sink", "guard"}:
            return self._resolution_error(
                mode if isinstance(mode, str) else "",
                vulnerable_text,
                fix_text,
                "invalid_mode",
                "Critical mode must be exactly 'sink' or 'guard'.",
                status="incorrect",
            )
        requested_mode: CriticalMode = mode

        candidate_source: object = candidates
        if isinstance(candidates, Mapping) and "candidates" in candidates:
            try:
                candidate_source = candidates["candidates"]
            except Exception as error:
                return self._resolution_error(
                    requested_mode,
                    vulnerable_text,
                    fix_text,
                    "candidate_input_unreadable",
                    f"Patch analysis candidates could not be read safely: {error}.",
                    status="uncertain",
                )
        elif not isinstance(candidates, (str, bytes, bytearray, Mapping)):
            try:
                analysis_candidates = getattr(candidates, "candidates", _MISSING)
            except Exception as error:
                return self._resolution_error(
                    requested_mode,
                    vulnerable_text,
                    fix_text,
                    "candidate_input_unreadable",
                    f"Patch analysis candidates could not be read safely: {error}.",
                    status="uncertain",
                )
            if analysis_candidates is not _MISSING:
                candidate_source = analysis_candidates

        if isinstance(candidate_source, (str, bytes, bytearray, Mapping)):
            return self._resolution_error(
                requested_mode,
                vulnerable_text,
                fix_text,
                "invalid_candidates",
                "candidates must be an iterable of candidate objects, not one scalar or mapping.",
                status="incorrect",
            )
        try:
            iterator = iter(candidate_source)  # type: ignore[arg-type]
            bounded: list[object] = []
            for _ in range(self.max_candidates + 1):
                try:
                    bounded.append(next(iterator))
                except StopIteration:
                    break
        except Exception as error:
            return self._resolution_error(
                requested_mode,
                vulnerable_text,
                fix_text,
                "candidate_input_unreadable",
                f"Candidate input could not be read safely: {error}.",
                status="uncertain",
            )
        if len(bounded) > self.max_candidates:
            return self._resolution_error(
                requested_mode,
                vulnerable_text,
                fix_text,
                "candidate_limit_exceeded",
                f"Candidate count exceeds the configured limit of {self.max_candidates}.",
                status="uncertain",
            )
        if not bounded:
            return CriticalResolutionResult(
                mode=requested_mode,
                status="uncertain",
                fact_status="uncertain",
                vulnerable_commit=vulnerable_text,
                fix_commit=fix_text,
                candidates=(),
                provisional_candidate_ids=(),
                semantic_role_verified=False,
                evidence="No patch-derived critical-operation candidates were supplied; no location was guessed.",
                counterevidence=(),
                missing_information=(
                    f"A patch-derived {requested_mode} candidate anchored in vulnerable-version code is required.",
                ),
                error_code="no_candidates",
            )

        transition: CommitTransitionValidationResult | None = None
        diff_cache: dict[str, TextFileDiff | GitFactError] = {}

        def get_transition() -> CommitTransitionValidationResult:
            nonlocal transition
            if transition is None:
                transition = self._transition_validator.validate(
                    vulnerable_commit, fix_commit
                )
            return transition

        assessments: list[CriticalCandidateAssessment] = []
        seen_ids: set[str] = set()
        for index, value in enumerate(bounded, start=1):
            try:
                candidate = _coerce_candidate(value, index)
                if len(candidate.code) > self.max_candidate_code_chars:
                    raise CandidateContractError(
                        "candidate_code_too_large",
                        "candidate code exceeds the configured limit of "
                        f"{self.max_candidate_code_chars} characters",
                        candidate.candidate_id,
                    )
                if candidate.candidate_id in seen_ids:
                    raise CandidateContractError(
                        "duplicate_candidate_id",
                        f"candidate_id {candidate.candidate_id!r} is duplicated",
                        candidate.candidate_id,
                    )
                seen_ids.add(candidate.candidate_id)
            except CandidateContractError as error:
                assessments.append(
                    self._invalid_assessment(
                        error.candidate_id,
                        requested_mode,
                        vulnerable_text,
                        fix_text,
                        str(error),
                        error.code,
                    )
                )
                continue
            except Exception as error:
                candidate_id = _candidate_hint(value, f"candidate-{index:04d}")
                assessments.append(
                    self._uncertain_assessment(
                        candidate_id,
                        requested_mode,
                        vulnerable_text,
                        fix_text,
                        f"Candidate input could not be interpreted safely: {error}.",
                        "candidate_input_unreadable",
                    )
                )
                continue

            assessments.append(
                self._assess_candidate(
                    candidate,
                    requested_mode,
                    vulnerable_commit,
                    fix_commit,
                    get_transition,
                    diff_cache,
                )
            )

        provisional = tuple(
            item.candidate_id for item in assessments if item.is_provisional
        )
        aggregate_counterevidence = tuple(
            f"{item.candidate_id}: {counter}"
            for item in assessments
            for counter in item.counterevidence
        )
        if provisional:
            status: ValidationStatus = "uncertain"
            fact_status: ValidationStatus = "correct"
            evidence = (
                f"Git corroborated {len(provisional)} {requested_mode} location "
                "candidate(s) on the vulnerable/removed side. These facts do not "
                "establish the final vulnerability semantic role."
            )
            missing = (
                f"Independent advisory/data-flow evidence must establish which candidate is the actual {requested_mode}.",
            )
            error_code = None
        elif any(item.fact_status == "uncertain" for item in assessments):
            status = "uncertain"
            fact_status = "uncertain"
            evidence = (
                "No candidate was corroborated, and at least one candidate could not "
                "be checked with the available immutable Git facts."
            )
            missing = ("Complete local Git history and readable bounded source/diff evidence are required.",)
            error_code = "candidate_facts_incomplete"
        else:
            status = "incorrect"
            fact_status = "incorrect"
            evidence = (
                "Every supplied candidate was deterministically refuted; no critical "
                "operation location was invented."
            )
            missing = ()
            error_code = "all_candidates_refuted"

        return CriticalResolutionResult(
            mode=requested_mode,
            status=status,
            fact_status=fact_status,
            vulnerable_commit=vulnerable_text,
            fix_commit=fix_text,
            candidates=tuple(assessments),
            provisional_candidate_ids=provisional,
            semantic_role_verified=False,
            evidence=evidence,
            counterevidence=aggregate_counterevidence,
            missing_information=missing,
            error_code=error_code,
        )

    def _assess_candidate(
        self,
        candidate: CriticalPatchCandidate,
        requested_mode: CriticalMode,
        vulnerable_commit: object,
        fix_commit: object,
        get_transition: object,
        diff_cache: dict[str, TextFileDiff | GitFactError],
    ) -> CriticalCandidateAssessment:
        vulnerable_text = vulnerable_commit if isinstance(vulnerable_commit, str) else None
        fix_text = fix_commit if isinstance(fix_commit, str) else None
        candidate_mode = _canonical_candidate_mode(candidate.mode)
        if candidate_mode is None:
            return self._refuted(candidate, requested_mode, vulnerable_text, fix_text, "Unsupported patch candidate mode.", "invalid_candidate_mode")
        if candidate_mode != requested_mode:
            return self._refuted(candidate, requested_mode, vulnerable_text, fix_text, f"Candidate mode {candidate.mode!r} does not match requested {requested_mode!r} mode.", "candidate_mode_mismatch")
        if candidate.change_kind == "added":
            return self._refuted(
                candidate,
                requested_mode,
                vulnerable_text,
                fix_text,
                "Candidate quotes fix-added code, which cannot be the required location in the vulnerable commit.",
                "fix_only_added_candidate",
            )
        if candidate.change_kind not in {"removed", "changed"}:
            return self._refuted(
                candidate,
                requested_mode,
                vulnerable_text,
                fix_text,
                "Candidate is not identified as vulnerable-side removed/changed code.",
                "candidate_not_old_changed_side",
            )
        if candidate.old_line is None:
            code = (
                "fix_only_added_candidate"
                if candidate.new_line is not None
                else "missing_vulnerable_line"
            )
            return self._refuted(
                candidate,
                requested_mode,
                vulnerable_text,
                fix_text,
                "Candidate has no vulnerable-side old_line; a fix-side line is not a substitute.",
                code,
            )
        try:
            path = validate_repo_relative_path(candidate.file)
        except InvalidRepositoryPath as error:
            return self._refuted(candidate, requested_mode, vulnerable_text, fix_text, f"Candidate path is invalid: {error}.", "invalid_candidate_path")

        transition = get_transition()  # type: ignore[operator]
        if transition.fact_status != "correct":
            return self._assessment(
                candidate,
                requested_mode,
                vulnerable_text,
                fix_text,
                status=transition.status,
                fact_status=transition.fact_status,
                transition_fact_status=transition.fact_status,
                source_fact_status=None,
                in_removed=None,
                location=None,
                evidence=transition.evidence,
                counterevidence=(transition.evidence,),
                error_code=transition.error_code,
            )

        location = self._location_validator.validate(
            vulnerable_commit,
            file=path,
            line=candidate.old_line,
            code=candidate.code,
        )
        if location.fact_status != "correct":
            return self._assessment(
                candidate,
                requested_mode,
                vulnerable_text,
                fix_text,
                status=location.status,
                fact_status=location.fact_status,
                transition_fact_status="correct",
                source_fact_status=location.fact_status,
                in_removed=None,
                location=None,
                evidence=location.evidence,
                counterevidence=(location.evidence,),
                error_code=location.error_code,
            )

        if self._repository is None:
            detail = self._repository_error or "repository unavailable"
            evidence = f"Source location was checked, but the exact patch side could not be inspected: {detail}."
            return self._assessment(
                candidate,
                requested_mode,
                vulnerable_text,
                fix_text,
                status="uncertain",
                fact_status="uncertain",
                transition_fact_status="correct",
                source_fact_status="correct",
                in_removed=None,
                location=None,
                evidence=evidence,
                counterevidence=(evidence,),
                error_code="diff_unavailable",
            )

        cached = diff_cache.get(path)
        if cached is None:
            try:
                cached = self._repository.diff_text_file(
                    vulnerable_commit, fix_commit, path
                )
            except GitFactError as error:
                cached = error
            diff_cache[path] = cached
        if isinstance(cached, GitFactError):
            evidence = f"Exact source diff could not be read safely: {cached}."
            return self._assessment(
                candidate,
                requested_mode,
                vulnerable_text,
                fix_text,
                status="uncertain",
                fact_status="uncertain",
                transition_fact_status="correct",
                source_fact_status="correct",
                in_removed=None,
                location=None,
                evidence=evidence,
                counterevidence=(evidence,),
                error_code="diff_read_failed",
            )
        if not cached.changed:
            return self._refuted(
                candidate,
                requested_mode,
                vulnerable_text,
                fix_text,
                "Candidate path has the same blob in vulnerable and fix commits.",
                "candidate_path_unchanged",
                transition_fact_status="correct",
                source_fact_status="correct",
            )
        try:
            removed_lines = _removed_line_numbers(cached)
        except ValueError as error:
            evidence = f"Generated diff could not support safe old-side line facts: {error}."
            return self._assessment(
                candidate,
                requested_mode,
                vulnerable_text,
                fix_text,
                status="uncertain",
                fact_status="uncertain",
                transition_fact_status="correct",
                source_fact_status="correct",
                in_removed=None,
                location=None,
                evidence=evidence,
                counterevidence=(evidence,),
                error_code="diff_hunk_unreadable",
            )

        assert location.matched_start is not None
        assert location.matched_end is not None
        matched_span = set(range(location.matched_start, location.matched_end + 1))
        if not matched_span.intersection(removed_lines):
            return self._refuted(
                candidate,
                requested_mode,
                vulnerable_text,
                fix_text,
                "Candidate source exists, but its resolved vulnerable-version span does not overlap any removed/replaced old-side line in the exact diff.",
                "candidate_not_in_removed_side",
                transition_fact_status="correct",
                source_fact_status="correct",
                in_removed=False,
            )

        line_value: int | str = (
            location.matched_start
            if location.matched_start == location.matched_end
            else f"{location.matched_start}-{location.matched_end}"
        )
        provisional_location = CriticalLocation(
            file=path,
            line=line_value,
            code=location.matched_code or candidate.code,
        )
        semantic_gap = (
            f"Patch/source facts do not prove this location is the actual vulnerability {requested_mode}; "
            "the patch-analyzer reason is treated as an untrusted claim."
        )
        return self._assessment(
            candidate,
            requested_mode,
            vulnerable_text,
            fix_text,
            status="uncertain",
            fact_status="correct",
            transition_fact_status="correct",
            source_fact_status="correct",
            in_removed=True,
            location=provisional_location,
            evidence=(
                f"Git proves {path!r} changed from the vulnerable commit to the fix, "
                f"and committed lines {location.matched_start}-{location.matched_end} "
                "contain the candidate and overlap removed/replaced old-side code. "
                f"{semantic_gap}"
            ),
            counterevidence=(semantic_gap,),
            error_code=None,
        )

    @staticmethod
    def _assessment(
        candidate: CriticalPatchCandidate,
        requested_mode: str,
        vulnerable_commit: str | None,
        fix_commit: str | None,
        *,
        status: ValidationStatus,
        fact_status: ValidationStatus,
        transition_fact_status: ValidationStatus | None,
        source_fact_status: ValidationStatus | None,
        in_removed: bool | None,
        location: CriticalLocation | None,
        evidence: str,
        counterevidence: tuple[str, ...],
        error_code: str | None,
    ) -> CriticalCandidateAssessment:
        return CriticalCandidateAssessment(
            candidate_id=candidate.candidate_id,
            requested_mode=requested_mode,
            candidate_mode=candidate.mode,
            change_kind=candidate.change_kind,
            vulnerable_commit=vulnerable_commit,
            fix_commit=fix_commit,
            file=candidate.file,
            requested_old_line=candidate.old_line,
            requested_new_line=candidate.new_line,
            status=status,
            fact_status=fact_status,
            transition_fact_status=transition_fact_status,
            source_fact_status=source_fact_status,
            in_removed_or_changed_side=in_removed,
            semantic_role_verified=False,
            location=location,
            claimed_reason=candidate.reason,
            evidence=evidence,
            counterevidence=counterevidence,
            error_code=error_code,
        )

    @classmethod
    def _refuted(
        cls,
        candidate: CriticalPatchCandidate,
        requested_mode: str,
        vulnerable_commit: str | None,
        fix_commit: str | None,
        evidence: str,
        error_code: str,
        *,
        transition_fact_status: ValidationStatus | None = None,
        source_fact_status: ValidationStatus | None = None,
        in_removed: bool | None = None,
    ) -> CriticalCandidateAssessment:
        return cls._assessment(
            candidate,
            requested_mode,
            vulnerable_commit,
            fix_commit,
            status="incorrect",
            fact_status="incorrect",
            transition_fact_status=transition_fact_status,
            source_fact_status=source_fact_status,
            in_removed=in_removed,
            location=None,
            evidence=evidence,
            counterevidence=(evidence,),
            error_code=error_code,
        )

    @staticmethod
    def _invalid_assessment(
        candidate_id: str,
        requested_mode: str,
        vulnerable_commit: str | None,
        fix_commit: str | None,
        evidence: str,
        error_code: str,
    ) -> CriticalCandidateAssessment:
        return CriticalCandidateAssessment(
            candidate_id=candidate_id,
            requested_mode=requested_mode,
            candidate_mode=None,
            change_kind=None,
            vulnerable_commit=vulnerable_commit,
            fix_commit=fix_commit,
            file=None,
            requested_old_line=None,
            requested_new_line=None,
            status="incorrect",
            fact_status="incorrect",
            transition_fact_status=None,
            source_fact_status=None,
            in_removed_or_changed_side=None,
            semantic_role_verified=False,
            location=None,
            claimed_reason="",
            evidence=evidence,
            counterevidence=(evidence,),
            error_code=error_code,
        )

    @staticmethod
    def _uncertain_assessment(
        candidate_id: str,
        requested_mode: str,
        vulnerable_commit: str | None,
        fix_commit: str | None,
        evidence: str,
        error_code: str,
    ) -> CriticalCandidateAssessment:
        return CriticalCandidateAssessment(
            candidate_id=candidate_id,
            requested_mode=requested_mode,
            candidate_mode=None,
            change_kind=None,
            vulnerable_commit=vulnerable_commit,
            fix_commit=fix_commit,
            file=None,
            requested_old_line=None,
            requested_new_line=None,
            status="uncertain",
            fact_status="uncertain",
            transition_fact_status=None,
            source_fact_status=None,
            in_removed_or_changed_side=None,
            semantic_role_verified=False,
            location=None,
            claimed_reason="",
            evidence=evidence,
            counterevidence=(),
            error_code=error_code,
        )

    @staticmethod
    def _resolution_error(
        mode: str,
        vulnerable_commit: str | None,
        fix_commit: str | None,
        error_code: str,
        evidence: str,
        *,
        status: ValidationStatus,
    ) -> CriticalResolutionResult:
        return CriticalResolutionResult(
            mode=mode,
            status=status,
            fact_status=status,
            vulnerable_commit=vulnerable_commit,
            fix_commit=fix_commit,
            candidates=(),
            provisional_candidate_ids=(),
            semantic_role_verified=False,
            evidence=evidence,
            counterevidence=(),
            missing_information=(),
            error_code=error_code,
        )


def resolve_critical_operation(
    repository: GitRepository | str,
    vulnerable_commit: object,
    fix_commit: object,
    *,
    mode: object,
    candidates: (
        Iterable[
            CriticalPatchCandidate | PatchCandidateProtocol | Mapping[str, object]
        ]
        | PatchAnalysisProtocol
        | Mapping[str, object]
    ),
    line_tolerance: int = 5,
    timeout_seconds: float = 10.0,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> CriticalResolutionResult:
    """Convenience wrapper for one bounded Sink/Guard resolution pass."""

    return CriticalOperationResolver(
        repository,
        line_tolerance=line_tolerance,
        timeout_seconds=timeout_seconds,
        max_candidates=max_candidates,
    ).resolve(
        vulnerable_commit,
        fix_commit,
        mode=mode,
        candidates=candidates,
    )
