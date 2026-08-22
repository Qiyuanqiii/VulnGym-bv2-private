"""Independent D3 reviewer for one source-discovery producer draft."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from threading import RLock
from typing import Any, Final

from vulngym_agent.agents.model_runtime import StructuredModelBackend
from vulngym_agent.benchmark.reviewer_contracts import (
    REVIEWER_ASSESSMENTS,
    REVIEWER_CRITERIA,
    ReviewerCandidateVerdictV1,
    ReviewerContractError,
    ReviewerCriterionV1,
    ReviewerDeferredV1,
    ReviewerEvidenceSelectionV1,
    ReviewerFinalizedV1,
    ReviewerInputV1,
    ReviewerResultV1,
    parse_reviewer_result_v1,
)
from vulngym_agent.benchmark.sealed_tree_access import BoundSealedTree
from vulngym_agent.orchestrator.budget import Budget, BudgetExceeded
from vulngym_agent.orchestrator.reviewer_context import (
    ReviewerCandidateContext,
    ReviewerContextBindingError,
    ReviewerContextError,
    ReviewerContextLimitExceeded,
    ReviewerContextSession,
    ReviewerValidationArtifact,
)
from vulngym_agent.tools.runtime import ArtifactRef


REVIEWER_RESPONSE_CONTRACT_ID: Final[str] = (
    "source-discovery-review-response@1"
)
_MODEL_BATCH_SIZE: Final[int] = 2


class _Stop(Exception):
    __slots__ = ("missing_information", "reason_code")

    def __init__(self, reason_code: str, missing_information: tuple[str, ...]) -> None:
        self.reason_code = reason_code
        self.missing_information = missing_information
        super().__init__(reason_code)


def _exact_object(
    value: Any, *, keys: frozenset[str], name: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != keys:
        raise ReviewerContractError(
            "invalid_keys", f"{name} does not use the fixed response schema"
        )
    return value


def _array(value: Any, *, name: str, maximum: int) -> tuple[Any, ...]:
    if type(value) not in (tuple, list):
        raise ReviewerContractError("invalid_type", f"{name} must be an array")
    result = tuple(value)
    if len(result) > maximum:
        raise ReviewerContractError("limit_exceeded", f"{name} exceeds its limit")
    return result


def _insufficient_criteria() -> tuple[ReviewerCriterionV1, ...]:
    return tuple(
        ReviewerCriterionV1(
            criterion=criterion,
            assessment="insufficient",
            selections=(),
        )
        for criterion in REVIEWER_CRITERIA
    )


class SourceDiscoveryReviewerController:
    """Run one bounded, fresh-source-only D3 review and close every sidecar."""

    __slots__ = (
        "_cancelled",
        "_lock",
        "_result",
        "_review_input",
        "_running",
        "_session",
        "_stage",
    )

    def __init__(
        self,
        review_input: ReviewerInputV1,
        tree: BoundSealedTree,
        budget: Budget,
        backend: StructuredModelBackend,
    ) -> None:
        session: ReviewerContextSession | None = None
        try:
            session = ReviewerContextSession(review_input, tree, budget, backend)
            self._session = session
            self._review_input = session.review_input
            self._stage = "BUILD"
            self._result: ReviewerResultV1 | None = None
            self._cancelled = False
            self._running = False
            self._lock = RLock()
            return
        except BaseException:
            if session is not None:
                try:
                    session.abort()
                except BaseException:
                    pass
            raise

    @staticmethod
    def _request_contract() -> dict[str, Any]:
        return {
            "response_contract_id": REVIEWER_RESPONSE_CONTRACT_ID,
            "response_exact_keys": ["reviews"],
            "review_exact_keys": [
                "candidate_id",
                "criteria",
            ],
            "criterion_exact_keys": [
                "assessment",
                "criterion",
                "selections",
            ],
            "selection_exact_keys": ["artifact_id", "node_id"],
            "criteria": list(REVIEWER_CRITERIA),
            "assessments": sorted(REVIEWER_ASSESSMENTS),
            "decision_is_controller_derived": True,
            "digests_are_controller_derived": True,
        }

    def _parse_response(
        self,
        response: Any,
        contexts: tuple[ReviewerCandidateContext, ...],
    ) -> tuple[tuple[ReviewerCriterionV1, ...], ...]:
        root = _exact_object(
            response,
            keys=frozenset({"reviews"}),
            name="review response",
        )
        reviews = _array(root["reviews"], name="reviews", maximum=_MODEL_BATCH_SIZE)
        if len(reviews) != len(contexts):
            raise ReviewerContractError(
                "verdict_coverage_mismatch",
                "model response does not cover its exact context batch",
            )
        parsed: list[tuple[ReviewerCriterionV1, ...]] = []
        observed: list[str] = []
        for index, (raw_review, context) in enumerate(
            zip(reviews, contexts, strict=True)
        ):
            review = _exact_object(
                raw_review,
                keys=frozenset({"candidate_id", "criteria"}),
                name=f"reviews[{index}]",
            )
            if (
                type(review["candidate_id"]) is not str
                or review["candidate_id"] != context.candidate_id
            ):
                raise ReviewerContractError(
                    "invalid_binding", "model review does not match its context"
                )
            observed.append(review["candidate_id"])
            raw_criteria = _array(
                review["criteria"],
                name=f"reviews[{index}].criteria",
                maximum=len(REVIEWER_CRITERIA),
            )
            criteria: list[ReviewerCriterionV1] = []
            for criterion_index, raw_criterion in enumerate(raw_criteria):
                item = _exact_object(
                    raw_criterion,
                    keys=frozenset({"assessment", "criterion", "selections"}),
                    name=f"reviews[{index}].criteria[{criterion_index}]",
                )
                if (
                    type(item["criterion"]) is not str
                    or type(item["assessment"]) is not str
                ):
                    raise ReviewerContractError(
                        "invalid_type", "criterion names and assessments must be strings"
                    )
                raw_selections = _array(
                    item["selections"],
                    name=(
                        f"reviews[{index}].criteria[{criterion_index}].selections"
                    ),
                    maximum=8,
                )
                selections: list[ReviewerEvidenceSelectionV1] = []
                for selection_index, raw_selection in enumerate(raw_selections):
                    selection = _exact_object(
                        raw_selection,
                        keys=frozenset({"artifact_id", "node_id"}),
                        name=(
                            f"reviews[{index}].criteria[{criterion_index}]"
                            f".selections[{selection_index}]"
                        ),
                    )
                    if (
                        type(selection["artifact_id"]) is not str
                        or type(selection["node_id"]) is not str
                    ):
                        raise ReviewerContractError(
                            "invalid_type", "model selections must use string tokens"
                        )
                    selections.append(
                        self._session.resolve_selection(
                            context,
                            artifact_id=selection["artifact_id"],
                            node_id=selection["node_id"],
                        )
                    )
                if item["assessment"] == "insufficient" and selections:
                    raise ReviewerContractError(
                        "invalid_state",
                        "insufficient criteria cannot select conclusive evidence",
                    )
                criteria.append(
                    ReviewerCriterionV1(
                        criterion=item["criterion"],
                        assessment=item["assessment"],
                        selections=tuple(selections),
                    )
                )
            canonical = tuple(criteria)
            if tuple(item.criterion for item in canonical) != REVIEWER_CRITERIA:
                raise ReviewerContractError(
                    "invalid_state", "model response must use fixed criterion order"
                )
            parsed.append(canonical)
        expected = [context.candidate_id for context in contexts]
        if observed != expected or len(observed) != len(set(observed)):
            raise ReviewerContractError(
                "verdict_coverage_mismatch", "model response coverage is ambiguous"
            )
        return tuple(parsed)

    @staticmethod
    def _selection_refs(
        context: ReviewerCandidateContext,
        criteria: Sequence[ReviewerCriterionV1],
    ) -> tuple[ArtifactRef, ...]:
        selected = {
            (selection.artifact_id, selection.node_id)
            for criterion in criteria
            for selection in criterion.selections
        }
        refs: dict[str, ArtifactRef] = {}
        for node in context.nodes:
            if (node.artifact_id, node.node_id) in selected:
                refs[node.artifact_id] = node.artifact_ref
        if len(selected) != sum(
            1
            for artifact_id, node_id in selected
            if any(
                node.artifact_id == artifact_id and node.node_id == node_id
                for node in context.nodes
            )
        ):
            raise ReviewerContextBindingError("selection closure differs from context")
        return tuple(refs[item] for item in sorted(refs))

    def _run_body(
        self,
    ) -> tuple[
        tuple[ReviewerCandidateVerdictV1, ...],
        tuple[ArtifactRef, ...],
        tuple[str, ...],
    ]:
        candidates = self._review_input.producer_draft.candidates
        contexts = tuple(
            self._session.build_candidate_context(candidate.candidate_id)
            for candidate in candidates
        )
        criteria_by_candidate: dict[str, tuple[ReviewerCriterionV1, ...]] = {
            context.candidate_id: _insufficient_criteria()
            for context in contexts
            if context.context_status == "unavailable"
        }
        model_digest_by_candidate: dict[str, str | None] = {
            context.candidate_id: None
            for context in contexts
            if context.context_status == "unavailable"
        }

        available = tuple(
            context for context in contexts if context.context_status == "available"
        )
        self._stage = "REVIEW"
        for start in range(0, len(available), _MODEL_BATCH_SIZE):
            batch = available[start : start + _MODEL_BATCH_SIZE]
            model_call = self._session.call_model(
                f"MODEL-D3-{start // _MODEL_BATCH_SIZE + 1:03d}-SEMANTIC",
                batch,
                self._request_contract(),
            )
            if model_call.result.status != "success" or model_call.result.response is None:
                raise _Stop("runtime.model_failed", ("model_response",))
            parsed = self._parse_response(model_call.result.response, batch)
            for context, criteria in zip(batch, parsed, strict=True):
                criteria_by_candidate[context.candidate_id] = criteria
                model_digest_by_candidate[context.candidate_id] = (
                    model_call.record_sha256
                )

        self._stage = "VALIDATE"
        candidate_by_id = {item.candidate_id: item for item in candidates}
        contexts_by_id = {item.candidate_id: item for item in contexts}
        verdicts: list[ReviewerCandidateVerdictV1] = []
        refs: dict[str, ArtifactRef] = {}
        model_records: set[str] = set()
        for candidate_id in sorted(candidate_by_id):
            candidate = candidate_by_id[candidate_id]
            context = contexts_by_id[candidate_id]
            criteria = criteria_by_candidate[candidate_id]
            model_digest = model_digest_by_candidate[candidate_id]
            validation: ReviewerValidationArtifact = self._session.issue_validation(
                context,
                criteria,
                model_record_sha256=model_digest,
            )
            for ref in self._selection_refs(context, criteria):
                refs[ref.artifact_id] = ref
            refs[validation.artifact_ref.artifact_id] = validation.artifact_ref
            if model_digest is not None:
                model_records.add(model_digest)
            verdicts.append(
                ReviewerCandidateVerdictV1(
                    candidate_id=candidate.candidate_id,
                    candidate_sha256=candidate.candidate_sha256,
                    review_input_sha256=self._review_input.review_input_sha256,
                    criteria=criteria,
                    context_sha256=context.context_sha256,
                    validation_artifact_id=validation.artifact_ref.artifact_id,
                    validation_artifact_sha256=(
                        validation.artifact_ref.artifact_sha256
                    ),
                    model_record_sha256=model_digest,
                )
            )
        return (
            tuple(verdicts),
            tuple(refs[item] for item in sorted(refs)),
            tuple(sorted(model_records)),
        )

    def _closed_deferred(self, stopped: _Stop) -> ReviewerResultV1:
        try:
            seal = self._session.finalize(
                used_artifacts=(),
                used_model_records=(),
            )
        except BaseException as exc:
            if not isinstance(exc, Exception):
                raise
            return parse_reviewer_result_v1(
                ReviewerDeferredV1(
                    review_input=self._review_input,
                    stage="FINALIZE",
                    reason_code="runtime.seal_failed",
                    missing_information=("attempt_seal",),
                    attempt_seal=None,
                )
            )
        return parse_reviewer_result_v1(
            ReviewerDeferredV1(
                review_input=self._review_input,
                stage="REVIEW",
                reason_code=stopped.reason_code,
                missing_information=stopped.missing_information,
                attempt_seal=seal,
            )
        )

    def _finalize_success(
        self,
        verdicts: tuple[ReviewerCandidateVerdictV1, ...],
        used_artifacts: tuple[ArtifactRef, ...],
        used_model_records: tuple[str, ...],
    ) -> ReviewerResultV1:
        try:
            seal = self._session.finalize(
                used_artifacts=used_artifacts,
                used_model_records=used_model_records,
            )
        except BaseException as exc:
            if not isinstance(exc, Exception):
                raise
            return parse_reviewer_result_v1(
                ReviewerDeferredV1(
                    review_input=self._review_input,
                    stage="FINALIZE",
                    reason_code="runtime.seal_failed",
                    missing_information=("attempt_seal",),
                    attempt_seal=None,
                )
            )
        try:
            return parse_reviewer_result_v1(
                ReviewerFinalizedV1(
                    review_input=self._review_input,
                    verdicts=verdicts,
                    attempt_seal=seal,
                )
            )
        except (ReviewerContractError, TypeError, ValueError):
            return parse_reviewer_result_v1(
                ReviewerDeferredV1(
                    review_input=self._review_input,
                    stage="FINALIZE",
                    reason_code="contract.invalid",
                    missing_information=("candidate_coverage",),
                    attempt_seal=seal,
                )
            )

    def _stop_for(self, error: Exception) -> _Stop:
        if isinstance(error, BudgetExceeded):
            return _Stop("runtime.budget_exhausted", ("budget_ledger",))
        if isinstance(error, ReviewerContractError):
            if self._stage == "REVIEW":
                return _Stop("runtime.model_failed", ("model_response",))
            return _Stop(
                "contract.invalid", ("candidate_coverage", "model_response")
            )
        if isinstance(error, ReviewerContextLimitExceeded):
            return _Stop("review.incomplete", ("review_evidence",))
        if isinstance(error, ReviewerContextBindingError):
            if self._stage == "BUILD":
                return _Stop("runtime.source_failed", ("source_ledger",))
            if self._stage == "VALIDATE":
                return _Stop("runtime.tool_failed", ("artifact_catalog",))
            return _Stop("runtime.model_failed", ("model_response",))
        if isinstance(error, ReviewerContextError):
            return _Stop("review.incomplete", ("review_evidence",))
        return _Stop("review.incomplete", ("review_evidence",))

    def run(self) -> ReviewerResultV1:
        """Run once; repeated calls return the same strictly normalized result."""

        with self._lock:
            if self._result is not None:
                return self._result
            if self._cancelled:
                raise RuntimeError("reviewer run was irreversibly cancelled")
            if self._running:
                raise RuntimeError("re-entrant reviewer runs are not allowed")
            self._running = True
            try:
                try:
                    verdicts, artifacts, model_records = self._run_body()
                except _Stop as stopped:
                    self._result = self._closed_deferred(stopped)
                except Exception as error:
                    self._result = self._closed_deferred(self._stop_for(error))
                else:
                    self._result = self._finalize_success(
                        verdicts, artifacts, model_records
                    )
                return self._result
            except BaseException:
                self._cancelled = True
                self._session.abort()
                raise
            finally:
                self._running = False


__all__ = [
    "REVIEWER_RESPONSE_CONTRACT_ID",
    "SourceDiscoveryReviewerController",
]
