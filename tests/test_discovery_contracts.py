from __future__ import annotations

import copy
import unittest

import vulngym_agent.benchmark as benchmark_api
from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import (
    DEFAULT_DISCOVERY_LIMITS,
    DISCOVERY_ERROR_TAXONOMY_VERSION,
    DISCOVERY_LIMITS_VERSION,
    DiscoveryCandidate,
    DiscoveryContractError,
    DiscoveryContractLimits,
    DiscoveryDeferred,
    DiscoveryLocation,
    DiscoveryReview,
    DiscoveryTaskInputV1,
    DiscoveryTaskResult,
)
from vulngym_agent.benchmark.discovery_projection import project_discovery_result


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
TASK_ID = "VG-TEST-0123456789ABCDEF0123"
REPO_URL = "https://github.com/example/discovery"
COMMIT = "1" * 40


def _task() -> DiscoveryTaskInputV1:
    return DiscoveryTaskInputV1(
        task_id=TASK_ID,
        repo_url=REPO_URL,
        commit=COMMIT,
        instruction_id=INSTRUCTION_ID,
        snapshot_manifest_sha256=DIGEST_A,
        snapshot_content_root=DIGEST_B,
    )


def _location(
    file: str, line: int, *, code_sha256: str = DIGEST_C
) -> DiscoveryLocation:
    return DiscoveryLocation(
        file=file,
        line_start=line,
        line_end=line,
        code_sha256=code_sha256,
    )


def _candidate(
    task: DiscoveryTaskInputV1,
    *,
    entry_line: int = 4,
    critical_line: int = 19,
    trace: tuple[DiscoveryLocation, ...] = (),
    entry_code_sha256: str = DIGEST_C,
) -> DiscoveryCandidate:
    return DiscoveryCandidate(
        task_id=task.task_id,
        snapshot_id=task.snapshot_id,
        repo_url=task.repo_url,
        commit=task.commit,
        entry_point=_location(
            "src/routes.py", entry_line, code_sha256=entry_code_sha256
        ),
        critical_operation=_location("src/service.py", critical_line),
        trace=trace,
        relationship_evidence_refs=("REL-0001",),
        source_evidence_refs=("SRC-0001", "SRC-0002"),
    )


def _review(candidate: DiscoveryCandidate, decision: str = "emit") -> DiscoveryReview:
    return DiscoveryReview(
        task_id=candidate.task_id,
        snapshot_id=candidate.snapshot_id,
        candidate_id=candidate.candidate_id,
        candidate_sha256=candidate.candidate_sha256,
        decision=decision,
        reason_codes=("source_relationship_supported",),
    )


class DiscoveryContractTests(unittest.TestCase):
    def test_d0_contracts_are_available_from_the_benchmark_package(self) -> None:
        self.assertIs(DiscoveryTaskInputV1, benchmark_api.DiscoveryTaskInputV1)
        self.assertIs(DiscoveryTaskResult, benchmark_api.DiscoveryTaskResult)
        self.assertIs(project_discovery_result, benchmark_api.project_discovery_result)

    def test_task_round_trip_has_stable_snapshot_identity_and_answer_free_keys(self) -> None:
        first = _task()
        second = _task()
        self.assertEqual(first.snapshot_id, second.snapshot_id)
        self.assertRegex(first.snapshot_id, r"^VGS-[0-9A-F]{32}$")
        self.assertEqual(first, DiscoveryTaskInputV1.from_dict(first.to_dict()))
        serialized = first.to_dict()
        for forbidden in (
            "report_id",
            "entry_id",
            "gold",
            "ghsa",
            "title",
            "verify",
        ):
            self.assertNotIn(forbidden, serialized)

        changed = DiscoveryTaskInputV1(
            task_id=first.task_id,
            repo_url=first.repo_url,
            commit=first.commit,
            instruction_id=first.instruction_id,
            snapshot_manifest_sha256=first.snapshot_manifest_sha256,
            snapshot_content_root="d" * 64,
        )
        self.assertNotEqual(first.snapshot_id, changed.snapshot_id)

    def test_task_and_nested_wire_contracts_reject_extra_keys_and_tampered_ids(self) -> None:
        value = _task().to_dict()
        value["report_id"] = "GHSA-0000-0000-0000"
        with self.assertRaises(DiscoveryContractError) as caught:
            DiscoveryTaskInputV1.from_dict(value)
        self.assertEqual("invalid_keys", caught.exception.code)

        value = _task().to_dict()
        value["snapshot_id"] = "VGS-" + "0" * 32
        with self.assertRaises(DiscoveryContractError) as caught:
            DiscoveryTaskInputV1.from_dict(value)
        self.assertEqual("invalid_binding", caught.exception.code)

        value = _task().to_dict()
        value["contract_version"] = True
        with self.assertRaises(DiscoveryContractError):
            DiscoveryTaskInputV1.from_dict(value)

    def test_location_is_canonical_bounded_and_bool_is_not_an_integer(self) -> None:
        location = DiscoveryLocation(
            file="src/app.py",
            line_start=8,
            line_end=10,
            code_sha256=DIGEST_A,
        )
        self.assertEqual(
            {"file": "src/app.py", "line": "8-10"},
            location.evaluator_location(),
        )
        self.assertEqual(location, DiscoveryLocation.from_dict(location.to_dict()))

        for path in (
            "../secret",
            "/absolute",
            "-option",
            "src\\app.py",
            "C:/app.py",
            "src//app.py",
            "src/./app.py",
            "src/\x00app.py",
            "src/.git/config",
            "src/.GiT/config",
            "src/．git/config",
            "src/CON",
            "src/nul.txt",
            "src/COM1.log",
            "src/name.",
            "src/name ",
            "src/file?.py",
        ):
            with self.subTest(path=path), self.assertRaises(DiscoveryContractError):
                DiscoveryLocation(path, 1, 1, DIGEST_A)
        with self.assertRaises(DiscoveryContractError):
            DiscoveryLocation("src/app.py", True, 1, DIGEST_A)
        with self.assertRaises(DiscoveryContractError):
            DiscoveryLocation("src/app.py", 4, 3, DIGEST_A)
        self.assertEqual(
            256,
            DiscoveryLocation("src/app.py", 10, 265, DIGEST_A).line_end
            - 10
            + 1,
        )
        with self.assertRaises(DiscoveryContractError):
            DiscoveryLocation("src/app.py", 10, 266, DIGEST_A)
        sixty_four_components = "/".join("a" for _ in range(64))
        self.assertEqual(
            sixty_four_components,
            DiscoveryLocation(sixty_four_components, 1, 1, DIGEST_A).file,
        )
        with self.assertRaises(DiscoveryContractError):
            DiscoveryLocation("/".join("a" for _ in range(65)), 1, 1, DIGEST_A)

    def test_candidate_is_deeply_immutable_and_endpoint_id_ignores_trace_and_code_digest(self) -> None:
        task = _task()
        mutable_trace = [_location("src/middle.py", 9)]
        mutable_relationship = ["REL-0001"]
        mutable_source = ["SRC-0001"]
        candidate = DiscoveryCandidate(
            task_id=task.task_id,
            snapshot_id=task.snapshot_id,
            repo_url=task.repo_url,
            commit=task.commit,
            entry_point=_location("src/routes.py", 4),
            critical_operation=_location("src/service.py", 19),
            trace=mutable_trace,
            relationship_evidence_refs=mutable_relationship,
            source_evidence_refs=mutable_source,
        )
        mutable_trace.clear()
        mutable_relationship.append("REL-0002")
        mutable_source.clear()
        self.assertEqual(1, len(candidate.trace))
        self.assertEqual(("REL-0001",), candidate.relationship_evidence_refs)
        self.assertEqual(("SRC-0001",), candidate.source_evidence_refs)

        same_endpoints = _candidate(
            task,
            trace=(_location("different/trace.py", 77),),
            entry_code_sha256=DIGEST_A,
        )
        baseline = _candidate(task)
        self.assertEqual(baseline.candidate_id, same_endpoints.candidate_id)
        self.assertNotEqual(baseline.candidate_sha256, same_endpoints.candidate_sha256)
        same_trace_different_code = _candidate(task, entry_code_sha256=DIGEST_A)
        self.assertEqual(baseline.candidate_id, same_trace_different_code.candidate_id)

    def test_candidate_round_trip_rejects_entry_fields_and_candidate_id_tamper(self) -> None:
        candidate = _candidate(_task())
        self.assertEqual(candidate, DiscoveryCandidate.from_dict(candidate.to_dict()))
        value = candidate.to_dict()
        value["verify"] = 0
        with self.assertRaises(DiscoveryContractError) as caught:
            DiscoveryCandidate.from_dict(value)
        self.assertEqual("invalid_keys", caught.exception.code)

        value = candidate.to_dict()
        value["candidate_id"] = "VGC-" + "0" * 32
        with self.assertRaises(DiscoveryContractError) as caught:
            DiscoveryCandidate.from_dict(value)
        self.assertEqual("invalid_binding", caught.exception.code)

    def test_review_binds_exact_candidate_digest_and_uses_fixed_decisions(self) -> None:
        candidate = _candidate(_task())
        review = _review(candidate)
        review.assert_candidate(candidate)
        self.assertEqual(review, DiscoveryReview.from_dict(review.to_dict()))

        changed = _candidate(_task(), trace=(_location("src/trace.py", 2),))
        self.assertEqual(candidate.candidate_id, changed.candidate_id)
        with self.assertRaises(DiscoveryContractError) as caught:
            review.assert_candidate(changed)
        self.assertEqual("invalid_binding", caught.exception.code)

        with self.assertRaises(DiscoveryContractError):
            DiscoveryReview(
                task_id=candidate.task_id,
                snapshot_id=candidate.snapshot_id,
                candidate_id=candidate.candidate_id,
                candidate_sha256=candidate.candidate_sha256,
                decision="correct",  # type: ignore[arg-type]
                reason_codes=("source_relationship_supported",),
            )

    def test_finalized_result_requires_exact_review_closure_and_unknown_coverage(self) -> None:
        task = _task()
        first = _candidate(task)
        second = _candidate(task, entry_line=5, critical_line=20)
        result = DiscoveryTaskResult(
            task=task,
            status="finalized",
            coverage_status="unknown",
            candidates=(first, second),
            reviews=(_review(first, "emit"), _review(second, "reject")),
        )
        self.assertEqual((first,), result.emitted_candidates)
        self.assertEqual(result, DiscoveryTaskResult.from_dict(result.to_dict()))

        with self.assertRaises(DiscoveryContractError) as caught:
            DiscoveryTaskResult(
                task=task,
                status="finalized",
                coverage_status="unknown",
                candidates=(first, second),
                reviews=(_review(first),),
            )
        self.assertEqual("review_coverage_mismatch", caught.exception.code)

        with self.assertRaises(DiscoveryContractError):
            DiscoveryTaskResult(
                task=task,
                status="finalized",
                coverage_status="complete",  # type: ignore[arg-type]
                candidates=(),
                reviews=(),
            )

    def test_deferred_result_is_fail_closed_and_cannot_carry_partial_candidates(self) -> None:
        task = _task()
        deferred = DiscoveryDeferred(
            task_id=task.task_id,
            snapshot_id=task.snapshot_id,
            stage="scouting",
            reason_code="evidence_insufficient",
            missing_information=("a bounded structural relationship is required",),
        )
        result = DiscoveryTaskResult(
            task=task,
            status="deferred",
            coverage_status="unknown",
            candidates=(),
            reviews=(),
            deferred=deferred,
        )
        self.assertEqual((), result.emitted_candidates)
        self.assertEqual(result, DiscoveryTaskResult.from_dict(result.to_dict()))

        candidate = _candidate(task)
        with self.assertRaises(DiscoveryContractError):
            DiscoveryTaskResult(
                task=task,
                status="deferred",
                coverage_status="unknown",
                candidates=(candidate,),
                reviews=(_review(candidate),),
                deferred=deferred,
            )

    def test_fixed_limits_are_versioned_and_candidate_count_is_bounded(self) -> None:
        self.assertEqual(DISCOVERY_LIMITS_VERSION, DEFAULT_DISCOVERY_LIMITS.limits_version)
        self.assertEqual(
            DISCOVERY_ERROR_TAXONOMY_VERSION,
            DiscoveryContractError.taxonomy_version,
        )
        self.assertEqual(64, DEFAULT_DISCOVERY_LIMITS.max_candidates_per_task)
        self.assertEqual(64, DEFAULT_DISCOVERY_LIMITS.max_path_depth)
        with self.assertRaises(DiscoveryContractError) as caught:
            DiscoveryContractLimits(max_candidates_per_task=63)
        self.assertEqual("invalid_value", caught.exception.code)
        with self.assertRaises(DiscoveryContractError) as caught:
            DiscoveryContractLimits(limits_version=[])  # type: ignore[arg-type]
        self.assertEqual("invalid_value", caught.exception.code)

        task = _task()
        candidates = tuple(
            _candidate(task, entry_line=index + 1, critical_line=index + 101)
            for index in range(65)
        )
        reviews = tuple(_review(candidate) for candidate in candidates)
        with self.assertRaises(DiscoveryContractError) as caught:
            DiscoveryTaskResult(
                task=task,
                status="finalized",
                coverage_status="unknown",
                candidates=candidates,
                reviews=reviews,
            )
        self.assertEqual("limit_exceeded", caught.exception.code)

    def test_to_dict_returns_detached_json(self) -> None:
        task = _task()
        candidate = _candidate(task, trace=(_location("src/trace.py", 7),))
        result = DiscoveryTaskResult(
            task=task,
            status="finalized",
            coverage_status="unknown",
            candidates=(candidate,),
            reviews=(_review(candidate),),
        )
        value = result.to_dict()
        detached = copy.deepcopy(value)
        value["candidates"][0]["trace"].clear()
        value["reviews"][0]["reason_codes"].append("mutated")
        self.assertEqual(detached, result.to_dict())

    def test_result_canonicalizes_candidate_and_review_order(self) -> None:
        task = _task()
        first = _candidate(task, entry_line=4, critical_line=20)
        second = _candidate(task, entry_line=5, critical_line=21)
        forward = DiscoveryTaskResult(
            task=task,
            status="finalized",
            coverage_status="unknown",
            candidates=(first, second),
            reviews=(_review(first, "emit"), _review(second, "reject")),
        )
        reverse = DiscoveryTaskResult(
            task=task,
            status="finalized",
            coverage_status="unknown",
            candidates=(second, first),
            reviews=(_review(second, "reject"), _review(first, "emit")),
        )
        self.assertEqual(forward.to_dict(), reverse.to_dict())
        self.assertEqual(forward.emitted_candidates, reverse.emitted_candidates)

    def test_result_rejects_duplicate_endpoints_when_only_trace_differs(self) -> None:
        task = _task()
        baseline = _candidate(task)
        traced = _candidate(task, trace=(_location("src/trace.py", 9),))
        self.assertEqual(baseline.candidate_id, traced.candidate_id)
        with self.assertRaises(DiscoveryContractError) as caught:
            DiscoveryTaskResult(
                task=task,
                status="finalized",
                coverage_status="unknown",
                candidates=(baseline, traced),
                reviews=(_review(baseline), _review(traced)),
            )
        self.assertEqual("duplicate_candidate", caught.exception.code)

    def test_wire_arrays_reject_non_json_sequence_lookalikes(self) -> None:
        candidate = _candidate(_task())
        candidate_value = candidate.to_dict()
        candidate_value["source_evidence_refs"] = ("SRC-0001",)
        with self.assertRaises(DiscoveryContractError) as caught:
            DiscoveryCandidate.from_dict(candidate_value)
        self.assertEqual("invalid_type", caught.exception.code)

        review_value = _review(candidate).to_dict()
        review_value["reason_codes"] = ("source_relationship_supported",)
        with self.assertRaises(DiscoveryContractError):
            DiscoveryReview.from_dict(review_value)

    def test_public_constructors_normalize_malformed_collection_and_state_errors(self) -> None:
        task = _task()
        candidate = _candidate(task)

        candidate_kwargs = {
            "task_id": task.task_id,
            "snapshot_id": task.snapshot_id,
            "repo_url": task.repo_url,
            "commit": task.commit,
            "entry_point": candidate.entry_point,
            "critical_operation": candidate.critical_operation,
            "relationship_evidence_refs": ("REL-0001",),
            "source_evidence_refs": ("SRC-0001",),
        }
        for malformed_trace in (None, "src/trace.py", {"trace": "value"}, {1}):
            with self.subTest(trace=malformed_trace), self.assertRaises(
                DiscoveryContractError
            ) as caught:
                DiscoveryCandidate(trace=malformed_trace, **candidate_kwargs)  # type: ignore[arg-type]
            self.assertEqual("invalid_type", caught.exception.code)

        with self.assertRaises(DiscoveryContractError) as caught:
            DiscoveryReview(
                task_id=candidate.task_id,
                snapshot_id=candidate.snapshot_id,
                candidate_id=candidate.candidate_id,
                candidate_sha256=candidate.candidate_sha256,
                decision=[],  # type: ignore[arg-type]
                reason_codes=("source_relationship_supported",),
            )
        self.assertEqual("invalid_value", caught.exception.code)

        malformed_results = (
            {"status": [], "coverage_status": "unknown", "candidates": (), "reviews": ()},
            {"status": "finalized", "coverage_status": [], "candidates": (), "reviews": ()},
            {"status": "finalized", "coverage_status": "unknown", "candidates": None, "reviews": ()},
            {"status": "finalized", "coverage_status": "unknown", "candidates": (), "reviews": None},
        )
        for kwargs in malformed_results:
            with self.subTest(kwargs=kwargs), self.assertRaises(DiscoveryContractError):
                DiscoveryTaskResult(task=task, **kwargs)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
