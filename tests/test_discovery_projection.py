from __future__ import annotations

import unittest

from vulngym_agent.benchmark.contracts import INSTRUCTION_ID
from vulngym_agent.benchmark.discovery_contracts import (
    DiscoveryCandidate,
    DiscoveryDeferred,
    DiscoveryLocation,
    DiscoveryReview,
    DiscoveryTaskInputV1,
    DiscoveryTaskResult,
)
from vulngym_agent.benchmark.discovery_projection import (
    DISCOVERY_PROJECTION_ERROR_TAXONOMY_VERSION,
    DISCOVERY_PROJECTION_VERSION,
    DiscoveryProjectionError,
    project_discovery_result,
)


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def _task() -> DiscoveryTaskInputV1:
    return DiscoveryTaskInputV1(
        task_id="VG-TEST-0123456789ABCDEF0123",
        repo_url="https://github.com/example/discovery",
        commit="1" * 40,
        instruction_id=INSTRUCTION_ID,
        snapshot_manifest_sha256=DIGEST_A,
        snapshot_content_root=DIGEST_B,
    )


def _location(file: str, start: int, end: int | None = None) -> DiscoveryLocation:
    return DiscoveryLocation(file, start, start if end is None else end, DIGEST_C)


def _candidate(
    task: DiscoveryTaskInputV1,
    index: int,
    *,
    trace: tuple[DiscoveryLocation, ...] = (),
) -> DiscoveryCandidate:
    return DiscoveryCandidate(
        task_id=task.task_id,
        snapshot_id=task.snapshot_id,
        repo_url=task.repo_url,
        commit=task.commit,
        entry_point=_location("src/routes.py", index + 1),
        critical_operation=_location("src/service.py", index + 101, index + 102),
        trace=trace,
        relationship_evidence_refs=(f"REL-{index:04d}",),
        source_evidence_refs=(f"SRC-{index:04d}",),
    )


def _review(candidate: DiscoveryCandidate, decision: str) -> DiscoveryReview:
    return DiscoveryReview(
        task_id=candidate.task_id,
        snapshot_id=candidate.snapshot_id,
        candidate_id=candidate.candidate_id,
        candidate_sha256=candidate.candidate_sha256,
        decision=decision,
        reason_codes=("independent_review_complete",),
    )


def _result(
    task: DiscoveryTaskInputV1,
    candidates: tuple[DiscoveryCandidate, ...],
    decisions: tuple[str, ...],
) -> DiscoveryTaskResult:
    return DiscoveryTaskResult(
        task=task,
        status="finalized",
        coverage_status="unknown",
        candidates=candidates,
        reviews=tuple(
            _review(candidate, decision)
            for candidate, decision in zip(candidates, decisions, strict=True)
        ),
    )


class DiscoveryProjectionTests(unittest.TestCase):
    def test_projects_only_evaluator_fields_and_strips_discovery_sidecars(self) -> None:
        task = _task()
        candidate = _candidate(
            task,
            1,
            trace=(_location("src/trace.py", 50),),
        )
        findings = project_discovery_result(_result(task, (candidate,), ("emit",)))
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual(
            {
                "commit",
                "critical_operation",
                "entry_point",
                "finding_id",
                "repo_url",
                "task_id",
                "trace",
            },
            set(finding),
        )
        self.assertEqual({"file", "line"}, set(finding["entry_point"]))
        self.assertEqual("102-103", finding["critical_operation"]["line"])
        serialized = repr(finding).casefold()
        for forbidden in (
            "report_id",
            "entry_id",
            "ghsa",
            "title",
            "verify",
            "code_sha256",
            "evidence",
            "review",
            "snapshot",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_finding_identity_is_stable_and_trace_does_not_change_endpoint_identity(self) -> None:
        task = _task()
        baseline = _candidate(task, 1)
        traced = _candidate(task, 1, trace=(_location("src/trace.py", 50),))
        self.assertEqual(baseline.candidate_id, traced.candidate_id)

        baseline_finding = project_discovery_result(
            _result(task, (baseline,), ("emit",))
        )[0]
        traced_finding = project_discovery_result(
            _result(task, (traced,), ("emit",))
        )[0]
        self.assertEqual(
            baseline_finding["finding_id"], traced_finding["finding_id"]
        )
        self.assertNotIn("trace", baseline_finding)
        self.assertIn("trace", traced_finding)

        with self.assertRaisesRegex(ValueError, "repeats an endpoint"):
            _result(task, (traced, baseline), ("emit", "emit"))

    def test_review_decisions_filter_without_changing_task_binding(self) -> None:
        task = _task()
        candidates = tuple(_candidate(task, index) for index in range(3))
        result = _result(task, candidates, ("emit", "reject", "defer"))
        findings = project_discovery_result(result)
        self.assertEqual(1, len(findings))
        self.assertEqual(task.task_id, findings[0]["task_id"])
        self.assertEqual(task.repo_url, findings[0]["repo_url"])
        self.assertEqual(task.commit, findings[0]["commit"])

    def test_zero_findings_are_supported_for_finalized_and_deferred_tasks(self) -> None:
        task = _task()
        empty = DiscoveryTaskResult(
            task=task,
            status="finalized",
            coverage_status="unknown",
            candidates=(),
            reviews=(),
        )
        self.assertEqual((), project_discovery_result(empty))

        deferred = DiscoveryDeferred(
            task_id=task.task_id,
            snapshot_id=task.snapshot_id,
            stage="scouting",
            reason_code="evidence_insufficient",
            missing_information=("more source evidence is required",),
        )
        deferred_result = DiscoveryTaskResult(
            task=task,
            status="deferred",
            coverage_status="unknown",
            candidates=(),
            reviews=(),
            deferred=deferred,
        )
        self.assertEqual((), project_discovery_result(deferred_result))

    def test_one_task_can_emit_exactly_sixty_four_stably_ordered_findings(self) -> None:
        task = _task()
        candidates = tuple(_candidate(task, index) for index in reversed(range(64)))
        result = _result(task, candidates, ("emit",) * 64)
        first = project_discovery_result(result)
        second = project_discovery_result(
            _result(task, tuple(reversed(candidates)), ("emit",) * 64)
        )
        self.assertEqual(64, len(first))
        self.assertEqual(first, second)
        self.assertEqual(
            sorted(item["finding_id"] for item in first),
            sorted(item["finding_id"] for item in second),
        )

    def test_projection_and_serialization_are_independent_of_input_order(self) -> None:
        task = _task()
        first = _candidate(task, 1)
        second = _candidate(task, 2)
        forward = _result(task, (first, second), ("emit", "emit"))
        reverse = _result(task, (second, first), ("emit", "emit"))
        self.assertEqual(forward.to_dict(), reverse.to_dict())
        self.assertEqual(
            project_discovery_result(forward),
            project_discovery_result(reverse),
        )

    def test_projected_findings_are_deeply_immutable(self) -> None:
        task = _task()
        candidate = _candidate(
            task, 1, trace=(_location("src/trace.py", 50),)
        )
        finding = project_discovery_result(
            _result(task, (candidate,), ("emit",))
        )[0]
        with self.assertRaises(TypeError):
            finding["entry_point"]["line"] = 999  # type: ignore[index]
        with self.assertRaises(TypeError):
            finding["trace"][0]["file"] = "changed.py"  # type: ignore[index]

    def test_projection_limit_is_fail_closed_not_silent_top_k_truncation(self) -> None:
        task = _task()
        candidates = (_candidate(task, 1), _candidate(task, 2))
        result = _result(task, candidates, ("emit", "emit"))
        with self.assertRaises(DiscoveryProjectionError) as caught:
            project_discovery_result(result, max_findings=1)
        self.assertEqual("projection_limit_exceeded", caught.exception.code)
        for invalid in (True, -1, 65, 1.0):
            with self.subTest(invalid=invalid), self.assertRaises(
                DiscoveryProjectionError
            ):
                project_discovery_result(result, max_findings=invalid)  # type: ignore[arg-type]

    def test_projection_rejects_raw_entry_or_mapping_interfaces(self) -> None:
        raw_entry = {
            "repo_url": _task().repo_url,
            "commit": _task().commit,
            "entry_point": {"file": "src/routes.py", "line": 1},
            "critical_operation": {"file": "src/service.py", "line": 2},
            "report_id": "GHSA-0000-0000-0000",
            "entry_id": "entry-00001",
            "verify": 0,
        }
        with self.assertRaises(DiscoveryProjectionError) as caught:
            project_discovery_result(raw_entry)  # type: ignore[arg-type]
        self.assertEqual("invalid_result", caught.exception.code)

    def test_projection_rejects_result_subclass_with_overridden_emission(self) -> None:
        task = _task()
        candidate = _candidate(task, 1)

        class ForgedResult(DiscoveryTaskResult):
            @property
            def emitted_candidates(self):
                return (candidate,)

        forged = ForgedResult(
            task=task,
            status="finalized",
            coverage_status="unknown",
            candidates=(),
            reviews=(),
        )
        with self.assertRaises(DiscoveryProjectionError) as caught:
            project_discovery_result(forged)
        self.assertEqual("invalid_result", caught.exception.code)

    def test_projection_rejects_nested_polymorphic_contract_nodes(self) -> None:
        task = _task()
        candidate = _candidate(task, 1)
        review = _review(candidate, "reject")

        class RewrittenReview(DiscoveryReview):
            def to_dict(self):
                value = super().to_dict()
                value["decision"] = "emit"
                return value

        class RaisingReview(DiscoveryReview):
            def to_dict(self):
                raise RuntimeError("must not escape the projection boundary")

        class RewrittenCandidate(DiscoveryCandidate):
            def to_dict(self):
                value = super().to_dict()
                value["critical_operation"] = value["entry_point"]
                return value

        class RewrittenLocation(DiscoveryLocation):
            def evaluator_location(self):
                return {"file": "rewritten.py", "line": 1}

        rewritten_review = RewrittenReview(
            task_id=review.task_id,
            snapshot_id=review.snapshot_id,
            candidate_id=review.candidate_id,
            candidate_sha256=review.candidate_sha256,
            decision=review.decision,
            reason_codes=review.reason_codes,
        )
        raising_review = RaisingReview(
            task_id=review.task_id,
            snapshot_id=review.snapshot_id,
            candidate_id=review.candidate_id,
            candidate_sha256=review.candidate_sha256,
            decision=review.decision,
            reason_codes=review.reason_codes,
        )
        rewritten_candidate = RewrittenCandidate(
            task_id=candidate.task_id,
            snapshot_id=candidate.snapshot_id,
            repo_url=candidate.repo_url,
            commit=candidate.commit,
            entry_point=candidate.entry_point,
            critical_operation=candidate.critical_operation,
            trace=candidate.trace,
            relationship_evidence_refs=candidate.relationship_evidence_refs,
            source_evidence_refs=candidate.source_evidence_refs,
        )
        rewritten_location_candidate = DiscoveryCandidate(
            task_id=candidate.task_id,
            snapshot_id=candidate.snapshot_id,
            repo_url=candidate.repo_url,
            commit=candidate.commit,
            entry_point=RewrittenLocation(**candidate.entry_point.to_dict()),
            critical_operation=candidate.critical_operation,
            trace=candidate.trace,
            relationship_evidence_refs=candidate.relationship_evidence_refs,
            source_evidence_refs=candidate.source_evidence_refs,
        )

        variants = (
            DiscoveryTaskResult(
                task=task,
                status="finalized",
                coverage_status="unknown",
                candidates=(candidate,),
                reviews=(rewritten_review,),
            ),
            DiscoveryTaskResult(
                task=task,
                status="finalized",
                coverage_status="unknown",
                candidates=(candidate,),
                reviews=(raising_review,),
            ),
            DiscoveryTaskResult(
                task=task,
                status="finalized",
                coverage_status="unknown",
                candidates=(rewritten_candidate,),
                reviews=(_review(rewritten_candidate, "reject"),),
            ),
            DiscoveryTaskResult(
                task=task,
                status="finalized",
                coverage_status="unknown",
                candidates=(rewritten_location_candidate,),
                reviews=(
                    _review(rewritten_location_candidate, "reject"),
                ),
            ),
        )
        for variant in variants:
            with self.subTest(node=type(variant.candidates[0]).__name__), self.assertRaises(
                DiscoveryProjectionError
            ) as caught:
                project_discovery_result(variant)
            self.assertEqual("invalid_result", caught.exception.code)

    def test_projection_policy_and_error_taxonomy_are_versioned(self) -> None:
        self.assertEqual("source-discovery-projection-v1", DISCOVERY_PROJECTION_VERSION)
        self.assertEqual(
            DISCOVERY_PROJECTION_ERROR_TAXONOMY_VERSION,
            DiscoveryProjectionError.taxonomy_version,
        )


if __name__ == "__main__":
    unittest.main()
